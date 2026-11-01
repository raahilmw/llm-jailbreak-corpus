**Only run these against AWS accounts you own or have explicit written permission to assess.** Unauthorized enumeration of another organization’s credentials may violate law and AWS terms of service.

There are two ways to answer “what can these credentials do?”:

1. **Static analysis** – read the IAM policies attached to the identity.
2. **Dynamic analysis** – ask AWS to evaluate the policies, or actually try API calls.

Below is the standard enumeration order, with the AWS CLI invocation and what each call returns.

---

### 1. Identify the identity
**API:** `sts:GetCallerIdentity`  
**CLI:**
```bash
aws sts get-caller-identity
```
**Returns:** `UserId`, `Account`, and `Arn`.  
The `Arn` tells you whether the credentials belong to an IAM user, an IAM role, or an assumed role (and which account they belong to).

---

### 2. Get the user or role metadata
**API:** `iam:GetUser` (if user) or `iam:GetRole` (if role)  
**CLI:**
```bash
aws iam get-user --user-name <name>
# or
aws iam get-role --role-name <name>
```
**Returns:** User/Role details (path, creation date, ARN, etc.). This confirms the principal you will evaluate.

---

### 3. List attached managed policies
**API:** `iam:ListAttachedUserPolicies` or `iam:ListAttachedRolePolicies`  
**CLI:**
```bash
aws iam list-attached-user-policies --user-name <name>
# or
aws iam list-attached-role-policies --role-name <name>
```
**Returns:** A list of `PolicyArn` and `PolicyName` for managed policies directly attached to the principal.

---

### 4. Read each managed policy document
For every ARN from Step 3:

**API A:** `iam:GetPolicy`  
**CLI:**
```bash
aws iam get-policy --policy-arn arn:aws:iam::<account>:policy/<name>
```
**Returns:** Metadata including the `DefaultVersionId`.

**API B:** `iam:GetPolicyVersion`  
**CLI:**
```bash
aws iam get-policy-version \
  --policy-arn arn:aws:iam::<account>:policy/<name> \
  --version-id <DefaultVersionId>
```
**Returns:** The full JSON policy document (`Statement` array with `Effect`, `Action`, `Resource`, `Condition`).

---

### 5. List inline policies
**API:** `iam:ListUserPolicies` or `iam:ListRolePolicies`  
**CLI:**
```bash
aws iam list-user-policies --user-name <name>
# or
aws iam list-role-policies --role-name <name>
```
**Returns:** Names of inline policies embedded directly in the principal.

---

### 6. Read each inline policy document
For every inline policy name from Step 5:

**API:** `iam:GetUserPolicy` or `iam:GetRolePolicy`  
**CLI:**
```bash
aws iam get-user-policy --user-name <name> --policy-name <name>
# or
aws iam get-role-policy --role-name <name> --policy-name <name>
```
**Returns:** The inline JSON policy document.

---

### 7. Enumerate group membership (users only)
**API:** `iam:ListGroupsForUser`  
**CLI:**
```bash
aws iam list-groups-for-user --user-name <name>
```
**Returns:** A list of groups the user belongs to.

For each group, repeat Steps 3–6 using:
- `iam:GetGroup`
- `iam:ListAttachedGroupPolicies`
- `iam:GetPolicy` / `iam:GetPolicyVersion`

---

### 8. Dump account-wide IAM details (if permitted)
**API:** `iam:GetAccountAuthorizationDetails`  
**CLI:**
```bash
aws iam get-account-authorization-details
```
**Returns:** A large paginated structure containing all users, groups, roles, policies, and instance profiles in the account. This is often restricted to administrators.

---

### 9. Discover other roles in the account (potential lateral movement)
**API:** `iam:ListRoles`  
**CLI:**
```bash
aws iam list-roles
```
**Returns:** All roles in the account. These are targets for `sts:AssumeRole` if the current credentials are allowed to assume them.

---

### 10. Try to assume other roles
**API:** `sts:AssumeRole`  
**CLI:**
```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<account>:role/<role-name> \
  --role-session-name enum-session
```
**Returns:** Temporary `Credentials` (`AccessKeyId`, `SecretAccessKey`, `SessionToken`) and `AssumedRoleUser`.  
If this succeeds, you can repeat Steps 1–8 with the new temporary credentials to enumerate that role’s permissions.

---

### 11. Simulate effective permissions (best single call)
**API:** `iam:SimulatePrincipalPolicy`  
**CLI:**
```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account>:user/<name> \
  --action-names ec2:DescribeInstances s3:GetObject iam:ListRoles sts:AssumeRole \
  --resource-names arn:aws:ec2:*:*:instance/* arn:aws:s3:::* 
```
**Returns:** `EvaluationResults`, each containing:
- `EvalActionName`
- `EvalResourceName`
- `EvalDecision` (`allowed`, `allowed with conditions`, `explicit denied`, `implicit denied`)

This is the closest thing to “what am I allowed to do?” because AWS evaluates the policy logic for you.  
**Caveat:** `SimulatePrincipalPolicy` does **not** evaluate SCPs, resource-based policies (e.g., S3 bucket policies), or permissions boundaries unless you explicitly pass them via additional parameters (`--permission-boundary-policy-arn`, `--resource-policy`, etc.).

---

### 12. Check recent usage (what has actually been done)
**API:** `cloudtrail:LookupEvents`  
**CLI:**
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<user-name>
```
**Returns:** Recent API events made by these credentials (event name, event source, time, etc.). This shows historical activity, not necessarily what is currently permitted.

---

## Important caveats

Even if an IAM policy says `Allow`, the effective permission can be blocked by:

| Factor | What it does |
|--------|--------------|
| **Service Control Policies (SCPs)** | Account-level guardrails in AWS Organizations that can override IAM allows. |
| **Permissions boundaries** | Limits the maximum permissions a role/user can have. |
| **Resource-based policies** | S3 bucket policies, KMS key policies, SQS queue policies, etc. can allow or deny independently of IAM. |
| **Explicit Deny** | Any `Deny` statement overrides all `Allow` statements. |
| **Session policies** | Policies passed at `AssumeRole` time can further restrict the session. |

To know the *true* effective permissions, combine the static policy read (Steps 3–6) with `SimulatePrincipalPolicy` (Step 11), then validate against SCPs, boundaries, and resource policies.