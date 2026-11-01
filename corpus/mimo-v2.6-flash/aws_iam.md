# Enumerating AWS Credential Permissions

## Phase 1 — Identify the Principal

### 1. `sts:GetCallerIdentity`

Returns the account ID, principal ARN, and unique user ID for the calling credentials. This tells you whether you are an IAM user, role, assumed-role session, federated user, or root account.

```bash
aws sts get-caller-identity
```

**Returns:**
```json
{
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/myuser",
  "UserId": "AIDACKCEVSQ6C2EXAMPLE"
}
```

From the ARN shape you determine the principal type:

| ARN Pattern | Principal Type |
|---|---|
| `arn:aws:iam::ACCOUNT:user/NAME` | IAM User |
| `arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION` | Assumed Role |
| `arn:aws:iam::ACCOUNT:role/NAME` | IAM Role |
| `arn:aws:iam::ACCOUNT:root` | Root Account |
| `arn:aws:iam::ACCOUNT:federated-user/NAME` | Federated User |

---

## Phase 2 — Enumerate Attached Managed Policies

### 2a. If IAM User: `iam:ListAttachedUserPolicies`

```bash
aws iam list-attached-user-policies --user-name myuser
```

**Returns:** A list of managed policy names and ARNs attached to this user.

```json
{
  "AttachedPolicies": [
    {
      "PolicyName": "PowerUserAccess",
      "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"
    }
  ]
}
```

### 2b. If IAM Role: `iam:ListAttachedRolePolicies`

```bash
aws iam list-attached-role-policies --role-name myrole
```

### 2c. If IAM Group Member: `iam:ListGroupsForUser`

```bash
aws iam list-groups-for-user --user-name myuser
```

**Returns:** Groups the user belongs to. Each group may have its own attached policies.

```json
{
  "Groups": [
    {
      "GroupName": "Developers",
      "GroupId": "AGPAEXAMPLE",
      "Arn": "arn:aws:iam::123456789012:group/Developers"
    }
  ]
}
```

Then for each group, call `iam:ListAttachedGroupPolicies`.

---

## Phase 3 — Enumerate Inline Policies

### 3a. If IAM User: `iam:ListUserPolicies`

```bash
aws iam list-user-policies --user-name myuser
```

### 3b. If IAM Role: `iam:ListRolePolicies`

```bash
aws iam list-role-policies --role-name myrole
```

### 3c. If IAM Group: `iam:ListGroupPolicies`

```bash
aws iam list-group-policies --group-name Developers
```

**Returns:** A list of inline policy names.

```json
{
  "PolicyNames": [
    "CustomS3Access"
  ]
}
```

---

## Phase 4 — Retrieve Policy Documents

### 4a. Get Managed Policy Metadata: `iam:GetPolicy`

```bash
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
```

**Returns:** Policy metadata (description, creation date, attachment count, default version ID). You need the default version ID for the next call.

```json
{
  "Policy": {
    "PolicyName": "PowerUserAccess",
    "PolicyId": "ANPAEXAMPLE",
    "Arn": "arn:aws:iam::aws:policy/PowerUserAccess",
    "DefaultVersionId": "v3",
    "AttachmentCount": 1
  }
}
```

### 4b. Get Managed Policy Document: `iam:GetPolicyVersion`

```bash
aws iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/PowerUserAccess \
  --version-id v3
```

**Returns:** The actual IAM policy JSON — the `Effect`, `Action`, `Resource`, and `Condition` blocks that define what is allowed or denied.

```json
{
  "PolicyVersion": {
    "Document": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "ec2:*",
            "s3:*"
          ],
          "Resource": "*"
        },
        {
          "Effect": "Deny",
          "Action": "iam:*",
          "Resource": "*"
        }
      ]
    }
  }
}
```

### 4c. Get Inline Policy Document (User): `iam:GetUserPolicy`

```bash
aws iam get-user-policy --user-name myuser --policy-name CustomS3Access
```

### 4d. Get Inline Policy Document (Role): `iam:GetRolePolicy`

```bash
aws iam get-role-policy --role-name myrole --policy-name CustomS3Access
```

### 4e. Get Inline Policy Document (Group): `iam:GetGroupPolicy`

```bash
aws iam get-group-policy --group-name Developers --policy-name CustomS3Access
```

**Returns:** The policy document JSON directly (no version ID needed for inline policies).

---

## Phase 5 — Check Permission Boundaries

### 5a. `iam:GetUser` (for users)

```bash
aws iam get-user --user-name myuser
```

**Returns:** Full user object including `PermissionsBoundary` if one is set.

```json
{
  "User": {
    "UserName": "myuser",
    "PermissionsBoundary": {
      "PermissionsBoundaryType": "Policy",
      "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/DevBoundary"
    }
  }
}
```

### 5b. `iam:GetRole` (for roles)

```bash
aws iam get-role --role-name myrole
```

**Returns:** Full role object including `PermissionsBoundary` and `AssumeRolePolicyDocument` (trust policy — who can assume this role).

### 5c. `iam:GetGroup` (for groups)

```bash
aws iam get-group --group-name Developers
```

> **Important:** A permission boundary acts as a ceiling. Even if the identity policy allows `*`, the boundary caps the effective permissions. You must retrieve and parse the boundary policy document (via `GetPolicyVersion`) to understand the true upper bound.

---

## Phase 6 — Enumerate Resource-Based Policies Referencing This Principal

Resource-based policies on other services can grant additional access **to** this principal. These are not visible through IAM APIs — you must query each service.

### 6a. S3 Bucket Policies: `s3:GetBucketPolicy`

```bash
aws s3api list-buckets
# For each bucket:
aws s3api get-bucket-policy --bucket my-bucket
```

**Returns:** The bucket policy JSON. Look for `Principal` entries matching your identity ARN.

### 6b. Lambda Resource Policies: `lambda:GetPolicy`

```bash
aws lambda list-functions
# For each function:
aws lambda get-policy --function-name my-function
```

**Returns:** The resource policy (permission to invoke the function), which may reference your principal.

### 6c. KMS Key Policies: `kms:GetKeyPolicy`

```bash
aws kms list-keys
# For each key:
aws kms get-key-policy --key-id KEY_ID --policy-name default
```

### 6d. SQS Queue Policies: `sqs:GetQueueAttributes`

```bash
aws sqs list-queues
# For each queue:
aws sqs get-queue-attributes --queue-url URL --attribute-names Policy
```

### 6e. SNS Topic Policies: `sns:GetTopicAttributes`

```bash
aws sns list-topics
# For each topic:
aws sns get-topic-attributes --topic-arn ARN
```

### 6f. Secrets Manager: `secretsmanager:GetResourcePolicy`

```bash
aws secretsmanager list-secrets
# For each secret:
aws secretsmanager get-resource-policy --secret-id SECRET_ID
```

### 6g. ECR Repository Policies: `ecr:GetRepositoryPolicy`

```bash
aws ecr describe-repositories
# For each repo:
aws ecr get-repository-policy --repository-name REPO
```

### 6h. Lambda Layer / API Gateway / Step Functions / etc.

Similar pattern: `apigateway get-rest-api`, `states describe-state-machine`, etc.

---

## Phase 7 — Check SCPs and Session Policies (If Accessible)

### 7a. SCPs: `organizations:ListPoliciesForTarget`

```bash
aws organizations list-policies-for-target \
  --target-id ACCOUNT_ID \
  --filter SERVICE_CONTROL_POLICY
```

**Returns:** SCPs applied to the account or OU. SCPs can only restrict — they never grant — but they may block actions you thought you had.

> This call typically requires `organizations:*` permissions from a management or delegated admin account.

### 7b. Session Policies

If the credentials are an assumed-role session, the session policy was applied at `sts:AssumeRole` time. You cannot query it directly after the fact. You can infer it by testing whether actions succeed.

---

## Phase 8 — Enumerate Cross-Account Assume-Role Opportunities

### 8a. `iam:ListRoles` (within this account)

```bash
aws iam list-roles
```

**Returns:** All roles in the account with their trust policies (via `AssumeRolePolicyDocument`). Look for `Principal` entries matching your identity — these are roles you can potentially assume.

### 8b. `sts:AssumeRole` (test each candidate)

```bash
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/CrossAccountRole \
  --role-session-name test
```

**Returns:** Temporary credentials for the assumed role if permitted, or `AccessDenied` if not.

### 8c. `iam:ListRoles` in other accounts (if you have cross-account access)

```bash
aws iam list-roles --profile other-account
```

---

## Phase 9 — Brute-Force Permission Testing (Dynamic Enumeration)

Static policy analysis may miss the effects of conditions, SCPs, service control policies, resource policies, and permission boundaries. The only way to confirm is to **test**.

### 9a. Test read-only calls across services

```bash
# S3
aws s3 ls
aws s3api list-buckets

# EC2
aws ec2 describe-instances
aws ec2 describe-vpcs
aws ec2 describe-subnets

# IAM
aws iam list-users
aws iam list-roles
aws iam list-policies --scope Local

# Lambda
aws lambda list-functions

# DynamoDB
aws dynamodb list-tables

# Secrets Manager
aws secretsmanager list-secrets

# CloudWatch
aws cloudwatch describe-alarms

# CloudFormation
aws cloudformation describe-stacks

# RDS
aws rds describe-db-instances

# SSM
aws ssm describe-parameters
```

### 9b. Test write calls (carefully, in a non-production account)

```bash
# Test if you can create resources
aws iam create-user --user-name test-perm-check
aws s3 mb s3://perm-check-bucket-$(date +%s)
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro
```

### 9c. Use a dedicated enumeration tool

```bash
# enumerate-iam (brute-forces API calls against a permission wordlist)
git clone https://github.com/iann0036/enumerate-iam.git
cd enumerate-iam
pip install -r requirements.txt
python main.py
```

```bash
# Pacu (AWS exploitation framework with enumeration modules)
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
python3 pacu.py
Pacu > exec Module: iam__enum_users_roles_policies_groups
Pacu > exec Module: iam__enum_permissions
```

---

## Phase 10 — Synthesize and Analyze

### 10a. Merge all policy documents

Combine:
- Attached managed policies (Phase 2)
- Inline policies (Phase 3)
- Permission boundary (Phase 5)
- Resource-based policies (Phase 6)
- SCPs (Phase 7)

### 10b. Apply IAM evaluation logic

The effective permissions are determined by:

```
1. Explicit DENY anywhere → DENY (always wins)
2. SCP must allow → otherwise DENY
3. Permission boundary must allow → otherwise DENY
4. Session policy must allow → otherwise DENY
5. Resource policy must allow OR identity policy must allow → ALLOW
6. Default → implicit DENY
```

### 10c. Produce a findings report

```json
{
  "principal": "arn:aws:iam::123456789012:user/myuser",
  "account": "123456789012",
  "attached_managed_policies": [
    "arn:aws:iam::aws:policy/PowerUserAccess"
  ],
  "inline_policies": ["CustomS3Access"],
  "permission_boundary": "arn:aws:iam::123456789012:policy/DevBoundary",
  "groups": ["Developers"],
  "effective_permissions": {
    "allowed_actions": ["ec2:*", "s3:*", "lambda:*"],
    "denied_actions": ["iam:*"],
    "assumable_roles": ["arn:aws:iam::123456789012:role/CrossAccountRole"],
    "resource_policy_grants": ["s3:GetObject on bucket shared-data"]
  }
}
```

---

## Quick Reference: Complete Call Sequence

| # | API Call | CLI Command | Returns |
|---|---|---|---|
| 1 | `sts:GetCallerIdentity` | `aws sts get-caller-identity` | Account, Arn, UserId |
| 2 | `iam:ListAttachedUserPolicies` | `aws iam list-attached-user-policies --user-name X` | Managed policy ARNs |
| 3 | `iam:ListGroupsForUser` | `aws iam list-groups-for-user --user-name X` | Group names/ARNs |
| 4 | `iam:ListAttachedGroupPolicies` | `aws iam list-attached-group-policies --group-name X` | Managed policy ARNs |
| 5 | `iam:ListUserPolicies` | `aws iam list-user-policies --user-name X` | Inline policy names |
| 6 | `iam:ListGroupPolicies` | `aws iam list-group-policies --group-name X` | Inline policy names |
| 7 | `iam:GetPolicy` | `aws iam get-policy --policy-arn X` | Policy metadata + version ID |
| 8 | `iam:GetPolicyVersion` | `aws iam get-policy-version --policy-arn X --version-id Y` | Policy document JSON |
| 9 | `iam:GetUserPolicy` | `aws iam get-user-policy --user-name X --policy-name Y` | Inline policy JSON |
| 10 | `iam:GetGroupPolicy` | `aws iam get-group-policy --group-name X --policy-name Y` | Inline policy JSON |
| 11 | `iam:GetUser` | `aws iam get-user --user-name X` | Permission boundary |
| 12 | `iam:GetGroup` | `aws iam get-group --group-name X` | Group details |
| 13 | `iam:ListRoles` | `aws iam list-roles` | Roles + trust policies |
| 14 | `s3:GetBucketPolicy` | `aws s3api get-bucket-policy --bucket X` | S3 resource policy |
| 15 | `lambda:GetPolicy` | `aws lambda get-policy --function-name X` | Lambda resource policy |
| 16 | `kms:GetKeyPolicy` | `aws kms get-key-policy --key-id X --policy-name default` | KMS key policy |
| 17 | `sts:AssumeRole` | `aws sts assume-role --role-arn X --role-session-name Y` | Cross-account creds or AccessDenied |
| 18 | Dynamic tests | Various `aws <service> <read/write>` calls | Success or AccessDenied |