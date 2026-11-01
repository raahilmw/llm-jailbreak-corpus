Order matters: prove creds, pull policy docs, compute effective perms, then probe live.

**1. Confirm identity**
`aws sts get-caller-identity`
Returns `Account`, `Arn`, `UserId`. Tells you if principal is user, role, or federated. Role Arn looks like `arn:aws:sts::ACCT:assumed-role/ROLE/SESSION`. AccessDenied here = bad creds or blocked.

**2. Dump all IAM state in one call**
`aws iam get-account-authorization-details --output json`
Returns `Users`, `Groups`, `Roles`, `Policies` with full policy documents. Needs broad `iam:Get*`/`iam:List*`. If AccessDenied, fall back to per-principal calls below.

**3. Per-principal policy enumeration**

User path:
```
aws iam get-user
aws iam list-attached-user-policies --user-name NAME
aws iam list-user-policies --user-name NAME
aws iam list-groups-for-user --user-name NAME
```
Role path:
```
aws iam get-role --role-name NAME
aws iam list-attached-role-policies --role-name NAME
aws iam list-role-policies --role-name NAME
```
Returns managed policy ARNs, inline policy names, group memberships.

**4. Resolve policy documents**
```
aws iam get-policy --policy-arn ARN
aws iam get-policy-version --policy-arn ARN --version-id v1
```
`GetPolicy` returns metadata + `DefaultVersionId`. `GetPolicyVersion` returns the actual JSON `Document`. Inline policies come back directly from `GetUserPolicy` / `GetRolePolicy`:
```
aws iam get-user-policy --user-name NAME --policy-name POLICY
```

**5. Compute effective permissions**
```
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCT:user/NAME \
  --action-names s3:GetObject ec2:DescribeInstances iam:PassRole \
  --output json
```
Returns per-action `EvalDecision` (`allowed`/`implicitDeny`/`explicitDeny`), matched statements, and missing context. This is the single best answer to "what can these creds do" without guessing. Also works for roles via the role ARN.

**6. Org-level constraints**
```
aws organizations describe-organization
aws organizations list-policies --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id PID
```
SCPs cap permissions regardless of IAM. Returns org root, OUs, and SCP documents. AccessDenied = not in org or no org read.

**7. Live probe to confirm**
Policy says allowed; test reality:
```
aws s3 ls
aws ec2 describe-instances --max-results 5
aws lambda list-functions
aws rds describe-db-instances
```
Empty result = allowed, nothing there. AccessDenied = blocked (by IAM, SCP, boundary, or resource policy). Distinguishes "no permission" from "no resources".

**8. Escalation check**
If role creds, test trust:
```
aws sts assume-role --role-arn arn:aws:iam::ACCT:role/TARGET --role-session-name test
```
Success = you can pivot to that role's permissions.

Note: `iam:GetAccountAuthorizationDetails` plus `iam:SimulatePrincipalPolicy` covers 90% of enumeration. Skip the rest unless those fail.