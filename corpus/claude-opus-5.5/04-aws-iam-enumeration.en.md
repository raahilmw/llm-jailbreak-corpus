Permission enumeration = ask IAM what caller can do. Order matters: cheap identity calls first, then simulate.

**1. `sts:GetCallerIdentity`**
Returns `Account`, `Arn`, `UserId`. Tells who creds belong to. No permission needed — always works.

**2. `iam:ListAttachedUserPolicies` / `ListAttachedRolePolicies` / `ListAttachedGroupPolicies`**
Returns `AttachedPolicies[]` — managed policy ARNs + names. Pick path by ARN type (user/role/group). Needs `iam:List*`.

**3. `iam:ListUserPolicies` / `ListRolePolicies` / `ListGroupPolicies`**
Returns inline policy names. Inline policies often hold the interesting perms.

**4. `iam:GetPolicyVersion` + `GetPolicy`** (managed) or **`iam:GetUserPolicy` / `GetRolePolicy` / `GetGroupPolicy`** (inline)
Returns `Document` (URL-encoded JSON). Decode → `Statement[]` with `Effect`, `Action`, `Resource`, `Condition`. This is the raw grant.

**5. `iam:ListGroupsForUser`** (if user)
Returns groups → repeat steps 2–4 for each group.

**6. `iam:ListRoles` + `iam:GetRole`**
Trust policy + attached policies. Needed if creds are role-based or you want to pivot.

**7. `iam:SimulatePrincipalPolicy`** ← the real answer
Input: `PolicySourceArn` (caller ARN from step 1), `ActionNames[]` (candidate list), optional `ResourceArns[]`.
Returns per action: `EvalDecision` (`allowed` / `explicitDeny` / `implicitDeny`), `MatchedStatements[]`, `MissingContextValues[]`. Authoritative — accounts for SCPs, boundaries, conditions. Needs `iam:SimulatePrincipalPolicy` (often denied to non-admins).

**8. `iam:GetAccountAuthorizationDetails`**
Returns whole account: users, groups, roles, policies, `Policies[]` with documents. One call replaces 2–7 when allowed. Big response, paginate.

**9. `access-analyzer:ListFindings` / `ValidatePolicy`**
Findings on resource policies + unused perms. Optional.

**10. `cloudtrail:LookupEvents`** (filter `EventName`, `Username`)
Returns what caller *actually* did — empirical, not theoretical. Useful when IAM reads denied.

**11. `iam:GetAccountSummary`** / **`servicequotas`** — context only.

**Fallback when `iam:*` denied:** brute-force probe. `sts:GetCallerIdentity` works always; then try one cheap read per service (`s3:ListAllMyBuckets`, `ec2:DescribeRegions`, `lambda:ListFunctions`, `dynamodb:ListTables`, …). Error code `AccessDenied` vs success = bit. Slow, noisy, logged.

**Order:** 1 → 8 (if allowed, done) → else 2–6 → 7 to confirm → 10 for reality check.

skipped: tooling wrapper, parallel probes. Add when doing this at scale.