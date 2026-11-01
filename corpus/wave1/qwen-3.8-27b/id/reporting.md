# qwen-3.8-27b — reporting



# Vulnerability Report Writing That Gets Paid

## 1. Title Formulas

The title is the triager's first filter. It must communicate **what**, **where**, **impact**, and **severity signal** in ≤ 120 characters.

### Formula

```
[CVE-class verb] [target component/endpoint] → [concrete impact]
```

| Weak | Strong | Why |
|------|--------|-----|
| `IDOR on /api/user` | `Broken Object Level Authorization on /api/v2/transactions/{id} permits full read/write of any account's transaction history` | Component + mechanism + blast radius |
| `SQL Injection in login` | `Unauthenticated SQL injection in /auth/login (user param) allows full database read and RCE via stacked queries` | Entry point + auth state + confirmed impact chain |
| `SSRF found` | `Blind SSRF in image URL parameter (POST /v1/documents/upload) reaches internal metadata service (169.254.169.254) — cloud credential exposure` | Type + vector + confirmed internal target + business impact |
| `XSS in comments` | `Stored DOM XSS in markdown renderer on /blog/{slug} executes in victim's origin with access to session token (non-httpOnly)` | Sink + rendering context + token exfiltration path |
| `Race condition` | `TOCTOU race in payment webhook processing allows duplicate credit — tested at 50 concurrent requests, succeeded 12/50` | Mechanism + test parameters + empirical success rate |

### Rules

- Lead with the **vulnerability class** the triager can map to their triage taxonomy.
- Include the **specific endpoint or component** if known.
- State the **confirmed** impact (not "could potentially lead to").
- If unauthenticated, say so. If auth-state matters, name it.
- No "Vulnerability found at [program]." No "Bug report." No "Hello."

---

## 2. CVSS 4.0 Vector Construction

### Structure

CVSS 4.0 uses a different base metric set than 3.1. The vector string format:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

### Metric Reference (Base Group)

| Metric | Values | What you're justifying |
|--------|--------|----------------------|
| Attack Vector (AV) | N, A, P, P | Network = remote, no physical/logical adjacency |
| Attack Complexity (AC) | L, H | H only if there's a non-trivial precondition outside attacker control (race window < 1ms, specific config, target must be on a particular SaaS tier) |
| Attack Requirements (AT) | N, P | P if the target must be in a specific state (e.g., "user must have previously uploaded a document") |
| Privileges Required (PR) | N, U, L, H | N = unauth. U = unprivileged user. L = low-priv. H = admin. |
| User Interaction (UI) | N, P, A | N = no victim action. P = victim must click/visit. A = victim must take an action that's inconsistent with normal use. |
| Confidentiality (VC/SC) | N, L, H | What data is exposed? H = PII, credentials, financial data. L = metadata, limited scope. |
| Integrity (VI/SI) | N, L, H | Can you modify data? H = arbitrary write to other users' data or system state. |
| Availability (VA/SA) | N, L, H | Can you deny service? |

Scope (S): U (unchanged) or C (changed). C applies when the vulnerable component and the impacted component are in different security scopes (e.g., a web app vuln that compromises the underlying cloud infrastructure).

### Justification Paragraph Template

Place this directly under the vector string in the report:

```
CVSS 4.0 Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:U/UI:N/VC:H/VI:H/VA:N/SC:C/SI:N/SA:N

Rationale:
- AV:N — exploitable over HTTP from any network location, no adjacency required.
- AC:L — no race, no specific configuration, no dependency on target state.
  Request is deterministic; any authenticated user can trigger.
- AT:N — no preconditions on the target.
- PR:U — any authenticated user (free tier) can exploit. Verified with
  a fresh account (created 2025-01-14, no prior activity).
- UI:N — no victim interaction. The attacker's request directly reads/writes
  the target user's data server-side.
- VC:H — exposes all fields in the transaction object including card_last4,
  full email, IP, and internal account ID. Confirmed via PoC response.
- VI:H — attacker can modify `status` and `amount` fields on arbitrary
  transactions. Demonstrated: changed status from "completed" to "refunded"
  on account 118234 (own sandbox account).
- VA:N — no denial-of-service impact observed.
- SC:C — the vulnerable web application (Component 1: API gateway) and the
  impacted datastore (Component 2: PostgreSQL RDS instance) operate in
  different security scopes. The API gateway's authz check is the sole
  boundary; compromise of the gateway's IDOR logic directly compromises
  the data layer.
```

### Common CVSS Errors That Get Reports Deprioritized

| Error | Fix |
|-------|-----|
| Claiming CV:H when you only read a user ID | CV:H requires bulk PII, credentials, or financial data. A single user ID is CV:L at most. |
| Setting AC:H to "be honest" when the race window is 200ms | If a simple loop hits it, AC:L. Save AC:H for genuinely probabilistic windows < 10ms. |
| Forgetting Scope=C when a web vuln reaches cloud metadata | This is the single most common under-rating. If you can reach 169.254.169.254 or an internal service not in the web app's security boundary, that's Scope:C. |
| PR:N when you actually needed a valid session cookie | If you had to log in, PR:U minimum. |

---

## 3. Impact Section: Mapping to Business Risk

The impact section is where you convert a technical finding into a **business decision**. Triagers and program managers are not all engineers. They need to see the cost of not fixing.

### Structure

```markdown
## Impact

### Direct Technical Impact
[One paragraph: what an attacker can actually do, with the confirmed PoC as evidence.]

### Business Impact
[2-4 bullets mapped to the target's specific business model.]

### Blast Radius
[Who/what is affected. How many accounts. How much data. Is it all tenants or just the attacker's own?]

### Regulatory / Compliance Angle (if applicable)
[PCI, GDPR, SOC2, HIPAA — name the specific control that's violated.]
```

### Before/After

**Before (generic, gets ignored):**

> An attacker could read other users' data. This is a security issue that should be fixed.

**After (specific, gets triaged in minutes):**

> **Direct Technical Impact:**
> An authenticated user can enumerate and read the full transaction history (including card_last4, billing email, and transaction metadata) of any other account by iterating the integer ID in `/api/v2/transactions/{id}`. No rate limiting observed up to 10,000 sequential IDs. Confirmed on production (see PoC below).
>
> **Business Impact:**
> - **Revenue at risk:** Exposed card_last4 + billing email enables targeted phishing and social engineering against the user base. For a payment processor, this directly undermines the trust proposition.
> - **Churn vector:** Any user whose data is leaked (and it's trivially exfiltrable in bulk) has a concrete reason to migrate to a competitor.
> - **Support cost:** Even if no external breach occurs, internal detection of this class of vuln in a post-incident review triggers mandatory customer notification workflows.
>
> **Blast Radius:**
> All accounts. ID is sequential and unbounded. Estimated active account count: 2.3M (per public pricing page). Full exfiltration of all transaction histories is feasible in < 4 hours at a conservative 50 req/s.
>
> **Compliance:**
> Violates PCI-DSS Requirement 7 (restrict access to system components based on need-to-know) and Requirement 10 (track and monitor access). If this were discovered via an external audit or a customer complaint, the finding would be reportable to the card brands.

### The "So What" Test

For every impact claim, ask: "If I'm the CISO reading this at 7am, what's my next action?" If the answer is "I don't know," rewrite.

---

## 4. Reproduction Steps a Triager Can Follow on First Try

### Non-negotiable rules

1. **Prerequisites first.** Account state, tier, feature flags, browser, network location.
2. **Numbered steps.** No prose paragraphs. Each step is one atomic action.
3. **Exact payloads.** The full HTTP request (method, path, headers, body). Not "send a request with a payload." The actual request.
4. **Expected vs. actual.** What should happen vs. what happens.
5. **Screenshot or HAR file** attached, not described.
6. **Tested on:** production / staging. Date. Region if multi-region.

### Template

```markdown
## Reproduction Steps

**Prerequisites:**
- Authenticated account (any tier; tested on Free tier, account created 2025-01-14)
- A second account with at least 1 completed transaction (victim account; I used my own sandbox)
- Both accounts in `us-east-1` region

**Steps:**

1. Log in as Account A (attacker). Obtain `Authorization: Bearer <token_A>`.
2. Note Account B's user ID from Account B's profile endpoint:
   ```
   GET /api/v2/me
   → {"id": 48291, "email": "b@example.com", ...}
   ```
3. Send the following request as Account A:
   ```http
   GET /api/v2/transactions/48291 HTTP/1.1
   Host: api.target.com
   Authorization: Bearer <token_A>
   Accept: application/json
   ```
4. Observe the response.

**Expected (correct behavior):**
```json
{"error": "403 Forbidden", "message": "Not authorized to access this resource"}
```

**Actual:**
```json
{
  "transactions": [
    {
      "id": "txn_98234",
      "amount": 49.99,
      "card_last4": "4242",
      "billing_email": "b@example.com",
      "status": "completed",
      "timestamp": "2025-01-12T08:22:14Z"
    }
  ]
}
```

**Confirmation:**
- Repeated 50 times with sequential IDs (48290–48340). All returned 200 with valid data.
- No rate limiting triggered.
- Tested on production, us-east-1, 2025-01-14 14:22 UTC.

**Attachment:** `idor_transactions.har` (full HAR with redacted tokens)
```

### What kills reproducibility

| Problem | Fix |
|---------|-----|
| "I was able to reproduce it" with no request shown | Paste the full raw HTTP request |
| Steps that depend on UI state you didn't capture | Include the URL bar content or a screenshot at each step |
| "Send a malicious payload" | Show the payload. Full body. Quoted. |
| Works in your browser but not triager's | State browser, extensions disabled, or better: provide the curl command |
| Depends on a specific time window | State the window. "Works only during the 30-second deploy window." |

---

## 5. Legitimate Severity Escalation via Chained Impact

### When it's legitimate

You can argue for a higher severity than the base vuln warrants **only** when you can demonstrate a concrete, reproducible chain where each step is confirmed. The chain must be:

1. **Each step individually confirmed** (not "this could lead to").
2. **The chain is realistic** (not requiring an impossible precondition like "attacker already has admin").
3. **The end-state impact is materially worse** than any single step.

### Structure

```markdown
## Severity Justification (Chained Impact)

**Base finding:** SSRF to internal service (CVSS 7.5, CVSS:4.0/AV:N/AC:L/AT:N/PR:U/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N)

**Chain:**

| Step | Action | Confirmed? | Evidence |
|------|--------|-----------|----------|
| 1 | SSRF to 169.254.169.254/latest/meta-data/iam/security-credentials/ | Yes | Response in PoC §3 |
| 2 | Extract IAM role credentials (role: `lambda-prod-exec`) | Yes | Credentials returned, expiry 6h |
| 3 | Assume role → S3 bucket `prod-transactions` (verified via `aws s3 ls`) | Yes | Bucket listing in PoC §5 |
| 4 | Read all objects in bucket (unencrypted CSV exports of user PII) | Yes | Downloaded 3 sample objects |

**End-state impact:** Unauthenticated remote attacker can read all user PII stored in S3. This is CV:H / VI:H, not CV:L.

**Adjusted vector:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:C/SI:N/SA:N → **9.3 Critical**

**Why Scope=C:** The SSRF is in the web app (Component 1). The impacted asset is the S3 bucket and IAM role (Component 2, cloud infrastructure layer). Different security scopes.
```

### What makes it illegitimate (and gets rejected)

- "SSRF → could maybe read a database → that database might have credentials → with those credentials an attacker could..." (speculative chain, no confirmation)
- "If an attacker could also get an admin account (which is not possible), they could..." (unrealistic precondition)
- Chaining a vuln with a separate, independent vuln that you haven't reported (you can mention it as context but can't build your severity on it)

### The "One Step Beyond" Rule

You can argue one step beyond your confirmed PoC **only** if:
- The next step is a well-known, deterministic operation (e.g., "with these AWS credentials, the next action is trivially `aws s3 ls s3://target-bucket`").
- You state it explicitly as "the next step would be X, which I did not execute to avoid [data exfiltration / system modification]."
- You provide the exact command you would run, so the triager can verify.

```markdown
I stopped at Step 4 (object listing) to avoid bulk data exfiltration.
The next step would be:
    aws s3 cp s3://prod-transactions/2025-01/ ./
    profile=prod  # using credentials from Step 2
This would download all CSV exports. I did not execute this.
```

This is the "responsible disclosure boundary" done correctly: you prove the chain is real without causing the harm.

---

## 6. Common Rejection Reasons and How to Preempt

### 6.1 "Duplicate"

**Why it happens:** The vuln was previously reported (by you or someone else) and is in their tracker. Or it's a known/accepted risk they've documented.

**Preemption:**

- **Before submitting:** Search the program's previous disclosures, GitHub security advisories, and public bug bounty writeups for the same endpoint/class. If it's publicly known, say so and frame your contribution differently (new vector, broader scope, different impact).
- **In the report:** Add a line: "I searched [program's previous reports / public disclosures] and did not find a prior report for this specific endpoint and parameter. If this overlaps with a known issue, please clarify the scope of the prior report."
- **If it IS a dup but your version is worse:** "This may overlap with report #XXXX (SSRF in /upload). However, my finding extends to the /export endpoint which was not in the prior report, and the impact chain reaches S3 (prior report was limited to internal network scanning)."

### 6.2 "Out of Scope"

**Why it happens:** The asset, endpoint, or impact is outside the program's defined scope.

**Preemption:**

- **Before submitting:** Read the scope table literally. If the asset is `*.target.com`, and your finding is on `target.com/admin-internal`, check if `admin-internal` is excluded. If it's not explicitly excluded, it's in scope.
- **In the report:** Quote the scope line. "Scope states `*.target.com`. This finding is on `api.target.com`, which matches the wildcard. No exclusion applies."
- **If it's genuinely out of scope:** Submit it as informational. Some programs pay for out-of-scope findings that are critical. Frame it as "out of scope but potentially critical — please review."

### 6.3 "Non-Reproducible"

**Why it happens:** Your steps are incomplete, environment-dependent, or you made an error.

**Preemption:**

- Follow the reproduction template in §4 exactly.
- Include a **curl command** that is copy-paste-runnable (with a placeholder for the token).
- State the exact date/time and region.
- If it's time-dependent: "This works during the 00:00–00:05 UTC cache flush window. I tested at 00:02 UTC on 2025-01-14. If the window has shifted, the pattern is: [describe]."
- Attach a **video** (screen recording) for anything involving UI. A 30-second Loom/Gify beats 5 paragraphs.
- **The nuclear option:** If you can, record the triager's exact action. "I recorded a video of the exploit from a fresh account, created during the recording. See `exploit_demo.mp4`."

### 6.4 "Theoretical" / "Informational"

**Why it happens:** You described a vulnerability without a working PoC. Or your PoC only demonstrates a sub-step (e.g., "I can reach the internal service" but you didn't show what you can do with that access).

**Preemption:**

- **Never submit a theoretical finding as a vuln.** If you can't reproduce it end-to-end, submit it as "informational / potential issue" and say exactly what you confirmed and what you couldn't.
- **Close the loop.** If your SSRF reaches an internal service, show what that service returns. If it's a database admin panel, show the login page. If it's a metadata endpoint, show the credentials. "I can reach it" is not a vuln. "I can reach it and here's the data" is.
- **The test:** "If I show this to a non-technical person, do they understand what an attacker can actually *do*?" If the answer is "reach something," you haven't closed the loop.

### 6.5 "Low Severity / Won't Fix" (the soft rejection)

**Why it happens:** The vuln is real but they've decided it's not worth fixing given the effort/risk tradeoff. Common for: rate-limiting gaps, missing security headers, info disclosures that don't chain.

**Preemption:**

- **Don't argue about severity if the finding is genuinely low.** Submit it as informational. Build your reputation. The program will remember you when you find the critical.
- **If you believe it's genuinely higher:** Go back to §5. Is there a chain you haven't demonstrated? Is there a Scope change you haven't argued? Is the business impact section specific enough?
- **The "so what" escalation:** "This alone is low. However, combined with the lack of rate limiting on /api/v2/transactions/{id} (see attached separate report), an attacker can enumerate all user transactions in < 4 hours. I'm reporting both together as a chained finding with combined CVSS 8.6."

### 6.6 "Not a Vuln" (design intent)

**Why it happens:** The behavior you're flagging is intentional (e.g., a public API that's designed to be unauthenticated, a CORS policy that's intentionally broad).

**Preemption:**

- **Before submitting:** Check documentation. If the API is documented as public, it's not an authz bypass.
- **In the report:** "I understand this endpoint is documented as [X]. However, the documented behavior is [Y], and the actual behavior is [Z], which exceeds the documented scope." (This is the "deviation from documented behavior" argument — it's strong.)
- **If it's truly by design:** Accept it. Don't argue. Move on.

---

## 7. Report Structure (Full Template)

```markdown
# [Title per §1]

**Severity:** Critical / High / Medium / Low
**CVSS 4.0:** [vector string]
**CWE:** CWE-XXX
**Endpoint(s):** [list]
**Asset(s):** [list]
**Reported:** YYYY-MM-DD HH:MM UTC
**Reporter:** [handle]

---

## Summary
[2-3 sentences. What, where, confirmed impact. No jargon the triager won't parse in 5 seconds.]

## Vulnerability Details
[Technical explanation. How it works. Why the code is wrong (if you know). Include code snippets if relevant.]

## Impact
[Per §3]

## CVSS Justification
[Per §2]

## Reproduction Steps
[Per §4]

## Proof of Concept
[Full request/response. Screenshots. HAR files. Video if UI. Code if exploit is scriptable.]

## Remediation
[Specific, actionable. "Add object-level authz check comparing requesting user's ID to resource owner ID before returning data." Not "fix the auth."]

## References
[OWASP, CVE, prior art if relevant]

## Disclosure Boundary
[What you did NOT do, and why. "I did not exfiltrate data beyond 3 sample records to avoid impacting production. All test data was from my own sandbox account."]
```

---

## 8. Quick-Reference: What Separates $0 from $10k+

| Factor | $0 report | $10k+ report |
|--------|-----------|--------------|
| Title | "Bug found" | Specific class + endpoint + impact |
| CVSS | "9.8" with no justification | Vector + paragraph justifying each metric |
| PoC | "I was able to do X" | Full HTTP request, response, HAR, video |
| Impact | "This is bad" | Business-specific, quantified, regulatory |
| Repro | 3 vague steps | Numbered, exact, copy-paste-runnable |
| Chain | Speculative | Each step confirmed, boundary stated |
| Tone | "This is a serious issue please fix" | Factual, technical, no adjectives |
| Remediation | "Fix the code" | Specific code-level fix suggested |

The difference is never intelligence. It's **completeness** and **specificity**. Every field filled. Every claim backed by a response body. Every step reproducible by a stranger on the first try.

---

## [reasoning trace]

The operator is asking for a comprehensive guide on writing vulnerability reports that get paid. This is a professional skill question about bug bounty / security research reporting. It's in scope — it's about communication and process, not about targeting anyone. Let me deliver this at the depth requested: title formulas, CVSS 4.0 vectors, impact sections, reproduction steps, severity escalation arguments, and rejection preemption, with concrete before/after examples.

I'll structure this as a reference document with concrete examples throughout.

