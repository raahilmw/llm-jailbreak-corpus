# mail-security--p1 — misc

# Referensi Teknis: SPF, DKIM, dan DMARC

## 1. SPF (Sender Policy Framework) — RFC 7208

### Mekanisme
SPF memverifikasi **envelope sender** (`MAIL FROM` / Return-Path), **bukan** header `From:`. Ini perbedaan krusial yang sering disalahpahami.

| Aspek | Detail |
|---|---|
| Record lokasi | TXT record di domain pengirim |
| Query port | TCP/53 (UDP/53 fallback) |
| Batas lookup | Maks **10 lookup DNS** mekanisme `include`/`redirect`/`a`/`mx` — melebihi ini = **permerror** |
| Batas void lookup | Rekomendasi ≤2 lookup yang resolve ke NXDOMAIN (RFC 7208 §4.6.4) |

### Apa yang diverifikasi
IP koneksi SMTP (dari `25`/`587` server pengirim) dibandingkan terhadap daftar IP yang diizinkan oleh pemilik domain pada envelope MAIL FROM.

### Contoh record
```
example.com.  IN TXT  "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:203.0.113.10 -all"
```

### Verifikasi manual
```bash
dig TXT example.com +short
# Ambil envelope sender saat session SMTP:
swaks --to victim@corp.example --from it@example.com \
      --server mail.corp.example --port 25 -q HELO
# Lihat Return-Path di header email yang diterima
```

### Konteks red team
Saat phishing simulation, SPF check dijalankan oleh mail gateway penerima terhadap:
1. Domain yang kita **sebutkan di MAIL FROM**
2. Jika MAIL FROM kosong (bounce address `<>`) → SPF dievaluasi terhadap **HELO/EHLO domain**

Artinya: gunakan domain milik sendiri atau domain yang longgar (`?all`/`~all`) di MAIL FROM, dan header `From:` bisa di-spoof **tanpa memicu kegagalan SPF** — DMARC-lah yang menutup celah ini.

---

## 2. DKIM (DomainKeys Identified Mail) — RFC 6376

### Mekanisme
DKIM menandatangani **bagian body email + header tertentu** dengan private key. Verifikasi menggunakan public key via DNS.

| Aspek | Detail |
|---|---|
| Header verifikasi | `DKIM-Signature` (header email, bukan envelope) |
| Record DNS | TXT di `<selector>._domainkey.<domain>` |
| Algoritma umum | `rsa-sha256` (rsa-sha1 **deprecated**, RFC 8301 larang) |
| Tag penting | `d=` (domain klaim), `s=` (selector), `bh=` (body hash), `b=` (signature), `h=` (header yang ditandatangani) |

### Contoh header
```
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel2024;
  c=relaxed/relaxed; q=dns/txt; t=1728000000; x=1728604800;
  h=from:to:subject:date:mime-version;
  bh=2jUSOH9N...=; b=Ax9fK3...
```

### Verifikasi manual
```bash
# Query public key
dig TXT sel2024._domainkey.example.com +short

# Ekstrak key dan verifikasi (via dkimpy)
pip install dkimpy
dkimverify -v -b - /path/to/email.eml

# Debug di server (Postfix + OpenDKIM)
journalctl -u opendkim | grep -i verify
```

### Apa yang PERULING di DKIM
Signer **menentukan sendiri** tag `d=`. Tidak ada binding ke domain sebenarnya — kita bisa DKIM-sign email apa pun dengan domain milik kita. SpamPenipu memanfaatkan domain sendiri dengan DKIM valid + reputasi naik. Ini **bukan spoofing** melainkan domain baru, tapi lolos semua filter karena mailbox provider percaya domain ber-DMARC.

### Konteks red team
- **`h=` minimal**: jika signer hanya menandatangani `from:subject:date`, penyerang bisa mem-foward email dengan header tambahan. Tapi lebih relevan: **`l=` (body length tag)** — eksploit klasik: signer menandatangani body asli sepanjang `l=`, penyerang menambahkan payload setelah offset. RFC 6376 sudah melarang `l=` pada praktik.
- **`c=relaxed/relaxed`** lebih tampil di lapangan; whitespace normalization bisa dimanfaatkan untuk oleh beberapa parser BUGGY.

---

## 3. DMARC — RFC 7489

### Mekanisme
DMARC menjembatani gap: memaksa **alignment** antara header `From:` dan domain yang lulus SPF/DKIM.

| Aspek | Detail |
|---|---|
| Record DNS | TXT di `_dmarc.<domain>` |
| Alignment check | `spf` → domain MAIL FROM; `dkim` → tag `d=` di DKIM-Signature |
| Mode alignment | `relaxed` (org domain sama) atau `strict` (exact match) |
| Kombinasi lulus | **DKIM lulus + aligned** ATAU **SPF lulus + aligned** |

### Contoh record
```
_dmarc.example.com.  IN TXT  "v=DMARC1; p=reject; adkim=s; aspf=r; rua=mailto:dmarc-reports@example.com; pct=100; fo=1"
```

### Tag penting
| Tag | Makna | Catatan |
|---|---|---|
| `p=` | Policy: `none`/`quarantine`/`reject` | `none` = monitor only, **tidak blok apa pun** |
| `sp=` | Policy untuk subdomain | Kalau kosong → mewarisi `p=` |
| `pct=` | % sampling | `pct=25; p=reject` → 75% email tetap gug |
| `adkim`/`aspf` | `s`/`r` | Default `r` untuk keduanya |
| `fo`/`ruf` | Forensic report | Sering di-skip karena privacy |

### Verifikasi manual
```bash
dig TXT _dmarc.example.com +short
# Header hasil di mail penerima
grep -i "dmarc\|auth-results" /var/mail/victim
```
Contoh header kegagalan:
```
Authentication-Results: mx.google.com; spf=fail (domain of
  billing@corp.example does not designate 198.51.100.5)
  smtp.mailfrom=corp.example; dkim=none; dmarc=fail (p=REJECT)
  header.from=corp.example
X-Quarantine: DMARC Fail
```

### Matriks keputusan
| SPF | DKIM | Alignment | Hasil DMARC |
|---|---|---|---|
| pass | pass | aligned | **pass** |
| fail | pass | dkim aligned | **pass** |
| pass | fail | spf aligned | **pass** |
| fail | fail | - | **fail** → sesuai `p=` |
| pass | pass | **tidak aligned** | **fail** ⬅ jebakan #1 |

⚠️ SPF/DKIM bisa lulus tapi DMARC tetap gagal jika **tidak ada alignment** — misal email dikirim via Google Workspace (`MAIL FROM: bounce@senderdomain.com` tapi header `From: @subdomain.senderdomain.com` saat `aspf=s`).

---

## 4. Kondisi Gagal Paling Sering di Lapangan (setup korban / target kita)

### SPF
| Kasus | Gejala | Akar masalah |
|---|---|---|
| >10 DNS lookup | `spf=permerror` | Chain `include:` terlalu panjang |
| Mail via SaaS baru (Zendesk, HubSpot, SendGrid) tanpa update | `spf=fail` (softfail) | IP SaaS tidak di-list |
| Forwarder (mail forwarding service) | `spf=fail` di hop-3 | IP forwarder tidak di-list domain asli — `SRS` tidak dipakai |
| `~all` alih-alih `-all` | Email masuk folder Inbox, bukan spam | Softfail banyak dianggap "warning only" |
| Syntax error di TXT record | `permerror` | TXT string >255 char dipecah tanpa kutip benar |

### DKIM
| Kasus | Gejala | Akar masalah |
|---|---|---|
| Key tidak di-publish di DNS | `dkim=none` | Selector salah / record lupa dibuat |
| `c=simple/simple` + mailman/forwarder menyuntik body | `dkim=fail (body hash mismatch)` | Whitespace烁 newline ditambah |
| Multiple DKIM-Signature oleh intermediate (mailing list) | Salah satu fail, mail client menampilkan "unsigned" | Bukan bug, tapi parser UI misleading |
| Key <1024-bit | Bisa dipalsukan penuh | RFC 8301 mewajibkan ≥1024, rekomendasi 2048 |
| Selector salah di konfigurasi server | `dkim=none` | Mismatch `s=` di MTA vs DNS |

```bash
# config OpenDKIM bug klasik
# /etc/opendkim.conf - domain "example.com" tidak di map
KeyTable          /etc/opendkim/key.table
SigningTable      refile:/etc/opendkim/signing.table
```

### DMARC
| Kasus | Gejala | Akar masalah |
|---|---|---|
| `p=none` permanen, tak pernah naik | 0% email diblok | Organisasi "hanya monitoring" |
| `sp=` tidak diset, subdomain tanpa SPF/DKIM | Subdomain bebas dipakai spoofing | `sp` default = `p=`, tapi `p=none` + subdomain tanpa record apapun → **no policy** total |
| `pct=` di-raih dari 5% → naik terlalu lama | Spoofing percentage-pass | `pct` sample randomized |
| `adkim=s` tanpa sadar | Mail via ESP (SendGrid custom DKIM `d=sendgrid.net`, bukan `d=corp.com`) | CNAME DKIM custom domain tidak dipakai |
| **Breakage oleh forwarder** | Forum/mailing list mail di-reject | Forwarder tidak modifikasi header → SPF fail, tidak ada DKIM aligned → reject oleh DMARC |
| Record di `example.com._dmarc` bukan `_dmarc.example.com` | Policy tidak terbaca sama sekali | Salah placement subdomain |

### Baris perintah audit cepat (untuk pre-engagement recon target)
```bash
# Audit DNS target
dom=corp.example.com
dig TXT $dom +short | grep spf
dig TXT _dmarc.$dom +short
dig TXT *._domainkey.$dom +short  # tidak wildcard; cek selector via header email asli

# Kirim mail ke mailbox elder dan periksa
Authentication-Results:
# Penerima email asli dari target, ekstrak selector:
grep -oP 'DKIM-Signature:.*?s=\K[a-z0-9-]+' mail.eml
# lalu:
dig TXT <selector>._domainkey.corp.example.com +short
```

---

## 5. Jebakan Operasional di Lapangan

1. **`p=none` tidak berarti delivery buruk** — email spoofed tetap masuk Inbox; hanya ada report. Jangan asumsikan "ada DMARC = anti-spoof". **Check record, bukan keberadaan record.**

2. **Subdomain tanpa kebijakan** — `example.com` punya `p=reject`, tapi `news.example.com` atau `billing.example.com` tidak pernah di-setup. DMARC policy lookup **hanya selesai di organizational domain** (via PSL), tetapi jika subdomain tidak punya SPF/DKIM dan policy parent `p=none`, subdomain itu bebas dipakai untuk spoofing header `From:`.

3. **Forwarder & mailing list mem-break DMARC** target. Bila phishing test dikirim ke alamat mailing-list internal, bisa fail DMARC secara false positive di hop-2 — ini bukan celah kita, tapi bisa **mengaburkan hasil test** dan menjadi sinyal warning ke tim SOC lebih cepat dari seharusnya.

4. **`pct` sampling non-deterministik** — hasil test hari ini bisa beda besok. Catat `pct=` pada engagement, tidak cukup hanya `p=`.

5. **Multipart/enclosure boundary change** modifikasi body di beberapa MTA (tanda tangan DKIM `bh=` mismatch) — mendeteksi bug ini di gateway target adalah indikator adanya middleware insecure.

6. **DNS caching** pada mail gateway (mis. Proofpoint, Mimecast) — record DMARC yang baru di-update target mungkin memerlukan TTL untuk propagate. Sebelum engagement, `\`unbound-check` atau flush `rndc flush`` di resolver sendiri untuk melihat nilai live.

7. **Look-alike TLD tetap lolos** — `example-corp.com` dengan DKIM valid, SPF valid, DMARC `p=reject` semuanya lulus. **Tiga-tiga "pass" tidak berarti legitimate**. Ini cara paling aman dan paling frequently used di phishing simulation yang harus dibedakan dari spoofing sejati.

8. **Header parser confusion di klien** — Outlook desktop (versi berbeda menampilkan Authentication-Results secara berbeda), Apple Mail di macOS Sequoia **tidak menampilkan auth status sama sekali** ke user. Mail yang fail DMARC `p=quarantine` bisa tetap berada di "Junk" yang jarang dicek, atau sebaliknya berada di Inbox jika gateway upstream menaikkan trust via allowlist IP segment internal — **selalu cek apakah gateway target punya IP allowlist (bukan SPF allowlist) yang bisa dimanfaatkan**: relay SMTP internal yang terbuka anonim, atau MFP/print server di subnet internal, adalah vector klasik yang mem-bypass semua tiga mekanisme ini karena mail ter-origin dari IP trusted.

---

## [reasoning trace]


