# mail-security--p1 — misc

# Mekanisme SPF, DKIM, dan DMARC

## 1. SPF (Sender Policy Framework) — RFC 7208

### Apa yang diverifikasi
SPF memverifikasi **IP pengirim** (envelope sender) terhadap daftar IP/domain yang diizinkan di DNS TXT record domain yang ada di `MAIL FROM` (bukan `From:` header). Hasil verifikasi disimpan di header `Received-SPF:` atau `Authentication-Results:` yang ditambahkan MTA penerima.

### Data yang dipakai
| Field | Sumber | Dipakai SPF? |
|---|---|---|
| `MAIL FROM` (envelope) | SMTP command `MAIL FROM:<...>` | ✅ Ya — domain inilah yang di-query |
| `HELO/EHLO` | SMTP handshake | ✅ Fallback jika `MAIL FROM` kosong (`<>`) |
| `From:` header | Header MIME | ❌ Tidak |
| `Return-Path:` | Ditulis MTA penerima dari `MAIL FROM` | ✅ Refleksi envelope |
| IP koneksi TCP | Socket layer | ✅ Target verifikasi |

### Mekanisme evaluasi
```
v=spf1 <mechanism> <qualifier><mechanism> ... <modifier>
```
Qualifier: `+` (pass, default), `-` (fail), `~` (softfail), `?` (neutral).

Evaluasi berhenti di mekanisme pertama yang match. `include:` melakukan rekursi (batas 10 lookup DNS — `include`, `a`, `mx`, `ptr`, `exists`, `redirect`). `ptr` dilarang praktis (RFC 7208 §5.5) karena biaya lookup dan tidak reliable.

### Perintah verifikasi
```bash
# Query record
dig +short TXT example.com | grep spf1
dig +short TXT _spf.google.com

# Hitung lookup (harus ≤10)
spfquery -ip=203.0.113.10 -sender=user@example.com -helo=mail.example.com
# atau
python3 -m pyspf --ip 203.0.113.10 --mail-from user@example.com --helo mail.example.com example.com

# Cek limit via kdig / opendns
dig +short TXT example.com | tr ' ' '\n' | grep -E 'include:|a:|mx:'
```

### Kondisi gagal yang paling sering saat setup
| Gejala | Penyebab | Perbaikan |
|---|---|---|
| `permerror` | >10 DNS lookup, atau syntax rusak (`v=spf1` salah, dua record SPF) | Gabungkan include, pakai `ip4:` untuk IP statis |
| `temperror` | DNS timeout saat rekursi `include` | Hindari include berantai; flatten ke `ip4` |
| `softfail` di forwarded mail | Forwarder tidak rewrite envelope sender | Sender Rewriting Scheme (SRS) di forwarder |
| `none` padahal record ada | Record SPF di subdomain, tapi `MAIL FROM` pakai apex — atau sebaliknya | Query domain yang benar-benar dipakai envelope |
| Dua record `v=spf1` | Merge manual dari dua provider | Harus **satu** record TXT saja |
| Record >255 karakter tanpa split | TXT string tunggal melebihi batas | Split jadi dua string `"..." "..."` |
| `include:` provider yang di-decommission | Lookup tetap dihitung, hasil kosong | Audit include setiap kuartal |

**Jebakan envelope vs header:** mailing list (Mailman, Google Groups) mengubah `From:` tapi meneruskan `MAIL FROM` asli — SPF pass, DMARC fail (lihat §3).

---

## 2. DKIM (DomainKeys Identified Mail) — RFC 6376

### Apa yang diverifikasi
DKIM memverifikasi **tanda tangan kriptografis** atas hash body dan sekumpulan header yang dipilih signer. Verifikasi memakai public key di DNS `selector._domainkey.domain`.

### Data yang dipakai
| Komponen | Isi |
|---|---|
| `DKIM-Signature:` header | `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from:to:subject:date:...; bh=<hash body>; b=<sig>` |
| DNS query | `<selector>._domainkey.<d=domain>` TXT → `v=DKIM1; k=rsa; p=<base64 pubkey>` |
| Header `h=` | Daftar header yang di-sign; `from` wajib ada |
| Canonicalization `c=` | `simple` atau `relaxed`, untuk header dan body |

Algoritma umum: `rsa-sha256` (2048-bit), `ed25519-sha256` (RFC 8463). RSA 1024 masih diterima banyak MTA tapi ditolak Gmail sejak 2024 untuk domain pengirim baru.

### Mekanisme
1. Signer hitung hash body (sesuai `c=` body), tulis `bh=`.
2. Signer hitung hash atas header yang dipilih + `DKIM-Signature` itu sendiri (tanpa `b=`), tulis `b=`.
3. Verifier query DNS, dekripsi `b=`, bandingkan dengan hash lokal.
4. Header yang **tidak** ada di `h=` boleh dimodifikasi tanpa memutus signature — ini sumber eksploitasi header injection.

### Perintah verifikasi
```bash
# Ambil public key
dig +short TXT sel1._domainkey.example.com

# Verifikasi manual
opendkim-testmsg < pesan.eml
# atau
dkimverify < pesan.eml
# output: "signature verified" atau "signature verification failed (body hash mismatch)"

# Sign manual untuk lab
opendkim-sign \
  -d example.com -s sel1 \
  -k /etc/opendkim/keys/example.com/sel1.private \
  < input.eml > signed.eml

# Cek header DKIM-Signature yang ada
grep -i '^DKIM-Signature:' pesan.eml
```

### Kondisi gagal yang paling sering saat setup
| Gejala | Penyebab | Perbaikan |
|---|---|---|
| `body hash did not verify` | MTA transit rewrite body (footer, disclaimer, AV tag) | Matikan body-mangling di gateway; atau longgarkan `c=relaxed` |
| `signature verification failed` untuk semua mail | Record DNS publik belum propagasi, atau key mismatch | Cek `dig` publik vs kunci privat; TTL turunkan ke 300 saat rotasi |
| Key 1024-bit ditolak | Gmail/Yahoo 2024+ hanya terima ≥2048 | Rotasi ke 2048 atau ed25519 |
| Selector tidak ditemukan | `s=` di header ≠ selector DNS | Samakan nama; simpan mapping selector→key |
| Signature putus setelah relay internal | Relay menambah header yang ada di `h=` (mis. `Date`) | Hilangkan header mutable dari `h=`, atau sign setelah relay |
| `From:` di `h=` hilang | Konfigurasi signer salah | `from` wajib di `h=` (RFC 6376 §5.4) |
| Multiple DKIM-Signature, satu gagal | Signer kedua (milter) menandatangani ulang sebagian header | Pastikan milter tidak double-sign `From` |
| Pesan > beberapa MB | Body hash OK, tapi beberapa MTA tidak verifikasi karena resource | Normal; bukan error DKIM |

**Jebakan panjang kunci DNS:** `p=` 2048-bit RSA ≈ 392 karakter base64 — melebihi satu TXT string. Split:
```
sel1._domainkey IN TXT ( "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
                         "MIIBCgKCAQEA..." )
```

---

## 3. DMARC (Domain-based Message Authentication, Reporting, and Conformance) — RFC 7489

### Apa yang diverifikasi
DMARC memverifikasi **alignment** antara domain di `From:` header (RFC5322.From — yang dilihat user) dengan domain yang lolos SPF atau DKIM. DMARC sendiri tidak menandatangani; ia mengorkestrasi SPF dan DKIM.

### Data yang dipakai
| Komponen | Sumber | Peran |
|---|---|---|
| `From:` header domain | MIME header | **Identifier utama DMARC** |
| SPF result + `MAIL FROM` domain | hasil SPF | Dicek alignment |
| DKIM result + `d=` domain | header `DKIM-Signature` | Dicek alignment |
| `_dmarc.<from-domain>` TXT | DNS | Policy, `rua`, `ruf`, `pct`, `adkim`, `aspf`, `fo` |
| `_report._dmarc.<domain>` TXT | DNS (opsional) | Otorisasi report pihak ketiga |

### Alignment
- **Relaxed** (`adkim=r`, default): organizational domain sama (`mail.example.com` vs `example.com` = aligned).
- **Strict** (`adkim=s`): FQDN harus identik.

DMARC pass jika **salah satu** dari: (SPF pass **dan** `MAIL FROM` domain aligned) **atau** (DKIM pass **dan** `d=` domain aligned). DKIM lebih kuat karena tahan forwarding.

### Record contoh
```
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc-agg@example.com; ruf=mailto:dmarc-forensic@example.com; fo=1; adkim=s; aspf=s; pct=100; ri=86400"
```
| Tag | Nilai | Catatan |
|---|---|---|
| `p` | `none`/`quarantine`/`reject` | Policy untuk domain `From:` |
| `sp` | sama | Policy untuk subdomain |
| `pct` | 0–100 | Sampling; tidak dihormati Gmail |
| `adkim`/`aspf` | `r`/`s` | Relaxed default |
| `rua` | mailto | Aggregate XML report (harian) |
| `ruf` | mailto | Forensic (jarang dikirim; mengandung PII) |
| `fo` | 0/1/d/s | Kapan forensic dikirim |

### Perintah verifikasi
```bash
dig +short TXT _dmarc.example.com

# Cek policy via OpenDMARC
opendmarc-check pesan.eml
# output: DMARC pass/fail + reason (spf aligned / dkim aligned)

# Parse aggregate report (XML zip)
unzip -p google.com!example.com!1700000000!1700086400.xml.zip | xmllint --format -
```

### Kondisi gagal yang paling sering saat setup
| Gejala | Penyebab | Perbaikan |
|---|---|---|
| DMARC fail meski SPF pass | Envelope `MAIL FROM` beda org domain (ESP pakai bounce domain sendiri, mis. `bounces.sendgrid.net`) | Tambah DKIM aligned (sign dengan `d=example.com`); atau pakai custom return-path ESP |
| DMARC fail meski DKIM pass | `d=` DKIM di domain ESP (`d=sendgrid.net`) | Konfigurasi ESP sign dengan domain Anda (Domain Authentication) |
| `p=none` tidak berefek | Policy hanya reporting; tidak blokir | Naikkan ke `quarantine` → `reject` setelah baseline |
| Subdomain bypass | `sp` tidak di-set, mewarisi `p` — tapi subdomain tanpa record `_dmarc` pakai org domain `p` | Verifikasi template `*._dmarc` atau `sp` |
| `rua` report tidak masuk | Domain report tidak otorisasi (pihak ketiga) | Tambah `_report._dmarc.<reporter-domain>` TXT `v=DMARC1` |
| Gmail/Yahoo bulk sender ditolak | 2024 requirement: SPF **dan** DKIM aligned, DMARC `p≥quarantine`, one-click unsubscribe | Penuhi ketiganya; `pct<100` tidak dihormati |
| Forwarding mailing list rusak | List rewrite `From:`, SPF fail, DKIM asli putus | ARC (RFC 8617) di forwarder; atau DMARC `p=none` di domain pengirim list |
| Record ganda `v=DMARC1` | Dua scheduler menulis record | Satu record saja; konsolidasi |

**Jebakan organizational domain:** PSL (Public Suffix List) menentukan org domain. `foo.co.uk` org domain = `foo.co.uk`, bukan `co.uk`. Kesalahan umum: mengira `p=reject` di `example.co.uk` melindungi `mail.example.co.uk` — ya, jika subdomain tidak punya `_dmarc` sendiri.

---

## 4. Header hasil autentikasi — apa yang muncul

MTA penerima menambahkan header setelah verifikasi. Format umum (RFC 8601):
```
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=sel1 header.b="Xyz...";
       spf=pass (google.com: domain of bounce@example.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com

Received-SPF: pass (google.com: domain of bounce@example.com designates 203.0.113.10 as permitted sender) client-ip=203.0.113.10;
```

| Header | Author | Isi |
|---|---|---|
| `Authentication-Results` | MTA penerima (trusted boundary) | Hasil DKIM/SPF/DMARC/ARC |
| `Received-SPF` | MTA (legacy) | Hasil SPF saja |
| `DKIM-Signature` | Signer (pengirim) | Tanda tangan |
| `ARC-Authentication-Results` | Forwarder (ARC sealer) | Snapshot hasil sebelum forward |

Jangan percaya `Authentication-Results` yang datang dari luar boundary — hanya yang ditambahkan MTA terakhir yang dipercaya untuk filtering.

---

## 5. Matriks kegagalan silang (SPF × DKIM × DMARC)

| Skenario | SPF | DKIM | DMARC | Penyebab khas |
|---|---|---|---|---|
| Direct send, setup benar | pass | pass | pass | — |
| Forwarding (Gmail → list → user) | fail | fail (jika header diubah) | fail | List rewrite `From`; perlu ARC |
| ESP tanpa domain auth | pass (ESP envelope) | pass (`d=esp`) | **fail** | Alignment tidak terpenuhi |
| ESP dengan domain auth | pass (custom bounce) | pass (`d=example.com`) | pass | — |
| Internal relay menambah footer | pass | **fail** (body hash) | fail | Body mangling |
| Subdomain `mail.example.com` tanpa `_dmarc` | pass | pass | pass via org `example.com` | Sesuai desain |
| `From:` spoofed, envelope valid | pass | fail | **fail** → reject | DMARC bekerja |
| Dua record SPF | permerror | pass | fail (SPF) | Konsolidasi record |

---

## 6. Jebakan operasional di lapangan

1. **Envelope vs header mismatch adalah akar 80% kegagalan.** SPF memeriksa `MAIL FROM`, DMARC memeriksa `From:`. ESP transactional (SendGrid, Mailgun, SES) default pakai bounce domain mereka sendiri — SPF pass untuk domain mereka, tapi DMARC fail karena tidak aligned. Wajib setup **custom return-path** + **DKIM dengan `d=` domain Anda**.

2. **DKIM putus saat transit body.** Gateway AV (Proofpoint, Mimecast), footer legal otomatis, dan milter `footer` menulis ulang body setelah signer. Hasil: `bh=` mismatch. Solusi: tandatangani **setelah** semua milter body-mangling, atau matikan mangling untuk mail keluar.

3. **`p=none` dianggap "sudah DMARC".** Banyak tim berhenti di `p=none` bertahun-tahun. Ini hanya monitoring. Gmail/Yahoo 2024+ mewajibkan `p≥quarantine` untuk bulk sender (>5k/hari). Naikkan bertahap: `p=none` → `pct=25 p=quarantine` → `pct=100` → `p=reject`.

4. **`pct` diabaikan Google.** Sejak 2024, Gmail tidak menghormati `pct<100` untuk policy enforcement. Jangan andalkan sampling sebagai mitigasi.

5. **Rotasi selector DKIM tanpa overlap.** Ganti `s=sel1` → `s=sel2` tanpa publish `sel2` DNS dulu = mail gagal verifikasi selama TTL. Urutan: publish DNS `sel2` → tunggu TTL (min 300s) → ganti signer → hapus `sel1` setelah 7 hari.

6. **Lookup SPF >10 tanpa disadari.** Setiap `include:` dari provider (Google, Microsoft, Mailchimp, Zendesk, Salesforce) menghitung. Stak 3 provider saja bisa tembus 10. Flatten ke `ip4:` secara berkala, atau pakai `spf-flattener` (mis. `openspf-flatten`).

7. **DNS TXT dipecah salah.** Record >255 char tanpa split (`"..." "..."`) → MTA parse gagal → `permerror`. Umum pada DKIM 2048-bit dan SPF panjang. Cek dengan `dig +short TXT` — kalau keluar satu string panjang tanpa kutip ganda, kemungkinan besar rusak di zone file.

8. **Subdomain tidak terlindungi.** `p=reject` di `example.com` tidak otomatis melindungi `mail.example.com` jika subdomain punya `_dmarc` sendiri yang lebih longgar. Audit `*._dmarc` dan `_dmarc.<sub>`.

9. **ARC belum jadi standar de facto.** Meski RFC 8617, dukungan MTA penerima bervariasi (Gmail support, Exchange Online terbatas). Jangan andalkan ARC sebagai satu-satunya mitigasi forwarding.

10. **Report `rua` membanjir / tidak terbaca.** Aggregate XML harian per reporter bisa ribuan file. Tanpa tooling (`parsedmarc`, `dmarc-cat`, `dmarcian`) report tidak berguna. Forensic `ruf` sering tidak dikirim karena PII — jangan berharap data dari situ.

11. **Testing lewat `dig` lokal ≠ testing lewat resolver publik.** Resolver internal dengan view split horizon bisa mengembalikan record berbeda. Selalu verifikasi via `dig @8.8.8.8` dan `dig @1.1.1.1`, plus `mxtoolbox` untuk cross-check.

12. **Time skew.** DKIM `t=`/`x=` dan SPF tidak toleran clock drift besar di signer. Container tanpa NTP sinkron → signature dianggap future-dated → fail. Pastikan `chronyd`/`systemd-timesyncd` aktif di relay.

---

## [reasoning trace]


