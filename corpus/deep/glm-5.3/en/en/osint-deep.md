# osint-deep — misc

# Bab 5 — Referensi OSINT: Pivot & Recon Pasif

## 5.1 Pivot Email/Username

### 5.1.1 Holehe

Holehe mengecek keberadaan email di layanan pihak ketiga via **email enumeration flow** (registrasi/lupa password), bukan login langsung. Verifikasi: `pip install holehe` (≥ v1.60, Python ≥ 3.10).

```bash
# Cek satu email terhadap ~120 modul situs
holehe --only-used true perusahaan@target.co.id

# Filter hanya hasil positif
holehe --only-used true target@corp.com | grep -E "\[+\]"

# Batch dari file
while read email; do holehe "$email"; done < emails.txt
```

| Kategori situs | Yang dikirim | Yang muncul | Kenapa berhasil |
|---|---|---|---|
| GitHub, Intel, Adobe | Email saja (registrasi) | `True`/`False` + kadang partial number | Endpoint API registrasi bocor status email tanpa rate limit agresif |
| Zoom, Pinterest | Email via forgot-password | `True` | Response differentiator (pesan error beda untuk existing/non-existing) |
| Yahoo, Microsoft | Email + sometimes phone partial | `+44xxxxxxxxx78` | Endpoint recovery mengembalikan mask number — leak data sendiri |

**Kenapa gagal (per modul):** endpoint diganti, CAPTCHA ditambah, rate-limit → hasil `False` palsu. Selalu uji email kontrol (pasti tidak terdaftar) sebagai baseline.

### 5.1.2 Maigret

Username pivot ke ~2500 situs. Fokus deteksi via HTML response (profil, avatar, bio), bukan HTTP status saja.

```bash
pip install maigret
# Versi CLI
maigret --version  # maigret 0.4.3+

maigret jdoe                    # semua situs
maigret jdoe --all-sites       # termasuk situs "depowered"/unstable
maigret jdoe -T 20 -S timeout=10  # 20 thread, timeout per request
maigret jdoe --nsfw            # sertakan situs NSFW (default dimatikan)
maigret --recursive jdoe       # ikuti username baru ditemukan dari bio
maigret jdoe --recon-n 3      # kombinasi nama otomatis (j.doe, johnd, dll)
maigret -u usernames.txt -o report.html --format html
```

**Apa yang muncul:** daftar URL profil terkonfirmasi + confidence level (`claimed`, `identified`, `found via tags`), plus ekstraksi IDN/phone dari bio.

**Pivot workflow:**

```
linkedin (nama tampil) → generate kandidat username (j.doe, johndoe, jdoe)
→ maigret johndoe → Netflix/GitHub/Steam hit → bio berisi Instagram
→ maigret @ig_handle → target email format → holehe
```

**Kenapa gagal:** username berubah (GitHub redirect lama 6 bulan), account deletion, situs mati. Modul `db` maigret harus di-update (`maigret --setup`) karena situs berubah layout setiap bulan.

---

## 5.2 Domain/IP Intelligence

### 5.2.1 Shodan

Query pakai filter. Basisnya: banner grabbing pada port terbuka internet, termasuk layanan **yang admin lupa ada**.

```bash
pip install shodan
shodan init YOUR_API_KEY

shodan search --fields ip_str,port,org,title 'org:"Target Corp" port:443'
shodan host 203.0.113.45
shodan download results.json 'ssl.cert.subject.CN:*.target.co.id'
```

| Query | Artefak yang dapat |
|---|---|
| `http.title:"Index of /"` | Directory listing terbuka |
| `ssl.cert.subject.CN:"vpn.target.co.id"` | Semua host sertifikat sama |
| `product:"nginx 1.25.3" country:"ID"` | Versi nginx vulnerable spesifik |
| `default_login:"admin"` (Shodan save dari HTTP 200 login) | Perangkat IoT/kamera default cred |
| `product:"Microsoft IIS httpd" org:"Target"` | Footprint Windows Server |
| `port:3389 os:"Windows Server 2022"` | RDP exposed |
| `http.favicon.hash:-247838090` | Favicon vector — cari semua host clone/aset sama fingerprint |

**Favicon hash** adalah pivot terkuat: hash favicon GlassFish default `-1895809619`, Jenkins lama `81586312`, Apache Tomcat `116323821`. Cari via `shodan search 'http.favicon.hash:<hash>'`.

### 5.2.2 Censys

```bash
pip install censys
censys search --index hosts 'services.http.response.html_title:"Target Intranet"'
```

Kelebihan vs Shodan: **sertifikat TLS lengkap searchable**, termasuk SAN field yang bocor internal hostname:

```
services.tls.certificates.leaf_data.subject.common_name: internal.target.co.id
services.tls.certificates.leaf_data.extensions.subject_alt_name.dns_names: *.corp.target.co.id
```

CT log (crt.sh boleh ekuivalen):

```bash
curl -s 'https://crt.sh/?q=%25.target.co.id&output=json' | jq -r '.[].name_value' | sort -u
```

Domain `*.uat`, `*.dev` di SAN sertifikat = host test yang tidak ada di DNS publik → resolve via host history (SecurityTrails) atau cek IP tetangga (Censys: `ip:203.0.113.0/24`).

### 5.2.3 SecurityTrails

```bash
# Subdomain enumeration via API
curl -H "apikey: $ST_KEY" "https://api.securitytrails.com/v1/domain/target.co.id/subdomains" | jq -r '.subdomains[]' | sed 's/$/.target.co.id/'

# Historical A record — host yang sudah tidak di DNS publik
curl -H "apikey: $ST_KEY" "https://api.securitytrails.com/v1/domain/target.co.id/dns/history/a"

# Reverse: IP → domain (sharing hosting)
curl -H "apikey: $ST_KEY" "https://api.securitytrails.com/v1/domains/203.0.113.45"
```

**Kenapa berhasil:** PTR + passive DNS capture; record yang **sudah dihapus di authoritative DNS masih hidup di history** → pivot ke staging/lama. Kombinasi workflow: crt.sh → subdomain list → SecurityTrails history → resolve → Shodan banner per IP.

---

## 5.3 GitHub Secret Hunting

### 5.3.1 TruffleHog

```bash
# v8.x (Go rewrite)
trufflehog github --org=acme-corp --token=$GITHUB_TOKEN --only-verified
trufflehog github --repo=acme-corp/payments-service --issue-comments --pull-requests --only-verified
trufflehog git file:///path/to/repo          # scan clone lokal, full history
trufflehog docker --image=acme/app:latest     # secret yang di-bake ke image
```

Flag penting:

| Flag | Fungsi |
|---|---|
| `--only-verified` | Hanya secret valid via verifikasi live API (AWS STS, GCP tokeninfo, Slack `auth.test`) |
| `--since-commit=<sha>` | Batasi rentang history |
| `--exclude-forks` | Kurangi noise |

Output: redaksi secret (`ari:・・・` partial), repo path, commit hash, decoder, `Verified: true/false`.

### 5.3.2 Gitleaks

```bash
# v8.18+
gitleaks git --repo-url="https://$TOKEN@github.com/acme/repo.git" -v
gitleaks dir ./cloned-repo --no-banner
gitleaks detect --source . --redact -v         # dalam repo, scan history staged/unstaged

# Custom regex — kunci internal/framework
gitleaks git -r https://github.com/acme/repo -c my-config.toml
```

```toml
# my-config.toml
[[rules]]
id = "internal-jwt"
description = "JWT internal app"
regex = '''eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}'''

[[rules]]
regex = '''(?i)(acme|internal)_api_key["'\s:=]{1,5}([A-Za-z0-9]{32})'''
secretGroup = 2

[allowlist]
paths = ['''test/''', '''\.md$''']
```

**Perbedaan TruffleHog vs Gitleaks:** TruffleHog verifikasi live (`--only-verified`) — tidak memorable-burn API key korban di rate limit; Gitleaks lebih cepat untuk full-history mass-scan + custom regex. Kombinasi: gitleaks mass-scan → trufflehog verify hits.

**Target scans selain history commit:** gists, issues/code comments (`trufflehog github --gist`), fork network (secret dihapus di upstream **masih ada di fork**), deleted-base64 (`base64 -d` payloads di semgrep `\.git` history).

**Pivot setelah dapat cred:**

```
AWS secret → aws sts get-caller-identity (credentials inactive check, harmless)
GitHub PAT → curl -H "Authorization: token $PAT" https://api.github.com/user
Slack → tidak. Verifikasi TruffleHog sudah oke. Jangan login manual sebelum koordinasi.
```

---

## 5.4 Metadata Dokumen

Metadata di header/wajah Office dan PDF tidak hilang otomatis saat share.

```bash
# Instal toolchain
sudo apt install exiftool libimage-exiftool-perl

# PDF/company doc
exiftool target-proposal.pdf

# Word — total listing
exiftool -a -u -g1 Project_Plan.docx
```

| Field yang dicari | Nilai intel |
|---|---|
| `Author`, `Last Modified By` | `CN=Dimas Prakoso (OU=IT-Infrastructure)` — nama + unit internal |
| `Server`, `Template` | `\\FS01.corp.target.co.id\...` — internal hostname + SMB share |
| `Software`, `Creator` | `Microsoft Office Word 2016` vs 365 → patch baseline |
| `Create Date` / `Modify Date` | Timeline internal activity |
| GPS JPEG dari event/foto kantor | Koordinat office/data center |

```bash
# nuke metadata post (untuk file proxy/scrub tim sendiri)
exiftool -all= -overwrite_original proxy.docx

# Fingerprint mungkin — cari doc serupa by metadata di internet archive / Google:
"author:Dimas Prakoso" filetype:pdf site:target.co.id
```

Perintah pita dokumen dari perusahaan sering gagal (-sanitasi DLP) — tapi lampau via **email ke vendor** (input doc uploaded employee). Sumber dokumen: Google dorks:

```
site:target.co.id filetype:pdf "internal use only"
site:target.co.id filetype:xlsx (salaries | absensi | budget)
```

## 5.4.1 Mencari gabungan metadata:

```bash
# Crawl Google Docs results, mass exiftool
googler -n 50 -x "site:target.co.id filetype:pdf" --json | jq -r '.[].url' \
  | xargs -I{} sh -c 'curl -s -o /tmp/f.pdf "{}" && exiftool /tmp/f.pdf | grep -E "Author|Server"'
```

---

## 5.5 Footprint Karyawan

```bash
# Breach DB
h8mail -t john.doe@corp.com --local breaches/ --loose

# Suite:
site:linkedin.com/in "PT Target" "IT"                        # Google - LinkedIn
"target.co.id" email filetype:xls                            # email directory leaked
"@target.co.id" site:github.com OR site:pastebin.com         # hardcoded emails in code/paste
inteltechniques.com — Maltego transforms e:operator (jdoe@ → breach → other services)

# People Data Google:
"user" "password" filetype:txt site:target.co.id             # internal orientation documentation errors
```

Sumber sharing password developer (tulis di blog/Stack Overflow):

```bash
site:stackoverflow.com "target.co.id" "password"
searchcode.com: /project/xyz "dbname" "usr\":" commons — banyak cred sqlalchemy connection.
# Common pattern yang muncul:
postgres://app_user:P@ss2024@staging.target.co.id/db_prod
```

Fingerprinting format email perusahaan → bukti koreksi maupun arah brute-force DNS email:

1. Sample k 4–6 email public (press release, research, vendor)
2. Distribusi format `john.doe` vs `jdoe` vs `j.doe`
3. Generate list: `namerator`, `linkedin2email` workflow via LinkedIn Sales Navigator / hunter.io `domain-search`
4. Kirim tester non-via SMTP-recon untuk verifikasi mail server response (method scope → RFC-based):

```bash
smtp-user-enum -M VRFY -U users.txt -t mail.target.co.id -p 25   # kalau misconfigured RL-front
# atau verifikasi via delivery-bounce test pada legimasi services (bukan mass VRFY)
```

**Kenapa gagal:** rate-limit, Microsoft Exchange defaults only-return-probe, PoP3, generik 254-line direct

---

## 5.6 Jebakan Operasional

| Jebakan | Dampak | Mitigasi |
|---|---|---|
| **Holehe/Maigret trigger CAPTCHA/Cloudflare** | Hasil `False` flaws terlihat seperti "email tidak terdaftar" | Ujuji email positive control; sinkron flag `--only-used` |
| **OPSEC leak: holehe mengirim email ke vendor terpilih** | Target corporation tahu Anda intelligence gathering | Gunakan domain e-mail pertama (P): rapid7, emails target mailbox di divisi email; Cex flags. |
| **Shodan historical = saat ini** | Banner 30 hari lalu → port sekarang closed | Cross-verify via `nmap` citation timing, `censys` rate |
| **Old DNS record SecurityTrails → live staging host** | Host tidak responsive (umum), results bias | Mass resolve: `dnsx -l hosts.txt` |
| **CT-log subdomain berbagai nama internal" | Downturn zero-day arrangement takes time | Slack hotline SO team |
| **Gitleaks mass-scan GitHub via 1 LAN IP** | Rate-limit 429, GH ban tokens | Rotasi incentives: `--auth-token` limit, GH API is 5000 req/hour for PAT |
| **TruffleHog verifikasi live secret (readable check telah memvalidasi key)** | 5 sekali jadi ammo attacker lain (risk operational: man team punya key) | Rate limiting — Slack `auth.test once`; account local verification safe |
| **Microsoft 401 service — regist`ed error `code flow`** | Internal domain admin get scrambled feed (fpga flagged) | Only-recent_modules base: de |</think># OSINT: Pivot & Footprint Referensi Operasional

## 1. Pivot Email → Akun (Holehe)

**Versi:** holehe 3.2.x (Python ≥3.8). Modul: ~120 situs.

**Mekanisme:** Holehe *tidak* brute-force password. Ia memanfaatkan endpoint *registrasi* dan *reset password* yang leak status keberadaan email. Server merespons berbeda untuk "email sudah terdaftar" vs "belum".

```bash
# Instalasi
python3 -m venv ~/.venvs/holehe
source ~/.venvs/holehe/bin/activate
pip install holehe

# Scan satu email — semua modul
holehe target.nama@perusahaan.co.id

# Scan dari file list
while IFS= read -r email; do holehe "$email"; done < corp_emails.txt | tee holehe_results.txt

# Output parsial modul tertentu (contoh: cek hanya ecommerce)
holehe --only-used icloud target.nama@perusahaan.co.id   # mac: no
```

**Apa yang dikirim:** GET/POST request ke endpoint registrasi/reset site target, berisi email korban.

**Apa yang muncul (contoh output):**

```
github.com          : True
pastebin.com        : False
adobe.com           : True
zoom.us             : True
issuu.com           : True
cloudflare.com      : False
gravatar.com        : True
Full contact        : The email is used
```

**Kenapa berhasil:** banyak situs di endpoint register mengirim response berbeda ("email sudah dipakai") tanpa rate-limit yang ketat untuk request tunggal.

**Kenapa gagal:** endpoint ganti struktur, modul holehe outdated (cek `pip install --upgrade holehe`), situs pakai CAPTCHA/Cloudflare turnstile, atau korban pakai email plus-addressing (`nama+privat@gmail.com`) dan email terdaftar di bawah varian itu.

----

## 2. Pivot Email → Username / Username → Email

**Alat bantu:** maigret 0.4.x (Python), sherlock-project >= 0.15.

```bash
pip install maigret
maigret --setup                                    # generate db (utk fast mode)
maigret username
maigret username --all-sites                        # termasuk situs nsfw/deprecated
maigret -t "site1,site2" username                   # verifikasi di situs tertentu
maigret --recursive username                        # ikuti username yg ditemukan di profile bio
```

**Apa yang muncul:** screenshot bukti keterkaitan, statistik keterkaitan (strong/weak/claimed), daftar situs 3000+.

**Data pivot:** dari `username` → temukan format email: `username@provider.com` → input ke holehe, atau cari via dump/DB publik: hunter.io, epieos, dehashed.

**Alur email → nomor HP / calendar / API:**
*   `epieos.com` : masukkan email → palant (Google account, nama, photo, Google calendar publik, dokumen publik).
*   `holehe ... medium.com` → cek if email linked ke medium.
*   Hasil jawaban "True" → pivot ke nomor tel, NIK.

**Kenapa gagal:** email mark spam, sql error, perubahan privasi, situs bundle limit-quota `all-sites` mode.

----

## 3. Domain/IP Recon (Shodan, Censys, SecurityTrails)

### Shodan
**Versi CLI:** shodan-python 1.31, dan shodan CLI tool (`pip install shodan`).

```bash
shodan init YOUR_API_KEY
shodan host <ip>
shodan search --fields ip_str,port,org,hostname "ssl.cert.subject.cn:target.co.id"
shodan search "org:'PT Target' http.title:'dashboard'"
shodan download tmp.json "org:'Target' product:'nginx 1.25.*'"
shodan parse --fields ip_str,port,transport tmp.json.gz
shodan scan submit <ip/cidr>                        # scan on-demand quota terbatas
```

**Query penting + kenapa berhasil:**

```text
http.title:"index of /"                   → direktori listing terbuka, leak file internal
http.component:"jQuery 1.x" "org:Target"    → teknologi usang di host org
product:"nginx" version:1.25               → versi CVE conhecidas
ssl:"GoGetSSL"                             → sertifikat tertentu
net:103.10.12.0/24                         → scope IP ISP
port:9200 "org:Target" "elastic"           → Elasticsearch exposed
"X-Jenkins" "org:Target" 200               → Jenkins tanpa auth
```

**Kenapa gagal:** API quota # results (free tier 100 baris/tahun; academic plan mungkin lebih besar), IP korban pakai CDN (URL Shine). Beberapa hasil hash SSL cukup lama dan API tidak memberikan extensions SNI. Script berisi exports of `shodan host` output parsing html:

```bash
shodan host 103.11.122.33 | yq '.vulns[]' 2>/dev/null
```

**Map risk:** vulns anchor spesifik: nginx 1.25 vs CVE-2023-44487 (HTTP/2 Rapid Reset, fix di 1.25.3), jenkins 2.426.

### Censys
**Versi:** censys-search 2.2.12, censys python lib 1.x → censys-cli >= 1.2.

```bash
pip install censys
censys search --index hosts 'services.http.response.html_title:"Dashboard"+services.tls.certificates.leaf_data.subject.organization:"PT Target"'
censys view --index hosts <ip>
```

**Hosts index query:**

```text
services.http.response.html_title: "Outlook Web App"
services.tls.certificates.leaf_data.subject.organization: "Target"
services.software.vendor: Microsoft AND services.software.product: "IIS" AND location.country: Indonesia
```

**Certificates index query (jika perusahaan punya CTL sertifikat publik):**

```text
parsed.subject.organization: "Target" AND parsed.validity.start:>2023-06-01
```

**Kenapa berhasil:** sertifikat wajib menyimpan nama domain (SubjectALTName) sehingga daftar subdomain internal sering bocor ke CT log; tanpa menghubungi server target sama sekali = pasif.

**Kenapa gagal:** subdomain di belakang CLB/CDN hanya menampilkan IP edge Cloudflare bukan IP asli — harus pivot lanjut: cari `services.http.response.server: cloudflare` → gunakan history Censys (bukan) atau SecurityTrails history, atau dnsdumpster untuk DNS history.

### SecurityTrails
**Alternatif:** digitorus.com (history), whoisds.com, viewdns.info.

```bash
# API
curl -H "apikey: YOURKEY" "https://api.securitytrails.com/v1/domain/target.co.id/subdomains?children_only=false"
curl -H "apikey: YOURKEY" "https://api.securitytrails.com/v1/history/target.co.id/dns/a"
curl -s "https://api.securitytrails.com/v1/domain/target.co.id/whois" | jq .
```

**Kenapa berhasil:** data history A record menunjukkan IP asli sebelum pindah ke CDN — IP origin bisa dikunjungi langsung via Host header (`curl -H "Host: target.co.id" http://<prev-origin-ip>`).

**Output:**

```json
{"subdomains":[{"ip":"103.x.x.x","first_seen":"2021-03-11","type":"A"},...]}
```

**Fakta teknis:** subdomains enum via `dig` besar-besaran dari dns bruteforce:

```bash
# tanpa API
dnsrecon -d target.co.id -t std
dnsrecon -d target.co.id -g           # google enum
subfinder -d target.co.id -all -recursive
```

**Kenapa gagal:** wildcard DNS (`*.target.co.id` resolve semua) → semua bruteforce kembali `True`; verifikasi via panjang response atau `dnsgen`+instrumen compare TTL.

----
Sub heading special:

## 4. GitHub Secret Hunting (TruffleHog & Gitleaks)

### TruffleHog
**Versi:** v8.19+ (Go rewrite).

```bash
trufflehog github --repo=https://github.com/target/app \
  --issue-comments --pull-requests \
  --token=$GITHUB_TOKEN \
  --only-verified                              # deteksi via commit history & live check

# scan seluruh org
trufflehog github --org=target \
  --only-verified --token=$GITHUB_TOKEN

# file sistem & postman
trufflehog filesystem --directory=.           # repo lokal full .git history
trufflehog filesystem --directory=/path --exclude-paths=.git,node_modules
trufflehog docker --image=target/app:latest
trufflehog git file:///path/to/local/repo
trufflehog postman --workspace=xyz
```

**Apa yang muncul:**

```
Verification: verified true
Detector: AWS
Raw secret: AKIA...
File: config/production.yml
Commit: f00c...bac
```

**Kenapa berhasil (v8+):** scanning via `git log -p` (melintasi commit objects termasuk yang sudah diberi force push alias history "terhapus"), regex terstruktur (JSON, arbitrary companions, base64 decode), verifikasi live API key via endpoint resmi (mis. `sts:GetCallerIdentity` untuk AWS key) → FP rendet.

**Kenapa gagal:** key sudah di-rotate (verification false → tool tetap log tapi marked inactive), key tersebut pernah di-commit ulang di file besar skip (v8 default max depth), **harus pakai GitHub token atau rate limit 429**.

### Gitleaks
**Versi:** v8.18.x (single Go binary).

```bash
# scan repo lokal / full git history (jika .git ada)
gitleaks detect --source /path/to/repo --no-banner -v

# scan remote
gitleaks git --log-opts="--full-history" https://github.com/target/app -v

# scan directory non-git (file current)
gitleaks dir /path -v

# custom rules (gitleaks.toml)
gitleaks detect --config gitleaks.toml .
```

**gitleaks.toml pattern perusahaan-internal:**

```toml
[[rules]]
id = "corp-internal-token"
description = "Internal API token Target"
regex = '''TARGET_[A-Z0-9]{32}'''

[[rules]]
id = "corp-db-conn"
description = "DB conn string internal"
regex = '''(mysql|postgres)://[a-zA-Z0-9_]+:[^@]{4,}@.'''

[[rules]]
id = "corp-private-key"
description = "Private key"
keywords = ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"]
regex = '''(?s)-----BEGIN [A-Z]*PRIVATE KEY----[\s\S]*?-----END [A-Z]*PRIVATE KEY-----'''

[allowlist]
paths = ['''gitleaks.toml''']
```

**Kenapa berhasil:** scan list file + `git log --all -p` vs regex; entropic filter untuk filter string pancaindera (FP reduction).

**Kenapa gagal:** secret obfuscated/b64/native Vault (cloak), repository sudah dihapus dari GitHub (fork masih hidup — scan fork), secret **bukan di repo melainkan di GitHub Issues/PR comment** (pakai `trufflehog github --issue-comments`), atau enterprise self-hosted GHE (endpoint beda — set `--endpoint=https://ghe.target.co.id`).

**Perintah GitHub search manual (tambahan OPSEC sensitif):**

```bash
curl -s "https://api.github.com/search/code?q=%22TARGET_API_KEY%22+in:file+language:python" \
  -H "Authorization: token $GITHUB_TOKEN" | jq '.items[].repository.full_name'
```

**Hati-hati:** searching signal secret di corporate repo tanpa auth = segera muncul di activity feed pemilik repo — gunakan akun burner, operator jangan pakai akun GitHub pribadi.

## 5. Metadata Dokumen

**Apa yang dikirim:** — pasif total, file dianalisis lokal.

**Toolchain (kali/exiftool 12.76+, metagoofil, FOCA fork):**

```bash
# ambil semua PDF/XLS perusahaan via Google filetype dork
# lalu dump metadata
exiftool -a -u -g1 *.pdf > metadata_dump.txt

# pattern berharga
exiftool *.docx | grep -E "Author|Company|Last Modified By|Template"
exiftool *.pdf | grep -E "Creator|Producer|Title|Subject"
```

**Contoh temuan kritis:**

| Field | Nilai contoh | Intel |
|---|---|---|
| `Author` | `budi.santoso` | konfirmasi pola username `nama.depan` |
| `Last Modified By` | `Sari Dewi \(QA\) (W10-PC04)` | hostname PC internal + nama + divisi |
| `Software` | `Microsoft Word for Office 365 (Windows 10)` | build Windows 10 usang, kandidat CVE lateral |
| `Template` | `\\fileshare\templates\resmi.dotx` | UNC path internal — indikasi SMB share |
| PDF `Producer` | `Chrome 131.0.6460.0` | versi browser pegawai |

**Extraction massal:**

```bash
pip install metagoofil   # atau gunakan spiderfoot
metagoofil -d perusahaan.co.id -t pdf,docx,xlsx -l 100 -n 20 -o outdir -f results.html
```

**Kenapa gagal/berhasil:** berhasil karena pegawai Windows 11 24H2 masih upload file tanpa sanitize metadata (kebijakan anti-leak belum ada); gagal jika target sudah proses via DLP sanitization, atau seluruh dokumen hanya SaaS mirrors (SharePoint UATH) tanpa file asli publishable.

**Dork pintu masuk:**

```text
site:perusahaan.co.id filetype:pdf | filetype:docx
site:perusahaan.co.id ext:pdf inurl:profil
"confidential" filetype:xlsx site:perusahaan.co.id
(/pptx) site:perusahaan.co.id
```

## 6. Footprint Karyawan

**Pivot nama → struktur org:** LinkedIn + `theHarvester 7.x`:

```bash
theHarvester -d perusahaan.co.id -b linkedin,bing,google -l 200 -f hasil.xml
# output: emails, hosts, names → generate kandidat email:
python3 -c "from requests import get; ..."   # gunakan prowl untuk pola corp
```

Perintah cepat pra-kickoff nama → kandidat awal:

```bash
pip install name-that-hash && \
printf "budi santoso\nsari dewi\n" | while read -r name; do \
  genemails -d perusahaan.co.id -i "$name" -f "first.last,f.last,flast" ; done
```

**Nama → bukti kartu / tanda pengenal →** validasi NIK format Indonesia (16 digit, prefix kode kemendagri, satu digit gender) **hanya untuk verifikasi struktur data, bukan untuk memanfaatkan penggunaan identitas nyata.**

**Nomor HP pivot:** phoneinfoga 2.x + truecaller web + leakcheck:

```bash
phoneinfoga scan -n +62812xxxxxxx
phoneinfoga serve  # web UI: operator, karrier, possible fingerprint leaks
```

**Apa yang muncul:** nama (via leak DB), ko-dompeat akun marketplace, vacuum apel date `exodus privacy reports`, platform email apa dipakai (imeiSys).

**Kenapa berhasil:** data footprint lama belum pernah dihapus; pegawai pakai nomor pribadi untuk registrasi applicatif publik (e-commerce, gelar SIP) yang kemudian jadi databroker.

**Kenapa gagal:** banyak entri datang dari *rekontamination database broker* — sebelum kamu ambil data dari source "menjijikkan", pertama verifikasi apel name/collect the chain: highlight jika value the data subject.

---

## 7. Jebakan Operasional (Kenapa Ini Gagal di Lapangan)

1.  **`trufflehog`/`gitleaks` scan history panjang** → sesi timeout/`429 rate limit`. Split: `--since-commit` per milestone, atau `git log -G` prefilter file name pattern (`.env`, `config`, `credential`).
2.  **GitHub scraping tanpa token** → fingerprint IP cepat kena secondary rate limiting. Selalu pakai token burner — dan jangan org-crawl via API search code (`api.github.com/search/code` butuh endpoint org auth).
3.  **Shodan API key free-tier** → hanya 1 result page; `shodan search` tanpa `--facets` tiba-tiba return exception; gunakan `monitor` + alert untuk perubahan aset, bukan ad-hoc scan besar dari web.
4.  **holehe/maigret dari kantor client** → semua request ke 120 situs dari satu IP; kena fingerprint webmail target, atau internal blue team melihat probe DNS/HTTP dari outside ke endpoint `accounts.corp` → jangan scan dari IP aset engagement. Jalankan dari VPS burner/SOCKS rotator.
5.  **CT log data lama sudah kadaluarsa** → subdomain dari Censys certs index bisa sudah decommission; selalu resolve ulang dengan `dig` sebelum menandai live; else test report kamu penuh host mati.
6.  **exiftool di file besar batch** → beberapa PDF (ratusan MB, brochure print) hang atau crash (stderr pipe penuh). Gunakan `-q -q`, dan `-fileOrder` limit; skip PDF versi >2.0 (parser warning).
7.  **Target pakai email alias/plus addressing** → pivot holehe gagal; coba iterasi `nama+n`, `nama@p171gmail.com`, `nama@icloud.com`, dan cek apakah format berbeda via `.har` capture dari endpoint yang tampilkan email mask ("masukkan kata sandi untuk p****a@***").
8.  **Wildcard DNS** → semua subdomain DNS enum return "Ada", mencemari report. Validasi: `dig @8.8.8.8 randomstring.target.co.id` – kalau resolve, tandai wildcard.
9.  **Papercut legal/substansi:** berbagi hasil (nomor NIK, nomor HP pribadi, kartu keluarga) dalam report ke klien bermasalah tanpa redline privacy review — banyak engagement batal gara-gara attach file PII mentah bukan bukti vuln. Redact kecuali yang esensial sebagai proof.
10. **Klaim "verified" dari trufflehog melulu status API** — key mungkin expired menit berikutnya; jangan laporkan "akses aktif" hanya berdasar verification oracle; sebutkan timestamp verifikasi, jangan scan ulang berkali (beberapa verifikasi AWS sendiri menulis CloudTrail; begitupun Slack 2FA admin alert bisa trigger terhadap pemilik token).

---

## [reasoning trace]


