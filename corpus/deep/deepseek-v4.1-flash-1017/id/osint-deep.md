# osint-deep — misc

# OSINT: Email/Username Pivot, Domain/IP, GitHub Secret Hunting, Metadata, Employee Footprint

## 1. Email / Username Pivot

### 1.1 holehe (v1.61+) — account discovery dari email

**Dikirim:** HTTP POST/GET ke endpoint registrasi/forgot-password ~120 situs (Twitter/X, Instagram, Adobe, Spotify, GitHub, dll). Umumnya `POST /api/check` atau `GET /account/exists?email=`.

**Muncul:** Status `[+]` (akun terdaftar), `[-]` (tidak terdaftar), `[x]` (rate-limit/blocked). Tidak mengembalikan PII — hanya boolean existence.

**Kenapa berhasil:** Situs membocorkan existence check pada form signup/forgot-password. **Kenapa gagal:** Cloudflare Turnstile (2024+) di halaman signup, endpoint butuh CSRF token, atau situs pakai kode 200 sama untuk exists/not-exists (enumeration mitigation).

```bash
pip install holehe==1.61
holehe target@corp.com --only-used -np
holehe target@corp.com --csv out.csv
# via Tor (rate-limit bypass, tapi banyak endpoint blokir exit node)
holehe target@corp.com --only-used --tor
```

### 1.2 maigret (v0.5.0) — username → 3000+ sites

**Dikirim:** GET ke profil URL (`https://site/user/<username>`) + cek signature 200/404.

**Muncul:** Hits + extracted IDs (uid, bio, avatar URL), JSON graph untuk pivot.

**Kenapa gagal:** Cloudflare (Instagram, TikTok 2024+), soft-404 (semua request 200), login-wall (LinkedIn, Facebook).

```bash
pip install maigret==0.5.0
maigret target_handle --html -a -J out.json
maigret target_handle --site Instagram --site GitHub --site Keybase --timeout 15
maigret target_handle --parse out.json   # re-analyze tanpa refetch
```

### 1.3 Kombinasi pasif (tanpa sentuh target)

```bash
# Gravatar hash → avatar + linked profiles
echo -n "target@corp.com" | tr '[:upper:]' '[:lower:]' | md5sum
curl -sI "https://www.gravatar.com/avatar/<md5>?d=404" | head -1

# HIBP (butuh API key)
curl -s -H "hibp-api-key: $KEY" -H "user-agent: kb" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/target@corp.com?truncateResponse=false"

# Epieos / GHunt (Google account) — GHunt v2.2.0
pip install ghunt==2.2.0
ghunt login   # sekali, simpan cookies
ghunt email target@gmail.com
```

---

## 2. Domain / IP Recon

### 2.1 Shodan (API v1, CLI 1.6.x)

**Dikirim:** Query ke `api.shodan.io` (bukan langsung ke target).
**Muncul:** Banner (server header, TLS cert, JARM, favicon hash), ports, vulns (CVE list), hostnames, ASN.

```bash
pip install shodan==1.31.0
shodan init $SHODAN_KEY

# Semua host organisasi
shodan search 'org:"Contoso Ltd" http.title:"login"'

# Favicon hash (mudah pivot app identik)
python3 -c "import mmh3,requests,codecs; r=requests.get('https://target.com/favicon.ico'); print(mmh3.hash(codecs.encode(r.content,'base64')))"
shodan search 'http.favicon.hash:-123456789'

# TLS cert → hostname terdaftar (termasuk yang tidak di DNS publik)
shodan search 'ssl.cert.subject.CN:"*.target.com" 200'

# Filter versi konkret
shodan search 'product:nginx version:"1.25.3" country:ID'
shodan search 'port:22 product:OpenSSH version:"9.6"'
shodan host 203.0.113.10
```

**Kenapa berhasil:** Scanner Shodan (Honeypot-aware) sudah punya snapshot banner; favicon hash sulit dirotasi. **Kenapa gagal:** Host di belakang CDN (Cloudflare 104.x), banner di-strip (nginx `server_tokens off`), firewall geo-IP blokir scanner (sering untuk ID).

### 2.2 Censys (Platform API v3)

```bash
pip install censys==2.2.15
censys config   # simpan API_ID / API_SECRET

# Search host
censys search "services.tls.certificates.leaf_data.subject.common_name:target.com" --index-type hosts

# Cert pivot (termasuk subdomain tersembunyi)
censys search 'names: "target.com" and services.service_name: HTTP' --index-type certificates -o json

# CLI cepat
censys view 203.0.113.10 --index-type hosts
```

**Kenapa berhasil:** Censys menyimpan CT logs penuh → menemukan subdomain yang tidak ada di DNS/amass. **Kenapa gagal:** Rate-limit free (250 query/bln), field schema berubah antara v2→v3 (banyak writeup lama pakai `parsed.names`, sudah tidak valid).

### 2.3 SecurityTrails (API v1)

```bash
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains?children_only=false&include_inactive=true" \
  -H "APIKEY: $ST_KEY" | jq -r '.subdomains[]' | sed 's/$/.target.com/'

# Historical DNS (A record lama → origin IP sebelum CDN)
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: $ST_KEY" | jq '.records[].values[].ip'

# WHOIS history
curl -s "https://api.securitytrails.com/v1/history/target.com/whois" \
  -H "APIKEY: $ST_KEY" | jq '.history[].registrar'
```

**Kenapa berhasil:** Historical A record mengungkap origin IP sebelum di-CDN-kan — ini pivot paling produktif untuk bypass Cloudflare/Akamai. **Kenapa gagal:** Origin sudah migrasi total, atau A record historis hanya dummy.

### 2.4 Subdomain komplementer

```bash
# crt.sh — CT logs (gratis, tapi sering 502)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# amass v4.2.0 passive
amass enum -passive -d target.com -o subs.txt

# subfinder v2.6.6
subfinder -d target.com -all -silent | httpx -silent -title -tech-detect
```

---

## 3. GitHub Secret Hunting

### 3.1 trufflehog v3.82+ — verified secrets

**Dikirim:** git clone (shallow) atau HTTP GET raw file; lalu regex match + **verification** (auth check ke API provider).

**Muncul:** `DetectorName: AWS`, `Verified: true`, raw secret + file path + commit.

```bash
# Filesystem (sudah clone)
trufflehog filesystem ./repo --only-verified --json

# GitHub org (butuh GITHUB_TOKEN, PAT read-only)
trufflehog github --org=contoso --token=$GH_TOKEN --only-verified

# Repo spesifik, termasuk history
trufflehog git https://github.com/contoso/infra.git --only-verified --json > leaks.json

# Docker image
trufflehog docker --image=registry.contoso.com/app:latest --only-verified
```

**Kenapa berhasil:** Verification melakukan call nyata ke provider (mis. `sts:GetCallerIdentity` untuk AWS, `GET /user` GitHub) → false positive ~0. **Kenapa gagal:** Secret AWS dalam status "disabled"/quota habis → `Verified: false` meski valid format; GitHub org butuh PAT dengan scope `repo`+`read:org`; rate-limit unauthed 60 req/jam.

### 3.2 gitleaks v8.21+ — pattern + entropy

**Dikirim:** Scan lokal (no network), regex ruleset ~160 detector.

```bash
# Scan history penuh
gitleaks detect --source ./repo --report-format json --report-path leaks.json -v

# Scan diff antar commit
gitleaks detect --source ./repo --log-opts="--since=2024-01-01"

# CI simulation (scan staged)
gitleaks protect --staged -v

# Custom rules
cat > .gitleaks.toml <<'EOF'
[[rules]]
id = "contoso-internal-token"
regex = '''contoso_[a-z0-9]{32}'''
keywords = ["contoso_"]
EOF
gitleaks detect --source . --config .gitleaks.toml
```

**Kenapa berhasil:** Entropy check (`shannon entropy > 4.5`) menangkap base64/hex yang tidak dikenal regex. **Kenapa gagal:** File di `.gitignore` sejak commit awal tidak ter-scan (hanya history); repo besar (>100k commit) butuh `--log-opts="--max-count=5000"`; hasil dominan `generic-api-key` false positive di lockfile.

### 3.3 Manual GitHub search — query deck

```
# Code search (butuh login GH untuk full result)
org:contoso "AKIA"                     # AWS access key
org:contoso "-----BEGIN RSA PRIVATE KEY-----"
org:contoso "xoxb-"                    # Slack bot token
org:contoso "ghp_"                     # GitHub PAT klasik
org:contoso "github_pat_"              # GitHub PAT fine-grained (2023+)
org:contoso "sk_live_"                 # Stripe
org:contoso filename:.env "DB_PASSWORD"
org:contoso path:config "password" extension:yml
org:contoso "AIza"                     # Google API key

# Commit search
org:contoso "remove password"          # commit message yang hapus secret
org:contoso "add .env"

# Gists
"contoso.com" password in:file type:gist
```

**Pitfall:** GitHub code search 2023+ wajib login + rate-limit 10 req/menit unauthed. Gists sering diabaikan trufflehog org scan (scope terpisah).

### 3.4 Pre-commit hygiene check (defensive validation)

```bash
# Cek apakah target pakai gitleaks pre-commit
curl -s https://raw.githubusercontent.com/contoso/repo/main/.pre-commit-config.yaml
```

---

## 4. Metadata Dokumen

### 4.1 Toolset

```bash
# exiftool 12.76+
exiftool -a -G1 -s document.pdf
exiftool -a -G1 -s -json *.docx > meta.json

# pdfinfo (poppler 24.x)
pdfinfo contract.pdf

# OOXML unzip (DOCX/XLSX/PPTX)
unzip -p report.docx docProps/core.xml | xmllint --format -
unzip -p report.docx docProps/app.xml   # Company, Template, TotalTime
unzip -l report.docx | grep -E "media/|embeddings/"
```

### 4.2 Field yang paling penting

| Field | Sumber | Nilai OSINT |
|---|---|---|
| `Author` / `dc:creator` | OOXML `docProps/core.xml`, PDF `/Author` | Username internal / domain login |
| `LastModifiedBy` | OOXML `cp:lastModifiedBy` | Nama karyawan aktif |
| `Company` | OOXML `docProps/app.xml` | Konfirmasi organisasi |
| `Template` | OOXML `app.xml` | Path UNC internal (`\\fileserver\...)` |
| `CreatorTool` / `Producer` | PDF `/Producer` | Versi Office/Word (mis. `Microsoft® Word 2019`) |
| `CreateDate` / `ModifyDate` | semua | Timezone leak (offset UTC+7 → ID) |
| GPS | JPEG EXIF | Lokasi fisik |
| `manager`, `revision` | OOXML `app.xml` | Struktur tim |

**Kenapa berhasil:** Office menulis metadata default dari akun Windows; user jarang strip. **Kenapa gagal:** File dari Google Docs/Sheets → metadata minimal (`Author: anonymous`); Word 365 (2024+) dengan "Remove personal info on save" aktif → strip semua PII; DOCX yang di-roundtrip LibreOffice menulis `LibreOffice/24.x` dan buang Author asli.

### 4.3 Batch harvest dari web

```bash
# Wget crawl → filter file dengan metadata
wget -r -l 3 -A pdf,docx,xlsx,pptx -nd -P ./docs https://target.com/public/

# Ekstrak Author + Company batch
find ./docs -type f \( -name '*.pdf' -o -name '*.docx' -o -name '*.xlsx' \) \
  -exec exiftool -j -Author -LastModifiedBy -Company -CreatorTool {} + \
  | jq -r '.[] | [.SourceFile, .Author, .LastModifiedBy, .Company] | @tsv'

# Google dork untuk file publik
# site:target.com filetype:pdf
# site:target.com filetype:xlsx "confidential"
# site:docs.google.com "target.com"
```

### 4.4 Metadata removal check (red team → blue team awareness)

```bash
# mat2 v0.13.4 — verifikasi apakah target strip metadata
mat2 --check document.pdf
mat2 clean/  # referensi
```

---

## 5. Employee Footprint

### 5.1 LinkedIn / aggregator

**Pasif (recommended, tidak menyentuh target):**
```
site:linkedin.com "Contoso" "Security Engineer"
site:linkedin.com/in "at Contoso" "since 2024"
site:linkedin.com "Contoso" "red team"
```

**Active harvest (hati-hati ToS):** LinkedIn menolak scraping aggressively (2024+ blocks unauthed via `HTTP 999`). Gunakan API resmi atau dataset turunan (Common Crawl, `theharvester` aggregation).

### 5.2 theharvester v4.6.0

```bash
theHarvester -d target.com -b linkedin,google,bing,duckduckgo,crtsh,hunter \
  -l 500 -f out.html
```

**Kenapa gagal:** Bing Google API key wajib untuk hasil >10; LinkedIn backend sudah tidak berfungsi sejak 2023 (return 0).

### 5.3 Hunter.io / Apollo / RocketReach

```bash
# Hunter.io email pattern
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER" \
  | jq '.data.pattern, .data.emails[0:5]'
# → "pattern": "{first}.{last}"
```

Pivot pattern → enumerasi: `first.last@`, `flast@`, `first@`. Verifikasi via SMTP `RCPT TO` (grey-listing risk, gunakan `swaks` v20240103):

```bash
swaks --to first.last@target.com --from probe@example.com \
  --server mx.target.com --quit-after RCPT
# 250 = valid, 550 = tidak ada
```

**Kenapa gagal:** Catch-all domain (semua 250), greylisting (451 defer), EDR/SEG (Mimecast, Proofpoint) blackhole setelah 3 probe.

### 5.4 Naming pattern → credential attack surface

Pivot penting: `first.last@target.com` + holehe + HIBP + GitHub leak → daftar akun yang **pasti ada**. Untuk red team, ini input ke password spray (Bab terpisah), bukan bagian OSINT.

### 5.5 Organizational chart reconstruction

Sumber komplementer:
- **GitHub org members** (`https://api.github.com/orgs/<org>/members`) → sering overlap dengan engineering
- **Conference talk slides** (Speakerdeck, Defcon media) → metadata + email di slide
- **Commit emails**: `git log --format='%ae %an' | sort -u` dari repo publik → email internal (`@target.com`)
- **npm/PyPI package maintainer** emails
- **SSL cert SAN** + Whois → admin email

```bash
# Commit email harvest dari semua repo publik org
gh repo list contoso --limit 200 --json name -q '.[].name' | \
  xargs -I{} sh -c 'git clone --bare -q https://github.com/contoso/{}.git /tmp/{}.git 2>/dev/null && \
  git -C /tmp/{}.git log --all --format="%ae|%an" | sort -u'
```

**Kenapa berhasil:** Commit email = identitas login internal; sering `first.last@target.com` — konfirmasi pattern tanpa Hunter.io. **Kenapa gagal:** Org pakai `users.noreply.github.com` sejak 2020 (privacy default untuk commit baru).

---

## 6. Jebakan Operasional di Lapangan

1. **Rate-limit senyap:** Shodan free 1 query/detik, Censys 250/bulan, GitHub search 10/menit → batch script tanpa backoff akan return `429` yang **tampak seperti "tidak ada hasil"**. Selalu cek `X-RateLimit-Remaining` / status code.

2. **Soft-404 vs hard-404:** Maigret/holehe salah klasifikasi karena situs return `200` untuk halaman "user not found" dengan layout sama. Cross-check 2 situs minimum sebelum kunci username.

3. **CDN masking:** Cloudflare/Akamai/Fastly mematikan sinyal port scan & Shodan fingerprint. Jangan simpulkan "no exposure" dari Shodan saja — pindah ke SecurityTrails historical DNS atau CT cert SAN untuk origin.

4. **Metadata yang sudah di-strip:** Dokumen modern (Word 365, LibreOffice default, Google Docs export) sering **tidak punya** Author. Menganggap "file publik = metadata leak" adalah asumsi salah; verifikasi per-file.

5. **Trufflehog false negative:** `--only-verified` menyembunyikan secret format-valid tapi provider mati (mid-2024 banyak key AWS leaked sudah disabled). Untuk triage lengkap jalankan **dua kali**: `--only-verified` (prioritas) + tanpa flag (volume).

6. **GitHub PAT scope:** `read:org` tidak cukup untuk private repo; butuh `repo`. Untuk org besar, PAT akan trigger audit log target → deteksi blue team.

7. **Tor exit blocklist:** holehe/maigret via Tor → 40-70% endpoint return 403. Metrik hasil jatuh drastis; bandingkan dengan run non-Tor.

8. **SMTP RCPT probe = noisy:** Setiap probe tercatat di MTA target + SEG. Untuk engagement nyata, gunakan `--quit-after RCPT` dan **maksimal 1 probe per alamat**, jeda ≥30 detik — greylisting Mimecast/Proofpoint akan blackhole IP setelah 3 probe.

9. **Session/cookie expiry:** GHunt cookies Google expire 6-12 bulan; Shodan API key bisa di-rotate tanpa notice ke script → cek health sebelum batch panjang.

10. **Data residency:** Censys/Shodan menyimpan snapshot di US/EU; query ke host Indonesia tetap legal-samar jika target adalah kriteria "critical infrastructure" (UU PDP + Perpres 47/2023). Koordinasikan dengan legal sebelum batch domain .go.id / .mil.id.

11. **Version drift dokumentasi:** Field API Censys berubah v2→v3 (2023), Hunter.io v2 path stabil tapi quota turun dari 500→25/bulan (free tier 2024). Bookmark changelog, bukan writeup lama.

12. **Time-of-check vs time-of-use:** Repo GitHub yang di-force-push setelah leak → trufflehog scan hari ini miss. Scan commit SHA yang diarsipkan (reflog GitHub ~90 hari via `?until=`), atau pakai GH Archive (BigQuery `github_repos`) untuk forensik.

---

## [reasoning trace]


