# osint-deep — misc

# OSINT: Email/Username Pivot, Domain/IP, GitHub Secret Hunting, Metadata, Employee Footprint

## 1. Email / Username Pivot

### 1.1 holehe (v1.61+) — account discovery from email

**Sent:** HTTP POST/GET to registration/forgot-password endpoints of ~120 sites (Twitter/X, Instagram, Adobe, Spotify, GitHub, etc.). Generally `POST /api/check` or `GET /account/exists?email=`.

**Appears:** Status `[+]` (account registered), `[-]` (not registered), `[x]` (rate-limit/blocked). Does not return PII — only boolean existence.

**Why it works:** Sites leak existence check on signup/forgot-password forms. **Why it fails:** Cloudflare Turnstile (2024+) on signup page, endpoint requires CSRF token, or site uses the same 200 code for exists/not-exists (enumeration mitigation).

```bash
pip install holehe==1.61
holehe target@corp.com --only-used -np
holehe target@corp.com --csv out.csv
# via Tor (rate-limit bypass, tapi banyak endpoint blokir exit node)
holehe target@corp.com --only-used --tor
```

### 1.2 maigret (v0.5.0) — username → 3000+ sites

**Sent:** GET to profile URL (`https://site/user/<username>`) + check 200/404 signature.

**Appears:** Hits + extracted IDs (uid, bio, avatar URL), JSON graph for pivot.

**Why it fails:** Cloudflare (Instagram, TikTok 2024+), soft-404 (all requests 200), login-wall (LinkedIn, Facebook).

```bash
pip install maigret==0.5.0
maigret target_handle --html -a -J out.json
maigret target_handle --site Instagram --site GitHub --site Keybase --timeout 15
maigret target_handle --parse out.json   # re-analyze tanpa refetch
```

### 1.3 Passive combination (without touching target)

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

**Sent:** Query to `api.shodan.io` (not directly to target).
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

**Why it works:** Shodan scanner (Honeypot-aware) already has banner snapshot; favicon hash is hard to rotate. **Why it fails:** Host behind CDN (Cloudflare 104.x), banner stripped (nginx `server_tokens off`), geo-IP firewall blocks scanner (often for ID).

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

**Why it works:** Censys stores full CT logs → finds subdomains not present in DNS/amass. **Why it fails:** Free rate-limit (250 queries/month), field schema changed between v2→v3 (many old writeups use `parsed.names`, no longer valid).

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

**Why it works:** Historical A record reveals origin IP before being CDN'd — this is the most productive pivot for bypassing Cloudflare/Akamai. **Why it fails:** Origin has fully migrated, or historical A record is only a dummy.

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

**Sent:** git clone (shallow) or HTTP GET raw file; then regex match + **verification** (auth check to API provider).

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

**Why it works:** Verification makes a real call to the provider (e.g. `sts:GetCallerIdentity` for AWS, `GET /user` GitHub) → false positive ~0. **Why it fails:** AWS secret in "disabled" status/quota exhausted → `Verified: false` despite valid format; GitHub org requires PAT with `repo`+`read:org` scope; unauthed rate-limit 60 req/hour.

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

**Why it works:** Entropy check (`shannon entropy > 4.5`) catches base64/hex not recognized by regex. **Why it fails:** Files in `.gitignore` since initial commit are not scanned (history only); large repo (>100k commits) requires `--log-opts="--max-count=5000"`; results dominated by `generic-api-key` false positives in lockfiles.

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

**Pitfall:** GitHub code search 2023+ requires login + rate-limit 10 req/minute unauthed. Gists are often ignored by trufflehog org scan (separate scope).

### 3.4 Pre-commit hygiene check (defensive validation)

```bash
# Cek apakah target pakai gitleaks pre-commit
curl -s https://raw.githubusercontent.com/contoso/repo/main/.pre-commit-config.yaml
```

---

## 4. Document Metadata

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

### 4.2 Most important fields

| Field | Source | OSINT Value |
|---|---|---|
| `Author` / `dc:creator` | OOXML `docProps/core.xml`, PDF `/Author` | Username internal / domain login |
| `LastModifiedBy` | OOXML `cp:lastModifiedBy` | Nama karyawan aktif |
| `Company` | OOXML `docProps/app.xml` | Konfirmasi organisasi |
| `Template` | OOXML `app.xml` | Path UNC internal (`\\fileserver\...)` |
| `CreatorTool` / `Producer` | PDF `/Producer` | Versi Office/Word (mis. `Microsoft® Word 2019`) |
| `CreateDate` / `ModifyDate` | all | Timezone leak (offset UTC+7 → ID) |
| GPS | JPEG EXIF | Lokasi fisik |
| `manager`, `revision` | OOXML `app.xml` | Team structure |

**Why it works:** Office writes default metadata from Windows account; users rarely strip it. **Why it fails:** Files from Google Docs/Sheets → minimal metadata (`Author: anonymous`); Word 365 (2024+) with "Remove personal info on save" enabled → strips all PII; DOCX round-tripped through LibreOffice writes `LibreOffice/24.x` and discards original Author.

### 4.3 Batch harvest from the web

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

**Passive (recommended, does not touch target):**
```
site:linkedin.com "Contoso" "Security Engineer"
site:linkedin.com/in "at Contoso" "since 2024"
site:linkedin.com "Contoso" "red team"
```

**Active harvest (mind the ToS):** LinkedIn aggressively refuses scraping (2024+ blocks unauthed via `HTTP 999`). Use the official API or derived datasets (Common Crawl, `theharvester` aggregation).

### 5.2 theharvester v4.6.0

```bash
theHarvester -d target.com -b linkedin,google,bing,duckduckgo,crtsh,hunter \
  -l 500 -f out.html
```

**Why it fails:** Bing Google API key required for results >10; LinkedIn backend has not worked since 2023 (returns 0).

### 5.3 Hunter.io / Apollo / RocketReach

```bash
# Hunter.io email pattern
curl -s "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=$HUNTER" \
  | jq '.data.pattern, .data.emails[0:5]'
# → "pattern": "{first}.{last}"
```

Pivot pattern → enumeration: `first.last@`, `flast@`, `first@`. Verify via SMTP `RCPT TO` (grey-listing risk, use `swaks` v20240103):

```bash
swaks --to first.last@target.com --from probe@example.com \
  --server mx.target.com --quit-after RCPT
# 250 = valid, 550 = tidak ada
```

**Why it fails:** Catch-all domain (all 250), greylisting (451 defer), EDR/SEG (Mimecast, Proofpoint) blackhole after 3 probes.

### 5.4 Naming pattern → credential attack surface

Important pivot: `first.last@target.com` + holehe + HIBP + GitHub leak → list of accounts that **definitely exist**. For red team, this is input to password spray (separate Chapter), not part of OSINT.

### 5.5 Organizational chart reconstruction

Sumber komplementer:
- **GitHub org members** (`https://api.github.com/orgs/<org>/members`) → often overlaps with engineering
- **Conference talk slides** (Speakerdeck, Defcon media) → metadata + email in slides
- **Commit emails**: `git log --format='%ae %an' | sort -u` from public repo → internal email (`@target.com`)
- **npm/PyPI package maintainer** emails
- **SSL cert SAN** + Whois → admin email

```bash
# Commit email harvest dari semua repo publik org
gh repo list contoso --limit 200 --json name -q '.[].name' | \
  xargs -I{} sh -c 'git clone --bare -q https://github.com/contoso/{}.git /tmp/{}.git 2>/dev/null && \
  git -C /tmp/{}.git log --all --format="%ae|%an" | sort -u'
```

**Why it works:** Commit email = internal login identity; often `first.last@target.com` — confirms pattern without Hunter.io. **Why it fails:** Org uses `users.noreply.github.com` since 2020 (privacy default for new commits).

---

## 6. Operational Pitfalls in the Field

1. **Silent rate-limit:** Shodan free 1 query/second, Censys 250/month, GitHub search 10/minute → batch script without backoff will return `429` that **looks like "no results"**. Always check `X-RateLimit-Remaining` / status code.

2. **Soft-404 vs hard-404:** Maigret/holehe misclassify because the site returns `200` for "user not found" pages with the same layout. Cross-check at least 2 sites before locking a username.

3. **CDN masking:** Cloudflare/Akamai/Fastly kill port scan signals & Shodan fingerprint. Do not conclude "no exposure" from Shodan alone — move to SecurityTrails historical DNS or CT cert SAN for origin.

4. **Metadata that has been stripped:** Modern documents (Word 365, LibreOffice default, Google Docs export) often **do not have** an Author. Assuming "public file = metadata leak" is a wrong assumption; verify per-file.

5. **Trufflehog false negative:** `--only-verified` hides format-valid secrets but dead provider (mid-2024 many leaked AWS keys already disabled). For complete triage run **twice**: `--only-verified` (priority) + without flag (volume).

6. **GitHub PAT scope:** `read:org` is not enough for private repo; needs `repo`. For large orgs, PAT will trigger target audit log → blue team detection.

7. **Tor exit blocklist:** holehe/maigret via Tor → 40-70% endpoint return 403. Result metrics drop drastically; compare with non-Tor run.

8. **SMTP RCPT probe = noisy:** Every probe is recorded in target MTA + SEG. For real engagement, use `--quit-after RCPT` and **maximum 1 probe per address**, delay ≥30 seconds — Mimecast/Proofpoint greylisting will blackhole IP after 3 probes.

9. **Session/cookie expiry:** GHunt Google cookies expire 6-12 months; Shodan API key can be rotated without notice to script → check health before long batch.

10. **Data residency:** Censys/Shodan store snapshots in US/EU; query to Indonesian hosts remains legally ambiguous if target is "critical infrastructure" criteria (UU PDP + Perpres 47/2023). Coordinate with legal before batch of .go.id / .mil.id domains.

11. **Documentation version drift:** Censys API fields changed v2→v3 (2023), Hunter.io v2 path stable but quota dropped from 500→25/month (free tier 2024). Bookmark changelog, not old writeups.

12. **Time-of-check vs time-of-use:** GitHub repo that was force-pushed after leak → trufflehog scan today misses. Scan archived commit SHA (GitHub reflog ~90 days via `?until=`), or use GH Archive (BigQuery `github_repos`) for forensics.

---

## [reasoning trace]


