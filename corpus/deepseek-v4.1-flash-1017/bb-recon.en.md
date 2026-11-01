# bb-recon — bb

# Bug Bounty Recon 2026 — Technical Reference

## 1. Peta Pipeline

| Stage | Tool | Input | Output | Key artifacts |
|---|---|---|---|---|
| Subdomain enum | subfinder, amass (passive), github-subdomains | domain | `subs.txt` | resolvable + wildcard noise |
| Resolusi & validation | puredns, dnsx | `subs.txt` | `resolved.txt` | A/AAAA/CNAME |
| Permutation | gotator, dnsgen | `subs.txt` | `perm.txt` | brute force wordlist resp |
| HTTP probe & tech | httpx | `resolved.txt` | `httpx.json` | status, title, tech, CDN |
| Port scan | naabu | `resolved.txt`/IPs | `ports.txt` | non-80/443 |
| URL collection | waybackurls, gau, katana | subs | `urls.txt` | params, endpoints |
| JS mining | LinkFinder, SecretFinder, xnLinkFinder | JS URLs | `endpoints.txt`, `secrets.txt` | API rot, tokens |
| Vuln scan | nuclei | URLs | `nuclei.txt` | CVE, exposures |

---

## 2. Subdomain Enumeration

### 2.1 subfinder (v2.6.x)

```bash
subfinder -d example.com -all -recursive -silent -o subs_subfinder.txt
# dengan config provider API (Shodan, Censys, SecurityTrails, Virustotal, Chaos)
subfinder -dL scopes.txt -all -recursive -timeout 30 -max-time 60 -o subs_all.txt
```

- **Sent**: query to ~40 passive sources (CT logs, VirusTotal, Censys, Shodan, Chaos, bufferover, etc.). Not active DNS resolution.
- **Appears**: subdomain + source tag (`-v` to see source). Output auto-deduplicated.
- **Why it fails**: provider API not set → only CT logs run (Censys/VT/Chaos skipped). `-all` without API key = ~30% coverage. Domain not in CT (private/internal) → empty.

### 2.2 amass passive (v4.x / OWASP Amass v5 fork)

```bash
amass enum -passive -d example.com -o amass_passive.txt -config ~/.config/amass/config.ini
amass enum -passive -df scopes.txt -o amass_all.txt
```

- **Sent**: query to passive sources only (no active DNS). Differs from `-active`, which performs zone transfer + bruteforce.
- **Appears**: subdomain + assoc source. Amass has a local federated DB (`~/.config/amass/amass.sqlite`) — use `amass db -names -d example.com` to dump.
- **Why it fails**: amass v4 often hangs on certain sources (Wayback) — set `timeout` per source in config. v5 syntax differs (`amass enum -passive` → stays the same, but config path changes). Without `-timeout`, one slow source blocks the entire run.

### 2.3 github-subdomains (v1.x)

```bash
export GITHUB_TOKEN=ghp_xxx
github-subdomains -d example.com -t $GITHUB_TOKEN -o gh_subs.txt
github-subdomains -d example.com -t $GITHUB_TOKEN -raw -o gh_raw.txt
```

- **Sent**: GitHub Search API query `example.com`. Searches for the domain string in code, commits, issues, PRs.
- **Appears**: subdomains that appear in public repo text + repo URL.
- **Why it fails**: rate limit 30 req/min unauthenticated, 5000/hour user token. Without token → exhausted in 1 query. Term "example.com" hits code search restriction (GitHub code search must be authenticated + repo indexed). Private repos are not covered.

### 2.4 Agregasi

```bash
cat subs_subfinder.txt amass_passive.txt gh_subs.txt | sort -u > subs.txt
```

---

## 3. Resolution & Validation

### 3.1 puredns (v2.1.x)

```bash
# resolvers: puredns butuh massdns; pakai resolvers publik
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
puredns resolve subs.txt -r resolvers.txt -w resolved.txt --rate-limit 5000
# wildcard filtering sebelum bruteforce
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w brute_out.txt --wildcard-tests 10
```

- **Sent**: DNS A/AAAA query to resolver list, with burst via massdns.
- **Appears**: subdomains that resolve. `--wildcard-tests` detects wildcard `*.example.com` with 10 random queries.
- **Why it fails**: wildcard not filtered → `subs.txt` full of false positives (e.g. `anything.example.com` resolves to parked IP). `--rate-limit` too high → public resolver blocks → resolution drops (false negative). Resolver list dead/outdated → 0 results.

### 3.2 dnsx (v1.2.x)

```bash
dnsx -l subs.txt -a -resp -silent -o dnsx_a.txt
dnsx -l resolved.txt -cname -resp -silent -o cname.txt    # dangling CNAME hunting
dnsx -l subs.txt -a -resp-only -json -o dnsx.json
```

- **Sent**: direct A/AAAA/CNAME/TXT query (without massdns, Go resolver).
- **Appears**: record + value. `-cname` for subdomain takeover (S3, GitHub Pages,Heroku, Azure — check with nuclei `takeovers/`).
- **Why it fails**: dnsx uses system resolver by default → hits ISP/router rate limit. Set `-r resolvers.txt` explicitly. `-resp-only` hides the domain — do not use it for JSON pipeline.

---

## 4. Permutation

### 4.1 gotator (v1.x)

```bash
gotator -sub subs.txt -perm wordlist-perm.txt -depth 2 -numbers 3 -md -silent > perm.txt
gotator -sub resolved.txt -perm /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -depth 1 -mindup -md -silent > perm.txt
```

- **Dikirim**: kombinasi `existing-sub + delimiter + word` (mis. `dev` → `dev-api`, `api-dev`, `dev1`, `dev2`).
- **Muncul**: kandidat subdomain baru (belum diresolve).
- **Why it fails**: `-depth 2` + large wordlist → millions of candidates, resolution takes hours. Without `-md` (mindup/dedup) → duplicates bloat. Use `-numbers 3` to enumerate `app1..app999`.

### 4.2 Pipeline permutation lengkap

```bash
gotator -sub resolved.txt -perm wordlist-perm.txt -depth 1 -silent > perm.txt
dnsgen resolved.txt > dnsgen_out.txt
cat perm.txt dnsgen_out.txt | sort -u > perm_all.txt
puredns resolve perm_all.txt -r resolvers.txt -w perm_resolved.txt --wildcard-tests 10
```

---

## 5. HTTP Probe & Tech Detect

### 5.1 httpx (v1.6.x)

```bash
httpx -l resolved.txt -silent -threads 100 -timeout 10 \
  -status-code -title -tech-detect -web-server -cdn -cname \
  -json -o httpx.json
# filter hidup
httpx -l resolved.txt -silent -mc 200,201,301,302,401,403 -o live.txt
# screenshot
httpx -l live.txt -silent -ss -srd screenshots/
```

- **Sent**: HTTP GET (default) to 80/443 + HTTPS fallback, User-Agent header `httpx/1.6`.
- **Muncul**: status, title, tech (via Wappalyzer signatures lokal), server (`nginx 1.25`, `Apache 2.4.62`), CDN (Cloudflare/Akamai), CNAME.
- **Why it fails**:
- WAF CDN (Cloudflare 2024+) returns 403 with challenge page → mass 403 status, tech detect only "Cloudflare".
- Default httpx User-Agent is often blocked (403); set `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"`.
- `-cdn` filter: `-fcdn cloudflare` to skip CF, but this also discards legitimate targets on CF.
- TLS SNI mismatch on direct IP → httpx fails; use `-sni` or `-host`.

---

## 6. Port Scan

### 6.1 naabu (v2.3.x)

```bash
naabu -l resolved.txt -top-ports 1000 -rate 5000 -silent -o naabu_top.txt
naabu -l resolved.txt -p - -rate 3000 -silent -o naabu_full.txt   # full 65535
naabu -host target.com -p 21,22,80,443,3306,5432,6379,8080,8443,9200,27017 -silent -o naabu_services.txt
```

- **Sent**: TCP SYN (default, requires root) or CONNECT scan. Global rate per second.
- **Appears**: `host:port`. `-json` for details.
- **Why it fails**: without root → fallback to CONNECT (slow, hits WAF). `-rate 5000` on shared ISP → SYN flood detection, packet loss, false negative. Scan from cloud VPS (DigitalOcean/AWS) → egress IP often blacklisted by target; scan from residential is more accurate. Port filtered by stateful firewall → naabu does not always distinguish `closed` vs `filtered`.

---

## 7. URL Collection

### 7.1 waybackurls (v0.2.x)

```bash
cat subs.txt | waybackurls | tee wb_raw.txt | sort -u > wb.txt
cat wb.txt | grep -Ev '\.(png|jpg|jpeg|gif|css|woff|woff2|svg|ico)$' | sort -u > wb_clean.txt
```

- **Sent**: query to `web.archive.org/cdx/search/cdx?url=*.example.com/*&output=txt&collapse=urlkey`.
- **Muncul**: URL historis (termasuk param, endpoint mati).
- **Why it fails**: Wayback rate limit (can be 429) — bulk 1000 subdomains gets blocked. `collapse=urlkey` deduplicates; without it output is bloated. Wayback only has snapshots that were crawled — new endpoints (<6 months) are absent.

### 7.2 gau (v2.2.x)

```bash
cat subs.txt | gau --threads 5 --subs --providers wayback,commoncrawl,otx,urlscan --o gau.txt
gau --providers wayback --blacklist png,jpg,gif,css,woff,svg,ico --fc 404,403 --o gau_clean.txt
```

- **Dikirim**: query multi-provider (Wayback, CommonCrawl 2024 index, OTX AlienVault, URLScan).
- **Appears**: URL + source. Selective `--providers` for rate control.
- **Why it fails**: `--subs` without `*.` handling → subdomain `a.b.example.com` is sometimes queried as `subs.a.b.example.com`. CommonCrawl index requires downloading large WARC files (slow). Rate limit per provider.

### 7.3 katana (v1.1.x)

```bash
# crawler aktif
katana -list live.txt -d 3 -jc -kf all -silent -o katana.txt
# headless (butuh chrome)
katana -list live.txt -d 3 -headless -jsl -noi -silent -o katana_headless.txt
# form & endpoint parsing
katana -list live.txt -d 2 -aff -fx -silent -o katana_form.txt
```

- **Sent**: active HTTP request + JS parsing (with `-jsl`), form fill (`-aff`), XHR (`-fx`).
- **Muncul**: endpoint live + `method`, `form`, path JS.
- **Why it fails**: without `-headless` → SPA (React Router, Angular, Vue 3) is not crawled because it is JS-driven. `-headless` requires Chrome 131+ / `KATANA_HEADLESS_BROWSER=/path/chrome`. Scope leak: `-fs rdn` (fqdn/rdn) is required to limit to registrable domain. Depth >3 → time explodes.

### 7.4 Gabungan

```bash
cat wb.txt gau.txt katana.txt | sort -u | grep -Ev '\.(png|jpg|jpeg|gif|css|woff2?|svg|ico|ttf)$' > urls_all.txt
cat urls_all.txt | grep '=' > urls_params.txt
cat urls_all.txt | grep -E '\.(js|mjs|jsx|ts)$' > urls_js.txt
```

---

## 8. JS Mining

### 8.1 LinkFinder (v1.x, Python)

```bash
python3 linkfinder.py -i https://example.com/app.js -o cli
cat urls_js.txt | while read u; do python3 linkfinder.py -i "$u" -o cli; done | sort -u > linkfinder_out.txt
cat urls_js.txt | while read u; do python3 linkfinder.py -i "$u" -o cli -d; done  # -d = endpoints dinamis
```

- **Sent**: fetch JS + regex `js-beautify`-style extraction for paths & endpoints.
- **Muncul**: `/api/v1/users`, `/graphql`, `/internal/admin`.
- **Why it fails**: minified Webpack/Vite bundle with base64 string / template literal (`${a}${b}`) → regex miss. Source map `.js.map` usually directly gives original source — check `curl -s $js_url | grep sourceMappingURL`. LinkFinder Python does not handle dynamic `import()` with variables.

### 8.2 SecretFinder (v1.x)

```bash
python3 SecretFinder.py -i https://example.com/app.js -o cli
cat urls_js.txt | while read u; do python3 SecretFinder.py -i "$u" -o cli -e; done | tee secrets_raw.txt
```

- **Dikirim**: regex set (AWS AKIA, Google API `AIza`, Stripe `sk_live`, JWT, private keys, Slack `xox[baprs]`, GitHub `ghp_`, Twilio, SendGrid).
- **Muncul**: match + entropy score.
- **Why it fails**: minifier splits tokens (`AKIA` + runtime concat) → regex miss. Modern bundler stores secrets in runtime config (`window.__ENV__`) that is fetched separately — requires headless to intercept. Entropy-based false positives are high; validate tokens with vendor tool (e.g. `TruffleHog verify`).

### 8.3 xnLinkFinder (v1.x, Golang)

```bash
xnLinkFinder -i https://example.com -d 3 -sp https://example.com -o xnOut.txt
xnLinkFinder -i urls_js.txt -sf subdomains.txt -d 2 -o xn_links.txt -v
# secret + endpoint bersamaan
xnLinkFinder -i https://example.com -d 3 -o xn.txt -sf subs.txt -s
```

- **Sent**: crawl + JS parse (regex more aggressive than LinkFinder, handles `import()`, `fetch`, `axios`, optional base64 decode).
- **Muncul**: link + parameter + secret.
- **Why it fails**: `-sp` (scope) must be set, otherwise it will crawl outside the domain. Flag `-d 3` + `-s` (secret) slows down significantly; limit `-d 2` for batch.

---

## 9. Nuclei Selection

### 9.1 Versi & Instalasi

```bash
nuclei -version   # v3.3.x (2025) / v3.4+ (2026)
nuclei -update-templates
```

### 9.2 Seleksi Template — Prioritas Recon

```bash
# 1) Exposures & misconfig (paling produktif di awal)
nuclei -l live.txt -tags exposure,config,backup,logs -severity medium,high,critical -o nuclei_exp.txt

# 2) Takeover
nuclei -l resolved.txt -t http/takeovers/ -o nuclei_takeover.txt
nuclei -l cname.txt -t dns/takeover/ -o nuclei_dns_takeover.txt

# 3) CVE by tech (pakai httpx tech output)
nuclei -l live.txt -tags cve -severity high,critical -o nuclei_cve.txt

# 4) Default credential & panel
nuclei -l live.txt -tags default-login,panel -o nuclei_panel.txt

# 5) Specific tech dari httpx
nuclei -l live.txt -tags nginx,apache,jenkins,grafana,gitlab,wordpress -o nuclei_tech.txt
```

| Kategori | Tags | Noise | Prioritas |
|---|---|---|---|
| Takeover | `takeover` | rendah | 1 |
| Exposures | `exposure`, `config`, `backup` | medium | 1 |
| CVE | `cve` + `-severity high,critical` | tinggi | 2 |
| Default login | `default-login` | medium | 2 |
| Fuzzing | `fuzz` | tinggi + kena WAF | 3 |
| Tech recon | `tech` | rendah | 3 |

- **Dikirim**: request template YAML per matcher. Matcher berbasis regex/status/word/dsl.
- **Muncul**: match + matcher-name + extracted.
- **Why it fails**:
- `-tags cve` without updating templates → CVE 2025/2026 are missing.
- Default rate limit (`-rl 150`) hits WAF 429; set `-rl 50 -c 25` for sensitive targets.
- The `fuzz` template produces thousands of false positives if the target returns 200 for all paths — `-fs` filter or a custom matcher is mandatory.
- Interactsh (`-interactsh-server`) requires outbound DNS/HTTP — blocked on many networks → OOB detection is dead.

---

## 10. Chained Commands (Resep Lengkap)

### 10.1 Recon day-1 (passive → resolve → http → scan)

```bash
DOMAIN=example.com
mkdir -p recon/$DOMAIN && cd recon/$DOMAIN

subfinder -d $DOMAIN -all -recursive -silent -o subs_subfinder.txt
amass enum -passive -d $DOMAIN -o amass.txt 2>/dev/null
github-subdomains -d $DOMAIN -t $GITHUB_TOKEN -o gh.txt
cat subs_subfinder.txt amass.txt gh.txt | sort -u > subs.txt

curl -s https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt
puredns resolve subs.txt -r resolvers.txt -w resolved.txt --wildcard-tests 10

httpx -l resolved.txt -silent -threads 100 -timeout 10 \
  -status-code -title -tech-detect -cdn -cname -json -o httpx.json
httpx -l resolved.txt -silent -mc 200,201,301,302,401,403 -o live.txt

naabu -l resolved.txt -top-ports 1000 -rate 3000 -silent -o naabu.txt

nuclei -l live.txt -tags takeover,exposure,config -severity medium,high,critical -rl 100 -o nuclei_day1.txt
```

### 10.2 Permutation chain

```bash
gotator -sub resolved.txt -perm wordlist-perm.txt -depth 1 -md -silent > perm.txt
dnsgen resolved.txt > dnsgen.txt
cat perm.txt dnsgen.txt | sort -u > perm_all.txt
puredns resolve perm_all.txt -r resolvers.txt -w perm_resolved.txt --wildcard-tests 10
httpx -l perm_resolved.txt -silent -mc 200,301,302,401,403 -o perm_live.txt
```

### 10.3 URL + JS + diffable artefak

```bash
cat subs.txt | gau --threads 5 --subs --providers wayback,commoncrawl,otx,urlscan -o gau.txt
cat subs.txt | waybackurls | sort -u > wb.txt
katana -list live.txt -d 3 -jc -kf all -jsl -noi -silent -o katana.txt

cat gau.txt wb.txt katana.txt | sort -u \
  | grep -Ev '\.(png|jpe?g|gif|css|woff2?|svg|ico|ttf|eot|mp4)$' > urls_all.txt
cat urls_all.txt | grep '=' > urls_params.txt
cat urls_all.txt | grep -E '\.(js|mjs|jsx|ts)$' | sort -u > urls_js.txt

# JS mining paralel
cat urls_js.txt | xargs -P 8 -I{} xnLinkFinder -i {} -sf subs.txt -d 1 -silent 2>/dev/null > xn_all.txt
cat urls_js.txt | xargs -P 8 -I{} sh -c 'python3 SecretFinder.py -i "{}" -o cli -e 2>/dev/null' > secrets.txt 2>&1

# Nuclei final
nuclei -l urls_all.txt -tags exposure,config,backup,logs,cve -severity medium,high,critical -rl 100 -o nuclei_urls.txt
```

### 10.4 Diff between runs (monitoring)

```bash
# run harian
comm -13 <(sort resolved_$(date -d yesterday +%F).txt) <(sort resolved_$(date +%F).txt) > new_subs.txt
comm -23 <(sort resolved_$(date -d yesterday +%F).txt) <(sort resolved_$(date +%F).txt) > gone_subs.txt
```

---

## 11. Operational Pitfalls in the Field

| Jebakan | Gejala | Mitigasi |
|---|---|---|
| **Wildcard DNS** | All `subs*.example.com` resolve → mass false positives, JHaddix wordlist is useless | `puredns --wildcard-tests 10`; verify with 3 random queries |
| **Resolver publik mati/rate-limit** | Resolusi drop, `resolved.txt` tipis | Rotasi `resolvers.txt` (trickest), `--rate-limit 3000`, fallback `dnsx -r` |
| **Source APIs not configured** | subfinder/amass coverage ~30% | Set `provider-config.yaml` (Shodan, Censys, Virustotal, SecurityTrails, Chaos), amass `config.ini` |
| **VPN/Cloud egress blacklisted** | mass httpx 403, naabu all ports filtered | Scan from residential/another VPS region; `-H` UA Chrome 131; `-tls-grab` to verify TLS |
| **Cloudflare 403 challenge** | httpx status 403, tech=Cloudflare, missing title | `-fcdn cloudflare` to skip, or `-favicon` + origin leak analysis via dnsx CNAME |
| **WAF blocks nuclei** | consecutive 429s, 5-minute scan → 30 requests | `-rl 30 -c 10`, realistic `-H` UA, `-retries 2`, `-ni` delay for interactsh |
| **Interactsh unreachable** | OOB detection (SSRF, blind CVE) silent | custom `-iserver` / VPS; verify `curl https://oast.fun` from the scanner host |
| **SPA not crawled** | katana only gets root + static | `-headless` + Chrome 131 binary, `-nos` to skip non-headless |
| **Minified JS misses endpoints** | LinkFinder output empty/false | Check `.js.map` (`sourceMappingURL`), parse `import()` via xnLinkFinder, or headless + DevTools protocol |
| **SecretFinder false positives** | Thousands of "keys" from high-entropy strings | Validate per vendor (AWS STS, Google API key checker, TruffleHog `--only-verified`) |
| **Outdated Nuclei templates** | CVE 2025/2026 missed | `nuclei -update-templates` before run; pin template version per engagement |
| **Scope drift** | Scanning domains outside in-scope → out-of-bounds bounty | Keep `scopes.txt`; katana `-fs rdn`, gau `--subs` with `*.example.com` filter; review diff |
| **Wayback rate limit** | waybackurls/gau 429 or partially empty output | Split input per 50 subs, `sleep 2`, use only gau `--providers wayback` |
| **Permutation eksplosif** | gotator `-depth 2` × wordlist 10k = 1M kandidat | `-depth 1`, `-md`, puredns `--rate-limit 5000`, batch 250k per iterasi |
| **Pipeline timeout** | httpx `-timeout 10` but target is slow (Nginx 1.25 with slow backend) | `-timeout 15 -retries 2`, `-http2` for modern servers |
| **DNS rebinding / sinkhole** | Resolves to internal IP (10.x, 172.16.x) → httpx hangs | Filter private IPs post-resolve: `grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'` |
| **Amass v4 vs v5 config** | Command runs but 0 output | Check `amass -version`; v5 uses `amass enum -passive -d` + `$AMASS_CONFIG`; migrate `config.ini` |
| **Naabu without root** | Slow scan, hits WAF, false negatives | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/naabu` or run as root (VPS) |
| **Output not reproducible** | Diff between runs invalid | Set `TZ=UTC`, use consistent file timestamps, `sort -u` before saving, save `versions.txt` (subfinder -version, httpx -version, etc.) |

---

## [reasoning trace]


