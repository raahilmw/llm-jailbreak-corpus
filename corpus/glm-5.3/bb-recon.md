# bb-recon — bb

# Chapter 12: Bug Bounty Recon Pipeline 2026

## 12.1 Overview Arsitektur Pipeline

Modern recon pipeline consists of 5 stages: subdomain enumeration → DNS resolution → permutation → HTTP/service probing → URL & JS mining → template scanning.

```
Assets → subfinder/amass → puredns resolve → dnsx/gotator → httpx → naabu
                                                              ↓
                                        waybackurls/gau/katana → LinkFinder/SecretFinder/xnLinkFinder → nuclei
```

---

## 12.2 Subdomain Enumeration

### 12.2.1 subfinder

**Command:**
```bash
subfinder -d target.com -all -recursive -o subs_subfinder.txt -t 100 \
  -sCT  # simpan certificate transparency raw
```
The `-all` flag executes all sources (default only passively-fast sources). Reference version: subfinder v2.6.x (projectdiscovery).

**What is sent:** queries to 30+ passive sources (Censys, crt.sh, FOFA, Chaos, VirusTotal, Shodan, SecurityTrails).
**What appears:** plaintext subdomain list.
**Why it works:** passive sources do not touch target infrastructure — zero footprint, not affected by WAF/rate limit.
**Why it fails:** Censys/Shodan free tier API accounts exhaust hourly quota; internal-only subdomains (never exposed to CT logs) do not appear.

Set up API keys in `$HOME/.config/subfinder/provider-config.yaml`:

```yaml
censys: ["<api-id>:<secret>"]
shodan: ["<api-key>"]
virustotal: ["<api-key>"]
github: ["<token>"]
chaos: ["<projectdiscovery-api-key>"]
```

### 12.2.2 Amass (passive mode)

**Command:**
```bash
amass enum -passive -d target.com -o subs_amass.txt \
  -config ~/.config/amass/config.ini
```
Amass v4.x. `-passive` mode = no packets to target infrastructure. Adding `-alts` does not work in passive mode — permutation only works in active mode (`-active`), use gotator instead (see 12.4).

**Difference vs subfinder:** Amass also extracts subdomains from ASNP/others relationships and web page parsing (passively scraping vendor pages), so it often finds assets belonging to vendors/brands that `subfinder` misses.

**Why it fails:** Amass is slow — passive full `target.com` can take 20-40 minutes. Dead source timeouts (BeетеAPI, etc.) cause hangs without progress in some builds v4.0-4.3.

### 12.2.3 github-subdomains

**Command:**
```bash
github-subdomains -d target.com -t ghp_xxxx -o subs_github.txt
# atau via gau-style token file
```

**What is sent:** GitHub code search API for `-d target.com` and subdomain patterns.
**What appears:** subdomains that appear in code/PR/issues — including **internal subdomains**: `internal-api.target.com`, `staging.target.com`, dev URLs in config files.
**Why it works:** developers leak internal hostnames in repos, gists, and removed gists but still indexed.
**Why it fails:** GitHub API rate limit 30 search requests/minute (authenticated 30/minute, unauthenticated 10/minute). Use multiple tokens and rotate.

### 12.2.4 Fusi & Dedup

```bash
cat subs_*.txt | sort -u > subs_all.txt
# normalisasi wildcard: hapus entry yang resolve ke semua NXDOMAIN
```

---

## 12.3 Resolusi DNS — puredns & dnsx

### 12.3.1 puredns

**Perintuh:**
```bash
puredns resolve subs_all.txt \
  --resolvers resolvers.txt \
  --wildcard-domain target.com \
  --wildcard-batch 30 \
  -w subs_resolved.txt \
  --dns-validate
```

**What is sent:** DNS A/AAAA queries to public resolvers (resolver list ~1000 entries from trickest/resolvers). `--wildcard-batch 30` tests 30 random prefixes (`a1b2c3.target.com`) for wildcard DNS detection.
**What appears:**
- `subs_resolved.txt` — only subdomains that resolve, **free of wildcard false positives**
- `subs_wildcards.txt` — subdomains under wildcard records.

**Why it works:** puredns performs two-pass validation (`--dns-validate`): each IP answer is re-verified by another resolver to avoid DNS poisoning/router hijack from dead resolvers.

**Why it fails:** ISP resolvers on operational networks perform DNS filtering → false negatives. DNS providers (Cloudflare 1.1.1.1, Quad9) rate limit mass resolution (>~2000 req/min) → truncated results. Switch to local resolv.conf DNS server or subscribe to an updated trickest resolver list.

### 12.3.2 dnsx

**Command:**
```bash
dnsx -l subs_resolved.txt -a -aaaa -cname -resp -silent -o dnsx_out.txt \
  -cdn  # deteksi CDN (bug bounty reject WAF/CDN assets sering)
cat subs_resolved.txt | dnsx -a -resp -recon  # screenshot-style fingerprint
```

**What appears:**
```
api.target.com [1.2.3.4] [CNAME: api-eu-west-1.elb.amazonaws.com] [AWS]
static.target.com [... CNAME: d3xyz.cloudfront.net] [CDN: CloudFront]
```

**Why it matters:** the `-cdn` flag tells you **before** scanning whether an asset is on a CDN — saving nuclei runs and preventing scan blocking/whitelabel errors. CNAME chain disclosure also often leaks third-party assets (SaaS vendors, forgotten stacks).

Fingerprint berbasis teks:
```bash
dnsx -l subs_resolved.txt -a -resp -fc <(internetdb response, use ipinfo)
```

---

## 12.4 Permutation — gotator

**Command:**
```bash
gotator -sub subs_resolved.txt -perm permutations_list.txt -depth 1 \
  -numbers 10 -mindup -adv -md -silent > subs_permutations.txt

puredns resolve subs_permutations.txt --resolvers resolvers.txt \
  --wildcard-batch 30 -w subs_perm_resolved.txt
```

**What is sent:** generates candidates from wordlist patterns (`admin.`, `dev.`, `vpn.`, `-prod`, `-homolog`, `old.`, `uat.`) on each subdomain:
```
api.target.com → api-dev.target.com, api-old.target.com, admin-api.target.com
```

**What appears:** subdomains that do not appear in CT logs — because their certs are wildcards (important: many companies use `*.target.com` wildcards so CT logs are zero-visible).
**Why it works:** consistent internal naming convention. If `api-eu.target.com` exists, `api-us.target.com` and `api-asia.target.com` most likely exist.
**Why it fails:** without `--wildcard-batch` during resolution, permutation results on wildcard domains (e.g., `*.cloudfront.net`) produce 100% false positives.

---

## 12.5 HTTPXTech Detect

**Command:**
```bash
httpx -l subs_all_resolved.txt -o httpx_out.txt \
  -title -tech-detect -status-code -follow-redirects \
  -ports 80,443,8080,8443,8888,9443 \
  -threads 150 \
  -timeout 15 \
  -json -o httpx.json \
  -location   # capture Location header untuk redirect routing
  -cname \
  -websocketpathx  # not yet standard
```

Core flags for recon:
| Flag | Fungsi |
|------|--------|
| `-tech-detect` | fingerprint via Wappalyzer core (nginx 1.25, Apache 2.4.62, WordPress 6.x, React, Next.js) |
| `-title` | HTML `<title>` |
| `-status-code` | HTTP status |
| `-follow-redirects` | follows to origin server (reveals `login.target.com` → SaaS) |
| `-web-server` | parse `Server` header (nginx 1.25.3, Werkzeug 3.0, IIS 10.0) |
| `-ip`, `-cname`, `-cdn` |

Sample output JSON:
```json
{
  "url": "https://admin.target.com",
  "status_code": 200,
  "title": "Grafana",
  "webserver": "nginx 1.25.3",
  "tech": ["Grafava 10.4.0", "Go", "nginx 1.25.3"]
}
```

**Why it works:** concrete software versions = triage origination. Grafana 10.x → check CVE-2024-9264 (SQL Expressions), nginx 1.25 without patch → known cve path.
**Why it fails:** banner masking, `Server:` removed; TLS fingerprint false; some web apps use SPAs where the title is blank ("Loading...") — merging of 443 and 80 probing needed.

---

## 12.6 Port Scanning — naabu

**Command:**
```bash
naabu -l live_hosts.txt -top-ports 1000 -rate 1000 -c 25 \
  -exclude-ips /24-range/to-skip.txt \  # skip CIDR sponsor-owned
  -o naabu_1000.txt
# atau full TCP range untuk high-value hosts:
naabu -host high_value_target -p - -rate 1500 -o naabu_full.txt
# service detection via nmap jika perlu UDP:
sudo nmap -sU -sV --top-ports 100 high_value_target
```

Naabu v2.3.x — SYN scan, ultra cepat (10k+ pps), tapi:
**Why it fails:** requires root/SYN_RAW for full performance; on Windows 11 24H2/WSL2 raw socket privilеge issue — run via VPS Linux. High SYN rate triggers IDS — some providers block inbound ICMP dest-unreachable → false positive open port; always verify:
```bash
nc -zv host port  # atau
nmap -sV -p PORT host
```

---

## 12.7 URL Collection

### 12.7.1 waybackurls & gau

```bash
echo target.com | waybackurls > urls_wayback.txt
gau --threads 5 --timeout 30 target.com --o urls_gau.txt
# gabung
cat urls_*.txt | sort -u > urls_all.txt
# filter injection points:
cat urls_all.txt | uro > urls_uniq.txt  # dedup with param-based uniqueness
grep "api\|admin\|internal\|\?.*=" urls_uniq.txt | qsreplace FUZZ
```

**What appears:** historical URLs including endpoints that are **already deprecated** but still live (`.php` endpoints, `?id=` parameters, `/api/v1/` paths). Additionally add CommonCrawl + OTX + URLScan index.

### 12.7.2 katana (crawler aktif)

```bash
katana -u https://target.com -d 5 -jc -kf all -fx \
  -o urls_katana.txt \
  -c 60 -headless  # JS-render untuk SPA (Chrome 131 headless)
```

Important flags: `-jc` JS crawl (follows routes inside bundles), `-fx` fetch-xhr (intercepts XHR/fetch requests in React/Vue SPAs), `-kf knownfiles` (all: .env, .git/config, backup).

**Why it works:** SPAs have no `<a href>` — URLs are hidden inside the JS router. With headless Chrome 131, XHR endpoints to internal APIs are captured.
**Why it fails:** headless Chrome 131 is blocked by HoneyPort/Cloudflare Turnstile challenge; depth 5 on a large site = days of crawling network; binary blobs (PDF, video) are not extracted by default → use `-fx=true -X GET,POST`.

---

## 12.8 JS Mining

### 12.8.1 LinkFinder — endpoint extraction

```bash
# LinkFinder (GerbenJavado)
python3 linkfinder.py -i https://target.com/assets/*.js -o cli -d -E
# atau dari file
python3 linkfinder.py -i 'target.com/*.js' -o results.html
```

**What is sent:** downloads JS, regex-matches endpoint patterns (`api/`, `/v[0-9]/`, strings with `/`).
**What appears:** endpoint list including those removed from visible router but still reachable.

### 12.8.2 SecretFinder

```bash
# SecretFinder (fork LinkFinder + secret regex)
python3 SecretFinder.py -i https://target.com/main.js -o results.html
# atau dict mode:
python3 SecretFinder.py -i target.com -e -o results/cli
```

**What appears:**
```
[GOOGLE_API_KEY] AIza... 
[AWS_ACCESS_KEY] AKIA...
[SLACK_TOKEN] xoxb-...
[JIRA] url from JS
```

**Why it works:** JS bundled in frontend is unprotected; minified code often still contains keys that are "already replaced" but old commits are still live on CDN/cache (`httpx -cache-buster` bypass).
**Why it fails:** Webpack/chunk split — runtime chunks containing keys are loaded dynamically; make sure to fetch the whole manifest file via katana crawl. Nuclei and manual grep sometimes needed — SecretFinder regex false positives are high (manual validation required: `aws sts get-caller-identity` for AWS keys, etc.*

### 12.8.3 xnLinkFinder (superior 2026)

```bash
xnLinkFinder -u https://target.com -e http://target.com -d 3 -sf subs_resolved.txt -o t_output/xn_recon -i -wp
# -wp = WordPress route detect, -sf = scope file validation
# dari file list
python3 xnLinkFinder.py -i httpx_out.txt -d 3 -sf scope_file -i
```

**Why xnLinkFinder excels:** (1) supports in-source regex scope, (2) automatically deduplicates routes with parameter normalization, (3) `-sp` spider relation releases large JS and cross-scope (sub-to-sub). Output:
```
Unvalidated: /api/admin/deleteUser (potential BOLA!)
```

**Auto-parse JS:**
```bash
# extract semua JS dari output xnLinkFinder/katana buat SecretFinder:
katana -u https://target.com -d 3 -jc | grep "\.js" | sort -u > js_files.txt
# check live:
httpx -l js_urls.txt -status-code -silent | cut -d " " -f1 | \
  python3 SecretFinder.py -i -  -o results.html
```

---

## 12.9 Nuclei Selection (not brute-forcing all templates)

Don't run `-t all` (25k+ templates in 2026). Use tag selection with target data from httpx:

```bash
# 1. Update
nuclei -update-templates

# 2. Berdasarkan tech detect:
nuclei -l httpx_out.txt -tags grafana,nginx,apache -severity medium,high,critical -o nuc_tech.txt
nuclei -l httpx_out.txt -tech-detect-input ... # not built-in; use manual:
nuclei -l <(httpx.json | jq -r 'select(.tech[0]|test("Grafana")) | .url') -tags grafana

# 3. Berdasarkan service exposed (naabu output):
nuclei -u target -tags network -port 6379,27017,9200  # redis, mongo, elastic

# 4. Exposure dan config:
nuclei -l httpx_out.txt -tags exposure,config,misconfig,takeover,token

# 5. CVE-only critical:
nuclei -l httpx_out.txt -tags cve -severity critical,high -c 50 \
  -rl 80 -timeout 15 -o nuc_cve.txt
```

Rate & stealth:
```bash
nuclei -l targets.txt -c 25 -rl 50 -timeout 10 -retries 1 -random-agent
```

**Why it works:** tier-critical & takeover templates (`cname_takeover`, subdomain takeover in dangling CNAME from dnsx output) prioritize report quality.
**Why it fails:** `-tags all` = 3000+ requests/host = WAF trigger, IP ban, duplicate noise.

### 12.9.1 Takeover check chain (high-yield combo)

```bash
# gabung dnsx CNAME output + httpx status & body-check
cat subs_all.txt | dnsx -cname -resp -silent | nuclei -tags takeover -o tk.txt
```
Dangling CNAME (`herokuapp.com`, `azurewebsites.net`, `zendesk`, `readme.io`, `Surge.sh`, `pantheon`) + origin-404 → potential takeover. Manual validation before reporting: error signature list in the `can-i-takeover-xyz` repo.

---

## 12.10 Chained Command (Full Pipeline One-Liner-ish)

```bash
#!/bin/bash
# encode chain recon v2026
SCOPE="target.com"
RESOLVERS="resolvers.txt"

# Tahap 1: enumerasi
subfinder -d $SCOPE -all -recursive -o subs_1.txt
amass enum -passive -d $SCOPE -o subs_2.txt
github-subdomains -d $SCOPE -t $GITHUB_TOKEN -o subs_3.txt
cat subs_*.txt | sort -u > subs_all.txt

# Tahap 2: resolusi + permutation
puredns resolve subs_all.txt --resolvers $RESOLVERS \
  --wildcard-batch 30 -w subs_resolved.txt
gotator -sub subs_resolved.txt -perm wordlist/permutations.txt \
  -depth 1 -numbers 10 -silent > subs_perm.txt
puredns resolve subs_perm.txt --resolvers $RESOLVERS \
  --wildcard-batch 30 -w subs_perm_resolved.txt
cat subs_resolved.txt subs_perm_resolved.txt | sort -u > subs_final.txt

# Tahap 3: fingerprint + port
dnsx -l subs_final.txt -a -cname -resp -cdn -silent -o dnsx_out.txt
httpx -l subs_final.txt -tech-detect -status-code -title -web-server \
  -follow-redirects -json -o httpx.json
jq -r '.url' httpx.json > live.txt
naabu -l live.txt -top-ports 500 -rate 800 -o naabu.txt

# Tahap 4: URL & JS
katana -l live.txt -d 3 -jc -fx -o urls_katana.txt
echo $SCOPE | waybackurls > urls_wb.txt
gau $SCOPE > urls_gau.txt
cat urls_*.txt | sort -u | uro > urls_final.txt

# Tahap 5: JS mining
cat urls_final.txt | grep "\.js" | sort -u > js_urls.txt
xnLinkFinder -i js_urls.txt -sf subs_final.txt -o xn/
SecretFinder.py -i js_urls.txt -o secrets/html

# Tahap 6: nuclei (selection)
nuclei -l live.txt -tags takeover,exposure,misconfig,cve \
  -severity medium,high,critical -c 50 -rl 80 -o nuclei/
```

---

## 12.11 Operational Pitfalls (Field Failures)

1. **Wildcard DNS false positive** — without puredns' `--wildcard-batch`, `subfinder` + `dnsx` return thousands of "live" hosts that all resolve to one concrete IP. Always test `randomstring123.target.com`.

2. **CDN probing banned** — `httpx` to `*.cloudfront.net` & `*.cloudflare.net` target domains yields 403 generic legal-block page; tech detection wrong ("nginx 1.25" when in fact it's a CDN edge, not origin). Differentiate via `-cdn` flag before triage.

3. **naabu without raw socket = garbage results** — on VPS without CAP_NET_RAW (container, macOS lima terminal), SYN scan timeout errors become "open". Verify new ports via `nc -zv` before considering them attack surface. WSL2 and Windows 11 24H2 specifically block raw sockets in WSL firewall.

4. **GitHub token scope wrong** — github-subdomains needs `repo`/`code:search` scope; classic tokens with wrong scope return 403 that is forwarded without an error log. Use 3-5 rotating tokens; search API limit is 30 req/min, not 30/detail keyword per minute per account.

5. **Web archive rate limit** — `gau` & `waybackurls` on large scopes (100k+ URLs) are rate-limited by CommonCrawl source (unknown delay); retry-with-backoff is not built in; use `--threads 5 --timeout 50` and split by subdomain list.

6. **katana headless Chrome 131 = 300MB RAM per tab** — 5+ tabs with heavyweight SPA trigger OOM on 2GB VPS; limit `-c 10` and use `--headless -time-limit 90` via Docker isolation.

7. **SecretFinder false positive** — API key regex sees any base64 string; `90%` of results on one CPA domain. All finds must be manually validated (try `sts get-caller-identity`, `curl -H "Authorization: Bearer"` etc.) — reports without validation zero/duplicate = bounty reputation rejection.

8. **Nuclei `-tags cve` on hosts with WAF = IP banned** before scan finishes; always follow-up `nuclei` in stage 6 using a different IP, domain throughput throttled (`-rl 50`), and scan during working hours to match legitimate traffic.

9. **Public resolver list decomposes** — resolvers file `trickest/resolvers` Nov month contains 5-15% dead resolvers. Update every 2 weeks, or build a private resolver via unbound on a Droplet (your own resolver with rate-limit disabled).

10. **Probe ports 9200/6379 to target IP on shared hosting** — shared webhost often (fine burial team), scanning admin interface port => report rejection, or masked `block` — check IP reputation (hosting vs dedicated) before naabu scanning.

---

## [reasoning trace]


