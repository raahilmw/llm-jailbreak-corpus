# bb-recon-2

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 17399 | reasoning: 0
- source: deep harvest

# Chapter 12: Bug Bounty Recon Pipeline 2026

## 12.1 Overview Arsitektur Pipeline

A modern recon pipeline consists of 5 stages: subdomain enumeration → DNS resolution → permutation → HTTP/service probing → URL & JS mining → template scanning.

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
The `-all` flag executes all sources (default is only passively-fast sources). Reference version: subfinder v2.6.x (projectdiscovery).

**What is sent:** queries to 30+ passive sources (Censys, crt.sh, FOFA, Chaos, VirusTotal, Shodan, SecurityTrails).
**What appears:** plaintext list of subdomains.
**Why it works:** passive sources don't touch the target infra — zero footprint, not hit by WAF/rate limit.
**Why it fails:** Censys/Shodan free tier API accounts run out of quota per hour; internal-only subdomains (never exposed in CT logs) don't appear.

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
Amass v4.x. Mode `-passive` = no packets to target infra. Adding `-alts` doesn't work in passive mode — permutation only in active mode (`-active`), use gotator instead (see 12.4).

**Difference vs subfinder:** Amass also extracts subdomains from ASNP/others relationships and web page parsing (passively scraping vendor pages), so it often finds assets belonging to vendors/brands that `subfinder` misses.

**Why it fails:** Amass is slow — passive full `target.com` can take 20-40 minutes. Timeout of dead sources (BeетеAPI, etc.) causes hang without progress in some v4.0-4.3 builds.

### 12.2.3 github-subdomains

**Command:**
```bash
github-subdomains -d target.com -t ghp_xxxx -o subs_github.txt
# atau via gau-style token file
```

**What is sent:** GitHub code search API for `-d target.com` and subdomain patterns.
**What appears:** subdomains that appear in code/PR/issues — including **internal subdomains**: `internal-api.target.com`, `staging.target.com`, dev URLs in config files.
**Why it works:** developers leak internal hostnames in repos, gists, and gists removed but still indexed.
**Why it fails:** GitHub API rate limit 30 search requests/minute (authenticated 30/min, unauthenticated 10/min). Use multiple tokens and rotate.

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

**What is sent:** DNS query A/AAAA to public resolvers (list of resolvers ~1000 entries from trickest/resolvers). `--wildcard-batch 30` tests 30 random prefixes (`a1b2c3.target.com`) for wildcard DNS detection.
**What appears:**
- `subs_resolved.txt` — only subdomains that resolve, **free of wildcard false positives**
- `subs_wildcards.txt` — subdomains under wildcard records

**Why it works:** puredns performs two-pass validation (`--dns-validate`): each IP answer is re-verified by another resolver to avoid DNS poisoning/router hijack from dead resolvers.

**Why it fails:** ISP resolver on the operational network performs DNS filtering → false negative. DNS providers (Cloudflare 1.1.1.1, Quad9) rate limit mass resolution (>~2000 req/min) → truncated results. Switch to local resolv.conf of your own DNS server or subscribe to the updated trickest resolver list.

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

**Why it matters:** the `-cdn` flag tells **before** scanning whether an asset is on a CDN — saves nuclei runs and prevents scan blocking/whitelabel errors. CNAME chain disclosure also often leaks third-party assets (SaaS vendors, forgotten stacks).

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

**What is sent:** generate candidates from pattern wordlist (`admin.`, `dev.`, `vpn.`, `-prod`, `-homolog`, `old.`, `uat.`) on each subdomain:
```
api.target.com → api-dev.target.com, api-old.target.com, admin-api.target.com
```

**What appears:** subdomains that don't appear in CT logs — because the cert is wildcard (important part: many companies use `*.target.com` wildcard so CT logs are zero-visible).
**Why it works:** internal naming convention is consistent. If `api-eu.target.com` exists, most likely `api-us.target.com`, `api-asia.target.com` exist.
**Why it fails:** without `--wildcard-batch` in resolution, permutation results on wildcard domains (e.g. `*.cloudfront.net`) produce 100% false positives.

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
| `-follow-redirects` | follow to origin server (reveals `login.target.com` → SaaS) |
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

**Why it works:** concrete software version = triage origination. Grafana 10.x → check CVE-2024-9264 (SQL Expressions), nginx 1.25 without patch → known CVE path.
**Why it fails:** banner masking, `Server:` removed; TLS fingerprint false; some web apps use SPA where title is also blank ("Loading...") — merge from 443 and 80 probing needed.

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
**Why it fails:** needs root/SYN_RAW for full performance; on Windows 11 24H2/WSL2 raw socket privilеge issue — run via Linux VPS. High SYN rate triggers IDS — some providers block inbound ICMP dest-unreachable → false positive open port; always verify:
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

**What appears:** historical URLs including endpoints that are **already deprecated** but still live (`.php` endpoints, `?id=` parameters, `/api/v1/` paths). gau adds CommonCrawl + OTX + URLScan index.

### 12.7.2 katana (crawler aktif)

```bash
katana -u https://target.com -d 5 -jc -kf all -fx \
  -o urls_katana.txt \
  -c 60 -headless  # JS-render untuk SPA (Chrome 131 headless)
```

Important flags: `-jc` JS crawl (follows routes inside bundles), `-fx` fetch-xhr (intercepts XHR/fetch requests in React/Vue SPAs), `-kf knownfiles` (all: .env, .git/config, backup).

**Why it works:** SPAs don't have `<a href>` — URLs are hidden inside the JS router. With Chrome 131 headless, XHR endpoints to internal APIs are captured.
**Why it fails:** headless Chrome 131 is blocked by HoneyPort/Cloudflare Turnstile challenge; depth 5 on large sites = days of crawl network; binary blobs (PDF, video) are not extracted by default → use `-fx=true -X GET,POST`.

---

## 12.8 JS Mining

### 12.8.1 LinkFinder — endpoint extraction

```bash
# LinkFinder (GerbenJavado)
python3 linkfinder.py -i https://target.com/assets/*.js -o cli -d -E
# atau dari file
python3 linkfinder.py -i 'target.com/*.js' -o results.html
```

**What is sent:** download JS, regex-match endpoint pattern (`api/`, `/v[0-9]/`, string with `/`).
**What appears:** endpoint list including those removed from the visible router but still reachable.

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

**Why it works:** JS bundled in the frontend is not protected; minified code often still contains keys that were "already changed" but old commits are still live on the CDN/cache (`httpx -cache-buster` bypass).
**Why it fails:** Webpack/chunk split — the runtime chunk containing the key is loaded dynamically; ensure you fetch the whole file manifest via katana crawl. Nuclei and manual grep are sometimes needed — SecretFinder regex has a high false positive rate (manual validation required: `aws sts get-caller-identity` for AWS key, etc.*

### 12.8.3 xnLinkFinder (superior 2026)

```bash
xnLinkFinder -u https://target.com -e http://target.com -d 3 -sf subs_resolved.txt -o t_output/xn_recon -i -wp
# -wp = WordPress route detect, -sf = scope file validation
# dari file list
python3 xnLinkFinder.py -i httpx_out.txt -d 3 -sf scope_file -i
```

**Why xnLinkFinder is superior:** (1) supports in-source regex scope, (2) automatic route deduplication with param normalization, (3) `-sp` spider relationship releases large JS and cross-scope (sub-to-sub). Output:
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

Do not run `-t all` (25k+ templates 2026). Use tag selection with target data from httpx:

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

**Why it works:** tier-critical & takeover templates (`cname_takeover`, subdomain takeover on dangling CNAME from dnsx output) prioritize report quality.
**Why it fails:** `-tags all` = 3000+ requests/host = WAF trigger, IP ban, duplicate noise.

### 12.9.1 Takeover check chain (high-yield combo)

```bash
# gabung dnsx CNAME output + httpx status & body-check
cat subs_all.txt | dnsx -cname -resp -silent | nuclei -tags takeover -o tk.txt
```
Dangling CNAME (`herokuapp.com`, `azurewebsites.net`, `zendesk`, `readme.io`, `Surge.sh`, `pantheon`) + origin-404 → potential takeover. Manual validation before report: list error signatures in `can-i-takeover-xyz` repo.

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

1. **Wildcard DNS false positive** — without `--wildcard-batch` puredns, `subfinder` + `dnsx` return thousands of "live" hosts that all resolve to a single concrete IP. Always test `randomstring123.target.com`.

2. **CDN probing banned** — `httpx` to `*.cloudfront.net` & `*.cloudflare.net` target domains returns a generic 403 legal-block page; tech detect is wrong ("nginx 1.25" when it is the CDN edge, not origin). Differentiate via `-cdn` flag before triage.

3. **naabu without raw socket = garbage results** — on a VPS without CAP_NET_RAW (container, macOS lima terminal), SYN scan timeout errors become "open". Verify new ports via `nc -zv` before considering them attack surface. WSL2 and Windows 11 24H2 are special: raw socket is blocked by WSL firewall.

4. **Wrong GitHub token scope** — github-subdomains needs `repo`/`code:search` scope; classic token with wrong scope returns 403 which is forwarded without an error log. Use 3-5 rotating tokens; search API limit is 30 req/min, not 30/detail keyword per minute per account.

5. **Web archive rate limit** — `gau` & `waybackurls` on large scope (100k+ URLs) are rate-limited by CommonCrawl source (unknown delay); retry-with-backoff is not built in; use `--threads 5 --timeout 50` and split by subdomain list.

6. **katana headless Chrome 131 = 300MB RAM per tab** — 5+ tabs with weighty SPAs can trigger OOM on a 2GB VPS; limit `-c 10` and use `--headless -time-limit 90` via Docker isolation.

7. **SecretFinder false positive** — API key regex sees any base64 string; `90%` of results on one CPA domain. All finds must be manually validated (try `sts get-caller-identity`, `curl -H "Authorization: Bearer"` etc.) — reporting without validation zero/dupe = bounty reputation rejection.

8. **Nuclei `-tags cve` on host with WAF = IP banned** before scan completes; sales follow-up ` nuclei` at stage 6 uses a different IP, domain throughput throttled (`-rl 50`), and scans during working hours to match legitimate traffic.

9. **Public resolver list decomposes** — `trickest/resolvers` resolver file in Nov contains 5-15% dead resolvers. Update every 2 weeks, or build a private resolver via unbound on a Droplet (one own resolver with rate-limit disabled).

10. **Probe ports 9200/6379 to target IP on shared hosting** — shared Webhost hosts are often \(fine burial team\), scanning admin interface ports => report rejection, but masked `block` — check IP reputation (hosting vs dedicated) before naabu scanning.

---

## [reasoning trace]


