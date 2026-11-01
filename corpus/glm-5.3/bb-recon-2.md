# bb-recon-2

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 17399 | reasoning: 0
- source: deep harvest

# Bab 12: Bug Bounty Recon Pipeline 2026

## 12.1 Overview Arsitektur Pipeline

Pipeline recon modern terdiri dari 5 tahap: enumerasi subdomain → resolusi DNS → permutation → probing HTTP/service → URL & JS mining → template scanning.

```
Assets → subfinder/amass → puredns resolve → dnsx/gotator → httpx → naabu
                                                              ↓
                                        waybackurls/gau/katana → LinkFinder/SecretFinder/xnLinkFinder → nuclei
```

---

## 12.2 Subdomain Enumeration

### 12.2.1 subfinder

**Perintah:**
```bash
subfinder -d target.com -all -recursive -o subs_subfinder.txt -t 100 \
  -sCT  # simpan certificate transparency raw
```
Flag `-all` mengeksekutasi semua source (default hanya source passively-fast). Versi rujukan: subfinder v2.6.x (projectdiscovery).

**Apa yang dikirim:** query ke 30+ passive source (Censys, crt.sh, FOFA, Chaos, VirusTotal, Shodan, SecurityTrails).
**Apa yang muncul:** plaintext list subdomain.
**Kenapa berhasil:** passive source tidak menyentuh infra target — zero footprint, tidak kena WAF/rate limit.
**Kenapa gagal:** akun API free tier Censys/Shodan habis quota per jam; internal-only subdomain (tidak pernah terekspos CT log) tidak muncul.

Setup API keys di `$HOME/.config/subfinder/provider-config.yaml`:

```yaml
censys: ["<api-id>:<secret>"]
shodan: ["<api-key>"]
virustotal: ["<api-key>"]
github: ["<token>"]
chaos: ["<projectdiscovery-api-key>"]
```

### 12.2.2 Amass (passive mode)

**Perintah:**
```bash
amass enum -passive -d target.com -o subs_amass.txt \
  -config ~/.config/amass/config.ini
```
Amass v4.x. Mode `-passive` = tanpa packet ke infra target. Tambah `-alts` tidak berhasil di passive mode — permutation hanya di active mode (`-active`), gunakan gotator sebagai gantinya (lihat 12.4).

**Perbedaan vs subfinder:** Amass mengekstrak subdomain juga dari ASNP/others relationship dan parsing halaman web (passively scraping vendor pages), sehingga sering menemukan asset milik vendor/brand yang `subfinder` lewatkan.

**Kenapa gagal:** Amass lambat — passive full `target.com` bisa 20-40 menit. Timeout source yang mati (BeетеAPI, dll.) menyebabkan hang tanpa progress di beberapa build v4.0-4.3.

### 12.2.3 github-subdomains

**Perintah:**
```bash
github-subdomains -d target.com -t ghp_xxxx -o subs_github.txt
# atau via gau-style token file
```

**Apa yang dikirim:** GitHub code search API untuk `-d target.com` dan pattern subdomain.
**Apa yang muncul:** subdomain yang muncul di code/PR/issues — termasuk **internal subdomain**: `internal-api.target.com`, `staging.target.com`, dev URL di config file.
**Kenapa berhasil:** developer bocorkan internal hostname di repo, gists, dan gists removed tapi masih ter-index.
**Kenapa gagal:** GitHub API rate limit 30 search request/menit (authenticated 30/menit, unauthenticated 10/menit). Gunakan beberapa token dan rotasi.

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

**Yang dikirim:** DNS query A/AAAA ke resolver publik (list resolvers ~1000 entries dari trickest/resolvers). `--wildcard-batch 30` menguji 30 random prefix (`a1b2c3.target.com`) untuk deteksi wildcard DNS.
**Yang muncul:**
- `subs_resolved.txt` — hanya subdomain yang resolve, **bebas wildcard false positive**
- `subs_wildcards.txt` — subdomain di bawah wildcard-record

**Kenapa berhasil:** puredns melakukan two-pass validation (`--dns-validate`): setiap IP answer diverifikasi ulang oleh resolver lain untuk menghindari DNS poisoning/router hijack dari resolver mati.

**Kenapa gagal:** ISP resolver di jaringan operasional melakukan DNS filtering → false negative. Provider DNS (Cloudflare 1.1.1.1, Quad9) rate limit resolusi massal (>~2000 req/mnt) → hasil terpotong. Ganti ke resolv.conf lokal DNS server sendiri atau subscribe list resolver trickest yang di-update.

### 12.3.2 dnsx

**Perintah:**
```bash
dnsx -l subs_resolved.txt -a -aaaa -cname -resp -silent -o dnsx_out.txt \
  -cdn  # deteksi CDN (bug bounty reject WAF/CDN assets sering)
cat subs_resolved.txt | dnsx -a -resp -recon  # screenshot-style fingerprint
```

**Yang muncul:**
```
api.target.com [1.2.3.4] [CNAME: api-eu-west-1.elb.amazonaws.com] [AWS]
static.target.com [... CNAME: d3xyz.cloudfront.net] [CDN: CloudFront]
```

**Kenapa penting:** `-cdn` flag memberi tahu **sebelum** scanning apakah asset di CDN — menghemat nuclei run dan mencegah scan blocking/whitelabel error. CNAME chain disclosure juga sering bocorkan asset pihak ketiga (vendor SaaS, forgotten stack).

Fingerprint berbasis teks:
```bash
dnsx -l subs_resolved.txt -a -resp -fc <(internetdb response, use ipinfo)
```

---

## 12.4 Permutation — gotator

**Perintah:**
```bash
gotator -sub subs_resolved.txt -perm permutations_list.txt -depth 1 \
  -numbers 10 -mindup -adv -md -silent > subs_permutations.txt

puredns resolve subs_permutations.txt --resolvers resolvers.txt \
  --wildcard-batch 30 -w subs_perm_resolved.txt
```

**Apa yang dikirim:** generate kandidat dari wordlist pattern (`admin.`, `dev.`, `vpn.`, `-prod`, `-homolog`, `old.`, `uat.`) di-setiap subdomain:
```
api.target.com → api-dev.target.com, api-old.target.com, admin-api.target.com
```

**Apa yang muncul:** subdomain yang tidak muncul di CT log — karena cert-nya wildcard (bagian penting: banyak perusahaan pakai `*.target.com` wildcard sehingga CT log zero-visible).
**Kenapa berhasil:** internal naming convention konsisten. Jika `api-eu.target.com` ada, kemungkinan besar `api-us.target.com`, `api-asia.target.com` ada.
**Kenapa gagal:** tanpa `--wildcard-batch` di resolusi, hasil permutation di wildcard domain (misalnya `*.cloudfront.net`) menghasilkan 100% false positive.

---

## 12.5 HTTPXTech Detect

**Perintah:**
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

Flag inti untuk recon:
| Flag | Fungsi |
|------|--------|
| `-tech-detect` | fingerprint via Wappalyzer core (nginx 1.25, Apache 2.4.62, WordPress 6.x, React, Next.js) |
| `-title` | HTML `<title>` |
| `-status-code` | HTTP status |
| `-follow-redirects` | follow ke origin server (mengungkap `login.target.com` → SaaS) |
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

**Kenapa berhasil:** versi software konkret = triage origination. Grafana 10.x → cek CVE-2024-9264 (SQL Expressions), nginx 1.25 tanpa patch → cve known path.
**Kenapa gagal:** banner masking, `Server:` dihapus; TLS fingerprint false; beberapa web app pakai SPA di mana title sama blank ("Loading...") — merge dari 443 dan 80 probing needed.

---

## 12.6 Port Scanning — naabu

**Perintah:**
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
**Kenapa gagal:** perlu root/SYN_RAW untuk full performance; di Windows 11 24H2/WSL2 raw socket privilеge issue — run via VPS Linux. SYN rate tinggi trier IDS — some providers block inbound ICMP dest-unreachable → false positive open port; always verify:
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

**Apa yang muncul:** URL historis termasuk endpoint yang **sudah deprecated** tapi masih live (endpoint `.php`, parameter `?id=`, path `/api/v1/`). gau tambahkan CommonCrawl + OTX + URLScan index.

### 12.7.2 katana (crawler aktif)

```bash
katana -u https://target.com -d 5 -jc -kf all -fx \
  -o urls_katana.txt \
  -c 60 -headless  # JS-render untuk SPA (Chrome 131 headless)
```

Flag penting: `-jc` JS crawl (mengikuti route di dalam bundle), `-fx` fetch-xhr (intercept XHR/fetch requests di SPA React/Vue), `-kf knownfiles` (all: .env, .git/config, backup).

**Kenapa berhasil:** SPA tidak punya `<a href>` — URL tersembunyi di dalam router JS. Dengan Chrome 131 headless, XHR endpoint ke API internal tertangkap.
**Kenapa gagal:** headless Chrome 131 diblok HoneyPort/Cloudflare Turnstile challenge; depth 5 di site besar = jaringan crawl hari; binary blob (PDF, video) tidak di-extract default → gunakan `-fx=true -X GET,POST`.

---

## 12.8 JS Mining

### 12.8.1 LinkFinder — endpoint extraction

```bash
# LinkFinder (GerbenJavado)
python3 linkfinder.py -i https://target.com/assets/*.js -o cli -d -E
# atau dari file
python3 linkfinder.py -i 'target.com/*.js' -o results.html
```

**Apa yang dikirim:** download JS, regex-match pattern endpoint (`api/`, `/v[0-9]/`, string dengan `/`).
**Apa yang muncul:** list endpoint termasuk yang di-remove dari router visible tapi masih reachable.

### 12.8.2 SecretFinder

```bash
# SecretFinder (fork LinkFinder + secret regex)
python3 SecretFinder.py -i https://target.com/main.js -o results.html
# atau dict mode:
python3 SecretFinder.py -i target.com -e -o results/cli
```

**Apa yang muncul:**
```
[GOOGLE_API_KEY] AIza... 
[AWS_ACCESS_KEY] AKIA...
[SLACK_TOKEN] xoxb-...
[JIRA] url from JS
```

**Kenapa berhasil:** JS di-bundle di frontend tidak diproteksi; minified code sering masih memuat key yang "sudah diganti" tapi commit lama masih live di CDN/cache (`httpx -cache-buster` bypass).
**Kenapa gagal:** Webpack/chunk split — runtime chunk yang berisi key di-load dinamis; pastikan ambil whole file manifest via katana crawl. Nuclei dan grep manual kadang needed — regex SecretFinder false positive tinggi (validasi manual wajib: `aws sts get-caller-identity` untuk AWS key, dsb.*

### 12.8.3 xnLinkFinder (superior 2026)

```bash
xnLinkFinder -u https://target.com -e http://target.com -d 3 -sf subs_resolved.txt -o t_output/xn_recon -i -wp
# -wp = WordPress route detect, -sf = scope file validation
# dari file list
python3 xnLinkFinder.py -i httpx_out.txt -d 3 -sf scope_file -i
```

**Kenapa xnLinkFinder unggul:** (1) support in-source regex scope, (2) deduplicate route automatic dengan normalisasi param, (3) `-sp` spider relationship release large JS dan cross-scope (sub-to-sub). Output:
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

## 12.9 Nuclei Selection (bukan brute-force semua template)

Jangan jalankan `-t all` (25k+ template 2026). Gunakan tag selection dengan target data dari httpx:

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

**Kenapa berhasil:** template tier-critical & takeover (`cname_takeover`, subdomain takeover di CNAME dangling dari dnsx output) prioritas report quality.
**Kenapa gagal:** `-tags all` = 3000+ request/host = WAF trigger, IP ban, duplikat noise.

### 12.9.1 Takeover check chain (high-yield combo)

```bash
# gabung dnsx CNAME output + httpx status & body-check
cat subs_all.txt | dnsx -cname -resp -silent | nuclei -tags takeover -o tk.txt
```
Dangling CNAME (`herokuapp.com`, `azurewebsites.net`, `zendesk`, `readme.io`, `Surge.sh`, `pantheon`) + origin-404 → potential takeover. Validasi manual sebelum report: daftar error signature di `can-i-takeover-xyz` repo.

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

## 12.11 Jebakan Operasional (Field Failures)

1. **Wildcard DNS false positive** — tanpa `--wildcard-batch` puredns, `subfinder` + `dnsx` mengembalikan ribuan "live" host yang semuanya resolve ke satu IP kongkret. Selalu test `randomstring123.target.com`.

2. **CDN probing banned** — `httpx` ke `*.cloudfront.net` & `*.cloudflare.net` domain target menghasilkan 403 generic legal-block page; tech detect salah ("nginx 1.25" padahal itu edge CDN, bukan origin). Bedakan via `-cdn` flag sebelum triage.

3. **naabu tanpa raw socket = hasil sampah** — di VPS tanpa CAP_NET_RAW (container, macOS lima terminal), SYN scan timeout error jadi "open". Verifikasi port baru via `nc -zv` sebelum dianggap attack surface. WSL2 dan Windows 11 24H2 istimewa raw socket di-block WSL firewall.

4. **GitHub token scope salah** — github-subdomains butuh `repo`/`code:search` scope; token klasik dengan scope wrong return 403 yang diteruskan tanpa error log. Gunakan 3-5 token rotasi; search API limit 30 req/min, bukan 30/detail keyword permenit per-account.

5. **Rate limit web archive** — `gau` & `waybackurls` pada scope besar (100k+ URL) rate-limited oleh CommonCrawl source (delay unknown); retry-with-backoff tidak dibangun; gunakan `--threads 5 --timeout 50` dan split by subdomain list.

6. **katana headless Chrome 131 = 300MB RAM per tab** — 5+ tab dengan SPA weighty touchantara OOM di VPS 2GB; limit `-c 10` dan gunakan `--headless -time-limit 90` via Docker isolation.

7. **SecretFinder false positive** — API key regex lihat base64-string apa pun; `90%` hasil di domain satu CPA. Semua find wajib divalidasi manual (coba `sts get-caller-identity`, `curl -H "Authorization: Bearer"` dsb) — report tanpa validasi nol/dupe = reputasi bounty rejection.

8. **Nuclei `-tags cve` di host with WAF = IP banned** sebelum scan selesai; sales follow-up ` nuclei` di stage 6 menggunakan IP berbeda, domain throughput throttled (`-rl 50`), dan scan di working hours to match legitimate traffic.

9. **Resolver list public decompose** — file resolvers `trickest/resolvers` Nov month contains dead resolvers 5-15%. Perbarui tiap 2 minggu, atau build private resolver via unbound di Droplet (satu resolver sendiri dengan rate-limit disabled).

10. **Probe port 9200/6379 ke IP target di shared hosting** — host shared Webhost sering \(fine burial team\), scan port admin interface => report rejection, ma masked `block` — check IP-reputation (hosting vs dedicated) before naabu scanning.

---

## [reasoning trace]


