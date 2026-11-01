# bb-recon — bb

# Bug Bounty Recon 2026 — Referensi Teknis

## 1. Peta Pipeline

| Stage | Tool | Input | Output | Artefak kunci |
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

- **Dikirim**: query ke ~40 passive sources (CT logs, VirusTotal, Censys, Shodan, Chaos, bufferover, dll). Bukan resolusi DNS aktif.
- **Muncul**: subdomain + source tag (`-v` untuk lihat sumber). Output dedup otomatis.
- **Kenapa gagal**: provider API tidak diset → hanya CT logs yang jalan (Censys/VT/Chaos lewat). `-all` tanpa API key = ~30% coverage. Domain tidak di CT (private/internal) → kosong.

### 2.2 amass passive (v4.x / OWASP Amass v5 fork)

```bash
amass enum -passive -d example.com -o amass_passive.txt -config ~/.config/amass/config.ini
amass enum -passive -df scopes.txt -o amass_all.txt
```

- **Dikirim**: query ke sumber pasif saja (tidak ada DNS aktif). Beda dengan `-active` yang melakukan zone transfer + bruteforce.
- **Muncul**: subdomain + assoc source. Amass punya federated DB lokal (`~/.config/amass/amass.sqlite`) — pakai `amass db -names -d example.com` untuk dump.
- **Kenapa gagal**: amass v4 sering hang pada source tertentu (Wayback) — set `timeout` per source di config. v5 syntax berbeda (`amass enum -passive` → tetap sama, tapi config path berubah). Tanpa `-timeout`, satu source lambat memblokir seluruh run.

### 2.3 github-subdomains (v1.x)

```bash
export GITHUB_TOKEN=ghp_xxx
github-subdomains -d example.com -t $GITHUB_TOKEN -o gh_subs.txt
github-subdomains -d example.com -t $GITHUB_TOKEN -raw -o gh_raw.txt
```

- **Dikirim**: GitHub Search API query `example.com`. Mencari string domain di kode, commit, issue, PR.
- **Muncul**: subdomain yang muncul di teks repo publik + URL repo.
- **Kenapa gagal**: rate limit 30 req/menit unauthenticated, 5000/jam token user. Tanpa token → habis di 1 query. Term "example.com" kena code search restriction (GitHub code search harus authenticated + repo indexed). Repo private tidak tercover.

### 2.4 Agregasi

```bash
cat subs_subfinder.txt amass_passive.txt gh_subs.txt | sort -u > subs.txt
```

---

## 3. Resolusi & Validasi

### 3.1 puredns (v2.1.x)

```bash
# resolvers: puredns butuh massdns; pakai resolvers publik
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
puredns resolve subs.txt -r resolvers.txt -w resolved.txt --rate-limit 5000
# wildcard filtering sebelum bruteforce
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w brute_out.txt --wildcard-tests 10
```

- **Dikirim**: DNS A/AAAA query ke resolver list, dengan burst via massdns.
- **Muncul**: subdomain yang resolve. `--wildcard-tests` mendeteksi wildcard `*.example.com` dengan 10 query random.
- **Kenapa gagal**: wildcard tidak di-filter → `subs.txt` penuh false positive (mis. `anything.example.com` resolve ke IP parked). `--rate-limit` terlalu tinggi → resolver publik memblokir → resolusi drop (false negative). Resolver list mati/outdated → 0 hasil.

### 3.2 dnsx (v1.2.x)

```bash
dnsx -l subs.txt -a -resp -silent -o dnsx_a.txt
dnsx -l resolved.txt -cname -resp -silent -o cname.txt    # dangling CNAME hunting
dnsx -l subs.txt -a -resp-only -json -o dnsx.json
```

- **Dikirim**: A/AAAA/CNAME/TXT query langsung (tanpa massdns, Go resolver).
- **Muncul**: record + nilai. `-cname` untuk subdomain takeover (S3, GitHub Pages,Heroku, Azure — cek dengan nuclei `takeovers/`).
- **Kenapa gagal**: dnsx pakai system resolver default → kena rate limit ISP/router. Set `-r resolvers.txt` eksplisit. `-resp-only` menyembunyikan domain — jangan dipakai untuk JSON pipeline.

---

## 4. Permutation

### 4.1 gotator (v1.x)

```bash
gotator -sub subs.txt -perm wordlist-perm.txt -depth 2 -numbers 3 -md -silent > perm.txt
gotator -sub resolved.txt -perm /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt -depth 1 -mindup -md -silent > perm.txt
```

- **Dikirim**: kombinasi `existing-sub + delimiter + word` (mis. `dev` → `dev-api`, `api-dev`, `dev1`, `dev2`).
- **Muncul**: kandidat subdomain baru (belum diresolve).
- **Kenapa gagal**: `-depth 2` + wordlist besar → jutaan kandidat, resolusi butuh jam. Tanpa `-md` (mindup/dedup) → duplikat membengkakkan. Pakai `-numbers 3` untuk enumerasi `app1..app999`.

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

- **Dikirim**: HTTP GET (default) ke 80/443 + HTTPS fallback, header User-Agent `httpx/1.6`.
- **Muncul**: status, title, tech (via Wappalyzer signatures lokal), server (`nginx 1.25`, `Apache 2.4.62`), CDN (Cloudflare/Akamai), CNAME.
- **Kenapa gagal**:
  - WAF CDN (Cloudflare 2024+) mengembalikan 403 dengan halaman challenge → status 403 massal, tech detect hanya "Cloudflare".
  - User-Agent default httpx sering di-block (403); set `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"`.
  - `-cdn` filter: `-fcdn cloudflare` untuk skip CF, tapi ini juga membuang target yang legitimate di CF.
  - TLS SNI mismatch pada IP langsung → httpx gagal; pakai `-sni` atau `-host`.

---

## 6. Port Scan

### 6.1 naabu (v2.3.x)

```bash
naabu -l resolved.txt -top-ports 1000 -rate 5000 -silent -o naabu_top.txt
naabu -l resolved.txt -p - -rate 3000 -silent -o naabu_full.txt   # full 65535
naabu -host target.com -p 21,22,80,443,3306,5432,6379,8080,8443,9200,27017 -silent -o naabu_services.txt
```

- **Dikirim**: TCP SYN (default, butuh root) atau CONNECT scan. Rate global per detik.
- **Muncul**: `host:port`. `-json` untuk detail.
- **Kenapa gagal**: tanpa root → fallback ke CONNECT (lambat, kena WAF). `-rate 5000` di ISP shared → SYN flood detection, packet loss, false negative. Scan dari cloud VPS (DigitalOcean/AWS) → IP egress sering di-blacklist target; scan dari residential lebih akurat. Port filtered firewall stateful → naabu tidak selalu membedakan `closed` vs `filtered`.

---

## 7. URL Collection

### 7.1 waybackurls (v0.2.x)

```bash
cat subs.txt | waybackurls | tee wb_raw.txt | sort -u > wb.txt
cat wb.txt | grep -Ev '\.(png|jpg|jpeg|gif|css|woff|woff2|svg|ico)$' | sort -u > wb_clean.txt
```

- **Dikirim**: query ke `web.archive.org/cdx/search/cdx?url=*.example.com/*&output=txt&collapse=urlkey`.
- **Muncul**: URL historis (termasuk param, endpoint mati).
- **Kenapa gagal**: Wayback rate limit (bisa 429) — bulk 1000 subdomain kena block. `collapse=urlkey` meng-unik, tanpa itu output melimpah. Wayback hanya punya snapshot yang pernah di-crawl — endpoint baru (<6 bulan) tidak ada.

### 7.2 gau (v2.2.x)

```bash
cat subs.txt | gau --threads 5 --subs --providers wayback,commoncrawl,otx,urlscan --o gau.txt
gau --providers wayback --blacklist png,jpg,gif,css,woff,svg,ico --fc 404,403 --o gau_clean.txt
```

- **Dikirim**: query multi-provider (Wayback, CommonCrawl 2024 index, OTX AlienVault, URLScan).
- **Muncul**: URL + source. `--providers` selektif untuk kontrol rate.
- **Kenapa gagal**: `--subs` tanpa `*.` handling → subdomain `a.b.example.com` kadang di-query sebagai `subs.a.b.example.com`. CommonCrawl index butuh download WARC besar (lambat). Rate limit per provider.

### 7.3 katana (v1.1.x)

```bash
# crawler aktif
katana -list live.txt -d 3 -jc -kf all -silent -o katana.txt
# headless (butuh chrome)
katana -list live.txt -d 3 -headless -jsl -noi -silent -o katana_headless.txt
# form & endpoint parsing
katana -list live.txt -d 2 -aff -fx -silent -o katana_form.txt
```

- **Dikirim**: HTTP request aktif + parsing JS (dengan `-jsl`), form fill (`-aff`), XHR (`-fx`).
- **Muncul**: endpoint live + `method`, `form`, path JS.
- **Kenapa gagal**: tanpa `-headless` → SPA (React Router, Angular, Vue 3) tidak ter-crawl karena JS-driven. `-headless` butuh Chrome 131+ / `KATANA_HEADLESS_BROWSER=/path/chrome`. Scope leak: `-fs rdn` (fqdn/rdn) wajib untuk batasi ke registrable domain. Depth >3 → waktu eksplosif.

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

- **Dikirim**: fetch JS + regex `js-beautify`-style extraction untuk path & endpoint.
- **Muncul**: `/api/v1/users`, `/graphql`, `/internal/admin`.
- **Kenapa gagal**: bundle Webpack/Vite minified dengan base64 string / template literal (`${a}${b}`) → regex miss. Source map `.js.map` biasanya langsung memberi source asli — cek `curl -s $js_url | grep sourceMappingURL`. LinkFinder Python tidak handle `import()` dynamic dengan variabel.

### 8.2 SecretFinder (v1.x)

```bash
python3 SecretFinder.py -i https://example.com/app.js -o cli
cat urls_js.txt | while read u; do python3 SecretFinder.py -i "$u" -o cli -e; done | tee secrets_raw.txt
```

- **Dikirim**: regex set (AWS AKIA, Google API `AIza`, Stripe `sk_live`, JWT, private keys, Slack `xox[baprs]`, GitHub `ghp_`, Twilio, SendGrid).
- **Muncul**: match + entropy score.
- **Kenapa gagal**: minifier memecah token (`AKIA` + concat runtime) → regex miss. Modern bundler menyimpan secret di runtime config (`window.__ENV__`) yang di-fetch terpisah — perlu headless untuk intercept. Entropy-based false positive tinggi; validasi token dengan tool vendor (mis. `TruffleHog verify`).

### 8.3 xnLinkFinder (v1.x, Golang)

```bash
xnLinkFinder -i https://example.com -d 3 -sp https://example.com -o xnOut.txt
xnLinkFinder -i urls_js.txt -sf subdomains.txt -d 2 -o xn_links.txt -v
# secret + endpoint bersamaan
xnLinkFinder -i https://example.com -d 3 -o xn.txt -sf subs.txt -s
```

- **Dikirim**: crawl + JS parse (regex lebih agresif dari LinkFinder, handle `import()`, `fetch`, `axios`, base64 decode opsional).
- **Muncul**: link + parameter + secret.
- **Kenapa gagal**: `-sp` (scope) harus di-set, jika tidak akan crawl keluar domain. Flag `-d 3` + `-s` (secret) memperlambat signifikan; batasi `-d 2` untuk batch.

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
| Exposures | `exposure`, `config`, `backup` | sedang | 1 |
| CVE | `cve` + `-severity high,critical` | tinggi | 2 |
| Default login | `default-login` | sedang | 2 |
| Fuzzing | `fuzz` | tinggi + kena WAF | 3 |
| Tech recon | `tech` | rendah | 3 |

- **Dikirim**: request template YAML per matcher. Matcher berbasis regex/status/word/dsl.
- **Muncul**: match + matcher-name + extracted.
- **Kenapa gagal**:
  - `-tags cve` tanpa update template → CVE 2025/2026 tidak ada.
  - Rate limit default (`-rl 150`) kena WAF 429; set `-rl 50 -c 25` untuk target sensitif.
  - Template `fuzz` menghasilkan ribuan false positive jika target mengembalikan 200 untuk semua path — wajib `-fs` filter atau custom matcher.
  - Interactsh (`-interactsh-server`) butuh outbound DNS/HTTP — blocked di banyak network → OOB detection mati.

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

### 10.4 Diff antar run (monitoring)

```bash
# run harian
comm -13 <(sort resolved_$(date -d yesterday +%F).txt) <(sort resolved_$(date +%F).txt) > new_subs.txt
comm -23 <(sort resolved_$(date -d yesterday +%F).txt) <(sort resolved_$(date +%F).txt) > gone_subs.txt
```

---

## 11. Jebakan Operasional di Lapangan

| Jebakan | Gejala | Mitigasi |
|---|---|---|
| **Wildcard DNS** | Semua `subs*.example.com` resolve → false positive massal, JHaddix wordlist sia-sia | `puredns --wildcard-tests 10`; verifikasi dengan 3 random query |
| **Resolver publik mati/rate-limit** | Resolusi drop, `resolved.txt` tipis | Rotasi `resolvers.txt` (trickest), `--rate-limit 3000`, fallback `dnsx -r` |
| **Source API tidak dikonfigurasi** | subfinder/amass coverage ~30% | Set `provider-config.yaml` (Shodan, Censys, Virustotal, SecurityTrails, Chaos), amass `config.ini` |
| **VPN/Cloud egress di-blacklist** | httpx 403 massal, naabu port filtered semua | Scan dari residential/VPS region lain; `-H` UA Chrome 131; `-tls-grab` untuk verifikasi TLS |
| **Cloudflare 403 challenge** | httpx status 403, tech=Cloudflare, kehilangan title | `-fcdn cloudflare` untuk skip, atau `-favicon` + analisa origin leak via dnsx CNAME |
| **WAF memblokir nuclei** | 429 beruntun, scan 5 menit → 30 request | `-rl 30 -c 10`, `-H` UA realistis, `-retries 2`, jeda `-ni` untuk interactsh |
| **Interactsh tidak reachable** | OOB detection (SSRF, blind CVE) diam | `-iserver` custom / VPS; verifikasi `curl https://oast.fun` dari host scanner |
| **SPA tidak ter-crawl** | katana hanya dapat root + static | `-headless` + Chrome 131 binary, `-nos` untuk skip non-headless |
| **Minified JS miss endpoint** | LinkFinder output kosong/palsu | Cek `.js.map` (`sourceMappingURL`), parse `import()` via xnLinkFinder, atau headless + DevTools protocol |
| **SecretFinder false positive** | Ribuan "key" dari string entropy tinggi | Validasi per-vendor (AWS STS, Google API key checker, TruffleHog `--only-verified`) |
| **Nuclei template basi** | CVE 2025/2026 miss | `nuclei -update-templates` sebelum run; pin template version per engagement |
| **Scope drift** | Scan ke domain di luar in-scope → out-of-bounds bounty | Simpan `scopes.txt`; katana `-fs rdn`, gau `--subs` dengan filter `*.example.com`; review diff |
| **Rate-limit Wayback** | waybackurls/gau 429 atau output kosong sebagian | Split input per 50 subs, `sleep 2`, pakai gau `--providers wayback` saja |
| **Permutation eksplosif** | gotator `-depth 2` × wordlist 10k = 1M kandidat | `-depth 1`, `-md`, puredns `--rate-limit 5000`, batch 250k per iterasi |
| **Timeout pipeline** | httpx `-timeout 10` tapi target lambat (Nginx 1.25 dengan backend slow) | `-timeout 15 -retries 2`, `-http2` untuk server modern |
| **DNS rebinding / sinkhole** | Resolve ke IP internal (10.x, 172.16.x) → httpx hang | Filter private IP pasca-resolve: `grep -vE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'` |
| **Amass v4 vs v5 config** | Command jalan tapi 0 output | Cek `amass -version`; v5 pakai `amass enum -passive -d` + `$AMASS_CONFIG`; migrasi `config.ini` |
| **Naabu tanpa root** | Scan lambat, kena WAF, false negative | `setcap cap_net_raw,cap_net_admin=eip /usr/bin/naabu` atau jalan sebagai root (VPS) |
| **Output tidak reproducibility** | Diff antar run tidak valid | Set `TZ=UTC`, gunakan timestamp file konsisten, `sort -u` sebelum save, simpan `versions.txt` (subfinder -version, httpx -version, dll) |

---

## [reasoning trace]


