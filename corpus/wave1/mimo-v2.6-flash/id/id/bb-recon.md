# mimo-v2.6-flash — bb-recon

```bash
#!/usr/bin/env bash
# recon-pipeline.sh — full-scope bounty recon, 2026 toolchain
set -euo pipefail

DOMAIN="target.com"
OUT="recon/${DOMAIN}"
mkdir -p "${OUT}"/{subs,dns,http,ports,urls,js,nuclei}
export DOMAIN OUT
```

## 1. Subdomain enumeration (parallel, all sources in one fan-out)

```bash
(
  subfinder -d "$DOMAIN" -all -silent -rc -nc \
    -o "${OUT}/subs/subfinder.txt" &

  amass enum -passive -d "$DOMAIN" -silent \
    -o "${OUT}/subs/amass.txt" &

  assetfinder --subs-only "$DOMAIN" \
    | grep -F ".$DOMAIN" > "${OUT}/subs/assetfinder.txt" &

  github-subdomains -d "$DOMAIN" -t tokens/github.txt -o "${OUT}/subs/github.txt" &

  wait
)
```

Merge + dedupe + strip wildcards:

```bash
cat "${OUT}/subs/"*.txt \
  | sed "s/*\.//g; s/^[[:space:]]*//; s/[[:space:]]*$//; s/\.${DOMAIN}$//" \
  | sort -u | grep -F ".${DOMAIN}$" \
  > "${OUT}/subs/all.txt"

wc -l "${OUT}/subs/all.txt"
```

Optional passive additions:

```bash
findomain -t "$DOMAIN" -w -q >> "${OUT}/subs/all.txt"
chaos -d "$DOMAIN" -silent >> "${OUT}/subs/all.txt"
curl -s "https://crt.sh/?q=%.%${DOMAIN}&output=json" \
  | jq -r '.[].name_value' | sort -u >> "${OUT}/subs/all.txt"
```

## 2. Permutation + DNS resolution

```bash
# gotator: bruteforce + alterations in one pass, resolves inline
gotator -sub "${OUT}/subs/all.txt" \
  -perm wordlists/permutations.txt \
  -depth 2 -res -threads 64 \
  -o "${OUT}/subs/permutations.txt"

# or: puredns (bruteforce + wildcard handling)
puredns resolve "${OUT}/subs/all.txt" \
  --resolvers wordlists/resolvers.txt \
  --enable-domainscan --wildcard-tests \
  -w "${OUT}/subs/valid.txt" -q

# dnsx enrichment: A/AAAA/CAA/MX/NS/TXT/SPF + CDN detect + HTTP screenshot flag
dnsx -l "${OUT}/subs/valid.txt" \
  -a -aaaa -caa -mx -ns -txt -ptr -soa -resp -cdn \
  -json -o "${OUT}/dns/dnsx.json"

dnsx -l "${OUT}/subs/valid.txt" -silent -apr \
  | awk '{print $2}' | sort -u > "${OUT}/dns/ips.txt"
```

## 3. Port scanning (naabu → httpx input)

```bash
# top 1000 against live DNS only
naabu -l "${OUT}/subs/valid.txt" \
  -top-ports 1000 -silent -c 200 -rate 3000 \
  -verify -banner -json -o "${OUT}/ports/naabu-top.json"

# full 65535 on anything not behind CDN, per-host budgeted
cat "${OUT}/subs/valid.txt" | naabu -p - -c 500 -rate 5000 \
  -silent -o "${OUT}/ports/naabu-full.txt"

# merged host:port list for HTTP probing
cat "${OUT}/ports/naabu-"*.txt | sort -u > "${OUT}/ports/all.txt"
```

## 4. HTTP probing + tech detection + fingerprinting

```bash
httpx -l "${OUT}/subs/valid.txt" \
  -silent -status-code -title -tech-detect -content-length -follow-redirects \
  -server -web-server -content-type -location -method -ip -cname -hash sha256 \
  -cdn -probe -threads 50 -retries 1 -timeout 10 \
  -json -o "${OUT}/http/subs.json"

# probe open ports (grab unusual services: alt-http, alt-https)
httpx -l "${OUT}/ports/all.txt" \
  -silent -json -title -tech-detect -status-code -ip -web-server \
  -t 150 -timeout 8 -o "${OUT}/http/ports.json"

# screenshots at scale
httpx -l "${OUT}/http/subs.json" -sd -sud 300x300 -threads 10 -o "${OUT}/http/shots.txt"

# chromepassive-style enrichment
cat "${OUT}/http/subs.json" \
  | jq -r '.url' | httpx -silent -wc -ct -ld -l \
    -ts -td -asn -cname -asn -tr -sx 2>/dev/null > "${OUT}/http/enriched.txt"
```

Extract high-value hosts (admin/dev/staging/api/dr-panel class):

```bash
jq -r '.url' "${OUT}/http/subs.json" \
  | grep -Ei 'admin|dev|stg|stage|test|api|grafana|jenkins|jira|graf|mail|vpn|panel|internal|dashboard|console|argo|kube|git|ci' \
  | sort -u > "${OUT}/http/priority.txt"
```

## 5. URL collection

```bash
cat "${OUT}/subs/all.txt" \
  | gau --threads 10 --blacklist png,jpg,gif,svg,woff,woff2,ttf \
  | grep -v -E '\.(png|jpg|jpeg|gif|svg|css|woff2?|ttf|eot)(\?|$)' \
  > "${OUT}/urls/gau.txt" &

cat "${OUT}/subs/all.txt" \
  | waybackurls > "${OUT}/urls/wayback.txt" &

katana -d "$DOMAIN" -d 5 -jc -kf -ef png,jpg,gif,svg,woff,css,mp4 \
  -jc -known-assets -rate-limit 50 -o "${OUT}/urls/katana.txt" &

cat "${OUT}/subs/all.txt" \
  | hakrawler -depth 5 -subs -insecure -o "${OUT}/urls/hakrawler.txt" &

wait
```

Merge, clean, extract unique endpoints:

```bash
cat "${OUT}/urls/"*.txt \
  | grep -Ei "^(https?:)?//[^ ]*${DOMAIN}" \
  | sed 's/^\/\//https:\/\//' \
  | sort -u > "${OUT}/urls/all.txt"

jq -r '.url? // empty' "${OUT}/http/subs.json" >> "${OUT}/urls/all.txt"

# parameter-focused slice for further testing
grep -E '\?[^=]+=' "${OUT}/urls/all.txt" | sort -u > "${OUT}/urls/with-params.txt"
```

Re-probe collected URLs (they include dead/404 links):

```bash
httpx -l "${OUT}/urls/all.txt" -silent -mc 200,201,204,301,302,307,308,401,403,405,500 \
  -mr 'flag|login|dashboard|panel|dashboard' -title -td \
  -threads 100 -o "${OUT}/http/urls-live.txt"
```

## 6. JS mining — extraction → LinkFinder → SecretFinder

```bash
# harvest JS URLs
cat "${OUT}/urls/all.txt" \
  | grep -Ei '\.js($|\?| )|\.mjs($|\?| )' \
  | sort -u > "${OUT}/js/jsurls.txt"

# also pull inline/linked JS from live pages via katana
katana -list "${OUT}/http/subs.txt" -d 3 -ef png,jpg,css -jc \
  | grep -Ei '\.js' >> "${OUT}/js/jsurls.txt"
sort -u -o "${OUT}/js/jsurls.txt" "${OUT}/js/jsurls.txt"

# download
mkdir -p "${OUT}/js/files"
cat "${OUT}/js/jsurls.txt" | xargs -P 20 -I{} bash -c '
  u="$1"; f=$(echo "$u" | md5sum | cut -d" " -f1)
  curl -sS --max-time 10 -k -H "User-Agent: Mozilla/5.0" \
    -o "${OUT}/js/files/${f}.js" "$u" && echo "$f $u" >> "${OUT}/js/map.txt"
' _ {}

# LinkFinder: endpoint-shaped strings per file
cat "${OUT}/js/jsurls.txt" | \
  xargs -P 25 -I{} python3 LinkFinder/linkfinder.py \
    -i "{}" -o cli >> "${OUT}/js/linkfinder.txt" 2>/dev/null

# xnLinkFinder (multi-URL, faster)
xnLinkFinder -i "${OUT}/js/jsurls.txt" \
  -o cli -sf -mc 200,204,301,302,403 -o "${OUT}/js/xnlinkfinder.txt"

# SecretFinder across downloaded files
python3 SecretFinder/SecretFinder.py \
  -i "${OUT}/js/files/*.js" -o cli -e \
  > "${OUT}/js/secrets.txt" 2>/dev/null
```

TruffleHog v3 over the same corpus (and any git-sourced artifacts):

```bash
trufflehog filesystem "${OUT}/js/files" \
  --only-verified --json > "${OUT}/js/trufflehog.json" 2>/dev/null || true
```

Filter JS for custom-defined routes + API-ish hits:

```bash
grep -Eo "(https?://[^\"' ]+|/[A-Za-z0-9_\-./{}]+)" "${OUT}/js/jsurls.txt" | \
  xargs -I{} grep -rhoE '["'"'"'`](/[A-Za-z0-9_\-./@{}?&=%]+)' "${OUT}/js/files" \
  | tr -d '"'"'"`'"'" | sort -u > "${OUT}/js/endpoints.txt"
```

## 7. Nuclei template selection

```bash
nuclei -update-templates -silent
```

Template tiering used for each batch:

```bash
# Tier 1 — low-noise, high-signal, run on everything:
nuclei -l "${OUT}/http/subs.json" \
  -tags cves,lfi,ssrf,redirect,rce,payloads,unsafe,auth-bypass,misconfig \
  -severity critical,high,medium \
  -rl 100 -c 25 -timeout 8 -retries 1 \
  -o "${OUT}/nuclei/tier1.txt"

# Tier 2 — tech-matched: derive template tags from httpx tech-detect output
jq -r '.tech[]? // empty' "${OUT}/http/subs.json" \
  | tr '[:upper:]' '[:lower:]' | sort -u > "${OUT}/nuclei/tech.txt"

while read tech; do
  nuclei -u "$tech" -type tech 2>/dev/null || true
done < "${OUT}/nuclei/tech.txt" > /dev/null

nuclei -l "${OUT}/http/subs.json" -tags "$(paste -sd, "${OUT}/nuclei/tech.txt")" \
  -severity low,medium,high -rl 80 -o "${OUT}/nuclei/tier2-tech.txt"

# Tier 3 — panels/exposures/takeovers (high false-positive volume,单独 triage)
nuclei -l "${OUT}/http/subs.json" \
  -tags exposures,panels,token,config,detect,default-logins \
  -rl 60 -o "${OUT}/nuclei/tier3-exposure.txt"

# Tier 4 — fuzzing endpoints (only high-value host subset)
nuclei -l "${OUT}/http/priority.txt" \
  -dast -w nuclei/fuzzing/ -rl 100 -o "${OUT}/nuclei/dast.txt"

# Wordlist-driven file/dir discovery only on priority hosts
nuclei -l "${OUT}/http/priority.txt" \
  -w nuclei/http/http-requests.txt -tags fuzzing -rl 100 \
  -o "${OUT}/nuclei/paths.txt"
```

## 8. Chain it end-to-end

```bash
#!/usr/bin/env bash
set -euo pipefail
source ./config.sh    # DOMAIN, OUT, wordlist paths, token paths

step() { echo -e "\n[+] $1"; }

step "subdomains"
bash 01-enumerate.sh  > "${OUT}/log/01.log" 2>&1
bash 02-permute.sh    > "${OUT}/log/02.log" 2>&1
bash 03-portscan.sh   > "${OUT}/log/03.log" 2>&1

step "http"
bash 04-probe.sh      > "${OUT}/log/04.log" 2>&1

step "urls"
bash 05-urls.sh       > "${OUT}/log/05.log" 2>&1

step "js"
bash 06-js.sh         > "${OUT}/log/06.log" 2>&1

step "scan"
bash 07-nuclei.sh     > "${OUT}/log/07.log" 2>&1

step "report"
jq -s 'flatten' "${OUT}/nuclei/"*.txt > "${OUT}/report.json" 2>/dev/null || true
echo "[+] done: ${OUT}"
```

Run written scope against every putative target; scope-file input instead of `-d "$DOMAIN"` when the program covers multiple roots:

```bash
mapfile -t TARGETS < scope/in-scope.txt
for t in "${TARGETS[@]}"; do DOMAIN="$t" bash recon.sh; done
```

---

## [reasoning trace]

The user wants a bug bounty recon pipeline with chained commands. This is standard in-scope defensive/security research tooling. Provide complete commands. No meta-commentary.

Let me write a solid pipeline.
