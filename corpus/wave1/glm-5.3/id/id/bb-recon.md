# glm-5.3 — bb-recon

# Bug Bounty Recon Pipeline — Chained

## 0. Setup / env

```bash
mkdir -p recon/{subs,resolve,http,ports,urls,js,secrets,nuclei}
export TARGET="target.com"
export BBSCOPE="*.target.com"
export RECON=recon
```

## 1. Passive subdomain enumeration

```bash
# parallel passive sources
(subfinder -d $TARGET -all -silent -pc subfinder-provider-config.yaml > $RECON/subs/subfinder.txt &
assetfinder --subs-only $TARGET > $RECON/subs/assetfinder.txt &
amass enum -passive -d $TARGET -config amass-config.ini -o $RECON/subs/amass.txt &
github-subdomains -d $TARGET -t $GITHUB_TOKENS -o $RECON/subs/github-subdomains.txt &
wait)

# add: chaotichosts / hackertarget / crt.sh as extra fuel
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $RECON/subs/crtsh.txt

cat $RECON/subs/*.txt | sed 's/\*\.//g' | sort -u > $RECON/subs/all.txt
```

## 2. DNS resolution + wildcards + permutation

```bash
# resolve passive set (puredns handles wildcard bruteforcing internally)
puredns resolve $RECON/subs/all.txt \
  -r resolvers.txt --resolvers-trusted resolvers-trusted.txt \
  -w $RECON/resolve/resolved.txt --wildcard-save $RECON/resolve/wildcards.txt

# permutation with gotator (needs resolved subs + a wordlist)
gotator -sub $RECON/resolve/resolved.txt -perm perm-words.txt -depth 1 -mindup -adv -md > $RECON/resolve/gotator.txt
gotator -sub $RECON/resolve/resolved.txt -perm perm-words.txt -depth 1 -mindup -fast -md >> $RECON/resolve/gotator.txt

# resolve permutations + a bruteforce round
(dnsx -l $RECON/resolve/gotator.txt -r resolvers.txt -silent -a -resp -o $RECON/resolve/perms-resolved.txt) &
(puredns bruteforce best-dns-wordlist.txt $TARGET -r resolvers.txt --resolvers-trusted resolvers-trusted.txt -w $RECON/resolve/brute.txt) &
wait

cat $RECON/resolve/resolved.txt $RECON/resolve/brute.txt | sort -u > $RECON/resolve/live.txt
# pull IPs for later ASN/cidr correlation
dnsx -l $RECON/resolve/live.txt -silent -a -resp -o $RECON/resolve/live-ips.json
```

## 3. HTTP probing with tech detection

```bash
httpx -l $RECON/resolve/live.txt \
  -threads 50 -rate-limit 100 \
  -tech-detect -status-code -content-length -title -ip -cname -cdn \
  -follow-hosts -follow-redirects -max-redirects 5 \
  -web-server -fingerprint \
  -json -o $RECON/http/probe.json

# scope-cleaned host list + quick triage
jq -r 'select(.failed==false) | .url' $RECON/http/probe.json | sort -u > $RECON/http/live-urls.txt
jq -r 'select(.failed==false) | "\(.status_code) \(.url) [\(.tech // [] | join(", "))]"' $RECON/http/probe.json | tee $RECON/http/summary.txt
```

## 4. Port scanning (naabu)

```bash
naabu -l $RECON/resolve/live.txt \
  -top-ports 1000 -rate 2000 -c 50 -exclude-cdn \
  -verify -silent -o $RECON/ports/naabu.txt

# targeted second pass on interesting hosts (http/ssh/rdbms/etc. commonly missed)
naabu -l $RECON/resolve/live.txt -p 21,22,23,25,53,80,110,135,139,443,445,1433,1521,2049,2375,2376,3000,3306,3389,4444,5432,5984,6379,8080,8443,9000,9200,11211,27017,5601 \
  -rate 3000 -verify -silent -o $RECON/ports/naabu-extra.txt

# nmap on live ports for service fingerprinting
naabu -l $RECON/resolve/live.txt -top-ports 1000 -verify -silent | \
  nmap -iL - -sV --open --open-only -oG $RECON/ports/nmap.gnmap - | tail -n +1
```

## 5. URL collection

```bash
# passive
(waybackurls $TARGET > $RECON/urls/wayback.txt &
gau --subs --threads 10 $TARGET > $RECON/urls/gau.txt &
wait)
cat $RECON/urls/wayback.txt $RECON/urls/gau.txt | sort -u > $RECON/urls/passive-all.txt

# active crawl of live hosts (katana)
katana -list $RECON/http/live-urls.txt \
  -d 4 -jc -kf all -fx -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,webm \
  -c 30 -rl 150 -timeout 15 \
  -o $RECON/urls/katana.txt

cat $RECON/urls/passive-all.txt $RECON/urls/katana.txt | sort -u > $RECON/urls/all.txt

# high-signal slices
grep -Ei '\.(js|json|map)(\?|$)' $RECON/urls/all.txt | sort -u > $RECON/urls/js.txt
grep -Ei '(=|\?|%3d|%3f)' $RECON/urls/all.txt | sort -u > $RECON/urls/params.txt
grep -Ei '\.(ashx|aspx|jsp|php|action|do|cgi|pl)(\?|$)' $RECON/urls/all.txt | sort -u > $RECON/urls/server-side.txt
grep -Ei '(admin|api|config|debug|env|backup|test|staging|internal|v1|v2)' $RECON/urls/all.txt | sort -u > $RECON/urls/interesting.txt
```

## 6. JS mining — endpoints + secrets

```bash
# download all JS first (linkfinder works offline)
mkdir -p $RECON/js/files
while read u; do
  fn=$(echo "$u" | md5sum | cut -d' ' -f1).js
  curl -sL --max-time 20 -A "Mozilla/5.0" "$u" -o "$RECON/js/files/$fn"
done < $RECON/urls/js.txt

# endpoint extraction
(ls $RECON/js/files/*.js | xargs -P 10 -I{} linkfinder -i {} -o cli) \
  | grep -Eo '(https?://[^"'"'"' ]+|/[a-zA-Z0-9_./?&=-]+)' | sort -u > $RECON/js/endpoints.txt

# endpoints with parameters only
grep '=' $RECON/js/endpoints.txt | sort -u > $RECON/js/endpoints-with-params.txt

# secret extraction
(ls $RECON/js/files/*.js | xargs -P 10 -I{} secretfinder -i {} -o cli) \
  > $RECON/secrets/secretfinder.txt

# xnLinkFinder on the full URL set — better coverage, catches relative paths
xnLinkFinder -i $RECON/urls/all.txt -d $TARGET -sf $TARGET -o $RECON/js/xnlinks.txt -r $RECON/js/xnRaw.txt

# fallback secret sweep — trufflehog on the crawled content
ls $RECON/js/files/*.js | xargs -P 10 -I{} trufflehog filesystem --only-verified --json {} > $RECON/secrets/trufflehog.json 2>/dev/null

# grep-based belt and suspenders
grep -rEhoi "(api[_-]?key|secret|token|password|auth)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]" $RECON/js/files/ | sort -u > $RECON/secrets/grep-hits.txt
```

## 7. Nuclei template selection + run

```bash
nuclei -update-templates

# curated severity tiers — run cheap first, then heavy
nuclei -l $RECON/http/live-urls.txt \
  -t nuclei-templates/http/cves/ -t nuclei-templates/http/vulnerabilities/ \
  -severity critical,high \
  -rl 100 -c 50 -timeout 8 -retries 1 -silent \
  -o $RECON/nuclei/crit-high.txt

nuclei -l $RECON/http/live-urls.txt \
  -t nuclei-templates/http/exposures/ -t nuclei-templates/http/misconfiguration/ \
  -t nuclei-templates/http/tokens/ -t nuclei-templates/file/ \
  -severity medium,high,critical \
  -rl 100 -c 50 -silent \
  -o $RECON/nuclei/exposures.txt

# tech-matched templates only — cut noise by reading httpx tech field
jq -r 'select(.failed==false) | . as $x | (.tech // [])[] | "\(.):\($x.url)"' $RECON/http/probe.json \
  | grep -Ei 'wordpress|jenkins|tomcat|weblogic|struts|drupal|jira|gitlab' \
  | cut -d: -f2- | sort -u > $RECON/nuclei/tech-targets.txt
# then run the matching -tags list against tech-targets.txt
nuclei -l $RECON/nuclei/tech-targets.txt -tags jira,gitlab,wordpress,tomcat -severity critical,high -silent -o $RECON/nuclei/tech.txt

# low-volume passive/panels last
nuclei -l $RECON/http/live-urls.txt -t nuclei-templates/http/technologies/ -silent -o $RECON/nuclei/tech-detect.txt
```

## 8. Wrap-up / triage feed

```bash
cat $RECON/nuclei/*.txt $RECON/secrets/* | sort -u > $RECON/findings.txt
# kill-chain summary
wc -l $RECON/subs/all.txt $RECON/resolve/live.txt $RECON/http/live-urls.txt $RECON/urls/all.txt $RECON/js/endpoints.txt
```

## Scheduling notes

- Cron the passive block daily, permutation+resolution weekly, active crawl (katana) on-demand only against newly resolved hosts — `comm -13 <(sort prev-resolved.txt) $RECON/resolve/live.txt | sort -u > new-subs.txt` and feed that to httpx→katana→nuclei instead of the full set.
- `resolvers.txt`: regenerate weekly via `dnsx -l subs/all.txt -silent -a -resp | jq -r .a[]` against a known-good baseline, or pull from the `trickest/resolvers` repo.
- Rate limits: keep nuclei `-rl 100` and katana `-rl 150` — most BB platforms kill you for sustained >200 rps per host; naabu `-rate 2000` is fine for host-level SYN scanning but dial back to ~500 if the target is behind a single load-balancer IP.
- Dedup JS endpoints against `urls/all.txt` before testing — LinkFinder output overlaps heavily with gau.
- Prioritize: `secrets/` verified hits → `nuclei/crit-high.txt` → `endpoints-with-params.txt` not present in wayback (never-archived params = best bug density) → ports not exposed via CDN front (`naabu -exclude-cdn` output).

---

## [reasoning trace]

Provide a comprehensive recon pipeline with commands.
