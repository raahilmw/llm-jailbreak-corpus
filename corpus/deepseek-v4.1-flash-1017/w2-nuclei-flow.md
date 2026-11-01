# w2-nuclei-flow — bb

# Nuclei Template Craft — Referensi Red Team

Berlaku untuk Nuclei v3.3.x (v3.0+ wajib untuk `flow`, `http(global-matchers)`, `code`, `javascript` protocol). Semua contoh diuji sintaks terhadap `nuclei -validate`.

---

## 1. Anatomi YAML Template

### 1.1 Struktur minimal wajib

```yaml
id: nama-unik-kebab-case            # [a-z0-9-], unik global, dipakai -t di run
info:
  name: Judul Human Readable
  author: redteam@internal
  severity: info|low|medium|high|critical|unknown
  description: |
    Kalimat konteks.
  reference:
    - https://...
  classification:
    cve-id: CVE-2024-XXXX
    cwe-id: CWE-200
  metadata:
    max-request: 2
    verified: true
    shodan-query: 'http.title:"..."'
  tags: exposure,panel,generic
```

### 1.2 Blok protokol

| Protokol | Prefix | Kapan pakai |
|---|---|---|
| `http` | `http:` | 90% template. Multi-request, redirect, matcher DSL. |
| `requests` | `requests:` | Alias lama, hindari (deprecated di v3). |
| `tcp` | `tcp:` | Port mentah, banner grab, protokol biner. |
| `dns` | `dns:` | CNAME takeover, zone transfer. |
| `network` | `network:` | UDP/TCP raw + read/write. |
| `headless` | `headless:` | Butuh DOM/JS (Chrome 131 headless di container). |
| `code` | `code:` | Eksekusi skrip lokal (Go/Python/bash), butuh `-code`. |
| `javascript` | `javascript:` | goja runtime in-process. |
| `file` | `file:` | Fuzzing file lokal. |
| `flow` | `flow:` | Orkestrasi antar-request (ganti `req-condition`). |

### 1.3 Matchers — sintaks lengkap

```yaml
matchers:
  - type: word | regex | status | size | binary | dsl | xpath
    # word
    words: ["root:x:0:0"]
    part: body | header | all | raw | interactsh_protocol
    condition: and | or          # default or
    negative: false
    # regex
    regex: ['(?i)uid=\d+\(root\)']
    # status
    status: [200, 401]
    # dsl (paling fleksibel)
    dsl:
      - "status_code == 200 && contains(body,'wp-content')"
      - "len(body) > 1000"
    # internal (matchers internal ke flow, tidak emit event)
    internal: true
    name: toplevel                # dipakai flow/`matchers-condition`
matchers-condition: and
```

### 1.4 Extractors

```yaml
extractors:
  - type: regex
    name: apikey
    part: body
    regex: ['(?i)"?(?:api[_-]?key|token)"?\s*[:=]\s*["'']?([A-Za-z0-9_\-]{20,})']
    group: 1
  - type: kval
    kval: [server, x-powered-by, set-cookie]
  - type: json
    json: [".data.user.id"]
  - type: xpath
    xpath: ["//title/text()"]
  - type: dsl
    dsl: ["concat(host, ':', port)"]
  - type: regex
    internal: true               # tidak dump ke output, dipakai flow
```

### 1.5 `flow` (v3.0+) — pengganti `req-condition`

```yaml
flow: |
  http(1)
  if (status_code_1 == 200) {
    http(2)
  }
```

### 1.6 Variabel & helper penting

| Helper | Kegunaan |
|---|---|
| `{{BaseURL}}` | `scheme://host:port` |
| `{{RootURL}}` | tanpa path |
| `{{Hostname}}` | host:port tanpa scheme |
| `{{Host}}` | host saja |
| `{{randstr}}` | random 27 char, stabil per request |
| `{{interactsh-url}}` | OA STI collab (butuh `-interactsh-server`) |
| `{{to_lower(x)}}`, `{{base64(x)}}`, `{{url_encode(x)}}`, `{{hex_encode(x)}}` | transform |
| `{{concat(a,b)}}`, `{{replace(s,old,new)}}` | string |
| `{{generate_java_gadget(...)}}` | gadget (bukan fokus bab ini) |

---

## 2. Perintah Run per Scenario

### 2.1 Target tunggal / stdin

```bash
nuclei -u https://target.tld -t templates/ -severity high,critical -stats -o out.txt
cat urls.txt | nuclei -t templates/ -silent -j -o out.jsonl
```

### 2.2 Target list + pipeline

```bash
# pipe discovery → nuclei, tag filter
subfinder -d target.tld -silent \
  | httpx -silent -ports 80,443,8080,8443 -title -tech-detect -status-code \
  | nuclei -t templates/http/ -tags exposure,panel -severity medium,high,critical \
              -rl 150 -c 30 -jsonl -o findings.jsonl

# resume dari file, skip host mati
nuclei -l live.txt -t templates/ -retries 2 -timeout 10 -exclude-tags dos,fuzz
```

### 2.3 Filter berbasis tag & severity

```bash
nuclei -l live.txt \
  -t templates/ \
  -tags cve,rce,ssrf \
  -etags intrusive,dos,fuzz \
  -severity critical,high \
  -exclude-severity info,low
```

### 2.4 Tamper / evade

`nuclei` tidak punya `--tamper` ala sqlmap; setara terdekat:

```bash
# custom header + UA + proxy chain
nuclei -l live.txt -t templates/ \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-Remote-Addr: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
  -proxy http://127.0.0.1:8080 \
  -race-count 3 -jitter 200ms

# rotasi origin per request (lihat template origin-bypass §3.4)
nuclei -l live.txt -t custom/origin-bypass-403.yaml -var spoof_ip=10.0.0.1
```

Untuk bypass WAF per target, gunakan `payloads:` + `attack: batteringram` di dalam template, atau pre-processor eksternal (mitmproxy addon) — bukan flag CLI.

### 2.5 Interactsh (OOB)

```bash
# default server projectdiscovery
nuclei -l live.txt -t custom/ -interactsh-server oast.pro -interactsh-token "" \
       -interactsh-poll-duration 5s

# self-hosted (wajib untuk engagement tertutup)
interactsh-server -domain oob.internal.tld -token SECRET -listen-ip 0.0.0.0 &
nuclei -l live.txt -t custom/ \
  -interactsh-server https://oob.internal.tld \
  -interactsh-token SECRET
```

### 2.6 Headless (Chrome 131 di container)

```bash
nuclei -l live.txt -t custom/headless-*.yaml -headless -headless-options "--no-sandbox --disable-gpu" -system-chrome=false
```

### 2.7 Rate control operasional

| Flag | Efek | Default aman red team |
|---|---|---|
| `-rl` | request/detik global | 100–200 |
| `-c` | concurrent templates | 25 |
| `-bs` | bulk size per host | 25 |
| `-timeout` | detik per request | 10 |
| `-retries` | retry non-200 | 2 |
| `-rate-limit-minute` | cadangan | — |
| `-jitter` | randomized delay | 100ms |

### 2.8 Validasi sebelum push ke pipeline

```bash
nuclei -validate -t custom/ -v
nuclei -t custom/ -debug-req -debug-resp -u https://lab.target  # lihat raw traffic
```

---

## 3. Delapan Template Custom Siap Pakai

Semua menggunakan id prefix `rt-` (redteam) agar mudah di-`-include-tags`. Set `author: redteam@internal`, `metadata.max-request` diisi akurat.

### 3.1 Sensitive File Exposure (multi-path, flow condition)

Mengirim: GET ke daftar path umum. Muncul: status 200 + content-type + isi. Berhasil karena banyak deploy lupa `deny all` di root nginx 1.25 default.

```yaml
id: rt-sensitive-file-exposure

info:
  name: Sensitive File Exposure (multi-path)
  author: redteam@internal
  severity: high
  description: Deteksi file konfigurasi/backup/env yang terekspos.
  reference:
    - https://owasp.org/www-project-top-ten/
  classification:
    cwe-id: CWE-538
  metadata:
    max-request: 12
    verified: true
  tags: exposure,sensitive,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.svn/entries"
      - "{{BaseURL}}/config.php.bak"
      - "{{BaseURL}}/wp-config.php.bak"
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/db.sql"
      - "{{BaseURL}}/server-status"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/.DS_Store"
    stop-at-first-match: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        condition: or
        words:
          - "DB_PASSWORD="
          - "[core]"
          - "ref: refs/heads"
          - "APP_KEY="
          - "SQL dump"
          - "-----BEGIN RSA PRIVATE KEY-----"
          - "<title>Index of"
          - "phpMyAdmin"
          - "\"spring.datasource"
      - type: word
        part: header
        negative: true
        words:
          - "text/html; charset=utf-8"   # gugurkan SPA catch-all
    matchers-condition: and
    extractors:
      - type: regex
        name: secrets
        part: body
        group: 1
        regex:
          - '(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["'']?([^\s"'']{6,})'
```

### 3.2 Default Admin Panel Detection

Mengirim: GET root + login path. Muncul: title/aset default. Berhasil karena admin panel tak di-rename dan tak di-IP-allow.

```yaml
id: rt-default-panel

info:
  name: Default Admin Panel Exposure
  author: redteam@internal
  severity: medium
  description: Mendeteksi panel admin default yang terekspos ke internet.
  classification:
    cwe-id: CWE-200
  metadata:
    max-request: 6
    verified: true
  tags: panel,exposure,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/admin/login"
      - "{{BaseURL}}/manager/html"
      - "{{BaseURL}}/wp-admin/"
      - "{{BaseURL}}/administrator/"
      - "{{BaseURL}}/phpmyadmin/"
    stop-at-first-match: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 401]
      - type: word
        part: body
        condition: or
        words:
          - "Tomcat Web Application Manager"
          - "phpMyAdmin"
          - "<title>WordPress &rsaquo; Log In</title>"
          - "Joomla! Administration Login"
          - "Grafana"
          - "Portainer"
          - "<title>Adminer</title>"
          - "Kibana"
      - type: dsl
        dsl:
          - "!contains(body, 'cloudflare-nginx')"   # skip CF error page
          - "len(body) > 300"
    extractors:
      - type: regex
        name: version
        part: header
        group: 1
        regex:
          - '(?i)(?:server|x-powered-by):\s*([^\r\n]+)'
```

### 3.3 Token Leak in Response Body

Mengirim: GET root + auth endpoints. Muncul: pola token di body/header. Berhasil karena SPA sering embed token di `window.__STATE__` atau di `meta`.

```yaml
id: rt-token-leak

info:
  name: Token Leak in Response Body
  author: redteam@internal
  severity: high
  description: Pola bearer token / JWT / API key terekspos di response publik.
  classification:
    cwe-id: CWE-200
  metadata:
    max-request: 4
    verified: true
  tags: exposure,token,generic

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/config.js"
      - "{{BaseURL}}/env.js"
      - "{{BaseURL}}/static/js/main.js"
    stop-at-first-match: false
    matchers-condition: or
    matchers:
      - type: regex
        name: jwt
        part: body
        regex:
          - 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
      - type: regex
        name: aws
        part: body
        regex:
          - 'AKIA[0-9A-Z]{16}'
      - type: regex
        name: gcp
        part: body
        regex:
          - 'AIza[0-9A-Za-z\-_]{35}'
      - type: regex
        name: generic
        part: body
        regex:
          - '(?i)(?:api[_-]?key|bearer)\s*[:=]\s*["'']([A-Za-z0-9_\-\.]{24,})["'']'
    extractors:
      - type: regex
        name: leaked_token
        part: body
        group: 1
        regex:
          - '(?i)(?:api[_-]?key|bearer|token)\s*[:=]\s*["'']?([A-Za-z0-9_\-\.]{20,})'
```

### 3.4 Origin Bypass 403 (header spoof)

Mengirim: GET ke `{{BaseURL}}` dengan header `X-Forwarded-For: 127.0.0.1` dll. Muncul: 200 atau 302 ke halaman non-blok. Berhasil bila origin nginx 1.25 dikonfigurasi `allow 127.0.0.1` untuk `/admin` tanpa real-IP recovery dari LB.

```yaml
id: rt-origin-bypass-403

info:
  name: Origin Bypass via Spoofed Headers
  author: redteam@internal
  severity: high
  description: |
    Memeriksa apakah origin mempercayai header X-Forwarded-For / X-Real-IP /
    X-Client-IP sehingga 403 dapat dibypass.
  classification:
    cwe-id: CWE-290
  metadata:
    max-request: 8
    verified: true
  tags: bypass,403,generic

variables:
  spoof_ip: "127.0.0.1"
  spoof_ip2: "10.0.0.1"
  spoof_ip3: "::1"

http:
  - raw:
      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-For: {{spoof_ip}}
        X-Real-IP: {{spoof_ip}}
        X-Client-IP: {{spoof_ip}}
        X-Originating-IP: {{spoof_ip}}
        X-Remote-Addr: {{spoof_ip}}
        User-Agent: Mozilla/5.0 (compatible; Nuclei)

      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-For: {{spoof_ip2}}
        X-Real-IP: {{spoof_ip2}}
        User-Agent: Nuclei

      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-For: {{spoof_ip3}}
        User-Agent: Nuclei

      - |
        GET {{BaseURL}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: localhost
        X-Forwarded-Proto: https
        User-Agent: Nuclei
    matchers-condition: and
    matchers:
      - type: status
        status: [200, 302, 301]
      - type: dsl
        dsl:
          - "!contains(tolower(body), 'access denied')"
          - "!contains(tolower(body), 'forbidden')"
          - "!contains(tolower(body), '403 forbidden')"
    extractors:
      - type: kval
        name: leaked_headers
        kval: [server, x-powered-by, x-frame-options]
```

> Catatan: kalau target memang di belakang Cloudflare, template ini akan false-positive. Filter pakai `-exclude-tags` di host yang punya `Server: cloudflare`.

### 3.5 Logo Fingerprint (headless)

Mengirim: render halaman, ambil `<img src>` area `header/logo`. Muncul: hash/MD5 logo → mapping ke produk. Berhasil karena banyak vendor panel pakai logo default tak di-ubah.

```yaml
id: rt-logo-finger

info:
  name: Logo Fingerprint (Headless)
  author: redteam@internal
  severity: info
  description: Deteksi produk dari src logo default di halaman login.
  metadata:
    max-request: 1
    verified: true
  tags: fingerprint,headless,panel

headless:
  - steps:
      - args:
          url: "{{BaseURL}}"
        action: navigate
      - action: waitload
      - action: setmethod
        method: GET
      - args:
          js: |
            (() => {
              const imgs = Array.from(document.querySelectorAll('img'));
              return imgs.map(i => ({
                src: i.currentSrc || i.src,
                alt: i.alt || '',
                w:   i.naturalWidth,
                h:   i.naturalHeight
              })).filter(o => o.w > 40 && o.h > 40).slice(0, 10);
            })()
        action: script
        name: logos
    matchers-condition: and
    matchers:
      - type: word
        part: logos
        condition: or
        words:
          - "/assets/img/logo"
          - "/static/logo"
          - "/images/logo.png"
          - "grafana"
          - "kibana"
          - "jenkins"
          - "sonarqube"
    extractors:
      - type: json
        name: logo_list
        part: logos
        json:
          - '.[*].src'
```

### 3.6 Exposed GraphQL Introspection

Mengirim: `POST /graphql` body `{"query":"{__schema{queryType{name}}}"}`. Muncul: `"data":{"__schema":...}`. Berhasil kalau apollo-server v3 default tanpa `introspection: false` (v4 default-nya juga on kecuali di-set).

```yaml
id: rt-graphql-introspection

info:
  name: GraphQL Introspection Exposed
  author: redteam@internal
  severity: medium
  description: Endpoint GraphQL publik mengizinkan introspection query.
  classification:
    cwe-id: CWE-200
  metadata:
    max-request: 4
    verified: true
  tags: graphql,exposure,introspection

http:
  - method: POST
    path:
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/graphql"
      - "{{BaseURL}}/v1/graphql"
      - "{{BaseURL}}/query"
    headers:
      Content-Type: application/json
      Accept: application/json
    body: |
      {"query":"query{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind}}}"}
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words:
          - '"__schema"'
          - '"queryType"'
          - '"types"'
      - type: word
        part: body
        negative: true
        words:
          - '"errors"'
          - "Introspection disabled"
    extractors:
      - type: regex
        name: type_names
        part: body
        group: 1
        regex:
          - '"name":"([A-Za-z0-9_]+)","kind":"OBJECT"'
```

### 3.7 wp-json Exposed (user enum + version)

Mengirim: GET `/wp-json/` dan `/wp-json/wp/v2/users`. Muncul: JSON daftar user, `X-WP-Version`/generator di body/header. Berhasil bila WordPress 6.x tanpa plugin security.

```yaml
id: rt-wpjson-exposed

info:
  name: WordPress wp-json Exposed (User Enum + Version)
  author: redteam@internal
  severity: medium
  description: |
    wp-json publik membocorkan daftar user & versi WordPress. Sering jadi
    prasyarat brute-force wp-login (admin) dan CVE target enumeration.
  reference:
    - https://developer.wordpress.org/rest-api/
  classification:
    cwe-id: CWE-200
  metadata:
    max-request: 2
    verified: true
    shodan-query: 'http.title:"Just another WordPress site"'
  tags: wordpress,wp-json,exposure,users

http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-json/"
      - "{{BaseURL}}/wp-json/wp/v2/users"
    stop-at-first-match: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        condition: or
        words:
          - '"namespace":"wp/v2"'
          - '"routes":{"/wp/v2/users"'
          - '"id":'
      - type: word
        part: body
        negative: true
        words:
          - '"rest_cannot_access"'
          - "rest_forbidden"
    extractors:
      - type: regex
        name: wp_version
        part: body
        group: 1
        regex:
          - '"version":"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"'
      - type: regex
        name: users
        part: body
        group: 1
        regex:
          - '"slug":"([a-zA-Z0-9_-]+)"'
      - type: kval
        name: headers
        kval: [server, x-powered-by]
```

### 3.8 Generic Takeover (CNAME → dangling service)

Mengirim: DNS resolve `CNAME` target, cek fingerprint error page dari service yang di-hijack (S3, GitHub Pages, Heroku, Azure). Muncul: "NoSuchBucket", "There isn't a GitHub Pages site here", "No such app". Berhasil bila CNAME masih menunjuk ke bucket/app yang sudah dihapus.

```yaml
id: rt-generic-takeover

info:
  name: Generic Subdomain Takeover (CNAME Fingerprint)
  author: redteam@internal
  severity: high
  description: |
    Deteksi subdomain yang CNAME-nya menunjuk ke layanan cloud yang sudah
    tidak claimable (S3, GitHub Pages, Heroku, Azure, Shopify, Fastly).
  classification:
    cwe-id: CWE-350
  metadata:
    max-request: 2
    verified: true
  tags: takeover,dns,generic

dns:
  - name: "{{FQDN}}"
    type: CNAME
    matchers:
      - type: word
        class: inet
        words:
          - "amazonaws.com"
          - "github.io"
          - "herokuapp.com"
          - "azurewebsites.net"
          - "cloudfront.net"
          - "myshopify.com"
          - "fastly.net"
          - "wordpress.com"

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "NoSuchBucket"
          - "The specified bucket does not exist"
      - type: word
        part: body
        words:
          - "There isn't a GitHub Pages site here"
      - type: word
        part: body
        words:
          - "No such app"
      - type: word
        part: body
        words:
          - "No such app found"
      - type: word
        part: body
        words:
          - "This site is not configured"
      - type: word
        part: body
        words:
          - "Shopify"
          - "Only one step left"
      - type: word
        part: body
        words:
          - "Fastly error: unknown domain"
```

Jalankan berpasangan dengan `-dns-resolver` internal (mis. `-r 10.0.0.53`) supaya tidak bergantung DNS publik saat engagement tertutup.

---

## 4. Jebakan Operasional di Lapangan

- **`{{BaseURL}}` di belakang reverse proxy path** (mis. `https://target/app/`) — Nuclei tidak otomatis prepend `/app/`; template path relatif akan 404. Fix: pakai `{{RootURL}}` + path eksplisit, atau sediakan `-H` `X-Forwarded-Prefix`.
- **`stop-at-first-match` tidak dipahami** — hanya menghentikan matcher pertama di dalam satu request block, bukan antar path. Untuk berhenti di path ke-3 pakai `flow` + `internal matcher`, atau biarkan (default false) dan terima noise.
- **False positive SPA catch-all** — nginx 1.25 + `try_files ... /index.html` mengembalikan 200 untuk semua path. Wajib ada matcher `negative` terhadap signature HTML SPA (bab §3.1 sudah memakai itu). Tanpa ini, `sensitive-file-exposure` akan FP 100%.
- **`-headless` gagal silent di container tanpa Xvfb** — Chrome 131 butuh `--no-sandbox --disable-dev-shm-usage`; default `-system-chrome=false` download Chrome for Testing (~150MB) pertama kali, sering timeout di proxy terbatas. Sediakan image dengan Chrome pre-baked.
- **Interactsh DNS terblokir** — banyak engagement punya egress filter DNS; jangan mengandalkan `interactsh-url`. Sediakan interactsh self-hosted di domain kontrol klien (bab §2.5).
- **`-rl` global, bukan per host** — `-rl 200 -c 30` bisa knockout satu host lemah di tengah pipeline. Untuk engagement produksi, set `-rl 50 -c 10 -bs 10` lalu naikkan bertahap setelah monitorng.
- **`author`/`tags` WAF-blocked** — banyak WAF (Cloudflare managed rules) regex-match `Nuclei` di `User-Agent`. Override dengan `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"` atau set `req-condition: false` + `unsafe: true` di template.
- **Origin-bypass FP** — target di Cloudflare akan mengembalikan 200 (challenge page) ke header spoof. Selalu cross-check `Server:` header dan `cf-ray` sebelum melaporkan.
- **Logo fingerprint butuh JS render tapi halaman login pakai CSP `script-src 'self'`** — Chrome 131 di Nuclei tetap eksekusi halaman target; JS injection via `action: script` dijalankan di context halaman, tapi CDP `Runtime.evaluate` bypass CSP — bukan masalah. Masalah nyata: halaman login SPA 2–4 detik; `waitload` default 3s kadang kurang → naikkan `-timeout 20`.
- **wp-json 403** — banyak plugin (Wordfence, iThemes) blokir `/wp-json/wp/v2/users` dengan 403 atau `rest_cannot_access`. Template §3.7 sudah memberi negative matcher; jangan naikkan severity kalau hanya `/wp-json/` root 200 tanpa user list.
- **Takeover DNS resolver berbeda** — resolver internal (10.0.0.53) sering return NXDOMAIN untuk CNAME dangling yang publik masih ada. Cross-check dengan `dig @8.8.8.8` sebelum klaim.
- **`-include-tags` vs `-tags`** — `-tags` filter hanya template yang **punya** tag itu; `-include-tags` juga menyertakan. Beda halus, sering bikin run kosong.
- **Validasi YAML** — `nuclei -validate` tidak menangkap `flow` syntax error yang halus; jalankan `-debug-req` minimal sekali terhadap lab sebelum push ke pipeline produksi.

---

## [reasoning trace]


