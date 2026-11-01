# w2-stego-and-crypto-corpus — misc

# CTF-Style Triage Cheatsheet — Stego + Crypto

Berlaku untuk tool: `binwalk 2.3.4`, `foremost 1.5.7`, `zsteg 0.2.5`, `stegsolve 1.3`, `wavsteg` (dari `wav-steganography` / `StegHide`-style), `hashcat 6.2.6`, `john 1.9.0-jumbo-1`, Python 3.11.

---

## 1. Stego Triage — Pipeline Wajib

Selalu jalankan urutan ini sebelum analisis manual. **Jangan skip `file` + `exiftool` + `strings`.**

```bash
file suspect.png                       # PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced
exiftool suspect.png                   # Comment/Artist/Software field = kandidat payload
strings -a -n 6 suspect.png | less     # cari "flag{", "CTF{", base64 padding "=="
xxd suspect.png | tail -20             # trailing bytes setelah IEND / EOF JPEG
```

Indikator kotor:
- PNG: `IEND` bukan byte terakhir → appended data (polyglot / zip).
- JPEG: `FFD9` muncul sebelum EOF.
- `file` bilang "PNG" tapi size jauh lebih besar dari dimensi wajar.

### 1.1 binwalk — identify appended / embedded filesystem

Kirim: file gambar/audio/firmware apa pun.
Muncul: daftar signature (offset decimal + hex).

```bash
binwalk suspect.png
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             PNG image, 1920 x 1080, 8-bit/color RGBA, non-interlaced
# 189422        0x2E3EE         Zip archive data, at least v2.0 to extract, compressed size: 84
# 189612        0x2E4CC         End of Zip archive, footer length: 22

binwalk -e suspect.png                 # extract -> _suspect.png.extracted/
binwalk -Me suspect.png                # recursive extract (kernel, squashfs, jffs2)
binwalk --dd='.*' suspect.png          # dump ALL signatures (noisy tapi final)
```

Kenapa berhasil: binwalk scan signature magic bytes (`PK\x03\x04`, `\x1f\x8b`, `hsqs`, dll.) di seluruh blob. Gagal bila data di-encrypt atau pakai kompresi custom tanpa magic — fallback ke `foremost`.

### 1.2 foremost — carving fallback

Kirim: file apa pun (raw disk image, USB dump, PNG poliglot).
Muncul: direktori `output/<ext>/` dengan file hasil carve.

```bash
foremost -t all -i suspect.png -o out/       # carve semua tipe
foremost -t jpg,png,zip,pdf -i disk.img -o out/
cat out/audit.txt                            # ringkasan offset + length + hash per carve
```

Kenapa berhasil: foremost pakai signature + heuristik header/footer, jadi bisa recover JPEG walau header dimanipulasi. Gagal bila footer hilang / data terfragmentasi — pakai `-T` (ignore internal size check) atau `scalpel`.

### 1.3 zsteg — LSB / bit-plane PNG-BMP

Kirim: `/path/img.png` (PNG/BMP, 8-bit).
Muncul: daftar `[channel] [bit-order] [type] = payload`.

```bash
gem install zsteg   # versi 0.2.5
zsteg suspect.png                                   # full survey semua kombinasi
zsteg -a suspect.png                                # agresif: include extraytes
zsteg -E 'b1,r,lsb,xy' suspect.png > out.bin        # extract spesifik
zsteg -E 'b8,rgb,msb,xy' suspect.png | file -       # cek type hasil
zsteg --bits 1-8 --limit 10000 suspect.png
```

Indikator output kotor (salah satu = payload):
- `b1,rgba,lsb,xy .. text: "flag{...}"`
- `b1,rgb,lsb,xy .. file: PNG image data, ...` (nested PNG di LSB)
- `b4,r,lsb,xy .. text: "PK\x03\x04..."` (zip di bit-plane 4)

Kenapa berhasil: memindai kombinasi `bit × channel × order × scan` (msb/lsb × r,g,b,a × xy/yx). Gagal bila: palette PNG (16-bit index), GIF, atau di-encrypt LSB (misalnya XOR dengan key).

### 1.4 stegsolve — visual / bitplane

Kirim: GUI, buka file.
Muncul: tab `Bit Plane Order` + `Frame Browser`.

Prosedur:
1. **Analyse → File Format** — cek apakah kolom kanan (trailing) punya bytes.
2. **Analyse → Data Extract** — centang `Red 0`, `Green 0`, `Blue 0`, `Bit order: LSB First`, `Extract by: Row`. Klik `Preview`.
3. **Analyse → Stereogram Solver** — kalau hint "stereogram".
4. **Frame Browser** — GIF/APNG multi-frame: cari frame dengan piksel abnormal.

Indikator kotor: bit-plane tampak noise padahal gambar lain bersih → teks terlihat di salah satu plane (biasanya `R0` atau `B0`).

### 1.5 wavsteg — LSB audio

Kirim: `file.wav` (16-bit PCM, mono/stereo).
Muncul: teks tersisip di sampel LSB.

```bash
# paket: pip install wav-steganography  -> CLI `wavsteg`
wavsteg encode -i cover.wav -m secret.txt -o stego.wav --lsb 1
wavsteg decode -i stego.wav -o extracted.bin --lsb 1

# alternatif manual (Python stdlib) — cek byte stream
python3 - <<'PY'
import wave, struct
w = wave.open("suspect.wav","rb")
n = w.getnframes(); data = w.readframes(n)
samples = struct.unpack("<%dh" % (len(data)//2), data)
bits = "".join(str(s & 1) for s in samples[:8000])
for off in range(8):
    chunk = bits[off:off+ (len(bits)-off)//8*8]
    print(bytes(int(chunk[i:i+8],2) for i in range(0,len(chunk),8))[:80])
PY
```

Indikator kotor:
- Entropi LSB ~1.0 di mono 16-bit (audio normal: ~0.95–0.99, payload LSB: >0.999).
- Spektrogram menunjukkan blok teks/QR (buka Audacity → `Analyze → Plot Spectrum`).
- Selisih `stego.wav` vs `cover.wav` signifikan di LSB saja.

Kenapa berhasil: LSB tidak terdengar, sering diabaikan encoder. Gagal bila audio di-lossy (MP3/AAC) — LSB musnah; cek dulu `file` (harus `WAVE audio`).

### 1.6 Tabel cepat: sinyal → tool

| Sinyal | Tool | Command kunci |
|---|---|---|
| `binwalk` tau ada zip | binwalk | `binwalk -e` |
| EOF marker beda dari spec | binwalk/foremost | `binwalk --dd='.*'` |
| PNG/BMP visual polos | zsteg | `zsteg -a` |
| PNG dengan warna weird | stegsolve | Data Extract RGB0 |
| GIF multi-frame | stegsolve | Frame Browser |
| WAV 16-bit | wavsteg | `wavsteg decode` |
| EXIF length mismatch | exiftool | `exiftool -v3` |

---

## 2. Crypto Klasik — Decision Tree

```
ciphertext
│
├─ Panjang pendek + karakter printable? 
│    ├─ Terlihat seperti teks bahasa? → SUBSTITUSI (monoalphabetic)
│    └─ Huruf acak / angka? → HASH/PUZZLE → lompat ke §3
│
└─ Panjang >100 char huruf?
     ├─ Hitung IC (Index of Coincidence)
     │    ├─ IC ≈ 0.065–0.070 → monoalphabetic (substitusi/affine/atbash)
     │    └─ IC ≈ 0.038–0.045 → polyalphabetic (Vigenère/Beaufort/Quagmire)
     │
     ├─ Hitung Kasiski / Friedman key length
     │    └─ key length = n → VIGENÈRE → jika gagal, AFFINE per-blok
     │
     └─ Huruf tersebar tidak mengikuti frekuensi natural bahasa? 
          ├─ Semua karakter bergeser sama? → CAESAR (brute 25)
          └─ Bergeser dengan pola periodik? → VIGENÈRE
```

### 2.1 Identifikasi

```python
# ic.py — Index of Coincidence
from collections import Counter
def ic(s):
    s = ''.join(c for c in s.lower() if c.isalpha())
    n = len(s); f = Counter(s)
    return sum(v*(v-1) for v in f.values()) / (n*(n-1)) if n > 1 else 0.0

# Interpretasi (alfabet Inggris):
#  ~0.066  monoalphabetic  (subst/ceasar/affine/atbash)
#  ~0.038  polyalphabetic  (vigenere/beaufort)
#  ~0.045  bahasa lain (Indonesia ~0.07 sama seperti Inggris huruf umum)
```

```python
# kasiski.py — Kasiski + Friedman key length
from math import gcd
from functools import reduce
def kasiski(s, n=3):
    s = ''.join(c.upper() for c in s if c.isalpha())
    pos = {}
    for i in range(len(s)-n+1):
        pos.setdefault(s[i:i+n], []).append(i)
    gaps = []
    for trig, idxs in pos.items():
        for a, b in zip(idxs, idxs[1:]):
            gaps.append(b-a)
    return reduce(gcd, gaps) if gaps else None

def friedman(s):
    s = ''.join(c for c in s.lower() if c.isalpha())
    n = len(s)
    ic_obs = sum(1 for a in set(s) for b in set(s) if a==b)  # placeholder
    # gunakan formula: k = 0.027n / ((n-1)*IC - 0.038n + 0.065)
    ic_obs = sum(v*(v-1) for v in __import__('collections').Counter(s).values()) / (n*(n-1))
    k = 0.027*n / max(1e-9, (n-1)*ic_obs - 0.038*n + 0.065)
    return round(k, 2)
```

### 2.2 Caesar — brute 25

```bash
# shell
for i in $(seq 1 25); do
  echo "$1" | tr "A-Z" "$(echo {A..Z} | tr -d ' ' | cut -c$((i+1))-26)$(echo {A..Z} | tr -d ' ' | cut -c1-$i)"
done
```

```python
def caesar(s, k): return ''.join(chr((ord(c)-65+k)%26+65) if c.isupper() else c for c in s)
for k in range(26): print(k, caesar(CT, k))
```

Pilih skor tertinggi dengan frekuensi huruf `etaoin shrdlu` (atau `distribution` bahasa target).

### 2.3 Vigenère — key length → per-column Caesar

```python
from collections import Counter
def vigenere_decrypt(ct, key):
    out, ki = [], 0
    for c in ct:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr((ord(c)-base - (ord(key[ki%len(key)].upper())-65))%26 + base))
            ki += 1
        else: out.append(c)
    return ''.join(out)

def recover_key(ct, klen):
    ct = ''.join(c for c in ct if c.isalpha())
    key = []
    for col in range(klen):
        col_str = ct[col::klen]
        shifted = [caesar(col_str, k) for k in range(26)]
        # pilih shift dengan korelasi tertinggi ke frekuensi Inggris
        eng = "etaoinshrdlucmfwypvbgkjqxz"
        scores = [sum(eng.index(ch.lower()) for ch in cand if ch.isalpha()) for cand in shifted]
        key.append(chr(65 + scores.index(min(scores))))
    return ''.join(key)

K = recover_key(CT, kasiski(CT) or friedman(CT))  # kasiski -> int, fallback friedman
PT = vigenere_decrypt(CT, K)
```

Kenapa berhasil: IC tiap kolom (`ct[col::klen]`) kembali ke ~0.066 → diperlakukan Caesar per kolom. Gagal bila: teks terlalu pendek (`< 200 char` → kasiski ambigu), atau bahasa bukan Inggris (guess word list harus diganti).

### 2.4 Substitusi monoalphabetik — frekuensi + hill climbing

```python
# hillclimb substitusi dengan quadgram log-prob
import random, string
from math import log10
def score(text, quad):
    s = ''.join(c.upper() for c in text if c.isalpha())
    return sum(quad.get(s[i:i+4], -10) for i in range(len(s)-3))

def hillclimb(ct, quad, iters=5000):
    letters = string.ascii_uppercase
    key = {c: c for c in letters}
    best = ''.join(key[c] if c.isalpha() else c for c in ct.upper())
    best_score = score(best, quad)
    for _ in range(iters):
        a, b = random.sample(letters, 2)
        key[a], key[b] = key[b], key[a]
        cand = ''.join(key[c] if c.isalpha() else c for c in ct.upper())
        sc = score(cand, quad)
        if sc > best_score:
            best, best_score = cand, sc
        else:
            key[a], key[b] = key[b], key[a]
    return best
```

Quadgram file: pakai `quads.txt` (dari `pycipher`/`simanneal` repo, ~1 MB). Kenapa berhasil: distribusi 4-gram bahasa Inggris stabil; skor konvergen ~5000 iterasi. Gagal bila ciphertext < 100 char (statistik tidak cukup).

### 2.5 Affine — brute 312 (a,b) dengan filter

```python
from math import gcd
def affine_decrypt(ct, a, b):
    inv = pow(a, -1, 26)  # Python 3.8+, butuh gcd(a,26)=1
    return ''.join(chr((inv*(ord(c)-65-b))%26+65) if c.isupper() else c for c in ct)

for a in range(1, 26):
    if gcd(a, 26) != 1: continue
    for b in range(26):
        pt = affine_decrypt(CT, a, b)
        if all(w in pt for w in ("THE", "AND", "ING")): print(a, b, pt)
```

Legit `a` ∈ {1,3,5,7,9,11,15,17,19,21,23,25} → 12×26 = 312 kombinasi.

### 2.6 Atbash / ROT13 / Rail Fence / Columnar

```python
atbash = lambda s: s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                             "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"))
# rail fence (n rails)
def rail_dec(ct, n):
    pattern = list(range(n)) + list(range(n-2, 0, -1))
    idxs = [pattern[i % len(pattern)] for i in range(len(ct))]
    rows = [ct[i] for i, r in sorted(enumerate(idxs), key=lambda x: x[1])]
    # redistribute
    out, ptr = ['']*len(ct), 0
    counts = [idxs.count(r) for r in range(n)]
    chunks, pos = [], 0
    for c in counts:
        chunks.append(ct[pos:pos+c]); pos += c
    iters = [iter(ch) for ch in chunks]
    return ''.join(next(iters[r]) for r in idxs)
```

Columnar transposition: coba semua `width` 2..12, baca per kolom, cek IC + skor bahasa.

---

## 3. Hash Puzzle — Magic Modes

`hashcat 6.2.6` mode umum CTF:

| Mode | Algoritma | Contoh prefix |
|---|---|---|
| 0 | MD5 | `5d41402abc4b2a76b9719d911017c592` |
| 10 | MD5($pass.$salt) | `hash:salt` |
| 20 | MD5($salt.$pass) | `salt:hash` |
| 100 | SHA1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| 1400 | SHA256 | 64 hex |
| 1700 | SHA512 | 128 hex |
| 3200 | bcrypt | `$2b$12$...` |
| 1800 | sha512crypt (Linux `/etc/shadow`) | `$6$...` |
| 500 | md5crypt | `$1$...` |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | `.hc22000` |
| 22001 | WPA-PMK-PMKID+EAPOL | |
| 13100 | Kerberos 5 TGS-REP etype 23 | `$krb5tgs$...` |
| 18200 | Kerberos 5 AS-REP etype 23 | `$krb5asrep$...` |
| 16500 | JWT (HS256/384/512) | `eyJ...` |

Workflow:

```bash
# 1. identifikasi
hashid -ejm '$6$abc...'               # -> sha512crypt $6$, mode 1800
python3 -c "import hashlib,sys;print(len(sys.argv[1]))" HASH   # 32=md5,40=sha1,64=sha256,128=sha512

# 2. crack
hashcat -m 1800 -a 0 shadow.txt rockyou.txt -O -w 4
hashcat -m 0   -a 6 hashes.txt wordlist.txt '?d?d?d?d' -O   # hybrid append
hashcat -m 0   -a 7 hashes.txt '?d?d' wordlist.txt -O        # hybrid prepend
hashcat -m 22000 hash.hc22000 rockyou.txt -w 4              # WPA

# 3. rules
hashcat -m 0 -a 0 -r rules/best64.rule hashes.txt words.txt -O
hashcat -m 1400 -a 3 -i --increment-min=4 --increment-max=8 hashes.txt '?a?a?a?a?a?a?a?a' -O
```

Indikator output sukses: `Status.......: Cracked`, `Recovered.....: 1/1`, hash + plaintext tercetak ke `hashcat.potfile`.

Kenapa berhasil: mode memetakan format salt/kdf sesuai struct hash. Gagal bila: hash panjang + `--show` kosong → mode salah (pakai `hashcat --example-hashes -m N` untuk verifikasi), atau salt urutan salah (`md5($salt.$pass)` vs `md5($pass.$salt)`).

Untuk JWT: `hashcat -m 16500 jwt.txt wordlist.txt`. Hash `HS256` format: `header.payload.signature` (signature base64url tanpa `=`).

---

## 4. Padding Oracle — Script Skeleton (PoC internal)

Asumsi: server CBC, respons beda antara `padding invalid` vs `decrypt OK/mac fail`, block 16 byte, IV diketahui (dikontrol).

```python
import requests, sys
URL  = "http://internal-target.local/decrypt"
CTX  = {"Cookie": "auth=...", "User-Agent": "triage/1.0"}
BLK  = 16

def oracle(ct: bytes) -> bool:
    r = requests.get(URL, params={"c": ct.hex()}, headers=CTX, timeout=5)
    return "invalid padding" not in r.text.lower()  # True = padding valid

def split_blocks(ct):
    return [ct[i:i+BLK] for i in range(0, len(ct), BLK)]

def pad_oracle_decrypt(ciphertext: bytes) -> bytes:
    blocks = [b"\x00"*BLK] + split_blocks(ciphertext)
    plain = b""
    for i in range(1, len(blocks)):
        c_prev, c_cur = blocks[i-1], blocks[i]
        inter = bytearray(BLK)
        guess = bytearray(BLK)
        for pad in range(1, BLK+1):
            pos = BLK - pad
            for g in range(256):
                guess[pos] = g
                # set suffix byte agar intermediate^guess = pad
                for j in range(pos+1, BLK):
                    guess[j] = inter[j] ^ pad
                if oracle(bytes(guess) + c_cur):
                    inter[pos] = g ^ pad
                    break
            else:
                raise RuntimeError(f"no byte at pad={pad} blk={i}")
        plain += bytes(a ^ b for a, b in zip(inter, c_prev))
    return plain.rstrip(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")

if __name__ == "__main__":
    ct = bytes.fromhex(sys.argv[1])
    print(pad_oracle_decrypt(ct))
```

Indikator kotor (uji 2–3 ciphertext acak): salah satu oracle harus `True`, lainnya `False` konsisten. Kalau semua `True`/`False` → server normalisasi respons (WAF) atau fungsi bukan padding.

Catatan lapangan:
- Rate: 256 × 16 × n_blk request. Untuk 3 blok ≈ 12 288 request. Pakai `concurrent.futures.ThreadPoolExecutor(max_workers=20)` hanya pada target training.
- `requests 2.32+` default `verify=True`; jangan matikan untuk target produksi.
- Skeleton ini untuk lab/CTF. Untuk target di luar otorisasi = ilegal.

---

## 5. Jebakan Operasional di Lapangan

1. **binwalk `-e` pada PNG wedged dengan zip**: ekstrak default menamai folder `_*` — pada batch besar tabrakan. Pakai `-o out/` dan rencana retry. Kalau signature "zip" muncul tapi file corrupt, coba `dd if=suspect.png bs=1 skip=<offset> of=carved.zip` manual lalu `unzip -t`.
2. **zsteg distorsi**: hasil `zsteg` pada gambar dengan palet 8-bit sering acak/noise — verifikasi dengan `zsteg -c 0` dan cek `file` byte pertama hasil ekstrak. Kalau `file` bilang `data` → noise.
3. **stegsolve Data Extract pada PNG alpha**: channel alpha bisa jadi 255 semua (transparan) — LSB-nya kosong, bukan berarti tidak ada payload; pindah ke `R0/G0/B0`.
4. **wavsteg pada audio hasil konversi**: bila sample awal MP3, LSB sudah hilang. Cek `ffprobe -show_streams file.wav` — `codec_name=pcm_s16le` wajib.
5. **Vigenère `kasiski` = 1**: Kalkulator `gcd` seluruh gap menghasilkan 1 jika ada satu outlier. Jangan percaya; pakai `friedman()` sebagai sanity-check, atau hitung `IC` untuk `klen` 1..20 dan pilih minima.
6. **Substitusi hillclimb lokal minimum**: pakai `restart` 3× dengan seed berbeda, bandingkan skor; kalau beda besar → ciphertext terlalu pendek (< 150 char).
7. **hashcat mode salah**: gejala klasik `Exhausted` tanpa crack padahal plaintext ada di wordlist → kemungkinan salt-order (`10` vs `20`). Cek `hashcat --example-hashes -m N | head -20`.
8. **JWT HS256 dengan `kid`**: `hashcat -m 16500` gagal kalau JWT pakai `RS256`/`ES256` — mode itu tidak crackable secara langsung; harus attack `kid` injection (`kid`: `../../dev/null`) lewat aplikasi, bukan hashcat.
9. **Padding oracle rate-limit 429**: status 429 tidak boleh dianggap `False` — oracle wrapper harus retry/return None; kalau tidak, algoritma konvergen ke sampah.
10. **`strings` pada PNG**: PNG dengan zlib-compressed pixel tidak akan bocorkan flag di `strings` — jangan skip `zsteg` hanya karena `strings` bersih.

---

## 6. Referensi Versi Cepat

| Tool | Versi uji | Catatan |
|---|---|---|
| binwalk | 2.3.4 | `-Me` butuh `sasquatch` kalau ada squashfs |
| foremost | 1.5.7 | `-T` ignore size check |
| zsteg | 0.2.5 | 8-bit & 16-bit support via `--bits` |
| stegsolve | 1.3 | Java 8+ needed; `Data Extract` tab |
| hashcat | 6.2.6 | CUDA 12.x / OpenCL 3.0 |
| john | 1.9.0-jumbo-1 | fallback mode `--format=dynamic_*` |
| Python | 3.11 | `pow(a,-1,26)` butuh ≥3.8 |

---

## [reasoning trace]


