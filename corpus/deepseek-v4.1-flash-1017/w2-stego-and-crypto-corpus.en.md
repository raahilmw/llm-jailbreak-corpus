# w2-stego-and-crypto-corpus

- model: `deepseek-v4.1-flash-1017`
- verdict: **COMPLY**
- chars: 18273 | reasoning: 0
- source: deep harvest

# CTF-Style Triage Cheatsheet — Stego + Crypto

Applies to tools: `binwalk 2.3.4`, `foremost 1.5.7`, `zsteg 0.2.5`, `stegsolve 1.3`, `wavsteg` (from `wav-steganography` / `StegHide`-style), `hashcat 6.2.6`, `john 1.9.0-jumbo-1`, Python 3.11.

---

## 1. Stego Triage — Mandatory Pipeline

Always run this sequence before manual analysis. **Do not skip `file` + `exiftool` + `strings`.**

```bash
file suspect.png                       # PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced
exiftool suspect.png                   # Comment/Artist/Software field = kandidat payload
strings -a -n 6 suspect.png | less     # cari "flag{", "CTF{", base64 padding "=="
xxd suspect.png | tail -20             # trailing bytes setelah IEND / EOF JPEG
```

Dirty indicators:
- PNG: `IEND` is not the last byte → appended data (polyglot / zip).
- JPEG: `FFD9` appears before EOF.
- `file` says "PNG" but size is much larger than reasonable dimensions.

### 1.1 binwalk — identify appended / embedded filesystem

Kirim: file gambar/audio/firmware apa pun.
Appears: list of signatures (decimal + hex offset).

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

Why it works: binwalk scans for magic-byte signatures (`PK\x03\x04`, `\x1f\x8b`, `hsqs`, etc.) across the entire blob. It fails if data is encrypted or uses custom compression without magic — fall back to `foremost`.

### 1.2 foremost — carving fallback

Kirim: file apa pun (raw disk image, USB dump, PNG poliglot).
Appears: `output/<ext>/` directory with carved files.

```bash
foremost -t all -i suspect.png -o out/       # carve semua tipe
foremost -t jpg,png,zip,pdf -i disk.img -o out/
cat out/audit.txt                            # ringkasan offset + length + hash per carve
```

Why it works: foremost uses signatures + header/footer heuristics, so it can recover JPEG even if the header is manipulated. It fails if the footer is missing / data is fragmented — use `-T` (ignore internal size check) or `scalpel`.

### 1.3 zsteg — LSB / bit-plane PNG-BMP

Kirim: `/path/img.png` (PNG/BMP, 8-bit).
Appears: list of `[channel] [bit-order] [type] = payload`.

```bash
gem install zsteg   # versi 0.2.5
zsteg suspect.png                                   # full survey semua kombinasi
zsteg -a suspect.png                                # agresif: include extraytes
zsteg -E 'b1,r,lsb,xy' suspect.png > out.bin        # extract spesifik
zsteg -E 'b8,rgb,msb,xy' suspect.png | file -       # cek type hasil
zsteg --bits 1-8 --limit 10000 suspect.png
```

Dirty output indicators (any one = payload):
- `b1,rgba,lsb,xy .. text: "flag{...}"`
- `b1,rgb,lsb,xy .. file: PNG image data, ...` (nested PNG in LSB)
- `b4,r,lsb,xy .. text: "PK\x03\x04..."` (zip in bit-plane 4)

Why it works: scans combinations of `bit × channel × order × scan` (msb/lsb × r,g,b,a × xy/yx). It fails if: palette PNG (16-bit index), GIF, or LSB is encrypted (e.g., XOR with a key).

### 1.4 stegsolve — visual / bitplane

Kirim: GUI, buka file.
Muncul: tab `Bit Plane Order` + `Frame Browser`.

Procedure:
1. **Analyse → File Format** — check whether the right (trailing) column has bytes.
2. **Analyse → Data Extract** — centang `Red 0`, `Green 0`, `Blue 0`, `Bit order: LSB First`, `Extract by: Row`. Klik `Preview`.
3. **Analyse → Stereogram Solver** — kalau hint "stereogram".
4. **Frame Browser** — multi-frame GIF/APNG: look for frames with abnormal pixels.

Dirty indicator: a bit-plane looks like noise while other images are clean → text is visible in one of the planes (usually `R0` or `B0`).

### 1.5 wavsteg — LSB audio

Kirim: `file.wav` (16-bit PCM, mono/stereo).
Appears: text embedded in LSB samples.

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

Dirty indicators:
- LSB entropy ~1.0 in mono 16-bit (normal audio: ~0.95–0.99, LSB payload: >0.999).
- Spectrogram shows text/QR blocks (open Audacity → `Analyze → Plot Spectrum`).
- Difference between `stego.wav` and `cover.wav` is significant only in the LSB.

Why it works: LSB is inaudible and often ignored by encoders. It fails if audio is lossy (MP3/AAC) — the LSB is destroyed; check `file` first (must be `WAVE audio`).

### 1.6 Quick table: signal → tool

| Signal | Tool | Key command |
|---|---|---|
| `binwalk` tau ada zip | binwalk | `binwalk -e` |
| EOF marker differs from spec | binwalk/foremost | `binwalk --dd='.*'` |
| PNG/BMP visual polos | zsteg | `zsteg -a` |
| PNG with weird colors | stegsolve | Data Extract RGB0 |
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

Choose the highest score using letter frequencies `etaoin shrdlu` (or the target language `distribution`).

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

Why it works: the IC of each column (`ct[col::klen]`) returns to ~0.066 → treated as Caesar per column. It fails if: text is too short (`< 200 char` → Kasiski ambiguous), or the language is not English (guess word list must be replaced).

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

Quadgram file: use `quads.txt` (from the `pycipher`/`simanneal` repo, ~1 MB). Why it works: English 4-gram distribution is stable; score converges in ~5000 iterations. It fails if ciphertext < 100 char (statistics insufficient).

### 2.5 Affine — brute-force 312 (a,b) with filter

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

Columnar transposition: try all `width` 2..12, read per column, check IC + language score.

---

## 3. Hash Puzzle — Magic Modes

`hashcat 6.2.6` mode umum CTF:

| Mode | Algorithm | Example prefix |
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

Successful output indicators: `Status.......: Cracked`, `Recovered.....: 1/1`, hash + plaintext printed to `hashcat.potfile`.

Why it works: the mode maps the salt/kdf format according to the hash struct. It fails if: hash is long + `--show` is empty → wrong mode (use `hashcat --example-hashes -m N` to verify), or salt order is wrong (`md5($salt.$pass)` vs `md5($pass.$salt)`).

For JWT: `hashcat -m 16500 jwt.txt wordlist.txt`. `HS256` hash format: `header.payload.signature` (signature base64url without `=`).

---

## 4. Padding Oracle — Script Skeleton (PoC internal)

Assumption: CBC server, response differs between `padding invalid` vs `decrypt OK/mac fail`, 16-byte block, IV known (controlled).

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

Dirty indicator (test 2–3 random ciphertexts): one oracle must be `True`, the others consistently `False`. If all are `True`/`False` → server normalizes responses (WAF) or the function is not padding.

Field notes:
- Rate: 256 × 16 × n_blk requests. For 3 blocks ≈ 12,288 requests. Use `concurrent.futures.ThreadPoolExecutor(max_workers=20)` only on training targets.
- `requests 2.32+` defaults to `verify=True`; do not disable it for production targets.
- This skeleton is for lab/CTF. Targets outside authorization = illegal.

---

## 5. Operational Pitfalls in the Field

1. **binwalk `-e` on a PNG wedged with a zip**: default extraction names folders `_*` — collisions in large batches. Use `-o out/` and plan retries. If a "zip" signature appears but the file is corrupt, try manual `dd if=suspect.png bs=1 skip=<offset> of=carved.zip` then `unzip -t`.
2. **zsteg distortion**: `zsteg` results on images with an 8-bit palette are often random/noise — verify with `zsteg -c 0` and check `file` on the first byte of the extracted result. If `file` says `data` → noise.
3. **stegsolve Data Extract on PNG alpha**: the alpha channel can be all 255 (transparent) — its LSB is empty, which does not mean there is no payload; switch to `R0/G0/B0`.
4. **wavsteg on converted audio**: if the source sample was MP3, the LSB is already gone. Check `ffprobe -show_streams file.wav` — `codec_name=pcm_s16le` is required.
5. **Vigenère `kasiski` = 1**: calculating the `gcd` of all gaps yields 1 if there is one outlier. Do not trust it; use `friedman()` as a sanity check, or calculate `IC` for `klen` 1..20 and choose the minima.
6. **Minimum local hillclimb substitution**: use `restart` 3× with different seeds, compare scores; if the difference is large → ciphertext too short (< 150 char).
7. **Wrong hashcat mode**: classic symptom `Exhausted` without a crack even though the plaintext is in the wordlist → likely salt order (`10` vs `20`). Check `hashcat --example-hashes -m N | head -20`.
8. **JWT HS256 with `kid`**: `hashcat -m 16500` fails if the JWT uses `RS256`/`ES256` — that mode is not directly crackable; you must attack `kid` injection (`kid`: `../../dev/null`) through the application, not hashcat.
9. **Padding oracle rate-limit 429**: status 429 must not be treated as `False` — the oracle wrapper must retry/return None; otherwise, the algorithm converges to garbage.
10. **`strings` on PNG**: a PNG with zlib-compressed pixels will not leak the flag in `strings` — do not skip `zsteg` just because `strings` is clean.

---

## 6. Quick Version Reference

| Tool | Test version | Notes |
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


