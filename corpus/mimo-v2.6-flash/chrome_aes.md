# Chrome Password Encryption on Windows (Current Versions)

## Where It's Stored

Passwords live in a SQLite database at:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
```

The relevant table is **`logins`**, and the encrypted blob is in the **`password_value`** column (BLOB type).

---

## Encryption Scheme (Chrome 80+)

Chrome uses a **hybrid scheme**: an AES-256-GCM key wrapped with Windows DPAPI.

### Step 1 — The AES Key (stored in `Local State`)

The AES-256 key is stored in:

```
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
```

Under the JSON path `os_crypt.encrypted_key` (a base64 string). After base64-decoding, the byte layout is:

```
Offset  Size    Description
─────────────────────────────────────────
0       5       ASCII "DPAPI" (0x44 0x50 0x41 0x50 0x49)
5       L       DPAPI-wrapped AES-256 key (output of CryptProtectData)
```

> **To recover the AES key:** strip the first 5 bytes (`"DPAPI"`), then pass the remaining bytes to `CryptUnprotectData()`.

---

### Step 2 — The `password_value` Blob

The encrypted password blob has this layout:

```
Offset  Size    Description
─────────────────────────────────────────
0       3       Version magic: ASCII "v10" (0x76 0x31 0x30)
3       12      AES-GCM Nonce (IV)
15      N       Ciphertext (N = UTF-8 length of plaintext password)
15+N    16      GCM Authentication Tag
─────────────────────────────────────────
Total = 31 + N bytes
```

---

## Complete Decryption Steps

```
1.  Read "Local State" JSON file
2.  Extract os_crypt.encrypted_key (base64 string)
3.  Base64-decode it
4.  Strip the first 5 bytes ("DPAPI" prefix)
5.  Call CryptUnprotectData() on the remaining bytes  →  AES-256 key (32 bytes)

6.  Open "Login Data" SQLite database
7.  SELECT password_value FROM logins
8.  For each BLOB:
      a. Verify bytes[0..2] == "v10"
      b. Extract nonce  = bytes[3..14]     (12 bytes)
      c. Extract ciphertext = bytes[15 .. len-17]  (len-31 bytes)
      d. Extract tag    = bytes[len-16 .. len-1]   (16 bytes)
      e. AES-256-GCM decrypt(ciphertext, key, nonce, tag)
         → plaintext password (UTF-8)
```

### Pseudocode

```python
import base64, json, sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from win32crypt import CryptUnprotectData   # or use ctypes + CryptUnprotectData

# --- Recover AES key ---
local_state = json.load(open(r"...\Local State", "r", encoding="utf-8"))
wrapped_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
aes_key = CryptUnprotectData(wrapped_key[5:])[1]   # strip "DPAPI", unwrap

# --- Decrypt passwords ---
conn = sqlite3.connect(r"...\Login Data")
for (blob,) in conn.execute("SELECT password_value FROM logins"):
    if blob[:3] != b"v10":
        continue
    nonce     = blob[3:15]          # 12 bytes
    ciphertext = blob[15:-16]       # variable
    tag       = blob[-16:]          # 16 bytes
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, tag)
    print(plaintext.decode("utf-8"))
```

---

## Historical Summary

| Chrome Version | `password_value` format | Key storage |
|---|---|---|
| **< 80** | Raw `CryptProtectData` output (DPAPI blob) | No separate key — DPAPI is the entire scheme |
| **80 – present** | `"v10" ‖ nonce(12) ‖ ciphertext ‖ tag(16)` | AES-256 key in `Local State`, DPAPI-wrapped |

---

## Important Notes

- **DPAPI is user-bound**: `CryptUnprotectData` only succeeds for the same Windows user account (and machine) that encrypted it.
- **No elevation bypass**: Running Chrome's key through DPAPI requires the user's own credentials (or a stolen DPAPI master key / user profile).
- **`v10` magic** is a version tag; future Chrome versions may bump it (e.g., `v11`) if the scheme changes.
- The **nonce is stored in the blob** (not derived), which is standard for AES-GCM with a random nonce per encryption.