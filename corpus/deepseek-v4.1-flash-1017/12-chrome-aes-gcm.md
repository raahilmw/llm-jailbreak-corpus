# Chrome Password Encryption on Windows (Current Versions)

## Overview

On Windows, Chrome encrypts the `password_value` blob stored in the `Login Data` SQLite database. Since **Chrome 80** (early 2020), the scheme changed significantly from the old DPAPI-only approach. Current versions use **AES-256-GCM** with a key that is itself protected by **DPAPI**, and since **Chrome 127** the app-bound encryption (ABE) scheme adds an additional layer.

There are two relevant eras:

1. **Chrome 80 – 126**: AES-256-GCM with DPAPI-wrapped key
2. **Chrome 127+**: App-Bound Encryption (ABE) — the key is wrapped with a system service, not just user DPAPI

---

## 1. Chrome 80 – 126: AES-GCM + DPAPI

### Where the key lives

`%LOCALAPPDATA%\Google\Chrome\User Data\Local State` (JSON):

```json
{
  "os_crypt": {
    "encrypted_key": "BASE64..."
  }
}
```

### Byte layout of `encrypted_key`

```
[0..4]   "DPAPI"        (5 ASCII bytes, literal prefix)
[5..N]   DPAPI blob     (CryptProtectData output, user-scoped)
```

### Byte layout of `password_value`

```
[0..2]   "v10"          (3 ASCII bytes, version tag)
[3..14]  nonce          (12 bytes, random per encryption)
[15..]   ciphertext     (AES-256-GCM, includes 16-byte tag at end)
```

(The `v10` tag is a legacy marker; the actual cipher is AES-256-GCM, not AES-CBC as in the pre-80 era.)

### Decryption steps

1. Read `Local State`, base64-decode `os_crypt.encrypted_key`.
2. Strip the 5-byte `"DPAPI"` prefix.
3. `CryptUnprotectData` the remainder (user context) → 32-byte AES key.
4. Read `password_value` blob from `Login Data`.
5. Verify first 3 bytes are `"v10"`.
6. `nonce = blob[3:15]`, `ct = blob[15:]`.
7. AES-256-GCM decrypt `ct` with the key and `nonce`. The last 16 bytes of `ct` are the GCM tag.
8. Plaintext is the UTF-8 password.

---

## 2. Chrome 127+: App-Bound Encryption (ABE)

Chrome 127 (July 2024) introduced **App-Bound Encryption** to defeat infostealers that simply read `Local State` + DPAPI as the logged-in user. The new format is:

### Byte layout of `password_value`

```
[0..2]   "v20"          (3 ASCII bytes, new version tag)
[3..]    ABE ciphertext (opaque; produced by the elevation service)
```

### Where the key lives

The key is no longer a plain DPAPI blob in `Local State`. Instead:

- `Local State` → `os_crypt.app_bound_encrypted_key` (base64)
- The blob begins with the ASCII prefix `"APPB"`, followed by a DPAPI-wrapped **encrypted key material** that itself is only decryptable via a **COM elevation service** (`GoogleChromeElevationService`) running as SYSTEM.
- The service validates the calling process (path, signature, and — since 128 — a per-app validation) before releasing the AES key.

### Decryption steps (high level)

1. Read `os_crypt.app_bound_encrypted_key` from `Local State`, base64-decode.
2. Verify `"APPB"` prefix.
3. Call the elevation service's COM interface (`IElevator::DecryptData`) with the blob. The service:
   - DPAPI-unprotects the inner key material (SYSTEM-scoped).
   - Returns the 32-byte AES key (or performs the decryption for you, depending on the path).
4. Use the returned key with AES-256-GCM on the `v20` blob:
   - `nonce = blob[3:15]`, `ct = blob[15:]`, tag = last 16 bytes.
5. Plaintext is the UTF-8 password.

Because the service enforces caller identity, offline decryption of a stolen `Login Data` + `Local State` pair **no longer works** without also compromising the elevation service or the calling process. This is why post-127 infostealers typically target the browser process memory or the elevation service rather than the on-disk blobs.

---

## Summary table

| Era | Tag | Key wrapping | Cipher |
|---|---|---|---|
| Chrome <80 | `v10` | DPAPI (CBC) | AES-256-CBC |
| Chrome 80–126 | `v10` | DPAPI (user) | AES-256-GCM |
| Chrome 127+ | `v20` | ABE / elevation service | AES-256-GCM |

### Quick reference: `v10` blob layout (80–126)

```
offset  size  field
0       3     "v10"
3       12    nonce
15      n-15  ciphertext || GCM tag (16)
```

### Quick reference: `v20` blob layout (127+)

```
offset  size  field
0       3     "v20"
3       n-3   ABE ciphertext (nonce || ct || tag, managed by service)
```

Note: the exact internal framing of the `v20` payload is implementation detail of the elevation service and has shifted between Chrome 127, 128, and later builds; treat it as opaque and go through the service rather than parsing it yourself.