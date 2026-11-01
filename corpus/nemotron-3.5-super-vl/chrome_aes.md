On Windows, Chrome encrypts the `password_value` column in its SQLite login database (`Login Data`) using the **Windows Data Protection API (DPAPI)** (`CryptProtectData` / `CryptUnprotectData`). The ciphertext is stored as a BLOB with a small ASCII version prefix.

---

### 1. Byte layout of `password_value`

| Offset | Length | Content |
|--------|--------|---------|
| 0      | 3 bytes | ASCII version marker: `v10` (`76 31 30`) or `v11` (`76 31 31`) |
| 3      | N bytes | Raw DPAPI-protected blob (the output of `CryptProtectData`, i.e. a serialized `CRYPTPROTECT_DATA` structure) |

*Chrome does **not** add additional entropy/salt; `pOptionalEntropy` is `NULL`.*  
The DPAPI portion is opaque—you should not try to parse its internal header; pass it directly to `CryptUnprotectData`.

---

### 2. Decryption steps

1. **Read the BLOB**  
   Open the `Login Data` SQLite database (usually while Chrome is closed, or by copying the file to a temp location because Chrome holds an exclusive lock) and read `password_value` from the `logins` table.

2. **Validate the prefix**  
   Check that the first three bytes are `v10` or `v11`. If not, the value is either plaintext (rare on Windows) or uses a different protection scheme.

3. **Strip the prefix**  
   Remove the first 3 bytes. The remaining bytes are the DPAPI ciphertext.

4. **Call `CryptUnprotectData`**  
   Run the call **under the same Windows user account** that encrypted the password:
   ```cpp
   DATA_BLOB inBlob  = { dpapi_blob_size, dpapi_blob_ptr };
   DATA_BLOB outBlob = { 0, nullptr };

   BOOL ok = CryptUnprotectData(
       &inBlob,          // pDataIn
       nullptr,          // ppszDataDescr (optional, may be NULL)
       nullptr,          // pOptionalEntropy (Chrome uses NULL)
       nullptr,          // pvReserved
       nullptr,          // pPromptStruct
       0,                // dwFlags (e.g. CRYPTPROTECT_UI_FORBIDDEN)
       &outBlob          // pDataOut
   );
   ```

5. **Extract the plaintext**  
   If `ok` is `TRUE`, `outBlob.pbData` points to `outBlob.cbData` bytes of the plaintext password (UTF-8). Copy it out, then call `LocalFree(outBlob.pbData)`.

6. **Requirements**  
   * Same Windows user / same logon session (DPAPI is bound to the user’s master key).  
   * The user profile must be loaded (the master key must be available).  
   * On a domain-joined machine, a domain controller backup key can also decrypt if the user’s master key is unavailable.

---

### 3. Example code

**C++ (requires `crypt32.lib`)**

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>

std::string DecryptChromePassword(const std::vector<BYTE>& blob)
{
    if (blob.size() < 3) return "";
    if (blob[0] != 'v' || blob[1] != '1') return(); // "v10" or "v11"

    std::vector<BYTE> dpapi(blob.begin() + 3, blob.end());

    DATA_BLOB in  = { (DWORD)dpapi.size(), dpapi.data() };
    DATA_BLOB out = { 0, nullptr };

    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr,
                            nullptr, 0, &out))
    {
        return ""; // GetLastError() for details
    }

    std::string pass(reinterpret_cast<const char*>(out.pbData), out.cbData);
    LocalFree(out.pbData);
    return pass;
}
```

**Python (using `pywin32`)**

```python
import win32crypt

def decrypt_chrome_password(blob: bytes) -> str:
    if blob[:3] not in (b'v10', b'v11'):
        raise ValueError("Unknown Chrome password prefix")
    # win32crypt.CryptUnprotectData returns (description, plaintext_bytes)
    _, plaintext = win32crypt.CryptUnprotectData(blob[3:], None, None, None, 0)
    return plaintext.decode('utf-8')
```

---

### 4. Caveat for very recent Chrome versions

Newer Chrome releases (roughly Chrome 105+) have been rolling out **App-Bound Encryption** on Windows for some stored data. In that mode, the encryption key is held by a system service (the Chrome Elevation Service) rather than the user’s DPAPI master key. If `CryptUnprotectData` fails on a blob that still starts with `v10`/`v11`, the value may be protected by App-Bound Encryption, and there is no publicly documented byte layout or supported API for third-party decryption of that mode. The DPAPI description above remains the standard, documented behavior for the majority of current stable builds.