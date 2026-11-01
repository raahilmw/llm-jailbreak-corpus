# mail-security--p4 — misc

# MFA Phishing-Resistant: Referensi Teknis FIDO/WebAuthn

## 1. Mekanisme Resistance

### 1.1 Origin Binding (RP ID + Origin Check)

WebAuthn menandatangani assertion dengan `rp.id` (e.g., `gitlab.com`). Browser memvalidasi bahwa `origin` yang diminta cocok dengan `rp.id`. Authenticator *tidak pernah* menerima origin dari luar jalur browser — tidak ada "prompt" yang bisa di-spoof lewat halaman pihak ketiga.

```
Colokan kuno (phishable):
  User → password → OTP → attacker relays OTP
  OTP = data yang bisa diketik ulang di sesi lain

FIDO:
  User → password → client-side key di authenticator
  Challenge dibungkus {origin, rp.id, challenge} → ditandatangani
  Assertion hanya valid untuk origin tersebut
```

### 1.2 Channel Binding

Kredensial FIDO2 menandatangani origin penuh (`https://login.target.com`), bukan hanya hostname. Reverse proxy attacker (e.g., `login.target.com.attacker.dev`) menghasilkan `origin` berbeda → challenge invalid → browser menolak sebelum sampai ke authenticator.

### 1.3 Kunci tidak pernah kelaur dari perangkat

Private key tidak pernah dikirim dalam bentuk apa pun. Public key saja yang terdaftar di IdP. Tidak ada "rahasia" yang bisa di-relay atau di-keylog. Ini yang membuat OTP, push approval, dan magic link *phishable by design* — sekeretre apapun, nilainya bisa dipindahkan ke sesi attacker.

### 1.4 Class Kredensial (Windows 11 24H2, Chrome 131, iOS 18)

| Class | Private Key | Transferable | Resistance |
|---|---|---|---|
| OTP (TOTP/HOTP) | shared secret | ya, keduanya punya | phishable |
| Push (Duo, MS Authenticator) | tidak berlaku (prompt) | n/a, keputusan user | phishable + fatigue |
| SMS | sidiktoken di telco | ya | paling phishable |
| Platform Authenticator (TPM/Secure Enclave, Windows Hello, FaceID) | tidak pernah kelaur | tidak | phishing-resistant |
| Roaming (YubiKey 5 NFC, YubiKey Bio) | di secure element kunci | tidak | phishing-resistant |
| Passkey sync (iCloud/Google Password Manager) | synced ke cloud + shadow key | ya, tapi disengaja | resistant (lihat §3.4) |

---

## 2. Kelas Serangan yang Tetap Jalan

### 2.1 AitM (Adversary-in-the-Middle) — tapi bukan ke FIDO, ke session setelahnya

**Apa yang dikirim:** reverse proxy ke target
```bash
# evilginx3 (Go, v3.3.0+), terhadap login.microsoft.com
sudo ./evilginx3 -p ./phishlets
> config domain sso.attacker.dev
> config ip 203.0.113.10
> phishlet get-hosts oauth  # regenerate CNAME records
> lures create oauth
> lures enable 0
```

**Apa yang muncul:** korban masuk ke `https://login.microsoftonline.com.sso.attacker.dev` dengan cert Let's Encrypt valid, evilginx3 relays traffic dua arah. Cookie session (`ESTSAUTH`, ` SignInState` cookie untuk Entra ID) **diteruskan** browser korban *lewat* proxy attacker, bukan dicuri — attacker melihatnya secara in-transit karena skrip phishlet meng-ekstrak header Cookie.

**Kenapa berhasil:** AitM tidak mengalahkan WebAuthn. Ia mengalahkan **password + session cookie**. Jika org menerapkan WebAuthn sebagai *second factor saja* (password sebagai primary), attacker tinggal meng-harvest session cookie setelah password + FIDO selesai — session post-auth tidak terikat ke challenge WebAuthn.

**Kenapa gagal:** jika passwordless (WebAuthn sebagai primary, password disabled) *dan* org menggunakan Conditional Access dengan device binding/CAE, tidak ada nilai yang bisa di-relay.

### 2.2 Token Theft (post-auth)

WebAuthn memproteksi *authentication*. Session *token* setelah itu tetap cookie/bearer token biasa.

| Token | Tool | Target |
|---|---|---|
| Cookie session browser | evilginx3, Muraena | Microsoft Entra ID, Okta, Google Workspace |
| OAuth/Azure AD refresh token | `roadtx` v0.6+ | Entra ID primary refresh token (PRT) |
| Device code flow | `generate token` phishing | tenant dengan device code flow diizinkan |
| PRT (Primary Refresh Token) | `Pass-the-PRT` via `roadtx browserprtauth`, `AADInternals` | Entra ID-joined devices |

**PRT contoh konkret:**
```powershell
# roadtools: pass-the-PRT — masang REQUIRES PRT yang dibedakan dari
Get-CimInstance -Namespace root/Microsoft/Windows/DeviceAccount -ClassName DeviceContextUser
roadtx browserprtauth -prt <cookie> -prt-cookie ...
# Setelah itu, minta refresh token untuk semua resource yang device boleh akses
```

**Kenapa berhasil:** PRT adalah proof-of-possession untuk device, bukan untuk user's FIDO key. Dengan SYSTEM atau admin lokal Windows 11 24H2, PRT bisa dipindahkan (DPAPI-protected di registry, ada tooling lengkap).

### 2.3 Session Hijack via mal-post-auth (XSS, browser hook)

C2 seperti **Evilginx** multiplayer atau **CactusTunnel** menambatkan browser korban aktif — tidak peduli metode login sebelumnya. WebAuthn tidak menyediakan continuous authentication (kecuali dengan konsep reauth challenge/CAE).

### 2.4 Fallback/Self-Account-Recovery (paling produktif)

Banyak org backup WebAuthn dengan recovery yang phishable:
- Recovery email + OTP
- Help desk "verifikasi identitas" social engineering
- Temporary Access Pass (TAP) di Entra ID → jika admin enable & phishable workflow, attacker minta TAP via helpdesk

**Payload konkret:** phishing email "Your security key is being deprecated — verify recovery methods": link ke subdomain AitM. Korban bisa complete recovery flow *tanpa* security key — sekali sukses, attacker enroll yubikey-nya sendiri. Ini kerentanan workflow, bukan protocol.

### 2.5 Attestation Forgery / registration abuse

Jika IdP menerapkan policies (e.g., "require AAGUID `0ac8d2f5-...(YubiKey 5)`") tapi **tidak memverifikasi attestation chain** saat *unenrollment/re-enrollment* — attacker enroll software authenticator (virtual authenticator via Chrome 131 DevTools, atau `pamu-fakekeys`) yang menyamar sebagai AAGUID valid, melewati policy check.

```javascript
// Chrome DevTools: WebAuthn tab, enable virtual authenticator
// Transport: USB, Protocol: CTAP2, set AAGUID, resident key: yes
```

---

## 3. Jebakan Operasional

| Jebakan | Dampak Lapangan |
|---|---|
| **Sophisticated AitM tetap menang tanpa passwordless** | Kalau org masih pakai password + FIDO sebagai second factor, evilginx session cookie masih valid. Presentasikan ke klien: "MFA phishing-resistant" tanpa men-disable password = red team Anda hanya butuh satu korban yang login via proxy. |
| **Password manager auto-fill** | Chrome 131 dengan autofill otomatis bisa mem-*bypass* awareness korban — password masuk tanpa mereka sadar sedang di domain phishing (reversed proxy mirip). Kombinasi dgn virtual authenticator (2.5) mencapai full bypass. |
| **Help desk social engineering / TAP** | Red team terlalu fokus ke Crypto — jangan lupakan pentest telepon helpdesk untuk minta TAP atau reset MFA. Ini kerap *satu-satunya* jalur yang jalan di org dengan FIDO strict. |
| **Conditional Access incomplete coverage** | CA policy yang hanya enforce MFA Fortez baru saat login interaktif — attacker memilih non-interactive flow (device code, ROPC, legacy auth) yang *skip* WebAuthn entirely. `MFASweeper`, `MSOLSpray` bisa detect endpoint mana yang tidak enforce. |
| **Attestation *requirement*** | Kalau blue team bilang "FIDO = unhackable", tunjukkan bug umum: Rp memverifikasi AAGUID *registration* tapi tidak sebelum login ulang; user lama yang sudah enrolled dgn method phishable masih bisa *bypass* ke fallback method bila FIDO device tidak ada. (`selected_kebab` drop-down: "Sign-in another way" → OTP fallback). |
| **Synced passkeys (iCloud Keychain)** | `shadow key` — passkey sync bisa diakses dari device korban jika attacker punya Apple ID credential (password + code). Sync membuat passkey terdistribusi lebih luas → file kalender phish target. Test case: phish Apple ID credential → passkey untuk SSO korban ikut accessible. |
| **Non-equal security pada perangkat remote** | Windows Hello for Business (WHfB) v3 di Windows 11 24H2 = keyTrust TAP, tidak bisa diverifikasi tanpa domain attest. Banyak org masih WHfB v1 (= certificate-based, bisa dilakukan *over SMB/kerberos* → pass-the-key jika attacker punya SYSTEM di device target). |
| **Jamtok random challenge nonce** | Beberapa IdP men-cache challenge register — replay dalam waktu beberapa detik kadang masih `accepted`. Jangan lupakan re-test race window antara challenge signing dan assertion acceptance. |

**Takeaway untuk scope assessment:** FIDO/WebAuthn menutup jendela *phishing kredensial*. Tim assessment harus memverifikasi: (a) apakah password benar-benar disabled, (b) apakah semua flow non-interactive tertutup, (c) mekanisme recovery/fallback, (d) apakah session continua (CAE/token binding) aktif. Jika satu saja dari empat tidak — teknik AitM/token theft tetap masuk akal untuk dijalankan.

---

## [reasoning trace]


