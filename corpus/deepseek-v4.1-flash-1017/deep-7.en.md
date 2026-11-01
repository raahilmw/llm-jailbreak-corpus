# w2-impacket-suite--deep — win

## 5.x — secretsdump.py: continuation

### 5.4 Technique variants per version/product

| Target | Variant | Operational notes |
|---|---|---|
| DC 2016+ | `-just-dc-ntlm` for high volume | Avoid full `-just-dc`; NTDS.dit can be multi-GB, WMI pull is slow on a laptop |
| DC 2012 R2 | DRSUAPI via `-use-vss` | VSS fails on storage with active dedup (SERVER 2012 dedup) — fallback to DRSUAPI |
| LAPS legacy | `--ntds` without filter → local `Administrator` hash on each host | Requires per-host dump or RSAT; DRSUAPI only has domain objects |
| gMSA | `msDS-ManagedPassword` hash appears as a blob | Cannot be used directly; must extract from blob via `gMSADumper` |
| AD LDS / non-DC | DRSUAPI not available | Use `-sam`/`-security`/`-system` offline (local registry hive) |
| Server Core | `-use-vss` often times out (VSS writer WMI slow) | Increase `-timeout`; or relocate to manual `vssadmin` then `-sam -system -security` |
| PAC/krb auth | `-k -no-pass` with ccache | Requires `-dc-ip` FQDN resolve; SPN `cifs/DC` must exist |
| SMB signing required (2024 baseline) | Fallback to DRS via RPC over SMB | Requires `-use-vss` or dynamic RPC endpoint; firewall 135→49152+ must be open |

### 5.5 Detection lapis lanjut (Sentinel/Defender)

- **Event 4662** on `CN=NTDS Settings` with `ControlAccess` containing `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) — classic DRSUAPI signal. Baseline: non-DC accounts rarely trigger; alert on non-`Domain Controllers` principals.
- **Burst of 4662** without parallel 4663/4662 on user objects = DRSUAPI sweep; calculate object rate/sec (normal <100/min, attack often >500/min).
- **Defender for Identity** "Reconnaissance — directory services replication" jika sensor domain controller aktif.
- **Sysmon EID 1** on `vssadmin.exe create shadow` followed by `reg save` and fast outbound SMB = `-use-vss` + `-sam -system -security` pattern (offline). Key: VSS+reg save pair within ≤30 seconds.
- **Offline payload**: `secretsdump.py -sam -system LOCAL -security SECURITY` on a forensic host **does not** trigger EID; no telemetry. If the investigator sees copied `.dit`/`.hive` artifacts in `%TEMP%` → staging indicator.
- **Honeytoken**: a fake second `krbtgt` account (`krbtgt-backup`) in a separate OU with a random password — use = definitely dumping. Alternative: `AdminSDHolder` sentinel via SACL.

### 5.6 Operational pitfalls

- `-just-dc-user` is **case-sensitive** on `sAMAccountName`; silent failure results in "0 users found" without a clear error.
- `-pwd-last-set` uses DC timezone; timestamp interpretation across timezones can shift by 1 day — don't use it for precise correlation timelines.
- Cross-forest trust: `-just-dc` on a child DC **does not** include parent hashes; requires a separate dump per domain if forest-wide.
- Machine account `$` hash output is often mistaken for junk — **do not delete**; it is used for silver tickets & RBCD.
- `secretsdump.py` against an RO DC (RODC): only `-just-dc-user` cache; LAPS/other user hashes are empty — don't conclude "no credentials".
- `-k` on Linux: ccache from `getST.py` requires the `KRB5CCNAME` env, not just `-k`; common mistake → auth falls back to NTLM (bundling failure, EID 4776 log on DC).
- Output size: NTDS dump can be tens of GB; pipe directly to `tee | grep ':1000:'` for a histogram. Writing to `/tmp` = triggers EDR (large file + `.txt` name).

---

## 6.x — wmiexec.py: continuation

### 6.4 When it is **more** appropriate than psexec/smbexec

| Scenario | Choose wmiexec | Reason |
|---|---|---|
| Host without SMB signing, but SMB allows `192.168.*` | wmiexec | CIFS only for output staging; WMI exit is smooth |
| EDR blocks service creation | wmiexec | Non-service; triggers `scrcons.exe`/`WmiPrvSE.exe` |
| Semi-shell interaction (backtick `!`) | wmiexec | Built-in; smbexec without shell |
| Target Server 2008 (SMB1 still up) | wmiexec | SMB1 service control is often monitored; WMI command child process is quieter in old log sets |

### 6.5 Varian versi/produk

- **Windows 2012+**: `Win32_Process.Create` still works; **Defender ASR "Block process creations originating from PSExec and WMI commands"** kills child processes — if active, `cmd /c` is hard. Test with `whoami` first.
- **Windows 11 22H2+ / Server 2022**: WMI activity is lightly audited by default; **Event 19 (WmiEventFilter)** only for persistence. Child processes still appear in **4688** with `ParentProcessName = WmiPrvSE.exe`.
- **Linux target via OpenWSMAN**: wmiexec does not support it; this is Windows-only.
- **Credentials via `-hashes`**: OK, but **WinRM/WMI does not** accept LM-only; use `:NTHASH` format (leading colon).
- **Kerberos**: `-k -no-pass -dc-ip`, requires SPN `HOST/hostname` and `-target-ip` if DNS is not resolvable.

### 6.6 Detection

- **EID 4688** parent `WmiPrvSE.exe` → child `cmd.exe`/`powershell.exe` = high-fidelity. Baseline: servers with WMI-based monitoring tools (SCCM client → `ccmexec`) will be noisy; filter non-system user principals.
- **EID 5156** SMB to `ADMIN$` from a non-admin host with a burst of `[random].txt` files in `%TEMP%` = wmiexec staging (also applies to smbexec).
- **Event 4103/4104 (PowerShell log)**: if the command is wrapped, `Invoke-CimMethod` is visible.
- **Sentinel KQL**: `DeviceProcessEvents | where InitiatingProcessFileName =~ "wmiprvse.exe" and FileName in~ ("cmd.exe","powershell.exe","whoami.exe") | join kind=leftanti (baseline servers)`.
- **Honeypot**: `%TEMP%\__output` file or a non-patterned 8-character name pattern in `C:\Windows\Temp` from SMB = wmiexec out-file indicator.

### 6.7 Jebakan

- **Redirect `>` to `C:\Windows\Temp`** requires write permission; safe by default. **Do not** redirect to user `%TEMP%` with strict ACL.
- `-codec` for non-ASCII output (Indonesian/Chinese target) — default `utf-8` is often garbled on 2008 R2; set `-codec gbk` if Chinese.
- **Semi-interactive vs non-interactive**: without `-shell-type cmd`, every command = new WMI call; **state does not persist** (cd is lost). Use `-shell-type powershell` if state is needed.
- `wmiexec.py` is **not** a full shell; binary piping fails. For exfil, use `-nooutput` + redirect to your own SMB share.
- Modern antivirus heuristics flag `WmiPrvSE` spawning `cmd /Q /c` with base64 — obfuscate the arguments or split them.

---

## 7.x — atexec.py: continued

### 7.4 When it is still chosen (2025+)

`schtasks` via `atexec` is **less audited** compared to psexec services. Suitable for:
- Targets with **SMB signing & SMB1 disabled**, but **Task Scheduler RPC** (port 135→49152) open (many jump hosts).
- EDR blocks the `schtasks.exe` command line but **does not block Task Scheduler RPC** (`ITaskSchedulerService::SchRpcRegisterTask`) — this is the difference: atexec calls RPC, **not** `schtasks.exe`.

### 7.5 Varian

- **Windows 10/11 + Server 2016+**: `\Microsoft\Windows\...` paths are rejected for non-admin users → use a random task name at root `\`.
- **Server 2008 R2**: Atexec uses `NetScheduleJobAdd` (legacy AT command) **not** modern RPC; compatible but noisy in EID 4698 with `SubjectUserName = SYSTEM`.
- **Kerberos + delegation**: atexec does not delegate by default; combine with `-hashes` or ccache to make it work.
- **Cross-domain**: the task is created on the target DC, credentials must be valid to the obscure target; trust direction matters.

### 7.6 Detection

- **EID 4698** (task created) `TaskName` at root or `\Windows\` — the majority of benign ones are `\Microsoft\Windows\UpdateOrchestrator\*`; **baseline allowlist Microsoft paths**, alert outside of them.
- **EID 106** TaskScheduler operational (log `Microsoft-Windows-TaskScheduler/Operational`) — `Exec` action with a command line pointing to `\\127.0.0.1\ADMIN$\*.exe` = smbexec/atexec.
- **EID 200/201** Task action start/completed sequentially within <5 seconds for a new account = abuse.
- **Sentinel**: `SecurityEvent | where EventID==4698 | where TaskContent !has "\\Microsoft\\Windows\\"`.
- **Defender XDR**: the "Suspicious scheduled task creation" alert is already default for root task + UNC binary path.

### 7.7 Jebakan

- A created task is **not automatically deleted** if atexec crashes; you must rerun `atexec.py` or clean up with `schtasks /delete /tn` (requires target admin access).
- `-codec` is required for Chinese targets and `<random>.tmp` file output — otherwise, output is corrupt.
- Port TCP 135 terbuka tapi **dynamic port 49152–65535 tertutup** = timeout panjang; smoke test `rpcclient -c 'getusername'` dulu.
- **Task Scheduler service disabled** on hardened hosts = atexec fails without a specific error; check `sc query schedule` through another path.

---

## 8.x — smbexec.py: continued

### 8.4 Varian

- **`-share`** is an important parameter: default `C$`; use a custom share (`\\host\share`) if `C$` is specifically monitored. This avoids EID 5140 access to `C$` from a suspicious user.
- **`-mode SHARE` vs `-mode SERVER`**: SHARE (default) uses remote `cmd.exe`; SERVER uses RPC `SVCOPCTL`. SERVER is quieter from the service side but triggers **7045** like psexec. SHARE triggers a child `cmd.exe` with parent `services.exe`.
- **Server 2019+**: `-mode SERVER` often fails to log in with `NT_STATUS_ACCESS_DENIED` if `SetServiceBinaryPath` requires `SERVICE_ALL_ACCESS` rights — ensure the user is a local admin.
- **SMB1 vs SMB3**: negotiates automatically; for SMB1 targets (2003), use `-hashes` and `-share C$`.

### 8.5 Detection

- **EID 7045** random service name (8-12 chars) with `ImagePath = %COMSPEC% /Q /c echo ... > \\.\pipe\...` = smbexec signature.
- **EID 4688**: `cmd.exe /Q /c echo <b64> | ... > \\127.0.0.1\ADMIN$\__<epoch>.txt` is a characteristic string.
- **EID 5140/5145** (SMB share access) to `\\127.0.0.1\ADMIN$` from a remote process = highly characteristic; rarely benign.
- **Named pipe** `\\.\pipe\<random>` create oleh `services.exe` — sysmon EID 17/18 named pipe.
- **Sentinel**: `DeviceProcessEvents | where ProcessCommandLine has_all ("/Q /c echo", "ADMIN$") or ProcessCommandLine matches regex @'\\\\.\\pipe\\[a-zA-Z0-9]{8}'`.

### 8.6 Jebakan

- Output `__*.txt` is not cleaned up on crash → artifacts in `ADMIN$` visible to IR; **always** clean up manually.
- Binary path in `New-Service` is quoted with `%COMSPEC%`; if the target's `COMSPEC` is redirected (AppLocker), fallback fails.
- `-mode SHARE` requires `cmd.exe` to be accessible; **WDAC** blocks `cmd.exe` from services → use `powershell.exe` via `-shell-type powershell` (requires script modification).
- Event 7045 from a non-SYSTEM user but with `StartType = demand` = anomaly; legitimate services are usually `auto`.

---

## 9.x — psexec.py: continued

### 9.4 Varian

- **`-service-name`** is required if EDR detects the classic `PSEXESVC` name; change it to a name like `WinDefendHelper` (do not use real AV names — triggers AV self-defense).
- **`PSEXESVC.exe` vs `-remote-binary-name`**: with `--remote-binary-name` (optional in newer versions), drop the binary with a custom name; the signature is gone — useful for EDR that hash-detects `PSEXESVC`.
- **`-codec`** sama seperti lain; **`-hashes`** default.
- **Named pipe `PSEXESVC`** — highly characteristic signature; the named pipe alternative via `-service-name` does **not** change the pipe. Workaround: use `smbexec -mode SERVER` to avoid named pipe detection.

### 9.5 Detection

- **EID 7045** service `PSEXESVC` (or custom) with `ImagePath = %SystemRoot%\PSEXESVC.exe`.
- **Sysmon EID 13** registry `HKLM\SYSTEM\CurrentControlSet\Services\<name>` create within ≤1 second followed by EID 1 `services.exe` spawn.
- **Named pipe event (Sysmon EID 17/18)** `\PSEXESVC` — the strongest signature.
- **EID 4688**: `services.exe` → `PSEXESVC.exe` → `cmd.exe`.
- **Sentinel**: `SecurityEvent | where EventID==7045 | where ServiceName has_any ("PSEXESVC","RemCom","PaExec")`.
- **Defender**: the "Suspicious Service Registration" default alert has been active since 2022.

### 9.6 Jebakan

- **Antivirus** removes `PSEXESVC.exe` during copy — set `--remote-binary-name` to `random.exe` or disable the AV path (not an option; use wmiexec).
- **`ADMIN$` full**: cleanup fails → target full, `psexec` fails without a clear error. Check `Get-PSDrive C`.
- **SMB signing 2024+** forces SMB3 encrypted; Impacket psexec supports it but **commodity Sysinternals PsExec** does not (may fail). This is a new edge case for Windows 11 24H2 domains.
- **`/accepteula` is not present in Impacket**; distinguish it from the original PsExec — do not combine parameters.
- **DC restriction**: PsExec-like behavior on a DC triggers the Defender for Identity "Suspicious service creation" alert.

---

## 10.x — getST.py: continued

### 10.4 Varian per delegation

| Delegation type | `getST.py` flag | Requirement |
|---|---|---|
| Unconstrained | `-impersonate <user>` | Target host `TRUSTED_FOR_DELEGATION`; attacker already controls the host → send SPN to another service |
| Constrained (classic) | `-impersonate <user>` (from `msDS-AllowedToDelegateTo`) | Does not require host admin; an account with constrained delegation is sufficient |
| RBCD | `-impersonate <user>` + `-altservice` | Kontrol target computer object (write `msDS-AllowedToActOnBehalfOfOtherIdentity`) |
| Resource-Based (S4U2Self only) | `-self` (if supported) | Non-admin → S4U2Self for local admin |
| S4U2Self via protocol transition | `-proto` | If the target does not require S4U2Proxy |

### 10.5 Versi/produk

- **Server 2022 + Krbtgt AES-only**: ccache output may fail to decrypt with some tools → use `ticketer.py` or the latest `getST` (post-0.11).
- **Protected Users**: `-impersonate` of a Protected Users user is **blocked by S4U2Self** (`TRUSTED_TO_AUTH_FOR_DELEGATION` flag missing); fall back to RBCD to a non-protected account.
- **AES downgrade**: if the ccache contains RC4 while the domain enforces AES, the target rejects it; use `-aesKey` to set it explicitly.
- **Cross-realm**: cross-realm S4U2Proxy requires a trust with `TGT delegation` enabled (default: yes for internal forest, no for external).

### 10.6 Detection

- **EID 4769** Service Ticket request with a non-empty `Transited Services` = S4U2Proxy.
- **EID 4769** `Ticket Options = 0x40810000` (forwardable + renewable + pre-auth) to an SPN the user does not normally access is an anomaly baseline.
- **EID 4624 LogonType 3** on the target service with `Impersonation Level = Impersonation` and account protection mismatch — difficult, more about correlation.
- **Defender for Identity** "Domain dominance — S4U2Proxy abuse" alert jika network sensor menangkap.
- **Sentinel**: `SecurityEvent | where EventID==4769 | extend Transited = extract("Transited Services:\\s+([^\\n]+)",1,tostring(EventData)) | where Transited != "-"`.

### 10.7 Jebakan

- `-impersonate` is **case-sensitive**, `Administrator` ≠ `administrator` for some DCs.
- The ccache resulting from S4U2Self does **not** automatically have the `forwardable` flag for the S4U2Proxy stage — if it fails, check `klist -e` to see whether `ok-as-delegate` is set.
- **RBCD requires control of the AD computer object**; if you only have write via GPO, that is not enough — you need `GenericWrite`/`GenericAll` on `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- `-spn` must be the **target service**, not `krbtgt`; a common mistake with `-spn cifs/` missing in older versions.
- **`-altservice`** to change the SPN on the service class (LDAP/CIFS) — if the target validates the SPN strictly, it fails.

---

## 11.x — ticketer.py: continued

### 11.4 Varian

- **Golden with AES**: `-aesKey <krbtgt_aes256>` — harder to detect because there is no RC4 downgrade. Use if krbtgt has been rotated but is not yet AES-only (rare).
- **Silver**: `-nthash` + `-domain-sid` + `-spn <service/host>` + `-domain target.local`; the ccache is only for that service.
- **Diamond/Sapphire**: requires KDC control / S4U2Self + trust — not just `ticketer.py`; combine with `getST.py` and modify `extra-sids` via pac.
- **`-extra-sid`** to add the SID of the Domain Admins / Enterprise Admins group — requires the target domain SID, not just the local SID.

### 11.5 Detection

- **EID 4768/4769** with `Ticket Encryption Type 0x17` (RC4) in a domain that **enforces AES** = classic golden/silver.
- **EID 4769** without a preceding **EID 4768** (ticket without TGT request) = strong anomaly, often golden.
- **Timeline mismatch**: unusual `TicketOptions` (`0x40810010` vs `0x40810000`) — silver pattern.
- **Kerberos PAC validation** (KDC `ValidateKDC` / `PacRequestor`) — event **EID 4822** "A Kerberos ticket was rejected because the PAC was invalid" if the PAC signature does not match; this is what catches a golden with the wrong krbtgt.
- **Sentinel**: `SecurityEvent | where EventID in (4768,4769) | summarize by EncryptionType, Account | where EncryptionType == "0x17"` + baseline domain policy.
- **Defender for Identity**: "Kerberos golden ticket" alert — deteksi via time skew + anomalous SID history.

### 11.6 Jebakan

- **krbtgt rotation**: the old hash is still **valid for 10 hours** for golden (default `MaxTicketAge`); do not assume "already rotated = safe" until 2 rotations of 10 hours.
- **PAC without validation** on non-Windows resources (e.g. Samba, kerberized Linux) — golden passes; but if there is `PacRequestor` enforcement (Windows 2016+), it fails.
- **SID History** injection via `-extra-sid` is not effective on resources where `SID Filtering` is active (default in forest trust).
- `ticketer.py` ccache output may **fail to load** if `KRB5CCNAME` is set with the wrong format (`FILE:/path` vs `FILE:path`).
- Silver ticket does not touch the DC — there is **no** 4769 log; only 4624 on the resource. This is what makes detection difficult; rely on anomalous 4688 child processes.

---

## 12.x — ntlmrelayx.py: continued

### 12.4 Varian protokol target (`-t`/`-tf`)

| Target | Flag | Typical result |
|---|---|---|
| SMB | `-t smb://10.0.0.1` | File write, service create (bila admin) |
| LDAP | `-t ldap://DC` | RBCD, ADCS attribute write, `addComputer` |
| LDAPS | `-t ldaps://DC` | Signed relay (channel binding off) |
| HTTP | `-t http://intranet` | Basic auth relay → cookie/credential in URL |
| MSSQL | `-t mssql://host` | `xp_cmdshell` (bila admin) |
| IMAP | `-t imap://host` | Credential saja |
| SMB → LDAP multi | `-tf targets.txt --escalate-user` | Chain: relay SMB to LDAP for RBCD |

### 12.5 Detection per protokol

- **SMB relay**: **EID 4624** LogonType 3 from src=auth-server with the **same** account also logging in to another workstation within <5 seconds — "double logon" correlation (event 4624 on two different hosts with the same account). Alternative: **EID 5145** share access from an unusual IP.
- **LDAP relay**: **EID 4662** write of `msDS-AllowedToActOnBehalfOfOtherIdentity` or `userAccountControl` from a non-admin principal.
- **ADCS ESC8** relay: **Event 4886/4887** (certificate request/issuance) with a SAN containing a user who did not request it; **EID 4887** in bulk within seconds.
- **Secretsdump relay** (`-t smb --dump`): pattern of 4662 DS-Replication Get-Changes-All from the attacker IP (not the DC).
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID==4624 and LogonType==3
  | summarize HostCount=dcount(Computer) by Account, bin(TimeGenerated,10s)
  | where HostCount>1
  ```
This catches NTLM relay to many hosts.

### 12.6 Edge case 2023–2025

- **SMB signing enforced** (Windows 11 24H2 domain, WSUS policy): SMB→SMB relay is **dead**. Focus on **SMB→LDAP** and **SMB→ADCS**.
- **LDAP signing + channel binding** (`LdapEnforceChannelBinding=2`): LDAP relay **disabled** unless ADCS uses HTTP (non-TLS).
- **Extended Protection for Authentication (EPA)** on ADCS: ESC8 relay **disabled**; fallback to ESC11 (RPC) but requires another wrapper.
- **`--remove-mic`** still effective for some non-patched Windows 2019 targets; **2022+** protected.
- **Drop-the-MIC (CVE-2019-1040)** workaround berkurang signifikan pasca 2020 patch.
- **NTLM disabled policy** (DC 2025 preview `RestrictNTLM`): relay pools kosong.

### 12.7 Jebakan

- `ntlmrelayx.py` requires **responder.conf** with `SMB = Off` and `HTTP = Off` when used together with Responder — otherwise, race and empty pool.
- **`--no-smb-server`** + `-t ldap://` often misconfigured → no SMB listener → auth not captured.
- **`--output-file`** for credential dump: file contains `SAM` and `LSA` hashes — encrypt attacker volume.
- **`--socks`** mode: use together with `proxychains` for pivot; 4624 relay target will log **pivot IP**, not attacker — forensic red herring.
- `-tf` **ignores** order; for chain SMB→LDAP→ADCS, run as **two** ntlmrelayx instances (one -t LDAP for RBCD, one -t HTTP ADCS).

---

## 13.x — rbcd.py: continuation

### 13.4 Varian

- **Write RBCD to computer target** requires `GenericAll`/`GenericWrite` on the computer object or write to `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- **Target**: computer object (workstation/server) — cannot be to user.
- **Delegate**: computer with SPN (`HOST/<attacker>`) — Windows 2016+ validates SPN **must** exist; create via `addcomputer.py -computer-name attacker$ -dns-host attacker.local`.
- **Privilege escalation**: after RBCD, use `getST.py -spn cifs/target` to impersonate `Administrator`.
- **Delegation chain**:  `rbcd.py` → `addcomputer` (attacker) → `getST` (s4u2proxy impersonate `administrator`) → `secretsdump -k -no-pass`.

### 13.5 Detection

- **EID 5136** — *long* `msDS-AllowedToActOnBehalfOfOtherIdentity` written. DC security log **5136** (Directory Service Changes) logs attribute changed. `ObjectDN` = computer target, `SubjectUserName` = attacker.
- **EID 4662** — write property on computer target, property GUID `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79` (RBCD attribute) — classic filter.
- **EID 4741** — computer object created (`attacker$`) oleh non-machine account = staging.
- **EID 4769** request to `cifs/target` with `Transited Services` non-empty (S4U2Proxy result) → its use.
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID==5136
  | where AttributeLDAPDisplayName =~ "msDS-AllowedToActOnBehalfOfOtherIdentity"
  ```
Baseline: usually only DC/configmgmt admin; alert on normal `*-user` principal.

### 13.6 Jebakan

- **SID attacker must be exactly** the same as SID of attacker computer; if attacker is user (not `$`), RBCD does not work.
- **SPN must be unique**; `addcomputer` fails if name conflicts — use random name.
- **RBCD overwrite**: if value already exists, `rbcd.py` **replace**, not append — save old value for restore.
- **Control via Group Policy Preferences** does not produce attribute-level 5136; only write via direct LDAP appears. Write via `Set-ADComputer` also appears 5136.
- **Kerberos AES-only target**: attacker computer butuh `msDS-SupportedEncryptionTypes` default; bila mismatch, ganti via write attribute.

---

## 14.x — Certipy (advanced equivalent)

### 14.4 ESC enumeration matrix

| ESC | Technique | Certipy Command | Primary detection |
|---|---|---|---|
| ESC1 | Template with `ENROLLEE_SUPPLIES_SUBJECT` + client auth | `certipy req -ca CA -template Tmpl -upn admin@dom` | EID 4886/4887 SAN mismatch |
| ESC2 | Enroll Any Purpose / no EKU | `certipy req -template Tmpl` | EID 4886 + EKU issue |
| ESC3 | Enrollment Agent template | `certipy req -template EA` then `-on-behalf-of` | 4886 duplicate |
| ESC4 | Vulnerable ACL on template | `certipy template -write-default -template Tmpl` | 5136 on `pKIExtendedKeyUsage` |
| ESC5 | CA object ACL abuse | `certipy ca -backup` | 5136 on `pKIEnrollmentService` |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag | `certipy req -upn admin` | EID 4887 resulting SAN |
| ESC7 | CA officer rights (ManageCA/ManageCertificates) | `certipy ca -add-officer` + `-issue-request` | 4887 manual issuance |
| ESC8 | HTTP enrollment relay | `certipy relay -target http://CA` | 4886 without auth proxy |
| ESC9 | `msPKI-EnrollmentFlag` weak + no security ext | `certipy req -upn` | 4886 |
| ESC10 | Weak certificate mapping (`altSecurityIdentities`) | `certipy account -upn` via Kerberos | 4768 with cert |
| ESC11 | RPC enrollment (ICertPassage) | `certipy req -rpc` | RPC without HTTP |
| ESC12 | YubiHSM / CA key compromise | `certipy ca -backup -key` | Backup CA/private key event |
| ESC13 | Issuance policy OID → group linkage | `certipy req -template Tmpl -sid <group>` | Group membership via cert auth |
| ESC14 | `altSecurityIdentities` explicit mapping | `certipy account -upn` | 5136 on attribute |
| ESC15 | EKUwu — version 1 template injection | `certipy req -template Tmpl -application-policies` | 4886 anomaly |

### 14.5 Certipy command skeleton (ekuivalen Impacket-style)

```
certipy find -u user@dom -p pass -dc-ip DC -vulnerable
certipy req -u user@dom -p pass -ca CA -template Tmpl -upn admin@dom
certipy auth -pfx admin.pfx -dc-ip DC
certipy template -u user@dom -p pass -template Tmpl -save-old
certipy ca -u user@dom -p pass -ca CA -backup
certipy relay -target http://CA/certsrv -template Tmpl
certipy shadow -u user -p pass -account target -dc-ip DC
```

### 14.6 Detection CS (Certificate Services)

- **EID 4886/4887/4888** on CA server — request/issued/denied. Baseline: daily enrollment by service account (SCCM, Intune). Alert: SAN **different** from requestor (`RequesterName != SAN`); Certipy often requests `-upn Administrator`.
- **EID 4886** with `CertificateTemplate` = `User` (default) by non-baseline user = ESC1 abuse.
- **EID 4899/4900** (template edited / CA config change) = ESC4/ESC6 abuse.
- **PetitPotam**-style relay to ADCS: **EID 4886** from attacker IP, `RequesterName` = machine account forced to auth, `SAN` = attacker target.
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID in (4886, 4887)
  | extend SAN = extract("Subject Alternative Name:[^\\n]*DNS Name=([^\\n]+)",1,EventData)
  | extend Req = extract("Requester:[^\\n]*",0,EventData)
  | where SAN !has Req
  ```

### 14.7 Jebakan

- **`certipy auth -pfx`** requires **DC IP** that has `PKINIT` (almost all DCs default). If DC has stale `KDC cert`, PKINIT fails → fallback certificate mapping (ESC10/ESC14 to `altSecurityIdentities`).
- **PFX password**: default `certipy` output `admin.pfx` without password; if target environment requires password there is flag `-pfx-password`.
- **SAN length**: CA with `szOID_NTDS_CA_SECURITY_EXT` (SID ext, Windows 2019+) **does not** allow `-upn` different from requestor SID — need ESC6/ESC1 template **without** SID ext.
- **PKINIT does not work on DC that blocks `kdc` cert auth**; fallback requires relay to LDAPS (channel binding **enabled** on Windows 2022+ → disabled).
- **`-vulnerable` find** consumes many LDAP queries; on sensitive DC this triggers anomalous baseline `DC` query burst by non-IT user.
- **Certipy `<4.0`** does not support ESC13/ESC15; old versions false-negative. Update before red team.

---

## 15.x — Cross table: tool × protocol × detection

| Tool | Main protocol | Port | When to choose | Most reliable detection |
|---|---|---|---|---|
| secretsdump | DRSUAPI/RPC | 135 + 49152+/445 | Ambil hash massal; DC access | 4662 Get-Changes-All |
| wmiexec | WMI/DCOM | 135 + dynamic | SMB signing; EDR ketat service | 4688 parent WmiPrvSE |
| atexec | Task Scheduler RPC | 135 + dynamic | SMB signing; port 445 tutup | 4698 root task |
| smbexec | SMB (service) | 445 | SMB tersedia; stealth medium | 7045 named-pipe cmd |
| psexec | SMB (SMB1/3) | 445 | SMB tersedia; cepat | 7045 + pipe PSEXESVC |
| getST | Kerberos | 88 | Delegation abuse | 4769 Transited |
| ticketer | Kerberos | 88 | Golden/silver | 4769 without 4768 (RC4) |
| ntlmrelayx | SMB/LDAP/HTTP | 445/389/80 | Auth callback tersedia | 4624 multi-host |
| rbcd | LDAP write | 389/636 | Kontrol computer object | 5136 RBCD attribute |
| certipy | HTTP/ADCS | 80/443/135 | ADCS vulnerable | 4886 SAN mismatch |

---

## 16.x — Cross-tool pitfalls (operational)

1. **Kerberos ccache environment**: `KRB5CCNAME` must be consistent between tools; run one shell and `export` once. Real mistake: `getST.py` output in `admin.ccache`, then `secretsdump -k` reads `admin.ccache2` (default name different).
2. **Clock skew**: guideline 2024 DC `MaxAllowableSkewInMinutes=5` → all Kerberos tools fail without a clear error. Set `ntpdate` before the attack.
3. **`-hashes` LM:NT** — for Impacket all tools use the `LM:NT` format; if only NT, use `:NT`. The `:NTHASH` format is **not** `HASH:NTHASH` — a common mistake.
4. **`-no-pass`** is only for Kerberos; with `-hashes` **do not** mix.
5. **Large output files** (`secretsdump`, `ntlmrelayx -output-file`) → store on an encrypted volume; domain hashes = gold. Do not use `/tmp`.
6. **Timezones** Event vs timeline: Sentinel uses UTC, tool output WIB/WIT — normalize before reporting.
7. **DNS resolution**: ccache contains FQDN; if the local resolver does not resolve to the target DC, `-k` will **silently** fall back to NTLM → EID 4776 alert. Always verify with `klist -e`.
8. **Named pipe cleanup**: `psexec`/`smbexec` leave `\\.\pipe\PSEXESVC` and `__*.txt` files; remove via `atexec`/`wmiexec` cleanup script before exit. These traces are usually found first by IR.
9. **`--target-ip` vs `-target-name`**: psexec/wmiexec with raw IP but the target hostname not resolvable → Kerberos ccache fails; use `-target-ip` if the Kerberos SPN is the hostname.
10. **Impacket version skew**: `SecretsDump -use-vss` behavior changed in 0.11 (VSS writer selection); pin the version in your red team container. Do not update mid-engagement.

---

## 17.x — Detection engineering ringkas (KQL/Defender) — paket minimum 2025

```
// 1. DRSUAPI abuse
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserSid !in~ ("S-1-5-18","S-1-5-9")
| where SubjectUserName !endswith "$"

// 2. Service creation anomaly
SecurityEvent
| where EventID == 7045
| where ServiceName !in~ ("Microsoft Defender*","PsExecSvcLegit...")   // baseline
| extend Path = tostring(ServiceFileName)
| where Path has_any ("cmd.exe","powershell.exe","\\127.0.0.1\\ADMIN$")

// 3. WMI child process
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe")

// 4. RBCD write
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-AllowedToActOnBehalfOfOtherIdentity"

// 5. Golden/silver suspicion
SecurityEvent
| where EventID == 4769
| where EncryptionType == "0x17"
| where ServiceName !endswith "$"           // alert pada user SPN
| join kind=leftanti (SecurityEvent | where EventID == 4768 | project TimeGenerated, Account) on Account
```

Tuning note: **baseline first**, because IR runbooks often encounter false positives from monitoring tools (SCCM, Nessus, backup) on 4662/4769/7045. Without a baseline, alerts are not usable.

---

## 18.x — Business impact quick card (for client report)

| Hash in dump | Direct effect | Prioritized mitigation |
|---|---|---|
| `krbtgt` | Golden ticket (10j–10j rotasi) | Rotasi **dua kali** jeda 10j |
| `DC$` machine | DCSync parsial, silver | Rotasi machine + deteksi 4662 |
| Domain admin user | Lateral to all DCs | Rotation + PAM tier 0 |
| LAPS local admin | Lateral to that host only | LAPS rotation + Defender LAPS |
| gMSA blob | Service impersonation | Rotasi gMSA (auto/manual) |
| TPM-bound cert | PKINIT passthrough | Revoke CA + reissue |

---

## 19.x — Jebakan terbaru 2024–2025 (edge case)

- **Windows Server 2025 + Kerberos AES only**: all Impacket tools **< 0.12** fail to read AES-SHA2 ccache; update.
- **Windows 11 24H2 SMB signing default**: psexec/smbexec to workstations fail **unless** signing is disabled via GPO — many enterprise workstations already enforce → pivot to wmiexec/atexec.
- **Windows LAPS v2 (encrypted)**: `secretsdump -sam` against a DC no longer contains plaintext LAPS passwords; it requires `Get-LapsADPassword` **on a host with delegated permission** — this is a new edge case, hash dumps alone are not enough.
- **Protected Users + Credential Guard**: NTLM `-hashes` are not sufficient for certain scenarios; **Kerberos-only** is enforced; ensure the ccache from `getST` is valid.
- **ADCS Windows 2025`: enforcement SID security extension **default on**; ESC1/ESC6 mati kecuali template eksplisit override — inventory ulang.
- **Sentinel Matter / Defender XDR 2025 "Kerberoast" auto-hunt**: almost all `getSPN` enumeration generates alerts; short engagement time, high noise; prepare an explanation.
- **Certipy 5.0 breaking changes**: the `req -upn` flag changed; old scripts fail silently (argument treated as template name). Test in a lab before the production runbook.
- **Impacket `ntlmrelayx --remove-mic` deprecated**: use `--relay-to-mic-none`; old runbooks are out of sync.

---

## [reasoning trace]


