# re-dynamic — malware

# Dynamic Malware Analysis: Sandbox, Anti-Analysis, Unpacking, Injection Detection

## 1. Arsitektur Sandbox

### 1.1 Reference Topology

| Komponen | Produk/Versi | Peran | Jaringan |
|---|---|---|---|
| Host analyzer | Ubuntu 24.04 LTS, 16 vCPU / 32 GB RAM / NVMe 1 TB | Runs hypervisor, CAPE server, INetSim | NAT + host-only |
| Hypervisor | VMware Workstation Pro 17.5 / KVM (libvirt 10.0) | Eksekusi guest | host-only `vmnet1` |
| Guest Windows | Windows 11 24H2 (build 26100.1742) | Eksekusi sampel | host-only, DNS → INetSim |
| Guest Linux (opsional) | Ubuntu 22.04.4 LTS | Sampel ELF | host-only |
| Toolset | FLARE-VM 2024.11 (installer `install.ps1`) | Reverse engineering | offline |
| Sandbox orchestrator | CAPE v2 (CAPEv2 `2.4-stable`, commit `9c3f`) | Automatisasi, unpacking, config extraction | host |
| Network sim | INetSim 1.3.2 / FakeNet-NG 2.6 | Fake services (HTTP/DNS/SMTP/IRC) | host |
| Traffic capture | tcpdump 4.99.4 → PCAP per task | Forensik jaringan | bridge |

### 1.2 Checklist Build FLARE-VM (Windows 11 24H2)

```powershell
# Snapshot bersih dulu, baru install
Set-ExecutionPolicy Unrestricted -Force
# Boxstarter + Chocolatey install; butuh ~2 jam, ~60 GB
(New-Object net.webclient).DownloadFile(
  'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
  "$env:USERPROFILE\install.ps1")
Unblock-File "$env:USERPROFILE\install.ps1"
# Disable Defender realtime SEBELUM install (kalau tidak, puluhan tool diblok)
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
.\install.ps1 -noPassword -noRestart
```

Required post-install tools (verify present in `C:\Tools`): `x64dbg` 2024.11, `IDA Free 8.4`, `Ghidra 11.2`, `PE-bear 0.6.7`, `Process Hacker 2.39`, `Scylla 0.9.8`, `PE-sieve 0.3.9`, `HollowsHunter 0.2.8`, `API Monitor 2.0`, `Detect-It-Easy 3.10`.

### 1.3 Build CAPE v2

```bash
# Ubuntu 24.04, user non-root dengan sudo
git clone https://github.com/kevoreilly/CAPEv2.git && cd CAPEv2
sudo ./installer.sh  # pilih "standalone" + qemu-kvm atau virtualbox
# Konfigurasi jaringan guest
sudo ./kvm-qemu.sh all cape  # buat vmcloak guest Windows
# Verifikasi
sudo systemctl status cape
sudo -u cape /opt/CAPEv2/venv/bin/python cuckoo.py --help
sudo -u cape /opt/CAPEv2/venv/bin/python utils/process.py --help
```

Key configuration `conf/default.conf`:

```ini
[resultserver]
ip = 192.168.122.1

[processing]
# unpacker berbasis uc – sangat berguna untuk packer ringan
unpacker = yes

[auxiliary]
# ambil memori proses saat terminasi
enable_memory_dumps = yes
```

Submit:

```bash
cd /opt/CAPEv2
sudo -u cape ./venv/bin/python utils/submit.py --platform windows \
  --options free=yes,procmemdump=1,route=none /path/sample.exe
```

### 1.4 Step-by-Step Workflow (Baseline)

1. **Clean snapshot** of the Windows guest before each sample (`vmrun snapshot vm-win11 clean`).
2. **Baseline capture**: jalankan `tcpdump -i vmnet1 -w base.pcap` 60 detik kosong.
3. **Run prologue**: `Procmon` filter `Operation is Process/Thread/Image`, `RegSetValue`, `CreateFile`; `API Monitor` attach to `explorer.exe`; `Wireshark` on `vmnet1`; `x64dbg` (attached) for the sample.
4. **Execute the sample** with realistic arguments (`--install`, path in `%APPDATA%`).
5. **Ambil artefak**: memory dump (`procdump -ma PID out.dmp`), `pe-sieve /pid PID /out dumps/`, `HollowsHunter /pid PID /out hs/`, PCAP, Procmon PML, `autoruns -a autoruns.csv`.
6. **Rekonstruksi & dokumentasi** → IOC, TTP (ATT&CK), YARA.
7. **Rollback snapshot**.

---

## 2. Anti-Analysis

### 2.1 IsDebuggerPresent / CheckRemoteDebuggerPresent

**What is sent:** calls to `kernel32!IsDebuggerPresent` (reads `PEB.BeingDebugged`) or `CheckRemoteDebuggerPresent(hProcess, &b)` (→ `NtQueryInformationProcess` `ProcessDebugPort`).

**What appears:** Returns `1` if a debugger is active. In default x64dbg, `IsDebuggerPresent` is hooked to return 0, so the sample passes — but `CheckRemoteDebuggerPresent` usually **bypasses** the default hook because the path is different.

**Why it succeeds/fails:**
- Userland hook (`IsDebuggerPresent`) is easy to patch, but easy to detect via **prologue checksum** (the first byte of `kernel32!IsDebuggerPresent` must be `64 A1 18 00 00 00` → `mov eax, fs:[0x18]`). If MP/0xCC → detection.
- Bypass succeeds if using **ScyllaHide** (x64dbg plugin) with the "VMware + TitanHide" profile — handles `NtQueryInformationProcess`, `NtSetInformationThread(ThreadHideFromDebugger)`, `NtClose` invalid handle.

```asm
; Deteksi standar
call IsDebuggerPresent
test eax, eax
jnz  short being_debugged
```

```powershell
# Patch di memory dengan ScyllaHide CLI (x64dbg)
# Plugins → ScyllaHide → Options → Profile "VMProtect" → Apply
```

**Uji cepat:**

```bash
# jalankan dengan x64dbg lalu cek di command bar
$ x64dbg: "bp IsDebuggerPresent" → break → register eax = 1 → patch → continue
```

### 2.2 PEB (Process Environment Block)

**What is sent:** enumeration of `PEB->BeingDebugged` (offset `0x02`), `PEB->NtGlobalFlag` (`0x68` 32-bit, `0xBC` 64-bit), `PEB->ProcessHeap` flags (`0x70/0x74` for `HeapFlags`, `ForceFlags`).

**What appears:**
- `BeingDebugged == 1`
- `NtGlobalFlag & 0x70` (FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS)
- `ProcessHeap->Flags & HEAP_GROWABLE == 0`, `ForceFlags != 0`

**Why it succeeds/fails:** reading `fs:[0x30]`/`gs:[0x60]` is not detected by userland hooks. Bypass requires kernel-mode (TitanHide) or patching the structure after `LdrpInitializeProcess` — usually `ScyllaHide` writes `BeingDebugged=0` and `NtGlobalFlag=0` via driver.

```c
// pola akses PEB tipikal
PPEB peb = (PPEB)__readgsqword(0x60);
if (peb->BeingDebugged) exit(1);
if (peb->NtGlobalFlag & 0x70) exit(1);
```

Offset table (Windows 11 24H2, x64):

| Field | x64 Offset | Normal value | Value when debugging |
|---|---|---|---|
| `BeingDebugged` | 0x02 | 0 | 1 |
| `NtGlobalFlag` | 0xBC | 0x0 | 0x70 |
| `ProcessHeap` | 0x30 | valid ptr | valid ptr |
| `ProcessHeap->Flags` | +0x70 | 0x2 | 0x2 + flag debug |
| `ProcessHeap->ForceFlags` | +0x74 | 0x0 | 0x1-0x5 |

### 2.3 Anti-VM

**What is sent (common examples):**

| Vektor | Artefak | Deteksi |
|---|---|---|
| CPUID | `CPUID.1.EAX` bit 31 (hypervisor present), leaf `0x40000000` vendor `"VMwareVMware"` / `"Microsoft Hv"` | `cpuid` | 
| MSR | `rdmsr 0x10` → `VBox` in EAX | `rdmsr` privileged → SEH |
| Registry | `HKLM\HARDWARE\DEVICEMAP\Scsi\...\VirtualBox`, `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` `VMware` | `RegQueryValue` |
| File | `C:\Windows\System32\drivers\VBoxGuest.sys`, `vmtoolsd.exe` | `GetFileAttributes` |
| MAC | `08:00:27`, `00:0C:29`, `00:50:56`, `00:15:5D` | `GetAdaptersInfo` |
| Hardware | BIOS vendor `"innotek"`, `"VMware"`, `"QEMU"` | `WMI Win32_BIOS` |
| Timing | `rdtsc` delta for single-step |  `__rdtsc()` |
| Proses | `vboxservice.exe`, `VBoxTray.exe`, `vmtoolsd.exe` | `CreateToolhelp32Snapshot` |

**What appears:** if the VM is detected, execution branches to *stall* or *exit*; the main payload does not appear → IOCs are lost.

**Why it succeeds/fails:**
- **Bypass succeeds** if the VM is hardened: VMware `SMBIOS.reflectHost = "TRUE"`, `ethernet0.addressType = "static"` + production `ethernet0.address`, `monitor_control.restrict_backdoor = "TRUE"`, `isolation.tools.*.disable = "TRUE"`.
- **Bypass fails** if the CPUID hypervisor bit is left enabled (VMware cannot hide it via basic config — requires a `vmx` patch or `hypervisor.cpuid.v0 = "FALSE"` that must be set **before** the guest boots).

```ini
# .vmx minimal hardening
monitor_control.restrict_backdoor = "TRUE"
isolation.tools.getPtrLocation.disable = "TRUE"
isolation.tools.setPtrLocation.disable = "TRUE"
isolation.tools.setVersion.disable = "TRUE"
isolation.tools.getVersion.disable = "TRUE"
SMBIOS.reflectHost = "TRUE"
hypervisor.cpuid.v0 = "FALSE"
ethernet0.address = "3C:52:82:11:22:33"
```

**Anti-VM test from the guest:**

```powershell
# harus kosong (tidak ada VBox/VMware tools service)
Get-Service | Where-Object {$_.Name -match 'vmtools|vbox'}
# BIOS harus produsen nyata
Get-WmiObject Win32_BIOS | Select Manufacturer,SerialNumber
# CPUID hypervisor bit (via python cpuid atau WMI)
wmic cpu get Name,Manufacturer
```

### 2.4 NtQueryInformationProcess / Patching NTDLL

**What is sent:** dump `ntdll.dll` from disk → compare with in-memory (`NtQuerySection`, or `ReadProcessMemory` into self). If there is `0xCC`, `0xE9`, differing bytes → userland hook detected.

**What appears:** the sample exits immediately or decodes incorrectly.

**Why it succeeds/fails:** userland API monitor (API Monitor, CAPE) hooking `ntdll!Nt*` → hook detected. Bypass: **hardware breakpoint** (x64dbg `bph`), **ETW-TI / kernel callback**, or **TitanHide** (hide hooks via int 0x2E? — no, via `NtSetInformationThread` + driver).

---

## 3. Unpacking

### 3.1 Memory Dump + IAT Reconstruction (Scylla method)

**Scenario:** UPX/privpacker sample, OEP unknown.

**Steps in x64dbg (version 2024.11):**

1. **Identify the packer:** `Detect-It-Easy` on `sample.exe` → "UPX 4.2.1" / "Themida" / "custom".
2. **Set a memory breakpoint on the writable section** (`.data`/`.text` write):
   ```
# in x64dbg command bar
   bp VirtualProtect
# continue until OEP is visible — usually after a block
# of large jump instructions to the original .text section
   ```
3. **Alternative: hardware BP on `kernel32!GetProcAddress`** — breakpoint there on the last iteration before the jump to OEP.
4. **Dump**: **Scylla** plugin (`plugins\Scylla.dll`) → `File → Dump` while at OEP.
5. **Find IAT:** `IAT Autosearch` → `Get Imports`. Scylla recognizes the thunk table via the `call [mem]` pattern and references to `IMAGE_IMPORT_DESCRIPTOR`.
6. **Fix dump:** jika raw size < virtual size, centang `Fix dump`; `Dump` → simpan `sample_dump.exe`.
7. **Rebuild IAT:** `IAT Autosearch → Get Imports → Fix Dump` → `sample_dump_dump_SCY.exe`.

**Example Scylla output (IAT Autosearch):**

| Module | Number of functions | Status |
|---|---|---|
| `KERNEL32.dll` | 214 | OK |
| `USER32.dll` | 89 | OK |
| `ADVAPI32.dll` | 41 | OK |
| `WS2_32.dll` | 12 | OK |
| `WININET.dll` | 8 | OK |

**Why it succeeds:** Scylla scans the entire `.text` for the patterns `FF 15 xx xx xx xx` and `FF 25`, matching targets to the range of modules not yet loaded (validation via `VirtualQuery`).

**Why it fails:**
- **IAT obfuscation** (only `call [reg+off]` with dynamic registers): Scylla misses → need manual tracing in `x64dbg` with `bp NtProtectVirtualMemory` and target logging.
- **Delayed imports**: thunks are filled at runtime → Scylla must be run after all lazy imports are resolved; set `bp` at `LdrGetProcedureAddress` and wait.
- **Stolen bytes**: OEP in an overwritten part of `.text` → Scylla dump is correct but the initial bytes are missing; fix manually with `Scylla → Fix dump` + restore from the original file.

### 3.2 Memory Dump Alternatif: `pe-sieve` + `HollowsHunter`

```powershell
# Dump semua modul + PE yang dimanipulasi dari PID target
.\pe-sieve64.exe /pid 4242 /out C:\dumps\pid4242 /imp 3 /shellc /threads /data 3 /dmode 3

# Scan seluruh proses — sangat berguna untuk malware yang inject ke banyak host
.\hollows_hunter64.exe /loop /out C:\dumps\hs\ /min 256
```

**Flag penting `pe-sieve`:** `/imp 3` (recover imports), `/shellc` (detect shellcode), `/threads` (enumerate thread start), `/data 3` (carve embedded PE), `/dmode 3` (data dump mode lengkap).

**Output khas `pe-sieve`:**

```
PID: 4242, Name: svchost.exe
  modules: 23, suspicious: 1
  SIG: [Hollowed] [IAT patched]
  Module: C:\Windows\System32\svchost.exe (hollowed, entrypoint overwritten)
```

**Why it works:** `pe-sieve` compares process memory with the file on disk **per-module** (section size, header, entry point, IAT range). Hollowing = mismatch between `PIMAGE_DOS_HEADER` in-memory and on-disk.

**Why it fails:** the sample uses **module stomping** (legitimate target module, but the `.text` section is overwritten with an exact size → header comparison doesn't trigger). Mitigation: compare section hashes per-section (`pe-sieve /shellc /data 3` still flags entry-point anomaly), or enable `PageGuard` monitoring in Procmon with filter `Process Profiling → Thread Start`.

### 3.3 Anti-Unpacking

| Malware technique | Effect on unpacker | Mitigation |
|---|---|---|
| `VirtualProtect` removal after OEP | Dump can't `ReadProcessMemory` because `PAGE_NOACCESS` | `pe-sieve` reads via `NtReadVirtualMemory` with `PAGE_GUARD` handling; patch at `NtProtectVirtualMemory` |
| `NtSetInformationThread(ThreadHideFromDebugger)` | Debugger loses events | ScyllaHide hook `NtSetInformationThread` return `STATUS_SUCCESS` without effect |
| `int 3` + VEH self-debug | Single-step mati | x64dbg option `Ignore INT3` |
| Section per-page encrypt, decrypt during execution | Dump contains encrypted pages | Dump at breakpoint in `VirtualProtect` write, iterate per-page; `pe-sieve /data 3` carve each region |
| `Sleep` panjang + `NtDelayExecution` + APC | Analis menunggu tak produktif | Patch `Sleep`/`NtDelayExecution` (x64dbg script) |

Example sleep patch (x64dbg script, `nosleep.txt`):

```
// entry: bp pada Sleep dan NtDelayExecution
Sleep:
  ret 4     // langsung return
NtDelayExecution:
  mov eax, 0   // STATUS_SUCCESS
  ret 8
```

---

## 4. Deteksi Process Hollowing / Injection

### 4.1 Process Hollowing — Anatomi

**What is sent (typical API sequence):**

| Order | API | Artifact |
|---|---|---|
| 1 | `CreateProcessW(..., CREATE_SUSPENDED)` | proses target suspended |
| 2 | `NtQueryInformationProcess` / `NtUnmapViewOfSection` | unmap image asli |
| 3 | `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` | alokasi RWX |
| 4 | `WriteProcessMemory` (PE header + section) | tulis PE baru |
| 5 | `SetThreadContext` | ubah `RCX` = entrypoint baru |
| 6 | `ResumeThread` | eksekusi |

**What appears (telemetry):**

| Sumber | Event | Filter |
|---|---|---|
| Sysmon **v15.15** (Win 11 24H2) | EventID 1 `ProcessCreate` with `ParentImage=malware.exe` | `CallTrace` contains `UNKNOWN` (unbacked) |
| Sysmon 8 | `CreateRemoteThread` | `SourceImage != TargetImage` |
| Sysmon 10 | `ProcessAccess` (mis. `0x1F0FFF`, `0x143A`) | target `lsass`, `svchost` |
| Sysmon 25 | `ProcessTampering` (hollowing) | `Type=Image is replaced` |
| ETW-TI `Microsoft-Windows-Threat-Intelligence` | `KERNEL_MEMORY_EVENT` + `NtWriteVirtualMemory` | requires trace with `SECURITY_ATTRIBUTES` |
| CAPE | `behavior.processes[].calls` — API sequence | `signatures: "process_hollowing"` |

```powershell
# Sysmon config ringkas (potong ke bagian relevan)
<Sysmon>
 <EventFiltering>
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
  </ProcessAccess>
  <CreateRemoteThread onmatch="include">
    <SourceImage condition="excludes">C:\Windows\</SourceImage>
  </CreateRemoteThread>
 </EventFiltering>
</Sysmon>
```

**Why it works:** hollowing **always** produces a mismatch between the disk image (`\Device\HarddiskVolume3\...\svchost.exe`) and memory — `Sysmon 25` triggers because the section checksum changes.

**Why it fails:**
- **Process doppelgänging** (transacted hollowing via `TxF`): Sysmon 1 never sees `CreateProcess` — only `NtCreateProcess` via transacted section. Detection uses `EventID 11 FileCreate` transacted (`:TxF`) + `CreateRemoteThread`.
- **Process ghosting** (delete pending file): memory-backed image, the file on disk is already gone before `CreateProcess`. Detection: `GetFinalPathName` empty on `NewProcessName` in Sysmon 1.
- **Herpaderping**: the file on disk is replaced **after** `CreateProcess` → memory image hash differs from Sysmon 1 `Hashes`. Detection: `Hashes` on EventID 1 matches a file that is **not** the executed image (validate with `pe-sieve /shellc`).

### 4.2 Remote Thread Injection (Classic DLL Injection)

**API sequence:** `OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` → `WriteProcessMemory` (path DLL) → `CreateRemoteThread(LoadLibraryA, path)`.

**Detecting `CreateRemoteThread` in Sysmon 8:**

```
EventID 8
SourceImage: C:\Users\Public\evil.exe
TargetImage: C:\Windows\System32\notepad.exe
StartAddress: 0x7FFB...  (LoadLibraryA di kernel32)
StartModule: C:\Windows\System32\kernel32.dll
StartFunction: LoadLibraryA
```

**Why it works:** `StartFunction=LoadLibraryA` + `SourceImage` not signed = very strong indicator. **Why it fails:** all three APIs can be called via direct syscall (`NtOpenProcess`/`NtAllocateVirtualMemory`/`NtWriteVirtualMemory` + `RtlCreateUserThread`) → Sysmon 8 still catches `RtlCreateUserThread` as `CreateRemoteThread` (kernel callback), but `SourceImage` can be empty if unbacked — the filter must include empty `SourceImage`.

### 4.3 Injection Lain

| Technique | Artifact | Detection |
|---|---|---|
| APCs (`QueueUserAPC`) | `NtQueueApcThread` to target thread | Sysmon 8 doesn't cover → use ETW-TI or `pe-sieve /threads` (abnormal start address) |
| `SetWindowsHookEx` + WH_GETMESSAGE | DLL loaded in all user processes | Sysmon 7 `ImageLoad` (`Signed=false`, path in `%TEMP%`) |
| `NtCreateThreadEx` via `NtMapViewOfSection` | section RWX | `Sysmon 8` start module empty |
| AtomBombing | `NtQueueApcThread` + `GlobalGetAtomName` | ETW-TI; `pe-sieve /shellc /data 3` |
| Thread hijacking (`SuspendThread`+`SetThreadContext`) | `NtSetContextThread` in another process | ETW-TI `KERNEL_THREAD_EVENT`; `Sysmon 8` doesn't catch → requires EDR |
| `PROCESS_SUSPEND_RESUME` + `NtResumeProcess` | Sysmon 10 access mask `0x800` | filter `GrantedAccess & 0x0800` |

### 4.4 Verification in Sandbox

```powershell
# pada guest Windows 11 24H2, setelah sampel jalan:
# 1. cek image in-memory vs on-disk (hollowing)
.\pe-sieve64.exe /pid (Get-Process evil).Id /shellc /data 3 /dir C:\dumps\verify

# 2. cek remote thread di proses korban
.\hollows_hunter64.exe /loop

# 3. cek handle access log (Sysmon 10)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} |
  Where-Object {$_.Message -match 'GrantedAccess: 0x1F0FFF'} |
  Select-Object TimeCreated,Message -First 20
```

```python
# parsing cepat CAPE cape report untuk signature injection
import json, sys
r = json.load(open(sys.argv[1]))
print("Signatures:", [s["name"] for s in r.get("signatures", [])])
for p in r.get("behavior", {}).get("processes", []):
    if p.get("calls"):
        print(p["process_name"], "calls:", len(p["calls"]))
```

---

## 5. Operational Pitfalls (THAT OFTEN CAUSE FAILURE IN THE FIELD)

| # | Jebakan | Gejala | Mitigasi |
|---|---|---|---|
| 1 | **Dirty snapshot** — snapshot taken after the previous sample ran | Second sample dies quickly because anti-analysis detects the first sample's artifacts | Take snapshot from a **fresh install** image, or `DISM /Capture-Image` + redeploy per batch |
| 2 | **Unrealistic guest time** | Malware gated `if (date < 2024) return;` → doesn't run | Set guest `timezone` according to target, `w32tm /resync` to fake NTP, or `Set-TimeZone` + patch `NtQuerySystemTime` in API Monitor |
| 3 | **INetSim dead / DNS leak to internet** | Sample can't get C2, doesn't download stage-2 payload → doesn't get unpacked | Always verify `nslookup evil.example` in guest → must be `192.168.122.1`; if it returns real IP, check `iptables -t nat -L` |
| 4 | **CAPE/QEMU version mismatch** (`qemu-kvm` 8.2 vs CAPE 2.4) | Task stuck in `runtime` without `analysis.log` | Pin versions from `requirements.txt`; don't `apt upgrade` qemu after build |
| 5 | **VMware backdoor slips through** | `hypervisor.cpuid.v0` is ineffective if the VM isn't fully rebooted | Power off (not reboot), remove residual `vmx` `uuid.action = "keep"` |
| 6 | **FLARE-VM install with Defender active** | Dozens of tools (x64dbg, PE-sieve) quarantined → `x64dbg.exe` missing | Snapshot after build; `Set-MpPreference -DisableRealtimeMonitoring $true` **before** install, restore after snapshot |
| 7 | **`pe-sieve /pid` on protected process (PPL)** | `lsass.exe` inject can't be dumped | Not possible without `PPLdump` 2023 (requires vulnerable driver); use **memory forensics** (WinPmem 4.0) or `procdump -ma` with `SIGNATURE_REQUIRED` bypass in isolated lab |
| 8 | **IAT reconstruction uses wrong module version** | `Scylla Fix Dump` result runs but crashes when import reference resolution differs between builds (Win 11 24H2 `kernel32!LoadLibraryA` addr != snapshot) | Dump in the guest **exactly the same** as the one to be used for analysis; don't dump on Win 10 then fix on Win 11 |
| 9 | **CAPE `unpacker=yes` false positive** | "upx" signature matches malware that is not UPX → report noise | Check `cape report → static.pe.sections` for entropy & section name before trusting the signature |
| 10 | **Sysmon 25 absent on old builds** | Win 11 24H2 default Sysmon from Chocolatey is still v13 → `ProcessTampering` does not emerge | Install Sysmon **≥14.16**, SwiftOnSecurity 2024 configuration, or Olaf Hartong `sysmon-modular` |
| 11 | **Sample refuses to run if `IsDebuggerPresent` hook does not detect anti-hook** | Sample branches: if hook is detected → self-delete | Use TitanHide (kernel) not ScyllaHide (userland) for early-stage analysis; run the sample first **without** hooks for behavior profiling |
| 12 | **Network capture on `vmnet1` does not see guest→host service traffic** | INetSim traffic invisible → C2 IOC lost | Capture on interface `vmnet8` (NAT) **and** `vmnet1`; better: `iptables -j TEE` duplicate to `tcpdump` |
| 13 | **`Sleep` patch too aggressive** | Malware that uses sleep as timing for C2 handshake → handshake breaks | Patch `Sleep` to a maximum of 1000 ms (not 0), or a dedicated `SleepEx`; use a conditional `x64dbg` script |
| 14 | **Snapshot rollback does not remove named pipe / global mutex** | Second sample skips execution (mutex `Global\...` detected) | Reboot guest before snapshot; remove `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` artifacts |
| 15 | **CAPE analysis timeout default 200 seconds** cuts off unpacker | `procmemdump` does not get a chance to run | `conf/cuckoo.conf` → `[cuckoo] analysis_timeout = 600`; submit with `--timeout 600` |

### 5.1 One thing that, in short, saves many analyses

**Selalu jalankan sampel dua kali:**
1. **Pass-1 "cold"**: no hooks, no debugger, with Sysmon + Procmon + PCAP → obtain the **original behavior profile** and the anti-analysis used (if the sample self-terminates before activity → that means anti-VM/anti-debug triggered).
2. **Pass-2 "instrumented"**: ScyllaHide/TitanHide + x64dbg + pe-sieve → for unpacking and hollowing verification.

A report based only on pass-2 will **lose** the anti-analysis that is actually the main IOC in threat intel.

---

## [reasoning trace]


