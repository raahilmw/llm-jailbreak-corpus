# evasion-windows--deep — win

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

Technique: set `Dr0 = &AmsiScanBuffer`, `Dr7 = 0x1` (execute breakpoint); the handler in VEH (`AddVectoredExceptionHandler`) checks `ExceptionCode == EXCEPTION_SINGLE_STEP` and manipulates `Rip`.

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
- **Per-thread vs per-process**: Dr is per-thread only. The `.NET` runtime thread pool must be enumerated via `NtGetNextThread` to set all worker threads before AMSI is called.
- **CET (Control-flow Enforcement Technology)** in Windows 11 24H2 validates returns without `CALL` — the "ret simulation" technique above can trigger a `#CP` fault if the shadow stack is active. **Workaround**: use `jmp` to the caller label or patch only `Rax/Rdx` and `EXCEPTION_CONTINUE_EXECUTION` without ret (native AmsiScanBuffer will still execute — it must be skipped via `Rip` advance to `ret`).

### 7.3 Reflection Bypass — Varian PowerShell Terbaru

`[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` starts tripping signatures (AMSI signature `AmsiUtils` string). Advanced variants:

```powershell
# Obfuscation berbasis reflection tanpa string literal "AmsiUtils"
$t = [Ref].Assembly.GetTypes() | ? {$_.Name -match '^AmsiU\w+$'}
$f = $t.GetField('amsiInitFailed', 'NonPublic,Static')
$f.SetValue($null, $true)
```

**Edge case**:
- **PowerShell 7.x (.NET Core)**: the `AmsiUtils` type **does not exist** — AMSI is hosted by the `System.Management.Automation.dll` native shim (Windows only). Classic reflection fails. Alternative: patch `amsi.dll` in the memory of the `pwsh.exe` process via `VirtualProtect` (PowerShell 7 still calls `AmsiScanBuffer` from the native host).
- **Constrained Language Mode (CLM)**: blocks `[Ref].Assembly` — but `[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer` is also blocked, so the technique of patching native code from pure PowerShell is impossible. Use `Add-Type` (also blocked) or injection from another process.
- **PowerShell 5.1 with AMSI "audit only"** (default in some SKUs on Windows Server 2019+): `AmsiScanBuffer` returns clean but still logs — the bypass is "successful" in execution but detected via telemetry. Check `HKLM\SOFTWARE\Microsoft\AMSI\Features\` for status.

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
- `EtwEventWrite` is `forward`ed to `EtwEventWriteFull` and `EtwEventWriteTransfer`. **A single patch on `EtwEventWrite` does not cover `EtwEventWriteFull`** — the .NET runtime calls `EtwEventWriteTransfer` or the `Ex` variant directly. Patch at least three: `EtwEventWrite`, `EtwEventWriteFull`, `EtwEventWriteEx`.
- **Provider-level disable**: `EtwEventRegister` returns a `REGHANDLE` + `ENABLED` flag. Patch `EtwEventRegister` to force `isEnabled = FALSE` for specific providers — more selective and avoids crashes because certain providers (e.g. `Microsoft-Windows-Kernel-Process`) are consumed by kernel drivers (userland patches have no effect).
- **WiFi/Bluetooth telemetry**: `EtwEventWrite` is routed to `NtTraceEvent` via **direct syscall** if the bindiff is compiled with `RtlGetCurrentPeb()->...` — userland patches do not cover it. This indicates the EDR uses **direct syscalls** to emit telemetry — the trace cannot be safely disabled from userland.

### 8.2 `EtwpEventWriteFull` / `EtwNotificationRegister` Patch (Rarely Documented)

`EtwNotificationRegister` (Win8+) is used by **"modern" ETW** and some EDRs for callback registration. Patching this function prevents the EDR from registering new callbacks — **but** already-registered callbacks remain active.

**Operational pitfall**: patching `EtwNotificationRegister` by malware is often **logged** by `Microsoft-Windows-Threat-Intelligence` (ETW-TI), which runs in the **kernel** — it cannot be patched from userland. Solution: **do not patch** if ETW-TI is active (detect via `NtQuerySystemInformation(SystemCodeIntegrityInformation)` or check `EtwpGlobalSequenceNumber`, which cannot be modified).

### 8.3 ETW-TI (Threat-Intelligence) — Realitas

ETW-TI (`Microsoft-Windows-Threat-Intelligence`) is a **kernel provider** that emits events for executable `VirtualAlloc`, cross-process `WriteProcessMemory`, `QueueUserAPC`. Known userland mitigations:

| Technique | Effectiveness | Risk |
|---|---|---|
| Patch `EtwEventWrite` | ❌ No (kernel-emit) | — |
| Patch `NtTraceEvent` | ❌ No | — |
| Unhook `ntdll!NtTraceEvent` syscall | ⚠️ Sebagian | BSOD jika patch global |
| Disable via registry `HKLM\...\WINEVT\Channels` | ❌ No (per-consumer) | — |
| Patch consumer (`svchost!Timeline`) | ⚠️ Fragile | restart service |
| **Blind spot**: syscall from user mode via `NtTraceEvent` that is `syscall`ed directly (not IAT) | ✅ If the EDR does not hook the SSDT | HVCI blocks |

**Operational conclusion**: ETW-TI cannot be bypassed from pure userland. The realistic strategy is to **reduce signals** (non-exec `VirtualAlloc` then `VirtualProtect`, `NtMapViewOfSection` RX, etc.) rather than disabling the provider.

## 9. Unhooking ntdll — Advanced Variants

### 9.1 Technique Comparison (Additional Table)

| Technique | Fresh Copy Source | Direct Syscall | EDR Detection | Complexity |
|---|---|---|---|---|
| **Classic unhook** (`CreateFileMapping` + `NtMapViewOfSection` section) | KnownDlls `\KnownDlls\ntdll.dll` | ❌ | ⚠️ Jelas (RWX section, private mapping) | Low |
| **Fresh copy** `LoadLibrary("C:\\Windows\\System32\\ntdll.dll")` | File (redirected to KnownDlls) | ❌ | ⚠️ EDR can hook `LoadLibrary` | Low |
| **Hell's Gate** | N/A (read SSN from original stub) | ✅ | ⚠️ SSN extraction signature | Medium |
| **Halo's Gate** | Neighbor stub (SSN±1) | ✅ | ✅ More subtle (SSN from neighbor) | Medium |
| **Tartarus Gate** | Neighbor via `jmp` check + up/down | ✅ | ✅ Robust against partial hooks | Medium |
| **SysWhispers 2/3** | Hardcoded SSN table | ✅ | ❌ Static (SSN table per build) | Low |
| **FreshyCalls** | Sort `Zw*` by address, index = SSN | ✅ | ✅ No stub read needed | Medium |
| **RecycledGate** | Same as FreshyCalls + jmp-aware | ✅ | ✅ Robust hook | Medium-High |
| **PerunsFart** | `RtlGetThreadStartAddress` + heap walk | ✅ | ✅ Runtime resolve | High |
| **Syscall via `ntdll` stalk** | Stalk prolog, extract `mov eax, imm` | ✅ | ✅ Tahan hook `jmp` | Medium |

### 9.2 Hell's Gate — Edge Case Terbaru

**Problem**: modern EDRs (CrowdStrike Falcon, SentinelOne) hook with a **5-byte `jmp`** at the start of the function — `mov eax, SSN` becomes `E9 xx xx xx xx`, so reading `[p+4] == 0xB8` fails. This triggers **Hell's Gate failure** → crash.

**Halo's Gate** (neighbor): if stub `p` is hooked, look for `p-1` (previous) or `p+1`. SSN = SSN_neighbor ∓ 1. **Edge case**: on Windows 11 with **branching hook chains** (EDR hooks interleaved with AMSI/manual-mapped), the neighbor can also be hooked → cascading failure wave.

**Tartarus Gate** (fix): check the `jmp` target. If the stub contains `E9`, follow the target (likely an EDR trampoline) — the trampoline usually preserves the original `mov eax, SSN` after the `jmp` returns. If not, use the neighbor with direction based on the sorted `Zw*` address order.

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

### 9.3 FreshyCalls & RecycledGate — Resolve Without Reading Stubs

Insight: in `ntdll`, `Zw*` exports sorted by address = monotonic SSN. Resolve SSN = index in the sorted array + base.

```
1. Enum export directory ntdll (parse PE header manual — hindari GetProcAddress yang di-hook)
2. Filter nama berawalan "Zw"
3. Sort berdasarkan address (bukan nama)
4. SSN = index + baseSSN (baseSSN di-tuning per Windows build, atau di-resolve dari satu stub known-good)
```

**RecycledGate** adds: validate that the stub is not hooked via a `jmp` check; if it is, use the neighbor with a **corrected index**.

**Jebakan**:
- **Kernel 24H2 (build 26100)**: ntdll is re-`link`ed; the `Zw*` order remains monotonic but **baseSSN shifts** because new syscalls are inserted. `FreshyCalls` must resolve baseSSN from one unhooked stub (e.g. `NtQuerySystemTime` — usually not hooked because it is not sensitive).
- **EDR hooks on the sorted array**: some modern EDRs move `Zw*` stubs to a **different section** (`.mrdata` vs `.text`) so sorting by address is still correct, but if the EDR copies stubs to a trampoline, the address order in `.text` is no longer monotonic. **Solution**: sort by **name** and batch with `NtQueryInformationProcess` for validation — or use a `Hell's Gate` hybrid for doubtful stubs.

### 9.4 Direct Syscall — Deteksi & Edge Case

**Deteksi EDR** (System call origin check):
- **`Thread.ProcessId` in the syscall chain**: kernel ETW-TI emits `SysCallEnter` with `CallStack`. EDR detects `NtProtectVirtualMemory` called from an address **not** in ntdll `.text` → alert.
- **Indirect syscall** (SysWhispers 3 / `JumpToSyscall`): `jmp ntdll!Nt*` with `syscall` elsewhere. EDR detects via mismatched **unwind info** or `RtlVirtualUnwind` mismatch.
- **Mitigation**: **`NtCreateThreadEx` to a syscall gadget from `win32u` / `wow64cpu`** (halo's gate variant — the syscall instruction in `win32u.dll` is rarely hooked).

**Edge case penting (2024)**:
- **`Wow64`**: 32-bit processes on a 64-bit OS perform thunking. Direct syscall from `wow64cpu.dll` has a stub **recognized** by EDR as legit — the historical trick was to **inject into a WOW64 process** and call via `KiFastSystemCall`. This technique is now **detected** because Microsoft moved the thunk to the `wow64` subsystem with ETW events.
- **`syscall` instruction under HVCI**: syscalls from user mode are still allowed, but **SSDT patching is not possible** — irrelevant for userland bypass.
- **`NtCreateThreadEx` + `RtlCreateUserThread`**: both trigger ETW-TI `RemoteThread` events. Use `NtQueueApcThreadEx` to a thread that is already `alertable` — APC events are now also emitted (Win11 22H2+). **There is no remote injection without ETW-TI on modern Windows 11**.

## 10. EDR Userland Hook Detection — Detection For Attackers

### 10.1 Self-Check: Deteksi Hook oleh EDR

Before unhooking, verify whether a hook exists (to prevent excessive unhooking that causes integrity detection):

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

**Limitation**: EDR "stealth" hooks (inline in the middle of the function, after the prolog — detour by [Minhook](https://github.com/TsudaKageyu/minhook) or [Detours](https://github.com/microsoft/Detours) with `VirtualProtect` on the body) are **not detected** by the prolog check. Alternative: compare ntdll `.text` in memory with the file on disk (per-section checksum), or `NtReadVirtualMemory` from `\KnownDlls`.

### 10.2 Deteksi Hook via Cross-Process Compare

Reading ntdll from **another** process (e.g. a Windows process not yet injected by EDR — `smss.exe`, `csrss.exe`) then comparing `.text` bytes:

```c
// 1. Buka smss.exe (PPID system, biasanya tanpa EDR hook)
// 2. NtReadVirtualMemory(ntdllBase, .text, size) -> freshText
// 3. Bandingkan dengan ntdll lokal -> diff = hook region
```

**Pitfall**: modern EDRs (Microsoft Defender for Endpoint 2023+) perform **Cross-Process Injection** into `smss.exe`, `lsass.exe`, `csrss.exe` — all hooked. Comparing with an EDR child process gives a false negative. Use the **`\KnownDlls\ntdll.dll` section** via `NtOpenSection` + `NtMapViewOfSection(SEC_IMAGE)` — this mapping is **read-only and immutable** (kernel-backed image section), not hooked.

### 10.3 Hook Detection via `PAGE_GUARD` and `PAGE_EXECUTE_READWRITE` Scan

Scan ntdll `.text` for regions with **RWX** permission (EDR trampolines are usually RWX or RX outside the image range):

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

Classic technique: `NtDelayExecution(10000 * 10000000)` (1000 seconds) then run normally — the sandbox patches `Sleep`/`NtDelayExecution` to "fast-forward". Detect with a **timing check**:

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
- **`Sleep` by `WaitForSingleObject` on event timeout** is harder to patch (some sandboxes do not intercept).
- **`SetTimer` + `MsgWaitForMultipleObjects`** — timer acceleration terdeteksi via `GetTickCount64`.
- **Nested timing**: use 3 parallel timers (`QPC`, `GetTickCount64`, `__rdtsc`) — sandboxes usually patch one, not all. Compare.
- **`NtQueryTimerResolution` before/after sleep** — sandboxes that fast-forward temporarily change the timer resolution.

**Sandbox counter** (for defender): hook `NtDelayExecution` with the original delay but advance the virtual clock — the QPC clock is also virtualized, so the timing check "deceives" the malware.

### 11.2 User Interaction — Varian Terbaru

```c
// Cek input terakhir — trace historis cursor
LASTINPUTINFO lii = {.cbSize = sizeof(lii)};
GetLastInputInfo(&lii);
DWORD idle = GetTickCount() - lii.dwTime;
// Sandbox headless: idle sangat besar (~uptime). Real user: < beberapa menit.
```

**Varian 2024**:
- **Repeated `GetCursorPos`**: sample cursor position every 200ms; if the position is constant and always `(0,0)` or the center point → headless.
- **`GetForegroundWindow` + `GetWindowText`**: sandboxes without interaction usually maintain `Default IME` / `Progman` in the foreground. Real users have variable foreground.
- **`GetSystemMetrics(SM_MOUSEBUTTONS)`** — jika 0 (headless server), curiga. (Rarely effective — nilainya 2 default.)
- **`NtUserGetRawInputData`** — check raw input buffer; headless without a device does not have one.

**Edge case**: modern sandboxes (Any.Run, Joe Sandbox) **simulate** mouse move + click via hypervisor — the techniques above fail. Variation: check mouse movement **entropy** (via hooking `SetWindowsHookEx(WH_MOUSE_LL)`) — humans do not move linearly. **Trap**: hooking HIDLL is detected as malware behavior.

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
| **`cpuid` hypervisor leaf** | `__cpuid(0x40000000)` | "KVMKVMKVM", "Microsoft Hv", "VMwareVMware" | **Hyper-V in Windows 11 default** — false positive |

**Edge case baru**:
- **Windows 11 with VBS/HVCI**: `__cpuid(0x40000000)` returns "Microsoft Hv" even on physical hardware — the hypervisor CPUID technique is **obsolete**. Use a combination with `rdtsc` skew **with correction** (small VBS skew, large VM skew).
- **Apple Silicon Mac (ARM64 Windows, Parallels)**: CPUID equivalent (`MRS ID_AA64PFR0_EL1`) returns ARM64 — a strong indicator of VM/emulation for x64-only malware.
**Cloud (AWS/Azure)**: MAC `02:*:*:*:*:*` (AWS) or `00:0D:3A` (Azure) + SMBIOS `Amazon EC2`/`Microsoft Corporation`. This fingerprint is **system-specific, not sandbox** — many commercial malware whitelist the cloud to avoid false-positive detection on enterprise victims. **Trap**: malware that rejects the cloud will **fail on victims in the cloud** (high miss rate).

### 11.4 Complementary: Timing-Based VM Detection (`rdtsc` diff)

```c
// Deteksi VM exit: instruksi privileged yang memicu VM exit akan jauh lebih lambat
UINT64 t1 = __rdtsc();
__cpuid(...);  // atau instr privileged ring-0
UINT64 t2 = __rdtsc();
if (t2 - t1 > 1000) { /* VM exit */ }
```

**Trap**: on physical machines with SMT active, the diff can be > 1000 due to interrupts/context switch. **Use the median of 100 samples**, and compare it with the `rdtsc` baseline (gap between two consecutive `rdtsc` calls). Ratio > 4–8x → VM.

### 11.5 Sandbox "Anti-VM" — Deteksi oleh Sandbox

Defender now detects this technique:
- **Static**: signature API call sequence (`__cpuid` + `GlobalMemoryStatusEx` + MAC check) → sandbox "suspicious" flag.
- **Dynamic**: sandbox `fake` values (Any.Run "evasion" mode) — if the malware still exits, flag it as anti-sandbox (indicator of maliciousness).
- **Attacker strategy**: **do not exit prematurely**. Collect fingerprints, store them, but continue running normally — detection by the analyst becomes slower. Or **branch** to "benign" behavior (e.g., calculator) when detected — the analyst is confused.

## 12. Cross-Technique Operational Traps

### 12.1 Orde Eksekusi

Safe order and reasons:

1. **Fingerprint env first** (`__cpuid`, SMBIOS) — read-only operation, does not trip ETW-TI.
2. **Sleep acceleration check** — cheapest, not sensitive.
3. **AMSI patch** — before sensitive strings touch PowerShell/.NET; if after, it's too late.
4. **ETW patch** — before `VirtualAlloc`/`VirtualProtect` (which emit ETW-TI). Note: patching ETW **does not** close ETW-TI, so this order only reduces userland noise.
5. **Unhook ntdll** — last before custom syscall; if done early, self-check hook detection could be wrong because ntdll has been modified.
6. **Syscall** — all sensitive operations via direct/indirect.

**Common mistakes**: patching AMSI after dropping to disk → AMSI scans the file and detects it. Or unhooking ntdll after the first `VirtualProtect` → ETW-TI logs inform of `NtProtectVirtualMemory` from ntdll (but `CallStack` is normal).

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

### 12.3 Often Overlooked Forensic Logging

Every evasion technique leaves a trace in unexpected places:

| Aksi | Jejak | Lokasi |
|---|---|---|
| `VirtualProtect` in `.text` ntdll/amsi | `Microsoft-Windows-Threat-Intelligence` event 6 | Kernel → ETW-TI EventLog channel (if consumed) |
| Section mapping `\KnownDlls\ntdll.dll` | `MuiCache`, `Prefetch` entry baru | `NTUSER.DAT`, `Windows\Prefetch` |
| `LoadLibrary` private copy ntdll | `AppCompat` shim cache, `Amcache.hve` | `Amcache.hve`, `Windows\AppCompat\Programs` |
| HWBP set (Dr0) | `Sysmon` Event ID 8 (CreateRemoteThread) sometimes misses, but **Intel PT trace** saves it | Kernel (requires Intel PT / ETW capture) |
| Cross-process compare ntdll | `Sysmon` Event ID 10 (ProcessAccess) with `GrantedAccess` = `0x1010` (VM_READ) | Sysmon |
| `__cpuid(0x40000000)` + SMBIOS read | **None** — silent, but **behavioral** (API pattern) is recorded in EDR telemetry | Internal EDR |

**Implication**: unhooking and patching indeed eliminate userland logs, but the kernel side still records (ETW-TI, Sysmon, Intel PT, Hyper-V hypervisor logs). An attacker who successfully bypasses userland is still detected by an analyst with access to kernel-level telemetry.

### 12.4 Specific Defender Configurations That Break These Techniques

- **Microsoft Defender for Endpoint (MDE) "Tamper Protection" + "Script Scanning"**: blocks `AmsiUtils` reflection (signature `AmsiUtils`/`amsiInitFailed`), `AmsiScanBuffer` patch via APT (Attack Surface Reduction rule "Block process creations originating from PSExec and WMI"), and ETW patch via T1562.006 detection (managed).
- **CrowdStrike Falcon "User-Mode Hooking" + "Kernel Sensor"**: patching ntdll causes an integrity check via Falcon kernel driver → `SuspiciousProcessAccess` alert (not a block, but the log is sent). FreshCalls against a `jmp`-ed ntdll results in a mismatch unwind — Falcon detects it as `InvalidUnwindInfo`.
- **SentinelOne "Static AI" + "ARO"**: `Dr0-Dr3` write via `SetThreadContext` is logged by the **SentinelOne driver** — triggers the `HardwareBreakpointSet` alert (rarely used by legit software).
- **Windows Defender Application Control (WDAC) + HVCI**: `VirtualProtect(PAGE_EXECUTE_READWRITE)` on the **image section** of ntdll → **HVCI block** (`STATUS_INVALID_PAGE_PROTECTION`). Unhook via `VirtualProtect` of ntdll **fails** on HVCI machines — only `NtMapViewOfSection` from a file copy succeeds (because it does not modify the original image section).

### 12.5 Practical Recommendations (For Red Team)

1. **Always fingerprint first** before patching — patching AMSI in a Windows Defender + HVCI sandbox will **crash** the audit process.
2. **Prefer `NtMapViewOfSection` fresh copy** over `VirtualProtect` — saves one ETW-TI call and is HVCI-compatible.
3. **Avoid `Dr0` on HVCI + CET** — use **Veh + inline patch** for AMSI (`AmsiScanBuffer` → `mov eax, 0x80070057; ret`), which is more stable across all versions.
4. **Do not fully unhook `ntdll`** — unhook only the functions needed (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`). Full unhooking triggers an integrity check.
5. **For internal .NET**: hook `Assembly.Load`, not `AmsiScanBuffer` — more selective, does not interfere with scanning other PowerShell files (which may be reported to the SOC as "normal").
6. **Test on HVCI-enabled Windows 11 24H2** — many old techniques fail; do not assume compatibility from Win10.

### 12.6 Detection Engineering (For the Blue Team on This Side)

Effective signatures to detect the above techniques **without** relying on userland hooks:

- **`LoadLibrary` from the path `System32\ntdll.dll`** without `LOAD_LIBRARY_AS_DATAFILE` → suspicious (ntdll is always in KnownDlls).
- **`NtMapViewOfSection` with section path `\KnownDlls\`** — legitimate (loader), but **private mapping (SEC_IMAGE)** in a non-loader process → suspicious.
- **`VirtualProtect` that modifies `.text`** (image region, not `MEM_PRIVATE`) → almost always evasion (or hook installation by the EDR itself — false positive; whitelist the EDR module base address).
- **`SetThreadContext` with `Dr0 != 0`** — very rarely legitimate. Whitelist debuggers (WinDbg, x64dbg).
- **`EtwsEventWrite` returns 0 without an event being sent** (comparison with ETW-TI consumer) → indication of a patch. Can only be detected by the kernel.
- **`__cpuid(0x40000000)` in a non-hypervisor-aware process** → aggressive sample. Whitelist hardware-inventory processes (`msinfo32.exe`, `dxdiag.exe`).

**Key insight**: userland defense evasion does **not** eliminate evidence from kernel telemetry (ETW-TI, HVCI, Hyper-V). Blue team investment is better spent on **kernel-side detection** than on userland hooks that can be bypassed. This is a fundamental industry shift from 2023–2025.

---

## [reasoning trace]


