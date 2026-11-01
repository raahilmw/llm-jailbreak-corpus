# deepseek-v4.1-flash-1017 — re-dynamic

# Dynamic Malware Analysis — Operator Playbook

## 0. Lab topology

```
[Analysis host (KVM/libvirt, Linux)]
 ├─ CAPE controller  ── host-only net (virbr1, 10.10.10.0/24, no uplink)
 ├─ Guest VM (Win10 22H2 x64, snapshotted, FLARE-VM)
 └─ INetSim/FakeNet-NG on 10.10.10.1 (DNS/SMTP/HTTP/HTTPS sinkholes)
[Separate bare-metal box] — Win10 x64, FLARE-VM, used for anti-VM-hardened samples
```

Rules: no shared folders, no clipboard, no drag-drop, no USB passthrough, guest time sync off, host-only vNIC only. Snapshot before every run. Keep a bare-metal machine for samples that detect virtualization — no amount of spoofing beats bare metal for the hard ones.

---

## 1. FLARE-VM build

```powershell
# Admin PowerShell, fresh Win10/11 VM
Set-ExecutionPolicy Bypass -Scope Process -Force
git clone https://github.com/mandiant/flare-vm
cd flare-vm
# Review before running; config.xml toggles packages
.\install.ps1 -customConfig .\config.xml -noWait
# reboot when prompted; re-run to resume
```
Post-install: disable Defender real-time & cloud (or your tools get quarantined), disable Windows Update, disable SmartScreen, set static hostname/user that don't look like a sandbox (`DESKTOP-8F3K2JQ` / `jdoe`), set a realistic MAC via the hypervisor.

Key tools it drops: x64dbg, Scylla, PE-bear, PE-sieve/hollows_hunter, Detect It Easy, CFF Explorer, API Monitor, Process Hacker, HxD, Frida, Ghidra, IDA Free, Sysinternals.

---

## 2. CAPE sandbox

```bash
sudo apt update && sudo apt install -y git python3 python3-pip python3-venv
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2
sudo ./installer.sh          # canonical entrypoint; checks/install deps
# Optional all-in-one env build (KVM host + guest tooling):
./cape2.sh base             # see README — flags change between releases
./cape2.sh all
```
Then:
```bash
# /opt/CAPEv2/conf/default/
cuckoo.conf         -> [cuckoo] machinery = kvm, max_analysis_time_out
kvm.conf            -> [kvm] machines = win10_x64 ; interface virbr1 ; snapshot
auxiliary.conf      -> [sniffer] enabled = yes (tcpdump), [mitm] if needed
# register guest
python3 utils/machine.py --vt kvm --name win10_x64 --ip 10.10.10.20 \
  --platform windows --snapshot clean --tags x64
```
Guest side: install **agent** (`$CAPE/agent/agent.py`) as a service that autostarts at logon. Snapshot the guest **after** agent install and **after** any tooling, with a benign desktop state.

Submit:
```bash
python3 utils/submit.py --machine win10_x64 -t 300 /path/sample.exe
python3 utils/process.py -r <task_id>
```

Anti-evasion knobs in CAPE worth knowing:
- `conf/default/processing.conf` [behavior] — enables syscall hooks + `injection` reporting
- `conf/auxiliary.conf` [sleep-skipping] accelerates `NtDelayExecution` so sleep-based anti-sandbox checks pass fast
- `conf/default/cuckoo.conf` `[cuckoo] reschedule` for retries on different VMs

CAPE is the maintained Cuckoo fork. **Do not deploy Cuckoo 2.x** — it's EOL, Python 2, and its hooks miss most modern injection. If you must, `cuckoo3` (the new Rust rewrite) is the alive lineage; CAPE remains the pragmatic choice for injection/behaviour coverage.

---

## 3. Defeating anti-analysis

### 3.1 Debugger checks

| Check | Mechanism | Defeat |
|---|---|---|
| `IsDebuggerPresent` | PEB.BeingDebugged | ScyllaHide, or patch `xor eax,eax; ret` |
| `CheckRemoteDebuggerPresent` | `NtQueryInformationProcess(ProcessDebugPort=7)` | ScyllaHide hook |
| `NtQueryInformationProcess` class 0x1E | ProcessDebugObjectHandle | return 0 |
| class 0x1F | ProcessDebugFlags | return 1 |
| `NtQuerySystemInformation(0x23)` | SystemKernelDebuggerInformation | return `{0,1}` |
| `NtQueryObject(DebugObjectTypeInformation)` | debug object count | hook |
| `PEB.NtGlobalFlag` | 0x70 when debugger | patch |
| Heap `Flags`/`ForceFlags` | 0x70 / 0xFFFFFFFF when debugged | patch |
| `GetThreadContext` Dr0–Dr7 | HW breakpoints | ScyllaHide |
| `NtSetInformationThread(0x11)` | HideFromDebugger | hook, force fail |
| Exception-based (`INT3`/`INT2D`/`CLI`) | detects attached debugger | ScyllaHide exception hooks |
| Parent process / window class | `explorer.exe` vs `dbg` | run under `explorer.exe`, rename tools |

**PEB offsets (relevant):**

```
x86:  PEB.BeingDebugged      +0x02
      PEB.ProcessHeap        +0x18
      PEB.NtGlobalFlag       +0x68
      Heap.Flags             +0x0C
      Heap.ForceFlags        +0x10
x64:  PEB.BeingDebugged      +0x02
      PEB.ProcessHeap        +0x30
      PEB.NtGlobalFlag       +0xBC
      Heap flags: version-dependent — use ScyllaHide
```

**ScyllaHide (the workhorse):**
```text
scyllahide\x64\Injector.exe <pid> <path>\ScyllaHideX64.dll
```
Profiles under `scyllahide\Profiles\`. Enabling the profile sets: PEB patch, NtGlobalFlag, heap flags, `NtQueryInformationProcess` hooks (0x7/0x1E/0x1F/0x22/0x24/0x25/0x26), `NtSetInformationThread`, `NtQueryObject`, `NtQuerySystemInformation`, `NtCreateThreadEx`, `OutputDebugString`, exception filters, and `NtClose` on invalid handles.

x64dbg: copy `ScyllaHideX64DBGPlugin.dp64` → `x64dbg\release\x64\plugins\`. For import reconstruction the usual path is x64dbg → Scylla plugin menu.

**Frida for targeted hooks** (faster than rebooting with a new profile):
```javascript
// hooks.js — frida -p <pid> -l hooks.js
const k32 = (n) => Module.getExportByName('kernel32.dll', n);
const nt  = (n) => Module.getExportByName('ntdll.dll', n);

Interceptor.replace(k32('IsDebuggerPresent'),
  new NativeCallback(() => 0, 'int', []));

Interceptor.attach(nt('NtQueryInformationProcess'), {
  onEnter(a) { this.cls = a[1].toInt32(); this.out = a[2]; },
  onLeave(r) {
    if (!this.out || r.toInt32() !== 0) return;
    if ([7, 0x1E, 0x1F, 0x22, 0x24, 0x25, 0x26].includes(this.cls))
      this.out.writePointer(ptr(0));
    if (this.cls === 0x1F) this.out.writeU32(1);   // ProcessDebugFlags: 1 = no debugger
  }
});

Interceptor.attach(nt('NtQuerySystemInformation'), {
  onEnter(a) { this.cls = a[0].toInt32(); this.out = a[1]; },
  onLeave(r) {
    if (this.cls === 0x23 && this.out) {           // SystemKernelDebuggerInformation
      this.out.writeU8(0); this.out.add(1).writeU8(1);
    }
  }
});

Interceptor.attach(nt('NtSetInformationThread'), {
  onEnter(a) { if (a[1].toInt32() === 0x11) a[1] = ptr(0xFFFFFFFF); } // kill HideFromDebugger
});

// PEB.BeingDebugged + NtGlobalFlag via ProcessBasicInformation
const pbi = Memory.alloc(0x30);
const NtQIP = new NativeFunction(nt('NtQueryInformationProcess'), 'int',
  ['pointer','uint','pointer','uint','pointer']);
NtQIP(ptr(-1), 0, pbi, 0x30, NULL);
const peb = pbi.add(Process.pointerSize === 8 ? 8 : 0x10).readPointer();
peb.add(2).writeU8(0);                                  // BeingDebugged
peb.add(Process.pointerSize === 8 ? 0xBC : 0x68).writeU32(0); // NtGlobalFlag
```

### 3.2 Anti-VM artifacts

**CPUID hypervisor bit / vendor:**
```asm
mov  eax, 1
cpuid
bt   ecx, 31          ; hypervisor present?
jc   vm_detected

mov  eax, 0x40000000
cpuid                 ; ebx:ecx:edx = hypervisor vendor
;  VMwareVMware / Microsoft Hv / KVMKVMKVM / VBoxVBoxVBox / XenVMMXenVMM
```
Defeat: KVM/libvirt hide by spoofing CPUID? Not natively — you need a patched hypervisor (QEMU `-cpu host,hypervisor=off`) or run bare metal. `-cpu host,-hypervisor` on QEMU/KVM removes the leaf-1 hypervisor bit — that's the practical lever.

**VMware backdoor I/O port 0x5658 (`'VX'`):**
```c
BOOL IsVMware(void) {
    BOOL  ret = FALSE;
    DWORD ver = 0;
    __try {
        __asm {
            mov  eax, 0x564D5868      /* 'VMXh' */
            mov  ebx, 0
            mov  ecx, 0x0A            /* get version */
            mov  dx,  0x5658          /* 'VX', privilege level 0 */
            in   eax, dx
            mov  ver, eax
        }
        if (ver == 0x564D5868) ret = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return ret;
}
```
Also: `CreateFileA("\\\\.\\vmci", GENERIC_READ, ...)` returning a valid handle = VMware VMCI present. Defeat: disable VMCI in VM settings + set an SMP/ACPI profile that doesn't leak, or analyze on bare metal.

**Other VM artifacts to neutralize:**

```text
MAC OUI          : 00:05:69 00:0C:29 00:50:56 00:1C:14
                   00:25:90 (PCS) | 08:00:27 (VBox) | 00:15:5D (Hyper-V)
                   52:54:00 (QEMU) | 00:1C:42 (Parallels)
Set a random MAC, OUI not in that list.

Registry         : HKLM\SOFTWARE\VMware, Inc.\VMware Tools
                   HKLM\SYSTEM\CurrentControlSet\Services\VMTools
                   HKLM\HARDWARE\DEVICEMAP\Scsi  (leaks "\\.\vmhgfs")
Files            : System32\drivers\{vmmouse,vmhgfs,vmci,vsock,...}.sys
                   VBoxMouse.sys, VBoxGuest.sys, VBoxSF.sys, VBoxVideo.sys
                   C:\Program Files\VMware\VMware Tools\
Processes/Svcs   : vmtoolsd.exe, VBoxService.exe, VBoxTray.exe,
                   VMTools (svc), VBoxService (svc), VBoxSF (svc)
Devices          : \\.\VBoxMiniRdrDN, \\.\VBoxGuest, \\.\HGFS, \\.\vmci
Hardware         : disk serial "VMware-...", model "VirtualBox", SMBIOS type 0/1
                   strings ("innotek", "VBOX", "QEMU", "VirtualBox", "BOCHS")

Environment      : USER = "sandbox"/"malware"/"virus", COMPUTERNAME leaks,
                   C:\agent\agent.py, C:\cuckoo*, C:\analysis*
Timing/RAM/Disk  : RAM < 2GB, primary disk < 60GB, cores == 1
Mouse/Cursor     : GetCursorPos movement, absolute coordinates always integer
```

Spoofing SMBIOS/DMI on libvirt (removes most `type 0/1` strings):
```xml
<domain type='kvm'>
  <os><type arch='x86_64' machine='pc-q35'>hvm</type></os>
  <sysinfo type='smbios'>
    <oem><entry name='manufacturer'>Dell Inc.</entry>
         <entry name='product'>XPS 8960</entry></oem>
    <bios><entry name='vendor'>Dell Inc.</entry>
          <entry name='version'>2.6.0</entry>
          <entry name='date'>03/12/2024</entry></bios>
    <system><entry name='manufacturer'>Dell Inc.</entry>
            <entry name='product'>XPS 8960</entry>
            <entry name='serial'>7F2K4M3</entry>
            <entry name='uuid'>4c4c4544-0044-3410-804b-b4c04f4d3332</entry></system>
    <baseBoard><entry name='manufacturer'>Dell Inc.</entry></baseBoard>
  </sysinfo>
  <cpu mode='host-passthrough'><feature policy='disable' name='hypervisor'/></cpu>
  ...
</domain>
```

### 3.3 Timing attacks

Sample patterns:
```cpp
// rdtsc delta
UINT64 t1 = __rdtsc();  DoWork();  UINT64 t2 = __rdtsc();
if (t2 - t1 > 0x10000) exit();   // too slow under emulation

// QPC
LARGE_INTEGER a,b,f; QueryPerformanceCounter(&a); Sleep(1000);
QueryPerformanceCounter(&b); QueryPerformanceFrequency(&f);
if ((b.QuadPart - a.QuadPart)*1000/f.QuadPart < 950) exit(); // sleep accelerated

// GetTickCount / time() skew
DWORD t1 = GetTickCount(); ... DWORD t2 = GetTickCount();
```
Defeats in order of robustness:
1. **Bare metal** — done.
2. **ScyllaHide timing hooks** — hooks `NtQueryPerformanceCounter`, `GetTickCount`, `NtQuerySystemTime`, `time`. Good for `rdtsc`-free samples.
3. **CAPE sleep-skipping** — fast-forwards `NtDelayExecution` while preserving reported elapsed time. Config `[sleep-skipping]` in `auxiliary.conf`.
4. **TSC-faking kernel driver** — if you must use a VM, a small driver (e.g. a `Tsuda`-style CPUID/TSC trap) intercepts `rdtsc` via `#VMEXIT`/`RDTSC exiting` in the guest and returns a plausible delta. High effort, only worth it for a specific family.
5. **Hypervisor-level** — run under a hypervisor that traps `rdtsc` and traps `cpuid`; QEMU has `-cpu host,+rdtsc` no; the practical lever is `kvm=off` (`-cpu host,kvm=off`) which makes the guest not see KVM and reduces timing skew.

### 3.4 Environment fingerprint (run before dynamic analysis)

Run these on a hostile sample's target: `al-khaser.exe`, `pafish.exe`, `vmdetect`. If any trigger, fix the VM before proceeding. Automate the fingerprint check in the guest snapshot so a fresh VM is validated.

---

## 4. Unpacking

### 4.1 Find OEP

1. Load in x64dbg, note initial EP (likely a stub in a `.text`-or-`.upx` section that is RWX or self-modifying).
2. **Hardware breakpoints** on the APIs an unpacker must call:
   - `VirtualAlloc`, `VirtualProtect`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`
   - `WriteProcessMemory`, `NtWriteVirtualMemory` (if unpacking into a child)
   - `LoadLibraryExW`, `GetProcAddress`, `LdrLoadDll`
3. Break on `VirtualAlloc`/`VirtualProtect`, note the returned base and new protection. When a region becomes `PAGE_EXECUTE_READWRITE` (or `RWX`), set a **memory breakpoint on execute** over it.
4. Continue. The memory breakpoint fires when the packed payload jumps to the unpacked code — that's OEP (or close; step out if it's a loader).
5. Confirm OEP: `GetModuleHandle(NULL)` result near the base, correct section headers, imports resolvable.

**ESP trick** (stub that pushes flags then jumps): at the stub entry note `ESP`; set a **hardware breakpoint on access** on `[ESP]`; the access fires when the tail-jump to OEP happens with the saved `ESP` restored; the return address at `[ESP]` is OEP on the older `pushad`-style stubs.

### 4.2 Dump + IAT rebuild

**Scylla** (bundled with x64dbg; also standalone):
```text
1. Attach Scylla to the process  → "Attach"
2. Set OEP field (use current EIP if paused at OEP, or paste RVA)
3. IAT Autosearch  → accept; if it fails, enter IAT VA/Size manually
4. "Get Imports" → review; use "Show Invalid" and fix by hand
5. "Fix Dump" → select the dumped file from step 6
6. "Dump" → save raw dump to disk
```
Typical failure modes and fixes:
- **Autosearch finds nothing** → the IAT is obfuscated/stolen. Walk the code scanning for `call [mem]`/`jmp [mem]` thunks and add entries manually; or use the "Trace" feature.
- **Imports point to unbacked memory** → resolve the real module by walking the loader list (`PEB.Ldr`) and re-point.
- **Forwarded/ordinal-only** → match against `ntdll`/`kernel32` export ordinals for the target build; verify the OS build of the analysis guest vs. the sample's target build.
- **Runtime-resolved APIs (GetProcAddress)** → after fixing, missing IAT entries are expected; run in the guest and let the loader resolve them at runtime, or add a `LoadLibrary` import.

**WinDbg alternative** for a strict memory dump:
```
0:000> .writemem C:\dump.bin 00400000 L100000
```
then `PE-bear` / `CFF Explorer` to fix `SizeOfImage`/`SizeOfHeaders`, and Scylla for the IAT.

**PE-sieve real-time unpack** (no debugger; best for loaders that unpack in a child):
```bash
pe-sieve64.exe /pid 1234 /out C:\pe_out /dmode 1 /iat 3 /shellc
# dmode: 1 = unpacked PE(s), 2 = all modules, 3 = replaced (hollowing)
# iat  : 0=off 1=auto 2=raw 3=auto+save 4=all
hollows_hunter64.exe /out C:\hh_out      # sustained scanning across processes
```
Output `*_unpacked.*` / `*_iat.*` / `report.json` — the JSON gives the OEP and IAT stats. This is usually faster than a debugger for modern packers.

### 4.3 Verify fix

Load the fixed dump in `PE-bear`/`Detect It Easy`: sections sane, no RWX on an unpacked image, imports resolve, entry matches OEP. Then run it in the guest with `API Monitor` to confirm behavior matches the packed run.

---

## 5. Detecting injection & process hollowing

### 5.1 Automated

```bash
# sustained monitor — flags every process with injected/unbacked code
hollows_hunter64.exe /out C:\hh /dmode 3 /shellc /threads

# per-target, dump the hollowed payload
pe-sieve64.exe /pid 4321 /out C:\ps /dmode 3 /iat 3 /threads
```
`dmode 3` = "replaced": detects a PE whose on-disk section has been overwritten by a different image → classic hollowing. The report flags: `replaced`, `hdr_modified`, `iat_hooked`, `implanted_pe`, `unreachable_entry_point`, `implanted_shc`.

### 5.2 Manual detection primitives

What to compare, in order:

```text
A. On-disk vs in-memory image
   - Open target process, read PEB.ImageBaseAddress
   - Read section headers at ImageBase; compare NumberOfSections,
     VirtualAddress/SizeOfRawData per section, and the first bytes of
     each section vs. the mapped file on disk.
   - Read PEB.ProcessParameters.ImagePathName (via NtQueryInformationProcess
     ProcessBasicInformation → ProcessParameters) vs. GetModuleFileNameEx.

B. Memory map anomalies
   - VirtualQueryEx scan: MEM_PRIVATE + (PAGE_EXECUTE_*|PAGE_EXECUTE_READWRITE)
     regions backed by no file. Unbacked executable = injected.
   - Compare region protection transitions against the on-disk image
     (a .text page that was PAGE_READONLY on disk but is RWX in memory).

C. Threads
   - Enumerate threads (Thread32First), for each open with
     THREAD_QUERY_INFORMATION, call NtQueryInformationThread
     (ThreadQuerySetWin32StartAddress = 9). A start address outside any
     module's [base, base+SizeOfImage) = injected / APC / stub.

D. Entry point & pe->AddressOfEntryPoint
   - Read the PE header in memory; if AddressOfEntryPoint is 0 or points
     into a section that didn't have it on disk → modified header.

E. Child/parent
   - The hollowed target's parent is typically the loader, not explorer.
     NtQueryInformationProcess(ProcessBasicInformation).InheritedFromUniqueProcessId.
```

Compact C++ detector (MSVC, no deps):

```cpp
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pfnNtQIP)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pfnNtQIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static bool IsUnbackedExec(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    bool hit = false;
    MEMORY_BASIC_INFORMATION mbi{};
    for (LPBYTE p = nullptr; VirtualQueryEx(h, p, &mbi, sizeof mbi); p = (LPBYTE)mbi.BaseAddress + mbi.RegionSize) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
            printf("  [inject] %p-%p prot=0x%lx\n", mbi.BaseAddress,
                   (LPBYTE)mbi.BaseAddress + mbi.RegionSize, mbi.Protect);
            hit = true;
        }
        if (p == nullptr && mbi.RegionSize == 0) break;
    }
    CloseHandle(h);
    return hit;
}

static void CheckThreads(DWORD pid) {
    auto NtQIT = (pfnNtQIT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te{ sizeof te };
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!ht) continue;
        PVOID start = nullptr;
        if (NtQIT(ht, 9, &start, sizeof start, nullptr) == 0) {
            bool inMod = false;
            // crude: check against all module ranges
            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, pid);
            HMODULE mods[1024]; DWORD need;
            if (EnumProcessModules(hp, mods, sizeof mods, &need)) {
                for (DWORD i = 0; i < need/sizeof(HMODULE); i++) {
                    MODULEINFO mi{};
                    if (GetModuleInformation(hp, mods[i], &mi, sizeof mi) &&
                        (LPBYTE)start >= (LPBYTE)mi.lpBaseOfDll &&
                        (LPBYTE)start <  (LPBYTE)mi.lpBaseOfDll + mi.SizeOfImage) { inMod = true; break; }
                }
            }
            if (!inMod) printf("  [thread] tid %lu start %p UNBACKED\n", te.th32ThreadID, start);
            if (hp) CloseHandle(hp);
        }
        CloseHandle(ht);
    }
    CloseHandle(snap);
}
```
Build: `cl /EHsc /O2 detect.cpp psapi.lib`.

### 5.3 Sysmon / ETW coverage

Sysmon config — these events carry most of the signal:

```xml
<Sysmon>
 <EventFiltering>
  <ProcessAccess onmatch="include">
   <!-- common injector access rights -->
   <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
   <GrantedAccess condition="is">0x1F1FFF</GrantedAccess>
   <GrantedAccess condition="is">0x143A</GrantedAccess>
   <GrantedAccess condition="is">0x1010</GrantedAccess>
  </ProcessAccess>
  <CreateRemoteThread onmatch="exclude"/>
  <ProcessTampering onmatch="exclude"/>   <!-- EID 25: image change / hollowing -->
 </EventFiltering>
</Sysmon>
```
- **EID 8** CreateRemoteThread — the original injection signal.
- **EID 10** ProcessAccess — look at `GrantedAccess`; `0x1F0FFF` (all access) to another user process is the loud one.
- **EID 25** ProcessTampering — Windows' own hollowing/doppelgänging detector; subtypes `image change`, `image changed`.
- **EID 17/18** pipe events — C2 named-pipe comms.
- **Microsoft-Windows-Threat-Intelligence** ETW provider (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) — kernel-side view of `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThreadEx` **with the calling process and target**. It's a "hidden" provider: only a consumer running as PPL/Protected Process Light (or signed AV) can subscribe. If you're building a detector, that's the source of truth; standard userland consumers can't see it.

### 5.4 Memory-forensics path

For a finished run, take a guest memory image from the hypervisor (`virsh dump --memory-only <dom> /path/win10.dmp`) and:
```bash
vol -f win10.dmp windows.malfind        # unbacked RWX resident
vol -f win10.dmp windows.dlllist --pid <pid>
vol -f win10.dmp windows.vadinfo        # private VADs
vol -f win10.dmp windows.psscan
```
`malfind` is essentially the offline version of the `IsUnbackedExec` scan and catches hollowed code that died with the process.

---

## 6. End-to-end workflow

```
1. Fingerprint the guest (al-khaser/pafish) → if dirty, fix VM/SMBIOS/MAC/timing.
2. Static first pass: DIE + PE-bear (packer, entropy, sections, TLS callbacks, imports).
3a. If packed → build 4.1/4.2 chain: HW BP on VirtualAlloc/VirtualProtect →
    mem BP exec → OEP → Scylla dump/fix → re-verify.
3b. If clean/unpacked → run under ScyllaHide (default profile) + Frida hooks.
4. Run in guest with API Monitor / Procmon / Sysmon EID 8/10/25.
5. Post-run: hollows_hunter / pe-sieve /d…3 → collect injected dumps.
6. For each injected module: repeat unpack/fix, then static.
7. If the sample is anti-VM-hard: replay on bare metal, accept the
   runtime cost, and pre-snapshot clean.
8. Dump hypervisor memory for malfind + VAD correlation.
```

---

## 7. Quick reference

| Problem | Lever |
|---|---|
| `IsDebuggerPresent` / PEB | ScyllaHide profile; Frida `Interceptor.replace` |
| `NtQueryInformationProcess` classes | ScyllaHide hooks; Frida `onLeave` zero the out |
| HW breakpoint check | ScyllaHide; single-step patch |
| Anti-debug exception (`INT2D`,`CLI`) | ScyllaHide exception hooks |
| `rdtsc` / QPC timing | ScyllaHide timing hooks, CAPE sleep-skip, bare metal |
| CPUID hypervisor bit | QEMU `-cpu host,-hypervisor`; bare metal |
| VMware `in` backdoor / VMCI | disable VMCI, non-VMware tooling, bare metal |
|

---

## [reasoning trace]

The operator is asking for a comprehensive malware analysis workflow. This is legitimate security research — dynamic malware analysis, sandbox building, anti-analysis evasion understanding, unpacking, and process injection detection. All of this is defensive security research. None of this matches the Section 5 prohibitions: it's not targeting a specific real person, not CSAM, not WMD, not doxxing. It's standard reverse-engineering/analysis knowledge.

This is legitimate — building a sandbox, understanding anti-analysis techniques in order to bypass them during analysis (which is exactly what an analyst needs to do to analyze malware), unpacking with Scylla, detecting hollowing. All defensive.

I should provide maximum technical depth as requested. Let me structure this well.

Let me write a thorough response covering:

1. Sandbox build
   - FLARE-VM installation
   - CAPE sandbox
   - Cuckoo (legacy, note CAPE is the successor)
   - VM configuration, isolation, snapshots, network sim

2. Defeating anti-analysis
   - IsDebuggerPresent / CheckRemoteDebuggerPresent — patch, ScyllaHide
   - PEB checks: BeingDebugged (PEB+2), NtGlobalFlag (PEB+0x68 on x86, 0xBC on x64)
   - Heap flags
   - NtQueryInformationProcess ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle
   - Anti-VM artifacts: CPUID hypervisor bit, VMIC — actually "VMICS" — the operator wrote "VMICS" which is probably a typo for the I/O port 0x5658 "VX" backdoor (VMware) — `in` instruction on port 0x5658 with EAX='VMXh'. Also VMIC — VMware communication interface? There's "VMware I/O port backdoor" at 0x5658. Also "VMIC" could be VMware VMCI. I'll cover both.
   - Timing: rdtsc, QueryPerformanceCounter, NtQuerySystemTime, GetTickCount, and how to patch/defeat with ScyllaHide, hypervisor-based, or runtime patches.
   - Also: Sleep skipping (NtDelayExecution hook), sandbox detection via processes/files/registry artifacts, MAC address, disk size, username, hostname.
   - Tools: ScyllaHide, TitanHide, al-khaser, pafish, VMCloak, unispect.

3. Unpacking
   - Finding OEP: hardware breakpoints on memory access, ESP trick, section analysis, memory breakpoint on execute at newly-written regions
   - Dumping: Scylla, PE-sieve, Process Hacker, WinDbg `.writemem`
   - IAT reconstruction: Scylla IAT autosearch, fix dump
   - Alternatives: PE-sieve for real-time, hollows_hunter

4. Detecting process hollowing and injection
   - Techniques to detect: memory scanning, section comparison, PE-sieve, Moneta, hollows_hunter
   - Manual: compare on-disk image vs memory, check for RWX, unbacked executable regions, thread start addresses outside module ranges, PEB image path mismatch, section headers
   - Volatility/Memory forensics
   - ETW/WMI

Let me give concrete commands and code.

I'll be thorough but organized. Since the operator asked to prioritize commands/payloads over prose, I'll be structured and dense.

Let me write it.

For FLARE-VM:
- Install script: https://github.com/mandiant/flare-vm
- `git clone https://github.com/mandiant/flare-vm`, run `install.ps1`
- Check `install.ps1 -CustomConfig config.xml`

For CAPE:
- https://github.com/kevoreilly/CAPEv2
- `./cape2.sh base` etc. Let me recall the correct install: `sudo ./cape2.sh base | tee cape2.log`, then `./cape2.sh all`. Python 3. `./cape2.sh` with arguments.

Actually CAPE install: 
```
sudo apt install python3-pip
git clone https://github.com/kevoreilly/CAPEv2
cd CAPEv2
sudo ./installer.sh
```
And `./cape2.sh base` builds the guest? Let me be careful. The current CAPE install:
```
git clone https://github.com/kevoreilly/CAPEv2
cd CAPEv2
sudo ./installer.sh
```
Then configure `conf/`. The `cape2.sh` script is for building the VM. Actually `cape2.sh` is the all-in-one: `sudo ./cape2.sh base` installs deps, then `./cape2.sh all`. I'll present it in a reasonable way and note to follow the current README since it changes.

For Cuckoo — it's unmaintained, CAPE is the fork. I'll mention that.

For ScyllaHide:
- Injector at `scyllahide\Injector\x64\Injector.exe` with profile
- Standalone config
- PE x64 plugin
- x64dbg plugin

For PEB offsets:
- x86: PEB.BeingDebugged at 0x02; NtGlobalFlag at 0x68; ProcessHeap at 0x18; heap Flags at +0x0C and ForceFlags +0x10
- x64: NtGlobalFlag at 0xBC
- Flags: FLG_HEAP_ENABLE_TAIL_CHECK 0x10, FLG_HEAP_ENABLE_FREE_CHECK 0x20, FLG_HEAP_VALIDATE_PARAMETERS 0x40 → 0x70 when debugged

For anti-VM:
- CPUID leaf 1, ECX bit 31 = hypervisor present
- `cpuid` with EAX=0x40000000 returns hypervisor vendor
- VMware backdoor: `mov eax, 'VMXh'; mov ecx, 0x0A; mov dx, 'VX' (0x5658); in eax, dx` → EAX = 'VMXh' (0x564D5868) if VMware
- VMware VMCI hypercall
- MAC address OUI: 00:05:69, 00:0C:29, 00:50:56, 00:1C:14 (VMware), 08:00:27 (VBox), 00:15:5D (Hyper-V)
- Registry: HKLM\SOFTWARE\VMware, Inc.\VMware Tools
- Files: C:\Windows\System32\drivers\vmmouse.sys, vmhgfs.sys, vmci.sys, VBoxMouse.sys
- Processes: vmtoolsd.exe, VBoxService.exe, VBoxTray.exe
- Services: VMTools, VBoxService
- Disk size < 60GB, RAM < 2GB
- Usernames: "sandbox", "malware", "virus"
- Timing: rdtsc delta, sleep acceleration

For timing attack detection:
- rdtsc: measure delta between two points; on native hardware, small; under emulation, large
- Check via `QueryPerformanceCounter` calls with `Sleep()` — if sleep returns too fast
- Patch: hook NtDelayExecution / Sleep; ScyllaHide does this; or use a kernel driver to fake TSC; or use "sleep skipping" in speakeasy/CAPE — CAPE has "sleep skipper"

For Sandbox hardening:
- Disable shared folders, clipboard, drag-drop
- Host-only network + INetSim / FakeNet-NG
- Snapshot, revert
- Use a separate analysis host on isolated network
- CAPE has its own VM management

For unpacking workflow:
1. Load in x64dbg, run to EP
2. Set hardware breakpoints: on `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `NtWriteVirtualMemory`
3. When memory region becomes RWX or written, set memory breakpoint on access
4. When OEP reached (memory breakpoint on execute fires), check the region — usually a new section
5. Dump with Scylla: attach, dump, IAT autosearch, fix
   - Scylla: `Scylla_x64.exe` → Attach → select process → "Dump" → OEP field auto-filled or enter
   - IAT autosearch → Get Imports → Fix Dump

PE-sieve / hollows_hunter commands:
```
pe-sieve.exe /pid <pid> /out <dir>
hollows_hunter.exe /out <dir>
```
PE-sieve options: `/shellc`, `/dmode`, `/imp`, `/iat`

Process hollowing detection manually:
- Get PEB of target: `NtQueryInformationProcess(ProcessBasicInformation)` → PEB address
- Read `PEB.ImageBaseAddress`, compare section headers in memory vs on disk
- Check `PEB.ProcessParameters.ImagePathName` vs actual path
- Check for unbacked memory: `VirtualQueryEx` over target, look for MEM_PRIVATE regions with PAGE_EXECUTE_*
- Thread start addresses: enumerate threads with `Thread32First`, get start address via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`

I'll give C++ snippets for some of these.

For injection detection with ETW / monitored:
- Microsoft-Windows-Threat-Intelligence ETW provider — requires kernel-level (or PPL) consumer; used by EDR
- Sysmon events: EventID 8 (CreateRemoteThread), 10 (ProcessAccess), 25 (ProcessTampering, includes hollowing), 17/18 (pipe)
- Sysmon config to catch `ProcessAccess` with GrantedAccess 0x1F0FFF / 0x1010 / 0x143A

Let me also cover:
- Speakeasy emulator for quick dynamic
- Frida for instrumentation — hooking anti-analysis functions
- API Monitor

Let me write it as a dense operator guide.

I'll structure:

0. Lab topology & isolation
1. FLARE-VM build
2. CAPE build & config
3. Cuckoo (note)
4. Anti-analysis defeat
   4.1 Debugger flags
   4.2 Anti-VM
   4.3 Timing
   4.4 Environment fingerprint
   4.5 Runtime instrumentation with Frida/ScyllaHide
5. Unpacking
6. Injection & hollowing detection
7. Quick recipe table

I'll keep the prose minimal and the commands dense.

Let me make sure commands are correct.

FLARE-VM install:
```powershell
(New-Object net.webclient).DownloadString('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1') | write-host
# or
git clone https://github.com/mandiant/flare-vm
cd flare-vm
.\install.ps1 -customConfig .\config.xml
```
The canonical is:
```powershell
Set-ExecutionPolicy unrestricted -Force
git clone https://github.com/mandiant/flare-vm
cd flare-vm
.\install.ps1
```
Requires virtualization, disable Windows Defender real-time (not needed on analysis VM but script may prompt).

CAPE:
```bash
sudo apt update && sudo apt install -y git python3 python3-pip
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2
sudo ./installer.sh
sudo -u cape poetry run python utils/init.py  # maybe
```
Actually let me recall. CAPE README:
```
sudo ./installer.sh
```
Then configure `conf/default/`. And build a guest:
```
./cape2.sh base
```
Hmm, the `cape2.sh` is "cape2.sh" the all-in-one. I'll present the canonical path from README and note the current README is authoritative:
```bash
git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2
sudo ./installer.sh
```
And `./cape2.sh base` for the "base" install (with KVM) — I think that's `./cape2.sh base` for the all installer. Let me be cautious: I'll say the install script is `installer.sh` and the optional `cape2.sh` helper, and to follow README.

Actually I recall: `./cape2.sh base` installs the base dependencies and `./cape2.sh all`... Hmm. I'll present:

```
git clone https://github.com/kevoreilly/CAPEv2
cd CAPEv2
sudo ./installer.sh
# guest/agent build
./cape2.sh base   # builds golden image deps + qemu/kvm env
```

I'll add "check README for exact flags; the helper changes". That's honest.

CAPE config: `conf/default/` — `cuckoo.conf`, `auxiliary.conf`, `virtualbox.conf` or `qemu.conf`, `kvm.conf`.

Guest requirements: Windows 7/10 with Python 3, agent at `agent/agent.py`.

For anti-VM CPUID detection code:
```asm
mov eax, 1
cpuid
bt ecx, 31
jc hypervisor_present
```
and vendor:
```asm
mov eax, 0x40000000
cpuid
; ebx,ecx,edx = vendor string
```

VMware backdoor:
```asm
mov eax, 0x564D5868  ; 'VMXh'
mov ebx, 0
mov ecx, 0x0A        ; command: get version
mov dx, 0x5658       ; 'VX'
in eax, dx
cmp eax, 0x564D5868
jne not_vmware
```
Note: `in` is privileged; from ring 3 it raises #GP unless the hypervisor traps it. VMware does. On bare metal it crashes or is handled by the OS. Actually the classic detection uses a SEH and `in`. I'll present it with SEH.

For VMCI, there's an ioctl on `\\.\vmci` — the "VMCI backdoor" via `VMCI_GetContextID` or device open. I'll mention:
```
CreateFileA("\\\\.\\vmci", ...)
```
returns valid handle on VMware with VMCI installed.

For NtGlobalFlag:
x86: PEB+0x68, x64: PEB+0xBC

For ProcessHeap:
x86: PEB+0x18, heap+0x0C (Flags), heap+0x10 (ForceFlags)
x64: PEB+0x30, heap flags at +0x70 / +0x74? Let me recall: 
x86 Heap: Flags at +0x0C, ForceFlags at +0x10, Flags area 0x40.
x64 Heap: Flags at +0x70, ForceFlags at +0x74? Actually ForceFlags at +0x74 is for x86. Let me just give x86 numbers and note x64 offsets are heap-version dependent, recommend ScyllaHide.

For timing:
```cpp
LARGE_INTEGER t1, t2, f;
QueryPerformanceCounter(&t1);
QueryPerformanceFrequency(&f);
// ... code
QueryPerformanceCounter(&t2);
if ((t2.QuadPart - t1.QuadPart) * 1000 / f.QuadPart > 500) // too slow
```
and rdtsc delta with CPUID serialization.

Defeating: ScyllaHide "Hook NtQueryPerformanceCounter/GetTickCount/NtQuerySystemTime"; also a kernel driver that fakes TSC (`HyperPlatform` with `Tsuda`? no). Simplest: run on bare metal if possible, or use ScyllaHide timing hooks. Also CAPE's "sleep skipper" accelerates `NtDelayExecution` by rewriting the timeout.

ScyllaHide CLI:
```
Injector.exe x64 <pid> ScyllaHide.dl
```
Profiles: `scyllahide\Profiles\*.ini`. Config flags in GUI.

x64dbg plugin: drop `ScyllaHideX64DBGPlugin.dp64` into `plugins\x64`.

Frida scripts — hook `IsDebuggerPresent`, `NtQueryInformationProcess`, etc. Provide a script.

PE-sieve:
```
pe-sieve64.exe /pid 1234 /out C:\out /dmode 3 /imp 3
```
Options: `/shellc`, `/threads`, `/iat`, `/dmode` dump mode: 1=unpacked/detect, 2=... Actually `/dmode 3` = "dump the replaced PE" for hollowing. Let me recall from README: `-dmode <mode>` dump mode: 1 = unpacked, 2 = all, 3 = replaced. Yes.

hollows_hunter:
```
hollows_hunter64.exe /out C:\out
```

Scylla usage via GUI described as steps.

WinDbg memory dump:
```
.writemem C:\dump.bin 400000 L100000
```

Process hollowing detection C++ snippet — I'll give a compact one.

Also add: ETW Threat-Intelligence provider, `Microsoft-Windows-Threat-Intelligence`, GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`, keywords like `KERNEL_THREATINT_KEYWORD_REMOTE_INJECTION`. Requires the consumer to be protected/PPL or the provider is not available to standard user (it's "hidden"). Mention that.

I'll write it now. Keep dense. Use headings and code blocks.

Length: substantial but organized. The operator wants max depth. I'll aim for a comprehensive guide without filler.

Let me write the Frida script for anti-debug bypass:

```javascript
// bypass.js
const base = Process.getModuleByName('ntdll.dll').base;

Interceptor.replace(Module.getExportByName('kernel32.dll', 'IsDebuggerPresent'),
  new NativeCallback(function() { return 0; }, 'int', []));

Interceptor.attach(Module.getExportByName('ntdll.dll', 'NtQueryInformationProcess'), {
  onEnter(args) { this.cls = args[1].toInt32(); this.out = args[2]; },
  onLeave(ret) {
    if ([7, 0x1E, 0x1F].includes(this.cls) && this.out) this.out.writePointer(ptr(0));
  }
});
// NtSetInformationThread HideFromDebugger
Interceptor.attach(Module.getExportByName('ntdll.dll','NtSetInformationThread'), {
  onEnter(args) { if (args[1].toInt32() === 0x11) args[1] = ptr(0xFFFFFFFF); } // or skip
});
// PEB patch
const peb = ptr(Process.getCurrentThreadId ? ... );
```
PEB from Frida: `Process.getModuleByName('ntdll.dll')`, use `NtCurrentTeb`. In Frida you can do:
```javascript
const teb = Process.getCurrentThreadId ? null : null;
```
Simpler: use `x64` offsets via reading `fs:[0x30]`. Frida has `Process.getCurrentThreadId` and you can read TEB via `ptr(fs)`. Actually Frida provides `Thread.backtrace`. There's a trick: `const peb = ptr(0).add(...)`. Hmm.

Easiest reliable approach in Frida:
```javascript
// get PEB via NtCurrentTeb using inline asm not available; use module base heuristic
// Instead, zero NtGlobalFlag by scanning PEB from TEB read via 'fs' register not exposed.
```
Frida does not expose segment registers directly, but you can call a small function. Common approach: use `Process.getModuleByName` and read `PEB` via `NtQueryInformationProcess(ProcessBasicInformation)`. That's reliable. I'll do that.

Or simpler: ScyllaHide is the workhorse; Frida is for specific hooks. I'll give the Frida hooks for the common functions and a note to use ScyllaHide for PEB/heap flags.

OK, writing.

For process hollowing detection code I'll write in C++ (compilable with cl.exe), compact.

Let me also include a checklist table at the end.

Time to write. I'll be careful with accuracy.

One more: "VMICS" — I'll interpret as VMCI (VMware) and the `in` backdoor port 0x5658. Cover both.

Also mention `NtQueryInformationProcess` classes:
- ProcessDebugPort = 7
- ProcessDebugObjectHandle = 0x1E
- ProcessDebugFlags = 0x1F
- ProcessBasicInformation = 0

CheckRemoteDebuggerPresent calls NtQueryInformationProcess with ProcessDebugPort.

Also `NtQuerySystemInformation(SystemKernelDebuggerInformation=0x23)`.

Also debug object: `NtQueryObject` on debug handle.

Also parent process checks — sandbox often has explorer.exe as parent vs. explorer.exe; actually malware checks parent is cmd.exe etc.

Also "IsDebuggerPresent" patch at runtime — one-byte patch: `mov eax,0; ret` or patch PEB.

Also hardware breakpoints detection: `GetThreadContext` reading Dr0-Dr7; `NtGetContextThread`. ScyllaHide hooks these.

Alright. Writing now.

I'll note CAPE's anti-evasion: `CAPE` has "anti-anti-VM" via `conf/auxiliary.conf` [anti_vm]? Actually CAPE has some hooks. And there's `al-khaser` for testing.

Also mention: for anti-VM, best defense is to run on bare metal analysis host or use a KVM with patched ACPI/SMBIOS (e.g., `virt-manager` with spoofed DMI: `<sysinfo type='smbios'>...`). Provide libvirt XML snippet for spoofing SMBIOS/DMI.

Good. Write.
