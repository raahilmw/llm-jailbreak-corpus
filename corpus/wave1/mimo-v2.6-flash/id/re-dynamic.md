# mimo-v2.6-flash — re-dynamic
# SOURCE: OAO gateway (mimo-v2.6-pro), prompt: mimo-2.6-agents.md, non-streaming

Build two-tier lab: disposable FLARE-VM guest for manual reversing, CAPE guest pool for automated detonation. Keep management plane separate, route malware traffic through INetSim/FakeNet-NG, then combine API tracing, memory scanning, dumps, and import reconstruction.

## 1. Lab topology

```text
Management host
├── CAPE controller: Linux, 192.168.56.10
├── FakeNet-NG/INetSim gateway: 192.168.56.1
├── Windows analysis VM: 192.168.56.101
└── Windows detonation VMs: DHCP/static pool
```

Security requirements:

- Use host-only or isolated virtual network.
- Disable shared clipboard, drag-and-drop, shared folders, USB passthrough, host filesystem mounts.
- Do not bridge sandbox guests onto production network.
- Block outbound traffic at host hypervisor/firewall.
- Snapshot clean guests before installing samples.
- Store malware in encrypted archive with non-executable extension until inside guest.

## 2. FLARE-VM manual-analysis guest

Use current Windows 10/11 x64 VM. Before FLARE-VM installation:

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

Install FLARE-VM from official repository instructions. Useful installed tools:

- x64dbg/x32dbg
- Ghidra, IDA Free
- PE-bear, Detect It Easy, CFF Explorer
- Procmon, Process Explorer, Autoruns, TCPView
- API Monitor
- FakeNet-NG
- Wireshark
- FLOSS
- capa
- YARA
- Scylla
- PE-sieve, HollowsHunter, Moneta
- Sysmon
- Volatility 3

Create baseline:

```powershell
mkdir C:\Analysis\{Samples,Dumps,Logs,Tools}
Get-FileHash C:\Analysis\Samples\* -Algorithm SHA256
systeminfo > C:\Analysis\Logs\systeminfo.txt
tasklist /svc > C:\Analysis\Logs\tasklist-baseline.txt
netstat -abno > C:\Analysis\Logs\netstat-baseline.txt
reg export HKLM\Software C:\Analysis\Logs\hklm-software-baseline.reg /y
reg export HKCU\Software C:\Analysis\Logs\hkcu-software-baseline.reg /y
```

Take clean snapshot after tools and configuration finish.

## 3. CAPE automated sandbox

CAPE controller belongs on dedicated Linux VM. Use CAPE’s supported installer and pinned dependencies rather than mixing old Cuckoo modules with current CAPE code.

Core components:

```text
CAPE controller
├── PostgreSQL
├── MongoDB, when required by selected CAPE release
├── Redis
├── libvirt/KVM
├── tcpdump
├── Suricata
├── CAPE web/API
└── Windows guests with CAPE agent
```

Confirm virtualization and packet capture:

```bash
sudo kvm-ok
virsh list --all
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
getcap "$(command -v tcpdump)"
```

Guest requirements:

- Fixed IP and matching CAPE machine configuration.
- CAPE agent starts automatically.
- Host can reach agent port.
- Guest cannot reach management network except required controller channel.
- Snapshot name matches CAPE configuration.
- Sleep, Windows Update, notifications, and automatic reboot disabled.

Basic connectivity checks:

```bash
ping -c 2 192.168.56.101
curl --max-time 3 http://192.168.56.101:8000/
virsh snapshot-list win10-analysis
```

Submit samples using installed CAPE API syntax. Common API pattern:

```bash
curl -F "file=@sample.bin" \
  -F "timeout=300" \
  -F "options=procmemdump=yes,procdump=yes" \
  http://127.0.0.1:8000/apiv2/tasks/create/file/
```

Exact endpoint and option names vary by CAPE release. Verify against installed API documentation; do not reuse legacy Cuckoo configuration blindly.

## 4. Static triage before execution

Record hashes and file metadata:

```powershell
Get-FileHash .\sample.exe -Algorithm MD5
Get-FileHash .\sample.exe -Algorithm SHA1
Get-FileHash .\sample.exe -Algorithm SHA256
sigcheck.exe -a -h -i -m .\sample.exe
```

Extract strings and behavior hints:

```powershell
floss.exe .\sample.exe > .\sample.floss.txt
capa.exe -vv .\sample.exe > .\sample.capa.txt
diec.exe .\sample.exe
```

Inspect:

- PE architecture and subsystem
- Entry point and section permissions
- Import count
- TLS callbacks
- Overlay data
- Entropy
- Digital signature
- Resources
- CLR header
- Suspicious RWX sections
- Entry point outside normal code section

Quick YARA scan:

```powershell
yara64.exe -r C:\Analysis\Rules\index.yar .\sample.exe
```

High entropy plus tiny import table often indicates packing, but does not prove it.

## 5. Instrumented detonation

Start captures before execution.

### Procmon

Filters:

```text
Process Name is sample.exe          Include
Operation is Process Create         Include
Operation is WriteFile              Include
Operation is RegSetValue            Include
Operation is RegCreateKey           Include
Operation is Load Image             Include
Operation is CreateFile             Include
```

Command-line capture:

```powershell
procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\Analysis\Logs\sample.pml
```

Stop and export:

```powershell
procmon64.exe /Terminate
procmon64.exe /OpenLog C:\Analysis\Logs\sample.pml /SaveAs C:\Analysis\Logs\sample.csv
```

### Network

```powershell
fakenet.exe -i 1
```

Or capture directly:

```powershell
tshark.exe -i 1 -w C:\Analysis\Logs\sample.pcapng
```

### Process baseline

```powershell
tasklist /v > C:\Analysis\Logs\tasklist-before.txt
netstat -abno > C:\Analysis\Logs\netstat-before.txt
```

Execute from debugger when anti-analysis is expected:

```powershell
x64dbg.exe C:\Analysis\Samples\sample.exe
```

After execution:

```powershell
tasklist /v > C:\Analysis\Logs\tasklist-after.txt
netstat -abno > C:\Analysis\Logs\netstat-after.txt
autorunsc64.exe -accepteula -a * -c -h -s > C:\Analysis\Logs\autoruns-after.csv
```

## 6. Anti-debug checks

Common checks:

```text
kernel32!IsDebuggerPresent
kernel32!CheckRemoteDebuggerPresent
ntdll!NtQueryInformationProcess
ntdll!NtQuerySystemInformation
PEB.BeingDebugged
PEB.NtGlobalFlag
ProcessHeap flags
OutputDebugString
CloseHandle invalid-handle exception
INT 2D
ICEBP
Hardware debug registers DR0–DR7
Parent-process inspection
Window/class/process-name enumeration
```

### x64dbg breakpoints

Set breakpoints before running:

```text
bp kernel32.IsDebuggerPresent
bp kernel32.CheckRemoteDebuggerPresent
bp ntdll.NtQueryInformationProcess
bp ntdll.NtQuerySystemInformation
bp kernel32.QueryPerformanceCounter
bp kernel32.GetTickCount
bp kernel32.GetTickCount64
bp kernel32.Sleep
bp ntdll.NtDelayExecution
```

At `IsDebuggerPresent`, force false:

```text
EAX = 0
```

At `CheckRemoteDebuggerPresent`, inspect second argument and set pointed `BOOL` to zero, then force successful return if needed.

For `NtQueryInformationProcess`, important information classes include:

```text
ProcessDebugPort       = 7
ProcessDebugObjectHandle = 30
ProcessDebugFlags      = 31
```

Expected non-debugged results:

```text
ProcessDebugPort:         0
ProcessDebugObjectHandle: 0
ProcessDebugFlags:        nonzero
```

### PEB checks

Typical values:

```text
PEB + 0x02: BeingDebugged
PEB + 0x68: NtGlobalFlag on common x86 layouts
PEB + 0xBC: NtGlobalFlag on common x64 layouts
```

Offsets can differ across architecture and Windows build. Confirm structure in debugger symbols instead of patching blindly.

Use debugger plugins such as ScyllaHide to virtualize common checks. Enable only required hooks; broad hiding can change behavior and produce false conclusions.

Prefer runtime result manipulation over permanently patching sample. If patching branch logic:

```text
JNZ detected_debugger
```

Change only working copy, commonly to:

```text
JZ detected_debugger
```

or NOP conditional branch. Record original bytes, RVA, patched bytes, and reason.

## 7. Anti-VM artifact handling

Check what sample sees:

```powershell
systeminfo
Get-CimInstance Win32_ComputerSystem | Format-List *
Get-CimInstance Win32_BIOS | Format-List *
Get-CimInstance Win32_BaseBoard | Format-List *
Get-CimInstance Win32_DiskDrive | Format-List *
Get-CimInstance Win32_VideoController | Format-List *
Get-NetAdapter | Format-Table Name,InterfaceDescription,MacAddress
```

Common artifacts:

- BIOS strings containing VMware, VirtualBox, QEMU, KVM
- Hypervisor CPUID bit
- VM-specific MAC prefixes
- Guest additions, drivers, devices, services
- Low RAM, disk, CPU, uptime, or user activity
- Default usernames and hostnames
- Empty browser history and recent-files lists
- Known analysis tool processes
- Registry keys for hypervisor tools
- ACPI and SMBIOS identifiers
- VM backdoor instructions such as VMware I/O communication
- Timing differences around CPUID, RDTSC, API calls, or exceptions

Best strategy: use realistic guest resources and normal activity, then identify and neutralize exact branch in debugger. Trying to erase every VM artifact is fragile.

Reasonable guest profile:

```text
4+ CPU cores
8+ GB RAM
80+ GB disk
Normal hostname and local username
Installed browser and common applications
Populated documents, downloads, and recent-file history
Realistic uptime and interaction
```

Do not uninstall guest drivers required for stable snapshots until confirming sample checks them. Prefer multiple environments: VMware/manual guest plus KVM/CAPE guest. Different behavior is evidence.

## 8. Timing checks

Typical sequence:

```text
t1 = RDTSC/GetTickCount/QueryPerformanceCounter
Sleep or expensive operation
t2 = same clock
if t2 - t1 is abnormal: exit
```

Breakpoints:

```text
kernel32!Sleep
kernel32!GetTickCount
kernel32!GetTickCount64
kernel32!QueryPerformanceCounter
ntdll!NtDelayExecution
```

Approaches:

1. Let delay run once and snapshot after initialization.
2. Shorten requested delay while preserving monotonic clock behavior.
3. Patch comparison branch in working copy.
4. Use debugger/plugin time virtualization.
5. Trigger execution path manually after sleep loop.

Avoid changing only `Sleep()` to zero when sample also compares wall clock. That exposes acceleration immediately.

For direct `RDTSC`, locate opcode:

```text
0F 31
```

Trace surrounding subtraction and threshold comparison. Modify resulting delta or branch, not every clock instruction.

## 9. Unpacking workflow

1. Identify packer using DIE, entropy, imports, and entry-point behavior.
2. Start under correct x86/x64 debugger.
3. Break on memory allocation and permission changes.
4. Trace writes into newly allocated executable regions.
5. Find original entry point.
6. Dump mapped image.
7. Reconstruct imports.
8. Validate sections, entry point, and relocations.
9. Execute repaired copy only in restored snapshot.

Useful breakpoints:

```text
kernel32!VirtualAlloc
kernel32!VirtualProtect
kernel32!LoadLibraryA
kernel32!LoadLibraryW
kernel32!GetProcAddress
ntdll!NtAllocateVirtualMemory
ntdll!NtProtectVirtualMemory
ntdll!LdrLoadDll
ntdll!LdrGetProcedureAddress
```

Signals that unpacking finished:

- Control transfers from stub into a different code region.
- New region contains normal compiler-generated code.
- Imports resolve in a concentrated loop.
- Section protections change from writable to executable.
- Stack stabilizes near expected program entry.
- Code starts accessing normal globals, resources, and application logic.

Use hardware breakpoint on unpacked region after observing writes:

```text
Memory map
Select destination region
Set hardware breakpoint on access/execution
Run
```

Do not assume first jump outside packer is OEP. TLS callbacks, secondary loaders, and staged decryptors can precede actual application entry.

## 10. Dump and rebuild with Scylla

At suspected OEP:

1. Pause process.
2. Note current instruction address.
3. Calculate OEP RVA:

```text
OEP RVA = current instruction VA - image base
```

4. Open Scylla attached to process.
5. Select correct module.
6. Enter OEP RVA.
7. Run `IAT Autosearch`.
8. Run `Get Imports`.
9. Resolve invalid or redirected thunks.
10. Select `Dump`.
11. Select `Fix Dump`.
12. Save repaired image separately.

Validate repaired file:

```powershell
dumpbin.exe /headers .\sample_fixed.exe
dumpbin.exe /imports .\sample_fixed.exe
sigcheck.exe -a -h .\sample_fixed.exe
capa.exe .\sample_fixed.exe
```

Common repair failures:

- Wrong OEP
- Dump taken before import resolution finished
- Imports redirected through packer stubs
- x86/x64 mismatch
- TLS callback omitted
- Relocations damaged
- Section raw sizes inconsistent with virtual sizes
- Manually mapped image lacking normal loader metadata
- Multiple payload modules, with wrong module dumped

If Scylla imports remain invalid, trace resolver calls and map each returned address back to module/export:

```text
LoadLibraryA/W
GetProcAddress
LdrLoadDll
LdrGetProcedureAddress
```

For API hashing, debugger trace must associate hash input with resolved export. Static IAT reconstruction alone may be impossible because no persistent IAT exists.

## 11. Process hollowing detection

Classic hollowing pattern:

```text
CreateProcess(..., CREATE_SUSPENDED)
NtUnmapViewOfSection
VirtualAllocEx/NtAllocateVirtualMemory
WriteProcessMemory/NtWriteVirtualMemory
SetThreadContext/NtSetContextThread
ResumeThread/NtResumeThread
```

Set breakpoints:

```text
kernel32!CreateProcessW
kernel32!CreateProcessA
ntdll!NtUnmapViewOfSection
kernel32!VirtualAllocEx
ntdll!NtAllocateVirtualMemory
kernel32!WriteProcessMemory
ntdll!NtWriteVirtualMemory
kernel32!SetThreadContext
ntdll!NtSetContextThread
kernel32!ResumeThread
ntdll!NtResumeThread
```

At `CreateProcess`, inspect creation flags for:

```text
CREATE_SUSPENDED = 0x00000004
```

Record:

- Parent PID
- Child PID
- Child image path
- Original image base
- Unmapped region
- Remote allocation base and size
- Bytes written
- New thread context
- Resume time

Scan live processes:

```powershell
pe-sieve64.exe /all /shellc /iat 3 /threads /dir C:\Analysis\Dumps\pesieve
```

Or:

```powershell
hollows_hunter64.exe /dir C:\Analysis\Dumps\hollows /threads /iat 3
```

Suspicious findings:

- Main module VAD does not match on-disk image.
- PE header exists in private executable memory.
- Thread instruction pointer lies outside loaded modules.
- Image path claims one executable while memory contains another.
- Header or executable sections differ materially from disk.
- Entry point lands in `MEM_PRIVATE` RX/RWX memory.
- PEB image base disagrees with mapped image metadata.

## 12. General injection detection

Monitor these behavior families:

### Remote thread injection

```text
OpenProcess
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
NtCreateThreadEx
RtlCreateUserThread
```

### APC injection

```text
OpenThread
VirtualAllocEx
WriteProcessMemory
QueueUserAPC/NtQueueApcThread
ResumeThread/SleepEx
```

### Section mapping

```text
NtCreateSection
NtMapViewOfSection in source process
NtMapViewOfSection in target process
Copy payload
Change protection
Start or redirect thread
```

### Thread-context hijacking

```text
SuspendThread
GetThreadContext
WriteProcessMemory
SetThreadContext
ResumeThread
```

### Module stomping

Look for executable image-backed pages whose in-memory bytes differ from file, especially near module entry points or unused sections.

Run complementary scanners:

```powershell
pe-sieve64.exe /all /shellc /threads /iat 3 /data 3 /dir C:\Analysis\Dumps\pesieve
moneta64.exe -m ioc -o C:\Analysis\Logs\moneta.txt
hollows_hunter64.exe /dir C:\Analysis\Dumps\hollows /threads /iat 3
```

No single scanner covers every injection technique. Compare scanner output with API trace and memory layout.

## 13. Sysmon telemetry

Useful event IDs:

- 1: Process creation
- 3: Network connection
- 7: Image loaded
- 8: CreateRemoteThread
- 10: Process access
- 11: File creation
- 12–14: Registry changes
- 17–18: Named pipes
- 22: DNS query
- 25: Process tampering, depending on Sysmon version

Install with chosen configuration:

```powershell
sysmon64.exe -accepteula -i C:\Analysis\sysmon-config.xml
```

Export logs:

```powershell
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Analysis\Logs\sysmon.evtx
```

For process-access telemetry, include access associated with injection, but expect noise:

```xml
<ProcessAccess onmatch="include">
  <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
  <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
  <GrantedAccess condition="is">0x1F3FFF</GrantedAccess>
</ProcessAccess>
```

Do not treat one `OpenProcess` event as injection proof. Require supporting allocation, write, thread, context, or anomalous-memory evidence.

## 14. Offline memory forensics

Capture full memory before terminating suspicious processes. Analyze with Volatility 3:

```bash
python3 vol.py -f memory.raw windows.info
python3 vol.py -f memory.raw windows.pslist
python3 vol.py -f memory.raw windows.pstree
python3 vol.py -f memory.raw windows.psscan
python3 vol.py -f memory.raw windows.cmdline
python3 vol.py -f memory.raw windows.dlllist
python3 vol.py -f memory.raw windows.handles
python3 vol.py -f memory.raw windows.netscan
python3 vol.py -f memory.raw windows.malfind
python3 vol.py -f memory.raw windows.vadinfo --pid 1234
```

Key comparisons:

- `pslist` versus `psscan`
- PEB module list versus VAD mappings
- Thread start addresses versus loaded module ranges
- Image-backed versus private executable mappings
- Disk module hashes versus dumped mappings
- Process creation timeline versus network and registry activity

Dump suspicious regions using plugins supported by installed Volatility version. Plugin names and dump options vary; check:

```bash
python3 vol.py windows.malfind --help
python3 vol.py windows.vadinfo --help
```

## 15. Evidence package

Preserve:

```text
sample original hash
original sample
patched analysis copy
patch log with RVA and bytes
Procmon PML and CSV
PCAP/PCAPNG
Sysmon EVTX
CAPE report
screenshots and debugger notes
process memory dumps
full memory image
unpacked dump
Scylla-fixed dump
YARA/capa/FLOSS output
timeline
IOC list
```

Hash outputs:

```powershell
Get-ChildItem C:\Analysis -Recurse -File |
  Get-FileHash -Algorithm SHA256 |
  Export-Csv C:\Analysis\hashes.csv -NoTypeInformation
```

## 16. Fast operator sequence

1. Revert snapshot.
2. Hash and statically triage sample.
3. Start Procmon, Sysmon, FakeNet-NG, packet capture.
4. Run sample normally once.
5. Save behavioral artifacts and memory.
6. Revert snapshot.
7. Run under debugger with targeted API breakpoints.
8. Neutralize only observed anti-analysis branches.
9. Trace allocation, writes, protection changes, and control transfer.
10. Stop at stable unpacked code.
11. Dump process image and rebuild imports with Scylla.
12. Scan all processes using PE-sieve, HollowsHunter, and Moneta.
13. Capture full memory if hollowing/injection appears.
14. Correlate API calls, Sysmon events, VADs, thread starts, and network traffic.
15. Revert snapshot before next sample.

---

## [reasoning trace]


