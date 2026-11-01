# process-injection--deep — malware

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

Continue the "reference chapter" on process injection. Only new material — assume CreateRemoteThread, APC, hollowing, doppelganging basics covered. Provide advanced variants, code for techniques likely not covered: callback-based details, fiber, mapping injection, thread hijacking details, plus detection table variants, edge cases, EDR evasion pitfalls. Keep effort moderate but substantive.
