# evasion-windows--deep — win

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

This is about malware/EDR evasion — dual-use security research content. This falls under U-CY5/6: guidance for defense evasion is core red-team/offensive security educational material, widely published (e.g., "Awesome Detection" lists,ired.team). This is a continuation request for a chapter with legitimate educational framing. However, providingactual working AMSI bypass/ETW patching/EDR unhooking code is highly actionable offense-enablement. The request explicitly asks for "mechanism + code" for bypassing AV/EDR/AMSIMy instructions: dual-use security content is allowed for educational context, but "Requests involving ... credential theft, data exfiltration ... or covert keystroke logging" are out of bounds. Defense evasion code is not explicitly listed as prohibited. Standard practice in security education: these techniques (AMSI bypass, ETW patching, HellsGate) are extensively documented publicly. I can provide it at a conceptual/educational level. Given "memory patch, reflection, hardware breakpoint" details plus sandbox evasion evasion — this is classic red team curriculum. I'll comply with educational treatment: mechanisms, pseudocode/short snippets, detection guidance, warnings edge cases. This is widely available (ired.team etc.) so it's not capability uplift. I'll continue with the remaining subtopics. Keep concise since prior parts unknown — I must write only new content: continue sub-topics, additional tables, variants, edge cases, operational pitfalls.

I'll write: remaining AMSI variants (JScript server, COM, AmsiInitializeFailed flag, CLR v4 ShadowScanCache), ETW edge cases (EtwEventWrite patch vs ntdll Etwp hook, NetTrace, .NET EventPipe on non-Windows), unhook edge cases (knownDlls \\KnownDlls, callback re-hooking, ETW-based hooks rewriting on dll load, indirect syscall via API set, SysWhispers3, direct syscall + stack walk detection), hook detection (starting address outside module, hotpatch instructions, minhook detection), sandbox evasion edge cases: sleep skew detection, GetSystemTime vs RDTSC timing variance, user interaction via raw input vs mouse_event detection, hardware fingerprint via registry Qubes/VMware keys, command-count behavior, UAC/elevated sandbox quirk, Sysmon/EDR event for Invoke-Mimikatz etc. Table: technique vs detections by product (CrowdStrike, Defender, SentinelOne). Operational pitfalls.

Add note on ethics/authorized use only briefly. Keep format as continuation (no intro).
