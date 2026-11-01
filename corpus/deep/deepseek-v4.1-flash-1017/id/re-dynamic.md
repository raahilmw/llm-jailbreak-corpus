# re-dynamic — malware

# Dynamic Malware Analysis: Sandbox, Anti-Analysis, Unpacking, Injection Detection

## 1. Arsitektur Sandbox

### 1.1 Topologi Referensi

| Komponen | Produk/Versi | Peran | Jaringan |
|---|---|---|---|
| Host analyzer | Ubuntu 24.04 LTS, 16 vCPU / 32 GB RAM / NVMe 1 TB | Menjalankan hypervisor, CAPE server, INetSim | NAT + host-only |
| Hypervisor | VMware Workstation Pro 17.5 / KVM (libvirt 10.0) | Eksekusi guest | host-only `vmnet1` |
| Guest Windows | Windows 11 24H2 (build 26100.1742) | Eksekusi sampel | host-only, DNS → INetSim |
| Guest Linux (opsional) | Ubuntu 22.04.4 LTS | Sampel ELF | host-only |
| Toolset | FLARE-VM 2024.11 (installer `install.ps1`) | Reverse engineering | offline |
| Sandbox orchestrator | CAPE v2 (CAPEv2 `2.4-stable`, commit `9c3f`) | Automatisasi, unpacking, config extraction | host |
| Network sim | INetSim 1.3.2 / FakeNet-NG 2.6 | Layanan palsu (HTTP/DNS/SMTP/IRC) | host |
| Traffic capture | tcpdump 4.99.4 → PCAP per task | Forensik jaringan | bridge |

### 1.2 Checklist Build FLARE-VM (Windows 11 24H2)

```powershell
# Snapshot bersih dulu, baru install
Set-ExecutionPolicy Unrestricted -Force
# Boxstarter + Chocolatey install; butuh ~2 jam, ~60 GB
(New-Object net.webclient).DownloadFile(
  'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
  "$env:USERPROFILE\install.ps1")
Unblock-File "$env:USERPROFILE\install.ps1"
# Disable Defender realtime SEBELUM install (kalau tidak, puluhan tool diblok)
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
.\install.ps1 -noPassword -noRestart
```

Tool wajib pasca-install (verifikasi ada di `C:\Tools`): `x64dbg` 2024.11, `IDA Free 8.4`, `Ghidra 11.2`, `PE-bear 0.6.7`, `Process Hacker 2.39`, `Scylla 0.9.8`, `PE-sieve 0.3.9`, `HollowsHunter 0.2.8`, `API Monitor 2.0`, `Detect-It-Easy 3.10`.

### 1.3 Build CAPE v2

```bash
# Ubuntu 24.04, user non-root dengan sudo
git clone https://github.com/kevoreilly/CAPEv2.git && cd CAPEv2
sudo ./installer.sh  # pilih "standalone" + qemu-kvm atau virtualbox
# Konfigurasi jaringan guest
sudo ./kvm-qemu.sh all cape  # buat vmcloak guest Windows
# Verifikasi
sudo systemctl status cape
sudo -u cape /opt/CAPEv2/venv/bin/python cuckoo.py --help
sudo -u cape /opt/CAPEv2/venv/bin/python utils/process.py --help
```

Konfigurasi kunci `conf/default.conf`:

```ini
[resultserver]
ip = 192.168.122.1

[processing]
# unpacker berbasis uc – sangat berguna untuk packer ringan
unpacker = yes

[auxiliary]
# ambil memori proses saat terminasi
enable_memory_dumps = yes
```

Submit:

```bash
cd /opt/CAPEv2
sudo -u cape ./venv/bin/python utils/submit.py --platform windows \
  --options free=yes,procmemdump=1,route=none /path/sample.exe
```

### 1.4 Alur Kerja Langkah demi Langkah (Baseline)

1. **Snapshot bersih** guest Windows sebelum tiap sampel (`vmrun snapshot vm-win11 clean`).
2. **Baseline capture**: jalankan `tcpdump -i vmnet1 -w base.pcap` 60 detik kosong.
3. **Jalankan prologue**: `Procmon` filter `Operation is Process/Thread/Image`, `RegSetValue`, `CreateFile`; `API Monitor` attach ke `explorer.exe`; `Wireshark` pada `vmnet1`; `x64dbg` (attached) untuk sampel.
4. **Eksekusi sampel** dengan argumen realistis (`--install`, path di `%APPDATA%`).
5. **Ambil artefak**: memory dump (`procdump -ma PID out.dmp`), `pe-sieve /pid PID /out dumps/`, `HollowsHunter /pid PID /out hs/`, PCAP, Procmon PML, `autoruns -a autoruns.csv`.
6. **Rekonstruksi & dokumentasi** → IOC, TTP (ATT&CK), YARA.
7. **Rollback snapshot**.

---

## 2. Anti-Analisis

### 2.1 IsDebuggerPresent / CheckRemoteDebuggerPresent

**Yang dikirim:** panggilan `kernel32!IsDebuggerPresent` (baca `PEB.BeingDebugged`) atau `CheckRemoteDebuggerPresent(hProcess, &b)` (→ `NtQueryInformationProcess` `ProcessDebugPort`).

**Yang muncul:** Return `1` jika debugger aktif. Di x64dbg default, `IsDebuggerPresent` di-hook untuk return 0, sehingga sampel lolos — tetapi `CheckRemoteDebuggerPresent` biasanya **lolos** dari hook default karena jalur berbeda.

**Kenapa berhasil/gagal:**
- Hook userland (`IsDebuggerPresent`) mudah dipatch, tapi mudah dideteksi via **checksum prolog** (byte pertama `kernel32!IsDebuggerPresent` harus `64 A1 18 00 00 00` → `mov eax, fs:[0x18]`). Jika MP/0xCC → deteksi.
- Bypass berhasil jika pakai **ScyllaHide** (x64dbg plugin) dengan profil "VMware + TitanHide" — menangani `NtQueryInformationProcess`, `NtSetInformationThread(ThreadHideFromDebugger)`, `NtClose` invalid handle.

```asm
; Deteksi standar
call IsDebuggerPresent
test eax, eax
jnz  short being_debugged
```

```powershell
# Patch di memory dengan ScyllaHide CLI (x64dbg)
# Plugins → ScyllaHide → Options → Profile "VMProtect" → Apply
```

**Uji cepat:**

```bash
# jalankan dengan x64dbg lalu cek di command bar
$ x64dbg: "bp IsDebuggerPresent" → break → register eax = 1 → patch → continue
```

### 2.2 PEB (Process Environment Block)

**Yang dikirim:** enumerasi `PEB->BeingDebugged` (offset `0x02`), `PEB->NtGlobalFlag` (`0x68` 32-bit, `0xBC` 64-bit), `PEB->ProcessHeap` flags (`0x70/0x74` untuk `HeapFlags`, `ForceFlags`).

**Yang muncul:**
- `BeingDebugged == 1`
- `NtGlobalFlag & 0x70` (FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS)
- `ProcessHeap->Flags & HEAP_GROWABLE == 0`, `ForceFlags != 0`

**Kenapa berhasil/gagal:** pembacaan `fs:[0x30]`/`gs:[0x60]` tidak terdeteksi userland hook. Bypass butuh kernel-mode (TitanHide) atau patch struktur setelah `LdrpInitializeProcess` — biasanya `ScyllaHide` menulis `BeingDebugged=0` dan `NtGlobalFlag=0` via driver.

```c
// pola akses PEB tipikal
PPEB peb = (PPEB)__readgsqword(0x60);
if (peb->BeingDebugged) exit(1);
if (peb->NtGlobalFlag & 0x70) exit(1);
```

Tabel offset (Windows 11 24H2, x64):

| Field | Offset x64 | Nilai normal | Nilai saat debug |
|---|---|---|---|
| `BeingDebugged` | 0x02 | 0 | 1 |
| `NtGlobalFlag` | 0xBC | 0x0 | 0x70 |
| `ProcessHeap` | 0x30 | valid ptr | valid ptr |
| `ProcessHeap->Flags` | +0x70 | 0x2 | 0x2 + flag debug |
| `ProcessHeap->ForceFlags` | +0x74 | 0x0 | 0x1-0x5 |

### 2.3 Anti-VM

**Yang dikirim (contoh yang umum):**

| Vektor | Artefak | Deteksi |
|---|---|---|
| CPUID | `CPUID.1.EAX` bit 31 (hypervisor present), leaf `0x40000000` vendor `"VMwareVMware"` / `"Microsoft Hv"` | `cpuid` | 
| MSR | `rdmsr 0x10` → `VBox` di EAX | `rdmsr` privileged → SEH |
| Registry | `HKLM\HARDWARE\DEVICEMAP\Scsi\...\VirtualBox`, `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` `VMware` | `RegQueryValue` |
| File | `C:\Windows\System32\drivers\VBoxGuest.sys`, `vmtoolsd.exe` | `GetFileAttributes` |
| MAC | `08:00:27`, `00:0C:29`, `00:50:56`, `00:15:5D` | `GetAdaptersInfo` |
| Hardware | BIOS vendor `"innotek"`, `"VMware"`, `"QEMU"` | `WMI Win32_BIOS` |
| Timing | `rdtsc` delta untuk single-step |  `__rdtsc()` |
| Proses | `vboxservice.exe`, `VBoxTray.exe`, `vmtoolsd.exe` | `CreateToolhelp32Snapshot` |

**Yang muncul:** kalau VM terdeteksi, eksekusi bercabang ke *stall* atau *exit*; payload utama tidak muncul → IOC hilang.

**Kenapa berhasil/gagal:**
- **Bypass berhasil** jika VM di-harden: VMware `SMBIOS.reflectHost = "TRUE"`, `ethernet0.addressType = "static"` + `ethernet0.address` produksi, `monitor_control.restrict_backdoor = "TRUE"`, `isolation.tools.*.disable = "TRUE"`.
- **Bypass gagal** jika CPUID hypervisor bit dibiarkan hidup (VMware tidak bisa sembunyikan via config dasar — butuh patch `vmx` atau `hypervisor.cpuid.v0 = "FALSE"` yang harus diset **sebelum** guest boot).

```ini
# .vmx minimal hardening
monitor_control.restrict_backdoor = "TRUE"
isolation.tools.getPtrLocation.disable = "TRUE"
isolation.tools.setPtrLocation.disable = "TRUE"
isolation.tools.setVersion.disable = "TRUE"
isolation.tools.getVersion.disable = "TRUE"
SMBIOS.reflectHost = "TRUE"
hypervisor.cpuid.v0 = "FALSE"
ethernet0.address = "3C:52:82:11:22:33"
```

**Uji anti-VM dari guest:**

```powershell
# harus kosong (tidak ada VBox/VMware tools service)
Get-Service | Where-Object {$_.Name -match 'vmtools|vbox'}
# BIOS harus produsen nyata
Get-WmiObject Win32_BIOS | Select Manufacturer,SerialNumber
# CPUID hypervisor bit (via python cpuid atau WMI)
wmic cpu get Name,Manufacturer
```

### 2.4 NtQueryInformationProcess / Patching NTDLL

**Yang dikirim:** dump `ntdll.dll` dari disk → bandingkan dengan in-memory (`NtQuerySection`, atau `ReadProcessMemory` ke self). Jika ada `0xCC`, `0xE9`, byte berbeda → userland hook terdeteksi.

**Yang muncul:** sampel langsung exit atau decode salah.

**Kenapa berhasil/gagal:** userland API-monitor (API Monitor, CAPE) hooking `ntdll!Nt*` → hook terdeteksi. Bypass: **hardware breakpoint** (x64dbg `bph`), **ETW-TI / kernel callback**, atau **TitanHide** (sembunyikan hook via int 0x2E? — tidak, via `NtSetInformationThread` + driver).

---

## 3. Unpacking

### 3.1 Dump Memori + Rekonstruksi IAT (metode Scylla)

**Skenario:** sampel UPX/privpacker, OEP tidak diketahui.

**Langkah di x64dbg (versi 2024.11):**

1. **Identifikasi packer:** `Detect-It-Easy` pada `sample.exe` → "UPX 4.2.1" / "Themida" / "custom".
2. **Set memory breakpoint pada section writable** (`.data`/`.text` write):
   ```
   # di x64dbg command bar
   bp VirtualProtect
   # lanjut sampai OEP terlihat — biasanya setelah blok
   # instruksi jump besar ke section .text asli
   ```
3. **Alternatif: hardware BP pada `kernel32!GetProcAddress`** — breakpoint di sana pada iterasi terakhir sebelum jump ke OEP.
4. **Dump**: plugin **Scylla** (`plugins\Scylla.dll`) → `File → Dump` saat di OEP.
5. **Find IAT:** `IAT Autosearch` → `Get Imports`. Scylla mengenali thunk table via pola `call [mem]` dan referensi ke `IMAGE_IMPORT_DESCRIPTOR`.
6. **Fix dump:** jika raw size < virtual size, centang `Fix dump`; `Dump` → simpan `sample_dump.exe`.
7. **Rebuild IAT:** `IAT Autosearch → Get Imports → Fix Dump` → `sample_dump_dump_SCY.exe`.

**Contoh output Scylla (IAT Autosearch):**

| Modul | Jumlah fungsi | Status |
|---|---|---|
| `KERNEL32.dll` | 214 | OK |
| `USER32.dll` | 89 | OK |
| `ADVAPI32.dll` | 41 | OK |
| `WS2_32.dll` | 12 | OK |
| `WININET.dll` | 8 | OK |

**Kenapa berhasil:** Scylla memindai seluruh `.text` untuk pola `FF 15 xx xx xx xx` dan `FF 25`, mencocokkan target ke range modul yang belum ter-load (validasi via `VirtualQuery`).

**Kenapa gagal:**
- **IAT obfuscation** (hanya `call [reg+off]` dengan register dinamis): Scylla miss → perlu manual trace di `x64dbg` dengan `bp NtProtectVirtualMemory` dan log target.
- **Delayed imports**: thunks diisi saat runtime → Scylla perlu dijalankan setelah semua lazy import resolved; set `bp` di `LdrGetProcedureAddress` dan tunggu.
- **Stolen bytes**: OEP di bagian `.text` yang overwritten → dump Scylla benar tapi bytes awal hilang; fix manual dengan `Scylla → Fix dump` + restore dari file asli.

### 3.2 Memory Dump Alternatif: `pe-sieve` + `HollowsHunter`

```powershell
# Dump semua modul + PE yang dimanipulasi dari PID target
.\pe-sieve64.exe /pid 4242 /out C:\dumps\pid4242 /imp 3 /shellc /threads /data 3 /dmode 3

# Scan seluruh proses — sangat berguna untuk malware yang inject ke banyak host
.\hollows_hunter64.exe /loop /out C:\dumps\hs\ /min 256
```

**Flag penting `pe-sieve`:** `/imp 3` (recover imports), `/shellc` (detect shellcode), `/threads` (enumerate thread start), `/data 3` (carve embedded PE), `/dmode 3` (data dump mode lengkap).

**Output khas `pe-sieve`:**

```
PID: 4242, Name: svchost.exe
  modules: 23, suspicious: 1
  SIG: [Hollowed] [IAT patched]
  Module: C:\Windows\System32\svchost.exe (hollowed, entrypoint overwritten)
```

**Kenapa berhasil:** `pe-sieve` membandingkan memori proses dengan file di disk **per-modul** (ukuran section, header, entry poin, IAT range). Hollowing = mismatch antara `PIMAGE_DOS_HEADER` in-memory dan di-disk.

**Kenapa gagal:** sampel menggunakan **module stomping** (target module legal, tapi section `.text` di-overwrite dengan ukuran pas → perbandingan header tidak trigger). Mitigasi: bandingkan hash section per-section (`pe-sieve /shellc /data 3` tetap menandai entry-point anomaly), atau aktifkan `PageGuard` monitoring di Procmon filter `Process Profiling → Thread Start`.

### 3.3 Anti-Unpacking

| Teknik malware | Efek pada unpacker | Mitigasi |
|---|---|---|
| `VirtualProtect` removal setelah OEP | Dump tidak bisa `ReadProcessMemory` karena `PAGE_NOACCESS` | `pe-sieve` baca via `NtReadVirtualMemory` dengan `PAGE_GUARD` handling; patch di `NtProtectVirtualMemory` |
| `NtSetInformationThread(ThreadHideFromDebugger)` | Debugger kehilangan event | ScyllaHide hook `NtSetInformationThread` return `STATUS_SUCCESS` tanpa effect |
| `int 3` + VEH self-debug | Single-step mati | x64dbg option `Ignore INT3` |
| Section per-page encrypt, decrypt saat eksekusi | Dump mengandung halaman terenkripsi | Dump saat breakpoint di `VirtualProtect` write, iterasi per-halaman; `pe-sieve /data 3` carve setiap region |
| `Sleep` panjang + `NtDelayExecution` + APC | Analis menunggu tak produktif | Patch `Sleep`/`NtDelayExecution` (x64dbg script) |

Contoh patch sleep (x64dbg script, `nosleep.txt`):

```
// entry: bp pada Sleep dan NtDelayExecution
Sleep:
  ret 4     // langsung return
NtDelayExecution:
  mov eax, 0   // STATUS_SUCCESS
  ret 8
```

---

## 4. Deteksi Process Hollowing / Injection

### 4.1 Process Hollowing — Anatomi

**Yang dikirim (API sequence khas):**

| Urutan | API | Artefak |
|---|---|---|
| 1 | `CreateProcessW(..., CREATE_SUSPENDED)` | proses target suspended |
| 2 | `NtQueryInformationProcess` / `NtUnmapViewOfSection` | unmap image asli |
| 3 | `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` | alokasi RWX |
| 4 | `WriteProcessMemory` (PE header + section) | tulis PE baru |
| 5 | `SetThreadContext` | ubah `RCX` = entrypoint baru |
| 6 | `ResumeThread` | eksekusi |

**Apa yang muncul (telemetry):**

| Sumber | Event | Filter |
|---|---|---|
| Sysmon **v15.15** (Win 11 24H2) | EventID 1 `ProcessCreate` dengan `ParentImage=malware.exe` | `CallTrace` mengandung `UNKNOWN` (unbacked) |
| Sysmon 8 | `CreateRemoteThread` | `SourceImage != TargetImage` |
| Sysmon 10 | `ProcessAccess` (mis. `0x1F0FFF`, `0x143A`) | target `lsass`, `svchost` |
| Sysmon 25 | `ProcessTampering` (hollowing) | `Type=Image is replaced` |
| ETW-TI `Microsoft-Windows-Threat-Intelligence` | `KERNEL_MEMORY_EVENT` + `NtWriteVirtualMemory` | butuh trace dengan `SECURITY_ATTRIBUTES` |
| CAPE | `behavior.processes[].calls` — urutan API | `signatures: "process_hollowing"` |

```powershell
# Sysmon config ringkas (potong ke bagian relevan)
<Sysmon>
 <EventFiltering>
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
    <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
  </ProcessAccess>
  <CreateRemoteThread onmatch="include">
    <SourceImage condition="excludes">C:\Windows\</SourceImage>
  </CreateRemoteThread>
 </EventFiltering>
</Sysmon>
```

**Kenapa berhasil:** hollowing **selalu** menghasilkan ketidakcocokan antara image disk (`\Device\HarddiskVolume3\...\svchost.exe`) dengan memory — `Sysmon 25` memicu karena checksum section berubah.

**Kenapa gagal:**
- **Process doppelgänging** (transacted hollowing via `TxF`): Sysmon 1 tidak pernah melihat `CreateProcess` — hanya `NtCreateProcess` via transacted section. Deteksi pakai `EventID 11 FileCreate` transacted (`:TxF`) + `CreateRemoteThread`.
- **Process ghosting** (delete pending file): memory-backed image, file di disk sudah hilang sebelum `CreateProcess`. Deteksi: `GetFinalPathName` empty pada `NewProcessName` di Sysmon 1.
- **Herpaderping**: file di disk sudah diganti **setelah** `CreateProcess` → image memory hash beda dengan Sysmon 1 `Hashes`. Deteksi: `Hashes` pada EventID 1 cocok dengan file yang **bukan** image yang dieksekusi (validasi dengan `pe-sieve /shellc`).

### 4.2 Remote Thread Injection (Classic DLL Injection)

**API sequence:** `OpenProcess(PROCESS_ALL_ACCESS)` → `VirtualAllocEx` → `WriteProcessMemory` (path DLL) → `CreateRemoteThread(LoadLibraryA, path)`.

**Deteksi `CreateRemoteThread` di Sysmon 8:**

```
EventID 8
SourceImage: C:\Users\Public\evil.exe
TargetImage: C:\Windows\System32\notepad.exe
StartAddress: 0x7FFB...  (LoadLibraryA di kernel32)
StartModule: C:\Windows\System32\kernel32.dll
StartFunction: LoadLibraryA
```

**Kenapa berhasil:** `StartFunction=LoadLibraryA` + `SourceImage` tidak signed = indikator sangat kuat. **Kenapa gagal:** ketiga API bisa dipanggil via direct syscall (`NtOpenProcess`/`NtAllocateVirtualMemory`/`NtWriteVirtualMemory` + `RtlCreateUserThread`) → Sysmon 8 tetap menangkap `RtlCreateUserThread` sebagai `CreateRemoteThread` (kernel callback), tapi `SourceImage` bisa kosong jika unbacked — filter harus include empty `SourceImage`.

### 4.3 Injection Lain

| Teknik | Artefak | Deteksi |
|---|---|---|
| APCs (`QueueUserAPC`) | `NtQueueApcThread` ke thread target | Sysmon 8 tidak cover → pakai ETW-TI atau `pe-sieve /threads` (start address abnormal) |
| `SetWindowsHookEx` + WH_GETMESSAGE | DLL di-load semua proses user | Sysmon 7 `ImageLoad` (`Signed=false`, path di `%TEMP%`) |
| `NtCreateThreadEx` via `NtMapViewOfSection` | section RWX | `Sysmon 8` start module empty |
| AtomBombing | `NtQueueApcThread` + `GlobalGetAtomName` | ETW-TI; `pe-sieve /shellc /data 3` |
| Thread hijacking (`SuspendThread`+`SetThreadContext`) | `NtSetContextThread` di proses lain | ETW-TI `KERNEL_THREAD_EVENT`; `Sysmon 8` tidak menangkap → butuh EDR |
| `PROCESS_SUSPEND_RESUME` + `NtResumeProcess` | Sysmon 10 access mask `0x800` | filter `GrantedAccess & 0x0800` |

### 4.4 Verifikasi di Sandbox

```powershell
# pada guest Windows 11 24H2, setelah sampel jalan:
# 1. cek image in-memory vs on-disk (hollowing)
.\pe-sieve64.exe /pid (Get-Process evil).Id /shellc /data 3 /dir C:\dumps\verify

# 2. cek remote thread di proses korban
.\hollows_hunter64.exe /loop

# 3. cek handle access log (Sysmon 10)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} |
  Where-Object {$_.Message -match 'GrantedAccess: 0x1F0FFF'} |
  Select-Object TimeCreated,Message -First 20
```

```python
# parsing cepat CAPE cape report untuk signature injection
import json, sys
r = json.load(open(sys.argv[1]))
print("Signatures:", [s["name"] for s in r.get("signatures", [])])
for p in r.get("behavior", {}).get("processes", []):
    if p.get("calls"):
        print(p["process_name"], "calls:", len(p["calls"]))
```

---

## 5. Jebakan Operasional (YANG SERING BIKIN GAGAL DI LAPANGAN)

| # | Jebakan | Gejala | Mitigasi |
|---|---|---|---|
| 1 | **Snapshot kotor** — snapshot diambil setelah sampel sebelumnya jalan | Sampel kedua mati cepat karena anti-analysis mendeteksi artefak sampel pertama | Ambil snapshot dari image **baru install**, atau `DISM /Capture-Image` + deploy ulang per batch |
| 2 | **Waktu guest tidak realistik** | Malware gated `if (date < 2024) return;` → tidak jalan | Set guest `timezone` sesuai target, `w32tm /resync` ke NTP fake, atau `Set-TimeZone` + patch `NtQuerySystemTime` di API Monitor |
| 3 | **INetSim mati / DNS leak ke internet** | Sampel tidak dapat C2, tidak download payload stage-2 → tidak ke unpack | Selalu verifikasi `nslookup evil.example` di guest → harus `192.168.122.1`; kalau return real IP, cek `iptables -t nat -L` |
| 4 | **CAPE/QEMU versi mismatch** (`qemu-kvm` 8.2 vs CAPE 2.4) | Task stuck di `runtime` tanpa `analysis.log` | Pin versi dari `requirements.txt`; jangan `apt upgrade` qemu setelah build |
| 5 | **VMware backdoor lolos** | `hypervisor.cpuid.v0` tidak efektif kalau VM tidak di-reboot penuh | Power off (bukan reboot), hapus `vmx` `uuid.action = "keep"` residual |
| 6 | **FLARE-VM install dalam kondisi Defender hidup** | Puluhan tool (x64dbg, PE-sieve) di-quarantine → `x64dbg.exe` hilang | Snapshot setelah build; `Set-MpPreference -DisableRealtimeMonitoring $true` **sebelum** install, restore setelah snapshot |
| 7 | **`pe-sieve /pid` di process protected (PPL)** | `lsass.exe` inject tidak bisa di-dump | Tidak bisa tanpa `PPLdump` 2023 (butuh vulnerable driver); gunakan **memory forensics** (WinPmem 4.0) atau `procdump -ma` dengan `SIGNATURE_REQUIRED` bypass di lab isolated |
| 8 | **IAT rekonstruksi pakai modul yang salah versi** | Hasil `Scylla Fix Dump` jalan tapi crash saat import reference resolusi beda antar build (Win 11 24H2 `kernel32!LoadLibraryA` addr != snapshot) | Dump di guest yang **sama persis** dengan yang akan dipakai analisis; jangan dump di Win 10 lalu fix di Win 11 |
| 9 | **CAPE `unpacker=yes` false positive** | Signature "upx" match pada malware yang bukan UPX → report noise | Cek `cape report → static.pe.sections` untuk entropy & section name sebelum percaya signature |
| 10 | **Sysmon 25 absen di build lama** | Win 11 24H2 default Sysmon dari Chocolatey masih v13 → `ProcessTampering` tidak emerge | Install Sysmon **≥14.16**, konfigurasi SwiftOnSecurity 2024, atau Olaf Hartong `sysmon-modular` |
| 11 | **Sample menolak jalan jika `IsDebuggerPresent` hook tidak deteksi anti-hook** | Sampel bercabang: jika hook terdeteksi → self-delete | Gunakan TitanHide (kernel) bukan ScyllaHide (userland) untuk analisis tahap awal; jalankan sampel pertama **tanpa** hook untuk profil behavior |
| 12 | **Network capture pada `vmnet1` tidak melihat trafik guest→host service** | INetSim traffic invisible → IOC C2 hilang | Capture di interface `vmnet8` (NAT) **dan** `vmnet1`; lebih baik: `iptables -j TEE` duplikat ke `tcpdump` |
| 13 | **`Sleep` patch terlalu agresif** | Malware yang pakai sleep sebagai timing untuk C2 handshake → handshake putus | Patch `Sleep` ke maksimum 1000 ms (bukan 0), atau `SleepEx` khusus; gunakan script `x64dbg` conditional |
| 14 | **Snapshot rollback tidak menghapus named pipe / mutex global** | Sampel kedua skip eksekusi (mutex `Global\...` terdeteksi) | Reboot guest sebelum snapshot; hapus `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` artefak |
| 15 | **CAPE analysis timeout default 200 detik** memotong unpacker | `procmemdump` tidak sempat jalan | `conf/cuckoo.conf` → `[cuckoo] analysis_timeout = 600`; submit dengan `--timeout 600` |

### 5.1 Satu hal yang ringkasnya menyelamatkan banyak analisis

**Selalu jalankan sampel dua kali:**
1. **Pass-1 "cold"**: tanpa hook, tanpa debugger, dengan Sysmon + Procmon + PCAP → dapatkan **profil perilaku asli** dan anti-analysis yang dipakai (kalau sampel self-terminate sebelum aktivitas → berarti anti-VM/anti-debug trigger).
2. **Pass-2 "instrumented"**: ScyllaHide/TitanHide + x64dbg + pe-sieve → untuk unpacking dan verifikasi hollowing.

Laporan yang hanya berdasarkan pass-2 akan **kehilangan** anti-analysis yang justru menjadi IOC utama di threat intel.

---

## [reasoning trace]


