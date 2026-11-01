# w2-impacket-suite--deep — win

## 5.x — secretsdump.py: lanjutan

### 5.4 Varian teknik per versi/produk

| Target | Varian | Catatan operasional |
|---|---|---|
| DC 2016+ | `-just-dc-ntlm` untuk volume tinggi | Hindari `-just-dc` penuh; NTDS.dit bisa multi-GB, WMI pull lambat laptop |
| DC 2012 R2 | DRSUAPI via `-use-vss` | VSS gagal pada storage dengan dedup aktif (SERVER 2012 dedup) — fallback ke DRSUAPI |
| LAPS legacy | `--ntds` tanpa filter → hash `Administrator` lokal tiap host | Butuh dump per-host atau RSAT; DRSUAPI hanya domain objects |
| gMSA | Hash `msDS-ManagedPassword` muncul sebagai blob | Tidak bisa dipakai langsung; perlu ekstrak dari blob via `gMSADumper` |
| AD LDS / non-DC | DRSUAPI tidak tersedia | Pakai `-sam`/`-security`/`-system` offline (registry hive lokal) |
| Server Core | `-use-vss` sering timeout (VSS writer WMI slow) | Naikkan `-timeout`; atau relokasi ke `vssadmin` manual lalu `-sam -system -security` |
| PAC/krb auth | `-k -no-pass` dengan ccache | Wajib `-dc-ip` FQDN resolve; SPN `cifs/DC` harus ada |
| SMB signing wajib (2024 baseline) | Fallback ke DRS via RPC over SMB | Perlu `-use-vss` atau RPC endpoint dynamic; firewall 135→49152+ harus terbuka |

### 5.5 Detection lapis lanjut (Sentinel/Defender)

- **Event 4662** pada `CN=NTDS Settings` dengan `ControlAccess` berisi `DS-Replication-Get-Changes-All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) — signal DRSUAPI klassik. Baseline: akun non-DC jarang memicu; alert pada principal non-`Domain Controllers`.
- **Burst 4662** tanpa 4663/4662 paralel pada objek user = DRSUAPI sweep; hitung laju objek/detik (normal <100/menit, attack sering >500/menit).
- **Defender for Identity** "Reconnaissance — directory services replication" jika sensor domain controller aktif.
- **Sysmon EID 1** pada `vssadmin.exe create shadow` diikuti `reg save` dan SMB outbound cepat = pola `-use-vss` + `-sam -system -security` (offline). Kuncinya: pasangan VSS+reg save dalam ≤30 detik.
- **Offline payload**: `secretsdump.py -sam -system LOCAL -security SECURITY` di host forensik **tidak** memicu EID; tidak ada telemetri. Bila investigator melihat artefak `.dit`/`.hive` copy di `%TEMP%` → indikator staging.
- **Honeytoken**: akun `krbtgt` kedua palsu (`krbtgt-backup`) di OU terpisah dengan password acak — pemakaian = pasti dumping. Alternatif: `AdminSDHolder` sentinel via SACL.

### 5.6 Jebakan operasional

- `-just-dc-user` **case-sensitive** pada `sAMAccountName`; kegagalan senyap menghasilkan "0 users found" tanpa error jelas.
- `-pwd-last-set` memakai timezone DC; interpretasi timestamp antar timezone bisa geser 1 hari — jangan pakai untuk timeline korelasi presisi.
- Trust cross-forest: `-just-dc` pada child DC **tidak** menyertakan hash parent; butuh dump terpisah per domain bila forestwide.
- Hash output machine account `$` sering dikira junk — **jangan hapus**; dipakai untuk silver ticket & RBCD.
- `secretsdump.py` terhadap RO DC (RODC): hanya cache `-just-dc-user`; LAPS/hash user lain kosong — jangan simpulkan "tidak ada kredensial".
- `-k` di Linux: ccache dari `getST.py` butuh `KRB5CCNAME` env, bukan `-k` saja; kesalahan umum → auth jatuh ke NTLM (bundling failure, log EID 4776 di DC).
- Ukuran output: NTDS dump bisa puluhan GB; pipe langsung `tee | grep ':1000:'` untuk histogram. Menulis ke `/tmp` = memicu EDR (large file + nama `.txt`).

---

## 6.x — wmiexec.py: lanjutan

### 6.4 Kapan **lebih** tepat dari psexec/smbexec

| Skenario | Pilih wmiexec | Alasan |
|---|---|---|
| Host tanpa SMB signing, tapi SMB mengizinkan `192.168.*` | wmiexec | CIFS hanya untuk staging output; WMI exit mulus |
| EDR memblokir service creation | wmiexec | Non-service; trigger `scrcons.exe`/`WmiPrvSE.exe` |
| Interaksi semi-shell (backtick `!`) | wmiexec | Built-in; smbexec tanpa shell |
| Target Server 2008 (SMB1 still up) | wmiexec | SMB1 service control sering dimonitor; WMI command child process lebih senyap di set log lama |

### 6.5 Varian versi/produk

- **Windows 2012+**: `Win32_Process.Create` tetap jalan; **Defender ASR "Block process creations originating from PSExec and WMI commands"** mematikan child process — bila aktif, `cmd /c` keras. Uji dengan `whoami` dulu.
- **Windows 11 22H2+ / Server 2022**: WMI activity diaudit default ringan; **Event 19 (WmiEventFilter)** hanya untuk persistence. Child process tetap muncul di **4688** dengan `ParentProcessName = WmiPrvSE.exe`.
- **Linux target via OpenWSMAN**: wmiexec tidak mendukung; ini Windows-only.
- **Credential via `-hashes`**: OK, tapi **WinRM/WMI tidak** menerima LM-only; gunakan `:NTHASH` format (leading colon).
- **Kerberos**: `-k -no-pass -dc-ip`, wajib SPN `HOST/hostname` dan `-target-ip` bila DNS tidak resolvable.

### 6.6 Detection

- **EID 4688** parent `WmiPrvSE.exe` → child `cmd.exe`/`powershell.exe` = tinggi-fidelity. Baseline: server dengan WMI-based monitoring tools (SCCM client → `ccmexec`) akan noise; filter principal user non-system.
- **EID 5156** SMB ke `ADMIN$` dari host non-admin dengan burst file `[random].txt` di `%TEMP%` = staging wmiexec (juga berlaku smbexec).
- **Event 4103/4104 (PowerShell log)**: bila command di-wrap, terlihat `Invoke-CimMethod`.
- **Sentinel KQL**: `DeviceProcessEvents | where InitiatingProcessFileName =~ "wmiprvse.exe" and FileName in~ ("cmd.exe","powershell.exe","whoami.exe") | join kind=leftanti (baseline servers)`.
- **Honeypot**: file `%TEMP%\__output` atau pola nama 8-karakter tidak berpola di `C:\Windows\Temp` dari SMB = indikator out-file wmiexec.

### 6.7 Jebakan

- **Redirect `>` ke `C:\Windows\Temp`** butuh hak tulis; default aman. **Jangan** redirect ke `%TEMP%` user dengan ACL ketat.
- `-codec` untuk output non-ASCII (Indonesia/Chinese target) — default `utf-8` sering garbled pada 2008 R2; set `-codec gbk` bila Chinese.
- **Semi-interaktif vs non-interaktif**: tanpa `-shell-type cmd`, setiap perintah = new WMI call; **state tidak persist** (cd hilang). Gunakan `-shell-type powershell` bila perlu state.
- `wmiexec.py` **bukan** shell penuh; pipe binary gagal. Untuk exfil, pakai `-nooutput` + redirect ke SMB share sendiri.
- Antivirus modern heuristik `WmiPrvSE` spawn `cmd /Q /c` dengan base64 — obfuscate argumen atau split.

---

## 7.x — atexec.py: lanjutan

### 7.4 Kapan masih dipilih (2025+)

`schtasks` via `atexec` **kurang diaudit** dibanding psexec services. Cocok untuk:
- Target dengan **SMB signing & SMB1 disabled**, tetapi **Task Scheduler RPC** (port 135→49152) terbuka (banyak jump host).
- EDR memblokir `schtasks.exe` command-line tapi **tidak memblokir RPC Task Scheduler** (`ITaskSchedulerService::SchRpcRegisterTask`) — ini bedanya: atexec memanggil RPC, **bukan** `schtasks.exe`.

### 7.5 Varian

- **Windows 10/11 + Server 2016+**: `\Microsoft\Windows\...` path ditolak untuk user non-admin → gunakan nama task acak root `\`.
- **Server 2008 R2**: Atexec menggunakan `NetScheduleJobAdd` (AT command lama) **bukan** RPC modern; kompatibel tetapi noisy di EID 4698 dengan `SubjectUserName = SYSTEM`.
- **Kerberos + delegation**: atexec tidak delegate secara default; kombinasikan dengan `-hashes` atau ccache agar jalan.
- **Cross-domain**: task dibuat di DC target, credentials harus valid ke target samar; trust direction berpengaruh.

### 7.6 Detection

- **EID 4698** (task created) `TaskName` di root atau `\Windows\` — mayoritas benign adalah `\Microsoft\Windows\UpdateOrchestrator\*`; **baseline allowlist path Microsoft**, alert di luar itu.
- **EID 106** TaskScheduler operational (log `Microsoft-Windows-TaskScheduler/Operational`) — action `Exec` dengan command line mengarah ke `\\127.0.0.1\ADMIN$\*.exe` = smbexec/atexec.
- **EID 200/201** Task action start/completed berurutan dalam <5 detik untuk akun baru = abuse.
- **Sentinel**: `SecurityEvent | where EventID==4698 | where TaskContent !has "\\Microsoft\\Windows\\"`.
- **Defender XDR**: "Suspicious scheduled task creation" alert sudah default untuk root task + binary path UNC.

### 7.7 Jebakan

- Task yang dibuat **tidak otomatis dihapus** bila atexec crash; harus `atexec.py` ulang atau cleanup `schtasks /delete /tn` (butuh akses admin target).
- `-codec` wajib untuk target Chinese dan output file `<random>.tmp` — bila tidak, output corrupt.
- Port TCP 135 terbuka tapi **dynamic port 49152–65535 tertutup** = timeout panjang; smoke test `rpcclient -c 'getusername'` dulu.
- **Task Scheduler service disabled** pada host hardening = atexec gagal tanpa error spesifik; cek `sc query schedule` lewat path lain.

---

## 8.x — smbexec.py: lanjutan

### 8.4 Varian

- **`-share`** parameter penting: default `C$`; gunakan share custom (`\\host\share`) bila `C$` di-monitor khusus. Ini menghindari EID 5140 akses `C$` dari user aneh.
- **`-mode SHARE` vs `-mode SERVER`**: SHARE (default) menggunakan `cmd.exe` remote; SERVER memakai RPC `SVCOPCTL`. SERVER lebih senyap dari sisi service tetapi memicu **7045** seperti psexec. SHARE trigger child `cmd.exe` parent `services.exe`.
- **Server 2019+**: `-mode SERVER` sering gagal login dengan `NT_STATUS_ACCESS_DENIED` bila `SetServiceBinaryPath` butuh hak `SERVICE_ALL_ACCESS` — pastikan user admin lokal.
- **SMB1 vs SMB3**: otomatis negotiate; untuk SMB1 target (2003), gunakan `-hashes` dan `-share C$`.

### 8.5 Detection

- **EID 7045** service name random (8-12 char) dengan `ImagePath = %COMSPEC% /Q /c echo ... > \\.\pipe\...` = signature smbexec.
- **EID 4688**: `cmd.exe /Q /c echo <b64> | ... > \\127.0.0.1\ADMIN$\__<epoch>.txt` adalah string khas.
- **EID 5140/5145** (SMB share access) ke `\\127.0.0.1\ADMIN$` dari proses remote = sangat khas; jarang benign.
- **Named pipe** `\\.\pipe\<random>` create oleh `services.exe` — sysmon EID 17/18 named pipe.
- **Sentinel**: `DeviceProcessEvents | where ProcessCommandLine has_all ("/Q /c echo", "ADMIN$") or ProcessCommandLine matches regex @'\\\\.\\pipe\\[a-zA-Z0-9]{8}'`.

### 8.6 Jebakan

- Output `__*.txt` tidak dibersihkan pada crash → artefak di `ADMIN$` visible untuk IR; **selalu** cleanup manual.
- Binary path di `New-Service` di-quote dengan `%COMSPEC%`; jika target `COMSPEC` di-redirect (AppLocker), fallback gagal.
- `-mode SHARE` butuh `cmd.exe` accessible; **WDAC** memblokir `cmd.exe` dari service → gunakan `powershell.exe` via `-shell-type powershell` (butuh modifikasi script).
- Event 7045 dari user non-SYSTEM tapi dengan `StartType = demand` = anomali; service legit biasanya `auto`.

---

## 9.x — psexec.py: lanjutan

### 9.4 Varian

- **`-service-name`** wajib bila EDR mendeteksi nama `PSEXESVC` klasik; ganti ke nama seperti `WinDefendHelper` (jangan pakai nama AV asli — trigger AV self-defense).
- **`PSEXESVC.exe` vs `-remote-binary-name`**: dengan `--remote-binary-name` (opsional di versi baru), drop binary dengan nama custom; signature hilang — berguna untuk EDR yang hash-detect `PSEXESVC`.
- **`-codec`** sama seperti lain; **`-hashes`** default.
- **Named pipe `PSEXESVC`** — signature sangat khas; alternatif named pipe via `-service-name` **tidak** mengubah pipe. Workaround: gunakan `smbexec -mode SERVER` untuk menghindari named pipe detection.

### 9.5 Detection

- **EID 7045** service `PSEXESVC` (atau custom) dengan `ImagePath = %SystemRoot%\PSEXESVC.exe`.
- **Sysmon EID 13** registry `HKLM\SYSTEM\CurrentControlSet\Services\<name>` create dalam ≤1 detik diikuti EID 1 `services.exe` spawn.
- **Named pipe event (Sysmon EID 17/18)** `\PSEXESVC` — signature paling kuat.
- **EID 4688**: `services.exe` → `PSEXESVC.exe` → `cmd.exe`.
- **Sentinel**: `SecurityEvent | where EventID==7045 | where ServiceName has_any ("PSEXESVC","RemCom","PaExec")`.
- **Defender**: "Suspicious Service Registration" default alert aktif sejak 2022.

### 9.6 Jebakan

- **Antivirus** menghapus `PSEXESVC.exe` saat copy — set `--remote-binary-name` `random.exe` atau disable AV path (bukan opsi; gunakan wmiexec).
- **`ADMIN$` full**: cleanup gagal → target penuh, `psexec` gagal tanpa error jelas. Cek `Get-PSDrive C`.
- **SMB signing 2024+** memaksa SMB3 encrypted; psexec Impacket mendukung tapi **commodity Sysinternals PsExec** tidak (bisa fail). Ini edge case baru Windows 11 24H2 domain.
- **`/accepteula` tidak ada di Impacket**; bedakan dengan PsExec asli — jangan gabungkan parameter.
- **DC restriction**: PsExec-like behavior pada DC memicu Defender for Identity "Suspicious service creation" alert.

---

## 10.x — getST.py: lanjutan

### 10.4 Varian per delegation

| Delegation type | `getST.py` flag | Syarat |
|---|---|---|
| Unconstrained | `-impersonate <user>` | Host target `TRUSTED_FOR_DELEGATION`; attacker sudah control host → kirim SPN ke service lain |
| Constrained (classic) | `-impersonate <user>` (dari `msDS-AllowedToDelegateTo`) | Tidak butuh admin host; cukup account dengan constrained delegation |
| RBCD | `-impersonate <user>` + `-altservice` | Kontrol target computer object (write `msDS-AllowedToActOnBehalfOfOtherIdentity`) |
| Resource-Based (S4U2Self only) | `-self` (bila support) | Non-admin → S4U2Self untuk local admin |
| S4U2Self via protocol transition | `-proto` | Bila target tidak butuh S4U2Proxy |

### 10.5 Versi/produk

- **Server 2022 + Krbtgt AES-only**: ccache output bisa gagal decrypt oleh beberapa tool → gunakan `ticketer.py` atau `getST` terbaru (post-0.11).
- **Protected Users**: `-impersonate` user Protected Users **diblokir S4U2Self** (`TRUSTED_TO_AUTH_FOR_DELEGATION` flag hilang); fallback RBCD ke akun non-protected.
- **AES downgrade**: bila ccache berisi RC4 padahal domain enforce AES, target menolak; `-aesKey` untuk set eksplisit.
- **Cross-realm**: S4U2Proxy cross-realm butuh trust dengan `TGT delegation` enabled (default: yes untuk forest internal, no untuk external).

### 10.6 Detection

- **EID 4769** Service Ticket request dengan `Transited Services` tidak kosong = S4U2Proxy.
- **EID 4769** `Ticket Options = 0x40810000` (forwardable + renewable + pre-auth) ke SPN yang tidak biasanya diakses user adalah baseline anomali.
- **EID 4624 LogonType 3** di target service dengan `Impersonation Level = Impersonation` dan account protection mismatch — sulit, lebih ke korelasi.
- **Defender for Identity** "Domain dominance — S4U2Proxy abuse" alert jika network sensor menangkap.
- **Sentinel**: `SecurityEvent | where EventID==4769 | extend Transited = extract("Transited Services:\\s+([^\\n]+)",1,tostring(EventData)) | where Transited != "-"`.

### 10.7 Jebakan

- `-impersonate` **case-sensitive**, `Administrator` ≠ `administrator` untuk beberapa DC.
- ccache hasil S4U2Self **tidak** otomatis memiliki flag `forwardable` untuk tahap S4U2Proxy — bila fail, cek `klist -e` apakah `ok-as-delegate` set.
- **RBCD butuh kontrol AD computer object**; bila hanya write via GPO, tidak cukup — harus `GenericWrite`/`GenericAll` ke `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- `-spn` harus **service target**, bukan `krbtgt`; kesalahan umum dengan `-spn cifs/` hilang di versi lama.
- **`-altservice`** untuk mengubah SPN pada service class (LDAP/CIFS) — bila target memvalidasi SPN ketat, gagal.

---

## 11.x — ticketer.py: lanjutan

### 11.4 Varian

- **Golden dengan AES**: `-aesKey <krbtgt_aes256>` — lebih sulit dideteksi karena tidak ada downgrade RC4. Gunakan bila krbtgt dirotasi tapi belum AES-only (rare).
- **Silver**: `-nthash` + `-domain-sid` + `-spn <service/host>` + `-domain target.local`; ccache hanya untuk service itu.
- **Diamond/Sapphire**: memerlukan kontrol KDC / S4U2Self + trust — bukan sekadar `ticketer.py`; gabung dengan `getST.py` dan modifikasi `extra-sids` via pac.
- **`-extra-sid`** untuk menambah SID grup Domain Admins / Enterprise Admins — butuh SID domain target, bukan hanya SID lokal.

### 11.5 Detection

- **EID 4768/4769** dengan `Ticket Encryption Type 0x17` (RC4) di domain yang **enforce AES** = golden/silver klasik.
- **EID 4769** tanpa **EID 4768** sebelumnya (ticket tanpa TGT request) = anomali kuat, sering golden.
- **Timeline mismatch**: `TicketOptions` tidak wajar (`0x40810010` vs `0x40810000`) — pola silver.
- **Kerberos PAC validation** (KDC `ValidateKDC` / `PacRequestor`) — event **EID 4822** "A Kerberos ticket was rejected because the PAC was invalid" bila signature PAC tidak match; ini yang menangkap golden dengan krbtgt salah.
- **Sentinel**: `SecurityEvent | where EventID in (4768,4769) | summarize by EncryptionType, Account | where EncryptionType == "0x17"` + baseline domain policy.
- **Defender for Identity**: "Kerberos golden ticket" alert — deteksi via time skew + anomalous SID history.

### 11.6 Jebakan

- **krbtgt rotation**: hash lama masih **valid 10 jam** untuk golden (default `MaxTicketAge`); jangan asumsikan "sudah rotasi = aman" sampai 2 rotasi 10 jam.
- **PAC tanpa validasi** pada resource non-Windows (mis. Samba, kerberized Linux) — golden lolos; tapi bila ada `PacRequestor` enforcement (Windows 2016+), gagal.
- **SID History** injection via `-extra-sid` tidak efektif pada resource yang `SID Filtering` aktif (default di forest trust).
- `ticketer.py` output ccache bisa **tidak diload** bila `KRB5CCNAME` diset dengan format salah (`FILE:/path` vs `FILE:path`).
- Silver ticket tidak menyentuh DC — **tidak ada** log 4769; hanya 4624 di resource. Ini yang membuat deteksi sulit; andalkan 4688 child process anomali.

---

## 12.x — ntlmrelayx.py: lanjutan

### 12.4 Varian protokol target (`-t`/`-tf`)

| Target | Flag | Hasil khas |
|---|---|---|
| SMB | `-t smb://10.0.0.1` | File write, service create (bila admin) |
| LDAP | `-t ldap://DC` | RBCD, ADCS attribute write, `addComputer` |
| LDAPS | `-t ldaps://DC` | Signed relay (channel binding off) |
| HTTP | `-t http://intranet` | Basic auth relay → cookie/credential di URL |
| MSSQL | `-t mssql://host` | `xp_cmdshell` (bila admin) |
| IMAP | `-t imap://host` | Credential saja |
| SMB → LDAP multi | `-tf targets.txt --escalate-user` | Chain: relay SMB ke LDAP untuk RBCD |

### 12.5 Detection per protokol

- **SMB relay**: **EID 4624** LogonType 3 dari src=auth-server dengan account yang **sama** juga login ke workstation lain dalam <5 detik — korelasi "double logon" (event 4624 dua host berbeda dengan account sama). Alternatif: **EID 5145** share access dari IP yang tidak wajar.
- **LDAP relay**: **EID 4662** write `msDS-AllowedToActOnBehalfOfOtherIdentity` atau `userAccountControl` dari principal non-admin.
- **ADCS ESC8** relay: **Event 4886/4887** (certificate request/issuance) dengan SAN berisi user yang tidak request; **EID 4887** massal dalam hitungan detik.
- **Secretsdump relay** (`-t smb --dump`): pola 4662 DS-Replication Get-Changes-All dari IP attacker (bukan DC).
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID==4624 and LogonType==3
  | summarize HostCount=dcount(Computer) by Account, bin(TimeGenerated,10s)
  | where HostCount>1
  ```
  Ini menangkap NTLM relay ke banyak host.

### 12.6 Edge case 2023–2025

- **SMB signing enforced** (Windows 11 24H2 domain, WSUS policy): SMB→SMB relay **mati**. Fokus ke **SMB→LDAP** dan **SMB→ADCS**.
- **LDAP signing + channel binding** (`LdapEnforceChannelBinding=2`): relay LDAP **mati** kecuali ADCS pakai HTTP (non-TLS).
- **Extended Protection for Authentication (EPA)** pada ADCS: ESC8 relay **mati**; fallback ke ESC11 (RPC) tetapi butuh wrapper lain.
- **`--remove-mic`** masih efektif untuk beberapa target Windows 2019 non-patch; **2022+** protected.
- **Drop-the-MIC (CVE-2019-1040)** workaround berkurang signifikan pasca 2020 patch.
- **NTLM disabled policy** (DC 2025 preview `RestrictNTLM`): relay pools kosong.

### 12.7 Jebakan

- `ntlmrelayx.py` butuh **responder.conf** dengan `SMB = Off` dan `HTTP = Off` bila dipakai bersama Responder — kalau tidak, race dan pool kosong.
- **`--no-smb-server`** + `-t ldap://` sering salah konfigurasi → tidak ada listener SMB → auth tidak tertangkap.
- **`--output-file`** untuk dump credential: file berisi hash `SAM` dan `LSA` — enkripsi volume attacker.
- **`--socks`** mode: pakai bersama `proxychains` untuk pivot; 4624 relay target akan mencatat **IP pivot**, bukan attacker — forensic red herring.
- `-tf` **mengabaikan** urutan; untuk chain SMB→LDAP→ADCS, jalankan sebagai **dua** instance ntlmrelayx (satu -t LDAP untuk RBCD, satu -t HTTP ADCS).

---

## 13.x — rbcd.py: lanjutan

### 13.4 Varian

- **Write RBCD ke computer target** butuh `GenericAll`/`GenericWrite` pada computer object atau write ke `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- **Target**: computer object (workstation/server) — tidak bisa ke user.
- **Delegate**: computer dengan SPN (`HOST/<attacker>`) — Windows 2016+ memvalidasi SPN **wajib** ada; buat via `addcomputer.py -computer-name attacker$ -dns-host attacker.local`.
- **Privilege escalation**: setelah RBCD, pakai `getST.py -spn cifs/target` untuk impersonate `Administrator`.
- **Delegation chain**:  `rbcd.py` → `addcomputer` (attacker) → `getST` (s4u2proxy impersonate `administrator`) → `secretsdump -k -no-pass`.

### 13.5 Detection

- **EID 5136** — *long* `msDS-AllowedToActOnBehalfOfOtherIdentity` ditulis. DC security log **5136** (Directory Service Changes) mencatat attribute changed. `ObjectDN` = computer target, `SubjectUserName` = attacker.
- **EID 4662** — write property pada computer target, property GUID `3f78c3e5-f79a-46bd-a0b8-9d18116ddc79` (RBCD attribute) — filter klasik.
- **EID 4741** — computer object created (`attacker$`) oleh non-machine account = staging.
- **EID 4769** request ke `cifs/target` dengan `Transited Services` non-empty (S4U2Proxy result) → penggunaannya.
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID==5136
  | where AttributeLDAPDisplayName =~ "msDS-AllowedToActOnBehalfOfOtherIdentity"
  ```
  Baseline: biasanya hanya admin DC/configmgmt; alert pada principal `*-user` normal.

### 13.6 Jebakan

- **SID attacker harus persis** sama dengan SID computer attacker; kalau attacker user (bukan `$`), RBCD tidak jalan.
- **SPN harus unique**; `addcomputer` gagal bila nama bentrok — pakai random name.
- **RBCD overwrite**: bila sudah ada value, `rbcd.py` **replace**, bukan append — simpan value lama untuk restore.
- **Kontrol lewat Group Policy Preferences** tidak menghasilkan 5136 attribute-level; hanya write via LDAP langsung muncul. Write via `Set-ADComputer` juga muncul 5136.
- **Kerberos AES-only target**: attacker computer butuh `msDS-SupportedEncryptionTypes` default; bila mismatch, ganti via write attribute.

---

## 14.x — Certipy (ekuivalen lanjutan)

### 14.4 ESC enumeration matrix

| ESC | Teknik | Command Certipy | Detection utama |
|---|---|---|---|
| ESC1 | Template with `ENROLLEE_SUPPLIES_SUBJECT` + client auth | `certipy req -ca CA -template Tmpl -upn admin@dom` | EID 4886/4887 SAN mismatch |
| ESC2 | Enroll Any Purpose / no EKU | `certipy req -template Tmpl` | EID 4886 + EKU issue |
| ESC3 | Enrollment Agent template | `certipy req -template EA` lalu `-on-behalf-of` | 4886 ganda |
| ESC4 | Vulnerable ACL on template | `certipy template -write-default -template Tmpl` | 5136 pada `pKIExtendedKeyUsage` |
| ESC5 | CA object ACL abuse | `certipy ca -backup` | 5136 pada `pKIEnrollmentService` |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag | `certipy req -upn admin` | EID 4887 SAN hasil |
| ESC7 | CA officer rights (ManageCA/ManageCertificates) | `certipy ca -add-officer` + `-issue-request` | 4887 manual issuance |
| ESC8 | HTTP enrollment relay | `certipy relay -target http://CA` | 4886 tanpa auth proxy |
| ESC9 | `msPKI-EnrollmentFlag` weak + no security ext | `certipy req -upn` | 4886 |
| ESC10 | Weak certificate mapping (`altSecurityIdentities`) | `certipy account -upn` via Kerberos | 4768 dengan cert |
| ESC11 | RPC enrollment (ICertPassage) | `certipy req -rpc` | RPC tanpa HTTP |
| ESC12 | YubiHSM / CA key compromise | `certipy ca -backup -key` | Backup CA/private key event |
| ESC13 | Issuance policy OID → group linkage | `certipy req -template Tmpl -sid <group>` | Group membership via cert auth |
| ESC14 | `altSecurityIdentities` explicit mapping | `certipy account -upn` | 5136 pada attribute |
| ESC15 | EKUwu — version 1 template injection | `certipy req -template Tmpl -application-policies` | 4886 anomaly |

### 14.5 Certipy command skeleton (ekuivalen Impacket-style)

```
certipy find -u user@dom -p pass -dc-ip DC -vulnerable
certipy req -u user@dom -p pass -ca CA -template Tmpl -upn admin@dom
certipy auth -pfx admin.pfx -dc-ip DC
certipy template -u user@dom -p pass -template Tmpl -save-old
certipy ca -u user@dom -p pass -ca CA -backup
certipy relay -target http://CA/certsrv -template Tmpl
certipy shadow -u user -p pass -account target -dc-ip DC
```

### 14.6 Detection CS (Certificate Services)

- **EID 4886/4887/4888** pada CA server — request/issued/denied. Baseline: enrollment harian oleh service account (SCCM, Intune). Alert: SAN **berbeda** dari requestor (`RequesterName != SAN`); Certipy sering request `-upn Administrator`.
- **EID 4886** dengan `CertificateTemplate` = `User` (default) oleh user non-baseline = ESC1 abuse.
- **EID 4899/4900** (template edited / CA config change) = ESC4/ESC6 abuse.
- **PetitPotam**-style relay ke ADCS: **EID 4886** dari IP attacker, `RequesterName` = machine account yang dipaksa auth, `SAN` = attacker target.
- **Sentinel**:
  ```
  SecurityEvent
  | where EventID in (4886, 4887)
  | extend SAN = extract("Subject Alternative Name:[^\\n]*DNS Name=([^\\n]+)",1,EventData)
  | extend Req = extract("Requester:[^\\n]*",0,EventData)
  | where SAN !has Req
  ```

### 14.7 Jebakan

- **`certipy auth -pfx`** butuh **DC IP** yang punya `PKINIT` (hampir semua DC default). Bila DC basil `KDC cert`, PKINIT gagal → fallback certificate mapping (ESC10/ESC14 ke `altSecurityIdentities`).
- **PFX password**: default `certipy` output `admin.pfx` tanpa password; bila target environment butuh password ada flag `-pfx-password`.
- **SAN length**: CA dengan `szOID_NTDS_CA_SECURITY_EXT` (SID ext, Windows 2019+) **tidak** mengizinkan `-upn` berbeda SID requestor — perlu ESC6/ESC1 template **tanpa** SID ext.
- **PKINIT tidak bekerja pada DC yang block `kdc` cert auth**; fallback butuh relay ke LDAPS (channel binding **enabled** pada Windows 2022+ → mati).
- **`-vulnerable` find** menghabiskan banyak query LDAP; di DC sensitif ini memicu baseline anomali `DC` query burst oleh user non-IT.
- **Certipy `<4.0`** tidak mendukung ESC13/ESC15; versi lama false-negative. Update sebelum red team.

---

## 15.x — Tabel silang: tool × protokol × deteksi

| Tool | Protokol utama | Port | Kapan pilih | Detection paling andal |
|---|---|---|---|---|
| secretsdump | DRSUAPI/RPC | 135 + 49152+/445 | Ambil hash massal; DC access | 4662 Get-Changes-All |
| wmiexec | WMI/DCOM | 135 + dynamic | SMB signing; EDR ketat service | 4688 parent WmiPrvSE |
| atexec | Task Scheduler RPC | 135 + dynamic | SMB signing; port 445 tutup | 4698 root task |
| smbexec | SMB (service) | 445 | SMB tersedia; stealth medium | 7045 named-pipe cmd |
| psexec | SMB (SMB1/3) | 445 | SMB tersedia; cepat | 7045 + pipe PSEXESVC |
| getST | Kerberos | 88 | Delegation abuse | 4769 Transited |
| ticketer | Kerberos | 88 | Golden/silver | 4769 tanpa 4768 (RC4) |
| ntlmrelayx | SMB/LDAP/HTTP | 445/389/80 | Auth callback tersedia | 4624 multi-host |
| rbcd | LDAP write | 389/636 | Kontrol computer object | 5136 RBCD attribute |
| certipy | HTTP/ADCS | 80/443/135 | ADCS vulnerable | 4886 SAN mismatch |

---

## 16.x — Jebakan lintas-tool (operasional)

1. **Kerberos ccache environment**: `KRB5CCNAME` harus konsisten antar tool; jalankan satu shell dan `export` sekali. Kesalahan nyata: `getST.py` output di `admin.ccache`, lalu `secretsdump -k` membaca `admin.ccache2` (default nama berbeda). 
2. **Clock skew**: guild line 2024 DC `MaxAllowableSkewInMinutes=5` → semua tool Kerberos gagal tanpa error jelas. Set `ntpdate` sebelum serangan.
3. **`-hashes` LM:NT** — untuk Impacket semua tool pakai format `LM:NT`; bila hanya NT, gunakan `:NT`. Format `:NTHASH` **bukan** `HASH:NTHASH` — kesalahan umum.
4. **`-no-pass`** hanya untuk Kerberos; dengan `-hashes` **jangan** campurkan.
5. **Output file besar** (`secretsdump`, `ntlmrelayx -output-file`) → simpan pada volume terenkripsi; hash domain = gold. Jangan `/tmp`.
6. **Timezones** Event vs timeline: sentinel pakai UTC, tool output WIB/WIT — normalisasi sebelum report.
7. **DNS resolution**: ccache berisi FQDN; bila resolver lokal tidak resolve ke DC target, `-k` akan NTLM fallback **diam-diam** → EID 4776 alert. Verifikasi selalu dengan `klist -e`.
8. **Named pipe cleanup**: `psexec`/`smbexec` meninggalkan `\\.\pipe\PSEXESVC` dan `__*.txt` files; hapus via `atexec`/`wmiexec` cleanup script sebelum exit. Jejak ini biasanya ditemukan pertama oleh IR.
9. **`--target-ip` vs `-target-name`**: psexec/wmiexec dengan IP mentah tapi hostname target tidak resolvable → ccache Kerberos gagal; pakai `-target-ip` bila SPN kerberos hostname.
10. **Impacket version skew**: `SecretsDump -use-vss` behavior berubah di 0.11 (VSS writer selection); pin versi di container red team Anda. Jangan update di tengah engagement.

---

## 17.x — Detection engineering ringkas (KQL/Defender) — paket minimum 2025

```
// 1. DRSUAPI abuse
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserSid !in~ ("S-1-5-18","S-1-5-9")
| where SubjectUserName !endswith "$"

// 2. Service creation anomaly
SecurityEvent
| where EventID == 7045
| where ServiceName !in~ ("Microsoft Defender*","PsExecSvcLegit...")   // baseline
| extend Path = tostring(ServiceFileName)
| where Path has_any ("cmd.exe","powershell.exe","\\127.0.0.1\\ADMIN$")

// 3. WMI child process
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe")

// 4. RBCD write
SecurityEvent
| where EventID == 5136
| where AttributeLDAPDisplayName =~ "msDS-AllowedToActOnBehalfOfOtherIdentity"

// 5. Golden/silver suspicion
SecurityEvent
| where EventID == 4769
| where EncryptionType == "0x17"
| where ServiceName !endswith "$"           // alert pada user SPN
| join kind=leftanti (SecurityEvent | where EventID == 4768 | project TimeGenerated, Account) on Account
```

Tuning catatan: **baseline terlebih dahulu**, karena runbook IR sering mendapati false positive dari monitoring tools (SCCM, Nessus, backup) pada 4662/4769/7045. Tanpa baseline, alert tidak usable.

---

## 18.x — Kartu cepat business impact (untuk report klien)

| Hash di dump | Efek langsung | Mitigasi prioritaskan |
|---|---|---|
| `krbtgt` | Golden ticket (10j–10j rotasi) | Rotasi **dua kali** jeda 10j |
| `DC$` machine | DCSync parsial, silver | Rotasi machine + deteksi 4662 |
| User domain admin | Lateral ke semua DC | Rotasi + PAM tier 0 |
| LAPS local admin | Lateral ke host itu saja | Rotasi LAPS + Defender LAPS |
| gMSA blob | Service impersonation | Rotasi gMSA (auto/manual) |
| TPM-bound cert | PKINIT passthrough | Revoke CA + reissue |

---

## 19.x — Jebakan terbaru 2024–2025 (edge case)

- **Windows Server 2025 + Kerberos AES only**: semua tool Impacket **< 0.12** gagal baca ccache AES-SHA2; update.
- **Windows 11 24H2 SMB signing default**: psexec/smbexec ke workstation gagal **kecuali** signing di-disable via GPO — banyak workstation enterprise sudah enforce → pivot ke wmiexec/atexec.
- **Windows LAPS v2 (encrypted)**: `secretsdump -sam` terhadap DC tidak lagi mengandung password LAPS plaintext; butuh `Get-LapsADPassword` **di host dengan delegated permission** — ini edge case baru, dumps hash saja tidak cukup.
- **Protected Users + Credential Guard**: `-hashes` NTLM tidak meme cukup untuk skenario tertentu; **Kerberos-only** dipaksa; pastikan ccache dari `getST` valid.
- **ADCS Windows 2025`: enforcement SID security extension **default on**; ESC1/ESC6 mati kecuali template eksplisit override — inventory ulang.
- **Sentinel Matter / Defender XDR 2025 "Kerberoast" auto-hunt**: hampir semua `getSPN` enumeration menghasilkan alert; waktu engagement singkat, noise tinggi; siapkan penjelasan.
- **Certipy 5.0 breaking changes**: flag `req -upn` berubah; skrip lama gagal silent (argumen dianggap template name). Uji pada lab sebelum runbook production.
- **Impacket `ntlmrelayx --remove-mic` deprecated**: gunakan `--relay-to-mic-none`; runbook lama tidak sinkron.

---

## [reasoning trace]


