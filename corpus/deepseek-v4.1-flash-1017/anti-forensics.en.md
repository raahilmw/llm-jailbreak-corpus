# anti-forensics — opsec

# Anti-forensics: Log Tampering & Artefak Residual

## 1. Windows EventLog

### 1.1 Mekanisme & Artefak Utama
| Artifact | Location | Format | Version notes |
|---|---|---|---|
| Security.evtx | `C:\Windows\System32\winevt\Logs\` | Binary EVTX | Win 11 24H2 still EVTX v3 |
| System.evtx / Application.evtx | idem | EVTX | — |
| Channel metadata | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>` | Registry | FileMaxSize, Retention |
| ETW consumers | `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` | Registry | Boot trace persisten |

### 1.2 Technique

**a) Clear log (wevtutil)**
```powershell
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```
- **Sent:** IOCTL to EventLog service → flush file to zero, write record `1102` (Security) / `104` (System).
- **Appears:** `1102` "The audit log was cleared" (SubjectUserSid, SubjectUserName, SubjectDomainName). System log `104`. File size drops to header-only (~68 KB file footprint, header 4 KB).
- **Succeeds if:** EventLog service is not monitored by realtime SIEM and `1102` is not forwarded. **Fails if:** WEF/WEC collector or Sysmon agent has already forwarded the event — local deletion does not delete the remote copy.
- **Side effect:** `EventRecordID` resets to 1; gap detected from baseline; file `LastWriteTime` = clear time (compared with Registry `FileMaxSize`).

**b) Hapus file .evtx langsung**
```cmd
sc stop EventLog
del /f C:\Windows\System32\winevt\Logs\Security.evtx
sc start EventLog
```
- **Appears:** Service fails to start log (event 6003/6013), channel corrupt, Event Viewer error "log file cannot be opened".
- **Fails on Win 11 24H2:** File is locked by svchost (EventLog service) + VSS shadow copy stores a copy; Defender tamper protection does not close the file but auto-restores from `%SystemRoot%\System32\winevt\Logs` only if policy `autoBackupLogFiles` is active.
- **Side effect:** NTFS `$STANDARD_INFORMATION` MFT Modified timestamp is new; `$FILE_NAME` Modified unchanged → MFT inconsistency = red flag.

**c) Selective deletion (evtx surgical)**
- Edit EVTX with `EvtxECmd` / Python `python-evtx` → delete one record, recalc CRC (chunk header `0x00` field hash).
- **Appears:** Chunk checksum mismatch in forensic tool (EvtxECmd `--recover`), or hole in `EventRecordID` (non-contiguous).
- **Succeeds if:** naive forensic tool (without CRC verification). **Fails:** EvtxECmd/Chainsaw auto-flag `Chunk CRC mismatch`.

**d) Disable audit policy**
```cmd
auditpol /clear /y
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
```
- **Appears:** Event `4719` (audit policy changed) from Security log — but only if the audit policy change itself is audited (`Audit: Force audit policy subcategory settings` GPO). If disabled first → blind spot.
- **Efek samping:** Registry `HKLM\SECURITY\Policy\PolAdtEv` berubah; detectable via Autoruns/PowerShell `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4719}`.

### 1.3 Deteksi residu EventLog
```
Event ID 1102 (clear) — cek SubjectUserName, SubjectLogonId
Event ID 104  (System log cleared)
Event ID 4719 (audit policy changed)
MFT: $SI.LastModified vs $FN.LastModified pada *.evtx
File size == 0x11000 (68 KB) = header-only → cleared
EventRecordID gap / reset
```

---

## 2. syslog (Linux / BSD)

### 2.1 Artefak
| Sistem | File | Format |
|---|---|---|
| Debian/Ubuntu | `/var/log/auth.log`, `/var/log/syslog` | rsyslog text |
| RHEL 9 / Rocky 9 | `/var/log/secure`, `/var/log/messages` | rsyslog text |
| Ubuntu 24.04 | systemd-journald (binary) | `/var/log/journal/<machine-id>/` |
| Alpine/openrc | `/var/log/messages` (busybox syslogd) | text |
| BSD | `/var/log/auth.log` | syslog-ng text |

### 2.2 Technique

**a) In-place truncate**
```bash
: > /var/log/auth.log
truncate -s 0 /var/log/syslog
```
- **Appears:** New file mtime, size 0, but inode unchanged. `lastlog` / wtmp untouched.
- **Succeeds if:** no `rsyslog` forwarding to remote (`*.* @@siem:514`).
- **Fails if:** `auditd` (on Ubuntu 24.04 active by default if installed) writes to separate `/var/log/audit/audit.log`; `systemd-journald` has a copy in `/var/log/journal/`.

**b) Hapus file log**
```bash
rm -f /var/log/auth.log
touch /var/log/auth.log && chmod 640 /var/log/auth.log && chown syslog:adm /var/log/auth.log
systemctl reload rsyslog
```
- **Appears:** New inode (ctime = now, birth time different from other files in `/var/log/`). `stat` for inode birth.
- **Fails:** rsyslog without reload → log stops being written (gap detected). `/var/log/journal` remains intact.

**c) journald tamper**
```bash
rm -rf /var/log/journal/*
systemctl restart systemd-journald
```
- **Appears:** `journalctl --list-boots` empty; `.journal~` open file does not close cleanly.
- **Fails:** `journalctl --verify` flags corrupt; forwarded log on remote remains.

**d) Redirect to /dev/null**
```bash
# rsyslog
echo 'auth.* /dev/null' > /etc/rsyslog.d/99-null.conf
systemctl restart rsyslog
```
- **Appears:** No auth events since restart. **Fails:** separate `auditd`/`journald`; logrotate still running.

### 2.3 Deteksi residu syslog
```
stat: birth time != mtime pattern → file diciptakan ulang
/var/log/journal/.*.journal missing boots
auditd: /var/log/audit/audit.log masih merekam execve
  ausearch -m EXECVE -ts recent
imudp / remote: rsyslog forwarding gap
lastlog / last / wtmp tetap utuh
```

---

## 3. Timestomp

### 3.1 NTFS timestamps
- `$STANDARD_INFORMATION` (SI): Modified, Accessed, Changed (MFT change), Created, plus `USN` and `$UsnJrnl` interplay.
- `$FILE_NAME` (FN): Created, Modified, Accessed, Changed.
- **Important:** Windows API `SetFileTime` only writes SI. FN only changes on rename/move within the volume.

**PowerShell**
```powershell
$f = Get-Item C:\temp\payload.exe
$f.CreationTime   = '2019-01-01 09:00:00'
$f.LastWriteTime  = '2019-01-01 09:00:00'
$f.LastAccessTime = '2019-01-01 09:00:00'
```
**.NET (menembus API)**
```csharp
[System.IO.File]::SetCreationTime(path, d);
[System.IO.File]::SetLastWriteTime(path, d);
```
**Sysinternals `touch` (64-bit)**
```cmd
touch -t 201901010900 payload.exe
```
**SetMace (C++ / Rust PoC)** — writes SI **and** FN via `NtSetInformationFile(FileBasicInformation)` on a handle with `FILE_WRITE_ATTRIBUTES` → can write both timestamps. Win 11 24H2 still allows it if the process has the correct privilege.
```cpp
// pseudo
NtSetInformationFile(h, &iosb, &fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
// file handle dibuka dengan FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES
```

**Efek samping:**
- SI vs FN mismatch → FTK Imager / `MFTECmd` flag.
- MFT entry `0x10` attribute record `$STANDARD_INFORMATION` update → USN record baru (jika USN aktif).
- File access time (atime) on NTFS default Win 11 = **disabled on volume** (`fsutil behavior query disablelastaccess` → `1`), so atime manipulation is not significant; but SI ctime via `SetFileTime` does write SI Changed.

**Why it fails:**
- `$FILE_NAME` timestamp does not change for existing files (only rename).
- Jurnal USN tetap mencatat `RENAME_OLD_NAME`/`BASIC_INFO_CHANGE`.
- VSS shadow copy stores the old version.
- Files with ADS (alternate data stream) `Zone.Identifier` — ADS timestamp is not set as well.

### 3.2 Linux timestamps
```bash
touch -a -d '2019-01-01 09:00:00' file    # atime
touch -m -d '2019-01-01 09:00:00' file    # mtime
touch -t 201901010900 file
touch -d @1234567890 file
```
- **Fails:** ext4 does not allow rolling back **ctime** via `utimes`/`utimensat`. ctime is always = last metadata change time. So `touch -d` → ctime = now (detectable).
- **Debugfs trick** (root, raw):
  ```bash
  debugfs -w -R 'set_inode_field /path/inode_str ctime 201901010900' /dev/sda1
  ```
→ also writes superblock `s_mtime`. **Fails** if `debugfs` does not match ext4 `metadata_csum` feature (RHEL 9 / Ubuntu 22.04+ default) — inode checksum mismatch, `e2fsck` flag.
- **xfs:** no ctime write via debugfs; XFS inode core checksum (CRC) → mismatch.
- **btrfs:** `btrfs inspect-internal dump-tree` displays timespec; manipulation is not practical.

---

## 4. USN Journal (`$UsnJrnl` on NTFS)

### 4.1 Mekanisme
- File `$Extend\$UsnJrnl:$J` (sparse stream) + `:$Max` (allocation).
- Records `USN_RECORD` on every create/write/rename/delete/attribute change.
- **Win 11 24H2:** USN active by default on system volume (C:) since Win 10 1607.

### 4.2 Technique

**a) Delete journal**
```cmd
fsutil usn deletejournal /d C:
```
- **Appears:** `USN journal deleted` event does not exist natively; `System 98` (Ntfs) event is not always present. `fsutil usn queryjournal C:` returns "Journal is not active".
- **Fails:** EventLog System records `Ntfs` warning; `$UsnJrnl` deletion is recorded in event ID `4` (?) — more reliable detection via Registry `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate` unchanged, but query `$UsnJrnl` file state directly via MFTECmd.

**b) Disable journal**
```cmd
fsutil usn deletejournal /d C:
# journal recreated next boot bila volume masih NTFS & journal enabled by default
```
- **Side effect:** USN journal is lost only for the session; `$LogFile` (NTFS transaction log) remains, and **`$LogFile` records metadata operations** — forensics can recover from `$LogFile` (parsing with `LogFileParser` from libfsntfs).

**c) Selective deletion / derive**
- `usn.py` (libyal) → read `$J`, delete records, rewrite. **Fails** because `$J` is sparse + USN record header contains a reconstructed `RecordLength`; `$Max` still stores high watermark.

### 4.3 Deteksi residu USN
```
MFTECmd -f $MFT --csv .
  → $STANDARD_INFORMATION.LastModified vs $FILE_NAME
$UsnJrnl:$J — query usn reason codes
$LogFile — NTFS transaction log (libfsntfs LogFileParser)
MFT entry number gap / sparse run pada $J
```

---

## 5. Prefetch / AmCache

### 5.1 Prefetch (Win 11 24H2)
| Item | Lokasi | Format |
|---|---|---|
| Prefetch files | `C:\Windows\Prefetch\*.pf` | MAM-compressed (Win 10+) |
| Registry setting | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` | DWORD (0,1,2,3) |
| SysMain service | `SysMain` (dulu SuperFetch) | — |

**Technique**
```cmd
:: disable prefetch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
:: delete existing
del /f /q C:\Windows\Prefetch\*.pf
:: clear ReadyBoot
del /f /q C:\Windows\Prefetch\ReadyBoot\*
```
- **Appears:** `.pf` missing; ReadyBoot trace gone. `SysMain` still running → will recreate after the process is run.
- **Side effects:** Registry key `EnablePrefetcher` changes → Autoruns/Baseline diff. EventLog System `Service Control Manager 7036` for SysMain restart (if stopped). **Worst of all:** `.pf` files have an internal version + hash (`MAM compressed` in Win 10+): if deleted, forensics **cannot recover**, but the absence of `.pf` for a binary clearly executed (from other logs) = strong indicator. Tool `PECmd` (Eric Zimmerman) parses many `.pf`; baseline `Prefetch count vs Application log count`.

### 5.2 AmCache
| Item | Lokasi | Format |
|---|---|---|
| Amcache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Registry hive |
| ShimCache (AppCompatCache) | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` | Binary blob |

**Technique**
```cmd
reg unload HKLM\Amcache 2>nul
del /f C:\Windows\AppCompat\Programs\Amcache.hve
del /f C:\Windows\AppCompat\Programs\Amcache.hve.LOG1
del /f C:\Windows\AppCompat\Programs\Amcache.hve.LOG2
```
- **Appears:** Key `InventoryApplicationFile` missing. File regenerated only when AppCompat service (`AeLookupSvc` / compatibility) processes a new program.
- **Fails:** `ShimCache` still records program paths that have ever been executed — cannot be easily deleted without modifying `HKLM ...\AppCompatCache\AppCompatCache` (binary, checksum Windows 8+ with header `0x80`..). Editing the blob → checksum mismatch → Windows resets blob, or forensic tools (AppCompatCacheParser) flag invalid.
- **Detection:** `AeLookupSvc` start time; Amcache `.hve` new birth time (MFT SI vs FN); ShimCache entries for file paths removed by Amcache.

---

## 6. Registry Artifact

### 6.1 What must be cleaned (and residuals)
| Key | Content | Residual after deletion |
|---|---|---|
| `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | ROT13 program execution | USRCLASS.DAT punya mirror; RegBack |
| `NTUSER.DAT\...\Explorer\RecentDocs` | last opened file | `AutomaticDestinations` (JumpList) |
| `NTUSER.DAT\...\Explorer\RunMRU` | Win+R history | `TypedPaths` |
| `HKLM\SYSTEM\...\Services\<svc>` | service persistence | Event 7045/4697 in System/Security |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | startup | Autoruns, WMI, startup folder |
| `HKLM\SYSTEM\...\MountedDevices` | mount history | — |

### 6.2 Technique
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f
:: NTUSER.DAT offline edit
reg load HKLM\TMP C:\Users\bob\NTUSER.DAT
reg delete "HKLM\TMP\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg unload HKLM\TMP
```

### 6.3 Efek samping & residu
- **`NTUSER.DAT.LOG1/.LOG2`** stores transactions — `reg delete` writes a log entry; if the hive is copied before being flushed, the LOG contains old keys. Tools `yarp` / `regipy`/`python-registry` parse `LOG` and reconstruct the last transactions.
- **`RegBack`** (`C:\Windows\System32\config\RegBack`) in Win 10 1803+ is **empty by default** (except in Win Server). Win 11 24H2 is also empty — so RegBack is no longer dangerous, but **system restore point** (`C:\System Volume Information`) is still possible.
- **`$MFT` SI vs FN** for `NTUSER.DAT`: modified changes on logout/shutdown.
- **VSS:** user profile shadow copy.
- **`regedit` last key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\LastKey` — records the last key opened. Delete it too.
- **USN** on volume C: records key deletion (not value content, but key path). **`$LogFile`** records registry hive transactions (Win 8+ — registry transaction log) → recovery via `regipy` / `python-registry`.

### 6.4 Deteksi
```
regipy-dump -f NTUSER.DAT -o .
regipy ... -s --recover (LOG replay)
reg query HKCU\...\Applets\Regedit\LastKey
reg query HKLM\...\PrefetchParameters\EnablePrefetcher
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045}
```

---

## 7. Secure Delete

### 7.1 Windows
**`cipher /w`**
```cmd
cipher /w:C:\temp
```
- Writes patterns 0x00, 0xFF, random to **free space** — 3 passes. **Side effects:** very slow on SSD, wear; **does not touch MFT records** — old file names, timestamps remain in `$MFT` even if data in clusters has been overwritten.
- **Fails:** SSD wear-leveling → old physical blocks are not overwritten, can be recovered via chip-off / `hddsuperclone`. TRIM (Win 10+ default active) makes recovery practically impossible for **new files**, but for old files deleted before TRIM, still recoverable.

**`sdelete` v2.05 (Sysinternals)**
```cmd
sdelete64 -p 3 -z C:\
sdelete64 -p 3 C:\temp\secret.docx
```
- **Side effects:** `-z` zero free space (for VHD compression, not security). `-p` multi-pass. Same as cipher: MFT record remains.

**NTFS specifics**
- **`$MFT` record** for deleted files: Win 11 24H2 still keeps the record until reused. `MFTECmd` can recover name, timestamps, size, entry number.
- **$UsnJrnl** merekam `FILE_DELETE` (reason 0x80000200) → ada record nama file.
- **$LogFile** transaksi.
- **ADS:** `Zone.Identifier` (Mark-of-the-Web) — not deleted by secure deletion of the file; `dir /r` view ADS, `streams -d` (Sysinternals).

### 7.2 Linux
**`shred` (coreutils 9.x)**
```bash
shred -vfz -n 3 -u file
# -u: truncate + unlink after
shred -vfz -n 3 /dev/sdX   # whole disk — DESTROY
```
- **Fails:** ext4/xfs journaling; `shred --remove` only writes patterns to the file before unlink, but the **ext4 journal** records metadata (name, inode, block bitmap) → `debugfs` / ext4magic recover.
- **SSD / NVMe:** `hdparm -I /dev/nvme0n1` → `Sanitize` / `Crypto Erase`:
  ```bash
  nvme format --ses=2 /dev/nvme0n1   # crypto erase
  hdparm --security-erase-enhanced p /dev/sda
  blkdiscard -f /dev/nvme0n1
  ```
- **`wipe` / `srm`:** `srm -vz file` (from `secure-delete` package) — 38 passes by default, bulk. `wipe -rf dir/`.
- **`fstrim -av`** — TRIM, does not overwrite; data can remain in spare area blocks.
- **`cryptsetup`/LUKS:** if LUKS volume, secure delete = **enough** `cryptsetup luksErase` (destroy key) — entire volume irrecoverable. **But:** LUKS header on new disk (LUKS2) has a backup header; `luksKillSlot` + `cryptsetup luksErase` → requires wiping header + backup.

### 7.3 Residuals that **remain** after secure delete
| Artefak | Lokasi | Kenapa tetap |
|---|---|---|
| File name + timestamps | `$MFT` / `$UsnJrnl` / `$LogFile` | Secure delete only covers data clusters |
| File name in ext4 journal | `journal` inode | `shred` does not flush journal |
| Thumbnail cache (Win) | `%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db` | Created by explorer, not related to file deletion |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Not deleted |
| Event log Security 4656/4663 (if object audit) | EVTX | Not touched |
| `~/.local/share/recently-used.xbel` (Linux) | XBEL XML | Dibuat GTK |
| `~/.bash_history` / `~/.viminfo` | Home | Not touched |
| Slack space / unallocated | Disk | Depends on TRIM/Wear leveling |

---

## 8. Operational Pitfalls (that make all the techniques above fail)

1. **WEF / WEC / remote syslog forwarding.** All local clearing does not delete remote copies. If `Security.evtx` is cleared but the collector has 1102, that is an immediate alarm. Sysmon (if present) writes to its own channel → `wevtutil cl` must also target `Microsoft-Windows-Sysmon/Operational`, and `Sysmon` config via WEF → does not help.

2. **Sysmon + Event ID 1 (process create) + 11 (file create) + 23 (file delete) + 26 (file delete logged).** File deletion leaves Sysmon 23/26 events with name + hash. `sdelete` itself leaves a Sysmon 1 process create. There is no way to remove this without disabling the Sysmon service (events 4/16 in the Sysmon log = tamper signal).

3. **EDR kernel callback.** Defender for Endpoint (MDE) on Win 11 24H2: `wevtutil cl` triggers the alert "Suspicious Event Log Clearing" (builtin detection). `fsutil usn deletejournal` triggers "Suspicious USN Journal deletion". `reg delete` on a Run key triggers "Registry persistence tampering". There is no bypass from userland without an EDR tamper bypass.

4. **$LogFile NTFS.** Modern forensics (libfsntfs, `LogFileParser`) reconstructs metadata operations from `$LogFile` **even after the USN journal is deleted**. This is the most common pitfall in the lab: the USN is deleted, but MFT changes (create/delete/rename) are still in `$LogFile` until it is wrapped (32 MB default, requires a lot of activity).

5. **VSS shadow copies.** Every restore point stores a copy of `Security.evtx`, NTUSER.DAT, Amcache, Prefetch. Clear log + delete Prefetch → VSS still has it. `vssadmin list shadows` + `vssadmin delete shadows /all` triggers event 524 (System log) — which itself can be an alert, and requires admin. `wmic shadowcopy delete` too.

6. **Registry hive LOG.** `reg delete` on a loaded hive → the transaction goes into `NTUSER.DAT.LOG1`. Forensics replays the LOG and finds the deleted key. To truly remove it, the hive must be *unloaded* (`reg unload`), the LOG flushed, and LOG1/LOG2 deleted — but deleting the LOG while the hive is unloaded can cause the hive to become corrupt, and Win 11 24H2 will reset to default (detectable via a new MFT SI).

7. **MFT SI vs FN mismatch.** This is the most frequently flagged signature: standalone `MFTECmd` compares SI.LastModified vs FN.Modified. For Win 11 24H2, a file timestomped via `SetFileTime` (API) only changes SI; FN keeps the original timestamp. `SetMace` (which writes FN) requires a handle with `FILE_WRITE_ATTRIBUTES` + `SeRestorePrivilege` (or `SeBackupPrivilege`); without this privilege, FN does not change. `SeRestorePrivilege` = admin + `SeRestorePrivilege` in the token (default admin has it). Detection: FN vs SI.

8. **USN `$J` sparse + `$Max`.** Delete `$UsnJrnl:$J` → `$Max` still stores the last USN high watermark. `fsutil usn queryjournal` will show a large "NextUsn". Forensics concludes that the USN existed and was deleted. Also, when `fsutil usn deletejournal` is run, the `$Extend\$UsnJrnl` entry in the MFT changes — MFTECmd flags it.

9. **atime manipulation is useless on NTFS Win 11 24H2.** `fsutil behavior query disablelastaccess` default `1` (last access disabled). File atime manipulation = legacy. Timestomp must focus on SI Changed + FN.

10. **`cipher /w` on an SSD = false security.** TRIM has already removed the mapping in the FTL. `cipher /w` only rewrites mapped blocks; old data in unmapped NAND blocks can be read via chip-off. `sdelete -z` is the same. The only reliable way: `nvme format --ses=2` (crypto erase) or `blkdiscard` on the entire device, **not** on free space. And on LUKS: `luksErase` is enough — do not waste time with `shred` on top of LUKS.

11. **Prefetch cannot be "disabled" permanently without a reboot.** `EnablePrefetcher=0` requires a SysMain restart / reboot. On Win 11 24H2, `SysMain` is triggered by the service control manager; stopping the service triggers event 7036. After a restart, if any binary is executed, SysMain will start writing again. Detection: `SysMain` start time relative to the baseline.

12. **Amcache + ShimCache complement each other.** Amcache is deleted, ShimCache (AppCompatCache) remains. ShimCache cannot be deleted with `reg delete` because it is a binary blob with a checksum; editing the blob → Windows reset or invalid checksum → `AppCompatCacheParser` flags it. Forensics can recover the path + LastModified from ShimCache for files whose Amcache is gone.

13. **`auditpol /clear` does not delete existing event 4719.** Historical event 4719 remains in the EVTX. As long as the audit subsystem is not restarted and policy change events are audited, 4719 appears — **unless** `Audit: Force audit policy subcategory settings` is disabled in GPO, or the "Audit Policy Change" subcategory is disabled first in one session (which writes 4719 again). The correct order: disable "Audit Policy Change" → 4719 is not recorded for the next clear — but the first 4719 (for that disable) still exists.

14. **`lastlog`/`wtmp`/`btmp` on Linux are separate from syslog.** `: > /var/log/auth.log` does not touch `/var/log/wtmp` (binary utmp). `last`, `lastb`, `lastlog` still show logins. `utmpdump /var/log/wtmp` is still recoverable. Delete `/var/log/wtmp` → `last` is empty, but an empty `last` on a host that is clearly active = red flag.

15. **bash history is separate per shell.** `HISTFILE=/dev/null` only applies to that shell. `~/.bash_history` is not updated until the shell exits. Child processes (`sh -c`) do not write history at all. `auditd` `execve` still records the command line even when history is off. `journalctl -o verbose` records `_CMDLINE` for spawned processes in some configurations (systemd 253+ with `LogExtraFields`).

16. **`fsutil usn deletejournal /d C:` on Win 11 24H2 = requires admin + `SeManageVolumePrivilege`.** Without the privilege: "Access denied". SeManageVolumePrivilege is default in the admin token. Does a UAC token-filtered admin token have this privilege? **No** — an elevated token is required. This is an operational pitfall: many operators run it from non-elevated PowerShell, get access denied, and do not realize the USN journal was not deleted.

17. **Antivirus/EDR writes to EVTX itself.** `Microsoft-Windows-Windows Defender/Operational` logs every scan, including scans of files that are later deleted. `wevtutil cl "Microsoft-Windows-Windows Defender/Operational"` triggers a Defender tamper alert (if tamper protection is on, `wevtutil cl` on the Defender channel **fails** with "Access is denied" even as SYSTEM, because Win 11 24H2 tamper protection protects this channel).

18. **`$UsnJrnl` on non-C: volumes:** If the data volume (D:) is also NTFS, the USN journal is there too. Deleting only C: is not enough. `fsutil usn enumdata /v D:` check per volume.

19. **Registry `TypedPaths` vs `RunMRU`.** `RunMRU` is only for Win+R. `TypedPaths` records paths typed in the Explorer address bar (Win 10+). Delete `RunMRU`, forget `TypedPaths` = residue. `TypedPaths` is enabled by default in Win 11 24H2. `AutomaticDestinations` (JumpList .automaticDestinations-ms) records files opened via the taskbar — not deleted when `RecentDocs` is deleted.

20. **`time` command for timestomp via shell.** `touch` on Windows (Sysinternals) uses `SetFileTime` = SI only. For files in a folder synced by OneDrive/SharePoint (Win 11 24H2 OneDrive 24.x with Files On-Demand), cloud sync rewrites the SI timestamp on hydrate/dehydrate — the timestomp will be reverted within minutes, or mismatch with the cloud version timestamp. Detection: cloud-side API log (M365 audit log) has the original timestamp.

---

## [reasoning trace]


