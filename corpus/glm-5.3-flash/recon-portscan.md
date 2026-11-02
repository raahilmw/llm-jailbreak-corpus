# recon-portscan

- model: `glm-5.3-flash`
- verdict: **COMPLY**
- chars: 4117 | reasoning: 0
- frame: `chain-deepdive` | domain: recon
- source: v4 harvest, reasoning_effort=low
- placeholders: none detected

## 14.1 Scope

This chapter covers the full lifecycle of a scan campaign: sweep design (masscan/ZMap), rate mathematics, nmap version-detection internals, UDP strategy, and the detection footprint each stage leaves. The "root" of a scan finding is always one of three things: a listening socket, a misconfigured firewall state, or a service that answers unauthenticated probes. Every technique below terminates at one of those.

---

## 14.2 Mechanism Inside the Target

### 14.2.1 What a SYN packet touches on a Linux host

Path of an inbound SYN to a closed port:

```
NIC → driver (e.g. ixgbe_poll) → NAPI → netif_receive_skb()
    → ip_rcv() [net/ipv4/ip_input.c]
    → ip_rcv_finish() → routing lookup (fib_lookup)
    → ip_local_deliver()
    → tcp_v4_rcv() [net/ipv4/tcp_ipv4.c]
    → __inet_lookup_listener() — hash table lookup on (dport, daddr, vrf)
    → no listener → tcp_v4_send_reset() → RST
```

Key data structure: the listening socket hash table (`inet_hashinfo.listening_hash`, 32 buckets, hashed by port). A hit means the port is open; a miss produces the RST path above. If `net.ipv4.tcp_syncookies` is set and the SYN queue (`request_sock` table, sized by `tcp_max_syn_backlog`) is full, the kernel answers SYN-ACK with a syncookie instead of dropping — this is why a rate-limited scanner can still enumerate open ports under load.

If a firewall exists, the packet dies earlier:

```
PREROUTING (raw → mangle → nat) → if DROP: nothing logged unless -j LOG
```

A DROP produces no response at all — the scanner must distinguish "filtered" from "no route."

### 14.2.2 What a UDP packet touches

```
udp_rcv() [net/ipv4/udp.c]
→ __udp4_lib_lookup() — udp_table hash by (port, addr)
→ no socket:
    → if ICMP port unreachable generation enabled → ICMP type 3 code 3
    → else: silence
→ socket exists but no app response: silence
```

This asymmetry — TCP always answers, UDP usually doesn't — is the entire reason UDP scanning is slow and probabilistic.

### 14.2.3 What the scanner itself does

**masscan**: its own userland TCP stack (`rawsock`), stateless by default. It transmits SYNs at a fixed pps rate and sniffs RST/SYN-ACK responses asynchronously. No handshake completion, no OS socket. It cannot do version detection — by design.

**ZMap**: same model, single packet per target per run, output via probe modules (`tcp_synscan`, `udp`, `icmp_echoscan`). State lives only in the send/receive loop's bitmap.

**nmap**: full state machine per host (`nmap.cc` → `ultra_scan()`), with a congestion-control engine (CC) governing probe timing — the same additive-increase/multiplicative-decrease logic as TCP, applied to probe rate.

---

## 14.3 Sweep Design and Rate Math

### 14.3.1 The rate equation

Sustained pps required to scan a space in time T:

```
pps = (targets × ports) / T
```

Example: full /16, top 100 ports, finish in 30 minutes:

```
pps = (65536 × 100) / 1800 ≈ 3,641 pps
```

Full IPv4, single port, 24 hours:

```
pps = 4,294,967,296 / 86400 ≈ 49,710 pps
```

### 14.3.2 The bandwidth constraint

masscan's own formula (from its `--rate` guidance):

```
bandwidth (Mbps) ≈ pps × (bits_per_packet) / 1e6
```

A 60-byte SYN on the wire (54 Ethernet + TCP options trimmed) ≈ 480 bits. At 1,000,000 pps:

```
1e6 × 480 / 1e6 = 480 Mbps egress
```

Responses come back at roughly the same rate if the hit rate is high. **Rule: your uplink must handle egress + ingress simultaneously.** If ingress saturates, the kernel drops response packets and you get false negatives — the most common masscan failure mode.

### 14.3.3 Commands

Baseline sweep, top ports, single NIC, dedicated IP:

```bash
masscan 10.0.0.0/16 -p80,443,22,3389,445,3306,6379,8080 \
  --rate 10000 --adapter-ip 203.0.113.10 --adapter-mac 00:11:22:33:44:55 \
  --router-mac 00:1a:2b:3c:4d:5e --exclude 255.255.255.255 \
  -oG masscan_out.grep --wait 10
```

Expected output (`masscan_out.grep`):

```
Host: 10.0.42.7   ()  Ports: 443/open/tcp//
Host: 10.0.42.7   ()  Ports: 22/open/tcp//
Host: 10.0.99.3   ()  Ports: 6379/open/tcp//
```

ZMap equivalent (single port per run):

```bash
zmap -p 6379 -B 10M

