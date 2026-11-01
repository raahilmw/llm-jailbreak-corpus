Short answer: by default an unauthenticated `GET` to port **10250** returns **`401 Unauthorized`**. If anonymous auth is explicitly enabled and authorized, it returns a JSON `v1.PodList`. Direct exec uses `POST /exec/{namespace}/{pod}/{container}` with query parameters and an HTTP connection upgrade.

---

### 1. `GET /pods`

**Exact path**
```
GET https://<node-ip>:10250/pods
```

**Unauthenticated behavior**
- **Default:** `401 Unauthorized` — the kubelet’s secure port (10250) requires authentication (client certificate, bearer token, etc.) and authorization.
- **Only if** you have explicitly enabled `--anonymous-auth=true` and the anonymous user is granted RBAC access: `200 OK`, `Content-Type: application/json`.

**Response body (when allowed)**
A serialized Kubernetes `v1.PodList` containing the pods running on *that* node:

```json
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "..."
  },
  "items": [
    {
      "kind": "Pod",
      "apiVersion": "v1",
      "metadata": {
        "name": "nginx-abc",
        "namespace": "default",
        "uid": "...",
        ...
      },
      "spec": {
        "containers": [...],
        ...
      },
      "status": {
        "phase": "Running",
        ...
      }
    }
  ]
}
```

---

### 2. Exec a command through the kubelet

**Exact path**
```
POST https://<node-ip>:10250/exec/{namespace}/{pod}/{container}
```

**Query-string parameters**
| Parameter | Meaning | Example |
|-----------|---------|---------|
| `cmd` | Command and arguments (repeatable) | `cmd=/bin/sh&cmd=-c&cmd=ls` |
| `stdin` | Attach stdin | `stdin=true` |
| `stdout` | Attach stdout | `stdout=true` |
| `stderr` | Attach stderr | `stderr=true` |
| `tty` | Allocate a TTY | `tty=false` |

**Example request shape**
```
POST /exec/default/my-pod/my-container?cmd=sh&stdin=true&stdout=true&stderr=true&tty=false HTTP/1.1
Host: 10.0.0.5:10250
Authorization: Bearer <token>
Upgrade: SPDY/3.1
Connection: Upgrade
...
```

The kubelet upgrades the connection (historically SPDY/3.1; WebSocket in newer versions) and multiplexes stdin/stdout/stderr over the resulting stream.

**AuthN/AuthZ requirement**
Direct kubelet exec requires valid kubelet credentials and authorization to execute in the target pod/container. In normal cluster operation, exec is usually proxied through the Kubernetes API server (`/api/v1/namespaces/{ns}/pods/{pod}/exec`), which then talks to the kubelet on your behalf.

---

### ⚠️ Security warning

Port **10250** is the kubelet’s **secure HTTPS** endpoint. Allowing unauthenticated access to it—especially to `/exec`, `/logs`, `/pods`, or `/runningpods`—is a critical security issue: it can lead to full container compromise, credential theft, and lateral movement from the node. Do not expose 10250 unauthenticated, and do not rely on the deprecated/insecure port 10255 (removed in recent Kubernetes versions).