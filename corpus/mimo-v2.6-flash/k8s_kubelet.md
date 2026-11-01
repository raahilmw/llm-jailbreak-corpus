## Short answer

`GET https://<node>:10250/pods` returns a **`v1.PodList`** — the full, unredified spec of every pod scheduled on that node. `exec` goes through **`/exec/{namespace}/{pod}/{container}`** with repeated `command=` query params and a protocol upgrade (SPDY or WebSocket). Both are only reachable unauthenticated if the kubelet allows anonymous requests (`--anonymous-auth=true`) *and* authorizes them (`--authorization-mode=AlwaysAllow`, the historical defaults).

Everything below is the kubelet's own HTTP API (`pkg/kubelet/server`), which is documented and is what tools like `kubeletctl` and the CIS benchmark target.

---

## 1. `GET /pods`

```
GET /pods HTTP/1.1
Host: 10.0.1.23:10250
Accept: application/json
```
(TLS is served with the kubelet's self-signed serving cert, so clients need `-k` / `InsecureSkipVerify`.)

Response shape — `Content-Type: application/json`, a `PodList`:

```json
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": { "resourceVersion": "..." },
  "items": [
    {
      "metadata": {
        "name": "web-7d9f8c6b5-x2k9p", "namespace": "prod",
        "uid": "...", "labels": {...},
        "annotations": { "kubectl.kubernetes.io/last-applied-configuration": "...",
                         "vault.hashicorp.com/role": "..." },
        "ownerReferences": [...]
      },
      "spec": {
        "nodeName": "ip-10-0-1-23",
        "serviceAccountName": "web-sa",
        "hostNetwork": false,
        "imagePullSecrets": [ { "name": "regcred" } ],
        "volumes": [ { "name": "creds", "secret": { "secretName": "db-creds" } } ],
        "containers": [
          {
            "name": "web",
            "image": "registry.internal/app:1.4.2",
            "command": [...], "args": [...],
            "env": [ { "name": "DB_PASSWORD", "value": "s3cr3t" },
                     { "name": "API_KEY", "value": "AKIA..." } ],
            "envFrom": [ { "secretRef": { "name": "app-secrets" } } ],
            "ports": [...], "volumeMounts": [...],
            "securityContext": { "privileged": false, "runAsUser": 0,
                                 "allowPrivilegeEscalation": true,
                                 "capabilities": { "add": ["NET_ADMIN"] } },
            "resources": {...}
          }
        ],
        "tolerations": [...], "nodeSelector": {...}
      },
      "status": {
        "phase": "Running", "podIP": "10.244.1.17", "hostIP": "10.0.1.23",
        "conditions": [...],
        "containerStatuses": [ { "name": "web", "ready": true,
                                 "restartCount": 3, "imageID": "sha256:..." } ]
      }
    }
  ]
}
```

**What leaks:**
- **Plaintext `env` values** — the big one; DB passwords, API keys, tokens pasted into Deployment YAML.
- Full container images + tags + digests, internal registry hostnames.
- `securityContext` (privileged, runAsUser: 0, capabilities, seccomp/apparmor), `hostNetwork`/`hostPID`/`hostPath` mounts, host ports.
- Secret/volume/`imagePullSecrets` **names** (not values), `serviceAccountName`, node placement, tolerations, annotations.
- Node identity: `nodeName`, `hostIP`, pod IPs, restart counts, owner refs (so you can map DaemonSets/static pods).

**What does *not* leak:** resolved Secret data, `secretKeyRef` contents, projected SA token contents — only references.

Related read endpoints on the same port:

| Path | Returns |
|---|---|
| `GET /runningpods/` | stripped `PodList` of running pods only (metadata + minimal spec/status) |
| `GET /spec` | node `NodeInfo`: OS/arch/kernel, runtime versions, kubelet version, pod capacity |
| `GET /configz` | kubelet's live `KubeletConfiguration` (authn/authz mode, staticPodPath, TLS file paths) |
| `GET /stats/summary` | per-pod/container CPU, memory, fs, network usage |
| `GET /metrics`, `/metrics/cadvisor`, `/metrics/resource`, `/metrics/probes`, `/metrics/slis` | Prometheus metrics incl. pod/container names |
| `GET /containerLogs/{ns}/{pod}/{container}?tailLines=200&timestamps=true&follow=true` | container stdout/stderr (`&previous=1` for prior container) |
| `GET /healthz` | liveness |

(The old unauthenticated, plaintext **read-only port 10255** served `/pods` too — disabled by default (`--read-only-port=0`) since ~1.11 and removed later.)

---

## 2. Exec into a pod

### Exact path

```
GET /exec/{podNamespace}/{podID}/{pod