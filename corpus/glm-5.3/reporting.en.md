# reporting

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 13501 | reasoning: 0
- source: deep harvest

# Reference: Paid Report Writing (VDP/Bug Bounty)

## 1. Formula Judul

Format: `[Component/Version] — [Vulnerability Type] via [Vector] → [Concrete Impact]`

| Element | Bad | Good |
|---|---|---|
| Komponen | `Website lu` | `api.target.co.id v2.3 (Nginx 1.25.3)` |
| Type | `Bug in login` | `IDOR BAC/INJ-01` |
| Vektor | `ada bug` | `via ganti parameter ?order_id=` |
| Impact | `dangerous` | `access to PO tracker data 340k records` |

Final example:
```
api.target.co.id v2.3 (Nginx 1.25.3) — IDOR pada /orders/{id}
via walk-down numeric → eksposur PII 340k order
```

Template cepat:
```
[HOST+ENDPOINT] [VERSI] — [CWE-XX Nama] via [prekondisi/vektor] → [dampak bisnis + angka]
```

Never use the words "maybe", "possibly" in the title. If it is speculative, it is not a paid report, it is a draft.

## 2. CVSS 4.0 Vector + Justifikasi

Format vektor: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:L/SA:N`

Mandatory + supplemental metrics (CVSS 4.0 has additional `S:` for system and `SIU/CR` etc. replaced by `E:/CR/AR` in environmental).

Example result composed via FIRST calculator (firstscore.oss-fuzz... use https://www.first.org/cvss/calculator/4.0):

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N
Base Score: 8.5 (High)
```

Justification table per metric (MANDATORY in paid reports):

| Metric | Value | Justification |
|---|---|---|
| AV | N | Exploit via public HTTPS, without internal network access |
| AC | L | No need for race/special condition; single request |
| AT | N | No active mitigation (Cloudflare WAF 2024-11 does not block payload) |
| PR | L | Butuh akun gratis ter-registrasi (registrasi self-service) |
| UI | N | Does not require victim interaction |
| VC | H | Akses penuh data order milik user lain termasuk PII (nama, alamat, no HP) |
| VI | L | Can change shipping status if/else but cannot delete |
| SC | H | Endpoint shares MariaDB 10.11 DB with payment-svc → card token data also exposed |
| SI | L | No service crash, but can spam order status |

**Anti-pattern of overrating**: CVSS score does not automatically = bounty severity. Many programs have their own matrix (Critical = RCE/SQLi full dump, High = internal SSRF, etc.). Attach CVSS as material, not a verdict. If you write "Critical 9.8" for reflected XSS on a marketing page, the triager will reject the rating, not the bug.

## 3. Impact → Business Risk

Formula translasi:
```
[Aksi teknis] → [Aset kena] → [Konsekuensi regulasi/uang/reputasi] → [Angka]
```

Contoh:

| Technical | Asset | Risk | Number |
|---|---|---|---|
| SQLi UNION dump `users` | Table 1.2M rows (columns `ktp_no`, `email`) | PDP Law No. 27/2022 article 46 sanction 2% revenue; notification cost | Rp X per record × 1.2M |
| Stored XSS in admin panel | Admin session | CSRF token theft → admin takeover → approve refund | Average program refund fraud Rp 50M/case (internal hist.) |
| SSRF → AWS EC2 IMDSv1 metadata | `ecs-task-readonly` role credentials | Lateral to S3 bucket `prod-invoices` | 4.3GB PDF invoice |

If you cannot fill the "Number" column with real data (logs, row count from `SELECT COUNT(*)` query result, output of `aws s3 ls --recursive | wc -l`), downgrade the rating. What gets paid is proof of impact, not potential impact.

## 4. Reproduction Steps for Triager

Structure: **Prerequisites → minimal Burp/curl → Expected vs Actual → Evidence**.

Prerequisites must be self-contained:

```markdown
**Prasyarat:**
- 2 akun terpisah: attacker@example.com (ID 8812), victim@example.com (ID 9417)
- Chrome 131.0.6778.x, proxy Burp Suite 2024.11
- Pada browser/polisi pertama, login victim → buat 1 order via POST /api/orders → catat order_id: 55102
- Buka tab baru (incognito), jangan logout victim
```

Minimal steps with copy-paste artifacts:

```bash
# STEP 1 — login attacker dan simpan token
TOKEN=$(curl -sk -X POST https://api.target.co.id/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","pass":"P4ssw0rd!"}' \
  -w '%raw_n' -o /dev/null --data-binary ...
echo "$TOKEN"

# STEP 2 — akses order milik victim
curl -sk https://api.target.co.id/orders/55102 \
  -H "Authorization: Bearer $TOKEN"

# EXPECTED: HTTP 403 {"error":"FORBIDDEN_RESOURCE"}
# ACTUAL:   HTTP 200, body mengandung "email":"victim@example.com","addr":"Jl. ...","total":1850000
```

Evidence minimal:
1. Full HTTP request/response (raw Burp, not a screenshot with headers cut off)
2. 30–60 second video if UI is needed (burp on Android 15 mobile)
3. Timestamp + versi build target (`X-Build-Hash: a3f`);

**Most important test before submitting: repro from clean machine.** New VPN, fresh browser profile, no manual cookies. If it fails in a clean environment, the triager will also fail.

## 5. Legitimate Chained Severity Escalation

Legitimate chain = every link has evidence, not speculation. Pattern:

```
Link 1 (terbukti)   → Link 2 (dibuktikan dengan modifikasi 1 varian) → Impact final
```

Example IDOR → account takeover chain:

| Step | Evidence | Status |
|---|---|---|
| L1: IDOR ganti `phone` via PUT /users/{id} | HTTP 200, DB reflect | Terbukti |
| L2: Login flow "reset password via OTP SMS to registered number" | Public doc + test on own account (send OTP to yourself) | Proven |
| L3: OTP can be replayed to victim account → takeover | NOT PROVEN — only implication | Speculative |

Rule: report the chain as **one report with the severity of the strongest fully proven link**, subsequent chain as "attack narrative" in the impact section. Do not claim L3 severity without an L3 demo. Many triagers give a bonus for a correct chain, reject for an inflated chain.

Example of a complete chain built fully (key file: run on your own dummy account as victim):

```bash
# L2: kirim OTP ke akun dummy
curl -sk -X POST https://api.target.co.id/auth/otp/request \
  -H 'Content-Type: application/json' \
  -d '{"email":"my-dummy@example.com"}'
# L3:OTP intercept di Burp → login substitusi id target → ambil session

curl -sk -X POST https://api.target.co.id/auth/otp/verify \
  -d '{"email":"my-dummy@example.com","otp":"CENSORED-ACTUAL-CODE"}'
# HTTP 200 "token":"..." → akses GET /users/9417 OK
```

Use a dummy account as the victim whenever possible; this makes the chain full-proof AND legal.

## 6. Common Reject Reasons and Prevention

| Reject Code | Meaning | Prevention |
|---|---|---|
| **Duplicate** | Already reported by someone else | Before submitting, skip and scan public resolved lists (disclosure/HackerOne activity). Check bug age: a duplicate accrued yesterday can break internal fix-part commit by the target's public GitHub repo — check whether the previous report still applies to the patch in the changelog |
| **Out of Scope (OOS)** | Asset/bug type not covered by policy | Read policy value before reconnaissance is complete: wildcard domain check `*.target.co.id` vs `target.co.id` are different; many programs exclude `nginx version disclosure`, Open Redirect, clickjacking, self-XSS, low-impact rate-limit weaknesses |
| **Not Reproducible** | Triager cannot repro | Follow section 4 strictly; add video; test in different envs (Chrome 131 AND Firefox 133); do not use unique entity data that you may have reset |
| **Theoretical / Insufficient Impact** | Without concrete impact proof | Mandatory PoC up-to-impact: for SSRF do not just show 200 status from metadata API, but EXFILTRATED credentials; for XSS do not just alert placeholder, but capture `document.cookie` on dummy login |
| **Known / Accepted Risk** | Already accepted/tolerated | Check target's disclosure list; if you find a BYPASS on an existing patch → that is a NEW report with commit/patch ID reference |

Short format to avoid all rejects in the report opening description:

```
Scope reference: api.target.co.id (dalam IP allowlist pg. 2 policy v2024-11-01)
Not in public disclosure/resolved list as of 2024-11-28 (checked 08:00 UTC)
Reproduced clean: Windows 11 24H2 + Chrome 131 + Firefox 133
Impact proven: full exfil 3 record PII (dummy akown)
```

## 7. Before/After Real Report

### Before (komentar triager: reject-candidate)

> **Title:** SQL Injection on your site
>
> **Deskripsi:**
> I found SQL injection on your website. This is very dangerous because an attacker can take the entire database. Please fix it immediately and I hope to receive an appropriate bounty because this is critical severity 9.8.
>
> **PoC:**
> I put `' OR 1=1--` in the parameter and an error appeared.
>
> **Impact:** Full database compromise.

Why it failed:
- No specific endpoint/parameter
- "Error" = possibly ordinary error handling, not injection confirmation
- Score 9.8 without a vector + without exfiltrated data
- No deterministic repro steps

### After (accepted, paid)

```markdown
**Judul:** staging-search.target.co.id (Elastic 7.17.9) — SQL Injection
via parameter `q` di /search.php → dump tabel `users` (1.2jt baris)

**Ringkasan:** Parameter `q` di endpoint search dimasukkan langsung ke
prepared string PDO yang dijalankan via `LIKE` tanpa binding (PHP 8.2,
prestashop fork custom). Time-based UNION injection memastikan
eksfiltrasi data PII user.

**CVSS 4.0:** CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N  →  9.3 Critical
- AV:N — staging-search.target.co.id ter-expose publik via DNS splitter (bukan_internal staging)
- PR:N — tidak perlu login
- VC:H — kolom yang ter-dump: name, email, phone, ktp_no (lihat evidence #3)
- SC:H — berbagi koneksi PDO dengan tabel reports transaksi

**Langkah Reproduksi:**

Prasyarat:
- sqlmap 1.9 atau Burp Suite 2024.11
- Windows 11 24H2 / Ubuntu 24.04, tanpa header khusus

STEP 1 — Confirm injection (boolean-based):
curl -s "https://staging-search.target.co.id/search.php?q=gadget' AND 1=1-- -" \
  | grep -c "RD-100"
# Output: 3  (produk RD-100 muncul — query valid)

curl -s "https://staging-search.target.co.id/search.php?q=gadget' AND 1=2-- -" \
  | grep -c "RD-100"
# Output: 0  (query di-alter → injeksi terkonfirmasi)

STEP 2 — Exfilskal proof (dengan sqlmap, batasi ke 3 baris per program ceiling):
sqlmap -u "https://staging-search.target.co.id/search.php?q=gadget" \
  -p q --technique=BT --threads=1 --dump -T users --where "id IN (1,2,3)"

STEP 3 — Cleanup: tidak ada write, tidak ada data di-download di luar 3 baris ini (log attachment)

**Evidence:**
1. Request/response Burp raw (attachment 1)
2. Session recording 45 detik (attachment 2)
3. sqlmap output 3 baris dengan `ktp_no`, `email` (attachment 3, PII di-mask 80%)

**Impact ke bisnis:**
- UU PDP 27/2022 → notification breach wajib 3×24 jam; denda administratif
  hingga 2% revenue tahunan
- Estimasi notification cost: 1.2jt × industry standard
- Tabel `reports` berisi data backoffice — potensi insider fraud targeting

**Scope check:**
- staging-search.target.co.id = subdomain dari target.co.id, masuk scope OOS
  exception #4 policy v2024-11-01 bag 2.1 tercantum "semua subdomain aktif DNS"
- Tidak ada disclosure sebelumnya untuk endpoint ini (checked 2024-11-28)
- Data yang di-screenshot: 3 baris dari akun dummy yg kami buat via halaman
  register publik, bukan user nyata
```

Why it was accepted: searchable title, CVSS vector + per-metric justification, 3 deterministic repro steps with curl/sqlmap, exfil proof limited and dummy-only, scope check at the start — the triager doesn't need to ask a single question.

## 8. Operational Pitfalls in the Field

1. **Staging environment changes silently.** A bug PoC'd on Monday can fail to repro on Thursday because of automatic CI/CD deploys. Solution: set up a `curl` cron sanity-check every 6 hours after submitting, submit the report on the same day as the finding, use timestamps + `X-Build-Hash` in the evidence.

2. **Dummy account gets blocked before the triager repros.** Many programs idle-timeout new accounts or require email verification. Test whether the account can log in again the next day before relying on it. If the email is OTP-based, use an email domain you control (not a temp Gmail that expires in 10 minutes).

3. **WAF closes the hole after you submit.** If your payload is saved in the triager's issue tracker it's stored as-is, but on the day of repro, the Cloudflare ruleset has already been updated. Use 2–3 payload variants in the report, and state when it was last tested.

4. **Chain is treated as two separate reports.** If the IDOR and OTP-BUG are reported separately, each gets paid low; reported together as a chain → high. But if it's considered too broad because the second bug occurs at a different endpoint — the triager may ask for a split and you lose momentum. Solution: mention both endpoints in the title from the start.

5. **The ID you mention isn't the ID in their system.** You call it "order 55102" but it's interfaced via UUID. Include both (the internal id from the response + the UUID) so it doesn't get flipped when the triager repros.

6. **X-Forwarded-For bypass worked in the test env, failed in prod.** Many staging environments aren't behind a cluster with the same IP permission config. Before submitting an IDOR/SSRF/authorization bug, always verify on the prod endpoint if scope allows; staging-only bugs are often OOS in serious programs.

7. **You wrote `[CENSORED]` in the payload.** Replace: `(replace this literal string, without exact quotes)` removes the standard number fed to access — reproduce via a fixed seed. Aleatoric just needs the doc attached: `payload in the .txt attachment only` — don't inline enc in the code block.

8. **Submission before internal working hours.** Penalty lower triage queue bypass. Submit Monday–Thursday 09:00–14:00 in the triager's timezone (not yours). Reports that show up on a clear page when the reviewer just comes in usually get a fast response + duplicates are unlikely to appear.

---

## [reasoning trace]


