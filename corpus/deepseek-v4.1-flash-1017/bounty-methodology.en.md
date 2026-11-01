# bounty-methodology — bb

# Metodologi Hunting — Red Team Internal

## 1. Pemilihan Program (Target Selection)

Program score is calculated before entering the hunter loop. Default weights:

| Factor | Weight | Score 1 (bad) | Score 3 (medium) | Score 5 (good) |
|---|---|---|---|---|
| Usia program | 15% | < 30 hari | 1–6 bln | > 12 bln, scope stabil |
| Scope luas | 25% | 1 domain, wildcard sempit | 5–20 domain | wildcard `*.tld`, API+web+mobile |
| Payout | 25% | none/points | $50–500 | > $1000 critical |
| Duplikat rate | 15% | known crowded | mixed | niche stack / produk baru |
| Responsiveness | 10% | > 30 hari | 7–30 hari | < 7 hari |
| Asset baru | 10% | static | minor update | merger/akuisisi/replatform |

**Rule of thumb:** skor ≥ 4.0 → masuk sprint. 3.0–4.0 → queue time-boxed 2 jam. < 3.0 → skip.

**New** program (aging < 60 days) = low dup rate but payout often untested. Prioritize wildcard scope (asset enumeration > single asset deep-dive) because enumeration ROI is high in the early phase.

**Broad-scope** program = needs automated subdomain/asset inventory before hunting. Without inventory, time is wasted on recon.

```bash
# inventory cepat — subfinder v2.6 + dnsx + httpx
subfinder -d target.tld -all -silent | dnsx -silent -a -resp \
  | httpx -silent -sc -title -tech-detect -td -threads 100 \
  -o inventory.txt
```

Output `inventory.txt` → filter `[nginx 1.25]`, `[Chrome 131]` in UA, `[Windows 11 24H2]` in RDP banner are not relevant — focus on web tech stack.

## 2. Time-Boxing

| Fase | Durasi | Exit criteria |
|---|---|---|
| Recon/asset enum | 2 jam | inventory + tech tags |
| Surface mapping (param, endpoint, auth flow) | 3 jam | endpoint list + auth boundary |
| Deep-dive 1 technique | 4 hours | PoC or documented null result |
| Tulis + submit | 1 jam | report + ledger entry |

Block 10 hours per sprint per program. If deep-dive > 6 hours without PoC → **pivot** (second wave of other techniques), not continue. Overrun estimate is a signal of wrong program choice, not lack of persistence.

Timebox tracker:

```bash
# timer sprint 10 jam, log ke ledger
START=$(date +%s); PHASE=recon
check() { echo "$(date -u +%FT%TZ) phase=$PHASE elapsed=$(( ($(date +%s)-START)/60 ))m"; }
```

## 3. Triage Cepat

Every finding enters 15-minute triage. Binary classification first, detailed validation later.

| Signal | Aksi |
|---|---|
| Reflected input, no filter → XSS | validate in Chrome 131 + Firefox 133 (not just curl) |
| 401/403 → 200 with additional header | check `X-Forwarded-For: 127.0.0.1`, `X-Original-URL` |
| SQLi error string (`SQLSTATE`, `ORA-`) | confirm time-based, not just union |
| SSRF callback | DNS + HTTP callback on controlled webhook |
| IDOR object ID increment | check 3 valid IDs before claiming |
| Subdomain takeover | `nginx 1.25` default page fingerprint ≠ takeover; check CNAME to `*.herokuapp.com`, `*.s3.amazonaws.com` |

**Triage rule:** a finding without deterministic reproduction does **not** enter the ledger as a finding — it enters as `candidate`. Validate using browser + curl, because many WAFs (Cloudflare, Akamai) block default curl.

```bash
# curl dengan fingerprint browser untuk lulus WAF
curl -s -o /dev/null -w "%{http_code}\n" \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  -H 'Accept: text/html,application/xhtml+xml' \
  https://target.tld/path
```

What is sent: full UA + Accept headers. What appears: 200 (vs 403 with default curl). Why it works: default WAF rule rejects UA `curl/*`. Why it fails: target uses mTLS or Cloudflare Bot Management — UA spoofing is not enough, TLS fingerprint is needed (`curl-impersonate`).

## 4. Kolaborasi 4 Otak

Four parallel hunters, fixed roles per sprint (rotate between sprints to avoid silos):

| Otak | Peran | Output |
|---|---|---|
| A — Recon | asset enum, tech fingerprint, endpoint discovery | inventory + param list |
| B — Auth/Session | auth flow, JWT/cookie, IDOR/priv-esc, SSO | boundary map + PoC auth |
| C — Injection/Server | XSS, SSTI, SQLi, SSRF, file upload, deser | payload library + PoC |
| D — Business Logic | state machine, race, payment, coupon, workflow | sequence abuse + PoC |

Sync every 2 hours: 10 minutes — each brain shares one artifact, not a story. Artifact must enter the ledger before sync. No artifact = considered not done.

**Collaboration rules:**
- Brain B → C handoff: successful auth endpoint = injection point for C.
- Brain D needs inventory from A, not C's results.
- Scope conflict (two brains on the same endpoint) → empty ledger = may enter, filled ledger = review only.

## 5. Ledger Temuan

Satu file per program, format TSV, append-only. Skema:

```
ts         | otak | host        | endpoint              | teknik      | status    | severity | artifact
2026-01-12T03:41Z | C | api.tld     | /v1/export            | ssrf        | candidate | -        | /tmp/ssrf-001.txt
2026-01-12T04:02Z | B | app.tld     | /admin/users/123      | idor        | confirmed | high     | /tmp/idor-002.txt
```

Status: `candidate` → `confirmed` → `submitted` → `triaged` → `dup`/`paid`.

SQLite backing store for metric queries:

```bash
sqlite3 ledger.db "CREATE TABLE findings(ts TEXT, otak TEXT, host TEXT, endpoint TEXT, teknik TEXT, status TEXT, sev TEXT, artifact TEXT);"
sqlite3 ledger.db "SELECT teknik, status, COUNT(*) FROM findings GROUP BY teknik,status;"
```

**Submit gate:** `confirmed` at least 3 deterministic reproductions (new cookie, different IP no — old session). Submit within < 30 minutes after confirmed, before dup.

## 6. Checklist Harian

- [ ] Check program aging (any new program < 7 days? add to queue)
- [ ] Refresh inventory (`subfinder` delta) — new asset = opportunity before crowded
- [ ] Sync 4 otak: 1 artefak per otak, 10 menit
- [ ] Triage all `candidate` from previous day (15 minutes each)
- [ ] Ledger: minimal 2 entry baru per otak
- [ ] Cek notifikasi program (scope change, payout change, resolved dup)
- [ ] Submit at least 1 `confirmed` before end of day
- [ ] Pivot block: any deep-dive > 6 hours without PoC? cut + pivot

## 7. Metrik

| Metrik | Formula | Target |
|---|---|---|
| Finding rate | findings_confirmed / hr_hunting | ≥ 0.3 |
| Valid rate | paid / submitted | ≥ 0.6 |
| Dup rate | dup / submitted | ≤ 0.25 |
| Time-to-submit | ts_submit − ts_confirmed | < 30 menit |
| Time-to-triage | ts_triaged − ts_submitted | < 72 jam |
| Pivot rate | pivots / deep_dive | 0.2–0.4 (too low = blindly persistent, too high = unfocused) |
| Recon coverage | assets_inventoried / assets_in_scope | ≥ 0.85 |
| Payout/hr | total_payout / hr_hunting | monotonic per sprint |

Query mingguan:

```bash
sqlite3 ledger.db "SELECT SUM(sev='high' OR sev='critical')*1.0/COUNT(*) FROM findings WHERE status IN ('paid','submitted');"
```

---

## Operational Pitfalls That Cause Failure in the Field

1. **Enumeration without tech filtering** — 50k subdomain inventory, 90% parked page `nginx 1.25` default. Without `httpx -td`, deep-dive time is wasted on empty pages. Filter: `-fc 404,403 -mc 200,401,500`.
2. **WAF blocks curl, not browser** — report "cannot reproduce" because only default curl was used. Use `curl-impersonate` (chrome131 preset) or browser + DevTools copy-as-cURL.
3. **Dup due to slow submission** — a `confirmed` finding left idle > 2 hours to "clean up the report" = lose the race. Submit minimal first, edit later (many platforms allow edit < 24 hours).
4. **Deep-dive overrun** — one technique > 6 hours without PoC still continued = 10-hour sprint spent on one endpoint. Pivot is mandatory, not optional.
5. **Ledger is not append-only** — editing/overwriting old entries erases the trace of `candidate` that could actually be upsold after getting a new technique. Append + status transition only.
6. **Collaboration without artifacts** — 4-brain sync becomes a storytelling session, decisions based on memory not evidence. Artifact required before sync.
7. **Timebox not logged** — without timestamp, overrun estimates are not detected. Timer required in shell, log to ledger.
8. **Triage IDOR with one ID** — object ID valid once ≠ IDOR. Required 3 IDs belonging to different users + confirm cross-account access in browser (not just curl, because of session cache).
9. **Subdomain takeover false positive** — `nginx 1.25` default page on `*.herokuapp.com` is Heroku 404, not takeover. Must check HTTP response body + CNAME chain, not just status 200.

---

## [reasoning trace]


