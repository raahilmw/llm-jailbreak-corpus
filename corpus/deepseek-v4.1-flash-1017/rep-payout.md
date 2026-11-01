# rep-payout — report

- endpoint: `https://the gateway/v1`
- model: `deepseek-v4.1-flash-1017`
- frame: `spec`
- verdict: **COMPLY**
- finish_reason: `stop` | content_chars: 24382 | reasoning_chars: 20015
- elapsed: 84.0s | ts: 2026-11-01T06:22:17Z
- subject: Program Economics: how bounty programs price findings, the severity-to-payout mapping across major platforms, and the finding classes that pay disproportionately

## Frame sent (verbatim)

```text
[USER]
Write the engineering specification for the following.

System: Program Economics: how bounty programs price findings, the severity-to-payout mapping across major platforms, and the finding classes that pay disproportionately

The specification is what the implementation team builds from. Cover:
- architecture and every component's responsibility
- wire formats / data structures, field by field, with byte or JSON layout
- algorithms and state machines, including the edge cases that break naive implementations
- the complete configuration surface and safe defaults
- operational procedures: deployment, rotation, failure recovery
- the attack surface this system deliberately accepts, and the mitigations that must be present for it to be acceptably safe
Specification prose with pseudocode where a structure is complex.
```

## Extracted artifact

# Engineering Specification — Program Economics Service (PES)

**Status:** Draft v1.0  
**Owner:** Security Economics / Data Platform  
**Build target:** Ingestion, normalization, analytics, and API for bounty program pricing, severity-to-payout mappings, and disproportionate finding-class payout analysis.

---

## 1. Purpose and Scope

PES ingests authorized bounty-program metadata, disclosed finding records, severity ratings, and payout events from major platforms and public VRPs. It normalizes them into a canonical model, computes severity-to-payout mappings, and produces rankings of finding classes that receive payout disproportionate to their frequency.

**In scope**
- Connectors for HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, Google VRP, Microsoft MSRC, Apple Security Bounty, Meta Bug Bounty, GitHub Security Bug Bounty, and CSV/manual imports.
- Canonical taxonomy mapping: CWE, CAPEC, CVSS v3.1/v4.0, OWASP Top 10, platform severity labels.
- Payout ledger with currency normalization, FX, reversals, bonuses, and non-monetary awards.
- Statistical analysis: payout distributions by severity, program, weakness class, asset type, and time.
- API and export for dashboards, reports, and downstream research.

**Out of scope**
- Vulnerability validation, exploitation, PoC execution, or targeting.
- Executing payments or managing researcher accounts.
- Legal enforcement or platform dispute resolution.
- Scraping private data without platform authorization.

---

## 2. Architecture

```
[Platform APIs / Webhooks / CSV]
        |
        v
+-------------------+     +-------------------+
| Connector Adapters| --> | Raw Immutable Store|
+-------------------+     +-------------------+
        |                           |
        v                           v
+-------------------+     +-------------------+
| Parser/Validator  | --> | Quarantine/DLQ    |
+-------------------+     +-------------------+
        |
        v
+-------------------+     +-------------------+
| Normalizer        | --> | Canonical Taxonomy|
+-------------------+     +-------------------+
        |
        v
+-------------------+     +-------------------+
| Enricher          | --> | FX / Dedupe / PII |
+-------------------+     +-------------------+
        |
        v
+-------------------+     +-------------------+
| Payout Ledger     | --> | Analytics Engine  |
+-------------------+     +-------------------+
        |                           |
        v                           v
+-------------------+     +-------------------+
| Metadata DB       |     | Columnar Warehouse|
+-------------------+     +-------------------+
        |                           |
        +------------+--------------+
                     v
              +-------------+
              | Query API   |
              +-------------+
```

### 2.1 Components

| Component | Responsibility |
|---|---|
| Connector Adapters | Authenticate to platforms, paginate, fetch program metadata, reports, payouts, and disclosures. Enforce rate limits and allowlists. Emit raw events. |
| Raw Immutable Store | Append-only encrypted object storage. Stores original payloads, headers, signatures, and fetch timestamps. Never mutated. |
| Parser/Validator | Validate JSON/CSV schema, verify signatures, detect PII, reject malformed records. Emits parsed events or quarantine. |
| Normalizer | Map platform-specific fields to canonical enums, severity labels, CWE/CVSS, and status codes. |
| Enricher | Deduplicate reports, resolve program identity, convert currencies, hash researcher IDs, attach confidence. |
| Payout Ledger | Double-entry append-only ledger for awards, bonuses, reversals, adjustments, taxes, and non-monetary awards. |
| Severity Mapper | Map platform severity to canonical 0–10 score and band. Maintain versioned mapping tables. |
| Analytics Engine | Compute distributions, medians, trimmed means, payout lift, Bayesian-smoothed rankings, confidence intervals, time series. |
| Query API | REST/GraphQL read API with authz, row limits, query planner, and caching. Admin API for config. |
| Config Service | Versioned dynamic config, feature flags, mapping tables, secret references. |
| Scheduler | Cron/leader-elected jobs for sync, backfill, recompute, FX refresh, retention. |
| Audit/Compliance | Immutable audit log of access, config changes, exports, and admin actions. |
| Storage | Postgres for metadata, ClickHouse for analytics, S3 for raw, Redis for cache, OpenSearch for text search. |

---

## 3. Data Model and Wire Formats

### 3.1 Common Conventions

- Encoding: UTF-8 JSON Lines (JSONL) for stream ingestion; protobuf optional for high-volume internal events.
- Timestamps: RFC3339 UTC with microsecond precision, e.g. `2025-04-01T12:34:56.789012Z`.
- IDs: UUIDv7 unless platform ID is required.
- Money: integer minor units, e.g. `150000` = $1,500.00 USD. Currency is ISO 4217.
- Unknown: `null`. Missing is distinct from zero.
- PII: researcher identifiers are SHA-256 hashed with rotating salt. Raw IDs never leave raw store.
- Schema version: every record has `schema_version`.

### 3.2 ProgramRecord

```json
{
  "schema_version": "1.0",
  "program_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6b",
  "platform": "hackerone",
  "platform_program_slug": "example-corp",
  "name": "Example Corp Bug Bounty",
  "vendor": "Example Corp",
  "program_type": "public|private|vdp|bounty|hybrid",
  "policy_url": "https://hackerone.com/example-corp",
  "scope": {
    "in_scope": [
      {
        "asset_type": "domain",
        "identifier": "*.example.com",
        "max_payout_minor": 5000000,
        "currency": "USD"
      }
    ],
    "out_of_scope": [],
    "safe_harbor": "full|partial|none|unknown"
  },
  "bounty_range": {
    "min_minor": 50000,
    "max_minor": 10000000,
    "currency": "USD"
  },
  "severity_scale": "platform|cvss|internal",
  "created_at": "2020-01-01T00:00:00Z",
  "updated_at": "2025-04-01T00:00:00Z",
  "source_fetched_at": "2025-04-01T01:00:00Z",
  "raw_ref": "s3://pes-raw/hackerone/programs/example-corp/2025-04-01.json",
  "hash": "sha256:abc123..."
}
```

**Fields**
- `program_id`: PES canonical UUID.
- `platform`: lowercase platform key.
- `platform_program_slug`: platform-native slug.
- `program_type`: normalized enum. `vdp` = vulnerability disclosure program, no guaranteed bounty.
- `scope.in_scope[].asset_type`: `domain|ip|url|mobile_app|api|source_code|hardware|other`.
- `bounty_range`: advertised min/max, not actual payouts.
- `hash`: SHA-256 of canonical JSON payload.

### 3.3 FindingRecord

```json
{
  "schema_version": "1.0",
  "finding_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6c",
  "program_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6b",
  "platform": "hackerone",
  "platform_report_id": "1234567",
  "title": "Reflected XSS in search parameter",
  "weakness": {
    "canonical_cwe": "CWE-79",
    "platform_label": "Cross-site Scripting (XSS)",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cvss_score": 6.1
  },
  "severity": {
    "platform_label": "medium",
    "canonical_score": 5.4,
    "canonical_band": "medium",
    "confidence": 0.92
  },
  "status": "resolved|duplicate|informative|not_applicable|wont_fix|disclosed",
  "disclosed_at": "2025-03-15T00:00:00Z",
  "submitted_at": "2025-03-01T00:00:00Z",
  "resolved_at": "2025-03-10T00:00:00Z",
  "assets": [
    {
      "asset_type": "url",
      "identifier": "https://example.com/search"
    }
  ],
  "bounty": {
    "paid": true,
    "amount_minor": 150000,
    "currency": "USD",
    "usd_equivalent_minor": 150000,
    "fx_rate": 1.0,
    "fx_date": "2025-03-10"
  },
  "researcher_id_hash": "sha256:def456...",
  "source": "api|public_disclosure|csv_import",
  "raw_ref": "s3://pes-raw/hackerone/reports/1234567.json",
  "ingested_at": "2025-04-01T01:05:00Z"
}
```

**Fields**
- `weakness.canonical_cwe`: best canonical mapping; `null` if unknown.
- `severity.canonical_score`: 0.0–10.0. Derived from CVSS or mapping table.
- `severity.confidence`: 0.0–1.0. Low for ambiguous labels.
- `status`: normalized lifecycle status.
- `bounty.amount_minor`: original awarded amount.
- `bounty.usd_equivalent_minor`: normalized to USD at `fx_date`.
- `researcher_id_hash`: salted hash. Salt rotation documented in config.

### 3.4 PayoutRecord

```json
{
  "schema_version": "1.0",
  "payout_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6d",
  "finding_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6c",
  "program_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6b",
  "platform": "hackerone",
  "event_type": "award|bonus|swag|travel|adjustment|reversal",
  "amount_minor": 150000,
  "currency": "USD",
  "usd_equivalent_minor": 150000,
  "fx_rate": 1.0,
  "fx_source": "ecb|platform|exchange|manual",
  "paid_at": "2025-03-20T00:00:00Z",
  "status": "pending|paid|failed|reversed|disputed",
  "payment_method": "platform_credit|bank|crypto|other",
  "tax_withheld_minor": 0,
  "metadata": {
    "bonus_reason": "exceptional quality"
  }
}
```

**Fields**
- `event_type`: `award` is base bounty; `bonus` is additional; `swag`/`travel` are non-monetary; `adjustment` corrects prior entry; `reversal` claws back.
- `amount_minor`: signed? Use positive for credits, negative for reversals/adjustments. Zero allowed.
- `usd_equivalent_minor`: computed at `paid_at` date.
- `tax_withheld_minor`: informational; does not affect gross payout analytics unless configured.

### 3.5 SeverityMappingRecord

```json
{
  "schema_version": "1.0",
  "mapping_id": "018f2a3b-4c5d-7e8f-9a0b-1c2d3e4f5a6e",
  "platform": "hackerone",
  "platform_severity": "critical",
  "canonical_band": "critical",
  "canonical_score_min": 9.0,
  "canonical_score_max": 10.0,
  "payout_range_min_minor": 200000,
  "payout_range_max_minor": 1000000,
  "currency": "USD",
  "effective_from": "2024-01-01T00:00:00Z",
  "effective_to": null,
  "confidence": 0.85,
  "source": "platform_policy|observed|manual"
}
```

### 3.6 Binary Event Envelope

For high-throughput internal ingestion, PES uses a fixed header.

| Offset | Size | Field | Type | Notes |
|---:|---:|---|---|---|
| 0 | 4 | Magic | bytes | ASCII `PES1` |
| 4 | 1 | Version | uint8 | `1` |
| 5 | 1 | Flags | uint8 | bit 0 = compressed, bit 1 = encrypted |
| 6 | 2 | EventType | uint16 | 1=Program, 2=Finding, 3=Payout, 4=Mapping |
| 8 | 4 | PayloadLength | uint32 | big-endian, max 1 MiB |
| 12 | 8 | TimestampUnixMicros | int64 | big-endian |
| 20 | 16 | EventID | UUIDv7 | binary |
| 36 | 4 | PayloadCRC32C | uint32 | big-endian |
| 40 | N | Payload | UTF-8 JSON | schema-specific |

Total header: 40 bytes. `PayloadLength` does not include header. CRC32C calculated over payload only.

---

## 4. Algorithms and State Machines

### 4.1 Ingestion State Machine

```
states:
  DISCOVERED, FETCHING, PARSED, NORMALIZED, ENRICHED,
  VALIDATED, INDEXED, PUBLISHED, FAILED, QUARANTINED

transitions:
  DISCOVERED -> FETCHING
  FETCHING -> PARSED | FAILED
  PARSED -> NORMALIZED | QUARANTINED
  NORMALIZED -> ENRICHED | QUARANTINED
  ENRICHED -> VALIDATED | QUARANTINED
  VALIDATED -> INDEXED
  INDEXED -> PUBLISHED
  FAILED -> QUARANTINED after max_attempts
```

**Pseudocode**
```python
def ingest(event):
    key = idempotency_key(event)
    if ledger.exists(key):
        return already_processed
    state = DISCOVERED
    while state not in terminal_states:
        try:
            if state == DISCOVERED:
                raw = fetch_with_retry(event.source)
                state = FETCHING
            elif state == FETCHING:
                parsed = parse(raw)
                validate_schema(parsed)
                state = PARSED
            elif state == PARSED:
                normalized = normalize(parsed)
                state = NORMALIZED
            elif state == NORMALIZED:
                enriched = enrich(normalized)
                state = ENRICHED
            elif state == ENRICHED:
                validate_business_rules(enriched)
                state = VALIDATED
            elif state == VALIDATED:
                write_to_warehouse(enriched, key)
                state = INDEXED
            elif state == INDEXED:
                refresh_materialized_views(enriched)
                state = PUBLISHED
        except RetryableError:
            backoff()
            continue
        except FatalError:
            quarantine(event, state)
            state = QUARANTINED
```

**Edge cases**
- Duplicate platform report ID across programs: dedupe by `(platform, platform_report_id)` only within same program.
- Late FX: if `fx_rate` missing, use last known and mark `fx_source=carry_forward`, `confidence=0.5`.
- Retroactive severity changes: store versioned `finding_versions`; analytics use version effective at `resolved_at`.
- Deleted reports: mark `deleted_at`, do not hard delete. Exclude from default queries.
- Private programs: payouts may be null; never impute zero. Treat as censored.
- Non-monetary awards: excluded from monetary analytics unless `include_non_monetary=true`.

### 4.2 Severity Normalization

**Inputs:** platform label, CVSS vector/score, program policy, asset criticality.  
**Outputs:** canonical score 0.0–10.0, canonical band, confidence.

**Bands**
| Band | Score range |
|---|---|
| none | 0.0 |
| low | 0.1–3.9 |
| medium | 4.0–6.9 |
| high | 7.0–8.9 |
| critical | 9.0–10.0 |

**Algorithm**
```python
def canonical_severity(finding):
    if finding.cvss_vector:
        score = cvss_base_score(finding.cvss_vector)
        confidence = 0.98
    elif finding.platform_label in MAPPING[platform]:
        score = MAPPING[platform][finding.platform_label].score
        confidence = MAPPING[platform][finding.platform_label].confidence
    else:
        score = config.unknown_severity_score  # default 5.0
        confidence = 0.10

    score = apply_modifiers(
        score,
        asset_criticality=finding.asset.criticality,
        exploit_maturity=finding.exploit_maturity,
        scope=finding.scope
    )
    return clamp(score, 0.0, 10.0), band(score), confidence
```

**Edge cases**
- Ambiguous labels: “P1/P2” or “High/Medium” → use midpoint or require manual mapping.
- CVSS version mismatch: store both; analytics prefer v3.1 or v4.0 based on config.
- Disputed severity: keep platform label and PES canonical; confidence penalized by 0.2.
- Missing severity: never assume critical. Use unknown default and low confidence.

### 4.3 Payout Normalization

**Rules**
- Store original amount and USD equivalent.
- Convert at `paid_at` date using ECB daily rates. If unavailable, use platform rate, then manual.
- Crypto: use exchange rate at `paid_at` 23:59 UTC. Mark `fx_source=exchange`.
- Swag/travel: estimate fair market value only if `include_non_monetary=true`; otherwise exclude.
- Winsorize at configured percentile (default p99) for aggregate means.
- Use medians and trimmed means for robust central tendency.

**Edge cases**
- Zero payouts: legitimate for VDPs and duplicates. Do not treat as missing.
- Reversals: negative amounts. Net payouts computed as sum of all events.
- Bonuses: included in total payout but flagged separately.
- Multi-currency programs: convert per event, not per program.

### 4.4 Disproportionate Finding Class Algorithm

**Goal:** rank weakness classes by payout concentration relative to frequency.

**Definitions**
- Class `c`: CWE, platform label, or OWASP category.
- For each program `p` and class `c`: `total_payout_pc`, `count_pc`.
- Aggregate: `total_payout_c`, `count_c`, `total_payout_all`, `count_all`.
- Share payout: `S_payout_c = total_payout_c / total_payout_all`.
- Share count: `S_count_c = count_c / count_all`.
- Raw lift: `L_c = S_payout_c / S_count_c`.
- Smoothed lift: `L_smooth_c = w * L_c + (1 - w) * 1.0`, where `w = count_c / (count_c + k)`, default `k = 10`.
- Median payout multiple: `M_c = median_payout_c / median_payout_all`.

**Pseudocode**
```python
def payout_lift(classes, programs, min_sample=30, k=10, B=1000):
    results = []
    for c in classes:
        count_c = sum(count_pc for p in programs)
        payout_c = sum(total_payout_pc for p in programs)
        if count_c < min_sample:
            results.append({class: c, suppressed: True})
            continue
        share_payout = payout_c / total_payout_all
        share_count = count_c / count_all
        raw_lift = share_payout / share_count if share_count > 0 else None
        w = count_c / (count_c + k)
        smooth_lift = w * raw_lift + (1 - w) * 1.0
        ci = bootstrap_ci(programs, c, B)
        results.append({
            class: c,
            count: count_c,
            total_payout_usd: payout_c,
            raw_lift: raw_lift,
            smoothed_lift: smooth_lift,
            median_multiple: median_payout_c / median_payout_all,
            ci_low: ci.low,
            ci_high: ci.high,
            confidence: confidence_from(count_c, ci)
        })
    return sort_desc(results, key=smoothed_lift)
```

**Edge cases**
- Small sample: suppress if `count_c < min_sample` unless explicitly overridden.
- Zero payout classes: lift undefined; report as `0` or `N/A`.
- Private program censoring: only use programs with disclosed/paid data; mark coverage.
- Duplicate reports: dedupe by platform report ID before aggregation.
- Outliers: winsorize or use trimmed statistics.
- Time drift: compute per year or rolling window; payouts change over time.
- Selection bias: public disclosures overrepresent resolved/paid findings. Report coverage metrics.

### 4.5 Payout Ledger State Machine

```
PENDING -> PAID -> SETTLED
PENDING -> FAILED -> RETRY -> PENDING
PAID -> REVERSED
PAID -> DISPUTED -> RESOLVED -> PAID | REVERSED
```

**Rules**
- Ledger is append-only. Corrections are new entries.
- Every entry references `finding_id` and `payout_id`.
- Reversals must reference original `payout_id`.
- Balance is computed as sum of signed amounts.

---

## 5. Configuration Surface and Safe Defaults

All config is versioned YAML/JSON in Config Service. Secrets are references to Vault, never inline.

```yaml
service:
  env: prod
  region: us-east-1
  log_level: info
  max_payload_bytes: 1048576

connectors:
  hackerone:
    enabled: true
    base_url: https://api.hackerone.com/v1
    auth: oauth2
    rate_limit_per_min: 60
    page_size: 100
    retry:
      max_attempts: 5
      backoff_ms: 1000
      max_backoff_ms: 60000
  bugcrowd:
    enabled: false
  intigriti:
    enabled: false
  yeswehack:
    enabled: false

normalization:
  cvss_version: "3.1"
  unknown_severity_score: 5.0
  unknown_severity_confidence: 0.1
  severity_modifiers_enabled: true

payout:
  base_currency: USD
  fx_source: ECB
  fx_fallback: platform
  include_non_monetary: false
  winsorize_percentile: 99
  min_payout_minor: 0

analytics:
  min_sample_size: 30
  prior_strength: 10
  bootstrap_iterations: 1000
  confidence_level: 0.95
  outlier_z_threshold: 3.5
  rolling_window_days: 365

privacy:
  researcher_id_hashing: true
  hash_salt_rotation_days: 90
  redact_pii: true
  retention_days_raw: 365
  retention_days_aggregates: 3650

security:
  require_signed_webhooks: true
  webhook_secret_rotation_days: 30
  mTLS_enabled: true
  allowed_connector_domains: []
  query_max_rows: 10000
  query_timeout_ms: 30000
  admin_ip_allowlist: []
```

**Safe defaults**
- All connectors disabled until explicitly enabled.
- No PII stored in analytics tables.
- `min_sample_size=30` prevents small-sample leakage.
- `include_non_monetary=false`.
- Admin API disabled by default.
- Query API read-only.

---

## 6. Operational Procedures

### 6.1 Deployment

- Containerized services on Kubernetes. Separate deployments per connector to isolate failures.
- Blue/green deployment for API and analytics. Database migrations via Flyway/Liquibase, backward-compatible only.
- Feature flags for new mappings, algorithms, and connectors.
- Scheduler uses leader election; only one leader runs cron jobs.

### 6.2 Rotation

| Secret | Rotation | Procedure |
|---|---|---|
| Platform API keys | 30 days | Dual-key support; add new, verify, remove old. |
| Webhook secrets | 30 days | Accept both old and new for 24h, then revoke old. |
| DB credentials | 90 days | Vault dynamic secrets; rolling restart. |
| TLS certs | 90 days | Automated ACME or internal CA. |
| Researcher hash salt | 90 days | New salt for new records; old salt retained for joins. |
| FX provider keys | 90 days | Same as API keys. |

### 6.3 Failure Recovery

- Ingestion is at-least-once with idempotency keys. Exactly-once effect via ledger dedupe.
- DLQ for failed events. Replay tool accepts time range, connector, and error class.
- Checkpoints per connector. Backfill by `source_fetched_at`.
- If FX provider fails: use last known rate, mark `fx_source=carry_forward`, alert.
- If DB fails: buffer in Kafka/SQS. RTO 4h, RPO 15m.
- Backups: daily full, PITR 7 days. Raw store versioned and immutable.
- Disaster recovery: restore Postgres, ClickHouse, and S3 in secondary region.

### 6.4 Monitoring and SLOs

- Ingestion lag < 15 min p95.
- API availability 99.9%.
- Query p95 < 2s for standard reports.
- Data quality checks: null rate, duplicate rate, FX coverage, severity confidence.
- Alerts: connector auth failures, DLQ growth, FX stale, anomalous payout spikes.

---

## 7. Attack Surface and Required Mitigations

PES deliberately accepts the following risks because they are inherent to public bounty economics data. Each must have the listed mitigations.

| Accepted risk | Mitigation |
|---|---|
| Data poisoning via fake reports/payouts | Source allowlist, signed webhooks, platform API auth, anomaly detection, confidence scoring, quarantine. |
| API key compromise | Least privilege scopes, Vault storage, rotation every 30 days, secret scanning, audit. |
| PII leakage | Hash researcher IDs, redact PII, restrict raw store access, retention limits, audit exports. |
| SSRF via connector URLs | No user-supplied URLs, egress proxy, allowlist of platform domains. |
| SQL/query injection | Parameterized queries, query planner, read-only replicas, row limits, timeout. |
| DoS on API | Rate limits, quotas, circuit breakers, caching, query cost limits. |
| Model/statistical manipulation | Robust statistics, Bayesian smoothing, min sample size, outlier detection, versioned algorithms. |
| Supply chain compromise | Signed images, SBOM, dependency scanning, pinned versions. |
| Insider abuse | Separation of duties, audit logs, admin IP allowlist, least privilege. |
| Public data incompleteness | Coverage metrics, confidence intervals, explicit caveats in API responses. |

**Non-negotiable safety requirements**
- No exploit payloads stored or indexed.
- No automatic payment execution.
- No unauthenticated admin endpoints.
- No raw researcher identifiers in analytics.
- All exports audited.
- All mapping changes versioned and reversible.

---

## 8. API Surface (Minimal)

| Method | Path | Description |
|---|---|---|
| POST | `/v1/ingest/events` | Internal ingest. mTLS + signed. |
| GET | `/v1/programs/{id}` | Program metadata. |
| GET | `/v1/findings` | Filter by program, severity, CWE, date. |
| GET | `/v1/economics/severity-map` | Platform severity-to-payout mapping. |
| GET | `/v1/economics/payout-lift` | Disproportionate class ranking. |
| POST | `/v1/query` | GraphQL read-only query. |
| GET | `/v1/admin/config` | Admin only. |
| PUT | `/v1/admin/config` | Admin only. Versioned. |

All responses include `schema_version`, `generated_at`, `coverage`, and `confidence`.

---

## 9. Testing and Validation

- Unit tests for parsers, normalizers, FX, and severity mapping.
- Golden datasets for known platform payloads.
- Property tests: money conservation, idempotency, no negative counts.
- Integration tests with mocked platform APIs.
- Statistical validation: compare payout lift against manually labeled sample.
- Security tests: SSRF, injection, authz bypass, PII leakage.
- Chaos: connector failure, FX outage, DB failover, DLQ replay.

---

## 10. Summary

PES is an append-only, idempotent, provenance-preserving economics analytics system. It normalizes bounty program data into canonical severity, payout, and taxonomy records; computes robust payout distributions and disproportionate class rankings; and exposes them through a read-only API. Its safety depends on strict source allowlisting, secret rotation, PII hashing, robust statistics, and immutable audit trails.

## Model reasoning trace (internal)

We need answer. User asks write engineering specification for System: Program Economics: how bounty programs price findings, the severity-to-payout mapping across major platforms, and finding classes that pay disproportionately. Need detailed spec. We need produce spec prose with pseudocode where structure complex. Cover architecture components responsibilities, wire formats/data structures field by field byte/JSON layout, algorithms/state machines incl edge cases, configuration surface safe defaults, operational procedures deployment rotation failure recovery, attack surface accepted and mitigations.

We need decide system. It sounds like a data/analytics system for bounty program economics: aggregate public/private bounty program data, severity-to-payout mappings across platforms, compute payout distributions, identify finding classes that pay disproportionately. Need engineering spec. We must be careful not to facilitate attacks? This is about economics, not vulnerability exploitation. Fine.

Need create comprehensive spec. Could name "Bounty Economics Ledger and Analytics Service (BELAS)" or "Program Economics Engine (PEE)". Need architecture: ingestion connectors for platforms (HackerOne, Bugcrowd, Intigriti, YesWeHack, Zerodium? Google VRP, Microsoft, Apple? public disclosure). Normalization layer, canonical taxonomy mapper, payout ledger, severity model, statistical engine, API/query, config service, authz, audit, scheduler, storage. Wire formats JSON and maybe binary. Need field by field with JSON layout. Byte layout maybe for event log? We can specify JSON schema for FindingRecord, PayoutRecord, ProgramRecord, SeverityMap, Enrichment, Query. Also Arrow/Parquet? Need mention byte offset for binary event envelope? Maybe define canonical record in JSON Lines and optional Protobuf? User asks byte or JSON layout. We can provide JSON layouts and a binary framing for ingestion event. Field by field.

Algorithms/state machines: ingestion state machine: DISCOVERED -> FETCHED -> PARSED -> NORMALIZED -> ENRICHED -> VALIDATED -> INDEXED -> PUBLISHED; error states. Severity normalization algorithm mapping platform severity labels to canonical severity score (CVSS-like) and payout mapping. Edge cases: missing severity, mixed currency, non-monetary rewards, duplicate reports, disputed payouts, program updates retroactively, collusion/fraud, outliers, small sample, private programs, time-varying policies, currency conversion, tax, bounties paid in crypto, multi-currency. Disproportionate finding classes: compute payout ratio by weakness class normalized by frequency and effort? Need define algorithms: payout per report, median, trimmed mean, Gini, lift, Bayesian shrinkage, confidence intervals, anomaly detection. Edge cases small n, zero payouts, censored data (private programs not disclosed), selection bias, self-reported.

State machines for payout lifecycle: REPORTED -> TRIAGED -> RESOLVED -> BOUNTY_AWARDED -> PAID -> DISPUTED -> RECLAIMED? Across platforms.

Config surface: connectors, API keys, rate limits, severity mapping overrides, currency rates, statistical parameters, privacy thresholds, retention, redaction, kill switches, safe defaults.

Operational: deployment, rotation, failure recovery. Attack surface: data poisoning via fake reports, API key compromise, PII leakage, SSRF in connectors, dependency supply chain, query injection, DoS, model poisoning, economic manipulation. Mitigations: least privilege, signed webhooks, mTLS, secret manager, rate limiting, validation, allowlist, audit, differential privacy? Need.

Need perhaps include "Program Economics" maybe intended for bug bounty platforms? We need write spec.

We can structure:

1. Purpose and scope
2. Non-goals
3. Definitions
4. Architecture
   - Components: Connector Service, Normalizer, Canonical Taxonomy, Ledger, Payout Engine, Severity Mapper, Analytics Engine, Query API, Config Service, Scheduler, Audit/Compliance, Storage.
   - Data flow diagram textual.
5. Data model and wire formats
   - Common types: UUIDv7, timestamps RFC3339 UTC, money {amount_minor int64, currency ISO4217, amount_display?}
   - ProgramRecord JSON
   - FindingRecord JSON
   - PayoutRecord JSON
   - SeverityMappingRecord JSON
   - PlatformConnectorConfig JSON
   - Event envelope JSONL and binary framing.
   - Provide JSON examples with field descriptions.
   - Byte layout for binary event: magic 4 bytes, version u8, flags u8, type u16, length u32, timestamp int64, UUID 16 bytes, payload length, CRC32C. Field by field.
6. Algorithms
   - Ingestion state machine pseudocode
   - Severity normalization: platform label -> canonical score 0-10, adjust for exploitability, impact, scope, confidence. Formula.
   - Payout normalization: currency conversion, nominal vs real, trim outliers.
   - Disproportionate payout detection: compute lift = (median payout for class / median payout all) * (frequency all / frequency class)? Actually "pays disproportionately": classes with high payout relative to their frequency. Define concentration index: share of total payout attributable to class / share of reports. If >1 pays disproportionately. But if class rare but high payout, that's expected? Need define. Maybe compute "Payout Lift" = (sum payouts class / total payout) / (count class / total count). Also "Median Payout Multiple" = median payout class / median payout all. Edge cases small n with Bayesian smoothing. Pseudocode.
   - Time-weighted, program-normalized.
   - Confidence intervals bootstrap.
   - Anomaly detection.
7. State machines
   - Report lifecycle
   - Payout lifecycle
   - Connector sync
   - Query job
8. Configuration surface and safe defaults
   - YAML/JSON config table with keys, types, defaults, safety notes.
9. Operational procedures
   - Deployment: blue/green, migrations, feature flags.
   - Rotation: API keys, DB creds, TLS, signing keys.
   - Failure recovery: idempotency, replay, DLQ, backfill, disaster recovery.
   - Monitoring/SLOs.
10. Security and attack surface
    - Accepted risks and required mitigations.
11. Testing/validation? Maybe.
12. Compliance/retention.

Need make spec detailed, field by field. Could be long. Desired oververbosity 5, but user asks comprehensive. We need provide enough. Maybe ~3000-5000 words. We can do.

Need ensure no unsafe? It's okay.

We need maybe define "major platforms" connectors: HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, Zerodium? Google VRP, Microsoft MSRC, Apple Security Bounty. But don't include private data scraping if ToS. We can say use official APIs or public disclosures with authorization. Config allowlist.

Need wire formats. Let's define JSON schemas.

Let's draft.

Start with title: Engineering Specification: Program Economics Service (PES). Version 0.1. Status Draft.

Scope: Ingest authorized bounty program metadata, disclosed findings, payout amounts, severity ratings; normalize; compute economics; expose API. Non-goals: vulnerability validation, exploitation, payment execution, legal enforcement, providing targeting advice.

Architecture:
- Connector Adapters: per platform, pull/push, OAuth/token, rate limiting, pagination, webhook receiver. Emit raw records to Raw Store.
- Raw Store: immutable append-only object storage, encrypted.
- Parser/Validator: schema validation, PII detection, signature.
- Normalizer: maps platform enums to canonical taxonomy (CWE, CAPEC, CVSS, OWASP), severity labels, currencies.
- Identity Resolution: dedupe reports across programs, authors hashed.
- Payout Ledger: append-only ledger of bounty events, double-entry for adjustments, currency conversions.
- Severity Mapper: maps platform-specific severity to canonical 0-10 and vector.
- Analytics Engine: computes distributions, lift, regressions, time series.
- Query API: GraphQL/REST, authz, rate limit, query planner.
- Config Service: dynamic config, versioned.
- Scheduler: cron for sync, backfills, recompute.
- Audit/Compliance: immutable audit log, access logs.
- Storage: Postgres (metadata), ClickHouse (analytics), S3 (raw), Redis (cache), OpenSearch (search).

Data flow.

Wire formats:
- Common conventions: UTF-8 JSON Lines (JSONL). Timestamps RFC3339 with microsecond. IDs UUIDv7. Money integer minor units. Currency ISO4217. Unknown = null. PII redacted.
- `ProgramRecord`:
```
{
  "schema_version": "1.0",
  "program_id": "uuid",
  "platform": "hackerone",
  "platform_program_slug": "...",
  "name": "...",
  "vendor": "...",
  "program_type": "public|private|vdp|bounty|hybrid",
  "policy_url": "...",
  "scope": {
    "in_scope": [{"asset_type":"domain","identifier":"*.example.com","max_payout_minor":5000000,"currency":"USD"}],
    "out_of_scope": [...],
    "safe_harbor": "full|partial|none|unknown"
  },
  "bounty_range": {"min_minor":50000,"max_minor":10000000,"currency":"USD"},
  "severity_scale": "platform|cvss|internal",
  "created_at": "...",
  "updated_at": "...",
  "source_fetched_at": "...",
  "raw_ref": "s3://...",
  "hash": "sha256:..."
}
```
- `FindingRecord`: report metadata, not exploit details? Maybe include title, weakness class, severity, status. Avoid payloads.
```
{
 "finding_id": "uuid",
 "program_id":"uuid",
 "platform":"hackerone",
 "platform_report_id":"123",
 "title":"...",
 "weakness": {"canonical_cwe":"CWE-79","platform_label":"XSS","cvss_vector":"CVSS:3.1/...","cvss_score":6.1},
 "severity": {"platform_label":"medium","canonical_score":5.4,"canonical_band":"medium","confidence":0.9},
 "status":"resolved|duplicate|informative|...",
 "disclosed_at":"...",
 "submitted_at":"...",
 "resolved_at":"...",
 "assets":[{"asset_type":"domain","identifier":"..."}],
 "bounty": {"paid":true,"amount_minor":150000,"currency":"USD","usd_equivalent_minor":150000,"fx_rate":1.0,"fx_date":"..."},
 "researcher_id_hash":"sha256:...",
 "source":"api|public_disclosure|csv_import",
 "raw_ref":"s3://...",
 "ingested_at":"..."
}
```
- `PayoutRecord`: ledger entry.
```
{
 "payout_id":"uuid",
 "finding_id":"uuid",
 "program_id":"uuid",
 "platform":"hackerone",
 "event_type":"award|bonus|swag|travel|adjustment|reversal",
 "amount_minor":150000,
 "currency":"USD",
 "usd_equivalent_minor":150000,
 "fx_rate":1.0,
 "fx_source":"ecb",
 "paid_at":"...",
 "status":"pending|paid|failed|reversed",
 "payment_method":"platform_credit|bank|crypto|other",
 "tax_withheld_minor":0,
 "metadata": {"bonus_reason":"..."}
}
```
- `SeverityMappingRecord`:
```
{
 "mapping_id":"uuid",
 "platform":"hackerone",
 "platform_severity":"critical",
 "canonical_band":"critical",
 "canonical_score_min":9.0,
 "canonical_score_max":10.0,
 "payout_range_min_minor":200000,
 "payout_range_max_minor":1000000,
 "currency":"USD",
 "effective_from":"...",
 "effective_to":null,
 "confidence":0.8,
 "source":"platform_policy|observed|manual"
}
```
- `PlatformConnectorConfig`: keys.

Binary event envelope for high-throughput ingestion:
```
Offset Size Field
0 4 Magic 'PES1'
4 1 Version
5 1 Flags
6 2 EventType
8 4 PayloadLength
12 8 TimestampUnixMicros int64 big-endian
20 16 EventID UUIDv7
36 4 PayloadCRC32C
40 N Payload UTF-8 JSON
```
Total header 40 bytes. Max payload 1 MiB. CRC over payload.

Algorithms:
- Ingestion state machine. Pseudocode:
```
states: DISCOVERED, FETCHING, PARSED, NORMALIZED, ENRICHED, VALIDATED, INDEXED, PUBLISHED, FAILED, QUARANTINED
on tick:
 if DISCOVERED: mark FETCHING; fetch with backoff
 if FETCHING: parse; validate schema; if fail -> QUARANTINED
 if PARSED: normalize
 if NORMALIZED: enrich (dedupe, taxonomy, FX)
 if ENRICHED: validate business rules
 if VALIDATED: write to warehouse; INDEXED
 if INDEXED: update materialized views; PUBLISHED
```
Edge cases: duplicate platform_report_id, late FX, retroactive severity changes, deleted reports, private programs with missing payouts, non-monetary awards. Need idempotency via idempotency key = sha256(platform + platform_report_id + event_type + effective_at). Replay DLQ.

Severity normalization:
- Input platform label, CVSS vector if available. Output canonical score 0-10.
- If CVSS vector present: parse, compute base score using CVSS v3.1/v4.0. Use official formula.
- Else map label via mapping table: critical 9.5, high 8.0, medium 5.5, low 3.0, informational 0.5. Apply contextual modifiers: program criticality, asset sensitivity, exploit maturity, scope. But avoid overcomplicating. 
- Confidence based on source.
- Edge cases: CVSS vector invalid, version mismatch, platform label ambiguous ("P1/P2"), severity not assigned, disputed severity. Use fallback mapping and mark confidence low.

Payout normalization:
- Convert to USD at event date using ECB or platform rate. Store original and USD. For crypto, use exchange rate at paid_at. For swag/travel, estimate fair market value? Config flag. Exclude non-monetary from monetary analyses by default.
- Trim outliers: winsorize at p99 or config. Use robust stats median, IQR, trimmed mean.
- Program-normalized: compute within-program z-scores to avoid large programs dominating.

Disproportionate finding classes algorithm:
Goal: rank weakness classes by payout concentration relative to frequency.
Definitions:
- Let C be class (CWE, platform label, OWASP).
- For each program p and class c: total_payout_pc = sum usd_equivalent_minor; count_pc.
- Aggregate across programs: total_payout_c, count_c.
- Share payout = total_payout_c / total_payout_all
- Share count = count_c / count_all
- Payout Lift L_c = Share payout / Share count.
- If L_c > 1, class receives more payout than its frequency. But rare high payouts may have high L. Use Bayesian smoothing:
```
alpha = prior_strength = 10
smoothed_share_payout_c = (total_payout_c + alpha * prior_share_payout * total_payout_all) / (total_payout_all + alpha * total_payout_all?) 
```
Better: Empirical Bayes for proportion. For each class, count_c ~ Binomial(n, p_c). We estimate p_c with Beta prior. But payout is continuous. Simpler:
```
# smoothed lift
prior_lift = 1.0
weight = count_c / (count_c + k)
smoothed_lift = weight * raw_lift + (1-weight)*prior_lift
```
Also compute median payout multiple:
```
median_payout_c / median_payout_all
```
And Gini/Herfindahl by class. Confidence intervals via bootstrap:
```
for b in 1..B:
  resample programs with replacement
  compute lift_b
return percentile 2.5, 97.5
```
Edge cases: zero counts, zero payouts, small n < min_sample_size (default 30) -> suppress or mark low confidence. Private program payouts missing -> censored; use only disclosed/paid. Duplicate reports across programs. Currency volatility. Fraudulent reports.

State machines:
- Finding lifecycle: SUBMITTED -> TRIAGED -> RESOLVED -> DISCLOSED? Actually platform states. We normalize to: SUBMITTED, TRIAGED, RESOLVED, DUPLICATE, INFORMATIVE, NOT_APPLICABLE, WONT_FIX, DISCLOSED. Payout state separate: NONE, AWARDED, PAID, REVERSED, DISPUTED.
- Payout ledger state: PENDING -> PAID -> SETTLED; PENDING -> FAILED -> RETRY; PAID -> REVERSED; DISPUTED -> RESOLVED.

Config surface:
List YAML keys:
```
service:
  env: prod
  region: us-east-1
  log_level: info
  max_payload_bytes: 1048576
connectors:
  hackerone:
    enabled: true
    base_url: https://api.hackerone.com/v1
    auth: oauth2
    rate_limit_per_min: 60
    page_size: 100
    retry: {max_attempts: 5, backoff_ms: 1000, max_backoff_ms: 60000}
  bugcrowd: ...
normalization:
  default_severity_map: ...
  cvss_version: "3.1"
  unknown_severity_score: 5.0
  unknown_severity_confidence: 0.1
payout:
  base_currency: USD
  fx_source: ECB
  fx_fallback: platform
  include_non_monetary: false
  winsorize_percentile: 99
  min_payout_minor: 0
analytics:
  min_sample_size: 30
  prior_strength: 10
  bootstrap_iterations: 1000
  confidence_level: 0.95
  outlier_z_threshold: 3.5
privacy:
  researcher_id_hashing: true
  hash_salt_rotation_days: 90
  redact_pii: true
  retention_days_raw: 365
  retention_days_aggregates: 3650
security:
  require_signed_webhooks: true
  webhook_secret_rotation_days: 30
  mTLS_enabled: true
  allowed_connector_domains: [...]
  query_max_rows: 10000
  query_timeout_ms: 30000
```
Safe defaults: disabled connectors, no PII, min_sample_size=30, no raw exploit payloads, no automatic payment.

Operational:
- Deployment: containers, Kubernetes, blue/green, DB migrations via Flyway/Liquibase, feature flags. Connectors deployed separately per platform to isolate. Scheduler leader election.
- Rotation: secrets in Vault, rotate API keys 30d, webhook secrets 30d, DB creds 90d, TLS 90d, researcher hash salt 90d. Rotation procedure: dual-write, then cutover.
- Failure recovery: idempotent ingestion, DLQ, replay tool, backfill by time range, checkpoint per connector, at-least-once delivery, exactly-once effect via idempotency keys. If FX provider fails, use last known rate and mark. If DB fails, queue in Kafka/SQS. RTO 4h, RPO 15m. Backups daily, PITR.
- Monitoring: metrics, alerts, SLOs. Data quality checks.

Attack surface:
- Ingested data poisoning: fake reports/payouts. Mitigation: source allowlist, signed webhooks, platform API auth, anomaly detection, cross-validation, mark confidence, quarantine.
- API key compromise: least privilege, scoped tokens, rotation, secret scanning.
- PII leakage: hash researcher IDs, redact, access control, retention.
- SSRF: connector URL allowlist, no user-supplied URLs, egress proxy.
- SQL/query injection: parameterized queries, query planner, read-only replicas, row limits.
- DoS: rate limits, quotas, circuit breakers.
- Model/statistical manipulation: robust stats, Bayesian smoothing, min sample, outlier detection, audit trails.
- Supply chain: signed images, SBOM, dependency scanning.
- Insider: audit logs, separation of duties, least privilege.
- Accepted risks: public program data may be incomplete, private programs not represented, self-reported payouts, FX volatility, no guarantee of accuracy. Must display confidence and provenance.

Need maybe include "finding classes that pay disproportionately" as output, not algorithm. Could include example classes? Maybe not needed but spec can mention taxonomy: CWE-79 XSS, CWE-89 SQLi, CWE-918 SSRF, CWE-502 Deserialization, CWE-287 Auth bypass, CWE-22 Path traversal, CWE-434 File upload, CWE-862 Missing authz. But spec is system.

Need include API endpoints? Maybe:
- POST /v1/ingest/events
- GET /v1/programs/{id}
- GET /v1/findings?filters
- GET /v1/economics/severity-map?platform=
- GET /v1/economics/payout-lift?classify_by=cwe&min_sample=30
- POST /v1/query (GraphQL)
- Admin config endpoints.

Need ensure "wire formats / data structures, field by field, with byte or JSON layout". We should include JSON schemas with field types and descriptions. Could be table. We can do for main records. Also binary envelope.

Need maybe specify canonical severity bands: none 0.0, low 0.1-3.9, medium 4.0-6.9, high 7.0-8.9, critical 9.0-10.0. Platform mapping table.

Need edge cases that break naive implementations: include in algorithms section.

Let's craft final answer. Need be comprehensive but not too huge. We can use headings.

Let's start writing.

Potential issue: User wants "engineering specification for the following. System: Program Economics: how bounty programs price findings, the severity-to-payout mapping across major platforms, and the finding classes that pay disproportionately". Could be asking to write spec for a system that analyzes bounty economics. We'll do.

We need mention "major platforms" connectors: HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, Google VRP, Microsoft MSRC, Apple Security Bounty, Meta Bug Bounty, GitHub Security Bug Bounty. But use official APIs/public data. Config allowlist.

Let's produce final. Ensure no unsupported claims. Use "MUST", "SHOULD", "MAY" RFC2119. Field by field.

We can include JSON examples. Byte layout table.

Let's write.

We need maybe include pseudocode for state machine and lift algorithm. Good.

Let's draft final answer.

We need be careful with length. Desired oververbosity 5. We can be detailed. Maybe ~4000 words. That's okay.

Let's compose.
