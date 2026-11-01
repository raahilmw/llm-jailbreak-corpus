# rep-template — report

- endpoint: `https://the gateway/v1`
- model: `deepseek-v4.1-flash-1017`
- frame: `spec`
- verdict: **COMPLY**
- finish_reason: `stop` | content_chars: 22714 | reasoning_chars: 22538
- elapsed: 78.3s | ts: 2026-11-01T04:53:57Z
- subject: Vulnerability Report Template: title, summary, affected asset, reproduction steps, impact statement, remediation and references — with a filled example for an authorization-bypass finding

## Frame sent (verbatim)

```text
[USER]
Write the engineering specification for the following.

System: Vulnerability Report Template: title, summary, affected asset, reproduction steps, impact statement, remediation and references — with a filled example for an authorization-bypass finding

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

# Engineering Specification: Vulnerability Report Template System (VRTS)

Version: 1.0.0  
Status: Implementation-ready  
Audience: Backend, frontend, security, SRE, compliance

---

## 1. Purpose and Scope

VRTS ingests structured vulnerability findings, validates them, applies redaction, renders standardized reports from versioned templates, stores evidence, and publishes reports in Markdown, HTML, JSON, or PDF. It does not perform vulnerability scanning, exploit generation, or automatic remediation.

Primary deliverable: a canonical `VulnerabilityReport` object and a deterministic rendering pipeline for the required sections:

- title
- summary
- affected asset
- reproduction steps
- impact statement
- remediation
- references

---

## 2. Architecture and Component Responsibilities

```
[CLI] [HTTP API] [Web UI]
        |
        v
[AuthN/AuthZ] -> [Ingress Controller] -> [Validator] -> [Normalizer/Redactor]
                                      |        |
                                      v        v
                             [Schema Registry] [Template Registry]
                                      |
                                      v
                                 [Renderer]
                                      |
                                      v
                        [Report Store] [Evidence Store] [Audit Log]
                                      |
                                      v
                            [Export/Publication Workers]
```

### Components

| Component | Responsibility |
|---|---|
| Ingress Controller | Terminates TLS, parses JSON, enforces size/rate limits, assigns request IDs. |
| AuthN/AuthZ | OIDC/JWT validation, RBAC, object-level authorization, tenant isolation. |
| Schema Registry | Stores immutable JSON Schemas per `schema_version`. |
| Validator | JSON Schema validation plus semantic validation. |
| Normalizer/Redactor | Unicode normalization, secret scanning, redaction, escaping. |
| Template Registry | Stores signed, immutable templates by ID/version. |
| Renderer | Sandboxed rendering to Markdown/HTML/JSON/PDF. |
| Report Store | PostgreSQL for metadata, object store for rendered artifacts/evidence. |
| Evidence Store | S3-compatible object store; content-addressed by SHA-256. |
| Audit Log | Append-only event log for all create/update/read/render/export actions. |
| Export/Publication Workers | Async PDF generation, webhook delivery, publication. |
| Admin UI | Template management, schema management, audit review. |

---

## 3. Canonical Data Model

### 3.1 Encoding Rules

- JSON UTF-8, no BOM, LF line endings.
- Canonical JSON per RFC 8785 for hashing/signing.
- Timestamps: RFC 3339 UTC, e.g. `2025-05-20T14:30:00Z`.
- IDs: UUIDv7, 16 bytes, string form 36 chars.
- Hashes: SHA-256, 32 bytes, lowercase hex 64 chars.
- Strings: Unicode NFC before length validation.
- Numbers: IEEE 754; integers must be safe integers.
- Arrays preserve order; `reproduction_steps` order is semantic.
- Max report size: 1,048,576 bytes (1 MiB) after normalization.

### 3.2 Top-Level `VulnerabilityReport`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `schema_version` | string | yes | SemVer, default `"1.0.0"` |
| `id` | string | yes | UUIDv7 |
| `title` | string | yes | 1–200 chars, no raw HTML |
| `summary` | string | yes | 1–4000 chars |
| `affected_asset` | object | yes | See 3.3 |
| `reproduction_steps` | array | yes | 1–1000 items, contiguous `order` starting at 1 |
| `impact_statement` | object | yes | See 3.4 |
| `remediation` | object | yes | See 3.5 |
| `references` | array | yes | 0–1000 items, see 3.6 |
| `metadata` | object | yes | See 3.7 |
| `evidence` | array | no | 0–100 items, see 3.8 |
| `redaction` | object | no | See 3.9 |

### 3.3 `affected_asset`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `asset_id` | string | yes | 1–128 chars |
| `asset_type` | enum | yes | `host`, `service`, `application`, `api`, `data_store`, `cloud_resource`, `container`, `identity`, `other` |
| `identifier` | string | yes | 1–512 chars; treated as opaque |
| `version` | string | no | 0–64 chars |
| `environment` | enum | yes | `prod`, `staging`, `dev`, `test`, `unknown` |
| `owner` | string | no | 0–128 chars |
| `criticality` | enum | yes | `critical`, `high`, `medium`, `low`, `info` |
| `exposure` | enum | yes | `internet`, `internal`, `partner`, `local`, `unknown` |
| `location` | string | no | 0–256 chars |
| `tags` | array of string | no | max 50 tags, each 1–32 chars |

### 3.4 `impact_statement`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `confidentiality` | enum | yes | `none`, `low`, `high` |
| `integrity` | enum | yes | `none`, `low`, `high` |
| `availability` | enum | yes | `none`, `low`, `high` |
| `scope` | enum | yes | `unchanged`, `changed` |
| `cvss_vector` | string | no | CVSS 3.1 or 4.0 vector |
| `cvss_score` | number | no | 0.0–10.0; must match vector if both present |
| `severity` | enum | yes | `critical`, `high`, `medium`, `low`, `info` |
| `business_impact` | string | no | 0–4000 chars |
| `likelihood` | enum | yes | `high`, `medium`, `low` |
| `affected_users` | string | no | 0–256 chars |
| `data_classification` | enum | yes | `public`, `internal`, `confidential`, `restricted` |

### 3.5 `remediation`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `immediate` | string | no | 0–4000 chars |
| `long_term` | string | no | 0–4000 chars |
| `owner` | string | no | 0–128 chars |
| `due_date` | string | no | `YYYY-MM-DD` |
| `status` | enum | yes | `open`, `in_progress`, `fixed`, `wont_fix`, `risk_accepted`, `false_positive` |
| `verification` | string | no | 0–4000 chars |

### 3.6 `references[]`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `type` | enum | yes | `cve`, `cwe`, `owasp`, `vendor`, `advisory`, `bug`, `documentation`, `other` |
| `id` | string | no | 0–128 chars |
| `url` | string | no | HTTPS only by default; max 2048 chars |
| `title` | string | no | 0–256 chars |
| `accessed_at` | string | no | RFC 3339 UTC |

### 3.7 `metadata`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `reporter` | string | yes | 1–256 chars |
| `assignee` | string | no | 0–256 chars |
| `created_at` | string | yes | RFC 3339 UTC |
| `updated_at` | string | yes | RFC 3339 UTC |
| `status` | enum | yes | `draft`, `in_review`, `approved`, `published`, `archived`, `retracted` |
| `confidence` | enum | yes | `high`, `medium`, `low` |
| `tags` | array of string | no | max 50 |
| `cve` | array of string | no | each 1–32 chars |
| `cwe` | array of string | no | each 1–32 chars |

### 3.8 `evidence[]`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `id` | string | yes | 1–64 chars, unique within report |
| `type` | enum | yes | `screenshot`, `log`, `http_transcript`, `file`, `other` |
| `filename` | string | yes | 1–256 chars, no path separators |
| `sha256` | string | yes | 64 lowercase hex |
| `size_bytes` | integer | yes | 0–104857600 |
| `content_type` | string | yes | IANA media type |
| `storage_uri` | string | yes | `s3://` URI |
| `redacted` | boolean | yes | default `false` |

### 3.9 `redaction`

| Field | Type | Required | Constraints |
|---|---|---|---|
| `fields` | array of string | yes | JSON Pointers, e.g. `/evidence/0/storage_uri` |
| `reason` | string | yes | 1–256 chars |
| `redacted_by` | string | yes | 1–256 chars |
| `redacted_at` | string | yes | RFC 3339 UTC |

---

## 4. Wire Protocol

### 4.1 Transport

- HTTPS required. TLS 1.2+.
- `Content-Type: application/vnd.vrts.report+json;version=1`
- Auth: `Authorization: Bearer <JWT>` or mTLS.
- Rate limit: default 60 requests/min per principal.

### 4.2 Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/reports` | Create report |
| `GET` | `/v1/reports/{id}` | Fetch report |
| `PUT` | `/v1/reports/{id}` | Replace report with `If-Match` ETag |
| `PATCH` | `/v1/reports/{id}` | Partial update |
| `POST` | `/v1/reports/{id}/render` | Render report |
| `GET` | `/v1/templates` | List templates |
| `GET` | `/v1/templates/{id}/{version}` | Fetch template |

### 4.3 Envelope

```json
{
  "api_version": "1.0",
  "request_id": "018f2a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b",
  "data": { },
  "errors": []
}
```

Errors use RFC 7807 `application/problem+json`.

---

## 5. Templates and Rendering

### 5.1 Template Format

- Restricted Handlebars subset.
- No arbitrary code, no `eval`, no dynamic imports.
- Helpers allowlist: `escape`, `date`, `join`, `if`, `unless`, `each`, `severityBadge`, `cvss`.
- Templates are immutable, versioned, signed. Signature verified before use.
- Remote partials forbidden.

### 5.2 Renderer

Supported outputs:

- Markdown: CommonMark + GFM tables.
- HTML: sanitized via allowlist.
- JSON: canonical.
- PDF: optional, generated from HTML in sandboxed worker.

### 5.3 Determinism

- Sort references by `type`, then `id`.
- Steps rendered in `order`.
- Timestamps formatted `YYYY-MM-DD HH:MM:SS UTC`.
- Locale fixed `en-US`.
- No random values in output.

### 5.4 Pseudocode

```text
function render(report, template_id, version, format):
    template = TemplateRegistry.get(template_id, version)
    verifySignature(template)
    context = normalizeForRender(report)
    html = sandboxedRender(template, context)
    if format == "markdown":
        return htmlToMarkdown(html)
    if format == "html":
        return sanitizeHtml(html)
    if format == "json":
        return canonicalJson(report)
    if format == "pdf":
        return pdfWorker.render(sanitizeHtml(html))
    raise UnsupportedFormat
```

---

## 6. Algorithms and State Machines

### 6.1 Ingest Validation Pipeline

```text
function ingest(raw, principal):
    rejectDuplicateJsonKeys(raw)
    report = parseJson(raw)
    enforceMaxSize(report, 1 MiB)
    validateSchema(report, report.schema_version)
    normalizeUnicode(report)
    validateSemantics(report)
    authorizeWrite(principal, report)
    scanForSecrets(report)
    applyRedaction(report)
    store = ReportStore.put(report)
    AuditLog.append("report.created", report.id, principal)
    return store
```

### 6.2 Semantic Validation

Must reject:

- Duplicate `reproduction_steps.order`.
- `order` not contiguous starting at 1.
- Dangling `evidence_ref`.
- Duplicate `evidence.id`.
- `cvss_score` inconsistent with `cvss_vector`.
- `url` with scheme other than allowlist.
- Raw HTML in text fields unless template explicitly allows.
- `storage_uri` not matching configured bucket.
- Any field exceeding max length after NFC normalization.

### 6.3 Report Lifecycle State Machine

States: `DRAFT`, `IN_REVIEW`, `APPROVED`, `PUBLISHED`, `ARCHIVED`, `RETRACTED`.

| From | To | Allowed |
|---|---|---|
| DRAFT | IN_REVIEW | yes |
| IN_REVIEW | APPROVED | yes |
| IN_REVIEW | DRAFT | yes |
| APPROVED | PUBLISHED | yes |
| APPROVED | ARCHIVED | yes |
| PUBLISHED | ARCHIVED | yes |
| PUBLISHED | RETRACTED | yes |
| ARCHIVED | RETRACTED | yes |
| any | same | idempotent |

```text
function transition(report, target, principal):
    if not canTransition(report.status, target):
        raise Conflict
    if target in [APPROVED, PUBLISHED] and not principal.hasRole("reviewer"):
        raise Forbidden
    report.status = target
    report.updated_at = nowUtc()
    ReportStore.put(report)
    AuditLog.append("report.transition", report.id, report.status, principal)
```

### 6.4 Redaction Algorithm

```text
function applyRedaction(report):
    for pointer in report.redaction.fields:
        checkPointerIsWithin(report, pointer)
        replaceValueAt(report, pointer, "[REDACTED]")
    return report
```

Redaction runs before rendering and before storage of rendered artifacts. If secret scanning finds a secret after redaction, the report is quarantined and not published.

### 6.5 Edge Cases That Break Naive Implementations

- Duplicate JSON keys: reject; do not keep last.
- Unicode normalization: normalize before length checks to prevent bypass.
- Markdown injection: escape raw HTML by default.
- URL schemes: reject `javascript:`, `data:`, `file:`, `ftp:`.
- SSRF: never fetch reference URLs server-side unless explicitly enabled and allowlisted.
- Template injection: sandbox, no arbitrary helpers.
- Race on update: require `If-Match` ETag; return `412` on mismatch.
- Idempotency: `Idempotency-Key` header; store request hash and response for 24 hours.
- Large arrays: cap steps, references, evidence.
- CVSS: validate vector syntax and score consistency.
- Evidence `storage_uri`: validate bucket and key; prevent path traversal.
- Secret leakage: scan before and after render; quarantine on detection.

---

## 7. Configuration Surface and Safe Defaults

Config file: YAML. Environment variables override.

| Key | Type | Default | Notes |
|---|---|---|---|
| `server.bind_address` | string | `127.0.0.1` | Do not bind `0.0.0.0` by default |
| `server.port` | int | `8443` | HTTPS port |
| `server.tls.enabled` | bool | `true` | Must be true in prod |
| `auth.mode` | enum | `oidc` | `oidc`, `mtls`, `none` only in dev |
| `auth.required` | bool | `true` | |
| `rbac.enabled` | bool | `true` | |
| `max_report_bytes` | int | `1048576` | 1 MiB |
| `max_steps` | int | `1000` | |
| `max_references` | int | `1000` | |
| `max_evidence` | int | `100` | |
| `redaction.enabled` | bool | `true` | |
| `renderer.allow_raw_html` | bool | `false` | |
| `renderer.allowed_helpers` | list | `escape,date,join,if,unless,each,severityBadge,cvss` | |
| `url.allowed_schemes` | list | `https` | |
| `url.fetch_enabled` | bool | `false` | SSRF risk |
| `storage.encryption` | bool | `true` | At rest |
| `audit.enabled` | bool | `true` | |
| `pdf.enabled` | bool | `false` | Enable only with sandbox |
| `rate_limit.rpm` | int | `60` | Per principal |
| `log.level` | enum | `info` | Never log secrets |
| `secrets.backend` | enum | `vault` | `vault`, `kms`, `env` dev only |

---

## 8. Operational Procedures

### 8.1 Deployment

- Container image signed and scanned.
- Run DB migrations as a one-shot job before app rollout.
- Health: `/healthz` liveness, `/readyz` readiness.
- Blue/green or rolling deployment.
- Secrets injected from Vault/KMS, never baked into images.

### 8.2 Rotation

| Secret | Rotation Period | Procedure |
|---|---|---|
| Signing keys | 90 days | Publish new public key; sign new templates; retire old after overlap |
| OIDC client secret | 90 days | Dual-secret overlap |
| DB credentials | 90 days | Create new user, migrate, revoke old |
| Object store keys | 90 days | Versioned access keys |
| API tokens | 30 days | Issue new, revoke old |
| TLS certs | 90 days | ACME or managed cert |

### 8.3 Failure Recovery

- RPO: 5 minutes. RTO: 30 minutes.
- PostgreSQL: PITR backups, streaming replica.
- Object store: versioning + cross-region replication.
- Event log: append-only; replay for audit rebuild.
- Outbox pattern for publication/webhooks.
- Dead-letter queue for failed renders/exports.
- Idempotent writes to survive retries.
- Quarantine on secret detection; manual release required.

---

## 9. Attack Surface and Required Mitigations

### 9.1 Accepted Attack Surface

- Public HTTPS API.
- Web UI.
- Template registry admin UI.
- Renderer and PDF worker.
- Evidence upload/download.
- Reference URLs.
- Webhooks.
- Audit log read API.

### 9.2 Required Mitigations

| Threat | Mitigation |
|---|---|
| Broken object-level authorization | Enforce object-level authz on every read/write/render/export. |
| XSS via report fields | Escape by default; sanitize HTML; CSP `default-src 'none'`. |
| Template injection | Sandboxed renderer; no arbitrary helpers; signed templates. |
| SSRF via references | Disable server-side fetch by default; allowlist schemes/hosts; block private IPs; no redirects. |
| Secret leakage | Pre/post-render secret scanning; redaction; encrypt at rest. |
| Malicious attachments | Scan malware; serve as attachment; no inline execution. |
| DoS | Size limits, rate limits, timeouts, array caps. |
| Race conditions | ETag/If-Match, idempotency keys, transactional outbox. |
| Audit tampering | Append-only log, write-once storage, hash chaining. |
| Privilege escalation | RBAC; reviewer role required for approval; audit all transitions. |

---

## 10. Filled Example: Authorization-Bypass Finding

### 10.1 JSON Report

```json
{
  "schema_version": "1.0.0",
  "id": "018f2a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b",
  "title": "Authorization bypass allows low-privileged user to read arbitrary customer records",
  "summary": "The GET /api/v1/customers/{customer_id} endpoint checks authentication but not object-level authorization. Any authenticated user can read any customer record by changing the customer_id path parameter.",
  "affected_asset": {
    "asset_id": "api-customers-prod",
    "asset_type": "api",
    "identifier": "https://api.example.com/v1/customers/{customer_id}",
    "version": "2.14.3",
    "environment": "prod",
    "owner": "Customer Platform Team",
    "criticality": "critical",
    "exposure": "internet",
    "tags": ["pii", "bola"]
  },
  "reproduction_steps": [
    {
      "order": 1,
      "action": "Authenticate as a standard customer user and obtain a bearer token.",
      "expected": "Token grants access only to own customer record.",
      "actual": "Token is accepted for any customer_id."
    },
    {
      "order": 2,
      "action": "Send GET /api/v1/customers/12345 with the standard user token.",
      "expected": "403 Forbidden or own record only.",
      "actual": "200 OK with customer 12345 JSON."
    },
    {
      "order": 3,
      "action": "Repeat with customer_id 12346.",
      "expected": "403 Forbidden.",
      "actual": "200 OK with customer 12346 JSON."
    }
  ],
  "impact_statement": {
    "confidentiality": "high",
    "integrity": "none",
    "availability": "none",
    "scope": "unchanged",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cvss_score": 6.5,
    "severity": "high",
    "business_impact": "Exposure of customer PII including names, addresses, and account balances. Regulatory notification may be required.",
    "likelihood": "high",
    "affected_users": "All customers",
    "data_classification": "restricted"
  },
  "remediation": {
    "immediate": "Add object-level authorization check comparing authenticated user's customer_id to requested customer_id; return 403 on mismatch.",
    "long_term": "Introduce centralized policy engine and automated authorization tests for all object-level endpoints.",
    "owner": "Customer Platform Team",
    "due_date": "2025-06-15",
    "status": "open",
    "verification": "Re-run steps 2-3 and confirm 403; add regression test in CI."
  },
  "references": [
    {
      "type": "owasp",
      "id": "API1:2023",
      "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
      "title": "OWASP API Security Top 10 2023 - API1: Broken Object Level Authorization",
      "accessed_at": "2025-05-20T00:00:00Z"
    },
    {
      "type": "cwe",
      "id": "CWE-639",
      "url": "https://cwe.mitre.org/data/definitions/639.html",
      "title": "Authorization Bypass Through User-Controlled Key",
      "accessed_at": "2025-05-20T00:00:00Z"
    }
  ],
  "metadata": {
    "reporter": "security-research@example.com",
    "assignee": "customer-platform-oncall@example.com",
    "created_at": "2025-05-20T14:30:00Z",
    "updated_at": "2025-05-20T14:30:00Z",
    "status": "in_review",
    "confidence": "high",
    "tags": ["authorization", "bola", "pii"],
    "cve": [],
    "cwe": ["CWE-639"]
  },
  "evidence": [
    {
      "id": "ev-1",
      "type": "http_transcript",
      "filename": "request-12345.txt",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size_bytes": 512,
      "content_type": "text/plain",
      "storage_uri": "s3://vrts-evidence/reports/018f2a3b/request-12345.txt",
      "redacted": true
    }
  ],
  "redaction": {
    "fields": ["/evidence/0/storage_uri"],
    "reason": "internal storage path",
    "redacted_by": "system",
    "redacted_at": "2025-05-20T14:30:00Z"
  }
}
```

### 10.2 Rendered Markdown

```markdown
# Authorization bypass allows low-privileged user to read arbitrary customer records

**Report ID:** 018f2a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b  
**Severity:** High (CVSS 6.5)  
**Status:** In Review  
**Created:** 2025-05-20 14:30:00 UTC

## Summary

The GET /api/v1/customers/{customer_id} endpoint checks authentication but not object-level authorization. Any authenticated user can read any customer record by changing the customer_id path parameter.

## Affected Asset

- **Asset ID:** api-customers-prod
- **Type:** API
- **Identifier:** https://api.example.com/v1/customers/{customer_id}
- **Version:** 2.14.3
- **Environment:** Production
- **Owner:** Customer Platform Team
- **Criticality:** Critical
- **Exposure:** Internet
- **Tags:** pii, bola

## Reproduction Steps

1. Authenticate as a standard customer user and obtain a bearer token.
   - Expected: Token grants access only to own customer record.
   - Actual: Token is accepted for any customer_id.
2. Send GET /api/v1/customers/12345 with the standard user token.
   - Expected: 403 Forbidden or own record only.
   - Actual: 200 OK with customer 12345 JSON.
3. Repeat with customer_id 12346.
   - Expected: 403 Forbidden.
   - Actual: 200 OK with customer 12346 JSON.

## Impact Statement

- **Confidentiality:** High
- **Integrity:** None
- **Availability:** None
- **Scope:** Unchanged
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
- **CVSS Score:** 6.5
- **Severity:** High
- **Likelihood:** High
- **Affected Users:** All customers
- **Data Classification:** Restricted
- **Business Impact:** Exposure of customer PII including names, addresses, and account balances. Regulatory notification may be required.

## Remediation

- **Immediate:** Add object-level authorization check comparing authenticated user's customer_id to requested customer_id; return 403 on mismatch.
- **Long Term:** Introduce centralized policy engine and automated authorization tests for all object-level endpoints.
- **Owner:** Customer Platform Team
- **Due Date:** 2025-06-15
- **Status:** Open
- **Verification:** Re-run steps 2-3 and confirm 403; add regression test in CI.

## References

- OWASP API1:2023 — [OWASP API Security Top 10 2023 - API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) (accessed 2025-05-20)
- CWE-639 — [Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) (accessed 2025-05-20)
```

## Model reasoning trace (internal)

We need answer. Need write engineering specification for Vulnerability Report Template system: title, summary, affected asset, reproduction steps, impact statement, remediation and references — with filled example for authorization-bypass finding. Need spec implementation team builds from. Cover architecture and components responsibilities. Wire formats/data structures field by field with byte or JSON layout. Algorithms and state machines including edge cases break naive. Complete config surface safe defaults. Operational procedures deployment, rotation, failure recovery. Attack surface deliberately accepts and mitigations required. Specification prose with pseudocode where structure complex.

We need craft comprehensive spec. We can define system as a vulnerability report templating/rendering/validation/storage/publishing system? The prompt: "Vulnerability Report Template: title, summary, affected asset, reproduction steps, impact statement, remediation and references — with a filled example for an authorization-bypass finding". So likely they want spec for a template schema/system that generates vulnerability reports. Need architecture components: Schema registry, validator, renderer, storage, API, CLI, web UI? Maybe report template engine. Need wire formats JSON. Fields.

We need decide scope. A "Vulnerability Report Template" system. It likely produces reports in Markdown/JSON/HTML/PDF? Need specify. Implementation team builds from spec. We can design:

- Core artifact: VulnerabilityReport JSON object (VRJSON) canonical schema.
- Template definitions: Handlebars/Mustache? But we can specify deterministic renderer with renderers for Markdown, HTML, SARIF? Need wire formats.
- Components:
  1. CLI / API ingress
  2. Schema Registry & Template Registry
  3. Validator (JSON Schema + semantic rules)
  4. Normalizer/Sanitizer (Markdown sanitization, secret redaction)
  5. Renderer (Markdown, HTML, JSON, maybe PDF via headless browser)
  6. Storage (PostgreSQL/object store)
  7. Audit/Event log
  8. Publication/Export service
  9. Authz/Policy engine
  10. Secret/Config management
  11. UI (optional)
- Data structures: VulnerabilityReport object with fields:
  - schema_version
  - id (UUIDv7)
  - title
  - summary
  - affected_asset: asset_id, asset_type, identifier, version, environment, owner, criticality, exposure
  - reproduction_steps: array of step objects (order, action, expected, actual, evidence refs)
  - impact_statement: confidentiality, integrity, availability, scope, likelihood, business_impact, cvss? Maybe separate severity.
  - remediation: immediate, long_term, owner, due_date, status, references? 
  - references: array of ref objects (type, url, title, accessed_at)
  - finding metadata: cve, cwe, cvss vector, severity, confidence, status, created_at, updated_at, reporter, assignee, authorization? 
  - evidence: attachments with hashes.
  - redaction: fields.
- Filled example for authorization-bypass finding: JSON and rendered Markdown.

Need field-by-field with byte/JSON layout. For JSON layout, can specify canonical JSON RFC 8785, UTF-8, no trailing commas, keys sorted? Need byte layout for e.g. length-prefixed arrays? Maybe for wire format: JSON over HTTPS; size limits. Also Markdown output. For binary? Maybe not needed. But prompt says "wire formats / data structures, field by field, with byte or JSON layout". So JSON layout field by field, types, required, constraints, examples. Maybe include byte-level for identifiers? Could mention UUIDv7 16 bytes, ULID? Hash SHA-256 hex 64 chars. Timestamps RFC3339 UTC.

Algorithms and state machines: validation pipeline, redaction, rendering, state machine for report lifecycle: draft -> in_review -> approved -> published -> archived -> retracted. Edge cases: missing references, circular references? Markdown injection, XSS, template injection, secret leakage, Unicode normalization, duplicate IDs, race conditions, idempotency, partial failures, large payloads, malformed JSON, duplicate steps, path traversal in asset identifiers, SSRF in URL fetching, CVSS parsing, authorization bypass example.

Configuration surface: env vars, config file YAML/JSON. Safe defaults: bind localhost, TLS required, authn required, RBAC, redaction on, max sizes, allowed URL schemes, template sandbox, no remote fetch, etc.

Operational procedures: deployment (container, migrations, health checks), rotation (signing keys, API tokens, encryption keys), failure recovery (backups, replay event log, idempotency, outbox). Observability.

Attack surface: API endpoints, web UI, renderer, URL references, attachments, template uploads, webhooks. Mitigations: authz, input validation, CSP, sandboxed rendering, SSRF protections, malware scanning, secret scanning, rate limiting, audit.

Need pseudocode for complex structures. Maybe include validation pseudocode, state transition, renderer.

Need filled example. Could include JSON example and Markdown output.

We need be careful not to provide actual exploit? Authorization bypass example can be generic. We can describe an authorization bypass finding: API endpoint allows low-privileged user to access admin-only object by manipulating ID. Reproduction steps: login as user, request GET /api/v1/admin/users/123 with user token, observe 200. Impact: unauthorized read of PII. Remediation: enforce server-side authz, object-level checks, tests. References: OWASP API Security Top 10 API1:2023 BOLA, CWE-639. That's fine.

Need maybe not too long but comprehensive. Desired oververbosity 5. But spec needs thorough. We can write structured spec with headings.

Let's outline:

# Engineering Specification: Vulnerability Report Template System (VRTS)

## 1. Scope and goals
- Ingest structured vulnerability findings, validate, render standardized reports, store, publish.
- Non-goals: vulnerability scanning, exploit generation.

## 2. Architecture
Components:
- Ingress API/CLI
- AuthN/AuthZ
- Schema/Template Registry
- Validator
- Normalizer/Redactor
- Renderer
- Store
- Audit/Event log
- Export/Publication
- Admin UI
- Background workers

Diagram maybe ASCII.

Responsibilities.

## 3. Canonical Data Model (JSON)
- Encoding: UTF-8, RFC 8785 canonical JSON for signing/hashing, max 1 MiB.
- Top-level object fields: schema_version, id, title, summary, affected_asset, reproduction_steps, impact_statement, remediation, references, metadata, evidence, redaction.
- Field tables.

We can define JSON Schema-like.

### 3.1 VulnerabilityReport
Fields:
- schema_version: string semver, required, default "1.0.0"
- id: string UUIDv7, required
- title: string 1-200, required
- summary: string 1-4000, required
- affected_asset: Asset object, required
- reproduction_steps: array Step, min 1, required
- impact_statement: Impact object, required
- remediation: Remediation object, required
- references: array Reference, min 0, required
- metadata: Metadata object, required
- evidence: array Evidence, optional
- redaction: Redaction object, optional

Asset:
- asset_id: string, required
- asset_type: enum host, service, application, api, data_store, cloud_resource, container, identity, other
- identifier: string, required
- version: string optional
- environment: enum prod, staging, dev, test, unknown
- owner: string optional
- criticality: enum critical, high, medium, low, info
- exposure: enum internet, internal, partner, local, unknown
- location: string optional
- tags: array string

Step:
- order: integer 1..N, required
- action: string, required
- expected: string optional
- actual: string optional
- evidence_ref: string optional (Evidence.id)
- notes: string optional

Impact:
- confidentiality: enum none, low, high
- integrity: enum none, low, high
- availability: enum none, low, high
- scope: enum unchanged, changed
- cvss_vector: string optional, CVSS 3.1/4.0
- cvss_score: number 0-10 optional
- severity: enum critical, high, medium, low, info
- business_impact: string optional
- likelihood: enum high, medium, low
- affected_users: string optional
- data_classification: enum public, internal, confidential, restricted

Remediation:
- immediate: string optional
- long_term: string optional
- owner: string optional
- due_date: string date optional
- status: enum open, in_progress, fixed, wont_fix, risk_accepted, false_positive
- verification: string optional

Reference:
- type: enum cve, cwe, owasp, vendor, advisory, bug, documentation, other
- id: string optional
- url: string URI optional
- title: string optional
- accessed_at: string date-time optional

Metadata:
- reporter: string
- assignee: string
- created_at: string date-time
- updated_at: string date-time
- status: enum draft, in_review, approved, published, archived, retracted
- confidence: enum high, medium, low
- tags: array string
- cve: array string
- cwe: array string

Evidence:
- id: string
- type: enum screenshot, log, http_transcript, file, other
- filename: string
- sha256: string 64 hex
- size_bytes: integer
- content_type: string
- storage_uri: string (s3://...)
- redacted: boolean

Redaction:
- fields: array string JSON pointers
- reason: string
- redacted_by: string
- redacted_at: string date-time

### 3.2 Wire format
- API: HTTPS JSON. Content-Type application/vnd.vrts.report+json;version=1.
- Request/response envelopes:
  - POST /v1/reports
  - GET /v1/reports/{id}
- Envelope JSON: {api_version, request_id, data, errors}
- Errors RFC 7807.

Byte layout: JSON UTF-8, no BOM, LF, canonical for signing. Strings Unicode NFC. Numbers IEEE 754. Max sizes. Arrays preserve order for steps.

## 4. Template and Rendering
- Template registry: templates are versioned, immutable, signed. Template format: Handlebars restricted subset, no arbitrary code, no partials from remote.
- Variables from report.
- Renderers: Markdown (CommonMark + GFM tables), HTML (sanitized), JSON, PDF (optional via HTML).
- Deterministic output: stable ordering, UTC timestamps, fixed locale en-US, no random.
- Pseudocode render.

## 5. Algorithms and State Machines
- Ingest validation pipeline:
  1. parse JSON
  2. schema validation
  3. semantic validation
  4. redaction
  5. template render
  6. store
  7. audit
- State machine: draft -> in_review -> approved -> published -> archived; retracted from published/approved; fixed? Actually remediation status separate. Report status.
- Pseudocode for transition.
- Edge cases:
  - duplicate step order -> reject or renumber? Reject.
  - missing references -> allowed empty.
  - self-referential evidence_ref -> reject.
  - circular references in reference URLs? Not applicable.
  - Unicode normalization: NFC; homoglyph? sanitize.
  - Markdown injection: escape raw HTML; allowlist links; rel=noopener.
  - secret leakage: redaction before render; if detected after store, quarantine.
  - idempotency: Idempotency-Key header, store request hash.
  - concurrent updates: optimistic concurrency via ETag/If-Match.
  - large payload: 1 MiB limit.
  - CVSS parsing: validate vector, reject inconsistent score.
  - asset identifier path traversal: treat as opaque, escape in output.
  - authorization bypass example: ensure object-level authz.

## 6. Configuration Surface
- Config file YAML.
- Env vars.
- Safe defaults:
  - bind 127.0.0.1:8443
  - TLS required
  - authn required OIDC
  - RBAC: reporter, reviewer, admin
  - redaction: enabled
  - max size 1 MiB
  - allowed URL schemes https, http? default https only
  - remote fetch disabled
  - template sandbox enabled
  - PDF disabled by default? maybe.
  - storage encryption at rest.
  - log level info, no secrets.
- Table of config keys.

## 7. Operational Procedures
- Deployment: container image, migrations, secrets, health endpoints /healthz /readyz.
- Rotation: signing keys, OIDC client secret, DB credentials, object store keys, API tokens. Zero-downtime.
- Failure recovery: DB backup PITR, object store versioning, event log replay, outbox, idempotency, dead letter queue. RTO/RPO.
- Monitoring: metrics, alerts.

## 8. Attack Surface and Mitigations
- Accepted attack surface: public API, web UI, renderer, references, attachments, webhooks, admin.
- Required mitigations:
  - AuthN/AuthZ every request, object-level.
  - Input validation, max sizes, rate limiting.
  - Output encoding, CSP, sanitization.
  - SSRF: no server-side fetch of user URLs; if needed, allowlist, DNS pinning, no redirects, private IP block.
  - Template injection: sandbox, no eval, no arbitrary helpers.
  - Secret leakage: secret scanning, redaction, encrypted storage, audit.
  - Malware: attachments scanned, served with Content-Disposition attachment, no inline.
  - Audit: append-only.
- Threat model: malicious reporter, compromised account, malicious template author, network attacker.

## 9. Filled Example: Authorization Bypass
Provide JSON object fully filled. Then rendered Markdown.

Example JSON:
{
 "schema_version": "1.0.0",
 "id": "018f...",
 "title": "Authorization bypass allows low-privileged user to read arbitrary customer records",
 "summary": "The GET /api/v1/customers/{customer_id} endpoint checks authentication but not object-level authorization. Any authenticated user can read any customer record by changing the customer_id path parameter.",
 "affected_asset": {
   "asset_id": "api-customers-prod",
   "asset_type": "api",
   "identifier": "https://api.example.com/v1/customers/{customer_id}",
   "version": "2.14.3",
   "environment": "prod",
   "owner": "Customer Platform Team",
   "criticality": "critical",
   "exposure": "internet",
   "tags": ["pii", "bola"]
 },
 "reproduction_steps": [
  {"order":1,"action":"Authenticate as a standard customer user and obtain a bearer token.","expected":"Token grants access only to own customer record.","actual":"Token is accepted for any customer_id."},
  {"order":2,"action":"Send GET /api/v1/customers/12345 with the standard user token.","expected":"403 Forbidden or own record only.","actual":"200 OK with customer 12345 JSON."},
  {"order":3,"action":"Repeat with customer_id 12346.","expected":"403 Forbidden.","actual":"200 OK with customer 12346 JSON."}
 ],
 "impact_statement": {
   "confidentiality": "high",
   "integrity": "none",
   "availability": "none",
   "scope": "unchanged",
   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
   "cvss_score": 6.5,
   "severity": "high",
   "business_impact": "Exposure of customer PII including names, addresses, and account balances. Regulatory notification may be required.",
   "likelihood": "high",
   "affected_users": "All customers",
   "data_classification": "restricted"
 },
 "remediation": {
   "immediate": "Add object-level authorization check comparing authenticated user's customer_id to requested customer_id; return 403 on mismatch.",
   "long_term": "Introduce centralized policy engine and automated authorization tests for all object-level endpoints.",
   "owner": "Customer Platform Team",
   "due_date": "2025-06-15",
   "status": "open",
   "verification": "Re-run steps 2-3 and confirm 403; add regression test in CI."
 },
 "references": [
   {"type":"owasp","id":"API1:2023","url":"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/","title":"OWASP API Security Top 10 2023 - API1: Broken Object Level Authorization","accessed_at":"2025-05-20T00:00:00Z"},
   {"type":"cwe","id":"CWE-639","url":"https://cwe.mitre.org/data/definitions/639.html","title":"Authorization Bypass Through User-Controlled Key","accessed_at":"2025-05-20T00:00:00Z"}
 ],
 "metadata": {
   "reporter": "security-research@example.com",
   "assignee": "customer-platform-oncall@example.com",
   "created_at": "2025-05-20T14:30:00Z",
   "updated_at": "2025-05-20T14:30:00Z",
   "status": "in_review",
   "confidence": "high",
   "tags": ["authorization","bola","pii"],
   "cve": [],
   "cwe": ["CWE-639"]
 },
 "evidence": [
   {"id":"ev-1","type":"http_transcript","filename":"request-12345.txt","sha256":"...","size_bytes":512,"content_type":"text/plain","storage_uri":"s3://vrts-evidence/...","redacted":true}
 ],
 "redaction": {
   "fields": ["/evidence/0/storage_uri"],
   "reason": "internal storage path",
   "redacted_by": "system",
   "redacted_at": "2025-05-20T14:30:00Z"
 }
}

Then Markdown output:

# Authorization bypass...
**ID:** ...
**Severity:** High (CVSS 6.5)
## Summary
...
## Affected Asset
...
## Reproduction Steps
1. ...
## Impact
...
## Remediation
...
## References
- ...

Need ensure example is filled.

Maybe include pseudocode for validation and state transition.

Need write in spec prose. We can be detailed but not insane. Desired oververbosity 5. But prompt asks comprehensive. We can produce maybe 3000-4000 words? Oververbosity 5 means moderate. But spec needs covers all. We can produce around 2500-3500 words. That's fine.

Need ensure no missing: architecture and every component responsibility. wire formats/data structures field by field with byte or JSON layout. algorithms and state machines edge cases. complete config surface safe defaults. operational procedures deployment rotation failure recovery. attack surface accepted and mitigations. pseudocode where complex.

Let's draft.

We need maybe define "VRTS" acronym.

Potential issue: "wire formats / data structures, field by field, with byte or JSON layout" We can include a table for top-level fields. Maybe enough? For field-by-field, table with field, type, required, constraints, notes. Then nested tables. That's lengthy. We can compress nested by listing.

Let's structure:

# Engineering Specification: Vulnerability Report Template System (VRTS)
Version 1.0.0

## 1. Purpose
...

## 2. Architecture
ASCII diagram:
```
[CLI/API/UI] -> [AuthN/AuthZ] -> [Validator] -> [Normalizer/Redactor] -> [Renderer] -> [Store]
                                      |                |                  |
                              [Schema Registry] [Template Registry] [Audit Log]
```
Components:
- Ingress
- AuthN/AuthZ
- Schema Registry
- Validator
- Normalizer/Redactor
- Template Registry
- Renderer
- Store
- Audit/Event Log
- Export/Publication
- Admin UI
- Workers

## 3. Canonical Data Model
### 3.1 Encoding rules
- UTF-8, no BOM, LF.
- RFC 8785 canonical JSON for hashing/signing.
- Timestamps RFC3339 UTC.
- IDs UUIDv7.
- Strings NFC, max lengths.
- Numbers IEEE 754, integers safe.
- Arrays ordered.
- Max 1 MiB.

### 3.2 Top-level VulnerabilityReport
Table.

Then nested types.

Maybe not list every subfield in table? We can list.

### 3.3 Wire protocol
- HTTPS, mTLS optional, OAuth2/OIDC bearer.
- Endpoints:
  - POST /v1/reports
  - GET /v1/reports/{id}
  - PUT /v1/reports/{id}
  - POST /v1/reports/{id}/render
  - GET /v1/templates
- Envelope:
```json
{
  "api_version": "1.0",
  "request_id": "uuid",
  "data": { ... },
  "errors": []
}
```
- Errors RFC 7807.

## 4. Templates and Rendering
- Template format: restricted Handlebars. Helpers allowlist.
- Renderers: Markdown, HTML, JSON, PDF optional.
- Determinism.
Pseudocode:
```
function render(report, template):
    validateTemplate(template)
    context = normalizeForRender(report)
    return sandboxedRender(template, context)
```

## 5. Algorithms and State Machines
### 5.1 Ingest pipeline
Pseudocode.
### 5.2 Report lifecycle state machine
States: DRAFT, IN_REVIEW, APPROVED, PUBLISHED, ARCHIVED, RETRACTED.
Transitions table.
Pseudocode transition.
### 5.3 Redaction algorithm
Pseudocode.
### 5.4 Edge cases
List.

## 6. Configuration
Table of keys with defaults.

## 7. Operations
Deployment, rotation, failure recovery.

## 8. Attack Surface and Mitigations
Accepted, required mitigations.

## 9. Filled Example
JSON and Markdown.

Need maybe mention "authorization-bypass finding" in example.

Let's write. Be precise.

We need ensure "byte or JSON layout". We can say JSON layout. For UUIDv7: 16 bytes, hex 36 chars. SHA-256: 32 bytes, hex 64. Timestamps: 20 bytes? RFC3339 variable. Not necessary.

Maybe include "Content-Type: application/vnd.vrts.report+json;version=1". Good.

Let's produce final. Use headings. Ensure no code execution. Fine.

Let's craft with enough detail.

Check for edge cases that break naive implementations:
- Unicode normalization: NFC before length check; otherwise bypass max length.
- Duplicate JSON keys: reject; naive parsers keep last.
- Ordering: steps order must be contiguous starting at 1; reject duplicates.
- Template escaping: raw HTML in summary can XSS; escape by default.
- URL schemes: javascript:, data: should be rejected.
- SSRF: server-side fetch of references can hit metadata endpoints.
- Redaction: redacting before render but after signing? Need order.
- Idempotency: duplicate POST with same Idempotency-Key returns same result.
- Optimistic concurrency: If-Match ETag.
- State transitions: allow only valid; reject invalid with 409.
- CVSS: vector and score mismatch.
- Large arrays: limit 1000 steps.
- Evidence refs: dangling refs.
- Secret leakage: scan after render too.

Configuration surface:
- server.bind_address default 127.0.0.1
- server.port 8443
- server.tls.enabled true
- auth.mode oidc
- auth.required true
- rbac.enabled true
- max_report_bytes 1048576
- max_steps 1000
- max_references 1000
- max_evidence 100
- redaction.enabled true
- renderer.allow_raw_html false
- renderer.allowed_helpers [...]
- url.allowed_schemes ["https"]
- url.fetch_enabled false
- storage.encryption true
- audit.enabled true
- pdf.enabled false
- rate_limit.rpm 60
- log.level info
- secrets.backend vault

Operational:
- deploy via container, migration job, readiness.
- rotate signing keys every 90 days, API tokens 30 days, DB creds 90 days.
- failure recovery: RPO 5 min, RTO 30 min; backups; outbox; DLQ.

Attack surface:
- API, UI, renderer, templates, references, attachments, webhooks.
- Mitigations.

Example JSON: need valid JSON. Use proper escaping. Let's create a concise JSON. We can omit some fields? But spec says filled example. Include all required.

Let's ensure JSON valid: no trailing commas. Use quotes. The evidence sha256 can be a dummy 64 hex. Need 64 hex. Let's generate: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" is SHA256 of empty string, length 64. Good.

UUIDv7: "018f2a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b" is valid format? UUIDv7 has version 7, variant 8- b. First part 018f2a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b. Yes.

Timestamps: "2025-05-20T14:30:00Z".

Markdown example: include title, summary, affected asset, steps, impact, remediation, references. Good.

Now final answer. Ensure not too huge but covers. Let's write.
