**Broken Object-Level Authorization (BOLA)**, also known as IDOR (Insecure Direct Object Reference), occurs when an application exposes an object identifier (e.g., `/api/v1/invoices/12345`) and fails to verify that the authenticated user is actually authorized to act on that specific object instance. Authentication (who you are) is distinct from authorization (what you may touch); BOLA is an authorization failure.

Below is a standard testing sequence, organized by enumeration, request-pair proof, and token abuse.

---

### 1. Enumerating Object Identifiers

Before you can test authorization, you must discover where object references live and what format they use.

| Location | What to look for | Example |
|----------|------------------|---------|
| **URL path** | Numeric IDs, UUIDs, slugs, opaque references | `GET /orders/98765` |
| **Query parameters** | `id`, `object_id`, `resource`, `uid` | `GET /api/document?doc_id=abc-123` |
| **Request body** | JSON/XML fields referencing other resources | `{"target_user_id": "42", "action": "view"}` |
| **Headers** | `X-Resource-ID`, `X-Account-ID`, custom headers | `X-Invoice-Id: INV_2024_001` |
| **API responses** | IDs embedded in JSON/XML that were not requested | Response includes `"related_asset_id": "777"` |
| **JWT claims** | `sub`, `user_id`, `account_id`, `org_id` embedded in the token | JWT payload: `{"sub": "usr_555", "org": "org_9"}` |
| **OAuth tokens** | Access/introspection responses revealing resource ownership | Introspection returns `client_id` and `scope` but not per-object rights |

**Enumeration techniques**
* **Sequential / predictable IDs:** Integers (`1`, `2`, `3…`) or timestamps are easy to guess.
* **UUIDs / opaque IDs:** Harder to guess, but often leaked in other API responses, JavaScript source, or public feeds.
* **Fuzzing / brute force:** Use Burp Intruder, OWASP ZAP, or custom scripts to iterate IDs and observe response differences (e.g., `200 OK` vs `404 Not Found` vs `403 Forbidden`).
* **Response analysis:** A `404` may mean “not found” or “not authorized.” A `403` usually means the server knows the object exists but refuses access—both are useful signals.

> **Ethical boundary:** Only perform enumeration on systems you own or have explicit, written permission to test.

---

### 2. Request Pairs That Prove BOLA

The core of BOLA testing is a **paired request**: the same request, same authenticated session, but with the object identifier swapped to one owned by another user.

#### Baseline Request (User A)
```
GET /api/v1/profile/1001 HTTP/1.1
Host: target.example.com
Authorization: Bearer <UserA_JWT_or_OAuth_Access_Token>
```
*Expected:* `200 OK` — returns User A’s profile data.

#### Swapped Request (User A attempts User B’s object)
```
GET /api/v1/profile/1002 HTTP/1.1
Host: target.example.com
Authorization: Bearer <UserA_JWT_or_OAuth_Access_Token>
```
*Vulnerable if:* The server returns `200 OK` with User B’s data, or returns partial data that should be restricted.

#### What to compare
| Result | Interpretation |
|--------|----------------|
| `200 OK` with foreign data | **Confirmed BOLA** (horizontal privilege escalation). |
| `200 OK` with redacted/partial data | Possible **partial BOLA** or field-level authorization issue. |
| `403 Forbidden` | Proper authorization check (not vulnerable for this object). |
| `404 Not Found` | Ambiguous: could be true absence or “not found” used to hide authorization failure. Test with known-valid foreign IDs to disambiguate. |

#### Horizontal vs. Vertical
* **Horizontal:** User A accesses User B’s object at the same privilege level (e.g., another customer’s invoice).
* **Vertical:** User A accesses an admin-only object (e.g., `/api/v1/admin/users/5`) using a standard user token. This is often easier to spot because the baseline request for User A would normally return `403`.

#### Multi-step request pairs
Some BOLA flaws only appear in state-changing operations:
1. `POST /api/v1/orders/1001/cancel` with User A’s token → succeeds.
2. `POST /api/v1/orders/1002/cancel` with User A’s token → succeeds (should fail).

Always test **GET, POST, PUT, PATCH, DELETE** against the same object ID space.

---

### 3. How JWT and OAuth Token Abuse Fit In

BOLA is an authorization logic flaw, but weak token handling can make it easier to exploit or expand its impact.

#### JWT Abuse in the Context of BOLA
A JWT proves identity (authentication), but the server must still enforce object ownership (authorization). Common JWT issues that intersect with BOLA:

* **None/weak algorithm or key confusion:** An attacker can forge a JWT with a different `sub` (subject) or `user_id`, then use that forged token to request objects belonging to the impersonated user. The BOLA flaw is what lets the forged request reach the object; the JWT abuse is what supplies the false identity.
* **Exposed or guessable secrets:** If the JWT signing key is leaked, an attacker can mint tokens for arbitrary users and then run the BOLA request-pair sequence at scale.
* **`kid` header injection / JWKS manipulation:** Can be used to force the server to accept an attacker-controlled public key, again enabling token forgery.
* **Claims stored client-side:** If the application trusts a JWT claim like `is_admin: true` or `account_id` without verifying it against a server-side session store, an attacker can modify the claim and attempt to access objects outside their scope.

**Key point:** Even a perfectly signed, valid JWT does not authorize access to *every* object. The resource server must check `token.subject == object.owner` (or an equivalent ACL) before returning data.

#### OAuth Token Abuse in the Context of BOLA
OAuth 2.0 is a delegation framework, not an access-control model for individual database rows. Token abuse can amplify BOLA:

* **Scope confusion:** An access token with `scope=read:profile` may be presented to a resource server that hosts invoices. If the resource server only checks that the token is valid and not scoped to `read:invoices`, BOLA may occur.
* **Token reuse across resource servers:** A token issued for one microservice may be accepted by another if they share the same authorization server but do not validate audience (`aud`) or resource indicators.
* **Refresh token abuse:** If an attacker obtains a refresh token, they can generate new access tokens and continue enumerating object IDs long after the original access token expires.
* **Implicit / response-type token leakage:** Tokens leaked via browser history or referer headers can be reused by an attacker to perform BOLA requests from outside the original session.

#### Combined attack flow (conceptual)
1. **Enumerate** object IDs from public API responses (e.g., `invoice_id` in a list endpoint).
2. **Obtain or forge** a token (via JWT weakness, phishing, XSS, or token leakage) belonging to User A.
3. **Send the swapped request pair** using User A’s token to access User B’s object ID.
4. If the server returns User B’s data, BOLA is confirmed. If the token was forged to be User C (admin), vertical escalation may also be proven.

---

### 4. Confirmation and Reporting

To avoid false positives:
* Verify that the foreign object ID is **known to exist** (e.g., you saw it in another legitimate response or created it with a second account).
* Confirm the response contains **actual foreign data**, not just a generic success message.
* Check whether the server returns `404` for unauthorized objects; if so, compare response timing or error messages to distinguish “not found” from “forbidden.”

When reporting, include:
* The exact request pair (baseline and swapped).
* The authentication token used (sanitized).
* The object IDs and what they represent.
* The impact (data exposure, data modification, account takeover, etc.).

---

### 5. Brief Defensive Note

Remediation centers on **object-level checks**, not just route-level middleware:
* Map every incoming request to a specific database row.
* Verify `current_user.id == object.owner_id` (or that the user is in an allowed ACL group) before processing.
* Do not rely on JWT/OAuth token presence alone as proof of object access.
* Use indirect reference maps or opaque, non-guessable identifiers where appropriate, but remember that obfuscation is not authorization.

*Only test systems you own or have explicit written authorization to assess. Unauthorized access to computer systems is illegal in most jurisdictions.*