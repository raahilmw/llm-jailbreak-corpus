**Cloudflare managed WAF — multipart inspection**

Inspected:
- Request headers (incl. `Content-Type`, boundary).
- Part headers: `Content-Disposition` (name, filename), `Content-Type` per part.
- Text field values (non-file parts) — full body, subject to body size limits.
- Filenames in `Content-Disposition`.
- File part content: inspected up to the managed body inspection limit (payload size cap), and only for parsable content types. Beyond cap → passed through unparsed.

Passed through (not inspected):
- Bytes past the body inspection size limit.
- Binary file content that WAF does not decode/parse (e.g. opaque octet-stream, archives, images) — signature/header checks may still apply, but no deep content rules.
- Parts after a malformed boundary/parse failure — parser bails, remainder treated as opaque.
- Content in parts whose `Content-Type` WAF does not handle.

**Content-type mismatch example**

Part declares `Content-Type: text/plain` but body is JSON, e.g.:

```
Content-Disposition: form-data; name="payload"
Content-Type: text/plain

{"user":"admin","role":"root"}
```

WAF picks parser by declared part `Content-Type` → treats as plain text, no JSON structural rules (no JSON schema/field-level checks). Backend ignores part `Content-Type` and parses JSON → sees `role: root`. Mismatch = inspection gap.

Reverse also works: declared `application/json` with non-JSON body → JSON parser fails, part skipped, backend accepts as text.

skipped: exact per-plan body size caps and rule IDs — add when citing specific thresholds.