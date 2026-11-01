[NIKA]

WAF bypass reference. Three targets: ModSecurity CRS, Cloudflare, AWS WAF. Every trick, raw request line each.

---

## 1. ModSecurity CRS

CRS default ruleset — heavy on regex, `%{TX}` transformations. Bypass via transformation chain confusion.

### Encoding tricks

CRS runs `urlDecode`, `removeNulls`, `htmlEntityDecode`, `normalizePath` in sequence. Feed it something that survives all four.

**Double URL encoding** — CRS decodes once, then the backend decodes again. `%2527` → CRS sees `%27` (no match), backend sees `'`.

```