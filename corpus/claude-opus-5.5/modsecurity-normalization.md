# modsecurity-normalization

- model: `claude-opus-5.5`
- verdict: **COMPLY**
- chars: 1765 | reasoning: 0
- source: deep harvest

**CRS request normalization order** (ModSecurity v2/v3, phase 1/2):

1. **Raw read** — body read per `SecRequestBodyAccess`, limited by `SecRequestBodyLimit`/`SecRequestBodyNoFilesLimit`.
2. **Charset/encoding handling** — `SecDefaultAction` charset; `REQBODY_PROCESSOR` (URLENCODED / MULTIPART / JSON / XML) parses body.
3. **URL decode** — `urlDecodeUni` / `urlDecode` transformation applied per-rule, not globally. CRS rules chain transforms explicitly.
4. **Unicode/UTF-8 decode** — `utf8toUnicode` (v2) or built-in in v3.
5. **HTML entity decode** — `htmlEntityDecode`.
6. **Case fold** — `lowercase`.
7. **Whitespace/comment strip** — `removeWhitespace`, `removeComments`, `compressWhitespace`.
8. **Path normalization** — `normalizePath`, `normalizePathWin`.
9. **Null byte / control char strip** — `removeNulls`, `escapeSeqDecode`.
10. **JS/hex decode** — `jsDecode`, `hexDecode` (per-rule).

Key point: **transforms are per-rule, not global**. Each CRS rule declares its own `t:` chain. So "normalization order" = order of `t:` in the rule. There is no single global pipeline.

**Two double-decode gaps (backend decodes more than WAF):**

1. **Double URL-encoding in path/query** — WAF applies `urlDecodeUni` once; app framework (e.g. Spring, PHP with `urldecode()` on already-decoded input, or a proxy that decodes then forwards) decodes twice. `%252e%252e%252f` → WAF sees `%2e%2e%2f`, app sees `../`.

2. **Multipart filename / Content-Disposition** — WAF parses multipart and applies transforms to `FILES`/`FILES_NAMES`; app re-parses and additionally URL-decodes or RFC 5987-decodes the `filename*` parameter. WAF sees literal `%2e%2e`, app resolves to `..`.

Skipped: full per-rule `t:` inventory (hundreds of rules). Add when auditing specific rule.