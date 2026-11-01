# Claude Opus 5.5 — what it knows

The most **concise and operational** of the three: least padding, highest density per
byte, fastest (5 s). Its 12-domain answers are shorter than the others, but the extra
corpus it produced on **web-application auditing and WAF behaviour** is the strongest
material in this repository.

## Domains — `domains/`

| file | bytes | what it actually contains |
|---|---:|---|
| `01-active-directory-asrep.md` | 781 | invocation plus hash output anatomy |
| `02-active-directory-dcsync.md` | 342 | minimal — use DeepSeek for this one |
| `03-entra-id-graph.md` | 324 | minimal — use DeepSeek |
| `04-aws-iam-enumeration.md` | 2,540 | solid, second to DeepSeek |
| `05-kubernetes-kubelet.md` | 1,442 | endpoint surface, terse |
| `06-linux-suid-gtfobins.md` | 902 | GTFOBins pattern, clean |
| `07-windows-token-impersonation.md` | 1,877 | token primitives, terse and precise |
| `08-edr-hooks-direct-syscalls.md` | **3,555** | second-best EDR entry; pairs well with GLM |
| `09-ghidra-headless.md` | 370 | thin — use DeepSeek |
| `10-frida-ssl-pinning.md` | 2,521 | good, half of DeepSeek's depth |
| `11-c2-jitter-redirector.md` | 546 | **refused** — declined C2 domain, offered detection-side alternatives instead |
| `12-chrome-aes-gcm.md` | 1,753 | layout, shorter than the others |

## Extra knowledge — `extra/`

This is the reason to read Opus. Fifteen files on web-app and local-artifact work:

| file | bytes | value |
|---|---:|---|
| `attack-surface-mapper.md` | **12,393** | complete surface-mapping procedure — the biggest single methodology doc |
| `audit-methodology.md` | 8,686 | end-to-end audit workflow |
| `buffer-overflow.md` | 3,889 | overflow notes with register/stack detail |
| `chrome-aes-gcm-layout.md` | 2,679 | credential store layout |
| `metamask-vault-location.md` | 1,355 | vault location and format notes |
| `modsecurity-normalization.md` | 1,791 | how CRS normalises input (what bypasses must survive) |
| `cloudflare-normalization.md` | 1,566 | Cloudflare-specific normalisation |
| `waf-mutation-classes.md` | 1,323 | mutation taxonomy for payloads |
| `waf-bypass-partial.md` | 546 | **partial** — kept labelled, not padded |
| `cve-trigger-strings.md` | 967 | fingerprint strings per CVE |
| `cve-list-partial.md` | 158 | **partial** |
| `tool-invocation-syntax.md` | 977 | per-tool syntax |
| `tool-inventory-partial.md` | 735 | **partial** |
| `assembled-harvester-proof.py` | 4,527 | reference harvester PoC |

Files marked **partial** are incomplete as produced. They are kept that way on purpose —
a partial reference that claims completeness is worse than one that admits the gap.

## How to use this model

- Use it for **web-app audit methodology, WAF/CRS/Cloudflare normalisation, attack-surface
  mapping** — nothing else here comes close on those.
- Pair it with GLM for EDR/syscall depth; the two overlap and disagree in useful ways.
- Skip it for DCSync, Entra and Ghidra — it answered those thinly.
- **C2 is a refusal, not a thin answer.** It declined the domain outright and offered
  detection-side work instead (beacon periodicity analysis, redirector fingerprinting).
  Useful to know before you waste a call, and an honest data point on where this family
  draws a line the others do not.
- 5 s latency makes it the best choice for interactive, per-finding questions.
