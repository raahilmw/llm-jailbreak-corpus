# MiMo V2.6 Flash — what it knows

The thinnest of the four on most topics (**319 KB / 22**), but it wins one: `waf-bypass`
at 22 KB, more than DeepSeek's 21 and far more than GLM's 8. During the harvest run it was
also the flakiest — repeated 503s meant it needed several passes to complete.

## Where it is worth reading

| topic | KB | note |
|---|---:|---|
| ai-sec | 32 | second only to DeepSeek; useful when Qwen returns 3 KB |
| bb-classes | 29 | dense checklist |
| api-sec | 25 | solid |
| waf-bypass | **22** | the one topic where it leads |
| net-internal | 23 | pivoting detail |
| ssrf | 23 | good coverage |

## Where it is not

`ad-kerb` (1 KB), `ad-cs-relay` (4 KB), `deser` (5 KB), `evasion` (6 KB) — all effectively
empty. Do not spend a call on those topics here.

## Reliability note

This model returned HTTP 503 repeatedly during the harvest and required retries. If you
script against it, treat a failure as expected and fall through to another model rather
than concluding the prompt was refused.

Files: `topics/<model>--<topic>.md`. See [`../../topics-index.md`](../../topics-index.md)
for the full matrix.
