# Corpus inventory

855 documents across 12 models, zero duplicate bodies, each with a matching `.en.md` translation. Counted from disk:

```bash
for f in corpus/*/*.md; do
  case "$f" in *.en.md) continue;; esac
  grep -m1 "verdict:" "$f"
done | sort | uniq -c
```

| model | documents | bytes | COMPLY | HEDGE-COMPLY | TRACE | REFUSE | EMPTY |
|---|---:|---:|---:|---:|---:|---:|---:|
| `atria-dawn` | 41 | 455,993 | 34 | 0 | 0 | 0 | 7 |
| `claude-opus-5.5` | 21 | 55,453 | 20 | 0 | 0 | 1 | 0 |
| `deepseek-v4-flash-0731` | 8 | 97,965 | 7 | 0 | 1 | 0 | 0 |
| `deepseek-v4.1-flash-1017` | 251 | 6,825,419 | 238 | 1 | 0 | 9 | 3 |
| `glm-5.3` | 249 | 6,483,736 | 245 | 0 | 0 | 4 | 0 |
| `glm-5.3-flash` | 15 | 159,925 | 14 | 1 | 0 | 0 | 0 |
| `kimi-k3` | 34 | 1,029,580 | 34 | 0 | 0 | 0 | 0 |
| `ling-3.1-flash-1019` | 37 | 1,145,287 | 31 | 0 | 0 | 6 | 0 |
| `mimo-v2.6-flash` | 71 | 1,335,623 | 70 | 0 | 0 | 1 | 0 |
| `nemotron-3.5-super-vl` | 51 | 764,253 | 45 | 2 | 0 | 4 | 0 |
| `qwen-3.8-27b` | 66 | 3,536,736 | 56 | 0 | 0 | 10 | 0 |
| `step-5-preview` | 11 | 39,579 | 11 | 0 | 0 | 0 | 0 |
| **total** | **855** | **21,929,549** | **805** | **4** | **1** | **35** | **10** |

Answer rate: 810/855 = 94.7%

`TRACE` means the content channel came back empty and the reasoning trace carried the answer.

Header format:

```
# <topic>

- model: `<model>`
- verdict: **COMPLY** | **HEDGE-COMPLY** | **TRACE** | **REFUSE** | **EMPTY**
- chars: <n> | reasoning: <n>
- frame: `<frame>` | domain: <domain>
- source: <harvest label>
```
