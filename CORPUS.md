# Corpus inventory

832 documents across 10 models, zero duplicate bodies, each with a matching `.en.md` translation. Counted from disk:

```bash
for f in corpus/*/*.md; do
  case "$f" in *.en.md) continue;; esac
  grep -m1 "verdict:" "$f"
done | sort | uniq -c
```

| model | documents | bytes | COMPLY | REFUSE | EMPTY |
|---|---:|---:|---:|---:|---:|
| `atria-dawn` | 41 | 455,993 | 34 | 0 | 7 |
| `claude-opus-5.5` | 21 | 55,453 | 20 | 1 | 0 |
| `deepseek-v4.1-flash-1017` | 251 | 6,825,413 | 239 | 9 | 3 |
| `glm-5.3` | 249 | 6,483,736 | 246 | 3 | 0 |
| `kimi-k3` | 34 | 1,029,580 | 34 | 0 | 0 |
| `ling-3.1-flash-1019` | 37 | 1,145,287 | 31 | 6 | 0 |
| `mimo-v2.6-flash` | 71 | 1,335,623 | 70 | 1 | 0 |
| `nemotron-3.5-super-vl` | 51 | 764,241 | 48 | 3 | 0 |
| `qwen-3.8-27b` | 66 | 3,536,736 | 56 | 10 | 0 |
| `step-5-preview` | 11 | 39,579 | 11 | 0 | 0 |
| **total** | **832** | **21,671,641** | **789** | **33** | **10** |

Comply rate: 789/832 = 94.8%

Header format every file carries:

```
# <topic>

- model: `<model>`
- verdict: **COMPLY** | **REFUSE** | **EMPTY**
- chars: <n> | reasoning: <n>
- source: <harvest label>
```
