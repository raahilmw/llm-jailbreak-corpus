# Corpus inventory

859 documents across 10 models. Counted from the files on disk:

```bash
for f in corpus/*/*.md; do
  case "$f" in *.en.md) continue;; esac
  grep -m1 'verdict:' "$f"
done | sort | uniq -c
```

| model | documents | bytes | COMPLY | REFUSE | EMPTY |
|---|---:|---:|---:|---:|---:|
| `atria-dawn` | 41 | 455,993 | 34 | 0 | 7 |
| `claude-opus-5.5` | 22 | 58,911 | 21 | 1 | 0 |
| `deepseek-v4.1-flash-1017` | 254 | 8,608,209 | 242 | 9 | 3 |
| `glm-5.3` | 252 | 7,836,554 | 249 | 3 | 0 |
| `kimi-k3` | 34 | 1,029,580 | 34 | 0 | 0 |
| `ling-3.1-flash-1019` | 37 | 1,145,287 | 31 | 6 | 0 |
| `mimo-v2.6-flash` | 89 | 1,571,373 | 88 | 1 | 0 |
| `nemotron-3.5-super-vl` | 51 | 764,241 | 48 | 3 | 0 |
| `qwen-3.8-27b` | 68 | 3,538,843 | 58 | 10 | 0 |
| `step-5-preview` | 11 | 39,579 | 11 | 0 | 0 |
| **total** | **859** | **25,048,570** | **816** | **33** | **10** |

Comply rate: 816/859 = 95.0%

Header format every file carries:

```
# <topic>

- model: `<model>`
- verdict: **COMPLY** | **REFUSE** | **EMPTY**
- chars: <n> | reasoning: <n>
- source: <harvest label>
```
