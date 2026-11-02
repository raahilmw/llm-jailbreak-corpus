# glm-5.3

- **249** documents in this repository
- stack **A** — `glm53-extract/frames.py`
- Frame ladder over long-form topics. `manual` carried most of it; `detect` and `prefill` were the last rungs.

## Frame that finally answered

Counted from the `frame:` field of the source corpus headers, per document.

| frame | documents |
|---|---:|
| `manual` | 60 |
| `detect` | 20 |
| `spec` | 8 |
| `prefill` | 6 |
| `matrix` | 6 |
| `curriculum` | 1 |
| `diff` | 1 |
| `codefix` | 1 |
| `lab` | 1 |

## Every rung the ladder tried

Includes refusals and empty responses before the working frame. Counted from the `ladder:` field.

| frame | attempts |
|---|---:|
| not recorded | |

## Subject strings, sample

- not recovered from the source corpus

Templates: see `../frames/`. A `+budget` suffix means the same frame re-sent with a doubled token
budget after an EMPTY response — not a different prompt.
