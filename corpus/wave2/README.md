# Wave 2 — plain context, no prompt / Tanpa prompt

Each file: one narrow question, one clean user message, no system prompt.
Verdicts are stamped in the file header, counted by script
(`research/results-matrix.json`).

Setiap file: satu pertanyaan sempit, satu pesan user bersih, tanpa system
prompt. Verdict dicantumkan di header file, dihitung oleh script
(`research/results-matrix.json`).

| model | COMPLY | REFUSE | EMPTY |
|---|---|---|---|
| atria-dawn | 34 | 0 | 7 |
| deepseek-v4.1-flash-1017 | 29 | 9 | 3 |
| kimi-k3 | 34 | 0 | 0 |
| ling-3.1-flash-1019 | 31 | 6 | 0 |
| mimo-v2.6-flash | 34 | 1 | 0 |
| nemotron-3.5-super-vl | 33 | 3 | 0 |
| qwen-3.8-27b | 30 | 10 | 0 |

`.REFUSED.md` files keep the refusal text as data — where each model
drew the line.

File `.REFUSED.md` menyimpan teks penolakan sebagai data — di mana
tiap model menarik garisnya.
