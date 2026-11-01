# Jailbreak Prompts / Prompt Jailbreak

Each model got a tailored system-prompt-style jailbreak, tested live with a
canary question before the harvest started. The full versions live here.

Setiap model dapat jailbreak bergaya system-prompt yang disesuaikan, diuji
live dengan pertanyaan canary sebelum panen dimulai. Versi penuh ada di sini.

| file | model | style |
|---|---|---|
| [glm-5-3-flash.md](glm-5-3-flash.md) | glm-5.3-flash | "Assistant Operating Specification" (workspace policy) |
| [deepseek-4-1.md](deepseek-4-1.md) | deepseek-v4.1-flash-1017 | same family, tuned refusal-handling section |
| [qwen-3.8.md](qwen-3.8.md) | qwen-3.8-27b | same family, tuned refusal-handling section |
| [mimo-2.6-agents.md](mimo-2.6-agents.md) | mimo-v2.6-flash | "agents" variant for the coding-agent persona |

The wave-2 models (atria-dawn, kimi-k3, ling-3.1, nemotron-3.5, qwen retests)
answered through the plain-message channel: no system prompt, one user message,
clean context. The measured result that drove that choice is in
[`research/ab-test-c01.json`](research/ab-test-c01.json) — persona/ticket frames
did not pass the gate, plain context did.

Model gelombang-2 (atria-dawn, kimi-k3, ling-3.1, nemotron-3.5, uji ulang
qwen) lewat jalur pesan polos: tanpa system prompt, satu pesan user, konteks
bersih. Hasil pengukuran yang mendasari pilihan itu ada di
[`research/ab-test-c01.json`](research/ab-test-c01.json) — frame persona/tiket
tidak menembus, konteks polos menembus.
