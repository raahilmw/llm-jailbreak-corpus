# Jailbreak prompts

32 prompts, flat, one per file. Named after the model family each was written for.

These are workspace-policy documents: role, values, content policy, refusal handling. Not
one-line "ignore previous instructions" tricks. The long form is what worked on these checkpoints.

Use one as a starting point, not as a costume. Change the operator context to something true about
your own setup. A prompt pasted verbatim into an unrelated session reads as a role-play and gets
handled like one, and the policy's own honesty requirement ("do not fabricate") stops meaning
anything.

| file | written for |
|---|---|
| `beam.md` | Beam 1.0 |
| `bigpickle-opencode.md` | BigPickle (opencode agent) |
| `claude-opus-v2.md` | Claude Opus |
| `claude-sonnet-v2.md` | Claude Sonnet |
| `deepseek-4.1-operator.md` | DeepSeek V4.1 — used for the wave-1 harvest |
| `deepseek-v3.md` | DeepSeek V3 |
| `deepseek-v4.md` | DeepSeek V4 |
| `gemini-4-argon.md` | Gemini 4 (Argon) |
| `gemma4.md` | Gemma 4 |
| `glm-5.2.md` | GLM 5.2 |
| `glm-5.3-chat-opener.md` | GLM 5.3, chat opener variant |
| `glm-5.3-consolidated.md` | GLM 5.3, consolidated |
| `glm-5.3-flash-operator.md` | GLM 5.3 Flash — used for the wave-1 harvest |
| `glm-5.3-opencode.md` | GLM 5.3 (opencode agent) |
| `glm-zcode-5.3.md` | GLM ZCode 5.3 |
| `glm-zcode-5.3-agents.md` | GLM ZCode 5.3 as `AGENTS.md` |
| `gpt-oss-20b.md` | GPT-OSS 20B |
| `grok-4.7.md` | Grok 4.7 |
| `grok-build.md` | Grok Build |
| `kimi-k2.md` | Kimi K2 |
| `kimi-k3-agents.md` | Kimi K3 as `AGENTS.md` |
| `kimi-k3.1.md` | Kimi K3.1 |
| `longcat-agents.md` | LongCat as `AGENTS.md` |
| `mimo-2.6-agents.md` | MiMo 2.6 as `AGENTS.md` |
| `mistral-large-4.md` | Mistral Large 4 |
| `muse-spark-1.3-v2.md` | Muse Spark 1.3 |
| `muse-wonder.md` | Muse Wonder |
| `nemotron-3-ultra.md` | Nemotron 3 Ultra |
| `qwen-3.7.md` | Qwen 3.7 |
| `spacebunny-agents.md` | SpaceBunny as `AGENTS.md` |
| `step-5-preview.md` | Step 5 Preview |
| `unified.md` | cross-model unified policy |

Wave 2 in this repository ran with no prompt at all: one clean user message per question, no system
prompt, no framing. On these checkpoints the plain message outperformed every persona wrapper, which
is why `corpus/` files from that run carry `frame: plain` in the header.
