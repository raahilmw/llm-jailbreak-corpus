# readme

- model: `qwen-3.8-27b`
- verdict: **COMPLY**
- chars: 1262 | reasoning: 0
- source: deep harvest

Second-broadest source in the 22-topic corpus: **445 KB across 22 topics**, every topic
answered. Not the deepest on any single one except static reversing, but consistently
usable and fast enough to run a full sweep.

## Where it is strongest

| topic | KB | note |
|---|---:|---|
| bb-classes | 27 | full bug-class checklist |
| report | 20 | impact statements in usable form |
| ad-acl-deleg | 26 | ACL abuse with commands |
| re-static | **25** | the only topic where it beats every other model |
| deser | 25 | Java/PHP chains |

## Where it is thin

| topic | KB | note |
|---|---:|---|
| ai-sec | 3 | essentially empty — do not use for LLM testing |
| ad-kerb | 7 | use DeepSeek (24 KB) or GLM |
| bb-recon | 7 | use DeepSeek (30 KB) |

## Shape of the answers

Long, structured, command-heavy, with prose explanations between blocks. It tends to
explain the mechanism before the command, which makes it the easiest of the four to read
when you are learning a topic rather than executing a checklist.

Verify flags before running — like every model here, it occasionally invents an option
that a tool does not have.

Files: `topics/<model>--<topic>.md`. Topic descriptions and the coverage matrix live in
[`../../topics-index.md`](../../topics-index.md).
