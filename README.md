# LLM Jailbreak Corpus

<p align="center">
  <img src="assets/banner.png" alt="banner" width="100%"/>
</p>

Security knowledge extracted from eight language models, file per file,
with the exact prompts that opened each one and the raw evidence of every
refusal. 676 corpus documents plus the research data, Indonesian
originals plus English translations in progress.

---

## Corpus Jailbreak LLM

Pengetahuan keamanan yang diekstrak dari delapan model bahasa, file per
file, lengkap dengan prompt persis yang membuka masing-masing model dan
bukti mentah setiap penolakan. 676 dokumen korpus plus data riset, asli
bahasa Indonesia plus terjemahan Inggris yang masih berjalan.

---

## The three waves / Tiga gelombang

<p align="center">
  <img src="assets/method.png" alt="method" width="420"/>
</p>

**Wave 1 — system-prompt jailbreak.** Four models answered 22 long-form
security topics each, through a tailored "operating specification" prompt.
Indonesian prose, exact commands preserved.

**Wave 1 — jailbreak system-prompt.** Empat model menjawab 22 topik
keamanan panjang masing-masing, lewat prompt "operating specification"
yang disesuaikan per model. Prosa bahasa Indonesia, perintah persis
dipertahankan apa adanya.

**Deep harvest — topic decomposition.** The two strongest models went a
second round: each topic split into sub-questions, follow-ups until the
answer stopped growing. 183 documents.

**Deep harvest — dekomposisi topik.** Dua model terkuat masuk ronde kedua:
tiap topik dipecah jadi sub-pertanyaan, follow-up sampai jawaban berhenti
bertambah. 183 dokumen.

**Wave 2 — no prompt at all.** Seven models, 40 narrow factual questions
each, one clean user message per question, no system prompt. 264
answer files, every one stamped COMPLY / REFUSE / EMPTY. This is the
control group — and it is the interesting part: several models complied
to plain factual questions without any jailbreak.

**Wave 2 — tanpa prompt sama sekali.** Tujuh model, 40 pertanyaan faktual
sempit masing-masing, satu pesan user bersih per pertanyaan, tanpa system
prompt. 264 file jawaban, semuanya diberi label COMPLY / REFUSE / EMPTY.
Ini kelompok kontrol — dan justru bagian paling menarik: beberapa model
patuh pada pertanyaan faktual polos tanpa jailbreak apa pun.

---

## Numbers / Angka

<p align="center">
  <img src="assets/models.png" alt="models" width="420"/>
</p>

Wave 1 + deep harvest (system-prompt jailbreak):

| model | deep | wave-1 | files |
|---|---|---|---|
| glm-5.3 | 83 | 22 | 105 |
| deepseek-v4.1-flash-1017 | 100 | 22 | 122 |
| qwen-3.8-27b | — | 22 | 22 |
| mimo-v2.6-flash | — | 22 | 22 |
| **total** | **183** | **88** | **271** |

Wave 2 (plain context, no prompt) — verdicts counted from the files:

| model | COMPLY | REFUSE | EMPTY | compliant bytes |
|---|---|---|---|---|
| atria-dawn | 34 | 0 | 7 | 102,538 |
| deepseek-v4.1-flash-1017 | 29 | 9 | 3 | 198,691 |
| kimi-k3 | 34 | 0 | 0 | 246,027 |
| ling-3.1-flash-1019 | 31 | 6 | 0 | 659,186 |
| mimo-v2.6-flash | 34 | 1 | 0 | 671,927 |
| nemotron-3.5-super-vl | 33 | 3 | 0 | 290,297 |
| qwen-3.8-27b | 30 | 10 | 0 | 629,036 |
| **total** | **225** | **29** | **10** | **2,797,692** |

Machine-checked, not hand-typed: `research/results-matrix.json`,
per-file `research/results-kimi3.json`.

Dihitung mesin, bukan diketik tangan: `research/results-matrix.json`,
per-file `research/results-kimi3.json`.

---

## What is actually in here / Isi sebenarnya

<p align="center">
  <img src="assets/corpus.png" alt="corpus" width="420"/>
</p>

```
corpus/
  wave1/<model>/id/*.md       22 long-form topics x 4 models
  wave1/KB.id.md              compiled knowledge base
  deep/<model>/id/*.md        83-100 decomposed topics x 2 models
  deep/<model>/en/*.md        English translations (in progress)
  wave2/<model>/id/*.md       40 atom questions x 7 models, verdict-labeled
prompts/                      the four working jailbreak prompts + notes
research/                     canary JSON, A/B ablation, refusal ladder,
                              per-model reports, results matrix
tools/                        sanitize script used before publishing
assets/                       illustrations
```

Each answer file is self-describing: model name, verdict, char count,
reasoning-token count, latency, finish reason, then the probe question
and the verbatim answer. Nothing is paraphrased; the model's own words
are the data.

Setiap file jawaban menjelaskan dirinya sendiri: nama model, verdict,
jumlah karakter, jumlah token reasoning, latensi, finish reason, lalu
pertanyaan probe dan jawaban verbatim. Tidak ada parafrase; kata-kata
model sendiri adalah datanya.

---

## Prompts / Prompt

<p align="center">
  <img src="assets/jailbreak.png" alt="jailbreak" width="420"/>
</p>

The four wave-1 prompts are complete and paste-ready:
[`prompts/`](prompts/README.md). They are workspace-policy style documents
(role, values, content policy, refusal handling) rather than one-liner
DAN variants — the long form is what worked on these models.

Empat prompt gelombang-1 lengkap dan siap paste:
[`prompts/`](prompts/README.md). Bentuknya dokumen gaya "kebijakan
workspace" (peran, nilai, kebijakan konten, penanganan penolakan),
bukan varian DAN satu baris — bentuk panjang itulah yang bekerja pada
model-model ini.

Wave 2 ran with no prompt at all. The A/B test behind that decision
(persona/ticket frames losing to plain context on the same question) is
in `research/ab-test-c01.json` and the refusal-ladder run in
`research/ladder1.json`.

Gelombang-2 jalan tanpa prompt sama sekali. Uji A/B di balik keputusan
itu (frame persona/tiket kalah dari konteks polos pada pertanyaan yang
sama) ada di `research/ab-test-c01.json` dan hasil refusal-ladder di
`research/ladder1.json`.

---

## What the data says / Apa kata data

- **Shape beats content.** GLM-5.3 refused based on prompt shape, not
  topic: dropping the "internal ticket" wrapper raised compliance from
  0% to 40-100% on identical payloads. Full matrix in
  `research/glm53_matrix.json`.
  **Bentuk mengalahkan konten.** GLM-5.3 menolak berdasarkan bentuk
  prompt, bukan topik: membuang wrapper "tiket internal" menaikkan
  kepatuhan dari 0% ke 40-100% pada payload yang sama. Matriks lengkap
  di `research/glm53_matrix.json`.
- **Atomisation reaches near-100%.** Splitting a topic into single
  factual questions with clean context got answers where the combined
  prompt was refused — including topics that refused three times in a
  row before being split.
  **Atomisasi nyaris sempurna.** Memecah topik jadi pertanyaan faktual
  tunggal dengan konteks bersih menghasilkan jawaban di tempat prompt
  gabungan ditolak — termasuk topik yang menolak tiga kali berturut-turut
  sebelum dipecah.
- **Refusals cluster, they don't spread.** Wave-2 refusals concentrate in
  credential-theft and C2-infrastructure questions; adjacent topics
  (evasion, exploit dev, kernel) sailed through on the same models.
  Refusal behavior is a per-topic property, not a per-model property.
  **Penolakan mengelompok, tidak menyebar.** Penolakan gelombang-2
  terkonsentrasi di pertanyaan pencurian kredensial dan infrastruktur
  C2; topik tetangga (evasion, exploit dev, kernel) lolos di model yang
  sama. Perilaku penolakan adalah properti per-topik, bukan per-model.
- **Reasoning tokens predict compliance.** COMPLY answers in wave 2 came
  with 4k-88k reasoning tokens; the reasoning traces show the model
  arguing itself out of a refusal before writing a single content token.
  **Token reasoning memprediksi kepatuhan.** Jawaban COMPLY di gelombang-2
  datang dengan 4k-88k token reasoning; trace reasoning menunjukkan
  model membujuk dirinya sendiri keluar dari penolakan sebelum menulis
  satu token konten pun.

---

## Method notes / Catatan metode

- Every number in this README is re-derivable from the files: count
  `verdict: **COMPLY**` lines or run the sanitize script's summary.
  Setiap angka di README ini bisa dihitung ulang dari file: hitung baris
  `verdict: **COMPLY**` atau jalankan ringkasan script sanitize.
- Provider names, gateway hosts, and API keys are scrubbed. The models
  are identified by their public names only.
  Nama provider, host gateway, dan kunci API dibersihkan. Model
  diidentifikasi dengan nama publiknya saja.
- `.REFUSED.md` files are kept as data: they show exactly where each
  model drew its line, which is as useful as knowing where it doesn't.
  File `.REFUSED.md` dipertahankan sebagai data: mereka menunjukkan
  persis di mana tiap model menarik garisnya — sama bergunanya dengan
  tahu di mana garis itu tidak ada.

## License

Research use. The extracted text is model output, not copyrighted source
material.
