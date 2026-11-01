# fuzzing — misc

# Fuzzing: AFL++ / libFuzzer / honggfuzz / boofuzz / Triage Crash

## 1. Comparison Matrix

| Tool | Ref version | Target | Instrumentation | Strengths | Limits |
|---|---|---|---|---|---|
| AFL++ | 4.21c | native binary, persistent | LTO/PCGUARD/LLVM | cmplog, dict, persistent loop | Butuh rebuild target |
| libFuzzer | LLVM 18.1 / 19 | C/C++ functions | `-fsanitize=fuzzer` | In-process, coverage-guided, fast | Must link to binary |
| honggfuzz | 2.6 | native + HW feedback | ptrace/perf/BTS | HW coverage without rebuild, many sanitizers | x86 coverage limited to Intel BTS |
| boofuzz | 0.4.2 | network/protokol | Python, mutasi blok | Stateful protocol, sesi TCP/UDP | Throughput rendah (~1k req/s) |

## 2. AFL++ — Persistent Mode

### Build target (example target: `jq`-like JSON parser, gcc 13, Ubuntu 24.04)

```bash
# Compile dengan instrumen LTO + persistent
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LAF_ALL=1        # LAF-Intel: split compare
make -j$(nproc)
```

### Harness persistent (C/C++)

Persistent loop `__AFL_LOOP(N)` avoids fork per input — throughput increases 10–100x. Suitable for stateless parsers. **Do not use for targets that leave global state/leaked fds** — memory will grow.

```c
// json_harness.c
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int parse_json(const char *buf, size_t len);  // fungsi target

__AFL_FUZZ_INIT();

int main(void) {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        parse_json((const char*)buf, len);
    }
    return 0;
}
```

```bash
afl-clang-lto -O2 -g json_harness.c libparse.a -o json_fuzz
mkdir -p in out
echo '{"k":1}' > in/seed1
echo '[]' > in/seed2
afl-fuzz -i in -o out -M main -- ./json_fuzz
```

### AFL++ key settings

| Env / flag | Effect | Relevant for |
|---|---|---|
| `AFL_FUZZ_INIT` + `__AFL_LOOP` | persistent mode | parser stateless |
| `-x dict.txt` | dictionary token | protokol, format teks |
| `-l 3` (cmplog mode) | cmp-log for magic bytes | `memcmp`, `strcmp` guards |
| `AFL_CMPLOG_ONLY_NEW=1` | saves cmplog time | large corpus |
| `-p fast` / `-p explore` | power schedule | fase eksplorasi |
| `AFL_MAP_SIZE=65536` | coverage map | large targets (increase to 262144) |
| `-t 500+` | timeout ms | target lambat |
| `-m none` | no memory limit | ASAN, large targets |
| `AFL_HARDEN=1` | stack protector | produksi hardening |

### Dictionary format

```
# http.dict
"HTTP/1.1 "
"Content-Length: "
"Transfer-Encoding: chunked\r\n"
"\r\n\r\n"
"GET "
"POST "
```

```bash
afl-fuzz -i in -o out -x http.dict -m none -t 2000+ -- ./nginx_fuzz
```

**Why it works:** the dict gives the mutator whole tokens, bypassing long `strncmp` guards without having to brute force per-byte.

**Why it fails:** dict too large/garbage → mutations become biased toward tokens and coverage does not increase; prioritize 20–200 correctly formatted tokens.

### CmpLog (Redqueen) — example target with magic check

```c
if (memcmp(buf, "\x7fELF\x02", 5) != 0) return -1;   // gate
if (*(uint32_t*)(buf+16) == 0x0003003e) { /* deep */ }
```

```bash
# build versi cmplog (instrumen tambahan, tanpa persistent)
AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -g json_harness.c -o json_fuzz_cmplog
afl-fuzz -i in -o out -c ./json_fuzz_cmplog -- ./json_fuzz
```

**Why it works:** cmplog extracts (input, compare result) pairs from the trace; Redqueen feeds the comparison value directly into the input. Suitable for architecture gates (ELF, PE, PNG magic).

**Why it fails:** the comparison is done on hashed/decrypted values → there are no string literals that can be rewritten. Also cmplog slows things down 2–3x; **do not** use `-c` at the start of exploration (by default it only exists when `AFL_CMPLOG_ONLY_NEW=1`).

## 3. libFuzzer Harness

### Build

```bash
clang-18 -g -O1 -fsanitize=fuzzer,address,undefined \
  -fno-omit-frame-pointer json_harness.cc -o jfuzzer
```

### Harness minimal

```cpp
#include <cstdint>
#include <cstddef>
extern "C" int parse_json(const char*, size_t);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1<<20) return 0;  // batasi
    parse_json((const char*)data, size);
    return 0;
}
```

Fixed corpus mode and reproduction:

```bash
mkdir corpus
./jfuzzer corpus/ -dict=json.dict -timeout=2 -rss_limit_mb=2048 -artifact_prefix=crash-
./jfuzzer crash-deadbeef  # reproduksi satu input
```

**practical limits:** `-jobs=8 -workers=8` for parallelism on one machine (fork per worker, not thread). `-max_len` set explicitly to prevent memory blow-up.

## 4. honggfuzz

### Build (target without rebuild via HW feedback)

```bash
make -C /opt/honggfuzz           # v2.6
# Compile target dengan sanitizer tapi tanpa instrumen HF
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
  json_harness.c -o jfuzz_hf
```

### Run

```bash
honggfuzz -i in/ -W out/ -n 8 \
  --sanitizers --exit_upon_crash \
  --dict http.dict -- ./jfuzz_hf ___FILE___
```

| Flag | Efek |
|---|---|
| `-P` (persistent) | harness must use `HF_ITER`/`HF_ITER_LEN` |
| `--sanitizers` | feed ASAN/UBSan results as crashes |
| `-n N` | worker (process) |
| `--linux_perf_bts_edge` | edge coverage via Intel BTS (requires root + Intel CPU) |
| `--linux_perf_ipt_dump` | PT via perf (Intel) |

**Why it works without rebuild:** HW feedback reads CPU branches (BTS/PT). On non-Intel (AMD, ARM64) only instruction/sw feedback — no edge coverage, so effectively random. **Pitfall:** `perf_event_paranoid` > 2 → the discipline cannot attach; set `sysctl kernel.perf_event_paranoid=1`.

## 5. Network Protocol Fuzzing — boofuzz

Reference target: **nginx 1.25** HTTP parser, or a dummy TCP server at `127.0.0.1:9000`.

```python
# fuzz_http.py — boofuzz 0.4.2
from boofuzz import *

def req():
    s_static("GET ", name="method")
    s_string("/index.html", name="path")
    s_static(" HTTP/1.1\r\n")
    s_static("Host: ")
    s_string("localhost", name="host")
    s_static("\r\nContent-Length: ")
    s_size("body", length=5, output_format="ascii", name="clen")
    s_static("\r\n\r\n")
    s_string("AAAA", name="body")
    s_static("\r\n")

session = Session(
    target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)),
    sleep_time=0.001,
    restart_interval=500,
    crash_filename="boofuzz-crash.log",
)
session.connect(req())
session.fuzz()
```

```bash
python3 fuzz_http.py --csv boofuzz.csv --enable-web 2>&1 | tee boofuzz.log
```

**Why it works:** stateful blocks preserve the request structure so mutations reach the parser end-to-end (e.g. chunked encoding, header folding).

**Why it fails:** stateful targets with TLS/keep-alive/rate-limit → `TCPSocketConnection` disconnects after one session, all mutations are rejected. For **nginx 1.25** enable high `worker_connections` and disable `limit_req`, or use `RawTCPSocketConnection` with a TLS preamble via `ssl.wrap_socket` + `pre_send_callbacks`.

### Bandingkan UDP (DNS)

```python
from boofuzz import *
s_initialize("dns")
s_static(b"\x00\x01", name="id")
s_static(b"\x01\x00")
s_static(b"\x00\x01\x00\x00\x00\x00\x00\x00")
s_string(b"\x07example\x03com\x00", name="qname")
s_static(b"\x00\x01\x00\x01")
session = Session(target=Target(connection=UDPSocketConnection("127.0.0.1", 53)))
session.connect(s_get("dns")); session.fuzz()
```

## 6. Triage Crash

### Klasifikasi cepat

```bash
# ASAN output → ringkas
ASAN_OPTIONS=symbolize=1:abort_on_error=0:print_summary=1 \
  ./json_fuzz < crash-xxxx 2> asan.txt
grep -E 'ERROR: AddressSanitizer|SUMMARY|#0 ' asan.txt
```

Example output that distinguishes bugs:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 1 at 0x... thread T0
    #0 0x... in parse_json parser.c:142
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.c:142 in parse_json
```

- **heap-buffer-overflow** → +1 byte read is often a false positive on safe-len simulators; look at frames `#0..#3`.
- **use-after-free** → note `freed by thread` and `previously allocated by` to make sure it is not use-after-return.
- **stack-overflow** in recursive parsers → prioritize; easily becomes RCE via depth control.
- **SEGV without ASAN** → likely stack corruption; run in an ASAN build + `UBSAN_OPTIONS=halt_on_error=1`.

### Reproduce and minimize

```bash
# libFuzzer
./jfuzzer -minimize_crash=1 -runs=100000 crash-xxxx > min.txt
# AFL++
afl-tmin -i out/default/crashes/id:000000* -o crash.min -- ./json_fuzz
# untuk persistent: gunakan afl-tmin dengan AFL_TMIN_EXACT=1
```

### Debugging with gdb

```bash
gdb -q --args ./json_fuzz crash-xxxx
(gdb) set env ASAN_OPTIONS=abort_on_error=1:disable_coredump=0
(gdb) run
(gdb) bt full                  # backtrace + variabel lokal
(gdb) p/x *(char*)($rsi)       # window input sekitar yang crash
(gdb) info registers
(gdb) x/16bx $rdi
```

For ASAN + gdb on fork-heavy AFL++ processes, disable `ASAN_OPTIONS=handle_segv=0` so gdb receives SIGSEGV.

### Dedup manual (bash)

```bash
for f in out/default/crashes/id:*; do
  ./json_fuzz "$f" 2>&1 | grep -m1 'SUMMARY' ;
done | sort | uniq -c | sort -rn
```

Automatic dedup: `afl-collect` (AFL++) or `casr-afl` (CASR 2.7); dedup results in seconds vs. manual triage.

### Exploitability classification (reference example)

| Crash | ASAN message | Exploitabilitas kasar |
|---|---|---|
| OOB read 1 byte | heap-buffer-overflow READ | Info leak (low) |
| OOB write | heap-buffer-overflow WRITE | Potensial RCE |
| UAF write | heap-use-after-free | RCE jika eksekusi pointer |
| Stack overflow parser | stack-overflow | DoS, kadang RCE |
| Null deref | SEGV on unknown address 0x0 | DoS (low) |

## 7. Operational Pitfalls in the Field

1. **Persistent loop + leaked state** — `__AFL_LOOP(10000)` on a target that closes fd/file only once will balloon memory until OOM before AFL finishes; solution: `fork` per `LOOP` for stateful parsers or call `malloc_trim(0)` per iteration.
2. **CmpLog too early** — `-c` from the start makes throughput drop 5–10x; use `AFL_CMPLOG_ONLY_NEW=1` and enable it after ~30 minutes of coverage plateau.
3. **LAF-Intel breaks sizing** — `AFL_LLVM_LAF_ALL=1` on 32-bit binaries or binaries with tight inline assembly causes compare mismatch; test first with `AFL_LLVM_LAF=split`.
4. **Dictionary spam** — token > 1 KB memperlambat splatter; batasi dict < 200 entri, masing-masing < 64 byte.
5. **`-m none` masks OOM bugs** — OOM-only targets pass; also run a parallel run with `-m 1024` specifically for heap exhaustion.
6. **ASAN + fork server** — persistent `__AFL_LOOP` + ASAN is **not** compatible if the target `abort()`s inside the loop with `AFL_HARDEN`; set `ASAN_OPTIONS=abort_on_error=0:halt_on_error=1` — halt in both options conflicts, pick one per run.
7. **honggfuzz without perf** — in containers the default is `perf_event_paranoid=4`; the fuzzer runs but coverage is empty → results are nearly random. Verify with `honggfuzz -v`, the "Coverage:" line; if it stays 0 after the first minute, feedback is dead.
8. **boofuzz + TLS** — `TCPSocketConnection` does not close TLS correctly on keep-alive nginx 1.25; the log is full of `ConnectionResetError` and mutations are discarded. Use `RawTCPSocketConnection` + a pre-callback that performs `context.wrap_socket()`.
9. **Wrong time budget** — `-timeout=2s` on a target that normally needs 3 s because of the `slowloris` self-test; raise it to `-t 10000+`, don't lower it, or every execution will be considered a hang.
10. **Dedup without normalize** — crashes from two identical files after minimization waste time; run `afl-tmin` first, then dedup the SHA-256 hash of the stack trace (`casr-afl` does this).
11. **Reproduction fails in release build** — the bug only appears in the debug ASAN build because of an uninitialized read; always reproduce in the debug build **and** the release build before reporting.
12. **Large corpus without minimize** — `afl-cmin` on 10k seeds takes > 30 minutes; run `afl-cmin -i in -o in_min -m none -- ./target @@` before the campaign.
13. **Coverage differs between workers** — AFL++ `-M/-S` with a non-uniform `AFL_MAP_SIZE` will make sync fail silently; set it on all workers.
14. **Multi-threaded target** — AFL++ persistent mode is single-threaded; a target with background threads will make the next iteration hit a false race condition; add `AFL_NO_FORKSRV=0` and make sure the target is quiescent before the next `__AFL_LOOP`.
15. **ASAN and missing stack traces** — without `-fno-omit-frame-pointer` the ASAN backtrace becomes `??` garbage; always compile with this flag when fuzzing.

---

## [reasoning trace]


