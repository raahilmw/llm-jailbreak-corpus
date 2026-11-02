# re-static

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 15764 | reasoning: 0
- source: deep harvest

# Chapter 8 — Static RE Triage: PE/ELF

## 8.1 Core Toolchain

| Tool | Versi | Fungsi |
|---|---|---|
| Detect It Easy (DIE) | 3.10 | Deteksi packer/compiler via signature |
| PE-bear | 0.6.x | Parse header PE, dump section/TLS/overlay |
| CFF Explorer | 8.x | Alternatif parser PE + hexeditor terintegrasi |
| pestudio | 9.x | Scoring static, whitelist import |
| `readelf` / `objdump` (binutils 2.42) | — | Parse ELF header/section/dynamic |
| `strings` (binutils) + `rabin2` (radare2 5.9) | — | Ekstraksi string multi-encoding |
| `floss` (mandiant/flare-floss 3.x) | — | String deobfuscated via emulasi |
| dnSpyEx | 6.5+ | Dekompilasi/patch .NET assembly |
| ILSpy | 9.x | Dekompilasi .NET alternatif |
| IDA Free 9 / Ghidra 11.3 | — | Further analysis |

---

## 8.2 Quick Triage with DIE

**What is submitted:**
```bash
diec.exe -e -a -d sample.exe   # entropy, semua signature, deep scan
```

**What appears:**
```text
PE32
  Protector: UPX (3.96) [signature: UPX0, UPX1, UPX!]
  Compiler: MSVC (19.29.30133) [link 14.29]
  Entropy: 7.82 (section UPX1)
```

**Why it works:** DIE matches static byte signatures in the header/file + section name heuristics. Entropy > 7.0 in a code section almost always = compressed/encrypted.

**Why it fails:** Custom packers without a public signature show up as "Nothing detected" — don't trust a negative DIE result. Modified UPX (anti-DIE anti-UPX patch) is still detected but manual unpacking fails with `upx -d`.

---

## 8.3 PE Header Parse (PE-bear)

**What is submitted:** open the sample in PE-bear, focus on:
1. **DOS Header** — `e_magic = MZ`, `e_lfanew` offset (valid: 0x40–0x200)
2. **NT Header** — `TimeDateStamp` (bogus if uniform `0x55555555` or next year's epoch), `SizeOfOptionalHeader`
3. **Section Table** — periksa flag anomali:

| Anomali | Indikasi |
|---|---|
| `IMAGE_SCN_MEM_WRITE \| EXECUTE` (0x60000020) | Self-modifying/unpacking |
| Section name kosong/non-standar + entropy ≥ 7.0 | Packer |
| `PointerToRawData = 0` tapi `SizeOfRawData > 0` |irtual section / fileless tample |

**Why it works:** malware commonly modifies PE loader invariants. The Windows 11 24H2 loader is very tolerant (sections can overlap, header flags can be inconsistent) so packers abuse this slack.

---

## 8.4 Section Entropy Manual

**What is submitted:**
```bash
# Rata-rata entropy per section via radare2
rabin2 -S sample.exe | while read; do :; done
# Atau Python:
python3 -c "
from math import log2
data=open('sample.exe','rb').read()
[print(hex(s.Name_padded.decode(errors='ignore') if False else ''),]
"
python3 <<'EOF'
import pefile
pe = pefile.PE('sample.exe')
for s in pe.sections:
    import math
    d = s.get_data()
    ent = -sum((d.count(b)/len(d))*math.log2(d.count(b)/len(d)) if d.count(b) else 0 for b in set(d))
    print(f"{s.Name.decode().strip('\\x00')}: E={ent:.2f}")
EOF
```

**Output:**
```text
.text: E=6.12      ← kode normal (5.5–6.5)
.rdata: E=5.80
UPX1: E=7.89      ← compressed
.rsrc: E=6.40
```

**Why it fails:** entropy 7.3+ in `.rsrc` could be a legitimate PNG icon/embedded data, not packed code. Low entropy does not rule out obfuscation via stack strings (Flare-on style).

---

## 8.5 Import Table

**What is submitted:**
```bash
rabin2 -i sample.exe
# atau pestudio → Imports tab (highlight merah otomatis)
```

**Mining indicators (pestudio blacklist):**

| API | Probable usage |
|---|---|
| `VirtualAlloc` + `VirtualProtect` + `WriteProcessMemory` | Injection / unpacking |
| `LoadLibraryA` + `GetProcAddress` with an empty IAT | Dynamic resolution / packed, real IAT at runtime |
| `RtlUnwind`, anti-debug flags `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` | Anti-analysis |
| `InternetOpenUrlA`, `URLDownloadToFileA` | Second-stage loader |
| `CryptDecrypt` + `CryptStringToBinaryA` | Payload decryption builtin |

**IAT with only 2-3 imports (kernel32: LoadLibrary/GetProcAddress/ExitProcess)** ⇒ 99% packed or manually resolved. The original header appears after unpacking — save the dump.

---

## 8.6 TLS Callback

**Why it matters:** TLS callbacks execute **before** the entry point (`AddressOfEntryPoint`) — used for unpacking and anti-debug kill switches.

**What is submitted:** PE-bear → Data Directories → `TLS Table`:
- `AddressOfCallBacks` (at runtime points to a pointer array, terminated NULL)
- `AddressOfIndex` (slot index)
- Raw AddressOfCallBacks

**Flip-peforma:** flag `IMAGE_DIRECTORY_ENTRY_TLS` index 9 in OptionalHeader DataDirectory.

**Output:** if a callback exists and the binary is a packed sample, move the analysis entry to the callback address, not `AddressOfEntryPoint`. The Windows loader (including 24H2) always triggers this before the loader epilogue → classic UPX-modified technique, Carp/pack DB.

**Fails:** if the packer zeroes out the flag in the header but the `.rdata` region has a callback array — the Windows loader ignores it (header flag mn10), but some versions of nanami (Crystal) call it manually via `TlsAlloc` — check the call site.

---

## 8.7 Overlay (Appendix Data)

**What is submitted:** PE-bear → last section header row → compare the last `PointerToRawData + SizeOfRawData` vs `file size`:
```bash
# oto
rabin2 -SSo sample.exe     # overlay offset
xxd -s $OVERLAY_OFFSET sample.exe | head
```

**What appears (real example):** 2.1MB file, last section end = 0x1A0000, remaining 0xC0000 bytes = overlay data with `MZ` magic + new → appended second-stage dropper, the loader computes `(file_size - overlay_marker_offset)` runtime offset.

**Why it works:** the Windows loader ignores data beyond mapped size → a favorite place to store a second stage, config, or implant.

**Action:**`binwalk overlay.bin` to carve nested embedded ZIP/CAB/PE.

---

## 8.8 ELF Triage

**What is submitted:**
```bash
readelf -h sample.elf      # header — periksa e_type (EXEC/DYN), e_entry
readelf -S sample.elf      # section — entropy.check
readelf -d sample.elf       # DT_NEEDED (libc dinamis?), DT_FLAGS (pie?)
objdump -T sample.elf      # dynamic symbol (lekstra imports dt PLT)
readelf -r sample.elf      # reloc GOT hijack
```

**Indicators:**

| Artefak | Indikasi |
|---|---|
| `e_type = EXEC` + empty `DT_NEEDED` | Statically linked — statically linked glibc grows to ~800KB; mirriadi bounce |
| Section `.text` entropy > 7 | UPX ELF (`UPX!` magic near EOF) |
| `DT_DEBUG` missing + custom interpreter path | Packed/musl |
| GOT entry patched post-link (compare `.rela.dyn`) | Hooking runtime (Egg/Audit LD_PRELOAD style) |

**Why it fails:** a stripped static ELF on musl (or Zig) — almost no dynamic strings, no symbols. Byte fingerprinting in `.rodata` (musl constants) or `__libc_start_main` alternative signatures is required.

---

## 8.9 Ekstraksi String (Multi-Encoding)

**What is submitted:**
```bash
# ASCII + UTF-16LE (Windows DLL/apiNames)
strings -a -n 6 sample.exe
strings -a --encoding=b sample.exe   # UTF-16LE
# via rabin2
rabin2 -zz sample.exe                # strings dalam tiap section
# dengan FLOSS (emulated deobfuscation)
floss sample.exe
```

**Output terprioritas (full triage output):**
```text
UTF-16LE: " SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
W comand: "powershell.exe -nop -w hidden -enc <base64>"
ASCII: "1.2.3.4" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Chrome/131)"
Floss: stack-string decrypted dari routine di sub_4012f0
```

**Why it works:** UTF-16LE (`--encoding=b` / `-e l`) is required for registry paths & APIs — plain ASCII strings miss in Windows PE binaries. When the file is created via the `CharUpperW` pointer shellcode, encoded strings appear as stack-constructed in the disassembly (from ISH — Immediate String Heap) and are only visible to **FLOSS / strings-emulator**, not strings.

**Fails when:** stack strings with a single-byte XOR key — FLOSS emulation fails if it uses a multi-rotate loop. Use IDA/Ghidra + manual decryption via Python: `bytes([c ^ 0x37 for c in stack_bytes])`.

---

## 8.10 Symbol Recovery: Go & Rust

**Go binary:**

**What is submitted:**
```bash
goresym.exe -t -d -p sample.exe   # GoReSym (mandiant) 1.7+
# atau di Ghidra: > Golang symbol recovery (Refinery) extension
```

**Why it works:** the Go runtime needs the internal pcln function table (`runtime.pclntab`) for trace/panic, and symbols and source file paths are often intact even when stripped. GoReSym finds the pclntab magic `0xFFFFFFF0` (go1.18+) or `0xFFFFFFFB` (go1.20+, requires the exact major.minor.patch version), rebuilds function names (`main.main`, `net.Dial`), the firstmoduledata address, and buildID.

Output:
```text
Build ID: GO\n1.21.0\linux\namd64
Functions: 15200
main.main RIPPER: 0x4a2f10
main.injectShell
```

**Fails if:** the binary is built with `go build -ldflags="-s -w"` + malformed pclntab (Go malware commonly corrupts specific fields so that GoReSym and the IDA golang loader fail). Counter: manual patching for `pclntab.pcln` pointer recovery based on the `runtime.moredetails` scan pattern.

**Rust binary:**
- No equivalent pclntab. Recovery via: (1) panic string `panicked at 'src/main.rs:?:?'` containing path+line; (2) vtable + `rust_begin_unwind` still present in static ELF symbols; (3) in IDA, apply **cargo sccache** style regex pattern matching — look for the call pattern `core::result::unwrap_failed`.
- A stripped Rust binary on ELF musl: almost zero names. Identify by unique server strings: the `rustc` release channel or crate panic messages `assertion failed: ...`.
- Tool `rust-stripped-annotate`/IDB script by ban be memory forensics — pattern880 v0.3; requires commits to peer projects (một Bebek) to update signatures for the newest rustc 1.83 release.

---

## 8.11 .NET Decompilation (dnSpyEx / ILSpy)

**When:** DIE detects `.NET` / `MSIL`, or `mscoree.dll` in the imports + a CLI header (`IMAGE_DIRECTORY_ENTRY_COMHEADER` index 14).

**What is sent:**
```bash
# dnSpyEx 6.5.4 (fork maintained dnSpy) — drag-drop .exe
# Build-in decompiler: View → Windows → IL decompiler (switch C# ↔ IL)
```

**What appears:**
```csharp
// d98xxCrypto3.cs
protected static byte[] Decode(XElement x) {
    return Convert.FromBase64String(x.Value).Select((b, i) => (byte)(b ^ key[i % key.Length])).ToArray();
}
// key = "tVictoryPath24; strOver = "https://.../gate.php"
```

**Why it works:** most .NET loaders (Dany, Quasar, Remcos loader, AsyncRAT 0.5.x) only obfuscate at the metadata level (ConfuserEx, .NET Reactor), not their semantic IL — dnSpy decompiles 95% of the code readable without any work.

**ConfuserEx 1.0 sample:**
```text
"<PrivateImplementationDetails>" tidak muncul
string reference via resource decrypt — cari fungsi integer-id lookup, rename symbol dengan dnSpy → buka Method → Edit Method untuk modular check
```

For ConfuserEx samples: use **de4dot-cex** (fork) or **ConfuserEx-Tools**:
```bash
de4dot.exe -p un sample.exe   # generic unpacker profile detection
```

**ILSpy** (9.x, cross-platform, headless):
```bash
ilspycmd -p -o out/ sample.exe
```
Use if dnSpyEdit fails on .NET 8/9 runtime (native AOT — cannot be decompiled; explain in the entry: single-file self-contained .NET 8+ native AOT moves to the native-the-section-8.3 realm).

**Fails:** (1) harassed symbols + heavily obfuscated control flow (Agile.NET), where control flow becomes `switch(temp) goto` — requires a dedicated deobfuscator; (2) JIT hooking / runtime patch of `Assembly.Load` byte stream — only loads at runtime, scripting requires dnSpy debugger attach when loading the extension.

---

## 8.12 Toolchain Order for Unknown Samples (runbook)

```text
┌─ 0. Isolasi: sha256sum, salin ke VM analysis (Windows 11 24H2 atau Win7x64 lab) — NO execute dulu.
│
├─ 1. File type cepat:
│   $ file sample.bin           # PE32/ELF/script/unknown
│   $ diec -a -e sample.bin     # packer/compiler/entropy overview
│
├─ 2. PE path:
│   ├─ PE-bear → header anoma, section, TLS callback offset, overlay offset
│   ├─ Periksa: .NET? (mscoree import / CLI header)
│   │    └─ YA → de4dot, lalu dnSpyEx decompile → str extraction .NET-style
│   ├─ Packed? (entropy high, section UPX*/non-std)
│   │    └─ YA → upx -d atau dump otomatis via x64dbg run-trace
│   │           ulang step 1 pada dump
│   └─ Simpan: strings -a + -e b + floss → IOCs (C2, mutex, persistence path)
│
├─ 3. ELF path:
│   ├─ readelf -h -S -d → dyn/static, pie, interpreter
│   ├─ rabin2 -zz → strings (ASCII/UTF8/UTF16)
│   └─ Go? → goresym; Rust? → panic-message anchor; static → Ghidra
│
├─ 4. Overlay & resource carve: binwalk,foremost -i sample.bin, 7z-style exe resource explorer
│
└─ 5. Konfigurasi extraction & IOC → report yara/pattern untuk tim
```

**YARA checkpoint from triage:** if strings and IAT are clean, and only injection functions are visible → do not stop — samples considered a "simple loader" are commonly a trial stage encapsulated in a resource/overlay/gate-server; ensure stage-2 extraction via config decode is just completed, return to step 4 if it turns out to be nested.

---

## 8.13 Operational Pitfalls

1. **Negative DIE signature ≠ clean.** Custom crypters 2023+ (e.g. native Indonesian-rea injector loaders) are not in the DIE database. Always manually cross-check section entropy: low "safe" entropy can be code that is partially decrypted at runtime.

2. **PE TimeDateStamp and `TimeDateStamp` are spoofable.** Do not use for timestamp commitment — verify with PE Rich Header (`@comp.id` MSVC setter) or debug directory (`RSDS` path + timestamp), which are rarely patched.

3. **Modified UPX packer: `upx -d` fails.** Inland packers just patch 1-2 bytes in the `UPX!` header to make official UPX refuse to unpack — a manual way is required (x64dbg ESP trick on that packer) or manually patch it back to expected — this makes batch-processing auto-unpack pipelines fail silently.

4. **TLS callback anti-debug automatically destroys the sample** when dumping is done via the run approach: some samples check the `BeingDebugged` flag and then `TerminateProcess` → the full dump never reaches staging. Use an anti-anti-debug plugin (ScyllaHide 1.5) before running the process in a lab VM snapshot.

5. **Large file sizes (installer, LG installer, adapted dropper)** make FLOSS very slow (emulating all routines can take ~1-2 hours for a 50MB installer). Pre-scan: limit `-n minimal` and carve resources first (`7z x`) before flossing the binary in question.

6. **Modern .NET (IC 2024+: native AOT .NET 8/9 or self-contained single file)** — dnSpyEx/ILSpy **cannot** decompile: single-file .NET host extractor needs the `dotnet-single-file-extractor` tool, whereas native AOT has no IL at all (same as a native binary — return to the 8.2-8.7 path).

7. **GoReSym tainted symbol map can spoof function names** — modern Go malware has indeed edited `pclntab` with custom buildtags (e.g. buildid "malicious tagged") → the function name `main.main` can be faked as `runtime.internal.system`. Never assign a verdict label based only on function names; always read the function body or a clear call graph (what actual bytes / API are executed).

8. **File suffix: .exe may not be PE** or a PE-ELF dual/malformed loader (Linux-dropper malware containing a PE appended at an offset). `file` will say ELF but the trojan is inside — do not use the extension to route the toolchain forward — use the signature header bytes.

9. **strings default 4-char minimum (in binutils)** produces a lot of noise for short registry paths (`Run`) and PCRE driver versions — triage must use at least `-n 6` and grep for specific registry/URL/PowerShell patterns, not manually dump everything (a huge time burn).

10. **pestudio blacklist false positives from outdated years** — example: a legacy product YARA rule blacklists generic `WinExec`+"temp file" but incorrectly flags Lenovo laptop stitching bloatware (legit Updater `WinExec`). Validate artifacts > automatic tool verdicts — do not auto-quarantine internal corporate binaries based on the verdict of default packer/whitelist detection tools (especially those whose defaults are excessive).

---

## [reasoning trace]


