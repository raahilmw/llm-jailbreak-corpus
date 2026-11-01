# re-static — malware

# Static RE Triage: PE/ELF

## 1. Toolchain Order for Unknown Sample

| # | Step | Tool | Desired Output |
|---|---------|------|---------------------|
| 1 | Identifikasi format/arch | `file`, `diec` (Detect It Easy 3.09) | PE/ELF, x86/x64/ARM, compiler hint |
| 2 | Hash & metadata | `sha256sum`, `exiftool`, `pescan`, `pefile` | Timestamp, linker version, imphash |
| 3 | Header dump | `pe-bear 0.7.0`, `CFF Explorer`, `readelf -h` | Entrypoint, section table, DOS/NT anomaly |
| 4 | Section entropy | DIE, `pefile` + `math.log2`, `rabin2 -S` | Section >7.2 = packed/encrypted |
| 5 | Import table | `dumpbin /imports`, `rabin2 -i`, `objdump -T` | API minimal, LoadLibrary/GetProcAddress, VirtualProtect |
| 6 | TLS callback | `pefile` script, `PE-bear` TLS tab | Callback VA before EP (anti-debug) |
| 7 | Overlay | `pe-bear`, `binwalk`, `foremost` | Data appended after last section |
| 8 | Strings (multi-encoding) | `strings -a -el`, `floss 3.1.1`, `rabin2 -zzz` | URL, mutex, registry, IDE console |
| 9 | Symbol recovery | `go version -m`, `redress`, `rustfilt`, `nm -C` | Go buildinfo, Rust mangled names |
| 10 | Decompile (if applicable) | `dnSpy 6.1.8`, `ILSpy 9.0`, `pycdc` | C#/IL, Python bytecode |
| 11 | Dynamic hand-off | x64dbg, gdb+pwndbg, Frida | Runtime unpack, API resolve |

---

## 2. PE Header Triage

**Kirim:** `pefile` parser minimal.

```python
import pefile, math, hashlib
pe = pefile.PE("sample.exe", fast_load=False)
print("EP:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("ImageBase:", hex(pe.OPTIONAL_HEADER.ImageBase))
print("TimeDateStamp:", pe.FILE_HEADER.TimeDateStamp)
print("LinkerVer:", pe.OPTIONAL_HEADER.MajorLinkerVersion,
      pe.OPTIONAL_HEADER.MinorLinkerVersion)
print("Subsystem:", pe.OPTIONAL_HEADER.Subsystem)
for s in pe.sections:
    data = s.get_data()
    ent = 0.0
    if data:
        freq = [0]*256
        for b in data: freq[b] += 1
        f = [x/len(data) for x in freq if x]
        ent = -sum(p*math.log2(p) for p in f)
    print(f"{s.Name.decode(errors='ignore').rstrip(chr(0)):8} "
          f"VA={hex(s.VirtualAddress):>10} "
          f"raw={s.SizeOfRawData:>8} vsz={s.Misc_VirtualSize:>8} "
          f"ent={ent:.3f} flags={hex(s.Characteristics)}")
```

**Appears:** Linker 6.0 + timestamp 0 + Subsystem GUI + section `.text` entropy 7.9 → strongly packed (.NET linker 6.0 often appears in Delphi/C++ Builder; timestamp 0 = Go/Link or time tampering).

**Why it works:** UPX/MPRESS/VMProtect packers must have ≥1 writable+executable section (`0xE0000020`) or a `.packed`/`.upx0` section. Linker version 2.0–6.0 on Win11 24H2 is almost certainly a modern non-MSVC compilation.

**Fails:** Go sample — section names are always `.text/.data/.bss`, timestamp 0 is valid (Go repro). Do not flag as packed.

---

## 3. ELF Header Triage

```bash
readelf -h -l -S -d sample.elf
```
Look for:
- `Type: DYN` + `Entry point` < 0x1000 → likely PIE shellcode
- `PT_LOAD` with `PF_W|PF_X` → RWX segment (packer/JIT)
- No `.symtab` + no `.dynamic` + entry at end of last PT_LOAD → static stripped / packed
- `readelf -n` for `.note.go.buildid` (Go) / `.note.gnu.build-id`

```bash
rabin2 -I -S -i -zzz sample.elf   # radare2 5.9.x
```

**Muncul:** `Ndx section .text entropy 3.1` normal; `PT_LOAD[2] rwx 0x00001000-0x00400000` → upx/themida-linux.

**Why it works:** ELF packers (upx, Burneye, ELFcrypt) usually add a new PT_LOAD or widen the RWX extent.

---

## 4. Section Entropy — Reference Numbers

| Entropy | Interpretasi |
|---------|--------------|
| <4.0 | Zero-padding, BSS-normal |
| 4.0–6.5 | Kode biner normal (x86/x64) — `4.7–5.2` khas MSVC |
| 6.0–7.0 | Resource terkompresi (`.rsrc`, PNG in resources) |
| 7.0–7.9 | Base64 blob, embedded zip, or cipher stream |
| ≥7.9 | Encrypted / compressed — packer shellcode, Crypter payload |

Operational rule: **entropy >7.2 in executable section (`0x20000000`+.text-like) → prioritize unpacking before further static analysis.**

---

## 5. Import Table — Signal vs Noise

**Signal positif:**
- Very small import (<10 APIs) but large file size → resolver-driven packer
- Only `LoadLibraryA` + `GetProcAddress` + `VirtualAlloc` + `VirtualProtect` → manual mapping shellcode
- `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, `OutputDebugString` → anti-debug
- `CreateToolhelp32Snapshot` + `Process32First/Next` → proses enumeration (C2 discovery)
- `WinExec` / `ShellExecute` / `CreateProcess` + `WinHttpOpen` → dropper tipikal
- Delphi: large `kernel32` import + large `.idata` section — Delphi RTL imports (don't mistake for packed)

**Red herring:**
- `.NET PE` — import is only `mscoree.dll!_CorExeMain`, the rest is in metadata. High `.text` entropy is normal due to JIT.
- Go — static imports, only a `kernel32` subset via `syscall`. Go 1.21+ uses `ntdll` directly for syscalls.

---

## 6. TLS Callback Detection

Callback runs **before** the entry point is executed — often used for anti-debug / unpacking stub.

```python
import pefile
pe = pefile.PE("sample.exe")
if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    base = pe.OPTIONAL_HEADER.ImageBase
    rva = tls.AddressOfCallBacks - base
    arr = pe.get_dword_at_rva(rva)
    i = 0
    while arr:
        print(f"TLS cb[{i}]: {hex(arr)} (RVA {hex(arr-base)})")
        i += 1
        arr = pe.get_dword_at_rva(rva + i*4)
```

**Appears:** Callback at an RVA higher than EP, or in a non-.text section. In x64dbg, set a breakpoint at the TLS callback **before** PAUSE — default x64dbg 2024.x only breaks at EP; enable `Options → Events → TLS Callbacks`.

**Why it works:** Many crypters (ConfuserEx, Themida, Enigma) put the decryption stub in the TLS callback so that analysts who only break at EP see the payload still encrypted.

---

## 7. Overlay Extraction

Overlay = data after the last section. Often contains: ZIP, second PE (dropper), C2 config, fake certificate.

```bash
python3 -c "
import pefile
p = pefile.PE('sample.exe')
last = max(s.PointerToRawData + s.SizeOfRawData for s in p.sections)
import os; print('overlay_off:', hex(last), 'size:', os.path.getsize('sample.exe')-last)
"
dd if=sample.exe of=overlay.bin bs=1 skip=$((0xLAST)) 
file overlay.bin
binwalk -e overlay.bin
```

PE-bear displays the overlay in the **Overlay** tab with magic-byte hints (`PK\x03\x04`, `MZ`, JSON).

**Why it works:** The Windows loader ignores bytes after `SizeOfImage`/section table; packers & droppers exploit this because it is not mapped.

**Fails:** File with Authenticode signature — the signature **is** a valid overlay (Certificate Table), do not flag as payload. Check `IMAGE_DIRECTORY_ENTRY_SECURITY` offset vs file size.

---

## 8. Deteksi Packer

### Detect It Easy (DIE) 3.09
```bash
diec -d sample.exe        # deep scan
diec --json sample.exe > die.json
```
Signatures: UPX, MPRESS, ASPack, PECompact, Themida/WinLicense, VMProtect, Enigma, .NET Reactor, ConfuserEx.

**Why it works:** DIE matches section-name heuristic + byte signature + import pattern + entropy, multi-engine. 3.09 adds detection for Go 1.22 and Rust 1.80.

**Fails:**
- UPX modified header (`UPX!` removed, section renamed) — DIE still detects via stub prolog `60 BE ?? ?? ?? ?? 8D BE`
- Custom packer (modified VMProtect) — DIE returns "Unknown", fallback to entropy+import
- Go binary — DIE detects "Go" but **not** a packer; however "packed (heuristic)" often appears falsely because of high section entropy from compressed pclntab

### PE-bear 0.7.0
Load → **Sections** tab: check `RawSize=0` but `VirtualSize>0` (UPX compressed), `Name=.upx0/.upx1`. **Imports** tab: `Invalid imports` → packer corrupts IAT. **Resources** tab: large `RCDATA` + high entropy → embedded payload.

### Unpack UPX
```bash
upx -d sample.exe -o unpacked.exe
# kalau stub dimodifikasi:
# 1. break di EP (OEP biasanya jump setelah popad)
# 2. x64dbg: Scylla plugin, IAT autosearch
```
Modified UPX: patch `UPX!` byte → find `popad` → large `jmp` → OEP. Dump with Scylla (2024.x), fix IAT, rebuild PE.

---

## 9. String Extraction with Encoding

### Tool matrix

| Tool | Encoding | Cmd |
|------|----------|-----|
| `strings` GNU binutils 2.42 | ASCII, UTF-16LE | `strings -a -el -n 6 sample.exe` |
| FLOSS 3.1.1 | ASCII, UTF-16, stack, decoded (XOR, base64) | `floss sample.exe -o floss.json` |
| rabin2 5.9.0 | ASCII, UTF-8/16, base64 | `rabin2 -zzz sample.elf` |
| CyberChef | Manual multi-encoding | Resep: From Base64 → XOR Bruteforce |

### FLOSS — string obfuscated
```bash
floss --no-static-strings --only-decoded-strings sample.exe
```
**Appears:** Strings not present in regular `strings` — result of emulating the first 2000 instructions (stack strings) + 1-byte XOR brute force. ConfuserEx / Rust malware use stack-string construction.

**Why it works:** FLOSS 3.x emulates with Unicorn, capturing `push 0x68; push 0x61...` stack assembly.

**Fails:** Payloads that decode strings beyond the first 2000 instructions, or require runtime env (registry, network). Increase with `--max-instructions 1000000` — but walk time increases exponentially.

### Encoding manual
```bash
# UTF-16LE
iconv -f UTF-16LE -t UTF-8 <(tail -c +0 sample.bin) | strings
# Base64 blobs
grep -aEo '[A-Za-z0-9+/]{40,}={0,2}' sample.bin | while read b; do echo "$b" | base64 -d 2>/dev/null | head -c 200; echo; done
```

---

## 10. Symbol Recovery — Go

```bash
go version -m sample.exe
# atau untuk ELF
go version -m sample.elf
```
**Appears:** lines `path`, `mod`, `dep`, `build` — including `-ldflags`, Go version (e.g. `go1.22.5`), GOOS/GOARCH.

Jika stripped (`-s -w`):
```bash
redress -a sample.exe           # redress 1.2.0 (github.com/goretk/redress)
redress -p sample.exe           # package list
redress -s sample.exe           # structs + types
```

**Manual pclntab recovery:** search for magic `0xFFFFFFF1` (Go 1.20+) or `0xFFFFFFFA` (Go 1.16-1.19) in `.text`/`.rdata`. `redress` scans all variants.

**Why it works:** Go binary stores `.gopclntab` + `.gosymtab` (if not stripped) — even with `-s -w`, pclntab remains because the runtime needs it for panic/stack trace. Full function names recoverable.

**Fails:** Go 1.21+ with `-ldflags="-s -w"` **and** `-buildmode=pie` + stripped `pclntab` via garble. Garble obfuscates names → `redress` gives hash-like names that are useless.

---

## 11. Symbol Recovery — Rust

Rust compile default mangles: `_ZN...17h<hash>E`. Tool:
```bash
# rustfilt v0.2.1
nm -C sample.elf | rustfilt
# atau tanpa binary
nm sample.elf | grep _ZN | rustfilt
```

For stripped Rust binary:
- Cari string panic: `"called `Option::unwrap()` on a `None` value"`, `"index out of bounds"`
- Search for `.rustc` section in `readelf -S` → contains rustc version, crate hash
- `strings | grep -E '\.cargo|/rustc/'` — path build sering tersisa
- Function boundary: check `.eh_frame` FDE entries with `readelf --debug-dump=frames` — Rust does not always strip `.eh_frame`

**Muncul:** `cargo` path reveals crate names + versions — peta dependency vuln langsung.

**Fails:** Build with `strip = true` + `panic = "abort"` + `lto = "fat"` → minimal `.eh_frame`, panic strings gone. Runtime analysis is more effective.

---

## 12. .NET Decompile

Detect first: PE header `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (DataDirectory[14]) is not zero.

```bash
# ConfuserEx / obfuscated?
diec sample.exe        # detect ConfuserEx 1.6, .NET Reactor 6, SmartAssembly
```

### dnSpy 6.1.8
- **File → Open** → tree Class/Method.
- **Debug → Start** (butuh `dnspy.exe` + x86/x64 sesuai bitness) — jadikan live.
- **Bypass ConfuserEx anti-tamper:** dump from memory once `Module..cctor` has finished (breakpoint after the `InitializeArray` decrypt loop) → `File → Save Module` → cleaner in dnSpy removes junk.

### ILSpy 9.0 (CLI `ilspycmd`)
```bash
ilspycmd sample.exe -o ./src          # decompile full
ilspycmd sample.exe -t MyNs.MyClass   # single type
```

### de4dot-cex (community) 3.4.0 — unpacker
```bash
de4dot-cex sample.exe -o clean.exe
```

**Shows up as:** Method stub `return null` + `call <obfuscated>` → ConfuserEx proxy. de4dot-cex unwraps it to the real call.

**Why it works:** .NET IL is complete with method bodies + metadata names — deterministic decompile (IL → C# heuristic is enough).

**Fails:**
- **Native AOT .NET 8/9** — no longer managed, hides the COM descriptor. Triage as native x64 (use the Go/Rust techniques above, look for the `.rdata` string `Microsoft.NET.Host`).
- **ConfuserEx 2 (fork)** — control-flow + anti-tamper can't be automated; requires a manual dump post-decrypt.
- **.NET Reactor 6+** — native stub loader (not IL) before `mscoree`, de4dot fails.

---

## 13. Example End-to-End Flow for an Unknown Sample

```bash
S=unknown.bin
file $S && sha256sum $S
diec $S                       # → PE32+ x64, .NET 4.8, ConfuserEx 1.6
python3 pe_entropy.py $S      # → .text=2.1 (normal for IL), .cctor section=7.9
strings -a -el -n 8 $S | head -50
rabin2 -i $S | grep -E 'VirtualProtect|GetProcAddress'  # → tidak ada, murni managed
python3 tls_cb.py $S          # → TLS callback 0 (unusual di .NET) — RED FLAG
# .NET path
ilspycmd $S -o src/ 2>err.log; head err.log
de4dot-cex $S -o $S.clean
ilspycmd $S.clean -t Loader.Main   # inspect
# kalau native AOT fallback:
go version -m $S || bw 0.1  # detect managed/native
```

---

## 14. Operational Pitfalls (That Make You Fail in the Field)

1. **High entropy in .NET / Go is not a packer.** .NET `InitializeArray` in the `#US` heap is normally 7.8+, Go `pclntab` (1–3 MB) entropy is 7.5+. Flagging it as packed = wasting 30 minutes on an unnecessary unpack. **Rule:** first check whether a packer signature exists (DIE) before trusting entropy.

2. **TLS callbacks are not caught by default in x64dbg.** x64dbg 2024.x still breaks at EP first. You must enable `Options → Preferences → Events → System Breakpoint + TLS Callbacks`. Otherwise you think the sample "isn't anti-debug" when the callback actually runs `NtQueryInformationProcess` first.

3. **Overlay vs Authenticode conflated.** `binwalk -e` will extract the `.p7b` certificate as "payload". Check `IMAGE_DIRECTORY_ENTRY_SECURITY` (DataDir[4]) — if `Size > 0` and the offset matches "overlay start", skip it. Valid certificate ≠ payload.

4. **Modified UPX passes DIE but isn't custom.** A patched UPX stub (renamed section, changed `UPX!` magic) can still be unpacked with a patched `upx -d` or manual OEP recovery — don't immediately give up to "VMProtect" just because the section name is unique. Check the stub prolog: `60 BE xx xx xx xx 8D BE xx xx xx xx 57 83 CD FF EB 10 90 90 90 90 90 90 90 90` = UPX stub.

5. **Go stripped (`-s -w`) ≠ symbols completely gone.** `.gopclntab` is never stripped because the runtime needs it. `redress` almost always recovers the full function list. If `redress` fails, likely causes: garble (names hashed), or a plugin buildmode that cuts pclntab. Don't conclude "heavily obfuscated binary" before trying redress + checking `.eh_frame`.

6. **Go 1.21+ uses direct syscalls, zero `kernel32` imports.** Many new analysts panic seeing empty imports and classify it as shellcode. Check `readelf -S` / PE `IMAGE_IMPORT_DESCRIPTOR` — if there's a Go buildinfo string (`go1.22`), it's normal Go.

7. **Rust `-C strip=symbols` + LTO discards all names.** `rustfilt` on a stripped binary returns empty, and analysts think the tool is broken. Solution: `readelf --debug-dump=frames` for `.eh_frame` FDE boundaries + `strings | grep panic` — not rustfilt.

8. **dnSpy debug requires a bitness match.** dnSpy 6.1.8 `dnspy.exe` 32-bit can't debug .NET x64 (AnyCPU secondary on Win11 24H2 defaults to x64). Use `dnspy-x86.exe` for 32-bit samples, `dnspy.exe` for 64-bit. If the sample crashes during debug with "unsupported bitness", this is the cause, not anti-debug.

9. **ConfuserEx Constants can decrypt strings in `cctor`.** Dumping before `cctor` finishes = all strings are still ciphertext. The breakpoint must be at `Module<Module>::.cctor` **return**, not the start. Premature dump = you think the sample is benign.

10. **`strings -el` (UTF-16LE) on large files creates false positives.** `strings` 2.42 default `-n 4` sometimes picks up many random 4-byte sequences from compressed sections that happen to be valid UTF-16. Filter with `-n 8` for the UTF-16 minimum, and check the section the string came from (don't trust strings from a compressed `.rsrc`).

11. **`floss` 3.1.1 times out on large samples (>30 MB).** Default 2000 instructions per function × thousands of functions = an hours-long walk. Limit it with `floss --function-timeout 10 --max-instructions 50000` or use `--only-decoded-strings` for quick results.

12. **Decompiling .NET Native AOT = empty ILSpy.** .NET 7+ PublishAot produces a native PE that still has a COM directory hint but the `IL Only` flag is clearly 0 and `.text` is native. `ilspycmd` outputs "not a .NET assembly". Don't consider it obfuscated — it really is native. Triage as x64 native, look for `Microsoft.NET.Host` / `PublishAot` strings.

13. **UPX on ELF becomes an RWX `PT_LOAD` overlap.** `readelf -l` on a UPX ELF has 2 `PT_LOAD` segments with overlapping extents (packer + stub). `upx -d` restores it to normal. If the section headers (`-S`) still exist but the data is sparse, the file may be truncated — don't continue triage on a broken file; re-fetch the sample.

14. **`rabin2 -zzz` JSON output breaks the parsing pipeline.** `-zzz` (all encodings) defaults to plain text, `rabin2 -j -zzz` is JSON. But `-zzz` on a large stripped ELF can OOM with >2 GB of output. Use `rabin2 -qzzz -n 8` to filter minimum length, redirect to a file, not a stdout pipe.

---

## [reasoning trace]


