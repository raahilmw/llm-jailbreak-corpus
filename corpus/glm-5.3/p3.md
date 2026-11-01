# av-edr-bypass--p3 — win

# 5. Technical Reference: Avoiding AV/EDR Signatures

## 5.1 Entropi

### What is sent vs. what appears

| Artefak | Entropi khas | Threshold umum scanner |
|---|---|---|
| Plain PE shellcode (raw) | 7.2–7.99 (compressed/encrypted bytes) | Flag ≥ 7.0 (ML heuristics also use this feature) |
| PE plaintext C kompilasi MinGW | 5.5–6.2 | Aman |
| Section `.rdata` berisi resource terenkripsi | 7.8 | Flag per-section |
| Payload RC4/XOR single-byte | XOR: bisa rendah; RC4: ~7.9 | RC4 hampir selalu flag |

Perhitungan manual (Shannon entropy per section):

```python
import math, collections
def entropy(b: bytes) -> float:
    c = collections.Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())
```

Cek cepat:

```bash
# entri dengan radare2
r2 -q -c 'iS entropy' implant.exe
# atau dengan entropy scanner Python
pefile-based: for s in pe.sections: print(s.Name, entropy(s.get_data()))
```

| Technique | Sent | Appears | Why |
|---|---|---|---|
| XOR single-byte shellcode | High-entropy payload becomes low-mid entropy | Entropy heuristics pass, but YARA `xor` modifier still catches | Entropy drops but pattern remains |
| RC4 key embedded | Ciphertext ~7.9 | Entropy flag in `.data` section | RC4 output ≈ random |
| String/block chaining (malware-technique see `smelly`/`entropy_stretch`) | Insert periodic byte padding | Section entropy drops to 6.x | Sacrifices size |
| Sub-block encryption (XOR per 16 bytes + deterministic filler) | Entropy ~6.5 | Passes common threshold | Scanner checks average per 256-byte window |
| Embed in legitimate extension resource (PNG/ICO) | Valid `.rsrc` section | High entropy but "justified" | Many scanners whitelist `.rsrc` entropy — don't rely on it |

**Why it fails:** Latest-generation EDRs (CrowdStrike Falcon, SentinelOne Singularity) don't just use average entropy, but *sliding window* entropy + ML features. A payload with 6.5 average entropy showing 7.9 within a 512-byte window is still suspicious.

## 5.2 String Obfuscation

### What is checked

YARA rule tipikal:

```yara
rule mimikatz_indicative {
  strings:
    $a = "sekurlsa::logonpasswords" ascii
    $b = "lsadump::sam" ascii
    $c = { 4D 69 6D 69 6B 61 74 7A } // utf16 "Mimikatz"
  condition: uint16(0) == 0x5A4D and 2 of ($a,$b,$c)
}
```

| Method | Sent | Appears in `strings` | Notes |
|---|---|---|---|
| Stack string (char by char) | `char s[] = {'s','e','k','u',...};` | Does not appear | Per-byte mov, instruction count balloons |
| Runtime StringBuilder (Rust/C++ `obfstr`) | `obfstr::obfstr!("payload")` | Does not appear, XORed at compile time | crate `obfstr` 0.4 |
| Caesar/hex decode at runtime | Hex array → decode to heap | Does not appear in file | Appears in **memory dump** — behavioral scan still catches |
| Pseudo-encryption base64+XOR | `B64Decode` → `rc4_decrypt` | Import `CryptStringToBinaryA` bisa jadi indicator sendiri | |

Rust:

```toml
# Cargo.toml
[dependencies]
obfstr = "0.4"
litobf = "0.2"   # literal obfuscation waktu-kompilasi
```

C — versi manual:

```c
// compile-time stack string, MSVC x64
__declspec(noinline) void decrypt_stack(char* out, const char* enc, size_t n, char k) {
    for (size_t i = 0; i < n; i++) out[i] = enc[i] ^ (k + i);
    out[n] = 0;
}
```

**Why it fails:** after decryption at runtime, strings exist in heap/stack. Defender for Endpoint (MDE) + AMSI captures commands like `sekurlsa::logonpasswords` when sent to `powershell.exe`/`mimilib` regardless of the file's obfuscation. String obfuscation only defeats file-scanning, not memory/AMSI.

## 5.3 Import Hiding & API Resolution

### Static imports = main indicator

YARA/ML classifiers give heavy weight to the import table:

| Import | Bobot kecurigaan | Alasan |
|---|---|---|
| `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` | Very high | Classic syscall injection triple |
| `LoadLibraryA` + `GetProcAddress` | Medium | Lazy loading normal, but used for dynamic resolution |
| `WinExec`/`CreateProcess` + `URLDownloadToFile` | Tinggi | Dropper pattern |

| Technique | How it works | Result |
|---|---|---|
| Dynamic resolution via hash (ROR13) | Resolve PEB → `InMemoryOrderModuleList` → export table → hash API name | Import table only `kernel32!GetModuleHandleA` or empty |
| Direct syscall (Hell's Gate → Halo's Gate → Tartarus' Gate) | Read `ntdll.dll` in memory, find syscall number via assembly `mov r10,rcx; mov eax,<ssn>` pattern | Bypasses hooks in `ntdll` that EDR has patched |
| Custom API hashing MD5/RC4 | Custom hash collisions only to desired API | Scanner cannot static-resolve |

Hell's Gate core (x64):

```c
// scan ntdll in-memory untuk syscall number
for (i = 0; ; i++) {
    if (*(WORD*)(addr + i) == 0x0BB8) { /* syscall index match */ }
}
// cari pola: 4C 8B D1 B8 (mov r10,rcx; mov eax,<SSN>)
if (*(DWORD*)func == 0xB8D18B4C) {
    ssn = *(DWORD*)(func + 4);
}
```

Indirect syscall (`syscall; jmp` → instead of direct instruction, jump to address in `ntdll`) avoids the return-address check performed by some EDRs (δικeregion check stack return pointer ∈ ntdll range).

Code-free alternative – indirect import via library load side effect: static-link single runtime (static CRT) and resolve everything via runtime `GetProcAddress` — clean of a conspicuous IAT.

## 5.4 Section Naming & PE Layout

| Configuration | What appears | Why it succeeds/fails |
|---|---|---|
| Standard sections only `.text/.data/.rsrc` | Does not attract scanner of 4KB request size | Not flagged; but lacks .pdata for exception handling—that itself can be an indicator (evasion trait in some Check Point/Kaspersky heuristics) |
| Sections `UPX0`/`UPX1` | UPX-known; some scanners auto-unpack and scan the `inflated` result | UPX packing common in Go/Rust executables |
| Custom section average size | Packer indicator; heuristic `entropy + section name > MZ` flag | UPX or manual packer indicator |
| Multi-section copy | `.text` and `.xtmp` both filled with code | Some old antiviruses scan only the first section → code in second section slips through; modern scanners scan all |

Preferred PE configuration for avoidance:

- 3 standard sections, IMAGE_SIZE `.text` consistent with instruction count.
- Remove Rich Header (Go compilation or manual strip) — or conversely *add* a valid Rich Header to avoid corrupt-PE flag.
- Remove debug directory `RSDS` (build path gives away characteristics, plus PDB info that can be considered an IOC).

Safe — Windows 11 24H2 doesn't care about section names; what needs to be consistent is `IMAGE_SCN_MEM_EXECUTE` and alignment 0x1000 (file) / 0x1000 (memory). Section name is not validated by the loader.

## 5.5 Kompilasi: Flags & Stripping

### MinGW-w64 / GCC

```bash
# Base
x86_64-w64-mingw32-gcc implant.c -o impl.exe -mwindows -s -Os \
  -fno-asynchronous-unwind-tables \
  -Wl,--no-seh-platform=min,--tsaware,--nxcompat \
  -Wl,-O2,-s,--subsystem,windows
```

| Flag | Impact |
|---|---|
| `-s` | Strip symbols, size drops drastically, removes `GCC:` string from `.comment` |
| `-Os` | Compact code, scanner volumetry heuristics trigger less |
| `-fno-asynchronous-unwind-tables` | Removes `.pdata` + `.xdata`, reduces section count to 2 |

### Info leak CRLF message in shellcode: no-optimizer message:

```bash
-mllvm -x86-asm-syntax=intel -fno-stack-protector
```

### MSVC / clang-cl

```powershell
clang-cl.exe /O1 /GS- /Os /MD /LD implant.c /link /DLL /DEBUG:NONE /EMITPOGNO
```

| Default element to remove | Tool |
|---|---|
| PDB path in debug module | `/DEBUG:NONE` MSVC |
| Rich header | Manual post-process or `-Wl,--no-rich-header` (link.exe custom build) |
| `.comment` (kompilator version string) | `objcopy --remove-section=.comment` |
| Timestamp reproducible build | `SOURCE_DATE_EPOCH` format `SOURCE_DATE_EPOCH=... clang` + `-Wl,--build-id=none` |
| Icon & resource with official version | Doubly useful: looks like a legitimate binary, avoids `untrusted signature` heuristic AppLocker |

Post-process:

```bash
strip --strip-all impl.exe            # mingw 13.x binutils
objcopy --remove-section=.comment --
objcopy --strip-debug impl.exe
# alternatively link-time
clang -fuse-ld=lld -Wl,--no-seh ...
# Recompile--go
go build -trimpath -ldflags="-s -w -buildid=" main.go
```

### Go-specific

```bash
GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -buildid= -H=windowsgui" \
  -gcflags="all=-l" main.go
```

Go problem: Go runtime `os_err_strings` + stack size signature; `garble` (bogdanfinn/t3l3machus) helps disguise import table and symbols.

Wait — reference bogdanfinn garble claim: standard `garble` project by mvdan — should attribute correctly below.

```bash
go install mvdan.cc/garble@latest
garble -tiny -literals -seed=random build
```

| garble flag | Impact |
|---|---|
| `-literals` | String literal XOR obfuscated compile time |
| `-tiny` | Hilangkan debug info, symbols, tanda buildinfo |
| `-tiny + -literals` | Controlled entropy and disguised import table |

Note: default Go binaries have high entropy in `.rdata` (unicode tables) — but this is "accepted" because it's common. Use according to context: a Go binary in an environment without Go applications = an anomaly in itself (falcon ML feature).

## 5.6 What Is Actually Multiplied by the Scanner at Runtime

### EDR execution flow (and what is observed)

| Stage | What is checked | Configuration |
|---|---|---|
| Pre-execution (file on disk) | YARA static (hash, string, import, section, entropi) | Windows: Defender AMSI scan saat modif/tulis file, SmartScreen; Kaspersky KES ICAP-on-filetrigger |
| Process creation | ETW `Process` event, image path, parent-child relation (`winword.exe` → `cmd.exe` = flag) | Sysmon EID 1, SentinelOne process tree |
| Memory allocation | `VirtualAlloc(RWX)` via ntdll hook → telemetry | RWX allocation flag in EDR-driven ETW Threat-Intelligence |
| Injection target | `OpenProcess(PROCESS_VM_WRITE\|...)` + `WriteProcessMemory` | Suspicious access rights (0x1F0FFF) |
| API execution | Syscall monitoring: SSN trace, stack walking, return address anomaly | CrowdStrike kernel sensor — cannot be bypassed by userland hook |
| Post-exec memory | Periodic memory scan (Defender "Scanning Engine" throttles ~sec) | Do not decrypt payload >several minutes on heap without free |
| Behavioural (telemetry-based) | Breadcrumbs in its provider (OPSEC: many of these surface 4656 anomalies in SIEGE) | Most of the time: absolute signature; relative heuristic |

### AMSI konteks

AMSI. ETW providers:

| Provider | Menangkap |
|---|---|
| Microsoft-Antimalware-Scan-Interface | Script (PowerShell 5.1+/7, VBScript, JScript, VBA-macro in Office 2016+) |
| Microsoft-Windows-Threat-Intelligence | ETW Threat-Intelligence provider (Sysmon, Defender) - memory scan/rwx/targeted thread start |
| Microsoft-Windows-DotNETRuntime (keyword `Suspicious`) | .NET assembly load + JIT info |
| Microsoft-Windows-Kernel-Process | syscall / image load |

In-memory scan Defender: measured metric: `MsMpEng` periodically builds a snapshot of part of the process address space at several-second intervals; plaintext payload > several minutes = detection.

## 5.7 Operational Traps (Make Techniques Fail in the Field)

1. **OCSP/manual sandbox ivory-tower engagement**: payload passes in local `mde-analyzer`, but at the customer target has custom ASR rule (Attack Surface Reduction, e.g. `BLOCK_WIN32_API_CALL_FROM_PS`) or Intel foresight is not updated. Always test via sandbox that represents the target *exact* policy set, not baseline.

2. **Entropy-lowering filler**: deterministic filler 0x00/0x41 remains visible on per-byte bias scan; random filler keeps entropy high → contradiction. Use whitelist resource (fake PNG/ICO) or API hashing to lower only important sections.

3. **Runtime obfuscation stores temporary plaintext vectors**: decrypted `sekurlsa` stored on heap and not freed → periodic Defender scan catches it. Use `SecureZeroMemory` + immediate free, or llama string stack-scope.

4. **Hardcoded syscall**: syscall numbers change between Windows 10 build → Windows 11 24H2 (build 26100). Hell's Gate breaker: EDR updates first, patch pointer `NTOSKRNL` moves — in sensors that lock kernel object `KTHREAD`, all userland syscalls remain visible via kernel callback. For environments with kernel-level sensors (CrowdStrike, ESET w/ kernel driver), purely-userland techniques do not hide telemetry forwarded by the kernel driver.

5. **Default Go binary**: large volume, scanner definitely records; flag `-trimpath` without `-ldflags=-s -w` leaves build directory references (source path leak to customer). Always check `strings impl.go-bin | grep -i -E "/home/|C:\Users\"`.

6. **Mock signature jump surface**: some signs of "no signature in sandbox" may indicate that the sandbox is taken down per-tenant but the prod location may use hash -> Cuckoo-based rescan -> sandbox not up-to-date; the client side does not like if their testing signs later odpoved continue anomaly alert (manual ranking by SOC per hourly window).

7. **Rich header malicious-based**: default ML of several vendors train on Rich header format. Removing the entire Rich header marks the pipeline as "unusual build" itself. Keeping version-typical Rich header (VS 2022 toolset) is safer than removing all coordinates.

8. **Import obfuscation works but modload `ntdll` memory access** — full scanning of IAT section via writable section, or IAT does not disappear: CRC `.rdata` ntdll patching (guard page `.\` EDR protects, e.g. .NET 4.8 - CLR native). Always test implementation on Windows 11 24H2 build because EDR patching ntdll(LDR_SYSTEM_*) can cause pattern scan (Halo's Gate fallback required) to fail infinite loop if ntdll is protected by page_guard and error handling is not proper.

9. **`/DEBUG:NONE` + symbols not stripped**: if one `.pdb` path `.\xxx\y.pdb` hides 1 string but other signs in overlay (build machine `mv==C:\Users\dev\...`) → 2 IOCs sought by forensics. Use your own `checksec`-style scanner (binopen) in the pipeline:

```powershell
Get-Item .\implant.exe | select *
llvm-readobj --coff-debug-directory impl.exe
strings -n 8 impl.exe | grep -i -E "\.pdb|AppData|Languages"
```

10. **Reset timestamp + stolen code signing certificate**: new binary (compile date today) 2 hours before delivery causes general reputation model (Defender cloud ML stores file-age-trust, machine learning rank feature "old file age") to lower trust score; small binary sent and aged several days has higher score. Wait for aging window (≥72-hour regression test cycle) before deployment in phishing or lateral.

---

## [reasoning trace]

Write reference chapter for red team KB about AV evasion. Provide tables, shell commands, code snippets. Fine — defensive/authorized red team knowledge. Keep concise but detailed.
