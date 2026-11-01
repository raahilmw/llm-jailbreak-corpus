# re-static — malware

# Bab 8 — Static RE Triage: PE/ELF

## 8.1 Toolchain Inti

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
| IDA Free 9 / Ghidra 11.3 | — | Analisis lanjut |

---

## 8.2 Triage Cepat dengan DIE

**Apa yang dikirim:**
```bash
diec.exe -e -a -d sample.exe   # entropy, semua signature, deep scan
```

**Apa yang muncul:**
```text
PE32
  Protector: UPX (3.96) [signature: UPX0, UPX1, UPX!]
  Compiler: MSVC (19.29.30133) [link 14.29]
  Entropy: 7.82 (section UPX1)
```

**Kenapa berhasil:** DIE match signature byte statis di header/file + heuristik nama section. Entropy > 7.0 pada section kode hampir selalu = compressed/encrypted.

**Kenapa gagal:** Custom packer tanpa signature publik muncul "Nothing detected" — jangan percaya hasil negatif DIE. UPX modifikasi (anti-DIE anti-UPX patch) tetap terdeteksi tapi unpack manual gagal dengan `upx -d`.

---

## 8.3 PE Header Parse (PE-bear)

**Apa yang dikirim:** buka sample di PE-bear, fokus ke:
1. **DOS Header** — `e_magic = MZ`, `e_lfanew` offset (valid: 0x40–0x200)
2. **NT Header** — `TimeDateStamp` (bogus jika uniform `0x55555555` atau epoch tahun depan), `SizeOfOptionalHeader`
3. **Section Table** — periksa flag anomali:

| Anomali | Indikasi |
|---|---|
| `IMAGE_SCN_MEM_WRITE \| EXECUTE` (0x60000020) | Self-modifying/unpacking |
| Section name kosong/non-standar + entropy ≥ 7.0 | Packer |
| `PointerToRawData = 0` tapi `SizeOfRawData > 0` |irtual section / fileless tample |

**Kenapa berhasil:** malware umum modifikasi invariants PE loader. Loader Windows 11 24H2 sangat toleran (section bisa overlap, header flag bisa inkonsisten) sehingga packer menyalahgunakan slack ini.

---

## 8.4 Section Entropy Manual

**Apa yang dikirim:**
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

**Kenapa gagal:** entropy 7.3+ pada `.rsrc` bisa jadi ikon PNG/embedded legit, bukan packed kode. Entropy rendah tidak menutup kemungkinan obfuscation via string stack (Flare-on style).

---

## 8.5 Import Table

**Apa yang dikirim:**
```bash
rabin2 -i sample.exe
# atau pestudio → Imports tab (highlight merah otomatis)
```

**Indikator mining (pestudio blacklist):**

| API | Probable penggunaan |
|---|---|
| `VirtualAlloc` + `VirtualProtect` + `WriteProcessMemory` | Injection / unpacking |
| `LoadLibraryA` + `GetProcAddress` dengan IAT kosong | Resolusi dinamis / packed, IAT asli runtime |
| `RtlUnwind`, anti-debug flags `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` | Anti-analysis |
| `InternetOpenUrlA`, `URLDownloadToFileA` | Second-stage loader |
| `CryptDecrypt` + `CryptStringToBinaryA` | Payload decryption builtin |

**IAT hanya 2-3 import (kernel32: LoadLibrary/GetProcAddress/ExitProcess)** ⇒ 99% packed atau manually-resolved. Header asli muncul setelah unpack — simpan dump.

---

## 8.6 TLS Callback

**Kenapa penting:** callback TLS dieksekusi **sebelum** entry point (`AddressOfEntryPoint`) — dipakai untuk unpacking dan kill-switch anti-debug.

**Apa yang dikirim:** PE-bear → Data Directories → `TLS Table`:
- `AddressOfCallBacks` (runtime ke pointer array, terminated NULL)
- `AddressOfIndex` (slot index)
- Raw AddressOfCallBacks

**Flip-peforma:** flag `IMAGE_DIRECTORY_ENTRY_TLS` index 9 di OptionalHeader DataDirectory.

**Output:** jika callback ada dan binary adalah packed sample, pindahkan entry analisis ke callback-address, bukan `AddressOfEntryPoint`. Loader Windows (termasuk 24H2) selalu trigger ini sebelum epilogue loader → teknik klasik UPX-modified, Carp/pack DB.

**Gagal:** jika packer zero-out flag di header tapi region `.rdata` punya callback array — loader Windows ignore (header flag mn10), tapi beberapa versi nanami (Crystal) memanggil manual via `TlsAlloc` — periksa call site.

---

## 8.7 Overlay (Appendix Data)

**Apa yang dikirim:** PE-bear → baris terakhir section header → bandingkan `PointerToRawData + SizeOfRawData` terakhir vs `file size`:
```bash
# oto
rabin2 -SSo sample.exe     # overlay offset
xxd -s $OVERLAY_OFFSET sample.exe | head
```

**Apa yang muncul (contoh nyata):** file 2.1MB, last section end = 0x1A0000, sisa 0xC0000 bytes = data overlay magic `MZ` + baru → dropper second stage appended, loader menghitung `(file_size - overlay_marker_offset)` runtime offset.

**Kenapa berhasil:** loader Windows mengabaikan data > mapped size → tempat favorit nyimpan second stage, config, atau implant.

**Action:**`binwalk overlay.bin` untuk carve embedded ZIP/CAB/PE nested.

---

## 8.8 ELF Triage

**Apa yang dikirim:**
```bash
readelf -h sample.elf      # header — periksa e_type (EXEC/DYN), e_entry
readelf -S sample.elf      # section — entropy.check
readelf -d sample.elf       # DT_NEEDED (libc dinamis?), DT_FLAGS (pie?)
objdump -T sample.elf      # dynamic symbol (lekstra imports dt PLT)
readelf -r sample.elf      # reloc GOT hijack
```

**Indikator:**

| Artefak | Indikasi |
|---|---|
| `e_type = EXEC` + `DT_NEEDED` kosong | Statically linked — glibc statically-linked membesar ke ~800KB; mirriadi bounce |
| Section `.text` entropy > 7 | UPX ELF (`UPX!` magic near EOF) |
| `DT_DEBUG` missing + custom interpreter path | Packed/musl |
| GOT entry patched post-link (compare `.rela.dyn`) | Hooking runtime (Egg/Audit LD_PRELOAD style) |

**Kenapa gagal:** stripped static ELF pada musl (atau Zig) — hampir tidak ada strings dinamis, no symbol. Wajib fingerprinting byte di `.rodata` (musl constant) atau signature `__libc_start_main` alternative.

---

## 8.9 Ekstraksi String (Multi-Encoding)

**Apa yang dikirim:**
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

**Kenapa berhasil:** UTF-16LE (`--encoding=b` / `-e l`) wajib untuk registry path & API — plain ASCII strings meleset di binary PE Windows. Waktu file dibuat via shellcode `CharUpperW` pointer, encoded strings muncul sebagai stack-constructed dalam disassembly (dari ISH — Immediate String Heap) dan hanya terlihat oleh **FLOSS / strings-emulator**, bukan strings.

**Gagal ketika:** stack strings dengan XOR kunci single byte — FLOSS emulasi gagal jika pakai loop untul multi-rotate. Pakai IDA/Ghidra + dekripsi manual via Python: `bytes([c ^ 0x37 for c in stack_bytes])`.

---

## 8.10 Symbol Recovery: Go & Rust

**Go binary:**

**Apa yang dikirim:**
```bash
goresym.exe -t -d -p sample.exe   # GoReSym (mandiant) 1.7+
# atau di Ghidra: > Golang symbol recovery (Refinery) extension
```

**Kenapa berhasil:** Go runtime butuh function table internal pcln (`runtime.pclntab`) untuk trace/panic,DAn symbol dan file name source path sering intact meski stripped. GoReSym menemukan pclntab magic `0xFFFFFFF0` (go1.18+) atau `0xFFFFFFFB` (go1.20+, perlu versi major.minor.patch exact), rebuild nama function (`main.main`, `net.Dial`), firstmoduledata address, buildID.

Output:
```text
Build ID: GO\n1.21.0\linux\namd64
Functions: 15200
main.main RIPPER: 0x4a2f10
main.injectShell
```

**Gagal jika:** binary build dengan `go build -ldflags="-s -w"` + malformed pclntab (malware-go umum corruptu specific field biar IDA GoReSym dan IDA golang loader gagal). Counter: patch manual `pclntab.pcln` pointer recovery berbasis scan pattern `runtime.moredetails`.

**Rust binary:**
- Tidak ada pclntab ekivalen. Recovery via: (1) panic string `panicked at 'src/main.rs:?:?'` berisi path+line; (2) vtable + `rust_begin_unwind` masih ada di symbol-ELF statis; (3) di IDA, apply **cargo sccache** style regex pattern matching — cari call pattern `core::result::unwrap_failed`.
- Stripped Rust binary di ELF musl: hampir zero nama. Identifikasi by unique strings peladen: `rustc` release channel atau crate panic messages `assertion failed: ...`.
- Tool `rust-stripped-annotate`/IDB script oleh ban be memory forensics — pattern880 v0.3; perlu commit peer projects (một Bebek) untuk update tanda newest rustc 1.83 release.

---

## 8.11 .NET Decompilation (dnSpyEx / ILSpy)

**Kapan:** DIE deteksi `.NET` / `MSIL`, atau `mscoree.dll` di import + CLI header (`IMAGE_DIRECTORY_ENTRY_COMHEADER` index 14).

**Apa yang dikirim:**
```bash
# dnSpyEx 6.5.4 (fork maintained dnSpy) — drag-drop .exe
# Build-in decompiler: View → Windows → IL decompiler (switch C# ↔ IL)
```

**Apa yang muncul:**
```csharp
// d98xxCrypto3.cs
protected static byte[] Decode(XElement x) {
    return Convert.FromBase64String(x.Value).Select((b, i) => (byte)(b ^ key[i % key.Length])).ToArray();
}
// key = "tVictoryPath24; strOver = "https://.../gate.php"
```

**Kenapa berhasil:** kebanyakan loader .NET (Dany, Quasar, Remcos loader, AsyncRAT 0.5.x) hanya obfuscate metadata level (ConfuserEx, .NET Reactor), bukan IL semantiknya — dnSpy decompile 95% kode readable tanpa pengerjaan apapun.

**ConfuserEx 1.0 sample:**
```text
"<PrivateImplementationDetails>" tidak muncul
string reference via resource decrypt — cari fungsi integer-id lookup, rename symbol dengan dnSpy → buka Method → Edit Method untuk modular check
```

Untuk sample ConfuserEx: gunakan **de4dot-cex** (fork) atau **ConfuserEx-Tools**:
```bash
de4dot.exe -p un sample.exe   # generic unpacker profile detection
```

**ILSpy** (9.x, cross-platform, headless):
```bash
ilspycmd -p -o out/ sample.exe
```
Gunakan bila dnSpyEdit gagal pada .NET 8/9 runtime (native AOT — tidak bisa decompile; jelaskan di entry: single-file self-contained .NET 8+ native AOT memindahkan ke native-the-section-8.3 realm).

**Gagal:** (1) harassed symbols + control-flow obfuscated berat (Agile.NET), di mana control flow jadi `switch(temp) goto` — perlu deobfuscator dedicated; (2) JIT hooking / runtime patch `Assembly.Load` byte stream — hanya load di runtime, scripting perlu dnSpy debugger attach saat load ekstensi.

---

## 8.12 Urutan Toolchain untuk Sample Unknown (runbook)

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

**Checkpoint YARA hasil triage:** jika strings dan IAT clean, dan hanya fungsi injeksi terlihat → jangan berhenti — sample yang dianggap "sederhana loader" umum trial stage terenkapsulasi di resource/overlay/gate-server; pastikan stage-2 extraction via config decode baru selesai, kembali step 4 jika ternyata nested.

---

## 8.13 Jebakan Operasional

1. **DIE signature negative ≠ bersih.** Custom crypter 2023+ (mis. injector loader native Indonesia-rea) tidak ada di database DIE. Selalu cross-check entropy section manual: entropy rendah "aman" bisa berupa kod yang di-decrypt partial runtime.

2. **TimeDateStamp PEs dan `TimeDateStamp` adalah spoofable.** Jangan pakai untuk timestamp commitment — verifikasi dengan PEs Rich Header (`@comp.id` setter MSVC) atau debug directory (`RSDS` path + timestamp) yang jarang di-patch.

3. **Packer UPX-modifikasi: `upx -d` gagal.** Packer inland cukup patch 1-2 byte di `UPX!` header untuk membuat official UPX refuse unpack — wajib caraруч way (x64dbg ESP trick pada packer tersebut) atau man-patch kembali ke expected — ini membuat batch-processing pipeline auto-unpack gagal diam-diam.

4. **TLS callback anti-debug auto-menghancurkan sample** ketika dump dilakukan via run approach: beberapa sample cek `BeingDebugged` flag lalu `TerminateProcess` → dump bagian penuh tidak pernah sampai ke staging. Gunakan anti-anti-debug plugin (ScyllaHide 1.5) sebelum proses run di lab VM snapshot.

5. **File-size besar (installer, installer LG, Dropper adapted)** membuat FLOSS sangat lambat (emulasi semua routine bisa ~ 1-2 jam untuk 50MB installer). Pra-sigital: batasi `-n minimal` dan carve dulu resource (`7z x`) sebelum floss pada binary paten.

6. **.NET modern (IC 2024+: native AOT .NET 8/9 atau self-contained single file)** — dnSpyEx/ILSpy **tidak bisa** decompile: single-file .NET host extractor perlu `dotnet-single-file-extractor` tool, sedangkan native AOT tidak ada IL sama sekali (sama seperti native binary — kembali ke jalur 8.2-8.7).

7. **Tainted symbol map GoReSym bisa spoof nama function** — malware-go modern memang sudah edit `pclntab` custom buildtag (misal buildid "malicious tagged") → nama fungsi `main.main` bisa dipalsukan jadi `runtime.internal.system`. Jangan pernah memberi label verdict hanya dari nama fungsi; selalu baca body function atau call graph yang jelas (What actual bytes / API executed).

8. **Suffix file: .exe bisa bukan PE** atau PE-ELF dual/malformed loader (malware linux-dropper berisi PE appended di offset). `file` akan bilang ELF tapi trojan di dalam — jangan gunakan ekstensi untuk routing toolchain forward — gunakan signature header byte.

9. **strings default 4-char minimal (dalam binutils)** menghasilkan banyak noise untuk registry path pendek (`Run`) dan PCRE driver versi — triage harus minimal `-n 6` dan grep specific registry/URL/powershell pattern, bukan dump manual semua (time-burn besar).

10. **pestudio-blacklist miss positive tahun-tahun outdated** — contoh: YARA rule produk legacy mem-blacklist `WinExec`+"temp file" generic tapi keliru men-flag Lenovo bloatware laptop stitching (Updater `WinExec` legit). Validate artefak > tool verdict otomatis — jangan auto-quarantine binary internal corporate dari verdict packer/whitelist detection tool default (terutama yang defaultnya excessive).

---

## [reasoning trace]


