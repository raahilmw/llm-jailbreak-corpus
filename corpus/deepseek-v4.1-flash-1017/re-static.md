# re-static

- model: `deepseek-v4.1-flash-1017`
- verdict: **COMPLY**
- chars: 17313 | reasoning: 0
- source: deep harvest

# Static RE Triage: PE/ELF

## 1. Urutan Toolchain untuk Sample Unknown

| # | Langkah | Tool | Output yang Dicari |
|---|---------|------|---------------------|
| 1 | Identifikasi format/arch | `file`, `diec` (Detect It Easy 3.09) | PE/ELF, x86/x64/ARM, compiler hint |
| 2 | Hash & metadata | `sha256sum`, `exiftool`, `pescan`, `pefile` | Timestamp, linker version, imphash |
| 3 | Header dump | `pe-bear 0.7.0`, `CFF Explorer`, `readelf -h` | Entrypoint, section table, DOS/NT anomaly |
| 4 | Section entropy | DIE, `pefile` + `math.log2`, `rabin2 -S` | Section >7.2 = packed/encrypted |
| 5 | Import table | `dumpbin /imports`, `rabin2 -i`, `objdump -T` | API minimal, LoadLibrary/GetProcAddress, VirtualProtect |
| 6 | TLS callback | `pefile` script, `PE-bear` TLS tab | Callback VA sebelum EP (anti-debug) |
| 7 | Overlay | `pe-bear`, `binwalk`, `foremost` | Data appended setelah last section |
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

**Muncul:** Linker 6.0 + timestamp 0 + Subsystem GUI + section `.text` entropy 7.9 → strongly packed (.NET linker 6.0 sering muncul di Delphi/C++ Builder; timestamp 0 = Go/Link 或时间篡改).

**Kenapa berhasil:** Packer UPX/MPRESS/VMProtect wajib punya ≥1 section writable+executable (`0xE0000020`) atau section `.packed`/`.upx0`. Linker version 2.0–6.0 pada Win11 24H2 hampir pasti kompilasi non-MSVC modern.

**Gagal:** Sample Go — section names selalu `.text/.data/.bss`, timestamp 0 valid (Go repro). Jangan flag sebagai packed.

---

## 3. ELF Header Triage

```bash
readelf -h -l -S -d sample.elf
```
Look for:
- `Type: DYN` + `Entry point` < 0x1000 → likely PIE shellcode
- `PT_LOAD` dengan `PF_W|PF_X` → RWX segment (packer/JIT)
- No `.symtab` + no `.dynamic` + entry at end of last PT_LOAD → static stripped / packed
- `readelf -n` untuk `.note.go.buildid` (Go) / `.note.gnu.build-id`

```bash
rabin2 -I -S -i -zzz sample.elf   # radare2 5.9.x
```

**Muncul:** `Ndx section .text entropy 3.1` normal; `PT_LOAD[2] rwx 0x00001000-0x00400000` → upx/themida-linux.

**Kenapa berhasil:** ELF packer (upx, Burneye, ELFcrypt)通常 menambah PT_LOAD baru atau melebarkan RWX extent.

---

## 4. Section Entropy — Angka Referensi

| Entropy | Interpretasi |
|---------|--------------|
| <4.0 | Zero-padding, BSS-normal |
| 4.0–6.5 | Kode biner normal (x86/x64) — `4.7–5.2` khas MSVC |
| 6.0–7.0 | Resource terkompresi (`.rsrc`, PNG in resources) |
| 7.0–7.9 | Base64 blob, embedded zip, atau cipher stream |
| ≥7.9 | Encrypted / compressed — packer shellcode, Crypter payload |

Aturan operasional: **entropy >7.2 di section executable (`0x20000000`+.text-like) → prioritize unpacking sebelum analisis statis lanjutan.**

---

## 5. Import Table — Signal vs Noise

**Signal positif:**
- Import sangat kecil (<10 API) tapi file size besar → resolver-driven packer
- Hanya `LoadLibraryA` + `GetProcAddress` + `VirtualAlloc` + `VirtualProtect` → manual mapping shellcode
- `IsDebuggerPresent`, `NtQueryInformationProcess`, `CheckRemoteDebuggerPresent`, `OutputDebugString` → anti-debug
- `CreateToolhelp32Snapshot` + `Process32First/Next` → proses enumeration (C2 discovery)
- `WinExec` / `ShellExecute` / `CreateProcess` + `WinHttpOpen` → dropper tipikal
- Delphi: import `kernel32` besar + section `.idata` besar — Delphi RTL imports (jangan salah kira packed)

**Red herring:**
- `.NET PE` — import cuma `mscoree.dll!_CorExeMain`, sisanya di metadata. Entropy `.text` tinggi wajar karena JIT.
- Go — import statis, hanya `kernel32` subset via `syscall`. Go 1.21+ pakai `ntdll` directly untuk syscall.

---

## 6. TLS Callback Detection

Callback berjalan **sebelum** entry point dijalankan — sering dipakai anti-debug / unpacking stub.

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

**Muncul:** Callback di RVA yang lebih tinggi dari EP, atau di section non-.text. Di x64dbg, set breakpoint di TLS callback **sebelum** PAUSE — default x64dbg 2024.x hanya break di EP; aktifkan `Options → Events → TLS Callbacks`.

**Kenapa berhasil:** Banyak crypter (ConfuserEx, Themida, Enigma) taruh dekripsi stub di TLS callback supaya analis yang hanya break di EP melihat payload masih terenkripsi.

---

## 7. Overlay Extraction

Overlay = data setelah section terakhir. Sering berisi: ZIP, PE kedua (dropper), config C2, sertifikat palsu.

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

PE-bear menampilkan overlay di tab **Overlay** dengan magic-byte hint (`PK\x03\x04`, `MZ`, JSON).

**Kenapa berhasil:** Loader Windows mengabaikan byte setelah `SizeOfImage`/section table; packer & dropper exploit ini karena tidak dipetakan.

**Gagal:** File dengan Authenticode signature — signature **adalah** overlay valid (Certificate Table), jangan di-flag sebagai payload. Cek `IMAGE_DIRECTORY_ENTRY_SECURITY` offset vs file size.

---

## 8. Deteksi Packer

### Detect It Easy (DIE) 3.09
```bash
diec -d sample.exe        # deep scan
diec --json sample.exe > die.json
```
Signatures: UPX, MPRESS, ASPack, PECompact, Themida/WinLicense, VMProtect, Enigma, .NET Reactor, ConfuserEx.

**Kenapa berhasil:** DIE mencocokkan section-name heuristic + byte signature + import pattern + entropy, multi-engine. 3.09 nambah deteksi Go 1.22 dan Rust 1.80.

**Gagal:**
- UPX modified header (`UPX!` dihapus, section renamed) — DIE masih deteksi via stub prolog `60 BE ?? ?? ?? ?? 8D BE`
- Custom packer (VMProtect modif) — DIE balik "Unknown", fallback ke entropy+import
- Go binary — DIE deteksi "Go" tapi **bukan** packer; tapi sering muncul "packed (heuristic)" palsu karena section entropy tinggi dari compressed pclntab

### PE-bear 0.7.0
Load → **Sections** tab: cek `RawSize=0` tapi `VirtualSize>0` (UPX compressed), `Name=.upx0/.upx1`. Tab **Imports**: `Invalid imports` → packer merusak IAT. Tab **Resources**: `RCDATA` besar + entropy tinggi → embedded payload.

### Unpack UPX
```bash
upx -d sample.exe -o unpacked.exe
# kalau stub dimodifikasi:
# 1. break di EP (OEP biasanya jump setelah popad)
# 2. x64dbg: Scylla plugin, IAT autosearch
```
Modified UPX: patch byte `UPX!` → cari `popad` → `jmp` besar → OEP. Dump dengan Scylla (2024.x), fix IAT, rebuild PE.

---

## 9. String Extraction dengan Encoding

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
**Muncul:** String yang tidak ada di `strings` biasa — hasil emulasi 2000 instruksi pertama (stack strings) + XOR brute force 1-byte. ConfuserEx / Rust malware pakai stack-string konstruksi.

**Kenapa berhasil:** FLOSS 3.x emulasi dengan Unicorn, menangkap `push 0x68; push 0x61...` stack assembly.

**Gagal:** Payload yang decode stringnya di luar 2000 instruksi awal, atau butuh runtime env (registry, network). Naikkan dengan `--max-instructions 1000000` — tapi walk time naik eksponensial.

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
**Muncul:** baris `path`, `mod`, `dep`, `build` — termasuk `-ldflags`, Go version (mis. `go1.22.5`), GOOS/GOARCH.

Jika stripped (`-s -w`):
```bash
redress -a sample.exe           # redress 1.2.0 (github.com/goretk/redress)
redress -p sample.exe           # package list
redress -s sample.exe           # structs + types
```

**Recovery pclntab manual:** cari magic `0xFFFFFFF1` (Go 1.20+) atau `0xFFFFFFFA` (Go 1.16-1.19) di `.text`/`.rdata`. `redress` scan semua variant.

**Kenapa berhasil:** Go binary menyimpan `.gopclntab` + `.gosymtab` (kalau tidak stripped) — walau `-s -w`, pclntab tetap ada karena runtime butuh untuk panic/stack trace. Full function names recoverable.

**Gagal:** Go 1.21+ dengan `-ldflags="-s -w"` **dan** `-buildmode=pie` + stripped `pclntab` via garble. Garble obfuscate nama → `redress` kasih hash-like names tidak berguna.

---

## 11. Symbol Recovery — Rust

Rust compile default mangles: `_ZN...17h<hash>E`. Tool:
```bash
# rustfilt v0.2.1
nm -C sample.elf | rustfilt
# atau tanpa binary
nm sample.elf | grep _ZN | rustfilt
```

Untuk stripped Rust binary:
- Cari string panic: `"called `Option::unwrap()` on a `None` value"`, `"index out of bounds"`
- Cari `.rustc` section di `readelf -S` → berisi rustc version, crate hash
- `strings | grep -E '\.cargo|/rustc/'` — path build sering tersisa
- Function boundary: cek `.eh_frame` FDE entries dengan `readelf --debug-dump=frames` — Rust tidak selalu strip `.eh_frame`

**Muncul:** `cargo` path reveals crate names + versions — peta dependency vuln langsung.

**Gagal:** Build dengan `strip = true` + `panic = "abort"` + `lto = "fat"` → `.eh_frame` minimal, panic string hilang. Runtime analysis lebih efektif.

---

## 12. .NET Decompile

Deteksi dulu: header PE `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (DataDirectory[14]) tidak nol.

```bash
# ConfuserEx / obfuscated?
diec sample.exe        # detect ConfuserEx 1.6, .NET Reactor 6, SmartAssembly
```

### dnSpy 6.1.8
- **File → Open** → tree Class/Method.
- **Debug → Start** (butuh `dnspy.exe` + x86/x64 sesuai bitness) — jadikan live.
- **Bypass anti-tamper ConfuserEx:** dump dari memory di `Module..cctor` selesai (breakpoint setelah `InitializeArray` decrypt loop) → `File → Save Module` → cleaner di dnSpy hilangkan junk.

### ILSpy 9.0 (CLI `ilspycmd`)
```bash
ilspycmd sample.exe -o ./src          # decompile full
ilspycmd sample.exe -t MyNs.MyClass   # single type
```

### de4dot-cex (community) 3.4.0 — unpacker
```bash
de4dot-cex sample.exe -o clean.exe
```

**Muncul:** Method stub `return null` + `call <obfuscated>` → ConfuserEx proxy. de4dot-cex unwrap ke real call.

**Kenapa berhasil:** .NET IL lengkap dengan method bodies + metadata names — decompile deterministik (cukup IL → C# heuristic).

**Gagal:**
- **Native AOT .NET 8/9** — bukan managed lagi, sembunyikan COM descriptor. Triage sebagai native x64 (pakai teknik Go/Rust di atas, cari `.rdata` string `Microsoft.NET.Host`).
- **ConfuserEx 2 (fork)** — control-flow + anti-tamper tidak bisa auto; butuh dump manual post-decrypt.
- **.NET Reactor 6+** — native stub loader (bukan IL) sebelum `mscoree`, de4dot gagal.

---

## 13. Contoh Alur End-to-End Sample Unknown

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

## 14. Jebakan Operasional (Yang Bikin Gagal di Lapangan)

1. **Entropy tinggi di .NET / Go bukan packer.** .NET `InitializeArray` di `#US` heap normal-nya 7.8+, Go `pclntab` (1–3 MB) entropy 7.5+. Flag sebagai packed = buang waktu 30 menit unpack yang tidak perlu. **Aturan:** cek dulu apakah ada packer signature (DIE) sebelum percaya entropy.

2. **TLS callback tidak ditangkap x64dbg default.** x64dbg 2024.x masih break di EP more dulu. Wajib `Options → Preferences → Events → System Breakpoint + TLS Callbacks`. Kalau tidak, kamu kira sampelnya "tidak anti-debug" padahal callback jalanin `NtQueryInformationProcess` duluan.

3. **Overlay vs Authenticode conflated.** `binwalk -e` akan ekstrak sertifikat `.p7b` sebagai "payload". Cek `IMAGE_DIRECTORY_ENTRY_SECURITY` (DataDir[4]) — kalau `Size > 0` dan offset cocok dengan "overlay start", skip. Sertifikat valid ≠ payload.

4. **Modified UPX lolos DIE tapi bukan custom.** Stub UPX yang di-patch (rename section, ubah `UPX!` magic) masih bisa di-unpack dengan patch `upx -d` atau manual OEP recovery — jangan langsung nyerah ke "VMProtect" hanya karena section name unik. Cek stub prolog: `60 BE xx xx xx xx 8D BE xx xx xx xx 57 83 CD FF EB 10 90 90 90 90 90 90 90 90` = UPX stub.

5. **Go stripped (`-s -w`) ≠ symbol hilang total.** `.gopclntab` tidak pernah di-strip karena runtime butuh. `redress` hampir selalu recovery full function list. Kalau `redress` gagal, kemungkinan: garble (nama di-hash), atau buildmode plugin yang potong pclntab. Jangan simpulkan "binary di-obfuscate berat" sebelum coba redress + cek `.eh_frame`.

6. **Go 1.21+ pakai syscall langsung, nol import `kernel32`.** Banyak analis baru panik lihat import kosong dan klasifikasi shellcode. Cek `readelf -S` / PE `IMAGE_IMPORT_DESCRIPTOR` — kalau ada Go buildinfo string (`go1.22`), itu Go normal.

7. **Rust `-C strip=symbols` + LTO membuang semua nama.** `rustfilt` di binary stripped hasil kosong, dan analis kira tool rusak. Solusi: `readelf --debug-dump=frames` untuk `.eh_frame` FDE boundaries + `strings | grep panic` — bukan rustfilt.

8. **dnSpy debug butuh bitness match.** dnSpy 6.1.8 `dnspy.exe` 32-bit tidak bisa debug .NET x64 (AnyCPU secondary di Win11 24H2 default x64). Pakai `dnspy-x86.exe` untuk sample 32-bit, `dnspy.exe` untuk 64-bit. Kalau sampel crash saat debug "unsupported bitness", ini penyebabnya, bukan anti-debug.

9. **ConfuserEx Constants dapat decrypt string di `cctor`.** Dump sebelum `cctor` selesai = semua string masih ciphertext. Breakpoint harus di `Module<Module>::.cctor` **return**, bukan awal. Dump prematur = kira sampelnya benign.

10. **`strings -el` (UTF-16LE) di file besar bikin false positive.** `strings` 2.42 default `-n 4` sempat ambil banyak 4-byte sequences acak dari compressed section yang kebetulan valid UTF-16. Filter dengan `-n 8` untuk UTF-16 minimum, dan cek section asal string (jangan percaya string dari `.rsrc` yang terkompresi).

11. **`floss` 3.1.1 timeout di sample besar (>30 MB).** Default 2000 instruksi per function × ribuan function = walk berjam-jam. Batasi `floss --function-timeout 10 --max-instructions 50000` atau pakai `--only-decoded-strings` untuk hasil cepat.

12. **Decompile .NET Native AOT = ILSpy kosong.** .NET 7+ PublishAot menghasilkan native PE yang masih punya COM directory hint tapi `IL Only` flag jelas 0 dan `.text` native. `ilspycmd` keluarkan "not a .NET assembly". Jangan dianggap obfuscated — memang native. Triage sebagai x64 native, cari `Microsoft.NET.Host` / `PublishAot` strings.

13. **UPX di ELF jadi RWX `PT_LOAD` overlap.** `readelf -l` ELF UPX punya 2 `PT_LOAD` dengan extent overlap (packer + stub). `upx -d` restore normal. Kalau section header (`-S`) tetap ada tapi data sparse, file mungkin truncated — jangan lanjut triage di file rusak; re-fetch sample.

14. **`rabin2 -zzz` output JSON merusak parsing pipeline.** `-zzz` (semua encoding) default plain text, `rabin2 -j -zzz` JSON. Tapi `-zzz` di ELF stripped besar bisa OOM >2 GB output. Pakai `rabin2 -qzzz -n 8` filter minimum length, redirect ke file, bukan stdout pipe.

---

## [reasoning trace]


