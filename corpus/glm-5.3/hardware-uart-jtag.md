# hardware-uart-jtag — hardware

# Hardware Hacking — Bab Referensi Red Team

Versi dokumen: 1.0 | Target audience: operator field team | Scope: IoT/router/kamera IP/perekam DVR

---

## 0. Perangkat Wajib Bawa

| Perangkat | Fungsi | Alternatif |
|---|---|---|
| Logic analyzer **Saleae Logic 8** (clone ~IDR 150rb, firmware sigrok OK) | UART discovery, timing | DSLogic Plus |
| **CH341A** programmer + socket SOP8/DIP8 + adapter 1.8V | SPI flash dump in-circuit/out-circuit | MiniPRO TL866-II Plus, Raspberry Pi GPIO bitbang |
| **FTDI FT232H** breakout | UART + bitbang SPI/JTAG | CP2102 (UART saja) |
| **Bus Pirate v3.6** | UART/SPI quick check | — |
| Kabel jumper dupont, klip Pomona SOIC8 (untuk dump tanpa penyolderan), multimeter, stetoskop probe | — | — |
| **Raspberry Pi 4/5** atau laptop Linux | host tooling | — |

Software baseline: Debian 12 (bookworm), kernel 6.1+.

```bash
sudo apt install sigrok-cli openocd flashrom binwalk python3-pip usbutils
pip install unblob
git clone https://github.com/firmianhayi/FirmAE && cd FirmAE && ./install.sh
# binwalk modern: pakai binwalk v3 (unblob backend), v2 sudah deprecated DIY
```

---

## 1. Identifikasi UART

### 1.1 Apa yang dicari
Port UART 4-pin di PCB: pola pad/pin berjejer 4, label kadang **TX RX GND VCC / T R G / CON3 / J4**. Vias test-point juga sering UART.

### 1.2 Prosedur tanpa dokumentasi

1. Bongkas perangkat, foto dua sisi PCB (label silkscreen, jumlah layer).
2. Cari **GND** dulu: continuity test antar pin ke shielding/ground plane.
3. Cari pin RDF/level konstan (hanya GND yang konsisten dipakai). Sisanya: colok logic analyzer.

### 1.3 Logic analyzer — capture & decode

**Yang dikirim:** tidak ada (passive sniff). Analyzer hanya merekam.

**Yang muncul:** transisi digital pada saat boot (UART bootloader/console biasanya aktif saat power-on).

```bash
# sigrok + Saleae clone (fx2lafw)
sigrok-cli --driver fx2lafw --channels D0=RX,D1=TX,D2=GND --continuous \
  --time 10000 --output-format bits:width=16 | head -50

# decode baud otomatis: ukur lebar pulsa terpendek manual
# sampling 16 MHz, pulsi terpendek x sample → 1/baud
sigrok-cli --driver fx2lafw --config samplerate=16M --samples 16M \
  -o uart.sr -p uart:baud=115200
```

Dekode manual di PulseView: tambahkan protokol **UART**, set baud, coba urutan pin TX/RX dibalik kalau hasilnya sampah.

**Tabel baud umum:**

| Device class | Baud tipikal |
|---|---|
| Router TP-Link/Mercusys | 115200 |
| Kamera IP (Hikvision, Dahua) | 115200 |
| ESP32/ESP8266 dev | 115200 (ESP32: 115200 default console) |
| STB/Android TV box | 115200, kadang 921600 |
| Modem LTE (HiSilicon) | 115200 |
| Router ISP ZTE/Fiberhome (GPON ONT) | 115200 atau 921600 |

> Kalau teks sampah semua: baud salah. Sampling 16MHz, pulsa terpendek ±875 sample → 16e6/875 ≈ 18285 → coba 19200. Hitung: **176 sample @16MHz ≈ 921600 baud**.

### 1.4 Konsol interaktif

```bash
sudo apt install picocom
sudo picocom -b 115200 /dev/ttyUSB0
# keluar: Ctrl-A Ctrl-X
```

**Yang dikirim:** newline; enter ganda saat boot (interrupt autoboot).

**Yang muncul dan kenapa penting:**
- `Press Ctrl-C to abort autoboot` dalam 1–2 detik → **interrupt bootloader** untuk ambil command line U-Boot.
- Shell root tanpa login (sering di kamera murah) → shell langsung.
- Prompt login tapi kredensial vendor → lanjut dump firmware.

### 1.5 Payload U-Boot umum

```
# di prompt U-Boot saat boot:
setenv bootdelay 5; saveenv          # hilangkan autoboot count
printenv bootargs                    # lihat bootargs, alamat kernel
bootdelay=-1
# bypass verifikasi kalau ada:
setenv verify no; saveenv
# boot ke shell: ubah init
setenv bootargs ${bootargs} init=/bin/sh
boot
```

**Kenapa berhasil:** U-Boot hampir selalu tanpa auth; `bootargs init=/bin/sh` bypass pseudoroot karena init diganti sebelum pencarian user-land.

**Kenapa gagal:** U-Boot dikunci (`CFG_ENV_IS_NOWHERE`, `saveenv` disabled), autoboot tanpa delay 0, atau output UART mati begitu kernel start (console di device tree dialihkan).

### 1.6 Password hash di konsol terkunci
Coba default vendor (kalau sudah di-scope) lalu kalau sudah ok, lanjut SPI dump. Tidak brute force di lapangan — dump dulu.

---

## 2. JTAG / Debug Port

### 2.1 Identifikasi
Header 10–20 pin, label **TDI TDO TCK TMS TRST SRST**, atau pad test-point 5–6 berkelompok. Samakan arah GND dan 1 sel pin lain. Banyak device modern: **ARM SWD** (2 pin: SWDIO + SWCLK) — lebih ringkas, cek mikrokontroler (STM32 family → SWD pasti).

### 2.2 OpenOCD

Versi baseline: OpenOCD 0.12.0+ (patch EJTAG MIPS dari 0.11+ per vendor).

```bash
sudo openocd -f interface/ftdi/ft232h-module-swd.cfg \
  -f target/stm32f1x.cfg
# koneksi umum FT2232H:
sudo openocd -f interface/ftdi/jtagkey.cfg -f target/atheros_ar9331.cfg
```

**Skrip khas router MIPS (AR9331/Ath79):**

```tcl
# ar9331-ddr-wrt.cfg
source [find target/atheros_ar9331.cfg]
jtag_rclk 1000    # adaptive clock, RCLK penting: clock terlalu tinggi tanpa RTCK = TAP error
```

Hubungkan via telnet:

```bash
telnet localhost 4444
> reset halt
> flash probe 0
> mdw 0x80000000 32      # memory read
> dump_image ram.bin 0x80000000 0x10000
> flash read_bank 0 firmware_spi.bin 0    # dump flash via JTAG
```

HiSilicon GPON ONT (sering di rumah user SGP): scan JTAG dengan jtagfinder/jtagulator, lalu OpenOCD custom target config (tidak ada di upstream openocd 0.12, config harus dibuat manual dari chip datasheet IR register).

### 2.3 Tool scan JTAG tanpa config

```bash
git clone https://github.com/cybergibbons/jtagulator
# JTAGULATOR: brute force 4-wire JTAG atau 2-wire SWD, laporan IR length
```

### 2.4 Kenapa berhasil/gagal

- Gagal: kebanyakan router SoC produksi memiliki boundary scan TAP saja (bukan CPU TAP), tidak bisa debug dengan chip yang sama; developer middleware mematikan non-debug mode produksi, JTAG perlu **keadaan reset saat dikonfigurasi**.
- Yang aksesnya biasanya dimatikan dengan hardware (hold-down) EFuse di ARMada / MT7xxx series: ini bukan mitos—terlalu banyak menghabiskan waktu; kalau perangkat tidak merespons reset halt, langsung ke SPI dump.
- Sering gagal dengan OpenOCD dan clock terlalu tinggi; awalnya selalu `jtag_rclk` di bawah 1 MHz, adaptif.
- Berhasil kalau target STM32/ESP32 debug port tidak terkunci flash (baca `RDP` level: option bytes RDP0 = open).

---

## 3. SPI Flash Dump (NOR)

### 3.1 Identifikasi flash chip

Baca top marking chip SOP8/SOP16:

| Marking | Chip | Size | Voltage |
|---|---|---|---|
| **W25Q128JV** | Winbond | 16 MB | 3.3V |
| **W25Q64FV** | Winbond | 8 MB | 3.3V |
| **MX25L1606E** | Macronix | 2 MB | 3.3V |
| **GD25Q128** | GigaDevice | 16 MB | 3.3V |
| **EN25QH64A** | EON | 8 MB | 3.3V |
| MT25QL128 (NAND, bukan NOR/NOR untuk flashrom) | Micron | — | 3.3V/1.8V — pakai flashrom bb_spi |
| **W25Q128JW** | Winbond | 16 MB | **1.8V** — CH341A 3.3V bisa membunuh chip |

Pinout SOP8 standar (view dari atas, dot di pin 1):
```
      ┌───∪───┐
 /CS ─┤1    8├─ VCC
  DO ─┤2    7├─ /HOLD (atau RESET)
 /WP ─┤3    6├─ CLK
 GND ─┤4    5├─ DI
      └──────┘
```

### 3.2 Dump dengan CH341A

**Yang dikirim:** flashrom mengirim `0x9F` (JEDEC ID) lalu read command `0x03` per 256 byte page.

**Yang muncul:** JEDEC ID (mis. `ef 40 18` = W25Q128) dan dump file.

```bash
# out-of-circuit (chip dicabut/klip SOIC8 langsung):
sudo flashrom -p ch341a_spi -r dump1.bin
sudo flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin && echo "DUMP OK (stabil)" || echo "Noise! ulangi / cek kabel"

# identifikasi saja:
sudo flashrom -p ch341a_spi
# output: "Found Winbond flash chip "W25Q128.V/M" (16384 kB, SPI) on ch341a_spi."
```

### 3.3 Dump in-circuit (perangkat tetap menyala / chip tetap tersolder)

**Masalah:** SoC ikut meng-drive bus. Solusi:

1. Mod CH341A: cut jalur 3.3V programmer saat read? Tidak — gunakan **"3.3V pin lift"** atau supply eksternal.
2. Lebih aman: cabuk/hold **/CS chip** ke GND pakai jumper, matikan board, dump dead-bug.
3. Alternatif: dump via JTAG/OpenOCD kalau TAP hidup, atau via konsol U-Boot (`sf read` + `md.b`/kermit).

```bash
# flashrom v1.3.0: syntax baru
sudo flashrom -p ch341a_spi:spispeed=2000 -r dump.bin
# voltage: chip 1.8V → jangan pakai CH341A. Pakai FT232H + level shifter/perlengkapan:
sudo flashrom -p ft2232_spi:type=232H,port=A,divisor=4 -r dump_18V.bin
```

### 3.4 Kenapa berhasil/gagal

| Gejala | Penyebab | Perbaikan |
|---|---|---|
| `No EEPROM/flash device found` | JEDEC ID tidak terbaca; potensi chip 1.8V atau jalur /CS tak terhubung | cek kontinuitas, cek patch VCC |
| Dump beda tiap kali | bus contention (SoC drive), clock terlalu tinggi | matikan board, potong /CS, spispeed=1000 |
| Hanya blok FF setelah 0x1000 | SoC firmware menimpa flash saat dump mulai (boot loader di RAM driver aktif) | dump dengan GND SoC ditarik / dump halaman halaman di 2 pass |
| Terkunci parkir / **BRICK** (dump rusak lama ladder) | Bukan. Tapi flashron **-w** ke device yang salah = brick, selalu `-r` dulu, jangan `--write` di lapangan | — |

**Backup penting:** dump SPI flash pada perangkat target **adalah backup UID Mac/serial/kalibrasi radio**. Setelah flash ulang tanpe backup → device brick permanen. Buat minimal 2 dump, verifikasi dengan md5.

```bash
md5sum dump*.bin
strings -n 8 dump.bin | head -100    # cek signature firmware muncul di plaintext
binwalk dump.bin                      # lihat section 4
```

---

## 4. Firmware Extraction

### 4.1 binwalk (v3)

```bash
# Debian: binwalk 2.3.3 apt; pakai v3 dari source untuk unblob backend
binwalk dump.bin                       # scan signature
binwalk -e dump.bin                    # auto-extract ke _dump.bin.extracted/
binwalk -Me dump.bin                   # recursive
binwalk -A dump.bin                     # entropy scan per blok  → deteksi TLS/compressed/encrypted region
```

**Yang muncul pada firmware router tipikal:**

```
DECIMAL       HEX         DESCRIPTION
----------------------------------------------------------------
0             0x0         uImage header, CPU: MIPS, image type: firmware
64            0x40        LZMA compressed data
1024          0x400       uImage header, CPU: MIPS, image type: OS kernel image
1064          0x428       LZMA compressed data
10576         0x2950      squashfs, version 4.0, little-endian, 8347454 bytes
```

Filesystem SquashFS = **rootfs**: semua yang kita cari.

```bash
# manual extract squashfs (binwalk kadang gagal kalau header custom):
unsquashfs _dump.bin.extracted/10576
# firmware pakai header定制 (offset) → dd:
dd if=dump.bin bs=1 skip=10576 count=8347454 of=root.squash
unsquashfs root.squash
# grep hash password:
grep -rE '\$[156]\$' squashfs-root/etc/shadow
grep -ri 'password\|passwd\|telnet\|debug' squashfs-root/etc/init.d/
find squashfs-root -name '*.conf' | xargs grep -l httpd
```

**Hash John:**

```bash
unshadow passwd shadow > hashes.txt
john --wordlist=rockyou.txt hashes.txt     # hash $1$ MD5-crypt masih umum di firmware lama
john --show hashes.txt
```

### 4.2 unblob (lebih robust)

```bash
# unblob v1.3+ (instal via pip di Debian 12):
unblob -e dump.bin -o output -v
```

**Kenapa binwalk kadang gagal, unblob berhasil:** binwalk v2 memakai signature magic-string diketahui; vendor sering shift header 1–8 byte (custom padding) atau pakai XOR-obfuscated header. Unblob pakai parser asli untuk beberapa filesystem + extraction handler modular, jadi structure-based bukan magic-offset. Rencana: `unblob` untuk binary di atas 5 MB, binwalk untuk cepat/hands-on di field.

### 4.3 Kenapa gagal

- Binwalk `--entropy` flat merata tinggi semua → firmware terenkripsi (uboot `image_decrypt`) / signed firmware → cek di bootloader source string untuk AES key, atau pakai **fatcat/squashfs custom offset**.
- U-Boot image terenkripsi individual dari vendor (misal Xiaomi / TP-Link Deco: AES-CBC, kunci lengkap di bootloader kita temukan pakai `strings` di image `bl31` atau u-boot region).
- SquashFS dengan endian/big-endian nonstandard (broadcom) → gunakan `sasquatch` (squashfs patched).
- Filesystem pakai **UBIFs** (NAND device) → dump harus OKD (out-of-band data): flashrom gagal murni, harus `nanddump` via OpenOCC atau `ubireader_extract_file` di dumps hasil `nanddump`.

---

## 5. Emulasi Firmware

### 5.1 FirmAE

FirmAE (firmadyne fork, commit 2023) memberikan success rate jauh lebih tinggi di router consumer: penuh instrumentasi & pengurangan ketergantungan NVRAM.

```bash
sudo ./init.sh
# QEMU 5.x static build + FirmAE
sudo ./firmwati.py -c /dev/sdb --input /dev/sdb1 --target 192.168.1.1  # (contoh) tidak—perintah asli:
sudo ./fatcat.py -h

# extract:
sudo ./extracter/extractor.py -k -b dump.bin ./images/
# proces identify & infer:
sudo ./sources/scraper/scrape.py -a ./images/1663 ./sources/INFER.sh
# emulate:
sudo ./run.sh -i 1663 -c -q -m -w
# output:
# [+] Network interfaces: eth0 (192.168.0.1)
# [+] Web server daemon: lighttpd 1.4.48 (port 80, 443)
```

Internal IP emulation biasanya muncul sebagai 192.168.0.1, lintasan QEMU bridge `br0`. **Buka browser ke IP itu = halaman login admin persis fisik** — lakukan vulnerability assessment sambil host firmware asli tetap di lab.

### 5.2 QEMU manual (untuk single binary)

```bash
# squashfs-root hasil extraction:
sudo qemu-system-mips -M malta -kernel vmlinux \
  -drive format=raw,file=rootfs.qcow2 -append "root=/dev/sda1 console=ttyS0" \
  -nographic -netdev user,id=n0,hostfwd=tcp::8080-:80 -device e1000,netdev=n0
# chroot untuk binary:
qemu-mipsel-static -L squashfs-root/ ./squashfs-root/usr/bin/httpd
# L path = sysroot arch, chroot dulu:
sudo chroot squashfs-root/ /usr/bin/qemu-mipsel-static ./usr/bin/httpd
```

**Yang muncul:** binary httpd berjalan di port 8080/8080 — CVE hunting lebih mudah (gdb multiarch attach).

**Debug dengan gdb:**

```bash
gdb-multiarch ./httpd
(gdb) set architecture mips
(gdb) target remote :1234
# QEMU start debug: qemu-mipsel-static -g 1234 ...
```

### 5.3 Kenapa gagal

- Firmware butuh NVRAM values: gunakan libnvram FirmAE atau manual `grep` string key di dump, tulis ke `libnvram` config.
- Web server cek MAC/hardware → gunakan fake NVRAM untuk `et0macaddr` dari firmware fisik.
- QEMU CPU mode salah: double-check `uname -m` di string firmware → MIPS/ARM. Salah endian → kernel panic.
- Kamera IP / SoC Realtek: biasanya kurang support emulation (peripheral khusus), sering gagal — pilih hardware fuzz.
- Watchdog timer aktif → proses httpd mati sendiri dalam 30 detik; disable script watchdogd dengan `source` jail fake NVRAM.

---

## 6. Perintah Cepat (cheat sheet)

```bash
# Scan potential UART: kontinuitas ground + logic analyzer passive
# Dump SPI flash
sudo flashrom -p ch341a_spi -r dump.bin && sudo flashrom -p ch341a_spi -r dump2.bin && cmp dump.bin dump2.bin

# OpenOCD MIPS router
openocd -f interface/jtagkey.cfg -f target/atheros_ar9331.cfg

# JTAG hardcoded: dump memory
reset halt; dump_image out.bin 0x80000000 0x100000

# Binwalk
binwalk -Me firmware.bin

# Unblob
unblob -e -o out extraction firmware.bin

# User hashes
unshadow passwd shadow > hashes; john hashes --wordlist=rockyou.txt

# FirmAE: full emulation
sudo ./run.sh -i 1663 -c -q -m -w

# QEMU binary debugging
qemu-mipsel-static -g 1234 /opt/squashfs-root/usr/bin/httpd
```

---

## 7. Jebakan Operasional (Read Before Deploy)

1. **Board dengan standby power:** perangkat "off" tapi PSU masih mengirim 3.3V ke flash → dump in-circuit kontaminasi. Cabut total (unplug + baterai CMOS jika ada) sebelum dump.
2. **Chip 1.8V (sering di kamera IP baru dan beberapa ONT):** klip langsung dari CH341A 3.3V menghancurkan. Selalu cek top marking Winbond `...JW/IM` vs datasheet atas volatilitas. Perlu adapter 1.8V (SPI blaster atau level-shifter).
3. **Flash питания berikan kontaminasi saat dump mulai resist:** beberapa board menghidupkan flash saat USB programming (CH341A pinjal VCC oleh jalur 3.3V sendiri) — solusinya SOIC8 klip + cut VCC programmer, atau dump dead-bug.
4. **Dump yang hanya diverifikasi sekali, atau tanpa `cmp`:** flash ganda butuh 2 dump identik. Flash noise dapat karena `WP` tidak di-ground atau `HOLD` floating — hubungkan `WP` dan `HOLD/RST` ke VCC yang tepat, bukan floating (paling umum penyebab dump gagal di lapangan).
5. **Kehilangan kabel**: UART pinout **GND** salah → TX analyzer pada VCC → logic analyzer input bisa rusak; TX-RX dibalik → data terima sampah
   sebenarnya lumayan normal, hanya kebalikkan.
6. **Entropi binwalk merata**: firmware terenkripsi. Jangan buang waktu buat "extraction" — cari kunci firmware release pabrik / rools
   UP - cancel scna Loren. ke dua: cek demo UI vendor, kunci AES sering melakukan nekro morf dalam bootloader string.
7. **Tulis ulang firmware tanpa backup → BRICK**, pastikan dump MD5 tersimpan minimal 2 lokasi (USB + server). UID/RF calibration page biasanya HIDDEN,
   vendor tools bisa flashing an... nanti tidak lagi tersedia. Dump chip sendiri = last resort bahkan untuk unbrick.
8. **U-Boot `saveenv` peranggo milik ISP (ONT Huawei/ZTE/HG8245)** = menulis ke variabel `bootdelay` terketuk ENV CRC, bisa brick bootloader jika ENV
   regio tight. Selalu `saveenv` AFTER screenshot `printenv` full, siap full flash dump sebelum saveenv.
9. **Flash yang bukan SOP8/DIP8 (WSON8 tidak dapat klip SOIC8):** tanpa hot-air bisa merusak pad. Solusi: dump via U-Boot sf read + tftp, atau JTAG.
10. **Non-auth UART/JTAG tidak sama dengan "Akses penuh": barebox/U-Boot dapat 'secure boot'** dengan signed zImage (fit image). Interrupt hanya memberikan akses ke bootloader, bukan OS. Cek `iminfo` output.
11. **Lingkungan flashrom v1.3+ berbeda kaleuuan CH341A knock-off**: kombinasi cheap CH341A + flashrom 1.3.x kadang rusak `spispeed`/read timing, flashrom 1.2 lebih reliable untuk suatu board tertentu. Catat veriabel flashrom + commit yang dipakai per target device di entry KB.
12. **FirmAE memory:** emulation openwrt-modern 4MB flash bisa consume 8GB RAM (kernel + ramdis image full size). Pastikan host lab 32GB min
    kalau mau parallel emulasi.</think># Hardware Hacking — Bab Referensi Red Team

Versi dokumen: 1.4 | Scope: IoT, router, kamera IP, ONT GPON | Toolchain: Debian 12, kernel 6.1+

---

## 0. Kit Standar

| Perangkat | Fungsi | Catatan |
|---|---|---|
| Logic analyzer 24MHz 8ch (clone Saleae/DSLogic) | Sniff UART, decode protokol | PulseView 0.5.x cukup |
| CH341A + adapter 1.8V + klip Pomona SOIC8 | SPI flash dump | CH341A default 3.3V — cek tegangan chip! |
| FT232H / Bus Pirate v3.6 | SPI/UART in-circuit, bitbang | Bus Pirate µPython mode post-2022 firmware |
| JTAGulator | Brute-force pinout JTAG/SWD | Hemat waktu vs tebak header |
| FTDI FT230X/TinyCAD + stetoskop/FLIR tumbler 3B+ adapter | — | Multimeter wajib |

```bash
sudo apt install sigrok pulseview openocd flashrom picocom python3-pip
pip install unblob
# binwalk modern v3 (unblob backend); v2 dari apt sudah deprecated untuk extraction
```

---

## 1. Identifikasi UART

### 1.1 Mencari pinout
Kandidat: 4 pad sejajar (TX/RX/GND/VCC), silkscreen `J1`, `CON`, `DEBUG`, via berukuran lebih besar. Cari GND dulu (continuity ke shield/ground plane), lalu ukur tiap pin:

| Gejala pin | Interpretasi |
|---|---|
| Konstan 3.3V / 5V | VCC (runtime) |
| ~0V konstan | GND (verifikasi beep ke plane) |
| ~3.3V, sesekali drop saat boot | **TX target → RX analyzer** |

### 1.2 Sniff dengan logic analyzer
Sampling PulseView ≥ 1 MHz per channel, ~16 MHz keseluruhan. Rekam **saat power-on** — boot banner keluar dalam 2–5 detik pertama.

**Yang dikirim:** tidak ada (passive).
**Yang muncul:** burst aktivitas sekitar `0x0D 0x0A` — teks banner.

Tambah decoder UART di PulseView, tebak baud, atur RX channel. Salah baud = karakter acak; pulsanya seragam → hitung baud manual:

- Lebar pulsa bit terpendek = 1/baud. Contoh q= 8.68 µs → 115200.

Baud umum:

| Kelas perangkat | Baud |
|---|---|
| Router MT76xx/QCA | 115200 |
| Modem STM32/industrial | 9600/19200 |
| ESP32 (boot ROM) | 115200 |
| Somfy/HiSoC/Cortex-A STB | 1500000 (jangan подключ分析仪 жалгат) 115200/1500000 |
| ONT GPON ZTE/Huawei | 115200 |

Perangkat di shell kubectl idle dasar-band, jangan idle logic test.

### 1.3 Interaksi serial

```bash
sudo picocom -b 115200 /dev/ttyUSB0
# keluar: Ctrl-A Ctrl-X
```

**Yang dikirim:** enter berkali saat boot; atau Ctrl-C dalam window `1-2s` saat `Hit any key to stop autoboot`.
**Yang muncul:** prompt U-Boot (` великийA U-Boot>`, `AR7161 #`) atau Linux shell.

Payload U-Boot standar:

```
printenv                        # dump seluruh env, cari baudrate/serverip
bootdelay                       # kenaikan autoboot window
setenv bootargs console=ttyS0,115200 init=/bin/sh root=/dev/mtdblockX   # rootfs tanpa init
boot
# atau oracle dump via serial memang лектор mungkin tak perlu network:
md.b 0x80002000 0x1000          # dump via command-line ke terminal H/F
```

Kenapa berhasil: U-Boot/Bootloader sering `CONFIG_DISABLE_CONSOLE=n` dan `bootdelay>0`.
Kenapa gagal: kernel `console=` salah tty (output mati setelah kernel start — output bootloader tetap terlihat), logic level 1.8V vs USB-UART 3.3V, atau `bootdelay=0` genap (patch vendor umum di ONT ISP).

---

## 2. JTAG (OpenOCD)

### 2.1 Identifikasi
Header 10–20 pin, label `TCK/TMS/TDI/TDO/TRST`, atau pad test-point 5+ berkelompok. Samakan arah GND dan satu pin tahan tegangan konstan (idle-high TMS, clock-low waktu istirahat). Kalau pin tak berlabel: JTAGulator brute-force semua kombinasi 4-pin dalam <1 menit.

OpenOCD target harus cocok dengan SoC:

| SoC | Config OpenOCD (v0.12.0+) |
|---|---|
| MT7621 (Mir4/AirMax/Ubiquiti era 2018+) | `target/mt7621.cfg` via custom cfg (OpenOCD 0.12 + patch) |
| Atheros AR9343 (router Qualcomm Atheros) | `target/atheros_ar9340.cfg` (IR custom ada di README OpenOCD issue #411) |
| STM32/hiFiBerry/kamera CP2102 | `target/stm32f1x.cfg` |

```bash
# contoh MT7621:
cat > stm32_install.cfg <<EOF
adapter driver ftdi
ftdi device_desc "FT232H"
ftdi vid_pid 0x0403 0x6014
ftdi layout_init 0x0088 0x008b
transport select jtag
adapter speed 1000
set _CHIPNAME mt7621
jtag newtap \$_CHIPNAME cpu -irlen 5 -expected-id 0x03637001
set _TARGETNAME \$_CHIPNAME.cpu
target create \$_TARGETNAME mips_mips64 -chain-position \$_CHIPNAME.cpu
EOF
sudo openocd -f mt7621.cfg
# connects to port 3333 telnet via:
telnet localhost 4444
```

Perintah telnet OpenOCD untuk mendapatkan akses:

```
> reset halt
> mww 0xB800000 ... (konfigur register per kartu)
> mdw 0x80010000 32        # baca RAM
> flash banks              # hmm — target MIPS perlu proxy
> dump_image spi_via_cpu.bin 0x9D000000 0x1000000   # address-mapped flash di KSEG1
```

Kenapa berhasil: JTAG scan-chain tidak diburn SRST pin kegagkan pada router bootloader mode (harus jadi kasus `openocd` with `reset_config none` jika tidak ada `trst`/`srst` — halus dengan `reset` peragas via `halts` setelah kernel actives).
Kenapa gagal: BLock `reset halt` saat SoC shooting aktif Anda perlu reset papan (power ciclo/manual); `expected-id` tidak cocok (patch IR length per datasheet); OpenOCD 0.12 tanpa patch tidak support ar9343 eJTAG > 2.0 (gunakan `ejtag_srst` patch).

OpenOCD dipakai untuk VM introspection/`reset halt` — untuk dev board ESP32/RT5350/sering ada `flashrom` route lebih reliable (bab 3).

---

## 3. SPI Flash Dump

### 3.1 Identifikasi chip

Baca topmarking chip SOP8 ( NOR umum 1–32 MB):

| Marking | Chip | Size | Voltage |
|---|---|---|---|
| W25Q128JV | Winbond | 16 MB | 3.3V |
| W25Q64FV | Winbond | 8 MB | 3.3V |
| MX25L1606E | Macronix | 2 MB | 3.3V |
| GD25Q128 | GigaDevice | 16 MB | 3.3V |
| EN25QH64A | EON | 8 MB | 3.3V |
| MT25QL128 (NAND, bukan NOR) | Micron | — | pakai flashrom bb_spi |

Pinout SOP8 NOR (view dari atas, notch pin 1):

```
      ┌───∪───┐
 /CS ─┤1    8├─ VCC
  DO ─┤2    7├─ /HOLD (bisa jadiRESET)
 /WP ─┤3    6├─ CLK
 GND ─┤4    5├─ DI
      └──────┘
```

### 3.2 Dump dengan CH341A + flashrom

Dengan klip SOIC8 ke chip (perangkat mati / baterai dilepas), atau lepas chip:

```bash
sudo flashrom -p ch341a_spi:r     # ops: read; identify
sudo flashrom -p ch341a_spi -r dump1.bin
sudo flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin   # harus identik; kalau beda → tambat/noise → cek kabel
```

**Yang dikirim:** flashrom mengirim `0x9F` (JEDEC ID), lalu read command `0x03` per byte page.
**Yang muncul:** `Found Winbond flash chip "

## [lanjutan]

## 3.6 Sub-topik Lanjutan Hardware Hacking

### 3.6.1 Identifikasi UART pada Perangkat Tanpa Header Jelas

Banyak perangkat produksi massal tidak menyediakan header UART eksplisit. Pendekatan lanjutan:

**Metode visual dan kontinuitas**

1. Cari 4 pad/berlubang (via) sejajar dekat TX chip (MTK, Realtek, Qualcomm).
2. Multimeter mode kontinuitas: pin yang tersambung ke GND, pin dengan ~3.3V stabil (VCC), dua pin tersisa (TX/RX).
3. Ukur tegangan idle: TX pegang logika tinggi (~3.3V), RX biasanya rendah/mengambang.

**Tabel kontinuitas tipikal**

| Pin | Ciri |
|---|---|
| GND | Beep ke casing/pad ground besar |
| VCC | 3.3V tetap saat boot |
| TX | 3.3V idle, turun saat boot (burst data) |
| RX | 0V atau mengambang |

**Menangkap baud tanpa tebak-tebakan**

Logic analyzer + PulseView/DSView, dekode protokol UART otomatis:

```
# PulseView: klik decoder UART, run pada saat boot device
# Alternatif: retdec UART quess / brute-force dengan script python serial
```

Baud rate tidak baku? Beberapa vendor:

| Vendor | Baud umum |
|---|---|
| Ubiquiti | 115200 |
| Xiaomi | 115200 |
| TP-Link | 115200, sesekali 57600 |
| Huawei | 115200 |
| IoT Zigbee (TI CC2530) | 115200 tapi 8N1 dengan header biner |
| Modem GSM Quectel | 115200 (AT di console) |

Jebakan: beberapa chip menggunakan **921600**, 250000 (debug ESP8266/ESP32 ROM), 74880 (boot ROM ESP8266). Divider clock tidak selalu menghasilkan baud standar.

### 3.6.2 JTAG: Pinout Non-Standar dan Proteksi

- **OpenOCD** config tipikal, contoh chip populer:

```
# /usr/share/openocd/scripts/target/stm32f1x.cfg
openocd -f interface/stlink.cfg -f target/stm32f1x.cfg
openocd -f interface/jlink.cfg -c "transport select jtag" -f target/atheros_ar9331.cfg
```

- **Chip kustom (Broadcom/Qualcomm Router)** sering menyembunyikan JTAG; TCK/TMS/TDO/TDI terdeteksi via JTAGulator atau JTAGenum (Arduino):

```
# JTAGulator
python3 jtagulator.py  # brute-force pin mapping per pin
```

- **Edge case terbaru**: banyak SoC IoT beralih ke **SWD** (2 pin) — gunakan `interface/cmsis-dap.cfg`; JTAG out-of-the-box tidak bekerja.

Jebakan operasional JTAG:

- Register IR lebih dari 8 bit (misal 12 bit Xilinx) — gagal deteksi bila `IR length` salah di config OpenOCD.
- Ada fuse **JTAG disable irreversible** (efuse pada Qualcomm/MediaTek) — cek datasheet sebelum probing agresif.
- RST/timing: jalankan `reset halt` sebelum read flash agar CPU tidak menimpa memori.

### 3.6.3 SPI Flash Dump — Mode Lanjutan

**CH341A edge case**

- Tegangan default 3.3V — cek modul "CH341A 1.8V fix" untuk flash NAND P/popper modern (MacBook, beberapa Winbond 1.8V series W25QxxxxFW).
- Flash 1.8V/0.9V (misal Winbond W25M) butuh adaptor level shifter, bukan sambung langsung.

**Dua chip / dual-die (stacked)**

- Chip dengan stack die (W25M512JV) — gunakan `flashrom --die 0` / `--die 1`.
- Perintah dump:

```
flashrom -p ch341a_spi -r backup1.bin --die 0
flashrom --chip W25M512JV -r dump.bin --die 1
```

**Konsistensi dump**

- Selalu dump 2x dan `diff`; jika berbeda kemungkinan chip terlalu lambat atau kabel noise:
  - Kurangi kecepatan SPI (`spispeed` di rasPi:

```
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=2000 -r dump.bin
```

**Flash belum dikenali**

- Coba `flashrom --flash-name` atau `-c <nama manual>` bila ID JEDEC beda bit.
- Untuk NOR klone China (SFDP tidak valid), pakai `-c` dengan profil chip terdekat — risiko erasing salah.

**Dump **in-circuit** (tanpa solder lepas)**

- Pastikan MCU tidak menggiring bus SPI; opsi:
  - Tahan MCU di reset (tahan NRST low).
  - Putus jalur CS (IR dropdown, potong jumper).
  - Gunakan "Spike` clip kecil" SOIC8/SOP16/WSON8.

**Edge case**: WSON8 dan VQFP memory pakai probe kit `Pomona 5250` ke bawah; tidak semua clip menepu pada package tanpa lead.

**Polaris `espressif` dan `xtensa` build** (QEMU fork ESP):

```
make chip=esp8266 || qemu-system-xtensa -M esp8266 -kernel dump.bin
```

### 3.6.4 Firmware Extraction — Binwalk & Unblob Deep Dive

**Binwalk v3 (jamin)**

```
binwalk -Me firmware.bin          # extraction rekursif
binwalk -A firmware.bin          # signature scan
binwalk --entropy firmware.bin   # deteksi terenkripsi/compressed
```

- **Konten CramFS/SquashFS**: binwalk ekstrak akan mem-mount filesystem - sekitar daftar kernel:
  - `squashfs-root/` | binwalk akan list `LZMA`, `gzip`, `SQUASHFS`.
- Kalau gagal, gunakan `sasquatch` (untuk versi squashfs non-standar — DD-WRT, vendor custom):
  - `unsquashfs -d outdir squashfs-root/squashfs.bin`

**Unblob** (pengganti modern binwalk untuk firmware besar)

```
unblob extract firmware.bin
unblob -e /tmp/out -v firmware.bin
```

- Kelebihan: deteksi entropy + exFAT, UBI, CPIO terbaru, multi-thread parallel.
- UBI/UBIFS: `ubireader_extract_files` (dari package `ubi_reader`).
- Filesystem singularity modern: JFFS2 perlu `jefferson` (Python):

```
jefferson jffs2.img -d output/
```

**Firmware Terenkripsi (uang banyak vendor)**

- `binwalk --entropy` menunjukkan flat ~1.0 entropy sejak awal file → kemungkinan header terenkripsi.
- Cari string "AES" atau key di firmware unit sejenis versi lebih lama; beberapa key telah di-publikasikan di repositori `firmware-mod-kit`, `fwtool`, dan `IoTFirmwareKeyDumps`.
- Alternatif hardware: dump flash → jalankan binary image **via UART uboot** → dump RAM untuk decrypt key di runtime.

**UBI dump dari flash - mounting loop:**

```
ubinize /dev/mtd0 -o ubi.img  # tidak: use nanddump untuk full
nanddump -f nand.bin /dev/mtd0
ubireader_extract_files nand.bin
```

### 3.6.5 Emulasi — FirmAE, Firmadyo, QEMU

**Matriks emulasi**

| Tool | Kecepatan penyiapan | Dukungan router | Fitur khusus |
|---|---|---|---|
| FirmAE | Oke, otomatis 30+ brand | Bagus | ` FirmAE/init.py` assess + run |
| Firmadyo (asal) | Lambat, manual | Sedang | Penuh network sim |
| QEMU user-mode | Cepat per-binary | - | Emulasi binary tunggal `qemu-arm-static ./busybox` |
| QEMU full-system | Manual | - | Debug `-d in_asm -kernel zimage` |

**Perintah tipikal FirmAE**

```
./init.sh
./scratch 2 <vendor> <firmware.bin>   # mode assess
./scratch 1 <vendor> <firmware.bin>   # mode run full
```

Jebakan: **FirmAE Mac M1** gagal compile karena klean butuh `afl` flag波澜; gunakan Intel x86 docker image `firmae:latest`.

**QEMU per-arsitektur**

```
qemu-system-arm -M vexpress-a9 -kernel zImage -dtb vexpress-v2p-ca9.dtb \
     -drive file=rootfs.ext2,if=sd -append "root=/dev/mmcblk0"
```

**Debug edge**:

- QEMU gagal boot karena `drivers/spi` atau `PHY` chip tidak ada — kernel panic `VFS unable to mount root` → cek `root=`, `console=ttyS0`.
- MIPS-BE vs MIPS-LE: salah endianness menyebabkan `Bad Ramirez` — binwalk `E`ELF header check terlebih dahulu.
- Network QEMU: gunakan perintah `-netdev user,id=net0,hostfwd=tcp::80-:80` dan cek via `nmap` internal `10.0.2.2`.

**Debug MIPS kernel via qemu** (untuk zero-day kernel IoT):

```
qemu-system-mips -M malta -kernel vmlinux -hda rootfs.img \
   -append "root=/dev/sda1 console=ttyS0" -nographic -netdev user,id=n1
```

**Emulasi single binary (Non-root perkakas)**

- `firmadyne` penuh vs `qemu-arm-static` untuk fuzzing klien tunggal — ekstrak `usr/bin/httpd`, helper `LD_LIBRARY_PATH`:

```
sudo chroot . /usr/bin/qemu-mips-static ./usr/sbin/httpd
```

Jebakan umum: `/etc/init.d/rcS` script memanggil device-specific daemon, tidak berjalan di QEMU (tanpa `/dev/gpio`) — stub manual atau patch strace.

### 3.6.6 Perangkat Fisik dan Alat Pengukuran

**Tabel alat**

| Kebutuhan | Alat | Catatan |
|---|---|---|
| Dapat SPI 8-SOIC | CH341A + Pomona 5250 | ~5 USD, populer |
| Logic analyzer | Saleae Logic 8, DSLogic Plus | 16 channel cukup untuk SPI+UART |
| JTAG/SWD | J-Link, ST-Link v2, FTDI (OpenOCD) | ST-Link murah untuk ARM Cortex |
| Oscilloscope | Rigol DS1054Z | analisis rise-time SPI clock |
| UART USB adapter | FT232H / CP2102 | 3.3V/1.8V switchable |
| Hot air rework | Quick 861DW | untuk WSON/QFN flash chip |

**Tabel kerentanan FPGA** – ZYNQ: `xc3sprog` (Xilinx) via JTAG untuk dump bitstream:

```
xc3sprog -c jtaghs1 bitstream.bit
```

### 3.6.7 Proses Analisis Perangkat Nyata

**Contoh walkthrough TP-Link Archer C7:**

1. Buka casing, lihat UART melalui pad J3 (tanpa header) - solder.
2. `screen /dev/ttyUSB0 115200` - dapat shell busybox level user.
3. UART hanya user shell; untuk root, dump SPI dengan CH341A:
   - `flashrom -p ch341a_spi -r backup.bin --chip MX25L6406E`
4. `binwalk -Me backup.bin`, buka `/etc/shadow` → crack hash:
   - `hashcat -m 500 hash.txt wordlist`
5. `FirmAE scratch 2 tplink archer-c7-firmware.bin` → nmap full router:
   - hasil: web admin siap difuzz dengan `ffuf`.

**Contoh IoT Zigbee (TI CC2538):**

- Debug via JTAG `openocd -c "adapter driver linux_spi"` + `cc2538.cfg`.

### 3.6.8 Jebakan Operasional & Kesalahan Umum

- **Tegangan flash** — jangan asumsi 3.3V; cek datasheet sebelum dump.
- **Half pint (trace tebal)** mengakibatkan read gagal intermiten, SDM wave: kurangi spispeed.
- CH341A **menyediakan 5V** di versi lama — bisa merusak flash 3.3V; gunakan modul regulator atau versi baru.
- FlashROM dan **SPI bus in-circuit dengan pull-up lemah**: pertimbangkan `SPI` pin `WP#/HOLD#` di-tambah `flyback` diode dalam beberapa board modem.
- UART **serial console dua kabel** (tanpa GND bersama) menyebabkan garbage→ pastikan ground lang antara USB adapter dan perangkat.
- `binwalk -Me` pada firmware terenkripsi bisa membuat ribuan file sampah — **selalu konten entropy dulu**.
- OpenOCD gagal "target not halted" pada chip yang menggabungkan **two die** (misal nRF52840) — gunakan `nrf51.cpu` / `nrf52.cpu cmake single` tap config.
- Saat re-flashing flash hasil temuan vendor, ** tandai biner lama** sebagai backup karena sebagian vendor menyimpan data kalibrasi (MAC, calibration) di blok data bukan firmware main.

### 3.6.9 Terminologi & Panduan Lab Setup

- Keran alat: multiplexer UART - kalau menguji 5+ perangkat: [pipert 3 port ].(itorial)
- Isolasi USB (isolator) untuk perangkat dengan ground loop (PoE router, dimmer high-side).
- Lab notebook — catat tiap dump MD5:
  `md5sum backup.bin` termasuk ringkas alat dan `flashrom version` — auditabilitas dan perbandingan sesudahnya.

---

## Daftar perintah cheat sheet

```
# UART
sudo screen /dev/ttyUSB0 115200 8N1

# SPI
flashrom --flash-name
flashrom -p ch341a_spi -r dump.bin
flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r d.bin
flashrom -p ch341a_spi --die 0 -r d0.bin

# JTAG
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg
telnet localhost 4444

# Ekstraksi
binwalk -Me fw.bin
unblob extract fw.bin
sasquatch sqfs.bin
jefferson jffs2.bin

# Emulasi
qemu-arm-static ./binary
./scratch 1 tplink fw.bin   # FirmAE
```

Bab ini menutup aspek hardware hacking lanjutan — identifikasi manual UART, proteksi JTAG/efuse, dump SPI non-standar, firmware terkompresi/terenkripsi, dan strategi emulasi — sebagai fondasi audit keamanan perangkat IoT tertanam.

---

## [reasoning trace]


