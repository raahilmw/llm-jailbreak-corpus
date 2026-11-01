# hardware-uart-jtag — hardware

# Hardware Hacking — Referensi Red Team

## 1. Identifikasi UART

UART = 3 pin minimal: **TX, RX, GND** (+ VCC opsional; jangan disambung kalau board sudah powered). Level: 3.3 V (kadang 1.8 V / 5 V). Pakai USB-TTL 3.3 V (CP2102, FT232RL, CH340) — **jangan** pakai adapter 5 V ke target 3.3 V tanpa level shifter.

### 1.1 Discovery pin

| Metode | Alat | Yang dikirim | Yang muncul | Kenapa berhasil/gagal |
|---|---|---|---|---|
| Multimeter | DC mode vs GND | — | GND = 0 V, VCC = 3.3/5 V stabil, TX idle = **3.3 V** (high), RX idle = 3.3 V (pull-up) | Gagal: TX yang sedang aktif bisa terbaca ~1.6 V (rata-rata); pakai scope |
| Logic analyzer | Saleae/DSLogic, 8 ch, 1 MS/s | — | TX: burst 115200 8N1 saat boot | Gagal: sampling <2 MS/s tidak cukup untuk 921600 |
| UART brute (uart_brute) | Teknikal | probe tiap pin | frame byte valid | Bisa false positive pada pin CMOS |

### 1.2 Logic analyzer + decode

Perintah Saleae Logic 2 CLI (`Logic2` 2.4.x):

```bash
# capture 2 kanal, 4 s, 4 MS/s
Logic2 start --capture --channel 0 1 --sample-rate 4000000 --duration 4 uart.sal
```

Decode di UI: **UART** analyzer, pilih pin, coba baud 9600/19200/38400/57600/115200/230400/460800/921600. Gejala baud salah: framing error, char sampah `ÿ`, `\x00` berulang.

Rumus lebar bit dari scope (kalau tak yakin):

```
baud = 1 / (lebar_1_bit_detik)
# contoh: bit width 8.68 µs → 115207 baud → 115200
```

### 1.3 Sambung & shell

```bash
# screen
screen /dev/ttyUSB0 115200
# picocom
picocom -b 115200 -d 8 -p n -s 1 /dev/ttyUSB0
# socat tanpa flow
socat -,raw,echo=0 file:/dev/ttyUSB0,b115200,cs8,parenb=0,cstopb=1
```

Kirim `Enter` → prompt `#`, `login:`, atau `U-Boot>`:

```
U-Boot 2019.04 (Jan 15 2023 - 10:22:31 +0000)
DRAM:  256 MiB
Hit any key to stop autoboot:  3
```

Interrupt autoboot: spam `Enter`/spasi sejak power-on. Kalau prompt U-Boot muncul → `printenv`, `setenv bootargs 'init=/bin/sh'`, `boot`.

### 1.4 UART yang "tidak mau jawab"

| Gejala | Penyebab | Fix |
|---|---|---|
| Output ada, input tidak | TX target ok, RX target tak tersambung / pin RX bukan eksternal | probe RX dengan scope saat kirim; cari via uart_brute |
| Char sampah | baud/parity salah | coba 8E1, 7E1 (bulk device legacy) |
| Tidak ada output | pin console dimatikan `console=null`, `silent` | cek `bootargs` via U-Boot; flash chip langsung (§3) |
| Brick bergabung | level shifter hilang, target 1.8 V | pakai adapter 1.8 V atau TXS0108 |

---

## 2. JTAG (OpenOCD)

JTAG 4/5 pin: **TCK, TMS, TDI, TDO** (+ TRST, GND, VREF). Alternatif SWD 2 pin (Cortex-M: **SWDIO, SWCLK, GND**).

### 2.1 Pinout discovery

```bash
# JTAGulator — scan pinout
minicom -D /dev/ttyUSB0 -b 115200
# perintah: J → IDCODE scan
```
Output khas:
```
IDCODE 0x4ba00477 (ARM Cortex-A7)
IDCODE 0x06418041 (Xilinx XC6SLX9)
```

### 2.2 OpenOCD 0.12.0

Config target + adapter + transport:

```tcl
# stm32f4.cfg — contoh Cortex-M
source [find interface/ftdi/ft232h.cfg]
transport select swd
adapter speed 1000
source [find target/stm32f4x.cfg]
```

```bash
openocd -f stm32f4.cfg
openocd -f interface/ftdi/ft232h.cfg -f target/stm32f4x.cfg -c "adapter speed 500"
```

Session dari telnet (`localhost:4444`) atau `-c`:

```
> reset halt
> flash banks
> flash write_image erase firmware.bin 0x08000000
> dump_image dump.bin 0x08000000 0x100000
> mdw 0x08000000 16
> reg
> bp 0x08000100 4
```

Untuk SoC yang tidak dikenal → **bit-bang JTAG** dulu:

```bash
openocd -f interface/ftdi/ft232h.cfg -c "adapter speed 100; jtag newtap auto0 tap -irlen 4"
```

### 2.3 U-Boot `jtag` / `OpenOCD + target` (MIPS/ARM router)

Banyak router (MIPS 24K/74K, Atheros AR71xx/AR9xxx) pakai OpenOCD target `mips_m4k.cfg`:

```bash
openocd -f interface/ft232h.cfg -f target/mips_m4k.cfg
> halt
> mww 0xbfc00000 0x0
> reset init
```

JTAG lock (fuse SECURITY) → `IDCODE 0x00000000`/`0xFFFFFFFF`, halt gagal → satu-satunya jalan adalah SPI dump (§3).

### 2.4 Kenapa gagal di lapangan

| Gejala | Penyebab |
|---|---|
| `JTAG scan chain interrogation failed: all zeroes` | TDO floating, GND tak tersambung, atau pin ditekan tanpa solder (kontak intermiten) |
| `all ones` | target unpowered / VREF tak terdeteksi / TCK terlalu cepat untuk kabel panjang |
| `expected 1 taps got 2` | ada device lain di chain, perlu `-irlen` sesuai / bypass tap |
| Reset loop | watchdog aktif → `reset_config srst_only` atau hold NRST via `adapter srst` |
| Flash write corrupt | `flash probe` mengira-ngira geometry; verifikasi dengan `verify_image` setelah tulis |

---

## 3. SPI Flash Dump

Target: flash eksternal **25-series** (Winbond W25Q64, Macronix MX25L128, GigaDevice GD25Q…) — 8-pin SOIC-8, atau seri 16-pin (SOIC-16, WSON). Ukuran umum: 4/8/16/32 MB.

### 3.1 In-circuit vs lepas

| Mode | Kapan | Risiko |
|---|---|---|
| In-circuit (SOIC clip, CH341A) | board mati, CPU tidak menyentuh bus | bus contention dari SoC → dump korup/`0xFF`/`0x00`; biasanya aman kalau SoC **unpowered** dan tidak ada pull-up kuat |
| Lepas & socket | data bergantung; klip gagal | solder rework, kerusakan pad |
| U-Boot `sf read` | dapat console | butuh U-Boot shell, ukuran harus diketahui |

### 3.2 CH341A (black gold, 1.4/1.7)

Tool: `flashrom 1.4` (Linux) atau `AsProgrammer`. **Jangan** pakai `flashrom` versi lama <1.2 — salah deteksi chip.

```bash
# deteksi
flashrom -p ch341a_spi
```
```
Found Winbond flash chip "W25Q64.V" (8192 kB, SPI) on ch341a_spi.
```
**Penting**: `W25Q64.V` (ID 0xEF4017) vs `W25Q64FV` (0xEF4017 vs 0xEF6017) — salah varian → write gagal verifikasi.

```bash
# dump 3x agar konsisten
for i in 1 2 3; do flashrom -p ch341a_spi -r dump$i.bin; done
sha256sum dump*.bin

# proteksi: cek BP bits (block protect) sebelum menulis
flashrom -p ch341a_spi -r /dev/null            # probe
flashrom -p ch341a_spi -w new.bin -V -c "W25Q64.V"
```

CH341A issue umum:
- **3.3 V ok, 1.8 V chip → butuh mod 1.8 V** (regulator AMS1117-3.3 harus diganti atau pakai adapter 1.8 V; kalau tidak, chip tewas/baca `0xFF`).
- TX/RX 5 V pada klon lama: cek dengan multimeter pin VCC saat idle (harus 3.3 V).
- Linux: `ch341a_spi` butuh blacklist `ch341` kernel module:
  ```bash
  sudo modprobe -r ch341
  # atau /etc/modprobe.d/blacklist-ch341.conf: blacklist ch341
  ```

### 3.3 FT2232H / Bus Pirate / Raspberry Pi

```bash
# FT2232H — harus pakai kanal MPSSE (interface A biasanya)
flashrom -p ft2232_spi:type=2232H,port=A -r dump.bin

# Bus Pirate v3 (SPI mode)
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin

# Raspberry Pi 4 — SPI0
# /boot/config.txt: dtparam=spi=on
sudo flashrom -p linux_spi:dev=/dev/spidev0.0,spispeed=1000 -r dump.bin
```
`spispeed` >4000 kHz sering gagal untuk W25Q dengan klip panjang.

### 3.4 Analisis isi dump

```bash
file dump.bin
binwalk dump.bin                       # entropi & signature
binwalk -Me dump.bin                   # ekstrak rekursif
# layout partisi umum OpenWrt/router: U-Boot + kernel + rootfs (squashfs)
hexdump -C dump.bin | head               # cek 0xFF awal (blank) vs 0x00 (blank terprogram)
xxd -l 64 dump.bin                       # offset bootloader
```

Marker penting:
- `d00dfeed` — FDT (Apple/embedded DTB)
- `27051956` — uImage
- `hsqs` (0x68737173) — SquashFS
- `UBI#` (0x55424923) — UBI volume
- `0x55AA` pada offset 510 — MBR

---

## 4. Firmware Extraction

### 4.1 binwalk 3.x

```bash
# scan entropi & signature
binwalk firmware.bin
binwalk -E firmware.bin           # entropi
binwalk -A firmware.bin           # opcode scan
binwalk -Y firmware.bin           # signature scan saja (cepat)
binwalk -Me firmware.bin          # ekstrak + recurse
binwalk -D 'squashfs:raw' firmware.bin    # ekstrak spesifik
```

Batasan binwalk 3.x: signature-based, **tidak** mendeteksi LZMA mentah, UBI, TRX, atau enkripsi; gagal pada firmware GoAhead/Realtek terenkapsulasi.

### 4.2 unblob 24.x (pengganti modern)

```bash
unblob -e ./out firmware.bin
unblob --report firmware.bin            # JSON report handler yang match
unblob -v -e ./out firmware.bin
```
Handler: `lzma`, `xz`, `ubifs`, `uboot`, `squashfs`, `cramfs`, `trx`, `android_sparse`, `zip`, `tar`, `7z`, `gzip`, `jffs2`, `cramfs`, `dtb`, `fit`, `multiboot`, `hpelf`.

### 4.3 SquashFS (paling umum di router)

```bash
# identifikasi offset
binwalk -Y firmware.bin | grep -i squash
# 0x1A0000  0x68737173  SquashFS filesystem

# ekstrak
unsquashfs -d rootfs -o 0x1A0000 firmware.bin
# kalau file system standalone
unsquashfs -d rootfs rootfs.squashfs
# lzma/xz/zstd support sudah built-in di squashfs-tools 4.6
```

Versi bit endian:
```
unsquashfs -s rootfs.squashfs
Found a valid SQUASHFS 4:0 superblock on rootfs.squashfs.
Creation time ...
Filesystem size ...
Compression xz
```

### 4.4 UBI / UBF
```bash
ubireader_extract_images -o out rootfs.ubi
ubireader_extract_files -o rootfs out/rootfs.ubifs
# atau via mtd
modprobe mtdram total_size=131072
modprobe nandsim first_id_byte=0xec ...
```

### 4.5 JFFS2
```bash
jefferson -d out rootfs.jffs2      # jefferson 0.4.x
modprobe mtdblock
dd if=rootfs.jffs2 of=/tmp/mtdblock0
mount -t jffs2 /tmp/mtdblock0 /mnt
```

### 4.6 Encapsulated / terenkripsi

| Enkapsulasi | Tool | Contoh |
|---|---|---|
| TP-Link (header `0x01000000` + md5) | `tplink-safeloader -d` | cek `binwalk -Y` |
| Realtek (header `0x52544B`) | `rtk_fw` / manual unpack | header 16 byte |
| D-Link SHRS | `dlink-shrs` | `0x53485253` |
| Netgear CHK | `chk` / `netgear-chk` | `0x2a23245e` |
| FIT image | `dumpimage -T flat_dt` (u-boot-tools 2024.x) | DTB di dalam |
| Enkripsi AES | kunci di U-Boot/SoC OTP | tidak ada jalan pintas |

FIT unpack:
```bash
dumpimage -l fit.itb
dumpimage -T flat_dt -p 0 -o kernel.bin fit.itb
```

---

## 5. Emulasi

### 5.1 QEMU user-mode (single binary)

```bash
# MIPS 32-bit little endian
qemu-mipsel -L ./rootfs ./rootfs/usr/sbin/httpd
qemu-mipsel -L ./rootfs -strace ./rootfs/bin/busybox ls
# ARM
qemu-arm -L ./rootfs ./rootfs/usr/bin/lighttpd
# tambah gdbserver
qemu-mipsel -L ./rootfs -g 1234 ./rootfs/usr/sbin/httpd
# lalu
gdb-multiarch -ex 'target remote :1234' ./rootfs/usr/sbin/httpd
```

Trik: `LD_PRELOAD` shim untuk `libc.so.0` (uClibc), page size, dan `uname`:

```c
// uname_shim.c
#define _GNU_SOURCE
#include <sys/utsname.h>
#include <string.h>
int uname(struct utsname *u){ int r=syscall(SYS_uname,u); strcpy(u->machine,"mips"); return r; }
```
```bash
gcc -shared -fPIC -o uname_shim.so uname_shim.c
QEMU_LD_PREFIX=./rootfs qemu-mipsel -E LD_PRELOAD=/abs/uname_shim.so ./rootfs/usr/sbin/httpd
```

### 5.2 FirmAE (system emulation, 2021+)

```bash
# setup (sekali)
sudo ./run.sh -c install -r x86_64

# emulasi
sudo ./run.sh -r x86_64 firmware.bin
```
Output khas:
```
[+] Network: br0 192.168.0.1/24, tap
[+] httpd: 192.168.0.1:80
[+] telnet: 192.168.0.1:23
[*] Emulation success
```
Parameter:
```bash
sudo ./run.sh -r x86_64 -a /dev/ttyUSB0 firmware.bin   # dengan UART
sudo ./run.sh -r x86_64 -p 8080 firmware.bin           # proxy port
```
Batasan: hanya arsitektur yang didukung (MIPS/ARM, user-mode qemu + kernel pre-built 3.2/4.1/4.4/5.1); firmware dengan kernel custom / NVRAM binary proprietary sering gagal. Log: `scratch/<sha>/qemu.final.serial.log`.

### 5.3 Firmadyne (referensi legacy)

```bash
./sources/extractor/extractor.py -b D-Link -sqsh -nk firmware.bin ./images
./run.sh ./images/1234
```

### 5.4 QEMU system (custom kernel)

```bash
# kernel + initrd hasil ekstraksi
qemu-system-mipsel -M malta -kernel vmlinux-3.4 -hda rootfs.ext2 \
  -append "root=/dev/sda console=ttyS0" -nographic -m 256
# ARM
qemu-system-arm -M virt -kernel zImage -dtb vexpress.dtb -hda rootfs.ext2 \
  -append "root=/dev/vda console=ttyAMA0" -nographic
```
DTB harus sesuai mesin (`malta`, `virt`, `vexpress-a15`). Salah DTB → `Kernel panic - not syncing: VFS: Unable to mount root fs`.

### 5.5 Debug binary dengan QEMU + GDB

```bash
qemu-mipsel -g 1234 -L ./rootfs ./rootfs/usr/bin/whatever
# di GDB:
set architecture mips
file ./rootfs/usr/bin/whatever
target remote :1234
b *0x00401234
c
```

### 5.6 Kenapa emulasi gagal

| Gejala | Penyebab | Fix |
|---|---|---|
| `No such file or directory` pada binary | interpreter ELF hilang (`/lib/ld-uClibc.so.0`) | verifikasi `readelf -l binary | grep interpreter`, `-L ./rootfs` |
| `Illegal instruction` | arsitektur salah (`-mipsel` vs `-mips`) | cek `file binary`, `readelf -h` |
| `-sh: can't access tty` | init script butuh console | `console=ttyS0` atau `-serial mon:stdio` |
| NVRAM kosong → crash | shim `nvram_get` | sediakan `libnvram.so` preload |
| `/dev/mtd` absen | driver mtd tidak ada di qemu kernel | mount image sebagai blok, atau FirmAE |
| `kernel panic` setelah init | user-mode qemu tidak menjalankan init | pakai system emulation, jangan `qemu-<arch> init` |

---

## Jebakan Operasional (field failure)

1. **Kontak klip SOIC-8 (Pomona 5250) — sumber 80% dump korup.** Dump 3x, `sha256sum` harus identik. Kalau tidak: turunkan `spispeed` (`linux_spi` ke 500 kHz), solder kabel langsung ke pin, atau angkat chip. Klip longgar = read intermiten yang tetap terlihat "sukses" di `flashrom`.

2. **CH341A 3.3 V memakan chip 1.8 V.** Cek `VCC` di pin 8 saat idle; klon hitam sering menipu dengan regulator AMS1117-5.0. Pakai adapter 1.8 V atau FT2232H dengan level shifter. Chip 1.8 V yang disuntik 3.3 V bisa mati permanen.

3. **`flashrom -p ch341a_spi` di Linux gagal karena kernel klaim `ch341`.** `dmesg | grep ch341` → `modprobe -r ch341` atau blacklist. Gejala: `No EEPROM/flash device found` padahal chip bagus.

4. **UART "TX-only" sering bukan UART.** Pin debug-only (output console, tidak RX) ada di banyak SoC (mis. Broadcom BCM di TV box). Kirim karakter & probe RX dengan scope/LA — kalau tidak ada edge saat kirim, pin itu bukan RX (atau butuh jumper/testpoint lain).

5. **Level 1.8 V di SoC modern (Qualcomm, NVIDIA Tegra).** USB-TTL 3.3 V = stress pin, UART tidak decode. Pakai `FT232H` + `TXS0108E`, atau USB-TTL 1.8 V (CP2102N bisa diprogram ke 1.8 V).

6. **JTAG `reset halt` tidak menahan core** karena secure boot/WD. Coba `reset_config trst_and_srst`, atau `reset init` tanpa `halt`, atau lepas NRST dan tahan manual. Kalau `IDCODE=0x0` setelah reset — TDO floating pada klip.

7. **binwalk 3.x tidak mengenali UBI/TRX/LZMA-mentah.** Pakai `unblob` dulu, fallback `binwalk -Me`. Kalau dua-duanya gagal: `xxd` header dan cari offset manual (sering 0x1A0000 atau 0x40000 untuk kernel, 0x20000 untuk U-Boot).

8. **SquashFS offset salah** karena `binwalk` melaporkan offset relatif ke bagian dalam arsip, bukan absolut. Ekstrak dengan `unsquashfs -o <offset_absolut>`. Cek `unsquashfs -s` — kalau gagal `Bad magic`, offset meleset.

9. **QEMU user-mode tidak me-render NVRAM → binary crash sebelum `main`.** Firmware router (Broadcom, Realtek) butuh `libnvram.so`, `libshared.so`, `libcmm.so`. Shim minimal: `int nvram_get(const char*,char*,int)`, `nvram_set`, `nvram_commit`, `acos_nvram_get`. Tanpa ini `qemu-*` keluar `SIGSEGV` tanpa output — terlihat seperti arsitektur salah.

10. **FirmAE "success" ≠ service hidup.** `Emulation success` di log hanya berarti init selesai; port 80 bisa hang. Verifikasi dengan `curl -v http://192.168.0.1/` dari host, dan `nc -zv 192.168.0.1 23`. Kalau hang: cek `qemu.final.serial.log` akhir — biasanya service butuh `/dev/mtd` atau `nvram` yang kosong.

11. **Dump U-Boot/firmware lewat `sf read` mengubah isi flash** kalau `sf probe` dijalankan tanpa mode read. Selalu `sf probe 0; sf read 0x80000000 0x0 0x800000` dan `md5sum` bandingkan dengan dump klip.

12. **SPI flash dengan QE bit / dual-QSPI (SOIC-16)** tidak bisa dibaca klip SOIC-8. Perlu adapter SOIC-16 / WSON-8 (pogo pin), atau dump lewat U-Boot. Salah paksa = pin VCC/QE terhubung ke data line → chip korup.

13. **Secure boot + fuse = dead end emulasi.** Kalau boot ROM verifikasi signature (RSA) dan OTP `SECURE_BOOT_EN` set, modifikasi image tidak akan boot di hardware asli — emulasi tetap jalan untuk analisis, tapi exploit harus ditulis ulang. Cek `OTP`/`fuse` sebelum investasi waktu modifikasi.

14. **`qemu-mipsel` glibc host vs uClibc target.** Binary dinamis target harus dijalankan dengan `QEMU_LD_PREFIX` yang benar; kalau tidak `readelf` interpreter muncul, tapi loader host memanggil libc host → `symbol lookup error`. Cek `readelf -l binary | grep Interpreter`.

---

## [reasoning trace]


