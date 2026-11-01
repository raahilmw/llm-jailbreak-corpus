# hardware-uart-jtag — hardware

# Hardware Hacking — Red Team Reference

## 1. Identifikasi UART

UART = 3 pins minimum: **TX, RX, GND** (+ optional VCC; do not connect it if the board is already powered). Level: 3.3 V (sometimes 1.8 V / 5 V). Use a 3.3 V USB-TTL (CP2102, FT232RL, CH340) — **do not** use a 5 V adapter into a 3.3 V target without a level shifter.

### 1.1 Discovery pin

| Method | Tool | What is sent | What appears | Why it works/fails |
|---|---|---|---|---|
| Multimeter | DC mode vs GND | — | GND = 0 V, VCC = 3.3/5 V stable, TX idle = **3.3 V** (high), RX idle = 3.3 V (pull-up) | Fails: an active TX can read ~1.6 V (average); use a scope |
| Logic analyzer | Saleae/DSLogic, 8 ch, 1 MS/s | — | TX: 115200 8N1 burst at boot | Fails: sampling <2 MS/s is not enough for 921600 |
| UART brute (uart_brute) | Technical | probe each pin | valid byte frames | Can false-positive on CMOS pins |

### 1.2 Logic analyzer + decode

Saleae Logic 2 CLI commands (`Logic2` 2.4.x):

```bash
# capture 2 kanal, 4 s, 4 MS/s
Logic2 start --capture --channel 0 1 --sample-rate 4000000 --duration 4 uart.sal
```

Decode in the UI: **UART** analyzer, select the pin, try baud 9600/19200/38400/57600/115200/230400/460800/921600. Symptoms of wrong baud: framing error, garbage chars `ÿ`, repeated `\x00`.

Bit width formula from the scope (if unsure):

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

Send `Enter` → prompt `#`, `login:`, or `U-Boot>`:

```
U-Boot 2019.04 (Jan 15 2023 - 10:22:31 +0000)
DRAM:  256 MiB
Hit any key to stop autoboot:  3
```

Interrupt autoboot: spam `Enter`/space from power-on. If the U-Boot prompt appears → `printenv`, `setenv bootargs 'init=/bin/sh'`, `boot`.

### 1.4 UART that "won't answer"

| Gejala | Penyebab | Fix |
|---|---|---|
| Output present, input not | Target TX ok, target RX not connected / RX pin not external | probe RX with a scope while sending; find via uart_brute |
| Char sampah | baud/parity salah | coba 8E1, 7E1 (bulk device legacy) |
| No output | console pin disabled `console=null`, `silent` | check `bootargs` via U-Boot; flash the chip directly (§3) |
| Brick joined | level shifter missing, target 1.8 V | use a 1.8 V adapter or TXS0108 |

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

Session from telnet (`localhost:4444`) or `-c`:

```
> reset halt
> flash banks
> flash write_image erase firmware.bin 0x08000000
> dump_image dump.bin 0x08000000 0x100000
> mdw 0x08000000 16
> reg
> bp 0x08000100 4
```

For an unknown SoC → **bit-bang JTAG** first:

```bash
openocd -f interface/ftdi/ft232h.cfg -c "adapter speed 100; jtag newtap auto0 tap -irlen 4"
```

### 2.3 U-Boot `jtag` / `OpenOCD + target` (MIPS/ARM router)

Many routers (MIPS 24K/74K, Atheros AR71xx/AR9xxx) use the OpenOCD target `mips_m4k.cfg`:

```bash
openocd -f interface/ft232h.cfg -f target/mips_m4k.cfg
> halt
> mww 0xbfc00000 0x0
> reset init
```

JTAG lock (SECURITY fuse) → `IDCODE 0x00000000`/`0xFFFFFFFF`, halt fails → the only way is an SPI dump (§3).

### 2.4 Why it fails in the field

| Gejala | Penyebab |
|---|---|
| `JTAG scan chain interrogation failed: all zeroes` | TDO floating, GND not connected, or pins pressed without solder (intermittent contact) |
| `all ones` | target unpowered / VREF not detected / TCK too fast for a long cable |
| `expected 1 taps got 2` | another device on the chain, need the matching `-irlen` / bypass the tap |
| Reset loop | watchdog active → `reset_config srst_only` or hold NRST via `adapter srst` |
| Flash write corrupt | `flash probe` guesses the geometry; verify with `verify_image` after writing |

---

## 3. SPI Flash Dump

Target: external **25-series** flash (Winbond W25Q64, Macronix MX25L128, GigaDevice GD25Q…) — 8-pin SOIC-8, or the 16-pin series (SOIC-16, WSON). Common sizes: 4/8/16/32 MB.

### 3.1 In-circuit vs lepas

| Mode | When | Risk |
|---|---|---|
| In-circuit (SOIC clip, CH341A) | board off, CPU not touching the bus | bus contention from the SoC → corrupt dump/`0xFF`/`0x00`; usually safe if the SoC is **unpowered** and there are no strong pull-ups |
| Remove & socket | data depends; clip fails | solder rework, pad damage |
| U-Boot `sf read` | console available | requires a U-Boot shell, size must be known |

### 3.2 CH341A (black gold, 1.4/1.7)

Tool: `flashrom 1.4` (Linux) or `AsProgrammer`. **Do not** use an old `flashrom` version <1.2 — it misdetects the chip.

```bash
# deteksi
flashrom -p ch341a_spi
```
```
Found Winbond flash chip "W25Q64.V" (8192 kB, SPI) on ch341a_spi.
```
**Important**: `W25Q64.V` (ID 0xEF4017) vs `W25Q64FV` (0xEF4017 vs 0xEF6017) — wrong variant → write fails verification.

```bash
# dump 3x agar konsisten
for i in 1 2 3; do flashrom -p ch341a_spi -r dump$i.bin; done
sha256sum dump*.bin

# proteksi: cek BP bits (block protect) sebelum menulis
flashrom -p ch341a_spi -r /dev/null            # probe
flashrom -p ch341a_spi -w new.bin -V -c "W25Q64.V"
```

CH341A issue umum:
- **3.3 V ok, 1.8 V chip → needs a 1.8 V mod** (the AMS1117-3.3 regulator must be replaced or use a 1.8 V adapter; otherwise the chip dies/reads `0xFF`).
- TX/RX 5 V on old clones: check the VCC pin with a multimeter at idle (must be 3.3 V).
- Linux: `ch341a_spi` butuh blacklist `ch341` kernel module:
  ```bash
  sudo modprobe -r ch341
# or /etc/modprobe.d/blacklist-ch341.conf: blacklist ch341
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
`spispeed` >4000 kHz often fails for W25Q with a long clip.

### 3.4 Analyzing the dump contents

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
- `0x55AA` at offset 510 — MBR

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

binwalk 3.x limitations: signature-based, **does not** detect raw LZMA, UBI, TRX, or encryption; fails on encapsulated GoAhead/Realtek firmware.

### 4.2 unblob 24.x (pengganti modern)

```bash
unblob -e ./out firmware.bin
unblob --report firmware.bin            # JSON report handler yang match
unblob -v -e ./out firmware.bin
```
Handler: `lzma`, `xz`, `ubifs`, `uboot`, `squashfs`, `cramfs`, `trx`, `android_sparse`, `zip`, `tar`, `7z`, `gzip`, `jffs2`, `cramfs`, `dtb`, `fit`, `multiboot`, `hpelf`.

### 4.3 SquashFS (most common on routers)

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

| Encapsulation | Tool | Example |
|---|---|---|
| TP-Link (header `0x01000000` + md5) | `tplink-safeloader -d` | cek `binwalk -Y` |
| Realtek (header `0x52544B`) | `rtk_fw` / manual unpack | header 16 byte |
| D-Link SHRS | `dlink-shrs` | `0x53485253` |
| Netgear CHK | `chk` / `netgear-chk` | `0x2a23245e` |
| FIT image | `dumpimage -T flat_dt` (u-boot-tools 2024.x) | DTB inside |
| AES encryption | key in U-Boot/SoC OTP | no shortcut |

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

Trick: `LD_PRELOAD` shim for `libc.so.0` (uClibc), page size, and `uname`:

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
Limitations: only supported architectures (MIPS/ARM, user-mode qemu + pre-built kernel 3.2/4.1/4.4/5.1); firmware with a custom kernel / proprietary NVRAM binary often fails. Log: `scratch/<sha>/qemu.final.serial.log`.

### 5.3 Firmadyne (legacy reference)

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
The DTB must match the machine (`malta`, `virt`, `vexpress-a15`). Wrong DTB → `Kernel panic - not syncing: VFS: Unable to mount root fs`.

### 5.5 Debugging binaries with QEMU + GDB

```bash
qemu-mipsel -g 1234 -L ./rootfs ./rootfs/usr/bin/whatever
# di GDB:
set architecture mips
file ./rootfs/usr/bin/whatever
target remote :1234
b *0x00401234
c
```

### 5.6 Why emulation fails

| Gejala | Penyebab | Fix |
|---|---|---|
| `No such file or directory` on a binary | missing ELF interpreter (`/lib/ld-uClibc.so.0`) | verify `readelf -l binary | grep interpreter`, `-L ./rootfs` |
| `Illegal instruction` | arsitektur salah (`-mipsel` vs `-mips`) | cek `file binary`, `readelf -h` |
| `-sh: can't access tty` | init script needs a console | `console=ttyS0` or `-serial mon:stdio` |
| NVRAM kosong → crash | shim `nvram_get` | sediakan `libnvram.so` preload |
| `/dev/mtd` absent | mtd driver not in the qemu kernel | mount the image as a block, or FirmAE |
| `kernel panic` after init | user-mode qemu does not run init | use system emulation, not `qemu-<arch> init` |

---

## Operational Pitfalls (field failure)

1. **SOIC-8 clip contact (Pomona 5250) — source of 80% of corrupt dumps.** Dump 3x, `sha256sum` must be identical. If not: lower `spispeed` (`linux_spi` to 500 kHz), solder wires directly to the pins, or lift the chip. A loose clip = intermittent reads that still look "successful" in `flashrom`.

2. **CH341A 3.3 V kills 1.8 V chips.** Check `VCC` on pin 8 at idle; black clones often lie with an AMS1117-5.0 regulator. Use a 1.8 V adapter or an FT2232H with a level shifter. A 1.8 V chip fed 3.3 V can die permanently.

3. **`flashrom -p ch341a_spi` on Linux fails because the kernel claims `ch341`.** `dmesg | grep ch341` → `modprobe -r ch341` or blacklist it. Symptom: `No EEPROM/flash device found` even though the chip is good.

4. **A "TX-only" UART is often not a UART.** Debug-only pins (console output, no RX) exist on many SoCs (e.g. Broadcom BCM in TV boxes). Send characters and probe RX with a scope/LA — if there is no edge when sending, that pin is not RX (or it needs another jumper/testpoint).

5. **1.8 V levels on modern SoCs (Qualcomm, NVIDIA Tegra).** A 3.3 V USB-TTL = stressing the pin, UART won't decode. Use `FT232H` + `TXS0108E`, or a 1.8 V USB-TTL (CP2102N can be programmed to 1.8 V).

6. **JTAG `reset halt` doesn't hold the core** because of secure boot/WD. Try `reset_config trst_and_srst`, or `reset init` without `halt`, or release NRST and hold it manually. If `IDCODE=0x0` after reset — TDO is floating at the clip.

7. **binwalk 3.x doesn't recognize UBI/TRX/raw LZMA.** Use `unblob` first, fall back to `binwalk -Me`. If both fail: `xxd` the header and look for the offset manually (often 0x1A0000 or 0x40000 for the kernel, 0x20000 for U-Boot).

8. **Wrong SquashFS offset** because `binwalk` reports offsets relative to the section inside the archive, not absolute. Extract with `unsquashfs -o <absolute_offset>`. Check `unsquashfs -s` — if it fails with `Bad magic`, the offset is off.

9. **QEMU user-mode doesn't render NVRAM → the binary crashes before `main`.** Router firmware (Broadcom, Realtek) needs `libnvram.so`, `libshared.so`, `libcmm.so`. Minimal shim: `int nvram_get(const char*,char*,int)`, `nvram_set`, `nvram_commit`, `acos_nvram_get`. Without these `qemu-*` exits with `SIGSEGV` and no output — it looks like the wrong architecture.

10. **FirmAE "success" ≠ service is alive.** `Emulation success` in the log only means init finished; port 80 can hang. Verify with `curl -v http://192.168.0.1/` from the host, and `nc -zv 192.168.0.1 23`. If it hangs: check the end of `qemu.final.serial.log` — usually the service needs `/dev/mtd` or `nvram`, which is empty.

11. **Dumping U-Boot/firmware via `sf read` changes the flash contents** if `sf probe` is run without read mode. Always `sf probe 0; sf read 0x80000000 0x0 0x800000` and compare `md5sum` with the clip dump.

12. **SPI flash with QE bit / dual-QSPI (SOIC-16)** cannot be read with an SOIC-8 clip. You need an SOIC-16 / WSON-8 adapter (pogo pin), or dump via U-Boot. Forcing it wrong = VCC/QE pin connected to a data line → corrupted chip.

13. **Secure boot + fuse = emulation dead end.** If the boot ROM verifies signatures (RSA) and the OTP `SECURE_BOOT_EN` is set, a modified image won't boot on real hardware — emulation still works for analysis, but the exploit must be rewritten. Check `OTP`/`fuse` before investing time in modification.

14. **`qemu-mipsel` host glibc vs target uClibc.** A dynamic target binary must be run with the correct `QEMU_LD_PREFIX`; otherwise `readelf` shows the interpreter, but the host loader calls the host libc → `symbol lookup error`. Check `readelf -l binary | grep Interpreter`.

---

## [reasoning trace]


