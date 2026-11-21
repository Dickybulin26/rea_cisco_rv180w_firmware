# Cisco RV180W v1.0.5.4 — Rust Firmware Clone & Modern TLS Mod Kit

Perkakas **Firmware Clone & Mod Kit** berbasis **Rust** untuk membongkar (*unpack*) firmware resmi **Cisco RV180W v1.0.5.4**, menyisipkan reverse proxy **TLS 1.2 & TLS 1.3** (`rustls` + `rcgen`) agar dashboard `192.168.1.1` berjalan lancar di browser modern, menambahkan perbaikan kompatibilitas JS `/var/www` & halaman diagnostik baru (`modStatus.htm` / `modStatus.cgi`), lalu membungkusnya kembali (*repack*) menjadi `dist/RV180W-Firmware-1.0.5.4-MOD.img` dengan *checksum* header Cisco yang terverifikasi.

## Struktur Layout Biner Terverifikasi (via REA + Ghidra 12.2)

| Offset | Ukuran | Komponen |
| :--- | :--- | :--- |
| `0x000000`–`0x000200` | `512` bytes | **Vendor Header** (struct `0x94` bytes + zero padding): `reserved=0`, `magic1=0x00011D7A`, `magic2=0xC3E6E6AB`, `fw_length`, `checksum` (32-bit byte-sum tanpa `0x14..0x18`), `priority=1`, `device_name="RV180W"` |
| `0x000200`–`0x600000` | `6,290,944` bytes | **Kernel Partition (`/dev/mtd1`, total 6 MiB = `96 × 64 KiB`)**: ARM32 `zImage` (`Linux 2.6.31.1-cavm1`, ARMv6 soft-float EABI) + `rootfs.ext2.gz` initrd + padding |
| `0x600000`–`aligned` | dinamis (4 KiB aligned) | **RootFS Partition (`/dev/mtd2`, mount di `/pfrm2.0`)**: SquashFS v4.0 Little-Endian, kompresi `gzip`, block size `131072` (128 KiB) |
| `aligned`–`+0x200` | `512` bytes | **Trailer**: `FWCHKADDISABABA\n` + zero padding |

> **Verifikasi Checksum (`firmImageVerify` dari `/pfrm2.0/bin/upgrade`):**
> `checksum = sum_u32_wrapping(all_file_bytes) - sum(bytes[0x14..0x18])`.

## Cara Build & Jalankan

```bash
# 1. Cross-compile daemon TLS 1.2/1.3 statis untuk CPU ARMv6 router
cargo zigbuild --release -p target-tls-proxy --target arm-unknown-linux-musleabi

# 2. Build CLI host-modkit
cargo build --release -p host-modkit

# 3. Jalankan pipeline penuh (Unpack -> Patch -> Repack -> Self-Verify)
./target/release/host-modkit build \
  --input ../RV180W-Firmware-1.0.5.4.img \
  --proxy-bin target/arm-unknown-linux-musleabi/release/modern-tls-proxy \
  --work-dir build \
  --output dist/RV180W-Firmware-1.0.5.4-MOD.img

# 4. Verifikasi image hasil build terhadap aturan exact firmImageVerify
./target/release/host-modkit verify --input dist/RV180W-Firmware-1.0.5.4-MOD.img
```

## Pengujian QEMU ARM

```bash
chmod +x scripts/test_qemu.sh
./scripts/test_qemu.sh
```

## Prosedur Pemulihan Hardware (Wajib Sebelum Flash Fisik)

1. Hubungkan adaptor **USB-to-TTL UART 3.3V** (`38400 8N1`, TX/RX/GND — **jangan hubungkan VCC!**) ke header serial PCB Cisco RV180W (`sudo picocom -b 38400 /dev/ttyUSB0`).
2. Siapkan server **TFTP** lokal di PC (IP `192.168.1.2/24`) yang menyajikan salinan `RV180W-Firmware-1.0.5.4.img` asli agar dapat memulihkan melalui konsol **U-Boot** jika diperlukan.
3. Unggah `dist/RV180W-Firmware-1.0.5.4-MOD.img` lewat *Administration -> Firmware Upgrade* sambil memantau konsol serial UART.
4. Setelah reboot, akses `https://192.168.1.1` (dashboard utama) atau `https://192.168.1.1/modStatus.htm` (diagnostik baru). Sertifikat ECDSA P-256 otomatis tersimpan permanen di `/data/certs/modern_https.{crt,key}` (partisi JFFS2 `/dev/mtdblock3`).
