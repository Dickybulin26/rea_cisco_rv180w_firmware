# REA Cisco RV180W Firmware Mod Kit (`v2.0.0-beta`)

Perkakas **Firmware Clone & Modern TLS Mod Kit** berbasis **Rust** untuk router **Cisco RV180W (v1.0.5.4)** yang dibangun menggunakan hasil reverse engineering dengan **REA (Reverse Engineer Anything)** + **Ghidra 12.2**.

## Isi Repositori
- [`planning.md`](planning.md) — Rencana pengembangan 6 fase.
- [`rv180w-modkit/`](rv180w-modkit/) — Cargo Workspace Rust:
  - **`host-modkit`** (`v2.0.0-beta`): CLI untuk *unpack* (pure-Rust `backhand` + `binrw`), *patch* (`/pfrm2.0/bin/thttpd` wrapper, watchdog, kompatibilitas JS `/var/www`, & halaman diagnostik `modStatus.htm`/`modStatus.cgi`), *repack* SquashFS 4.0 LE Gzip 128 KiB, dan rekalkulasi *checksum* header Cisco (`firmImageVerify` 32-bit unsigned byte-sum).
  - **`target-tls-proxy`** (`v2.0.0-beta`): Daemon static ARMv6 musl (`rustls` TLS 1.2 & TLS 1.3 + `rcgen` ECDSA P-256 SAN `IP:192.168.1.1`) di `0.0.0.0:443` → `127.0.0.1:80`.
  - **`scripts/`**: Wrapper cross-compile Zig ARMv6 (`zig-arm-musleabi-cc.sh`) dan pengujian QEMU ARM32 (`test_qemu.sh`).

> **Catatan:** File biner firmware resmi (`RV180W-Firmware-1.0.5.4.img`) dan hasil ekstraksi vendor (`rea_extracted/`) tidak disertakan di repositori ini. Letakkan file firmware resmi di root direktori sebelum menjalankan `host-modkit build`. Lihat [`rv180w-modkit/README.md`](rv180w-modkit/README.md) untuk panduan lengkap build, pengujian QEMU, dan pemulihan UART/TFTP.
