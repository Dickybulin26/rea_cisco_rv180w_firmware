# REA Cisco RV180W Firmware Mod Kit & `rv180w-next` (`v3.0.0-beta`)

Perkakas **Firmware Clone, Mod Kit & Next-Gen Pure Rust Control Plane** untuk router **Cisco RV180W (v1.0.5.4)** yang dibangun menggunakan hasil reverse engineering dengan **REA (Reverse Engineer Anything)** + **Ghidra 12.2**.

## Isi Repositori
- [`docs/RV180W-NEXT-V3-PLAN.md`](docs/RV180W-NEXT-V3-PLAN.md) — Roadmap 6 fase & target anggaran resource ultra-ringan (`< 8-12 MB RSS`, `< 1% CPU idle`, `< 2 MB` binary ARMv6).
- [`rv180w-modkit/`](rv180w-modkit/) — Cargo Workspace Rust:
  - **`rv180wd`** (`v3.0.0-beta`): Daemon control plane tunggal statis ARMv6 pengganti stack TeamF1 (SQLite/Lua/`thttpd`):
    - Native HTTP (:80) + **TLS 1.2/1.3** (`rustls` + `rcgen` ECDSA P-256 SAN `192.168.1.1`) (:443)
    - Embedded Modern SPA Dashboard (~10 KB, zero external CDN) + REST API `/api/v1/*`
    - Atomic config store (`/data/rv180w/config.json` + `.bak` rollback atomik + 60s Safe-Mode Guard)
    - Auth aman (`/data/rv180w/auth.json` `0600`, PBKDF2-HMAC-SHA256, 256-bit sliding session, CSRF, per-IP rate limit — bebas bug login `Referer`/SQLi)
    - Zero-reboot diff-based hot-reload reconcilers (Network, `dnsmasq`, atomic `iptables-restore`, Atheros Wi-Fi, on-demand QoS/VPN)
  - **`host-modkit`**: CLI host PC untuk *unpack*, *patch* (`--rv180wd-bin` untuk v3 fast-boot atau `--proxy-bin` untuk v2), *repack* SquashFS 4.0 LE Gzip 128 KiB, dan verifikasi exact checksum Cisco (`firmImageVerify`).
  - **`target-tls-proxy`**: Reverse proxy TLS 1.2/1.3 ringan (mode v2).
  - **`scripts/`**: Wrapper cross-compile Zig ARMv6 (`zig-arm-musleabi-cc.sh`) dan uji QEMU ARMv6 (`test_rv180wd_qemu.sh`, `test_qemu.sh`).

> **Catatan:** File biner firmware resmi (`RV180W-Firmware-1.0.5.4.img`) dan hasil ekstraksi vendor (`rea_extracted/`) tidak disertakan di repositori publik ini. Letakkan file firmware resmi di root direktori sebelum menjalankan `host-modkit build`.
