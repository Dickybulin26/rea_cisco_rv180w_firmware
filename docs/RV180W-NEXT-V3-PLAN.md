# Rencana Rombak Total & Optimasi Firmware Cisco RV180W (`rv180w-next` v3.0)

> Dokumen ini merupakan rencana kerja terstruktur di dalam repositori untuk [Issue #1](https://github.com/Dickybulin26/rea_cisco_rv180w_firmware/issues/1).

## 1. Latar Belakang & Akar Masalah Firmware Pabrikan (Temuan REA + Ghidra)

Berdasarkan bedah forensik terhadap firmware resmi **Cisco RV180W v1.0.5.4** (`Linux 2.6.31.1-cavm1`, Cavium CNS3xxx ARMv6 soft-float EABI5), seluruh keluhan performa, bug login, dan kerentanan keamanan berasal dari arsitektur *management stack* lawas **TeamF1 SGS (2007–2014)**:

1. **Booting Sangat Lambat (100–200+ detik):**
   - `sqliteInit` membangun ulang 3 database SQLite dari nol pada **setiap boot** (`system.sql` >5.600 baris + `stats.sql` + `log.sql` + I18N).
   - `configInit` menjalankan `restoreDB.lua` + `user2.lua` untuk mengimpor ulang ribuan baris `/data/tmp/teamf1.cfg.ascii` sambil memicu *DB triggers* sekuensial.
   - `platformInit` mengeksekusi ~50 skrip `*Init` berurutan penuh `sleep 2` / `sleep 3`.
2. **Save Config Lambat & Memicu Restart Router:**
   - Setiap klik *Save*, `saveDB.lua` (`db.save`) men-dump seluruh SQLite lewat Lua 5.1 dengan `f:flush()` di tiap node ke NOR flash JFFS2.
   - Modul inti (`lan.lua`, `wizard.lua`, `dot11View.lua`) memicu `touch /tmp/reboot` / `rebootFlag = true`.
3. **Bug Login Kronis & Kerentanan Keamanan:**
   - `login.lua` memvalidasi sesi dengan `ipaddr = REMOTE_ADDR AND cookie = ... AND protocol = split(HTTP_REFERER, "://")[1]` (rapuh di browser modern / reverse proxy).
   - `login.authenticate` menyusun query SQLite mentah tanpa *parameterized query* (SQLi & gagal pada karakter spesial).
   - `thttpd` memakai **OpenSSL 0.9.8** (TLS 1.0/1.1) dan sertifikat `md5WithRSAEncryption` RSA 1024-bit kedaluwarsa tanpa SAN.

---

## 2. Target KPI Optimasi & Anggaran Resource (Ultra-Light Rust)

| Metrik | Firmware Pabrikan (1.0.5.4) | Target `rv180w-next` (v3.0) |
| :--- | :--- | :--- |
| **Waktu Booting** | ~120–240 detik | **< 20 detik** |
| **Save Config** | ~30–180 detik + sering reboot | **< 1 detik, 0 reboot (Hot-Reload)** |
| **RAM RSS `rv180wd` (Idle)** | ~35–55 MB (40+ daemon, SQLite, Lua CGI) | **< 8–12 MB RSS** (1 daemon statis + service aktif saja) |
| **CPU Usage (Idle)** | Polling periodik banyak daemon & watchdog | **< 1% CPU** (telemetry on-demand saat dashboard dibuka) |
| **Ukuran Binary `rv180wd`** | Puluhan MB binary + shared libs TeamF1 | **< 2.0 MB** (static ARMv6 musl, `opt-level="z"`, LTO, stripped) |
| **Aset Web UI SPA** | > 5 MB file HTML/JS/GIF terpisah | **< 100 KB** ter-embed (zero-bloat vanilla SPA) |
| **Keamanan Web & TLS** | TLS 1.0, RSA-1024 MD5, SQLi di login | **TLS 1.2/1.3 ECDSA P-256, PBKDF2-SHA256, Anti-SQLi/CMDi/CSRF** |
| **Stabilitas Login** | Gagal karena `Referer`/`REMOTE_ADDR`/flush | **100% deterministik, atomic fsync `0600` ke flash** |

### Prinsip Desain Hemat Resource (Zero-Bloat Rust)
1. **Tanpa Framework Async Berat:** Tidak memakai `tokio`/`hyper`/`axum`/`actix`/ORM; gunakan `std::net` + *bounded worker pool* (8–12 koneksi) dan buffer tetap (`8 KiB`), serta batas ketat jumlah sesi (`32`) dan entri rate-limiter (`128`).
2. **Strict On-Demand Services:** VPN (`racoon`/`pptpd`/`l2tp`), QoS (`tc`), NTP, dan fitur opsional lain **0 proses & 0 KB RAM** saat nonaktif.
3. **On-Demand Telemetry & Anti Flash-Wear:** `/proc` hanya dibaca saat dashboard dibuka; log & leases di `tmpfs` (`/tmp`), NOR flash `/data/rv180w/` hanya ditulis sekali secara atomik (`tmp -> fsync -> rename`) saat admin klik *Save*.

---

## 3. Roadmap 6 Fase

- [x] **Fase 1 — Audit HAL Hardware via REA (`hal/mod.rs`):** Pemetaan `cns3xxx.ko`, `bcm5398.ko` (`bcmswitch="bcm5395"`, `/dev/bcm53980`), `sppe_ioctl sppe <enable|disable>`, `vlan_table_func` (`eth0.1` VLAN 1 → bridge `bdg1`), `set_wan_port_func`, MADWiFi Atheros (`ath_*`/`wlan_*`), `/proc/led`, `/proc/push_button`, `/proc/macAddress`, dan partisi MTD riil 32 MB flash (`mtd0` UBoot 512 KB, `mtd1` Kernel 6 MiB `0x080000–0x680000`, `mtd2` Rootfs 23 MiB `0x680000–0x1D80000`, `mtd3` Config JFFS2 1 MiB `0x1D80000–0x1E80000`, RAM 128 MB, CPU 600 MHz).
- [x] **Fase 2 — Atomic Config Store & Auth Aman (`config/` & `auth/`):** `config.json` atomic + `.bak` rollback atomik + diff engine 7 subsistem; `auth.json` (`0600`) PBKDF2-HMAC-SHA256 (tuned 25k iterasi untuk ARMv6), sliding session 256-bit, CSRF constant-time, rate-limiter terbatas.
- [x] **Fase 3 — Zero-Reboot Hot-Reload Reconcilers (`reconciler/` & `upgrade/`):** Reconciler subsistem (`system`, `network`, `dhcp_dns`, `firewall` atomic `iptables-restore`, `wifi`, `qos`, `vpn`) + verifikasi exact `firmImageVerify` untuk safe upgrade.
- [x] **Fase 4 — Native Rust HTTP + TLS 1.2/1.3 Server & Modern SPA (`server/` & `web-ui/`):** `rustls` TLS 1.2/1.3 ECDSA P-256 SAN `192.168.1.1`, REST API `/api/v1/*`, First-Boot Wizard, Safe-Rollback 60s, dan Modern Responsive SPA Dashboard.
- [x] **Fase 5 — Fast-Boot Init & Hardening (`host-modkit` `--mode next`):** Integrasi `rv180wd` + `fastBootInit` (< 20s) + mode failsafe `.legacy_boot` + default-deny WAN.
- [ ] **Fase 6 — Pengujian QEMU ARMv6 & Flashing Aman (UART 3.3V + TFTP):** Validasi penuh di `qemu-arm-static`, benchmark ukuran binary & login ARMv6, lalu uji di perangkat fisik dengan jalur pemulihan UART/TFTP.
