# Rencana Rombak Total & Optimasi Firmware Cisco RV180W (`rv180w-next` v3.0)

> Dokumen ini disalin dari [Issue #1](https://github.com/Dickybulin26/rea_cisco_rv180w_firmware/issues/1) sebagai rencana kerja terstruktur di dalam repositori.

## 1. Latar Belakang & Akar Masalah Firmware Pabrikan (Temuan REA + Ghidra)

Berdasarkan bedah forensik terhadap firmware resmi **Cisco RV180W v1.0.5.4** (`Linux 2.6.31.1-cavm1`, Cavium CNS3xxx ARMv6 soft-float EABI5), seluruh keluhan performa, bug login, dan kerentanan keamanan berasal dari arsitektur *management stack* lawas **TeamF1 SGS (2007–2014)**:

1. **Booting Sangat Lambat (100–200+ detik):**
   - `sqliteInit` membangun ulang 3 database SQLite dari nol pada **setiap boot** dengan mem-parsing `system.sql` (>5.600 baris) + `stats.sql` + `log.sql` + file bahasa I18N.
   - `configInit` lalu menjalankan `restoreDB.lua` + `user2.lua` (Lua 5.1) untuk mengimpor ulang ribuan baris dari `/data/tmp/teamf1.cfg.ascii` satu per satu, memicu *DB triggers* yang menjalankan puluhan proses C/shell secara sekuensial.
   - `platformInit` mengeksekusi ~50 skrip `*Init` berurutan lengkap dengan `sleep 2` / `sleep 3` manual demi menghindari *SQLite lock*.
2. **Save Config Lambat & Memicu Restart Router:**
   - Setiap klik *Save*, `db.save` (`saveDB.lua`) men-dump **seluruh database SQLite** secara rekursif lewat Lua 5.1 sambil memanggil `f:flush()` di setiap node tabel langsung ke NOR flash JFFS2 (`/data/tmp/teamf1.cfg.ascii`).
   - Perubahan dasar (LAN di `lan.lua`, Quick Setup di `wizard.lua`, mode Wi-Fi di `dot11View.lua`) langsung memanggil `touch /tmp/reboot` atau `rebootFlag = true` sehingga seluruh router harus reboot ratusan detik.
3. **Bug Login Kronis & Kerentanan Keamanan:**
   - `login.lua` memvalidasi sesi dengan `ipaddr = REMOTE_ADDR AND cookie = ... AND protocol = split(HTTP_REFERER, "://")[1]` — sangat rapuh terhadap browser modern (`Referrer-Policy`), *reverse proxy* (`REMOTE_ADDR = 127.0.0.1`), serta `Set-Cookie: Secure`.
   - `login.authenticate` menyusun query SQLite mentah (`WHERE username = '%s' AND password = '%s'`) tanpa *parameterized query* (rentan SQL Injection dan gagal total bila password mengandung karakter spesial tertentu).
   - Quick Setup + Upgrade rentan kehilangan state kredensial bila `/data/tmp/teamf1.cfg.ascii` belum ter-flush atau ter-reset saat upgrade.
   - Web server `thttpd` memakai **OpenSSL 0.9.8** (TLS 1.0/1.1) dengan sertifikat `md5WithRSAEncryption` RSA 1024-bit kedaluwarsa (`Oct 2024`) tanpa SAN.

---

## 2. Visi Arsitektur Baru: `rv180w-next` (Pure Rust Control Plane)

Kita **mempertahankan seluruh driver hardware asli kernel `2.6.31.1-cavm1`** agar semua fungsi fisik router (Switch Gigabit Broadcom `bcm5398`, HW NAT `sppe.ko`, Wi-Fi Atheros 802.11n `ath_*`/`wlan_*`, LED `scm-led.ko`, tombol reset `push_button.ko`, hardware crypto `cavium.ko`/`vipsec.ko`, `iptables`, `dnsmasq`, `pppd`, `racoon`) tetap berjalan 100%, sambil **mengganti total seluruh lapisan manajemen TeamF1** (SQLite + Lua 5.1 + `thttpd` + `evtDsptchd` + `platformd` + 50 skrip `*Init`) dengan **satu daemon Rust statis ARMv6 ultra-ringan (`rv180wd`)**.

### Target KPI Optimasi & Anggaran Resource (Ultra-Light Rust)

| Metrik | Firmware Pabrikan (1.0.5.4) | Target `rv180w-next` (v3.0) |
| :--- | :--- | :--- |
| **Waktu Booting** | ~120–240 detik | **< 20 detik** |
| **Save Config** | ~30–180 detik + sering reboot | **< 1 detik, 0 reboot (Hot-Reload)** |
| **RAM RSS `rv180wd` (Idle)** | ~35–55 MB (40+ daemon, SQLite, Lua CGI) | **< 8–12 MB RSS** |
| **CPU Usage (Idle)** | Polling periodik banyak daemon & watchdog | **< 1% CPU** |
| **Ukuran Binary `rv180wd`** | Puluhan MB binary + shared libs TeamF1 | **< 2.0 MB** |
| **Aset Web UI SPA** | > 5 MB file HTML/JS/GIF terpisah | **< 100 KB** pre-compressed `gzip` |
| **Keamanan Web & TLS** | TLS 1.0, RSA-1024 MD5, SQLi di login | **TLS 1.2/1.3 ECDSA P-256, PBKDF2/Argon2, Anti-SQLi/CMDi/CSRF** |
| **Stabilitas Login** | Gagal karena `Referer`/`REMOTE_ADDR`/flush | **100% deterministik, atomic fsync ke flash** |

### Prinsip Desain Hemat Resource (Zero-Bloat Rust)
1. **Tanpa Framework Async Berat:** `std::net` + *bounded worker pool* kecil (maks. 8–12 koneksi) dengan buffer tetap (`8 KiB`).
2. **Zero-Copy Pre-Compressed Web Assets:** SPA di-`gzip` saat compile time (`include_bytes!`).
3. **Strict On-Demand Services:** VPN/DDNS/QoS opsional = 0 proses & 0 KB RAM saat nonaktif.
4. **On-Demand Telemetry & Anti Flash-Wear:** telemetry saat dashboard dibuka; NOR flash hanya disentuh lewat 1 atomic write saat Save.

---

## 3. Fase 1: Audit HAL via REA & Pemetaan Driver Asli
- [ ] Pemetaan Switch, VLAN & HW NAT (`hal/switch.rs`)
- [ ] Pemetaan Wi-Fi Atheros 802.11n (`hal/wifi.rs`)
- [ ] Pemetaan LED, Reset Button & MAC Flash (`hal/board.rs`)
- [ ] Pemetaan Partisi MTD & Upgrade Aman (`upgrade/mod.rs`)

## 4. Fase 2: Rombak Database Konfigurasi & Sistem Autentikasi Aman
- [ ] Atomic Config Store (`/data/rv180w/config.json`, tmp→fsync→bak→rename, safe-mode rollback 60s)
- [ ] Perbaikan Total Sistem Login & Autentikasi (hash PBKDF2/Argon2id + salt, token 256-bit, rate limit, CSRF, first-boot wizard)

## 5. Fase 3: Engine Zero-Reboot Hot-Reload & Preservasi Fitur Router
- [ ] Config Diff Engine
- [ ] Reconciler: WAN/LAN/VLAN, DHCP/DNS, Firewall/NAT, Wi-Fi, QoS, VPN, Sistem & Upgrade

## 6. Fase 4: Native Rust HTTPS Server & Revamp Total Dashboard UI
- [ ] Server terintegrasi `rv180wd` (rustls TLS 1.2/1.3, HTTP+HTTPS, REST `/api/v1/*`, exec tanpa shell interpolation)
- [ ] Dashboard SPA modern responsif (< 150 KB gzip, embedded)

## 7. Fase 5: Fast-Boot Init System, Pruning Bloat & Hardening Keamanan
- [ ] Fast-Boot Init (`/pfrm2.0/etc/fastBootInit`, `rv180wd --boot/--serve`, failsafe recovery)
- [ ] Pruning layanan usang & hardening (disable snmpd/upnpd/telnetd/thttpd legacy, default-deny WAN mgmt)

## 8. Fase 6: Pengujian Menyeluruh, QEMU & Prosedur Flashing Aman
- [ ] Unit & integration tests (`cargo test`)
- [ ] Uji emulasi QEMU ARMv6 (`scripts/test_qemu.sh`)
- [ ] Flashing aman ke router fisik (UART + TFTP, verifikasi checksum, ukur boot/save)

