# Issue Plan: Perbaikan Bootloop / Power-LED-Only & Hardening `rv180w-modkit`

> **Target Repositori:** `github.com/Dickybulin26/rea_cisco_rv180w_firmware` (branch `main`, baseline commit `70b96ab`)  
> **Perangkat Target:** Cisco RV180W (Cavium CNS3410 ARM11MPCore ARMv6 soft-float, 128 MB RAM, 32 MB SPI NOR Flash, Broadcom BCM5398/BCM53125 GbE, Kernel `Linux 2.6.31.1-cavm1`)  
> **Prioritas:** `P0 - Critical` (Hardware Unbrick & Anti-Brick Guard)  
> **Status:** Perencanaan Siap Eksekusi

---

## 1. Ringkasan Insiden & Gejala

Setelah melakukan update firmware hasil build `rv180w-modkit` ke router **Cisco RV180W**, perangkat gagal booting secara normal (mengalami hang / bootloop):
- **Indikator fisik:** Hanya lampu **Power LED** yang menyala (LED LAN/System/Wireless tidak masuk kondisi normal).
- **Konektivitas:** Dashboard `192.168.1.1` tidak dapat diakses dan perangkat tidak menyelesaikan urutan inisialisasi jaringan.
- **Status Bootloader (`mtd0`):** Aman (>95% masih utuh), karena layout firmware dan skrip upgrade Cisco RV180W hanya menulis partisi `mtd1` (kernel 6 MiB: `0x000000..0x600000`) dan `mtd2` (SquashFS `/pfrm2.0`: `0x600000+`), tidak pernah menyentuh `mtd0` (U-Boot).

---

## 2. Analisis Akar Masalah (Root Cause Analysis dari Audit Kode Repo)

Berdasarkan audit langsung terhadap source code di `rv180w-modkit/`, terdapat **5 cacat teknis nyata** yang secara tunggal maupun gabungan menyebabkan kondisi Power-LED-only / bootloop pada hardware fisik:

| ID | Severitas | Lokasi File di Repo | Akar Masalah & Dampak di Hardware |
| :--- | :--- | :--- | :--- |
| **RC-1** | **Kritis** | `rv180w-modkit/host-modkit/src/patcher.rs` (`FAST_BOOT_INIT`) & `rv180wd/src/reconciler/mod.rs` | `FAST_BOOT_INIT` menggantikan seluruh `/pfrm2.0/etc/platformInit` namun hanya memuat `bcm5398.ko` + MADWiFi. Inisialisasi driver Ethernet Cavium PSE (`cns3xxx.ko`), tabel VLAN switch (`vlan_table_func`), mount `/data` (`/dev/mtdblock3` JFFS2), bridge LAN, dan daemon/keepalive hardware watchdog (`wdt`) terlewat. Ketika `rv180wd --boot` gagal pada `ip addr add ... dev eth0?`, fungsi keluar dengan `Err` sebelum memanggil `hal::board::set_led("P1")` sehingga lampu tetap tertahan di Power-only atau hardware watchdog memicu bootloop. |
| **RC-2** | **Kritis** | `rv180w-modkit/host-modkit/src/repacker.rs` (`build_squashfs_pure_rust`) | Partisi `/dev/mtd2` (`/pfrm2.0`) dibangun ulang menggunakan crate modern `backhand 0.25.5`. Kernel `Linux 2.6.31.1-cavm1` (2009) memakai implementasi sangat awal SquashFS 4.0 (baru masuk di 2.6.29, belum mendukung xattr yang baru hadir di 2.6.35). Flag superblock modern (`COMP_OPT` / xattr table) menyebabkan `mount -t squashfs /dev/mtdblock2 /pfrm2.0` gagal di `rcS` sehingga `/pfrm2.0/etc/platformInit` tidak pernah ditemukan. |
| **RC-3** | **Tinggi** | `rv180w-modkit/.cargo/config.toml` & `scripts/zig-arm-musleabi-cc.sh` & `scripts/test_rv180wd_qemu.sh` | Flag `-mcpu=mpcorenovfp -mfloat-abi=soft` hanya diterapkan ke compiler C (`zig cc`), **tidak** ke `rustc` (`rustflags` belum menetapkan `-C target-cpu=mpcorenovfp` dan `-C target-feature=-vfp2,-vfp3,-neon,-thumb2`). Uji `qemu-arm-static` berjalan di kernel Linux host modern (5.x/6.x), sehingga tidak mendeteksi crash `SIGILL` (instruksi VFP/Thumb-2 dari `rustc`/`ring 0.17`) atau `ENOSYS` (syscall modern seperti `getrandom`/`statx`/`clock_gettime64` di Linux 2.6.31.1). |
| **RC-4** | **Sedang** | `rv180w-modkit/host-modkit/src/unpacker.rs` (baris 253–262) & `repacker.rs` | `unpacker.rs` membuang seluruh special nodes (`CharacterDevice`, `BlockDevice`, `Fifo`, `Socket`) ke stderr dan menaikkan izin direktori (`|= 0o700`), sementara `repacker.rs` memaksa `uid=0, gid=0` dan tidak merekonstruksi special nodes. Pada mode v2.0, hilangnya device node/FIFO bawaan dapat menggagalkan daemon TeamF1 saat boot. |
| **RC-5** | **Sedang** | `rv180w-modkit/host-modkit/src/repacker.rs` (`SQUASHFS_ALIGN` & `image_name`) | Padding segmen SquashFS sebelum trailer `FWCHKADDISABABA` hanya diselaraskan ke `4 KiB` (`0x1000`), bukan batas eraseblock SPI NOR Flash `64 KiB` (`0x10000`). Selain itu, gangguan flashing/file `.bin` korup dapat memutus penulisan `mtd1`/`mtd2`. |

---

## 3. Rencana Kerja Bertahap (Phased Fix Plan)

### Fase 0 — Pemulihan Hardware (Unbrick Router Sekarang)

Tujuan: Mengembalikan Cisco RV180W ke firmware resmi `RV180W-Firmware-1.0.5.4.img` sekaligus menangkap log serial UART untuk mengonfirmasi 100% mana dari RC-1..RC-5 yang memicu kegagalan.

- [ ] **0.1 Verifikasi integritas file stok resmi (`RV180W-Firmware-1.0.5.4.img`)**
  - Jalankan `host-modkit verify --input RV180W-Firmware-1.0.5.4.img` (atau cek melalui tab *Inspektor Biner*).
  - Pastikan `magic1=0x00011d7a`, `magic2=0xc3e6e6ab`, `device_name="RV180W"`, checksum cocok, SquashFS berada di `0x600000`, dan trailer `FWCHKADDISABABA` utuh.
- [ ] **0.2 Jalur 1 — Emergency Web Recovery (Tanpa Bongkar Casing)**
  1. Matikan Wi-Fi PC, sambungkan kabel LAN langsung dari PC ke **Port LAN 1** router.
  2. Set IP statis Ethernet PC ke `192.168.1.2` (netmask `255.255.255.0`).
  3. Cabut adaptor daya router, tekan & tahan tombol **Reset** di belakang router, tancapkan daya sambil menahan Reset selama **15–20 detik**.
  4. Jalankan `ping -t 192.168.1.1` (Windows) / `ping 192.168.1.1` (Linux/macOS).
  5. Jika ping dibalas, buka `http://192.168.1.1` (HTTP polos), unggah `RV180W-Firmware-1.0.5.4.img`, dan **tunggu penuh 10–15 menit tanpa memutus listrik**.
- [ ] **0.3 Jalur 2 — Konsol Serial UART 3.3V & U-Boot TFTP (Jika Jalur 1 Tidak Merespons)**
  1. Buka casing, hubungkan adaptor **USB-to-TTL 3.3V** (`115200 8N1`): `TX -> RX`, `RX -> TX`, `GND -> GND` (**JANGAN sambungkan pin VCC!**).
  2. Rekam log boot penuh sejak daya ditancapkan (simpan ke `uart_brick_capture.log`) untuk verifikasi akar masalah pasti (`SQUASHFS error` vs `SIGILL` vs `Watchdog` vs `Bad Data CRC`).
  3. **Failsafe Cepat v3.0:** Jika shell Linux terbuka di konsol UART, jalankan:
     ```sh
     mountpoint -q /data || mount -t jffs2 /dev/mtdblock3 /data
     mkdir -p /data/rv180w
     touch /data/rv180w/.legacy_boot
     sync && reboot
     ```
  4. **Pemulihan U-Boot TFTP:** Jika kernel/SquashFS gagal boot, interupsi U-Boot (`Enter`/`Ctrl+C`), jalankan `printenv` untuk memastikan alamat partisi/variabel upgrade papan, lalu tarik `RV180W-Firmware-1.0.5.4.img` dari TFTP server di `192.168.1.2`. **Dilarang keras menghapus `mtd0` (offset `0x000000`).**
- [ ] **0.4 Jalur 3 — External SPI NOR Programmer (Hanya Jika UART 0 Karakter di 115200 & 57600 Baud)**
  - Gunakan CH341A 3.3V / XGecu + `flashrom` untuk **dump backup penuh 32 MB** terlebih dahulu (menyelamatkan MAC & data kalibrasi radio Atheros) sebelum menulis ulang image sehat.

---

### Fase 1 — Perbaikan Pipeline `host-modkit` (`unpacker.rs`, `repacker.rs`, `main.rs`)

Tujuan: Menjamin image SquashFS hasil repack 100% kompatibel dengan `Linux 2.6.31.1-cavm1` dan batas sektor SPI NOR Flash 64 KiB.

- [ ] **1.1 Pertahankan Special Nodes & Metadata RootFS (`unpacker.rs`)**
  - Saat ekstraksi `rootfs_orig.squashfs`, catat seluruh `CharacterDevice`, `BlockDevice`, `Fifo`, dan `Socket` (beserta major/minor, uid, gid, mode) ke file `pseudo_nodes.json` / format pseudo-file `mksquashfs` di dalam `work_dir` daripada membuangnya.
  - Simpan permission asli direktori (jangan memaksa `|= 0o700` permanen ke image akhir).
- [ ] **1.2 Ganti / Tambahkan Backend `mksquashfs` Kompatibel Linux 2.6.31.1 (`repacker.rs`)**
  - Tambahkan opsi default atau backend `mksquashfs` (dari `squashfs-tools`) dengan flag ketat untuk kernel 2.6.31:
    ```bash
    mksquashfs build/squashfs-root build/rootfs_mod.squashfs \
      -comp gzip -b 131072 -no-xattrs -all-root -noappend -pf build/pseudo_nodes.txt
    ```
  - Jika mode pure-Rust `backhand` tetap dipertahankan sebagai opsi eksperimental, validasi superblock hasil build agar:
    - `s_major == 4 && s_minor == 0`
    - `compression_id == 1` (`gzip`)
    - `block_size == 131072` (128 KiB)
    - `xattr_id_table_start == 0xffff_ffff_ffff_ffff`
    - Bit flag `SQUASHFS_COMP_OPT` (`0x0400`) bernilai `0`.
- [ ] **1.3 Ubah Alignment Padding dari 4 KiB ke 64 KiB Eraseblock NOR Flash (`repacker.rs`)**
  - Ubah `const SQUASHFS_ALIGN: usize = 0x1000;` menjadi `const SQUASHFS_ALIGN: usize = 0x1_0000;` (`65.536` bytes) agar batas akhir SquashFS tepat di batas eraseblock SPI NOR flash 64 KiB sebelum trailer 512 byte `FWCHKADDISABABA`.
- [ ] **1.4 Perketat `host-modkit verify` (`main.rs` & `unpacker.rs`)**
  - Selain `firmImageVerify` (magic, panjang, checksum byte-sum), wajibkan `host-modkit verify` memeriksa:
    1. Keberadaan magic SquashFS `hsqs` tepat di offset `0x600000`.
    2. Superblock SquashFS 4.0 LE Gzip 128 KiB tanpa xattr/COMP_OPT.
    3. Alignment 64 KiB segmen SquashFS.
    4. Keberadaan trailer `FWCHKADDISABABA` pada 512 byte terakhir.
    5. Integritas ELF binary ARMv6 (`rv180wd` / `modern-tls-proxy`) bebas flag VFP/Thumb-2.

---

### Fase 2 — Hardening Cross-Compile ARMv6 & Audit Syscall Linux 2.6.31.1

Tujuan: Menghilangkan risiko crash `SIGILL` dan `ENOSYS` ketika binary Rust dijalankan di CPU Cavium CNS3410 + kernel `2.6.31.1`.

- [ ] **2.1 Kunci Target CPU & Fitur ISA pada `rustc` (`rv180w-modkit/.cargo/config.toml`)**
  - Perbarui konfigurasi target menjadi:
    ```toml
    [target.arm-unknown-linux-musleabi]
    linker = "rust-lld"
    rustflags = [
      "-C", "linker-flavor=ld.lld",
      "-C", "target-cpu=mpcorenovfp",
      "-C", "target-feature=+crt-static,-vfp2,-vfp3,-neon,-thumb2",
      "-C", "link-self-contained=yes",
    ]
    ```
- [ ] **2.2 Tambahkan Pemeriksaan Otomatis Atribut ELF ARMv6 di Build Script**
  - Tambahkan langkah validasi menggunakan `readelf -A` (atau parser atribut ARM `.ARM.attributes`) di `scripts/test_rv180wd_qemu.sh`:
    - Pastikan `Tag_CPU_arch: v6` (bukan v7).
    - Pastikan **tidak ada** `Tag_FP_arch` (soft-float murni).
    - Pastikan **tidak ada** instruksi Thumb-2 / NEON.
- [ ] **2.3 Uji Binary dengan Emulasi CPU Ketat & Audit Syscall Kernel 2.6.31**
  - Jalankan `qemu-arm-static -cpu arm11mpcore -strace ...` (bukan CPU default QEMU yang mendukung ARMv7/VFP!).
  - Inspeksi daftar syscall dari `-strace`: pastikan tidak ada syscall fatal tanpa fallback pada Linux 2.6.31.1 (mis. pastikan `getrandom` jatuh bersih ke `/dev/urandom`, `clock_gettime64` jatuh bersih ke `clock_gettime`, dan `ring 0.17` tidak memicu `SIGILL` saat inisialisasi `rustls` / `rcgen` / PBKDF2).

---

### Fase 3 — Perbaikan `FAST_BOOT_INIT`, HAL Switch/Watchdog & Auto-Fallback Anti-Brick

Tujuan: Menjamin router **tidak pernah bisa brick** walau `rv180wd` gagal dijalankan atau konfigurasi jaringan bermasalah.

- [ ] **3.1 Audit Lengkap `/pfrm2.0/etc/platformInit` Asli dari Firmware 1.0.5.4**
  - Catat daftar pasti modul kernel yang dimuat (`cns3xxx.ko`, `bcm5398.ko`, driver PSE/GPIO/LED/watchdog), urutan inisialisasi switch (`vlan_table_func`, `set_wan_port_func`), dan nama interface jaringan aktual (`eth0`/`eth1`/`bdg1`/`br0`) dari `platformInit` pabrikan.
  - Samakan nama interface di `rv180wd/src/reconciler/mod.rs` (`network`, `dhcp_dns`, `firewall`) dengan hasil audit tersebut agar tidak meng-hardcode `eth0`/`eth1` secara keliru.
- [ ] **3.2 Rombak `FAST_BOOT_INIT` dengan Hardware Init Lengkap + Auto-Fallback (`patcher.rs`)**
  - Pastikan `/data` (`/dev/mtdblock3` JFFS2) sudah ter-mount sebelum mengecek `/data/rv180w/.legacy_boot`.
  - Tambahkan deteksi **Hardware Failsafe via Tombol Reset** (`/proc/push_button`): jika tombol Reset ditahan saat boot, otomatis masuk ke `platformInit.legacy` tanpa perlu membuka casing/UART!
  - Muat seluruh modul hardware & watchdog daemon yang diperlukan sebelum menjalankan `rv180wd --boot`.
  - Wajibkan auto-fallback: jika `/pfrm2.0/bin/rv180wd --boot` mengembalikan status non-zero (termasuk crash `SIGILL`), catat error ke `/tmp/rv180wd-boot.log` lalu **otomatis `exec /bin/sh /pfrm2.0/etc/platformInit.legacy`** agar router tetap menyala normal dengan firmware stok.
  ```sh
  #!/bin/sh
  mountpoint -q /data || mount -t jffs2 /dev/mtdblock3 /data 2>/dev/null

  # Failsafe 1: Flag file .legacy_boot
  # Failsafe 2: Tombol fisik Reset ditekan saat boot (/proc/push_button == 1)
  if [ -f /data/rv180w/.legacy_boot ] || [ "$(cat /proc/push_button 2>/dev/null)" = "1" ]; then
      echo "[rv180w-next] Failsafe triggered -> exec platformInit.legacy"
      exec /bin/sh /pfrm2.0/etc/platformInit.legacy
  fi

  # Inisialisasi hardware inti (sesuaikan hasil audit platformInit.legacy)
  [ -f /pfrm2.0/lib/modules/cns3xxx.ko ] && insmod /pfrm2.0/lib/modules/cns3xxx.ko 2>/dev/null
  [ -f /pfrm2.0/lib/modules/swdrv/bcm5398.ko ] && insmod /pfrm2.0/lib/modules/swdrv/bcm5398.ko 2>/dev/null
  [ -x /pfrm2.0/bin/vlan_table_func ] && /pfrm2.0/bin/vlan_table_func init 2>/dev/null

  # Boot rv180wd dengan fallback otomatis jika gagal/crash
  if ! /pfrm2.0/bin/rv180wd --boot >/tmp/rv180wd-boot.log 2>&1; then
      echo "[rv180w-next] rv180wd --boot failed! Reverting to platformInit.legacy"
      exec /bin/sh /pfrm2.0/etc/platformInit.legacy
  fi

  /pfrm2.0/bin/rv180wd --serve >/tmp/rv180wd.log 2>&1 &
  ```
- [ ] **3.3 Jangan Hentikan Seluruh Boot Karena Satu Sub-Command (`rv180wd/src/config/boot.rs` & `reconciler/mod.rs`)**
  - Pastikan kegagalan non-fatal pada subsistem opsional (`wifi`, `qos`, `vpn`, `wan`) hanya dicatat sebagai warning dan **tidak** memblokir konfigurasi IP LAN (`192.168.1.1`) maupun pemanggilan `hal::board::set_led("P1")`.

---

### Fase 4 — Gerbang Validasi Pra-Flash (Pre-Flash Gate) & Uji Hardware Bertahap

Tujuan: Tidak ada lagi flashing "buta" ke router fisik sebelum seluruh syarat lolos.

- [ ] **4.1 Uji Unit & Integrasi Host (`cargo test`)**
  - Tambah unit test pada `host-modkit` untuk validasi superblock SquashFS (menolak xattr/COMP_OPT), alignment 64 KiB, dan preservasi special nodes.
- [ ] **4.2 Uji Emulasi ARM11MPCore (`qemu-arm-static -cpu arm11mpcore`)**
  - Jalankan `scripts/test_rv180wd_qemu.sh` dengan `-cpu arm11mpcore` dan pastikan TLS 1.2/1.3, setup password, login, dan config save lulus tanpa `SIGILL`.
- [ ] **4.3 Uji Staging 2 Langkah di Hardware (Dengan Konsol UART Terpasang)**
  1. **Uji Tahap A (SquashFS Repack Tanpa Patch Init):** Unpack lalu repack firmware 1.0.5.4 **tanpa** mengubah `platformInit`, flash sambil pantau UART. Pastikan `/pfrm2.0` berhasil di-mount oleh kernel `2.6.31.1` dan router boot normal.
  2. **Uji Tahap B (Jalankan `rv180wd` Manual dari `/tmp` via UART/SSH):** Salin binary `rv180wd` ke `/tmp` router yang sedang berjalan di firmware stok, jalankan `/tmp/rv180wd --version` dan `/tmp/rv180wd --serve` pada port sementara (`8080`/`8443`) untuk membuktikan 100% bebas `SIGILL`/`ENOSYS` di kernel `2.6.31.1` asli.
  3. **Uji Tahap C (Flash Full `rv180w-next` v3.0):** Baru flash image v3.0 penuh setelah Tahap A dan B lulus sempurna, sambil tetap menghubungkan konsol UART dan menguji tombol Reset failsafe.

---

## 4. Kriteria Selesai (Definition of Done)

- [ ] Router fisik Cisco RV180W berhasil dipulihkan ke firmware resmi `1.0.5.4` dan log UART insiden awal terdokumentasi.
- [ ] `host-modkit repack` menghasilkan SquashFS 4.0 LE Gzip 128 KiB yang ter-mount bersih di kernel `Linux 2.6.31.1-cavm1` (terbukti lewat Uji Tahap A).
- [ ] Binary `rv180wd` & `modern-tls-proxy` terverifikasi `Tag_CPU_arch: v6` soft-float murni tanpa VFP/Thumb-2 dan berjalan stabil di hardware asli (terbukti lewat Uji Tahap B).
- [ ] `FAST_BOOT_INIT` memiliki auto-fallback ke `platformInit.legacy` (baik saat `rv180wd --boot` gagal maupun saat tombol Reset ditekan waktu boot).
- [ ] `host-modkit verify` memeriksa header `firmImageVerify`, offset `0x600000`, superblock SquashFS 2.6.31, alignment 64 KiB, dan trailer `FWCHKADDISABABA`.
