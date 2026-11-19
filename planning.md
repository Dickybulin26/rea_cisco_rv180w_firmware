# Rencana Pengembangan Rust Firmware Mod Kit (`RV180W-Firmware-1.0.5.4.img`)

## 1. Tujuan Utama & Arsitektur Solusi

Proyek ini bertujuan membangun perkakas **Firmware Clone & Mod Kit** berbasis bahasa **Rust** untuk membongkar (*unpack*) firmware resmi **Cisco RV180W v1.0.5.4**, menyisipkan fitur baru agar dashboard `192.168.1.1` dapat diakses secara mulus di **browser modern** (Chrome, Firefox, Edge, Safari), lalu membungkusnya kembali (*repack*) menjadi file image baru (`RV180W-Firmware-1.0.5.4-MOD.img`) yang siap di-*flash* ke perangkat router.

### Akar Masalah & Strategi Teknis
Firmware asli `1.0.5.4` (rilis November 2014) ditolak oleh browser modern karena web server bawaannya hanya mendukung **TLS 1.0/1.1**, *cipher suite* usang (RC4/3DES/SHA-1), serta sertifikat RSA 1024-bit. Solusinya dirancang menggunakan **Cargo Workspace** yang terdiri dari dua komponen Rust:
1. **`host-modkit` (Aplikasi CLI di PC):** Memisahkan *vendor header*, *kernel*, dan *SquashFS*, menyuntikkan modifikasi ke dalam *root filesystem*, menghitung ulang *checksum* header Cisco, dan menghasilkan file `.img` baru.
2. **`target-tls-proxy` (Binary Static ARM32 di Router):** Layanan *reverse proxy* HTTPS modern (`rustls` dengan **TLS 1.2 & TLS 1.3**) yang berjalan di port `443` router dan meneruskan permintaan ke web server internal router (`127.0.0.1:80`).

### Struktur Proyek Cargo Workspace

```text
rv180w-modkit/
├── Cargo.toml                  # Konfigurasi Cargo Workspace
├── host-modkit/                # Perkakas CLI Unpack -> Patch -> Repack (Host PC)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs             # Orkestrasi pipeline build firmware baru
│       ├── unpacker.rs         # Ekstraksi header, zImage kernel, & SquashFS
│       ├── patcher.rs          # Injeksi binary proxy, skrip init, & patch UI /www
│       └── repacker.rs         # Pembuatan SquashFS baru & rekalkulasi checksum Cisco
└── target-tls-proxy/           # Daemon TLS 1.2/1.3 ringan untuk CPU ARM32 Router
    ├── Cargo.toml
    └── src/
        └── main.rs             # HTTPS listener (port 443) -> HTTP backend (127.0.0.1:80)
```

---

## 2. Fase 1: Setup Toolchain Rust & Cross-Compilation ARM32

Menyiapkan lingkungan kompilasi agar dapat membangun aplikasi CLI di komputer host sekaligus menghasilkan *static binary* yang berjalan di atas kernel Linux 2.6 lama milik Cisco RV180W.

- [ ] **Inisialisasi Cargo Workspace:** Buat direktori `rv180w-modkit` beserta sub-proyek `host-modkit` dan `target-tls-proxy`.
- [ ] **Konfigurasi Target Cross-Compile Router:**
  - Tambahkan target arsitektur ARM32 Little-Endian dengan pustaka statis *musl* agar tidak bergantung pada `uClibc` lama di dalam router:
    `rustup target add arm-unknown-linux-musleabi`
  - Siapkan *cross-linker* (`arm-linux-musleabi-gcc` atau `cargo-zigbuild`).
- [ ] **Konfigurasi Dependensi (`Cargo.toml`):**
  - **`host-modkit`:** `clap` (CLI), `binrw` / `nom` (parsing header biner), `backhand` (baca/tulis SquashFS), `flate2` (kompresi gzip), `crc32fast`, `sha2`, `anyhow`.
  - **`target-tls-proxy`:** `rustls`, `rustls-pemfile`, `rcgen` (generasi sertifikat ECDSA P-256 / RSA-2048 lokal otomatis saat *first boot* dengan SAN `192.168.1.1`).
- [ ] **Optimasi Ukuran Binary Target:** Karena flash internal RV180W berkapasitas terbatas (16 MB), aktifkan profil rilis minimal pada `target-tls-proxy` (`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`).

---

## 3. Fase 2: Cloning & Unpacking Firmware Asli (`host-modkit/src/unpacker.rs`)

Membongkar file `RV180W-Firmware-1.0.5.4.img` secara presisi tanpa merusak struktur byte asli sehingga setiap komponen dapat direkonstruksi ulang.

- [ ] **Validasi Input & Cadangan Mentah:** Hitung hash `SHA-256` file sumber dan simpan salinan utuh sebagai referensi pembanding.
- [ ] **Ekstraksi Vendor Header (`vendor_header.bin`):**
  - Baca struktur header Cisco dari offset `0x00` hingga akhir blok *padding* sebelum kode mesin ARM32.
  - Simpan metadata penting: identifier model (`RV180W`), versi firmware (`1.0.5.4`), versi header (`0.1`), timestamp kompilasi, offset awal partisi, ukuran payload, dan *checksum* asli.
- [ ] **Pemisahan Kernel (`kernel_zimage.bin`):**
  - Pindai batas awal instruksi ARM32 (`zImage` decompressor stub) hingga akhir aliran *gzip* kernel, lalu simpan sebagai segmen biner tersendiri.
- [ ] **Ekstraksi Root Filesystem (`squashfs-root/`):**
  - Deteksi *superblock* SquashFS (`hsqs` / `sqsh`) dan catat parameter formatnya (**versi SquashFS**, **algoritma kompresi**, **block size**, dan **endianness**) agar hasil *repack* nanti 100% terbaca oleh kernel bawaan.
  - Ekstrak seluruh isi sistem berkas ke direktori kerja `build/squashfs-root/` dengan mempertahankan atribut izin eksekusi (`chmod`) dan *symbolic link*.

---

## 4. Fase 3: Pengembangan Proxy TLS Modern (`target-tls-proxy`)

Membangun pengganti layanan HTTPS bawaan router agar dashboard `192.168.1.1` lolos validasi keamanan browser modern.

- [ ] **Listener HTTPS Modern (TLS 1.2 & TLS 1.3):**
  - Implementasikan server TLS menggunakan `rustls` yang mendengarkan koneksi masuk pada `0.0.0.0:443`.
  - Dukung *cipher suite* modern (AES-GCM, ChaCha20-Poly1305) dan sertifikat X.509 v3 dengan ekstensi *Subject Alternative Name* (`IP:192.168.1.1`).
- [ ] **HTTP Reverse Proxy & Header Rewriting:**
  - Teruskan seluruh permintaan HTTP (`GET`, `POST`, upload konfigurasi/firmware, dan panggilan `/cgi-bin/`) dari port `443` ke server web internal router pada `127.0.0.1:80`.
  - Sesuaikan header `Host`, `Origin`, `Referer`, dan atribut `Set-Cookie` agar mekanisme sesi login bawaan RV180W tetap berfungsi normal di browser modern.
- [ ] **Efisiensi Memori (Low-Footprint):** Gunakan model *thread-pool* atau *non-blocking I/O* ringan dengan buffer tetap agar penggunaan RAM tetap rendah di perangkat keras router.

---

## 5. Fase 4: Patching Root Filesystem & Fitur Dashboard (`host-modkit/src/patcher.rs`)

Menyuntikkan komponen baru ke dalam `build/squashfs-root/` serta memperbarui antarmuka pengguna dashboard.

- [ ] **Integrasi Layanan TLS Proxy:**
  - Salin hasil kompilasi ARM32 `target-tls-proxy` ke `build/squashfs-root/usr/sbin/modern-tls-proxy` dengan izin eksekusi `0755`.
  - Modifikasi skrip *startup* di `/etc/init.d/` atau `/etc/rc.d/` untuk menonaktifkan modul SSL lama pada web server bawaan, memastikan port `80` aktif untuk koneksi lokal (`127.0.0.1` dan LAN), serta menjalankan `/usr/sbin/modern-tls-proxy` secara otomatis saat *booting*.
- [ ] **Kompatibilitas UI & Penambahan Fitur Baru di `/www`:**
  - Audit dan perbaiki kode HTML/CSS/JavaScript lawas di dalam `build/squashfs-root/www/` (seperti pemanggilan `XMLHttpRequest` sinkron atau deteksi *User-Agent* lama yang menghambat rendering di browser modern).
  - Tambahkan fitur baru sesuai kebutuhan pada menu dashboard (misalnya halaman diagnostik jaringan lanjutan, monitor beban CPU/RAM, atau pengaturan kustom via skrip CGI baru di `/www/cgi-bin/`).

---

## 6. Fase 5: Repacking Image & Rekalkulasi Header Cisco (`host-modkit/src/repacker.rs`)

Menggabungkan seluruh komponen menjadi satu file firmware baru yang valid dan siap diunggah ke router.

- [ ] **Pembuatan Image SquashFS Baru (`rootfs_mod.squashfs`):**
  - Kompres ulang direktori `build/squashfs-root/` menggunakan parameter versi SquashFS, algoritma kompresi, dan *block size* yang identik dengan hasil inspeksi pada Fase 2.
- [ ] **Perakitan Layout Biner & Padding:**
  - Gabungkan secara berurutan: `Vendor Header` + `Kernel zImage` + `rootfs_mod.squashfs`, lengkap dengan perataan byte (*alignment padding*) yang sesuai dengan layout partisi flash RV180W.
  - Verifikasi bahwa total ukuran file tidak melebihi kapasitas maksimal partisi firmware pada flash 16 MB perangkat.
- [ ] **Rekalkulasi Panjang & Checksum Header:**
  - Perbarui nilai *field* ukuran payload/image di dalam struktur *Vendor Header*.
  - Hitung ulang nilai *checksum* (CRC32/MD5 sesuai format validasi header RV180W) dan tulis kembali ke blok header agar lolos pemeriksaan integritas saat proses *Firmware Upgrade*.
  - Simpan output akhir sebagai `dist/RV180W-Firmware-1.0.5.4-MOD.img`.

---

## 7. Fase 6: Pengujian Emulasi & Prosedur Flashing Aman

Memastikan firmware hasil kloning berjalan stabil sebelum dipasang ke perangkat keras fisik.

- [ ] **Simulasi Penuh di QEMU ARM:**
  - Jalankan `kernel_zimage.bin` dan `rootfs_mod.squashfs` menggunakan `qemu-system-arm` dengan antarmuka jaringan virtual (`TAP/Bridge`) beralamat IP `192.168.1.1`.
  - Buka `https://192.168.1.1` dan `http://192.168.1.1` menggunakan browser versi terbaru (Chrome, Firefox, Edge), uji proses login, navigasi menu, penyimpanan konfigurasi, serta fitur baru yang ditambahkan.
- [ ] **Persiapan Jalur Pemulihan Hardware (Wajib):**
  - Siapkan adaptor **USB-to-TTL UART (3.3V)** yang terhubung ke header serial pada papan PCB Cisco RV180W serta server **TFTP** lokal sebagai jalur pemulihan darurat apabila terjadi kegagalan *booting*.
- [ ] **Flashing ke Router Fisik:**
  - Unggah `RV180W-Firmware-1.0.5.4-MOD.img` melalui menu *Administration -> Firmware Upgrade* pada dashboard router dan pantau log proses *booting* melalui konsol serial hingga dashboard `192.168.1.1` aktif kembali.