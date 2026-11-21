use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use backhand::{FilesystemReader, InnerNode};
use binrw::{BinRead, BinWrite};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VENDOR_HEADER_PADDED_LEN: usize = 0x200; // 512 bytes
pub const VENDOR_HEADER_STRUCT_LEN: u32 = 0x94; // 148 bytes
pub const KERNEL_PARTITION_SIZE: usize = 0x60_0000; // 6 MiB (96 * 64 KiB, matches upgrade.sh)
pub const TRAILER_LEN: usize = 0x200; // 512 bytes ("FWCHKADDISABABA\n" + padding)
pub const MAGIC1: u32 = 0x0001_1D7A;
pub const MAGIC2: u32 = 0xC3E6_E6AB;

#[derive(BinRead, BinWrite, Debug, Clone)]
#[brw(little)]
pub struct VendorHeader {
    pub reserved: u32,
    pub magic1: u32,
    pub magic2: u32,
    pub header_len: u32,
    pub fw_length: u32,
    pub checksum: u32,
    pub priority: u32,
    pub fw_version: [u8; 12],
    pub hdr_version: [u8; 12],
    pub device_name: [u8; 32],
    pub build_time: [u8; 32],
    pub image_name: [u8; 32],
}

impl VendorHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < VENDOR_HEADER_STRUCT_LEN as usize {
            bail!("buffer too small for VendorHeader ({} bytes)", bytes.len());
        }
        let mut cursor = Cursor::new(bytes);
        Self::read(&mut cursor).context("failed to parse VendorHeader via binrw")
    }

    pub fn to_padded_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(VENDOR_HEADER_PADDED_LEN);
        let mut cursor = Cursor::new(&mut buf);
        self.write(&mut cursor)
            .context("failed to serialize VendorHeader via binrw")?;
        if buf.len() != VENDOR_HEADER_STRUCT_LEN as usize {
            bail!("unexpected VendorHeader serialized size: {}", buf.len());
        }
        buf.resize(VENDOR_HEADER_PADDED_LEN, 0u8);
        Ok(buf)
    }

    pub fn fw_version_str(&self) -> String {
        cstr_from_fixed(&self.fw_version)
    }

    pub fn hdr_version_str(&self) -> String {
        cstr_from_fixed(&self.hdr_version)
    }

    pub fn device_name_str(&self) -> String {
        cstr_from_fixed(&self.device_name)
    }

    pub fn build_time_str(&self) -> String {
        cstr_from_fixed(&self.build_time)
    }

    pub fn image_name_str(&self) -> String {
        cstr_from_fixed(&self.image_name)
    }

    pub fn set_image_name(&mut self, name: &str) {
        self.image_name = [0u8; 32];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(31);
        self.image_name[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
}

pub fn cstr_from_fixed(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

/// Exact checksum algorithm verified from Ghidra decompilation of `firmImageVerify`
/// in `/pfrm2.0/bin/upgrade`: 32-bit unsigned byte-sum over the entire firmware file,
/// excluding the 4 checksum bytes at offsets 0x14..0x18.
pub fn compute_cisco_byte_sum(image: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (idx, &b) in image.iter().enumerate() {
        if (0x14..0x18).contains(&idx) {
            continue;
        }
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

pub fn verify_firmware_bytes(data: &[u8]) -> Result<VendorHeader> {
    let hdr = VendorHeader::parse(data)?;
    if hdr.reserved != 0 {
        bail!("invalid reserved value: 0x{:08x}", hdr.reserved);
    }
    if hdr.magic1 != MAGIC1 {
        bail!("invalid magic1: 0x{:08x} (expected 0x{:08x})", hdr.magic1, MAGIC1);
    }
    if hdr.magic2 != MAGIC2 {
        bail!("invalid magic2: 0x{:08x} (expected 0x{:08x})", hdr.magic2, MAGIC2);
    }
    if hdr.header_len != VENDOR_HEADER_STRUCT_LEN {
        bail!(
            "invalid header_len: 0x{:x} (expected 0x{:x})",
            hdr.header_len,
            VENDOR_HEADER_STRUCT_LEN
        );
    }
    if hdr.fw_length as usize != data.len() {
        bail!(
            "invalid firmware length: header says {} bytes, actual file is {} bytes",
            hdr.fw_length,
            data.len()
        );
    }
    let calc = compute_cisco_byte_sum(data);
    if hdr.checksum != calc {
        bail!(
            "invalid checksum: header=0x{:08x}, computed=0x{:08x}",
            hdr.checksum,
            calc
        );
    }
    if hdr.priority != 1 {
        bail!("invalid priority: {} (expected 1)", hdr.priority);
    }
    if hdr.device_name_str() != "RV180W" {
        bail!(
            "invalid device name: '{}' (expected 'RV180W')",
            hdr.device_name_str()
        );
    }
    Ok(hdr)
}

/// Deep compatibility checks for a packed RV180W image:
/// - SquashFS `hsqs` at 0x600000
/// - SquashFS 4.0 LE gzip 128 KiB, no xattr table, no COMP_OPT flag
/// - 64 KiB NOR eraseblock alignment of SquashFS segment end (before 512-byte trailer)
/// - Trailer `FWCHKADDISABABA` in last 512 bytes
pub fn verify_packed_image_compat(data: &[u8]) -> Result<()> {
    if data.len() < KERNEL_PARTITION_SIZE + TRAILER_LEN {
        bail!("image too small for RV180W layout");
    }
    if &data[KERNEL_PARTITION_SIZE..KERNEL_PARTITION_SIZE + 4] != b"hsqs" {
        bail!("SquashFS magic 'hsqs' not found at offset 0x{:x}", KERNEL_PARTITION_SIZE);
    }

    let trailer_off = data.len() - TRAILER_LEN;
    let trailer = &data[trailer_off..];
    let trailer_magic = cstr_from_fixed(trailer).trim().to_string();
    if trailer_magic != "FWCHKADDISABABA" {
        bail!(
            "invalid trailer magic at end of image: expected 'FWCHKADDISABABA', got {:?}",
            trailer_magic
        );
    }

    // SquashFS segment occupies [0x600000 .. trailer_off) and must be 64 KiB-aligned in total image layout
    // (i.e. trailer starts at a 64 KiB-aligned boundary).
    if trailer_off % 0x1_0000 != 0 {
        bail!(
            "SquashFS segment end/trailer offset 0x{:x} is not 64 KiB aligned (0x10000)",
            trailer_off
        );
    }

    let squashfs_slice = &data[KERNEL_PARTITION_SIZE..trailer_off];
    validate_squashfs_kernel_compat(squashfs_slice)?;
    Ok(())
}

/// Verify ARMv6 ELF attributes for injected binaries inside the image squashfs (best-effort).
/// Checks Tag_CPU_arch == v6, no Tag_FP_arch (soft-float), no Thumb-2.
pub fn verify_embedded_armv6_binaries(data: &[u8]) -> Result<Vec<String>> {
    let trailer_off = data.len().checked_sub(TRAILER_LEN).ok_or_else(|| anyhow!("image too small"))?;
    let squashfs_slice = &data[KERNEL_PARTITION_SIZE..trailer_off];
    let reader = FilesystemReader::from_reader(BufReader::new(Cursor::new(squashfs_slice)))
        .context("failed to read squashfs for ELF verification")?;

    let mut checked = Vec::new();
    for path in ["/bin/rv180wd", "/bin/modern-tls-proxy"] {
        let file = match reader.files().find(|n| n.fullpath.to_string_lossy() == path) {
            Some(n) => n,
            None => continue,
        };
        if let InnerNode::File(f) = &file.inner {
            let mut buf = Vec::new();
            let mut r = reader.file(f).reader();
            r.read_to_end(&mut buf)?;
            validate_armv6_elf(&buf, path)?;
            checked.push(path.to_string());
        }
    }
    Ok(checked)
}

fn validate_armv6_elf(bytes: &[u8], name: &str) -> Result<()> {
    if bytes.len() < 20 || &bytes[0..4] != b"\x7fELF" {
        bail!("{name}: not an ELF binary");
    }
    if bytes[4] != 1 {
        bail!("{name}: not ELF32 (class={})", bytes[4]);
    }
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if e_machine != 40 {
        bail!("{name}: not ARM ELF (machine={e_machine})");
    }

    // Prefer host readelf -A for authoritative ARM attribute parsing.
    if let Ok(out) = std::process::Command::new("readelf")
        .args(["-A", "/dev/stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = std::io::Write::write_all(&mut stdin, bytes);
            }
            child.wait_with_output()
        })
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            // Tag_CPU_arch: v6 / v6K / v6KZ etc. acceptable for arm11mpcore; reject v7+
            if let Some(line) = s.lines().find(|l| l.contains("Tag_CPU_arch")) {
                if line.contains("v7") || line.contains("v8") {
                    bail!("{name}: ARM attributes indicate incompatible CPU arch: {}", line.trim());
                }
                if !line.contains("v6") && !line.contains("v5") {
                    // if present but not v6-ish, be cautious
                    eprintln!("[verify] warning: {name} {}", line.trim());
                }
            }
            if s.contains("Tag_FP_arch") {
                bail!("{name}: contains Tag_FP_arch (VFP/FPU) but target requires soft-float");
            }
            if s.contains("Tag_THUMB_ISA_use: Thumb-2") {
                bail!("{name}: contains Thumb-2 ISA use; arm11mpcore/2.6.31 target expects ARMv6");
            }
            return Ok(());
        }
    }

    // Fallback heuristic: scan for obvious markers in .ARM.attributes bytes if readelf unavailable.
    let hay = String::from_utf8_lossy(bytes);
    if hay.contains("v7") && hay.contains("Tag_CPU_arch") {
        bail!("{name}: heuristic detected possible ARMv7 attributes");
    }
    Ok(())
}

pub fn verify_firmware_deep(data: &[u8]) -> Result<VendorHeader> {
    let hdr = verify_firmware_bytes(data)?;
    verify_packed_image_compat(data)?;
    let checked = verify_embedded_armv6_binaries(data)?;
    if !checked.is_empty() {
        eprintln!("[verify] ARMv6 ELF checks passed for: {}", checked.join(", "));
    }
    Ok(hdr)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SquashFsInfo {
    pub offset: usize,
    pub raw_length: usize,
    pub bytes_used: u64,
    pub version_major: u16,
    pub version_minor: u16,
    pub compression_id: u16,
    pub block_size: u32,
    pub inode_count: u32,
    pub mkfs_time: u32,
    pub endianness: String,
}

#[derive(Debug, Clone)]
pub struct SquashfsCompatInfo {
    pub version_major: u16,
    pub version_minor: u16,
    pub compression_id: u16,
    pub block_size: u32,
    pub flags: u16,
    pub xattr_id_table_start: u64,
    pub bytes_used: u64,
}

pub fn read_squashfs_superblock(bytes: &[u8]) -> Result<SquashfsCompatInfo> {
    if bytes.len() < 96 {
        bail!("buffer too small for SquashFS superblock");
    }
    let magic = &bytes[0..4];
    if magic != b"hsqs" {
        bail!("invalid SquashFS magic: {:02x?} (expected 'hsqs')", magic);
    }
    Ok(SquashfsCompatInfo {
        version_major: u16::from_le_bytes(bytes[28..30].try_into().unwrap()),
        version_minor: u16::from_le_bytes(bytes[30..32].try_into().unwrap()),
        compression_id: u16::from_le_bytes(bytes[20..22].try_into().unwrap()),
        block_size: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        flags: u16::from_le_bytes(bytes[24..26].try_into().unwrap()),
        bytes_used: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
        xattr_id_table_start: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
    })
}

/// Validate SquashFS is compatible with Linux 2.6.31.1-cavm1 (4.0 LE gzip 128KiB, no xattrs/COMP_OPT).
pub fn validate_squashfs_kernel_compat(bytes: &[u8]) -> Result<SquashfsCompatInfo> {
    let sb = read_squashfs_superblock(bytes)?;
    if sb.version_major != 4 || sb.version_minor != 0 {
        bail!(
            "SquashFS version {}.{} is not 4.0 (required by Linux 2.6.31.1)",
            sb.version_major,
            sb.version_minor
        );
    }
    if sb.compression_id != 1 {
        bail!(
            "SquashFS compression_id {} is not gzip(1) (required by Linux 2.6.31.1)",
            sb.compression_id
        );
    }
    if sb.block_size != 131072 {
        bail!(
            "SquashFS block_size {} is not 131072 (128 KiB)",
            sb.block_size
        );
    }
    if sb.xattr_id_table_start != 0xffff_ffff_ffff_ffff {
        bail!(
            "SquashFS has xattr table (0x{:016x}); Linux 2.6.31.1 does not support xattrs",
            sb.xattr_id_table_start
        );
    }
    const COMP_OPT: u16 = 0x0400;
    if sb.flags & COMP_OPT != 0 {
        bail!(
            "SquashFS COMP_OPT flag set (flags=0x{:04x}); Linux 2.6.31.1 may reject it",
            sb.flags
        );
    }
    Ok(sb)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudoNode {
    pub path: String,
    #[serde(rename = "type")]
    pub node_type: String, // "dir", "char", "block", "fifo", "socket"
    pub mode: u16,
    pub uid: u16,
    pub gid: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub major: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minor: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PseudoNodesFile {
    pub nodes: Vec<PseudoNode>,
}

impl PseudoNodesFile {
    pub fn path(work_dir: &Path) -> PathBuf {
        work_dir.join("pseudo_nodes.json")
    }

    pub fn load(work_dir: &Path) -> Result<Self> {
        let p = Self::path(work_dir);
        if !p.exists() {
            return Ok(Self::default());
        }
        let s = fs::read_to_string(&p)
            .with_context(|| format!("failed to read {}", p.display()))?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn save(&self, work_dir: &Path) -> Result<()> {
        let p = Self::path(work_dir);
        let f = File::create(&p).with_context(|| format!("failed to create {}", p.display()))?;
        serde_json::to_writer_pretty(BufWriter::new(f), self)?;
        Ok(())
    }

    /// Generate mksquashfs -pf pseudo file entries for special nodes and directory modes.
    /// Format: https://github.com/plougher/squashfs-tools (pseudo file definitions)
    pub fn write_mksquashfs_pf(&self, path: &Path) -> Result<()> {
        let mut out = String::new();
        for n in &self.nodes {
            let rel = n.path.trim_start_matches('/');
            if rel.is_empty() {
                continue;
            }
            match n.node_type.as_str() {
                "dir" => {
                    // 'm' modifies attributes of existing path
                    out.push_str(&format!(
                        "{} m {:o} {} {}\n",
                        rel, n.mode & 0o7777, n.uid, n.gid
                    ));
                }
                "char" => {
                    let maj = n.major.unwrap_or(0);
                    let min = n.minor.unwrap_or(0);
                    out.push_str(&format!(
                        "{} c {:o} {} {} {} {}\n",
                        rel, n.mode & 0o7777, n.uid, n.gid, maj, min
                    ));
                }
                "block" => {
                    let maj = n.major.unwrap_or(0);
                    let min = n.minor.unwrap_or(0);
                    out.push_str(&format!(
                        "{} b {:o} {} {} {} {}\n",
                        rel, n.mode & 0o7777, n.uid, n.gid, maj, min
                    ));
                }
                "fifo" => {
                    out.push_str(&format!(
                        "{} p {:o} {} {}\n",
                        rel, n.mode & 0o7777, n.uid, n.gid
                    ));
                }
                "socket" => {
                    out.push_str(&format!(
                        "{} s {:o} {} {}\n",
                        rel, n.mode & 0o7777, n.uid, n.gid
                    ));
                }
                _ => {}
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, out).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

/// Decode Linux/SquashFS 4.0 device number to (major, minor).
pub fn decode_dev(dev: u32) -> (u32, u32) {
    let major = (dev & 0xfff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    (major, minor)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackManifest {
    pub source_sha256: String,
    pub source_crc32: u32,
    pub source_size: usize,
    pub fw_version: String,
    pub hdr_version: String,
    pub device_name: String,
    pub build_time: String,
    pub image_name: String,
    pub header_checksum: String,
    pub kernel_offset: usize,
    pub kernel_gzip_offset: Option<usize>,
    pub kernel_version_banner: Option<String>,
    pub kernel_partition_size: usize,
    pub squashfs: SquashFsInfo,
    pub trailer_offset: usize,
    pub trailer_length: usize,
    pub trailer_magic: String,
    pub extracted_files: usize,
    pub extracted_dirs: usize,
    pub extracted_symlinks: usize,
    #[serde(default)]
    pub extracted_special_nodes: usize,
}

fn find_pattern(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|pos| start + pos)
}

fn extract_kernel_banner(kernel_gzip_slice: &[u8]) -> Option<String> {
    let mut decoder = GzDecoder::new(kernel_gzip_slice);
    let mut decompressed = Vec::new();
    // Ignore trailing garbage after gzip stream (embedded initrd follows).
    let _ = decoder.read_to_end(&mut decompressed);
    if decompressed.is_empty() {
        return None;
    }
    let needle = b"Linux version ";
    let pos = find_pattern(&decompressed, needle, 0)?;
    let end = decompressed[pos..]
        .iter()
        .position(|&b| b == 0 || b == b'\n')
        .unwrap_or(160)
        .min(200);
    Some(String::from_utf8_lossy(&decompressed[pos..pos + end]).trim().to_string())
}

fn sanitize_rel_path(fullpath: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for comp in fullpath.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => clean.push(part),
            Component::ParentDir => {
                bail!("path traversal component '..' detected in {:?}", fullpath);
            }
            Component::Prefix(_) => {
                bail!("unexpected path prefix in {:?}", fullpath);
            }
        }
    }
    Ok(clean)
}

fn parse_squashfs_superblock(slice: &[u8], offset: usize) -> Result<SquashFsInfo> {
    if slice.len() < 48 {
        bail!("SquashFS slice too short");
    }
    let magic = &slice[0..4];
    let endianness = match magic {
        b"hsqs" => "little-endian",
        b"sqsh" => "big-endian",
        _ => bail!("invalid SquashFS magic at 0x{:x}: {:02x?}", offset, magic),
    };
    let inodes = u32::from_le_bytes(slice[4..8].try_into()?);
    let mkfs_time = u32::from_le_bytes(slice[8..12].try_into()?);
    let block_size = u32::from_le_bytes(slice[12..16].try_into()?);
    let comp = u16::from_le_bytes(slice[20..22].try_into()?);
    let s_major = u16::from_le_bytes(slice[28..30].try_into()?);
    let s_minor = u16::from_le_bytes(slice[30..32].try_into()?);
    let bytes_used = u64::from_le_bytes(slice[40..48].try_into()?);

    Ok(SquashFsInfo {
        offset,
        raw_length: slice.len(),
        bytes_used,
        version_major: s_major,
        version_minor: s_minor,
        compression_id: comp,
        block_size,
        inode_count: inodes,
        mkfs_time,
        endianness: endianness.to_string(),
    })
}

pub fn unpack_firmware(input_path: &Path, work_dir: &Path) -> Result<UnpackManifest> {
    let data = fs::read(input_path)
        .with_context(|| format!("failed to read firmware image {}", input_path.display()))?;

    let sha256 = hex::encode(Sha256::digest(&data));
    let crc32 = crc32fast::hash(&data);

    let hdr = verify_firmware_bytes(&data)
        .context("input firmware failed Cisco RV180W firmImageVerify validation")?;

    fs::create_dir_all(work_dir)
        .with_context(|| format!("failed to create work dir {}", work_dir.display()))?;

    // Save untouched raw reference backup
    let backup_path = work_dir.join("original_backup.img");
    if !backup_path.exists() {
        fs::write(&backup_path, &data)?;
    }

    // 1. Vendor header (0x000..0x200)
    fs::write(work_dir.join("vendor_header.bin"), &data[..VENDOR_HEADER_PADDED_LEN])?;

    // 2. Kernel + embedded rootfs.ext2.gz partition (0x200..0x600000)
    let squashfs_offset = find_pattern(&data, b"hsqs", VENDOR_HEADER_PADDED_LEN)
        .ok_or_else(|| anyhow!("SquashFS magic 'hsqs' not found in firmware image"))?;
    if squashfs_offset != KERNEL_PARTITION_SIZE {
        bail!(
            "unexpected SquashFS offset 0x{:x} (expected 0x{:x})",
            squashfs_offset,
            KERNEL_PARTITION_SIZE
        );
    }

    let kernel_gzip_offset = find_pattern(&data[..squashfs_offset], &[0x1f, 0x8b, 0x08], VENDOR_HEADER_PADDED_LEN);
    let kernel_banner = kernel_gzip_offset.and_then(|off| extract_kernel_banner(&data[off..squashfs_offset]));

    fs::write(
        work_dir.join("kernel_zimage.bin"),
        &data[VENDOR_HEADER_PADDED_LEN..squashfs_offset],
    )?;

    // 3. Trailer detection (last 512 bytes: "FWCHKADDISABABA\n" + zero padding)
    let trailer_offset = data
        .len()
        .checked_sub(TRAILER_LEN)
        .ok_or_else(|| anyhow!("firmware image smaller than trailer length"))?;
    let trailer_bytes = &data[trailer_offset..];
    let trailer_magic = cstr_from_fixed(trailer_bytes).trim().to_string();
    fs::write(work_dir.join("trailer.bin"), trailer_bytes)?;

    // 4. SquashFS segment (0x600000 .. trailer_offset)
    let squashfs_slice = &data[squashfs_offset..trailer_offset];
    let squashfs_info = parse_squashfs_superblock(squashfs_slice, squashfs_offset)?;
    let sqsh_path = work_dir.join("rootfs_orig.squashfs");
    fs::write(&sqsh_path, squashfs_slice)?;

    // 5. Extract SquashFS via pure-Rust `backhand`
    let root_out = work_dir.join("squashfs-root");
    if root_out.exists() {
        fs::remove_dir_all(&root_out)?;
    }
    fs::create_dir_all(&root_out)?;

    let sqsh_file = BufReader::new(File::open(&sqsh_path)?);
    let fs_reader = FilesystemReader::from_reader(sqsh_file)
        .context("backhand failed to parse SquashFS 4.0 LE image")?;

    let mut file_count = 0usize;
    let mut dir_count = 0usize;
    let mut symlink_count = 0usize;
    let mut special_count = 0usize;
    let mut pseudo = PseudoNodesFile::default();

    // Pass 1: directories first so parent dirs exist (keep writable for extraction)
    for node in fs_reader.files() {
        if let InnerNode::Dir(_) = &node.inner {
            let rel = sanitize_rel_path(&node.fullpath)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            let target = root_out.join(&rel);
            fs::create_dir_all(&target)?;
            let orig_mode = (node.header.permissions & 0o7777) as u16;
            pseudo.nodes.push(PseudoNode {
                path: format!("/{}", rel.display()),
                node_type: "dir".to_string(),
                mode: orig_mode,
                uid: node.header.uid as u16,
                gid: node.header.gid as u16,
                major: None,
                minor: None,
                device_number: None,
            });
            dir_count += 1;
        }
    }

    // Pass 2: regular files, symlinks, and special nodes (record special nodes for repack)
    for node in fs_reader.files() {
        let rel = sanitize_rel_path(&node.fullpath)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = root_out.join(&rel);
        let path_str = format!("/{}", rel.display());
        let mode = (node.header.permissions & 0o7777) as u16;
        let uid = node.header.uid as u16;
        let gid = node.header.gid as u16;
        match &node.inner {
            InnerNode::File(f) => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut reader = fs_reader.file(f).reader();
                let mut out_file = File::create(&target)?;
                std::io::copy(&mut reader, &mut out_file)?;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode as u32))?;
                file_count += 1;
            }
            InnerNode::Symlink(s) => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                if target.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&target);
                }
                symlink(&s.link, &target)?;
                symlink_count += 1;
            }
            InnerNode::Dir(_) => {}
            InnerNode::CharacterDevice(dev) => {
                let (maj, min) = decode_dev(dev.device_number);
                pseudo.nodes.push(PseudoNode {
                    path: path_str,
                    node_type: "char".to_string(),
                    mode,
                    uid,
                    gid,
                    major: Some(maj),
                    minor: Some(min),
                    device_number: Some(dev.device_number),
                });
                special_count += 1;
            }
            InnerNode::BlockDevice(dev) => {
                let (maj, min) = decode_dev(dev.device_number);
                pseudo.nodes.push(PseudoNode {
                    path: path_str,
                    node_type: "block".to_string(),
                    mode,
                    uid,
                    gid,
                    major: Some(maj),
                    minor: Some(min),
                    device_number: Some(dev.device_number),
                });
                special_count += 1;
            }
            InnerNode::NamedPipe => {
                pseudo.nodes.push(PseudoNode {
                    path: path_str,
                    node_type: "fifo".to_string(),
                    mode,
                    uid,
                    gid,
                    major: None,
                    minor: None,
                    device_number: None,
                });
                special_count += 1;
            }
            InnerNode::Socket => {
                pseudo.nodes.push(PseudoNode {
                    path: path_str,
                    node_type: "socket".to_string(),
                    mode,
                    uid,
                    gid,
                    major: None,
                    minor: None,
                    device_number: None,
                });
                special_count += 1;
            }
        }
    }

    // Persist special nodes / original metadata for repack (mksquashfs -pf and backhand replay)
    pseudo.save(work_dir)?;
    pseudo.write_mksquashfs_pf(&work_dir.join("pseudo_nodes.txt"))?;

    // Pass 3: make extracted directories writable for patching (original modes preserved in pseudo_nodes.json)
    for node in fs_reader.files() {
        if let InnerNode::Dir(_) = &node.inner {
            let rel = sanitize_rel_path(&node.fullpath)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            let target = root_out.join(&rel);
            let mode = ((node.header.permissions as u32) & 0o7777) | 0o700;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
        }
    }

    let manifest = UnpackManifest {
        source_sha256: sha256,
        source_crc32: crc32,
        source_size: data.len(),
        fw_version: hdr.fw_version_str(),
        hdr_version: hdr.hdr_version_str(),
        device_name: hdr.device_name_str(),
        build_time: hdr.build_time_str(),
        image_name: hdr.image_name_str(),
        header_checksum: format!("0x{:08x}", hdr.checksum),
        kernel_offset: VENDOR_HEADER_PADDED_LEN,
        kernel_gzip_offset,
        kernel_version_banner: kernel_banner,
        kernel_partition_size: KERNEL_PARTITION_SIZE,
        squashfs: squashfs_info,
        trailer_offset,
        trailer_length: TRAILER_LEN,
        trailer_magic,
        extracted_files: file_count,
        extracted_dirs: dir_count,
        extracted_symlinks: symlink_count,
        extracted_special_nodes: special_count,
    };

    fs::write(
        work_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    Ok(manifest)
}
