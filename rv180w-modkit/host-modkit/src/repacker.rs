use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufWriter;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use backhand::compression::Compressor;
use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::unpacker::{
    compute_cisco_byte_sum, verify_firmware_bytes, PseudoNodesFile, UnpackManifest, VendorHeader,
    KERNEL_PARTITION_SIZE, VENDOR_HEADER_PADDED_LEN,
};

const SQUASHFS_ALIGN: usize = 0x1_0000; // 64 KiB SPI NOR eraseblock alignment before trailer
const DEFAULT_MAX_IMAGE_BYTES: usize = 26 * 1024 * 1024; // Safety cap for RV180W 32 MB flash
pub const TRAILER_MAGIC: &[u8] = b"FWCHKADDISABABA\n";



pub struct RepackReport {
    pub output_path: String,
    pub squashfs_bytes: usize,
    pub total_image_bytes: usize,
    pub size_delta_bytes: isize,
    pub checksum_hex: String,
    pub crc32_hex: String,
    pub sha256_hex: String,
    pub squashfs_backend: String,
}

fn restore_dir_modes_from_pseudo(rootfs_dir: &Path, pseudo: &PseudoNodesFile) {
    for n in &pseudo.nodes {
        if n.node_type != "dir" {
            continue;
        }
        let rel = n.path.trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }
        let target = rootfs_dir.join(rel);
        if target.is_dir() {
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode((n.mode & 0o7777) as u32));
        }
    }
}

pub fn build_squashfs_mksquashfs(
    work_dir: &Path,
    rootfs_dir: &Path,
    out_squashfs: &Path,
) -> Result<usize> {
    if out_squashfs.exists() {
        let _ = fs::remove_file(out_squashfs);
    }
    let pf = work_dir.join("pseudo_nodes.txt");
    let mut cmd = Command::new("mksquashfs");
    cmd.arg(rootfs_dir)
        .arg(out_squashfs)
        .args(["-comp", "gzip"])
        .args(["-b", "131072"])
        .arg("-no-xattrs")
        .arg("-all-root")
        .arg("-noappend");
    if pf.exists() {
        cmd.arg("-pf").arg(&pf);
    }
    let status = cmd
        .status()
        .with_context(|| "failed to execute mksquashfs")?;
    if !status.success() {
        bail!("mksquashfs failed with status {status}");
    }
    let len = fs::metadata(out_squashfs)?.len() as usize;
    Ok(len)
}

pub fn build_squashfs_pure_rust(
    work_dir: &Path,
    rootfs_dir: &Path,
    out_squashfs: &Path,
    block_size: u32,
    mkfs_time: u32,
) -> Result<usize> {
    let pseudo = PseudoNodesFile::load(work_dir)?;
    // Build lookup for original dir modes/owners
    let mut dir_meta: HashMap<String, (u16, u16, u16)> = HashMap::new();
    for n in &pseudo.nodes {
        if n.node_type == "dir" {
            dir_meta.insert(n.path.clone(), (n.mode & 0o7777, n.uid, n.gid));
        }
    }

    let mut writer = FilesystemWriter::default();
    writer.set_time(mkfs_time);
    writer.set_block_size(block_size);
    writer.set_compressor(FilesystemCompressor::new(Compressor::Gzip, None)?);
    writer.set_root_uid(0);
    writer.set_root_gid(0);

    let mut entries: Vec<_> = WalkDir::new(rootfs_dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    for entry in entries.drain(..) {
        let path = entry.path();
        let rel = path
            .strip_prefix(rootfs_dir)
            .context("failed to strip rootfs prefix")?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let sqsh_path = Path::new("/").join(rel);
        let sqsh_path_str = format!("/{}", rel.display());
        let meta = fs::symlink_metadata(path)?;
        let ft = meta.file_type();

        if ft.is_dir() {
            let (perms, uid, gid) = dir_meta
                .get(&sqsh_path_str)
                .copied()
                .unwrap_or(((meta.permissions().mode() & 0o7777) as u16, 0, 0));
            let header = NodeHeader {
                permissions: perms,
                uid: uid as u32,
                gid: gid as u32,
                mtime: mkfs_time,
            };
            writer
                .push_dir(&sqsh_path, header)
                .with_context(|| format!("push_dir failed for {:?}", sqsh_path))?;
        } else if ft.is_symlink() {
            let perms = (meta.permissions().mode() & 0o7777) as u16;
            let header = NodeHeader { permissions: perms, uid: 0, gid: 0, mtime: mkfs_time };
            let link_target = fs::read_link(path)?;
            let target_str = link_target
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 symlink target at {:?}", path))?;
            writer
                .push_symlink(target_str, &sqsh_path, header)
                .with_context(|| format!("push_symlink failed for {:?}", sqsh_path))?;
        } else if ft.is_file() {
            let perms = (meta.permissions().mode() & 0o7777) as u16;
            let header = NodeHeader { permissions: perms, uid: 0, gid: 0, mtime: mkfs_time };
            let f = File::open(path)
                .with_context(|| format!("failed to open file {:?}", path))?;
            writer
                .push_file(f, &sqsh_path, header)
                .with_context(|| format!("push_file failed for {:?}", sqsh_path))?;
        }
    }

    // Replay special nodes (device nodes, FIFOs, sockets) from unpack metadata
    for n in &pseudo.nodes {
        if n.node_type == "dir" {
            continue;
        }
        let sqsh_path = Path::new(&n.path);
        let header = NodeHeader {
            permissions: n.mode & 0o7777,
            uid: n.uid as u32,
            gid: n.gid as u32,
            mtime: mkfs_time,
        };
        match n.node_type.as_str() {
            "char" => {
                let dev = n.device_number.unwrap_or(0);
                writer.push_char_device(dev, sqsh_path, header)?;
            }
            "block" => {
                let dev = n.device_number.unwrap_or(0);
                writer.push_block_device(dev, sqsh_path, header)?;
            }
            "fifo" => {
                writer.push_fifo(sqsh_path, header)?;
            }
            "socket" => {
                writer.push_socket(sqsh_path, header)?;
            }
            _ => {}
        }
    }

    let out_file = File::create(out_squashfs)
        .with_context(|| format!("failed to create {}", out_squashfs.display()))?;
    let mut buf_writer = BufWriter::new(out_file);
    writer
        .write(&mut buf_writer)
        .context("backhand failed to write SquashFS 4.0 LE gzip image")?;
    drop(buf_writer);

    let len = fs::metadata(out_squashfs)?.len() as usize;
    Ok(len)
}

pub fn build_squashfs(
    work_dir: &Path,
    rootfs_dir: &Path,
    out_squashfs: &Path,
    block_size: u32,
    mkfs_time: u32,
) -> Result<(usize, String)> {
    // Restore original dir modes on disk when possible (best-effort) for correct packing.
    if let Ok(pseudo) = PseudoNodesFile::load(work_dir) {
        restore_dir_modes_from_pseudo(rootfs_dir, &pseudo);
    }

    // Prefer mksquashfs for strict Linux 2.6.31.1 compatibility (no xattrs/COMP_OPT quirks).
    match build_squashfs_mksquashfs(work_dir, rootfs_dir, out_squashfs) {
        Ok(len) => {
            let bytes = fs::read(out_squashfs)?;
            match crate::unpacker::validate_squashfs_kernel_compat(&bytes) {
                Ok(_) => return Ok((len, "mksquashfs".to_string())),
                Err(e) => {
                    eprintln!("[repacker] WARNING: mksquashfs output failed compat check: {e}; falling back to backhand");
                    let _ = fs::remove_file(out_squashfs);
                }
            }
        }
        Err(e) => {
            eprintln!("[repacker] mksquashfs unavailable/failed ({e}); trying pure-Rust backhand");
            let _ = fs::remove_file(out_squashfs);
        }
    }

    // Re-ensure dirs are writable for backhand's internal operations if needed
    if let Ok(pseudo) = PseudoNodesFile::load(work_dir) {
        for n in &pseudo.nodes {
            if n.node_type == "dir" {
                let rel = n.path.trim_start_matches('/');
                if rel.is_empty() { continue; }
                let t = rootfs_dir.join(rel);
                if t.is_dir() {
                    let _ = fs::set_permissions(&t, fs::Permissions::from_mode(((n.mode & 0o7777) | 0o700) as u32));
                }
            }
        }
    }

    let len = build_squashfs_pure_rust(work_dir, rootfs_dir, out_squashfs, block_size, mkfs_time)?;
    let bytes = fs::read(out_squashfs)?;
    crate::unpacker::validate_squashfs_kernel_compat(&bytes)
        .context("backhand-produced SquashFS is not compatible with Linux 2.6.31.1-cavm1")?;
    Ok((len, "backhand".to_string()))
}

pub fn repack_firmware(
    work_dir: &Path,
    output_path: &Path,
    max_image_bytes: Option<usize>,
) -> Result<RepackReport> {
    let manifest_raw = fs::read_to_string(work_dir.join("manifest.json"))
        .context("missing manifest.json — run `unpack` first")?;
    let manifest: UnpackManifest = serde_json::from_str(&manifest_raw)?;

    let vendor_hdr_raw = fs::read(work_dir.join("vendor_header.bin"))?;
    let kernel_zimage = fs::read(work_dir.join("kernel_zimage.bin"))?;
    let trailer = fs::read(work_dir.join("trailer.bin"))?;

    if vendor_hdr_raw.len() != VENDOR_HEADER_PADDED_LEN {
        bail!(
            "vendor_header.bin must be {} bytes, got {}",
            VENDOR_HEADER_PADDED_LEN,
            vendor_hdr_raw.len()
        );
    }
    if VENDOR_HEADER_PADDED_LEN + kernel_zimage.len() != KERNEL_PARTITION_SIZE {
        bail!(
            "header + kernel_zimage must equal exact 6 MiB kernel partition ({}), got {}",
            KERNEL_PARTITION_SIZE,
            VENDOR_HEADER_PADDED_LEN + kernel_zimage.len()
        );
    }

    let rootfs_dir = work_dir.join("squashfs-root");
    let sqsh_out = work_dir.join("rootfs_mod.squashfs");
    let (sqsh_len, backend) = build_squashfs(
        work_dir,
        &rootfs_dir,
        &sqsh_out,
        manifest.squashfs.block_size,
        manifest.squashfs.mkfs_time,
    )?;
    let sqsh_bytes = fs::read(&sqsh_out)?;

    // Assemble final firmware binary with exact RV180W flash layout:
    // [0x000000..0x000200] Vendor Header (updated below)
    // [0x000200..0x600000] Kernel zImage + embedded rootfs.ext2.gz + padding
    // [0x600000..aligned]  New SquashFS 4.0 LE Gzip 128KiB padded to 64 KiB NOR eraseblock boundary
    // [aligned..+512]      Original FWCHKADDISABABA trailer
    let mut image = Vec::with_capacity(KERNEL_PARTITION_SIZE + sqsh_bytes.len() + SQUASHFS_ALIGN + trailer.len());
    image.extend_from_slice(&vendor_hdr_raw);
    image.extend_from_slice(&kernel_zimage);
    assert_eq!(image.len(), KERNEL_PARTITION_SIZE);

    image.extend_from_slice(&sqsh_bytes);
    let rem = image.len() % SQUASHFS_ALIGN;
    if rem != 0 {
        image.resize(image.len() + (SQUASHFS_ALIGN - rem), 0u8);
    }
    image.extend_from_slice(&trailer);

    let limit = max_image_bytes.unwrap_or(DEFAULT_MAX_IMAGE_BYTES);
    if image.len() > limit {
        bail!(
            "repacked firmware ({} bytes) exceeds safety limit ({} bytes)",
            image.len(),
            limit
        );
    }

    // Update VendorHeader fields (fw_length, image_name, and Cisco byte-sum checksum)
    let mut hdr = VendorHeader::parse(&vendor_hdr_raw)?;
    hdr.fw_length = image.len() as u32;
    if let Some(fname) = output_path.file_name().and_then(|n| n.to_str()) {
        hdr.set_image_name(fname);
    }
    hdr.checksum = 0;

    let padded_hdr_zero_chk = hdr.to_padded_bytes()?;
    image[..VENDOR_HEADER_PADDED_LEN].copy_from_slice(&padded_hdr_zero_chk);

    let new_checksum = compute_cisco_byte_sum(&image);
    hdr.checksum = new_checksum;
    let padded_hdr_final = hdr.to_padded_bytes()?;
    image[..VENDOR_HEADER_PADDED_LEN].copy_from_slice(&padded_hdr_final);

    // Self-verify using the exact `firmImageVerify` rules + deep image checks!
    verify_firmware_bytes(&image)
        .context("repacked firmware failed internal firmImageVerify self-check")?;
    crate::unpacker::verify_packed_image_compat(&image)?;

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output_path, &image)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    let sha256 = hex::encode(Sha256::digest(&image));
    let crc32 = crc32fast::hash(&image);

    Ok(RepackReport {
        output_path: output_path.display().to_string(),
        squashfs_bytes: sqsh_len,
        total_image_bytes: image.len(),
        size_delta_bytes: image.len() as isize - manifest.source_size as isize,
        checksum_hex: format!("0x{:08x}", new_checksum),
        crc32_hex: format!("0x{:08x}", crc32),
        sha256_hex: sha256,
        squashfs_backend: backend,
    })
}
