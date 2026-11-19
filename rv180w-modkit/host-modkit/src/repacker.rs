use std::fs::{self, File};
use std::io::BufWriter;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use backhand::compression::Compressor;
use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::unpacker::{
    compute_cisco_byte_sum, verify_firmware_bytes, UnpackManifest, VendorHeader,
    KERNEL_PARTITION_SIZE, VENDOR_HEADER_PADDED_LEN,
};

const SQUASHFS_ALIGN: usize = 0x1000; // 4 KiB alignment before FWCHKADDISABABA trailer
const DEFAULT_MAX_IMAGE_BYTES: usize = 26 * 1024 * 1024; // Safety cap for RV180W 32 MB flash

pub struct RepackReport {
    pub output_path: String,
    pub squashfs_bytes: usize,
    pub total_image_bytes: usize,
    pub size_delta_bytes: isize,
    pub checksum_hex: String,
    pub crc32_hex: String,
    pub sha256_hex: String,
}

pub fn build_squashfs_pure_rust(
    rootfs_dir: &Path,
    out_squashfs: &Path,
    block_size: u32,
    mkfs_time: u32,
) -> Result<usize> {
    let mut writer = FilesystemWriter::default();
    writer.set_time(mkfs_time);
    writer.set_block_size(block_size);
    writer.set_compressor(FilesystemCompressor::new(Compressor::Gzip, None)?);
    writer.set_root_uid(0);
    writer.set_root_gid(0);

    // Deterministic sorted traversal so builds are clean and reproducible.
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
        let meta = fs::symlink_metadata(path)?;
        let perms = (meta.permissions().mode() & 0o7777) as u16;
        let header = NodeHeader {
            permissions: perms,
            uid: 0,
            gid: 0,
            mtime: mkfs_time,
        };

        let ft = meta.file_type();
        if ft.is_dir() {
            writer
                .push_dir(&sqsh_path, header)
                .with_context(|| format!("push_dir failed for {:?}", sqsh_path))?;
        } else if ft.is_symlink() {
            let link_target = fs::read_link(path)?;
            let target_str = link_target
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non-UTF8 symlink target at {:?}", path))?;
            writer
                .push_symlink(target_str, &sqsh_path, header)
                .with_context(|| format!("push_symlink failed for {:?}", sqsh_path))?;
        } else if ft.is_file() {
            let f = File::open(path)
                .with_context(|| format!("failed to open file {:?}", path))?;
            writer
                .push_file(f, &sqsh_path, header)
                .with_context(|| format!("push_file failed for {:?}", sqsh_path))?;
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
    let sqsh_len = build_squashfs_pure_rust(
        &rootfs_dir,
        &sqsh_out,
        manifest.squashfs.block_size,
        manifest.squashfs.mkfs_time,
    )?;
    let sqsh_bytes = fs::read(&sqsh_out)?;

    // Assemble final firmware binary with exact RV180W flash layout:
    // [0x000000..0x000200] Vendor Header (updated below)
    // [0x000200..0x600000] Kernel zImage + embedded rootfs.ext2.gz + padding
    // [0x600000..aligned]  New SquashFS 4.0 LE Gzip 128KiB padded to 4 KiB boundary
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

    // Self-verify using the exact `firmImageVerify` rules!
    verify_firmware_bytes(&image)
        .context("repacked firmware failed internal firmImageVerify self-check")?;

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
    })
}
