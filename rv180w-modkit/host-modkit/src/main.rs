mod patcher;
mod repacker;
mod unpacker;

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(
    name = "host-modkit",
    version,
    about = "Cisco RV180W v1.0.5.4 Rust Firmware Clone & Modern TLS Mod Kit"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Unpack RV180W firmware into header, kernel zImage, trailer, and SquashFS root
    Unpack {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value = "build")]
        work_dir: PathBuf,
    },
    /// Patch extracted squashfs-root (v2 proxy mode with --proxy-bin, or v3 rv180w-next mode with --rv180wd-bin)
    Patch {
        #[arg(short, long, default_value = "build")]
        work_dir: PathBuf,
        #[arg(short, long)]
        proxy_bin: Option<PathBuf>,
        #[arg(long)]
        rv180wd_bin: Option<PathBuf>,
    },
    /// Repack patched squashfs-root into a checksum-valid RV180W firmware image
    Repack {
        #[arg(short, long, default_value = "build")]
        work_dir: PathBuf,
        #[arg(short, long, default_value = "dist/RV180W-Firmware-1.0.5.4-MOD.img")]
        output: PathBuf,
        #[arg(long)]
        max_image_bytes: Option<usize>,
    },
    /// Run full Unpack -> Patch -> Repack pipeline in one command
    Build {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        proxy_bin: Option<PathBuf>,
        #[arg(long)]
        rv180wd_bin: Option<PathBuf>,
        #[arg(short, long, default_value = "build")]
        work_dir: PathBuf,
        #[arg(short, long, default_value = "dist/RV180W-Firmware-1.0.5.4-MOD.img")]
        output: PathBuf,
        #[arg(long)]
        max_image_bytes: Option<usize>,
    },
    /// Verify a Cisco RV180W firmware image against exact firmImageVerify header rules
    Verify {
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Unpack { input, work_dir } => {
            let m = unpacker::unpack_firmware(&input, &work_dir)?;
            println!("[OK] Unpacked {}", input.display());
            println!("  SHA-256      : {}", m.source_sha256);
            println!("  Device / Ver : {} v{} (hdr v{})", m.device_name, m.fw_version, m.hdr_version);
            println!("  Checksum     : {} (verified)", m.header_checksum);
            if let Some(ref k) = m.kernel_version_banner {
                println!("  Kernel       : {}", k);
            }
            println!(
                "  SquashFS     : v{}.{} {} comp={} block={} inodes={} ({} bytes)",
                m.squashfs.version_major,
                m.squashfs.version_minor,
                m.squashfs.endianness,
                m.squashfs.compression_id,
                m.squashfs.block_size,
                m.squashfs.inode_count,
                m.squashfs.bytes_used
            );
            println!(
                "  Extracted    : {} files, {} dirs, {} symlinks -> {}/squashfs-root",
                m.extracted_files,
                m.extracted_dirs,
                m.extracted_symlinks,
                work_dir.display()
            );
        }
        Commands::Patch {
            work_dir,
            proxy_bin,
            rv180wd_bin,
        } => {
            let r = match (rv180wd_bin, proxy_bin) {
                (Some(bin), _) => patcher::patch_rootfs_next(&work_dir, &bin)?,
                (None, Some(bin)) => patcher::patch_rootfs(&work_dir, &bin)?,
                (None, None) => anyhow::bail!("provide either --rv180wd-bin (v3) or --proxy-bin (v2)"),
            };
            println!("[OK] Patched {}/squashfs-root", work_dir.display());
            println!("  ARM32 binary : {} bytes (ELF32 ARM verified)", r.proxy_size_bytes);
            for item in &r.patched_files {
                println!("  + {}", item);
            }
        }
        Commands::Repack {
            work_dir,
            output,
            max_image_bytes,
        } => {
            let r = repacker::repack_firmware(&work_dir, &output, max_image_bytes)?;
            println!("[OK] Repacked -> {}", r.output_path);
            println!("  SquashFS     : {} bytes", r.squashfs_bytes);
            println!("  Total Size   : {} bytes (delta {:+} bytes)", r.total_image_bytes, r.size_delta_bytes);
            println!("  Cisco Sum    : {} (firmImageVerify PASS)", r.checksum_hex);
            println!("  CRC32        : {}", r.crc32_hex);
            println!("  SHA-256      : {}", r.sha256_hex);
        }
        Commands::Build {
            input,
            proxy_bin,
            rv180wd_bin,
            work_dir,
            output,
            max_image_bytes,
        } => {
            println!("==> [1/3] Unpacking {}...", input.display());
            let m = unpacker::unpack_firmware(&input, &work_dir)?;
            println!(
                "    Verified {} v{}, {} files / {} dirs / {} symlinks extracted.",
                m.device_name, m.fw_version, m.extracted_files, m.extracted_dirs, m.extracted_symlinks
            );

            println!("==> [2/3] Patching root filesystem...");
            let p = match (rv180wd_bin, proxy_bin) {
                (Some(bin), _) => patcher::patch_rootfs_next(&work_dir, &bin)?,
                (None, Some(bin)) => patcher::patch_rootfs(&work_dir, &bin)?,
                (None, None) => anyhow::bail!("provide either --rv180wd-bin (v3) or --proxy-bin (v2)"),
            };
            println!(
                "    Injected ARM32 binary ({} bytes) and {} patches.",
                p.proxy_size_bytes,
                p.patched_files.len()
            );

            println!("==> [3/3] Repacking & recalculating Cisco header checksum...");
            let r = repacker::repack_firmware(&work_dir, &output, max_image_bytes)?;
            println!("[SUCCESS] Built {}", r.output_path);
            println!("  SquashFS     : {} bytes", r.squashfs_bytes);
            println!("  Total Size   : {} bytes (delta {:+} bytes)", r.total_image_bytes, r.size_delta_bytes);
            println!("  Cisco Sum    : {} (firmImageVerify PASS)", r.checksum_hex);
            println!("  SHA-256      : {}", r.sha256_hex);
        }
        Commands::Verify { input } => {
            let data = fs::read(&input)?;
            let hdr = unpacker::verify_firmware_bytes(&data)?;
            let sha256 = hex::encode(Sha256::digest(&data));
            println!("[PASS] {} passed exact Cisco RV180W firmImageVerify!", input.display());
            println!("  Device       : {}", hdr.device_name_str());
            println!("  Version      : {} (hdr {})", hdr.fw_version_str(), hdr.hdr_version_str());
            println!("  Image Name   : {}", hdr.image_name_str());
            println!("  Total Bytes  : {} (0x{:x})", hdr.fw_length, hdr.fw_length);
            println!("  Checksum     : 0x{:08x}", hdr.checksum);
            println!("  SHA-256      : {}", sha256);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::unpacker::{compute_cisco_byte_sum, VendorHeader, MAGIC1, MAGIC2, VENDOR_HEADER_STRUCT_LEN};

    #[test]
    fn vendor_header_roundtrip_and_checksum() {
        let mut hdr = VendorHeader {
            reserved: 0,
            magic1: MAGIC1,
            magic2: MAGIC2,
            header_len: VENDOR_HEADER_STRUCT_LEN,
            fw_length: 1024,
            checksum: 0,
            priority: 1,
            fw_version: [0; 12],
            hdr_version: [0; 12],
            device_name: [0; 32],
            build_time: [0; 32],
            image_name: [0; 32],
        };
        hdr.fw_version[..7].copy_from_slice(b"1.0.5.4");
        hdr.hdr_version[..3].copy_from_slice(b"0.1");
        hdr.device_name[..6].copy_from_slice(b"RV180W");
        hdr.set_image_name("RV180W-MOD.img");

        let mut img = hdr.to_padded_bytes().unwrap();
        img.resize(1024, 0xAB);
        let sum = compute_cisco_byte_sum(&img);
        hdr.checksum = sum;
        let final_hdr = hdr.to_padded_bytes().unwrap();
        img[..512].copy_from_slice(&final_hdr);

        let parsed = super::unpacker::verify_firmware_bytes(&img).unwrap();
        assert_eq!(parsed.device_name_str(), "RV180W");
        assert_eq!(parsed.checksum, sum);

        // Corrupt 1 byte in payload and confirm firmImageVerify rejects it
        img[600] ^= 0x01;
        assert!(super::unpacker::verify_firmware_bytes(&img).is_err());
    }
}
