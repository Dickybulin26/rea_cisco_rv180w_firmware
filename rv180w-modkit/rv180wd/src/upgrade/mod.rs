#![allow(dead_code)]
//! Firmware upgrade verification matching exact Cisco RV180W `firmImageVerify` rules
//! reverse-engineered from `/pfrm2.0/bin/upgrade` via REA + Ghidra 12.2.

use serde::Serialize;

pub const HEADER_STRUCT_LEN: u32 = 0x94; // 148 bytes
pub const MAGIC1: u32 = 0x0001_1D7A;
pub const MAGIC2: u32 = 0xC3E6_E6AB;
pub const KERNEL_PARTITION_BYTES: usize = 0x60_0000; // 6 MiB (96 * 64 KiB)
pub const MAX_SAFE_FIRMWARE_BYTES: usize = 26 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedImageInfo {
    pub device_name: String,
    pub fw_version: String,
    pub image_name: String,
    pub total_bytes: usize,
    pub checksum_hex: String,
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn cstr(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).to_string()
}

pub fn compute_cisco_byte_sum(bytes: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for (idx, &b) in bytes.iter().enumerate() {
        if (0x14..0x18).contains(&idx) {
            continue;
        }
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

/// Strictly validates a firmware image buffer against Cisco RV180W `firmImageVerify` rules.
pub fn verify_image_bytes(bytes: &[u8]) -> Result<VerifiedImageInfo, String> {
    if bytes.len() < 512 {
        return Err("image too small (< 512 bytes)".to_string());
    }
    if bytes.len() > MAX_SAFE_FIRMWARE_BYTES {
        return Err(format!(
            "image exceeds max safe flash limit ({} > {} bytes)",
            bytes.len(),
            MAX_SAFE_FIRMWARE_BYTES
        ));
    }

    let reserved = read_u32_le(bytes, 0x00);
    let magic1 = read_u32_le(bytes, 0x04);
    let magic2 = read_u32_le(bytes, 0x08);
    let hdr_len = read_u32_le(bytes, 0x0C);
    let fw_len = read_u32_le(bytes, 0x10);
    let stored_sum = read_u32_le(bytes, 0x14);
    let priority = read_u32_le(bytes, 0x18);

    if reserved != 0 {
        return Err(format!("invalid reserved value: 0x{reserved:08x}"));
    }
    if magic1 != MAGIC1 {
        return Err(format!("invalid magic1: 0x{magic1:08x}"));
    }
    if magic2 != MAGIC2 {
        return Err(format!("invalid magic2: 0x{magic2:08x}"));
    }
    if hdr_len != HEADER_STRUCT_LEN {
        return Err(format!("invalid header length: 0x{hdr_len:x}"));
    }
    if fw_len as usize != bytes.len() {
        return Err(format!(
            "firmware length mismatch: header={fw_len}, actual={}",
            bytes.len()
        ));
    }
    if priority != 1 {
        return Err(format!("invalid priority: {priority}"));
    }

    let device_name = cstr(&bytes[0x34..0x54]);
    if device_name != "RV180W" {
        return Err(format!("invalid device name: '{device_name}'"));
    }

    let calc_sum = compute_cisco_byte_sum(bytes);
    if stored_sum != calc_sum {
        return Err(format!(
            "checksum mismatch: header=0x{stored_sum:08x}, computed=0x{calc_sum:08x}"
        ));
    }

    Ok(VerifiedImageInfo {
        device_name,
        fw_version: cstr(&bytes[0x1C..0x28]),
        image_name: cstr(&bytes[0x74..0x94]),
        total_bytes: bytes.len(),
        checksum_hex: format!("0x{stored_sum:08x}"),
    })
}

pub fn mtd_layout_summary() -> &'static str {
    "mtd1: kernel (6 MiB, 0x000000..0x600000), mtd2: squashfs /pfrm2.0 (0x600000+), mtd3: jffs2 /data"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_valid_header_and_rejects_corruption() {
        let mut img = vec![0u8; 1024];
        img[0x04..0x08].copy_from_slice(&MAGIC1.to_le_bytes());
        img[0x08..0x0C].copy_from_slice(&MAGIC2.to_le_bytes());
        img[0x0C..0x10].copy_from_slice(&HEADER_STRUCT_LEN.to_le_bytes());
        let total_len = img.len() as u32;
        img[0x10..0x14].copy_from_slice(&total_len.to_le_bytes());
        img[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        img[0x1C..0x23].copy_from_slice(b"3.0.0-b");
        img[0x34..0x3A].copy_from_slice(b"RV180W");
        img[0x74..0x7E].copy_from_slice(b"rv180w.img");
        img[512..].fill(0x5A);

        let sum = compute_cisco_byte_sum(&img);
        img[0x14..0x18].copy_from_slice(&sum.to_le_bytes());

        let info = verify_image_bytes(&img).expect("valid image should pass");
        assert_eq!(info.device_name, "RV180W");
        assert_eq!(info.total_bytes, 1024);

        img[600] ^= 0xFF;
        assert!(verify_image_bytes(&img).is_err());
    }
}
