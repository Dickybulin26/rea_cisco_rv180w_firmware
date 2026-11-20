//! Hardware Abstraction Layer (HAL) for Cisco RV180W (Cavium CNS3xxx ARMv6, Linux 2.6.31.1-cavm1).
//! All external commands use explicit argv arrays via `std::process::Command` (never `sh -c`).

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Serialize;

/// Returns true when running on host PC / QEMU test mode rather than real router hardware.
pub fn is_dry_run() -> bool {
    if let Ok(v) = std::env::var("RV180WD_DRY_RUN") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    !Path::new("/pfrm2.0/bin/vlan_table_func").exists()
}

pub fn exec_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    if is_dry_run() {
        eprintln!("[hal:dry-run] {} {}", program, args.join(" "));
        return Ok(());
    }
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} exited with status {status}"));
    }
    Ok(())
}

pub fn exec_cmd_with_stdin(program: &str, args: &[&str], stdin_data: &str) -> Result<(), String> {
    if is_dry_run() {
        eprintln!(
            "[hal:dry-run] {} {} (stdin {} bytes)",
            program,
            args.join(" "),
            stdin_data.len()
        );
        return Ok(());
    }
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .map_err(|e| format!("failed to write stdin to {program}: {e}"))?;
    }
    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for {program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} exited with status {status}"));
    }
    Ok(())
}

pub mod board {
    use super::*;

    #[derive(Debug, Clone, Serialize)]
    pub struct BoardInfo {
        pub model: String,
        pub lan_mac: Option<String>,
        pub dry_run: bool,
    }

    pub fn read_lan_mac() -> Option<String> {
        fs::read_to_string("/proc/macAddress")
            .ok()
            .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
            .filter(|s| !s.is_empty())
    }

    /// Set hardware status LED (`/proc/led`: "P2" = booting, "P1" = ready).
    pub fn set_led(state: &str) {
        if is_dry_run() {
            return;
        }
        let _ = fs::write("/proc/led", format!("{state}\n"));
    }

    /// Read physical reset button state from `/proc/push_button`.
    #[allow(dead_code)]
    pub fn read_reset_button_pressed() -> bool {
        fs::read_to_string("/proc/push_button")
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    }

    pub fn info() -> BoardInfo {
        BoardInfo {
            model: "Cisco RV180W (CNS3xxx ARMv6)".to_string(),
            lan_mac: read_lan_mac(),
            dry_run: is_dry_run(),
        }
    }
}

pub mod switch {
    use super::*;

    /// Configure Cavium CNS3xxx PSE VLAN table & MAC2 WAN port (matches rcS hardware setup).
    pub fn set_hw_nat(enable: bool) -> Result<(), String> {
        let arg = if enable { "enable" } else { "disable" };
        exec_cmd("/pfrm2.0/bin/sppe_ioctl", &[arg])
    }

    pub fn configure_wan_port() -> Result<(), String> {
        exec_cmd("/pfrm2.0/bin/set_wan_port_func", &["set", "2"])
    }

    pub fn read_iface_operstate(iface: &str) -> String {
        fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

pub mod wifi {
    use super::*;

    /// Configure Atheros MADWiFi VAP interface (`ath0`) safely using direct argv commands.
    pub fn apply_madwifi_ap(
        iface: &str,
        ssid: &str,
        channel: u8,
        enabled: bool,
    ) -> Result<(), String> {
        if !enabled {
            let _ = exec_cmd("/sbin/ifconfig", &[iface, "down"]);
            return Ok(());
        }
        let ch_str = channel.to_string();
        exec_cmd("/sbin/iwconfig", &[iface, "essid", ssid])?;
        if channel > 0 {
            exec_cmd("/sbin/iwconfig", &[iface, "channel", &ch_str])?;
        }
        exec_cmd("/sbin/ifconfig", &[iface, "up"])?;
        Ok(())
    }
}
