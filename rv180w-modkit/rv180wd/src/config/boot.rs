use std::path::Path;

use crate::config::{schema::Config, store};
use crate::hal;
use crate::reconciler;

/// Boot-time config application entrypoint (`rv180wd --boot`).
/// Applies persisted config to hardware/network/services once without TeamF1 SQLite rebuild.
/// Must never block management access: non-fatal subsystem errors are warned, not fatal.
pub fn apply_boot_config() -> Result<String, String> {
    apply_boot_config_from(&store::default_config_path())
}

pub fn apply_boot_config_from(path: &Path) -> Result<String, String> {
    hal::board::set_led("P2");
    let cfg = store::load_or_default(path);
    let (summary, warnings) = apply_config(&cfg);
    // Always signal ready LED after attempting LAN/config application.
    hal::board::set_led("P1");
    for w in &warnings {
        eprintln!("[rv180wd] boot warning: {w}");
    }
    Ok(summary)
}

pub fn apply_config(cfg: &Config) -> (String, Vec<String>) {
    let (applied, warnings) = reconciler::reconcile_all(cfg);
    let summary = format!(
        "applied=[{}] warnings={} hostname={} lan={} wan={:?} wifi={} vpn(ipsec={},pptp={},l2tp={})",
        applied.join(","),
        warnings.len(),
        cfg.system.hostname,
        cfg.network.lan.ip,
        cfg.network.wan.mode,
        cfg.wifi.enabled,
        cfg.vpn.ipsec_enabled,
        cfg.vpn.pptp_enabled,
        cfg.vpn.l2tp_enabled
    );
    (summary, warnings)
}
