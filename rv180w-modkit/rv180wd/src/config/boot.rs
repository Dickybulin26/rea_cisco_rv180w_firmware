use std::path::Path;

use crate::config::{schema::Config, store};

/// Boot-time config application entrypoint (`rv180wd --boot`).
/// Applies persisted config to system/network/services in a safe, idempotent way.
/// Current implementation is a scaffold: loads/validates config and reports summary.
pub fn apply_boot_config() -> Result<String, String> {
    apply_boot_config_from(&store::default_config_path())
}

pub fn apply_boot_config_from(path: &Path) -> Result<String, String> {
    let cfg = store::load_or_default(path);
    apply_config(&cfg)
}

pub fn apply_config(cfg: &Config) -> Result<String, String> {
    // TODO(phase-3): invoke subsystem reconcilers in dependency-safe order.
    // For now we validate/load and return a deterministic summary for observability.
    Ok(format!(
        "hostname={} lan={} wan={:?} wifi={} vpn(ipsec={},pptp={},l2tp={})",
        cfg.system.hostname,
        cfg.network.lan.ip,
        cfg.network.wan.mode,
        cfg.wifi.enabled,
        cfg.vpn.ipsec_enabled,
        cfg.vpn.pptp_enabled,
        cfg.vpn.l2tp_enabled
    ))
}
