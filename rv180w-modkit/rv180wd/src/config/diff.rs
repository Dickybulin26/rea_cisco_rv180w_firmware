use crate::config::schema::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    System,
    Network,
    DhcpDns,
    Wifi,
    Firewall,
    Qos,
    Vpn,
}

/// Compute which top-level subsystems changed between two configs.
/// This drives the zero-reboot diff/hot-reload reconciler.
pub fn diff_subsystems(old: &Config, new: &Config) -> Vec<Subsystem> {
    let mut changed = Vec::new();
    if old.system != new.system {
        changed.push(Subsystem::System);
    }
    if old.network != new.network {
        changed.push(Subsystem::Network);
    }
    if old.dhcp_dns != new.dhcp_dns {
        changed.push(Subsystem::DhcpDns);
    }
    if old.wifi != new.wifi {
        changed.push(Subsystem::Wifi);
    }
    if old.firewall != new.firewall {
        changed.push(Subsystem::Firewall);
    }
    if old.qos != new.qos {
        changed.push(Subsystem::Qos);
    }
    if old.vpn != new.vpn {
        changed.push(Subsystem::Vpn);
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changed_subsystems() {
        let old = Config::default();
        let mut new = old.clone();
        new.network.lan.ip = "192.168.10.1".into();
        new.wifi.ssid = "NewSSID".into();
        let changed = diff_subsystems(&old, &new);
        assert!(changed.contains(&Subsystem::Network));
        assert!(changed.contains(&Subsystem::Wifi));
        assert!(!changed.contains(&Subsystem::Firewall));
    }
}
