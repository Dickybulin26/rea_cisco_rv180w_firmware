//! Zero-reboot diff-based subsystem reconcilers.
//! Only changed subsystems are hot-reloaded (< 1s, zero router reboot).
//! Optional services (QoS, VPN, NTP) consume 0 processes and 0 RAM when disabled.
//! Boot must never be blocked by optional/non-fatal subsystem failures.

use std::fs;
use std::path::Path;

use crate::config::diff::Subsystem;
use crate::config::schema::{Config, WanMode};
use crate::hal;

pub fn reconcile_subsystems(cfg: &Config, subsystems: &[Subsystem]) -> (Vec<String>, Vec<String>) {
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    for sub in subsystems {
        let res = match sub {
            Subsystem::System => system::reconcile(cfg),
            Subsystem::Network => network::reconcile(cfg),
            Subsystem::DhcpDns => dhcp_dns::reconcile(cfg),
            Subsystem::Firewall => firewall::reconcile(cfg),
            Subsystem::Wifi => wifi::reconcile(cfg),
            Subsystem::Qos => qos::reconcile(cfg),
            Subsystem::Vpn => vpn::reconcile(cfg),
        };
        match res {
            Ok(()) => applied.push(format!("{sub:?}").to_lowercase()),
            Err(e) => {
                if is_optional_subsystem(*sub) {
                    warnings.push(format!("{sub:?} (optional): {e}"));
                    // mark as attempted/applied-with-warning for visibility
                    applied.push(format!("{:?}(warn)", sub).to_lowercase());
                } else {
                    warnings.push(format!("{sub:?}: {e}"));
                    applied.push(format!("{:?}(err)", sub).to_lowercase());
                }
            }
        }
    }
    (applied, warnings)
}

pub fn reconcile_all(cfg: &Config) -> (Vec<String>, Vec<String>) {
    reconcile_subsystems(
        cfg,
        &[
            Subsystem::System,
            Subsystem::Network,
            Subsystem::DhcpDns,
            Subsystem::Firewall,
            Subsystem::Wifi,
            Subsystem::Qos,
            Subsystem::Vpn,
        ],
    )
}

fn is_optional_subsystem(sub: Subsystem) -> bool {
    matches!(sub, Subsystem::Wifi | Subsystem::Qos | Subsystem::Vpn)
}

fn netmask_to_prefix(mask: &str) -> u8 {
    mask.parse::<std::net::Ipv4Addr>()
        .map(|ip| u32::from(ip).count_ones() as u8)
        .unwrap_or(24)
}

pub mod system {
    use super::*;

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        if !cfg.system.hostname.is_empty() {
            let _ = hal::exec_cmd("/bin/busybox", &["hostname", &cfg.system.hostname]);
        }
        if !hal::is_dry_run() {
            let _ = fs::write("/tmp/TZ", format!("{}\n", cfg.system.timezone));
        }
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "ntpd"]);
        if cfg.system.ntp_enabled {
            if let Some(server) = cfg.system.ntp_servers.first() {
                let _ = hal::exec_cmd("/pfrm2.0/bin/ntpd", &["-p", server]);
            }
        }
        Ok(())
    }
}

pub mod network {
    use super::*;

    /// Network reconcile: LAN configuration is critical for management access (192.168.1.1).
    /// WAN, routes, and HW NAT toggles are best-effort/non-fatal so boot is never blocked.
    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        let mut warnings: Vec<String> = Vec::new();

        let _ = hal::switch::configure_wan_port();
        hal::switch::enable_lan_switch_ports();

        // --- Critical: LAN interface (eth0.1 VLAN 1 -> bdg1 bridge) for management access ---
        // RV180W Cavium CNS3xxx PSE (`rcS`: vlan_table_func edit 1 0 4 5 1 ...) tags LAN frames
        // to/from CPU on eth0 with 802.1Q VID=1 -> eth0.1, bridged into `bdg1` (exact stock layout).
        let _ = hal::exec_cmd("/bin/busybox", &["ifconfig", "eth0", "0.0.0.0", "up"]);
        let _ = hal::exec_cmd("/bin/busybox", &["vconfig", "add", "eth0", "1"]);
        let _ = hal::exec_cmd("/bin/busybox", &["ifconfig", "eth0.1", "0.0.0.0", "up"]);
        let _ = hal::exec_cmd("/pfrm2.0/bin/brctl", &["addbr", "bdg1"]);
        let _ = hal::exec_cmd("/pfrm2.0/bin/brctl", &["setfd", "bdg1", "0"]);
        let _ = hal::exec_cmd("/pfrm2.0/bin/brctl", &["addif", "bdg1", "eth0.1"]);

        let prefix = netmask_to_prefix(&cfg.network.lan.netmask);
        let lan_cidr = format!("{}/{}", cfg.network.lan.ip, prefix);
        let mut lan_ok = false;
        if hal::exec_cmd(
            "/bin/busybox",
            &[
                "ifconfig",
                "bdg1",
                &cfg.network.lan.ip,
                "netmask",
                &cfg.network.lan.netmask,
                "up",
            ],
        )
        .is_ok()
        {
            lan_ok = true;
        } else if hal::exec_cmd("/pfrm2.0/bin/ip", &["addr", "add", &lan_cidr, "dev", "bdg1"]).is_ok() {
            let _ = hal::exec_cmd("/pfrm2.0/bin/ip", &["link", "set", "bdg1", "up"]);
            lan_ok = true;
        }
        if !lan_ok && !hal::is_dry_run() {
            return Err("failed to configure LAN IP on bdg1".to_string());
        }

        // --- Best-effort: WAN interface (eth1) without reboot ---
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "dhclient"]);
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "pppd"]);
        let _ = hal::exec_cmd("/bin/busybox", &["ifconfig", "eth1", "up"]);

        match cfg.network.wan.mode {
            WanMode::Dhcp => {
                if let Err(e) = hal::exec_cmd("/pfrm2.0/bin/dhclient", &["-nw", "eth1"]) {
                    warnings.push(format!("wan dhcp: {e}"));
                }
            }
            WanMode::Static => {
                if let (Some(ip), Some(mask)) =
                    (&cfg.network.wan.static_ip, &cfg.network.wan.static_netmask)
                {
                    if let Err(e) = hal::exec_cmd(
                        "/bin/busybox",
                        &["ifconfig", "eth1", ip, "netmask", mask, "up"],
                    ) {
                        warnings.push(format!("wan static addr: {e}"));
                    }
                    if let Some(gw) = &cfg.network.wan.static_gateway {
                        let _ = hal::exec_cmd(
                            "/pfrm2.0/bin/ip",
                            &["route", "replace", "default", "via", gw, "dev", "eth1"],
                        );
                    }
                }
            }
            WanMode::Pppoe => {
                if !hal::is_dry_run() {
                    let user = cfg.network.wan.pppoe_username.as_deref().unwrap_or("");
                    let opts = format!("plugin rp-pppoe.so eth1\nuser \"{user}\"\ndefaultroute\nusepeerdns\npersist\n");
                    let _ = fs::write("/tmp/pppoe.opts", opts);
                }
                if let Err(e) = hal::exec_cmd("/pfrm2.0/bin/pppd", &["file", "/tmp/pppoe.opts"]) {
                    warnings.push(format!("wan pppoe: {e}"));
                }
            }
        }

        // Apply static routes (best-effort)
        for r in &cfg.network.static_routes {
            if !r.destination.is_empty() && !r.gateway.is_empty() {
                let dest = format!("{}/{}", r.destination, netmask_to_prefix(&r.netmask));
                let _ = hal::exec_cmd(
                    "/pfrm2.0/bin/ip",
                    &["route", "replace", &dest, "via", &r.gateway],
                );
            }
        }

        // Enable HW NAT acceleration when QoS is off (best-effort)
        let _ = hal::switch::set_hw_nat(!cfg.qos.enabled);

        for w in &warnings {
            eprintln!("[reconciler:network] warning: {w}");
        }
        Ok(())
    }
}

pub mod dhcp_dns {
    use super::*;

    pub fn render_dnsmasq_conf(cfg: &Config) -> String {
        let mut s = String::from(
            "# Auto-generated by rv180wd (stored in tmpfs to avoid flash wear)\n\
             user=root\n\
             interface=bdg1\n\
             bind-interfaces\n\
             pid-file=/var/run/dnsmasq.pid\n\
             dhcp-leasefile=/tmp/dnsmasq.leases\n\
             no-poll\n",
        );
        if cfg.dhcp_dns.dhcp_enabled {
            s.push_str(&format!(
                "dhcp-range={},{},{}m\n",
                cfg.dhcp_dns.range_start,
                cfg.dhcp_dns.range_end,
                cfg.dhcp_dns.lease_time_minutes.max(5)
            ));
            s.push_str(&format!("dhcp-option=3,{}\n", cfg.network.lan.ip));
            s.push_str(&format!("dhcp-option=6,{}\n", cfg.network.lan.ip));
        }
        if let Some(ref dom) = cfg.dhcp_dns.local_domain {
            if !dom.is_empty() {
                s.push_str(&format!("domain={dom}\nlocal=/{dom}/\n"));
            }
        }
        for dns in &cfg.dhcp_dns.dns_servers {
            if !dns.is_empty() {
                s.push_str(&format!("server={dns}\n"));
            }
        }
        s
    }

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        let conf = render_dnsmasq_conf(cfg);
        if !hal::is_dry_run() {
            fs::write("/tmp/dnsmasq.conf", conf)
                .map_err(|e| format!("failed to write /tmp/dnsmasq.conf: {e}"))?;
        }
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "dnsmasq"]);
        if cfg.dhcp_dns.dhcp_enabled || !cfg.dhcp_dns.dns_servers.is_empty() {
            let _ = hal::exec_cmd("/pfrm2.0/bin/dnsmasq", &["-C", "/tmp/dnsmasq.conf"]);
        }
        Ok(())
    }
}

pub mod firewall {
    use super::*;

    /// Render a complete atomic `iptables-restore` ruleset (zero packet-drop window).
    pub fn render_iptables_rules(cfg: &Config) -> String {
        let mut out = String::new();
        // NAT table
        out.push_str("*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n");
        for pf in &cfg.firewall.port_forwards {
            if !pf.enabled || pf.external_port == 0 || pf.internal_port == 0 || pf.internal_ip.is_empty() {
                continue;
            }
            let proto = match pf.proto.to_ascii_lowercase().as_str() {
                "udp" => "udp",
                _ => "tcp",
            };
            out.push_str(&format!(
                "-A PREROUTING -i eth1 -p {proto} --dport {} -j DNAT --to-destination {}:{}\n",
                pf.external_port, pf.internal_ip, pf.internal_port
            ));
        }
        out.push_str("-A POSTROUTING -o eth1 -j MASQUERADE\nCOMMIT\n");

        // Filter table (default-deny WAN ingress, full LAN access on bdg1/eth0/ath0)
        let input_policy = if cfg.firewall.default_wan_ingress_deny {
            "DROP"
        } else {
            "ACCEPT"
        };
        out.push_str(&format!(
            "*filter\n:INPUT {input_policy} [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n\
             -A INPUT -i lo -j ACCEPT\n\
             -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
             -A INPUT -i bdg1 -j ACCEPT\n\
             -A INPUT -i eth0.1 -j ACCEPT\n\
             -A INPUT -i eth0 -j ACCEPT\n\
             -A INPUT -i ath0 -j ACCEPT\n"
        ));
        if cfg.system.remote_mgmt_wan {
            out.push_str("-A INPUT -i eth1 -p tcp --dport 443 -j ACCEPT\n");
        }
        out.push_str(
            "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
             -A FORWARD -i bdg1 -o eth1 -j ACCEPT\n\
             -A FORWARD -i eth0 -o eth1 -j ACCEPT\n\
             -A FORWARD -i ath0 -o eth1 -j ACCEPT\n",
        );
        for pf in &cfg.firewall.port_forwards {
            if !pf.enabled || pf.internal_port == 0 || pf.internal_ip.is_empty() {
                continue;
            }
            let proto = match pf.proto.to_ascii_lowercase().as_str() {
                "udp" => "udp",
                _ => "tcp",
            };
            out.push_str(&format!(
                "-A FORWARD -i eth1 -p {proto} -d {} --dport {} -j ACCEPT\n",
                pf.internal_ip, pf.internal_port
            ));
        }
        for rule in &cfg.firewall.access_rules {
            if !rule.enabled || rule.src.is_empty() {
                continue;
            }
            let target = if rule.action.eq_ignore_ascii_case("allow") {
                "ACCEPT"
            } else {
                "DROP"
            };
            if rule.dst.is_empty() {
                out.push_str(&format!("-A FORWARD -s {} -j {target}\n", rule.src));
            } else {
                out.push_str(&format!(
                    "-A FORWARD -s {} -d {} -j {target}\n",
                    rule.src, rule.dst
                ));
            }
        }
        out.push_str("COMMIT\n");
        out
    }

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        if !hal::is_dry_run() {
            let _ = fs::write("/proc/sys/net/ipv4/ip_forward", "1\n");
        }
        let rules = render_iptables_rules(cfg);
        let bin = if Path::new("/pfrm2.0/bin/iptables-restore").exists() {
            "/pfrm2.0/bin/iptables-restore"
        } else {
            "/pfrm2.0/bin/iptables-multi"
        };
        let args: &[&str] = if bin.ends_with("iptables-multi") {
            &["iptables-restore"]
        } else {
            &[]
        };
        hal::exec_cmd_with_stdin(bin, args, &rules)
    }
}

pub mod wifi {
    use super::*;

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        hal::wifi::apply_madwifi_ap(
            "ath0",
            &cfg.wifi.ssid,
            cfg.wifi.channel,
            cfg.wifi.enabled,
        )?;
        if let Some(ref guest) = cfg.wifi.guest_network {
            let _ = hal::wifi::apply_madwifi_ap("ath1", &guest.ssid, cfg.wifi.channel, guest.enabled);
        }
        Ok(())
    }
}

pub mod qos {
    use super::*;

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        let _ = hal::exec_cmd("/pfrm2.0/bin/tc", &["qdisc", "del", "dev", "eth1", "root"]);
        if cfg.qos.enabled {
            let _ = hal::switch::set_hw_nat(false);
            let _ = hal::exec_cmd(
                "/pfrm2.0/bin/tc",
                &["qdisc", "add", "dev", "eth1", "root", "sfq", "perturb", "10"],
            );
        } else {
            let _ = hal::switch::set_hw_nat(true);
        }
        Ok(())
    }
}

pub mod vpn {
    use super::*;

    /// Strictly on-demand VPN services: 0 processes & 0 RAM when disabled.
    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "racoon"]);
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "pptpd"]);
        let _ = hal::exec_cmd("/bin/busybox", &["killall", "l2tp"]);

        if cfg.vpn.ipsec_enabled {
            let _ = hal::exec_cmd("/pfrm2.0/bin/racoon", &["-f", "/tmp/racoon.conf"]);
        }
        if cfg.vpn.pptp_enabled {
            let _ = hal::exec_cmd("/pfrm2.0/bin/pptpd", &["-c", "/tmp/pptpd.conf"]);
        }
        if cfg.vpn.l2tp_enabled {
            let _ = hal::exec_cmd("/pfrm2.0/bin/l2tp", &[]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_valid_dnsmasq_and_iptables_configs() {
        let mut cfg = Config::default();
        cfg.firewall.port_forwards.push(crate::config::schema::PortForwardRule {
            name: "web".into(),
            enabled: true,
            proto: "tcp".into(),
            external_port: 8443,
            internal_ip: "192.168.1.50".into(),
            internal_port: 443,
        });
        let dns = dhcp_dns::render_dnsmasq_conf(&cfg);
        assert!(dns.contains("dhcp-range=192.168.1.100,192.168.1.200,1440m"));

        let fw = firewall::render_iptables_rules(&cfg);
        assert!(fw.contains(":INPUT DROP [0:0]"));
        assert!(fw.contains("--dport 8443 -j DNAT --to-destination 192.168.1.50:443"));
        assert!(fw.contains("-A POSTROUTING -o eth1 -j MASQUERADE"));
    }
}
