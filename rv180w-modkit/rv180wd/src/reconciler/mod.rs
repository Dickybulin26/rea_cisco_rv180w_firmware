//! Zero-reboot diff-based subsystem reconcilers.
//! Only changed subsystems are hot-reloaded (< 1s, zero router reboot).
//! Optional services (QoS, VPN, NTP) consume 0 processes and 0 RAM when disabled.

use std::fs;
use std::path::Path;

use crate::config::diff::Subsystem;
use crate::config::schema::{Config, WanMode};
use crate::hal;

pub fn reconcile_subsystems(cfg: &Config, subsystems: &[Subsystem]) -> Result<Vec<String>, String> {
    let mut applied = Vec::new();
    for sub in subsystems {
        match sub {
            Subsystem::System => {
                system::reconcile(cfg)?;
                applied.push("system".to_string());
            }
            Subsystem::Network => {
                network::reconcile(cfg)?;
                applied.push("network".to_string());
            }
            Subsystem::DhcpDns => {
                dhcp_dns::reconcile(cfg)?;
                applied.push("dhcp_dns".to_string());
            }
            Subsystem::Wifi => {
                wifi::reconcile(cfg)?;
                applied.push("wifi".to_string());
            }
            Subsystem::Firewall => {
                firewall::reconcile(cfg)?;
                applied.push("firewall".to_string());
            }
            Subsystem::Qos => {
                qos::reconcile(cfg)?;
                applied.push("qos".to_string());
            }
            Subsystem::Vpn => {
                vpn::reconcile(cfg)?;
                applied.push("vpn".to_string());
            }
        }
    }
    Ok(applied)
}

pub fn reconcile_all(cfg: &Config) -> Result<Vec<String>, String> {
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

fn netmask_to_prefix(mask: &str) -> u8 {
    mask.parse::<std::net::Ipv4Addr>()
        .map(|ip| u32::from(ip).count_ones() as u8)
        .unwrap_or(24)
}

pub mod system {
    use super::*;

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        if !cfg.system.hostname.is_empty() {
            let _ = hal::exec_cmd("/bin/hostname", &[&cfg.system.hostname]);
        }
        if !hal::is_dry_run() {
            let _ = fs::write("/tmp/TZ", format!("{}\n", cfg.system.timezone));
        }
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "ntpd"]);
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

    pub fn reconcile(cfg: &Config) -> Result<(), String> {
        let _ = hal::switch::configure_wan_port();

        // Configure LAN interface (eth0) without reboot
        let prefix = netmask_to_prefix(&cfg.network.lan.netmask);
        let lan_cidr = format!("{}/{}", cfg.network.lan.ip, prefix);
        let _ = hal::exec_cmd("/pfrm2.0/bin/ip", &["addr", "flush", "dev", "eth0"]);
        hal::exec_cmd("/pfrm2.0/bin/ip", &["addr", "add", &lan_cidr, "dev", "eth0"])?;
        hal::exec_cmd("/pfrm2.0/bin/ip", &["link", "set", "eth0", "up"])?;

        // Configure WAN interface (eth1) without reboot
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "dhclient"]);
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "pppd"]);
        let _ = hal::exec_cmd("/pfrm2.0/bin/ip", &["link", "set", "eth1", "up"]);

        match cfg.network.wan.mode {
            WanMode::Dhcp => {
                let _ = hal::exec_cmd("/pfrm2.0/bin/dhclient", &["-nw", "eth1"]);
            }
            WanMode::Static => {
                if let (Some(ip), Some(mask)) =
                    (&cfg.network.wan.static_ip, &cfg.network.wan.static_netmask)
                {
                    let wan_cidr = format!("{}/{}", ip, netmask_to_prefix(mask));
                    let _ = hal::exec_cmd("/pfrm2.0/bin/ip", &["addr", "flush", "dev", "eth1"]);
                    hal::exec_cmd("/pfrm2.0/bin/ip", &["addr", "add", &wan_cidr, "dev", "eth1"])?;
                    if let Some(gw) = &cfg.network.wan.static_gateway {
                        let _ = hal::exec_cmd(
                            "/pfrm2.0/bin/ip",
                            &["route", "replace", "default", "via", gw, "dev", "eth1"],
                        );
                    }
                }
            }
            WanMode::Pppoe => {
                // Rendered cleanly to /tmp/pppoe.opts (no shell interpolation)
                if !hal::is_dry_run() {
                    let user = cfg.network.wan.pppoe_username.as_deref().unwrap_or("");
                    let opts = format!("plugin rp-pppoe.so eth1\nuser \"{user}\"\ndefaultroute\nusepeerdns\npersist\n");
                    let _ = fs::write("/tmp/pppoe.opts", opts);
                }
                let _ = hal::exec_cmd("/pfrm2.0/bin/pppd", &["file", "/tmp/pppoe.opts"]);
            }
        }

        // Apply static routes
        for r in &cfg.network.static_routes {
            if !r.destination.is_empty() && !r.gateway.is_empty() {
                let dest = format!("{}/{}", r.destination, netmask_to_prefix(&r.netmask));
                let _ = hal::exec_cmd(
                    "/pfrm2.0/bin/ip",
                    &["route", "replace", &dest, "via", &r.gateway],
                );
            }
        }

        // Enable HW NAT acceleration when QoS is off (SPPE conflicts with software tc QoS)
        let _ = hal::switch::set_hw_nat(!cfg.qos.enabled);
        Ok(())
    }
}

pub mod dhcp_dns {
    use super::*;

    pub fn render_dnsmasq_conf(cfg: &Config) -> String {
        let mut s = String::from(
            "# Auto-generated by rv180wd (stored in tmpfs to avoid flash wear)\n\
             interface=eth0\n\
             bind-interfaces\n\
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
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "dnsmasq"]);
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

        // Filter table (default-deny WAN ingress)
        let input_policy = if cfg.firewall.default_wan_ingress_deny {
            "DROP"
        } else {
            "ACCEPT"
        };
        out.push_str(&format!(
            "*filter\n:INPUT {input_policy} [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n\
             -A INPUT -i lo -j ACCEPT\n\
             -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
             -A INPUT -i eth0 -j ACCEPT\n\
             -A INPUT -i ath0 -j ACCEPT\n"
        ));
        if cfg.system.remote_mgmt_wan {
            out.push_str("-A INPUT -i eth1 -p tcp --dport 443 -j ACCEPT\n");
        }
        out.push_str(
            "-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
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
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "racoon"]);
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "pptpd"]);
        let _ = hal::exec_cmd("/usr/bin/killall", &["-q", "l2tp"]);

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
