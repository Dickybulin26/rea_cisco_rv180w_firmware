//! On-demand lightweight telemetry collectors (0% idle CPU, read only when dashboard queries API).

use serde::Serialize;

use crate::hal;

#[derive(Debug, Clone, Serialize)]
pub struct NetIfaceStats {
    pub name: String,
    pub operstate: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpLease {
    pub expires: String,
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub uptime_sec: Option<f64>,
    pub loadavg: Option<String>,
    pub mem_total_kb: Option<u64>,
    pub mem_free_kb: Option<u64>,
    pub mem_available_kb: Option<u64>,
    pub board: hal::board::BoardInfo,
    pub interfaces: Vec<NetIfaceStats>,
    pub dhcp_leases: Vec<DhcpLease>,
}

fn read_net_dev() -> Vec<NetIfaceStats> {
    let Ok(content) = std::fs::read_to_string("/proc/net/dev") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines().skip(2) {
        let Some((name_part, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name_part.trim();
        if name == "lo" {
            continue;
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let rx_bytes = cols[0].parse().unwrap_or(0);
        let tx_bytes = cols[8].parse().unwrap_or(0);
        out.push(NetIfaceStats {
            name: name.to_string(),
            operstate: hal::switch::read_iface_operstate(name),
            rx_bytes,
            tx_bytes,
        });
    }
    out
}

fn read_dhcp_leases() -> Vec<DhcpLease> {
    let Ok(content) = std::fs::read_to_string("/tmp/dnsmasq.leases") else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                Some(DhcpLease {
                    expires: cols[0].to_string(),
                    mac: cols[1].to_string(),
                    ip: cols[2].to_string(),
                    hostname: cols[3].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

pub fn collect_snapshot() -> Snapshot {
    let uptime_sec = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse().ok());
    let loadavg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "));
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok();
    let parse_kb = |key: &str| -> Option<u64> {
        meminfo.as_ref()?.lines().find_map(|l| {
            if l.starts_with(key) {
                l.split_whitespace().nth(1)?.parse().ok()
            } else {
                None
            }
        })
    };
    Snapshot {
        uptime_sec,
        loadavg,
        mem_total_kb: parse_kb("MemTotal:"),
        mem_free_kb: parse_kb("MemFree:"),
        mem_available_kb: parse_kb("MemAvailable:").or_else(|| parse_kb("MemFree:")),
        board: hal::board::info(),
        interfaces: read_net_dev(),
        dhcp_leases: read_dhcp_leases(),
    }
}
