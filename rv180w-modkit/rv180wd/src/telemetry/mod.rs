//! Live telemetry collectors (Phase 4/6 scaffolding).
//! On-demand reads from /proc, switch, Wi-Fi, and DHCP leases.

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub uptime_sec: Option<f64>,
    pub loadavg: Option<String>,
    pub mem_total_kb: Option<u64>,
    pub mem_free_kb: Option<u64>,
}

pub fn collect_snapshot() -> Snapshot {
    // Best-effort host-safe reads; on router these map to real /proc data.
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
        mem_total_kb: parse_kb("MemTotal"),
        mem_free_kb: parse_kb("MemFree"),
    }
}
