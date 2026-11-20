use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    window_start: Instant,
    blocked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct LoginRateLimiter {
    max_failures: u32,
    window: Duration,
    block_duration: Duration,
    entries: HashMap<IpAddr, Entry>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, window: Duration, block_duration: Duration) -> Self {
        Self {
            max_failures,
            window,
            block_duration,
            entries: HashMap::new(),
        }
    }

    pub fn default_policy() -> Self {
        Self::new(5, Duration::from_secs(60), Duration::from_secs(120))
    }

    pub fn check_allowed(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.entries.entry(ip).or_insert(Entry {
            failures: 0,
            window_start: now,
            blocked_until: None,
        });

        if let Some(until) = entry.blocked_until {
            if now < until {
                return false;
            }
            entry.blocked_until = None;
            entry.failures = 0;
            entry.window_start = now;
        }

        if now.duration_since(entry.window_start) > self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        true
    }

    pub fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let entry = self.entries.entry(ip).or_insert(Entry {
            failures: 0,
            window_start: now,
            blocked_until: None,
        });
        if now.duration_since(entry.window_start) > self.window {
            entry.failures = 0;
            entry.window_start = now;
        }
        entry.failures += 1;
        if entry.failures >= self.max_failures {
            entry.blocked_until = Some(now + self.block_duration);
        }
    }

    pub fn record_success(&mut self, ip: IpAddr) {
        self.entries.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn blocks_after_failures() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut rl = LoginRateLimiter::new(3, Duration::from_secs(60), Duration::from_secs(60));
        assert!(rl.check_allowed(ip));
        rl.record_failure(ip);
        rl.record_failure(ip);
        assert!(rl.check_allowed(ip));
        rl.record_failure(ip);
        assert!(!rl.check_allowed(ip));
        rl.record_success(ip);
        assert!(rl.check_allowed(ip));
    }
}
