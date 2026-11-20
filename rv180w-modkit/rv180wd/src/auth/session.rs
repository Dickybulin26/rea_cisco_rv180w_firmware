use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;

pub const SESSION_COOKIE_NAME: &str = "rv180w_session";
pub const DEFAULT_SESSION_TTL_SECS: u64 = 30 * 60; // 30 minutes
const TOKEN_BYTES: usize = 32; // 256-bit
const MAX_SESSIONS: usize = 32;

#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub csrf_token: String,
    pub expires_at: Instant,
}

#[derive(Debug)]
pub struct SessionStore {
    sessions: HashMap<String, Session>,
    ttl: Duration,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_SESSION_TTL_SECS))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
        }
    }

    pub fn create(&mut self, username: &str) -> (String, String) {
        self.gc();
        while self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(k, _)| k.clone())
            {
                self.sessions.remove(&oldest);
            } else {
                break;
            }
        }
        let token = random_token(TOKEN_BYTES);
        let csrf = random_token(16);
        let session = Session {
            username: username.to_string(),
            csrf_token: csrf.clone(),
            expires_at: Instant::now() + self.ttl,
        };
        self.sessions.insert(token.clone(), session);
        (token, csrf)
    }

    /// Look up session and apply sliding TTL expiration on valid activity.
    pub fn get(&mut self, token: &str) -> Option<Session> {
        let now = Instant::now();
        self.gc();
        if let Some(s) = self.sessions.get_mut(token) {
            if s.expires_at > now {
                s.expires_at = now + self.ttl;
                return Some(s.clone());
            }
        }
        self.sessions.remove(token);
        None
    }

    pub fn invalidate(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    #[allow(dead_code)]
    pub fn invalidate_all(&mut self) {
        self.sessions.clear();
    }

    pub fn gc(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, s| s.expires_at > now);
    }
}

pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    B64URL.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_session_with_sliding_ttl() {
        let mut store = SessionStore::new();
        let (token, csrf) = store.create("admin");
        let s = store.get(&token).unwrap();
        assert_eq!(s.username, "admin");
        assert_eq!(s.csrf_token, csrf);
    }

    #[test]
    fn invalidate_and_cap_sessions() {
        let mut store = SessionStore::new();
        let (token, _) = store.create("admin");
        store.invalidate(&token);
        assert!(store.get(&token).is_none());

        for i in 0..50 {
            store.create(&format!("u{i}"));
        }
        assert!(store.sessions.len() <= MAX_SESSIONS);
    }
}
