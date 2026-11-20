use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32; // 256-bit derived key
// Tuned for Cavium CNS3xxx ARMv6 (~300-600 MHz without SHA hardware acceleration):
// strong KDF resistance while keeping login responsive (< 300ms) and preventing CPU DoS.
const DEFAULT_ITERATIONS: u32 = 25_000;
const MAX_ITERATIONS: u32 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHash {
    pub iterations: u32,
    pub salt_b64: String,
    pub hash_b64: String,
}

impl PasswordHash {
    pub fn encode(&self) -> String {
        format!(
            "pbkdf2-sha256${}${}${}",
            self.iterations, self.salt_b64, self.hash_b64
        )
    }

    pub fn decode(s: &str) -> Option<Self> {
        let mut parts = s.split('$');
        let alg = parts.next()?;
        if alg != "pbkdf2-sha256" {
            return None;
        }
        let iterations: u32 = parts.next()?.parse().ok()?;
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return None;
        }
        let salt_b64 = parts.next()?.to_string();
        let hash_b64 = parts.next()?.to_string();
        if parts.next().is_some() || salt_b64.is_empty() || hash_b64.is_empty() {
            return None;
        }
        Some(Self {
            iterations,
            salt_b64,
            hash_b64,
        })
    }
}

pub fn hash_password(password: &str) -> PasswordHash {
    hash_password_with_iterations(password, DEFAULT_ITERATIONS)
}

pub fn hash_password_with_iterations(password: &str, iterations: u32) -> PasswordHash {
    let iters = iterations.clamp(1, MAX_ITERATIONS);
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    derive(&salt, password, iters)
}

fn derive(salt: &[u8], password: &str, iterations: u32) -> PasswordHash {
    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut dk);
    PasswordHash {
        iterations,
        salt_b64: B64.encode(salt),
        hash_b64: B64.encode(dk),
    }
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Some(ph) = PasswordHash::decode(encoded) else {
        return false;
    };
    let Ok(salt) = B64.decode(ph.salt_b64.as_bytes()) else {
        return false;
    };
    let Ok(expected) = B64.decode(ph.hash_b64.as_bytes()) else {
        return false;
    };
    // Prevent empty/truncated hash bypass and weak/corrupt salts.
    if salt.len() < SALT_LEN || expected.len() != KEY_LEN {
        return false;
    }
    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ph.iterations, &mut dk);
    constant_time_eq(&dk, &expected)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let pw = "Str0ng!P@ssw0rd#2026";
        let h = hash_password_with_iterations(pw, 5_000);
        let enc = h.encode();
        assert!(verify_password(pw, &enc));
        assert!(!verify_password("wrong", &enc));
    }

    #[test]
    fn supports_special_characters() {
        let pw = "p@ss'\";DROP TABLE users;--";
        let h = hash_password_with_iterations(pw, 5_000);
        assert!(verify_password(pw, &h.encode()));
    }

    #[test]
    fn rejects_corrupt_or_empty_hashes() {
        let valid_salt = B64.encode([1u8; SALT_LEN]);
        assert!(!verify_password("anything", &format!("pbkdf2-sha256$1000${valid_salt}$")));
        assert!(!verify_password("anything", &format!("pbkdf2-sha256$0${valid_salt}$AAAA")));
        assert!(!verify_password("anything", "pbkdf2-sha256$1000$short$AAAA"));
        assert!(!verify_password("anything", &format!("pbkdf2-sha256$1000${valid_salt}$AAAA")));
    }
}
