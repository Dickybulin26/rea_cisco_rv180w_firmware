use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::auth::password;

pub const DEFAULT_AUTH_FILE: &str = "auth.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub username: String,
    pub password_hash: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthDb {
    pub users: Vec<UserRecord>,
    pub initialized: bool,
}

impl AuthDb {
    pub fn find_user(&self, username: &str) -> Option<&UserRecord> {
        self.users.iter().find(|u| u.username == username)
    }

    pub fn upsert_user(&mut self, username: &str, plaintext_password: &str, role: &str) {
        let hash = password::hash_password(plaintext_password).encode();
        if let Some(u) = self.users.iter_mut().find(|u| u.username == username) {
            u.password_hash = hash;
            u.role = role.to_string();
        } else {
            self.users.push(UserRecord {
                username: username.to_string(),
                password_hash: hash,
                role: role.to_string(),
            });
        }
        self.initialized = true;
    }

    pub fn verify(&self, username: &str, plaintext_password: &str) -> bool {
        match self.find_user(username) {
            Some(u) => password::verify_password(plaintext_password, &u.password_hash),
            None => false,
        }
    }
}

pub fn default_auth_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DEFAULT_AUTH_FILE)
}

pub fn load_or_default(path: &Path) -> AuthDb {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str::<AuthDb>(&s).unwrap_or_default(),
        Err(_) => AuthDb::default(),
    }
}

pub fn save_atomic(path: &Path, db: &AuthDb) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "auth path has no parent"))?;
    fs::create_dir_all(dir)?;
    let json = serde_json::to_vec_pretty(db)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&json)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    if path.exists() {
        let _ = fs::copy(path, path.with_extension("json.bak"));
    }
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("rv180wd-auth-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn auth_store_roundtrip_and_verify() {
        let dir = temp_dir();
        let path = dir.join("auth.json");
        let mut db = AuthDb::default();
        db.upsert_user("admin", "secret-pass", "admin");
        save_atomic(&path, &db).unwrap();
        let loaded = load_or_default(&path);
        assert!(loaded.initialized);
        assert!(loaded.verify("admin", "secret-pass"));
        assert!(!loaded.verify("admin", "wrong"));
        let _ = fs::remove_dir_all(dir);
    }
}
