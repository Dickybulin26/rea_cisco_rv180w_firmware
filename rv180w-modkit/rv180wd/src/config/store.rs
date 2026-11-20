use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::schema::Config;

pub const DEFAULT_DATA_DIR: &str = "/data/rv180w";
pub const DEFAULT_CONFIG_FILE: &str = "config.json";
pub const DEFAULT_BACKUP_FILE: &str = "config.json.bak";

pub fn default_config_path() -> PathBuf {
    Path::new(DEFAULT_DATA_DIR).join(DEFAULT_CONFIG_FILE)
}

pub fn default_backup_path() -> PathBuf {
    Path::new(DEFAULT_DATA_DIR).join(DEFAULT_BACKUP_FILE)
}

/// Load config from disk. If missing or invalid, returns defaults (non-destructive).
pub fn load_or_default(path: &Path) -> Config {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str::<Config>(&s).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Atomically persist config: write tmp -> fsync tmp -> backup current -> fsync dir -> rename tmp.
/// Also keeps `.bak` as rollback copy when a previous config exists.
pub fn save_atomic(path: &Path, cfg: &Config) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent"))?;
    fs::create_dir_all(dir)?;

    let json = serde_json::to_vec_pretty(cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp_path = path.with_extension("json.tmp");
    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        tmp.write_all(&json)?;
        tmp.write_all(b"\n")?;
        tmp.sync_all()?;
    }

    // Preserve previous good config as .bak for rollback/failsafe.
    if path.exists() {
        let bak = path.with_extension("json.bak");
        let _ = fs::copy(path, bak);
    }

    fs::rename(&tmp_path, path)?;
    sync_dir(dir)?;
    Ok(())
}

pub fn rollback_to_backup(path: &Path) -> io::Result<()> {
    let bak = path.with_extension("json.bak");
    if !bak.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "backup config not found",
        ));
    }
    fs::copy(&bak, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(())
}

pub fn factory_reset_default_paths() -> io::Result<()> {
    let dir = Path::new(DEFAULT_DATA_DIR);
    if dir.exists() {
        // Keep directory but remove rv180w-next state files; preserve unrelated data if any.
        let cfg = dir.join(DEFAULT_CONFIG_FILE);
        let bak = dir.join(DEFAULT_BACKUP_FILE);
        let tmp = dir.join("config.json.tmp");
        let auth = dir.join("auth.json");
        let auth_bak = dir.join("auth.json.bak");
        for p in [cfg, bak, tmp, auth, auth_bak] {
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
        sync_dir(dir)?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    // fsync directory for durability on POSIX filesystems.
    let f = File::open(dir)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rv180wd-{name}-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn save_load_and_backup_roundtrip() {
        let dir = temp_dir("cfg");
        let path = dir.join("config.json");
        let mut cfg = Config::default();
        cfg.system.hostname = "router-test".into();
        save_atomic(&path, &cfg).unwrap();

        let loaded = load_or_default(&path);
        assert_eq!(loaded.system.hostname, "router-test");

        let mut cfg2 = cfg.clone();
        cfg2.system.hostname = "router-test-2".into();
        save_atomic(&path, &cfg2).unwrap();
        assert!(path.with_extension("json.bak").exists());

        rollback_to_backup(&path).unwrap();
        let rolled = load_or_default(&path);
        assert_eq!(rolled.system.hostname, "router-test");

        let _ = fs::remove_dir_all(dir);
    }
}
