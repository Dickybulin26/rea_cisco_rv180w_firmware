use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::schema::Config;

pub const DEFAULT_DATA_DIR: &str = "/data/rv180w";
pub const DEFAULT_CONFIG_FILE: &str = "config.json";
pub const DEFAULT_BACKUP_FILE: &str = "config.json.bak";

pub fn data_dir() -> PathBuf {
    std::env::var("RV180WD_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DATA_DIR))
}

pub fn default_config_path() -> PathBuf {
    data_dir().join(DEFAULT_CONFIG_FILE)
}

#[allow(dead_code)]
pub fn default_backup_path() -> PathBuf {
    data_dir().join(DEFAULT_BACKUP_FILE)
}

/// Load config from disk. If missing or invalid, returns defaults (non-destructive).
pub fn load_or_default(path: &Path) -> Config {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str::<Config>(&s).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Atomically persist config: write & fsync backup -> write & fsync tmp -> atomic rename -> fsync dir.
pub fn save_atomic(path: &Path, cfg: &Config) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent"))?;
    fs::create_dir_all(dir)?;

    let mut json = serde_json::to_vec_pretty(cfg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    json.push(b'\n');

    // Preserve previous good config atomically as .bak for rollback/failsafe.
    if path.exists() {
        if let Ok(prev) = fs::read(path) {
            let bak_tmp = path.with_extension("json.bak.tmp");
            let bak = path.with_extension("json.bak");
            if write_and_sync(&bak_tmp, &prev).is_ok() {
                let _ = fs::rename(&bak_tmp, &bak);
            }
        }
    }

    let tmp_path = path.with_extension("json.tmp");
    write_and_sync(&tmp_path, &json)?;
    fs::rename(&tmp_path, path)?;
    sync_dir(dir)?;
    Ok(())
}

/// Atomically restore `.bak` over `config.json` (crash-safe even on sudden power loss).
pub fn rollback_to_backup(path: &Path) -> io::Result<Config> {
    let bak = path.with_extension("json.bak");
    if !bak.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "backup config not found",
        ));
    }
    let bak_bytes = fs::read(&bak)?;
    let parsed: Config = serde_json::from_slice(&bak_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("corrupt backup: {e}")))?;

    let tmp_path = path.with_extension("json.rollback.tmp");
    write_and_sync(&tmp_path, &bak_bytes)?;
    fs::rename(&tmp_path, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(parsed)
}

pub fn factory_reset_default_paths() -> io::Result<()> {
    let dir = data_dir();
    if dir.exists() {
        for name in [
            DEFAULT_CONFIG_FILE,
            DEFAULT_BACKUP_FILE,
            "config.json.tmp",
            "auth.json",
            "auth.json.bak",
            "auth.json.tmp",
        ] {
            let p = dir.join(name);
            if p.exists() {
                let _ = fs::remove_file(p);
            }
        }
        sync_dir(&dir)?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
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
    fn save_load_and_atomic_rollback_roundtrip() {
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

        let rolled = rollback_to_backup(&path).unwrap();
        assert_eq!(rolled.system.hostname, "router-test");
        assert_eq!(load_or_default(&path).system.hostname, "router-test");

        let _ = fs::remove_dir_all(dir);
    }
}
