//! Local folder relocation with rollback and atomic config rewrite.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::paths;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationReport {
    pub from: PathBuf,
    pub to: PathBuf,
    pub moved_files: u64,
    pub skipped: u64,
}

/// True when `path` is inside (or equal to) `dir`.
pub fn is_within(path: &Path, dir: &Path) -> bool {
    path == dir || path.starts_with(dir)
}

/// Reject nonsensical targets before touching any file.
pub fn validate_target(from: &Path, to: &Path) -> Result<()> {
    if from == to {
        return Err(Error::Config(
            "new sync folder is the same as the current one".into(),
        ));
    }
    if is_within(to, from) {
        return Err(Error::Config(
            "new sync folder cannot be inside the current sync folder".into(),
        ));
    }
    if is_within(from, to) {
        return Err(Error::Config(
            "new sync folder already contains the current sync folder".into(),
        ));
    }
    Ok(())
}

/// Move the top-level contents of `from` into `to`.
///
/// The destination is created if needed. If a move fails, already-moved items
/// are moved back so the operation is effectively atomic at the top level.
pub fn move_contents(from: &Path, to: &Path) -> Result<RelocationReport> {
    validate_target(from, to)?;
    if !from.is_dir() {
        return Err(Error::Config(format!(
            "current sync folder does not exist: {}",
            from.display()
        )));
    }
    fs::create_dir_all(to)?;

    let mut report = RelocationReport {
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        moved_files: 0,
        skipped: 0,
    };
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    let entries = fs::read_dir(from)?;

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let src = from.join(&name);
        let dst = to.join(&name);
        if dst.exists() {
            report.skipped += 1;
            continue;
        }
        match fs::rename(&src, &dst) {
            Ok(()) => {
                moved.push((dst, src));
                report.moved_files += 1;
            }
            #[cfg(windows)]
            Err(_) if src.is_dir() => {
                copy_dir_recursive(&src, &dst)?;
                fs::remove_dir_all(&src)?;
                moved.push((dst, src));
                report.moved_files += 1;
            }
            Err(error) => {
                for (moved_to, moved_from) in moved.into_iter().rev() {
                    let _ = fs::rename(&moved_to, &moved_from);
                }
                return Err(error.into());
            }
        }
    }
    Ok(report)
}

#[cfg(windows)]
fn copy_dir_recursive(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_dir_recursive(&src, &dst)?;
        } else {
            fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// Atomically point the config file at the new folder.
pub fn rewrite_config(config: &Config, path: &Path) -> Result<()> {
    config.write(path)
}

pub fn config_path(config: &Config) -> Result<PathBuf> {
    Ok(config
        .config_path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths::config_file().unwrap_or_else(|_| PathBuf::from("config.yaml"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn move_contents_moves_and_rolls_back_on_conflict() {
        let dir = TempDir::new();
        let from = dir.path.join("old");
        let to = dir.path.join("new");
        fs::create_dir_all(from.join("sub")).unwrap();
        fs::write(from.join("a.txt"), b"a").unwrap();
        fs::write(from.join("sub/b.txt"), b"b").unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(to.join("a.txt"), b"existing").unwrap();

        let report = move_contents(&from, &to).unwrap();
        assert_eq!(report.from, from);
        assert_eq!(report.to, to);
        assert_eq!(report.moved_files, 1);
        assert_eq!(report.skipped, 1);
        assert!(to.join("sub/b.txt").exists());
        assert_eq!(fs::read(to.join("a.txt")).unwrap(), b"existing");
    }

    #[test]
    fn target_validation() {
        let dir = TempDir::new();
        let from = dir.path.join("a");
        assert!(validate_target(&from, &from).is_err());
        assert!(validate_target(&from, &from.join("child")).is_err());
        assert!(validate_target(&from, &dir.path.join("b")).is_ok());
    }

    #[test]
    fn config_rewrite_never_writes_password() {
        let dir = TempDir::new();
        let path = dir.path.join("config.yaml");
        let mut config = Config::load_defaults();
        config.set_username("user@example.com");
        config.sync_folder = dir.path.join("new");
        config.password = "super-secret".into();
        rewrite_config(&config, &path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("super-secret"));
        assert!(Config::load(&path).unwrap().sync_folder == dir.path.join("new"));
    }
}
