//! Cross-platform data locations.
//!
//! Linux follows the XDG base directory specification; Windows uses the
//! roaming (`%APPDATA%`) and local (`%LOCALAPPDATA%`) application data roots.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Application folder name inside the platform config/data roots.
pub const APP_NAME: &str = "ic-sync";

pub fn home() -> Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| Error::Config("could not determine home directory".into()))
}

#[cfg(windows)]
pub fn config_dir() -> Result<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(dirs::config_dir)
        .ok_or_else(|| Error::Config("could not determine %APPDATA%".into()))?;
    Ok(base.join(APP_NAME))
}

#[cfg(not(windows))]
pub fn config_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| home().ok().map(|h| h.join(".config")))
        .ok_or_else(|| Error::Config("could not determine XDG config directory".into()))?;
    Ok(base.join(APP_NAME))
}

#[cfg(windows)]
pub fn data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(dirs::data_dir)
        .ok_or_else(|| Error::Config("could not determine %LOCALAPPDATA%".into()))?;
    Ok(base.join(APP_NAME))
}

#[cfg(not(windows))]
pub fn data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| home().ok().map(|h| h.join(".local/share")))
        .ok_or_else(|| Error::Config("could not determine XDG data directory".into()))?;
    Ok(base.join(APP_NAME))
}

#[cfg(windows)]
pub fn state_dir() -> Result<PathBuf> {
    // Windows has no XDG state dir; local app data is the closest analogue.
    data_dir()
}

#[cfg(not(windows))]
pub fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| home().ok().map(|h| h.join(".local/state")))
        .ok_or_else(|| Error::Config("could not determine XDG state directory".into()))?;
    Ok(base.join(APP_NAME))
}

#[cfg(windows)]
pub fn cache_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(dirs::cache_dir)
        .ok_or_else(|| Error::Config("could not determine %LOCALAPPDATA%".into()))?;
    Ok(base.join(APP_NAME).join("cache"))
}

#[cfg(not(windows))]
pub fn cache_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| home().ok().map(|h| h.join(".cache")))
        .ok_or_else(|| Error::Config("could not determine XDG cache directory".into()))?;
    Ok(base.join(APP_NAME))
}

pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.yaml"))
}

pub fn cookie_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("cookies"))
}

pub fn state_db() -> Result<PathBuf> {
    Ok(cache_dir()?.join("state.sqlite3"))
}

pub fn log_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("ic-sync.log"))
}

pub fn status_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("status.json"))
}

pub fn sync_request_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("sync-request"))
}

pub fn sync_done_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("sync_done"))
}

pub fn default_sync_folder() -> Result<PathBuf> {
    Ok(home()?.join("iCloudDrive"))
}

/// Create an owner-only directory. On Windows the platform ACLs inherited from
/// the user profile apply; on Unix we explicitly use 0700.
pub fn create_secure_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub fn ensure_layout() -> Result<()> {
    for dir in [
        config_dir()?,
        cookie_dir()?,
        data_dir()?,
        state_dir()?,
        cache_dir()?,
        cache_dir()?.join("tmp"),
    ] {
        create_secure_dir(&dir)?;
    }
    Ok(())
}
