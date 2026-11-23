//! JSON status bridge consumed by the GUI and the tray.
//!
//! All writes are atomic so a reader never sees a half-written document.
//! `sync-request` and `sync_done` preserve the reference driver's on-demand
//! trigger/completion semantics (the GUI/tray can create the request file).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config;
use crate::error::Result;
use crate::paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Synced,
    Syncing,
    LoginRequired,
    Offline,
    Error,
    Unknown,
    Relocating,
}

impl SyncState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Syncing => "syncing",
            Self::LoginRequired => "login_required",
            Self::Offline => "offline",
            Self::Error => "error",
            Self::Unknown => "unknown",
            Self::Relocating => "relocating",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub state: SyncState,
    pub message: String,
    pub updated_at: i64,
    pub last_sync_at: Option<i64>,
    pub next_sync_at: Option<i64>,
    pub pending: u64,
    pub synced_files: u64,
    pub total_files: u64,
    pub current_folder: String,
    /// False when no OS credential store is available; secrets cannot be saved.
    #[serde(default)]
    pub secure_storage_available: bool,
}

impl ServiceStatus {
    pub fn new(state: SyncState, message: impl Into<String>) -> Self {
        Self {
            state,
            message: message.into(),
            updated_at: chrono::Utc::now().timestamp(),
            last_sync_at: None,
            next_sync_at: None,
            pending: 0,
            synced_files: 0,
            total_files: 0,
            current_folder: String::new(),
            secure_storage_available: config::secure_storage_available(),
        }
    }

    pub fn with_pending(mut self, pending: u64) -> Self {
        self.pending = pending;
        self
    }

    pub fn with_files(mut self, synced: u64, total: u64) -> Self {
        self.synced_files = synced;
        self.total_files = total;
        self
    }

    pub fn with_times(mut self, last: Option<i64>, next: Option<i64>) -> Self {
        self.last_sync_at = last;
        self.next_sync_at = next;
        self
    }

    pub fn with_folder(mut self, folder: impl Into<String>) -> Self {
        self.current_folder = folder.into();
        self
    }

    pub fn with_secure_storage(mut self, available: bool) -> Self {
        self.secure_storage_available = available;
        self
    }
}

/// Compact view for GUI progress bars; derived from the full status document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    pub state: SyncState,
    pub message: String,
    pub pending: u64,
    pub synced_files: u64,
    pub total_files: u64,
    pub current_folder: String,
}

impl From<&ServiceStatus> for SyncProgress {
    fn from(status: &ServiceStatus) -> Self {
        Self {
            state: status.state,
            message: status.message.clone(),
            pending: status.pending,
            synced_files: status.synced_files,
            total_files: status.total_files,
            current_folder: status.current_folder.clone(),
        }
    }
}

pub fn status_file() -> Result<PathBuf> {
    paths::status_file()
}

pub fn sync_request_file() -> Result<PathBuf> {
    paths::sync_request_file()
}

pub fn sync_done_file() -> Result<PathBuf> {
    paths::sync_done_file()
}

pub fn read_status() -> Result<Option<ServiceStatus>> {
    read_status_from(&status_file()?)
}

pub fn read_status_from(path: &Path) -> Result<Option<ServiceStatus>> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(serde_json::from_str(&raw)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn write_status(status: &ServiceStatus) -> Result<()> {
    write_status_to(&status_file()?, status)
}

pub fn write_status_to(path: &Path, status: &ServiceStatus) -> Result<()> {
    let raw = serde_json::to_vec(status)?;
    config::atomic_write(path, &raw)
}

pub fn read_sync_progress() -> Result<Option<SyncProgress>> {
    Ok(read_status()?.as_ref().map(SyncProgress::from))
}

/// Ask the running engine to perform one full crawl (SIGUSR1 equivalent).
pub fn request_sync() -> Result<()> {
    request_sync_to(&sync_request_file()?)
}

pub fn request_sync_to(path: &Path) -> Result<()> {
    config::atomic_write(path, b"sync")
}

pub fn sync_request_exists() -> Result<bool> {
    Ok(sync_request_file()?.exists())
}

/// Consume a pending request. Returns true when one was present.
pub fn consume_sync_request() -> Result<bool> {
    consume_sync_request_from(&sync_request_file()?)
}

pub fn consume_sync_request_from(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Write the completion marker watched by `icloudctl sync`-style callers.
pub fn write_sync_done() -> Result<()> {
    write_sync_done_to(&sync_done_file()?)
}

pub fn write_sync_done_to(path: &Path) -> Result<()> {
    let stamp = chrono::Utc::now().timestamp();
    config::atomic_write(path, stamp.to_string().as_bytes())
}

pub fn read_sync_done() -> Result<Option<i64>> {
    match fs::read_to_string(sync_done_file()?) {
        Ok(raw) => Ok(raw.trim().parse().ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn status_round_trip() {
        let dir = TempDir::new();
        let path = dir.path.join("status.json");
        let status = ServiceStatus::new(SyncState::LoginRequired, "sign in required")
            .with_pending(3)
            .with_files(7, 10)
            .with_times(Some(1), Some(2))
            .with_folder("/home/me/iCloudDrive")
            .with_secure_storage(true);
        write_status_to(&path, &status).unwrap();
        let read = read_status_from(&path).unwrap().unwrap();
        assert_eq!(read.state, SyncState::LoginRequired);
        assert_eq!(read.pending, 3);
        assert_eq!(read.synced_files, 7);
        assert_eq!(read.total_files, 10);
        assert_eq!(read.last_sync_at, Some(1));
        assert_eq!(read.next_sync_at, Some(2));
        assert_eq!(read.current_folder, "/home/me/iCloudDrive");
        assert!(read.secure_storage_available);
        let progress = SyncProgress::from(&read);
        assert_eq!(progress.pending, 3);
    }

    #[test]
    fn missing_status_is_none() {
        let dir = TempDir::new();
        assert!(
            read_status_from(&dir.path.join("nope.json"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sync_request_and_done_markers() {
        let dir = TempDir::new();
        let request = dir.path.join("sync-request");
        assert!(!consume_sync_request_from(&request).unwrap());
        request_sync_to(&request).unwrap();
        assert!(consume_sync_request_from(&request).unwrap());
        assert!(!consume_sync_request_from(&request).unwrap());

        let done = dir.path.join("sync_done");
        write_sync_done_to(&done).unwrap();
        assert!(read_sync_done_at(&done).is_some());
    }

    fn read_sync_done_at(path: &Path) -> Option<i64> {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }
}
