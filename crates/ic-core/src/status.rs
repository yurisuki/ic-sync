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

    /// Human-readable label shared by the dashboard, tray menu and tooltip.
    pub fn label(self) -> &'static str {
        match self {
            Self::Synced => "Synced",
            Self::Syncing => "Syncing",
            Self::LoginRequired => "Sign in required",
            Self::Offline => "Offline",
            Self::Error => "Error",
            Self::Unknown => "Unknown",
            Self::Relocating => "Moving folder",
        }
    }
}

/// What the sync engine is doing right now. Unlike `SyncState` (the coarse
/// outcome), this is updated per step so the GUI and tray can show the exact
/// process instead of just "Syncing".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SyncPhase {
    #[default]
    Idle,
    Connecting,
    RefreshingMetadata,
    Reconciling,
    Uploading,
    Downloading,
    Relocating,
    SignInRequired,
    Offline,
    Error,
}

impl SyncPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connecting => "Connecting",
            Self::RefreshingMetadata => "Refreshing metadata",
            Self::Reconciling => "Reconciling files",
            Self::Uploading => "Uploading",
            Self::Downloading => "Downloading",
            Self::Relocating => "Moving folder",
            Self::SignInRequired => "Sign in required",
            Self::Offline => "Offline",
            Self::Error => "Error",
        }
    }
}

/// Fine-grained progress for the current operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncDetail {
    #[serde(default)]
    pub phase: SyncPhase,
    /// Exact step being performed, e.g. "Uploading Photos/IMG_1234.jpg".
    #[serde(default)]
    pub step: String,
    /// Path currently being processed, when there is one.
    #[serde(default)]
    pub current_item: Option<String>,
    #[serde(default)]
    pub completed: u64,
    #[serde(default)]
    pub total: u64,
}

impl SyncDetail {
    pub fn new(phase: SyncPhase, step: impl Into<String>) -> Self {
        Self {
            phase,
            step: step.into(),
            current_item: None,
            completed: 0,
            total: 0,
        }
    }

    pub fn with_item(mut self, item: impl Into<String>) -> Self {
        self.current_item = Some(item.into());
        self
    }

    pub fn with_progress(mut self, completed: u64, total: u64) -> Self {
        self.completed = completed;
        self.total = total;
        self
    }

    /// Single-line description used by the tray and progress panels.
    pub fn summary(&self) -> String {
        let mut text = if self.step.is_empty() {
            self.phase.label().to_string()
        } else {
            self.step.clone()
        };
        if self.total > 0 {
            text.push_str(&format!(
                " ({}/{})",
                self.completed.min(self.total),
                self.total
            ));
        }
        text
    }
}

/// What happened to a file: the dashboard's minimalist recent-changes feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Modified,
    Removed,
    Renamed,
    Uploaded,
    Downloaded,
}

impl ChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Modified => "Modified",
            Self::Removed => "Removed",
            Self::Renamed => "Renamed",
            Self::Uploaded => "Uploaded",
            Self::Downloaded => "Downloaded",
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Self::Added => "+",
            Self::Modified => "~",
            Self::Removed => "−",
            Self::Renamed => "↔",
            Self::Uploaded => "↑",
            Self::Downloaded => "↓",
        }
    }
}

/// One entry of the recent-changes feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub at: i64,
    pub kind: ChangeKind,
    pub path: String,
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
    /// Exact step currently being performed (for the GUI and tray icon).
    #[serde(default)]
    pub detail: SyncDetail,
    #[serde(default)]
    pub recent_changes: Vec<FileChange>,
    /// Most recent engine warning (e.g. a folder that could not be uploaded
    /// yet). The GUI surfaces each new notice as a notification.
    #[serde(default)]
    pub notice: Option<String>,
    /// Monotonic counter so a reader can tell one notice from the next even
    /// when the text repeats.
    #[serde(default)]
    pub notice_seq: u64,
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
            detail: SyncDetail::default(),
            recent_changes: Vec::new(),
            notice: None,
            notice_seq: 0,
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

    pub fn with_detail(mut self, detail: SyncDetail) -> Self {
        self.detail = detail;
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
    #[serde(default)]
    pub detail: SyncDetail,
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
            detail: status.detail.clone(),
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
    fn status_detail_round_trip_and_default() {
        let dir = TempDir::new();
        let path = dir.path.join("status.json");
        let status = ServiceStatus::new(SyncState::Syncing, "uploading local changes").with_detail(
            SyncDetail::new(SyncPhase::Uploading, "Uploading Photos/IMG_1234.jpg")
                .with_item("Photos/IMG_1234.jpg")
                .with_progress(3, 12),
        );
        write_status_to(&path, &status).unwrap();
        let read = read_status_from(&path).unwrap().unwrap();
        assert_eq!(read.detail.phase, SyncPhase::Uploading);
        assert_eq!(
            read.detail.current_item.as_deref(),
            Some("Photos/IMG_1234.jpg")
        );
        assert_eq!(read.detail.completed, 3);
        assert_eq!(read.detail.total, 12);
        assert!(read.detail.summary().contains("3/12"));
        assert_eq!(read.notice, None);
        assert_eq!(read.notice_seq, 0);

        // Older status files have no `detail` field and must still load.
        let old = r#"{"state":"synced","message":"ok","updated_at":1,"last_sync_at":null,"next_sync_at":null,"pending":0,"synced_files":0,"total_files":0,"current_folder":""}"#;
        std::fs::write(&path, old).unwrap();
        let read = read_status_from(&path).unwrap().unwrap();
        assert_eq!(read.detail.phase, SyncPhase::Idle);
    }

    #[test]
    fn recent_changes_round_trip() {
        let dir = TempDir::new();
        let path = dir.path.join("status.json");
        let mut status = ServiceStatus::new(SyncState::Synced, "x");
        status.recent_changes = vec![FileChange {
            at: 1,
            kind: ChangeKind::Added,
            path: "p".into(),
        }];
        write_status_to(&path, &status).unwrap();
        let read = read_status_from(&path).unwrap().unwrap();
        assert_eq!(read.recent_changes.len(), 1);
        assert_eq!(read.recent_changes[0].at, 1);
        assert_eq!(read.recent_changes[0].kind, ChangeKind::Added);
        assert_eq!(read.recent_changes[0].path, "p");

        // Status files without the `recent_changes` field still load with an
        // empty feed.
        let old = r#"{"state":"synced","message":"ok","updated_at":1,"last_sync_at":null,"next_sync_at":null,"pending":0,"synced_files":0,"total_files":0,"current_folder":""}"#;
        fs::write(&path, old).unwrap();
        let read = read_status_from(&path).unwrap().unwrap();
        assert!(read.recent_changes.is_empty());
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
