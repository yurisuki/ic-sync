//! Local mirror + remote sync engine.
//!
//! Keeps the SQLite `entries` contract of the reference implementation,
//! hydrates placeholder files, uploads local changes and reconciles remote
//! moves with conflict copies. All work happens in background tasks; the GUI
//! only calls the small public surface on [`SyncEngine`].

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use notify::event::{EventKind, ModifyKind, RenameMode};
use notify::{Event, RecursiveMode, Watcher};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::api::{
    CLOUD_DOCS_ZONE, ICloudApi, ROOT_DOCWSID, ROOT_DRIVEWSID, RemoteNode, uploaded_document,
};
use crate::config::{self, Config};
use crate::error::{Error, Result};
#[cfg(test)]
use crate::mirror::conflict_path;
use crate::mirror::{Mirror, basename, join_path, parent_path};
use crate::relocation::{self, RelocationReport};
use crate::state::{Database, Entry};
use crate::status::{
    ChangeKind, FileChange, ServiceStatus, SyncDetail, SyncPhase, SyncState, write_status_to,
};

/// Delay used to coalesce bursts of local file events into one remote crawl.
const REMOTE_WAKE_DEBOUNCE: Duration = Duration::from_secs(1);
/// Let a burst of Create/Modify/Rename events settle before deciding what a
/// local file operation actually was (editors emit several events per save).
const LOCAL_EVENT_SETTLE: Duration = Duration::from_millis(300);
/// Never let a continuous event storm (copying thousands of files into the
/// mirror) postpone applying local changes forever.
const LOCAL_EVENT_MAX_WAIT: Duration = Duration::from_secs(2);
/// Flush a large watcher batch instead of letting it grow without bound.
const LOCAL_EVENT_MAX_BATCH: usize = 128;
/// Yield to the Tokio runtime between chunks so the GUI/Force-sync commands on
/// a current-thread runtime are never starved by a huge local backlog.
const LOCAL_APPLY_CHUNK: usize = 64;
/// Auto-retry gives up after this many consecutive failures: the machine is
/// notified once and the upload/remote loops pause until a later success.
const MAX_CONSECUTIVE_ERRORS: usize = 5;
/// A locally changed path stays protected from remote-view purges for this
/// long. Apple's crawl is eventually consistent, so a just-uploaded node can
/// legitimately be absent from the next snapshot.
const LOCAL_CHANGE_GRACE: Duration = Duration::from_secs(120);

/// Remembers paths touched by local changes and uploads that are waiting for
/// Apple's remote view to catch up. Purely in-memory: the DB already stores
/// the dirty/tombstone state; this only guards the race between `sync_dirty`
/// and the next remote crawl.
#[derive(Debug, Clone, Default)]
struct LocalChangeTracker {
    changed: Arc<std::sync::Mutex<HashMap<String, i64>>>,
    awaiting_visibility: Arc<std::sync::Mutex<HashSet<String>>>,
}

impl LocalChangeTracker {
    fn note_at(&self, path: &str, at: i64) {
        self.changed.lock().unwrap().insert(path.to_string(), at);
    }

    fn note(&self, path: &str) {
        self.note_at(path, chrono::Utc::now().timestamp());
    }

    fn note_awaiting_visibility(&self, path: &str) {
        self.note(path);
        self.awaiting_visibility
            .lock()
            .unwrap()
            .insert(path.to_string());
    }

    fn awaiting_paths(&self) -> Vec<String> {
        self.awaiting_visibility
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    /// The crawl now sees the node, so it is safe to purge if it later vanishes.
    fn mark_remote_visible(&self, path: &str) {
        self.awaiting_visibility.lock().unwrap().remove(path);
        self.changed.lock().unwrap().remove(path);
    }

    fn is_protected(&self, path: &str, grace: Duration) -> bool {
        let now = chrono::Utc::now().timestamp();
        // `note_awaiting_visibility` also refreshes this timestamp, so the
        // protection ends at grace expiry even if Apple never reports the node.
        self.changed
            .lock()
            .unwrap()
            .get(path)
            .is_some_and(|at| now - at < grace.as_secs() as i64)
    }
}

/// Whether a watcher batch must be flushed now, independent of the debounce
/// timer (which a continuous event storm would keep resetting forever).
fn local_batch_overdue(batch_len: usize, since_first: Option<Duration>) -> bool {
    batch_len >= LOCAL_EVENT_MAX_BATCH
        || since_first.is_some_and(|elapsed| elapsed >= LOCAL_EVENT_MAX_WAIT)
}

/// A local filesystem event reduced to the operation it may represent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalAction {
    Change(PathBuf),
    Delete(PathBuf),
    /// A single notify `Rename(Both { from, to })` event.
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    /// The two halves of a rename on backends that emit From/To separately.
    RenameFrom(PathBuf),
    RenameTo(PathBuf),
}

/// Ignore the engine's own atomic-write scratch files (`.<name>.<uuid>.tmp`)
/// and conflict copies; they are never user-visible iCloud nodes.
fn is_internal_local_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.contains(".local-conflict-") || (name.starts_with('.') && name.ends_with(".tmp"))
}

/// Map a notify event kind to a local action. All four mutation families are
/// handled: Create, Modify (including name changes), Remove and Rename.
fn action_from_event(event: &Event) -> Option<LocalAction> {
    match &event.kind {
        EventKind::Create(_) => event.paths.first().cloned().map(LocalAction::Change),
        EventKind::Remove(_) => event.paths.first().cloned().map(LocalAction::Delete),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            // notify puts (from, to) in event.paths for a combined rename.
            match event.paths.as_slice() {
                [from, to, ..] => Some(LocalAction::Rename {
                    from: from.clone(),
                    to: to.clone(),
                }),
                _ => None,
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            event.paths.first().cloned().map(LocalAction::RenameFrom)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            event.paths.first().cloned().map(LocalAction::RenameTo)
        }
        EventKind::Modify(_) | EventKind::Any | EventKind::Other => {
            event.paths.first().cloned().map(LocalAction::Change)
        }
        EventKind::Access(_) => None,
    }
}

/// Collapse a settled batch into one action per path, pairing split rename
/// events and preferring the filesystem's current state for ambiguous paths.
fn settle_actions(
    actions: Vec<LocalAction>,
    is_present: impl Fn(&Path) -> bool,
) -> Vec<LocalAction> {
    let mut result = Vec::new();
    let mut touched = HashSet::new();
    let mut rename_from = VecDeque::new();
    let mut rename_to = VecDeque::new();
    let mut simple = Vec::new();

    for action in actions {
        match action {
            LocalAction::Rename { from, to } => {
                result.push(LocalAction::Rename {
                    from: from.clone(),
                    to: to.clone(),
                });
                touched.insert(from);
                touched.insert(to);
            }
            LocalAction::RenameFrom(path) => rename_from.push_back(path),
            LocalAction::RenameTo(path) => rename_to.push_back(path),
            other => simple.push(other),
        }
    }
    while let (Some(from), Some(to)) = (rename_from.pop_front(), rename_to.pop_front()) {
        result.push(LocalAction::Rename {
            from: from.clone(),
            to: to.clone(),
        });
        touched.insert(from);
        touched.insert(to);
    }
    for path in rename_from {
        simple.push(LocalAction::Delete(path));
    }
    for path in rename_to {
        simple.push(LocalAction::Change(path));
    }
    // Last write wins per path; existence breaks ties between Create/Remove.
    let mut by_path: Vec<(PathBuf, LocalAction)> = Vec::new();
    for action in simple {
        let path = match &action {
            LocalAction::Change(path) | LocalAction::Delete(path) => path.clone(),
            _ => unreachable!(),
        };
        if touched.contains(&path) {
            continue;
        }
        if let Some(existing) = by_path.iter_mut().find(|(p, _)| *p == path) {
            existing.1 = action;
        } else {
            by_path.push((path, action));
        }
    }
    for (path, action) in by_path {
        let present = is_present(&path);
        let action = match action {
            LocalAction::Change(_) if !present => LocalAction::Delete(path.clone()),
            LocalAction::Delete(_) if present => LocalAction::Change(path.clone()),
            other => other,
        };
        result.push(action);
    }
    result
}

/// Coalescing wake signal for the remote crawl loop. `Notify` stores at most
/// one permit, so any number of requests during a debounce window produce a
/// single crawl. Also carries the "next sync" timestamp shown to the GUI.
#[derive(Debug, Clone)]
struct RemoteSyncSignal {
    wake: Arc<Notify>,
    next_sync_at: Arc<AtomicI64>,
}

impl RemoteSyncSignal {
    fn new() -> Self {
        Self {
            wake: Arc::new(Notify::new()),
            next_sync_at: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Synchronous, non-blocking wake request.
    fn request(&self) {
        let soon = chrono::Utc::now().timestamp() + REMOTE_WAKE_DEBOUNCE.as_secs() as i64;
        self.next_sync_at.store(soon, AtomicOrdering::Relaxed);
        self.wake.notify_one();
    }

    /// After a crawl, the next interval-driven crawl is `interval_secs` away.
    fn scheduled(&self, interval_secs: u64) {
        self.next_sync_at.store(
            chrono::Utc::now().timestamp() + interval_secs as i64,
            AtomicOrdering::Relaxed,
        );
    }

    fn next(&self) -> Option<i64> {
        let value = self.next_sync_at.load(AtomicOrdering::Relaxed);
        (value > 0).then_some(value)
    }

    /// Drop a permit that accumulated while the debounce sleep was running.
    /// Without this, a burst could schedule a second redundant crawl.
    async fn drain(&self) {
        let notified = self.wake.notified();
        tokio::pin!(notified);
        tokio::select! {
            _ = &mut notified => {}
            _ = sleep(Duration::from_millis(1)) => {}
        }
    }
}

/// The last authoritative remote view: paths we mirror and ids we own.
#[derive(Clone)]
struct RemoteView {
    paths: HashSet<String>,
    ids: HashSet<String>,
}

struct EngineInner {
    api: Arc<ICloudApi>,
    mirror: Arc<Mirror>,
    state: Arc<Database>,
    config: std::sync::Mutex<Config>,
    /// Safety-net upload wake; kept separate from the remote crawl signal.
    wake: Arc<Notify>,
    remote_wake: RemoteSyncSignal,
    /// Serializes remote crawls: the poll loop, the sync-request file loop and
    /// Force sync can all ask for a crawl at once.
    crawl_lock: Arc<Mutex<()>>,
    /// Paths recently changed locally or uploaded but not yet visible remote.
    local_changes: LocalChangeTracker,
    /// Uploads wait for the first crawl so a local mirror of a remote tree is
    /// not re-uploaded as brand-new nodes before the remote ids are known.
    first_crawl_done: AtomicBool,
    crawl_done: Arc<Notify>,
    shutdown: AtomicBool,
    started: AtomicBool,
    downloads: mpsc::UnboundedSender<String>,
    download_rx: Arc<Mutex<mpsc::UnboundedReceiver<String>>>,
    scheduled: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Files currently being written by hydration. The watcher must not treat
    /// these self-generated writes (or their atomic `.tmp` siblings) as edits.
    hydrating: Arc<std::sync::Mutex<HashSet<String>>>,
    download_slots: Arc<Semaphore>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    watcher: std::sync::Mutex<Option<notify::RecommendedWatcher>>,
    status_cache: std::sync::Mutex<ServiceStatus>,
    /// Status document written by this engine (injectable in tests so a test
    /// can never clobber the user's live status file).
    status_path: PathBuf,
    /// Set by the first successful crawl; gates stale-row purging so an empty
    /// pre-crawl view can never wipe a legitimate cache.
    remote_view: std::sync::Mutex<Option<RemoteView>>,
    last_sync_at: AtomicI64,
    /// Lets `&self` methods hand an owned `Arc` to spawned 'static tasks.
    self_ref: std::sync::OnceLock<Arc<EngineInner>>,
    /// Consecutive auto-reported errors (report_error). Reset on success.
    error_streak: AtomicUsize,
    /// Set at MAX_CONSECUTIVE_ERRORS; auto-retry loops pause until success.
    fatal_error: AtomicBool,
}

/// Headless sync engine. Cheap to clone; clones share the same background
/// tasks and SQLite connection.
#[derive(Clone)]
pub struct SyncEngine {
    inner: Arc<EngineInner>,
}

impl SyncEngine {
    pub async fn new(api: Arc<ICloudApi>, config: Config) -> Result<Self> {
        Self::new_with_status_path(api, config, crate::status::status_file()?).await
    }

    async fn new_with_status_path(
        api: Arc<ICloudApi>,
        config: Config,
        status_path: PathBuf,
    ) -> Result<Self> {
        config.validate()?;
        crate::paths::ensure_layout()?;
        let state = Arc::new(Database::open(&config.state_db())?);
        let mirror = Arc::new(Mirror::new(config.sync_folder.clone(), config.tmp_dir())?);
        let (downloads, download_rx) = mpsc::unbounded_channel();
        let workers = config.warmup_workers.max(1);
        let last = config.last_sync_at.unwrap_or(0);
        let status = ServiceStatus::new(SyncState::Unknown, "engine initialized");
        let inner = Arc::new(EngineInner {
            api,
            mirror,
            state,
            config: std::sync::Mutex::new(config),
            wake: Arc::new(Notify::new()),
            remote_wake: RemoteSyncSignal::new(),
            crawl_lock: Arc::new(Mutex::new(())),
            local_changes: LocalChangeTracker::default(),
            first_crawl_done: AtomicBool::new(false),
            crawl_done: Arc::new(Notify::new()),
            shutdown: AtomicBool::new(false),
            started: AtomicBool::new(false),
            downloads,
            download_rx: Arc::new(Mutex::new(download_rx)),
            scheduled: Arc::new(std::sync::Mutex::new(HashSet::new())),
            hydrating: Arc::new(std::sync::Mutex::new(HashSet::new())),
            download_slots: Arc::new(Semaphore::new(workers)),
            tasks: std::sync::Mutex::new(Vec::new()),
            watcher: std::sync::Mutex::new(None),
            status_cache: std::sync::Mutex::new(status),
            status_path,
            remote_view: std::sync::Mutex::new(None),
            last_sync_at: AtomicI64::new(last),
            self_ref: std::sync::OnceLock::new(),
            error_streak: AtomicUsize::new(0),
            fatal_error: AtomicBool::new(false),
        });
        if inner.self_ref.set(inner.clone()).is_err() {
            panic!("engine self-reference was already set");
        }
        Ok(Self { inner })
    }

    /// Start the crawl, watcher, upload, hydration, scheduler and status loops.
    /// Calling twice is a no-op.
    pub async fn start(&self) -> Result<()> {
        self.inner.start().await
    }

    /// Full remote crawl plus local reconcile.
    pub async fn sync_once(&self) -> Result<()> {
        self.inner.sync_once().await
    }

    /// Push locally dirty entries to iCloud.
    pub async fn sync_dirty(&self) -> Result<()> {
        self.inner.sync_dirty().await
    }

    pub fn status(&self) -> ServiceStatus {
        self.inner.status()
    }

    pub fn pending_count(&self) -> u64 {
        self.inner.pending_count()
    }

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    pub fn unhydrated_count(&self) -> u64 {
        self.inner.unhydrated_count()
    }

    /// Move only when the mirror is clean; otherwise the GUI can defer.
    pub fn relocate_folder(&self, new_folder: PathBuf) -> Result<RelocationReport> {
        self.inner.relocate_folder(new_folder)
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Wake the upload loop (for example after a UI-initiated file change).
    pub fn request_sync(&self) {
        // `notify_one` keeps the wake even when the upload loop is still busy
        // with a large batch; `notify_waiters` would drop it on the floor.
        self.inner.wake.notify_one();
    }

    /// Synchronously request an event-driven remote crawl. This never blocks:
    /// it signals the remote loop, which debounces bursts of requests (~1s)
    /// before doing a single crawl. Works independently of `instant_sync`;
    /// local watcher/uploads only call it when that preference is enabled.
    pub fn request_remote_sync(&self) {
        self.inner.request_remote_sync();
    }

    pub fn mark_local_change(&self, path: &str) -> Result<()> {
        self.inner.mark_local_change(path)
    }

    pub fn mark_local_delete(&self, path: &str) -> Result<()> {
        self.inner.mark_local_delete(path)
    }

    pub fn mark_local_rename(&self, from: &str, to: &str) -> Result<()> {
        self.inner.mark_local_rename(from, to)
    }

    pub fn ensure_hydrated(&self, path: &str) -> Result<()> {
        self.inner.ensure_hydrated(path)
    }

    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    pub fn read_only(&self) -> bool {
        self.inner.read_only()
    }

    pub fn debug_snapshot(&self) -> Result<Value> {
        Ok(json!({
            "entries": self.entry_count(),
            "dirty": self.pending_count(),
            "authenticated": self.inner.api.is_authenticated(),
            "needs_2fa": self.inner.api.requires_2fa(),
            "offline": self.inner.api.is_offline(),
        }))
    }
}

impl EngineInner {
    fn self_arc(&self) -> Arc<EngineInner> {
        self.self_ref
            .get()
            .expect("engine self-reference is initialized in new()")
            .clone()
    }

    fn cfg(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    fn is_shutdown(&self) -> bool {
        self.shutdown.load(AtomicOrdering::Relaxed)
    }

    fn shutdown(&self) {
        self.shutdown.store(true, AtomicOrdering::Relaxed);
        self.wake.notify_waiters();
        self.remote_wake.wake.notify_waiters();
        *self.watcher.lock().unwrap() = None;
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }

    fn push_task(&self, task: tokio::task::JoinHandle<()>) {
        match self.tasks.lock() {
            Ok(mut tasks) => tasks.push(task),
            Err(_) => task.abort(),
        }
    }

    fn last_sync(&self) -> Option<i64> {
        let value = self.last_sync_at.load(AtomicOrdering::Relaxed);
        (value > 0).then_some(value)
    }

    fn next_sync(&self) -> Option<i64> {
        self.remote_wake.next()
    }

    fn set_next_sync(&self) {
        self.remote_wake.scheduled(self.cfg().sync_interval_seconds);
    }

    /// The first authoritative remote view is available: uploads may now run
    /// without mistaking a mirrored remote tree for local-only new files.
    fn mark_first_crawl_done(&self) {
        if !self.first_crawl_done.swap(true, AtomicOrdering::SeqCst) {
            self.crawl_done.notify_waiters();
        }
    }

    /// Non-blocking wake for an event-driven remote crawl. Also pushes queued
    /// local changes: Force sync must do something even when the remote crawl
    /// is slow and `instant_sync` is disabled.
    fn request_remote_sync(&self) {
        if !self.is_shutdown() {
            self.wake.notify_one();
            self.remote_wake.request();
        }
    }

    /// Wake the upload loop and (when instant sync is on) ask for a fresh
    /// remote check. `notify_one` stores a permit, so a wake arriving while
    /// the upload loop is busy is not lost.
    fn notify_local_change(&self) {
        self.wake.notify_one();
        if self.cfg().instant_sync {
            self.remote_wake.request();
        }
    }

    fn pending_count(&self) -> u64 {
        self.state.list_dirty().map(|v| v.len() as u64).unwrap_or(0)
    }

    fn entry_count(&self) -> u64 {
        self.state.count_entries().unwrap_or(0).max(0) as u64
    }

    fn unhydrated_count(&self) -> u64 {
        self.state.count_unhydrated().unwrap_or(0).max(0) as u64
    }

    fn status(&self) -> ServiceStatus {
        let mut status = self.status_cache.lock().unwrap().clone();
        status.pending = self.pending_count();
        status.total_files = self.entry_count();
        status.synced_files = self.state.count_synced().unwrap_or(0).max(0) as u64;
        status.last_sync_at = self.last_sync();
        status.next_sync_at = self.next_sync();
        let cfg = self.cfg();
        status.current_folder = cfg.sync_folder.to_string_lossy().into_owned();
        // Plain mode needs no OS keyring; secure mode must have one.
        status.secure_storage_available = config::credential_storage_ready(cfg.credential_mode);
        status.updated_at = chrono::Utc::now().timestamp();
        status
    }

    fn publish(&self, state: SyncState, message: impl Into<String>) {
        let cfg = self.cfg();
        let mut status = ServiceStatus::new(state, message)
            .with_pending(self.pending_count())
            .with_files(
                self.state.count_synced().unwrap_or(0).max(0) as u64,
                self.entry_count(),
            )
            .with_times(self.last_sync(), self.next_sync())
            .with_folder(cfg.sync_folder.to_string_lossy().into_owned())
            .with_secure_storage(config::credential_storage_ready(cfg.credential_mode));
        // `publish` reports the coarse state; the fine-grained detail and any
        // unacknowledged notice belong to the cache and must survive it.
        {
            let cache = self.status_cache.lock().unwrap();
            status.detail = cache.detail.clone();
            status.recent_changes = cache.recent_changes.clone();
            status.notice = cache.notice.clone();
            status.notice_seq = cache.notice_seq;
        }
        *self.status_cache.lock().unwrap() = status.clone();
        if let Err(error) = write_status_to(&self.status_path, &status) {
            warn!("could not write status file: {error}");
        }
    }

    /// Record the exact step currently being performed. The status loop writes
    /// it to disk so the GUI/tray can show live progress instead of a bare
    /// "Syncing".
    fn update_detail(
        &self,
        phase: SyncPhase,
        step: impl Into<String>,
        current_item: Option<&str>,
        completed: u64,
        total: u64,
    ) {
        let mut cache = self.status_cache.lock().unwrap();
        cache.detail = SyncDetail {
            phase,
            step: step.into(),
            current_item: current_item.map(str::to_string),
            completed,
            total,
        };
    }

    /// Record a file change in the minimal recent-changes feed. Entries are
    /// newest first and the list is capped, so the status document written
    /// every second stays small.
    fn record_change(&self, kind: ChangeKind, path: impl Into<String>) {
        const RECENT_CHANGES_LIMIT: usize = 20;
        let mut cache = self.status_cache.lock().unwrap();
        cache.recent_changes.insert(
            0,
            FileChange {
                at: chrono::Utc::now().timestamp(),
                kind,
                path: path.into(),
            },
        );
        cache.recent_changes.truncate(RECENT_CHANGES_LIMIT);
    }

    /// Surface an engine problem to the GUI/tray.
    ///
    /// Core has no channel to the GUI, so the notice rides on the status
    /// document: the next status poll picks it up and shows a notification.
    /// The monotonic `notice_seq` lets the GUI show each notice exactly once.
    fn notify_warning(&self, message: impl Into<String>) {
        let message = message.into();
        warn!("{message}");
        {
            let mut cache = self.status_cache.lock().unwrap();
            cache.notice = Some(message);
            cache.notice_seq = cache.notice_seq.wrapping_add(1);
        }
        // Write immediately instead of waiting for the periodic status loop so
        // a short-lived failure is still visible to the GUI.
        let status = self.status();
        if let Err(error) = write_status_to(&self.status_path, &status) {
            warn!("could not write status file: {error}");
        }
    }

    /// Every sync path ends here, so `Syncing` is never the terminal state of
    /// a completed or failed operation (including callers that ignore `Err`).
    fn finish_sync(&self, result: &Result<()>, success_message: &str) {
        match result {
            Ok(()) => {
                if let Err(error) = self.state.prune_pending_ops() {
                    debug!("could not prune pending ops: {error}");
                }
                self.error_streak.store(0, AtomicOrdering::SeqCst);
                self.fatal_error.store(false, AtomicOrdering::SeqCst);
                self.publish(SyncState::Synced, success_message);
            }
            Err(error) => self.report_error(error),
        }
    }

    fn report_error(&self, error: &Error) {
        match error {
            Error::Http(_) | Error::Offline(_) => {
                self.publish(SyncState::Offline, format!("offline: {error}"));
            }
            Error::Auth(_) | Error::TwoFactor(_) | Error::CodeRejected(_) => {
                self.publish(SyncState::LoginRequired, error.to_string());
            }
            _ => {
                error!("sync error: {error}");
                self.publish(SyncState::Error, error.to_string());
            }
        }
        // Give up on endless retry loops: after a few consecutive failures
        // the user gets a machine notification, and the loops pause until a
        // later success. Auth states (signed out / 2FA pending) are not
        // failures — they are normal.
        if !error.is_auth() {
            let streak = self.error_streak.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            if streak >= MAX_CONSECUTIVE_ERRORS
                && !self.fatal_error.swap(true, AtomicOrdering::SeqCst)
            {
                self.machine_notify(&format!(
                    "IC-SYNC is stuck: {streak} consecutive errors. Automatic retries paused; \
                     check the app for details."
                ));
            }
        }
    }

    fn is_fatal(&self) -> bool {
        self.fatal_error.load(AtomicOrdering::SeqCst)
    }

    /// Best-effort desktop notification + beep. Linux uses notify-send and the
    /// desktop beep; Windows shows a MessageBox and beeps. Everything is
    /// fire-and-forget: a missing tool just means no notification.
    fn machine_notify(&self, message: &str) {
        #[cfg(target_os = "windows")]
        {
            let script = format!(
                "Add-Type -AssemblyName System.Windows.Forms;\
                 [System.Media.SystemSounds]::Hand.Play();\
                 [System.Windows.MessageBox]::Show('{}','IC-SYNC',0,48)",
                message.replace('\'', "")
            );
            let _ = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &script])
                .spawn();
        }
        #[cfg(all(unix, not(target_os = "windows")))]
        {
            let _ = std::process::Command::new("notify-send")
                .args(["-u", "critical", "-a", "ic-sync", "IC-SYNC", message])
                .spawn();
            // Warning error sound: first available player wins, fire-and-forget.
            let _ = ["paplay", "aplay", "ffplay"]
                .into_iter()
                .find_map(|player| {
                    std::process::Command::new(player)
                        .arg("/usr/share/sounds/freedesktop/stereo/bell.oga")
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .ok()
                });
        }
    }

    fn read_only(&self) -> bool {
        !self.api.is_authenticated() || self.api.requires_2fa()
    }

    fn unavailable_status(&self) -> (SyncState, String) {
        if self.api.is_offline() {
            let detail = self
                .api
                .offline_message()
                .unwrap_or_else(|| "Apple is unreachable".into());
            (
                SyncState::Offline,
                format!("offline; showing cached files ({detail})"),
            )
        } else {
            (
                SyncState::LoginRequired,
                "sign in to IC-SYNC to continue".into(),
            )
        }
    }

    fn path_allowed(&self, path: &str) -> bool {
        self.cfg().path_allowed(path)
    }

    async fn start(&self) -> Result<()> {
        if self.started.swap(true, AtomicOrdering::SeqCst) {
            return Ok(());
        }
        let workers = self.cfg().warmup_workers.max(1);
        for _ in 0..workers {
            self.spawn_hydration_loop(self.download_rx.clone());
        }
        self.spawn_request_loop();
        self.spawn_status_loop();

        if self.read_only() {
            info!("iCloud session unavailable; using cached files only");
            if self.state.count_entries()? > 0 {
                self.reconcile_cache()?;
            } else {
                self.mirror.ensure_dir("/")?;
            }
            let (state, message) = self.unavailable_status();
            self.publish(state, message);
            return Ok(());
        }

        self.publish(SyncState::Syncing, "starting iCloud sync");

        // Start every loop BEFORE the first crawl. A full remote crawl of a
        // large account can take minutes (one Apple request per folder); doing
        // it inline here meant the watcher, uploader and Force-sync wake were
        // not installed yet, so local edits during that window were invisible
        // and the app appeared to sync only once, at startup.
        let mut watcher_error = None;
        if self.cfg().auto_sync {
            self.spawn_remote_loop();
            self.spawn_upload_loop();
            watcher_error = self.spawn_local_watcher().err();
        }
        self.set_next_sync();
        if let Some(error) = watcher_error {
            self.report_error(&error);
        }

        // The remote snapshot is authoritative. Rebuilding from the cached DB
        // is what resurrects folders deleted locally/remotely, but it must not
        // block `start()` or the event loops above.
        info!("rebuilding local mirror from current iCloud metadata");
        let starter = self.self_arc();
        let startup = tokio::spawn(async move {
            let _crawl_guard = starter.crawl_lock.lock().await;
            starter.publish(SyncState::Syncing, "refreshing remote metadata");
            let mut startup_error: Option<Error> = None;
            if let Err(error) = starter.crawl_and_apply().await {
                startup_error = Some(error);
            } else if let Err(error) = starter.schedule_all_unhydrated() {
                startup_error = Some(error);
            }
            match startup_error {
                Some(error) => starter.report_error(&error),
                None => starter.publish(SyncState::Synced, "iCloud up to date"),
            }
            // Unblock uploads even after a failed crawl: local changes still
            // need to be pushed once connectivity returns.
            starter.mark_first_crawl_done();
        });
        self.push_task(startup);
        Ok(())
    }

    fn spawn_request_loop(&self) {
        let requester = self.self_arc();
        let task = tokio::spawn(async move {
            loop {
                if requester.is_shutdown() {
                    break;
                }
                sleep(Duration::from_secs(1)).await;
                if !matches!(crate::status::sync_request_exists(), Ok(true)) {
                    continue;
                }
                let _ = crate::status::consume_sync_request();
                info!("sync request received; starting remote crawl");
                match requester.sync_once().await {
                    Ok(()) => {
                        if !requester.read_only()
                            && let Err(error) = requester.sync_dirty().await
                        {
                            requester.report_error(&error);
                        }
                    }
                    Err(error) => requester.report_error(&error),
                }
                if let Err(error) = crate::status::write_sync_done() {
                    warn!("could not write sync marker: {error}");
                }
            }
        });
        self.push_task(task);
    }

    fn spawn_status_loop(&self) {
        let publisher = self.self_arc();
        let status_path = self.status_path.clone();
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if publisher.is_shutdown() {
                    break;
                }
                let status = publisher.status();
                if let Err(error) = write_status_to(&status_path, &status) {
                    warn!("could not write status file: {error}");
                }
            }
        });
        self.push_task(task);
    }

    fn spawn_remote_loop(&self) {
        let refresher = self.self_arc();
        // No artificial clamp: the configured interval is the contract.
        let interval_secs = self.cfg().sync_interval_seconds;
        let task = tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(interval_secs));
            timer.tick().await; // tokio's first tick is immediate
            loop {
                let woken = tokio::select! {
                    _ = timer.tick() => false,
                    _ = refresher.remote_wake.wake.notified() => true,
                };
                if refresher.is_shutdown() {
                    break;
                }
                if refresher.is_fatal() {
                    continue;
                }
                if woken {
                    // Bursts of file events collapse into a single crawl.
                    sleep(REMOTE_WAKE_DEBOUNCE).await;
                    if refresher.is_shutdown() {
                        break;
                    }
                    refresher.remote_wake.drain().await;
                }
                refresher.set_next_sync();
                // `sync_once` already reports errors through `finish_sync`;
                // calling `report_error` here again would double-count.
                let _ = refresher.sync_once().await;
                // Restart the interval after every crawl (including wake-driven
                // ones) so a signal cannot trigger an immediate extra crawl.
                timer.reset();
            }
        });
        self.push_task(task);
    }

    fn spawn_upload_loop(&self) {
        let uploader = self.self_arc();
        let interval_secs = self.cfg().upload_interval_seconds;
        let task = tokio::spawn(async move {
            // Do not upload before the first crawl knows which local paths are
            // already remote; otherwise mirroring a large remote tree creates
            // thousands of duplicate nodes on Apple's side.
            while !uploader.first_crawl_done.load(AtomicOrdering::SeqCst) && !uploader.is_shutdown()
            {
                tokio::select! {
                    _ = uploader.crawl_done.notified() => {}
                    _ = sleep(Duration::from_secs(1)) => {}
                }
            }
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            // The first crawl is done, so the remote view is known: pick up
            // local files that have no DB row (created while the app was not
            // running) and mark them dirty so the upload loop below pushes
            // them.
            uploader.scan_untracked_local_files();
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = uploader.wake.notified() => {}
                }
                if uploader.is_shutdown() {
                    break;
                }
                // Paused by repeated failures: the user was notified and
                // retrying forever would just spam. A later success clears
                // the flag (finish_sync).
                if uploader.is_fatal() {
                    continue;
                }
                if let Err(error) = uploader.sync_dirty().await {
                    uploader.report_error(&error);
                }
            }
        });
        self.push_task(task);
    }

    fn spawn_local_watcher(&self) -> Result<()> {
        let (tx, mut rx) = mpsc::unbounded_channel::<LocalAction>();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if let Some(action) = action_from_event(&event) {
                let paths = match &action {
                    LocalAction::Rename { from, to } => vec![from.clone(), to.clone()],
                    LocalAction::Change(path)
                    | LocalAction::Delete(path)
                    | LocalAction::RenameFrom(path)
                    | LocalAction::RenameTo(path) => vec![path.clone()],
                };
                if paths.iter().any(|path| is_internal_local_path(path)) {
                    return;
                }
                let _ = tx.send(action);
            }
        })
        .map_err(|e| Error::other(format!("could not start local watcher: {e}")))?;
        let folder = self.cfg().sync_folder;
        watcher
            .watch(&folder, RecursiveMode::Recursive)
            .map_err(|e| Error::other(format!("could not watch {}: {e}", folder.display())))?;
        *self.watcher.lock().unwrap() = Some(watcher);
        info!("watching {folder:?} for local changes");

        let watcher_inner = self.self_arc();
        let task = tokio::spawn(async move {
            let mut batch: Vec<LocalAction> = Vec::new();
            let mut first_event: Option<tokio::time::Instant> = None;
            let settle = tokio::time::sleep(LOCAL_EVENT_SETTLE);
            tokio::pin!(settle);
            loop {
                tokio::select! {
                    incoming = rx.recv() => {
                        let Some(action) = incoming else {
                            watcher_inner.apply_local_actions(std::mem::take(&mut batch)).await;
                            break;
                        };
                        if watcher_inner.is_shutdown() {
                            break;
                        }
                        if batch.is_empty() {
                            first_event = Some(tokio::time::Instant::now());
                        }
                        batch.push(action);
                        // Bound both the size and the age of a batch: a huge
                        // local tree must not starve newer events, status
                        // updates or Force-sync commands.
                        let over_limit =
                            local_batch_overdue(batch.len(), first_event.map(|at| at.elapsed()));
                        if over_limit {
                            watcher_inner
                                .apply_local_actions(std::mem::take(&mut batch))
                                .await;
                            first_event = None;
                        }
                        settle.as_mut().reset(tokio::time::Instant::now() + LOCAL_EVENT_SETTLE);
                    }
                    _ = &mut settle => {
                        if !batch.is_empty() {
                            watcher_inner
                                .apply_local_actions(std::mem::take(&mut batch))
                                .await;
                            first_event = None;
                        }
                        settle.as_mut().reset(tokio::time::Instant::now() + LOCAL_EVENT_SETTLE);
                    }
                }
            }
        });
        self.push_task(task);
        Ok(())
    }

    /// Canonical `"/..."` iCloud path for a watched local path, or `None` when
    /// the event is outside the sync folder, the root, or not allowed by config.
    fn canonical_watch_path(&self, path: &Path) -> Option<String> {
        let folder = self.cfg().sync_folder;
        let relative = path.strip_prefix(&folder).ok()?;
        if relative.as_os_str().is_empty() {
            return None;
        }
        let relative =
            config::normalize_icloud_path(&relative.to_string_lossy().replace('\\', "/"));
        if relative == "/" || !self.path_allowed(&relative) {
            return None;
        }
        Some(relative)
    }

    fn is_hydrating(&self, relative: &str) -> bool {
        self.hydrating.lock().unwrap().contains(relative)
    }

    async fn apply_local_actions(&self, actions: Vec<LocalAction>) {
        let actions = settle_actions(actions, |path| path.exists());
        for (index, action) in actions.into_iter().enumerate() {
            if index > 0 && index % LOCAL_APPLY_CHUNK == 0 {
                tokio::task::yield_now().await;
            }
            match action {
                LocalAction::Rename { from, to } => {
                    let (Some(from_path), Some(to_path)) = (
                        self.canonical_watch_path(&from),
                        self.canonical_watch_path(&to),
                    ) else {
                        continue;
                    };
                    if self.is_hydrating(&from_path) || self.is_hydrating(&to_path) {
                        continue;
                    }
                    if let Err(error) = self.mark_local_rename(&from_path, &to_path) {
                        debug!("ignoring local rename {from_path} -> {to_path}: {error}");
                    }
                }
                LocalAction::Change(path) => {
                    let Some(relative) = self.canonical_watch_path(&path) else {
                        continue;
                    };
                    if self.is_hydrating(&relative) || self.is_ignorable_empty_ghost(&relative) {
                        continue;
                    }
                    // A change on a path with no row is a local add; on an
                    // existing row it is a modification.
                    let was_new = self
                        .state
                        .get_entry(&relative)
                        .map(|entry| entry.is_none())
                        .unwrap_or(false);
                    if let Err(error) = self.mark_local_change(&relative) {
                        debug!("ignoring local change for {relative}: {error}");
                    } else if was_new {
                        self.record_change(ChangeKind::Added, relative);
                    } else {
                        self.record_change(ChangeKind::Modified, relative);
                    }
                }
                LocalAction::Delete(path) => {
                    let Some(relative) = self.canonical_watch_path(&path) else {
                        continue;
                    };
                    if self.is_hydrating(&relative) {
                        continue;
                    }
                    if let Err(error) = self.mark_local_delete(&relative) {
                        debug!("ignoring local delete for {relative}: {error}");
                    }
                }
                LocalAction::RenameFrom(_) | LocalAction::RenameTo(_) => {
                    // Pairing happens in `settle_actions`.
                }
            }
        }
    }

    // -- remote crawl -----------------------------------------------------

    pub async fn sync_once(&self) -> Result<()> {
        let result = self.sync_once_inner().await;
        self.finish_sync(&result, "iCloud up to date");
        result
    }

    async fn sync_once_inner(&self) -> Result<()> {
        // One authoritative crawl at a time. Without this, a timed poll and a
        // Force-sync request could both reconcile (and purge) against the same
        // SQLite state concurrently.
        let _crawl_guard = self.crawl_lock.lock().await;
        if self.api.is_offline() {
            return Err(Error::Offline("cached files are read-only".into()));
        }
        if self.read_only() {
            return Err(Error::Auth("sign in before syncing".into()));
        }
        self.update_detail(SyncPhase::Connecting, "Connecting to iCloud…", None, 0, 0);
        self.publish(SyncState::Syncing, "refreshing remote metadata");
        self.crawl_and_apply().await?;
        self.mark_first_crawl_done();
        self.update_detail(SyncPhase::Idle, "Up to date", None, 0, 0);
        let now = chrono::Utc::now().timestamp();
        self.last_sync_at.store(now, AtomicOrdering::Relaxed);
        self.set_next_sync();
        self.state
            .sync_state_set("last_sync_at", &now.to_string())?;
        Ok(())
    }

    async fn crawl_and_apply(&self) -> Result<()> {
        let crawl_started_at = chrono::Utc::now().timestamp();
        self.update_detail(
            SyncPhase::RefreshingMetadata,
            "Refreshing remote metadata",
            None,
            0,
            0,
        );
        // The Python reference crawls only `root.get_children()`. Apple already
        // lists the user's app libraries there (e.g. Pages); `app_libraries()`
        // is a catalogue of *all* app containers and must not be mirrored as
        // top-level folders. The old code did exactly that and doubled names.
        let root = self.api.root().await?;
        let (nodes, id_paths) =
            collect_remote_nodes(&self.api, root, |path| self.path_allowed(path)).await?;
        self.update_detail(
            SyncPhase::Reconciling,
            format!("Reconciling {} remote item(s)", nodes.len()),
            None,
            0,
            nodes.len() as u64,
        );
        let snapshot: HashMap<String, RemoteNode> = nodes.into_iter().collect();
        let view = RemoteView {
            paths: snapshot.keys().cloned().collect(),
            ids: snapshot
                .values()
                .map(|node| node.drivewsid.clone())
                .collect(),
        };
        *self.remote_view.lock().unwrap() = Some(view.clone());
        // Once Apple's snapshot contains a locally uploaded node it is no
        // longer "pending visibility" and may be purged if it later disappears.
        for path in self.local_changes.awaiting_paths() {
            if snapshot.contains_key(&path) {
                self.local_changes.mark_remote_visible(&path);
            }
        }
        // Older builds dropped Apple's separate `extension` field, leaving
        // extensionless rows/files behind. Repair them from remote metadata
        // *before* purging, so local content is moved to the canonical path
        // instead of being orphaned or duplicated.
        repair_extensionless_paths(&self.state, &self.mirror, &snapshot)?;
        // Reconcile against the authoritative view before the watcher/upload
        // loops can see (and recreate) stale local or DB state.
        purge_stale_entries(
            &self.state,
            &self.mirror,
            &view,
            &self.local_changes,
            LOCAL_CHANGE_GRACE,
        )?;
        drop_stale_duplicates(&self.state, &self.mirror)?;
        reconcile_bad_paths(&self.state, &self.mirror, &id_paths, &snapshot)?;

        let remote_ids: HashSet<String> = view.ids.clone();
        let mut handled = HashSet::new();
        for (path, node) in &snapshot {
            let by_id = self.state.get_entry_by_remote_id(&node.drivewsid)?;
            let has_remote_id = by_id.is_some();
            let at_path = self.state.get_entry(path)?;
            let Some(entry) = by_id.or_else(|| at_path.clone()) else {
                self.materialize_remote_entry(path, node, crawl_started_at)
                    .await?;
                handled.insert(path.clone());
                continue;
            };

            if entry.dirty {
                let conflict = entry
                    .synced_path
                    .as_deref()
                    .is_some_and(|synced| synced != path.as_str())
                    || entry
                        .remote_etag
                        .as_ref()
                        .zip(node.etag.as_ref())
                        .is_some_and(|(old, new)| old != new)
                    || (!has_remote_id && at_path.is_some());
                if conflict {
                    // No local conflict copies: the user wants their sync folder
                    // to mirror iCloud cleanly. Remote metadata always wins.
                    debug!("remote version wins on {}", entry.path);
                    self.materialize_remote_entry(path, node, crawl_started_at)
                        .await?;
                } else {
                    handled.insert(entry.path.clone());
                }
            } else {
                if entry.path != *path {
                    if is_duplicate_path(&entry.path, path) {
                        // Reconciliation only removes empty directories. If a
                        // duplicate has real content, moving it over the
                        // canonical path could clobber it; leave and report.
                        self.notify_warning(format!(
                            "Keeping duplicate directory {}; canonical path {path} is occupied",
                            entry.path
                        ));
                        handled.insert(entry.path.clone());
                        handled.insert(path.clone());
                        continue;
                    }
                    self.rename_local_tree(&entry.path, path)?;
                }
                self.refresh_clean_entry(path, node, crawl_started_at)
                    .await?;
            }
            handled.insert(path.clone());
        }

        for entry in self.state.list_entries()? {
            if handled.contains(&entry.path) || !self.path_allowed(&entry.path) || entry.path == "/"
            {
                continue;
            }
            // A directory shaped like `<name>/<name>` is the signature of the
            // old path bug. Reconciliation handles the safe (empty) ones; never
            // recursively delete one that still holds content. The same care
            // applies to a parent about to be removed recursively: it may
            // still contain a duplicate we deliberately left in place.
            if entry.is_dir()
                && (is_duplicate_shape(&entry.path) || self.has_duplicate_child(&entry.path))
            {
                debug!(
                    "keeping directory {}; duplicate content is not proven safe to remove",
                    entry.path
                );
                continue;
            }
            // Conflict copies and local-only files have no remote identity yet.
            let Some(remote_id) = entry.remote_drivewsid.as_deref() else {
                continue;
            };
            if remote_ids.contains(remote_id) {
                continue;
            }
            if entry.dirty {
                if entry.synced_path.as_deref() == Some(entry.path.as_str()) {
                    continue;
                }
                if entry.is_dir()
                    && is_duplicate_shape(&entry.path)
                    && self
                        .state
                        .list_subtree(&entry.path)?
                        .iter()
                        .all(|child| child.is_dir())
                {
                    // The remote id vanished; clearing it would just hand the
                    // stale duplicate to the upload loop. Drop the row quietly.
                    self.state.remove_subtree(&entry.path)?;
                    continue;
                }
                self.state.clear_remote_identity(&entry.path)?;
                continue;
            }
            if entry
                .last_synced_at
                .is_some_and(|synced| synced >= crawl_started_at)
            {
                continue;
            }
            if entry.is_dir() {
                let _ = self.mirror.remove_dir_all(&entry.path);
            } else {
                let _ = self.mirror.remove_file(&entry.path);
            }
            self.state.remove_subtree(&entry.path)?;
        }
        Ok(())
    }

    fn entry_from_node(&self, path: &str, node: &RemoteNode, now: i64) -> Entry {
        Entry {
            path: path.to_string(),
            entry_type: if node.is_dir() {
                "folder".into()
            } else {
                "file".into()
            },
            parent_path: parent_path(path),
            remote_drivewsid: Some(node.drivewsid.clone()),
            remote_docwsid: node.docwsid.clone(),
            remote_etag: node.etag.clone(),
            remote_zone: node.zone.clone().or(Some("com.apple.CloudDocs".into())),
            remote_shareid: node.share_id.as_ref().map(|v| v.to_string()),
            size: node.size,
            mtime: node.date_changed.unwrap_or(now),
            hydrated: false,
            dirty: false,
            tombstone: false,
            local_sha256: None,
            last_synced_at: Some(now),
            synced_path: Some(path.to_string()),
        }
    }

    async fn materialize_remote_entry(
        &self,
        path: &str,
        node: &RemoteNode,
        now: i64,
    ) -> Result<()> {
        let mut entry = self.entry_from_node(path, node, now);
        if node.is_dir() {
            self.mirror.ensure_dir(path)?;
            entry.hydrated = true;
        } else if node.size > 0 {
            self.mirror
                .materialize_placeholder(path, node.size as u64, entry.mtime)?;
            self.schedule_download(path);
        } else {
            self.mirror.write_all(path, b"")?;
            entry.hydrated = true;
            entry.local_sha256 = Some(self.mirror.sha256(path)?);
        }
        self.state.upsert_entry(&entry)?;
        Ok(())
    }

    async fn refresh_clean_entry(&self, path: &str, node: &RemoteNode, now: i64) -> Result<()> {
        let Some(old) = self.state.get_entry(path)? else {
            self.materialize_remote_entry(path, node, now).await?;
            return Ok(());
        };
        let mtime = node.date_changed.unwrap_or(now);
        let changed = old.remote_etag != node.etag || old.size != node.size || old.mtime != mtime;
        let mut entry = self.entry_from_node(path, node, now);
        entry.hydrated = old.hydrated;
        entry.local_sha256 = old.local_sha256.clone();
        if node.is_dir() {
            self.mirror.ensure_dir(path)?;
            entry.hydrated = true;
        } else if old.hydrated
            && self.mirror.exists(path)
            && old.size == node.size
            && entry.local_sha256.is_some()
        {
            // Already hydrated with matching size. Metadata-only crawls must not
            // replace real content with a fresh placeholder.
            entry.hydrated = true;
        } else if changed || !self.mirror.exists(path) {
            if node.size > 0 {
                self.mirror
                    .materialize_placeholder(path, node.size as u64, mtime)?;
            } else {
                self.mirror.write_all(path, b"")?;
            }
            entry.hydrated = node.size == 0;
            entry.local_sha256 = None;
        }
        self.state.upsert_entry(&entry)?;
        if !node.is_dir() && !entry.hydrated {
            self.schedule_download(path);
        }
        Ok(())
    }

    fn rename_local_tree(&self, from: &str, to: &str) -> Result<()> {
        self.mirror.rename(from, to)?;
        self.state.rename_tree(from, to, true)?;
        Ok(())
    }

    fn schedule_all_unhydrated(&self) -> Result<()> {
        for entry in self.state.list_unhydrated()? {
            self.schedule_download(&entry.path);
        }
        Ok(())
    }

    fn schedule_download(&self, path: &str) {
        let path = path.to_string();
        let scheduled = self.scheduled.clone();
        let sender = self.downloads.clone();
        tokio::spawn(async move {
            let mut set = scheduled.lock().unwrap();
            if set.insert(path.clone()) {
                let _ = sender.send(path);
            }
        });
    }

    // -- hydration --------------------------------------------------------

    fn spawn_hydration_loop(&self, receiver: Arc<Mutex<mpsc::UnboundedReceiver<String>>>) {
        let hydrator = self.self_arc();
        let task = tokio::spawn(async move {
            loop {
                let path = {
                    let mut rx = receiver.lock().await;
                    rx.recv().await
                };
                let Some(path) = path else {
                    break;
                };
                if hydrator.is_shutdown() {
                    break;
                }
                hydrator.hydrate(&path).await;
            }
        });
        self.push_task(task);
    }

    async fn hydrate(&self, path: &str) {
        self.hydrating.lock().unwrap().insert(path.to_string());
        self.hydrate_inner(path).await;
        self.hydrating.lock().unwrap().remove(path);
        // A successful download is a completed operation: never leave a stale
        // "Syncing" status behind if this was the last outstanding work.
        if matches!(self.status().state, SyncState::Syncing) && self.pending_count() == 0 {
            self.publish(SyncState::Synced, "file hydrated");
        }
    }

    async fn hydrate_inner(&self, path: &str) {
        self.update_detail(
            SyncPhase::Downloading,
            format!("Downloading {path}"),
            Some(path),
            0,
            0,
        );
        let entry = match self.state.get_entry(path) {
            Ok(Some(entry)) => entry,
            Ok(None) => return,
            Err(error) => {
                error!("cannot read entry {path}: {error}");
                return;
            }
        };
        let Some(id) = entry.remote_docwsid.clone() else {
            return;
        };
        let zone = entry
            .remote_zone
            .clone()
            .unwrap_or_else(|| "com.apple.CloudDocs".into());
        let owner = entry.remote_shareid.as_deref().and_then(owner_from_shareid);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let permit = match self.download_slots.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(error) => {
                    error!("download semaphore closed: {error}");
                    break;
                }
            };
            let result = self.api.download(&id, &zone, owner.as_deref()).await;
            drop(permit);
            match result {
                Ok(bytes) => {
                    let checksum = format!("{:x}", Sha256::digest(&bytes));
                    let size = bytes.len() as i64;
                    match self.mirror.write_atomic_stream(
                        path,
                        Cursor::new(&bytes),
                        Some(entry.mtime),
                    ) {
                        Ok(_) => {
                            let _ =
                                self.state
                                    .mark_hydrated(path, Some(&checksum), size, entry.mtime);
                            self.record_change(ChangeKind::Downloaded, path);
                            debug!("hydrated {path} ({size} bytes)");
                            break;
                        }
                        Err(error) => error!("cannot write {path}: {error}"),
                    }
                }
                Err(Error::Auth(_)) | Err(Error::TwoFactor(_)) => {
                    self.publish(SyncState::LoginRequired, "login required to download files");
                    break;
                }
                Err(error) if error.is_offline() => {
                    self.publish(
                        SyncState::Offline,
                        format!("offline: could not download {path}"),
                    );
                    break;
                }
                Err(error) => {
                    warn!("download {path} failed (attempt {attempt}): {error}");
                    if attempt >= 5 {
                        self.publish(SyncState::Error, format!("download failed for {path}"));
                        break;
                    }
                    sleep(Duration::from_secs(2u64.pow(attempt - 1))).await;
                }
            }
        }
        self.scheduled.lock().unwrap().remove(path);
        self.update_detail(SyncPhase::Idle, "Up to date", None, 0, 0);
    }

    // -- local changes / uploads -----------------------------------------

    fn mark_local_change(&self, path: &str) -> Result<()> {
        let canonical = config::normalize_icloud_path(path);
        let path = canonical.as_str();
        if path.contains(".local-conflict-") {
            return Ok(());
        }
        let meta = self.mirror.metadata(path)?;
        // Directory mtime changes caused by hydration/content writes are not
        // user changes. Child file events carry the real change.
        if meta.is_dir()
            && let Some(existing) = self.state.get_entry(path)?
            && existing.remote_drivewsid.is_some()
        {
            return Ok(());
        }
        let size = meta.len() as i64;
        let mtime = meta
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let checksum = if meta.is_dir() {
            None
        } else {
            Some(self.mirror.sha256(path)?)
        };

        if let Some(entry) = self.state.get_entry(path)? {
            if !entry.dirty {
                // Ignore events caused by our own hydration of a placeholder.
                if !entry.hydrated && !entry.is_dir() {
                    return Ok(());
                }
                if entry.mtime == mtime
                    && entry.size == size
                    && entry.local_sha256.as_deref() == checksum.as_deref()
                {
                    return Ok(());
                }
            }
            self.state
                .mark_dirty(path, checksum.as_deref(), size, mtime)?;
            self.state.queue_op("modify", path, None)?;
        } else {
            let entry = Entry {
                path: path.into(),
                entry_type: if meta.is_dir() {
                    "folder".into()
                } else {
                    "file".into()
                },
                parent_path: parent_path(path),
                remote_drivewsid: None,
                remote_docwsid: None,
                remote_etag: None,
                remote_zone: None,
                remote_shareid: None,
                size,
                mtime,
                hydrated: true,
                dirty: true,
                tombstone: false,
                local_sha256: checksum,
                last_synced_at: None,
                synced_path: None,
            };
            self.state.upsert_entry(&entry)?;
            self.state.queue_op("create", path, None)?;
        }
        self.local_changes.note(path);
        self.notify_local_change();
        Ok(())
    }

    /// Mark local files that exist in the mirror but have no DB row yet —
    /// typically created while the app was not running, so the watcher never
    /// saw them. Called once after the first crawl; the upload loop then
    /// pushes them like any other local change.
    fn scan_untracked_local_files(&self) {
        fn walk(dir: &Path, icloud: &str, out: &mut Vec<String>) {
            let Ok(entries) = fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let relative = if icloud.is_empty() {
                    name.clone()
                } else {
                    format!("{icloud}/{name}")
                };
                if entry.path().is_dir() {
                    walk(&entry.path(), &relative, out);
                } else {
                    out.push(relative);
                }
            }
        }
        let mut files = Vec::new();
        walk(&self.mirror.root(), "", &mut files);
        for relative in files {
            let path = config::normalize_icloud_path(&relative);
            if self.state.get_entry(&path).ok().flatten().is_none() {
                // Debug, not warn: a missing row is expected for files that
                // predate the app or the user's session.
                self.mark_local_change(&path).ok();
            }
        }
    }

    fn mark_local_delete(&self, path: &str) -> Result<()> {
        let canonical = config::normalize_icloud_path(path);
        let path = canonical.as_str();
        if path.contains(".local-conflict-") {
            return Ok(());
        }
        if let Some(entry) = self.state.get_entry(path)? {
            if entry.remote_drivewsid.is_some() {
                self.state.mark_tombstone(path)?;
                self.state.queue_op("delete", path, None)?;
            } else {
                self.state.remove_subtree(path)?;
            }
            self.local_changes.note(path);
            self.notify_local_change();
            self.record_change(ChangeKind::Removed, path);
        }
        Ok(())
    }

    fn mark_local_rename(&self, from: &str, to: &str) -> Result<()> {
        let from = config::normalize_icloud_path(from);
        let to = config::normalize_icloud_path(to);
        if self.state.get_entry(&from)?.is_some() {
            self.state.rename_tree(&from, &to, false)?;
            self.state.queue_op("rename", &to, Some(&from))?;
            self.local_changes.note(&from);
            self.local_changes.note(&to);
            self.notify_local_change();
        } else if self.state.get_entry(&to)?.is_none() {
            // A brand-new local file renamed before its first upload has no
            // row yet: treat the destination as a new file so it still syncs.
            self.mark_local_change(&to)?;
        }
        Ok(())
    }

    fn ensure_hydrated(&self, path: &str) -> Result<()> {
        if self.read_only() {
            return Ok(());
        }
        if let Some(entry) = self.state.get_entry(path)?
            && !entry.hydrated
            && entry.remote_docwsid.is_some()
        {
            self.schedule_download(path);
        }
        Ok(())
    }

    /// Mark an uploaded row clean only when it owns a remote id. A local
    /// folder whose `createFolders` response was ignored used to be cleaned
    /// anyway, leaving all of its children permanently un-uploadable.
    /// Returns `false` when the row must stay dirty and be retried.
    fn finish_upload(&self, path: &str, now: i64) -> Result<bool> {
        let Some(fresh) = self.state.get_entry(path)? else {
            // Tombstones remove their row on success.
            return Ok(true);
        };
        if fresh.tombstone {
            return Ok(true);
        }
        if fresh.remote_drivewsid.is_none() {
            return Ok(false);
        }
        self.state
            .mark_clean(path, now, fresh.local_sha256.as_deref())?;
        Ok(true)
    }

    pub async fn sync_dirty(&self) -> Result<()> {
        let result = self.sync_dirty_inner().await;
        self.finish_sync(&result, "local changes uploaded");
        result
    }

    async fn sync_dirty_inner(&self) -> Result<()> {
        if self.api.is_offline() {
            return Err(Error::Offline("local changes will sync later".into()));
        }
        if self.read_only() {
            return Err(Error::Auth("sign in before uploading changes".into()));
        }
        // Stale rows from the old doubled-path crawl have no remote identity
        // and must never be recreated on the cloud by the upload loop.
        drop_stale_duplicates(&self.state, &self.mirror)?;
        drop_orphan_ghost_files(&self.state, &self.mirror)?;
        // Drop mtime-only "modify" operations for already-tracked directories.
        // Hydration rewrites children and bumps parent mtimes; that is not a
        // remote change and caused repeated conflict copies of whole folders.
        let dir_modify_ops: Vec<(i64, String)> = self
            .state
            .list_pending_ops()?
            .into_iter()
            .filter(|op| op.op == "modify")
            .filter_map(|op| {
                self.state
                    .get_entry(&op.path)
                    .ok()
                    .flatten()
                    .filter(|entry| entry.is_dir() && entry.remote_drivewsid.is_some())
                    .map(|_| (op.id, op.path))
            })
            .collect();
        if !dir_modify_ops.is_empty() {
            let now = chrono::Utc::now().timestamp();
            for (id, path) in dir_modify_ops {
                self.state.delete_op(id)?;
                self.state.mark_clean(&path, now, None)?;
            }
        }

        let mut failures = 0usize;
        // A pure local rename of an already-synced item leaves the row clean,
        // so it lives only in pending_ops. Handle it before the dirty list is
        // consulted, otherwise the op would be pruned and never reach Apple.
        let rename_ops: Vec<_> = self
            .state
            .list_pending_ops()?
            .into_iter()
            .filter(|op| op.op == "rename")
            .collect();
        for op in rename_ops {
            let Some(entry) = self.state.get_entry(&op.path)? else {
                self.state.delete_op(op.id)?;
                continue;
            };
            if entry.dirty
                || entry.tombstone
                || entry.remote_drivewsid.is_none()
                || entry.synced_path.as_deref() == Some(entry.path.as_str())
            {
                // Dirty entries are processed by sync_file/sync_directory below.
                continue;
            }
            match self.sync_move_or_rename(&entry).await {
                Ok(()) => {
                    let now = chrono::Utc::now().timestamp();
                    self.state
                        .mark_clean(&entry.path, now, entry.local_sha256.as_deref())?;
                    self.state.delete_op(op.id)?;
                    if self.cfg().instant_sync {
                        self.request_remote_sync();
                    }
                }
                Err(error) => {
                    failures += 1;
                    let _ = self.state.bump_op_retry(op.id, &error.to_string());
                    self.notify_warning(format!("Could not rename {}: {error}", entry.path));
                }
            }
        }

        let mut dirty = self.state.list_dirty()?;
        // Hydration may leave dirty rows whose content already matches the
        // stored checksum. Re-uploading them is pointless and produced hundreds
        // of queued modify ops, leaving the UI stuck at "syncing".
        let already_clean: Vec<String> = dirty
            .iter()
            .filter(|entry| {
                if entry.tombstone || entry.is_dir() || entry.remote_drivewsid.is_none() {
                    return false;
                }
                // A queued local-change op is proof the user edited the file:
                // `mark_dirty` stores the NEW checksum, so comparing hashes
                // alone would silently discard real edits (== "nothing syncs").
                // Only self-generated hydration dirt without an op is skipped.
                !self.state.has_local_change_op(&entry.path).unwrap_or(true)
                    && entry.local_sha256.is_some()
            })
            .filter(|entry| {
                let local = match self.mirror.local_path(&entry.path) {
                    Ok(path) => path,
                    Err(_) => return false,
                };
                if !local.is_file() {
                    return false;
                }
                match self.mirror.sha256(&entry.path) {
                    Ok(hash) => Some(hash) == entry.local_sha256,
                    Err(_) => false,
                }
            })
            .map(|entry| entry.path.clone())
            .collect();
        if !already_clean.is_empty() {
            let now = chrono::Utc::now().timestamp();
            for path in already_clean {
                self.state.clear_pending_subtree(&path)?;
                self.state.mark_clean(&path, now, None)?;
            }
            dirty = self.state.list_dirty()?;
        }
        // Conflict copies are local-only by design. They must never be
        // uploaded, and their stale queued operations must not be retried.
        let conflict_paths: Vec<String> = self
            .state
            .list_entries()?
            .into_iter()
            .filter(|entry| entry.path.contains(".local-conflict-"))
            .map(|entry| entry.path)
            .collect();
        if !conflict_paths.is_empty() {
            self.state.clear_all_conflict_pending()?;
            let now = chrono::Utc::now().timestamp();
            for path in conflict_paths {
                self.state.clear_pending_subtree(&path)?;
                self.state.mark_clean(&path, now, None)?;
            }
            dirty.retain(|entry| !entry.path.contains(".local-conflict-"));
        }
        if dirty.is_empty() {
            self.update_detail(SyncPhase::Idle, "Up to date", None, 0, 0);
            self.set_next_sync();
            return Ok(());
        }
        dirty.sort_by(|a, b| match (a.tombstone, b.tombstone) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (true, true) => {
                let depth_a = a.path.matches('/').count();
                let depth_b = b.path.matches('/').count();
                depth_b.cmp(&depth_a).then_with(|| a.path.cmp(&b.path))
            }
            (false, false) => {
                let kind_a = a.is_dir();
                let kind_b = b.is_dir();
                kind_b
                    .cmp(&kind_a)
                    .then_with(|| {
                        a.path
                            .matches('/')
                            .count()
                            .cmp(&b.path.matches('/').count())
                    })
                    .then_with(|| a.path.cmp(&b.path))
            }
        });
        self.update_detail(
            SyncPhase::Uploading,
            format!("Uploading {} local change(s)", dirty.len()),
            None,
            0,
            dirty.len() as u64,
        );
        self.publish(SyncState::Syncing, "uploading local changes");
        let total = dirty.len() as u64;
        for (index, entry) in dirty.into_iter().enumerate() {
            self.update_detail(
                SyncPhase::Uploading,
                format!("Uploading {}", entry.path),
                Some(&entry.path),
                index as u64,
                total,
            );
            // Re-arm the purge grace for every queued local change, including
            // rows queued before this engine started (e.g. on bootstrap).
            self.local_changes.note(&entry.path);
            let result = if entry.tombstone {
                self.sync_tombstone(&entry).await
            } else if entry.is_dir() {
                self.sync_directory(&entry).await
            } else {
                self.sync_file(&entry).await
            };
            match result {
                Ok(()) => {
                    let now = chrono::Utc::now().timestamp();
                    if !self.finish_upload(&entry.path, now)? {
                        failures += 1;
                        self.notify_warning(format!(
                            "Keeping {} dirty: no remote identity was recorded",
                            entry.path
                        ));
                    } else if !entry.tombstone {
                        // Apple's metadata is eventually consistent: keep this
                        // path protected until a crawl actually sees the node.
                        self.local_changes.note_awaiting_visibility(&entry.path);
                        self.record_change(ChangeKind::Uploaded, entry.path.clone());
                    }
                    // The remote copy just changed; verify it right away when
                    // instant sync is enabled instead of waiting for the poll.
                    if self.cfg().instant_sync {
                        self.request_remote_sync();
                    }
                }
                Err(error) if error.is_auth() => {
                    return Err(Error::Auth("login required to upload changes".into()));
                }
                Err(error) => {
                    failures += 1;
                    self.notify_warning(format!("Could not sync {}: {error}", entry.path));
                    if let Ok(ops) = self.state.list_pending_ops() {
                        for op in ops.iter().filter(|op| op.path == entry.path) {
                            let _ = self.state.bump_op_retry(op.id, &error.to_string());
                        }
                    }
                }
            }
        }
        self.set_next_sync();
        self.update_detail(SyncPhase::Idle, "Upload complete", None, 0, 0);
        if failures > 0 {
            return Err(Error::other(format!(
                "{failures} local change(s) could not be uploaded; will retry"
            )));
        }
        Ok(())
    }

    async fn sync_tombstone(&self, entry: &Entry) -> Result<()> {
        let Some(id) = entry.remote_drivewsid.as_deref() else {
            self.state.remove_subtree(&entry.path)?;
            self.record_change(ChangeKind::Removed, entry.path.clone());
            return Ok(());
        };
        let etag = entry.remote_etag.as_deref().unwrap_or_default();
        self.api.delete_node(id, etag).await?;
        self.state.remove_subtree(&entry.path)?;
        self.record_change(ChangeKind::Removed, entry.path.clone());
        Ok(())
    }

    async fn sync_directory(&self, entry: &Entry) -> Result<()> {
        if entry.remote_drivewsid.is_some() {
            self.sync_move_or_rename(entry).await?;
            self.state.mark_synced_subtree(&entry.path)?;
            return Ok(());
        }
        let parent_id = self.remote_id_for_path(&parent_path(&entry.path)).await?;
        let response = self
            .api
            .create_folder(&parent_id, &basename(&entry.path))
            .await?;
        // Apple wraps the new node in `items`. The old code read the top-level
        // `clientId` (our own temporary id!) as the remote id, so folders were
        // marked clean with no real identity and every child failed with
        // "remote parent ... is not uploaded yet".
        let identity = folder_identity_from_response(&response).ok_or_else(|| {
            Error::other(format!(
                "createFolders returned no remote identity for {}",
                entry.path
            ))
        })?;
        let mut doc_id = identity.docwsid;
        let mut etag = identity.etag;
        let mut zone = identity.zone;
        if doc_id.is_none() {
            match self.api.retrieve_node(&identity.drivewsid, None).await {
                Ok(node) => {
                    doc_id = node.docwsid.clone();
                    etag = etag.or(node.etag);
                    if zone.is_none() {
                        zone = node.zone.clone();
                    }
                }
                Err(error) => self.notify_warning(format!(
                    "Could not refresh new folder {}: {error}",
                    entry.path
                )),
            }
        }
        self.state.update_remote_fields(
            &entry.path,
            Some(&identity.drivewsid),
            doc_id.as_deref(),
            etag.as_deref(),
            Some(zone.as_deref().unwrap_or(CLOUD_DOCS_ZONE)),
        )?;
        // Never report success unless the row actually owns a remote id.
        if self
            .state
            .get_entry(&entry.path)?
            .and_then(|fresh| fresh.remote_drivewsid)
            .is_none()
        {
            return Err(Error::other(format!(
                "new folder {} still has no remote id",
                entry.path
            )));
        }
        Ok(())
    }

    async fn sync_file(&self, entry: &Entry) -> Result<()> {
        if !self.mirror.exists(&entry.path) {
            self.state.mark_tombstone(&entry.path)?;
            return Ok(());
        }
        let parent_folder = parent_path(&entry.path);
        let parent_drivewsid = self.remote_id_for_path(&parent_folder).await?;
        let (parent_doc_id, zone) = self.remote_doc_id_for_path(&parent_folder)?;
        let name = basename(&entry.path);
        if entry.remote_drivewsid.is_some() {
            self.sync_move_or_rename(entry).await?;
            if let Some(id) = entry.remote_drivewsid.as_deref() {
                let etag = entry.remote_etag.as_deref().unwrap_or_default();
                if let Err(error) = self.api.delete_node(id, etag).await {
                    self.notify_warning(format!(
                        "Could not remove stale remote file {}: {error}",
                        entry.path
                    ));
                }
            }
        }
        let content = std::fs::read(self.mirror.local_path(&entry.path)?)?;
        let response = self
            .api
            .upload(&parent_doc_id, &zone, &name, content, entry.mtime)
            .await?;
        // The update response has no drivewsid: Python re-reads the parent's
        // children after an upload to record the new node's remote identity.
        let mut drivewsid = None;
        let mut docwsid = None;
        let mut etag = None;
        let mut remote_zone = None;
        match self.api.retrieve_node(&parent_drivewsid, None).await {
            Ok(parent) => {
                if let Some(child) = parent
                    .items
                    .as_ref()
                    .and_then(|items| items.iter().find(|node| node.display_name() == name))
                {
                    drivewsid = Some(child.drivewsid.clone());
                    docwsid = child.docwsid.clone();
                    etag = child.etag.clone();
                    remote_zone = child.zone.clone();
                }
            }
            Err(error) => self.notify_warning(format!(
                "Could not refresh uploaded file {}: {error}",
                entry.path
            )),
        }
        // If the crawl has not caught up yet, fall back to the nested document
        // in the update response so the row never stays identity-less.
        if docwsid.is_none()
            && let Some(uploaded) = uploaded_document(&response)
        {
            docwsid = Some(uploaded.docwsid.clone());
            etag = etag.or(uploaded.etag);
            let cloud_docs = uploaded.zone.as_deref().unwrap_or(CLOUD_DOCS_ZONE) == CLOUD_DOCS_ZONE;
            remote_zone = remote_zone.or(uploaded.zone);
            if drivewsid.is_none() && cloud_docs {
                drivewsid = Some(format!("FILE::{CLOUD_DOCS_ZONE}::{}", uploaded.docwsid));
            }
        }
        self.state.update_remote_fields(
            &entry.path,
            drivewsid.as_deref(),
            docwsid.as_deref(),
            etag.as_deref(),
            remote_zone.as_deref(),
        )?;
        Ok(())
    }

    async fn sync_move_or_rename(&self, entry: &Entry) -> Result<()> {
        let (Some(id), Some(synced)) = (
            entry.remote_drivewsid.as_deref(),
            entry.synced_path.as_deref(),
        ) else {
            return Ok(());
        };
        if synced == entry.path {
            return Ok(());
        }
        let mut etag = entry.remote_etag.clone().unwrap_or_default();
        let moved = parent_path(synced) != parent_path(&entry.path);
        if moved {
            let destination = self.remote_id_for_path(&parent_path(&entry.path)).await?;
            self.api.move_node(id, &etag, &destination).await?;
            // Python re-reads the node after a move: the etag changes and a
            // simultaneous rename must use the fresh one.
            let share = entry
                .remote_shareid
                .as_deref()
                .and_then(|value| serde_json::from_str::<Value>(value).ok());
            if let Ok(node) = self.api.retrieve_node(id, share.as_ref()).await {
                if let Some(fresh) = node.etag {
                    etag = fresh;
                }
                self.state.update_remote_fields(
                    &entry.path,
                    None,
                    node.docwsid.as_deref(),
                    Some(&etag),
                    node.zone.as_deref(),
                )?;
            }
        }
        // A move that also changes the basename needs both operations, exactly
        // like the Python driver's `_sync_move_or_rename`.
        if basename(synced) != basename(&entry.path) {
            self.api
                .rename_node(id, &etag, &basename(&entry.path))
                .await?;
        }
        self.state.update_synced_path(&entry.path)?;
        self.record_change(ChangeKind::Renamed, entry.path.clone());
        Ok(())
    }

    async fn remote_id_for_path(&self, path: &str) -> Result<String> {
        if path == "/" {
            return Ok(ROOT_DRIVEWSID.into());
        }
        if let Some(entry) = self.state.get_entry(path)?
            && let Some(id) = entry.remote_drivewsid
        {
            return Ok(id);
        }
        self.state.queue_op("create", path, None)?;
        self.mark_folder_dirty_for_upload(path);
        let message = format!("Remote parent for {path} is not uploaded yet");
        self.notify_warning(message.clone());
        Err(Error::other(message))
    }

    /// Insert a dirty folder row for `path` and queue its `create` op so the
    /// upload loop creates the folder on its next pass. Without this, an
    /// upload blocked on a missing parent retries forever with no path
    /// forward.
    fn mark_folder_dirty_for_upload(&self, path: &str) {
        if self.state.get_entry(path).ok().flatten().is_none() {
            let entry = Entry {
                path: path.to_string(),
                entry_type: "folder".into(),
                parent_path: parent_path(path),
                remote_drivewsid: None,
                remote_docwsid: None,
                remote_etag: None,
                remote_zone: None,
                remote_shareid: None,
                size: 0,
                mtime: 0,
                hydrated: true,
                dirty: true,
                tombstone: false,
                local_sha256: None,
                last_synced_at: None,
                synced_path: None,
            };
            if let Err(error) = self.state.upsert_entry(&entry) {
                debug!("could not mark {path} dirty for upload: {error}");
            }
        }
        if let Err(error) = self.state.queue_op("create", path, None) {
            debug!("could not queue create for {path}: {error}");
        }
        self.local_changes.note(path);
        self.notify_local_change();
    }

    /// Parent identity used by `/update/documents` when adding a file.
    ///
    /// The drivewsid (`FOLDER::com.apple.CloudDocs::…`) is for drivews
    /// operations (create/move/delete); the document service chains a new
    /// file to its parent by **docwsid** (a bare UUID, or `root`). Passing a
    /// drivewsid here is what makes Apple answer HTTP 412
    /// `VALIDATING_REFERENCE_ERROR` ("parents were missing").
    fn remote_doc_id_for_path(&self, path: &str) -> Result<(String, String)> {
        let entry = self.state.get_entry(path)?;
        let drivewsid = entry
            .as_ref()
            .and_then(|entry| entry.remote_drivewsid.clone())
            .or_else(|| (path == "/").then(|| ROOT_DRIVEWSID.to_string()));
        let Some(drivewsid) = drivewsid else {
            self.state.queue_op("create", path, None)?;
            self.mark_folder_dirty_for_upload(path);
            let message = format!("Remote parent for {path} is not uploaded yet");
            self.notify_warning(message.clone());
            return Err(Error::other(message));
        };
        let docwsid = entry
            .as_ref()
            .and_then(|entry| entry.remote_docwsid.clone())
            .or_else(|| docwsid_from_drivewsid(&drivewsid))
            .or_else(|| (path == "/").then(|| ROOT_DOCWSID.to_string()))
            .ok_or_else(|| Error::other(format!("remote parent for {path} has no document id")))?;
        let zone = entry
            .as_ref()
            .and_then(|entry| entry.remote_zone.clone())
            .unwrap_or_else(|| CLOUD_DOCS_ZONE.to_string());
        Ok((docwsid, zone))
    }

    /// A watcher event for an empty local directory with no remote node and
    /// no dirty DB entry is a ghost; creating a row for it would resurrect it.
    fn is_ignorable_empty_ghost(&self, relative: &str) -> bool {
        let Some(view) = self.remote_view.lock().unwrap().clone() else {
            return false;
        };
        let path = if relative.starts_with('/') {
            relative.to_string()
        } else {
            format!("/{relative}")
        };
        if view.paths.contains(&path) || path.contains(".local-conflict-") {
            return false;
        }
        if matches!(self.state.get_entry(&path), Ok(Some(entry)) if entry.dirty || entry.tombstone)
        {
            return false;
        }
        let Ok(local) = self.mirror.local_path(relative) else {
            return false;
        };
        local.is_dir()
            && fs::read_dir(local)
                .map(|mut children| children.next().is_none())
                .unwrap_or(false)
    }

    /// Whether a directory still contains a child shaped like `<name>/<name>`.
    /// Such a child may hold real content that reconciliation refused to drop.
    fn has_duplicate_child(&self, path: &str) -> bool {
        let Ok(local) = self.mirror.local_path(path) else {
            return false;
        };
        let Ok(children) = fs::read_dir(local) else {
            return false;
        };
        for child in children.flatten() {
            if child.path().is_dir() {
                let name = child.file_name().to_string_lossy().into_owned();
                if is_duplicate_shape(&join_path(path, &name)) {
                    return true;
                }
            }
        }
        false
    }

    fn reconcile_cache(&self) -> Result<()> {
        let entries = self.state.list_entries()?;
        let mut recreated = 0;
        for entry in entries {
            if entry.tombstone || !self.path_allowed(&entry.path) {
                continue;
            }
            if entry.is_dir() {
                if !self.mirror.exists(&entry.path) {
                    self.mirror.ensure_dir(&entry.path)?;
                    recreated += 1;
                }
                continue;
            }
            if self.mirror.exists(&entry.path) {
                let meta = self.mirror.metadata(&entry.path)?;
                let size = meta.len() as i64;
                let mtime = meta
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let checksum =
                    if entry.local_sha256.is_none() || entry.size != size || entry.mtime != mtime {
                        Some(self.mirror.sha256(&entry.path)?)
                    } else {
                        entry.local_sha256.clone()
                    };
                self.state.upsert_entry(&Entry {
                    hydrated: entry.hydrated || entry.remote_drivewsid.is_none() || size == 0,
                    size,
                    mtime,
                    local_sha256: checksum,
                    ..entry
                })?;
                continue;
            }
            if entry.remote_drivewsid.is_some() {
                self.mirror.materialize_placeholder(
                    &entry.path,
                    entry.size.max(0) as u64,
                    entry.mtime,
                )?;
                self.state.upsert_entry(&Entry {
                    hydrated: entry.size == 0,
                    ..entry
                })?;
            } else {
                self.mirror.write_all(&entry.path, b"")?;
                let checksum = self.mirror.sha256(&entry.path)?;
                self.state.upsert_entry(&Entry {
                    hydrated: true,
                    size: 0,
                    local_sha256: Some(checksum),
                    ..entry
                })?;
            }
        }
        info!("persistent cache ready: {recreated} directories recreated");
        Ok(())
    }

    // -- relocation -------------------------------------------------------

    fn relocate_folder(&self, new_folder: PathBuf) -> Result<RelocationReport> {
        if self.status().state != SyncState::Synced {
            return Err(Error::NotClean(
                "sync must be Synced before moving the folder".into(),
            ));
        }
        if self.pending_count() > 0
            || self.state.count_pending_ops()? > 0
            || self.state.count_unhydrated()? > 0
        {
            return Err(Error::NotClean(
                "dirty, pending or unhydrated entries remain; sync first".into(),
            ));
        }
        self.update_detail(
            SyncPhase::Relocating,
            "Moving local sync folder",
            None,
            0,
            0,
        );
        self.publish(SyncState::Relocating, "moving local sync folder");
        let result = self.perform_relocation(new_folder);
        match &result {
            Ok(report) => self.publish(
                SyncState::Synced,
                format!(
                    "moved {} files to {}",
                    report.moved_files,
                    report.to.display()
                ),
            ),
            Err(error) => self.publish(SyncState::Error, format!("folder move failed: {error}")),
        }
        self.update_detail(SyncPhase::Idle, "Up to date", None, 0, 0);
        result
    }

    fn perform_relocation(&self, new_folder: PathBuf) -> Result<RelocationReport> {
        let old_config = self.cfg();
        let config_path = relocation::config_path(&old_config)?;
        let report = relocation::move_contents(&old_config.sync_folder, &new_folder)?;

        let mut new_config = old_config.clone();
        new_config.sync_folder = new_folder.clone();
        new_config.set_config_path(config_path.clone());
        if let Err(error) = relocation::rewrite_config(&new_config, &config_path) {
            // Roll the files back so config and filesystem stay consistent.
            let _ = relocation::move_contents(&new_folder, &old_config.sync_folder);
            return Err(error);
        }
        if let Err(error) = self.mirror.relocate_root(new_folder) {
            let _ = relocation::rewrite_config(&old_config, &config_path);
            return Err(error);
        }
        *self.config.lock().unwrap() = new_config;
        Ok(report)
    }
}

/// Repair rows/files that an older build stored without Apple's separate
/// `extension` field.
///
/// Only nodes whose canonical name is exactly `<old name>.<extension>` in the
/// same folder are considered, so unrelated local files and genuine renames
/// are never touched. Local content is *moved* (never deleted): if both paths
/// hold real content the canonical file wins and the other file is left in
/// place rather than risking data loss.
fn repair_extensionless_paths(
    state: &Database,
    mirror: &Mirror,
    snapshot: &HashMap<String, RemoteNode>,
) -> Result<usize> {
    let entries = state.list_entries()?;
    let mut repaired = 0usize;
    for (canonical, node) in snapshot {
        if node.is_dir() {
            continue;
        }
        let Some(ext) = node.extension.as_deref().filter(|ext| !ext.is_empty()) else {
            continue;
        };
        let Some(canonical_name) = canonical.rsplit('/').next() else {
            continue;
        };
        let Some(plain_name) = canonical_name.strip_suffix(&format!(".{ext}")) else {
            continue;
        };
        if plain_name.is_empty() {
            continue;
        }
        let old_path = join_path(&parent_path(canonical), plain_name);
        if old_path == *canonical {
            continue;
        }
        let old_local = mirror.local_path(&old_path)?;
        let new_local = mirror.local_path(canonical)?;
        let file_size = |path: &std::path::Path| fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let old_entry = entries.iter().find(|entry| entry.path == old_path);

        if let Some(old_entry) = old_entry.filter(|entry| !entry.tombstone)
            && old_entry.remote_drivewsid.as_deref() == Some(node.drivewsid.as_str())
        {
            let canonical_entry = entries.iter().find(|entry| entry.path == *canonical);
            if canonical_entry.is_some_and(|entry| {
                entry.remote_drivewsid.as_deref() != Some(node.drivewsid.as_str())
            }) {
                // A different remote node legitimately owns the canonical path.
                continue;
            }
            if old_local.is_file() {
                let new_has_content = new_local.is_file() && file_size(&new_local) > 0;
                if !new_has_content {
                    mirror.rename(&old_path, canonical)?;
                }
            }
            if canonical_entry.is_some() {
                state.remove_subtree(&old_path)?;
            } else {
                state.rename_tree_preserving_state(&old_path, canonical)?;
            }
            repaired += 1;
            continue;
        }

        // No stale row, but an extensionless local file with content may be
        // left over from the same bug. Move it onto the canonical path before
        // materialization creates a second copy.
        if old_entry.is_none() && old_local.is_file() && file_size(&old_local) > 0 {
            let new_has_content = new_local.is_file() && file_size(&new_local) > 0;
            if !new_has_content {
                mirror.rename(&old_path, canonical)?;
                repaired += 1;
            }
        }
    }
    if repaired > 0 {
        info!("repaired {repaired} extensionless paths from remote metadata");
    }
    Ok(repaired)
}

/// Walk the remote tree and build canonical paths in one place.
///
/// Only `root`'s children are mirrored: Apple already lists the user's app
/// libraries there (Pages, etc.), while `app_libraries()` is a catalogue of
/// every app container on the account. The root is the only node mapped to
/// `/`, and every other node contributes exactly one sanitized component.
/// Walk the remote tree, fetching node details for folders whose children were
/// not inlined. Apple's root response lists folders with `items: null`; without
/// `retrieveItemDetailsInFolders` the crawl sees zero files.
async fn collect_remote_nodes(
    api: &ICloudApi,
    root: RemoteNode,
    allowed: impl Fn(&str) -> bool,
) -> Result<(Vec<(String, RemoteNode)>, HashMap<String, String>)> {
    let mut queue = vec![("/".to_string(), root, true)];
    let mut visited = HashSet::new();
    let mut nodes = Vec::new();
    let mut id_paths = HashMap::new();
    while let Some((parent, mut node, is_root)) = queue.pop() {
        if !visited.insert(node.drivewsid.clone()) {
            continue;
        }
        let path = if is_root {
            "/".to_string()
        } else {
            join_path(&parent, &node.display_name())
        };
        // The root is the crawl entry point; an allowlist of real folders
        // must not prevent us from enumerating its children.
        if !is_root
            && (path == "/TRASH_ROOT" || path.starts_with("/TRASH_ROOT/") || !allowed(&path))
        {
            continue;
        }
        id_paths.insert(node.drivewsid.clone(), path.clone());

        let mut children = node.items.clone().unwrap_or_default();
        if !is_root && node.is_dir() && children.is_empty() {
            match api
                .retrieve_node(&node.drivewsid, node.share_id.as_ref())
                .await
            {
                Ok(detail) => {
                    children = detail.items.clone().unwrap_or_default();
                    if node.etag.is_none() {
                        node.etag = detail.etag;
                    }
                    if node.size == 0 {
                        node.size = detail.size;
                    }
                    if node.date_changed.is_none() {
                        node.date_changed = detail.date_changed;
                    }
                }
                Err(error) => {
                    debug!("could not list children of {path}: {error}");
                }
            }
        }
        for child in children {
            queue.push((path.clone(), child, false));
        }
        nodes.push((path, node));
    }
    Ok((nodes, id_paths))
}

/// Synchronous test-only walker for inlined node trees.
#[cfg(test)]
fn walk_remote_nodes(
    root: RemoteNode,
    allowed: impl Fn(&str) -> bool,
) -> (Vec<(String, RemoteNode)>, HashMap<String, String>) {
    let mut queue = vec![("/".to_string(), root, true)];
    let mut visited = HashSet::new();
    let mut nodes = Vec::new();
    let mut id_paths = HashMap::new();
    while let Some((parent, node, is_root)) = queue.pop() {
        if !visited.insert(node.drivewsid.clone()) {
            continue;
        }
        let path = if is_root {
            "/".to_string()
        } else {
            join_path(&parent, &node.display_name())
        };
        if !is_root
            && (path == "/TRASH_ROOT" || path.starts_with("/TRASH_ROOT/") || !allowed(&path))
        {
            continue;
        }
        id_paths.insert(node.drivewsid.clone(), path.clone());
        for child in node.items.clone().unwrap_or_default() {
            queue.push((path.clone(), child, false));
        }
        nodes.push((path, node));
    }
    (nodes, id_paths)
}

/// `path` is `canonical` followed by one or more repeats of its own basename.
/// This is the signature of the old `/Parent/Parent` build.
fn is_duplicate_path(path: &str, canonical: &str) -> bool {
    if canonical == "/" || !path.starts_with(canonical) {
        return false;
    }
    let rest = &path[canonical.len()..];
    if !rest.starts_with('/') {
        return false;
    }
    let leaf = canonical
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("");
    if leaf.is_empty() {
        return false;
    }
    rest.split('/')
        .filter(|part| !part.is_empty())
        .all(|part| part == leaf)
}

/// A path whose final component repeats an ancestor component, e.g.
/// `/dir/dir`.
fn is_duplicate_shape(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let Some(last) = parts.last().copied() else {
        return false;
    };
    parts.len() > 1 && parts[..parts.len() - 1].contains(&last)
}

/// Any file anywhere under `path` means there may be user data: leave it.
fn dir_has_file(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            if dir_has_file(&child) {
                return true;
            }
        } else {
            return true;
        }
    }
    false
}

/// A non-empty file (or any directory containing a file) is real local data.
/// `dir_has_file()` alone returned false for a *file* path, which is exactly
/// how a just-uploaded file got purged before Apple's crawl listed it.
fn local_path_has_content(mirror: &Mirror, path: &str) -> bool {
    let Ok(local) = mirror.local_path(path) else {
        return false;
    };
    if local.is_file() {
        return fs::metadata(&local)
            .map(|meta| meta.len() > 0)
            .unwrap_or(false);
    }
    local.is_dir() && dir_has_file(&local)
}

/// Outer DB paths for stale duplicates created by the bad path build.
///
/// A candidate is a duplicate-shaped directory with no remote identity and no
/// file entries in its subtree. Its parent is included when it is also a
/// remote-less directory whose subtree is directories only — that is the
/// top-level app-library folder the bad crawl created. Entries with a real
/// remote id are never candidates.
fn stale_duplicate_paths(state: &Database) -> Result<Vec<String>> {
    let entries = state.list_entries()?;
    let mut candidates = HashSet::new();
    for entry in &entries {
        if !is_duplicate_shape(&entry.path) || !entry.is_dir() || entry.remote_drivewsid.is_some() {
            continue;
        }
        if state
            .list_subtree(&entry.path)?
            .iter()
            .any(|child| !child.is_dir())
        {
            continue;
        }
        let parent = parent_path(&entry.path);
        let parent_ok = match entries.iter().find(|item| item.path == parent) {
            Some(item) => {
                item.is_dir()
                    && item.remote_drivewsid.is_none()
                    && state
                        .list_subtree(&parent)?
                        .iter()
                        .all(|child| child.is_dir())
            }
            None => true,
        };
        candidates.insert(if parent_ok {
            parent
        } else {
            entry.path.clone()
        });
    }
    // Keep outermost paths so subtrees never overlap.
    let mut sorted: Vec<String> = candidates.into_iter().collect();
    sorted.sort_by_key(|path| path.len());
    let mut outermost = Vec::new();
    for path in sorted {
        if outermost
            .iter()
            .any(|root| path == *root || path.starts_with(&format!("{root}/")))
        {
            continue;
        }
        outermost.push(path);
    }
    Ok(outermost)
}

/// Drop stale duplicate rows (and their pending ops) before they reach the
/// upload loop. Local directories are left alone; a path containing any file
/// is left in place. Returns the number of DB entries removed.
fn drop_stale_duplicates(state: &Database, mirror: &Mirror) -> Result<usize> {
    let mut dropped = 0usize;
    for path in stale_duplicate_paths(state)? {
        if let Ok(local) = mirror.local_path(&path)
            && dir_has_file(&local)
        {
            continue;
        }
        dropped += state.list_subtree(&path)?.len();
        state.remove_subtree(&path)?;
    }
    if dropped > 0 {
        info!("dropped {dropped} stale duplicate entries");
    }
    Ok(dropped)
}

/// Remote identity returned by Apple's `createFolders`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderIdentity {
    drivewsid: String,
    docwsid: Option<String>,
    etag: Option<String>,
    zone: Option<String>,
}

/// Read the new node's identity from a `createFolders` response. Apple returns
/// an `items` array; older builds read the top-level `clientId`, which is our
/// own temporary id and must never be stored as a remote identity.
fn folder_identity_from_response(response: &Value) -> Option<FolderIdentity> {
    let first = |key: &str| {
        response
            .get(key)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
    };
    let candidates = [
        first("items"),
        first("folders"),
        response.get("folder"),
        response.get("result"),
        Some(response),
    ];
    for node in candidates
        .into_iter()
        .flatten()
        .filter(|node| node.is_object())
    {
        let Some(drivewsid) = node
            .get("drivewsid")
            .and_then(Value::as_str)
            .or_else(|| node.get("id").and_then(Value::as_str))
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let text = |key: &str| {
            node.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        return Some(FolderIdentity {
            drivewsid: drivewsid.to_string(),
            docwsid: text("docwsid").or_else(|| docwsid_from_drivewsid(drivewsid)),
            etag: text("etag"),
            zone: text("zone"),
        });
    }
    None
}

/// A CloudDocs drivewsid is `FOLDER::com.apple.CloudDocs::<docwsid>` (or
/// `FILE::…`); the last segment is the docwsid the document service uses.
fn docwsid_from_drivewsid(drivewsid: &str) -> Option<String> {
    let id = drivewsid
        .strip_prefix("FOLDER::com.apple.CloudDocs::")
        .or_else(|| drivewsid.strip_prefix("FILE::com.apple.CloudDocs::"))?;
    (!id.is_empty()).then(|| id.to_string())
}

/// Drop DB rows for local-only ghost files that cannot be uploaded: dirty
/// file rows with no remote id whose local file no longer exists. Empty files
/// are legitimate (Apple accepts zero-byte uploads), so they stay. No local
/// file is ever deleted here. This stops endless "remote parent … is not
/// uploaded yet" warnings from rows that no longer have content at all.
fn drop_orphan_ghost_files(state: &Database, mirror: &Mirror) -> Result<usize> {
    let mut dropped = 0usize;
    for entry in state.list_entries()? {
        if entry.path == "/" || entry.is_dir() || entry.tombstone {
            continue;
        }
        if entry.remote_drivewsid.is_some() || entry.remote_docwsid.is_some() {
            continue;
        }
        let Ok(local) = mirror.local_path(&entry.path) else {
            continue;
        };
        if local.exists() {
            continue;
        }
        dropped += state.list_subtree(&entry.path)?.len();
        state.remove_subtree(&entry.path)?;
    }
    if dropped > 0 {
        info!("dropped {dropped} local-only ghost file entries");
    }
    Ok(dropped)
}

/// Drop DB rows (and pending ops) absent from the authoritative remote
/// view. Only clean paths with no real file content are removed; dirty
/// entries, conflict copies and files stay. Empty local directories for
/// those paths are removed with `remove_dir` (never recursively).
fn purge_stale_entries(
    state: &Database,
    mirror: &Mirror,
    view: &RemoteView,
    local_changes: &LocalChangeTracker,
    grace: Duration,
) -> Result<usize> {
    let mut stale = Vec::new();
    for entry in state.list_entries()? {
        if entry.path == "/" || view.paths.contains(&entry.path) {
            continue;
        }
        // A local change may have been uploaded moments ago but Apple's next
        // snapshot can still omit it. Never purge during the grace window,
        // while an operation is queued, or while real local content exists.
        if local_changes.is_protected(&entry.path, grace)
            || state.has_pending_op(&entry.path)?
            || local_path_has_content(mirror, &entry.path)
        {
            continue;
        }
        // Legacy watcher rows without a leading slash were created by the
        // path-normalization bug. They are never real remote nodes; drop them
        // only when they contain no real file content.
        if !entry.path.starts_with('/') {
            if entry.remote_drivewsid.is_none() {
                stale.push(entry.path);
            }
            continue;
        }
        // Conflict copies are local-only. Drop DB rows for conflicts whose
        // local copy no longer exists; keep any conflict that still has data.
        if entry.path.contains(".local-conflict-") {
            if let Ok(local) = mirror.local_path(&entry.path)
                && (local.exists() || dir_has_file(&local))
            {
                continue;
            }
            stale.push(entry.path);
            continue;
        }
        if entry.dirty || entry.tombstone {
            continue;
        }
        // A clean entry whose id is still remote was moved; let the normal
        // rename logic reconcile it instead of dropping the row.
        if entry
            .remote_drivewsid
            .as_deref()
            .is_some_and(|id| view.ids.contains(id))
        {
            continue;
        }
        // Never drop an ancestor of a mirrored path.
        if view
            .paths
            .iter()
            .any(|path| path.starts_with(&format!("{}/", entry.path)))
        {
            continue;
        }
        stale.push(entry.path);
    }
    let mut removed = 0usize;
    for path in stale {
        removed += state.list_subtree(&path)?.len();
        state.remove_subtree(&path)?;
        if let Ok(local) = mirror.local_path(&path)
            && local.is_dir()
        {
            let _ = fs::remove_dir(&local);
        }
    }
    remove_empty_ghost_dirs(state, mirror, view, local_changes, grace)?;
    if removed > 0 {
        info!("purged {removed} stale entries absent from iCloud");
    }
    Ok(removed)
}

/// Remove empty local directories that no remote node accounts for.
/// Processed deepest-first so a nested ghost does not shield its parent.
fn remove_empty_ghost_dirs(
    state: &Database,
    mirror: &Mirror,
    view: &RemoteView,
    local_changes: &LocalChangeTracker,
    grace: Duration,
) -> Result<()> {
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, out);
                    out.push(path);
                }
            }
        }
    }
    let root = mirror.root();
    let mut dirs = Vec::new();
    collect(&root, &mut dirs);
    dirs.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for dir in dirs {
        let Ok(relative) = dir.strip_prefix(&root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.is_empty() {
            continue;
        }
        let path = format!("/{relative}");
        if view.paths.contains(&path) || path.contains(".local-conflict-") {
            continue;
        }
        if local_changes.is_protected(&path, grace) || state.has_pending_op(&path)? {
            continue;
        }
        if matches!(state.get_entry(&path), Ok(Some(entry)) if entry.dirty || entry.tombstone) {
            continue;
        }
        // A directory the user just created (mtime inside the grace window)
        // is not proven stale yet: the watcher/upload pipeline still owes it a
        // row, and deleting it immediately breaks brand-new folders.
        let dir_mtime_secs = dir
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|age| age.as_secs() as i64);
        let age = dir_mtime_secs.map(|mtime| chrono::Utc::now().timestamp() - mtime);
        if age.is_some_and(|age| age < grace.as_secs() as i64) {
            continue;
        }
        let Ok(mut children) = fs::read_dir(&dir) else {
            continue;
        };
        if children.next().is_none() {
            let _ = fs::remove_dir(&dir);
        }
    }
    Ok(())
}

/// Remove only duplicate directories that the DB and filesystem both prove
/// were created by the bad path: clean, empty, no recorded children and no
/// current remote entry at that path. Files and non-empty directories are
/// always left alone.
fn reconcile_bad_paths(
    state: &Database,
    mirror: &Mirror,
    id_paths: &HashMap<String, String>,
    snapshot: &HashMap<String, RemoteNode>,
) -> Result<()> {
    for entry in state.list_entries()? {
        if snapshot.contains_key(&entry.path) || !entry.is_dir() || entry.dirty || entry.tombstone {
            continue;
        }
        let mapped = entry
            .remote_drivewsid
            .as_deref()
            .and_then(|id| id_paths.get(id).map(String::as_str));
        // The current crawl still maps this id to exactly this path.
        if mapped == Some(entry.path.as_str()) {
            continue;
        }
        let duplicate = mapped.is_some_and(|canonical| is_duplicate_path(&entry.path, canonical))
            || is_duplicate_shape(&entry.path);
        if !duplicate {
            continue;
        }
        // DB proof: nothing is recorded below the duplicate and it is clean.
        if state.list_subtree(&entry.path)?.len() != 1 {
            continue;
        }
        // Filesystem proof: either an empty directory or no directory at all
        // (the user may already have deleted it locally). A plain `remove_dir`
        // can never delete a file, and a path holding a file is left alone.
        let local = match mirror.local_path(&entry.path) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if local.is_dir() {
            let mut children = match fs::read_dir(&local) {
                Ok(children) => children,
                Err(_) => continue,
            };
            if children.next().is_some() || fs::remove_dir(&local).is_err() {
                continue;
            }
        } else if local.exists() {
            continue;
        }
        state.remove_subtree(&entry.path)?;
    }
    Ok(())
}

fn owner_from_shareid(share_id: &str) -> Option<String> {
    serde_json::from_str::<Value>(share_id)
        .ok()
        .and_then(|value| {
            value
                .get("ownerRecordName")
                .or_else(|| value.get("owner_record_name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::normalize_icloud_path;
    use crate::testutil::TempDir;

    #[test]
    fn path_helpers() {
        assert_eq!(join_path("/", "Photos"), "/Photos");
        assert_eq!(parent_path("/Photos/one.jpg"), "/Photos");
        assert_eq!(normalize_icloud_path("/a/../b"), "/b");
    }

    #[test]
    fn docwsid_is_last_component_of_a_cloud_docs_drivewsid() {
        assert_eq!(
            docwsid_from_drivewsid(ROOT_DRIVEWSID).as_deref(),
            Some(ROOT_DOCWSID)
        );
        assert_eq!(
            docwsid_from_drivewsid("FOLDER::com.apple.CloudDocs::BAA2B1DA").as_deref(),
            Some("BAA2B1DA")
        );
        assert_eq!(
            docwsid_from_drivewsid("FILE::com.apple.CloudDocs::9EDA025E").as_deref(),
            Some("9EDA025E")
        );
        // Non-CloudDocs ids must not be guessed: they belong to app libraries.
        assert_eq!(docwsid_from_drivewsid("FOLDER::other::documents"), None);
    }

    #[test]
    fn conflict_name_timestamp_shape() {
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
        let path = conflict_path("/docs/note.txt", &stamp);
        assert_eq!(path, format!("/docs/note.txt.local-conflict-{stamp}"));
        assert_eq!(stamp.len(), 14);
    }

    #[test]
    fn remote_wake_signal_reflects_wake_and_interval_state() {
        let signal = RemoteSyncSignal::new();
        assert_eq!(signal.next(), None);

        let now = chrono::Utc::now().timestamp();
        signal.request();
        let next = signal.next().unwrap();
        assert!(next >= now && next <= now + REMOTE_WAKE_DEBOUNCE.as_secs() as i64);

        signal.scheduled(15);
        let next = signal.next().unwrap();
        assert!(next >= now + 14 && next <= now + 16);
    }

    fn clean_dir(path: &str, id: &str) -> Entry {
        Entry {
            path: path.into(),
            entry_type: "folder".into(),
            parent_path: parent_path(path),
            remote_drivewsid: Some(id.into()),
            remote_docwsid: None,
            remote_etag: None,
            remote_zone: None,
            remote_shareid: None,
            size: 0,
            mtime: 0,
            hydrated: true,
            dirty: false,
            tombstone: false,
            local_sha256: None,
            last_synced_at: Some(1),
            synced_path: Some(path.into()),
        }
    }

    fn dirty_dir(path: &str, id: Option<&str>) -> Entry {
        Entry {
            path: path.into(),
            entry_type: "folder".into(),
            parent_path: parent_path(path),
            remote_drivewsid: id.map(str::to_string),
            remote_docwsid: None,
            remote_etag: None,
            remote_zone: None,
            remote_shareid: None,
            size: 0,
            mtime: 0,
            hydrated: true,
            dirty: true,
            tombstone: false,
            local_sha256: None,
            last_synced_at: None,
            synced_path: None,
        }
    }

    fn dirty_file(path: &str, id: Option<&str>) -> Entry {
        let mut entry = dirty_dir(path, id);
        entry.entry_type = "file".into();
        entry
    }

    #[test]
    fn orphan_ghost_file_rows_are_dropped_without_touching_real_files() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();

        // A vanished local file is a ghost; an empty file is a real upload.
        db.upsert_entry(&dirty_file("/missing.txt", None)).unwrap();
        db.upsert_entry(&dirty_file("/empty.txt", None)).unwrap();
        mirror.write_all("/empty.txt", b"").unwrap();
        db.queue_op("create", "/missing.txt", None).unwrap();
        db.queue_op("create", "/empty.txt", None).unwrap();

        // Real content is never dropped, even when the row is local-only.
        db.upsert_entry(&dirty_file("/test/test.txt", None))
            .unwrap();
        mirror.write_all("/test/test.txt", b"lol\n").unwrap();
        db.queue_op("modify", "/test/test.txt", None).unwrap();

        // A row with a remote id is not a ghost; sync owns its lifecycle.
        db.upsert_entry(&dirty_file("/remote.txt", Some("FILE::id")))
            .unwrap();

        assert_eq!(drop_orphan_ghost_files(&db, &mirror).unwrap(), 1);
        assert!(db.get_entry("/missing.txt").unwrap().is_none());
        assert!(db.get_entry("/empty.txt").unwrap().is_some());
        assert!(db.get_entry("/test/test.txt").unwrap().is_some());
        assert!(db.get_entry("/remote.txt").unwrap().is_some());
        // Pending ops for dropped rows are gone; real ones stay.
        let paths: Vec<String> = db
            .list_pending_ops()
            .unwrap()
            .into_iter()
            .map(|op| op.path)
            .collect();
        assert!(!paths.iter().any(|path| path == "/missing.txt"));
        assert!(paths.iter().any(|path| path == "/empty.txt"));
        assert!(paths.iter().any(|path| path == "/test/test.txt"));
        assert_eq!(
            fs::read(mirror.local_path("/empty.txt").unwrap()).unwrap(),
            b""
        );
        assert_eq!(
            fs::read(mirror.local_path("/test/test.txt").unwrap()).unwrap(),
            b"lol\n"
        );
    }

    #[test]
    fn embedded_path_names_are_reduced_to_one_component() {
        let root = RemoteNode::from_value(&json!({
            "name": "",
            "type": "folder",
            "drivewsid": ROOT_DRIVEWSID,
            "items": [
                {"name":"/Docs/Docs","type":"folder","drivewsid":"FOLDER::nested"},
                {"name":"Full::Path::Name/Full::Path::Name","type":"app_library","drivewsid":"FOLDER::Full::Path::Name"}
            ]
        }));
        let (nodes, _) = walk_remote_nodes(root, |_| true);
        let paths: HashSet<&str> = nodes.iter().map(|(path, _)| path.as_str()).collect();
        assert!(paths.contains("/Docs"));
        assert!(paths.contains("/Full::Path::Name"));
        assert!(!paths.iter().any(|path| path.contains("Docs/Docs")));
        assert!(
            !paths
                .iter()
                .any(|path| path.contains("Full::Path::Name/Full::Path::Name"))
        );
    }
    async fn test_engine(dir: &TempDir) -> SyncEngine {
        let mut config = Config::load_defaults();
        config.credential_mode = crate::config::CredentialMode::Plain;
        config.sync_folder = dir.path.join("sync");
        config.cache_dir = dir.path.join("cache");
        config.cookie_dir = dir.path.join("cookies");
        config.auto_sync = false;
        config.instant_sync = false;
        let api = crate::api::test_api(
            json!({"dsInfo": {}, "hsaTrustedBrowser": true}),
            crate::api::SessionData {
                session_token: Some("test-session".into()),
                ..Default::default()
            },
            false,
        );
        SyncEngine::new_with_status_path(Arc::new(api), config, dir.path.join("status.json"))
            .await
            .unwrap()
    }

    #[test]
    fn watcher_maps_all_notify_event_kinds() {
        use notify::event::EventAttributes;
        let file = PathBuf::from("/sync/Docs/note.txt");
        let event = |kind| Event {
            kind,
            paths: vec![file.clone()],
            attrs: EventAttributes::new(),
        };
        assert_eq!(
            action_from_event(&event(EventKind::Create(notify::event::CreateKind::File))),
            Some(LocalAction::Change(file.clone()))
        );
        assert_eq!(
            action_from_event(&event(EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Content
            )))),
            Some(LocalAction::Change(file.clone()))
        );
        assert_eq!(
            action_from_event(&event(EventKind::Remove(notify::event::RemoveKind::File))),
            Some(LocalAction::Delete(file.clone()))
        );
        assert_eq!(
            action_from_event(&event(EventKind::Modify(ModifyKind::Name(
                RenameMode::From
            )))),
            Some(LocalAction::RenameFrom(file.clone()))
        );
        assert_eq!(
            action_from_event(&event(EventKind::Modify(ModifyKind::Name(RenameMode::To)))),
            Some(LocalAction::RenameTo(file.clone()))
        );
        let both = Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            paths: vec![file.clone(), PathBuf::from("/sync/Docs/new.txt")],
            attrs: EventAttributes::new(),
        };
        assert_eq!(
            action_from_event(&both),
            Some(LocalAction::Rename {
                from: file.clone(),
                to: PathBuf::from("/sync/Docs/new.txt"),
            })
        );
        assert_eq!(
            action_from_event(&event(EventKind::Access(notify::event::AccessKind::Close(
                notify::event::AccessMode::Write
            )))),
            None
        );
    }

    #[test]
    fn settled_events_pair_renames_and_normalize_paths() {
        let old = PathBuf::from("/sync/Docs/note.txt");
        let new = PathBuf::from("/sync/Docs/note2.txt");
        let paired = settle_actions(
            vec![
                LocalAction::RenameFrom(old.clone()),
                LocalAction::RenameTo(new.clone()),
            ],
            |_| true,
        );
        assert_eq!(
            paired,
            vec![LocalAction::Rename {
                from: old.clone(),
                to: new.clone()
            }]
        );

        // A create followed by a remove of the same path resolves by current
        // filesystem state instead of queuing contradictory ops.
        let resolved = settle_actions(
            vec![
                LocalAction::Change(old.clone()),
                LocalAction::Delete(old.clone()),
            ],
            |_| false,
        );
        assert_eq!(resolved, vec![LocalAction::Delete(old.clone())]);

        let actions = settle_actions(
            vec![LocalAction::Change(PathBuf::from("/sync/Docs/new.txt"))],
            |_| true,
        );
        let LocalAction::Change(path) = &actions[0] else {
            panic!("expected a change");
        };
        assert_eq!(
            config::normalize_icloud_path(
                &path
                    .strip_prefix("/sync")
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            ),
            "/Docs/new.txt"
        );
    }

    #[tokio::test]
    async fn watcher_paths_are_mapped_to_canonical_icloud_paths() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        let root = engine.inner.cfg().sync_folder;
        assert_eq!(
            engine
                .inner
                .canonical_watch_path(&root.join("Docs").join("note.txt"))
                .as_deref(),
            Some("/Docs/note.txt")
        );
        assert_eq!(
            engine.inner.canonical_watch_path(&root).as_deref(),
            None,
            "the watch root is not a node"
        );
        assert_eq!(
            engine
                .inner
                .canonical_watch_path(Path::new("/somewhere/else/note.txt"))
                .as_deref(),
            None
        );
        assert!(is_internal_local_path(Path::new(
            "/sync/Docs/.note.txt.8f2c.tmp"
        )));
    }

    #[tokio::test]
    async fn local_add_rename_and_delete_are_recorded_with_canonical_paths() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        engine
            .inner
            .mirror
            .write_all("/Docs/new.txt", b"hello")
            .unwrap();

        engine.inner.mark_local_change("Docs/new.txt").unwrap();
        let added = engine
            .inner
            .state
            .get_entry("/Docs/new.txt")
            .unwrap()
            .unwrap();
        assert!(added.dirty);
        assert!(
            engine
                .inner
                .state
                .has_local_change_op("/Docs/new.txt")
                .unwrap()
        );

        engine
            .inner
            .mark_local_rename("/Docs/new.txt", "/Docs/renamed.txt")
            .unwrap();
        assert!(
            engine
                .inner
                .state
                .get_entry("/Docs/new.txt")
                .unwrap()
                .is_none()
        );
        let renamed = engine
            .inner
            .state
            .get_entry("/Docs/renamed.txt")
            .unwrap()
            .unwrap();
        assert!(renamed.dirty);
        assert!(
            engine
                .inner
                .state
                .has_local_change_op("/Docs/renamed.txt")
                .unwrap()
        );
        assert!(
            engine
                .inner
                .state
                .list_pending_ops()
                .unwrap()
                .iter()
                .any(|op| op.op == "rename"
                    && op.path == "/Docs/renamed.txt"
                    && op.target_path.as_deref() == Some("/Docs/new.txt"))
        );

        engine.inner.mark_local_delete("/Docs/renamed.txt").unwrap();
        assert!(
            engine
                .inner
                .state
                .get_entry("/Docs/renamed.txt")
                .unwrap()
                .is_none()
        );
        // Deleting a local-only row removes its queued ops; pruning catches any
        // leftovers so `pending` always reaches zero.
        engine.inner.state.prune_pending_ops().unwrap();
        assert_eq!(engine.inner.state.count_pending_ops().unwrap(), 0);
    }

    #[tokio::test]
    async fn record_change_is_newest_first_and_capped() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        engine.inner.record_change(ChangeKind::Added, "a");
        engine.inner.record_change(ChangeKind::Removed, "b");
        let status = engine.inner.status();
        assert_eq!(status.recent_changes[0].path, "b");
        assert_eq!(status.recent_changes[1].path, "a");
        for i in 0..22 {
            engine
                .inner
                .record_change(ChangeKind::Modified, format!("f{}", i));
        }
        let status = engine.inner.status();
        assert!(status.recent_changes.len() <= 20);
        assert_eq!(status.recent_changes[0].path, "f21");
    }
    #[tokio::test]
    async fn upload_uses_parent_docwsid_not_drivewsid() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        let mut docs = clean_dir("/Docs", "FOLDER::com.apple.CloudDocs::DOC-ID");
        docs.remote_docwsid = Some("DOC-ID".into());
        docs.remote_zone = Some(CLOUD_DOCS_ZONE.into());
        engine.inner.state.upsert_entry(&docs).unwrap();
        assert_eq!(
            engine.inner.remote_doc_id_for_path("/Docs").unwrap(),
            ("DOC-ID".to_string(), CLOUD_DOCS_ZONE.to_string())
        );
        assert_eq!(
            engine.inner.remote_doc_id_for_path("/").unwrap(),
            (ROOT_DOCWSID.to_string(), CLOUD_DOCS_ZONE.to_string())
        );
        let payload = crate::api::add_file_payload_for_test(
            "DOC-ID",
            "note.txt",
            "DOCUMENT-ID",
            1,
            &json!({"fileChecksum": "c"}),
        );
        assert_eq!(payload["path"]["starting_document_id"], "DOC-ID");
        assert_eq!(payload["path"]["path"], "note.txt");
    }

    #[tokio::test]
    async fn sync_paths_never_leave_status_at_syncing() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        // No drivews URL: the crawl fails with Auth before any remote change.
        assert!(engine.sync_once().await.is_err());
        assert_ne!(engine.status().state, SyncState::Syncing);
        assert_eq!(engine.status().state, SyncState::LoginRequired);

        let dir2 = TempDir::new();
        let unauth = crate::api::test_api(Value::Null, Default::default(), false);
        let mut config = Config::load_defaults();
        config.credential_mode = crate::config::CredentialMode::Plain;
        config.sync_folder = dir2.path.join("sync");
        config.cache_dir = dir2.path.join("cache");
        config.cookie_dir = dir2.path.join("cookies");
        let engine2 = SyncEngine::new_with_status_path(
            Arc::new(unauth),
            config,
            dir2.path.join("status.json"),
        )
        .await
        .unwrap();
        assert!(engine2.sync_dirty().await.is_err());
        assert_eq!(engine2.status().state, SyncState::LoginRequired);

        engine.inner.report_error(&Error::Offline("down".into()));
        assert_eq!(engine.status().state, SyncState::Offline);
        engine.inner.report_error(&Error::other("broken"));
        assert_eq!(engine.status().state, SyncState::Error);

        // Hydration has its own finally-style reset too.
        *engine.inner.status_cache.lock().unwrap() =
            ServiceStatus::new(SyncState::Syncing, "hydrating");
        engine.inner.hydrate("/Docs/no-such-file.txt").await;
        assert_ne!(engine.status().state, SyncState::Syncing);
    }

    #[tokio::test]
    async fn remote_wake_coalesces_bursts_into_one_permit() {
        let signal = RemoteSyncSignal::new();
        for _ in 0..8 {
            signal.request();
        }
        tokio::time::timeout(REMOTE_WAKE_DEBOUNCE, signal.wake.notified())
            .await
            .expect("a wake request must be delivered");

        // The debounce drain consumes the single accumulated permit.
        signal.drain().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(1), signal.wake.notified())
                .await
                .is_err(),
            "bursts must not leave multiple pending crawls"
        );
    }

    #[test]
    fn watcher_batch_is_bounded_by_size_and_age() {
        assert!(!local_batch_overdue(1, Some(Duration::from_millis(10))));
        assert!(local_batch_overdue(
            LOCAL_EVENT_MAX_BATCH,
            Some(Duration::from_millis(10))
        ));
        assert!(local_batch_overdue(1, Some(LOCAL_EVENT_MAX_WAIT)));
        assert!(!local_batch_overdue(1, None));
    }

    #[tokio::test]
    async fn start_installs_loops_without_waiting_for_the_startup_crawl() {
        let dir = TempDir::new();
        let mut config = Config::load_defaults();
        config.credential_mode = crate::config::CredentialMode::Plain;
        config.sync_folder = dir.path.join("sync");
        config.cache_dir = dir.path.join("cache");
        config.cookie_dir = dir.path.join("cookies");
        config.auto_sync = true;
        config.instant_sync = true;
        let api = crate::api::test_api(
            json!({"dsInfo": {}, "hsaTrustedBrowser": true}),
            crate::api::SessionData {
                session_token: Some("test-session".into()),
                ..Default::default()
            },
            false,
        );
        let engine =
            SyncEngine::new_with_status_path(Arc::new(api), config, dir.path.join("status.json"))
                .await
                .unwrap();

        // The startup crawl fails instantly with this API; `start()` must still
        // return and must already have installed the watcher/upload/poll loops.
        tokio::time::timeout(Duration::from_secs(2), engine.start())
            .await
            .expect("start must not block on the crawl")
            .unwrap();
        assert!(engine.inner.watcher.lock().unwrap().is_some());
        assert!(
            engine.inner.tasks.lock().unwrap().len() >= 5,
            "hydration, request, status, remote, upload and watcher tasks expected"
        );
        engine.shutdown();
    }

    #[test]
    fn create_folder_response_yields_real_remote_identity() {
        let response = json!({
            "items": [{
                "drivewsid": "FOLDER::com.apple.CloudDocs::NEW-ID",
                "docwsid": "NEW-ID",
                "etag": "etag-1",
                "zone": "com.apple.CloudDocs",
                "clientId": "FOLDER::UNKNOWN_ZONE::TempId-fake"
            }]
        });
        assert_eq!(
            folder_identity_from_response(&response),
            Some(FolderIdentity {
                drivewsid: "FOLDER::com.apple.CloudDocs::NEW-ID".into(),
                docwsid: Some("NEW-ID".into()),
                etag: Some("etag-1".into()),
                zone: Some(CLOUD_DOCS_ZONE.into()),
            })
        );
        // A bare clientId (our own temporary id) is never a remote identity.
        assert_eq!(
            folder_identity_from_response(&json!({
                "clientId": "FOLDER::UNKNOWN_ZONE::TempId-fake"
            })),
            None
        );
        // A drivewsid alone still yields the docwsid used by child uploads.
        let bare = folder_identity_from_response(&json!({
            "items": [{"drivewsid": "FOLDER::com.apple.CloudDocs::ABC"}]
        }))
        .unwrap();
        assert_eq!(bare.docwsid.as_deref(), Some("ABC"));
    }

    fn clean_file(path: &str, id: &str) -> Entry {
        let mut entry = dirty_file(path, Some(id));
        entry.dirty = false;
        entry.synced_path = Some(path.to_string());
        entry
    }

    fn test_remote_view() -> RemoteView {
        RemoteView {
            paths: HashSet::from(["/".to_string(), "/Docs".to_string()]),
            ids: HashSet::from(["FOLDER::docs".to_string()]),
        }
    }

    #[test]
    fn locally_uploaded_entry_survives_purge_until_remote_sees_it() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        mirror.write_all("/Docs/new.txt", b"").unwrap();
        db.upsert_entry(&clean_file("/Docs/new.txt", "FILE::new"))
            .unwrap();
        let tracker = LocalChangeTracker::default();
        tracker.note_awaiting_visibility("/Docs/new.txt");

        // Apple's snapshot has not caught up with the upload yet.
        assert_eq!(
            purge_stale_entries(
                &db,
                &mirror,
                &test_remote_view(),
                &tracker,
                LOCAL_CHANGE_GRACE
            )
            .unwrap(),
            0
        );
        assert!(db.get_entry("/Docs/new.txt").unwrap().is_some());

        // Once the crawl sees the node, the wait ends; if it later disappears,
        // the (empty, local-only) row is no longer protected.
        tracker.mark_remote_visible("/Docs/new.txt");
        assert_eq!(
            purge_stale_entries(
                &db,
                &mirror,
                &test_remote_view(),
                &tracker,
                LOCAL_CHANGE_GRACE
            )
            .unwrap(),
            1
        );
        assert!(db.get_entry("/Docs/new.txt").unwrap().is_none());
    }
    #[test]
    fn remove_empty_ghost_dirs_spares_freshly_created_dirs() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        let view = test_remote_view();

        // The user just created this folder; it is not in the remote view,
        // has no DB row yet, but is protected by the grace window.
        mirror.ensure_dir("/Docs/Fresh").unwrap();

        remove_empty_ghost_dirs(
            &db,
            &mirror,
            &view,
            &LocalChangeTracker::default(),
            LOCAL_CHANGE_GRACE,
        )
        .unwrap();
        assert!(
            mirror.local_path("/Docs/Fresh").unwrap().exists(),
            "a recently created folder must not be deleted immediately"
        );
    }

    #[tokio::test]
    async fn mark_folder_dirty_for_upload_creates_dirty_row() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        engine.inner.mark_folder_dirty_for_upload("/new-folder");
        let entry = engine
            .inner
            .state
            .get_entry("/new-folder")
            .unwrap()
            .unwrap();
        assert!(entry.dirty);
        assert!(entry.remote_drivewsid.is_none());
        assert!(engine.inner.state.has_pending_op("/new-folder").unwrap());
        // Idempotent: a second call must not error.
        engine.inner.mark_folder_dirty_for_upload("/new-folder");
        engine.shutdown();
    }

    #[tokio::test]
    async fn remote_parent_missing_marks_folder_for_upload() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        assert!(
            engine
                .inner
                .state
                .get_entry("/Docs/payslips/2026")
                .unwrap()
                .is_none()
        );
        let error = engine
            .inner
            .remote_id_for_path("/Docs/payslips/2026")
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Remote parent for /Docs/payslips/2026")
        );
        // The folder is queued and dirty so the upload loop creates it on its
        // next pass instead of retrying the file forever.
        let entry = engine
            .inner
            .state
            .get_entry("/Docs/payslips/2026")
            .unwrap()
            .unwrap();
        assert!(entry.dirty);
        assert!(entry.remote_drivewsid.is_none());
        assert!(
            engine
                .inner
                .state
                .has_pending_op("/Docs/payslips/2026")
                .unwrap()
        );
        assert!(
            engine
                .inner
                .state
                .list_dirty()
                .unwrap()
                .iter()
                .any(|entry| entry.path == "/Docs/payslips/2026")
        );
        engine.shutdown();
    }

    #[tokio::test]
    async fn folder_without_remote_id_stays_dirty() {
        let dir = TempDir::new();
        let engine = test_engine(&dir).await;
        let mut folder = dirty_dir("/new-folder", None);
        folder.entry_type = "folder".into();
        engine.inner.state.upsert_entry(&folder).unwrap();
        engine
            .inner
            .state
            .queue_op("create", "/new-folder", None)
            .unwrap();

        let now = chrono::Utc::now().timestamp();
        assert!(!engine.inner.finish_upload("/new-folder", now).unwrap());
        let still_dirty = engine
            .inner
            .state
            .get_entry("/new-folder")
            .unwrap()
            .unwrap();
        assert!(still_dirty.dirty);
        assert!(still_dirty.remote_drivewsid.is_none());
        assert_eq!(engine.inner.state.count_pending_ops().unwrap(), 1);

        // Once Apple's id is recorded the same upload completes normally.
        engine
            .inner
            .state
            .update_remote_fields("/new-folder", Some("FOLDER::new"), None, None, None)
            .unwrap();
        assert!(engine.inner.finish_upload("/new-folder", now).unwrap());
        let clean = engine
            .inner
            .state
            .get_entry("/new-folder")
            .unwrap()
            .unwrap();
        assert!(!clean.dirty);
        assert_eq!(clean.remote_drivewsid.as_deref(), Some("FOLDER::new"));
        assert_eq!(engine.inner.state.count_pending_ops().unwrap(), 0);
    }
}
