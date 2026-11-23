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
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering};
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
use crate::status::{ServiceStatus, SyncState, write_status_to};

/// Delay used to coalesce bursts of local file events into one remote crawl.
const REMOTE_WAKE_DEBOUNCE: Duration = Duration::from_secs(1);
/// Let a burst of Create/Modify/Rename events settle before deciding what a
/// local file operation actually was (editors emit several events per save).
const LOCAL_EVENT_SETTLE: Duration = Duration::from_millis(300);

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
        self.inner.wake.notify_waiters();
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

    /// Non-blocking wake for an event-driven remote crawl.
    fn request_remote_sync(&self) {
        if !self.is_shutdown() {
            self.remote_wake.request();
        }
    }

    /// Keep the existing upload wake and additionally ask for a fresh remote
    /// check when instant sync is enabled.
    fn notify_local_change(&self) {
        self.wake.notify_waiters();
        if self.cfg().instant_sync {
            self.request_remote_sync();
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
        let status = ServiceStatus::new(state, message)
            .with_pending(self.pending_count())
            .with_files(
                self.state.count_synced().unwrap_or(0).max(0) as u64,
                self.entry_count(),
            )
            .with_times(self.last_sync(), self.next_sync())
            .with_folder(cfg.sync_folder.to_string_lossy().into_owned())
            .with_secure_storage(config::credential_storage_ready(cfg.credential_mode));
        *self.status_cache.lock().unwrap() = status.clone();
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
        // The remote snapshot is authoritative. Rebuilding from the cached DB
        // here is what resurrects folders that were deleted locally/remotely.
        info!("rebuilding local mirror from current iCloud metadata");
        let mut startup_error: Option<Error> = None;
        if let Err(error) = self.crawl_and_apply().await {
            startup_error = Some(error);
        } else if let Err(error) = self.schedule_all_unhydrated() {
            startup_error = Some(error);
        }

        // Always start the background loops, even when the first crawl failed:
        // a transient Apple error must not disable local watching/uploads (that
        // left the app showing "Syncing" while nothing was ever synced).
        let mut watcher_error = None;
        if self.cfg().auto_sync {
            self.spawn_remote_loop();
            self.spawn_upload_loop();
            watcher_error = self.spawn_local_watcher().err();
        }
        self.set_next_sync();
        match startup_error.or(watcher_error) {
            Some(error) => self.report_error(&error),
            None => self.publish(SyncState::Synced, "iCloud up to date"),
        }
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
            let mut interval = tokio::time::interval(Duration::from_secs(3));
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
                if woken {
                    // Bursts of file events collapse into a single crawl.
                    sleep(REMOTE_WAKE_DEBOUNCE).await;
                    if refresher.is_shutdown() {
                        break;
                    }
                    refresher.remote_wake.drain().await;
                }
                refresher.set_next_sync();
                if let Err(error) = refresher.sync_once().await {
                    refresher.report_error(&error);
                }
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
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = uploader.wake.notified() => {}
                }
                if uploader.is_shutdown() {
                    break;
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
            let settle = tokio::time::sleep(LOCAL_EVENT_SETTLE);
            tokio::pin!(settle);
            loop {
                tokio::select! {
                    incoming = rx.recv() => {
                        let Some(action) = incoming else {
                            watcher_inner.apply_local_actions(std::mem::take(&mut batch));
                            break;
                        };
                        if watcher_inner.is_shutdown() {
                            break;
                        }
                        batch.push(action);
                        settle.as_mut().reset(tokio::time::Instant::now() + LOCAL_EVENT_SETTLE);
                    }
                    _ = &mut settle => {
                        if !batch.is_empty() {
                            watcher_inner.apply_local_actions(std::mem::take(&mut batch));
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

    fn apply_local_actions(&self, actions: Vec<LocalAction>) {
        let actions = settle_actions(actions, |path| path.exists());
        for action in actions {
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
                    if let Err(error) = self.mark_local_change(&relative) {
                        debug!("ignoring local change for {relative}: {error}");
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
        if self.api.is_offline() {
            return Err(Error::Offline("cached files are read-only".into()));
        }
        if self.read_only() {
            return Err(Error::Auth("sign in before syncing".into()));
        }
        self.publish(SyncState::Syncing, "refreshing remote metadata");
        self.crawl_and_apply().await?;
        let now = chrono::Utc::now().timestamp();
        self.last_sync_at.store(now, AtomicOrdering::Relaxed);
        self.set_next_sync();
        self.state
            .sync_state_set("last_sync_at", &now.to_string())?;
        Ok(())
    }

    async fn crawl_and_apply(&self) -> Result<()> {
        let crawl_started_at = chrono::Utc::now().timestamp();
        // The Python reference crawls only `root.get_children()`. Apple already
        // lists the user's app libraries there (e.g. Pages); `app_libraries()`
        // is a catalogue of *all* app containers and must not be mirrored as
        // top-level folders. The old code did exactly that and doubled names.
        let root = self.api.root().await?;
        let (nodes, id_paths) =
            collect_remote_nodes(&self.api, root, |path| self.path_allowed(path)).await?;
        let snapshot: HashMap<String, RemoteNode> = nodes.into_iter().collect();
        let view = RemoteView {
            paths: snapshot.keys().cloned().collect(),
            ids: snapshot
                .values()
                .map(|node| node.drivewsid.clone())
                .collect(),
        };
        *self.remote_view.lock().unwrap() = Some(view.clone());
        // Older builds dropped Apple's separate `extension` field, leaving
        // rows/files named `bumpers` instead of `bumpers.pdf`. Repair them
        // from remote metadata *before* purging, so local content is moved to
        // the canonical path instead of being orphaned or duplicated.
        repair_extensionless_paths(&self.state, &self.mirror, &snapshot)?;
        // Reconcile against the authoritative view before the watcher/upload
        // loops can see (and recreate) stale local or DB state.
        purge_stale_entries(&self.state, &self.mirror, &view)?;
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
                        warn!(
                            "keeping duplicate directory {}; canonical path {path} is occupied",
                            entry.path
                        );
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
        self.notify_local_change();
        Ok(())
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
            self.notify_local_change();
        }
        Ok(())
    }

    fn mark_local_rename(&self, from: &str, to: &str) -> Result<()> {
        let from = config::normalize_icloud_path(from);
        let to = config::normalize_icloud_path(to);
        if self.state.get_entry(&from)?.is_some() {
            self.state.rename_tree(&from, &to, false)?;
            self.state.queue_op("rename", &to, Some(&from))?;
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
                    warn!("could not rename {}: {error}", entry.path);
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
        self.publish(SyncState::Syncing, "uploading local changes");
        for entry in dirty {
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
                    if let Some(fresh) = self.state.get_entry(&entry.path)?
                        && !fresh.tombstone
                    {
                        self.state
                            .mark_clean(&entry.path, now, fresh.local_sha256.as_deref())?;
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
                    warn!("could not sync {}: {error}", entry.path);
                    if let Ok(ops) = self.state.list_pending_ops() {
                        for op in ops.iter().filter(|op| op.path == entry.path) {
                            let _ = self.state.bump_op_retry(op.id, &error.to_string());
                        }
                    }
                }
            }
        }
        self.set_next_sync();
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
            return Ok(());
        };
        let etag = entry.remote_etag.as_deref().unwrap_or_default();
        self.api.delete_node(id, etag).await?;
        self.state.remove_subtree(&entry.path)?;
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
        let id = response
            .get("drivewsid")
            .or_else(|| response.get("clientId"))
            .and_then(Value::as_str)
            .map(str::to_string);
        // `createFolders` returns only a drivewsid. The Python reference
        // refreshes the child meta right after mkdir because an upload into
        // the new folder must chain to its docwsid, not its drivewsid.
        let mut doc_id = response
            .get("docwsid")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut zone = response
            .get("zone")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(id) = id.as_deref()
            && doc_id.is_none()
        {
            match self.api.retrieve_node(id, None).await {
                Ok(node) => {
                    doc_id = node.docwsid.clone();
                    if zone.is_none() {
                        zone = node.zone.clone();
                    }
                }
                Err(error) => warn!("could not refresh new folder {}: {error}", entry.path),
            }
        }
        self.state.update_remote_fields(
            &entry.path,
            id.as_deref(),
            doc_id.as_deref(),
            None,
            Some(zone.as_deref().unwrap_or(CLOUD_DOCS_ZONE)),
        )?;
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
                    warn!("could not remove stale remote file {}: {error}", entry.path);
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
            Err(error) => warn!("could not refresh uploaded file {}: {error}", entry.path),
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
        Err(Error::other(format!(
            "remote parent for {path} is not uploaded yet"
        )))
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
            return Err(Error::other(format!(
                "remote parent for {path} is not uploaded yet"
            )));
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
/// `extension` field (e.g. `/Docs/bumpers` for remote `bumpers.pdf`).
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
/// `/Instagram/Instagram` or `/FOLDER::X/FOLDER::X`.
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
fn purge_stale_entries(state: &Database, mirror: &Mirror, view: &RemoteView) -> Result<usize> {
    let mut stale = Vec::new();
    for entry in state.list_entries()? {
        if entry.path == "/" || view.paths.contains(&entry.path) {
            continue;
        }
        // Legacy watcher rows without a leading slash were created by the
        // path-normalization bug. They are never real remote nodes; drop them
        // only when they contain no real file content.
        if !entry.path.starts_with('/') {
            if entry.remote_drivewsid.is_none() {
                if let Ok(local) = mirror.local_path(&entry.path)
                    && dir_has_file(&local)
                {
                    continue;
                }
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
        if let Ok(local) = mirror.local_path(&entry.path)
            && dir_has_file(&local)
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
    remove_empty_ghost_dirs(state, mirror, view)?;
    if removed > 0 {
        info!("purged {removed} stale entries absent from iCloud");
    }
    Ok(removed)
}

/// Remove empty local directories that no remote node accounts for.
/// Processed deepest-first so a nested ghost does not shield its parent.
fn remove_empty_ghost_dirs(state: &Database, mirror: &Mirror, view: &RemoteView) -> Result<()> {
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
        if matches!(state.get_entry(&path), Ok(Some(entry)) if entry.dirty || entry.tombstone) {
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

    fn dir_entry(path: &str, id: Option<&str>, dirty: bool) -> Entry {
        let mut entry = dirty_dir(path, id);
        entry.dirty = dirty;
        entry.synced_path = (!dirty).then(|| path.to_string());
        entry
    }

    #[test]
    fn allowlist_snapshot_purges_ghosts_and_keeps_real_roots() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();

        let mut config = Config::load_defaults();
        config.sync_paths = vec!["/Docs".into(), "/Downloads".into()];
        let root = RemoteNode::from_value(&json!({
            "name": "",
            "type": "folder",
            "drivewsid": ROOT_DRIVEWSID,
            "items": [
                {"name":"Docs","type":"folder","drivewsid":"FOLDER::docs"},
                {"name":"Downloads","type":"folder","drivewsid":"FOLDER::downloads"},
                {"name":"Dropbox","type":"folder","drivewsid":"FOLDER::dropbox"},
                {"name":"Pages","type":"app_library","drivewsid":"FOLDER::com.apple.Pages::documents"},
                {"name":"Alibaba","type":"folder","drivewsid":"FOLDER::alibaba"},
                {"name":"FOLDER::com","type":"folder","drivewsid":"FOLDER::com"}
            ]
        }));
        let (nodes, _) = walk_remote_nodes(root, |path| config.path_allowed(path));
        let snapshot: HashMap<String, RemoteNode> = nodes.into_iter().collect();
        let view = RemoteView {
            paths: snapshot.keys().cloned().collect(),
            ids: snapshot
                .values()
                .map(|node| node.drivewsid.clone())
                .collect(),
        };
        let mut paths: Vec<&str> = view.paths.iter().map(String::as_str).collect();
        paths.sort();
        assert_eq!(paths, vec!["/", "/Docs", "/Downloads"]);

        // Stale DB rows/local folders outside the allowlist.
        for path in [
            "/Docs",
            "/Downloads",
            "/Dropbox",
            "/Pages",
            "/Alibaba",
            "/FOLDER::com",
            "/Instagram",
            "/Instagram/Instagram",
            "/Work Chat",
            "/Docs.local-conflict-20261123000000",
        ] {
            let id = match path {
                "/Docs" => Some("FOLDER::docs"),
                "/Downloads" => Some("FOLDER::downloads"),
                _ => None,
            };
            db.upsert_entry(&dir_entry(path, id, false)).unwrap();
            mirror.ensure_dir(path).unwrap();
        }
        // A directory with real content and a conflict copy must survive.
        mirror
            .write_all("/Work Chat/keep.txt", b"precious")
            .unwrap();
        // A purely local empty ghost with no DB row at all.
        mirror.ensure_dir("/Ghost").unwrap();

        let removed = purge_stale_entries(&db, &mirror, &view).unwrap();
        assert!(removed > 0);

        assert!(db.get_entry("/Docs").unwrap().is_some());
        assert!(db.get_entry("/Downloads").unwrap().is_some());
        assert!(mirror.exists("/Docs"));
        assert!(mirror.exists("/Downloads"));
        for path in [
            "/Dropbox",
            "/Pages",
            "/Alibaba",
            "/FOLDER::com",
            "/Instagram",
            "/Instagram/Instagram",
            "/Ghost",
        ] {
            assert!(db.get_entry(path).unwrap().is_none(), "DB row for {path}");
            assert!(!mirror.exists(path), "local folder {path} survived");
        }
        assert!(db.get_entry("/Work Chat").unwrap().is_some());
        assert_eq!(
            fs::read(mirror.local_path("/Work Chat/keep.txt").unwrap()).unwrap(),
            b"precious"
        );
        assert!(
            db.get_entry("/Docs.local-conflict-20261123000000")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn stale_duplicate_rows_are_dropped_before_upload() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();

        // Exactly the shape left by the bad crawl: the bogus top-level app
        // library folder and its doubled child, both dirty with no remote id.
        db.upsert_entry(&dirty_dir("/Instagram", None)).unwrap();
        db.upsert_entry(&dirty_dir("/Instagram/Instagram", None))
            .unwrap();
        db.queue_op("create", "/Instagram", None).unwrap();
        db.queue_op("create", "/Instagram/Instagram", None).unwrap();
        db.upsert_entry(&clean_dir("/Docs", "FOLDER::docs"))
            .unwrap();

        // The user already removed the local directories; DB rows are stale.
        let dropped = drop_stale_duplicates(&db, &mirror).unwrap();
        assert_eq!(dropped, 2);
        assert!(db.get_entry("/Instagram").unwrap().is_none());
        assert!(db.get_entry("/Instagram/Instagram").unwrap().is_none());
        assert!(db.list_pending_ops().unwrap().is_empty());
        assert!(db.list_dirty().unwrap().is_empty());
        assert!(db.get_entry("/Docs").unwrap().is_some());
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
    fn duplicate_with_real_remote_id_is_kept() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        db.upsert_entry(&dirty_dir("/Instagram", Some("FOLDER::parent")))
            .unwrap();
        db.upsert_entry(&dirty_dir("/Instagram/Instagram", Some("FOLDER::real")))
            .unwrap();
        assert_eq!(drop_stale_duplicates(&db, &mirror).unwrap(), 0);
        assert!(db.get_entry("/Instagram").unwrap().is_some());
        assert!(db.get_entry("/Instagram/Instagram").unwrap().is_some());
    }

    #[test]
    fn duplicate_with_local_file_is_kept() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        db.upsert_entry(&dirty_dir("/Instagram", None)).unwrap();
        db.upsert_entry(&dirty_dir("/Instagram/Instagram", None))
            .unwrap();
        mirror.ensure_dir("/Instagram/Instagram").unwrap();
        mirror
            .write_all("/Instagram/Instagram/keep.txt", b"precious")
            .unwrap();
        assert_eq!(drop_stale_duplicates(&db, &mirror).unwrap(), 0);
        assert!(db.get_entry("/Instagram/Instagram").unwrap().is_some());
        assert_eq!(
            fs::read(mirror.local_path("/Instagram/Instagram/keep.txt").unwrap()).unwrap(),
            b"precious"
        );
    }

    #[test]
    fn reconciliation_drops_duplicate_row_without_local_directory() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        db.upsert_entry(&clean_dir("/Instagram/Instagram", "FOLDER::old"))
            .unwrap();
        let mut id_paths = HashMap::new();
        id_paths.insert("FOLDER::old".to_string(), "/Instagram".to_string());
        let snapshot = HashMap::new();
        reconcile_bad_paths(&db, &mirror, &id_paths, &snapshot).unwrap();
        assert!(db.get_entry("/Instagram/Instagram").unwrap().is_none());
    }

    #[test]
    fn crawl_only_mirrors_true_root_items_with_canonical_paths() {
        // Shape observed live: root children include regular folders and app
        // libraries, and some app-library `name` values are raw drivewsids.
        let root = RemoteNode::from_value(&json!({
            "name": "",
            "type": "folder",
            "drivewsid": ROOT_DRIVEWSID,
            "items": [
                {"name":"Docs","type":"folder","drivewsid":"FOLDER::docs"},
                {"name":"Downloads","type":"folder","drivewsid":"FOLDER::downloads"},
                {"name":"Dropbox","type":"folder","drivewsid":"FOLDER::dropbox"},
                {"name":"Pages","type":"app_library","drivewsid":"FOLDER::com.apple.Pages::documents"},
                {"name":"FOLDER::com.apple.TextInput::documents","type":"app_library","drivewsid":"FOLDER::com.apple.TextInput::documents"}
            ]
        }));
        let (nodes, id_paths) = walk_remote_nodes(root, |_| true);
        let paths: HashSet<&str> = nodes.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(paths.len(), 6);
        for expected in [
            "/",
            "/Docs",
            "/Downloads",
            "/Dropbox",
            "/Pages",
            "/FOLDER::com.apple.TextInput::documents",
        ] {
            assert!(
                paths.contains(expected),
                "missing canonical path {expected}"
            );
        }
        assert_eq!(
            id_paths
                .get("FOLDER::com.apple.Pages::documents")
                .map(String::as_str),
            Some("/Pages")
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

    #[test]
    fn duplicate_path_signatures() {
        assert!(is_duplicate_path("/Instagram/Instagram", "/Instagram"));
        assert!(is_duplicate_path("/FOLDER::X/FOLDER::X", "/FOLDER::X"));
        assert!(is_duplicate_path("/A/A/A", "/A"));
        assert!(!is_duplicate_path("/Instagram/Photos", "/Instagram"));
        assert!(!is_duplicate_path("/Instagram", "/Instagram"));
        assert!(is_duplicate_shape("/Cloud Music/Cloud Music"));
        assert!(!is_duplicate_shape("/Docs/Downloads"));
    }

    #[test]
    fn reconciliation_removes_only_empty_db_proven_duplicates() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        let bad_id = "FOLDER::iCloud.com.burbn.instagram::documents";
        db.upsert_entry(&clean_dir("/Instagram/Instagram", bad_id))
            .unwrap();
        mirror.ensure_dir("/Instagram/Instagram").unwrap();
        // A legitimate `/Docs/Docs` mapped to itself must not be touched.
        db.upsert_entry(&clean_dir("/Docs/Docs", "FOLDER::real-docs-docs"))
            .unwrap();
        mirror.ensure_dir("/Docs/Docs").unwrap();

        let mut id_paths = HashMap::new();
        id_paths.insert(bad_id.to_string(), "/Instagram".to_string());
        id_paths.insert(
            "FOLDER::real-docs-docs".to_string(),
            "/Docs/Docs".to_string(),
        );
        let snapshot = HashMap::new();
        reconcile_bad_paths(&db, &mirror, &id_paths, &snapshot).unwrap();

        assert!(db.get_entry("/Instagram/Instagram").unwrap().is_none());
        assert!(!mirror.exists("/Instagram/Instagram"));
        assert!(db.get_entry("/Docs/Docs").unwrap().is_some());
        assert!(mirror.exists("/Docs/Docs"));
    }

    #[test]
    fn reconciliation_leaves_duplicate_with_content() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        let bad_id = "FOLDER::iCloud.com.sevenam.CloudMusic::documents";
        db.upsert_entry(&clean_dir("/Cloud Music/Cloud Music", bad_id))
            .unwrap();
        mirror.ensure_dir("/Cloud Music/Cloud Music").unwrap();
        mirror
            .write_all("/Cloud Music/Cloud Music/keep.txt", b"precious")
            .unwrap();

        let mut id_paths = HashMap::new();
        id_paths.insert(bad_id.to_string(), "/Cloud Music".to_string());
        let snapshot = HashMap::new();
        reconcile_bad_paths(&db, &mirror, &id_paths, &snapshot).unwrap();

        assert!(db.get_entry("/Cloud Music/Cloud Music").unwrap().is_some());
        assert_eq!(
            fs::read(
                mirror
                    .local_path("/Cloud Music/Cloud Music/keep.txt")
                    .unwrap()
            )
            .unwrap(),
            b"precious"
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

    #[test]
    fn repair_moves_extensionless_file_without_losing_content() {
        let dir = TempDir::new();
        let db = Database::open(&dir.path.join("state.sqlite3")).unwrap();
        let mirror = Mirror::new(dir.path.join("sync"), dir.path.join("tmp")).unwrap();
        mirror.write_all("/Docs/bumpers", b"precious").unwrap();
        let mut old = dir_entry("/Docs/bumpers", Some("FILE::id"), true);
        old.entry_type = "file".into();
        old.synced_path = Some("/Docs/bumpers".into());
        db.upsert_entry(&old).unwrap();
        db.queue_op("modify", "/Docs/bumpers", None).unwrap();
        let snapshot: HashMap<String, RemoteNode> = [(
            "/Docs/bumpers.pdf".to_string(),
            RemoteNode::from_value(&json!({
                "name": "bumpers", "extension": "pdf", "type": "file", "drivewsid": "FILE::id"
            })),
        )]
        .into_iter()
        .collect();

        assert_eq!(
            repair_extensionless_paths(&db, &mirror, &snapshot).unwrap(),
            1
        );
        assert!(db.get_entry("/Docs/bumpers").unwrap().is_none());
        let fixed = db.get_entry("/Docs/bumpers.pdf").unwrap().unwrap();
        assert_eq!(fixed.synced_path.as_deref(), Some("/Docs/bumpers.pdf"));
        assert!(fixed.dirty); // a queued local edit must survive the repair
        assert_eq!(
            fs::read(mirror.local_path("/Docs/bumpers.pdf").unwrap()).unwrap(),
            b"precious"
        );
        assert!(!mirror.exists("/Docs/bumpers"));

        // A second repair is a no-op and never duplicates data.
        assert_eq!(
            repair_extensionless_paths(&db, &mirror, &snapshot).unwrap(),
            0
        );
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
}
