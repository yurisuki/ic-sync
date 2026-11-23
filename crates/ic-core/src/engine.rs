//! Local mirror + remote sync engine.
//!
//! Keeps the SQLite `entries` contract of the reference implementation,
//! hydrates placeholder files, uploads local changes and reconciles remote
//! moves with conflict copies. All work happens in background tasks; the GUI
//! only calls the small public surface on [`SyncEngine`].

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering};
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
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
use crate::mirror::{Mirror, basename, conflict_path, join_path, parent_path};
use crate::relocation::{self, RelocationReport};
use crate::state::{Database, Entry};
use crate::status::{ServiceStatus, SyncState, write_status};

/// Delay used to coalesce bursts of local file events into one remote crawl.
const REMOTE_WAKE_DEBOUNCE: Duration = Duration::from_secs(1);

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
    download_slots: Arc<Semaphore>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    watcher: std::sync::Mutex<Option<notify::RecommendedWatcher>>,
    status_cache: std::sync::Mutex<ServiceStatus>,
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
            download_slots: Arc::new(Semaphore::new(workers)),
            tasks: std::sync::Mutex::new(Vec::new()),
            watcher: std::sync::Mutex::new(None),
            status_cache: std::sync::Mutex::new(status),
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
        if let Err(error) = write_status(&status) {
            warn!("could not write status file: {error}");
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
        self.crawl_and_apply().await?;
        self.schedule_all_unhydrated()?;

        if self.cfg().auto_sync {
            self.spawn_remote_loop();
            self.spawn_upload_loop();
            self.spawn_local_watcher()?;
        }
        self.set_next_sync();
        self.publish(SyncState::Synced, "iCloud up to date");
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
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3));
            loop {
                interval.tick().await;
                if publisher.is_shutdown() {
                    break;
                }
                let status = publisher.status();
                if let Err(error) = write_status(&status) {
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
        let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                for path in event.paths {
                    let _ = tx.send(path);
                }
            }
        })
        .map_err(|e| Error::other(format!("could not start local watcher: {e}")))?;
        let folder = self.cfg().sync_folder;
        watcher
            .watch(&folder, RecursiveMode::Recursive)
            .map_err(|e| Error::other(format!("could not watch {}: {e}", folder.display())))?;
        *self.watcher.lock().unwrap() = Some(watcher);

        let watcher_inner = self.self_arc();
        let task = tokio::spawn(async move {
            while let Some(path) = rx.recv().await {
                if watcher_inner.is_shutdown() {
                    break;
                }
                // Let atomic writes/temp renames settle before inspecting the
                // file; otherwise hydration writes look like user edits.
                sleep(Duration::from_millis(300)).await;
                let folder = watcher_inner.cfg().sync_folder;
                let relative = path.strip_prefix(&folder).unwrap_or(&path);
                if relative.as_os_str().is_empty() {
                    continue;
                }
                // Canonical iCloud paths always start with '/'. Without this,
                // watcher events create DB rows like "Alibaba" instead of
                // "/Alibaba", which are then uploaded as bogus root items.
                let relative =
                    config::normalize_icloud_path(&relative.to_string_lossy().replace('\\', "/"));
                if relative == "/" {
                    continue;
                }
                if !watcher_inner.path_allowed(&relative) {
                    continue;
                }
                let result = if path.exists() {
                    if watcher_inner.is_ignorable_empty_ghost(&relative) {
                        continue;
                    }
                    watcher_inner.mark_local_change(&relative)
                } else {
                    watcher_inner.mark_local_delete(&relative)
                };
                if let Err(error) = result {
                    debug!("ignoring local event for {relative}: {error}");
                }
            }
        });
        self.push_task(task);
        Ok(())
    }

    // -- remote crawl -----------------------------------------------------

    pub async fn sync_once(&self) -> Result<()> {
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
        self.publish(SyncState::Synced, "iCloud up to date");
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
                    warn!("conflict on {}; preserving local copy", entry.path);
                    self.resolve_conflict(&entry.path)?;
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

    /// Preserve a dirty local copy as `<name>.local-conflict-<stamp>` and detach
    /// it from its remote identity so the upload loop recreates it.
    fn resolve_conflict(&self, path: &str) -> Result<()> {
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
        let target = conflict_path(path, &stamp);
        let subtree = self.state.list_subtree(path)?;
        if self.mirror.exists(path) {
            self.mirror.rename(path, &target)?;
        }
        self.state.detach_subtree_as_conflict(path, &target)?;
        for entry in subtree {
            let suffix = if entry.path == path {
                ""
            } else {
                &entry.path[path.len()..]
            };
            let new_path = if suffix.is_empty() {
                target.clone()
            } else {
                format!("{target}{suffix}")
            };
            self.state.queue_op("conflict-copy", &new_path, None)?;
        }
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
        self.state.rename_tree(from, to, false)?;
        self.state.queue_op("rename", to, Some(from))?;
        self.notify_local_change();
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
        let mut dirty = self.state.list_dirty()?;
        // Hydration may leave dirty rows whose content already matches the
        // stored checksum. Re-uploading them is pointless and produced hundreds
        // of queued modify ops, leaving the UI stuck at "syncing".
        let already_clean: Vec<String> = dirty
            .iter()
            .filter(|entry| {
                !entry.tombstone
                    && !entry.is_dir()
                    && entry.remote_drivewsid.is_some()
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
                Err(error) => warn!("could not sync {}: {error}", entry.path),
            }
        }
        self.set_next_sync();
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
        let etag = entry.remote_etag.as_deref().unwrap_or_default();
        if parent_path(synced) != parent_path(&entry.path) {
            let destination = self.remote_id_for_path(&parent_path(&entry.path)).await?;
            self.api.move_node(id, etag, &destination).await?;
        } else {
            self.api
                .rename_node(id, etag, &basename(&entry.path))
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
