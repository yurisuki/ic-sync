//! Local mirror + remote sync engine.
//!
//! Keeps the SQLite `entries` contract of the reference implementation,
//! hydrates placeholder files, uploads local changes and reconciles remote
//! moves with conflict copies. All work happens in background tasks; the GUI
//! only calls the small public surface on [`SyncEngine`].

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering};
use std::time::Duration;

use notify::{RecursiveMode, Watcher};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::api::{ICloudApi, ROOT_DRIVEWSID, RemoteNode};
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
    download_rx: Mutex<Option<mpsc::UnboundedReceiver<String>>>,
    scheduled: Arc<std::sync::Mutex<HashSet<String>>>,
    download_slots: Arc<Semaphore>,
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    watcher: std::sync::Mutex<Option<notify::RecommendedWatcher>>,
    status_cache: std::sync::Mutex<ServiceStatus>,
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
            download_rx: Mutex::new(Some(download_rx)),
            scheduled: Arc::new(std::sync::Mutex::new(HashSet::new())),
            download_slots: Arc::new(Semaphore::new(1)),
            tasks: std::sync::Mutex::new(Vec::new()),
            watcher: std::sync::Mutex::new(None),
            status_cache: std::sync::Mutex::new(status),
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
            Error::Auth(_) | Error::TwoFactor(_) => {
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
        if let Some(receiver) = self.download_rx.lock().await.take() {
            self.spawn_hydration_loop(receiver);
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
        if self.state.count_entries()? > 0 && self.mirror.exists("/") {
            info!(
                "using persistent local cache at {}",
                self.mirror.root().display()
            );
            self.reconcile_cache()?;
        } else {
            info!("no persistent cache found; performing first remote crawl");
            self.crawl_and_apply().await?;
        }
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
                let folder = watcher_inner.cfg().sync_folder;
                let relative = path.strip_prefix(&folder).unwrap_or(&path);
                if relative.as_os_str().is_empty() {
                    continue;
                }
                let relative = relative.to_string_lossy().replace('\\', "/");
                if !watcher_inner.path_allowed(&relative) {
                    continue;
                }
                let result = if path.exists() {
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
        let mut snapshot = HashMap::new();
        let mut queue = vec![("/".to_string(), self.api.root().await?)];
        for app in self.api.app_libraries().await.unwrap_or_default() {
            if self.path_allowed(&format!("/{}", app.name)) {
                queue.push((format!("/{}", app.name), app));
            }
        }
        let mut visited = HashSet::new();
        while let Some((parent, node)) = queue.pop() {
            if !visited.insert(node.drivewsid.clone()) {
                continue;
            }
            let path = if parent == "/" && node.drivewsid == ROOT_DRIVEWSID {
                "/".to_string()
            } else {
                join_path(&parent, &node.name)
            };
            if path == "/TRASH_ROOT" || path.starts_with("/TRASH_ROOT/") {
                continue;
            }
            if !self.path_allowed(&path) {
                continue;
            }
            let children = node.items.clone().unwrap_or_default();
            snapshot.insert(path.clone(), node);
            for child in children {
                queue.push((path.clone(), child));
            }
        }

        let remote_ids: HashSet<String> = snapshot
            .values()
            .map(|node| node.drivewsid.clone())
            .collect();
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

    fn spawn_hydration_loop(&self, mut receiver: mpsc::UnboundedReceiver<String>) {
        let hydrator = self.self_arc();
        let task = tokio::spawn(async move {
            while let Some(path) = receiver.recv().await {
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
        let meta = self.mirror.metadata(path)?;
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
        let mut dirty = self.state.list_dirty()?;
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
        self.state.update_remote_fields(
            &entry.path,
            id.as_deref(),
            None,
            None,
            Some("com.apple.CloudDocs"),
        )?;
        Ok(())
    }

    async fn sync_file(&self, entry: &Entry) -> Result<()> {
        if !self.mirror.exists(&entry.path) {
            self.state.mark_tombstone(&entry.path)?;
            return Ok(());
        }
        let parent_id = self.remote_id_for_path(&parent_path(&entry.path)).await?;
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
            .upload(&parent_id, &name, content, entry.mtime)
            .await?;
        if let Some(id) = response.get("drivewsid").and_then(Value::as_str) {
            self.state
                .update_remote_fields(&entry.path, Some(id), None, None, None)?;
        }
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

    #[test]
    fn path_helpers() {
        assert_eq!(join_path("/", "Photos"), "/Photos");
        assert_eq!(parent_path("/Photos/one.jpg"), "/Photos");
        assert_eq!(normalize_icloud_path("/a/../b"), "/b");
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
