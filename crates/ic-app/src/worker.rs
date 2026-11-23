//! Async bridge between Iced and `ic-core`.
//!
//! The GUI thread only ever sends `GuiMessage` values into a bounded Tokio
//! channel and listens for `WorkerEvent` values on a broadcast channel. Every
//! call into `ic-core` happens on the Tokio runtime owned by `main`, so the UI
//! never blocks on network, SQLite or disk I/O.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use iced::futures::Stream;
use iced::futures::sink::SinkExt;
use iced::{Subscription, stream};
use tokio::sync::{broadcast, mpsc};

use ic_core::auth::{self, AuthOptions, AuthStep};
use ic_core::status::{self, ServiceStatus};
use ic_core::{Config, Error as CoreError, ICloudApi, SyncEngine};

/// Severity used by the Activity page and toasts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// The verification method offered in the sign-in UI. The exact core route
/// returned by `authenticate()` is stored in `AuthContext` and replayed on
/// `submit_code`; this enum only represents the user's choice/intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationMethod {
    TrustedDevice,
    Sms,
}

impl VerificationMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::TrustedDevice => "iPhone / trusted device",
            Self::Sms => "SMS to trusted number",
        }
    }
}

/// Commands sent from the GUI to the core worker.
#[derive(Clone, Debug)]
pub enum GuiMessage {
    /// Load config/status from disk and (if a session exists) start the engine.
    Bootstrap,
    SignIn {
        username: String,
        password: String,
        method: VerificationMethod,
        accept_terms: bool,
    },
    SubmitCode {
        code: String,
        accept_terms: bool,
    },
    /// Re-issue the challenge for the selected method (method switches must
    /// re-arm delivery before the new code is valid).
    ResendCode {
        method: VerificationMethod,
    },
    ForceSync,
    RefreshStatus,
    SetAutoSync(bool),
    SetAutostart(bool),
    RefreshAutostart,
    ForgetSession,
    SaveSettings(Box<Config>),
    RelocateFolder {
        new_folder: PathBuf,
        sync_now_first: bool,
    },
    Shutdown,
}

/// Events sent from the core worker back to the GUI.
///
/// Deliberately carries no passwords or tokens.
#[derive(Clone, Debug)]
pub enum WorkerEvent {
    Bootstrapped {
        config: Config,
        status: Option<ServiceStatus>,
        secure_storage: bool,
    },
    Connecting,
    Status(ServiceStatus),
    TwoFactorRequired {
        method: String,
        /// Route selected by core; replayed verbatim on submit.
        route: ic_core::auth::TwoFactorRoute,
        hint: Option<String>,
    },
    SignedIn,
    SyncStarted,
    SyncFinished,
    SettingsSaved(Config),
    /// Current autostart state as reported by the OS.
    AutostartState(bool),
    SessionForgotten,
    Relocated {
        moved: String,
        destination: String,
    },
    RelocationBlocked {
        reason: String,
    },
    /// The OS credential store is missing/unusable; do not prompt again in a loop.
    SecureStorageUnavailable {
        reason: String,
    },
    Activity {
        level: LogLevel,
        message: String,
    },
    Toast {
        level: LogLevel,
        message: String,
    },
    Error {
        context: String,
        message: String,
    },
    Lagged(u64),
}

type EventSender = broadcast::Sender<WorkerEvent>;

static EVENT_BUS: OnceLock<EventSender> = OnceLock::new();
static COMMAND_TX: OnceLock<mpsc::Sender<GuiMessage>> = OnceLock::new();
static COMMAND_RX: OnceLock<std::sync::Mutex<Option<mpsc::Receiver<GuiMessage>>>> = OnceLock::new();

fn event_bus() -> &'static EventSender {
    EVENT_BUS.get_or_init(|| broadcast::channel(256).0)
}

/// Creates the command channel synchronously, before the GUI boots.
///
/// The receiver is handed to the dedicated worker thread by
/// [`run_on_current_thread`].
pub fn start_channel() -> mpsc::Sender<GuiMessage> {
    let (commands, receiver) = mpsc::channel(64);
    let _ = COMMAND_TX.set(commands.clone());
    let _ = COMMAND_RX.set(std::sync::Mutex::new(Some(receiver)));
    commands
}

/// Drives all `ic-core` calls on a current-thread Tokio runtime.
///
/// Some `ic-core` authentication futures hold a `ThreadRng` across `.await`
/// and are therefore not `Send`; they must be created and polled on this
/// thread, never moved across threads or run on the Iced UI thread.
pub fn run_on_current_thread() {
    let receiver = COMMAND_RX
        .get()
        .expect("start_channel must be called first")
        .lock()
        .expect("command receiver mutex poisoned")
        .take()
        .expect("worker thread started twice");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    runtime.block_on(run(receiver, event_bus().clone()));
}

/// Clone of the command sender for use from Iced's boot/update functions.
pub fn commands() -> mpsc::Sender<GuiMessage> {
    COMMAND_TX
        .get()
        .expect("worker must be started before the GUI boots")
        .clone()
}

/// Fire-and-forget send used by GUI event handlers.
pub fn send(message: GuiMessage) {
    let _ = commands().try_send(message);
}

/// Iced subscription that forwards worker events to the UI.
pub fn subscription() -> Subscription<WorkerEvent> {
    Subscription::run(event_stream)
}

fn event_stream() -> impl Stream<Item = WorkerEvent> {
    stream::channel(64, async |mut output| {
        let mut receiver = event_bus().subscribe();
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if output.send(event).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    let _ = output.send(WorkerEvent::Lagged(skipped)).await;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// State for the in-flight 2FA challenge. The route comes from core and must
/// be replayed exactly when the code is submitted.
#[derive(Default)]
struct AuthContext {
    selected: Option<VerificationMethod>,
    route: Option<ic_core::auth::TwoFactorRoute>,
}

struct Worker {
    commands: mpsc::Receiver<GuiMessage>,
    events: EventSender,
    config: Config,
    api: Option<Arc<ICloudApi>>,
    engine: Option<SyncEngine>,
    secure_storage: bool,
    auth: AuthContext,
}

async fn run(commands: mpsc::Receiver<GuiMessage>, events: EventSender) {
    let config = Config::load_defaults();
    let secure_storage = ic_core::config::credential_storage_ready(config.credential_mode);
    let mut worker = Worker {
        commands,
        events,
        config,
        api: None,
        engine: None,
        secure_storage,
        auth: AuthContext::default(),
    };

    while let Some(message) = worker.commands.recv().await {
        match message {
            GuiMessage::Bootstrap => worker.bootstrap().await,
            GuiMessage::SignIn {
                username,
                password,
                method,
                accept_terms,
            } => {
                worker
                    .sign_in(username, password, method, accept_terms)
                    .await
            }
            GuiMessage::SubmitCode { code, accept_terms } => {
                worker.submit_code(code, accept_terms).await
            }
            GuiMessage::ResendCode { method } => worker.resend_code(method).await,
            GuiMessage::ForceSync => worker.force_sync().await,
            GuiMessage::RefreshStatus => worker.refresh_status(),
            GuiMessage::SetAutoSync(enabled) => worker.set_auto_sync(enabled),
            GuiMessage::SetAutostart(enabled) => worker.set_autostart(enabled),
            GuiMessage::RefreshAutostart => worker.refresh_autostart(),
            GuiMessage::ForgetSession => worker.forget_session(),
            GuiMessage::SaveSettings(config) => worker.save_settings(*config),
            GuiMessage::RelocateFolder {
                new_folder,
                sync_now_first,
            } => worker.relocate(new_folder, sync_now_first).await,
            GuiMessage::Shutdown => {
                if let Some(engine) = worker.engine.take() {
                    engine.shutdown();
                }
                worker.activity(LogLevel::Info, "Core worker stopped");
                break;
            }
        }
    }
}

impl Worker {
    fn emit(&self, event: WorkerEvent) {
        // A send fails only when there are no GUI subscribers (shutdown).
        let _ = self.events.send(event);
    }

    fn activity(&self, level: LogLevel, message: impl Into<String>) {
        self.emit(WorkerEvent::Activity {
            level,
            message: message.into(),
        });
    }

    fn error(&self, context: impl Into<String>, error: &CoreError) {
        let message = error.to_string();
        if matches!(error, CoreError::Credential(_)) {
            self.emit(WorkerEvent::SecureStorageUnavailable {
                reason: message.clone(),
            });
        }
        self.emit(WorkerEvent::Error {
            context: context.into(),
            message,
        });
    }

    /// YAML always redacts the password; callers still use this helper so a
    /// future storage change cannot accidentally reintroduce plaintext.
    fn persist(&self, config: &Config) {
        let config_path = match ic_core::paths::config_file() {
            Ok(path) => path,
            Err(err) => {
                self.error("Locating config file", &err);
                return;
            }
        };
        if let Err(err) = config.write(&config_path) {
            self.error("Saving settings", &err);
        }
    }

    fn config_path(&self) -> Option<PathBuf> {
        match ic_core::paths::config_file() {
            Ok(path) => Some(path),
            Err(err) => {
                self.error("Locating config file", &err);
                None
            }
        }
    }

    async fn bootstrap(&mut self) {
        let Some(path) = self.config_path() else {
            return;
        };

        // Load non-secret fields first: a missing/broken credential store must
        // not discard the user's settings or trigger a sign-in loop.
        let mut config = if path.is_file() {
            match Config::load(&path) {
                Ok(config) => config,
                Err(err) => {
                    self.error("Loading settings", &err);
                    Config::load_defaults()
                }
            }
        } else {
            let mut config = Config::load_defaults();
            config.set_config_path(path.clone());
            config
        };

        // Secure mode: a legacy plaintext password must never survive in memory
        // or on disk. Plain mode is an explicit opt-in and keeps the password
        // in the YAML, so do not wipe it here.
        if config.credential_mode == ic_core::config::CredentialMode::Secure {
            config.password.clear();
        }
        self.persist(&config);

        // Hydrate the password from the OS keyring in secure mode.
        if config.credential_mode == ic_core::config::CredentialMode::Secure
            && !config.username.is_empty()
            && let Err(err) = config.hydrate_secrets()
        {
            self.error("Reading saved credentials", &err);
        }

        // The OS is the source of truth for autostart: it can be toggled by
        // desktop settings or a failed write outside this app.
        match ic_core::autostart::is_enabled() {
            Ok(enabled) => config.autostart = enabled,
            Err(err) => self.error("Reading launch-at-login state", &err),
        }

        let status = status::read_status().ok().flatten();
        self.config = config.clone();
        self.secure_storage = ic_core::config::credential_storage_ready(config.credential_mode);
        // The GUI never needs the secret; send a redacted view of the config.
        let mut view = config.clone();
        view.password.clear();
        self.emit(WorkerEvent::Bootstrapped {
            config: view,
            status,
            secure_storage: self.secure_storage,
        });
        self.activity(LogLevel::Info, "Settings and status loaded");

        if !self.secure_storage {
            self.emit(WorkerEvent::SecureStorageUnavailable {
                reason: "No OS credential store is available. Credentials cannot be saved."
                    .to_string(),
            });
            return;
        }
        if !self.config.username.is_empty() && !self.config.password.is_empty() {
            self.connect().await;
        }
    }

    async fn connect(&mut self) {
        self.emit(WorkerEvent::Connecting);
        self.activity(LogLevel::Info, "Connecting to iCloud Drive…");

        let api = match ICloudApi::new(&self.config).await {
            Ok(api) => Arc::new(api),
            Err(err) => {
                self.error("Connecting", &err);
                return;
            }
        };

        let engine = match SyncEngine::new(api.clone(), self.config.clone()).await {
            Ok(engine) => engine,
            Err(err) => {
                self.error("Starting sync engine", &err);
                return;
            }
        };

        // `SyncEngine` is an Arc-backed cloneable handle; do not wrap it again.
        if let Err(err) = engine.start().await {
            self.error("Starting sync engine", &err);
            return;
        }

        self.api = Some(api);
        self.engine = Some(engine);
        self.activity(LogLevel::Success, "Connected. Automatic sync is running.");
        self.refresh_status();
    }

    async fn sign_in(
        &mut self,
        username: String,
        password: String,
        method: VerificationMethod,
        accept_terms: bool,
    ) {
        if !accept_terms {
            self.emit(WorkerEvent::Toast {
                level: LogLevel::Warning,
                message: "Please accept the terms to continue.".to_string(),
            });
            return;
        }
        if !ic_core::config::credential_storage_ready(self.config.credential_mode) {
            self.secure_storage = false;
            self.emit(WorkerEvent::SecureStorageUnavailable {
                reason: "Secure storage unavailable — credentials cannot be stored.".to_string(),
            });
            return;
        }

        self.config.set_username(username.clone());
        if let Err(err) = self.config.store_password(&password) {
            self.config.password.clear();
            self.error("Saving password", &err);
            return;
        }
        self.persist(&self.config);

        // Trust/session tokens are handled by `ic-core::auth` automatically;
        // the GUI no longer exposes a manual token field.
        self.auth.selected = Some(method);
        self.auth.route = None;
        let options = AuthOptions {
            force_sms: method == VerificationMethod::Sms,
            trust_token: None,
            accept_terms,
        };

        let api = match ICloudApi::new(&self.config).await {
            Ok(api) => Arc::new(api),
            Err(err) => {
                self.error("Sign in", &err);
                return;
            }
        };

        self.activity(LogLevel::Info, "Authenticating…");
        match auth::authenticate(&api, &username, &password, &options).await {
            Ok(AuthStep::Authenticated) => {
                self.api = Some(api.clone());
                self.start_engine(api).await;
                self.emit(WorkerEvent::SignedIn);
                self.activity(LogLevel::Success, "Signed in successfully.");
                self.refresh_status();
            }
            Ok(AuthStep::TwoFactorRequired {
                method,
                hint,
                route,
            }) => {
                self.api = Some(api);
                // Remember the exact route so the code is answered on the same
                // Apple endpoint that issued it.
                self.auth.route = Some(route);
                self.emit(WorkerEvent::TwoFactorRequired {
                    method,
                    route,
                    hint,
                });
                self.activity(LogLevel::Info, "Two-factor code required.");
            }
            Err(err) => self.error("Sign in", &err),
        }
    }

    async fn start_engine(&mut self, api: Arc<ICloudApi>) {
        match SyncEngine::new(api, self.config.clone()).await {
            Ok(engine) => {
                if let Err(err) = engine.start().await {
                    self.error("Starting sync engine", &err);
                    return;
                }
                self.engine = Some(engine);
            }
            Err(err) => self.error("Starting sync engine", &err),
        }
    }

    async fn submit_code(&mut self, code: String, accept_terms: bool) {
        let Some(api) = self.api.clone() else {
            self.emit(WorkerEvent::Toast {
                level: LogLevel::Warning,
                message: "Start a sign-in before entering a code.".to_string(),
            });
            return;
        };

        // Use the route core selected when it issued the challenge; never
        // re-detect it here (that was the source of -21669 routing errors).
        let route = self.auth.route.unwrap_or(match self.auth.selected {
            Some(VerificationMethod::Sms) => ic_core::auth::TwoFactorRoute::Sms,
            Some(VerificationMethod::TrustedDevice) | None => {
                ic_core::auth::TwoFactorRoute::TrustedDeviceLegacy
            }
        });

        match auth::submit_code(&api, &code, route, accept_terms).await {
            Ok(AuthStep::Authenticated) => {
                self.auth.route = None;
                self.start_engine(api).await;
                self.emit(WorkerEvent::SignedIn);
                self.activity(LogLevel::Success, "Two-factor code accepted.");
                self.refresh_status();
            }
            Ok(AuthStep::TwoFactorRequired {
                method,
                hint,
                route,
            }) => {
                self.auth.route = Some(route);
                self.emit(WorkerEvent::TwoFactorRequired {
                    method,
                    route,
                    hint,
                });
                self.emit(WorkerEvent::Toast {
                    level: LogLevel::Warning,
                    message: "That code was not accepted. Check the selected method and try again."
                        .to_string(),
                });
            }
            Err(err) => self.error("Two-factor code", &err),
        }
    }

    /// Re-arm code delivery after the user changes verification method.
    async fn resend_code(&mut self, method: VerificationMethod) {
        let Some(api) = self.api.clone() else {
            self.emit(WorkerEvent::Toast {
                level: LogLevel::Warning,
                message: "Start a sign-in before requesting a code.".to_string(),
            });
            return;
        };

        let route = match method {
            VerificationMethod::Sms => ic_core::auth::TwoFactorRoute::Sms,
            VerificationMethod::TrustedDevice => match self.auth.route {
                // Keep the exact device variant core reported (legacy vs bridge).
                Some(
                    r @ (ic_core::auth::TwoFactorRoute::TrustedDeviceLegacy
                    | ic_core::auth::TwoFactorRoute::TrustedDeviceBridge),
                ) => r,
                _ => ic_core::auth::TwoFactorRoute::TrustedDeviceLegacy,
            },
        };
        self.auth.selected = Some(method);
        self.activity(
            LogLevel::Info,
            format!("Requesting a new verification code via {}.", method.label()),
        );
        match auth::request_verification_route(&api, route).await {
            Ok(()) => {
                self.auth.route = Some(route);
                self.emit(WorkerEvent::TwoFactorRequired {
                    method: route.method().to_string(),
                    route,
                    hint: None,
                });
                self.emit(WorkerEvent::Toast {
                    level: LogLevel::Success,
                    message: format!("A new code was requested via {}.", route.method()),
                });
            }
            Err(err) => {
                self.error("Re-sending verification code", &err);
                self.emit(WorkerEvent::Toast {
                    level: LogLevel::Warning,
                    message: "That method could not be re-armed. Restart sign-in to request a \
                              fresh code, then choose the method again."
                        .to_string(),
                });
            }
        }
    }

    async fn force_sync(&mut self) {
        self.emit(WorkerEvent::SyncStarted);

        if let Some(engine) = self.engine.clone() {
            // Fast path: wake the engine's event-driven remote crawl instead of
            // awaiting a full synchronous reconcile on the UI action.
            engine.request_remote_sync();
            self.activity(LogLevel::Info, "Remote sync requested.");
        } else if let Some(api) = self.api.clone() {
            // No running engine but a session exists: fall back to the original
            // full `sync_once()` reconcile on this worker thread.
            match SyncEngine::new(api, self.config.clone()).await {
                Ok(engine) => {
                    self.activity(LogLevel::Info, "Full sync requested.");
                    if let Err(err) = engine.sync_once().await {
                        self.error("Sync", &err);
                    } else {
                        self.activity(LogLevel::Success, "Full sync finished.");
                    }
                }
                Err(err) => self.error("Starting sync engine", &err),
            }
        } else {
            // Nothing to drive locally: queue the on-disk request marker for
            // an external/headless worker.
            if let Err(err) = status::request_sync() {
                self.error("Sync request", &err);
            } else {
                self.activity(LogLevel::Info, "Full sync request queued.");
            }
        }

        self.emit(WorkerEvent::SyncFinished);
        self.refresh_status();
    }

    fn refresh_status(&self) {
        let status = self
            .engine
            .as_ref()
            .map(|engine| engine.status())
            .or_else(|| status::read_status().ok().flatten());
        if let Some(status) = status {
            if !status.secure_storage_available {
                self.emit(WorkerEvent::SecureStorageUnavailable {
                    reason: "Secure storage unavailable — credentials cannot be saved.".to_string(),
                });
            }
            self.emit(WorkerEvent::Status(status));
        }
    }

    fn set_auto_sync(&mut self, enabled: bool) {
        self.config.auto_sync = enabled;
        self.persist(&self.config);
        self.activity(
            LogLevel::Info,
            if enabled {
                "Automatic sync enabled."
            } else {
                "Automatic sync paused."
            },
        );
    }

    /// Apply the launch-at-login switch on the worker thread; never do OS
    /// registry/desktop-file work on the UI thread.
    fn set_autostart(&mut self, enabled: bool) {
        match ic_core::autostart::set_enabled(enabled, self.config.start_minimized) {
            Ok(()) => {
                self.config.autostart = enabled;
                self.persist(&self.config);
                self.emit(WorkerEvent::AutostartState(enabled));
                self.emit(WorkerEvent::Toast {
                    level: LogLevel::Success,
                    message: if enabled {
                        "IC-SYNC will launch at login.".to_string()
                    } else {
                        "Launch at login disabled.".to_string()
                    },
                });
            }
            Err(err) => {
                self.error("Changing launch at login", &err);
                self.emit(WorkerEvent::Toast {
                    level: LogLevel::Warning,
                    message: "Could not change launch at login. Check platform support and \
                              permissions, then try again."
                        .to_string(),
                });
                self.emit(WorkerEvent::AutostartState(self.config.autostart));
            }
        }
    }

    fn refresh_autostart(&self) {
        match ic_core::autostart::is_enabled() {
            Ok(enabled) => self.emit(WorkerEvent::AutostartState(enabled)),
            Err(err) => self.error("Reading launch-at-login state", &err),
        }
    }

    fn save_settings(&mut self, config: Config) {
        use ic_core::config::CredentialMode;

        // The GUI never sends a usable password; merge the worker's runtime
        // copy when plain-text storage was explicitly selected.
        let mut next = config;
        if next.credential_mode == CredentialMode::Plain {
            next.password = self.config.password.clone();
        } else if self.config.credential_mode == CredentialMode::Plain
            && !self.config.password.is_empty()
        {
            // Switching plain -> secure: move the secret into the OS store.
            let secret = self.config.password.clone();
            if !next.username.trim().is_empty() {
                match next.store_password(&secret) {
                    Ok(()) => next.password.clear(),
                    Err(err) => {
                        self.error("Moving password to secure storage", &err);
                        // Keep the explicit plain choice rather than lose the
                        // only copy of the credential.
                        next.credential_mode = CredentialMode::Plain;
                        next.password = secret;
                    }
                }
            }
        }

        let old_autostart = self.config.autostart;
        let old_start_minimized = self.config.start_minimized;

        self.persist(&next);
        self.config = next;

        // Keep the OS launch entry in sync with the saved preferences.
        let autostart_changed = self.config.autostart != old_autostart;
        let minimized_changed =
            self.config.autostart && self.config.start_minimized != old_start_minimized;
        if (autostart_changed || minimized_changed)
            && let Err(err) =
                ic_core::autostart::set_enabled(self.config.autostart, self.config.start_minimized)
        {
            self.error("Updating launch at login", &err);
            self.emit(WorkerEvent::Toast {
                level: LogLevel::Warning,
                message: "Settings saved, but launch at login could not be updated. \
                          Check platform support and permissions."
                    .to_string(),
            });
        }

        let mut view = self.config.clone();
        view.password.clear();
        self.emit(WorkerEvent::SettingsSaved(view));
        self.activity(LogLevel::Success, "Settings saved.");
    }

    fn forget_session(&mut self) {
        if let Some(engine) = self.engine.take() {
            engine.shutdown();
        }
        if let Some(api) = &self.api
            && let Err(err) = api.clear_session()
        {
            self.error("Clearing session", &err);
        }
        self.api = None;
        if let Err(err) = self.config.forget_credentials() {
            self.error("Forget session", &err);
        }
        self.config.set_username("");
        self.config.password.clear();
        self.persist(&self.config);
        self.emit(WorkerEvent::SessionForgotten);
        self.activity(
            LogLevel::Warning,
            "Session forgotten. Sign in again to sync.",
        );
        self.refresh_status();
    }

    async fn relocate(&mut self, new_folder: PathBuf, sync_now_first: bool) {
        let Some(engine) = self.engine.clone() else {
            self.emit(WorkerEvent::RelocationBlocked {
                reason: "The sync engine is not running. Sign in first.".to_string(),
            });
            return;
        };

        if sync_now_first {
            self.activity(LogLevel::Info, "Syncing before moving the folder…");
            if let Err(err) = engine.sync_once().await {
                self.error("Sync before move", &err);
                self.emit(WorkerEvent::RelocationBlocked {
                    reason: "The sync could not be completed. Please try again.".to_string(),
                });
                return;
            }
        }

        // `relocate_folder` is synchronous; we are already on the Tokio worker.
        match engine.relocate_folder(new_folder.clone()) {
            Ok(report) => {
                self.config.sync_folder = new_folder.clone();
                self.persist(&self.config);
                self.emit(WorkerEvent::Relocated {
                    moved: report.moved_files.to_string(),
                    destination: new_folder.to_string_lossy().into_owned(),
                });
                self.activity(
                    LogLevel::Success,
                    format!(
                        "Sync folder moved. {} file(s) relocated.",
                        report.moved_files
                    ),
                );
                self.refresh_status();
            }
            Err(CoreError::NotClean(_)) | Err(CoreError::Conflict(_)) => {
                self.emit(WorkerEvent::RelocationBlocked {
                    reason: "Files are still syncing or have local changes. Sync now, then move."
                        .to_string(),
                });
                self.activity(
                    LogLevel::Warning,
                    "Folder move was deferred: files are not clean.",
                );
            }
            Err(err) => {
                self.error("Move sync folder", &err);
                self.emit(WorkerEvent::RelocationBlocked {
                    reason: err.to_string(),
                });
            }
        }
    }
}
