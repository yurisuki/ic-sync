//! Iced application state, message routing and shell layout.
//!
//! Pages live in `ui::pages`; colours and reusable styles in `ui::theme`.

pub mod pages;
pub mod theme;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::theme::Mode as SystemThemeMode;
use iced::widget::{button, column, container, row, text};
use iced::{Element, Task, Theme};

use ic_core::config::{Config, CredentialMode, ThemePreference};
use ic_core::status::{self, ServiceStatus, SyncState};

use crate::tray::{self, TrayHandle};
use crate::worker::{self, GuiMessage, LogLevel, WorkerEvent};

use theme::{SPACE, SPACE_LARGE, SPACE_SMALL};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    Setup,
    Dashboard,
    Settings,
    Activity,
    About,
}

impl Page {
    fn label(self) -> &'static str {
        match self {
            Page::Setup => "Sign in",
            Page::Dashboard => "Dashboard",
            Page::Settings => "Settings",
            Page::Activity => "Activity",
            Page::About => "About",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TwoFactorPrompt {
    /// Route name reported by Apple/core (shown in the verification panel).
    pub method: String,
    /// Actual route chosen by core; must be replayed when submitting the code.
    pub route: ic_core::auth::TwoFactorRoute,
    pub hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActivityEntry {
    pub time: String,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Toast {
    pub level: LogLevel,
    pub message: String,
    pub expires: Instant,
}

#[derive(Clone, Debug)]
pub struct SettingsDraft {
    pub sync_folder: PathBuf,
    pub auto_sync: bool,
    pub instant_sync: bool,
    pub sync_interval: String,
    pub upload_interval: String,
    pub theme: ThemePreference,
    pub credential_mode: CredentialMode,
    pub start_minimized: bool,
    pub autostart: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_input: String,
    pub deny_input: String,
}

impl SettingsDraft {
    fn from_config(config: &Config) -> Self {
        Self {
            sync_folder: config.sync_folder.clone(),
            auto_sync: config.auto_sync,
            instant_sync: config.instant_sync,
            sync_interval: config.sync_interval_seconds.to_string(),
            upload_interval: config.upload_interval_seconds.to_string(),
            theme: config.theme,
            credential_mode: config.credential_mode,
            start_minimized: config.start_minimized,
            autostart: config.autostart,
            allow: config.sync_paths.clone(),
            deny: config.exclude_paths.clone(),
            allow_input: String::new(),
            deny_input: String::new(),
        }
    }
}

pub struct App {
    pub page: Page,
    pub config: Config,
    pub status: Option<ServiceStatus>,
    pub draft: SettingsDraft,

    // Sign-in form
    pub apple_id: String,
    pub password: String,
    pub verification_method: worker::VerificationMethod,
    pub accept_terms: bool,
    pub code: String,
    pub two_factor: Option<TwoFactorPrompt>,
    pub auth_busy: bool,
    pub auth_error: Option<String>,

    // Feedback
    pub activity: Vec<ActivityEntry>,
    pub toast: Option<Toast>,
    pub warning: Option<String>,
    pub pending_relocation: Option<PathBuf>,
    pub confirm_forget: bool,

    /// OS-reported mode, used when `config.theme` is `system`.
    pub system_mode: SystemThemeMode,
    /// Last time the system appearance was re-probed (poll fallback).
    last_theme_probe: Instant,
    pub secure_storage: String,
    pub secure_available: bool,
    pub tray: Option<TrayHandle>,
    /// Whether a completed Apple sign-in is available for this session.
    pub signed_in: bool,
    /// The single main window, if it is currently open. Daemon mode lets us
    /// destroy it on close without exiting the process.
    window_id: Option<iced::window::Id>,
    last_state: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
    Navigate(Page),

    AppleIdChanged(String),
    PasswordChanged(String),
    VerificationMethodChanged(worker::VerificationMethod),
    ResendCode,
    AcceptTermsChanged(bool),
    SignIn,
    CodeChanged(String),
    SubmitCode {
        accept_terms: bool,
    },

    ForceSync,
    ToggleAutoSync,
    OpenFolder,
    ForgetSession,
    CheckStatus,

    PickFolder,
    FolderPicked(Option<PathBuf>),
    AllowInput(String),
    DenyInput(String),
    AddAllow,
    AddDeny,
    RemoveAllow(usize),
    RemoveDeny(usize),
    SyncIntervalChanged(String),
    UploadIntervalChanged(String),
    DraftAutoSync(bool),
    InstantSyncChanged(bool),
    ThemeChanged(ThemePreference),
    CredentialModeChanged(CredentialMode),
    StartMinimizedChanged(bool),
    AutostartChanged(bool),
    SystemThemeChanged(SystemThemeMode),
    /// Result of the desktop-settings fallback used when iced cannot report
    /// the system appearance (e.g. no XDG Settings portal on Hyprland).
    SystemThemeFallback(Option<SystemThemeMode>),
    SaveSettings,
    SyncThenMove,
    DismissWarning,

    Worker(Box<WorkerEvent>),
    Tray(tray::TrayAction),
    CloseRequested(iced::window::Id),
    WindowOpened(iced::window::Id),
    Tick,
    ClearToast,
}

pub fn new() -> (App, Task<Message>) {
    let config = Config::load_defaults();
    let status = status::read_status().ok().flatten();
    let draft = SettingsDraft::from_config(&config);
    let secure_available = crate::secrets::available();
    let secure_storage = secure_storage_label(config.credential_mode, secure_available);

    let signed_in = status
        .as_ref()
        .is_some_and(|s| s.state != SyncState::LoginRequired);
    let tray = tray::spawn(signed_in);

    let mut app = App {
        page: if signed_in {
            Page::Dashboard
        } else {
            Page::Setup
        },
        apple_id: config.username.clone(),
        password: String::new(),
        verification_method: worker::VerificationMethod::TrustedDevice,
        accept_terms: false,
        code: String::new(),
        two_factor: None,
        auth_busy: false,
        auth_error: None,
        activity: Vec::new(),
        toast: None,
        warning: None,
        pending_relocation: None,
        confirm_forget: false,
        system_mode: SystemThemeMode::Light,
        last_theme_probe: Instant::now(),
        secure_storage,
        secure_available,
        tray,
        signed_in,
        window_id: None,
        last_state: None,
        status,
        config,
        draft,
    };

    app.log(LogLevel::Info, "IC-SYNC started");
    worker::send(GuiMessage::Bootstrap);

    // Probe the OS appearance once; the subscription and Tick fallback below
    // keep it in sync when the desktop does not emit theme changes.
    let system_theme_task = probe_system_theme();

    // Daemon mode: start with no window only when already signed in AND the
    // preference says minimized. An unsigned-in session must always show the
    // sign-in window, otherwise the user has no way to log in from the tray.
    // Closing a window later only destroys that window; the process and tray
    // stay alive.
    let window_task = if signed_in && crate::start_minimized() {
        Task::none()
    } else {
        open_window()
    };

    (app, Task::batch([system_theme_task, window_task]))
}

/// Open the single main window and report its id back to the application.
fn open_window() -> Task<Message> {
    let (id, opened) = iced::window::open(crate::window_settings());
    Task::batch([
        opened.map(move |_| Message::WindowOpened(id)),
        iced::window::gain_focus(id),
    ])
}

/// Indicator shown in the sidebar and Settings. Plain-text mode is deliberately
/// loud: it is an explicit opt-in and must never look "secure".
fn secure_storage_label(mode: CredentialMode, available: bool) -> String {
    match mode {
        CredentialMode::Secure => {
            if available {
                crate::secrets::descriptor()
            } else {
                "Secure storage unavailable".to_string()
            }
        }
        CredentialMode::Plain => "⚠ Plain text file — UNSAFE (NOT RECOMMENDED)".to_string(),
    }
}

pub fn title(_app: &App) -> String {
    "IC-SYNC".to_string()
}

/// Resolves the application theme from the persisted preference. `System`
/// follows the OS-reported mode tracked by `App::system_mode`.
pub fn theme(app: &App) -> Theme {
    match app.config.theme {
        ThemePreference::Light => Theme::Light,
        ThemePreference::Dark => Theme::Dark,
        ThemePreference::System => match app.system_mode {
            SystemThemeMode::Dark => Theme::Dark,
            _ => Theme::Light,
        },
    }
}

/// Ask Iced for the system appearance. Its `theme_changes` subscription relies
/// on the XDG Settings portal, which is silent on some desktops (notably
/// Hyprland), so `Message::SystemThemeChanged` falls back to the desktop
/// setting when Iced reports `None`.
fn probe_system_theme() -> Task<Message> {
    iced::system::theme().map(Message::SystemThemeChanged)
}

/// Last-resort appearance probe for Linux desktops where the XDG Settings
/// portal used by Iced does not expose `color-scheme`. Most of them (including
/// Hyprland, GNOME and XFCE) still store the preference in gsettings.
fn desktop_color_scheme() -> Option<SystemThemeMode> {
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "color-scheme"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout);
        if value.contains("prefer-dark") {
            Some(SystemThemeMode::Dark)
        } else if value.contains("prefer-light") || value.contains("default") {
            Some(SystemThemeMode::Light)
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub fn subscription(_app: &App) -> iced::Subscription<Message> {
    iced::Subscription::batch([
        worker::subscription().map(|event| Message::Worker(Box::new(event))),
        tray::subscription().map(Message::Tray),
        iced::window::close_requests().map(Message::CloseRequested),
        iced::system::theme_changes().map(Message::SystemThemeChanged),
        iced::time::every(Duration::from_millis(500)).map(|_| Message::Tick),
    ])
}

impl App {
    /// Convenience for view code that needs mode-specific colours.
    pub fn is_dark(&self) -> bool {
        theme(self) == Theme::Dark
    }

    /// Syncing requires a usable session. Status may lag behind `signed_in`,
    /// so check both sources here.
    pub fn can_sync(&self) -> bool {
        self.signed_in
            && !self
                .status
                .as_ref()
                .is_some_and(|status| status.state == SyncState::LoginRequired)
    }

    /// Push the current sync availability to the tray menu.
    fn refresh_tray_actions(&self) {
        if let Some(tray) = &self.tray {
            tray.set_sync_enabled(self.can_sync());
        }
    }

    /// Recompute the credential indicator after config/mode changes.
    fn refresh_secure_storage(&mut self) {
        self.secure_storage =
            secure_storage_label(self.config.credential_mode, self.secure_available);
    }

    fn log(&mut self, level: LogLevel, message: impl Into<String>) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        self.activity.insert(
            0,
            ActivityEntry {
                time,
                level,
                message: message.into(),
            },
        );
        self.activity.truncate(250);
    }

    fn toast(&mut self, level: LogLevel, message: impl Into<String>) {
        self.toast = Some(Toast {
            level,
            message: message.into(),
            expires: Instant::now() + Duration::from_secs(6),
        });
    }

    fn command(&self, message: GuiMessage) {
        worker::send(message);
    }

    fn push_status_to_tray(&self, status: &ServiceStatus) {
        if let Some(tray) = &self.tray {
            tray.set_status(format!(
                "{} · {} pending",
                state_label(&status.state),
                status.pending
            ));
        }
        self.refresh_tray_actions();
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(page) => {
                self.page = page;
                self.warning = None;
                if page == Page::Settings {
                    self.command(GuiMessage::RefreshAutostart);
                }
            }

            Message::AppleIdChanged(value) => self.apple_id = value,
            Message::PasswordChanged(value) => self.password = value,
            Message::VerificationMethodChanged(method) => {
                self.verification_method = method;
                // Re-arm code delivery for the newly selected method. The old
                // code belongs to the previous endpoint and will be rejected.
                if self.two_factor.is_some() {
                    self.command(GuiMessage::ResendCode { method });
                }
            }
            Message::ResendCode => {
                self.command(GuiMessage::ResendCode {
                    method: self.verification_method,
                });
                self.log(LogLevel::Info, "Re-sending verification code");
            }
            Message::AcceptTermsChanged(value) => self.accept_terms = value,
            Message::CodeChanged(value) => self.code = value,

            Message::SignIn => {
                if !ic_core::config::credential_storage_ready(self.config.credential_mode) {
                    self.auth_error = Some(
                        "Secure storage unavailable — choose a secure credential store, or opt \
                         into plain-text storage in Settings (NOT RECOMMENDED)."
                            .to_string(),
                    );
                } else if self.apple_id.trim().is_empty() || self.password.is_empty() {
                    self.auth_error = Some("Enter your Apple ID and password.".to_string());
                } else if !self.accept_terms {
                    self.auth_error = Some("Please accept the terms to continue.".to_string());
                } else {
                    self.auth_error = None;
                    self.auth_busy = true;
                    self.log(LogLevel::Info, "Sign-in requested");
                    self.command(GuiMessage::SignIn {
                        username: self.apple_id.trim().to_string(),
                        password: self.password.clone(),
                        method: self.verification_method,
                        accept_terms: self.accept_terms,
                    });
                    // The password lives in the OS store after this point; the
                    // GUI drops its copy as soon as the command is queued.
                    self.password.clear();
                }
            }

            Message::SubmitCode { accept_terms } => {
                if self.code.trim().is_empty() {
                    self.auth_error = Some("Enter the 6-digit code.".to_string());
                } else {
                    self.auth_error = None;
                    self.auth_busy = true;
                    self.command(GuiMessage::SubmitCode {
                        code: self.code.trim().to_string(),
                        accept_terms,
                    });
                    self.code.clear();
                    self.log(LogLevel::Info, "Two-factor code submitted");
                }
            }

            Message::ForceSync => {
                // Both the tray item and the dashboard button are disabled
                // while signed out; guard here too in case a stale event slips
                // through before the tray thread processes the update.
                if self.can_sync() {
                    self.log(LogLevel::Info, "Force sync pressed");
                    self.command(GuiMessage::ForceSync);
                }
            }
            Message::CheckStatus => self.command(GuiMessage::RefreshStatus),

            Message::ToggleAutoSync => {
                let enabled = !self.config.auto_sync;
                self.config.auto_sync = enabled;
                self.draft.auto_sync = enabled;
                self.command(GuiMessage::SetAutoSync(enabled));
            }

            Message::OpenFolder => {
                let folder = self.config.sync_folder.clone();
                if folder.as_os_str().is_empty() {
                    self.toast(LogLevel::Warning, "No sync folder has been selected yet.");
                } else {
                    reveal_folder(&folder);
                    self.log(
                        LogLevel::Info,
                        format!("Opened folder {}", path_text(&folder)),
                    );
                }
            }

            Message::ForgetSession => {
                if self.confirm_forget {
                    self.confirm_forget = false;
                    self.command(GuiMessage::ForgetSession);
                } else {
                    self.confirm_forget = true;
                }
            }

            Message::PickFolder => {
                let initial = self.draft.sync_folder.clone();
                return Task::perform(
                    async move {
                        match tokio::task::spawn_blocking(move || {
                            rfd::FileDialog::new().set_directory(initial).pick_folder()
                        })
                        .await
                        {
                            Ok(folder) => folder,
                            Err(err) => {
                                tracing::warn!("Folder picker task failed: {err}");
                                None
                            }
                        }
                    },
                    Message::FolderPicked,
                );
            }

            Message::FolderPicked(Some(folder)) => {
                self.draft.sync_folder = folder.clone();
                if folder != self.config.sync_folder {
                    self.pending_relocation = Some(folder.clone());
                    self.warning = Some(format!(
                        "The sync folder will be moved to {}. Files must be fully synced first.",
                        path_text(&folder)
                    ));
                    self.log(
                        LogLevel::Info,
                        format!("Selected new folder {}", path_text(&folder)),
                    );
                    self.command(GuiMessage::RelocateFolder {
                        new_folder: folder,
                        sync_now_first: false,
                    });
                }
            }
            Message::FolderPicked(None) => {}

            Message::AllowInput(value) => self.draft.allow_input = value,
            Message::DenyInput(value) => self.draft.deny_input = value,
            Message::AddAllow => {
                let value = self.draft.allow_input.trim().to_string();
                if !value.is_empty() && !self.draft.allow.contains(&value) {
                    self.draft.allow.push(value);
                }
                self.draft.allow_input.clear();
            }
            Message::AddDeny => {
                let value = self.draft.deny_input.trim().to_string();
                if !value.is_empty() && !self.draft.deny.contains(&value) {
                    self.draft.deny.push(value);
                }
                self.draft.deny_input.clear();
            }
            Message::RemoveAllow(index) => {
                if index < self.draft.allow.len() {
                    self.draft.allow.remove(index);
                }
            }
            Message::RemoveDeny(index) => {
                if index < self.draft.deny.len() {
                    self.draft.deny.remove(index);
                }
            }
            Message::SyncIntervalChanged(value) => self.draft.sync_interval = value,
            Message::UploadIntervalChanged(value) => self.draft.upload_interval = value,
            Message::DraftAutoSync(value) => {
                self.draft.auto_sync = value;
                self.config.auto_sync = value;
            }
            Message::InstantSyncChanged(value) => {
                self.draft.instant_sync = value;
                self.config.instant_sync = value;
                self.log(
                    LogLevel::Info,
                    if value {
                        "Instant sync enabled."
                    } else {
                        "Instant sync disabled."
                    },
                );
            }
            Message::ThemeChanged(value) => {
                self.draft.theme = value;
                self.config.theme = value;
                if value == ThemePreference::System {
                    return probe_system_theme();
                }
            }
            Message::CredentialModeChanged(value) => {
                self.draft.credential_mode = value;
                self.config.credential_mode = value;
                self.refresh_secure_storage();
                if value == CredentialMode::Plain {
                    self.log(
                        LogLevel::Warning,
                        "UNSAFE plain-text credential storage selected (NOT RECOMMENDED).",
                    );
                }
            }
            Message::StartMinimizedChanged(value) => {
                self.draft.start_minimized = value;
                self.config.start_minimized = value;
            }
            Message::AutostartChanged(value) => {
                self.draft.autostart = value;
                self.config.autostart = value;
                self.command(GuiMessage::SetAutostart(value));
            }
            Message::SystemThemeChanged(mode) => {
                if mode == SystemThemeMode::None {
                    // Iced could not determine the desktop appearance (no XDG
                    // Settings portal on this compositor). Ask the desktop
                    // directly without blocking the UI thread.
                    return Task::perform(
                        tokio::task::spawn_blocking(desktop_color_scheme),
                        |result| Message::SystemThemeFallback(result.ok().flatten()),
                    );
                }
                self.system_mode = mode;
            }
            Message::SystemThemeFallback(Some(mode)) => self.system_mode = mode,
            Message::SystemThemeFallback(None) => {}

            Message::SaveSettings => {
                let mut config = self.config.clone();
                config.sync_folder = self.draft.sync_folder.clone();
                config.auto_sync = self.draft.auto_sync;
                config.instant_sync = self.draft.instant_sync;
                config.theme = self.draft.theme;
                config.credential_mode = self.draft.credential_mode;
                config.start_minimized = self.draft.start_minimized;
                config.autostart = self.draft.autostart;
                config.sync_paths = self.draft.allow.clone();
                config.exclude_paths = self.draft.deny.clone();
                config.sync_interval_seconds = parse_interval(
                    &self.draft.sync_interval,
                    config.sync_interval_seconds,
                    ic_core::config::MIN_SYNC_INTERVAL_SECONDS,
                );
                config.upload_interval_seconds = parse_interval(
                    &self.draft.upload_interval,
                    config.upload_interval_seconds,
                    ic_core::config::MIN_UPLOAD_INTERVAL_SECONDS,
                );
                // The GUI never holds a usable password; the worker merges its
                // own runtime copy before persisting.
                config.password.clear();
                self.draft.sync_interval = config.sync_interval_seconds.to_string();
                self.draft.upload_interval = config.upload_interval_seconds.to_string();
                self.command(GuiMessage::SaveSettings(Box::new(config)));
            }

            Message::SyncThenMove => {
                if let Some(folder) = self.pending_relocation.clone().filter(|_| self.can_sync()) {
                    self.warning = None;
                    self.log(LogLevel::Info, "Syncing, then moving sync folder");
                    self.command(GuiMessage::RelocateFolder {
                        new_folder: folder,
                        sync_now_first: true,
                    });
                }
            }
            Message::DismissWarning => {
                self.warning = None;
                self.pending_relocation = None;
            }

            Message::Worker(event) => return self.handle_worker(*event),
            Message::Tray(action) => match action {
                tray::TrayAction::Open => {
                    // Reuse the existing window when it is open; otherwise open
                    // a fresh one. This is the only reliable "show" on Wayland.
                    return match self.window_id {
                        Some(id) => iced::window::gain_focus(id),
                        None => open_window(),
                    };
                }
                tray::TrayAction::SyncNow => {
                    if self.can_sync() {
                        self.log(LogLevel::Info, "Sync requested from tray");
                        self.command(GuiMessage::ForceSync);
                    }
                }
                tray::TrayAction::Quit => {
                    self.log(LogLevel::Info, "Quit requested from tray");
                    self.command(GuiMessage::Shutdown);
                    self.window_id = None;
                    return iced::exit();
                }
            },
            Message::CloseRequested(id) => {
                // Destroy only the window. Iced is running in daemon mode, so
                // the process, tray icon and sync engine stay alive. The tray
                // menu opens a new window on demand.
                self.window_id = None;
                return iced::window::close(id);
            }
            Message::WindowOpened(id) => {
                self.window_id = Some(id);
                return iced::window::gain_focus(id);
            }

            Message::Tick => {
                if self
                    .toast
                    .as_ref()
                    .is_some_and(|t| Instant::now() >= t.expires)
                {
                    self.toast = None;
                }
                // Polling fallback: some desktops never emit theme changes,
                // so re-read the OS appearance every few seconds. This is
                // cheap and also keeps the gsettings fallback up to date.
                if Instant::now().duration_since(self.last_theme_probe) >= Duration::from_secs(3) {
                    self.last_theme_probe = Instant::now();
                    return probe_system_theme();
                }
            }
            Message::ClearToast => self.toast = None,
        }

        Task::none()
    }

    fn handle_worker(&mut self, event: WorkerEvent) -> Task<Message> {
        match event {
            WorkerEvent::Bootstrapped {
                config,
                status,
                secure_storage,
            } => {
                self.secure_available = secure_storage;
                self.config = config.clone();
                self.draft = SettingsDraft::from_config(&config);
                self.refresh_secure_storage();
                if self.apple_id.is_empty() {
                    self.apple_id = config.username.clone();
                }
                if let Some(status) = status {
                    self.signed_in = status.state != SyncState::LoginRequired;
                    self.push_status_to_tray(&status);
                    self.status = Some(status);
                }
                self.log(LogLevel::Info, "Configuration loaded");
            }
            WorkerEvent::Connecting => self.log(LogLevel::Info, "Connecting to iCloud Drive…"),
            WorkerEvent::Status(status) => {
                if status.state == SyncState::LoginRequired {
                    self.signed_in = false;
                }
                let label = state_label(&status.state);
                if self.last_state.as_deref() != Some(label) {
                    self.last_state = Some(label.to_string());
                    self.log(LogLevel::Info, format!("Status: {label}"));
                }
                self.push_status_to_tray(&status);
                self.status = Some(status);
            }
            WorkerEvent::TwoFactorRequired {
                method,
                route,
                hint,
            } => {
                self.auth_busy = false;
                self.signed_in = false;
                self.refresh_tray_actions();
                self.verification_method = match route {
                    ic_core::auth::TwoFactorRoute::Sms => worker::VerificationMethod::Sms,
                    _ => worker::VerificationMethod::TrustedDevice,
                };
                self.two_factor = Some(TwoFactorPrompt {
                    method,
                    route,
                    hint,
                });
                self.page = Page::Setup;
                self.toast(LogLevel::Warning, "Two-factor verification required.");
            }
            WorkerEvent::SignedIn => {
                self.auth_busy = false;
                self.signed_in = true;
                self.refresh_tray_actions();
                self.two_factor = None;
                self.auth_error = None;
                self.page = Page::Dashboard;
                self.toast(LogLevel::Success, "Signed in successfully.");
            }
            WorkerEvent::SyncStarted => self.log(LogLevel::Info, "Sync started"),
            WorkerEvent::SyncFinished => {
                self.auth_busy = false;
                self.log(LogLevel::Success, "Sync finished");
            }
            WorkerEvent::SettingsSaved(config) => {
                self.config = config.clone();
                self.draft = SettingsDraft::from_config(&config);
                self.refresh_secure_storage();
                self.toast(LogLevel::Success, "Settings saved.");
            }
            WorkerEvent::AutostartState(enabled) => {
                // The OS is the source of truth for autostart (it can be changed
                // outside the app).
                self.config.autostart = enabled;
                self.draft.autostart = enabled;
            }
            WorkerEvent::SessionForgotten => {
                self.signed_in = false;
                self.refresh_tray_actions();
                self.page = Page::Setup;
                self.password.clear();
                self.apple_id.clear();
                self.status = None;
                self.toast(LogLevel::Success, "Session forgotten.");
            }
            WorkerEvent::Relocated { moved, destination } => {
                self.pending_relocation = None;
                self.warning = None;
                self.draft.sync_folder = PathBuf::from(&destination);
                self.config.sync_folder = PathBuf::from(&destination);
                self.toast(
                    LogLevel::Success,
                    format!("Moved {moved} file(s) to {destination}."),
                );
            }
            WorkerEvent::RelocationBlocked { reason } => {
                self.warning = Some(reason.clone());
                self.toast(LogLevel::Warning, "Folder move was deferred.");
                self.log(LogLevel::Warning, reason);
            }
            WorkerEvent::Activity { level, message } => self.log(level, message),
            WorkerEvent::Toast { level, message } => {
                self.log(level, message.clone());
                self.toast(level, message);
            }
            WorkerEvent::Error { context, message } => {
                self.auth_busy = false;
                // Core's typed CodeRejected error already explains -21669 and
                // which method the code must come from; show it verbatim.
                self.auth_error = Some(message.clone());
                let combined = if context.is_empty() {
                    message
                } else {
                    format!("{context}: {message}")
                };
                self.log(LogLevel::Error, combined.clone());
                self.toast(LogLevel::Error, combined);
            }
            WorkerEvent::SecureStorageUnavailable { reason } => {
                self.secure_available = false;
                self.refresh_secure_storage();
                self.auth_busy = false;
                self.log(
                    LogLevel::Error,
                    format!("Secure storage unavailable: {reason}"),
                );
                // Plain-text mode is an explicit opt-in and does not need the
                // OS store, so only block sign-in in secure mode.
                if self.config.credential_mode == CredentialMode::Secure {
                    self.auth_error = Some(reason.clone());
                    self.page = Page::Setup;
                }
            }
            WorkerEvent::Lagged(skipped) => {
                self.log(
                    LogLevel::Warning,
                    format!("Skipped {skipped} worker updates"),
                );
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        let dark = self.is_dark();
        let header = container(
            row![
                text("IC-SYNC").size(26).color(theme::accent(dark)),
                text("  iCloud Drive, on your terms")
                    .size(13)
                    .color(theme::text_muted(dark)),
            ]
            .spacing(SPACE_SMALL)
            .align_y(iced::Alignment::Center),
        )
        .padding([SPACE, SPACE_LARGE])
        .style(|iced_theme| container::Style {
            background: Some(iced::Background::Color(theme::surface(theme::is_dark(
                iced_theme,
            )))),
            border: iced::Border {
                color: theme::border(theme::is_dark(iced_theme)),
                width: 1.0,
                ..iced::Border::default()
            },
            ..Default::default()
        });

        let mut nav = column![].spacing(6).padding([SPACE_LARGE, SPACE]);
        let pages: &[Page] = if self.signed_in {
            &[Page::Dashboard, Page::Settings, Page::Activity, Page::About]
        } else {
            &[Page::Setup, Page::Settings, Page::Activity, Page::About]
        };
        for &page in pages {
            let label = page.label();
            let style = if self.page == page {
                theme::primary_button
            } else {
                theme::secondary_button
            };
            nav = nav.push(
                button(label)
                    .width(iced::Fill)
                    .on_press(Message::Navigate(page))
                    .style(style),
            );
        }
        // Push the account block to the bottom-left of the sidebar.
        nav = nav.push(container(text("")).height(iced::Fill));
        if self.signed_in {
            let account_label = if self.apple_id.is_empty() {
                "Account".to_owned()
            } else {
                self.apple_id.chars().take(24).collect::<String>()
            };
            nav = nav.push(
                button(
                    column![
                        text("Account").size(12).color(theme::text_muted(dark)),
                        text(account_label).size(13),
                    ]
                    .spacing(2),
                )
                .width(iced::Fill)
                .on_press(Message::Navigate(Page::Settings))
                .style(theme::secondary_button),
            );
        }
        nav = nav.push(
            text(format!("Secure storage\n{}", self.secure_storage))
                .size(11)
                .color(theme::text_muted(dark)),
        );

        let sidebar = container(nav)
            .width(200)
            .height(iced::Fill)
            .style(|iced_theme| container::Style {
                background: Some(iced::Background::Color(theme::surface(theme::is_dark(
                    iced_theme,
                )))),
                border: iced::Border {
                    color: theme::border(theme::is_dark(iced_theme)),
                    width: 1.0,
                    ..iced::Border::default()
                },
                ..Default::default()
            });

        let page = container(pages::view(self))
            .padding(SPACE_LARGE)
            .height(iced::Fill)
            .width(iced::Fill);

        let body = row![sidebar, page];

        let mut root = column![header, body];
        if let Some(toast) = &self.toast {
            root = root.push(
                container(
                    row![
                        text(toast.level.glyph()).color(theme::status_text(toast.level, dark)),
                        text(&toast.message).size(14),
                        button("Dismiss")
                            .style(theme::secondary_button)
                            .on_press(Message::ClearToast),
                    ]
                    .spacing(SPACE)
                    .align_y(iced::Alignment::Center),
                )
                .padding([SPACE_SMALL, SPACE])
                .style(theme::flat_card),
            );
        }

        container(root)
            .width(iced::Fill)
            .height(iced::Fill)
            .style(theme::page_style)
            .into()
    }
}

impl LogLevel {
    pub fn glyph(self) -> &'static str {
        match self {
            LogLevel::Info => "•",
            LogLevel::Success => "✓",
            LogLevel::Warning => "!",
            LogLevel::Error => "×",
        }
    }
}

fn state_label(state: &SyncState) -> &'static str {
    match state {
        SyncState::Synced => "Synced",
        SyncState::Syncing => "Syncing",
        SyncState::LoginRequired => "Sign in required",
        SyncState::Offline => "Offline",
        SyncState::Error => "Error",
        SyncState::Relocating => "Moving folder",
        _ => "Unknown",
    }
}

fn path_text(path: impl AsRef<Path>) -> String {
    path.as_ref().to_string_lossy().into_owned()
}

pub(crate) fn reveal_folder(path: &Path) {
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("explorer").arg(path).spawn();
    #[cfg(not(target_os = "windows"))]
    let result = std::process::Command::new("xdg-open").arg(path).spawn();

    if let Err(err) = result {
        tracing::warn!("Could not open sync folder: {err}");
    }
}

/// Parses a user-entered interval, falling back to the previous value and
/// enforcing the core's minimum.
fn parse_interval(raw: &str, fallback: u64, minimum: u64) -> u64 {
    raw.trim().parse::<u64>().unwrap_or(fallback).max(minimum)
}

/// Human-friendly countdown for the dashboard's next-sync indicator.
pub fn display_countdown(timestamp: Option<i64>) -> String {
    let Some(seconds) = timestamp else {
        return "Not scheduled".to_string();
    };
    let now = chrono::Utc::now().timestamp();
    let remaining = seconds - now;
    if remaining <= 0 {
        "Due now".to_string()
    } else if remaining < 60 {
        format!("in {remaining}s")
    } else {
        format!("in {}m {}s", remaining / 60, remaining % 60)
    }
}

/// Formats an optional Unix timestamp for display without panicking on
/// invalid values.
pub fn display_time(timestamp: Option<i64>) -> String {
    match timestamp {
        Some(seconds) => chrono::DateTime::from_timestamp(seconds, 0)
            .map(|dt| {
                dt.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d %H:%M")
                    .to_string()
            })
            .unwrap_or_else(|| "Unknown".to_string()),
        None => "Not yet".to_string(),
    }
}
