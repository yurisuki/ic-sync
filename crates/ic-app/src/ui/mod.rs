//! Iced application state, message routing and shell layout.
//!
//! Pages live in `ui::pages`; colours and reusable styles in `ui::theme`.

pub mod pages;
pub mod theme;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use iced::theme::Mode as SystemThemeMode;
use iced::widget::{button, column, container, row, text, text_editor};
use iced::{Element, Task, Theme};

use ic_core::config::{Config, CredentialMode, ThemePreference};
use ic_core::status::{self, ServiceStatus, SyncPhase, SyncState};

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

/// Category filter for the Activity page. `Success` is grouped with `Info`
/// because both describe normal operation; only `Warning` and `Error` are
/// problems the user may want to isolate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityFilter {
    All,
    Info,
    Warning,
    Error,
}

impl ActivityFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Info => "Info",
            Self::Warning => "Warn",
            Self::Error => "Error",
        }
    }

    pub fn matches(self, level: LogLevel) -> bool {
        match self {
            Self::All => true,
            Self::Info => matches!(level, LogLevel::Info | LogLevel::Success),
            Self::Warning => level == LogLevel::Warning,
            Self::Error => level == LogLevel::Error,
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
    pub activity_filter: ActivityFilter,
    pub toast: Option<Toast>,
    pub warning: Option<String>,
    pub pending_relocation: Option<PathBuf>,
    pub confirm_forget: bool,
    /// Set when the user asks to quit while an upload/download is in flight;
    /// `Tick` completes the shutdown once the engine goes idle.
    pub pending_quit: bool,

    /// OS-reported mode, used when `config.theme` is `system`.
    pub system_mode: SystemThemeMode,
    /// Last time the system appearance was re-probed (poll fallback).
    last_theme_probe: Instant,
    pub secure_storage: String,
    pub secure_available: bool,
    pub tray: Option<TrayHandle>,
    /// Whether a completed Apple sign-in is available for this session.
    pub signed_in: bool,
    /// A spinning frame counter advanced by `Tick`; the loading wheel uses it.
    pub loading_frame: usize,
    /// Read-only copy of the activity log for the Activity page's text form.
    pub activity_editor: text_editor::Content,
    /// The single main window, if it is currently open. Daemon mode lets us
    /// destroy it on close without exiting the process.
    window_id: Option<iced::window::Id>,
    /// The dedicated 2FA window, when a code challenge is in progress.
    verification_window: Option<iced::window::Id>,
    last_state: Option<String>,
    /// Highest `notice_seq` already shown, so a warning is notified once.
    last_notice_seq: u64,
    /// Last engine error already shown as a notification.
    last_error_message: Option<String>,
    /// Throttles the status poll that feeds live progress to the dashboard.
    last_status_poll: Instant,
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

    /// Open/close the dedicated, always-on-top two-factor window.
    OpenVerificationWindow,
    CloseVerificationWindow,
    VerificationWindowOpened(iced::window::Id),
    /// Quit after the current sync operation finishes.
    QuitApp,
    FilterActivity(ActivityFilter),
    /// Write the activity log to a file and toast the path.
    ExportLogs,

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
        activity_filter: ActivityFilter::All,
        toast: None,
        warning: None,
        pending_relocation: None,
        confirm_forget: false,
        pending_quit: false,
        system_mode: SystemThemeMode::Light,
        last_theme_probe: Instant::now(),
        secure_storage,
        secure_available,
        tray,
        signed_in,
        loading_frame: 0,
        activity_editor: text_editor::Content::new(),
        window_id: None,
        verification_window: None,
        last_state: None,
        last_notice_seq: status.as_ref().map_or(0, |status| status.notice_seq),
        last_error_message: None,
        last_status_poll: Instant::now(),
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

/// Title for a specific window. The verification popup is labelled separately
/// so window switchers show what it is.
pub fn title_for(app: &App, window: iced::window::Id) -> String {
    match app.verification_window {
        Some(id) if id == window => "IC-SYNC — Verification".to_string(),
        _ => "IC-SYNC".to_string(),
    }
}

/// Render the window identified by `window`. The main window shows the normal
/// shell; the dedicated 2FA window shows only the code challenge.
pub fn view_for<'a>(app: &'a App, window: iced::window::Id) -> Element<'a, Message> {
    if app.verification_window == Some(window) {
        return container(pages::two_factor(app))
            .width(iced::Fill)
            .height(iced::Fill)
            .style(theme::page_style)
            .into();
    }
    app.view()
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

    /// Whether the dedicated two-factor window is currently open.
    pub fn verification_window_open(&self) -> bool {
        self.verification_window.is_some()
    }

    /// Renders the full activity log as plain text, newest first. Shared by
    /// the Activity page editor, the export button, and toast fallbacks.
    pub fn activity_log_text(&self) -> String {
        self.activity
            .iter()
            .map(|entry| {
                format!(
                    "{}  {:>8}  {}",
                    entry.time,
                    entry.level.label(),
                    entry.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Exports the activity log to a timestamped file in the app's data dir.
    fn export_activity_log(&mut self) {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
        let name = format!("ic-sync-activity-{stamp}.log");
        let body = self.activity_log_text();
        match ic_core::paths::data_dir() {
            Ok(dir) => {
                let path = dir.join(&name);
                let result = std::fs::create_dir_all(&dir)
                    .and_then(|()| std::fs::write(&path, format!("{body}\n")));
                match result {
                    Ok(()) => self.toast(
                        LogLevel::Success,
                        format!("Logs exported to {}", path.display()),
                    ),
                    Err(error) => {
                        self.toast(LogLevel::Warning, format!("Could not export logs: {error}"))
                    }
                }
            }
            Err(error) => self.toast(LogLevel::Warning, format!("Could not export logs: {error}")),
        }
    }

    /// True while an upload, download, crawl or folder move is in flight.
    /// Quit waits for these so the user never loses a half-written transfer.
    fn live_operation(&self) -> bool {
        let Some(status) = &self.status else {
            return false;
        };
        if matches!(status.state, SyncState::Syncing | SyncState::Relocating) {
            return true;
        }
        matches!(
            status.detail.phase,
            SyncPhase::Connecting
                | SyncPhase::RefreshingMetadata
                | SyncPhase::Reconciling
                | SyncPhase::Uploading
                | SyncPhase::Downloading
                | SyncPhase::Relocating
        )
    }

    fn open_verification_window(&mut self) -> Task<Message> {
        if self.verification_window.is_some() {
            return Task::none();
        }
        let (id, opened) = iced::window::open(crate::two_factor_window_settings());
        self.verification_window = Some(id);
        Task::batch([
            opened.map(move |_| Message::VerificationWindowOpened(id)),
            iced::window::gain_focus(id),
        ])
    }

    fn close_verification_window(&mut self) -> Task<Message> {
        match self.verification_window.take() {
            Some(id) => iced::window::close(id),
            None => Task::none(),
        }
    }

    /// Quit immediately when idle, otherwise finish the live operation first.
    fn request_quit(&mut self) -> Task<Message> {
        if self.pending_quit {
            return Task::none();
        }
        if self.live_operation() {
            self.pending_quit = true;
            self.log(
                LogLevel::Info,
                "Quit requested; waiting for the current sync to finish",
            );
            self.toast(
                LogLevel::Warning,
                "Finishing the current sync before quitting…",
            );
            Task::none()
        } else {
            self.begin_shutdown()
        }
    }

    fn begin_shutdown(&mut self) -> Task<Message> {
        self.pending_quit = false;
        self.log(LogLevel::Info, "Quitting");
        self.command(GuiMessage::Shutdown);
        self.window_id = None;
        let mut tasks = Vec::new();
        if let Some(id) = self.verification_window.take() {
            tasks.push(iced::window::close(id));
        }
        tasks.push(iced::exit());
        Task::batch(tasks)
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

    /// Rebuild `activity_editor` from the activity log and the active category
    /// filter. Called on every new log entry and when the user switches filter.
    fn refresh_activity_editor(&mut self) {
        let text: String = self
            .activity
            .iter()
            .filter(|entry| self.activity_filter.matches(entry.level))
            .map(|entry| {
                format!(
                    "{}  {:>8}  {}",
                    entry.time,
                    entry.level.label(),
                    entry.message
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        self.activity_editor = text_editor::Content::with_text(&text);
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
        self.refresh_activity_editor();
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
            tray.set_status(status);
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

            Message::OpenVerificationWindow => return self.open_verification_window(),
            Message::CloseVerificationWindow => return self.close_verification_window(),
            Message::VerificationWindowOpened(id) => {
                self.verification_window = Some(id);
                return iced::window::gain_focus(id);
            }
            Message::QuitApp => return self.request_quit(),
            Message::FilterActivity(filter) => {
                self.activity_filter = filter;
                self.refresh_activity_editor();
            }
            Message::ExportLogs => self.export_activity_log(),

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
                tray::TrayAction::Quit => return self.request_quit(),
            },
            Message::CloseRequested(id) => {
                // Destroy only the window that was closed. Iced is running in
                // daemon mode, so the process, tray icon and sync engine stay
                // alive; the tray menu opens a new window on demand.
                if self.verification_window == Some(id) {
                    self.verification_window = None;
                } else if self.window_id == Some(id) {
                    self.window_id = None;
                }
                return iced::window::close(id);
            }
            Message::WindowOpened(id) => {
                self.window_id = Some(id);
                return iced::window::gain_focus(id);
            }

            Message::Tick => {
                self.loading_frame = self.loading_frame.wrapping_add(1);
                if self
                    .toast
                    .as_ref()
                    .is_some_and(|t| Instant::now() >= t.expires)
                {
                    self.toast = None;
                }
                // A quit requested during an upload/download waits for the
                // engine to go idle; re-check on every tick.
                if self.pending_quit && !self.live_operation() {
                    return self.begin_shutdown();
                }
                let now = Instant::now();
                let mut tasks = Vec::new();
                // Live progress and engine warnings ride on the status
                // document, so poll it once a second while the GUI is open.
                if now.duration_since(self.last_status_poll) >= Duration::from_secs(1) {
                    self.last_status_poll = now;
                    self.command(GuiMessage::RefreshStatus);
                }
                // Polling fallback: some desktops never emit theme changes,
                // so re-read the OS appearance every few seconds. This is
                // cheap and also keeps the gsettings fallback up to date.
                if now.duration_since(self.last_theme_probe) >= Duration::from_secs(3) {
                    self.last_theme_probe = now;
                    tasks.push(probe_system_theme());
                }
                if !tasks.is_empty() {
                    return Task::batch(tasks);
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
                self.config = (*config).clone();
                self.draft = SettingsDraft::from_config(&config);
                self.refresh_secure_storage();
                if self.apple_id.is_empty() {
                    self.apple_id = config.username.clone();
                }
                if let Some(status) = status {
                    self.signed_in = status.state != SyncState::LoginRequired;
                    self.last_notice_seq = status.notice_seq;
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
                // Engine warnings (e.g. "remote parent … not uploaded yet")
                // arrive on the status document; notify once per sequence.
                if status.notice_seq > self.last_notice_seq {
                    self.last_notice_seq = status.notice_seq;
                    if let Some(notice) = &status.notice {
                        self.log(LogLevel::Warning, notice.clone());
                        self.toast(LogLevel::Warning, notice.clone());
                    }
                }
                // A terminal error is worth a notification even when it has no
                // dedicated `notice` entry.
                if status.state == SyncState::Error {
                    if self.last_error_message.as_deref() != Some(status.message.as_str()) {
                        self.last_error_message = Some(status.message.clone());
                        self.toast(LogLevel::Error, status.message.clone());
                    }
                } else {
                    self.last_error_message = None;
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
                if let Some(tray) = &self.tray {
                    tray.set_verification_required();
                }
                return self.open_verification_window();
            }
            WorkerEvent::SignedIn => {
                self.auth_busy = false;
                self.signed_in = true;
                self.refresh_tray_actions();
                self.two_factor = None;
                self.auth_error = None;
                self.page = Page::Dashboard;
                self.toast(LogLevel::Success, "Signed in successfully.");
                return self.close_verification_window();
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
                return self.close_verification_window();
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
        let pages: Vec<Page> = if self.signed_in {
            vec![Page::Dashboard, Page::Activity, Page::Settings, Page::About]
        } else {
            vec![
                Page::Setup,
                Page::Dashboard,
                Page::Activity,
                Page::Settings,
                Page::About,
            ]
        };
        for &page in &pages {
            let label = page.label();
            // The active page is highlighted; the Sign-in page (first when
            // signed out) is the only other styled entry, keeping it distinct.
            let style = if page == self.page {
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
        nav = nav.push(
            button(text("⏻  Quit IC-SYNC").size(13))
                .width(iced::Fill)
                .on_press(Message::QuitApp)
                .style(theme::danger_button),
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

    /// Full name used by the Activity page's export header and files.
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Info => "Info",
            LogLevel::Success => "Success",
            LogLevel::Warning => "Warning",
            LogLevel::Error => "Error",
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
