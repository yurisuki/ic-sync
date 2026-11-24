//! The five application pages. All views are pure functions of `App` state.

use iced::widget::{
    button, column, container, progress_bar, row, scrollable, text, text_editor, text_input,
    toggler,
};

use iced::{Element, Fill};

use ic_core::config::{CredentialMode, ThemePreference};
use ic_core::status::SyncState;

use crate::worker::VerificationMethod;

use super::theme;
use super::{ActivityFilter, App, Message, display_countdown, display_time, path_text};

/// Braille spinner frames for the loading wheel (advanced by `App::loading_frame`).
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A braille "wheel" that rotates while an operation waits.
pub fn spinner(frame: usize) -> &'static str {
    SPINNER_FRAMES[frame % SPINNER_FRAMES.len()]
}

pub fn view(app: &App) -> Element<'_, Message> {
    match app.page {
        super::Page::Setup => setup(app),
        super::Page::Dashboard => dashboard(app),
        super::Page::Settings => settings(app),
        super::Page::Activity => activity(app),
        super::Page::About => about(app),
    }
}

fn section<'a>(title: &'static str, body: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(column![text(title).size(19), body.into()].spacing(theme::SPACE))
        .padding(theme::SPACE_LARGE)
        .style(theme::card)
        .into()
}

fn field<'a>(label: &'static str, input: Element<'a, Message>, dark: bool) -> Element<'a, Message> {
    column![text(label).size(13).color(theme::text_muted(dark)), input]
        .spacing(6)
        .into()
}

fn action<'a>(label: &'static str, message: Message, primary: bool) -> Element<'a, Message> {
    let button = button(label).on_press(message);
    if primary {
        button.style(theme::primary_button)
    } else {
        button.style(theme::secondary_button)
    }
    .into()
}

/// Non-interactive, visually muted counterpart of `action`. With no
/// `on_press`, Iced renders it as disabled and ignores clicks on it.
fn disabled_action(label: &'static str) -> Element<'static, Message> {
    button(label).style(theme::disabled_button).into()
}

fn setup(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();
    let mut content = column![].spacing(theme::SPACE_LARGE);

    // Loading wheel while sign-in is in flight (busy on form submit or the
    // 2FA challenge, until the engine reports success or another prompt).
    if app.auth_busy {
        content = content.push(
            column![
                text(spinner(app.loading_frame))
                    .size(20)
                    .color(theme::accent(dark)),
                text("Signing in…").size(14).color(theme::text_muted(dark)),
            ]
            .spacing(theme::SPACE)
            .align_x(iced::Alignment::Center),
        );
    }

    content = content.push(section(
        "Sign in to iCloud Drive",
        column![
            field(
                "Apple ID",
                text_input("name@example.com", &app.apple_id)
                    .on_input(Message::AppleIdChanged)
                    .on_submit(Message::SignIn)
                    .padding(12)
                    .size(15)
                    .width(Fill)
                    .into(),
                dark,
            ),
            field(
                "Password",
                text_input("Password", &app.password)
                    .on_input(Message::PasswordChanged)
                    .on_submit(Message::SignIn)
                    .secure(true)
                    .padding(12)
                    .size(15)
                    .width(Fill)
                    .into(),
                dark,
            ),
            text(
                "Your password is stored using the credential mode chosen in Settings. \
                 Trust and session tokens are handled automatically — no manual token entry needed.",
            )
            .size(12)
            .color(theme::text_muted(dark)),
            text("Verification method").size(13).color(theme::text_muted(dark)),
            verification_method_selector(app.verification_method),
            checkbox_row(
                app.accept_terms,
                "I accept the iCloud terms of service",
                Message::AcceptTermsChanged,
            ),
            if app.auth_busy {
                let waiting = match app.verification_method {
                    crate::worker::VerificationMethod::TrustedDevice => {
                        "Waiting for verification on your iPhone…"
                    }
                    crate::worker::VerificationMethod::Sms => "Waiting for SMS code…",
                };
                text(waiting).color(theme::blue(dark))
            } else if app.two_factor.is_some() {
                text("Waiting for verification…").color(theme::blue(dark))
            } else {
                text("")
            },
            if let Some(error) = &app.auth_error {
                text(error).color(theme::red(dark)).size(14)
            } else {
                text("")
            },
            row![action("Sign in", Message::SignIn, true)].spacing(theme::SPACE),
        ]
        .spacing(theme::SPACE),
    ));

    if app.two_factor.is_some() {
        // The code is entered in its own, always-on-top window. Keep a way to
        // reopen it here in case the user closed the popup by accident.
        content = content.push(section(
            "Two-factor verification",
            column![
                text("Enter the verification code in the separate verification window.").size(15),
                text(if app.verification_window_open() {
                    "The verification window is open."
                } else {
                    "The verification window was closed."
                })
                .size(13)
                .color(theme::text_muted(dark)),
                if app.verification_window_open() {
                    disabled_action("Verification window open")
                } else {
                    action(
                        "Open verification window",
                        Message::OpenVerificationWindow,
                        true,
                    )
                },
            ]
            .spacing(theme::SPACE),
        ));
    }

    scrollable(content).height(Fill).into()
}

/// Content of the dedicated 2FA window. This is the only place where the code
/// is entered; the main window just points to this popup.
pub fn two_factor(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();

    // While the code is being verified, the window is greyed/blurred with a
    // loading wheel instead of the prompt form.
    if app.auth_busy {
        return container(
            column![
                text(spinner(app.loading_frame))
                    .size(24)
                    .color(theme::accent(dark)),
                text("Verifying the code…")
                    .size(14)
                    .color(theme::text_muted(dark)),
            ]
            .spacing(theme::SPACE_LARGE),
        )
        .padding([64, 80])
        .align_x(iced::Alignment::Center)
        .align_y(iced::Alignment::Center)
        .style(theme::busy_overlay)
        .into();
    }

    let Some(prompt) = &app.two_factor else {
        return container(
            column![
                text("Two-factor verification").size(19),
                text("No verification is in progress.").color(theme::text_muted(dark)),
                action("Close", Message::CloseVerificationWindow, false),
            ]
            .spacing(theme::SPACE),
        )
        .padding(theme::SPACE_LARGE)
        .into();
    };
    let instruction = if prompt.route.is_trusted_device() {
        "Enter the code shown on your iPhone"
    } else {
        "Enter the code sent by SMS"
    };
    let hint = prompt.hint.as_deref().unwrap_or("");

    container(
        column![
            text("Two-factor verification").size(20),
            text(instruction).size(15),
            text(format!("Method reported by Apple: {}", prompt.method))
                .size(12)
                .color(theme::text_muted(dark)),
            text(if hint.is_empty() {
                String::new()
            } else {
                format!("Sent to: {hint}")
            })
            .size(13)
            .color(theme::text_muted(dark)),
            text("Wrong method? Choose another one below, then resend the code.")
                .size(12)
                .color(theme::text_muted(dark)),
            verification_method_selector(app.verification_method),
            field(
                "6-digit code",
                text_input("123456", &app.code)
                    .on_input(Message::CodeChanged)
                    .on_submit(Message::SubmitCode {
                        accept_terms: app.accept_terms,
                    })
                    .padding(12)
                    .size(15)
                    .width(Fill)
                    .into(),
                dark,
            ),
            if let Some(error) = &app.auth_error {
                text(error).color(theme::red(dark)).size(14)
            } else {
                text("")
            },
            row![
                action(
                    "Verify",
                    Message::SubmitCode {
                        accept_terms: app.accept_terms,
                    },
                    true,
                ),
                action("Resend code / use this method", Message::ResendCode, false),
            ]
            .spacing(theme::SPACE_SMALL)
            .wrap(),
        ]
        .spacing(theme::SPACE),
    )
    .padding(theme::SPACE_LARGE)
    .into()
}

/// Verification method: trusted device first (recommended), SMS second.
/// Security-key accounts are handled automatically by core, not offered here.
fn verification_method_selector(selected: VerificationMethod) -> Element<'static, Message> {
    row![
        choice_button(
            "iPhone / trusted device (recommended)",
            selected == VerificationMethod::TrustedDevice,
            Message::VerificationMethodChanged(VerificationMethod::TrustedDevice),
        ),
        choice_button(
            "SMS to trusted number (second option)",
            selected == VerificationMethod::Sms,
            Message::VerificationMethodChanged(VerificationMethod::Sms),
        ),
    ]
    .spacing(theme::SPACE_SMALL)
    .wrap()
    .into()
}

fn checkbox_row<'a>(
    checked: bool,
    label: &'static str,
    on_toggle: fn(bool) -> Message,
) -> Element<'a, Message> {
    iced::widget::checkbox(checked)
        .label(label)
        .on_toggle(on_toggle)
        .text_size(14)
        .into()
}

fn dashboard(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();
    let Some(status) = &app.status else {
        return section(
            "Dashboard",
            text("Loading sync status…").color(theme::text_muted(dark)),
        );
    };

    let state_label = super::state_label(&status.state);
    let badge = container(text(state_label).size(15))
        .padding([8, 16])
        .style(move |iced_theme| {
            let d = theme::is_dark(iced_theme);
            theme::tinted(theme::status_tint(&status.state, d), d)
        });

    let stats = column![
        stat_row("Last sync", display_time(status.last_sync_at), dark),
        stat_row(
            "Next sync",
            format!(
                "{} ({})",
                display_time(status.next_sync_at),
                display_countdown(status.next_sync_at)
            ),
            dark,
        ),
        stat_row("Pending changes", status.pending.to_string(), dark),
        stat_row(
            "Files synced",
            format!("{} / {}", status.synced_files, status.total_files),
            dark,
        ),
        stat_row("Sync folder", status.current_folder.clone(), dark),
    ]
    .spacing(10);

    let detail = &status.detail;
    let step = if detail.step.is_empty() {
        status.message.clone()
    } else {
        detail.step.clone()
    };
    let mut process = column![
        text(step).size(14),
        text(format!("Phase: {}", detail.phase.label()))
            .size(12)
            .color(theme::text_muted(dark)),
    ]
    .spacing(6);
    // Loading wheel while the engine is mid-operation (syncing or relocating).
    if matches!(status.state, SyncState::Syncing | SyncState::Relocating) {
        process = process.push(
            text(spinner(app.loading_frame))
                .size(18)
                .color(theme::accent(dark)),
        );
    }
    if detail.total > 0 {
        let completed = detail.completed.min(detail.total) as f32;
        process = process.push(progress_bar(0.0..=1.0, completed / detail.total as f32).girth(8));
        process = process.push(
            text(format!(
                "Progress: {} / {} items",
                detail.completed.min(detail.total),
                detail.total
            ))
            .size(12)
            .color(theme::text_muted(dark)),
        );
    }
    if let Some(item) = &detail.current_item {
        process = process.push(
            text(format!("Current item: {item}"))
                .size(12)
                .color(theme::text_muted(dark)),
        );
    }

    let sync_control = if app.can_sync() {
        action("Force sync", Message::ForceSync, true)
    } else {
        disabled_action("Force sync")
    };

    let controls = row![
        sync_control,
        action(
            if app.config.auto_sync {
                "Pause auto-sync"
            } else {
                "Resume auto-sync"
            },
            Message::ToggleAutoSync,
            false,
        ),
        action("Open folder", Message::OpenFolder, false),
        action("Check status", Message::CheckStatus, false),
        if app.confirm_forget {
            button("Confirm sign out")
                .style(theme::danger_button)
                .on_press(Message::ForgetSession)
        } else {
            button("Forget session")
                .style(theme::danger_button)
                .on_press(Message::ForgetSession)
        },
    ]
    .spacing(theme::SPACE_SMALL)
    .wrap();

    column![
        section(
            "Status",
            column![
                badge,
                text(status.message.to_string())
                    .size(14)
                    .color(theme::text_muted(dark))
            ]
            .spacing(theme::SPACE),
        ),
        section("Recent changes", recent_changes(app, 6)),
        section("Sync process", process),
        section("Overview", stats),
        section("Actions", controls),
        text(format!(
            "Instant sync is {}. Local edits upload immediately and trigger a debounced remote check.",
            if app.config.instant_sync {
                "on"
            } else {
                "off"
            }
        ))
        .size(12)
        .color(theme::text_muted(dark)),
    ]
    .spacing(theme::SPACE_LARGE)
    .into()
}

/// Minimal recent-changes feed: symbol + path + age, newest first.
fn recent_changes(app: &App, limit: usize) -> Element<'_, Message> {
    let dark = app.is_dark();
    let status = match &app.status {
        Some(status) => status,
        None => {
            return text("No changes yet.")
                .color(theme::text_muted(dark))
                .into();
        }
    };
    if status.recent_changes.is_empty() {
        return text("No changes yet.")
            .color(theme::text_muted(dark))
            .into();
    }
    let mut list = column![].spacing(theme::SPACE_SMALL);
    for change in status.recent_changes.iter().take(limit) {
        list = list.push(
            row![
                text(change.kind.symbol())
                    .size(14)
                    .color(theme::status_text_change(change.kind, dark))
                    .width(24),
                text(change.path.to_string()).size(13),
                text(relative_time(change.at))
                    .size(12)
                    .color(theme::text_muted(dark))
                    .width(52),
            ]
            .spacing(theme::SPACE_SMALL),
        );
    }
    column![
        list,
        text(format!(
            "Last {} shown",
            status.recent_changes.len().min(limit)
        ))
        .size(11)
        .color(theme::text_muted(dark))
    ]
    .spacing(theme::SPACE_SMALL)
    .into()
}

fn relative_time(at: i64) -> String {
    let delta = chrono::Utc::now().timestamp().saturating_sub(at);
    if delta < 60 {
        format!("{delta}s ago")
    } else {
        let minutes = delta / 60;
        if minutes < 60 {
            format!("{minutes}m ago")
        } else {
            let hours = minutes / 60;
            if hours < 24 {
                format!("{hours}h ago")
            } else {
                format!("{}d ago", hours / 24)
            }
        }
    }
}

fn stat_row(label: &'static str, value: String, dark: bool) -> Element<'static, Message> {
    row![
        text(label)
            .size(14)
            .color(theme::text_muted(dark))
            .width(160),
        text(value).size(14),
    ]
    .spacing(theme::SPACE)
    .into()
}

fn settings(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();
    let draft = &app.draft;

    let folder = column![
        row![
            text(path_text(&draft.sync_folder)).size(14),
            button("Browse…")
                .style(theme::secondary_button)
                .on_press(Message::PickFolder),
        ]
        .spacing(theme::SPACE)
        .align_y(iced::Alignment::Center),
        text("Changing the folder moves your files only after a clean sync.")
            .size(12)
            .color(theme::text_muted(dark)),
    ]
    .spacing(theme::SPACE_SMALL);

    // Startup is first and prominent: these are the two people most often
    // look for when IC-SYNC is set to run in the background.
    let startup = column![
        toggler(draft.start_minimized)
            .label("Start minimized to tray")
            .on_toggle(Message::StartMinimizedChanged)
            .text_size(14),
        text("On by default. IC-SYNC starts in the tray/taskbar; use Open IC-SYNC to show the window.")
            .size(12)
            .color(theme::text_muted(dark)),
        toggler(draft.autostart)
            .label("Launch at login (autostart)")
            .on_toggle(Message::AutostartChanged)
            .text_size(14),
        text("Starts IC-SYNC automatically when you log in; uses the startup preference above.")
            .size(12)
            .color(theme::text_muted(dark)),
    ]
    .spacing(theme::SPACE_SMALL);

    let mut content = column![section("Startup", startup), section("Sync folder", folder)];

    if let Some(warning) = &app.warning {
        content = content.push(
            container(
                column![
                    text("Folder move needs a clean sync").size(16),
                    text(warning.to_string()).size(14),
                    row![
                        if app.can_sync() {
                            action("Sync now, then move", Message::SyncThenMove, true)
                        } else {
                            disabled_action("Sync now, then move")
                        },
                        action("Dismiss", Message::DismissWarning, false),
                    ]
                    .spacing(theme::SPACE_SMALL),
                ]
                .spacing(theme::SPACE_SMALL),
            )
            .padding(theme::SPACE)
            .style(|iced_theme| {
                let d = theme::is_dark(iced_theme);
                container::Style {
                    background: Some(iced::Background::Color(theme::warning_surface(d))),
                    border: iced::Border {
                        color: theme::amber(d),
                        width: 1.0,
                        radius: theme::CARD_RADIUS.into(),
                    },
                    text_color: Some(theme::text_primary(d)),
                    ..Default::default()
                }
            }),
        );
    }

    // Appearance: System / Light / Dark segmented control.
    let theme_choice = row![
        choice_button(
            "System",
            draft.theme == ThemePreference::System,
            Message::ThemeChanged(ThemePreference::System),
        ),
        choice_button(
            "Light",
            draft.theme == ThemePreference::Light,
            Message::ThemeChanged(ThemePreference::Light),
        ),
        choice_button(
            "Dark",
            draft.theme == ThemePreference::Dark,
            Message::ThemeChanged(ThemePreference::Dark),
        ),
    ]
    .spacing(theme::SPACE_SMALL);

    let appearance = column![
        field("Theme", theme_choice.into(), dark),
        text("System follows your desktop appearance automatically.")
            .size(12)
            .color(theme::text_muted(dark)),
    ]
    .spacing(theme::SPACE_SMALL);
    content = content.push(section("Appearance", appearance));

    // Scheduling: quick presets plus the precise numeric fields.
    let current_interval = draft.sync_interval.trim().parse::<u64>().ok();
    let presets = row![
        preset_button("5s Instant", 5, current_interval),
        preset_button("15s Fast (default)", 15, current_interval),
        preset_button("30s Balanced", 30, current_interval),
        preset_button("60s Relaxed", 60, current_interval),
    ]
    .spacing(theme::SPACE_SMALL)
    .wrap();

    let timing = column![
        toggler(draft.auto_sync)
            .label("Automatic sync")
            .on_toggle(Message::DraftAutoSync)
            .text_size(14),
        toggler(draft.instant_sync)
            .label("Instant sync")
            .on_toggle(Message::InstantSyncChanged)
            .text_size(14),
        text("Local edits upload immediately and trigger a debounced remote check.")
            .size(12)
            .color(theme::text_muted(dark)),
        field(
            "Remote check interval (seconds)",
            text_input("15", &draft.sync_interval)
                .on_input(Message::SyncIntervalChanged)
                .padding(10)
                .width(Fill)
                .into(),
            dark,
        ),
        presets,
        field(
            "Upload safety sweep (seconds)",
            text_input("5", &draft.upload_interval)
                .on_input(Message::UploadIntervalChanged)
                .padding(10)
                .width(Fill)
                .into(),
            dark,
        ),
    ]
    .spacing(theme::SPACE);

    content = content.push(section("Schedule", timing));

    // Credential storage: the unsafe option is deliberately loud.
    let plain = draft.credential_mode == CredentialMode::Plain;
    let secure_choice = button("Secure — OS credential store (recommended)")
        .on_press(Message::CredentialModeChanged(CredentialMode::Secure))
        .style(if draft.credential_mode == CredentialMode::Secure {
            theme::primary_button
        } else {
            theme::secondary_button
        });
    let plain_label = if plain {
        "✓ ⚠ Plain text file — UNSAFE (selected)"
    } else {
        "⚠ Plain text file — UNSAFE"
    };
    let plain_choice = button(plain_label)
        .on_press(Message::CredentialModeChanged(CredentialMode::Plain))
        .style(theme::unsafe_button);

    let credentials = column![
        text("Credential storage").size(14),
        row![secure_choice, plain_choice]
            .spacing(theme::SPACE_SMALL)
            .wrap(),
        if plain {
            plain_storage_warning(dark)
        } else {
            text("").into()
        },
    ]
    .spacing(theme::SPACE_SMALL);
    content = content.push(section("Credentials", credentials));

    let paths = column![
        text("Remote allowlist").size(14),
        list_editor(
            &draft.allow,
            &draft.allow_input,
            Message::AllowInput,
            Message::AddAllow,
            Message::RemoveAllow,
            "e.g. Photos/2026"
        ),
        text("Remote denylist (excluded paths)").size(14),
        list_editor(
            &draft.deny,
            &draft.deny_input,
            Message::DenyInput,
            Message::AddDeny,
            Message::RemoveDeny,
            "e.g. Temp"
        ),
    ]
    .spacing(theme::SPACE_SMALL);
    content = content.push(section("Remote paths", paths));

    let safety = column![
        text(format!(
            "Conflict handling: {}",
            debug_text(&app.config.conflict_mode)
        ))
        .size(14),
        text("Conflicting copies are kept as <name>.local-conflict-<timestamp>; nothing is deleted automatically.")
            .size(12)
            .color(theme::text_muted(dark)),
        text("Secure storage").size(14),
        text(app.secure_storage.as_str())
            .size(12)
            .color(if plain {
                theme::red(dark)
            } else {
                theme::text_muted(dark)
            }),
    ]
    .spacing(theme::SPACE_SMALL);
    content = content.push(section("Safety", safety));

    content = content
        .push(row![action("Save settings", Message::SaveSettings, true)].spacing(theme::SPACE));

    scrollable(content.spacing(theme::SPACE_LARGE))
        .height(Fill)
        .into()
}

fn choice_button<'a>(
    label: &'static str,
    selected: bool,
    message: Message,
) -> Element<'a, Message> {
    button(label)
        .on_press(message)
        .style(if selected {
            theme::primary_button
        } else {
            theme::secondary_button
        })
        .into()
}

fn preset_button<'a>(
    label: &'static str,
    seconds: u64,
    current: Option<u64>,
) -> Element<'a, Message> {
    button(label)
        .on_press(Message::SyncIntervalChanged(seconds.to_string()))
        .style(if current == Some(seconds) {
            theme::primary_button
        } else {
            theme::secondary_button
        })
        .into()
}

fn plain_storage_warning(dark: bool) -> Element<'static, Message> {
    let detail = ic_core::plain_storage_warning().to_string();
    container(
        column![
            text("⚠ UNSAFE — NOT RECOMMENDED")
                .size(16)
                .color(theme::red(dark)),
            text(detail).size(13).color(theme::text_primary(dark)),
            text("Your password would be written to the local config file in plain text. Anyone with access to your account can read it.")
                .size(12)
                .color(theme::text_muted(dark)),
        ]
        .spacing(theme::SPACE_SMALL),
    )
    .padding(theme::SPACE)
    .style(|iced_theme| {
        let d = theme::is_dark(iced_theme);
        container::Style {
            background: Some(iced::Background::Color(theme::warning_surface(d))),
            border: iced::Border {
                color: theme::red(d),
                width: 1.5,
                radius: theme::CARD_RADIUS.into(),
            },
            text_color: Some(theme::text_primary(d)),
            ..Default::default()
        }
    })
    .into()
}

fn list_editor<'a>(
    items: &'a [String],
    input: &'a str,
    on_input: impl Fn(String) -> Message + 'a,
    on_add: Message,
    on_remove: impl Fn(usize) -> Message + 'a,
    placeholder: &'static str,
) -> Element<'a, Message> {
    let mut column = column![].spacing(6);
    for (index, item) in items.iter().enumerate() {
        column = column.push(
            row![
                text(item.as_str()).size(14),
                button("Remove")
                    .style(theme::secondary_button)
                    .on_press(on_remove(index)),
            ]
            .spacing(theme::SPACE_SMALL),
        );
    }
    column = column.push(
        row![
            text_input(placeholder, input)
                .on_input(on_input)
                .padding(9)
                .width(Fill),
            button("Add")
                .style(theme::secondary_button)
                .on_press(on_add),
        ]
        .spacing(theme::SPACE_SMALL),
    );
    column.into()
}

fn activity(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();

    // Minimal category chips: user can isolate Info, Warnings or Errors.
    let mut filters = row![].spacing(theme::SPACE_SMALL);
    for filter in [
        ActivityFilter::All,
        ActivityFilter::Info,
        ActivityFilter::Warning,
        ActivityFilter::Error,
    ] {
        let count = app
            .activity
            .iter()
            .filter(|entry| filter.matches(entry.level))
            .count();
        let style = if app.activity_filter == filter {
            theme::primary_button
        } else {
            theme::secondary_button
        };
        filters = filters.push(
            button(text(format!("{} ({count})", filter.label())))
                .on_press(Message::FilterActivity(filter))
                .style(style),
        );
    }

    // The log as a selectable text form: the user can read it, select it and
    // copy/paste to report problems. `activity_editor` reflects the active
    // category filter (rebuilt on every log entry / filter change).
    let log: Element<'_, Message> = if app.activity.is_empty() {
        text("No activity yet.")
            .color(theme::text_muted(dark))
            .into()
    } else {
        text_editor::TextEditor::new(&app.activity_editor).into()
    };

    column![
        row![
            text("Recent events").size(19),
            action("Export logs", Message::ExportLogs, false),
        ]
        .spacing(theme::SPACE)
        .align_y(iced::Alignment::Center),
        filters,
        log,
    ]
    .spacing(theme::SPACE)
    .into()
}

fn about(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();
    column![
        section(
            "IC-SYNC",
            column![
                text(format!("Version {}", env!("CARGO_PKG_VERSION"))).size(15),
                text("A native, standalone iCloud Drive folder sync application.").size(14),
                text("Built with Rust, Iced and Tokio. No Python, no webview.")
                    .size(13)
                    .color(theme::text_muted(dark)),
            ]
            .spacing(theme::SPACE_SMALL),
        ),
        section(
            "Details",
            column![
                text("License: MIT").size(14),
                text("Source: https://github.com/yurisuki/ic-sync").size(13),
                text(format!("Secure storage: {}", app.secure_storage))
                    .size(13)
                    .color(if app.config.credential_mode == CredentialMode::Plain {
                        theme::red(dark)
                    } else {
                        theme::text_muted(dark)
                    }),
            ]
            .spacing(theme::SPACE_SMALL),
        ),
    ]
    .spacing(theme::SPACE_LARGE)
    .into()
}

fn debug_text<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}").trim_matches('"').to_string()
}
