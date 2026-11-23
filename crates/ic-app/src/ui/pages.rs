//! The five application pages. All views are pure functions of `App` state.

use iced::widget::{button, column, container, row, scrollable, text, text_input, toggler};
use iced::{Element, Fill};

use ic_core::config::{CredentialMode, ThemePreference};

use super::theme;
use super::{App, Message, display_countdown, display_time, path_text};

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

fn setup(app: &App) -> Element<'_, Message> {
    let dark = app.is_dark();
    let mut content = column![].spacing(theme::SPACE_LARGE);

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
            checkbox_row(
                app.force_sms,
                "Force SMS verification",
                Message::ForceSmsChanged,
            ),
            checkbox_row(
                app.accept_terms,
                "I accept the iCloud terms of service",
                Message::AcceptTermsChanged,
            ),
            if app.auth_busy {
                text("Signing in…").color(theme::blue(dark))
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

    if let Some(prompt) = &app.two_factor {
        content = content.push(section(
            "Two-factor verification",
            column![
                text(format!("Method: {}", debug_text(&prompt.method))).size(14),
                text(format!("Hint: {}", debug_text(&prompt.hint)))
                    .size(14)
                    .color(theme::text_muted(dark)),
                field(
                    "6-digit code",
                    text_input("123456", &app.code)
                        .on_input(Message::CodeChanged)
                        .on_submit(Message::SubmitCode {
                            force_sms: app.force_sms,
                            accept_terms: app.accept_terms,
                        })
                        .padding(12)
                        .size(15)
                        .width(Fill)
                        .into(),
                    dark,
                ),
                row![action(
                    "Verify",
                    Message::SubmitCode {
                        force_sms: app.force_sms,
                        accept_terms: app.accept_terms,
                    },
                    true
                )]
                .spacing(theme::SPACE),
            ]
            .spacing(theme::SPACE),
        ));
    }

    scrollable(content).height(Fill).into()
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

    let controls = row![
        action("Force sync", Message::ForceSync, true),
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

    let mut content = column![section("Sync folder", folder)];

    if let Some(warning) = &app.warning {
        content = content.push(
            container(
                column![
                    text("Folder move needs a clean sync").size(16),
                    text(warning.to_string()).size(14),
                    row![
                        action("Sync now, then move", Message::SyncThenMove, true),
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

    // Startup: hide the window at launch and keep syncing from the tray.
    let startup = column![
        toggler(draft.start_minimized)
            .label("Start minimized to tray")
            .on_toggle(Message::StartMinimizedChanged)
            .text_size(14),
        text("IC-SYNC stays running in the tray. Closing the window also hides it there; use the tray icon to reopen.")
            .size(12)
            .color(theme::text_muted(dark)),
    ]
    .spacing(theme::SPACE_SMALL);
    content = content.push(section("Startup", startup));

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
    if app.activity.is_empty() {
        return section(
            "Activity",
            text("No activity yet.").color(theme::text_muted(dark)),
        );
    }

    let mut rows = column![].spacing(theme::SPACE_SMALL);
    for entry in &app.activity {
        rows = rows.push(
            container(
                row![
                    text(entry.time.as_str())
                        .size(12)
                        .color(theme::text_muted(dark))
                        .width(70),
                    text(entry.level.glyph())
                        .size(14)
                        .color(theme::status_text(entry.level, dark))
                        .width(18),
                    text(entry.message.to_string()).size(13),
                ]
                .spacing(theme::SPACE_SMALL),
            )
            .padding([8, 12])
            .style(theme::flat_card),
        );
    }

    column![
        text("Recent events").size(19),
        scrollable(rows).height(Fill),
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
                text("Version 0.1.0").size(15),
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
