//! Shared visual language: spacing, accent colours and reusable styles.
//!
//! Every colour helper takes a `dark` flag resolved from the active
//! `iced::Theme`. The application deliberately uses a small custom palette in
//! both modes so text, cards and status badges stay readable when the user
//! switches between Light and Dark (including the `System` preference).

use crate::worker::LogLevel;
use ic_core::status::SyncState;
use iced::theme::{self, Base};
use iced::widget::{button, container};
use iced::{Background, Border, Color, Theme};

pub const SPACE_SMALL: f32 = 8.0;
pub const SPACE: f32 = 16.0;
pub const SPACE_LARGE: f32 = 24.0;
pub const CARD_RADIUS: f32 = 12.0;

pub fn color(hex: &str) -> Color {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0);
    Color::from_rgb8(r, g, b)
}

/// True when the given Iced theme uses dark tones.
pub fn is_dark(theme: &Theme) -> bool {
    theme.mode() == theme::Mode::Dark
}

pub fn canvas(dark: bool) -> Color {
    if dark {
        color("#12161F")
    } else {
        color("#F4F6FA")
    }
}

pub fn surface(dark: bool) -> Color {
    if dark { color("#1F2733") } else { Color::WHITE }
}

pub fn elevated_surface(dark: bool) -> Color {
    if dark {
        color("#273140")
    } else {
        color("#F9FAFB")
    }
}

pub fn hover_surface(dark: bool) -> Color {
    if dark {
        color("#334155")
    } else {
        color("#F3F4F6")
    }
}

pub fn text_primary(dark: bool) -> Color {
    if dark {
        color("#F3F4F6")
    } else {
        color("#111827")
    }
}

pub fn text_muted(dark: bool) -> Color {
    if dark {
        color("#AAB3C2")
    } else {
        color("#6B7280")
    }
}

pub fn border(dark: bool) -> Color {
    if dark {
        color("#3A4556")
    } else {
        color("#E5E7EB")
    }
}

pub fn border_strong(dark: bool) -> Color {
    if dark {
        color("#4B5563")
    } else {
        color("#D1D5DB")
    }
}

pub fn accent(dark: bool) -> Color {
    if dark {
        color("#60A5FA")
    } else {
        color("#2563EB")
    }
}

pub fn green(dark: bool) -> Color {
    if dark {
        color("#4ADE80")
    } else {
        color("#16A34A")
    }
}

pub fn blue(dark: bool) -> Color {
    if dark {
        color("#60A5FA")
    } else {
        color("#2563EB")
    }
}

pub fn amber(dark: bool) -> Color {
    if dark {
        color("#FBBF24")
    } else {
        color("#D97706")
    }
}

pub fn gray(dark: bool) -> Color {
    if dark {
        color("#9CA3AF")
    } else {
        color("#6B7280")
    }
}

pub fn red(dark: bool) -> Color {
    if dark {
        color("#F87171")
    } else {
        color("#DC2626")
    }
}

/// Background of callout/warning cards; never white-on-white in dark mode.
pub fn warning_surface(dark: bool) -> Color {
    if dark {
        color("#3A2B12")
    } else {
        color("#FFFBEB")
    }
}

pub fn status_color(state: &SyncState, dark: bool) -> Color {
    match state {
        SyncState::Synced => green(dark),
        SyncState::Syncing | SyncState::Relocating => blue(dark),
        SyncState::LoginRequired => amber(dark),
        SyncState::Offline => gray(dark),
        SyncState::Error => red(dark),
        _ => gray(dark),
    }
}

pub fn status_text(level: LogLevel, dark: bool) -> Color {
    match level {
        LogLevel::Info => blue(dark),
        LogLevel::Success => green(dark),
        LogLevel::Warning => amber(dark),
        LogLevel::Error => red(dark),
    }
}

pub fn status_tint(state: &SyncState, dark: bool) -> Color {
    let base = status_color(state, dark);
    Color {
        r: base.r,
        g: base.g,
        b: base.b,
        a: if dark { 0.22 } else { 0.14 },
    }
}

pub fn card(theme: &Theme) -> container::Style {
    let dark = is_dark(theme);
    container::Style {
        background: Some(Background::Color(surface(dark))),
        text_color: Some(text_primary(dark)),
        border: Border {
            color: border(dark),
            width: 1.0,
            radius: CARD_RADIUS.into(),
        },
        shadow: iced::Shadow {
            color: Color {
                a: if dark { 0.30 } else { 0.06 },
                ..Color::BLACK
            },
            blur_radius: 14.0,
            offset: iced::Vector::new(0.0, 3.0),
        },
        ..Default::default()
    }
}

pub fn flat_card(theme: &Theme) -> container::Style {
    let dark = is_dark(theme);
    container::Style {
        background: Some(Background::Color(elevated_surface(dark))),
        text_color: Some(text_primary(dark)),
        border: Border {
            color: border(dark),
            width: 1.0,
            radius: 10.0.into(),
        },
        ..Default::default()
    }
}

pub fn tinted(tint: Color, dark: bool) -> container::Style {
    container::Style {
        background: Some(Background::Color(tint)),
        text_color: Some(text_primary(dark)),
        border: Border {
            radius: 999.0.into(),
            ..Border::default()
        },
        ..Default::default()
    }
}

pub fn page_style(theme: &Theme) -> container::Style {
    let dark = is_dark(theme);
    container::Style {
        background: Some(Background::Color(canvas(dark))),
        text_color: Some(text_primary(dark)),
        ..Default::default()
    }
}

fn button_base(background: Color, foreground: Color) -> button::Style {
    button::Style {
        background: Some(Background::Color(background)),
        text_color: foreground,
        border: Border {
            radius: 8.0.into(),
            ..Border::default()
        },
        ..Default::default()
    }
}

pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
    let dark = is_dark(theme);
    let mut style = button_base(
        accent(dark),
        if dark { color("#0B1220") } else { Color::WHITE },
    );
    if matches!(status, button::Status::Hovered) {
        style.background = Some(Background::Color(if dark {
            color("#93C5FD")
        } else {
            color("#1D4ED8")
        }));
    }
    if matches!(status, button::Status::Disabled) {
        style.background = Some(Background::Color(if dark {
            color("#1E40AF")
        } else {
            color("#93C5FD")
        }));
    }
    style
}

pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
    let dark = is_dark(theme);
    let mut style = button::Style {
        background: Some(Background::Color(surface(dark))),
        text_color: text_primary(dark),
        border: Border {
            color: border_strong(dark),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    };
    if matches!(status, button::Status::Hovered) {
        style.background = Some(Background::Color(hover_surface(dark)));
    }
    style
}

/// Muted style for actions that cannot be used right now (e.g. syncing while
/// signed out). Buttons using this style are built without `on_press`, so Iced
/// also treats them as non-interactive.
pub fn disabled_button(theme: &Theme, _status: button::Status) -> button::Style {
    let dark = is_dark(theme);
    button::Style {
        background: Some(Background::Color(elevated_surface(dark))),
        text_color: text_muted(dark),
        border: Border {
            color: border(dark),
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}

/// Warning style used for the explicitly unsafe plain-text choice.
pub fn unsafe_button(theme: &Theme, status: button::Status) -> button::Style {
    let dark = is_dark(theme);
    let mut style = button_base(
        if dark {
            color("#7F1D1D")
        } else {
            color("#FEF3C7")
        },
        if dark {
            color("#FCA5A5")
        } else {
            color("#92400E")
        },
    );
    style.border = Border {
        color: amber(dark),
        width: 1.5,
        radius: 8.0.into(),
    };
    if matches!(status, button::Status::Hovered) {
        style.background = Some(Background::Color(if dark {
            color("#991B1B")
        } else {
            color("#FDE68A")
        }));
    }
    style
}

pub fn danger_button(theme: &Theme, status: button::Status) -> button::Style {
    let dark = is_dark(theme);
    // Keep white button text legible: a deeper red in dark mode.
    let mut style = button_base(
        if dark {
            color("#B91C1C")
        } else {
            color("#DC2626")
        },
        Color::WHITE,
    );
    if matches!(status, button::Status::Hovered) {
        style.background = Some(Background::Color(if dark {
            color("#DC2626")
        } else {
            color("#991B1B")
        }));
    }
    style
}
