//! IC-SYNC process bootstrap: tracing, Tokio runtime, tray, Iced application.

mod icons;
mod secrets;
mod tray;
mod ui;
mod worker;

use tracing_subscriber::EnvFilter;
use ui::App;

/// Read the persisted startup preference before the window is created.
///
/// Missing or unreadable config keeps the safe default (start minimized).
fn start_minimized() -> bool {
    // Autostart entries launch us with `--minimized`.
    if std::env::args().any(|arg| arg == "--minimized") {
        return true;
    }
    let Ok(path) = ic_core::paths::config_file() else {
        return true;
    };
    match ic_core::Config::load(&path) {
        Ok(config) => config.start_minimized,
        Err(err) => {
            tracing::warn!("Could not read startup preference: {err}");
            true
        }
    }
}

fn main() -> iced::Result {
    init_tracing();

    // ic-core's authentication futures hold a thread-local RNG across awaits
    // and are therefore not `Send`. Drive the worker on a dedicated current-
    // thread Tokio runtime so every core call happens there, never on the Iced
    // UI thread. The thread stays alive for the lifetime of the process.
    let _commands = worker::start_channel();
    std::thread::Builder::new()
        .name("ic-sync-core".to_string())
        .spawn(worker::run_on_current_thread)
        .expect("failed to spawn Tokio runtime thread");
    tracing::info!("Core worker started");

    // IC-SYNC runs as a daemon with no initial window. On Wayland, winit cannot
    // hide a window (`set_visible` is a no-op) and compositors such as Hyprland
    // may ignore `xdg_toplevel.set_minimized`. Creating no window at startup is
    // the only reliable way to stay alive in the tray; the GUI opens a window
    // when the tray asks for one, and destroys just that window on close.
    iced::daemon(ui::new, App::update, daemon_view)
        .title(daemon_title)
        .theme(daemon_theme)
        .subscription(ui::subscription)
        .run()
}

fn daemon_view<'a>(app: &'a App, window: iced::window::Id) -> iced::Element<'a, ui::Message> {
    ui::view_for(app, window)
}

fn daemon_title(app: &App, window: iced::window::Id) -> String {
    ui::title_for(app, window)
}

fn daemon_theme(app: &App, _window: iced::window::Id) -> iced::Theme {
    ui::theme(app)
}

pub(crate) fn window_settings() -> iced::window::Settings {
    iced::window::Settings {
        size: iced::Size {
            width: 1060.0,
            height: 760.0,
        },
        min_size: Some(iced::Size {
            width: 780.0,
            height: 580.0,
        }),
        icon: icons::load().window_icon(),
        ..Default::default()
    }
}

/// Compact, always-on-top window used only for the 2FA code challenge. It is
/// independent of the main window so a code prompt is never hidden behind it.
pub(crate) fn two_factor_window_settings() -> iced::window::Settings {
    iced::window::Settings {
        size: iced::Size {
            width: 470.0,
            height: 460.0,
        },
        min_size: Some(iced::Size {
            width: 400.0,
            height: 360.0,
        }),
        resizable: false,
        level: iced::window::Level::AlwaysOnTop,
        icon: icons::load().window_icon(),
        ..Default::default()
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "warn,wgpu_hal=error,wgpu_core=error,iced_wgpu=error,iced_winit=error,ic_app=info,ic_core=info",
        )
    });

    // Logging to stderr keeps credentials out of files by construction. The
    // core crate configures its own rotating log for engine diagnostics.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
