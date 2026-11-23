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

    let icon = icons::load().window_icon();
    let window = iced::window::Settings {
        size: iced::Size {
            width: 1060.0,
            height: 760.0,
        },
        min_size: Some(iced::Size {
            width: 780.0,
            height: 580.0,
        }),
        // The tray thread is already running when Iced boots. A hidden initial
        // window still receives `window::latest()`, so "Open IC-SYNC" can show
        // and focus it later via `window::set_mode(Windowed)`.
        visible: !start_minimized(),
        icon,
        ..Default::default()
    };

    iced::application(ui::new, App::update, App::view)
        .exit_on_close_request(false)
        .title(ui::title)
        .theme(ui::theme)
        .subscription(ui::subscription)
        .window(window)
        .run()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("ic_app=info,ic_core=info,warn"));

    // Logging to stderr keeps credentials out of files by construction. The
    // core crate configures its own rotating log for engine diagnostics.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
