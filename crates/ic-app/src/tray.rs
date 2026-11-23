//! System tray integration.
//!
//! Linux uses the KSNI (StatusNotifierItem) backend of `tray-icon`, which is
//! the native SNI protocol used by modern desktops and needs no GTK event loop.
//! Windows uses the native Win32 tray. The tray owns a small menu and a live
//! status line; all actions are forwarded to the Iced application as messages.

use std::sync::{OnceLock, mpsc};
use std::time::Duration;

use iced::futures::Stream;
use iced::futures::sink::SinkExt;
use iced::{Subscription, stream};
use tokio::sync::broadcast;
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

#[derive(Clone, Debug)]
pub enum TrayAction {
    Open,
    SyncNow,
    Quit,
}

type ActionSender = broadcast::Sender<TrayAction>;

static ACTIONS: OnceLock<ActionSender> = OnceLock::new();

fn actions() -> &'static ActionSender {
    ACTIONS.get_or_init(|| broadcast::channel(16).0)
}

/// Subscription used by the Iced application to receive tray actions.
pub fn subscription() -> Subscription<TrayAction> {
    Subscription::run(action_stream)
}

fn action_stream() -> impl Stream<Item = TrayAction> {
    stream::channel(16, async |mut output| {
        let mut receiver = actions().subscribe();
        loop {
            match receiver.recv().await {
                Ok(action) => {
                    if output.send(action).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Updates pushed from the GUI thread to the tray thread.
///
/// `MenuItem` is not `Send`, so the GUI sends plain values and the tray thread
/// applies them to the menu items it owns.
enum TrayUpdate {
    Status(String),
    SyncEnabled(bool),
}

/// Handle used by the GUI to push short status text into the tray menu and to
/// enable/disable the "Sync now" item according to the session state.
#[derive(Clone)]
pub struct TrayHandle {
    updates: mpsc::SyncSender<TrayUpdate>,
}

impl TrayHandle {
    /// Non-blocking; the GUI must never wait on the tray thread.
    pub fn set_status(&self, text: impl Into<String>) {
        let _ = self.updates.try_send(TrayUpdate::Status(text.into()));
    }

    /// Grey out (or restore) "Sync now" when there is no valid session.
    pub fn set_sync_enabled(&self, enabled: bool) {
        let _ = self.updates.try_send(TrayUpdate::SyncEnabled(enabled));
    }
}

/// Spawns the tray thread. Returns `None` only if a thread cannot be created.
/// Icon loading always falls back to a generated icon, so asset generation is
/// never a build/runtime dependency.
pub fn spawn(initial_sync_enabled: bool) -> Option<TrayHandle> {
    let (update_tx, update_rx) = mpsc::sync_channel::<TrayUpdate>(32);

    std::thread::Builder::new()
        .name("ic-sync-tray".to_string())
        .spawn(move || {
            if let Err(err) = run_tray(update_rx, initial_sync_enabled) {
                tracing::warn!("System tray unavailable: {err}");
            }
        })
        .ok()?;

    Some(TrayHandle { updates: update_tx })
}

fn run_tray(
    updates: mpsc::Receiver<TrayUpdate>,
    initial_sync_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let icon = crate::icons::load()
        .tray_icon()
        .ok_or("could not build tray icon from RGBA data")?;

    let menu = Menu::new();
    let open = MenuItem::with_id("open", "Open IC-SYNC", true, None);
    let sync = MenuItem::with_id("sync", "Sync now", initial_sync_enabled, None);
    let status = MenuItem::with_id("status", "Status: Starting…", false, None);
    let separator = PredefinedMenuItem::separator();
    let separator2 = PredefinedMenuItem::separator();
    let quit = MenuItem::with_id("quit", "Quit IC-SYNC", true, None);

    menu.append(&open)?;
    menu.append(&sync)?;
    menu.append(&separator)?;
    menu.append(&status)?;
    menu.append(&separator2)?;
    menu.append(&quit)?;

    // The left click is the "activate" action: it opens the window. On the
    // KSNI backend this setting is ignored (the status-notifier host handles
    // context menus itself and delivers left clicks as TrayIconEvent::Click);
    // on Windows/macOS it keeps the menu on the right click only.
    let _tray = tray_icon::TrayIconBuilder::new()
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .with_tooltip("IC-SYNC")
        .with_menu_on_left_click(false)
        .build()?;

    tracing::info!("System tray icon created");

    let mut sync_enabled = initial_sync_enabled;

    loop {
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            match event.id().as_ref() {
                "open" => {
                    let _ = actions().send(TrayAction::Open);
                }
                "sync" => {
                    if sync_enabled {
                        let _ = actions().send(TrayAction::SyncNow);
                    }
                }
                "quit" => {
                    let _ = actions().send(TrayAction::Quit);
                    // Give the GUI a moment to handle the quit message before
                    // the process ends and this thread is torn down.
                    std::thread::sleep(Duration::from_millis(100));
                    return Ok(());
                }
                _ => {}
            }
        }

        // Default activation (left click) opens the window. KSNI emits a
        // single Click with state Up; Windows/macOS emit Down and Up, so
        // filtering on Up avoids opening two windows per click. Right clicks
        // are owned by the SNI host / OS and keep showing the context menu.
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let _ = actions().send(TrayAction::Open);
            }
        }

        while let Ok(update) = updates.try_recv() {
            match update {
                TrayUpdate::Status(text) => status.set_text(format!("Status: {text}")),
                TrayUpdate::SyncEnabled(enabled) => {
                    sync_enabled = enabled;
                    sync.set_enabled(enabled);
                }
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}
