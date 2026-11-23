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

/// Handle used by the GUI to push short status text into the tray menu.
#[derive(Clone)]
pub struct TrayHandle {
    status_tx: mpsc::SyncSender<String>,
}

impl TrayHandle {
    /// Non-blocking; the GUI must never wait on the tray thread.
    pub fn set_status(&self, text: impl Into<String>) {
        let _ = self.status_tx.try_send(text.into());
    }
}

/// Spawns the tray thread. Returns `None` only if a thread cannot be created.
/// Icon loading always falls back to a generated icon, so asset generation is
/// never a build/runtime dependency.
pub fn spawn() -> Option<TrayHandle> {
    let (status_tx, status_rx) = mpsc::sync_channel::<String>(32);

    std::thread::Builder::new()
        .name("ic-sync-tray".to_string())
        .spawn(move || {
            if let Err(err) = run_tray(status_rx) {
                tracing::warn!("System tray unavailable: {err}");
            }
        })
        .ok()?;

    Some(TrayHandle { status_tx })
}

fn run_tray(status_rx: mpsc::Receiver<String>) -> Result<(), Box<dyn std::error::Error>> {
    let icon = crate::icons::load()
        .tray_icon()
        .ok_or("could not build tray icon from RGBA data")?;

    let menu = Menu::new();
    let open = MenuItem::with_id("open", "Open IC-SYNC", true, None);
    let sync = MenuItem::with_id("sync", "Sync now", true, None);
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

    let _tray = tray_icon::TrayIconBuilder::new()
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .with_tooltip("IC-SYNC")
        .build()?;

    tracing::info!("System tray icon created");

    loop {
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            match event.id().as_ref() {
                "open" => {
                    let _ = actions().send(TrayAction::Open);
                }
                "sync" => {
                    let _ = actions().send(TrayAction::SyncNow);
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

        while let Ok(text) = status_rx.try_recv() {
            status.set_text(format!("Status: {text}"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}
