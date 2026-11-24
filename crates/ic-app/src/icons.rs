//! Icon loading and conversion shared by the Iced window and the system tray.
//!
//! The preferred icon is `assets/ic-sync.png` (or one of the sized variants
//! produced by the assets job).  Everything here degrades gracefully to a
//! procedurally generated icon, so this crate compiles and runs even before the
//! asset generation job has finished.
//!
//! Tray and window icons are the plain cloud asset tinted by `SyncState`:
//! green when idle, orange while working, red on error, gray when offline.

use ic_core::status::SyncState;

/// Square icon size used for both the window and the tray.
pub const ICON_SIZE: u32 = 64;

/// RGBA pixels plus dimensions, ready for either Iced or `tray-icon`.
#[derive(Clone, Debug)]
pub struct RgbaIcon {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl RgbaIcon {
    pub fn window_icon(&self) -> Option<iced::window::Icon> {
        iced::window::icon::from_rgba(self.rgba.clone(), self.width, self.height).ok()
    }

    pub fn tray_icon(&self) -> Option<tray_icon::Icon> {
        tray_icon::Icon::from_rgba(self.rgba.clone(), self.width, self.height).ok()
    }

    /// Tray icon tinted and badged for the current sync state.
    pub fn state_tray_icon(&self, state: SyncState) -> Option<tray_icon::Icon> {
        state_variant(self, state).tray_icon()
    }
}

/// Accent colour for each state, used to tint the plain cloud favicon.
fn state_color(state: SyncState) -> Option<[u8; 3]> {
    Some(match state {
        // Idle: green.
        SyncState::Synced => [46, 176, 101],
        // Working: orange.
        SyncState::Syncing | SyncState::Relocating | SyncState::LoginRequired => [240, 170, 40],
        // Error: red.
        SyncState::Error => [220, 70, 70],
        // Not syncing at all: gray.
        SyncState::Offline => [130, 140, 150],
        SyncState::Unknown => return None,
    })
}

/// Tint the plain cloud icon with the state colour. The original asset is
/// left untouched for the `Unknown` state.
fn state_variant(base: &RgbaIcon, state: SyncState) -> RgbaIcon {
    let Some(color) = state_color(state) else {
        return base.clone();
    };
    let mut rgba = base.rgba.clone();
    for pixel in rgba.as_chunks_mut::<4>().0 {
        if pixel[3] == 0 {
            continue;
        }
        pixel[0] = color[0];
        pixel[1] = color[1];
        pixel[2] = color[2];
    }
    RgbaIcon {
        rgba,
        width: base.width,
        height: base.height,
    }
}

/// Candidate locations, in priority order, for the branded icon.
fn candidate_paths() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();

    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = std::path::Path::new(&manifest);
        // crates/ic-app -> repository root
        if let Some(repo) = root.parent().and_then(|p| p.parent()) {
            paths.push(repo.join("assets/ic-sync.png"));
            paths.push(repo.join("assets/ic-sync-256.png"));
            paths.push(repo.join("assets/ic-sync-icon.png"));
        }
    }

    // Also try relative to the process working directory (installed layouts).
    paths.push(std::path::PathBuf::from("assets/ic-sync.png"));
    paths.push(std::path::PathBuf::from("ic-sync.png"));
    paths
}

/// Loads the branded icon if available, otherwise generates a clean fallback.
pub fn load() -> RgbaIcon {
    for path in candidate_paths() {
        if !path.is_file() {
            continue;
        }
        match load_file(&path) {
            Ok(icon) => {
                tracing::debug!("Using app icon from {}", path.display());
                return icon;
            }
            Err(err) => tracing::warn!("Could not read icon {}: {err}", path.display()),
        }
    }

    tracing::debug!("Using generated fallback app icon");
    generated()
}

fn load_file(path: &std::path::Path) -> Result<RgbaIcon, image::ImageError> {
    let img = image::open(path)?;
    let resized = img.resize_exact(ICON_SIZE, ICON_SIZE, image::imageops::FilterType::Lanczos3);
    let rgba = resized.to_rgba8().into_raw();
    Ok(RgbaIcon {
        rgba,
        width: ICON_SIZE,
        height: ICON_SIZE,
    })
}

/// A deterministic, dependency-free 64x64 "cloud with sync arrows" icon.
///
/// This exists purely so the tray and window always have an icon even when the
/// PNG assets have not been generated yet.
fn generated() -> RgbaIcon {
    let (w, h) = (ICON_SIZE, ICON_SIZE);
    let mut rgba = vec![0u8; (w * h * 4) as usize];

    for y in 0..h {
        for x in 0..w {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let idx = ((y * w + x) * 4) as usize;

            let color = pixel(fx, fy, w as f32);
            rgba[idx] = color[0];
            rgba[idx + 1] = color[1];
            rgba[idx + 2] = color[2];
            rgba[idx + 3] = color[3];
        }
    }

    RgbaIcon {
        rgba,
        width: w,
        height: h,
    }
}

fn pixel(x: f32, y: f32, size: f32) -> [u8; 4] {
    let c = size / 2.0;
    let dx = x - c;
    let dy = y - c;
    let radius = dx * dx + dy * dy;

    // Rounded-square background with a subtle vertical gradient.
    let half = size * 0.44;
    let corner = size * 0.16;
    let ax = dx.abs();
    let ay = dy.abs();
    let inside_roundrect = ax <= half && ay <= half
        || (ax - (half - corner)).max(0.0).powi(2) + (ay - (half - corner)).max(0.0).powi(2)
            <= corner * corner;

    if !inside_roundrect {
        return [0, 0, 0, 0];
    }

    let t = y / size;
    let bg = [
        (33.0 + 8.0 * t) as u8,
        (132.0 - 20.0 * t) as u8,
        (217.0 - 25.0 * t) as u8,
        255,
    ];

    // White circular arc, open on the lower-left, with two arrowheads.
    let ring_r2 = (size * 0.235).powi(2);
    let ring_inner = (size * 0.175).powi(2);
    let angle = dy.atan2(dx).to_degrees();
    let on_arc = radius <= ring_r2
        && radius >= ring_inner
        && (angle > -160.0 || angle < -20.0)
        && !(angle > 20.0 && angle < 160.0);

    let arrow_top = (dy + size * 0.20).abs() < size * 0.055 && dx > size * 0.12 && dx < size * 0.29;
    let arrow_bottom =
        (dy - size * 0.20).abs() < size * 0.055 && dx < -size * 0.12 && dx > -size * 0.29;

    let center_dot = radius <= (size * 0.055).powi(2);

    if on_arc || arrow_top || arrow_bottom || center_dot {
        [255, 255, 255, 255]
    } else {
        bg
    }
}
