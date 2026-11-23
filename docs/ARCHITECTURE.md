# IC-SYNC architecture contract

IC-SYNC is a standalone, compiled, cross-platform (Linux + Windows) iCloud Drive
sync application. It is **not** a fork of the Python driver and does **not** use
FUSE. Instead it synchronizes a user-selected local folder with iCloud Drive.

## Ground rules

- Pure Rust. No Python runtime, no Node, no webview.
- GUI: `iced` (native Rust widgets). System tray: `tray-icon`.
- One user-facing binary: `ic-sync`. The GUI and tray are the same process.
- Existing Apple session/cookie JSON formats from the reference project are
  readable and writable, so users do not have to reauthenticate unnecessarily.
- Credentials are never logged, committed, or embedded in assets.
- No credentials, account names, session files, or tokens belong in the repo.
- Passwords and Apple session secrets must never be stored as plaintext on disk.
  Use the OS credential store (`keyring` crate: Credential Manager on Windows,
  Secret Service / keyring on Linux). Config YAML may contain a non-secret
  account label, but the password field must be empty/placeholder and the real
  secret fetched from the keyring at runtime. A one-time migration from the
  reference plaintext config is allowed: read it, move the secret to the
  keyring, then rewrite config without the secret. If no secure store is
  available, fail with a clear actionable error rather than writing plaintext.

## Crates

### `ic-core`

Headless sync engine and persistence. Must not depend on `iced` or `tray-icon`.

Public modules and required API:

- `error::{Error, Result}` — `thiserror`-based errors with `Auth`, `TwoFactor`,
  `Http`, `Config`, `Offline`, `Conflict`, `Io`, `Other` variants.
- `paths` — XDG on Linux, `%APPDATA%`/`%LOCALAPPDATA%` on Windows:
  `config_dir()`, `config_file()`, `data_dir()`, `state_dir()`, `cache_dir()`,
  `cookie_dir()`, `log_file()`, `status_file()`, `sync_request_file()`,
  `sync_done_file()`, `default_sync_folder()`, `ensure_layout()`.
- `config` — serde `Config` with fields:
  - `username: String`
  - `password: String` (runtime-only; serialized as empty string, never plaintext on disk)
  - `credential_key: String` (stable keyring entry name, not a secret)
  - `sync_folder: PathBuf` (local folder selected by the user)
  - `cache_dir: PathBuf`
  - `cookie_dir: PathBuf`
  - `sync_paths: Vec<String>` (iCloud remote allowlist)
  - `exclude_paths: Vec<String>`
  - `auto_sync: bool` (default true)
  - `sync_interval_seconds: u64` (default 15, minimum 5) — remote metadata poll
  - `upload_interval_seconds: u64` (default 5, minimum 1) — safety-net upload sweep
  - `instant_sync: bool` (default true) — event-driven remote checks after local activity
  - `theme: ThemePreference` (`system|light|dark`, default `system`)
  - `warmup_workers: usize` (default 1)
  - `conflict_mode: ConflictMode` (`copy` only)
  - `last_sync_at: Option<i64>`
  Functions: `Config::load_defaults()`, `Config::load(path)`, `Config::write(path)`,
  `Config::validate()`, `path_allowed()`.
- `status` — serde status bridge consumed by GUI and tray:
  - `SyncState::{Synced, Syncing, LoginRequired, Offline, Error, Unknown, Relocating}`
  - `ServiceStatus` with `state`, `message`, `updated_at`, `last_sync_at`,
    `next_sync_at`, `pending`, `synced_files`, `total_files`, `current_folder`
  - `read_status()`, `write_status()`, `read_sync_progress()`, `request_sync()`,
    `consume_sync_request()`, `write_sync_done()`.
- `api` — Apple iCloud client. Reuse request shapes from the Rust reference:
  partition probe, session/cookie persistence, token login, node retrieval,
  download, folder create, delete/rename/move, multipart upload. Must expose
  `ICloudApi::new(&Config).await`, `is_authenticated()`, `requires_2fa()`,
  `is_offline()`, `offline_message()`, `session_token()`.
- `auth` — SRP-6a + 2FA. Must expose `AuthOptions { force_sms, trust_token,
  accept_terms }`, `AuthStep::{Authenticated, TwoFactorRequired { method, hint }}`,
  `authenticate(&ICloudApi, &str, &str, &AuthOptions).await`,
  `submit_code(&ICloudApi, &str, bool, bool).await`.
  Use RFC 5054 padding exactly as pyicloud does.
- `state` — SQLite contract compatible with the reference schema:
  `entries`, `pending_ops`, `sync_state`. `pending_ops.retry_count INTEGER NOT NULL
  DEFAULT 0`. Conflict copies use `<name>.local-conflict-<YYYYMMDDHHMMSS>`.
- `mirror` — ordinary local folder operations (not FUSE): safe path joining,
  placeholders, atomics, sha256, rename subtrees.
- `engine` — `SyncEngine`:
  - `SyncEngine::new(api: Arc<ICloudApi>, config: Config).await -> Result<Self>`
  - `start()` background loops: remote crawl, local watcher, dirty upload,
    hydration, scheduler, status publisher.
  - `request_remote_sync()` — synchronous wake for an event-driven remote crawl.
    Local file changes and successful uploads must call this (debounced ~1s) so
    changes are detected right away instead of waiting for the full interval.
    The remote loop must wake on this signal *and* on the configured interval.
  - `sync_once()` full remote crawl + local reconcile.
  - `status() -> ServiceStatus`
  - `pending_count()`, `entry_count()`, `unhydrated_count()`
  - `relocate_folder(new_folder: PathBuf) -> Result<RelocationReport>`:
    if status is `Synced` and no dirty/pending entries, physically move the
    selected folder contents to the new folder and update config atomically;
    otherwise return a `Conflict`/`NotClean` error so the GUI can warn and defer
    until the next clean sync.
  - `shutdown()` for graceful stop.
- `relocation` — `RelocationReport { from, to, moved_files, skipped }` plus helpers
  for atomic folder swap and config rewrite.

### `ic-app`

Iced GUI + tray. Depends on `ic-core`.

- `main.rs` — process bootstrap, tracing, tray thread, app subscription.
- `ui/mod.rs` — Iced `Application` implementation with pages:
  - **Setup / Sign in**: Apple ID, password, trust token, force SMS, accept terms,
    2FA code entry, sign-in progress.
  - **Dashboard**: state badge, last sync time, next sync time, pending count,
    synced/total files, current folder, Force sync, Pause/Resume auto-sync,
    Open folder, Sign out/Forget session.
  - **Settings**: choose sync folder with native folder picker, remote allow/deny
    paths, theme preference (System/Light/Dark), Instant sync toggle, sync
    interval presets, conflict handling, relocation rules, save.
  - **Activity**: structured event log and status history.
  - **About**: version, links, license.
- `tray.rs` — `tray-icon` SNI on Linux / native tray on Windows. Menu items:
  Open IC-SYNC, Sync now, Status text, Quit. Icon comes from `assets/`.
- `worker.rs` — async bridge from Iced to `ic-core`; never block the UI thread.
- `icons.rs` — embeds tray/window icons via `image` and iced's icon type.

When the user changes the sync folder: call `SyncEngine::relocate_folder()`.
If it succeeds, show a success toast with the number of moved files. If it fails
because files are not clean, show a clear warning and offer "Sync now, then move".

## Data safety

- Never delete remote data without an explicit local tombstone.
- Dirty local files with changed remote etags must produce conflict copies.
- Session/cookie files are compatibility assets and must stay outside the repo.
- Relocation must be atomic where the OS permits; otherwise copy-then-swap with a
  rollback path.
