<p align="center">
  <img src="assets/ic-sync.svg" alt="IC-SYNC" width="112" height="112">
</p>

<h1 align="center">IC-SYNC</h1>

<p align="center">
  <strong>A small, standalone iCloud Drive sync app for your desktop.</strong><br>
  Native Rust. Native GUI. One ordinary folder. Linux and Windows.
</p>

---

## What IC-SYNC is

IC-SYNC keeps a **user-selected local folder** in sync with iCloud Drive. It is a
**standalone, compiled Rust application** that ships as a single binary named
`ic-sync`. The GUI and the system-tray applet are the same process.

- **Cross-platform:** Linux (x86_64 and aarch64) and Windows (x86_64).
- **Native UI:** built with [`iced`](https://github.com/iced-rs/iced) — real
  native widgets, rendered by the OS-facing windowing stack.
- **Native tray:** built with
  [`tray-icon`](https://github.com/tauri-apps/tray-icon) — an SNI/status-notifier
  applet on Linux and a native tray icon on Windows.
- **Ordinary folder sync:** your files live in a normal directory you choose.
  You can open it in a file manager, back it up, or search it with your usual
  tools.
- **Pure Rust:** no Python runtime, no Node.js, no Electron, no webview, no
  bundled browser, and no FUSE mount or kernel driver.

## What IC-SYNC is not

- It is **not** a fork of any Python iCloud driver.
- It does **not** mount iCloud Drive as a virtual filesystem (no FUSE).
- It does **not** run a web server or require a browser.
- It does **not** ship credentials, sessions, or test-account data of any kind.

## Features

- Sign in with an Apple ID, including 2FA by SMS, voice call or trusted device.
  Trust tokens are handled automatically — no manual entry in the normal flow.
- **Secure credential storage by default** — with `credential_mode: secure` (the
  default), password and session secrets go to Windows Credential Manager or the
  Linux Secret Service/keyring, never to a config file. An explicit `plain`
  opt-in exists but is **UNSAFE / NOT RECOMMENDED**: it stores the password in a
  local config file (see [Security and privacy](#security-and-privacy)).
- Incremental two-way sync with local and remote change detection.
- **Instant sync:** local edits are uploaded immediately by the filesystem
  watcher, and successful local activity triggers a debounced remote check so
  changes made on other devices are noticed right away.
- Configurable remote allow/deny paths and remote poll interval presets
  (5s Instant, 15s Fast (default), 30s Balanced, 60s Relaxed), plus a 5s
  safety-net upload sweep and auto-sync. Shorter intervals and instant checks
  are more responsive but make more Apple API requests; Relaxed is gentlest.
- Theme preference: **System** (follows your desktop), **Light** or **Dark**,
  saved in the config.
- **Start minimized to tray** (on by default): launch with only the tray icon;
  closing the window (X) also just hides to the tray while syncing continues.
  **Quit** in the tray menu exits completely.
- Conflict copies instead of silent data loss: a locally edited file whose
  remote counterpart changed is preserved as
  `<name>.local-conflict-<YYYYMMDDHHMMSS>`.
- Status dashboard with last/next sync times, pending count and per-file
  progress, mirrored in the tray menu.
- Safe folder relocation when the folder is fully synced and clean.
- Structured activity log for diagnosing sync problems.

## Quick start

### Install a prebuilt release

1. Download the archive for your platform from the
   [Releases page](https://github.com/yurisuki/ic-sync/releases).
2. Extract it:

   ```sh
   # Linux (x86_64 shown; use the aarch64 archive for ARM)
   tar -xzf ic-sync-linux-x86_64.tar.gz
   cd ic-sync-linux-x86_64
   ./ic-sync
   ```

   ```powershell
   # Windows (PowerShell) - the zip contains a top-level folder
   Expand-Archive .\ic-sync-windows-x86_64.zip -DestinationPath .
   cd .\ic-sync-windows-x86_64
   .\ic-sync.exe
   ```

3. On first launch, sign in with your Apple ID and choose the local folder to
   sync. **Start minimized to tray** is on by default, so IC-SYNC can launch
   hidden in the tray — choose **Open IC-SYNC** from the tray menu to show the
   window. See the [User Guide](docs/USER_GUIDE.md) for the full walkthrough.

### Build from source

Requirements:

- Rust **1.90 or newer** (required by the pinned `iced` 0.14, `tray-icon` 0.26
  and `keyring` 4 versions; the workspace uses edition 2024).
- Platform build dependencies; see [Linux build dependencies](#linux-build-dependencies).

```sh
git clone https://github.com/yurisuki/ic-sync.git
cd ic-sync

# Check the whole workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Build the release binary
cargo build --workspace --release
```

The runnable binary is produced at `target/release/ic-sync`
(`target/release/ic-sync.exe` on Windows).

#### Linux build dependencies

On Debian/Ubuntu, the GUI and tray stack need the X11/Wayland and D-Bus
development headers:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  pkg-config libssl-dev libxkbcommon-dev libwayland-dev \
  libx11-dev libxrandr-dev libxi-dev libxcursor-dev libxinerama-dev \
  libgl1-mesa-dev libudev-dev libdbus-1-dev libgtk-3-dev \
  libayatana-appindicator3-dev
```

At runtime you need a graphical session (X11 or Wayland) and a D-Bus session
bus for the tray icon. On Linux you also need a running Secret Service–compatible
keyring (for example GNOME Keyring or KDE Wallet) so IC-SYNC can store secrets;
on Windows the built-in Credential Manager is used. Headless servers can still
run the sync engine tests.

## Where files live

IC-SYNC follows platform conventions and keeps all state outside the source
tree:

- **Linux:** XDG directories — roughly `~/.config/ic-sync`,
  `~/.local/share/ic-sync`, `~/.local/state/ic-sync` and `~/.cache/ic-sync`.
- **Windows:** `%APPDATA%\ic-sync` and `%LOCALAPPDATA%\ic-sync`.

These directories hold the configuration, session/cookie compatibility files,
the local state database, logs and the status bridge used by the GUI and tray.
In the default **secure** credential mode, the config YAML contains **only
non-secret settings** — the password field is empty/placeholder and the real
secret lives in the OS credential store. If you explicitly opt into the
**UNSAFE plain mode**, the password is stored in a local config file instead
(see [Security and privacy](#security-and-privacy)). Your synced files live in
the folder **you** pick in Settings — never inside the application directories.

## Security and privacy

> **By default secrets stay in your OS keyring. Never commit credentials,
> config or session files.**

- In the default **`secure` credential mode**, your Apple ID **password** and
  Apple **session secrets** (including the automatically managed 2FA trust
  token) are stored in the **OS credential store** via the `keyring` crate:
  **Windows Credential Manager** on Windows and **Secret Service / keyring** on
  Linux. They are encrypted and managed by the OS; they are never written to
  the config file.
- In `secure` mode the **config YAML contains only non-secret settings**
  (account label, sync folder, paths, intervals, theme, etc.). Its password
  field is intentionally empty; the real secret is fetched from the keyring at
  runtime. A stable, non-secret `credential_key` identifies the keyring entry.
- **⚠️ UNSAFE / NOT RECOMMENDED — `credential_mode: plain`:** this is an
  explicit opt-in for users who understand the risk. In plain mode your Apple
  ID **password is stored in a local config file** instead of the OS credential
  store, so **any process or user with read access to that file can obtain your
  password**. The app shows a prominent **UNSAFE** warning when plain mode is
  selected. Secure mode remains the default; plain mode is never chosen
  automatically.
- **One-time migration:** if IC-SYNC finds an older plaintext configuration
  from the reference project, it reads the secret once, moves it into the OS
  credential store, and rewrites the config **without** the plaintext. After
  migration the plaintext is removed from disk.
- **No insecure fallback:** in `secure` mode, if no secure credential store is
  available, IC-SYNC fails with a clear, actionable error. It will **not**
  silently fall back to writing credentials in plaintext; plain mode must be
  selected deliberately.
- Credentials and sessions are **never logged**, never embedded in the binary,
  never placed in `assets/`, and never included in a release archive.
- **Never commit session/cookie/config files.** `.gitignore` excludes common
  credential/session filenames (`*.session`, `*.cookiejar`, `config.yaml`,
  `icloud.env`, `*.pem`, and others) as a safety net — but it cannot catch every
  renamed file. **Always review `git status` and your diff before committing.**
  No account names, Apple IDs, cookies, tokens or **test-account credentials**
  belong in this repository, in issues, or in documentation.
- If credentials may have been exposed, use **Sign out / Forget session** in
  the app (which removes the keyring entry, or the stored password in plain
  mode) and rotate your Apple ID password.

## Documentation

- [User Guide](docs/USER_GUIDE.md) — install, sign-in, sync folder, tray,
  troubleshooting.
- [Release process](docs/RELEASE.md) — CI policy, artifacts and how a release
  is cut.
- [Architecture contract](docs/ARCHITECTURE.md) — crate layout and internal
  API contract.
- [Assets](assets/README.md) — icon sources and regeneration commands.

## License

MIT — see [LICENSE](LICENSE) and the package metadata in [Cargo.toml](Cargo.toml).
