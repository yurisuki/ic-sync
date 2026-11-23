# IC-SYNC User Guide

IC-SYNC synchronizes an ordinary folder on your computer with iCloud Drive. It
runs as a native desktop application with a system-tray applet. This guide
covers installation, signing in, choosing a sync folder, understanding sync
status, and recovering from common problems.

> **Privacy note:** by default (secure credential mode), your Apple ID password
> and session secrets are stored in your operating system's credential store,
> not in plaintext files. The explicit **UNSAFE plain mode** opt-in stores the
> password in a local config file instead — see
> [Credential mode](#credential-mode-secure-vs-plain). Never paste credentials,
> session cookies/tokens or 2FA trust tokens into a GitHub issue, a log file
> shared with someone else, or any file you intend to commit.

---

## 1. Install

### Linux

Download `ic-sync-linux-x86_64.tar.gz` (or `-aarch64` for ARM) from the
[Releases page](https://github.com/yurisuki/ic-sync/releases), then:

```sh
tar -xzf ic-sync-linux-x86_64.tar.gz
cd ic-sync-linux-x86_64
./ic-sync
```

A graphical session (X11 or Wayland) and a D-Bus session bus are required for
the window and tray icon. The archive also contains this guide and the icon
assets.

### Windows

Download `ic-sync-windows-x86_64.zip`, extract it, and run `ic-sync.exe`.

If SmartScreen warns about an unsigned executable, verify the download came
from the official Releases page before choosing to run it.

### From source

See the [README](../README.md#build-from-source). You need Rust 1.90+ and the
Linux GUI development packages listed there. Build with:

```sh
cargo build --workspace --release
```

## 2. First launch

On first launch IC-SYNC opens the **Setup / Sign in** page. If a compatible
session from the reference project is already present in the local cookie
directory, IC-SYNC will reuse it and skip sign-in.

**Secure credential storage is the default and recommended mode**
(`credential_mode: secure`). IC-SYNC stores your Apple ID password and session
secrets in the OS credential store — Windows Credential Manager on Windows, or
the Secret Service/keyring on Linux. On Linux you need a running keyring
provider (for example GNOME Keyring or KDE Wallet) and a D-Bus session bus. If
no secure store is available, IC-SYNC shows a clear error and will **not**
silently fall back to writing your password in plaintext. An explicit
**UNSAFE `plain` mode** opt-in exists (see
[Credential mode](#credential-mode-secure-vs-plain)), but it is **not
recommended**.

In secure mode, if IC-SYNC detects an older **plaintext config** from the
reference project, it performs a one-time migration: it reads the secret, saves
it to the OS credential store, then rewrites the config without the plaintext
and removes the old secret from disk. You may be asked to sign in again if the
migrated secret is invalid.

1. Enter your **Apple ID** (email) and **password**.
2. Optionally check **Accept terms** if this account has not accepted Apple's
   current iCloud terms.
3. Optionally check **Force SMS** if you want a text message code even when a
   trusted device is available.
4. Click **Sign in**. Trust tokens are handled automatically; there is no
   manual trust-token field in the normal sign-in flow.

## 3. Two-factor authentication (2FA)

Most Apple IDs require 2FA. After the password step, the **2FA code** field
appears.

- **Trusted device:** choose this when one of your devices can display a
  6-digit code; enter the code shown there.
- **SMS / voice:** choose **Force SMS** (or select SMS when prompted) and enter
  the code sent to your trusted phone number. Voice calls are available for
  some regions/carriers.
- **Trust token:** IC-SYNC obtains and stores the trust token automatically
  after a successful sign-in and reuses it on future sign-ins, so there is
  nothing to copy or paste in the normal flow. You may still be asked for a
  code occasionally. Accounts that use security keys may need advanced
  handling outside the standard sign-in UI.

Codes are short-lived. If a code is rejected, wait for a fresh one rather than
reusing an expired code. Entering the wrong code repeatedly can cause Apple to
temporarily throttle login attempts — see
[Troubleshooting](#9-troubleshooting).

> IC-SYNC never sends your credentials anywhere except Apple's own endpoints,
> and never logs them.

## 4. Choosing (or changing) the sync folder

Open **Settings → Sync folder** and use the native folder picker to choose a
local directory. This folder is where iCloud Drive files are mirrored as
**real files**, not placeholders backed by a virtual filesystem.

- Pick a folder you own and can write to. Avoid the repository checkout and
  system directories.
- You may set **remote allow/deny paths** to limit which iCloud Drive folders
  are synchronized (for example, sync only `Notes` but skip `Photos`).
- **Sync timing:** remote poll interval presets and Instant sync are described
  in [Instant sync and poll intervals](#instant-sync-and-poll-intervals).
- **Theme:** choose System (follows your desktop), Light or Dark — see
  [Theme preference](#theme-preference).
- **Start minimized to tray:** on by default — see
  [Start minimized to tray](#start-minimized-to-tray).
- **Auto-sync** is on by default; you can pause/resume it from the Dashboard.
- **Credential mode:** secure (default) or the **UNSAFE** plain opt-in — see
  [Credential mode](#credential-mode-secure-vs-plain).

### Theme preference

In **Settings → Theme**, choose **System** (the default), **Light**, or
**Dark**. **System** follows your desktop's light/dark appearance automatically.
Your choice is saved in the configuration and restored on the next launch.

### Start minimized to tray

In **Settings → Start minimized to tray** (on by default), IC-SYNC launches with
only its tray icon and no main window, and the preference is saved in the
configuration. Syncing is already running in that state; choose **Open IC-SYNC**
in the tray menu to restore and focus the window.

This is the same as **closing** the window: the app stays in the tray and keeps
syncing. It is not the same as **Quit**, which exits the app — see
[Tray menu](#7-tray-menu).

### Instant sync and poll intervals

**Instant sync** (on by default) uses a filesystem watcher to upload local
edits as soon as they are saved. Successful local activity also triggers a
debounced remote check (about one second later), so changes made on other
devices are noticed right away instead of waiting for the next full poll.

The **remote poll interval** controls how often IC-SYNC checks iCloud Drive for
remote changes when there is no local activity. Choose a preset in Settings:

| Preset | Remote poll interval |
| --- | --- |
| **Instant** | 5s |
| **Fast** (default) | 15s |
| **Balanced** | 30s |
| **Relaxed** | 60s |

A separate **safety-net upload sweep** runs every 5s by default to catch local
changes the watcher might miss.

**Tradeoff:** shorter intervals and instant checks make syncing feel immediate,
but they increase the number of requests made to Apple's iCloud APIs.
**Relaxed** is the gentlest option if you want to minimize API traffic and
network/battery use.

### Relocation behavior (all files synced)

When the folder is **fully synced and clean** (state `Synced`, no pending or
dirty entries), changing the folder performs an atomic relocation:

1. IC-SYNC physically moves the existing folder contents into the new folder.
2. The configuration is updated atomically to point at the new location.
3. A success toast reports how many files were moved.

If anything is **not clean** — a sync in progress, pending uploads, or dirty
local files — relocation is refused with a clear **"files are not clean"**
warning. IC-SYNC will not move a partially synced folder. Use the offered
**"Sync now, then move"** action: run a full sync, wait for the Dashboard to
show `Synced` with zero pending files, then repeat the folder change.

## 5. Understanding sync times and progress

The **Dashboard** and the **tray menu** show the same status bridge:

| Field | Meaning |
| --- | --- |
| **State** | One of `Synced`, `Syncing`, `LoginRequired`, `Offline`, `Error`, `Relocating`, or `Unknown`. |
| **Last sync** | When the last full remote crawl/reconcile completed (`last_sync_at`). |
| **Next sync** | When the scheduler plans to run the next full sync (`next_sync_at`). Pausing auto-sync stops this countdown. |
| **Pending** | Number of local changes queued for upload or remote changes queued for download. |
| **Files** | `synced_files / total_files` observed in the current sync path. |
| **Current folder** | The local sync folder in use. |
| **Per-file progress** | During a run, the Activity page and status progress show which file is currently transferring and how far along it is. |

Times are displayed in your local timezone. **Force sync** starts a full crawl
immediately, regardless of the schedule. With Instant sync enabled, local
activity can trigger an early remote check, so **Next sync** may come sooner
than the configured interval.

## 6. Conflict copies

IC-SYNC prefers to preserve data rather than overwrite it. If you edit a local
file while the same file changed remotely, IC-SYNC keeps both:

- the remote version becomes the synced file, and
- your local version is saved alongside it as
  `<name>.local-conflict-<YYYYMMDDHHMMSS>`, where the timestamp is the moment
  the conflict was detected (for example, `Report.local-conflict-20260301143022.docx`).

Conflict handling is `copy` only. Look for `*.local-conflict-*` files in the
affected folder and merge their contents manually when convenient. These files
are ordinary files and are not deleted automatically.

IC-SYNC also follows the data-safety rule of **never deleting remote data
without an explicit local tombstone**.

## 7. Tray menu

The tray applet is always available while IC-SYNC is running:

- **Open IC-SYNC** — restore and focus the main window, including when the app
  started minimized to the tray.
- **Sync now** — request an immediate full sync (same as Force sync).
- **Status text** — a read-only line showing the current state and a short
  message, plus last/next sync details where space allows.
- **Quit** — exit IC-SYNC completely: gracefully shut down the sync engine and
  the GUI. Syncing stops.

**Close, Start minimized and Quit are different things:**

- **Close** (the window's X button) only hides the main window to the tray;
  IC-SYNC keeps syncing in the background.
- **Start minimized to tray** (Settings, on by default) launches IC-SYNC in that
  same hidden state with syncing already running.
- **Quit** (tray menu) exits completely and stops syncing. To get the window
  back without quitting, choose **Open IC-SYNC** from the tray.

On Linux the tray uses the Status Notifier Item (SNI) protocol; your desktop
environment must support it (GNOME needs an extension such as AppIndicator,
KDE Plasma and most other desktops support it natively). On Windows it uses the
native system tray.

## 8. Offline and login-required states

- **`Offline`** — the network or Apple's service is unreachable. IC-SYNC keeps
  queuing local changes and retries automatically. Local edits are never
  discarded. The Activity log records the offline message returned by the API.
- **`LoginRequired`** — the saved session expired or was revoked. Open the
  **Setup / Sign in** page and sign in again (2FA may be requested). Queued
  local changes remain intact.
- **`Error`** — a specific failure (for example, a permissions problem or a
  malformed config). Open **Activity** for the structured event that caused it.
- **`Relocating`** — a folder move is in progress. Avoid editing files in the
  sync folder until it completes.

When connectivity or authentication returns, IC-SYNC resumes the pending work
automatically; there is no need to restart the app.

## 9. Troubleshooting

**Sign-in fails with a 2FA error**
- Generate a fresh code; codes expire quickly.
- If you selected a trusted device but have none available, enable **Force SMS**.
- Repeated failures can trigger Apple's rate limiting. Wait a while before
  retrying, and do not repeatedly restart the app.

**Status stuck at `LoginRequired`**
- Sign out / **Forget session**, then sign in again.
- Confirm your Apple ID password is current and that 2FA is working.
- Verify your system clock; large time drift breaks token validation.

**Status stuck at `Offline`**
- Check network connectivity and any proxy/firewall blocking Apple endpoints.
- Confirm DNS resolution and that `*.icloud.com` hosts are reachable.

**Tray icon does not appear (Linux)**
- Ensure a D-Bus session bus is running and your desktop supports SNI (see
  [Tray menu](#7-tray-menu)).
- The main window still works; use it to sync and check status.

**Files are not appearing locally**
- Check the remote allow/deny paths in Settings — you may be filtering them out.
- Check the sync folder path is correct and writable.
- Run **Force sync** and watch the Activity page for per-file errors.

**Relocation refused ("files are not clean")**
- Wait for `Synced` with zero pending files, then retry. See
  [Relocation behavior](#relocation-behavior-all-files-synced).

**Where are logs and state?**
- Logs and local state are in the platform directories described in the
  [README](../README.md#where-files-live). When sharing a log, redact your
  Apple ID, file names you consider sensitive, and any tokens/cookies.

**"No secure credential store available"**
- In the default `secure` mode, IC-SYNC requires the OS credential store and
  deliberately refuses to save secrets in plaintext. On Linux, start your
  keyring provider (GNOME Keyring, KDE Wallet or another Secret Service
  implementation) and ensure a D-Bus session bus is running. On Windows, make
  sure Credential Manager is available. Fix the store, then restart IC-SYNC and
  sign in again.
- The **UNSAFE `plain`** opt-in avoids this requirement by storing your password
  in a local config file, but it is **not recommended**: any process or user
  with read access to that file can read your password.

**Credential safety**
- If you suspect a credential was exposed: use **Sign out / Forget session**
  (which removes the stored credential — the keyring entry, or the password in
  the plain-mode config), rotate your Apple ID password, and check that no
  session/config file was committed to Git. Never attach session/cookie JSON to
  an issue.

## 10. Credentials, config files and Git

### Credential mode (secure vs. plain)

IC-SYNC has two credential modes, selected in **Settings → Credential mode**:

- **`secure` (default, recommended):** your Apple ID password and session
  secrets are stored in the OS credential store (Windows Credential Manager on
  Windows, Secret Service/keyring on Linux). The config file holds only
  non-secret settings; its password field is empty/placeholder.
- **`plain` — ⚠️ UNSAFE / NOT RECOMMENDED:** an explicit opt-in only. Your Apple
  ID **password is stored in a local config file** instead of the OS credential
  store, so **any process or user with read access to that file can obtain your
  password**. The app displays a prominent **UNSAFE** warning when plain mode
  is selected. Choose it only if you understand and accept this risk; IC-SYNC
  never switches to plain mode automatically.

| Item | Where it lives |
| --- | --- |
| Apple ID password | `secure` (default): OS credential store (Windows Credential Manager / Linux Secret Service keyring) · `plain` (UNSAFE): local config file |
| Session secrets and automatically managed 2FA trust token | OS credential store |
| Account label, sync folder, paths, intervals, theme, credential mode | Config YAML (non-secret settings only in `secure` mode) |
| Config password field | Empty/placeholder in `secure` mode; contains the password in `plain` (UNSAFE) mode |
| Session/cookie compatibility JSON | Local application data directory, outside the repo |

- **Never commit** `config.yaml`, `icloud.env`, `*.session`, `*.cookiejar`,
  `*.cookies`, `token*.json`, `credentials.*` or similar files. The repository's
  `.gitignore` covers these patterns as a safety net, but it cannot catch every
  renamed file — review `git status` before every commit. In **plain mode the
  config file contains your password**, so this matters even more.
- **Never add test-account credentials, Apple IDs or tokens to the repository**,
  including in issues, logs, screenshots or documentation. Use throwaway,
  non-sensitive test data only, and keep it outside the repo.
- Sharing logs? Redact account identifiers and any tokens/cookies first.
