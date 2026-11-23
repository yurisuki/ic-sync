//! Configuration, path rules and OS credential-store access.
//!
//! Security contract: by default (`credential_mode: secure`) `password` is a
//! *runtime-only* field. `Config::load` clears it immediately and
//! [`Config::write`] always writes `password: ""`. Secrets live in the platform
//! credential store (Windows Credential Manager, Linux Secret Service) and are
//! fetched with `hydrate_secrets()` / `load_with_secrets()`.
//!
//! `credential_mode: plain` is an explicit, unsafe opt-in for machines with no
//! credential store: the password is kept in the local YAML (still written with
//! 0600 permissions) and session/trust tokens stay in the local compatibility
//! files. It is never the default; see [`plain_storage_warning`].

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use keyring::Entry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::paths;

/// Stable service name used for every keyring entry.
pub const KEYRING_SERVICE: &str = "ic-sync";
/// Files containing session material are created with 0600 on Unix.
pub const SECRET_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictMode {
    Copy,
}

/// User preference for the application colour theme. Serialized as lowercase
/// `system|light|dark`; configs written before this field existed fall back to
/// `system` through `#[serde(default)]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

/// Where the Apple ID password and session secrets are stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialMode {
    /// OS credential store (Windows Credential Manager / Linux Secret Service).
    /// The default; no secret is written to the config YAML.
    #[default]
    Secure,
    /// Explicit opt-in: the password is stored in the local config YAML and
    /// tokens remain in local session/cookie files. Unsafe; never the default.
    Plain,
}

impl CredentialMode {
    pub fn is_secure(self) -> bool {
        matches!(self, Self::Secure)
    }

    pub fn is_plain(self) -> bool {
        matches!(self, Self::Plain)
    }
}

/// Human-readable risk notice for the GUI whenever plain storage is selected
/// or offered. Kept as a function so every caller shows the same wording.
pub fn plain_storage_warning() -> &'static str {
    "Plain credential storage is unsafe: your Apple ID password and iCloud session/trust \
     tokens are kept in unencrypted local files (still restricted to your user account). \
     Anyone who can read your user files or a backup can reuse them. Use Secure storage \
     (OS keyring) unless you have no keyring and explicitly accept this risk."
}

/// Whether credentials can be stored under the selected mode right now.
/// Plain mode needs no OS keyring, so it is always "ready" (but unsafe).
pub fn credential_storage_ready(mode: CredentialMode) -> bool {
    mode.is_plain() || secure_storage_available()
}

/// Which Apple secret a keyring entry holds. The stable account name is
/// `"<credential_key>:<suffix>"` under [`KEYRING_SERVICE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    SessionToken,
    TrustToken,
}

impl SecretKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::SessionToken => "session-token",
            Self::TrustToken => "trust-token",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Apple ID (non-secret account label).
    pub username: String,
    /// Password. Empty on disk and after `Config::load` in `secure` mode;
    /// persisted in this YAML only in the explicit `plain` mode.
    #[serde(
        default,
        deserialize_with = "deserialize_password",
        serialize_with = "serialize_password"
    )]
    pub password: String,
    /// Credential storage backend. Defaults to `secure` for older configs.
    #[serde(default)]
    pub credential_mode: CredentialMode,
    /// Stable keyring account name (not a secret). Derived from `username` when empty.
    #[serde(default)]
    pub credential_key: String,
    #[serde(default = "default_sync_folder")]
    pub sync_folder: PathBuf,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_cookie_dir")]
    pub cookie_dir: PathBuf,
    #[serde(default)]
    pub sync_paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_sync: bool,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_seconds: u64,
    #[serde(default = "default_upload_interval")]
    pub upload_interval_seconds: u64,
    /// React to local file events with an immediate remote check instead of
    /// waiting for `sync_interval_seconds`.
    #[serde(default = "default_true")]
    pub instant_sync: bool,
    #[serde(default)]
    pub theme: ThemePreference,
    /// When true the GUI starts hidden in the system tray; when false the main
    /// window is shown on launch. Core only persists the preference.
    #[serde(default = "default_true")]
    pub start_minimized: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_warmup_workers")]
    pub warmup_workers: usize,
    #[serde(default = "default_conflict_mode")]
    pub conflict_mode: ConflictMode,
    #[serde(default)]
    pub last_sync_at: Option<i64>,
    /// Path this config was loaded from; used by folder relocation. Not serialized.
    #[serde(skip)]
    config_path: Option<PathBuf>,
}

fn default_sync_folder() -> PathBuf {
    paths::default_sync_folder().unwrap_or_else(|_| PathBuf::from("iCloudDrive"))
}
fn default_cache_dir() -> PathBuf {
    paths::cache_dir().unwrap_or_else(|_| PathBuf::from(".cache/ic-sync"))
}
fn default_cookie_dir() -> PathBuf {
    paths::cookie_dir().unwrap_or_else(|_| PathBuf::from(".config/ic-sync/cookies"))
}
fn default_true() -> bool {
    true
}
/// Minimum and default values are part of the persisted config contract.
pub const MIN_SYNC_INTERVAL_SECONDS: u64 = 5;
pub const MIN_UPLOAD_INTERVAL_SECONDS: u64 = 1;

fn default_sync_interval() -> u64 {
    15
}
fn default_upload_interval() -> u64 {
    5
}
fn default_warmup_workers() -> usize {
    1
}
fn default_conflict_mode() -> ConflictMode {
    ConflictMode::Copy
}

fn deserialize_password<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// Serialize the in-memory password. [`Config::write`] clears it first unless
/// `credential_mode` is `plain`, so secure configs never reach disk with a
/// secret. Direct `serde` serialization bypasses that safeguard; always use
/// `Config::write()`.
fn serialize_password<S>(password: &str, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(password)
}

/// Normalize an Apple ID into a stable, non-secret keyring account name.
pub fn credential_account(username: &str) -> String {
    username.trim().to_lowercase()
}

/// The account part of every keyring entry for this config.
pub fn credential_key(config: &Config) -> String {
    if config.credential_key.trim().is_empty() {
        credential_account(&config.username)
    } else {
        config.credential_key.trim().to_string()
    }
}

fn store_error(error: &keyring::Error) -> Error {
    Error::Credential(format!(
        "OS credential store is unavailable ({error}). On Linux, install and unlock a Secret \
         Service provider (gnome-keyring, kwallet or KeePassXC); on Windows, sign in to enable \
         Credential Manager. Refusing to store credentials in plaintext."
    ))
}

/// Cheap capability probe; safe to call before any credential is written.
pub fn secure_storage_available() -> bool {
    matches!(Entry::store_status(), Ok(()))
}

/// Fail early with an actionable message when there is no secure store.
pub fn require_secure_storage() -> Result<()> {
    if let Err(error) = Entry::store_status() {
        return Err(store_error(error));
    }
    Ok(())
}

fn entry_for(key: &str, kind: SecretKind) -> Result<Entry> {
    require_secure_storage()?;
    let account = format!("{key}:{}", kind.suffix());
    Entry::new(KEYRING_SERVICE, &account).map_err(|error| store_error(&error))
}

pub fn store_secret(key: &str, kind: SecretKind, value: &str) -> Result<()> {
    let entry = entry_for(key, kind)?;
    entry
        .set_password(value)
        .map_err(|error| store_error(&error))
}

/// `Ok(None)` means "no entry yet", which is normal before first sign-in.
pub fn load_secret(key: &str, kind: SecretKind) -> Result<Option<String>> {
    let entry = entry_for(key, kind)?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(store_error(&error)),
    }
}

pub fn delete_secret(key: &str, kind: SecretKind) -> Result<()> {
    let entry = entry_for(key, kind)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(store_error(&error)),
    }
}

/// Atomically write a file with restrictive permissions (0600 on Unix).
/// Used for the config YAML and for Apple session/cookie compatibility files.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        paths::create_secure_dir(parent)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let temp = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(SECRET_FILE_MODE);
    }
    {
        let mut handle = options.open(&temp)?;
        handle.write_all(data)?;
        handle.flush()?;
        handle.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(SECRET_FILE_MODE))?;
    }

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error.into())
        }
    }
}

impl Config {
    /// A config skeleton with every optional field set to its default.
    pub fn load_defaults() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            credential_mode: CredentialMode::default(),
            credential_key: String::new(),
            sync_folder: default_sync_folder(),
            cache_dir: default_cache_dir(),
            cookie_dir: default_cookie_dir(),
            sync_paths: Vec::new(),
            exclude_paths: Vec::new(),
            auto_sync: true,
            sync_interval_seconds: default_sync_interval(),
            upload_interval_seconds: default_upload_interval(),
            instant_sync: true,
            theme: ThemePreference::default(),
            start_minimized: true,
            autostart: false,
            warmup_workers: default_warmup_workers(),
            conflict_mode: ConflictMode::Copy,
            last_sync_at: None,
            config_path: None,
        }
    }

    /// Load persisted fields. In `secure` mode any plaintext password from a
    /// legacy config is discarded; use [`migrate_plaintext_password`] once to
    /// move it into the keyring. In `plain` mode the password is intentionally
    /// read back from this 0600 YAML.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let mut config: Self = serde_yml::from_str(&raw)?;
        config.username = config.username.trim().to_string();
        config.cache_dir = expand_path(&config.cache_dir)?;
        config.cookie_dir = expand_path(&config.cookie_dir)?;
        config.sync_folder = expand_path(&config.sync_folder)?;
        config.credential_key = credential_account(&config.credential_key);
        if config.credential_key.is_empty() {
            config.credential_key = credential_account(&config.username);
        }
        config.warmup_workers = config.warmup_workers.max(1);
        config.sync_interval_seconds = config.sync_interval_seconds.max(MIN_SYNC_INTERVAL_SECONDS);
        config.upload_interval_seconds = config
            .upload_interval_seconds
            .max(MIN_UPLOAD_INTERVAL_SECONDS);
        config.sync_paths = config
            .sync_paths
            .iter()
            .map(|p| normalize_icloud_path(p))
            .collect();
        config.exclude_paths = config
            .exclude_paths
            .iter()
            .map(|p| normalize_icloud_path(p))
            .collect();
        // Secure mode never keeps a legacy plaintext password in memory.
        if config.credential_mode.is_secure() {
            config.password.clear();
        }
        config.config_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Convenience for GUI workers: load the config and hydrate its password
    /// from the OS credential store. An empty `password` means "sign in".
    pub fn load_with_secrets(path: &Path) -> Result<Self> {
        let mut config = Self::load(path)?;
        config.hydrate_secrets()?;
        Ok(config)
    }

    /// Hydrate the Apple ID password according to `credential_mode`.
    /// Secure mode reads the OS credential store (missing entries are fine on
    /// first run; an unavailable store is an error). Plain mode keeps the
    /// password already read from the config YAML.
    pub fn hydrate_secrets(&mut self) -> Result<()> {
        if self.credential_mode.is_plain() {
            return Ok(());
        }
        let key = credential_key(self);
        self.password = load_secret(&key, SecretKind::Password)?.unwrap_or_default();
        Ok(())
    }

    /// Store the password according to `credential_mode` and keep it in memory.
    /// The config file itself is not written here; call `write()` separately.
    /// In plain mode the password is written to YAML by `write()` — see
    /// [`plain_storage_warning`].
    pub fn store_password(&mut self, password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(Error::Config("password must not be empty".into()));
        }
        if self.credential_key.trim().is_empty() {
            self.credential_key = credential_account(&self.username);
        }
        if self.username.trim().is_empty() {
            return Err(Error::Config(
                "username is required before storing a password".into(),
            ));
        }
        if self.credential_mode.is_plain() {
            self.password = password.to_string();
            return Ok(());
        }
        let key = credential_key(self);
        store_secret(&key, SecretKind::Password, password)?;
        self.password = password.to_string();
        Ok(())
    }

    /// Remove every credential belonging to this account (sign out / forget session).
    /// In plain mode there are no keyring entries; callers should also remove
    /// the local session/cookie files via `ICloudApi::clear_session()`.
    pub fn forget_credentials(&self) -> Result<()> {
        if self.credential_mode.is_plain() {
            return Ok(());
        }
        let key = credential_key(self);
        delete_secret(&key, SecretKind::Password)?;
        delete_secret(&key, SecretKind::SessionToken)?;
        delete_secret(&key, SecretKind::TrustToken)?;
        Ok(())
    }

    /// Write YAML atomically with 0600 permissions (the strictest the OS
    /// allows). In secure mode the password is cleared before serialization so
    /// no secret reaches disk; in explicit plain mode it is persisted locally.
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut sanitized = self.clone();
        if sanitized.credential_mode.is_secure() {
            sanitized.password.clear();
        }
        sanitized.config_path = Some(path.to_path_buf());
        let raw = serde_yml::to_string(&sanitized)?;
        debug_assert!(
            sanitized.credential_mode.is_plain() || sanitized.password.is_empty(),
            "secure credential mode must never write the password to YAML"
        );
        atomic_write(path, raw.as_bytes())
    }

    /// Validate non-secret fields. An empty Apple ID is allowed here so a fresh
    /// install can start in `LoginRequired` mode; sign-in validates it instead.
    pub fn validate(&self) -> Result<()> {
        if self.sync_folder.as_os_str().is_empty() {
            return Err(Error::Config("sync_folder is required".into()));
        }
        if self.warmup_workers == 0 {
            return Err(Error::Config("warmup_workers must be at least 1".into()));
        }
        if self.sync_interval_seconds < MIN_SYNC_INTERVAL_SECONDS {
            return Err(Error::Config(format!(
                "sync_interval_seconds must be at least {MIN_SYNC_INTERVAL_SECONDS}"
            )));
        }
        if self.upload_interval_seconds < MIN_UPLOAD_INTERVAL_SECONDS {
            return Err(Error::Config(format!(
                "upload_interval_seconds must be at least {MIN_UPLOAD_INTERVAL_SECONDS}"
            )));
        }
        // Secure mode is the only default. If there is no OS store, callers
        // must explicitly opt into `credential_mode: plain` and show the
        // warning rather than silently writing plaintext.
        if self.credential_mode.is_secure() {
            require_secure_storage()
                .map_err(|error| Error::Credential(format!("credential_mode=secure: {error}")))?;
        }
        Ok(())
    }

    pub fn path_allowed(&self, path: &str) -> bool {
        path_allowed(path, &self.sync_paths, &self.exclude_paths)
    }

    pub fn state_db(&self) -> PathBuf {
        self.cache_dir.join("state.sqlite3")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.cache_dir.join("tmp")
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub fn set_config_path(&mut self, path: PathBuf) {
        self.config_path = Some(path);
    }

    /// Update the Apple ID and keep the derived keyring key in sync.
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into().trim().to_string();
        if self.credential_key.trim().is_empty() {
            self.credential_key = credential_account(&self.username);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub migrated: bool,
    pub username: String,
    pub credential_key: String,
}

/// True when a config file still contains a plaintext password.
pub fn plaintext_password_in(path: &Path) -> Result<bool> {
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_yml::from_str(&raw)?;
    Ok(value
        .get("password")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|password| !password.is_empty()))
}

/// One-time migration for configs written before credential modes existed.
/// In `secure` mode (the default for old configs) the plaintext password is
/// moved into the keyring and the YAML is rewritten without it; a missing OS
/// store fails clearly rather than silently writing plaintext. In explicit
/// `plain` mode the password stays in the 0600 YAML and the mode is written
/// down, so the choice survives future loads. Safe to call repeatedly.
pub fn migrate_plaintext_password(path: &Path) -> Result<MigrationReport> {
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_yml::from_str(&raw)?;
    let password = value
        .get("password")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    let mut config = Config::load(path)?;
    let report = MigrationReport {
        migrated: false,
        username: config.username.clone(),
        credential_key: credential_key(&config),
    };
    if password.is_empty() {
        return Ok(report);
    }

    if config.credential_mode.is_plain() {
        config.password = password;
        config.write(path)?;
        return Ok(report);
    }

    require_secure_storage()?;
    store_secret(&report.credential_key, SecretKind::Password, &password)?;
    config.password.clear();
    config.write(path)?;
    Ok(MigrationReport {
        migrated: true,
        ..report
    })
}

pub fn expand_path(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/") {
        return Ok(paths::home()?.join(rest));
    }
    if text == "~" {
        return paths::home();
    }
    Ok(path.to_path_buf())
}

/// Normalize an iCloud path to an absolute, slash-separated path.
pub fn normalize_icloud_path(input: &str) -> String {
    let mut result = PathBuf::new();
    for component in Path::new(input).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
            Component::Prefix(_) => {}
        }
    }
    let normalized = format!("/{}", result.to_string_lossy().replace('\\', "/"));
    if normalized == "/" {
        "/".into()
    } else {
        normalized.trim_end_matches('/').into()
    }
}

/// Allowlist/denylist check. Deny always wins; an empty allowlist means all.
pub fn path_allowed(path: &str, allow: &[String], deny: &[String]) -> bool {
    let path = normalize_icloud_path(path);
    let matches = |prefix: &str| {
        let prefix = normalize_icloud_path(prefix);
        if prefix == "/" {
            true
        } else {
            path == prefix || path.starts_with(&format!("{prefix}/"))
        }
    };
    if deny.iter().any(|p| matches(p)) {
        return false;
    }
    allow.is_empty() || allow.iter().any(|p| matches(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn raw_config() -> &'static str {
        "username: user@example.com\n\
         password: legacy-secret\n\
         credential_key: user@example.com\n\
         sync_folder: /tmp/icloud\n\
         sync_paths:\n  - /Documents\n\
         exclude_paths:\n  - /Documents/Private\n"
    }

    #[test]
    fn load_clears_password_and_write_never_persists_it() {
        let dir = TempDir::new();
        let path = dir.path.join("config.yaml");
        fs::write(&path, raw_config()).unwrap();

        let mut config = Config::load(&path).unwrap();
        assert!(config.password.is_empty());
        assert_eq!(config.username, "user@example.com");
        assert_eq!(config.sync_folder, PathBuf::from("/tmp/icloud"));
        assert!(config.auto_sync);
        assert!(config.instant_sync);
        assert!(config.start_minimized);
        assert!(!config.autostart);
        assert_eq!(config.theme, ThemePreference::System);
        assert_eq!(config.credential_mode, CredentialMode::Secure);
        assert_eq!(config.sync_interval_seconds, 15);
        assert_eq!(config.upload_interval_seconds, 5);

        config.password = "session-only-secret".into();
        config.write(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("legacy-secret"));
        assert!(!raw.contains("session-only-secret"));
        assert!(raw.contains("password:"));
        assert_eq!(Config::load(&path).unwrap().password, "");
    }

    #[test]
    fn plaintext_detection_and_path_rules() {
        let dir = TempDir::new();
        let legacy = dir.path.join("legacy.yaml");
        fs::write(&legacy, raw_config()).unwrap();
        assert!(plaintext_password_in(&legacy).unwrap());

        let clean = dir.path.join("clean.yaml");
        fs::write(&clean, raw_config().replace("legacy-secret", "")).unwrap();
        assert!(!plaintext_password_in(&clean).unwrap());

        assert!(path_allowed(
            "/Documents/a.txt",
            &["/Documents".into()],
            &[]
        ));
        assert!(path_allowed(
            "/Documents/a.txt",
            &[],
            &["/Documents/Private".into()]
        ));
        assert!(!path_allowed("/Photos/a.txt", &["/Documents".into()], &[]));
        assert!(!path_allowed(
            "/Documents/Private/x",
            &[],
            &["/Documents/Private".into()]
        ));
        assert_eq!(normalize_icloud_path("/a/../b/./c"), "/b/c");
    }

    #[test]
    fn defaults_are_contract_values_and_serde_is_lowercase() {
        let config = Config::load_defaults();
        assert_eq!(config.theme, ThemePreference::System);
        assert_eq!(config.credential_mode, CredentialMode::Secure);
        assert!(config.instant_sync);
        assert!(config.start_minimized);
        assert!(!config.autostart);
        assert_eq!(config.sync_interval_seconds, 15);
        assert_eq!(config.upload_interval_seconds, 5);

        let yaml = serde_yml::to_string(&config).unwrap();
        for expected in [
            "theme: system",
            "credential_mode: secure",
            "instant_sync: true",
            "start_minimized: true",
            "autostart: false",
        ] {
            assert!(yaml.contains(expected), "missing {expected} in:\n{yaml}");
        }

        let dark_plain: Config = serde_yml::from_str(&raw_config().replace(
            "username: user@example.com\n",
            "username: user@example.com\n\
                 theme: dark\n\
                 credential_mode: plain\n\
                 start_minimized: false\n\
                 autostart: true\n\
                 instant_sync: false\n",
        ))
        .unwrap();
        assert_eq!(dark_plain.theme, ThemePreference::Dark);
        assert_eq!(dark_plain.credential_mode, CredentialMode::Plain);
        assert!(!dark_plain.start_minimized);
        assert!(dark_plain.autostart);
        assert!(!dark_plain.instant_sync);
    }

    #[test]
    fn old_config_without_new_fields_loads_with_backward_compatible_defaults() {
        let dir = TempDir::new();
        let path = dir.path.join("old.yaml");
        fs::write(&path, raw_config()).unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.theme, ThemePreference::System);
        assert_eq!(config.credential_mode, CredentialMode::Secure);
        assert!(config.instant_sync);
        assert!(config.start_minimized);
        assert_eq!(config.sync_interval_seconds, 15);
        assert_eq!(config.upload_interval_seconds, 5);
    }

    #[test]
    fn intervals_are_clamped_and_validation_names_the_mode() {
        let dir = TempDir::new();
        let path = dir.path.join("fast.yaml");
        let raw = raw_config().replace(
            "sync_paths:",
            "sync_interval_seconds: 1\nupload_interval_seconds: 0\nsync_paths:",
        );
        fs::write(&path, raw).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.sync_interval_seconds, MIN_SYNC_INTERVAL_SECONDS);
        assert_eq!(config.upload_interval_seconds, MIN_UPLOAD_INTERVAL_SECONDS);

        let mut invalid = Config::load_defaults();
        invalid.sync_interval_seconds = 4;
        let error = invalid.validate().unwrap_err().to_string();
        assert!(error.contains("sync_interval_seconds"), "{error}");
    }

    #[test]
    fn plain_mode_is_explicit_and_secure_mode_never_writes_a_password() {
        let dir = TempDir::new();
        let plain_path = dir.path.join("plain.yaml");
        let mut plain = Config::load_defaults();
        plain.username = "user@example.com".into();
        plain.credential_mode = CredentialMode::Plain;
        plain.store_password("plain-secret").unwrap();
        plain.hydrate_secrets().unwrap();
        plain.write(&plain_path).unwrap();
        let raw = fs::read_to_string(&plain_path).unwrap();
        assert!(raw.contains("credential_mode: plain"));
        assert!(raw.contains("plain-secret"));
        assert_eq!(Config::load(&plain_path).unwrap().password, "plain-secret");
        // Plain mode must not need a keyring even on sign-out.
        Config::load(&plain_path)
            .unwrap()
            .forget_credentials()
            .unwrap();
        assert!(plain_storage_warning().contains("unsafe"));

        let secure_path = dir.path.join("secure.yaml");
        let mut secure = Config::load_defaults();
        secure.username = "user@example.com".into();
        secure.password = "secure-secret".into();
        secure.write(&secure_path).unwrap();
        let raw = fs::read_to_string(&secure_path).unwrap();
        assert!(raw.contains("credential_mode: secure"));
        assert!(!raw.contains("secure-secret"));
        assert!(credential_storage_ready(CredentialMode::Plain));
    }
}
