use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors surfaced by the headless core.
///
/// The variants named in the architecture contract (`Auth`, `TwoFactor`,
/// `Http`, `Config`, `Offline`, `Conflict`, `Io`, `Other`) are all present;
/// the remaining variants cover concrete failure domains and carry enough
/// context for the GUI to render a useful message.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yml::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
    #[error("authentication required: {0}")]
    Auth(String),
    #[error("two-factor authentication required: {0}")]
    TwoFactor(String),
    /// A verification code was rejected by Apple (e.g. `-21669`). The
    /// challenge is still alive and the caller may retry or switch methods.
    #[error("verification code rejected: {0}")]
    CodeRejected(String),
    #[error("offline: {0}")]
    Offline(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("folder is not clean: {0}")]
    NotClean(String),
    #[error("secure credential store error: {0}")]
    Credential(String),
    #[error("Apple API error ({status}): {message}")]
    AppleApi { status: u16, message: String },
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth(message.into())
    }

    pub fn two_factor(message: impl Into<String>) -> Self {
        Self::TwoFactor(message.into())
    }

    pub fn offline(message: impl Into<String>) -> Self {
        Self::Offline(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    pub fn not_clean(message: impl Into<String>) -> Self {
        Self::NotClean(message.into())
    }

    pub fn credential(message: impl Into<String>) -> Self {
        Self::Credential(message.into())
    }

    pub fn code_rejected(message: impl Into<String>) -> Self {
        Self::CodeRejected(message.into())
    }

    /// True for failures that mean "try again later", not "ask the user to log in".
    pub fn is_offline(&self) -> bool {
        matches!(self, Self::Offline(_) | Self::Http(_))
    }

    /// True for failures that require interactive sign-in / 2FA.
    pub fn is_auth(&self) -> bool {
        matches!(
            self,
            Self::Auth(_) | Self::TwoFactor(_) | Self::CodeRejected(_)
        )
    }

    pub fn is_code_rejected(&self) -> bool {
        matches!(self, Self::CodeRejected(_))
    }
}
