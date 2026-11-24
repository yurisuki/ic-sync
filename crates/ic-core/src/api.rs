//! Minimal native client for the Apple iCloud web services used by iCloud Drive.
//!
//! Request shapes mirror the reference implementation so existing sessions,
//! cookies and account shards keep working. Secret material is mirrored to the
//! OS credential store; the compatibility files are written atomically with
//! 0600 permissions on Unix.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine;
use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, ORIGIN, REFERER, SET_COOKIE};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::bridge::BridgeSession;
use crate::config::{self, Config, SecretKind, atomic_write, credential_key};
use crate::error::{Error, Result};

pub const ROOT_DRIVEWSID: &str = "FOLDER::com.apple.CloudDocs::root";
/// The root folder's document id (the part after the final `::` in
/// `ROOT_DRIVEWSID`). Apple's `/update/documents` API chains children by
/// *docwsid*, never by drivewsid.
pub const ROOT_DOCWSID: &str = "root";
pub const CLOUD_DOCS_ZONE: &str = "com.apple.CloudDocs";
const CLIENT_BUILD_NUMBER: &str = "2534Project66";
const CLIENT_MASTERING_NUMBER: &str = "2534B22";
const OAUTH_CLIENT_ID: &str = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";
pub const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionData {
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub scnt: Option<String>,
    pub auth_attributes: Option<String>,
    pub session_token: Option<String>,
    pub trust_token: Option<String>,
    pub account_country: Option<String>,
    pub dsid: Option<String>,
    pub grant_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteNode {
    pub name: String,
    /// The separate extension Apple returns for most Drive nodes. Kept so the
    /// engine can repair extensionless rows created by older builds.
    pub extension: Option<String>,
    pub node_type: String,
    pub drivewsid: String,
    pub docwsid: Option<String>,
    pub etag: Option<String>,
    pub zone: Option<String>,
    pub share_id: Option<Value>,
    pub size: i64,
    pub date_changed: Option<i64>,
    pub items: Option<Vec<RemoteNode>>,
}

impl RemoteNode {
    pub fn from_value(value: &Value) -> Self {
        // Apple (and pyicloud's DriveNode.name) returns the base name in
        // `name` and the type suffix in a separate `extension` key. Using only
        // `name` produced extensionless local files in older builds.
        // Mirror the reference unconditionally: whenever `extension` is
        // present, the canonical name is `<base>.<extension>`.
        let extension = value
            .get("extension")
            .and_then(Value::as_str)
            .map(str::to_string);
        let base = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .or_else(|| value.get("drivewsid").and_then(Value::as_str))
            .unwrap_or("<unknown>");
        let name = match extension.as_deref() {
            Some(ext) if !ext.is_empty() && !base.ends_with(&format!(".{ext}")) => {
                format!("{base}.{ext}")
            }
            _ => base.to_string(),
        };
        let node_type = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_lowercase();
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(Self::from_value).collect());
        Self {
            name,
            extension,
            node_type,
            drivewsid: value
                .get("drivewsid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            docwsid: value
                .get("docwsid")
                .and_then(Value::as_str)
                .map(str::to_string),
            etag: value
                .get("etag")
                .and_then(Value::as_str)
                .map(str::to_string),
            zone: value
                .get("zone")
                .and_then(Value::as_str)
                .map(str::to_string),
            share_id: value.get("shareID").cloned(),
            size: value
                .get("size")
                .and_then(Value::as_i64)
                .or_else(|| {
                    value
                        .get("size")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                })
                .unwrap_or(0),
            date_changed: value
                .get("dateChanged")
                .and_then(Value::as_i64)
                .or_else(|| {
                    value
                        .get("dateChanged")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok())
                }),
            items,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.node_type.as_str(), "folder" | "app_library")
    }

    /// One safe path component for this node, never a path fragment.
    ///
    /// Apple sometimes returns a bare `name` that is actually a path
    /// (`Parent/Child`), starts with a slash, or (for some app libraries) is
    /// the raw `drivewsid` such as `FOLDER::com.apple.TextInput::documents`.
    /// Joining any of those onto a parent path produces the doubled paths
    /// (`/Parent/Parent`, `/Parent/Full::Path::Name`) seen after a bad crawl.
    pub fn display_name(&self) -> String {
        safe_node_name(&self.name)
            .or_else(|| safe_node_name(&self.drivewsid))
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Collapse a remote name to a single path component.
///
/// Returns `None` for empty, `.`, `..` or separator-only names. Both slashes
/// and backslashes are treated as separators so a remote name can never
/// inject extra path levels (or escape the mirror on Windows).
pub fn safe_node_name(raw: &str) -> Option<String> {
    let part = raw
        .trim()
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty() && *component != "." && *component != "..")?;
    Some(part.to_string())
}

#[derive(Clone)]
pub struct ICloudApi {
    pub client: Client,
    pub session: Arc<RwLock<SessionData>>,
    pub data: Arc<RwLock<Value>>,
    cookies: Arc<RwLock<HashMap<String, String>>>,
    cookie_path: PathBuf,
    session_path: PathBuf,
    pub auth_endpoint: String,
    pub setup_endpoint: String,
    pub home_endpoint: String,
    pub mfa_pending: Arc<RwLock<bool>>,
    /// The live HSA2 trusted-device bridge, kept alive between `authenticate()`
    /// and `submit_code()`. The transport is owned by core; the GUI never has
    /// to manage it.
    bridge: Arc<Mutex<Option<BridgeSession>>>,
    offline: Arc<RwLock<Option<String>>>,
    credential_key: String,
    /// Secure mode mirrors tokens into the OS keyring; plain mode keeps them
    /// only in the local 0600 session/cookie files.
    credential_mode: config::CredentialMode,
}

impl ICloudApi {
    pub async fn new(config: &Config) -> Result<Self> {
        // Never let a hung Apple request pin the engine in `Syncing`: the
        // remote/upload loops must be able to report an error and retry.
        let client = ClientBuilder::new()
            .user_agent(USER_AGENT)
            .default_headers(default_request_headers())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        if config.credential_mode.is_secure() {
            config::require_secure_storage()?;
        }

        paths_secure_dir(&config.cookie_dir)?;
        let safe_name: String = config
            .username
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let cookie_path = config.cookie_dir.join(format!("{safe_name}.cookiejar"));
        let session_path = config.cookie_dir.join(format!("{safe_name}.session"));

        let mut session = read_session_file(&session_path).unwrap_or_default();
        let cookies = read_cookie_file(&cookie_path).unwrap_or_default();
        let key = credential_key(config);

        // Secure mode prefers the keyring when the compatibility file has no
        // token. Plain mode deliberately uses only the local session files.
        if config.credential_mode.is_secure() {
            if session.session_token.is_none() {
                match config::load_secret(&key, SecretKind::SessionToken) {
                    Ok(Some(token)) => session.session_token = Some(token),
                    Ok(None) => {}
                    Err(error) => warn!("could not read stored session token: {error}"),
                }
            }
            if session.trust_token.is_none() {
                match config::load_secret(&key, SecretKind::TrustToken) {
                    Ok(Some(token)) => session.trust_token = Some(token),
                    Ok(None) => {}
                    Err(error) => warn!("could not read stored trust token: {error}"),
                }
            }
        }

        let (setup_endpoint, probe_error) = match probe_endpoint(&client).await {
            Ok(endpoint) => (endpoint, None),
            Err(error) => {
                warn!("could not probe Apple endpoint: {error}");
                (
                    "https://setup.icloud.com/setup/ws/1".to_string(),
                    Some(error.to_string()),
                )
            }
        };

        let api = Self {
            client,
            session: Arc::new(RwLock::new(session)),
            data: Arc::new(RwLock::new(Value::Null)),
            cookies: Arc::new(RwLock::new(cookies)),
            cookie_path,
            session_path,
            auth_endpoint: "https://idmsa.apple.com/appleauth/auth".into(),
            setup_endpoint,
            home_endpoint: "https://www.icloud.com".into(),
            mfa_pending: Arc::new(RwLock::new(false)),
            bridge: Arc::new(Mutex::new(None)),
            offline: Arc::new(RwLock::new(probe_error)),
            credential_key: key,
            credential_mode: config.credential_mode,
        };

        // A broken saved session must never crash startup: fall back to the
        // cached, read-only state so Apple cannot be hammered by a restart loop.
        if api.session_token().is_some() {
            match api.login_with_token().await {
                Ok(()) => *api.offline.write().unwrap() = None,
                Err(Error::Auth(message)) => warn!("saved session no longer valid: {message}"),
                Err(Error::TwoFactor(message)) => {
                    warn!("saved session needs 2FA: {message}");
                    *api.mfa_pending.write().unwrap() = true;
                }
                Err(error) => {
                    if error.is_offline() {
                        *api.offline.write().unwrap() = Some(error.to_string());
                    }
                    warn!("could not restore saved iCloud session: {error}");
                }
            }
        }
        Ok(api)
    }

    pub fn is_offline(&self) -> bool {
        self.offline.read().unwrap().is_some()
    }

    pub fn offline_message(&self) -> Option<String> {
        self.offline.read().unwrap().clone()
    }

    pub fn session_token(&self) -> Option<String> {
        self.session.read().unwrap().session_token.clone()
    }

    /// Store the bridge session created by `authenticate()` for later code
    /// validation. Any previous (stale) session is replaced.
    pub fn set_bridge_session(&self, session: BridgeSession) {
        *self.bridge.lock().unwrap() = Some(session);
    }

    /// Take the bridge session out of storage so code validation can use it
    /// without holding a lock across network I/O.
    pub fn take_bridge_session(&self) -> Option<BridgeSession> {
        self.bridge.lock().unwrap().take()
    }

    /// Discard any live bridge transport.
    pub fn clear_bridge_session(&self) {
        *self.bridge.lock().unwrap() = None;
    }

    pub fn is_authenticated(&self) -> bool {
        self.data.read().unwrap().get("dsInfo").is_some() && self.session_token().is_some()
    }

    pub fn is_trusted(&self) -> bool {
        self.data
            .read()
            .unwrap()
            .get("hsaTrustedBrowser")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub fn requires_2fa(&self) -> bool {
        *self.mfa_pending.read().unwrap()
            || self
                .data
                .read()
                .unwrap()
                .get("hsaChallengeRequired")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || (self.is_authenticated() && !self.is_trusted())
    }

    pub fn dsid(&self) -> Option<String> {
        self.data
            .read()
            .unwrap()
            .get("dsInfo")
            .and_then(|info| info.get("dsid"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| self.session.read().unwrap().dsid.clone())
    }

    pub fn webservice_url(&self, key: &str) -> Result<String> {
        self.data
            .read()
            .unwrap()
            .get("webservices")
            .and_then(|ws| ws.get(key))
            .and_then(|entry| entry.get("url"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Auth(format!("iCloud webservice '{key}' is not available")))
    }

    pub fn params(&self) -> Vec<(String, String)> {
        let session = self.session.read().unwrap();
        let mut params = vec![
            (
                "clientBuildNumber".to_string(),
                CLIENT_BUILD_NUMBER.to_string(),
            ),
            (
                "clientMasteringNumber".to_string(),
                CLIENT_MASTERING_NUMBER.to_string(),
            ),
            (
                "clientId".to_string(),
                session.client_id.clone().unwrap_or_default(),
            ),
        ];
        if let Some(dsid) = self.dsid().or_else(|| session.dsid.clone()) {
            params.push(("dsid".to_string(), dsid));
        }
        params
    }

    pub fn auth_headers(&self) -> HeaderMap {
        let session = self.session.read().unwrap();
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Accept", "application/json, text/javascript");
        insert_header(&mut headers, "Content-Type", "application/json");
        insert_header(&mut headers, "Referer", "https://idmsa.apple.com");
        insert_header(&mut headers, "X-Apple-Oauth-Client-Id", OAUTH_CLIENT_ID);
        insert_header(&mut headers, "X-Apple-Oauth-Client-Type", "firstPartyAuth");
        insert_header(
            &mut headers,
            "X-Apple-Oauth-Redirect-Uri",
            &self.home_endpoint,
        );
        insert_header(&mut headers, "X-Apple-Oauth-Require-Grant-Code", "true");
        insert_header(&mut headers, "X-Apple-Oauth-Response-Mode", "web_message");
        insert_header(&mut headers, "X-Apple-Oauth-Response-Type", "code");
        insert_header(
            &mut headers,
            "X-Apple-Oauth-State",
            session.client_id.as_deref().unwrap_or_default(),
        );
        insert_header(&mut headers, "X-Apple-Widget-Key", OAUTH_CLIENT_ID);
        insert_header(
            &mut headers,
            "X-Apple-Frame-Id",
            session.client_id.as_deref().unwrap_or_default(),
        );
        insert_header(
            &mut headers,
            "X-Apple-FD-Client-Info",
            &json!({"U": USER_AGENT, "L": "en-US", "Z": "GMT+00:00", "V": "1.1", "F": ""})
                .to_string(),
        );
        if let Some(scnt) = &session.scnt {
            insert_header(&mut headers, "scnt", scnt);
        }
        if let Some(id) = &session.session_id {
            insert_header(&mut headers, "X-Apple-ID-Session-Id", id);
        }
        if let Some(attrs) = &session.auth_attributes {
            insert_header(&mut headers, "X-Apple-Auth-Attributes", attrs);
        }
        headers
    }

    pub fn with_cookies(&self, request: RequestBuilder) -> RequestBuilder {
        let jar = self.cookies.read().unwrap();
        if jar.is_empty() {
            request
        } else {
            let header = jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request.header(COOKIE, header)
        }
    }

    /// Capture only cookies from a response. Bridge steps use raw HTTP in the
    /// Python implementation: their headers must not overwrite Apple session
    /// tokens, but refreshed auth cookies still need to be kept.
    pub fn capture_cookies(&self, response: &Response) {
        let mut changed = false;
        {
            let mut jar = self.cookies.write().unwrap();
            for values in response.headers().get_all(SET_COOKIE).iter() {
                let Ok(text) = values.to_str() else { continue };
                if let Some((name, rest)) = text.split_once('=') {
                    // Apple's auth cookie values carry literal surrounding
                    // quotes. Python's http.cookiejar keeps them, and so must
                    // we: stripping them corrupts the token (HTTP 421 on every
                    // Drive call and a misleading "sign in required" status).
                    let value = rest.split(';').next().unwrap_or_default().trim();
                    if jar.get(name.trim()).map(String::as_str) != Some(value) {
                        jar.insert(name.trim().to_string(), value.to_string());
                        changed = true;
                    }
                }
            }
        }
        if changed {
            let _ = self.persist();
        }
    }

    pub fn capture(&self, response: &Response) {
        self.capture_cookies(response);
        update_session_from_headers(response, &self.session);
    }

    /// Persist the compatibility session/cookie files and mirror tokens into
    /// the credential store. Residual risk: the 0600 files still hold Apple's
    /// session material in plain text because the web auth flow requires it;
    /// they stay outside the repo and are never logged.
    pub fn persist(&self) -> Result<()> {
        let session = self.session.read().unwrap();
        atomic_write(
            &self.session_path,
            serde_json::to_string_pretty(&*session)?.as_bytes(),
        )?;
        let jar = self.cookies.read().unwrap();
        let mut lines = vec!["#LWP-Cookies-2.0".to_string()];
        let mut names: Vec<_> = jar.keys().collect();
        names.sort();
        for name in names {
            lines.push(format!(
                "Set-Cookie3: {}={}; path=\"/\"; domain=.icloud.com; path_spec; secure; discard; version=0",
                name,
                quote_cookie_value(&jar[name])
            ));
        }
        atomic_write(&self.cookie_path, (lines.join("\n") + "\n").as_bytes())?;

        if self.credential_mode.is_secure() {
            if let Some(token) = &session.session_token
                && let Err(error) =
                    config::store_secret(&self.credential_key, SecretKind::SessionToken, token)
            {
                warn!("{error}");
            }
            if let Some(token) = &session.trust_token
                && let Err(error) =
                    config::store_secret(&self.credential_key, SecretKind::TrustToken, token)
            {
                warn!("{error}");
            }
        }
        // Plain mode intentionally leaves tokens only in the local files.
        // See config::plain_storage_warning() for the documented risk.
        Ok(())
    }

    /// Sign out: remove compatibility files and keyring tokens.
    pub fn clear_session(&self) -> Result<()> {
        for path in [&self.session_path, &self.cookie_path] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if self.credential_mode.is_secure() {
            for kind in [SecretKind::SessionToken, SecretKind::TrustToken] {
                config::delete_secret(&self.credential_key, kind)?;
            }
        }
        *self.session.write().unwrap() = SessionData::default();
        self.cookies.write().unwrap().clear();
        *self.data.write().unwrap() = Value::Null;
        *self.mfa_pending.write().unwrap() = false;
        self.clear_bridge_session();
        Ok(())
    }

    pub async fn checked(&self, response: Response) -> Result<Response> {
        self.capture(&response);
        let status = response.status().as_u16();
        if response.status().is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        // Never log response bodies: Apple error payloads can echo tokens.
        debug!("Apple API returned HTTP {status}");
        match status {
            421 => {
                *self.data.write().unwrap() = Value::Null;
                Err(Error::Auth("Apple session token expired (421)".into()))
            }
            409 => {
                *self.mfa_pending.write().unwrap() = true;
                Err(Error::TwoFactor(
                    "Apple requires two-factor authentication".into(),
                ))
            }
            _ => {
                if (500..600).contains(&status) {
                    *self.offline.write().unwrap() = Some(format!("Apple returned HTTP {status}"));
                }
                Err(Error::AppleApi {
                    status,
                    message: body,
                })
            }
        }
    }

    /// Safe, value-free diagnostics for authentication failures.
    pub fn auth_diagnostics(&self) -> String {
        let session = self.session.read().unwrap();
        let cookies = self.cookies.read().unwrap();
        let mut names: Vec<&str> = cookies.keys().map(String::as_str).collect();
        names.sort_unstable();
        format!(
            "sessionTokenLen={} trustToken={} country={:?} cookies=[{}] setup={}",
            session.session_token.as_ref().map_or(0, String::len),
            session.trust_token.is_some(),
            session.account_country.as_deref().unwrap_or(""),
            names.join(", "),
            self.setup_endpoint
        )
    }

    pub async fn login_with_token(&self) -> Result<()> {
        let (token, country, trust) = {
            let session = self.session.read().unwrap();
            (
                session.session_token.clone(),
                session.account_country.clone(),
                session.trust_token.clone().unwrap_or_default(),
            )
        };
        let token = token.ok_or_else(|| Error::Auth("no saved session token".into()))?;
        let response = self
            .with_cookies(
                self.client
                    .post(format!("{}/accountLogin", self.setup_endpoint))
                    .header("Origin", "https://www.icloud.com")
                    .header("Referer", "https://www.icloud.com/"),
            )
            .json(&json!({
                "accountCountryCode": country.unwrap_or_default(),
                "dsWebAuthToken": token,
                "extended_login": true,
                "trustToken": trust,
            }))
            .send()
            .await?;
        let response = self.checked(response).await?;
        let data: Value = response.json().await?;
        if data
            .get("hsaChallengeRequired")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            *self.mfa_pending.write().unwrap() = true;
        }
        *self.data.write().unwrap() = data;
        self.clear_bridge_session();
        if let Some(dsid) = self
            .data
            .read()
            .unwrap()
            .get("dsInfo")
            .and_then(|i| i.get("dsid"))
            .and_then(Value::as_str)
        {
            self.session.write().unwrap().dsid = Some(dsid.to_string());
        }
        self.persist()?;
        if self.requires_2fa() {
            // Keep the cached-session state explicit: an untrusted or still
            // challenged session must look like "needs sign-in" to callers,
            // never like a usable read/write session.
            *self.mfa_pending.write().unwrap() = true;
            return Err(Error::TwoFactor("finish 2FA in IC-SYNC to continue".into()));
        }
        Ok(())
    }

    pub async fn validate_token(&self) -> Result<bool> {
        if self.session_token().is_none()
            || !self
                .cookies
                .read()
                .unwrap()
                .contains_key("X-APPLE-WEBAUTH-TOKEN")
        {
            return Ok(false);
        }
        let response = self
            .with_cookies(
                self.client
                    .post(format!("{}/validate", self.setup_endpoint)),
            )
            .body("null")
            .header(CONTENT_TYPE, "text/plain;charset=UTF-8")
            .send()
            .await?;
        match self.checked(response).await {
            Ok(_) => Ok(true),
            Err(Error::Auth(_)) | Err(Error::TwoFactor(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub async fn retrieve_node(
        &self,
        drivewsid: &str,
        share_id: Option<&Value>,
    ) -> Result<RemoteNode> {
        let mut item = json!({"drivewsid": drivewsid, "partialData": false});
        if let Some(share) = share_id {
            item["shareID"] = share.clone();
        }
        let url = format!(
            "{}/retrieveItemDetailsInFolders",
            self.webservice_url("drivews")?
        );
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&json!([item]))
            .send()
            .await?;
        let response = self.checked(response).await?;
        let body: Value = response.json().await?;
        body.get(0)
            .map(RemoteNode::from_value)
            .ok_or_else(|| Error::other("Apple returned no node details"))
    }

    pub async fn root(&self) -> Result<RemoteNode> {
        self.retrieve_node(ROOT_DRIVEWSID, None).await
    }

    pub async fn app_libraries(&self) -> Result<Vec<RemoteNode>> {
        let url = format!("{}/retrieveAppLibraries", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.get(url).query(&self.params()))
            .send()
            .await?;
        let response = self.checked(response).await?;
        let body: Value = response.json().await?;
        Ok(body
            .get("items")
            .and_then(Value::as_array)
            .map(|items| items.iter().map(RemoteNode::from_value).collect())
            .unwrap_or_default())
    }

    pub async fn download(
        &self,
        document_id: &str,
        zone: &str,
        owner: Option<&str>,
    ) -> Result<Vec<u8>> {
        let document_root = self.webservice_url("docws")?;
        let mut path = format!("/ws/{zone}/download/by_id");
        if let Some(owner) = owner {
            path.push('/');
            path.push_str(&url_encode(owner));
        }
        let mut params = self.params();
        params.push(("document_id".into(), document_id.into()));
        let response = self
            .with_cookies(
                self.client
                    .get(format!("{document_root}{path}"))
                    .query(&params),
            )
            .send()
            .await?;
        let response = self.checked(response).await?;
        let body: Value = response.json().await?;
        let url = body
            .get("data_token")
            .and_then(|t| t.get("url"))
            .or_else(|| body.get("package_token").and_then(|t| t.get("url")))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::other("Apple download response had no token URL"))?;
        let response = self
            .with_cookies(self.client.get(url).query(&self.params()))
            .send()
            .await?;
        Ok(self.checked(response).await?.bytes().await?.to_vec())
    }

    pub async fn create_folder(&self, parent: &str, name: &str) -> Result<Value> {
        let url = format!("{}/createFolders", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .header(CONTENT_TYPE, "plain/text")
            .json(&json!({
                "destinationDrivewsId": parent,
                "folders": [{
                    "clientId": format!("FOLDER::UNKNOWN_ZONE::TempId-{}", Uuid::new_v4()),
                    "name": name,
                }],
            }))
            .send()
            .await?;
        Ok(self.checked(response).await?.json().await?)
    }

    pub async fn delete_node(&self, id: &str, etag: &str) -> Result<()> {
        let url = format!("{}/deleteItems", self.webservice_url("drivews")?);
        let client_id = self
            .session
            .read()
            .unwrap()
            .client_id
            .clone()
            .unwrap_or_default();
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&delete_payload(id, etag, &client_id))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    pub async fn rename_node(&self, id: &str, etag: &str, name: &str) -> Result<()> {
        let url = format!("{}/renameItems", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&rename_payload(id, etag, name))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    pub async fn move_node(&self, id: &str, etag: &str, destination: &str) -> Result<()> {
        // pyicloud's DriveService.move_nodes_to_node posts to `/moveItems`
        // with clientId == drivewsid (not `/moveNodesToNode`).
        let url = format!("{}/moveItems", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&move_payload(destination, id, etag))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    /// Upload a complete file to the iCloud Drive content service.
    ///
    /// `parent_doc_id` must be the parent folder's **docwsid** (not its
    /// drivewsid): Apple chains the new document to its parent by document id
    /// in `/update/documents`, and a drivewsid there yields HTTP 412
    /// `VALIDATING_REFERENCE_ERROR` ("parents were missing"). `zone` is the
    /// parent's zone; it is part of both document-service URL paths.
    pub async fn upload(
        &self,
        parent_doc_id: &str,
        zone: &str,
        name: &str,
        content: Vec<u8>,
        mtime: i64,
    ) -> Result<Value> {
        let document_root = self.webservice_url("docws")?;
        let token = self
            .cookies
            .read()
            .unwrap()
            .get("X-APPLE-WEBAUTH-VALIDATE")
            .and_then(|value| {
                let start = value.find("t=")? + 2;
                Some(value[start..].split(';').next()?.to_string())
            })
            .ok_or_else(|| Error::Auth("upload token cookie not found".into()))?;
        let mut params = self.params();
        params.push(("token".into(), token));
        let response = self
            .with_cookies(
                self.client
                    .post(format!("{document_root}/ws/{zone}/upload/web"))
                    .query(&params),
            )
            .header(CONTENT_TYPE, "text/plain")
            .json(&json!({
                "filename": name,
                "type": "FILE",
                "content_type": guess_content_type(name),
                "size": content.len(),
            }))
            .send()
            .await?;
        let response = self.checked(response).await?;
        let body: Value = response.json().await?;
        let first = body
            .get(0)
            .ok_or_else(|| Error::other("upload response was empty"))?;
        let document_id = first
            .get("document_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::other("upload response had no document_id"))?
            .to_string();
        let upload_url = first
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::other("upload response had no url"))?
            .to_string();

        let response = self
            .with_cookies(self.client.post(&upload_url))
            .multipart(upload_form(name, content))
            .send()
            .await?;
        let receipt: Value = self.checked(response).await?.json().await?;
        let file_info = receipt
            .get("singleFile")
            .ok_or_else(|| Error::other("upload receipt had no singleFile"))?;
        let data = add_file_payload(parent_doc_id, name, &document_id, mtime, file_info);
        let response = self
            .with_cookies(
                self.client
                    .post(format!("{document_root}/ws/{zone}/update/documents"))
                    .query(&self.params()),
            )
            .header(CONTENT_TYPE, "text/plain")
            .json(&data)
            .send()
            .await?;
        Ok(self.checked(response).await?.json().await?)
    }
}

/// `POST /deleteItems` body, mirroring pyicloud `DriveService.delete_items`.
fn delete_payload(id: &str, etag: &str, client_id: &str) -> Value {
    json!({"items": [{"drivewsid": id, "etag": etag, "clientId": client_id}]})
}

/// `POST /renameItems` body, mirroring pyicloud `DriveService.rename_items`.
fn rename_payload(id: &str, etag: &str, name: &str) -> Value {
    json!({"items": [{"drivewsid": id, "etag": etag, "name": name}]})
}

/// `POST /moveItems` body. Python uses the node id as `clientId` for moves.
fn move_payload(destination: &str, id: &str, etag: &str) -> Value {
    json!({
        "destinationDrivewsId": destination,
        "items": [{"drivewsid": id, "etag": etag, "clientId": id}],
    })
}

/// Build the exact multipart body Python sends for a content-WS upload:
/// a single field named after the file, with the filename set to the same
/// value and no per-part `Content-Type` (urllib3 omits it when requests is
/// given `files={name: file_object}`).
fn upload_form(name: &str, content: Vec<u8>) -> reqwest::multipart::Form {
    let part = reqwest::multipart::Part::bytes(content).file_name(name.to_string());
    reqwest::multipart::Form::new().part(name.to_string(), part)
}

/// Mirror of pyicloud's `DriveService._update_contentws`: the new document is
/// chained to its parent by **docwsid**, and `path.path` is the basename.
fn add_file_payload(
    parent_doc_id: &str,
    name: &str,
    document_id: &str,
    mtime: i64,
    file_info: &Value,
) -> Value {
    let mut data = json!({
        "data": {
            "signature": file_info.get("fileChecksum").cloned().unwrap_or(Value::Null),
            "wrapping_key": file_info.get("wrappingKey").cloned().unwrap_or(Value::Null),
            "reference_signature": file_info.get("referenceChecksum").cloned().unwrap_or(Value::Null),
            "size": file_info.get("size").cloned().unwrap_or(Value::Null),
        },
        "command": "add_file",
        "create_short_guid": true,
        "document_id": document_id,
        "path": {
            "starting_document_id": parent_doc_id,
            "path": file_basename(name),
        },
        "allow_conflict": true,
        "file_flags": {"is_writable": true, "is_executable": false, "is_hidden": false},
        "mtime": mtime * 1000,
        "btime": mtime * 1000,
    });
    // Absent for zero-byte files; Python only adds the key when truthy.
    if let Some(receipt) = file_info.get("receipt")
        && json_is_truthy(receipt)
    {
        data["data"]["receipt"] = receipt.clone();
    }
    data
}

/// Identity returned by `/update/documents` after a successful add.
#[derive(Debug, Clone)]
pub struct UploadedDocument {
    pub docwsid: String,
    pub etag: Option<String>,
    pub zone: Option<String>,
}

/// `POST /update/documents` answers with
/// `{"results":[{"document":{"document_id":…,"etag":…,"zone":…}}],"status":…}`.
/// It has no top-level `drivewsid`, so callers must read the nested document
/// (or refresh the parent's children like the Python reference does).
pub fn uploaded_document(response: &Value) -> Option<UploadedDocument> {
    let document = response.get("results")?.get(0)?.get("document")?;
    let docwsid = document.get("document_id")?.as_str()?.to_string();
    Some(UploadedDocument {
        docwsid,
        etag: document
            .get("etag")
            .and_then(Value::as_str)
            .map(str::to_string),
        zone: document
            .get("zone")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

/// Python truthiness for JSON values, used for the optional upload receipt.
fn json_is_truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64().is_none_or(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        Value::Bool(true) => true,
    }
}

/// Python uses `os.path.basename(file_object.name)` for the path component.
/// The watcher already passes a basename; applying it here too keeps the
/// payload correct when callers pass a fuller name.
fn file_basename(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

fn paths_secure_dir(path: &std::path::Path) -> Result<()> {
    crate::paths::create_secure_dir(path)
}

/// Python sends Origin/Referer on every request through its session defaults.
/// Apple's Drive endpoints answer HTTP 421 without them, which our status
/// bridge reports as "sign in required" even for a valid, trusted session.
fn default_request_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ORIGIN, "https://www.icloud.com".parse().unwrap());
    headers.insert(REFERER, "https://www.icloud.com/".parse().unwrap());
    headers
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn update_session_from_headers(response: &Response, session: &Arc<RwLock<SessionData>>) {
    const FIELDS: &[(&str, &str)] = &[
        ("X-Apple-ID-Account-Country", "account_country"),
        ("X-Apple-ID-Session-Id", "session_id"),
        ("X-Apple-Auth-Attributes", "auth_attributes"),
        ("X-Apple-Session-Token", "session_token"),
        ("X-Apple-TwoSV-Trust-Token", "trust_token"),
        ("X-Apple-OAuth-Grant-Code", "grant_code"),
        ("scnt", "scnt"),
    ];
    let mut data = session.write().unwrap();
    for (header, field) in FIELDS {
        if let Some(value) = response
            .headers()
            .get(*header)
            .and_then(|v| v.to_str().ok())
        {
            match *field {
                "account_country" => data.account_country = Some(value.into()),
                "session_id" => data.session_id = Some(value.into()),
                "auth_attributes" => data.auth_attributes = Some(value.into()),
                "session_token" => data.session_token = Some(value.into()),
                "trust_token" => data.trust_token = Some(value.into()),
                "grant_code" => data.grant_code = Some(value.into()),
                "scnt" => data.scnt = Some(value.into()),
                _ => {}
            }
        }
    }
    if data.client_id.is_none() {
        data.client_id = Some(Uuid::new_v4().to_string());
    }
}

async fn probe_endpoint(client: &Client) -> Result<String> {
    let response = client
        .post("https://setup.icloud.com/setup/ws/1/validate")
        .header("Origin", "https://www.icloud.com")
        .header("Referer", "https://www.icloud.com/")
        .header("User-Agent", USER_AGENT)
        .json(&json!({}))
        .send()
        .await?;
    let partition = response
        .headers()
        .get("x-apple-user-partition")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    Ok(match partition {
        Some(partition) if partition.chars().all(|c| c.is_ascii_alphanumeric()) => {
            format!("https://p{partition}-setup.icloud.com/setup/ws/1")
        }
        _ => "https://setup.icloud.com/setup/ws/1".into(),
    })
}

fn read_session_file(path: &std::path::Path) -> Result<SessionData> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

/// Decode a value from an LWP (`Set-Cookie3:`) cookie file. Apple's web-auth
/// cookies carry literal leading/trailing quotes as part of the value, which
/// LWP stores as `name="\"value\""`. Only the outer quotes are syntax; the
/// escaped inner quotes belong to the token. Stripping those literal quotes
/// (as older IC-SYNC releases did) corrupts the cookie and Apple answers every
/// Drive call with HTTP 421, which looks like an expired login.
fn unquote_cookie_value(raw: &str) -> String {
    let trimmed = raw.trim();
    let body = if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next().unwrap_or('\\'));
        } else {
            out.push(ch);
        }
    }
    out
}

/// LWP-escaped form of a cookie value, so the value round-trips through both
/// our reader and Python's `LWPCookieJar` exactly.
fn quote_cookie_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        if ch == '"' || ch == '\\' {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

fn is_apple_auth_cookie(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("X-APPLE-") || upper.starts_with("X_APPLE_WEB_KB-")
}

fn read_cookie_file(path: &std::path::Path) -> Result<HashMap<String, String>> {
    let raw = fs::read_to_string(path)?;
    let lines: Vec<_> = raw
        .lines()
        .filter(|line| line.starts_with("Set-Cookie3: "))
        .collect();
    // Compatibility for cookie files written by older IC-SYNC builds: they
    // used one fixed attribute suffix for every cookie and stripped the
    // literal quotes from Apple's auth cookie values. Only that exact shape is
    // repaired, so a correctly written file is never rewritten heuristically.
    let legacy = !lines.is_empty()
        && lines
            .iter()
            .all(|line| line.contains("domain=.icloud.com; path_spec; secure; discard; version=0"));
    let mut jar = HashMap::new();
    for line in lines {
        let Some((name, value)) = line.trim_start_matches("Set-Cookie3: ").split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = unquote_cookie_value(value.split(';').next().unwrap_or_default());
        let value = if legacy
            && is_apple_auth_cookie(name)
            && !(value.starts_with('"') && value.ends_with('"'))
        {
            // The quotes were part of the original token; restore them.
            format!("\"{value}\"")
        } else {
            value
        };
        jar.insert(name.to_string(), value);
    }
    Ok(jar)
}

fn guess_content_type(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "md" | "log" | "json" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn url_encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

pub fn b64(data: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(data.as_ref())
}

pub fn unb64(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| Error::other(format!("invalid base64: {error}")))
}

/// Exposes the content-WS payload builder to engine tests that verify the
/// parent document id used for uploads.
#[cfg(test)]
pub(crate) fn add_file_payload_for_test(
    parent_doc_id: &str,
    name: &str,
    document_id: &str,
    mtime: i64,
    file_info: &Value,
) -> Value {
    add_file_payload(parent_doc_id, name, document_id, mtime, file_info)
}

/// In-memory API used only by state-transition tests; never touches the
/// network or the user's credential files.
#[cfg(test)]
pub(crate) fn test_api(data: Value, session: SessionData, mfa_pending: bool) -> ICloudApi {
    ICloudApi {
        client: Client::new(),
        session: Arc::new(RwLock::new(session)),
        data: Arc::new(RwLock::new(data)),
        cookies: Arc::new(RwLock::new(HashMap::new())),
        cookie_path: PathBuf::from("/tmp/ic-core-test.cookiejar"),
        session_path: PathBuf::from("/tmp/ic-core-test.session"),
        auth_endpoint: "https://idmsa.apple.com/appleauth/auth".into(),
        setup_endpoint: "https://setup.icloud.com/setup/ws/1".into(),
        home_endpoint: "https://www.icloud.com".into(),
        mfa_pending: Arc::new(RwLock::new(mfa_pending)),
        bridge: Arc::new(Mutex::new(None)),
        offline: Arc::new(RwLock::new(None)),
        credential_key: "ic-core-test".into(),
        credential_mode: config::CredentialMode::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn apple_cookie_quotes_survive_lwp_round_trip() {
        // Python's jar stores the outer quotes as part of the token value.
        let value = "\"eyJhbGciOi...\"";
        let encoded = quote_cookie_value(value);
        assert_eq!(encoded, "\"\\\"eyJhbGciOi...\\\"\"");
        assert_eq!(unquote_cookie_value(&encoded), value);
    }

    #[test]
    fn lwp_cookie_file_keeps_apple_auth_cookie_quotes() {
        let dir = TempDir::new();
        let path = dir.path.join("cookies");
        fs::write(
            &path,
            "#LWP-Cookies-2.0\n\
             Set-Cookie3: X-APPLE-WEBAUTH-TOKEN=\"\\\"token\\\"\"; path=\"/\"; \
             domain=.icloud.com; path_spec; domain_dot; secure; \
             expires=\"2027-01-01 00:00:00Z\"; version=0\n",
        )
        .unwrap();
        let jar = read_cookie_file(&path).unwrap();
        assert_eq!(
            jar.get("X-APPLE-WEBAUTH-TOKEN").map(String::as_str),
            Some("\"token\"")
        );
    }

    #[test]
    fn legacy_cookie_file_is_repaired_on_load() {
        let dir = TempDir::new();
        let path = dir.path.join("cookies");
        // Exact shape written by older IC-SYNC releases: one attribute suffix
        // for every cookie and the literal token quotes already stripped.
        fs::write(
            &path,
            "#LWP-Cookies-2.0\n\
             Set-Cookie3: X-APPLE-WEBAUTH-TOKEN=token; path=\"/\"; \
             domain=.icloud.com; path_spec; secure; discard; version=0\n\
             Set-Cookie3: site=abc; path=\"/\"; \
             domain=.icloud.com; path_spec; secure; discard; version=0\n",
        )
        .unwrap();
        let jar = read_cookie_file(&path).unwrap();
        assert_eq!(
            jar.get("X-APPLE-WEBAUTH-TOKEN").map(String::as_str),
            Some("\"token\"")
        );
        assert_eq!(jar.get("site").map(String::as_str), Some("abc"));
        // The repaired jar must round-trip to a valid LWP file.
        let encoded = quote_cookie_value(jar.get("X-APPLE-WEBAUTH-TOKEN").unwrap());
        assert_eq!(encoded, "\"\\\"token\\\"\"");
    }

    #[test]
    fn default_request_headers_match_python_session() {
        let headers = default_request_headers();
        assert_eq!(headers.get(ORIGIN).unwrap(), "https://www.icloud.com");
        assert_eq!(headers.get(REFERER).unwrap(), "https://www.icloud.com/");
    }

    #[test]
    fn remote_node_composes_extension_like_pyicloud() {
        // An empty name falls back to the id, then still gets the extension.
        let node = RemoteNode::from_value(&json!({
            "name": "",
            "extension": "txt",
            "drivewsid": "FILE::fallback",
        }));
        assert_eq!(node.name, "FILE::fallback.txt");

        // Nested nodes are composed too (the crawl uses items recursively).
        let parent = RemoteNode::from_value(&json!({
            "name": "Docs",
            "type": "folder",
            "drivewsid": "FOLDER::docs",
            "items": [{"name": "Scanned Document", "extension": "pdf", "type": "file"}],
        }));
        assert_eq!(
            parent.items.as_ref().unwrap()[0].name,
            "Scanned Document.pdf"
        );

        // No extension key: the bare name is preserved.
        let node = RemoteNode::from_value(&json!({"name": "Folder", "type": "folder"}));
        assert_eq!(node.name, "Folder");
        assert_eq!(node.extension, None);

        // Already-qualified names are not doubled.
        let node = RemoteNode::from_value(&json!({"name": "note.txt", "extension": "txt"}));
        assert_eq!(node.name, "note.txt");
    }

    #[test]
    fn remote_node_display_name_is_a_single_component() {
        // Apple returns some app-library names as a full drivewsid.
        let node = RemoteNode::from_value(&json!({
            "name": "FOLDER::com.apple.TextInput::documents",
            "type": "app_library",
            "drivewsid": "FOLDER::com.apple.TextInput::documents",
        }));
        assert_eq!(
            node.display_name(),
            "FOLDER::com.apple.TextInput::documents"
        );

        // A name that smuggles in a parent path is reduced to its basename.
        let node = RemoteNode::from_value(&json!({
            "name": "/Parent/Child",
            "type": "folder",
            "drivewsid": "FOLDER::child",
        }));
        assert_eq!(node.display_name(), "Child");
        let node = RemoteNode::from_value(&json!({
            "name": "Parent\\Child",
            "type": "folder",
            "drivewsid": "FOLDER::child",
        }));
        assert_eq!(node.display_name(), "Child");

        // The root node has an empty name; fall back to its id, still one level.
        let node = RemoteNode::from_value(&json!({
            "name": "",
            "type": "folder",
            "drivewsid": ROOT_DRIVEWSID,
        }));
        assert_eq!(node.display_name(), ROOT_DRIVEWSID);
        assert_eq!(safe_node_name("///"), None);
        assert_eq!(safe_node_name(".."), None);
    }

    #[test]
    fn rename_delete_move_payloads_match_python_drivews_calls() {
        let delete = delete_payload("FILE::42", "etag-1", "client-9");
        assert_eq!(
            delete,
            json!({"items": [{"drivewsid": "FILE::42", "etag": "etag-1", "clientId": "client-9"}]})
        );
        let rename = rename_payload("FILE::42", "etag-1", "renamed.txt");
        assert_eq!(
            rename,
            json!({"items": [{"drivewsid": "FILE::42", "etag": "etag-1", "name": "renamed.txt"}]})
        );
        let moved = move_payload("FOLDER::dest", "FILE::42", "etag-1");
        assert_eq!(
            moved,
            json!({
                "destinationDrivewsId": "FOLDER::dest",
                "items": [{"drivewsid": "FILE::42", "etag": "etag-1", "clientId": "FILE::42"}],
            })
        );
    }

    #[test]
    fn add_file_payload_matches_python_contentws_shape() {
        let receipt = json!({
            "fileChecksum": "checksum",
            "wrappingKey": "wrapping",
            "referenceChecksum": "reference",
            "size": 1234,
            "receipt": "receipt-data",
        });
        let payload = add_file_payload(
            "BAA2B1DA-B402-4E55-A97B-F69BBE6CE9F3",
            "ic-sync-upload-test.txt",
            "DOCUMENT-ID",
            1_795_451_883,
            &receipt,
        );

        // Apple rejects a drivewsid here with 412 VALIDATING_REFERENCE_ERROR.
        assert_eq!(
            payload["path"]["starting_document_id"],
            "BAA2B1DA-B402-4E55-A97B-F69BBE6CE9F3"
        );
        assert_eq!(payload["path"]["path"], "ic-sync-upload-test.txt");
        assert_eq!(payload["command"], "add_file");
        assert_eq!(payload["create_short_guid"], true);
        assert_eq!(payload["document_id"], "DOCUMENT-ID");
        assert_eq!(payload["allow_conflict"], true);
        assert_eq!(payload["file_flags"]["is_writable"], true);
        assert_eq!(payload["mtime"], 1_795_451_883_000_i64);
        assert_eq!(payload["btime"], 1_795_451_883_000_i64);
        assert_eq!(payload["data"]["signature"], "checksum");
        assert_eq!(payload["data"]["wrapping_key"], "wrapping");
        assert_eq!(payload["data"]["reference_signature"], "reference");
        assert_eq!(payload["data"]["size"], 1234);
        assert_eq!(payload["data"]["receipt"], "receipt-data");
    }

    #[test]
    fn add_file_payload_uses_basename_and_root_docwsid() {
        let payload = add_file_payload(
            ROOT_DOCWSID,
            "/Docs/ic-sync-upload-test.txt",
            "DOC",
            1,
            &json!({"fileChecksum": "", "wrappingKey": "", "referenceChecksum": "", "size": 0, "receipt": ""}),
        );
        assert_eq!(payload["path"]["starting_document_id"], ROOT_DOCWSID);
        assert_eq!(payload["path"]["path"], "ic-sync-upload-test.txt");
        // Python omits a falsy receipt.
        assert!(payload["data"].get("receipt").is_none());
    }

    #[test]
    fn uploaded_document_is_read_from_nested_update_response() {
        let response = json!({
            "results": [{
                "document": {
                    "document_id": "3AADC7EA-F48A-4D88-94C9-515096DFA566",
                    "etag": "14m1::14m0",
                    "zone": "com.apple.CloudDocs",
                    "item_id": "CLXZ8uBKEAAiEC1jc1PA4EDAuVNhXXlFI7Q"
                },
                "operation_id": "op",
                "status": "success"
            }],
            "status": {"status_code": 0, "error_message": ""}
        });
        let document = uploaded_document(&response).unwrap();
        assert_eq!(document.docwsid, "3AADC7EA-F48A-4D88-94C9-515096DFA566");
        assert_eq!(document.etag.as_deref(), Some("14m1::14m0"));
        assert_eq!(document.zone.as_deref(), Some(CLOUD_DOCS_ZONE));
        assert!(uploaded_document(&json!({"status": {"status_code": 0}})).is_none());
    }

    #[tokio::test]
    async fn multipart_body_matches_python_requests_upload() {
        use futures_util::TryStreamExt;

        let form = upload_form("ic-sync-upload-test.txt", b"hello world".to_vec());
        let boundary = form.boundary().to_string();
        let body = form
            .into_stream()
            .try_fold(Vec::new(), |mut body, chunk| async move {
                body.extend_from_slice(&chunk);
                Ok(body)
            })
            .await
            .unwrap();
        let text = String::from_utf8(body).unwrap();

        assert!(text.starts_with(&format!("--{boundary}\r\n")));
        assert!(text.contains(
            "Content-Disposition: form-data; name=\"ic-sync-upload-test.txt\"; \
             filename=\"ic-sync-upload-test.txt\"\r\n"
        ));
        // requests/urllib3 omit a per-part Content-Type when none is supplied.
        assert!(!text.contains("Content-Type:"));
        assert!(text.contains("\r\n\r\nhello world\r\n"));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
    }
}
