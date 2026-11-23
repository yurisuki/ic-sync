//! Minimal native client for the Apple iCloud web services used by iCloud Drive.
//!
//! Request shapes mirror the reference implementation so existing sessions,
//! cookies and account shards keep working. Secret material is mirrored to the
//! OS credential store; the compatibility files are written atomically with
//! 0600 permissions on Unix.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use base64::Engine;
use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, SET_COOKIE};
use reqwest::{Client, ClientBuilder, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{self, Config, SecretKind, atomic_write, credential_key};
use crate::error::{Error, Result};

pub const ROOT_DRIVEWSID: &str = "FOLDER::com.apple.CloudDocs::root";
pub const CLOUD_DOCS_ZONE: &str = "com.apple.CloudDocs";
const CLIENT_BUILD_NUMBER: &str = "2534Project66";
const CLIENT_MASTERING_NUMBER: &str = "2534B22";
const OAUTH_CLIENT_ID: &str = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
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
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                value.get("extension").and_then(Value::as_str).map(|ext| {
                    format!(
                        "{}.{ext}",
                        value
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                    )
                })
            })
            .unwrap_or_else(|| {
                value
                    .get("drivewsid")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>")
                    .to_string()
            });
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
    offline: Arc<RwLock<Option<String>>>,
    credential_key: String,
    /// Secure mode mirrors tokens into the OS keyring; plain mode keeps them
    /// only in the local 0600 session/cookie files.
    credential_mode: config::CredentialMode,
}

impl ICloudApi {
    pub async fn new(config: &Config) -> Result<Self> {
        let client = ClientBuilder::new().user_agent(USER_AGENT).build()?;
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

    pub fn capture(&self, response: &Response) {
        let mut changed = false;
        {
            let mut jar = self.cookies.write().unwrap();
            for values in response.headers().get_all(SET_COOKIE).iter() {
                let Ok(text) = values.to_str() else { continue };
                if let Some((name, rest)) = text.split_once('=') {
                    let value = rest
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .trim_matches('"');
                    if jar.get(name).map(String::as_str) != Some(value) {
                        jar.insert(name.trim().to_string(), value.to_string());
                        changed = true;
                    }
                }
            }
        }
        if changed {
            let _ = self.persist();
        }
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
                name, jar[name]
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
                    .post(format!("{}/accountLogin", self.setup_endpoint)),
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
            .json(&json!({"items": [{"drivewsid": id, "etag": etag, "clientId": client_id}]}))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    pub async fn rename_node(&self, id: &str, etag: &str, name: &str) -> Result<()> {
        let url = format!("{}/renameItems", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&json!({"items": [{"drivewsid": id, "etag": etag, "name": name}]}))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    pub async fn move_node(&self, id: &str, etag: &str, destination: &str) -> Result<()> {
        let url = format!("{}/moveNodesToNode", self.webservice_url("drivews")?);
        let response = self
            .with_cookies(self.client.post(url).query(&self.params()))
            .json(&json!({
                "destinationDrivewsId": destination,
                "items": [{"drivewsid": id, "etag": etag, "clientId": id}],
            }))
            .send()
            .await?;
        self.checked(response).await?;
        Ok(())
    }

    /// Upload a complete file to the iCloud Drive content service.
    pub async fn upload(
        &self,
        folder_id: &str,
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
                    .post(format!("{document_root}/ws/{CLOUD_DOCS_ZONE}/upload/web"))
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

        let part = reqwest::multipart::Part::bytes(content).file_name(name.to_string());
        let response = self
            .with_cookies(self.client.post(&upload_url))
            .multipart(reqwest::multipart::Form::new().part(name.to_string(), part))
            .send()
            .await?;
        let receipt: Value = self.checked(response).await?.json().await?;
        let file_info = receipt
            .get("singleFile")
            .ok_or_else(|| Error::other("upload receipt had no singleFile"))?;
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
            "path": {"starting_document_id": folder_id, "path": name},
            "allow_conflict": true,
            "file_flags": {"is_writable": true, "is_executable": false, "is_hidden": false},
            "mtime": mtime * 1000,
            "btime": mtime * 1000,
        });
        if let Some(receipt_value) = file_info.get("receipt") {
            data["data"]["receipt"] = receipt_value.clone();
        }
        let response = self
            .with_cookies(
                self.client
                    .post(format!(
                        "{document_root}/ws/{CLOUD_DOCS_ZONE}/update/documents"
                    ))
                    .query(&self.params()),
            )
            .header(CONTENT_TYPE, "text/plain")
            .json(&data)
            .send()
            .await?;
        Ok(self.checked(response).await?.json().await?)
    }
}

fn paths_secure_dir(path: &std::path::Path) -> Result<()> {
    crate::paths::create_secure_dir(path)
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

fn read_cookie_file(path: &std::path::Path) -> Result<HashMap<String, String>> {
    let mut jar = HashMap::new();
    for line in fs::read_to_string(path)?.lines() {
        let Some(rest) = line.strip_prefix("Set-Cookie3: ") else {
            continue;
        };
        if let Some((name, value)) = rest.split_once('=') {
            jar.insert(
                name.trim().to_string(),
                value
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
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
