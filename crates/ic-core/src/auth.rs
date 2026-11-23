//! Native Apple ID authentication: SRP-6a with SHA-256 and interactive 2FA.
//!
//! The maths mirrors pyicloud's `srp` package: RFC 5054 2048-bit group,
//! fixed-width big-endian padding for hashed integers, `no_username_in_x`,
//! and the `s2k` / `s2k_fo` password derivations.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::api::{ICloudApi, b64, unb64};
use crate::bridge;
use crate::error::{Error, Result};

const OAUTH_CLIENT_ID: &str = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";

const N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    pub force_sms: bool,
    pub trust_token: Option<String>,
    pub accept_terms: bool,
}

/// The 2FA route selected by [`authenticate`]. The GUI must pass the same
/// value back to [`submit_code`], otherwise the code is sent to the wrong
/// Apple endpoint (which produces `-21669 Incorrect Verification Code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoFactorRoute {
    /// Legacy trusted-device code (`/verify/trusteddevice/securitycode`).
    TrustedDeviceLegacy,
    /// Newer HSA2 bridge/APNS flow. `authenticate()` opens the WSS bridge and
    /// keeps the session on `ICloudApi`; `submit_code()` drives the prover
    /// exchange over that retained session.
    TrustedDeviceBridge,
    Sms,
    SecurityKey,
}

impl TwoFactorRoute {
    /// Distinct canonical value for logs and callers that need the detail.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrustedDeviceLegacy => "trusted_device_legacy",
            Self::TrustedDeviceBridge => "trusted_device_bridge",
            Self::Sms => "sms",
            Self::SecurityKey => "security_key",
        }
    }

    /// Value used for the existing `AuthStep::method` string, kept stable for
    /// GUI compatibility (both device variants report `trusted_device`).
    pub fn method(self) -> &'static str {
        match self {
            Self::TrustedDeviceLegacy | Self::TrustedDeviceBridge => "trusted_device",
            Self::Sms => "sms",
            Self::SecurityKey => "security_key",
        }
    }

    /// True for either trusted-device variant.
    pub fn is_trusted_device(self) -> bool {
        matches!(self, Self::TrustedDeviceLegacy | Self::TrustedDeviceBridge)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStep {
    Authenticated,
    TwoFactorRequired {
        method: String,
        hint: Option<String>,
        route: TwoFactorRoute,
    },
}

pub async fn authenticate(
    api: &ICloudApi,
    username: &str,
    password: &str,
    options: &AuthOptions,
) -> Result<AuthStep> {
    if let Some(token) = &options.trust_token {
        api.session.write().unwrap().trust_token = Some(token.clone());
        api.login_with_token().await?;
        return Ok(AuthStep::Authenticated);
    }

    srp_signin(api, username, password).await?;
    if !api.requires_2fa() && api.is_authenticated() && api.is_trusted() {
        // The session/trust tokens were captured from Apple's responses; save
        // them now so the next launch can restore the session automatically.
        if let Err(error) = api.persist() {
            warn!("could not persist Apple session: {error}");
        }
        return Ok(AuthStep::Authenticated);
    }

    // This response refreshes the scnt/session-id headers used below. Select
    // the route once here; submit_code must replay exactly this decision.
    let auth_options = fetch_auth_options(api).await?;
    let mut route = select_route(&auth_options, options.force_sms);
    // A new challenge invalidates any bridge socket left over from an earlier
    // attempt (for example a user who switched verification method).
    api.clear_bridge_session();
    if route == TwoFactorRoute::TrustedDeviceBridge {
        // The phone prompt is caused by POST /bridge/step/0, which can only be
        // issued after the WSS bridge handshake yields a push token. Do this
        // here, while the SRP session is fresh, and keep the socket alive for
        // submit_code().
        match bridge::start(api, &auth_options).await {
            Ok(session) => api.set_bridge_session(session),
            Err(error) => {
                warn!("trusted-device bridge bootstrap failed: {error}");
                if can_request_sms(&auth_options) {
                    request_sms(api, &auth_options).await?;
                    route = TwoFactorRoute::Sms;
                } else {
                    return Err(Error::TwoFactor(format!(
                        "Apple requested a trusted-device prompt, but the secure bridge could \
                         not be started ({error}). Approve the prompt on your device and sign \
                         in again, or choose SMS verification if it is available."
                    )));
                }
            }
        }
    } else {
        request_default_code(api, &auth_options, route).await?;
    }
    let method = route.method().to_string();
    Ok(AuthStep::TwoFactorRequired {
        method,
        hint: phone_hint(&auth_options),
        route,
    })
}

pub async fn submit_code(
    api: &ICloudApi,
    code: &str,
    route: TwoFactorRoute,
    accept_terms: bool,
) -> Result<AuthStep> {
    let options = fetch_auth_options(api).await?;
    // `route` comes from authenticate(); never re-detect it here, or an SMS
    // challenge can be answered on the trusted-device endpoint.
    let mut headers = api.auth_headers();
    let accept = if route == TwoFactorRoute::Sms {
        "application/json, plain/text"
    } else {
        "application/json"
    };
    headers.insert(ACCEPT, accept.parse().unwrap());
    add_origin(&mut headers);

    let mut effective_route = route;
    let mut bridge_done = false;
    if route == TwoFactorRoute::TrustedDeviceBridge {
        match api.take_bridge_session() {
            Some(bridge_session) if !bridge_session.uses_legacy_verifier() => {
                // validate_code closes the websocket whether it succeeds or
                // fails; the session is never reused for a second code.
                let verified = bridge::validate_code(api, bridge_session, code, &headers).await?;
                if !verified {
                    return Err(invalid_code_error(route, false));
                }
                bridge_done = true;
            }
            Some(_) => {
                // Apple's `_W` txnid routes the challenge to the legacy device
                // verifier, which accepts the plain code on its own endpoint.
                effective_route = TwoFactorRoute::TrustedDeviceLegacy;
            }
            None if has_legacy_verifier(&options) => {
                effective_route = TwoFactorRoute::TrustedDeviceLegacy;
            }
            None => {
                return Err(Error::TwoFactor(
                    "The trusted-device bridge session was lost during sign-in. Start sign-in \
                     again to re-arm the device prompt."
                        .into(),
                ));
            }
        }
    }

    if !bridge_done {
        let (url, payload) =
            verification_request(&api.auth_endpoint, effective_route, code, &options)?;
        let response = api
            .with_cookies(
                api.client
                    .post(url)
                    .headers(headers.clone())
                    .header(CONTENT_TYPE, "application/json"),
            )
            .json(&payload)
            .send()
            .await?;
        api.capture(&response);
        let status = response.status().as_u16();
        if status == 409 {
            // pyicloud also treats 409 as success when securityCode.valid is true.
            let body: Value = response.json().await.unwrap_or(Value::Null);
            if !verification_accepted(status, &body) {
                return Err(invalid_code_error(effective_route, false));
            }
        } else {
            match api.checked(response).await {
                Ok(_) => {}
                Err(Error::TwoFactor(_)) => {
                    return Err(invalid_code_error(effective_route, false));
                }
                Err(Error::AppleApi {
                    status: 400,
                    message,
                }) => {
                    // Apple echoes `-21669` in `service_errors`/`serviceErrors`.
                    // Parse it but never surface the raw HTTP body to the GUI.
                    let rejected = serde_json::from_str::<Value>(&message)
                        .map(|body| is_code_rejected(&body))
                        .unwrap_or(true);
                    return Err(invalid_code_error(effective_route, rejected));
                }
                Err(error) => return Err(error),
            }
        }
    }

    // Mirror Python's trust_session() postcondition: a genuinely accepted code
    // must end with data.dsInfo present, hsaTrustedBrowser == true, no
    // hsaChallengeRequired and no pending MFA. The reference driver and auth
    // CLI run the trust cycle a second time when the first accountLogin still
    // reports an untrusted browser (driver.py:1668-1671, auth.py:127-132).
    for _ in 0..2 {
        match finish_trusted_login(api, &headers).await {
            Ok(()) => {}
            Err(error) if error.is_auth() => {
                // login_with_token persists the refreshed data before it
                // raises, so the second attempt starts from fresh state.
                let _ = error;
            }
            Err(error) => return Err(error),
        }
        if session_ready(api) {
            if accept_terms {
                accept_terms_if_needed(api).await?;
            }
            return Ok(AuthStep::Authenticated);
        }
    }

    Err(Error::TwoFactor(format!(
        "iCloud did not mark this session as trusted after the verification code. \
         Start sign-in again and enter a fresh code. [{}]",
        api.auth_diagnostics()
    )))
}

/// One Python-style `trust_session()` cycle: clear the pending-MFA marker,
/// trust the browser, then re-run accountLogin with the session token.
async fn finish_trusted_login(api: &ICloudApi, headers: &HeaderMap) -> Result<()> {
    // Python sets `_requires_mfa = False` on every trust attempt, not just the
    // first. A 409 from /2sv/trust sets it again; the next attempt clears it.
    *api.mfa_pending.write().unwrap() = false;

    let response = api
        .with_cookies(
            api.client
                .get(format!("{}/2sv/trust", api.auth_endpoint))
                .headers(headers.clone()),
        )
        .send()
        .await?;
    api.checked(response)
        .await
        .map_err(|_| Error::TwoFactor("Apple did not accept 2sv/trust".into()))?;

    api.login_with_token().await.map_err(|error| match error {
        // Never surface Apple's raw error body: it can echo token material.
        Error::AppleApi { status, .. } => {
            Error::Auth(format!("accountLogin after 2FA failed (HTTP {status})"))
        }
        Error::Http(_) => Error::Offline("accountLogin after 2FA was unreachable".into()),
        other => other,
    })
}

/// The exact postcondition the Python reference expects after 2FA.
fn session_ready(api: &ICloudApi) -> bool {
    api.is_authenticated() && api.is_trusted() && !api.requires_2fa()
}

async fn srp_signin(api: &ICloudApi, username: &str, password: &str) -> Result<()> {
    let headers = api.auth_headers();
    let client_id = api
        .session
        .read()
        .unwrap()
        .client_id
        .clone()
        .unwrap_or_default();
    let response = api
        .with_cookies(
            api.client
                .get(format!("{}/authorize/signin", api.auth_endpoint))
                .headers(headers.clone()),
        )
        .query(&[
            ("frame_id", client_id.as_str()),
            ("skVersion", "7"),
            ("iframeid", client_id.as_str()),
            ("client_id", OAUTH_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", "https://www.icloud.com"),
            ("response_mode", "web_message"),
            ("state", client_id.as_str()),
            ("authVersion", "latest"),
        ])
        .send()
        .await?;
    api.checked(response).await?;

    let mut rng = rand::rng();
    let mut secret = [0u8; 256];
    rng.fill_bytes(&mut secret);
    secret[0] |= 0x80;
    let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16)
        .ok_or_else(|| Error::other("bad SRP group constants"))?;
    let g = BigUint::one() + BigUint::one();
    let a = BigUint::from_bytes_be(&secret);
    let big_a = g.modpow(&a, &n);

    // pyicloud enables rfc5054: H(N,g) and u use fixed-width big-endian ints.
    // The public A itself is sent unpadded (srp.User.start_authentication).
    let width = n.to_bytes_be().len();
    let response = api
        .with_cookies(
            api.client
                .post(format!("{}/signin/init", api.auth_endpoint))
                .headers(headers.clone()),
        )
        .json(&json!({
            "a": b64(bigint_bytes(&big_a, None)),
            "accountName": username,
            "protocols": ["s2k", "s2k_fo"],
        }))
        .send()
        .await?;
    // `signin/init` failures are frequently Apple throttling, not bad
    // credentials. Classify them before reporting anything to the user.
    api.capture(&response);
    let status = response.status().as_u16();
    if (500..600).contains(&status) {
        return Err(srp_throttled(&format!("HTTP {status}")));
    }
    if status == 400 {
        return Err(srp_throttled("HTTP 400"));
    }
    if status == 409 {
        *api.mfa_pending.write().unwrap() = true;
        return Err(Error::TwoFactor(
            "Apple requires two-factor authentication".into(),
        ));
    }
    if status == 421 {
        *api.data.write().unwrap() = Value::Null;
        return Err(Error::Auth("Apple session token expired (421)".into()));
    }
    if status == 401 || status == 403 {
        return Err(Error::Auth("Apple rejected the sign-in credentials".into()));
    }
    if !(200..300).contains(&status) {
        return Err(Error::other(format!(
            "Apple sign-in request failed (HTTP {status})"
        )));
    }
    let body: Value = response.json().await?;
    if let Some(error) = srp_service_error(&body) {
        return Err(error);
    }
    let salt = unb64(get_str(&body, "salt")?)?;
    let big_b = BigUint::from_bytes_be(&unb64(get_str(&body, "b")?)?);
    let iterations = srp_iterations(&body)?;
    let protocol = get_str(&body, "protocol")?;
    let client_c = body.get("c").cloned().unwrap_or(Value::Null);

    if (&big_b % &n).is_zero() {
        return Err(Error::Auth(
            "SRP server sent an invalid public value".into(),
        ));
    }

    let password_digest = Sha256::digest(password.as_bytes());
    let derived = match protocol {
        "s2k_fo" => {
            let text = hex(&password_digest);
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(text.as_bytes(), &salt, iterations, &mut out);
            out
        }
        "s2k" => {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(&password_digest, &salt, iterations, &mut out);
            out
        }
        other => return Err(Error::other(format!("unsupported SRP protocol: {other}"))),
    };

    // x = H(salt | H("" | ":" | derived)): pyicloud calls no_username_in_x().
    let inner = sha256(&[b":".as_slice(), derived.as_slice()].concat());
    let x = BigUint::from_bytes_be(&sha256(&[salt.as_slice(), inner.as_slice()].concat()));
    let v = g.modpow(&x, &n);
    let k = BigUint::from_bytes_be(&sha256(
        &[bigint_bytes(&n, Some(width)), bigint_bytes(&g, Some(width))].concat(),
    ));
    let u = BigUint::from_bytes_be(&sha256(
        &[
            bigint_bytes(&big_a, Some(width)),
            bigint_bytes(&big_b, Some(width)),
        ]
        .concat(),
    ));
    if u.is_zero() {
        return Err(Error::Auth(
            "SRP shared scrambling parameter was zero".into(),
        ));
    }
    let kv = (k.clone() * &v) % &n;
    let base = if big_b >= kv {
        &big_b - &kv
    } else {
        &big_b + &n - &kv
    };
    let exponent = &a + &u * &x;
    let s = base.modpow(&exponent, &n);
    let key = sha256(&bigint_bytes(&s, None));

    let mut m_input = Vec::new();
    m_input.extend_from_slice(&hnxorg(&n, &g, Some(width)));
    m_input.extend_from_slice(&sha256(username.as_bytes()));
    m_input.extend_from_slice(&salt);
    m_input.extend_from_slice(&bigint_bytes(&big_a, None));
    m_input.extend_from_slice(&bigint_bytes(&big_b, None));
    m_input.extend_from_slice(&key);
    let m1 = sha256(&m_input);
    let m2 = sha256(&[bigint_bytes(&big_a, None), m1.clone(), key].concat());

    let mut complete = json!({
        "accountName": username,
        "c": client_c,
        "m1": b64(m1),
        "m2": b64(m2),
        "rememberMe": true,
        "trustTokens": [],
    });
    if let Some(token) = api.session.read().unwrap().trust_token.clone() {
        complete["trustTokens"] = json!([token]);
    }
    let response = api
        .with_cookies(
            api.client
                .post(format!("{}/signin/complete", api.auth_endpoint))
                .headers(headers)
                .query(&[("isRememberMeEnabled", "true")]),
        )
        .json(&complete)
        .send()
        .await?;
    match api.checked(response).await {
        Ok(_) => {}
        Err(Error::TwoFactor(_)) => *api.mfa_pending.write().unwrap() = true,
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Fetch the 2FA challenge. pyicloud first requests HTML and parses the
/// `<script class="boot_args">` JSON (which carries `direct.twoSV.*`), then
/// makes a second JSON request only for `fsaChallenge` / `keyNames`. Doing
/// only the JSON request made us miss the trusted-device path and fall back
/// to SMS — the cause of the wrong-endpoint bug.
async fn fetch_auth_options(api: &ICloudApi) -> Result<Value> {
    let mut html_headers = api.auth_headers();
    html_headers.insert(ACCEPT, "text/html".parse().unwrap());
    add_origin(&mut html_headers);
    let response = api
        .with_cookies(api.client.get(&api.auth_endpoint).headers(html_headers))
        .send()
        .await?;
    let response = api.checked(response).await?;
    let html = response.text().await?;
    let boot = parse_boot_args(&html).unwrap_or_else(|| json!({}));

    let mut json_headers = api.auth_headers();
    json_headers.insert(ACCEPT, "application/json".parse().unwrap());
    add_origin(&mut json_headers);
    let response = api
        .with_cookies(api.client.get(&api.auth_endpoint).headers(json_headers))
        .send()
        .await?;
    let response = api.checked(response).await?;
    let text = response.text().await?;
    let json_options: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text}));
    Ok(merge_auth_options(boot, json_options))
}

/// Extract the JSON object inside `<script class="boot_args">…</script>`.
fn parse_boot_args(html: &str) -> Option<Value> {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(found) = lower[cursor..].find("boot_args") {
        let marker = cursor + found;
        let open = html[marker..].find('>')? + marker;
        let tail = &html[open + 1..].to_ascii_lowercase();
        let close = tail.find("</script")? + open + 1;
        let candidate = html[open + 1..close].trim();
        if let Ok(value) = serde_json::from_str::<Value>(candidate)
            && value.is_object()
        {
            return Some(value);
        }
        cursor = marker + "boot_args".len();
    }
    None
}

/// Flatten `direct.*` into top-level keys so all helpers see the same data.
/// Priority: JSON probe > bridge > twoSV > direct > boot top-level.
fn merge_auth_options(boot: Value, json: Value) -> Value {
    let mut merged = if json.is_object() { json } else { json!({}) };
    let Some(map) = merged.as_object_mut() else {
        return merged;
    };
    if let Some(direct) = boot.get("direct") {
        map.insert("direct".into(), direct.clone());
    }
    for source in [
        boot.get("direct")
            .and_then(|v| v.get("twoSV"))
            .and_then(|v| v.get("bridgeInitiateData")),
        boot.get("direct").and_then(|v| v.get("twoSV")),
        boot.get("direct"),
        Some(&boot),
    ] {
        if let Some(object) = source.and_then(Value::as_object) {
            for (key, value) in object {
                map.entry(key.clone()).or_insert_with(|| value.clone());
            }
        }
    }
    merged
}

fn add_origin(headers: &mut reqwest::header::HeaderMap) {
    if !headers.contains_key(reqwest::header::ORIGIN) {
        headers.insert(
            reqwest::header::ORIGIN,
            "https://www.icloud.com".parse().unwrap(),
        );
    }
}

/// Mode hint from the 2FA options probe. Apple exposes it either at the top
/// level, inside `twoSV`, or nested under `direct.twoSV.bridgeInitiateData`.
fn two_sv_mode(options: &Value) -> Option<&str> {
    let bridge = options
        .get("direct")
        .and_then(|value| value.get("twoSV"))
        .and_then(|value| value.get("bridgeInitiateData"));
    for container in [Some(options), options.get("twoSV"), bridge] {
        if let Some(mode) = container
            .and_then(|value| value.get("mode"))
            .and_then(Value::as_str)
        {
            return Some(mode);
        }
        if let Some(route) = container
            .and_then(|value| value.get("authInitialRoute"))
            .and_then(Value::as_str)
        {
            return Some(route);
        }
    }
    None
}

fn is_sms_mode(mode: Option<&str>) -> bool {
    mode.is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("sms") || value.contains("phone")
    })
}

fn is_security_key(options: &Value) -> bool {
    options.get("fsaChallenge").is_some() || options.get("keyNames").is_some()
}

fn trusted_devices(options: &Value) -> Option<&Vec<Value>> {
    for container in [
        Some(options),
        options.get("direct"),
        options.get("direct").and_then(|v| v.get("twoSV")),
        options
            .get("direct")
            .and_then(|v| v.get("twoSV"))
            .and_then(|v| v.get("bridgeInitiateData")),
    ] {
        if let Some(devices) = container
            .and_then(|value| value.get("trustedDevices"))
            .and_then(Value::as_array)
        {
            return Some(devices);
        }
    }
    None
}

fn has_trusted_device_path(options: &Value) -> bool {
    if options.get("hasTrustedDevices").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    if options
        .get("trustedDevice")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || options
            .get("hsa2")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || options.get("authFactors").is_some()
        || options.get("bridgeInitiateData").is_some()
        || options
            .get("direct")
            .and_then(|value| value.get("twoSV"))
            .and_then(|value| value.get("bridgeInitiateData"))
            .is_some()
        || options
            .get("authInitialRoute")
            .and_then(Value::as_str)
            .is_some_and(|route| !is_sms_mode(Some(route)))
    {
        return true;
    }
    trusted_devices(options).is_some_and(|devices| !devices.is_empty())
}

/// A legacy `_W` verifier can still be submitted through the trusted-device
/// code endpoint even when Apple advertises the newer bridge.
fn has_legacy_verifier(options: &Value) -> bool {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(map) => map.iter().any(|(key, child)| {
                let key = key.to_ascii_lowercase();
                if (key.contains("verif") || key.contains("challenge"))
                    && let Some(text) = child.as_str()
                {
                    return text.contains("_W");
                }
                walk(child)
            }),
            Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    walk(options)
}

fn bridge_required(options: &Value) -> bool {
    if has_legacy_verifier(options) {
        return false;
    }
    let route = two_sv_mode(options).unwrap_or_default();
    let route_is_bridge =
        route.eq_ignore_ascii_case("auth/bridge/step") || route.eq_ignore_ascii_case("bridge");
    let bridge_data = options.get("bridgeInitiateData").is_some();
    route_is_bridge || (bridge_data && trusted_devices(options).is_some_and(|d| !d.is_empty()))
}

/// Select the route exactly once. Priority: security key → trusted device
/// (bridge or legacy) → SMS only when forced or when there is no device path.
fn select_route(options: &Value, force_sms: bool) -> TwoFactorRoute {
    if is_security_key(options) {
        return TwoFactorRoute::SecurityKey;
    }
    if force_sms {
        return TwoFactorRoute::Sms;
    }
    if has_trusted_device_path(options) {
        return if bridge_required(options) {
            TwoFactorRoute::TrustedDeviceBridge
        } else {
            TwoFactorRoute::TrustedDeviceLegacy
        };
    }
    if is_sms_mode(two_sv_mode(options)) || trusted_phone(options).is_some() {
        return TwoFactorRoute::Sms;
    }
    TwoFactorRoute::TrustedDeviceLegacy
}

fn phone_hint(options: &Value) -> Option<String> {
    let phone = trusted_phone(options)?;
    phone
        .get("numberWithDots")
        .and_then(Value::as_str)
        .or_else(|| phone.get("displayNumber").and_then(Value::as_str))
        .map(str::to_string)
}

fn trusted_phone(options: &Value) -> Option<&Value> {
    let bridge = options
        .get("direct")
        .and_then(|value| value.get("twoSV"))
        .and_then(|value| value.get("bridgeInitiateData"));
    let bridge_phones = bridge.and_then(|value| value.get("phoneNumberVerification"));
    for container in [
        Some(options),
        options.get("phoneNumberVerification"),
        bridge,
        bridge_phones,
    ] {
        let Some(container) = container else {
            continue;
        };
        if let Some(phone) = container
            .get("trustedPhoneNumber")
            .filter(|value| value.is_object())
        {
            return Some(phone);
        }
        // Newer responses use plural lists, sometimes under the nested probe.
        if let Some(phone) = container
            .get("trustedPhoneNumbers")
            .and_then(Value::as_array)
            .and_then(|phones| phones.iter().find(|value| value.is_object()))
        {
            return Some(phone);
        }
    }
    None
}

fn phone_payload(phone: &Value) -> Value {
    let mut payload = json!({"id": phone.get("id").cloned().unwrap_or(Value::Null)});
    if let Some(non_fteu) = phone.get("nonFTEU") {
        payload["nonFTEU"] = non_fteu.clone();
    }
    payload
}

/// Build the exact endpoint + body for the selected route. Keeping this pure
/// makes the routing testable without a live Apple session.
fn verification_request(
    endpoint: &str,
    route: TwoFactorRoute,
    code: &str,
    options: &Value,
) -> Result<(String, Value)> {
    match route {
        TwoFactorRoute::Sms => {
            let phone = trusted_phone(options).ok_or_else(|| {
                Error::TwoFactor(
                    "no trusted phone number available for the selected SMS route".into(),
                )
            })?;
            let mode = phone
                .get("pushMode")
                .or_else(|| phone.get("push_mode"))
                .and_then(Value::as_str)
                .unwrap_or("sms");
            Ok((
                format!("{endpoint}/verify/phone/securitycode"),
                json!({
                    "phoneNumber": phone_payload(phone),
                    "securityCode": {"code": code},
                    "mode": mode,
                }),
            ))
        }
        TwoFactorRoute::TrustedDeviceLegacy => Ok((
            format!("{endpoint}/verify/trusteddevice/securitycode"),
            json!({"securityCode": {"code": code}}),
        )),
        TwoFactorRoute::TrustedDeviceBridge => {
            if has_legacy_verifier(options) {
                // The legacy endpoint still accepts a `_W` verifier.
                Ok((
                    format!("{endpoint}/verify/trusteddevice/securitycode"),
                    json!({"securityCode": {"code": code}}),
                ))
            } else {
                Err(Error::TwoFactor(
                    "this account requires the iCloud trusted-device bridge, but no bridge \
                     session is active. Start sign-in again to re-arm the device prompt."
                        .into(),
                ))
            }
        }
        TwoFactorRoute::SecurityKey => Err(Error::TwoFactor(
            "this account uses a security key; approve it on a trusted device or switch to SMS"
                .into(),
        )),
    }
}

/// Apple returns 409 from both verification endpoints when the code itself is
/// valid; `securityCode.valid == true` means success, not an error.
fn verification_accepted(status: u16, body: &Value) -> bool {
    if (200..300).contains(&status) {
        return true;
    }
    status == 409
        && body
            .get("securityCode")
            .and_then(|value| value.get("valid"))
            .and_then(Value::as_bool)
            == Some(true)
}

fn service_error_codes(body: &Value) -> Vec<String> {
    let mut codes = Vec::new();
    for key in ["service_errors", "serviceErrors"] {
        if let Some(errors) = body.get(key).and_then(Value::as_array) {
            for error in errors {
                if let Some(code) = error.get("code") {
                    match code {
                        Value::String(text) => codes.push(text.trim().to_string()),
                        Value::Number(number) => codes.push(number.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }
    codes
}

fn is_code_rejected(body: &Value) -> bool {
    service_error_codes(body)
        .iter()
        .any(|code| code == "-21669" || code == "21669")
}

fn invalid_code_error(route: TwoFactorRoute, rejected_code: bool) -> Error {
    let advice = match route {
        TwoFactorRoute::Sms => "Use the code Apple sent by SMS to your trusted phone.",
        TwoFactorRoute::TrustedDeviceLegacy | TwoFactorRoute::TrustedDeviceBridge => {
            "Use the code shown on your trusted device."
        }
        TwoFactorRoute::SecurityKey => "Approve the security key prompt on your trusted device.",
    };
    let prefix = if rejected_code {
        "Apple reported -21669. "
    } else {
        ""
    };
    Error::code_rejected(format!(
        "{prefix}Incorrect code for the selected method — check the code or switch verification \
         method. {advice}"
    ))
}

/// True when Apple advertised SMS delivery and a trusted phone number.
fn can_request_sms(options: &Value) -> bool {
    is_sms_mode(two_sv_mode(options)) && trusted_phone(options).is_some()
}

async fn request_sms(api: &ICloudApi, options: &Value) -> Result<()> {
    let phone = trusted_phone(options).ok_or_else(|| {
        Error::TwoFactor("no trusted phone number available; try a trusted device code".into())
    })?;
    let mut headers = api.auth_headers();
    headers.insert(ACCEPT, "application/json, plain/text".parse().unwrap());
    add_origin(&mut headers);
    let response = api
        .with_cookies(
            api.client
                .put(format!("{}/verify/phone", api.auth_endpoint))
                .headers(headers)
                .json(&json!({"phoneNumber": phone_payload(phone), "mode": "sms"})),
        )
        .send()
        .await?;
    api.checked(response).await?;
    Ok(())
}

async fn request_default_code(
    api: &ICloudApi,
    options: &Value,
    route: TwoFactorRoute,
) -> Result<()> {
    if route == TwoFactorRoute::Sms {
        return request_sms(api, options).await;
    }
    // Legacy/trusted-device and bridge challenges are armed by the SRP
    // challenge itself; do not put an SMS request in flight for those routes.
    Ok(())
}

/// Re-initiate code delivery after the user switches verification method.
/// SMS can be re-armed directly. Trusted-device delivery requires a fresh
/// sign-in, so the GUI should call `authenticate()` again in that case.
pub async fn request_verification_route(api: &ICloudApi, route: TwoFactorRoute) -> Result<()> {
    let options = fetch_auth_options(api).await?;
    match route {
        TwoFactorRoute::Sms => request_sms(api, &options).await,
        TwoFactorRoute::TrustedDeviceLegacy | TwoFactorRoute::TrustedDeviceBridge => {
            Err(Error::TwoFactor(
                "switching to a trusted device requires starting sign-in again; call \
                 authenticate() to re-arm the device code"
                    .into(),
            ))
        }
        TwoFactorRoute::SecurityKey => Err(Error::TwoFactor(
            "security keys cannot be re-armed from IC-SYNC; approve the prompt and sign in again"
                .into(),
        )),
    }
}

pub async fn accept_terms_if_needed(api: &ICloudApi) -> Result<()> {
    if !api
        .data
        .read()
        .unwrap()
        .get("termsUpdateNeeded")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let response = api
        .with_cookies(
            api.client
                .get(format!("{}/getTerms", api.setup_endpoint))
                .query(&api.params()),
        )
        .send()
        .await?;
    let terms: Value = api.checked(response).await?.json().await?;
    let version = terms
        .get("iCloudTerms")
        .and_then(|t| t.get("version"))
        .and_then(Value::as_i64);
    let Some(version) = version else {
        return Err(Error::other("could not read iCloud terms version"));
    };
    let response = api
        .with_cookies(
            api.client
                .get(format!("{}/repairDone", api.setup_endpoint))
                .query(&api.params())
                .json(&json!({"acceptedICloudTerms": version})),
        )
        .send()
        .await?;
    api.checked(response).await?;
    api.login_with_token().await?;
    Ok(())
}

/// Keys Apple has used for the PBKDF2 iteration count. The wire value is a
/// JSON number in current responses; older ones used a string. Aliases are
/// tried in priority order and no fallback count is ever invented: a wrong
/// count produces the wrong SRP proof.
const SRP_ITERATION_KEYS: [&str; 4] = [
    "iteration",
    "iterations",
    "iterationCount",
    "iteration_count",
];

fn srp_iterations(body: &Value) -> Result<u32> {
    let mut seen: Vec<&str> = Vec::new();
    for key in SRP_ITERATION_KEYS {
        let Some(value) = body.get(key) else {
            continue;
        };
        seen.push(key);
        let parsed = match value {
            Value::Number(number) => number.as_u64().and_then(|n| u32::try_from(n).ok()),
            Value::String(text) => text.trim().parse::<u32>().ok(),
            _ => None,
        };
        let Some(iterations) = parsed else {
            return Err(Error::other(format!(
                "Apple SRP response has an unparseable '{key}' value (keys seen: {}); expected a \
                 JSON number or string",
                seen.join(", ")
            )));
        };
        if iterations == 0 {
            return Err(srp_throttled("iteration count was zero"));
        }
        return Ok(iterations);
    }
    let seen_text = if seen.is_empty() {
        "none".to_string()
    } else {
        seen.join(", ")
    };
    Err(Error::other(format!(
        "Apple SRP response missing iteration count (checked {}; keys seen: {seen_text})",
        SRP_ITERATION_KEYS.join(", ")
    )))
}

fn srp_throttled(detail: &str) -> Error {
    Error::Offline(format!(
        "Apple is temporarily refusing sign-in requests ({detail}). This is usually throttling or \
         a temporary service refusal, not an incorrect password — wait a few minutes and try again."
    ))
}

/// Apple's `signin/init` can answer HTTP 200 with a `serviceErrors` array.
/// `-900007` is a throttle/refusal; never present it as a credential failure.
fn srp_service_error(body: &Value) -> Option<Error> {
    let errors = body.get("serviceErrors")?.as_array()?;
    for error in errors {
        let code = error.get("code").and_then(|value| match value {
            Value::String(text) => Some(text.trim().to_string()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        });
        if code.as_deref() == Some("-900007") {
            return Some(srp_throttled("Apple service error -900007"));
        }
    }
    None
}

fn get_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::other(format!("Apple SRP response missing '{key}'")))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Big-endian bytes, optionally left-padded to `width` (RFC 5054 hashing).
fn bigint_bytes(value: &BigUint, width: Option<usize>) -> Vec<u8> {
    let raw = value.to_bytes_be();
    match width {
        Some(width) if raw.len() < width => {
            let mut padded = vec![0u8; width - raw.len()];
            padded.extend_from_slice(&raw);
            padded
        }
        _ => raw,
    }
}

fn hnxorg(n: &BigUint, g: &BigUint, width: Option<usize>) -> Vec<u8> {
    let hash_n = sha256(&bigint_bytes(n, width));
    let hash_g = sha256(&bigint_bytes(g, width));
    hash_n.into_iter().zip(hash_g).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srp_group_is_2048_bits() {
        let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).unwrap();
        assert_eq!(n.to_bytes_be().len(), 256);
    }

    #[test]
    fn hnxorg_is_xor_of_hashes() {
        let n = BigUint::from(7u8);
        let g = BigUint::from(2u8);
        assert_eq!(hnxorg(&n, &g, Some(2)).len(), 32);
    }

    #[test]
    fn rfc5054_padding_is_used_only_for_hashed_integers() {
        let g = BigUint::from(2u8);
        assert_eq!(bigint_bytes(&g, None), vec![2]);
        assert_eq!(bigint_bytes(&g, Some(4)), vec![0, 0, 0, 2]);
        let n = BigUint::from(7u8);
        let expected: Vec<u8> = sha256(&[0, 0, 0, 7])
            .into_iter()
            .zip(sha256(&[0, 0, 0, 2]))
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(hnxorg(&n, &g, Some(4)), expected);
    }

    #[test]
    fn s2k_fo_uses_hex_password_digest() {
        let digest = Sha256::digest(b"password");
        let text = hex(&digest);
        assert_eq!(text.len(), 64);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(text.as_bytes(), b"salt", 100, &mut a);
        pbkdf2::pbkdf2_hmac::<Sha256>(&digest, b"salt", 100, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn srp_iterations_accept_numbers_strings_and_aliases() {
        assert_eq!(srp_iterations(&json!({"iteration": 1000})).unwrap(), 1000);
        assert_eq!(srp_iterations(&json!({"iteration": "1000"})).unwrap(), 1000);
        assert_eq!(srp_iterations(&json!({"iterations": 2000})).unwrap(), 2000);
        assert_eq!(
            srp_iterations(&json!({"iterationCount": "3000"})).unwrap(),
            3000
        );
        assert_eq!(
            srp_iterations(&json!({"iteration_count": 4000})).unwrap(),
            4000
        );
    }

    #[test]
    fn srp_iteration_errors_are_clear_and_secret_free() {
        let error = srp_iterations(&json!({"salt": "SALTVALUE", "b": "BVALUE"}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("iteration"), "{error}");
        assert!(error.contains("keys seen"), "{error}");
        assert!(!error.contains("SALTVALUE"), "{error}");
        assert!(!error.contains("BVALUE"), "{error}");
        assert!(
            srp_iterations(&json!({"iteration": 0}))
                .unwrap_err()
                .is_offline()
        );
    }

    #[test]
    fn apple_service_errors_are_throttling_not_bad_credentials() {
        let error = srp_service_error(&json!({"serviceErrors": [{"code": "-900007"}]})).unwrap();
        assert!(error.is_offline());
        assert!(error.to_string().contains("not an incorrect password"));
        assert!(srp_service_error(&json!({"serviceErrors": []})).is_none());
        assert!(srp_service_error(&json!({"serviceErrors": [{"code": "123"}]})).is_none());
    }

    #[test]
    fn route_selection_prefers_devices_over_sms() {
        let options = json!({
            "trustedPhoneNumbers": [{"id": 1, "displayNumber": "+1 42"}],
            "authFactors": ["trustedDevice"]
        });
        assert!(trusted_phone(&options).is_some());
        assert_eq!(
            select_route(&options, false),
            TwoFactorRoute::TrustedDeviceLegacy
        );
        assert_eq!(select_route(&options, false).method(), "trusted_device");

        let nested = json!({
            "direct": {"twoSV": {"bridgeInitiateData": {
                "mode": "sms",
                "phoneNumberVerification": {"trustedPhoneNumbers": [{"id": 2}]}
            }}}
        });
        assert_eq!(two_sv_mode(&nested), Some("sms"));
        assert!(trusted_phone(&nested).is_some());
        // A device path exists, so the SMS mode hint must not misroute us.
        assert_eq!(
            select_route(&nested, false),
            TwoFactorRoute::TrustedDeviceLegacy
        );

        let sms_only = json!({"mode": "sms", "trustedPhoneNumbers": [{"id": 3}]});
        assert_eq!(select_route(&sms_only, false), TwoFactorRoute::Sms);
    }

    #[test]
    fn route_priority_security_key_bridge_and_force_sms() {
        let bridge = json!({
            "direct": {"twoSV": {"bridgeInitiateData": {
                "authInitialRoute": "auth/bridge/step",
                "trustedDevices": [{"id": "d1"}]
            }}}
        });
        assert_eq!(
            select_route(&bridge, false),
            TwoFactorRoute::TrustedDeviceBridge
        );

        let legacy = json!({
            "authInitialRoute": "auth/bridge/step",
            "trustedDevices": [{"id": "d1"}],
            "verificationCode": "_Wabcdef"
        });
        assert_eq!(
            select_route(&legacy, false),
            TwoFactorRoute::TrustedDeviceLegacy
        );

        let security = json!({"fsaChallenge": {}, "trustedDevices": [{"id": 1}]});
        assert_eq!(select_route(&security, true), TwoFactorRoute::SecurityKey);
        assert_eq!(select_route(&bridge, true), TwoFactorRoute::Sms);
    }

    #[test]
    fn verification_request_shapes_and_bridge_unsupported() {
        let options = json!({
            "trustedPhoneNumbers": [{"id": 7, "pushMode": "push", "nonFTEU": true}]
        });
        let (url, body) =
            verification_request("https://auth", TwoFactorRoute::Sms, "123456", &options).unwrap();
        assert_eq!(url, "https://auth/verify/phone/securitycode");
        assert_eq!(body["securityCode"]["code"], "123456");
        assert_eq!(body["mode"], "push");
        assert_eq!(body["phoneNumber"]["id"], 7);

        let (url, body) = verification_request(
            "https://auth",
            TwoFactorRoute::TrustedDeviceLegacy,
            "123456",
            &options,
        )
        .unwrap();
        assert_eq!(url, "https://auth/verify/trusteddevice/securitycode");
        assert_eq!(body, json!({"securityCode": {"code": "123456"}}));

        let error = verification_request(
            "https://auth",
            TwoFactorRoute::TrustedDeviceBridge,
            "1",
            &options,
        )
        .unwrap_err();
        assert!(error.is_auth());
        assert!(error.to_string().contains("bridge"));
    }

    #[test]
    fn verification_409_success_and_typed_code_rejection() {
        assert!(verification_accepted(200, &json!({})));
        assert!(verification_accepted(
            409,
            &json!({"securityCode": {"valid": true}})
        ));
        assert!(!verification_accepted(
            409,
            &json!({"securityCode": {"valid": false}})
        ));
        assert!(is_code_rejected(
            &json!({"service_errors": [{"code": -21669}]})
        ));
        assert!(is_code_rejected(
            &json!({"serviceErrors": [{"code": "-21669"}]})
        ));

        let error = invalid_code_error(TwoFactorRoute::Sms, true);
        assert!(error.is_code_rejected());
        let text = error.to_string();
        assert!(
            text.contains("Incorrect code for the selected method"),
            "{text}"
        );
        assert!(text.contains("SMS"), "{text}");
        assert!(text.contains("-21669"), "{text}");
        let device = invalid_code_error(TwoFactorRoute::TrustedDeviceLegacy, false).to_string();
        assert!(device.contains("trusted device"), "{device}");
    }

    #[test]
    fn accepted_code_postcondition_requires_authenticated_trusted_and_no_mfa() {
        let session = || crate::api::SessionData {
            session_token: Some("session-token".into()),
            ..Default::default()
        };
        let trusted_data = || json!({"dsInfo": {"dsid": "1"}, "hsaTrustedBrowser": true});

        let ready = crate::api::test_api(trusted_data(), session(), false);
        assert!(ready.is_authenticated());
        assert!(ready.is_trusted());
        assert!(!ready.requires_2fa());
        assert!(session_ready(&ready));

        // Untrusted browser after accountLogin: retry the trust cycle.
        let untrusted = crate::api::test_api(
            json!({"dsInfo": {"dsid": "1"}, "hsaTrustedBrowser": false}),
            session(),
            false,
        );
        assert!(untrusted.is_authenticated());
        assert!(!untrusted.is_trusted());
        assert!(untrusted.requires_2fa());
        assert!(!session_ready(&untrusted));

        // The !is_trusted() clause must stay: a stale mfa_pending alone is not
        // the only way requires_2fa can be true.
        let pending = crate::api::test_api(trusted_data(), session(), true);
        assert!(pending.requires_2fa());
        assert!(!session_ready(&pending));

        let challenged = crate::api::test_api(
            json!({"dsInfo": {"dsid": "1"}, "hsaTrustedBrowser": true, "hsaChallengeRequired": true}),
            session(),
            false,
        );
        assert!(challenged.requires_2fa());
        assert!(!session_ready(&challenged));

        let missing_info =
            crate::api::test_api(json!({"hsaTrustedBrowser": true}), session(), false);
        assert!(!missing_info.is_authenticated());
        assert!(!session_ready(&missing_info));
    }

    #[test]
    fn boot_args_are_parsed_and_flattened() {
        let html = r#"<html><script class="boot_args">{"direct":{"authInitialRoute":"auth/bridge/step","hasTrustedDevices":true,"twoSV":{"authFactors":["hsa2"],"bridgeInitiateData":{"mode":"sms"}}},"hsa2":true}</script></html>"#;
        let boot = parse_boot_args(html).unwrap();
        assert_eq!(boot["direct"]["authInitialRoute"], "auth/bridge/step");
        let merged = merge_auth_options(boot, json!({"fsaChallenge": {}}));
        assert_eq!(merged["authInitialRoute"], "auth/bridge/step");
        assert_eq!(merged["hasTrustedDevices"], true);
        assert_eq!(merged["authFactors"], json!(["hsa2"]));
        assert_eq!(merged["mode"], "sms");
        assert!(merged["fsaChallenge"].is_object());
    }
}
