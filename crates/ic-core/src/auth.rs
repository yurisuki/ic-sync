//! Native Apple ID authentication: SRP-6a with SHA-256 and interactive 2FA.
//!
//! The maths mirrors pyicloud's `srp` package: RFC 5054 2048-bit group,
//! fixed-width big-endian padding for hashed integers, `no_username_in_x`,
//! and the `s2k` / `s2k_fo` password derivations.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::api::{ICloudApi, b64, unb64};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStep {
    Authenticated,
    TwoFactorRequired {
        method: String,
        hint: Option<String>,
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

    // This response refreshes the scnt/session-id headers used below.
    let auth_options = fetch_auth_options(api).await?;
    let method = detect_method(&auth_options, options.force_sms);
    if options.force_sms {
        request_sms(api, &auth_options).await?;
    } else {
        request_default_code(api, &auth_options).await?;
    }
    Ok(AuthStep::TwoFactorRequired {
        method,
        hint: phone_hint(&auth_options),
    })
}

pub async fn submit_code(
    api: &ICloudApi,
    code: &str,
    force_sms: bool,
    accept_terms: bool,
) -> Result<AuthStep> {
    let options = fetch_auth_options(api).await?;
    let phone = trusted_phone(&options);
    let mut headers = api.auth_headers();
    headers.insert(ACCEPT, "application/json, text/plain".parse().unwrap());
    // Honour the probe's SMS mode even when the UI no longer offers a manual
    // choice; `force_sms` still wins.
    let prefer_sms = force_sms || is_sms_mode(two_sv_mode(&options));
    let sms_phone = if prefer_sms { phone.cloned() } else { None };
    let (url, payload) = if let Some(phone) = &sms_phone {
        (
            format!("{}/verify/phone/securitycode", api.auth_endpoint),
            json!({
                "phoneNumber": phone_payload(phone),
                "securityCode": {"code": code},
                "mode": phone.get("pushMode").and_then(Value::as_str).unwrap_or("sms"),
            }),
        )
    } else if options.get("fsaChallenge").is_some() || options.get("keyNames").is_some() {
        return Err(Error::TwoFactor(
            "this account uses a security key; use a trusted device or SMS verification code"
                .into(),
        ));
    } else {
        (
            format!("{}/verify/trusteddevice/securitycode", api.auth_endpoint),
            json!({"securityCode": {"code": code}}),
        )
    };

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
    match api.checked(response).await {
        Ok(_) => {}
        Err(Error::TwoFactor(_)) => {
            return Err(Error::TwoFactor("invalid verification code".into()));
        }
        Err(error) => return Err(error),
    }

    let response = api
        .with_cookies(
            api.client
                .get(format!("{}/2sv/trust", api.auth_endpoint))
                .headers(headers),
        )
        .send()
        .await?;
    api.checked(response).await?;
    api.login_with_token().await?;
    if accept_terms {
        accept_terms_if_needed(api).await?;
    }
    Ok(AuthStep::Authenticated)
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

async fn fetch_auth_options(api: &ICloudApi) -> Result<Value> {
    let mut headers = api.auth_headers();
    headers.insert(ACCEPT, "application/json".parse().unwrap());
    let response = api
        .with_cookies(api.client.get(&api.auth_endpoint).headers(headers))
        .send()
        .await?;
    let response = api.checked(response).await?;
    let text = response.text().await?;
    Ok(serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw": text})))
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
        value.eq_ignore_ascii_case("sms") || value.eq_ignore_ascii_case("phone")
    })
}

fn detect_method(options: &Value, force_sms: bool) -> String {
    if force_sms {
        return "sms".into();
    }
    if options.get("fsaChallenge").is_some() || options.get("keyNames").is_some() {
        return "security_key".into();
    }
    let mode = two_sv_mode(options);
    if is_sms_mode(mode) {
        return "sms".into();
    }
    if options.get("authFactors").is_some()
        || options.get("authInitialRoute").is_some()
        || options.get("trustedDevice").is_some()
        || options.get("hsa2").is_some()
        || mode.is_some_and(|value| value.eq_ignore_ascii_case("trusteddevice"))
    {
        return "trusted_device".into();
    }
    if trusted_phone(options).is_some() {
        return "sms".into();
    }
    "unknown".into()
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

async fn request_sms(api: &ICloudApi, options: &Value) -> Result<()> {
    let phone = trusted_phone(options).ok_or_else(|| {
        Error::TwoFactor("no trusted phone number available; try a trusted device code".into())
    })?;
    let mut headers = api.auth_headers();
    headers.insert(ACCEPT, "application/json".parse().unwrap());
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

async fn request_default_code(api: &ICloudApi, options: &Value) -> Result<()> {
    if detect_method(options, false) == "sms" {
        return request_sms(api, options).await;
    }
    // Trusted-device push is initiated by Apple when the challenge is created.
    Ok(())
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
    fn two_fa_helpers_cover_new_apple_shapes() {
        let options = json!({
            "trustedPhoneNumbers": [{"id": 1, "displayNumber": "+1 42"}],
            "authFactors": ["trustedDevice"]
        });
        assert!(trusted_phone(&options).is_some());
        assert_eq!(detect_method(&options, false), "trusted_device");

        let nested = json!({
            "direct": {"twoSV": {"bridgeInitiateData": {
                "mode": "sms",
                "phoneNumberVerification": {"trustedPhoneNumbers": [{"id": 2}]}
            }}}
        });
        assert_eq!(two_sv_mode(&nested), Some("sms"));
        assert!(trusted_phone(&nested).is_some());
        assert_eq!(detect_method(&nested, false), "sms");
    }
}
