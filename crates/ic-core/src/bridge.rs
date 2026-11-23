//! Apple HSA2 trusted-device bridge transport.
//!
//! This is the native equivalent of pyicloud's `hsa2_bridge` module. Apple's
//! browser flow opens a WSS connection to the WebCourier push service, obtains
//! a push token, and posts `/bridge/step/0` to make the phone prompt appear.
//! The remaining steps exchange SPAKE2-like prover messages over that same
//! socket and finish with `/bridge/code/validate`.
//!
//! No token, cookie, push token or session identifier is ever written to a log
//! or included in an error: identifiers are shortened before `debug!` output.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rand::RngCore;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue as WsHeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tracing::debug;
use uuid::Uuid;

use crate::api::{ICloudApi, USER_AGENT, b64, unb64};
use crate::bridge_prover::TrustedDeviceBridgeProver;
use crate::error::{Error, Result};

const BRIDGE_STEP_PATH: &str = "/bridge/step/";
const BRIDGE_CODE_VALIDATE_PATH: &str = "/bridge/code/validate";
const NEW_CONNECTION_EXPIRATION_SECONDS: u64 = 86_400;
const WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(30);
const BRIDGE_SIGNATURE_PREFIX: [u8; 2] = [0x01, 0x03];
const STATUS_OK: u64 = 0;
const STATUS_INVALID_NONCE: u64 = 2;
const DONE_DATA_B64: &str = "ZG9uZQ=="; // base64("done")

/// HSA2 boot data relevant to the trusted-device bridge.
#[derive(Debug, Clone, Default)]
pub struct Hsa2BootContext {
    pub auth_initial_route: String,
    pub has_trusted_devices: bool,
    pub bridge_initiate_data: Value,
    pub source_app_id: Option<String>,
}

impl Hsa2BootContext {
    /// Normalise boot data found in Apple's JSON probe or HTML `boot_args`.
    pub fn from_auth_options(options: &Value) -> Self {
        let direct = options.get("direct");
        let two_sv = direct.and_then(|value| value.get("twoSV"));

        let route = two_sv
            .and_then(|value| value.get("authInitialRoute"))
            .or_else(|| direct.and_then(|value| value.get("authInitialRoute")))
            .or_else(|| options.get("authInitialRoute"))
            .and_then(Value::as_str)
            .unwrap_or_default();

        let has_trusted_devices = [
            direct.and_then(|value| value.get("hasTrustedDevices")),
            options.get("hasTrustedDevices"),
        ]
        .iter()
        .any(|value| value.and_then(Value::as_bool).unwrap_or(false));

        let bridge_initiate_data = two_sv
            .and_then(|value| value.get("bridgeInitiateData"))
            .or_else(|| options.get("bridgeInitiateData"))
            .filter(|value| value.is_object())
            .cloned()
            .unwrap_or_else(|| json!({}));

        let source_app_id = two_sv
            .and_then(|value| value.get("sourceAppId"))
            .or_else(|| options.get("sourceAppId"))
            .and_then(Value::as_str)
            .map(str::to_string);

        Self {
            auth_initial_route: route.to_string(),
            has_trusted_devices,
            bridge_initiate_data,
            source_app_id,
        }
    }
}

/// Whether Apple advertised the HSA2 bridge route in this challenge.
pub fn supports_bridge(options: &Value) -> bool {
    let boot = Hsa2BootContext::from_auth_options(options);
    boot.auth_initial_route
        .eq_ignore_ascii_case("auth/bridge/step")
        && boot.has_trusted_devices
        && boot
            .bridge_initiate_data
            .as_object()
            .is_some_and(|data| !data.is_empty())
}

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Bridge data retained between `authenticate()` and `submit_code()`.
pub struct BridgeSession {
    stream: WsStream,
    pub connection_path: String,
    push_token: String,
    session_uuid: String,
    topic: String,
    topics_by_hash: HashMap<String, String>,
    source_app_id: Option<String>,
    next_step: Option<String>,
    push_payload: Value,
    txnid: Option<String>,
    salt: Option<String>,
    mid: Option<String>,
    idmsdata: Option<String>,
    akdata: Option<Value>,
    data: Option<String>,
    encrypted_code: Option<String>,
    error_code: Option<i64>,
}

impl BridgeSession {
    /// Apple sometimes routes a bridge challenge to the legacy verifier; the
    /// `txnid` suffix `_W` is the signal used by the browser client.
    pub fn uses_legacy_verifier(&self) -> bool {
        self.txnid
            .as_deref()
            .is_some_and(|txnid| txnid.ends_with("_W"))
    }

    fn apply_push(&mut self, push: BridgePushPayload) {
        self.push_payload = push.payload;
        self.session_uuid = push.session_uuid;
        self.next_step = push.next_step;
        self.txnid = push.txnid;
        self.salt = push.salt;
        self.mid = push.mid;
        self.idmsdata = push.idmsdata;
        self.akdata = push.akdata;
        self.data = push.data;
        self.encrypted_code = push.encrypted_code;
        self.error_code = push.error_code;
    }

    /// Best-effort clean close; failures are irrelevant because the session is
    /// discarded immediately afterwards.
    pub async fn close(&mut self) {
        let _ = self.stream.close(None).await;
    }
}

#[derive(Debug)]
struct BridgePushPayload {
    payload: Value,
    session_uuid: String,
    had_session_uuid: bool,
    next_step: Option<String>,
    txnid: Option<String>,
    salt: Option<String>,
    mid: Option<String>,
    idmsdata: Option<String>,
    akdata: Option<Value>,
    data: Option<String>,
    encrypted_code: Option<String>,
    error_code: Option<i64>,
}

fn optional_string(payload: &Value, key: &str) -> Result<Option<String>> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(Some(text.clone())),
        Some(Value::String(_)) => Err(Error::other(
            "Malformed trusted-device bridge push payload.",
        )),
        Some(_) => Err(Error::other(
            "Malformed trusted-device bridge push payload.",
        )),
    }
}

fn parse_push_payload(payload: Value) -> Result<BridgePushPayload> {
    let session_uuid = optional_string(&payload, "sessionUUID")?
        .or_else(|| optional_string(&payload, "flowid").ok().flatten())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            Error::other("Trusted-device bridge push payload is missing sessionUUID/flowid.")
        })?;
    let had_session_uuid = payload.get("sessionUUID").is_some();

    let next_step = match payload.get("nextStep") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if !text.trim().is_empty() => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => {
            return Err(Error::other(
                "Malformed trusted-device bridge push payload.",
            ));
        }
    };
    let error_code = match payload.get("ec") {
        Some(Value::Number(number)) => number.as_i64(),
        _ => None,
    };
    // Validated but not needed after the bootstrap: Apple may include a
    // present-but-blank ruiURLKey, which must be treated as a malformed push.
    let _rui_url_key = optional_string(&payload, "ruiURLKey")?;

    Ok(BridgePushPayload {
        had_session_uuid,
        session_uuid,
        next_step,
        txnid: optional_string(&payload, "txnid")?,
        salt: optional_string(&payload, "salt")?,
        mid: optional_string(&payload, "mid")?,
        idmsdata: optional_string(&payload, "idmsdata")?,
        akdata: payload.get("akdata").cloned(),
        data: optional_string(&payload, "data")?,
        encrypted_code: optional_string(&payload, "encryptedCode")?,
        error_code,
        payload,
    })
}

#[derive(Debug, Clone)]
enum FieldValue {
    Varint(u64),
    Bytes(Vec<u8>),
}

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn encode_bytes_field(number: u32, value: &[u8], output: &mut Vec<u8>) {
    encode_varint(((number as u64) << 3) | 2, output);
    encode_varint(value.len() as u64, output);
    output.extend_from_slice(value);
}

fn encode_uint32_field(number: u32, value: u64, output: &mut Vec<u8>) {
    encode_varint((number as u64) << 3, output);
    encode_varint(value, output);
}

fn read_varint(data: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let start = *offset;
    loop {
        if *offset >= data.len() {
            return Err(Error::other("Truncated bridge protobuf varint."));
        }
        let byte = data[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 || *offset - start >= 10 {
            return Err(Error::other("Malformed bridge protobuf varint."));
        }
    }
}

fn decode_fields(data: &[u8]) -> Result<HashMap<u32, Vec<FieldValue>>> {
    let mut fields: HashMap<u32, Vec<FieldValue>> = HashMap::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let key = read_varint(data, &mut offset)?;
        let number = (key >> 3) as u32;
        let wire_type = key & 0x07;
        let value = match wire_type {
            0 => FieldValue::Varint(read_varint(data, &mut offset)?),
            2 => {
                let length = read_varint(data, &mut offset)? as usize;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| Error::other("Malformed bridge protobuf field."))?;
                if end > data.len() {
                    return Err(Error::other("Truncated bridge protobuf field."));
                }
                let bytes = data[offset..end].to_vec();
                offset = end;
                FieldValue::Bytes(bytes)
            }
            other => {
                return Err(Error::other(format!(
                    "Unsupported bridge protobuf wire type: {other}"
                )));
            }
        };
        fields.entry(number).or_default().push(value);
    }
    Ok(fields)
}

fn bytes_field(fields: &HashMap<u32, Vec<FieldValue>>, number: u32) -> Option<&[u8]> {
    fields
        .get(&number)
        .and_then(|values| values.first())
        .and_then(|value| match value {
            FieldValue::Bytes(bytes) => Some(bytes.as_slice()),
            FieldValue::Varint(_) => None,
        })
}

fn varint_field(fields: &HashMap<u32, Vec<FieldValue>>, number: u32) -> u64 {
    fields
        .get(&number)
        .and_then(|values| values.first())
        .map_or(0, |value| match value {
            FieldValue::Varint(number) => *number,
            FieldValue::Bytes(_) => 0,
        })
}

#[derive(Debug)]
struct ConnectionResponse {
    push_token_b64: String,
    status: u64,
    server_timestamp_seconds: Option<u64>,
}

#[derive(Debug)]
struct PushMessage {
    topic: Vec<u8>,
    message_id: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct ServerMessage {
    connection: Option<ConnectionResponse>,
    push: Option<PushMessage>,
    subscription_status: Option<u64>,
    field_numbers: Vec<u32>,
}

fn decode_connection_response(message: &[u8]) -> Result<ConnectionResponse> {
    let fields = decode_fields(message)?;
    let push_token_b64 = bytes_field(&fields, 1)
        .map(|bytes| String::from_utf8(bytes.to_vec()))
        .transpose()
        .map_err(|_| Error::other("Malformed bridge connection response push token."))?
        .unwrap_or_default();
    let server_timestamp_seconds = if fields.contains_key(&3) {
        Some(varint_field(&fields, 3))
    } else {
        None
    };
    Ok(ConnectionResponse {
        push_token_b64,
        status: varint_field(&fields, 2),
        server_timestamp_seconds,
    })
}

fn decode_push_message(message: &[u8]) -> Result<PushMessage> {
    let fields = decode_fields(message)?;
    Ok(PushMessage {
        topic: bytes_field(&fields, 1).unwrap_or_default().to_vec(),
        message_id: varint_field(&fields, 2),
        payload: bytes_field(&fields, 4).unwrap_or_default().to_vec(),
    })
}

fn decode_subscription_status(message: &[u8]) -> Result<u64> {
    let fields = decode_fields(message)?;
    Ok(varint_field(&fields, 3))
}

fn decode_server_message(message: &[u8]) -> Result<ServerMessage> {
    let fields = decode_fields(message)?;
    let mut result = ServerMessage {
        field_numbers: {
            let mut numbers: Vec<u32> = fields.keys().copied().collect();
            numbers.sort_unstable();
            numbers
        },
        ..ServerMessage::default()
    };
    if let Some(bytes) = bytes_field(&fields, 1) {
        result.connection = Some(decode_connection_response(bytes)?);
    }
    if let Some(bytes) = bytes_field(&fields, 2) {
        result.push = Some(decode_push_message(bytes)?);
    }
    if let Some(bytes) = bytes_field(&fields, 3) {
        result.subscription_status = Some(decode_subscription_status(bytes)?);
    }
    Ok(result)
}

fn encode_connection_message(public_key: &[u8], nonce: &[u8], signature: &[u8]) -> Vec<u8> {
    let wrapped_signature = if signature.starts_with(&BRIDGE_SIGNATURE_PREFIX) {
        signature.to_vec()
    } else {
        [BRIDGE_SIGNATURE_PREFIX.as_slice(), signature].concat()
    };
    let mut inner = Vec::new();
    encode_bytes_field(1, public_key, &mut inner);
    encode_bytes_field(2, nonce, &mut inner);
    encode_bytes_field(3, &wrapped_signature, &mut inner);
    let mut expiration = Vec::new();
    encode_uint32_field(1, NEW_CONNECTION_EXPIRATION_SECONDS, &mut expiration);
    encode_bytes_field(5, &expiration, &mut inner);

    let mut outer = Vec::new();
    encode_bytes_field(1, &inner, &mut outer);
    outer
}

fn encode_web_filter(topic: &str) -> Vec<u8> {
    let mut filter = Vec::new();
    encode_bytes_field(1, topic.as_bytes(), &mut filter);
    let mut message = Vec::new();
    encode_bytes_field(3, &filter, &mut message);
    message
}

fn encode_ack(topic: &[u8], message_id: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_bytes_field(1, topic, &mut payload);
    encode_uint32_field(2, message_id, &mut payload);
    let mut message = Vec::new();
    encode_bytes_field(2, &payload, &mut message);
    message
}

fn topic_hash(topic: &str) -> String {
    hex::encode(Sha1::digest(topic.as_bytes()))
}

fn topic_name(topic: &[u8], topics_by_hash: &HashMap<String, String>) -> String {
    topics_by_hash
        .get(&hex::encode(topic))
        .cloned()
        .unwrap_or_else(|| String::from_utf8_lossy(topic).into_owned())
}

fn extract_json_payload(payload: &[u8]) -> Result<Value> {
    if let Ok(value) = serde_json::from_slice::<Value>(payload)
        && value.is_object()
    {
        return Ok(value);
    }
    let text = String::from_utf8_lossy(payload);
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while let Some(relative) = text[start..].find('{') {
        let begin = start + relative;
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        for index in begin..bytes.len() {
            let byte = bytes[index];
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Ok(value) = serde_json::from_slice::<Value>(&bytes[begin..=index])
                            && value.is_object()
                        {
                            return Ok(value);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
        start = begin + 1;
    }
    Err(Error::other(
        "Could not decode the trusted-device bridge push payload.",
    ))
}

fn resolve_websocket_host(boot: &Hsa2BootContext) -> Result<String> {
    if let Some(url) = boot
        .bridge_initiate_data
        .get("webSocketUrl")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        if url.contains("://") {
            let parsed = url::Url::parse(url)?;
            if let Some(host) = parsed.host_str() {
                return Ok(host.to_string());
            }
        } else {
            return Ok(url.split('/').next().unwrap_or(url).to_string());
        }
    }
    match boot
        .bridge_initiate_data
        .get("apnsEnvironment")
        .and_then(Value::as_str)
    {
        Some("prod") => Ok("websocket.push.apple.com".into()),
        Some("sandbox") => Ok("websocket.sandbox.push.apple.com".into()),
        _ => Err(Error::TwoFactor(
            "Apple did not provide a trusted-device bridge websocket host.".into(),
        )),
    }
}

fn resolve_apns_topic(boot: &Hsa2BootContext) -> Result<String> {
    boot.bridge_initiate_data
        .get("apnsTopic")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            Error::TwoFactor("Apple did not provide a trusted-device APNS topic.".into())
        })
}

fn derive_origin(auth_endpoint: &str) -> Result<String> {
    let parsed = url::Url::parse(auth_endpoint)?;
    let host = parsed.host_str().ok_or_else(|| {
        Error::TwoFactor("Invalid auth endpoint for the trusted-device bridge.".into())
    })?;
    Ok(format!("{}://{}", parsed.scheme(), host))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_nonce(timestamp_ms: u64) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(17);
    nonce.push(0u8);
    nonce.extend_from_slice(&timestamp_ms.to_be_bytes());
    let mut random = [0u8; 8];
    rand::rng().fill_bytes(&mut random);
    nonce.extend_from_slice(&random);
    nonce
}

fn generate_signing_key() -> Result<SigningKey> {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    SigningKey::from_slice(&bytes)
        .map_err(|_| Error::other("Could not create the bridge signing key."))
}

fn summarize(value: Option<&str>, prefix: usize) -> &'static str {
    match value {
        Some(text) if text.len() > prefix => "<id>",
        Some(_) => "<short>",
        None => "<none>",
    }
}

enum TokenWait {
    Token(Vec<u8>),
    InvalidNonce(u64),
}

async fn read_ws(stream: &mut WsStream, deadline: Instant) -> Result<Message> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::other(
            "Timed out waiting for the trusted-device bridge.",
        ));
    }
    match tokio::time::timeout(remaining, stream.next()).await {
        Ok(Some(Ok(message))) => Ok(message),
        Ok(Some(Err(_))) => Err(Error::other(
            "Trusted-device bridge websocket transport error.",
        )),
        Ok(None) => Err(Error::other(
            "Trusted-device bridge websocket closed before delivering a prompt.",
        )),
        Err(_) => Err(Error::other(
            "Timed out waiting for the trusted-device bridge.",
        )),
    }
}

fn message_bytes(message: Message) -> Result<Option<Vec<u8>>> {
    match message {
        Message::Binary(bytes) => Ok(Some(bytes.to_vec())),
        Message::Text(text) => Ok(Some(text.as_bytes().to_vec())),
        Message::Close(_) => Err(Error::other(
            "Trusted-device bridge websocket closed before delivering a prompt.",
        )),
        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
    }
}

async fn send_binary(stream: &mut WsStream, payload: Vec<u8>) -> Result<()> {
    stream
        .send(Message::Binary(payload.into()))
        .await
        .map_err(|_| Error::other("Could not send a trusted-device bridge frame."))
}

async fn wait_for_push_token(stream: &mut WsStream) -> Result<TokenWait> {
    let deadline = Instant::now() + WEBSOCKET_TIMEOUT;
    loop {
        let Some(bytes) = message_bytes(read_ws(stream, deadline).await?)? else {
            continue;
        };
        let server = decode_server_message(&bytes)?;
        let Some(connection) = server.connection else {
            debug!(
                "Ignoring non-connection bridge frame; fields={:?}",
                server.field_numbers
            );
            continue;
        };
        if connection.status == STATUS_OK && !connection.push_token_b64.is_empty() {
            let token = unb64(&connection.push_token_b64)
                .map_err(|_| Error::other("Malformed bridge push token."))?;
            debug!("Received bridge push token ({} bytes)", token.len());
            return Ok(TokenWait::Token(token));
        }
        if connection.status == STATUS_INVALID_NONCE
            && let Some(timestamp) = connection.server_timestamp_seconds
        {
            return Ok(TokenWait::InvalidNonce(timestamp.saturating_mul(1000)));
        }
        return Err(Error::other(format!(
            "Bridge server returned status {}.",
            connection.status
        )));
    }
}

async fn wait_for_bridge_push(
    stream: &mut WsStream,
    topic: &str,
    topics_by_hash: &HashMap<String, String>,
) -> Result<BridgePushPayload> {
    let deadline = Instant::now() + WEBSOCKET_TIMEOUT;
    loop {
        let Some(bytes) = message_bytes(read_ws(stream, deadline).await?)? else {
            continue;
        };
        let server = decode_server_message(&bytes)?;
        if let Some(status) = server.subscription_status
            && status != STATUS_OK
        {
            return Err(Error::other(format!(
                "Trusted-device bridge topic subscription failed (status {status})."
            )));
        }
        let Some(push) = server.push else {
            debug!(
                "Ignoring non-push bridge frame; fields={:?}",
                server.field_numbers
            );
            continue;
        };
        send_binary(stream, encode_ack(&push.topic, push.message_id)).await?;
        if topic_name(&push.topic, topics_by_hash) != topic {
            continue;
        }
        let payload = extract_json_payload(&push.payload)?;
        return parse_push_payload(payload);
    }
}

async fn post_bridge(
    api: &ICloudApi,
    path: &str,
    body: Value,
    headers: HeaderMap,
    allow_precondition_failed: bool,
) -> Result<u16> {
    let response = api
        .with_cookies(
            api.client
                .post(format!("{}{}", api.auth_endpoint, path))
                .headers(headers),
        )
        .json(&body)
        .send()
        .await?;
    // Bridge steps must not update Apple session headers: pyicloud uses raw
    // requests here. Capturing transient bridge headers can overwrite the real
    // X-Apple-Session-Token/scnt and make the final 2sv/trust login return 421.
    // Cookies are still refreshed, exactly as a requests.Session would.
    api.capture_cookies(&response);
    let status = response.status().as_u16();
    let accepted = status == 200
        || status == 204
        || status == 409
        || (allow_precondition_failed && status == 412);
    if !accepted {
        return Err(Error::other(format!(
            "Trusted-device bridge request failed (HTTP {status})."
        )));
    }
    Ok(status)
}

fn bridge_headers(api: &ICloudApi, source_app_id: Option<&str>) -> HeaderMap {
    let mut headers = api.auth_headers();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if let Some(app_id) = source_app_id
        && let Ok(value) = HeaderValue::from_str(app_id)
    {
        headers.insert("X-Apple-App-Id", value);
    }
    headers
}

fn step_request(session: &BridgeSession, next_step: u64, data: String) -> Value {
    let mut payload = json!({
        "sessionUUID": session.session_uuid,
        "data": data,
        "ptkn": session.push_token,
        "nextStep": next_step,
    });
    if let Some(idmsdata) = &session.idmsdata {
        payload["idmsdata"] = json!(idmsdata);
    }
    if let Some(akdata) = &session.akdata {
        let encoded = match akdata {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        payload["akdata"] = json!(encoded);
    }
    payload
}

fn hex_to_b64(value: &str) -> Result<String> {
    let bytes = hex::decode(value)
        .map_err(|_| Error::other("Malformed trusted-device bridge prover message."))?;
    Ok(b64(bytes))
}

fn b64_to_hex(value: &str) -> Result<String> {
    Ok(hex::encode(unb64(value).map_err(|_| {
        Error::other("Malformed trusted-device bridge prover message.")
    })?))
}

fn apply_step_push(session: &mut BridgeSession, push: BridgePushPayload) -> Result<()> {
    if push.session_uuid != session.session_uuid {
        return Err(Error::TwoFactor(
            "Trusted-device bridge returned a mismatched session UUID.".into(),
        ));
    }
    if !matches!(push.error_code, None | Some(0)) {
        return Err(Error::TwoFactor(
            "Trusted-device bridge returned an error push.".into(),
        ));
    }
    session.apply_push(push);
    Ok(())
}

/// Bootstrap the bridge until Apple delivers the first prompt payload.
///
/// The `/bridge/step/0` POST happens immediately after the push token arrives
/// (not after the first push): that POST is what causes the phone notification.
pub async fn start(api: &ICloudApi, options: &Value) -> Result<BridgeSession> {
    let boot = Hsa2BootContext::from_auth_options(options);
    let topic = resolve_apns_topic(&boot)?;
    let host = resolve_websocket_host(&boot)?;
    let origin = derive_origin(&api.auth_endpoint)?;
    let mut topics_by_hash = HashMap::new();
    topics_by_hash.insert(topic_hash(&topic), topic.clone());

    let signing_key = generate_signing_key()?;
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    let mut timestamp_ms: Option<u64> = None;
    let mut last_error: Option<Error> = None;
    for _ in 0..2 {
        let nonce = build_nonce(timestamp_ms.unwrap_or_else(now_ms));
        let signature: Signature = signing_key.sign(&nonce);
        let connection_message =
            encode_connection_message(&public_key, &nonce, signature.to_der().as_bytes());
        let connection_path = hex::encode(&connection_message);
        debug!(
            "Opening trusted-device websocket: bootstrapPayloadLen={}",
            connection_path.len()
        );
        // Let tungstenite build a valid client handshake (Sec-WebSocket-Key,
        // Version, Connection/Upgrade, Host). Building the Request by hand
        // omits those headers and Apple rejects it with a protocol error.
        let url = format!("wss://{host}/v2/{connection_path}");
        let mut request = url.as_str().into_client_request().map_err(|error| {
            Error::other(format!(
                "Could not build the trusted-device websocket request: {error}"
            ))
        })?;
        request.headers_mut().insert(
            "Origin",
            WsHeaderValue::from_str(&origin)
                .map_err(|_| Error::other("Invalid trusted-device websocket Origin header."))?,
        );
        request.headers_mut().insert(
            "User-Agent",
            WsHeaderValue::from_str(USER_AGENT)
                .map_err(|_| Error::other("Invalid trusted-device websocket User-Agent header."))?,
        );

        let (mut stream, _) = match connect_async(request).await {
            Ok(connection) => connection,
            Err(error) => {
                last_error = Some(Error::other(format!(
                    "Could not connect to the trusted-device bridge: {error}"
                )));
                continue;
            }
        };

        match wait_for_push_token(&mut stream).await {
            Ok(TokenWait::InvalidNonce(server_time)) => {
                debug!("Bridge server requested a nonce refresh.");
                timestamp_ms = Some(server_time);
                last_error = Some(Error::other(
                    "Trusted-device bridge rejected the connection nonce.",
                ));
                let _ = stream.close(None).await;
                continue;
            }
            Ok(TokenWait::Token(token)) => {
                let push_token = hex::encode(&token);
                send_binary(&mut stream, encode_web_filter(&topic)).await?;

                let session_uuid = format!("{}-{}", Uuid::new_v4(), now_ms());
                debug!(
                    "Posting bridge step 0: sessionUUID={} ptknLen={}",
                    summarize(Some(&session_uuid), 8),
                    push_token.len()
                );
                let headers = bridge_headers(api, boot.source_app_id.as_deref());
                post_bridge(
                    api,
                    &format!("{BRIDGE_STEP_PATH}0"),
                    json!({"sessionUUID": session_uuid, "ptkn": push_token}),
                    headers,
                    false,
                )
                .await?;

                let push = wait_for_bridge_push(&mut stream, &topic, &topics_by_hash).await?;
                if push.had_session_uuid && push.session_uuid != session_uuid {
                    return Err(Error::TwoFactor(
                        "Trusted-device bridge returned a mismatched session UUID.".into(),
                    ));
                }
                let mut session = BridgeSession {
                    stream,
                    connection_path,
                    push_token,
                    session_uuid: push.session_uuid.clone(),
                    topic,
                    topics_by_hash,
                    source_app_id: boot.source_app_id,
                    next_step: None,
                    push_payload: Value::Null,
                    txnid: None,
                    salt: None,
                    mid: None,
                    idmsdata: None,
                    akdata: None,
                    data: None,
                    encrypted_code: None,
                    error_code: None,
                };
                session.apply_push(push);
                return Ok(session);
            }
            Err(error) => {
                last_error = Some(error);
                let _ = stream.close(None).await;
                break;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        Error::TwoFactor("Failed to bootstrap the trusted-device bridge prompt.".into())
    }))
}

/// Complete the bridge verification and return false for a rejected code.
pub async fn validate_code(
    api: &ICloudApi,
    mut session: BridgeSession,
    code: &str,
    headers: &HeaderMap,
) -> Result<bool> {
    let result = validate_code_inner(api, &mut session, code, headers).await;
    session.close().await;
    result
}

async fn validate_code_inner(
    api: &ICloudApi,
    session: &mut BridgeSession,
    code: &str,
    headers: &HeaderMap,
) -> Result<bool> {
    if session.uses_legacy_verifier() {
        return Err(Error::TwoFactor(
            "Legacy trusted-device verification should bypass the bridge verifier.".into(),
        ));
    }
    if session.next_step.as_deref() != Some("2") {
        return Err(Error::TwoFactor(
            "Trusted-device bridge is not ready for step 2 verification.".into(),
        ));
    }
    let salt = session
        .salt
        .clone()
        .ok_or_else(|| Error::TwoFactor("Trusted-device bridge payload has no salt.".into()))?;

    let mut prover = TrustedDeviceBridgeProver::new();
    prover
        .init_with_salt(&salt, code)
        .map_err(|_| Error::two_factor("Trusted-device bridge prover could not be initialized."))?;
    let message1 = prover.get_message1();

    let mut bridge_headers = headers.clone();
    if let Some(app_id) = &session.source_app_id
        && let Ok(value) = HeaderValue::from_str(app_id)
    {
        bridge_headers.insert("X-Apple-App-Id", value);
    }

    debug!(
        "Posting bridge step 2: sessionUUID={}",
        summarize(Some(&session.session_uuid), 8)
    );
    post_bridge(
        api,
        &format!("{BRIDGE_STEP_PATH}2"),
        step_request(session, 2, hex_to_b64(&message1)?),
        bridge_headers.clone(),
        false,
    )
    .await?;

    let step4_push =
        wait_for_bridge_push(&mut session.stream, &session.topic, &session.topics_by_hash).await?;
    apply_step_push(session, step4_push)?;
    if session.next_step.as_deref() != Some("4") {
        return Err(Error::TwoFactor(
            "Trusted-device bridge returned an unexpected post-step-2 payload.".into(),
        ));
    }
    let data = session.data.clone().ok_or_else(|| {
        Error::TwoFactor("Trusted-device bridge step 4 has no prover data.".into())
    })?;
    let (first, second) = unb64(&data)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|text| {
            text.split_once('_')
                .map(|(a, b)| (a.to_string(), b.to_string()))
        })
        .ok_or_else(|| {
            Error::TwoFactor("Trusted-device bridge step 4 data is malformed.".into())
        })?;
    let bridge_message1 = b64_to_hex(&first)?;
    let bridge_message2 = b64_to_hex(&second)?;

    let message2 = prover
        .process_message1(&bridge_message1)
        .map_err(|_| Error::two_factor("Trusted-device bridge step 4 data is malformed."))?;
    if prover.process_message2(&bridge_message2).is_err() || !prover.is_verified() {
        debug!("Trusted-device bridge prover rejected the confirmation.");
        return Ok(false);
    }

    debug!(
        "Posting bridge step 4: sessionUUID={}",
        summarize(Some(&session.session_uuid), 8)
    );
    post_bridge(
        api,
        &format!("{BRIDGE_STEP_PATH}4"),
        step_request(session, 4, hex_to_b64(&message2)?),
        bridge_headers.clone(),
        false,
    )
    .await?;

    let final_push =
        wait_for_bridge_push(&mut session.stream, &session.topic, &session.topics_by_hash).await?;
    apply_step_push(session, final_push)?;
    if !matches!(session.next_step.as_deref(), Some("4" | "6")) {
        return Err(Error::TwoFactor(
            "Trusted-device bridge returned an unexpected final payload.".into(),
        ));
    }
    let encrypted_code = session.encrypted_code.clone().ok_or_else(|| {
        Error::TwoFactor("Trusted-device bridge final payload has no encryptedCode.".into())
    })?;
    let derived_code = prover
        .decrypt_message(&encrypted_code)
        .map_err(|_| Error::other("Failed to decrypt the trusted-device bridge code."))?;

    let verify_status = post_bridge(
        api,
        BRIDGE_CODE_VALIDATE_PATH,
        json!({"sessionUUID": session.session_uuid, "code": derived_code}),
        bridge_headers.clone(),
        true,
    )
    .await?;
    let verified = verify_status != 412;

    let completion = if session.next_step.as_deref() == Some("6") {
        6
    } else {
        4
    };
    post_bridge(
        api,
        &format!("{BRIDGE_STEP_PATH}{completion}"),
        step_request(session, completion, DONE_DATA_B64.to_string()),
        bridge_headers,
        false,
    )
    .await?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_context_reads_nested_and_flat_shapes() {
        let options = json!({
            "direct": {"twoSV": {
                "authInitialRoute": "auth/bridge/step",
                "bridgeInitiateData": {"apnsTopic": "com.apple.test", "sourceAppId": "app"},
                "sourceAppId": "app"
            }, "hasTrustedDevices": true}
        });
        let boot = Hsa2BootContext::from_auth_options(&options);
        assert_eq!(boot.auth_initial_route, "auth/bridge/step");
        assert!(boot.has_trusted_devices);
        assert_eq!(boot.source_app_id.as_deref(), Some("app"));
        assert!(supports_bridge(&options));
    }

    #[test]
    fn connection_frame_uses_length_delimited_fields() {
        let mut message = Vec::new();
        encode_bytes_field(1, b"abc", &mut message);
        assert_eq!(message, vec![0x0a, 0x03, b'a', b'b', b'c']);
        let frame = encode_connection_message(&[0x04; 65], &[0x09; 17], &[0x30, 0x01]);
        let outer = decode_fields(&frame).unwrap();
        let inner = decode_fields(bytes_field(&outer, 1).unwrap()).unwrap();
        assert_eq!(bytes_field(&inner, 1).unwrap().len(), 65);
        assert_eq!(bytes_field(&inner, 2).unwrap().len(), 17);
        assert_eq!(bytes_field(&inner, 3).unwrap(), &[0x01, 0x03, 0x30, 0x01]);
        let expiration = decode_fields(bytes_field(&inner, 5).unwrap()).unwrap();
        assert_eq!(
            varint_field(&expiration, 1),
            NEW_CONNECTION_EXPIRATION_SECONDS
        );
    }

    #[test]
    fn server_messages_decode_push_and_connection() {
        let mut connection = Vec::new();
        encode_bytes_field(1, b"dGVzdA==", &mut connection);
        encode_uint32_field(2, 0, &mut connection);
        let mut frame = Vec::new();
        encode_bytes_field(1, &connection, &mut frame);
        let decoded = decode_server_message(&frame).unwrap();
        assert_eq!(decoded.connection.unwrap().push_token_b64, "dGVzdA==");

        let mut push = Vec::new();
        encode_bytes_field(1, b"topic", &mut push);
        encode_uint32_field(2, 7, &mut push);
        encode_bytes_field(4, b"{}", &mut push);
        let mut frame = Vec::new();
        encode_bytes_field(2, &push, &mut frame);
        let decoded = decode_server_message(&frame).unwrap();
        let push = decoded.push.unwrap();
        assert_eq!(push.topic, b"topic");
        assert_eq!(push.message_id, 7);
        assert_eq!(push.payload, b"{}");
    }

    #[test]
    fn json_payload_is_recovered_from_noisy_frame() {
        let payload = b"noise{\"sessionUUID\":\"abc\",\"nextStep\":2}trailer";
        let value = extract_json_payload(payload).unwrap();
        assert_eq!(value["sessionUUID"], "abc");
        assert_eq!(value["nextStep"], 2);
        assert!(extract_json_payload(b"nothing here").is_err());
    }

    #[test]
    fn push_payload_requires_a_session_identifier() {
        assert!(parse_push_payload(json!({"nextStep": "2"})).is_err());
        let push = parse_push_payload(json!({
            "flowid": "flow-1",
            "nextStep": 2,
            "salt": "c2FsdA==",
            "txnid": "tx_W"
        }))
        .unwrap();
        assert_eq!(push.session_uuid, "flow-1");
        assert_eq!(push.next_step.as_deref(), Some("2"));
        assert!(!push.had_session_uuid);
    }

    #[test]
    fn websocket_hosts_and_topic_hashes_are_deterministic() {
        let prod = Hsa2BootContext::from_auth_options(&json!({
            "bridgeInitiateData": {"apnsEnvironment": "prod"}
        }));
        assert_eq!(
            resolve_websocket_host(&prod).unwrap(),
            "websocket.push.apple.com"
        );
        let sandbox = Hsa2BootContext::from_auth_options(&json!({
            "bridgeInitiateData": {"webSocketUrl": "wss://example.test/v2/abc"}
        }));
        assert_eq!(resolve_websocket_host(&sandbox).unwrap(), "example.test");
        assert_eq!(topic_hash("topic").len(), 40);
    }

    #[test]
    fn base64_hex_helpers_round_trip() {
        assert_eq!(b64_to_hex("aGVsbG8=").unwrap(), "68656c6c6f");
        assert_eq!(hex_to_b64("68656c6c6f").unwrap(), "aGVsbG8=");
    }
}
