//! Port of pyicloud's `hsa2_bridge_prover.py` (Apple HSA2 trusted-device
//! bridge prover).
//!
//! This module deliberately keeps the hand-rolled P-256 point arithmetic,
//! HKDF-like expansion, SPAKE2-style handshake and AES-GCM payload layout of
//! the Python implementation. Apple's verifier expects the exact transcript
//! bytes produced by that code, so none of the crypto may be "simplified" to
//! a different (even if standard) construction.
//!
//! The public API mirrors the Python `TrustedDeviceBridgeProver` one-to-one.
//! Where the Python raises for uninitialised state this Rust API returns an
//! empty string (the getters) or an [`Error::Other`] (the fallible methods),
//! because the fixed signatures cannot express both outcomes.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::{TryRngCore, rngs::OsRng};
use scrypt::{Params as ScryptParams, scrypt as scrypt_kdf};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCRYPT_LOG_N: u8 = 14; // 2^14 == 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 64;

const CLIENT_IDENTITY: &[u8] = b"com.apple.security.webprover";
const SERVER_IDENTITY: &[u8] = b"com.apple.security.webverifier";
const SPAKE2_CONTEXT: &[u8] = b"SPAKE2Web";
const KEY_LENGTH: usize = 32;
const VERIFIER_KEY_INFO: &[u8] = b"webVerifier";
const PROVER_KEY_INFO: &[u8] = b"webProver";

const P256_P_HEX: &str = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
const P256_B_HEX: &str = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
const P256_ORDER_HEX: &str = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
const P256_GX_HEX: &str = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
const P256_GY_HEX: &str = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
const SPAKE2_M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const SPAKE2_N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

/// Only version 0 is described by the bridge protocol: 12-byte IV, 16-byte tag.
const AES_GCM_IV_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;

fn aes_iv(iv: &[u8]) -> Result<[u8; AES_GCM_IV_LEN]> {
    if iv.len() != AES_GCM_IV_LEN {
        return Err(Error::other("Malformed bridge payload"));
    }
    let mut bytes = [0u8; AES_GCM_IV_LEN];
    bytes.copy_from_slice(iv);
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Small hex / base64 helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_val(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::other("Invalid hex string")),
    }
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(Error::other("Invalid hex string"));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    Ok(out)
}

fn b64_decode(value: &str) -> Result<Vec<u8>> {
    B64.decode(value)
        .map_err(|err| Error::other(format!("Invalid base64: {err}")))
}

#[cfg(test)]
fn b64_encode(value: &[u8]) -> String {
    B64.encode(value)
}

// ---------------------------------------------------------------------------
// Affine P-256 arithmetic
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Point {
    x: Option<BigUint>,
    y: Option<BigUint>,
}

impl Point {
    fn infinity() -> Self {
        Self { x: None, y: None }
    }

    fn new(x: BigUint, y: BigUint) -> Self {
        Self {
            x: Some(x),
            y: Some(y),
        }
    }

    fn is_infinity(&self) -> bool {
        self.x.is_none() || self.y.is_none()
    }

    fn coords(&self) -> (&BigUint, &BigUint) {
        (
            self.x.as_ref().expect("finite point has an x coordinate"),
            self.y.as_ref().expect("finite point has a y coordinate"),
        )
    }
}

fn bigint_from_hex(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid hex constant")
}

fn curve_p() -> BigUint {
    bigint_from_hex(P256_P_HEX)
}

fn curve_a() -> BigUint {
    // _P256_A = (p - 3) % p == p - 3 because p > 3.
    &curve_p() - BigUint::from(3u32)
}

fn curve_b() -> BigUint {
    bigint_from_hex(P256_B_HEX)
}

fn curve_order() -> BigUint {
    bigint_from_hex(P256_ORDER_HEX)
}

fn generator() -> Point {
    Point::new(bigint_from_hex(P256_GX_HEX), bigint_from_hex(P256_GY_HEX))
}

fn spake2_m() -> Point {
    decode_point(SPAKE2_M).expect("SPAKE2_M is a valid compressed point")
}

fn spake2_n() -> Point {
    decode_point(SPAKE2_N).expect("SPAKE2_N is a valid compressed point")
}

fn pow_mod(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

/// Modular inverse modulo the (prime) curve field. Uses Fermat's little
/// theorem, matching Python's `pow(value, -1, p)`.
fn mod_inv(value: &BigUint, modulus: &BigUint) -> BigUint {
    pow_mod(value, &(modulus - BigUint::from(2u32)), modulus)
}

/// Big-endian encoding, optionally to a fixed width. With no width this
/// mirrors Python's `_int_to_bytes`: `max(1, (bit_length + 7) // 8)` bytes.
fn int_to_bytes(value: &BigUint, length: Option<usize>) -> Vec<u8> {
    let width = length.unwrap_or_else(|| {
        let bits = value.bits() as usize;
        std::cmp::max(1, (bits + 7) / 8)
    });
    let raw = value.to_bytes_be();
    debug_assert!(raw.len() <= width);
    let mut out = vec![0u8; width];
    out[width - raw.len()..].copy_from_slice(&raw);
    out
}

fn is_on_curve(point: &Point) -> bool {
    if point.is_infinity() {
        return false;
    }
    let (x, y) = point.coords();
    let p = curve_p();
    let lhs = pow_mod(y, &BigUint::from(2u32), &p);
    let rhs = (pow_mod(x, &BigUint::from(3u32), &p) + curve_a() * x + curve_b()) % &p;
    ((lhs + &p - rhs) % &p).is_zero()
}

fn decode_point(value: &str) -> Result<Point> {
    let raw = hex_decode(value)?;
    let point = if raw.len() == 65 && raw[0] == 0x04 {
        Point::new(
            BigUint::from_bytes_be(&raw[1..33]),
            BigUint::from_bytes_be(&raw[33..65]),
        )
    } else if raw.len() == 33 && (raw[0] == 0x02 || raw[0] == 0x03) {
        let p = curve_p();
        let x = BigUint::from_bytes_be(&raw[1..]);
        let rhs = (pow_mod(&x, &BigUint::from(3u32), &p) + curve_a() * &x + curve_b()) % &p;
        let mut y = pow_mod(&rhs, &((&p + BigUint::from(1u32)) >> 2usize), &p);
        if y.bit(0) != (raw[0] & 1 == 1) {
            y = (&p - y) % &p;
        }
        Point::new(x, y)
    } else {
        return Err(Error::other("Unsupported P-256 point encoding."));
    };

    if !is_on_curve(&point) {
        return Err(Error::other("Invalid P-256 point."));
    }
    Ok(point)
}

fn encode_point(point: &Point) -> Result<String> {
    if point.is_infinity() {
        return Err(Error::other("Cannot encode the point at infinity."));
    }
    let (x, y) = point.coords();
    Ok(format!(
        "04{}{}",
        hex_encode(&int_to_bytes(x, Some(32))),
        hex_encode(&int_to_bytes(y, Some(32)))
    ))
}

fn negate(point: &Point) -> Point {
    if point.is_infinity() {
        return point.clone();
    }
    let (x, y) = point.coords();
    let p = curve_p();
    Point::new(x.clone(), (&p - y) % &p)
}

/// Affine point addition. All callers pass validated curve points, so this is
/// infallible (the only non-trivial operation is an inverse of a non-zero
/// field element).
fn add_points(left: &Point, right: &Point) -> Point {
    if left.is_infinity() {
        return right.clone();
    }
    if right.is_infinity() {
        return left.clone();
    }

    let (lx, ly) = left.coords();
    let (rx, ry) = right.coords();
    let p = curve_p();

    if lx == rx && ((ly + ry) % &p).is_zero() {
        return Point::infinity();
    }

    let slope = if lx == rx && ly == ry {
        if ly.is_zero() {
            return Point::infinity();
        }
        let numerator = (BigUint::from(3u32) * lx * lx + curve_a()) % &p;
        let denominator = (BigUint::from(2u32) * ly) % &p;
        (numerator * mod_inv(&denominator, &p)) % &p
    } else {
        let numerator = (ry + &p - ly) % &p;
        let denominator = (rx + &p - lx) % &p;
        (numerator * mod_inv(&denominator, &p)) % &p
    };

    let x = ((&slope * &slope) + &p - lx + &p - rx) % &p;
    let y = (&slope * (lx + &p - &x) + &p - ly) % &p;
    Point::new(x, y)
}

/// Double-and-add scalar multiplication; the scalar is reduced mod the group
/// order exactly as in the Python implementation.
fn multiply_point(point: &Point, scalar: &BigUint) -> Point {
    let mut scalar = scalar % curve_order();
    let mut result = Point::infinity();
    let mut addend = point.clone();
    while !scalar.is_zero() {
        if scalar.bit(0) {
            result = add_points(&result, &addend);
        }
        addend = add_points(&addend, &addend);
        scalar >>= 1usize;
    }
    result
}

// ---------------------------------------------------------------------------
// Transcript, HKDF-like derivation and shared secrets
// ---------------------------------------------------------------------------

fn concat_length_prefixed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// HKDF-like expand used by the bridge worker. Note the salt default and the
/// odd `previous || info || counter` block input, both of which must match.
fn hkdf_like(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let salt = if salt.is_empty() {
        vec![0u8; 32]
    } else {
        salt.to_vec()
    };
    let prk = hmac_sha256(&salt, ikm);

    let mut blocks = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter: u8 = 1;
    while blocks.len() < length {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac_sha256(&prk, &input).to_vec();
        blocks.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    blocks.truncate(length);
    blocks
}

fn derive_key(ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    // Bridge quirk: any info label containing "ConfirmationKeys" expands to
    // 64 bytes regardless of the requested length.
    let actual_length = if info
        .windows(b"ConfirmationKeys".len())
        .any(|window| window == b"ConfirmationKeys")
    {
        64
    } else {
        length
    };
    hkdf_like(ikm, b"", info, actual_length)
}

fn derive_prover_and_verifier_keys(raw_key_hex: &str) -> Result<(String, String)> {
    let raw_key = hex_decode(raw_key_hex)?;
    let verifier_key = derive_key(&raw_key, VERIFIER_KEY_INFO, KEY_LENGTH);
    let prover_key = derive_key(&raw_key, PROVER_KEY_INFO, KEY_LENGTH);
    Ok((hex_encode(&verifier_key), hex_encode(&prover_key)))
}

#[derive(Clone, Debug)]
struct SharedSecret {
    confirm_client: Vec<u8>,
    confirm_server: Vec<u8>,
    shared_key: Vec<u8>,
}

impl SharedSecret {
    fn new(transcript: &[u8]) -> Self {
        let digest = Sha256::digest(transcript);
        let confirmations = derive_key(&digest, b"ConfirmationKeys", 64);
        Self {
            confirm_client: confirmations[..32].to_vec(),
            confirm_server: confirmations[32..64].to_vec(),
            shared_key: derive_key(&digest, b"SharedKey", KEY_LENGTH),
        }
    }
}

#[derive(Clone, Debug)]
struct ClientSharedSecret {
    secret: SharedSecret,
    share_p: String,
    share_v: String,
}

impl ClientSharedSecret {
    fn new(transcript: &[u8], share_p: String, share_v: String) -> Self {
        Self {
            secret: SharedSecret::new(transcript),
            share_p,
            share_v,
        }
    }

    fn get_confirmation(&self) -> String {
        let share = hex_decode(&self.share_v).expect("stored share is valid hex");
        hex_encode(&hmac_sha256(&self.secret.confirm_client, &share))
    }

    fn verify(&self, message_hex: &str) -> Result<Vec<u8>> {
        let share = hex_decode(&self.share_p)?;
        let expected = hex_encode(&hmac_sha256(&self.secret.confirm_server, &share));
        if expected != message_hex {
            return Err(Error::other("invalid confirmation from server"));
        }
        Ok(self.secret.shared_key.clone())
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ServerSharedSecret {
    secret: SharedSecret,
    share_p: String,
    share_v: String,
}

#[cfg(test)]
impl ServerSharedSecret {
    fn new(transcript: &[u8], share_p: String, share_v: String) -> Self {
        Self {
            secret: SharedSecret::new(transcript),
            share_p,
            share_v,
        }
    }

    fn get_confirmation(&self) -> String {
        let share = hex_decode(&self.share_p).expect("stored share is valid hex");
        hex_encode(&hmac_sha256(&self.secret.confirm_server, &share))
    }

    fn verify(&self, message_hex: &str) -> Result<Vec<u8>> {
        let share = hex_decode(&self.share_v)?;
        let expected = hex_encode(&hmac_sha256(&self.secret.confirm_client, &share));
        if expected != message_hex {
            return Err(Error::other("invalid confirmation from client"));
        }
        Ok(self.secret.shared_key.clone())
    }
}

// ---------------------------------------------------------------------------
// SPAKE2-style handshakes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct ClientHandshake {
    x: BigUint,
    w0: BigUint,
    w1: BigUint,
}

impl ClientHandshake {
    fn message1_point(&self) -> Point {
        add_points(
            &multiply_point(&generator(), &self.x),
            &multiply_point(&spake2_m(), &self.w0),
        )
    }

    fn get_message(&self) -> Result<String> {
        encode_point(&self.message1_point())
    }

    fn finish(&self, server_message_hex: &str) -> Result<ClientSharedSecret> {
        let server_point = decode_point(server_message_hex)?;
        if server_point.is_infinity() {
            return Err(Error::other("invalid curve point"));
        }

        let adjusted = add_points(
            &server_point,
            &negate(&multiply_point(&spake2_n(), &self.w0)),
        );
        let y_point = multiply_point(&adjusted, &self.x);
        let v_point = multiply_point(&adjusted, &self.w1);

        let transcript = concat_length_prefixed(&[
            SPAKE2_CONTEXT,
            CLIENT_IDENTITY,
            SERVER_IDENTITY,
            &hex_decode(&encode_point(&spake2_m())?)?,
            &hex_decode(&encode_point(&spake2_n())?)?,
            &hex_decode(&encode_point(&self.message1_point())?)?,
            &hex_decode(&encode_point(&server_point)?)?,
            &hex_decode(&encode_point(&y_point)?)?,
            &hex_decode(&encode_point(&v_point)?)?,
            &int_to_bytes(&self.w0, None),
        ]);

        Ok(ClientSharedSecret::new(
            &transcript,
            self.get_message()?,
            server_message_hex.to_owned(),
        ))
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ServerHandshake {
    y: BigUint,
    w0: BigUint,
    verifier_point: Point,
}

#[cfg(test)]
impl ServerHandshake {
    fn message1_point(&self) -> Point {
        add_points(
            &multiply_point(&generator(), &self.y),
            &multiply_point(&spake2_n(), &self.w0),
        )
    }

    fn get_message(&self) -> Result<String> {
        encode_point(&self.message1_point())
    }

    fn finish(&self, client_message_hex: &str) -> Result<ServerSharedSecret> {
        let client_point = decode_point(client_message_hex)?;
        if client_point.is_infinity() {
            return Err(Error::other("invalid curve point"));
        }

        let adjusted = add_points(
            &client_point,
            &negate(&multiply_point(&spake2_m(), &self.w0)),
        );
        let y_point = multiply_point(&adjusted, &self.y);
        let verifier_share = multiply_point(&self.verifier_point, &self.y);

        let transcript = concat_length_prefixed(&[
            SPAKE2_CONTEXT,
            CLIENT_IDENTITY,
            SERVER_IDENTITY,
            &hex_decode(&encode_point(&spake2_m())?)?,
            &hex_decode(&encode_point(&spake2_n())?)?,
            &hex_decode(&encode_point(&client_point)?)?,
            &hex_decode(&encode_point(&self.message1_point())?)?,
            &hex_decode(&encode_point(&y_point)?)?,
            &hex_decode(&encode_point(&verifier_share)?)?,
            &int_to_bytes(&self.w0, None),
        ]);

        Ok(ServerSharedSecret::new(
            &transcript,
            client_message_hex.to_owned(),
            self.get_message()?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Password / randomness derivation
// ---------------------------------------------------------------------------

fn compute_w0_w1(password: &str, salt_b64: &str) -> Result<(BigUint, BigUint)> {
    let salt = b64_decode(salt_b64)?;
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)
        .map_err(|err| Error::other(format!("scrypt params: {err}")))?;
    let mut derived = [0u8; SCRYPT_DKLEN];
    scrypt_kdf(password.as_bytes(), &salt, &params, &mut derived)
        .map_err(|err| Error::other(format!("scrypt failed: {err}")))?;

    let midpoint = derived.len() / 2;
    Ok((
        BigUint::from_bytes_be(&derived[..midpoint]),
        BigUint::from_bytes_be(&derived[midpoint..]),
    ))
}

/// Uniform sample from `[1, order)` with rejection sampling, mirroring
/// `secrets.randbelow(_P256_ORDER)` plus the non-zero retry loop.
fn random_nonzero_scalar() -> BigUint {
    let order = curve_order();
    let mut bytes = [0u8; 32];
    loop {
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS random source unavailable");
        let scalar = BigUint::from_bytes_be(&bytes);
        if !scalar.is_zero() && scalar < order {
            return scalar;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of a successful verifier confirmation exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProverResult {
    pub verified: bool,
    pub key: String,
    /// Reserved for the caller to fill in after decrypting Apple's final
    /// validation payload. Always `None` immediately after confirmation.
    pub decrypted_code: Option<String>,
}

/// Client-side prover mirroring Apple's prover worker.
#[derive(Debug, Default)]
pub struct TrustedDeviceBridgeProver {
    client: Option<ClientHandshake>,
    shared_secret: Option<ClientSharedSecret>,
    raw_key: Option<String>,
    verified: bool,
    verifier_key: Option<String>,
    // Kept to mirror the Python prover's persisted keys; currently unused by
    // the public API because Apple's final payload uses the verifier key.
    #[allow(dead_code)]
    prover_key: Option<String>,
}

impl TrustedDeviceBridgeProver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialise the prover with Apple's base64 bridge salt and the code the
    /// user entered. Resets all state from any previous attempt.
    pub fn init_with_salt(&mut self, salt_b64: &str, code: &str) -> Result<()> {
        let (w0, w1) = compute_w0_w1(code, salt_b64)?;
        self.client = Some(ClientHandshake {
            x: random_nonzero_scalar(),
            w0,
            w1,
        });
        self.shared_secret = None;
        self.raw_key = None;
        self.verified = false;
        self.verifier_key = None;
        self.prover_key = None;
        Ok(())
    }

    /// Return the prover's first bridge message (uncompressed SEC1 point, hex).
    /// Empty if [`Self::init_with_salt`] has not been called.
    pub fn get_message1(&self) -> String {
        match &self.client {
            Some(client) => client.get_message().unwrap_or_default(),
            None => String::new(),
        }
    }

    /// Process Apple's first bridge message and return the prover confirmation.
    pub fn process_message1(&mut self, message_hex: &str) -> Result<String> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| Error::other("init_with_salt must be called before process_message1"))?;
        let secret = client.finish(message_hex)?;
        let confirmation = secret.get_confirmation();
        self.shared_secret = Some(secret);
        Ok(confirmation)
    }

    /// Return the prover confirmation generated from the shared transcript.
    /// Empty if [`Self::process_message1`] has not been called.
    pub fn get_message2(&self) -> String {
        match &self.shared_secret {
            Some(secret) => secret.get_confirmation(),
            None => String::new(),
        }
    }

    /// Verify Apple's confirmation, persist the derived bridge keys and return
    /// the raw shared key as hex.
    pub fn process_message2(&mut self, message_hex: &str) -> Result<BridgeProverResult> {
        let raw_key = {
            let secret = self.shared_secret.as_ref().ok_or_else(|| {
                Error::other("process_message1 must be called before process_message2")
            })?;
            hex_encode(&secret.verify(message_hex)?)
        };
        let (verifier_key, prover_key) = derive_prover_and_verifier_keys(&raw_key)?;
        self.raw_key = Some(raw_key.clone());
        self.verifier_key = Some(verifier_key);
        self.prover_key = Some(prover_key);
        self.verified = true;
        Ok(BridgeProverResult {
            verified: true,
            key: raw_key,
            decrypted_code: None,
        })
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Return the raw shared bridge key as hex. Empty before confirmation.
    pub fn get_key(&self) -> String {
        self.raw_key.clone().unwrap_or_default()
    }

    /// Decrypt Apple's final encrypted validation code.
    ///
    /// Payload layout: `version(1) || iv(12) || tag(16) || ciphertext`. The
    /// version byte is also used as AEAD associated data.
    pub fn decrypt_message(&self, ciphertext_b64: &str) -> Result<String> {
        let malformed = || Error::other("Malformed bridge payload");
        let verifier_key = self
            .verifier_key
            .as_ref()
            .ok_or_else(|| Error::other("Bridge verifier key is not available."))?;

        let payload = b64_decode(ciphertext_b64).map_err(|_| malformed())?;
        let version = *payload.first().ok_or_else(malformed)?;
        let (iv_len, tag_len) = match version {
            0 => (AES_GCM_IV_LEN, AES_GCM_TAG_LEN),
            _ => return Err(malformed()),
        };
        if payload.len() < 1 + iv_len + tag_len {
            return Err(malformed());
        }
        let iv = &payload[1..1 + iv_len];
        let tag = &payload[1 + iv_len..1 + iv_len + tag_len];
        let ciphertext = &payload[1 + iv_len + tag_len..];

        let key_bytes = hex_decode(verifier_key).map_err(|_| malformed())?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| malformed())?;
        let mut ciphertext_and_tag = Vec::with_capacity(ciphertext.len() + tag_len);
        ciphertext_and_tag.extend_from_slice(ciphertext);
        ciphertext_and_tag.extend_from_slice(tag);
        let plaintext = cipher
            .decrypt(
                &Nonce::from(aes_iv(iv)?),
                Payload {
                    msg: &ciphertext_and_tag,
                    aad: &[version],
                },
            )
            .map_err(|_| malformed())?;
        String::from_utf8(plaintext).map_err(|_| malformed())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed scalars extracted from the Python implementation with a patched
    // `_random_nonzero_scalar`, plus password "123456" and
    // salt_b64 "dGVzdC1zYWx0LXZlY3Rvci0wMDAx".
    const PASSWORD: &str = "123456";
    const SALT_B64: &str = "dGVzdC1zYWx0LXZlY3Rvci0wMDAx";
    const W0_DEC: &str =
        "36609316449040540889937916836385973208686938560264571274960552625445841918112";
    const W1_DEC: &str =
        "54022014178355445458197989503927641256134656847399418424266738700712001338336";
    const X_DEC: &str = "123456789012345678901234567890123456789012345678901234567890123456789";
    const Y_DEC: &str = "987654321098765432109876543210987654321098765432109876543210987654322";

    const CLIENT_M1: &str = "04df7d509bd19b7fd9fc1ab8178a3ef2015a21485347d83463d01da0b10e1c11e84b3b7984b7527d7bc27d8d477b225f0529ff7557401deb9721bff16b52a0f460";
    const SERVER_M1: &str = "04ac6de64c121f84f0957bd62a6096d0069aac00e54359f2af5dd4641bdb9e81331ba18110a39333f3204be9addd7c854d8991e047af8b8049bda7a49797312f5a";
    const CLIENT_M2: &str = "8b43b6a3e161268c4e655db17c4ad9ae6194b1b87cac98e9e3becac1b2f878df";
    const SERVER_M2: &str = "c0a7b797a9b6d195c95ddfed87a1e1768027d3a1e4777e0e38a94b37e56aef8b";
    const RAW_KEY: &str = "37fd62a87f41bb6eb35ed8e4fa0fd0f250c1cb00ccee04f93a93968116d306fb";
    const VERIFIER_KEY: &str = "0b2b0e11ca0d0fb221aaad0d2edb3c38c2b7dbafff5b2e970330a269d7c44143";
    const PROVER_KEY: &str = "e55c5c13a628962af08bc22f8898778ad8cfa4357080a39030b75431a7dd845b";
    const CIPHERTEXT_B64: &str =
        "ABmObalDvOIrh8FaL1inLV5AsZuAX2tjo5IyLuEXJhLKXhMJXEH+CTfiBI0tAp8mEmFe";
    const PLAINTEXT: &str = "ABC123-validation-code";

    fn dec(value: &str) -> BigUint {
        BigUint::parse_bytes(value.as_bytes(), 10).unwrap()
    }

    fn fixed_client() -> ClientHandshake {
        ClientHandshake {
            x: dec(X_DEC),
            w0: dec(W0_DEC),
            w1: dec(W1_DEC),
        }
    }

    fn fixed_server() -> ServerHandshake {
        ServerHandshake {
            y: dec(Y_DEC),
            w0: dec(W0_DEC),
            verifier_point: multiply_point(&generator(), &dec(W1_DEC)),
        }
    }

    /// Test-only mirror of Python's `_TrustedDeviceBridgeServerProver`.
    struct TestServer {
        handshake: ServerHandshake,
        shared_secret: Option<ServerSharedSecret>,
        verifier_key: Option<String>,
    }

    impl TestServer {
        fn new(password: &str, salt_b64: &str) -> Result<Self> {
            Self::with_y(password, salt_b64, random_nonzero_scalar())
        }

        fn with_y(password: &str, salt_b64: &str, y: BigUint) -> Result<Self> {
            let (w0, w1) = compute_w0_w1(password, salt_b64)?;
            Ok(Self {
                handshake: ServerHandshake {
                    y,
                    w0,
                    verifier_point: multiply_point(&generator(), &w1),
                },
                shared_secret: None,
                verifier_key: None,
            })
        }

        fn get_message1(&self) -> Result<String> {
            self.handshake.get_message()
        }

        fn process_message1(&mut self, client_message_hex: &str) -> Result<String> {
            let secret = self.handshake.finish(client_message_hex)?;
            let confirmation = secret.get_confirmation();
            self.shared_secret = Some(secret);
            Ok(confirmation)
        }

        fn verify_message2(&mut self, message_hex: &str) -> Result<String> {
            let secret = self
                .shared_secret
                .as_ref()
                .ok_or_else(|| Error::other("process_message1 must be called first"))?;
            let raw_key = hex_encode(&secret.verify(message_hex)?);
            let (verifier_key, _) = derive_prover_and_verifier_keys(&raw_key)?;
            self.verifier_key = Some(verifier_key);
            Ok(raw_key)
        }

        fn encrypt_message(&self, plaintext: &str) -> Result<String> {
            let verifier_key = self
                .verifier_key
                .as_ref()
                .ok_or_else(|| Error::other("Bridge verifier key is not available."))?;
            let key_bytes = hex_decode(verifier_key)?;
            let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                .map_err(|_| Error::other("Invalid AES key"))?;
            let mut iv = [0u8; AES_GCM_IV_LEN];
            OsRng
                .try_fill_bytes(&mut iv)
                .expect("OS random source unavailable");
            let encrypted = cipher
                .encrypt(
                    &Nonce::from(aes_iv(&iv)?),
                    Payload {
                        msg: plaintext.as_bytes(),
                        aad: &[0u8],
                    },
                )
                .map_err(|_| Error::other("Encryption failed"))?;
            let split = encrypted.len() - AES_GCM_TAG_LEN;
            let ciphertext = &encrypted[..split];
            let tag = &encrypted[split..];
            let mut payload = vec![0u8];
            payload.extend_from_slice(&iv);
            payload.extend_from_slice(tag);
            payload.extend_from_slice(ciphertext);
            Ok(b64_encode(&payload))
        }
    }

    #[test]
    fn point_encoding_and_arithmetic() {
        let m = spake2_m();
        let n = spake2_n();
        assert!(is_on_curve(&m));
        assert!(is_on_curve(&n));
        assert!(is_on_curve(&generator()));

        // Compressed M/N decode to the expected uncompressed SEC1 form.
        assert_eq!(
            encode_point(&m).unwrap(),
            "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20"
        );

        // Doubling then adding agrees with multiplication by 3.
        let g = generator();
        let doubled = add_points(&g, &g);
        let tripled = add_points(&doubled, &g);
        assert_eq!(tripled, multiply_point(&g, &BigUint::from(3u32)));

        // P + (-P) is infinity; scalar multiplication by the order is infinity.
        assert!(add_points(&g, &negate(&g)).is_infinity());
        assert!(multiply_point(&g, &curve_order()).is_infinity());

        assert!(decode_point("04deadbeef").is_err());
        assert!(decode_point("02").is_err());
    }

    #[test]
    fn scrypt_derives_expected_scalars() {
        let (w0, w1) = compute_w0_w1(PASSWORD, SALT_B64).unwrap();
        assert_eq!(w0, dec(W0_DEC));
        assert_eq!(w1, dec(W1_DEC));
    }

    #[test]
    fn known_handshake_vectors() {
        let client = fixed_client();
        let server = fixed_server();

        assert_eq!(client.get_message().unwrap(), CLIENT_M1);
        assert_eq!(server.get_message().unwrap(), SERVER_M1);

        let client_secret = client.finish(SERVER_M1).unwrap();
        let server_secret = server.finish(CLIENT_M1).unwrap();

        assert_eq!(client_secret.get_confirmation(), CLIENT_M2);
        assert_eq!(server_secret.get_confirmation(), SERVER_M2);
        assert_eq!(
            hex_encode(&client_secret.verify(SERVER_M2).unwrap()),
            RAW_KEY
        );
        assert_eq!(
            hex_encode(&server_secret.verify(CLIENT_M2).unwrap()),
            RAW_KEY
        );

        let (verifier_key, prover_key) = derive_prover_and_verifier_keys(RAW_KEY).unwrap();
        assert_eq!(verifier_key, VERIFIER_KEY);
        assert_eq!(prover_key, PROVER_KEY);
    }

    #[test]
    fn wrong_confirmation_is_rejected() {
        let client = fixed_client();
        let server = fixed_server();
        let secret = client.finish(&server.get_message().unwrap()).unwrap();
        assert!(
            secret
                .verify("0000000000000000000000000000000000000000000000000000000000000000")
                .is_err()
        );
    }

    #[test]
    fn known_ciphertext_decrypts() {
        // Build a prover with the confirmed key state taken from the vector.
        let mut prover = TrustedDeviceBridgeProver::new();
        let (verifier_key, prover_key) = derive_prover_and_verifier_keys(RAW_KEY).unwrap();
        prover.raw_key = Some(RAW_KEY.to_owned());
        prover.verifier_key = Some(verifier_key);
        prover.prover_key = Some(prover_key);
        prover.verified = true;

        assert_eq!(prover.decrypt_message(CIPHERTEXT_B64).unwrap(), PLAINTEXT);
    }

    #[test]
    fn full_public_api_roundtrip_and_decrypt() {
        let salt_b64 = b64_encode(b"roundtrip-salt-vector-0001");
        let code = "654321";

        let mut client = TrustedDeviceBridgeProver::new();
        assert!(client.get_message1().is_empty());
        assert!(client.get_message2().is_empty());
        assert!(client.get_key().is_empty());
        assert!(!client.is_verified());

        client.init_with_salt(&salt_b64, code).unwrap();
        let client_m1 = client.get_message1();
        assert!(!client_m1.is_empty());
        // Deterministic for a fixed client: get_message1 does not mutate state.
        assert_eq!(client_m1, client.get_message1());

        let mut server = TestServer::new(code, &salt_b64).unwrap();
        let server_m1 = server.get_message1().unwrap();

        let client_m2 = client.process_message1(&server_m1).unwrap();
        assert_eq!(client_m2, client.get_message2());

        let server_m2 = server.process_message1(&client_m1).unwrap();
        let result = client.process_message2(&server_m2).unwrap();
        assert!(result.verified);
        assert!(result.decrypted_code.is_none());
        assert_eq!(result.key, client.get_key());
        assert!(client.is_verified());

        let server_raw = server.verify_message2(&client_m2).unwrap();
        assert_eq!(server_raw, client.get_key());

        let payload = server.encrypt_message(PLAINTEXT).unwrap();
        assert_eq!(client.decrypt_message(&payload).unwrap(), PLAINTEXT);

        // A tampered payload must fail.
        let mut tampered = b64_decode(&payload).unwrap();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(client.decrypt_message(&b64_encode(&tampered)).is_err());
        assert!(client.decrypt_message("not-base64!!").is_err());
    }

    #[test]
    fn uninitialised_fallible_calls_error() {
        let mut prover = TrustedDeviceBridgeProver::new();
        assert!(prover.process_message1("00").is_err());
        assert!(prover.process_message2("00").is_err());
        assert!(prover.decrypt_message("AA==").is_err());
    }
}
