//! IC-SYNC headless core: persistence, Apple client, auth and sync engine.
//!
//! This crate intentionally has no GUI dependencies. The `ic-app` crate owns
//! the iced frontend and the system tray; everything below it is reusable from
//! a CLI, a service, or tests.

pub mod api;
pub mod auth;
pub mod autostart;
pub mod bridge;
// The prover is a byte-for-byte port of Apple's/Python's transcript handling;
// the low-level hex and bit-length idioms are intentional.
#[allow(
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of
)]
pub mod bridge_prover;
pub mod config;
pub mod engine;
pub mod error;
pub mod mirror;
pub mod paths;
pub mod relocation;
pub mod state;
pub mod status;

#[cfg(test)]
mod testutil;

pub use api::ICloudApi;
pub use auth::{TwoFactorRoute, request_verification_route};
pub use autostart::{is_enabled as autostart_is_enabled, set_enabled as autostart_set_enabled};
pub use config::{Config, ConflictMode, CredentialMode, ThemePreference, plain_storage_warning};
pub use engine::SyncEngine;
pub use error::{Error, Result};
pub use relocation::RelocationReport;
pub use status::{ServiceStatus, SyncState};
