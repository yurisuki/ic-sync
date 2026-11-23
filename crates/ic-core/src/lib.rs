//! IC-SYNC headless core: persistence, Apple client, auth and sync engine.
//!
//! This crate intentionally has no GUI dependencies. The `ic-app` crate owns
//! the iced frontend and the system tray; everything below it is reusable from
//! a CLI, a service, or tests.

pub mod api;
pub mod auth;
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
pub use config::{Config, ConflictMode, CredentialMode, ThemePreference, plain_storage_warning};
pub use engine::SyncEngine;
pub use error::{Error, Result};
pub use relocation::RelocationReport;
pub use status::{ServiceStatus, SyncState};
