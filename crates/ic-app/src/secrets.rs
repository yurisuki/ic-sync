//! Secure-storage status for the GUI.
//!
//! All credential I/O lives in `ic-core::config` (the OS keyring is the only
//! backing store; YAML always contains `password: ""`). This module is a thin
//! facade so the UI can present a clear "OS credential store" / unavailable
//! indicator without depending on keyring internals.

/// Human-readable description shown in Settings/About.
pub fn descriptor() -> String {
    if ic_core::config::secure_storage_available() {
        "OS credential store (native keychain / Secret Service)".to_string()
    } else {
        "Credential store unavailable: no OS keyring or Secret Service found".to_string()
    }
}

pub fn available() -> bool {
    ic_core::config::secure_storage_available()
}
