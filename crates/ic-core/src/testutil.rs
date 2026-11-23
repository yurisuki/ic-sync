//! Test-only helpers. No tempfile dependency is needed: `uuid` is already a
//! workspace dependency and gives us collision-free scratch directories.

use std::path::{Path, PathBuf};

use uuid::Uuid;

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ic-core-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
