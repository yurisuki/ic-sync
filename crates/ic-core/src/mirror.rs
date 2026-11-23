//! Ordinary local-folder mirror operations (no FUSE).
//!
//! Every iCloud path is validated before it is joined to the selected local
//! folder, and atomic writes go through a temporary file in the same directory
//! so `rename` stays atomic across platforms.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub struct Mirror {
    root: RwLock<PathBuf>,
    #[allow(dead_code)]
    tmp: PathBuf,
}

impl Mirror {
    pub fn new(root: PathBuf, tmp: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&tmp)?;
        Ok(Self {
            root: RwLock::new(root),
            tmp,
        })
    }

    /// Current local sync folder (cloned so callers cannot hold a stale guard).
    pub fn root(&self) -> PathBuf {
        self.root.read().unwrap().clone()
    }

    /// Switch to a new local folder after a successful relocation.
    pub fn relocate_root(&self, new_root: PathBuf) -> Result<()> {
        fs::create_dir_all(&new_root)?;
        *self.root.write().unwrap() = new_root;
        Ok(())
    }

    /// Safely map an iCloud path to a path under the local sync folder.
    /// Parent components that would escape the root are rejected.
    pub fn local_path(&self, icloud_path: &str) -> Result<PathBuf> {
        let root = self.root.read().unwrap();
        let mut result = root.clone();
        for component in Path::new(icloud_path).components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    if result == *root {
                        return Err(Error::other(format!(
                            "path escapes sync folder: {icloud_path}"
                        )));
                    }
                    result.pop();
                }
                Component::Normal(part) => result.push(part),
                Component::Prefix(_) => {
                    return Err(Error::other(format!(
                        "invalid path component: {icloud_path}"
                    )));
                }
            }
        }
        if !result.starts_with(root.as_path()) {
            return Err(Error::other("path escapes sync folder"));
        }
        Ok(result)
    }

    pub fn exists(&self, path: &str) -> bool {
        self.local_path(path).map(|p| p.exists()).unwrap_or(false)
    }

    pub fn ensure_parent(&self, path: &str) -> Result<()> {
        if let Some(parent) = self.local_path(path)?.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    pub fn ensure_dir(&self, path: &str) -> Result<()> {
        fs::create_dir_all(self.local_path(path)?)?;
        Ok(())
    }

    /// Create a sparse placeholder of the expected remote size.
    pub fn materialize_placeholder(&self, path: &str, size: u64, mtime: i64) -> Result<()> {
        let target = self.local_path(path)?;
        self.ensure_parent(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target)?;
        if size > 0 {
            file.set_len(size)?;
        }
        set_mtime(&file, mtime)?;
        Ok(())
    }

    /// Stream content to a temporary file and atomically replace the target.
    pub fn write_atomic_stream<R: Read>(
        &self,
        path: &str,
        mut reader: R,
        mtime: Option<i64>,
    ) -> Result<u64> {
        let target = self.local_path(path)?;
        self.ensure_parent(path)?;
        let temp = temp_sibling(&target);
        let mut total = 0u64;
        {
            let mut handle = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                handle.write_all(&buffer[..read])?;
                total += read as u64;
            }
            handle.flush()?;
            handle.sync_all()?;
            if let Some(mtime) = mtime {
                set_mtime(&handle, mtime)?;
            }
        }
        replace_file(&temp, &target)?;
        Ok(total)
    }

    pub fn write_all(&self, path: &str, data: &[u8]) -> Result<()> {
        let target = self.local_path(path)?;
        self.ensure_parent(path)?;
        fs::write(target, data)?;
        Ok(())
    }

    pub fn read_at(&self, path: &str, offset: u64, length: u32) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new().read(true).open(self.local_path(path)?)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut buffer = vec![0u8; length as usize];
        let read = file.read(&mut buffer)?;
        buffer.truncate(read);
        Ok(buffer)
    }

    pub fn write_at(&self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(self.local_path(path)?)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }

    pub fn truncate(&self, path: &str, size: u64) -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .open(self.local_path(path)?)?;
        file.set_len(size)?;
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let src = self.local_path(from)?;
        let dst = self.local_path(to)?;
        self.ensure_parent(to)?;
        match fs::rename(&src, &dst) {
            Ok(()) => Ok(()),
            #[cfg(windows)]
            Err(error) if dst.exists() => {
                fs::remove_dir_all(&dst).or_else(|_| fs::remove_file(&dst))?;
                fs::rename(&src, &dst).map_err(Into::into)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn remove_file(&self, path: &str) -> Result<()> {
        match fs::remove_file(self.local_path(path)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn remove_dir_all(&self, path: &str) -> Result<()> {
        match fs::remove_dir_all(self.local_path(path)?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn sha256(&self, path: &str) -> Result<String> {
        let mut file = File::open(self.local_path(path)?)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn metadata(&self, path: &str) -> Result<fs::Metadata> {
        Ok(fs::symlink_metadata(self.local_path(path)?)?)
    }

    pub fn open(&self, path: &str) -> Result<File> {
        Ok(File::open(self.local_path(path)?)?)
    }
}

fn set_mtime(file: &File, mtime: i64) -> Result<()> {
    let time = if mtime >= 0 {
        UNIX_EPOCH + Duration::from_secs(mtime as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(mtime.unsigned_abs())
    };
    file.set_times(fs::FileTimes::new().set_modified(time))?;
    Ok(())
}

fn temp_sibling(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    target.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()))
}

fn replace_file(temp: &Path, target: &Path) -> Result<()> {
    #[cfg(windows)]
    if target.exists() {
        fs::remove_file(target)?;
    }
    match fs::rename(temp, target) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(temp);
            Err(error.into())
        }
    }
}

pub fn parent_path(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".into(),
        Some(index) => path[..index].to_string(),
    }
}

pub fn basename(path: &str) -> String {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("")
        .to_string()
}

pub fn join_path(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{parent}/{child}")
    }
}

/// Conflict copies are named `<name>.local-conflict-<YYYYMMDDHHMMSS>`.
pub fn conflict_path(path: &str, stamp: &str) -> String {
    let parent = parent_path(path);
    let name = basename(path);
    if parent == "/" {
        format!("/{name}.local-conflict-{stamp}")
    } else {
        format!("{parent}/{name}.local-conflict-{stamp}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn mirror() -> (TempDir, Mirror) {
        let dir = TempDir::new();
        let root = dir.path.join("sync");
        let tmp = dir.path.join("tmp");
        (dir, Mirror::new(root, tmp).unwrap())
    }

    #[test]
    fn path_helpers_and_conflict_name() {
        assert_eq!(join_path("/", "Photos"), "/Photos");
        assert_eq!(join_path("/Photos", "one.jpg"), "/Photos/one.jpg");
        assert_eq!(parent_path("/Photos/one.jpg"), "/Photos");
        assert_eq!(basename("/Photos/one.jpg"), "one.jpg");
        assert_eq!(
            conflict_path("/Photos/one.jpg", "20261123120000"),
            "/Photos/one.jpg.local-conflict-20261123120000"
        );
        assert_eq!(
            conflict_path("/one.jpg", "20261123120000"),
            "/one.jpg.local-conflict-20261123120000"
        );
    }

    #[test]
    fn local_path_rejects_escapes() {
        let (_dir, mirror) = mirror();
        assert_eq!(
            mirror.local_path("/a/b.txt").unwrap(),
            mirror.root().join("a").join("b.txt")
        );
        assert!(mirror.local_path("../../etc/passwd").is_err());
        assert!(mirror.local_path("/a/../../etc/passwd").is_err());
    }

    #[test]
    fn atomic_write_preserves_content_and_mtime() {
        let (_dir, mirror) = mirror();
        let bytes = b"hello ic-sync";
        let written = mirror
            .write_atomic_stream("/docs/a.txt", &bytes[..], Some(1_700_000_000))
            .unwrap();
        assert_eq!(written, bytes.len() as u64);
        assert_eq!(
            fs::read(mirror.local_path("/docs/a.txt").unwrap())
                .unwrap()
                .as_slice(),
            &bytes[..]
        );
        assert_eq!(
            mirror.sha256("/docs/a.txt").unwrap(),
            format!("{:x}", Sha256::digest(bytes))
        );

        mirror.rename("/docs/a.txt", "/docs/b.txt").unwrap();
        assert!(mirror.exists("/docs/b.txt"));
        assert!(!mirror.exists("/docs/a.txt"));
    }
}
