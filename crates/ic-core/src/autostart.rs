//! Launch-at-login registration.
//!
//! Linux uses an XDG autostart `.desktop` file; Windows uses the per-user
//! `Run` registry key. The executable path is re-resolved on every call so a
//! moved binary updates the launch command on the next `set_enabled()`.

use std::path::Path;

#[cfg(not(target_os = "linux"))]
use crate::error::Error;
use crate::error::Result;

#[cfg(target_os = "linux")]
const DESKTOP_FILE_NAME: &str = "ic-sync.desktop";

#[cfg(target_os = "linux")]
fn config_home() -> Result<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME")
        && !value.is_empty()
    {
        return Ok(std::path::PathBuf::from(value));
    }
    crate::paths::home().map(|home| home.join(".config"))
}

#[cfg(target_os = "linux")]
fn desktop_path(base: &Path) -> std::path::PathBuf {
    base.join("autostart").join(DESKTOP_FILE_NAME)
}

#[cfg(target_os = "linux")]
fn quoted_exe() -> Result<String> {
    let exe = std::env::current_exe()?;
    let text = exe.to_string_lossy();
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(target_os = "linux")]
fn desktop_entry(start_minimized: bool) -> Result<String> {
    let exec = quoted_exe()?;
    let exec = if start_minimized {
        format!("{exec} --minimized")
    } else {
        exec
    };
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=IC-SYNC\n\
         Comment=iCloud Drive sync\n\
         Exec={exec}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n\
         NoDisplay=false\n"
    ))
}

#[cfg(target_os = "linux")]
fn is_enabled_in(base: &Path) -> Result<bool> {
    Ok(desktop_path(base).exists())
}

#[cfg(target_os = "linux")]
fn set_enabled_in(base: &Path, enabled: bool, start_minimized: bool) -> Result<()> {
    let path = desktop_path(base);
    if !enabled {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    }
    crate::config::atomic_write(&path, desktop_entry(start_minimized)?.as_bytes())
}

/// True when IC-SYNC is registered to launch at login.
#[cfg(target_os = "linux")]
pub fn is_enabled() -> Result<bool> {
    is_enabled_in(&config_home()?)
}

/// Add or remove the launch-at-login entry. `start_minimized` controls the
/// `--minimized` argument passed to the current executable.
#[cfg(target_os = "linux")]
pub fn set_enabled(enabled: bool, start_minimized: bool) -> Result<()> {
    set_enabled_in(&config_home()?, enabled, start_minimized)
}

#[cfg(target_os = "windows")]
const RUN_VALUE: &str = "IC-SYNC";

#[cfg(target_os = "windows")]
fn run_key() -> Result<winreg::RegKey> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_READ | KEY_SET_VALUE,
        )
        .map_err(|error| Error::other(format!("cannot open autostart registry key: {error}")))
}

#[cfg(target_os = "windows")]
fn command_line(start_minimized: bool) -> Result<String> {
    let exe = std::env::current_exe()?;
    let text = exe.to_string_lossy();
    let mut command = format!("\"{}\"", text.replace('"', "\\\""));
    if start_minimized {
        command.push_str(" --minimized");
    }
    Ok(command)
}

/// True when IC-SYNC is registered to launch at login.
#[cfg(target_os = "windows")]
pub fn is_enabled() -> Result<bool> {
    let key = run_key()?;
    match key.get_value::<String, _>(RUN_VALUE) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::other(format!(
            "cannot read autostart registry value: {error}"
        ))),
    }
}

/// Add or remove the per-user `Run` registry value.
#[cfg(target_os = "windows")]
pub fn set_enabled(enabled: bool, start_minimized: bool) -> Result<()> {
    let key = run_key()?;
    if !enabled {
        match key.delete_value(RUN_VALUE) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::other(format!(
                "cannot remove autostart registry value: {error}"
            ))),
        }
    } else {
        key.set_value(RUN_VALUE, &command_line(start_minimized)?)
            .map_err(|error| Error::other(format!("cannot set autostart registry value: {error}")))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn is_enabled() -> Result<bool> {
    Err(Error::other(
        "launch-at-login is only supported on Linux and Windows",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn set_enabled(_enabled: bool, _start_minimized: bool) -> Result<()> {
    Err(Error::other(
        "launch-at-login is only supported on Linux and Windows",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn desktop_entry_toggles_and_uses_current_executable() {
        let dir = TempDir::new();
        assert!(!is_enabled_in(&dir.path).unwrap());

        set_enabled_in(&dir.path, true, true).unwrap();
        assert!(is_enabled_in(&dir.path).unwrap());
        let content = std::fs::read_to_string(desktop_path(&dir.path)).unwrap();
        for expected in [
            "[Desktop Entry]",
            "Type=Application",
            "Name=IC-SYNC",
            "Comment=iCloud Drive sync",
            "Terminal=false",
            "X-GNOME-Autostart-enabled=true",
            "NoDisplay=false",
        ] {
            assert!(
                content.contains(expected),
                "missing {expected} in:\n{content}"
            );
        }
        let exe = std::env::current_exe().unwrap();
        let quoted = format!(
            "\"{}\"",
            exe.to_string_lossy()
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        );
        assert!(content.contains(&format!("Exec={quoted} --minimized")));

        set_enabled_in(&dir.path, true, false).unwrap();
        let content = std::fs::read_to_string(desktop_path(&dir.path)).unwrap();
        assert!(content.contains(&format!("Exec={quoted}\n")));
        assert!(!content.contains("--minimized"));

        set_enabled_in(&dir.path, false, false).unwrap();
        assert!(!is_enabled_in(&dir.path).unwrap());
    }
}
