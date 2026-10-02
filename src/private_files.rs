// PortRedirect - Handling of files with secrets (private keys, PSKs)
//
// License: GPL-3.0-only

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tracing::warn;

/// Creates a directory and its missing parents, accessible only by the owner (on Unix).
///
/// Existing directories are left unchanged.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Writes `contents` to `path`, readable and writable only by the owner (on Unix).
///
/// An existing file is truncated and its permissions are restricted before anything is written.
pub fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;

    // The mode above only applies to newly created files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(contents)?;
    file.sync_all()
}

/// Logs a warning if the file at `path` can be accessed by users other than its owner (on Unix).
pub fn warn_if_accessible_by_others(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "{} contains a secret but is accessible by other users (mode {:o}), restrict it with: chmod 600 {}",
                    path.display(),
                    mode,
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn test_create_private_dir_all() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("a").join("b");

        create_private_dir_all(&dir).unwrap();

        assert!(dir.is_dir());
        assert_eq!(mode(&dir), 0o700);
        // Creating an existing directory is not an error.
        create_private_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_write_private_file_creates_owner_only_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("secret");

        write_private_file(&path, b"secret").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"secret");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn test_write_private_file_restricts_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("secret");
        fs::write(&path, b"old and longer content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(mode(&path), 0o600);
    }
}
