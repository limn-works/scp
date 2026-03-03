//! Filesystem-backed [`Storage`] implementation.
//!
//! Maps keys to file paths under a base directory: `{base_dir}/{key}` where
//! `/` in keys maps to directory separators. Values are written atomically
//! (write to temp file in the same directory, then rename). Useful for
//! server-side deployments where inspectability matters (debugging, backup,
//! migration). Not recommended for mobile or performance-sensitive use.
//!
//! See spec section 17.6.

use std::path::{Path, PathBuf};

use crate::error::PlatformError;
use crate::traits::Storage;

/// Filesystem-backed storage adapter.
///
/// Keys are mapped to file paths under a base directory. The `/` character
/// in keys maps to OS directory separators. Values are stored as raw bytes
/// in files, written atomically via a temp-file-then-rename pattern.
///
/// See spec section 17.6.
pub struct FilesystemStorage {
    base_dir: PathBuf,
}

impl FilesystemStorage {
    /// Creates a new filesystem storage rooted at `base_dir`.
    ///
    /// The directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the directory cannot be
    /// created.
    pub fn new(base_dir: &Path) -> Result<Self, PlatformError> {
        std::fs::create_dir_all(base_dir).map_err(|e| {
            PlatformError::StorageError(format!("failed to create base directory: {e}"))
        })?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }
}

/// Converts a storage key to a filesystem path under `base_dir`.
fn key_to_path(base_dir: &Path, key: &str) -> PathBuf {
    let mut path = base_dir.to_path_buf();
    for component in key.split('/') {
        path.push(component);
    }
    path
}

/// Converts a filesystem path back to a storage key relative to `base_dir`.
///
/// Returns `None` if the path is not under `base_dir`.
fn path_to_key(base_dir: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(base_dir).ok().map(|rel| {
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    })
}

/// Recursively walks a directory and collects all file paths.
fn walk_dir(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PlatformError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(PlatformError::StorageError(format!(
                "failed to read directory: {e}"
            )));
        }
    };

    for entry in entries {
        let entry = entry.map_err(|e| {
            PlatformError::StorageError(format!("failed to read directory entry: {e}"))
        })?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}

/// Removes empty parent directories up to (but not including) `base_dir`.
fn remove_empty_parents(path: &Path, base_dir: &Path) {
    let mut current = path.to_path_buf();
    while current != base_dir {
        if std::fs::remove_dir(&current).is_err() {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl Storage for FilesystemStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        let data = data.to_vec();
        async move {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    PlatformError::StorageError(format!("failed to create parent directory: {e}"))
                })?;
            }

            // Atomic write: write to temp file, then rename.
            let parent = path.parent().unwrap_or(&path);
            let temp_path = parent.join(format!(
                ".tmp.{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));

            std::fs::write(&temp_path, &data).map_err(|e| {
                PlatformError::StorageError(format!("failed to write temp file: {e}"))
            })?;

            std::fs::rename(&temp_path, &path).map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                PlatformError::StorageError(format!("failed to rename temp file: {e}"))
            })?;

            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        async move {
            match std::fs::read(&path) {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(PlatformError::StorageError(format!(
                    "failed to read file: {e}"
                ))),
            }
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        let base_dir = self.base_dir.clone();
        async move {
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    if let Some(parent) = path.parent() {
                        remove_empty_parents(parent, &base_dir);
                    }
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(PlatformError::StorageError(format!(
                    "failed to delete file: {e}"
                ))),
            }
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let base_dir = self.base_dir.clone();
        let prefix = prefix.to_owned();
        async move {
            let search_dir = if prefix.is_empty() {
                base_dir.clone()
            } else {
                let prefix_path = key_to_path(&base_dir, &prefix);
                if prefix_path.is_dir() {
                    prefix_path
                } else {
                    prefix_path
                        .parent()
                        .map_or_else(|| base_dir.clone(), Path::to_path_buf)
                }
            };

            let mut files = Vec::new();
            walk_dir(&search_dir, &mut files)?;

            let mut keys: Vec<String> = files
                .iter()
                .filter_map(|path| {
                    let key = path_to_key(&base_dir, path)?;
                    if key.starts_with(&prefix) {
                        Some(key)
                    } else {
                        None
                    }
                })
                .collect();
            keys.sort();
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let base_dir = self.base_dir.clone();
        let prefix = prefix.to_owned();
        async move {
            let mut files = Vec::new();
            walk_dir(&base_dir, &mut files)?;

            let matching: Vec<PathBuf> = files
                .into_iter()
                .filter(|path| {
                    path_to_key(&base_dir, path).is_some_and(|key| key.starts_with(&prefix))
                })
                .collect();

            let count = matching.len() as u64;

            for path in &matching {
                if let Err(e) = std::fs::remove_file(path)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(PlatformError::StorageError(format!(
                        "failed to delete file: {e}"
                    )));
                }
            }

            for path in &matching {
                if let Some(parent) = path.parent() {
                    remove_empty_parents(parent, &base_dir);
                }
            }

            Ok(count)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        async move { Ok(path.is_file()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_to_path_simple() {
        let path = key_to_path(Path::new("/tmp/test-fs"), "context/abc/state");
        assert_eq!(path, PathBuf::from("/tmp/test-fs/context/abc/state"));
    }

    #[test]
    fn path_to_key_roundtrip() {
        let base = Path::new("/tmp/test-fs");
        let path = key_to_path(base, "context/abc/state");
        let key = path_to_key(base, &path);
        assert_eq!(key, Some("context/abc/state".to_owned()));
    }
}
