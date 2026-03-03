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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::PlatformError;
use crate::traits::Storage;

/// Monotonic counter for generating unique temp file names across threads.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
///
/// # Errors
///
/// Returns [`PlatformError::StorageError`] if the key contains path traversal
/// components (`.` or `..`) or resolves outside `base_dir`.
fn key_to_path(base_dir: &Path, key: &str) -> Result<PathBuf, PlatformError> {
    let mut path = base_dir.to_path_buf();
    for component in key.split('/') {
        if component == "." || component == ".." {
            return Err(PlatformError::StorageError(format!(
                "key contains forbidden path component: {component:?}"
            )));
        }
        path.push(component);
    }
    // Belt-and-suspenders: verify the resolved path is still under base_dir.
    if !path.starts_with(base_dir) {
        return Err(PlatformError::StorageError(
            "key resolves outside base directory".to_owned(),
        ));
    }
    Ok(path)
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

/// Converts a [`tokio::task::JoinError`] to a [`PlatformError`].
///
/// Takes ownership because `map_err` passes the error by value.
#[allow(clippy::needless_pass_by_value)]
fn join_err(e: tokio::task::JoinError) -> PlatformError {
    PlatformError::StorageError(format!("blocking task failed: {e}"))
}

impl Storage for FilesystemStorage {
    // All file I/O is wrapped in `tokio::task::spawn_blocking` to avoid
    // blocking the async runtime. Filesystem operations can stall on slow
    // disks, NFS mounts, or under heavy I/O contention, making them unsafe
    // to run directly in an async context.

    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        let data = data.to_vec();
        async move {
            let path = path?;
            tokio::task::spawn_blocking(move || {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        PlatformError::StorageError(format!(
                            "failed to create parent directory: {e}"
                        ))
                    })?;
                }

                // Atomic write: write to temp file, then rename.
                // Temp file name includes PID + atomic counter for uniqueness
                // across concurrent tasks (timestamp alone can collide).
                let parent = path.parent().unwrap_or(&path);
                let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
                let pid = std::process::id();
                let temp_path = parent.join(format!(
                    ".tmp.{}.{pid}.{counter}",
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
            })
            .await
            .map_err(join_err)?
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        async move {
            let path = path?;
            tokio::task::spawn_blocking(move || match std::fs::read(&path) {
                Ok(data) => Ok(Some(data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(PlatformError::StorageError(format!(
                    "failed to read file: {e}"
                ))),
            })
            .await
            .map_err(join_err)?
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        let base_dir = self.base_dir.clone();
        async move {
            let path = path?;
            tokio::task::spawn_blocking(move || match std::fs::remove_file(&path) {
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
            })
            .await
            .map_err(join_err)?
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
                let prefix_path = key_to_path(&base_dir, &prefix)?;
                if prefix_path.is_dir() {
                    prefix_path
                } else {
                    prefix_path
                        .parent()
                        .map_or_else(|| base_dir.clone(), Path::to_path_buf)
                }
            };

            let bd = base_dir.clone();
            let pf = prefix.clone();
            tokio::task::spawn_blocking(move || {
                let mut files = Vec::new();
                walk_dir(&search_dir, &mut files)?;

                let mut keys: Vec<String> = files
                    .iter()
                    .filter_map(|path| {
                        let key = path_to_key(&bd, path)?;
                        if key.starts_with(&pf) {
                            Some(key)
                        } else {
                            None
                        }
                    })
                    .collect();
                keys.sort();
                Ok(keys)
            })
            .await
            .map_err(join_err)?
        }
    }

    /// Deletes all keys matching the given prefix. Returns the count of
    /// successfully deleted files.
    ///
    /// Note: `FilesystemStorage` does not support transactional semantics.
    /// If a deletion fails partway through, the returned count reflects
    /// only the files actually removed (best-effort).
    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let base_dir = self.base_dir.clone();
        let prefix = prefix.to_owned();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut files = Vec::new();
                walk_dir(&base_dir, &mut files)?;

                let matching: Vec<PathBuf> = files
                    .into_iter()
                    .filter(|path| {
                        path_to_key(&base_dir, path).is_some_and(|key| key.starts_with(&prefix))
                    })
                    .collect();

                let mut deleted_count: u64 = 0;

                for path in &matching {
                    match std::fs::remove_file(path) {
                        Ok(()) => deleted_count += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // File was already removed (e.g. concurrent deletion);
                            // not counted.
                        }
                        Err(e) => {
                            return Err(PlatformError::StorageError(format!(
                                "failed to delete file: {e}"
                            )));
                        }
                    }
                }

                for path in &matching {
                    if let Some(parent) = path.parent() {
                        remove_empty_parents(parent, &base_dir);
                    }
                }

                Ok(deleted_count)
            })
            .await
            .map_err(join_err)?
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let path = key_to_path(&self.base_dir, key);
        async move {
            let path = path?;
            tokio::task::spawn_blocking(move || Ok(path.is_file()))
                .await
                .map_err(join_err)?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_to_path_simple() {
        let path = key_to_path(Path::new("/tmp/test-fs"), "context/abc/state").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test-fs/context/abc/state"));
    }

    #[test]
    fn key_to_path_rejects_dot_dot() {
        let result = key_to_path(Path::new("/tmp/test-fs"), "../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn key_to_path_rejects_single_dot() {
        let result = key_to_path(Path::new("/tmp/test-fs"), "foo/./bar");
        assert!(result.is_err());
    }

    #[test]
    fn path_to_key_roundtrip() {
        let base = Path::new("/tmp/test-fs");
        let path = key_to_path(base, "context/abc/state").unwrap();
        let key = path_to_key(base, &path);
        assert_eq!(key, Some("context/abc/state".to_owned()));
    }
}
