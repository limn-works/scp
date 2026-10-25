//! Filesystem-backed [`Storage`] implementation.
//!
//! Maps keys to file paths under a base directory: `{base_dir}/{key}` where
//! `/` in keys maps to directory separators. Values are written atomically
//! and durably (write a temp file in the same directory, fsync it, rename it,
//! then fsync the directory), and on Unix every directory on the key's path
//! is durable before a put returns. A temp file is never a key. Useful for
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

// Every temp file name starts with `TEMP_FILE_PREFIX`. No key component may
// start with it (`sanitize_key_component` refuses it on every backend, and
// `key_to_path` repeats the check), and `list_keys` and `delete_prefix` skip
// every file whose name starts with it, so a temp file left by a crash is
// never a key (spec section 17.6, "FilesystemStorage").
use crate::store_value::TEMP_FILE_PREFIX;

/// True when `path` names a temp file that [`FilesystemStorage`] wrote.
fn is_temp_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(TEMP_FILE_PREFIX))
}

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
    /// The directory is created if it does not exist, and on Unix the parent
    /// of each directory this call created is fsynced, so the first put's
    /// directories are reachable after a power loss (spec section 17.6).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the directory cannot be
    /// created or resolved, or a created directory's parent cannot be
    /// fsynced.
    pub fn new(base_dir: &Path) -> Result<Self, PlatformError> {
        // The deepest ancestor that exists before the create; every directory
        // below it on the way to `base_dir` is new.
        #[cfg(unix)]
        let existing = base_dir
            .ancestors()
            .find(|dir| dir.as_os_str().is_empty() || dir.is_dir())
            .map(Path::to_path_buf);
        std::fs::create_dir_all(base_dir).map_err(|e| {
            PlatformError::StorageError(format!("failed to create base directory: {e}"))
        })?;
        // One spelling of `base_dir`, so the fsync walks below and in a put
        // stop at it.
        #[cfg(unix)]
        let base_dir = std::fs::canonicalize(base_dir).map_err(|e| {
            PlatformError::StorageError(format!("failed to resolve base directory: {e}"))
        })?;
        #[cfg(unix)]
        if let Some(existing) = existing {
            let existing = if existing.as_os_str().is_empty() {
                std::env::current_dir()
            } else {
                std::fs::canonicalize(&existing)
            }
            .map_err(|e| {
                PlatformError::StorageError(format!("failed to resolve base directory: {e}"))
            })?;
            let mut created = base_dir.as_path();
            while created != existing && created.starts_with(&existing) {
                let Some(parent) = created.parent() else {
                    break;
                };
                sync_dir(parent)?;
                created = parent;
            }
        }
        #[cfg(not(unix))]
        let base_dir = base_dir.to_path_buf();
        Ok(Self { base_dir })
    }
}

/// Converts a storage key to a filesystem path under `base_dir`.
///
/// # Errors
///
/// Returns [`PlatformError::StorageError`] if the key contains path traversal
/// components (`.` or `..`), a component that starts with the temp file
/// prefix `.tmp.`, or resolves outside `base_dir`.
fn key_to_path(base_dir: &Path, key: &str) -> Result<PathBuf, PlatformError> {
    let mut path = base_dir.to_path_buf();
    for component in key.split('/') {
        if component == "." || component == ".." {
            return Err(PlatformError::StorageError(format!(
                "key contains forbidden path component: {component:?}"
            )));
        }
        if component.starts_with(TEMP_FILE_PREFIX) {
            return Err(PlatformError::StorageError(format!(
                "key component {component:?} starts with the temp file prefix {TEMP_FILE_PREFIX:?}"
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

/// Recursively walks a directory and collects every file path except temp
/// files, which are never keys.
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
        } else if !is_temp_file(&path) {
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

/// Creates `dir` and its missing ancestors, and on Unix fsyncs the parent of
/// every directory from `dir` up to and including `base_dir`, deepest first.
///
/// No record of durable directories is kept (spec section 17.6): another
/// store or process can remove a directory and recreate it at any time, so
/// every put makes every directory on its path durable again.
///
/// # Errors
///
/// Returns [`PlatformError::StorageError`] if a directory cannot be created
/// or a parent cannot be fsynced.
fn create_durable_dirs(dir: &Path, base_dir: &Path) -> Result<(), PlatformError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        PlatformError::StorageError(format!("failed to create parent directory: {e}"))
    })?;
    #[cfg(unix)]
    {
        let mut current = dir;
        while current.starts_with(base_dir) {
            let Some(parent) = current.parent() else {
                break;
            };
            sync_dir(parent)?;
            current = parent;
        }
    }
    #[cfg(not(unix))]
    let _ = base_dir;
    Ok(())
}

/// Fsyncs a directory, so the entries created or renamed in it survive a
/// power loss.
///
/// # Errors
///
/// Returns [`PlatformError::StorageError`] if the directory cannot be opened
/// or fsynced.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), PlatformError> {
    #[cfg(test)]
    tests::record_sync(dir);
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|e| {
            PlatformError::StorageError(format!("failed to fsync directory {}: {e}", dir.display()))
        })
}

/// Writes `data` to a new file at `path` and fsyncs it.
fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    file.write_all(data)?;
    file.sync_all()
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
        let base_dir = self.base_dir.clone();
        let data = data.to_vec();
        async move {
            let path = path?;
            tokio::task::spawn_blocking(move || {
                // Atomic, durable write: write a temp file and fsync it, rename
                // it over the key's file, then fsync the directory so the
                // rename itself survives a power loss. A put that returned is
                // therefore on disk before the next put starts, so a later put
                // (an event log head) never survives a power loss that an
                // earlier one (its unit) does not.
                // Temp file name includes PID + atomic counter for uniqueness
                // across concurrent tasks (timestamp alone can collide).
                let parent = path.parent().unwrap_or(&path);
                let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
                let pid = std::process::id();
                let temp_path = parent.join(format!(
                    "{TEMP_FILE_PREFIX}{}.{pid}.{counter}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_nanos())
                ));

                // Directory durability runs on Unix only (spec section 17.6):
                // every directory on the key's path gets its entry fsynced
                // into its parent. A concurrent delete can remove the key's
                // empty directory before the temp file lands in it, so a
                // write that finds no directory creates the directories again
                // and retries once.
                let mut written = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
                for _ in 0..2 {
                    create_durable_dirs(parent, &base_dir)?;
                    #[cfg(test)]
                    tests::after_dirs_created(parent);
                    written = write_synced(&temp_path, &data);
                    if !matches!(&written, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
                        break;
                    }
                }
                if let Err(e) = written {
                    if let Err(cleanup) = std::fs::remove_file(&temp_path)
                        && cleanup.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            path = %temp_path.display(),
                            error = %cleanup,
                            "failed to remove a temp file after a failed write; it is never read as a key"
                        );
                    }
                    return Err(PlatformError::StorageError(format!(
                        "failed to write temp file: {e}"
                    )));
                }

                if let Err(e) = std::fs::rename(&temp_path, &path) {
                    if let Err(cleanup) = std::fs::remove_file(&temp_path) {
                        tracing::warn!(
                            path = %temp_path.display(),
                            error = %cleanup,
                            "failed to remove a temp file after a failed rename; it is never read as a key"
                        );
                    }
                    return Err(PlatformError::StorageError(format!(
                        "failed to rename temp file: {e}"
                    )));
                }

                #[cfg(unix)]
                sync_dir(parent)?;

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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn key_to_path_simple() {
        let path = key_to_path(Path::new("/tmp/test-fs"), "context/abc/state").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test-fs/context/abc/state"));
    }

    /// Every directory `sync_dir` fsynced in this test process. Tests use
    /// distinct base directories, so each reads only its own entries.
    #[cfg(unix)]
    static SYNCED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    #[cfg(unix)]
    pub(super) fn record_sync(dir: &Path) {
        SYNCED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(dir.to_path_buf());
    }

    #[cfg(unix)]
    fn sync_count(dir: &Path) -> usize {
        SYNCED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|synced| synced.as_path() == dir)
            .count()
    }

    #[cfg(unix)]
    fn fresh_base(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "scp-durable-dirs-{tag}-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::canonicalize(&base).unwrap()
    }

    /// Directories whose next creation by a put is undone right after it,
    /// as a concurrent delete's empty-directory removal would. Each entry
    /// fires once.
    #[cfg(unix)]
    static REMOVE_AFTER_CREATE: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    /// The put's hook between creating the key's directories and writing
    /// its temp file there.
    pub(super) fn after_dirs_created(dir: &Path) {
        #[cfg(unix)]
        {
            let fires = {
                let mut pending = REMOVE_AFTER_CREATE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending
                    .iter()
                    .position(|p| p == dir)
                    .map(|i| pending.remove(i))
                    .is_some()
            };
            if fires {
                std::fs::remove_dir(dir).unwrap();
            }
        }
        #[cfg(not(unix))]
        let _ = dir;
    }

    /// A put into directories that its own put did not create fsyncs the
    /// parent of each one, `base_dir` included, before it returns.
    #[cfg(unix)]
    #[tokio::test]
    async fn put_makes_a_directory_it_did_not_create_durable() {
        let base = fresh_base("existing");
        let storage = FilesystemStorage::new(&base).unwrap();
        std::fs::create_dir_all(base.join("a").join("b")).unwrap();

        storage.store("a/b/key", b"v").await.unwrap();

        assert!(sync_count(&base) >= 1, "the entry of `a` in base_dir");
        assert!(sync_count(&base.join("a")) >= 1, "the entry of `b` in `a`");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Creating a store over a missing `base_dir` fsyncs the parent of each
    /// directory it created, so the base directory survives a power loss
    /// before any put.
    #[cfg(unix)]
    #[test]
    fn new_over_a_missing_base_dir_syncs_its_parent() {
        let root = fresh_base("new");
        let base = root.join("x").join("y");

        let storage = FilesystemStorage::new(&base).unwrap();

        assert_eq!(storage.base_dir, base);
        assert_eq!(sync_count(&root.join("x")), 1, "the entry of `y` in `x`");
        assert_eq!(
            sync_count(&root),
            1,
            "the entry of `x` in the existing root"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A store over an existing `base_dir` creates nothing and fsyncs
    /// nothing.
    #[cfg(unix)]
    #[test]
    fn new_over_an_existing_base_dir_syncs_nothing() {
        let root = fresh_base("new-existing");
        let base = root.join("x");
        std::fs::create_dir(&base).unwrap();

        FilesystemStorage::new(&base).unwrap();

        assert_eq!(sync_count(&root), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A delete that removed the key's directory between a put's directory
    /// creation and its temp-file write does not fail the put: the put
    /// creates the directory again, fsyncs its entry again, and writes.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_put_racing_a_directory_removal_recreates_it_and_writes() {
        let base = fresh_base("race");
        let storage = FilesystemStorage::new(&base).unwrap();
        REMOVE_AFTER_CREATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(base.join("a"));

        storage.store("a/k", b"v").await.unwrap();

        assert_eq!(storage.retrieve("a/k").await.unwrap(), Some(b"v".to_vec()));
        assert_eq!(
            sync_count(&base),
            2,
            "the entry of `a` is fsynced for the creation and the recreation"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Every put fsyncs every directory entry on its path, so a put after a
    /// delete removed the directory makes the recreated directory durable,
    /// whichever store or process removed it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_put_after_a_delete_removed_the_directory_syncs_again() {
        let base = fresh_base("delete");
        let storage = FilesystemStorage::new(&base).unwrap();
        let other = FilesystemStorage::new(&base.join("alias").join("..")).unwrap();
        assert_eq!(storage.base_dir, other.base_dir);

        storage.store("a/k1", b"v").await.unwrap();
        assert_eq!(sync_count(&base), 1);
        other.delete("a/k1").await.unwrap();
        assert!(!base.join("a").exists());

        storage.store("a/k2", b"v").await.unwrap();
        assert_eq!(sync_count(&base), 2, "the recreated `a` is fsynced again");
        std::fs::remove_dir_all(&base).unwrap();
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
