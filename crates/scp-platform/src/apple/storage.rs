//! ``SQLCipher`` [`Storage`] adapter for Apple platforms (iOS, macOS).
//!
//! [`AppleStorage`] wraps `rusqlite` with `bundled-sqlcipher` to provide an
//! encrypted key-value store. The encryption key is supplied by the caller --
//! on Apple platforms the 32-byte AES-256 key is generated and managed by the
//! Keychain in the Swift `AppleStorage` actor.
//!
//! # Schema
//!
//! ```sql
//! CREATE TABLE kv (
//!     key TEXT PRIMARY KEY,
//!     value BLOB NOT NULL
//! ) WITHOUT ROWID;
//! ```
//!
//! `WITHOUT ROWID` uses a clustered B-tree index on `key`, which is optimal
//! for KV workloads. WAL mode enables concurrent readers with one writer.
//!
//! # Prefix Queries
//!
//! `list_keys` and `delete_prefix` use B-tree range scans (`key >= ? AND key < ?`)
//! rather than `LIKE`. The upper bound is computed by [`prefix_successor`], which
//! increments the last byte of the prefix. This leverages the clustered index
//! directly and avoids full-table scans.
//!
//! # References
//!
//! - Spec section 17.5 (``SQLCipher`` configuration)
//! - Spec section 17.6 (``SQLite`` schema)
//! - ADR-025 (Apple Platform Adapter)

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use tokio::sync::Mutex;

use crate::error::PlatformError;
use crate::traits::Storage;

/// ``SQLCipher``-encrypted [`Storage`] adapter for Apple platforms.
///
/// Opened via [`AppleStorage::open`] with a directory path and an externally-
/// managed encryption key (from Apple Keychain). Implements the 6-method
/// [`Storage`] trait using a `WITHOUT ROWID` KV table.
///
/// # Thread Safety
///
/// The inner `rusqlite::Connection` is protected by a `tokio::sync::Mutex`.
/// All database operations acquire the lock, execute synchronous ``SQLite`` calls,
/// and release it. This is safe because `SQLite` operations are fast (< 1ms for
/// typical KV operations) and the mutex prevents concurrent writes.
pub struct AppleStorage {
    conn: Mutex<Connection>,
}

impl AppleStorage {
    /// Open (or create) an encrypted `SQLite` database in `dir`.
    ///
    /// The database file is named `scp.db` inside `dir`. The encryption key
    /// must be exactly 32 bytes (AES-256); it is hex-encoded and passed to
    /// `SQLCipher` via `PRAGMA key`.
    ///
    /// # `SQLCipher` Configuration (spec section 17.5)
    ///
    /// After setting the key, the following pragmas are applied:
    /// - `cipher_page_size = 4096`
    /// - `kdf_iter = 256000`
    /// - `cipher_hmac_algorithm = HMAC_SHA512`
    /// - `cipher_kdf_algorithm = PBKDF2_HMAC_SHA512`
    /// - `journal_mode = WAL`
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if:
    /// - The encryption key is not exactly 32 bytes.
    /// - The database file cannot be opened or created.
    /// - Any `SQLCipher` pragma fails to apply.
    pub fn open(dir: &Path, encryption_key: &[u8]) -> Result<Self, PlatformError> {
        if encryption_key.len() != 32 {
            return Err(PlatformError::StorageError(format!(
                "encryption key must be exactly 32 bytes, got {}",
                encryption_key.len()
            )));
        }

        let db_path = dir.join("scp.db");
        let conn = Connection::open(&db_path).map_err(|e| {
            PlatformError::StorageError(format!(
                "failed to open database at {}: {e}",
                db_path.display()
            ))
        })?;

        // Apply `SQLCipher` encryption key as hex-encoded PRAGMA.
        let hex_key = hex::encode(encryption_key);
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{hex_key}'\";\
             PRAGMA cipher_page_size = 4096;\
             PRAGMA kdf_iter = 256000;\
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"
        ))
        .map_err(|e| {
            PlatformError::StorageError(format!("failed to apply `SQLCipher` pragmas: {e}"))
        })?;

        // Enable WAL mode for concurrent read access.
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|e| PlatformError::StorageError(format!("failed to set WAL mode: {e}")))?;

        // Create the KV table if it does not exist.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (\
                 key TEXT PRIMARY KEY,\
                 value BLOB NOT NULL\
             ) WITHOUT ROWID;",
        )
        .map_err(|e| PlatformError::StorageError(format!("failed to create kv table: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Compute the exclusive upper bound for a B-tree range scan on `prefix`.
///
/// Given a prefix string, returns a string that is lexicographically just past
/// all strings that start with `prefix`. This is done by incrementing the last
/// byte. If the last byte is `0xFF`, it is removed and the preceding byte is
/// incremented (recursively). If the entire prefix is `0xFF` bytes (or empty),
/// returns `None` -- meaning there is no upper bound and the query should use
/// `key >= prefix` without an upper constraint.
///
/// # Examples
///
/// - `"abc"` -> `Some("abd")`
/// - `"abc\xff"` -> `Some("abd")`
/// - `"\xff\xff"` -> `None`
/// - `""` -> `None`
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();

    // Pop trailing 0xFF bytes -- they cannot be incremented.
    while bytes.last() == Some(&0xFF) {
        bytes.pop();
    }

    if bytes.is_empty() {
        // The prefix is empty or was all 0xFF bytes; no finite upper bound.
        return None;
    }

    // Increment the last non-0xFF byte.
    if let Some(last) = bytes.last_mut() {
        *last += 1;
    }

    // The result may not be valid UTF-8 in edge cases, but `SQLite` TEXT
    // comparison is byte-based so this is correct for range queries.
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

// The trait uses RPITIT (`-> impl Future<...> + Send`), so each impl method
// must return a future rather than use `async fn` directly.
#[allow(
    clippy::manual_async_fn,
    clippy::significant_drop_tightening,
    clippy::single_match_else
)]
impl Storage for AppleStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, data],
            )
            .map_err(|e| PlatformError::StorageError(format!("store failed: {e}")))?;
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self.conn.lock().await;
            let mut stmt = conn
                .prepare_cached("SELECT value FROM kv WHERE key = ?1")
                .map_err(|e| {
                    PlatformError::StorageError(format!("retrieve prepare failed: {e}"))
                })?;
            let result = stmt
                .query_row(rusqlite::params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("retrieve failed: {e}")))?;
            Ok(result)
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self.conn.lock().await;
            conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = self.conn.lock().await;

            let keys = match prefix_successor(&prefix) {
                Some(upper) => {
                    let mut stmt = conn
                        .prepare_cached(
                            "SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key",
                        )
                        .map_err(|e| {
                            PlatformError::StorageError(format!("list_keys prepare failed: {e}"))
                        })?;
                    let rows = stmt
                        .query_map(rusqlite::params![prefix, upper], |row| {
                            row.get::<_, String>(0)
                        })
                        .map_err(|e| {
                            PlatformError::StorageError(format!("list_keys query failed: {e}"))
                        })?;
                    rows.collect::<Result<Vec<_>, _>>().map_err(|e| {
                        PlatformError::StorageError(format!("list_keys row read failed: {e}"))
                    })?
                }
                None => {
                    // No upper bound: either empty prefix (return all) or all-0xFF prefix.
                    let mut stmt = conn
                        .prepare_cached("SELECT key FROM kv WHERE key >= ?1 ORDER BY key")
                        .map_err(|e| {
                            PlatformError::StorageError(format!("list_keys prepare failed: {e}"))
                        })?;
                    let rows = stmt
                        .query_map(rusqlite::params![prefix], |row| row.get::<_, String>(0))
                        .map_err(|e| {
                            PlatformError::StorageError(format!("list_keys query failed: {e}"))
                        })?;
                    rows.collect::<Result<Vec<_>, _>>().map_err(|e| {
                        PlatformError::StorageError(format!("list_keys row read failed: {e}"))
                    })?
                }
            };

            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = self.conn.lock().await;

            let deleted = match prefix_successor(&prefix) {
                Some(upper) => conn
                    .execute(
                        "DELETE FROM kv WHERE key >= ?1 AND key < ?2",
                        rusqlite::params![prefix, upper],
                    )
                    .map_err(|e| {
                        PlatformError::StorageError(format!("delete_prefix failed: {e}"))
                    })?,
                None => conn
                    .execute("DELETE FROM kv WHERE key >= ?1", rusqlite::params![prefix])
                    .map_err(|e| {
                        PlatformError::StorageError(format!("delete_prefix failed: {e}"))
                    })?,
            };

            Ok(deleted as u64)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self.conn.lock().await;
            let mut stmt = conn
                .prepare_cached("SELECT 1 FROM kv WHERE key = ?1 LIMIT 1")
                .map_err(|e| PlatformError::StorageError(format!("exists prepare failed: {e}")))?;
            let found = stmt
                .query_row(rusqlite::params![key], |_row| Ok(true))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("exists failed: {e}")))?;
            Ok(found.unwrap_or(false))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Create a temporary directory and a deterministic 32-byte key for testing.
    fn test_storage() -> (AppleStorage, PathBuf) {
        let dir = tempfile::tempdir().unwrap().keep();
        let key = [0x42u8; 32];
        let storage = AppleStorage::open(&dir, &key).unwrap();
        (storage, dir)
    }

    #[tokio::test]
    async fn store_and_retrieve_roundtrip() {
        let (storage, _dir) = test_storage();
        storage.store("key1", b"value1").await.unwrap();
        let result = storage.retrieve("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn retrieve_nonexistent_returns_none() {
        let (storage, _dir) = test_storage();
        let result = storage.retrieve("missing").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn store_overwrites_existing_value() {
        let (storage, _dir) = test_storage();
        storage.store("key", b"first").await.unwrap();
        storage.store("key", b"second").await.unwrap();
        let result = storage.retrieve("key").await.unwrap();
        assert_eq!(result, Some(b"second".to_vec()));
    }

    #[tokio::test]
    async fn delete_removes_value() {
        let (storage, _dir) = test_storage();
        storage.store("key", b"value").await.unwrap();
        storage.delete("key").await.unwrap();
        let result = storage.retrieve("key").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let (storage, _dir) = test_storage();
        storage.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn list_keys_returns_matching_prefix_in_sorted_order() {
        let (storage, _dir) = test_storage();
        storage.store("prefix/c", b"").await.unwrap();
        storage.store("prefix/a", b"").await.unwrap();
        storage.store("prefix/b", b"").await.unwrap();
        storage.store("other/x", b"").await.unwrap();

        let keys = storage.list_keys("prefix/").await.unwrap();
        assert_eq!(keys, vec!["prefix/a", "prefix/b", "prefix/c"]);
    }

    #[tokio::test]
    async fn list_keys_empty_prefix_returns_all_sorted() {
        let (storage, _dir) = test_storage();
        storage.store("b", b"").await.unwrap();
        storage.store("a", b"").await.unwrap();

        let keys = storage.list_keys("").await.unwrap();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn list_keys_no_matches_returns_empty() {
        let (storage, _dir) = test_storage();
        storage.store("foo", b"").await.unwrap();

        let keys = storage.list_keys("bar").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn delete_prefix_removes_matching_keys_and_returns_count() {
        let (storage, _dir) = test_storage();
        storage.store("ctx/a", b"1").await.unwrap();
        storage.store("ctx/b", b"2").await.unwrap();
        storage.store("ctx/c", b"3").await.unwrap();
        storage.store("other/d", b"4").await.unwrap();

        let deleted = storage.delete_prefix("ctx/").await.unwrap();
        assert_eq!(deleted, 3);

        assert_eq!(storage.retrieve("ctx/a").await.unwrap(), None);
        assert_eq!(storage.retrieve("ctx/b").await.unwrap(), None);
        assert_eq!(storage.retrieve("ctx/c").await.unwrap(), None);
        assert_eq!(
            storage.retrieve("other/d").await.unwrap(),
            Some(b"4".to_vec())
        );
    }

    #[tokio::test]
    async fn delete_prefix_no_matches_returns_zero() {
        let (storage, _dir) = test_storage();
        storage.store("foo", b"bar").await.unwrap();
        let deleted = storage.delete_prefix("zzz").await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn exists_returns_true_for_stored_key() {
        let (storage, _dir) = test_storage();
        storage.store("key", b"value").await.unwrap();
        assert!(storage.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn exists_returns_false_for_missing_key() {
        let (storage, _dir) = test_storage();
        assert!(!storage.exists("missing").await.unwrap());
    }

    #[tokio::test]
    async fn exists_returns_false_after_delete() {
        let (storage, _dir) = test_storage();
        storage.store("key", b"value").await.unwrap();
        storage.delete("key").await.unwrap();
        assert!(!storage.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn store_empty_value_succeeds() {
        let (storage, _dir) = test_storage();
        storage.store("empty", b"").await.unwrap();
        let result = storage.retrieve("empty").await.unwrap();
        assert_eq!(result, Some(vec![]));
    }

    #[tokio::test]
    async fn rejects_wrong_key_length() {
        let dir = tempfile::tempdir().unwrap();
        let short_key = [0u8; 16];
        let result = AppleStorage::open(dir.path(), &short_key);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reopen_persists_data() {
        let dir = tempfile::tempdir().unwrap().keep();
        let key = [0xABu8; 32];

        // Write with one instance.
        {
            let storage = AppleStorage::open(&dir, &key).unwrap();
            storage.store("persist", b"across restarts").await.unwrap();
        }

        // Read with a new instance.
        {
            let storage = AppleStorage::open(&dir, &key).unwrap();
            let result = storage.retrieve("persist").await.unwrap();
            assert_eq!(result, Some(b"across restarts".to_vec()));
        }
    }

    // -- prefix_successor unit tests -----------------------------------------

    #[test]
    fn prefix_successor_normal() {
        assert_eq!(prefix_successor("abc"), Some("abd".to_owned()));
    }

    #[test]
    fn prefix_successor_trailing_high_byte() {
        // UTF-8 strings cannot contain raw 0xFF bytes. Test with the highest
        // valid single-byte ASCII character (0x7E = '~') to exercise the
        // increment logic. '~' (0x7E) + 1 = 0x7F (DEL control char).
        assert_eq!(prefix_successor("ab~"), Some("ab\x7f".to_owned()));
    }

    #[test]
    fn prefix_successor_empty() {
        assert_eq!(prefix_successor(""), None);
    }

    #[test]
    fn prefix_successor_single_char() {
        assert_eq!(prefix_successor("a"), Some("b".to_owned()));
    }
}
