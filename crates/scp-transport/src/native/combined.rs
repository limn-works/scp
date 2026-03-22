//! Combined client + relay storage in a single `SQLite` database.
//!
//! [`CombinedNodeStorage`] implements both [`Storage`] (key-value store for
//! client state via `ProtocolRepository`) and [`BlobStorage`] (blob store for relay
//! state) in one `SQLCipher`-encrypted `SQLite` database. This enables the
//! "personal node" deployment pattern where one directory = complete node state.
//!
//! See SCP-PERSIST-063 and spec section 17.1 (deployment patterns).

use scp_primitives::Clock;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use scp_platform::{PlatformError, Storage};
use zeroize::Zeroize;

use super::storage::{BlobStorage, StorageError, StoredBlob};

// ---------------------------------------------------------------------------
// Clock function for testability
// ---------------------------------------------------------------------------

/// A clock function that returns the current Unix timestamp in seconds.
///
/// The default ([`system_clock`]) delegates to [`scp_primitives::SystemClock`].
/// Tests inject a deterministic clock via [`CombinedNodeStorage::open_with_clock`].
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Returns a [`ClockFn`] backed by the real system clock.
#[must_use]
pub fn system_clock() -> ClockFn {
    Arc::new(|| scp_primitives::SystemClock.now_secs())
}

// ---------------------------------------------------------------------------
// Prefix successor computation (for B-tree range scans)
// ---------------------------------------------------------------------------

/// Converts a `Vec<u8>` to a `[u8; 32]` array, returning a `rusqlite::Error`
/// if the length doesn't match.
fn vec_to_array(v: Vec<u8>, field: &str) -> Result<[u8; 32], rusqlite::Error> {
    v.try_into().map_err(|v: Vec<u8>| {
        rusqlite::Error::InvalidColumnType(
            0,
            format!("{field} has wrong length: expected 32, got {}", v.len()),
            rusqlite::types::Type::Blob,
        )
    })
}

/// Computes the lexicographic successor of `prefix` for B-tree range scans.
///
/// Returns `None` if the prefix is empty or consists entirely of `0xFF` bytes
/// (no finite successor exists). Otherwise, increments the last non-`0xFF`
/// byte and truncates.
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    // Pop trailing 0xFF bytes.
    while bytes.last() == Some(&0xFF) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return None;
    }
    // Increment the last byte.
    if let Some(last) = bytes.last_mut() {
        *last += 1;
    }
    // SAFETY: The input was valid UTF-8 and we only incremented a byte.
    // In practice, SCP keys are ASCII, so this is always valid.
    String::from_utf8(bytes).ok()
}

// ---------------------------------------------------------------------------
// CombinedNodeStorage
// ---------------------------------------------------------------------------

/// Combined client + relay storage backed by a single `SQLCipher`-encrypted
/// `SQLite` database.
///
/// The database contains two tables:
/// - `kv` — key-value store implementing [`Storage`] (client `ProtocolRepository`)
/// - `blobs` — blob store implementing [`BlobStorage`] (relay blob storage)
///
/// Uses `Arc<std::sync::Mutex<Connection>>` (not `tokio::sync::Mutex`) because
/// all `SQLite` operations are sub-millisecond and blocking briefly is cheaper
/// than the overhead of an async mutex. The `Arc` wrapper enables cheap clones
/// for concurrent access patterns. This matches the pattern established by
/// `InMemoryStorage` for the [`Storage`] trait.
///
/// # Construction
///
/// ```ignore
/// let storage = CombinedNodeStorage::open(dir, encryption_key)?;
/// ```
///
/// Creates `node.db` inside `dir` with WAL mode and `SQLCipher` encryption.
///
/// Clone is cheap — the connection and clock are shared via `Arc`.
#[derive(Clone)]
pub struct CombinedNodeStorage {
    conn: Arc<Mutex<Connection>>,
    clock: ClockFn,
}

impl std::fmt::Debug for CombinedNodeStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CombinedNodeStorage")
            .field("conn", &"<Arc<Mutex<Connection>>>")
            .finish()
    }
}

impl CombinedNodeStorage {
    /// Opens (or creates) a combined node database at `dir/node.db`.
    ///
    /// The database is encrypted with `SQLCipher` using the provided `key`.
    /// WAL mode is enabled for concurrent read performance.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened or
    /// the schema cannot be initialized.
    pub fn open(dir: &Path, key: &[u8]) -> Result<Self, StorageError> {
        Self::open_impl(dir, key, system_clock())
    }

    /// Opens (or creates) a combined node database with an injectable clock.
    ///
    /// Useful for tests that need deterministic timestamps for TTL expiry.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened or
    /// the schema cannot be initialized.
    pub fn open_with_clock(dir: &Path, key: &[u8], clock: ClockFn) -> Result<Self, StorageError> {
        Self::open_impl(dir, key, clock)
    }

    fn open_impl(dir: &Path, key: &[u8], clock: ClockFn) -> Result<Self, StorageError> {
        // Ensure the target directory exists.
        std::fs::create_dir_all(dir)
            .map_err(|e| StorageError::Internal(format!("failed to create directory: {e}")))?;

        let db_path = dir.join("node.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| StorageError::Internal(format!("failed to open database: {e}")))?;

        // Apply SQLCipher encryption key and hardening PRAGMAs.
        // Matches SqliteStorage settings for consistent security posture.
        let mut hex_key = hex::encode(key);
        let mut pragma_sql = format!(
            "PRAGMA key = \"x'{hex_key}'\";\n\
             PRAGMA cipher_page_size = 4096;\n\
             PRAGMA kdf_iter = 256000;\n\
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\n\
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"
        );
        hex_key.zeroize();
        let result = conn.execute_batch(&pragma_sql);
        pragma_sql.zeroize();
        result.map_err(|e| StorageError::Internal(format!("failed to set encryption key: {e}")))?;

        // Enable WAL mode for concurrent reads.
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|e| StorageError::Internal(format!("failed to enable WAL: {e}")))?;

        // Create the kv table (Storage trait).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            ) WITHOUT ROWID;",
        )
        .map_err(|e| StorageError::Internal(format!("failed to create kv table: {e}")))?;

        // Create the blobs table (BlobStorage trait) per spec section 17.7.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blobs (
                blob_id BLOB PRIMARY KEY,
                routing_id BLOB NOT NULL,
                recipient_hint BLOB,
                blob_ttl INTEGER NOT NULL,
                stored_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                blob BLOB NOT NULL
            ) WITHOUT ROWID;

            CREATE INDEX IF NOT EXISTS idx_routing ON blobs (routing_id, stored_at);
            CREATE INDEX IF NOT EXISTS idx_expiry ON blobs (expires_at);",
        )
        .map_err(|e| StorageError::Internal(format!("failed to create blobs table: {e}")))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }

    /// Acquires the database connection lock.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the mutex is poisoned.
    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StorageError> {
        self.conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("mutex poisoned: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Storage trait implementation (kv table)
// ---------------------------------------------------------------------------

#[allow(clippy::manual_async_fn, clippy::significant_drop_tightening)]
impl Storage for CombinedNodeStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, data],
            )
            .map_err(|e| PlatformError::StorageError(format!("insert failed: {e}")))?;
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;
            let mut stmt = conn
                .prepare_cached("SELECT value FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let result = stmt
                .query_row(rusqlite::params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?;
            Ok(result)
        }
    }

    fn delete(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;
            conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;

            let keys = if prefix.is_empty() {
                // Empty prefix: return all keys sorted.
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                stmt.query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| PlatformError::StorageError(format!("collect failed: {e}")))?
            } else if let Some(successor) = prefix_successor(&prefix) {
                // B-tree range scan: key >= prefix AND key < successor.
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv WHERE key >= ?1 AND key < ?2 ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                stmt.query_map(rusqlite::params![prefix, successor], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PlatformError::StorageError(format!("collect failed: {e}")))?
            } else {
                // Prefix is all 0xFF — fall back to LIKE (very rare edge case).
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv WHERE key >= ?1 ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                stmt.query_map(rusqlite::params![prefix], |row| row.get::<_, String>(0))
                    .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?
                    .filter_map(|r| {
                        r.ok().and_then(|k| {
                            if k.starts_with(&prefix) {
                                Some(Ok(k))
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, rusqlite::Error>>()
                    .map_err(|e| PlatformError::StorageError(format!("collect failed: {e}")))?
            };

            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl std::future::Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;

            let deleted = if prefix.is_empty() {
                conn.execute("DELETE FROM kv", [])
                    .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?
            } else if let Some(successor) = prefix_successor(&prefix) {
                conn.execute(
                    "DELETE FROM kv WHERE key >= ?1 AND key < ?2",
                    rusqlite::params![prefix, successor],
                )
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?
            } else {
                // Prefix is all 0xFF — fall back to scanning keys then deleting.
                // Collect keys under the same lock to avoid a second lock acquisition.
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv WHERE key >= ?1 ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                let keys: Vec<String> = stmt
                    .query_map(rusqlite::params![prefix], |row| row.get::<_, String>(0))
                    .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?
                    .filter_map(|r| r.ok().filter(|k| k.starts_with(&prefix)))
                    .collect();
                let count = keys.len();
                for key in &keys {
                    conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                        .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
                }
                count
            };

            Ok(deleted as u64)
        }
    }

    fn exists(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = self
                .lock_conn()
                .map_err(|e| PlatformError::StorageError(e.to_string()))?;
            let mut stmt = conn
                .prepare_cached("SELECT 1 FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let exists = stmt
                .query_row(rusqlite::params![key], |_| Ok(()))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("query failed: {e}")))?
                .is_some();
            Ok(exists)
        }
    }
}

// ---------------------------------------------------------------------------
// BlobStorage trait implementation (blobs table)
// ---------------------------------------------------------------------------

#[allow(clippy::significant_drop_tightening)]
#[async_trait::async_trait]
impl BlobStorage for CombinedNodeStorage {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        blob_ttl: u32,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = (self.clock)();
        let expires_at = stored_at.saturating_add(u64::from(blob_ttl));

        let hint_bytes: Option<Vec<u8>> = recipient_hint.map(|h| h.to_vec());

        let conn = self.lock_conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO blobs
                (blob_id, routing_id, recipient_hint, blob_ttl, stored_at, expires_at, blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                blob_id.as_slice(),
                routing_id.as_slice(),
                hint_bytes,
                blob_ttl,
                stored_at,
                expires_at,
                blob,
            ],
        )
        .map_err(|e| StorageError::Internal(format!("insert blob failed: {e}")))?;

        Ok(StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            blob,
        })
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let now = (self.clock)();
        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT routing_id, recipient_hint, blob_ttl, stored_at, blob
                 FROM blobs WHERE blob_id = ?1 AND expires_at > ?2",
            )
            .map_err(|e| StorageError::Internal(format!("prepare failed: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![blob_id.as_slice(), now], |row| {
                let routing_id_vec: Vec<u8> = row.get(0)?;
                let hint_vec: Option<Vec<u8>> = row.get(1)?;
                let blob_ttl: u32 = row.get(2)?;
                let stored_at: u64 = row.get(3)?;
                let blob: Vec<u8> = row.get(4)?;

                let routing_id: [u8; 32] = vec_to_array(routing_id_vec, "routing_id")?;
                let recipient_hint = hint_vec
                    .map(|h| vec_to_array(h, "recipient_hint"))
                    .transpose()?;

                Ok(StoredBlob {
                    routing_id,
                    blob_id: *blob_id,
                    recipient_hint,
                    blob_ttl,
                    stored_at,
                    blob,
                })
            })
            .optional()
            .map_err(|e| StorageError::Internal(format!("query failed: {e}")))?;

        Ok(result)
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = (self.clock)();
        let conn = self.lock_conn()?;

        let since_ts = since.unwrap_or(0);

        let mut stmt = conn
            .prepare_cached(
                "SELECT blob_id, recipient_hint, blob_ttl, stored_at, blob
                 FROM blobs
                 WHERE routing_id = ?1 AND expires_at > ?2 AND stored_at > ?3
                 ORDER BY stored_at ASC
                 LIMIT ?4",
            )
            .map_err(|e| StorageError::Internal(format!("prepare failed: {e}")))?;

        let rows = stmt
            .query_map(
                rusqlite::params![routing_id.as_slice(), now, since_ts, limit],
                |row| {
                    let blob_id_vec: Vec<u8> = row.get(0)?;
                    let hint_vec: Option<Vec<u8>> = row.get(1)?;
                    let blob_ttl: u32 = row.get(2)?;
                    let stored_at: u64 = row.get(3)?;
                    let blob: Vec<u8> = row.get(4)?;

                    let blob_id: [u8; 32] = vec_to_array(blob_id_vec, "blob_id")?;
                    let recipient_hint = hint_vec
                        .map(|h| vec_to_array(h, "recipient_hint"))
                        .transpose()?;

                    Ok(StoredBlob {
                        routing_id: *routing_id,
                        blob_id,
                        recipient_hint,
                        blob_ttl,
                        stored_at,
                        blob,
                    })
                },
            )
            .map_err(|e| StorageError::Internal(format!("query failed: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| StorageError::Internal(format!("row error: {e}")))?);
        }

        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let conn = self.lock_conn()?;
        let deleted = conn
            .execute(
                "DELETE FROM blobs WHERE blob_id = ?1",
                rusqlite::params![blob_id.as_slice()],
            )
            .map_err(|e| StorageError::Internal(format!("delete blob failed: {e}")))?;
        Ok(deleted > 0)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        let conn = self.lock_conn()?;
        let purged = conn
            .execute(
                "DELETE FROM blobs WHERE expires_at <= ?1",
                rusqlite::params![now],
            )
            .map_err(|e| StorageError::Internal(format!("purge failed: {e}")))?;
        Ok(purged)
    }

    async fn count(&self) -> Result<usize, StorageError> {
        let conn = self.lock_conn()?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
            .map_err(|e| StorageError::Internal(format!("count failed: {e}")))?;
        #[allow(clippy::cast_sign_loss)]
        Ok(count as usize)
    }
}

// We need the optional() extension.
use rusqlite::OptionalExtension;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Creates a deterministic test clock starting at the given timestamp.
    fn test_clock(start: u64) -> (ClockFn, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(start));
        let time_clone = Arc::clone(&time);
        let clock: ClockFn = Arc::new(move || Ok(time_clone.load(Ordering::Relaxed)));
        (clock, time)
    }

    /// Creates a `CombinedNodeStorage` in a temporary directory with a test clock.
    fn make_test_storage(dir: &Path, start_time: u64) -> (CombinedNodeStorage, Arc<AtomicU64>) {
        let key = [0u8; 32]; // Test encryption key.
        let (clock, time) = test_clock(start_time);
        let storage = CombinedNodeStorage::open_with_clock(dir, &key, clock)
            .expect("failed to create test storage");
        (storage, time)
    }

    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    // -----------------------------------------------------------------------
    // Storage trait tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn kv_store_and_retrieve_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "key1", b"value1").await.unwrap();
        let result = Storage::retrieve(&storage, "key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn kv_retrieve_nonexistent_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let result = Storage::retrieve(&storage, "missing").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn kv_store_overwrites_existing_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "key", b"first").await.unwrap();
        Storage::store(&storage, "key", b"second").await.unwrap();
        let result = Storage::retrieve(&storage, "key").await.unwrap();
        assert_eq!(result, Some(b"second".to_vec()));
    }

    #[tokio::test]
    async fn kv_delete_removes_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "key", b"value").await.unwrap();
        Storage::delete(&storage, "key").await.unwrap();
        let result = Storage::retrieve(&storage, "key").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn kv_delete_nonexistent_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::delete(&storage, "nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn kv_list_keys_prefix_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "prefix/c", b"").await.unwrap();
        Storage::store(&storage, "prefix/a", b"").await.unwrap();
        Storage::store(&storage, "prefix/b", b"").await.unwrap();
        Storage::store(&storage, "other/x", b"").await.unwrap();

        let keys = Storage::list_keys(&storage, "prefix/").await.unwrap();
        assert_eq!(keys, vec!["prefix/a", "prefix/b", "prefix/c"]);
    }

    #[tokio::test]
    async fn kv_list_keys_empty_prefix_returns_all_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "b", b"").await.unwrap();
        Storage::store(&storage, "a", b"").await.unwrap();

        let keys = Storage::list_keys(&storage, "").await.unwrap();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn kv_list_keys_no_matches_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "foo", b"").await.unwrap();
        let keys = Storage::list_keys(&storage, "bar").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn kv_delete_prefix_removes_matching() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "ctx/a", b"1").await.unwrap();
        Storage::store(&storage, "ctx/b", b"2").await.unwrap();
        Storage::store(&storage, "ctx/c", b"3").await.unwrap();
        Storage::store(&storage, "other/d", b"4").await.unwrap();

        let deleted = Storage::delete_prefix(&storage, "ctx/").await.unwrap();
        assert_eq!(deleted, 3);

        assert_eq!(Storage::retrieve(&storage, "ctx/a").await.unwrap(), None);
        assert_eq!(Storage::retrieve(&storage, "ctx/b").await.unwrap(), None);
        assert_eq!(Storage::retrieve(&storage, "ctx/c").await.unwrap(), None);
        assert_eq!(
            Storage::retrieve(&storage, "other/d").await.unwrap(),
            Some(b"4".to_vec())
        );
    }

    #[tokio::test]
    async fn kv_delete_prefix_no_matches_returns_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "foo", b"bar").await.unwrap();
        let deleted = Storage::delete_prefix(&storage, "zzz").await.unwrap();
        assert_eq!(deleted, 0);
    }

    #[tokio::test]
    async fn kv_exists_returns_true_for_stored_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "key", b"value").await.unwrap();
        assert!(Storage::exists(&storage, "key").await.unwrap());
    }

    #[tokio::test]
    async fn kv_exists_returns_false_for_missing_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        assert!(!Storage::exists(&storage, "missing").await.unwrap());
    }

    #[tokio::test]
    async fn kv_exists_returns_false_after_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "key", b"value").await.unwrap();
        Storage::delete(&storage, "key").await.unwrap();
        assert!(!Storage::exists(&storage, "key").await.unwrap());
    }

    #[tokio::test]
    async fn kv_store_empty_value_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        Storage::store(&storage, "empty", b"").await.unwrap();
        let result = Storage::retrieve(&storage, "empty").await.unwrap();
        assert_eq!(result, Some(vec![]));
    }

    // -----------------------------------------------------------------------
    // BlobStorage trait tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn blob_store_and_get_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored =
            BlobStorage::store(&storage, routing_id, blob_id, None, 3600, blob_data.clone())
                .await
                .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.blob_ttl, 3600);
        assert_eq!(stored.stored_at, 1_000_000);

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    async fn blob_get_nonexistent_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn blob_delete_removes_blob() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        BlobStorage::store(&storage, routing_id, blob_id, None, 3600, blob_data)
            .await
            .unwrap();

        let deleted = BlobStorage::delete(&storage, &blob_id).await.unwrap();
        assert!(deleted);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn blob_delete_nonexistent_returns_false() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let blob_id = [0xFF; 32];
        let deleted = BlobStorage::delete(&storage, &blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn blob_query_returns_blobs_for_routing_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            // Advance clock by 1 second between stores so each gets a distinct stored_at.
            time.store(1_000_000 + u64::from(i), Ordering::Relaxed);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            BlobStorage::store(&storage, routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn blob_query_respects_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            time.store(1_000_000 + u64::from(i), Ordering::Relaxed);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            BlobStorage::store(&storage, routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 3).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn blob_query_returns_oldest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            time.store(1_000_000 + u64::from(i), Ordering::Relaxed);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            BlobStorage::store(&storage, routing_id, blob_id, None, 3600, data)
                .await
                .unwrap();
        }

        let results = storage.query(&routing_id, None, 100).await.unwrap();
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn blob_query_different_routing_id_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        BlobStorage::store(&storage, routing_id_a, blob_id, None, 3600, data)
            .await
            .unwrap();

        let results = storage.query(&routing_id_b, None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn blob_store_with_recipient_hint_preserves_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = BlobStorage::store(&storage, routing_id, blob_id, Some(hint), 3600, data)
            .await
            .unwrap();
        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    #[tokio::test]
    async fn blob_purge_expired_removes_old_blobs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 100 seconds.
        BlobStorage::store(&storage, routing_id, blob_id, None, 100, data)
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_101, Ordering::Relaxed);

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn blob_purge_expired_does_not_remove_active_blobs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        BlobStorage::store(&storage, routing_id, blob_id, None, 3600, data)
            .await
            .unwrap();

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn blob_get_expired_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, time) = make_test_storage(dir.path(), 1_000_000);

        let routing_id = [0xAA; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        BlobStorage::store(&storage, routing_id, blob_id, None, 100, data)
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_101, Ordering::Relaxed);

        // get should filter out expired blobs.
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Combined: both tables coexist in one database
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn combined_kv_and_blobs_coexist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _time) = make_test_storage(dir.path(), 1_000_000);

        // Store KV data.
        Storage::store(&storage, "client/state", b"hello")
            .await
            .unwrap();

        // Store blob data.
        let routing_id = [0xDD; 32];
        let blob_data = vec![42; 100];
        let blob_id = make_blob_id(&blob_data);
        BlobStorage::store(&storage, routing_id, blob_id, None, 3600, blob_data.clone())
            .await
            .unwrap();

        // Both should be retrievable independently.
        assert_eq!(
            Storage::retrieve(&storage, "client/state").await.unwrap(),
            Some(b"hello".to_vec())
        );
        let blob = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(blob.blob, blob_data);
    }

    #[tokio::test]
    async fn one_directory_complete_node_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = [0u8; 32];

        // Create storage, write data, drop it.
        {
            let (clock, _time) = test_clock(1_000_000);
            let storage = CombinedNodeStorage::open_with_clock(dir.path(), &key, clock)
                .expect("create storage");
            Storage::store(&storage, "identity/did", b"did:dht:test")
                .await
                .unwrap();
            let routing_id = [0xEE; 32];
            let blob_data = vec![99; 50];
            let blob_id = make_blob_id(&blob_data);
            BlobStorage::store(&storage, routing_id, blob_id, None, 86400, blob_data)
                .await
                .unwrap();
        }

        // Re-open from same directory — data should survive.
        {
            let (clock, _time) = test_clock(1_000_000);
            let storage = CombinedNodeStorage::open_with_clock(dir.path(), &key, clock)
                .expect("reopen storage");
            let did = Storage::retrieve(&storage, "identity/did").await.unwrap();
            assert_eq!(did, Some(b"did:dht:test".to_vec()));

            let blob_data = vec![99; 50];
            let blob_id = make_blob_id(&blob_data);
            let blob = storage.get(&blob_id).await.unwrap();
            assert!(blob.is_some());
            assert_eq!(blob.unwrap().blob, blob_data);
        }
    }

    // -----------------------------------------------------------------------
    // Prefix successor helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn prefix_successor_normal_ascii() {
        assert_eq!(prefix_successor("abc"), Some("abd".to_string()));
        assert_eq!(prefix_successor("prefix/"), Some("prefix0".to_string()));
    }

    #[test]
    fn prefix_successor_empty_returns_none() {
        assert_eq!(prefix_successor(""), None);
    }
}
