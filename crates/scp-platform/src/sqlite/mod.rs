//! `SQLite`-backed [`Storage`] implementation with `SQLCipher` encryption.
//!
//! The production default storage adapter per spec section 17.6. Uses
//! `rusqlite` with `bundled-sqlcipher` for at-rest encryption. WAL mode
//! enables concurrent readers with one writer. Schema is intentionally
//! minimal — all structure lives in the key convention, not the table
//! schema.
//!
//! Prefix queries use B-tree range scans (`key >= prefix AND key <
//! prefix_successor`), not `LIKE`, for O(log n) performance via the
//! clustered index.
//!
//! See spec section 17.6 and ADR-006.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use zeroize::Zeroize;

use crate::error::PlatformError;
use crate::traits::Storage;

/// `SQLite`-backed storage adapter with `SQLCipher` encryption.
///
/// Uses a single `WITHOUT ROWID` table with a clustered index on the
/// primary key for optimal KV workloads. Encryption is provided by
/// `SQLCipher` with the following configuration:
///
/// - `cipher_page_size = 4096`
/// - `kdf_iter = 256000`
/// - `cipher_hmac_algorithm = HMAC_SHA512`
/// - `cipher_kdf_algorithm = PBKDF2_HMAC_SHA512`
///
/// See spec section 17.6.
pub struct SqliteStorage {
    // Uses `std::sync::Mutex` deliberately rather than `tokio::sync::Mutex`.
    // All rusqlite operations are sub-millisecond (single-row KV on WAL-mode
    // SQLite with no network I/O), so blocking the async runtime for that
    // duration is preferable to the overhead and complexity of
    // `spawn_blocking` per call. The mutex hold time is bounded by SQLite's
    // single-writer guarantee — only one thread can hold the lock at a time,
    // and each operation completes quickly.
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    /// Opens or creates an encrypted `SQLite` database at `{dir}/scp.db`.
    ///
    /// The `key` parameter is the raw encryption key material. It is
    /// hex-encoded and passed to `SQLCipher` via `PRAGMA key`. The
    /// hex-encoded key string is zeroized after the PRAGMA is executed,
    /// but `SQLCipher` retains the derived key internally for the lifetime
    /// of the connection — this is inherent to how `SQLCipher` works and
    /// cannot be avoided without closing the connection.
    ///
    /// Callers that hold the raw key in a `Vec<u8>` or similar should
    /// zeroize it after passing it to this constructor.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the database cannot be
    /// opened, the encryption key is rejected, or the schema cannot be
    /// created.
    pub fn new(dir: &Path, key: &[u8]) -> Result<Self, PlatformError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| PlatformError::StorageError(format!("failed to create directory: {e}")))?;

        let db_path = dir.join("scp.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| PlatformError::StorageError(format!("failed to open database: {e}")))?;

        // Apply SQLCipher pragmas (spec section 17.6).
        // The hex key format is `PRAGMA key = "x'<hex>'"` — a double-quoted
        // string containing `x'...'`. This tells SQLCipher to interpret the
        // value as raw hex key bytes rather than a passphrase.
        let mut hex_key = hex::encode(key);
        let mut pragma_sql = format!(
            "PRAGMA key = \"x'{hex_key}'\";\n\
             PRAGMA cipher_page_size = 4096;\n\
             PRAGMA kdf_iter = 256000;\n\
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;\n\
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;"
        );
        // Zeroize the hex key immediately — it's now embedded in pragma_sql.
        hex_key.zeroize();
        let result = conn.execute_batch(&pragma_sql);
        // Zeroize the SQL string containing the key material.
        pragma_sql.zeroize();
        result.map_err(|e| {
            PlatformError::StorageError(format!("failed to set SQLCipher pragmas: {e}"))
        })?;

        // Enable WAL mode for concurrent readers.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| PlatformError::StorageError(format!("failed to enable WAL mode: {e}")))?;

        // Create the KV table (spec section 17.6).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (\
                key TEXT PRIMARY KEY, \
                value BLOB NOT NULL\
            ) WITHOUT ROWID;",
        )
        .map_err(|e| PlatformError::StorageError(format!("failed to create schema: {e}")))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Computes the exclusive upper bound for a prefix range scan.
///
/// Given a prefix string, returns a string that is the lexicographic
/// successor — the smallest string that is greater than all strings
/// starting with the prefix. This enables efficient B-tree range scans
/// (`key >= prefix AND key < successor`) instead of `LIKE` queries.
///
/// Returns `None` if no successor exists (prefix is all `\xff` bytes or
/// empty), in which case only a `key >= prefix` bound should be used.
fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    // Walk backwards, incrementing the last byte that isn't 0xFF.
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return String::from_utf8(bytes).ok();
        }
        bytes.pop();
    }
    None
}

/// Acquires the connection lock, mapping poison errors to
/// [`PlatformError::StorageError`].
fn lock_conn(
    conn: &Mutex<Connection>,
) -> Result<std::sync::MutexGuard<'_, Connection>, PlatformError> {
    conn.lock()
        .map_err(|e| PlatformError::StorageError(format!("mutex poisoned: {e}")))
}

/// Collects rows from a statement into a `Vec<String>`.
fn collect_keys(
    stmt: &mut rusqlite::CachedStatement<'_>,
    params: &[&dyn rusqlite::types::ToSql],
) -> Result<Vec<String>, PlatformError> {
    stmt.query_map(params, |row| row.get::<_, String>(0))
        .map_err(|e| PlatformError::StorageError(format!("list_keys failed: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PlatformError::StorageError(format!("list_keys row failed: {e}")))
}

#[allow(clippy::manual_async_fn)]
impl Storage for SqliteStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            let conn = lock_conn(&self.conn)?;
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)",
                rusqlite::params![key, data],
            )
            .map_err(|e| PlatformError::StorageError(format!("store failed: {e}")))?;
            drop(conn);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            let mut stmt = conn
                .prepare_cached("SELECT value FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let result = stmt
                .query_row(rusqlite::params![key], |row| row.get::<_, Vec<u8>>(0))
                .optional()
                .map_err(|e| PlatformError::StorageError(format!("retrieve failed: {e}")))?;
            drop(stmt);
            drop(conn);
            Ok(result)
        }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            conn.execute("DELETE FROM kv WHERE key = ?1", rusqlite::params![key])
                .map_err(|e| PlatformError::StorageError(format!("delete failed: {e}")))?;
            drop(conn);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;

            let keys = if prefix.is_empty() {
                let mut stmt = conn
                    .prepare_cached("SELECT key FROM kv ORDER BY key")
                    .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
                collect_keys(&mut stmt, &[])
            } else {
                prefix_successor(&prefix).map_or_else(
                    || {
                        let mut stmt = conn
                            .prepare_cached("SELECT key FROM kv WHERE key >= ?1 ORDER BY key")
                            .map_err(|e| {
                                PlatformError::StorageError(format!("prepare failed: {e}"))
                            })?;
                        collect_keys(&mut stmt, &[&prefix as &dyn rusqlite::types::ToSql])
                    },
                    |successor| {
                        let mut stmt = conn
                            .prepare_cached(
                                "SELECT key FROM kv \
                                 WHERE key >= ?1 AND key < ?2 ORDER BY key",
                            )
                            .map_err(|e| {
                                PlatformError::StorageError(format!("prepare failed: {e}"))
                            })?;
                        collect_keys(
                            &mut stmt,
                            &[
                                &prefix as &dyn rusqlite::types::ToSql,
                                &successor as &dyn rusqlite::types::ToSql,
                            ],
                        )
                    },
                )
            }?;

            drop(conn);
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;

            let deleted = prefix_successor(&prefix)
                .map_or_else(
                    || conn.execute("DELETE FROM kv WHERE key >= ?1", rusqlite::params![prefix]),
                    |successor| {
                        conn.execute(
                            "DELETE FROM kv WHERE key >= ?1 AND key < ?2",
                            rusqlite::params![prefix, successor],
                        )
                    },
                )
                .map_err(|e| PlatformError::StorageError(format!("delete_prefix failed: {e}")))?;

            drop(conn);
            Ok(deleted as u64)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            let conn = lock_conn(&self.conn)?;
            let mut stmt = conn
                .prepare_cached("SELECT COUNT(*) FROM kv WHERE key = ?1")
                .map_err(|e| PlatformError::StorageError(format!("prepare failed: {e}")))?;
            let count: i64 = stmt
                .query_row(rusqlite::params![key], |row| row.get(0))
                .map_err(|e| PlatformError::StorageError(format!("exists failed: {e}")))?;
            drop(stmt);
            drop(conn);
            Ok(count > 0)
        }
    }
}

/// Extension trait for optional query results.
///
/// Mirrors `rusqlite::OptionalExtension` but works with the method
/// resolution rules needed for `prepare_cached` statements.
trait OptionalResult<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalResult<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_successor_normal() {
        assert_eq!(prefix_successor("ctx/"), Some("ctx0".to_owned()));
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
