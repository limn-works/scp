//! `SQLite`-backed blob storage for the SCP native relay.
//!
//! Implements [`BlobStorage`] using `rusqlite` with `bundled-sqlcipher`. Schema
//! matches spec section 17.7 (`SqliteBlobStore` Schema): blobs table `WITHOUT
//! ROWID`, routing index, and expiry index. WAL mode is enabled for concurrent
//! reader/writer access.
//!
//! Gated behind the `sqlite-blob` feature flag.
//!
//! See spec section 17.7 in `.docs/specs/17-persistence-and-storage.md`.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::Mutex;

use super::storage::{BlobStorage, ClockFn, StorageError, StoredBlob, system_clock};

/// `SQLite`-backed blob storage for relay-side encrypted message blobs.
///
/// No at-rest encryption is applied because relay blob stores contain
/// already-encrypted data (MLS ciphertexts or broadcast AES-256-GCM
/// payloads). Operators who want at-rest encryption can use
/// filesystem-level encryption (e.g., LUKS, `FileVault`).
///
/// Schema per spec section 17.7:
///
/// ```sql
/// CREATE TABLE blobs (
///     blob_id BLOB PRIMARY KEY,
///     routing_id BLOB NOT NULL,
///     recipient_hint BLOB,
///     blob_ttl INTEGER NOT NULL,
///     stored_at INTEGER NOT NULL,
///     expires_at INTEGER NOT NULL,
///     blob BLOB NOT NULL
/// ) WITHOUT ROWID;
///
/// CREATE INDEX idx_routing ON blobs (routing_id, stored_at);
/// CREATE INDEX idx_expiry ON blobs (expires_at);
/// ```
///
/// WAL mode is enabled for concurrent reader/writer access.
#[derive(Clone)]
pub struct SqliteBlobStore {
    conn: Arc<Mutex<Connection>>,
    clock: ClockFn,
}

impl std::fmt::Debug for SqliteBlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBlobStore")
            .field("clock", &"<fn>")
            .finish()
    }
}

impl SqliteBlobStore {
    /// Opens (or creates) an `SQLite` blob store at the given file path.
    ///
    /// The database is created with WAL mode and the required schema if it
    /// does not already exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened or
    /// the schema cannot be applied.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_clock(path, system_clock())
    }

    /// Opens an `SQLite` blob store with a controllable clock.
    ///
    /// Used by conformance tests for deterministic TTL testing.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened.
    pub fn open_with_clock(path: &Path, clock: ClockFn) -> Result<Self, StorageError> {
        let conn = Connection::open(path)
            .map_err(|e| StorageError::Internal(format!("sqlite open: {e}")))?;
        Self::init_connection(conn, clock)
    }

    /// Creates an in-memory `SQLite` blob store (useful for testing without
    /// filesystem state).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened.
    pub fn in_memory() -> Result<Self, StorageError> {
        Self::in_memory_with_clock(system_clock())
    }

    /// Creates an in-memory `SQLite` blob store with a controllable clock.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened.
    pub fn in_memory_with_clock(clock: ClockFn) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StorageError::Internal(format!("sqlite open: {e}")))?;
        Self::init_connection(conn, clock)
    }

    /// Initializes the connection with WAL mode and schema.
    fn init_connection(conn: Connection, clock: ClockFn) -> Result<Self, StorageError> {
        // PRAGMA synchronous = NORMAL with WAL mode: the last transaction
        // before a power failure may be lost, but the database will not be
        // corrupted. This is acceptable for relay blob storage because
        // messages can always be retransmitted by senders. The performance
        // benefit (fewer fsyncs) outweighs the minor durability trade-off.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|e| StorageError::Internal(format!("sqlite pragma: {e}")))?;

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
        .map_err(|e| StorageError::Internal(format!("sqlite schema: {e}")))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }
}

#[allow(clippy::significant_drop_tightening)]
impl BlobStorage for SqliteBlobStore {
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

        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO blobs
                (blob_id, routing_id, recipient_hint, blob_ttl, stored_at, expires_at, blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                blob_id.as_slice(),
                routing_id.as_slice(),
                recipient_hint.map(|h| h.to_vec()),
                blob_ttl,
                stored_at,
                expires_at,
                blob,
            ],
        )
        .map_err(|e| StorageError::Internal(format!("sqlite insert: {e}")))?;

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
        let conn = self.conn.lock().await;

        let mut stmt = conn
            .prepare_cached(
                "SELECT routing_id, recipient_hint, blob_ttl, stored_at, blob
                 FROM blobs WHERE blob_id = ?1 AND expires_at > ?2",
            )
            .map_err(|e| StorageError::Internal(format!("sqlite prepare: {e}")))?;

        let result = stmt.query_row(rusqlite::params![blob_id.as_slice(), now], |row| {
            let routing_id_vec: Vec<u8> = row.get(0)?;
            let hint_opt: Option<Vec<u8>> = row.get(1)?;
            let blob_ttl: u32 = row.get(2)?;
            let stored_at: u64 = row.get(3)?;
            let blob: Vec<u8> = row.get(4)?;

            let routing_id: [u8; 32] = routing_id_vec.as_slice().try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    "routing_id".to_owned(),
                    rusqlite::types::Type::Blob,
                )
            })?;

            let recipient_hint = hint_opt
                .map(|h| -> Result<[u8; 32], rusqlite::Error> {
                    h.as_slice().try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            1,
                            "recipient_hint".to_owned(),
                            rusqlite::types::Type::Blob,
                        )
                    })
                })
                .transpose()?;

            Ok(StoredBlob {
                routing_id,
                blob_id: *blob_id,
                recipient_hint,
                blob_ttl,
                stored_at,
                blob,
            })
        });

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Internal(format!("sqlite get: {e}"))),
        }
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = (self.clock)();
        let conn = self.conn.lock().await;

        let since_ts = since.unwrap_or(0);

        let mut stmt = conn
            .prepare_cached(
                "SELECT blob_id, recipient_hint, blob_ttl, stored_at, blob
                 FROM blobs
                 WHERE routing_id = ?1 AND expires_at > ?2 AND stored_at > ?3
                 ORDER BY stored_at ASC
                 LIMIT ?4",
            )
            .map_err(|e| StorageError::Internal(format!("sqlite prepare: {e}")))?;

        let rows = stmt
            .query_map(
                rusqlite::params![routing_id.as_slice(), now, since_ts, limit],
                |row| {
                    let blob_id_vec: Vec<u8> = row.get(0)?;
                    let hint_opt: Option<Vec<u8>> = row.get(1)?;
                    let blob_ttl: u32 = row.get(2)?;
                    let stored_at: u64 = row.get(3)?;
                    let blob: Vec<u8> = row.get(4)?;

                    let blob_id: [u8; 32] = blob_id_vec.as_slice().try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "blob_id".to_owned(),
                            rusqlite::types::Type::Blob,
                        )
                    })?;

                    let recipient_hint = hint_opt
                        .map(|h| -> Result<[u8; 32], rusqlite::Error> {
                            h.as_slice().try_into().map_err(|_| {
                                rusqlite::Error::InvalidColumnType(
                                    1,
                                    "recipient_hint".to_owned(),
                                    rusqlite::types::Type::Blob,
                                )
                            })
                        })
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
            .map_err(|e| StorageError::Internal(format!("sqlite query: {e}")))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| StorageError::Internal(format!("sqlite row: {e}")))?);
        }
        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let conn = self.conn.lock().await;

        let rows_affected = conn
            .execute(
                "DELETE FROM blobs WHERE blob_id = ?1",
                rusqlite::params![blob_id.as_slice()],
            )
            .map_err(|e| StorageError::Internal(format!("sqlite delete: {e}")))?;

        Ok(rows_affected > 0)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        let conn = self.conn.lock().await;

        let rows_affected = conn
            .execute(
                "DELETE FROM blobs WHERE expires_at <= ?1",
                rusqlite::params![now],
            )
            .map_err(|e| StorageError::Internal(format!("sqlite purge: {e}")))?;

        Ok(rows_affected)
    }
}
