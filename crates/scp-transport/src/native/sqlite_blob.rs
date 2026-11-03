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

use super::sql_blob;
use super::storage::{
    BlobStorage, ClockFn, LifetimeFilter, QueryCursor, StorageError, StoredBlob, StoredLifetime,
    system_clock,
};

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
///     blob_ttl INTEGER,          -- NULL: a retained record
///     admission INTEGER,         -- a retained record's admission counter; NULL on a TTL blob
///     stored_at INTEGER NOT NULL,
///     expires_at INTEGER,        -- NULL: never expires
///     blob BLOB NOT NULL
/// ) WITHOUT ROWID;
///
/// CREATE INDEX idx_routing ON blobs (routing_id, stored_at, blob_id);
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
        let conn =
            scp_sqlite_pools::open(path).map_err(|e| StorageError::Internal(e.to_string()))?;
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
        let conn = scp_sqlite_pools::open_in_memory()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        Self::init_connection(conn, clock)
    }

    /// Initializes the connection with WAL mode and schema.
    fn init_connection(conn: Connection, clock: ClockFn) -> Result<Self, StorageError> {
        // PRAGMA synchronous = NORMAL with WAL mode: the last transaction
        // before a power failure may be lost, but the database will not be
        // corrupted. This is acceptable for relay blob storage because
        // messages can always be retransmitted by senders. The performance
        // benefit (fewer fsyncs) outweighs the minor durability trade-off.
        //
        // rusqlite is built with `bundled-sqlcipher`, so this connection is a
        // SQLCipher connection too. `cipher_memory_security` makes SQLCipher
        // wipe every block its allocator frees; its `malloc` heap is outside
        // the wiping global allocator. A block reaches that allocator only
        // because SQLite's page-cache bulk block is absent, no page-cache
        // buffer has held a page, and the connection's lookaside pool is off,
        // which `scp_sqlite_pools` checked before handing the connection over;
        // that holds while no code in the process reconfigures SQLite (spec
        // §17.6, and §9.15 of the security-model spec, freed heap memory).
        //
        // The pragma runs alone and is read back before `journal_mode = WAL`,
        // the connection's first statement that reads a page: while no code in
        // the process reconfigures SQLite, `1` shows memory security is on and
        // that SQLCipher is the linked engine.
        conn.execute_batch("PRAGMA cipher_memory_security = ON;")
            .map_err(|e| StorageError::Internal(format!("sqlite pragma: {e}")))?;
        scp_sqlite_pools::require_memory_security(&conn)
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )
        .map_err(|e| StorageError::Internal(format!("sqlite pragma: {e}")))?;

        conn.execute_batch(sql_blob::SCHEMA)
            .map_err(|e| StorageError::Internal(format!("sqlite schema: {e}")))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }
}

#[allow(clippy::significant_drop_tightening)]
#[async_trait::async_trait]
impl BlobStorage for SqliteBlobStore {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        lifetime: StoredLifetime,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored = StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at: (self.clock)(),
            blob,
        };
        sql_blob::store(&*self.conn.lock().await, stored)
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let now = (self.clock)();
        sql_blob::get(&*self.conn.lock().await, blob_id, now)
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        cursor: QueryCursor,
        filter: LifetimeFilter,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = (self.clock)();
        sql_blob::query(
            &*self.conn.lock().await,
            routing_id,
            cursor,
            filter,
            limit,
            now,
        )
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        sql_blob::delete(&*self.conn.lock().await, blob_id)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        sql_blob::purge_expired(&*self.conn.lock().await, now)
    }

    async fn count(&self) -> Result<usize, StorageError> {
        sql_blob::count(&*self.conn.lock().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each constructor's own connection serves nothing from `SQLite`'s
    /// lookaside pool after its pragmas and an insert with bound values
    /// (spec §17.6, `SQLCipher` configuration).
    fn assert_serves_nothing_from_lookaside(
        store: &SqliteBlobStore,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = store.conn.blocking_lock();
        conn.execute_batch("CREATE TABLE lookaside_probe (k TEXT NOT NULL, v BLOB NOT NULL)")?;
        conn.execute(
            "INSERT INTO lookaside_probe (k, v) VALUES (?1, ?2)",
            rusqlite::params!["a-key", vec![0x5A_u8; 64]],
        )?;
        let used = scp_sqlite_pools::lookaside_use(&conn)?;
        drop(conn);
        assert_eq!(
            used,
            scp_sqlite_pools::LookasideUse {
                slots_high_water: 0,
                hits: 0
            },
            "no lookaside slot may hold the key statement or the bound values"
        );
        Ok(())
    }

    #[test]
    fn file_connection_serves_nothing_from_lookaside() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = SqliteBlobStore::open(&dir.path().join("blobs.db"))?;
        assert_serves_nothing_from_lookaside(&store)
    }

    #[test]
    fn in_memory_connection_serves_nothing_from_lookaside() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SqliteBlobStore::in_memory()?;
        assert_serves_nothing_from_lookaside(&store)
    }
}
