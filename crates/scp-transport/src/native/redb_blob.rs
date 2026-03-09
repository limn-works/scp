//! redb-backed blob storage for the SCP native relay.
//!
//! Implements [`BlobStorage`] using redb (pure Rust B-tree database). Two
//! tables: `blobs` (`blob_id` -> serialized `StoredBlob`) and `routing`
//! (multimap: `routing_id` -> `blob_id` set). TTL enforcement via periodic
//! scan of the blobs table.
//!
//! Gated behind the `redb-blob` feature flag.
//!
//! See spec section 17.7 (`RedbBlobStore`) in
//! `.docs/specs/17-persistence-and-storage.md`.

use std::path::Path;
use std::sync::Arc;

use redb::{
    Database, MultimapTableDefinition, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::storage::{BlobStorage, ClockFn, StorageError, StoredBlob, system_clock};

/// Table: `blob_id` (32 bytes) -> `MessagePack`-serialized [`SerializedBlob`].
const BLOBS_TABLE: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("blobs");

/// Multimap table: `routing_id` (32 bytes) -> set of `blob_id` (32 bytes).
const ROUTING_TABLE: MultimapTableDefinition<&[u8; 32], &[u8; 32]> =
    MultimapTableDefinition::new("routing");

/// Internal serializable representation of a stored blob.
///
/// Stored as `MessagePack` in the blobs table. Fields mirror [`StoredBlob`]
/// plus `expires_at` for TTL enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedBlob {
    routing_id: [u8; 32],
    blob_id: [u8; 32],
    recipient_hint: Option<[u8; 32]>,
    blob_ttl: u32,
    stored_at: u64,
    expires_at: u64,
    #[serde(with = "serde_bytes")]
    blob: Vec<u8>,
}

impl SerializedBlob {
    /// Converts to a [`StoredBlob`].
    ///
    /// `recipient_hint` is `Option<[u8; 32]>` in both types, so no manual
    /// conversion is needed — serde validates the length at deserialization
    /// time.
    fn to_stored_blob(&self) -> StoredBlob {
        StoredBlob {
            routing_id: self.routing_id,
            blob_id: self.blob_id,
            recipient_hint: self.recipient_hint,
            blob_ttl: self.blob_ttl,
            stored_at: self.stored_at,
            blob: self.blob.clone(),
        }
    }
}

/// redb-backed blob storage for relay-side encrypted message blobs.
///
/// Uses two redb tables per spec section 17.7:
/// - `blobs: Table<&[u8; 32], &[u8]>` -- `blob_id` -> serialized blob
/// - `routing: MultimapTable<&[u8; 32], &[u8; 32]>` -- `routing_id` -> `blob_id` set
///
/// TTL enforcement via periodic scan (redb does not support secondary
/// indexes natively).
#[derive(Clone)]
pub struct RedbBlobStore {
    db: Arc<Mutex<Database>>,
    clock: ClockFn,
}

impl std::fmt::Debug for RedbBlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbBlobStore")
            .field("clock", &"<fn>")
            .finish()
    }
}

impl RedbBlobStore {
    /// Opens (or creates) a redb blob store at the given file path.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Self::open_with_clock(path, system_clock())
    }

    /// Opens a redb blob store with a controllable clock.
    ///
    /// Used by conformance tests for deterministic TTL testing.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be opened.
    pub fn open_with_clock(path: &Path, clock: ClockFn) -> Result<Self, StorageError> {
        let db = Database::create(path)
            .map_err(|e| StorageError::Internal(format!("redb create: {e}")))?;
        Self::init_tables(db, clock)
    }

    /// Creates a temporary redb blob store (useful for testing without
    /// persistent filesystem state).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be created.
    pub fn temporary() -> Result<Self, StorageError> {
        Self::temporary_with_clock(system_clock())
    }

    /// Creates a temporary redb blob store with a controllable clock.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the database cannot be created.
    pub fn temporary_with_clock(clock: ClockFn) -> Result<Self, StorageError> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| StorageError::Internal(format!("redb create: {e}")))?;
        Self::init_tables(db, clock)
    }

    /// Initializes the database by opening a write transaction that touches
    /// both table definitions, ensuring they exist.
    fn init_tables(db: Database, clock: ClockFn) -> Result<Self, StorageError> {
        // Open a write transaction to create tables if they don't exist.
        let write_txn = db
            .begin_write()
            .map_err(|e| StorageError::Internal(format!("redb begin_write: {e}")))?;
        {
            let _blobs = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;
            let _routing = write_txn
                .open_multimap_table(ROUTING_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open routing: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Internal(format!("redb commit: {e}")))?;

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            clock,
        })
    }
}

#[allow(clippy::significant_drop_tightening)]
#[async_trait::async_trait]
impl BlobStorage for RedbBlobStore {
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

        let entry = SerializedBlob {
            routing_id,
            blob_id,
            recipient_hint,
            blob_ttl,
            stored_at,
            expires_at,
            blob: blob.clone(),
        };

        let serialized = rmp_serde::to_vec(&entry)
            .map_err(|e| StorageError::Internal(format!("msgpack encode: {e}")))?;

        let db = self.db.lock().await;
        let write_txn = db
            .begin_write()
            .map_err(|e| StorageError::Internal(format!("redb begin_write: {e}")))?;
        {
            let mut blobs_table = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;
            blobs_table
                .insert(&blob_id, serialized.as_slice())
                .map_err(|e| StorageError::Internal(format!("redb insert blob: {e}")))?;

            let mut routing_table = write_txn
                .open_multimap_table(ROUTING_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open routing: {e}")))?;
            routing_table
                .insert(&routing_id, &blob_id)
                .map_err(|e| StorageError::Internal(format!("redb insert routing: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Internal(format!("redb commit: {e}")))?;

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
        let db = self.db.lock().await;
        let read_txn = db
            .begin_read()
            .map_err(|e| StorageError::Internal(format!("redb begin_read: {e}")))?;
        let blobs_table = read_txn
            .open_table(BLOBS_TABLE)
            .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;

        let Some(value) = blobs_table
            .get(blob_id)
            .map_err(|e| StorageError::Internal(format!("redb get: {e}")))?
        else {
            return Ok(None);
        };

        let entry: SerializedBlob = rmp_serde::from_slice(value.value())
            .map_err(|e| StorageError::Internal(format!("msgpack decode: {e}")))?;

        if entry.expires_at <= now {
            return Ok(None);
        }

        Ok(Some(entry.to_stored_blob()))
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        since: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = (self.clock)();
        let db = self.db.lock().await;
        let read_txn = db
            .begin_read()
            .map_err(|e| StorageError::Internal(format!("redb begin_read: {e}")))?;

        let routing_table = read_txn
            .open_multimap_table(ROUTING_TABLE)
            .map_err(|e| StorageError::Internal(format!("redb open routing: {e}")))?;
        let blobs_table = read_txn
            .open_table(BLOBS_TABLE)
            .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;

        // Collect all blob_ids for this routing_id.
        let blob_ids_iter = routing_table
            .get(routing_id)
            .map_err(|e| StorageError::Internal(format!("redb routing get: {e}")))?;

        let mut candidates = Vec::new();
        for result in blob_ids_iter {
            let bid_guard =
                result.map_err(|e| StorageError::Internal(format!("redb routing iter: {e}")))?;
            let bid = *bid_guard.value();

            if let Some(value) = blobs_table
                .get(&bid)
                .map_err(|e| StorageError::Internal(format!("redb get blob: {e}")))?
            {
                let entry: SerializedBlob = rmp_serde::from_slice(value.value())
                    .map_err(|e| StorageError::Internal(format!("msgpack decode: {e}")))?;

                // Skip expired blobs.
                if entry.expires_at <= now {
                    continue;
                }

                // Apply since filter.
                if let Some(since_ts) = since
                    && entry.stored_at <= since_ts
                {
                    continue;
                }

                candidates.push(entry.to_stored_blob());
            }
        }

        // Sort by stored_at ascending (oldest first).
        candidates.sort_by_key(|b| b.stored_at);

        // Apply limit.
        candidates.truncate(limit as usize);

        Ok(candidates)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let db = self.db.lock().await;

        // First, read the blob to get its routing_id for index cleanup.
        let routing_id = {
            let read_txn = db
                .begin_read()
                .map_err(|e| StorageError::Internal(format!("redb begin_read: {e}")))?;
            let blobs_table = read_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;

            let Some(value) = blobs_table
                .get(blob_id)
                .map_err(|e| StorageError::Internal(format!("redb get: {e}")))?
            else {
                return Ok(false);
            };

            let entry: SerializedBlob = rmp_serde::from_slice(value.value())
                .map_err(|e| StorageError::Internal(format!("msgpack decode: {e}")))?;
            entry.routing_id
        };

        // Delete from both tables in a single write transaction.
        let write_txn = db
            .begin_write()
            .map_err(|e| StorageError::Internal(format!("redb begin_write: {e}")))?;
        {
            let mut blobs_table = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;
            blobs_table
                .remove(blob_id)
                .map_err(|e| StorageError::Internal(format!("redb remove blob: {e}")))?;

            let mut routing_table = write_txn
                .open_multimap_table(ROUTING_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open routing: {e}")))?;
            routing_table
                .remove(&routing_id, blob_id)
                .map_err(|e| StorageError::Internal(format!("redb remove routing: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Internal(format!("redb commit: {e}")))?;

        Ok(true)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = (self.clock)();
        let db = self.db.lock().await;

        // Phase 1: Identify expired blob_ids by scanning the blobs table.
        let expired: Vec<([u8; 32], [u8; 32])> = {
            let read_txn = db
                .begin_read()
                .map_err(|e| StorageError::Internal(format!("redb begin_read: {e}")))?;
            let blobs_table = read_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;

            let mut expired_entries = Vec::new();
            let iter = blobs_table
                .iter()
                .map_err(|e| StorageError::Internal(format!("redb iter: {e}")))?;

            for result in iter {
                let (key, value) =
                    result.map_err(|e| StorageError::Internal(format!("redb iter entry: {e}")))?;
                let entry: SerializedBlob = rmp_serde::from_slice(value.value())
                    .map_err(|e| StorageError::Internal(format!("msgpack decode: {e}")))?;

                if entry.expires_at <= now {
                    expired_entries.push((*key.value(), entry.routing_id));
                }
            }
            expired_entries
        };

        if expired.is_empty() {
            return Ok(0);
        }

        let count = expired.len();

        // Phase 2: Remove expired entries in a single write transaction.
        let write_txn = db
            .begin_write()
            .map_err(|e| StorageError::Internal(format!("redb begin_write: {e}")))?;
        {
            let mut blobs_table = write_txn
                .open_table(BLOBS_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;
            let mut routing_table = write_txn
                .open_multimap_table(ROUTING_TABLE)
                .map_err(|e| StorageError::Internal(format!("redb open routing: {e}")))?;

            for (blob_id, routing_id) in &expired {
                blobs_table
                    .remove(blob_id)
                    .map_err(|e| StorageError::Internal(format!("redb remove blob: {e}")))?;
                routing_table
                    .remove(routing_id, blob_id)
                    .map_err(|e| StorageError::Internal(format!("redb remove routing: {e}")))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| StorageError::Internal(format!("redb commit: {e}")))?;

        Ok(count)
    }

    async fn count(&self) -> Result<usize, StorageError> {
        let db = self.db.lock().await;
        let read_txn = db
            .begin_read()
            .map_err(|e| StorageError::Internal(format!("redb begin_read: {e}")))?;
        let blobs_table = read_txn
            .open_table(BLOBS_TABLE)
            .map_err(|e| StorageError::Internal(format!("redb open blobs: {e}")))?;
        let len = blobs_table
            .len()
            .map_err(|e| StorageError::Internal(format!("redb len: {e}")))?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(len as usize)
    }
}
