//! The `blobs` table both `SQLite` blob stores share: `SqliteBlobStore`
//! (feature `sqlite-blob`) and `CombinedNodeStorage` (feature `combined`)
//! (spec §17.7, `SqliteBlobStore` Schema). The module compiles under either
//! feature alone, so it links to neither type.
//!
//! A retained record (`09-security-model.md` §9.10.12) stores NULL in
//! `blob_ttl` and `expires_at` and its admission counter in `admission`: no
//! live-row check expires it and TTL purge never deletes it. A TTL blob
//! stores NULL in `admission`. Queries return rows in ascending
//! (`stored_at`, `blob_id`) order, resume after a [`QueryCursor`], and apply
//! a [`LifetimeFilter`] in the `WHERE` clause.

use rusqlite::{Connection, OptionalExtension};

use super::storage::{
    LifetimeFilter, QueryCursor, StorageError, StoredBlob, StoredLifetime, lifetime_predicate,
};

/// Creates the `blobs` table and its indexes.
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS blobs (
        blob_id BLOB PRIMARY KEY,
        routing_id BLOB NOT NULL,
        recipient_hint BLOB,
        blob_ttl INTEGER,
        admission INTEGER,
        stored_at INTEGER NOT NULL,
        expires_at INTEGER,
        blob BLOB NOT NULL
    ) WITHOUT ROWID;

    CREATE INDEX IF NOT EXISTS idx_routing ON blobs (routing_id, stored_at, blob_id);
    CREATE INDEX IF NOT EXISTS idx_expiry ON blobs (expires_at);";

/// The columns [`read_row`] reads, in order.
const COLUMNS: &str = "routing_id, blob_id, recipient_hint, blob_ttl, admission, stored_at, blob";

/// The live-row predicate over `?2 = now`: a retained row never expires.
const LIVE: &str = "(expires_at IS NULL OR expires_at > ?2)";

fn internal(op: &str, e: &rusqlite::Error) -> StorageError {
    StorageError::Internal(format!("sqlite {op}: {e}"))
}

/// Reads a 32-byte column, failing the row on any other width.
fn column32(row: &rusqlite::Row<'_>, index: usize, name: &str) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(index)?;
    bytes.as_slice().try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, name.to_owned(), rusqlite::types::Type::Blob)
    })
}

/// Reads a row of [`COLUMNS`]. A row carrying both a TTL and an admission
/// counter, or neither, fails as a conversion error.
fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredBlob> {
    let recipient_hint = match row.get::<_, Option<Vec<u8>>>(2)? {
        Some(_) => Some(column32(row, 2, "recipient_hint")?),
        None => None,
    };
    Ok(StoredBlob {
        routing_id: column32(row, 0, "routing_id")?,
        blob_id: column32(row, 1, "blob_id")?,
        recipient_hint,
        lifetime: StoredLifetime::from_columns(row.get(3)?, row.get(4)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Integer, e.into())
        })?,
        stored_at: row.get(5)?,
        blob: row.get(6)?,
    })
}

/// Inserts or replaces a blob stored at `stored_at`.
pub(super) fn store(conn: &Connection, stored: StoredBlob) -> Result<StoredBlob, StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO blobs
            (blob_id, routing_id, recipient_hint, blob_ttl, admission, stored_at, expires_at, blob)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            stored.blob_id.as_slice(),
            stored.routing_id.as_slice(),
            stored.recipient_hint.map(|h| h.to_vec()),
            stored.lifetime.ttl(),
            stored.lifetime.admission(),
            stored.stored_at,
            stored.lifetime.expires_at(stored.stored_at),
            stored.blob,
        ],
    )
    .map_err(|e| internal("insert", &e))?;
    Ok(stored)
}

/// Reads a live blob by id.
pub(super) fn get(
    conn: &Connection,
    blob_id: &[u8; 32],
    now: u64,
) -> Result<Option<StoredBlob>, StorageError> {
    conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM blobs WHERE blob_id = ?1 AND {LIVE}"
    ))
    .map_err(|e| internal("prepare", &e))?
    .query_row(rusqlite::params![blob_id.as_slice(), now], read_row)
    .optional()
    .map_err(|e| internal("get", &e))
}

/// Reads the live blobs of a routing id that `filter` admits after
/// `cursor`, in query order.
pub(super) fn query(
    conn: &Connection,
    routing_id: &[u8; 32],
    cursor: QueryCursor,
    filter: LifetimeFilter,
    limit: u32,
    now: u64,
) -> Result<Vec<StoredBlob>, StorageError> {
    // ?3 is the `stored_at` floor and ?4 the cursor's `blob_id`, or NULL for a
    // cursor without one; a row at the floor passes only above ?4. ?6 is the
    // lifetime filter's code.
    let lifetime = lifetime_predicate("?6");
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM blobs
             WHERE routing_id = ?1 AND {LIVE} AND {lifetime} AND stored_at >= ?3
               AND (?4 IS NULL OR stored_at > ?3 OR blob_id > ?4)
             ORDER BY stored_at ASC, blob_id ASC
             LIMIT ?5"
        ))
        .map_err(|e| internal("prepare", &e))?;
    let rows = stmt
        .query_map(
            rusqlite::params![
                routing_id.as_slice(),
                now,
                cursor.floor(),
                cursor.after_blob().map(|id| id.to_vec()),
                limit,
                filter.sql_code(),
            ],
            read_row,
        )
        .map_err(|e| internal("query", &e))?;
    rows.map(|row| row.map_err(|e| internal("row", &e)))
        .collect()
}

/// Deletes a blob by id; `true` when a row was removed.
pub(super) fn delete(conn: &Connection, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
    conn.execute(
        "DELETE FROM blobs WHERE blob_id = ?1",
        rusqlite::params![blob_id.as_slice()],
    )
    .map(|n| n > 0)
    .map_err(|e| internal("delete", &e))
}

/// Deletes every expired TTL blob, and no retained one.
pub(super) fn purge_expired(conn: &Connection, now: u64) -> Result<usize, StorageError> {
    conn.execute(
        "DELETE FROM blobs WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        rusqlite::params![now],
    )
    .map_err(|e| internal("purge", &e))
}

/// Counts every stored row, expired or not.
pub(super) fn count(conn: &Connection) -> Result<usize, StorageError> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get(0))
        .map_err(|e| internal("count", &e))?;
    usize::try_from(count)
        .map_err(|e| StorageError::Internal(format!("blob count {count} out of range: {e}")))
}
