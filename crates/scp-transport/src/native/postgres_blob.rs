//! `PostgreSQL`-backed blob storage for production/enterprise SCP relay deployments.
//!
//! [`PostgresBlobStore`] implements the [`BlobStorage`] trait using `sqlx` with
//! `PostgreSQL`. It mirrors the `SqliteBlobStore` schema but uses `PostgreSQL`-native
//! types (`BYTEA`, `BIGINT`, `INTEGER`).
//!
//! # Usage
//!
//! ```rust,no_run
//! use scp_transport::native::postgres_blob::PostgresBlobStore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let store = PostgresBlobStore::open("postgres://localhost/scp_blobs").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature flag
//!
//! This module requires the `postgres-blob` feature:
//!
//! ```toml
//! scp-transport = { path = "...", features = ["postgres-blob"] }
//! ```
//!
//! See `.docs/specs/17-persistence-and-storage.md` section 17.7 for the full
//! specification.

use std::sync::Arc;

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use super::storage::{
    BlobStorage, ClockFn, LifetimeFilter, QueryCursor, StorageError, StoredBlob, StoredLifetime,
    lifetime_predicate, system_clock,
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS blobs (
    blob_id BYTEA PRIMARY KEY,
    routing_id BYTEA NOT NULL,
    recipient_hint BYTEA,
    blob_ttl INTEGER,
    admission BIGINT,
    stored_at BIGINT NOT NULL,
    expires_at BIGINT,
    blob BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_routing ON blobs (routing_id, stored_at, blob_id);
CREATE INDEX IF NOT EXISTS idx_expiry ON blobs (expires_at);
";

// ---------------------------------------------------------------------------
// PostgresBlobStore
// ---------------------------------------------------------------------------

/// `PostgreSQL`-backed blob storage for the SCP native relay.
///
/// Uses `sqlx` with a connection pool. Schema is created automatically on
/// [`open`](Self::open). Suitable for production and enterprise relay
/// deployments where `PostgreSQL` is the operational database.
///
/// Thread-safe: all operations go through the `sqlx` pool which manages
/// connections internally.
pub struct PostgresBlobStore {
    pool: PgPool,
    clock: ClockFn,
}

impl std::fmt::Debug for PostgresBlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresBlobStore")
            .field("pool", &"<PgPool>")
            .field("clock", &"<fn>")
            .finish()
    }
}

impl Clone for PostgresBlobStore {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            clock: Arc::clone(&self.clock),
        }
    }
}

impl PostgresBlobStore {
    /// Opens a connection to the `PostgreSQL` database at `database_url` and
    /// creates the schema if it does not exist.
    ///
    /// Uses the system clock for timestamp generation.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the connection or schema creation
    /// fails.
    pub async fn open(database_url: &str) -> Result<Self, StorageError> {
        Self::open_with_clock(database_url, system_clock()).await
    }

    /// Opens a connection with an injectable clock (for testing).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the connection or schema creation
    /// fails.
    pub async fn open_with_clock(database_url: &str, clock: ClockFn) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| StorageError::Internal(format!("postgres connect: {e}")))?;

        // Create schema (idempotent). `SCHEMA_SQL` holds three statements;
        // `raw_sql` sends them over the simple-query protocol, because the
        // extended protocol `query` uses prepares one statement and PostgreSQL
        // refuses a multi-statement string there.
        sqlx::raw_sql(SCHEMA_SQL)
            .execute(&pool)
            .await
            .map_err(|e| StorageError::Internal(format!("postgres schema: {e}")))?;

        Ok(Self { pool, clock })
    }

    /// Returns the current timestamp from the injected clock.
    fn now(&self) -> u64 {
        (self.clock)()
    }
}

// ---------------------------------------------------------------------------
// BlobStorage implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl BlobStorage for PostgresBlobStore {
    async fn store(
        &self,
        routing_id: [u8; 32],
        blob_id: [u8; 32],
        recipient_hint: Option<[u8; 32]>,
        lifetime: StoredLifetime,
        blob: Vec<u8>,
    ) -> Result<StoredBlob, StorageError> {
        let stored_at = self.now();

        let hint_slice: Option<&[u8]> = recipient_hint.as_ref().map(AsRef::as_ref);
        let admission = lifetime
            .admission()
            .map(i64::try_from)
            .transpose()
            .map_err(|e| StorageError::Internal(format!("admission counter out of range: {e}")))?;

        sqlx::query(
            "INSERT INTO blobs (blob_id, routing_id, recipient_hint, blob_ttl, admission, stored_at, expires_at, blob) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (blob_id) DO UPDATE SET \
               routing_id = EXCLUDED.routing_id, \
               recipient_hint = EXCLUDED.recipient_hint, \
               blob_ttl = EXCLUDED.blob_ttl, \
               admission = EXCLUDED.admission, \
               stored_at = EXCLUDED.stored_at, \
               expires_at = EXCLUDED.expires_at, \
               blob = EXCLUDED.blob",
        )
        .bind(blob_id.as_slice())
        .bind(routing_id.as_slice())
        .bind(hint_slice)
        .bind(lifetime.ttl().map(u32_to_i32))
        .bind(admission)
        .bind(u64_to_i64(stored_at))
        .bind(lifetime.expires_at(stored_at).map(u64_to_i64))
        .bind(&blob)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("postgres store: {e}")))?;

        Ok(StoredBlob {
            routing_id,
            blob_id,
            recipient_hint,
            lifetime,
            stored_at,
            blob,
        })
    }

    async fn get(&self, blob_id: &[u8; 32]) -> Result<Option<StoredBlob>, StorageError> {
        let now = self.now();

        let row = sqlx::query(
            "SELECT routing_id, recipient_hint, blob_ttl, admission, stored_at, blob \
             FROM blobs WHERE blob_id = $1 AND (expires_at IS NULL OR expires_at > $2)",
        )
        .bind(blob_id.as_slice())
        .bind(u64_to_i64(now))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("postgres get: {e}")))?;

        match row {
            None => Ok(None),
            Some(row) => {
                let routing_id = bytes_to_array32(row.get::<Vec<u8>, _>("routing_id"))?;
                let recipient_hint = optional_bytes_to_array32(row.get("recipient_hint"))?;
                let lifetime = read_lifetime(&row)?;
                let stored_at = i64_to_u64(row.get::<i64, _>("stored_at"));
                let blob: Vec<u8> = row.get("blob");

                Ok(Some(StoredBlob {
                    routing_id,
                    blob_id: *blob_id,
                    recipient_hint,
                    lifetime,
                    stored_at,
                    blob,
                }))
            }
        }
    }

    async fn query(
        &self,
        routing_id: &[u8; 32],
        cursor: QueryCursor,
        filter: LifetimeFilter,
        limit: u32,
    ) -> Result<Vec<StoredBlob>, StorageError> {
        let now = self.now();

        // $3 is the `stored_at` floor and $4 the cursor's `blob_id`, or NULL
        // for a cursor without one; a row at the floor passes only above it.
        // $6 is the lifetime filter's code.
        let rows = sqlx::query(&format!(
            "SELECT blob_id, recipient_hint, blob_ttl, admission, stored_at, blob \
             FROM blobs \
             WHERE routing_id = $1 AND (expires_at IS NULL OR expires_at > $2) \
               AND {} \
               AND stored_at >= $3 \
               AND ($4::BYTEA IS NULL OR stored_at > $3 OR blob_id > $4) \
             ORDER BY stored_at ASC, blob_id ASC \
             LIMIT $5",
            lifetime_predicate("$6")
        ))
        .bind(routing_id.as_slice())
        .bind(u64_to_i64(now))
        .bind(u64_to_i64(cursor.floor()))
        .bind(cursor.after_blob().map(|id| id.to_vec()))
        .bind(i64::from(limit))
        .bind(filter.sql_code())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Internal(format!("postgres query: {e}")))?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let blob_id = bytes_to_array32(row.get::<Vec<u8>, _>("blob_id"))?;
            let recipient_hint = optional_bytes_to_array32(row.get("recipient_hint"))?;
            let lifetime = read_lifetime(&row)?;
            let stored_at = i64_to_u64(row.get::<i64, _>("stored_at"));
            let blob: Vec<u8> = row.get("blob");

            results.push(StoredBlob {
                routing_id: *routing_id,
                blob_id,
                recipient_hint,
                lifetime,
                stored_at,
                blob,
            });
        }

        Ok(results)
    }

    async fn delete(&self, blob_id: &[u8; 32]) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM blobs WHERE blob_id = $1")
            .bind(blob_id.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(format!("postgres delete: {e}")))?;

        Ok(result.rows_affected() > 0)
    }

    async fn purge_expired(&self) -> Result<usize, StorageError> {
        let now = self.now();

        let result =
            sqlx::query("DELETE FROM blobs WHERE expires_at IS NOT NULL AND expires_at <= $1")
                .bind(u64_to_i64(now))
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::Internal(format!("postgres purge: {e}")))?;

        #[allow(clippy::cast_possible_truncation)]
        Ok(result.rows_affected() as usize)
    }

    async fn count(&self) -> Result<usize, StorageError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blobs")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(format!("postgres count: {e}")))?;
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        Ok(row.0 as usize)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// -- Safe integer conversion helpers (`PostgreSQL` uses signed types) ----------

/// Casts a `u64` to `i64` for `PostgreSQL` `BIGINT` columns.
///
/// Unix timestamps and blob counts fit in `i64` for centuries. Values above
/// `i64::MAX` are clamped — this is defense-in-depth, not expected in practice.
#[allow(clippy::cast_possible_wrap)]
const fn u64_to_i64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

/// Casts an `i64` from a `PostgreSQL` `BIGINT` column back to `u64`.
///
/// Negative values (should not occur for timestamps) are clamped to 0.
#[allow(clippy::cast_sign_loss)]
const fn i64_to_u64(v: i64) -> u64 {
    if v < 0 { 0 } else { v as u64 }
}

/// Casts a `u32` to `i32` for `PostgreSQL` `INTEGER` columns.
///
/// `blob_ttl` is a `u32` representing seconds. Values above `i32::MAX` (~68 years)
/// are clamped — effectively unlimited TTL.
#[allow(clippy::cast_possible_wrap)]
const fn u32_to_i32(v: u32) -> i32 {
    if v > i32::MAX as u32 {
        i32::MAX
    } else {
        v as i32
    }
}

/// Casts an `i32` from a `PostgreSQL` `INTEGER` column back to `u32`.
#[allow(clippy::cast_sign_loss)]
const fn i32_to_u32(v: i32) -> u32 {
    if v < 0 { 0 } else { v as u32 }
}

/// Converts a `Vec<u8>` from a `BYTEA` column to a `[u8; 32]`.
/// Reads the `blob_ttl` and `admission` columns: a TTL alone is a TTL blob
/// and a counter alone a retained record.
///
/// # Errors
///
/// [`StorageError::Internal`] for a negative counter or a row carrying both
/// columns or neither.
fn read_lifetime(row: &sqlx::postgres::PgRow) -> Result<StoredLifetime, StorageError> {
    let admission = row
        .get::<Option<i64>, _>("admission")
        .map(u64::try_from)
        .transpose()
        .map_err(|e| StorageError::Internal(format!("admission counter out of range: {e}")))?;
    StoredLifetime::from_columns(
        row.get::<Option<i32>, _>("blob_ttl").map(i32_to_u32),
        admission,
    )
}

fn bytes_to_array32(bytes: Vec<u8>) -> Result<[u8; 32], StorageError> {
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| StorageError::Internal(format!("expected 32 bytes, got {}", v.len())))
}

/// Converts an optional `Vec<u8>` from a nullable `BYTEA` column to `Option<[u8; 32]>`.
fn optional_bytes_to_array32(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, StorageError> {
    bytes.map(bytes_to_array32).transpose()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The tests need a running `PostgreSQL` server, named by `DATABASE_URL`, on
// which the URL's role may run `CREATE DATABASE`. Each test creates its own
// database there, so tests running in parallel never share a `blobs` table.
// CI's `transport-blob` leg starts a `PostgreSQL` container and sets
// `DATABASE_URL` (`.github/workflows/ci.yml`, "Run the blob-backend tests").
//
// Run with: DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
//   cargo test -p scp-transport --features postgres-blob --lib postgres_blob
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn make_blob_id(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Creates a database no other test uses on the server `DATABASE_URL`
    /// names, and returns its URL. A test without `DATABASE_URL` fails here
    /// rather than passing without a server.
    async fn isolated_database_url() -> String {
        let server = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL names the PostgreSQL server these tests run against");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&server)
            .await
            .expect("connect to the DATABASE_URL server");
        let name = format!("scp_test_{:016x}", rand::random::<u64>());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .expect("create the test database");
        admin.close().await;
        let mut url = url::Url::parse(&server).expect("DATABASE_URL is a URL");
        url.set_path(&name);
        url.to_string()
    }

    /// Creates a controllable clock starting at `start`.
    fn test_clock(start: u64) -> (ClockFn, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(start));
        let time_clone = Arc::clone(&time);
        let clock: ClockFn = Arc::new(move || time_clone.load(Ordering::SeqCst));
        (clock, time)
    }

    /// Opens a store on a database of its own.
    async fn fresh_store() -> PostgresBlobStore {
        PostgresBlobStore::open(&isolated_database_url().await)
            .await
            .unwrap()
    }

    /// Opens a store with an injectable clock on a database of its own.
    async fn fresh_store_with_clock(clock: ClockFn) -> PostgresBlobStore {
        PostgresBlobStore::open_with_clock(&isolated_database_url().await, clock)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn store_and_get_returns_blob() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![1, 2, 3, 4];
        let blob_id = make_blob_id(&blob_data);

        let stored = storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data.clone(),
            )
            .await
            .unwrap();

        assert_eq!(stored.blob_id, blob_id);
        assert_eq!(stored.routing_id, routing_id);
        assert_eq!(stored.blob, blob_data);
        assert_eq!(stored.lifetime, StoredLifetime::Ttl(3600));
        assert!(stored.stored_at > 0);

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, blob_data);
        assert_eq!(retrieved.blob_id, blob_id);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let storage = fresh_store().await;
        let blob_id = [0xFF; 32];
        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_blob() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![5, 6, 7];
        let blob_id = make_blob_id(&blob_data);

        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data,
            )
            .await
            .unwrap();

        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(deleted);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let storage = fresh_store().await;
        let blob_id = [0xFF; 32];
        let deleted = storage.delete(&blob_id).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn query_returns_blobs_for_routing_id() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];

        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = storage
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn query_respects_limit() {
        let storage = fresh_store().await;
        let routing_id = [0xBB; 32];

        for i in 0u8..10 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = storage
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                3,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn query_returns_oldest_first() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xCC; 32];

        for i in 0u8..3 {
            // Advance clock so stored_at values are distinct and ordered.
            time.store(1_000_000 + u64::from(i) * 10, Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let results = storage
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        for window in results.windows(2) {
            assert!(window[0].stored_at <= window[1].stored_at);
        }
    }

    #[tokio::test]
    async fn query_different_routing_id_returns_empty() {
        let storage = fresh_store().await;
        let routing_id_a = [0xAA; 32];
        let routing_id_b = [0xBB; 32];

        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);
        storage
            .store(
                routing_id_a,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        let results = storage
            .query(
                &routing_id_b,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn store_with_recipient_hint_preserves_it() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let hint = [0xBB; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        let stored = storage
            .store(
                routing_id,
                blob_id,
                Some(hint),
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        assert_eq!(stored.recipient_hint, Some(hint));

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.recipient_hint, Some(hint));
    }

    /// `09-security-model.md` §9.10.12: a retained record carries no TTL, so
    /// no purge removes it while a TTL blob beside it expires.
    #[tokio::test]
    async fn retained_record_survives_every_purge() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xAD; 32];
        let retained = vec![0x52; 16];
        let retained_id = make_blob_id(&retained);
        storage
            .store(
                routing_id,
                retained_id,
                None,
                crate::native::storage::StoredLifetime::Retained { admission: 0 },
                retained.clone(),
            )
            .await
            .unwrap();
        let ttl_data = vec![0x54; 16];
        let ttl_id = make_blob_id(&ttl_data);
        storage
            .store(
                routing_id,
                ttl_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(10),
                ttl_data,
            )
            .await
            .unwrap();

        // Past the longest TTL a blob may carry, twice.
        for _ in 0..2 {
            time.fetch_add(
                u64::from(scp_relay_client::MAX_BLOB_TTL) + 1,
                Ordering::SeqCst,
            );
            storage.purge_expired().await.unwrap();
        }

        let held = storage.get(&retained_id).await.unwrap().unwrap();
        assert_eq!(held.blob, retained);
        assert_eq!(
            held.lifetime,
            crate::native::storage::StoredLifetime::Retained { admission: 0 }
        );
        assert!(storage.get(&ttl_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_expired_removes_old_blobs() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 60 seconds. expires_at = 1_000_060.
        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(60),
                data,
            )
            .await
            .unwrap();

        // Advance clock past expiry.
        time.store(1_000_100, Ordering::SeqCst);

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn purge_expired_does_not_remove_active_blobs() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let data = vec![4, 5, 6];
        let blob_id = make_blob_id(&data);

        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 0);

        let result = storage.get(&blob_id).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn delete_cleans_up_and_query_returns_empty() {
        let storage = fresh_store().await;
        let routing_id = [0xDD; 32];
        let data = vec![7, 8, 9];
        let blob_id = make_blob_id(&data);

        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        storage.delete(&blob_id).await.unwrap();

        let results = storage
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::All,
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn query_with_since_filter() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xEE; 32];

        // Store 3 blobs at different times.
        for i in 0u8..3 {
            time.store(1_000_000 + u64::from(i) * 100, Ordering::SeqCst);
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(86400),
                    data,
                )
                .await
                .unwrap();
        }

        // Query with since=1_000_050 should exclude the first blob (stored_at=1_000_000)
        // and include the second (stored_at=1_000_100) and third (stored_at=1_000_200).
        let results = storage
            .query(
                &routing_id,
                crate::native::storage::QueryCursor::Since(1_000_050),
                crate::native::storage::LifetimeFilter::Any,
                100,
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].stored_at > 1_000_050);
    }

    #[tokio::test]
    async fn get_expired_returns_none() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xAA; 32];
        let data = vec![1, 2, 3];
        let blob_id = make_blob_id(&data);

        // Store with TTL of 60 seconds.
        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(60),
                data,
            )
            .await
            .unwrap();

        // Blob should be retrievable before TTL expires.
        let before = storage.get(&blob_id).await.unwrap();
        assert!(before.is_some());

        // Advance clock past expiry.
        time.store(1_000_061, Ordering::SeqCst);

        // Blob should not be returned after TTL expires.
        let after = storage.get(&blob_id).await.unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn store_returns_correct_blob_id() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let blob_data = vec![11, 22, 33, 44, 55];
        let expected_id = make_blob_id(&blob_data);

        let stored = storage
            .store(
                routing_id,
                expected_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                blob_data,
            )
            .await
            .unwrap();

        assert_eq!(stored.blob_id, expected_id);
    }

    #[tokio::test]
    async fn concurrent_store_purge() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xAA; 32];

        // Store blobs with short TTL.
        for i in 0u8..5 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(10),
                    data,
                )
                .await
                .unwrap();
        }

        // Advance clock past TTL.
        time.store(1_000_011, Ordering::SeqCst);

        // Run purge and store concurrently.
        let storage_clone = storage.clone();
        let purge_handle = tokio::spawn(async move { storage_clone.purge_expired().await });

        // Store new blobs while purge runs.
        for i in 10u8..15 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            storage
                .store(
                    routing_id,
                    blob_id,
                    None,
                    crate::native::storage::StoredLifetime::Ttl(3600),
                    data,
                )
                .await
                .unwrap();
        }

        let purge_result = purge_handle.await.unwrap();
        assert!(purge_result.is_ok());

        // Verify newly stored blobs are still retrievable.
        for i in 10u8..15 {
            let data = vec![i; 10];
            let blob_id = make_blob_id(&data);
            let result = storage.get(&blob_id).await.unwrap();
            assert!(result.is_some(), "blob {i} should survive concurrent purge");
            assert_eq!(result.unwrap().blob, data);
        }
    }

    #[tokio::test]
    async fn purge_expired_only_removes_expired() {
        let (clock, time) = test_clock(1_000_000);
        let storage = fresh_store_with_clock(clock).await;
        let routing_id = [0xAA; 32];

        // Store a short-lived blob (TTL 10s).
        let short_data = vec![1, 2, 3];
        let short_id = make_blob_id(&short_data);
        storage
            .store(
                routing_id,
                short_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(10),
                short_data,
            )
            .await
            .unwrap();

        // Store a long-lived blob (TTL 3600s).
        let long_data = vec![4, 5, 6];
        let long_id = make_blob_id(&long_data);
        storage
            .store(
                routing_id,
                long_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                long_data.clone(),
            )
            .await
            .unwrap();

        // Advance clock past short TTL but not long TTL.
        time.store(1_000_011, Ordering::SeqCst);

        let purged = storage.purge_expired().await.unwrap();
        assert_eq!(purged, 1);

        // Short-lived blob should be gone.
        let short_result = storage.get(&short_id).await.unwrap();
        assert!(short_result.is_none());

        // Long-lived blob should still exist.
        let long_result = storage.get(&long_id).await.unwrap().unwrap();
        assert_eq!(long_result.blob, long_data);
    }

    #[tokio::test]
    async fn store_overwrites_existing_blob() {
        let storage = fresh_store().await;
        let routing_id = [0xAA; 32];
        let data = vec![1u8; 10];
        let blob_id = make_blob_id(&data);

        storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(3600),
                data,
            )
            .await
            .unwrap();

        // Overwrite with different TTL.
        let updated_data = vec![1u8; 20];
        let result = storage
            .store(
                routing_id,
                blob_id,
                None,
                crate::native::storage::StoredLifetime::Ttl(7200),
                updated_data.clone(),
            )
            .await;
        assert!(result.is_ok());

        let retrieved = storage.get(&blob_id).await.unwrap().unwrap();
        assert_eq!(retrieved.blob, updated_data);
        assert_eq!(retrieved.lifetime, StoredLifetime::Ttl(7200));
    }
}
