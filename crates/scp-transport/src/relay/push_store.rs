//! Relay push registration store (spec §10.7.1 step 4, PUSH-006).
//!
//! A relay that runs the push role keeps each verified `PushRegistration` in
//! this store. The store indexes registrations two ways:
//!
//! - by registration key: the registrant's identity identifier, the push
//!   platform, and the platform token, so one identity can register several
//!   devices on one platform;
//! - by routing ID, so a message arriving on a routing ID finds every token to
//!   wake.
//!
//! It also keeps, per key, a count of consecutive invalid-token responses from
//! the push service, which the sender uses to deregister a token after three
//! failures (§10.7.1, `PushDeregistration`).
//!
//! # Freshness floor
//!
//! §10.7.1 "Freshness" rejects a message whose timestamp is at or below the
//! last one the relay accepted for the same registration key, and keeps that
//! timestamp after a deregistration removes the registration, so a
//! registration replayed after its deregistration is stale. The store keeps
//! that last accepted timestamp per key: the registration's own while it is
//! stored, and a deregistration floor once it is removed.
//! [`PushRegistrationStore::accepted_timestamp`] reads it, every write refuses
//! a timestamp at or below it with [`PushStoreError::Stale`], and
//! [`PushRegistrationStore::prune_deregistrations`] drops floors old enough
//! that the skew window already rejects every message they would refuse. The
//! relay applies the skew window itself; the store holds no clock.
//!
//! # Capability selection
//!
//! [`PushRegistrationStore`] is the capability selector (spec §17.17, ADR-062).
//! It implements no `Default`, so a relay names its arm explicitly.
//!
//! - [`PushRegistrationStore::Sqlite`] is the only arm a shipped build
//!   contains. It opens its database through `scp-sqlite-pools`.
//! - `PushRegistrationStore::InMemory` exists only under the `testing`
//!   feature. Its classification under §17.17.2 is durability-only: a restart
//!   loses registrations and clients re-register, and it accepts nothing the
//!   relay has not already verified.
//!
//! # Token handling
//!
//! A platform token is stored because the relay needs it to send a wake, and
//! for no other reason. No `Debug` output, error message, or log line in this
//! module carries a token; [`PushRegistrationKey`] and
//! [`PushRegistrationRecord`] print only the token's length.
//!
//! # Identity field
//!
//! `registrant` carries today's identity string (a `did:dht` identifier) until
//! SCP-308 S1 defines the identity identifier type that the §22.11.4 wire table
//! names. The store treats it as an opaque string.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use scp_protocol::discovery::push::PushPlatform;
use tokio::sync::Mutex;

/// The most registrations one registrant may hold on one relay.
///
/// An upsert of a new key for a registrant that already holds this many
/// registrations returns [`PushStoreError::LimitReached`]. An upsert of a key
/// the registrant already holds is never refused by the cap.
pub const MAX_REGISTRATIONS_PER_REGISTRANT: usize = 16;

/// A relay routing ID (32 bytes).
pub type RoutingId = [u8; 32];

/// The key a registration is stored under: (registrant, platform, token).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PushRegistrationKey {
    /// The identity identifier that signed the registration.
    pub registrant: String,
    /// The push service platform.
    pub platform: PushPlatform,
    /// The platform token. Never logged.
    pub token: Vec<u8>,
}

impl std::fmt::Debug for PushRegistrationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistrationKey")
            .field("registrant", &self.registrant)
            .field("platform", &self.platform)
            .field("token_len", &self.token.len())
            .finish()
    }
}

/// One stored push registration.
#[derive(Clone, PartialEq, Eq)]
pub struct PushRegistrationRecord {
    /// The identity identifier that signed the registration.
    pub registrant: String,
    /// The push service platform.
    pub platform: PushPlatform,
    /// The platform token. Never logged.
    pub token: Vec<u8>,
    /// The routing IDs whose traffic wakes this token. The store keeps them
    /// sorted and free of duplicates, and refuses an empty list.
    pub routing_ids: Vec<RoutingId>,
    /// The registration's timestamp, in Unix seconds.
    pub timestamp: u64,
}

impl PushRegistrationRecord {
    /// Returns the key this record is stored under.
    #[must_use]
    pub fn key(&self) -> PushRegistrationKey {
        PushRegistrationKey {
            registrant: self.registrant.clone(),
            platform: self.platform,
            token: self.token.clone(),
        }
    }
}

impl std::fmt::Debug for PushRegistrationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistrationRecord")
            .field("registrant", &self.registrant)
            .field("platform", &self.platform)
            .field("token_len", &self.token.len())
            .field("routing_ids", &self.routing_ids.len())
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// What an accepted [`PushRegistrationStore::upsert`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// No registration existed under the key; the store added one.
    Inserted,
    /// A registration existed under the key with a different routing-ID set;
    /// the store replaced it and its routing-ID index entries.
    Replaced,
    /// A registration existed under the key with the same routing-ID set; the
    /// store updated only its timestamp and left the index unchanged.
    Refreshed,
}

/// Errors from the push registration store. No variant carries a token.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PushStoreError {
    /// The offered timestamp is not newer than the last one the store accepted
    /// for the key, from a registration or a deregistration.
    #[error("push message is stale: last accepted timestamp {last_accepted}, offered {offered}")]
    Stale {
        /// The last timestamp the store accepted for the key.
        last_accepted: u64,
        /// The offered message's timestamp.
        offered: u64,
    },
    /// The registrant already holds the per-registrant maximum of
    /// registrations, and the offered key is a new one.
    #[error("push registration limit of {cap} per registrant reached")]
    LimitReached {
        /// The per-registrant cap ([`MAX_REGISTRATIONS_PER_REGISTRANT`]).
        cap: usize,
    },
    /// The registration lists no routing ID.
    #[error("push registration lists no routing ID")]
    EmptyRoutingIds,
    /// The timestamp exceeds what the store can persist (`i64::MAX`).
    #[error("push registration timestamp {0} is out of range")]
    TimestampOutOfRange(u64),
    /// The backing database failed or holds a malformed row.
    #[error("push store: {0}")]
    Storage(String),
}

impl PushStoreError {
    /// The relay wire code (ADR-004) the relay answers this refusal with.
    ///
    /// - [`Self::Stale`]: `4062` `PUSH_REGISTRATION_STALE`. A timestamp the
    ///   store cannot persist ([`Self::TimestampOutOfRange`]) lies far outside
    ///   the skew window, so it gets the same code.
    /// - [`Self::LimitReached`]: `4064` `PUSH_REGISTRATION_LIMIT`.
    /// - [`Self::EmptyRoutingIds`]: `4060` `PUSH_REGISTRATION_REJECTED`.
    /// - [`Self::Storage`]: `5000` `INTERNAL_ERROR`.
    #[must_use]
    pub const fn wire_code(&self) -> u16 {
        use scp_relay_client::code;
        match self {
            Self::Stale { .. } | Self::TimestampOutOfRange(_) => code::PUSH_REGISTRATION_STALE,
            Self::LimitReached { .. } => code::PUSH_REGISTRATION_LIMIT,
            Self::EmptyRoutingIds => code::PUSH_REGISTRATION_REJECTED,
            Self::Storage(_) => code::INTERNAL_ERROR,
        }
    }
}

/// Refuses `offered` when it is at or below `last_accepted`.
const fn check_fresh(last_accepted: Option<u64>, offered: u64) -> Result<(), PushStoreError> {
    match last_accepted {
        Some(last_accepted) if offered <= last_accepted => Err(PushStoreError::Stale {
            last_accepted,
            offered,
        }),
        _ => Ok(()),
    }
}

/// Refuses a timestamp the SQLite arm cannot persist, so both arms refuse the
/// same messages.
fn check_timestamp(timestamp: u64) -> Result<(), PushStoreError> {
    if i64::try_from(timestamp).is_err() {
        return Err(PushStoreError::TimestampOutOfRange(timestamp));
    }
    Ok(())
}

/// The relay push registration store: the capability selector.
///
/// Implements no `Default` (spec §17.17.1 SCP-CAPSEL-8000). Construct the
/// shipped arm with [`PushRegistrationStore::open_sqlite`].
#[derive(Debug, Clone)]
pub enum PushRegistrationStore {
    /// The durable arm: an `SQLCipher` database opened through
    /// `scp-sqlite-pools`.
    Sqlite(SqlitePushStore),
    /// The durability-only arm, compiled only under the `testing` feature.
    #[cfg(feature = "testing")]
    InMemory(InMemoryPushStore),
}

impl PushRegistrationStore {
    /// Opens (or creates) the SQLite arm at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`PushStoreError::Storage`] when the database cannot be opened
    /// or its schema cannot be applied. The caller sees the failure; nothing
    /// falls back to another arm (SCP-CAPSEL-8001).
    pub fn open_sqlite(path: &Path) -> Result<Self, PushStoreError> {
        Ok(Self::Sqlite(SqlitePushStore::open(path)?))
    }

    /// Creates the in-memory arm. Compiled only under the `testing` feature.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn in_memory() -> Self {
        Self::InMemory(InMemoryPushStore::default())
    }

    /// Stores `record` under its key.
    ///
    /// - A timestamp at or below the key's last accepted one (see
    ///   [`Self::accepted_timestamp`]) returns [`PushStoreError::Stale`], so a
    ///   registration replayed after its deregistration is refused.
    /// - With no registration under the key, the store adds `record`, unless
    ///   the registrant already holds [`MAX_REGISTRATIONS_PER_REGISTRANT`]. The
    ///   added registration's timestamp replaces any deregistration floor.
    /// - With a stored registration, a newer timestamp replaces the stored
    ///   routing IDs and timestamp, and leaves the index untouched when the
    ///   routing-ID set is unchanged. The cap never refuses a stored key.
    ///
    /// The consecutive invalid-token count survives a replacement, because a
    /// re-registration says nothing about whether the token is valid.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Stale`], [`PushStoreError::LimitReached`],
    /// [`PushStoreError::EmptyRoutingIds`],
    /// [`PushStoreError::TimestampOutOfRange`], or
    /// [`PushStoreError::Storage`].
    pub async fn upsert(
        &self,
        record: PushRegistrationRecord,
    ) -> Result<UpsertOutcome, PushStoreError> {
        let record = normalize(record)?;
        match self {
            Self::Sqlite(s) => s.upsert(&record).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => s.upsert(record).await,
        }
    }

    /// Returns the registration stored under `key`.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn get(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<PushRegistrationRecord>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.get(key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.get(key).await),
        }
    }

    /// Deletes the registration under `key`, its routing-ID index entries and
    /// its invalid-token count, as the relay does after three consecutive
    /// invalid-token responses (§10.7.1). The registration's timestamp stays
    /// as the key's deregistration floor. Returns whether a registration
    /// existed. The registrant's other registrations stay in place.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn remove(&self, key: &PushRegistrationKey) -> Result<bool, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.remove(key, None).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => s.remove(key, None).await,
        }
    }

    /// Applies an accepted `PushDeregistration` for `key` carrying
    /// `timestamp` (§10.7.1).
    ///
    /// - A timestamp at or below the key's last accepted one returns
    ///   [`PushStoreError::Stale`] and changes nothing.
    /// - Otherwise the store deletes the registration under `key` as
    ///   [`Self::remove`] does and keeps `timestamp` as the key's
    ///   deregistration floor. The registrant's other registrations stay in
    ///   place.
    /// - With no registration under `key`, the store raises an existing floor
    ///   to `timestamp` and records no new one, so a deregistration for a key
    ///   the relay never held stores nothing.
    ///
    /// Returns whether a registration existed.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Stale`], [`PushStoreError::TimestampOutOfRange`], or
    /// [`PushStoreError::Storage`].
    pub async fn deregister(
        &self,
        key: &PushRegistrationKey,
        timestamp: u64,
    ) -> Result<bool, PushStoreError> {
        check_timestamp(timestamp)?;
        match self {
            Self::Sqlite(s) => s.remove(key, Some(timestamp)).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => s.remove(key, Some(timestamp)).await,
        }
    }

    /// Returns the last timestamp the store accepted for `key`: the stored
    /// registration's, or else the key's deregistration floor. The relay
    /// compares a message's timestamp with it before verifying the signature
    /// (§10.7.1 "Freshness").
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn accepted_timestamp(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u64>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.accepted_timestamp(key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.accepted_timestamp(key).await),
        }
    }

    /// Drops every deregistration floor below `accepted_before` and returns
    /// how many it dropped.
    ///
    /// The relay passes its clock minus the push timestamp skew window
    /// (§10.7.1, §9.18.13). A message at or below a dropped floor carries a
    /// timestamp older than that, which the skew check already rejects, so
    /// dropping the floor admits no replay.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn prune_deregistrations(
        &self,
        accepted_before: u64,
    ) -> Result<usize, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.prune_deregistrations(accepted_before).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.prune_deregistrations(accepted_before).await),
        }
    }

    /// Returns every registration that lists `routing_id`, each once, ordered
    /// by key.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn tokens_for_routing_id(
        &self,
        routing_id: &RoutingId,
    ) -> Result<Vec<PushRegistrationRecord>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.tokens_for_routing_id(routing_id).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.tokens_for_routing_id(routing_id).await),
        }
    }

    /// Adds one to the consecutive invalid-token count under `key` and returns
    /// the new count, or `None` when no registration exists under `key`.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn record_invalid_token(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u32>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.record_invalid_token(key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.record_invalid_token(key).await),
        }
    }

    /// Resets the consecutive invalid-token count under `key` to zero, as a
    /// delivery the push service accepted does. Returns whether a
    /// registration exists under `key`.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn clear_invalid_tokens(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<bool, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.clear_invalid_tokens(key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.clear_invalid_tokens(key).await),
        }
    }

    /// Returns the consecutive invalid-token count under `key`, or `None`
    /// when no registration exists under `key`.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn invalid_token_failures(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u32>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.invalid_token_failures(key).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.invalid_token_failures(key).await),
        }
    }
}

/// Sorts and de-duplicates the routing IDs, and checks the invariants every
/// arm relies on, so both arms accept and refuse the same records.
fn normalize(mut record: PushRegistrationRecord) -> Result<PushRegistrationRecord, PushStoreError> {
    record.routing_ids.sort_unstable();
    record.routing_ids.dedup();
    if record.routing_ids.is_empty() {
        return Err(PushStoreError::EmptyRoutingIds);
    }
    check_timestamp(record.timestamp)?;
    Ok(record)
}

// ---------------------------------------------------------------------------
// SQLite arm
// ---------------------------------------------------------------------------

/// The durable push registration store, an `SQLCipher` database opened through
/// `scp-sqlite-pools`.
///
/// No at-rest key is applied, as for the relay blob store: §10.7.1 accepts that
/// the relay operator sees registrations and their tokens. Operators who want
/// at-rest encryption use filesystem-level encryption.
#[derive(Clone)]
pub struct SqlitePushStore {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for SqlitePushStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlitePushStore").finish_non_exhaustive()
    }
}

fn storage(context: &str, e: &rusqlite::Error) -> PushStoreError {
    PushStoreError::Storage(format!("{context}: {e}"))
}

fn platform_from_tag(tag: u8) -> Result<PushPlatform, PushStoreError> {
    [PushPlatform::Apns, PushPlatform::Fcm, PushPlatform::WebPush]
        .into_iter()
        .find(|p| p.tag_byte() == tag)
        .ok_or_else(|| PushStoreError::Storage(format!("unknown platform tag {tag}")))
}

fn routing_id_from_blob(blob: &[u8]) -> Result<RoutingId, PushStoreError> {
    blob.try_into()
        .map_err(|_| PushStoreError::Storage(format!("routing_id has {} bytes", blob.len())))
}

fn timestamp_from_column(value: i64) -> Result<u64, PushStoreError> {
    u64::try_from(value).map_err(|_| PushStoreError::Storage(format!("timestamp {value}")))
}

/// `normalize` has already proven the timestamp fits.
fn timestamp_to_column(value: u64) -> Result<i64, PushStoreError> {
    i64::try_from(value).map_err(|_| PushStoreError::TimestampOutOfRange(value))
}

fn routing_ids_for(
    conn: &Connection,
    key: &PushRegistrationKey,
) -> Result<Vec<RoutingId>, PushStoreError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT routing_id FROM push_routing_index
             WHERE registrant = ?1 AND platform = ?2 AND token = ?3
             ORDER BY routing_id",
        )
        .map_err(|e| storage("prepare routing ids", &e))?;
    let rows = stmt
        .query_map(
            params![key.registrant, key.platform.tag_byte(), key.token],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|e| storage("query routing ids", &e))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(routing_id_from_blob(
            &row.map_err(|e| storage("read routing id", &e))?,
        )?);
    }
    Ok(out)
}

fn stored_timestamp(
    conn: &Connection,
    key: &PushRegistrationKey,
) -> Result<Option<u64>, PushStoreError> {
    conn.prepare_cached(
        "SELECT timestamp FROM push_registrations
         WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
    )
    .map_err(|e| storage("prepare timestamp", &e))?
    .query_row(
        params![key.registrant, key.platform.tag_byte(), key.token],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(|e| storage("read timestamp", &e))?
    .map(timestamp_from_column)
    .transpose()
}

fn floor_timestamp(
    conn: &Connection,
    key: &PushRegistrationKey,
) -> Result<Option<u64>, PushStoreError> {
    conn.prepare_cached(
        "SELECT timestamp FROM push_deregistrations
         WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
    )
    .map_err(|e| storage("prepare floor", &e))?
    .query_row(
        params![key.registrant, key.platform.tag_byte(), key.token],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(|e| storage("read floor", &e))?
    .map(timestamp_from_column)
    .transpose()
}

/// The registration's timestamp, or else the deregistration floor. A key never
/// holds both: an insert deletes the floor and a removal writes it.
fn last_accepted(
    conn: &Connection,
    key: &PushRegistrationKey,
) -> Result<Option<u64>, PushStoreError> {
    if let Some(timestamp) = stored_timestamp(conn, key)? {
        return Ok(Some(timestamp));
    }
    floor_timestamp(conn, key)
}

fn insert_index(conn: &Connection, record: &PushRegistrationRecord) -> Result<(), PushStoreError> {
    let mut stmt = conn
        .prepare_cached(
            "INSERT INTO push_routing_index (routing_id, registrant, platform, token)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .map_err(|e| storage("prepare index insert", &e))?;
    for routing_id in &record.routing_ids {
        stmt.execute(params![
            routing_id.as_slice(),
            record.registrant,
            record.platform.tag_byte(),
            record.token
        ])
        .map_err(|e| storage("insert index", &e))?;
    }
    Ok(())
}

fn delete_index(conn: &Connection, key: &PushRegistrationKey) -> Result<(), PushStoreError> {
    conn.execute(
        "DELETE FROM push_routing_index WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
        params![key.registrant, key.platform.tag_byte(), key.token],
    )
    .map_err(|e| storage("delete index", &e))?;
    Ok(())
}

impl SqlitePushStore {
    /// Opens (or creates) the store at `path`.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database cannot be opened, memory
    /// security cannot be confirmed, or the schema cannot be applied.
    pub fn open(path: &Path) -> Result<Self, PushStoreError> {
        let conn =
            scp_sqlite_pools::open(path).map_err(|e| PushStoreError::Storage(e.to_string()))?;
        // The connection is a SQLCipher connection (`bundled-sqlcipher`).
        // `cipher_memory_security` wipes every block SQLCipher frees, under the
        // conditions `scp_sqlite_pools` checked before returning it (spec
        // §17.6); the pragma runs alone and is read back before the first
        // statement that reads a page, as in `native::sqlite_blob`.
        conn.execute_batch("PRAGMA cipher_memory_security = ON;")
            .map_err(|e| storage("pragma", &e))?;
        scp_sqlite_pools::require_memory_security(&conn)
            .map_err(|e| PushStoreError::Storage(e.to_string()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS push_registrations (
                 registrant TEXT NOT NULL,
                 platform INTEGER NOT NULL,
                 token BLOB NOT NULL,
                 timestamp INTEGER NOT NULL,
                 invalid_token_failures INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (registrant, platform, token)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS push_routing_index (
                 routing_id BLOB NOT NULL,
                 registrant TEXT NOT NULL,
                 platform INTEGER NOT NULL,
                 token BLOB NOT NULL,
                 PRIMARY KEY (routing_id, registrant, platform, token)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_push_routing_by_key
                 ON push_routing_index (registrant, platform, token);
             CREATE TABLE IF NOT EXISTS push_deregistrations (
                 registrant TEXT NOT NULL,
                 platform INTEGER NOT NULL,
                 token BLOB NOT NULL,
                 timestamp INTEGER NOT NULL,
                 PRIMARY KEY (registrant, platform, token)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_push_deregistrations_by_timestamp
                 ON push_deregistrations (timestamp);",
        )
        .map_err(|e| storage("schema", &e))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn upsert(
        &self,
        record: &PushRegistrationRecord,
    ) -> Result<UpsertOutcome, PushStoreError> {
        let key = record.key();
        let timestamp = timestamp_to_column(record.timestamp)?;
        let mut conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| storage("begin", &e))?;
        check_fresh(last_accepted(&tx, &key)?, record.timestamp)?;
        let outcome = if stored_timestamp(&tx, &key)?.is_some() {
            tx.execute(
                "UPDATE push_registrations SET timestamp = ?4
                 WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
                params![
                    key.registrant,
                    key.platform.tag_byte(),
                    key.token,
                    timestamp
                ],
            )
            .map_err(|e| storage("update", &e))?;
            if routing_ids_for(&tx, &key)? == record.routing_ids {
                UpsertOutcome::Refreshed
            } else {
                delete_index(&tx, &key)?;
                insert_index(&tx, record)?;
                UpsertOutcome::Replaced
            }
        } else {
            let held: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM push_registrations WHERE registrant = ?1",
                    params![key.registrant],
                    |row| row.get(0),
                )
                .map_err(|e| storage("count", &e))?;
            if usize::try_from(held).map_or(true, |h| h >= MAX_REGISTRATIONS_PER_REGISTRANT) {
                return Err(PushStoreError::LimitReached {
                    cap: MAX_REGISTRATIONS_PER_REGISTRANT,
                });
            }
            tx.execute(
                "INSERT INTO push_registrations (registrant, platform, token, timestamp)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    key.registrant,
                    key.platform.tag_byte(),
                    key.token,
                    timestamp
                ],
            )
            .map_err(|e| storage("insert", &e))?;
            insert_index(&tx, record)?;
            tx.execute(
                "DELETE FROM push_deregistrations
                 WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
                params![key.registrant, key.platform.tag_byte(), key.token],
            )
            .map_err(|e| storage("delete floor", &e))?;
            UpsertOutcome::Inserted
        };
        tx.commit().map_err(|e| storage("commit", &e))?;
        drop(conn);
        Ok(outcome)
    }

    async fn get(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<PushRegistrationRecord>, PushStoreError> {
        let conn = self.conn.lock().await;
        let Some(timestamp) = stored_timestamp(&conn, key)? else {
            return Ok(None);
        };
        let routing_ids = routing_ids_for(&conn, key)?;
        drop(conn);
        Ok(Some(PushRegistrationRecord {
            registrant: key.registrant.clone(),
            platform: key.platform,
            token: key.token.clone(),
            routing_ids,
            timestamp,
        }))
    }

    /// `deregistered_at` is a deregistration's timestamp, or `None` for a
    /// removal after invalid-token failures, which keeps the registration's
    /// own timestamp as the floor.
    async fn remove(
        &self,
        key: &PushRegistrationKey,
        deregistered_at: Option<u64>,
    ) -> Result<bool, PushStoreError> {
        let mut conn = self.conn.lock().await;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| storage("begin", &e))?;
        if let Some(offered) = deregistered_at {
            check_fresh(last_accepted(&tx, key)?, offered)?;
        }
        let registered_at = stored_timestamp(&tx, key)?;
        // A key the store holds nothing for gets no floor.
        let held = registered_at.is_some() || floor_timestamp(&tx, key)?.is_some();
        let floor = deregistered_at.or(registered_at).filter(|_| held);
        delete_index(&tx, key)?;
        tx.execute(
            "DELETE FROM push_registrations
             WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
            params![key.registrant, key.platform.tag_byte(), key.token],
        )
        .map_err(|e| storage("delete", &e))?;
        if let Some(floor) = floor {
            tx.execute(
                "INSERT INTO push_deregistrations (registrant, platform, token, timestamp)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (registrant, platform, token) DO UPDATE SET timestamp = ?4",
                params![
                    key.registrant,
                    key.platform.tag_byte(),
                    key.token,
                    timestamp_to_column(floor)?
                ],
            )
            .map_err(|e| storage("write floor", &e))?;
        }
        tx.commit().map_err(|e| storage("commit", &e))?;
        drop(conn);
        Ok(registered_at.is_some())
    }

    async fn accepted_timestamp(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u64>, PushStoreError> {
        let conn = self.conn.lock().await;
        let accepted = last_accepted(&conn, key)?;
        drop(conn);
        Ok(accepted)
    }

    async fn prune_deregistrations(&self, accepted_before: u64) -> Result<usize, PushStoreError> {
        let conn = self.conn.lock().await;
        // A bound above `i64::MAX` exceeds every floor the store can hold.
        let pruned = i64::try_from(accepted_before)
            .map_or_else(
                |_| conn.execute("DELETE FROM push_deregistrations", []),
                |bound| {
                    conn.execute(
                        "DELETE FROM push_deregistrations WHERE timestamp < ?1",
                        params![bound],
                    )
                },
            )
            .map_err(|e| storage("prune floors", &e))?;
        drop(conn);
        Ok(pruned)
    }

    async fn tokens_for_routing_id(
        &self,
        routing_id: &RoutingId,
    ) -> Result<Vec<PushRegistrationRecord>, PushStoreError> {
        let conn = self.conn.lock().await;
        let mut keys = Vec::new();
        {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT registrant, platform, token FROM push_routing_index
                     WHERE routing_id = ?1
                     ORDER BY registrant, platform, token",
                )
                .map_err(|e| storage("prepare lookup", &e))?;
            let rows = stmt
                .query_map(params![routing_id.as_slice()], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u8>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(|e| storage("query lookup", &e))?;
            for row in rows {
                let (registrant, tag, token) = row.map_err(|e| storage("read lookup", &e))?;
                keys.push(PushRegistrationKey {
                    registrant,
                    platform: platform_from_tag(tag)?,
                    token,
                });
            }
        }
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let timestamp = stored_timestamp(&conn, &key)?.ok_or_else(|| {
                PushStoreError::Storage("index entry without registration".to_owned())
            })?;
            let routing_ids = routing_ids_for(&conn, &key)?;
            out.push(PushRegistrationRecord {
                registrant: key.registrant,
                platform: key.platform,
                token: key.token,
                routing_ids,
                timestamp,
            });
        }
        drop(conn);
        Ok(out)
    }

    async fn record_invalid_token(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u32>, PushStoreError> {
        let conn = self.conn.lock().await;
        let count = conn
            .query_row(
                "UPDATE push_registrations
                 SET invalid_token_failures = invalid_token_failures + 1
                 WHERE registrant = ?1 AND platform = ?2 AND token = ?3
                 RETURNING invalid_token_failures",
                params![key.registrant, key.platform.tag_byte(), key.token],
                |row| row.get::<_, u32>(0),
            )
            .optional()
            .map_err(|e| storage("record failure", &e))?;
        drop(conn);
        Ok(count)
    }

    async fn clear_invalid_tokens(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<bool, PushStoreError> {
        let conn = self.conn.lock().await;
        let updated = conn
            .execute(
                "UPDATE push_registrations SET invalid_token_failures = 0
                 WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
                params![key.registrant, key.platform.tag_byte(), key.token],
            )
            .map_err(|e| storage("clear failures", &e))?;
        drop(conn);
        Ok(updated > 0)
    }

    async fn invalid_token_failures(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u32>, PushStoreError> {
        let conn = self.conn.lock().await;
        let count = conn
            .query_row(
                "SELECT invalid_token_failures FROM push_registrations
                 WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
                params![key.registrant, key.platform.tag_byte(), key.token],
                |row| row.get::<_, u32>(0),
            )
            .optional()
            .map_err(|e| storage("read failures", &e))?;
        drop(conn);
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// In-memory arm (testing only)
// ---------------------------------------------------------------------------

#[cfg(feature = "testing")]
pub use in_memory::InMemoryPushStore;

#[cfg(feature = "testing")]
mod in_memory {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::{
        MAX_REGISTRATIONS_PER_REGISTRANT, PushRegistrationKey, PushRegistrationRecord,
        PushStoreError, RoutingId, UpsertOutcome, check_fresh,
    };

    #[derive(Debug, Default)]
    struct InMemoryState {
        records: HashMap<PushRegistrationKey, (PushRegistrationRecord, u32)>,
        by_routing_id: HashMap<RoutingId, HashSet<PushRegistrationKey>>,
        per_registrant: HashMap<String, usize>,
        /// Deregistration floors; a key never holds a record and a floor.
        floors: HashMap<PushRegistrationKey, u64>,
    }

    impl InMemoryState {
        fn last_accepted(&self, key: &PushRegistrationKey) -> Option<u64> {
            self.records
                .get(key)
                .map(|(record, _)| record.timestamp)
                .or_else(|| self.floors.get(key).copied())
        }

        fn unindex(&mut self, key: &PushRegistrationKey, routing_ids: &[RoutingId]) {
            for routing_id in routing_ids {
                if let Some(keys) = self.by_routing_id.get_mut(routing_id) {
                    keys.remove(key);
                    if keys.is_empty() {
                        self.by_routing_id.remove(routing_id);
                    }
                }
            }
        }

        fn index(&mut self, key: &PushRegistrationKey, routing_ids: &[RoutingId]) {
            for routing_id in routing_ids {
                self.by_routing_id
                    .entry(*routing_id)
                    .or_default()
                    .insert(key.clone());
            }
        }
    }

    /// The durability-only push registration store. Compiled only under the
    /// `testing` feature; a restart loses every registration.
    #[derive(Debug, Clone, Default)]
    pub struct InMemoryPushStore {
        state: Arc<Mutex<InMemoryState>>,
    }

    impl InMemoryPushStore {
        pub(super) async fn upsert(
            &self,
            record: PushRegistrationRecord,
        ) -> Result<UpsertOutcome, PushStoreError> {
            let key = record.key();
            let mut state = self.state.lock().await;
            check_fresh(state.last_accepted(&key), record.timestamp)?;
            let previous = state
                .records
                .get(&key)
                .map(|(stored, failures)| (stored.routing_ids.clone(), *failures));
            let outcome = if let Some((routing_ids, failures)) = previous {
                let outcome = if routing_ids == record.routing_ids {
                    UpsertOutcome::Refreshed
                } else {
                    state.unindex(&key, &routing_ids);
                    state.index(&key, &record.routing_ids);
                    UpsertOutcome::Replaced
                };
                state.records.insert(key, (record, failures));
                outcome
            } else {
                let held = state
                    .per_registrant
                    .get(&record.registrant)
                    .copied()
                    .unwrap_or(0);
                if held >= MAX_REGISTRATIONS_PER_REGISTRANT {
                    return Err(PushStoreError::LimitReached {
                        cap: MAX_REGISTRATIONS_PER_REGISTRANT,
                    });
                }
                *state
                    .per_registrant
                    .entry(record.registrant.clone())
                    .or_insert(0) += 1;
                state.index(&key, &record.routing_ids);
                state.floors.remove(&key);
                state.records.insert(key, (record, 0));
                UpsertOutcome::Inserted
            };
            drop(state);
            Ok(outcome)
        }

        pub(super) async fn get(
            &self,
            key: &PushRegistrationKey,
        ) -> Option<PushRegistrationRecord> {
            self.state
                .lock()
                .await
                .records
                .get(key)
                .map(|(record, _)| record.clone())
        }

        /// Mirrors `SqlitePushStore::remove`.
        pub(super) async fn remove(
            &self,
            key: &PushRegistrationKey,
            deregistered_at: Option<u64>,
        ) -> Result<bool, PushStoreError> {
            let mut state = self.state.lock().await;
            if let Some(offered) = deregistered_at {
                check_fresh(state.last_accepted(key), offered)?;
            }
            let held = state.floors.contains_key(key);
            let Some((record, _)) = state.records.remove(key) else {
                if held && let Some(offered) = deregistered_at {
                    state.floors.insert(key.clone(), offered);
                }
                drop(state);
                return Ok(false);
            };
            state.unindex(key, &record.routing_ids);
            if let Some(count) = state.per_registrant.get_mut(&key.registrant) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_registrant.remove(&key.registrant);
                }
            }
            state
                .floors
                .insert(key.clone(), deregistered_at.unwrap_or(record.timestamp));
            drop(state);
            Ok(true)
        }

        pub(super) async fn accepted_timestamp(&self, key: &PushRegistrationKey) -> Option<u64> {
            self.state.lock().await.last_accepted(key)
        }

        pub(super) async fn prune_deregistrations(&self, accepted_before: u64) -> usize {
            let mut state = self.state.lock().await;
            let before = state.floors.len();
            state.floors.retain(|_, floor| *floor >= accepted_before);
            let pruned = before - state.floors.len();
            drop(state);
            pruned
        }

        pub(super) async fn tokens_for_routing_id(
            &self,
            routing_id: &RoutingId,
        ) -> Vec<PushRegistrationRecord> {
            let state = self.state.lock().await;
            let mut keys: Vec<&PushRegistrationKey> = state
                .by_routing_id
                .get(routing_id)
                .map(|keys| keys.iter().collect())
                .unwrap_or_default();
            keys.sort_by(|a, b| {
                (&a.registrant, a.platform.tag_byte(), &a.token).cmp(&(
                    &b.registrant,
                    b.platform.tag_byte(),
                    &b.token,
                ))
            });
            let records = keys
                .into_iter()
                .filter_map(|key| state.records.get(key).map(|(record, _)| record.clone()))
                .collect();
            drop(state);
            records
        }

        pub(super) async fn record_invalid_token(&self, key: &PushRegistrationKey) -> Option<u32> {
            let mut state = self.state.lock().await;
            let count = state.records.get_mut(key).map(|(_, failures)| {
                *failures = failures.saturating_add(1);
                *failures
            });
            drop(state);
            count
        }

        pub(super) async fn clear_invalid_tokens(&self, key: &PushRegistrationKey) -> bool {
            let mut state = self.state.lock().await;
            let found = state
                .records
                .get_mut(key)
                .map(|(_, failures)| *failures = 0)
                .is_some();
            drop(state);
            found
        }

        pub(super) async fn invalid_token_failures(
            &self,
            key: &PushRegistrationKey,
        ) -> Option<u32> {
            self.state
                .lock()
                .await
                .records
                .get(key)
                .map(|(_, failures)| *failures)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build without `testing` holds exactly one arm: this exhaustive match
    /// names only `Sqlite`, so it stops compiling if `InMemory` is present.
    #[cfg(not(feature = "testing"))]
    #[test]
    fn store_without_testing_has_only_the_sqlite_arm() -> Result<(), Box<dyn std::error::Error>> {
        fn arm_name(store: &PushRegistrationStore) -> &'static str {
            match store {
                PushRegistrationStore::Sqlite(_) => "sqlite",
            }
        }
        let dir = tempfile::tempdir()?;
        let store = PushRegistrationStore::open_sqlite(&dir.path().join("push.db"))?;
        assert_eq!(arm_name(&store), "sqlite");
        Ok(())
    }

    /// Each refusal maps to the relay wire code ADR-004 registers for it.
    #[test]
    fn refusals_map_to_their_relay_wire_codes() {
        assert_eq!(
            PushStoreError::LimitReached { cap: 16 }.wire_code(),
            4064,
            "a new key past the cap"
        );
        assert_eq!(
            PushStoreError::Stale {
                last_accepted: 2,
                offered: 1
            }
            .wire_code(),
            4062
        );
        assert_eq!(
            PushStoreError::TimestampOutOfRange(u64::MAX).wire_code(),
            4062
        );
        assert_eq!(PushStoreError::EmptyRoutingIds.wire_code(), 4060);
        assert_eq!(PushStoreError::Storage(String::new()).wire_code(), 5000);
    }

    #[test]
    fn debug_output_omits_the_token() {
        let record = PushRegistrationRecord {
            registrant: "did:dht:alice".to_owned(),
            platform: PushPlatform::Apns,
            token: b"secret-token-bytes".to_vec(),
            routing_ids: vec![[1; 32]],
            timestamp: 7,
        };
        let shown = format!("{record:?} {:?}", record.key());
        assert!(!shown.contains("secret-token-bytes"), "{shown}");
        assert!(!shown.contains(&format!("{:?}", record.token)), "{shown}");
        assert!(shown.contains("token_len: 18"), "{shown}");
    }
}
