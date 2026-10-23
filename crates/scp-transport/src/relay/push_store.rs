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
//! It also keeps, per token, a count of consecutive invalid-token responses
//! from the push service, and removes every registration holding a token
//! whose count reaches [`INVALID_TOKEN_REMOVAL_THRESHOLD`] (§10.7.1
//! `PushDeregistration`: "3 consecutive delivery failures for the same
//! token"). The count is keyed by (platform, token), not by registration key,
//! because the push service judges the token, whoever registered it.
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
//! SCP-315 retypes it to the `Identifier` SCP-308 defines, the type the
//! §22.11.4 wire table names. The store treats it as an opaque string.

use std::path::Path;
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use scp_protocol::discovery::push::PushPlatform;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// The most registrations one registrant may hold on one relay.
///
/// An upsert of a new key for a registrant that already holds this many
/// registrations returns [`PushStoreError::LimitReached`]. An upsert of a key
/// the registrant already holds is never refused by the cap.
pub const MAX_REGISTRATIONS_PER_REGISTRANT: usize = 16;

/// A relay routing ID (32 bytes).
pub type RoutingId = [u8; 32];

/// The consecutive invalid-token responses for one token after which the
/// relay removes every registration holding it (§10.7.1 `PushDeregistration`).
pub const INVALID_TOKEN_REMOVAL_THRESHOLD: u32 = 3;

/// What [`PushRegistrationStore::record_invalid_token`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTokenOutcome {
    /// The token's consecutive count rose to `failures`, still below
    /// [`INVALID_TOKEN_REMOVAL_THRESHOLD`]; every registration stays.
    Counted {
        /// The token's consecutive invalid-token count after this response.
        failures: u32,
    },
    /// The count reached [`INVALID_TOKEN_REMOVAL_THRESHOLD`]: the store
    /// removed every registration holding the token, as
    /// [`PushRegistrationStore::remove`] does for each, and dropped the count.
    Removed {
        /// How many registrations held the token.
        registrations: usize,
    },
    /// No registration holds the token, so nothing was counted. A
    /// deregistration can land between a job's enqueue and its send.
    NotRegistered,
}

/// Where [`PushRegistrationStore::record_invalid_token`] starts the token's
/// consecutive count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountFrom {
    /// Add one to the stored count.
    Stored,
    /// Reset the count to zero and then add one, in the same transaction.
    /// The dispatcher passes it when the token's last outcome was a delivery
    /// whose reset the store failed to write, so that delivery still breaks
    /// the run of consecutive failures (§10.7.1).
    Zero,
}

/// One token to wake: the platform and the token, and nothing else.
pub struct WakeToken {
    /// The push service platform.
    pub platform: PushPlatform,
    /// The platform token, in a zeroizing buffer. Never logged.
    pub token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for WakeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeToken")
            .field("platform", &self.platform)
            .field("token_len", &self.token.len())
            .finish()
    }
}

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
    /// The token's consecutive invalid-token count survives a replacement and
    /// applies to a new registrant of the same token, because the count belongs
    /// to the token and a registration says nothing about whether the token is
    /// valid.
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
            Self::Sqlite(s) => s.upsert(record).await,
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

    /// Deletes the registration under `key` and its routing-ID index entries,
    /// and the token's invalid-token count once no registration holds the
    /// token. The registration's timestamp stays as the key's deregistration
    /// floor. Returns whether a registration existed. The registrant's other
    /// registrations stay in place.
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
    /// - With no registration under `key`, the store still keeps `timestamp`
    ///   as the key's deregistration floor, so a registration under `key` at
    ///   or below `timestamp` that arrives later is stale.
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

    /// Returns each distinct (platform, token) among the registrations that
    /// list `routing_id`, at most `limit` of them. One query reads only the
    /// routing index, so the lookup a publish triggers reads no registrant,
    /// routing-ID list or timestamp.
    ///
    /// When more than `limit` tokens match, the result is a uniform random
    /// sample, drawn afresh on each call, so tokens that sort first (which a
    /// registrant chooses) cannot hold every slot and keep the routing ID's
    /// other devices from ever being woken.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn wake_tokens(
        &self,
        routing_id: &RoutingId,
        limit: usize,
    ) -> Result<Vec<WakeToken>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.wake_tokens(routing_id, limit).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.wake_tokens(routing_id, limit).await),
        }
    }

    /// Counts one invalid-token response from the push service for the
    /// (`platform`, `token`) pair, whoever registered it (§10.7.1).
    ///
    /// In one transaction, the store resets the count first when `count_from`
    /// is [`CountFrom::Zero`], adds one to the token's consecutive count
    /// and, when the count reaches [`INVALID_TOKEN_REMOVAL_THRESHOLD`], removes
    /// every registration holding the token as [`Self::remove`] does (each
    /// key keeps its registration's timestamp as its deregistration floor) and
    /// drops the count. With no registration holding the token it counts
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails; the transaction
    /// then changes nothing.
    pub async fn record_invalid_token(
        &self,
        platform: PushPlatform,
        token: &[u8],
        count_from: CountFrom,
    ) -> Result<InvalidTokenOutcome, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.record_invalid_token(platform, token, count_from).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => s.record_invalid_token(platform, token, count_from).await,
        }
    }

    /// Resets the (`platform`, `token`) pair's consecutive invalid-token count
    /// to zero, as a delivery the push service accepted does. Returns whether
    /// any registration holds the token.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn clear_invalid_tokens(
        &self,
        platform: PushPlatform,
        token: &[u8],
    ) -> Result<bool, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.clear_invalid_tokens(platform, token).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.clear_invalid_tokens(platform, token).await),
        }
    }

    /// Returns the (`platform`, `token`) pair's consecutive invalid-token
    /// count, or `None` when no registration holds the token.
    ///
    /// # Errors
    ///
    /// [`PushStoreError::Storage`] when the database fails.
    pub async fn invalid_token_failures(
        &self,
        platform: PushPlatform,
        token: &[u8],
    ) -> Result<Option<u32>, PushStoreError> {
        match self {
            Self::Sqlite(s) => s.invalid_token_failures(platform, token).await,
            #[cfg(feature = "testing")]
            Self::InMemory(s) => Ok(s.invalid_token_failures(platform, token).await),
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

/// The floor a removal leaves for its key: an accepted deregistration's own
/// timestamp, whether or not the store held anything for the key, because
/// every accepted message bounds later ones (§10.7.1 Freshness); else, for a
/// removal after invalid-token failures, the removed registration's timestamp.
/// `None` writes no floor and leaves any existing one in place. Both arms call
/// this, so they cannot diverge on which removals record a floor.
fn floor_after_removal(deregistered_at: Option<u64>, registered_at: Option<u64>) -> Option<u64> {
    deregistered_at.or(registered_at)
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

/// Removes the registration under `key` inside the caller's transaction, as
/// [`PushRegistrationStore::remove`] and [`PushRegistrationStore::deregister`]
/// describe, and drops the token's invalid-token count once no registration
/// holds the token.
fn remove_in(
    conn: &Connection,
    key: &PushRegistrationKey,
    deregistered_at: Option<u64>,
) -> Result<bool, PushStoreError> {
    if let Some(offered) = deregistered_at {
        check_fresh(last_accepted(conn, key)?, offered)?;
    }
    let registered_at = stored_timestamp(conn, key)?;
    let floor = floor_after_removal(deregistered_at, registered_at);
    delete_index(conn, key)?;
    conn.execute(
        "DELETE FROM push_registrations
         WHERE registrant = ?1 AND platform = ?2 AND token = ?3",
        params![key.registrant, key.platform.tag_byte(), key.token],
    )
    .map_err(|e| storage("delete", &e))?;
    if let Some(floor) = floor {
        conn.execute(
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
    conn.execute(
        "DELETE FROM push_token_failures
         WHERE platform = ?1 AND token = ?2
           AND NOT EXISTS (SELECT 1 FROM push_registrations WHERE platform = ?1 AND token = ?2)",
        params![key.platform.tag_byte(), key.token],
    )
    .map_err(|e| storage("drop token count", &e))?;
    Ok(registered_at.is_some())
}

/// Every registration key holding (`platform`, `token`), through
/// `idx_push_registrations_by_token`.
fn keys_for_token(
    conn: &Connection,
    platform: PushPlatform,
    token: &[u8],
) -> Result<Vec<PushRegistrationKey>, PushStoreError> {
    let mut stmt = conn
        .prepare_cached(
            "SELECT registrant FROM push_registrations
             WHERE platform = ?1 AND token = ?2
             ORDER BY registrant",
        )
        .map_err(|e| storage("prepare token keys", &e))?;
    let rows = stmt
        .query_map(params![platform.tag_byte(), token], |row| {
            row.get::<_, String>(0)
        })
        .map_err(|e| storage("query token keys", &e))?;
    let mut keys = Vec::new();
    for row in rows {
        keys.push(PushRegistrationKey {
            registrant: row.map_err(|e| storage("read token key", &e))?,
            platform,
            token: token.to_vec(),
        });
    }
    Ok(keys)
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
                 PRIMARY KEY (registrant, platform, token)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS idx_push_registrations_by_token
                 ON push_registrations (platform, token);
             CREATE TABLE IF NOT EXISTS push_token_failures (
                 platform INTEGER NOT NULL,
                 token BLOB NOT NULL,
                 failures INTEGER NOT NULL,
                 PRIMARY KEY (platform, token)
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

    /// Runs `f` on the connection on tokio's blocking pool, so no `SQLite`
    /// call runs on an async worker thread. The connection lock is held until
    /// `f` returns, even when the caller stops waiting, so a transaction
    /// always commits or rolls back whole.
    async fn with_conn<T, F>(&self, f: F) -> Result<T, PushStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, PushStoreError> + Send + 'static,
    {
        let mut conn = Arc::clone(&self.conn).lock_owned().await;
        tokio::task::spawn_blocking(move || f(&mut conn))
            .await
            .map_err(|e| PushStoreError::Storage(format!("store task failed: {e}")))?
    }

    async fn upsert(
        &self,
        record: PushRegistrationRecord,
    ) -> Result<UpsertOutcome, PushStoreError> {
        self.with_conn(move |conn| upsert_in(conn, &record)).await
    }

    async fn get(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<PushRegistrationRecord>, PushStoreError> {
        let key = key.clone();
        self.with_conn(move |conn| {
            let Some(timestamp) = stored_timestamp(conn, &key)? else {
                return Ok(None);
            };
            let routing_ids = routing_ids_for(conn, &key)?;
            Ok(Some(PushRegistrationRecord {
                registrant: key.registrant,
                platform: key.platform,
                token: key.token,
                routing_ids,
                timestamp,
            }))
        })
        .await
    }

    /// `deregistered_at` is a deregistration's timestamp, or `None` for a
    /// removal after invalid-token failures, which keeps the registration's
    /// own timestamp as the floor.
    async fn remove(
        &self,
        key: &PushRegistrationKey,
        deregistered_at: Option<u64>,
    ) -> Result<bool, PushStoreError> {
        let key = key.clone();
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage("begin", &e))?;
            let existed = remove_in(&tx, &key, deregistered_at)?;
            tx.commit().map_err(|e| storage("commit", &e))?;
            Ok(existed)
        })
        .await
    }

    async fn accepted_timestamp(
        &self,
        key: &PushRegistrationKey,
    ) -> Result<Option<u64>, PushStoreError> {
        let key = key.clone();
        self.with_conn(move |conn| last_accepted(conn, &key)).await
    }

    async fn prune_deregistrations(&self, accepted_before: u64) -> Result<usize, PushStoreError> {
        self.with_conn(move |conn| {
            // A bound above `i64::MAX` exceeds every floor the store can hold.
            i64::try_from(accepted_before)
                .map_or_else(
                    |_| conn.execute("DELETE FROM push_deregistrations", []),
                    |bound| {
                        conn.execute(
                            "DELETE FROM push_deregistrations WHERE timestamp < ?1",
                            params![bound],
                        )
                    },
                )
                .map_err(|e| storage("prune floors", &e))
        })
        .await
    }

    async fn tokens_for_routing_id(
        &self,
        routing_id: &RoutingId,
    ) -> Result<Vec<PushRegistrationRecord>, PushStoreError> {
        let routing_id = *routing_id;
        self.with_conn(move |conn| {
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
                let timestamp = stored_timestamp(conn, &key)?.ok_or_else(|| {
                    PushStoreError::Storage("index entry without registration".to_owned())
                })?;
                let routing_ids = routing_ids_for(conn, &key)?;
                out.push(PushRegistrationRecord {
                    registrant: key.registrant,
                    platform: key.platform,
                    token: key.token,
                    routing_ids,
                    timestamp,
                });
            }
            Ok(out)
        })
        .await
    }

    async fn wake_tokens(
        &self,
        routing_id: &RoutingId,
        limit: usize,
    ) -> Result<Vec<WakeToken>, PushStoreError> {
        let routing_id = *routing_id;
        // A limit above `i64::MAX` bounds nothing a table can hold.
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT platform, token FROM (
                         SELECT DISTINCT platform, token FROM push_routing_index
                         WHERE routing_id = ?1
                     )
                     ORDER BY random()
                     LIMIT ?2",
                )
                .map_err(|e| storage("prepare wake lookup", &e))?;
            let rows = stmt
                .query_map(params![routing_id.as_slice(), limit], |row| {
                    Ok((row.get::<_, u8>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| storage("query wake lookup", &e))?;
            let mut out = Vec::new();
            for row in rows {
                let (tag, token) = row.map_err(|e| storage("read wake lookup", &e))?;
                out.push(WakeToken {
                    platform: platform_from_tag(tag)?,
                    token: Zeroizing::new(token),
                });
            }
            Ok(out)
        })
        .await
    }

    async fn record_invalid_token(
        &self,
        platform: PushPlatform,
        token: &[u8],
        count_from: CountFrom,
    ) -> Result<InvalidTokenOutcome, PushStoreError> {
        let token = Zeroizing::new(token.to_vec());
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage("begin", &e))?;
            let keys = keys_for_token(&tx, platform, &token)?;
            if keys.is_empty() {
                return Ok(InvalidTokenOutcome::NotRegistered);
            }
            if count_from == CountFrom::Zero {
                tx.execute(
                    "DELETE FROM push_token_failures WHERE platform = ?1 AND token = ?2",
                    params![platform.tag_byte(), token.as_slice()],
                )
                .map_err(|e| storage("reset token failures", &e))?;
            }
            let failures = tx
                .query_row(
                    "INSERT INTO push_token_failures (platform, token, failures) VALUES (?1, ?2, 1)
                     ON CONFLICT (platform, token) DO UPDATE SET failures = failures + 1
                     RETURNING failures",
                    params![platform.tag_byte(), token.as_slice()],
                    |row| row.get::<_, u32>(0),
                )
                .map_err(|e| storage("count token failure", &e))?;
            let outcome = if failures >= INVALID_TOKEN_REMOVAL_THRESHOLD {
                for key in &keys {
                    remove_in(&tx, key, None)?;
                }
                InvalidTokenOutcome::Removed {
                    registrations: keys.len(),
                }
            } else {
                InvalidTokenOutcome::Counted { failures }
            };
            tx.commit().map_err(|e| storage("commit", &e))?;
            Ok(outcome)
        })
        .await
    }

    async fn clear_invalid_tokens(
        &self,
        platform: PushPlatform,
        token: &[u8],
    ) -> Result<bool, PushStoreError> {
        let token = Zeroizing::new(token.to_vec());
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| storage("begin", &e))?;
            tx.execute(
                "DELETE FROM push_token_failures WHERE platform = ?1 AND token = ?2",
                params![platform.tag_byte(), token.as_slice()],
            )
            .map_err(|e| storage("clear token failures", &e))?;
            let held = !keys_for_token(&tx, platform, &token)?.is_empty();
            tx.commit().map_err(|e| storage("commit", &e))?;
            Ok(held)
        })
        .await
    }

    async fn invalid_token_failures(
        &self,
        platform: PushPlatform,
        token: &[u8],
    ) -> Result<Option<u32>, PushStoreError> {
        let token = Zeroizing::new(token.to_vec());
        self.with_conn(move |conn| {
            if keys_for_token(conn, platform, &token)?.is_empty() {
                return Ok(None);
            }
            let count = conn
                .query_row(
                    "SELECT failures FROM push_token_failures WHERE platform = ?1 AND token = ?2",
                    params![platform.tag_byte(), token.as_slice()],
                    |row| row.get::<_, u32>(0),
                )
                .optional()
                .map_err(|e| storage("read token failures", &e))?;
            Ok(Some(count.unwrap_or(0)))
        })
        .await
    }
}

/// The SQLite upsert, in one immediate transaction on `conn`.
fn upsert_in(
    conn: &mut Connection,
    record: &PushRegistrationRecord,
) -> Result<UpsertOutcome, PushStoreError> {
    let key = record.key();
    let timestamp = timestamp_to_column(record.timestamp)?;
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
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// In-memory arm (testing only)
// ---------------------------------------------------------------------------

#[cfg(feature = "testing")]
pub use in_memory::InMemoryPushStore;

#[cfg(feature = "testing")]
mod in_memory {
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::sync::Arc;

    use scp_protocol::discovery::push::PushPlatform;
    use tokio::sync::Mutex;
    use zeroize::Zeroizing;

    use super::{
        CountFrom, INVALID_TOKEN_REMOVAL_THRESHOLD, InvalidTokenOutcome,
        MAX_REGISTRATIONS_PER_REGISTRANT, PushRegistrationKey, PushRegistrationRecord,
        PushStoreError, RoutingId, UpsertOutcome, WakeToken, check_fresh, floor_after_removal,
    };

    /// A (platform, token) pair, the key of the invalid-token count.
    type TokenId = (PushPlatform, Vec<u8>);

    fn token_id(key: &PushRegistrationKey) -> TokenId {
        (key.platform, key.token.clone())
    }

    #[derive(Debug, Default)]
    struct InMemoryState {
        records: HashMap<PushRegistrationKey, PushRegistrationRecord>,
        by_routing_id: HashMap<RoutingId, HashSet<PushRegistrationKey>>,
        /// The registrants holding each token, ordered like the SQLite arm's
        /// `ORDER BY registrant`.
        by_token: HashMap<TokenId, BTreeSet<String>>,
        per_registrant: HashMap<String, usize>,
        /// Deregistration floors; a key never holds a record and a floor.
        floors: HashMap<PushRegistrationKey, u64>,
        /// Consecutive invalid-token counts; a token holds one only while a
        /// registration holds the token.
        token_failures: HashMap<TokenId, u32>,
    }

    impl InMemoryState {
        fn last_accepted(&self, key: &PushRegistrationKey) -> Option<u64> {
            self.records
                .get(key)
                .map(|record| record.timestamp)
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

        fn holders(&self, id: &TokenId) -> bool {
            self.by_token.get(id).is_some_and(|r| !r.is_empty())
        }

        /// Mirrors the SQLite arm's `remove_in`.
        fn remove(
            &mut self,
            key: &PushRegistrationKey,
            deregistered_at: Option<u64>,
        ) -> Result<bool, PushStoreError> {
            if let Some(offered) = deregistered_at {
                check_fresh(self.last_accepted(key), offered)?;
            }
            let Some(record) = self.records.remove(key) else {
                if let Some(floor) = floor_after_removal(deregistered_at, None) {
                    self.floors.insert(key.clone(), floor);
                }
                return Ok(false);
            };
            self.unindex(key, &record.routing_ids);
            let id = token_id(key);
            if let Some(registrants) = self.by_token.get_mut(&id) {
                registrants.remove(&key.registrant);
                if registrants.is_empty() {
                    self.by_token.remove(&id);
                }
            }
            if !self.holders(&id) {
                self.token_failures.remove(&id);
            }
            if let Some(count) = self.per_registrant.get_mut(&key.registrant) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.per_registrant.remove(&key.registrant);
                }
            }
            if let Some(floor) = floor_after_removal(deregistered_at, Some(record.timestamp)) {
                self.floors.insert(key.clone(), floor);
            }
            Ok(true)
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
                .map(|stored| stored.routing_ids.clone());
            let outcome = if let Some(routing_ids) = previous {
                let outcome = if routing_ids == record.routing_ids {
                    UpsertOutcome::Refreshed
                } else {
                    state.unindex(&key, &routing_ids);
                    state.index(&key, &record.routing_ids);
                    UpsertOutcome::Replaced
                };
                state.records.insert(key, record);
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
                state
                    .by_token
                    .entry(token_id(&key))
                    .or_default()
                    .insert(key.registrant.clone());
                state.floors.remove(&key);
                state.records.insert(key, record);
                UpsertOutcome::Inserted
            };
            drop(state);
            Ok(outcome)
        }

        pub(super) async fn get(
            &self,
            key: &PushRegistrationKey,
        ) -> Option<PushRegistrationRecord> {
            self.state.lock().await.records.get(key).cloned()
        }

        /// Mirrors `SqlitePushStore::remove`.
        pub(super) async fn remove(
            &self,
            key: &PushRegistrationKey,
            deregistered_at: Option<u64>,
        ) -> Result<bool, PushStoreError> {
            self.state.lock().await.remove(key, deregistered_at)
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
                .filter_map(|key| state.records.get(key).cloned())
                .collect();
            drop(state);
            records
        }

        /// Mirrors `SqlitePushStore::wake_tokens`.
        pub(super) async fn wake_tokens(
            &self,
            routing_id: &RoutingId,
            limit: usize,
        ) -> Vec<WakeToken> {
            let state = self.state.lock().await;
            let mut tokens: Vec<WakeToken> = state
                .by_routing_id
                .get(routing_id)
                .map(|keys| {
                    keys.iter()
                        .map(|key| WakeToken {
                            platform: key.platform,
                            token: Zeroizing::new(key.token.clone()),
                        })
                        .collect()
                })
                .unwrap_or_default();
            drop(state);
            tokens.sort_unstable_by(|a, b| {
                (a.platform.tag_byte(), a.token.as_slice())
                    .cmp(&(b.platform.tag_byte(), b.token.as_slice()))
            });
            tokens.dedup_by(|a, b| a.platform == b.platform && a.token == b.token);
            rand::seq::SliceRandom::shuffle(tokens.as_mut_slice(), &mut rand::thread_rng());
            tokens.truncate(limit);
            tokens
        }

        /// Mirrors `SqlitePushStore::record_invalid_token`; the one lock is
        /// the transaction.
        pub(super) async fn record_invalid_token(
            &self,
            platform: PushPlatform,
            token: &[u8],
            count_from: CountFrom,
        ) -> Result<InvalidTokenOutcome, PushStoreError> {
            let mut state = self.state.lock().await;
            let id = (platform, token.to_vec());
            let Some(registrants) = state.by_token.get(&id).cloned() else {
                return Ok(InvalidTokenOutcome::NotRegistered);
            };
            if count_from == CountFrom::Zero {
                state.token_failures.remove(&id);
            }
            let failures = {
                let count = state.token_failures.entry(id).or_insert(0);
                *count = count.saturating_add(1);
                *count
            };
            if failures < INVALID_TOKEN_REMOVAL_THRESHOLD {
                return Ok(InvalidTokenOutcome::Counted { failures });
            }
            for registrant in &registrants {
                let key = PushRegistrationKey {
                    registrant: registrant.clone(),
                    platform,
                    token: token.to_vec(),
                };
                state.remove(&key, None)?;
            }
            drop(state);
            Ok(InvalidTokenOutcome::Removed {
                registrations: registrants.len(),
            })
        }

        pub(super) async fn clear_invalid_tokens(
            &self,
            platform: PushPlatform,
            token: &[u8],
        ) -> bool {
            let mut state = self.state.lock().await;
            let id = (platform, token.to_vec());
            state.token_failures.remove(&id);
            let held = state.holders(&id);
            drop(state);
            held
        }

        pub(super) async fn invalid_token_failures(
            &self,
            platform: PushPlatform,
            token: &[u8],
        ) -> Option<u32> {
            let state = self.state.lock().await;
            let id = (platform, token.to_vec());
            let count = state
                .holders(&id)
                .then(|| state.token_failures.get(&id).copied().unwrap_or(0));
            drop(state);
            count
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
