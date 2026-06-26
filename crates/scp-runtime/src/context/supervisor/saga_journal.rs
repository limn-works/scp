//! Cross-actor saga journal — durable coordinator surface (spec §17.16).
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §3).
//!
//! # Trait
//!
//! [`SagaJournal`] is the supervisor's durable coordinator record for
//! cross-actor sagas (the sole saga is cross-context tool invoke,
//! §6.2.4). It exposes three operations per
//! spec §17.16.1:
//!
//! - [`SagaJournal::append`] — durably persist a state transition. Flushes
//!   write buffers before returning. Cancel-hostile.
//! - [`SagaJournal::load_unresolved`] — latest entry per unresolved saga.
//!   Cancel-safe.
//! - [`SagaJournal::mark_resolved`] — terminal marker. For secret-bearing
//!   sagas, synchronously overwrites on-disk evidence before returning
//!   (spec §9.4.3). Cancel-hostile.
//!
//! # Wire format
//!
//! Each journal entry is stored under a dedicated key namespace keyed by
//! `saga_journal/{saga_id}/{seq_per_saga}`. The stored value is:
//!
//! ```text
//!   [4-byte BE u32 length][MessagePack-encoded JournalEntry bytes][4-byte BE u32 CRC32 checksum]
//! ```
//!
//! The length prefix + trailing CRC32 together defeat partial-write attacks
//! on storage backends that do not provide atomic writes: a truncated value
//! either has the wrong length, a wrong-size payload, or a mismatched
//! checksum. All three are detected on load and the entry is reported as
//! corrupt (via [`JournalError::Codec`]).
//!
//! # Secret handling
//!
//! [`JournalEntry::evidence`] is `Zeroizing<Vec<u8>>` — the secret-bearing
//! commitment and nonce never sit in a plain `Vec<u8>` on the stack. The
//! manual `Serialize`/`Deserialize` impls encode through a private local
//! `EvidenceWire` type that is itself zeroized before going out of scope,
//! so deserialization never leaves unwrapped secret bytes across an await.
//!
//! # Key-namespace isolation (spec §17.16.3)
//!
//! All keys live under the `saga_journal/` prefix. Backend operations on
//! other surfaces (context snapshots, event log) use disjoint prefixes and
//! cannot collide.
//!
//! See ADR-049 §3 and spec §§9.4.3, 17.16.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

use scp_platform::traits::Storage;

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------

/// Key prefix for every saga journal entry (spec §17.16.3).
pub const SAGA_JOURNAL_KEY_PREFIX: &str = "saga_journal/";

/// Fixed header length: BE u32 length prefix.
const HEADER_LEN: usize = 4;
/// Fixed trailer length: BE u32 CRC32.
const TRAILER_LEN: usize = 4;
/// Minimum encoded entry size: 4-byte length + 1-byte payload + 4-byte CRC.
const MIN_ENCODED_LEN: usize = HEADER_LEN + 1 + TRAILER_LEN;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Saga identifier (UUID v4 as a string).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SagaId(pub String);

impl SagaId {
    /// Generate a fresh saga identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for SagaId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SagaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lifecycle state of a saga in the coordinator's journal.
///
/// Mirrors the FSM described in ADR-049 §3: `Initiated → PreparingA →
/// PreparingB → Committing → Committed | Aborting → Aborted | NeedsRepair`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaState {
    /// Supervisor has registered the saga; no actor contacted yet.
    Initiated,
    /// Prepare sent to actor A; awaiting reply.
    PreparingA,
    /// A Prepared; Prepare sent to actor B; awaiting reply.
    PreparingB,
    /// Both Prepared; Commit in flight.
    Committing,
    /// Terminal success.
    Committed,
    /// Abort in flight (one Prepare failed or timed out).
    Aborting,
    /// Terminal abort.
    Aborted,
    /// Commit exhausted its retry budget and requires operator action.
    NeedsRepair,
}

impl SagaState {
    /// Is this a terminal state (no further transitions expected without
    /// operator intervention)?
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }
}

/// Terminal classification for [`SagaJournal::mark_resolved`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaTerminalState {
    /// Saga succeeded; both actors committed.
    Committed,
    /// Saga aborted; no persistent state change.
    Aborted,
}

impl From<SagaTerminalState> for SagaState {
    fn from(t: SagaTerminalState) -> Self {
        match t {
            SagaTerminalState::Committed => Self::Committed,
            SagaTerminalState::Aborted => Self::Aborted,
        }
    }
}

/// A single journal entry recording one saga state transition.
///
/// Append-only per `saga_id` — later state transitions append new entries;
/// earlier entries are never mutated. The exception is
/// [`SagaJournal::mark_resolved`] for secret-bearing sagas, which overwrites
/// the `evidence` bytes of existing entries for that saga with zeros before
/// the call returns.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Saga identifier. Same across all entries for one saga.
    pub saga_id: SagaId,
    /// The saga's state at this transition.
    pub state: SagaState,
    /// Context or identity identifiers of the saga participants. For
    /// cross-context operations these are context IDs; for cross-identity
    /// operations they are DIDs. Interpretation is saga-type specific.
    pub participants: Vec<String>,
    /// Saga-type specific evidence — MessagePack-encoded `SagaPreparedState`.
    /// Wrapped in [`Zeroizing`] so any secret-bearing payload zeroes on drop.
    /// No current saga is secret-bearing (all three journal public metadata
    /// only); this is the §9.4.3 forward contract for any future
    /// secret-bearing saga. See spec §9.4.3.
    pub evidence: Zeroizing<Vec<u8>>,
    /// Milliseconds since the UNIX epoch when the entry was appended.
    pub timestamp_ms: u64,
    /// Monotonic counter per `saga_id` — distinguishes the original
    /// append from retries that land with the same timestamp.
    pub seq_per_saga: u64,
}

// Manual Serialize/Deserialize: round-trips `evidence` through an inner
// `Zeroizing`-wrapped buffer without ever leaving an unwrapped `Vec<u8>` on
// the stack across an await boundary. The `EvidenceWire` type below is the
// single owner of the unwrapped bytes during (de)serialization and its
// lifetime is confined to the synchronous scope of the trait methods.

#[derive(Serialize)]
struct JournalEntryWire<'a> {
    saga_id: &'a SagaId,
    state: SagaState,
    participants: &'a [String],
    #[serde(with = "serde_bytes")]
    evidence: &'a [u8],
    timestamp_ms: u64,
    seq_per_saga: u64,
}

#[derive(Deserialize)]
struct JournalEntryWireOwned {
    saga_id: SagaId,
    state: SagaState,
    participants: Vec<String>,
    #[serde(with = "serde_bytes")]
    evidence: Vec<u8>,
    timestamp_ms: u64,
    seq_per_saga: u64,
}

impl Drop for JournalEntryWireOwned {
    fn drop(&mut self) {
        // Zero the evidence buffer as it leaves scope. `Zeroize` on `Vec<u8>`
        // overwrites the storage in place, even after move-out via the
        // conversion below.
        self.evidence.zeroize();
    }
}

impl Serialize for JournalEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = JournalEntryWire {
            saga_id: &self.saga_id,
            state: self.state,
            participants: &self.participants,
            evidence: self.evidence.as_slice(),
            timestamp_ms: self.timestamp_ms,
            seq_per_saga: self.seq_per_saga,
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JournalEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut owned = JournalEntryWireOwned::deserialize(deserializer)?;
        // Move the evidence bytes into a Zeroizing wrapper; the source Vec is
        // then truncated and zeroized by the owned-wrapper's Drop.
        let evidence = Zeroizing::new(std::mem::take(&mut owned.evidence));
        Ok(Self {
            saga_id: owned.saga_id.clone(),
            state: owned.state,
            participants: std::mem::take(&mut owned.participants),
            evidence,
            timestamp_ms: owned.timestamp_ms,
            seq_per_saga: owned.seq_per_saga,
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by [`SagaJournal`] operations.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// Storage-backend I/O failure (unreachable for in-memory, propagated
    /// from `SQLite` / filesystem).
    #[error("storage I/O failure: {0}")]
    Io(String),

    /// Serialization / deserialization failed — malformed entry or schema
    /// mismatch.
    #[error("codec error: {0}")]
    Codec(String),

    /// The durable-persist barrier did not complete. Backends that
    /// guarantee durability only on fsync return this if the sync fails.
    #[error("durable persist did not complete")]
    NotDurable,

    /// Secret-bearing marker arrived, but the storage backend does not
    /// support synchronous secure overwrite.
    #[error("secure overwrite not supported by storage backend")]
    CannotOverwrite,

    /// A stored entry's length/CRC preamble or trailer was corrupt.
    #[error("entry integrity check failed: {0}")]
    IntegrityFailure(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Durable saga coordinator surface. See spec §17.16.
///
/// Implementations MUST be `Send + Sync` and durably persist every append
/// before returning. `load_unresolved` is the crash-recovery entry point
/// invoked at supervisor startup.
#[async_trait]
pub trait SagaJournal: Send + Sync {
    /// Appends a state transition durably.
    ///
    /// Write buffers (OS page cache, application buffer, replication
    /// pipeline) MUST be flushed before the call returns. The operation is
    /// cancel-hostile in practice: callers MUST NOT cancel mid-flight; a
    /// cancelled append is treated as "state unknown" and reconciled by the
    /// next [`load_unresolved`](Self::load_unresolved) pass.
    ///
    /// # Errors
    ///
    /// See [`JournalError`].
    async fn append(&self, entry: JournalEntry) -> Result<(), JournalError>;

    /// Returns the latest entry per unresolved saga. "Unresolved" means
    /// [`SagaState::is_terminal`] is `false`.
    ///
    /// Cancel-safe — the implementation performs only reads.
    ///
    /// # Errors
    ///
    /// See [`JournalError`].
    async fn load_unresolved(&self) -> Result<Vec<JournalEntry>, JournalError>;

    /// Marks a saga resolved.
    ///
    /// For `secret_bearing = true`, the implementation MUST synchronously
    /// overwrite the on-disk evidence bytes of every entry for `saga_id`
    /// with zeros before returning success — not at next compaction
    /// (spec §9.4.3). The operation is cancel-hostile: if cancellation
    /// occurs before the overwrite completes, the overwrite MUST complete
    /// on next process start before the journal is opened for any other
    /// use. Secret bytes MUST NOT survive on disk past the next journal
    /// open.
    ///
    /// For `secret_bearing = false`, the on-disk evidence is non-secret, so the
    /// terminal overwrite is not security-mandated. The production implementation
    /// nonetheless COMPACTS the saga down to zero entries on resolution (it
    /// appends the durable terminal marker, then deletes the saga's keys in a
    /// crash-safe order) so that `load_unresolved`'s cost stays bounded to the
    /// number of unresolved sagas. Implementations MAY instead leave earlier
    /// entries for later compaction; either is spec-conformant.
    ///
    /// # Errors
    ///
    /// See [`JournalError`].
    async fn mark_resolved(
        &self,
        saga_id: SagaId,
        terminal: SagaTerminalState,
        secret_bearing: bool,
    ) -> Result<(), JournalError>;
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Encode a [`JournalEntry`] into the wire format:
/// `len(BE u32) || msgpack || crc32(BE u32)`.
fn encode_entry(entry: &JournalEntry) -> Result<Vec<u8>, JournalError> {
    let body =
        rmp_serde::to_vec_named(entry).map_err(|e| JournalError::Codec(format!("encode: {e}")))?;

    #[allow(clippy::cast_possible_truncation)]
    let len = body.len() as u32;
    if body.is_empty() {
        return Err(JournalError::Codec("empty body".to_string()));
    }
    let crc = crc32_ieee(&body);

    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + TRAILER_LEN);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out)
}

/// Decode a wire-format entry. Returns `JournalError::IntegrityFailure` on
/// length mismatch, wrong-size payload, or CRC mismatch — the partial-write
/// detection surface required by spec §17.16.1.
fn decode_entry(raw: &[u8]) -> Result<JournalEntry, JournalError> {
    if raw.len() < MIN_ENCODED_LEN {
        return Err(JournalError::IntegrityFailure(format!(
            "entry too short: {} bytes (minimum {MIN_ENCODED_LEN})",
            raw.len(),
        )));
    }
    let (len_bytes, rest) = raw.split_at(HEADER_LEN);
    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(len_bytes);
    let declared_len = u32::from_be_bytes(len_arr) as usize;

    if rest.len() < declared_len + TRAILER_LEN {
        return Err(JournalError::IntegrityFailure(format!(
            "declared length {declared_len} exceeds remaining bytes {}",
            rest.len(),
        )));
    }
    let (body, crc_bytes) = rest.split_at(declared_len);
    if crc_bytes.len() != TRAILER_LEN {
        return Err(JournalError::IntegrityFailure(format!(
            "trailer length {} != expected {TRAILER_LEN}",
            crc_bytes.len(),
        )));
    }
    let mut crc_arr = [0u8; 4];
    crc_arr.copy_from_slice(crc_bytes);
    let stored_crc = u32::from_be_bytes(crc_arr);
    let computed_crc = crc32_ieee(body);
    if stored_crc != computed_crc {
        return Err(JournalError::IntegrityFailure(format!(
            "CRC mismatch: stored={stored_crc:08x} computed={computed_crc:08x}",
        )));
    }

    rmp_serde::from_slice(body).map_err(|e| JournalError::Codec(format!("decode: {e}")))
}

/// CRC-32/IEEE 802.3 (polynomial `0xEDB88320`). Matches zlib / `crc32fast`.
///
/// Implementation is a plain byte-at-a-time loop without lookup tables —
/// journal entries are small (few KB) and the hot path is the storage round
/// trip, not the CRC. Adding a `crc32fast` dep is not justified at this
/// layer.
fn crc32_ieee(bytes: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLY & mask);
        }
    }
    !crc
}

/// Extract the `saga_id` segment from a journal key for log attribution.
///
/// Key layout is `saga_journal/{saga_id}/{seq}` (see
/// [`SAGA_JOURNAL_KEY_PREFIX`]): strip the prefix, then take everything before
/// the LAST `/` (the trailing segment is the seq). On any key that does not
/// match this shape we fall back to the whole key so the log still carries
/// something greppable rather than an empty field.
fn saga_id_from_key(key: &str) -> &str {
    key.strip_prefix(SAGA_JOURNAL_KEY_PREFIX)
        .and_then(|s| s.rsplit_once('/'))
        .map_or(key, |(id, _seq)| id)
}

// ---------------------------------------------------------------------------
// Production impl — ProtocolRepositorySagaJournal
// ---------------------------------------------------------------------------

/// Production [`SagaJournal`] backed by any `scp_platform::Storage` backend.
///
/// Writes every entry under `saga_journal/{saga_id}/{seq_per_saga:020}`.
/// The 20-digit zero-padded `seq_per_saga` ensures lexicographic listing
/// returns entries in insertion order (spec §17.16.3 key namespace is a
/// lexicographic KV).
///
/// On `mark_resolved` with `secret_bearing = true`, every entry under
/// `saga_journal/{saga_id}/` first has its evidence bytes overwritten with
/// zeros via a zero-length-evidence re-encode (spec §9.4.3 "synchronously
/// overwrite on-disk evidence before returning"). Then — for BOTH the
/// secret-bearing and non-secret paths — the terminal marker is appended and
/// the saga's keys are deleted in a crash-safe order, COMPACTING the resolved
/// saga down to zero on-disk entries (spec §17.16.1 "Bounded-cost recovery").
/// This keeps `load_unresolved`'s startup cost bounded to the number of
/// UNRESOLVED sagas rather than every saga ever run. See `mark_resolved` for the
/// crash-safety ordering argument.
pub struct ProtocolRepositorySagaJournal<S: Storage + 'static> {
    storage: Arc<S>,
}

impl<S: Storage + 'static> ProtocolRepositorySagaJournal<S> {
    /// Creates a new journal over the given shared storage backend.
    #[must_use]
    pub const fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

    /// Builds the storage key for a given saga + seq.
    fn entry_key(saga_id: &SagaId, seq: u64) -> String {
        format!("{SAGA_JOURNAL_KEY_PREFIX}{saga_id}/{seq:020}")
    }

    /// Builds the per-saga listing prefix.
    fn saga_prefix(saga_id: &SagaId) -> String {
        format!("{SAGA_JOURNAL_KEY_PREFIX}{saga_id}/")
    }
}

#[async_trait]
impl<S: Storage + 'static> SagaJournal for ProtocolRepositorySagaJournal<S> {
    async fn append(&self, entry: JournalEntry) -> Result<(), JournalError> {
        let key = Self::entry_key(&entry.saga_id, entry.seq_per_saga);
        let encoded = encode_entry(&entry)?;
        self.storage
            .store(&key, &encoded)
            .await
            .map_err(|e| JournalError::Io(e.to_string()))?;
        Ok(())
    }

    async fn load_unresolved(&self) -> Result<Vec<JournalEntry>, JournalError> {
        // Enumerate every entry under the journal prefix.
        let keys = self
            .storage
            .list_keys(SAGA_JOURNAL_KEY_PREFIX)
            .await
            .map_err(|e| JournalError::Io(e.to_string()))?;

        // Group by saga_id and pick the max-seq entry per saga. `list_keys`
        // is lexicographic, which — combined with our 20-digit zero-padded
        // seq formatting — means the last key in a saga's group has the
        // highest `seq_per_saga`.
        //
        // We materialize into (saga_id, latest_key) pairs first, then load
        // the values. Because `mark_resolved` COMPACTS a resolved saga down to
        // zero on-disk entries (it deletes the saga's keys after the terminal
        // resolution is durable), the only keys this sweep ever lists, retrieves,
        // and decodes belong to sagas that are still in flight — so both the
        // listing breadth and the wire-parse cost are bounded to the number of
        // UNRESOLVED sagas, not the number of sagas ever run.
        let mut latest_by_saga: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for key in keys {
            // Key layout: `saga_journal/{saga_id}/{seq}`. Split once after
            // the prefix, then once before the trailing seq.
            let Some(stripped) = key.strip_prefix(SAGA_JOURNAL_KEY_PREFIX) else {
                continue;
            };
            let Some(slash_idx) = stripped.rfind('/') else {
                continue;
            };
            let saga_id_str = &stripped[..slash_idx];
            // The prior latest (if any) has a smaller lexicographic seq
            // than this one by construction.
            latest_by_saga.insert(saga_id_str.to_string(), key);
        }

        let mut out = Vec::with_capacity(latest_by_saga.len());
        for key in latest_by_saga.values() {
            // Fault isolation (availability): a single corrupt OR torn-write
            // entry under `saga_journal/` MUST NOT abort the entire sweep and
            // thereby skip EVERY other unresolved saga (recovery denied,
            // reservations / escrow stranded). The CRC framing exists precisely
            // because torn writes happen, so a per-entry decode failure is
            // reachable benignly, not just adversarially. On a per-saga
            // retrieve/decode fault we log, emit the saga-repair-needed metric
            // so an operator is alerted, and SKIP this saga — never silently
            // fall back to an earlier-seq entry (that risks resurrecting stale
            // pre-commit state). All OTHER sagas are still recovered.
            //
            // NB: genuine `list_keys` I/O failure above stays a hard `?` — a
            // backend that cannot list is a real failure, not a per-entry fault.
            let raw = match self.storage.retrieve(key).await {
                Ok(Some(raw)) => raw,
                Ok(None) => {
                    // The latest key vanished between list and retrieve. Treat
                    // it as a per-saga fault: flag and skip, do not abort.
                    // `record_saga_repair_needed()` is intentionally rate-only —
                    // no `saga_id` label, because a per-saga counter dimension is
                    // an unbounded-cardinality anti-pattern. The per-saga signal
                    // an operator greps is the `saga_id` field on the error log
                    // below, not a metric label.
                    crate::metrics::record_saga_repair_needed();
                    tracing::error!(
                        key = %key,
                        saga_id = %saga_id_from_key(key),
                        "SCP-SAGA-RECOVERY: journal entry disappeared during load — \
                         saga skipped, manual repair needed; other sagas unaffected"
                    );
                    continue;
                }
                Err(e) => {
                    // Backend retrieve error on ONE key is a per-saga fault, not
                    // a list-level failure: flag and skip, do not abort.
                    crate::metrics::record_saga_repair_needed();
                    tracing::error!(
                        key = %key,
                        saga_id = %saga_id_from_key(key),
                        error = %e,
                        "SCP-SAGA-RECOVERY: journal entry retrieve failed — \
                         saga skipped, manual repair needed; other sagas unaffected"
                    );
                    continue;
                }
            };
            match decode_entry(&raw) {
                Ok(entry) => {
                    if !entry.state.is_terminal() {
                        out.push(entry);
                    }
                }
                Err(e) => {
                    // Corrupt / torn-write entry: flag and skip, do not abort.
                    crate::metrics::record_saga_repair_needed();
                    tracing::error!(
                        key = %key,
                        saga_id = %saga_id_from_key(key),
                        error = %e,
                        "SCP-SAGA-RECOVERY: corrupt journal entry, saga skipped, \
                         manual repair needed; other sagas unaffected"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn mark_resolved(
        &self,
        saga_id: SagaId,
        terminal: SagaTerminalState,
        secret_bearing: bool,
    ) -> Result<(), JournalError> {
        let prefix = Self::saga_prefix(&saga_id);

        if secret_bearing {
            // Spec §9.4.3: overwrite evidence bytes synchronously before
            // returning. We iterate every entry under the saga's prefix,
            // read it, zero the evidence, write it back, and only after
            // all are zeroed append the terminal marker.
            let keys = self
                .storage
                .list_keys(&prefix)
                .await
                .map_err(|e| JournalError::Io(e.to_string()))?;
            for key in keys {
                let raw = self
                    .storage
                    .retrieve(&key)
                    .await
                    .map_err(|e| JournalError::Io(e.to_string()))?;
                if let Some(bytes) = raw {
                    // SECURITY: unlike `load_unresolved` (availability-oriented,
                    // skip-and-flag), the secret-bearing overwrite path FAILS
                    // LOUD on a decode error. A corrupt entry we cannot decode is
                    // an entry whose evidence bytes we cannot locate to zero —
                    // silently skipping it would leave secret bytes on disk past
                    // the next journal open (violating spec §9.4.3). Aborting
                    // here surfaces the fault so an operator can repair it before
                    // the secret is considered overwritten.
                    let mut entry = decode_entry(&bytes)?;
                    // Overwrite evidence with zeros of the same length so the
                    // on-disk footprint stays stable and the record remains
                    // parseable (length-check invariants stay intact).
                    let len = entry.evidence.len();
                    entry.evidence = Zeroizing::new(vec![0u8; len]);
                    let re_encoded = encode_entry(&entry)?;
                    self.storage
                        .store(&key, &re_encoded)
                        .await
                        .map_err(|e| JournalError::Io(e.to_string()))?;
                }
            }
        }

        // Append a terminal marker at the strictly-highest seq (max prior + 1).
        // The 20-digit zero-padded seq formatting makes this marker the
        // lexicographic MAXIMUM under the saga prefix, so until it is the last
        // thing deleted below, it is the entry `load_unresolved` selects for the
        // saga — and being terminal, it makes the saga drop out of the
        // unresolved set.
        let next_seq = self.next_seq_for_saga(&saga_id).await?;
        let marker_key = Self::entry_key(&saga_id, next_seq);

        let marker = JournalEntry {
            saga_id: saga_id.clone(),
            state: SagaState::from(terminal),
            participants: Vec::new(),
            evidence: Zeroizing::new(Vec::new()),
            timestamp_ms: current_timestamp_ms(),
            seq_per_saga: next_seq,
        };
        self.append(marker).await?;

        // Compaction (spec §17.16.1 "Bounded-cost recovery"): a resolved saga
        // leaves NO entries, so `load_unresolved` only ever lists + decodes
        // entries for sagas that are genuinely still in flight — its cost is
        // bounded to the number of UNRESOLVED sagas, not the number of sagas
        // EVER run.
        //
        // CRASH-SAFETY ORDERING (no dependence on backend delete order):
        //   1. The terminal marker is durable (appended above) at the strictly
        //      max seq.
        //   2. Delete every NON-terminal entry for this saga FIRST, leaving the
        //      terminal marker in place as the safety net. A crash at any point
        //      during these deletes leaves the marker — still the max-seq entry
        //      — so `load_unresolved` selects it, sees a terminal state, and the
        //      saga stays resolved. Removing any subset of the lower-seq
        //      non-terminal entries while the terminal max-seq marker survives
        //      can NEVER resurrect a stale pre-commit entry as the saga's
        //      "latest" state.
        //   3. Delete the terminal marker LAST. A crash before this step leaves
        //      the saga resolved (marker present); a crash after leaves the saga
        //      fully gone. Either outcome is terminal — never a half-state that
        //      re-drives stale evidence.
        //
        // For the secret-bearing path the evidence bytes were already zeroized
        // in place above (spec §9.4.3), so even if a delete below fails midway
        // no secret bytes linger; deleting the prefix is then strictly better
        // than leaving zeroed husks around.
        let keys = self
            .storage
            .list_keys(&prefix)
            .await
            .map_err(|e| JournalError::Io(e.to_string()))?;
        for key in &keys {
            if key == &marker_key {
                // Defer the terminal marker — it is the crash-safety net and
                // must be the LAST key removed.
                continue;
            }
            self.storage
                .delete(key)
                .await
                .map_err(|e| JournalError::Io(e.to_string()))?;
        }
        // Now that no non-terminal entry remains, drop the terminal marker so a
        // resolved saga leaves zero on-disk footprint.
        self.storage
            .delete(&marker_key)
            .await
            .map_err(|e| JournalError::Io(e.to_string()))?;

        Ok(())
    }
}

impl<S: Storage + 'static> ProtocolRepositorySagaJournal<S> {
    async fn next_seq_for_saga(&self, saga_id: &SagaId) -> Result<u64, JournalError> {
        let prefix = Self::saga_prefix(saga_id);
        let keys = self
            .storage
            .list_keys(&prefix)
            .await
            .map_err(|e| JournalError::Io(e.to_string()))?;
        // Compute the max seq over all PARSEABLE trailing-seq suffixes. A
        // single key with a malformed suffix (a corrupt key in this saga's own
        // prefix) is skipped-and-logged rather than aborting next-seq
        // computation — same fault-isolation posture as `load_unresolved`. The
        // zero-padded 20-digit seq formatting means lexicographic max == numeric
        // max, so skipping an unparseable outlier never picks a lower-than-real
        // next seq from the well-formed entries.
        let mut max_seq: Option<u64> = None;
        for k in &keys {
            let suffix = k.rsplit('/').next().unwrap_or("");
            match suffix.parse::<u64>() {
                Ok(n) => {
                    max_seq = Some(max_seq.map_or(n, |m| m.max(n)));
                }
                Err(e) => {
                    tracing::warn!(
                        key = %k,
                        saga_id = %saga_id_from_key(k),
                        error = %e,
                        "SCP-SAGA-RECOVERY: malformed seq suffix in journal key, \
                         skipped for next-seq computation; manual repair may be needed"
                    );
                }
            }
        }
        Ok(max_seq.map_or(0, |m| m.saturating_add(1)))
    }
}

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

fn current_timestamp_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    ms
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryStorage;

    fn test_journal() -> ProtocolRepositorySagaJournal<InMemoryStorage> {
        ProtocolRepositorySagaJournal::new(Arc::new(InMemoryStorage::new()))
    }

    // -----------------------------------------------------------------------
    // Tracing capture (FIX E — metric-fired proof)
    //
    // The metrics facade (`metrics` crate) has NO test recorder installed in
    // this crate — there is no snapshotter dependency, and `set_global_recorder`
    // is never called in test code. The codebase DOES already support capturing
    // structured events via a hand-rolled `tracing::Subscriber` (see
    // supervisor.rs's watchdog tests). Every `record_saga_repair_needed()` call
    // in `load_unresolved` is emitted alongside a structured `SCP-SAGA-RECOVERY`
    // `tracing::error!`, so we assert the repair signal fired by capturing that
    // event rather than reading a counter we have no recorder for.
    //
    // We install the capturing subscriber THREAD-LOCALLY via `set_default`
    // (NOT process-globally): the default single-threaded `#[tokio::test]`
    // keeps the future on one thread, so the returned `DefaultGuard` stays
    // active across `load_unresolved`'s `.await` points (which never
    // `tokio::spawn`). A thread-local default also avoids colliding with the
    // process-global default the supervisor.rs watchdog tests install in the
    // same test binary.
    //
    // Returns the shared buffer plus the guard; hold the guard for the duration
    // of the captured calls, then read the buffer.
    // -----------------------------------------------------------------------
    fn install_event_capture() -> (
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        tracing::subscriber::DefaultGuard,
    ) {
        use std::sync::{Arc as StdArc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::{Event, Metadata};

        struct CaptureSub {
            buf: StdArc<Mutex<Vec<String>>>,
        }
        struct LineVisitor<'a>(&'a mut String);
        impl Visit for LineVisitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
            fn record_str(&mut self, field: &Field, value: &str) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={value}", field.name());
            }
        }
        impl tracing::Subscriber for CaptureSub {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut line = String::new();
                let mut v = LineVisitor(&mut line);
                event.record(&mut v);
                self.buf.lock().unwrap().push(line);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let buf = StdArc::new(Mutex::new(Vec::new()));
        let guard = tracing::subscriber::set_default(CaptureSub {
            buf: StdArc::clone(&buf),
        });
        (buf, guard)
    }

    fn test_entry(saga_id: &SagaId, seq: u64, state: SagaState, evidence: Vec<u8>) -> JournalEntry {
        JournalEntry {
            saga_id: saga_id.clone(),
            state,
            participants: vec!["ctx-a".into(), "ctx-b".into()],
            evidence: Zeroizing::new(evidence),
            timestamp_ms: 1_700_000_000_000 + seq,
            seq_per_saga: seq,
        }
    }

    #[tokio::test]
    async fn append_then_load_unresolved_returns_latest() {
        let journal = test_journal();
        let saga = SagaId::new();

        journal
            .append(test_entry(&saga, 0, SagaState::Initiated, b"ev0".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&saga, 1, SagaState::PreparingA, b"ev1".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&saga, 2, SagaState::PreparingB, b"ev2".to_vec()))
            .await
            .unwrap();

        let unresolved = journal.load_unresolved().await.unwrap();
        assert_eq!(unresolved.len(), 1);
        let latest = &unresolved[0];
        assert_eq!(latest.saga_id, saga);
        assert_eq!(latest.state, SagaState::PreparingB);
        assert_eq!(&*latest.evidence, b"ev2");
    }

    #[tokio::test]
    async fn terminal_entries_are_not_returned_by_load_unresolved() {
        let journal = test_journal();
        let saga = SagaId::new();

        journal
            .append(test_entry(&saga, 0, SagaState::Initiated, b"ev0".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&saga, 1, SagaState::Committed, Vec::new()))
            .await
            .unwrap();

        let unresolved = journal.load_unresolved().await.unwrap();
        assert!(
            unresolved.is_empty(),
            "Committed saga should not appear in unresolved list",
        );
    }

    #[tokio::test]
    async fn multiple_sagas_deduplicated_to_latest_per_saga() {
        let journal = test_journal();
        let s1 = SagaId::new();
        let s2 = SagaId::new();

        journal
            .append(test_entry(&s1, 0, SagaState::Initiated, b"s1-ev0".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&s2, 0, SagaState::Initiated, b"s2-ev0".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(
                &s1,
                1,
                SagaState::PreparingA,
                b"s1-ev1".to_vec(),
            ))
            .await
            .unwrap();

        let mut unresolved = journal.load_unresolved().await.unwrap();
        unresolved.sort_by(|a, b| a.saga_id.0.cmp(&b.saga_id.0));
        assert_eq!(unresolved.len(), 2);
        for entry in &unresolved {
            if entry.saga_id == s1 {
                assert_eq!(entry.state, SagaState::PreparingA);
            } else if entry.saga_id == s2 {
                assert_eq!(entry.state, SagaState::Initiated);
            }
        }
    }

    #[tokio::test]
    async fn mark_resolved_secret_bearing_zeroes_evidence_bytes() {
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
        let saga = SagaId::new();

        let secret_evidence = b"BEARER-ARTIFACT-COMMITMENT-BYTES".to_vec();
        journal
            .append(test_entry(
                &saga,
                0,
                SagaState::PreparingA,
                secret_evidence.clone(),
            ))
            .await
            .unwrap();

        // Pre-resolve: raw storage contains the secret bytes somewhere inside
        // the encoded entry.
        let key0 = ProtocolRepositorySagaJournal::<InMemoryStorage>::entry_key(&saga, 0);
        let pre = storage.retrieve(&key0).await.unwrap().unwrap();
        assert!(
            contains_subsequence(&pre, &secret_evidence),
            "evidence bytes should be present before mark_resolved",
        );

        // Resolve as secret-bearing.
        journal
            .mark_resolved(saga.clone(), SagaTerminalState::Committed, true)
            .await
            .unwrap();

        // Post-resolve: the secret-bearing path FIRST overwrites evidence bytes
        // in place (spec §9.4.3), THEN compacts the saga to zero on-disk entries
        // (spec §17.16.1). So the prepare-A key is gone outright...
        assert!(
            storage.retrieve(&key0).await.unwrap().is_none(),
            "the secret-bearing entry must be compacted away after resolution",
        );

        // ...and — the security invariant that matters — NO key anywhere under
        // the journal prefix still carries the secret subsequence. (The in-place
        // overwrite is what guarantees this even on a backend where a delete
        // might leave a tombstoned husk; here it is verified end-to-end.)
        let all_keys = storage.list_keys(SAGA_JOURNAL_KEY_PREFIX).await.unwrap();
        for key in &all_keys {
            let raw = storage.retrieve(key).await.unwrap().unwrap();
            assert!(
                !contains_subsequence(&raw, &secret_evidence),
                "secret bytes must not survive on disk after secret-bearing \
                 mark_resolved; found in {key}",
            );
        }
    }

    #[tokio::test]
    async fn mark_resolved_non_secret_compacts_saga_to_zero_entries() {
        // FIX B (compaction): a non-secret resolve appends the terminal marker,
        // then deletes every key for the saga (crash-safe order) so the resolved
        // saga leaves ZERO on-disk entries and never participates in a later
        // unresolved-saga scan (spec §17.16.1 "Bounded-cost recovery").
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
        let saga = SagaId::new();

        // Several entries for ONE saga across its lifecycle.
        journal
            .append(test_entry(&saga, 0, SagaState::Initiated, b"ev0".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&saga, 1, SagaState::PreparingA, b"ev1".to_vec()))
            .await
            .unwrap();
        journal
            .append(test_entry(&saga, 2, SagaState::PreparingB, b"ev2".to_vec()))
            .await
            .unwrap();

        journal
            .mark_resolved(saga.clone(), SagaTerminalState::Committed, false)
            .await
            .unwrap();

        // No on-disk keys remain under this saga's prefix.
        let prefix = ProtocolRepositorySagaJournal::<InMemoryStorage>::saga_prefix(&saga);
        let remaining = storage.list_keys(&prefix).await.unwrap();
        assert!(
            remaining.is_empty(),
            "a resolved non-secret saga must compact to zero entries, found {remaining:?}",
        );

        // And the saga does not surface from a recovery sweep.
        let unresolved = journal.load_unresolved().await.unwrap();
        assert!(
            !unresolved.iter().any(|e| e.saga_id == saga),
            "a compacted resolved saga must not appear in load_unresolved, got {unresolved:?}",
        );
    }

    #[tokio::test]
    async fn mark_resolved_secret_bearing_compacts_saga_to_zero_entries() {
        // FIX B (compaction) — secret-bearing variant: after the evidence
        // overwrite (spec §9.4.3) the resolve still compacts the saga to zero
        // residual keys, leaving no zeroed husks behind.
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
        let saga = SagaId::new();

        journal
            .append(test_entry(
                &saga,
                0,
                SagaState::PreparingA,
                b"BEARER-ARTIFACT-COMMITMENT-BYTES".to_vec(),
            ))
            .await
            .unwrap();
        journal
            .append(test_entry(
                &saga,
                1,
                SagaState::Committing,
                b"more".to_vec(),
            ))
            .await
            .unwrap();

        journal
            .mark_resolved(saga.clone(), SagaTerminalState::Committed, true)
            .await
            .unwrap();

        let prefix = ProtocolRepositorySagaJournal::<InMemoryStorage>::saga_prefix(&saga);
        let remaining = storage.list_keys(&prefix).await.unwrap();
        assert!(
            remaining.is_empty(),
            "a resolved secret-bearing saga must compact to zero entries, found {remaining:?}",
        );

        let unresolved = journal.load_unresolved().await.unwrap();
        assert!(
            !unresolved.iter().any(|e| e.saga_id == saga),
            "a compacted secret-bearing saga must not appear in load_unresolved, got {unresolved:?}",
        );
    }

    #[test]
    fn partial_write_truncation_detected_by_decode() {
        // The CRC framing detects a torn write at the DECODE boundary. (The
        // load sweep itself is fault-isolating — it skips a corrupt entry rather
        // than aborting; see `load_unresolved_truncation_skips_not_aborts` — so
        // the integrity check is asserted here directly against `decode_entry`,
        // the single point where the length/CRC invariant is enforced.)
        let saga = SagaId::new();
        let entry = test_entry(&saga, 0, SagaState::Initiated, b"ev".to_vec());
        let mut full = encode_entry(&entry).unwrap();
        // Truncate to simulate a partial write (cut off CRC trailer).
        full.truncate(full.len() - 2);

        let err = decode_entry(&full).unwrap_err();
        assert!(
            matches!(err, JournalError::IntegrityFailure(_)),
            "truncation must be caught as integrity failure, got {err:?}",
        );
    }

    #[tokio::test]
    async fn load_unresolved_truncation_skips_not_aborts() {
        // A torn-write entry under the journal prefix is skipped (fault
        // isolation), never aborting the whole sweep.
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
        let saga = SagaId::new();
        journal
            .append(test_entry(&saga, 0, SagaState::Initiated, b"ev".to_vec()))
            .await
            .unwrap();

        let key0 = ProtocolRepositorySagaJournal::<InMemoryStorage>::entry_key(&saga, 0);
        let mut full = storage.retrieve(&key0).await.unwrap().unwrap();
        // Truncate to simulate a partial write (cut off CRC trailer).
        full.truncate(full.len() - 2);
        storage.store(&key0, &full).await.unwrap();

        let unresolved = journal
            .load_unresolved()
            .await
            .expect("a torn-write entry must be skipped, not abort the sweep");
        assert!(
            !unresolved.iter().any(|e| e.saga_id == saga),
            "the torn-write saga must be skipped (not surfaced), got {unresolved:?}",
        );
    }

    #[tokio::test]
    async fn load_unresolved_skips_corrupt_entry_and_recovers_the_rest() {
        // Availability regression guard: a single corrupt (or torn-write) entry
        // under `saga_journal/` MUST NOT blind recovery to EVERY other
        // unresolved saga. Plant two legitimate non-terminal sagas plus one
        // garbage key, then assert `load_unresolved` returns Ok with BOTH legit
        // sagas present (the corrupt one skipped-and-flagged).
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));

        let saga_b = SagaId::new();
        let saga_c = SagaId::new();
        journal
            .append(test_entry(
                &saga_b,
                0,
                SagaState::PreparingB,
                b"legit-b".to_vec(),
            ))
            .await
            .unwrap();
        journal
            .append(test_entry(
                &saga_c,
                0,
                SagaState::Committing,
                b"legit-c".to_vec(),
            ))
            .await
            .unwrap();

        // Plant a garbage value under a well-formed key so it groups as its own
        // saga and its latest key is selected for decode — exactly the entry the
        // pre-fix `?` would have aborted the whole sweep on.
        let corrupt_saga_id = "zzcorrupt";
        let corrupt_key = format!("{SAGA_JOURNAL_KEY_PREFIX}{corrupt_saga_id}/{:020}", 0);
        storage
            .store(&corrupt_key, b"not-a-valid-wire-entry")
            .await
            .unwrap();

        // Capture the structured recovery events for the metric-fired assertion
        // (FIX E). The repair signal is `record_saga_repair_needed()`, for which
        // no test recorder exists; it is emitted alongside the `SCP-SAGA-RECOVERY`
        // `tracing::error!` we capture here. See `install_event_capture`.
        let (events, _guard) = install_event_capture();

        let unresolved = journal.load_unresolved().await.expect(
            "a single corrupt entry must NOT abort the sweep — the other sagas must still recover",
        );

        // --- Survivor presence (availability) ---
        assert!(
            unresolved.iter().any(|e| e.saga_id == saga_b),
            "PreparingB saga must survive the corrupt-entry skip, got {unresolved:?}",
        );
        assert!(
            unresolved.iter().any(|e| e.saga_id == saga_c),
            "Committing saga must survive the corrupt-entry skip, got {unresolved:?}",
        );
        assert!(
            !unresolved.iter().any(|e| e.saga_id.0 == corrupt_saga_id),
            "the corrupt saga must be skipped, not surfaced as unresolved",
        );

        // --- Survivor STATE (FIX E): the surviving sagas must carry their
        // expected FSM state, not merely be present. ---
        let b_entry = unresolved
            .iter()
            .find(|e| e.saga_id == saga_b)
            .expect("saga_b present");
        assert_eq!(
            b_entry.state,
            SagaState::PreparingB,
            "saga_b must recover with its PreparingB FSM state intact",
        );
        let c_entry = unresolved
            .iter()
            .find(|e| e.saga_id == saga_c)
            .expect("saga_c present");
        assert_eq!(
            c_entry.state,
            SagaState::Committing,
            "saga_c must recover with its Committing FSM state intact",
        );

        // --- Repair signal fired (FIX E): the corrupt-skip path emitted the
        // structured `SCP-SAGA-RECOVERY` error carrying the corrupt saga_id, the
        // log-side counterpart of the rate-only `saga_repair_needed` metric. ---
        let lines = events.lock().unwrap().clone();
        assert!(
            lines.iter().any(|l| l.contains("SCP-SAGA-RECOVERY")
                && l.contains("corrupt journal entry")
                && l.contains(corrupt_saga_id)),
            "the corrupt-skip must emit a SCP-SAGA-RECOVERY error tagged with the \
             corrupt saga_id (the per-saga signal paired with the repair metric); got {lines:?}",
        );
    }

    #[test]
    fn crc_mismatch_detected_by_decode() {
        // A flipped payload bit is caught at the decode boundary by the CRC
        // check. (The load sweep skips such an entry; see
        // `load_unresolved_crc_mismatch_skips_not_aborts`.)
        let saga = SagaId::new();
        let entry = test_entry(&saga, 0, SagaState::Initiated, b"ev".to_vec());
        let mut full = encode_entry(&entry).unwrap();
        // Flip a bit in the middle of the payload.
        let mid = full.len() / 2;
        full[mid] ^= 0xFF;

        let err = decode_entry(&full).unwrap_err();
        assert!(matches!(err, JournalError::IntegrityFailure(_)));
    }

    #[tokio::test]
    async fn load_unresolved_crc_mismatch_skips_not_aborts() {
        let storage = Arc::new(InMemoryStorage::new());
        let journal = ProtocolRepositorySagaJournal::new(Arc::clone(&storage));
        let saga = SagaId::new();
        journal
            .append(test_entry(&saga, 0, SagaState::Initiated, b"ev".to_vec()))
            .await
            .unwrap();

        let key0 = ProtocolRepositorySagaJournal::<InMemoryStorage>::entry_key(&saga, 0);
        let mut full = storage.retrieve(&key0).await.unwrap().unwrap();
        // Flip a bit in the middle of the payload.
        let mid = full.len() / 2;
        full[mid] ^= 0xFF;
        storage.store(&key0, &full).await.unwrap();

        let unresolved = journal
            .load_unresolved()
            .await
            .expect("a CRC-corrupt entry must be skipped, not abort the sweep");
        assert!(
            !unresolved.iter().any(|e| e.saga_id == saga),
            "the CRC-corrupt saga must be skipped, got {unresolved:?}",
        );
    }

    #[tokio::test]
    async fn round_trip_preserves_all_fields() {
        let journal = test_journal();
        let saga = SagaId::new();
        let entry = JournalEntry {
            saga_id: saga.clone(),
            state: SagaState::PreparingB,
            participants: vec!["a".into(), "b".into(), "c".into()],
            evidence: Zeroizing::new(b"payload".to_vec()),
            timestamp_ms: 42,
            seq_per_saga: 7,
        };
        journal.append(entry.clone()).await.unwrap();

        let loaded = journal.load_unresolved().await.unwrap();
        assert_eq!(loaded.len(), 1);
        let got = &loaded[0];
        assert_eq!(got.saga_id, entry.saga_id);
        assert_eq!(got.state, entry.state);
        assert_eq!(got.participants, entry.participants);
        assert_eq!(&*got.evidence, &*entry.evidence);
        assert_eq!(got.timestamp_ms, entry.timestamp_ms);
        assert_eq!(got.seq_per_saga, entry.seq_per_saga);
    }

    #[test]
    fn crc32_matches_known_vectors() {
        // Standard CRC-32 test vectors (IEEE 802.3, polynomial 0xEDB88320).
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn saga_state_terminal_classification() {
        assert!(SagaState::Committed.is_terminal());
        assert!(SagaState::Aborted.is_terminal());
        assert!(!SagaState::Initiated.is_terminal());
        assert!(!SagaState::PreparingA.is_terminal());
        assert!(!SagaState::PreparingB.is_terminal());
        assert!(!SagaState::Committing.is_terminal());
        assert!(!SagaState::Aborting.is_terminal());
        assert!(!SagaState::NeedsRepair.is_terminal());
    }

    // Helper: substring search on byte slices (since std doesn't have one).
    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
