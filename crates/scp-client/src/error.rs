//! Error types for the SCP participant driver.
//!
//! [`ClientError`] is the single error surfaced by every [`crate::ScpClient`]
//! operation. It wraps the shared lower-layer errors ([`scp_mls::MlsError`],
//! [`scp_protocol::crypto::sender_keys::SenderKeyError`],
//! [`scp_event_log::EventLogError`]) via `#[from]` so the driver bodies can use
//! `?` without re-deriving error taxonomies.

use scp_event_log::EventLogError;
use scp_mls::MlsError;
use scp_protocol::crypto::sender_keys::SenderKeyError;

/// Errors produced by the SCP participant driver.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// An MLS group operation failed (create/add/join/encrypt/decrypt/commit).
    #[error("MLS error: {0}")]
    Mls(#[from] MlsError),

    /// A sender-key (§9.16) layer operation failed.
    #[error("sender key error: {0}")]
    SenderKey(#[from] SenderKeyError),

    /// An event-log append or proof operation failed.
    #[error("event log error: {0}")]
    EventLog(#[from] EventLogError),

    /// A TLS-codec (de)serialization of an MLS wire object failed.
    #[error("MLS wire codec error: {0}")]
    Codec(String),

    /// The requested context is not known to this client.
    #[error("unknown context: {0}")]
    UnknownContext(String),

    /// A context with the requested id already exists in this client.
    #[error("context already exists: {0}")]
    ContextAlreadyExists(String),

    /// A received Commit carried a membership change the Slice 2 participant
    /// driver does not converge — specifically a member removal, for which
    /// there is no convergent removal-leaf transport yet. The driver returns
    /// this rather than silently merging and diverging its event log from the
    /// committer's (ADR-057 Slice 2 scope).
    #[error("unsupported membership change: {0}")]
    UnsupportedMembershipChange(String),

    /// A driver invariant was violated (e.g. missing sender key for a member
    /// that is in the membership set, or a malformed driver argument).
    #[error("driver error: {0}")]
    Driver(String),

    /// The injected [`Storage`](crate::Storage) backend itself failed — a
    /// `get`/`put`/`delete`/`list_keys` returned an error (quota exhausted,
    /// transaction aborted, backend unavailable). Surfaced as `SCP-STORAGE-8010`.
    /// Distinct from a corrupt-but-readable blob: this is an I/O-level fault, not
    /// a content problem. A `put` failure raised here from a state-mutating op
    /// also **poisons** the context (see [`ClientError::ContextPoisoned`]): the
    /// live state advanced but the durable snapshot did not.
    #[error("storage backend error: {0}")]
    StorageBackend(String),

    /// A persisted snapshot could not be trusted for restore: it failed to
    /// deserialize, carried an unknown format version, embedded a different
    /// context id than its storage key, or failed the §9.9.3 checkpoint compare
    /// (the event-log root recomputed from the restored state does not equal the
    /// root the snapshot recorded — a torn/corrupt/truncated event stream). The
    /// in-blob root binds the event log only and is not tamper-resistant, so
    /// whole-blob authenticity rests on the backend's authenticated encryption at
    /// rest. Restore fails closed rather than resuming a context from
    /// inconsistent state (ADR-057 crash/consistency consequence, §17.6).
    /// Surfaced as `SCP-STORAGE-8011`.
    ///
    /// REDACTION SCOPE: when this wraps a `MessagePack` (`rmp_serde`) decode
    /// failure, the embedded message reports the codec's *type/position*
    /// diagnostic (e.g. "invalid type … at offset N"), NOT the raw blob bytes —
    /// so it does not leak persisted key material. This is the honest bound on
    /// the redaction claim: the guarantee covers the lower-layer `Display` text
    /// this variant forwards, and `rmp_serde`'s `Display` is structural, not a
    /// byte dump.
    #[error("corrupt snapshot: {0}")]
    StorageCorrupt(String),

    /// A persisted snapshot belongs to a different identity than the client
    /// attempting to restore it (its bound `owner_did` does not match this
    /// client's DID). Restoring another identity's MLS/sender-key state under
    /// this client would be an identity confusion, so it fails closed. Surfaced
    /// as `SCP-STORAGE-8012`.
    #[error("snapshot identity mismatch: {0}")]
    StorageIdentityMismatch(String),

    /// A context was **poisoned** by a storage write that failed *after* its
    /// in-memory state had already advanced irreversibly (the MLS ratchet cannot
    /// be un-advanced, and a new event-log leaf was already appended). Durable
    /// storage now holds a strictly-older snapshot than the live in-memory state,
    /// so the two have diverged: continuing to operate the live context would
    /// hand out ciphertext / event-log leaves that no peer and no reopened tab
    /// will ever see, permanently forking this member's Merkle root from the
    /// group's. Every operation that would advance or expose the diverged state
    /// therefore refuses it. There are two mutually-exclusive terminal paths:
    /// - **RECOVER** — discard this client and build a fresh one via
    ///   [`ScpClient::new`](crate::ScpClient::new) over the same storage; restore
    ///   rebuilds the context from its last *durable* snapshot, unpoisoned by
    ///   construction. The durable snapshot is preserved.
    /// - **ABANDON** — call [`close_context`](crate::ScpClient::close_context), the
    ///   deliberate discard path: it deletes the durable snapshot and drops the
    ///   context, **permanently forfeiting recovery**. It is the one op that does
    ///   not go through the poison guard, so a diverged context can always be
    ///   closed cleanly.
    ///
    /// Surfaced as `SCP-STORAGE-8013`.
    #[error(
        "context '{context_id}' is poisoned: a storage write failed after its \
         in-memory state advanced irreversibly, so durable and live state have \
         diverged; discard this client and reconstruct via ScpClient::new to \
         resume from the last durable snapshot"
    )]
    ContextPoisoned {
        /// The id of the diverged context.
        context_id: String,
    },
}
