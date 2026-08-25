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

    /// This client cannot mint a `KeyPackage`, because it cannot reach the DID
    /// `#active`/`#agent` key that signs the `KeyPackage` attestation
    /// (§9.7.1).
    ///
    /// §9.7.1 binds an MLS leaf to its DID through an attestation the
    /// identity's custody key signs, and every `Add` verifier rejects a leaf
    /// that carries none. The in-browser driver holds only the ephemeral MLS
    /// `SignatureKeyPair` in wasm memory — [`Signer`](crate::Signer) exposes
    /// `did()` and `signing_key_id()` and no signing operation — so it has no
    /// key to sign with. ADR-057's 2026-08-01 amendment records that a browser
    /// client "joins with an attestation minted by a custody-capable surface"
    /// and couples browser-side issuance to the on-device identity-custody work
    /// of #1980.
    ///
    /// Returning this error is the honest state of that boundary: the driver
    /// refuses to produce a `KeyPackage` no verifier can bind, rather than
    /// producing an unattested one that every adder rejects.
    #[error(
        "this client cannot sign a KeyPackage attestation: no on-device \
         #active/#agent key is reachable (§9.7.1; ADR-057 Amendment 2026-08-01)"
    )]
    AttestationSignerUnavailable,

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

    /// A decrypted frame's content type did not match the relay channel it arrived
    /// on (§9.10.4 defense-in-depth): a tagged `PseudonymAnnouncement` delivered on
    /// a peer-pseudonym (app-data) routing id, or app data delivered on the shared
    /// `context_routing_id` (announcement) channel. The channel is chosen from the
    /// RELAY-supplied routing id, so a hostile/buggy relay re-routing a frame is the
    /// cause; the frame is DROPPED before advancing any per-channel replay floor
    /// (the primary duplicate-delivery guarantee is openmls's per-generation replay
    /// protection — this is defense-in-depth). Benign-dropped by
    /// [`handle_relay_frame`](crate::ScpClient::handle_relay_frame). Surfaced as
    /// `SCP-VALID-7029`.
    #[error("frame content does not match its relay channel (mis-routed; dropped)")]
    ChannelContentMismatch,

    /// The injected [`RelaySink`](crate::RelaySink) failed to enqueue an outbound relay
    /// frame (the WebSocket is closed, a JS exception was thrown, etc.). Best-effort
    /// transport loss — the relay is an untrusted dumb pipe and the message may be
    /// re-driven — NOT a state-corrupting error: by the time a frame is published
    /// the driver's crypto/log state has already advanced and been persisted.
    /// Surfaced as `SCP-TRANS-5005`.
    #[error("transport error: {0}")]
    Transport(String),

    /// An application-data [`send_message`](crate::ScpClient::send_message) was
    /// attempted in an encrypted multi-member context whose peer-pseudonym registry
    /// is still empty — no peer has announced its per-context routing ID yet, so
    /// there is nowhere to fan the ciphertext out to. Fanning out to zero addresses
    /// would silently drop the payload and mask a bidirectional bootstrap deadlock,
    /// so the driver returns this typed, **retryable** error instead: the caller
    /// waits until peers' announcements have been pumped in (via
    /// [`handle_relay_frame`](crate::ScpClient::handle_relay_frame)) and retries.
    /// It is raised *before* the MLS ratchet advances, so no crypto state is
    /// consumed by the failed send. Mirrors the native runtime's
    /// `ContextError::PseudonymRegistryEmpty`. Surfaced as `SCP-CTX-2095`.
    #[error(
        "context '{context_id}' has {member_count} members but no peer has announced a \
         pseudonym yet; retry after peers' announcements are pumped in"
    )]
    PseudonymRegistryEmpty {
        /// The id of the context with no announced peer pseudonyms.
        context_id: String,
        /// The context's current member count (> 1, so peers are expected).
        member_count: usize,
    },

    /// [`join_context_encrypted`](crate::ScpClient::join_context_encrypted) was
    /// called for a context with no retained pending join material — either
    /// [`generate_key_package_for_join`](crate::ScpClient::generate_key_package_for_join)
    /// was never called for it, or a **prior join attempt already consumed it**
    /// (the pending material is single-use per join attempt — see that method's
    /// contract). Retrying after a failed join requires reconstructing the client
    /// from durable storage (which restores the still-present pending blob) or
    /// publishing a fresh `KeyPackage`; the live in-memory material is gone.
    #[error(
        "no pending key package for context '{context_id}'; call generate_key_package_for_join first"
    )]
    NoPendingJoinMaterial {
        /// The id of the context with no pending join material.
        context_id: String,
    },

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
    ///   context, **permanently forfeiting recovery**. It bypasses the driver's
    ///   per-context poison GUARD (distinct from the storage backend's *own* fault
    ///   state), so the poison verdict itself never blocks the discard. If the
    ///   underlying storage instance is itself sticky-faulted — as it typically is
    ///   here, since a context is poisoned precisely because a durable write failed
    ///   (a browser `IndexedDbStorage` whose durable backend is failing throws on
    ///   every op until re-open) — the snapshot delete surfaces that backend fault
    ///   (`SCP-STORAGE-8010`) rather than landing. Clean abandonment then composes
    ///   with a **re-open** over the same durable store: the fresh instance is
    ///   un-faulted, so the retried `close_context` lands the snapshot delete.
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
