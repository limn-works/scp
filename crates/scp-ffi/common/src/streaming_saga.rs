//! Bridge-agnostic pieces of the §5.4.5 cross-context streaming-saga FFI
//! surface (SCP-OUT-047).
//!
//! Shared by the three native bridges (`PyO3`, `napi-rs`, `UniFFI`) so their
//! streaming-saga open / poll / recover wiring cannot drift — the same "one
//! place, no drift" rationale as [`crate::outlet_stream_credit`] and
//! [`crate::saga_errors`].
//!
//! What lives here is only what is genuinely free of bridge-specific types:
//!
//! - [`StreamingSagaEntry`] — the per-instance registry value for one live
//!   cross-context streaming saga. Holds the runtime's plaintext operator-signed
//!   chunk receiver (returned promptly at the Commit-transition, AC1), plus the
//!   durable `saga_id`, the operating context id, the pinned invoker DID, and
//!   the stream `request_id`. No `PyObject` / napi / `UniFFI` type appears, so
//!   all three bridges store the identical shape.
//! - [`serialize_saga_chunk`] — the one chunk-serialization + terminal-detection
//!   step every bridge's `poll_next` performs, so the JSON encoding and the
//!   "terminal ⇒ evict" boundary are byte-identical across bridges.
//! - [`drive_recover_truncated_close`] — the key-bearing in-session
//!   reconnect/repair driver body (SCP-OUT-046 #136 AC7 / ADR-049 §3a). It
//!   performs the ADR-056
//!   chokepoint id conversion (decode-64-hex-else-SHA256) THE SAME WAY on every
//!   bridge before reaching
//!   [`Supervisor::recover_streaming_saga_truncated_close`] — so no bridge can
//!   double-hash the target id and key the wrong actor.
//!
//! The bridge-specific `open` path (custody signer resolution, per-instance
//! identity/context lookup, GIL/error plumbing) stays per-bridge — it touches
//! types this crate cannot name.

use std::sync::Arc;

use scp_core::context::actor::commands::SigningKeyBytes;
use scp_core::context::outlets::stream::OutletStreamChunk;
use scp_core::context::supervisor::{SagaError, SagaId, Supervisor};
use tokio::sync::{Mutex, mpsc};

/// One live cross-context streaming saga tracked in a bridge instance.
///
/// Stored in the per-instance `outlet_streaming_saga_registry` (NEVER a global —
/// the same handle-affinity discipline as the same-context stream registry).
///
/// The `receiver` yields A's plaintext, unmodified, operator-signed
/// [`OutletStreamChunk`]s verbatim (the bridge never re-signs and introduces no
/// new send-sequence at the plaintext hand-off, §5.4.5). Re-encryption of each
/// still-operator-signed chunk for A's OTHER members is a downstream SDK
/// consumer concern — it composes `poll_next` with the EXISTING A-context MLS
/// application-message transport (§5.4.5:568); this bridge introduces no new
/// primitive for it.
pub struct StreamingSagaEntry {
    /// The runtime's plaintext operator-signed chunk receiver, handed to the
    /// bridge PROMPTLY at the Commit-transition (AC1). Behind an async lock so a
    /// `poll_next` parked in `recv()` clones the `Arc` out of the registry shard
    /// guard before awaiting (never holding a `DashMap` ref across `.await`).
    pub receiver: Arc<Mutex<mpsc::Receiver<OutletStreamChunk>>>,
    /// The durable saga id — the operator-repair handle the in-session
    /// reconnect/repair truncated-close keys on, and the registry key (as its
    /// string form).
    pub saga_id: SagaId,
    /// The OPERATING context B (hex) that hosts the streaming outlet
    /// registration — the context whose Active Signing Key seals the receipt at
    /// a truncated-close recovery.
    pub target_context_id: String,
    /// The invoker DID pinned at open (the §5.4.5 `invoker_did`).
    pub invoker_did: String,
    /// The stream's 16-byte `request_id` pinned at open.
    pub request_id: [u8; 16],
}

/// Serializes one forwarded [`OutletStreamChunk`] to its JSON wire bytes.
///
/// Also reports whether it is a TERMINAL chunk (`End` / `Error { terminal:
/// true }`).
///
/// Every bridge's `poll_next` calls this so the encoding and the "terminal ⇒
/// evict the registry entry" boundary are identical across `PyO3` / napi /
/// `UniFFI`. A terminal chunk is still RETURNED to the caller (it carries the
/// clean stream end / error terminal); the bridge evicts the entry AFTER
/// returning it so a run-to-terminal caller that never performs the trailing
/// `None`-drain cannot leak the entry.
///
/// # Errors
///
/// Returns the underlying [`serde_json::Error`] if the chunk cannot be
/// serialized (a runtime invariant violation — chunks are always serializable).
pub fn serialize_saga_chunk(
    chunk: &OutletStreamChunk,
) -> Result<(Vec<u8>, bool), serde_json::Error> {
    let terminal = chunk.payload.is_terminal();
    let bytes = serde_json::to_vec(chunk)?;
    Ok((bytes, terminal))
}

/// The key-bearing streaming-saga in-session reconnect/repair truncated-close
/// driver (SCP-OUT-046 #136 AC7).
///
/// This is IN-SESSION reconnect/repair: each bridge's recover surface calls it to
/// re-drive a seal that stalled or went `NeedsRepair` while THIS bridge process
/// is still ALIVE (e.g. a client reconnects to the same live node). The
/// per-instance saga registry that routes to it is in-memory, so this driver does
/// NOT survive a process/node restart — cross-restart recovery replays the
/// durable saga journal via a separate operator path (§17.16), not this surface.
///
/// Given the OPERATING context B's Active Signing Key (resolved per-call from
/// custody by the caller — the runtime holds none autonomously, ADR-006), it
/// seals B's durable prefix and resolves the saga `Committed` WITHOUT re-opening
/// the stream or re-invoking the executor.
///
/// This is the SHARED body so every bridge performs the ADR-056 chokepoint id
/// conversion identically: `target_context_id` is a context-id STRING, decoded
/// to `[u8; 32]` via [`context_id_to_bytes`](scp_core::context::state::context_id_to_bytes)
/// (decode-64-hex-else-SHA256). The producer keys the actor via
/// `hex::encode(bytes)`, so a raw SHA-256 of a 64-hex id would double-hash and
/// miss the actor — pinning the conversion here closes that drift across
/// bridges.
///
/// The `signing_key` is the Active Signing Key resolved per-call from custody —
/// NEVER envelope-asserted.
///
/// # Errors
///
/// Propagates the [`SagaError`] from
/// [`Supervisor::recover_streaming_saga_truncated_close`] — notably
/// [`SagaError::NeedsRepair`] (carrying the durable `saga_id`) when the target
/// is not resident or the seal dispatch fails, so the saga stays unresolved for
/// a later retry.
pub async fn drive_recover_truncated_close(
    supervisor: &Arc<Supervisor>,
    saga_id: SagaId,
    target_context_id: &str,
    signing_key: SigningKeyBytes,
) -> Result<(), SagaError> {
    // ADR-056 chokepoint: decode the id STRING the SAME way the producer keys
    // the actor (decode a real 64-hex id rather than re-hashing it).
    let target_bytes = scp_core::context::state::context_id_to_bytes(target_context_id);
    supervisor
        .recover_streaming_saga_truncated_close(saga_id, target_bytes, signing_key)
        .await
}
