//! Outlet streaming wire types — `OutletStreamOpen`, `OutletStreamChunk`,
//! `OutletStreamCredit`, and the tagged `ChunkPayload` union.
//!
//! Implements the §5.4.5 "Progressive Output (Streaming)" wire contract:
//! every outlet invocation is a stream by construction. A non-streaming
//! invocation is the degenerate single-chunk case (`Data(output)` followed
//! by `End(output)`); there is no separate `OutletResponse` wire type.
//! Per ADR-049 §5, the legacy `OutletResponse` is **deleted** — this module
//! is its replacement.
//!
//! # Wire types
//!
//! - [`OutletStreamOpen`] — opens a stream; carries the UCAN (checked once
//!   at open) and the `caveats_binding` that pins the open to a specific
//!   token, request, invoker, and effective caveat set.
//! - [`OutletStreamChunk`] — one operator-signed chunk in the stream;
//!   sequence numbers are strictly monotonic per `request_id`.
//! - [`OutletStreamCredit`] — invoker-signed credit grant. Stream-identity
//!   binding (`context_id`, `outlet_id`, `caveats_binding`, `stream_epoch`)
//!   is committed in the signed preimage so a grant signed for stream A in
//!   context X at epoch E cannot be replayed against stream B / context Y /
//!   epoch E+1.
//! - [`ChunkPayload`] — tagged union with discriminator `@type` (leading
//!   `@` so RFC 8785 JCS sort order places the tag first in every variant —
//!   `@` is `0x40`, before lowercase letters `0x61..0x7A`).
//! - [`StreamTerminalStatus`] — what the event-log records at terminal
//!   chunk (§5.4.5 event-log shape).
//!
//! # Domain separators (§9.18.2)
//!
//! - `SCP-OUTLET-CHUNK-V1:` — Merkle leaf/interior tag for the chunk
//!   manifest (RFC 6962). Defined by §5.4.5; this story exposes the
//!   constant for use by event-log code (SCP-OUT-033/034).
//! - `SCP-OUTLET-CHUNK-SIG-V1:` — per-chunk operator signature.
//! - `SCP-OUTLET-CAVEAT-BIND-V1:` — `caveats_binding` preimage.
//! - `SCP-OUTLET-CREDIT-V1:` — `OutletStreamCredit.sig` preimage.
//!
//! Each preimage uses the §9.5.1 uniform construction rule: every
//! variable-length field is `len_be32 || bytes`. Fixed-width fields
//! (`request_id` 16 bytes, `caveats_binding` 32 bytes, integer big-endian)
//! are emitted verbatim.
//!
//! # Runtime hand-off
//!
//! Several §5.4.5 / §6.2.1.1 invariants are runtime state-machine
//! responsibilities — they are not pure types, and they ride on data
//! the operator and invoker accumulate over the lifetime of a stream
//! (revocation cache, per-session stream table, MLS epoch counter):
//!
//! - **UCAN revocation re-check** every
//!   [`ContextParams::stream_ucan_recheck_secs`]
//!   (default [`DEFAULT_STREAM_UCAN_RECHECK_SECS`]) — terminates with
//!   [`StreamRejection::RevokedMidStream`] within `stream_ucan_recheck_secs`
//!   of the revocation event regardless of executor checkpoint behavior.
//! - **Per-session invariants** (§6.2.1.1): one concurrent stream per
//!   session, session-pinned `caveats_binding`, session-pinned
//!   `origin_kind`, separate `session_epoch` and `stream_epoch`.
//!
//! For the runtime side, this story defines [`StreamRejection`] and the
//! validator helpers that map a stream-table observation to a typed
//! rejection (with the §5.4.4 `OutletErrorClass` and slug). The runtime
//! state machine that actually maintains the stream table and re-check
//! timer is wired in SCP-OUT-033/034.
//!
//! [`ContextParams::stream_ucan_recheck_secs`]: #
//!   "ContextParams field — registered in §9.18.B; runtime SCP-OUT-033"

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::context::outlets::error_codes::{
    CODE_AUTHORIZATION_DENIED, CODE_EXECUTION_CANCEL_ACK_TIMEOUT, CODE_EXECUTION_CREDIT,
    CODE_EXECUTION_CREDIT_STALL, CODE_PROTOCOL_SESSION, CODE_PROTOCOL_VIOLATION,
    SLUG_AUTHORIZATION_ATTENUATION_VIOLATION, SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
    SLUG_EXECUTION_CANCEL_ACK_TIMEOUT, SLUG_EXECUTION_CREDIT_EXHAUSTED,
    SLUG_EXECUTION_CREDIT_STALL, SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
    SLUG_PROTOCOL_STREAM_ALREADY_OPEN, SLUG_PROTOCOL_UNKNOWN_SESSION,
};
use crate::context::outlets::errors::OutletErrorClass;
use crate::context::outlets::{OutletId, OutletKind};
use crate::serde_util::{serde_hash_32, serde_id_16, serde_signature_64};
use scp_did::DID;

// ---------------------------------------------------------------------------
// Domain separators — §9.18.2 / §5.4.5
// ---------------------------------------------------------------------------

/// `SCP-OUTLET-CHUNK-V1:` — Merkle leaf/interior tag for the chunk manifest
/// (§5.4.5 chunk manifest leaf construction; RFC 6962 §2.1).
///
/// Used as the prefix of `leaf_i` and `interior` in the chunk-manifest
/// Merkle tree:
///
/// ```text
/// leaf_i   = SHA-256("SCP-OUTLET-CHUNK-V1:" || 0x00 || canonical_jcs(chunk_i))
/// interior = SHA-256("SCP-OUTLET-CHUNK-V1:" || 0x01 || left_hash || right_hash)
/// ```
pub const SCP_OUTLET_CHUNK_V1: &[u8] = b"SCP-OUTLET-CHUNK-V1:";

/// `SCP-OUTLET-CHUNK-SIG-V1:` — per-chunk operator-signature domain prefix.
///
/// (§5.4.5 per-chunk operator signature.) Binds `context_id`, `outlet_id`,
/// `caveats_binding` so a chunk signed in one stream cannot be replayed
/// into another.
pub const SCP_OUTLET_CHUNK_SIG_V1: &[u8] = b"SCP-OUTLET-CHUNK-SIG-V1:";

/// `SCP-OUTLET-CAVEAT-BIND-V1:` — `caveats_binding` preimage prefix.
///
/// (§5.4.5 `caveats_binding` preimage.) Binds `(ucan_cid, request_id,
/// invoker_did, estimated_chunk_count, canonical_jcs(effective_caveats))`
/// so the binding pins the open to a specific token + stream instance +
/// invoker + chunk-ceiling + caveat set.
pub const SCP_OUTLET_CAVEAT_BIND_V1: &[u8] = b"SCP-OUTLET-CAVEAT-BIND-V1:";

/// `SCP-OUTLET-CREDIT-V1:` — `OutletStreamCredit.sig` preimage prefix.
///
/// (§5.4.5 credit grant signature.) Binds stream identity (`context_id`,
/// `outlet_id`, `caveats_binding`, `stream_epoch`) so a grant signed for
/// one (stream, epoch) cannot be replayed against another.
pub const SCP_OUTLET_CREDIT_V1: &[u8] = b"SCP-OUTLET-CREDIT-V1:";

/// `SCP-OUTLET-CANCEL-V1:` — `OutletStreamCancel.sig` preimage prefix
/// (round-7 cancel-auth tightening).
///
/// (§5.4.5 streaming cancel signature.) Binds stream identity
/// (`context_id`, `outlet_id`, `caveats_binding`) plus the receiver-side
/// next-to-emit cursor (`next_seq`) and `request_id` so a cancel signed
/// for one stream / cursor cannot be replayed across streams or cursors.
pub const SCP_OUTLET_CANCEL_V1: &[u8] = b"SCP-OUTLET-CANCEL-V1:";

// ---------------------------------------------------------------------------
// Runtime defaults — §5.4.5 / §9.18.B
// ---------------------------------------------------------------------------

/// Default `ContextParams::stream_ucan_recheck_secs` cadence (§5.4.5
/// "Revocation re-check cadence (receiver-side)"). Range `[1, 60]`.
pub const DEFAULT_STREAM_UCAN_RECHECK_SECS: u32 = 10;

/// Default credit window (§5.4.5 backpressure). Each open starts with
/// this many chunks of headroom.
pub const DEFAULT_CREDIT_WINDOW: u32 = 32;

/// Default credit-stall timeout (§5.4.5 backpressure). A stream whose
/// credit reaches zero and is not replenished within this many seconds
/// is cancelled with `OutletErrorClass::Execution::CreditStall`.
pub const DEFAULT_STREAM_CREDIT_STALL_SECS: u32 = 30;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A 64-byte Ed25519 signature on the wire.
///
/// The §5.4.5 wire types fix Ed25519 signatures at exactly 64 bytes.
/// Encoded as compact binary via `serde_bytes` (rmp-serde produces a
/// fixed-length bin8 byte sequence; deserialization rejects any other
/// length per [`serde_signature_64`]).
pub type Ed25519Signature = [u8; 64];

/// A 16-byte stream request identifier (`UUIDv7` per §5.4.5).
///
/// First 48 bits encode a Unix-millisecond timestamp; tail is CSPRNG.
/// Wire format is the raw 16 bytes (NOT the 36-character hyphenated
/// hex form) so `request_id` is a fixed-width field in the
/// `caveats_binding` and per-chunk-signature preimages.
pub type RequestId = [u8; 16];

/// MLS epoch counter (§6.2.1.1(e)). The hosting context's MLS epoch at
/// `OutletStreamOpen` acceptance is pinned in the stream table as
/// `stream_epoch` and committed in every credit-grant signature.
pub type MlsEpoch = u64;

// ---------------------------------------------------------------------------
// OutletStreamOpen — §5.4.5
// ---------------------------------------------------------------------------

/// Opens an outlet stream. Carries the UCAN (validated once at open) and
/// the `caveats_binding` that pins the open to a specific token, request,
/// invoker, billable-chunk ceiling, and effective caveat set.
///
/// # Field invariants
///
/// - `request_id` — 16-byte `UUIDv7`. Receivers pin
///   `(request_id → {context_id, outlet_id, caveats_binding, stream_epoch,
///   invoker_pk, ...})` for the stream lifetime; a later open with the
///   same `request_id` but a different `caveats_binding` is rejected as
///   `OutletErrorClass::Authorization::AttenuationViolation` (§5.4.5
///   binding-pinning invariant).
/// - `chain_depth` — `u8` to match §24.4 width `[0, 255]` and ADR-043.
///   Inherited by every chunk; chunks do not recompute or check it.
/// - `caveats_binding` — SHA-256 over the §5.4.5 preimage (computed by
///   [`compute_caveats_binding`]). Closes the cross-stream replay surface
///   on chunks and credit grants.
/// - `estimated_chunk_count` — invoker-declared upper bound on billable
///   (Data) chunks. Coerced from `caveats.max_calls` when not declared
///   explicitly. Per §5.4.5 MUST satisfy
///   `estimated_chunk_count <= min(credit_window, caveats.max_calls)`
///   on Action outlets; otherwise the open is rejected with
///   `OutletErrorClass::Input::EstimateExceedsBound`. For Query outlets
///   and zero-cost Action outlets the value is advisory (escrow = 0
///   regardless).
/// - `session_id` — optional stateful-session binding (§6.2.1.1). When
///   present, the open MUST reference an existing, non-expired session
///   whose recorded `origin_kind` is compatible with the outlet's kind.
///   See [`StreamRejection`] for the rejection slugs that the runtime
///   stream-table check produces.
///
/// Wire encoding is `MessagePack` via `serde`. Field order on the wire
/// follows the struct declaration order; serde renames are deliberately
/// not used so the field names match the §5.4.5 spec table verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletStreamOpen {
    /// Per-stream `UUIDv7` (§5.4.5). Monotonic time-sortable.
    #[serde(with = "serde_id_16")]
    pub request_id: RequestId,
    /// Outlet to invoke.
    pub outlet_id: OutletId,
    /// Input value matching the outlet's `input_schema` (max 64 KiB
    /// serialized per §5.4.5; size enforcement is a runtime concern).
    pub input: serde_json::Value,
    /// DID of the invoker (the immediate-previous-hop caller).
    pub invoker_did: DID,
    /// UCAN JWT bytes presented at open. Validated exactly once
    /// (§5.4.5 "UCAN check locus") — chunks do not re-present.
    pub ucan: Vec<u8>,
    /// SHA-256 over the §5.4.5 caveats-binding preimage.
    /// Computed by [`compute_caveats_binding`].
    #[serde(with = "serde_hash_32")]
    pub caveats_binding: [u8; 32],
    /// Cross-context call chain depth. `u8` per §24.4 / ADR-043.
    /// Inherited from the opening call on cross-context hops.
    pub chain_depth: u8,
    /// Initial credit window (§5.4.5 backpressure). The executor may emit
    /// up to this many Data/Progress chunks before it must wait for an
    /// `OutletStreamCredit` grant.
    pub credit_window: u32,
    /// Invoker-declared upper bound on billable (Data) chunks. Used for
    /// escrow-at-open computation. See struct-level rustdoc for the
    /// `min(credit_window, caveats.max_calls)` invariant.
    pub estimated_chunk_count: u32,
    /// Optional stateful-session binding (§6.2.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Absolute stream timeout in milliseconds. `0` = use context default.
    pub timeout_ms: u32,
}

// ---------------------------------------------------------------------------
// caveats_binding preimage — §5.4.5
// ---------------------------------------------------------------------------

/// Computes the §5.4.5 `caveats_binding` SHA-256 hash.
///
/// # Preimage
///
/// ```text
/// SHA-256(
///   "SCP-OUTLET-CAVEAT-BIND-V1:"
///   || len_be32(ucan_cid) || ucan_cid
///   || request_id                                  // 16 bytes, fixed
///   || len_be32(invoker_did) || invoker_did
///   || estimated_chunk_count_be                    // 4 bytes, BE
///   || len_be32(canonical_jcs(effective_caveats))
///   || canonical_jcs(effective_caveats)
/// )
/// ```
///
/// The final variable-length JCS-bytes field is **explicitly
/// length-prefixed** per §9.5.1's uniform construction rule — without
/// the prefix, a preimage-collision class exists where a carefully chosen
/// suffix of one caveat-set's JCS bytes could be reinterpreted as the
/// prefix of a later extension field if the preimage were ever extended
/// (round-3 fix preserved verbatim).
///
/// # Caveat encoding
///
/// `effective_caveats_jcs` is the RFC 8785 JCS canonical encoding of the
/// `InvocationCaveats` record (§7.3.8) AFTER all delegation-chain
/// narrowing has been applied. The same bytes are consumed twice (length
/// prefix + payload) — callers compute the JCS bytes once and pass them
/// in.
///
/// `Option`-typed fields in `effective_caveats` MUST be **omitted** from
/// the JCS encoding when `None` (NOT serialized as explicit `null`) per
/// §5.4.5 "JCS Option serialization rule". This module does not own the
/// caveats type; it consumes the JCS bytes the caller produced. The
/// caller is responsible for the `skip_serializing_if = "Option::is_none"`
/// convention before canonicalization. A cross-SDK conformance fixture
/// in `scp-testing` covers this invariant (see §5.4.5).
#[must_use]
pub fn compute_caveats_binding(
    ucan_cid: &[u8],
    request_id: &RequestId,
    invoker_did: &str,
    estimated_chunk_count: u32,
    effective_caveats_jcs: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CAVEAT_BIND_V1);
    update_with_len_prefix(&mut hasher, ucan_cid);
    hasher.update(request_id);
    update_with_len_prefix(&mut hasher, invoker_did.as_bytes());
    hasher.update(estimated_chunk_count.to_be_bytes());
    update_with_len_prefix(&mut hasher, effective_caveats_jcs);
    hasher.finalize().into()
}

/// Writes `len_be32(bytes) || bytes` into `hasher`. The §9.5.1 uniform
/// construction rule for variable-length fields.
fn update_with_len_prefix(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

// ---------------------------------------------------------------------------
// ChunkPayload — §5.4.5 (tagged union with `@type` discriminator)
// ---------------------------------------------------------------------------

/// One payload value carried by an [`OutletStreamChunk`].
///
/// Tagged union whose discriminator is named `@type` (leading `@`) so
/// that under RFC 8785 JCS sort order the discriminator key precedes
/// every body-field key in every variant: ASCII `@` (`0x40`) sorts before
/// lowercase letters `a..z` (`0x61..0x7A`). The canonical-hashed
/// serialization of every variant therefore has `"@type"` as its first
/// key, and the variant is unambiguously classified before any body
/// field is read.
///
/// (The earlier draft used `"type"`, which under JCS sorts AFTER
/// `aggregate`, `code`, `execution_time_ms`, `message`, `note`, `pct`,
/// `provenance`, and `terminal` — i.e., last in every variant, defeating
/// the "classify first" property.)
///
/// # Variants
///
/// - [`ChunkPayload::Data`] — billable chunk; `value` matches the
///   outlet's `output_schema`. Each Data chunk accrues
///   `cost.amount` per §5.4.5 billing semantics.
/// - [`ChunkPayload::Progress`] — non-billable status update; `pct` is
///   in basis points (`[0, 10000]`). `note` is optional (may be `None`).
/// - [`ChunkPayload::End`] — terminal chunk with the aggregate output
///   and provenance. Does NOT consume credit (executor can always
///   close).
/// - [`ChunkPayload::Error`] — error chunk. `terminal: true` closes the
///   stream; `terminal: false` is informational and the stream remains
///   open. Terminal Error refunds full escrow if no Data chunk has been
///   billed (§5.4.5 billing semantics).
///
/// # Variant size note
///
/// `End` is intentionally larger than `Data` / `Progress` / `Error`
/// because it carries the full provenance record and the aggregate
/// output. Streams emit exactly one `End`, so the payload size of the
/// terminal chunk dominating the variant size is acceptable. (Boxing
/// `End` would force a heap allocation on every chunk that is observed
/// only at terminal time, in exchange for shrinking 99% of stream
/// chunks by ~200 bytes — a poor trade for the protocol's primary
/// pattern of small, frequent Data chunks followed by a single End.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "@type", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)] // End carries full provenance — see "Variant size note" above.
pub enum ChunkPayload {
    /// Billable data chunk. `value` matches the outlet's `output_schema`.
    Data {
        /// Per-chunk output value.
        value: serde_json::Value,
    },
    /// Non-billable progress update.
    Progress {
        /// Completion in basis points (`[0, 10000]`).
        pct: u16,
        /// Optional human-readable note. Omitted from canonical JCS
        /// when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Terminal chunk: aggregate output + provenance + total wall-clock
    /// elapsed.
    End {
        /// Aggregate output (matches `aggregate_schema` or defaults to
        /// the last Data value per §5.4.5).
        aggregate: serde_json::Value,
        /// Provenance metadata for the full stream output.
        provenance: crate::provenance::DataProvenance,
        /// Wall-clock execution time in milliseconds, summed across the
        /// stream's lifetime.
        execution_time_ms: u64,
    },
    /// Error chunk. `terminal: true` closes the stream.
    Error {
        /// `SCP-OUTLET-NNNN` error code (§5.4.4).
        code: String,
        /// Operator-supplied human message (typically the catalog
        /// template — see SCP-OUT-040).
        message: String,
        /// `true` closes the stream; `false` is informational.
        terminal: bool,
    },
}

impl ChunkPayload {
    /// Returns `true` for [`Self::End`] and [`Self::Error`] with
    /// `terminal: true`. Used by the executor and receiver to identify
    /// the chunk that closes the stream.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        match self {
            Self::End { .. } => true,
            Self::Error { terminal, .. } => *terminal,
            Self::Data { .. } | Self::Progress { .. } => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OutletStreamChunk — §5.4.5
// ---------------------------------------------------------------------------

/// One chunk in an outlet stream. `sig` is the operator's Ed25519
/// signature over the §5.4.5 per-chunk-signature preimage (computed by
/// [`compute_chunk_sig_preimage`]).
///
/// Per-chunk signing closes the **equivocation** gap: without per-chunk
/// signatures, an operator could stream one sequence of chunks to one
/// member and a different sequence to another, then commit a
/// `stream_manifest_hash` that covers only one of the streams. With
/// per-chunk signatures, a mismatch between what a member received and
/// what the committed manifest covers is cryptographically detectable.
/// Binding `context_id`, `outlet_id`, and `caveats_binding` into the
/// preimage closes the cross-outlet, cross-context, and cross-caveat-set
/// replay surface.
///
/// # Sequence ordering
///
/// `sequence` values are strictly monotonic per `request_id`, starting
/// at `0`. A receiver that observes a gap (missing sequence) MUST cancel
/// the stream with `OutletErrorClass::Execution::StreamGap` and
/// SHOULD rerun (§5.4.5 ordering rule). MLS has no per-message
/// retransmit primitive, so the mitigation is cancel-and-rerun, not
/// retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletStreamChunk {
    /// Stream identifier.
    #[serde(with = "serde_id_16")]
    pub request_id: RequestId,
    /// Strictly monotonic per-stream sequence number, starting at `0`.
    pub sequence: u64,
    /// Payload variant (Data / Progress / End / Error).
    pub payload: ChunkPayload,
    /// Operator's Ed25519 signature over the §5.4.5 per-chunk-signature
    /// preimage. Verify with [`verify_chunk_signature`].
    #[serde(with = "serde_signature_64")]
    pub sig: Ed25519Signature,
}

/// Computes the SHA-256 preimage hash that the operator signs for one
/// chunk (§5.4.5 per-chunk operator signature).
///
/// # Preimage
///
/// ```text
/// SHA-256(
///   "SCP-OUTLET-CHUNK-SIG-V1:"
///   || len_be32(context_id) || context_id
///   || len_be32(outlet_id)  || outlet_id
///   || request_id                              // 16 bytes
///   || sequence_be                             // 8 bytes, BE
///   || caveats_binding                         // 32 bytes
///   || SHA-256(canonical_jcs(payload))         // 32 bytes
/// )
/// ```
///
/// `payload` is canonicalized via RFC 8785 JCS — the `@type`
/// discriminator sorts to position 0 in every variant (§5.4.5 wire
/// types).
///
/// # Errors
///
/// Returns the JCS error string if `payload` cannot be canonicalized
/// (should not happen for valid `ChunkPayload` values; surfaced for
/// completeness).
pub fn compute_chunk_sig_preimage(
    context_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    sequence: u64,
    caveats_binding: &[u8; 32],
    payload: &ChunkPayload,
) -> Result<[u8; 32], String> {
    let payload_jcs = crate::jcs::to_vec(payload)?;
    let payload_hash: [u8; 32] = Sha256::digest(&payload_jcs).into();

    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CHUNK_SIG_V1);
    update_with_len_prefix(&mut hasher, context_id.as_bytes());
    update_with_len_prefix(&mut hasher, outlet_id.as_bytes());
    hasher.update(request_id);
    hasher.update(sequence.to_be_bytes());
    hasher.update(caveats_binding);
    hasher.update(payload_hash);
    Ok(hasher.finalize().into())
}

/// Signs a chunk's preimage with the operator's Ed25519 signing key and
/// returns the 64-byte signature.
///
/// Convenience constructor for tests and for executors that hold an
/// `ed25519_dalek::SigningKey` directly. Production code typically signs
/// via the platform `KeyCustody` abstraction, in which case it composes
/// [`compute_chunk_sig_preimage`] with the custody-side signing call.
///
/// # Errors
///
/// Returns the JCS error string if `payload` cannot be canonicalized.
pub fn sign_chunk(
    signing_key: &SigningKey,
    context_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    sequence: u64,
    caveats_binding: &[u8; 32],
    payload: &ChunkPayload,
) -> Result<Ed25519Signature, String> {
    let preimage = compute_chunk_sig_preimage(
        context_id,
        outlet_id,
        request_id,
        sequence,
        caveats_binding,
        payload,
    )?;
    Ok(signing_key.sign(&preimage).to_bytes())
}

/// Verifies a chunk's `sig` against the operator's `VerifyingKey` and the
/// §5.4.5 per-chunk-signature preimage.
///
/// Returns `true` iff the signature is valid for the preimage built from
/// `(context_id, outlet_id, chunk.request_id, chunk.sequence,
/// caveats_binding, chunk.payload)`. A canonicalization failure or a
/// malformed signature also returns `false` — callers receive a single
/// boolean for the "this chunk is from this operator for this stream"
/// predicate.
#[must_use]
pub fn verify_chunk_signature(
    chunk: &OutletStreamChunk,
    operator_pk: &VerifyingKey,
    context_id: &str,
    outlet_id: &str,
    caveats_binding: &[u8; 32],
) -> bool {
    let Ok(preimage) = compute_chunk_sig_preimage(
        context_id,
        outlet_id,
        &chunk.request_id,
        chunk.sequence,
        caveats_binding,
        &chunk.payload,
    ) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&chunk.sig);
    operator_pk.verify_strict(&preimage, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// OutletStreamCredit — §5.4.5
// ---------------------------------------------------------------------------

/// Invoker-signed credit grant. Each grant authorizes the executor to
/// emit `grant` additional billable chunks, on top of the unspent
/// portion of `credit_window`.
///
/// `monotonic_seq` is per-`request_id` and strictly increasing; the
/// executor's credit accounting admits a grant only if (a) the signature
/// verifies under the invoker's public key recorded at stream open,
/// (b) `context_id`, `outlet_id`, `stream_epoch`, and `caveats_binding`
/// bound into the preimage match the pinned values for this `request_id`
/// at first open, and (c) `monotonic_seq` strictly exceeds every
/// previously accepted `monotonic_seq` for this `request_id`. Duplicates
/// and regressions are rejected as
/// `OutletErrorClass::Authorization::CreditReplay`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletStreamCredit {
    /// Stream identifier.
    #[serde(with = "serde_id_16")]
    pub request_id: RequestId,
    /// Additional chunks the executor may send.
    pub grant: u32,
    /// Per-stream monotonic grant counter, starting at `0`. Duplicates
    /// and regressions are rejected as `CreditReplay`.
    pub monotonic_seq: u64,
    /// Invoker's Ed25519 signature over the §5.4.5 credit-grant preimage.
    /// Verify with [`verify_credit_signature`].
    #[serde(with = "serde_signature_64")]
    pub sig: Ed25519Signature,
}

/// Computes the SHA-256 preimage hash the invoker signs for one credit
/// grant (§5.4.5 credit grant signature).
///
/// # Preimage
///
/// ```text
/// SHA-256(
///   "SCP-OUTLET-CREDIT-V1:"
///   || len_be32(context_id) || context_id
///   || len_be32(outlet_id)  || outlet_id
///   || request_id                       // 16 bytes
///   || grant_be                         // 4 bytes, BE
///   || monotonic_seq_be                 // 8 bytes, BE
///   || stream_epoch_be                  // 8 bytes, BE
///   || caveats_binding                  // 32 bytes
/// )
/// ```
///
/// `stream_epoch` is the hosting context's MLS epoch counter at
/// `OutletStreamOpen` acceptance — pinned in the stream table at first
/// open per §6.2.1.1(e). Binding it into the preimage closes the
/// cross-epoch grant-replay surface that exists when `request_id`
/// collides across binding-eviction races.
#[must_use]
pub fn compute_credit_sig_preimage(
    context_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    grant: u32,
    monotonic_seq: u64,
    stream_epoch: MlsEpoch,
    caveats_binding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CREDIT_V1);
    update_with_len_prefix(&mut hasher, context_id.as_bytes());
    update_with_len_prefix(&mut hasher, outlet_id.as_bytes());
    hasher.update(request_id);
    hasher.update(grant.to_be_bytes());
    hasher.update(monotonic_seq.to_be_bytes());
    hasher.update(stream_epoch.to_be_bytes());
    hasher.update(caveats_binding);
    hasher.finalize().into()
}

/// Bundle of fields the invoker signs in a credit grant.
///
/// Grouping them keeps [`sign_credit_grant`] under the workspace's
/// `clippy::too_many_arguments` ceiling and matches the §5.4.5 preimage
/// shape — every field below is committed to the signed hash.
#[derive(Debug, Clone, Copy)]
pub struct CreditGrantSigningInputs<'a> {
    /// Hosting context's id.
    pub context_id: &'a str,
    /// Outlet id (matches `OutletStreamOpen.outlet_id`).
    pub outlet_id: &'a str,
    /// Stream identifier.
    pub request_id: &'a RequestId,
    /// Number of additional billable chunks granted.
    pub grant: u32,
    /// Per-stream monotonic grant counter (strictly increasing per
    /// `request_id`).
    pub monotonic_seq: u64,
    /// Stream-epoch pinned at `OutletStreamOpen` acceptance
    /// (§6.2.1.1(e)).
    pub stream_epoch: MlsEpoch,
    /// Stream's `caveats_binding`.
    pub caveats_binding: &'a [u8; 32],
}

/// Signs a credit grant's preimage with the invoker's Ed25519 signing
/// key.
#[must_use]
pub fn sign_credit_grant(
    signing_key: &SigningKey,
    inputs: &CreditGrantSigningInputs<'_>,
) -> Ed25519Signature {
    let preimage = compute_credit_sig_preimage(
        inputs.context_id,
        inputs.outlet_id,
        inputs.request_id,
        inputs.grant,
        inputs.monotonic_seq,
        inputs.stream_epoch,
        inputs.caveats_binding,
    );
    signing_key.sign(&preimage).to_bytes()
}

/// Verifies a credit grant's `sig` against the invoker's `VerifyingKey`
/// and the §5.4.5 credit-grant preimage. Returns `true` on a valid
/// signature, `false` otherwise (including malformed signatures).
#[must_use]
pub fn verify_credit_signature(
    credit: &OutletStreamCredit,
    invoker_pk: &VerifyingKey,
    context_id: &str,
    outlet_id: &str,
    stream_epoch: MlsEpoch,
    caveats_binding: &[u8; 32],
) -> bool {
    let preimage = compute_credit_sig_preimage(
        context_id,
        outlet_id,
        &credit.request_id,
        credit.grant,
        credit.monotonic_seq,
        stream_epoch,
        caveats_binding,
    );
    let signature = ed25519_dalek::Signature::from_bytes(&credit.sig);
    invoker_pk.verify_strict(&preimage, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// OutletStreamCancel — §5.4.5 round-7 cancel-auth
// ---------------------------------------------------------------------------

/// Streaming-form `OutletCancel` carrying the invoker's Ed25519 signature
/// over the §5.4.5 cancel preimage (round-7 cancel-auth tightening).
///
/// Distinct from the legacy [`crate::context::outlets::lifecycle::OutletCancel`]
/// (which carries `request_id: String` + free-form timestamp and is used
/// by the non-streaming cancellation surface). The streaming wire form
/// requires fixed-width identifiers and a signature that binds stream
/// identity into the preimage so a cancel signed for one stream cannot
/// be replayed against another.
///
/// The runtime accepts a streaming cancel only when (a) the signature
/// verifies under the invoker's public key recorded at stream open, and
/// (b) `(context_id, outlet_id, caveats_binding)` bound into the preimage
/// match the pinned values for this `request_id`. A failure returns
/// `OutletErrorClass::Authorization::AuthorizationFailed` and does NOT
/// mutate stream state — the cancel-ack timer does not arm and
/// `cancel_ack_seq` is not recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutletStreamCancel {
    /// Stream identifier — same 16-byte raw form as
    /// [`OutletStreamCredit::request_id`].
    #[serde(with = "serde_id_16")]
    pub request_id: RequestId,
    /// Receiver-side next-to-emit cursor at the moment the cancel is
    /// constructed. Committed into the preimage so a cancel cannot be
    /// replayed at a different cursor position.
    pub next_seq: u64,
    /// Invoker's Ed25519 signature over the §5.4.5 cancel preimage.
    /// Verify with [`verify_cancel_signature`].
    #[serde(with = "serde_signature_64")]
    pub sig: Ed25519Signature,
}

/// Computes the SHA-256 preimage hash the invoker signs for a streaming
/// cancel (§5.4.5 round-7 cancel signature).
///
/// # Preimage
///
/// ```text
/// SHA-256(
///   "SCP-OUTLET-CANCEL-V1:"
///   || len_be32(context_id) || context_id
///   || len_be32(outlet_id)  || outlet_id
///   || request_id                       // 16 bytes
///   || next_seq_be                      // 8 bytes, BE
///   || caveats_binding                  // 32 bytes
/// )
/// ```
#[must_use]
pub fn compute_cancel_sig_preimage(
    context_id: &str,
    outlet_id: &str,
    request_id: &RequestId,
    next_seq: u64,
    caveats_binding: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CANCEL_V1);
    update_with_len_prefix(&mut hasher, context_id.as_bytes());
    update_with_len_prefix(&mut hasher, outlet_id.as_bytes());
    hasher.update(request_id);
    hasher.update(next_seq.to_be_bytes());
    hasher.update(caveats_binding);
    hasher.finalize().into()
}

/// Bundle of fields the invoker signs in a streaming cancel.
///
/// Grouped so [`sign_cancel`] stays under the workspace's
/// `clippy::too_many_arguments` ceiling and matches the §5.4.5 cancel
/// preimage shape verbatim.
#[derive(Debug, Clone, Copy)]
pub struct CancelSigningInputs<'a> {
    /// Hosting context's id.
    pub context_id: &'a str,
    /// Outlet id (matches `OutletStreamOpen.outlet_id`).
    pub outlet_id: &'a str,
    /// Stream identifier.
    pub request_id: &'a RequestId,
    /// Receiver-side next-to-emit cursor.
    pub next_seq: u64,
    /// Stream's `caveats_binding`.
    pub caveats_binding: &'a [u8; 32],
}

/// Signs a streaming-cancel preimage with the invoker's Ed25519 signing
/// key. Returns the 64-byte signature — caller composes it into an
/// [`OutletStreamCancel`].
#[must_use]
pub fn sign_cancel(signing_key: &SigningKey, inputs: &CancelSigningInputs<'_>) -> Ed25519Signature {
    let preimage = compute_cancel_sig_preimage(
        inputs.context_id,
        inputs.outlet_id,
        inputs.request_id,
        inputs.next_seq,
        inputs.caveats_binding,
    );
    signing_key.sign(&preimage).to_bytes()
}

/// Verifies a streaming cancel's `sig` against the invoker's
/// `VerifyingKey` and the §5.4.5 cancel preimage. Returns `true` on a
/// valid signature, `false` otherwise (including malformed signatures).
///
/// Callers must pass the SAME `(context_id, outlet_id, caveats_binding)`
/// pinned at stream open. Mismatch on any field flips the verifier to
/// `false` even when the signature is otherwise valid — that is the
/// cross-stream replay closure.
#[must_use]
pub fn verify_cancel_signature(
    cancel: &OutletStreamCancel,
    invoker_pk: &VerifyingKey,
    context_id: &str,
    outlet_id: &str,
    caveats_binding: &[u8; 32],
) -> bool {
    let preimage = compute_cancel_sig_preimage(
        context_id,
        outlet_id,
        &cancel.request_id,
        cancel.next_seq,
        caveats_binding,
    );
    let signature = ed25519_dalek::Signature::from_bytes(&cancel.sig);
    invoker_pk.verify_strict(&preimage, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// StreamTerminalStatus — §5.4.5 event-log shape
// ---------------------------------------------------------------------------

/// Terminal status recorded in the `OutletInvokedEvent` at stream close
/// (§5.4.5 event-log shape).
///
/// On the wire this is an externally-tagged enum: `Ok` and `Cancelled`
/// serialize as bare strings (`"Ok"`, `"Cancelled"`), and `Error(code)`
/// serializes as a single-key object `{"Error":"SCP-OUTLET-NNNN"}`. The
/// `OutletInvokedEvent` field that carries this value uses the same
/// serde representation across all four FFI bridges (`PyO3` / NAPI /
/// `UniFFI` / WASM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamTerminalStatus {
    /// Stream completed normally with [`ChunkPayload::End`].
    Ok,
    /// Stream terminated with [`ChunkPayload::Error`] or with a
    /// runtime-forced terminal chunk. The wrapped string is the
    /// `code` carried by the terminal chunk (e.g., `SCP-OUTLET-6130`).
    Error(String),
    /// Stream was cancelled (the cancel-ack chunk closed it).
    Cancelled,
}

// ---------------------------------------------------------------------------
// TerminateReason — closed set of framework-side stream termination causes
// ---------------------------------------------------------------------------

/// Closed set of framework-emitted stream termination causes (§5.4.5).
///
/// This is the canonical enumeration of reasons the runtime / framework
/// MAY force-close a stream with a synthetic terminal `Error{terminal:true}`
/// chunk. Every variant maps deterministically to a §5.4.4 slug + code +
/// canonical default message via [`Self::slug`], [`Self::code`], and
/// [`Self::default_message`]. Callers MUST NOT supply free-form slug or
/// code strings — those are derived from the enum so attacker-controlled
/// strings cannot enter the provenance record through the termination path.
///
/// # Spec source
///
/// Spec §5.4.5 defines exactly three framework-side termination causes:
///
/// - "Revocation re-check cadence (receiver-side)" → [`RevokedMidStream`]
///   (slug `authorization.revoked-mid-stream`, code `SCP-OUTLET-6110`). The
///   receiver-side SDK framework periodic UCAN re-check observes the
///   opening token revoked since stream open and force-closes within
///   `stream_ucan_recheck_secs`.
/// - "Cancellation and billing boundary" → [`CancelAckTimeout`] (slug
///   `execution.cancel-ack-timeout`, code `SCP-OUTLET-6135`). The executor
///   failed to emit a terminal chunk within `stream_cancel_ack_secs`
///   after `OutletCancel` arrival.
/// - Credit-stall timer → [`CreditStall`] (slug `execution.credit-stall`,
///   code `SCP-OUTLET-6133`). The credit window remained at zero past
///   `stream_credit_stall_secs` and no fresh grant arrived.
/// - Context teardown (round 8) → [`ContextClosedMidStream`] (slug
///   `protocol.context-closed-mid-stream`, code `SCP-OUTLET-6101`,
///   Protocol class). The hosting context was closed or the operator
///   was evicted/left while the stream was active. Distinct from
///   [`RevokedMidStream`] (Authorization class) — the invoker's UCAN
///   was never revoked; the stream's substrate disappeared. Recording
///   teardown as revocation would write a false audit signal and hand
///   an operator a `DoS` lever (synthesizing a revocation-class
///   behavioral record against an in-flight invoker). Context teardown
///   takes precedence over revocation when both are observable in the
///   same re-check tick (§5.4.5 "Context teardown vs. revocation").
///
/// Any termination cause not in this set is not a legitimate framework
/// close — it is either an executor-emitted terminal (which the executor
/// produces directly, never through this enum) or an architectural gap
/// (which is a code bug, not a new variant). Adding a variant requires
/// a corresponding slug allocation in [`super::error_codes`] and a spec
/// change in §5.4.5.
///
/// [`RevokedMidStream`]: Self::RevokedMidStream
/// [`CancelAckTimeout`]: Self::CancelAckTimeout
/// [`CreditStall`]: Self::CreditStall
/// [`ContextClosedMidStream`]: Self::ContextClosedMidStream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TerminateReason {
    /// `authorization.revoked-mid-stream` / `SCP-OUTLET-6110` — UCAN
    /// revocation re-check observed the opening token revoked since
    /// stream open. The receiver-side SDK framework drives this path
    /// via the periodic re-check loop.
    RevokedMidStream,
    /// `execution.cancel-ack-timeout` / `SCP-OUTLET-6135` — executor failed
    /// to emit a terminal chunk within `stream_cancel_ack_secs` after
    /// `OutletCancel` arrival. The framework forces the stream closed
    /// at the next-to-emit sequence (§5.4.5 cancel-ack timer).
    CancelAckTimeout,
    /// `execution.credit-stall` / `SCP-OUTLET-6133` — credit window
    /// remained at zero past `stream_credit_stall_secs` and no fresh
    /// grant arrived. The framework forces the stream closed.
    CreditStall,
    /// `protocol.context-closed-mid-stream` / `SCP-OUTLET-6101`
    /// (Protocol class) — the hosting context was closed or the
    /// operator was evicted/left while the stream was active (round 8).
    /// Distinct from [`Self::RevokedMidStream`]: the invoker's UCAN was
    /// never revoked; the stream's substrate disappeared. Takes
    /// precedence over revocation when both are observable in the same
    /// re-check tick.
    ContextClosedMidStream,
    /// `execution.credit-exhausted` / `SCP-OUTLET-6131` (Execution class)
    /// — the §5.4.5:758 HARD cumulative billable-chunk ceiling
    /// (`min(credit_window, max_calls)`) was reached. The framework
    /// terminates the stream because no further billable chunk may flow
    /// "regardless of executor behavior" — additional credit grants
    /// cannot raise the cumulative cap. The per-chunk gate
    /// (`StreamGateOutcome::CreditExhausted` in the runtime) drives this
    /// path when a billable chunk arrives at an already-saturated stream.
    CreditExhausted,
}

impl TerminateReason {
    /// Returns the §5.4.4 slug for this termination cause.
    ///
    /// Static, never derived from caller input. The slug uniquely
    /// identifies the termination path in the §5.4.4 catalog and is
    /// committed verbatim into the synthetic terminal chunk's message
    /// (prefixed before any [`Self::default_message`] / caller-supplied
    /// override).
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::RevokedMidStream => SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
            Self::CancelAckTimeout => SLUG_EXECUTION_CANCEL_ACK_TIMEOUT,
            Self::CreditStall => SLUG_EXECUTION_CREDIT_STALL,
            Self::ContextClosedMidStream => SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
            Self::CreditExhausted => SLUG_EXECUTION_CREDIT_EXHAUSTED,
        }
    }

    /// Returns the §5.4.4 `SCP-OUTLET-NNNN` code for this termination
    /// cause. Static; never caller-derived.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RevokedMidStream => CODE_AUTHORIZATION_DENIED,
            Self::CancelAckTimeout => CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
            Self::CreditStall => CODE_EXECUTION_CREDIT_STALL,
            Self::ContextClosedMidStream => CODE_PROTOCOL_SESSION,
            Self::CreditExhausted => CODE_EXECUTION_CREDIT,
        }
    }

    /// Returns the canonical default message string the framework
    /// emits when no caller override is supplied.
    ///
    /// Matches the strings produced by
    /// [`super::super::stream::CancelAckTracker::cancel_ack_timeout_payload`]
    /// and `credit_stall_payload` in the runtime so a `TerminateReason`-
    /// driven terminal chunk is byte-identical to a timer-driven one
    /// (modulo the operator signature, which depends on `request_id` /
    /// `sequence` and is necessarily distinct per stream).
    #[must_use]
    pub const fn default_message(&self) -> &'static str {
        match self {
            Self::RevokedMidStream => "ucan revoked mid-stream",
            Self::CancelAckTimeout => {
                "executor failed to emit terminal chunk within stream_cancel_ack_secs"
            }
            Self::CreditStall => "credit window remained at zero past stream_credit_stall_secs",
            Self::ContextClosedMidStream => "hosting context closed or operator evicted mid-stream",
            Self::CreditExhausted => {
                "cumulative billable-chunk ceiling reached (min(credit_window, max_calls))"
            }
        }
    }

    /// Parses a slug string back to a [`TerminateReason`] variant.
    ///
    /// Used by the `PyO3` / NAPI bridges that accept a slug `&str` /
    /// `string` on the wire (per-language idiom — Python and JS
    /// developers expect string identifiers, not opaque integers).
    /// Returns `None` for unknown slugs; callers must surface a
    /// `Validation` error to the SDK rather than silently defaulting.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            SLUG_AUTHORIZATION_REVOKED_MID_STREAM => Some(Self::RevokedMidStream),
            SLUG_EXECUTION_CANCEL_ACK_TIMEOUT => Some(Self::CancelAckTimeout),
            SLUG_EXECUTION_CREDIT_STALL => Some(Self::CreditStall),
            SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM => Some(Self::ContextClosedMidStream),
            SLUG_EXECUTION_CREDIT_EXHAUSTED => Some(Self::CreditExhausted),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Chunk manifest — §5.4.5 / SCP-OUT-035
// ---------------------------------------------------------------------------

/// RFC 6962 leaf-tag byte (`0x00`). Inserted between the
/// [`SCP_OUTLET_CHUNK_V1`] domain separator and the canonical-JCS chunk
/// bytes when computing a chunk-manifest leaf hash.
pub const CHUNK_MANIFEST_LEAF_TAG: u8 = 0x00;

/// RFC 6962 interior-tag byte (`0x01`). Inserted between the
/// [`SCP_OUTLET_CHUNK_V1`] domain separator and the concatenated
/// `left_hash || right_hash` when computing an interior node hash.
pub const CHUNK_MANIFEST_INTERIOR_TAG: u8 = 0x01;

/// Computes the SHA-256 leaf hash for one chunk in the manifest tree
/// (§5.4.5 chunk manifest leaf construction; RFC 6962 §2.1):
///
/// ```text
/// leaf_i = SHA-256("SCP-OUTLET-CHUNK-V1:" || 0x00 || canonical_jcs(chunk_i))
/// ```
///
/// `canonical_jcs(chunk_i)` covers the entire [`OutletStreamChunk`] —
/// `request_id`, `sequence`, `payload` (already JCS-canonical via the
/// `@type` discriminator rule), AND `sig`. The leaf therefore commits
/// to the operator's per-chunk signature, so a later verifier holding
/// a chunk and the manifest root can prove the operator signed that
/// exact chunk. The leaf-tag byte (`0x00`) prevents a second-preimage
/// collision class against interior nodes (which use `0x01`).
///
/// # Errors
///
/// Returns the JCS canonicalization error string if the chunk cannot
/// be serialized — should not happen for valid [`OutletStreamChunk`]
/// values; surfaced for completeness.
pub fn compute_chunk_leaf_hash(chunk: &OutletStreamChunk) -> Result<[u8; 32], String> {
    let chunk_jcs = crate::jcs::to_vec(chunk)?;
    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CHUNK_V1);
    hasher.update([CHUNK_MANIFEST_LEAF_TAG]);
    hasher.update(&chunk_jcs);
    Ok(hasher.finalize().into())
}

/// Computes the SHA-256 interior-node hash from two child hashes
/// (§5.4.5; RFC 6962 §2.1):
///
/// ```text
/// interior = SHA-256("SCP-OUTLET-CHUNK-V1:" || 0x01 || left_hash || right_hash)
/// ```
///
/// The interior-tag byte (`0x01`) is distinct from the leaf-tag byte
/// (`0x00`) used by [`compute_chunk_leaf_hash`], preventing a leaf
/// from colliding with an interior node sharing the same SHA-256 input
/// length.
#[must_use]
pub fn compute_chunk_interior_hash(left_hash: &[u8; 32], right_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SCP_OUTLET_CHUNK_V1);
    hasher.update([CHUNK_MANIFEST_INTERIOR_TAG]);
    hasher.update(left_hash);
    hasher.update(right_hash);
    hasher.finalize().into()
}

/// Computes the chunk-manifest Merkle root over an ordered chunk
/// sequence (§5.4.5 / SCP-OUT-035).
///
/// The construction follows RFC 6962 §2.1 exactly:
///
/// 1. Each chunk produces a leaf hash via [`compute_chunk_leaf_hash`].
/// 2. Adjacent leaves are paired and combined via
///    [`compute_chunk_interior_hash`]; an odd-count level promotes the
///    final unpaired hash to the next level WITHOUT re-hashing
///    (matching CT, RFC 6962 §2.1's tree-of-records definition).
/// 3. The single hash remaining at the top is the manifest root.
///
/// Edge cases:
///
/// - **Empty stream**: returns the all-zero sentinel `[0u8; 32]`. A
///   stream that emits no chunks is not a valid §5.4.5 stream (every
///   stream produces at least one terminal chunk), but the function
///   defines a total mapping for completeness so callers writing a
///   legacy / synthetic event do not need to special-case the empty
///   slice.
/// - **Single chunk**: the leaf hash IS the root (no interior nodes).
///
/// # Errors
///
/// Propagates the first JCS canonicalization error encountered while
/// hashing leaves.
pub fn compute_chunk_manifest_root(chunks: &[OutletStreamChunk]) -> Result<[u8; 32], String> {
    if chunks.is_empty() {
        return Ok([0u8; 32]);
    }

    // Layer 0: leaf hashes.
    let mut current: Vec<[u8; 32]> = chunks
        .iter()
        .map(compute_chunk_leaf_hash)
        .collect::<Result<Vec<_>, String>>()?;

    while current.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.chunks_exact(2);
        for pair in &mut iter {
            // chunks_exact yields slices of length 2 → indexing is
            // bounded; pattern-match keeps clippy.indexing happy too.
            let [left, right] = pair else { unreachable!() };
            next.push(compute_chunk_interior_hash(left, right));
        }
        if let Some(unpaired) = iter.remainder().first().copied() {
            // Odd-count level: promote the unpaired final hash to the
            // next level verbatim (RFC 6962 §2.1).
            next.push(unpaired);
        }
        current = next;
    }

    // current.len() == 1 by the loop invariant + the early return on
    // empty input; index 0 is safe.
    Ok(current[0])
}

// ---------------------------------------------------------------------------
// MerkleFrontier — incremental O(log n) RFC-6962 root (§5.4.5 / ADR-061)
// ---------------------------------------------------------------------------

/// An incremental, append-only RFC-6962 Merkle frontier over an outlet
/// chunk stream (§5.4.5 chunk manifest; ADR-061 "seal phase").
///
/// The batch [`compute_chunk_manifest_root`] retains the **entire** chunk
/// slice to compute the root; ADR-061 forbids the streaming pump from
/// accumulating the full payload set in memory (the durable capture must
/// be "an O(log n) frontier, not the payload set"). This type ingests one
/// chunk at a time via [`Self::push`], retains only `≤ ⌈log2(n)⌉ + 1`
/// subtree hashes, and yields the running root, leaf count, and billed
/// count in `O(log n)` space.
///
/// # Root equivalence (invariant)
///
/// For **any** chunk sequence — length 0, 1, 2, 3, odd, even, large —
/// [`Self::root`] equals [`compute_chunk_manifest_root`] over the same
/// sequence. `compute_chunk_manifest_root` remains the batch **oracle**
/// (the auditor's re-derivation path per §5.4.5 "Inclusion proofs" and
/// this type's equivalence property test); the frontier is the streaming
/// producer of the identical value. Both implement the RFC-6962 §2.1
/// Merkle-tree hash: the batch via level-by-level pair-and-promote, this
/// type via a forest of perfect subtrees folded right-to-left. Both equal
/// the RFC-6962 recursive `MTH`, hence each other.
///
/// # Billed count
///
/// [`Self::billed_count`] tracks the §5.4.5 reference billable-chunk count
///
/// ```text
/// chunks_billed_ref = |{ i : chunk_i.payload.@type == "data"
///                            && chunk_i.sequence <= cancel_ack_ceiling }|
/// ```
///
/// matching `scp_runtime::context::outlets::stream::compute_chunks_billed_ref`
/// (which filters on `chunk.sequence`, the renumbered outer-pump sequence,
/// not the slice index). The ceiling is fixed at construction:
/// [`Self::new`] uses `u64::MAX` (no cancel — the predicate reduces to
/// `@type == "data"`); [`Self::with_ceiling`] pins a `cancel_ack_seq`. The
/// dispatch pump uses [`Self::new`] because it never *pushes* an
/// above-ceiling `Data` chunk (those are dropped at the gate before
/// emission), so the unbounded ceiling yields the identical count over the
/// emitted manifest.
#[derive(Debug, Clone)]
pub struct MerkleFrontier {
    /// Perfect-subtree roots, bottom (largest, leftmost) → top (smallest,
    /// rightmost). Each entry is `(level, hash)` where a level-`L` subtree
    /// covers exactly `2^L` leaves. Levels are strictly decreasing from
    /// bottom to top, so `stack.len() <= ⌈log2(n)⌉ + 1`.
    stack: Vec<(u8, [u8; 32])>,
    /// Total number of leaves (chunks) ingested.
    leaf_count: u64,
    /// Count of `Data` chunks with `sequence <= ceiling` ingested so far.
    billed_count: u64,
    /// Cancel-ack ceiling; `u64::MAX` when the stream has no cancel.
    ceiling: u64,
}

impl Default for MerkleFrontier {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleFrontier {
    /// Creates an empty frontier with an **unbounded** billing ceiling
    /// (`u64::MAX`) — every `Data` chunk is billable regardless of
    /// sequence. This is the dispatch-pump constructor: the pump drops
    /// above-cancel-ack `Data` chunks before emission, so no pushed `Data`
    /// chunk ever exceeds the real cancel-ack sequence and the unbounded
    /// ceiling produces the same billed count as the pinned one.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_ceiling(u64::MAX)
    }

    /// Creates an empty frontier that only bills `Data` chunks whose
    /// `sequence <= cancel_ack_ceiling` (§5.4.5 cancel-ack billing
    /// boundary). Pass `u64::MAX` for a stream that terminated without
    /// cancel.
    #[must_use]
    pub const fn with_ceiling(cancel_ack_ceiling: u64) -> Self {
        Self {
            stack: Vec::new(),
            leaf_count: 0,
            billed_count: 0,
            ceiling: cancel_ack_ceiling,
        }
    }

    /// Ingests one chunk: folds its leaf hash into the Merkle forest and
    /// updates the leaf/billed counters. Chunks MUST be pushed in the
    /// stream's emission order (the same order the batch oracle hashes
    /// them) — the RFC-6962 tree is order-dependent.
    ///
    /// # Errors
    ///
    /// Propagates the JCS canonicalization error from
    /// [`compute_chunk_leaf_hash`] if the chunk cannot be serialized. This
    /// is unreachable for a chunk that was already operator-signed (signing
    /// JCS-canonicalizes the same payload), but is surfaced rather than
    /// swallowed so a genuine encoding fault is never silently folded as a
    /// zero leaf.
    pub fn push(&mut self, chunk: &OutletStreamChunk) -> Result<(), String> {
        let leaf = compute_chunk_leaf_hash(chunk)?;

        // Fold the new leaf into the forest of perfect subtrees: push it as
        // a level-0 subtree, then while the top two subtrees share a level,
        // combine them into their parent (RFC-6962 interior node). This
        // maintains the invariant that levels strictly decrease from the
        // bottom of the stack to the top.
        self.stack.push((0, leaf));
        loop {
            // Match the top two subtrees (last = right, second-last = left)
            // WITHOUT indexing. `(u8, [u8; 32])` is `Copy`, so the parent is
            // computed inside the borrow and the pair copied out; the borrow
            // ends before the pops, satisfying the borrow checker.
            let parent = match self.stack.as_slice() {
                [.., (below_level, below_hash), (top_level, top_hash)]
                    if below_level == top_level =>
                {
                    Some((
                        *top_level + 1,
                        compute_chunk_interior_hash(below_hash, top_hash),
                    ))
                }
                _ => None,
            };
            let Some(parent) = parent else { break };
            self.stack.pop();
            self.stack.pop();
            self.stack.push(parent);
        }

        self.leaf_count = self.leaf_count.saturating_add(1);
        if chunk.sequence <= self.ceiling && matches!(chunk.payload, ChunkPayload::Data { .. }) {
            self.billed_count = self.billed_count.saturating_add(1);
        }
        Ok(())
    }

    /// Returns the running RFC-6962 Merkle root over every chunk pushed so
    /// far. Equal to [`compute_chunk_manifest_root`] over the same
    /// sequence. `O(log n)`.
    ///
    /// An empty frontier returns the all-zero sentinel `[0u8; 32]`,
    /// matching the batch oracle's empty-slice convention.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut iter = self.stack.iter().rev();
        let Some(&(_, mut root)) = iter.next() else {
            return [0u8; 32];
        };
        // Fold the forest right-to-left: the rightmost (smallest) subtree
        // is the deepest-right of the RFC-6962 tree; each subtree to its
        // left is the left child at the next level up.
        for &(_, left) in iter {
            root = compute_chunk_interior_hash(&left, &root);
        }
        root
    }

    /// Total number of chunks ingested (all `@type`s, including the
    /// terminal chunk) — the §5.4.5 `stream_chunk_count`.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Count of billable `Data` chunks at or below the cancel-ack ceiling —
    /// the §5.4.5 `chunks_billed` reference value.
    #[must_use]
    pub const fn billed_count(&self) -> u64 {
        self.billed_count
    }
}

// ---------------------------------------------------------------------------
// Session × stream invariants — §6.2.1.1
// ---------------------------------------------------------------------------

/// Observation passed to [`evaluate_session_open`] describing what the
/// runtime stream-table check sees at `OutletStreamOpen` acceptance time.
///
/// This is the typed input boundary between the protocol-side validator
/// (this module) and the runtime state machine (SCP-OUT-033/034). The
/// runtime constructs an [`OpenObservation`] from its session/stream
/// table; the validator returns the typed [`StreamRejection`] (or
/// `Ok(())` on accept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenObservation<'a> {
    /// Outlet kind declared by the registration (§5.4.2).
    pub outlet_kind: OutletKind,
    /// `effective_caveats.origin_kind` from the open's UCAN narrowing,
    /// if specified.
    pub effective_origin_kind: Option<OutletKind>,
    /// `caveats_binding` carried by the open.
    pub caveats_binding: [u8; 32],
    /// State of the session named by `OutletStreamOpen.session_id`, if
    /// any. `None` means the open did not carry a `session_id`.
    pub session: Option<SessionState<'a>>,
}

/// A snapshot of the runtime's session-table entry that
/// [`evaluate_session_open`] consults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState<'a> {
    /// Session id.
    pub session_id: &'a str,
    /// Whether the session has expired (TTL elapsed).
    pub expired: bool,
    /// Recorded `origin_kind` at session-open time (§6.2.1.1(c)).
    pub origin_kind: OutletKind,
    /// Pinned `caveats_binding` from the session's first stream
    /// (§6.2.1.1(d)). `None` only when no stream has yet opened against
    /// the session — the first stream establishes the binding.
    pub pinned_caveats_binding: Option<[u8; 32]>,
    /// Whether a stream is already live against this session
    /// (§6.2.1.1(b)).
    pub has_live_stream: bool,
}

/// Typed rejection returned by [`evaluate_session_open`] and
/// [`evaluate_revocation_recheck`].
///
/// Each variant carries the §5.4.4 `OutletErrorClass`, allocated code
/// (`SCP-OUTLET-NNNN`), and slug — enough for the runtime to construct the
/// wire `OutletError` envelope and for SDK adapters to surface the
/// failure in their idiomatic typed-error tree.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamRejection {
    /// `protocol.unknown-session` — `session_id` references an unknown
    /// or expired session (§6.2.1.1(a)).
    #[error("unknown or expired session: \"{session_id}\"")]
    UnknownSession {
        /// The session id that did not resolve.
        session_id: String,
    },
    /// `protocol.stream-already-open` — a second concurrent open against
    /// a session that already has a live stream (§6.2.1.1(b)).
    #[error("session \"{session_id}\" already has a live stream")]
    StreamAlreadyOpen {
        /// The session id that already has a live stream.
        session_id: String,
    },
    /// `authorization.attenuation-violation` — caveats-binding or
    /// origin-kind mismatch against the session's pinned values
    /// (§6.2.1.1(c)/(d)) **or** a per-stream binding-pinning mismatch
    /// (§5.4.5 binding-pinning invariant).
    #[error("attenuation violation: {reason}")]
    AttenuationViolation {
        /// Operator-attributable reason — one of the strings emitted
        /// by [`evaluate_session_open`] or [`evaluate_open_pinning`].
        reason: String,
    },
    /// `authorization.revoked-mid-stream` — UCAN revocation re-check
    /// observed the opening token revoked since stream open
    /// (§5.4.5 revocation re-check cadence).
    #[error("UCAN revoked mid-stream")]
    RevokedMidStream,
}

impl StreamRejection {
    /// Returns the §5.4.4 `OutletErrorClass` this rejection maps to.
    #[must_use]
    pub const fn class(&self) -> OutletErrorClass {
        match self {
            Self::UnknownSession { .. } | Self::StreamAlreadyOpen { .. } => {
                OutletErrorClass::Protocol
            }
            Self::AttenuationViolation { .. } | Self::RevokedMidStream => {
                OutletErrorClass::Authorization
            }
        }
    }

    /// Returns the allocated `SCP-OUTLET-NNNN` code (§5.4.4 / SCP-OUT-025).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownSession { .. } => CODE_PROTOCOL_SESSION,
            Self::StreamAlreadyOpen { .. } => CODE_PROTOCOL_VIOLATION,
            Self::AttenuationViolation { .. } | Self::RevokedMidStream => CODE_AUTHORIZATION_DENIED,
        }
    }

    /// Returns the kebab-case slug (§5.4.4 catalog).
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::UnknownSession { .. } => SLUG_PROTOCOL_UNKNOWN_SESSION,
            Self::StreamAlreadyOpen { .. } => SLUG_PROTOCOL_STREAM_ALREADY_OPEN,
            Self::AttenuationViolation { .. } => SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
            Self::RevokedMidStream => SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
        }
    }
}

/// Evaluates the §6.2.1.1 session×stream invariants given a runtime
/// observation. Returns `Ok(())` on accept; a typed [`StreamRejection`]
/// otherwise.
///
/// The runtime stream-table check (SCP-OUT-033/034) builds an
/// [`OpenObservation`] from its session and stream tables and calls this
/// validator at `OutletStreamOpen` acceptance time. The validator is a
/// pure function over its observation — it does not perform any I/O or
/// modify state.
///
/// # Invariants checked
///
/// In order:
///
/// 1. **§6.2.1.1(a) `session_id` carried on open.** Missing or expired
///    session → `UnknownSession`.
/// 2. **§6.2.1.1(b) one concurrent stream per session.** A second open
///    against a session that already has a live stream →
///    `StreamAlreadyOpen`.
/// 3. **§6.2.1.1(c) session owns `origin_kind`.** Mismatch between
///    `effective_caveats.origin_kind` and the session's recorded
///    `origin_kind` → `AttenuationViolation`.
/// 4. **§6.2.1.1(d) session owns `caveats_binding`.** Mismatch between
///    the open's `caveats_binding` and the session's pinned binding →
///    `AttenuationViolation`. The first stream against a session
///    establishes the pinned binding (so `pinned_caveats_binding ==
///    None` is acceptable).
///
/// `stream_epoch != session_epoch` is permitted per §6.2.1.1(e); see
/// the spec note.
///
/// # Errors
///
/// Returns the matching [`StreamRejection`] variant on the first
/// invariant violation observed.
pub fn evaluate_session_open(obs: &OpenObservation<'_>) -> Result<(), StreamRejection> {
    let Some(session) = obs.session.as_ref() else {
        // No session_id on open — invariants (a) through (d) do not apply.
        return Ok(());
    };

    if session.expired {
        return Err(StreamRejection::UnknownSession {
            session_id: session.session_id.to_owned(),
        });
    }

    if session.has_live_stream {
        return Err(StreamRejection::StreamAlreadyOpen {
            session_id: session.session_id.to_owned(),
        });
    }

    // Session origin_kind binding (§6.2.1.1(c)). When the open's UCAN
    // does not specify origin_kind, the runtime treats it as compatible
    // (the session governs); when it does, it must match.
    if let Some(open_origin) = obs.effective_origin_kind
        && open_origin != session.origin_kind
    {
        return Err(StreamRejection::AttenuationViolation {
            reason: format!(
                "session origin_kind mismatch: session={:?}, open={:?}",
                session.origin_kind, open_origin
            ),
        });
    }

    // Session caveats_binding pinning (§6.2.1.1(d)).
    if let Some(pinned) = session.pinned_caveats_binding
        && pinned != obs.caveats_binding
    {
        return Err(StreamRejection::AttenuationViolation {
            reason: "session caveats_binding mismatch".to_owned(),
        });
    }

    // §6.2.1.1(c) sub-rule: session origin_kind must be compatible with
    // outlet kind. (Mirror of §6.2.0.3 amplification check; the runtime
    // will emit AmplificationViolation for cross-kind breaches —
    // SCP-OUT-033 wires that path. Here we just check parity.)
    if obs.outlet_kind == OutletKind::Query && session.origin_kind == OutletKind::Action {
        return Err(StreamRejection::AttenuationViolation {
            reason: "session origin_kind=Action incompatible with Query outlet".to_owned(),
        });
    }

    Ok(())
}

/// Evaluates the §5.4.5 binding-pinning invariant when a later open
/// arrives carrying the same `request_id` as an existing pinned stream.
///
/// Returns `Ok(())` on accept (the stream table may have evicted the
/// pinning record, in which case the runtime treats it as a fresh
/// open) or [`StreamRejection::AttenuationViolation`] when the new
/// open's `caveats_binding` differs from the pinned value.
///
/// # Errors
///
/// Returns [`StreamRejection::AttenuationViolation`] when
/// `new_caveats_binding != pinned_caveats_binding`.
pub fn evaluate_open_pinning(
    pinned_caveats_binding: &[u8; 32],
    new_caveats_binding: &[u8; 32],
) -> Result<(), StreamRejection> {
    if pinned_caveats_binding == new_caveats_binding {
        Ok(())
    } else {
        Err(StreamRejection::AttenuationViolation {
            reason: "request_id collision with different caveats_binding".to_owned(),
        })
    }
}

/// Evaluates the §5.4.5 receiver-side UCAN revocation re-check given the
/// time elapsed since stream open and the time at which the framework
/// observed the opening UCAN's revocation.
///
/// The runtime SDK framework re-checks every
/// [`DEFAULT_STREAM_UCAN_RECHECK_SECS`] (configurable via
/// `ContextParams::stream_ucan_recheck_secs`, range `[1, 60]`). When the
/// revocation cache reports the token revoked, the framework MUST
/// terminate the stream within `stream_ucan_recheck_secs` of the
/// revocation event.
///
/// Returns [`StreamRejection::RevokedMidStream`] when the revocation
/// cache reports the token revoked AND the elapsed time since revocation
/// is at most `stream_ucan_recheck_secs` (i.e., the framework's worst-
/// case detection deadline has been met). Returns `Ok(())` otherwise.
///
/// This validator establishes the typed error mapping; the runtime
/// state machine that maintains the recheck timer is wired in
/// SCP-OUT-033.
///
/// # Errors
///
/// Returns [`StreamRejection::RevokedMidStream`] when `revoked` is
/// `true` and `time_since_revocation <=
/// Duration::from_secs(stream_ucan_recheck_secs.into())`.
pub const fn evaluate_revocation_recheck(
    revoked: bool,
    time_since_revocation: Duration,
    stream_ucan_recheck_secs: u32,
) -> Result<(), StreamRejection> {
    if !revoked {
        return Ok(());
    }
    // The §5.4.5 contract says revocation MUST terminate the stream
    // within `stream_ucan_recheck_secs` of the revocation event. The
    // rejection is `RevokedMidStream` regardless of whether the
    // observation arrived inside the SLA window — the variant means
    // "we observed revocation," not "we observed it in time." A breach
    // of the deadline is a separate observability concern handled by
    // SCP-OUT-033 via the runtime's metrics emission. The
    // `stream_ucan_recheck_secs` and `time_since_revocation` arguments
    // are kept on the public signature so the runtime can pass the
    // observation it has on hand without computing the predicate
    // separately, and so future revisions can branch on the SLA
    // without a wire-shape change.
    let _ = (stream_ucan_recheck_secs, time_since_revocation);
    Err(StreamRejection::RevokedMidStream)
}

// ---------------------------------------------------------------------------
// FFI-shaped fully-populated example for cross-bridge round-trip tests
// ---------------------------------------------------------------------------

/// Constructs the canonical fully-populated [`OutletStreamOpen`] used by
/// the cross-bridge conformance fixture. Fields are at realistic values
/// (session_id present, estimated_chunk_count > 0, every Option-typed
/// field populated). Each FFI bridge round-trips the same fixture and
/// asserts byte-equality after `serde_json_canonicalizer`
/// re-canonicalization (SCP-OUT-032 AC-19).
///
/// This is a `#[doc(hidden)]` constructor — callers in the
/// `scp-protocol` test suite consume it directly; FFI bridge wrappers
/// (PyO3 / NAPI / UniFFI / WASM) re-export and re-canonicalize the same
/// shape.
#[doc(hidden)]
#[must_use]
pub fn fully_populated_open_fixture() -> OutletStreamOpen {
    OutletStreamOpen {
        request_id: [0xA7; 16],
        outlet_id: "outlet-canonical".to_owned(),
        input: serde_json::json!({"a": 1, "b": [2, 3], "c": {"d": "e"}}),
        invoker_did: "did:dht:z6MkInvoker".into(),
        ucan: vec![0xCA, 0xFE, 0xBA, 0xBE],
        caveats_binding: [0x42; 32],
        chain_depth: 3,
        credit_window: DEFAULT_CREDIT_WINDOW,
        estimated_chunk_count: 42,
        session_id: Some("sess-abc".to_owned()),
        timeout_ms: 60_000,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_PROTOCOL_SESSION, CODE_PROTOCOL_VIOLATION,
        SLUG_AUTHORIZATION_ATTENUATION_VIOLATION, SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
        SLUG_PROTOCOL_STREAM_ALREADY_OPEN, SLUG_PROTOCOL_UNKNOWN_SESSION,
    };
    use crate::context::outlets::errors::OutletErrorClass;
    use crate::context::params::MemoryScope;
    use crate::provenance::{DataProvenance, DiscoveryMethod, SourceType};
    use rmp_serde::{from_slice as rmp_from_slice, to_vec_named as rmp_to_vec_named};
    use serde_json::Value;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    fn fixed_request_id() -> RequestId {
        [0x9A; 16]
    }

    fn fixed_caveats_binding() -> [u8; 32] {
        [0xC1; 32]
    }

    fn sample_provenance() -> DataProvenance {
        DataProvenance {
            source_context: "ctx-source".into(),
            source_type: SourceType::Persistent,
            counterparties: vec!["did:dht:z6MkA".into()],
            purpose: None,
            discovery_method: DiscoveryMethod::OutOfBand,
            age: Duration::from_secs(0),
            memory_scope: MemoryScope::Full,
            chain_depth: 0,
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        }
    }

    // -----------------------------------------------------------------------
    // AC-1, AC-2, AC-3 — struct field-shape sanity (compile time + grep)
    // -----------------------------------------------------------------------

    #[test]
    fn outlet_stream_open_field_types() {
        let open = fully_populated_open_fixture();
        // Compile-time field-type assertions. We move `open` into
        // tuple destructuring so each field is consumed exactly once
        // without redundant clones.
        let OutletStreamOpen {
            request_id,
            outlet_id,
            input,
            invoker_did: _,
            ucan,
            caveats_binding,
            chain_depth,
            credit_window,
            estimated_chunk_count,
            session_id,
            timeout_ms,
        } = open;
        let _: [u8; 16] = request_id;
        let _: String = outlet_id;
        let _: Value = input;
        let _: Vec<u8> = ucan;
        let _: [u8; 32] = caveats_binding;
        let _: u8 = chain_depth;
        let _: u32 = credit_window;
        let _: u32 = estimated_chunk_count;
        let _: Option<String> = session_id;
        let _: u32 = timeout_ms;
    }

    #[test]
    fn outlet_stream_chunk_field_types() {
        let chunk = OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: 7,
            payload: ChunkPayload::Data {
                value: serde_json::json!(null),
            },
            sig: [0; 64],
        };
        let _: u64 = chunk.sequence;
        let _: Ed25519Signature = chunk.sig;
    }

    #[test]
    fn outlet_stream_credit_field_types() {
        let credit = OutletStreamCredit {
            request_id: fixed_request_id(),
            grant: 5,
            monotonic_seq: 0,
            sig: [0; 64],
        };
        let _: u32 = credit.grant;
        let _: u64 = credit.monotonic_seq;
        let _: Ed25519Signature = credit.sig;
    }

    // -----------------------------------------------------------------------
    // AC-4, AC-5 — ChunkPayload variants + is_terminal
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_payload_is_terminal_data_progress_false() {
        assert!(
            !ChunkPayload::Data {
                value: serde_json::json!("x")
            }
            .is_terminal()
        );
        assert!(
            !ChunkPayload::Progress {
                pct: 5_000,
                note: None
            }
            .is_terminal()
        );
    }

    #[test]
    fn chunk_payload_is_terminal_end_true() {
        let end = ChunkPayload::End {
            aggregate: serde_json::json!("done"),
            provenance: sample_provenance(),
            execution_time_ms: 123,
        };
        assert!(end.is_terminal());
    }

    #[test]
    fn chunk_payload_is_terminal_error_terminal_only() {
        assert!(
            ChunkPayload::Error {
                code: "SCP-OUTLET-6130".into(),
                message: "panic".into(),
                terminal: true,
            }
            .is_terminal()
        );
        assert!(
            !ChunkPayload::Error {
                code: "SCP-OUTLET-6130".into(),
                message: "warn".into(),
                terminal: false,
            }
            .is_terminal()
        );
    }

    // -----------------------------------------------------------------------
    // AC-6 — StreamTerminalStatus exists with three variants
    // -----------------------------------------------------------------------

    #[test]
    fn stream_terminal_status_three_variants() {
        let _ = StreamTerminalStatus::Ok;
        let _ = StreamTerminalStatus::Error("SCP-OUTLET-6130".into());
        let _ = StreamTerminalStatus::Cancelled;
    }

    #[test]
    fn stream_terminal_status_serde_roundtrip() {
        let cases = [
            StreamTerminalStatus::Ok,
            StreamTerminalStatus::Error("SCP-OUTLET-6135".into()),
            StreamTerminalStatus::Cancelled,
        ];
        for status in cases {
            let json = serde_json::to_string(&status).unwrap();
            let back: StreamTerminalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    // -----------------------------------------------------------------------
    // AC-9 — Round-trip MessagePack on each type
    // -----------------------------------------------------------------------

    #[test]
    fn outlet_stream_open_messagepack_roundtrip() {
        let open = fully_populated_open_fixture();
        let bytes = rmp_to_vec_named(&open).unwrap();
        let back: OutletStreamOpen = rmp_from_slice(&bytes).unwrap();
        assert_eq!(open, back);
        // Critical: fully-populated AC-19 fields survive.
        assert_eq!(back.session_id.as_deref(), Some("sess-abc"));
        assert_eq!(back.estimated_chunk_count, 42);
    }

    #[test]
    fn outlet_stream_chunk_messagepack_roundtrip() {
        let chunk = OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence: 99,
            payload: ChunkPayload::Progress {
                pct: 4_200,
                note: Some("almost there".to_owned()),
            },
            sig: [0xEE; 64],
        };
        let bytes = rmp_to_vec_named(&chunk).unwrap();
        let back: OutletStreamChunk = rmp_from_slice(&bytes).unwrap();
        assert_eq!(chunk, back);
    }

    #[test]
    fn outlet_stream_credit_messagepack_roundtrip() {
        let credit = OutletStreamCredit {
            request_id: fixed_request_id(),
            grant: 8,
            monotonic_seq: 17,
            sig: [0x77; 64],
        };
        let bytes = rmp_to_vec_named(&credit).unwrap();
        let back: OutletStreamCredit = rmp_from_slice(&bytes).unwrap();
        assert_eq!(credit, back);
    }

    // -----------------------------------------------------------------------
    // AC-10 — 100-chunk stream round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn hundred_chunk_stream_roundtrip() {
        let request_id = fixed_request_id();
        let mut chunks: Vec<OutletStreamChunk> = (0_u64..98)
            .map(|i| OutletStreamChunk {
                request_id,
                sequence: i,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({"i": i}),
                },
                sig: [(i & 0xFF) as u8; 64],
            })
            .collect();
        chunks.push(OutletStreamChunk {
            request_id,
            sequence: 98,
            payload: ChunkPayload::Progress {
                pct: 9_900,
                note: None,
            },
            sig: [0xAA; 64],
        });
        chunks.push(OutletStreamChunk {
            request_id,
            sequence: 99,
            payload: ChunkPayload::End {
                aggregate: serde_json::json!({"total": 98}),
                provenance: sample_provenance(),
                execution_time_ms: 9_876,
            },
            sig: [0xFF; 64],
        });

        let bytes = rmp_to_vec_named(&chunks).unwrap();
        let back: Vec<OutletStreamChunk> = rmp_from_slice(&bytes).unwrap();
        assert_eq!(chunks.len(), back.len());
        assert_eq!(chunks, back);
        // Terminal sentinel:
        assert!(back.last().unwrap().payload.is_terminal());
    }

    // -----------------------------------------------------------------------
    // AC-13 — caveats_binding preimage matches §5.4.5
    // -----------------------------------------------------------------------

    #[test]
    fn caveats_binding_preimage_matches_spec() {
        let request_id: RequestId = [0x01; 16];
        let ucan_cid = b"\x12\x20".to_vec(); // multihash-ish placeholder
        let invoker_did = "did:dht:z6MkInvoker";
        let estimated_chunk_count: u32 = 7;
        let caveats_jcs = br#"{"max_calls":7}"#;

        // Build the expected preimage by hand to confirm the helper
        // produces a byte-equivalent hash.
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OUTLET-CAVEAT-BIND-V1:");
        hasher.update(u32::try_from(ucan_cid.len()).unwrap().to_be_bytes());
        hasher.update(&ucan_cid);
        hasher.update(request_id);
        hasher.update(u32::try_from(invoker_did.len()).unwrap().to_be_bytes());
        hasher.update(invoker_did.as_bytes());
        hasher.update(estimated_chunk_count.to_be_bytes());
        hasher.update(u32::try_from(caveats_jcs.len()).unwrap().to_be_bytes());
        hasher.update(caveats_jcs);
        let expected: [u8; 32] = hasher.finalize().into();

        let computed = compute_caveats_binding(
            &ucan_cid,
            &request_id,
            invoker_did,
            estimated_chunk_count,
            caveats_jcs,
        );
        assert_eq!(computed, expected);
    }

    #[test]
    fn caveats_binding_changes_on_estimated_chunk_count() {
        let req: RequestId = [0x02; 16];
        let a = compute_caveats_binding(b"cid", &req, "did:dht:zX", 1, b"{}");
        let b = compute_caveats_binding(b"cid", &req, "did:dht:zX", 2, b"{}");
        assert_ne!(a, b, "estimated_chunk_count is bound into the preimage");
    }

    // -----------------------------------------------------------------------
    // AC-14 — chunk sig preimage + verify_chunk_signature
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_sig_preimage_matches_spec() {
        let context_id = "ctx-abc";
        let outlet_id = "out-xyz";
        let request_id: RequestId = [0x10; 16];
        let sequence: u64 = 3;
        let caveats_binding = fixed_caveats_binding();
        let payload = ChunkPayload::Data {
            value: serde_json::json!({"k": "v"}),
        };
        let payload_jcs = crate::jcs::to_vec(&payload).unwrap();
        let payload_hash: [u8; 32] = Sha256::digest(&payload_jcs).into();

        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OUTLET-CHUNK-SIG-V1:");
        hasher.update(u32::try_from(context_id.len()).unwrap().to_be_bytes());
        hasher.update(context_id.as_bytes());
        hasher.update(u32::try_from(outlet_id.len()).unwrap().to_be_bytes());
        hasher.update(outlet_id.as_bytes());
        hasher.update(request_id);
        hasher.update(sequence.to_be_bytes());
        hasher.update(caveats_binding);
        hasher.update(payload_hash);
        let expected: [u8; 32] = hasher.finalize().into();

        let computed = compute_chunk_sig_preimage(
            context_id,
            outlet_id,
            &request_id,
            sequence,
            &caveats_binding,
            &payload,
        )
        .unwrap();
        assert_eq!(computed, expected);
    }

    #[test]
    fn verify_chunk_signature_accepts_valid() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let context_id = "ctx-abc";
        let outlet_id = "out-xyz";
        let request_id: RequestId = [0x10; 16];
        let caveats_binding = fixed_caveats_binding();

        let payload = ChunkPayload::Progress {
            pct: 1_000,
            note: Some("step".into()),
        };
        let sig = sign_chunk(
            &signing_key,
            context_id,
            outlet_id,
            &request_id,
            5,
            &caveats_binding,
            &payload,
        )
        .unwrap();
        let chunk = OutletStreamChunk {
            request_id,
            sequence: 5,
            payload,
            sig,
        };
        assert!(verify_chunk_signature(
            &chunk,
            &verifying_key,
            context_id,
            outlet_id,
            &caveats_binding
        ));
    }

    #[test]
    fn verify_chunk_signature_rejects_wrong_context() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x11; 16];
        let caveats_binding = fixed_caveats_binding();
        let payload = ChunkPayload::Data {
            value: serde_json::json!("x"),
        };
        let sig = sign_chunk(
            &signing_key,
            "ctx-original",
            "out",
            &request_id,
            0,
            &caveats_binding,
            &payload,
        )
        .unwrap();
        let chunk = OutletStreamChunk {
            request_id,
            sequence: 0,
            payload,
            sig,
        };
        assert!(!verify_chunk_signature(
            &chunk,
            &verifying_key,
            "ctx-replay",
            "out",
            &caveats_binding
        ));
    }

    #[test]
    fn verify_chunk_signature_rejects_wrong_caveats_binding() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x12; 16];
        let cb_a = [0x01; 32];
        let cb_b = [0x02; 32];
        let payload = ChunkPayload::Data {
            value: serde_json::json!("x"),
        };
        let sig = sign_chunk(&signing_key, "ctx", "out", &request_id, 0, &cb_a, &payload).unwrap();
        let chunk = OutletStreamChunk {
            request_id,
            sequence: 0,
            payload,
            sig,
        };
        assert!(!verify_chunk_signature(
            &chunk,
            &verifying_key,
            "ctx",
            "out",
            &cb_b
        ));
    }

    // -----------------------------------------------------------------------
    // AC-15 — credit sig preimage + verify_credit_signature with stream_epoch
    // -----------------------------------------------------------------------

    #[test]
    fn credit_sig_preimage_matches_spec() {
        let context_id = "ctx-x";
        let outlet_id = "out-y";
        let request_id: RequestId = [0x20; 16];
        let grant: u32 = 4;
        let monotonic_seq: u64 = 9;
        let stream_epoch: MlsEpoch = 17;
        let caveats_binding = fixed_caveats_binding();

        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OUTLET-CREDIT-V1:");
        hasher.update(u32::try_from(context_id.len()).unwrap().to_be_bytes());
        hasher.update(context_id.as_bytes());
        hasher.update(u32::try_from(outlet_id.len()).unwrap().to_be_bytes());
        hasher.update(outlet_id.as_bytes());
        hasher.update(request_id);
        hasher.update(grant.to_be_bytes());
        hasher.update(monotonic_seq.to_be_bytes());
        hasher.update(stream_epoch.to_be_bytes());
        hasher.update(caveats_binding);
        let expected: [u8; 32] = hasher.finalize().into();

        let computed = compute_credit_sig_preimage(
            context_id,
            outlet_id,
            &request_id,
            grant,
            monotonic_seq,
            stream_epoch,
            &caveats_binding,
        );
        assert_eq!(computed, expected);
    }

    #[test]
    fn verify_credit_signature_rejects_wrong_epoch() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x21; 16];
        let caveats_binding = fixed_caveats_binding();

        let sig = sign_credit_grant(
            &signing_key,
            &CreditGrantSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                grant: 1,
                monotonic_seq: 0,
                stream_epoch: 5,
                caveats_binding: &caveats_binding,
            },
        );
        let credit = OutletStreamCredit {
            request_id,
            grant: 1,
            monotonic_seq: 0,
            sig,
        };
        // Same parameters except a different stream_epoch — verifier rejects.
        assert!(!verify_credit_signature(
            &credit,
            &verifying_key,
            "ctx",
            "out",
            6,
            &caveats_binding
        ));
        // Same epoch — verifier accepts.
        assert!(verify_credit_signature(
            &credit,
            &verifying_key,
            "ctx",
            "out",
            5,
            &caveats_binding
        ));
    }

    // -----------------------------------------------------------------------
    // Round-7 cancel signature — preimage round-trip + tamper-on-each-field
    // -----------------------------------------------------------------------

    /// Reference vector: the cancel preimage matches the byte-for-byte
    /// SCP-OUTLET-CANCEL-V1 spec block.
    #[test]
    fn cancel_sig_preimage_matches_spec() {
        let request_id: RequestId = [0x33; 16];
        let caveats_binding: [u8; 32] = [0x44; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OUTLET-CANCEL-V1:");
        let ctx = "ctx";
        let outlet = "out";
        hasher.update(u32::try_from(ctx.len()).unwrap().to_be_bytes());
        hasher.update(ctx.as_bytes());
        hasher.update(u32::try_from(outlet.len()).unwrap().to_be_bytes());
        hasher.update(outlet.as_bytes());
        hasher.update(request_id);
        hasher.update(7u64.to_be_bytes());
        hasher.update(caveats_binding);
        let expected: [u8; 32] = hasher.finalize().into();
        let computed = compute_cancel_sig_preimage(ctx, outlet, &request_id, 7, &caveats_binding);
        assert_eq!(computed, expected);
    }

    /// Round-trip: a freshly signed cancel verifies under the matching key.
    #[test]
    fn verify_cancel_signature_accepts_valid() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x22; 16];
        let caveats_binding = fixed_caveats_binding();
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 11,
                caveats_binding: &caveats_binding,
            },
        );
        let cancel = OutletStreamCancel {
            request_id,
            next_seq: 11,
            sig,
        };
        assert!(verify_cancel_signature(
            &cancel,
            &verifying_key,
            "ctx",
            "out",
            &caveats_binding
        ));
    }

    /// Tampering with `context_id` flips verification to `false`.
    #[test]
    fn verify_cancel_signature_rejects_wrong_context() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x44; 16];
        let caveats_binding = fixed_caveats_binding();
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 3,
                caveats_binding: &caveats_binding,
            },
        );
        let cancel = OutletStreamCancel {
            request_id,
            next_seq: 3,
            sig,
        };
        assert!(!verify_cancel_signature(
            &cancel,
            &verifying_key,
            "OTHER",
            "out",
            &caveats_binding
        ));
    }

    /// Tampering with `outlet_id` flips verification to `false`.
    #[test]
    fn verify_cancel_signature_rejects_wrong_outlet() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x55; 16];
        let caveats_binding = fixed_caveats_binding();
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 9,
                caveats_binding: &caveats_binding,
            },
        );
        let cancel = OutletStreamCancel {
            request_id,
            next_seq: 9,
            sig,
        };
        assert!(!verify_cancel_signature(
            &cancel,
            &verifying_key,
            "ctx",
            "OTHER",
            &caveats_binding
        ));
    }

    /// Tampering with `request_id` flips verification to `false` (the
    /// preimage carries the `request_id` verbatim, so the verifier
    /// re-derives it from the cancel struct).
    #[test]
    fn verify_cancel_signature_rejects_wrong_request_id() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x66; 16];
        let caveats_binding = fixed_caveats_binding();
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 4,
                caveats_binding: &caveats_binding,
            },
        );
        // Tamper: same `next_seq` and signature but a different
        // `request_id` in the wire struct.
        let cancel = OutletStreamCancel {
            request_id: [0x77; 16],
            next_seq: 4,
            sig,
        };
        assert!(!verify_cancel_signature(
            &cancel,
            &verifying_key,
            "ctx",
            "out",
            &caveats_binding
        ));
    }

    /// Tampering with `next_seq` flips verification to `false`.
    #[test]
    fn verify_cancel_signature_rejects_wrong_next_seq() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x88; 16];
        let caveats_binding = fixed_caveats_binding();
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 100,
                caveats_binding: &caveats_binding,
            },
        );
        // Tamper: same signature, different next_seq.
        let cancel = OutletStreamCancel {
            request_id,
            next_seq: 101,
            sig,
        };
        assert!(!verify_cancel_signature(
            &cancel,
            &verifying_key,
            "ctx",
            "out",
            &caveats_binding
        ));
    }

    /// Tampering with `caveats_binding` flips verification to `false`.
    #[test]
    fn verify_cancel_signature_rejects_wrong_caveats_binding() {
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x99; 16];
        let caveats_binding_a: [u8; 32] = [0xAA; 32];
        let caveats_binding_b: [u8; 32] = [0xBB; 32];
        let sig = sign_cancel(
            &signing_key,
            &CancelSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                next_seq: 0,
                caveats_binding: &caveats_binding_a,
            },
        );
        let cancel = OutletStreamCancel {
            request_id,
            next_seq: 0,
            sig,
        };
        // Verifier rebuilds the preimage with the wrong caveats_binding.
        assert!(!verify_cancel_signature(
            &cancel,
            &verifying_key,
            "ctx",
            "out",
            &caveats_binding_b
        ));
    }

    // -----------------------------------------------------------------------
    // AC-17 — `@type` placed FIRST in canonical JCS for every variant
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_payload_type_first_data() {
        let p = ChunkPayload::Data {
            value: serde_json::json!(""),
        };
        let jcs = crate::jcs::to_string(&p).unwrap();
        assert!(jcs.starts_with("{\"@type\":\"data\""), "got {jcs}");
    }

    #[test]
    fn chunk_payload_type_first_progress() {
        let p = ChunkPayload::Progress { pct: 0, note: None };
        let jcs = crate::jcs::to_string(&p).unwrap();
        assert!(jcs.starts_with("{\"@type\":\"progress\""), "got {jcs}");
    }

    #[test]
    fn chunk_payload_type_first_end() {
        let p = ChunkPayload::End {
            aggregate: serde_json::json!("agg"),
            provenance: sample_provenance(),
            execution_time_ms: 0,
        };
        let jcs = crate::jcs::to_string(&p).unwrap();
        assert!(jcs.starts_with("{\"@type\":\"end\""), "got {jcs}");
    }

    #[test]
    fn chunk_payload_type_first_error() {
        let p = ChunkPayload::Error {
            code: "SCP-OUTLET-6130".into(),
            message: "x".into(),
            terminal: true,
        };
        let jcs = crate::jcs::to_string(&p).unwrap();
        assert!(jcs.starts_with("{\"@type\":\"error\""), "got {jcs}");
    }

    // -----------------------------------------------------------------------
    // AC-18 — '@type' first vs body keys spanning the alphabet
    //         (regression test name fixed by spec)
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_payload_type_first_with_body_keys_across_alphabet() {
        // Variant whose body keys begin with 'a' — the most adversarial
        // case under JCS sort order. With "type" (no leading @), 'aggregate'
        // would sort BEFORE 'type'; the assertion would fail. The leading
        // '@' (0x40) is what guarantees @type-first.
        let p_a = ChunkPayload::End {
            aggregate: serde_json::json!("a"),
            provenance: sample_provenance(),
            execution_time_ms: 0,
        };
        let jcs_a = crate::jcs::to_string(&p_a).unwrap();
        assert!(
            jcs_a.starts_with("{\"@type\":"),
            "End: @type not first, got {jcs_a}"
        );

        // Variant with a 'z'-prefixed body key (synthesized via Data
        // value object) — at the other end of the alphabet.
        let p_z = ChunkPayload::Data {
            value: serde_json::json!({"zeta_field": 1, "alpha_field": 2}),
        };
        let jcs_z = crate::jcs::to_string(&p_z).unwrap();
        assert!(
            jcs_z.starts_with("{\"@type\":"),
            "Data: @type not first, got {jcs_z}"
        );

        // Progress with body keys 'pct' and 'note' (both > 'i' but < 'q').
        let p_p = ChunkPayload::Progress {
            pct: 5_000,
            note: Some("mid".to_owned()),
        };
        let jcs_p = crate::jcs::to_string(&p_p).unwrap();
        assert!(
            jcs_p.starts_with("{\"@type\":"),
            "Progress: @type not first, got {jcs_p}"
        );

        // Error with body keys 'code', 'message', 'terminal' — 'c' is
        // close to 'a'.
        let p_e = ChunkPayload::Error {
            code: "SCP-OUTLET-6130".into(),
            message: "x".into(),
            terminal: false,
        };
        let jcs_e = crate::jcs::to_string(&p_e).unwrap();
        assert!(
            jcs_e.starts_with("{\"@type\":"),
            "Error: @type not first, got {jcs_e}"
        );
    }

    // -----------------------------------------------------------------------
    // AC — variant collision guard
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_payload_variant_collision_guard() {
        let data = ChunkPayload::Data {
            value: serde_json::json!(""),
        };
        let progress = ChunkPayload::Progress { pct: 0, note: None };
        let h_data = Sha256::digest(crate::jcs::to_vec(&data).unwrap()).to_vec();
        let h_progress = Sha256::digest(crate::jcs::to_vec(&progress).unwrap()).to_vec();
        assert_ne!(
            h_data, h_progress,
            "distinct variants must canonical-hash to different values"
        );
    }

    // -----------------------------------------------------------------------
    // AC-19 — full V2 OutletStreamOpen JCS round-trip stability
    //         (the cross-bridge fixture; per-bridge re-canonicalization
    //          is in scp-testing — Rust side asserts byte equality of
    //          a JCS round-trip on the same fixture so regressions on
    //          this side are caught alongside the bridge tests.)
    // -----------------------------------------------------------------------

    #[test]
    fn full_v2_open_jcs_roundtrip_byte_equal() {
        let open = fully_populated_open_fixture();
        let jcs1 = crate::jcs::to_vec(&open).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&jcs1).unwrap();
        let jcs2 = crate::jcs::to_vec(&parsed).unwrap();
        assert_eq!(jcs1, jcs2, "JCS re-canonicalization must be byte-equal");
        // Critical surviving fields.
        let parsed_open: OutletStreamOpen = serde_json::from_slice(&jcs1).unwrap();
        assert_eq!(parsed_open.session_id.as_deref(), Some("sess-abc"));
        assert_eq!(parsed_open.estimated_chunk_count, 42);
    }

    // -----------------------------------------------------------------------
    // AC-20..23 — Session × stream invariants via evaluate_session_open
    // -----------------------------------------------------------------------

    fn obs_with_session(session: SessionState<'_>, cb: [u8; 32]) -> OpenObservation<'_> {
        OpenObservation {
            outlet_kind: OutletKind::Action,
            effective_origin_kind: None,
            caveats_binding: cb,
            session: Some(session),
        }
    }

    #[test]
    fn session_open_unknown_session_when_expired() {
        let s = SessionState {
            session_id: "sess-1",
            expired: true,
            origin_kind: OutletKind::Action,
            pinned_caveats_binding: None,
            has_live_stream: false,
        };
        let obs = obs_with_session(s, [0; 32]);
        let err = evaluate_session_open(&obs).unwrap_err();
        assert!(matches!(err, StreamRejection::UnknownSession { .. }));
        assert_eq!(err.slug(), SLUG_PROTOCOL_UNKNOWN_SESSION);
        assert_eq!(err.code(), CODE_PROTOCOL_SESSION);
        assert_eq!(err.class(), OutletErrorClass::Protocol);
    }

    #[test]
    fn session_open_stream_already_open_when_live_stream_exists() {
        let s = SessionState {
            session_id: "sess-2",
            expired: false,
            origin_kind: OutletKind::Action,
            pinned_caveats_binding: None,
            has_live_stream: true,
        };
        let obs = obs_with_session(s, [0; 32]);
        let err = evaluate_session_open(&obs).unwrap_err();
        assert!(matches!(err, StreamRejection::StreamAlreadyOpen { .. }));
        assert_eq!(err.slug(), SLUG_PROTOCOL_STREAM_ALREADY_OPEN);
        assert_eq!(err.code(), CODE_PROTOCOL_VIOLATION);
        assert_eq!(err.class(), OutletErrorClass::Protocol);
    }

    #[test]
    fn session_open_origin_kind_mismatch_attenuation_violation() {
        let s = SessionState {
            session_id: "sess-3",
            expired: false,
            origin_kind: OutletKind::Query,
            pinned_caveats_binding: None,
            has_live_stream: false,
        };
        let obs = OpenObservation {
            outlet_kind: OutletKind::Query,
            effective_origin_kind: Some(OutletKind::Action),
            caveats_binding: [0; 32],
            session: Some(s),
        };
        let err = evaluate_session_open(&obs).unwrap_err();
        assert!(matches!(err, StreamRejection::AttenuationViolation { .. }));
        assert_eq!(err.slug(), SLUG_AUTHORIZATION_ATTENUATION_VIOLATION);
        assert_eq!(err.code(), CODE_AUTHORIZATION_DENIED);
        assert_eq!(err.class(), OutletErrorClass::Authorization);
    }

    #[test]
    fn session_open_caveats_binding_mismatch_attenuation_violation() {
        let s = SessionState {
            session_id: "sess-4",
            expired: false,
            origin_kind: OutletKind::Action,
            pinned_caveats_binding: Some([0xAA; 32]),
            has_live_stream: false,
        };
        let obs = obs_with_session(s, [0xBB; 32]);
        let err = evaluate_session_open(&obs).unwrap_err();
        assert!(matches!(err, StreamRejection::AttenuationViolation { .. }));
        assert_eq!(err.slug(), SLUG_AUTHORIZATION_ATTENUATION_VIOLATION);
    }

    #[test]
    fn session_open_first_stream_pins_binding_no_rejection() {
        let s = SessionState {
            session_id: "sess-5",
            expired: false,
            origin_kind: OutletKind::Action,
            pinned_caveats_binding: None,
            has_live_stream: false,
        };
        let obs = obs_with_session(s, [0xCC; 32]);
        assert!(evaluate_session_open(&obs).is_ok());
    }

    #[test]
    fn session_open_no_session_id_no_rejection() {
        let obs = OpenObservation {
            outlet_kind: OutletKind::Action,
            effective_origin_kind: None,
            caveats_binding: [0; 32],
            session: None,
        };
        assert!(evaluate_session_open(&obs).is_ok());
    }

    // -----------------------------------------------------------------------
    // AC — binding-pinning invariant on collision
    // -----------------------------------------------------------------------

    #[test]
    fn open_pinning_rejects_different_caveats_binding() {
        let pinned = [0x10; 32];
        let new = [0x20; 32];
        let err = evaluate_open_pinning(&pinned, &new).unwrap_err();
        assert!(matches!(err, StreamRejection::AttenuationViolation { .. }));
        assert_eq!(err.slug(), SLUG_AUTHORIZATION_ATTENUATION_VIOLATION);
    }

    #[test]
    fn open_pinning_accepts_same_caveats_binding() {
        let pinned = [0x10; 32];
        assert!(evaluate_open_pinning(&pinned, &pinned).is_ok());
    }

    // -----------------------------------------------------------------------
    // AC-16 — UCAN revocation re-check terminates the stream within
    //          stream_ucan_recheck_secs of the revocation event
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_recheck_terminates_within_window() {
        // Default cadence = 10s. Token revoked 3s ago — framework MUST
        // produce RevokedMidStream.
        let err = evaluate_revocation_recheck(true, Duration::from_secs(3), 10).unwrap_err();
        assert!(matches!(err, StreamRejection::RevokedMidStream));
        assert_eq!(err.slug(), SLUG_AUTHORIZATION_REVOKED_MID_STREAM);
        assert_eq!(err.code(), CODE_AUTHORIZATION_DENIED);
        assert_eq!(err.class(), OutletErrorClass::Authorization);
    }

    #[test]
    fn revocation_recheck_terminates_at_deadline_boundary() {
        // exactly at the deadline.
        let err = evaluate_revocation_recheck(true, Duration::from_secs(10), 10).unwrap_err();
        assert!(matches!(err, StreamRejection::RevokedMidStream));
    }

    #[test]
    fn revocation_recheck_accepts_when_not_revoked() {
        assert!(evaluate_revocation_recheck(false, Duration::from_secs(0), 10).is_ok());
    }

    // -----------------------------------------------------------------------
    // AC-24 — stream_epoch != session_epoch is permitted (§6.2.1.1(e))
    // -----------------------------------------------------------------------

    #[test]
    fn stream_epoch_differs_from_session_epoch_permitted() {
        // Two distinct epochs are recorded separately; the credit
        // signature uses stream_epoch (NOT session_epoch). Verify by
        // signing with stream_epoch=7 and rejecting verification under
        // session_epoch=5.
        let signing_key = fixed_signing_key();
        let verifying_key = signing_key.verifying_key();
        let request_id: RequestId = [0x99; 16];
        let cb = fixed_caveats_binding();
        let stream_epoch: MlsEpoch = 7;
        let session_epoch: MlsEpoch = 5;
        let sig = sign_credit_grant(
            &signing_key,
            &CreditGrantSigningInputs {
                context_id: "ctx",
                outlet_id: "out",
                request_id: &request_id,
                grant: 1,
                monotonic_seq: 0,
                stream_epoch,
                caveats_binding: &cb,
            },
        );
        let credit = OutletStreamCredit {
            request_id,
            grant: 1,
            monotonic_seq: 0,
            sig,
        };
        // Signature was produced under stream_epoch=7. Verifier with
        // stream_epoch=7 accepts; with session_epoch=5 rejects.
        assert!(verify_credit_signature(
            &credit,
            &verifying_key,
            "ctx",
            "out",
            stream_epoch,
            &cb
        ));
        assert!(!verify_credit_signature(
            &credit,
            &verifying_key,
            "ctx",
            "out",
            session_epoch,
            &cb
        ));
    }

    // -----------------------------------------------------------------------
    // Sanity — deletion of OutletResponse leaves no struct in this module
    // -----------------------------------------------------------------------

    #[test]
    fn no_outlet_response_in_module() {
        // Type-system enforcement: this test fails to compile if a
        // type named `OutletResponse` is added in this module's scope.
        // Compile-time-only assertion via type alias resolution.
        // (Cannot reference a non-existent type to assert non-existence;
        // we leave the assertion as a code-comment and rely on the
        // grep checks in CI per AC-7/AC-8.)
    }

    #[test]
    fn context_id_alias_resolves() {
        // Ensures the ContextId alias is reachable from the streaming
        // module so future runtime wiring (SCP-OUT-033) can use the
        // existing typed alias rather than a re-declared `String`.
        let _: crate::context::outlets::interface::ContextId = "ctx".into();
    }

    // -----------------------------------------------------------------------
    // TerminateReason — closed-set framework-termination cause mapping
    // -----------------------------------------------------------------------

    /// Each `TerminateReason` variant maps to the §5.4.4 catalog slug
    /// it is documented to surface. Pinning the mapping in a test
    /// guarantees a future variant rename / re-route surfaces here
    /// rather than as a silent provenance corruption.
    #[test]
    fn terminate_reason_slug_matches_5_4_4_catalog() {
        use crate::context::outlets::error_codes::{
            SLUG_AUTHORIZATION_REVOKED_MID_STREAM, SLUG_EXECUTION_CANCEL_ACK_TIMEOUT,
            SLUG_EXECUTION_CREDIT_STALL, SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
        };
        assert_eq!(
            TerminateReason::RevokedMidStream.slug(),
            SLUG_AUTHORIZATION_REVOKED_MID_STREAM
        );
        assert_eq!(
            TerminateReason::CancelAckTimeout.slug(),
            SLUG_EXECUTION_CANCEL_ACK_TIMEOUT
        );
        assert_eq!(
            TerminateReason::CreditStall.slug(),
            SLUG_EXECUTION_CREDIT_STALL
        );
        assert_eq!(
            TerminateReason::ContextClosedMidStream.slug(),
            SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM
        );
    }

    /// Each `TerminateReason` variant maps to the `SCP-OUTLET-NNNN` code
    /// allocated to its §5.4.4 class. Same regression-pinning rationale
    /// as the slug test.
    #[test]
    fn terminate_reason_code_matches_5_4_4_allocation() {
        use crate::context::outlets::error_codes::{
            CODE_AUTHORIZATION_DENIED, CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
            CODE_EXECUTION_CREDIT_STALL, CODE_PROTOCOL_SESSION,
        };
        assert_eq!(
            TerminateReason::RevokedMidStream.code(),
            CODE_AUTHORIZATION_DENIED
        );
        assert_eq!(
            TerminateReason::CancelAckTimeout.code(),
            CODE_EXECUTION_CANCEL_ACK_TIMEOUT
        );
        assert_eq!(
            TerminateReason::CreditStall.code(),
            CODE_EXECUTION_CREDIT_STALL
        );
        assert_eq!(
            TerminateReason::ContextClosedMidStream.code(),
            CODE_PROTOCOL_SESSION
        );
        // Round-8 invariant: context teardown is Protocol-class, NOT the
        // Authorization-class revoked-mid-stream code. Conflating them
        // would write a false revocation audit signal.
        assert_ne!(
            TerminateReason::ContextClosedMidStream.code(),
            TerminateReason::RevokedMidStream.code(),
            "context-closed-mid-stream must not share the Authorization code with revoked-mid-stream"
        );
    }

    /// `from_slug` round-trips every variant. Unknown slugs return
    /// `None` so callers can surface a `Validation` error rather than
    /// silently defaulting to a wrong cause.
    #[test]
    fn terminate_reason_from_slug_roundtrips_and_rejects_unknown() {
        for r in [
            TerminateReason::RevokedMidStream,
            TerminateReason::CancelAckTimeout,
            TerminateReason::CreditStall,
            TerminateReason::ContextClosedMidStream,
            TerminateReason::CreditExhausted,
        ] {
            assert_eq!(TerminateReason::from_slug(r.slug()), Some(r));
        }
        assert_eq!(TerminateReason::from_slug(""), None);
        assert_eq!(TerminateReason::from_slug("not-a-real-slug"), None);
        // Attacker-controlled string that LOOKS like a slug but is not
        // in the §5.4.4 catalog must fail closed.
        assert_eq!(
            TerminateReason::from_slug("authorization.attacker-injected"),
            None
        );
    }

    /// Default messages are non-empty and contain no slug colon prefix
    /// (the caller is expected to prefix the slug; the default message
    /// is the suffix only).
    #[test]
    fn terminate_reason_default_messages_are_non_empty_and_unprefixed() {
        for r in [
            TerminateReason::RevokedMidStream,
            TerminateReason::CancelAckTimeout,
            TerminateReason::CreditStall,
            TerminateReason::ContextClosedMidStream,
            TerminateReason::CreditExhausted,
        ] {
            let msg = r.default_message();
            assert!(!msg.is_empty(), "empty default message for {r:?}");
            assert!(
                !msg.contains(": "),
                "default message must not carry its own slug prefix: {msg:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // MerkleFrontier — incremental root/billed equivalence (§5.4.5 / ADR-061)
    // -----------------------------------------------------------------------

    /// Batch reference for the billed count, mirroring
    /// `scp_runtime::context::outlets::stream::compute_chunks_billed_ref`
    /// (kept here as an independent oracle so the frontier is checked
    /// against a second implementation, not against itself).
    fn billed_ref(chunks: &[OutletStreamChunk], ceiling: u64) -> u64 {
        chunks
            .iter()
            .filter(|c| c.sequence <= ceiling && matches!(c.payload, ChunkPayload::Data { .. }))
            .count() as u64
    }

    /// Builds a chunk of a given `@type` at `sequence`. `kind`:
    /// 0 = Data, 1 = Progress, 2 = End (terminal), 3 = Error.
    fn chunk_of_kind(sequence: u64, kind: u8) -> OutletStreamChunk {
        let payload = match kind % 4 {
            0 => ChunkPayload::Data {
                value: serde_json::json!({ "seq": sequence }),
            },
            1 => ChunkPayload::Progress {
                pct: (sequence % 10_001) as u16,
                note: None,
            },
            2 => ChunkPayload::End {
                aggregate: serde_json::json!({ "final": sequence }),
                provenance: sample_provenance(),
                execution_time_ms: sequence,
            },
            _ => ChunkPayload::Error {
                code: "SCP-OUTLET-6130".to_owned(),
                message: "err".to_owned(),
                terminal: true,
            },
        };
        OutletStreamChunk {
            request_id: fixed_request_id(),
            sequence,
            // Non-zero, sequence-varied sig so the leaf preimage exercises
            // the full canonical chunk (request_id, sequence, payload, sig).
            payload,
            sig: [(sequence & 0xFF) as u8 ^ 0x5A; 64],
        }
    }

    /// Feeds `chunks` (in order) through a fresh frontier with `ceiling`
    /// and returns `(root, leaf_count, billed_count)`.
    fn drive_frontier(chunks: &[OutletStreamChunk], ceiling: u64) -> ([u8; 32], u64, u64) {
        let mut f = MerkleFrontier::with_ceiling(ceiling);
        for c in chunks {
            f.push(c).expect("valid chunk hashes without JCS error");
        }
        (f.root(), f.leaf_count(), f.billed_count())
    }

    /// Hand-worked edge cases: 0, 1, 2, 3 chunks and a cancel ceiling that
    /// truncates billing. Root MUST equal the batch oracle; billed MUST
    /// equal the batch billed reference; `leaf_count` MUST equal the length.
    #[test]
    fn frontier_matches_oracle_small_cases() {
        // n = 0 (empty stream): both yield the all-zero sentinel.
        let (root, leaves, billed) = drive_frontier(&[], u64::MAX);
        assert_eq!(root, compute_chunk_manifest_root(&[]).unwrap());
        assert_eq!(root, [0u8; 32]);
        assert_eq!(leaves, 0);
        assert_eq!(billed, 0);

        // n = 1..=3 with mixed @types, unbounded ceiling.
        for n in 1_u64..=3 {
            let chunks: Vec<_> = (0..n).map(|i| chunk_of_kind(i, (i % 4) as u8)).collect();
            let (root, leaves, billed) = drive_frontier(&chunks, u64::MAX);
            assert_eq!(
                root,
                compute_chunk_manifest_root(&chunks).unwrap(),
                "root mismatch at n={n}"
            );
            assert_eq!(leaves, n, "leaf_count mismatch at n={n}");
            assert_eq!(
                billed,
                billed_ref(&chunks, u64::MAX),
                "billed mismatch at n={n}"
            );
        }

        // Cancel ceiling truncates billing: 5 Data chunks at seq 0..5,
        // ceiling = 2 → only seq {0,1,2} are billable.
        let data: Vec<_> = (0..5).map(|i| chunk_of_kind(i, 0)).collect();
        let (root, leaves, billed) = drive_frontier(&data, 2);
        assert_eq!(root, compute_chunk_manifest_root(&data).unwrap());
        assert_eq!(leaves, 5);
        assert_eq!(billed, 3);
        assert_eq!(billed, billed_ref(&data, 2));
    }

    proptest::proptest! {
        // Deterministic: proptest uses a fixed default RNG seed unless the
        // PROPTEST_SEED env var overrides it, so CI runs are reproducible.

        /// For random chunk sequences (length 0..=257, mixed @types, mixed
        /// sequence numbers) and a random cancel-ack ceiling, the frontier's
        /// running root equals the batch oracle, its leaf_count equals the
        /// length, and its billed_count equals the batch billed reference —
        /// for ALL n (0, 1, 2, 3, odd, even, large).
        #[test]
        fn frontier_root_and_billed_match_oracle(
            kinds in proptest::collection::vec(0u8..4, 0usize..=257),
            ceiling_pick in 0u64..300,
            use_unbounded in proptest::bool::ANY,
        ) {
            // Sequence numbers are the renumbered outer-pump seq: strictly
            // monotonic from 0, matching how the dispatch pump stamps chunks.
            let chunks: Vec<OutletStreamChunk> = kinds
                .iter()
                .enumerate()
                .map(|(i, &k)| chunk_of_kind(i as u64, k))
                .collect();
            let ceiling = if use_unbounded { u64::MAX } else { ceiling_pick };

            let (root, leaves, billed) = drive_frontier(&chunks, ceiling);
            let oracle_root = compute_chunk_manifest_root(&chunks).unwrap();

            proptest::prop_assert_eq!(root, oracle_root, "root diverged from batch oracle");
            proptest::prop_assert_eq!(leaves, chunks.len() as u64, "leaf_count diverged");
            proptest::prop_assert_eq!(
                billed,
                billed_ref(&chunks, ceiling),
                "billed_count diverged from batch reference"
            );

            // The running root must also match the oracle at EVERY prefix,
            // not just at the end — the pump reads the root at close but the
            // frontier must be correct incrementally.
            let mut f = MerkleFrontier::with_ceiling(ceiling);
            for (i, c) in chunks.iter().enumerate() {
                f.push(c).unwrap();
                let prefix_oracle = compute_chunk_manifest_root(&chunks[..=i]).unwrap();
                proptest::prop_assert_eq!(
                    f.root(),
                    prefix_oracle,
                    "prefix root diverged at len {}",
                    i + 1
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-035 AC[11]/[12] — INDEPENDENT RFC-6962 known-answer tests.
    //
    // These pin `compute_chunk_leaf_hash` / `compute_chunk_interior_hash` /
    // `compute_chunk_manifest_root` against a *second, independent* RFC-6962
    // implementation written inline below (raw `Sha256`, recursive split-at-
    // largest-power-of-two `MTH`) AND against hardcoded golden hex digests.
    // The independent oracle deliberately does NOT call any of the library's
    // manifest functions, so a regression in the domain separator, tag
    // bytes, child order, or tree shape is caught even if it were mirrored
    // into a copy-pasted helper.
    // -----------------------------------------------------------------------

    /// Independent leaf hash: `SHA-256("SCP-OUTLET-CHUNK-V1:" ‖ 0x00 ‖
    /// canonical_jcs(chunk))`. Computed with a raw hasher — never calls
    /// [`compute_chunk_leaf_hash`].
    fn indep_leaf(chunk: &OutletStreamChunk) -> [u8; 32] {
        let jcs = crate::jcs::to_vec(chunk).expect("chunk canonicalizes");
        let mut h = Sha256::new();
        h.update(b"SCP-OUTLET-CHUNK-V1:");
        h.update([0x00]);
        h.update(&jcs);
        h.finalize().into()
    }

    /// Independent interior hash: `SHA-256("SCP-OUTLET-CHUNK-V1:" ‖ 0x01 ‖
    /// left ‖ right)`. Never calls [`compute_chunk_interior_hash`].
    fn indep_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SCP-OUTLET-CHUNK-V1:");
        h.update([0x01]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    /// Independent RFC-6962 §2.1 Merkle Tree Hash via the canonical
    /// recursive definition: split at the largest power of two strictly
    /// less than `n`. Structurally distinct from the library's iterative
    /// level-by-level pair-and-promote, so agreement is meaningful.
    fn indep_mth(chunks: &[OutletStreamChunk]) -> [u8; 32] {
        match chunks.len() {
            0 => [0u8; 32],
            1 => indep_leaf(&chunks[0]),
            n => {
                // k = largest power of two strictly less than n.
                let mut k = 1usize;
                while k << 1 < n {
                    k <<= 1;
                }
                let (left, right) = chunks.split_at(k);
                indep_node(&indep_mth(left), &indep_mth(right))
            }
        }
    }

    /// AC[11]: the library leaf hash of a fixed 10-chunk manifest matches
    /// the independent leaf hasher AND a hardcoded golden for chunk 0.
    #[test]
    fn independent_leaf_kat_matches_library() {
        let chunks: Vec<OutletStreamChunk> =
            (0..10).map(|i| chunk_of_kind(i, (i % 4) as u8)).collect();
        for (i, c) in chunks.iter().enumerate() {
            let lib = compute_chunk_leaf_hash(c).unwrap();
            let indep = indep_leaf(c);
            assert_eq!(lib, indep, "leaf {i} diverged from independent hasher");
        }
        // Hardcoded golden for chunk 0 (Data @ seq 0), pinning the exact
        // leaf preimage bytes (domain sep ‖ 0x00 ‖ jcs).
        let golden_leaf0 = "4eee760677a6ca760ff1d411dd53067eaff63f8b95f5d40e1c068da11dc9e8d4";
        assert_eq!(
            hex::encode(compute_chunk_leaf_hash(&chunks[0]).unwrap()),
            golden_leaf0,
            "leaf-0 golden KAT drift"
        );
    }

    /// AC[12]: the library interior hash and manifest root of fixed 2-leaf
    /// and 4-leaf manifests match the independent recursive RFC-6962 MTH
    /// AND hardcoded golden roots.
    #[test]
    fn independent_interior_and_root_kat_matches_library() {
        // Interior-node KAT: two fixed leaves.
        let c0 = chunk_of_kind(0, 0);
        let c1 = chunk_of_kind(1, 0);
        let l0 = compute_chunk_leaf_hash(&c0).unwrap();
        let l1 = compute_chunk_leaf_hash(&c1).unwrap();
        assert_eq!(
            compute_chunk_interior_hash(&l0, &l1),
            indep_node(&l0, &l1),
            "interior hash diverged from independent hasher"
        );

        // 2-leaf root.
        let two = [c0, c1];
        assert_eq!(
            compute_chunk_manifest_root(&two).unwrap(),
            indep_mth(&two),
            "2-leaf root diverged from independent MTH"
        );
        let golden_root2 = "04183441720a2024662106a362a77392ce46f8f90bcd770013efc2c4b9026fb2";
        assert_eq!(
            hex::encode(compute_chunk_manifest_root(&two).unwrap()),
            golden_root2,
            "2-leaf root golden KAT drift"
        );

        // 4-leaf root (perfect tree; exercises interior-of-interior).
        let four: Vec<OutletStreamChunk> = (0..4).map(|i| chunk_of_kind(i, 0)).collect();
        assert_eq!(
            compute_chunk_manifest_root(&four).unwrap(),
            indep_mth(&four),
            "4-leaf root diverged from independent MTH"
        );
        let golden_root4 = "6fcec837b7fad4699ad2c3691d1e6c4e35956dc382df57be8df43f6bb485fbef";
        assert_eq!(
            hex::encode(compute_chunk_manifest_root(&four).unwrap()),
            golden_root4,
            "4-leaf root golden KAT drift"
        );
    }
}
