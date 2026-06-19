//! Per-saga staged-mutation evidence held in
//! `PerContextState.saga_pending` between Prepare and Commit (ADR-049 §3,
//! plan §"`SagaPreparedState` contents" table).
//!
//! Unlike [`crate::context::supervisor::saga_journal::JournalEntry`] —
//! which is the supervisor-side durable coordinator record — values of
//! [`SagaPreparedState`] live in actor-local memory and are persisted only
//! as part of the actor's coalesced [`ContextSnapshot`](crate::context::state::ContextSnapshot). The split is
//! deliberate:
//!
//! - **Journal (durable, supervisor-side):** records *which* saga is in
//!   *which* phase, plus a public commitment for any secret-bearing saga.
//!   Spec §9.4.3 forbids the journal from holding bearer artifacts
//!   directly. No live saga is secret-bearing (see below); the commitment
//!   path is dormant.
//! - **`saga_pending` (actor-side):** holds the full evidence the actor
//!   needs to apply the mutation at Commit time. For a future
//!   secret-bearing saga the bearer envelope would sit here under
//!   `Zeroizing` so drop zeros the bytes if the actor crashes before
//!   Commit; no current variant carries one.
//!
//! At Commit time the actor reconstructs its evidence from `saga_pending`
//! and applies the mutation. If `saga_pending` rolled back beyond the
//! prepared state (e.g. coalesced-snapshot crash window), Commit replay
//! fails fast with `SagaCommitFailed` — no half-applied mutation.
//!
//! # EXPLICIT NON-DERIVES — the §9.4.3 forward contract
//!
//! Per spec §9.4.3, any container holding bearer bytes MUST NOT be
//! `Clone`, `Debug`, `Display`, `Serialize`, or `Deserialize`. The bearer
//! field itself would be wrapped in `Zeroizing<Vec<u8>>` so drop zeros the
//! bytes; the wrapping struct must additionally refuse the trait set
//! above so a misuse like `format!("{:?}", state)` cannot leak bytes
//! into a log line, and a snapshot serializer cannot accidentally write
//! the bearer to disk.
//!
//! No current variant is bearer-bearing: the cross-identity custody
//! handover — the only secret-bearing saga ever contemplated — was
//! withdrawn (ADR-049 §4, tombstoned; it is a §5.11A.6 security violation,
//! not a saga). The discipline above is the contract any *future*
//! bearer-bearing saga type (none planned) MUST satisfy. The wrapping
//! enum [`SagaPreparedState`] still does NOT derive any of these traits,
//! preserving the static barrier so a future bearer variant cannot leak
//! through the enum's auto-generated impls.
//!
//! See ADR-049 §3 (saga protocol), spec §9.4.3 (saga journal secret
//! handling), and `crate::context::supervisor::identity_capability` for
//! the analogous capability-token discipline.

use scp_identity::DID;
use serde::{Deserialize, Serialize};

use crate::context::supervisor::creation_receipt::CreationReceipt;

// ---------------------------------------------------------------------------
// Discriminated union over the 3 saga types defined by ADR-049 §3
// ---------------------------------------------------------------------------

/// Discriminated union over the 3 saga types defined by ADR-049 §3.
///
/// Each variant carries every field needed to replay Commit deterministically
/// from the Prepare-time snapshot. The shape is saga-type specific; see the
/// per-variant documentation.
///
/// **Non-derives.** No `Clone`, `Debug`, `Display`, `Serialize`,
/// `Deserialize` — see module-level documentation for rationale.
pub enum SagaPreparedState {
    /// Standing-pair creation between two identities. All public per spec
    /// §5.15.8; not secret-bearing.
    StandingPairCreate(StandingPairCreatePrepared),
    /// Cross-context tool invocation. The UCAN proof bytes are NOT carried
    /// here — only the proof's identifier — to keep the prepared-state non-
    /// secret-bearing.
    CrossContextToolInvocation(CrossContextToolInvocationPrepared),
    /// Broadcast-hosting handshake. Public per spec §5.14.2; not
    /// secret-bearing.
    BroadcastHostingHandshake(BroadcastHostingHandshakePrepared),
}

// ---------------------------------------------------------------------------
// Standing-pair create
// ---------------------------------------------------------------------------

/// Staged state for a standing-pair-creation saga (spec §5.15.8 Prepare-A
/// / Prepare-B field table).
///
/// All fields are public per spec §5.15.8 (standing-pair handshake): the
/// peer DID, the local DID, the deterministically-derived context ID, and
/// — on the A-side only — the staged [`CreationReceipt`]. None of these
/// are bearer artifacts.
///
/// # No `group_id`
///
/// There is **no** `group_id` field. MLS group isolation keys off
/// `derived_context_id`; the crypto provider computes the MLS group id
/// internally as `SHA-256("standing-" ‖ hex(derived_context_id))` inside
/// `create_mls_group`'s `Entry::Vacant` collision guard. Neither party
/// allocates or carries a separate group id (§5.15.8).
///
/// # A-side vs B-side
///
/// `creation_receipt` is `Some` on the **A-side** (the lower DID,
/// `local_did == did_lo`) and `None` on the **B-side** (`local_did ==
/// did_hi`). The `CreationReceipt` booleans are inherently A-local
/// creation state — B, joining via Welcome, creates no group or sender
/// key and authors no independent receipt (§5.15.8 "Prepare-B").
///
/// # Serialization
///
/// This actor-side prepared state is deliberately NOT `Serialize` (the
/// wrapping [`SagaPreparedState`] enum carries the §9.4.3 non-derive
/// barrier). Journal evidence is produced via the explicit
/// [`StandingPairCreatePreparedWire`] mirror (`MessagePack` of the public
/// fields, §5.15.8 "Commitment coverage"), reached through
/// [`StandingPairCreatePrepared::to_evidence_bytes`] /
/// [`StandingPairCreatePrepared::from_evidence_bytes`].
pub struct StandingPairCreatePrepared {
    /// The remote peer's DID. A-side: `did_hi`; B-side: `did_lo`.
    pub peer_did: DID,
    /// The local identity's DID. A-side: `did_lo`; B-side: `did_hi`.
    pub local_did: DID,
    /// The 32-byte context ID derived from the sorted DID pair — see
    /// §5.15.8 "Determinism precondition" for the derivation. This is the
    /// raw digest (before the `"standing-"` prefix and hex), and is the
    /// key the crypto provider indexes MLS group state by.
    pub derived_context_id: [u8; 32],
    /// Staged [`CreationReceipt`] — `Some` on the A-side (`local_did ==
    /// did_lo`), `None` on the B-side. B authors no receipt (§5.15.8
    /// "Prepare-B").
    ///
    /// `private_interfaces` is allowed for the deliberate-by-design
    /// asymmetry: the field is `pub` (matching the rest of the struct's
    /// public surface) while [`CreationReceipt`] is `pub(in crate::context)`
    /// — the receipt type is crate-context-internal but the field through
    /// which a handler reads it is public, mirroring the
    /// `SupervisorHandle`/`OwnedIdentityDid` discipline in this module.
    #[allow(private_interfaces)]
    pub creation_receipt: Option<CreationReceipt>,
}

/// `Serialize`/`Deserialize` wire mirror of the **public** fields of
/// [`StandingPairCreatePrepared`], used to produce the journal `evidence`
/// (spec §5.15.8 "Commitment coverage": the `MessagePack` of the public
/// prepared state). The actor-side [`StandingPairCreatePrepared`] is
/// deliberately non-`Serialize` because the wrapping [`SagaPreparedState`]
/// enum carries the §9.4.3 non-derive barrier; this explicit mirror is the
/// sanctioned serialization path, matching the
/// `JournalEntryWire`/`EvidenceWire` discipline in
/// [`crate::context::supervisor::saga_journal`].
///
/// All fields are public plan-metadata classified **public** — there is
/// no §9.4.3 secret commitment. `DID` is carried as its canonical string.
///
/// `dead_code` is allowed: this wire mirror and the `to_evidence_bytes` /
/// `from_evidence_bytes` helpers below are the journal-evidence path for
/// the standing-pair saga, consumed when the saga dispatch wiring lands in
/// a follow-on PR. The unit tests exercise the round-trip now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub(in crate::context) struct StandingPairCreatePreparedWire {
    /// `peer_did.0`.
    pub peer_did: String,
    /// `local_did.0`.
    pub local_did: String,
    /// The raw 32-byte derived context id.
    pub derived_context_id: [u8; 32],
    /// `Some` on the A-side; `None` on the B-side (§5.15.8 "Prepare-B").
    pub creation_receipt: Option<CreationReceipt>,
}

#[allow(dead_code)] // evidence path consumed by the saga dispatch wiring PR
impl StandingPairCreatePrepared {
    /// Encode the public prepared state to its journal `evidence` bytes —
    /// `MessagePack` of the [`StandingPairCreatePreparedWire`] mirror
    /// (spec §5.15.8 "Commitment coverage"). Classified **public**; the
    /// supervisor wraps these bytes in the standard `Zeroizing` envelope
    /// for uniformity only.
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` encode error string if serialization fails.
    pub(in crate::context) fn to_evidence_bytes(&self) -> Result<Vec<u8>, String> {
        let wire = StandingPairCreatePreparedWire {
            peer_did: self.peer_did.0.clone(),
            local_did: self.local_did.0.clone(),
            derived_context_id: self.derived_context_id,
            creation_receipt: self.creation_receipt.clone(),
        };
        rmp_serde::to_vec_named(&wire).map_err(|e| format!("encode: {e}"))
    }

    /// Decode public prepared state from its journal `evidence` bytes,
    /// reversing [`Self::to_evidence_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` decode error string if `bytes` is not a
    /// valid `MessagePack` encoding of the wire mirror.
    pub(in crate::context) fn from_evidence_bytes(bytes: &[u8]) -> Result<Self, String> {
        let wire: StandingPairCreatePreparedWire =
            rmp_serde::from_slice(bytes).map_err(|e| format!("decode: {e}"))?;
        Ok(Self {
            peer_did: DID(wire.peer_did),
            local_did: DID(wire.local_did),
            derived_context_id: wire.derived_context_id,
            creation_receipt: wire.creation_receipt,
        })
    }
}

// ---------------------------------------------------------------------------
// Cross-context tool invocation
// ---------------------------------------------------------------------------

/// Staged state for a cross-context tool-invocation saga.
///
/// This is the **public-metadata journal projection** of the
/// `CrossContextToolInvoke` envelope (spec §6.2.4 "Public-metadata
/// journaling") — eight fields, all public.
///
/// **Not bearer-bearing.** The UCAN proof bytes are NOT carried here;
/// only the proof's identifier (token ID). The receiving actor re-resolves
/// the proof from its own UCAN store at Commit time, re-running the full §7
/// validation re-bound to `caller_did` plus `tool_registration_id`. This
/// keeps the prepared-state non-secret-bearing (`mark_resolved(secret_bearing
/// = false)`); the §9.4.3 commitment path stays dormant.
///
/// **B-controlled, replay-deterministic fields.** Three of the eight fields
/// are staged at Prepare-B precisely so a Commit replayed after a crash —
/// when B no longer holds the wire envelope — reproduces the signed
/// `CrossContextToolReceipt` preimage byte-for-byte from durable state:
///
/// - `recorded_timestamp_ms` is B's OWN clock captured once at Prepare-B
///   (NOT the caller-asserted envelope `timestamp_ms`, which is untrusted
///   and consumed only by the freshness check).
/// - `recorded_nonce` is B's staged COPY of the 16-byte wire `nonce`. It
///   equals the caller-supplied wire value by design — the `nonce` is a
///   public correlation/dedup token, not a trust-bearing input — but is
///   staged from B's captured copy so a replayed Commit reproduces it
///   without the envelope.
/// - `recorded_chain_depth` is B's OWN re-derived inbound depth
///   (`incoming chain_depth + 1`), explicitly NOT the caller-asserted
///   advisory envelope `chain_depth`.
///
/// All three are public plan-metadata; staging them keeps the journal
/// non-secret-bearing.
///
/// # Serialization
///
/// This actor-side prepared state is deliberately NOT `Serialize` (the
/// wrapping [`SagaPreparedState`] enum carries the §9.4.3 non-derive
/// barrier). Journal evidence is produced via the explicit
/// [`CrossContextToolInvocationPreparedWire`] mirror (`MessagePack` of the
/// public fields), reached through
/// [`CrossContextToolInvocationPrepared::to_evidence_bytes`] /
/// [`CrossContextToolInvocationPrepared::from_evidence_bytes`], mirroring
/// the [`StandingPairCreatePrepared`] discipline above.
pub struct CrossContextToolInvocationPrepared {
    /// Calling context ID — the raw 32-byte context-id digest (never a
    /// `"standing-"`-prefixed string), matching the id-form rule §6.2.4
    /// states for both context ids.
    pub caller_context_id: [u8; 32],
    /// Target context ID — B's own context, the context in which B executes
    /// the tool (the verified `target_context` of the established interface,
    /// §6.2.4 "Target-context binding"). Raw 32-byte digest, same id-form as
    /// `caller_context_id`.
    pub target_context_id: [u8; 32],
    /// Calling DID.
    pub caller_did: DID,
    /// Tool registration ID (target tool's stable identifier). Context-LOCAL
    /// — it indexes B's own tool registry.
    pub tool_registration_id: String,
    /// UCAN proof reference (token ID), NOT the proof bytes. Resolved
    /// against the receiving actor's UCAN store at Commit time.
    pub ucan_proof_id: String,
    /// B's wall-clock value captured ONCE at Prepare-B (§6.2.4 "Recorded
    /// timestamp"). Both the Commit-time `ToolInvoked` record and the
    /// receipt signature draw `timestamp_ms` from this single staged value;
    /// it is NOT the caller-asserted envelope `timestamp_ms`.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire `nonce` (§6.2.4 "Staged nonce and
    /// recorded chain-depth"). Equal to the caller-supplied wire value by
    /// design; staged from B's captured copy for replay determinism.
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound chain depth = `incoming chain_depth + 1`
    /// (§6.2.4 "Chain-depth enforcement" / "Staged nonce and recorded
    /// chain-depth"). NOT the caller-asserted advisory envelope
    /// `chain_depth`. A `u8`, matching `ProvenanceRecord.chain_depth` and
    /// the `[1, 255]` range in §6.2.0 / §24.4.
    pub recorded_chain_depth: u8,
}

/// `Serialize`/`Deserialize` wire mirror of the **public** fields of
/// [`CrossContextToolInvocationPrepared`], used to produce the journal
/// `evidence` (the `MessagePack` of the eight public journaled fields,
/// §6.2.4 "Public-metadata journaling"). The actor-side
/// [`CrossContextToolInvocationPrepared`] is deliberately non-`Serialize`
/// because the wrapping [`SagaPreparedState`] enum carries the §9.4.3
/// non-derive barrier; this explicit mirror is the sanctioned serialization
/// path, matching the [`StandingPairCreatePreparedWire`] discipline above.
///
/// All eight fields are public plan-metadata classified **public** — there
/// is no §9.4.3 secret commitment (`mark_resolved(secret_bearing=false)`).
/// `DID` is carried as its canonical string.
///
/// `dead_code` is allowed: this wire mirror and the `to_evidence_bytes` /
/// `from_evidence_bytes` helpers below are the journal-evidence path for the
/// cross-context tool-invocation saga, consumed when the saga dispatch
/// wiring lands in a follow-on PR. The unit tests exercise the round-trip
/// now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub(in crate::context) struct CrossContextToolInvocationPreparedWire {
    /// The raw 32-byte caller context id.
    pub caller_context_id: [u8; 32],
    /// The raw 32-byte target context id.
    pub target_context_id: [u8; 32],
    /// `caller_did.0`.
    pub caller_did: String,
    /// Context-local tool registration id.
    pub tool_registration_id: String,
    /// UCAN proof reference (token id), not the proof bytes.
    pub ucan_proof_id: String,
    /// B's Prepare-B captured clock value.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire nonce.
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound depth = `incoming chain_depth + 1`.
    pub recorded_chain_depth: u8,
}

#[allow(dead_code)] // evidence path consumed by the saga dispatch wiring PR
impl CrossContextToolInvocationPrepared {
    /// Encode the public prepared state to its journal `evidence` bytes —
    /// `MessagePack` of the [`CrossContextToolInvocationPreparedWire`]
    /// mirror (§6.2.4 "Public-metadata journaling"). Classified **public**;
    /// the supervisor wraps these bytes in the standard `Zeroizing` envelope
    /// for uniformity only.
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` encode error string if serialization fails.
    pub(in crate::context) fn to_evidence_bytes(&self) -> Result<Vec<u8>, String> {
        let wire = CrossContextToolInvocationPreparedWire {
            caller_context_id: self.caller_context_id,
            target_context_id: self.target_context_id,
            caller_did: self.caller_did.0.clone(),
            tool_registration_id: self.tool_registration_id.clone(),
            ucan_proof_id: self.ucan_proof_id.clone(),
            recorded_timestamp_ms: self.recorded_timestamp_ms,
            recorded_nonce: self.recorded_nonce,
            recorded_chain_depth: self.recorded_chain_depth,
        };
        rmp_serde::to_vec_named(&wire).map_err(|e| format!("encode: {e}"))
    }

    /// Decode public prepared state from its journal `evidence` bytes,
    /// reversing [`Self::to_evidence_bytes`].
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` decode error string if `bytes` is not a valid
    /// `MessagePack` encoding of the wire mirror.
    pub(in crate::context) fn from_evidence_bytes(bytes: &[u8]) -> Result<Self, String> {
        let wire: CrossContextToolInvocationPreparedWire =
            rmp_serde::from_slice(bytes).map_err(|e| format!("decode: {e}"))?;
        Ok(Self {
            caller_context_id: wire.caller_context_id,
            target_context_id: wire.target_context_id,
            caller_did: DID(wire.caller_did),
            tool_registration_id: wire.tool_registration_id,
            ucan_proof_id: wire.ucan_proof_id,
            recorded_timestamp_ms: wire.recorded_timestamp_ms,
            recorded_nonce: wire.recorded_nonce,
            recorded_chain_depth: wire.recorded_chain_depth,
        })
    }
}

// ---------------------------------------------------------------------------
// Broadcast hosting handshake
// ---------------------------------------------------------------------------

/// Staged state for a broadcast-hosting-handshake saga.
///
/// **Not bearer-bearing.** Public per spec §5.14.2: the host context, the
/// broadcast context, the subscriber DID, and the negotiated host config
/// (encoded opaquely here pending the broadcast handler's migration).
pub struct BroadcastHostingHandshakePrepared {
    /// The hosting context ID.
    pub host_context_id: [u8; 32],
    /// The broadcast context ID being hosted.
    pub broadcast_context_id: [u8; 32],
    /// The subscriber DID requesting hosting.
    pub subscriber_did: DID,
    /// Encoded `BroadcastHostConfig` bytes. Concrete type is wired in
    /// when the broadcast handler migrates to the actor model.
    pub broadcast_host_config_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Class-S snapshot mirror (ADR-049 §9 line 144)
// ---------------------------------------------------------------------------

/// `Serialize`/`Deserialize` snapshot mirror of [`SagaPreparedState`].
///
/// Used to persist the actor-side `saga_pending` slot inside
/// [`ContextSnapshot`](crate::context::state::ContextSnapshot) as **Class S**
/// (synchronously-persisted, fail-closed) state per ADR-049 §9 line 144.
///
/// # Why a separate mirror
///
/// The live [`SagaPreparedState`] enum deliberately does NOT derive `Clone`,
/// `Debug`, `Display`, `Serialize`, or `Deserialize` — the §9.4.3 non-derive
/// barrier so a future bearer-bearing variant cannot leak through the enum's
/// auto-generated impls (see this module's header). The snapshot path
/// therefore CANNOT serialize the live enum directly. This mirror carries
/// ONLY the public, non-bearer projection of each variant (the same public
/// fields the per-variant `*Wire` mirrors already journal), so `saga_pending`
/// can ride [`ContextSnapshot`] across an actor crash without the live enum
/// ever gaining a serialization impl. A future bearer-bearing variant would
/// have to add its own explicit, audited mirror branch here (under
/// `Zeroizing` discipline) — the barrier holds.
///
/// The match in [`SagaPreparedStateSnapshot::from_prepared`] is exhaustive
/// over every live variant: adding a variant to [`SagaPreparedState`] fails
/// to compile here until its snapshot projection is decided, so a new saga
/// type can never be silently dropped from the Class-S snapshot.
///
/// Each variant carries its OWN public-field payload struct rather than
/// reusing the `pub(in crate::context)` journal `*Wire` mirrors: the
/// snapshot rides the fully-`pub` [`ContextSnapshot`] surface, while the
/// journal wires stay crate-context-internal to the evidence path. The two
/// projections cover the identical public fields but have independent
/// visibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaPreparedStateSnapshot {
    /// Mirror of [`SagaPreparedState::StandingPairCreate`].
    StandingPairCreate(StandingPairCreateSnapshot),
    /// Mirror of [`SagaPreparedState::CrossContextToolInvocation`].
    CrossContextToolInvocation(CrossContextToolInvocationSnapshot),
    /// Mirror of [`SagaPreparedState::BroadcastHostingHandshake`].
    BroadcastHostingHandshake(BroadcastHostingHandshakeSnapshot),
}

/// Public snapshot payload for [`SagaPreparedState::StandingPairCreate`]
/// (§5.15.8; all fields public, not bearer-bearing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPairCreateSnapshot {
    /// `peer_did.0`.
    pub peer_did: String,
    /// `local_did.0`.
    pub local_did: String,
    /// The raw 32-byte derived context id.
    pub derived_context_id: [u8; 32],
    /// `Some` on the A-side; `None` on the B-side (§5.15.8 "Prepare-B").
    ///
    /// `private_interfaces` is allowed for the same deliberate asymmetry as
    /// the live [`StandingPairCreatePrepared::creation_receipt`] field: the
    /// field is `pub` (the snapshot rides the public [`ContextSnapshot`]
    /// surface) while [`CreationReceipt`] is `pub(in crate::context)`.
    #[allow(private_interfaces)]
    pub creation_receipt: Option<CreationReceipt>,
}

/// Public snapshot payload for
/// [`SagaPreparedState::CrossContextToolInvocation`] (§6.2.4 "Public-metadata
/// journaling"; all eight fields public, not bearer-bearing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContextToolInvocationSnapshot {
    /// The raw 32-byte caller context id.
    pub caller_context_id: [u8; 32],
    /// The raw 32-byte target context id.
    pub target_context_id: [u8; 32],
    /// `caller_did.0`.
    pub caller_did: String,
    /// Context-local tool registration id.
    pub tool_registration_id: String,
    /// UCAN proof reference (token id), not the proof bytes.
    pub ucan_proof_id: String,
    /// B's Prepare-B captured clock value.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire nonce.
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound depth = `incoming chain_depth + 1`.
    pub recorded_chain_depth: u8,
}

/// Public snapshot payload for
/// [`SagaPreparedState::BroadcastHostingHandshake`] (§5.14.2; all fields
/// public, not bearer-bearing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastHostingHandshakeSnapshot {
    /// The raw 32-byte hosting context id.
    pub host_context_id: [u8; 32],
    /// The raw 32-byte broadcast context id being hosted.
    pub broadcast_context_id: [u8; 32],
    /// `subscriber_did.0`.
    pub subscriber_did: String,
    /// Encoded `BroadcastHostConfig` bytes (opaque pending the broadcast
    /// handler's actor migration).
    pub broadcast_host_config_bytes: Vec<u8>,
}

impl SagaPreparedStateSnapshot {
    /// Project a live [`SagaPreparedState`] onto its serializable Class-S
    /// snapshot mirror.
    ///
    /// The match is exhaustive — a new [`SagaPreparedState`] variant must add
    /// a branch here, so it cannot be silently dropped from the snapshot.
    #[must_use]
    pub fn from_prepared(prepared: &SagaPreparedState) -> Self {
        match prepared {
            SagaPreparedState::StandingPairCreate(inner) => {
                Self::StandingPairCreate(StandingPairCreateSnapshot {
                    peer_did: inner.peer_did.0.clone(),
                    local_did: inner.local_did.0.clone(),
                    derived_context_id: inner.derived_context_id,
                    creation_receipt: inner.creation_receipt.clone(),
                })
            }
            SagaPreparedState::CrossContextToolInvocation(inner) => {
                Self::CrossContextToolInvocation(CrossContextToolInvocationSnapshot {
                    caller_context_id: inner.caller_context_id,
                    target_context_id: inner.target_context_id,
                    caller_did: inner.caller_did.0.clone(),
                    tool_registration_id: inner.tool_registration_id.clone(),
                    ucan_proof_id: inner.ucan_proof_id.clone(),
                    recorded_timestamp_ms: inner.recorded_timestamp_ms,
                    recorded_nonce: inner.recorded_nonce,
                    recorded_chain_depth: inner.recorded_chain_depth,
                })
            }
            SagaPreparedState::BroadcastHostingHandshake(inner) => {
                Self::BroadcastHostingHandshake(BroadcastHostingHandshakeSnapshot {
                    host_context_id: inner.host_context_id,
                    broadcast_context_id: inner.broadcast_context_id,
                    subscriber_did: inner.subscriber_did.0.clone(),
                    broadcast_host_config_bytes: inner.broadcast_host_config_bytes.clone(),
                })
            }
        }
    }

    /// Rehydrate a live [`SagaPreparedState`] from its snapshot mirror — the
    /// same-node restore path (ADR-049 §9 crash recovery). The inverse of
    /// [`Self::from_prepared`].
    #[must_use]
    pub fn into_prepared(self) -> SagaPreparedState {
        match self {
            Self::StandingPairCreate(snap) => {
                SagaPreparedState::StandingPairCreate(StandingPairCreatePrepared {
                    peer_did: DID(snap.peer_did),
                    local_did: DID(snap.local_did),
                    derived_context_id: snap.derived_context_id,
                    creation_receipt: snap.creation_receipt,
                })
            }
            Self::CrossContextToolInvocation(snap) => {
                SagaPreparedState::CrossContextToolInvocation(CrossContextToolInvocationPrepared {
                    caller_context_id: snap.caller_context_id,
                    target_context_id: snap.target_context_id,
                    caller_did: DID(snap.caller_did),
                    tool_registration_id: snap.tool_registration_id,
                    ucan_proof_id: snap.ucan_proof_id,
                    recorded_timestamp_ms: snap.recorded_timestamp_ms,
                    recorded_nonce: snap.recorded_nonce,
                    recorded_chain_depth: snap.recorded_chain_depth,
                })
            }
            Self::BroadcastHostingHandshake(snap) => {
                SagaPreparedState::BroadcastHostingHandshake(BroadcastHostingHandshakePrepared {
                    host_context_id: snap.host_context_id,
                    broadcast_context_id: snap.broadcast_context_id,
                    subscriber_did: DID(snap.subscriber_did),
                    broadcast_host_config_bytes: snap.broadcast_host_config_bytes,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Committed cross-context tool-invocation capture (spec §6.2.4)
// ---------------------------------------------------------------------------

/// Durable, `SagaId`-keyed capture of a COMMITTED cross-context tool
/// invocation, held on the TARGET (B) actor (spec §6.2.4 "Exactly-once
/// execution with durable output capture").
///
/// The tool executes **exactly once**; its output + the signed
/// [`CrossContextToolReceipt`] are captured here so a Commit replayed after a
/// crash (§17.16.4) re-emits the STORED output and re-emits the IDENTICAL
/// signed receipt — **never re-invoking the tool** and never minting a fresh
/// `tool_invoked_event_id`. Both the receipt and the raw output are reproduced
/// byte-for-byte from this record.
///
/// **Class S.** Held in
/// [`PerContextState.xctx_committed_outputs`](crate::context::actor::state::PerContextState::xctx_committed_outputs)
/// and synchronously persisted fail-closed (ADR-049 §9) the same way
/// `saga_pending` is — a crash that rolled the capture back behind an acked
/// Commit-B would let a replayed Commit re-invoke the tool, breaking the
/// exactly-once guarantee.
///
/// **Not bearer-bearing.** The receipt and tool output are public protocol
/// artifacts (the receipt is the signed return-path response; the output is
/// the tool result A already receives). There is no §9.4.3 secret here, so —
/// unlike [`SagaPreparedState`] — this type derives `Serialize`/`Clone`
/// directly and rides the public [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// surface without a separate mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedToolInvocation {
    /// The target's signed receipt over the staged provenance + output hash +
    /// event id. Re-emitted verbatim on a replayed Commit so the signature
    /// preimage reproduces byte-for-byte.
    pub receipt: scp_protocol::context::tools::cross_context_saga::CrossContextToolReceipt,
    /// The captured tool output bytes — the receipt's `output_jcs`, stored
    /// alongside so a replay re-emits the exact output A originally received.
    #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
    pub output_bytes: Vec<u8>,
    /// The `SagaId`-stable `ToolInvoked` event-log entry id (also carried on
    /// the receipt; stored explicitly so a replay re-acks the same id without
    /// re-deriving it).
    pub tool_invoked_event_id: String,
}

/// Caller-side (A-owned) durable reversal record for a cross-context tool
/// invocation's Prepare-A economy reservation (spec §6.2.4 "Reservation release
/// on every terminal path").
///
/// Prepare-A durably persists the caller's velocity / budget / hard-rate-limit
/// deductions and authorizes the external payment escrow, but the live
/// [`ToolEconomyReservation`](crate::context::tools_helpers::ToolEconomyReservation)
/// RAII carrier that holds the means to reverse them lives ONLY in the
/// supervisor's in-memory saga context — it dies with an actor/process crash.
/// On a `PreparingB`-window crash the §17.16.4 recovery sweep re-drives the
/// saga to a CLEAN abort by sending `Abort { reservation: None }` to the caller
/// actor; with no carrier, the persisted deductions could never be reversed and
/// the escrow could never be voided, durably OVER-CHARGING the caller and
/// LEAKING the external payment hold. This record is the durable, by-`SagaId`
/// reversal evidence that closes that gap: it carries exactly what is needed to
/// reverse THIS saga's caller-side contribution without the volatile carrier.
///
/// **Carrier-authoritative; record is the crash-only fallback.** The live
/// `Abort { Some(reservation) }` and Commit-A paths still reverse / settle via
/// the carrier (whose `VelocityRollbackToken` is valid in-process and whose
/// escrow handle is live), then CONSUME this record (remove without
/// re-reversing). The record's own reversal runs ONLY when the carrier is
/// absent (`Abort { None }`), so the two reversal paths are mutually exclusive
/// by construction and a saga is never double-reversed.
///
/// **Class S** — synchronously persisted fail-closed (ADR-049 §9): inserted at
/// Prepare-A in the SAME Class-S snapshot as the deduction it reverses, so the
/// deduction and its reversal evidence land (and roll back) atomically. Survives
/// same-node restore; dropped on cross-node export/import (caller economy is
/// local — a foreign node must never drive local reversal).
///
/// **`NeedsRepair` interaction (spec §6.2.4 "`NeedsRepair` reservation
/// semantics").** The record's reversal is reached ONLY through the
/// crash-recovery `Abort { None }`, which the §17.16.4 recovery sweep drives
/// EXCLUSIVELY for a `PreparingB`-journal entry (the pre-Commit crash window). A
/// saga that progressed to Committing / `NeedsRepair` is NEVER re-driven through
/// that abort — `NeedsRepair` is a terminal carryover that holds the escrow for
/// operator repair (via the carrier's `hold_external_for_repair`), so this
/// record is never auto-reversed for it and the held escrow is never wrongly
/// voided. Its compaction is therefore tied to saga-journal retention, like
/// [`CommittedToolInvocation`] — a `NeedsRepair` saga's inert leftover record is
/// pruned with the journal entry it belongs to.
///
/// **Not bearer-bearing.** Every field is public economy metadata —
/// [`PaymentAuthorization`](crate::economy::adapter::PaymentAuthorization) is
/// the same serde type the payment rail issues, and the velocity entry is
/// reversed by its TIMESTAMP (the non-durable `VelocityRollbackToken` is
/// deliberately NOT stored — a restored tracker re-synthesizes sequence numbers,
/// so a persisted token could never match). There is no §9.4.3 secret, so this
/// type derives `Serialize`/`Clone` directly and rides the public
/// [`ContextSnapshot`](crate::context::state::ContextSnapshot) surface without a
/// separate mirror, exactly like [`CommittedToolInvocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerReservationRecord {
    /// The caller DID the reservation was made for — the key for budget /
    /// velocity / hard-rate-limit reversal against the actor's owned trackers.
    pub actor_did: DID,
    /// The budget amount deducted at Prepare-A (`None` for a free action).
    /// Reversed via `budget_tracker.reverse_spend` on the crash-abort path.
    pub deducted_cost: Option<scp_protocol::economy::types::Amount>,
    /// Whether the hard-rate-limit token consumed at Prepare-A must be refunded
    /// on reversal (mirrors `ToolEconomyTicket::needs_hard_rate_limit_refund`).
    pub needs_hard_rate_limit_refund: bool,
    /// Unix-seconds timestamp of the Prepare-A velocity entry. The velocity
    /// reversal removes the single entry recorded at this timestamp via
    /// `SenderVelocityTracker::rollback_one_at` — durable across a restore where
    /// the original rollback token is meaningless.
    pub recorded_at_secs: u64,
    /// The external payment escrow authorization to void on reversal (`None`
    /// when no economic policy / payment adapter is configured). Serde-safe; the
    /// `PreparedAction`/`ActionEnvelope` wrappers are NOT, so only the
    /// authorization handle is persisted.
    pub escrow_authorization: Option<crate::economy::adapter::PaymentAuthorization>,
    /// Spawn-generation of the actor instance the reservation was made against
    /// (`PerContextState::generation`). The crash-abort reversal is
    /// generation-checked: on a MISMATCH (the actor was despawned + respawned —
    /// e.g. an import replace — between Prepare-A and the recovery abort) the
    /// local budget / velocity / hard-rate-limit MUST NOT be touched (that would
    /// be a confused-deputy write to the WRONG instance); only the external
    /// escrow is voided.
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn alice() -> DID {
        DID("did:example:alice".to_owned())
    }
    fn bob() -> DID {
        DID("did:example:bob".to_owned())
    }

    fn sample_receipt() -> CreationReceipt {
        CreationReceipt::new_pending(format!("standing-{}", "cd".repeat(32)), &alice(), &bob())
    }

    #[test]
    fn standing_pair_create_a_side_constructs() {
        // A-side: local_did = did_lo (alice), receipt present.
        let receipt = sample_receipt();
        let state = SagaPreparedState::StandingPairCreate(StandingPairCreatePrepared {
            peer_did: bob(),
            local_did: alice(),
            derived_context_id: [1u8; 32],
            creation_receipt: Some(receipt.clone()),
        });
        match state {
            SagaPreparedState::StandingPairCreate(inner) => {
                assert_eq!(inner.peer_did, bob());
                assert_eq!(inner.local_did, alice());
                assert_eq!(inner.derived_context_id, [1u8; 32]);
                assert_eq!(inner.creation_receipt, Some(receipt));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn standing_pair_create_b_side_has_no_receipt() {
        // B-side: local_did = did_hi (bob), receipt absent (§5.15.8
        // Prepare-B — B authors no CreationReceipt).
        let inner = StandingPairCreatePrepared {
            peer_did: alice(),
            local_did: bob(),
            derived_context_id: [2u8; 32],
            creation_receipt: None,
        };
        assert_eq!(inner.local_did, bob());
        assert!(inner.creation_receipt.is_none());
    }

    #[test]
    fn standing_pair_evidence_round_trips_a_side() {
        let original = StandingPairCreatePrepared {
            peer_did: bob(),
            local_did: alice(),
            derived_context_id: [9u8; 32],
            creation_receipt: Some(sample_receipt()),
        };
        let bytes = original.to_evidence_bytes().unwrap();
        let back = StandingPairCreatePrepared::from_evidence_bytes(&bytes).unwrap();
        assert_eq!(back.peer_did, original.peer_did);
        assert_eq!(back.local_did, original.local_did);
        assert_eq!(back.derived_context_id, original.derived_context_id);
        assert_eq!(back.creation_receipt, original.creation_receipt);
    }

    #[test]
    fn standing_pair_evidence_round_trips_b_side() {
        let original = StandingPairCreatePrepared {
            peer_did: alice(),
            local_did: bob(),
            derived_context_id: [3u8; 32],
            creation_receipt: None,
        };
        let bytes = original.to_evidence_bytes().unwrap();
        let back = StandingPairCreatePrepared::from_evidence_bytes(&bytes).unwrap();
        assert_eq!(back.peer_did, original.peer_did);
        assert_eq!(back.local_did, original.local_did);
        assert_eq!(back.derived_context_id, original.derived_context_id);
        assert!(back.creation_receipt.is_none());
    }

    #[test]
    fn cross_context_tool_invocation_constructs() {
        let state =
            SagaPreparedState::CrossContextToolInvocation(CrossContextToolInvocationPrepared {
                caller_context_id: [5u8; 32],
                target_context_id: [6u8; 32],
                caller_did: alice(),
                tool_registration_id: "calculator-v1".to_owned(),
                ucan_proof_id: "ucan-token-abcdef".to_owned(),
                recorded_timestamp_ms: 1_725_000_000_123,
                recorded_nonce: [0xABu8; 16],
                recorded_chain_depth: 3,
            });
        match state {
            SagaPreparedState::CrossContextToolInvocation(inner) => {
                assert_eq!(inner.caller_context_id, [5u8; 32]);
                assert_eq!(inner.target_context_id, [6u8; 32]);
                assert_eq!(inner.caller_did, alice());
                assert_eq!(inner.tool_registration_id, "calculator-v1");
                assert_eq!(inner.ucan_proof_id, "ucan-token-abcdef");
                assert_eq!(inner.recorded_timestamp_ms, 1_725_000_000_123);
                assert_eq!(inner.recorded_nonce, [0xABu8; 16]);
                assert_eq!(inner.recorded_chain_depth, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cross_context_tool_invocation_evidence_round_trips_all_eight_fields() {
        let original = CrossContextToolInvocationPrepared {
            caller_context_id: [0x11u8; 32],
            target_context_id: [0x22u8; 32],
            caller_did: alice(),
            tool_registration_id: "calculator-v1".to_owned(),
            ucan_proof_id: "ucan-token-abcdef".to_owned(),
            recorded_timestamp_ms: 1_725_000_000_123,
            recorded_nonce: [0xCDu8; 16],
            recorded_chain_depth: 7,
        };
        let bytes = original.to_evidence_bytes().unwrap();
        let back = CrossContextToolInvocationPrepared::from_evidence_bytes(&bytes).unwrap();
        assert_eq!(back.caller_context_id, original.caller_context_id);
        assert_eq!(back.target_context_id, original.target_context_id);
        assert_eq!(back.caller_did, original.caller_did);
        assert_eq!(back.tool_registration_id, original.tool_registration_id);
        assert_eq!(back.ucan_proof_id, original.ucan_proof_id);
        assert_eq!(back.recorded_timestamp_ms, original.recorded_timestamp_ms);
        assert_eq!(back.recorded_nonce, original.recorded_nonce);
        assert_eq!(back.recorded_chain_depth, original.recorded_chain_depth);
    }

    #[test]
    fn cross_context_tool_invocation_wire_round_trips_via_messagepack() {
        // Exercises the explicit Wire mirror directly, matching the
        // §9.4.3 non-derive discipline: the live enum stays non-Serialize,
        // serialization flows only through the Wire type.
        let wire = CrossContextToolInvocationPreparedWire {
            caller_context_id: [0x33u8; 32],
            target_context_id: [0x44u8; 32],
            caller_did: bob().0,
            tool_registration_id: "translator-v2".to_owned(),
            ucan_proof_id: "ucan-token-99".to_owned(),
            recorded_timestamp_ms: 42,
            recorded_nonce: [0xEEu8; 16],
            recorded_chain_depth: 255,
        };
        let bytes = rmp_serde::to_vec_named(&wire).unwrap();
        let back: CrossContextToolInvocationPreparedWire = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back, wire);
    }

    #[test]
    fn broadcast_hosting_handshake_constructs() {
        let state =
            SagaPreparedState::BroadcastHostingHandshake(BroadcastHostingHandshakePrepared {
                host_context_id: [6u8; 32],
                broadcast_context_id: [7u8; 32],
                subscriber_did: bob(),
                broadcast_host_config_bytes: vec![0xDD; 48],
            });
        match state {
            SagaPreparedState::BroadcastHostingHandshake(inner) => {
                assert_eq!(inner.host_context_id, [6u8; 32]);
                assert_eq!(inner.broadcast_context_id, [7u8; 32]);
                assert_eq!(inner.subscriber_did, bob());
                assert_eq!(inner.broadcast_host_config_bytes, vec![0xDD; 48]);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// Compile-time witnesses that the prepared-state types ARE
    /// `Send + Sync` (required for `ActorDeps` movement into
    /// `tokio::spawn`), the only auto-trait obligation they carry.
    ///
    /// The wrapping enum [`SagaPreparedState`] still does NOT derive
    /// `Clone`, `Debug`, `Display`, `Serialize`, or `Deserialize`,
    /// preserving the §9.4.3 static barrier so a future bearer-bearing
    /// variant cannot leak through auto-generated impls. No current
    /// variant is bearer-bearing (custody handover withdrawn — ADR-049
    /// §4).
    #[test]
    fn types_are_send_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SagaPreparedState>();
        assert_send_sync::<StandingPairCreatePrepared>();
        assert_send_sync::<CrossContextToolInvocationPrepared>();
        assert_send_sync::<BroadcastHostingHandshakePrepared>();
    }

    /// The Class-S snapshot mirror (ADR-049 §9 line 144) must serialize, then
    /// deserialize, then rehydrate to an identical live `SagaPreparedState`
    /// for the standing-pair variant (receipt-bearing A-side).
    #[test]
    fn snapshot_mirror_round_trips_standing_pair_a_side() {
        let prepared = SagaPreparedState::StandingPairCreate(StandingPairCreatePrepared {
            peer_did: bob(),
            local_did: alice(),
            derived_context_id: [0x5Cu8; 32],
            creation_receipt: Some(sample_receipt()),
        });
        let mirror = SagaPreparedStateSnapshot::from_prepared(&prepared);
        let bytes = serde_json::to_vec(&mirror).unwrap();
        let back: SagaPreparedStateSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mirror, back);
        match back.into_prepared() {
            SagaPreparedState::StandingPairCreate(inner) => {
                assert_eq!(inner.peer_did, bob());
                assert_eq!(inner.local_did, alice());
                assert_eq!(inner.derived_context_id, [0x5Cu8; 32]);
                assert_eq!(inner.creation_receipt, Some(sample_receipt()));
            }
            _ => panic!("wrong variant after rehydrate"),
        }
    }

    /// Same round-trip for the cross-context tool-invocation variant — all
    /// eight journaled fields must survive (§6.2.4 public-metadata journaling).
    #[test]
    fn snapshot_mirror_round_trips_cross_context_tool() {
        let prepared =
            SagaPreparedState::CrossContextToolInvocation(CrossContextToolInvocationPrepared {
                caller_context_id: [0x1Au8; 32],
                target_context_id: [0x2Bu8; 32],
                caller_did: alice(),
                tool_registration_id: "calc-v2".to_owned(),
                ucan_proof_id: "ucan-xyz".to_owned(),
                recorded_timestamp_ms: 1_700_111_222_333,
                recorded_nonce: [0x9Eu8; 16],
                recorded_chain_depth: 7,
            });
        let mirror = SagaPreparedStateSnapshot::from_prepared(&prepared);
        let bytes = serde_json::to_vec(&mirror).unwrap();
        let back: SagaPreparedStateSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mirror, back);
        match back.into_prepared() {
            SagaPreparedState::CrossContextToolInvocation(inner) => {
                assert_eq!(inner.caller_context_id, [0x1Au8; 32]);
                assert_eq!(inner.target_context_id, [0x2Bu8; 32]);
                assert_eq!(inner.caller_did, alice());
                assert_eq!(inner.tool_registration_id, "calc-v2");
                assert_eq!(inner.ucan_proof_id, "ucan-xyz");
                assert_eq!(inner.recorded_timestamp_ms, 1_700_111_222_333);
                assert_eq!(inner.recorded_nonce, [0x9Eu8; 16]);
                assert_eq!(inner.recorded_chain_depth, 7);
            }
            _ => panic!("wrong variant after rehydrate"),
        }
    }

    /// Same round-trip for the broadcast-hosting-handshake variant
    /// (§5.14.2 public fields).
    #[test]
    fn snapshot_mirror_round_trips_broadcast_hosting() {
        let prepared =
            SagaPreparedState::BroadcastHostingHandshake(BroadcastHostingHandshakePrepared {
                host_context_id: [0x3Cu8; 32],
                broadcast_context_id: [0x4Du8; 32],
                subscriber_did: bob(),
                broadcast_host_config_bytes: vec![0xAB, 0xCD, 0xEF],
            });
        let mirror = SagaPreparedStateSnapshot::from_prepared(&prepared);
        let bytes = serde_json::to_vec(&mirror).unwrap();
        let back: SagaPreparedStateSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mirror, back);
        match back.into_prepared() {
            SagaPreparedState::BroadcastHostingHandshake(inner) => {
                assert_eq!(inner.host_context_id, [0x3Cu8; 32]);
                assert_eq!(inner.broadcast_context_id, [0x4Du8; 32]);
                assert_eq!(inner.subscriber_did, bob());
                assert_eq!(inner.broadcast_host_config_bytes, vec![0xAB, 0xCD, 0xEF]);
            }
            _ => panic!("wrong variant after rehydrate"),
        }
    }
}
