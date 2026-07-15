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

use scp_did::DID;
use scp_protocol::context::outlets::stream::MerkleFrontier;
use scp_protocol::economy::types::Amount;
use serde::{Deserialize, Serialize};

use crate::context::supervisor::saga_journal::SagaId;

// ---------------------------------------------------------------------------
// Discriminated union over the ADR-049 §3 saga type-space (one variant today; extensible)
// ---------------------------------------------------------------------------

/// Prepared (Prepare-time) snapshot for an in-flight saga.
///
/// The sole production saga is cross-context outlet invocation (spec §6.2.4);
/// the other contemplated saga types (custody handover, standing-pair create,
/// broadcast hosting handshake) were all withdrawn as category errors
/// (ADR-049 §3/§3b), so today this carries a single variant.
///
/// It is retained as a discriminated union so that adding a new saga type
/// later is a compile error at every match site — the default branch is not
/// permitted, and no future variant can be silently dropped from the replay
/// or snapshot paths.
///
/// The variant carries every field needed to replay Commit deterministically
/// from the Prepare-time snapshot; see the variant's own documentation for the
/// per-saga shape.
///
/// **Non-derives.** No `Clone`, `Debug`, `Display`, `Serialize`,
/// `Deserialize` — see module-level documentation for rationale.
#[allow(
    clippy::large_enum_variant,
    reason = "The streaming variant carries the durable Merkle frontier + the \
              SCP-OUT-046 settlement ledger; the large variant is the NORMAL \
              durable-state case (not an error path), and boxing a hot durable \
              slot to equalize with the unary variant is negative value."
)]
pub enum SagaPreparedState {
    /// Cross-context outlet invocation. The UCAN proof bytes are NOT carried
    /// here — only the proof's identifier — to keep the prepared-state non-
    /// secret-bearing.
    CrossContextOutletInvocation(CrossContextOutletInvocationPrepared),
    /// Cross-context **streaming** outlet invocation (ADR-061 seal phase,
    /// §6.2.5 streaming saga). Carries the same replay-deterministic receipt
    /// inputs as the unary variant plus the live, `SagaId`-keyed durable
    /// capture (an O(log n) Merkle frontier + credit ledger) the seal phase
    /// reads at stream-close to finalize `stream_manifest_hash` and settle
    /// escrow. Like the unary variant it is non-secret-bearing (frontier
    /// peaks + counters + public metadata), so it rides the Class-S snapshot
    /// mirror rather than a `Zeroizing` branch.
    ///
    /// The production constructor lands with the streaming seal-phase FSM
    /// (SCP-OUT-046 PR-B); PR-A stages the type, its Class-S mirror, and the
    /// compile-forced match barrier, mirroring how the unary variant's
    /// serializable mirror shipped ahead of its dispatch wiring.
    CrossContextStreamingOutletInvocation(CrossContextStreamingOutletInvocationPrepared),
}

// ---------------------------------------------------------------------------
// Cross-context outlet invocation
// ---------------------------------------------------------------------------

/// Staged state for a cross-context outlet-invocation saga.
///
/// This is the **public-metadata journal projection** of the
/// `CrossContextOutletInvoke` envelope (spec §6.2.4 "Public-metadata
/// journaling") — eight fields, all public.
///
/// **Not bearer-bearing.** The UCAN proof bytes are NOT carried here;
/// only the proof's identifier (token ID). The receiving actor re-resolves
/// the proof from its own UCAN store at Commit time, re-running the full §7
/// validation re-bound to `caller_did` plus `outlet_registration_id`. This
/// keeps the prepared-state non-secret-bearing (`mark_resolved(secret_bearing
/// = false)`); the §9.4.3 commitment path stays dormant.
///
/// **B-controlled, replay-deterministic fields.** Three of the eight fields
/// are staged at Prepare-B precisely so a Commit replayed after a crash —
/// when B no longer holds the wire envelope — reproduces the signed
/// `CrossContextOutletReceipt` preimage byte-for-byte from durable state:
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
/// [`CrossContextOutletInvocationPreparedWire`] mirror (`MessagePack` of the
/// public fields), reached through
/// [`CrossContextOutletInvocationPrepared::to_evidence_bytes`] /
/// [`CrossContextOutletInvocationPrepared::from_evidence_bytes`], mirroring
/// the `JournalEntryWire`/`EvidenceWire` discipline in
/// [`crate::context::supervisor::saga_journal`].
pub struct CrossContextOutletInvocationPrepared {
    /// Calling context ID — the raw 32-byte context-id digest (never a
    /// `"standing-"`-prefixed string), matching the id-form rule §6.2.4
    /// states for both context ids.
    pub caller_context_id: [u8; 32],
    /// Target context ID — B's own context, the context in which B executes
    /// the outlet (the verified `target_context` of the established interface,
    /// §6.2.4 "Target-context binding"). Raw 32-byte digest, same id-form as
    /// `caller_context_id`.
    pub target_context_id: [u8; 32],
    /// Calling DID.
    pub caller_did: DID,
    /// Outlet registration ID (target outlet's stable identifier). Context-LOCAL
    /// — it indexes B's own outlet registry.
    pub outlet_registration_id: String,
    /// UCAN proof reference (token ID), NOT the proof bytes. Resolved
    /// against the receiving actor's UCAN store at Commit time.
    pub ucan_proof_id: String,
    /// B's wall-clock value captured ONCE at Prepare-B (§6.2.4 "Recorded
    /// timestamp"). Both the Commit-time `OutletInvoked` record and the
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
/// [`CrossContextOutletInvocationPrepared`], used to produce the journal
/// `evidence` (the `MessagePack` of the eight public journaled fields,
/// §6.2.4 "Public-metadata journaling"). The actor-side
/// [`CrossContextOutletInvocationPrepared`] is deliberately non-`Serialize`
/// because the wrapping [`SagaPreparedState`] enum carries the §9.4.3
/// non-derive barrier; this explicit mirror is the sanctioned serialization
/// path, matching the `JournalEntryWire`/`EvidenceWire` discipline in
/// [`crate::context::supervisor::saga_journal`].
///
/// All eight fields are public plan-metadata classified **public** — there
/// is no §9.4.3 secret commitment (`mark_resolved(secret_bearing=false)`).
/// `DID` is carried as its canonical string.
///
/// `dead_code` is allowed: this wire mirror and the `to_evidence_bytes` /
/// `from_evidence_bytes` helpers below are the journal-evidence path for the
/// cross-context outlet-invocation saga, consumed when the saga dispatch
/// wiring lands in a follow-on PR. The unit tests exercise the round-trip
/// now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub(in crate::context) struct CrossContextOutletInvocationPreparedWire {
    /// The raw 32-byte caller context id.
    pub caller_context_id: [u8; 32],
    /// The raw 32-byte target context id.
    pub target_context_id: [u8; 32],
    /// `caller_did.0`.
    pub caller_did: String,
    /// Context-local outlet registration id.
    pub outlet_registration_id: String,
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
impl CrossContextOutletInvocationPrepared {
    /// Encode the public prepared state to its journal `evidence` bytes —
    /// `MessagePack` of the [`CrossContextOutletInvocationPreparedWire`]
    /// mirror (§6.2.4 "Public-metadata journaling"). Classified **public**;
    /// the supervisor wraps these bytes in the standard `Zeroizing` envelope
    /// for uniformity only.
    ///
    /// # Errors
    ///
    /// Returns the `rmp_serde` encode error string if serialization fails.
    pub(in crate::context) fn to_evidence_bytes(&self) -> Result<Vec<u8>, String> {
        let wire = CrossContextOutletInvocationPreparedWire {
            caller_context_id: self.caller_context_id,
            target_context_id: self.target_context_id,
            caller_did: self.caller_did.0.clone(),
            outlet_registration_id: self.outlet_registration_id.clone(),
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
        let wire: CrossContextOutletInvocationPreparedWire =
            rmp_serde::from_slice(bytes).map_err(|e| format!("decode: {e}"))?;
        Ok(Self {
            caller_context_id: wire.caller_context_id,
            target_context_id: wire.target_context_id,
            caller_did: DID(wire.caller_did),
            outlet_registration_id: wire.outlet_registration_id,
            ucan_proof_id: wire.ucan_proof_id,
            recorded_timestamp_ms: wire.recorded_timestamp_ms,
            recorded_nonce: wire.recorded_nonce,
            recorded_chain_depth: wire.recorded_chain_depth,
        })
    }
}

// ---------------------------------------------------------------------------
// Cross-context STREAMING outlet invocation (ADR-061 seal phase; §6.2.5)
// ---------------------------------------------------------------------------

/// Staged state for a cross-context **streaming** outlet-invocation saga
/// (ADR-061 seal phase; spec §6.2.5 streaming saga).
///
/// The streaming saga reuses the §6.2.4 unary envelope but replaces the
/// single committed `output_jcs` with a `stream_manifest_hash` sealed at
/// stream-close from an incremental Merkle frontier. This prepared state
/// therefore carries the SAME eight replay-deterministic receipt inputs as
/// [`CrossContextOutletInvocationPrepared`] — so the seal can reproduce the
/// streaming receipt preimage byte-for-byte on a replayed Commit — plus the
/// live, `SagaId`-keyed **durable capture** the seal reads at close:
///
/// - `frontier` — the O(log n) RFC-6962 Merkle frontier over the emitted
///   chunk manifest. `frontier.root()` is the `stream_manifest_hash`; on a
///   mid-stream crash the recovery seals THIS (the last durable prefix) and
///   re-derives the root from the restored peaks without re-hashing the
///   payload set (ADR-061 write-through capture). No output bytes are staged
///   — the streaming receipt attests the root, not carried output.
/// - `reserved` / `billed` / `billed_count` — the Class-S credit ledger.
///   Settlement at close refunds `reserved − billed`; `billed_count` is the
///   §5.4.5 billable-`Data`-chunk count the escrow cross-check verifies.
/// - `cancel_ack_ceiling` — the `CancelAckTracker` ceiling that makes a
///   truncated close well-defined (the billing boundary a cancel pins).
///
/// **Not bearer-bearing.** Every field is public protocol metadata (frontier
/// peaks, counters, ids), so — like the unary variant — it rides the Class-S
/// snapshot mirror ([`CrossContextStreamingOutletInvocationSnapshot`]) and
/// the wrapping [`SagaPreparedState`] enum keeps its §9.4.3 non-derive
/// barrier.
///
/// The production constructor lands with the streaming seal-phase FSM
/// (SCP-OUT-046 PR-B). PR-A stages the type + its Class-S mirror + the
/// compile-forced match barrier, and is exercised by the snapshot round-trip
/// tests below.
pub struct CrossContextStreamingOutletInvocationPrepared {
    /// The `SagaId` this durable capture is keyed by (spec §6.2.5 "captured
    /// durably and incrementally … keyed by `SagaId`"). The SCP-OUT-046 seal
    /// FSM (PR-B) runs an off-mailbox seal task that holds this capture
    /// *detached* from the `saga_pending` map, so the id must live on the
    /// struct itself: the task keys its durable frontier write-backs — and the
    /// seal at stream-close — by this `SagaId` without a live map handle.
    pub saga_id: SagaId,
    /// Calling context ID — raw 32-byte digest (§6.2.4 id-form rule).
    pub caller_context_id: [u8; 32],
    /// Target context ID — B's own context (§6.2.4 "Target-context binding").
    pub target_context_id: [u8; 32],
    /// Calling DID.
    pub caller_did: DID,
    /// Outlet registration ID (context-local stable identifier).
    pub outlet_registration_id: String,
    /// UCAN proof reference (token ID), NOT the proof bytes.
    pub ucan_proof_id: String,
    /// B's wall-clock captured ONCE at Prepare-B (§6.2.4 "Recorded
    /// timestamp"); the receipt signature draws `timestamp_ms` from this.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire `nonce` (§6.2.4).
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound chain depth = `incoming chain_depth + 1`
    /// (§6.2.4 "Chain-depth enforcement").
    pub recorded_chain_depth: u8,
    /// The live incremental Merkle frontier over the emitted chunk manifest.
    /// `frontier.root()` is the sealed `stream_manifest_hash`.
    pub frontier: MerkleFrontier,
    /// Total credit reserved at Prepare (the escrow cap). Refund at close is
    /// `reserved − billed`.
    pub reserved: Amount,
    /// The per-billable-`Data`-chunk price pinned at the Commit-transition
    /// (ADR-061 seal phase). Held on the durable ledger so the seal at
    /// stream-close can reconstruct the escrow (`StreamEscrow::from_reserved`)
    /// and settle `refund = reserved − billed` with NO live pump — the pump is
    /// gone after a crash, so escrow MUST settle from this durable ledger, not
    /// the in-memory `PumpEscrowGuard`.
    pub cost_per_chunk: Amount,
    /// Credit billed so far (advances with the frontier's billable chunks;
    /// `cost_per_chunk × frontier.billed_count()`). Class-S monotonic (KEEP).
    pub billed: Amount,
    /// The §5.4.5 billable-`Data`-chunk count captured alongside the ledger;
    /// the escrow cross-check verifies it against `frontier.billed_count()`.
    pub billed_count: u32,
    /// The `CancelAckTracker` ceiling that bounds a truncated close (the
    /// cancel-ack billing boundary; `u64::MAX` when the stream has no cancel).
    pub cancel_ack_ceiling: u64,
    /// The stream `request_id` (SCP-OUT-046 settlement ledger) — the key the
    /// close-time [`StreamSettlement`](crate::context::outlets::invoke::StreamSettlement)
    /// receipt + event-log provenance anchor to. Staged at Prepare-B so the
    /// seal (and crash recovery) settle against the SAME id the pump billed.
    pub request_id: [u8; 16],
    /// The §5.4.5 MED-HIGH economic policy snapshotted at acceptance
    /// (SCP-OUT-046 settlement ledger). Stored as the raw
    /// [`EconomicPolicy`](scp_protocol::economy::types::EconomicPolicy) (the
    /// `EconomicPolicySnapshot` wrapper is not `Serialize`) so the seal captures
    /// the billed `PaymentReceipt` for service rendered even if B is torn down
    /// mid-stream. `None` for zero-cost / Query streams.
    pub economic_policy: Option<scp_protocol::economy::types::EconomicPolicy>,
    /// The §7.3.8 worst-case cumulative-counter amount RESERVED at the open-time
    /// final gate (SCP-OUT-046 settlement ledger). The seal releases the UNSPENT
    /// portion (`reserved − billed_count × cost_per_chunk`) back to the counter
    /// at close. `0` when no cap / no store / `cost_per_chunk == 0`. Staged
    /// post-open via [`SagaPhaseMessage::StreamStageCounterReserve`](crate::context::actor::commands::SagaPhaseMessage::StreamStageCounterReserve).
    pub amount_cumulative_reserved: u64,
    /// The invoker-declared `estimated_chunk_count` (SCP-OUT-046 settlement
    /// ledger; diagnostics / event field only — the release reconciles by
    /// AMOUNT). Staged post-open alongside `amount_cumulative_reserved`.
    pub reserved_chunks: u32,
    /// The opening UCAN CID (SCP-OUT-046 settlement ledger) — the durable
    /// `AmountCumulative` counter's key, so the close-time release targets the
    /// same counter the open reserved. Empty when no counter reservation.
    /// Staged post-open alongside `amount_cumulative_reserved`.
    pub ucan_cid: String,
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
/// The variant carries its OWN public-field payload struct rather than
/// reusing the `pub(in crate::context)` journal `*Wire` mirror: the
/// snapshot rides the fully-`pub` [`ContextSnapshot`] surface, while the
/// journal wire stays crate-context-internal to the evidence path. The two
/// projections cover the identical public fields but have independent
/// visibility. A future saga type would add its own branch here under the
/// same discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "Mirrors SagaPreparedState — the streaming snapshot carries the \
              durable frontier + SCP-OUT-046 settlement ledger; the large \
              variant is the normal durable-snapshot case."
)]
pub enum SagaPreparedStateSnapshot {
    /// Mirror of [`SagaPreparedState::CrossContextOutletInvocation`].
    CrossContextOutletInvocation(CrossContextOutletInvocationSnapshot),
    /// Mirror of [`SagaPreparedState::CrossContextStreamingOutletInvocation`].
    CrossContextStreamingOutletInvocation(CrossContextStreamingOutletInvocationSnapshot),
}

/// Public snapshot payload for
/// [`SagaPreparedState::CrossContextOutletInvocation`] (§6.2.4 "Public-metadata
/// journaling"; all eight fields public, not bearer-bearing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContextOutletInvocationSnapshot {
    /// The raw 32-byte caller context id.
    pub caller_context_id: [u8; 32],
    /// The raw 32-byte target context id.
    pub target_context_id: [u8; 32],
    /// `caller_did.0`.
    pub caller_did: String,
    /// Context-local outlet registration id.
    pub outlet_registration_id: String,
    /// UCAN proof reference (token id), not the proof bytes.
    pub ucan_proof_id: String,
    /// B's Prepare-B captured clock value.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire nonce.
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound depth = `incoming chain_depth + 1`.
    pub recorded_chain_depth: u8,
}

/// Public snapshot payload for the streaming variant (ADR-061 seal phase;
/// §6.2.5 streaming saga).
///
/// Mirrors [`CrossContextStreamingOutletInvocationPrepared`] with `caller_did`
/// as its canonical string and the now-`Serialize` [`MerkleFrontier`] embedded
/// directly — the frontier's four private fields are its minimal complete
/// state, so the derive captures them losslessly and `root()` reproduces
/// bit-identically after restore (the AC7 durable-prefix reproducibility
/// property). Not bearer-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContextStreamingOutletInvocationSnapshot {
    /// The `SagaId` the durable capture is keyed by — mirror of the live
    /// field the PR-B off-mailbox seal task uses to key its frontier
    /// write-backs and the seal itself while detached from `saga_pending`.
    pub saga_id: String,
    /// The raw 32-byte caller context id.
    pub caller_context_id: [u8; 32],
    /// The raw 32-byte target context id.
    pub target_context_id: [u8; 32],
    /// `caller_did.0`.
    pub caller_did: String,
    /// Context-local outlet registration id.
    pub outlet_registration_id: String,
    /// UCAN proof reference (token id), not the proof bytes.
    pub ucan_proof_id: String,
    /// B's Prepare-B captured clock value.
    pub recorded_timestamp_ms: u64,
    /// B's staged copy of the 16-byte wire nonce.
    pub recorded_nonce: [u8; 16],
    /// B's re-derived inbound depth = `incoming chain_depth + 1`.
    pub recorded_chain_depth: u8,
    /// The incremental Merkle frontier, serialized verbatim; `root()`
    /// reproduces after restore.
    pub frontier: MerkleFrontier,
    /// Total credit reserved at Prepare (the escrow cap).
    pub reserved: Amount,
    /// The per-billable-`Data`-chunk price pinned at the Commit-transition; the
    /// seal reconstructs the escrow from `(cost_per_chunk, reserved)` at close.
    pub cost_per_chunk: Amount,
    /// Credit billed so far.
    pub billed: Amount,
    /// The §5.4.5 billable-`Data`-chunk count.
    pub billed_count: u32,
    /// The cancel-ack billing ceiling.
    pub cancel_ack_ceiling: u64,
    /// The stream `request_id` (SCP-OUT-046 settlement ledger).
    pub request_id: [u8; 16],
    /// The acceptance-time economic policy (raw, `Serialize`) — `None` for
    /// zero-cost / Query streams.
    pub economic_policy: Option<scp_protocol::economy::types::EconomicPolicy>,
    /// The §7.3.8 worst-case cumulative-counter amount reserved at open.
    pub amount_cumulative_reserved: u64,
    /// The invoker-declared `estimated_chunk_count` (diagnostics only).
    pub reserved_chunks: u32,
    /// The opening UCAN CID — the cumulative counter's key.
    pub ucan_cid: String,
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
            SagaPreparedState::CrossContextOutletInvocation(inner) => {
                Self::CrossContextOutletInvocation(CrossContextOutletInvocationSnapshot {
                    caller_context_id: inner.caller_context_id,
                    target_context_id: inner.target_context_id,
                    caller_did: inner.caller_did.0.clone(),
                    outlet_registration_id: inner.outlet_registration_id.clone(),
                    ucan_proof_id: inner.ucan_proof_id.clone(),
                    recorded_timestamp_ms: inner.recorded_timestamp_ms,
                    recorded_nonce: inner.recorded_nonce,
                    recorded_chain_depth: inner.recorded_chain_depth,
                })
            }
            SagaPreparedState::CrossContextStreamingOutletInvocation(inner) => {
                Self::CrossContextStreamingOutletInvocation(
                    CrossContextStreamingOutletInvocationSnapshot {
                        saga_id: inner.saga_id.0.clone(),
                        caller_context_id: inner.caller_context_id,
                        target_context_id: inner.target_context_id,
                        caller_did: inner.caller_did.0.clone(),
                        outlet_registration_id: inner.outlet_registration_id.clone(),
                        ucan_proof_id: inner.ucan_proof_id.clone(),
                        recorded_timestamp_ms: inner.recorded_timestamp_ms,
                        recorded_nonce: inner.recorded_nonce,
                        recorded_chain_depth: inner.recorded_chain_depth,
                        frontier: inner.frontier.clone(),
                        reserved: inner.reserved,
                        cost_per_chunk: inner.cost_per_chunk,
                        billed: inner.billed,
                        billed_count: inner.billed_count,
                        cancel_ack_ceiling: inner.cancel_ack_ceiling,
                        request_id: inner.request_id,
                        economic_policy: inner.economic_policy.clone(),
                        amount_cumulative_reserved: inner.amount_cumulative_reserved,
                        reserved_chunks: inner.reserved_chunks,
                        ucan_cid: inner.ucan_cid.clone(),
                    },
                )
            }
        }
    }

    /// Rehydrate a live [`SagaPreparedState`] from its snapshot mirror — the
    /// same-node restore path (ADR-049 §9 crash recovery). The inverse of
    /// [`Self::from_prepared`].
    #[must_use]
    pub fn into_prepared(self) -> SagaPreparedState {
        match self {
            Self::CrossContextOutletInvocation(snap) => {
                SagaPreparedState::CrossContextOutletInvocation(
                    CrossContextOutletInvocationPrepared {
                        caller_context_id: snap.caller_context_id,
                        target_context_id: snap.target_context_id,
                        caller_did: DID(snap.caller_did),
                        outlet_registration_id: snap.outlet_registration_id,
                        ucan_proof_id: snap.ucan_proof_id,
                        recorded_timestamp_ms: snap.recorded_timestamp_ms,
                        recorded_nonce: snap.recorded_nonce,
                        recorded_chain_depth: snap.recorded_chain_depth,
                    },
                )
            }
            Self::CrossContextStreamingOutletInvocation(snap) => {
                SagaPreparedState::CrossContextStreamingOutletInvocation(
                    CrossContextStreamingOutletInvocationPrepared {
                        saga_id: SagaId(snap.saga_id),
                        caller_context_id: snap.caller_context_id,
                        target_context_id: snap.target_context_id,
                        caller_did: DID(snap.caller_did),
                        outlet_registration_id: snap.outlet_registration_id,
                        ucan_proof_id: snap.ucan_proof_id,
                        recorded_timestamp_ms: snap.recorded_timestamp_ms,
                        recorded_nonce: snap.recorded_nonce,
                        recorded_chain_depth: snap.recorded_chain_depth,
                        frontier: snap.frontier,
                        reserved: snap.reserved,
                        cost_per_chunk: snap.cost_per_chunk,
                        billed: snap.billed,
                        billed_count: snap.billed_count,
                        cancel_ack_ceiling: snap.cancel_ack_ceiling,
                        request_id: snap.request_id,
                        economic_policy: snap.economic_policy,
                        amount_cumulative_reserved: snap.amount_cumulative_reserved,
                        reserved_chunks: snap.reserved_chunks,
                        ucan_cid: snap.ucan_cid,
                    },
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Committed cross-context outlet-invocation capture (spec §6.2.4)
// ---------------------------------------------------------------------------

/// Durable, `SagaId`-keyed capture of a COMMITTED cross-context outlet
/// invocation, held on the TARGET (B) actor (spec §6.2.4 "Exactly-once
/// execution with durable output capture").
///
/// The outlet executes **exactly once**; its output + the signed
/// [`CrossContextOutletReceipt`] are captured here so a Commit replayed after a
/// crash (§17.16.4) re-emits the STORED output and re-emits the IDENTICAL
/// signed receipt — **never re-invoking the outlet** and never minting a fresh
/// `outlet_invoked_event_id`. Both the receipt and the raw output are reproduced
/// byte-for-byte from this record.
///
/// **Class S.** Held in
/// [`PerContextState.xctx_committed_outputs`](crate::context::actor::state::PerContextState::xctx_committed_outputs)
/// and synchronously persisted fail-closed (ADR-049 §9) the same way
/// `saga_pending` is — a crash that rolled the capture back behind an acked
/// Commit-B would let a replayed Commit re-invoke the outlet, breaking the
/// exactly-once guarantee.
///
/// **Not bearer-bearing.** The receipt and outlet output are public protocol
/// artifacts (the receipt is the signed return-path response; the output is
/// the outlet result A already receives). There is no §9.4.3 secret here, so —
/// unlike [`SagaPreparedState`] — this type derives `Serialize`/`Clone`
/// directly and rides the public [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// surface without a separate mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedOutletInvocation {
    /// The target's signed receipt over the staged provenance + output hash +
    /// event id. Re-emitted verbatim on a replayed Commit so the signature
    /// preimage reproduces byte-for-byte.
    pub receipt: scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt,
    /// The captured outlet output bytes — the receipt's `output_jcs`, stored
    /// alongside so a replay re-emits the exact output A originally received.
    #[serde(with = "scp_protocol::serde_util::serde_bounded_bytes")]
    pub output_bytes: Vec<u8>,
    /// The `SagaId`-stable `OutletInvoked` event-log entry id (also carried on
    /// the receipt; stored explicitly so a replay re-acks the same id without
    /// re-deriving it).
    pub outlet_invoked_event_id: String,
}

/// Durable, `SagaId`-keyed capture of a COMMITTED cross-context **streaming**
/// outlet invocation, held on the TARGET (B) actor.
///
/// ADR-061 seal phase; spec §6.2.5 streaming saga — the streaming sibling of
/// [`CommittedOutletInvocation`].
///
/// The seal phase reaches the `Committed` terminal at stream-close (not at the
/// Commit-transition). At that instant the target durably captures — keyed by
/// `SagaId` — the signed streaming receipt plus the sealed `stream_manifest_hash`
/// and the billing/chunk counters, so a Commit replayed after a crash (§17.16.4)
/// re-emits the IDENTICAL signed receipt and the SAME `outlet_invoked_event_id`
/// **without re-invoking the outlet** (re-invoking a non-deterministic LLM would
/// break §6.2.4 replay-determinism). Unlike the unary
/// [`CommittedOutletInvocation`], no output bytes are captured — the streaming
/// receipt attests the Merkle root, and the root reproduces from the durable
/// `SagaId`-keyed frontier, never from carried output (ADR-061 "Receipt
/// (streaming)").
///
/// **Class S** — held in
/// [`PerContextState.xctx_committed_stream_outputs`](crate::context::actor::state::PerContextState::xctx_committed_stream_outputs)
/// and synchronously persisted fail-closed (ADR-049 §9), the same discipline as
/// [`CommittedOutletInvocation`]: a crash that rolled the capture back behind an
/// acked seal-close would re-invoke the outlet on replay, breaking exactly-once.
///
/// **Not bearer-bearing.** The receipt and the manifest root are public protocol
/// artifacts (the receipt is the signed streaming return-path response), so — like
/// [`CommittedOutletInvocation`] — this type derives `Serialize`/`Clone` directly
/// and rides the public [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// surface without a separate mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedStreamingOutletInvocation {
    /// The target's signed streaming receipt over the staged provenance + the
    /// sealed `stream_manifest_hash` + event id. Re-emitted verbatim on a
    /// replayed Commit so the signature preimage reproduces byte-for-byte.
    pub receipt:
        scp_protocol::context::outlets::cross_context_saga::CrossContextOutletStreamReceipt,
    /// The sealed RFC-6962 Merkle root over the emitted chunk sequence — the
    /// `frontier.root()` finalized at stream-close (also carried on the receipt;
    /// stored explicitly so a replay re-emits it without re-deriving).
    pub stream_manifest_hash: [u8; 32],
    /// Credit billed at seal-close settled from the durable ledger
    /// (`cost_per_chunk × billed_count`); stored so a replayed Commit re-emits the
    /// IDENTICAL settlement without recomputing.
    pub billed: Amount,
    /// Escrow refund at seal-close = `reserved − billed`; stored so a replay
    /// re-emits the same refund (the money already moved on the first settle).
    pub refund: Amount,
    /// The §5.4.5 billable-`Data`-chunk count sealed at close
    /// (`frontier.billed_count()`), recorded into the B-side `OutletInvoked` event.
    pub billed_count: u32,
    /// Total chunks in the sealed manifest (`frontier.leaf_count()`), the §5.4.5
    /// `stream_chunk_count` recorded into the B-side `OutletInvoked` event.
    pub stream_chunk_count: u64,
    /// The `SagaId`-stable `OutletInvoked` event-log entry id (also carried on the
    /// receipt; stored explicitly so a replay re-acks the same id).
    pub outlet_invoked_event_id: String,
}

/// Caller-side (A-owned) durable reversal record for a cross-context outlet
/// invocation's Prepare-A economy reservation (spec §6.2.4 "Reservation release
/// on every terminal path").
///
/// Prepare-A durably persists the caller's velocity / budget / hard-rate-limit
/// deductions and authorizes the external payment escrow, but the live
/// [`OutletEconomyReservation`](crate::context::outlets_helpers::OutletEconomyReservation)
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
/// **Reversal is unconditional on the crash path** — see
/// [`reverse_caller_reservation_record`](crate::context::outlets_helpers::reverse_caller_reservation_record).
/// The record and the deductions it reverses are rehydrated from ONE consistent
/// snapshot into the SAME restored context, so there is no "replaced instance"
/// to confuse: routing by `context_id` plus keying every reversal by
/// `actor_did` is what guarantees only this actor's OWNED bookkeeping is
/// touched. (A spawn-generation comparison would be a FALSE mismatch — every
/// respawn stamps a fresh `state.generation`, so it never equals the pre-crash
/// value — and would wrongly SKIP the refund on every real restart.)
///
/// **Escrow void MUST be idempotent across a recovery re-drive.** The crash
/// abort voids the escrow BEFORE its Class-S persist; if that persist fails the
/// record stays durable, so the next recovery sweep voids the SAME
/// [`PaymentAuthorization`](crate::economy::adapter::PaymentAuthorization)
/// again. This is the same idempotency the carrier's `void_external_and_consume`
/// already relies on and the payment-adapter `void` contract guarantees.
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
/// [`CommittedOutletInvocation`] — a `NeedsRepair` saga's inert leftover record is
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
/// separate mirror, exactly like [`CommittedOutletInvocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerReservationRecord {
    /// The caller DID the reservation was made for — the key for budget /
    /// velocity / hard-rate-limit reversal against the actor's owned trackers.
    pub actor_did: DID,
    /// The budget amount deducted at Prepare-A (`None` for a free action).
    /// Reversed via `budget_tracker.reverse_spend` on the crash-abort path.
    pub deducted_cost: Option<scp_protocol::economy::types::Amount>,
    /// Whether the hard-rate-limit token consumed at Prepare-A must be refunded
    /// on reversal (mirrors `OutletEconomyTicket::needs_hard_rate_limit_refund`).
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

    #[test]
    fn cross_context_outlet_invocation_constructs() {
        let state =
            SagaPreparedState::CrossContextOutletInvocation(CrossContextOutletInvocationPrepared {
                caller_context_id: [5u8; 32],
                target_context_id: [6u8; 32],
                caller_did: alice(),
                outlet_registration_id: "calculator-v1".to_owned(),
                ucan_proof_id: "ucan-token-abcdef".to_owned(),
                recorded_timestamp_ms: 1_725_000_000_123,
                recorded_nonce: [0xABu8; 16],
                recorded_chain_depth: 3,
            });
        let SagaPreparedState::CrossContextOutletInvocation(inner) = state else {
            panic!("expected the unary cross-context outlet-invocation variant");
        };
        assert_eq!(inner.caller_context_id, [5u8; 32]);
        assert_eq!(inner.target_context_id, [6u8; 32]);
        assert_eq!(inner.caller_did, alice());
        assert_eq!(inner.outlet_registration_id, "calculator-v1");
        assert_eq!(inner.ucan_proof_id, "ucan-token-abcdef");
        assert_eq!(inner.recorded_timestamp_ms, 1_725_000_000_123);
        assert_eq!(inner.recorded_nonce, [0xABu8; 16]);
        assert_eq!(inner.recorded_chain_depth, 3);
    }

    #[test]
    fn cross_context_outlet_invocation_evidence_round_trips_all_eight_fields() {
        let original = CrossContextOutletInvocationPrepared {
            caller_context_id: [0x11u8; 32],
            target_context_id: [0x22u8; 32],
            caller_did: alice(),
            outlet_registration_id: "calculator-v1".to_owned(),
            ucan_proof_id: "ucan-token-abcdef".to_owned(),
            recorded_timestamp_ms: 1_725_000_000_123,
            recorded_nonce: [0xCDu8; 16],
            recorded_chain_depth: 7,
        };
        let bytes = original.to_evidence_bytes().unwrap();
        let back = CrossContextOutletInvocationPrepared::from_evidence_bytes(&bytes).unwrap();
        assert_eq!(back.caller_context_id, original.caller_context_id);
        assert_eq!(back.target_context_id, original.target_context_id);
        assert_eq!(back.caller_did, original.caller_did);
        assert_eq!(back.outlet_registration_id, original.outlet_registration_id);
        assert_eq!(back.ucan_proof_id, original.ucan_proof_id);
        assert_eq!(back.recorded_timestamp_ms, original.recorded_timestamp_ms);
        assert_eq!(back.recorded_nonce, original.recorded_nonce);
        assert_eq!(back.recorded_chain_depth, original.recorded_chain_depth);
    }

    #[test]
    fn cross_context_outlet_invocation_wire_round_trips_via_messagepack() {
        // Exercises the explicit Wire mirror directly, matching the
        // §9.4.3 non-derive discipline: the live enum stays non-Serialize,
        // serialization flows only through the Wire type.
        let wire = CrossContextOutletInvocationPreparedWire {
            caller_context_id: [0x33u8; 32],
            target_context_id: [0x44u8; 32],
            caller_did: bob().0,
            outlet_registration_id: "translator-v2".to_owned(),
            ucan_proof_id: "ucan-token-99".to_owned(),
            recorded_timestamp_ms: 42,
            recorded_nonce: [0xEEu8; 16],
            recorded_chain_depth: 255,
        };
        let bytes = rmp_serde::to_vec_named(&wire).unwrap();
        let back: CrossContextOutletInvocationPreparedWire = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back, wire);
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
        assert_send_sync::<CrossContextOutletInvocationPrepared>();
        assert_send_sync::<CrossContextStreamingOutletInvocationPrepared>();
    }

    /// The Class-S snapshot mirror (ADR-049 §9 line 144) must serialize, then
    /// deserialize, then rehydrate to an identical live `SagaPreparedState`.
    /// Same round-trip for the cross-context outlet-invocation variant — all
    /// eight journaled fields must survive (§6.2.4 public-metadata journaling).
    #[test]
    fn snapshot_mirror_round_trips_cross_context_outlet() {
        let prepared =
            SagaPreparedState::CrossContextOutletInvocation(CrossContextOutletInvocationPrepared {
                caller_context_id: [0x1Au8; 32],
                target_context_id: [0x2Bu8; 32],
                caller_did: alice(),
                outlet_registration_id: "calc-v2".to_owned(),
                ucan_proof_id: "ucan-xyz".to_owned(),
                recorded_timestamp_ms: 1_700_111_222_333,
                recorded_nonce: [0x9Eu8; 16],
                recorded_chain_depth: 7,
            });
        let mirror = SagaPreparedStateSnapshot::from_prepared(&prepared);
        let bytes = serde_json::to_vec(&mirror).unwrap();
        let back: SagaPreparedStateSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mirror, back);
        let SagaPreparedState::CrossContextOutletInvocation(inner) = back.into_prepared() else {
            panic!("expected the unary cross-context outlet-invocation variant");
        };
        assert_eq!(inner.caller_context_id, [0x1Au8; 32]);
        assert_eq!(inner.target_context_id, [0x2Bu8; 32]);
        assert_eq!(inner.caller_did, alice());
        assert_eq!(inner.outlet_registration_id, "calc-v2");
        assert_eq!(inner.ucan_proof_id, "ucan-xyz");
        assert_eq!(inner.recorded_timestamp_ms, 1_700_111_222_333);
        assert_eq!(inner.recorded_nonce, [0x9Eu8; 16]);
        assert_eq!(inner.recorded_chain_depth, 7);
    }

    /// The Class-S snapshot mirror must round-trip the **streaming** variant
    /// (ADR-061 seal phase; §6.2.5) losslessly through
    /// `from_prepared → serialize → deserialize → into_prepared`, and — the
    /// AC7 witness — the rehydrated `frontier.root()`/`billed_count()` must
    /// reproduce the pre-snapshot values (crash recovery seals the durable
    /// prefix by re-deriving the root from the restored peaks).
    #[test]
    fn snapshot_mirror_round_trips_cross_context_streaming_outlet() {
        use scp_protocol::context::outlets::stream::{
            ChunkPayload, MerkleFrontier, OutletStreamChunk,
        };
        use scp_protocol::economy::types::Amount;

        // Build a non-trivial frontier over 4 Data chunks so root() and
        // billed_count() are meaningful values the round-trip must preserve.
        let mut frontier = MerkleFrontier::with_ceiling(2);
        for seq in 0u64..4 {
            frontier
                .push(&OutletStreamChunk {
                    request_id: [0x7Au8; 16],
                    sequence: seq,
                    payload: ChunkPayload::Data {
                        value: serde_json::json!({ "seq": seq }),
                    },
                    sig: [(seq & 0xFF) as u8 ^ 0x5A; 64],
                })
                .expect("valid chunk hashes");
        }
        let expected_root = frontier.root();
        let expected_billed = frontier.billed_count(); // ceiling 2 → seq {0,1,2}
        let expected_leaves = frontier.leaf_count();

        let prepared = SagaPreparedState::CrossContextStreamingOutletInvocation(
            CrossContextStreamingOutletInvocationPrepared {
                saga_id: SagaId("saga-stream-1".to_owned()),
                caller_context_id: [0x3Au8; 32],
                target_context_id: [0x4Bu8; 32],
                caller_did: alice(),
                outlet_registration_id: "llm-stream-v1".to_owned(),
                ucan_proof_id: "ucan-stream-xyz".to_owned(),
                recorded_timestamp_ms: 1_700_222_333_444,
                recorded_nonce: [0x8Fu8; 16],
                recorded_chain_depth: 5,
                frontier,
                reserved: Amount::new(1_000),
                cost_per_chunk: Amount::new(100),
                billed: Amount::new(300),
                billed_count: 3,
                cancel_ack_ceiling: 2,
                request_id: [0x7Au8; 16],
                // Query / zero-cost stream — no policy snapshot. The
                // `Option<EconomicPolicy>` field round-trips as `None`;
                // `EconomicPolicy`'s own `Serialize` is proven by its derive.
                economic_policy: None,
                amount_cumulative_reserved: 900,
                reserved_chunks: 9,
                ucan_cid: "bafy-stream-ucan".to_owned(),
            },
        );

        let mirror = SagaPreparedStateSnapshot::from_prepared(&prepared);
        let bytes = serde_json::to_vec(&mirror).unwrap();
        let back: SagaPreparedStateSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mirror, back);

        let SagaPreparedState::CrossContextStreamingOutletInvocation(inner) = back.into_prepared()
        else {
            panic!("expected the streaming cross-context outlet-invocation variant");
        };
        assert_eq!(inner.saga_id, SagaId("saga-stream-1".to_owned()));
        assert_eq!(inner.caller_context_id, [0x3Au8; 32]);
        assert_eq!(inner.target_context_id, [0x4Bu8; 32]);
        assert_eq!(inner.caller_did, alice());
        assert_eq!(inner.outlet_registration_id, "llm-stream-v1");
        assert_eq!(inner.ucan_proof_id, "ucan-stream-xyz");
        assert_eq!(inner.recorded_timestamp_ms, 1_700_222_333_444);
        assert_eq!(inner.recorded_nonce, [0x8Fu8; 16]);
        assert_eq!(inner.recorded_chain_depth, 5);
        assert_eq!(inner.reserved, Amount::new(1_000));
        assert_eq!(inner.cost_per_chunk, Amount::new(100));
        assert_eq!(inner.billed, Amount::new(300));
        assert_eq!(inner.billed_count, 3);
        assert_eq!(inner.cancel_ack_ceiling, 2);
        // SCP-OUT-046 settlement-ledger fields survive the snapshot (durable
        // for crash-recovery settlement).
        assert_eq!(inner.request_id, [0x7Au8; 16]);
        assert_eq!(inner.economic_policy, None);
        assert_eq!(inner.amount_cumulative_reserved, 900);
        assert_eq!(inner.reserved_chunks, 9);
        assert_eq!(inner.ucan_cid, "bafy-stream-ucan");
        // The AC7 durable-prefix reproducibility witness: the frontier's
        // root and counters survive the snapshot byte-for-byte.
        assert_eq!(inner.frontier.root(), expected_root);
        assert_eq!(inner.frontier.billed_count(), expected_billed);
        assert_eq!(inner.frontier.leaf_count(), expected_leaves);
    }
}
