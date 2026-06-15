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
/// **Not bearer-bearing.** The UCAN proof bytes are NOT carried here;
/// only the proof's identifier (token ID). The receiving actor re-resolves
/// the proof from its own UCAN store at Commit time. This keeps the
/// prepared-state non-secret-bearing.
pub struct CrossContextToolInvocationPrepared {
    /// Calling context ID.
    pub caller_context_id: [u8; 32],
    /// Calling DID.
    pub caller_did: DID,
    /// Tool registration ID (target tool's stable identifier).
    pub tool_registration_id: String,
    /// UCAN proof reference (token ID), NOT the proof bytes. Resolved
    /// against the receiving actor's UCAN store at Commit time.
    pub ucan_proof_id: String,
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
                caller_did: alice(),
                tool_registration_id: "calculator-v1".to_owned(),
                ucan_proof_id: "ucan-token-abcdef".to_owned(),
            });
        match state {
            SagaPreparedState::CrossContextToolInvocation(inner) => {
                assert_eq!(inner.caller_context_id, [5u8; 32]);
                assert_eq!(inner.caller_did, alice());
                assert_eq!(inner.tool_registration_id, "calculator-v1");
                assert_eq!(inner.ucan_proof_id, "ucan-token-abcdef");
            }
            _ => panic!("wrong variant"),
        }
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
}
