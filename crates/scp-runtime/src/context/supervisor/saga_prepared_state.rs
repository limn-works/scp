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
    /// §5.15.7; not secret-bearing.
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

/// Staged state for a standing-pair-creation saga.
///
/// All fields are public per spec §5.15.7 (standing-pair handshake): the
/// peer DID, the local DID, the deterministically-derived context ID, the
/// MLS group ID, and the staged `CreationReceipt`. None of these are
/// bearer artifacts.
pub struct StandingPairCreatePrepared {
    /// The remote peer's DID.
    pub peer_did: DID,
    /// The local identity's DID.
    pub local_did: DID,
    /// The context ID derived from `(peer_did, local_did)` — see §5.15.7
    /// for the derivation function.
    pub derived_context_id: [u8; 32],
    /// The newly-generated MLS group ID for the standing pair.
    pub group_id: Vec<u8>,
    /// Staged `CreationReceipt`. Held opaquely as bytes here; the concrete
    /// receipt type is wired in when the standing handler migrates to the
    /// actor model in a later commit. Conformant serializations must round-
    /// trip through `CreationReceipt::to_bytes`/`from_bytes` (spec §5.15.7).
    pub creation_receipt_bytes: Vec<u8>,
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

    #[test]
    fn standing_pair_create_constructs() {
        let state = SagaPreparedState::StandingPairCreate(StandingPairCreatePrepared {
            peer_did: bob(),
            local_did: alice(),
            derived_context_id: [1u8; 32],
            group_id: vec![0xAA; 16],
            creation_receipt_bytes: vec![0xBB; 64],
        });
        match state {
            SagaPreparedState::StandingPairCreate(inner) => {
                assert_eq!(inner.peer_did, bob());
                assert_eq!(inner.local_did, alice());
                assert_eq!(inner.derived_context_id, [1u8; 32]);
                assert_eq!(inner.group_id, vec![0xAA; 16]);
                assert_eq!(inner.creation_receipt_bytes, vec![0xBB; 64]);
            }
            _ => panic!("wrong variant"),
        }
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
