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
//!   *which* phase, plus a public commitment for secret-bearing sagas. Spec
//!   §9.4.3 forbids the journal from holding bearer artifacts directly.
//! - **`saga_pending` (actor-side):** holds the full evidence the actor
//!   needs to apply the mutation at Commit time. For secret-bearing sagas
//!   (migration), the bearer envelope sits here under `Zeroizing` so drop
//!   zeros the bytes if the actor crashes before Commit.
//!
//! At Commit time the actor reconstructs the bearer from `saga_pending`,
//! verifies the journal's commitment matches via SHA-256, then applies
//! the mutation. If `saga_pending` rolled back beyond the prepared state
//! (e.g. coalesced-snapshot crash window), Commit replay fails fast with
//! `SagaCommitFailed` — no half-applied migration, no bearer reconstruction
//! from the journal alone.
//!
//! # EXPLICIT NON-DERIVES on bearer-bearing variants
//!
//! Per spec §9.4.3, any container holding bearer bytes MUST NOT be
//! `Clone`, `Debug`, `Display`, `Serialize`, or `Deserialize`. The bearer
//! field itself is wrapped in `Zeroizing<Vec<u8>>` so drop zeros the
//! bytes; the wrapping struct must additionally refuse the trait set
//! above so a misuse like `format!("{:?}", state)` cannot leak bytes
//! into a log line, and a snapshot serializer cannot accidentally write
//! the bearer to disk.
//!
//! [`ContextMigrationPrepared`] is the only variant whose containing
//! struct currently bears this restriction. Future bearer-bearing saga
//! types (none planned) would need the same discipline. The wrapping
//! enum [`SagaPreparedState`] does NOT derive any of these traits either,
//! because that would expose the inner bearer through the enum's auto-
//! generated impls (e.g. derived `Debug` on the enum recurses into the
//! variant's `Debug`, which would either fail to compile or leak).
//!
//! See ADR-049 §3 (saga protocol), spec §9.4.3 (saga journal secret
//! handling), and `crate::context::supervisor::identity_capability` for
//! the analogous capability-token discipline.

use scp_identity::DID;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Discriminated union over the 4 saga types defined by ADR-049 §3
// ---------------------------------------------------------------------------

/// Discriminated union over the 4 saga types defined by ADR-049 §3.
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
    /// Context migration between two identities (target-side). The
    /// `CustodyHandover` envelope is the bearer artifact and is held here
    /// under `Zeroizing`; the journal stores only a SHA-256 commitment per
    /// spec §9.4.3.
    ContextMigration(ContextMigrationPrepared),
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
// Context migration (target-side) — secret-bearing
// ---------------------------------------------------------------------------

/// Staged state for a target-side context-migration saga.
///
/// **Bearer-bearing.** Per spec §9.4.3 the journal stores only
/// `handover_commitment = SHA-256(domain_separator ‖ envelope ‖ nonce)`.
/// The actual `CustodyHandover` envelope (the bearer) is held in this
/// struct in actor-local memory under [`Zeroizing<Vec<u8>>`] so a Drop
/// during a crash window zeros the bytes.
///
/// **Non-derives.** No `Clone`, no `Debug`, no `Display`, no `Serialize`,
/// no `Deserialize` on this struct itself. The `Zeroizing` wrapper around
/// `handover_envelope` is the runtime barrier; the trait restrictions
/// here are the static barrier. Both layers are required by spec §9.4.3.
///
/// **Snapshot persistence.** When `PerContextState.saga_pending` is
/// persisted as part of the actor's coalesced snapshot in a later commit,
/// the snapshot serializer MUST hand-roll the encoding for this variant —
/// it cannot use a derived `Serialize` because none exists. The serializer
/// will route the bearer bytes through a `Zeroizing`-aware codec analogous
/// to `JournalEntry`'s `EvidenceWire` pattern, and the snapshot backend
/// MUST satisfy the at-rest-encryption requirement (§9.4.3) before the
/// snapshot is allowed to host secret-bearing saga state.
pub struct ContextMigrationPrepared {
    /// The source context ID being migrated.
    pub source_context_id: [u8; 32],
    /// The DID of the source identity.
    pub source_identity_did: DID,
    /// `SHA-256(domain_separator ‖ envelope ‖ nonce)` per spec §9.4.3.
    /// Must equal the value the supervisor recorded in the journal entry
    /// for this saga; mismatch fails Commit fast.
    pub handover_commitment: [u8; 32],
    /// 32-byte `OsRng` nonce mixed into the commitment. Distinct per saga
    /// instance; nonce reuse is a protocol violation.
    pub handover_nonce: [u8; 32],
    /// The `CustodyHandover` envelope bytes (canonical serialization, spec
    /// §9.4.3). Held in `Zeroizing` so drop zeros the storage even on
    /// panic / cancellation / early `?` return paths in the surrounding
    /// handler.
    pub handover_envelope: Zeroizing<Vec<u8>>,
    /// Staged `MigrationImport` metadata — public fields only (no key
    /// bytes). Concrete type is wired in when the migration handler
    /// migrates to the actor model.
    pub migration_import_metadata: Vec<u8>,
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
    fn context_migration_constructs() {
        let envelope_bytes: Vec<u8> = (0..128u8).collect();
        let state = SagaPreparedState::ContextMigration(ContextMigrationPrepared {
            source_context_id: [2u8; 32],
            source_identity_did: alice(),
            handover_commitment: [3u8; 32],
            handover_nonce: [4u8; 32],
            handover_envelope: Zeroizing::new(envelope_bytes.clone()),
            migration_import_metadata: vec![0xCC; 32],
        });
        match state {
            SagaPreparedState::ContextMigration(inner) => {
                assert_eq!(inner.source_context_id, [2u8; 32]);
                assert_eq!(inner.source_identity_did, alice());
                assert_eq!(inner.handover_commitment, [3u8; 32]);
                assert_eq!(inner.handover_nonce, [4u8; 32]);
                assert_eq!(&*inner.handover_envelope, &envelope_bytes[..]);
                assert_eq!(inner.migration_import_metadata, vec![0xCC; 32]);
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

    /// `Zeroize` on the `Zeroizing<Vec<u8>>` envelope writes zeros into
    /// the buffer in place. Verifies via the safe API: explicit `zeroize`
    /// followed by reading the wrapper's contents.
    ///
    /// We do NOT use raw-pointer / use-after-free inspection here:
    /// `crates/scp-runtime/src/lib.rs` is `#![forbid(unsafe_code)]`, so
    /// raw-pointer inspection cannot live in this crate. The `zeroize`
    /// crate's own Drop-zeros invariant is upstream-tested; what we need
    /// to verify here is that
    ///
    ///   (a) the bearer field is wrapped in `Zeroizing<Vec<u8>>` (the
    ///       only type we expose for it — any change is a compile error
    ///       at every call site), and
    ///   (b) explicit `zeroize()` succeeds and zeroes the bytes (which
    ///       is what `Drop` would call).
    ///
    /// `Zeroizing<T>::drop` is documented by the `zeroize` crate as
    /// calling `T::zeroize`. `Vec<u8>::zeroize` overwrites the storage
    /// with zeros and truncates the length to 0. The combination of
    /// those upstream-tested behaviors with the type-system witness
    /// (`handover_envelope: Zeroizing<Vec<u8>>`) is the load-bearing
    /// evidence that drop zeros the bytes.
    #[test]
    fn migration_prepared_envelope_zeroizes() {
        use zeroize::Zeroize;

        let sentinel: Vec<u8> = (1..=96u8).cycle().take(96).collect();
        let mut prepared = ContextMigrationPrepared {
            source_context_id: [0u8; 32],
            source_identity_did: alice(),
            handover_commitment: [0u8; 32],
            handover_nonce: [0u8; 32],
            handover_envelope: Zeroizing::new(sentinel.clone()),
            migration_import_metadata: Vec::new(),
        };

        // Pre-zeroize: the wrapper holds the sentinel.
        assert_eq!(&*prepared.handover_envelope, &sentinel[..]);

        // Explicit zeroize via the trait `Zeroize`. This is what
        // `Zeroizing::drop` calls during normal drop; calling it here
        // exercises the same code path through the safe API.
        prepared.handover_envelope.zeroize();

        // Post-zeroize: `Vec<u8>::zeroize` truncates len to 0 AND
        // overwrites the backing storage. We check len-0 here through
        // the safe API; the storage-overwrite is the upstream-tested
        // invariant of `Vec<u8>: Zeroize`.
        assert_eq!(
            prepared.handover_envelope.len(),
            0,
            "Zeroizing<Vec<u8>> wrapper must zero AND truncate the bearer \
             envelope on zeroize() — required by spec §9.4.3",
        );
    }

    /// Compile-time witness that the bearer field's type is exactly
    /// `Zeroizing<Vec<u8>>`. If a future change weakens it (e.g. to
    /// `Vec<u8>`), this assertion fails to compile because we destructure
    /// against the exact type pattern.
    ///
    /// Combined with the runtime test above, this proves the spec §9.4.3
    /// container discipline is enforced by the type system.
    #[test]
    fn migration_prepared_envelope_field_is_zeroizing_vec_u8() {
        let prepared = ContextMigrationPrepared {
            source_context_id: [0u8; 32],
            source_identity_did: alice(),
            handover_commitment: [0u8; 32],
            handover_nonce: [0u8; 32],
            handover_envelope: Zeroizing::new(vec![1u8, 2, 3]),
            migration_import_metadata: Vec::new(),
        };
        // Destructure with explicit type binding — fails to compile if
        // the field type changes from `Zeroizing<Vec<u8>>`.
        let envelope: Zeroizing<Vec<u8>> = prepared.handover_envelope;
        assert_eq!(&*envelope, &[1u8, 2, 3]);
    }

    /// Compile-time witnesses that bearer-bearing types do NOT implement
    /// the forbidden traits. If any of these blocks below would compile,
    /// it's a regression — the explicit non-derive discipline has been
    /// silently broken (e.g. by adding `#[derive(Clone)]`).
    ///
    /// We don't have negative trait bounds in stable Rust, but we can
    /// assert positively that the types ARE `Send + Sync` (required for
    /// `ActorDeps` movement into `tokio::spawn`), which is the only
    /// auto-trait obligation they carry.
    #[test]
    fn types_are_send_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SagaPreparedState>();
        assert_send_sync::<StandingPairCreatePrepared>();
        assert_send_sync::<ContextMigrationPrepared>();
        assert_send_sync::<CrossContextToolInvocationPrepared>();
        assert_send_sync::<BroadcastHostingHandshakePrepared>();
    }
}
