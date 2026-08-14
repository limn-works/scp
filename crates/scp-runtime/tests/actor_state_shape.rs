//! Integration test for the ADR-049 commit-12a fields-only contract.
//!
//! Commit 12a extends [`scp_runtime::context::actor::state::PerContextState`],
//! [`scp_runtime::context::actor::state::ContextCryptoState`], and
//! [`scp_runtime::context::actor::state::BroadcastState`] with the legacy
//! field set so 12b+ handler migrations are mechanical. This test
//! witnesses the structural contract by:
//!
//! 1. Constructing each type's default-for-test fixture and verifying no
//!    field panics on read and every field is initialised.
//! 2. Destructuring [`PerContextState`] with an exhaustive pattern so
//!    adding a new field without updating the witness is a compile error
//!    (forward-locks future commits against silent field drops).
//! 3. Asserting mode-specific fields are present on the correct
//!    variants (encrypted → [`ContextCryptoState`], broadcast →
//!    [`BroadcastState`]).
//!
//! No behaviour tests. Handler bodies migrate in 12b+; this file is
//! exclusively about shape parity.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    // Test docs cite ADR section titles unquoted for readability.
    clippy::doc_markdown
)]

use std::collections::HashMap;

use scp_did::DID;
use scp_runtime::context::actor::{
    AuthorKeyEntry, BroadcastRecvTracker, BroadcastState, ContextCryptoState,
    ContextLifecycleState, ContextModeState, PendingBroadcastKeyRotation, PerContextState,
    RecvSequenceTracker, WelcomeProcessing,
};
use zeroize::Zeroizing;

fn test_admin() -> DID {
    DID("did:example:admin".to_owned())
}

// ---------------------------------------------------------------------------
// PerContextState shape witness
// ---------------------------------------------------------------------------

/// Commit 12a contract: [`PerContextState::new_for_test_encrypted`]
/// produces a struct with every pub-visible field initialised and
/// reachable.
///
/// Integration tests cannot destructure exhaustively because several
/// fields on [`PerContextState`] carry `pub(crate)`-typed values
/// (`GovernanceState`, `EpochState`, `AccessControlState`, `TtlState`)
/// — these legacy types are only usable inside `scp-runtime`. The
/// crate-internal unit test
/// [`encrypted_constructor_populates_every_per_context_field`](
///   crate::context::actor::state::tests::encrypted_constructor_populates_every_per_context_field)
/// witnesses exhaustiveness; this integration test mirrors the SDK-
/// visible surface.
#[test]
fn per_context_state_encrypted_public_fields_accessible() {
    let s = PerContextState::new_for_test_encrypted([0xA1; 32], 1_700_000_000, test_admin());

    // Identity + lifetime.
    assert_eq!(s.context_id, [0xA1; 32]);
    assert_eq!(s.created_at, 1_700_000_000);
    assert_eq!(s.generation, 0);
    // `handle.context_id()` is the hex-encoded context ID.
    assert_eq!(s.handle.context_id().len(), 64);

    // Membership + role.
    assert_eq!(s.membership.count(), 0);
    assert_eq!(s.members.len(), 0);
    assert_eq!(s.role_state.members.len(), 0);

    // Event buffers + logs.
    assert!(s.event_log.is_none());
    assert_eq!(s.receive_buffer.len(), 0);

    // Mode-specific metadata.
    assert!(s.broadcast_context.is_none());
    assert!(s.migration_state.is_none());

    // Routing (§9.10.4): an encrypted context is pseudonymous with an empty
    // peer registry and a (zero, in the test fixture) local pseudonym.
    assert!(!s.routing.is_broadcast());
    assert!(s.routing.local_pseudonym().is_some());
    assert_eq!(
        s.routing
            .peer_registry()
            .map(std::collections::HashMap::len),
        Some(0)
    );

    // Anti-replay + reorder buffers.
    let _ = &s.sequence_tracker;
    let _ = &s.reorder_buffer;

    // Commit retry + checkpointing.
    assert_eq!(s.pending_commits.len(), 0);
    assert!(s.commit_fault.is_none());
    assert_eq!(s.checkpoint_events_since, 0);
    assert_eq!(s.checkpoint_last_time_secs, 0);
    assert_eq!(s.checkpoints.len(), 0);

    // New actor-shape fields.
    assert_eq!(s.send_tracker.last_issued(), 0);
    let _ = s.recv_tracker.last_seen(&DID("did:example:eve".to_owned()));
    assert_eq!(s.saga_pending().len(), 0);
    assert!(s.welcome_scratchpad.is_none());
    assert_eq!(s.lifecycle_state, ContextLifecycleState::Open);

    // Mode.
    match &s.mode {
        ContextModeState::Encrypted(_) => {}
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

#[test]
fn per_context_state_broadcast_mode_placement() {
    let s = PerContextState::new_for_test_broadcast([0xB2; 32], 42, test_admin());
    match &s.mode {
        ContextModeState::Broadcast(b) => {
            assert_eq!(b.local_send_sequence, 0);
            assert!(b.author_keys.is_empty());
            assert!(b.blocked_authors.is_empty());
            assert!(b.subscribers.is_empty());
            assert!(b.pending_key_rotations.is_empty());
            assert!(b.recv_sequence_trackers.is_empty());
        }
        ContextModeState::Encrypted(_) => panic!("expected broadcast mode"),
    }
}

// ---------------------------------------------------------------------------
// ContextCryptoState shape witness
// ---------------------------------------------------------------------------

/// Commit 12a contract: [`ContextCryptoState::default`] populates every
/// field. The destructure below enforces exhaustiveness the same way as
/// the [`PerContextState`] witness.
#[test]
fn context_crypto_state_default_exhaustive_field_witness() {
    let c = ContextCryptoState::default();
    let ContextCryptoState {
        mls_group,
        sender_key,
        sender_key_store,
        sender_key_epoch,
        pending_distributions,
        nonce_dedup,
        member_wrapping_keys,
        recv_sequence_tracker,
        // The `#[cfg(any(test, feature = "testing"))]` `force_rotation_failure`
        // fault-injection seam is `pub(crate)` — inaccessible from this
        // integration-test crate. The in-lib exhaustive witness
        // (`context_crypto_state_default_populates_every_field`) covers it.
        ..
    } = c;

    // MLS group and sender key default to `None` per ADR-049 actor
    // model — the Create / Join handlers in 12b+ populate them.
    assert!(mls_group.is_none(), "mls_group starts None");
    assert!(sender_key.is_none(), "sender_key starts None");

    // Counters + stores start empty.
    assert_eq!(sender_key_epoch, 0);
    assert!(pending_distributions.is_empty());
    assert!(member_wrapping_keys.is_empty());
    assert!(
        recv_sequence_tracker.is_empty(),
        "recv_sequence_tracker (MLS sender-key anti-replay) starts empty",
    );

    // Sub-stores: these types already Debug-redact; touching them
    // compiles only if the field exists.
    let _ = &sender_key_store;
    let _ = &nonce_dedup;
}

// ---------------------------------------------------------------------------
// BroadcastState shape witness
// ---------------------------------------------------------------------------

/// Commit 12a contract: [`BroadcastState::default`] populates every field
/// including the new `pending_key_rotations` queue added in 12a.
#[test]
fn broadcast_state_default_exhaustive_field_witness() {
    let b = BroadcastState::default();
    let BroadcastState {
        author_keys,
        blocked_authors,
        recv_sequence_trackers,
        local_send_sequence,
        subscribers,
        pending_key_rotations,
    } = b;

    assert!(author_keys.is_empty());
    assert!(blocked_authors.is_empty());
    assert!(recv_sequence_trackers.is_empty());
    assert_eq!(local_send_sequence, 0);
    assert!(subscribers.is_empty());
    assert!(pending_key_rotations.is_empty());
}

// ---------------------------------------------------------------------------
// Mode-specific type placement
// ---------------------------------------------------------------------------

/// Commit 12a contract: mode-specific fields live only on the mode
/// variant that applies. This test exercises every sub-type with
/// non-default values to prove the containing enum can carry them.
#[test]
fn broadcast_state_can_carry_pending_key_rotations() {
    let mut b = BroadcastState::default();
    b.pending_key_rotations
        .push_back(PendingBroadcastKeyRotation {
            author: DID("did:example:author-1".to_owned()),
            new_key: Zeroizing::new([0x77; 32]),
            new_epoch: 5,
            queued_at_ms: 1_700_000_000_000,
        });
    assert_eq!(b.pending_key_rotations.len(), 1);
    let rot = &b.pending_key_rotations[0];
    assert_eq!(rot.author, DID("did:example:author-1".to_owned()));
    assert_eq!(rot.new_epoch, 5);
    assert_eq!(rot.queued_at_ms, 1_700_000_000_000);
    assert_eq!(&*rot.new_key, &[0x77; 32]);
}

/// Witness that broadcast sub-types (`AuthorKeyEntry`,
/// `BroadcastRecvTracker`) round-trip as map values.
#[test]
fn broadcast_state_sub_types_round_trip() {
    let did = DID("did:example:author-2".to_owned());
    let mut author_keys: HashMap<DID, AuthorKeyEntry> = HashMap::new();
    author_keys.insert(
        did.clone(),
        AuthorKeyEntry {
            key: Zeroizing::new([0x11; 32]),
            epoch: 3,
            created_at_ms: 1_700_000_000_000,
        },
    );
    let mut trackers: HashMap<DID, BroadcastRecvTracker> = HashMap::new();
    trackers.insert(
        did.clone(),
        BroadcastRecvTracker {
            last_seen_epoch: 3,
            last_seen_sequence: 100,
        },
    );
    assert_eq!(author_keys.get(&did).unwrap().epoch, 3);
    assert_eq!(trackers.get(&did).unwrap().last_seen_sequence, 100);
}

// ---------------------------------------------------------------------------
// New actor-shape fields round-trip
// ---------------------------------------------------------------------------

#[test]
fn welcome_scratchpad_default_shape() {
    let w = WelcomeProcessing::default();
    // `staged_welcome` is an empty Zeroizing vec; `kp_reservation` is
    // None. Both are consistent with "no Welcome flow in progress."
    assert_eq!(w.staged_welcome.len(), 0);
    assert!(w.kp_reservation.is_none());
}

#[test]
fn recv_sequence_tracker_roundtrip() {
    let mut t = RecvSequenceTracker::new();
    let did = DID("did:example:peer".to_owned());
    assert!(t.record(did.clone(), 1));
    assert!(t.record(did.clone(), 2));
    assert!(!t.record(did.clone(), 2));
    assert_eq!(t.last_seen(&did), 2);
}

// ---------------------------------------------------------------------------
// Send + Sync witnesses
// ---------------------------------------------------------------------------

#[test]
fn state_types_are_send() {
    const fn assert_send<T: Send>() {}
    // `PerContextState` moves into the actor's owning task via
    // `tokio::spawn` (commit 6). The compile-time witness below pins
    // that contract at the type level.
    assert_send::<PerContextState>();
    assert_send::<ContextCryptoState>();
    assert_send::<BroadcastState>();
    assert_send::<PendingBroadcastKeyRotation>();
}

// ---------------------------------------------------------------------------
// Containers wire up
// ---------------------------------------------------------------------------

/// Witness that the legacy-typed containers on `PerContextState` —
/// `pending_commits: VecDeque<PendingCommit>` and `checkpoints:
/// Vec<ConsistencyCheckpoint>` — are the expected container types. The
/// assertions use container operations that would fail to compile if a
/// future commit changed the declared type.
#[test]
fn legacy_container_types_are_expected_shapes() {
    let s = PerContextState::new_for_test_encrypted([0xC3; 32], 99, test_admin());
    // `VecDeque::iter` is sufficient to witness the container type
    // without naming `PendingCommit` (whose constructor is gated on
    // internal crate types).
    let _: std::collections::vec_deque::Iter<'_, _> = s.pending_commits.iter();
    let _: std::slice::Iter<'_, _> = s.checkpoints.iter();
}
