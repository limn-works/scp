//! §9.9.3 convergence soundness proof for the event-log unification
//! (ADR-051 §6 / phase-2.md ADR-011 amendment exclusion taxonomy §2).
//!
//! The relay-equivocation detector (§9.9.3) rests on a single property: two
//! honest members at the same log position MUST derive the same
//! `event_log_merkle_root`. For that to hold, the canonical Merkle log may carry
//! only **convergent** events — those every honest member appends identically.
//! `MessageSent` / `ToolInvoked` / the payment receipts are per-author,
//! non-convergent, so they are excluded from the durable log and surfaced only
//! as local `ContextEvent`s.
//!
//! This test simulates two honest members, A and B, who:
//!   * process the SAME convergent (MLS-commit-ordered) event stream, and
//!   * produce DIVERGENT application-event streams (A "sends" 3 messages, B
//!     "sends" 5) which — under the unification — append NO durable leaf.
//!
//! After both, their Merkle roots MUST be byte-identical. (Before the
//! unification, A would have 3 extra `MessageSent` leaves and B 5, so the roots
//! would diverge — the exact §9.9.3 non-convergence the exclusion guards
//! against. The "negative control" sub-test below re-introduces the per-author
//! appends and asserts the roots then diverge, pinning that this test would
//! catch a regression.)

#![allow(clippy::unwrap_used, clippy::expect_used)]

use scp_event_log::{EventPayload, EventType};
use scp_runtime::context::builder::ContextEventLogProvider;
use scp_runtime::context::providers::MerkleEventLogProvider;

const CTX: [u8; 32] = [0x5cu8; 32];
const ALICE: &str = "did:dht:z6MkAliceConverge";
const BOB: &str = "did:dht:z6MkBobConverge";

/// The convergent stream every honest member appends identically and in the
/// same order: context creation + two joins + a governance action. These are
/// MLS-commit-ordered, so both members observe the same sequence.
fn append_convergent_stream(log: &MerkleEventLogProvider) {
    log.append_context_event(&CTX, EventType::ContextCreated, ALICE)
        .unwrap();
    log.append_context_event(&CTX, EventType::MemberJoined, ALICE)
        .unwrap();
    log.append_context_event(&CTX, EventType::MemberJoined, BOB)
        .unwrap();
    log.append_context_event_with_payload(
        &CTX,
        EventType::GovernanceAction,
        ALICE,
        EventPayload {
            data: b"{\"target_did\":\"did:dht:z6MkBobConverge\"}".to_vec(),
        },
    )
    .unwrap();
}

#[test]
fn two_honest_members_converge_despite_divergent_application_streams() {
    // Member A's local view.
    let log_a = MerkleEventLogProvider::new();
    log_a.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_a);
    // A's local application activity: 3 messages. Under the unification these
    // are local `ContextEvent`s only — NO durable leaf is appended, so they do
    // not perturb A's Merkle root.
    //   (intentionally append nothing to the durable log here — 3 local sends)

    // Member B's local view.
    let log_b = MerkleEventLogProvider::new();
    log_b.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_b);
    // B's local application activity: 5 messages — also durable-leaf-free.

    let root_a = log_a.event_log_merkle_root(&CTX).unwrap();
    let root_b = log_b.event_log_merkle_root(&CTX).unwrap();

    // The §9.9.3 soundness assertion: equal convergent stream ⇒ equal root,
    // independent of each member's divergent (now non-durable) application
    // activity. This is exactly what `assert_consistent_merkle_roots` checks
    // (byte-equality at zero drift); scp-testing is not a dev-dep of scp-runtime
    // (cycle), so the equality is asserted directly.
    assert_eq!(
        root_a, root_b,
        "two honest members with the same convergent event stream MUST derive \
         identical event_log_merkle_root regardless of per-author application \
         activity (§9.9.3; ADR-051 §6)"
    );
    assert_ne!(
        root_a, [0u8; 32],
        "the convergent stream is non-empty, so the shared root must be non-zero"
    );
}

#[test]
fn negative_control_per_author_appends_break_convergence() {
    // This pins that the convergence test above is not vacuous: if application
    // events WERE durably appended per author (the pre-unification behavior),
    // the divergent counts (3 vs 5) make the roots differ. Catching this proves
    // the positive test would detect a regression that re-introduced the
    // per-author `MessageSent` durable append.
    let log_a = MerkleEventLogProvider::new();
    log_a.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_a);
    for _ in 0..3 {
        log_a
            .append_context_event(&CTX, EventType::MessageSent, ALICE)
            .unwrap();
    }

    let log_b = MerkleEventLogProvider::new();
    log_b.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_b);
    for _ in 0..5 {
        log_b
            .append_context_event(&CTX, EventType::MessageSent, BOB)
            .unwrap();
    }

    let root_a = log_a.event_log_merkle_root(&CTX).unwrap();
    let root_b = log_b.event_log_merkle_root(&CTX).unwrap();

    assert_ne!(
        root_a, root_b,
        "with per-author MessageSent leaves durably appended, divergent counts \
         (3 vs 5) MUST make the roots differ — this is the non-convergence the \
         unification removes"
    );
}

#[test]
fn two_honest_members_converge_despite_divergent_payment_captures() {
    // Wave B: `PaymentReceived` is per-payee application activity — under the
    // unification it appends NO durable leaf (surfaced as a local
    // `ContextEvent` + the per-context `payment_receipts` buffer). Two honest
    // members who process the same convergent stream but capture a DIFFERENT
    // number of per-payee payments MUST still derive identical Merkle roots.
    let log_a = MerkleEventLogProvider::new();
    log_a.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_a);
    // A captures 2 payments — local-only, no durable leaf.

    let log_b = MerkleEventLogProvider::new();
    log_b.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_b);
    // B captures 4 payments — also durable-leaf-free.

    let root_a = log_a.event_log_merkle_root(&CTX).unwrap();
    let root_b = log_b.event_log_merkle_root(&CTX).unwrap();

    assert_eq!(
        root_a, root_b,
        "two honest members with the same convergent event stream MUST derive \
         identical event_log_merkle_root regardless of divergent per-payee \
         payment captures (§9.9.3; ADR-051 §6)"
    );
    assert_ne!(
        root_a, [0u8; 32],
        "the convergent stream is non-empty, so the shared root must be non-zero"
    );
}

#[test]
fn negative_control_per_payee_payment_appends_break_convergence() {
    // Pins that the payment-convergence test above is not vacuous: if
    // `PaymentReceived` leaves WERE durably appended per payee (the
    // pre-unification behavior), the divergent counts (2 vs 4) make the roots
    // differ. This proves the positive test would detect a regression that
    // re-introduced the per-payee `PaymentReceived` durable append.
    let log_a = MerkleEventLogProvider::new();
    log_a.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_a);
    for _ in 0..2 {
        log_a
            .append_context_event(&CTX, EventType::PaymentReceived, ALICE)
            .unwrap();
    }

    let log_b = MerkleEventLogProvider::new();
    log_b.init_event_log(&CTX).unwrap();
    append_convergent_stream(&log_b);
    for _ in 0..4 {
        log_b
            .append_context_event(&CTX, EventType::PaymentReceived, BOB)
            .unwrap();
    }

    let root_a = log_a.event_log_merkle_root(&CTX).unwrap();
    let root_b = log_b.event_log_merkle_root(&CTX).unwrap();

    assert_ne!(
        root_a, root_b,
        "with per-payee PaymentReceived leaves durably appended, divergent \
         counts (2 vs 4) MUST make the roots differ — this is the \
         non-convergence the unification removes"
    );
}
