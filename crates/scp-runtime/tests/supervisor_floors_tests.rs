//! Tests moved out of `scp-runtime-core` `context::supervisor::floors` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, MergePolicy};
use scp_runtime_core::context::supervisor::supervisor::Supervisor;
use std::sync::Arc;
use std::thread;

use scp_runtime_core::context::supervisor::floors::FloorAdvanceError;
use scp_runtime_core::context::supervisor::handle::SupervisorHandle;

const CTX: [u8; 32] = [0xA5u8; 32];
const DID: &str = "did:dht:z6MkFloorSenderFloorSenderFloorSenderAA";

/// Terse [`ReceiveFloor`] constructor for the recv-sequence tests.
const fn rf(epoch: u64, sequence: u64) -> ReceiveFloor {
    ReceiveFloor { epoch, sequence }
}

fn sup() -> Arc<Supervisor> {
    // The registry needs no providers, so the provider-free query shim is
    // the right lightweight constructor for these unit tests.
    Arc::new(Supervisor::for_query_shim(scp_runtime::domain_handlers()))
}

// -- sender-epoch monotonicity + overshoot ----------------------------------

#[test]
fn sender_epoch_advances_monotonically() {
    let s = sup();
    // First observation must be > 0 (matches SenderKeyStore::set_checked).
    assert_eq!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, 0, MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::SenderEpochNotMonotonic {
            did: DID.to_owned(),
            current: 0,
            proposed: 0,
        })
    );
    assert!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, 1, MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    assert!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, 5, MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    // Equal or lower is rejected (rollback / replay).
    assert!(matches!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, 5, MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
    ));
    assert!(matches!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, 4, MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
    ));
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![(DID.to_owned(), 5)]
    );
}

#[test]
fn sender_epoch_rejects_overshoot() {
    let s = sup();
    // From an absent floor (0), the ceiling is 0 + MAX_EPOCH_ADVANCE.
    assert_eq!(
        s.check_and_advance_sender_epoch_for_test(
            &CTX,
            DID,
            MAX_EPOCH_ADVANCE + 1,
            MAX_EPOCH_ADVANCE
        ),
        Err(FloorAdvanceError::SenderEpochOvershoot {
            did: DID.to_owned(),
            ceiling: MAX_EPOCH_ADVANCE,
            proposed: MAX_EPOCH_ADVANCE + 1,
        })
    );
    // Exactly at the ceiling is accepted.
    assert!(
        s.check_and_advance_sender_epoch_for_test(&CTX, DID, MAX_EPOCH_ADVANCE, MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    // A rejected overshoot leaves no floor written.
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![(DID.to_owned(), MAX_EPOCH_ADVANCE)]
    );
}

// -- recv-sequence monotonicity + overshoot ---------------------------------

#[test]
fn recv_sequence_advances_lexicographically() {
    let s = sup();
    // First observation for an absent sender is accepted (matches open()'s
    // Some-guarded replay check).
    assert!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(0, 3), MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    // Same (epoch, seq) is a replay — rejected.
    assert!(matches!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(0, 3), MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
    ));
    // Lower sequence at the same epoch — rejected.
    assert!(matches!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(0, 2), MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
    ));
    // Higher sequence at the same epoch — accepted.
    assert!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(0, 4), MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    // Advance to a higher epoch — accepted (epoch 1 is within the ceiling
    // `sender_epoch_floor(0) + MAX_EPOCH_ADVANCE`).
    assert!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(1, 0), MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    // Lower epoch, even with a much higher seq — rejected (lexicographic on
    // the `(epoch, seq)` pair: `(0, 99) < (1, 0)`).
    assert!(matches!(
        s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(0, 99), MAX_EPOCH_ADVANCE),
        Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
    ));
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![(DID.to_owned(), rf(1, 0))]
    );
}

#[test]
fn recv_sequence_overshoot_reads_epoch_floor_from_same_entry() {
    let s = sup();
    // Advance the sender epoch floor to 5 in the SAME entry.
    s.check_and_advance_sender_epoch_for_test(&CTX, DID, 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    // A recv epoch beyond epoch_floor(5) + MAX_EPOCH_ADVANCE is rejected.
    assert_eq!(
        s.check_and_advance_recv_sequence_for_test(
            &CTX,
            DID,
            rf(5 + MAX_EPOCH_ADVANCE + 1, 0),
            MAX_EPOCH_ADVANCE
        ),
        Err(FloorAdvanceError::RecvSequenceOvershoot {
            did: DID.to_owned(),
            ceiling: 5 + MAX_EPOCH_ADVANCE,
            proposed: 5 + MAX_EPOCH_ADVANCE + 1,
        })
    );
    // At the ceiling — accepted.
    assert!(
        s.check_and_advance_recv_sequence_for_test(
            &CTX,
            DID,
            rf(5 + MAX_EPOCH_ADVANCE, 0),
            MAX_EPOCH_ADVANCE
        )
        .is_ok()
    );
}

#[test]
fn recv_ceiling_reads_the_advanced_sender_epoch_floor_f2_discriminating() {
    // F-2 (catch-up-after-lag), DISCRIMINATING: the recv overshoot ceiling
    // must read the ADVANCED sender_epoch floor from the SAME entry — not a
    // stale baseline. Pick a recv epoch (1002) that sits in the gap between
    // the stale floor-0 ceiling (0 + MAX_EPOCH_ADVANCE = 1000, which would
    // REJECT 1002) and the advanced floor-1500 ceiling (1500 +
    // MAX_EPOCH_ADVANCE = 2500, which ACCEPTS 1002). Acceptance therefore
    // PROVES the just-advanced floor was read (a stale read would reject).
    const ADVANCED: [u8; 32] = [0xF2u8; 32];
    const STALE: [u8; 32] = [0xF3u8; 32];
    let recv_epoch = MAX_EPOCH_ADVANCE + 2; // 1002 — beyond the stale ceiling.

    // Advanced entry: sender epoch floor raised to 1500 (as the key-dist seam
    // would). max_advance = 1500 lets the single advance from 0 reach it.
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&ADVANCED, DID, 1500, 1500)
        .unwrap();
    assert!(
        s.check_and_advance_recv_sequence_for_test(
            &ADVANCED,
            DID,
            rf(recv_epoch, 0),
            MAX_EPOCH_ADVANCE
        )
        .is_ok(),
        "a recv at epoch {recv_epoch} must be ACCEPTED once sender_epochs[did]=1500 \
             (ceiling 2500) — proving the recv ceiling read the ADVANCED floor"
    );

    // Stale entry (SAME recv epoch, floor still 0): the ceiling is 0 +
    // MAX_EPOCH_ADVANCE = 1000, so the identical recv is REJECTED. This is the
    // discriminator: if the recv ceiling ignored the floor, both would pass.
    assert!(
        matches!(
            s.check_and_advance_recv_sequence_for_test(
                &STALE,
                DID,
                rf(recv_epoch, 0),
                MAX_EPOCH_ADVANCE
            ),
            Err(FloorAdvanceError::RecvSequenceOvershoot { .. })
        ),
        "the SAME recv epoch {recv_epoch} against a stale floor-0 ceiling (1000) must be \
             REJECTED — so acceptance above is not vacuous"
    );
}

// -- merge / seed / export --------------------------------------------------

#[test]
fn merge_is_monotone_max_and_seed_is_insert_if_absent() {
    let s = sup();
    // seed creates a default-empty entry (insert-if-absent).
    s.seed_context_floors_for_test(&CTX);
    assert!(s.export_sender_key_epochs_for_test(&CTX).is_empty());

    // Advance one sender, then merge a mix of lower + higher + new.
    s.check_and_advance_sender_epoch_for_test(&CTX, DID, 10, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.validate_and_merge_epoch_floors_for_test(
        &CTX,
        vec![
            (DID.to_owned(), 4),              // lower — must NOT regress
            (DID.to_owned(), 12),             // higher — wins via max
            ("did:dht:zOther".to_owned(), 7), // new sender
        ],
        MAX_EPOCH_ADVANCE,
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();
    let mut got = s.export_sender_key_epochs_for_test(&CTX);
    got.sort();
    assert_eq!(
        got,
        vec![(DID.to_owned(), 12), ("did:dht:zOther".to_owned(), 7)]
    );

    // seed after advance must NOT reset the entry.
    s.seed_context_floors_for_test(&CTX);
    let mut after = s.export_sender_key_epochs_for_test(&CTX);
    after.sort();
    assert_eq!(after, got);

    // recv merge twin — monotone max, lexicographic.
    s.validate_and_merge_recv_sequence_floors_for_test(
        &CTX,
        vec![(DID.to_owned(), rf(2, 9)), (DID.to_owned(), rf(1, 0))],
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![(DID.to_owned(), rf(2, 9))]
    );
    // empty merge is a no-op that does not error.
    assert!(
        s.validate_and_merge_epoch_floors_for_test(
            &CTX,
            vec![],
            MAX_EPOCH_ADVANCE,
            MergePolicy::RejectRegression
        )
        .is_ok()
    );
}

// -- §23.17.2 validating epoch merge (Inv-2/Inv-3/Inv-4 + overshoot) --------

#[test]
fn epoch_merge_max_merges_accepted_monotonic() {
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_sender_epoch_for_test(&CTX, "B", 10, MAX_EPOCH_ADVANCE)
        .unwrap();
    // Inv-2 (MaxMergeTrustedLocal): B:3 lags — tolerated, live 10 dominates;
    // A:8 wins via max; C:2 is a new sender (insert-if-absent).
    s.validate_and_merge_epoch_floors_for_test(
        &CTX,
        vec![
            ("A".to_owned(), 8),
            ("B".to_owned(), 3),
            ("C".to_owned(), 2),
        ],
        MAX_EPOCH_ADVANCE,
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();
    let mut got = s.export_sender_key_epochs_for_test(&CTX);
    got.sort();
    assert_eq!(
        got,
        vec![
            ("A".to_owned(), 8),
            ("B".to_owned(), 10),
            ("C".to_owned(), 2)
        ]
    );
}

#[test]
fn epoch_merge_rejects_regression_atomically() {
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_sender_epoch_for_test(&CTX, "B", 10, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_sender_epoch_for_test(&CTX, "C", 1, MAX_EPOCH_ADVANCE)
        .unwrap();
    let before = {
        let mut v = s.export_sender_key_epochs_for_test(&CTX);
        v.sort();
        v
    };
    // Inv-3 (RejectRegression): A:9 validates OK first, then B:3 < 10 fails.
    // The FIRST failure is returned (single-sender FloorAdvanceError).
    assert_eq!(
        s.validate_and_merge_epoch_floors_for_test(
            &CTX,
            vec![("A".to_owned(), 9), ("B".to_owned(), 3)],
            MAX_EPOCH_ADVANCE,
            MergePolicy::RejectRegression,
        ),
        Err(FloorAdvanceError::SenderEpochNotMonotonic {
            did: "B".to_owned(),
            current: 10,
            proposed: 3,
        })
    );
    // Atomicity: A was NOT advanced despite validating OK — no partial apply.
    let after = {
        let mut v = s.export_sender_key_epochs_for_test(&CTX);
        v.sort();
        v
    };
    assert_eq!(after, before, "rejected merge leaves the map unchanged");
}

#[test]
fn epoch_merge_rejects_overshoot_under_reject_regression_only() {
    // ADR-049 A2: the epoch-poisoning overshoot ceiling is enforced ONLY on
    // the UNTRUSTED-import path (RejectRegression). Under MaxMergeTrustedLocal
    // (trusted self-snapshot / cold restore) the accumulated high-water loads
    // VERBATIM, so a context whose true floor exceeds MAX_EPOCH_ADVANCE stays
    // restorable (ADR-049:239).
    {
        let s = sup();
        s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        // RejectRegression: overshoot rejected atomically (floor unchanged).
        assert_eq!(
            s.validate_and_merge_epoch_floors_for_test(
                &CTX,
                vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE + 1)],
                MAX_EPOCH_ADVANCE,
                MergePolicy::RejectRegression,
            ),
            Err(FloorAdvanceError::SenderEpochOvershoot {
                did: "A".to_owned(),
                ceiling: 5 + MAX_EPOCH_ADVANCE,
                proposed: 5 + MAX_EPOCH_ADVANCE + 1,
            })
        );
        assert_eq!(
            s.export_sender_key_epochs_for_test(&CTX),
            vec![("A".to_owned(), 5)]
        );
        // Exactly at the ceiling is accepted under RejectRegression.
        s.validate_and_merge_epoch_floors_for_test(
            &CTX,
            vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE)],
            MAX_EPOCH_ADVANCE,
            MergePolicy::RejectRegression,
        )
        .unwrap();
        assert_eq!(
            s.export_sender_key_epochs_for_test(&CTX),
            vec![("A".to_owned(), 5 + MAX_EPOCH_ADVANCE)]
        );
    }
    {
        // MaxMergeTrustedLocal: a high floor far beyond the ceiling loads
        // VERBATIM (no overshoot reject).
        let s = sup();
        s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
            .unwrap();
        let far = 5 + MAX_EPOCH_ADVANCE * 10 + 1;
        s.validate_and_merge_epoch_floors_for_test(
            &CTX,
            vec![("A".to_owned(), far)],
            MAX_EPOCH_ADVANCE,
            MergePolicy::MaxMergeTrustedLocal,
        )
        .expect("trusted-local cold restore loads a high floor verbatim");
        assert_eq!(
            s.export_sender_key_epochs_for_test(&CTX),
            vec![("A".to_owned(), far)]
        );
    }
}

#[test]
fn epoch_merge_trusted_local_tolerates_vs_untrusted_rejects() {
    let regressing = vec![("A".to_owned(), 3)];
    // Inv-2 (trusted-local): the lagging floor is tolerated; live 10 dominates.
    let trusted = sup();
    trusted
        .check_and_advance_sender_epoch_for_test(&CTX, "A", 10, MAX_EPOCH_ADVANCE)
        .unwrap();
    trusted
        .validate_and_merge_epoch_floors_for_test(
            &CTX,
            regressing.clone(),
            MAX_EPOCH_ADVANCE,
            MergePolicy::MaxMergeTrustedLocal,
        )
        .unwrap();
    assert_eq!(
        trusted.export_sender_key_epochs_for_test(&CTX),
        vec![("A".to_owned(), 10)]
    );
    // Inv-3 (untrusted): the SAME regression is rejected.
    let untrusted = sup();
    untrusted
        .check_and_advance_sender_epoch_for_test(&CTX, "A", 10, MAX_EPOCH_ADVANCE)
        .unwrap();
    assert!(matches!(
        untrusted.validate_and_merge_epoch_floors_for_test(
            &CTX,
            regressing,
            MAX_EPOCH_ADVANCE,
            MergePolicy::RejectRegression,
        ),
        Err(FloorAdvanceError::SenderEpochNotMonotonic { .. })
    ));
    assert_eq!(
        untrusted.export_sender_key_epochs_for_test(&CTX),
        vec![("A".to_owned(), 10)]
    );
}

#[test]
fn epoch_merge_empty_is_noop() {
    for policy in [
        MergePolicy::MaxMergeTrustedLocal,
        MergePolicy::RejectRegression,
    ] {
        let s = sup();
        s.check_and_advance_sender_epoch_for_test(&CTX, "A", 7, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.validate_and_merge_epoch_floors_for_test(&CTX, vec![], MAX_EPOCH_ADVANCE, policy)
            .unwrap();
        assert_eq!(
            s.export_sender_key_epochs_for_test(&CTX),
            vec![("A".to_owned(), 7)]
        );
    }
}

// -- §23.17.2/.3 validating recv-sequence merge -----------------------------

#[test]
fn recv_merge_max_merges_lexicographic() {
    let s = sup();
    s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(2, 5), MAX_EPOCH_ADVANCE)
        .unwrap();
    // Inv-4 max-merge, epoch-major: rf(2,9) dominates; rf(1,99) is below
    // (lower epoch beats higher sequence).
    s.validate_and_merge_recv_sequence_floors_for_test(
        &CTX,
        vec![("A".to_owned(), rf(2, 9)), ("A".to_owned(), rf(1, 99))],
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("A".to_owned(), rf(2, 9))]
    );
}

#[test]
fn recv_merge_rejects_regression_atomically() {
    let s = sup();
    s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(3, 0), MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_recv_sequence_for_test(&CTX, "B", rf(1, 4), MAX_EPOCH_ADVANCE)
        .unwrap();
    // Inv-3: rf(2,9) < rf(3,0) lexicographically (lower epoch) — rejected.
    assert_eq!(
        s.validate_and_merge_recv_sequence_floors_for_test(
            &CTX,
            vec![("A".to_owned(), rf(2, 9))],
            MergePolicy::RejectRegression,
        ),
        Err(FloorAdvanceError::RecvSequenceNotMonotonic {
            did: "A".to_owned(),
            current: rf(3, 0),
            proposed: rf(2, 9),
        })
    );
    // Atomicity: A keeps rf(3,0); sibling B is untouched.
    let mut got = s.export_recv_sequence_floors_for_test(&CTX);
    got.sort();
    assert_eq!(
        got,
        vec![("A".to_owned(), rf(3, 0)), ("B".to_owned(), rf(1, 4))]
    );
}

#[test]
fn recv_merge_rejects_epoch_overshoot() {
    let s = sup();
    // Advance the sender epoch floor to 5 in the SAME entry.
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    // The recv overshoot ceiling reads `sender_epochs[A]`(5) + MAX_EPOCH_ADVANCE
    // from the SAME entry (F-3): a recv epoch beyond it is rejected.
    assert_eq!(
        s.validate_and_merge_recv_sequence_floors_for_test(
            &CTX,
            vec![("A".to_owned(), rf(5 + MAX_EPOCH_ADVANCE + 1, 0))],
            MergePolicy::RejectRegression,
        ),
        Err(FloorAdvanceError::RecvSequenceOvershoot {
            did: "A".to_owned(),
            ceiling: 5 + MAX_EPOCH_ADVANCE,
            proposed: 5 + MAX_EPOCH_ADVANCE + 1,
        })
    );
    // Rejected atomically — no recv floor written for A.
    assert!(s.export_recv_sequence_floors_for_test(&CTX).is_empty());
}

#[test]
fn recv_merge_trusted_local_loads_high_epoch_verbatim() {
    // ADR-049 A2: under MaxMergeTrustedLocal the recv floor's epoch-axis
    // ceiling is SKIPPED — a trusted self-snapshot / cold restore loads the
    // recv floor verbatim even when its epoch far exceeds MAX_EPOCH_ADVANCE.
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    let far_epoch = 5 + MAX_EPOCH_ADVANCE * 10 + 1;
    s.validate_and_merge_recv_sequence_floors_for_test(
        &CTX,
        vec![("A".to_owned(), rf(far_epoch, 7))],
        MergePolicy::MaxMergeTrustedLocal,
    )
    .expect("trusted-local cold restore loads a high recv floor verbatim");
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("A".to_owned(), rf(far_epoch, 7))]
    );
}

#[test]
fn recv_merge_trusted_local_tolerates_regression() {
    let s = sup();
    s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(3, 0), MAX_EPOCH_ADVANCE)
        .unwrap();
    // Inv-2: a lagging restored recv floor is tolerated; live rf(3,0) dominates.
    s.validate_and_merge_recv_sequence_floors_for_test(
        &CTX,
        vec![("A".to_owned(), rf(2, 9))],
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("A".to_owned(), rf(3, 0))]
    );
}

#[test]
fn recv_merge_empty_is_noop() {
    for policy in [
        MergePolicy::MaxMergeTrustedLocal,
        MergePolicy::RejectRegression,
    ] {
        let s = sup();
        s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(1, 1), MAX_EPOCH_ADVANCE)
            .unwrap();
        s.validate_and_merge_recv_sequence_floors_for_test(&CTX, vec![], policy)
            .unwrap();
        assert_eq!(
            s.export_recv_sequence_floors_for_test(&CTX),
            vec![("A".to_owned(), rf(1, 1))]
        );
    }
}

// -- combined cross-axis validating merge (validate_and_merge_all_floors) ----

#[test]
fn all_floors_merge_is_cross_axis_atomic() {
    // The A-defect guard: the EPOCH axis validates OK but the RECV axis
    // regresses → the WHOLE merge is rejected and BOTH maps are UNCHANGED (the
    // epoch apply must NOT stick — the sequential two-merge form would have
    // left the epoch floor advanced with no rollback).
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(3, 0), MAX_EPOCH_ADVANCE)
        .unwrap();
    let before_epochs = s.export_sender_key_epochs_for_test(&CTX);
    let before_recv = s.export_recv_sequence_floors_for_test(&CTX);

    // epoch A:9 would validate (>= 5, within ceiling), but recv A:rf(2,9) <
    // rf(3,0) regresses under RejectRegression.
    assert!(matches!(
        s.validate_and_merge_all_floors_for_test(
            &CTX,
            vec![("A".to_owned(), 9)],
            vec![("A".to_owned(), rf(2, 9))],
            MAX_EPOCH_ADVANCE,
            MergePolicy::RejectRegression,
        ),
        Err(FloorAdvanceError::RecvSequenceNotMonotonic { .. })
    ));
    // CROSS-AXIS ATOMICITY: the epoch floor did NOT advance to 9.
    assert_eq!(s.export_sender_key_epochs_for_test(&CTX), before_epochs);
    assert_eq!(s.export_recv_sequence_floors_for_test(&CTX), before_recv);
}

#[test]
fn all_floors_merge_applies_both_axes_on_success() {
    let s = sup();
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    // recv epoch 6 is within the PROJECTED epoch (max(local 5, incoming 6))
    // + MAX_EPOCH_ADVANCE — accepted because the epoch merge in the SAME call
    // raises A to 6 first.
    s.validate_and_merge_all_floors_for_test(
        &CTX,
        vec![("A".to_owned(), 6)],
        vec![("A".to_owned(), rf(6, 2))],
        MAX_EPOCH_ADVANCE,
        MergePolicy::RejectRegression,
    )
    .expect("both axes valid — merge applies");
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![("A".to_owned(), 6)]
    );
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("A".to_owned(), rf(6, 2))]
    );
}

#[test]
fn all_floors_merge_empty_both_is_noop() {
    for policy in [
        MergePolicy::MaxMergeTrustedLocal,
        MergePolicy::RejectRegression,
    ] {
        let s = sup();
        s.check_and_advance_sender_epoch_for_test(&CTX, "A", 7, MAX_EPOCH_ADVANCE)
            .unwrap();
        s.validate_and_merge_all_floors_for_test(&CTX, vec![], vec![], MAX_EPOCH_ADVANCE, policy)
            .unwrap();
        assert_eq!(
            s.export_sender_key_epochs_for_test(&CTX),
            vec![("A".to_owned(), 7)]
        );
    }
}

#[test]
fn all_floors_merge_trusted_local_loads_high_epochs_verbatim() {
    // Cross-axis cold-restore of a context whose floors far exceed the
    // ceiling loads verbatim under MaxMergeTrustedLocal (A2).
    let s = sup();
    let far = 5000u64;
    s.validate_and_merge_all_floors_for_test(
        &CTX,
        vec![("A".to_owned(), far)],
        vec![("A".to_owned(), rf(far, 3))],
        MAX_EPOCH_ADVANCE,
        MergePolicy::MaxMergeTrustedLocal,
    )
    .expect("trusted-local cold restore loads high floors verbatim");
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![("A".to_owned(), far)]
    );
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("A".to_owned(), rf(far, 3))]
    );
}

// -- member-granular floor prune --------------------------------------------

#[test]
fn remove_member_floors_drops_member_keeps_siblings() {
    const OTHER_CTX: [u8; 32] = [0x11u8; 32];
    let s = sup();
    // Populate BOTH maps for two members.
    s.check_and_advance_sender_epoch_for_test(&CTX, "A", 5, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_sender_epoch_for_test(&CTX, "B", 7, MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_recv_sequence_for_test(&CTX, "A", rf(1, 2), MAX_EPOCH_ADVANCE)
        .unwrap();
    s.check_and_advance_recv_sequence_for_test(&CTX, "B", rf(3, 4), MAX_EPOCH_ADVANCE)
        .unwrap();

    s.remove_member_floors_for_test(&CTX, "A");

    // A is gone from BOTH maps; B is intact in BOTH; the ctx entry survives.
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![("B".to_owned(), 7)]
    );
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("B".to_owned(), rf(3, 4))]
    );
    assert_eq!(
        s.floors_for_test().len(),
        1,
        "ctx entry kept — only the member pruned"
    );

    // Idempotent: removing the now-absent member again is a no-op.
    s.remove_member_floors_for_test(&CTX, "A");
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![("B".to_owned(), 7)]
    );
    assert_eq!(
        s.export_recv_sequence_floors_for_test(&CTX),
        vec![("B".to_owned(), rf(3, 4))]
    );

    // Absent ctx is a no-op — it does not create an entry.
    s.remove_member_floors_for_test(&OTHER_CTX, "A");
    assert!(s.export_sender_key_epochs_for_test(&OTHER_CTX).is_empty());
    assert_eq!(
        s.floors_for_test().len(),
        1,
        "absent-ctx prune created no entry"
    );
}

// -- Decision-13: exactly ONE registry entry per gate (single-guard body) ---

#[test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "test read: the DashMap entry guard is held only across the immediate assertions verifying the single-entry invariant"
)]
fn gate_uses_single_entry_no_double_insert() {
    let s = sup();
    assert_eq!(s.floors_for_test().len(), 0);
    s.check_and_advance_sender_epoch_for_test(&CTX, DID, 1, MAX_EPOCH_ADVANCE)
        .unwrap();
    // One gate → exactly one context entry created.
    assert_eq!(
        s.floors_for_test().len(),
        1,
        "one entry() per gate (Decision-13)"
    );
    // A recv gate on the same ctx reuses the SAME entry — no second insert.
    s.check_and_advance_recv_sequence_for_test(&CTX, DID, rf(1, 1), MAX_EPOCH_ADVANCE)
        .unwrap();
    assert_eq!(
        s.floors_for_test().len(),
        1,
        "recv gate reuses the same ctx entry"
    );
    // Both floors live under that single entry.
    let entry = s.floors_for_test().get(&CTX).expect("ctx entry");
    assert_eq!(entry.sender_epochs_for_test().get(DID).copied(), Some(1));
    assert_eq!(
        entry.recv_sequence_for_test().get(DID).copied(),
        Some(rf(1, 1))
    );
}

// -- Decision-14: gate work is O(1) — independent of sender count -----------

#[test]
#[allow(
    clippy::significant_drop_tightening,
    reason = "test read: the DashMap entry guard is held only across the immediate assertions verifying O(1) per-sender isolation"
)]
fn gate_is_o1_independent_of_sender_count() {
    let s = sup();
    // Pre-load the registry entry with many senders.
    for i in 0..5_000u64 {
        let did = format!("did:dht:zBulk{i}");
        s.check_and_advance_sender_epoch_for_test(&CTX, &did, 1, MAX_EPOCH_ADVANCE)
            .unwrap();
    }
    // A single-sender advance in a large registry touches ONLY that sender:
    // no O(senders) scan/clone (the property the Decision-14 <15% budget
    // rests on — the mirror-forward reads the value from `open()`/getters in
    // O(1), never via an O(senders) export re-read).
    s.check_and_advance_sender_epoch_for_test(&CTX, DID, 42, MAX_EPOCH_ADVANCE)
        .unwrap();
    let entry = s.floors_for_test().get(&CTX).expect("ctx entry");
    assert_eq!(entry.sender_epochs_for_test().get(DID).copied(), Some(42));
    // Every pre-loaded sender is untouched (still 1) — the gate did not
    // rewrite or iterate them.
    assert_eq!(
        entry
            .sender_epochs_for_test()
            .get("did:dht:zBulk0")
            .copied(),
        Some(1)
    );
    assert_eq!(
        entry
            .sender_epochs_for_test()
            .get("did:dht:zBulk4999")
            .copied(),
        Some(1)
    );
    assert_eq!(entry.sender_epochs_for_test().len(), 5_001);
}

// -- shuttle-style strict-monotonicity concurrency test ---------------------
//
// NOTE: this lives inline (crate-internal) rather than in
// `tests/shuttle_actor.rs` because the registry gate is capability-reduced
// (`pub(in crate::context)`) and is NOT reachable from the external test
// crate without violating Invariant 3 / the cross-layer gate. It exercises
// the same "strict-monotonicity under concurrent writers" invariant with
// real OS threads, exactly like the sibling `context_handle_cas_stress`
// stress test in `tests/shuttle_actor.rs`.

#[test]
fn concurrent_advances_are_strictly_monotone_no_lost_update() {
    const LADDER: u64 = 2_000;
    let s = sup();

    // Two threads race the SAME (ctx, did) ladder 1..=LADDER. Each epoch in
    // the ladder can be accepted by AT MOST ONE thread (the single-`entry()`
    // guard serializes gate-then-write); a slower thread re-loads the fresh
    // higher floor and is rejected. Under ANY interleaving the invariants are:
    //  (a) strict monotonicity — no accepted epoch is ever <= a prior floor;
    //  (b) no lost update — every epoch 1..=LADDER is accepted EXACTLY once,
    //      so the two threads' success counts sum to exactly LADDER;
    //  (c) the final floor is exactly the ladder top.
    let worker = |s: Arc<Supervisor>| {
        move || {
            let mut accepted = 0u64;
            for epoch in 1..=LADDER {
                // max_advance = LADDER guarantees +1 steps never overshoot.
                if s.check_and_advance_sender_epoch_for_test(&CTX, DID, epoch, LADDER)
                    .is_ok()
                {
                    accepted += 1;
                }
            }
            accepted
        }
    };
    let a = thread::spawn(worker(Arc::clone(&s)));
    let b = thread::spawn(worker(Arc::clone(&s)));
    let count_a = a.join().expect("thread a");
    let count_b = b.join().expect("thread b");

    // (b) no lost update, no double-accept.
    assert_eq!(
        count_a + count_b,
        LADDER,
        "each epoch must be accepted exactly once across both racers"
    );
    // (a)/(c) the floor landed exactly on the ladder top, strictly monotone.
    assert_eq!(
        s.export_sender_key_epochs_for_test(&CTX),
        vec![(DID.to_owned(), LADDER)]
    );
}

// -- SupervisorHandle fan-out accessors forward to the registry -------------

#[test]
fn handle_accessors_forward_to_registry() {
    let s = sup();
    let h = SupervisorHandle::wrap_for_test(&s);

    h.seed_context_floors(&CTX).unwrap();
    assert!(
        h.check_and_advance_sender_epoch(&CTX, DID, 3, MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    assert!(
        h.check_and_advance_recv_sequence(&CTX, DID, rf(3, 1), MAX_EPOCH_ADVANCE)
            .is_ok()
    );
    h.validate_and_merge_all_floors_for_test(
        &CTX,
        vec![(DID.to_owned(), 8)],
        vec![(DID.to_owned(), rf(8, 2))],
        MAX_EPOCH_ADVANCE,
        MergePolicy::MaxMergeTrustedLocal,
    )
    .unwrap();

    // The handle reads must agree with the direct Supervisor reads.
    let epochs = h.export_sender_key_epochs(&CTX).unwrap();
    let recv = h.export_recv_sequence_floors(&CTX).unwrap();
    assert_eq!(epochs, s.export_sender_key_epochs_for_test(&CTX));
    assert_eq!(recv, s.export_recv_sequence_floors_for_test(&CTX));
    assert_eq!(epochs, vec![(DID.to_owned(), 8)]);
    assert_eq!(recv, vec![(DID.to_owned(), rf(8, 2))]);

    // The remove_member_floors fan-out reaches the registry: pruning DID via
    // the handle drops it from BOTH maps of the direct Supervisor view.
    h.remove_member_floors(&CTX, DID);
    assert!(s.export_sender_key_epochs_for_test(&CTX).is_empty());
    assert!(s.export_recv_sequence_floors_for_test(&CTX).is_empty());
}
