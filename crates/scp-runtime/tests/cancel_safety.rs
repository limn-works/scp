//! ADR-049 cancel-safety verification (`cargo test -p scp-runtime --test
//! cancel_safety`, named by the ADR §Verification block).
//!
//! # What "cancel-safety" means here
//!
//! A future dropped (cancelled) mid-flight — because a `tokio::select!`
//! branch lost the race or a `tokio::time::timeout` elapsed — MUST NOT leave
//! partial/committed state or leak a reservation. This suite drives that
//! property through TWO different surfaces under real tokio cancellation (a
//! suspended future dropped in place — a distinct runtime path from the
//! `?`-early-return and panic-unwind paths the `sequence.rs` unit tests
//! already cover):
//!
//! 1. Cases 1 & 2 — the
//!    [`SequenceReservation`](scp_runtime::context::actor::SequenceReservation)
//!    RAII TYPE CONTRACT (ADR-049 §8 "`SequenceReservation` RAII": rollback
//!    fires on `Drop` unless `commit()` ran; monotonicity "holds across
//!    panics, cancellations, and early `?` returns"). These are
//!    PRIMITIVE-LEVEL tests of the public guard type, NOT of the real send
//!    path — see the honesty note below.
//! 2. Case 3 — the `SagaSetReservation` per-participant-context-set saga
//!    gating guard (ADR-049 §3a, spec §5.15.4), driven through the REAL
//!    production reservation critical section (`try_reserve_context_set`) on
//!    a real `Supervisor`. `start_saga` runs the FSM INLINE under the guard
//!    (`run_saga(..).await`), so a saga future cancelled in-flight releases
//!    its slot rather than wedging every overlapping saga with a leaked
//!    `SagaBusy`.
//!
//! # Honesty note — Cases 1 & 2 do NOT drive the real send handler
//!
//! It is tempting to claim these witness "the cancellation arm of the real
//! send path." They do not, and the code says why. The primary production
//! send handler,
//! [`handle_send_message`](../src/context/actor/handlers/messaging.rs), does
//! NOT rely on `SequenceReservation`'s drop-on-cancel:
//!
//! - It `reserve()`s AND `commit()`s the actor-shape `send_tracker`
//!   SYNCHRONOUSLY and adjacently (one `{ … }` block, no `.await` between),
//!   BEFORE building the transport future. So no UNCOMMITTED reservation is
//!   ever held across the transport await — a mid-await drop has nothing to
//!   roll back.
//! - It then awaits the transport under its OWN `tokio::time::timeout`
//!   (`HANDLER_TIMEOUT`) and rolls the tracker back MANUALLY in the
//!   `Ok(Err(..))` / `Err(_elapsed)` arms — arms that run only when `timeout`
//!   RETURNS. The wire sequence in `messaging_helpers::send_message` is the
//!   same shape: `MembershipState::next_sequence_number` then a MANUAL
//!   `rollback_sequence_number` via the `SendAbort` token in post-await error
//!   arms. Neither uses RAII drop-on-cancel.
//!
//! Consequently the real send handler cannot be turned into a
//! drop-mid-await cancellation test that asserts a sequence rollback:
//!
//! - (a) There is no uncommitted guard across the await to roll back.
//! - (b) EXTERNAL cancellation of the handler future runs NONE of the manual
//!   rollback arms, so it would NOT roll the sequence back — asserting
//!   "rolled back on cancel" against the real handler would assert a FALSE
//!   property. The handler future is anyway never caller-cancellable
//!   (block-until-terminal — see `ContextActorHandle::send`'s cancellation
//!   docs); only an actor abort drops it, after which the COALESCED,
//!   Class-C send-tracker bump is floored by the persisted snapshot on
//!   respawn (ADR §8/§9), a durability property no in-process drop test can
//!   observe.
//! - (c) Even to invoke the handler at all requires a full
//!   `ClassSCell` + `ActorDeps` fixture (MLS crypto, an enrolled-sender
//!   membership, economy, event log, persistence, transport) plus a stalling
//!   `ContextTransportProvider`; and the only cancel behaviour that fixture
//!   could observe is the `HANDLER_TIMEOUT`-RETURN arm — a TIMEOUT test, not
//!   a drop-mid-await test.
//!
//! So Cases 1 & 2 are scoped honestly as witnesses of the `SequenceReservation`
//! TYPE contract's async-drop dimension — defense-in-depth for any future
//! async caller that DOES hold an uncommitted guard across an await (the ADR
//! §8 "cancellations" clause), and, for Case 2, the primitive analog of the
//! real handler's commit-BEFORE-transport-await ordering. The load-bearing,
//! production-path cancellation test in this file is Case 3.
//!
//! # Why each case is real and non-duplicate
//!
//! Each case was validated by transiently inverting its terminal assertion
//! and confirming the test FAILS (recorded in the task report), so none is
//! tautological. The existing coverage each case extends:
//!
//! - `sequence.rs` unit tests exercise SYNC scope-drop and `catch_unwind`
//!   panic-unwind — never a tokio future dropped while suspended at an
//!   `.await`. Cases 1 and 2 add ONLY that async-drop dimension of the guard
//!   contract (the delta is the runtime drop path, not new rollback logic).
//! - `supervisor.rs` / `actor_saga_coordinator.rs` cover overlap-while-held
//!   and sequential re-arm (release on a NORMAL terminal) — never release
//!   when the holding future is CANCELLED. Case 3 closes that gap against the
//!   real critical section.
//!
//! Class-S mutation atomicity under cancellation (ADR §9 fail-closed) is NOT
//! re-tested here: the actor processes each command to terminal regardless
//! of caller cancellation (the reply oneshot receiver-drop is the only
//! cancellation vector, and it only discards the reply — see the
//! `ContextActorHandle::send` cancellation docs), and the mutation is guarded
//! by the compile-time `ClassSCell` boundary (ADR §9 Enforcement), not by a
//! runtime property a cancellation test could observe.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    // Doc prose cites ADR/spec section titles unquoted for readability.
    clippy::doc_markdown
)]

use std::sync::Arc;
use std::time::Duration;

use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_runtime::context::actor::{SendSequenceTracker, SequenceReservation};
use scp_runtime::context::supervisor::{
    ProtocolRepositorySagaJournal, SagaInput, SagaJournal, Supervisor, SupervisorConfig,
};

// ---------------------------------------------------------------------------
// A cancellation window that is unambiguously mid-flight.
//
// `pending()` never resolves, so a future that awaits it is guaranteed to be
// dropped WHILE SUSPENDED at that point — the reservation/guard it holds is
// still outstanding (never committed / released by the normal path). This is
// the exact "cancelled mid-flight" condition the ADR cares about; a future
// that could resolve on its own would make "cancellation" unobservable.
// ---------------------------------------------------------------------------

/// Poll budget for the never-resolving branch before we cancel it. Small
/// enough to keep the suite fast; the tests assert on the cancellation
/// OUTCOME (`Elapsed` / the losing `select!` branch), not on wall-clock time.
const CANCEL_AFTER: Duration = Duration::from_millis(25);

// ---------------------------------------------------------------------------
// Case 1 — a send future cancelled BEFORE commit rolls the sequence back.
// ---------------------------------------------------------------------------

/// PRIMITIVE-LEVEL contract test (see the module "Honesty note"): the public
/// [`SequenceReservation`] guard's `Drop` rolls the tracker back when the
/// holding future is CANCELLED between `reserve()` and `commit()`. This
/// MODELS a hypothetical async caller that holds an uncommitted reservation
/// across an await — the ADR-049 §8 "holds across … cancellations" clause,
/// defense-in-depth for such a caller. The primary production send handler
/// does NOT have this shape (it commits synchronously up-front), so this is a
/// type-contract witness, not a real-send-path test. After rollback the slot
/// must be released (no leaked sequence) AND reusable by the next reservation
/// (no monotonicity gap the AAD byte-identity contract forbids).
///
/// Delta over `sequence.rs`: those unit tests roll back via synchronous
/// scope-drop and `catch_unwind` panic-unwind; this adds ONLY the async-drop
/// dimension — the real tokio runtime dropping a future suspended at an
/// `.await` in place.
#[tokio::test]
async fn send_future_cancelled_before_commit_rolls_back_sequence() {
    let mut tracker = SendSequenceTracker::new();

    // Model an async caller that reserves, awaits, then would commit; cancel
    // it at the await. The reservation is never committed (the `pending()`
    // await never resolves, so `commit()` is unreachable).
    let outcome = tokio::time::timeout(CANCEL_AFTER, async {
        // AAD sequence is read pre-reserve per the byte-identity convention.
        let aad_sequence = tracker.last_issued();
        assert_eq!(aad_sequence, 0, "first send reads AAD sequence 0");

        let reservation = SequenceReservation::reserve(&mut tracker);
        assert_eq!(reservation.number(), 1, "first reservation is slot 1");

        // A hypothetical await the reservation is held across — cancelled here.
        std::future::pending::<()>().await;

        reservation.commit(); // unreachable: pending() never resolves
    })
    .await;

    assert!(
        outcome.is_err(),
        "the send future must be cancelled at the transport await, not resolve"
    );

    // The cancelled future was dropped -> the reservation's Drop ran -> the
    // tracker rolled back. A leaked sequence would leave `last_issued() == 1`.
    assert_eq!(
        tracker.last_issued(),
        0,
        "a send cancelled before commit must not leak a sequence number"
    );

    // The freed slot is reusable: the retry reserves 1 again (no gap).
    let retry = SequenceReservation::reserve(&mut tracker);
    assert_eq!(
        retry.number(),
        1,
        "the retry after cancellation reuses the freed slot (no monotonicity gap)"
    );
    retry.commit();
    assert_eq!(tracker.last_issued(), 1, "the retry commit is permanent");
}

// ---------------------------------------------------------------------------
// Case 2 — a send future cancelled AFTER commit keeps its sequence.
// ---------------------------------------------------------------------------

/// PRIMITIVE-LEVEL contract test and the primitive analog of the real
/// handler's ordering. `handle_send_message` `commit()`s the sequence
/// SYNCHRONOUSLY, THEN awaits the transport, and keeps the committed sequence
/// on the success path — so the property that matters is: a
/// [`SequenceReservation`] already `commit()`-ted and then cancelled at a
/// POST-commit await must NOT roll back ("committed state stays committed" —
/// `ContextActorHandle::send` cancellation docs; ADR §8). This models that
/// commit-before-await ordering with the guard type directly. Cancellation is
/// driven by a `tokio::select!` whose cancel branch wins, dropping the send
/// branch at its post-commit await.
///
/// Delta: distinct property from Case 1 (the far side of the commit boundary)
/// and a distinct cancellation driver (`select!` vs `timeout`). Like Case 1,
/// it is a type-contract witness — see the module "Honesty note" for why the
/// real send handler itself is not drivable as a cancellation test.
#[tokio::test]
async fn send_future_cancelled_after_commit_keeps_sequence() {
    let mut tracker = SendSequenceTracker::new();

    tokio::select! {
        // The send branch: reserve, COMMIT, then suspend on a post-commit
        // tail (e.g. best-effort bookkeeping). It never resolves, so the
        // cancel branch always wins and drops it here — after the commit.
        () = async {
            let reservation = SequenceReservation::reserve(&mut tracker);
            assert_eq!(reservation.number(), 1, "reservation is slot 1");
            reservation.commit();
            std::future::pending::<()>().await;
        } => unreachable!("the post-commit tail never resolves"),
        // The cancel branch: wins the race and cancels the send branch.
        () = tokio::time::sleep(CANCEL_AFTER) => {}
    }

    // The send branch was dropped AFTER commit; the committed sequence must
    // stand. A spurious rollback would leave `last_issued() == 0`.
    assert_eq!(
        tracker.last_issued(),
        1,
        "a committed sequence must survive cancellation of the post-commit tail"
    );
}

// ---------------------------------------------------------------------------
// Case 3 — a cancelled saga future releases its context-set reservation.
// ---------------------------------------------------------------------------

/// `Supervisor` fixture for the saga-reservation case. The reservation store
/// under test is in-memory (a `Mutex<HashSet<..>>`) and never touches
/// persistence or the journal, so the inert `NoOpContextPersistence` +
/// empty in-memory journal are sufficient — this mirrors `test_supervisor`
/// in `tests/actor_saga_coordinator.rs` (integration test files cannot share
/// a module, so the constructor is replicated).
fn test_supervisor() -> Supervisor {
    let persistence: Arc<dyn scp_runtime::context::persistence::ContextPersistence> =
        Arc::new(scp_runtime::context::persistence::NoOpContextPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    Supervisor::new(persistence, journal, SupervisorConfig::default())
}

/// ADR-049 §3a / spec §5.15.4: a saga reserves its participant-context SET
/// via `try_reserve_context_set`, and the `SagaSetReservation` RAII guard
/// releases that set on scope exit. Because `start_saga` drives the FSM
/// INLINE under the guard (`run_saga(..).await`), cancelling the saga future
/// mid-flight drops the guard and MUST release the slot — otherwise a
/// cancelled saga would wedge every overlapping saga with a leaked
/// `SagaBusy`. This drives that release through real tokio cancellation.
///
/// The test reserves via `test_reserve_saga_context_set`, which exercises the
/// SAME `try_reserve_context_set` critical section `start_saga` uses (not a
/// mock), holds the reservation across a `pending()` await inside a
/// `select!` branch, proves mid-flight that an OVERLAPPING reserve is
/// rejected (so the slot is genuinely held), then lets the cancel branch drop
/// the holder and asserts the overlapping reserve now SUCCEEDS.
///
/// Non-duplicate: existing tests cover overlap-while-held and release on a
/// normal terminal / sequential re-arm; none release the set because the
/// holding future was CANCELLED.
#[tokio::test]
async fn cancelled_saga_future_releases_context_set_reservation() {
    let supervisor = test_supervisor();
    // Identical inputs -> identical participant set -> they overlap.
    let input = SagaInput::test_cross_context_for_gating([0x11; 32], [0x22; 32]);

    tokio::select! {
        // The saga branch: hold the participant set, prove overlap is
        // rejected while held, then suspend forever so the cancel branch
        // drops us with the reservation still outstanding.
        () = async {
            let _held = supervisor
                .test_reserve_saga_context_set(&input)
                .expect("initial reservation of a free set succeeds");

            // While held, an overlapping saga must be rejected — proving the
            // slot is genuinely reserved, so the post-cancel release below is
            // a meaningful (non-vacuous) observation.
            assert!(
                matches!(
                    supervisor.test_reserve_saga_context_set(&input),
                    Err(ContextError::ActorBusy(_))
                ),
                "an overlapping set must be SagaBusy while the first is held in-flight"
            );

            // Suspend forever holding `_held` — the cancel branch drops this
            // whole future (and with it the reservation guard) mid-flight.
            std::future::pending::<()>().await;
        } => unreachable!("the in-flight saga branch never resolves"),
        () = tokio::time::sleep(CANCEL_AFTER) => {}
    }

    // The saga branch was dropped -> its `SagaSetReservation` Drop ran -> the
    // set is released. A leaked reservation would keep this SagaBusy.
    let reacquired = supervisor.test_reserve_saga_context_set(&input);
    assert!(
        reacquired.is_ok(),
        "a cancelled saga must release its participant-context-set reservation, \
         leaving the slot reservable; got {:?}",
        reacquired.err()
    );
}
