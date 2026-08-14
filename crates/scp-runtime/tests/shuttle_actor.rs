//! Shuttle-based deterministic-schedule exploration scaffold for the
//! ADR-049 actor loop and saga coordinator.
//!
//! # Scope (commit 11)
//!
//! Per plan row 11: "assertion scaffolding is sufficient" — commit 11
//! lands the structure of shuttle-based concurrency tests without the
//! shuttle crate as a runtime dependency. The saga-focused scaffolds only
//! compile when the `shuttle` feature is enabled; until that feature is
//! added and the shuttle dependency is wired in, they record the invariants
//! we intend to check:
//!
//! 1. Saga concurrency is gated per-participant-context-set: a saga
//!    reserves the SET of context-actors it spans, two sagas with
//!    DISJOINT sets run concurrently, an OVERLAPPING set is rejected with
//!    a typed `SagaBusy`, and every terminal (Committed / Aborted /
//!    NeedsRepair) RELEASES the reserved set — so the reservation store is
//!    empty once all sagas terminate, under all interleavings. (There is
//!    no instance-wide single-saga guard.)
//! 2. Journal append ordering is strictly monotonic even under task
//!    preemption.
//! 3. Crash-recovery replay is idempotent under arbitrary task
//!    preemption of the replay dispatcher.
//!
//! When the `shuttle` feature lands (future commit), these scaffolds
//! become real `#[shuttle::test]` invocations.
//!
//! # ADR-049 §13 concurrent-writer stress test (active today)
//!
//! The `context_handle_cas_stress` module below is NOT gated on the shuttle
//! feature: it is a real, always-compiled multi-thread stress test for the
//! Decision-12 `ContextHandle::transition_to` compare-and-swap loop, run
//! under ordinary `cargo nextest` / `cargo test`.

#![allow(
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    // `shuttle` is not a declared crate feature yet — the scaffold
    // intentionally gates its body behind the future feature so the
    // file stays a zero-cost placeholder until shuttle lands.
    unexpected_cfgs,
)]

// The body is entirely feature-gated; when `shuttle` is not enabled the
// file compiles to an empty `main`-less test binary.
#[cfg(feature = "shuttle")]
mod shuttle_tests {
    //! # Invariant 1 — every reservation is released on terminal.
    //!
    //! Saga concurrency is gated per-participant-context-set (ADR-049 §3a,
    //! spec §5.15.4): a saga reserves the SET of context-actors it spans, and
    //! each saga's terminal (Committed / Aborted / NeedsRepair) RELEASES its
    //! reserved set. There is no instance-wide guard. The shuttle invariant is
    //! therefore that the reservation store is EMPTY once all sagas terminate
    //! — running the same participant set repeatedly must re-arm, and disjoint
    //! sets must never serialize.
    //!
    //! ```ignore
    //! #[shuttle::test]
    //! fn reservations_release_on_terminal() {
    //!     let sup = Arc::new(test_supervisor());
    //!     let mut handles = vec![];
    //!     for _ in 0..4 {
    //!         let s = Arc::clone(&sup);
    //!         handles.push(shuttle::thread::spawn(move || {
    //!             // Disjoint sets run concurrently; overlapping sets serialize
    //!             // with a typed SagaBusy.
    //!             let _ = shuttle::future::block_on(s.start_saga(input()));
    //!         }));
    //!     }
    //!     for h in handles { h.join().unwrap(); }
    //!     // Invariant: once every saga has reached a terminal state, the
    //!     // per-set reservation store holds NO ids — each terminal drops its
    //!     // RAII `SagaSetReservation`, which removes exactly the set it took.
    //!     // (The shuttle test asserts emptiness through whatever observation
    //!     // surface the harness exposes — e.g. a follow-up `start_saga` over
    //!     // the same set must succeed, proving the slot was released.)
    //! }
    //! ```
    //!
    //! # Invariant 2 — journal append ordering is strictly monotonic.
    //!
    //! # Invariant 3 — crash-recovery replay is idempotent.
}

// ---------------------------------------------------------------------------
// ADR-049 §13 concurrent-writer stress test (Decision-12).
//
// Unlike the saga invariants above (which still await the `shuttle` feature),
// the `ContextHandle` lifecycle cell is a plain `Arc<ArcSwap<ContextState>>`
// with no async surface, so its concurrent-writer invariant can be exercised
// today with real OS threads under `cargo nextest` / `cargo test`. §13
// mandates a stress test for any commit that removes a serializing primitive:
// commit 12 removed the read-path `RwLock` that wrapped the former
// `ContextInner` and replaced the blind load-validate-store `transition_to`
// with a compare-and-swap retry loop.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "shuttle"))]
mod context_handle_cas_stress {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use scp_protocol::context::{ContextParams, ContextState};
    use scp_runtime::context::ContextHandle;

    /// States reachable from `Active` in exactly one FSM step. Crucially, none
    /// of them is reachable from any of the others (they are all terminal or
    /// one-way w.r.t. each other), so from a single `Active` cell AT MOST ONE
    /// concurrent `transition_to` may succeed — every other writer must observe
    /// the already-committed terminal state and be rejected.
    const TARGETS_FROM_ACTIVE: [ContextState; 4] = [
        ContextState::Closing,
        ContextState::Expired,
        ContextState::MigratingOut,
        ContextState::Poisoned,
    ];

    /// Every state the cell may legitimately hold during the race.
    fn is_reachable_state(s: &ContextState) -> bool {
        *s == ContextState::Active || TARGETS_FROM_ACTIVE.contains(s)
    }

    /// Hammers a single shared `ContextHandle` with several threads all racing
    /// to move it out of `Active`, plus a concurrent reader, across many
    /// iterations.
    ///
    /// Invariants (all must hold under ANY interleaving):
    /// (a) EXACTLY ONE writer wins per iteration. Under the old blind-store
    ///     `transition_to`, every thread validates against `Active`
    ///     independently and then stores, so two (or more) "succeed" and an
    ///     update is silently lost — this assertion fails. The CAS loop admits
    ///     exactly one committer; the losers re-load the fresh terminal state,
    ///     fail validation, and return `Err` without storing.
    /// (b) The committed state equals the winner's requested target — no
    ///     invalid edge (e.g. `Expired -> Closing`) ever lands.
    /// (c) No torn / invalid read: every value the reader observes is an
    ///     FSM-reachable state, never garbage.
    /// (d) A rejected transition leaves the cell unchanged (the loser threads
    ///     returning `Err` do not perturb the final state, which stays equal to
    ///     the single winner's target).
    #[test]
    fn transition_to_is_atomic_under_concurrent_writers() {
        const ITERATIONS: usize = 2_000;

        for iter in 0..ITERATIONS {
            // Fresh handle; drive Creating -> Active before the race.
            let handle = ContextHandle::new(format!("ctx-{iter}"), ContextParams::default());
            handle
                .transition_to(&ContextState::Active)
                .expect("Creating -> Active must succeed");

            // All writers rendezvous at the barrier so they race the SAME
            // `Active` cell — maximizing the load-before-store window that the
            // old blind-store implementation mishandled.
            let barrier = Arc::new(Barrier::new(TARGETS_FROM_ACTIVE.len()));
            let mut writers = Vec::with_capacity(TARGETS_FROM_ACTIVE.len());
            for target in TARGETS_FROM_ACTIVE {
                // Clone shares the same `Arc<ArcSwap<ContextState>>` cell.
                let handle = handle.clone();
                let barrier = Arc::clone(&barrier);
                writers.push(thread::spawn(move || {
                    barrier.wait();
                    // Success yields `Some(target)`; a rejected transition yields
                    // `None`. (b) a success must land exactly on the requested
                    // target.
                    handle.transition_to(&target).ok().map(|new_state| {
                        assert_eq!(
                            new_state, target,
                            "iteration {iter}: committed state must equal the requested target"
                        );
                        target
                    })
                }));
            }

            // Concurrent reader: (c) every observed state must be reachable.
            let reader_handle = handle.clone();
            let reader = thread::spawn(move || {
                for _ in 0..512 {
                    let observed = reader_handle.state();
                    assert!(
                        is_reachable_state(&observed),
                        "iteration {iter}: reader observed unreachable/torn state {observed:?}"
                    );
                }
            });

            let winners: Vec<ContextState> = writers
                .into_iter()
                .filter_map(|w| w.join().expect("writer thread panicked"))
                .collect();
            reader.join().expect("reader thread panicked");

            // (a) exactly one writer committed.
            assert_eq!(
                winners.len(),
                1,
                "iteration {iter}: exactly one transition may win the Active cell, got {}",
                winners.len()
            );

            // (d) the final cell state equals the sole winner's target — the
            // rejected losers left it untouched.
            let final_state = handle.state();
            assert_eq!(
                final_state, winners[0],
                "iteration {iter}: final state must equal the winning transition"
            );
        }
    }

    /// A rejected transition is a pure no-op: it returns `Err` and leaves the
    /// cell byte-for-byte unchanged (single-threaded direct check of the CAS
    /// loop's `Err` path).
    #[test]
    fn rejected_transition_leaves_state_unchanged() {
        let handle = ContextHandle::new("ctx-reject".to_owned(), ContextParams::default());
        handle
            .transition_to(&ContextState::Active)
            .expect("Creating -> Active");
        handle
            .transition_to(&ContextState::Expired)
            .expect("Active -> Expired");

        // Expired is terminal: any onward transition must be rejected...
        assert!(handle.transition_to(&ContextState::Closing).is_err());
        assert!(handle.transition_to(&ContextState::Active).is_err());
        // ...and the state must be exactly what it was before the attempts.
        assert_eq!(handle.state(), ContextState::Expired);
    }
}
