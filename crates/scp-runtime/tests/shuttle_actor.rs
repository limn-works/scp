//! Shuttle-based deterministic-schedule exploration scaffold for the
//! ADR-049 actor loop and saga coordinator.
//!
//! # Scope (commit 11)
//!
//! Per plan row 11: "assertion scaffolding is sufficient" — commit 11
//! lands the structure of shuttle-based concurrency tests without the
//! shuttle crate as a runtime dependency. The tests only compile when
//! the `shuttle` feature is enabled; until that feature is added and
//! the shuttle dependency is wired in, this file compiles to an empty
//! binary. The scaffold records the invariants we intend to check:
//!
//! 1. Saga coordinator guard admits at most one in-flight saga at a
//!    time under all interleavings.
//! 2. Journal append ordering is strictly monotonic even under task
//!    preemption.
//! 3. Crash-recovery replay is idempotent under arbitrary task
//!    preemption of the replay dispatcher.
//!
//! When the `shuttle` feature lands (future commit), these scaffolds
//! become real `#[shuttle::test]` invocations.

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
    //! # Invariant 1 — guard admits at most one saga.
    //!
    //! ```ignore
    //! #[shuttle::test]
    //! fn saga_guard_admits_one() {
    //!     let sup = Arc::new(test_supervisor());
    //!     let mut handles = vec![];
    //!     for _ in 0..4 {
    //!         let s = Arc::clone(&sup);
    //!         handles.push(shuttle::thread::spawn(move || {
    //!             let _ = shuttle::future::block_on(s.start_saga(input()));
    //!         }));
    //!     }
    //!     for h in handles { h.join().unwrap(); }
    //!     // guard must be cleared after all sagas terminate.
    //!     assert!(!sup.saga_pending_guard.load(Ordering::SeqCst));
    //! }
    //! ```
    //!
    //! # Invariant 2 — journal append ordering is strictly monotonic.
    //!
    //! # Invariant 3 — crash-recovery replay is idempotent.
}

// Empty main so the test binary always links.
#[cfg(not(feature = "shuttle"))]
#[test]
fn shuttle_scaffold_not_enabled() {
    // Intentionally empty — the scaffold's purpose is to reserve the
    // file location for future shuttle-feature activation. The real
    // tests land when `shuttle` is added as a dev-dependency and the
    // feature flag is wired into Cargo.toml.
}
