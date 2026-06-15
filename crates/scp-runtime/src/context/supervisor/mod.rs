//! Supervisor module — cross-actor coordination surfaces.
//!
//! Introduced by commit 4 of the actor-per-context refactor (ADR-049 §3).
//!
//! This module houses the durable saga coordinator and — in later commits —
//! the supervisor struct, identity-capability token, and actor registry.
//!
//! # Submodule visibility
//!
//! - [`saga_journal`] — `pub`. The trait + production impl are part of the
//!   crate's public API surface (consumed by the FFI bridges and tests).
//! - [`saga_prepared_state`] — `pub`. Variants are constructed by handler
//!   code in `actor/handlers/` once Prepare runs, and consumed by the same
//!   handlers at Commit time.
//! - [`identity_capability`] — `pub(in crate::context)`. The module path
//!   is nameable within `crate::context` so that
//!   [`crate::context::actor::deps::ActorDeps`] can hold an
//!   `OwnedIdentityDid` by-value and per-identity `SupervisorHandle`
//!   methods can take `&OwnedIdentityDid`. This does NOT weaken the mint
//!   guarantee: the token's **constructor `issue_for_actor` stays
//!   `pub(super)`** (only supervisor-module code can mint from a raw
//!   `DID`) and the struct's single field stays PRIVATE (no struct-literal
//!   construction outside the module). Module-path reachability lets
//!   `crate::context` code *name* the type; it grants no path to
//!   *construct* one. The module is NOT `pub`/`pub(crate)`. See ADR-049
//!   §"`OwnedIdentityDid` via module visibility" and the CI gate
//!   `scripts/check-owned-identity-did.py`.
//!
//! # `#![deny(unsafe_code)]`
//!
//! The crate-level lint at `lib.rs` is `forbid(unsafe_code)`, which already
//! covers this module. The module-level `deny` here is documentation: it
//! states the intent that no submodule of `supervisor/` may use `unsafe`
//! to fabricate an `OwnedIdentityDid` via `transmute` or escape its
//! `pub(super)` visibility via an unsafe `Send`/`Sync` impl. The crate-
//! level `forbid` makes the deny redundant in practice — but keeping the
//! deny here keeps the constraint legible at the module that the
//! constraint protects.

#![deny(unsafe_code)]

/// Public, A-authored standing-pair creation metadata (spec §5.15.8) plus
/// its reverse-order best-effort rollback. `pub(in crate::context)` —
/// reachable by the saga prepared-state wire type and the (later) abort
/// handler, never by external crates or FFI bridges.
pub(in crate::context) mod creation_receipt;
pub mod handle;
pub(in crate::context) mod identity_capability;
pub mod key_package_actor;
pub mod saga_journal;
pub mod saga_prepared_state;
#[allow(clippy::module_inception)]
pub mod supervisor;

pub use handle::SupervisorHandle;
pub use key_package_actor::{
    KP_MAILBOX_CAPACITY, KP_SEND_TIMEOUT, KeyPackageCommand, KeyPackageStoreActor,
    KeyPackageStoreHandle, KpRef, PooledKeyPackages, ReservationId,
};
pub use saga_journal::{
    JournalEntry, JournalError, ProtocolRepositorySagaJournal, SAGA_JOURNAL_KEY_PREFIX, SagaId,
    SagaJournal, SagaState, SagaTerminalState,
};
pub use saga_prepared_state::{
    BroadcastHostingHandshakePrepared, CrossContextToolInvocationPrepared, SagaPreparedState,
    StandingPairCreatePrepared,
};
/// The per-saga participant-context-set reservation RAII guard. Exposed only
/// under `test`/`testing` so integration tests can deterministically hold a
/// saga's slots in flight (see `Supervisor::test_reserve_saga_context_set`).
#[cfg(any(test, feature = "testing"))]
pub use supervisor::SagaSetReservation;
pub use supervisor::{
    ACTOR_MAILBOX_CAPACITY, CrashWindow, PendingSagaProjection, SagaInput, SagaOutput, Supervisor,
    SupervisorConfig,
};
