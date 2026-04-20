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
//! - [`identity_capability`] — **PRIVATE** (`mod`, not `pub mod`). The
//!   capability token's constructor must be unreachable from outside this
//!   module. See ADR-049 §"`OwnedIdentityDid` via module visibility" and
//!   the CI gate `scripts/check-owned-identity-did.py`.
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

mod identity_capability;
pub mod saga_journal;
pub mod saga_prepared_state;

pub use saga_journal::{
    JournalEntry, JournalError, ProtocolRepositorySagaJournal, SAGA_JOURNAL_KEY_PREFIX, SagaId,
    SagaJournal, SagaState, SagaTerminalState,
};
pub use saga_prepared_state::{
    BroadcastHostingHandshakePrepared, ContextMigrationPrepared,
    CrossContextToolInvocationPrepared, SagaPreparedState, StandingPairCreatePrepared,
};
