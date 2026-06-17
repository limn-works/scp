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
//!   *construct* one. The module is NOT `pub`/`pub(crate)`. The sole-minter
//!   guarantee is enforced by the compiler (the type system plus the two
//!   module lints below) and code review — there is NO bespoke CI scanner.
//!   See ADR-049 §5.
//!
//! # `#![deny(unsafe_code)]` and `#![deny(non_local_definitions)]`
//!
//! These two module lints, together with the type system, are what make the
//! `OwnedIdentityDid` token unforgeable — no source-text CI gate is used.
//!
//! - **`#![deny(unsafe_code)]`.** The crate-level lint at `lib.rs` is
//!   `forbid(unsafe_code)`, which already covers this module. The module-
//!   level `deny` here is legibility: it states the intent that no submodule
//!   of `supervisor/` may use `unsafe` to fabricate an `OwnedIdentityDid`
//!   via `transmute` or escape its `pub(super)` visibility via an unsafe
//!   `Send`/`Sync` impl. The crate-level `forbid` makes the deny redundant
//!   in practice — but keeping it here keeps the constraint legible at the
//!   module the constraint protects.
//! - **`#![deny(non_local_definitions)]`.** This closes the one forgery
//!   vector the visibility rules alone do not: a nested
//!   `impl OwnedIdentityDid { .. }` written inside a method body. Rust never
//!   scopes a nested impl to its enclosing fn — it applies globally — so
//!   such an impl would be a SECOND minter authored from inside the module.
//!   Denying the lint makes any nested impl a hard COMPILE error, enforcing
//!   the sole-minter invariant at the compiler rather than via a scanner.
//!
//! ## Compile-fail witness for the `non_local_definitions` guarantee
//!
//! The example below witnesses the ADR-049 §5 compiler-enforcement
//! guarantee: under `#![deny(non_local_definitions)]`, a second minter
//! smuggled into a function body as a nested `impl` (the exact vector the
//! type system's private-field + `pub(super)`-constructor rules do *not*
//! cover) is a hard compile error, not a warning. The stand-in `Cap` mirrors
//! `OwnedIdentityDid`: a private field with no public constructor. The
//! body-nested `impl Cap { .. }` is otherwise valid Rust — Rust applies it
//! globally rather than scoping it to `forge` — so the *only* reason this
//! fails to compile is the denied lint. If a future toolchain narrowed the
//! lint, this `compile_fail` doctest would start compiling and the test
//! would fail, surfacing the silent regression.
//!
//! ```compile_fail
//! #![deny(non_local_definitions)]
//!
//! mod capability {
//!     pub struct Cap {
//!         did: String,
//!     }
//!
//!     impl Cap {
//!         // The sole sanctioned minter (mirrors `issue_for_actor`).
//!         pub fn issue(did: String) -> Self {
//!             Self { did }
//!         }
//!     }
//! }
//!
//! fn forge(raw: String) -> capability::Cap {
//!     // A SECOND minter smuggled into a function body. Rust applies this
//!     // `impl` globally (never scoping it to `forge`), so it would forge a
//!     // `Cap` for an arbitrary DID from outside `capability` — but
//!     // `#![deny(non_local_definitions)]` turns it into a compile error.
//!     impl capability::Cap {
//!         fn smuggled(did: String) -> Self {
//!             // Routes through the sanctioned constructor: the point is
//!             // purely that this nested `impl` is rejected by the lint,
//!             // not by any name-resolution or visibility error.
//!             capability::Cap::issue(did)
//!         }
//!     }
//!     capability::Cap::smuggled(raw)
//! }
//!
//! fn main() {
//!     let _ = forge(String::from("did:example:attacker"));
//! }
//! ```

#![deny(unsafe_code)]
// `OwnedIdentityDid` (ADR-049 §5) is an unforgeable capability token: its
// constructor `issue_for_actor` is `pub(super)` and its `did` field is
// private, so the only way to mint a token for an arbitrary DID is from
// supervisor-module code. A nested `impl OwnedIdentityDid { .. }` written
// inside a method body would be a SECOND minter — Rust applies nested impls
// globally, never scoping them to the enclosing fn (the `non_local_definitions`
// lint) — defeating the sole-minter guarantee from inside the module. Denying
// the lint turns any such nested impl into a hard COMPILE error, closing that
// vector at the compiler instead of via a source-text scanner.
#![deny(non_local_definitions)]

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
