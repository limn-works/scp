//! Per-context actor module — owns `&mut PerContextState` by move.
//!
//! Introduced by commit 5 of the actor-per-context refactor (ADR-049 §1).
//!
//! Commit 5 lands only the foundational types referenced by the actor's
//! command-dispatch contract:
//!
//! - [`outcome::Outcome`] — handler return type. Carries `mutated: bool`
//!   so the actor knows when to mark its state dirty for coalesced
//!   persistence.
//! - [`sequence::SequenceReservation`] — RAII guard around a reserved
//!   send-sequence number. Drop rolls back; explicit `commit()` makes
//!   the reservation durable.
//! - [`sequence::SendSequenceTracker`] — minimal monotonic counter the
//!   reservation guards. The full per-actor send-sequence wiring is
//!   delivered in a later commit; this commit lands the type so the RAII
//!   semantics can be unit-tested in isolation.
//!
//! Later commits (6+) flesh this module out with `ContextActor`,
//! `ContextActorHandle`, `ActorDeps`, and the `handlers/` submodule.

pub mod outcome;
pub mod sequence;

pub use outcome::Outcome;
pub use sequence::{SendSequenceTracker, SequenceReservation};

/// Re-export of [`scp_protocol::context::ContextError`] for handler-side
/// use. `Outcome<T>` carries `Result<T, ContextError>`; handlers in later
/// commits will use this re-export rather than a deep path.
pub use scp_protocol::context::ContextError;
