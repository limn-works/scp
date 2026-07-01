//! Per-domain handler modules. See plan §"Submodule organization".
//!
//! Each submodule implements the handlers for one sub-enum of
//! [`ContextCommand`](crate::context::actor::commands::ContextCommand).
//! The dispatch entry point is a free `dispatch` function taking the
//! actor-owned state cell and deps (`(&mut ClassSCell, &ActorDeps,
//! SubCommand)` — `standing` takes deps only, its state being
//! supervisor-scoped) and returning an
//! [`Outcome`](crate::context::actor::outcome::Outcome).
//!
//! # Dispatch shape
//!
//! Every submodule owns a real actor-shape `dispatch` that operates on
//! the actor-owned state and awaits MLS/HPKE/transport/persistence
//! operations, with two carve-outs: `queries` is read-only by
//! construction, and the custody-bearing broadcast publish variants
//! are rejected on the mailbox in favor of the supervisor's
//! custody-generic two-phase path (see `broadcast.rs`). The
//! migration-window stub bodies (which replied `NotImplemented`) have
//! been deleted; the only surviving `NotImplemented` producer is the
//! state-less
//! [`ContextActor::skeleton_dispatch`](crate::context::actor::ContextActor)
//! path exercised by the actor's smoke tests.
//!
//! # `unused_async` allow, scoped module-wide
//!
//! The dispatch signature is `async fn` by contract — most handler
//! bodies await MLS/HPKE/transport/persistence operations. A few
//! read-only variants complete synchronously; allowing
//! `clippy::unused_async` at the module level keeps the uniform
//! `async fn dispatch` signature across every submodule so the actor's
//! main loop calls them identically.
#![allow(
    clippy::unused_async,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph
)]

pub mod broadcast;
pub mod economy;
pub mod governance;
pub mod lifecycle;
pub mod lifecycle_control;
pub mod messaging;
pub mod queries;
pub mod saga;
pub mod standing;
pub mod tools;
pub mod trust_recovery;
pub mod ttl_close;
