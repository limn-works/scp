//! Per-domain handler modules. See plan §"Submodule organization".
//!
//! Each submodule implements the handlers for one sub-enum of
//! [`ContextCommand`](crate::context::actor::commands::ContextCommand).
//! The dispatch entry point is a free `dispatch` function taking
//! `(&mut PerContextState, &ActorDeps, SubCommand)` and returning an
//! [`Outcome`](crate::context::actor::outcome::Outcome).
//!
//! # Commit 6 scope
//!
//! Every submodule carries a `dispatch` stub that returns
//! `Outcome::err(ContextError::NotImplemented(..))`. Real handler
//! bodies migrate off `ContextManager` in commits 7-11; commit 6 lands
//! only the dispatch shape so the actor's main loop compiles.
//!
//! # `unused_async` allow, scoped module-wide
//!
//! The dispatch signature is `async fn` by contract — handler bodies
//! await MLS/HPKE/transport/persistence operations. The commit-6 stubs
//! do not `await` because every variant returns `NotImplemented`
//! synchronously. Allowing `clippy::unused_async` at the module level
//! preserves the real signature so migrating handlers in later commits
//! does not force a signature change at every call site.
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
