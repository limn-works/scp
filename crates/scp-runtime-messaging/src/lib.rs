//! The messaging domain of the SCP runtime (ADR-070 §2): sending, receiving and decrypting application and management messages.
//!
//! The crate exports [`Messaging`], the
//! [`MessagingDomain`](scp_runtime_core::context::domains::MessagingDomain) implementation
//! that the assembly crate `scp-runtime` installs in
//! [`DomainHandlers`](scp_runtime_core::context::domains::DomainHandlers). Every other item is
//! private to the crate, except the `testing`-gated `testing_access` module.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Test targets require the `testing` feature: the `#[cfg(test)]` modules call
// `#[cfg(feature = "testing")]`-gated helpers of `scp-runtime-core`, and the
// command variants core gates on `testing` need this crate's match arms. No
// dev-dependency edge turns it on, so every test command names the feature. This
// tripwire turns a missing `--features` into a clear message instead of a cryptic E0599.
#[cfg(all(test, not(feature = "testing")))]
compile_error!(
    "scp-runtime-messaging test targets require the `testing` feature: pass \
     `--features testing` (or `--features scp-runtime-messaging/testing` in a multi-package command)."
);

mod handler;
mod helpers;
#[cfg(test)]
mod test_support;

/// The items sibling domain crates' tests call directly (`testing` only).
///
/// A domain's tests stay beside its code (ADR-070 plan §6.1), and a few of them
/// drive another domain's functions to set up or observe state. A sibling reaches
/// a domain only as a dev-dependency, so these items are exported here and
/// nowhere else; no production build compiles this module.
#[cfg(feature = "testing")]
pub mod testing_access {
    pub use crate::helpers::{
        decrypt_and_dispatch, deliver_message_and_drain_buffered, finalize_send,
    };
}

// The agent-binding live-pipeline tests (the whole file is `#![cfg(test)]`).
#[cfg(test)]
mod agent_binding_pipeline_tests;

// Runtime pseudonym-rotation tests (spec 09 §9.10.4.1), also `#![cfg(test)]`.
#[cfg(test)]
mod pseudonym_rotation_runtime_tests;

// Receive-side and reset tests for a membership Commit (spec 07 §7.3.1.1,
// story PUSH-030), also `#![cfg(test)]`.
#[cfg(test)]
mod processed_commit_tests;

// A sender-key distribution whose publish fails (spec 09 §9.16.9), also
// `#![cfg(test)]`.
#[cfg(test)]
mod sender_key_requeue_tests;

/// The messaging domain's [`MessagingDomain`](scp_runtime_core::context::domains::MessagingDomain)
/// implementation, which the assembly's `domain_handlers()` installs.
pub struct Messaging;

#[async_trait::async_trait]
impl scp_runtime_core::context::domains::MessagingDomain for Messaging {
    async fn dispatch(
        &self,
        cell: &mut scp_runtime_core::context::actor::class_s::ClassSCell,
        deps: &scp_runtime_core::context::actor::deps::ActorDeps,
        cmd: scp_runtime_core::context::actor::commands::MessagingCommand,
    ) -> scp_runtime_core::context::actor::outcome::Outcome<()> {
        handler::dispatch(cell, deps, cmd).await
    }
}
