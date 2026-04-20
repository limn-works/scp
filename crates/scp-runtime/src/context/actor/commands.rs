//! Command types accepted by `ContextActor`. See plan §"ContextActor" and
//! ADR-049 §1.
//!
//! # Clippy allows, scoped per-file
//!
//! - `doc_markdown` / `too_long_first_doc_paragraph`: the module docs
//!   reference plan-section titles like `§"ContextActor"` and
//!   `§"Cross-context saga protocol"` that cannot be trivially rewritten
//!   to satisfy the lint without losing traceability to the plan.
//!   Inline backticks break the readable prose; wrapping every section
//!   reference is churn for no reader benefit.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! # Shape
//!
//! The outer [`ContextCommand`] enum is a discriminated union over 12
//! domain-grouped sub-enums, one per handler file in
//! [`crate::context::actor::handlers`]. Each sub-enum carries the
//! command-specific payload plus a `tokio::sync::oneshot::Sender` for the
//! reply — the actor processes a command to completion and sends the
//! typed result; the caller's oneshot receiver is the cancellation
//! vector (drop-the-receiver = discard the outcome without rolling back
//! committed state — see plan §"Cancel-safety check").
//!
//! # Minimal variant surface (this commit)
//!
//! Commit 6 lands the enum SHAPE. Each sub-enum carries one or two
//! placeholder variants whose handlers return
//! `ContextError::NotImplemented(..)` via
//! [`Outcome::err`](crate::context::actor::Outcome::err). Commits 7-11
//! extend each sub-enum with real variants as the corresponding handler
//! migrates off the legacy `ContextManager`; the dispatch loop shape is
//! stable from this commit forward.
//!
//! # Naming
//!
//! Sub-enum names follow the handler file name (`MessagingCommand` ↔
//! `handlers/messaging.rs`). This keeps the routing trivially
//! grep-findable: `ContextCommand::Messaging(MessagingCommand::Send { .. })`
//! ↔ `handlers::messaging::dispatch`.

use tokio::sync::oneshot;

use scp_protocol::context::ContextError;

// ---------------------------------------------------------------------------
// Outer enum
// ---------------------------------------------------------------------------

/// Every command the `ContextActor` accepts. Routed by the actor's
/// dispatch loop to the matching handler module.
///
/// Variants correspond one-to-one with handler files under
/// [`crate::context::actor::handlers`]. The dispatch loop in
/// [`crate::context::actor::ContextActor::dispatch`] matches on this enum.
pub enum ContextCommand {
    /// Messaging — send, deliver, decrypt (spec §9.8).
    Messaging(MessagingCommand),
    /// Lifecycle — create, join, leave, close (spec §5.3).
    Lifecycle(LifecycleCommand),
    /// Governance — the 28 actions enumerated in ADR-031.
    Governance(GovernanceCommand),
    /// Broadcast — per-author key rotation, subscriber admission,
    /// broadcast publish/subscribe.
    Broadcast(BroadcastCommand),
    /// Economy — velocity trackers, escalations, payments (spec §19).
    Economy(EconomyCommand),
    /// Trust recovery — epoch floor reconciliation, recovery proofs
    /// (spec §23.17).
    TrustRecovery(TrustRecoveryCommand),
    /// Standing — saga initiator for standing-pair creation
    /// (spec §5.15.7).
    Standing(StandingCommand),
    /// TTL close — timer-driven close path (spec §5.8).
    TtlClose(TtlCloseCommand),
    /// Tools — saga initiator for cross-context tool invocation
    /// (spec §5.16).
    Tools(ToolsCommand),
    /// Read-only queries. Handlers MUST NOT mutate state; the actor
    /// takes `&self.state` when dispatching this variant.
    Queries(QueriesCommand),
    /// Saga phase messages — supervisor-driven Prepare / Commit / Abort
    /// arriving at this actor as a saga participant.
    SagaPhase(SagaPhaseMessage),
    /// Supervisor-originated lifecycle control (Pause, Resume, Shutdown,
    /// PersistSync). See plan §"BridgeInstance actor integration" — the
    /// bridge's suspend/resume default trait methods send these.
    LifecycleControl(LifecycleControlCommand),
}

// ---------------------------------------------------------------------------
// Placeholder sub-enums
// ---------------------------------------------------------------------------

/// See [`ContextCommand::Messaging`]. Real variants arrive in commit 8.
pub enum MessagingCommand {
    /// Placeholder — fully defined when `handlers/messaging.rs` migrates
    /// in commit 8 (plan "commit ladder"). Drop the oneshot receiver to
    /// cancel; the actor still processes the command but discards the
    /// outcome.
    Placeholder {
        /// Oneshot reply channel. Handler stub sends
        /// `Err(ContextError::NotImplemented(..))` back.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Lifecycle`]. Real variants arrive in commit 9.
pub enum LifecycleCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Governance`]. Real variants arrive in commit 10.
pub enum GovernanceCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Broadcast`]. Real variants arrive in commit 11.
pub enum BroadcastCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Economy`]. Real variants arrive in commit 10.
pub enum EconomyCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::TrustRecovery`]. Real variants arrive in commit 10.
pub enum TrustRecoveryCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Standing`]. Real variants arrive in commit 11.
pub enum StandingCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::TtlClose`]. Real variants arrive in commit 9.
pub enum TtlCloseCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Tools`]. Real variants arrive in commit 11.
pub enum ToolsCommand {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::Queries`]. Real variants arrive in commit 7 (the
/// first handler migration — queries are the lowest-blast-radius path).
pub enum QueriesCommand {
    /// Placeholder. Queries are pure-read; commit 7 adds real variants
    /// that return `Outcome { mutated: false }`.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::SagaPhase`]. Saga phase routing lands with the
/// saga path in commit 11.
pub enum SagaPhaseMessage {
    /// Placeholder.
    Placeholder {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

/// See [`ContextCommand::LifecycleControl`]. The supervisor's suspend /
/// resume / shutdown path sends these; real variants land with the
/// BridgeInstance integration in commit 11. Commit 6 only carries the
/// two Pause / PersistSync variants that the
/// [`BridgeInstanceCore`](scp_ffi_common::bridge_instance::BridgeInstanceCore)
/// default `suspend()` body calls, plus the terminal `Shutdown`.
pub enum LifecycleControlCommand {
    /// Supervisor asks the actor to quiesce: refuse new external
    /// commands but continue processing the current dispatch and any
    /// in-flight persists. The actor replies once the current dispatch
    /// finishes.
    Pause {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Supervisor asks the actor to synchronously flush its coalesced
    /// persist buffer. The actor replies once the snapshot write has
    /// durably completed.
    PersistSync {
        /// Oneshot reply channel.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Terminal command — the actor's dispatch loop exits after
    /// processing. `biased;` ordering in the `select!` guarantees this
    /// variant is dispatched before any timer or persistence arm fires
    /// on the same poll.
    Shutdown {
        /// Oneshot reply channel. The actor sends `Ok(())` after its
        /// final persist completes.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Returns the oneshot reply sender for a command, consuming the command.
/// Used by the test-only `send_not_implemented` helper on
/// [`crate::context::actor::ContextActorHandle`] to close out a stub
/// dispatch. Not part of the public API — the field is pattern-matched
/// directly by the handler stubs once they migrate.
impl ContextCommand {
    /// Internal: whether this variant is the terminal
    /// [`LifecycleControlCommand::Shutdown`]. Used by the actor's
    /// dispatch loop to decide when to exit after dispatching.
    #[must_use]
    pub const fn is_shutdown(&self) -> bool {
        matches!(
            self,
            Self::LifecycleControl(LifecycleControlCommand::Shutdown { .. })
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_variant_is_shutdown() {
        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::LifecycleControl(LifecycleControlCommand::Shutdown { reply: tx });
        assert!(cmd.is_shutdown());
    }

    #[test]
    fn non_shutdown_variants_are_not_shutdown() {
        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { reply: tx });
        assert!(!cmd.is_shutdown());

        let (tx, _rx) = oneshot::channel();
        let cmd = ContextCommand::Messaging(MessagingCommand::Placeholder { reply: tx });
        assert!(!cmd.is_shutdown());
    }

    #[test]
    fn sub_enum_placeholders_carry_reply_channels() {
        // Compile-time witness: every placeholder variant carries a
        // oneshot reply channel with the expected type.
        let (tx, rx) = oneshot::channel::<Result<(), ContextError>>();
        let _ = ContextCommand::Messaging(MessagingCommand::Placeholder { reply: tx });
        drop(rx);
    }
}
