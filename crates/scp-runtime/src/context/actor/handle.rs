//! Caller-side actor handle. See plan §"Mailbox parameters".
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles (`§"Mailbox parameters"`, etc.); wrapping each
//! reference in backticks is churn for no reader benefit.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! `ContextActorHandle` wraps a `tokio::sync::mpsc::Sender<ContextCommand>`
//! and enforces the two caller-side protocol contracts:
//!
//! 1. **Per-send timeout.** Every `send_*` method wraps the mailbox send in
//!    `tokio::time::timeout(Duration::from_secs(30), ...)`. If the mailbox
//!    is full for 30 s the caller receives
//!    [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy).
//!    This closes the "hung caller pile-up" failure mode documented in
//!    plan §"Mailbox parameters".
//! 2. **Cheap clone.** `mpsc::Sender` is already `Clone` — the handle
//!    follows its semantics. Each caller can clone the handle without
//!    coordinating with the actor; the shared refcount is `Sender`'s
//!    internal atomic counter.
//!
//! Cancellation semantics (plan §"Cancel-safety check"): dropping the
//! handle does NOT cancel in-flight commands. A command already in the
//! mailbox is processed to completion; the caller's oneshot receiver is
//! the only cancellation vector (drop the receiver → outcome is discarded
//! on `actor.dispatch`'s `reply.send` branch).

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use scp_protocol::context::ContextError;

use crate::context::actor::commands::{ContextCommand, LifecycleControlCommand};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Per-send mailbox timeout. Plan §"Mailbox parameters" fixes this at 30 s
/// — matching the actor-internal transport-timeout and the saga-phase
/// default so the end-to-end caller deadline is predictable. If this
/// value changes, audit the three sibling timers together.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// ContextActorHandle
// ---------------------------------------------------------------------------

/// Caller-side handle for a `ContextActor`. Cheap to clone; the actor
/// observes the sender refcount reaching zero as "all callers dropped"
/// and, together with `LifecycleControlCommand::Shutdown`, decides when
/// to exit `run()`.
///
/// The handle holds only the mpsc sender — no back-reference to the
/// actor task, no shared state, no locks. This keeps the hot path
/// (supervisor DashMap::get → clone handle → send) lock-free in the
/// common case.
#[derive(Clone)]
pub struct ContextActorHandle {
    /// Command inbox sender. `Sender::send` applies the bounded mailbox
    /// backpressure; `tokio::time::timeout` bounds the wait.
    inbox: mpsc::Sender<ContextCommand>,
}

impl ContextActorHandle {
    /// Wraps a raw mpsc sender. Visible only within the actor-supervisor
    /// module pair — the sender half is paired with an actor's `inbox:
    /// Receiver` by the `Supervisor::spawn_actor` constructor. External
    /// code obtains a handle via `Supervisor::lookup(context_id)`, not
    /// by constructing one directly.
    ///
    /// `dead_code` allow: the only production caller is
    /// `Supervisor::spawn_actor`, which is itself only exercised in
    /// `#[cfg(test)]` until the lifecycle handler migrates in commit 9.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context) const fn from_sender(inbox: mpsc::Sender<ContextCommand>) -> Self {
        Self { inbox }
    }

    /// Submits a command to the actor's mailbox, waits for the actor's
    /// oneshot reply, and returns the typed result.
    ///
    /// The `cmd_factory` closure constructs the command from the
    /// `oneshot::Sender<Result<T, ContextError>>` the handle creates for
    /// the reply. This keeps the oneshot lifetimes tied to this method
    /// call — callers cannot accidentally reuse a oneshot across
    /// commands.
    ///
    /// # Timeouts
    ///
    /// - **Send timeout.** Mailbox-send is bounded by [`SEND_TIMEOUT`]
    ///   (30 s). On timeout, returns
    ///   [`ContextError::ActorBusy`].
    /// - **Reply wait.** After the command enters the mailbox the reply
    ///   future is awaited unbounded — the actor's per-handler transport
    ///   and storage timeouts (30 s each per plan §"Transport timeouts
    ///   inside actor handlers") bound the end-to-end wait; a handler
    ///   that has entered the dispatch loop is expected to make progress.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] — the mailbox was full for the full
    ///   [`SEND_TIMEOUT`]; the command was never delivered.
    /// - Actor-channel-closed errors surface as
    ///   [`ContextError::ActorBusy`] with a descriptive message — the
    ///   actor has terminated and the handle is stale; callers typically
    ///   respond by fetching a fresh handle from the supervisor.
    /// - The handler's typed `ContextError` — whatever the handler
    ///   returned on the oneshot reply channel.
    ///
    /// # Cancellation
    ///
    /// Dropping the future returned by this method mid-flight is safe:
    /// the actor continues processing the command and attempts to
    /// `reply.send(..)`. Since the receiver is dropped, that send is a
    /// no-op — the committed state stays committed. See plan
    /// §"Cancel-safety check".
    pub async fn send<T, F>(&self, cmd_factory: F) -> Result<T, ContextError>
    where
        F: FnOnce(oneshot::Sender<Result<T, ContextError>>) -> ContextCommand,
    {
        let (tx, rx) = oneshot::channel::<Result<T, ContextError>>();
        let cmd = cmd_factory(tx);

        // Bounded-wait mailbox send. Plan §"Mailbox parameters".
        match tokio::time::timeout(SEND_TIMEOUT, self.inbox.send(cmd)).await {
            Ok(Ok(())) => rx.await.unwrap_or_else(|_| {
                Err(ContextError::ActorBusy(
                    "actor dropped reply channel before replying".to_owned(),
                ))
            }),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "actor inbox is closed — actor has terminated".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                "mailbox full for {} seconds",
                SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Submits a pre-built command to the actor's mailbox with a
    /// caller-supplied send-side timeout. **Does NOT wait for the
    /// reply.** Reply consumption is the caller's responsibility — the
    /// caller embedded a `oneshot::Sender` inside `cmd` and holds the
    /// matching `Receiver`.
    ///
    /// This is the spec-shape entry point per ADR-049 §"Mailbox
    /// parameters" / master plan §"Mailbox parameters". Used by the
    /// `Supervisor::dispatch_*_command` mailbox-routing path that
    /// constructs each command's reply-bearing oneshot, sends through
    /// the mailbox, then awaits the receiver itself.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] — mailbox full for the full
    ///   `timeout` window; the command was never delivered. The text
    ///   describes which condition (full vs. closed) the caller hit so
    ///   higher-level logging / metrics can disambiguate.
    /// - [`ContextError::ActorBusy`] (text contains "closed") — the
    ///   inbox receiver was already dropped (actor has terminated).
    ///   Callers typically respond by fetching a fresh handle.
    ///
    /// # Cancellation
    ///
    /// Dropping the future mid-flight aborts the in-flight mailbox
    /// send. If the send had not yet reached the actor, the command is
    /// discarded. Once enqueued, the actor processes the command to
    /// completion regardless of caller cancellation — the embedded
    /// reply oneshot's receiver-drop is the only cancellation vector
    /// for the actor-side outcome (plan §"Cancel-safety check").
    pub async fn send_with_timeout(
        &self,
        cmd: ContextCommand,
        timeout: std::time::Duration,
    ) -> Result<(), ContextError> {
        match tokio::time::timeout(timeout, self.inbox.send(cmd)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "actor inbox is closed — actor has terminated".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                "mailbox full for {} seconds",
                timeout.as_secs()
            ))),
        }
    }

    /// Submits `LifecycleControlCommand::Pause` to the actor and awaits
    /// the ack. See [`Self::send`] for error semantics.
    ///
    /// Called by the `BridgeInstanceCore::suspend` default body in
    /// `scp_ffi_common::bridge_instance::BridgeInstanceCore` — commit 6
    /// lands the send-path stub; the handler that processes the variant
    /// lands with the lifecycle-control migration in commit 11.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub async fn send_pause(&self) -> Result<(), ContextError> {
        self.send(|reply| {
            ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { reply })
        })
        .await
    }

    /// Submits `LifecycleControlCommand::PersistSync` to the actor and
    /// awaits the ack. See [`Self::send`] for error semantics.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub async fn send_persist_sync(&self) -> Result<(), ContextError> {
        self.send(|reply| {
            ContextCommand::LifecycleControl(LifecycleControlCommand::PersistSync { reply })
        })
        .await
    }

    /// Submits `LifecycleControlCommand::Shutdown` to the actor and
    /// awaits the ack. The actor exits its dispatch loop after
    /// processing this command. See [`Self::send`] for error semantics.
    ///
    /// # Errors
    ///
    /// Same as [`Self::send`].
    pub async fn send_shutdown(&self) -> Result<(), ContextError> {
        self.send(|reply| {
            ContextCommand::LifecycleControl(LifecycleControlCommand::Shutdown { reply })
        })
        .await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::actor::commands::MessagingCommand;

    #[test]
    fn send_timeout_is_30_seconds() {
        assert_eq!(SEND_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn send_to_closed_actor_returns_actor_busy() {
        // Build a mailbox, drop the receiver to simulate an actor that
        // has terminated, then try to send. The handle should map the
        // closed-channel error to `ActorBusy`.
        let (tx, rx) = mpsc::channel::<ContextCommand>(1);
        drop(rx);
        let handle = ContextActorHandle::from_sender(tx);
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .expect_err("closed mailbox must error");
        match err {
            ContextError::ActorBusy(msg) => assert!(
                msg.contains("closed"),
                "expected 'closed' in ActorBusy message, got {msg:?}"
            ),
            other => panic!("expected ActorBusy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_and_receive_roundtrip() {
        // Run a tiny pseudo-actor: receive one command, reply Ok.
        let (tx, mut rx) = mpsc::channel::<ContextCommand>(1);
        let handle = ContextActorHandle::from_sender(tx);

        let actor_task = tokio::spawn(async move {
            let cmd = rx.recv().await.expect("actor received a command");
            if let ContextCommand::Messaging(MessagingCommand::Placeholder { reply }) = cmd {
                let _ = reply.send(Ok(()));
            } else {
                panic!("unexpected command variant");
            }
        });

        let result: Result<(), ContextError> = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await;
        assert!(result.is_ok(), "roundtrip must succeed, got {result:?}");
        actor_task.await.unwrap();
    }

    #[tokio::test]
    async fn handle_is_cheap_to_clone() {
        let (tx, _rx) = mpsc::channel::<ContextCommand>(1);
        let h1 = ContextActorHandle::from_sender(tx);
        let h2 = h1.clone();
        let h3 = h2.clone();
        drop(h1);
        drop(h2);
        drop(h3);
    }

    #[tokio::test]
    async fn send_pause_sends_lifecycle_control_pause() {
        let (tx, mut rx) = mpsc::channel::<ContextCommand>(1);
        let handle = ContextActorHandle::from_sender(tx);

        let actor_task = tokio::spawn(async move {
            let cmd = rx.recv().await.expect("actor received a command");
            assert!(matches!(
                cmd,
                ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { .. })
            ));
            if let ContextCommand::LifecycleControl(LifecycleControlCommand::Pause { reply }) = cmd
            {
                let _ = reply.send(Ok(()));
            }
        });

        handle.send_pause().await.unwrap();
        actor_task.await.unwrap();
    }
}
