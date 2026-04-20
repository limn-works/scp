//! `KeyPackageStoreActor` — one actor per local identity, owns the
//! KeyPackage pool per spec §9.16.1 and plan §"KeyPackageStoreActor".
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Lifecycle contract:
//!
//! - Maintain a pool of 10 usable KeyPackages for this identity.
//! - Replenish when `pool.len() + reserved.len() < 5`.
//! - Two-phase reservation against Welcome processing (plan §"Welcome
//!   scratchpad"): `Reserve` moves a KP from `pool` to `reserved` and
//!   returns the private key; `ConfirmConsume` deletes the reservation
//!   permanently; `CancelReservation` discards the reservation (KP
//!   single-use semantics preclude returning to the pool).
//!
//! # Commit 6 scope
//!
//! This file lands the actor's TYPES — `KeyPackageCommand`,
//! `KeyPackageStoreActor`, `KeyPackageStoreHandle` — plus a trivial
//! `run()` loop that dispatches commands to
//! [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! stubs. The real KeyPackage pool (`HashMap<KpRef, KeyPackagePrivate>`,
//! replenish logic, publish-to-relay fan-out, persistence) lands with the
//! lifecycle handler migration in commit 9.

use std::time::Duration;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Mailbox capacity for a `KeyPackageStoreActor`. Deliberately smaller
/// than the per-context actor capacity (256) — KP operations are rare
/// per identity (a Reserve per Welcome, a Replenish every 5 consumed),
/// so 32 is plenty and keeps memory bounded when many identities are
/// registered.
pub const KP_MAILBOX_CAPACITY: usize = 32;

/// Per-caller mailbox-send timeout. Matches
/// [`crate::context::actor::handle::SEND_TIMEOUT`] for consistency.
pub const KP_SEND_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Command enum
// ---------------------------------------------------------------------------

/// Opaque reservation identifier. Supervisor-scoped; opaque to callers.
/// String-typed to keep the serialized actor snapshot straightforward;
/// semantically this is a UUID.
pub type ReservationId = String;

/// Opaque `KpRef` — the KeyPackage's stable identifier. String-typed
/// for commit 6; the real type (signature-derived hash + relay URL
/// tuple) lands when the lifecycle handler migrates in commit 9.
pub type KpRef = String;

/// Placeholder for a serialized private KeyPackage. Commit 9 replaces
/// with the real `KeyPackagePrivate` type from the MLS backend.
pub type KeyPackagePrivateStub = Vec<u8>;

/// Placeholder for a relay URL. Commit 9 replaces with the typed
/// `scp_transport::RelayUrl` (or equivalent) once the publish path
/// migrates.
pub type RelayUrl = String;

/// Commands the `KeyPackageStoreActor` accepts. Each variant carries a
/// `oneshot::Sender` for the reply; cancellation is via receiver drop.
pub enum KeyPackageCommand {
    /// Reserve one KP from the pool. Moves the entry into the `reserved`
    /// map and returns the private key plus a fresh `ReservationId`.
    /// The caller is the Welcome-processing `ContextActor`; on success
    /// the caller sends `ConfirmConsume`, on failure
    /// `CancelReservation`.
    Reserve {
        /// The `KpRef` identifying which KP to reserve.
        kp_ref: KpRef,
        /// Oneshot reply: `(ReservationId, private key bytes)` on success.
        reply: oneshot::Sender<Result<(ReservationId, KeyPackagePrivateStub), ContextError>>,
    },
    /// Permanently consume a reservation. The KP is deleted from the
    /// actor's tracked set — OpenMLS KPs are single-use by spec.
    ConfirmConsume {
        /// The reservation ID returned by [`Self::Reserve`].
        reservation_id: ReservationId,
        /// Oneshot reply.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Cancel a reservation. OpenMLS KPs are single-use by spec, so the
    /// KP is discarded, not returned to the pool; this triggers a
    /// `Replenish` on the next command-loop iteration if the pool size
    /// drops below the low-water mark.
    CancelReservation {
        /// The reservation ID returned by [`Self::Reserve`].
        reservation_id: ReservationId,
        /// Oneshot reply.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Explicitly replenish the pool up to the high-water mark (10 per
    /// spec §9.16.1). Returns the count of KPs newly generated.
    Replenish {
        /// Oneshot reply: count of KPs added to the pool.
        reply: oneshot::Sender<Result<usize, ContextError>>,
    },
    /// Publish the pool's public KPs to the given relay set. Idempotent.
    Publish {
        /// Relays to publish to.
        relay_set: Vec<RelayUrl>,
        /// Oneshot reply.
        reply: oneshot::Sender<Result<(), ContextError>>,
    },
    /// Terminal command — the actor's `run()` loop exits after this is
    /// observed. No reply channel: callers dropping the handle is the
    /// observable effect.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Caller-side handle for a `KeyPackageStoreActor`. Cheap to clone
/// (wraps `mpsc::Sender<KeyPackageCommand>`).
#[derive(Clone)]
pub struct KeyPackageStoreHandle {
    inbox: mpsc::Sender<KeyPackageCommand>,
}

impl KeyPackageStoreHandle {
    /// Wraps a raw sender. `pub(in crate::context)` matches
    /// `ContextActorHandle::from_sender` — only the supervisor
    /// constructs handles.
    #[must_use]
    pub(in crate::context) const fn from_sender(inbox: mpsc::Sender<KeyPackageCommand>) -> Self {
        Self { inbox }
    }

    /// Submit a command and await its reply. See
    /// [`ContextActorHandle::send`](crate::context::actor::handle::ContextActorHandle::send)
    /// for full semantics — this method follows the same shape.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] — mailbox full for
    ///   [`KP_SEND_TIMEOUT`], or inbox closed, or the actor dropped the
    ///   reply channel.
    /// - The handler's typed error.
    pub async fn send<T, F>(&self, cmd_factory: F) -> Result<T, ContextError>
    where
        F: FnOnce(oneshot::Sender<Result<T, ContextError>>) -> KeyPackageCommand,
    {
        let (tx, rx) = oneshot::channel::<Result<T, ContextError>>();
        let cmd = cmd_factory(tx);

        match tokio::time::timeout(KP_SEND_TIMEOUT, self.inbox.send(cmd)).await {
            Ok(Ok(())) => rx.await.unwrap_or_else(|_| {
                Err(ContextError::ActorBusy(
                    "key-package actor dropped reply channel".to_owned(),
                ))
            }),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "key-package actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(format!(
                "key-package actor mailbox full for {} seconds",
                KP_SEND_TIMEOUT.as_secs()
            ))),
        }
    }

    /// Fire-and-forget shutdown. Drops the supervisor's reference to the
    /// handle; the actor observes the refcount reaching zero (when all
    /// clones drop) or the terminal `Shutdown` command.
    ///
    /// # Errors
    ///
    /// Returns `ContextError::ActorBusy` if the mailbox is full for
    /// `KP_SEND_TIMEOUT` or the inbox is closed.
    pub async fn send_shutdown(&self) -> Result<(), ContextError> {
        match tokio::time::timeout(
            KP_SEND_TIMEOUT,
            self.inbox.send(KeyPackageCommand::Shutdown),
        )
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_closed)) => Err(ContextError::ActorBusy(
                "key-package actor inbox is closed".to_owned(),
            )),
            Err(_elapsed) => Err(ContextError::ActorBusy(
                "key-package actor mailbox full on shutdown".to_owned(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// One per local identity. Owns the KeyPackage pool and the reservation
/// map. Commit 6 lands the skeleton; the real pool management migrates
/// in commit 9.
pub struct KeyPackageStoreActor {
    /// The identity this actor owns the pool for.
    #[allow(dead_code)] // wired into handlers in commit 9
    identity: DID,
    /// Inbox receiver paired with `KeyPackageStoreHandle::inbox`.
    inbox: mpsc::Receiver<KeyPackageCommand>,
}

impl KeyPackageStoreActor {
    /// Spawns a new actor task and returns its handle.
    ///
    /// The returned handle is the only way to reach the actor — the
    /// `mpsc::Receiver<KeyPackageCommand>` is moved into the actor task
    /// and never escapes. Dropping every clone of the returned handle
    /// causes the actor's `run()` loop to observe `None` on its inbox
    /// and exit cleanly after processing any remaining buffered
    /// commands.
    ///
    /// # Panics
    ///
    /// Never. The actor task captures errors in its dispatch stubs and
    /// surfaces them through the oneshot replies; it does not panic on
    /// stubbed commands.
    #[must_use]
    pub fn spawn(identity: DID) -> KeyPackageStoreHandle {
        let (tx, rx) = mpsc::channel::<KeyPackageCommand>(KP_MAILBOX_CAPACITY);
        let actor = Self {
            identity,
            inbox: rx,
        };
        tokio::spawn(actor.run());
        KeyPackageStoreHandle::from_sender(tx)
    }

    /// Dispatch loop. Runs until the inbox closes or a `Shutdown`
    /// command arrives.
    async fn run(mut self) {
        while let Some(cmd) = self.inbox.recv().await {
            if matches!(cmd, KeyPackageCommand::Shutdown) {
                break;
            }
            Self::dispatch(cmd);
        }
    }

    /// Dispatch one command. Stubbed for commit 6 — every non-Shutdown
    /// variant replies with
    /// [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented).
    /// Commits 9 onward replace these stubs with real handlers.
    fn dispatch(cmd: KeyPackageCommand) {
        let err = || {
            ContextError::NotImplemented(
                "KeyPackageStoreActor command handler — migrates in commit 9 of ADR-049".to_owned(),
            )
        };

        // Route every non-Shutdown variant to its oneshot reply with
        // `NotImplemented`. The variants have distinct reply types
        // (`()` vs `(ReservationId, Vec<u8>)` vs `usize`), so the
        // match arms are type-distinct even though each ack path does
        // the same shape.
        match cmd {
            KeyPackageCommand::Reserve { reply, .. } => {
                // `_` on receiver drop — caller cancelled; discard.
                let _ = reply.send(Err(err()));
            }
            KeyPackageCommand::ConfirmConsume { reply, .. }
            | KeyPackageCommand::CancelReservation { reply, .. }
            | KeyPackageCommand::Publish { reply, .. } => {
                let _ = reply.send(Err(err()));
            }
            KeyPackageCommand::Replenish { reply } => {
                let _ = reply.send(Err(err()));
            }
            KeyPackageCommand::Shutdown => {
                // Filtered in run() before dispatch. Included here so
                // match exhaustiveness holds.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn alice() -> DID {
        DID("did:example:alice".to_owned())
    }

    #[tokio::test]
    async fn reserve_stub_returns_not_implemented() {
        let handle = KeyPackageStoreActor::spawn(alice());
        let err = handle
            .send(|reply| KeyPackageCommand::Reserve {
                kp_ref: "kp-1".to_owned(),
                reply,
            })
            .await
            .expect_err("stub must return NotImplemented");
        assert!(matches!(err, ContextError::NotImplemented(_)));
        handle.send_shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn replenish_stub_returns_not_implemented() {
        let handle = KeyPackageStoreActor::spawn(alice());
        let err = handle
            .send(|reply| KeyPackageCommand::Replenish { reply })
            .await
            .expect_err("stub must return NotImplemented");
        assert!(matches!(err, ContextError::NotImplemented(_)));
        handle.send_shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_exits_loop() {
        let handle = KeyPackageStoreActor::spawn(alice());
        handle.send_shutdown().await.unwrap();
        // After shutdown, sending another command must fail closed-inbox
        // (the actor task has exited).
        //
        // Give the runtime a chance to drain the shutdown before we try.
        tokio::task::yield_now().await;
        let result: Result<(), ContextError> = handle
            .send(|reply| KeyPackageCommand::Replenish { reply })
            .await
            .map(|_| ());
        assert!(
            matches!(result, Err(ContextError::ActorBusy(_))),
            "expected ActorBusy after shutdown, got {result:?}"
        );
    }

    #[tokio::test]
    async fn handle_is_clone() {
        let h1 = KeyPackageStoreActor::spawn(alice());
        let h2 = h1.clone();
        drop(h1);
        h2.send_shutdown().await.unwrap();
    }
}
