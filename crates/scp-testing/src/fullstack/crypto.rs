//! E2E crypto side channel for the full-stack harness (ADR-049 commit 12c.9f).
//!
//! After ADR-049 commit 12c.9e the `ContextCryptoProvider` trait is gone:
//! `Supervisor` binds the concrete [`MlsCryptoProvider`], and the per-context
//! MLS / sender-key / access-key state is owned by the context actor (the
//! creator side) or by the provider directly (the joiner side, which never
//! spawns an actor for the context).
//!
//! `E2eCryptoProvider` is the harness-side helper that bridges the
//! sealed-invitation / sender-key material between two in-process nodes through
//! a shared [`KeyExchange`]. It does NOT re-introduce a trait impl: every MLS
//! primitive runs on the real concrete [`MlsCryptoProvider`]; the `KeyExchange`
//! only carries the cross-process bootstrap bytes that a real deployment would
//! move over transport (the creator-signed, HPKE-sealed invitation bundle and
//! the MLS-wrapped sender-key distribution messages the inviter pushes to the
//! joiner). Per-member §9.17 access keys are NOT carried by the `KeyExchange`:
//! the joiner acquires them by issuing REAL §9.17 pull requests the creator
//! answers (see [`super::node::FullStackNode::join_from_welcome`]). The joiner
//! reserves its own `KeyPackage` on its supervisor and, after the creator's
//! `invite_member`, stands up a live actor via `spawn_actor_from_welcome`
//! (ADR-049 §9 2F-residual) — the legacy provider single-slot join path is gone.
//!
//! # What is real
//!
//! - `OpenMLS` group create / add / remove / encrypt / decrypt (via the
//!   concrete provider's inherent methods, which delegate to the same
//!   `group::*` / `encrypt::*` primitives as production).
//! - HPKE-sealed sender-key distribution (`distribute_sender_key`,
//!   `process_incoming_sender_key`), MLS-wrapped for transport.
//! - AES-256-KW access-key wrapping / unwrapping of content.
//!
//! # What is test infrastructure
//!
//! - The [`KeyExchange`] side channel that moves the bootstrap bytes
//!   between `FullStackNode`s without a live relay.

use std::sync::Arc;

use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_did::DID;

use super::exchange::KeyExchange;

/// Harness-side crypto helper for one `FullStackNode`.
///
/// Holds the node's concrete [`MlsCryptoProvider`] plus a handle on the
/// shared [`KeyExchange`]. The provider is the single source of MLS truth on
/// the joiner side; on the creator side the actor takes ownership of the
/// per-context state at spawn time, so creator-side reads route through the
/// `Supervisor` mailbox (see [`super::node::FullStackNode`]).
pub struct E2eCryptoProvider {
    /// Real crypto provider — every MLS / sender-key / access-key
    /// primitive flows through this field.
    pub provider: Arc<MlsCryptoProvider>,
    /// Shared key-exchange side channel across `FullStackNetwork` nodes.
    pub(crate) exchange: Arc<std::sync::Mutex<KeyExchange>>,
    /// This node's DID.
    pub local_did: DID,
}

impl E2eCryptoProvider {
    /// Constructs a new E2E crypto helper bound to `did`, sharing
    /// `exchange` with every other node in the same `FullStackNetwork`.
    #[must_use]
    pub fn new(did: DID, exchange: Arc<std::sync::Mutex<KeyExchange>>) -> Self {
        let provider = Arc::new(MlsCryptoProvider::new(
            did.as_ref().to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        Self {
            provider,
            exchange,
            local_did: did,
        }
    }

    /// Locks the shared exchange, recovering from a poisoned mutex (a panic
    /// in another node's harness code must not wedge the test).
    fn exchange(&self) -> std::sync::MutexGuard<'_, KeyExchange> {
        self.exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // -- Joiner side: pick up the sealed invitation ------------------------

    /// Takes (removes) the pending invitation deposited for this node — the
    /// creator-signed, HPKE-sealed [`SealedInvitation`](scp_core::context::invitation_helpers::SealedInvitation)
    /// bundle plus this node's reservation id. The joiner feeds these straight
    /// into `Supervisor::spawn_actor_from_welcome`.
    #[must_use]
    pub fn take_pending_join(&self, context_id: &[u8; 32]) -> Option<super::exchange::PendingJoin> {
        self.exchange()
            .take_pending_join(context_id, self.local_did.as_ref())
    }

    // -- Inviter side: deposit the sealed invitation + access keys ---------

    /// Deposits a pending invitation (sealed bundle + reservation id) for
    /// `joiner_did` to pick up. Produced by the inviter's
    /// `Supervisor::invite_member`.
    pub fn deposit_pending_join(
        &self,
        context_id: &[u8; 32],
        joiner_did: &str,
        pending: super::exchange::PendingJoin,
    ) {
        self.exchange()
            .deposit_pending_join(*context_id, joiner_did, pending);
    }

    // -- Epoch-advance Commits for existing members ------------------------

    /// Deposits a raw epoch-advance Commit for an existing member to process.
    pub fn deposit_commit(&self, context_id: &[u8; 32], member_did: &str, commit_bytes: Vec<u8>) {
        self.exchange()
            .deposit_commit(*context_id, member_did, commit_bytes);
    }

    /// Applies every pending epoch-advance Commit deposited for this node.
    ///
    /// Each raw Commit is wrapped in a throwaway `OuterEnvelope` and fed to
    /// [`MlsCryptoProvider::open`], which routes it through the MLS control
    /// path and merges the staged commit (advancing the group epoch).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`](scp_core::context::ContextError) if Commit
    /// processing fails.
    pub fn process_pending_commits(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let commits = {
            let mut exchange = self.exchange();
            exchange.take_commits(context_id, self.local_did.as_ref())
        };
        for commit_bytes in commits {
            let wrapped =
                super::node::wrap_raw_mls_message(&hex::encode(context_id), commit_bytes)?;
            match self.provider.open(context_id, context_id_str, &wrapped)? {
                // A Commit advances the epoch and surfaces as a control
                // message — no payload is produced.
                scp_core::context::builder::OpenResult::Control => {}
                scp_core::context::builder::OpenResult::Application(_)
                | scp_core::context::builder::OpenResult::Management { .. } => {
                    return Err(scp_core::context::ContextError::CryptoFailed(
                        "commit channel carried a non-control MLS message".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    // -- Sender keys: MLS-wrapped distribution side channel ----------------

    /// Deposits an MLS-wrapped sender-key distribution message captured from
    /// the inviter's transport so the joiner can process it after joining.
    pub fn deposit_sender_key_message(
        &self,
        context_id: &[u8; 32],
        joiner_did: &str,
        msg: Vec<u8>,
    ) {
        self.exchange()
            .deposit_sender_key_message(*context_id, joiner_did, msg);
    }

    /// Distributes this node's sender key to `target_did`: queues the
    /// HPKE-sealed distribution on the provider, drains and MLS-wraps it, and
    /// deposits the wrapped bytes in the exchange for the target to pick up.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`](scp_core::context::ContextError) on
    /// distribution, drain, or MLS-wrap failure.
    pub fn distribute_sender_key(
        &self,
        context_id: &[u8; 32],
        target_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        self.provider
            .distribute_sender_key(context_id, target_did)?;
        let routing_id = scp_core::context::context_routing_id(&hex::encode(context_id));
        let pending = self
            .provider
            .drain_pending_sender_key_messages(context_id)?;
        for (target, message) in pending {
            let wrapped =
                self.provider
                    .mls_encrypt_management(context_id, &message, &routing_id, 3600)?;
            self.deposit_sender_key_message(context_id, &target, wrapped);
        }
        Ok(())
    }

    /// Processes every MLS-wrapped sender-key distribution message deposited
    /// for this node: MLS-open each one, then feed the management payload to
    /// [`MlsCryptoProvider::process_incoming_sender_key`].
    ///
    /// Must be called after [`Self::join_from_welcome`] (the node needs its
    /// MLS group to decrypt the wrapped messages).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`](scp_core::context::ContextError) if MLS-open
    /// or sender-key processing fails.
    pub fn pickup_sender_key_messages(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let messages = {
            let mut exchange = self.exchange();
            exchange.take_sender_key_messages(context_id, self.local_did.as_ref())
        };
        for wrapped in messages {
            match self.provider.open(context_id, context_id_str, &wrapped)? {
                scp_core::context::builder::OpenResult::Management {
                    sender_did,
                    payload,
                } => {
                    // ADR-049 PR-6: `process_incoming_sender_key` now returns the
                    // authenticated `(key, epoch)` without installing; install it
                    // via `set_sender_key_unchecked`. This full-stack harness is a
                    // trusted pickup path (no adversarial-exporter registry gate).
                    let (key, _epoch) = self.provider.process_incoming_sender_key(
                        context_id,
                        &sender_did,
                        &payload,
                    )?;
                    self.provider
                        .set_sender_key_unchecked(context_id, &sender_did, key);
                }
                // A non-management message in the sender-key channel means
                // the wrong bytes were deposited — fail loudly rather than
                // silently dropping key material.
                scp_core::context::builder::OpenResult::Application(_)
                | scp_core::context::builder::OpenResult::Control => {
                    return Err(scp_core::context::ContextError::CryptoFailed(
                        "sender-key channel carried a non-management MLS message".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}
