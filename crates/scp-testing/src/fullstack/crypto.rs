//! E2E crypto side channel for the full-stack harness (ADR-049 §15).
//!
//! After ADR-049 §15 the `ContextCryptoProvider` trait is gone:
//! `Supervisor` binds the concrete [`NodeMlsFactory`], and the per-context
//! MLS / sender-key / access-key state is owned by the context actor (the
//! creator side) or by the provider directly (the joiner side, which never
//! spawns an actor for the context).
//!
//! `E2eCryptoProvider` is the harness-side helper that bridges the
//! sealed-invitation / sender-key material between two in-process nodes through
//! a shared [`KeyExchange`]. It does NOT re-introduce a trait impl: every MLS
//! primitive runs on the real concrete [`NodeMlsFactory`]; the `KeyExchange`
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
//! - `OpenMLS` group create / add / remove / encrypt / decrypt. On the receive
//!   side (Commit merge, sender-key install, message decrypt) this now runs
//!   through the REAL per-context actor via
//!   [`Supervisor::deliver_commit_blob`](scp_core::context::Supervisor::deliver_commit_blob)
//!   (ADR-049 PR-7, SCP-CRYPTOMOVE-001) — the provider `open` /
//!   `mls_encrypt_management` / `drain_pending_sender_key_messages` twins were
//!   deleted when crypto ownership moved onto the actor. Group create / add and
//!   the sender-key request/response (pull) primitives remain on the concrete
//!   provider.
//! - HPKE-sealed sender-key distribution, MLS-wrapped for transport: the
//!   inviter's actor pushes it during `invite_member`; the harness harvests the
//!   pushed blob from the transport and re-delivers it to the joiner through the
//!   actor receive path.
//! - AES-256-KW access-key wrapping / unwrapping of content.
//!
//! # What is test infrastructure
//!
//! - The [`KeyExchange`] side channel that moves the bootstrap bytes
//!   (sealed invitation, harvested sender-key blobs, epoch-advance Commits)
//!   between `FullStackNode`s without a live relay.

use std::sync::Arc;

use scp_core::crypto::mls::provider::NodeMlsFactory;
use scp_did::DID;

use super::exchange::KeyExchange;

/// Harness-side crypto helper for one `FullStackNode`.
///
/// Holds the node's concrete [`NodeMlsFactory`] plus a handle on the
/// shared [`KeyExchange`]. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the per-context
/// MLS group / sender-key decrypt state is owned by the context ACTOR (creator
/// and joiner alike now stand up a live actor), so every receive-side MLS
/// operation routes through the `Supervisor` mailbox (see
/// [`super::node::FullStackNode`]); the provider retains only the birth /
/// sender-key request-response primitives.
pub struct E2eCryptoProvider {
    /// Real crypto provider — every MLS / sender-key / access-key
    /// primitive flows through this field.
    pub provider: Arc<NodeMlsFactory>,
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
        let provider = Arc::new(NodeMlsFactory::new(
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

    /// Takes (drains) every raw epoch-advance Commit deposited for this node,
    /// in deposit order.
    ///
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the provider `open` twin is deleted —
    /// Commits are now merged through the REAL actor receive path. The caller
    /// ([`super::node::FullStackNode`]) wraps each raw Commit in a throwaway
    /// `OuterEnvelope` and feeds it to
    /// [`Supervisor::deliver_commit_blob`](scp_core::context::Supervisor::deliver_commit_blob),
    /// which routes it through the actor's `decrypt_and_dispatch` MLS control
    /// path and merges the staged commit (advancing the group epoch).
    #[must_use]
    pub fn take_pending_commits(&self, context_id: &[u8; 32]) -> Vec<Vec<u8>> {
        self.exchange()
            .take_commits(context_id, self.local_did.as_ref())
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

    /// Takes (drains) every MLS-wrapped sender-key distribution message
    /// deposited for this node, in deposit order.
    ///
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the provider `open` /
    /// `mls_encrypt_management` twins are deleted. Each drained blob is a full
    /// `OuterEnvelope` (harvested from the inviter's transport, where the
    /// inviter's actor pushed it during `invite_member`). The caller
    /// ([`super::node::FullStackNode`]) feeds each straight to
    /// [`Supervisor::deliver_commit_blob`](scp_core::context::Supervisor::deliver_commit_blob),
    /// whose `decrypt_and_dispatch` MLS-opens it and installs the authenticated
    /// sender key through the same gate-before-install path production uses.
    #[must_use]
    pub fn take_pending_sender_key_messages(&self, context_id: &[u8; 32]) -> Vec<Vec<u8>> {
        self.exchange()
            .take_sender_key_messages(context_id, self.local_did.as_ref())
    }
}
