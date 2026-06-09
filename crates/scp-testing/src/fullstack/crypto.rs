//! E2E crypto side channel for the full-stack harness (ADR-049 commit 12c.9f).
//!
//! After ADR-049 commit 12c.9e the `ContextCryptoProvider` trait is gone:
//! `Supervisor` binds the concrete [`MlsCryptoProvider`], and the per-context
//! MLS / sender-key / access-key state is owned by the context actor (the
//! creator side) or by the provider directly (the joiner side, which never
//! spawns an actor for the context).
//!
//! `E2eCryptoProvider` is the harness-side helper that bridges the
//! Welcome / sender-key / access-key material between two in-process nodes
//! through a shared [`KeyExchange`]. It does NOT re-introduce a trait impl:
//! every MLS primitive runs on the real concrete [`MlsCryptoProvider`]; the
//! `KeyExchange` only carries the cross-process bootstrap bytes that a real
//! deployment would move over transport (the joiner's key package, the
//! Welcome, the inviter-minted per-member access keys, and the MLS-wrapped
//! sender-key distribution messages).
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

use std::sync::{Arc, Mutex};

use scp_core::crypto::access_keys::{AccessKey, AccessKeyStore};
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_identity::DID;

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
    /// Joiner-side access-key store. On the creator side the per-member access
    /// keys live in the context actor's `PerContextState`; the joiner has no
    /// actor for the context, so it stores the keys the creator deposited here
    /// for the decrypt path to unwrap content with.
    access_keys: Mutex<AccessKeyStore>,
}

impl E2eCryptoProvider {
    /// Constructs a new E2E crypto helper bound to `did`, sharing
    /// `exchange` with every other node in the same `FullStackNetwork`.
    #[must_use]
    pub fn new(did: DID, exchange: Arc<std::sync::Mutex<KeyExchange>>) -> Self {
        let provider = Arc::new(MlsCryptoProvider::new(did.as_ref().to_owned()));
        Self {
            provider,
            exchange,
            local_did: did,
            access_keys: Mutex::new(AccessKeyStore::new()),
        }
    }

    /// Locks the shared exchange, recovering from a poisoned mutex (a panic
    /// in another node's harness code must not wedge the test).
    fn exchange(&self) -> std::sync::MutexGuard<'_, KeyExchange> {
        self.exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // -- Joiner side: key package -> Welcome -> join -----------------------

    /// Prepares a real MLS key package for this node to join a context and
    /// deposits it in the shared exchange for the inviter to pick up.
    ///
    /// The provider retains the matching signer / storage state internally
    /// (its `pending_joins` slot), consumed later by
    /// [`MlsCryptoProvider::join_from_welcome`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`](scp_core::context::ContextError) from key
    /// package generation.
    pub fn deposit_key_package(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let kp_bytes = self.provider.prepare_key_package_for_join()?;
        self.exchange()
            .deposit_key_package(*context_id, self.local_did.as_ref(), kp_bytes);
        Ok(())
    }

    /// Joins an MLS group from the Welcome the inviter deposited in the
    /// shared exchange, forming this node's local group state.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`](scp_core::context::ContextError) if no
    /// Welcome is available or Welcome processing fails.
    pub fn join_from_welcome(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let welcome_bytes = {
            let mut exchange = self.exchange();
            exchange
                .take_welcome(context_id, self.local_did.as_ref())
                .ok_or_else(|| {
                    scp_core::context::ContextError::CryptoFailed(format!(
                        "no Welcome available for {} in context {}",
                        self.local_did.as_ref(),
                        hex::encode(context_id)
                    ))
                })?
        };
        self.provider.join_from_welcome(context_id, &welcome_bytes)
    }

    // -- Inviter side: deposit Welcome + access keys -----------------------

    /// Deposits a Welcome for `joiner_did` to pick up.
    pub fn deposit_welcome(&self, context_id: &[u8; 32], joiner_did: &str, welcome_bytes: Vec<u8>) {
        self.exchange()
            .deposit_welcome(*context_id, joiner_did, welcome_bytes);
    }

    /// Takes (removes) a key package the joiner deposited for this context.
    #[must_use]
    pub fn take_key_package(&self, context_id: &[u8; 32], joiner_did: &str) -> Option<Vec<u8>> {
        self.exchange().take_key_package(context_id, joiner_did)
    }

    /// Deposits a per-member access key for `joiner_did` to pick up during
    /// join. `member_did` identifies whose key this is.
    pub fn deposit_access_key(
        &self,
        context_id: &str,
        joiner_did: &str,
        member_did: &str,
        key: AccessKey,
    ) {
        self.exchange()
            .deposit_access_key(context_id, joiner_did, member_did, key);
    }

    /// Picks up every access key the inviter deposited for this node and
    /// stores them locally so the decrypt path can unwrap content.
    pub fn pickup_access_keys(&self, context_id: &str) {
        let keys = {
            let mut exchange = self.exchange();
            exchange.take_access_keys(context_id, self.local_did.as_ref())
        };
        let mut store = self
            .access_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (member_did, key) in keys {
            store.set(context_id, &member_did, key);
        }
    }

    /// Returns this node's locally-stored access key for `member_did`, if any.
    #[must_use]
    pub fn get_access_key(&self, context_id: &str, member_did: &str) -> Option<AccessKey> {
        self.access_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(context_id, member_did)
            .cloned()
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
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let commits = {
            let mut exchange = self.exchange();
            exchange.take_commits(context_id, self.local_did.as_ref())
        };
        for commit_bytes in commits {
            let wrapped =
                super::node::wrap_raw_mls_message(&hex::encode(context_id), commit_bytes)?;
            match self.provider.open(context_id, &wrapped)? {
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
        context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::ContextError> {
        let messages = {
            let mut exchange = self.exchange();
            exchange.take_sender_key_messages(context_id, self.local_did.as_ref())
        };
        for wrapped in messages {
            match self.provider.open(context_id, &wrapped)? {
                scp_core::context::builder::OpenResult::Management {
                    sender_did,
                    payload,
                } => {
                    self.provider
                        .process_incoming_sender_key(context_id, &sender_did, &payload)?;
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
