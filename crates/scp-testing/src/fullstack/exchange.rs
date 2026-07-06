//! Shared key-exchange side channel for the full-stack harness.
//!
//! In a real deployment the creator-signed, HPKE-sealed invitation bundle, the
//! inviter-minted per-member access keys, and the MLS-wrapped sender-key
//! distribution messages all travel over transport (relay, blob store, MLS
//! management channel). In the in-process `FullStackNetwork` harness there is
//! no shared transport between the creator's actor and the joiner's supervisor,
//! so `KeyExchange` carries those bootstrap bytes between nodes.
//!
//! The reserve → `invite_member` → `spawn_actor_from_welcome` migration (ADR-049
//! §9 2F-residual) retires the legacy raw-Welcome slot: the creator now reserves
//! the joiner's KeyPackage directly on the joiner's supervisor and calls
//! `Supervisor::invite_member`, which returns a signed, sealed
//! [`SealedInvitation`]. That bundle (plus the joiner's reservation id) is what
//! crosses this channel — the joiner feeds it straight into
//! `Supervisor::spawn_actor_from_welcome`, becoming a live send-capable actor.

use std::collections::HashMap;

use scp_core::context::invitation_helpers::SealedInvitation;
use scp_core::context::supervisor::ReservationId;
use scp_core::crypto::access_keys::AccessKey;

/// A pending invitation for a joiner: the creator-signed, HPKE-sealed
/// [`SealedInvitation`] bundle plus the joiner's own reservation id (the handle
/// on the KeyPackage the creator's `invite_member` consumed). Together they are
/// exactly the inputs `Supervisor::spawn_actor_from_welcome` needs.
#[derive(Clone)]
pub struct PendingJoin {
    /// The creator-signed, HPKE-sealed invitation bundle.
    pub sealed: SealedInvitation,
    /// The joiner's reservation id for the KeyPackage the creator added.
    pub reservation_id: ReservationId,
}

/// Shared key-exchange between `E2eCryptoProvider` instances.
///
/// Thread-safe via an external `std::sync::Mutex` wrapping. Keyed by
/// `([u8; 32] context_id, joiner_did)` for per-joiner bootstrap material and
/// by `(context_id_str, joiner_did)` for access keys (which use the original
/// string context ID, matching the access-key store's keying).
pub struct KeyExchange {
    /// Pending invitations: `(context_id, joiner_did) -> PendingJoin`.
    /// The inviter deposits the creator-signed sealed bundle + reservation id
    /// produced by `Supervisor::invite_member`; the joiner takes it and feeds
    /// it to `Supervisor::spawn_actor_from_welcome`.
    pending_joins: HashMap<([u8; 32], String), PendingJoin>,
    /// MLS-wrapped sender-key distribution messages for joiners:
    /// `(context_id, joiner_did) -> Vec<wrapped_bytes>`. The inviter captures
    /// these off its transport during `add_member` and deposits them; the
    /// joiner MLS-opens each and processes the embedded sender key.
    sender_key_messages: HashMap<([u8; 32], String), Vec<Vec<u8>>>,
    /// Pending epoch-advance Commits for existing members:
    /// `(context_id, member_did) -> Vec<commit_bytes>`. When the inviter adds
    /// a new member every existing member must process the resulting Commit so
    /// their MLS group advances to the new epoch. Raw TLS-serialized MLS
    /// Commit bytes (not envelope-wrapped).
    commits: HashMap<([u8; 32], String), Vec<Vec<u8>>>,
    /// Access keys deposited for joiners:
    /// `(context_id_str, joiner_did) -> Vec<(member_did, AccessKey)>`.
    /// When the inviter adds a joiner it deposits every existing member's
    /// access key (including the joiner's own) so the joiner can both decrypt
    /// inbound content and wrap outbound content. A `Vec` allows multiple
    /// keys per joiner.
    access_keys: HashMap<(String, String), Vec<(String, AccessKey)>>,
}

impl KeyExchange {
    /// Creates an empty key exchange.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_joins: HashMap::new(),
            sender_key_messages: HashMap::new(),
            commits: HashMap::new(),
            access_keys: HashMap::new(),
        }
    }

    /// Deposits a pending invitation (sealed bundle + reservation id) for the
    /// given joiner to pick up.
    pub fn deposit_pending_join(
        &mut self,
        context_id: [u8; 32],
        joiner_did: &str,
        pending: PendingJoin,
    ) {
        self.pending_joins
            .insert((context_id, joiner_did.to_owned()), pending);
    }

    /// Takes (removes) the pending invitation deposited for the given joiner.
    #[must_use]
    pub fn take_pending_join(
        &mut self,
        context_id: &[u8; 32],
        joiner_did: &str,
    ) -> Option<PendingJoin> {
        self.pending_joins
            .remove(&(*context_id, joiner_did.to_owned()))
    }

    /// Deposits an MLS-wrapped sender-key distribution message for a joiner.
    pub fn deposit_sender_key_message(
        &mut self,
        context_id: [u8; 32],
        joiner_did: &str,
        msg: Vec<u8>,
    ) {
        self.sender_key_messages
            .entry((context_id, joiner_did.to_owned()))
            .or_default()
            .push(msg);
    }

    /// Takes all MLS-wrapped sender-key distribution messages deposited for
    /// the given joiner, in deposit order.
    #[must_use]
    pub fn take_sender_key_messages(
        &mut self,
        context_id: &[u8; 32],
        joiner_did: &str,
    ) -> Vec<Vec<u8>> {
        self.sender_key_messages
            .remove(&(*context_id, joiner_did.to_owned()))
            .unwrap_or_default()
    }

    /// Deposits a raw epoch-advance Commit for an existing member to process.
    pub fn deposit_commit(
        &mut self,
        context_id: [u8; 32],
        member_did: &str,
        commit_bytes: Vec<u8>,
    ) {
        self.commits
            .entry((context_id, member_did.to_owned()))
            .or_default()
            .push(commit_bytes);
    }

    /// Takes all pending Commits for the given member, in deposit order.
    #[must_use]
    pub fn take_commits(&mut self, context_id: &[u8; 32], member_did: &str) -> Vec<Vec<u8>> {
        self.commits
            .remove(&(*context_id, member_did.to_owned()))
            .unwrap_or_default()
    }

    /// Deposits an access key for a joiner to retrieve during join.
    ///
    /// The key is associated with `joiner_did` (who picks it up).
    /// `member_did` identifies whose access key this is. Call once per
    /// existing member when adding a new joiner.
    pub fn deposit_access_key(
        &mut self,
        context_id: &str,
        joiner_did: &str,
        member_did: &str,
        key: AccessKey,
    ) {
        self.access_keys
            .entry((context_id.to_owned(), joiner_did.to_owned()))
            .or_default()
            .push((member_did.to_owned(), key));
    }

    /// Takes (removes) all access keys deposited for the given joiner.
    ///
    /// Returns `(member_did, AccessKey)` pairs, or an empty `Vec` if none.
    #[must_use]
    pub fn take_access_keys(
        &mut self,
        context_id: &str,
        joiner_did: &str,
    ) -> Vec<(String, AccessKey)> {
        self.access_keys
            .remove(&(context_id.to_owned(), joiner_did.to_owned()))
            .unwrap_or_default()
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}
