//! Shared key-exchange side channel for the full-stack harness.
//!
//! In a real deployment the joiner's key package, the MLS Welcome, the
//! inviter-minted per-member access keys, and the MLS-wrapped sender-key
//! distribution messages all travel over transport (relay, blob store, MLS
//! management channel). In the in-process `FullStackNetwork` harness there is
//! no shared transport between the creator's actor and the joiner's provider,
//! so `KeyExchange` carries those bootstrap bytes between nodes.
//!
//! Everything stored here is wire bytes — there is no in-process MLS state
//! (no `MlsMessageOut`, signer, or `OpenMLS` provider) crossing the channel.
//! After ADR-049 commit 12c.9f the joiner generates and retains its own MLS
//! signer state inside its [`MlsCryptoProvider`](scp_core::crypto::mls::provider::MlsCryptoProvider);
//! only the serialized Welcome bytes need to travel.

use std::collections::HashMap;

use scp_core::crypto::access_keys::AccessKey;

/// Shared key-exchange between `E2eCryptoProvider` instances.
///
/// Thread-safe via an external `std::sync::Mutex` wrapping. Keyed by
/// `([u8; 32] context_id, joiner_did)` for per-joiner bootstrap material and
/// by `(context_id_str, joiner_did)` for access keys (which use the original
/// string context ID, matching the access-key store's keying).
pub struct KeyExchange {
    /// Joiner key packages: `(context_id, joiner_did) -> kp_bytes`.
    /// The joiner deposits its TLS-serialized MLS `KeyPackage`; the inviter
    /// takes it and feeds it to the real `add_member` path.
    key_packages: HashMap<([u8; 32], String), Vec<u8>>,
    /// Pending Welcomes: `(context_id, joiner_did) -> welcome_bytes`.
    /// The inviter deposits the TLS-serialized MLS Welcome produced by
    /// `add_member`; the joiner takes it and forms its group state.
    welcomes: HashMap<([u8; 32], String), Vec<u8>>,
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
            key_packages: HashMap::new(),
            welcomes: HashMap::new(),
            sender_key_messages: HashMap::new(),
            commits: HashMap::new(),
            access_keys: HashMap::new(),
        }
    }

    /// Deposits a joiner key package for the inviter to pick up.
    pub fn deposit_key_package(
        &mut self,
        context_id: [u8; 32],
        joiner_did: &str,
        kp_bytes: Vec<u8>,
    ) {
        self.key_packages
            .insert((context_id, joiner_did.to_owned()), kp_bytes);
    }

    /// Takes (removes) the key package the given joiner deposited.
    #[must_use]
    pub fn take_key_package(&mut self, context_id: &[u8; 32], joiner_did: &str) -> Option<Vec<u8>> {
        self.key_packages
            .remove(&(*context_id, joiner_did.to_owned()))
    }

    /// Deposits a serialized Welcome for a joiner to retrieve.
    pub fn deposit_welcome(
        &mut self,
        context_id: [u8; 32],
        joiner_did: &str,
        welcome_bytes: Vec<u8>,
    ) {
        self.welcomes
            .insert((context_id, joiner_did.to_owned()), welcome_bytes);
    }

    /// Takes (removes) the Welcome deposited for the given joiner.
    #[must_use]
    pub fn take_welcome(&mut self, context_id: &[u8; 32], joiner_did: &str) -> Option<Vec<u8>> {
        self.welcomes.remove(&(*context_id, joiner_did.to_owned()))
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
