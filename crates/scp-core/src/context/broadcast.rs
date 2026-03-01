//! Broadcast context subscriber registration and author blocking (SCP-227).
//!
//! Implements the subscriber registration protocol from spec section 5.14.3
//! and author-level blocking from spec section 5.14.8. Open broadcast contexts
//! allow DID-authenticated registration without UCAN; gated contexts require a
//! valid `messagesRead` UCAN. Blocking is per-author and cryptographic: the
//! author rotates their broadcast key, and the blocked subscriber receives no
//! response to future key requests.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::context::ContextError;
use crate::context::params::ContextMode;
use crate::context::roles::UcanToken;
use crate::crypto::sender_keys::{SenderKey, generate_sender_key};

// ---------------------------------------------------------------------------
// BroadcastAdmission
// ---------------------------------------------------------------------------

/// Admission policy for a broadcast context, derived from the template.
///
/// Open contexts grant `messagesRead` on DID-authenticated registration.
/// Gated contexts require an admin-issued UCAN with `messagesRead`.
/// See spec section 5.14.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastAdmission {
    /// Any DID can subscribe without a UCAN (public-broadcast template).
    Open,
    /// Subscription requires a valid `messagesRead` UCAN (gated-broadcast).
    Gated,
}

// ---------------------------------------------------------------------------
// SubscriberRecord
// ---------------------------------------------------------------------------

/// A registered subscriber in a broadcast context.
///
/// Corresponds to the `SubscriberRegistration` wire type in spec section
/// 5.14.3, but stored as the post-validation record. The original signature
/// and wrapping key are consumed during registration; only the identity and
/// registration metadata are retained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberRecord {
    /// The subscriber's DID.
    pub subscriber_did: String,
    /// Unix timestamp (seconds) when the subscriber registered.
    pub registered_at: u64,
    /// Whether the subscriber presented a UCAN (gated admission).
    pub has_ucan: bool,
}

// ---------------------------------------------------------------------------
// AuthorState
// ---------------------------------------------------------------------------

/// Per-author broadcast key state within a broadcast context.
///
/// Each author maintains an independent broadcast key with its own epoch
/// counter and block list. See spec section 5.14.2 for the key lifecycle
/// and section 5.14.8 for blocking semantics.
#[derive(Debug)]
pub struct AuthorState {
    /// The author's DID.
    pub author_did: String,
    /// The current AES-256-GCM broadcast key.
    pub broadcast_key: SenderKey,
    /// The current key epoch (monotonically increasing).
    pub epoch: u64,
    /// DIDs blocked by this author. Blocked subscribers receive no key
    /// material for epochs after the block.
    pub block_list: HashSet<String>,
}

impl AuthorState {
    /// Creates a new author state with a freshly generated broadcast key at
    /// epoch 0.
    #[must_use]
    pub fn new(author_did: String) -> Self {
        Self {
            author_did,
            broadcast_key: generate_sender_key(),
            epoch: 0,
            block_list: HashSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// SubscriptionResult
// ---------------------------------------------------------------------------

/// Result returned by [`BroadcastContext::subscribe`].
///
/// Contains the current author key epochs so the new subscriber knows which
/// epochs to request keys for.
#[derive(Debug, Clone)]
pub struct SubscriptionResult {
    /// Map of author DID to their current key epoch at time of subscription.
    pub author_epochs: HashMap<String, u64>,
}

// ---------------------------------------------------------------------------
// BlockResult
// ---------------------------------------------------------------------------

/// Result returned by [`BroadcastContext::block_subscriber`].
///
/// Contains the new broadcast key and epoch after rotation, which the caller
/// must distribute to non-blocked subscribers.
#[derive(Debug)]
pub struct BlockResult {
    /// The new AES-256-GCM broadcast key after rotation.
    pub new_key: SenderKey,
    /// The new epoch number after rotation.
    pub new_epoch: u64,
}

// ---------------------------------------------------------------------------
// BroadcastContext
// ---------------------------------------------------------------------------

/// Manages subscriber registration and author blocking for a broadcast context.
///
/// This is the context-level orchestrator that sits above the cryptographic
/// primitives in `crypto::sender_keys`. It enforces admission policy (open vs
/// gated), maintains the subscriber roster, and coordinates blocking with key
/// rotation.
///
/// Thread safety: not internally synchronized. The caller (ContextManager) is
/// responsible for serializing access.
#[derive(Debug)]
pub struct BroadcastContext {
    /// The context's unique identifier.
    context_id: String,
    /// Admission policy: open or gated.
    admission: BroadcastAdmission,
    /// Registered subscribers, keyed by DID.
    subscribers: HashMap<String, SubscriberRecord>,
    /// Per-author broadcast key state, keyed by author DID.
    authors: HashMap<String, AuthorState>,
}

impl BroadcastContext {
    /// Creates a new broadcast context with the given admission policy.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidMemoryScopeForBroadcast`] if `mode` is
    /// not `ContextMode::Broadcast`.
    pub fn new(
        context_id: String,
        mode: &ContextMode,
        admission: BroadcastAdmission,
    ) -> Result<Self, ContextError> {
        if *mode != ContextMode::Broadcast {
            return Err(ContextError::InvalidMemoryScopeForBroadcast);
        }
        Ok(Self {
            context_id,
            admission,
            subscribers: HashMap::new(),
            authors: HashMap::new(),
        })
    }

    /// Returns the context ID.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the admission policy.
    #[must_use]
    pub fn admission(&self) -> BroadcastAdmission {
        self.admission
    }

    /// Returns the number of registered subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Returns `true` if the given DID is a registered subscriber.
    #[must_use]
    pub fn is_subscriber(&self, did: &str) -> bool {
        self.subscribers.contains_key(did)
    }

    // -----------------------------------------------------------------------
    // Author management
    // -----------------------------------------------------------------------

    /// Registers an author with a freshly generated broadcast key at epoch 0.
    ///
    /// Authors hold `messagesWrite` capability. This is called when a
    /// `roleAssigned` event with role `author` is processed.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PermissionDenied`] if the author is already
    /// registered.
    pub fn add_author(&mut self, author_did: &str) -> Result<&AuthorState, ContextError> {
        if self.authors.contains_key(author_did) {
            return Err(ContextError::PermissionDenied(format!(
                "author already registered: {author_did}"
            )));
        }
        self.authors.insert(
            author_did.to_owned(),
            AuthorState::new(author_did.to_owned()),
        );
        Ok(self.authors.get(author_did).expect("just inserted"))
    }

    /// Returns the author state for a given DID, if registered.
    #[must_use]
    pub fn get_author(&self, author_did: &str) -> Option<&AuthorState> {
        self.authors.get(author_did)
    }

    /// Returns a mutable reference to the author state for a given DID.
    #[must_use]
    pub fn get_author_mut(&mut self, author_did: &str) -> Option<&mut AuthorState> {
        self.authors.get_mut(author_did)
    }

    // -----------------------------------------------------------------------
    // Subscriber registration (spec section 5.14.3)
    // -----------------------------------------------------------------------

    /// Registers a subscriber in the broadcast context.
    ///
    /// For open broadcast contexts (`BroadcastAdmission::Open`), any DID can
    /// subscribe with `ucan = None`. For gated contexts
    /// (`BroadcastAdmission::Gated`), a valid `messagesRead` UCAN must be
    /// provided.
    ///
    /// Returns the current epoch for each author so the subscriber knows which
    /// key epochs to request.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the context is gated and no
    ///   UCAN is provided, or the UCAN does not contain `messagesRead`.
    /// - [`ContextError::MembershipFailed`] if the subscriber is already
    ///   registered.
    pub fn subscribe(
        &mut self,
        subscriber_did: &str,
        ucan: Option<&UcanToken>,
        timestamp: u64,
    ) -> Result<SubscriptionResult, ContextError> {
        if self.subscribers.contains_key(subscriber_did) {
            return Err(ContextError::MembershipFailed(format!(
                "subscriber already registered: {subscriber_did}"
            )));
        }

        let has_ucan = match self.admission {
            BroadcastAdmission::Open => ucan.is_some(),
            BroadcastAdmission::Gated => {
                let token = ucan.ok_or_else(|| {
                    ContextError::PermissionDenied(
                        "gated broadcast requires messagesRead UCAN".to_owned(),
                    )
                })?;
                validate_messages_read_ucan(token, &self.context_id, subscriber_did)?;
                true
            }
        };

        self.subscribers.insert(
            subscriber_did.to_owned(),
            SubscriberRecord {
                subscriber_did: subscriber_did.to_owned(),
                registered_at: timestamp,
                has_ucan,
            },
        );

        let author_epochs = self
            .authors
            .iter()
            .map(|(did, state)| (did.clone(), state.epoch))
            .collect();

        Ok(SubscriptionResult { author_epochs })
    }

    // -----------------------------------------------------------------------
    // Blocking (spec section 5.14.8)
    // -----------------------------------------------------------------------

    /// Blocks a subscriber from receiving future broadcast keys from the
    /// specified author.
    ///
    /// The author's broadcast key is rotated (new random key, epoch
    /// incremented) and the subscriber DID is added to the author's block
    /// list. The blocked subscriber will receive no response to future key
    /// requests and cannot decrypt content encrypted with the new key.
    ///
    /// Blocking is per-author: blocking a subscriber for Author A does not
    /// affect their access to Author B's content (spec section 5.14.8).
    ///
    /// # Errors
    ///
    /// - [`ContextError::MemberNotFound`] if the author DID is not registered.
    /// - [`ContextError::CryptoFailed`] if the epoch counter overflows.
    pub fn block_subscriber(
        &mut self,
        author_did: &str,
        blocked_did: &str,
    ) -> Result<BlockResult, ContextError> {
        let author = self.authors.get_mut(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;

        author.block_list.insert(blocked_did.to_owned());

        let new_epoch = author
            .epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("broadcast key epoch overflow".to_owned()))?;

        let new_key = generate_sender_key();
        author.epoch = new_epoch;
        author.broadcast_key = new_key.clone();

        Ok(BlockResult { new_key, new_epoch })
    }

    /// Returns `true` if the given subscriber DID is blocked by the given
    /// author.
    #[must_use]
    pub fn is_blocked(&self, author_did: &str, subscriber_did: &str) -> bool {
        self.authors
            .get(author_did)
            .is_some_and(|a| a.block_list.contains(subscriber_did))
    }

    // -----------------------------------------------------------------------
    // Capability checks (spec section 5.14.9)
    // -----------------------------------------------------------------------

    /// Checks whether a DID holds `messagesWrite` (is a registered author).
    ///
    /// In broadcast contexts, `messagesWrite` is restricted to authors.
    #[must_use]
    pub fn can_write(&self, did: &str) -> bool {
        self.authors.contains_key(did)
    }

    /// Checks whether a DID holds `messagesRead` (is a registered subscriber
    /// or author).
    ///
    /// Authors implicitly have read access. Subscribers have read access
    /// through registration.
    #[must_use]
    pub fn can_read(&self, did: &str) -> bool {
        self.subscribers.contains_key(did) || self.authors.contains_key(did)
    }
}

// ---------------------------------------------------------------------------
// UCAN validation helper
// ---------------------------------------------------------------------------

/// Validates that a UCAN token grants `messagesRead` for the given context
/// and is audience-bound to the presenting subscriber.
///
/// Checks: (1) `token.aud == subscriber_did` — prevents presenting a UCAN
/// issued to someone else. (2) An attestation matching
/// `scp:ctx:{context_id}/messages:read` or `scp:ctx:*/messages:read`.
///
/// Full cryptographic UCAN validation (signature chains, expiry, revocation)
/// is deferred to the UCAN module (SCP-024).
fn validate_messages_read_ucan(
    token: &UcanToken,
    context_id: &str,
    subscriber_did: &str,
) -> Result<(), ContextError> {
    if token.aud != subscriber_did {
        return Err(ContextError::PermissionDenied(format!(
            "UCAN audience '{}' does not match subscriber '{}'",
            token.aud, subscriber_did,
        )));
    }
    let specific = format!("scp:ctx:{context_id}/messages:read");
    let wildcard = "scp:ctx:*/messages:read";
    let has_messages_read = token
        .att
        .iter()
        .any(|att| att.with == specific || att.with == wildcard);
    if !has_messages_read {
        return Err(ContextError::PermissionDenied(
            "UCAN does not grant messagesRead for this context".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::roles::UcanAttestation;
    use crate::crypto::sender_keys::{decrypt_sender_layer, encrypt_sender_layer};

    fn make_open_ctx() -> BroadcastContext {
        BroadcastContext::new(
            "ctx-broadcast-1".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap()
    }

    fn make_gated_ctx() -> BroadcastContext {
        BroadcastContext::new(
            "ctx-gated-1".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Gated,
        )
        .unwrap()
    }

    fn make_messages_read_ucan(context_id: &str, subscriber_did: &str) -> UcanToken {
        UcanToken {
            iss: "did:example:admin".to_owned(),
            aud: subscriber_did.to_owned(),
            att: vec![UcanAttestation {
                with: format!("scp:ctx:{context_id}/messages:read"),
                can: "invoke".to_owned(),
            }],
            nnc: "nonce-1".to_owned(),
        }
    }

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_rejects_encrypted_mode() {
        let result = BroadcastContext::new(
            "ctx-1".to_owned(),
            &ContextMode::Encrypted,
            BroadcastAdmission::Open,
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_broadcast_mode() {
        let ctx = make_open_ctx();
        assert_eq!(ctx.context_id(), "ctx-broadcast-1");
        assert_eq!(ctx.admission(), BroadcastAdmission::Open);
        assert_eq!(ctx.subscriber_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Author management
    // -----------------------------------------------------------------------

    #[test]
    fn add_author_creates_epoch_zero_key() {
        let mut ctx = make_open_ctx();
        let author = ctx.add_author("did:example:alice").unwrap();
        assert_eq!(author.author_did, "did:example:alice");
        assert_eq!(author.epoch, 0);
        assert!(author.block_list.is_empty());
    }

    #[test]
    fn add_author_rejects_duplicate() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let result = ctx.add_author("did:example:alice");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Open broadcast subscription (AC 1, 2)
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_open_without_ucan_succeeds() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let result = ctx.subscribe("did:example:bob", None, 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert_eq!(result.author_epochs["did:example:alice"], 0);
        assert!(ctx.is_subscriber("did:example:bob"));
        assert_eq!(ctx.subscriber_count(), 1);
    }

    #[test]
    fn subscribe_open_with_ucan_also_succeeds() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let ucan = make_messages_read_ucan("ctx-broadcast-1", "did:example:bob");

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert!(ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_returns_all_author_epochs() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();

        let result = ctx.subscribe("did:example:bob", None, 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 2);
        assert_eq!(result.author_epochs["did:example:alice"], 0);
        assert_eq!(result.author_epochs["did:example:carol"], 0);
    }

    #[test]
    fn subscribe_rejects_duplicate() {
        let mut ctx = make_open_ctx();
        ctx.subscribe("did:example:bob", None, 1000).unwrap();

        let result = ctx.subscribe("did:example:bob", None, 2000);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Gated broadcast subscription (AC 3)
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_gated_requires_ucan() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let result = ctx.subscribe("did:example:bob", None, 1000);
        assert!(result.is_err());
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_with_valid_ucan_succeeds() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let ucan = make_messages_read_ucan("ctx-gated-1", "did:example:bob");

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert!(ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_rejects_wrong_context_ucan() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let ucan = make_messages_read_ucan("wrong-context", "did:example:bob");

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000);
        assert!(result.is_err());
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_rejects_wrong_capability() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let ucan = UcanToken {
            iss: "did:example:admin".to_owned(),
            aud: "did:example:bob".to_owned(),
            att: vec![UcanAttestation {
                with: "scp:ctx:ctx-gated-1/messages:write".to_owned(),
                can: "invoke".to_owned(),
            }],
            nnc: "nonce-1".to_owned(),
        };

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000);
        assert!(result.is_err());
    }

    #[test]
    fn subscribe_gated_rejects_aud_mismatch() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let ucan = make_messages_read_ucan("ctx-gated-1", "did:example:carol");

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000);
        assert!(result.is_err());
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    // -----------------------------------------------------------------------
    // Blocking (AC 4)
    // -----------------------------------------------------------------------

    #[test]
    fn block_subscriber_rotates_key_and_increments_epoch() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.subscribe("did:example:dave", None, 1000).unwrap();

        let old_epoch = ctx.get_author("did:example:alice").unwrap().epoch;
        let old_key = ctx
            .get_author("did:example:alice")
            .unwrap()
            .broadcast_key
            .as_bytes()
            .to_owned();

        let result = ctx
            .block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();

        assert_eq!(result.new_epoch, old_epoch + 1);
        assert_ne!(result.new_key.as_bytes(), &old_key[..]);
        assert!(ctx.is_blocked("did:example:alice", "did:example:dave"));
    }

    #[test]
    fn block_is_per_author() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();
        ctx.subscribe("did:example:dave", None, 1000).unwrap();

        ctx.block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();

        assert!(ctx.is_blocked("did:example:alice", "did:example:dave"));
        assert!(!ctx.is_blocked("did:example:carol", "did:example:dave"));
    }

    #[test]
    fn block_unknown_author_returns_error() {
        let mut ctx = make_open_ctx();
        let result = ctx.block_subscriber("did:example:unknown", "did:example:dave");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Capability checks (AC 5)
    // -----------------------------------------------------------------------

    #[test]
    fn can_write_only_for_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.subscribe("did:example:bob", None, 1000).unwrap();

        assert!(ctx.can_write("did:example:alice"));
        assert!(!ctx.can_write("did:example:bob"));
        assert!(!ctx.can_write("did:example:unknown"));
    }

    #[test]
    fn can_read_for_subscribers_and_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.subscribe("did:example:bob", None, 1000).unwrap();

        assert!(ctx.can_read("did:example:alice"));
        assert!(ctx.can_read("did:example:bob"));
        assert!(!ctx.can_read("did:example:unknown"));
    }

    // -----------------------------------------------------------------------
    // Integration test: publish, subscribe, decrypt (AC 6)
    // -----------------------------------------------------------------------

    #[test]
    fn integration_author_publishes_3_subscribers_decrypt() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        ctx.subscribe("did:example:sub1", None, 1000).unwrap();
        ctx.subscribe("did:example:sub2", None, 1001).unwrap();
        ctx.subscribe("did:example:sub3", None, 1002).unwrap();

        let author = ctx.get_author("did:example:alice").unwrap();
        let plaintext = b"Hello from Alice's broadcast!";

        let ciphertext = encrypt_sender_layer(&author.broadcast_key, plaintext).unwrap();

        for sub_did in &["did:example:sub1", "did:example:sub2", "did:example:sub3"] {
            assert!(ctx.can_read(sub_did));
            let decrypted = decrypt_sender_layer(&author.broadcast_key, &ciphertext).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    // -----------------------------------------------------------------------
    // Integration test: blocked author's messages undecryptable (AC 7)
    // -----------------------------------------------------------------------

    #[test]
    fn integration_blocked_author_messages_undecryptable() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        ctx.subscribe("did:example:sub1", None, 1000).unwrap();
        ctx.subscribe("did:example:sub2", None, 1001).unwrap();

        let old_key = ctx
            .get_author("did:example:alice")
            .unwrap()
            .broadcast_key
            .clone();

        let pre_block_msg = b"message before block";
        let pre_block_ct = encrypt_sender_layer(&old_key, pre_block_msg).unwrap();

        assert_eq!(
            decrypt_sender_layer(&old_key, &pre_block_ct).unwrap(),
            pre_block_msg
        );

        let block_result = ctx
            .block_subscriber("did:example:alice", "did:example:sub2")
            .unwrap();

        let post_block_msg = b"message after block";
        let post_block_ct = encrypt_sender_layer(&block_result.new_key, post_block_msg).unwrap();

        let non_blocked_decrypted =
            decrypt_sender_layer(&block_result.new_key, &post_block_ct).unwrap();
        assert_eq!(non_blocked_decrypted, post_block_msg);

        let blocked_result = decrypt_sender_layer(&old_key, &post_block_ct);
        assert!(
            blocked_result.is_err(),
            "blocked subscriber should not be able to decrypt post-block messages"
        );
    }

    // -----------------------------------------------------------------------
    // Integration test: multiple authors, blocking one doesn't affect another
    // -----------------------------------------------------------------------

    #[test]
    fn integration_blocking_one_author_does_not_affect_another() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();

        ctx.subscribe("did:example:sub1", None, 1000).unwrap();

        ctx.block_subscriber("did:example:alice", "did:example:sub1")
            .unwrap();

        let carol_author = ctx.get_author("did:example:carol").unwrap();
        let carol_msg = b"Carol's message";
        let carol_ct = encrypt_sender_layer(&carol_author.broadcast_key, carol_msg).unwrap();

        let decrypted = decrypt_sender_layer(&carol_author.broadcast_key, &carol_ct).unwrap();
        assert_eq!(decrypted, carol_msg);
    }

    // -----------------------------------------------------------------------
    // Gated + blocking integration
    // -----------------------------------------------------------------------

    #[test]
    fn integration_gated_subscribe_then_block() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let ucan = make_messages_read_ucan("ctx-gated-1", "did:example:sub1");
        ctx.subscribe("did:example:sub1", Some(&ucan), 1000)
            .unwrap();

        let author = ctx.get_author("did:example:alice").unwrap();
        let old_key = author.broadcast_key.clone();

        let msg_before = b"gated message before block";
        let ct_before = encrypt_sender_layer(&old_key, msg_before).unwrap();

        assert_eq!(
            decrypt_sender_layer(&old_key, &ct_before).unwrap(),
            msg_before
        );

        let block_result = ctx
            .block_subscriber("did:example:alice", "did:example:sub1")
            .unwrap();

        let msg_after = b"gated message after block";
        let ct_after = encrypt_sender_layer(&block_result.new_key, msg_after).unwrap();

        let blocked_result = decrypt_sender_layer(&old_key, &ct_after);
        assert!(
            blocked_result.is_err(),
            "blocked subscriber cannot decrypt post-block gated messages"
        );
    }
}
