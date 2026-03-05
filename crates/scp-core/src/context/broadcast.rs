//! Broadcast context subscriber registration and author blocking (SCP-227).
//!
//! Implements the subscriber registration protocol from spec section 5.14.3
//! and author-level blocking from spec section 5.14.8. Open broadcast contexts
//! allow DID-authenticated registration without UCAN; gated contexts require a
//! valid `messagesRead` UCAN. Blocking is per-author and cryptographic: the
//! author rotates their broadcast key, and the blocked subscriber receives no
//! response to future key requests.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::context::ContextError;
use crate::context::membership::ContextEvent;
use crate::context::params::ContextMode;
use crate::crypto::sender_keys::{
    BroadcastEnvelope, BroadcastKey, SenderKey, generate_sender_key, seal_broadcast,
};
use crate::crypto::ucan::UcanToken;
use crate::crypto::ucan::capability::CapabilityUri;
use crate::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext, validate_ucan,
};
use scp_identity::DID;

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
/// epochs to request keys for, and the `MemberJoined` event that the caller
/// must append to the context's event log and receive buffer.
#[derive(Debug, Clone)]
pub struct SubscriptionResult {
    /// Map of author DID to their current key epoch at time of subscription.
    pub author_epochs: HashMap<String, u64>,
    /// The `MemberJoined` event for this subscription.
    ///
    /// The caller (`ContextManager`) is responsible for appending this event
    /// to the context's event log and receive buffer. See spec section 5.14.3:
    /// "Event log records registration via `MemberJoined` with role subscriber."
    pub event: ContextEvent,
}

// ---------------------------------------------------------------------------
// BlockResult
// ---------------------------------------------------------------------------

/// Result returned by [`BroadcastContext::block_subscriber`].
///
/// Contains the new broadcast key and epoch after rotation, which the caller
/// must distribute to non-blocked subscribers. Also includes the author DID
/// and the full block list so the caller can persist block state via
/// `ProtocolStore::store_broadcast_block_list`. See RED-016.
#[derive(Debug)]
pub struct BlockResult {
    /// The new AES-256-GCM broadcast key after rotation.
    pub new_key: SenderKey,
    /// The new epoch number after rotation.
    pub new_epoch: u64,
    /// The author DID whose block list was modified.
    pub author_did: String,
    /// The full block list after the block operation, for persistence.
    pub block_list: HashSet<String>,
}

// ---------------------------------------------------------------------------
// UnsubscribeResult
// ---------------------------------------------------------------------------

/// Result returned by [`BroadcastContext::unsubscribe`].
///
/// Contains the subscriber DID for `MemberLeft` event production, and
/// optionally the list of authors whose keys were rotated as a consequence
/// of the unsubscription (when `rotate_keys` is requested). Callers use this
/// to emit `MemberLeft` + `KeyEpochAdvance` events and distribute new keys.
#[derive(Debug)]
pub struct UnsubscribeResult {
    /// The DID of the unsubscribed member (for `MemberLeft` event).
    pub subscriber_did: String,
    /// Per-author key rotation results triggered by the unsubscription.
    /// Empty if `rotate_keys` was `false` or there are no authors.
    pub key_rotations: Vec<BlockResult>,
}

// ---------------------------------------------------------------------------
// AuthorBlockResult
// ---------------------------------------------------------------------------

/// Result returned by [`BroadcastContext::block_author`].
///
/// Contains the blocked author's DID for event emission. The author's sender
/// key is destroyed (removed from state), so subscribers who cached that key
/// can still decrypt old messages but no new messages can be sealed by the
/// blocked author. See SCP-227 AC4 and spec section 5.14.8.
#[derive(Debug, Clone)]
pub struct AuthorBlockResult {
    /// The DID of the blocked author.
    pub author_did: String,
    /// The key epoch at the time the author was blocked. Subscribers can
    /// use this to identify which key material is now invalid.
    pub final_epoch: u64,
}

// ---------------------------------------------------------------------------
// KeyRequestDecision
// ---------------------------------------------------------------------------

/// Decision returned by [`BroadcastContext::handle_key_request`].
///
/// The author-side broadcast context evaluates whether a subscriber is
/// authorized to receive key material. The decision is one of:
///
/// - **Grant**: the subscriber is registered, not blocked, and (for gated
///   contexts) holds a valid UCAN. The caller should proceed with HPKE key
///   distribution.
/// - **Deny**: the subscriber is blocked, unregistered, or unauthorized.
///   The author sends no response (cryptographic exclusion per §5.14.8).
#[derive(Clone, PartialEq, Eq)]
pub enum KeyRequestDecision {
    /// Grant: subscriber is authorized. Includes the author's current
    /// broadcast key bytes and epoch for HPKE wrapping.
    Grant {
        /// The raw 32-byte AES-256 broadcast key material.
        /// Wrapped in [`Zeroizing`] for defense-in-depth: key material is
        /// overwritten with zeros when the decision value is dropped.
        key_bytes: Zeroizing<[u8; 32]>,
        /// The current key epoch.
        epoch: u64,
    },
    /// Deny: subscriber is blocked, unregistered, or unauthorized.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
}

impl std::fmt::Debug for KeyRequestDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grant { epoch, .. } => f
                .debug_struct("Grant")
                .field("key_bytes", &"[REDACTED]")
                .field("epoch", epoch)
                .finish(),
            Self::Deny { reason } => f.debug_struct("Deny").field("reason", reason).finish(),
        }
    }
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
/// Thread safety: not internally synchronized. The caller (`ContextManager`) is
/// responsible for serializing access.
#[derive(Debug)]
pub struct BroadcastContext {
    /// The context's unique identifier.
    context_id: String,
    /// Admission policy: open or gated.
    admission: BroadcastAdmission,
    /// Local view of known subscribers. Not a distributed index — bounded by
    /// context policy, not `HashMap` capacity.
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
    pub const fn admission(&self) -> BroadcastAdmission {
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
        match self.authors.entry(author_did.to_owned()) {
            std::collections::hash_map::Entry::Occupied(_) => Err(ContextError::PermissionDenied(
                format!("author already registered: {author_did}"),
            )),
            std::collections::hash_map::Entry::Vacant(entry) => {
                Ok(entry.insert(AuthorState::new(author_did.to_owned())))
            }
        }
    }

    /// Returns the author state for a given DID, if registered.
    #[must_use]
    pub fn get_author(&self, author_did: &str) -> Option<&AuthorState> {
        self.authors.get(author_did)
    }

    /// Returns `true` if the given DID is a registered author.
    #[must_use]
    pub fn is_author(&self, did: &str) -> bool {
        self.authors.contains_key(did)
    }

    /// Blocks an author, revoking their ability to publish.
    ///
    /// Removes the author from the `authors` map, destroying their sender key
    /// and making `can_write(author_did)` return `false`. Subsequent calls to
    /// `publish()` by this author return [`ContextError::PermissionDenied`].
    ///
    /// Subscribers who cached the author's key can still decrypt old messages,
    /// but no new messages can be sealed because the key is destroyed and the
    /// author is no longer authorized. This is the admin-facing counterpart to
    /// `block_subscriber()` (which blocks a subscriber from receiving keys).
    ///
    /// See SCP-227 AC4 and spec section 5.14.8.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MemberNotFound`] if the author DID is not
    /// registered.
    pub(crate) fn block_author(
        &mut self,
        author_did: &str,
    ) -> Result<AuthorBlockResult, ContextError> {
        let author_state = self.authors.remove(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;

        Ok(AuthorBlockResult {
            author_did: author_did.to_owned(),
            final_epoch: author_state.epoch,
        })
    }

    // -----------------------------------------------------------------------
    // Subscriber registration (spec section 5.14.3)
    // -----------------------------------------------------------------------

    /// Registers a subscriber in the broadcast context.
    ///
    /// For open broadcast contexts (`BroadcastAdmission::Open`), any DID can
    /// subscribe with `ucan = None`. For gated contexts
    /// (`BroadcastAdmission::Gated`), a valid `messagesRead` UCAN must be
    /// provided and is validated through the full 11-step UCAN validation
    /// pipeline (signature, delegation chain, expiry, revocation, nonce —
    /// see ADR-016).
    ///
    /// Returns the current epoch for each author so the subscriber knows which
    /// key epochs to request.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the context is gated and no
    ///   UCAN is provided, or the UCAN fails full validation (signature,
    ///   expiry, revocation, capability match, etc.).
    /// - [`ContextError::MembershipFailed`] if the subscriber is already
    ///   registered.
    pub fn subscribe<D, N, R, P, S>(
        &mut self,
        subscriber_did: &str,
        ucan: Option<&UcanToken>,
        timestamp: u64,
        validation_ctx: Option<&mut ValidationContext<'_, D, N, R, P, S>>,
    ) -> Result<SubscriptionResult, ContextError>
    where
        D: DidResolver,
        N: NonceTracker,
        R: RevocationChecker,
        P: ProofResolver,
        S: BuildHasher,
    {
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
                let ctx = validation_ctx.ok_or_else(|| {
                    ContextError::PermissionDenied(
                        "gated broadcast requires validation context for UCAN verification"
                            .to_owned(),
                    )
                })?;
                validate_messages_read_ucan(token, &self.context_id, ctx)?;
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

        // Spec section 5.14.3: "Event log records registration via
        // MemberJoined with role subscriber."
        let event = ContextEvent::MemberJoined {
            member_did: DID(subscriber_did.to_owned()),
            role_name: "subscriber".to_owned(),
        };

        Ok(SubscriptionResult {
            author_epochs,
            event,
        })
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

        // Remove the blocked subscriber from the local subscriber roster so
        // `can_read()` immediately reflects the block. Without this, the
        // subscriber retains read permission until the next roster sync.
        self.subscribers.remove(blocked_did);

        let new_epoch = author
            .epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("broadcast key epoch overflow".to_owned()))?;

        let new_key = generate_sender_key();
        author.epoch = new_epoch;
        author.broadcast_key = new_key.clone();
        let result_author_did = author.author_did.clone();
        let result_block_list = author.block_list.clone();

        Ok(BlockResult {
            new_key,
            new_epoch,
            author_did: result_author_did,
            block_list: result_block_list,
        })
    }

    /// Blocks a group of identity-linked DIDs from receiving future broadcast
    /// keys from the specified author (Sybil defense, BLACK-006, §9.16.6).
    ///
    /// Behaves like [`block_subscriber`](Self::block_subscriber) but atomically
    /// adds all `blocked_dids` to the author's block list and removes them from
    /// the subscriber roster in a single key rotation. This ensures that when a
    /// Sybil cluster is identified, all linked DIDs are blocked in one epoch
    /// advance rather than N separate rotations.
    ///
    /// # Errors
    ///
    /// - [`ContextError::MemberNotFound`] if the author DID is not registered.
    /// - [`ContextError::CryptoFailed`] if the epoch counter overflows.
    pub fn block_subscriber_group(
        &mut self,
        author_did: &str,
        blocked_dids: &[&str],
    ) -> Result<BlockResult, ContextError> {
        if blocked_dids.is_empty() {
            return Err(ContextError::PermissionDenied(
                "blocked_dids must not be empty".to_owned(),
            ));
        }

        let author = self.authors.get_mut(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;

        for &did in blocked_dids {
            author.block_list.insert(did.to_owned());
            self.subscribers.remove(did);
        }

        let new_epoch = author
            .epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("broadcast key epoch overflow".to_owned()))?;

        let new_key = generate_sender_key();
        author.epoch = new_epoch;
        author.broadcast_key = new_key.clone();
        let result_author_did = author.author_did.clone();
        let result_block_list = author.block_list.clone();

        Ok(BlockResult {
            new_key,
            new_epoch,
            author_did: result_author_did,
            block_list: result_block_list,
        })
    }

    /// Returns `true` if the given subscriber DID is blocked by the given
    /// author.
    #[must_use]
    pub fn is_blocked(&self, author_did: &str, subscriber_did: &str) -> bool {
        self.authors
            .get(author_did)
            .is_some_and(|a| a.block_list.contains(subscriber_did))
    }

    /// Restores a previously persisted block list for an author.
    ///
    /// Called during initialization to rehydrate block state from
    /// `ProtocolStore::load_broadcast_block_list`. If the author is not
    /// registered, returns an error. See RED-016.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MemberNotFound`] if the author DID is not
    /// registered.
    pub fn restore_block_list(
        &mut self,
        author_did: &str,
        block_list: HashSet<String>,
    ) -> Result<(), ContextError> {
        let author = self.authors.get_mut(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;
        author.block_list = block_list;
        Ok(())
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

    // -----------------------------------------------------------------------
    // Publish (capability-enforced seal)
    // -----------------------------------------------------------------------

    /// Encrypts a payload as a broadcast message after verifying that the
    /// caller holds `messagesWrite` (is a registered author).
    ///
    /// This is the capability-enforced publish path: it combines the
    /// `can_write` check with [`seal_broadcast`] in a single operation so
    /// callers cannot accidentally bypass the authorization check.
    ///
    /// # Arguments
    ///
    /// * `author_did` -- The DID of the author publishing the message.
    /// * `payload` -- The plaintext content to encrypt.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if `author_did` is not a
    ///   registered author (does not hold `messagesWrite`).
    /// - [`ContextError::CryptoFailed`] if the AES-256-GCM seal operation
    ///   fails.
    ///
    /// [`seal_broadcast`]: crate::crypto::sender_keys::seal_broadcast
    pub fn publish(
        &self,
        author_did: &str,
        payload: &[u8],
    ) -> Result<BroadcastEnvelope, ContextError> {
        if !self.can_write(author_did) {
            return Err(ContextError::PermissionDenied(format!(
                "{author_did} is not an author (messagesWrite required)"
            )));
        }

        let author = self.authors.get(author_did).ok_or_else(|| {
            ContextError::MemberNotFound(format!("author not found: {author_did}"))
        })?;

        let broadcast_key = BroadcastKey::from_parts(
            author.broadcast_key.clone(),
            author.epoch,
            author.author_did.clone(),
        );

        seal_broadcast(&broadcast_key, payload)
            .map_err(|e| ContextError::CryptoFailed(format!("seal_broadcast failed: {e}")))
    }

    // -----------------------------------------------------------------------
    // Unsubscribe (spec section 5.14.7)
    // -----------------------------------------------------------------------

    /// Removes a subscriber from the broadcast context.
    ///
    /// Produces an [`UnsubscribeResult`] containing the subscriber DID for
    /// `MemberLeft` event production. When `rotate_keys` is `true`, all
    /// authors rotate their broadcast keys to exclude the departing
    /// subscriber (equivalent to blocking, ensuring forward secrecy of
    /// future content).
    ///
    /// # Errors
    ///
    /// - [`ContextError::MemberNotFound`] if the subscriber DID is not
    ///   registered.
    /// - [`ContextError::CryptoFailed`] if key rotation fails (epoch
    ///   overflow).
    pub fn unsubscribe(
        &mut self,
        subscriber_did: &str,
        rotate_keys: bool,
    ) -> Result<UnsubscribeResult, ContextError> {
        if !self.subscribers.contains_key(subscriber_did) {
            return Err(ContextError::MemberNotFound(format!(
                "subscriber not found: {subscriber_did}"
            )));
        }

        self.subscribers.remove(subscriber_did);

        let mut key_rotations = Vec::new();

        if rotate_keys {
            // Collect author DIDs first to avoid borrowing conflict.
            let author_dids: Vec<String> = self.authors.keys().cloned().collect();

            for author_did in &author_dids {
                // Safety: `author_did` was just collected from `self.authors.keys()`,
                // so the entry is guaranteed to exist.
                if let Some(author) = self.authors.get_mut(author_did.as_str()) {
                    let new_epoch = author.epoch.checked_add(1).ok_or_else(|| {
                        ContextError::CryptoFailed("broadcast key epoch overflow".to_owned())
                    })?;

                    let new_key = generate_sender_key();
                    author.epoch = new_epoch;
                    author.broadcast_key = new_key.clone();

                    key_rotations.push(BlockResult {
                        new_key,
                        new_epoch,
                        author_did: author_did.clone(),
                        block_list: author.block_list.clone(),
                    });
                }
            }
        }

        Ok(UnsubscribeResult {
            subscriber_did: subscriber_did.to_owned(),
            key_rotations,
        })
    }

    // -----------------------------------------------------------------------
    // Key request handling (spec sections 5.14.2, 5.14.4, 5.14.8)
    // -----------------------------------------------------------------------

    /// Evaluates whether a subscriber's broadcast key request should be
    /// granted or denied.
    ///
    /// This is the author-side decision function for the pull-based key
    /// distribution protocol (§9.16.2). The author checks:
    ///
    /// 1. The requester is a registered subscriber (or author).
    /// 2. The requester is not on the author's block list.
    /// 3. For gated contexts: the requester presented a valid UCAN at
    ///    registration time (recorded in [`SubscriberRecord::has_ucan`]).
    ///
    /// If all checks pass, returns [`KeyRequestDecision::Grant`] with the
    /// author's current broadcast key material and epoch. The caller is
    /// responsible for HPKE-wrapping the key material to the requester's
    /// wrapping public key (using `crypto::sender_keys::key_protocol`).
    ///
    /// If any check fails, returns [`KeyRequestDecision::Deny`]. Per
    /// §5.14.8, the author sends **no response** to denied requests --
    /// the requester times out and cannot decrypt future content.
    #[must_use]
    pub fn handle_key_request(&self, author_did: &str, requester_did: &str) -> KeyRequestDecision {
        // All deny paths use a uniform reason string so denial causes
        // (blocked, unsubscribed, gated, unknown author) are indistinguishable
        // in diagnostic output. This prevents block list status leakage
        // through logging. See §5.14.8.
        const DENY_REASON: &str = "key request denied";

        // Author must exist.
        let Some(author) = self.authors.get(author_did) else {
            return KeyRequestDecision::Deny {
                reason: DENY_REASON.to_owned(),
            };
        };

        // Requester must not be blocked.
        if author.block_list.contains(requester_did) {
            return KeyRequestDecision::Deny {
                reason: DENY_REASON.to_owned(),
            };
        }

        // Requester must be a registered subscriber or author.
        if !self.subscribers.contains_key(requester_did)
            && !self.authors.contains_key(requester_did)
        {
            return KeyRequestDecision::Deny {
                reason: DENY_REASON.to_owned(),
            };
        }

        // For gated contexts, the subscriber must have presented a UCAN at
        // registration time. Authors requesting keys from other authors are
        // always allowed (they hold messagesWrite which implies messagesRead).
        if self.admission == BroadcastAdmission::Gated
            && let Some(record) = self.subscribers.get(requester_did)
            && !record.has_ucan
        {
            return KeyRequestDecision::Deny {
                reason: DENY_REASON.to_owned(),
            };
        }

        KeyRequestDecision::Grant {
            key_bytes: Zeroizing::new(*author.broadcast_key.as_bytes()),
            epoch: author.epoch,
        }
    }

    /// Returns an iterator over all subscriber records.
    pub fn subscribers(&self) -> impl Iterator<Item = &SubscriberRecord> {
        self.subscribers.values()
    }

    /// Returns an iterator over all author DIDs.
    pub fn author_dids(&self) -> impl Iterator<Item = &String> {
        self.authors.keys()
    }

    /// Creates a serializable snapshot of the broadcast context state.
    ///
    /// Captures authors (with key material and epochs), subscribers, and
    /// admission policy. Used by `ProtocolStore::store_broadcast_state` to
    /// persist broadcast context state across process restarts.
    ///
    /// See spec section 5.14 and RED-016.
    #[must_use]
    pub fn to_snapshot(&self) -> BroadcastContextSnapshot {
        let authors = self
            .authors
            .iter()
            .map(|(did, state)| {
                (
                    did.clone(),
                    AuthorStateSnapshot {
                        author_did: state.author_did.clone(),
                        broadcast_key: state.broadcast_key.clone(),
                        epoch: state.epoch,
                        block_list: state.block_list.clone(),
                    },
                )
            })
            .collect();

        BroadcastContextSnapshot {
            context_id: self.context_id.clone(),
            admission: self.admission,
            subscribers: self.subscribers.clone(),
            authors,
        }
    }

    /// Reconstructs a `BroadcastContext` from a persisted snapshot.
    ///
    /// Restores authors (with key material, epochs, and block lists),
    /// subscribers, and admission policy. Called during context restoration
    /// after a process restart.
    #[must_use]
    pub fn from_snapshot(snapshot: BroadcastContextSnapshot) -> Self {
        let authors = snapshot
            .authors
            .into_iter()
            .map(|(did, snap)| {
                (
                    did,
                    AuthorState {
                        author_did: snap.author_did,
                        broadcast_key: snap.broadcast_key,
                        epoch: snap.epoch,
                        block_list: snap.block_list,
                    },
                )
            })
            .collect();

        Self {
            context_id: snapshot.context_id,
            admission: snapshot.admission,
            subscribers: snapshot.subscribers,
            authors,
        }
    }
}

// ---------------------------------------------------------------------------
// BroadcastContextSnapshot -- serializable persistence format
// ---------------------------------------------------------------------------

/// Serializable snapshot of a [`BroadcastContext`] for persistence.
///
/// Captures the full broadcast context state: admission policy, subscriber
/// roster, and per-author key state (including key material, epochs, and
/// block lists). Stored via `ProtocolStore::store_broadcast_state` under the
/// key `context/{context_id}/broadcast_state`.
///
/// This is separate from `BroadcastContext` because `AuthorState` contains
/// `SenderKey` which has `Zeroize`/`ZeroizeOnDrop` derives that make adding
/// `Serialize`/`Deserialize` directly to the live struct complex. The
/// snapshot acts as a clean serialization boundary.
///
/// See spec section 5.14 and §17.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastContextSnapshot {
    /// The context's unique identifier.
    pub context_id: String,
    /// Admission policy: open or gated.
    pub admission: BroadcastAdmission,
    /// Subscriber roster, keyed by subscriber DID.
    pub subscribers: HashMap<String, SubscriberRecord>,
    /// Per-author broadcast key state, keyed by author DID.
    pub authors: HashMap<String, AuthorStateSnapshot>,
}

/// Serializable snapshot of per-author broadcast key state.
///
/// Mirrors [`AuthorState`] but with `Serialize`/`Deserialize` derives for
/// persistence. Includes the raw key material, which is encrypted at rest
/// by the storage backend (`SQLCipher`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorStateSnapshot {
    /// The author's DID.
    pub author_did: String,
    /// The current AES-256-GCM broadcast key.
    pub broadcast_key: SenderKey,
    /// The current key epoch (monotonically increasing).
    pub epoch: u64,
    /// DIDs blocked by this author.
    pub block_list: HashSet<String>,
}

// ---------------------------------------------------------------------------
// UCAN validation helper
// ---------------------------------------------------------------------------

/// Validates that a UCAN token grants `messagesRead` for the given context
/// using the full 11-step UCAN validation pipeline from ADR-016.
///
/// Delegates to [`validate_ucan`] which performs: (1) JWT parse + header
/// validation, (2) Ed25519 signature verification, (3) delegation chain
/// integrity, (4) root issuer = context creator, (5) audience = presenting
/// subscriber, (6) capability match for `messages:read`, (7) attenuation
/// narrowing, (8) ceiling compliance, (9) nonce freshness + uniqueness,
/// (10) revocation check, (11) expiry + not-before bounds.
///
/// This replaces the previous stub that only checked `aud` and `att` strings
/// without cryptographic verification (RED-103).
fn validate_messages_read_ucan<D, N, R, P, S>(
    token: &UcanToken,
    context_id: &str,
    ctx: &mut ValidationContext<'_, D, N, R, P, S>,
) -> Result<(), ContextError>
where
    D: DidResolver,
    N: NonceTracker,
    R: RevocationChecker,
    P: ProofResolver,
    S: BuildHasher,
{
    let required_capability = CapabilityUri::new(context_id, "messages", "read");
    validate_ucan(token, &required_capability, ctx)
        .map_err(|e| ContextError::PermissionDenied(format!("UCAN validation failed: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto::sender_keys::{
        SenderKey, decrypt_sender_layer, encrypt_sender_layer, open_broadcast,
    };
    use crate::crypto::ucan::validate::{
        DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
        InMemoryProofResolver, InMemoryRevocationChecker,
    };
    use crate::crypto::ucan::{Attenuation, UcanHeader, UcanPayload};
    use std::collections::HashMap as StdHashMap;
    use std::hash::RandomState;

    /// Helper to call subscribe on open contexts without a validation context.
    /// Specifies the generic types so the compiler can infer them.
    fn subscribe_open(
        ctx: &mut BroadcastContext,
        subscriber_did: &str,
        ucan: Option<&UcanToken>,
        timestamp: u64,
    ) -> Result<SubscriptionResult, ContextError> {
        ctx.subscribe::<
            InMemoryDidResolver,
            InMemoryNonceTracker,
            InMemoryRevocationChecker,
            InMemoryProofResolver,
            RandomState,
        >(subscriber_did, ucan, timestamp, None)
    }

    /// Ed25519 keypair for test UCAN signing.
    fn test_keypair() -> ed25519_dalek::SigningKey {
        // Deterministic key for reproducible tests.
        let seed = [42u8; 32];
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    /// Creates a properly signed UCAN token for testing gated subscription.
    fn make_signed_ucan(
        context_id: &str,
        issuer_did: &str,
        subscriber_did: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> UcanToken {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::Signer;

        let now_secs = crate::time::now_secs().expect("clock unavailable in test");
        let now_millis = crate::time::now_millis().expect("clock unavailable in test");

        let header = UcanHeader::new();
        let payload = UcanPayload {
            iss: issuer_did.to_owned(),
            aud: subscriber_did.to_owned(),
            exp: now_secs + 3600,     // 1 hour from now
            nbf: Some(now_secs - 60), // valid from 1 minute ago
            nnc: format!("{now_millis}-aabbccdd11223344aabbccdd11223344"),
            att: vec![Attenuation {
                with: format!("scp:ctx:{context_id}/messages:read"),
                can: "read".to_owned(),
            }],
            prf: vec![],
            fct: None,
        };

        let header_json = serde_json::to_vec(&header).unwrap();
        let payload_json = serde_json::to_vec(&payload).unwrap();

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes().to_vec();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

        let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

        UcanToken {
            header,
            payload,
            signature: sig_bytes,
            encoded,
        }
    }

    /// Setup all the validation dependencies for a gated subscription test.
    struct GatedTestSetup {
        signing_key: ed25519_dalek::SigningKey,
        issuer_did: String,
        did_resolver: InMemoryDidResolver,
        nonce_tracker: InMemoryNonceTracker,
        revocation_checker: InMemoryRevocationChecker,
        proof_resolver: InMemoryProofResolver,
        ceiling: HashSet<String>,
    }

    impl GatedTestSetup {
        fn new() -> Self {
            let signing_key = test_keypair();
            let verifying_key = signing_key.verifying_key();
            let issuer_did = "did:example:admin".to_owned();

            let mut keys = StdHashMap::new();
            keys.insert(issuer_did.clone(), verifying_key.to_bytes());

            let mut ceiling = HashSet::new();
            ceiling.insert("messages:read".to_owned());
            ceiling.insert("messages:write".to_owned());

            Self {
                signing_key,
                issuer_did,
                did_resolver: InMemoryDidResolver {
                    keys,
                    kid_keys: std::collections::HashMap::new(),
                },
                nonce_tracker: InMemoryNonceTracker::new(),
                revocation_checker: InMemoryRevocationChecker::new(),
                proof_resolver: InMemoryProofResolver::new(),
                ceiling,
            }
        }

        fn make_ucan(&self, context_id: &str, subscriber_did: &str) -> UcanToken {
            make_signed_ucan(
                context_id,
                &self.issuer_did,
                subscriber_did,
                &self.signing_key,
            )
        }
    }

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

        let result = subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert_eq!(result.author_epochs["did:example:alice"], 0);
        assert!(ctx.is_subscriber("did:example:bob"));
        assert_eq!(ctx.subscriber_count(), 1);
    }

    #[test]
    fn subscribe_open_with_ucan_also_succeeds() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let setup = GatedTestSetup::new();
        let ucan = setup.make_ucan("ctx-broadcast-1", "did:example:bob");

        // Open context accepts UCAN but doesn't validate it.
        let result = subscribe_open(&mut ctx, "did:example:bob", Some(&ucan), 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert!(ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_returns_all_author_epochs() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();

        let result = subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        assert_eq!(result.author_epochs.len(), 2);
        assert_eq!(result.author_epochs["did:example:alice"], 0);
        assert_eq!(result.author_epochs["did:example:carol"], 0);
    }

    #[test]
    fn subscribe_rejects_duplicate() {
        let mut ctx = make_open_ctx();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let result = subscribe_open(&mut ctx, "did:example:bob", None, 2000);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Gated broadcast subscription (AC 3)
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_gated_requires_ucan() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();

        // Gated subscription with no UCAN and no validation context.
        let result = subscribe_open(&mut ctx, "did:example:bob", None, 1000);
        assert!(result.is_err());
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_with_valid_ucan_succeeds() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();
        let ucan = setup.make_ucan("ctx-gated-1", "did:example:bob");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx
            .subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx))
            .unwrap();

        assert_eq!(result.author_epochs.len(), 1);
        assert!(ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_rejects_wrong_context_ucan() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();
        // Token for wrong context — capability URI won't match.
        let ucan = setup.make_ucan("wrong-context", "did:example:bob");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx));
        assert!(result.is_err());
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_rejects_wrong_capability() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();

        // Manually construct a token with messages:write instead of messages:read.
        let ucan = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use ed25519_dalek::Signer;

            let now_secs = crate::time::now_secs().expect("clock unavailable in test");
            let now_millis = crate::time::now_millis().expect("clock unavailable in test");

            let header = UcanHeader::new();
            let payload = UcanPayload {
                iss: setup.issuer_did.clone(),
                aud: "did:example:bob".to_owned(),
                exp: now_secs + 3600,
                nbf: Some(now_secs - 60),
                nnc: format!("{now_millis}-bbccddee11223344bbccddee11223344"),
                att: vec![Attenuation {
                    with: "scp:ctx:ctx-gated-1/messages:write".to_owned(),
                    can: "write".to_owned(),
                }],
                prf: vec![],
                fct: None,
            };

            let header_json = serde_json::to_vec(&header).unwrap();
            let payload_json = serde_json::to_vec(&payload).unwrap();
            let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signature = setup.signing_key.sign(signing_input.as_bytes());
            let sig_bytes = signature.to_bytes().to_vec();
            let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
            let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

            UcanToken {
                header,
                payload,
                signature: sig_bytes,
                encoded,
            }
        };

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx));
        assert!(result.is_err());
    }

    #[test]
    fn subscribe_gated_rejects_aud_mismatch() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();
        // Token audience is "did:example:carol" but subscriber is "did:example:bob".
        let ucan = setup.make_ucan("ctx-gated-1", "did:example:carol");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx));
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
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

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
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

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
    // Author blocking (AC 4 — block_author)
    // -----------------------------------------------------------------------

    #[test]
    fn block_author_removes_from_authors_map() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:bob").unwrap();

        assert!(ctx.is_author("did:example:bob"));
        assert!(ctx.can_write("did:example:bob"));

        let result = ctx.block_author("did:example:bob").unwrap();

        assert_eq!(result.author_did, "did:example:bob");
        assert_eq!(result.final_epoch, 0);
        assert!(!ctx.is_author("did:example:bob"));
        assert!(!ctx.can_write("did:example:bob"));
        // Alice is unaffected.
        assert!(ctx.is_author("did:example:alice"));
        assert!(ctx.can_write("did:example:alice"));
    }

    #[test]
    fn block_author_returns_final_epoch() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

        // Advance Alice's epoch by blocking a subscriber.
        ctx.block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();
        assert_eq!(ctx.get_author("did:example:alice").unwrap().epoch, 1);

        let result = ctx.block_author("did:example:alice").unwrap();
        assert_eq!(result.final_epoch, 1);
    }

    #[test]
    fn block_author_unknown_returns_error() {
        let mut ctx = make_open_ctx();
        let result = ctx.block_author("did:example:unknown");
        assert!(result.is_err());
    }

    /// Blocking the only author leaves the context in a valid but authorless
    /// state: no authors remain, subscribers are still registered, and
    /// `can_write` returns `false` for the blocked author.
    #[test]
    fn block_last_author_leaves_valid_authorless_state() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:sole-author").unwrap();
        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();

        // Verify pre-condition: one author, one subscriber.
        assert_eq!(ctx.author_dids().count(), 1);
        assert_eq!(ctx.subscriber_count(), 1);
        assert!(ctx.is_author("did:example:sole-author"));
        assert!(ctx.can_write("did:example:sole-author"));

        // Block the only author.
        let result = ctx.block_author("did:example:sole-author").unwrap();
        assert_eq!(result.author_did, "did:example:sole-author");
        assert_eq!(result.final_epoch, 0);

        // Context is now authorless.
        assert_eq!(ctx.author_dids().count(), 0);
        assert!(!ctx.is_author("did:example:sole-author"));
        assert!(!ctx.can_write("did:example:sole-author"));

        // Subscriber is still registered and can read.
        assert_eq!(ctx.subscriber_count(), 1);
        assert!(ctx.can_read("did:example:sub1"));

        // Publishing fails (no author).
        let publish_result = ctx.publish("did:example:sole-author", b"after block");
        assert!(publish_result.is_err());

        // Key request for the blocked author returns Deny.
        assert!(matches!(
            ctx.handle_key_request("did:example:sole-author", "did:example:sub1"),
            KeyRequestDecision::Deny { .. }
        ));
    }

    #[test]
    fn block_author_publish_returns_permission_denied() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();

        // Alice can publish before block.
        assert!(ctx.publish("did:example:alice", b"hello").is_ok());

        ctx.block_author("did:example:alice").unwrap();

        // Alice cannot publish after block.
        let result = ctx.publish("did:example:alice", b"hello again");
        assert!(result.is_err());
    }

    #[test]
    fn block_author_key_request_returns_deny() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();

        // Key request succeeds before block.
        assert!(matches!(
            ctx.handle_key_request("did:example:alice", "did:example:sub1"),
            KeyRequestDecision::Grant { .. }
        ));

        ctx.block_author("did:example:alice").unwrap();

        // Key request fails after block (author not found).
        assert!(matches!(
            ctx.handle_key_request("did:example:alice", "did:example:sub1"),
            KeyRequestDecision::Deny { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Integration test: blocked author's messages undecryptable (AC 7)
    // -----------------------------------------------------------------------

    #[test]
    fn integration_blocked_author_cannot_publish_and_subscribers_unaffected() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:bob").unwrap();
        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();

        // Both authors can publish.
        let alice_author = ctx.get_author("did:example:alice").unwrap();
        let alice_key = alice_author.broadcast_key.clone();
        let bob_author = ctx.get_author("did:example:bob").unwrap();
        let bob_key = bob_author.broadcast_key.clone();

        let alice_msg = b"Alice's message";
        let alice_ct = encrypt_sender_layer(&alice_key, alice_msg).unwrap();
        let bob_msg = b"Bob's message";
        let bob_ct = encrypt_sender_layer(&bob_key, bob_msg).unwrap();

        // Both subscribers can decrypt both authors.
        assert_eq!(
            decrypt_sender_layer(&alice_key, &alice_ct).unwrap(),
            alice_msg
        );
        assert_eq!(decrypt_sender_layer(&bob_key, &bob_ct).unwrap(), bob_msg);

        // Block Bob (admin action).
        ctx.block_author("did:example:bob").unwrap();

        // Alice can still publish (unaffected).
        let alice_msg2 = b"Alice's second message";
        let _alice_envelope = ctx.publish("did:example:alice", alice_msg2).unwrap();

        // Subscribers can still decrypt Alice's messages via key request.
        let alice_decision = ctx.handle_key_request("did:example:alice", "did:example:sub1");
        assert!(matches!(alice_decision, KeyRequestDecision::Grant { .. }));

        // Bob cannot publish (PermissionDenied).
        let bob_result = ctx.publish("did:example:bob", b"Bob tries to publish");
        assert!(bob_result.is_err());

        // Key request for Bob returns Deny (author not found).
        let bob_decision = ctx.handle_key_request("did:example:bob", "did:example:sub1");
        assert!(matches!(bob_decision, KeyRequestDecision::Deny { .. }));

        // Subscribers cannot get Bob's key at any epoch — his key is destroyed.
        // Old messages encrypted with Bob's key are still decryptable with the
        // cached key, but no new messages can be produced.
        assert_eq!(decrypt_sender_layer(&bob_key, &bob_ct).unwrap(), bob_msg);
    }

    // -----------------------------------------------------------------------
    // Capability checks (AC 5)
    // -----------------------------------------------------------------------

    #[test]
    fn can_write_only_for_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        assert!(ctx.can_write("did:example:alice"));
        assert!(!ctx.can_write("did:example:bob"));
        assert!(!ctx.can_write("did:example:unknown"));
    }

    #[test]
    fn can_read_for_subscribers_and_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

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

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();
        subscribe_open(&mut ctx, "did:example:sub3", None, 1002).unwrap();

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

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();

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

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();

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

        let mut setup = GatedTestSetup::new();
        let ucan = setup.make_ucan("ctx-gated-1", "did:example:sub1");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:sub1",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };
        ctx.subscribe("did:example:sub1", Some(&ucan), 1000, Some(&mut val_ctx))
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

    // -----------------------------------------------------------------------
    // Wildcard UCAN rejection (RED-012)
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_gated_accepts_wildcard_ucan_with_full_validation() {
        // With full UCAN validation (signature, chain, expiry, revocation),
        // wildcard capabilities from legitimate issuers are safe to accept.
        // The original stub rejected wildcards because it lacked cryptographic
        // verification — without that, any wildcard token would grant access
        // to all contexts. Now that full validation is in place (RED-103),
        // wildcard grants from the context creator are legitimate.
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();

        let ucan = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use ed25519_dalek::Signer;

            let now_secs = crate::time::now_secs().expect("clock unavailable in test");
            let now_millis = crate::time::now_millis().expect("clock unavailable in test");

            let header = UcanHeader::new();
            let payload = UcanPayload {
                iss: setup.issuer_did.clone(),
                aud: "did:example:bob".to_owned(),
                exp: now_secs + 3600,
                nbf: Some(now_secs - 60),
                nnc: format!("{now_millis}-ccddee1122334455ccddee1122334455"),
                att: vec![Attenuation {
                    with: "scp:ctx:*/messages:read".to_owned(),
                    can: "read".to_owned(),
                }],
                prf: vec![],
                fct: None,
            };

            let header_json = serde_json::to_vec(&header).unwrap();
            let payload_json = serde_json::to_vec(&payload).unwrap();
            let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            let signing_input = format!("{header_b64}.{payload_b64}");
            let signature = setup.signing_key.sign(signing_input.as_bytes());
            let sig_bytes = signature.to_bytes().to_vec();
            let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
            let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

            UcanToken {
                header,
                payload,
                signature: sig_bytes,
                encoded,
            }
        };

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        // With full validation, a properly signed wildcard UCAN from the
        // context creator is accepted.
        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx));
        assert!(
            result.is_ok(),
            "fully validated wildcard UCAN should be accepted"
        );
        assert!(ctx.is_subscriber("did:example:bob"));
    }

    #[test]
    fn subscribe_gated_rejects_unsigned_wildcard_ucan() {
        // Verify that a wildcard UCAN with an invalid signature is rejected.
        // This is the actual security property: the old stub could not verify
        // signatures, so it rejected wildcards entirely. Now we verify
        // signatures, and an invalid signature correctly fails.
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();

        let ucan = {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;

            let now_secs = crate::time::now_secs().expect("clock unavailable in test");
            let now_millis = crate::time::now_millis().expect("clock unavailable in test");

            let header = UcanHeader::new();
            let payload = UcanPayload {
                iss: setup.issuer_did.clone(),
                aud: "did:example:bob".to_owned(),
                exp: now_secs + 3600,
                nbf: Some(now_secs - 60),
                nnc: format!("{now_millis}-ddee112233445566ddee112233445566"),
                att: vec![Attenuation {
                    with: "scp:ctx:*/messages:read".to_owned(),
                    can: "read".to_owned(),
                }],
                prf: vec![],
                fct: None,
            };

            let header_json = serde_json::to_vec(&header).unwrap();
            let payload_json = serde_json::to_vec(&payload).unwrap();
            let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
            // Invalid signature (all zeros)
            let sig_bytes = vec![0u8; 64];
            let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
            let encoded = format!("{header_b64}.{payload_b64}.{sig_b64}");

            UcanToken {
                header,
                payload,
                signature: sig_bytes,
                encoded,
            }
        };

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx.subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx));
        assert!(result.is_err(), "unsigned wildcard UCAN must be rejected");
        assert!(!ctx.is_subscriber("did:example:bob"));
    }

    // -----------------------------------------------------------------------
    // Block list restore (RED-016)
    // -----------------------------------------------------------------------

    #[test]
    fn restore_block_list_rehydrates_author_state() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

        let mut stored_block_list = HashSet::new();
        stored_block_list.insert("did:example:dave".to_owned());
        stored_block_list.insert("did:example:eve".to_owned());

        ctx.restore_block_list("did:example:alice", stored_block_list)
            .unwrap();

        assert!(ctx.is_blocked("did:example:alice", "did:example:dave"));
        assert!(ctx.is_blocked("did:example:alice", "did:example:eve"));
        assert!(!ctx.is_blocked("did:example:alice", "did:example:bob"));
    }

    #[test]
    fn restore_block_list_unknown_author_returns_error() {
        let mut ctx = make_open_ctx();
        let result = ctx.restore_block_list("did:example:unknown", HashSet::new());
        assert!(result.is_err());
    }

    #[test]
    fn block_result_includes_author_did_and_block_list() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

        let result = ctx
            .block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();

        assert_eq!(result.author_did, "did:example:alice");
        assert!(result.block_list.contains("did:example:dave"));
        assert_eq!(result.block_list.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Block removes subscriber from roster (RED-108)
    // -----------------------------------------------------------------------

    #[test]
    fn block_subscriber_removes_from_subscribers() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();

        assert!(ctx.is_subscriber("did:example:dave"));
        assert!(ctx.can_read("did:example:dave"));

        ctx.block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();

        // After blocking, subscriber should be removed from the roster and
        // can_read should return false (unless they are also an author).
        assert!(!ctx.is_subscriber("did:example:dave"));
        assert!(
            !ctx.can_read("did:example:dave"),
            "blocked subscriber must lose read access (RED-108)"
        );
    }

    // -----------------------------------------------------------------------
    // block_subscriber_group — Sybil defense (BLACK-006)
    // -----------------------------------------------------------------------

    #[test]
    fn block_subscriber_group_blocks_all_linked_dids() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:dave-alt", None, 1001).unwrap();
        subscribe_open(&mut ctx, "did:example:dave-bot", None, 1002).unwrap();

        let result = ctx
            .block_subscriber_group(
                "did:example:alice",
                &[
                    "did:example:dave",
                    "did:example:dave-alt",
                    "did:example:dave-bot",
                ],
            )
            .unwrap();

        // All three should be blocked.
        assert!(ctx.is_blocked("did:example:alice", "did:example:dave"));
        assert!(ctx.is_blocked("did:example:alice", "did:example:dave-alt"));
        assert!(ctx.is_blocked("did:example:alice", "did:example:dave-bot"));

        // All three should be removed from subscribers.
        assert!(!ctx.is_subscriber("did:example:dave"));
        assert!(!ctx.is_subscriber("did:example:dave-alt"));
        assert!(!ctx.is_subscriber("did:example:dave-bot"));

        // Single key rotation (epoch incremented once, not three times).
        assert_eq!(result.new_epoch, 1);
        assert_eq!(result.block_list.len(), 3);
    }

    #[test]
    fn block_subscriber_group_empty_returns_error() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let result = ctx.block_subscriber_group("did:example:alice", &[]);
        assert!(result.is_err(), "empty blocked_dids should return an error");
    }

    #[test]
    fn block_subscriber_group_unknown_author_returns_error() {
        let mut ctx = make_open_ctx();
        let result = ctx.block_subscriber_group("did:example:unknown", &["did:example:dave"]);
        assert!(result.is_err());
    }

    #[test]
    fn block_subscriber_group_single_epoch_increment() {
        // Verify that blocking a group of 3 DIDs only increments the epoch
        // once, unlike calling block_subscriber 3 times.
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let result = ctx
            .block_subscriber_group(
                "did:example:alice",
                &["did:example:d1", "did:example:d2", "did:example:d3"],
            )
            .unwrap();

        assert_eq!(
            result.new_epoch, 1,
            "single group block = single epoch bump"
        );
    }

    // -----------------------------------------------------------------------
    // MemberJoined event emission (issue #143, spec section 5.14.3)
    // -----------------------------------------------------------------------

    #[test]
    fn subscribe_emits_member_joined_event_with_subscriber_role() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let result = subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        assert_eq!(
            result.event,
            ContextEvent::MemberJoined {
                member_did: DID("did:example:bob".to_owned()),
                role_name: "subscriber".to_owned(),
            }
        );
    }

    #[test]
    fn subscribe_multiple_each_emits_member_joined_event() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let r1 = subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        let r2 = subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();
        let r3 = subscribe_open(&mut ctx, "did:example:sub3", None, 1002).unwrap();

        // Each subscription produces its own MemberJoined event with the
        // correct subscriber DID.
        assert_eq!(
            r1.event,
            ContextEvent::MemberJoined {
                member_did: DID("did:example:sub1".to_owned()),
                role_name: "subscriber".to_owned(),
            }
        );
        assert_eq!(
            r2.event,
            ContextEvent::MemberJoined {
                member_did: DID("did:example:sub2".to_owned()),
                role_name: "subscriber".to_owned(),
            }
        );
        assert_eq!(
            r3.event,
            ContextEvent::MemberJoined {
                member_did: DID("did:example:sub3".to_owned()),
                role_name: "subscriber".to_owned(),
            }
        );
    }

    #[test]
    fn subscribe_gated_emits_member_joined_event() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();
        let mut setup = GatedTestSetup::new();
        let ucan = setup.make_ucan("ctx-gated-1", "did:example:bob");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:bob",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        let result = ctx
            .subscribe("did:example:bob", Some(&ucan), 1000, Some(&mut val_ctx))
            .unwrap();

        assert_eq!(
            result.event,
            ContextEvent::MemberJoined {
                member_did: DID("did:example:bob".to_owned()),
                role_name: "subscriber".to_owned(),
            }
        );
    }

    // =======================================================================
    // Unsubscribe tests (§5.14.7, #101 AC: unsubscribe produces MemberLeft)
    // =======================================================================

    #[test]
    fn unsubscribe_removes_subscriber() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();
        assert!(ctx.is_subscriber("did:example:bob"));
        assert_eq!(ctx.subscriber_count(), 1);

        let result = ctx.unsubscribe("did:example:bob", false).unwrap();

        assert_eq!(result.subscriber_did, "did:example:bob");
        assert!(!ctx.is_subscriber("did:example:bob"));
        assert_eq!(ctx.subscriber_count(), 0);
        // No key rotations when rotate_keys is false.
        assert!(result.key_rotations.is_empty());
    }

    #[test]
    fn unsubscribe_unknown_subscriber_returns_error() {
        let mut ctx = make_open_ctx();
        let result = ctx.unsubscribe("did:example:unknown", false);
        assert!(result.is_err());
    }

    #[test]
    fn unsubscribe_revokes_read_access() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        assert!(ctx.can_read("did:example:bob"));
        ctx.unsubscribe("did:example:bob", false).unwrap();
        assert!(
            !ctx.can_read("did:example:bob"),
            "unsubscribed member must lose read access"
        );
    }

    #[test]
    fn unsubscribe_with_key_rotation_rotates_all_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let alice_epoch_before = ctx.get_author("did:example:alice").unwrap().epoch;
        let carol_epoch_before = ctx.get_author("did:example:carol").unwrap().epoch;

        let result = ctx.unsubscribe("did:example:bob", true).unwrap();

        assert_eq!(result.key_rotations.len(), 2);
        assert_eq!(
            ctx.get_author("did:example:alice").unwrap().epoch,
            alice_epoch_before + 1
        );
        assert_eq!(
            ctx.get_author("did:example:carol").unwrap().epoch,
            carol_epoch_before + 1
        );
    }

    #[test]
    fn unsubscribe_without_key_rotation_preserves_epochs() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let epoch_before = ctx.get_author("did:example:alice").unwrap().epoch;
        ctx.unsubscribe("did:example:bob", false).unwrap();
        assert_eq!(
            ctx.get_author("did:example:alice").unwrap().epoch,
            epoch_before,
            "epoch must not change when rotate_keys is false"
        );
    }

    #[test]
    fn unsubscribe_result_contains_subscriber_did_for_member_left_event() {
        let mut ctx = make_open_ctx();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let result = ctx.unsubscribe("did:example:bob", false).unwrap();
        // Caller uses this to emit a MemberLeft { member_did: result.subscriber_did }
        assert_eq!(result.subscriber_did, "did:example:bob");
    }

    #[test]
    fn subscribe_result_contains_author_epochs_for_key_requests() {
        // After subscription, the subscriber knows each author's current epoch
        // and can immediately request broadcast keys via the pull-based protocol.
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();

        // Block a third party to advance Alice's epoch.
        subscribe_open(&mut ctx, "did:example:eve", None, 500).unwrap();
        ctx.block_subscriber("did:example:alice", "did:example:eve")
            .unwrap();
        // Alice is now at epoch 1, Carol still at epoch 0.

        let result = subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();
        assert_eq!(result.author_epochs["did:example:alice"], 1);
        assert_eq!(result.author_epochs["did:example:carol"], 0);
    }

    // =======================================================================
    // Key request handling tests (§5.14.2, §5.14.4, §5.14.8, #101 AC)
    // =======================================================================

    #[test]
    fn handle_key_request_grants_registered_subscriber() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let decision = ctx.handle_key_request("did:example:alice", "did:example:bob");
        match decision {
            KeyRequestDecision::Grant { key_bytes, epoch } => {
                assert_eq!(epoch, 0);
                assert_eq!(
                    *key_bytes,
                    *ctx.get_author("did:example:alice")
                        .unwrap()
                        .broadcast_key
                        .as_bytes()
                );
            }
            KeyRequestDecision::Deny { reason } => {
                panic!("expected Grant, got Deny: {reason}");
            }
        }
    }

    #[test]
    fn handle_key_request_denies_blocked_subscriber() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:dave", None, 1000).unwrap();
        ctx.block_subscriber("did:example:alice", "did:example:dave")
            .unwrap();

        let decision = ctx.handle_key_request("did:example:alice", "did:example:dave");
        assert!(
            matches!(decision, KeyRequestDecision::Deny { .. }),
            "blocked subscriber must be denied"
        );
    }

    #[test]
    fn handle_key_request_denies_unregistered_did() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let decision = ctx.handle_key_request("did:example:alice", "did:example:unknown");
        assert!(
            matches!(decision, KeyRequestDecision::Deny { .. }),
            "unregistered DID must be denied"
        );
    }

    #[test]
    fn handle_key_request_denies_unknown_author() {
        let mut ctx = make_open_ctx();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let decision = ctx.handle_key_request("did:example:unknown", "did:example:bob");
        assert!(
            matches!(decision, KeyRequestDecision::Deny { .. }),
            "unknown author must result in deny"
        );
    }

    #[test]
    fn handle_key_request_grants_author_requesting_another_authors_key() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:carol").unwrap();

        // Authors have implicit read access and can request each other's keys.
        let decision = ctx.handle_key_request("did:example:alice", "did:example:carol");
        assert!(
            matches!(decision, KeyRequestDecision::Grant { .. }),
            "authors should be able to request each other's keys"
        );
    }

    #[test]
    fn handle_key_request_returns_current_epoch_after_rotation() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:eve", None, 1001).unwrap();

        // Block eve to advance Alice's epoch.
        ctx.block_subscriber("did:example:alice", "did:example:eve")
            .unwrap();

        let decision = ctx.handle_key_request("did:example:alice", "did:example:bob");
        match decision {
            KeyRequestDecision::Grant { epoch, .. } => {
                assert_eq!(epoch, 1, "should return the post-rotation epoch");
            }
            KeyRequestDecision::Deny { reason } => {
                panic!("expected Grant, got Deny: {reason}");
            }
        }
    }

    #[test]
    fn handle_key_request_gated_denies_subscriber_without_ucan() {
        // In a gated context, if somehow a subscriber was registered without
        // a UCAN (e.g. restored from storage with has_ucan=false), the key
        // request must be denied.
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();

        // Force-insert a subscriber record without UCAN (simulates a
        // data integrity issue or manual insertion).
        ctx.subscribers.insert(
            "did:example:bob".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:example:bob".to_owned(),
                registered_at: 1000,
                has_ucan: false,
            },
        );

        let decision = ctx.handle_key_request("did:example:alice", "did:example:bob");
        assert!(
            matches!(decision, KeyRequestDecision::Deny { .. }),
            "gated context must deny subscriber without UCAN"
        );
    }

    // =======================================================================
    // Subscriber / author iteration (#101 AC: roster maintenance)
    // =======================================================================

    #[test]
    fn subscribers_iterator_returns_all_records() {
        let mut ctx = make_open_ctx();
        subscribe_open(&mut ctx, "did:example:alice", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1001).unwrap();
        subscribe_open(&mut ctx, "did:example:carol", None, 1002).unwrap();

        let mut dids: Vec<&str> = ctx
            .subscribers()
            .map(|r| r.subscriber_did.as_str())
            .collect();
        dids.sort_unstable();
        assert_eq!(
            dids,
            vec!["did:example:alice", "did:example:bob", "did:example:carol"]
        );
    }

    #[test]
    fn author_dids_iterator_returns_all_authors() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        ctx.add_author("did:example:bob").unwrap();

        let mut dids: Vec<&str> = ctx.author_dids().map(String::as_str).collect();
        dids.sort_unstable();
        assert_eq!(dids, vec!["did:example:alice", "did:example:bob"]);
    }

    // =======================================================================
    // Integration: full subscriber lifecycle (#101 AC 7)
    // =======================================================================

    /// Integration test: create broadcast context -> subscribe -> receive
    /// broadcast message -> unsubscribe -> verify no further access.
    #[test]
    fn integration_full_subscriber_lifecycle() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        // Step 1: Subscribe.
        let sub_result = subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();
        assert_eq!(sub_result.author_epochs["did:example:alice"], 0);
        assert!(ctx.is_subscriber("did:example:bob"));

        // Step 2: Key request succeeds.
        let key_decision = ctx.handle_key_request("did:example:alice", "did:example:bob");
        let (key_bytes, epoch) = match key_decision {
            KeyRequestDecision::Grant { key_bytes, epoch } => (key_bytes, epoch),
            KeyRequestDecision::Deny { reason } => panic!("expected Grant: {reason}"),
        };
        assert_eq!(epoch, 0);

        // Step 3: Decrypt a broadcast message with the granted key.
        let author_key = &ctx.get_author("did:example:alice").unwrap().broadcast_key;
        let plaintext = b"Hello broadcast subscribers!";
        let ciphertext = encrypt_sender_layer(author_key, plaintext).unwrap();
        let received_key = SenderKey::from_bytes(*key_bytes);
        let decrypted = decrypt_sender_layer(&received_key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Step 4: Unsubscribe with key rotation.
        let unsub_result = ctx.unsubscribe("did:example:bob", true).unwrap();
        assert_eq!(unsub_result.subscriber_did, "did:example:bob");
        assert_eq!(unsub_result.key_rotations.len(), 1);
        assert_eq!(unsub_result.key_rotations[0].new_epoch, 1);

        // Step 5: Verify no further access.
        assert!(!ctx.is_subscriber("did:example:bob"));
        assert!(!ctx.can_read("did:example:bob"));

        // Step 6: Key request now denied.
        let denied = ctx.handle_key_request("did:example:alice", "did:example:bob");
        assert!(matches!(denied, KeyRequestDecision::Deny { .. }));

        // Step 7: Old key cannot decrypt new content.
        let new_author_key = &ctx.get_author("did:example:alice").unwrap().broadcast_key;
        let new_plaintext = b"Post-unsubscribe message";
        let new_ciphertext = encrypt_sender_layer(new_author_key, new_plaintext).unwrap();
        let old_decrypt_result = decrypt_sender_layer(&received_key, &new_ciphertext);
        assert!(
            old_decrypt_result.is_err(),
            "old key must not decrypt post-unsubscribe messages"
        );
    }

    /// Integration test: gated subscribe -> key request -> unsubscribe.
    #[test]
    fn integration_gated_subscriber_lifecycle() {
        let mut ctx = make_gated_ctx();
        ctx.add_author("did:example:alice").unwrap();

        let mut setup = GatedTestSetup::new();
        let ucan = setup.make_ucan("ctx-gated-1", "did:example:sub1");

        let mut val_ctx = ValidationContext {
            did_resolver: &setup.did_resolver,
            nonce_tracker: &mut setup.nonce_tracker,
            revocation_checker: &setup.revocation_checker,
            proof_resolver: &setup.proof_resolver,
            ceiling: &setup.ceiling,
            context_creator_did: &setup.issuer_did,
            presenting_agent_did: "did:example:sub1",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        };

        // Subscribe with UCAN.
        ctx.subscribe("did:example:sub1", Some(&ucan), 1000, Some(&mut val_ctx))
            .unwrap();
        assert!(ctx.is_subscriber("did:example:sub1"));

        // Key request succeeds (has_ucan = true).
        let decision = ctx.handle_key_request("did:example:alice", "did:example:sub1");
        assert!(matches!(decision, KeyRequestDecision::Grant { .. }));

        // Unsubscribe.
        let result = ctx.unsubscribe("did:example:sub1", false).unwrap();
        assert_eq!(result.subscriber_did, "did:example:sub1");
        assert!(!ctx.is_subscriber("did:example:sub1"));
    }

    /// Integration test: multiple subscribers, one unsubscribes, others
    /// continue receiving.
    #[test]
    fn integration_partial_unsubscribe() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();
        subscribe_open(&mut ctx, "did:example:sub3", None, 1002).unwrap();

        // Unsubscribe sub2 with key rotation.
        ctx.unsubscribe("did:example:sub2", true).unwrap();

        // sub1 and sub3 can still request keys.
        assert!(matches!(
            ctx.handle_key_request("did:example:alice", "did:example:sub1"),
            KeyRequestDecision::Grant { .. }
        ));
        assert!(matches!(
            ctx.handle_key_request("did:example:alice", "did:example:sub3"),
            KeyRequestDecision::Grant { .. }
        ));

        // sub2 is denied.
        assert!(matches!(
            ctx.handle_key_request("did:example:alice", "did:example:sub2"),
            KeyRequestDecision::Deny { .. }
        ));
    }

    /// Integration test: unsubscribe with key rotation produces keys that
    /// are different from the pre-unsubscribe keys.
    #[test]
    fn integration_unsubscribe_key_rotation_changes_key_material() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        let old_key = ctx
            .get_author("did:example:alice")
            .unwrap()
            .broadcast_key
            .as_bytes()
            .to_owned();

        let result = ctx.unsubscribe("did:example:bob", true).unwrap();
        let new_key = result.key_rotations[0].new_key.as_bytes();

        assert_ne!(
            &old_key[..],
            new_key,
            "key must change after unsubscribe with rotation"
        );
    }

    // =======================================================================
    // KeyRequestDecision Debug redaction
    // =======================================================================

    #[test]
    fn key_request_decision_debug_redacts_key_bytes() {
        let decision = KeyRequestDecision::Grant {
            key_bytes: Zeroizing::new([42u8; 32]),
            epoch: 5,
        };
        let debug = format!("{decision:?}");
        assert!(
            debug.contains("REDACTED"),
            "Grant debug must redact key bytes"
        );
        assert!(
            !debug.contains("42"),
            "Grant debug must not contain raw key byte values"
        );
        assert!(debug.contains('5'), "Grant debug must contain epoch");
    }

    // =======================================================================
    // SCP-227: Capability-enforced publish + BroadcastEnvelope integration
    // =======================================================================

    #[test]
    fn publish_rejects_non_author() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();
        subscribe_open(&mut ctx, "did:example:bob", None, 1000).unwrap();

        // Subscriber tries to publish -- must be rejected.
        let result = ctx.publish("did:example:bob", b"unauthorized message");
        assert!(
            matches!(&result, Err(ContextError::PermissionDenied(_))),
            "non-author must be rejected by publish: {result:?}"
        );

        // Completely unknown DID also rejected.
        let result = ctx.publish("did:example:unknown", b"ghost message");
        assert!(
            matches!(&result, Err(ContextError::PermissionDenied(_))),
            "unknown DID must be rejected by publish: {result:?}"
        );
    }

    /// SCP-227 integration test: author publishes via capability-enforced
    /// `publish()`, producing a `BroadcastEnvelope` that all 3 subscribers
    /// can decrypt with `open_broadcast` using the author's `BroadcastKey`.
    #[test]
    fn integration_publish_author_3_subscribers_decrypt_via_broadcast_envelope() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();
        subscribe_open(&mut ctx, "did:example:sub3", None, 1002).unwrap();

        let plaintext = b"Hello from Alice via publish()!";

        // Author publishes through the capability-enforced path.
        let envelope = ctx.publish("did:example:alice", plaintext).unwrap();

        // Verify envelope metadata.
        assert_eq!(envelope.author_did, "did:example:alice");
        assert_eq!(envelope.key_epoch, 0);

        // Each subscriber decrypts using the author's BroadcastKey.
        // In practice, subscribers obtain key material via the pull-based
        // key protocol (handle_key_request). Here we simulate that by
        // constructing a BroadcastKey from the granted key material.
        let author = ctx.get_author("did:example:alice").unwrap();
        let subscriber_key = BroadcastKey::from_parts(
            author.broadcast_key.clone(),
            author.epoch,
            author.author_did.clone(),
        );

        for sub_did in &["did:example:sub1", "did:example:sub2", "did:example:sub3"] {
            assert!(ctx.can_read(sub_did), "{sub_did} must have read access");
            let decrypted = open_broadcast(&subscriber_key, &envelope).unwrap();
            assert_eq!(
                decrypted, plaintext,
                "{sub_did} must decrypt the correct plaintext"
            );
        }
    }

    /// SCP-227 integration test: blocked author's post-block messages are
    /// undecryptable by subscribers who only hold the pre-block key, while
    /// pre-block messages remain decryptable with the old key.
    #[test]
    fn integration_publish_blocked_author_messages_undecryptable_via_broadcast_envelope() {
        let mut ctx = make_open_ctx();
        ctx.add_author("did:example:alice").unwrap();

        subscribe_open(&mut ctx, "did:example:sub1", None, 1000).unwrap();
        subscribe_open(&mut ctx, "did:example:sub2", None, 1001).unwrap();

        // Capture the pre-block BroadcastKey for later decryption attempts.
        let pre_block_author = ctx.get_author("did:example:alice").unwrap();
        let pre_block_key = BroadcastKey::from_parts(
            pre_block_author.broadcast_key.clone(),
            pre_block_author.epoch,
            pre_block_author.author_did.clone(),
        );

        // Author publishes a message before the block.
        let pre_block_msg = b"message visible to everyone";
        let pre_block_envelope = ctx.publish("did:example:alice", pre_block_msg).unwrap();

        // Both subscribers can decrypt the pre-block message.
        assert_eq!(
            open_broadcast(&pre_block_key, &pre_block_envelope).unwrap(),
            pre_block_msg,
        );

        // Block sub2: key rotates, sub2 loses access to future keys.
        let block_result = ctx
            .block_subscriber("did:example:alice", "did:example:sub2")
            .unwrap();
        assert_eq!(block_result.new_epoch, 1);

        // Author publishes a post-block message (with the new key).
        let post_block_msg = b"message only for sub1";
        let post_block_envelope = ctx.publish("did:example:alice", post_block_msg).unwrap();
        assert_eq!(post_block_envelope.key_epoch, 1);

        // sub1 (non-blocked) obtains the new key and can decrypt.
        let post_block_author = ctx.get_author("did:example:alice").unwrap();
        let post_block_key = BroadcastKey::from_parts(
            post_block_author.broadcast_key.clone(),
            post_block_author.epoch,
            post_block_author.author_did.clone(),
        );
        let sub1_decrypted = open_broadcast(&post_block_key, &post_block_envelope).unwrap();
        assert_eq!(sub1_decrypted, post_block_msg);

        // sub2 (blocked) only has the old key -- epoch mismatch means they
        // cannot even attempt decryption of the new envelope.
        let sub2_result = open_broadcast(&pre_block_key, &post_block_envelope);
        assert!(
            sub2_result.is_err(),
            "blocked subscriber must not decrypt post-block messages"
        );

        // Verify pre-block messages remain decryptable with the old key
        // (backwards compatibility: old content is not lost).
        let pre_block_still_ok = open_broadcast(&pre_block_key, &pre_block_envelope).unwrap();
        assert_eq!(pre_block_still_ok, pre_block_msg);
    }

    // =======================================================================
    // Broadcast MemberJoined event log persistence
    // =======================================================================

    /// Verifies that a `MemberJoined` event produced by
    /// `BroadcastContext::subscribe` can be persisted to an `EventLog` via
    /// `append_unsigned_event`, maintaining hash-chain integrity and a
    /// non-zero Merkle root.
    ///
    /// This is an integration smoke test bridging the broadcast subscription
    /// layer (spec section 5.14.3) with the event log layer (ADR-011).
    #[test]
    fn broadcast_subscribe_member_joined_persists_to_event_log() {
        use crate::context::membership::ContextEvent;
        use scp_event_log::tree::{GENESIS_PREV_HASH, append_unsigned_event, event_count, root};
        use scp_event_log::{Event, EventLog, EventPayload, EventType};

        // 1. Create an open broadcast context and subscribe a DID.
        let mut ctx = make_open_ctx();
        let subscriber_did = "did:example:subscriber-1";
        let result = subscribe_open(&mut ctx, subscriber_did, None, 1_700_000_000).unwrap();

        // 2. Verify the subscription produced a MemberJoined event.
        assert!(
            matches!(
                &result.event,
                ContextEvent::MemberJoined {
                    member_did,
                    role_name,
                } if member_did.0 == subscriber_did && role_name == "subscriber"
            ),
            "subscribe must produce MemberJoined with role 'subscriber'"
        );

        // 3. Convert the ContextEvent into an event-log Event.
        //    In production, ContextManager would do this conversion and sign
        //    the event. Here we use append_unsigned_event (the MCP FFI path).
        let event = Event {
            event_type: EventType::MemberJoined,
            actor_did: DID(subscriber_did.to_owned()),
            timestamp: 1_700_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"role:subscriber".to_vec(),
            },
            prev_hash: GENESIS_PREV_HASH,
            signature: Vec::new(),
        };

        // 4. Create an EventLog and append the unsigned event.
        let mut log = EventLog::new("ctx-broadcast-1".to_owned());
        let leaf_index = append_unsigned_event(&mut log, &event).unwrap();
        assert_eq!(leaf_index, 0, "first event should be at index 0");

        // 5. Verify the event log has exactly 1 entry.
        assert_eq!(event_count(&log), 1, "event log should contain 1 event");

        // 6. Verify the Merkle root is non-zero (a real commitment exists).
        let merkle_root = root(&log);
        assert_ne!(
            merkle_root, [0u8; 32],
            "Merkle root must be non-zero after appending an event"
        );
    }

    // -------------------------------------------------------------------
    // Snapshot persistence roundtrip tests
    // -------------------------------------------------------------------

    #[test]
    fn snapshot_roundtrip_preserves_empty_context() {
        let bc = BroadcastContext::new(
            "ctx-snap-1".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap();

        let snapshot = bc.to_snapshot();
        let restored = BroadcastContext::from_snapshot(snapshot);

        assert_eq!(restored.context_id(), "ctx-snap-1");
        assert_eq!(restored.admission(), BroadcastAdmission::Open);
        assert_eq!(restored.subscriber_count(), 0);
    }

    #[test]
    fn snapshot_roundtrip_preserves_subscribers_and_authors() {
        let mut bc = BroadcastContext::new(
            "ctx-snap-2".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap();

        // Add an author.
        bc.add_author("did:dht:z6MkAuthor1").unwrap();

        // Subscribe two subscribers.
        subscribe_open(&mut bc, "did:dht:z6MkSub1", None, 1_700_000_000).unwrap();
        subscribe_open(&mut bc, "did:dht:z6MkSub2", None, 1_700_000_100).unwrap();

        let snapshot = bc.to_snapshot();
        let restored = BroadcastContext::from_snapshot(snapshot);

        // Verify subscribers.
        assert_eq!(restored.subscriber_count(), 2);
        assert!(restored.is_subscriber("did:dht:z6MkSub1"));
        assert!(restored.is_subscriber("did:dht:z6MkSub2"));

        // Verify author.
        assert!(restored.can_write("did:dht:z6MkAuthor1"));
        let author = restored.get_author("did:dht:z6MkAuthor1").unwrap();
        assert_eq!(author.epoch, 0);
    }

    #[test]
    fn snapshot_roundtrip_preserves_block_lists_and_epochs() {
        let mut bc = BroadcastContext::new(
            "ctx-snap-3".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap();

        bc.add_author("did:dht:z6MkAuthor1").unwrap();
        subscribe_open(&mut bc, "did:dht:z6MkSub1", None, 1_700_000_000).unwrap();
        subscribe_open(&mut bc, "did:dht:z6MkSub2", None, 1_700_000_100).unwrap();

        // Block a subscriber (rotates key, increments epoch).
        bc.block_subscriber("did:dht:z6MkAuthor1", "did:dht:z6MkSub1")
            .unwrap();

        // Get the key bytes before snapshot for comparison.
        let original_author = bc.get_author("did:dht:z6MkAuthor1").unwrap();
        let original_key_bytes = *original_author.broadcast_key.as_bytes();
        let original_epoch = original_author.epoch;

        let snapshot = bc.to_snapshot();
        let restored = BroadcastContext::from_snapshot(snapshot);

        // Verify block list.
        assert!(restored.is_blocked("did:dht:z6MkAuthor1", "did:dht:z6MkSub1"));
        assert!(!restored.is_blocked("did:dht:z6MkAuthor1", "did:dht:z6MkSub2"));

        // Verify epoch was preserved.
        let restored_author = restored.get_author("did:dht:z6MkAuthor1").unwrap();
        assert_eq!(restored_author.epoch, original_epoch);
        assert_eq!(restored_author.epoch, 1);

        // Verify key material was preserved.
        assert_eq!(
            *restored_author.broadcast_key.as_bytes(),
            original_key_bytes
        );

        // Blocked subscriber should not be in subscriber list.
        assert!(!restored.is_subscriber("did:dht:z6MkSub1"));
        // Unblocked subscriber should still be there.
        assert!(restored.is_subscriber("did:dht:z6MkSub2"));
    }

    #[test]
    fn snapshot_roundtrip_preserves_gated_admission() {
        let bc = BroadcastContext::new(
            "ctx-snap-gated".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Gated,
        )
        .unwrap();

        let snapshot = bc.to_snapshot();
        let restored = BroadcastContext::from_snapshot(snapshot);

        assert_eq!(restored.admission(), BroadcastAdmission::Gated);
    }

    #[test]
    fn snapshot_serialization_roundtrip_via_msgpack() {
        let mut bc = BroadcastContext::new(
            "ctx-snap-msgpack".to_owned(),
            &ContextMode::Broadcast,
            BroadcastAdmission::Open,
        )
        .unwrap();

        bc.add_author("did:dht:z6MkAuthor1").unwrap();
        subscribe_open(&mut bc, "did:dht:z6MkSub1", None, 1_700_000_000).unwrap();

        let snapshot = bc.to_snapshot();

        // Serialize to MessagePack.
        let bytes = rmp_serde::to_vec(&snapshot).unwrap();
        assert!(!bytes.is_empty());

        // Deserialize from MessagePack.
        let decoded: BroadcastContextSnapshot = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.context_id, "ctx-snap-msgpack");
        assert_eq!(decoded.subscribers.len(), 1);
        assert_eq!(decoded.authors.len(), 1);
    }
}
