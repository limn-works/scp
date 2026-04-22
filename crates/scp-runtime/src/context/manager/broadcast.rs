//! Broadcast context operations (subscribe, publish, block).
//!
//! # Hoist (ADR-049 commit 12c.4)
//!
//! The ten `ContextManager` methods reached by the broadcast actor handler
//! (`subscribe_broadcast`, `unsubscribe_broadcast`, `publish_broadcast`,
//! `publish_broadcast_content`, `block_broadcast_subscriber`,
//! `unblock_broadcast_subscriber`, `handle_broadcast_key_request`,
//! `broadcast_subscriber_count`, `is_broadcast_subscriber`,
//! `broadcast_admission`) now forward to hoisted `pub async fn` free
//! functions in [`crate::context::broadcast_helpers`]. See the helper
//! module for the authoritative bodies; the methods here are one-line
//! forwarders that preserve the legacy `mgr.X(...)` call shape during
//! the commits-10-to-12 shim window.

use std::hash::BuildHasher;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::broadcast::{
    BlockResult, BroadcastAdmission, KeyRequestDecision, SubscriptionResult, UnsubscribeResult,
};
use scp_protocol::context::broadcast_content::BroadcastContent;
use scp_protocol::crypto::sender_keys::BroadcastEnvelope;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};
use tracing::instrument;

use super::ContextManager;

impl ContextManager {
    /// Subscribes a DID to a broadcast context.
    ///
    /// For open broadcast contexts, any DID can subscribe without a UCAN.
    /// For gated contexts, a valid `messagesRead` UCAN is required and
    /// validated through the full 11-step pipeline (ADR-016).
    ///
    /// Returns the current author key epochs so the subscriber knows which
    /// epochs to request keys for.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::subscribe_broadcast`] free
    /// function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context or the subscriber is already registered.
    /// - [`ContextError::PermissionDenied`] if the context is gated and no
    ///   valid `messagesRead` UCAN is supplied.
    #[instrument(skip_all, fields(context_id))]
    pub async fn subscribe_broadcast<D, N, R, P, S>(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        ucan: Option<&UcanToken>,
        timestamp: u64,
        validation_ctx: Option<&mut ValidationContext<'_, D, N, R, P, S>>,
    ) -> Result<SubscriptionResult, ContextError>
    where
        D: DidResolver + Send + Sync,
        N: NonceTracker + Send + Sync,
        R: RevocationChecker + Send + Sync,
        P: ProofResolver + Send + Sync,
        S: BuildHasher + Send + Sync,
    {
        crate::context::broadcast_helpers::subscribe_broadcast(
            self,
            context_id,
            subscriber_did,
            ucan,
            timestamp,
            validation_ctx,
        )
        .await
    }

    /// Unsubscribes a DID from a broadcast context.
    ///
    /// When `rotate_keys` is `true`, all authors rotate their broadcast keys
    /// to ensure forward secrecy (the departed subscriber cannot decrypt
    /// future content).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::unsubscribe_broadcast`] free
    /// function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn unsubscribe_broadcast(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        rotate_keys: bool,
    ) -> Result<UnsubscribeResult, ContextError> {
        crate::context::broadcast_helpers::unsubscribe_broadcast(
            self,
            context_id,
            subscriber_did,
            rotate_keys,
        )
        .await
    }

    /// Publishes a message to a broadcast context.
    ///
    /// Validates that the sender is a registered author (`messagesWrite`),
    /// seals the payload with the author's broadcast key, assigns a sequence
    /// number, and sends via transport.
    ///
    /// This is the broadcast-specific publish path. For a unified API, use
    /// [`send_message`](Self::send_message) which routes to this path
    /// automatically for broadcast contexts.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::publish_broadcast`] free
    /// function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::PermissionDenied`] if the sender is not an author.
    #[instrument(skip_all, fields(context_id))]
    pub async fn publish_broadcast(
        &self,
        context_id: &str,
        author_did: &DID,
        payload: &[u8],
        custody: &impl scp_platform::KeyCustody,
        signing_key_handle: &scp_platform::KeyHandle,
    ) -> Result<BroadcastEnvelope, ContextError> {
        crate::context::broadcast_helpers::publish_broadcast(
            self,
            context_id,
            author_did,
            payload,
            custody,
            signing_key_handle,
        )
        .await
    }

    /// Publishes a [`BroadcastContent`] to a broadcast context.
    ///
    /// This is the structured-content publish path. It serializes the
    /// `BroadcastContent` with the magic prefix and delegates to
    /// [`publish_broadcast`](Self::publish_broadcast).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::publish_broadcast_content`]
    /// free function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::PermissionDenied`] if the sender is not an author.
    /// - `ContextError::InvalidInput` if serialization fails.
    #[instrument(skip_all, fields(context_id))]
    pub async fn publish_broadcast_content(
        &self,
        context_id: &str,
        author_did: &DID,
        content: BroadcastContent,
        custody: &impl scp_platform::KeyCustody,
        signing_key_handle: &scp_platform::KeyHandle,
    ) -> Result<BroadcastEnvelope, ContextError> {
        crate::context::broadcast_helpers::publish_broadcast_content(
            self,
            context_id,
            author_did,
            content,
            custody,
            signing_key_handle,
        )
        .await
    }

    /// Blocks a subscriber from receiving future broadcast keys from a
    /// specific author.
    ///
    /// The author's broadcast key is rotated and the subscriber is added to
    /// the author's block list. The blocked subscriber receives no response
    /// to future key requests and cannot decrypt content encrypted with the
    /// new key.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::block_broadcast_subscriber`]
    /// free function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::MemberNotFound`] if the author is not registered.
    #[instrument(skip_all, fields(context_id))]
    pub async fn block_broadcast_subscriber(
        &self,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<BlockResult, ContextError> {
        crate::context::broadcast_helpers::block_broadcast_subscriber(
            self,
            context_id,
            author_did,
            subscriber_did,
        )
        .await
    }

    /// Unblocks a previously blocked subscriber in a broadcast context
    /// (§9.16.8 — forward-only restoration).
    ///
    /// Removes the subscriber DID from the specified author's block list.
    /// Per §9.16.8, the author does NOT rotate their sender key. The
    /// unblocked subscriber can request the current key on next pull but
    /// cannot decrypt content from the block period.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::unblock_broadcast_subscriber`]
    /// free function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is not registered
    ///   or is not a broadcast context.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MemberNotFound`] if the author DID is not registered.
    /// - [`ContextError::InvalidState`] if the subscriber is not blocked.
    #[instrument(skip_all, fields(context_id))]
    pub async fn unblock_broadcast_subscriber(
        &self,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<(), ContextError> {
        crate::context::broadcast_helpers::unblock_broadcast_subscriber(
            self,
            context_id,
            author_did,
            subscriber_did,
        )
        .await
    }

    /// Evaluates whether a subscriber's broadcast key request should be
    /// granted or denied.
    ///
    /// This is the author-side decision function for the pull-based key
    /// distribution protocol (spec section 9.16.6).
    ///
    /// # Defense-in-depth validation (#234)
    ///
    /// Before delegating to `BroadcastContext::handle_key_request`, this
    /// method verifies that `author_did` is registered as a locally
    /// controlled DID via [`register_local_did`](Self::register_local_did).
    /// This prevents misuse if the method is called from an unexpected
    /// context. Transport-layer auth (spec section 9.16.6) remains the
    /// primary enforcement mechanism; this check is an additional layer.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::handle_broadcast_key_request`]
    /// free function (ADR-049 commit 12c.4).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PermissionDenied`] if `author_did` is not
    /// registered as a locally controlled DID.
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    /// a broadcast context.
    #[instrument(skip_all, fields(context_id))]
    pub async fn handle_broadcast_key_request(
        &self,
        context_id: &str,
        author_did: &DID,
        requester_did: &DID,
    ) -> Result<KeyRequestDecision, ContextError> {
        crate::context::broadcast_helpers::handle_broadcast_key_request(
            self,
            context_id,
            author_did,
            requester_did,
        )
        .await
    }

    /// Returns the number of subscribers in a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::broadcast_subscriber_count`]
    /// free function (ADR-049 commit 12c.4).
    #[instrument(skip_all, fields(context_id))]
    pub async fn broadcast_subscriber_count(&self, context_id: &str) -> Option<usize> {
        crate::context::broadcast_helpers::broadcast_subscriber_count(self, context_id).await
    }

    /// Returns `true` if the given DID is a subscriber in a broadcast context.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::is_broadcast_subscriber`] free
    /// function (ADR-049 commit 12c.4).
    #[instrument(skip_all, fields(context_id))]
    pub async fn is_broadcast_subscriber(&self, context_id: &str, did: &str) -> bool {
        crate::context::broadcast_helpers::is_broadcast_subscriber(self, context_id, did).await
    }

    /// Returns the admission policy for a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::broadcast_helpers::broadcast_admission`] free
    /// function (ADR-049 commit 12c.4).
    #[instrument(skip_all, fields(context_id))]
    pub async fn broadcast_admission(&self, context_id: &str) -> Option<BroadcastAdmission> {
        crate::context::broadcast_helpers::broadcast_admission(self, context_id).await
    }
}
