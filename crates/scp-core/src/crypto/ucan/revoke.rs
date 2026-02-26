//! UCAN token revocation for SCP.
//!
//! Implements the per-context [`RevocationList`] and [`revoke_ucan`] function
//! specified by ADR-016 in `.docs/adrs/phase-3.md`. Revocations are distributed
//! as MLS application messages so all members maintain consistent revocation
//! lists. The revocation list is append-only: once a token CID is revoked, it
//! cannot be un-revoked.
//!
//! # Revocation states
//!
//! Each token tracked by the revocation list is in one of three states:
//!
//! - [`RevocationState::Active`] -- Not revoked. This is the default state and
//!   is not stored explicitly (absence from the map means Active).
//! - [`RevocationState::RevocationPending`] -- Revocation has been initiated
//!   locally but MLS distribution has not yet succeeded. Capability exercise
//!   is **denied** in this state (fail-closed).
//! - [`RevocationState::Revoked`] -- Revocation is fully committed: the token
//!   has been revoked locally and the revocation has been distributed to all
//!   context members via MLS.
//!
//! The [`revoke_ucan`] function is transactional: if MLS distribution fails,
//! the local revocation is rolled back so there is no split-brain between the
//! revoker and other context members.
//!
//! # Types
//!
//! - [`RevocationList`] -- Per-context set of revoked token CIDs with merge
//!   support for MLS-distributed synchronization.
//! - [`RevocationState`] -- Per-token revocation state.
//!
//! # Traits
//!
//! - [`RevocationDistributor`] -- Abstraction for distributing revocations via
//!   MLS application messages.
//! - [`RevocationEventLogger`] -- Abstraction for appending `TokenRevoked`
//!   events to the context's event log.
//! - [`RevocationAuthorizer`] -- Abstraction for verifying that a revoker is
//!   authorized (must be the token's issuer or the context creator).
//!
//! See ADR-016 acceptance criterion 5 and 7.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{UcanError, UcanPayload};
use crate::event_log::ContextId;

// ---------------------------------------------------------------------------
// RevocationState
// ---------------------------------------------------------------------------

/// Per-token revocation state.
///
/// Tokens progress through these states during the revocation flow:
///
/// ```text
/// Active -> RevocationPending -> Revoked
///                |
///                +-> Active (on distribution failure -- rollback)
/// ```
///
/// Both `RevocationPending` and `Revoked` are treated as revoked for
/// capability validation purposes (fail-closed). This ensures that a token
/// cannot be exercised during the propagation window between local revocation
/// and MLS distribution completing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationState {
    /// The token has not been revoked. This state is implicit -- tokens not
    /// present in the revocation list are considered Active.
    Active,
    /// Revocation has been initiated locally but MLS distribution has not yet
    /// succeeded. Capability exercise is denied in this state.
    RevocationPending,
    /// Revocation is fully committed: local revocation + MLS distribution.
    Revoked,
}

// ---------------------------------------------------------------------------
// RevocationList
// ---------------------------------------------------------------------------

/// Per-context revocation list tracking revoked UCAN token CIDs.
///
/// Revocations are append-only: once a token CID is added via [`revoke`], it
/// cannot be removed. The [`merge`] operation performs a set union with a remote
/// revocation list, preserving the append-only invariant.
///
/// Revocation lists are distributed to all context members as MLS application
/// messages. Each member maintains their own copy and merges incoming lists to
/// stay consistent.
///
/// See ADR-016 acceptance criterion 7.
///
/// [`revoke`]: RevocationList::revoke
/// [`merge`]: RevocationList::merge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    /// Map of token CIDs to their revocation state. Absence means Active.
    revoked: HashMap<String, RevocationState>,
    /// The context this revocation list belongs to.
    context_id: ContextId,
}

impl RevocationList {
    /// Creates a new empty revocation list for the given context.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            revoked: HashMap::new(),
            context_id,
        }
    }

    /// Returns the context ID this revocation list belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns `true` if the given token CID is in a revoked state.
    ///
    /// Both `RevocationPending` and `Revoked` return `true` (fail-closed).
    #[must_use]
    pub fn is_revoked(&self, token_cid: &str) -> bool {
        matches!(
            self.revoked.get(token_cid),
            Some(RevocationState::RevocationPending | RevocationState::Revoked)
        )
    }

    /// Returns the [`RevocationState`] for a token CID.
    #[must_use]
    pub fn state(&self, token_cid: &str) -> RevocationState {
        self.revoked
            .get(token_cid)
            .copied()
            .unwrap_or(RevocationState::Active)
    }

    /// Adds a token CID as fully [`Revoked`](RevocationState::Revoked).
    pub fn revoke(&mut self, token_cid: String) {
        self.revoked.insert(token_cid, RevocationState::Revoked);
    }

    /// Marks a token CID as [`RevocationPending`](RevocationState::RevocationPending).
    pub fn mark_pending(&mut self, token_cid: String) {
        if self.revoked.get(&token_cid) == Some(&RevocationState::Revoked) {
            return;
        }
        self.revoked
            .insert(token_cid, RevocationState::RevocationPending);
    }

    /// Transitions a pending entry to Revoked.
    pub fn confirm_revocation(&mut self, token_cid: &str) {
        if self.revoked.get(token_cid) == Some(&RevocationState::RevocationPending) {
            self.revoked
                .insert(token_cid.to_owned(), RevocationState::Revoked);
        }
    }

    /// Removes a pending entry (rollback to Active).
    pub fn rollback_revocation(&mut self, token_cid: &str) {
        if self.revoked.get(token_cid) == Some(&RevocationState::RevocationPending) {
            self.revoked.remove(token_cid);
        }
    }

    /// Merges a remote revocation list into this one.
    ///
    /// The merge is a set union: all CIDs from the remote list are added to
    /// this list. This preserves the append-only invariant -- a token cannot
    /// be un-revoked through a merge. Both lists must belong to the same
    /// context; if they do not, this is a no-op to prevent cross-context
    /// contamination.
    ///
    /// # Arguments
    ///
    /// * `remote` - The remote revocation list received via MLS application
    ///   message.
    pub fn merge(&mut self, remote: &Self) {
        if self.context_id != remote.context_id {
            return;
        }
        for (cid, remote_state) in &remote.revoked {
            let local_state = self.revoked.get(cid).copied();
            match (local_state, remote_state) {
                (_, RevocationState::Revoked) => {
                    self.revoked.insert(cid.clone(), RevocationState::Revoked);
                }
                (None | Some(RevocationState::Active), RevocationState::RevocationPending) => {
                    self.revoked
                        .insert(cid.clone(), RevocationState::RevocationPending);
                }
                _ => {}
            }
        }
    }

    /// Returns the number of revoked token CIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Returns `true` if the revocation list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Returns an iterator over the revoked token CIDs.
    ///
    /// The iteration order is not guaranteed.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.revoked.keys()
    }
}

impl PartialEq for RevocationList {
    fn eq(&self, other: &Self) -> bool {
        self.context_id == other.context_id && self.revoked == other.revoked
    }
}

impl Eq for RevocationList {}

// ---------------------------------------------------------------------------
// Trait abstractions for revoke_ucan dependencies
// ---------------------------------------------------------------------------

/// Abstraction for verifying that a revoker is authorized to revoke a token.
///
/// The revoker must be either the token's issuer or the context creator.
/// Implementations look up the token by CID to find its issuer, and check
/// whether the revoker DID matches the issuer or the context creator DID.
pub trait RevocationAuthorizer {
    /// Checks whether `revoker_did` is authorized to revoke `token_cid`.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationUnauthorized`] if the revoker is neither
    /// the token's issuer nor the context creator.
    /// Returns [`UcanError::RevocationFailed`] if the token CID cannot be
    /// resolved.
    fn authorize_revocation(&self, token_cid: &str, revoker_did: &str) -> Result<(), UcanError>;
}

/// Abstraction for distributing revocations via MLS application messages.
///
/// Implementations broadcast the serialized revocation list (or the revoked
/// CID) to all context members through the MLS group's application message
/// channel.
pub trait RevocationDistributor {
    /// Distributes a revocation to all members of the context.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationFailed`] if distribution fails.
    fn distribute_revocation(&self, context_id: &str, token_cid: &str) -> Result<(), UcanError>;
}

/// Abstraction for appending events to the context's event log.
///
/// Implementations append a `TokenRevoked` event to the context's Merkle tree
/// event log with the appropriate actor DID and payload.
pub trait RevocationEventLogger {
    /// Appends a `TokenRevoked` event for the given token CID and revoker.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationFailed`] if the event log append fails.
    fn log_token_revoked(
        &self,
        context_id: &str,
        token_cid: &str,
        revoker_did: &str,
    ) -> Result<(), UcanError>;
}

// ---------------------------------------------------------------------------
// Revocation CID computation
// ---------------------------------------------------------------------------

/// Computes a revocation CID as the hex-encoded SHA-256 hash of the
/// JSON-serialized UCAN payload (claims).
///
/// Unlike the proof-chain CID ([`super::mint::compute_cid`]) which hashes the
/// full encoded JWT, the revocation CID hashes only the canonical payload.
/// This produces a fixed-length 64-character hex string regardless of token
/// size, keeping revocation storage bounded and avoiding storing the full
/// variable-length JWT in the revocation list.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] if the payload cannot be serialized
/// to JSON. This should never happen for a well-formed [`UcanPayload`].
#[must_use]
pub fn compute_revocation_cid(payload: &UcanPayload) -> String {
    // SAFETY: UcanPayload derives Serialize with standard field types (String,
    // u64, Option, Vec, serde_json::Value). Serialization failure is not
    // possible for a well-formed payload, so we use an infallible fold.
    let payload_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let hash = Sha256::digest(&payload_bytes);
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ---------------------------------------------------------------------------
// revoke_ucan
// ---------------------------------------------------------------------------

/// Revokes a UCAN token within a context.
///
/// Computes the revocation CID as the hex-encoded SHA-256 hash of the
/// JSON-serialized UCAN payload, then performs the full revocation flow
/// specified by ADR-016 acceptance criterion 5:
///
/// 1. **CID computation** -- Computes the content-hash CID from the token
///    payload via [`compute_revocation_cid`].
/// 2. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator via [`RevocationAuthorizer`].
/// 3. **Revocation** -- Adds the token CID to the context's
///    [`RevocationList`].
/// 4. **Distribution** -- Broadcasts the revocation to all context members as
///    an MLS application message via [`RevocationDistributor`].
/// 5. **Event logging** -- Appends a `TokenRevoked` event to the context's
///    event log via [`RevocationEventLogger`].
///
/// # Arguments
///
/// * `revocation_list` - The context's mutable revocation list.
/// * `payload` - The UCAN token's payload, used to compute the revocation CID.
/// * `revoker_did` - The DID of the entity requesting the revocation.
/// * `authorizer` - Verifies the revoker is authorized.
/// * `distributor` - Distributes the revocation to context members.
/// * `event_logger` - Appends the `TokenRevoked` event.
///
/// # Returns
///
/// Returns the computed revocation CID on success.
///
/// # Errors
///
/// Returns [`UcanError::RevocationUnauthorized`] if the revoker is not
/// authorized.
/// Returns [`UcanError::RevocationFailed`] if distribution or logging fails.
///
/// See ADR-016 acceptance criterion 5.
pub fn revoke_ucan(
    revocation_list: &mut RevocationList,
    payload: &UcanPayload,
    revoker_did: &str,
    authorizer: &impl RevocationAuthorizer,
    distributor: &impl RevocationDistributor,
    event_logger: &impl RevocationEventLogger,
) -> Result<String, UcanError> {
    // Step 1: Compute content-hash CID from payload.
    let token_cid = compute_revocation_cid(payload);

    // Step 2: Mark as RevocationPending (fail-closed).
    revocation_list.mark_pending(token_cid.to_owned());

    // Step 3: Distribute via MLS. On failure, roll back.
    let context_id = revocation_list.context_id().to_owned();
    if let Err(e) = distributor.distribute_revocation(&context_id, &token_cid) {
        revocation_list.rollback_revocation(&token_cid);
        return Err(e);
    }

    // Step 4: Commit -- Pending to Revoked.
    revocation_list.confirm_revocation(&token_cid);

    // Step 5: Append TokenRevoked event.
    event_logger.log_token_revoked(&context_id, &token_cid, revoker_did)?;

    Ok(token_cid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A mock authorizer that approves specific revoker DIDs.
    struct MockAuthorizer {
        /// The token issuer DID.
        issuer_did: String,
        /// The context creator DID.
        creator_did: String,
    }

    impl RevocationAuthorizer for MockAuthorizer {
        fn authorize_revocation(
            &self,
            _token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            if revoker_did == self.issuer_did || revoker_did == self.creator_did {
                Ok(())
            } else {
                Err(UcanError::RevocationUnauthorized(format!(
                    "revoker {revoker_did} is neither the issuer nor the context creator"
                )))
            }
        }
    }

    /// A mock authorizer that always rejects.
    struct RejectingAuthorizer;

    impl RevocationAuthorizer for RejectingAuthorizer {
        fn authorize_revocation(
            &self,
            _token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationUnauthorized(format!(
                "{revoker_did} is not authorized"
            )))
        }
    }

    /// A mock distributor that records distributed revocations.
    struct MockDistributor {
        distributed: RefCell<Vec<(String, String)>>,
    }

    impl MockDistributor {
        fn new() -> Self {
            Self {
                distributed: RefCell::new(Vec::new()),
            }
        }
    }

    impl RevocationDistributor for MockDistributor {
        fn distribute_revocation(
            &self,
            context_id: &str,
            token_cid: &str,
        ) -> Result<(), UcanError> {
            self.distributed
                .borrow_mut()
                .push((context_id.to_owned(), token_cid.to_owned()));
            Ok(())
        }
    }

    /// A mock distributor that always fails.
    struct FailingDistributor;

    impl RevocationDistributor for FailingDistributor {
        fn distribute_revocation(
            &self,
            _context_id: &str,
            _token_cid: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationFailed(
                "MLS distribution failed".to_owned(),
            ))
        }
    }

    /// A mock event logger that records logged events.
    struct MockEventLogger {
        logged: RefCell<Vec<(String, String, String)>>,
    }

    impl MockEventLogger {
        fn new() -> Self {
            Self {
                logged: RefCell::new(Vec::new()),
            }
        }
    }

    impl RevocationEventLogger for MockEventLogger {
        fn log_token_revoked(
            &self,
            context_id: &str,
            token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            self.logged.borrow_mut().push((
                context_id.to_owned(),
                token_cid.to_owned(),
                revoker_did.to_owned(),
            ));
            Ok(())
        }
    }

    /// A mock event logger that always fails.
    struct FailingEventLogger;

    impl RevocationEventLogger for FailingEventLogger {
        fn log_token_revoked(
            &self,
            _context_id: &str,
            _token_cid: &str,
            _revoker_did: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationFailed(
                "event log append failed".to_owned(),
            ))
        }
    }

    /// Build a test payload for revocation tests.
    fn test_payload() -> UcanPayload {
        use super::super::Attenuation;
        UcanPayload {
            iss: "did:dht:z6MkIssuer".to_owned(),
            aud: "did:dht:z6MkMember".to_owned(),
            exp: 1_700_000_000,
            nbf: None,
            nnc: "1699999000000-aabbccdd11223344aabbccdd11223344".to_owned(),
            att: vec![Attenuation {
                with: "scp:ctx:ctx-1/messages:write".to_owned(),
                can: "write".to_owned(),
            }],
            prf: vec![],
            fct: None,
        }
    }

    // -----------------------------------------------------------------------
    // RevocationList -- construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_revocation_list_is_empty() {
        let list = RevocationList::new("ctx-1".to_owned());
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.context_id(), "ctx-1");
    }

    // -----------------------------------------------------------------------
    // RevocationList -- is_revoked
    // -----------------------------------------------------------------------

    #[test]
    fn is_revoked_returns_false_for_unknown_cid() {
        let list = RevocationList::new("ctx-1".to_owned());
        assert!(!list.is_revoked("bafyreiabc123"));
    }

    #[test]
    fn is_revoked_returns_true_after_revoke() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert!(list.is_revoked("bafyreiabc123"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- revoke
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_adds_cid_to_list() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert_eq!(list.len(), 1);
        assert!(list.is_revoked("bafyreiabc123"));
    }

    #[test]
    fn revoke_is_idempotent() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn revoke_multiple_distinct_cids() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyrei-a".to_owned());
        list.revoke("bafyrei-b".to_owned());
        list.revoke("bafyrei-c".to_owned());
        assert_eq!(list.len(), 3);
        assert!(list.is_revoked("bafyrei-a"));
        assert!(list.is_revoked("bafyrei-b"));
        assert!(list.is_revoked("bafyrei-c"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- merge
    // -----------------------------------------------------------------------

    #[test]
    fn merge_unions_two_disjoint_lists() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_with_overlapping_cids_produces_union() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());
        local.revoke("cid-b".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-b".to_owned());
        remote.revoke("cid-c".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 3);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
        assert!(local.is_revoked("cid-c"));
    }

    #[test]
    fn merge_with_empty_remote_is_noop() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let remote = RevocationList::new("ctx-1".to_owned());
        local.merge(&remote);

        assert_eq!(local.len(), 1);
        assert!(local.is_revoked("cid-a"));
    }

    #[test]
    fn merge_into_empty_list_copies_all() {
        let mut local = RevocationList::new("ctx-1".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-a".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_never_removes_existing_revocations() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());
        local.revoke("cid-b".to_owned());

        // Remote only has cid-a (no cid-b). Merge should not remove cid-b.
        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-a".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_rejects_cross_context_list() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let mut remote = RevocationList::new("ctx-2".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        // cid-b should NOT be added because the contexts differ.
        assert_eq!(local.len(), 1);
        assert!(!local.is_revoked("cid-b"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- serialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialization_roundtrip_empty() {
        let list = RevocationList::new("ctx-1".to_owned());
        let json = serde_json::to_string(&list).unwrap();
        let deserialized: RevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, deserialized);
    }

    #[test]
    fn serialization_roundtrip_with_entries() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyrei-a".to_owned());
        list.revoke("bafyrei-b".to_owned());
        list.revoke("bafyrei-c".to_owned());

        let json = serde_json::to_string(&list).unwrap();
        let deserialized: RevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, deserialized);
        assert!(deserialized.is_revoked("bafyrei-a"));
        assert!(deserialized.is_revoked("bafyrei-b"));
        assert!(deserialized.is_revoked("bafyrei-c"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- equality
    // -----------------------------------------------------------------------

    #[test]
    fn equality_same_context_same_entries() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-1".to_owned());
        b.revoke("cid-a".to_owned());

        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_contexts() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-2".to_owned());
        b.revoke("cid-a".to_owned());

        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_entries() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-1".to_owned());
        b.revoke("cid-b".to_owned());

        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // RevocationList -- iterator
    // -----------------------------------------------------------------------

    #[test]
    fn iter_yields_all_revoked_cids() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("cid-a".to_owned());
        list.revoke("cid-b".to_owned());

        let mut cids: Vec<&String> = list.iter().collect();
        cids.sort();
        assert_eq!(cids, vec![&"cid-a".to_owned(), &"cid-b".to_owned()]);
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- success path
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_success_as_issuer() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let payload = test_payload();
        let expected_cid = compute_revocation_cid(&payload);

        let result = revoke_ucan(
            &mut list,
            &payload,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        let returned_cid = result.unwrap();
        assert_eq!(returned_cid, expected_cid);
        assert!(list.is_revoked(&expected_cid));
        assert_eq!(distributor.distributed.borrow().len(), 1);
        assert_eq!(
            distributor.distributed.borrow()[0],
            ("ctx-1".to_owned(), expected_cid.clone())
        );
        assert_eq!(logger.logged.borrow().len(), 1);
        assert_eq!(
            logger.logged.borrow()[0],
            (
                "ctx-1".to_owned(),
                expected_cid,
                "did:dht:z6MkIssuer".to_owned()
            )
        );
    }

    #[test]
    fn revoke_ucan_success_as_context_creator() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let payload = test_payload();
        let expected_cid = compute_revocation_cid(&payload);

        let result = revoke_ucan(
            &mut list,
            &payload,
            "did:dht:z6MkCreator",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        assert!(list.is_revoked(&expected_cid));
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- authorization failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_rejects_unauthorized_revoker() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = RejectingAuthorizer;
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let payload = test_payload();
        let expected_cid = compute_revocation_cid(&payload);

        let result = revoke_ucan(
            &mut list,
            &payload,
            "did:dht:z6MkUnauthorized",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationUnauthorized(_)
        ));
        // Token should NOT be revoked on authorization failure.
        assert!(!list.is_revoked(&expected_cid));
        // Distribution and logging should not have been called.
        assert!(distributor.distributed.borrow().is_empty());
        assert!(logger.logged.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- distribution failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_distribution_failure_rolls_back() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = FailingDistributor;
        let logger = MockEventLogger::new();

        let result = revoke_ucan(
            &mut list,
            &test_payload(),
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationFailed(_)
        ));
        // The token must NOT remain after rollback.
        assert!(!list.is_revoked("bafyrei-token1"));
        assert_eq!(list.state("bafyrei-token1"), RevocationState::Active);
        assert!(list.is_empty());
        assert!(logger.logged.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- event logging failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_fails_on_event_log_error() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = FailingEventLogger;

        let result = revoke_ucan(
            &mut list,
            &test_payload(),
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationFailed(_)
        ));
    }


    // -----------------------------------------------------------------------
    // State transitions and fail-closed behavior
    // -----------------------------------------------------------------------

    #[test]
    fn mark_pending_sets_pending_state() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        assert_eq!(list.state("cid-a"), RevocationState::RevocationPending);
        assert!(list.is_revoked("cid-a"));
    }

    #[test]
    fn confirm_transitions_pending_to_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        list.confirm_revocation("cid-a");
        assert_eq!(list.state("cid-a"), RevocationState::Revoked);
    }

    #[test]
    fn rollback_removes_pending_entry() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        list.rollback_revocation("cid-a");
        assert!(!list.is_revoked("cid-a"));
        assert!(list.is_empty());
    }

    #[test]
    fn rollback_noop_for_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("cid-a".to_owned());
        list.rollback_revocation("cid-a");
        assert_eq!(list.state("cid-a"), RevocationState::Revoked);
    }

    #[test]
    fn pending_denies_capability_exercise() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("bafyrei-token1".to_owned());
        assert!(list.is_revoked("bafyrei-token1"));
        assert_eq!(
            list.state("bafyrei-token1"),
            RevocationState::RevocationPending
        );
    }

    #[test]
    fn success_path_final_state_is_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        assert_eq!(list.state("bafyrei-token1"), RevocationState::Active);
        revoke_ucan(
            &mut list,
            "bafyrei-token1",
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        )
        .unwrap();
        assert_eq!(list.state("bafyrei-token1"), RevocationState::Revoked);
    }

    // -----------------------------------------------------------------------
    // compute_revocation_cid -- content hash format
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_cid_is_deterministic() {
        let payload = test_payload();
        let cid1 = compute_revocation_cid(&payload);
        let cid2 = compute_revocation_cid(&payload);
        assert_eq!(cid1, cid2, "same payload must produce same CID");
    }

    #[test]
    fn revocation_cid_is_fixed_length_hex() {
        let payload = test_payload();
        let cid = compute_revocation_cid(&payload);
        // SHA-256 hex = 64 characters.
        assert_eq!(cid.len(), 64, "revocation CID must be 64 hex chars");
        assert!(
            cid.chars().all(|c| c.is_ascii_hexdigit()),
            "revocation CID must be hex-encoded"
        );
    }

    #[test]
    fn revocation_cid_differs_for_different_payloads() {
        let payload1 = test_payload();
        let mut payload2 = test_payload();
        payload2.aud = "did:dht:z6MkOther".to_owned();

        let cid1 = compute_revocation_cid(&payload1);
        let cid2 = compute_revocation_cid(&payload2);
        assert_ne!(cid1, cid2, "different payloads must produce different CIDs");
    }

    #[test]
    fn revocation_storage_size_is_bounded_per_entry() {
        // The revocation CID is always 64 hex characters, regardless of
        // the JWT payload size. This verifies the CID length is bounded.
        use super::super::Attenuation;
        let small_payload = test_payload();

        // Create a payload with many capabilities (large JWT).
        let large_payload = UcanPayload {
            iss: "did:dht:z6MkIssuer".to_owned(),
            aud: "did:dht:z6MkMember".to_owned(),
            exp: 1_700_000_000,
            nbf: None,
            nnc: "1699999000000-aabbccdd11223344aabbccdd11223344".to_owned(),
            att: (0..100)
                .map(|i| Attenuation {
                    with: format!("scp:ctx:ctx-{i}/messages:write"),
                    can: "write".to_owned(),
                })
                .collect(),
            prf: (0..50).map(|i| format!("bafyrei-proof-{i}")).collect(),
            fct: Some(serde_json::json!({"data": "x".repeat(10_000)})),
        };

        let small_cid = compute_revocation_cid(&small_payload);
        let large_cid = compute_revocation_cid(&large_payload);

        // Both CIDs are the same fixed length regardless of payload size.
        assert_eq!(small_cid.len(), 64);
        assert_eq!(large_cid.len(), 64);
        assert_ne!(small_cid, large_cid);
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- content-hash CID is found on subsequent lookup
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_cid_found_on_subsequent_lookup() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let payload = test_payload();

        // Revoke the token.
        let cid = revoke_ucan(
            &mut list,
            &payload,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        )
        .unwrap();

        // The CID should be the content hash, not the full JWT.
        let expected_cid = compute_revocation_cid(&payload);
        assert_eq!(cid, expected_cid);

        // Subsequent lookup by the same content-hash CID must find it.
        assert!(
            list.is_revoked(&expected_cid),
            "revocation must be findable by content-hash CID"
        );

        // Re-computing the CID from the same payload must also find it.
        let recomputed_cid = compute_revocation_cid(&payload);
        assert!(
            list.is_revoked(&recomputed_cid),
            "re-computed CID must match stored revocation"
        );
    }

    // -----------------------------------------------------------------------
    // proptest -- merge is commutative and idempotent
    // -----------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        fn arb_cid() -> impl Strategy<Value = String> {
            "[a-zA-Z0-9_-]{8,32}".prop_map(|s| format!("bafyrei-{s}"))
        }

        fn arb_revocation_list(ctx: &'static str) -> impl Strategy<Value = RevocationList> {
            proptest::collection::hash_set(arb_cid(), 0..20).prop_map(move |cids| {
                let mut list = RevocationList::new(ctx.to_owned());
                for cid in cids {
                    list.revoke(cid);
                }
                list
            })
        }

        proptest! {
            #[test]
            fn merge_is_commutative(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut ab = a.clone();
                ab.merge(&b);

                let mut ba = b.clone();
                ba.merge(&a);

                // After merge, both should have the same set of revocations.
                prop_assert_eq!(ab, ba);
            }

            #[test]
            fn merge_is_idempotent(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut first = a;
                first.merge(&b);

                let mut second = first.clone();
                second.merge(&b);

                // Merging the same list again should not change anything.
                prop_assert_eq!(first, second);
            }

            #[test]
            fn merge_preserves_all_entries(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut merged = a.clone();
                merged.merge(&b);

                // All entries from `a` are preserved.
                for cid in a.iter() {
                    prop_assert!(merged.is_revoked(cid));
                }
                // All entries from `b` are present.
                for cid in b.iter() {
                    prop_assert!(merged.is_revoked(cid));
                }
            }

            #[test]
            fn revoke_then_is_revoked(cid in arb_cid()) {
                let mut list = RevocationList::new("ctx-1".to_owned());
                list.revoke(cid.clone());
                prop_assert!(list.is_revoked(&cid));
            }
        }
    }
}
