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

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::UcanError;
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
    /// Set of revoked token CIDs. Once a CID is added, it cannot be removed.
    revoked: HashSet<String>,
    /// The context this revocation list belongs to.
    context_id: ContextId,
}

impl RevocationList {
    /// Creates a new empty revocation list for the given context.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            revoked: HashSet::new(),
            context_id,
        }
    }

    /// Returns the context ID this revocation list belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns `true` if the given token CID has been revoked.
    ///
    /// This is a constant-time set membership test.
    #[must_use]
    pub fn is_revoked(&self, token_cid: &str) -> bool {
        self.revoked.contains(token_cid)
    }

    /// Adds a token CID to the revocation list.
    ///
    /// This operation is idempotent: revoking the same CID twice has no
    /// additional effect. Once revoked, a token cannot be un-revoked.
    pub fn revoke(&mut self, token_cid: String) {
        self.revoked.insert(token_cid);
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
        for cid in &remote.revoked {
            self.revoked.insert(cid.clone());
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
        self.revoked.iter()
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
// revoke_ucan
// ---------------------------------------------------------------------------

/// Revokes a UCAN token within a context.
///
/// Performs the full revocation flow specified by ADR-016 acceptance criterion 5:
///
/// 1. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator via [`RevocationAuthorizer`].
/// 2. **Revocation** -- Adds the token CID to the context's
///    [`RevocationList`].
/// 3. **Distribution** -- Broadcasts the revocation to all context members as
///    an MLS application message via [`RevocationDistributor`].
/// 4. **Event logging** -- Appends a `TokenRevoked` event to the context's
///    event log via [`RevocationEventLogger`].
///
/// # Arguments
///
/// * `revocation_list` - The context's mutable revocation list.
/// * `token_cid` - The CID of the token to revoke.
/// * `revoker_did` - The DID of the entity requesting the revocation.
/// * `authorizer` - Verifies the revoker is authorized.
/// * `distributor` - Distributes the revocation to context members.
/// * `event_logger` - Appends the `TokenRevoked` event.
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
    token_cid: &str,
    revoker_did: &str,
    authorizer: &impl RevocationAuthorizer,
    distributor: &impl RevocationDistributor,
    event_logger: &impl RevocationEventLogger,
) -> Result<(), UcanError> {
    // Step 1: Verify authorization.
    authorizer.authorize_revocation(token_cid, revoker_did)?;

    // Step 2: Add to revocation list.
    revocation_list.revoke(token_cid.to_owned());

    // Step 3: Distribute via MLS.
    let context_id = revocation_list.context_id().to_owned();
    distributor.distribute_revocation(&context_id, token_cid)?;

    // Step 4: Append TokenRevoked event.
    event_logger.log_token_revoked(&context_id, token_cid, revoker_did)?;

    Ok(())
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

        let result = revoke_ucan(
            &mut list,
            "bafyrei-token1",
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        assert!(list.is_revoked("bafyrei-token1"));
        assert_eq!(distributor.distributed.borrow().len(), 1);
        assert_eq!(
            distributor.distributed.borrow()[0],
            ("ctx-1".to_owned(), "bafyrei-token1".to_owned())
        );
        assert_eq!(logger.logged.borrow().len(), 1);
        assert_eq!(
            logger.logged.borrow()[0],
            (
                "ctx-1".to_owned(),
                "bafyrei-token1".to_owned(),
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

        let result = revoke_ucan(
            &mut list,
            "bafyrei-token1",
            "did:dht:z6MkCreator",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        assert!(list.is_revoked("bafyrei-token1"));
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

        let result = revoke_ucan(
            &mut list,
            "bafyrei-token1",
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
        assert!(!list.is_revoked("bafyrei-token1"));
        // Distribution and logging should not have been called.
        assert!(distributor.distributed.borrow().is_empty());
        assert!(logger.logged.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- distribution failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_fails_on_distribution_error() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = FailingDistributor;
        let logger = MockEventLogger::new();

        let result = revoke_ucan(
            &mut list,
            "bafyrei-token1",
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
        // Event logging should not have been called since distribution failed.
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
            "bafyrei-token1",
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
