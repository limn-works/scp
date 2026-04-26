//! `SupervisorHandle` — capability-reduced supervisor surface held by
//! actors via [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §5 and plan §"ActorDeps and SupervisorHandle" the handle
//! must **not** expose any method that returns a
//! [`ContextActorHandle`](crate::context::actor::handle::ContextActorHandle).
//! Actors cannot reach sibling actors; cross-context work goes through
//! [`SupervisorHandle::start_saga`]. This is the capability-reduction mechanism:
//! the inner `Arc<Supervisor>` is private and no accessor exposes it.
//!
//! # `&OwnedIdentityDid` parameters
//!
//! Methods that touch per-identity state take `&OwnedIdentityDid`, not
//! `&DID`. [`OwnedIdentityDid`](super::identity_capability::OwnedIdentityDid)
//! is `pub(super)` inside the `supervisor/` module — this file is inside
//! that module so it CAN name the type. Handler code in
//! `actor/handlers/` cannot reach the type's constructor path and
//! therefore cannot call these methods with a fabricated token. See
//! plan §"`OwnedIdentityDid` capability tag".

use std::collections::HashSet;
use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::ContextError;

use crate::context::supervisor::identity_capability::OwnedIdentityDid;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::supervisor::{SagaInput, SagaOutput, Supervisor};

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Capability-reduced view of `Supervisor` held by actors. Cloned into
/// each actor's `ActorDeps` and never exposed outside `crate::context::`.
///
/// **No `ContextActorHandle` accessor.** This is the mechanical contract
/// that makes "actors cannot reach sibling actors" a type-system
/// property. The inner `Arc<Supervisor>` field is private; no public
/// method returns it. Cross-context work MUST go through
/// [`Self::start_saga`].
#[derive(Clone)]
pub struct SupervisorHandle {
    supervisor: Arc<Supervisor>,
}

impl SupervisorHandle {
    /// Wrap an `Arc<Supervisor>`. Visible only to supervisor-module
    /// code; the bridge instance constructs one at actor spawn time
    /// (commit 11 wires this through), and handlers receive the handle
    /// via `ActorDeps` at dispatch time.
    ///
    /// `dead_code` allow: commit 6 lands the constructor; the first
    /// production caller lands with the `BridgeInstance` integration
    /// in commit 11. The allow is removed then.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context::supervisor) const fn wrap(supervisor: Arc<Supervisor>) -> Self {
        Self { supervisor }
    }

    /// Start a cross-context saga. The ONLY way for an actor to affect
    /// state in another context.
    ///
    /// # Errors
    ///
    /// See `Supervisor::start_saga`. Commit 6: always
    /// [`ContextError::NotImplemented`].
    pub async fn start_saga(&self, input: SagaInput) -> Result<SagaOutput, ContextError> {
        self.supervisor.start_saga(input).await
    }

    /// Snapshot the local-DIDs set. Returned as an `Arc` so callers read
    /// without copying; the snapshot is stable for its lifetime even if
    /// the supervisor rotates the underlying `ArcSwap` mid-read.
    #[must_use]
    pub fn local_dids(&self) -> Arc<HashSet<DID>> {
        self.supervisor.local_dids.load_full()
    }

    /// Look up the registered standing-context peer DID for `peer_did`.
    /// Returns `None` if the peer has no registered standing context.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1): the prior
    /// signature took `ctx_id: &str` but the underlying
    /// `standing_contexts: ArcSwap<HashMap<String, DID>>` is keyed by
    /// the peer DID's `to_string()` form (see `standing_helpers.rs`
    /// lines 161/230/291). Querying by context ID always returned
    /// `None`. The renamed parameter matches the actual key shape; the
    /// lookup is now correct.
    #[must_use]
    pub fn standing_peer(&self, peer_did: &DID) -> Option<DID> {
        self.supervisor
            .standing_contexts
            .load()
            .get(peer_did.as_ref())
            .cloned()
    }

    /// Look up this identity's wrapping public key. Returns `None` if
    /// the identity has not set a wrapping keypair yet.
    ///
    /// Takes `&OwnedIdentityDid` — not `&DID` — so the caller must hold
    /// the capability proof that they are the actor for this identity.
    /// The token is constructed only in `supervisor/` code
    /// (`pub(super)` constructor); handler code cannot fabricate it.
    ///
    /// Visibility is `pub(in crate::context)` rather than `pub` because
    /// `OwnedIdentityDid` is `pub(super)` inside `supervisor/`.
    /// The narrower visibility scopes call-site reachability to handler
    /// code under `crate::context::actor::handlers/`.
    ///
    /// `private_interfaces` is allowed: the deliberate-by-design
    /// asymmetry (the type is more private than the method) is the
    /// capability discipline. Handlers receive `&OwnedIdentityDid`
    /// references through `ActorDeps`; they cannot construct one
    /// because `OwnedIdentityDid::issue_for_actor` is `pub(super)`
    /// inside `supervisor/`.
    #[must_use]
    #[allow(private_interfaces, dead_code)]
    pub(in crate::context) fn my_wrapping_public_key(
        &self,
        identity: &OwnedIdentityDid,
    ) -> Option<Arc<Vec<u8>>> {
        let did = identity.as_did();
        self.supervisor
            .wrapping_keys
            .get(did)
            .map(|entry| Arc::new(entry.value().load_full().public.to_vec()))
    }

    /// Look up this identity's `KeyPackageStoreActor` handle. Returns
    /// `None` if no KeyPackage actor has been spawned for the identity.
    ///
    /// Same capability discipline as [`Self::my_wrapping_public_key`].
    /// Visibility is `pub(in crate::context)` for the same reason.
    /// `private_interfaces` is allowed for the same deliberate
    /// asymmetry documented there.
    #[must_use]
    #[allow(private_interfaces, dead_code)]
    pub(in crate::context) fn my_key_package_store(
        &self,
        identity: &OwnedIdentityDid,
    ) -> Option<KeyPackageStoreHandle> {
        let did = identity.as_did();
        self.supervisor
            .key_package_stores
            .get(did)
            .map(|r| r.value().clone())
    }
}

// Explicit non-exposure check: ensure no public method returns
// `ContextActorHandle` or `Arc<Supervisor>`. This is enforced by the
// methods above (none do), but the file-level contract is documented
// here so future edits see the rule.
//
// Any method added to this impl that returns `ContextActorHandle`,
// `Arc<Supervisor>`, `&Supervisor`, or `&mut Supervisor` breaks the
// capability-reduction contract. Plan §"Mechanical enforcement" adds a
// CI grep-ban against those return types in this file in commit 12.

// ---------------------------------------------------------------------------
// Forbidden trait impls — compile-time checklist
// ---------------------------------------------------------------------------

// Do NOT impl:
// - `Deref<Target = Supervisor>` — would leak `&Supervisor` via auto-deref.
// - `AsRef<Supervisor>` — would leak `&Supervisor`.
// - `From<SupervisorHandle> for Arc<Supervisor>` — would smuggle the
//   Arc out past the capability boundary.
//
// These are documentation, not static assertions — Rust has no
// "forbid impl of trait X" attribute. The CI grep-ban landing in
// commit 12 is the mechanical enforcement.

// Compile-time witness that `SupervisorHandle` is `Send + Sync` — the
// handle rides inside `ActorDeps`, which is moved into `tokio::spawn`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SupervisorHandle>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::actor::state::WrappingKeyPair;
    use crate::context::supervisor::key_package_actor::KeyPackageStoreActor;
    use crate::context::supervisor::saga_journal::{ProtocolRepositorySagaJournal, SagaJournal};
    use crate::context::supervisor::supervisor::SupervisorConfig;
    use arc_swap::ArcSwap;
    use scp_platform::testing::InMemoryStorage;
    use zeroize::Zeroizing;

    struct TestPersistence;
    impl crate::context::persistence::ContextPersistence for TestPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    fn test_handle() -> (Arc<Supervisor>, SupervisorHandle) {
        let persistence: Arc<dyn crate::context::persistence::ContextPersistence> =
            Arc::new(TestPersistence);
        let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
            InMemoryStorage::new(),
        )));
        let sup = Arc::new(Supervisor::new(
            persistence,
            journal,
            SupervisorConfig::default(),
        ));
        let handle = SupervisorHandle::wrap(Arc::clone(&sup));
        (sup, handle)
    }

    #[tokio::test]
    async fn local_dids_returns_empty_snapshot_on_fresh_supervisor() {
        let (_sup, handle) = test_handle();
        assert!(handle.local_dids().is_empty());
    }

    #[tokio::test]
    async fn standing_peer_returns_none_when_unknown() {
        let (_sup, handle) = test_handle();
        let unknown = DID("did:example:never-registered".to_owned());
        assert!(handle.standing_peer(&unknown).is_none());
    }

    #[tokio::test]
    async fn start_saga_propagates_not_implemented() {
        let (_sup, handle) = test_handle();
        let err = handle
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn my_wrapping_public_key_returns_none_when_unset() {
        let (_sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did);
        assert!(handle.my_wrapping_public_key(&token).is_none());
    }

    #[tokio::test]
    async fn my_wrapping_public_key_reads_registered_value() {
        let (sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let kp = WrappingKeyPair {
            public: [0x42; 32],
            secret: Zeroizing::new([0u8; 32]),
        };
        sup.wrapping_keys
            .insert(did.clone(), ArcSwap::new(Arc::new(kp)));
        let token = OwnedIdentityDid::issue_for_actor(did);
        let got = handle.my_wrapping_public_key(&token).unwrap();
        assert_eq!(&*got, &vec![0x42u8; 32]);
    }

    #[tokio::test]
    async fn my_key_package_store_returns_none_when_unset() {
        let (_sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let token = OwnedIdentityDid::issue_for_actor(did);
        assert!(handle.my_key_package_store(&token).is_none());
    }

    #[tokio::test]
    async fn my_key_package_store_returns_registered_handle() {
        let (sup, handle) = test_handle();
        let did = DID("did:example:alice".to_owned());
        let kp_handle = KeyPackageStoreActor::spawn(did.clone());
        sup.key_package_stores.insert(did.clone(), kp_handle);
        let token = OwnedIdentityDid::issue_for_actor(did);
        let got = handle.my_key_package_store(&token);
        assert!(got.is_some());
        if let Some(h) = got {
            h.send_shutdown().await.unwrap();
        }
    }

    #[test]
    fn handle_is_clone_send_sync() {
        const fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<SupervisorHandle>();
    }
}
