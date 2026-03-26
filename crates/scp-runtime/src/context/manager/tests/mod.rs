use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use scp_protocol::context::params::MemoryScope;
use scp_protocol::context::{ContextMode, ContextState};
use scp_protocol::crypto::ucan::UcanToken;

mod broadcast;
mod governance;
mod lifecycle;
mod messaging;
mod queries;
mod trust_recovery;

// -----------------------------------------------------------------------
// Key resolver helpers for tests
// -----------------------------------------------------------------------

/// No-op key resolver that always returns `None`. Suitable for tests
/// that don't exercise governance vote signature verification.
pub(super) fn noop_key_resolver() -> KeyResolver {
    Arc::new(|_| None)
}

/// Derives a deterministic Ed25519 seed from a DID string.
/// Used by both `mock_key_resolver` and `signing_key_for_did` to
/// ensure signing keys and resolved verifying keys match.
pub(super) fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

/// Mock key resolver that returns a deterministic verifying key derived
/// from the DID string. Suitable for governance proposal tests that
/// need actual key resolution for vote verification.
pub(super) fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

/// Returns the signing key that corresponds to what `mock_key_resolver`
/// resolves for the given DID.
pub(super) fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

/// Creates an [`InMemoryKeyCustody`] and imports an Ed25519 signing key
/// from seed bytes, returning both the custody and the key handle.
///
/// Used by broadcast publish tests that need to pass custody + handle
/// to [`ContextManager::publish_broadcast`].
pub(super) async fn test_custody_from_seed(
    seed: &[u8; 32],
) -> (
    scp_platform::testing::InMemoryKeyCustody,
    scp_platform::KeyHandle,
) {
    let custody = scp_platform::testing::InMemoryKeyCustody::new();
    let handle = custody.import_ed25519_key(seed).await;
    (custody, handle)
}

// -----------------------------------------------------------------------
// Dummy UCAN for economy tests
// -----------------------------------------------------------------------

/// Returns a minimal [`UcanToken`] suitable for tests that need a spending
/// UCAN to pass the AND-composition gate (spec §19.5, #1593).
///
/// This token is structurally valid but not cryptographically signed.
/// The `check_and_composition` function only checks `Some` vs `None`,
/// so this suffices for unit tests. Positive-path testing with a real
/// signed JWT requires UCAN test fixtures (not yet built).
pub(super) fn dummy_spending_ucan() -> UcanToken {
    UcanToken {
        header: scp_protocol::crypto::ucan::UcanHeader::new(),
        payload: scp_protocol::crypto::ucan::UcanPayload {
            iss: "did:key:test-spender".to_owned(),
            aud: "did:key:test-context".to_owned(),
            exp: u64::MAX,
            nbf: None,
            nnc: "test-nonce".to_owned(),
            att: vec![],
            prf: vec![],
            fct: None,
        },
        signature: vec![],
        encoded: "test.spending.ucan".to_owned(),
    }
}

// -----------------------------------------------------------------------
// Reusable mock providers
// -----------------------------------------------------------------------

#[derive(Default)]
pub(super) struct MockCrypto {
    pub(super) fail_create_mls: AtomicBool,
    pub(super) fail_validate_key_package: AtomicBool,
    pub(super) fail_advance_epoch: AtomicBool,
    pub(super) fail_remove_member: AtomicBool,
    pub(super) fail_remove_member_sender_key: AtomicBool,
    pub(super) fail_rotate_sender_key: AtomicBool,
    pub(super) mls_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) sender_keys_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) broadcast_created: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) mls_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) sender_keys_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) members_added: std::sync::Mutex<Vec<String>>,
    pub(super) members_removed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_distributed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_removed: std::sync::Mutex<Vec<String>>,
    pub(super) sender_keys_rotated: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) messages_encrypted: std::sync::Mutex<Vec<Vec<u8>>>,
    pub(super) epochs_advanced: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Shared handle for test code to observe `advance_epoch` calls after
    /// the mock has been moved into the `ContextManager`.
    pub(super) epochs_advanced_shared: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
    /// Shared ordered call log for verifying cross-method call ordering.
    /// Each entry is a (`method_name`, arg) tuple recorded in call order.
    /// Used by `sender_key_before_mls_removal_ordering` to verify that
    /// `remove_member_sender_key` is called before `remove_member`.
    pub(super) call_order: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        if self.fail_create_mls.load(Ordering::Relaxed) {
            return Err(ContextCreationError::CryptoFailed("mock failure".into()));
        }
        self.mls_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.sender_keys_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.broadcast_created.lock().unwrap().push(*id);
        Ok(())
    }

    fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.mls_destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.sender_keys_destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        if self.fail_validate_key_package.load(Ordering::Relaxed) {
            return Err(ContextError::InvalidKeyPackage("mock invalid".into()));
        }
        Ok(())
    }

    fn add_member(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        self.members_added
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        Ok(scp_protocol::context::builder::AddMemberOutput::default())
    }

    fn remove_member(&self, _context_id: &[u8; 32], member_did: &str) -> Result<(), ContextError> {
        if self.fail_remove_member.load(Ordering::Relaxed) {
            return Err(ContextError::MembershipFailed(
                "mock remove_member failure".into(),
            ));
        }
        self.members_removed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        self.call_order
            .lock()
            .unwrap()
            .push(("remove_member".to_owned(), member_did.to_owned()));
        Ok(())
    }

    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        self.sender_keys_distributed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        Ok(())
    }

    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        member_did: &str,
    ) -> Result<(), ContextError> {
        if self.fail_remove_member_sender_key.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock remove_member_sender_key failure".into(),
            ));
        }
        self.sender_keys_removed
            .lock()
            .unwrap()
            .push(member_did.to_owned());
        self.call_order
            .lock()
            .unwrap()
            .push(("remove_member_sender_key".to_owned(), member_did.to_owned()));
        Ok(())
    }

    fn rotate_sender_key(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        if self.fail_rotate_sender_key.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock rotate_sender_key failure".into(),
            ));
        }
        self.sender_keys_rotated.lock().unwrap().push(*context_id);
        self.call_order
            .lock()
            .unwrap()
            .push(("rotate_sender_key".to_owned(), hex::encode(context_id)));
        Ok(())
    }

    fn seal(
        &self,
        _context_id: &[u8; 32],
        inner: &scp_protocol::envelope::inner::InnerEnvelope,
        _routing_id: &[u8],
        _blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        self.messages_encrypted
            .lock()
            .unwrap()
            .push(inner.payload.clone());
        // Mock: serialize inner envelope directly (no encryption).
        rmp_serde::to_vec_named(inner)
            .map_err(|e| ContextError::CryptoFailed(format!("mock seal: {e}")))
    }

    fn open(
        &self,
        _context_id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<Option<scp_protocol::context::builder::OpenedEnvelope>, ContextError> {
        // Mock: deserialize directly as InnerEnvelope (no decryption).
        let inner: scp_protocol::envelope::inner::InnerEnvelope =
            rmp_serde::from_slice(outer_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("mock open: {e}")))?;
        let sender_did = inner.sender_did.clone();
        Ok(Some(scp_protocol::context::builder::OpenedEnvelope {
            inner,
            sender_did,
        }))
    }

    fn advance_epoch(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        if self.fail_advance_epoch.load(Ordering::Relaxed) {
            return Err(ContextError::CryptoFailed(
                "mock advance_epoch failure".into(),
            ));
        }
        self.epochs_advanced.lock().unwrap().push(*context_id);
        self.epochs_advanced_shared
            .lock()
            .unwrap()
            .push(*context_id);
        Ok(())
    }
}

pub(super) struct MockTransport {
    pub(super) connected: AtomicBool,
    pub(super) published: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) deleted: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) messages_sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// Routing IDs passed to `send_message`. Each entry corresponds 1:1
    /// with `messages_sent`.
    pub(super) routing_ids_sent: Arc<std::sync::Mutex<Vec<[u8; 32]>>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self {
            connected: AtomicBool::new(false),
            published: std::sync::Mutex::new(Vec::new()),
            deleted: std::sync::Mutex::new(Vec::new()),
            messages_sent: Arc::new(std::sync::Mutex::new(Vec::new())),
            routing_ids_sent: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl MockTransport {
    pub(super) fn connected() -> Self {
        let t = Self::default();
        t.connected.store(true, Ordering::Relaxed);
        t
    }

    /// Returns a shared handle to the sent-messages buffer.
    /// Clone before moving the transport into `ContextManager` to observe
    /// transport output from test code.
    pub(super) fn sent_messages_handle(&self) -> Arc<std::sync::Mutex<Vec<Vec<u8>>>> {
        Arc::clone(&self.messages_sent)
    }

    /// Returns a shared handle to the routing IDs buffer.
    pub(super) fn routing_ids_handle(&self) -> Arc<std::sync::Mutex<Vec<[u8; 32]>>> {
        Arc::clone(&self.routing_ids_sent)
    }
}

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn publish_context(
        &self,
        id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.published.lock().unwrap().push(*id);
        Ok(())
    }

    fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.deleted.lock().unwrap().push(*id);
        Ok(())
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        self.routing_ids_sent.lock().unwrap().push(*context_id);
        self.messages_sent
            .lock()
            .unwrap()
            .push(encrypted_payload.to_vec());
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct MockEventLog {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    pub(super) events: std::sync::Mutex<Vec<([u8; 32], String)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        _actor_did: &str,
    ) -> Result<(), ContextCreationError> {
        self.events.lock().unwrap().push((*id, event.to_owned()));
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }
}

/// Extended event log mock that stores `actor_did` and supports
/// `event_log_entries()` reads. Used by tests that verify `actor_did`
/// attribution on event log entries (#1594).
#[derive(Default)]
pub(super) struct MockEventLogWithActorDid {
    pub(super) inited: std::sync::Mutex<Vec<[u8; 32]>>,
    /// Each entry: (`context_id`, `event_name`, `actor_did`, timestamp).
    pub(super) entries: std::sync::Mutex<Vec<([u8; 32], String, String, u64)>>,
    pub(super) destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
}

impl ContextEventLogProvider for MockEventLogWithActorDid {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.inited.lock().unwrap().push(*id);
        Ok(())
    }

    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
    ) -> Result<(), ContextCreationError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries
            .lock()
            .unwrap()
            .push((*id, event.to_owned(), actor_did.to_owned(), ts));
        Ok(())
    }

    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.destroyed.lock().unwrap().push(*id);
        Ok(())
    }

    fn event_log_entries(
        &self,
        context_id: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let entries = self.entries.lock().unwrap();
        let result: Vec<_> = entries
            .iter()
            .filter(|(cid, _, _, _)| cid == context_id)
            .map(
                |(_, event, actor_did, ts)| crate::context::providers::event_log::EventLogEntry {
                    event: event.clone(),
                    actor_did: actor_did.clone(),
                    timestamp: *ts,
                    prev_hash: [0u8; 32],
                    hash: [0u8; 32],
                },
            )
            .collect();
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

/// A transport mock that always fails on `send_message`.
/// Used to test that phantom `MessageSent` events are not emitted
/// when transport fails (#1420).
pub(super) struct FailingTransport;

impl ContextTransportProvider for FailingTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        _context_id: &[u8; 32],
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Err(ContextError::TransportFailed(
            "mock transport failure".into(),
        ))
    }
}

// -----------------------------------------------------------------------
// Helper: create a manager with default mocks and a registered context
// -----------------------------------------------------------------------

pub(super) async fn setup_active_context() -> (ContextManager, ContextHandle) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    let params = ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::ToolRegister,
            Capability::ToolInterface,
            Capability::ChildContextCreate,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("test-ctx".into(), params, "did:key:creator".into())
        .await
        .unwrap();

    (manager, handle)
}

// -----------------------------------------------------------------------
// Shared helpers used across multiple test files
// -----------------------------------------------------------------------

/// Helper: creates an approved governance proposal for an arbitrary action
/// using `SingleAdminEngine`. The admin is `admin_did`.
pub(super) fn approved_governance_proposal(
    admin_did: &DID,
    context_id: &str,
    target_did: &DID,
    action: super::GovernanceAction,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![
            (admin_did.clone(), "admin".to_owned()),
            (target_did.clone(), "subscriber".to_owned()),
        ],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}

/// Helper to create a broadcast context with two authors (alice + bob).
///
/// Both authors are registered in the `BroadcastContext` (for publish
/// capability) and in `MembershipState` (for sequence number tracking).
/// Both author DIDs are registered as locally controlled (#234).
pub(super) async fn setup_broadcast_context_two_authors() -> (ContextManager, ContextHandle, String)
{
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Register both author DIDs as locally controlled (#234).
    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("broadcast-2auth-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();

    // Add bob as a second author: both in BroadcastContext and membership.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("broadcast-2auth-ctx").unwrap();
        let bc = ctx.broadcast_context.as_mut().unwrap();
        bc.add_author("did:key:bob").unwrap();
        // Also add to membership tracking so sequence numbers work.
        ctx.membership
            .add_member("did:key:bob".into(), "author".into(), vec![]);
    }

    let ctx_id = "broadcast-2auth-ctx".to_owned();
    (manager, handle, ctx_id)
}

/// Helper: creates a broadcast context with `MemberBan` in ceiling,
/// admin (alice) and subscriber (sub1).
pub(super) async fn setup_broadcast_with_member_ban() -> (ContextManager, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    manager.register_local_did("did:key:alice".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("member:ban"),
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("broadcast-ban-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();

    // Subscribe sub1 directly via BroadcastContext.
    {
        use scp_protocol::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                "broadcast-ban-ctx",
                &DID("did:key:sub1".into()),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
    }

    let ctx_id = "broadcast-ban-ctx".to_owned();
    (manager, ctx_id)
}

/// Helper: creates an encrypted context with `MemberBan` in ceiling,
/// admin (alice) and member (bob).
pub(super) async fn setup_encrypted_with_member_ban() -> (ContextManager, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    manager.register_local_did("did:key:alice".into()).await;
    manager.register_local_did("did:key:bob".into()).await;

    let params = ContextParams {
        mode: ContextMode::Encrypted,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberBan,
        ],
        ..ContextParams::default()
    };

    let _handle = manager
        .create_context("enc-ban-ctx".into(), params, "did:key:alice".into())
        .await
        .unwrap();

    // Add bob as a member.
    {
        let mut contexts = manager.contexts.lock().await;
        let ctx = contexts.get_mut("enc-ban-ctx").unwrap();
        ctx.membership
            .add_member("did:key:bob".into(), "member".into(), vec![]);
    }

    (manager, "enc-ban-ctx".to_owned())
}

/// Helper: `ContextParams` with governance-compatible ceiling.
pub(super) fn governance_params() -> ContextParams {
    ContextParams {
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
            scp_protocol::context::params::Capability::new("governance:propose"),
            scp_protocol::context::params::Capability::new("governance:vote"),
            scp_protocol::context::params::Capability::new("member:ban"),
            scp_protocol::context::params::Capability::new("context:close"),
            Capability::ToolRegister,
        ],
        ..ContextParams::default()
    }
}

/// Helper: create a `ToolRegistration` fixture.
pub(super) fn test_tool_registration(id: &str) -> ToolRegistration {
    use scp_protocol::context::tools::registry::{TestVector, ToolSchema};
    ToolRegistration {
        tool_id: id.to_owned(),
        name: id.to_owned(),
        description: "test tool".to_owned(),
        schema: ToolSchema {
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: serde_json::json!({"type": "object"}),
        },
        implementation_hash: [0u8; 32],
        test_vectors: vec![TestVector {
            input: serde_json::json!({}),
            expected_output: serde_json::json!({}),
            description: "noop".to_owned(),
        }],
        operator_did: "did:key:test-operator".into(),
        cost: None,
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Helper: creates a broadcast context with an author (author1),
/// registers `did:key:author1` as a local DID.
pub(super) async fn setup_broadcast_context() -> (ContextManager, ContextHandle, String) {
    let manager = ContextManager::new(
        Box::new(MockCrypto::default()),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog::default()),
        noop_key_resolver(),
    );

    // Register the author DID as locally controlled (#234).
    manager.register_local_did("did:key:author1".into()).await;

    let params = ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: scp_protocol::context::MemoryScope::Full,
        ceiling: vec![
            scp_protocol::context::params::Capability::new("messages:read"),
            scp_protocol::context::params::Capability::new("messages:write"),
            scp_protocol::context::params::Capability::new("role:assign"),
        ],
        ..ContextParams::default()
    };

    let handle = manager
        .create_context("broadcast-ctx".into(), params, "did:key:author1".into())
        .await
        .unwrap();

    (manager, handle, "broadcast-ctx".into())
}

/// Helper: creates an approved `BlockAuthor` governance proposal using
/// `SingleAdminEngine` (admin = `admin_did`). Returns the approved
/// proposal that can be passed to `execute_governance_action()`.
pub(super) fn approved_block_author_proposal(
    admin_did: &DID,
    context_id: &str,
    target_did: &DID,
) -> super::GovernanceProposal {
    use scp_protocol::context::governance::{
        GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
    };

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let vk = signing_key.verifying_key();
    #[allow(clippy::type_complexity)]
    let resolver: std::sync::Arc<
        dyn Fn(&scp_identity::DID) -> Option<ed25519_dalek::VerifyingKey> + Send + Sync,
    > = std::sync::Arc::new(move |_| Some(vk));
    let mut engine = SingleAdminEngine::new(admin_did.clone(), resolver);
    let gov_ctx = GovernanceContext {
        context_id: context_id.to_owned(),
        members: vec![
            (admin_did.clone(), "admin".to_owned()),
            (target_did.clone(), "author".to_owned()),
        ],
        admin_dids: vec![admin_did.clone()],
        current_epoch: None,
        now: 1000,
    };

    let action = GovernanceAction::BlockAuthor {
        did: target_did.clone(),
        reason: Some("governance test".to_owned()),
    };

    let (proposal, _events) = engine
        .propose(admin_did, action, &gov_ctx, &signing_key)
        .unwrap();
    assert!(matches!(proposal.status, super::ProposalStatus::Approved));
    proposal
}
