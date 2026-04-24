//! Full-stack test node wrapping `ContextManager` with real crypto.
//!
//! Each `FullStackNode` owns a `ContextManager` backed by:
//! - [`E2eCryptoProvider`] — real MLS + sender keys with shared `KeyExchange`
//! - [`CapturingTransport`] — captures sent ciphertexts for retrieval by tests
//! - `MerkleEventLogProvider` — real Merkle-chained event log

use std::sync::{Arc, Mutex};

use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::{ContextEvent, KeyPackage};
use scp_core::context::providers::event_log::MerkleEventLogProvider;
use scp_core::context::{ContextError, ContextHandle, ContextManager, ContextParams};
use scp_identity::DID;

use super::crypto::E2eCryptoProvider;

/// Derives a deterministic 32-byte seed from a DID string for test key generation.
fn did_to_seed(did: &DID) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    did.as_ref().hash(&mut hasher);
    let h = hasher.finish();
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&h.to_le_bytes());
    seed
}

// ---------------------------------------------------------------------------
// CapturingTransport — stores sent ciphertexts for test retrieval
// ---------------------------------------------------------------------------

/// Shared buffer of `(context_id, ciphertext)` pairs.
type SentBuffer = Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>;

/// Transport provider that captures sent ciphertexts in a shared buffer.
///
/// After `ContextManager::send_message` encrypts and "sends" a message,
/// the ciphertext is stored here. Tests retrieve it via
/// `FullStackNode::take_sent_ciphertexts` and feed it to the receiver's
/// `decrypt_message`.
#[derive(Clone)]
struct CapturingTransport {
    /// `(context_id, ciphertext)` pairs, in send order.
    sent: SentBuffer,
}

impl CapturingTransport {
    const fn new(sent: SentBuffer) -> Self {
        Self { sent }
    }
}

#[allow(clippy::significant_drop_tightening)]
impl ContextTransportProvider for CapturingTransport {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sent.push((*context_id, encrypted_payload.to_vec()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FullStackNode
// ---------------------------------------------------------------------------

/// A test node with real `ContextManager`, real MLS crypto, and real event log.
///
/// Use `FullStackNetwork::create_node()` to construct nodes with a shared
/// `KeyExchange`.
pub struct FullStackNode {
    /// This node's DID.
    pub did: DID,
    /// The `ContextManager` with real crypto.
    pub manager: ContextManager,
    /// Direct access to the crypto provider for `join_from_welcome` and
    /// `decrypt_message` (methods not on the `ContextCryptoProvider` trait).
    pub crypto: Arc<E2eCryptoProvider>,
    /// The event log provider (for Merkle root verification in tests).
    pub event_log: Arc<MerkleEventLogProvider>,
    /// Deterministic signing key derived from this node's DID.
    signing_key: ed25519_dalek::SigningKey,
    /// Sent ciphertexts captured by the transport, shared with the manager.
    sent: SentBuffer,
}

impl FullStackNode {
    /// Creates a new full-stack node.
    ///
    /// # Arguments
    ///
    /// * `did` - This node's DID.
    /// * `crypto` - The E2E crypto provider (shared `KeyExchange` inside).
    /// * `key_resolver` - Resolver for governance vote verification.
    #[must_use]
    pub fn new(did: DID, crypto: Arc<E2eCryptoProvider>, key_resolver: KeyResolver) -> Self {
        let event_log = Arc::new(MerkleEventLogProvider::new());
        let sent: SentBuffer = Arc::new(Mutex::new(Vec::new()));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&did_to_seed(&did));

        let crypto_box: Box<dyn ContextCryptoProvider> =
            Box::new(ArcCryptoProvider(Arc::clone(&crypto)));
        let event_log_box: Box<dyn ContextEventLogProvider> =
            Box::new(ArcEventLogProvider(Arc::clone(&event_log)));
        let transport_box: Box<dyn ContextTransportProvider> =
            Box::new(CapturingTransport::new(Arc::clone(&sent)));

        let manager = ContextManager::new(crypto_box, transport_box, event_log_box, key_resolver);

        Self {
            did,
            manager,
            crypto,
            event_log,
            signing_key,
            sent,
        }
    }

    /// Creates a context and returns the handle.
    ///
    /// Also copies the creator's access key from the `ContextManager` into
    /// the `E2eCryptoProvider` so that `decrypt_message` (which reads from
    /// the crypto provider's local store) can find it. The `ContextManager`
    /// generates and stores the key in `PerContextState` during creation,
    /// but the `E2eCryptoProvider` has a separate access key store.
    ///
    /// # Errors
    ///
    /// Propagates `ContextCreationError` from `ContextManager`.
    pub async fn create_context(
        &self,
        context_id: &str,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        let handle = self
            .manager
            .create_context(context_id.to_owned(), params, self.did.clone(), [0u8; 32])
            .await?;

        // Copy the creator's access key from ContextManager's PerContextState
        // into E2eCryptoProvider's local store. Must use the SAME key (not a
        // newly generated one) because access keys are random — generating
        // a second key would produce a different value, causing AES-256-KW
        // integrity check failures on unwrap.
        if let Some(creator_key) = self
            .manager
            .get_access_key(context_id, self.did.as_ref())
            .await
        {
            self.crypto
                .set_access_key(context_id, self.did.as_ref(), creator_key);
        }

        Ok(handle)
    }

    /// Adds a member to the context (Alice-side operation).
    ///
    /// This calls `join_context` on the manager, which internally calls
    /// `crypto.add_member` (capturing the Welcome) and
    /// `crypto.distribute_sender_key` (depositing the sender key).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from `ContextManager`.
    pub async fn add_member(
        &self,
        handle: &ContextHandle,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let kp = KeyPackage::mock(DID::from(member_did));
        self.manager
            .join_context(handle, kp, None, [0u8; 32])
            .await?;

        // Deposit ALL existing members' access keys in the KeyExchange for
        // the joiner. This includes:
        // - The new member's own key (generated by join_context)
        // - The inviter's key (generated by create_context)
        // - Any previously-joined members' keys
        //
        // Access keys are random (OsRng), so the joiner cannot regenerate
        // them — they must be transferred from the inviter's PerContextState.
        let context_id = handle.context_id();
        let all_keys = self.manager.get_all_access_keys(context_id).await;
        for (did, key) in all_keys {
            self.crypto
                .deposit_access_key(context_id, member_did, &did, key);
        }
        Ok(())
    }

    /// Joins a context by retrieving the Welcome from the `KeyExchange`.
    ///
    /// This is the Bob-side operation. It calls `crypto.join_from_welcome`
    /// which retrieves the Welcome and sender keys deposited by Alice,
    /// then picks up the access key deposited by the inviter.
    ///
    /// # Arguments
    ///
    /// * `context_id_str` - The original string context ID (needed for
    ///   access key lookup in the `KeyExchange`).
    /// * `context_id` - The 32-byte SHA-256 hash of the context ID.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if no Welcome is available.
    pub fn join_from_welcome(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        self.crypto.join_from_welcome(context_id)?;

        // Pick up ALL access keys deposited by the inviter so this node
        // can decrypt messages and send to all members. The inviter deposits
        // every existing member's key (including the joiner's own) during
        // `add_member`.
        self.crypto.pickup_access_keys(context_id_str);

        Ok(())
    }

    /// Copies access keys from the `E2eCryptoProvider`'s local store into
    /// the `ContextManager`'s `PerContextState`.
    ///
    /// Must be called after [`join_from_welcome`](Self::join_from_welcome)
    /// (which populates the crypto provider's store from the `KeyExchange`)
    /// and from an async context (needs the async contexts lock).
    /// Ensures `send_message` wraps content for all recipients.
    pub async fn sync_access_keys_to_manager(&self, context_id_str: &str, context_id: &[u8; 32]) {
        let members = self.crypto.context_members(context_id);
        for member_did in &members {
            if let Some(key) = self.crypto.get_access_key(context_id_str, member_did) {
                self.manager
                    .inject_access_key(context_id_str, member_did, key)
                    .await;
            }
        }
    }

    /// Sends a message through `ContextManager` (encrypts with real crypto).
    ///
    /// The encrypted ciphertext is captured by the transport and can be
    /// retrieved via [`take_sent_ciphertexts`](Self::take_sent_ciphertexts).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from `ContextManager`.
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        payload: &[u8],
    ) -> Result<(), ContextError> {
        self.manager
            .send_message(
                handle,
                &self.did,
                payload,
                Some(&self.signing_key),
                None,
                None,
            )
            .await
    }

    /// Takes all captured ciphertexts sent by this node.
    ///
    /// Returns `(context_id_bytes, ciphertext)` pairs and clears the buffer.
    pub fn take_sent_ciphertexts(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *sent)
    }

    /// Processes any pending MLS commits for this node in the given context.
    ///
    /// Must be called before `decrypt_message` if another member added a
    /// third party since this node last synced (the MLS epoch advances and
    /// this node needs to process the Commit to stay current).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if commit processing fails.
    pub fn process_pending_commits(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.process_pending_commits(context_id)
    }

    /// Decrypts a message through the full envelope pipeline.
    ///
    /// Handles: process pending MLS commits → open outer envelope → MLS
    /// decrypt → sender key decrypt → deserialize `InnerEnvelope` → strip
    /// padding → verify integrity → unwrap access key → return plaintext.
    ///
    /// # Arguments
    ///
    /// * `context_id_str` - The original string context ID (for access key lookup).
    /// * `context_id` - The 32-byte SHA-256 hash of the context ID.
    /// * `ciphertext` - The serialized `OuterEnvelope` bytes from transport.
    /// * `sender_did` - The DID of the sender (for access key unwrapping AAD).
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` if any decryption or verification step fails.
    pub fn decrypt_message(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
        ciphertext: &[u8],
        sender_did: &str,
    ) -> Result<Vec<u8>, ContextError> {
        use scp_core::context::builder::ContextCryptoProvider;

        // Process any pending commits first to sync the MLS epoch.
        self.crypto.process_pending_commits(context_id)?;

        // Open: deserialize outer envelope → MLS decrypt → sender key
        // decrypt → deserialize InnerEnvelope → strip padding → verify hash.
        let open_result = self.crypto.open(context_id, ciphertext)?;
        let opened = match open_result {
            scp_core::context::builder::OpenResult::Application(env) => *env,
            scp_core::context::builder::OpenResult::Control => {
                return Err(ContextError::CryptoFailed("open returned Control".into()));
            }
            scp_core::context::builder::OpenResult::Management {
                sender_did,
                payload,
            } => {
                self.crypto
                    .process_incoming_sender_key(context_id, &sender_did, &payload)?;
                return Err(ContextError::CryptoFailed(
                    "open returned Management".into(),
                ));
            }
        };

        // Strip padding to recover the serialized WrappedContent.
        let stripped = scp_core::envelope::strip_padding(&opened.inner.payload)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Deserialize WrappedContent and unwrap access key layer.
        let wrapped: scp_core::crypto::access_keys::WrappedContent =
            rmp_serde::from_slice(&stripped).map_err(|e| {
                ContextError::CryptoFailed(format!("WrappedContent deserialization: {e}"))
            })?;

        let local_did = self.did.as_ref().to_string();
        let access_key = self
            .crypto
            .get_access_key(context_id_str, &local_did)
            .ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "no access key for {local_did} in context {context_id_str}"
                ))
            })?;

        scp_core::crypto::access_keys::wrapping::unwrap_content(
            &wrapped,
            &local_did,
            &access_key,
            context_id_str,
            sender_did,
            0,
            0,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))
    }

    /// Regenerates the local sender key and distributes it to all members.
    ///
    /// Call this after `join_from_welcome` so the joiner's sender key is
    /// deposited in the `KeyExchange` for existing members to pick up.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from the crypto provider.
    pub fn regenerate_and_distribute_sender_key(
        &self,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        self.crypto.regenerate_and_distribute_sender_key(context_id)
    }

    /// Picks up any pending sender keys from the shared `KeyExchange`.
    ///
    /// Call this after another node has distributed its sender key so this
    /// node can decrypt messages from that sender.
    ///
    /// # Errors
    ///
    /// Propagates `ContextError` from the crypto provider.
    pub fn pickup_sender_keys(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.pickup_sender_keys(context_id)
    }

    /// Drains events from the `ContextManager`.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.manager.drain_events(context_id).await
    }

    /// Returns the Merkle root of the event log for a context.
    ///
    /// # Errors
    ///
    /// Returns error if no event log exists for the context.
    pub fn merkle_root(&self, context_id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.event_log.event_log_merkle_root(context_id)
    }
}

// ---------------------------------------------------------------------------
// Arc wrapper newtypes — delegate trait methods to the inner Arc
// ---------------------------------------------------------------------------

/// Newtype wrapping `Arc<E2eCryptoProvider>` to implement `ContextCryptoProvider`.
struct ArcCryptoProvider(Arc<E2eCryptoProvider>);

impl ContextCryptoProvider for ArcCryptoProvider {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        self.0.validate_creator_identity()
    }
    fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.create_mls_group(id)
    }
    fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.generate_sender_key(id)
    }
    fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_broadcast_key(id)
    }
    fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_mls_group(id)
    }
    fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_sender_key(id)
    }
    fn validate_key_package(&self, did: &str, kp: Option<&[u8]>) -> Result<(), ContextError> {
        self.0.validate_key_package(did, kp)
    }
    fn add_member(
        &self,
        id: &[u8; 32],
        did: &str,
        kp: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, ContextError> {
        self.0.add_member(id, did, kp)
    }
    fn remove_member(
        &self,
        id: &[u8; 32],
        did: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, ContextError> {
        self.0.remove_member(id, did)
    }
    fn distribute_sender_key(&self, id: &[u8; 32], did: &str) -> Result<(), ContextError> {
        self.0.distribute_sender_key(id, did)
    }
    fn remove_member_sender_key(&self, id: &[u8; 32], did: &str) -> Result<(), ContextError> {
        self.0.remove_member_sender_key(id, did)
    }
    fn drain_pending_sender_key_messages(
        &self,
        id: &[u8; 32],
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        self.0.drain_pending_sender_key_messages(id)
    }
    fn process_incoming_sender_key(
        &self,
        id: &[u8; 32],
        did: &str,
        msg: &[u8],
    ) -> Result<(), ContextError> {
        self.0.process_incoming_sender_key(id, did, msg)
    }
    fn handle_sender_key_request(
        &self,
        id: &[u8; 32],
        req: &[u8],
        pk: &[u8],
        blocked_dids: &std::collections::HashSet<String>,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        self.0.handle_sender_key_request(id, req, pk, blocked_dids)
    }
    fn advance_epoch(
        &self,
        id: &[u8; 32],
    ) -> Result<scp_core::context::AdvanceEpochOutput, ContextError> {
        self.0.advance_epoch(id)
    }
    fn seal(
        &self,
        id: &[u8; 32],
        inner: &scp_core::envelope::inner::InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        self.0.seal(id, inner, routing_id, blob_ttl)
    }
    fn open(
        &self,
        id: &[u8; 32],
        outer_bytes: &[u8],
    ) -> Result<scp_core::context::builder::OpenResult, ContextError> {
        self.0.open(id, outer_bytes)
    }
}

/// Newtype wrapping `Arc<MerkleEventLogProvider>` to implement `ContextEventLogProvider`.
struct ArcEventLogProvider(Arc<MerkleEventLogProvider>);

impl ContextEventLogProvider for ArcEventLogProvider {
    fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id)
    }
    fn append_event(
        &self,
        id: &[u8; 32],
        event: &str,
        actor_did: &str,
        payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        self.0.append_event(id, event, actor_did, payload)
    }
    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }
    fn export_event_log_data(&self, id: &[u8; 32]) -> Result<Vec<u8>, ContextError> {
        self.0.export_event_log_data(id)
    }
    fn import_event_log_data(&self, id: &[u8; 32], data: &[u8]) -> Result<(), ContextError> {
        self.0.import_event_log_data(id, data)
    }
    fn event_log_merkle_root(&self, id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.0.event_log_merkle_root(id)
    }
    fn restore_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.restore_event_log(id)
    }
    fn prune_before_checkpoint(
        &self,
        context_id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_core::context::governance::PruningPolicy,
    ) -> Option<usize> {
        self.0
            .prune_before_checkpoint(context_id, checkpoint_event_count, policy)
    }
}
