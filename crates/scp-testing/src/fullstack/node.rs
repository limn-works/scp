//! Full-stack test node wrapping a real `Supervisor` with real crypto.
//!
//! Each `FullStackNode` owns a [`Supervisor`] bound to a concrete
//! [`MlsCryptoProvider`](scp_core::crypto::mls::provider::MlsCryptoProvider).
//! The creator side (Alice) drives every operation through the supervisor's
//! actor mailbox; the per-context MLS / sender-key / access-key state is owned
//! by the context actor. The joiner side (Bob, Carol) never spawns an actor
//! for the context — its MLS group lives directly in its provider, joined from
//! the Welcome the creator side produces.
//!
//! # Cross-node bridging (ADR-049 commit 12c.9f)
//!
//! In a real deployment the joiner's key package, the MLS Welcome, the
//! per-member access keys, and the MLS-wrapped sender-key distribution
//! messages travel over transport. In this in-process harness there is no
//! shared relay between the creator's actor and the joiner's provider, so the
//! shared [`KeyExchange`](super::exchange::KeyExchange) carries those bootstrap
//! bytes:
//!
//! - The joiner's [`E2eCryptoProvider`] generates a real MLS key package (its
//!   provider retains the matching signer state) and deposits the bytes.
//! - The creator's [`add_member`](FullStackNode::add_member) takes the key
//!   package, runs the real `join_context` path (real MLS add → real Welcome →
//!   real HPKE sender-key distribution → minted access keys), then extracts
//!   the Welcome (from the actor's `WelcomeGenerated` event — the same event a
//!   real SDK consumes off its event stream and forwards out-of-band per
//!   §9.17.2), the per-member access keys (via the actor `GetAllAccessKeys`
//!   query), and the MLS-wrapped sender-key distribution messages (captured
//!   off the creator's transport), and deposits them for the joiner.
//! - The joiner's [`join_from_welcome`](FullStackNode::join_from_welcome)
//!   forms its group from the Welcome, picks up its access keys, processes the
//!   sender-key messages, and applies any pending epoch-advance Commits.
//!
//! All MLS / sender-key / access-key cryptography is real; the `KeyExchange`
//! only substitutes for the absent transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::builder::{
    ContextCreationError, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::{ContextEvent, KeyPackage};
use scp_core::context::providers::event_log::MerkleEventLogProvider;
use scp_core::context::supervisor::{MessageSigner, Supervisor};
use scp_core::context::{ContextError, ContextHandle, ContextParams, context_routing_id};
use scp_identity::DID;

use super::crypto::E2eCryptoProvider;

/// Shared buffer of `(routing_id, ciphertext)` pairs captured by the transport.
type SentBuffer = Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>;

/// Registry of every node's crypto helper in a `FullStackNetwork`, keyed by
/// DID. Lets the creator side reach a joiner's provider to mint its real MLS
/// key package during `add_member` (the joiner provider retains the matching
/// signer state for its later Welcome processing).
pub(super) type NodeRegistry = Arc<Mutex<HashMap<String, Arc<E2eCryptoProvider>>>>;

/// Derives a deterministic 32-byte seed from a DID string for test key
/// generation. The signing key is used for inner-envelope signatures on the
/// send path.
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

/// Transport provider that captures every sent payload in a shared buffer.
///
/// After the context actor seals and "sends" a message, the ciphertext lands
/// here. Tests retrieve application ciphertexts via
/// [`FullStackNode::take_sent_ciphertexts`]; the harness drains MLS-wrapped
/// sender-key distribution messages out of the same buffer during
/// `add_member` so they never pollute the application-ciphertext assertions.
#[derive(Clone)]
struct CapturingTransport {
    /// `(routing_id, payload)` pairs, in send order.
    sent: SentBuffer,
}

impl CapturingTransport {
    const fn new(sent: SentBuffer) -> Self {
        Self { sent }
    }
}

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
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((*context_id, encrypted_payload.to_vec()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ArcEventLogProvider — share one MerkleEventLogProvider between node + actor
// ---------------------------------------------------------------------------

/// Newtype delegating [`ContextEventLogProvider`] to a shared
/// `Arc<MerkleEventLogProvider>` so the supervisor's actor and the node's
/// `merkle_root` / export helpers read and write the same event log.
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
    fn event_log_entries(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<Vec<scp_core::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        self.0.event_log_entries(id)
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
        id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_core::context::governance::PruningPolicy,
    ) -> Option<usize> {
        self.0
            .prune_before_checkpoint(id, checkpoint_event_count, policy)
    }
}

// ---------------------------------------------------------------------------
// FullStackNode
// ---------------------------------------------------------------------------

/// A test node with a real `Supervisor`, real MLS crypto, and a real event log.
///
/// Construct nodes through [`FullStackNetwork`](super::network::FullStackNetwork)
/// so they share a `KeyExchange` and node registry.
pub struct FullStackNode {
    /// This node's DID.
    pub did: DID,
    /// The `Supervisor` (actor owner of per-context state) with real crypto.
    pub manager: Arc<Supervisor>,
    /// Direct access to this node's crypto helper for the joiner-side
    /// `join_from_welcome` / `decrypt` paths and the `KeyExchange` bridge.
    pub crypto: Arc<E2eCryptoProvider>,
    /// The event log provider (shared with the supervisor's actor).
    pub event_log: Arc<MerkleEventLogProvider>,
    /// Deterministic signing key derived from this node's DID.
    signing_key: ed25519_dalek::SigningKey,
    /// Ciphertexts captured by the transport, shared with the supervisor.
    sent: SentBuffer,
    /// Registry of all nodes' crypto helpers in the network (creator side
    /// reaches the joiner's provider to mint its real key package).
    registry: NodeRegistry,
    /// Harness-side accumulator of non-`WelcomeGenerated` events drained from
    /// the actor during `add_member` (so the `WelcomeGenerated` event can be
    /// consumed for Welcome extraction without losing the events the tests
    /// assert on later).
    pending_events: Mutex<Vec<ContextEvent>>,
}

impl FullStackNode {
    /// Creates a new full-stack node.
    #[must_use]
    pub(super) fn new(
        did: DID,
        crypto: Arc<E2eCryptoProvider>,
        key_resolver: KeyResolver,
        registry: NodeRegistry,
    ) -> Self {
        let event_log = Arc::new(MerkleEventLogProvider::new());
        let sent: SentBuffer = Arc::new(Mutex::new(Vec::new()));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&did_to_seed(&did));

        let transport_box: Box<dyn ContextTransportProvider> =
            Box::new(CapturingTransport::new(Arc::clone(&sent)));
        let event_log_box: Box<dyn ContextEventLogProvider> =
            Box::new(ArcEventLogProvider(Arc::clone(&event_log)));

        let manager = scp_core::context::test_supervisor(
            Arc::clone(&crypto.provider),
            transport_box,
            event_log_box,
            key_resolver,
        );

        Self {
            did,
            manager,
            crypto,
            event_log,
            signing_key,
            sent,
            registry,
            pending_events: Mutex::new(Vec::new()),
        }
    }

    /// Locks the captured-send buffer, recovering from poisoning.
    fn lock_sent(&self) -> std::sync::MutexGuard<'_, Vec<([u8; 32], Vec<u8>)>> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Creates a context via the real `Supervisor`.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextCreationError`] from the supervisor.
    pub async fn create_context(
        &self,
        context_id: &str,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        self.manager
            .create_context(context_id.to_owned(), params, self.did.clone(), None)
            .await
    }

    /// Adds a member to the context (creator-side operation).
    ///
    /// Runs the real `join_context` path and bridges every cross-node artifact
    /// to the joiner through the shared `KeyExchange`. See the module docs for
    /// the full sequence.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor or crypto provider.
    pub async fn add_member(
        &self,
        handle: &ContextHandle,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id();
        let ctx_bytes = scp_core::context::context_id_bytes(context_id);

        // 1. The joiner mints a real MLS key package (its provider retains the
        //    matching signer state) and deposits the bytes in the exchange.
        let joiner_crypto = {
            let registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.get(member_did).cloned().ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "joiner {member_did} not registered in FullStackNetwork"
                ))
            })?
        };
        joiner_crypto.deposit_key_package(&ctx_bytes)?;

        // 2. Take the joiner's key package for the real add.
        let kp_bytes = self
            .crypto
            .take_key_package(&ctx_bytes, member_did)
            .ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "no key package deposited for joiner {member_did}"
                ))
            })?;

        // Capture the set of existing members BEFORE the add — they need the
        // epoch-advance Commit so their MLS groups stay in lockstep.
        let existing_members = self.manager.member_dids(context_id).await;

        // 3. Run the real join_context path: real MLS add → real Welcome →
        //    real HPKE sender-key distribution → minted access keys.
        let key_package = KeyPackage {
            owner_did: DID::from(member_did),
            mls_key_package_bytes: Some(kp_bytes),
        };
        self.manager
            .join_context(handle, key_package, None, None)
            .await?;

        // 4. The HPKE sender-key distribution messages were MLS-wrapped and
        //    "sent" by the actor — they are now in the capture buffer. Drain
        //    them and deposit for the joiner (keeping the buffer clean for the
        //    application ciphertext the test sends later).
        let captured: Vec<([u8; 32], Vec<u8>)> = std::mem::take(&mut *self.lock_sent());
        for (_routing_id, msg) in captured {
            self.crypto
                .deposit_sender_key_message(&ctx_bytes, member_did, msg);
        }

        // 5. Extract the Welcome (and the epoch-advance Commit for existing
        //    members) from the actor's WelcomeGenerated event. Accumulate every
        //    other event so the tests' later drain_events still observes them.
        let drained = self.manager.drain_events(context_id).await;
        {
            let mut pending = self
                .pending_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for event in drained {
                if let ContextEvent::WelcomeGenerated {
                    welcome_bytes,
                    commit_bytes,
                    ..
                } = event
                {
                    self.crypto
                        .deposit_welcome(&ctx_bytes, member_did, welcome_bytes.0);
                    // Deposit the Commit for every existing member so their MLS
                    // group advances to the new epoch (skip the new joiner, who
                    // receives the Welcome instead).
                    for existing in &existing_members {
                        if existing != member_did {
                            self.crypto.deposit_commit(
                                &ctx_bytes,
                                existing,
                                commit_bytes.0.clone(),
                            );
                        }
                    }
                } else {
                    pending.push(event);
                }
            }
        }

        // 6. Deposit every member's access key for the joiner (it needs every
        //    key to both decrypt inbound content and wrap outbound content).
        let all_keys = self.get_all_access_keys(context_id).await?;
        for (did, key) in all_keys {
            self.crypto
                .deposit_access_key(context_id, member_did, &did, key);
        }

        Ok(())
    }

    /// Reads every per-member access key from the creator's context actor via
    /// the `GetAllAccessKeys` mailbox query.
    async fn get_all_access_keys(
        &self,
        context_id: &str,
    ) -> Result<HashMap<String, scp_core::crypto::access_keys::AccessKey>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = scp_core::context::actor::QueriesCommand::GetAllAccessKeys {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.manager.dispatch_query(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "get_all_access_keys — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Joins a context by retrieving the Welcome from the `KeyExchange`
    /// (joiner-side operation).
    ///
    /// Forms the local MLS group, picks up access keys, processes the queued
    /// sender-key distribution messages, and applies any pending epoch-advance
    /// Commits.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if no Welcome is available or processing
    /// fails.
    pub fn join_from_welcome(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        self.crypto.join_from_welcome(context_id)?;
        self.crypto.pickup_access_keys(context_id_str);
        self.crypto.pickup_sender_key_messages(context_id)?;
        self.crypto.process_pending_commits(context_id)?;
        Ok(())
    }

    /// Sends a message through the real `Supervisor` (encrypts with real MLS +
    /// sender keys + access-key wrapping).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor.
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
                MessageSigner::Active(&self.signing_key),
                None,
                None,
            )
            .await
    }

    /// Sends a suppression-detection heartbeat (§9.9.2) through the real
    /// `Supervisor` — an empty-payload `MessageType::Heartbeat` envelope routed
    /// through the same encrypt-and-send pipeline as application messages. The
    /// captured ciphertext is available via [`take_sent_ciphertexts`](Self::take_sent_ciphertexts).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor.
    pub async fn send_heartbeat(&self, context_id: &str) -> Result<(), ContextError> {
        self.manager
            .send_heartbeat(context_id, &self.did, &self.signing_key)
            .await
    }

    /// Opens a captured ciphertext through the MLS + sender-key + inner-envelope
    /// layers and returns the decrypted [`InnerEnvelope`] without unwrapping the
    /// access-key content layer.
    ///
    /// Lets tests inspect `message_type` / `sequence` / `payload` on the inner
    /// envelope — e.g. to assert a sent heartbeat is tagged
    /// `MessageType::Heartbeat` and carries sequence `0` (§9.9.2).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if any decryption or verification step fails,
    /// or if the open yields a control / management result rather than an
    /// application envelope.
    pub fn open_inner_envelope(
        &self,
        context_id: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<scp_core::envelope::inner::InnerEnvelope, ContextError> {
        self.crypto.process_pending_commits(context_id)?;
        match self.crypto.provider.open(context_id, ciphertext)? {
            scp_core::context::builder::OpenResult::Application(env) => Ok(env.inner),
            scp_core::context::builder::OpenResult::Control => {
                Err(ContextError::CryptoFailed("open returned Control".into()))
            }
            scp_core::context::builder::OpenResult::Management { .. } => Err(
                ContextError::CryptoFailed("open returned Management".into()),
            ),
        }
    }

    /// Takes all captured application ciphertexts sent by this node and clears
    /// the buffer.
    #[must_use]
    pub fn take_sent_ciphertexts(&self) -> Vec<([u8; 32], Vec<u8>)> {
        std::mem::take(&mut *self.lock_sent())
    }

    /// Decrypts a message through the full envelope pipeline (joiner-side).
    ///
    /// Applies any pending epoch-advance Commits first (so the MLS epoch
    /// matches the sender), then opens the envelope and unwraps the access-key
    /// content layer.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if any decryption or verification step fails.
    pub fn decrypt_message(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
        ciphertext: &[u8],
        sender_did: &str,
    ) -> Result<Vec<u8>, ContextError> {
        // Apply any pending epoch-advance commits to sync the MLS epoch.
        self.crypto.process_pending_commits(context_id)?;

        // Open: outer envelope → MLS decrypt → sender-key decrypt → inner
        // envelope → strip padding → integrity check.
        let opened = match self.crypto.provider.open(context_id, ciphertext)? {
            scp_core::context::builder::OpenResult::Application(env) => *env,
            scp_core::context::builder::OpenResult::Control => {
                return Err(ContextError::CryptoFailed("open returned Control".into()));
            }
            scp_core::context::builder::OpenResult::Management {
                sender_did: mgmt_sender,
                payload,
            } => {
                self.crypto.provider.process_incoming_sender_key(
                    context_id,
                    &mgmt_sender,
                    &payload,
                )?;
                return Err(ContextError::CryptoFailed(
                    "open returned Management".into(),
                ));
            }
        };

        // Strip padding to recover the serialized WrappedContent.
        let stripped = scp_core::envelope::strip_padding(&opened.inner.payload)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // Deserialize WrappedContent and unwrap the access-key layer.
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

    /// Picks up and processes any sender-key distribution messages deposited
    /// for this node in the shared exchange.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the crypto provider.
    pub fn pickup_sender_keys(&self, context_id: &[u8; 32]) -> Result<(), ContextError> {
        self.crypto.pickup_sender_key_messages(context_id)
    }

    /// Drains events for a context.
    ///
    /// Returns the harness-accumulated events (drained during `add_member` to
    /// extract the Welcome) followed by a fresh drain from the actor.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        let mut events: Vec<ContextEvent> = {
            let mut pending = self
                .pending_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *pending)
        };
        events.extend(self.manager.drain_events(context_id).await);
        events
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

/// Builds a throwaway `OuterEnvelope` wrapping a raw MLS message and returns
/// its serialized bytes, for feeding a bare Commit through the provider's
/// `open` path (which expects an `OuterEnvelope`).
pub(super) fn wrap_raw_mls_message(
    context_id: &str,
    mls_bytes: Vec<u8>,
) -> Result<Vec<u8>, ContextError> {
    let routing_id = context_routing_id(context_id);
    let outer = scp_core::envelope::outer::create_outer_envelope(&routing_id, None, 0, mls_bytes)
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    rmp_serde::to_vec_named(&outer)
        .map_err(|e| ContextError::CryptoFailed(format!("outer envelope serialization: {e}")))
}
