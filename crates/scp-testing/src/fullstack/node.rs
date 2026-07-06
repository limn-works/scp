//! Full-stack test node wrapping a real `Supervisor` with real crypto.
//!
//! Each `FullStackNode` owns a [`Supervisor`] bound to a concrete
//! [`MlsCryptoProvider`](scp_core::crypto::mls::provider::MlsCryptoProvider).
//! Every node drives its operations through the supervisor's actor mailbox. The
//! creator side (Alice) owns the per-context state in its context actor; the
//! joiner side (Bob, Carol) stands up its OWN live per-context actor via
//! `spawn_actor_from_welcome` — the joiner is a registered, send-capable
//! participant, not a decrypt-only provider (ADR-049 §9 2F-residual).
//!
//! # Cross-node bridging (ADR-049 §9 2F-residual)
//!
//! In a real deployment the creator-signed, HPKE-sealed invitation bundle, the
//! per-member access keys, and the MLS-wrapped sender-key distribution messages
//! travel over transport. In this in-process harness there is no shared relay
//! between the creator's and the joiner's supervisors, so the shared
//! [`KeyExchange`](super::exchange::KeyExchange) carries those bootstrap bytes:
//!
//! - The joiner reserves its OWN pooled MLS `KeyPackage` on its OWN supervisor's
//!   `KeyPackageStoreActor` (which retains the private signer state).
//! - The creator's [`add_member`](FullStackNode::add_member) publishes the
//!   joiner's wrapping keypair, reserves that `KeyPackage`, calls
//!   `Supervisor::invite_member` (real in-actor MLS add → broadcast epoch
//!   Commit → creator `role_state` update → creator-signed, HPKE-sealed §5.12.3
//!   bundle), distributes the creator's sender key, then deposits the sealed
//!   bundle (+ reservation id), the epoch Commit (for existing members), and
//!   every member's access key (via the actor `GetAllAccessKeys` query).
//! - The joiner's [`join_from_welcome`](FullStackNode::join_from_welcome) opens
//!   the sealed bundle under its #active split custody, spawns a live actor via
//!   `Supervisor::spawn_actor_from_welcome`, picks up its access keys, processes
//!   the sender-key messages, and applies any pending epoch-advance Commits.
//!
//! All MLS / sender-key / access-key cryptography is real; the `KeyExchange`
//! only substitutes for the absent transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use scp_core::context::builder::{
    ContextCreationError, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::governance::KeyResolver;
use scp_core::context::membership::ContextEvent;
use scp_core::context::providers::event_log::MerkleEventLogProvider;
use scp_core::context::state::context_id_to_bytes;
use scp_core::context::supervisor::{
    InviteMemberOutcome, MessageSigner, Supervisor, WelcomeJoinRequest,
};
use scp_core::context::{ContextError, ContextHandle, ContextParams, context_routing_id};
use scp_did::DID;
use scp_platform::testing::InMemoryKeyCustody;
use zeroize::Zeroizing;

use super::crypto::E2eCryptoProvider;
use super::exchange::PendingJoin;

/// Shared buffer of `(routing_id, ciphertext)` pairs captured by the transport.
type SentBuffer = Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>;

/// A node's shared, cloneable handles — its `Supervisor` and crypto helper.
/// The creator side reaches a joiner's supervisor (to reserve the joiner's own
/// `KeyPackage`) and its crypto helper (to publish the joiner's wrapping keypair)
/// during `add_member`.
#[derive(Clone)]
pub(super) struct NodeShared {
    /// The joiner's `Supervisor` — the creator reserves the joiner's own pooled
    /// `KeyPackage` on it and (via the joiner) publishes its wrapping keypair.
    pub manager: Arc<Supervisor>,
    /// The joiner's crypto helper — source of the provider's own wrapping
    /// keypair so the reserved KP's `0xFF01` leaf and the secret the provider
    /// opens sender keys with are the SAME keypair.
    pub crypto: Arc<E2eCryptoProvider>,
}

/// Registry of every node's shared handles in a `FullStackNetwork`, keyed by
/// DID. Lets the creator side reach a joiner's supervisor + crypto helper to
/// reserve its real MLS key package and publish its wrapping keypair during
/// `add_member`.
pub(super) type NodeRegistry = Arc<Mutex<HashMap<String, NodeShared>>>;

/// Derives a deterministic 32-byte seed from a DID string for test key
/// generation. The signing key is used for inner-envelope signatures on the
/// send path AND as the node's `#active` identity key: the network's
/// deterministic [`KeyResolver`] resolves each DID to
/// `SigningKey::from_bytes(did_to_seed(did)).verifying_key()`, so a joiner's
/// `#active` custody (which imports this same seed) opens the invitation the
/// creator's `invite_member` sealed to the resolved key.
pub(super) fn did_to_seed(did: &DID) -> [u8; 32] {
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
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        self.0
            .append_event(id, event_type, actor_did, payload, timestamp_secs)
    }
    fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id)
    }
    fn event_log_entries(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
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

    /// Adds a member to the context (creator-side operation), driving the REAL
    /// reserve → `invite_member` → sealed-bundle path (ADR-049 §9 2F-residual).
    ///
    /// The joiner reserves its OWN pooled `KeyPackage` on its OWN supervisor; the
    /// creator calls `Supervisor::invite_member`, which runs the in-actor MLS
    /// add + broadcasts the epoch Commit + updates the creator's `role_state`, and
    /// returns a creator-signed, HPKE-sealed [`super::exchange::PendingJoin`].
    /// The creator then distributes its sender key (`invite_member` does NOT), and
    /// deposits the sealed bundle, the epoch Commit, and every member's access
    /// key for the joiner to pick up. See the module docs for the full sequence.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor or crypto provider —
    /// including the `invite_member` governed-context refusal (only `SingleAdmin`
    /// contexts authorize a unilateral invite).
    pub async fn add_member(
        &self,
        handle: &ContextHandle,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id();
        // ADR-056: resolve the context-id string to keying bytes through the
        // canonical chokepoint, which DECODES a real 64-hex id to its digest
        // rather than re-hashing it (the raw primitive would double-hash a real
        // id and key the wrong MLS group / key-exchange slot).
        let ctx_bytes = context_id_to_bytes(context_id);

        // 1. Reach the joiner's shared handles (its supervisor + crypto helper).
        let joiner: NodeShared = {
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

        // 2. Publish the joiner's OWN provider wrapping keypair into its
        //    supervisor slot BEFORE reserving, so the pooled KeyPackage embeds
        //    the matching `0xFF01` wrapping-leaf pubkey and the secret the
        //    provider opens sender keys with stays the SAME keypair across the
        //    reserve → spawn_actor_from_welcome migration.
        let (wpub, wsec) = joiner.crypto.provider.wrapping_keypair_snapshot();
        joiner
            .manager
            .set_wrapping_keys(
                DID::from(member_did),
                wpub.to_vec(),
                Zeroizing::new(wsec.to_vec()),
            )
            .await?;

        // 3. Reserve the joiner's own pooled KeyPackage on the joiner's
        //    supervisor (its KeyPackageStoreActor mints + retains the private
        //    signer state; only the reservation id + public bytes come back).
        let (reservation_id, kp_bytes) = joiner
            .manager
            .reserve_key_package(DID::from(member_did))
            .await?;

        // 4. Capture the set of existing members BEFORE the add — they need the
        //    epoch-advance Commit so their MLS groups stay in lockstep.
        let existing_members = self.manager.member_dids(context_id).await;

        // 5. Invite the joiner: the add is routed through the context actor's
        //    governance gate (SingleAdmin → auto-executes the real in-actor MLS
        //    add + broadcasts the epoch Commit), and the returned Welcome is
        //    signed + HPKE-sealed into a §5.12.3 bundle with this node's #active
        //    key.
        let outcome = self
            .manager
            .invite_member(
                context_id.to_owned(),
                self.did.clone(),
                DID::from(member_did),
                kp_bytes,
                vec![],
                &self.signing_key,
            )
            .await?;
        let InviteMemberOutcome::Sealed { bundle, .. } = outcome;

        // 6. Deposit the sealed invitation (+ reservation id) for the joiner to
        //    feed into `spawn_actor_from_welcome`.
        self.crypto.deposit_pending_join(
            &ctx_bytes,
            member_did,
            PendingJoin {
                sealed: bundle,
                reservation_id,
            },
        );

        // 7. Distribute THIS node's sender key to the new member — `invite_member`
        //    does NOT distribute sender keys on add, so the joiner needs it to
        //    decrypt the creator's traffic. Deposits directly into the exchange
        //    (does not touch the transport capture buffer).
        self.crypto.distribute_sender_key(&ctx_bytes, member_did)?;

        // 8. Extract the epoch-advance Commit from the actor's WelcomeGenerated
        //    event and deposit it for every existing member so their MLS group
        //    advances to the new epoch. The Welcome itself travels INSIDE the
        //    sealed bundle, so `welcome_bytes` is discarded here. Every OTHER
        //    event is buffered so the tests' later `drain_events` still sees it.
        let drained = self.manager.drain_events(context_id).await;
        {
            let mut pending = self
                .pending_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for event in drained {
                if let ContextEvent::WelcomeGenerated { commit_bytes, .. } = event {
                    for existing in &existing_members {
                        // Deposit the epoch-advance Commit only for OTHER existing
                        // members on separate nodes. Exclude the newly-added member
                        // (it joins via the Welcome, not a Commit) AND this node —
                        // the inviter ran the add in-actor on its own SHARED
                        // provider, so its MLS group already advanced to the new
                        // epoch. Re-depositing the Commit for `self.did` would make
                        // its later `decrypt_message` → `process_pending_commits`
                        // replay it, double-advancing the epoch and breaking the
                        // B→A roundtrip with an epoch mismatch.
                        if existing != member_did && existing.as_str() != self.did.as_ref() {
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

        // 9. `invite_member` broadcast the epoch Commit to the transport, so the
        //    capture buffer now holds it. The raw commit_bytes were already
        //    deposited for existing members from the event in step 8, so clear
        //    the buffer to keep `take_sent_ciphertexts` clean for later
        //    application-ciphertext assertions.
        let _ = std::mem::take(&mut *self.lock_sent());

        // 10. Deposit every member's access key for the joiner (it needs every
        //     key to both decrypt inbound content and wrap outbound content).
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

    /// Joins a context from the sealed invitation the creator deposited in the
    /// `KeyExchange` (joiner-side operation), standing up a live, send-capable
    /// per-context ACTOR via `Supervisor::spawn_actor_from_welcome` (ADR-049 §9
    /// 2F-residual).
    ///
    /// Opens the creator-signed, HPKE-sealed bundle under this node's #active
    /// split custody, installs the joined MLS group, spawns the actor, then
    /// picks up access keys, processes the queued sender-key distribution
    /// messages, and applies any pending epoch-advance Commits. Returns the
    /// live [`ContextHandle`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if no invitation is available, the spawn
    /// rejects the bundle (bad signature / binding / replay / persist), or any
    /// pickup step fails.
    pub async fn join_from_welcome(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<ContextHandle, ContextError> {
        // 1. Take the sealed invitation (bundle + reservation id) the creator
        //    deposited.
        let PendingJoin {
            sealed,
            reservation_id,
        } = self.crypto.take_pending_join(context_id).ok_or_else(|| {
            ContextError::CryptoFailed(format!(
                "no pending invitation for {} in context {}",
                self.did.as_ref(),
                hex::encode(context_id)
            ))
        })?;

        // 2. Build this node's #active split custody from the SAME seed the
        //    network resolver publishes for this DID (so the key the creator
        //    sealed to is exactly the key this custody opens with).
        let custody = InMemoryKeyCustody::new();
        let active_handle = custody
            .import_ed25519_key(&self.signing_key.to_bytes())
            .await;

        // 3. Reconstruct the request. The spawn entrypoint rejects `None` /
        //    all-zero pseudonyms, so derive a distinct non-zero §9.10.4
        //    pseudonym from this joiner's DID + context.
        let enc: [u8; 32] = sealed
            .enc
            .as_slice()
            .try_into()
            .map_err(|_| ContextError::CryptoFailed("sealed enc not 32 bytes".to_owned()))?;
        let req = WelcomeJoinRequest {
            context_id: sealed.context_id.clone(),
            creator_did: sealed.creator_did.clone(),
            sealed_bundle_enc: enc,
            sealed_bundle_ct: sealed.ciphertext.clone(),
            reservation_id,
            local_pseudonym: Some(harness_pseudonym(&self.did, context_id_str)),
        };

        // 4. Spawn the live per-context actor from the opened, verified bundle.
        let handle = self
            .manager
            .spawn_actor_from_welcome(self.did.clone(), &custody, &active_handle, req)
            .await?;

        // 5. Joiner-side pickup: access keys, sender-key distribution messages,
        //    and any pending epoch-advance Commits.
        self.crypto.pickup_access_keys(context_id_str);
        self.crypto
            .pickup_sender_key_messages(context_id_str, context_id)?;
        self.crypto
            .process_pending_commits(context_id_str, context_id)?;

        // 6. Mirror `add_member` step 7 in the OTHER direction: distribute THIS
        //    joiner's sender key to every existing member so they can decrypt the
        //    joiner's outbound traffic. Neither `invite_member` nor the Welcome
        //    carries the joiner's sender key to the incumbents, so without this a
        //    B→A send fails at the receiver with `sender key lookup failed`. The
        //    joiner holds each peer's `0xFF01` wrapping pubkey from the joined
        //    group's leaf nodes, so the HPKE seal targets the right recipient.
        let joiner_did = self.did.as_ref();
        for existing in self.manager.member_dids(handle.context_id()).await {
            if existing.as_str() != joiner_did {
                self.crypto.distribute_sender_key(context_id, &existing)?;
            }
        }
        Ok(handle)
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

    /// This node's `#active` Ed25519 verifying key. A governance test resolver
    /// maps each member DID to its node's verifying key so the real engine can
    /// verify propose/approve vote signatures (the default fullstack resolver
    /// returns `None` because most tests do not exercise the vote path).
    #[must_use]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Submits a governance proposal through the real `Supervisor`, signing the
    /// proposer's vote with this node's `#active` key. Returns the created
    /// proposal (its `proposal_id` is the engine-tracked handle for later
    /// approval / execution).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor.
    pub async fn propose_governance(
        &self,
        context_id: &str,
        action: scp_core::context::governance::GovernanceAction,
    ) -> Result<scp_core::context::governance::GovernanceProposal, ContextError> {
        let (proposal, _events, _execution) = self
            .manager
            .propose_governance_action(context_id, &self.did, action, &self.signing_key)
            .await?;
        Ok(proposal)
    }

    /// Casts an approval vote on a pending proposal through the real
    /// `Supervisor`, signing with this node's `#active` key. Returns the
    /// proposal status after the vote (e.g. `Approved` once quorum is crossed).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor.
    pub async fn approve_governance(
        &self,
        context_id: &str,
        proposal_id: &scp_core::context::governance::ProposalId,
    ) -> Result<scp_core::context::governance::ProposalStatus, ContextError> {
        let (status, _events) = self
            .manager
            .vote_on_proposal(context_id, proposal_id, &self.did, true, &self.signing_key)
            .await?;
        Ok(status)
    }

    /// Dispatches a direct execute-by-id through the real `Supervisor` — the
    /// FFI-shaped `ExecuteGovernanceAction` command, which carries ONLY the
    /// proposal id. The runtime resolves the authoritative proposal from its
    /// own quorum-validated engine; a caller cannot fabricate an approved
    /// proposal or substitute an action.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the supervisor — including a rejection
    /// of an untracked / unapproved / already-executed proposal id.
    pub async fn execute_governance_by_id(
        &self,
        context_id: &str,
        proposal_id: scp_core::context::governance::ProposalId,
    ) -> Result<scp_core::context::state::GovernanceActionResult, ContextError> {
        use scp_core::context::actor::commands::{
            ExecuteGovernanceActionPayload, GovernanceCommand,
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ExecuteGovernanceAction {
            payload: Box::new(ExecuteGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposal_id,
            }),
            reply: tx,
        };
        self.manager.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "FullStackNode::execute_governance_by_id — actor reply channel closed".to_owned(),
            )
        })?
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
        context_id_str: &str,
        context_id: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<scp_core::envelope::inner::InnerEnvelope, ContextError> {
        self.crypto
            .process_pending_commits(context_id_str, context_id)?;
        match self
            .crypto
            .provider
            .open(context_id, context_id_str, ciphertext)?
        {
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
        self.crypto
            .process_pending_commits(context_id_str, context_id)?;

        // Ingest any sender-key distribution addressed to this node before
        // opening. Distribution is symmetric — a joiner distributes its sender
        // key to the incumbents just as the inviter distributes to the joiner —
        // so the receiver must pick up the sender's key here or the open below
        // fails with `sender key lookup failed`.
        self.crypto
            .pickup_sender_key_messages(context_id_str, context_id)?;

        // Open: outer envelope → MLS decrypt → sender-key decrypt → inner
        // envelope → strip padding → integrity check.
        let opened = match self
            .crypto
            .provider
            .open(context_id, context_id_str, ciphertext)?
        {
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
    pub fn pickup_sender_keys(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        self.crypto
            .pickup_sender_key_messages(context_id_str, context_id)
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

/// Derives a distinct, non-zero §9.10.4 local pseudonym for a joiner from its
/// DID + context id. `Supervisor::spawn_actor_from_welcome` rejects a `None`
/// pseudonym and refuses the all-zero `[0u8; 32]`, so the harness supplies a
/// deterministic non-zero value (byte 31 is pinned to `0xA5` to guarantee it is
/// never all-zero even in the astronomically-unlikely hash-collision case).
fn harness_pseudonym(did: &DID, ctx: &str) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut pseudonym = [0u8; 32];
    // Fill the array with 4 rounds of a DefaultHasher over (did || ctx || round)
    // so it is distinct per joiner + context, not just a repeated 8-byte block.
    for (round, chunk) in pseudonym.chunks_mut(8).enumerate() {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        did.as_ref().hash(&mut hasher);
        ctx.hash(&mut hasher);
        round.hash(&mut hasher);
        let h = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&h[..chunk.len()]);
    }
    // Guarantee non-zero (spawn refuses the all-zero pseudonym).
    pseudonym[31] = 0xA5;
    pseudonym
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
