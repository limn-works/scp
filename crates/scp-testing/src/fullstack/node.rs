//! Full-stack test node wrapping a real `Supervisor` with real crypto.
//!
//! Each `FullStackNode` owns a [`Supervisor`] bound to a concrete
//! [`NodeMlsFactory`](scp_core::crypto::mls::provider::NodeMlsFactory).
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

/// Reads every per-member §9.17 access key held by `manager`'s context actor
/// via the `GetAllAccessKeys` mailbox query.
///
/// Used both for a node's OWN keys and — through the shared registry — to read
/// the CREATOR's held keys when answering a joiner's §9.17 pull requests.
async fn dispatch_get_all_access_keys(
    manager: &Arc<Supervisor>,
    context_id: &str,
) -> Result<HashMap<String, scp_core::crypto::access_keys::AccessKey>, ContextError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = scp_core::context::actor::QueriesCommand::GetAllAccessKeys {
        context_id: context_id.to_owned(),
        reply: tx,
    };
    manager.dispatch_query(cmd).await?;
    rx.await.map_err(|_| {
        ContextError::TransportFailed("get_all_access_keys — actor reply channel closed".to_owned())
    })?
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

#[async_trait::async_trait]
impl ContextTransportProvider for CapturingTransport {
    fn is_connected(&self) -> bool {
        true
    }

    async fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    async fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    async fn send_message(
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

#[async_trait::async_trait]
impl ContextEventLogProvider for ArcEventLogProvider {
    async fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.init_event_log(id).await
    }
    async fn append_event(
        &self,
        id: &[u8; 32],
        event_type: scp_event_log::EventType,
        actor_did: &str,
        payload: scp_event_log::EventPayload,
        timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        self.0
            .append_event(id, event_type, actor_did, payload, timestamp_secs)
            .await
    }
    async fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.destroy_event_log(id).await
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
    async fn import_event_log_data(&self, id: &[u8; 32], data: &[u8]) -> Result<(), ContextError> {
        self.0.import_event_log_data(id, data).await
    }
    fn event_log_merkle_root(&self, id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
        self.0.event_log_merkle_root(id)
    }
    async fn restore_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.restore_event_log(id).await
    }
    async fn prune_before_checkpoint(
        &self,
        id: &[u8; 32],
        checkpoint_event_count: u64,
        policy: &scp_core::context::governance::PruningPolicy,
    ) -> Option<usize> {
        self.0
            .prune_before_checkpoint(id, checkpoint_event_count, policy)
            .await
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
        // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the receive path now decrypts through
        // the context ACTOR's `deliver_incoming`, whose Phase-1 local-member lookup
        // matches the context membership against the supervisor-wide `local_dids`
        // registry. The deleted provider `open` twin required no such registry, so
        // the harness never registered its own DID; in production the FFI bridge
        // registers each identity via `identity_add`. Mirror that here (idempotent,
        // supervisor-wide) so this node can identify itself as the local member.
        let _ = self.manager.register_local_did(self.did.clone()).await;
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
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the inviter's actor pushes its
    /// MLS-wrapped sender key onto the transport during the in-actor add, so the
    /// creator harvests that pushed blob from the capture buffer (rather than the
    /// deleted provider `distribute`/`drain`/`mls_encrypt_management` path) and
    /// deposits it, the sealed bundle, and the epoch Commit for the joiner to
    /// pick up. See the module docs for the full sequence.
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

        // 7. Extract the epoch-advance Commit from the actor's WelcomeGenerated
        //    event and deposit it for every existing member so their MLS group
        //    advances to the new epoch. The Welcome itself travels INSIDE the
        //    sealed bundle, so `welcome_bytes` is discarded here. Every OTHER
        //    event is buffered so the tests' later `drain_events` still sees it.
        //    Capture the (broadcast) Commit ciphertext so the sender-key harvest
        //    in step 8 can distinguish it from the inviter's sender-key push.
        let drained = self.manager.drain_events(context_id).await;
        let mut commit_ct: Option<Vec<u8>> = None;
        {
            let mut pending = self
                .pending_events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for event in drained {
                if let ContextEvent::WelcomeGenerated { commit_bytes, .. } = event {
                    commit_ct = Some(commit_bytes.0.clone());
                    for existing in &existing_members {
                        // Deposit the epoch-advance Commit only for OTHER existing
                        // members on separate nodes. Exclude the newly-added member
                        // (it joins via the Welcome, not a Commit) AND this node —
                        // the inviter ran the add in-actor on its OWN actor, so its
                        // MLS group already advanced to the new epoch. Re-depositing
                        // the Commit for `self.did` would make its later
                        // `feed_pending_incoming` replay it, double-advancing the
                        // epoch and breaking the B→A roundtrip with an epoch mismatch.
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

        // 8. Harvest THIS node's sender-key distribution for the new member.
        //    ADR-049 PR-7 (SCP-CRYPTOMOVE-001): `invite_member` runs the add in
        //    the inviter's actor, whose drain-and-deliver pushes the inviter's
        //    MLS-wrapped sender key onto the transport (captured in `self.sent`).
        //    The provider `distribute_sender_key` → `drain` →
        //    `mls_encrypt_management` manual path is deleted, so harvest the
        //    pushed blob(s) here — every captured envelope that is NOT the
        //    (broadcast) epoch Commit — and deposit them for the joiner to feed
        //    through its actor receive path (`feed_pending_incoming`). Taking the
        //    buffer also clears it, keeping `take_sent_ciphertexts` clean for
        //    later application-ciphertext assertions.
        {
            let captured = std::mem::take(&mut *self.lock_sent());
            for (_routing_id, ct) in captured {
                if commit_ct.as_deref() != Some(ct.as_slice()) {
                    self.crypto
                        .deposit_sender_key_message(&ctx_bytes, member_did, ct);
                }
            }
        }

        // NOTE: the new member's access keys are NOT pushed here. The creator
        // (this node) holds every member's §9.17 access key in its OWN actor
        // store (minted at create / add). The joiner acquires the keys it needs
        // by issuing REAL §9.17 pull requests the creator answers — see
        // `join_from_welcome` → `pull_access_keys_from_creator`. The production
        // actor-loop distribution this replaces is deferred and tracked (#2050).

        Ok(())
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
        // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the receive path decrypts through the
        // context ACTOR's `deliver_incoming`, whose Phase-1 local-member lookup
        // matches the context membership against the supervisor-wide `local_dids`
        // registry (the deleted provider `open` twin needed no such registry). In
        // production the FFI bridge registers each identity via `identity_add`;
        // mirror that here (idempotent) so this joiner can identify itself as the
        // local member when it opens incumbent traffic.
        let _ = self.manager.register_local_did(self.did.clone()).await;

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
        // The creator holds every member's §9.17 access key (minted at create /
        // add) and answers this joiner's pull requests below.
        let creator_did = sealed.creator_did.clone();

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

        // 5. Joiner-side pickup: pending epoch-advance Commits and the pushed
        //    sender-key distribution messages, fed through the REAL actor
        //    receive path (ADR-049 PR-7). (§9.17 access keys are acquired via
        //    the real pull in step 7, not a deposit/pickup side-channel.)
        self.feed_pending_incoming(context_id_str, context_id)
            .await?;

        // 6. Joiner→incumbent sender-key exchange via the spec's PULL protocol
        //    (§9.16.2), the canonical new-member mechanism. Neither `invite_member`
        //    nor the Welcome carries the joiner's sender key to the incumbents, so
        //    without this a B→A send fails at the receiver with `sender key lookup
        //    failed`. The joiner CANNOT proactively PUSH its key: a push seals to
        //    each incumbent's STABLE `0xFF01` wrapping key, and openmls 0.8.1
        //    exposes no way to read a remote member's LeafNode extension from a
        //    joined group (ADR-057) — a joiner's `member_wrapping_keys` is empty.
        //    Instead each incumbent PULLS the joiner's key (see the helper).
        self.incumbents_pull_joiner_sender_key(context_id, &handle)
            .await?;

        // 7. §9.17 content-access-key acquisition via the REAL pull protocol.
        //    The joiner's actor spawned with an EMPTY access_key_store, so it can
        //    neither unwrap its own inbound CEKs nor wrap CEKs for its peers on
        //    send. It acquires every current member's access key (its own + the
        //    incumbents') by issuing signed §9.17 requests the creator (the key
        //    holder) answers via `handle_access_key_request`, then installs the
        //    opened keys into its actor store. (The production actor-loop
        //    distribution this simulates over the harness transport is deferred
        //    and tracked in #2050.)
        self.pull_access_keys_from_creator(context_id_str, &creator_did, &handle)
            .await?;
        Ok(handle)
    }

    /// Drives the §9.17 access-key PULL for a Welcome-joiner (`self`).
    ///
    /// The joiner's actor spawned with an empty access-key store. For EVERY
    /// current member `member` (the joiner itself + every incumbent), the joiner
    /// issues a signed [`AccessKeyRequest`](scp_core::crypto::access_keys::wire)
    /// with a fresh ephemeral wrapping key, the creator — which holds every
    /// member's access key (§9.17.1: "the key holder (context creator or
    /// `AddMember` executor)") — answers via
    /// [`handle_access_key_request`](scp_core::crypto::access_keys::wire::handle_access_key_request)
    /// with that member's key sealed to the ephemeral key, and the joiner opens
    /// the response and installs the key into its own actor store via the
    /// testing seam. This is the real request/response round trip over the
    /// harness's simulated transport — no deposit/pickup shortcut.
    ///
    /// The joiner pulls the FULL current member set at join time. Incremental
    /// re-distribution to already-joined members when a LATER member joins is the
    /// production actor-loop concern tracked in #2050 (no current test drives a
    /// joiner→later-joiner send, so it is not simulated here).
    ///
    /// # Expiry
    ///
    /// This driver EXPIRES with #2050, together with the `testing`-only
    /// `Supervisor::test_install_access_key` seam it lands each pulled key
    /// through. When production §9.17 distribution lands, DELETE this method and
    /// that seam, and confirm the Python/TS bidirectional tripwires still pass on
    /// the *production* distribution path rather than this harness stand-in.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if the creator node is not registered, the
    /// creator holds no key for a member, or any request / open / install fails.
    async fn pull_access_keys_from_creator(
        &self,
        context_id_str: &str,
        creator_did: &str,
        joiner_handle: &ContextHandle,
    ) -> Result<(), ContextError> {
        use scp_clock::Clock as _;
        use scp_core::crypto::access_keys::wire::{
            AccessKeyResponse, handle_access_key_request, open_access_key_response,
            request_access_key,
        };

        // Reach the creator node (the §9.17 key holder) through the shared
        // registry, and read the access keys it holds from its actor store.
        let creator = {
            let registry = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry.get(creator_did).cloned()
        };
        let Some(creator) = creator else {
            return Err(ContextError::CryptoFailed(format!(
                "§9.17 pull: creator node {creator_did} is not registered in the network"
            )));
        };
        let creator_keys = dispatch_get_all_access_keys(&creator.manager, context_id_str).await?;

        let joiner_did = self.did.as_ref();
        let mut nonce_dedup = scp_core::crypto::sender_keys::NonceDedup::new();

        for member_did in self.manager.member_dids(joiner_handle.context_id()).await {
            // The creator holds every member's key; a missing entry is a real
            // wiring bug (fail loud rather than silently skip a recipient).
            let member_key = creator_keys.get(&member_did).cloned().ok_or_else(|| {
                ContextError::CryptoFailed(format!(
                    "§9.17 pull: creator holds no access key for member {member_did}"
                ))
            })?;

            // 1. Joiner builds a signed request with a fresh ephemeral wrapping
            //    keypair (held in a throwaway in-memory custody).
            let custody = InMemoryKeyCustody::new();
            let signing_handle = custody
                .import_ed25519_key(&self.signing_key.to_bytes())
                .await;
            let request = request_access_key(
                &custody,
                &signing_handle,
                joiner_did,
                context_id_str,
                &scp_clock::SystemClock,
            )
            .await
            .map_err(|e| ContextError::CryptoFailed(format!("build access-key request: {e}")))?;

            // 2. Creator (holder) seals `member_did`'s key to the joiner's
            //    ephemeral wrapping key via the REAL responder path.
            let parsed_request: scp_core::crypto::access_keys::wire::AccessKeyRequest =
                serde_json::from_slice(&request.request_message).map_err(|e| {
                    ContextError::CryptoFailed(format!("decode access-key request: {e}"))
                })?;
            let response_bytes = handle_access_key_request(
                &parsed_request,
                self.signing_key.verifying_key().as_bytes(),
                &member_key,
                scp_clock::SystemClock.now_secs(),
                &mut nonce_dedup,
            )
            .map_err(|e| ContextError::CryptoFailed(format!("creator seals access key: {e}")))?;

            // 3. Joiner opens the response and installs the key into its actor.
            let response: AccessKeyResponse =
                serde_json::from_slice(&response_bytes).map_err(|e| {
                    ContextError::CryptoFailed(format!("decode access-key response: {e}"))
                })?;
            let key = open_access_key_response(&custody, &request.wrapping_key_handle, &response)
                .await
                .map_err(|e| {
                    ContextError::CryptoFailed(format!("open access-key response: {e}"))
                })?;
            self.manager
                .test_install_access_key(context_id_str, &member_did, key)
                .await?;
        }
        Ok(())
    }

    /// Drives the §9.16.2 PULL exchange for the joiner→incumbent direction.
    ///
    /// For each existing member `incumbent`, the incumbent issues a signed
    /// [`SenderKeyRequest`](scp_core::crypto::sender_keys::SenderKeyRequest)
    /// carrying a FRESH EPHEMERAL wrapping key, the joiner (`self`) answers via
    /// [`Supervisor::handle_sender_key_request`](scp_core::context::supervisor::Supervisor::handle_sender_key_request),
    /// and the incumbent opens the response with its ephemeral secret and stores
    /// the joiner's key in its OWN provider. This is the real request/response
    /// round trip, not a shortcut: the joiner's response goes through the H1
    /// membership gate (§9.16.6 Mitigation 1), which reads the joiner's MLS group
    /// tree — so the joiner accepts every incumbent (a member) even though its
    /// `member_wrapping_keys` cache is empty. The incumbent's `#active` signing
    /// key and provider are reached through the shared node registry, exactly as
    /// `add_member` reaches a joiner's supervisor.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if the request build, the joiner's response,
    /// the HPKE open, or the store fails. A missing registry entry for a member
    /// is skipped (only registered nodes participate in the harness exchange).
    async fn incumbents_pull_joiner_sender_key(
        &self,
        context_id: &[u8; 32],
        joiner_handle: &ContextHandle,
    ) -> Result<(), ContextError> {
        use scp_core::crypto::sender_keys::SenderKeyDistributionMessage;
        use scp_core::crypto::sender_keys::key_protocol::{
            open_sender_key_response, request_sender_key,
        };

        // The sender-key HPKE layer binds `hex::encode(context_id)` (the hex of
        // the 32-byte digest), NOT the human context-id string: the responder's
        // `handle_sender_key_request` seals with that value, so the requester
        // MUST open with the same one (§9.16.2 info/aad).
        let ctx_id_hex = hex::encode(context_id);
        let joiner_did = self.did.as_ref().to_owned();
        // The joiner's own sender key is minted at `install_joined_group` with
        // epoch 1. The request's `epoch` field is not validated by the responder
        // (it seals its CURRENT key and returns the authoritative epoch in the
        // response), so this is only the requester's best-effort hint.
        let joiner_epoch = 1u64;

        for incumbent_did in self.manager.member_dids(joiner_handle.context_id()).await {
            if incumbent_did == joiner_did {
                continue;
            }

            // Reach the incumbent's provider + derive its deterministic #active
            // signing key (the network resolver maps every DID to this key).
            let incumbent = {
                let registry = self
                    .registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                registry.get(&incumbent_did).cloned()
            };
            let Some(incumbent) = incumbent else {
                continue;
            };
            let incumbent_signing =
                ed25519_dalek::SigningKey::from_bytes(&did_to_seed(&DID(incumbent_did.clone())));

            // 1. Incumbent builds a signed request with a fresh ephemeral
            //    wrapping keypair (held in a throwaway in-memory custody).
            let custody = InMemoryKeyCustody::new();
            let signing_handle = custody
                .import_ed25519_key(&incumbent_signing.to_bytes())
                .await;
            let request = request_sender_key(
                &custody,
                &signing_handle,
                &incumbent_did,
                &joiner_did,
                joiner_epoch,
                &scp_clock::SystemClock,
            )
            .await
            .map_err(|e| {
                ContextError::CryptoFailed(format!("incumbent build sender-key request: {e}"))
            })?;

            // 2. Joiner answers via the ACTOR answer path (ADR-049 PR-7): the
            //    joiner's crypto is taken into its actor, so the emptied provider
            //    can no longer answer — reach the actor-owned
            //    `ContextCryptoState::handle_sender_key_request` (the same H1
            //    §9.16.6 Mitigation-1 membership gate, now on the actor) by
            //    `context_id` through the `HandleSenderKeyRequest` mailbox command.
            let response_bytes = self
                .manager
                .handle_sender_key_request(
                    joiner_handle.context_id(),
                    &request.request_message,
                    incumbent_signing.verifying_key().as_bytes(),
                )
                .await?
                .ok_or_else(|| {
                    ContextError::CryptoFailed(
                        "joiner declined the incumbent's sender-key request".to_owned(),
                    )
                })?;

            // 3. Incumbent opens the ephemeral-sealed response with its own
            //    custody (unchanged — the wrapping secret is node-resident), then
            //    lands the joiner's key onto its OWN actor store via the
            //    GATE-BEFORE-INSTALL `LandSenderKeyResponse` mailbox command
            //    (ADR-049 PR-7): the incumbent's provider is likewise taken, so
            //    the former direct `set_sender_key_unchecked` was a no-op on an
            //    emptied context. The Class-M floor gate runs inside the handler.
            // BLACK-P7-2 (ADR-049 PR-7): the actor answer is the
            // `SenderKeyDistributionMessage::KeyResponse` envelope (matching the
            // production receive path + the proactive push), so decode the enum
            // rather than a bare `SenderKeyResponse`.
            let response =
                match SenderKeyDistributionMessage::from_bytes(&response_bytes).map_err(|e| {
                    ContextError::CryptoFailed(format!("decode sender-key response: {e}"))
                })? {
                    SenderKeyDistributionMessage::KeyResponse(resp) => resp,
                    other => {
                        return Err(ContextError::CryptoFailed(format!(
                            "expected a KeyResponse from the joiner, got {other:?}"
                        )));
                    }
                };
            let joiner_key = open_sender_key_response(
                &custody,
                &request.wrapping_key_handle,
                &ctx_id_hex,
                &response,
            )
            .await
            .map_err(|e| {
                ContextError::CryptoFailed(format!("incumbent open sender-key response: {e}"))
            })?;
            incumbent
                .manager
                .land_sender_key_response(
                    joiner_handle.context_id(),
                    &joiner_did,
                    joiner_key,
                    response.epoch,
                )
                .await?;
        }
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
    /// layers and returns the decrypted [`InnerEnvelope`](scp_core::envelope::InnerEnvelope) without unwrapping the
    /// access-key content layer, so tests can inspect `message_type` /
    /// `sequence` / `payload` (e.g. assert a sent heartbeat is tagged
    /// `MessageType::Heartbeat` and carries sequence `0`, §9.9.2).
    ///
    /// # Read-only actor inspection (ADR-049 PR-7, SCP-CRYPTOMOVE-001)
    ///
    /// The crypto state is actor-owned (one-way take), so this routes through the
    /// context actor via
    /// [`Supervisor::inspect_incoming_inner`](scp_core::context::supervisor::Supervisor::inspect_incoming_inner)
    /// — the actor twin of the deleted provider `open` inspection twin. The actor
    /// handler decrypts through the OWNED crypto state and returns the RAW inner
    /// envelope.
    ///
    /// This inspection is NON-MUTATING on receive state by construction: the
    /// handler drives only the pure `ContextCryptoState::open` decrypt, NOT the
    /// messaging-seam anti-replay path (`check_and_advance_recv_sequence`, the
    /// Class-M floor registry, `nonce_dedup`, epoch advance). It therefore never
    /// consumes an application sequence or anti-replay slot — which is exactly
    /// what lets a test open the same three captured blobs and assert that the
    /// heartbeat between two messages did NOT advance the application sequence
    /// (§9.9.2). The only state change is the MLS decryption-ratchet advance
    /// intrinsic to any decrypt (the deleted provider twin was non-mutating in
    /// this same sense).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if any decryption or verification step fails,
    /// or if the blob decodes to a control / management result rather than an
    /// application envelope.
    pub async fn open_inner_envelope(
        &self,
        context_id_str: &str,
        _context_id: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<scp_core::envelope::inner::InnerEnvelope, ContextError> {
        self.manager
            .inspect_incoming_inner(context_id_str, ciphertext.to_vec())
            .await
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
    pub async fn decrypt_message(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
        ciphertext: &[u8],
        _sender_did: &str,
    ) -> Result<Vec<u8>, ContextError> {
        // Ingest any deposited epoch-advance Commits + pushed sender-key
        // distributions through the REAL actor receive path first, so the MLS
        // epoch is synced and the sender's key is installed before the
        // application ciphertext is opened. (The reverse joiner→incumbent
        // sender-key direction is handled at join time by the PULL protocol,
        // `incumbents_pull_joiner_sender_key`.)
        self.feed_pending_incoming(context_id_str, context_id)
            .await?;

        // Open through the real actor receive path (ADR-049 PR-7,
        // SCP-CRYPTOMOVE-001): `Supervisor::deliver_commit_blob` dispatches
        // `MessagingCommand::DeliverIncoming` to this node's context actor,
        // which runs `decrypt_and_dispatch` (outer envelope → MLS decrypt →
        // sender-key decrypt → inner envelope → anti-replay) followed by the
        // §9.17 access-key unwrap, returning the recovered plaintext. The
        // provider `open` twin is deleted; the actor is the sole crypto
        // authority for its context.
        match self
            .manager
            .deliver_commit_blob(context_id_str, ciphertext.to_vec())
            .await?
        {
            Some((plaintext, _sender)) => Ok(plaintext),
            None => Err(ContextError::CryptoFailed(
                "decrypt_message: blob classified as control/management, not application content"
                    .to_owned(),
            )),
        }
    }

    /// Feeds every deposited epoch-advance Commit and pushed sender-key
    /// distribution blob for this node through the REAL actor receive path.
    ///
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): replaces the deleted provider
    /// `open` / `mls_encrypt_management` pickup twins. Each blob is dispatched
    /// via [`Supervisor::deliver_commit_blob`](scp_core::context::supervisor::Supervisor::deliver_commit_blob),
    /// whose `decrypt_and_dispatch` merges Commits (advancing the MLS epoch) and
    /// installs authenticated sender keys through the same gate-before-install
    /// path production uses. Commits are applied BEFORE sender-key blobs so a
    /// sender key wrapped at a post-Commit epoch is decryptable. Sender-key
    /// blobs are full `OuterEnvelope`s (harvested from the inviter's transport
    /// in [`Self::add_member`]); raw Commits are wrapped in a throwaway
    /// `OuterEnvelope` first. `deliver_commit_blob` returns `None` for both
    /// (Control / Management), so the `Option` is intentionally discarded.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] if any deliver step fails.
    async fn feed_pending_incoming(
        &self,
        context_id_str: &str,
        context_id: &[u8; 32],
    ) -> Result<(), ContextError> {
        for commit_bytes in self.crypto.take_pending_commits(context_id) {
            let wrapped = wrap_raw_mls_message(context_id_str, commit_bytes)?;
            let _ = self
                .manager
                .deliver_commit_blob(context_id_str, wrapped)
                .await?;
        }
        for wrapped in self.crypto.take_pending_sender_key_messages(context_id) {
            let _ = self
                .manager
                .deliver_commit_blob(context_id_str, wrapped)
                .await?;
        }
        Ok(())
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
