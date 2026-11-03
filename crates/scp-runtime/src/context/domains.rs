//! The 13 domain traits and [`DomainHandlers`], the one value through which
//! core reaches domain code (ADR-070 §3).
//!
//! Core (the actor hub, the Supervisor, and the shared items in
//! [`crate::context::shared`]) never names a domain function. It calls the
//! trait object that the assembly crate's `domain_handlers()` built, through
//! [`ActorDeps::domains`] inside an actor turn or the Supervisor's own
//! `domains` field outside one. A domain reaches a sibling domain the same
//! way, so no domain depends on another.
//!
//! Each trait method keeps the name and parameter list of the domain function
//! it forwards to. A method whose list would pass seven parameters takes a
//! request struct defined here, since `clippy::too_many_arguments` denies the
//! longer list on a trait declaration.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use scp_did::DID;
use scp_event_log::checkpoint::{CheckpointComparison, ConsistencyCheckpoint};
use scp_protocol::context::broadcast::BlockResult;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::AccessScope;
use scp_protocol::context::membership::ReceiveBuffer;
use scp_protocol::context::{ContextError, ContextParams};
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::types::{Amount, PaidActionType};

use crate::context::ContextHandle;
use crate::context::actor::class_s::{
    ClassCMut, ClassSCell, ClassSCommitToken, ConsequenceStateSplit,
};
use crate::context::actor::commands::{
    BroadcastCommand, EconomyCommand, GovernanceCommand, LifecycleCommand, LifecycleControlCommand,
    MessagingCommand, OutletsCommand, PushCommand, QueriesCommand, SagaPhaseMessage,
    StandingCommand, TrustRecoveryCommand, TtlCloseCommand,
};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::{ContextCryptoState, DistributionReport, PerContextState};
use crate::context::builder::ContextEventLogProvider;
use crate::context::export_import::ContextExport;
use crate::context::outlets::invoke::InvocationCaveatBinding;
use crate::context::shared::economy::{
    EnforceEconomyRequest, OwnedAuthInputs, PaidActionAuthorization,
};
use crate::context::shared::governance::{
    BroadcastFailure, CommitMeta, EnforceConsequencesCtx, MigrationBootstrap,
};
use crate::context::shared::lifecycle::{DistributionScope, FirstStateRollback, SpawnedContext};
use crate::context::shared::messaging::Dispatched;
use crate::context::shared::outlets::{
    OutletEconomyReservation, OutletSettleOutcome, OutletSettleRequest,
};
use crate::context::shared::ttl_close::{ExtensionLeaf, TtlExpiryOutcome};
use crate::context::state::{CommitOperation, ContextSnapshot, MigrationProposedResult};
use crate::context::supervisor::saga_prepared_state::CallerReservationRecord;
use crate::context::supervisor::{MessageSigner, Supervisor};
use crate::context::ttl::CloseResult;
use crate::economy::adapter::PaymentReceipt;

/// The 13 domain handlers, one trait object per domain (ADR-070 §3).
///
/// The assembly crate's `domain_handlers()` is the only constructor in
/// production: there is no `Default`, registry or global, so a Supervisor
/// built without every domain does not compile.
pub struct DomainHandlers {
    /// Send, receive, seal and open (spec §5.4).
    pub messaging: Arc<dyn MessagingDomain>,
    /// Create, join, import, restore, close and sender-key distribution.
    pub lifecycle: Arc<dyn LifecycleDomain>,
    /// Proposals, votes, execution, revocation and consequences.
    pub governance: Arc<dyn GovernanceDomain>,
    /// Broadcast contexts: subscribe, block and key requests.
    pub broadcast: Arc<dyn BroadcastDomain>,
    /// Paid actions, escrow and receipts (spec §19).
    pub economy: Arc<dyn EconomyDomain>,
    /// Key recovery and trust contacts.
    pub trust_recovery: Arc<dyn TrustRecoveryDomain>,
    /// Standing pairs.
    pub standing: Arc<dyn StandingDomain>,
    /// TTL extension, expiry and close.
    pub ttl_close: Arc<dyn TtlCloseDomain>,
    /// Outlet registration, invocation and settlement.
    pub outlets: Arc<dyn OutletsDomain>,
    /// Push-wake registration and routes.
    pub push: Arc<dyn PushDomain>,
    /// Read-only queries, checkpoints and access keys.
    pub queries: Arc<dyn QueriesDomain>,
    /// Cross-context saga phases.
    pub saga: Arc<dyn SagaDomain>,
    /// Actor lifecycle control (shutdown, flush, crypto restore).
    pub lifecycle_control: Arc<dyn LifecycleControlDomain>,
}

impl std::fmt::Debug for DomainHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainHandlers").finish_non_exhaustive()
    }
}

/// [`MessagingDomain::finalize_send`]'s arguments after the cell and deps.
pub struct FinalizeSendRequest<'a> {
    /// The context the message was sealed for.
    pub context_id: &'a str,
    /// `context_id`'s 32-byte routing form.
    pub context_id_bytes: &'a [u8; 32],
    /// The sending member.
    pub sender_did: &'a DID,
    /// The reserved send sequence.
    pub sequence: u64,
    /// The application payload that was sealed.
    pub payload: &'a [u8],
    /// The signer for the outer envelope.
    pub signer: MessageSigner<'a>,
    /// The Class-S commit obligation the send carries, if any.
    pub token: Option<ClassSCommitToken>,
    /// Whether the send is a broadcast publish.
    pub is_broadcast: bool,
}

/// [`LifecycleDomain::create_context`]'s arguments after the deps.
pub struct CreateContextRequest<'a> {
    /// The new context's identifier.
    pub context_id: String,
    /// The new context's parameters.
    pub params: ContextParams,
    /// The creating member.
    pub creator_did: DID,
    /// The creator's pseudonym in the context, if it uses one.
    pub local_pseudonym: Option<[u8; 32]>,
    /// The relays the context publishes through.
    pub relay_urls: Vec<String>,
    /// The first-state claim the caller reserved before the create.
    pub first_state: &'a FirstStateRollback,
}

/// [`GovernanceDomain::execute_propose_context_migration`]'s arguments after
/// the cell and deps.
pub struct ProposeMigrationRequest<'a> {
    /// The migrating context.
    pub context_id: &'a str,
    /// The destination context's parameters.
    pub new_context_params: &'a ContextParams,
    /// The proposal's stated reason.
    pub reason: &'a str,
    /// The grace period before the source closes.
    pub grace_period_secs: u64,
    /// Whether members are invited to the destination automatically.
    pub auto_invite: bool,
    /// The executing commit's metadata.
    pub meta: CommitMeta<'a>,
    /// The bootstrap guard and first-state claim the executing call reserved.
    pub bootstrap: MigrationBootstrap,
}

/// [`OutletsDomain::reserve_outlet_economy`]'s arguments after the cell and
/// deps.
pub struct ReserveOutletEconomyRequest<'a> {
    /// The context hosting the outlet.
    pub context_id: &'a str,
    /// The invoking member.
    pub invoker_did: &'a DID,
    /// The spending UCAN the invocation presents, if any.
    pub spending_ucan: Option<&'a UcanToken>,
    /// The value-caveat binding the invocation carries, if any.
    pub caveat_binding: Option<&'a InvocationCaveatBinding>,
    /// The invocation input.
    pub input: &'a serde_json::Value,
    /// The reservation time.
    pub now_secs: u64,
}

/// Messaging domain (spec §5.4).
#[async_trait]
pub trait MessagingDomain: Send + Sync {
    /// Runs one messaging command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: MessagingCommand,
    ) -> Outcome<()>;

    /// Opens an inbound envelope and classifies its content.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the envelope cannot be opened.
    async fn decrypt_and_dispatch(
        &self,
        deps: &ActorDeps,
        crypto_state: Option<&mut ContextCryptoState>,
        context_id: &str,
        context_id_bytes: &[u8; 32],
        encrypted_blob: &[u8],
        denied: &HashSet<String>,
    ) -> Result<Dispatched, ContextError>;

    /// Records and publishes a sealed outbound message.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the publish or persist fails.
    async fn finalize_send(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        send: FinalizeSendRequest<'_>,
    ) -> Result<(), ContextError>;
}

/// Lifecycle domain: create, join, import, restore and close.
#[async_trait]
pub trait LifecycleDomain: Send + Sync {
    /// Runs one lifecycle command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: LifecycleCommand,
    ) -> Outcome<()>;

    /// Closes a context.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the close fails.
    async fn close_context(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        handle: &ContextHandle,
        initiator_did: &DID,
    ) -> Result<CloseResult, ContextError>;

    /// Creates a context and spawns its actor.
    ///
    /// # Errors
    /// Returns a `ContextCreationError` when validation or spawn fails.
    async fn create_context(
        &self,
        deps: &ActorDeps,
        create: CreateContextRequest<'_>,
    ) -> Result<SpawnedContext, ContextCreationError>;

    /// Delivers queued sender keys to members.
    async fn drain_and_deliver_sender_keys(
        &self,
        deps: &ActorDeps,
        view: &mut ClassCMut<'_>,
        context_id: &str,
        scope: DistributionScope,
    ) -> DistributionReport;

    /// Imports a context from a signed export.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the export fails validation.
    async fn import_context_from_export(
        &self,
        deps: &ActorDeps,
        export: ContextExport,
        verifying_key: &ed25519_dalek::VerifyingKey,
        local_pseudonym: Option<[u8; 32]>,
        first_state: &FirstStateRollback,
    ) -> Result<SpawnedContext, ContextError>;

    /// Restores every persisted context at Supervisor start.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the snapshot list cannot be read.
    async fn restore_all_contexts(
        &self,
        supervisor: &Arc<Supervisor>,
    ) -> Result<Vec<String>, ContextError>;

    /// Restores one context's state into its freshly spawned actor.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the snapshot fails validation.
    async fn restore_context(
        &self,
        deps: &ActorDeps,
        context_id: &str,
        handle: &ContextHandle,
        preloaded_snapshot: Option<ContextSnapshot>,
    ) -> Result<(), ContextError>;

    /// Retries a sender-key rotation an earlier turn left pending.
    async fn retry_pending_sender_key_rotation(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
    );

    /// Rotates the local sender key and distributes it.
    async fn rotate_sender_key_and_distribute(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
    );

    /// Shuts down every running context actor.
    async fn shutdown_all_contexts(&self, supervisor: &Supervisor);
}

/// Governance domain.
#[async_trait]
pub trait GovernanceDomain: Send + Sync {
    /// Runs one governance command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: GovernanceCommand,
    ) -> Outcome<()>;

    /// Evaluates proposal and deadlock timeouts on the actor's tick.
    async fn evaluate_governance_timeouts(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
    ) -> Outcome<bool>;

    /// Applies the consequence rules a new event triggered.
    async fn enforce_triggered_consequences(
        &self,
        state: &mut ConsequenceStateSplit<'_>,
        args: &EnforceConsequencesCtx<'_>,
        obligation: &mut Option<ClassSCommitToken>,
    ) -> bool;

    /// Reads the event-log entries consequence evaluation needs.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the event log cannot be read.
    fn event_log_entries_for_consequences(
        &self,
        receive_buffer: &ReceiveBuffer,
        context_id: &str,
        now: u64,
        event_log: &dyn ContextEventLogProvider,
    ) -> Result<(Vec<scp_event_log::Event>, u64), ContextError>;

    /// Reads the event-log entries consequence evaluation needs after a side
    /// effect already ran, falling back to the receive buffer.
    fn event_log_entries_for_consequences_after_side_effect(
        &self,
        receive_buffer: &ReceiveBuffer,
        context_id: &str,
        now: u64,
        event_log: &dyn ContextEventLogProvider,
    ) -> (Vec<scp_event_log::Event>, u64);

    /// Executes an approved context-migration proposal.
    fn execute_propose_context_migration<'a>(
        &'a self,
        cell: &'a mut ClassSCell,
        deps: &'a ActorDeps,
        proposal: ProposeMigrationRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<MigrationProposedResult, ContextError>> + Send + 'a>>;

    /// Executes a revocation.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the revocation fails.
    async fn execute_revoke(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        did: &DID,
        access: AccessScope,
        meta: CommitMeta<'_>,
    ) -> Result<usize, ContextError>;

    /// Keeps a failed commit broadcast for retry.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the pending commit cannot be kept.
    async fn keep_broadcast_failure(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        failure: BroadcastFailure,
    ) -> Result<(), ContextError>;

    /// Publishes a commit, returning the failure to keep when it does not land.
    async fn try_broadcast_commit(
        &self,
        deps: &ActorDeps,
        context_id: &str,
        commit_bytes: Vec<u8>,
        operation: &CommitOperation,
    ) -> Option<BroadcastFailure>;
}

/// Broadcast domain.
#[async_trait]
pub trait BroadcastDomain: Send + Sync {
    /// Runs one broadcast command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: BroadcastCommand,
    ) -> Outcome<()>;

    /// Blocks a subscriber from an author's broadcast.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the block fails.
    async fn block_broadcast_subscriber(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<BlockResult, ContextError>;

    /// Lifts a subscriber block.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the unblock fails.
    async fn unblock_broadcast_subscriber(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<(), ContextError>;
}

/// Economy domain (spec §19).
#[async_trait]
pub trait EconomyDomain: Send + Sync {
    /// Runs one economy command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: EconomyCommand,
    ) -> Outcome<()>;

    /// Places the escrow hold for a paid action.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the payment adapter refuses.
    async fn authorize_paid_action_hold(
        &self,
        inputs: OwnedAuthInputs,
        payer_did: &DID,
        context_id: &str,
    ) -> Result<Option<PaidActionAuthorization>, ContextError>;

    /// Reads what a paid-action hold needs from the actor state.
    fn authorize_paid_action_prepare(
        &self,
        state: &PerContextState,
        deps: &ActorDeps,
        action_type: PaidActionType,
        payer_did: &DID,
    ) -> Option<OwnedAuthInputs>;

    /// Captures a held payment and verifies its receipt.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when capture or verification fails.
    async fn capture_and_verify_paid_action(
        &self,
        auth: PaidActionAuthorization,
    ) -> Result<Option<PaymentReceipt>, ContextError>;

    /// Emits the `PaymentReceived` event for a captured receipt.
    fn emit_payment_received_event(
        &self,
        receive_buffer: &mut ReceiveBuffer,
        deps: &ActorDeps,
        receipt: &PaymentReceipt,
        context_id: &str,
    );

    /// Enforces pricing, budget and spending authority for one action.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the action is refused.
    fn enforce_economy(
        &self,
        req: EnforceEconomyRequest<'_>,
    ) -> Result<Option<Amount>, ContextError>;
}

/// Trust-recovery domain.
#[async_trait]
pub trait TrustRecoveryDomain: Send + Sync {
    /// Runs one trust-recovery command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: TrustRecoveryCommand,
    ) -> Outcome<()>;
}

/// Standing-pair domain.
#[async_trait]
pub trait StandingDomain: Send + Sync {
    /// Runs one standing command; it reads no per-context state.
    async fn dispatch(&self, deps: &ActorDeps, cmd: StandingCommand) -> Outcome<()>;
}

/// TTL-close domain.
#[async_trait]
pub trait TtlCloseDomain: Send + Sync {
    /// Runs one TTL-close command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: TtlCloseCommand,
    ) -> Outcome<()>;

    /// Extends the convergent TTL deadline and records the extension leaf.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the leaf cannot be appended.
    async fn extend_ttl_deadline_and_record(
        &self,
        cell: &mut ClassSCell,
        event_log: &dyn ContextEventLogProvider,
        context_id_bytes: &[u8; 32],
        actor_did: &str,
        additional_secs: u64,
        leaf: ExtensionLeaf,
    ) -> Result<(), ContextError>;

    /// Runs TTL expiry for the context.
    async fn handle_ttl_expiry(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        handle: &ContextHandle,
        prior_completed: u8,
    ) -> TtlExpiryOutcome;

    /// Re-arms the TTL timer with a new duration.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the context is not active.
    async fn reset_ttl_timer(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        new_duration: Duration,
    ) -> Result<(), ContextError>;
}

/// Outlets domain.
#[async_trait]
pub trait OutletsDomain: Send + Sync {
    /// Runs one outlets command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: OutletsCommand,
    ) -> Outcome<()>;

    /// Reserves the economy an outlet invocation will spend.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the reservation is refused.
    async fn reserve_outlet_economy(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        reserve: ReserveOutletEconomyRequest<'_>,
    ) -> Result<OutletEconomyReservation, ContextError>;

    /// Reverses a caller-side reservation record.
    async fn reverse_caller_reservation_record(
        &self,
        view: ClassCMut<'_>,
        deps: &ActorDeps,
        record: &CallerReservationRecord,
    ) -> bool;

    /// Settles an outlet invocation's economy.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when settlement fails.
    async fn settle_outlet_economy(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
        invoker_did: &DID,
        request: OutletSettleRequest,
    ) -> Result<OutletSettleOutcome, ContextError>;
}

/// Push-wake domain.
pub trait PushDomain: Send + Sync {
    /// Runs one push command; it only reads the actor state.
    fn dispatch(&self, state: &PerContextState, cmd: PushCommand) -> Outcome<()>;
}

/// Queries domain.
#[async_trait]
pub trait QueriesDomain: Send + Sync {
    /// Runs one query command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: QueriesCommand,
    ) -> Outcome<()>;

    /// Compares a remote consistency checkpoint with the local log.
    ///
    /// # Errors
    /// Returns the domain's `ContextError` when the local log cannot be read.
    fn compare_remote_checkpoint(
        &self,
        view: &mut ClassCMut<'_>,
        deps: &ActorDeps,
        context_id: &str,
        remote: &ConsistencyCheckpoint,
    ) -> Result<CheckpointComparison, ContextError>;
}

/// Saga domain.
#[async_trait]
pub trait SagaDomain: Send + Sync {
    /// Runs one saga phase inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: SagaPhaseMessage,
    ) -> Outcome<()>;
}

/// Lifecycle-control domain.
#[async_trait]
pub trait LifecycleControlDomain: Send + Sync {
    /// Runs one lifecycle-control command inside the actor turn.
    async fn dispatch(
        &self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        cmd: LifecycleControlCommand,
    ) -> Outcome<()>;
}
