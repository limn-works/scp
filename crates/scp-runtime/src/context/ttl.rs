//! Context close, finalize, TTL expiry, TTL enforcement, and TTL timer
//! management.
//!
//! Implements the context lifecycle termination operations from ADR-008
//! (`.docs/adrs/phase-2.md`) and TTL enforcement from ADR-018
//! (`.docs/adrs/phase-4.md`):
//!
//! - [`close_context`] -- Initiates cooperative close (Active -> Closing).
//! - [`finalize_close`] -- Completes close after members process notifications
//!   (Closing -> Closed).
//! - [`try_ttl_expiry_cleanup`] -- Automatic expiry when TTL elapses
//!   (Active -> Expired): terminal transition + key destruction +
//!   idempotent `ContextExpired` leaf.
//! - [`TtlTimer`] -- Records a context's convergent TTL expiry deadline
//!   (the actor-owned TTL arm reconciles a one-shot sleep against it;
//!   ADR-049 finding A3).
//! - [`TtlExtension`] -- Tracks unanimous consent for TTL extension.
//! - [`TtlPolicy`] -- TTL policy enum: `None` or `Finite(Duration)`.
//! - [`TtlExtensionProposal`] -- Proposal for TTL extension with consent
//!   tracking for bilateral and multi-party contexts.
//!
//! # Close Capability
//!
//! The initiator of `close_context` must hold the `ContextClose` capability
//! (admin role or governance-permitted). This is checked via
//! [`ContextRoleState::member_has_capability`].
//!
//! # TTL Enforcement (ADR-018 / ADR-049 finding A3)
//!
//! TTL is an ACTOR-OWNED timer arm: a context's convergent expiry deadline is
//! recorded on [`TtlTimer`] and the per-context actor's `reconcile_timers`
//! derives a one-shot sleep against it, firing the expiry pipeline on wake. TTL
//! expiry transitions the context to `Expired` and destroys keys per memory
//! scope -- no new actions are accepted after expiry. Extension requires
//! consent: all-member for bilateral contexts, governance for multi-party
//! contexts.
//!
//! # Memory Scope Behavior
//!
//! - **Ephemeral:** Keys destroyed on close/expiry. Content becomes unreadable.
//! - **Summary:** Summary generated during closing window, then keys destroyed.
//! - **Full:** Keys retained. Content remains readable after close.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use super::ContextHandle;
use super::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::crypto::mls::provider::MlsCryptoProvider;
use scp_clock::Clock;
use scp_did::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::roles::{self, ContextRoleState};
use scp_protocol::context::{ContextError, ContextState, MemoryScope};

// ---------------------------------------------------------------------------
// context_id_to_bytes helper (mirrors manager.rs)
// ---------------------------------------------------------------------------

/// Resolves a context-ID string to its MLS/event-log keying bytes.
///
/// Delegates to the canonical [`crate::context::state::context_id_to_bytes`]
/// (ADR-056): a real 64-hex context id resolves to its raw digest, matching
/// `PerContextState.context_id`; synthetic / non-context strings hash exactly
/// as before. Keeping this local wrapper aligned with `state`'s resolver is
/// what prevents the close/expire TTL crypto paths (`destroy_mls_group`,
/// `append_context_event`) from silently keying under the old `SHA-256(id)`
/// while live state keys under the digest.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    crate::context::state::context_id_to_bytes(context_id)
}

// ---------------------------------------------------------------------------
// TtlPolicy
// ---------------------------------------------------------------------------

/// TTL policy for a context, declared at creation time.
///
/// Determines whether the context has a finite lifespan. Contexts with
/// `Finite` TTL automatically expire when the duration elapses. Contexts
/// with `None` TTL have no automatic expiry.
///
/// See ADR-018 in `.docs/adrs/phase-4.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtlPolicy {
    /// No TTL -- the context has no automatic expiry.
    None,
    /// Finite TTL -- the context expires after this duration from creation
    /// (or from the last extension).
    Finite(Duration),
}

// ---------------------------------------------------------------------------
// TtlError
// ---------------------------------------------------------------------------

/// Errors produced by TTL enforcement operations.
#[derive(Debug, thiserror::Error)]
pub enum TtlError {
    /// The context's TTL has expired. No further actions are permitted.
    #[error("context TTL has expired")]
    Expired,

    /// A TTL extension was proposed for a context with no TTL policy.
    #[error("cannot extend TTL on a context with no TTL policy")]
    NoTtlPolicy,

    /// A TTL extension proposal is already in progress.
    #[error("a TTL extension proposal is already in progress")]
    ProposalAlreadyActive,

    /// No active TTL extension proposal to consent to.
    #[error("no active TTL extension proposal")]
    NoActiveProposal,

    /// The governance model does not permit this member to propose or
    /// approve extensions in a multi-party context.
    #[error("governance does not permit extension: {0}")]
    GovernanceDenied(String),
}

// ---------------------------------------------------------------------------
// TtlExpiryResult — structured expiry outcome with partial-success tracking
// ---------------------------------------------------------------------------

/// Tracks which cleanup operations succeeded/failed during TTL expiry.
///
/// Returned from both individual cleanup attempts and the retry loop.
/// On full success, all step bits are set and `errors` is empty.
/// On partial failure, the bitmask records which operations completed
/// so that retries can skip already-succeeded steps.
#[derive(Debug, Clone)]
pub struct TtlExpiryResult {
    /// Bitfield tracking completion of each cleanup step.
    ///
    /// Bit 0: state transition to `Expired`.
    /// Bit 1: MLS group destruction (or not required).
    /// Bit 2: sender key destruction (or not required).
    /// Bit 3: event log append.
    completed_steps: u8,
    /// The error messages from failed operations.
    errors: Vec<String>,
    /// `true` iff this is the deliberate no-op ABORT result
    /// ([`Self::aborted_no_deadline`], A3) — the single-source deadline was
    /// `None`, so the expiry did nothing (no transition, no key destruction). The
    /// actor uses this to distinguish an intentional benign abort from a genuine
    /// incomplete cleanup, so it does not emit a misleading "retrying" error.
    aborted: bool,
}

/// Bit positions for [`TtlExpiryResult::completed_steps`].
const STEP_STATE_TRANSITIONED: u8 = 0b0000_0001;
const STEP_MLS_DESTROYED: u8 = 0b0000_0010;
const STEP_SENDER_KEY_DESTROYED: u8 = 0b0000_0100;
const STEP_EVENT_LOGGED: u8 = 0b0000_1000;

/// Mask for all steps complete.
const ALL_STEPS: u8 =
    STEP_STATE_TRANSITIONED | STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED | STEP_EVENT_LOGGED;

/// Per-op budget for the BEST-EFFORT relay ciphertext deletion in the terminal
/// (expiry / close) paths (M2). Well under the handler-level
/// `HANDLER_TIMEOUT` (30 s) so a hostile/stalled relay cannot consume the whole
/// handler budget and starve the completeness-critical terminal leaf append —
/// which now runs BEFORE the relay delete. On elapse the delete is logged and
/// skipped: the keys are already destroyed, so the retained ciphertext is
/// unreadable regardless (§5.11).
const RELAY_DELETE_BUDGET: Duration = Duration::from_secs(5);

impl TtlExpiryResult {
    /// Whether the state transition to `Expired` succeeded.
    #[must_use]
    pub const fn state_transitioned(&self) -> bool {
        self.completed_steps & STEP_STATE_TRANSITIONED != 0
    }

    /// Whether MLS group destruction succeeded (or was not required).
    #[must_use]
    pub const fn mls_destroyed(&self) -> bool {
        self.completed_steps & STEP_MLS_DESTROYED != 0
    }

    /// Whether sender key destruction succeeded (or was not required).
    #[must_use]
    pub const fn sender_key_destroyed(&self) -> bool {
        self.completed_steps & STEP_SENDER_KEY_DESTROYED != 0
    }

    /// Whether the event log append succeeded.
    #[must_use]
    pub const fn event_logged(&self) -> bool {
        self.completed_steps & STEP_EVENT_LOGGED != 0
    }

    /// The error messages from failed cleanup operations.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// The raw `completed_steps` bitmask, for carrying forward across on-actor
    /// retries (SEC-1): the actor stores this in
    /// [`ContextActor::ttl_expiry_completed`](crate::context::actor) and passes
    /// it back as `prior_completed` on the next attempt so an already-succeeded
    /// step (a destroyed key, an appended leaf) is not re-run.
    #[must_use]
    pub const fn completed_steps(&self) -> u8 {
        self.completed_steps
    }

    const fn set_step(&mut self, step: u8) {
        self.completed_steps |= step;
    }

    /// A no-op result for an ABORTED TTL expiry (ADR-049 §9, A3): the
    /// single-source convergent deadline was `None` (promotion / no-TTL / empty
    /// or failed-hydration log), so the timer must NOT transition the FSM or
    /// destroy keys. No step is marked complete; the descriptive error records
    /// why the expiry did nothing.
    ///
    /// [`handle_ttl_expiry`](crate::context::ttl_close_helpers::handle_ttl_expiry)
    /// returns this WITHOUT emitting any `Expired` / `ExpiryFailed` event and
    /// after clearing the stale cached deadline, so the actor neither despawns
    /// nor retry-loops — the FSM is left untouched (`Active`).
    #[must_use]
    pub fn aborted_no_deadline() -> Self {
        Self {
            completed_steps: 0,
            errors: vec![
                "TTL expiry aborted: the single-source convergent deadline is None \
                 (promotion / no-TTL / empty or failed-hydration log); refusing key \
                 destruction (A3)"
                    .to_owned(),
            ],
            aborted: true,
        }
    }

    /// Whether this is the deliberate no-op ABORT result (A3): the single-source
    /// deadline was `None`, so nothing was transitioned or destroyed. Distinct
    /// from a genuine incomplete cleanup (which SHOULD be retried).
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        self.aborted
    }
}

impl std::fmt::Display for TtlExpiryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_complete() {
            write!(f, "TTL expiry complete")
        } else {
            write!(
                f,
                "TTL expiry incomplete (state_transitioned={}, mls_destroyed={}, \
                 sender_key_destroyed={}, event_logged={}): {}",
                self.state_transitioned(),
                self.mls_destroyed(),
                self.sender_key_destroyed(),
                self.event_logged(),
                self.errors.join("; "),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionConsentMode -- bilateral vs multi-party
// ---------------------------------------------------------------------------

/// Determines the consent model for TTL extension.
///
/// See ADR-018 acceptance criterion 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionConsentMode {
    /// All members must consent (bilateral contexts with exactly 2 members).
    AllMember,
    /// Extension follows the context's governance model (multi-party).
    Governance,
}

/// Determines the consent mode based on member count.
#[must_use]
pub const fn consent_mode_for_member_count(member_count: usize) -> ExtensionConsentMode {
    if member_count <= 2 {
        ExtensionConsentMode::AllMember
    } else {
        ExtensionConsentMode::Governance
    }
}

// ---------------------------------------------------------------------------
// TtlExtensionProposal -- structured extension proposal
// ---------------------------------------------------------------------------

/// A structured proposal for TTL extension, recorded as a context event
/// in the Merkle log (ADR-011).
///
/// See ADR-018 acceptance criterion 3.
#[derive(Debug, Clone)]
pub struct TtlExtensionProposal {
    /// DID of the member who proposed the extension.
    proposer_did: DID,
    /// The proposed additional TTL duration.
    proposed_duration: Duration,
    /// The consent mode (bilateral vs governance).
    consent_mode: ExtensionConsentMode,
    /// The underlying consent tracker.
    consent: TtlExtension,
    /// The governance model for this context.
    governance: GovernanceModel,
}

impl TtlExtensionProposal {
    /// Creates a new TTL extension proposal.
    #[must_use]
    pub fn new(
        proposer_did: DID,
        proposed_duration: Duration,
        member_count: usize,
        governance: GovernanceModel,
    ) -> Self {
        let consent_mode = consent_mode_for_member_count(member_count);
        let required_count = match consent_mode {
            ExtensionConsentMode::AllMember => member_count,
            ExtensionConsentMode::Governance => match &governance {
                GovernanceModel::SingleAdmin => 1,
                GovernanceModel::Threshold { threshold, .. } => *threshold as usize,
                GovernanceModel::Majority { eligible_voters } => {
                    // >50% of eligible voters (rounding up).
                    eligible_voters.len().div_ceil(2)
                }
                GovernanceModel::Unanimity { eligible_voters } => eligible_voters.len(),
            },
        };
        Self {
            proposer_did,
            proposed_duration,
            consent_mode,
            consent: TtlExtension::new(proposed_duration, required_count),
            governance,
        }
    }

    /// Records a member's consent for the extension.
    pub fn record_consent(&mut self, member_did: DID) -> bool {
        self.consent.add_consent(member_did)
    }

    /// Returns `true` if sufficient consent has been collected.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.consent.is_unanimous()
    }

    /// Returns the DID of the proposer.
    #[must_use]
    pub const fn proposer_did(&self) -> &DID {
        &self.proposer_did
    }

    /// Returns the proposed additional TTL duration.
    #[must_use]
    pub const fn proposed_duration(&self) -> Duration {
        self.proposed_duration
    }

    /// Returns the consent mode for this proposal.
    #[must_use]
    pub const fn consent_mode(&self) -> ExtensionConsentMode {
        self.consent_mode
    }

    /// Returns the number of consents received so far.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consent.consent_count()
    }

    /// Returns the number of consents still needed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.consent.remaining()
    }

    /// Returns the governance model for this proposal's context.
    #[must_use]
    pub const fn governance(&self) -> &GovernanceModel {
        &self.governance
    }

    /// Returns `true` if sufficient consent has been collected from active
    /// members only.
    ///
    /// Votes from members who were removed after casting their vote are
    /// excluded from the tally. The threshold is evaluated against the count
    /// of active-member votes only.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn is_approved_active(&self, active_members: &HashSet<DID>) -> bool {
        self.consent.is_unanimous_active(active_members)
    }

    /// Returns the number of consents from currently active members.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_consent_count(&self, active_members: &HashSet<DID>) -> usize {
        self.consent.active_consent_count(active_members)
    }

    /// Returns the number of active-member consents still needed.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_remaining(&self, active_members: &HashSet<DID>) -> usize {
        self.consent.active_remaining(active_members)
    }

    /// Computes the new deadline by adding the proposed duration to now.
    #[must_use]
    pub const fn compute_new_deadline(&self, now: u64) -> u64 {
        now.saturating_add(self.proposed_duration.as_secs())
    }
}

// ---------------------------------------------------------------------------
// close_context
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure.
///
/// See ADR-008 acceptance criterion 5.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`.
/// Returns [`ContextError::PermissionDenied`] if the initiator lacks the
/// `ContextClose` capability.
// ADR-049 §Decision 12: `state`/`transition_to` are now synchronous lock-free
// ArcSwap ops. Async is retained as the ContextManager helper API contract —
// callers await uniformly, and the event-log provider calls regain await
// points under ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::unused_async)]
pub async fn close_context(
    handle: &ContextHandle,
    initiator_did: &DID,
    role_state: &ContextRoleState,
    event_log: &dyn ContextEventLogProvider,
    // Convergent close timestamp recorded on the `ContextClosing` leaf: the
    // initiator's close-commit time (the `created_at` of the outgoing close
    // commit), copied by every member — never a per-member local `now()`
    // (§7.3.1, §9.9.3).
    timestamp_secs: u64,
) -> Result<CloseResult, ContextError> {
    let state = handle.state();
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    if !role_state.member_has_capability(initiator_did, &roles::Capability::ContextClose) {
        return Err(ContextError::PermissionDenied(format!(
            "member {initiator_did} does not have context:close capability"
        )));
    }

    handle.transition_to(&ContextState::Closing)?;

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);

    let memory_scope = handle.params().memory_scope;
    let should_generate_summary = memory_scope == MemoryScope::Summary;
    let should_schedule_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    event_log
        .append_context_event(
            &context_id_bytes,
            scp_event_log::EventType::ContextClosing,
            initiator_did.as_ref(),
            timestamp_secs,
        )
        .await?;

    Ok(CloseResult {
        should_generate_summary,
        should_schedule_key_destruction,
    })
}

/// Result of a successful `close_context` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseResult {
    /// If `true`, the caller should trigger summary generation.
    pub should_generate_summary: bool,
    /// If `true`, key destruction should be scheduled.
    pub should_schedule_key_destruction: bool,
}

// ---------------------------------------------------------------------------
// finalize_close
// ---------------------------------------------------------------------------

/// Completes context closure after all members have processed notifications.
///
/// See ADR-008 acceptance criterion 6.
///
/// # Errors
///
/// Returns [`ContextError::InvalidTransition`] if the context is not in
/// `Closing` state.
// ADR-049 §Decision 12: `transition_to` is now a synchronous lock-free ArcSwap
// store. Async is retained as the ContextManager helper API contract — callers
// await uniformly, and the crypto/transport/event-log provider calls regain
// await points under ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::unused_async)]
pub async fn finalize_close(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: &dyn ContextTransportProvider,
    event_log: &dyn ContextEventLogProvider,
    // Timestamp recorded on the `ContextClosed` leaf. This lower-level producer
    // records whatever instant the caller supplies. The sole production caller,
    // `ttl_close_helpers::finalize_close`, is the EXPLICIT Closing→Closed path and
    // passes the ACTUAL local close instant (`clock.now_secs()`): the convergent
    // TTL deadline would be a future instant unrelated to when the close happened
    // (F4). Cross-member convergence of an explicit governance close is anchored by
    // the prior `ContextClosing` leaf (the governance committer's convergent
    // close-commit time), not this terminal leaf's exact instant. The timer-driven
    // TTL path stamps a `ContextExpired` leaf off the convergent deadline in
    // `handle_ttl_expiry` and never reaches this function (§7.3.1, §9.9.3).
    timestamp_secs: u64,
) -> Result<(), ContextError> {
    // Validate state transition BEFORE destroying any key material.
    // Key destruction is irreversible — once zeroized, encrypted content
    // becomes permanently unreadable. If the transition fails (e.g. context
    // is not in Closing state), no keys must be destroyed.
    handle.transition_to(&ContextState::Closed)?;

    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    // Full memory scope retains keys — content remains readable after close.
    // Only destroy crypto material for Ephemeral and Summary scopes. Key
    // destruction is synchronous; the best-effort relay ciphertext deletion is
    // deferred until AFTER the completeness-critical `ContextClosed` append
    // below (M2), so a stalled relay cannot delay/starve the terminal leaf.
    let needs_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;
    if needs_key_destruction {
        crypto
            .destroy_mls_group(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        crypto
            .destroy_sender_key(&context_id_bytes)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
    }

    // (d) idempotent terminal leaf (ADR-049 §9 amendment): if a `ContextClosed`
    // leaf already exists for this context (a prior finalize appended it, then
    // the actor was interrupted / respawned before completing), do NOT append a
    // second one — a duplicate terminal leaf diverges the Merkle root across
    // members. A provider that cannot read entries falls back to the append
    // (Risk 3 safe fallback; the production `MerkleEventLogProvider` supports
    // reading). Runs BEFORE the best-effort relay delete (M2).
    if !terminal_leaf_exists(
        event_log,
        &context_id_bytes,
        scp_event_log::EventType::ContextClosed,
    ) {
        event_log
            .append_context_event(
                &context_id_bytes,
                scp_event_log::EventType::ContextClosed,
                scp_event_log::system_actors::SYSTEM_CLOSE_ACTOR,
                timestamp_secs,
            )
            .await?;
    }

    // Best-effort relay ciphertext deletion (§5.11), AFTER the critical
    // `ContextClosed` append and under its OWN bounded budget (M2) so a
    // hostile/stalled relay cannot delay the terminal leaf. Best-effort by
    // design: the keys are already destroyed, so the ciphertext is unreadable
    // regardless of whether the relay honours the delete.
    if needs_key_destruction {
        match tokio::time::timeout(
            RELAY_DELETE_BUDGET,
            transport.delete_published(&context_id_bytes),
        )
        .await
        {
            Ok(_) => {}
            Err(_elapsed) => {
                tracing::warn!(context_id = %context_id, budget = ?RELAY_DELETE_BUDGET,
                    "best-effort relay deletion exceeded its budget after close; \
                     skipping (keys already destroyed — ciphertext is unreadable)");
            }
        }
    }

    Ok(())
}

/// Single-call TTL-expiry COMPOSITION.
///
/// Runs the terminal phase ([`apply_ttl_terminal_transition`]) and, if it
/// transitioned, the bounded-I/O phase ([`finish_ttl_expiry_io`]) back-to-back,
/// returning a structured result.
///
/// This is NOT the live automatic-expiry path and it is NOT dead code. The live
/// actor path ([`crate::context::ttl_close_helpers::handle_ttl_expiry`]) drives
/// the two phases SEPARATELY so the fail-closed persist of the terminal
/// `Expired` state runs OUTSIDE the relay/event-log transport timeout (SEC-1).
/// This function is the convenient whole-in-one form, and is exercised by this
/// module's idempotency tests as the phase-equivalence composition (it must
/// produce the same result as the two phases run in sequence).
///
/// Returns a [`TtlExpiryResult`] that tracks which operations succeeded and
/// which failed. The `prior_completed` bitmask carries forward steps that
/// already succeeded on a previous attempt so they are not re-executed.
/// This prevents duplicate event log entries and redundant crypto operations
/// across retries.
///
/// State transition is inherently idempotent (an already-`Expired` context
/// is recognized as transitioned), but crypto destruction and event log
/// appends are **not** idempotent — hence the bitmask guard.
// ADR-049 §Decision 12: `state`/`transition_to` are now synchronous lock-free
// ArcSwap ops. Async is retained as the ContextManager helper API contract —
// callers await uniformly, and the crypto/transport/event-log provider calls
// regain await points under ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::unused_async)]
pub async fn try_ttl_expiry_cleanup(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    prior_completed: u8,
    // Timer-triggered expiry: the pre-computed convergent TTL deadline (every
    // member holds the identical value), recorded on the `ContextExpired` leaf
    // instead of a per-member local `now()` (§7.3.1, §9.9.3).
    expiry_deadline_secs: u64,
) -> TtlExpiryResult {
    // The SEC-1 rework (ADR-049 §9 amendment) splits this into a SYNC terminal
    // phase (FSM transition + key destruction — the security-critical steps the
    // actor persists FAIL-CLOSED before teardown) and an ASYNC bounded-I/O phase
    // (best-effort relay deletion + idempotent `ContextExpired` append). This
    // whole-in-one composition is the convenient single-call form (exercised by
    // this module's tests); the actor
    // (`ttl_close_helpers::handle_ttl_expiry`) drives the two phases
    // ([`apply_ttl_terminal_transition`] + [`finish_ttl_expiry_io`]) SEPARATELY
    // so the fail-closed persist runs OUTSIDE the relay/event-log transport
    // timeout.
    let result = apply_ttl_terminal_transition(handle, crypto, prior_completed);
    if result.completed_steps & STEP_STATE_TRANSITIONED == 0 {
        // Transition failed / context not in an expiry-eligible state — bail
        // before any I/O (mirrors the prior early return).
        return result;
    }
    finish_ttl_expiry_io(handle, transport, event_log, result, expiry_deadline_secs).await
}

/// SYNC terminal phase of TTL expiry (SEC-1): FSM transition + key destruction.
///
/// Transitions `Active`/`Expired` → `Expired` and destroys keys
/// (Ephemeral/Summary scopes). No transport or event-log I/O — those are the
/// caller's bounded-I/O phase ([`finish_ttl_expiry_io`]).
///
/// These are the security-critical steps the actor persists FAIL-CLOSED (ADR-049
/// §9 amendment, SEC-1): a lost persist of the terminal `Expired` state re-opens
/// the hostile-relay resurrection window, and a swallowed key-destruction failure
/// leaves keys undestroyed. Running them synchronously (they do no `.await`) lets
/// the caller drive them + the fail-closed persist OUTSIDE any transport timeout,
/// so a hung relay cannot cancel the durable terminal transition.
///
/// The `prior_completed` bitmask carries steps that already succeeded on a
/// previous attempt so a retry re-runs ONLY the failed step (e.g. a transient
/// `destroy_sender_key` failure). State transition is idempotent (an
/// already-`Expired` context is recognized as transitioned); key destruction is
/// bitmask-guarded.
#[must_use]
pub(crate) fn apply_ttl_terminal_transition(
    handle: &ContextHandle,
    crypto: &MlsCryptoProvider,
    prior_completed: u8,
) -> TtlExpiryResult {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;

    let mut result = TtlExpiryResult {
        completed_steps: prior_completed,
        errors: Vec::new(),
        aborted: false,
    };

    let needs_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    // If keys are not required to be destroyed, mark them as done.
    if !needs_key_destruction {
        result.set_step(STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED);
    }

    // 1. State transition (idempotent — skip if already Expired or already
    //    completed on a prior attempt).
    if result.completed_steps & STEP_STATE_TRANSITIONED == 0 {
        let state = handle.state();
        match state {
            ContextState::Active => match handle.transition_to(&ContextState::Expired) {
                Ok(_) => result.set_step(STEP_STATE_TRANSITIONED),
                Err(e) => {
                    let msg = format!("state transition failed: {e}");
                    tracing::error!(context_id = %context_id, "{msg}");
                    result.errors.push(msg);
                    // Cannot proceed with cleanup if transition failed.
                    return result;
                }
            },
            ContextState::Expired => {
                // Already expired (retry path). Continue with cleanup.
                result.set_step(STEP_STATE_TRANSITIONED);
            }
            _ => {
                let msg = format!(
                    "context is in {state} state, expected Active or Expired for TTL expiry"
                );
                tracing::error!(context_id = %context_id, "{msg}");
                result.errors.push(msg);
                return result;
            }
        }
    }

    // 2. Key destruction (Ephemeral/Summary only). Each operation is
    //    independent — a failure in one does not block the other. Skip
    //    operations that already succeeded on a prior attempt. SYNC crypto
    //    ops (no `.await`), so this whole phase runs outside any timeout.
    if needs_key_destruction {
        if result.completed_steps & STEP_MLS_DESTROYED == 0 {
            match crypto.destroy_mls_group(&context_id_bytes) {
                Ok(()) => result.set_step(STEP_MLS_DESTROYED),
                Err(e) => {
                    let msg = format!("failed to destroy MLS group: {e}");
                    tracing::warn!(context_id = %context_id, error = %e,
                        "failed to destroy MLS group after TTL expiry — keys may persist");
                    result.errors.push(msg);
                }
            }
        }
        if result.completed_steps & STEP_SENDER_KEY_DESTROYED == 0 {
            match crypto.destroy_sender_key(&context_id_bytes) {
                Ok(()) => result.set_step(STEP_SENDER_KEY_DESTROYED),
                Err(e) => {
                    let msg = format!("failed to destroy sender key: {e}");
                    tracing::warn!(context_id = %context_id, error = %e,
                        "failed to destroy sender key after TTL expiry — keys may persist");
                    result.errors.push(msg);
                }
            }
        }
    }

    result
}

/// ASYNC bounded-I/O phase of TTL expiry (SEC-1): relay deletion + leaf append.
///
/// Best-effort relay ciphertext deletion (§5.11) followed by the IDEMPOTENT
/// `ContextExpired` event-log append (ADR-049 §9 amendment, finding (d)).
/// Consumes and returns the running [`TtlExpiryResult`] so the caller can carry
/// `completed_steps` forward across retries.
///
/// The caller wraps this in `tokio::time::timeout(HANDLER_TIMEOUT, …)`: both the
/// relay deletion and the event-log append issue UNBOUNDED provider awaits, so a
/// hung relay must not wedge the single-threaded actor. The security-critical
/// terminal transition + fail-closed persist ran BEFORE this in
/// [`apply_ttl_terminal_transition`], outside that timeout.
///
/// # Idempotent leaf ((d))
///
/// Before appending, the running-tail of the event log is consulted
/// ([`ContextEventLogProvider::event_log_entries`]): if a terminal
/// `ContextExpired` leaf already exists for this context (a prior attempt
/// appended it, then crashed / was interrupted before recording the step), the
/// `STEP_EVENT_LOGGED` bit is set WITHOUT re-appending — no duplicate leaf, a
/// stable Merkle root across respawn. A provider that does not support entry
/// reading (`Err`) falls back to the bitmask-only behavior (append once per the
/// `completed_steps` guard).
pub(crate) async fn finish_ttl_expiry_io(
    handle: &ContextHandle,
    transport: Option<&dyn ContextTransportProvider>,
    event_log: &dyn ContextEventLogProvider,
    mut result: TtlExpiryResult,
    expiry_deadline_secs: u64,
) -> TtlExpiryResult {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);
    let memory_scope = handle.params().memory_scope;
    let needs_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    // ORDERING (M2): the completeness-critical `ContextExpired` leaf append runs
    // FIRST — BEFORE the best-effort relay deletion below — and the relay
    // deletion is bounded by its OWN budget. Pre-fix, `delete_published` was
    // awaited first while sharing the single outer `timeout(HANDLER_TIMEOUT)`
    // with the append: a hostile/stalled relay could consume the whole budget,
    // the append never ran, `is_complete()` never went true, and the actor's
    // TTL-expiry retry re-fired forever — the terminal leaf was never recorded.
    // Appending first (a committed side effect even if the outer timeout later
    // elapses) plus a bounded relay budget decouples the two so a stalled relay
    // can never starve the leaf.

    // 3. Event log append — skip if already succeeded on a prior attempt to
    //    avoid duplicate ContextExpired entries in the Merkle log.
    if result.completed_steps & STEP_EVENT_LOGGED == 0 {
        // (d) idempotent leaf: if a terminal `ContextExpired` leaf already
        // exists (a prior attempt appended it but did not record the step
        // before an interruption), mark the step done WITHOUT re-appending so
        // the Merkle root stays stable across respawn. A provider that cannot
        // read entries falls back to the append below (bitmask-only guard).
        if terminal_leaf_exists(
            event_log,
            &context_id_bytes,
            scp_event_log::EventType::ContextExpired,
        ) {
            result.set_step(STEP_EVENT_LOGGED);
        } else {
            match event_log
                .append_context_event(
                    &context_id_bytes,
                    scp_event_log::EventType::ContextExpired,
                    scp_event_log::system_actors::SYSTEM_TIMER_ACTOR,
                    expiry_deadline_secs,
                )
                .await
            {
                Ok(()) => result.set_step(STEP_EVENT_LOGGED),
                Err(e) => {
                    let msg = format!("failed to log ContextExpired event: {e}");
                    tracing::warn!(context_id = %context_id, error = %e,
                        "failed to append ContextExpired to event log");
                    result.errors.push(msg);
                }
            }
        }
    }

    // Best-effort relay ciphertext deletion (§5.11), AFTER the critical append
    // and under its OWN bounded budget (M2). Relay deletion is non-blocking —
    // even if the relay retains the encrypted blobs, the keys are destroyed and
    // the data is unreadable — so it is NOT tracked in the completeness bitmask.
    // Bounding it here means a hostile/stalled relay cannot hold this future
    // open and starve the actor's retry loop: the append above already ran, and
    // a stall past `RELAY_DELETE_BUDGET` is logged and skipped.
    if needs_key_destruction && let Some(transport) = transport {
        match tokio::time::timeout(
            RELAY_DELETE_BUDGET,
            transport.delete_published(&context_id_bytes),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(context_id = %context_id, error = %e,
                    "best-effort relay deletion failed after TTL expiry");
            }
            Err(_elapsed) => {
                tracing::warn!(context_id = %context_id, budget = ?RELAY_DELETE_BUDGET,
                    "best-effort relay deletion exceeded its budget after TTL expiry; \
                     skipping (keys already destroyed — ciphertext is unreadable)");
            }
        }
    }

    result
}

/// Returns `true` iff a terminal leaf of `event_type` already exists in the
/// event log for `context_id_bytes` (ADR-049 §9 amendment, idempotent terminal
/// leaf — finding (d)).
///
/// Consults [`ContextEventLogProvider::event_log_entries`]. A provider that does
/// not support entry reading (`Err`) — or a context with no log yet
/// (`Ok(None)`) — returns `false`: the caller then appends (or re-appends) under
/// its bitmask guard, the pre-(d) behavior. This is the SAFE fallback (Risk 3):
/// the production `MerkleEventLogProvider` supports reading, so real deployments
/// get the idempotent skip; a reduced test/embedded provider degrades to
/// append-once semantics rather than failing closed.
fn terminal_leaf_exists(
    event_log: &dyn ContextEventLogProvider,
    context_id_bytes: &[u8; 32],
    event_type: scp_event_log::EventType,
) -> bool {
    match event_log.event_log_entries(context_id_bytes) {
        Ok(Some(entries)) => entries.iter().any(|e| e.event_type == event_type),
        // `Ok(None)` (no log yet) and `Err(_)` (provider cannot read entries)
        // both fall back to "no existing leaf" ⇒ the caller appends under its
        // bitmask guard (the safe pre-(d) behavior).
        Ok(None) | Err(_) => false,
    }
}

impl TtlExpiryResult {
    /// Returns `true` if any cleanup operation failed.
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.completed_steps != ALL_STEPS
    }

    /// Returns `true` if the cleanup is fully complete — no errors.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.completed_steps == ALL_STEPS
    }
}

// ---------------------------------------------------------------------------
// TtlTimer -- convergent TTL deadline record (actor-owned arm)
// ---------------------------------------------------------------------------

/// Records a context's convergent TTL expiry deadline.
///
/// ADR-049 finding A3: the TTL timer is an ACTOR-OWNED arm — this type no
/// longer spawns or holds a background task. It carries the convergent expiry
/// `deadline_unix_secs` (recorded by
/// [`ttl_close_helpers::start_ttl_timer`](crate::context::ttl_close_helpers))
/// plus the clock used to compute remaining TTL for persistence snapshots. The
/// `ContextActor` `run()` loop reconciles a one-shot `sleep` against this
/// deadline and runs the expiry pipeline on wake.
pub struct TtlTimer {
    /// Absolute expiry deadline as Unix epoch seconds. `None` when no finite
    /// TTL is armed. Read by [`Self::remaining_secs`] (persistence snapshots)
    /// and by the actor's `reconcile_timers`.
    pub(crate) deadline_unix_secs: Option<u64>,
    /// Clock used for deadline computation.
    pub(crate) clock: Arc<dyn Clock>,
}

impl TtlTimer {
    /// Creates a new `TtlTimer` with no deadline, using the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            deadline_unix_secs: None,
            clock: Arc::new(scp_clock::SystemClock),
        }
    }

    /// Creates a new `TtlTimer` with a specific clock.
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            deadline_unix_secs: None,
            clock,
        }
    }

    /// Returns the remaining TTL seconds, computed from the stored deadline.
    ///
    /// Returns `None` only when no deadline has been recorded; returns `0`
    /// if the deadline has already passed.
    ///
    /// # Deadline-derived (ADR-049 finding A3)
    ///
    /// Derived purely from `deadline_unix_secs`. The TTL timer is an
    /// ACTOR-OWNED arm: `start_ttl_timer` records the convergent deadline
    /// without spawning any task. The persistence snapshot now persists the
    /// ABSOLUTE `deadline_unix_secs` directly (as `ttl_deadline_secs`), so this
    /// relative helper no longer gates restore re-arming.
    #[must_use]
    pub fn remaining_secs(&self) -> Option<u64> {
        let deadline = self.deadline_unix_secs?;
        let now_secs = self.clock.now_secs();
        Some(deadline.saturating_sub(now_secs))
    }
}

impl Default for TtlTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TtlExtension -- unanimous consent tracking
// ---------------------------------------------------------------------------

/// Tracks member consent for TTL extension.
#[derive(Debug, Clone)]
pub struct TtlExtension {
    /// The proposed new TTL duration.
    pub proposed_duration: Duration,
    /// DIDs that have consented to the extension.
    consented: HashSet<DID>,
    /// Total member count required for unanimity.
    required_count: usize,
}

impl TtlExtension {
    /// Creates a new TTL extension proposal.
    #[must_use]
    pub fn new(proposed_duration: Duration, member_count: usize) -> Self {
        Self {
            proposed_duration,
            consented: HashSet::new(),
            required_count: member_count,
        }
    }

    /// Records a member's consent. Returns `true` if this was a new consent.
    pub fn add_consent(&mut self, member_did: DID) -> bool {
        self.consented.insert(member_did)
    }

    /// Returns `true` if all members have consented (unanimous).
    #[must_use]
    pub fn is_unanimous(&self) -> bool {
        self.consented.len() >= self.required_count
    }

    /// Returns the number of consents received so far.
    #[must_use]
    pub fn consent_count(&self) -> usize {
        self.consented.len()
    }

    /// Returns the number of consents still needed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.required_count.saturating_sub(self.consented.len())
    }

    /// Returns the consenting member DIDs as a lexicographically SORTED `Vec`.
    ///
    /// The sort makes the list CONVERGENT (the underlying set iterates in a
    /// non-deterministic order): every member recording the `TtlExtended` leaf
    /// (§5.10.1 step 5) from the same consent tally serialises the identical
    /// `consenting_members` field. Used by
    /// [`reset_ttl_timer`](crate::context::ttl_close_helpers::reset_ttl_timer)
    /// to attribute the activation to the members who consented.
    #[must_use]
    pub fn consented_dids(&self) -> Vec<String> {
        let mut dids: Vec<String> = self.consented.iter().map(ToString::to_string).collect();
        dids.sort_unstable();
        dids
    }

    /// Returns the number of consents from members who are still active.
    ///
    /// Votes from members who have been removed since casting their vote are
    /// excluded from the count. This prevents a removed member's stale vote
    /// from contributing to the tally at evaluation time.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_consent_count(&self, active_members: &HashSet<DID>) -> usize {
        self.consented
            .iter()
            .filter(|did| active_members.contains(*did))
            .count()
    }

    /// Returns `true` if sufficient consent has been collected from active
    /// members only.
    ///
    /// Votes from removed members are excluded. The threshold is evaluated
    /// against the count of active-member votes, not the total historical
    /// vote count.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn is_unanimous_active(&self, active_members: &HashSet<DID>) -> bool {
        self.active_consent_count(active_members) >= self.required_count
    }

    /// Returns the number of active-member consents still needed.
    ///
    /// See SCP-195.
    #[must_use]
    pub fn active_remaining(&self, active_members: &HashSet<DID>) -> usize {
        self.required_count
            .saturating_sub(self.active_consent_count(active_members))
    }
}

// ---------------------------------------------------------------------------
// ContextEvent variants for close/expiry notifications
// ---------------------------------------------------------------------------

/// Creates a `SystemClose` notification event.
#[must_use]
pub fn closing_notification(initiator_did: &DID) -> ContextEvent {
    ContextEvent::SystemClose {
        initiator_did: initiator_did.clone(),
    }
}

/// Creates a `ContextExpired` notification event.
#[must_use]
pub const fn expiry_notification() -> ContextEvent {
    ContextEvent::Expired
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::iter_on_single_items,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use scp_clock::TestClock;
    use scp_protocol::context::params::ContextParams;
    use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use std::time::Duration;

    use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};

    /// Test DID used by the real [`MlsCryptoProvider`] in test bodies.
    ///
    /// The prior `MockCrypto` / `FailingMlsCrypto` / `TransientFailCrypto`
    /// scaffolds are deleted along with the `ContextCryptoProvider`
    /// trait in ADR-049 commit 12c.9e. Success-path tests now build a
    /// real [`MlsCryptoProvider::new(TEST_DID.to_owned())`]; tests that
    /// asserted mock trackers (`mls_destroyed` counts, sender-key-destroyed
    /// counts) or fail-injection semantics are `#[ignore]`d pending
    /// `MlsBackend`-level fail-injection in commit 12c.9f.
    const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn mk_crypto() -> std::sync::Arc<MlsCryptoProvider> {
        std::sync::Arc::new(MlsCryptoProvider::new(
            TEST_DID.to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ))
    }

    // ---------------------------------------------------------------------------
    // Transport / event-log mocks — these do NOT touch crypto.
    // ---------------------------------------------------------------------------

    struct NullTransport;

    #[async_trait::async_trait]
    impl ContextTransportProvider for NullTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _cid: &[u8; 32],
            _p: &ContextParams,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn delete_published(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn send_message(&self, _cid: &[u8; 32], _payload: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    /// Event-log double that STORES appended leaves and returns them from
    /// `event_log_entries`, so the idempotent-terminal-leaf guard ((d)) can
    /// observe an already-present `ContextExpired` leaf across a simulated
    /// respawn (a second attempt whose completed-steps bitmask was lost). The
    /// production `MerkleEventLogProvider` supports the same read (Risk 3).
    #[derive(Default)]
    struct StatefulEventLog {
        // Test-only capture buffer; the guard is never held across an `.await`
        // (locked, mutated, dropped synchronously). Per
        // `crates/scp-runtime/clippy.toml`, test-only `std::sync::Mutex` sites
        // carry this allow.
        #[allow(clippy::disallowed_types)]
        entries: std::sync::Mutex<Vec<scp_event_log::Event>>,
    }

    #[async_trait::async_trait]
    impl ContextEventLogProvider for StatefulEventLog {
        async fn init_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _cid: &[u8; 32],
            event: scp_event_log::EventType,
            actor_did: &str,
            payload: scp_event_log::EventPayload,
            timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.entries.lock().unwrap().push(scp_event_log::Event {
                event_type: event,
                actor_did: scp_did::DID(actor_did.to_owned()),
                timestamp: timestamp_secs,
                sequence: 0,
                payload,
                prev_hash: [0u8; 32],
                signature: Vec::new(),
            });
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn event_log_entries(
            &self,
            _cid: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            Ok(Some(self.entries.lock().unwrap().clone()))
        }
    }

    /// (d) idempotent terminal leaf (ADR-049 §9 amendment): a SECOND TTL expiry
    /// whose in-memory completed-steps bitmask was lost (a respawn re-running
    /// from `prior_completed = 0`) must NOT re-append a duplicate
    /// `ContextExpired` leaf — a duplicate diverges the Merkle root across
    /// members. Pre-fix, `try_ttl_expiry_cleanup` appended unconditionally
    /// whenever `STEP_EVENT_LOGGED` was unset, so the second attempt appended a
    /// second leaf. Post-fix it consults the log tail and skips.
    #[tokio::test]
    async fn expiry_leaf_append_is_idempotent_across_respawn() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = StatefulEventLog::default();
        let handle = active_handle("ctx-ttl-idem", MemoryScope::Full);

        // First expiry — appends the ContextExpired leaf.
        let r1 = super::try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            Some(&transport),
            &event_log,
            0,
            1_700_000_000,
        )
        .await;
        assert!(r1.is_complete(), "first expiry completes: {r1}");

        // Second expiry from a FRESH bitmask (respawn lost `prior_completed`):
        // the terminal leaf already exists, so the append is skipped.
        let r2 = super::try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            Some(&transport),
            &event_log,
            0,
            1_700_000_000,
        )
        .await;
        assert!(
            r2.is_complete(),
            "second expiry completes (idempotent): {r2}"
        );

        let entries = event_log.entries.lock().unwrap();
        let expired_count = entries
            .iter()
            .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
            .count();
        assert_eq!(
            expired_count, 1,
            "ContextExpired must be appended EXACTLY once across a respawn \
             (idempotent terminal leaf, (d)); pre-fix it appended twice"
        );
    }

    /// A transport whose `delete_published` STALLS (sleeps far past any budget),
    /// modelling a hostile/wedged relay. `send`/`publish` succeed. Records
    /// whether `delete_published` was ever entered so a test can assert the
    /// relay op was attempted (and stalled) rather than skipped.
    #[derive(Default)]
    struct StallingTransport {
        delete_entered: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl ContextTransportProvider for StallingTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _cid: &[u8; 32],
            _p: &ContextParams,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn delete_published(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.delete_entered
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // Stall far beyond any handler / relay budget.
            tokio::time::sleep(Duration::from_hours(1)).await;
            Ok(())
        }
        async fn send_message(&self, _cid: &[u8; 32], _payload: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    /// M2 (relay stall must not starve the leaf append, REGRESSION GATE): a
    /// hostile/stalled relay `delete_published` must NOT prevent the
    /// completeness-critical `ContextExpired` leaf from being recorded within
    /// the handler budget.
    ///
    /// Pre-fix this FAILED: `finish_ttl_expiry_io` awaited `delete_published`
    /// FIRST, sharing the single outer `timeout(HANDLER_TIMEOUT)` with the leaf
    /// append. A relay that stalls past the budget consumed the whole timeout,
    /// the append never ran, `is_complete()` never went true, and the actor's
    /// TTL-expiry retry re-fired forever with the leaf never recorded. The fix
    /// appends the leaf FIRST and bounds the best-effort relay delete with its
    /// own `RELAY_DELETE_BUDGET`, so a stalled relay cannot starve the append.
    #[tokio::test(start_paused = true)]
    async fn relay_stall_does_not_starve_leaf_append() {
        let crypto = mk_crypto();
        let transport = StallingTransport::default();
        let event_log = StatefulEventLog::default();
        // Ephemeral scope ⇒ the terminal path DOES issue the best-effort relay
        // delete (the op that stalls), and key destruction is idempotent on the
        // real crypto provider for an unregistered context.
        let handle = active_handle("ctx-ttl-relay-stall", MemoryScope::Ephemeral);

        // Wrap exactly as the actor does: a single outer `timeout(HANDLER_TIMEOUT)`
        // around the terminal I/O. Under `start_paused`, tokio auto-advances
        // virtual time to the next timer, so the bounded relay delete resolves at
        // `RELAY_DELETE_BUDGET` (5 s) — well within `HANDLER_TIMEOUT` (30 s) —
        // rather than the relay's 3600 s stall.
        let outcome = tokio::time::timeout(
            crate::context::actor::handlers::ttl_close::HANDLER_TIMEOUT,
            super::try_ttl_expiry_cleanup(
                &handle,
                crypto.as_ref(),
                Some(&transport),
                &event_log,
                0,
                1_700_000_000,
            ),
        )
        .await;

        let result = outcome.expect(
            "append-first + bounded relay budget must let the terminal I/O finish \
             within HANDLER_TIMEOUT despite the relay stall (M2); pre-fix the \
             relay-first ordering consumed the whole budget and this elapsed",
        );
        assert!(
            result.is_complete(),
            "the ContextExpired leaf is recorded despite the relay stall (M2): {result}"
        );

        let entries = event_log.entries.lock().unwrap();
        let expired_count = entries
            .iter()
            .filter(|e| e.event_type == scp_event_log::EventType::ContextExpired)
            .count();
        assert_eq!(
            expired_count, 1,
            "the ContextExpired leaf MUST be recorded exactly once despite the stall"
        );
        assert!(
            transport
                .delete_entered
                .load(std::sync::atomic::Ordering::SeqCst),
            "the best-effort relay delete WAS attempted (and stalled) — the append \
             simply no longer waits on it"
        );
    }

    struct NullEventLog;

    #[async_trait::async_trait]
    impl ContextEventLogProvider for NullEventLog {
        async fn init_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _cid: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Records the `(EventType, actor_did)` of every append so a test can
    /// assert the real producer stamps the convergent system-leaf sentinel.
    #[derive(Default)]
    struct CapturingEventLog {
        // Test-only capture buffer; the guard is never held across an `.await`
        // (locked, pushed, and dropped synchronously inside `append_event`).
        // Per `crates/scp-runtime/clippy.toml`, test-only `std::sync::Mutex`
        // sites carry this allow.
        #[allow(clippy::disallowed_types)]
        appends: std::sync::Mutex<Vec<(scp_event_log::EventType, String)>>,
    }

    #[async_trait::async_trait]
    impl ContextEventLogProvider for CapturingEventLog {
        async fn init_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _cid: &[u8; 32],
            event: scp_event_log::EventType,
            actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.appends
                .lock()
                .unwrap()
                .push((event, actor_did.to_owned()));
            Ok(())
        }
        async fn destroy_event_log(
            &self,
            _cid: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// §9.9.3 convergence: the native `finalize_close` producer MUST
    /// stamp the descriptive sentinel `"system:close"` on the `ContextClosed`
    /// leaf so it is byte-identical across all honest members' `finalize_close` leaves.
    #[tokio::test]
    async fn finalize_close_stamps_system_close_actor_did() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = CapturingEventLog::default();
        let handle = active_handle("ctx-close-actor", MemoryScope::Full);
        handle.transition_to(&ContextState::Closing).unwrap();
        finalize_close(
            &handle,
            crypto.as_ref(),
            &transport,
            &event_log,
            1_700_000_000,
        )
        .await
        .unwrap();

        let appends = event_log.appends.lock().unwrap();
        let closed = appends
            .iter()
            .find(|(e, _)| *e == scp_event_log::EventType::ContextClosed)
            .expect("ContextClosed leaf must be appended by finalize_close");
        assert_eq!(
            closed.1, "system:close",
            "native ContextClosed leaf MUST stamp \"system:close\" (§9.9.3 convergence)"
        );
    }

    /// §9.9.3 convergence: the native TTL-expiry producer
    /// ([`try_ttl_expiry_cleanup`]) MUST stamp the descriptive sentinel
    /// `"system:timer"` on the `ContextExpired` leaf so it is byte-identical
    /// across all honest members' leaves.
    #[tokio::test]
    async fn ttl_expiry_stamps_system_timer_actor_did() {
        let crypto = mk_crypto();
        let event_log = CapturingEventLog::default();
        let handle = active_handle("ctx-ttl-actor", MemoryScope::Full);
        let res = super::try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            Some(&NullTransport),
            &event_log,
            0,
            1_700_000_000,
        )
        .await;
        assert!(!res.has_failures(), "expiry cleanup completes: {res}");

        let appends = event_log.appends.lock().unwrap();
        let expired = appends
            .iter()
            .find(|(e, _)| *e == scp_event_log::EventType::ContextExpired)
            .expect("ContextExpired leaf must be appended by try_ttl_expiry_cleanup");
        assert_eq!(
            expired.1, "system:timer",
            "native ContextExpired leaf MUST stamp \"system:timer\" (§9.9.3 convergence)"
        );
    }

    fn active_handle(context_id: &str, memory_scope: MemoryScope) -> ContextHandle {
        let params = ContextParams {
            memory_scope,
            ..Default::default()
        };
        let handle = ContextHandle::new(context_id.to_owned(), params);
        handle.transition_to(&ContextState::Active).ok();
        handle
    }

    // ---------------------------------------------------------------------------
    // Smoke tests — just exercise the real MlsCryptoProvider path.
    // Deeper behaviour was covered by mock trackers that no longer exist;
    // those tests are deferred to commit 12c.9f (MlsBackend injection).
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn finalize_close_full_scope_skips_destruction() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = NullEventLog;
        let handle = active_handle("ctx-1", MemoryScope::Full);
        handle.transition_to(&ContextState::Closing).unwrap();
        let res = finalize_close(
            &handle,
            crypto.as_ref(),
            &transport,
            &event_log,
            1_700_000_000,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn finalize_close_ephemeral_scope_runs_destruction() {
        let crypto = mk_crypto();
        let transport = NullTransport;
        let event_log = NullEventLog;
        let handle = active_handle("ctx-eph", MemoryScope::Ephemeral);
        handle.transition_to(&ContextState::Closing).unwrap();
        let res = finalize_close(
            &handle,
            crypto.as_ref(),
            &transport,
            &event_log,
            1_700_000_000,
        )
        .await;
        // Real MlsCryptoProvider is idempotent on destroy for unregistered ctxs.
        assert!(res.is_ok());
    }

    /// ADR-056 forward-secrecy regression guard for the TTL-expiry destruction
    /// path. `try_ttl_expiry_cleanup` MUST resolve its MLS-keying bytes through
    /// the canonical
    /// [`context_id_to_bytes`](crate::context::state::context_id_to_bytes)
    /// chokepoint, NOT the raw
    /// [`context_id_bytes`](scp_protocol::context::context_id_bytes) primitive.
    ///
    /// For a REAL 64-hex member-context id the chokepoint DECODES the string to
    /// its 32-byte digest, while the raw primitive RE-HASHES it
    /// (`SHA-256(hex(digest))`). The live MLS group and sender key are keyed
    /// under the DIGEST, so a regression to the raw primitive would call
    /// `destroy_mls_group(SHA-256(id))` — a no-op against an unkeyed slot —
    /// while the real group SURVIVES past TTL expiry (the ADR-056 fail-open).
    ///
    /// The other ttl.rs tests use `"ctx-*"` labels, for which the chokepoint
    /// and the raw primitive coincide. This test seeds the group + sender key
    /// under the DIGEST of a real 64-hex id, drives the production
    /// `try_ttl_expiry_cleanup` path with an Ephemeral handle carrying the
    /// STRING id, and asserts the group was PRESENT before and GONE after —
    /// under the digest. `export_crypto_state` returns a non-empty snapshot only
    /// for a keyed context (empty vec otherwise), so a destruction that keyed
    /// off `SHA-256(id)` would leave the digest slot populated and FAIL the
    /// post-destruction emptiness assertion (mutation-resistant).
    #[tokio::test]
    async fn ttl_expiry_destroys_real_context_via_chokepoint_not_raw_primitive() {
        // A REAL (64-hex) member-context id: `hex(digest)` of a 32-byte digest.
        let digest = [0xABu8; 32];
        let id = hex::encode(digest);
        assert_eq!(id.len(), 64, "fixture id must be a real 64-hex context id");

        // Precondition: the canonical resolver DECODES the 64-hex id to its
        // digest, while the raw primitive RE-HASHES it. The two must differ,
        // otherwise this test could not distinguish the keying paths.
        let chokepoint_bytes = crate::context::state::context_id_to_bytes(&id);
        let raw_bytes = scp_protocol::context::context_id_bytes(&id);
        assert_eq!(
            chokepoint_bytes, digest,
            "the chokepoint must decode a 64-hex id to its digest"
        );
        assert_ne!(
            chokepoint_bytes, raw_bytes,
            "test precondition: digest must differ from SHA-256(hex(digest))"
        );

        // Seed an MLS group AND a sender key under the DIGEST — the slot the
        // live context (and the chokepoint) key on.
        let crypto = mk_crypto();
        crypto
            .create_mls_group(&digest)
            .expect("create_mls_group under the digest");
        crypto
            .generate_sender_key(&digest)
            .expect("generate_sender_key under the digest");

        // The group MUST be present under the digest before expiry — proves this
        // is a real destroy, not a phantom no-op against an empty slot.
        let before = crypto
            .export_crypto_state(&digest, Vec::new(), Vec::new())
            .expect("export under the decoded digest must not error");
        assert!(
            !before.is_empty(),
            "precondition: crypto state must be keyed under the digest before TTL expiry"
        );

        // Drive the REAL TTL-expiry destruction path with an Ephemeral handle
        // carrying the STRING id, so production resolves id -> bytes via the
        // chokepoint at :792.
        let event_log = NullEventLog;
        let handle = active_handle(&id, MemoryScope::Ephemeral);
        let result = try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            Some(&NullTransport),
            &event_log,
            0,
            1_700_000_000,
        )
        .await;

        // The cleanup must complete with no failures, and must report both the
        // MLS group and the sender key destroyed.
        assert!(
            !result.has_failures(),
            "TTL expiry cleanup must complete cleanly, errors: {:?}",
            result.errors()
        );
        assert!(
            result.mls_destroyed(),
            "TTL expiry must destroy the MLS group"
        );
        assert!(
            result.sender_key_destroyed(),
            "TTL expiry must destroy the sender key"
        );

        // The group MUST be GONE under the digest after expiry. If production had
        // resolved via the raw `SHA-256(id)` primitive, `destroy_mls_group`
        // would have addressed an unkeyed slot (a silent no-op) and the digest
        // slot would still be populated — this assertion FAILS in that case.
        let after_digest = crypto
            .export_crypto_state(&digest, Vec::new(), Vec::new())
            .expect("export under the decoded digest must not error");
        assert!(
            after_digest.is_empty(),
            "ADR-056 FAIL-OPEN: the MLS group SURVIVED under the digest after TTL \
             expiry — destruction keyed off the wrong slot (raw SHA-256(id) \
             instead of the chokepoint digest)"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_transitions_active_to_expired() {
        let crypto = mk_crypto();
        let event_log = NullEventLog;
        let handle = active_handle("ctx-ttl", MemoryScope::Full);
        let res = super::try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            None,
            &event_log,
            0,
            1_700_000_000,
        )
        .await;
        assert!(!res.has_failures(), "expiry cleanup completes: {res}");
        assert_eq!(handle.state(), ContextState::Expired);
    }

    #[tokio::test]
    async fn ttl_expiry_rejects_non_active_contexts() {
        let crypto = mk_crypto();
        let event_log = NullEventLog;
        let handle = ContextHandle::new("ctx-new".to_owned(), ContextParams::default());
        // Handle is in Creating state — not Active / Expired, so the terminal
        // transition is refused: the cleanup reports failure and no transition.
        let res = super::try_ttl_expiry_cleanup(
            &handle,
            crypto.as_ref(),
            None,
            &event_log,
            0,
            1_700_000_000,
        )
        .await;
        assert!(res.has_failures(), "non-active expiry must report failure");
        assert!(
            !res.state_transitioned(),
            "a non-Active/Expired context must not be transitioned by TTL expiry"
        );
        assert_eq!(
            handle.state(),
            ContextState::Creating,
            "the FSM stays in its original (Creating) state"
        );
    }

    /// ADR-049 finding A3: the ACTOR-OWNED TTL arm records the deadline on
    /// `TtlTimer` WITHOUT spawning any task, so `remaining_secs` derives from
    /// the recorded deadline. The persistence snapshot now persists the
    /// ABSOLUTE `deadline_unix_secs` directly (`ttl_deadline_secs`); this
    /// derived relative view is retained for callers that still want a
    /// remaining-time read.
    #[test]
    fn remaining_secs_is_deadline_derived() {
        let clock: std::sync::Arc<dyn scp_clock::Clock> = std::sync::Arc::new(TestClock::new(1000));
        let mut timer = TtlTimer::with_clock(clock);
        assert_eq!(timer.remaining_secs(), None, "no deadline recorded ⇒ None");

        // The actor arm records the convergent deadline directly.
        timer.deadline_unix_secs = Some(1000 + 600);
        assert_eq!(
            timer.remaining_secs(),
            Some(600),
            "a recorded deadline yields remaining"
        );

        // A past deadline saturates to 0 (a restore past the deadline
        // re-arms sleep(0) and re-closes idempotently).
        timer.deadline_unix_secs = Some(900);
        assert_eq!(timer.remaining_secs(), Some(0));
    }

    // ---------------------------------------------------------------------------
    // TtlExpiryResult pure tests (no crypto touched).
    // ---------------------------------------------------------------------------

    #[test]
    fn ttl_expiry_result_complete_when_all_steps_set() {
        let mut r = TtlExpiryResult {
            completed_steps: 0,
            errors: Vec::new(),
            aborted: false,
        };
        r.set_step(STEP_STATE_TRANSITIONED);
        r.set_step(STEP_MLS_DESTROYED);
        r.set_step(STEP_SENDER_KEY_DESTROYED);
        r.set_step(STEP_EVENT_LOGGED);
        assert!(r.is_complete());
        assert!(!r.has_failures());
    }

    #[test]
    fn ttl_expiry_result_has_failures_when_steps_missing() {
        let mut r = TtlExpiryResult {
            completed_steps: 0,
            errors: Vec::new(),
            aborted: false,
        };
        r.set_step(STEP_STATE_TRANSITIONED);
        assert!(r.has_failures());
        assert!(!r.is_complete());
    }

    // ---------------------------------------------------------------------------
    // TtlExtension pure tests.
    // ---------------------------------------------------------------------------

    #[test]
    fn ttl_extension_tracks_consent() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 3);
        assert_eq!(ext.consent_count(), 0);
        assert_eq!(ext.remaining(), 3);
        assert!(ext.add_consent(scp_did::DID::from("did:scp:alice")));
        assert_eq!(ext.consent_count(), 1);
        assert!(!ext.is_unanimous());
        assert!(ext.add_consent(scp_did::DID::from("did:scp:bob")));
        assert!(ext.add_consent(scp_did::DID::from("did:scp:carol")));
        assert!(ext.is_unanimous());
        assert_eq!(ext.remaining(), 0);
    }

    #[test]
    fn ttl_extension_duplicate_consent_rejected() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 2);
        let did = scp_did::DID::from("did:scp:alice");
        assert!(ext.add_consent(did.clone()));
        assert!(!ext.add_consent(did));
    }

    #[test]
    fn ttl_extension_active_consent_counts_exclude_removed_members() {
        let mut ext = TtlExtension::new(Duration::from_mins(1), 3);
        ext.add_consent(scp_did::DID::from("did:scp:alice"));
        ext.add_consent(scp_did::DID::from("did:scp:bob"));
        ext.add_consent(scp_did::DID::from("did:scp:carol"));
        let active: std::collections::HashSet<_> = [
            scp_did::DID::from("did:scp:alice"),
            scp_did::DID::from("did:scp:bob"),
        ]
        .into_iter()
        .collect();
        assert_eq!(ext.active_consent_count(&active), 2);
        assert!(!ext.is_unanimous_active(&active));
        assert_eq!(ext.active_remaining(&active), 1);
    }

    // ADR-049 commit 12c.9f: backend-injection seam landed via
    // `MlsCryptoProvider::with_backends`. Pre-existing tests that
    // asserted `MockCrypto` tracker behaviour (mls_destroyed counters,
    // sender-key-destroyed counters, fail-injection retry semantics)
    // are now expressed by passing a fail-injecting
    // `Arc<dyn MlsBackend>` into `with_backends`. The smoke below
    // confirms the seam exists; functional fail-injection tests live
    // next to the production-backend tests in
    // `crate::crypto::mls::production_backend`.
    #[test]
    fn ttl_fail_injection_uses_backend_injection() {
        use crate::crypto::hpke_backend::ProductionHpkeBackend;
        use crate::crypto::mls::production_backend::ProductionMlsBackend;
        use crate::crypto::mls::provider::MlsCryptoProvider;
        use std::sync::Arc;

        let provider = MlsCryptoProvider::with_backends(
            TEST_DID.to_owned(),
            Arc::new(ProductionMlsBackend::new(std::sync::Arc::new(
                scp_clock::SystemClock,
            ))),
            Arc::new(ProductionHpkeBackend::new()),
            std::sync::Arc::new(scp_clock::SystemClock),
        );
        let _mls = provider.mls_backend();
        let _hpke = provider.hpke_backend();
    }

    // Unused trait/type imports from the pre-12c.9e test scaffolding
    // must keep compiling: silence the "unused import" lint only where
    // the import truly has no downstream reference in the shrunk test
    // module.
    #[allow(dead_code)]
    const _CEILING_SMOKE: [Capability; 0] = [];
    #[allow(dead_code)]
    const _ROLE_STATE_SMOKE: Option<ContextRoleState> = None;
    #[allow(dead_code)]
    const _CEILING_STATE: Option<CapabilityCeiling> = None;
}
