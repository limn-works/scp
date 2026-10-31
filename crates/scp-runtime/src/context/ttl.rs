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
//! - [`apply_ttl_terminal_transition`] -- Automatic expiry when TTL elapses
//!   (Active -> Expired): terminal transition + key destruction. The caller
//!   (`ttl_close_helpers::handle_ttl_expiry`) queues the `ContextExpired`
//!   record in the persist that records the transition.
//! - [`delete_published_bounded`] -- Best-effort relay ciphertext deletion for
//!   a terminal Ephemeral or Summary context.
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
use super::builder::ContextTransportProvider;
use super::state::LeafSpec;
// #2148 (ADR-049 birth-into-actor): production TTL/close paths no longer take a
// crypto provider (key destruction runs on the actor-owned crypto). The single
// test that constructs a provider imports it locally.
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
/// `HANDLER_TIMEOUT` (30 s) so a hostile/stalled relay cannot hold the actor's
/// turn open; the terminal record is queued before the delete runs. On elapse
/// the delete is logged and skipped: the keys are already destroyed, so the
/// retained ciphertext is unreadable regardless (§5.11).
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

    /// Whether the `ContextExpired` record is durable: queued in the persist
    /// that recorded `Expired`, or already in the log or the queue.
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

    /// Records why a step the caller ran outside this module did not complete,
    /// leaving its bit unset so the expiry retries it.
    pub(crate) fn record_failure(&mut self, error: String) {
        self.errors.push(error);
    }

    /// Marks the `ContextExpired` record step done: the record is queued in
    /// the persist that recorded `Expired`, or the log or the queue already
    /// held it.
    pub(crate) const fn mark_event_logged(&mut self) {
        self.set_step(STEP_EVENT_LOGGED);
    }

    /// Whether `steps`, a carried `completed_steps` bitmask, includes the
    /// `ContextExpired` record step.
    pub(crate) const fn event_logged_in(steps: u8) -> bool {
        steps & STEP_EVENT_LOGGED != 0
    }

    /// A no-op result for an ABORTED TTL expiry (ADR-049 §9, A3): the
    /// single-source convergent deadline was `None` (promotion / no-TTL / empty
    /// or failed-hydration log), so the timer must NOT transition the FSM or
    /// destroy keys. No step is marked complete; the descriptive error records
    /// why the expiry did nothing.
    ///
    /// `handle_ttl_expiry`
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
/// Returns the close result and the `ContextClosing` record, planned before
/// the `Active -> Closing` transition. The caller queues the record in the
/// persist that records the transition (spec 17 §17.3 "Event log write
/// failures"); this function writes nothing to the event log.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotActive`] if the context is not `Active`.
/// Returns [`ContextError::PermissionDenied`] if the initiator lacks the
/// `ContextClose` capability.
pub fn close_context(
    handle: &ContextHandle,
    initiator_did: &DID,
    role_state: &ContextRoleState,
    // Convergent close timestamp recorded on the `ContextClosing` leaf: the
    // initiator's close-commit time (the `created_at` of the outgoing close
    // commit), copied by every member — never a per-member local `now()`
    // (§7.3.1, §9.9.3).
    timestamp_secs: u64,
) -> Result<(CloseResult, LeafSpec), ContextError> {
    let state = handle.state();
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }

    if !role_state.member_has_capability(initiator_did, &roles::Capability::ContextClose) {
        return Err(ContextError::PermissionDenied(format!(
            "member {initiator_did} does not have context:close capability"
        )));
    }

    let closing_record = LeafSpec::without_payload(
        scp_event_log::EventType::ContextClosing,
        initiator_did.as_ref().to_owned(),
        timestamp_secs,
    );

    handle.transition_to(&ContextState::Closing)?;

    let memory_scope = handle.params().memory_scope;
    let should_generate_summary = memory_scope == MemoryScope::Summary;
    let should_schedule_key_destruction =
        memory_scope == MemoryScope::Ephemeral || memory_scope == MemoryScope::Summary;

    Ok((
        CloseResult {
            should_generate_summary,
            should_schedule_key_destruction,
        },
        closing_record,
    ))
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
/// Transitions `Closing -> Closed` and returns the `ContextClosed` record,
/// planned before the transition, for the caller to queue in the persist that
/// records it (spec 17 §17.3 "Event log write failures"). `log_entries` is the
/// context's log plus its queued records, which the caller reads before this
/// call. When they already hold a `ContextClosed` record (a prior finalize
/// queued or wrote it), this returns `None`: a duplicate terminal record
/// diverges the Merkle root across members (ADR-049 §9 amendment, finding
/// (d)).
///
/// The caller destroys the actor-owned keys after this returns `Ok`, then
/// issues the best-effort relay delete ([`delete_published_bounded`]).
///
/// # Errors
///
/// Returns [`ContextError::InvalidTransition`] if the context is not in
/// `Closing` state; nothing is planned or destroyed then.
pub fn finalize_close(
    handle: &ContextHandle,
    log_entries: &[scp_event_log::Event],
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
) -> Result<Option<LeafSpec>, ContextError> {
    let closed_record = (!log_entries
        .iter()
        .any(|e| e.event_type == scp_event_log::EventType::ContextClosed))
    .then(|| {
        LeafSpec::without_payload(
            scp_event_log::EventType::ContextClosed,
            scp_event_log::system_actors::SYSTEM_CLOSE_ACTOR.to_owned(),
            timestamp_secs,
        )
    });

    // Validate the transition BEFORE any key destruction (which the caller,
    // `ttl_close_helpers::finalize_close`, performs on the ACTOR-owned crypto
    // AFTER this returns Ok). Key destruction is irreversible — once destroyed
    // (sender keys, MLS signer, and MLS provider storage zeroized), encrypted
    // content becomes permanently unreadable. If the transition fails (e.g. the
    // context is not in Closing state), no keys must be destroyed.
    handle.transition_to(&ContextState::Closed)?;

    Ok(closed_record)
}

/// Best-effort relay ciphertext deletion (§5.11) for a terminal context whose
/// memory scope destroys its keys (Ephemeral or Summary). A Full-scope context
/// keeps its keys and content, so nothing is deleted.
///
/// The terminal paths call this after the terminal record is queued, and the
/// delete runs under its own budget (`RELAY_DELETE_BUDGET`, M2), so a hostile
/// or stalled relay cannot delay the record or hold the actor's turn open. A
/// refused or timed-out delete is logged and skipped: the keys are already
/// destroyed, so the retained ciphertext is unreadable.
pub(crate) async fn delete_published_bounded(
    handle: &ContextHandle,
    transport: &dyn ContextTransportProvider,
) {
    let memory_scope = handle.params().memory_scope;
    if memory_scope != MemoryScope::Ephemeral && memory_scope != MemoryScope::Summary {
        return;
    }
    let context_id = handle.context_id();
    let context_id_bytes = context_id_to_bytes(context_id);
    match tokio::time::timeout(
        RELAY_DELETE_BUDGET,
        transport.delete_published(&context_id_bytes),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(context_id = %context_id, error = %e,
                "best-effort relay deletion failed after the terminal transition");
        }
        Err(_elapsed) => {
            tracing::warn!(context_id = %context_id, budget = ?RELAY_DELETE_BUDGET,
                "best-effort relay deletion exceeded its budget after the terminal \
                 transition; skipping (keys already destroyed — ciphertext is unreadable)");
        }
    }
}

/// SYNC terminal phase of TTL expiry (SEC-1): FSM transition + key destruction.
///
/// Transitions `Active`/`Expired` → `Expired` and destroys keys
/// (Ephemeral/Summary scopes). No transport or event-log I/O: the caller queues
/// the `ContextExpired` record in its persist and issues the relay delete
/// ([`delete_published_bounded`]).
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
    // #2148 (ADR-049 birth-into-actor): key destruction runs on the ACTOR-owned
    // crypto (the provider holds none). `Some` for an Encrypted context, `None`
    // for a Broadcast context (which is always Full scope, so no destruction is
    // ever needed) or an already-disposed one.
    crypto_state: Option<&mut crate::context::actor::ContextCryptoState>,
    prior_completed: u8,
) -> TtlExpiryResult {
    let context_id = handle.context_id().to_owned();
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

    // 2. Key destruction (Ephemeral/Summary only). #2148 (ADR-049
    //    birth-into-actor): the MLS group + sender key are ACTOR-owned, so
    //    destruction runs `dispose_secrets` on the actor-owned
    //    `ContextCryptoState`. The load-bearing reason to call it here is that
    //    this is a LIVE-actor seam — the `PerContextState` is NOT dropped on an
    //    Ephemeral/Summary close, so the secrets must be released explicitly.
    //    `dispose_secrets` runs OpenMLS `destroy_group` (eagerly dropping the
    //    Ed25519 signer, whose private key zeroizes on drop because
    //    `SignatureKeyPair` holds it in `SecretVLBytes`, and zeroizing the group's
    //    in-memory provider storage) and zeroizes the sender key material. SYNC (no `.await`), so
    //    this whole phase runs outside any timeout.
    //
    //    #2199 / F-BH — COMPLETION vs PROVENANCE are SEPARATED here. The STEP
    //    bits serve exactly ONE master on this path: COMPLETION. They drive
    //    `is_complete()`, which the actor's despawn gate (`actor/mod.rs`) requires
    //    to be `true` before it stops re-arming the terminal-cleanup retry. So a
    //    bit MUST be set once the destruction STEP has EXECUTED — i.e. after
    //    `dispose_secrets` runs (which frees whatever was present and is a no-op
    //    for what was absent) — WHETHER material was present-and-destroyed OR
    //    trivially absent. Gating these bits on the OBSERVED destruction flags
    //    (as an earlier revision did) conflated completion with provenance: a
    //    terminal Ephemeral/Summary context reaching TTL with a partially-absent
    //    or already-disposed crypto sub-component would set only a SUBSET, so
    //    `is_complete()` never held and the actor re-armed a retry FOREVER (a
    //    resource-exhaustion liveness bug). The honest DESTRUCTION PROVENANCE is
    //    NOT lost: it lives in the observed `DisposalOutcome`, which the CLOSE
    //    finalize seam (`ttl_close_helpers::finalize_close`) consumes to build the
    //    truthful `KeyDestructionAttestation`. The TTL-expiry path builds NO
    //    success attestation; on FAILURE the per-step bits surface via
    //    `ExpiryFailed` as an honest "step executed" diagnostic (not an
    //    attestation). A destruction-required scope with `None` crypto is an
    //    anomaly (unreachable in practice — Ephemeral/Summary are ALWAYS Encrypted
    //    and `seed_encrypted_crypto_from_owned` installs `mls_group` + `sender_key`
    //    as `Some` together; Broadcast is always Full) that is warned but STILL
    //    completes the step (nothing to destroy ⇒ trivially done) so the actor
    //    despawns.
    if needs_key_destruction
        && result.completed_steps & (STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED)
            != (STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED)
    {
        match crypto_state {
            Some(crypto_state) => {
                // Execute the disposal (the real teardown). The observed
                // `DisposalOutcome` is the PROVENANCE signal — consumed ONLY by
                // the close-seam attestation, never on this expiry path — so it is
                // discarded here explicitly (`#[must_use]`).
                let _ = crypto_state.dispose_secrets();
            }
            None => {
                // No `ContextCryptoState` on a destruction-required scope: nothing
                // to destroy (the step is trivially complete), but the shape is an
                // anomaly — surface it loudly. The completion bits are still set
                // below so the actor despawns instead of spinning (#2199 F-BH).
                tracing::warn!(
                    context_id = %context_id,
                    ?memory_scope,
                    "TTL expiry: destruction-required scope has no crypto state to \
                     dispose — nothing to tear down; marking the destruction STEP \
                     complete (trivially done) so the terminal actor despawns \
                     (#2199 F-BH completion, not a destruction claim)"
                );
            }
        }
        // COMPLETION (not provenance): the destruction STEP has EXECUTED, so mark
        // it done UNCONDITIONALLY. This restores the spin-prevention `is_complete()`
        // needs to hold so the terminal actor despawns; it does NOT assert any
        // destruction fact (that lives in the observed `DisposalOutcome` / the
        // close-seam attestation).
        result.set_step(STEP_MLS_DESTROYED | STEP_SENDER_KEY_DESTROYED);
    }

    result
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
/// `ttl_close_helpers::start_ttl_timer`)
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
    /// `reset_ttl_timer`
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

    use crate::context::builder::ContextTransportProvider;

    // #2148 (ADR-049 birth-into-actor): `mk_crypto` was DELETED — the production
    // TTL/close paths no longer take a crypto provider (key destruction runs on
    // the actor-owned crypto), and these tests exercise the FSM + record/relay
    // behaviour with `None` crypto state (an unregistered context has nothing to
    // dispose).

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
        async fn send_message(
            &self,
            _cid: &[u8; 32],
            _payload: &[u8],
            _ttl: scp_protocol::envelope::outer::BlobTtl,
        ) -> Result<(), ContextError> {
            Ok(())
        }
    }

    /// M2 (a stalled relay must not hold the terminal path open, REGRESSION
    /// GATE): the best-effort relay delete runs under its own
    /// `RELAY_DELETE_BUDGET`, so a relay whose `delete_published` stalls past
    /// any budget still lets the call return well within `HANDLER_TIMEOUT`.
    #[tokio::test(start_paused = true)]
    async fn delete_published_bounded_does_not_wait_on_a_stalled_relay() {
        let transport = StallingTransport::default();
        // Ephemeral scope ⇒ the delete is issued (the op that stalls).
        let handle = active_handle("ctx-ttl-relay-stall", MemoryScope::Ephemeral);

        // Under `start_paused`, tokio auto-advances virtual time to the next
        // timer, so the bounded delete resolves at `RELAY_DELETE_BUDGET` (5 s)
        // rather than the relay's 3600 s stall.
        tokio::time::timeout(
            crate::context::actor::handlers::ttl_close::HANDLER_TIMEOUT,
            super::delete_published_bounded(&handle, &transport),
        )
        .await
        .expect(
            "the bounded relay delete returns within HANDLER_TIMEOUT despite the \
             relay stall (M2)",
        );
        assert!(
            transport
                .delete_entered
                .load(std::sync::atomic::Ordering::SeqCst),
            "the best-effort relay delete WAS attempted (and stalled)"
        );
    }

    /// A Full-scope context keeps its keys and content, so the terminal path
    /// issues no relay delete.
    #[tokio::test(start_paused = true)]
    async fn delete_published_bounded_keeps_full_scope_content() {
        let transport = StallingTransport::default();
        let handle = active_handle("ctx-ttl-full-keep", MemoryScope::Full);
        super::delete_published_bounded(&handle, &transport).await;
        assert!(
            !transport
                .delete_entered
                .load(std::sync::atomic::Ordering::SeqCst),
            "a Full-scope context issues no relay delete"
        );
    }

    /// A stored `ContextClosed` entry, for the finalize de-duplication tests.
    fn closed_entry() -> scp_event_log::Event {
        scp_event_log::Event {
            event_type: scp_event_log::EventType::ContextClosed,
            actor_did: scp_did::DID("system:close".to_owned()),
            timestamp: 1_699_999_000,
            sequence: 0,
            payload: scp_event_log::EventPayload { data: Vec::new() },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        }
    }

    /// §9.9.3 convergence: finalize plans the `ContextClosed` record with the
    /// descriptive sentinel `"system:close"` so it is byte-identical across all
    /// honest members, stamped with the caller's instant, and transitions the
    /// context to `Closed`.
    #[test]
    fn finalize_close_plans_a_system_close_record() {
        let handle = active_handle("ctx-close-actor", MemoryScope::Full);
        handle.transition_to(&ContextState::Closing).unwrap();

        let record = finalize_close(&handle, &[], 1_700_000_000)
            .unwrap()
            .expect("a log without ContextClosed gets one planned");

        assert_eq!(record.event_type(), scp_event_log::EventType::ContextClosed);
        assert_eq!(
            record.actor_did(),
            "system:close",
            "the ContextClosed record MUST stamp \"system:close\" (§9.9.3 convergence)"
        );
        assert_eq!(record.timestamp_secs(), 1_700_000_000);
        assert_eq!(handle.state(), ContextState::Closed);
    }

    /// (d) idempotent terminal record (ADR-049 §9 amendment): when the log or
    /// the queue already holds a `ContextClosed` record, finalize plans none, so
    /// no member writes a duplicate that diverges the Merkle root.
    #[test]
    fn finalize_close_plans_no_second_closed_record() {
        let handle = active_handle("ctx-close-idem", MemoryScope::Full);
        handle.transition_to(&ContextState::Closing).unwrap();

        let record = finalize_close(&handle, &[closed_entry()], 1_700_000_000).unwrap();

        assert!(
            record.is_none(),
            "an existing ContextClosed record gets no duplicate: {record:?}"
        );
        assert_eq!(handle.state(), ContextState::Closed);
    }

    /// Finalize refuses a context that is not `Closing` and leaves its state
    /// unchanged.
    #[test]
    fn finalize_close_refuses_a_context_not_closing() {
        let handle = active_handle("ctx-close-active", MemoryScope::Ephemeral);

        let res = finalize_close(&handle, &[], 1_700_000_000);

        assert!(
            matches!(res, Err(ContextError::InvalidTransition { .. })),
            "an Active context cannot be finalized: {res:?}"
        );
        assert_eq!(handle.state(), ContextState::Active);
    }

    /// A role state whose creator is `did:example:roles-creator` and in which
    /// no one else holds a capability.
    fn creator_only_roles() -> ContextRoleState {
        ContextRoleState::new(
            "ctx-close-roles",
            "did:example:roles-creator",
            CapabilityCeiling::new([Capability::ContextClose]),
            Vec::new(),
            &TestClock::new(1_700_000_000),
        )
        .unwrap()
    }

    /// A role state in which `did` holds `ContextClose`.
    fn closer_roles(did: &DID) -> ContextRoleState {
        let mut role_state = creator_only_roles();
        role_state.members.insert(did.as_ref().to_owned());
        role_state.member_capabilities.insert(
            did.as_ref().to_owned(),
            std::iter::once(Capability::ContextClose).collect(),
        );
        role_state
    }

    /// Close plans the `ContextClosing` record for the initiator at the
    /// caller's convergent instant and transitions `Active -> Closing`.
    #[test]
    fn close_context_plans_the_closing_record_for_the_initiator() {
        let initiator = DID("did:example:closer".to_owned());
        let handle = active_handle("ctx-close-plan", MemoryScope::Summary);

        let (result, record) = close_context(
            &handle,
            &initiator,
            &closer_roles(&initiator),
            1_700_000_123,
        )
        .unwrap();

        assert_eq!(
            record.event_type(),
            scp_event_log::EventType::ContextClosing
        );
        assert_eq!(record.actor_did(), initiator.as_ref());
        assert_eq!(record.timestamp_secs(), 1_700_000_123);
        assert_eq!(handle.state(), ContextState::Closing);
        assert!(result.should_generate_summary && result.should_schedule_key_destruction);
    }

    /// Close refuses an initiator without `ContextClose`, plans nothing, and
    /// leaves the context `Active`.
    #[test]
    fn close_context_refuses_an_initiator_without_close_capability() {
        let initiator = DID("did:example:not-a-closer".to_owned());
        let handle = active_handle("ctx-close-denied", MemoryScope::Full);

        let res = close_context(&handle, &initiator, &creator_only_roles(), 1_700_000_000);

        assert!(
            matches!(res, Err(ContextError::PermissionDenied(_))),
            "close without ContextClose is refused: {res:?}"
        );
        assert_eq!(handle.state(), ContextState::Active);
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

    // #2148 (ADR-049 birth-into-actor): the ADR-056 TTL-expiry chokepoint
    // regression test was DELETED — the terminal transition disposes the
    // actor-owned crypto passed to it directly and no longer resolves a
    // context-id string to provider-map bytes, so there is no id-resolution to
    // guard here. The decode-not-rehash keying invariant is proved at the birth
    // seam / actor level (see `builder::create_context` tests).

    /// The terminal transition moves `Active -> Expired`. The `ContextExpired`
    /// record step is the caller's (it rides the caller's persist), so it stays
    /// undone here.
    #[test]
    fn ttl_expiry_transitions_active_to_expired() {
        let handle = active_handle("ctx-ttl", MemoryScope::Full);
        let res = super::apply_ttl_terminal_transition(&handle, None, 0);
        assert!(res.state_transitioned(), "Active ⇒ Expired: {res}");
        assert!(
            !res.event_logged(),
            "the record step is the caller's: {res}"
        );
        assert_eq!(handle.state(), ContextState::Expired);
    }

    #[test]
    fn ttl_expiry_rejects_non_active_contexts() {
        let handle = ContextHandle::new("ctx-new".to_owned(), ContextParams::default());
        // Handle is in Creating state — not Active / Expired, so the terminal
        // transition is refused: the result reports failure and no transition.
        let res = super::apply_ttl_terminal_transition(&handle, None, 0);
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

    /// #2199 F-BH — COMPLETION semantics on the TTL path. The STEP destroyed bits
    /// track COMPLETION (the teardown step EXECUTED), not destruction provenance:
    /// even a PARTIAL-ABSENT crypto (a present sender key, NO MLS group) sets BOTH
    /// bits once `dispose_secrets` runs, so `is_complete()` can hold and the actor
    /// despawns. The honest destruction PROVENANCE (that this disposal observed
    /// {mls: false, sender: true}) lives in the observed `DisposalOutcome` — tested
    /// at the `dispose_secrets` level (`state.rs`) and surfaced only by the CLOSE
    /// finalize attestation, never on this expiry path.
    #[test]
    fn apply_ttl_terminal_transition_partial_absent_completes_both_steps() {
        use crate::context::actor::ContextCryptoState;
        use scp_protocol::crypto::sender_keys::generate_sender_key;

        let handle = active_handle("ctx-2199-observed", MemoryScope::Ephemeral);
        // Present sender key, absent MLS group (partial-absent).
        let mut crypto = ContextCryptoState {
            sender_key: Some(generate_sender_key()),
            ..Default::default()
        };

        let result = super::apply_ttl_terminal_transition(&handle, Some(&mut crypto), 0);

        assert!(result.state_transitioned(), "Active ⇒ Expired");
        assert!(
            result.mls_destroyed() && result.sender_key_destroyed(),
            "the destruction step EXECUTED ⇒ BOTH completion bits set even for a \
             partial-absent crypto (completion, not a destruction claim): {result}"
        );
    }

    /// #2199 F-BH — LIVENESS regression guard. A `None`-crypto (or partial-absent)
    /// Ephemeral/Summary context reaching TTL MUST still reach `is_complete()` so
    /// the terminal actor DESPAWNS (`actor/mod.rs` despawn gate) instead of
    /// re-arming a retry FOREVER. An earlier revision gated the destroyed bits on
    /// the observed flags, so a `None`-crypto context set only a SUBSET, never
    /// completed, and the actor spun forever (resource exhaustion). Here the
    /// destruction step is trivially complete (nothing to destroy), both bits set;
    /// combined
    /// with the FSM transition + the leaf append the whole result is complete.
    #[test]
    fn apply_ttl_terminal_transition_none_crypto_ephemeral_completes_for_despawn() {
        let handle = active_handle("ctx-2199-absent", MemoryScope::Ephemeral);

        let mut result = super::apply_ttl_terminal_transition(&handle, None, 0);

        assert!(
            result.state_transitioned(),
            "the FSM still transitions to Expired"
        );
        assert!(
            result.mls_destroyed() && result.sender_key_destroyed(),
            "None crypto ⇒ nothing to destroy ⇒ destruction step trivially complete: \
             BOTH completion bits set so the actor can despawn (not spin): {result}"
        );
        // The record step is the only remaining one; once the caller queues the
        // record in its persist the result is fully complete and the despawn gate
        // (`is_complete()`) is met. Simulate it here to prove the terminal cleanup
        // CONVERGES (does NOT loop).
        result.mark_event_logged();
        assert!(
            result.is_complete(),
            "with the record queued the None-crypto expiry is COMPLETE ⇒ the actor \
             despawns rather than re-arming a retry forever (F-BH): {result}"
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
}
