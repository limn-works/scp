//! Compromise recovery orchestrator for SCP identity keys.
//!
//! Implements the 6-step ordered recovery protocol from spec §9.12. When a key
//! is known or suspected to be compromised, the orchestrator coordinates:
//!
//! 1. **Key rotation** on a trusted device (3 tiers: agent, active, identity).
//! 2. **MLS `Update`** in all active contexts (per-context, failure-isolated).
//! 3. **UCAN revocation** of all tokens issued by the compromised key.
//!    ([`ProductionRecoveryBackend`] fails this step closed — see #2069.)
//! 4. **`KeyPackage` rotation** — delete old, publish new.
//!    ([`ProductionRecoveryBackend`] fails this step closed — see #2240 Part B
//!    item 2 / #1083 finding 6.)
//! 5. **Contact notification** — key-change alerts to all known contacts.
//! 6. **Identity private state re-encryption** — PSK rotation, device removal.
//!    ([`ProductionRecoveryBackend`] fails this step closed — see #2240 Part
//!    B.)
//!
//! Step ordering is enforced by dependency: 1→2→3→4→(5,6 unordered).
//!
//! Steps 2 and 3 are **per-context**: a failure in one context does not block
//! recovery in others, and each retries independently. Steps 4, 5 and 6 are
//! **identity-scoped** — each runs exactly once per recovery, never once per
//! context, and runs regardless of how the per-context steps fared. Step 4
//! additionally *gates completion for every context*, so its failure is a
//! whole-recovery failure ([`RecoveryError::KeyPackageRotationFailed`]) rather
//! than a per-context one. See spec §9.12 "Step scope — per-context vs
//! identity-scoped".
//!
//! Three compromise tiers:
//! - **Agent key** (cheapest): DID doc update → scoped UCAN revocation → MLS
//!   `Update` → new `KeyPackages`. No identity migration.
//! - **Active signing key**: Includes PSK re-encryption.
//! - **Identity key** (most severe): Pre-rotation, new DID, forwarding record.
//!
//! See spec §9.12 and ADR-003 §4a/§4b.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use scp_did::DID;

// ContextManager type deleted in ADR-049 §15; recovery binds to
// the supervisor directly.
use scp_clock::Clock;

// ---------------------------------------------------------------------------
// CompromiseTier — which key was compromised
// ---------------------------------------------------------------------------

/// The tier of key compromise, determining the scope of recovery actions.
///
/// Ordered by severity: `Agent` (cheapest recovery) < `ActiveSigning`
/// < `IdentityKey` (most severe, requires identity migration).
///
/// See spec §9.12 steps 1a–1c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompromiseTier {
    /// Agent Signing Key (`#agent`) compromise — most common case.
    ///
    /// The agent runtime is typically less secure than device HSM. Recovery:
    /// publish new DID document removing/replacing `#agent` VM, revoke only
    /// agent-scoped UCANs, MLS `Update`, new `KeyPackages`. No identity
    /// migration.
    Agent,

    /// Active Signing Key (`#active`) compromise.
    ///
    /// Calls `rotate_active_key` (ADR-003 §4a). DID string unchanged. Includes
    /// PSK re-encryption (step 6).
    ActiveSigning,

    /// Identity Key (`#0`) compromise — rare, most severe.
    ///
    /// Calls `migrate_identity` (ADR-003 §4b) using pre-rotation key. Creates
    /// new DID with forwarding record. All contexts receive `DidRotationEvent`.
    IdentityKey,
}

// ---------------------------------------------------------------------------
// RecoveryStepError — per-step error type
// ---------------------------------------------------------------------------

/// Machine-readable classification of a [`RecoveryStepError`].
///
/// Callers, the orchestrator and tests branch on this — never on
/// [`RecoveryStepError::description`], which is prose for humans and free to be
/// reworded. Two concrete reasons this exists rather than substring matching:
///
/// * the orchestrator must recognise the ADR-029 Tier-3 rejoin signal to route
///   a context to `pending_rejoin` instead of `failed_contexts`; and
/// * regression tests that pin "this capability is still unwired" must survive
///   a correction to the explanatory prose. Prose-pinning tests block the very
///   corrections they should be permitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStepErrorCode {
    /// Step 2: the member has been offline too long and requires an ADR-029
    /// Tier-3 re-join (remove + re-add by an admin). Not a hard failure — the
    /// orchestrator continues into step 3 and flags the context.
    RequiresRejoin,

    /// Step 3: recovery has no wired path to revoke the compromised key's
    /// outstanding UCANs. See [`ProductionRecoveryBackend::revoke_ucans`] and
    /// #2069.
    UcanRevocationUnwired,

    /// Step 4: the `KeyPackage` attestation lifecycle is unwired, so there is
    /// nothing to rotate and no way to retract. See
    /// [`ProductionRecoveryBackend::rotate_key_packages`], #2240 Part B item 2
    /// and #1083 finding 6.
    KeyPackageRotationUnwired,

    /// Step 6: nothing installs a rotated PSK, so there is no way to re-encrypt
    /// identity private state under a new one. See
    /// [`ProductionRecoveryBackend::rotate_psk`] and #2240 Part B.
    ///
    /// **Permanent, like the two codes above** — a retry re-runs the whole
    /// non-idempotent sequence (see
    /// [`CompromiseRecoveryOrchestrator::execute_recovery`]) and reaches the
    /// same absent installer. This is why it is not
    /// [`Self::DispatchFailed`]: that code is documented as transient, and
    /// stamping a permanent structural gap with it steers automation into an
    /// unbounded loop of irreversible side effects.
    PskDistributionUnwired,

    /// The backend could not reach the runtime (mailbox, actor or transport
    /// failure). Transient — retrying the affected context may succeed.
    ///
    /// Reserved for genuine mailbox / actor / transport faults. A step that is
    /// structurally unable to do its work carries one of the `*Unwired` codes
    /// above instead — a permanent condition reported as transient invites the
    /// retry loop described on
    /// [`CompromiseRecoveryOrchestrator::execute_recovery`].
    DispatchFailed,

    /// A backend-specific failure with no dedicated code.
    Unspecified,
}

/// Error from a single recovery step.
///
/// Steps 2 and 3 are per-context and may fail independently; the orchestrator
/// collects those errors without blocking recovery in other contexts. Steps 4,
/// 5 and 6 are identity-scoped and produce at most one of these each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStepError {
    /// The step number (1–6) where the failure occurred.
    pub step: u8,

    /// Machine-readable classification. **Branch on this**, never on
    /// [`Self::description`].
    pub code: RecoveryStepErrorCode,

    /// Human-readable description of the failure. Prose for operators — its
    /// wording is not a stable contract and MUST NOT be matched against.
    ///
    /// **Keep it to what an operator must act on**: what did not happen, what
    /// is consequently still exposed, and the tracking issue. This is a `pub`
    /// API value that travels to logs, error surfaces and support channels —
    /// the traced call graph of an unwired capability (which symbols have zero
    /// production callers, which enforcement sets have no write path, which
    /// artifact cannot be retracted) belongs in the rustdoc of the method that
    /// raises it, where it is already recorded, not in a shipped string that
    /// reads as an exploitation map.
    pub description: String,
}

impl std::fmt::Display for RecoveryStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step {}: {}", self.step, self.description)
    }
}

// ---------------------------------------------------------------------------
// RecoveryResult — outcome of the full recovery sequence
// ---------------------------------------------------------------------------

/// Outcome of executing the compromise recovery protocol.
///
/// Contains per-context results with failure isolation: a partial failure does
/// not roll back completed contexts. Contexts requiring Tier 3 re-join (MLS
/// `Update` cannot succeed, e.g. member offline too long per ADR-029) are
/// flagged separately from outright failures.
///
/// There is deliberately **no `key_packages_rotated` field**. Step 4 is
/// identity-scoped and gates completion for every context (§9.12 "Step scope"),
/// so a step-4 failure returns
/// [`RecoveryError::KeyPackageRotationFailed`] instead of this struct —
/// receiving a `RecoveryResult` at all implies step 4 succeeded. A field that is
/// structurally always `true` would carry no information.
///
/// See spec §9.12 "Step ordering and failure isolation" and "Step scope".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    /// The compromise tier that was addressed.
    pub tier: CompromiseTier,

    /// The DID that initiated recovery.
    pub did: DID,

    /// Whether the DID changed (only for `IdentityKey` tier with migration).
    pub new_did: Option<DID>,

    /// Contexts where ALL recovery steps completed successfully.
    ///
    /// Disjoint from both [`Self::failed_contexts`] and
    /// [`Self::pending_rejoin`]. A context that requires an ADR-029 Tier-3
    /// re-join is NOT listed here even when steps 3–4 succeeded for it: its MLS
    /// `Update` did not complete, so it still needs an admin remove + re-add.
    pub completed_contexts: Vec<String>,

    /// Contexts where one or more steps failed.
    pub failed_contexts: Vec<(String, RecoveryStepError)>,

    /// Contexts flagged for manual re-join (Tier 3 per ADR-029).
    ///
    /// These contexts could not complete MLS `Update` because the member has
    /// been offline too long. Recovery is NOT blocked by these — they require
    /// separate action (remove + re-add by an admin).
    pub pending_rejoin: Vec<String>,

    /// Whether step 1 (key rotation on trusted device) succeeded.
    pub key_rotation_completed: bool,

    /// Outcome of step 5 (contact notification), naming which contacts were
    /// reached and which were not.
    ///
    /// [`ContactNotificationOutcome::Delivered`] means at least one contact was
    /// reached — the §9.12 best-effort bar — and carries the ones that were
    /// not, each of which still holds a §9.11 KCV binding to the compromised
    /// key. Use [`ContactNotificationOutcome::fully_delivered`], not
    /// "did not fail", to decide whether that window is closed.
    pub contact_notification: ContactNotificationOutcome,

    /// Outcome of step 6 (identity private-state re-encryption).
    ///
    /// Tri-state rather than `bool`: the `Agent` tier reports
    /// [`StepOutcome::NotApplicable`] because an agent-key compromise does not
    /// affect the PSK — the step genuinely does not run, which the old
    /// hardcoded `true` misreported as success.
    pub private_state_reencryption: StepOutcome,

    /// Unix timestamp (milliseconds) when recovery was initiated.
    pub initiated_at: u64,

    /// Unix timestamp (milliseconds) when recovery completed.
    pub completed_at: u64,
}

impl RecoveryResult {
    /// Returns `true` only when every §9.12 step that applied to this recovery
    /// actually completed.
    ///
    /// **`is_ok()` is not completion.** `Ok(RecoveryResult)` means only that no
    /// *fatal* condition fired: step 1 ran, step 4 succeeded, and at least one
    /// context made progress. A populated [`Self::failed_contexts`], a context
    /// awaiting an ADR-029 rejoin, a failed step 6, or a contact that was never
    /// told to re-run §9.11 KCV all ride along on the `Ok` path — by design,
    /// since §9.12 makes steps 5 and 6 non-fatal and per-context failures
    /// isolated. That is exactly the success-shape-for-work-that-did-not-happen
    /// this type otherwise exists to eliminate, one level up, so the predicate
    /// is provided rather than left for each caller to re-derive (and get
    /// wrong).
    ///
    /// Requires:
    ///
    /// * step 1 rotated the key ([`Self::key_rotation_completed`]);
    /// * no context failed a per-context step, and none is pending an ADR-029
    ///   Tier-3 rejoin (together these imply every context completed);
    /// * step 5 did not fail **and left no unreachable contact** — a contact
    ///   that was not reached still trusts the compromised key
    ///   ([`ContactNotificationOutcome::fully_delivered`], or
    ///   `NotApplicable` when the identity has no contacts); and
    /// * step 6 did not fail (`NotApplicable` counts — the `Agent` tier
    ///   genuinely does not touch the PSK).
    ///
    /// Step 4 is not tested: it gates the whole recovery, so holding a
    /// `RecoveryResult` at all implies it succeeded (§9.12 "Step scope").
    ///
    /// "Did not fail" rather than "succeeded" is deliberate for steps 5 and 6:
    /// a [`StepOutcome::NotApplicable`] step had no work to do, which does not
    /// make the recovery incomplete.
    #[must_use]
    pub fn fully_recovered(&self) -> bool {
        self.key_rotation_completed
            && self.failed_contexts.is_empty()
            && self.pending_rejoin.is_empty()
            && !self.contact_notification.failed()
            && self.contact_notification.unreachable().is_empty()
            && !self.private_state_reencryption.failed()
    }
}

// ---------------------------------------------------------------------------
// RecoveryError — orchestrator-level error
// ---------------------------------------------------------------------------

/// Errors produced by the compromise recovery orchestrator.
///
/// Step 1 (key rotation) failure is fatal — the orchestrator cannot proceed
/// without new key material. Steps 2–3 failures are per-context and recorded in
/// `RecoveryResult::failed_contexts`; but a *total* failure (every context
/// failed) fails the whole call closed via
/// [`RecoveryError::AllContextsFailed`] rather than returning an all-failed
/// `RecoveryResult` that could masquerade as success. Step 4 is
/// identity-scoped and gates completion for every context, so its failure is
/// always fatal — [`RecoveryError::KeyPackageRotationFailed`], never a
/// `failed_contexts` entry (§9.12 "Step scope"). Steps 5–6 failures are
/// non-fatal cleanup errors.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// Step 1 failed: key rotation on trusted device did not occur.
    ///
    /// This is fatal — the orchestrator cannot proceed without new key
    /// material. Also returned when the caller passes `key_rotation: None` to
    /// [`CompromiseRecoveryOrchestrator::execute_recovery`] (step 1 did not
    /// occur): the per-context steps rotate/replace material that only exists
    /// once step 1 has actually run, so recovery fails closed instead of
    /// fabricating a `RecoveryResult` that would imply a completed rotation.
    #[error("key rotation failed (step 1): {0}")]
    KeyRotationFailed(String),

    /// Step 4 (`KeyPackage` rotation) failed.
    ///
    /// Step 4 is **identity-scoped** and **gates completion for every
    /// context** (§9.12 "Step scope"): a surviving `KeyPackage` carrying an
    /// attestation signed by the retired key can be used to add the
    /// compromised member to a *new* group, so no context may be reported as
    /// recovered while step 4 has not succeeded.
    ///
    /// It is therefore a whole-recovery failure, **independent of context
    /// count** — including the zero-context case, where the per-context loop
    /// never runs. Without this variant a zero-context recovery returned
    /// `Ok(RecoveryResult { key_packages_rotated: false, .. })`, so a caller
    /// using `?` or `is_ok()` reported success while §9.12 step 4 had not
    /// happened and the compromised identity's `KeyPackages` stayed fetchable:
    /// the same "total failure observed as success" shape
    /// [`Self::AllContextsFailed`] exists to stop, surviving where the loop
    /// never ran.
    ///
    /// It is a dedicated variant rather than a per-context error so that an
    /// identity-scoped failure is never laundered through a per-context
    /// channel — a caller iterating `failed_contexts` and retrying per context
    /// could never make progress against it (§9.12: per-context retry does not
    /// apply to step 4).
    #[error(
        "step 4 (KeyPackage rotation) failed — identity-scoped, so no context can be \
             reported as recovered: {step_error}; {progress}"
    )]
    KeyPackageRotationFailed {
        /// The step-4 error from the backend.
        step_error: RecoveryStepError,

        /// How far the rest of recovery got. Steps 2–3 outcomes are preserved
        /// verbatim (not overwritten by this failure), and steps 5–6 still ran.
        progress: RecoveryProgress,
    },

    /// Total failure: there were contexts to recover but not one made real
    /// progress — every context ended with a step error, none completed and
    /// none is pending an ADR-029 rejoin.
    ///
    /// Returned instead of an all-failed `RecoveryResult` so a total failure —
    /// e.g. a no-op / unconfigured backend that rejects every context — cannot
    /// be observed as a success (fail-closed, #2240). A recovery for an
    /// identity in *zero* contexts is NOT a total *per-context* failure (there
    /// is simply no per-context work); the identity-scoped steps still gate it,
    /// via [`Self::KeyPackageRotationFailed`].
    ///
    /// The variant carries the per-context step errors *and* the outcomes of
    /// the identity-scoped steps (4, 5, 6), which run regardless of
    /// per-context failure. Dropping either would make the fail-closed path
    /// less informative than the success path: an operator could not tell an
    /// unwired capability ("UCAN revocation is not wired … #2069") from a
    /// transport outage, nor learn whether the PSK was rotated.
    #[error("recovery failed for all {attempted} context(s): zero contexts recovered; {progress}")]
    AllContextsFailed {
        /// Number of contexts attempted, all of which failed.
        attempted: usize,

        /// How far recovery got, including the per-context step errors.
        progress: RecoveryProgress,
    },

    /// The compromise tier requires an agent key but none exists.
    #[error("agent key not found in identity")]
    AgentKeyNotFound,

    /// The compromise tier requires a pre-rotation key but none is available.
    #[error("pre-rotation key not available for identity migration")]
    PreRotationKeyNotAvailable,

    /// The DID method implementation returned an error.
    #[error("DID method error: {0}")]
    DidMethodError(String),

    /// A platform custody error occurred during key operations.
    #[error("custody error: {0}")]
    CustodyError(String),
}

// ---------------------------------------------------------------------------
// StepOutcome — tri-state result of an identity-scoped cleanup step (6)
// ---------------------------------------------------------------------------

/// Outcome of an identity-scoped cleanup step.
///
/// Used for step 6. Step 5 has its own richer
/// [`ContactNotificationOutcome`], because "the step succeeded" is not an
/// adequate report when only some contacts were reached.
///
/// Replaces the `bool` these steps used to report, which could not distinguish
/// "succeeded" from "there was nothing to do" from "did not apply to this
/// tier". That conflation was actively misleading once outcomes were rendered
/// into the operator-facing error: an `Agent`-tier recovery with no known
/// contacts reported `contacts_notified=true, private_state_reencrypted=true`
/// when **neither step ran at all** — step 5 short-circuits on an empty contact
/// set and step 6 does not apply to the `Agent` tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// The step ran and succeeded.
    Succeeded,

    /// The step did not run because it does not apply to this recovery. The
    /// string states why (e.g. "no known contacts", "PSK unaffected by an
    /// agent-key compromise"). This is NOT success.
    NotApplicable(String),

    /// The step ran and failed. Non-fatal: steps 5 and 6 are cleanup, so a
    /// failure is reported rather than aborting recovery.
    Failed(RecoveryStepError),
}

impl StepOutcome {
    /// Returns `true` only when the step actually ran and succeeded.
    ///
    /// Deliberately distinct from "did not fail": a
    /// [`NotApplicable`](Self::NotApplicable) step did no work, so callers
    /// asserting that security cleanup *happened* must use this.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    /// Returns `true` when the step ran and failed.
    ///
    /// The complement of neither [`Self::succeeded`] nor "did nothing":
    /// `!succeeded()` is true for [`NotApplicable`](Self::NotApplicable) too.
    /// [`RecoveryResult::fully_recovered`] needs "nothing went wrong", which is
    /// `!failed()`, not `succeeded()`.
    #[must_use]
    pub const fn failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

// ---------------------------------------------------------------------------
// ContactNotificationOutcome — step 5's per-contact outcome
// ---------------------------------------------------------------------------

/// Outcome of §9.12 step 5 (contact notification), naming **which** contacts
/// were reached and which were not.
///
/// A plain "succeeded" is not an adequate report for this step. Step 5 is
/// best-effort — §9.12 requires no delivery confirmation — so reaching one of
/// 50 contacts is `Ok` and does not block recovery. But the 49 that were not
/// reached still hold a §9.11 Key Continuity Verification binding to the
/// compromised key and have not been told to re-verify: that is precisely the
/// impersonation window recovery exists to close, and an operator who sees only
/// "step 5 succeeded" never learns to chase them. §9.12's best-effort rule
/// governs whether recovery *blocks*, not whether the caller is *told*.
///
/// The unreachable set is **derived by the orchestrator**, as
/// `contacts - reached`, rather than reported by the backend. A backend that
/// under-reports what it reached therefore over-reports what is unreachable —
/// fail-safe — instead of silently shrinking the set an operator must chase.
/// Both lists are sorted so the report is stable across runs (the contact set
/// is a `HashSet`, whose iteration order is not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactNotificationOutcome {
    /// The step did not run: the identity has no known contacts. This is NOT
    /// success. The string states why.
    NotApplicable(String),

    /// The step ran and reached at least one contact.
    ///
    /// `unreachable` may still be non-empty — see the type-level note. It is
    /// disjoint from `reached` by construction.
    Delivered {
        /// Contacts the key-change notification reached, sorted.
        reached: Vec<DID>,
        /// Contacts it did not reach, sorted. Each still holds a §9.11 KCV
        /// binding to the compromised key.
        unreachable: Vec<DID>,
    },

    /// The step ran and reached nobody.
    ///
    /// Non-fatal (step 5 is cleanup), but every contact is unreachable.
    Failed {
        /// The step-5 error from the backend.
        error: RecoveryStepError,
        /// Every contact, sorted — none was reached.
        unreachable: Vec<DID>,
    },
}

impl ContactNotificationOutcome {
    /// Returns `true` only when the step ran and reached **every** contact.
    ///
    /// This — not [`Self::reached_any`] — is the predicate for "no contact is
    /// still trusting the compromised key".
    #[must_use]
    pub const fn fully_delivered(&self) -> bool {
        matches!(self, Self::Delivered { unreachable, .. } if unreachable.is_empty())
    }

    /// Returns `true` when the step ran and reached at least one contact.
    ///
    /// This is the §9.12 best-effort success bar — it does NOT mean every
    /// contact was told. Use [`Self::fully_delivered`] for that.
    #[must_use]
    pub const fn reached_any(&self) -> bool {
        matches!(self, Self::Delivered { .. })
    }

    /// Returns `true` when the step ran and reached nobody.
    #[must_use]
    pub const fn failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// The contacts that were NOT told to re-run §9.11 key-continuity
    /// verification. Empty for [`Self::NotApplicable`] (there were none).
    #[must_use]
    pub fn unreachable(&self) -> &[DID] {
        match self {
            Self::NotApplicable(_) => &[],
            Self::Delivered { unreachable, .. } | Self::Failed { unreachable, .. } => unreachable,
        }
    }

    /// The contacts that were reached. Empty unless [`Self::Delivered`].
    #[must_use]
    pub fn reached(&self) -> &[DID] {
        match self {
            Self::NotApplicable(_) | Self::Failed { .. } => &[],
            Self::Delivered { reached, .. } => reached,
        }
    }
}

impl std::fmt::Display for ContactNotificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplicable(why) => write!(f, "did not run ({why})"),
            Self::Delivered {
                reached,
                unreachable,
            } if unreachable.is_empty() => {
                write!(f, "ran, reached all {} contact(s)", reached.len())
            }
            Self::Delivered {
                reached,
                unreachable,
            } => write!(
                f,
                "ran, reached {} contact(s) but {} were NOT told to re-run §9.11 KCV (e.g. `{}`)",
                reached.len(),
                unreachable.len(),
                // Bounded output: one representative rather than the full list,
                // which grows with the contact set. The complete list stays on
                // the value.
                unreachable
                    .first()
                    .map_or("<none>", |contact| contact.as_ref()),
            ),
            Self::Failed { error, unreachable } => write!(
                f,
                "ran, FAILED: {error}; none of {} contact(s) was told to re-run §9.11 KCV",
                unreachable.len()
            ),
        }
    }
}

impl std::fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Succeeded => write!(f, "ran, succeeded"),
            Self::NotApplicable(why) => write!(f, "did not run ({why})"),
            Self::Failed(e) => write!(f, "ran, FAILED: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryProgress — how far recovery got before failing closed
// ---------------------------------------------------------------------------

/// How far a compromise recovery got before it failed closed.
///
/// Carried by every fatal [`RecoveryError`] raised after the steps began, so
/// the fail-closed path is never *less* informative than the `Ok` path. Two
/// things depend on that:
///
/// * an operator must be able to tell an unwired capability from a transport
///   outage; and
/// * an operator re-running recovery must be able to see which contexts already
///   advanced their MLS epoch and which are pending an ADR-029 rejoin, rather
///   than repeating completed work blind.
///
/// Per-context outcomes are preserved verbatim: an identity-scoped step-4
/// failure does NOT overwrite them — it has its own
/// [`RecoveryError::KeyPackageRotationFailed`] variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProgress {
    /// Contexts whose per-context steps (2 and 3) both succeeded, in
    /// orchestrator order. These already advanced their MLS epoch.
    pub contexts_through_per_context_steps: Vec<String>,

    /// The step error for every context that failed step 2 or 3, in
    /// orchestrator order. Surfaced (grouped by step) in the `Display`.
    pub failed_contexts: Vec<(String, RecoveryStepError)>,

    /// Contexts flagged for manual ADR-029 Tier-3 re-join whose remaining
    /// per-context steps were error-free. Disjoint from `failed_contexts`.
    pub pending_rejoin: Vec<String>,

    /// Outcome of the identity-scoped step 4 (`KeyPackage` rotation).
    pub key_package_rotation: StepOutcome,

    /// Outcome of step 5 (contact notification), including the contacts that
    /// were NOT reached.
    pub contact_notification: ContactNotificationOutcome,

    /// Outcome of step 6 (identity private-state re-encryption).
    pub private_state_reencryption: StepOutcome,
}

impl std::fmt::Display for RecoveryProgress {
    /// Renders per-context failures **grouped by step number** — one entry per
    /// distinct step, with the count of contexts that hit it, a representative
    /// context id, and that context's full description.
    ///
    /// Grouping by step (rather than by exact description) is what bounds the
    /// message: an unwired step produces a near-identical paragraph for every
    /// context, differing only in the embedded context id, so per-description
    /// deduplication would not collapse them and the output would grow linearly
    /// in the number of contexts. Step numbers are 1–6, so this is bounded by
    /// construction. The full, ungrouped list stays on `failed_contexts`.
    ///
    /// Identity-scoped steps render their tri-state
    /// [`StepOutcome`] verbatim, so a step that did not run never reads as
    /// having succeeded.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.failed_contexts.is_empty() {
            write!(f, "no per-context step errors")?;
        } else {
            // Preserve first-seen (orchestrator) order rather than sorting, so
            // the earliest-failing step leads.
            let mut by_step: Vec<(&str, &RecoveryStepError, usize)> = Vec::new();
            for (context_id, err) in &self.failed_contexts {
                if let Some(entry) = by_step
                    .iter_mut()
                    .find(|(_, seen, _)| seen.step == err.step)
                {
                    entry.2 += 1;
                } else {
                    by_step.push((context_id.as_str(), err, 1));
                }
            }
            let rendered = by_step
                .iter()
                .map(|(context_id, err, count)| {
                    format!(
                        "step {step}: {count} context(s), e.g. `{context_id}`: {description}",
                        step = err.step,
                        description = err.description,
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            write!(f, "[{rendered}]")?;
        }

        write!(
            f,
            " (contexts through steps 2-3: {through}, pending ADR-029 rejoin: {rejoin}; \
             step 4 KeyPackage rotation: {kp}; step 5 contact notification: {cn}; \
             step 6 private-state re-encryption: {psr})",
            through = self.contexts_through_per_context_steps.len(),
            rejoin = self.pending_rejoin.len(),
            kp = self.key_package_rotation,
            cn = self.contact_notification,
            psr = self.private_state_reencryption,
        )
    }
}

// ---------------------------------------------------------------------------
// ContextRecoveryState — per-context step tracking
// ---------------------------------------------------------------------------

/// Tracks which recovery steps have been completed for a single context.
///
/// Used internally by the orchestrator to resume after partial failures.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRecoveryState {
    /// The context ID.
    pub context_id: String,

    /// Whether step 2 (MLS `Update`) completed.
    pub mls_updated: bool,

    /// Whether step 3 (UCAN revocation) completed.
    pub ucan_revoked: bool,

    /// Whether step 4 (`KeyPackage` rotation) completed.
    pub key_packages_rotated: bool,

    /// Whether this context requires Tier 3 re-join.
    pub requires_rejoin: bool,

    /// Error encountered, if any.
    pub error: Option<RecoveryStepError>,
}

impl ContextRecoveryState {
    /// Creates a new context recovery state with no steps completed.
    #[must_use]
    pub const fn new(context_id: String) -> Self {
        Self {
            context_id,
            mls_updated: false,
            ucan_revoked: false,
            key_packages_rotated: false,
            requires_rejoin: false,
            error: None,
        }
    }

    /// Returns `true` if all per-context steps completed successfully.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        (self.mls_updated || self.requires_rejoin)
            && self.ucan_revoked
            && self.key_packages_rotated
            && self.error.is_none()
    }
}

// ---------------------------------------------------------------------------
// KeyRotationOutcome — result of step 1
// ---------------------------------------------------------------------------

/// Outcome of step 1 (key rotation on trusted device).
///
/// Contains the new key material identifiers needed by subsequent steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationOutcome {
    /// The compromise tier that was addressed.
    pub tier: CompromiseTier,

    /// The DID **before** rotation — the compromised identity.
    ///
    /// Equal to [`Self::did_after`] for `Agent`/`ActiveSigning` (the DID string
    /// does not change); the *old* DID for `IdentityKey`, where
    /// `migrate_identity` mints a new one.
    ///
    /// Load-bearing for any step that must name the material still at risk.
    /// Per-identity resources are keyed by **owner DID** — `KeyPackages` live
    /// in the supervisor's `key_package_stores: DashMap<DID, _>` — so after an
    /// `IdentityKey` migration the stale, compromised `KeyPackages` sit under
    /// `did_before`, not under the fresh `did_after`. Reporting `did_after`
    /// would send an operator looking under a DID that has none.
    pub did_before: DID,

    /// The DID after rotation. Same as original for `Agent`/`ActiveSigning`
    /// tiers; new DID for `IdentityKey` tier.
    pub did_after: DID,

    /// Whether the DID changed (identity migration occurred).
    pub did_changed: bool,

    /// Key scope(s) that were rotated — used to scope UCAN revocation.
    ///
    /// For `Agent` tier: `["#agent"]`.
    /// For `ActiveSigning` tier: `["#active"]`.
    /// For `IdentityKey` tier: `["#active", "#agent"]` (all signing keys).
    pub rotated_key_scopes: Vec<String>,

    /// Unix timestamp (milliseconds) of the rotation.
    pub rotated_at: u64,
}

// ---------------------------------------------------------------------------
// ContactNotification — step 5 payload
// ---------------------------------------------------------------------------

/// Key-change notification sent to contacts in step 5.
///
/// Contacts who completed Key Continuity Verification (§9.11) are alerted
/// that re-verification is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactNotification {
    /// The DID that underwent recovery.
    pub did: DID,

    /// The new DID, if identity migration occurred.
    pub new_did: Option<DID>,

    /// The compromise tier.
    pub tier: CompromiseTier,

    /// Unix timestamp (milliseconds) of the key change.
    pub timestamp: u64,

    /// Whether Key Continuity Verification re-verification is needed.
    pub kcv_reverification_required: bool,
}

/// What a [`RecoveryBackend::notify_contacts`] call actually achieved.
///
/// A backend reports only what it **did** — the contacts it reached. The
/// orchestrator derives the unreachable set as `contacts - reached` and reports
/// both on [`ContactNotificationOutcome`], so a backend cannot shrink the set
/// of contacts an operator must chase by omitting entries: an omission reads as
/// unreachable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactsReached {
    /// The DIDs the key-change notification was successfully sent to.
    ///
    /// Order and duplicates do not matter — the orchestrator canonicalises.
    /// A DID not present in the call's `contacts` argument is ignored.
    pub dids: Vec<DID>,
}

// ---------------------------------------------------------------------------
// PskRotationParams — step 6 parameters
// ---------------------------------------------------------------------------

/// Parameters for step 6: identity private state re-encryption.
///
/// Includes the set of enrolled device public keys (to distribute the new PSK
/// via HPKE) and optionally a compromised device to exclude.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PskRotationParams {
    /// The identity DID. Bound into the HPKE `info` for each wrapped PSK
    /// (`"scp-private-state-v1" || len(did) || did || "psk-rotate"`, §3.7.2),
    /// preventing a wrap intended for one identity from opening under another.
    pub did: String,

    /// X25519 public keys of all enrolled devices.
    pub enrolled_device_pubkeys: Vec<Vec<u8>>,

    /// If the compromise involved a device, its X25519 public key to exclude
    /// from new PSK distribution.
    pub compromised_device_pubkey: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// RecoveryBackend — trait for platform-specific recovery operations
// ---------------------------------------------------------------------------

/// Backend trait for platform-specific recovery operations.
///
/// The orchestrator defines step ordering and failure isolation; the backend
/// provides the concrete MLS, UCAN, `KeyPackage`, notification, and PSK
/// operations. Each method corresponds to one recovery step (2–6).
///
/// SDK integration layers implement this trait to wire the orchestrator into
/// the actual MLS group manager, UCAN store, relay transport, etc.
///
/// See spec §9.12.
///
/// The trait is `async` (via [`macro@async_trait`], ADR-049 Decision 7) so the
/// production backend can `.await` the supervisor mailbox directly rather than
/// bridging through `block_in_place` + `Handle::block_on`. It is consumed as
/// `&dyn RecoveryBackend`, so `#[async_trait(?Send)]` is used — the trait
/// object is deliberately not `Sync` (the orchestrator holds it across await
/// points on a single task; see [`CompromiseRecoveryOrchestrator::execute_recovery`]).
#[async_trait(?Send)]
pub trait RecoveryBackend {
    /// Step 2: Issue an MLS `Update` proposal in the given context.
    ///
    /// The MLS `Update` provides post-compromise security: new epoch keys are
    /// derived from the new key material, making the compromised old key
    /// useless for future messages.
    ///
    /// If the member has been offline too long (Tier 3 per ADR-029), return
    /// a `RecoveryStepError` with `description` containing "requires rejoin".
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if the MLS update proposal cannot be
    /// issued (e.g., the member requires rejoin or the MLS group is
    /// unavailable).
    async fn mls_update(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 3: Revoke all UCAN tokens issued by the compromised key.
    ///
    /// For agent key compromise: revoke only tokens with
    /// `fct.scp_key_scope: "#agent"`. The `key_rotation.rotated_key_scopes`
    /// field indicates which scopes to revoke.
    ///
    /// Adds revocations to the context's `RevocationList` and distributes
    /// via MLS application messages (§9.5). Issues new tokens signed by the
    /// new key.
    ///
    /// This is the **contract a backend must satisfy**, not a description of
    /// what ships: [`ProductionRecoveryBackend::revoke_ucans`] cannot satisfy
    /// it today and fails closed (#2069). An `Ok(())` from this method is a
    /// claim that the compromised key's tokens are now rejected at the
    /// revocation gates — only return it when that is true.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if UCAN revocation or re-issuance fails,
    /// or if the backend has no revocation capability at all.
    async fn revoke_ucans(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 4: Delete old `KeyPackages` and publish new ones.
    ///
    /// Prevents new group additions using old key material.
    ///
    /// **Identity-scoped, not context-scoped.** `KeyPackages` are published
    /// and stored per owner DID (the supervisor's `key_package_stores:
    /// DashMap<DID, _>`), so this takes no `context_id`: the orchestrator
    /// calls it exactly once per recovery, after the per-context steps and
    /// independently of how many contexts exist. The relevant identity is
    /// [`KeyRotationOutcome::did_before`] — the compromised DID the stale
    /// `KeyPackages` are keyed by (which differs from `did_after` after an
    /// `IdentityKey` migration).
    ///
    /// This is the **contract a backend must satisfy**, not a description of
    /// what ships: [`ProductionRecoveryBackend::rotate_key_packages`] cannot
    /// satisfy it today and fails closed (#2240 Part B item 2, #1083 finding
    /// 6). An `Ok(())` from this method is a claim that the compromised
    /// identity's published `KeyPackages` are gone from the relay and
    /// replacements carrying attestations re-issued under the new key are
    /// live (§9.12 step 4) — only return it when that is true. Notifying peers
    /// to drop cached copies is not sufficient.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] if old key packages cannot be deleted or
    /// new ones cannot be published, or if the backend has no implementation of
    /// the rotation protocol. Note that a relay publish *seam* does exist
    /// (`ContextTransportProvider::publish_key_package`); what
    /// [`ProductionRecoveryBackend::rotate_key_packages`] lacks is the
    /// attestation lifecycle that would give it something to rotate, plus any
    /// retract path — see that method's traced call graph.
    async fn rotate_key_packages(
        &self,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError>;

    /// Step 5: Send key-change notification to contacts.
    ///
    /// Contacts who completed Key Continuity Verification (§9.11) are alerted
    /// that re-verification is needed. Identity-scoped: called once per
    /// recovery, with a non-empty contact set (the orchestrator reports
    /// [`ContactNotificationOutcome::NotApplicable`] without calling when there
    /// are none).
    ///
    /// Best-effort per §9.12 — the protocol requires no delivery confirmation,
    /// so reaching at least one contact is `Ok`. **Return the DIDs actually
    /// reached**, not a bare success: §9.12's best-effort rule governs whether
    /// recovery blocks, not whether the caller is told which contacts still
    /// trust the compromised key. Every contact omitted from
    /// [`ContactsReached::dids`] is reported unreachable, so under-reporting is
    /// fail-safe and over-reporting is a lie.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] with `step: 5` if no contact could be
    /// reached. Non-fatal: the orchestrator records it and continues. Returning
    /// `Ok` with an empty [`ContactsReached::dids`] means the same thing and is
    /// normalised to the same failed outcome — prefer the explicit `Err`, which
    /// can explain why.
    async fn notify_contacts(
        &self,
        did: &DID,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contacts: &HashSet<DID>,
    ) -> Result<ContactsReached, RecoveryStepError>;

    /// Step 6: Rotate the PSK and re-encrypt identity private state.
    ///
    /// If the compromise involved a device, that device is excluded from the
    /// new PSK distribution. Identity-scoped: called once per recovery, and
    /// only for the tiers where the PSK is affected (the orchestrator reports
    /// [`StepOutcome::NotApplicable`] without calling for the `Agent` tier).
    ///
    /// This is the **contract a backend must satisfy**, not a description of
    /// what ships: [`ProductionRecoveryBackend::rotate_psk`] cannot satisfy it
    /// today and fails closed (#2240 Part B). An `Ok(())` from this method is a
    /// claim that identity private state (§3.7) is now encrypted under a PSK
    /// that every eligible enrolled device — and no excluded one — can open;
    /// only return it when that is true. Emitting wrapped PSKs that nothing
    /// installs is not sufficient.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryStepError`] with `step: 6` if the PSK could not be
    /// rotated or distributed. Non-fatal: the orchestrator records it and
    /// continues (§9.12 "Steps 5 and 6 are non-fatal").
    async fn rotate_psk(&self, params: &PskRotationParams) -> Result<(), RecoveryStepError>;
}

// ---------------------------------------------------------------------------
// CompromiseRecoveryOrchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the 6-step compromise recovery protocol (§9.12).
///
/// The orchestrator coordinates key rotation, MLS updates, UCAN revocation,
/// `KeyPackage` rotation, contact notification, and PSK re-encryption in
/// dependency order. Failure in one context does not block recovery in others.
///
/// Step operations are delegated to a [`RecoveryBackend`] implementation,
/// which provides the platform-specific MLS, UCAN, relay, and notification
/// primitives.
///
/// # Usage
///
/// ```rust,ignore
/// let backend = MyRecoveryBackend::new(/* ... */);
/// let orchestrator = CompromiseRecoveryOrchestrator::new(
///     did.clone(),
///     context_ids.clone(),
/// );
/// let result = orchestrator.execute_recovery(
///     CompromiseTier::Agent,
///     Some(&key_rotation_outcome), // step 1 ran; None would fail closed
///     &contact_dids,
///     None, // no PSK rotation for agent key compromise
///     &backend,
///     &clock,
/// ).await?;
/// ```
///
/// See spec §9.12.
pub struct CompromiseRecoveryOrchestrator {
    /// The DID performing recovery.
    did: DID,

    /// Active context IDs where the DID is a member.
    context_ids: Vec<String>,
}

impl CompromiseRecoveryOrchestrator {
    /// Creates a new orchestrator for the given DID and set of active contexts.
    ///
    /// # Arguments
    ///
    /// * `did` — The DID performing recovery.
    /// * `context_ids` — All context IDs where this DID is an active member.
    #[must_use]
    pub const fn new(did: DID, context_ids: Vec<String>) -> Self {
        Self { did, context_ids }
    }

    /// Executes the full 6-step compromise recovery protocol.
    ///
    /// # NOT IDEMPOTENT — do not blind-retry
    ///
    /// Every step this drives has a real side effect, and none is guarded by a
    /// completion marker, so re-invoking after a failure **re-executes the
    /// steps that already succeeded**:
    ///
    /// * step 2 issues another MLS epoch advance (a real commit) in every
    ///   context that got that far; and
    /// * step 5 re-notifies every contact.
    ///
    /// This matters because with the shipped [`ProductionRecoveryBackend`] this
    /// method currently ALWAYS returns `Err` (steps 3, 4 and 6 fail closed —
    /// #2069, #2240 Part B item 2, #2240 Part B), so a caller that retries on
    /// error will loop on those side effects forever. Callers must treat a
    /// failure as terminal and inspect [`RecoveryProgress`] to decide what, if
    /// anything, to re-drive. The `*Unwired` [`RecoveryStepErrorCode`] variants
    /// exist so this is machine-decidable: only
    /// [`RecoveryStepErrorCode::DispatchFailed`] is retryable.
    ///
    /// Steps execute in dependency order: 1→2→3→4→(5,6 parallel).
    ///
    /// Step 1 (key rotation) must be completed externally before calling this
    /// method — the caller provides the `KeyRotationOutcome` from step 1.
    /// This design separates the DID-method-specific rotation logic (which
    /// lives in `scp-identity`) from the protocol-level orchestration (which
    /// lives here in `scp-core`).
    ///
    /// Steps 2–3 execute per-context with failure isolation via the
    /// [`RecoveryBackend`]. Steps 4, 5 and 6 are **identity-scoped**: each runs
    /// exactly once, after the per-context loop, and — per §9.12's failure
    /// isolation rule — runs regardless of how the per-context steps fared. A
    /// per-context step being unavailable must not silently cancel identity-wide
    /// security work such as PSK rotation (step 6) or contact notification
    /// (step 5); their outcomes are reported on both the `Ok` and the
    /// fail-closed paths.
    ///
    /// # Arguments
    ///
    /// * `tier` — The compromise tier being addressed.
    /// * `key_rotation` — Step-1 (key rotation) outcome, completed externally.
    ///   `Some(outcome)` means step 1 *actually* ran and supplies the material
    ///   the per-context steps consume; `None` means step 1 did not occur, so
    ///   recovery fails closed (see Errors) before any context is touched. This
    ///   single `Option` makes the invalid "populated outcome but rotation did
    ///   not happen" state unrepresentable, and drives
    ///   `RecoveryResult::key_rotation_completed` (`= key_rotation.is_some()`).
    /// * `contact_dids` — DIDs to notify in step 5. Empty set skips notification.
    /// * `psk_params` — Parameters for step 6. `None` skips PSK re-encryption
    ///   (appropriate for agent key compromise where PSK is unaffected).
    /// * `backend` — Platform-specific implementation of recovery operations.
    ///
    /// # Errors
    ///
    /// Ordinary *per-context* failures are non-fatal and recorded in
    /// `RecoveryResult::failed_contexts` (partial success). This method fails
    /// closed with a typed [`RecoveryError`] only when nothing real backs the
    /// call:
    ///
    /// * [`RecoveryError::KeyRotationFailed`] — `key_rotation` is `None`
    ///   (step 1 did not occur).
    /// * [`RecoveryError::AllContextsFailed`] — there were contexts to recover
    ///   but every one failed (none completed, none pending an ADR-029
    ///   rejoin). A recovery for an identity in *zero* contexts is not a total
    ///   failure and stays on the `Ok` path. The variant carries the
    ///   per-context step errors and the identity-scoped step outcomes, which
    ///   are computed *before* this returns.
    // `key_rotation` is an `Option` rather than a `&KeyRotationOutcome` plus a
    // parallel `performed: bool`: the two-field shape admits an invalid state
    // (a populated outcome paired with "rotation did not happen"), whereas the
    // `Option` encodes "step 1 ran" in the presence of the outcome the steps
    // need — so the `None`/fail-closed and `Some`/proceed arms cannot disagree
    // (#2240). `KeyRotationOutcome` itself is unchanged (its serialized shape
    // and helper constructors always denote a *performed* rotation).
    #[allow(clippy::future_not_send)] // backend trait object is not Sync by design
    pub async fn execute_recovery(
        &self,
        tier: CompromiseTier,
        key_rotation: Option<&KeyRotationOutcome>,
        contact_dids: &HashSet<DID>,
        psk_params: Option<&PskRotationParams>,
        backend: &dyn RecoveryBackend,
        clock: &dyn Clock,
    ) -> Result<RecoveryResult, RecoveryError> {
        let initiated_at = clock.now_millis();

        // `key_rotation_completed` derives from whether step 1 produced an
        // outcome — no hardcoded `true`.
        let key_rotation_completed = key_rotation.is_some();

        // FAIL CLOSED (#2240): step 1 (key rotation on a trusted device) is the
        // precondition for every subsequent step — steps 2–4 rotate/replace key
        // material that exists only if rotation actually happened. `None` means
        // step 1 did not occur (the outcome the steps would consume is genuinely
        // absent), so recovery fails closed with the fatal step-1 error rather
        // than fabricate a `RecoveryResult` whose `key_rotation_completed` would
        // imply a completed rotation. `Some` unwraps to the outcome the steps
        // below use.
        let Some(key_rotation) = key_rotation else {
            return Err(RecoveryError::KeyRotationFailed(
                "step 1 key rotation did not occur (no KeyRotationOutcome supplied) — cannot \
                 recover without new key material"
                    .to_owned(),
            ));
        };

        let mut states = self.run_per_context_steps(key_rotation, backend).await;

        // Step 4: KeyPackage rotation — IDENTITY-scoped, so it runs exactly
        // once, outside the per-context loop (§9.12 "Step scope"). `KeyPackages`
        // are keyed by owner DID, not by context, so calling it per context was
        // both redundant and unreachable on the zero-context path.
        //
        // Its error is NOT stamped onto the per-context states: that would
        // erase their steps-2/3 outcomes and their ADR-029 rejoin flags, and
        // would launder an identity-scoped failure through a per-context
        // channel a caller cannot retry against. It gets its own fatal variant
        // below instead.
        let step_4 = backend.rotate_key_packages(key_rotation).await;
        if step_4.is_ok() {
            for state in &mut states {
                if state.error.is_none() {
                    state.key_packages_rotated = true;
                }
            }
        }

        // Derive the result lists from the per-context states. The three are
        // disjoint BY CONSTRUCTION: `failed` is exactly `error.is_some()`, and
        // the `requires_rejoin` / `is_complete` arms are mutually exclusive via
        // `else if`. A rejoin-pending context must NOT also be reported as
        // completed — `is_complete()` treats `requires_rejoin` as satisfying
        // step 2, but the MLS Update did not actually happen and the context
        // still needs an admin remove + re-add (ADR-029).
        let mut completed_contexts = Vec::new();
        let mut failed_contexts = Vec::new();
        let mut pending_rejoin = Vec::new();
        let mut contexts_through_per_context_steps = Vec::new();
        for state in &states {
            if let Some(err) = state.error.clone() {
                failed_contexts.push((state.context_id.clone(), err));
                continue;
            }
            contexts_through_per_context_steps.push(state.context_id.clone());
            if state.requires_rejoin {
                pending_rejoin.push(state.context_id.clone());
            } else if state.is_complete() {
                completed_contexts.push(state.context_id.clone());
            }
        }

        // Steps 5 and 6 (identity-scoped cleanup). See
        // `run_identity_scoped_cleanup` for why they run here.
        let (contact_notification, private_state_reencryption) = self
            .run_identity_scoped_cleanup(tier, key_rotation, contact_dids, psk_params, backend)
            .await;

        let progress = RecoveryProgress {
            contexts_through_per_context_steps,
            failed_contexts,
            pending_rejoin,
            key_package_rotation: match &step_4 {
                Ok(()) => StepOutcome::Succeeded,
                Err(e) => StepOutcome::Failed(e.clone()),
            },
            contact_notification,
            private_state_reencryption,
        };

        // FAIL CLOSED (§9.12 "Step scope"): step 4 is identity-scoped and gates
        // completion for EVERY context, so its failure is a whole-recovery
        // failure independent of context count — including zero contexts, where
        // the per-context loop never ran and the guard below cannot fire.
        // Without this a zero-context recovery returned `Ok` while §9.12 step 4
        // had not happened.
        if let Err(step_error) = step_4 {
            return Err(RecoveryError::KeyPackageRotationFailed {
                step_error,
                progress,
            });
        }

        // FAIL CLOSED (#2240): there were contexts to recover but not one made
        // real progress — every context ended with a step error, none completed
        // and none is pending an ADR-029 rejoin — so nothing real backs the
        // per-context half of this call. Returning an all-failed
        // `RecoveryResult` would let a total failure be observed as a success.
        if !self.context_ids.is_empty()
            && completed_contexts.is_empty()
            && progress.pending_rejoin.is_empty()
        {
            return Err(RecoveryError::AllContextsFailed {
                attempted: self.context_ids.len(),
                progress,
            });
        }

        let completed_at = clock.now_millis();

        Ok(RecoveryResult {
            tier,
            did: self.did.clone(),
            new_did: if key_rotation.did_changed {
                Some(key_rotation.did_after.clone())
            } else {
                None
            },
            completed_contexts,
            failed_contexts: progress.failed_contexts,
            pending_rejoin: progress.pending_rejoin,
            // Derived from whether step 1 supplied an outcome (`is_some()`),
            // computed above. Reaching this point implies it was `Some` — the
            // `None` arm fails closed — so it is `true` here, but by derivation,
            // never a hardcoded literal that could lie about step 1.
            key_rotation_completed,
            contact_notification: progress.contact_notification,
            private_state_reencryption: progress.private_state_reencryption,
            initiated_at,
            completed_at,
        })
    }

    /// Runs the per-context steps (2 and 3) for every context, returning one
    /// [`ContextRecoveryState`] per context in orchestrator order.
    ///
    /// Every context gets a state entry, including the ones that fail. The
    /// caller DERIVES `completed_contexts` / `failed_contexts` /
    /// `pending_rejoin` from these states rather than pushing to those lists
    /// mid-loop, which makes `failed_contexts` and `pending_rejoin` disjoint BY
    /// CONSTRUCTION. The previous shape pushed to both lists independently, so
    /// a context that requires an ADR-029 rejoin (step 2) and then fails step 3
    /// landed in `pending_rejoin` AND `failed_contexts` — and the total-failure
    /// guard, which tests `pending_rejoin.is_empty()`, was suppressed by its own
    /// failed context. That is the exact fail-open the guard exists to close.
    ///
    /// Step 4 is NOT here: it is identity-scoped and runs once, in the caller.
    #[allow(clippy::future_not_send)] // backend trait object is not Sync by design
    async fn run_per_context_steps(
        &self,
        key_rotation: &KeyRotationOutcome,
        backend: &dyn RecoveryBackend,
    ) -> Vec<ContextRecoveryState> {
        let mut states: Vec<ContextRecoveryState> = Vec::with_capacity(self.context_ids.len());
        for context_id in &self.context_ids {
            let mut state = ContextRecoveryState::new(context_id.clone());

            // Step 2: MLS Update.
            match backend.mls_update(context_id, key_rotation).await {
                Ok(()) => {
                    state.mls_updated = true;
                }
                Err(e) if e.code == RecoveryStepErrorCode::RequiresRejoin => {
                    // Tier 3 re-join needed (ADR-029). Not an error: recovery
                    // continues into step 3 to limit the compromised key's
                    // utility, and the context is reported as pending rejoin
                    // *only if* the remaining steps leave it error-free.
                    //
                    // Recognised by `code`, not by a substring of `description`
                    // — the prose is free to change; the classification is the
                    // contract.
                    state.requires_rejoin = true;
                }
                Err(e) => {
                    state.error = Some(e);
                    states.push(state);
                    continue;
                }
            }

            // Step 3: UCAN revocation (depends on step 2).
            if let Err(e) = backend.revoke_ucans(context_id, key_rotation).await {
                state.error = Some(e);
                states.push(state);
                continue;
            }
            state.ucan_revoked = true;

            states.push(state);
        }
        states
    }

    /// Runs the identity-scoped cleanup steps (5 and 6), returning their
    /// tri-state outcomes.
    ///
    /// These run **regardless of per-context outcomes**, and before the
    /// fail-closed guards: §9.12 makes them identity-wide cleanup after step 4,
    /// so a per-context failure must not silently cancel them. It previously
    /// did — the total-failure guard returned first — which meant a production
    /// recovery advanced the MLS epoch and did nothing else, and whether the
    /// PSK got rotated depended on the unrelated question of whether some
    /// context happened to need an ADR-029 rejoin.
    ///
    /// Each returns a tri-state [`StepOutcome`]. "Did not run" is never
    /// reported as success — the previous `bool` conflated them, so an
    /// agent-tier recovery with no contacts claimed both steps succeeded when
    /// neither executed.
    #[allow(clippy::future_not_send)] // backend trait object is not Sync by design
    async fn run_identity_scoped_cleanup(
        &self,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contact_dids: &HashSet<DID>,
        psk_params: Option<&PskRotationParams>,
        backend: &dyn RecoveryBackend,
    ) -> (ContactNotificationOutcome, StepOutcome) {
        // Step 5: Contact notification.
        let contact_notification = if contact_dids.is_empty() {
            ContactNotificationOutcome::NotApplicable("no known contacts to notify".to_owned())
        } else {
            // Every contact, sorted — the fallback "nobody was reached" set and
            // the base the unreachable set is derived from. Sorted because
            // `contact_dids` is a `HashSet`, whose iteration order would make
            // the report unstable across runs.
            let mut all_contacts: Vec<DID> = contact_dids.iter().cloned().collect();
            all_contacts.sort();

            match backend
                .notify_contacts(&self.did, tier, key_rotation, contact_dids)
                .await
            {
                Ok(reached) => {
                    // DERIVE the unreachable set rather than trusting a backend
                    // to report it: a backend that under-reports what it
                    // reached then over-reports what is unreachable (fail-safe),
                    // and cannot silently shrink the set an operator must chase.
                    // Entries the backend names that were never in `contacts`
                    // are ignored by the same construction.
                    let reached_set: HashSet<&DID> = reached.dids.iter().collect();
                    let (reached, unreachable): (Vec<DID>, Vec<DID>) = all_contacts
                        .into_iter()
                        .partition(|contact| reached_set.contains(contact));

                    if reached.is_empty() {
                        // `Ok` with nothing reached is the same event as `Err`:
                        // normalise it so a caller branching on the outcome
                        // cannot see an empty "delivered".
                        ContactNotificationOutcome::Failed {
                            error: RecoveryStepError {
                                step: 5,
                                code: RecoveryStepErrorCode::DispatchFailed,
                                description: format!(
                                    "the backend reported success for step 5 but named no \
                                     reached contact, so none of the {} contact(s) was told \
                                     to re-run §9.11 key-continuity verification",
                                    unreachable.len()
                                ),
                            },
                            unreachable,
                        }
                    } else {
                        ContactNotificationOutcome::Delivered {
                            reached,
                            unreachable,
                        }
                    }
                }
                Err(error) => ContactNotificationOutcome::Failed {
                    error,
                    unreachable: all_contacts,
                },
            }
        };

        // Step 6: Identity private-state re-encryption. The PSK is unaffected
        // by an agent-key compromise, so the Agent tier genuinely skips it.
        let private_state_reencryption = match tier {
            CompromiseTier::Agent => StepOutcome::NotApplicable(
                "PSK is unaffected by an agent-key compromise".to_owned(),
            ),
            CompromiseTier::ActiveSigning | CompromiseTier::IdentityKey => match psk_params {
                Some(params) => match backend.rotate_psk(params).await {
                    Ok(()) => StepOutcome::Succeeded,
                    Err(e) => StepOutcome::Failed(e),
                },
                None => StepOutcome::Failed(RecoveryStepError {
                    step: 6,
                    code: RecoveryStepErrorCode::Unspecified,
                    description: "this tier rotates the PSK but no PskRotationParams were \
                                  supplied, so step 6 could not run"
                        .to_owned(),
                }),
            },
        };

        (contact_notification, private_state_reencryption)
    }

    /// Returns the DID this orchestrator is recovering.
    #[must_use]
    pub const fn did(&self) -> &DID {
        &self.did
    }

    /// Returns the context IDs included in recovery.
    #[must_use]
    pub fn context_ids(&self) -> &[String] {
        &self.context_ids
    }
}

// ---------------------------------------------------------------------------
// Helper: build KeyRotationOutcome for each tier
// ---------------------------------------------------------------------------

/// Builds a [`KeyRotationOutcome`] for agent key compromise (tier 1).
///
/// The DID does not change. Only `#agent` key scope is rotated.
#[must_use]
pub fn agent_key_rotation_outcome(did: &DID, rotated_at: u64) -> KeyRotationOutcome {
    KeyRotationOutcome {
        tier: CompromiseTier::Agent,
        did_before: did.clone(),
        did_after: did.clone(),
        did_changed: false,
        rotated_key_scopes: vec!["#agent".to_owned()],
        rotated_at,
    }
}

/// Builds a [`KeyRotationOutcome`] for active signing key compromise (tier 2).
///
/// The DID does not change. Only `#active` key scope is rotated.
#[must_use]
pub fn active_key_rotation_outcome(did: &DID, rotated_at: u64) -> KeyRotationOutcome {
    KeyRotationOutcome {
        tier: CompromiseTier::ActiveSigning,
        did_before: did.clone(),
        did_after: did.clone(),
        did_changed: false,
        rotated_key_scopes: vec!["#active".to_owned()],
        rotated_at,
    }
}

/// Builds a [`KeyRotationOutcome`] for identity key compromise (tier 3).
///
/// The DID changes — `new_did` is the migrated identity, and `old_did` is
/// retained as [`KeyRotationOutcome::did_before`] because per-identity
/// resources (notably `KeyPackages`) remain keyed by the *old*, compromised
/// DID after migration.
#[must_use]
pub fn identity_key_rotation_outcome(
    old_did: &DID,
    new_did: DID,
    rotated_at: u64,
) -> KeyRotationOutcome {
    KeyRotationOutcome {
        tier: CompromiseTier::IdentityKey,
        did_before: old_did.clone(),
        did_after: new_did,
        did_changed: true,
        rotated_key_scopes: vec!["#active".to_owned(), "#agent".to_owned()],
        rotated_at,
    }
}

// ---------------------------------------------------------------------------
// ProductionRecoveryBackend — real implementation of RecoveryBackend
// ---------------------------------------------------------------------------

/// Production implementation of [`RecoveryBackend`] that dispatches MLS,
/// UCAN, `KeyPackage`, notification, and PSK operations through the
/// supervisor's trust-recovery actor mailbox.
///
/// [`RecoveryBackend`] is an `async` trait (ADR-049 Decision 7), so this
/// struct's methods `.await` the supervisor mailbox directly — there is no
/// `block_in_place` + `Handle::block_on` bridge (the former `block_on_async`
/// helper was deleted when the trait became async).
///
/// # ADR-049 Phase 2B — mailbox dispatch
///
/// Each per-context step builds a
/// [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand)
/// and routes it through
/// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command).
/// When the target context has a registered actor the command runs in
/// that actor's mailbox turn against owned `&mut PerContextState`; the
/// backend never reaches the supervisor's per-context state map directly.
/// This replaced the earlier direct supervisor-scoped calls that read
/// the `contexts` `DashMap` outside the actor mailbox.
///
/// # Construction
///
/// ```rust,ignore
/// let backend = ProductionRecoveryBackend::new(
///     supervisor.clone(),
///     post_rotation_signing_key,
/// );
/// ```
///
/// # Step mapping
///
/// | Trait method         | Mailbox command                                          |
/// |----------------------|----------------------------------------------------------|
/// | `mls_update`         | `RecoveryAdvanceEpoch` + `RecoverySendNotification` (seq 0) |
/// | `revoke_ucans`       | *none — fails closed (#2069); seq 1 is unallocated*      |
/// | `rotate_key_packages`| *none — fails closed (#2240 Part B item 2); seq 2 is unallocated* |
/// | `notify_contacts`    | `RecoveryNotifyContact` → `RecoverySendNotification` (seq 4, cross-context fan-out) |
/// | `rotate_psk`         | *none — fails closed (#2240 Part B); seq 3 is unallocated* |
///
/// See spec §9.12 and the [`CompromiseRecoveryOrchestrator`] for step
/// ordering and failure isolation semantics.
pub struct ProductionRecoveryBackend {
    /// The supervisor that owns crypto, transport, and event log providers.
    manager: Arc<crate::context::supervisor::Supervisor>,
    /// The signing key for the recovering identity (post-rotation).
    ///
    /// Recovery notifications must be signed by the real key so receivers can
    /// verify them against the sender's public key. An ephemeral key would
    /// produce signatures that don't match.
    signing_key: ed25519_dalek::SigningKey,
}

impl ProductionRecoveryBackend {
    /// Creates a new production recovery backend.
    ///
    /// # Arguments
    ///
    /// * `manager` — The context manager for the local node. Must be shared
    ///   via `Arc` because the orchestrator may run concurrently with other
    ///   context operations.
    /// * `signing_key` — The post-rotation signing key for the recovering
    ///   identity. Recovery notifications are signed with this key so
    ///   receivers can verify them against the sender's public key.
    #[must_use]
    pub const fn new(
        manager: Arc<crate::context::supervisor::Supervisor>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        Self {
            manager,
            signing_key,
        }
    }

    /// Maps a dispatch-level [`ContextError`](scp_protocol::context::ContextError)
    /// into a [`RecoveryStepError`].
    ///
    /// The `RecoveryBackend` trait is `async` (ADR-049 Decision 7), so backends
    /// `.await` the supervisor mailbox directly — there is no longer a
    /// `block_in_place` + `Handle::block_on` bridge. This helper only performs
    /// the error-shape conversion the former bridge also did: `step` is set to
    /// `0` and each caller overrides it with the concrete recovery-step number.
    ///
    /// The code is always [`RecoveryStepErrorCode::DispatchFailed`] — this
    /// helper only ever sees mailbox/actor/transport failures, which are
    /// transient. A caller that needs to report an *unwired capability* builds
    /// its own error with the specific code; it never routes through here.
    // Takes the error by value so it can be used directly as a `.map_err(...)`
    // fn-pointer (which hands the closure the owned error).
    #[allow(clippy::needless_pass_by_value)]
    fn dispatch_step_error(e: scp_protocol::context::ContextError) -> RecoveryStepError {
        RecoveryStepError {
            step: 0, // Caller overrides this.
            code: RecoveryStepErrorCode::DispatchFailed,
            description: e.to_string(),
        }
    }

    /// Dispatches a [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand) through the supervisor's
    /// trust-recovery mailbox (ADR-049 Phase 2B) and awaits the typed
    /// reply that the command carries on its embedded oneshot.
    ///
    /// `build_cmd` receives the freshly-created reply sender and returns
    /// the fully-constructed command. Routing decision lives entirely in
    /// [`Supervisor::dispatch_trust_recovery_command`](crate::context::supervisor::Supervisor::dispatch_trust_recovery_command): when a context
    /// actor is registered the command runs against that actor's owned
    /// `&mut PerContextState` (no per-context map lookup); otherwise it
    /// falls through to the supervisor-scoped direct path. Either way the typed
    /// result returns on `reply`.
    ///
    /// This replaces the previous direct supervisor-scoped calls that
    /// read the supervisor's per-context state map outside the actor
    /// mailbox.
    ///
    /// The dispatch error (the `Outcome` channel) and the command's own
    /// typed reply are folded into a single `Result`: a closed reply
    /// channel surfaces as a [`ContextError::TransportFailed`](scp_protocol::context::ContextError::TransportFailed) so the
    /// caller's [`Self::dispatch_step_error`] maps it to a [`RecoveryStepError`].
    async fn dispatch_trust_recovery<F, T>(
        &self,
        build_cmd: F,
    ) -> Result<T, scp_protocol::context::ContextError>
    where
        F: FnOnce(
            tokio::sync::oneshot::Sender<Result<T, scp_protocol::context::ContextError>>,
        ) -> crate::context::actor::commands::TrustRecoveryCommand,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = build_cmd(reply_tx);
        // The dispatch-level `Outcome` only reports the mailbox/timeout
        // envelope; the operation's typed result rides the command's own
        // oneshot. Propagate a dispatch-level error first (e.g. no
        // supervisor attached) before awaiting the reply.
        self.manager.dispatch_trust_recovery_command(cmd).await?;
        crate::context::actor::bounded_reply_await(reply_rx)
            .await
            .map_err(|_| {
                scp_protocol::context::ContextError::TransportFailed(
                    "trust-recovery reply channel closed or timed out before a result was sent"
                        .to_owned(),
                )
            })?
    }

    /// Dispatches a `RecoverySendNotification` for a named context
    /// through the trust-recovery mailbox and awaits its reply.
    ///
    /// Wraps the shared payload construction (context, sender DID,
    /// sequence, signing key) used by every recovery step that sends a
    /// notification to an already-known context. That is now step 2 (seq 0)
    /// only: steps 3, 4 and 6 fail closed before dispatching, so seq 1, seq 2
    /// and seq 3 are unallocated (#2069, #2240 Part B item 2, #2240 Part B).
    /// Step 5
    /// does NOT route through here — its context is not known up front, so
    /// [`RecoveryBackend::notify_contacts`] dispatches `RecoveryNotifyContact` and the
    /// supervisor's fan-out builds the seq-4 `RecoverySendNotification` after
    /// picking a shared context. The
    /// signing key is copied into the boxed payload via
    /// [`SigningKeyBytes::from_signing_key`](crate::context::actor::commands::SigningKeyBytes::from_signing_key) so it zeroizes on drop while
    /// the command is in flight.
    async fn dispatch_recovery_send_notification(
        &self,
        context_id: &str,
        sender_did: &str,
        payload: &[u8],
        sequence: u64,
    ) -> Result<(), scp_protocol::context::ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
        };

        let send_payload = Box::new(RecoverySendNotificationPayload {
            context_id: context_id.to_owned(),
            sender_did: sender_did.to_owned(),
            payload: payload.to_vec(),
            sequence,
            signing_key: SigningKeyBytes::from_signing_key(&self.signing_key),
        });
        self.dispatch_trust_recovery(|reply| TrustRecoveryCommand::RecoverySendNotification {
            payload: send_payload,
            reply,
        })
        .await
    }
}

#[async_trait(?Send)]
impl RecoveryBackend for ProductionRecoveryBackend {
    async fn mls_update(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // Step 2: Advance the MLS epoch for post-compromise security.
        // The ContextManager increments the epoch counter, places the old
        // epoch into the grace window, and emits an event log entry.
        use crate::context::actor::commands::TrustRecoveryCommand;
        let result = self
            .dispatch_trust_recovery(|reply| TrustRecoveryCommand::RecoveryAdvanceEpoch {
                context_id: context_id.to_owned(),
                reply,
            })
            .await
            .map_err(Self::dispatch_step_error);
        match result {
            Ok(_epoch) => {
                // Send a scoped epoch-advance notification including the
                // rotated key scopes so recipients know which keys were
                // compromised and can adjust their local trust state.
                let scoped_payload = serde_json::json!({
                    "event": "recovery:epoch_advanced",
                    "rotated_key_scopes": key_rotation.rotated_key_scopes,
                    "did_after": key_rotation.did_after.as_ref(),
                    "did_changed": key_rotation.did_changed,
                });
                match serde_json::to_vec(&scoped_payload) {
                    Ok(payload_bytes) => {
                        let notify_result = self
                            .dispatch_recovery_send_notification(
                                context_id,
                                key_rotation.did_after.as_ref(),
                                &payload_bytes,
                                0, // sequence 0: MLS epoch-advance notification
                            )
                            .await
                            .map_err(Self::dispatch_step_error);
                        // Notification failure is non-fatal — the epoch was
                        // already advanced, which is the critical security step.
                        if let Err(e) = notify_result {
                            tracing::warn!(
                                context_id = %context_id,
                                error = %e,
                                "failed to send scoped epoch-advance notification"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            context_id = %context_id,
                            error = %e,
                            "failed to serialize epoch-advance notification payload, skipping notification"
                        );
                    }
                }
                Ok(())
            }
            Err(mut e) => {
                e.step = 2;
                // Detect the Tier 3 re-join requirement (ADR-029) and translate
                // it into a typed code. This is the ONE place a substring match
                // is legitimate: it parses a foreign `ContextError` string from
                // the runtime, which has no recovery-specific code. Everything
                // downstream branches on `code`, never on this prose.
                if e.description.contains("requires rejoin") {
                    return Err(RecoveryStepError {
                        step: 2,
                        code: RecoveryStepErrorCode::RequiresRejoin,
                        description: "member requires rejoin (Tier 3, ADR-029)".to_owned(),
                    });
                }
                Err(e)
            }
        }
    }

    /// Step 3 — **not wired; always fails closed** (#2069).
    ///
    /// This step previously built a throwaway
    /// [`RevocationList`](scp_protocol::crypto::ucan::revoke::RevocationList),
    /// `revoke`d a *synthetic marker string*
    /// (`"recovery:{ctx}:scopes={..}:before={ts}"`) into it, distributed the
    /// serialized list over the recovery-notification channel and returned
    /// `Ok(())`. Nothing was revoked by that, and the step reported success for
    /// a security action that did not happen — the nullifier class the builder
    /// tenets forbid.
    ///
    /// # Why the marker could never bite
    ///
    /// Both revocation gates in the system are **exact SHA-256 token-CID**
    /// lookups
    /// ([`compute_revocation_cid`](scp_protocol::crypto::ucan::revoke::compute_revocation_cid)),
    /// so a synthetic scope+timestamp marker matches no real token in either:
    ///
    /// * the **runtime-side** set `governance.revoked_spending_ucan_cids`,
    ///   consulted through the crate-private `ContextRevocationChecker` adapter
    ///   in `context::economy_logic`; and
    /// * the **FFI-layer** per-context `RevocationList`, consulted through
    ///   `BridgeRevocationChecker` (`scp-ffi/common/src/resolvers.rs`).
    ///
    /// # What is and is not missing
    ///
    /// Per-token revocation by CID is **not** missing: the FFI-layer gate has a
    /// live, shipped write path (`ucan_revoke` → `core_revoke_ucan`), driven by
    /// a caller that already holds the token. What recovery lacks is narrower
    /// and still disqualifying:
    ///
    /// * recovery cannot **enumerate** the outstanding tokens issued by a
    ///   compromised key scope, so it cannot drive that per-CID path; and
    /// * the runtime-side enforcement set has **no write path at all** — no
    ///   receive-side handler merges a distributed revocation list into it.
    ///
    /// So this method returns a typed error rather than a false guarantee.
    /// Recovery surfaces the missing capability (a failed context, and
    /// [`RecoveryError::AllContextsFailed`] when no context recovers).
    ///
    /// The real wire — enumeration (or a scope+timestamp revocation predicate)
    /// plus a receive-side merge into the runtime enforcement set — is blocked
    /// on the §9.12 revocation-model design decisions catalogued in #2240 Part
    /// B item 1 and tracked by #2069. It is deliberately NOT invented here.
    ///
    /// # Errors
    ///
    /// Always returns a step-3 [`RecoveryStepError`].
    async fn revoke_ucans(
        &self,
        context_id: &str,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // FAIL CLOSED (#2069): recovery can neither enumerate the compromised
        // scope's tokens (to drive the working per-CID path) nor write to the
        // runtime enforcement set. Report the absence instead of the previous
        // marker-string no-op that returned `Ok(())` and let the orchestrator
        // set `ucan_revoked = true`.
        Err(RecoveryStepError {
            step: 3,
            code: RecoveryStepErrorCode::UcanRevocationUnwired,
            description: format!(
                "UCAN revocation is not wired for recovery — the tokens issued by the \
                 compromised key scope(s) [{scopes}] in context `{context_id}` remain \
                 valid and must be revoked individually by a caller holding them. \
                 Failing closed rather than reporting a revocation that did not happen \
                 (#2069)",
                scopes = key_rotation.rotated_key_scopes.join(", "),
            ),
        })
    }

    /// Step 4 — **not wired; always fails closed** (#2240 Part B item 2).
    ///
    /// This step previously sent a single literal notification —
    /// `"recovery:key_package_rotation:context={id}"` — over the
    /// recovery-notification channel and returned `Ok(())`. A hint to peers to
    /// drop cached copies is not the step: §9.12 step 4 requires *deleting* the
    /// published `KeyPackages` carrying attestations signed by the retired key
    /// and *publishing* replacements re-issued under the new key. Neither
    /// happened — the same nullifier class as [`Self::revoke_ucans`] (#2069).
    ///
    /// # Why it is unwired — traced, not inferred
    ///
    /// Every claim below was established by following callers in this repo. Two
    /// earlier versions of this comment were written from the spec and from
    /// adjacent symbol names instead, and both were wrong; do not reintroduce a
    /// justification you have not traced.
    ///
    /// 1. **No attestation is ever minted.** Every `KeyPackage` is built by
    ///    `generate_key_package_inner` (`scp-mls/src/group.rs:1172`), whose only
    ///    two callers — `generate_key_package_with_wrapping_key` (`:1090`) and
    ///    `generate_key_package_with_context_params` (`:1162`) — pass leaf
    ///    extensions that are at most `Extensions::single(wrapping_key_ext)`
    ///    (`:1082`, `:1155`). The `0xFF03` `scp_keypackage_attestation`
    ///    extension is therefore never attached, and it cannot be: its sole
    ///    constructor, `KeyPackageAttestation::make_attestation_extension`
    ///    (`scp-mls/src/keypackage_attestation.rs:334`), is called only from
    ///    that file's own test module (`:1215`). Every `KeyPackageAttestation`
    ///    construction in the workspace is likewise a test fixture (the only one
    ///    outside `keypackage_attestation.rs` is
    ///    `scp-runtime/src/crypto/mls/attestation_verification.rs:419`, inside
    ///    the `#[cfg(test)]` module that starts at `:255`).
    /// 2. **No Add path verifies one.** `verify_add_attestation`
    ///    (`scp-runtime/src/crypto/mls/attestation_verification.rs:191`) has
    ///    zero callers anywhere in `crates/` or `bindings/` outside its own test
    ///    module.
    /// 3. **Publication is undriven.** `KeyPackageCommand::Publish` →
    ///    `handle_publish` (`supervisor/key_package_actor.rs:1096`, defined at
    ///    `:1607`) is the sole caller of
    ///    `ContextTransportProvider::publish_key_package`, and nothing in
    ///    production sends that command — every sender is in
    ///    `key_package_actor_tests.rs`. (Note the contrast with
    ///    *replenishment*, which IS production-driven — see below.)
    ///
    /// So the KeyPackage-attestation lifecycle — mint (§9.7.1), verify at Add,
    /// publish (§9.16.1) — is unwired end to end. Step 4 has nothing to rotate.
    ///
    /// # What step 1's rotation actually revokes today: nothing
    ///
    /// §9.7.3/§9.12 designate `#active`/`#agent` rotation as the primary
    /// revocation lever, bounded by `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS`
    /// (300s, `scp-mls/src/keypackage_attestation.rs:98`). That is **spec
    /// intent, not yet in force**: with (1) no attestation minted and (2) no
    /// verifier invoking the §9.7.1 checks, there is nothing for a rotation to
    /// invalidate and nothing that would reject a stale attestation. An operator
    /// must NOT read step 1 as having already bounded this exposure to five
    /// minutes. It has not.
    ///
    /// # The genuine residual
    ///
    /// Not "stale published `KeyPackages` stay fetchable" — since publication is
    /// undriven (3), a production node has never published one, so there is no
    /// published artifact to retract. Replenishment, by contrast, IS
    /// production-driven: `KeyPackageStoreActor::run` replenishes on spawn
    /// (`key_package_actor.rs:1035`) and `maybe_replenish` runs after every
    /// `Reserve` / `ReserveAny` / `CancelReservation` (`:1067`, `:1074`,
    /// `:1090`), with `ReserveAny` dispatched by
    /// `Supervisor::reserve_key_package` (`supervisor/supervisor.rs:12948`), a
    /// shipped FFI export (`scp-ffi/uniffi/src/bridge.rs:10281`). Fresh
    /// `KeyPackages` are therefore minted continuously in production — they are
    /// simply never published and carry no attestation.
    ///
    /// The unretractable artifact is the `KeyPackage` **public bytes handed to
    /// inviters out-of-band** by `reserve_key_package`. Those have left the
    /// node; no relay delete would reach them, and no attestation check would
    /// reject them. That is the exposure step 4 cannot currently address.
    ///
    /// Separately, step 2's MLS epoch advance is irrelevant here: it gives
    /// post-compromise security inside *existing* groups and does nothing about
    /// key material offered for *future* additions.
    ///
    /// # What a correct implementation would have to do
    ///
    /// The missing pieces are all inside this repo, not external constraints:
    /// retain the published blob id (`publish_key_package` already *receives*
    /// one from `send_via_adapter` and discards it —
    /// `scp-transport/src/provider.rs:192`, `.map(|_blob_id| ())`), add a
    /// per-`KeyPackage` retract on `ContextTransportProvider` (the adapter
    /// already exposes `delete(&BlobId)` — `scp-transport/src/traits.rs:239`;
    /// the only provider-level delete today is the context-scoped
    /// `delete_published`, `provider.rs:161`), mint attestations at §9.7.1, and
    /// invoke the Add verifier. That is #2240 Part B item 2 and #1083 finding 6,
    /// and is deliberately NOT invented here.
    ///
    /// # Errors
    ///
    /// Always returns a step-4 [`RecoveryStepError`] coded
    /// [`RecoveryStepErrorCode::KeyPackageRotationUnwired`].
    async fn rotate_key_packages(
        &self,
        key_rotation: &KeyRotationOutcome,
    ) -> Result<(), RecoveryStepError> {
        // FAIL CLOSED (#2240 Part B item 2): the KeyPackage-attestation
        // lifecycle is unwired end to end (see the doc comment for the traced
        // call graph), so there is nothing to rotate and no way to retract what
        // was already handed out. Report the absence instead of the previous
        // notification-only no-op that returned `Ok(())`.
        Err(RecoveryStepError {
            step: 4,
            code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
            description: format!(
                "KeyPackage rotation is not wired for the compromised identity `{did}` — the \
                 KeyPackage-attestation lifecycle does not exist end to end, so nothing was \
                 retracted or re-issued and step 1's key rotation revokes nothing \
                 operationally. Do NOT treat this exposure as already time-bounded. Failing \
                 closed rather than reporting a rotation that did not happen (#2240 Part B \
                 item 2, #1083 finding 6)",
                did = key_rotation.did_before.as_ref(),
            ),
        })
    }

    async fn notify_contacts(
        &self,
        did: &DID,
        tier: CompromiseTier,
        key_rotation: &KeyRotationOutcome,
        contacts: &HashSet<DID>,
    ) -> Result<ContactsReached, RecoveryStepError> {
        // Step 5: Send key-change notification to contacts.
        //
        // Build a ContactNotification and serialize it, then attempt to
        // send it to each contact's known context. If we can reach at least
        // one context per contact, notification succeeds.
        //
        // For contacts we share contexts with, the notification is sent as
        // a recovery message via the existing context transport.
        let notification = ContactNotification {
            did: did.clone(),
            new_did: if key_rotation.did_changed {
                Some(key_rotation.did_after.clone())
            } else {
                None
            },
            tier,
            timestamp: key_rotation.rotated_at,
            kcv_reverification_required: true,
        };

        // Serialize the notification. If serialization fails, notification
        // cannot proceed.
        let payload = match serde_json::to_vec(&notification) {
            Ok(p) => p,
            Err(e) => {
                return Err(RecoveryStepError {
                    step: 5,
                    code: RecoveryStepErrorCode::Unspecified,
                    description: format!("failed to serialize the contact notification: {e}"),
                });
            }
        };

        // Attempt to notify each contact via shared contexts. The manager
        // exposes `is_member` and `recovery_send_notification` which we use
        // to find contexts where both the recovering DID and the contact are
        // members, then send the notification payload through those contexts.
        //
        // Partial delivery does not block recovery (§9.12 step 5 is
        // best-effort), but it is NOT reported as unqualified success: the
        // contacts actually reached are recorded here, and the orchestrator
        // derives the unreachable set from them so an operator learns exactly
        // who still holds a §9.11 KCV binding to the compromised key.
        let mut reached = ContactsReached {
            dids: Vec::with_capacity(contacts.len()),
        };

        // Retrieve all context IDs known to the orchestrator by looking up
        // contexts where the recovering DID is a member. The orchestrator
        // was constructed with these context IDs, but the backend doesn't
        // have direct access — we check membership per contact per context.
        for contact in contacts {
            let contact_did_str = contact.as_ref();
            let did_str = did.as_ref();

            // Try sending to a shared context where both the recovering DID
            // and the contact DID are members. The supervisor's
            // `RecoveryNotifyContact` mailbox command searches registered
            // contexts to find a suitable channel, then dispatches a
            // `RecoverySendNotification` through it.
            let send_result = self
                .dispatch_trust_recovery(|reply| {
                    use crate::context::actor::commands::{
                        RecoveryNotifyContactPayload, SigningKeyBytes, TrustRecoveryCommand,
                    };
                    TrustRecoveryCommand::RecoveryNotifyContact {
                        payload: Box::new(RecoveryNotifyContactPayload {
                            recovering_did: did_str.to_owned(),
                            contact_did: contact_did_str.to_owned(),
                            payload: payload.clone(),
                            signing_key: SigningKeyBytes::from_signing_key(&self.signing_key),
                        }),
                        reply,
                    }
                })
                .await
                .map_err(Self::dispatch_step_error);

            if send_result.is_ok() {
                reached.dids.push(contact.clone());
            }
            // Best-effort: failure for one contact doesn't block others.
        }

        // Contact notification is best-effort per spec §9.12 — the protocol
        // does not require delivery confirmation — so reaching at least one
        // contact is `Ok`, carrying exactly who was reached. The orchestrator
        // never calls this with an empty contact set (it reports
        // `ContactNotificationOutcome::NotApplicable` instead), so "nothing was
        // sent" here always means every contact was unreachable.
        if reached.dids.is_empty() {
            Err(RecoveryStepError {
                step: 5,
                code: RecoveryStepErrorCode::DispatchFailed,
                description: format!(
                    "no shared context could be found or reached for any of the {} contact(s), \
                     so none was told to re-run §9.11 key-continuity verification",
                    contacts.len()
                ),
            })
        } else {
            Ok(reached)
        }
    }

    /// Step 6 — **not wired; always fails closed** (#2240 Part B).
    ///
    /// This step previously minted a real 32-byte PSK from `OsRng`, HPKE-wrapped
    /// it per enrolled device (§3.7.2), dispatched
    /// `{"event":"recovery:psk_rotation","wrapped_psks":[..]}` to the literal
    /// context id `"identity-private-state"`, and returned `Ok(())`. Nothing
    /// re-encrypted any private state, and the step reported success for a
    /// security action that did not happen — the same nullifier class as
    /// [`Self::revoke_ucans`] (#2069) and [`Self::rotate_key_packages`]
    /// (#2240 Part B item 2).
    ///
    /// # Why it is unwired — traced, not inferred
    ///
    /// 1. **Nothing installs a delivered wrap.** `wrapped_psks`, `unwrap_psk`
    ///    and `install_psk` had exactly three occurrences across `crates/` and
    ///    `bindings/`, all inside the deleted `rotate_psk` body itself. There is
    ///    no receive-side handler for the `recovery:psk_rotation` event, no
    ///    private-state re-encryption driven by it, and no custody install — so
    ///    a wrap that arrived at a device installed nothing.
    /// 2. **The originator could not use the PSK either.** The plaintext was
    ///    held in `Zeroizing` and dropped at end of scope without being
    ///    retained anywhere, so a "successful" rotation produced a key *nobody*
    ///    could subsequently open the re-encrypted state with — including the
    ///    recovering identity.
    ///
    /// # The production failure was an accident, not a design
    ///
    /// The old body only ever errored because
    /// `recovery_send_notification_direct` rejects context ids that are not 64
    /// lowercase hex characters, and that path is reached only when no actor is
    /// registered for the id. But `Supervisor::create_context` takes a
    /// caller-supplied id and the FFI `validate_context_id` accepts
    /// alphanumerics, hyphens and underscores up to 256 characters — so
    /// `"identity-private-state"` is a perfectly legal id that any local caller
    /// could register, flipping step 6 to `Ok(())`. The fail-closed guarantee
    /// must not rest on an id-shape coincidence, so it is stated directly here.
    ///
    /// # What a correct implementation would have to do
    ///
    /// Beyond building the receive-side installer and retaining the PSK for the
    /// originator, the send **must not** be keyed on a global literal namespace
    /// string. Identity private state is addressed by the per-identity routing
    /// id
    /// <code>[derive_private_state_routing_id](scp_protocol::identity::private_state::derive_private_state_routing_id)(identity_key_material, did)</code>
    /// (§3.7, H12) — an HKDF output that is unlinkable to the DID without the
    /// identity key material. A single global namespace shared by every
    /// identity is exactly what makes the collision above possible, and it
    /// would also hand relays the correlation the routing-id derivation exists
    /// to deny. The wrap format itself is specified in §3.7.2 (RFC 9180 HPKE
    /// Base, `info = "scp-private-state-v1" || BE32(len(did)) || did ||
    /// "psk-rotate"`, wire `enc(32) || ct(48)`); the deleted helper is not
    /// preserved here because an unused send-side wrapper makes an absent
    /// capability look present.
    ///
    /// # Errors
    ///
    /// Always returns a step-6 [`RecoveryStepError`] coded
    /// [`RecoveryStepErrorCode::PskDistributionUnwired`].
    async fn rotate_psk(&self, params: &PskRotationParams) -> Result<(), RecoveryStepError> {
        // FAIL CLOSED (#2240 Part B): no receive-side installer exists, so a
        // delivered wrap would install nothing, and the originator never
        // retained the PSK either. Report the absence explicitly rather than
        // relying on the 64-hex id-shape rejection that made the old
        // notification-only body fail by accident.
        Err(RecoveryStepError {
            step: 6,
            code: RecoveryStepErrorCode::PskDistributionUnwired,
            description: format!(
                "PSK rotation is not wired for identity `{did}` — no receive-side installer \
                 exists, so identity private state (§3.7) was NOT re-encrypted and a compromised \
                 enrolled device retains access to it. Failing closed rather than reporting a \
                 rotation that did not happen (#2240 Part B)",
                did = params.did,
            ),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> DID {
        DID::from(s)
    }

    /// Returns a deterministic test signing key for `ProductionRecoveryBackend`.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    // -----------------------------------------------------------------------
    // Mock backend for testing
    // -----------------------------------------------------------------------

    /// Converts a mock's boolean success knob into the tri-state step result
    /// the trait now returns. Keeps the knobs readable while the production
    /// contract stays `Result`.
    fn step_result(step: u8, ok: bool) -> Result<(), RecoveryStepError> {
        if ok {
            Ok(())
        } else {
            Err(RecoveryStepError {
                step,
                code: RecoveryStepErrorCode::Unspecified,
                description: format!("mock backend configured to fail step {step}"),
            })
        }
    }

    /// A mock `RecoveryBackend` that succeeds for all operations by default.
    /// Individual steps can be configured to fail.
    struct MockRecoveryBackend {
        /// If set, `mls_update` returns this error for the matching context.
        mls_update_error: Option<(String, RecoveryStepError)>,
        /// If set, `revoke_ucans` returns this error for the matching context.
        revoke_ucans_error: Option<(String, RecoveryStepError)>,
        /// If set, `rotate_key_packages` returns this error. Not keyed by
        /// context: step 4 is identity-scoped and runs once per recovery.
        rotate_key_packages_error: Option<RecoveryStepError>,
        /// Whether `notify_contacts` reaches anybody at all. `false` makes it
        /// return the step-5 error.
        notify_contacts_result: bool,
        /// Contacts `notify_contacts` reports as NOT reached. Only meaningful
        /// when `notify_contacts_result` is `true`; models partial delivery.
        notify_contacts_unreachable: HashSet<DID>,
        /// Whether `rotate_psk` succeeds.
        rotate_psk_result: bool,
    }

    impl MockRecoveryBackend {
        fn new() -> Self {
            Self {
                mls_update_error: None,
                revoke_ucans_error: None,
                rotate_key_packages_error: None,
                notify_contacts_result: true,
                notify_contacts_unreachable: HashSet::new(),
                rotate_psk_result: true,
            }
        }
    }

    #[async_trait(?Send)]
    impl RecoveryBackend for MockRecoveryBackend {
        async fn mls_update(
            &self,
            context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            if let Some((ref ctx, ref err)) = self.mls_update_error
                && ctx == context_id
            {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn revoke_ucans(
            &self,
            context_id: &str,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            if let Some((ref ctx, ref err)) = self.revoke_ucans_error
                && ctx == context_id
            {
                return Err(err.clone());
            }
            Ok(())
        }

        async fn rotate_key_packages(
            &self,
            _key_rotation: &KeyRotationOutcome,
        ) -> Result<(), RecoveryStepError> {
            self.rotate_key_packages_error
                .as_ref()
                .map_or(Ok(()), |err| Err(err.clone()))
        }

        async fn notify_contacts(
            &self,
            _did: &DID,
            _tier: CompromiseTier,
            _key_rotation: &KeyRotationOutcome,
            contacts: &HashSet<DID>,
        ) -> Result<ContactsReached, RecoveryStepError> {
            step_result(5, self.notify_contacts_result)?;
            Ok(ContactsReached {
                dids: contacts
                    .iter()
                    .filter(|contact| !self.notify_contacts_unreachable.contains(*contact))
                    .cloned()
                    .collect(),
            })
        }

        async fn rotate_psk(&self, _params: &PskRotationParams) -> Result<(), RecoveryStepError> {
            step_result(6, self.rotate_psk_result)
        }
    }

    // -----------------------------------------------------------------------
    // CompromiseTier tests
    // -----------------------------------------------------------------------

    #[test]
    fn compromise_tier_serialization_roundtrip() {
        for tier in [
            CompromiseTier::Agent,
            CompromiseTier::ActiveSigning,
            CompromiseTier::IdentityKey,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: CompromiseTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    #[test]
    fn compromise_tier_msgpack_roundtrip() {
        for tier in [
            CompromiseTier::Agent,
            CompromiseTier::ActiveSigning,
            CompromiseTier::IdentityKey,
        ] {
            let bytes = rmp_serde::to_vec(&tier).unwrap();
            let parsed: CompromiseTier = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // KeyRotationOutcome helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn agent_key_rotation_outcome_does_not_change_did() {
        let outcome = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        assert_eq!(outcome.tier, CompromiseTier::Agent);
        assert_eq!(outcome.did_after, did("did:dht:alice"));
        assert!(!outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#agent"]);
    }

    #[test]
    fn active_key_rotation_outcome_does_not_change_did() {
        let outcome = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        assert_eq!(outcome.tier, CompromiseTier::ActiveSigning);
        assert_eq!(outcome.did_after, did("did:dht:alice"));
        assert!(!outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#active"]);
    }

    #[test]
    fn identity_key_rotation_outcome_changes_did() {
        let outcome =
            identity_key_rotation_outcome(&did("did:dht:alice"), did("did:dht:alice-new"), 3000);
        assert_eq!(outcome.tier, CompromiseTier::IdentityKey);
        assert_eq!(outcome.did_after, did("did:dht:alice-new"));
        assert!(outcome.did_changed);
        assert_eq!(outcome.rotated_key_scopes, vec!["#active", "#agent"]);
    }

    // -----------------------------------------------------------------------
    // ContextRecoveryState tests
    // -----------------------------------------------------------------------

    #[test]
    fn context_recovery_state_not_complete_initially() {
        let state = ContextRecoveryState::new("ctx-1".to_owned());
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_complete_when_all_steps_done() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(state.is_complete());
    }

    #[test]
    fn context_recovery_state_complete_with_rejoin() {
        // A context requiring rejoin is considered complete if
        // UCAN revocation and KeyPackage rotation succeeded.
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: false,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: true,
            error: None,
        };
        assert!(state.is_complete());
    }

    #[test]
    fn context_recovery_state_not_complete_with_error() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: Some(RecoveryStepError {
                step: 3,
                code: RecoveryStepErrorCode::UcanRevocationUnwired,
                description: "UCAN revocation failed".to_owned(),
            }),
        };
        assert!(!state.is_complete());
    }

    // -----------------------------------------------------------------------
    // ContactNotification tests
    // -----------------------------------------------------------------------

    #[test]
    fn contact_notification_serialization_roundtrip() {
        let notif = ContactNotification {
            did: did("did:dht:alice"),
            new_did: Some(did("did:dht:alice-new")),
            tier: CompromiseTier::IdentityKey,
            timestamp: 1_700_000_000_000,
            kcv_reverification_required: true,
        };

        let json = serde_json::to_string(&notif).unwrap();
        let parsed: ContactNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, notif);
    }

    #[test]
    fn contact_notification_without_new_did() {
        let notif = ContactNotification {
            did: did("did:dht:alice"),
            new_did: None,
            tier: CompromiseTier::Agent,
            timestamp: 1_700_000_000_000,
            kcv_reverification_required: true,
        };

        let json = serde_json::to_string(&notif).unwrap();
        let parsed: ContactNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, notif);
        assert!(parsed.new_did.is_none());
    }

    // -----------------------------------------------------------------------
    // RecoveryStepError tests
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_step_error_display() {
        let err = RecoveryStepError {
            step: 2,
            code: RecoveryStepErrorCode::Unspecified,
            description: "MLS Update failed".to_owned(),
        };
        assert_eq!(err.to_string(), "step 2: MLS Update failed");
    }

    #[test]
    fn recovery_step_error_serialization_roundtrip() {
        let err = RecoveryStepError {
            step: 4,
            code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
            description: "KeyPackage deletion failed".to_owned(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: RecoveryStepError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    // -----------------------------------------------------------------------
    // CompromiseRecoveryOrchestrator — execute_recovery tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn agent_key_recovery_all_contexts_succeed() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
        );

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::Agent);
        assert_eq!(result.did, did("did:dht:alice"));
        assert!(result.new_did.is_none());
        assert_eq!(result.completed_contexts.len(), 2);
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
        assert!(result.key_rotation_completed);
        // Empty contact set and Agent tier: NEITHER step 5 nor step 6 runs, so
        // both report NotApplicable. The old `bool` reported `true` for both
        // here, which read as "cleanup succeeded" when nothing executed.
        assert!(matches!(
            result.contact_notification,
            ContactNotificationOutcome::NotApplicable(_)
        ));
        assert!(matches!(
            result.private_state_reencryption,
            StepOutcome::NotApplicable(_)
        ));
        assert!(result.completed_at >= result.initiated_at);
    }

    #[tokio::test]
    async fn active_signing_key_recovery_with_psk_rotation() {
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::ActiveSigning);
        assert_eq!(result.completed_contexts, vec!["ctx-1"]);
        assert!(
            result.contact_notification.fully_delivered(),
            "every contact was reachable in this mock, so step 5 must report \
             full delivery — not merely `reached_any`"
        );
        assert!(result.private_state_reencryption.succeeded());
    }

    #[tokio::test]
    async fn identity_key_recovery_changes_did() {
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation =
            identity_key_rotation_outcome(&did("did:dht:alice"), did("did:dht:alice-new"), 3000);
        let contacts = HashSet::from([did("did:dht:bob")]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::IdentityKey,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert_eq!(result.tier, CompromiseTier::IdentityKey);
        assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
        assert!(result.key_rotation_completed);
        assert!(result.private_state_reencryption.succeeded());
    }

    #[tokio::test]
    async fn recovery_with_no_contexts() {
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(result.completed_contexts.is_empty());
        assert!(result.failed_contexts.is_empty());
        assert!(result.pending_rejoin.is_empty());
        // Zero contexts + a performed rotation is a valid no-context recovery,
        // and the field reflects the performed rotation.
        assert!(result.key_rotation_completed);
    }

    #[tokio::test]
    async fn recovery_partial_failure_stays_ok() {
        // One context succeeds, one fails at step 2. Per-context isolation keeps
        // this an `Ok` partial success with the failure recorded — NOT a
        // fail-closed error (that is reserved for a *total* failure). #2240.
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-ok".to_owned(), "ctx-fail".to_owned()],
        );
        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend {
            mls_update_error: Some((
                "ctx-fail".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::Unspecified,
                    description: "MLS group unavailable".to_owned(),
                },
            )),
            ..MockRecoveryBackend::new()
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect("partial failure must remain Ok");

        assert_eq!(result.completed_contexts, vec!["ctx-ok"]);
        assert_eq!(result.failed_contexts.len(), 1);
        assert_eq!(result.failed_contexts[0].0, "ctx-fail");
        assert!(result.pending_rejoin.is_empty());
        assert!(result.key_rotation_completed);
    }

    #[tokio::test]
    async fn recovery_fails_closed_when_all_contexts_fail() {
        // The backend rejects the (only) context's step-2 MLS update, so no
        // context recovers. The orchestrator must fail closed with
        // `AllContextsFailed` rather than return an all-failed `RecoveryResult`
        // that could be observed as success (#2240).
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend {
            mls_update_error: Some((
                "ctx-1".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::Unspecified,
                    description: "MLS group unavailable".to_owned(),
                },
            )),
            ..MockRecoveryBackend::new()
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("total per-context failure must fail closed");

        assert!(
            matches!(&err, RecoveryError::AllContextsFailed { attempted, .. } if *attempted == 1),
            "expected AllContextsFailed {{ attempted: 1 }}, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn recovery_fails_closed_when_rotation_not_performed() {
        // `key_rotation: None` means step 1 never ran; recovery must fail closed
        // with `KeyRotationFailed` before touching any context, and never
        // fabricate a `RecoveryResult` claiming a completed rotation.
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                None,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("key_rotation: None must fail closed");

        assert!(
            matches!(
                &err,
                RecoveryError::KeyRotationFailed(msg) if msg.contains("no KeyRotationOutcome supplied")
            ),
            "expected KeyRotationFailed mentioning the no-rotation reason, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn recovery_fails_closed_zero_contexts_no_rotation() {
        // Zero contexts with a *performed* rotation is a valid no-context Ok
        // (see `recovery_with_no_contexts`); but a rotation that did not occur
        // still fails closed even with no contexts to recover.
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                None,
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("zero contexts + no rotation must fail closed");

        assert!(matches!(err, RecoveryError::KeyRotationFailed(_)));
    }

    #[tokio::test]
    async fn recovery_without_psk_params_for_active_tier() {
        // ActiveSigning without PSK params → private_state_reencrypted is false.
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        // Without PSK params, re-encryption didn't happen.
        assert!(!result.private_state_reencryption.succeeded());
    }

    #[tokio::test]
    async fn psk_rotation_excludes_compromised_device() {
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        // Device 2 is compromised.
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(result.private_state_reencryption.succeeded());
    }

    #[tokio::test]
    async fn psk_rotation_fails_with_no_remaining_devices() {
        // All devices compromised → PSK rotation fails.
        let orch = CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec![]);

        let key_rotation = active_key_rotation_outcome(&did("did:dht:alice"), 2000);
        let contacts = HashSet::new();

        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: Some(vec![1u8; 32]),
        };

        // Backend reports PSK rotation failure (no remaining devices).
        let backend = MockRecoveryBackend {
            rotate_psk_result: false,
            ..MockRecoveryBackend::new()
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        assert!(!result.private_state_reencryption.succeeded());
    }

    #[tokio::test]
    async fn recovery_result_serialization_roundtrip() {
        let orch =
            CompromiseRecoveryOrchestrator::new(did("did:dht:alice"), vec!["ctx-1".to_owned()]);

        let key_rotation = agent_key_rotation_outcome(&did("did:dht:alice"), 1000);
        let contacts = HashSet::new();
        let backend = MockRecoveryBackend::new();

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .unwrap();

        let json = serde_json::to_string(&result).unwrap();
        let parsed: RecoveryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tier, result.tier);
        assert_eq!(parsed.did, result.did);
        assert_eq!(parsed.completed_contexts, result.completed_contexts);
    }

    // -----------------------------------------------------------------------
    // RecoveryResult field tests
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_result_msgpack_roundtrip() {
        let result = RecoveryResult {
            tier: CompromiseTier::ActiveSigning,
            did: did("did:dht:alice"),
            new_did: None,
            completed_contexts: vec!["ctx-1".to_owned()],
            failed_contexts: vec![(
                "ctx-2".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::Unspecified,
                    description: "MLS update failed".to_owned(),
                },
            )],
            pending_rejoin: vec!["ctx-3".to_owned()],
            key_rotation_completed: true,
            contact_notification: ContactNotificationOutcome::Delivered {
                reached: vec![did("did:dht:bob")],
                unreachable: vec![did("did:dht:carol")],
            },
            private_state_reencryption: StepOutcome::Succeeded,
            initiated_at: 1000,
            completed_at: 2000,
        };

        let bytes = rmp_serde::to_vec(&result).unwrap();
        let parsed: RecoveryResult = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(parsed.tier, CompromiseTier::ActiveSigning);
        assert_eq!(parsed.completed_contexts, vec!["ctx-1"]);
        assert_eq!(parsed.failed_contexts.len(), 1);
        assert_eq!(parsed.pending_rejoin, vec!["ctx-3"]);
    }

    // -----------------------------------------------------------------------
    // Orchestrator accessors
    // -----------------------------------------------------------------------

    #[test]
    fn orchestrator_accessors() {
        let orch = CompromiseRecoveryOrchestrator::new(
            did("did:dht:alice"),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
        );
        assert_eq!(*orch.did(), did("did:dht:alice"));
        assert_eq!(orch.context_ids().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Three recovery tiers — end-to-end test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn three_tiers_end_to_end() {
        let contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned(), "ctx-3".to_owned()];
        let alice = did("did:dht:alice");
        let contacts = HashSet::from([did("did:dht:bob"), did("did:dht:carol")]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };
        let backend = MockRecoveryBackend::new();

        // Tier 1: Agent key compromise (cheapest).
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = agent_key_rotation_outcome(&alice, 1000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::Agent,
                    Some(&kr),
                    &contacts,
                    None,
                    &backend,
                    &scp_clock::SystemClock,
                )
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::Agent);
            assert!(result.new_did.is_none()); // No DID change.
            assert_eq!(result.completed_contexts.len(), 3);
            // Agent tier: the PSK is unaffected, so step 6 genuinely does NOT
            // run — NotApplicable, never "succeeded".
            assert!(matches!(
                result.private_state_reencryption,
                StepOutcome::NotApplicable(_)
            ));
        }

        // Tier 2: Active signing key compromise.
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = active_key_rotation_outcome(&alice, 2000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::ActiveSigning,
                    Some(&kr),
                    &contacts,
                    Some(&psk_params),
                    &backend,
                    &scp_clock::SystemClock,
                )
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::ActiveSigning);
            assert!(result.new_did.is_none()); // No DID change.
            assert!(result.private_state_reencryption.succeeded());
        }

        // Tier 3: Identity key compromise (most severe).
        {
            let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
            let kr = identity_key_rotation_outcome(&alice, did("did:dht:alice-new"), 3000);
            let result = orch
                .execute_recovery(
                    CompromiseTier::IdentityKey,
                    Some(&kr),
                    &contacts,
                    Some(&psk_params),
                    &backend,
                    &scp_clock::SystemClock,
                )
                .await
                .unwrap();

            assert_eq!(result.tier, CompromiseTier::IdentityKey);
            assert_eq!(result.new_did, Some(did("did:dht:alice-new")));
            assert!(result.private_state_reencryption.succeeded());
        }
    }

    // -----------------------------------------------------------------------
    // Step ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn context_recovery_state_requires_mls_before_complete() {
        // Without MLS update AND without rejoin flag, not complete.
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: false,
            ucan_revoked: true,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_requires_ucan_revocation() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: false,
            key_packages_rotated: true,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    #[test]
    fn context_recovery_state_requires_key_package_rotation() {
        let state = ContextRecoveryState {
            context_id: "ctx-1".to_owned(),
            mls_updated: true,
            ucan_revoked: true,
            key_packages_rotated: false,
            requires_rejoin: false,
            error: None,
        };
        assert!(!state.is_complete());
    }

    // -----------------------------------------------------------------------
    // PskRotationParams tests
    // -----------------------------------------------------------------------

    #[test]
    fn psk_rotation_params_serialization_roundtrip() {
        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: Some(vec![2u8; 32]),
        };
        let json = serde_json::to_string(&params).unwrap();
        let parsed: PskRotationParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.enrolled_device_pubkeys.len(), 2);
        assert!(parsed.compromised_device_pubkey.is_some());
    }

    // -----------------------------------------------------------------------
    // ProductionRecoveryBackend tests
    // -----------------------------------------------------------------------

    /// Helper to create a minimal `ContextManager` for testing.
    ///
    /// After ADR-049 §15, the `ContextCryptoProvider` trait is
    /// deleted and tests bind to a real
    /// [`NodeMlsFactory`](crate::crypto::mls::provider::NodeMlsFactory)
    /// — fail-injection and stub-seal overrides move to
    /// backend-injection in ADR-049 §15.
    fn test_context_manager() -> Arc<crate::context::supervisor::Supervisor> {
        use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
        use scp_protocol::context::builder::ContextCreationError;
        use scp_protocol::context::{ContextError, ContextParams};

        const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        struct TestTransport;
        #[async_trait::async_trait]
        impl ContextTransportProvider for TestTransport {
            fn is_connected(&self) -> bool {
                true
            }
            async fn publish_context(
                &self,
                _: &[u8; 32],
                _: &ContextParams,
            ) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn send_message(&self, _: &[u8; 32], _: &[u8]) -> Result<(), ContextError> {
                Ok(())
            }
        }

        struct TestEventLog;
        #[async_trait::async_trait]
        impl ContextEventLogProvider for TestEventLog {
            async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn append_event(
                &self,
                _: &[u8; 32],
                _: scp_event_log::EventType,
                _actor_did: &str,
                _payload: scp_event_log::EventPayload,
                _timestamp_secs: u64,
            ) -> Result<(), ContextCreationError> {
                Ok(())
            }
            async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
                Ok(())
            }
            fn event_log_entries(
                &self,
                _: &[u8; 32],
            ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
                Ok(None)
            }
        }

        // ADR-049 §15: `ContextManager` is gone. Build the
        // `Supervisor` directly via `test_supervisor`.
        crate::context::test_supervisor(
            Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
                TEST_DID.to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            )),
            Box::new(TestTransport),
            Box::new(TestEventLog),
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None),
        )
    }

    /// Helper to create a context in the manager for testing.
    async fn setup_context(
        manager: &Arc<crate::context::supervisor::Supervisor>,
        context_id: &str,
        creator_did: &DID,
    ) {
        setup_context_with_members(manager, context_id, creator_did, &[]).await;
    }

    /// Helper to create a context with the creator and additional members.
    async fn setup_context_with_members(
        manager: &Arc<crate::context::supervisor::Supervisor>,
        context_id: &str,
        creator_did: &DID,
        additional_members: &[&DID],
    ) {
        use scp_protocol::context::ContextParams;
        use scp_protocol::context::membership::KeyPackage;
        use scp_protocol::context::params::{ContextMode, GovernanceModel};
        use scp_protocol::context::roles::Capability;

        let params = ContextParams {
            mode: ContextMode::Encrypted,
            governance: GovernanceModel::SingleAdmin,
            // Include role:assign capability so the admin can add members.
            ceiling: vec![
                Capability::new("messages:read").expect("known capability"),
                Capability::new("messages:write").expect("known capability"),
                Capability::new("role:assign").expect("known capability"),
            ],
            ..ContextParams::default()
        };

        // Create the context. This registers it in the manager.
        let handle = manager
            .create_context(context_id.to_owned(), params, creator_did.clone(), None)
            .await
            .expect("failed to create test context");

        // Add additional members via join_context.
        for member_did in additional_members {
            let kp = KeyPackage::mock((*member_did).clone());
            manager
                .join_context(&handle, kp, None, None)
                .await
                .expect("failed to join test member");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_mls_update_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let context_id = "ctx-prod-1";

        setup_context(&manager, context_id, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend.mls_update(context_id, &key_rotation).await;
        assert!(result.is_ok(), "mls_update should succeed: {result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_mls_update_unknown_context_fails() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let alice = did("did:dht:alice");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = backend
            .mls_update("nonexistent-context", &key_rotation)
            .await;
        assert!(result.is_err(), "mls_update on unknown context should fail");
        assert_eq!(result.unwrap_err().step, 2);
    }

    /// #2069: step 3 has no live write path into the revocation enforcement
    /// set, so the production backend MUST fail closed — even for a fully
    /// healthy, registered context where the old marker-string implementation
    /// happily returned `Ok(())`. This is the regression guard against the
    /// nullifier coming back.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_revoke_ucans_fails_closed() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let context_id = "ctx-prod-2";

        // A healthy, registered context: nothing about the *environment* is
        // making this fail — the capability is genuinely absent.
        setup_context(&manager, context_id, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let err = backend
            .revoke_ucans(context_id, &key_rotation)
            .await
            .expect_err("revoke_ucans must fail closed until #2069 is wired");

        // Assert on STRUCTURE, not prose. The description explains *why* to a
        // human and must stay free to be corrected; pinning its wording would
        // make this test block the corrections it should be permitting.
        assert_eq!(err.step, 3, "must be attributed to §9.12 step 3");
        assert_eq!(
            err.code,
            RecoveryStepErrorCode::UcanRevocationUnwired,
            "must be classified as an unwired capability, not a transient \
             dispatch failure — a caller retrying is futile"
        );
        assert!(
            !err.description.is_empty(),
            "an operator-facing explanation must be present"
        );
    }

    /// The step-3 failure is *capability absence*, not a dispatch failure:
    /// modulo the echoed context id the description is identical for a
    /// registered and a never-created context. A mapped dispatch failure would
    /// carry the `dispatch_step_error` shape (a `ContextError` string) and
    /// would differ between the two, so this pins that the error is a constant
    /// of the inputs rather than a consequence of talking to the mailbox.
    ///
    /// **What this does NOT prove:** that no notification was emitted. A
    /// regression that dispatched, discarded the result and returned the same
    /// constant error would still pass. A dispatch is not externally observable
    /// here (on a supervisor with no matching actor it fails and the error would
    /// be swallowed), and the sound guarantee is structural rather than
    /// behavioural: the method body is a single `Err(..)` expression with no
    /// `.await`, so it cannot reach the mailbox. A source-text scanner asserting
    /// that would be a self-matching denylist over this very file — the
    /// non-convergent shape `CLAUDE.md` warns against — so it is deliberately
    /// not added. Read the body.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_revoke_ucans_fails_closed_without_dispatching() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let registered = "ctx-prod-2b";

        setup_context(&manager, registered, &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let registered_err = backend
            .revoke_ucans(registered, &key_rotation)
            .await
            .expect_err("revoke_ucans must fail closed");
        let unknown_err = backend
            .revoke_ucans("ctx-never-created", &key_rotation)
            .await
            .expect_err("revoke_ucans must fail closed");

        assert_eq!(registered_err.step, 3);
        assert_eq!(unknown_err.step, 3);
        // Same failure mode either way, modulo the echoed context id.
        assert!(registered_err.description.contains(registered));
        assert!(unknown_err.description.contains("ctx-never-created"));
        assert_eq!(
            registered_err.description.replace(registered, "<ctx>"),
            unknown_err
                .description
                .replace("ctx-never-created", "<ctx>"),
            "the failure must not depend on mailbox dispatch"
        );
    }

    /// #2240 Part B item 2 / #1083 finding 6: the `KeyPackage`-attestation
    /// lifecycle is unwired end to end, so the production backend MUST fail
    /// closed — even in a fully healthy environment, where the old
    /// notification-only implementation happily returned `Ok(())`. This is the
    /// regression guard against the nullifier coming back.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_key_packages_fails_closed() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");

        // A healthy, registered context: nothing about the *environment* is
        // making this fail — the capability is genuinely absent. (Step 4 is
        // identity-scoped, so the context is only here to prove the
        // environment is not the cause.)
        setup_context(&manager, "ctx-prod-3", &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let err = backend
            .rotate_key_packages(&key_rotation)
            .await
            .expect_err("rotate_key_packages must fail closed until the lifecycle is wired");

        // Assert on STRUCTURE, not prose. Two successive corrections to this
        // message were blocked by substring assertions pinning the *previous*,
        // wrong explanation — the tests were enforcing the bug. The stable
        // contract is (step, code); the description is an operator-facing
        // explanation that must stay free to be corrected.
        assert_eq!(err.step, 4, "must be attributed to §9.12 step 4");
        assert_eq!(
            err.code,
            RecoveryStepErrorCode::KeyPackageRotationUnwired,
            "must be classified as an unwired capability, not a transient \
             dispatch failure — a caller retrying is futile"
        );
        assert!(
            !err.description.is_empty(),
            "an operator-facing explanation must be present"
        );
        // The compromised (pre-migration) identity is a machine-checkable part
        // of the contract, not prose: naming the wrong DID actively misdirects
        // remediation, so it stays pinned.
        assert!(
            err.description.contains(alice.as_ref()),
            "error must name the compromised identity: {}",
            err.description
        );
    }

    /// The step-4 failure is *capability absence*, not a dispatch failure.
    ///
    /// Step 4 is identity-scoped, so there is no context to vary; instead this
    /// pins that the error is a constant of the `KeyRotationOutcome` alone —
    /// byte-identical across an empty supervisor and a populated one. A mapped
    /// dispatch failure would carry the `dispatch_step_error` shape (a
    /// `ContextError` string) and would differ between the two.
    ///
    /// **What this does NOT prove:** that no notification was emitted — see
    /// [`production_backend_revoke_ucans_fails_closed_without_dispatching`] for
    /// why that guarantee is structural (a single `Err(..)` body with no
    /// `.await`) rather than test-observable.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_key_packages_fails_closed_without_dispatching() {
        let alice = did("did:dht:alice");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        // An empty supervisor: no contexts, no actors, nothing to dispatch to.
        let empty_backend =
            ProductionRecoveryBackend::new(test_context_manager(), test_signing_key());
        let empty_err = empty_backend
            .rotate_key_packages(&key_rotation)
            .await
            .expect_err("rotate_key_packages must fail closed");

        // A populated supervisor with a live, registered context.
        let manager = test_context_manager();
        setup_context(&manager, "ctx-prod-3b", &alice).await;
        let populated_backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let populated_err = populated_backend
            .rotate_key_packages(&key_rotation)
            .await
            .expect_err("rotate_key_packages must fail closed");

        assert_eq!(empty_err.step, 4);
        assert_eq!(populated_err.step, 4);
        assert_eq!(
            empty_err, populated_err,
            "step 4 must not depend on supervisor state — it never consults it"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_notify_contacts_succeeds() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");

        // Set up a shared context where alice, bob, and carol are all members.
        // recovery_notify_contact searches for shared contexts between the
        // recovering DID and each contact.
        setup_context_with_members(&manager, "ctx-shared", &alice, &[&bob, &carol]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::from([bob, carol]);

        let result = backend
            .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
            .await;
        assert!(result.is_ok(), "notify_contacts should succeed: {result:?}");
    }

    /// An empty contact set is the orchestrator's business, not the backend's:
    /// the orchestrator reports [`StepOutcome::NotApplicable`] *without calling*
    /// the backend. The backend therefore treats "reached nobody" as a step-5
    /// failure rather than vacuous success — exactly the conflation the
    /// tri-state [`StepOutcome`] removed.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_notify_contacts_empty_set_is_not_vacuous_success() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let alice = did("did:dht:alice");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::new();

        let err = backend
            .notify_contacts(&alice, CompromiseTier::Agent, &key_rotation, &contacts)
            .await
            .expect_err("reaching zero contacts is not success at the backend level");
        assert_eq!(err.step, 5);
    }

    /// The orchestrator-level complement: with no contacts, step 5 reports
    /// `NotApplicable` — NOT success — and the `Agent` tier reports the same for
    /// step 6. Before the tri-state, this exact scenario reported
    /// `contacts_notified: true, private_state_reencrypted: true` while
    /// **neither step ran**.
    #[tokio::test]
    async fn orchestrator_reports_steps_5_and_6_not_applicable_rather_than_success() {
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &MockRecoveryBackend::new(),
                &scp_clock::SystemClock,
            )
            .await
            .expect("all steps succeed with the default mock");

        assert!(
            matches!(
                result.contact_notification,
                ContactNotificationOutcome::NotApplicable(_)
            ),
            "no contacts must report NotApplicable, got {:?}",
            result.contact_notification
        );
        assert!(
            !result.contact_notification.reached_any()
                && !result.contact_notification.fully_delivered(),
            "NotApplicable must NOT read as success under either predicate"
        );
        assert!(
            matches!(
                result.private_state_reencryption,
                StepOutcome::NotApplicable(_)
            ),
            "agent tier must report step 6 NotApplicable, got {:?}",
            result.private_state_reencryption
        );
        assert!(!result.private_state_reencryption.succeeded());
    }

    /// Runs an `Agent`-tier recovery with the given contacts and mock knobs,
    /// returning step 5's outcome. Step 4 succeeds by default, so this stays on
    /// the `Ok` path and reads the outcome off `RecoveryResult`.
    #[allow(clippy::future_not_send)] // backend trait object is not Sync by design
    async fn step_5_outcome(
        contacts: &HashSet<DID>,
        unreachable: HashSet<DID>,
        reaches_anybody: bool,
    ) -> ContactNotificationOutcome {
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let backend = MockRecoveryBackend {
            notify_contacts_result: reaches_anybody,
            notify_contacts_unreachable: unreachable,
            ..MockRecoveryBackend::new()
        };

        orch.execute_recovery(
            CompromiseTier::Agent,
            Some(&key_rotation),
            contacts,
            None,
            &backend,
            &scp_clock::SystemClock,
        )
        .await
        .expect("steps 2-4 succeed with the mock")
        .contact_notification
    }

    /// `is_ok()` is not completion: every one of these `Ok` recoveries left
    /// real §9.12 work undone, and `fully_recovered()` is what says so.
    #[tokio::test]
    async fn fully_recovered_is_false_for_every_incomplete_ok_recovery() {
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contexts = vec!["ctx-1".to_owned(), "ctx-2".to_owned()];
        let contacts = HashSet::from([bob.clone()]);

        // Baseline: nothing left undone.
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), contexts.clone());
        let clean = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &MockRecoveryBackend::new(),
                &scp_clock::SystemClock,
            )
            .await
            .expect("the default mock completes every step");
        assert!(clean.fully_recovered());

        // A per-context step-2 failure. One context still completed, so this
        // stays on the `Ok` path.
        let partial = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &MockRecoveryBackend {
                    mls_update_error: Some((
                        "ctx-2".to_owned(),
                        RecoveryStepError {
                            step: 2,
                            code: RecoveryStepErrorCode::Unspecified,
                            description: "MLS update failed".to_owned(),
                        },
                    )),
                    ..MockRecoveryBackend::new()
                },
                &scp_clock::SystemClock,
            )
            .await
            .expect("one context completed, so this is not a total failure");
        // The `expect` above already proves `is_ok()` — which is the point.
        assert_eq!(partial.completed_contexts, vec!["ctx-1"]);
        assert!(
            !partial.fully_recovered(),
            "a failed context is not full recovery"
        );

        // A contact that was never told to re-run §9.11 KCV — step 5 reports
        // best-effort success, and that is precisely the case `is_ok()` hides.
        let unreached = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &MockRecoveryBackend {
                    notify_contacts_unreachable: HashSet::from([bob]),
                    ..MockRecoveryBackend::new()
                },
                &scp_clock::SystemClock,
            )
            .await
            .expect("step 5 is non-fatal");
        assert!(
            !unreached.fully_recovered(),
            "an unreachable contact is not full recovery"
        );

        // A failed step 6 — non-fatal, but the PSK was not rotated.
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };
        let psk_failed = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&active_key_rotation_outcome(&alice, 1000)),
                &contacts,
                Some(&psk_params),
                &MockRecoveryBackend {
                    rotate_psk_result: false,
                    ..MockRecoveryBackend::new()
                },
                &scp_clock::SystemClock,
            )
            .await
            .expect("step 6 is non-fatal");
        assert!(
            !psk_failed.fully_recovered(),
            "a failed PSK rotation is not full recovery"
        );
    }

    /// `NotApplicable` steps do NOT make a recovery incomplete: the `Agent`
    /// tier genuinely does not touch the PSK, and an identity with no contacts
    /// has nobody to notify. This is why `fully_recovered()` tests
    /// "did not fail" for steps 5 and 6 rather than "succeeded".
    #[tokio::test]
    async fn fully_recovered_treats_not_applicable_steps_as_complete() {
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &MockRecoveryBackend::new(),
                &scp_clock::SystemClock,
            )
            .await
            .expect("the default mock completes every applicable step");

        assert!(!result.contact_notification.reached_any());
        assert!(!result.private_state_reencryption.succeeded());
        assert!(
            result.fully_recovered(),
            "steps that did not apply must not count against completion"
        );
    }

    /// THE FINDING: with 3 contacts and 1 reachable, "step 5 succeeded" told an
    /// operator nothing about the 2 who still hold a §9.11 KCV binding to the
    /// compromised key — precisely the impersonation window recovery exists to
    /// close. §9.12's best-effort rule governs whether recovery *blocks*, not
    /// whether the caller is *told*.
    #[tokio::test]
    async fn step_5_partial_delivery_names_the_unreachable_contacts() {
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");
        let dave = did("did:dht:dave");
        let contacts = HashSet::from([bob.clone(), carol.clone(), dave.clone()]);

        let outcome = step_5_outcome(
            &contacts,
            HashSet::from([carol.clone(), dave.clone()]),
            true,
        )
        .await;

        // Best-effort success — recovery is NOT blocked...
        assert!(outcome.reached_any(), "reaching one contact is still `Ok`");
        // ...but it is NOT full delivery, and the gap is enumerable.
        assert!(
            !outcome.fully_delivered(),
            "2 of 3 contacts were never told to re-verify"
        );
        assert_eq!(outcome.reached(), &[bob]);
        // Sorted, so the report is stable across runs even though the contact
        // set is a `HashSet`.
        assert_eq!(outcome.unreachable(), &[carol, dave]);

        // The operator-facing rendering must not read as unqualified success.
        let rendered = outcome.to_string();
        assert!(
            rendered.contains("2 were NOT told"),
            "the Display must surface the gap: {rendered}"
        );
    }

    /// A backend that reaches nobody reports every contact unreachable — the
    /// orchestrator supplies the set, so the report cannot be empty just
    /// because the failing backend had nothing to say.
    #[tokio::test]
    async fn step_5_total_failure_reports_every_contact_unreachable() {
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");
        let contacts = HashSet::from([bob.clone(), carol.clone()]);

        let outcome = step_5_outcome(&contacts, HashSet::new(), false).await;

        assert!(outcome.failed());
        assert!(!outcome.reached_any() && !outcome.fully_delivered());
        assert!(outcome.reached().is_empty());
        assert_eq!(outcome.unreachable(), &[bob, carol]);
    }

    /// A backend that returns `Ok` while naming no reached contact is claiming
    /// the same thing as an `Err` — an empty "delivered" must not be
    /// representable in the outcome a caller branches on.
    #[tokio::test]
    async fn step_5_ok_with_no_reached_contact_is_normalised_to_failed() {
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");
        let contacts = HashSet::from([bob.clone(), carol.clone()]);

        // `reaches_anybody: true` → the mock returns `Ok`, but every contact is
        // filtered out of the reached set.
        let outcome = step_5_outcome(&contacts, contacts.clone(), true).await;

        assert!(
            outcome.failed(),
            "an `Ok` naming nobody must normalise to Failed, got {outcome:?}"
        );
        assert_eq!(outcome.unreachable(), &[bob, carol]);
    }

    /// A backend naming a DID that was never a contact cannot inflate the
    /// reached set: the outcome is derived from the caller's contact set.
    #[tokio::test]
    async fn step_5_ignores_reached_dids_that_were_never_contacts() {
        struct LiarBackend;

        #[async_trait(?Send)]
        impl RecoveryBackend for LiarBackend {
            async fn mls_update(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            async fn revoke_ucans(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            async fn rotate_key_packages(
                &self,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
            async fn notify_contacts(
                &self,
                _did: &DID,
                _tier: CompromiseTier,
                _key_rotation: &KeyRotationOutcome,
                _contacts: &HashSet<DID>,
            ) -> Result<ContactsReached, RecoveryStepError> {
                // Names a stranger and omits the real contact.
                Ok(ContactsReached {
                    dids: vec![did("did:dht:stranger")],
                })
            }
            async fn rotate_psk(
                &self,
                _params: &PskRotationParams,
            ) -> Result<(), RecoveryStepError> {
                Ok(())
            }
        }

        let bob = did("did:dht:bob");
        let contacts = HashSet::from([bob.clone()]);
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-1".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let outcome = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &LiarBackend,
                &scp_clock::SystemClock,
            )
            .await
            .expect("steps 2-4 succeed")
            .contact_notification;

        assert!(
            outcome.failed(),
            "the stranger must not count as a reached contact, got {outcome:?}"
        );
        assert_eq!(
            outcome.unreachable(),
            &[bob],
            "the real contact must still be reported unreachable"
        );
    }

    /// #2240 Part B: nothing installs a rotated PSK, so the production backend
    /// MUST fail closed — even with a healthy supervisor and a perfectly valid
    /// device set, where the old notification-only implementation returned
    /// `Ok(())`. This is the regression guard against the nullifier coming
    /// back.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_psk_fails_closed() {
        let manager = test_context_manager();
        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());

        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        let err = backend
            .rotate_psk(&params)
            .await
            .expect_err("rotate_psk must fail closed until an installer exists");

        // Assert on STRUCTURE, not prose (see the step-3 / step-4 guards).
        assert_eq!(err.step, 6, "must be attributed to §9.12 step 6");
        assert_eq!(
            err.code,
            RecoveryStepErrorCode::PskDistributionUnwired,
            "must be classified as an unwired capability, not a transient \
             dispatch failure — a retry re-runs the whole non-idempotent \
             sequence and reaches the same absent installer"
        );
        // The identity is machine-checkable content, not prose: naming the
        // wrong one misdirects remediation.
        assert!(
            err.description.contains(&params.did),
            "error must name the identity whose private state was NOT \
             re-encrypted: {}",
            err.description
        );
    }

    /// The step-6 failure is *capability absence*, not the accidental
    /// consequence of an id-shape rejection.
    ///
    /// The old body only errored because `recovery_send_notification_direct`
    /// rejects non-64-hex context ids, and only reached that path when no actor
    /// was registered for `"identity-private-state"` — a legal id any local
    /// caller could register, which flipped step 6 to `Ok(())`. This pins that
    /// the error is now a constant of the `PskRotationParams` alone:
    /// byte-identical across an empty supervisor and one with a live actor
    /// registered under exactly that id, and unaffected by the device set that
    /// the deleted body branched on.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_rotate_psk_fails_closed_regardless_of_supervisor_state() {
        let params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        // An empty supervisor: no contexts, no actors, nothing to dispatch to.
        let empty_backend =
            ProductionRecoveryBackend::new(test_context_manager(), test_signing_key());
        let empty_err = empty_backend
            .rotate_psk(&params)
            .await
            .expect_err("rotate_psk must fail closed");

        // A supervisor with a LIVE registered actor for the very id the old
        // body sent to — the configuration that used to make step 6 succeed.
        let manager = test_context_manager();
        setup_context(
            &manager,
            "identity-private-state",
            &did("did:dht:zRecoveryIdentityPrivateStateOwner"),
        )
        .await;
        let seeded_backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let seeded_err = seeded_backend
            .rotate_psk(&params)
            .await
            .expect_err("a registered `identity-private-state` actor must NOT make step 6 succeed");

        assert_eq!(
            empty_err, seeded_err,
            "step 6 must not depend on supervisor state — it never consults it"
        );
        assert_eq!(
            empty_err.code,
            RecoveryStepErrorCode::PskDistributionUnwired
        );

        // ...and not on the device set either: the deleted body branched on
        // "no eligible device remains" before doing anything else.
        let all_compromised = PskRotationParams {
            did: params.did.clone(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: Some(vec![1u8; 32]),
        };
        assert_eq!(
            seeded_backend
                .rotate_psk(&all_compromised)
                .await
                .expect_err("rotate_psk must fail closed"),
            empty_err,
            "the failure must not depend on the enrolled-device set"
        );
    }

    /// With steps 3 (#2069) and 4 (#2240 Part B item 2) both failing closed, a
    /// single-context production recovery can no longer complete — and,
    /// critically, it does NOT report success. The orchestrator's
    /// zero-contexts-recovered guard turns the failure into a typed
    /// [`RecoveryError::AllContextsFailed`].
    ///
    /// Before these fixes the same call returned `Ok` with
    /// `completed_contexts == ["ctx-full-recovery"]` while nothing had been
    /// revoked and no `KeyPackage` had been rotated.
    ///
    /// Step 3 is the first gate the orchestrator hits, so step 4 is not
    /// reachable through `execute_recovery`; it is pinned directly on the
    /// backend below so this test cannot pass for the wrong reason.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_agent_tier_fails_closed_on_steps_3_and_4() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let context_id = "ctx-full-recovery";

        // Set up a context with alice and bob as members so contact
        // notification can find a shared context.
        setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::from([bob]);

        // Step 2 (MLS epoch advance) genuinely succeeds for this context, so
        // the total failure is attributable to the unwired steps, not to a
        // broken environment.
        assert!(
            backend.mls_update(context_id, &key_rotation).await.is_ok(),
            "step 2 must still succeed"
        );
        // Step 3 is what `execute_recovery` trips on first...
        assert_eq!(
            backend
                .revoke_ucans(context_id, &key_rotation)
                .await
                .expect_err("step 3 must fail closed")
                .step,
            3
        );
        // ...and step 4 would fail closed too, so the orchestrator's verdict is
        // not hiding a step-4 success that never happens.
        assert_eq!(
            backend
                .rotate_key_packages(&key_rotation)
                .await
                .expect_err("step 4 must fail closed")
                .step,
            4
        );

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("recovery must fail closed while step 3 is unwired");

        // With the shipped backend BOTH step 3 and step 4 fail. Step 4 is
        // identity-scoped and gates completion for every context, so it is the
        // reported failure (§9.12 "Step scope").
        let RecoveryError::KeyPackageRotationFailed {
            ref step_error,
            ref progress,
        } = err
        else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        assert_eq!(step_error.step, 4);
        let failed_contexts = &progress.failed_contexts;

        // The honest per-step reason must be reachable THROUGH the orchestrator
        // — not only by calling the backend directly. Before the error carried
        // `failed_contexts`, an operator saw just "zero contexts recovered",
        // indistinguishable from a transport outage.
        assert_eq!(failed_contexts.len(), 1);
        assert_eq!(failed_contexts[0].0, context_id);
        assert_eq!(failed_contexts[0].1.step, 3);
        // The Display must surface the per-step reason at all — the point of
        // carrying `failed_contexts` on the error. Asserted by presence of the
        // step-3 description, not by its wording.
        let rendered = err.to_string();
        assert!(
            rendered.contains(&failed_contexts[0].1.description),
            "the fail-closed Display must surface the honest step reason: {rendered}"
        );

        // Identity-scoped steps ran and are reported even on the fail-closed
        // path: step 4 failed closed, step 5 reached bob.
        assert!(
            !progress.key_package_rotation.succeeded(),
            "step 4 is unwired"
        );
        assert!(
            progress.contact_notification.fully_delivered(),
            "step 5 must still run when every context fails — a stale contact \
             that never learns to re-run §9.11 KCV is the harm this prevents"
        );
        assert_eq!(
            progress.contact_notification.reached(),
            &[did("did:dht:bob")],
            "the reached contact must be named, not just counted"
        );
    }

    /// `ActiveSigning` tier: same fail-closed contract on steps 3 (#2069), 4
    /// (#2240 Part B item 2) and 6 (#2240 Part B). The tier plumbing (PSK
    /// params) is still exercised up to the point recovery fails closed.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_active_signing_tier_fails_closed_on_steps_3_4_and_6()
    {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let context_id = "ctx-active-recovery";

        // Set up a context with alice and bob as members so contact
        // notification can find a shared context.
        setup_context_with_members(&manager, context_id, &alice, &[&bob]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = active_key_rotation_outcome(&alice, 2000);
        let contacts = HashSet::from([bob]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32], vec![2u8; 32]],
            compromised_device_pubkey: None,
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("recovery must fail closed while steps 3 and 4 are unwired");

        // Step 4 is identity-scoped and gates completion for every context, so
        // with the shipped backend it is the reported failure (§9.12 "Step
        // scope"); step 3 also fails and is carried on `progress`.
        let RecoveryError::KeyPackageRotationFailed { ref progress, .. } = err else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        assert_eq!(progress.failed_contexts.len(), 1);
        assert_eq!(progress.failed_contexts[0].1.step, 3);

        // THE REGRESSION GUARD (M1): steps 5 and 6 are identity-scoped cleanup
        // and MUST run even though every context failed step 3. Previously the
        // total-failure guard returned before reaching them, so a production
        // compromise recovery advanced the MLS epoch and did nothing else — a
        // stolen device enrolled for identity-private-state would have kept
        // decrypting because the PSK was never rotated, and no contact was told
        // to re-run §9.11 KCV. Worse, the outcome was coupled to an unrelated
        // question: if any context had needed an ADR-029 rejoin, the guard
        // would not have fired and 5/6 WOULD have run.
        //
        // NOTE ON SCOPE: this asserts the ORCHESTRATOR reaches step 6 and
        // reports its outcome — REACHABILITY, not success. The earlier version
        // asserted `.succeeded()`, which was only ever reachable because a test
        // helper registered a synthetic `identity-private-state` actor: it
        // certified a `Succeeded` outcome production never produces. The
        // production backend fails step 6 closed (#2240 Part B), so the honest
        // reachability signal is a step-6 `Failed` carrying that code — a step
        // the orchestrator never called would report `NotApplicable` instead.
        assert!(
            matches!(
                progress.private_state_reencryption,
                StepOutcome::Failed(ref e)
                    if e.step == 6 && e.code == RecoveryStepErrorCode::PskDistributionUnwired
            ),
            "step 6 must be REACHED and its fail-closed outcome reported on the \
             fail-closed path, got {:?}",
            progress.private_state_reencryption
        );
        assert!(
            progress.contact_notification.fully_delivered(),
            "step 5 must be reached even when every context failed"
        );

        // Pin WHICH steps are responsible, so this cannot pass because step 2
        // broke: step 2 succeeds, steps 3 and 4 fail closed.
        assert!(backend.mls_update(context_id, &key_rotation).await.is_ok());
        assert_eq!(
            backend
                .revoke_ucans(context_id, &key_rotation)
                .await
                .expect_err("step 3 must fail closed")
                .step,
            3
        );
        assert_eq!(
            backend
                .rotate_key_packages(&key_rotation)
                .await
                .expect_err("step 4 must fail closed")
                .step,
            4
        );
    }

    /// M1 regression guard, isolated: with EVERY context failing step 3, the
    /// orchestrator must still invoke step 6 on the backend.
    ///
    /// The tier test above observes step 6's reported outcome; this observes
    /// the *call* via a counting backend, so it holds regardless of whether the
    /// PSK actually lands. That distinction matters: production PSK delivery is
    /// a separate, tracked question, but "recovery never even tries" is the
    /// regression this pins.
    #[tokio::test]
    async fn identity_scoped_steps_run_when_every_context_fails() {
        use std::cell::RefCell;

        /// Records the §9.12 step number of every backend call, in order.
        struct RecordingBackend {
            invoked: RefCell<Vec<u8>>,
        }

        impl RecordingBackend {
            fn record(&self, step: u8) {
                self.invoked.borrow_mut().push(step);
            }
        }

        #[async_trait(?Send)]
        impl RecoveryBackend for RecordingBackend {
            async fn mls_update(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                self.record(2);
                Ok(())
            }

            async fn revoke_ucans(
                &self,
                _context_id: &str,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                // Mirrors the production backend: step 3 always fails closed.
                self.record(3);
                Err(RecoveryStepError {
                    step: 3,
                    code: RecoveryStepErrorCode::UcanRevocationUnwired,
                    description: "UCAN revocation is not wired for recovery".to_owned(),
                })
            }

            async fn rotate_key_packages(
                &self,
                _key_rotation: &KeyRotationOutcome,
            ) -> Result<(), RecoveryStepError> {
                self.record(4);
                Err(RecoveryStepError {
                    step: 4,
                    code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
                    description: "KeyPackage rotation is not wired".to_owned(),
                })
            }

            async fn notify_contacts(
                &self,
                _did: &DID,
                _tier: CompromiseTier,
                _key_rotation: &KeyRotationOutcome,
                contacts: &HashSet<DID>,
            ) -> Result<ContactsReached, RecoveryStepError> {
                self.record(5);
                Ok(ContactsReached {
                    dids: contacts.iter().cloned().collect(),
                })
            }

            async fn rotate_psk(
                &self,
                _params: &PskRotationParams,
            ) -> Result<(), RecoveryStepError> {
                self.record(6);
                Ok(())
            }
        }

        let alice = did("did:dht:alice");
        let backend = RecordingBackend {
            invoked: RefCell::new(Vec::new()),
        };
        let orch = CompromiseRecoveryOrchestrator::new(
            alice.clone(),
            vec!["ctx-1".to_owned(), "ctx-2".to_owned()],
        );
        let key_rotation = active_key_rotation_outcome(&alice, 1000);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::ActiveSigning,
                Some(&key_rotation),
                &HashSet::from([did("did:dht:bob")]),
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("every context fails step 3 — must fail closed");

        // Steps 3 AND 4 both fail here. The identity-scoped gate takes
        // precedence: it is the more fundamental failure and, unlike
        // `AllContextsFailed`, is not something a per-context retry can address.
        assert!(
            matches!(&err, RecoveryError::KeyPackageRotationFailed { .. }),
            "expected KeyPackageRotationFailed, got: {err:?}"
        );
        // Exact call sequence for two contexts, both failing step 3:
        //   per-context: (2, 3) for ctx-1, (2, 3) for ctx-2
        //   identity-scoped, once each and in §9.12 order: 4, then 5, then 6.
        assert_eq!(
            backend.invoked.borrow().as_slice(),
            &[2, 3, 2, 3, 4, 5, 6],
            "steps 4, 5 and 6 MUST each run exactly once — and steps 5/6 MUST run even \
             though every context failed step 3 (the orchestrator used to return before \
             reaching them, silently skipping PSK rotation and contact notification)"
        );
    }

    /// `IdentityKey` tier: same fail-closed contract on steps 3 (#2069), 4
    /// (#2240 Part B item 2) and 6 (#2240 Part B). The most severe tier is exactly the one that must
    /// not report a phantom revocation of the compromised identity key's
    /// outstanding tokens, nor a phantom withdrawal of its published
    /// `KeyPackages`.
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_full_recovery_identity_key_tier_fails_closed_on_steps_3_4_and_6() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");
        let bob = did("did:dht:bob");
        let carol = did("did:dht:carol");
        let context_id = "ctx-identity-recovery";

        // Set up a context with alice, bob, and carol as members so
        // contact notification can find shared contexts.
        setup_context_with_members(&manager, context_id, &alice, &[&bob, &carol]).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), vec![context_id.to_owned()]);
        let key_rotation = identity_key_rotation_outcome(&alice, did("did:dht:alice-new"), 3000);
        let contacts = HashSet::from([bob, carol]);
        let psk_params = PskRotationParams {
            did: "did:dht:zRecoveryTestIdentity".to_owned(),
            enrolled_device_pubkeys: vec![vec![1u8; 32]],
            compromised_device_pubkey: None,
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::IdentityKey,
                Some(&key_rotation),
                &contacts,
                Some(&psk_params),
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("recovery must fail closed while step 3 is unwired");

        let RecoveryError::KeyPackageRotationFailed { ref progress, .. } = err else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        assert_eq!(progress.failed_contexts.len(), 1);
        assert_eq!(progress.failed_contexts[0].1.step, 3);

        // M1: the identity-scoped steps are REACHED on the fail-closed path, so
        // the setup above (shared members for step 5) is live rather than dead.
        // As in the ActiveSigning tier test the claim is reachability: step 6
        // fails closed in production, so its reached-and-reported signal is a
        // step-6 `Failed`, never `NotApplicable`.
        assert!(
            progress.contact_notification.fully_delivered(),
            "step 5 must be reached"
        );
        assert!(
            matches!(
                progress.private_state_reencryption,
                StepOutcome::Failed(ref e)
                    if e.step == 6 && e.code == RecoveryStepErrorCode::PskDistributionUnwired
            ),
            "step 6 must be reached and its fail-closed outcome reported, got {:?}",
            progress.private_state_reencryption
        );

        // The identity-migration outcome the tier helper builds is untouched by
        // the fail-closed verdict — the DID rotation itself (step 1) happened,
        // and BOTH endpoints are retained.
        assert!(key_rotation.did_changed);
        assert_eq!(key_rotation.did_after, did("did:dht:alice-new"));
        assert_eq!(
            key_rotation.did_before, alice,
            "the compromised (pre-migration) DID must be retained"
        );

        let step3_err = backend
            .revoke_ucans(context_id, &key_rotation)
            .await
            .expect_err("step 3 must fail closed");
        assert_eq!(step3_err.step, 3);
        assert_eq!(step3_err.code, RecoveryStepErrorCode::UcanRevocationUnwired);
        // The rotated scopes are machine-checkable content (which capabilities
        // remain live), not prose — this tier rotates both.
        assert!(step3_err.description.contains("#active"));
        assert!(step3_err.description.contains("#agent"));

        // Step 4 must name the PRE-migration DID. KeyPackages are keyed by
        // owner DID (`key_package_stores: DashMap<DID, _>`), so after an
        // IdentityKey migration the dangerous stale KeyPackages sit under the
        // OLD did — naming `did_after` would send an operator hunting under a
        // fresh DID that has none, leaving the compromised ones live.
        let step4_err = backend
            .rotate_key_packages(&key_rotation)
            .await
            .expect_err("step 4 must fail closed");
        assert_eq!(step4_err.step, 4);
        assert_eq!(
            step4_err.code,
            RecoveryStepErrorCode::KeyPackageRotationUnwired
        );
        assert!(
            step4_err.description.contains(alice.as_ref()),
            "step 4 error must name the COMPROMISED (pre-migration) identity: {}",
            step4_err.description
        );
        assert!(
            !step4_err.description.contains("did:dht:alice-new"),
            "step 4 error must NOT point at the post-migration DID, which owns no \
             stale KeyPackages: {}",
            step4_err.description
        );
    }

    /// A1 regression guard: a context that requires an ADR-029 rejoin AND then
    /// fails a later step must NOT suppress the fail-closed verdict.
    ///
    /// The old shape pushed to `pending_rejoin` and `failed_contexts`
    /// independently, so such a context appeared in both — and the guard, which
    /// tested `pending_rejoin.is_empty()`, was suppressed by its own failed
    /// context. `execute_recovery` then returned `Ok` with zero completed
    /// contexts and every context failed: a total failure observed as success,
    /// exactly the shape this guard exists to remove.
    ///
    /// The lists are now derived from per-context state, so they are disjoint
    /// by construction: `pending_rejoin` only ever holds error-free contexts.
    #[tokio::test]
    async fn rejoin_context_that_later_fails_does_not_suppress_fail_closed() {
        let alice = did("did:dht:alice");
        let orch =
            CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-rejoin".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let backend = MockRecoveryBackend {
            // Step 2 signals the ADR-029 Tier-3 rejoin path...
            mls_update_error: Some((
                "ctx-rejoin".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::RequiresRejoin,
                    description: "member requires rejoin".to_owned(),
                },
            )),
            // ...and step 3 then fails for the SAME context.
            revoke_ucans_error: Some((
                "ctx-rejoin".to_owned(),
                RecoveryStepError {
                    step: 3,
                    code: RecoveryStepErrorCode::UcanRevocationUnwired,
                    description: "UCAN revocation is not wired for recovery".to_owned(),
                },
            )),
            ..MockRecoveryBackend::new()
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err(
                "a rejoin context that then fails must NOT suppress the fail-closed verdict",
            );

        let RecoveryError::AllContextsFailed {
            attempted,
            ref progress,
        } = err
        else {
            panic!("expected AllContextsFailed, got: {err:?}");
        };
        assert_eq!(attempted, 1);
        let failed_contexts = &progress.failed_contexts;
        // The context is reported as FAILED, and (by construction) is not also
        // sitting in `pending_rejoin` masking the failure.
        assert_eq!(failed_contexts.len(), 1);
        assert_eq!(failed_contexts[0].0, "ctx-rejoin");
        assert_eq!(failed_contexts[0].1.step, 3);
    }

    /// The complement of the guard above: a rejoin context whose remaining
    /// steps SUCCEED stays on the `Ok` path and is reported as pending rejoin,
    /// not failed. Pins that the disjointness fix did not simply reclassify
    /// every rejoin context as a failure.
    #[tokio::test]
    async fn rejoin_context_that_succeeds_stays_pending_not_failed() {
        let alice = did("did:dht:alice");
        let orch =
            CompromiseRecoveryOrchestrator::new(alice.clone(), vec!["ctx-rejoin".to_owned()]);
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let backend = MockRecoveryBackend {
            mls_update_error: Some((
                "ctx-rejoin".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::RequiresRejoin,
                    description: "member requires rejoin".to_owned(),
                },
            )),
            ..MockRecoveryBackend::new()
        };

        let result = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect("steps 3 and 4 succeed, so this is not a total failure");

        assert_eq!(result.pending_rejoin, vec!["ctx-rejoin"]);
        assert!(
            result.failed_contexts.is_empty(),
            "an error-free rejoin context must not also be reported as failed"
        );
        // The third disjointness edge: `completed_contexts` must NOT also list
        // it. `is_complete()` treats `requires_rejoin` as satisfying step 2, so
        // a naive `if is_complete()` would report this context as fully
        // recovered — but its MLS Update never happened and it still needs an
        // admin remove + re-add (ADR-029). Reporting it as completed would tell
        // an operator the compromised key is dead in that context when it is
        // not.
        assert!(
            result.completed_contexts.is_empty(),
            "a rejoin-pending context must not also be reported as completed: {:?}",
            result.completed_contexts
        );
    }

    /// R2: a step-4 failure is fatal **independently of context count**,
    /// including the zero-context case where the per-context loop never runs
    /// and the `AllContextsFailed` guard therefore cannot fire.
    ///
    /// This is the fail-open that survived the first fix: with the shipped
    /// backend `rotate_key_packages` ALWAYS fails, so an identity whose contexts
    /// are all closed used to get `Ok(RecoveryResult { .. })`. A caller using
    /// `?`/`is_ok()` reported success while §9.12 step 4 had not happened.
    #[tokio::test]
    async fn zero_context_recovery_fails_closed_on_step_4() {
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(alice.clone(), Vec::new());
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let backend = MockRecoveryBackend {
            rotate_key_packages_error: Some(RecoveryStepError {
                step: 4,
                code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
                description: "KeyPackage rotation is not wired".to_owned(),
            }),
            ..MockRecoveryBackend::new()
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("a step-4 failure is fatal even with zero contexts");

        let RecoveryError::KeyPackageRotationFailed {
            ref step_error,
            ref progress,
        } = err
        else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        // Identity-scoped failure reported through its OWN variant, never
        // laundered into the per-context channel a caller cannot retry against.
        assert_eq!(step_error.step, 4);
        assert_eq!(
            step_error.code,
            RecoveryStepErrorCode::KeyPackageRotationUnwired
        );
        assert!(
            progress.failed_contexts.is_empty(),
            "an identity-scoped failure must not fabricate per-context errors"
        );
    }

    /// The step-4 failure stays fatal WITH contexts too, and takes precedence
    /// over `AllContextsFailed` — the identity-scoped gate is the more
    /// fundamental one. Steps 2/3 progress is preserved on the error rather
    /// than overwritten (R5).
    #[tokio::test]
    async fn step_4_failure_is_fatal_with_contexts_and_preserves_per_context_progress() {
        let alice = did("did:dht:alice");
        let orch = CompromiseRecoveryOrchestrator::new(
            alice.clone(),
            vec!["ctx-ok".to_owned(), "ctx-rejoin".to_owned()],
        );
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);

        let backend = MockRecoveryBackend {
            mls_update_error: Some((
                "ctx-rejoin".to_owned(),
                RecoveryStepError {
                    step: 2,
                    code: RecoveryStepErrorCode::RequiresRejoin,
                    description: "member requires rejoin".to_owned(),
                },
            )),
            rotate_key_packages_error: Some(RecoveryStepError {
                step: 4,
                code: RecoveryStepErrorCode::KeyPackageRotationUnwired,
                description: "KeyPackage rotation is not wired".to_owned(),
            }),
            ..MockRecoveryBackend::new()
        };

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &HashSet::new(),
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("a step-4 failure is fatal");

        let RecoveryError::KeyPackageRotationFailed { ref progress, .. } = err else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        // R5: steps 2/3 outcomes and the ADR-029 rejoin flag survive the
        // identity-scoped failure instead of being erased by it.
        assert_eq!(
            progress.contexts_through_per_context_steps,
            vec!["ctx-ok", "ctx-rejoin"],
            "both contexts cleared steps 2-3 and must still be reported as such"
        );
        assert_eq!(
            progress.pending_rejoin,
            vec!["ctx-rejoin"],
            "the ADR-029 rejoin flag must not be erased by a step-4 failure"
        );
        assert!(progress.failed_contexts.is_empty());
    }

    /// Multi-context production recovery, post-#2069 / #2240 Part B item 2.
    /// Per-context failure isolation still attributes failures to the right
    /// step — the two registered contexts get past step 2 and fail at step 3
    /// (and would fail at step 4), the unregistered one fails at step 2 — but
    /// because *no* context can complete, the whole call fails closed rather
    /// than reporting partial success.
    ///
    /// (Orchestrator-level partial-success isolation stays covered by
    /// [`recovery_partial_failure_stays_ok`], which drives the configurable
    /// [`MockRecoveryBackend`] and can still let steps 3 and 4 succeed.)
    #[tokio::test(flavor = "multi_thread")]
    async fn production_backend_multi_context_all_fail_closed() {
        let manager = test_context_manager();
        let alice = did("did:dht:alice");

        setup_context(&manager, "ctx-ok-1", &alice).await;
        setup_context(&manager, "ctx-ok-2", &alice).await;

        let backend = ProductionRecoveryBackend::new(manager, test_signing_key());
        let orch = CompromiseRecoveryOrchestrator::new(
            alice.clone(),
            vec![
                "ctx-ok-1".to_owned(),
                "ctx-ok-2".to_owned(),
                "ctx-nonexistent".to_owned(),
            ],
        );
        let key_rotation = agent_key_rotation_outcome(&alice, 1000);
        let contacts = HashSet::new();

        let err = orch
            .execute_recovery(
                CompromiseTier::Agent,
                Some(&key_rotation),
                &contacts,
                None,
                &backend,
                &scp_clock::SystemClock,
            )
            .await
            .expect_err("zero contexts can recover — must fail closed");

        // Step 4 (identity-scoped) is the reported failure; the per-context
        // step errors ride along on `progress`.
        let RecoveryError::KeyPackageRotationFailed { ref progress, .. } = err else {
            panic!("expected KeyPackageRotationFailed, got: {err:?}");
        };
        let failed_contexts = &progress.failed_contexts;

        // Per-step attribution, observed END-TO-END through the orchestrator
        // (the error now carries `failed_contexts`, so this no longer needs a
        // backend-level proxy): the two registered contexts get past step 2 and
        // fail at step 3; the unregistered one fails at step 2.
        let by_ctx: std::collections::HashMap<&str, u8> = failed_contexts
            .iter()
            .map(|(ctx, e)| (ctx.as_str(), e.step))
            .collect();
        assert_eq!(
            by_ctx.len(),
            3,
            "every context must be reported: {by_ctx:?}"
        );
        assert_eq!(by_ctx.get("ctx-ok-1"), Some(&3));
        assert_eq!(by_ctx.get("ctx-ok-2"), Some(&3));
        assert_eq!(by_ctx.get("ctx-nonexistent"), Some(&2));

        // The deduplicating Display renders the shared step-3 reason once, with
        // the repeat count — not once per context.
        let rendered = err.to_string();
        assert!(
            rendered.contains("step 3: 2 context(s)"),
            "same-step failures must be grouped with a count: {rendered}"
        );
        assert!(
            rendered.contains("step 2: 1 context(s)"),
            "every distinct step must be represented: {rendered}"
        );
    }
}
