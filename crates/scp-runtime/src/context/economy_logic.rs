//! Escrow-based payment flow on `ContextManager` (spec section 19.2.2, #1537).
//!
//! Implements the correct 9-step payment integration as an escrow pattern:
//! 1. `authorize_paid_action` — evaluates cost, checks spending UCAN,
//!    checks budget, calls adapter.authorize (escrow). Returns authorization.
//! 2. The caller performs the action (encrypt, MLS add, outlet execute).
//! 3. `complete_paid_action` — captures payment, stores receipt, records spend.
//! 4. `void_paid_action` — voids authorization, rolls back budget on failure.
//!
//! This eliminates the previous payment-before-action ordering bug where
//! payment was captured before the action succeeded.
//!
//! When no payment adapter is configured (`self.payment_adapter` is `None`),
//! `authorize_paid_action` returns `Ok(None)` immediately.
//!
//! See spec section 19.2.2 and ADR-033 in `.docs/adrs/phase-3.md`.

use std::collections::HashSet;
use std::sync::Arc;

use scp_did::{DID, SigningKeyId};
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::crypto::ucan::UcanError;
use scp_protocol::crypto::ucan::spending::{SpendingUcanCheck, validate_spending_ucan_signed};
use scp_protocol::crypto::ucan::validate::{
    DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, DidResolver, InMemoryProofResolver, RevocationChecker,
};
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;

use crate::economy::adapter::{PaymentAdapterDyn, PaymentReceipt};
use crate::economy::integration::{self, IntegrationError};

// ---------------------------------------------------------------------------
// Spending UCAN signature validation wiring (C1, PR #1606)
// ---------------------------------------------------------------------------

/// Adapts the [`KeyResolver`] closure that the `ContextManager` already
/// holds for governance vote verification into a UCAN [`DidResolver`].
///
/// The [`KeyResolver`] is VM-aware (ADR-039): it takes a `(DID, SigningKeyId)`
/// pair and returns the verifying key for that specific verification method.
/// This adapter threads the UCAN `kid` header through to the resolver so that
/// a spending UCAN declaring `kid: "#agent"` is verified against the agent key
/// and one declaring (or defaulting to) `#active` is verified against the
/// human key — they no longer collapse to a single key.
///
/// The bare [`resolve_public_key`](DidResolver::resolve_public_key) path (no
/// `kid` in the header) resolves `#active`, the default verification method.
/// [`resolve_public_key_by_kid`](DidResolver::resolve_public_key_by_kid) parses
/// the `kid` fragment (`"#active"` / `"#agent"`) into a [`SigningKeyId`] and
/// passes it to the resolver; an unrecognized fragment is rejected as
/// [`UcanError::MalformedToken`].
///
/// When a DID has no key registered for the requested verification method (the
/// `noop_key_resolver` test path, or a DID with no `#agent` key), resolution
/// returns [`UcanError::MalformedToken`] which the spending UCAN validator
/// surfaces as a signature failure — closing the C1 attack where a fabricated
/// UCAN with no real signer was accepted.
///
/// Public so the cross-context outlet-invocation saga handler
/// ([`crate::context::actor::handlers::saga`]) reuses the SAME VM-aware DID→key
/// adapter for its §7 UCAN re-validation (spec §6.2.4), rather than
/// reimplementing the `#active`/`#agent` resolution and so producing a divergent
/// answer than the rest of the runtime.
pub struct KeyResolverDidResolver<'a> {
    key_resolver: &'a KeyResolver,
}

impl<'a> KeyResolverDidResolver<'a> {
    pub(crate) fn new(key_resolver: &'a KeyResolver) -> Self {
        Self { key_resolver }
    }
}

impl DidResolver for KeyResolverDidResolver<'_> {
    fn resolve_public_key(&self, did: &str) -> Result<[u8; 32], UcanError> {
        // No `kid` in the header: resolve the default verification method
        // (`#active`, the human signing key).
        let did_owned = scp_did::DID::from(did.to_owned());
        (self.key_resolver)(&did_owned, SigningKeyId::Active)
            .map(|vk| vk.to_bytes())
            .ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "no public key registered for DID '{did}' (key_resolver returned None) — \
                     spending UCAN signature cannot be verified"
                ))
            })
    }

    fn resolve_public_key_by_kid(
        &self,
        did: &str,
        signing_key_id: SigningKeyId,
    ) -> Result<[u8; 32], UcanError> {
        // VM-aware resolution (ADR-039): resolve the key `signing_key_id` names
        // from the DID document. `verify_signature` decoded a `kid` header into
        // this value, so no fragment string reaches here.
        let did_owned = scp_did::DID::from(did.to_owned());
        (self.key_resolver)(&did_owned, signing_key_id)
            .map(|vk| vk.to_bytes())
            .ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "no public key registered for DID '{did}' verification method '{}' \
                     (key_resolver returned None) — spending UCAN signature cannot be verified",
                    signing_key_id.as_fragment()
                ))
            })
    }
}

/// Per-context revocation checker for spending UCANs.
///
/// Backed by an immutable borrow of the per-context `revoked_spending_ucan_cids`
/// set. The set is empty in the current build — spending UCAN revocation lists
/// have not yet been wired through governance — but the trait surface is
/// real, so when revocation lands the only change required is populating the
/// set. This is the opposite of a stub: it is the empty case of a real
/// integration.
///
/// `pub(crate)` so the cross-context outlet-invocation saga handler reuses the
/// SAME per-context revocation surface for its §7 UCAN re-validation (spec
/// §6.2.4), backed by the same `revoked_spending_ucan_cids` set.
pub struct ContextRevocationChecker<'a> {
    pub(crate) revoked_cids: &'a HashSet<String>,
}

impl RevocationChecker for ContextRevocationChecker<'_> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revoked_cids.contains(token_cid)
    }
}

/// Runs the full cryptographic + spending validation pipeline on a
/// spending UCAN, then maps any failure into a `ContextError` with the
/// appropriate SCP-ECON error code.
///
/// Splitting this out of [`enforce_economy`] keeps the latter focused on
/// cost evaluation and budget arithmetic. The validator owns:
///
/// - Ed25519 signature verification (kid-aware via the manager's
///   `KeyResolver`).
/// - `iss == aud == actor_did` binding (the C1 fix).
/// - Key-scope enforcement (ADR-039 self-delegation rule).
/// - Delegation chain walk (no-op for root spending UCANs, real for
///   sub-delegated ones).
/// - Expiry / not-before / 24-hour ceiling.
/// - Revocation lookup against the per-context revoked-CID set.
/// - Nonce reservation against the per-context spending nonce tracker.
/// - Spending-specific scope, lifetime, and parent attenuation checks.
pub fn validate_spending_ucan_or_error(
    spending: &scp_protocol::crypto::ucan::UcanToken,
    actor_did: &DID,
    context_id: &str,
    nonce_tracker: &mut scp_protocol::crypto::ucan::nonce::NonceTracker<Arc<dyn scp_clock::Clock>>,
    revoked_cids: &HashSet<String>,
    key_resolver: &KeyResolver,
    clock: &dyn scp_clock::Clock,
) -> Result<(), ContextError> {
    let did_resolver = KeyResolverDidResolver::new(key_resolver);
    let revocation_checker = ContextRevocationChecker { revoked_cids };
    let proof_resolver = InMemoryProofResolver::new();

    let check = SpendingUcanCheck {
        token: spending,
        context_id,
        actor_did: actor_did.as_ref(),
        parent_capability: None,
    };

    validate_spending_ucan_signed(
        check,
        &did_resolver,
        nonce_tracker,
        &revocation_checker,
        &proof_resolver,
        DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
        clock,
    )
    .map(|_| ())
    .map_err(|e| {
        ContextError::PermissionDenied(format!(
            "SCP-ECON-12065: spending UCAN signature/replay validation failed: {e}"
        ))
    })
}

/// Authorization token returned by `authorize_paid_action`.
///
/// Holds the escrow authorization and evaluated cost so that
/// `complete_paid_action` and `void_paid_action` can finalize or roll back.
///
/// Field visibility widened to `pub(crate)` in ADR-049 §15
/// so the hoisted free functions in
/// [`crate::context::economy_helpers`] can construct / destructure the
/// token without going through this module.
pub struct PaidActionAuthorization {
    /// The prepared action containing the authorization envelope.
    pub(crate) prepared: integration::PreparedAction,
    /// The payment adapter for capture/void.
    pub(crate) adapter: Arc<dyn PaymentAdapterDyn>,
    /// The economic policy used for evaluation.
    pub(crate) policy: scp_protocol::economy::types::EconomicPolicy,
    /// Metrics snapshot for `process_paid_action`.
    pub(crate) metrics: ObservableMetrics,
}

/// Maps an [`IntegrationError`] to a [`ContextError`] with proper SCP error codes.
///
/// Visibility widened in ADR-049 §15 so the hoisted
/// [`crate::context::economy_helpers`] free functions can map the same
/// way the legacy methods did. The enclosing `economy` module is
/// `pub(crate)` so the effective visibility is unchanged.
pub fn integration_error_to_context(err: IntegrationError) -> ContextError {
    match err {
        IntegrationError::CostEvaluationOverflow => {
            ContextError::PermissionDenied("SCP-ECON-12040: cost evaluation overflow".to_owned())
        }
        IntegrationError::AuthorizationFailed(e) => ContextError::PermissionDenied(format!(
            "SCP-ECON-12041: payment authorization failed: {e}"
        )),
        IntegrationError::CostInsufficient {
            expected, provided, ..
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12042: cost insufficient: expected {expected}, provided {provided}"
        )),
        IntegrationError::AuthorizationVerificationFailed(e) => ContextError::PermissionDenied(
            format!("SCP-ECON-12043: authorization verification failed: {e}"),
        ),
        IntegrationError::ActionProcessingFailed(msg) => ContextError::PermissionDenied(format!(
            "SCP-ECON-12044: action processing failed: {msg}"
        )),
        IntegrationError::CaptureFailed(e) => {
            ContextError::PermissionDenied(format!("SCP-ECON-12045: payment capture failed: {e}"))
        }
        IntegrationError::VoidFailed {
            original,
            void_error,
        } => ContextError::PermissionDenied(format!(
            "SCP-ECON-12046: void failed (original: {original}, void: {void_error})"
        )),
        IntegrationError::NoEconomicPolicy => ContextError::PermissionDenied(
            "SCP-ECON-12047: no economic policy configured".to_owned(),
        ),
    }
}

/// Verifies a receipt and checks it is valid.
///
/// Visibility widened in ADR-049 §15 so the hoisted
/// [`crate::context::economy_helpers::complete_paid_action`] free
/// function can call the same verifier the legacy method did. The
/// enclosing `economy` module is `pub(crate)` so the effective
/// visibility is unchanged.
pub async fn verify_and_check_receipt(
    adapter: &dyn PaymentAdapterDyn,
    receipt: &PaymentReceipt,
) -> Result<(), ContextError> {
    // Call verify_dyn directly — we have one adapter and one receipt, so
    // the multi-verifier dispatch in `verify_receipts_dyn` adds no value here.
    let result = adapter.verify_dyn(receipt).await.map_err(|e| {
        ContextError::PermissionDenied(format!("SCP-ECON-12049: receipt verification error: {e}"))
    })?;
    if !result.valid {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12048: receipt verification failed: receipt marked invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Input parameters for [`enforce_economy`].
///
/// F9: grouped into a struct to stop the parameter list from drifting
/// back above the `clippy::too_many_arguments` threshold as new layers
/// (pricing, nonce tracker, per-DID escalation) are added. Constructing
/// this struct directly at call sites is the contract; positional
/// argument calls are compile-rejected.
pub struct EnforceEconomyRequest<'a> {
    /// Per-context economic policy, if any. `None` means a free context.
    pub economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Per-context budget tracker (mutable — deductions happen in-place).
    pub budget_tracker: &'a mut scp_protocol::economy::budget::MemberBudgetTracker,
    /// Per-context velocity tracker — consulted for per-DID escalation.
    pub velocity_tracker: &'a scp_protocol::economy::antispam::SenderVelocityTracker,
    /// Current member count (used for the `member_count` metric).
    pub member_count: usize,
    /// The kind of paid action being enforced.
    pub action_type: PaidActionType,
    /// The DID being charged.
    pub actor_did: &'a DID,
    /// Unix seconds when this enforcement is running.
    pub now: u64,
    /// Optional spending UCAN provided by the caller. Required for paid actions.
    pub spending_ucan: Option<&'a scp_protocol::crypto::ucan::UcanToken>,
    /// Capability URI label stamped onto spending-UCAN validation errors.
    pub action_label: &'a str,
    /// Context ID the spending UCAN must scope to.
    pub context_id: &'a str,
    /// Clock used for UCAN expiry validation.
    pub clock: &'a dyn scp_clock::Clock,
    /// Per-context pricing configuration (escalation curve, floor, cap).
    pub pricing: &'a scp_protocol::economy::antispam::ContextMessagePricingConfig,
    /// Per-context nonce tracker for spending-UCAN replay prevention.
    pub nonce_tracker: &'a mut scp_protocol::crypto::ucan::nonce::NonceTracker<
        std::sync::Arc<dyn scp_clock::Clock>,
    >,
    /// Per-context revoked spending-UCAN CIDs (C1, PR #1606).
    ///
    /// Currently always empty — spending UCAN revocation lists have not been
    /// wired through governance. Passing the set explicitly (rather than
    /// constructing one inside `enforce_economy`) means the only change
    /// required when revocation lands is populating this field at call
    /// sites. The set is consumed by `validate_spending_ucan_signed` via
    /// the [`ContextRevocationChecker`] adapter.
    pub revoked_spending_ucan_cids: &'a HashSet<String>,
    /// Resolver for the actor's UCAN signing key (C1, PR #1606).
    ///
    /// VM-aware per ADR-039: the [`KeyResolver`] takes a `(DID, SigningKeyId)`
    /// pair, so a spending UCAN declaring `kid: "#agent"` is verified against
    /// the agent key and one defaulting to `#active` against the human key.
    /// The [`KeyResolverDidResolver`] adapter parses the UCAN `kid` header into
    /// a [`SigningKeyId`] and threads it through. This is the same resolver
    /// used for governance vote verification.
    pub key_resolver: &'a KeyResolver,
}

/// Unified economy enforcement: evaluate cost, check spending UCAN, check budget.
///
/// This replaces the former separate economy enforcement functions.
/// One unified flow per the escrow
/// pattern: evaluate cost -> check spending UCAN -> check budget -> deduct.
///
/// The cost is composed by (a) evaluating the policy formula (if any) to obtain
/// a base cost — falling back to `pricing.base_cost` when the formula is absent
/// — and then (b) layering the per-DID escalation/floor/cap from `pricing` via
/// [`SenderVelocityTracker::compute_escalated_cost`](scp_protocol::economy::antispam::SenderVelocityTracker::compute_escalated_cost) (spec §19.7).
///
/// Returns the deducted cost for rollback on failure, or `None` if no cost.
pub fn enforce_economy(
    req: EnforceEconomyRequest<'_>,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    let EnforceEconomyRequest {
        economic_policy,
        budget_tracker,
        velocity_tracker,
        member_count,
        action_type,
        actor_did,
        now,
        spending_ucan,
        action_label,
        context_id,
        clock,
        pricing,
        nonce_tracker,
        revoked_spending_ucan_cids,
        key_resolver,
    } = req;
    // Free contexts (no `economic_policy`) do not charge at the cost layer.
    // Defense-in-depth against spam on free contexts is provided by the
    // Matrix-style token-bucket hard rate limit, which is enforced earlier
    // in the send/join/invoke paths and operates independently of cost.
    let Some(policy) = economic_policy else {
        return Ok(None);
    };

    // Step 1: derive a base cost from the policy. When the policy carries a
    // pricing formula, evaluate it against observable metrics; otherwise the
    // formula is absent and `evaluate_cost` consults the flat `CostSchedule`.
    //
    // §19.7 escalation applies to MessageSend, ContextJoin, and OutletCall.
    // For SubscriptionPeriod and ByteStored we delegate entirely to the
    // policy (no per-DID escalation makes sense for them).
    let escalation_eligible = matches!(
        action_type,
        PaidActionType::MessageSend | PaidActionType::ContextJoin | PaidActionType::OutletCall
    );

    let velocity = velocity_tracker.get_velocity(actor_did, now);
    let metrics = ObservableMetrics {
        sender_velocity: velocity,
        member_count: u64::try_from(member_count).unwrap_or(u64::MAX),
        context_message_rate: velocity_tracker.aggregate_velocity(now),
        relay_queue_depth: 0,
        time_of_day: now % 86400,
        storage_usage: 0,
    };
    let Some(base_cost) =
        scp_protocol::economy::policy::evaluate_cost(policy, &action_type, &metrics)
    else {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12040: cost evaluation overflow".to_owned(),
        ));
    };

    // Step 2: layer per-DID escalation/floor/cap (§19.7) on top of the
    // policy-derived base cost for eligible actions. When the policy
    // explicitly prices an action at zero (`per_message: Some(Amount(0))`
    // or `per_message: None`), the action remains free — escalation only
    // layers on top of an existing non-zero cost so that operators can
    // define free action types even under a priced policy.
    let cost = if escalation_eligible && base_cost.value() > 0 {
        velocity_tracker.compute_escalated_cost(
            actor_did,
            now,
            base_cost,
            &pricing.escalation,
            pricing.floor,
            pricing.cap,
        )
    } else {
        base_cost
    };

    if cost.0 == 0 {
        return Ok(None);
    }

    // AND-composition (spec §19.5, #1593): paid actions require both the
    // action capability AND a spending UCAN. The action capability side is
    // verified UPSTREAM at the `member_has_capability` gate (see
    // `messaging.rs` for `MessagesWrite`, `lifecycle.rs` for `ContextJoin`,
    // etc.). This block verifies the spending side.
    // Free actions (cost == 0) pass through above.
    if spending_ucan.is_none() {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
        ));
    }
    debug_assert!(
        spending_ucan.is_some(),
        "spending UCAN should be Some at this point — None case returns above"
    );
    scp_protocol::crypto::ucan::spending::check_spending_capability(
        spending_ucan,
        scp_protocol::crypto::ucan::spending::Amount(cost.0),
        action_label,
    )
    .map_err(|e| ContextError::PermissionDenied(format!("SCP-ECON-12061: {e}")))?;

    // Cryptographic + replay probe + scope + expiry + attenuation validation
    // of the spending UCAN. `spending_ucan` is guaranteed `Some` by the guard
    // above.
    //
    // C1 (PR #1606): before this call landed, only `validate_spending_ucan`
    // was invoked, which checks scope and lifetime but performs NO
    // signature verification, NO `iss == actor_did` binding, NO key-scope
    // check, NO revocation lookup, and (separately) only the nonce check
    // below. A fabricated `UcanToken` with attacker-chosen fields and
    // `signature: vec![]` passed enforcement. The combined entry point
    // `validate_spending_ucan_signed` runs the full pipeline — signature,
    // chain, key scope, expiry, revocation, nonce probe (check_replay only),
    // scope, capability, attenuation — in one call, with the per-context
    // nonce tracker and revocation set wired in.
    //
    // H11: the nonce is only PROBED here (check_replay), not recorded.
    // Recording happens below, after the budget gate, via
    // `commit_spending_ucan_nonce`. This prevents nonce-burn DoS: a
    // budget-rejected request must not exhaust tracker capacity.
    if let Some(spending) = spending_ucan {
        validate_spending_ucan_or_error(
            spending,
            actor_did,
            context_id,
            nonce_tracker,
            revoked_spending_ucan_cids,
            key_resolver,
            clock,
        )?;
    }

    // Budget check — no auto-grant. If the member has no budget, fail with
    // NoBudget error telling the caller to request an ApproveSpend governance
    // action. Budget must be explicitly granted via governance.
    if !budget_tracker.has_budget(actor_did) {
        return Err(ContextError::PermissionDenied(format!(
            "SCP-ECON-12010: no budget for {actor_did} — request ApproveSpend governance action"
        )));
    }
    budget_tracker.record_spend(actor_did, cost).map_err(|e| {
        ContextError::PermissionDenied(format!("SCP-ECON-12011: budget exceeded: {e}"))
    })?;

    // H11: commit the nonce AFTER the budget gate passes. This is the
    // second phase of the split-phase nonce protocol — the read-only probe
    // (check_replay) ran inside validate_spending_ucan_or_error above;
    // the durable insertion (record) happens here so that budget-rejected
    // requests cannot burn nonce tracker capacity.
    if let Some(spending) = spending_ucan {
        scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(spending, nonce_tracker)
            .map_err(|e| {
            ContextError::PermissionDenied(format!(
                "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
            ))
        })?;
    }

    Ok(Some(cost))
}

/// Bundle of per-DID economy state that Phase 1 of a paid action took
/// ownership of. Every ticket **must** be consumed by either
/// [`commit_economy_ticket`] (success path) or
/// [`rollback_economy_ticket_inline_view`] (failure path). Dropping a ticket
/// without consuming it leaks budget
/// deduction, a velocity entry, and a hard-rate-limit token — the
/// `#[must_use]` attribute makes this a compile-time warning, and the
/// `Drop` impl logs + debug-asserts so unit tests fail loudly.
///
/// F4: this type exists because the previous `send_message` Phase 2 error
/// path only rolled back the budget, silently leaking the velocity entry
/// and the hard-rate-limit token. Unifying the rollback under a single
/// must-use handle prevents that class of bug from recurring when new
/// error branches are added.
#[must_use = "EconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and hard-rate-limit state"]
pub struct EconomyTicket {
    /// The DID being charged — needed for every rollback operation.
    pub actor_did: DID,
    /// The budget amount deducted by [`enforce_economy`] (if any).
    pub deducted_cost: Option<scp_protocol::economy::types::Amount>,
    /// Identifier of the velocity entry appended in Phase 1; used to
    /// roll back the specific entry and not race concurrent senders.
    pub velocity_token: scp_protocol::economy::antispam::VelocityRollbackToken,
    /// When `true`, Phase 1 consumed a hard-rate-limit token that must
    /// be refunded on rollback. `false` only for code paths that did
    /// not consume a token (e.g., `ContextJoin`).
    pub needs_hard_rate_limit_refund: bool,
    /// Set to `true` by `commit`/`rollback` so the `Drop` guard knows
    /// the caller honored the contract. Visible to the `messaging` /
    /// `lifecycle` modules that construct the ticket; mutated only via
    /// the `commit`/`rollback` helpers below.
    pub(crate) consumed: bool,
}

impl Drop for EconomyTicket {
    fn drop(&mut self) {
        if !self.consumed {
            // Log at error level so a leak is visible in production, and
            // debug-assert so the next CI run fails loudly.
            tracing::error!(
                actor_did = %self.actor_did,
                cost = ?self.deducted_cost,
                "EconomyTicket dropped without commit or rollback — budget and velocity state may be inconsistent"
            );
            debug_assert!(
                false,
                "EconomyTicket dropped without commit or rollback for actor {}",
                self.actor_did
            );
        }
    }
}

/// Marks the ticket as committed (success path). Returns the deducted
/// cost so callers can pass it to the payment capture step.
///
/// Call this exactly once per ticket. Dropping the returned
/// `Option<Amount>` is safe; the budget deduction has already been
/// recorded under the Phase 1 lock.
pub fn commit_economy_ticket(
    mut ticket: EconomyTicket,
) -> Option<scp_protocol::economy::types::Amount> {
    ticket.consumed = true;
    ticket.deducted_cost
}

/// Rolls back every piece of state the ticket represents: the budget
/// deduction, the velocity entry (via its rollback token, so we do not
/// race concurrent senders), and the hard-rate-limit token (when the
/// Phase 1 path consumed one).
///
/// Reverses the three Class-C governance fields (`velocity_tracker`,
/// `hard_rate_limit`, `budget_tracker`) through the actor-shape
/// [`GovernanceClassCMut`](crate::context::actor::class_s::GovernanceClassCMut)
/// view's field-granular accessors, touched SEQUENTIALLY so each `&mut` borrow
/// ends before the next — so the cell-holding send / join paths reverse a Phase-1
/// ticket with no whole `&mut GovernanceState` (nor a 3-field simultaneous
/// borrow). Every field it reverses is Class-C (the consume it undoes is itself
/// reversed by the economy-compensation hook when a persist does not land), so
/// no fail-closed persist and no Class-S reach is involved.
///
/// Consumes the ticket so the `Drop` guard does not fire.
pub fn rollback_economy_ticket_inline_view(
    governance: &mut crate::context::actor::class_s::GovernanceClassCMut,
    mut ticket: EconomyTicket,
) {
    ticket.consumed = true;
    governance
        .velocity_tracker_mut()
        .rollback(&ticket.actor_did, ticket.velocity_token);
    if ticket.needs_hard_rate_limit_refund {
        governance.hard_rate_limit_mut().refund(&ticket.actor_did);
    }
    if let Some(cost) = ticket.deducted_cost {
        governance
            .budget_tracker_mut()
            .reverse_spend(&ticket.actor_did, cost);
    }
}

pub fn rand_idempotency_key() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}
