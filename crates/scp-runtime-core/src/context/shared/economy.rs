//! Items the economy domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::deps::ActorDeps;
use scp_did::DID;
use scp_did::SigningKeyId;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::crypto::ucan::UcanError;
use scp_protocol::crypto::ucan::spending::SpendingUcanCheck;
use scp_protocol::crypto::ucan::spending::validate_spending_ucan_signed;
use scp_protocol::crypto::ucan::validate::DEFAULT_CLOCK_SKEW_TOLERANCE_SECS;
use scp_protocol::crypto::ucan::validate::DidResolver;
use scp_protocol::crypto::ucan::validate::InMemoryProofResolver;
use scp_protocol::crypto::ucan::validate::RevocationChecker;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::PaidActionType;
use scp_runtime_types::economy::adapter::PaymentAdapterDyn;
use scp_runtime_types::economy::adapter::PaymentReceipt;
use scp_runtime_types::economy::integration;
use std::collections::HashSet;
use std::sync::Arc;

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
/// (`scp_runtime_saga::handler`) reuses the SAME VM-aware DID→key
/// adapter for its §7 UCAN re-validation (spec §6.2.4), rather than
/// reimplementing the `#active`/`#agent` resolution and so producing a divergent
/// answer than the rest of the runtime.
pub struct KeyResolverDidResolver<'a> {
    /// The resolver that maps a DID's verification method to its public key.
    pub key_resolver: &'a KeyResolver,
}

impl<'a> KeyResolverDidResolver<'a> {
    /// Wraps `key_resolver` as a UCAN DID resolver.
    pub fn new(key_resolver: &'a KeyResolver) -> Self {
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

    fn resolve_public_key_by_kid(&self, did: &str, kid: &str) -> Result<[u8; 32], UcanError> {
        // VM-aware resolution (ADR-039): map the UCAN `kid` fragment to the
        // verification method it names (via the single canonical parser), then
        // resolve that specific key from the DID document. An unrecognized
        // fragment is a malformed token.
        let signing_key_id = SigningKeyId::from_fragment(kid).ok_or_else(|| {
            UcanError::MalformedToken(format!(
                "UCAN kid '{kid}' is not a known verification method \
                 (expected \"#active\" or \"#agent\") for DID '{did}'"
            ))
        })?;
        let did_owned = scp_did::DID::from(did.to_owned());
        (self.key_resolver)(&did_owned, signing_key_id)
            .map(|vk| vk.to_bytes())
            .ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "no public key registered for DID '{did}' verification method '{kid}' \
                     (key_resolver returned None) — spending UCAN signature cannot be verified"
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
pub struct ContextRevocationChecker<'a, S = std::collections::hash_map::RandomState> {
    /// The context's revoked spending-UCAN CIDs.
    pub revoked_cids: &'a HashSet<String, S>,
}

impl<S: std::hash::BuildHasher> RevocationChecker for ContextRevocationChecker<'_, S> {
    fn is_revoked(&self, token_cid: &str) -> bool {
        self.revoked_cids.contains(token_cid)
    }
}

/// Authorization token returned by `authorize_paid_action`.
///
/// Holds the escrow authorization and evaluated cost so that
/// `complete_paid_action` and `void_paid_action` can finalize or roll back.
///
/// Field visibility widened to `pub(crate)` in ADR-049 §15
/// so the hoisted free functions in
/// `scp_runtime_economy::helpers` can construct / destructure the
/// token without going through this module.
pub struct PaidActionAuthorization {
    /// The prepared action containing the authorization envelope.
    pub prepared: integration::PreparedAction,
    /// The payment adapter for capture/void.
    pub adapter: Arc<dyn PaymentAdapterDyn>,
    /// The economic policy used for evaluation.
    pub policy: scp_protocol::economy::types::EconomicPolicy,
    /// Metrics snapshot for `process_paid_action`.
    pub metrics: ObservableMetrics,
}

/// Input parameters for `scp_runtime_economy::logic::enforce_economy`.
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

/// Bundle of per-DID economy state that Phase 1 of a paid action took
/// ownership of.
///
/// Every ticket **must** be consumed by either [`commit_economy_ticket`]
/// (success path) or [`rollback_economy_ticket_inline_view`] (failure path).
/// Dropping a ticket without consuming it leaks budget deduction, a velocity
/// entry, and a hard-rate-limit token — the `#[must_use]` attribute makes this
/// a compile-time warning, and the `Drop` impl logs + debug-asserts so unit
/// tests fail loudly.
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
    /// The budget amount deducted by `scp_runtime_economy::logic::enforce_economy` (if any).
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
    pub consumed: bool,
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
#[must_use]
pub fn commit_economy_ticket(
    mut ticket: EconomyTicket,
) -> Option<scp_protocol::economy::types::Amount> {
    ticket.consumed = true;
    ticket.deducted_cost
}

/// Rolls back every piece of state the ticket represents.
///
/// That is the budget deduction, the velocity entry (via its rollback token,
/// so we do not race concurrent senders), and the hard-rate-limit token (when
/// the Phase 1 path consumed one).
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

/// Owned inputs that cross the sync→async boundary of the authorize split.
///
/// All fields are owned / `Send`, so the async `scp_runtime_economy::helpers::authorize_paid_action_hold`
/// future holds NO `&PerContextState` borrow (which would not be `Send`).
#[allow(dead_code)]
pub struct OwnedAuthInputs {
    /// The payment adapter that places the hold.
    pub adapter: Arc<dyn scp_runtime_types::economy::adapter::PaymentAdapterDyn>,
    /// The context's economic policy, cloned out of the state.
    pub policy: scp_protocol::economy::types::EconomicPolicy,
    /// The paid action being authorized.
    pub action_type: PaidActionType,
    /// The metrics the policy prices the action from.
    pub metrics: ObservableMetrics,
}

/// Record a verified receipt in the bounded `payment_receipts` ring.
///
/// This is the buffer half of
/// `scp_runtime_economy::helpers::surface_paid_action_receipt`, and it takes
/// only the `&mut VecDeque<PaymentReceipt>` field.
///
/// Spec §19.11: backs the `payment_history` query — NOT the durable Merkle log.
/// Bounded oldest-evicted ring at the same capacity as the sibling
/// `receive_buffer` so a long-lived paid context cannot grow this buffer without
/// limit (memory-growth `DoS`). Evicts the oldest before pushing the newest once
/// the buffer is full.
#[allow(dead_code)]
pub fn record_payment_receipt(
    payment_receipts: &mut std::collections::VecDeque<PaymentReceipt>,
    receipt: &PaymentReceipt,
) {
    if payment_receipts.len() >= scp_protocol::context::membership::DEFAULT_BUFFER_CAPACITY {
        payment_receipts.pop_front();
    }
    payment_receipts.push_back(receipt.clone());
}

/// Voids a paid action authorization on failure (escrow rollback).
///
/// Calls `adapter.void` to release the escrow hold. Best-effort: logs
/// but does not propagate void failures.
// Transitional Phase 2A surface: messaging/lifecycle call the legacy
// twins until those domains migrate to actor-owned state.
//
// ADR-049 §9 Class-S cell seam: takes NO per-context state — it touches only the
// adapter on the authorization. The former `&mut PerContextState` parameter was
// unused (`_state`); it is dropped rather than narrowed because this is an `async`
// fn and a `&PerContextState` held across the void `.await` is not `Send`
// (`PerContextState` is `!Sync`). Both callers (the join tail and the send path)
// drop the now-removed argument — a mechanical, behaviour-neutral call-site edit.
#[allow(dead_code)]
pub async fn void_paid_action(_deps: &ActorDeps, auth: PaidActionAuthorization, context_id: &str) {
    if let Some(ref authorization) = auth.prepared.envelope.authorization
        && let Err(e) = auth.adapter.void_dyn(authorization).await
    {
        tracing::warn!(context_id, "failed to void payment authorization: {e}");
    }
}

/// Runs the full cryptographic + spending validation pipeline on a
/// spending UCAN, then maps any failure into a `ContextError` with the
/// appropriate SCP-ECON error code.
///
/// Splitting this out of `scp_runtime_economy::logic::enforce_economy` keeps the latter focused on
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
///
/// # Errors
///
/// [`ContextError::PermissionDenied`] (`SCP-ECON-12065`) when any check fails.
pub fn validate_spending_ucan_or_error<S: std::hash::BuildHasher>(
    spending: &scp_protocol::crypto::ucan::UcanToken,
    actor_did: &DID,
    context_id: &str,
    nonce_tracker: &mut scp_protocol::crypto::ucan::nonce::NonceTracker<Arc<dyn scp_clock::Clock>>,
    revoked_cids: &HashSet<String, S>,
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
