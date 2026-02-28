//! Invitation evaluation pipeline for SCP context invitations.
//!
//! When the SDK receives a context invitation, it evaluates in strict
//! sequential order:
//!
//! 1. **Template check** -- If the invitation includes a template ID, validate
//!    that the context params match the template exactly. Reject if params don't
//!    match (prevents template spoofing).
//! 2. **Economic policy check** -- If the context has an `EconomicPolicy`,
//!    verify that a spending UCAN exists covering expected costs, a compatible
//!    payment adapter is configured, and sufficient balance is available. Paid
//!    contexts cannot auto-accept (hard rule, spec section 19.3/19.14).
//! 3. **Auto-accept check** -- If a matching auto-accept policy exists, evaluate
//!    trust requirement, TTL cap, and rate limit. If all conditions pass, join
//!    automatically.
//! 4. **Agent prompt** -- If no auto-accept policy matches, surface the
//!    invitation to the agent/human for decision.
//!
//! See `.docs/standards/sdk-common.md` section "Invitation evaluation" and
//! `.docs/specs/19-economic-governance.md` section 19.3.

use std::time::{Duration, Instant};

use crate::context::params::ContextParams;
use crate::context::policy::{AutoAcceptPolicy, RateLimit, TrustRequirement, auto_accept_allowed};
use crate::context::templates::validate_against_template;
use crate::identity::DID;

// ---------------------------------------------------------------------------
// InvitationError
// ---------------------------------------------------------------------------

/// Errors produced by the invitation evaluation pipeline.
///
/// Error codes follow the `SCP-CTX-` prefix (range 2000-2999) as defined in
/// `.docs/standards/sdk-common.md`.
#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    /// Template validation failed: the invitation claims a template but its
    /// context params do not match the template definition.
    #[error("template spoofing detected: {0}")]
    TemplateSpoofing(#[from] crate::context::templates::TemplateError),

    /// The context requires payment but no spending UCAN is available.
    #[error("spending UCAN required: context has economic policy requiring payment")]
    SpendingUcanRequired,

    /// No compatible payment adapter is configured for this context's
    /// accepted adapters.
    #[error(
        "no compatible payment adapter: context accepts {accepted:?}, configured {configured:?}"
    )]
    NoCompatibleAdapter {
        /// Adapters accepted by the context's economic policy.
        accepted: Vec<String>,
        /// Adapters configured locally.
        configured: Vec<String>,
    },

    /// Insufficient balance to cover the estimated cost.
    #[error("insufficient balance: estimated cost {estimated}, available {available}")]
    InsufficientBalance {
        /// The estimated cost for joining.
        estimated: u64,
        /// The available balance.
        available: u64,
    },
}

// ---------------------------------------------------------------------------
// EvaluationDecision
// ---------------------------------------------------------------------------

/// The result of evaluating an invitation through the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationDecision {
    /// The invitation was auto-accepted. The SDK should join automatically.
    AutoAccept,
    /// The invitation should be surfaced to the agent/human for decision.
    /// Contains the full context params and template ID (if present) for
    /// display.
    PromptAgent,
}

// ---------------------------------------------------------------------------
// SpendingContext
// ---------------------------------------------------------------------------

/// Information about the local identity's spending capabilities, provided by
/// the caller to the evaluation pipeline for economic policy checks.
#[derive(Debug, Clone)]
pub struct SpendingContext {
    /// Whether a valid spending UCAN exists covering the expected costs.
    pub has_spending_ucan: bool,
    /// Payment adapter IDs configured locally.
    pub configured_adapters: Vec<String>,
    /// Available balance in the smallest currency unit.
    pub available_balance: u64,
}

// ---------------------------------------------------------------------------
// TrustOracle
// ---------------------------------------------------------------------------

/// Trait for checking trust relationships between identities.
///
/// The invitation evaluation pipeline needs to check whether the inviter
/// satisfies the trust requirement of an auto-accept policy. This trait
/// abstracts over the actual trust-checking mechanism, making the pipeline
/// testable with mock implementations.
pub trait TrustOracle {
    /// Returns `true` if the `inviter` satisfies the given trust requirement
    /// relative to the local identity.
    fn satisfies_trust(&self, inviter: &DID, requirement: &TrustRequirement) -> bool;
}

// ---------------------------------------------------------------------------
// RateLimitTracker
// ---------------------------------------------------------------------------

/// Tracker for global auto-accept rate limiting.
///
/// Maintains timestamps of recent auto-accept events to enforce rate limits.
/// Each instance tracks accepts for a single identity (the local identity
/// receiving invitations). The rate limit is global across all peers, not
/// per-peer.
#[derive(Debug)]
pub struct RateLimitTracker {
    /// Timestamps of recent auto-accept events, per inviter DID.
    accepts: Vec<Instant>,
}

impl RateLimitTracker {
    /// Creates a new empty rate limit tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accepts: Vec::new(),
        }
    }

    /// Records an auto-accept event at the current time.
    pub fn record_accept(&mut self) {
        self.accepts.push(Instant::now());
    }

    /// Records an auto-accept event at a specific instant (for testing).
    pub fn record_accept_at(&mut self, at: Instant) {
        self.accepts.push(at);
    }

    /// Checks whether an additional auto-accept is allowed under the given
    /// rate limit. Prunes expired entries.
    #[must_use]
    pub fn is_allowed(&mut self, limit: &RateLimit) -> bool {
        let now = Instant::now();
        self.prune_expired(now, limit.window);
        self.accepts.len() < limit.max_count as usize
    }

    /// Checks whether an additional auto-accept is allowed at a specific
    /// instant (for testing).
    #[must_use]
    pub fn is_allowed_at(&mut self, limit: &RateLimit, now: Instant) -> bool {
        self.prune_expired(now, limit.window);
        self.accepts.len() < limit.max_count as usize
    }

    /// Removes entries older than `window` before `now`.
    fn prune_expired(&mut self, now: Instant, window: Duration) {
        self.accepts.retain(|&t| {
            // Retain entries within the window. Instant subtraction can panic
            // if `now < t` (should not happen in practice), so use
            // checked_duration_since to be safe.
            now.checked_duration_since(t)
                .is_none_or(|elapsed| elapsed < window)
        });
    }
}

impl Default for RateLimitTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// evaluate_invitation -- the main pipeline
// ---------------------------------------------------------------------------

/// Evaluates a context invitation through the sequential pipeline.
///
/// # Pipeline order (strictly sequential)
///
/// 1. **Template check** -- Validates params against template if present.
/// 2. **Economic policy check** -- If the context has economic policy requiring
///    payment, verifies spending UCAN, compatible adapter, and balance.
///    Paid contexts always prompt the agent (never auto-accept).
/// 3. **Auto-accept check** -- Evaluates trust, TTL cap, and rate limit against
///    a matching auto-accept policy.
/// 4. **Agent prompt** -- Falls through if no auto-accept matches.
///
/// # Errors
///
/// Returns [`InvitationError::TemplateSpoofing`] if template validation fails
/// (step 1).
///
/// Returns economic policy errors if the context requires payment but the
/// local identity cannot satisfy the requirements (step 2).
///
/// # Returns
///
/// [`EvaluationDecision::AutoAccept`] if a matching auto-accept policy passes
/// all checks. [`EvaluationDecision::PromptAgent`] if the agent should be
/// prompted (no matching policy, or paid context).
pub fn evaluate_invitation(
    params: &ContextParams,
    inviter: &DID,
    policy: Option<&AutoAcceptPolicy>,
    spending_ctx: Option<&SpendingContext>,
    trust_oracle: &impl TrustOracle,
    rate_tracker: &mut RateLimitTracker,
) -> Result<EvaluationDecision, InvitationError> {
    // Step 1: Template check.
    // If the invitation includes a template ID, validate that the context
    // params match the template exactly. Reject on mismatch (template spoofing).
    validate_against_template(params)?;

    // Step 2: Economic policy check.
    // Runs after template check but before auto-accept. Paid contexts cannot
    // auto-accept (hard rule, spec 19.3/19.14).
    if crate::context::policy::requires_payment(params) {
        let ctx = spending_ctx.ok_or(InvitationError::SpendingUcanRequired)?;

        if !ctx.has_spending_ucan {
            return Err(InvitationError::SpendingUcanRequired);
        }

        // Check compatible payment adapter.
        if let Some(ref econ) = params.economic_policy {
            let has_compatible = econ
                .payment_adapters
                .iter()
                .any(|accepted| ctx.configured_adapters.contains(accepted));

            if !has_compatible {
                return Err(InvitationError::NoCompatibleAdapter {
                    accepted: econ.payment_adapters.clone(),
                    configured: ctx.configured_adapters.clone(),
                });
            }

            // Check balance covers at least the per_join cost (if any).
            if let Some(ref per_join) = econ.cost_schedule.per_join
                && ctx.available_balance < per_join.value() {
                    return Err(InvitationError::InsufficientBalance {
                        estimated: per_join.value(),
                        available: ctx.available_balance,
                    });
                }
        }

        // Paid contexts always prompt agent -- never auto-accept.
        return Ok(EvaluationDecision::PromptAgent);
    }

    // Step 3: Auto-accept check.
    // Only if a policy is provided AND hard constraints pass.
    if let Some(policy) = policy
        && auto_accept_allowed(params) {
            // 3a. Template match: policy must match the invitation's template.
            let template_matches = params
                .template_id == Some(policy.template);

            if template_matches {
                // 3b. Trust requirement.
                if trust_oracle.satisfies_trust(inviter, &policy.from) {
                    // 3c. TTL cap.
                    let ttl_ok = match (&policy.max_ttl, &params.ttl) {
                        (Some(max), Some(actual)) => actual <= max,
                        // No TTL = unlimited but policy has a cap. This is
                        // context-dependent; a persistent context with no
                        // TTL is fine if the policy allows it (max_ttl is a
                        // cap, not a requirement). No cap = any TTL OK.
                        (Some(_), None) | (None, _) => true,
                    };

                    if ttl_ok {
                        // 3d. Rate limit.
                        let rate_ok = policy.rate_limit.as_ref().is_none_or(|limit| rate_tracker.is_allowed(limit));

                        if rate_ok {
                            rate_tracker.record_accept();
                            return Ok(EvaluationDecision::AutoAccept);
                        }
                    }
                }
            }
        }

    // Step 4: Agent prompt.
    // No auto-accept policy matched or conditions not met.
    Ok(EvaluationDecision::PromptAgent)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::params::{Capability, ContextMode, ContextParams, TemplateId};
    use crate::context::policy::{AutoAcceptPolicy, RateLimit, TrustRequirement};
    use crate::economy::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};
    use crate::identity::DID;
    use std::time::Duration;

    // --- Test TrustOracle implementation ---

    /// A simple trust oracle for testing that always returns a fixed value.
    struct AlwaysTrust(bool);

    impl TrustOracle for AlwaysTrust {
        fn satisfies_trust(&self, _inviter: &DID, _requirement: &TrustRequirement) -> bool {
            self.0
        }
    }

    /// A trust oracle that checks the explicit DID list.
    struct ExplicitTrust {
        trusted_dids: Vec<DID>,
    }

    impl TrustOracle for ExplicitTrust {
        fn satisfies_trust(&self, inviter: &DID, requirement: &TrustRequirement) -> bool {
            match requirement {
                TrustRequirement::Any => true,
                TrustRequirement::SharedContext => self.trusted_dids.contains(inviter),
                TrustRequirement::Explicit(dids) => dids.contains(inviter),
            }
        }
    }

    // --- Helper constructors ---

    fn bilateral_ephemeral_params(ttl: Duration) -> ContextParams {
        let mut params = ContextParams::from_template(TemplateId::BilateralEphemeral);
        params.ttl = Some(ttl);
        params
    }

    fn bilateral_persistent_params() -> ContextParams {
        ContextParams::from_template(TemplateId::BilateralPersistent)
    }

    fn alice() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    fn default_policy() -> AutoAcceptPolicy {
        AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: Some(Duration::from_secs(600)),
            rate_limit: Some(RateLimit::per_hour(5)),
        }
    }

    // -----------------------------------------------------------------------
    // Step 1: Template check
    // -----------------------------------------------------------------------

    #[test]
    fn valid_template_passes() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&default_policy()),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn spoofed_template_with_tool_capabilities_rejected() {
        // Invitation claims bilateral-ephemeral but includes tool capabilities.
        let mut params = bilateral_ephemeral_params(Duration::from_secs(300));
        params.ceiling.push(Capability::ToolInvokeAll);

        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&default_policy()),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvitationError::TemplateSpoofing(_)),
            "expected TemplateSpoofing, got: {err:?}"
        );
    }

    #[test]
    fn spoofed_template_wrong_mode_rejected() {
        // Claims bilateral-ephemeral but sets Broadcast mode.
        let mut params = bilateral_ephemeral_params(Duration::from_secs(300));
        params.mode = ContextMode::Broadcast;

        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(matches!(result, Err(InvitationError::TemplateSpoofing(_))));
    }

    #[test]
    fn no_template_skips_template_check() {
        // Explicit params (no template ID) -- no template check.
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    // -----------------------------------------------------------------------
    // Step 2: Economic policy check
    // -----------------------------------------------------------------------

    #[test]
    fn paid_context_without_spending_ucan_rejected() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            None, // No spending context provided
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(matches!(result, Err(InvitationError::SpendingUcanRequired)));
    }

    #[test]
    fn paid_context_without_spending_ucan_flag_rejected() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        let spending = SpendingContext {
            has_spending_ucan: false,
            configured_adapters: vec!["x402".to_owned()],
            available_balance: 1000,
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            Some(&spending),
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(matches!(result, Err(InvitationError::SpendingUcanRequired)));
    }

    #[test]
    fn paid_context_no_compatible_adapter_rejected() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["lightning".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        let spending = SpendingContext {
            has_spending_ucan: true,
            configured_adapters: vec!["x402".to_owned()], // No lightning
            available_balance: 1000,
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            Some(&spending),
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(matches!(
            result,
            Err(InvitationError::NoCompatibleAdapter { .. })
        ));
    }

    #[test]
    fn paid_context_insufficient_balance_rejected() {
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: None,
                    per_tool_invoke: None,
                    per_join: Some(Amount(500)),
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        let spending = SpendingContext {
            has_spending_ucan: true,
            configured_adapters: vec!["x402".to_owned()],
            available_balance: 100, // Less than per_join cost of 500
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            Some(&spending),
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert!(matches!(
            result,
            Err(InvitationError::InsufficientBalance {
                estimated: 500,
                available: 100,
            })
        ));
    }

    #[test]
    fn paid_context_prompts_agent_never_auto_accepts() {
        // Even with a matching auto-accept policy, paid contexts always prompt.
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            template_id: Some(TemplateId::BilateralEphemeral),
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            // Note: other fields don't match template, but template check will
            // fail first. We skip template check by setting template_id to None.
            ..ContextParams::default()
        };
        // Remove template_id to avoid template check failure
        let mut params_no_template = params;
        params_no_template.template_id = None;

        let spending = SpendingContext {
            has_spending_ucan: true,
            configured_adapters: vec!["x402".to_owned()],
            available_balance: 10000,
        };
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: None,
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params_no_template,
            &bob(),
            Some(&policy),
            Some(&spending),
            &AlwaysTrust(true),
            &mut tracker,
        );
        // Paid context = always prompt, never auto-accept.
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    // -----------------------------------------------------------------------
    // Step 3: Auto-accept check
    // -----------------------------------------------------------------------

    #[test]
    fn auto_accept_with_matching_policy() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let policy = default_policy();
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::AutoAccept);
    }

    #[test]
    fn auto_accept_template_mismatch_prompts_agent() {
        // Policy is for BilateralEphemeral but invitation is BilateralPersistent.
        let params = bilateral_persistent_params();
        let policy = default_policy(); // For BilateralEphemeral
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    #[test]
    fn auto_accept_trust_requirement_not_met_prompts_agent() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let policy = default_policy();
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(false), // Trust not satisfied
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    #[test]
    fn auto_accept_trust_explicit_list() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Explicit(vec![alice()]),
            max_ttl: Some(Duration::from_secs(600)),
            rate_limit: None,
        };
        let oracle = ExplicitTrust {
            trusted_dids: vec![alice()],
        };
        let mut tracker = RateLimitTracker::new();

        // Bob invites, but only Alice is in the explicit list.
        let result =
            evaluate_invitation(&params, &bob(), Some(&policy), None, &oracle, &mut tracker);
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);

        // Alice invites -- should auto-accept.
        let result = evaluate_invitation(
            &params,
            &alice(),
            Some(&policy),
            None,
            &oracle,
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::AutoAccept);
    }

    #[test]
    fn auto_accept_ttl_exceeds_cap_prompts_agent() {
        let params = bilateral_ephemeral_params(Duration::from_secs(3600)); // 1 hour
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: Some(Duration::from_secs(600)), // Cap at 10 minutes
            rate_limit: None,
        };
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    #[test]
    fn auto_accept_ttl_within_cap_accepts() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300)); // 5 minutes
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: Some(Duration::from_secs(600)), // Cap at 10 minutes
            rate_limit: None,
        };
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::AutoAccept);
    }

    #[test]
    fn auto_accept_no_ttl_cap_accepts_any_ttl() {
        let params = bilateral_ephemeral_params(Duration::from_secs(86400)); // 24 hours
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: None, // No cap
            rate_limit: None,
        };
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::AutoAccept);
    }

    #[test]
    fn auto_accept_rate_limited_prompts_agent() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let policy = AutoAcceptPolicy {
            template: TemplateId::BilateralEphemeral,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: Some(RateLimit {
                max_count: 2,
                window: Duration::from_secs(3600),
            }),
        };
        let mut tracker = RateLimitTracker::new();

        // First two should auto-accept.
        let r1 = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(r1.unwrap(), EvaluationDecision::AutoAccept);

        let r2 = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(r2.unwrap(), EvaluationDecision::AutoAccept);

        // Third should be rate limited -> prompt agent.
        let r3 = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(r3.unwrap(), EvaluationDecision::PromptAgent);
    }

    #[test]
    fn rate_limit_tracker_expires_old_entries() {
        let mut tracker = RateLimitTracker::new();
        let limit = RateLimit {
            max_count: 2,
            window: Duration::from_secs(10),
        };

        let t0 = Instant::now();

        // Record two accepts.
        tracker.record_accept_at(t0);
        tracker.record_accept_at(t0 + Duration::from_secs(1));

        // At t0+5, still within window: not allowed (2/2 used).
        assert!(!tracker.is_allowed_at(&limit, t0 + Duration::from_secs(5)));

        // At t0+11, first entry expired: allowed (1/2 used).
        assert!(tracker.is_allowed_at(&limit, t0 + Duration::from_secs(11)));

        // At t0+12, both entries expired: allowed (0/2 used).
        assert!(tracker.is_allowed_at(&limit, t0 + Duration::from_secs(12)));
    }

    // -----------------------------------------------------------------------
    // Step 4: Agent prompt (fallthrough)
    // -----------------------------------------------------------------------

    #[test]
    fn no_policy_prompts_agent() {
        let params = bilateral_ephemeral_params(Duration::from_secs(300));
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            None, // No policy
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    #[test]
    fn no_template_id_in_params_prompts_agent() {
        // Explicit params with no template -- auto-accept requires template match.
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            ..ContextParams::default()
        };
        let policy = default_policy(); // Expects BilateralEphemeral
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    // -----------------------------------------------------------------------
    // Hard rule: tool capabilities block auto-accept
    // -----------------------------------------------------------------------

    #[test]
    fn tool_capabilities_block_auto_accept() {
        // Coordination template includes ToolInvokeAll -- auto-accept should
        // not apply even if policy matches.
        let mut params = ContextParams::from_template(TemplateId::Coordination);
        params.ttl = Some(Duration::from_secs(300));
        let policy = AutoAcceptPolicy {
            template: TemplateId::Coordination,
            from: TrustRequirement::Any,
            max_ttl: None,
            rate_limit: None,
        };
        let mut tracker = RateLimitTracker::new();

        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        // Tool capabilities block auto-accept; falls through to PromptAgent.
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    // -----------------------------------------------------------------------
    // Integration: evaluation order is strictly sequential
    // -----------------------------------------------------------------------

    #[test]
    fn template_check_runs_before_economic_check() {
        // Spoofed template with economic policy. Template check should fail
        // before economic policy is evaluated.
        let mut params = bilateral_ephemeral_params(Duration::from_secs(300));
        params.ceiling.push(Capability::ToolInvokeAll); // Spoofs template
        params.economic_policy = Some(EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: Some(Amount(1)),
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["x402".to_owned()],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkPayee"),
        });

        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        // Should be TemplateSpoofing, not an economic error.
        assert!(matches!(result, Err(InvitationError::TemplateSpoofing(_))));
    }

    #[test]
    fn economic_check_runs_before_auto_accept() {
        // Paid context with auto-accept policy. Economic check should cause
        // PromptAgent before auto-accept is evaluated.
        let params = ContextParams {
            ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
            economic_policy: Some(EconomicPolicy {
                locked: false,
                cost_schedule: CostSchedule {
                    currency: CurrencyCode::from("USD"),
                    per_message: Some(Amount(1)),
                    per_tool_invoke: None,
                    per_join: None,
                    per_period: None,
                    per_byte_stored: None,
                },
                payment_adapters: vec!["x402".to_owned()],
                pricing_formula: None,
                payee: DID::from("did:dht:z6MkPayee"),
            }),
            ..ContextParams::default()
        };
        let spending = SpendingContext {
            has_spending_ucan: true,
            configured_adapters: vec!["x402".to_owned()],
            available_balance: 10000,
        };
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            None,
            Some(&spending),
            &AlwaysTrust(true),
            &mut tracker,
        );
        // Paid context always prompts agent.
        assert_eq!(result.unwrap(), EvaluationDecision::PromptAgent);
    }

    // -----------------------------------------------------------------------
    // RateLimitTracker unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_tracker_new_is_empty() {
        let mut tracker = RateLimitTracker::new();
        let limit = RateLimit::per_hour(5);
        assert!(tracker.is_allowed(&limit));
    }

    #[test]
    fn rate_limit_tracker_default_is_empty() {
        let mut tracker = RateLimitTracker::default();
        let limit = RateLimit::per_hour(5);
        assert!(tracker.is_allowed(&limit));
    }

    #[test]
    fn rate_limit_tracker_zero_limit_blocks_immediately() {
        let mut tracker = RateLimitTracker::new();
        let limit = RateLimit {
            max_count: 0,
            window: Duration::from_secs(3600),
        };
        assert!(!tracker.is_allowed(&limit));
    }

    // -----------------------------------------------------------------------
    // Free context with economic policy (all costs None) allows auto-accept
    // -----------------------------------------------------------------------

    #[test]
    fn free_economic_policy_allows_auto_accept() {
        let mut params = bilateral_ephemeral_params(Duration::from_secs(300));
        params.economic_policy = Some(EconomicPolicy {
            locked: true,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::from("USD"),
                per_message: None,
                per_tool_invoke: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:dht:z6MkFree"),
        });

        let policy = default_policy();
        let mut tracker = RateLimitTracker::new();
        let result = evaluate_invitation(
            &params,
            &bob(),
            Some(&policy),
            None,
            &AlwaysTrust(true),
            &mut tracker,
        );
        assert_eq!(result.unwrap(), EvaluationDecision::AutoAccept);
    }
}
