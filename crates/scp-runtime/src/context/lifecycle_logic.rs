//! Context lifecycle: free-function logic for create, join, leave,
//! restore, export, import. Hoisted out of the deleted `manager/`
//! directory in ADR-049 commit 12; the helpers in
//! [`crate::context::lifecycle_helpers`] call into these primitives.

use std::collections::HashMap;

use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;

use scp_identity::DID;

/// Builds an [`IdentityDepthAssessment`] for a member in a context.
///
/// Shared by `evaluate_sybil_resistance` (join path) and `check_proposer_eligibility`
/// (governance path). Populates trust signals from available context state:
///
/// - **`ParticipationHistory`** — participation duration from the member's
///   cached `ParticipationRecord` (§9.3 trust signal table row 3).
/// - **`ParticipationRecord`** — participation count from the same record
///   (§9.3 row 4). Strength = number of events by the member.
/// - **`EconomicActivity`** — total spend from the budget tracker (§9.3
///   row 5 / §19). Only populated if the member has budget state.
///
/// External signals (social attestation, device attestation, endorsements)
/// require DID document resolution and attestation verification, which
/// are not yet wired at the `ContextManager` layer. Those categories remain
/// empty until the trust signal provider infrastructure is built.
pub(super) fn build_identity_assessment(
    member_did: &DID,
    governance: &super::state::GovernanceState,
    now: u64,
) -> scp_protocol::trust::sybil::IdentityDepthAssessment {
    use scp_protocol::trust::sybil::{TrustSignal, TrustSignalCategory};

    let mut signals = HashMap::new();

    // Populate from participation cache if the member has a record.
    if let Some(record) = governance.participation_cache.get(member_did.as_ref()) {
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            TrustSignal {
                category: TrustSignalCategory::ParticipationHistory,
                verified_at: record.computed_at,
                strength: record.participation_duration_seconds,
                details: None,
            },
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            TrustSignal {
                category: TrustSignalCategory::ParticipationRecord,
                verified_at: record.computed_at,
                strength: record.participation_count,
                details: None,
            },
        );
    }

    // Populate economic activity from budget tracker.
    let total_spent = governance.budget_tracker.total_spent(member_did).0;
    if total_spent > 0 {
        signals.insert(
            TrustSignalCategory::EconomicActivity,
            TrustSignal {
                category: TrustSignalCategory::EconomicActivity,
                verified_at: now,
                strength: total_spent,
                details: None,
            },
        );
    }

    scp_protocol::trust::sybil::IdentityDepthAssessment::new(member_did.clone(), signals, now)
}

/// Validates all consequence rule string fields (defense-in-depth).
///
/// Called from `create_context` to catch internal callers that bypass FFI
/// validation. Rejects control characters, HTML-special characters, and
/// overly long strings.
pub fn validate_consequence_rules(
    rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    config: &scp_protocol::context::params::ConsequenceConfig,
) -> Result<(), ContextCreationError> {
    for rule in rules {
        rule.validate_against_config(config).map_err(|e| {
            ContextCreationError::CreationFailed(format!("consequence rule validation failed: {e}"))
        })?;
    }
    Ok(())
}

/// Maximum permitted future cooldown horizon, in seconds.
///
/// Cooldown timestamps in an imported or restored snapshot are clamped
/// to `now + MAX_COOLDOWN_SECS`. A malicious snapshot that injects
/// `cooldown_until[i] = u64::MAX` would otherwise permanently disable
/// the targeted consequence rule. 30 days is well above any legitimate
/// cooldown window — the longest spec-defined consequence cooldowns are
/// measured in hours — so the clamp is non-disruptive in practice.
pub(super) const MAX_COOLDOWN_SECS: u64 = 30 * 24 * 60 * 60;

/// Sanitizes an imported or restored `cooldown_until` map in place.
///
/// Drops every entry whose key (rule index) is out of bounds for the
/// supplied `consequence_rules` vector — these would otherwise let an
/// attacker inject cooldown state for nonexistent rules and influence
/// future rule evaluation. Clamps every remaining timestamp to
/// `now + MAX_COOLDOWN_SECS`. Both events emit a warning so anomalies
/// are visible at runtime.
///
/// Part of the imported-snapshot validation policy applied to the runtime
/// `ContextManager` import paths.
pub fn sanitize_cooldown_until(
    cooldown_until: &mut HashMap<usize, u64>,
    consequence_rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    now: u64,
    source: &str,
) {
    let max_ts = now.saturating_add(MAX_COOLDOWN_SECS);
    let rule_count = consequence_rules.len();
    cooldown_until.retain(|&rule_index, ts| {
        if rule_index >= rule_count {
            tracing::warn!(
                source = source,
                rule_index,
                rule_count,
                "dropping cooldown_until entry: rule_index out of bounds"
            );
            return false;
        }
        if *ts > max_ts {
            tracing::warn!(
                source = source,
                rule_index,
                original_ts = *ts,
                clamped_ts = max_ts,
                "clamping cooldown_until entry to MAX_COOLDOWN_SECS horizon"
            );
            *ts = max_ts;
        }
        true
    });
}

/// Validates imported `consequence_rules` against `consequence_config` and
/// returns [`ContextError::ImportRejected`] on failure.
///
/// Distinct from [`validate_consequence_rules`] which targets the
/// create-time path and returns [`ContextCreationError`]. This variant
/// is used by `import_context` and `restore_context` so the bridge
/// translators surface the canonical `SCP-CTX-2092` code.
pub fn validate_consequence_rules_for_import(
    rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    config: &scp_protocol::context::params::ConsequenceConfig,
) -> Result<(), ContextError> {
    for (idx, rule) in rules.iter().enumerate() {
        rule.validate_against_config(config)
            .map_err(|e| ContextError::ImportRejected {
                reason: format!("consequence_rules[{idx}] invalid: {e}"),
            })?;
    }
    Ok(())
}

// ADR-049 Phase 2A finalization keystone — type unification (commit 12):
// the legacy `evaluate_sybil_resistance(&PerContextState, ...)` /
// `post_join_bookkeeping(&mut PerContextState, ...)` /
// `enforce_join_economy(&mut PerContextState, ...)` wrappers were carried
// alongside their field-disjoint counterparts only because the legacy
// and actor struct types diverged. With the unified struct (single
// `PerContextState`), each public entry point now takes the field
// sub-borrows directly — callers build them from the unified struct at
// the call site. The legacy `&PerContextState` wrappers are gone.

/// Returns the spec §19.7 default per-DID message pricing configuration.
///
/// Every context now uses the same baseline: per-DID escalating cost for
/// `MessageSend`, `ContextJoin`, and `ToolInvoke`, plus the Matrix-style
/// hard rate limit. The `_economic_policy` parameter is intentionally
/// unused — it is kept in the signature so call-sites stay symmetrical
/// with the old `derive_relay_pricing_config` while documenting that
/// pricing is uniform across all contexts. Per-context pricing
/// customization will land via governance in a follow-up PR.
#[allow(clippy::unnecessary_wraps)] // Option return kept for forward compat
// with per-context pricing customization landing via governance.
pub fn derive_message_pricing(
    _economic_policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
) -> Option<scp_protocol::economy::antispam::ContextMessagePricingConfig> {
    Some(scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default())
}

/// Performs sybil resistance evaluation for a join candidate (#1530).
///
/// Reads the `sybil_policy` directly so callers may pass
/// `state.handle.params().sybil_policy.as_ref()` from the unified
/// [`PerContextState`] (ADR-049 §Decision 1). When `None`, passes
/// unconditionally. When `Some`, constructs an
/// [`IdentityDepthAssessment`] from the member's available trust signals
/// and delegates to [`scp_protocol::trust::sybil::evaluate_sybil_resistance`].
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] if the sybil policy is
/// configured and the assessment fails.
pub fn evaluate_sybil_resistance(
    sybil_policy: Option<&scp_protocol::trust::sybil::ContextSybilPolicy>,
    governance: &super::state::GovernanceState,
    member_did: &DID,
    now: u64,
) -> Result<(), ContextError> {
    let Some(policy) = sybil_policy else {
        tracing::trace!(
            member = %member_did,
            "sybil resistance check: no policy configured, passing"
        );
        return Ok(());
    };

    let assessment = build_identity_assessment(member_did, governance, now);

    scp_protocol::trust::sybil::evaluate_sybil_resistance(&assessment, policy, now, None)
        .map_err(|e| ContextError::PermissionDenied(format!("sybil resistance check failed: {e}")))
}

/// Initializes the per-member participation record for a new member (#1530):
/// computes a `ParticipationRecord` from the merged join event set and inserts it
/// into `participation_cache`. Budget spend is NOT recorded here — that is
/// `enforce_join_economy`'s responsibility (#1537). Takes the `&mut participation_cache` field and a
/// `&ReceiveBuffer` directly so callers may pass disjoint sub-borrows of the
/// unified [`PerContextState`] (ADR-049 §Decision 1) — a cell-holder supplies
/// the cache via `governance_class_c_mut().participation_cache_mut()` and the
/// buffer via `receive_buffer_mut()`, so no whole `&mut GovernanceState` (and no
/// `state_mut()`) is needed.
pub fn post_join_bookkeeping(
    participation_cache: &mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
    >,
    receive_buffer: &scp_protocol::context::membership::ReceiveBuffer,
    context_id: &str,
    member_did: &DID,
    now: u64,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) {
    let context_id_bytes = super::state::context_id_to_bytes(context_id);
    let merkle_root = event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    // Participation-record path consumes only the merged event set;
    // the consequence window anchor is not used here.
    let (join_events, _convergent_now) =
        super::governance_logic::event_log_entries_for_consequences(
            receive_buffer,
            context_id,
            now,
            event_log,
        );
    if !join_events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            &join_events,
            member_did.as_ref(),
            context_id,
            merkle_root,
            now,
        )
    {
        participation_cache.insert(member_did.to_string(), record);
    }
}

/// Enforces economic policy for context joins (#1537, #1593).
///
/// Checks auto-accept guard, then delegates to the unified
/// `enforce_economy` which evaluates join cost, checks spending UCAN
/// AND-composition (spec §19.5), and records spend against the joiner's
/// budget. Takes a `&mut GovernanceState` and `member_count` directly so
/// callers may pass disjoint sub-borrows of the unified
/// [`PerContextState`] (ADR-049 §Decision 1).
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] if the auto-accept guard
/// rejects, or any error surfaced by `enforce_economy`.
#[allow(clippy::too_many_arguments)]
pub fn enforce_join_economy(
    governance: &mut super::state::GovernanceState,
    member_count: usize,
    joiner_did: &DID,
    now: u64,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    context_id: &str,
    clock: &dyn scp_primitives::Clock,
    key_resolver: &scp_protocol::context::governance::KeyResolver,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    if scp_protocol::economy::policy::auto_accept_blocked_by_economics(
        governance.economic_policy.as_ref(),
    ) {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12030: paid context requires explicit acceptance".into(),
        ));
    }
    let pricing_default =
        scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default();
    let pricing = governance
        .message_pricing
        .as_ref()
        .unwrap_or(&pricing_default);
    super::economy_logic::enforce_economy(super::economy_logic::EnforceEconomyRequest {
        economic_policy: governance.economic_policy.as_ref(),
        budget_tracker: &mut governance.budget_tracker,
        velocity_tracker: &governance.velocity_tracker,
        member_count,
        action_type: scp_protocol::economy::types::PaidActionType::ContextJoin,
        actor_did: joiner_did,
        now,
        spending_ucan,
        action_label: "context:join",
        context_id,
        clock,
        pricing,
        nonce_tracker: &mut governance.class_s.spending_nonce_tracker,
        revoked_spending_ucan_cids: &governance.revoked_spending_ucan_cids,
        key_resolver,
    })
}
