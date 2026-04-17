//! Auto-accept policy types and pure evaluation functions for SCP context invitations.
//!
//! Pure sync types and constraint checks. Storage-dependent async functions
//! remain in `scp-runtime::context::policy`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::params::{Capability, ContextParams, TemplateId};
use scp_primitives::DID;

// ---------------------------------------------------------------------------
// TrustRequirement
// ---------------------------------------------------------------------------

/// Trust requirement for auto-accept policy evaluation.
///
/// Determines the minimum trust level an inviter must meet for the policy to
/// trigger automatic acceptance. See `.docs/standards/sdk-common.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustRequirement {
    /// Accept from any identity. Least restrictive.
    Any,
    /// Accept only from identities that share at least one active context
    /// with this identity.
    SharedContext,
    /// Accept only from identities explicitly listed by DID.
    Explicit(Vec<DID>),
}

// ---------------------------------------------------------------------------
// RateLimit
// ---------------------------------------------------------------------------

/// Rate limit for auto-accept policy evaluation.
///
/// Limits how frequently auto-accept can trigger within a rolling window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of auto-accepts allowed within `window`.
    pub max_count: u32,
    /// Rolling window duration. Effective resolution is one second;
    /// sub-second components are truncated during rate limit evaluation.
    pub window: Duration,
}

impl RateLimit {
    /// Creates a rate limit of `count` auto-accepts per hour.
    #[must_use]
    pub const fn per_hour(count: u32) -> Self {
        Self {
            max_count: count,
            window: Duration::from_hours(1),
        }
    }
}

// ---------------------------------------------------------------------------
// AutoAcceptPolicy
// ---------------------------------------------------------------------------

/// Auto-accept policy for incoming context invitations.
///
/// Configured per-identity and stored locally (never transmitted). When the
/// SDK receives a context invitation, the auto-accept evaluation pipeline
/// checks for a matching policy. If all conditions pass, the invitation is
/// accepted automatically.
///
/// See `.docs/standards/sdk-common.md` section "Auto-Accept Policies".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoAcceptPolicy {
    /// The template this policy applies to. Only invitations for contexts
    /// matching this template trigger auto-accept evaluation.
    pub template: TemplateId,
    /// Trust requirement the inviter must satisfy.
    pub from: TrustRequirement,
    /// Maximum TTL for auto-accepted contexts. Invitations for contexts with
    /// TTL exceeding this value are not auto-accepted. `None` means no TTL cap.
    pub max_ttl: Option<Duration>,
    /// Rate limit on auto-accept triggers. `None` means no rate limit.
    pub rate_limit: Option<RateLimit>,
}

// ---------------------------------------------------------------------------
// Hard rule checks
// ---------------------------------------------------------------------------

/// Returns `true` if the context params contain any tool-related capability
/// in the ceiling.
///
/// Tool-related capabilities: `ToolInvokeAll`, `ToolInvoke(_)`, `ToolRegister`.
///
/// **Non-overridable hard constraint:** Auto-accept NEVER applies to contexts
/// whose ceiling includes any of these capabilities. See
/// `.docs/standards/sdk-common.md`.
#[must_use]
pub fn has_tool_capabilities(params: &ContextParams) -> bool {
    params.ceiling.iter().any(|cap| {
        matches!(
            cap,
            Capability::ToolInvokeAll | Capability::ToolInvoke(_) | Capability::ToolRegister
        )
    })
}

/// Returns `true` if the context params have an economic policy that requires
/// payment (any non-zero cost in the cost schedule, or a pricing formula that
/// may produce non-zero costs).
///
/// **Non-overridable hard constraint:** Auto-accept NEVER applies to contexts
/// with economic policy requiring payment. See
/// `.docs/specs/19-economic-governance.md` section 19.3, 19.14.
#[must_use]
pub const fn requires_payment(params: &ContextParams) -> bool {
    let Some(ref econ) = params.economic_policy else {
        return false;
    };
    let cs = &econ.cost_schedule;
    cs.per_message.is_some()
        || cs.per_tool_invoke.is_some()
        || cs.per_join.is_some()
        || cs.per_period.is_some()
        || cs.per_byte_stored.is_some()
        || econ.pricing_formula.is_some()
}

/// Checks whether auto-accept is allowed for the given context params.
///
/// Returns `false` if any hard constraint is violated:
/// - Context ceiling includes tool-related capabilities.
/// - Context has an economic policy requiring payment.
///
/// Returns `true` if auto-accept evaluation may proceed (further checks like
/// template match, trust requirement, TTL cap, and rate limit are the caller's
/// responsibility).
#[must_use]
pub fn auto_accept_allowed(params: &ContextParams) -> bool {
    !has_tool_capabilities(params) && !requires_payment(params)
}
