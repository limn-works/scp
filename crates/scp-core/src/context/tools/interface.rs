//! Cross-context tool interfaces with bidirectional consent and rate limiting.
//!
//! Implements spec section 6.2: cross-context tool interfaces allow structured
//! interaction across context boundaries. The context governs the tool call,
//! not the agent. Both source and target contexts must explicitly approve the
//! interface before any calls are permitted.
//!
//! # Flow
//!
//! 1. Source context admin calls [`expose_tool`] to propose sharing a tool.
//!    This creates a [`ProposeToolInterface`] governance action.
//! 2. On governance approval, an [`InterfaceOffer`] is published (7-day expiry).
//! 3. Target context admin calls [`accept_tool_interface`] with an
//!    [`InboundPolicy`] to accept.
//! 4. Either context may call [`revoke_tool_interface`] to tear down.
//! 5. Participants invoke via [`invoke_cross_context`], which checks both
//!    approvals, enforces dual rate limits, and records events in both contexts.
//!
//! See ADR-010 in `.docs/adrs/phase-2.md` and spec §6.2.0.1, §6.2.0.2.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lifecycle::{ToolStatus, sha256_json};
use super::registry::{ToolRegistration, ToolRegistry};
use super::{DID, ToolError, ToolId, has_admin_role};
use crate::context::ContextHandle;
use crate::context::roles::ContextRoleState;
use crate::provenance::attach::effective_max_chain_depth;

// ---------------------------------------------------------------------------
// ContextId
// ---------------------------------------------------------------------------

/// Context identifier for cross-context operations.
///
/// Same underlying type as used elsewhere in the codebase (`String`).
pub type ContextId = String;

// ---------------------------------------------------------------------------
// Rate limit defaults (§6.2.0.2)
// ---------------------------------------------------------------------------

/// Default per-interface rate limit: 60 calls per minute (spec §6.2.0.2).
pub const DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE: u32 = 60;

/// Default per-caller rate limit: 10 calls per minute (spec §6.2.0.2).
pub const DEFAULT_PER_CALLER_CALLS_PER_MINUTE: u32 = 10;

/// Default burst allowance: 5 calls above limit within 1 second (spec §6.2.0.2).
pub const DEFAULT_BURST_ALLOWANCE: u32 = 5;

/// Default sliding window duration: 60 seconds (spec §6.2.0.2).
pub const DEFAULT_WINDOW_SECONDS: u64 = 60;

/// Interface offer expiry duration: 7 days (spec §6.2.0.1).
pub const OFFER_EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// OutboundPolicy (§6.2.0.1)
// ---------------------------------------------------------------------------

/// Policy set by the exposing context (Context A) for a tool interface.
///
/// Controls who can call through the interface and under what constraints.
/// See spec §6.2.0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundPolicy {
    /// DIDs in the source context authorized to use this interface.
    /// Empty means any member with the `ToolInterface` capability.
    pub allowed_callers: Vec<DID>,
    /// Maximum calls per minute from the source context's perspective.
    pub max_calls_per_minute: u32,
    /// Maximum request payload size in bytes. Default: 65536 (64 KiB).
    pub max_payload_bytes: u32,
    /// Whether responses must carry provenance. Default: true.
    pub require_provenance: bool,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            allowed_callers: Vec::new(),
            max_calls_per_minute: DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE,
            max_payload_bytes: 65_536,
            require_provenance: true,
        }
    }
}

// ---------------------------------------------------------------------------
// InboundPolicy (§6.2.0.1)
// ---------------------------------------------------------------------------

/// Policy set by the consuming context (Context B) for a tool interface.
///
/// Controls which roles in the source context can call and response constraints.
/// See spec §6.2.0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundPolicy {
    /// Roles in the source context whose members can call. Empty means any role.
    pub allowed_source_roles: Vec<String>,
    /// Maximum calls per minute from the target context's perspective.
    pub max_calls_per_minute: u32,
    /// Maximum response payload size in bytes. Default: 65536 (64 KiB).
    pub max_response_bytes: u32,
    /// Whether callers must present spending UCANs. Default: false.
    pub require_spending_ucan: bool,
}

impl Default for InboundPolicy {
    fn default() -> Self {
        Self {
            allowed_source_roles: Vec::new(),
            max_calls_per_minute: DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE,
            max_response_bytes: 65_536,
            require_spending_ucan: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Consent protocol events (§6.2.0.1)
// ---------------------------------------------------------------------------

/// Governance action: propose exposing a tool to another context (§6.2.0.1 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeToolInterface {
    /// The tool to expose.
    pub tool_id: ToolId,
    /// The context to expose the tool to.
    pub target_context: ContextId,
    /// Outbound policy for the interface.
    pub outbound_policy: OutboundPolicy,
    /// Per-interface rate limit (calls per minute).
    pub max_calls_per_minute: u32,
}

/// Published after governance approval of a tool interface proposal (§6.2.0.1 step 3).
///
/// The offer carries the full tool schema and outbound policy. It expires after
/// 7 days if not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceOffer {
    /// `SHA-256(source_context_id || tool_id || target_context_id || timestamp)`.
    pub offer_id: [u8; 32],
    /// The context exposing the tool.
    pub source_context: ContextId,
    /// The context the tool is offered to.
    pub target_context: ContextId,
    /// Full tool registration (schema, metadata).
    pub tool_schema: ToolRegistration,
    /// Outbound policy set by the source context.
    pub outbound_policy: OutboundPolicy,
    /// Unix timestamp (ms) when the offer expires (7 days from creation).
    pub expires_at: u64,
}

impl InterfaceOffer {
    /// Computes the offer ID as `SHA-256(source_context || tool_id || target_context || timestamp)`.
    #[must_use]
    pub fn compute_offer_id(
        source_context: &str,
        tool_id: &str,
        target_context: &str,
        timestamp: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(source_context.as_bytes());
        hasher.update(tool_id.as_bytes());
        hasher.update(target_context.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.finalize().into()
    }

    /// Returns whether this offer has expired relative to the given timestamp.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at
    }
}

/// Governance action: accept a tool interface offer (§6.2.0.1 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptToolInterface {
    /// The offer being accepted (must match an outstanding `InterfaceOffer`).
    pub offer_id: [u8; 32],
    /// Inbound policy set by the accepting context.
    pub inbound_policy: InboundPolicy,
}

/// Governance action: revoke a tool interface (§6.2.0.1 step 5).
///
/// Either context can revoke unilaterally. Recorded in the revoking context's
/// event log as an `InterfaceRevoked` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeToolInterface {
    /// The interface being revoked (same as the offer ID that established it).
    pub interface_id: [u8; 32],
}

/// Event recorded when both contexts have approved an interface (§6.2.0.1 step 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceEstablished {
    /// The interface/offer ID.
    pub interface_id: [u8; 32],
    /// Source context.
    pub source_context: ContextId,
    /// Target context.
    pub target_context: ContextId,
    /// Tool being shared.
    pub tool_id: ToolId,
    /// Unix timestamp (ms) when established.
    pub established_at: u64,
}

/// Event recorded when an interface is revoked (§6.2.0.1 step 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceRevoked {
    /// The interface being revoked.
    pub interface_id: [u8; 32],
    /// The context that initiated the revocation.
    pub revoking_context: ContextId,
    /// Unix timestamp (ms) when revoked.
    pub revoked_at: u64,
}

// ---------------------------------------------------------------------------
// RateLimit
// ---------------------------------------------------------------------------

/// Rate limit configuration for a cross-context tool interface.
///
/// Tracks the maximum number of calls permitted within a sliding time window.
/// The `current_count` and `window_start` fields are mutable state that is
/// updated on each invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of calls permitted within the time window.
    pub max_calls: u64,
    /// Duration of the sliding time window.
    pub window: Duration,
    /// Number of calls made in the current window.
    pub current_count: u64,
    /// Start of the current window as Unix timestamp in milliseconds.
    pub window_start: u64,
}

impl RateLimit {
    /// Creates a new rate limit with the given maximum calls and window duration.
    ///
    /// Initializes `current_count` to 0 and `window_start` to the current time.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    pub fn new(max_calls: u64, window: Duration) -> Result<Self, crate::time::ClockError> {
        Ok(Self {
            max_calls,
            window,
            current_count: 0,
            window_start: crate::time::now_millis()?,
        })
    }

    /// Checks whether a call is permitted under the current rate limit.
    ///
    /// If the current window has expired, resets the counter and starts a new
    /// window. Returns `true` if the call is permitted (count < max), `false`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    #[allow(clippy::cast_possible_truncation)]
    fn check_and_increment(&mut self) -> Result<bool, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;

        // If the window has expired, reset.
        if now.saturating_sub(self.window_start) >= window_ms {
            self.current_count = 0;
            self.window_start = now;
        }

        if self.current_count < self.max_calls {
            self.current_count += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// PerCallerRateLimit (§6.2.0.2)
// ---------------------------------------------------------------------------

/// Per-caller rate limiter for cross-context tool interfaces (spec §6.2.0.2).
///
/// Tracks per-DID call counts independently of the per-interface limit.
/// Default: 10 calls/minute per caller. Prevents a single caller from
/// monopolizing an interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCallerRateLimit {
    /// Maximum calls per caller within the window.
    pub max_calls_per_caller: u64,
    /// Sliding window duration.
    pub window: Duration,
    /// Per-caller counters: DID -> (count, `window_start_ms`).
    pub callers: HashMap<DID, (u64, u64)>,
}

impl PerCallerRateLimit {
    /// Creates a new per-caller rate limiter with the given limit and window.
    #[must_use]
    pub fn new(max_calls_per_caller: u64, window: Duration) -> Self {
        Self {
            max_calls_per_caller,
            window,
            callers: HashMap::new(),
        }
    }

    /// Checks whether a specific caller is within their per-caller rate limit.
    ///
    /// Returns `true` if the call is permitted, `false` if the caller has
    /// exceeded their individual limit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    #[allow(clippy::cast_possible_truncation)]
    pub fn check_and_increment(
        &mut self,
        caller_did: &DID,
    ) -> Result<bool, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;

        let (count, window_start) = self.callers.entry(caller_did.clone()).or_insert((0, now));

        // If the window has expired for this caller, reset.
        if now.saturating_sub(*window_start) >= window_ms {
            *count = 0;
            *window_start = now;
        }

        if *count < self.max_calls_per_caller {
            *count += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// ToolInterface
// ---------------------------------------------------------------------------

/// A cross-context tool interface with bidirectional consent and dual policies.
///
/// Represents an agreement between two contexts to share access to a specific
/// tool. Both contexts must approve the interface before any calls are
/// permitted. Dual rate limiting (per-interface + per-caller) is enforced.
///
/// See ADR-010 section 6 and spec section 6.2, §6.2.0.1, §6.2.0.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInterface {
    /// The context exposing (sourcing) the tool.
    pub source_context: ContextId,
    /// The context consuming (targeting) the tool.
    pub target_context: ContextId,
    /// The tool being shared across contexts.
    pub tool_id: ToolId,
    /// Optional per-interface rate limit for calls through this interface.
    pub rate_limit: Option<RateLimit>,
    /// Per-caller rate limiter (spec §6.2.0.2). Default: 10 calls/min per caller.
    pub per_caller_rate_limit: Option<PerCallerRateLimit>,
    /// Whether the source context has approved the interface.
    pub approved_by_source: bool,
    /// Whether the target context has approved the interface.
    pub approved_by_target: bool,
    /// Outbound policy set by the source context (§6.2.0.1).
    pub outbound_policy: Option<OutboundPolicy>,
    /// Inbound policy set by the target context (§6.2.0.1).
    pub inbound_policy: Option<InboundPolicy>,
}

// ---------------------------------------------------------------------------
// CrossContextEvent (event log integration)
// ---------------------------------------------------------------------------

/// Event payload for a cross-context tool invocation in the event log.
///
/// Both source and target contexts record this event to maintain full
/// provenance of cross-context calls. See protocol tenet 1: "Provenance
/// everywhere."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContextToolEvent {
    /// UUID v4 request identifier.
    pub request_id: String,
    /// The tool that was invoked.
    pub tool_id: ToolId,
    /// The context that initiated the call (source).
    pub source_context: ContextId,
    /// The context that received the call (target).
    pub target_context: ContextId,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// Terminal status of the invocation.
    pub status: ToolStatus,
    /// SHA-256 hash of the input (hex-encoded).
    pub input_hash: String,
    /// SHA-256 hash of the output (hex-encoded), if output was produced.
    pub output_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// expose_tool
// ---------------------------------------------------------------------------

/// Initiates a cross-context tool interface proposal from the source context.
///
/// The caller (admin of the source context) proposes sharing a specific tool
/// with the target context. The returned [`ToolInterface`] has
/// `approved_by_source = true` and `approved_by_target = false`. The target
/// context must call [`accept_tool_interface`] to complete the handshake.
///
/// Creates the interface with an [`OutboundPolicy`] (set by source context) and
/// a default per-caller rate limit of 10 calls/min (spec §6.2.0.2).
///
/// # Arguments
///
/// * `context` - The source context handle.
/// * `tool_id` - The ID of the tool to expose.
/// * `to_context` - The target context ID.
/// * `role_state` - The source context's role state for capability checking.
/// * `admin_did` - The DID of the admin proposing the interface.
/// * `registry` - The source context's tool registry.
/// * `rate_limit` - Optional per-interface rate limit.
/// * `outbound_policy` - Optional outbound policy (defaults to [`OutboundPolicy::default()`]).
///
/// # Errors
///
/// Returns [`ToolError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`ToolError::ToolNotFound`] if the tool is not in the registry.
#[allow(clippy::too_many_arguments)]
pub fn expose_tool(
    context: &ContextHandle,
    tool_id: &ToolId,
    to_context: &ContextId,
    role_state: &ContextRoleState,
    admin_did: &str,
    registry: &ToolRegistry,
    rate_limit: Option<RateLimit>,
    outbound_policy: Option<OutboundPolicy>,
) -> Result<ToolInterface, ToolError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(ToolError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the tool exists in the source context's registry.
    if !registry.contains(tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        });
    }

    let default_window = Duration::from_secs(DEFAULT_WINDOW_SECONDS);
    Ok(ToolInterface {
        source_context: context.context_id().to_owned(),
        target_context: to_context.to_owned(),
        tool_id: tool_id.to_owned(),
        rate_limit,
        per_caller_rate_limit: Some(PerCallerRateLimit::new(
            u64::from(DEFAULT_PER_CALLER_CALLS_PER_MINUTE),
            default_window,
        )),
        approved_by_source: true,
        approved_by_target: false,
        outbound_policy: Some(outbound_policy.unwrap_or_default()),
        inbound_policy: None,
    })
}

/// Creates an [`InterfaceOffer`] from an approved tool interface proposal.
///
/// Called after the source context's governance has approved the proposal.
/// The offer includes the full tool schema and expires after 7 days.
///
/// # Arguments
///
/// * `interface` - The approved tool interface.
/// * `tool_registration` - Full tool registration from the registry.
/// * `timestamp_ms` - Current timestamp in milliseconds.
///
/// # Returns
///
/// An [`InterfaceOffer`] to be published in the source context's event log.
#[must_use]
pub fn create_interface_offer(
    interface: &ToolInterface,
    tool_registration: &ToolRegistration,
    timestamp_ms: u64,
) -> InterfaceOffer {
    let offer_id = InterfaceOffer::compute_offer_id(
        &interface.source_context,
        &interface.tool_id,
        &interface.target_context,
        timestamp_ms,
    );

    let outbound_policy = interface.outbound_policy.clone().unwrap_or_default();

    InterfaceOffer {
        offer_id,
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        tool_schema: tool_registration.clone(),
        outbound_policy,
        expires_at: timestamp_ms.saturating_add(OFFER_EXPIRY_MS),
    }
}

/// Revokes an established tool interface (§6.2.0.1 step 5).
///
/// Either context can revoke unilaterally. Returns an [`InterfaceRevoked`]
/// event to be recorded in the revoking context's event log.
///
/// # Arguments
///
/// * `interface_id` - The interface/offer ID to revoke.
/// * `revoking_context` - The context performing the revocation.
/// * `timestamp_ms` - Current timestamp in milliseconds.
#[must_use]
pub fn revoke_tool_interface(
    interface_id: [u8; 32],
    revoking_context: &ContextId,
    timestamp_ms: u64,
) -> InterfaceRevoked {
    InterfaceRevoked {
        interface_id,
        revoking_context: revoking_context.clone(),
        revoked_at: timestamp_ms,
    }
}

// ---------------------------------------------------------------------------
// accept_tool_interface
// ---------------------------------------------------------------------------

/// Target context accepts a cross-context tool interface.
///
/// Sets `approved_by_target = true` and attaches the target's
/// [`InboundPolicy`]. Both `approved_by_source` and `approved_by_target`
/// must be `true` before calls are permitted.
///
/// The effective rate limit for calls is `min(outbound.max_calls_per_minute,
/// inbound.max_calls_per_minute)` (spec §6.2.0.1).
///
/// # Arguments
///
/// * `context` - The target context handle.
/// * `interface` - The tool interface to accept (mutated in place).
/// * `role_state` - The target context's role state for capability checking.
/// * `admin_did` - The DID of the admin accepting the interface.
/// * `inbound_policy` - Optional inbound policy (defaults to [`InboundPolicy::default()`]).
///
/// # Errors
///
/// Returns [`ToolError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`ToolError::InterfaceContextMismatch`] if the interface's target
/// context does not match the provided context handle.
pub fn accept_tool_interface(
    context: &ContextHandle,
    interface: &mut ToolInterface,
    role_state: &ContextRoleState,
    admin_did: &str,
    inbound_policy: Option<InboundPolicy>,
) -> Result<(), ToolError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(ToolError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the interface targets this context.
    if interface.target_context != context.context_id() {
        return Err(ToolError::InterfaceContextMismatch {
            expected: interface.target_context.clone(),
            actual: context.context_id().to_owned(),
        });
    }

    interface.approved_by_target = true;
    interface.inbound_policy = Some(inbound_policy.unwrap_or_default());
    Ok(())
}

// ---------------------------------------------------------------------------
// invoke_cross_context
// ---------------------------------------------------------------------------

/// Invokes a tool across context boundaries.
///
/// Performs the following checks:
/// 1. Chain depth against the source context's configured max (spec §24.4).
/// 2. Both `approved_by_source` and `approved_by_target` must be `true`.
/// 3. Per-interface rate limit is checked (spec §6.2.0.2).
/// 4. Per-caller rate limit is checked independently (spec §6.2.0.2).
/// 5. Source context governance checks outbound (invoker has tool invoke
///    capability in source context).
/// 6. Target context governance checks inbound (tool exists in target
///    registry and target context is active).
///
/// Returns the tool output along with event payloads for both the source
/// and target event logs.
///
/// # Arguments
///
/// * `source_context` - The source context handle.
/// * `interface` - The cross-context tool interface (mutated for rate limit
///   tracking).
/// * `input` - JSON input to pass to the tool.
/// * `invoker_did` - The DID of the participant invoking the tool.
/// * `source_role_state` - Source context role state for governance checks.
/// * `target_registry` - Target context tool registry.
/// * `chain_depth` - Current cross-context chain depth (0 for first hop).
/// * `executor` - Synchronous executor for the tool (returns Result).
///
/// # Errors
///
/// Returns [`ToolError::ChainDepthExceeded`] if `chain_depth` exceeds the
/// source context's effective max chain depth (default 3, hard max 5).
/// Returns [`ToolError::InterfaceNotApproved`] if either context has not
/// approved the interface.
/// Returns [`ToolError::InterfaceRateLimited`] if either the per-interface
/// or per-caller rate limit is exceeded.
/// Returns [`ToolError::InterfaceAdminRequired`] if the invoker lacks the
/// required capability in the source context.
#[allow(clippy::too_many_arguments)]
pub fn invoke_cross_context<F>(
    source_context: &ContextHandle,
    interface: &mut ToolInterface,
    input: &serde_json::Value,
    invoker_did: &DID,
    source_role_state: &ContextRoleState,
    target_registry: &ToolRegistry,
    chain_depth: u8,
    executor: F,
) -> Result<
    (
        serde_json::Value,
        CrossContextToolEvent,
        CrossContextToolEvent,
    ),
    ToolError,
>
where
    F: FnOnce(&serde_json::Value) -> Result<serde_json::Value, String>,
{
    // 0. Enforce chain depth limit from the source context's configured max
    // (spec §24.4). Falls back to DEFAULT_MAX_CHAIN_DEPTH (3) when unconfigured,
    // clamped to PROTOCOL_HARD_MAX_CHAIN_DEPTH (5).
    let max_depth = effective_max_chain_depth(source_context.params().max_chain_depth);
    if chain_depth > max_depth {
        return Err(ToolError::ChainDepthExceeded {
            depth: chain_depth,
            max_depth,
        });
    }

    // 1. Both sides must have approved.
    if !interface.approved_by_source || !interface.approved_by_target {
        return Err(ToolError::InterfaceNotApproved {
            source_approved: interface.approved_by_source,
            target_approved: interface.approved_by_target,
        });
    }

    // Verify the source context matches the interface.
    if interface.source_context != source_context.context_id() {
        return Err(ToolError::InterfaceContextMismatch {
            expected: interface.source_context.clone(),
            actual: source_context.context_id().to_owned(),
        });
    }

    // 2. Check per-interface rate limit (spec §6.2.0.2).
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut rate_limit) = interface.rate_limit
        && !rate_limit.check_and_increment()?
    {
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = rate_limit.window.as_millis() as u64;
        return Err(ToolError::InterfaceRateLimited {
            max_calls: rate_limit.max_calls,
            window_ms,
        });
    }

    // 3. Check per-caller rate limit independently (spec §6.2.0.2).
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut per_caller_rl) = interface.per_caller_rate_limit
        && !per_caller_rl.check_and_increment(invoker_did)?
    {
        let window_ms = per_caller_rl.window.as_millis() as u64;
        return Err(ToolError::InterfaceRateLimited {
            max_calls: per_caller_rl.max_calls_per_caller,
            window_ms,
        });
    }

    // 4. Source context governance: invoker must have tool invoke capability.
    if !super::invoke::has_tool_invoke_capability(
        source_role_state,
        invoker_did,
        &interface.tool_id,
    ) {
        return Err(ToolError::InterfaceInvokerNotAuthorized {
            did: invoker_did.to_string(),
            tool_id: interface.tool_id.clone(),
        });
    }

    // 5. Target context governance: tool must exist in target registry.
    if !target_registry.contains(&interface.tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: interface.tool_id.clone(),
        });
    }

    // 6. Execute the tool.
    let output =
        executor(input).map_err(|msg| ToolError::InterfaceExecutionFailed { message: msg })?;

    // 7. Build event payloads for both contexts.
    let request_id = uuid::Uuid::new_v4().to_string();
    let input_hash = sha256_json(input);
    let output_hash = Some(sha256_json(&output));

    let source_event = CrossContextToolEvent {
        request_id: request_id.clone(),
        tool_id: interface.tool_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: ToolStatus::Success,
        input_hash: input_hash.clone(),
        output_hash: output_hash.clone(),
    };

    let target_event = CrossContextToolEvent {
        request_id,
        tool_id: interface.tool_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: ToolStatus::Success,
        input_hash,
        output_hash,
    };

    Ok((output, source_event, target_event))
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::context::ContextParams;
    use crate::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use crate::context::tools::registry::{ToolRegistry, ToolSchema, register_tool};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates a test capability ceiling with all capabilities.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::ToolRegister,
            Capability::ToolInvokeAll,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ])
    }

    /// Creates a `ContextRoleState` with a creator that has admin (all) capabilities.
    fn test_role_state(context_id: &str, creator_did: &str) -> ContextRoleState {
        ContextRoleState::new(context_id, creator_did, test_ceiling(), vec![]).unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no admin, no tool invoke).
    fn test_role_state_with_non_admin_member(
        context_id: &str,
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(context_id, creator_did);
        state.members.insert(member_did.to_owned());
        let member_caps: HashSet<Capability> =
            [Capability::MessagesRead, Capability::MessagesWrite]
                .into_iter()
                .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a context handle (in Creating state).
    fn test_context(context_id: &str) -> ContextHandle {
        ContextHandle::new(context_id.to_owned(), ContextParams::default())
    }

    /// Creates a valid tool registration and registers it in a fresh registry.
    fn setup_registry_with_tool(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        let registration = ToolRegistration {
            tool_id: "calculator".to_owned(),
            name: "Calculator".to_owned(),
            description: "A simple calculator".to_owned(),
            schema: ToolSchema {
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "result": {"type": "number"}
                    }
                }),
            },
            implementation_hash: [0xAA; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            economic_metadata: None,
            registered_at: 0,
            signature: Vec::new(),
        };
        register_tool(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Simple synchronous executor that adds two numbers.
    fn add_executor(input: &serde_json::Value) -> Result<serde_json::Value, String> {
        let a = input
            .get("a")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'a'".to_owned())?;
        let b = input
            .get("b")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| "missing field 'b'".to_owned())?;
        Ok(serde_json::json!({"result": a + b}))
    }

    // -----------------------------------------------------------------------
    // expose_tool: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_creates_interface_with_source_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let interface = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            None,
            None,
        )
        .unwrap();

        assert_eq!(interface.source_context, "ctx-source");
        assert_eq!(interface.target_context, "ctx-target");
        assert_eq!(interface.tool_id, "calculator");
        assert!(interface.approved_by_source);
        assert!(!interface.approved_by_target);
        assert!(interface.rate_limit.is_none());
        // Default outbound policy is created
        assert!(interface.outbound_policy.is_some());
        // Per-caller rate limit is created by default
        assert!(interface.per_caller_rate_limit.is_some());
    }

    // -----------------------------------------------------------------------
    // expose_tool: requires admin capability
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_requires_admin_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let source_role_state =
            test_role_state_with_non_admin_member("ctx-source", admin_did, member_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let result = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            member_did,
            &registry,
            None,
            None,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceAdminRequired { .. }),
            "expected InterfaceAdminRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // expose_tool: tool not found
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_rejects_nonexistent_tool() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = ToolRegistry::new(); // Empty registry

        let result = expose_tool(
            &source_context,
            &"nonexistent".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            None,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // expose_tool: with rate limit
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_includes_rate_limit_when_provided() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let rate_limit = RateLimit::new(10, Duration::from_secs(60)).unwrap();
        let interface = expose_tool(
            &source_context,
            &"calculator".to_owned(),
            &"ctx-target".to_owned(),
            &source_role_state,
            admin_did,
            &registry,
            Some(rate_limit),
            None,
        )
        .unwrap();

        assert!(interface.rate_limit.is_some());
        let rl = interface.rate_limit.unwrap();
        assert_eq!(rl.max_calls, 10);
        assert_eq!(rl.window, Duration::from_secs(60));
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_sets_approved_by_target() {
        let admin_did = "did:dht:z6MkAdmin";
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_context = test_context("ctx-target");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            admin_did,
            None,
        );

        assert!(result.is_ok());
        assert!(interface.approved_by_target);
        assert!(interface.approved_by_source);
        // Default inbound policy is created
        assert!(interface.inbound_policy.is_some());
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: requires admin capability
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_requires_admin_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let target_role_state =
            test_role_state_with_non_admin_member("ctx-target", admin_did, member_did);
        let target_context = test_context("ctx-target");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            member_did,
            None,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceAdminRequired { .. }),
            "expected InterfaceAdminRequired, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // accept_tool_interface: context mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tool_interface_rejects_context_mismatch() {
        let admin_did = "did:dht:z6MkAdmin";
        let target_role_state = test_role_state("ctx-wrong", admin_did);
        let target_context = test_context("ctx-wrong");

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = accept_tool_interface(
            &target_context,
            &mut interface,
            &target_role_state,
            admin_did,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceContextMismatch { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_succeeds_with_full_approval() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let input = serde_json::json!({"a": 3, "b": 4});
        let (output, source_event, target_event) = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        )
        .unwrap();

        assert_eq!(output, serde_json::json!({"result": 7.0}));

        // Both events should record the cross-context call.
        assert_eq!(source_event.tool_id, "calculator");
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.status, ToolStatus::Success);
        assert!(!source_event.input_hash.is_empty());
        assert!(source_event.output_hash.is_some());

        assert_eq!(target_event.tool_id, "calculator");
        assert_eq!(target_event.source_context, "ctx-source");
        assert_eq!(target_event.target_context, "ctx-target");
        assert_eq!(target_event.invoker_did, admin_did);

        // Both events share the same request_id.
        assert_eq!(source_event.request_id, target_event.request_id);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: fails when only one side approved
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_fails_when_only_source_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false, // Target has NOT approved
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::InterfaceNotApproved {
                    source_approved: true,
                    target_approved: false,
                }
            ),
            "expected InterfaceNotApproved, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_fails_when_only_target_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: false, // Source has NOT approved
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::InterfaceNotApproved {
                    source_approved: false,
                    target_approved: true,
                }
            ),
            "expected InterfaceNotApproved, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_fails_when_neither_side_approved() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: false,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceNotApproved { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: rate limiting rejects calls beyond limit
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rate_limiting_rejects_beyond_limit() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: Some(RateLimit::new(2, Duration::from_secs(3600)).unwrap()),
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let input = serde_json::json!({"a": 1, "b": 2});

        // First call: should succeed.
        let result1 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );
        assert!(result1.is_ok(), "first call should succeed");

        // Second call: should succeed (at limit).
        let result2 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );
        assert!(result2.is_ok(), "second call should succeed");

        // Third call: should be rejected (over limit).
        let result3 = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );
        assert!(result3.is_err());
        let err = result3.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceRateLimited { max_calls: 2, .. }),
            "expected InterfaceRateLimited, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: both event logs record the call
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_both_event_logs_record_provenance() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let input = serde_json::json!({"a": 10, "b": 20});
        let (output, source_event, target_event) = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        )
        .unwrap();

        // Verify provenance in source event.
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.status, ToolStatus::Success);

        // Verify provenance in target event.
        assert_eq!(target_event.invoker_did, admin_did);
        assert_eq!(target_event.source_context, "ctx-source");
        assert_eq!(target_event.target_context, "ctx-target");
        assert_eq!(target_event.status, ToolStatus::Success);

        // Both events have correct hashes.
        let expected_input_hash = sha256_json(&input);
        let expected_output_hash = sha256_json(&output);
        assert_eq!(source_event.input_hash, expected_input_hash);
        assert_eq!(source_event.output_hash, Some(expected_output_hash.clone()));
        assert_eq!(target_event.input_hash, expected_input_hash);
        assert_eq!(target_event.output_hash, Some(expected_output_hash));

        // Events share the same request_id for correlation.
        assert_eq!(source_event.request_id, target_event.request_id);
        // Request IDs are UUID v4 format.
        assert_eq!(source_event.request_id.len(), 36);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: invoker without capability
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_invoker_without_capability() {
        let admin_did = "did:dht:z6MkAdmin";
        let member_did = "did:dht:z6MkMember";
        let source_role_state =
            test_role_state_with_non_admin_member("ctx-source", admin_did, member_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::InterfaceInvokerNotAuthorized { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: tool not found in target
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_when_tool_not_in_target_registry() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_registry = ToolRegistry::new(); // Empty target registry

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ToolError::ToolNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // RateLimit: window reset
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_resets_after_window_expires() {
        let mut rl = RateLimit {
            max_calls: 1,
            window: Duration::from_millis(1),
            current_count: 1,
            // Set window_start far in the past so the window is expired.
            window_start: 0,
        };

        // Window should have expired, so this should succeed and reset.
        assert!(rl.check_and_increment().unwrap());
        assert_eq!(rl.current_count, 1);
    }

    // -----------------------------------------------------------------------
    // RateLimit: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_serialization_roundtrip() {
        let rl = RateLimit {
            max_calls: 100,
            window: Duration::from_secs(60),
            current_count: 5,
            window_start: 1_000_000,
        };
        let json = serde_json::to_string(&rl).unwrap();
        let deserialized: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(rl, deserialized);
    }

    // -----------------------------------------------------------------------
    // ToolInterface: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn tool_interface_serialization_roundtrip() {
        let interface = ToolInterface {
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            tool_id: "tool-1".to_owned(),
            rate_limit: Some(RateLimit::new(50, Duration::from_secs(120)).unwrap()),
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: Some(OutboundPolicy::default()),
            inbound_policy: None,
        };
        let json = serde_json::to_string(&interface).unwrap();
        let deserialized: ToolInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_context, "ctx-a");
        assert_eq!(deserialized.target_context, "ctx-b");
        assert_eq!(deserialized.tool_id, "tool-1");
        assert!(deserialized.approved_by_source);
        assert!(!deserialized.approved_by_target);
        assert!(deserialized.rate_limit.is_some());
    }

    // -----------------------------------------------------------------------
    // CrossContextToolEvent: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn cross_context_tool_event_serialization_roundtrip() {
        let event = CrossContextToolEvent {
            request_id: "req-1".to_owned(),
            tool_id: "calculator".to_owned(),
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            invoker_did: "did:dht:z6MkTest".into(),
            status: ToolStatus::Success,
            input_hash: "abcd1234".to_owned(),
            output_hash: Some("efgh5678".to_owned()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CrossContextToolEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.tool_id, "calculator");
        assert_eq!(deserialized.status, ToolStatus::Success);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: chain depth exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_chain_depth_exceeding_max() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        // Chain depth 4 exceeds DEFAULT_MAX_CHAIN_DEPTH (3).
        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            4,
            add_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::ChainDepthExceeded {
                    depth: 4,
                    max_depth: 3,
                }
            ),
            "expected ChainDepthExceeded, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_allows_chain_depth_at_max() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        // Chain depth 3 == DEFAULT_MAX_CHAIN_DEPTH, should succeed.
        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            3,
            add_executor,
        );

        assert!(
            result.is_ok(),
            "chain depth at max should succeed: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: executor failure propagates
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_executor_failure_propagates() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let failing_executor = |_input: &serde_json::Value| -> Result<serde_json::Value, String> {
            Err("computation failed".to_owned())
        };

        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            failing_executor,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceExecutionFailed { .. }),
            "expected InterfaceExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation failed"));
    }

    // -----------------------------------------------------------------------
    // OutboundPolicy / InboundPolicy defaults
    // -----------------------------------------------------------------------

    #[test]
    fn outbound_policy_default_values() {
        let policy = OutboundPolicy::default();
        assert!(policy.allowed_callers.is_empty());
        assert_eq!(
            policy.max_calls_per_minute,
            DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE
        );
        assert_eq!(policy.max_payload_bytes, 65_536);
        assert!(policy.require_provenance);
    }

    #[test]
    fn inbound_policy_default_values() {
        let policy = InboundPolicy::default();
        assert!(policy.allowed_source_roles.is_empty());
        assert_eq!(
            policy.max_calls_per_minute,
            DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE
        );
        assert_eq!(policy.max_response_bytes, 65_536);
        assert!(!policy.require_spending_ucan);
    }

    #[test]
    fn outbound_policy_serialization_roundtrip() {
        let policy = OutboundPolicy {
            allowed_callers: vec!["did:dht:z6MkAlice".into()],
            max_calls_per_minute: 30,
            max_payload_bytes: 1024,
            require_provenance: false,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: OutboundPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn inbound_policy_serialization_roundtrip() {
        let policy = InboundPolicy {
            allowed_source_roles: vec!["admin".to_owned()],
            max_calls_per_minute: 20,
            max_response_bytes: 2048,
            require_spending_ucan: true,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: InboundPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    // -----------------------------------------------------------------------
    // Per-caller rate limiting (§6.2.0.2)
    // -----------------------------------------------------------------------

    #[test]
    fn per_caller_rate_limit_tracks_independently() {
        let mut rl = PerCallerRateLimit::new(2, Duration::from_secs(3600));
        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();

        // Alice: 2 calls allowed
        assert!(rl.check_and_increment(&alice).unwrap());
        assert!(rl.check_and_increment(&alice).unwrap());
        assert!(!rl.check_and_increment(&alice).unwrap());

        // Bob: still has 2 calls
        assert!(rl.check_and_increment(&bob).unwrap());
        assert!(rl.check_and_increment(&bob).unwrap());
        assert!(!rl.check_and_increment(&bob).unwrap());
    }

    #[test]
    fn per_caller_rate_limit_window_reset() {
        let mut rl = PerCallerRateLimit::new(1, Duration::from_millis(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        assert!(rl.check_and_increment(&alice).unwrap());
        assert!(!rl.check_and_increment(&alice).unwrap());

        // Set the window start far in the past to simulate window expiry.
        if let Some((_, ws)) = rl.callers.get_mut(&alice) {
            *ws = 0;
        }
        assert!(rl.check_and_increment(&alice).unwrap());
    }

    // -----------------------------------------------------------------------
    // InterfaceOffer / consent protocol
    // -----------------------------------------------------------------------

    #[test]
    fn interface_offer_id_is_deterministic() {
        let id1 = InterfaceOffer::compute_offer_id("ctx-a", "tool-1", "ctx-b", 1000);
        let id2 = InterfaceOffer::compute_offer_id("ctx-a", "tool-1", "ctx-b", 1000);
        assert_eq!(id1, id2);
    }

    #[test]
    fn interface_offer_id_differs_for_different_inputs() {
        let id1 = InterfaceOffer::compute_offer_id("ctx-a", "tool-1", "ctx-b", 1000);
        let id2 = InterfaceOffer::compute_offer_id("ctx-a", "tool-1", "ctx-b", 2000);
        assert_ne!(id1, id2);
    }

    #[test]
    fn interface_offer_expiry() {
        let offer = InterfaceOffer {
            offer_id: [0u8; 32],
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            tool_schema: ToolRegistration {
                tool_id: "t".to_owned(),
                name: "T".to_owned(),
                description: "test".to_owned(),
                schema: ToolSchema {
                    input_schema: serde_json::json!({"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}),
                    output_schema: serde_json::json!({"type": "object", "properties": {"r": {"type": "number"}}}),
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkOp".into(),
                economic_metadata: None,
                registered_at: 0,
                signature: Vec::new(),
            },
            outbound_policy: OutboundPolicy::default(),
            expires_at: 1000 + OFFER_EXPIRY_MS,
        };

        assert!(!offer.is_expired(1000));
        assert!(!offer.is_expired(1000 + OFFER_EXPIRY_MS - 1));
        assert!(offer.is_expired(1000 + OFFER_EXPIRY_MS));
        assert!(offer.is_expired(1000 + OFFER_EXPIRY_MS + 1));
    }

    // -----------------------------------------------------------------------
    // Chain depth reads from context config
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_uses_context_configured_chain_depth() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        // Create a context with max_chain_depth = 1.
        let params = ContextParams {
            max_chain_depth: Some(1),
            ..ContextParams::default()
        };
        let source_context = ContextHandle::new("ctx-source".to_owned(), params);
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        // Depth 1 should succeed (at limit).
        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            1,
            add_executor,
        );
        assert!(result.is_ok());

        // Depth 2 should fail (exceeds configured max of 1).
        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            2,
            add_executor,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                ToolError::ChainDepthExceeded {
                    depth: 2,
                    max_depth: 1
                }
            ),
            "expected ChainDepthExceeded with depth=2, max=1, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Revocation event
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_tool_interface_creates_event() {
        let interface_id = [0xAB; 32];
        let event = revoke_tool_interface(interface_id, &"ctx-a".to_owned(), 5000);
        assert_eq!(event.interface_id, interface_id);
        assert_eq!(event.revoking_context, "ctx-a");
        assert_eq!(event.revoked_at, 5000);
    }
}
