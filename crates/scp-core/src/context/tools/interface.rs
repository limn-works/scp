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

/// Default sliding window duration: 60 seconds (spec §6.2.0.2).
pub const DEFAULT_WINDOW_SECONDS: u64 = 60;

/// Default burst allowance: 5 calls above the per-minute limit within the burst
/// window (spec §6.2.0.2). Configurable range: 0-50.
pub const DEFAULT_BURST_ALLOWANCE: u32 = 5;

/// Default burst window duration: 1 second (spec §6.2.0.2).
pub const DEFAULT_BURST_WINDOW_SECS: u64 = 1;

/// Maximum configurable burst allowance (spec §6.2.0.2).
pub const MAX_BURST_ALLOWANCE: u32 = 50;

/// Interface offer expiry duration: 7 days (spec §6.2.0.1).
pub const OFFER_EXPIRY_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// OutboundPolicy (§6.2.0.1)
// ---------------------------------------------------------------------------

/// Policy set by the exposing context (Context A) for a tool interface.
///
/// Controls who can call through the interface and under what constraints.
/// All fields are enforced in [`invoke_cross_context`]:
/// - `allowed_callers`: checked before execution (empty = any member).
/// - `max_calls_per_minute`: enforced by the per-interface [`RateLimit`].
/// - `max_payload_bytes`: request input size checked before execution.
/// - `require_provenance`: advisory — signals to the caller that
///   responses should carry provenance metadata. Enforcement is the
///   caller's responsibility (the callee cannot force the caller to
///   attach provenance to its own records).
///
/// See spec §6.2.0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundPolicy {
    /// DIDs in the source context authorized to use this interface.
    /// Empty means any member with the `ToolInterface` capability.
    /// Enforced in [`invoke_cross_context`].
    pub allowed_callers: Vec<DID>,
    /// Maximum calls per minute from the source context's perspective.
    /// Enforced by the per-interface [`RateLimit`].
    pub max_calls_per_minute: u32,
    /// Maximum request payload size in bytes. Default: 65536 (64 KiB).
    /// Enforced in [`invoke_cross_context`] by checking serialized input size.
    pub max_payload_bytes: u32,
    /// Whether responses must carry provenance. Default: true.
    /// Advisory: signals expectation to the calling context.
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
/// Fields are enforced in [`invoke_cross_context`]:
/// - `allowed_source_roles`: advisory — role-based filtering is enforced by
///   the source context's governance engine (via `has_tool_invoke_capability`),
///   not repeated here. The field signals the target's expectations.
/// - `max_calls_per_minute`: enforced by the per-interface [`RateLimit`]
///   (effective limit is `min(outbound, inbound)`).
/// - `max_response_bytes`: response size checked after execution.
/// - `require_spending_ucan`: advisory — UCAN validation happens at the
///   governance layer before invocation reaches this function.
///
/// See spec §6.2.0.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundPolicy {
    /// Roles in the source context whose members can call. Empty means any role.
    /// Advisory: role enforcement is the source context governance engine's
    /// responsibility (it checks `has_tool_invoke_capability`).
    pub allowed_source_roles: Vec<String>,
    /// Maximum calls per minute from the target context's perspective.
    /// Enforced by the per-interface [`RateLimit`].
    pub max_calls_per_minute: u32,
    /// Maximum response payload size in bytes. Default: 65536 (64 KiB).
    /// Enforced in [`invoke_cross_context`] by checking serialized output size.
    pub max_response_bytes: u32,
    /// Whether callers must present spending UCANs. Default: false.
    /// Advisory: UCAN validation happens at the governance layer.
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
    /// `SHA-256("SCP-OFFER-ID-V1:" || len(source_context_id) || source_context_id || len(tool_id) || tool_id || len(target_context_id) || target_context_id || timestamp)`.
    /// Domain-separated and length-prefixed (4-byte big-endian) to prevent collisions.
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
    /// Computes the offer ID as `SHA-256("SCP-OFFER-ID-V1:" || len(source_context) || source_context || len(tool_id) || tool_id || len(target_context) || target_context || timestamp)`.
    ///
    /// The domain separator `"SCP-OFFER-ID-V1:"` ensures this hash cannot
    /// collide with hashes from other SCP subsystems. Each string field is
    /// length-prefixed with its byte length as a 4-byte big-endian integer
    /// to prevent concatenation ambiguity (e.g., `("ab", "cd")` vs
    /// `("a", "bcd")`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Protocol IDs are far below u32::MAX bytes.
    pub fn compute_offer_id(
        source_context: &str,
        tool_id: &str,
        target_context: &str,
        timestamp: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OFFER-ID-V1:");
        hasher.update((source_context.len() as u32).to_be_bytes());
        hasher.update(source_context.as_bytes());
        hasher.update((tool_id.len() as u32).to_be_bytes());
        hasher.update(tool_id.as_bytes());
        hasher.update((target_context.len() as u32).to_be_bytes());
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
///
/// Supports burst allowance (spec §6.2.0.2): up to `burst_allowance` calls
/// above `max_calls` are permitted if they occur within `burst_window` of
/// the first burst call. Default: 5 extra calls within 1 second.
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
    /// Number of additional calls allowed above `max_calls` within the burst
    /// window (spec §6.2.0.2). Default: 5. Range: 0-50.
    pub burst_allowance: u32,
    /// Duration of the burst window (spec §6.2.0.2). Default: 1 second.
    pub burst_window: Duration,
    /// Number of burst calls consumed in the current burst window.
    pub burst_count: u32,
    /// Start of the current burst window as Unix timestamp in milliseconds.
    pub burst_window_start: u64,
}

impl RateLimit {
    /// Creates a new rate limit with the given maximum calls and window duration.
    ///
    /// Uses default burst allowance (5 calls within 1 second, spec §6.2.0.2).
    /// Initializes `current_count` to 0 and `window_start` to the current time.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    pub fn new(max_calls: u64, window: Duration) -> Result<Self, crate::time::ClockError> {
        Self::with_burst(
            max_calls,
            window,
            DEFAULT_BURST_ALLOWANCE,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
        )
    }

    /// Creates a new rate limit with custom burst parameters.
    ///
    /// `burst_allowance` is clamped to [`MAX_BURST_ALLOWANCE`] (50).
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    pub fn with_burst(
        max_calls: u64,
        window: Duration,
        burst_allowance: u32,
        burst_window: Duration,
    ) -> Result<Self, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        Ok(Self {
            max_calls,
            window,
            current_count: 0,
            window_start: now,
            burst_allowance: burst_allowance.min(MAX_BURST_ALLOWANCE),
            burst_window,
            burst_count: 0,
            burst_window_start: now,
        })
    }

    /// Checks whether a call is permitted under the current rate limit.
    ///
    /// If the current window has expired, resets the counter and starts a new
    /// window. Returns `true` if the call is permitted (count < max), `false`
    /// otherwise.
    ///
    /// When the base rate limit is exhausted, burst allowance is checked:
    /// up to `burst_allowance` additional calls are permitted if they occur
    /// within `burst_window` of the first burst call (spec §6.2.0.2).
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    #[allow(clippy::cast_possible_truncation)]
    fn check_and_increment(&mut self) -> Result<bool, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;

        // If the window has expired, reset both base and burst counters.
        if now.saturating_sub(self.window_start) >= window_ms {
            self.current_count = 0;
            self.window_start = now;
            self.burst_count = 0;
            self.burst_window_start = now;
        }

        if self.current_count < self.max_calls {
            self.current_count += 1;
            Ok(true)
        } else if self.burst_allowance > 0 {
            // Base limit exhausted — try burst allowance (spec §6.2.0.2).
            // The burst window is a deadline: all burst calls must occur within
            // burst_window of the FIRST burst call. Once burst_allowance is
            // consumed OR burst_window expires, no more burst calls until the
            // base window resets (handled above at the window-expiry check).

            // Lazily anchor the burst window to the first actual burst call,
            // not construction/base-window-reset time (#588 R2-01).
            if self.burst_count == 0 {
                self.burst_window_start = now;
            }

            let burst_window_ms = self.burst_window.as_millis() as u64;

            // If the burst window has expired, burst is dead until base resets.
            if now.saturating_sub(self.burst_window_start) >= burst_window_ms {
                return Ok(false);
            }

            if self.burst_count < self.burst_allowance {
                self.burst_count += 1;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Returns the number of seconds until the current window resets.
    ///
    /// This is the `Retry-After` value per spec §6.2.0.2: the time a caller
    /// must wait before the next call will be accepted. The value is rounded
    /// up so callers never retry too early.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    #[allow(clippy::cast_possible_truncation)]
    pub fn retry_after_secs(&self) -> Result<u64, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        let window_ms = self.window.as_millis() as u64;
        let elapsed = now.saturating_sub(self.window_start);
        let remaining_ms = window_ms.saturating_sub(elapsed);
        // Ceiling division: round up so callers never retry too early.
        Ok(remaining_ms.div_ceil(1000))
    }
}

// ---------------------------------------------------------------------------
// PerCallerRateLimit (§6.2.0.2)
// ---------------------------------------------------------------------------

/// Maximum number of distinct callers tracked before rejecting new callers.
///
/// Prevents unbounded memory growth from a large number of unique DIDs
/// making single calls. When the limit is reached, expired entries are
/// evicted first; if still at capacity, new callers are rejected.
const MAX_TRACKED_CALLERS: usize = 10_000;

/// Per-caller rate limit state for a single DID (spec §6.2.0.2).
///
/// Tracks the base call count, window start, and burst state for one caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerState {
    /// Number of calls within the current base window.
    pub count: u64,
    /// Start of the current base window as Unix timestamp in milliseconds.
    pub window_start: u64,
    /// Number of burst calls consumed in the current burst window.
    pub burst_count: u32,
    /// Start of the current burst window as Unix timestamp in milliseconds.
    pub burst_window_start: u64,
}

/// Per-caller rate limiter for cross-context tool interfaces (spec §6.2.0.2).
///
/// Tracks per-DID call counts independently of the per-interface limit.
/// Default: 10 calls/minute per caller. Prevents a single caller from
/// monopolizing an interface. Expired entries are periodically evicted
/// and the total number of tracked callers is capped at
/// `MAX_TRACKED_CALLERS` to prevent unbounded memory growth.
///
/// Supports burst allowance: up to `burst_allowance` additional calls
/// above `max_calls_per_caller` within the burst window (spec §6.2.0.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCallerRateLimit {
    /// Maximum calls per caller within the window.
    pub max_calls_per_caller: u64,
    /// Sliding window duration.
    pub window: Duration,
    /// Number of additional calls allowed above `max_calls_per_caller` within
    /// the burst window (spec §6.2.0.2). Default: 5. Range: 0-50.
    pub burst_allowance: u32,
    /// Duration of the burst window (spec §6.2.0.2). Default: 1 second.
    pub burst_window: Duration,
    /// Per-caller state keyed by DID.
    pub callers: HashMap<DID, CallerState>,
}

impl PerCallerRateLimit {
    /// Creates a new per-caller rate limiter with the given limit and window.
    ///
    /// Uses default burst allowance (5 calls within 1 second, spec §6.2.0.2).
    #[must_use]
    pub fn new(max_calls_per_caller: u64, window: Duration) -> Self {
        Self::with_burst(
            max_calls_per_caller,
            window,
            DEFAULT_BURST_ALLOWANCE,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
        )
    }

    /// Creates a new per-caller rate limiter with custom burst parameters.
    ///
    /// `burst_allowance` is clamped to [`MAX_BURST_ALLOWANCE`] (50).
    #[must_use]
    pub fn with_burst(
        max_calls_per_caller: u64,
        window: Duration,
        burst_allowance: u32,
        burst_window: Duration,
    ) -> Self {
        Self {
            max_calls_per_caller,
            window,
            burst_allowance: burst_allowance.min(MAX_BURST_ALLOWANCE),
            burst_window,
            callers: HashMap::new(),
        }
    }

    /// Evicts all callers whose windows have expired.
    ///
    /// Called periodically during [`check_and_increment`] to reclaim memory
    /// from callers who are no longer active within the current window.
    #[allow(clippy::cast_possible_truncation)]
    fn evict_expired(&mut self, now: u64) {
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;
        self.callers
            .retain(|_, state| now.saturating_sub(state.window_start) < window_ms);
    }

    /// Checks whether a specific caller is within their per-caller rate limit.
    ///
    /// Periodically evicts expired entries to prevent unbounded memory growth.
    /// If the caller map is at capacity (`MAX_TRACKED_CALLERS`) after
    /// eviction, new callers are rejected with a rate-limit error.
    ///
    /// When the base rate limit is exhausted for a caller, burst allowance is
    /// checked: up to `burst_allowance` additional calls are permitted if they
    /// occur within `burst_window` of the first burst call (spec §6.2.0.2).
    ///
    /// Returns `true` if the call is permitted, `false` if the caller has
    /// exceeded their individual limit (including burst) or the caller map
    /// is at capacity.
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

        // Periodic eviction: run when approaching capacity to keep the map bounded.
        if self.callers.len() >= MAX_TRACKED_CALLERS {
            self.evict_expired(now);
            // After eviction, if still at capacity and this is a new caller, reject.
            if self.callers.len() >= MAX_TRACKED_CALLERS && !self.callers.contains_key(caller_did) {
                return Ok(false);
            }
        }

        let state = self
            .callers
            .entry(caller_did.clone())
            .or_insert(CallerState {
                count: 0,
                window_start: now,
                burst_count: 0,
                burst_window_start: now,
            });

        // If the window has expired for this caller, reset both base and burst.
        if now.saturating_sub(state.window_start) >= window_ms {
            state.count = 0;
            state.window_start = now;
            state.burst_count = 0;
            state.burst_window_start = now;
        }

        if state.count < self.max_calls_per_caller {
            state.count += 1;
            Ok(true)
        } else if self.burst_allowance > 0 {
            // Base limit exhausted — try burst allowance (spec §6.2.0.2).
            // The burst window is a deadline: all burst calls must occur within
            // burst_window of the FIRST burst call. Once burst_allowance is
            // consumed OR burst_window expires, no more burst calls until the
            // base window resets (handled above at the window-expiry check).

            // Lazily anchor the burst window to the first actual burst call,
            // not construction/base-window-reset time (#588 R2-01).
            if state.burst_count == 0 {
                state.burst_window_start = now;
            }

            let burst_window_ms = self.burst_window.as_millis() as u64;

            // If the burst window has expired, burst is dead until base resets.
            if now.saturating_sub(state.burst_window_start) >= burst_window_ms {
                return Ok(false);
            }

            if state.burst_count < self.burst_allowance {
                state.burst_count += 1;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Returns the number of seconds until the given caller's window resets.
    ///
    /// This is the `Retry-After` value per spec §6.2.0.2. Returns 0 if the
    /// caller has no tracked state (i.e., has never called). The value is
    /// rounded up so callers never retry too early.
    ///
    /// # Errors
    ///
    /// Returns [`crate::time::ClockError`] if the system clock is unavailable.
    #[allow(clippy::cast_possible_truncation)]
    pub fn retry_after_secs_for(&self, caller_did: &DID) -> Result<u64, crate::time::ClockError> {
        let now = crate::time::now_millis()?;
        let window_ms = self.window.as_millis() as u64;
        let Some(state) = self.callers.get(caller_did) else {
            return Ok(0);
        };
        let elapsed = now.saturating_sub(state.window_start);
        let remaining_ms = window_ms.saturating_sub(elapsed);
        // Ceiling division: round up so callers never retry too early.
        Ok(remaining_ms.div_ceil(1000))
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
/// Returns [`ToolError::InterfaceCallerNotAllowed`] if the invoker is not
/// in the outbound policy's `allowed_callers` list.
/// Returns [`ToolError::InterfacePayloadTooLarge`] if the serialized input
/// exceeds the outbound policy's `max_payload_bytes`.
/// Returns [`ToolError::InterfaceResponseTooLarge`] if the serialized output
/// exceeds the inbound policy's `max_response_bytes`.
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
        let retry_after_secs = rate_limit.retry_after_secs()?;
        return Err(ToolError::InterfaceRateLimited {
            max_calls: rate_limit.max_calls,
            window_ms,
            retry_after_secs,
        });
    }

    // 3. Check per-caller rate limit independently (spec §6.2.0.2).
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut per_caller_rl) = interface.per_caller_rate_limit
        && !per_caller_rl.check_and_increment(invoker_did)?
    {
        let window_ms = per_caller_rl.window.as_millis() as u64;
        let retry_after_secs = per_caller_rl.retry_after_secs_for(invoker_did)?;
        return Err(ToolError::InterfaceRateLimited {
            max_calls: per_caller_rl.max_calls_per_caller,
            window_ms,
            retry_after_secs,
        });
    }

    // 4. Outbound policy enforcement (§6.2.0.1): allowed_callers and payload size.
    if let Some(ref outbound) = interface.outbound_policy {
        // allowed_callers: empty means any member with ToolInterface capability.
        if !outbound.allowed_callers.is_empty() && !outbound.allowed_callers.contains(invoker_did) {
            return Err(ToolError::InterfaceCallerNotAllowed {
                did: invoker_did.to_string(),
            });
        }

        // max_payload_bytes: check serialized input size.
        let input_bytes = serde_json::to_vec(input).unwrap_or_default();
        if input_bytes.len() > outbound.max_payload_bytes as usize {
            return Err(ToolError::InterfacePayloadTooLarge {
                actual: input_bytes.len(),
                max: outbound.max_payload_bytes,
            });
        }
    }

    // 5. Source context governance: invoker must have tool invoke capability.
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

    // 6. Target context governance: tool must exist in target registry.
    if !target_registry.contains(&interface.tool_id) {
        return Err(ToolError::ToolNotFound {
            tool_id: interface.tool_id.clone(),
        });
    }

    // 7. Execute the tool.
    let output =
        executor(input).map_err(|msg| ToolError::InterfaceExecutionFailed { message: msg })?;

    // 8. Inbound policy enforcement (§6.2.0.1): response payload size.
    if let Some(ref inbound) = interface.inbound_policy {
        let response_bytes = serde_json::to_vec(&output).unwrap_or_default();
        if response_bytes.len() > inbound.max_response_bytes as usize {
            return Err(ToolError::InterfaceResponseTooLarge {
                actual: response_bytes.len(),
                max: inbound.max_response_bytes,
            });
        }
    }

    // 9. Build event payloads for both contexts.
    let (source_event, target_event) =
        build_cross_context_events(interface, input, &output, invoker_did);

    Ok((output, source_event, target_event))
}

/// Builds matched event payloads for the source and target contexts of a
/// cross-context tool invocation. Both events share the same `request_id`.
fn build_cross_context_events(
    interface: &ToolInterface,
    input: &serde_json::Value,
    output: &serde_json::Value,
    invoker_did: &DID,
) -> (CrossContextToolEvent, CrossContextToolEvent) {
    let request_id = uuid::Uuid::new_v4().to_string();
    let input_hash = sha256_json(input);
    let output_hash = Some(sha256_json(output));

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

    (source_event, target_event)
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
            cost: None,
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
        assert_eq!(rl.burst_allowance, DEFAULT_BURST_ALLOWANCE);
        assert_eq!(
            rl.burst_window,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS)
        );
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
            // Zero burst to test base limit rejection.
            rate_limit: Some(
                RateLimit::with_burst(2, Duration::from_secs(3600), 0, Duration::from_secs(1))
                    .unwrap(),
            ),
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
            burst_allowance: DEFAULT_BURST_ALLOWANCE,
            burst_window: Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
            burst_count: 0,
            burst_window_start: 0,
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
            burst_allowance: 10,
            burst_window: Duration::from_secs(2),
            burst_count: 3,
            burst_window_start: 999_000,
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
        // Zero burst to test base limit behavior independently.
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_secs(3600), 0, Duration::from_secs(1));
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
        // Use a long window so CI timing can't cause spurious resets.
        // Zero burst to test base limit behavior independently.
        let mut rl =
            PerCallerRateLimit::with_burst(1, Duration::from_secs(3600), 0, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        assert!(rl.check_and_increment(&alice).unwrap());
        assert!(!rl.check_and_increment(&alice).unwrap());

        // Set the window start far in the past to simulate window expiry.
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.window_start = 0;
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
                cost: None,
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

    // -----------------------------------------------------------------------
    // Burst allowance (§6.2.0.2)
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_burst_allows_calls_above_base_limit() {
        // Base limit: 2 calls, burst allowance: 5 within 1 second.
        let mut rl =
            RateLimit::with_burst(2, Duration::from_secs(3600), 5, Duration::from_secs(1)).unwrap();

        // First 2 calls: within base limit.
        assert!(rl.check_and_increment().unwrap());
        assert!(rl.check_and_increment().unwrap());

        // Next 5 calls: within burst allowance.
        for i in 0..5 {
            assert!(
                rl.check_and_increment().unwrap(),
                "burst call {i} should succeed"
            );
        }

        // 8th call (6th above base): exceeds burst allowance.
        assert!(
            !rl.check_and_increment().unwrap(),
            "call beyond burst allowance should fail"
        );
    }

    #[test]
    fn rate_limit_burst_of_5_rapid_calls_above_limit_succeeds_6th_fails() {
        // Spec §6.2.0.2: "5 calls above the per-minute limit within a
        // 1-second window." Exactly 5 burst calls succeed, 6th fails.
        let mut rl = RateLimit::with_burst(
            1,
            Duration::from_secs(3600),
            DEFAULT_BURST_ALLOWANCE,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
        )
        .unwrap();

        // Base call.
        assert!(
            rl.check_and_increment().unwrap(),
            "base call should succeed"
        );

        // 5 burst calls above the limit.
        for i in 0..5 {
            assert!(
                rl.check_and_increment().unwrap(),
                "burst call {i} should succeed"
            );
        }

        // 6th call above the limit: must fail.
        assert!(
            !rl.check_and_increment().unwrap(),
            "6th call above limit should fail"
        );
    }

    #[test]
    fn rate_limit_zero_burst_disables_burst() {
        let mut rl =
            RateLimit::with_burst(1, Duration::from_secs(3600), 0, Duration::from_secs(1)).unwrap();

        assert!(rl.check_and_increment().unwrap());
        // With zero burst, immediately fails after base limit.
        assert!(!rl.check_and_increment().unwrap());
    }

    #[test]
    fn rate_limit_burst_allowance_clamped_to_max() {
        let rl = RateLimit::with_burst(
            10,
            Duration::from_secs(60),
            100, // Above MAX_BURST_ALLOWANCE (50)
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(rl.burst_allowance, MAX_BURST_ALLOWANCE);
    }

    #[test]
    fn rate_limit_new_has_default_burst() {
        let rl = RateLimit::new(60, Duration::from_secs(60)).unwrap();
        assert_eq!(rl.burst_allowance, DEFAULT_BURST_ALLOWANCE);
        assert_eq!(
            rl.burst_window,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS)
        );
        assert_eq!(rl.burst_count, 0);
    }

    #[test]
    fn per_caller_rate_limit_burst_allows_calls_above_base_limit() {
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_secs(3600), 5, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Base: 2 calls.
        assert!(rl.check_and_increment(&alice).unwrap());
        assert!(rl.check_and_increment(&alice).unwrap());

        // Burst: 5 calls.
        for i in 0..5 {
            assert!(
                rl.check_and_increment(&alice).unwrap(),
                "burst call {i} should succeed"
            );
        }

        // 6th above base: fails.
        assert!(!rl.check_and_increment(&alice).unwrap());
    }

    #[test]
    fn per_caller_rate_limit_burst_is_independent_per_caller() {
        let mut rl =
            PerCallerRateLimit::with_burst(1, Duration::from_secs(3600), 2, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();

        // Alice exhausts base + burst.
        assert!(rl.check_and_increment(&alice).unwrap()); // base
        assert!(rl.check_and_increment(&alice).unwrap()); // burst 1
        assert!(rl.check_and_increment(&alice).unwrap()); // burst 2
        assert!(!rl.check_and_increment(&alice).unwrap()); // over

        // Bob still has full base + burst.
        assert!(rl.check_and_increment(&bob).unwrap());
        assert!(rl.check_and_increment(&bob).unwrap());
        assert!(rl.check_and_increment(&bob).unwrap());
        assert!(!rl.check_and_increment(&bob).unwrap());
    }

    #[test]
    fn per_caller_rate_limit_new_has_default_burst() {
        let rl = PerCallerRateLimit::new(10, Duration::from_secs(60));
        assert_eq!(rl.burst_allowance, DEFAULT_BURST_ALLOWANCE);
        assert_eq!(
            rl.burst_window,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS)
        );
    }

    #[test]
    fn per_caller_rate_limit_burst_clamped_to_max() {
        let rl = PerCallerRateLimit::with_burst(
            10,
            Duration::from_secs(60),
            100,
            Duration::from_secs(1),
        );
        assert_eq!(rl.burst_allowance, MAX_BURST_ALLOWANCE);
    }

    #[test]
    fn invoke_cross_context_burst_allows_calls_above_limit() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        // Base limit: 2 calls, burst allowance: 5.
        let mut interface = ToolInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            tool_id: "calculator".to_owned(),
            rate_limit: Some(
                RateLimit::with_burst(2, Duration::from_secs(3600), 5, Duration::from_secs(1))
                    .unwrap(),
            ),
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let input = serde_json::json!({"a": 1, "b": 2});

        // First 2 calls: within base limit.
        for i in 0..2 {
            let result = invoke_cross_context(
                &source_context,
                &mut interface,
                &input,
                &DID::from(admin_did),
                &source_role_state,
                &target_registry,
                0,
                add_executor,
            );
            assert!(result.is_ok(), "base call {i} should succeed");
        }

        // Next 5 calls: within burst allowance.
        for i in 0..5 {
            let result = invoke_cross_context(
                &source_context,
                &mut interface,
                &input,
                &DID::from(admin_did),
                &source_role_state,
                &target_registry,
                0,
                add_executor,
            );
            assert!(result.is_ok(), "burst call {i} should succeed");
        }

        // 8th call: exceeds burst allowance.
        let result = invoke_cross_context(
            &source_context,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ToolError::InterfaceRateLimited { max_calls: 2, .. }),
            "expected InterfaceRateLimited, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Burst window expiry within base window (F-06, #588)
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_burst_works_when_base_exhausted_after_burst_window_would_expire() {
        // Regression test for #588 R2-01: burst_window_start must be anchored
        // to the first burst call, not construction time. Without the lazy
        // initialization fix, exhausting base calls >1s after construction
        // causes the burst window to appear already expired.
        //
        // Setup: 2 base calls, 1-hour window, 5 burst calls, 1s burst window.
        let mut rl =
            RateLimit::with_burst(2, Duration::from_secs(3600), 5, Duration::from_secs(1)).unwrap();

        // Consume the 2 base calls.
        assert!(rl.check_and_increment().unwrap(), "base call 1");
        assert!(rl.check_and_increment().unwrap(), "base call 2");

        // Simulate being 30 seconds into the base window: push burst_window_start
        // 30s into the past to mimic the scenario where construction happened
        // 30s ago. Without the fix, the 1s burst window is long expired.
        rl.burst_window_start = rl.burst_window_start.saturating_sub(30_000);

        // With lazy initialization, the first burst call re-anchors
        // burst_window_start to now, so all burst calls should succeed.
        for i in 1..=5 {
            assert!(
                rl.check_and_increment().unwrap(),
                "burst call {i} should succeed — burst window lazily initialized"
            );
        }

        // 6th burst call should fail (burst allowance exhausted).
        assert!(
            !rl.check_and_increment().unwrap(),
            "burst call 6 should fail — burst allowance exhausted"
        );
    }

    #[test]
    fn per_caller_burst_works_when_base_exhausted_after_burst_window_would_expire() {
        // Same regression test for PerCallerRateLimit (#588 R2-01).
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_secs(3600), 5, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Consume the 2 base calls.
        assert!(rl.check_and_increment(&alice).unwrap(), "base call 1");
        assert!(rl.check_and_increment(&alice).unwrap(), "base call 2");

        // Simulate being 30 seconds into the base window.
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.burst_window_start = state.burst_window_start.saturating_sub(30_000);
        }

        // With lazy initialization, all burst calls should succeed.
        for i in 1..=5 {
            assert!(
                rl.check_and_increment(&alice).unwrap(),
                "burst call {i} should succeed — burst window lazily initialized"
            );
        }

        // 6th burst call should fail.
        assert!(
            !rl.check_and_increment(&alice).unwrap(),
            "burst call 6 should fail — burst allowance exhausted"
        );
    }

    #[test]
    fn rate_limit_burst_not_renewed_after_burst_window_expires() {
        // Base limit: 2 calls within a 1-hour window.
        // Burst: 3 calls within a 1-second burst window.
        let mut rl =
            RateLimit::with_burst(2, Duration::from_secs(3600), 3, Duration::from_secs(1)).unwrap();

        // Consume the 2 base calls.
        assert!(rl.check_and_increment().unwrap(), "base call 1");
        assert!(rl.check_and_increment().unwrap(), "base call 2");

        // Use 1 of 3 burst calls (burst window starts now).
        assert!(rl.check_and_increment().unwrap(), "burst call 1");

        // Simulate burst window expiry by pushing burst_window_start into the
        // past. The base window is still active (1-hour window).
        rl.burst_window_start = 0;

        // After burst window expires, NO more burst calls should be allowed
        // until the base window resets. This verifies the burst window is a
        // deadline, not a renewable cycle.
        assert!(
            !rl.check_and_increment().unwrap(),
            "burst must NOT renew after burst window expires within base window"
        );
    }

    #[test]
    fn per_caller_burst_not_renewed_after_burst_window_expires() {
        // Base limit: 2 calls within a 1-hour window.
        // Burst: 3 calls within a 1-second burst window.
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_secs(3600), 3, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Consume the 2 base calls.
        assert!(rl.check_and_increment(&alice).unwrap(), "base call 1");
        assert!(rl.check_and_increment(&alice).unwrap(), "base call 2");

        // Use 1 of 3 burst calls (burst window starts now).
        assert!(rl.check_and_increment(&alice).unwrap(), "burst call 1");

        // Simulate burst window expiry by pushing burst_window_start into the
        // past. The base window is still active (1-hour window).
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.burst_window_start = 0;
        }

        // After burst window expires, NO more burst calls should be allowed
        // until the base window resets.
        assert!(
            !rl.check_and_increment(&alice).unwrap(),
            "per-caller burst must NOT renew after burst window expires within base window"
        );
    }
}
