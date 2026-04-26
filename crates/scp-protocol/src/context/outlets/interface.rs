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
//!    This creates a [`ProposeOutletInterface`] governance action.
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

use scp_primitives::Clock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::lifecycle::{OutletStatus, sha256_json};
use super::registry::{OutletRegistration, OutletRegistry};
use super::{DID, OutletError, OutletId, OutletKind, has_admin_role};
use crate::context::roles::ContextRoleState;
use crate::provenance::DataProvenance;
use crate::provenance::attach::{SourceContextInfo, attach_provenance, effective_max_chain_depth};

// ---------------------------------------------------------------------------
// ContextId
// ---------------------------------------------------------------------------

/// Context identifier for cross-context operations.
///
/// Same underlying type as used elsewhere in the codebase (`String`).
pub type ContextId = String;

/// An Ed25519 signature (64 bytes).
///
/// Stored as a `Vec<u8>` for serde compatibility — matches the pattern used
/// in [`crate::context::metadata::Ed25519Signature`], [`scp_event_log::Ed25519Signature`],
/// and other module-local aliases across the workspace. Used in
/// [`InterfaceEstablished`] for `ikm_a_sig` / `ikm_b_sig` (spec §6.2.0.1
/// `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage signatures, ADR-049 round 5).
pub type Ed25519Signature = Vec<u8>;

// ---------------------------------------------------------------------------
// Rate limit defaults (§6.2.0.2)
// ---------------------------------------------------------------------------

/// Default per-interface rate limit for [`OutletKind::Action`] outlets:
/// 60 calls per minute (spec §6.2.0.2 Action tier — identical to the
/// pre-classification baseline).
///
/// Query outlets use the higher [`DEFAULT_QUERY_PER_INTERFACE_CALLS_PER_MINUTE`]
/// default. Use [`OutletInterfaceDefaults::for_kind`] to derive the correct
/// default at the call site rather than referencing this constant directly.
pub const DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE: u32 = 60;

/// Default per-caller rate limit for [`OutletKind::Action`] outlets:
/// 10 calls per minute (spec §6.2.0.2 Action tier).
///
/// Query outlets use the higher [`DEFAULT_QUERY_PER_CALLER_CALLS_PER_MINUTE`]
/// default. Use [`OutletInterfaceDefaults::for_kind`] to derive the correct
/// default at the call site rather than referencing this constant directly.
pub const DEFAULT_PER_CALLER_CALLS_PER_MINUTE: u32 = 10;

/// Default per-interface rate limit for [`OutletKind::Query`] outlets:
/// 600 calls per minute (spec §6.2.0.2 Query tier).
///
/// An order of magnitude higher than the Action default
/// ([`DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE`]), reflecting the idempotent
/// read-only contract that Query outlets carry under §5.4.2.
pub const DEFAULT_QUERY_PER_INTERFACE_CALLS_PER_MINUTE: u32 = 600;

/// Default per-caller rate limit for [`OutletKind::Query`] outlets:
/// 100 calls per minute (spec §6.2.0.2 Query tier).
///
/// An order of magnitude higher than the Action per-caller default
/// ([`DEFAULT_PER_CALLER_CALLS_PER_MINUTE`]).
pub const DEFAULT_QUERY_PER_CALLER_CALLS_PER_MINUTE: u32 = 100;

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
// OutletInterfaceDefaults (§6.2.0.2 classification-aware rate tiers)
// ---------------------------------------------------------------------------

/// Per-kind cross-context rate-tier defaults (spec §6.2.0.2).
///
/// Spec §6.2.0.2 partitions the cross-context outlet-interface rate-limit
/// defaults by [`OutletKind`]: Query outlets get an order-of-magnitude
/// higher tier (`600/100`) reflecting the idempotent read-only contract,
/// while Action outlets retain the pre-classification baseline (`60/10`).
/// Both tiers are independently configurable within the §6.2.0.2 ranges
/// (1–6000 per-interface, 1–1000 per-caller); the helper here only supplies
/// the *default* when no caller-supplied value is present.
///
/// **Single source of truth.** Callers that need to derive the kind-aware
/// default MUST use [`OutletInterfaceDefaults::for_kind`] — never hardcode
/// `60` or `600` at the call site, and never branch on
/// `OutletKind::{Query,Action}` to pick a constant manually. Centralising
/// the derivation here keeps the spec invariant
/// "Query > Action by 10x" mechanically enforced: a future spec revision
/// that tweaks the tiers updates one helper and every caller follows.
///
/// **Explicit values preserved.** This helper is *only* consulted when the
/// caller omitted a `max_calls_per_minute`. Builder functions
/// ([`expose_tool`], [`accept_tool_interface`], [`create_interface_offer`])
/// pass any caller-supplied `OutboundPolicy` / `InboundPolicy` through
/// untouched — only when the policy is `None` or carries a defaulted-by-kind
/// value do these defaults apply (spec §6.2.0.2 "Both tiers are
/// independently configurable").
///
/// **§5.4.2 cross-reference.** `OutletKind::Query` is the read-only,
/// idempotent, cacheable tier; `OutletKind::Action` is the mutating tier.
/// The §6.2.0.2 tier split mirrors the §5.4.2 classification — Query gets
/// the higher tier because reads are amortisable, Action gets the lower
/// tier because writes have economic and side-effect cost.
///
/// See spec §6.2.0.2 "Classification-aware rate tiers" and §5.4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutletInterfaceDefaults {
    /// The [`OutletKind`] this default tuple is keyed to. Stored so the
    /// helper round-trips through [`OutletInterfaceDefaults::for_kind`]
    /// and so callers that need the kind alongside the limits do not
    /// have to thread it separately.
    pub kind: OutletKind,
    /// Default per-interface calls per minute for this `kind`.
    /// `60` for Action, `600` for Query (spec §6.2.0.2).
    pub per_interface_calls_per_minute: u32,
    /// Default per-caller calls per minute for this `kind`.
    /// `10` for Action, `100` for Query (spec §6.2.0.2).
    pub per_caller_calls_per_minute: u32,
}

impl OutletInterfaceDefaults {
    /// Returns the §6.2.0.2 default rate-tier tuple
    /// `(per_interface, per_caller)` for the given [`OutletKind`].
    ///
    /// - [`OutletKind::Query`] → `(600, 100)` — read-only, idempotent,
    ///   amortisable (§6.2.0.2 Query tier; §5.4.2 cache property).
    /// - [`OutletKind::Action`] → `(60, 10)` — pre-classification baseline,
    ///   matches the §6.2.0.2 "default" row of the rate-limit table.
    ///
    /// **Stability invariant.** The returned tuple is stable across the
    /// `OutletKind` variants documented in this version of the protocol.
    /// If a future spec revision adds a new `OutletKind` variant, this
    /// helper MUST be updated in lockstep — every caller relies on
    /// `for_kind` returning a real default, never panicking and never
    /// returning a sentinel.
    ///
    /// See [`OutletInterfaceDefaults::tuple_for_kind`] for the direct
    /// `(u32, u32)` tuple shape used by `expose_tool` /
    /// `accept_tool_interface` / `create_interface_offer` when filling in
    /// a missing `max_calls_per_minute`.
    #[must_use]
    pub const fn for_kind(kind: OutletKind) -> Self {
        match kind {
            OutletKind::Query => Self {
                kind,
                per_interface_calls_per_minute: DEFAULT_QUERY_PER_INTERFACE_CALLS_PER_MINUTE,
                per_caller_calls_per_minute: DEFAULT_QUERY_PER_CALLER_CALLS_PER_MINUTE,
            },
            OutletKind::Action => Self {
                kind,
                per_interface_calls_per_minute: DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE,
                per_caller_calls_per_minute: DEFAULT_PER_CALLER_CALLS_PER_MINUTE,
            },
        }
    }

    /// Returns the `(per_interface, per_caller)` default tuple for the
    /// given [`OutletKind`] — the shape AC1/AC2 of SCP-OUT-016 assert
    /// against, and the shape that builder functions consume when filling
    /// in a missing `max_calls_per_minute`.
    ///
    /// Equivalent to
    /// `(Self::for_kind(kind).per_interface_calls_per_minute,
    ///   Self::for_kind(kind).per_caller_calls_per_minute)`.
    #[must_use]
    pub const fn tuple_for_kind(kind: OutletKind) -> (u32, u32) {
        let d = Self::for_kind(kind);
        (
            d.per_interface_calls_per_minute,
            d.per_caller_calls_per_minute,
        )
    }
}

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
    /// Empty means any member with the `OutletInterface` capability.
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
    /// Returns an [`OutletKind::Action`]-tier default policy
    /// (`max_calls_per_minute = 60`, spec §6.2.0.2 Action tier).
    ///
    /// The [`Default`] impl is fail-safe: it picks the stricter Action tier
    /// because `OutletKind::Action` is the §5.4.2 fail-safe default. Use
    /// [`OutboundPolicy::for_kind`] when you have an [`OutletKind`] in hand
    /// to pick the matching tier.
    fn default() -> Self {
        Self::for_kind(OutletKind::Action)
    }
}

impl OutboundPolicy {
    /// Returns the §6.2.0.2 default [`OutboundPolicy`] for the given
    /// [`OutletKind`].
    ///
    /// `max_calls_per_minute` is filled from
    /// [`OutletInterfaceDefaults::for_kind`] — `600` for Query, `60` for
    /// Action. All other fields take the protocol-wide defaults
    /// (empty `allowed_callers`, 64 KiB payload cap, `require_provenance =
    /// true`).
    #[must_use]
    pub const fn for_kind(kind: OutletKind) -> Self {
        let defaults = OutletInterfaceDefaults::for_kind(kind);
        Self {
            allowed_callers: Vec::new(),
            max_calls_per_minute: defaults.per_interface_calls_per_minute,
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
///   the source context's governance engine (via `has_outlet_call_capability`),
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
    /// responsibility (it checks `has_outlet_call_capability`).
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
    /// Returns an [`OutletKind::Action`]-tier default policy
    /// (`max_calls_per_minute = 60`, spec §6.2.0.2 Action tier).
    ///
    /// The [`Default`] impl is fail-safe: it picks the stricter Action tier
    /// because `OutletKind::Action` is the §5.4.2 fail-safe default. Use
    /// [`InboundPolicy::for_kind`] when you have an [`OutletKind`] in hand
    /// to pick the matching tier.
    fn default() -> Self {
        Self::for_kind(OutletKind::Action)
    }
}

impl InboundPolicy {
    /// Returns the §6.2.0.2 default [`InboundPolicy`] for the given
    /// [`OutletKind`].
    ///
    /// `max_calls_per_minute` is filled from
    /// [`OutletInterfaceDefaults::for_kind`] — `600` for Query, `60` for
    /// Action. All other fields take the protocol-wide defaults
    /// (empty `allowed_source_roles`, 64 KiB response cap,
    /// `require_spending_ucan = false`).
    #[must_use]
    pub const fn for_kind(kind: OutletKind) -> Self {
        let defaults = OutletInterfaceDefaults::for_kind(kind);
        Self {
            allowed_source_roles: Vec::new(),
            max_calls_per_minute: defaults.per_interface_calls_per_minute,
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
pub struct ProposeOutletInterface {
    /// The tool to expose.
    pub outlet_id: OutletId,
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
///
/// **Kind-aware default rate tier (§6.2.0.2).** The
/// [`outbound_policy.max_calls_per_minute`](OutboundPolicy::max_calls_per_minute)
/// field on this offer carries the §6.2.0.2 default keyed to
/// [`outlet_schema.kind`](OutletRegistration::kind) when the source
/// context's `expose_tool` call did not pass an explicit
/// [`OutboundPolicy`]: 600 calls/min for [`OutletKind::Query`] and 60
/// calls/min for [`OutletKind::Action`]. When the source context provided
/// an explicit policy, that policy's `max_calls_per_minute` is preserved
/// verbatim regardless of `kind` (AC5). See
/// [`OutletInterfaceDefaults::for_kind`] for the helper that derives the
/// default tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceOffer {
    /// `SHA-256("SCP-OFFER-ID-V1:" || len(source_context_id) || source_context_id || len(outlet_id) || outlet_id || len(target_context_id) || target_context_id || timestamp)`.
    /// Domain-separated and length-prefixed (4-byte big-endian) to prevent collisions.
    pub offer_id: [u8; 32],
    /// The context exposing the tool.
    pub source_context: ContextId,
    /// The context the tool is offered to.
    pub target_context: ContextId,
    /// Full tool registration (schema, metadata). The
    /// [`OutletRegistration::kind`] field on this schema selects the
    /// §6.2.0.2 default rate tier carried in
    /// [`outbound_policy`](Self::outbound_policy) when no caller-supplied
    /// policy was provided to [`expose_tool`] / [`create_interface_offer`].
    pub outlet_schema: OutletRegistration,
    /// Outbound policy set by the source context (§6.2.0.1, §6.2.0.2).
    ///
    /// When the source context's `expose_tool` call omitted an explicit
    /// [`OutboundPolicy`], this field holds the §6.2.0.2 kind-aware default
    /// derived via [`OutboundPolicy::for_kind`]
    /// (`outlet_schema.kind` → tier): 600 calls/min for `Query`, 60
    /// calls/min for `Action`. Explicit caller-supplied policies are
    /// preserved verbatim (AC5).
    pub outbound_policy: OutboundPolicy,
    /// Unix timestamp (ms) when the offer expires (7 days from creation).
    pub expires_at: u64,
}

impl InterfaceOffer {
    /// Computes the offer ID as `SHA-256("SCP-OFFER-ID-V1:" || len(source_context) || source_context || len(outlet_id) || outlet_id || len(target_context) || target_context || timestamp)`.
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
        outlet_id: &str,
        target_context: &str,
        timestamp: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-OFFER-ID-V1:");
        hasher.update((source_context.len() as u32).to_be_bytes());
        hasher.update(source_context.as_bytes());
        hasher.update((outlet_id.len() as u32).to_be_bytes());
        hasher.update(outlet_id.as_bytes());
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
pub struct AcceptOutletInterface {
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
pub struct RevokeOutletInterface {
    /// The interface being revoked (same as the offer ID that established it).
    pub interface_id: [u8; 32],
}

/// Event recorded when both contexts have approved an interface (§6.2.0.1 step 4).
///
/// # Round-5 + Round-6 fields (ADR-049)
///
/// In addition to the original `interface_id`, `source_context`,
/// `target_context`, `outlet_id`, and `established_at` fields, this struct
/// captures the cryptographic checkpoint and cluster-detection metadata
/// required for the bidirectional consent protocol per spec §6.2.0.1 and the
/// round-6 ADR-049 adjustments:
///
/// - **Epoch counters** (`epoch_a`, `epoch_b`) — each context's MLS epoch
///   counter at accept time. Persisted for audit; verifiers resolve admin
///   `#active` keys against the role registry at these epochs (§6.2.0.1
///   verifier rule).
/// - **Committed IKMs** (`ikm_a`, `ikm_b`) — each side's exporter-derived
///   input keying material at accept time, persisted verbatim in the event
///   metadata. The `(ikm_a, ikm_b)` pair pins the `hop_salt` derivation so
///   historic verifiability does not depend on retaining the underlying MLS
///   epoch exporter keys (§6.2.0.1 "Historic verifiability"). The peer's
///   `context_id` is incorporated into the MLS exporter label, so an `ikm`
///   from interface A↔B cannot be reused for A↔C (§6.2.0.1 "Why the label
///   suffix is required").
/// - **IKM commitment signatures** (`ikm_a_sig`, `ikm_b_sig`) — each side's
///   admin signs its own IKM under the `SCP-OUTLET-IKM-COMMITMENT-V1:`
///   preimage with its `#active` key (§6.2.0.1 "Committed-IKM signing").
///   Closes the Byzantine-admin attack where a hostile MLS implementation
///   could publish a low-entropy or attacker-chosen IKM. The preimage binds
///   the context-id pair and the acceptance epoch so a signature for one
///   interface cannot be reused for another.
/// - **Cluster-detection metadata** (`creator_did`, `admin_set`,
///   `capability_holder_set`) — captured at accept time to feed the
///   round-6 four-predicate cluster-match count `k` for the quadratic
///   interface-spam fee (§6.2.0.1 "Rolling window + cluster detection",
///   ADR-049 round-6 §"Cluster detection 4th predicate"):
///
///   1. `creator_did` — the DID captured at peer-context creation (the first
///      admin per §5.4 lifecycle). Fixed at creation; cannot be rotated out.
///   2. `admin_set` — the DIDs holding the admin role at interface-acceptance
///      time. Catches "new DID creates a context and invites the same admin
///      cluster" evasion.
///   3. `capability_holder_set` — the DIDs holding ANY of the
///      outlet-interface capabilities (`outlet:offer:*`, `outlet:query:*`,
///      `outlet:call:*`) at interface-acceptance time. Catches "rotate
///      creator+admin BUT keep a stable cross-context invoker" evasion. Sorted
///      lexicographically at construction time so `MessagePack` round-trip is
///      deterministic across implementations.
///
/// # Scope of this struct (SCP-OUT-042a)
///
/// This is the schema-only declaration: every field has a real type and is
/// serialized verbatim into the event log. Behavioural wiring is split across
/// downstream stories — crypto derivation + signing in OUT-042b, governance +
/// admin-removal + atomic rotation in OUT-042c, and `ContextParams` + cluster
/// detection + quadratic fee in OUT-042d. Construction-time population of
/// `creator_did`, `admin_set`, and `capability_holder_set` lands in OUT-042d.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceEstablished {
    /// The interface/offer ID.
    pub interface_id: [u8; 32],
    /// Source context.
    pub source_context: ContextId,
    /// Target context.
    pub target_context: ContextId,
    /// Tool being shared.
    pub outlet_id: OutletId,
    /// Unix timestamp (ms) when established.
    pub established_at: u64,
    /// Source context's (Context A's) MLS epoch counter at accept time
    /// (§6.2.0.1 step 4). Persisted for audit; verifiers resolve Context A's
    /// admin `#active` key against the role registry at this epoch.
    pub epoch_a: u64,
    /// Target context's (Context B's) MLS epoch counter at accept time
    /// (§6.2.0.1 step 4). Persisted for audit; verifiers resolve Context B's
    /// admin `#active` key against the role registry at this epoch.
    pub epoch_b: u64,
    /// Source context's (Context A's) exporter-derived IKM at accept time
    /// (§6.2.0.1 step 4 "Step 1 — accept-time IKM derivation"). Computed as
    /// `MLS_EXPORTER("scp-context-hop-salt-v1:" || context_b_id, b"", 32)`
    /// on Context A's accept-time epoch — labelled with Context B's id to
    /// prevent cross-interface reuse. Persisted verbatim so `hop_salt` can
    /// be re-derived deterministically without retaining MLS epoch secrets.
    pub ikm_a: [u8; 32],
    /// Source admin's signature over `ikm_a` under the
    /// `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage (§6.2.0.1 "Committed-IKM
    /// signing"). Computed by Context A's admin under their `#active` key
    /// over `SHA-256("SCP-OUTLET-IKM-COMMITMENT-V1:" ||
    /// len_be32(context_a_id) || context_a_id || len_be32(context_b_id) ||
    /// context_b_id || epoch_a_be || ikm_a)`. The preimage binds the
    /// context-id pair and the acceptance epoch so a signature for one
    /// interface cannot be reused for another. Verified at event-log append
    /// time — failure rejects the establishment with
    /// `authorization.ikm-signature-invalid` (`SCP-TOOL-6110`).
    pub ikm_a_sig: Ed25519Signature,
    /// Target context's (Context B's) exporter-derived IKM at accept time
    /// (§6.2.0.1 step 4 "Step 1 — accept-time IKM derivation"). Symmetric to
    /// `ikm_a`: `MLS_EXPORTER("scp-context-hop-salt-v1:" || context_a_id,
    /// b"", 32)` on Context B's accept-time epoch.
    pub ikm_b: [u8; 32],
    /// Target admin's signature over `ikm_b` under the
    /// `SCP-OUTLET-IKM-COMMITMENT-V1:` preimage (§6.2.0.1 "Committed-IKM
    /// signing"). Symmetric to `ikm_a_sig`: Context B's admin signs
    /// `(context_a_id, context_b_id, epoch_b, ikm_b)` under its `#active`
    /// key.
    pub ikm_b_sig: Ed25519Signature,
    /// The DID captured at the peer context's creation event — the first
    /// admin who created the context per §5.4 context lifecycle. Fixed at
    /// context creation; cannot be rotated out. Feeds cluster-detection
    /// predicate 2 (`P_i.creator_did == B.creator_did`) per §6.2.0.1
    /// "Rolling window + cluster detection".
    pub creator_did: DID,
    /// The set of DIDs holding the admin role in the peer context at
    /// interface-acceptance time. Feeds cluster-detection predicate 3
    /// (`P_i.admin_set ∩ B.admin_set ≠ ∅`) per §6.2.0.1 "Rolling window +
    /// cluster detection" — catches "new DID creates a context and invites
    /// the same admin cluster" evasion. Population is wired in OUT-042d.
    pub admin_set: Vec<DID>,
    /// The set of DIDs in the peer context that hold ANY of the
    /// outlet-interface capabilities (`outlet:offer:*`, `outlet:query:*`,
    /// `outlet:call:*`) at interface-acceptance time. Feeds round-6 cluster-
    /// detection predicate 4 (`P_i.capability_holder_set ∩
    /// B.capability_holder_set ≠ ∅`) per §6.2.0.1 "Rolling window + cluster
    /// detection" and ADR-049 round-6 §"Cluster detection 4th predicate".
    /// Catches "rotate creator+admin BUT keep a stable cross-context invoker"
    /// evasion.
    ///
    /// **Ordering invariant.** Sorted lexicographically by DID string at
    /// construction time so `MessagePack` round-trip yields deterministic
    /// bytes across implementations. Population is wired in OUT-042d.
    pub capability_holder_set: Vec<DID>,
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
// InterfaceSaltRotated (SCP-OUT-042c — admin-removal salt rotation)
// ---------------------------------------------------------------------------

/// Domain separator string (UTF-8 bytes) for the
/// `SCP-OUTLET-IKM-ROTATE-V1:` preimage. Registered in spec §9.18.2.
///
/// The trailing colon is part of the on-wire prefix per the §9.18.2
/// registration table — every other separator in §9.18.2 ends in a colon
/// and the §6.2.0.1 byte spec includes the colon literal.
pub const IKM_ROTATE_DOMAIN_SEPARATOR: &[u8] = b"SCP-OUTLET-IKM-ROTATE-V1:";

/// Rotation event emitted on every active interface a context holds when
/// an admin is removed via governance `RemoveMember`-with-admin-role
/// (spec §6.2.0.1 round-6 "Admin-removal salt rotation").
///
/// The removed admin retains prior knowledge of the committed
/// `(ikm_a, ikm_b)` and could continue computing
/// `HMAC(hop_salt, raw_context_id)` to reverse pseudonyms for hops they
/// no longer have a right to observe. To close this, on any admin
/// removal the governance engine emits one `InterfaceSaltRotated` per
/// active interface, atomic with the `RemoveMember` commit. Both sides
/// publish fresh IKMs; both contexts re-derive `hop_salt` from the new
/// pair. The removed admin's HMAC computations no longer match wire
/// pseudonyms.
///
/// # Field semantics
///
/// - `interface_id` — the prior `InterfaceEstablished`'s `offer_id`,
///   binding this rotation to a specific interface.
/// - `new_ikm_local` — fresh exporter output at `epoch_local` under the
///   §6.2.0.1 step-1 peer-suffixed label
///   (`scp-context-hop-salt-v1:` || `peer_context_id`).
/// - `new_ikm_local_sig` — Ed25519 signature over the
///   `SCP-OUTLET-IKM-ROTATE-V1:` preimage under the signing admin's
///   `#active` key. Computed by [`sign_interface_rotation`].
/// - `epoch_local` — local context's MLS epoch counter at rotation time.
/// - `trigger_removal_did` — the removed admin's DID (audit trail). Also
///   verified against the cited removal event's target DID.
/// - `removal_event_id` — event-log id of the `RemoveMember` (or
///   equivalent admin-removal) event that justifies this rotation. MUST
///   reference a prior event in the same local event log whose body is
///   an admin-removal action targeting `trigger_removal_did` and whose
///   epoch is equal to or one less than `epoch_local`.
///
/// # Zeroization
///
/// `ZeroizeOnDrop` is derived so the 32-byte `new_ikm_local` is zeroed
/// when the struct is dropped. The IKM is committed verbatim into the
/// public event log alongside the epoch counter, so it is not a
/// long-term secret — but in-memory zeroization closes the residual
/// memory-disclosure surface during the rotation pipeline. Other fields
/// (interface ids, signatures, the public DID string) are zeroized
/// alongside, which is harmless for their lifecycle.
///
/// # Wire format
///
/// JSON-serialized when persisted into the event log alongside
/// `RemoveMember` (the runtime's event-log adapter signs over
/// canonical-JCS bytes). The struct is also `MessagePack`-round-trippable
/// for cross-implementation conformance.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct InterfaceSaltRotated {
    /// The prior `InterfaceEstablished`'s `offer_id` — binds this
    /// rotation to a specific interface (predicate (a) of the §6.2.0.1
    /// rotation-signature preimage).
    pub interface_id: [u8; 32],
    /// Fresh exporter output at `epoch_local`, labeled per §6.2.0.1 step
    /// 1 (`scp-context-hop-salt-v1:` || `peer_context_id`). Persisted
    /// verbatim so verifiers can re-derive the post-rotation `hop_salt`
    /// without retaining MLS epoch secrets.
    pub new_ikm_local: [u8; 32],
    /// Remaining admin's Ed25519 signature over the
    /// `SCP-OUTLET-IKM-ROTATE-V1:` preimage. Verified at event-log
    /// append time per the §6.2.0.1 verifier rule.
    #[zeroize(skip)]
    pub new_ikm_local_sig: Ed25519Signature,
    /// Local context's MLS epoch counter at rotation time. Verifier
    /// resolves the signing admin's `#active` key against the role
    /// registry at this epoch.
    pub epoch_local: u64,
    /// The removed admin's DID — audit trail. Verifier checks that the
    /// cited `removal_event_id` references an admin-removal event whose
    /// target DID equals this value.
    #[zeroize(skip)]
    pub trigger_removal_did: DID,
    /// Event-log id of the `RemoveMember` (or equivalent admin-removal)
    /// event that justifies this rotation. Verifier rejects when this id
    /// does not reference a prior, valid admin-removal event targeting
    /// `trigger_removal_did` within the same or prior epoch — slug
    /// `authorization.salt-rotation-unjustified` (`SCP-TOOL-6115`).
    pub removal_event_id: [u8; 32],
}

/// Computes the canonical `SCP-OUTLET-IKM-ROTATE-V1:` preimage and
/// signs it with `signer` under the §6.2.0.1 round-6 rotation-signature
/// rule (admin-removal salt rotation).
///
/// The preimage is:
///
/// ```text
/// SHA-256(
///     "SCP-OUTLET-IKM-ROTATE-V1:"
///     || len_be32(interface_id) || interface_id
///     || len_be32(context_local_id) || context_local_id
///     || len_be32(context_peer_id) || context_peer_id
///     || epoch_local_be                               // 8 bytes BE u64
///     || new_ikm_local                                 // 32 bytes
///     || len_be32(trigger_removal_did) || trigger_removal_did
///     || len_be32(removal_event_id) || removal_event_id
/// )
/// ```
///
/// Length-prefixed variable-length fields prevent concatenation
/// ambiguity (e.g., `("ab", "cd")` vs `("a", "bcd")`). The 32-byte
/// fixed-width fields (`interface_id`, `new_ikm_local`,
/// `removal_event_id`) are length-prefixed in the spec text for
/// uniformity.
///
/// Note that `interface_id` is `[u8; 32]` — the spec's `len_be32(interface_id)` is
/// a fixed `0x00000020`. The signed bytes match the spec verbatim.
///
/// The `context_local_id` is the signer's own context id; the
/// `context_peer_id` is the other side. The pair is NOT canonicalized
/// here — the rotation preimage is per-side (each side signs with its
/// own ordering) so peers reciprocally rotate with `(local, peer)`
/// swapped on the other side per §6.2.0.1 "Atomic removal+rotation —
/// peer-side semantics".
#[must_use]
#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub fn sign_interface_rotation(
    signer: &ed25519_dalek::SigningKey,
    interface_id: &[u8; 32],
    context_local_id: &ContextId,
    context_peer_id: &ContextId,
    epoch_local: u64,
    new_ikm_local: &[u8; 32],
    trigger_removal_did: &DID,
    removal_event_id: &[u8; 32],
) -> Ed25519Signature {
    use ed25519_dalek::Signer;
    let preimage = rotation_preimage_hash(
        interface_id,
        context_local_id,
        context_peer_id,
        epoch_local,
        new_ikm_local,
        trigger_removal_did,
        removal_event_id,
    );
    signer.sign(&preimage).to_bytes().to_vec()
}

/// Verifies that `sig` authenticates the canonical
/// `SCP-OUTLET-IKM-ROTATE-V1:` preimage under `verifying_key`.
///
/// Mirrors [`sign_interface_rotation`] — same byte layout, same hash.
/// Returns `Ok(())` on cryptographic success, [`RotationVerifyError`]
/// on length-mismatch or verification failure.
///
/// # Errors
///
/// - [`RotationVerifyError::InvalidLength`] when `sig.len()` is not 64.
/// - [`RotationVerifyError::VerificationFailed`] when the cryptographic
///   verification returns an error. Maps to the §6.2.0.1 round-6
///   verifier-rule rejection slug `authorization.salt-rotation-unjustified`
///   (`SCP-TOOL-6115`) when fired at event-log append time alongside the
///   removal-event-binding checks.
#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub fn verify_interface_rotation(
    verifying_key: &ed25519_dalek::VerifyingKey,
    sig: &Ed25519Signature,
    interface_id: &[u8; 32],
    context_local_id: &ContextId,
    context_peer_id: &ContextId,
    epoch_local: u64,
    new_ikm_local: &[u8; 32],
    trigger_removal_did: &DID,
    removal_event_id: &[u8; 32],
) -> Result<(), RotationVerifyError> {
    use ed25519_dalek::Verifier;
    if sig.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(RotationVerifyError::InvalidLength {
            expected: ed25519_dalek::SIGNATURE_LENGTH,
            actual: sig.len(),
        });
    }
    let mut sig_bytes = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
    sig_bytes.copy_from_slice(sig);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let preimage = rotation_preimage_hash(
        interface_id,
        context_local_id,
        context_peer_id,
        epoch_local,
        new_ikm_local,
        trigger_removal_did,
        removal_event_id,
    );
    verifying_key.verify(&preimage, &signature).map_err(|e| {
        RotationVerifyError::VerificationFailed {
            reason: e.to_string(),
        }
    })
}

/// Failure modes for [`verify_interface_rotation`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RotationVerifyError {
    /// Signature byte length is not 64.
    #[error("rotation signature must be {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected length (always 64 for Ed25519).
        expected: usize,
        /// Actual length supplied by the caller.
        actual: usize,
    },
    /// Cryptographic verification failed — the signature does not
    /// authenticate the canonical preimage under the supplied key.
    #[error("rotation signature verification failed: {reason}")]
    VerificationFailed {
        /// Human-readable reason for diagnostic logging. Wire-level
        /// rejection uses `authorization.salt-rotation-unjustified`.
        reason: String,
    },
}

/// Computes the SHA-256 digest of the §6.2.0.1
/// `SCP-OUTLET-IKM-ROTATE-V1:` preimage. The digest is the input to
/// Ed25519 sign/verify in [`sign_interface_rotation`] and
/// [`verify_interface_rotation`].
#[must_use]
#[allow(clippy::similar_names)]
fn rotation_preimage_hash(
    interface_id: &[u8; 32],
    context_local_id: &ContextId,
    context_peer_id: &ContextId,
    epoch_local: u64,
    new_ikm_local: &[u8; 32],
    trigger_removal_did: &DID,
    removal_event_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(IKM_ROTATE_DOMAIN_SEPARATOR);
    // Fixed-width 32-byte interface_id: len_be32 = 32.
    hasher.update(32u32.to_be_bytes());
    hasher.update(interface_id);
    // Variable-length context ids — length-prefixed.
    let local_len = u32::try_from(context_local_id.len()).unwrap_or(u32::MAX);
    let peer_len = u32::try_from(context_peer_id.len()).unwrap_or(u32::MAX);
    hasher.update(local_len.to_be_bytes());
    hasher.update(context_local_id.as_bytes());
    hasher.update(peer_len.to_be_bytes());
    hasher.update(context_peer_id.as_bytes());
    // Fixed-width epoch / IKM.
    hasher.update(epoch_local.to_be_bytes());
    hasher.update(new_ikm_local);
    // Variable-length DID — length-prefixed.
    let did_str = trigger_removal_did.as_ref();
    let did_len = u32::try_from(did_str.len()).unwrap_or(u32::MAX);
    hasher.update(did_len.to_be_bytes());
    hasher.update(did_str.as_bytes());
    // Fixed-width 32-byte removal_event_id: len_be32 = 32.
    hasher.update(32u32.to_be_bytes());
    hasher.update(removal_event_id);
    hasher.finalize().into()
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
    pub fn new(max_calls: u64, window: Duration, clock: &dyn Clock) -> Self {
        Self::with_burst(
            max_calls,
            window,
            DEFAULT_BURST_ALLOWANCE,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
            clock,
        )
    }

    /// Creates a new rate limit with custom burst parameters.
    ///
    /// `burst_allowance` is clamped to [`MAX_BURST_ALLOWANCE`] (50).
    pub fn with_burst(
        max_calls: u64,
        window: Duration,
        burst_allowance: u32,
        burst_window: Duration,
        clock: &dyn Clock,
    ) -> Self {
        let now = clock.now_millis();
        Self {
            max_calls,
            window,
            current_count: 0,
            window_start: now,
            burst_allowance: burst_allowance.min(MAX_BURST_ALLOWANCE),
            burst_window,
            burst_count: 0,
            burst_window_start: now,
        }
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
    #[allow(clippy::cast_possible_truncation)]
    fn check_and_increment(&mut self, clock: &dyn Clock) -> bool {
        let now = clock.now_millis();
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
            true
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
                return false;
            }

            if self.burst_count < self.burst_allowance {
                self.burst_count += 1;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns the number of seconds until the current window resets.
    ///
    /// This is the `Retry-After` value per spec §6.2.0.2: the time a caller
    /// must wait before the next call will be accepted. The value is rounded
    /// up so callers never retry too early.
    #[allow(clippy::cast_possible_truncation)]
    pub fn retry_after_secs(&self, clock: &dyn Clock) -> u64 {
        let now = clock.now_millis();
        let window_ms = self.window.as_millis() as u64;
        let elapsed = now.saturating_sub(self.window_start);
        let remaining_ms = window_ms.saturating_sub(elapsed);
        // Ceiling division: round up so callers never retry too early.
        remaining_ms.div_ceil(1000)
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
    #[allow(clippy::cast_possible_truncation)]
    pub fn check_and_increment(&mut self, caller_did: &DID, clock: &dyn Clock) -> bool {
        let now = clock.now_millis();
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = self.window.as_millis() as u64;

        // Periodic eviction: run when approaching capacity to keep the map bounded.
        if self.callers.len() >= MAX_TRACKED_CALLERS {
            self.evict_expired(now);
            // After eviction, if still at capacity and this is a new caller, reject.
            if self.callers.len() >= MAX_TRACKED_CALLERS && !self.callers.contains_key(caller_did) {
                return false;
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
            true
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
                return false;
            }

            if state.burst_count < self.burst_allowance {
                state.burst_count += 1;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns the number of seconds until the given caller's window resets.
    ///
    /// This is the `Retry-After` value per spec §6.2.0.2. Returns 0 if the
    /// caller has no tracked state (i.e., has never called). The value is
    /// rounded up so callers never retry too early.
    #[allow(clippy::cast_possible_truncation)]
    pub fn retry_after_secs_for(&self, caller_did: &DID, clock: &dyn Clock) -> u64 {
        let now = clock.now_millis();
        let window_ms = self.window.as_millis() as u64;
        let Some(state) = self.callers.get(caller_did) else {
            return 0;
        };
        let elapsed = now.saturating_sub(state.window_start);
        let remaining_ms = window_ms.saturating_sub(elapsed);
        // Ceiling division: round up so callers never retry too early.
        remaining_ms.div_ceil(1000)
    }
}

// ---------------------------------------------------------------------------
// OutletInterface
// ---------------------------------------------------------------------------

/// A cross-context tool interface with bidirectional consent and dual policies.
///
/// Represents an agreement between two contexts to share access to a specific
/// tool. Both contexts must approve the interface before any calls are
/// permitted. Dual rate limiting (per-interface + per-caller) is enforced.
///
/// See ADR-010 section 6 and spec section 6.2, §6.2.0.1, §6.2.0.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutletInterface {
    /// The context exposing (sourcing) the tool.
    pub source_context: ContextId,
    /// The context consuming (targeting) the tool.
    pub target_context: ContextId,
    /// The tool being shared across contexts.
    pub outlet_id: OutletId,
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
    pub outlet_id: OutletId,
    /// The context that initiated the call (source).
    pub source_context: ContextId,
    /// The context that received the call (target).
    pub target_context: ContextId,
    /// The DID of the invoker.
    pub invoker_did: DID,
    /// Terminal status of the invocation.
    pub status: OutletStatus,
    /// SHA-256 hash of the input (hex-encoded).
    pub input_hash: String,
    /// SHA-256 hash of the output (hex-encoded), if output was produced.
    pub output_hash: Option<String>,
    /// Provenance metadata for this cross-context data flow (§7.7.1).
    ///
    /// Attached automatically by [`invoke_cross_context`] from the source
    /// context's [`SourceContextInfo`]. Records origin, counterparties,
    /// chain depth, and economic provenance.
    pub provenance: Option<DataProvenance>,
}

// ---------------------------------------------------------------------------
// expose_tool
// ---------------------------------------------------------------------------

/// Initiates a cross-context tool interface proposal from the source context.
///
/// The caller (admin of the source context) proposes sharing a specific tool
/// with the target context. The returned [`OutletInterface`] has
/// `approved_by_source = true` and `approved_by_target = false`. The target
/// context must call [`accept_tool_interface`] to complete the handshake.
///
/// Creates the interface with an [`OutboundPolicy`] (set by source context) and
/// a per-caller rate limit derived from the registered outlet's
/// [`OutletKind`] via [`OutletInterfaceDefaults::for_kind`]. Per spec
/// §6.2.0.2 the defaults are `600 / 100` (per-interface / per-caller) for
/// [`OutletKind::Query`] and `60 / 10` for [`OutletKind::Action`]. When the
/// caller passes an explicit `outbound_policy`, its `max_calls_per_minute`
/// is preserved verbatim regardless of kind.
///
/// # Arguments
///
/// * `context` - The source context handle.
/// * `outlet_id` - The ID of the tool to expose.
/// * `to_context` - The target context ID.
/// * `role_state` - The source context's role state for capability checking.
/// * `admin_did` - The DID of the admin proposing the interface.
/// * `registry` - The source context's tool registry.
/// * `rate_limit` - Optional per-interface rate limit. When `None`, no
///   per-interface counter is installed (the per-caller counter still
///   applies; spec §6.2.0.2 leaves the per-interface counter optional —
///   callers wire it explicitly when they want a context-wide cap).
/// * `outbound_policy` - Optional outbound policy. When `None`, defaults
///   to [`OutboundPolicy::for_kind`] using the registered outlet's
///   [`OutletKind`] — Query → 600 calls/min, Action → 60 calls/min
///   (spec §6.2.0.2 classification-aware tiers).
///
/// # Errors
///
/// Returns [`OutletError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`OutletError::OutletNotFound`] if the tool is not in the registry.
#[allow(clippy::too_many_arguments)]
pub fn expose_tool(
    context_id: &str,
    outlet_id: &OutletId,
    to_context: &ContextId,
    role_state: &ContextRoleState,
    admin_did: &str,
    registry: &OutletRegistry,
    rate_limit: Option<RateLimit>,
    outbound_policy: Option<OutboundPolicy>,
) -> Result<OutletInterface, OutletError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(OutletError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the tool exists in the source context's registry and recover
    // its declared OutletKind. The kind drives the §6.2.0.2 default rate
    // tier — Query gets 600/100, Action gets 60/10 — when the caller did
    // not supply an explicit `outbound_policy` or `rate_limit`. Reading
    // the kind from the *registered* outlet (not a parameter) means the
    // tier always matches the declaration the source context committed
    // to at registration time.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| OutletError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    let kind = registration.kind;

    let defaults = OutletInterfaceDefaults::for_kind(kind);
    let default_window = Duration::from_secs(DEFAULT_WINDOW_SECONDS);
    Ok(OutletInterface {
        source_context: context_id.to_owned(),
        target_context: to_context.to_owned(),
        outlet_id: outlet_id.to_owned(),
        rate_limit,
        // §6.2.0.2 per-caller default keyed to the registered kind:
        // 100/min for Query, 10/min for Action.
        per_caller_rate_limit: Some(PerCallerRateLimit::new(
            u64::from(defaults.per_caller_calls_per_minute),
            default_window,
        )),
        approved_by_source: true,
        approved_by_target: false,
        // §6.2.0.2 per-interface default keyed to the registered kind
        // when no caller-supplied policy is present (AC3/AC4). Caller's
        // explicit policy is passed through untouched (AC5).
        outbound_policy: Some(outbound_policy.unwrap_or_else(|| OutboundPolicy::for_kind(kind))),
        inbound_policy: None,
    })
}

/// Creates an [`InterfaceOffer`] from an approved tool interface proposal.
///
/// Called after the source context's governance has approved the proposal.
/// The offer includes the full tool schema and expires after 7 days.
///
/// **Kind-aware default (§6.2.0.2).** When the source `interface` has no
/// `outbound_policy` set, the helper fills one in from
/// [`OutboundPolicy::for_kind`] keyed to `tool_registration.kind` so the
/// published offer's `max_calls_per_minute` matches the §6.2.0.2 tier
/// (Query → 600/min, Action → 60/min). When the interface already carries
/// an `outbound_policy`, that policy is passed through unchanged — explicit
/// caller values are preserved regardless of kind (AC5).
///
/// # Arguments
///
/// * `interface` - The approved tool interface.
/// * `tool_registration` - Full tool registration from the registry. Its
///   `kind` field selects the §6.2.0.2 default rate tier when the
///   interface omits an `outbound_policy`.
/// * `timestamp_ms` - Current timestamp in milliseconds.
///
/// # Returns
///
/// An [`InterfaceOffer`] to be published in the source context's event log.
#[must_use]
pub fn create_interface_offer(
    interface: &OutletInterface,
    tool_registration: &OutletRegistration,
    timestamp_ms: u64,
) -> InterfaceOffer {
    let offer_id = InterfaceOffer::compute_offer_id(
        &interface.source_context,
        &interface.outlet_id,
        &interface.target_context,
        timestamp_ms,
    );

    // §6.2.0.2 default is keyed to the registered kind. When the
    // source interface already carries an explicit `outbound_policy`, it
    // is preserved verbatim (AC5). When omitted, fall back to the
    // kind-aware §6.2.0.2 default — Query → 600/min, Action → 60/min
    // (AC3/AC4).
    let outbound_policy = interface
        .outbound_policy
        .clone()
        .unwrap_or_else(|| OutboundPolicy::for_kind(tool_registration.kind));

    InterfaceOffer {
        offer_id,
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        outlet_schema: tool_registration.clone(),
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
/// **Default rate tier.** When `inbound_policy` is `None` this helper falls
/// back to [`InboundPolicy::default()`] — the §5.4.2 fail-safe Action tier
/// (60 calls/min). Callers that already know the accepted outlet's
/// [`OutletKind`] (typically from the matched [`InterfaceOffer::outlet_schema`])
/// SHOULD use [`accept_tool_interface_with_kind`] instead so the §6.2.0.2
/// default lines up with the kind (Query → 600/min, Action → 60/min). When
/// `inbound_policy` is `Some`, that policy is preserved verbatim regardless
/// of kind (AC5).
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
/// Returns [`OutletError::InterfaceAdminRequired`] if the caller is not an admin.
/// Returns [`OutletError::InterfaceContextMismatch`] if the interface's target
/// context does not match the provided context handle.
pub fn accept_tool_interface(
    context_id: &str,
    interface: &mut OutletInterface,
    role_state: &ContextRoleState,
    admin_did: &str,
    inbound_policy: Option<InboundPolicy>,
) -> Result<(), OutletError> {
    accept_tool_interface_with_kind(
        context_id,
        interface,
        role_state,
        admin_did,
        inbound_policy,
        None,
    )
}

/// Kind-aware variant of [`accept_tool_interface`] (spec §6.2.0.2).
///
/// Identical to [`accept_tool_interface`] except that when `inbound_policy`
/// is `None` and `kind` is `Some`, the helper fills in
/// [`InboundPolicy::for_kind`] keyed to that [`OutletKind`] so the accept
/// side's default `max_calls_per_minute` matches the §6.2.0.2 tier (Query
/// → 600/min, Action → 60/min). When `kind` is `None`, falls back to
/// [`InboundPolicy::default()`] (Action tier — §5.4.2 fail-safe).
///
/// Callers that hold the matched [`InterfaceOffer`] should pass
/// `Some(offer.outlet_schema.kind)` so the inbound default matches the
/// outbound default the offer carries — this preserves the
/// `min(outbound.max_calls_per_minute, inbound.max_calls_per_minute)`
/// effective-limit semantics from §6.2.0.1 across the kind tiers.
///
/// **Explicit values preserved.** When `inbound_policy` is `Some`, that
/// policy is preserved verbatim regardless of `kind` (AC5).
///
/// # Errors
///
/// Same as [`accept_tool_interface`]:
/// [`OutletError::InterfaceAdminRequired`] when the caller is not an admin
/// and [`OutletError::InterfaceContextMismatch`] when the interface's
/// target context does not match the provided context handle.
pub fn accept_tool_interface_with_kind(
    context_id: &str,
    interface: &mut OutletInterface,
    role_state: &ContextRoleState,
    admin_did: &str,
    inbound_policy: Option<InboundPolicy>,
    kind: Option<OutletKind>,
) -> Result<(), OutletError> {
    // Require admin capability.
    if !has_admin_role(role_state, admin_did) {
        return Err(OutletError::InterfaceAdminRequired {
            did: admin_did.to_owned(),
        });
    }

    // Verify the interface targets this context.
    if interface.target_context != context_id {
        return Err(OutletError::InterfaceContextMismatch {
            expected: interface.target_context.clone(),
            actual: context_id.to_owned(),
        });
    }

    interface.approved_by_target = true;
    // §6.2.0.2 kind-aware default for the inbound policy. Caller-supplied
    // policy is preserved verbatim (AC5); when `inbound_policy` is `None`
    // and `kind` is supplied, defaults are derived from the kind via
    // `InboundPolicy::for_kind` — Query → 600/min, Action → 60/min. When
    // both are `None`, falls back to the §5.4.2 fail-safe Action default.
    interface.inbound_policy = Some(
        inbound_policy
            .unwrap_or_else(|| kind.map_or_else(InboundPolicy::default, InboundPolicy::for_kind)),
    );
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
/// Returns [`OutletError::ChainDepthExceeded`] if `chain_depth` exceeds the
/// source context's effective max chain depth (default 8 per ADR-043).
/// Returns [`OutletError::InterfaceNotApproved`] if either context has not
/// approved the interface.
/// Returns [`OutletError::InterfaceRateLimited`] if either the per-interface
/// or per-caller rate limit is exceeded.
/// Returns [`OutletError::InterfaceCallerNotAllowed`] if the invoker is not
/// in the outbound policy's `allowed_callers` list.
/// Returns [`OutletError::InterfacePayloadTooLarge`] if the serialized input
/// exceeds the outbound policy's `max_payload_bytes`.
/// Returns [`OutletError::InterfaceResponseTooLarge`] if the serialized output
/// exceeds the inbound policy's `max_response_bytes`.
/// Returns [`OutletError::InterfaceAdminRequired`] if the invoker lacks the
/// required capability in the source context.
#[allow(clippy::too_many_arguments)]
pub fn invoke_cross_context<F>(
    source_context_id: &str,
    source_max_chain_depth: Option<u8>,
    interface: &mut OutletInterface,
    input: &serde_json::Value,
    invoker_did: &DID,
    source_role_state: &ContextRoleState,
    target_registry: &OutletRegistry,
    chain_depth: u8,
    executor: F,
    clock: &dyn Clock,
    source_context_info: &SourceContextInfo,
) -> Result<
    (
        serde_json::Value,
        CrossContextToolEvent,
        CrossContextToolEvent,
    ),
    OutletError,
>
where
    F: FnOnce(&serde_json::Value) -> Result<serde_json::Value, String>,
{
    // 0. Enforce chain depth limit from the source context's configured max
    // (spec §24.4). Falls back to DEFAULT_MAX_CHAIN_DEPTH (8) when unconfigured (ADR-043).
    let max_depth = effective_max_chain_depth(source_max_chain_depth);
    if chain_depth > max_depth {
        return Err(OutletError::ChainDepthExceeded {
            depth: chain_depth,
            max_depth,
        });
    }

    // 1. Both sides must have approved.
    if !interface.approved_by_source || !interface.approved_by_target {
        return Err(OutletError::InterfaceNotApproved {
            source_approved: interface.approved_by_source,
            target_approved: interface.approved_by_target,
        });
    }

    // Verify the source context matches the interface.
    if interface.source_context != source_context_id {
        return Err(OutletError::InterfaceContextMismatch {
            expected: interface.source_context.clone(),
            actual: source_context_id.to_owned(),
        });
    }

    // 2. Check per-interface rate limit (spec §6.2.0.2).
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut rate_limit) = interface.rate_limit
        && !rate_limit.check_and_increment(clock)
    {
        // Window durations are always far below u64::MAX milliseconds.
        let window_ms = rate_limit.window.as_millis() as u64;
        let retry_after_secs = rate_limit.retry_after_secs(clock);
        return Err(OutletError::InterfaceRateLimited {
            max_calls: rate_limit.max_calls,
            window_ms,
            retry_after_secs,
        });
    }

    // 3. Check per-caller rate limit independently (spec §6.2.0.2).
    #[allow(clippy::cast_possible_truncation)]
    if let Some(ref mut per_caller_rl) = interface.per_caller_rate_limit
        && !per_caller_rl.check_and_increment(invoker_did, clock)
    {
        let window_ms = per_caller_rl.window.as_millis() as u64;
        let retry_after_secs = per_caller_rl.retry_after_secs_for(invoker_did, clock);
        return Err(OutletError::InterfaceRateLimited {
            max_calls: per_caller_rl.max_calls_per_caller,
            window_ms,
            retry_after_secs,
        });
    }

    // 4. Outbound policy enforcement (§6.2.0.1): allowed_callers and payload size.
    if let Some(ref outbound) = interface.outbound_policy {
        // allowed_callers: empty means any member with OutletInterface capability.
        if !outbound.allowed_callers.is_empty() && !outbound.allowed_callers.contains(invoker_did) {
            return Err(OutletError::InterfaceCallerNotAllowed {
                did: invoker_did.to_string(),
            });
        }

        // max_payload_bytes: check serialized input size.
        let input_bytes = serde_json::to_vec(input).unwrap_or_default();
        if input_bytes.len() > outbound.max_payload_bytes as usize {
            return Err(OutletError::InterfacePayloadTooLarge {
                actual: input_bytes.len(),
                max: outbound.max_payload_bytes,
            });
        }
    }

    // 5. Source context governance: invoker must have tool invoke capability.
    if !super::has_outlet_call_capability(source_role_state, invoker_did, &interface.outlet_id) {
        return Err(OutletError::InterfaceInvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: interface.outlet_id.clone(),
        });
    }

    // 6. Target context governance: tool must exist in target registry.
    if !target_registry.contains(&interface.outlet_id) {
        return Err(OutletError::OutletNotFound {
            outlet_id: interface.outlet_id.clone(),
        });
    }

    // 7. Execute the tool.
    let output =
        executor(input).map_err(|msg| OutletError::InterfaceExecutionFailed { message: msg })?;

    // 8. Inbound policy enforcement (§6.2.0.1): response payload size.
    if let Some(ref inbound) = interface.inbound_policy {
        let response_bytes = serde_json::to_vec(&output).unwrap_or_default();
        if response_bytes.len() > inbound.max_response_bytes as usize {
            return Err(OutletError::InterfaceResponseTooLarge {
                actual: response_bytes.len(),
                max: inbound.max_response_bytes,
            });
        }
    }

    // 9. Attach provenance (§7.7.1, §24.3).
    let provenance =
        build_invocation_provenance(source_context_info, &interface.target_context, chain_depth);

    // 10. Build event payloads for both contexts.
    let (source_event, target_event) =
        build_cross_context_events(interface, input, &output, invoker_did, &provenance);

    Ok((output, source_event, target_event))
}

/// Constructs [`DataProvenance`] for a cross-context tool invocation (§7.7.1).
///
/// When `chain_depth > 0`, synthesizes a minimal existing provenance record so
/// [`attach_provenance`] correctly increments the chain depth and extends the
/// chain path. On the first hop (`chain_depth == 0`), no existing provenance
/// is passed and `chain_depth` starts at 0.
fn build_invocation_provenance(
    source_context_info: &SourceContextInfo,
    target_context: &ContextId,
    chain_depth: u8,
) -> DataProvenance {
    let existing = if chain_depth > 0 {
        Some(DataProvenance {
            source_context: source_context_info.context_id.clone(),
            source_type: source_context_info.source_type,
            counterparties: Vec::new(),
            purpose: None,
            discovery_method: source_context_info.discovery_method.clone(),
            age: source_context_info.data_age,
            memory_scope: source_context_info.memory_scope,
            chain_depth: chain_depth.saturating_sub(1),
            chain_path: None,
            payment_amount: None,
            payment_adapter: None,
            payment_receipt_id: None,
        })
    } else {
        None
    };

    attach_provenance(
        source_context_info,
        target_context,
        existing.as_ref(),
        None, // pseudonym key — applied upstream by the context manager
        None, // payment info — not available at this layer
    )
}

/// Builds matched event payloads for the source and target contexts of a
/// cross-context tool invocation. Both events share the same `request_id`.
fn build_cross_context_events(
    interface: &OutletInterface,
    input: &serde_json::Value,
    output: &serde_json::Value,
    invoker_did: &DID,
    provenance: &DataProvenance,
) -> (CrossContextToolEvent, CrossContextToolEvent) {
    let request_id = uuid::Uuid::new_v4().to_string();
    let input_hash = sha256_json(input);
    let output_hash = Some(sha256_json(output));

    let source_event = CrossContextToolEvent {
        request_id: request_id.clone(),
        outlet_id: interface.outlet_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: OutletStatus::Success,
        input_hash: input_hash.clone(),
        output_hash: output_hash.clone(),
        provenance: Some(provenance.clone()),
    };

    let target_event = CrossContextToolEvent {
        request_id,
        outlet_id: interface.outlet_id.clone(),
        source_context: interface.source_context.clone(),
        target_context: interface.target_context.clone(),
        invoker_did: invoker_did.to_owned(),
        status: OutletStatus::Success,
        input_hash,
        output_hash,
        provenance: Some(provenance.clone()),
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
    use crate::context::MemoryScope;
    use crate::context::outlets::registry::{OutletRegistry, OutletSchema, register_outlet};
    use crate::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
    use crate::provenance::attach::SourceContextInfo;
    use crate::provenance::evaluate::{SourceContextState, evaluate_quality};
    use crate::provenance::{CounterpartyPolicy, DiscoveryMethod, SourceType};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates a test capability ceiling with all capabilities.
    fn test_ceiling() -> CapabilityCeiling {
        CapabilityCeiling::new([
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::OutletRegister,
            Capability::OutletCallAll,
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
        ContextRoleState::new(
            context_id,
            creator_did,
            test_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap()
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

    /// Returns a test context ID string.
    fn test_context_id(context_id: &str) -> String {
        context_id.to_owned()
    }

    /// Creates a valid tool registration and registers it in a fresh registry.
    fn setup_registry_with_tool(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "calculator".to_owned(),
            kind: crate::context::outlets::OutletKind::Action,
            name: "Calculator".to_owned(),
            description: "A simple calculator".to_owned(),
            schema: OutletSchema {
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
            message_catalog: Vec::new(),
        };
        register_outlet(&mut registry, role_state, registration, registrant_did).unwrap();
        registry
    }

    /// Creates a test `SourceContextInfo` for a given context ID and member DID.
    fn test_source_context_info(context_id: &str, member_did: &str) -> SourceContextInfo {
        SourceContextInfo {
            context_id: context_id.to_owned(),
            source_type: SourceType::Persistent,
            memory_scope: MemoryScope::Full,
            members: vec![DID::from(member_did)],
            discovery_method: DiscoveryMethod::OutOfBand,
            data_age: Duration::from_secs(0),
            purpose: Some("cross-context tool invocation".to_owned()),
            counterparty_policy: CounterpartyPolicy::Full,
        }
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
        let source_context = test_context_id("ctx-source");
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
        assert_eq!(interface.outlet_id, "calculator");
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
        let source_context = test_context_id("ctx-source");
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
            matches!(err, OutletError::InterfaceAdminRequired { .. }),
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
        let source_context = test_context_id("ctx-source");
        let registry = OutletRegistry::new(); // Empty registry

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
            OutletError::OutletNotFound { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // expose_tool: with rate limit
    // -----------------------------------------------------------------------

    #[test]
    fn expose_tool_includes_rate_limit_when_provided() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let registry = setup_registry_with_tool(&source_role_state, admin_did);

        let rate_limit = RateLimit::new(10, Duration::from_mins(1), &scp_primitives::SystemClock);
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
        assert_eq!(rl.window, Duration::from_mins(1));
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
        let target_context = test_context_id("ctx-target");

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
        let target_context = test_context_id("ctx-target");

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            matches!(err, OutletError::InterfaceAdminRequired { .. }),
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
        let target_context = test_context_id("ctx-wrong");

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            OutletError::InterfaceContextMismatch { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_succeeds_with_full_approval() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        )
        .unwrap();

        assert_eq!(output, serde_json::json!({"result": 7.0}));

        // Both events should record the cross-context call.
        assert_eq!(source_event.outlet_id, "calculator");
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.status, OutletStatus::Success);
        assert!(!source_event.input_hash.is_empty());
        assert!(source_event.output_hash.is_some());

        assert_eq!(target_event.outlet_id, "calculator");
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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false, // Target has NOT approved
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::InterfaceNotApproved {
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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: false, // Source has NOT approved
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::InterfaceNotApproved {
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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: false,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::InterfaceNotApproved { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: rate limiting rejects calls beyond limit
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rate_limiting_rejects_beyond_limit() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            // Zero burst to test base limit rejection.
            rate_limit: Some(RateLimit::with_burst(
                2,
                Duration::from_hours(1),
                0,
                Duration::from_secs(1),
                &scp_primitives::SystemClock,
            )),
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
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result1.is_ok(), "first call should succeed");

        // Second call: should succeed (at limit).
        let result2 = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result2.is_ok(), "second call should succeed");

        // Third call: should be rejected (over limit).
        let result3 = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result3.is_err());
        let err = result3.unwrap_err();
        assert!(
            matches!(err, OutletError::InterfaceRateLimited { max_calls: 2, .. }),
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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        )
        .unwrap();

        // Verify provenance in source event.
        assert_eq!(source_event.invoker_did, admin_did);
        assert_eq!(source_event.source_context, "ctx-source");
        assert_eq!(source_event.target_context, "ctx-target");
        assert_eq!(source_event.status, OutletStatus::Success);

        // Verify provenance in target event.
        assert_eq!(target_event.invoker_did, admin_did);
        assert_eq!(target_event.source_context, "ctx-source");
        assert_eq!(target_event.target_context, "ctx-target");
        assert_eq!(target_event.status, OutletStatus::Success);

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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::InterfaceInvokerNotAuthorized { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: tool not found in target
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_when_tool_not_in_target_registry() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_registry = OutletRegistry::new(); // Empty target registry

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OutletError::OutletNotFound { .. }
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
        assert!(rl.check_and_increment(&scp_primitives::SystemClock));
        assert_eq!(rl.current_count, 1);
    }

    // -----------------------------------------------------------------------
    // RateLimit: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limit_serialization_roundtrip() {
        let rl = RateLimit {
            max_calls: 100,
            window: Duration::from_mins(1),
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
    // OutletInterface: serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn tool_interface_serialization_roundtrip() {
        let interface = OutletInterface {
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            outlet_id: "tool-1".to_owned(),
            rate_limit: Some(RateLimit::new(
                50,
                Duration::from_mins(2),
                &scp_primitives::SystemClock,
            )),
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: Some(OutboundPolicy::default()),
            inbound_policy: None,
        };
        let json = serde_json::to_string(&interface).unwrap();
        let deserialized: OutletInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_context, "ctx-a");
        assert_eq!(deserialized.target_context, "ctx-b");
        assert_eq!(deserialized.outlet_id, "tool-1");
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
            outlet_id: "calculator".to_owned(),
            source_context: "ctx-a".to_owned(),
            target_context: "ctx-b".to_owned(),
            invoker_did: "did:dht:z6MkTest".into(),
            status: OutletStatus::Success,
            input_hash: "abcd1234".to_owned(),
            output_hash: Some("efgh5678".to_owned()),
            provenance: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: CrossContextToolEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request_id, "req-1");
        assert_eq!(deserialized.outlet_id, "calculator");
        assert_eq!(deserialized.status, OutletStatus::Success);
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: chain depth exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_rejects_chain_depth_exceeding_max() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        // Chain depth 9 exceeds DEFAULT_MAX_CHAIN_DEPTH (8).
        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            9,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::ChainDepthExceeded {
                    depth: 9,
                    max_depth: 8,
                }
            ),
            "expected ChainDepthExceeded, got {err:?}"
        );
    }

    #[test]
    fn invoke_cross_context_allows_chain_depth_at_max() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        // Chain depth 8 == DEFAULT_MAX_CHAIN_DEPTH, should succeed.
        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            8,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
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
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            None,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            failing_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::InterfaceExecutionFailed { .. }),
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
            PerCallerRateLimit::with_burst(2, Duration::from_hours(1), 0, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();

        // Alice: 2 calls allowed
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));
        assert!(!rl.check_and_increment(&alice, &scp_primitives::SystemClock));

        // Bob: still has 2 calls
        assert!(rl.check_and_increment(&bob, &scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&bob, &scp_primitives::SystemClock));
        assert!(!rl.check_and_increment(&bob, &scp_primitives::SystemClock));
    }

    #[test]
    fn per_caller_rate_limit_window_reset() {
        // Use a long window so CI timing can't cause spurious resets.
        // Zero burst to test base limit behavior independently.
        let mut rl =
            PerCallerRateLimit::with_burst(1, Duration::from_hours(1), 0, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));
        assert!(!rl.check_and_increment(&alice, &scp_primitives::SystemClock));

        // Set the window start far in the past to simulate window expiry.
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.window_start = 0;
        }
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));
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
            outlet_schema: OutletRegistration {
                outlet_id: "t".to_owned(),
                kind: crate::context::outlets::OutletKind::Action,
                name: "T".to_owned(),
                description: "test".to_owned(),
                schema: OutletSchema {
                    input_schema: serde_json::json!({"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}}),
                    output_schema: serde_json::json!({"type": "object", "properties": {"r": {"type": "number"}}}),
                },
                implementation_hash: [0u8; 32],
                test_vectors: vec![],
                operator_did: "did:dht:z6MkOp".into(),
                cost: None,
                registered_at: 0,
                signature: Vec::new(),
                message_catalog: Vec::new(),
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
        // Context with max_chain_depth = 1.
        let source_context = "ctx-source".to_owned();
        let source_max_chain_depth = Some(1u8);
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
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
            source_max_chain_depth,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            1,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result.is_ok());

        // Depth 2 should fail (exceeds configured max of 1).
        let result = invoke_cross_context(
            &source_context,
            source_max_chain_depth,
            &mut interface,
            &serde_json::json!({"a": 1, "b": 2}),
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            2,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                OutletError::ChainDepthExceeded {
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
        let mut rl = RateLimit::with_burst(
            2,
            Duration::from_hours(1),
            5,
            Duration::from_secs(1),
            &scp_primitives::SystemClock,
        );

        // First 2 calls: within base limit.
        assert!(rl.check_and_increment(&scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&scp_primitives::SystemClock));

        // Next 5 calls: within burst allowance.
        for i in 0..5 {
            assert!(
                rl.check_and_increment(&scp_primitives::SystemClock),
                "burst call {i} should succeed"
            );
        }

        // 8th call (6th above base): exceeds burst allowance.
        assert!(
            !rl.check_and_increment(&scp_primitives::SystemClock),
            "call beyond burst allowance should fail"
        );
    }

    #[test]
    fn rate_limit_burst_of_5_rapid_calls_above_limit_succeeds_6th_fails() {
        // Spec §6.2.0.2: "5 calls above the per-minute limit within a
        // 1-second window." Exactly 5 burst calls succeed, 6th fails.
        let mut rl = RateLimit::with_burst(
            1,
            Duration::from_hours(1),
            DEFAULT_BURST_ALLOWANCE,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
            &scp_primitives::SystemClock,
        );

        // Base call.
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "base call should succeed"
        );

        // 5 burst calls above the limit.
        for i in 0..5 {
            assert!(
                rl.check_and_increment(&scp_primitives::SystemClock),
                "burst call {i} should succeed"
            );
        }

        // 6th call above the limit: must fail.
        assert!(
            !rl.check_and_increment(&scp_primitives::SystemClock),
            "6th call above limit should fail"
        );
    }

    #[test]
    fn rate_limit_zero_burst_disables_burst() {
        let mut rl = RateLimit::with_burst(
            1,
            Duration::from_hours(1),
            0,
            Duration::from_secs(1),
            &scp_primitives::SystemClock,
        );

        assert!(rl.check_and_increment(&scp_primitives::SystemClock));
        // With zero burst, immediately fails after base limit.
        assert!(!rl.check_and_increment(&scp_primitives::SystemClock));
    }

    #[test]
    fn rate_limit_burst_allowance_clamped_to_max() {
        let rl = RateLimit::with_burst(
            10,
            Duration::from_mins(1),
            100, // Above MAX_BURST_ALLOWANCE (50)
            Duration::from_secs(1),
            &scp_primitives::SystemClock,
        );

        assert_eq!(rl.burst_allowance, MAX_BURST_ALLOWANCE);
    }

    #[test]
    fn rate_limit_new_has_default_burst() {
        let rl = RateLimit::new(60, Duration::from_mins(1), &scp_primitives::SystemClock);
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
            PerCallerRateLimit::with_burst(2, Duration::from_hours(1), 5, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Base: 2 calls.
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock));

        // Burst: 5 calls.
        for i in 0..5 {
            assert!(
                rl.check_and_increment(&alice, &scp_primitives::SystemClock),
                "burst call {i} should succeed"
            );
        }

        // 6th above base: fails.
        assert!(!rl.check_and_increment(&alice, &scp_primitives::SystemClock));
    }

    #[test]
    fn per_caller_rate_limit_burst_is_independent_per_caller() {
        let mut rl =
            PerCallerRateLimit::with_burst(1, Duration::from_hours(1), 2, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();
        let bob: DID = "did:dht:z6MkBob".into();

        // Alice exhausts base + burst.
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock)); // base
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock)); // burst 1
        assert!(rl.check_and_increment(&alice, &scp_primitives::SystemClock)); // burst 2
        assert!(!rl.check_and_increment(&alice, &scp_primitives::SystemClock)); // over

        // Bob still has full base + burst.
        assert!(rl.check_and_increment(&bob, &scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&bob, &scp_primitives::SystemClock));
        assert!(rl.check_and_increment(&bob, &scp_primitives::SystemClock));
        assert!(!rl.check_and_increment(&bob, &scp_primitives::SystemClock));
    }

    #[test]
    fn per_caller_rate_limit_new_has_default_burst() {
        let rl = PerCallerRateLimit::new(10, Duration::from_mins(1));
        assert_eq!(rl.burst_allowance, DEFAULT_BURST_ALLOWANCE);
        assert_eq!(
            rl.burst_window,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS)
        );
    }

    #[test]
    fn per_caller_rate_limit_burst_clamped_to_max() {
        let rl =
            PerCallerRateLimit::with_burst(10, Duration::from_mins(1), 100, Duration::from_secs(1));
        assert_eq!(rl.burst_allowance, MAX_BURST_ALLOWANCE);
    }

    #[test]
    fn invoke_cross_context_burst_allows_calls_above_limit() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        // Base limit: 2 calls, burst allowance: 5.
        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: Some(RateLimit::with_burst(
                2,
                Duration::from_hours(1),
                5,
                Duration::from_secs(1),
                &scp_primitives::SystemClock,
            )),
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
                None,
                &mut interface,
                &input,
                &DID::from(admin_did),
                &source_role_state,
                &target_registry,
                0,
                add_executor,
                &scp_primitives::SystemClock,
                &test_source_context_info("ctx-source", admin_did),
            );
            assert!(result.is_ok(), "base call {i} should succeed");
        }

        // Next 5 calls: within burst allowance.
        for i in 0..5 {
            let result = invoke_cross_context(
                &source_context,
                None,
                &mut interface,
                &input,
                &DID::from(admin_did),
                &source_role_state,
                &target_registry,
                0,
                add_executor,
                &scp_primitives::SystemClock,
                &test_source_context_info("ctx-source", admin_did),
            );
            assert!(result.is_ok(), "burst call {i} should succeed");
        }

        // 8th call: exceeds burst allowance.
        let result = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &test_source_context_info("ctx-source", admin_did),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OutletError::InterfaceRateLimited { max_calls: 2, .. }),
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
        let mut rl = RateLimit::with_burst(
            2,
            Duration::from_hours(1),
            5,
            Duration::from_secs(1),
            &scp_primitives::SystemClock,
        );

        // Consume the 2 base calls.
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "base call 1"
        );
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "base call 2"
        );

        // Simulate being 30 seconds into the base window: push burst_window_start
        // 30s into the past to mimic the scenario where construction happened
        // 30s ago. Without the fix, the 1s burst window is long expired.
        rl.burst_window_start = rl.burst_window_start.saturating_sub(30_000);

        // With lazy initialization, the first burst call re-anchors
        // burst_window_start to now, so all burst calls should succeed.
        for i in 1..=5 {
            assert!(
                rl.check_and_increment(&scp_primitives::SystemClock),
                "burst call {i} should succeed — burst window lazily initialized"
            );
        }

        // 6th burst call should fail (burst allowance exhausted).
        assert!(
            !rl.check_and_increment(&scp_primitives::SystemClock),
            "burst call 6 should fail — burst allowance exhausted"
        );
    }

    #[test]
    fn per_caller_burst_works_when_base_exhausted_after_burst_window_would_expire() {
        // Same regression test for PerCallerRateLimit (#588 R2-01).
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_hours(1), 5, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Consume the 2 base calls.
        assert!(
            rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "base call 1"
        );
        assert!(
            rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "base call 2"
        );

        // Simulate being 30 seconds into the base window.
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.burst_window_start = state.burst_window_start.saturating_sub(30_000);
        }

        // With lazy initialization, all burst calls should succeed.
        for i in 1..=5 {
            assert!(
                rl.check_and_increment(&alice, &scp_primitives::SystemClock),
                "burst call {i} should succeed — burst window lazily initialized"
            );
        }

        // 6th burst call should fail.
        assert!(
            !rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "burst call 6 should fail — burst allowance exhausted"
        );
    }

    #[test]
    fn rate_limit_burst_not_renewed_after_burst_window_expires() {
        // Base limit: 2 calls within a 1-hour window.
        // Burst: 3 calls within a 1-second burst window.
        let mut rl = RateLimit::with_burst(
            2,
            Duration::from_hours(1),
            3,
            Duration::from_secs(1),
            &scp_primitives::SystemClock,
        );

        // Consume the 2 base calls.
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "base call 1"
        );
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "base call 2"
        );

        // Use 1 of 3 burst calls (burst window starts now).
        assert!(
            rl.check_and_increment(&scp_primitives::SystemClock),
            "burst call 1"
        );

        // Simulate burst window expiry by pushing burst_window_start into the
        // past. The base window is still active (1-hour window).
        rl.burst_window_start = 0;

        // After burst window expires, NO more burst calls should be allowed
        // until the base window resets. This verifies the burst window is a
        // deadline, not a renewable cycle.
        assert!(
            !rl.check_and_increment(&scp_primitives::SystemClock),
            "burst must NOT renew after burst window expires within base window"
        );
    }

    #[test]
    fn per_caller_burst_not_renewed_after_burst_window_expires() {
        // Base limit: 2 calls within a 1-hour window.
        // Burst: 3 calls within a 1-second burst window.
        let mut rl =
            PerCallerRateLimit::with_burst(2, Duration::from_hours(1), 3, Duration::from_secs(1));
        let alice: DID = "did:dht:z6MkAlice".into();

        // Consume the 2 base calls.
        assert!(
            rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "base call 1"
        );
        assert!(
            rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "base call 2"
        );

        // Use 1 of 3 burst calls (burst window starts now).
        assert!(
            rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "burst call 1"
        );

        // Simulate burst window expiry by pushing burst_window_start into the
        // past. The base window is still active (1-hour window).
        if let Some(state) = rl.callers.get_mut(&alice) {
            state.burst_window_start = 0;
        }

        // After burst window expires, NO more burst calls should be allowed
        // until the base window resets.
        assert!(
            !rl.check_and_increment(&alice, &scp_primitives::SystemClock),
            "per-caller burst must NOT renew after burst window expires within base window"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_cross_context: provenance attachment (§7.7.1)
    // -----------------------------------------------------------------------

    #[test]
    fn invoke_cross_context_attaches_provenance_with_correct_source_context() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let src_info = SourceContextInfo {
            context_id: "ctx-source".to_owned(),
            source_type: SourceType::Persistent,
            memory_scope: MemoryScope::Full,
            members: vec![DID::from(admin_did)],
            discovery_method: DiscoveryMethod::OutOfBand,
            data_age: Duration::from_secs(0),
            purpose: Some("test invocation".to_owned()),
            counterparty_policy: CounterpartyPolicy::Full,
        };

        let input = serde_json::json!({"a": 5, "b": 10});
        let (_output, source_event, target_event) = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &src_info,
        )
        .unwrap();

        // Both events carry provenance.
        let prov = source_event.provenance.as_ref().unwrap();
        assert_eq!(prov.source_context, "ctx-source");
        assert_eq!(prov.source_type, SourceType::Persistent);
        assert_eq!(prov.memory_scope, MemoryScope::Full);
        assert_eq!(prov.chain_depth, 0);
        assert!(prov.chain_path.is_none());
        assert_eq!(prov.purpose, Some("test invocation".to_owned()));
        // Counterparties include the admin DID (Full policy).
        assert_eq!(prov.counterparties, vec![DID::from(admin_did)]);

        // Target event carries the same provenance.
        let target_prov = target_event.provenance.as_ref().unwrap();
        assert_eq!(target_prov.source_context, "ctx-source");
        assert_eq!(target_prov.chain_depth, 0);
    }

    #[test]
    fn invoke_cross_context_provenance_evaluates_to_persistent_verifiable() {
        let admin_did = "did:dht:z6MkAdmin";
        let source_role_state = test_role_state("ctx-source", admin_did);
        let source_context = test_context_id("ctx-source");
        let target_role_state = test_role_state("ctx-target", admin_did);
        let target_registry = setup_registry_with_tool(&target_role_state, admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "calculator".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: true,
            outbound_policy: None,
            inbound_policy: None,
        };

        let src_info = SourceContextInfo {
            context_id: "ctx-source".to_owned(),
            source_type: SourceType::Persistent,
            memory_scope: MemoryScope::Full,
            members: vec![DID::from(admin_did)],
            discovery_method: DiscoveryMethod::OutOfBand,
            data_age: Duration::from_secs(0),
            purpose: None,
            counterparty_policy: CounterpartyPolicy::Full,
        };

        let input = serde_json::json!({"a": 1, "b": 2});
        let (_output, source_event, _target_event) = invoke_cross_context(
            &source_context,
            None,
            &mut interface,
            &input,
            &DID::from(admin_did),
            &source_role_state,
            &target_registry,
            0,
            add_executor,
            &scp_primitives::SystemClock,
            &src_info,
        )
        .unwrap();

        // Evaluate quality: persistent source, active context -> PersistentVerifiable.
        let prov = source_event.provenance.as_ref().unwrap();
        let quality = evaluate_quality(Some(prov), &SourceContextState::Active);
        assert_eq!(
            quality,
            crate::provenance::ProvenanceQuality::PersistentVerifiable,
            "persistent + active source should evaluate to PersistentVerifiable"
        );
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-016 — Per-kind cross-context rate tier defaults (§6.2.0.2)
    // -----------------------------------------------------------------------
    //
    // AC1: OutletInterfaceDefaults::for_kind(OutletKind::Query) returns (600, 100)
    // AC2: OutletInterfaceDefaults::for_kind(OutletKind::Action) returns (60, 10)
    // AC3: When an InterfaceOffer is built for a Query outlet and the caller
    //      omits max_calls_per_minute, the runtime writes 600
    // AC4: When an InterfaceOffer is built for an Action outlet and the caller
    //      omits max_calls_per_minute, the runtime writes 60
    // AC5: Explicit max_calls_per_minute values are preserved regardless of kind
    // AC6: A rate-limit unit test for both tiers
    // AC7: cargo test --workspace succeeds (covered by these tests + workspace)

    /// Helper: construct an [`OutletRegistration`] with the given kind for
    /// SCP-OUT-016 tests. Mirrors `setup_registry_with_tool` but parameterised
    /// on `kind` so the AC3/AC4 tests can register Query *and* Action tools.
    fn registration_for_kind(outlet_id: &str, kind: OutletKind) -> OutletRegistration {
        OutletRegistration {
            outlet_id: outlet_id.to_owned(),
            kind,
            name: format!("Test {kind:?}"),
            description: "SCP-OUT-016 fixture".to_owned(),
            schema: OutletSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
            },
            implementation_hash: [0xBB; 32],
            test_vectors: vec![],
            operator_did: "did:dht:z6MkOperator".into(),
            cost: None,
            registered_at: 0,
            signature: Vec::new(),
            message_catalog: Vec::new(),
        }
    }

    /// Helper: registry pre-populated with a single outlet of the given
    /// kind. Bypasses the registration validation path because SCP-OUT-016
    /// only cares about the kind being readable from the registry.
    fn registry_with_kind(outlet_id: &str, kind: OutletKind) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        registry.insert(registration_for_kind(outlet_id, kind));
        registry
    }

    /// AC1: `OutletInterfaceDefaults::for_kind(Query)` returns `(600, 100)`.
    #[test]
    fn ac1_outlet_interface_defaults_for_query_returns_600_100() {
        let defaults = OutletInterfaceDefaults::for_kind(OutletKind::Query);
        assert_eq!(defaults.kind, OutletKind::Query);
        assert_eq!(
            defaults.per_interface_calls_per_minute, 600,
            "§6.2.0.2 Query per-interface tier"
        );
        assert_eq!(
            defaults.per_caller_calls_per_minute, 100,
            "§6.2.0.2 Query per-caller tier"
        );

        // Tuple form (the shape the AC asserts against directly).
        let tuple = OutletInterfaceDefaults::tuple_for_kind(OutletKind::Query);
        assert_eq!(tuple, (600, 100));
    }

    /// AC2: `OutletInterfaceDefaults::for_kind(Action)` returns `(60, 10)`.
    #[test]
    fn ac2_outlet_interface_defaults_for_action_returns_60_10() {
        let defaults = OutletInterfaceDefaults::for_kind(OutletKind::Action);
        assert_eq!(defaults.kind, OutletKind::Action);
        assert_eq!(
            defaults.per_interface_calls_per_minute, 60,
            "§6.2.0.2 Action per-interface tier"
        );
        assert_eq!(
            defaults.per_caller_calls_per_minute, 10,
            "§6.2.0.2 Action per-caller tier"
        );

        // Tuple form.
        let tuple = OutletInterfaceDefaults::tuple_for_kind(OutletKind::Action);
        assert_eq!(tuple, (60, 10));
    }

    /// AC3: When an [`InterfaceOffer`] is built for a Query outlet and the
    /// caller omits `max_calls_per_minute`, the runtime writes 600.
    ///
    /// Verifies the full path: `expose_tool` (no `outbound_policy`) →
    /// `create_interface_offer` → `offer.outbound_policy.max_calls_per_minute`.
    #[test]
    fn ac3_interface_offer_for_query_writes_600_when_caller_omits_value() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-source", admin_did);
        let registry = registry_with_kind("query-outlet", OutletKind::Query);

        // Caller omits both rate_limit AND outbound_policy — the runtime
        // must derive the kind-aware default.
        let interface = expose_tool(
            "ctx-source",
            &"query-outlet".to_owned(),
            &"ctx-target".to_owned(),
            &role_state,
            admin_did,
            &registry,
            None, // rate_limit omitted
            None, // outbound_policy omitted — triggers §6.2.0.2 default-derivation
        )
        .unwrap();

        // §6.2.0.2 Query per-interface tier on the interface itself.
        let interface_outbound = interface
            .outbound_policy
            .as_ref()
            .expect("outbound_policy must be populated by expose_tool");
        assert_eq!(
            interface_outbound.max_calls_per_minute, 600,
            "Query interface omitted-policy default must be 600 (§6.2.0.2)"
        );

        // §6.2.0.2 Query per-caller tier on the per-caller rate limiter.
        let per_caller = interface
            .per_caller_rate_limit
            .as_ref()
            .expect("per_caller_rate_limit must be populated for Query");
        assert_eq!(
            per_caller.max_calls_per_caller, 100,
            "Query per-caller default must be 100 (§6.2.0.2)"
        );

        // Now build the offer — it carries the same defaulted policy.
        let registration = registry.get("query-outlet").unwrap();
        let offer = create_interface_offer(&interface, registration, 1_000);
        assert_eq!(
            offer.outbound_policy.max_calls_per_minute, 600,
            "InterfaceOffer for Query outlet must carry 600 calls/min default (AC3)"
        );

        // The offer also carries the kind through outlet_schema.
        assert_eq!(offer.outlet_schema.kind, OutletKind::Query);
    }

    /// AC4: When an [`InterfaceOffer`] is built for an Action outlet and the
    /// caller omits `max_calls_per_minute`, the runtime writes 60.
    #[test]
    fn ac4_interface_offer_for_action_writes_60_when_caller_omits_value() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-source", admin_did);
        let registry = registry_with_kind("action-outlet", OutletKind::Action);

        let interface = expose_tool(
            "ctx-source",
            &"action-outlet".to_owned(),
            &"ctx-target".to_owned(),
            &role_state,
            admin_did,
            &registry,
            None,
            None, // outbound_policy omitted — Action tier default applies
        )
        .unwrap();

        // §6.2.0.2 Action per-interface tier (the pre-classification baseline).
        let interface_outbound = interface
            .outbound_policy
            .as_ref()
            .expect("outbound_policy must be populated by expose_tool");
        assert_eq!(
            interface_outbound.max_calls_per_minute, 60,
            "Action interface omitted-policy default must be 60 (§6.2.0.2)"
        );

        // §6.2.0.2 Action per-caller tier (10/min).
        let per_caller = interface
            .per_caller_rate_limit
            .as_ref()
            .expect("per_caller_rate_limit must be populated for Action");
        assert_eq!(
            per_caller.max_calls_per_caller, 10,
            "Action per-caller default must be 10 (§6.2.0.2)"
        );

        // Build the offer.
        let registration = registry.get("action-outlet").unwrap();
        let offer = create_interface_offer(&interface, registration, 1_000);
        assert_eq!(
            offer.outbound_policy.max_calls_per_minute, 60,
            "InterfaceOffer for Action outlet must carry 60 calls/min default (AC4)"
        );

        assert_eq!(offer.outlet_schema.kind, OutletKind::Action);
    }

    /// AC5: Explicit `max_calls_per_minute` values are preserved regardless
    /// of kind.
    ///
    /// Drives both Query and Action paths with caller-supplied
    /// `OutboundPolicy` values that diverge from the §6.2.0.2 defaults
    /// (a Query outlet with the Action default, and an Action outlet with
    /// a one-off custom value). After `expose_tool` and
    /// `create_interface_offer` the explicit value MUST round-trip
    /// untouched.
    #[test]
    fn ac5_explicit_max_calls_preserved_regardless_of_kind() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-source", admin_did);

        // Query outlet with an explicit Action-tier (60) policy. The
        // builder MUST preserve the caller's 60 even though Query default
        // would be 600.
        let query_registry = registry_with_kind("query-outlet", OutletKind::Query);
        let explicit_for_query = OutboundPolicy {
            allowed_callers: Vec::new(),
            max_calls_per_minute: 60, // Caller picked the Action tier deliberately
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        let interface = expose_tool(
            "ctx-source",
            &"query-outlet".to_owned(),
            &"ctx-target".to_owned(),
            &role_state,
            admin_did,
            &query_registry,
            None,
            Some(explicit_for_query),
        )
        .unwrap();
        assert_eq!(
            interface
                .outbound_policy
                .as_ref()
                .unwrap()
                .max_calls_per_minute,
            60,
            "explicit value must be preserved for Query outlet (AC5)"
        );
        let registration = query_registry.get("query-outlet").unwrap();
        let offer = create_interface_offer(&interface, registration, 1_000);
        assert_eq!(
            offer.outbound_policy.max_calls_per_minute, 60,
            "explicit value must round-trip into the offer for Query outlet (AC5)"
        );

        // Action outlet with an explicit non-default value (1234) — also
        // preserved.
        let action_registry = registry_with_kind("action-outlet", OutletKind::Action);
        let explicit_for_action = OutboundPolicy {
            allowed_callers: Vec::new(),
            max_calls_per_minute: 1234, // Custom value — neither §6.2.0.2 default
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        let interface2 = expose_tool(
            "ctx-source",
            &"action-outlet".to_owned(),
            &"ctx-target".to_owned(),
            &role_state,
            admin_did,
            &action_registry,
            None,
            Some(explicit_for_action),
        )
        .unwrap();
        assert_eq!(
            interface2
                .outbound_policy
                .as_ref()
                .unwrap()
                .max_calls_per_minute,
            1234,
            "explicit value must be preserved for Action outlet (AC5)"
        );
        let registration2 = action_registry.get("action-outlet").unwrap();
        let offer2 = create_interface_offer(&interface2, registration2, 1_000);
        assert_eq!(
            offer2.outbound_policy.max_calls_per_minute, 1234,
            "explicit value must round-trip into the offer for Action outlet (AC5)"
        );
    }

    /// AC6: A rate-limit unit test for both tiers.
    ///
    /// Drives a [`RateLimit`] at the Query tier (600/min) and at the Action
    /// tier (60/min) and verifies the `check_and_increment` boundary
    /// behaviour at each tier — the 600th Query call passes, the 601st is
    /// rejected; the 60th Action call passes, the 61st is rejected.
    /// Burst allowance is set to 0 so the test isolates base-tier behaviour.
    #[test]
    fn ac6_rate_limit_unit_test_for_both_tiers() {
        // Action tier: 60 calls/min.
        let mut action_rl = RateLimit::with_burst(
            u64::from(DEFAULT_PER_INTERFACE_CALLS_PER_MINUTE),
            Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            0,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
            &scp_primitives::SystemClock,
        );
        assert_eq!(
            action_rl.max_calls, 60,
            "Action tier max_calls must equal §6.2.0.2 default (60)"
        );
        for i in 0..60 {
            assert!(
                action_rl.check_and_increment(&scp_primitives::SystemClock),
                "Action call {i} (1-indexed: {}) must succeed under tier limit",
                i + 1
            );
        }
        assert!(
            !action_rl.check_and_increment(&scp_primitives::SystemClock),
            "Action call 61 must be rejected — tier limit exhausted"
        );

        // Query tier: 600 calls/min.
        let mut query_rl = RateLimit::with_burst(
            u64::from(DEFAULT_QUERY_PER_INTERFACE_CALLS_PER_MINUTE),
            Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            0,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
            &scp_primitives::SystemClock,
        );
        assert_eq!(
            query_rl.max_calls, 600,
            "Query tier max_calls must equal §6.2.0.2 default (600)"
        );
        for i in 0..600 {
            assert!(
                query_rl.check_and_increment(&scp_primitives::SystemClock),
                "Query call {i} must succeed under tier limit",
            );
        }
        assert!(
            !query_rl.check_and_increment(&scp_primitives::SystemClock),
            "Query call 601 must be rejected — tier limit exhausted"
        );

        // Per-caller tiers also exercise the boundary at the §6.2.0.2
        // per-caller defaults (Query 100/min, Action 10/min). Burst zero
        // so we isolate base-tier behaviour.
        let alice: DID = "did:dht:z6MkAlice".into();
        let mut action_per_caller = PerCallerRateLimit::with_burst(
            u64::from(DEFAULT_PER_CALLER_CALLS_PER_MINUTE),
            Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            0,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
        );
        for i in 0..10 {
            assert!(
                action_per_caller.check_and_increment(&alice, &scp_primitives::SystemClock),
                "Action per-caller call {i} must succeed under tier (10)",
            );
        }
        assert!(
            !action_per_caller.check_and_increment(&alice, &scp_primitives::SystemClock),
            "Action per-caller call 11 must be rejected"
        );

        let mut query_per_caller = PerCallerRateLimit::with_burst(
            u64::from(DEFAULT_QUERY_PER_CALLER_CALLS_PER_MINUTE),
            Duration::from_secs(DEFAULT_WINDOW_SECONDS),
            0,
            Duration::from_secs(DEFAULT_BURST_WINDOW_SECS),
        );
        for i in 0..100 {
            assert!(
                query_per_caller.check_and_increment(&alice, &scp_primitives::SystemClock),
                "Query per-caller call {i} must succeed under tier (100)",
            );
        }
        assert!(
            !query_per_caller.check_and_increment(&alice, &scp_primitives::SystemClock),
            "Query per-caller call 101 must be rejected"
        );
    }

    /// `OutboundPolicy::for_kind(Query)` returns the Query tier (600).
    #[test]
    fn outbound_policy_for_kind_query_uses_600() {
        let policy = OutboundPolicy::for_kind(OutletKind::Query);
        assert_eq!(policy.max_calls_per_minute, 600);
        assert!(policy.allowed_callers.is_empty());
        assert_eq!(policy.max_payload_bytes, 65_536);
        assert!(policy.require_provenance);
    }

    /// `OutboundPolicy::for_kind(Action)` returns the Action tier (60) —
    /// matches the Default impl which is fail-safe Action.
    #[test]
    fn outbound_policy_for_kind_action_matches_default() {
        let policy = OutboundPolicy::for_kind(OutletKind::Action);
        assert_eq!(policy.max_calls_per_minute, 60);
        assert_eq!(policy, OutboundPolicy::default());
    }

    /// `InboundPolicy::for_kind(Query)` returns the Query tier (600).
    #[test]
    fn inbound_policy_for_kind_query_uses_600() {
        let policy = InboundPolicy::for_kind(OutletKind::Query);
        assert_eq!(policy.max_calls_per_minute, 600);
        assert!(policy.allowed_source_roles.is_empty());
        assert_eq!(policy.max_response_bytes, 65_536);
        assert!(!policy.require_spending_ucan);
    }

    /// `InboundPolicy::for_kind(Action)` returns the Action tier (60) —
    /// matches the Default impl which is fail-safe Action.
    #[test]
    fn inbound_policy_for_kind_action_matches_default() {
        let policy = InboundPolicy::for_kind(OutletKind::Action);
        assert_eq!(policy.max_calls_per_minute, 60);
        assert_eq!(policy, InboundPolicy::default());
    }

    /// `accept_tool_interface_with_kind(Some(Query))` writes 600 inbound when
    /// the caller omits an inbound policy. This is the symmetric AC3 on the
    /// accept side: `min(outbound, inbound) = 600` when both sides default
    /// to the Query tier.
    #[test]
    fn accept_tool_interface_with_kind_uses_kind_default_for_query() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-target", admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "query-outlet".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        accept_tool_interface_with_kind(
            "ctx-target",
            &mut interface,
            &role_state,
            admin_did,
            None,
            Some(OutletKind::Query),
        )
        .unwrap();

        let inbound = interface.inbound_policy.unwrap();
        assert_eq!(
            inbound.max_calls_per_minute, 600,
            "accept must use Query tier when kind=Query and inbound_policy=None"
        );
    }

    /// `accept_tool_interface_with_kind(Some(Action))` writes 60 inbound,
    /// matching the §5.4.2 fail-safe default.
    #[test]
    fn accept_tool_interface_with_kind_uses_kind_default_for_action() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-target", admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "action-outlet".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        accept_tool_interface_with_kind(
            "ctx-target",
            &mut interface,
            &role_state,
            admin_did,
            None,
            Some(OutletKind::Action),
        )
        .unwrap();

        let inbound = interface.inbound_policy.unwrap();
        assert_eq!(inbound.max_calls_per_minute, 60);
    }

    /// `accept_tool_interface_with_kind(None, None)` falls back to the
    /// §5.4.2 fail-safe Action default — backwards-compatible with the
    /// kind-blind `accept_tool_interface` wrapper.
    #[test]
    fn accept_tool_interface_with_kind_none_falls_back_to_action_default() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-target", admin_did);

        let mut interface = OutletInterface {
            source_context: "ctx-source".to_owned(),
            target_context: "ctx-target".to_owned(),
            outlet_id: "outlet".to_owned(),
            rate_limit: None,
            per_caller_rate_limit: None,
            approved_by_source: true,
            approved_by_target: false,
            outbound_policy: None,
            inbound_policy: None,
        };

        accept_tool_interface_with_kind(
            "ctx-target",
            &mut interface,
            &role_state,
            admin_did,
            None,
            None,
        )
        .unwrap();

        let inbound = interface.inbound_policy.unwrap();
        assert_eq!(
            inbound.max_calls_per_minute, 60,
            "kind=None must fall back to §5.4.2 fail-safe Action default"
        );
    }

    /// Per-kind defaults should round-trip through serde — the tier is part
    /// of the on-wire `outbound_policy.max_calls_per_minute`, so it must
    /// serialize to the explicit integer value (NOT the kind), and
    /// re-parse to the same numeric tier.
    #[test]
    fn outlet_interface_defaults_serialize_into_offer_explicitly() {
        let admin_did = "did:dht:z6MkAdmin";
        let role_state = test_role_state("ctx-source", admin_did);
        let registry = registry_with_kind("query-outlet", OutletKind::Query);

        let interface = expose_tool(
            "ctx-source",
            &"query-outlet".to_owned(),
            &"ctx-target".to_owned(),
            &role_state,
            admin_did,
            &registry,
            None,
            None,
        )
        .unwrap();

        let registration = registry.get("query-outlet").unwrap();
        let offer = create_interface_offer(&interface, registration, 1_000);

        let json = serde_json::to_string(&offer).unwrap();
        // The integer tier must appear verbatim in the JSON encoding.
        assert!(
            json.contains("\"max_calls_per_minute\":600"),
            "offer JSON must serialize Query tier as 600: {json}"
        );

        let decoded: InterfaceOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.outbound_policy.max_calls_per_minute, 600);
        assert_eq!(decoded.outlet_schema.kind, OutletKind::Query);
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-042a: InterfaceEstablished round-5 + round-6 field set
    // -----------------------------------------------------------------------

    /// Builds a fully-populated [`InterfaceEstablished`] event with deterministic
    /// values for round-trip testing per SCP-OUT-042a.
    ///
    /// The `capability_holder_set` is supplied pre-sorted so the helper itself
    /// imposes no implicit ordering; the dedicated ordering test asserts on the
    /// invariant explicitly.
    fn sample_interface_established() -> InterfaceEstablished {
        let mut admin_set: Vec<DID> = vec![
            "did:dht:admin-alpha".into(),
            "did:dht:admin-beta".into(),
            "did:dht:admin-gamma".into(),
        ];
        admin_set.sort();

        let mut capability_holder_set: Vec<DID> = vec![
            "did:dht:caller-mu".into(),
            "did:dht:caller-lambda".into(),
            "did:dht:caller-nu".into(),
        ];
        capability_holder_set.sort();

        InterfaceEstablished {
            interface_id: [0xAB; 32],
            source_context: "ctx-source-A".to_owned(),
            target_context: "ctx-target-B".to_owned(),
            outlet_id: "outlet-x".to_owned(),
            established_at: 1_700_000_000_000,
            epoch_a: 42,
            epoch_b: 17,
            ikm_a: [0x11; 32],
            ikm_a_sig: vec![0x22; 64],
            ikm_b: [0x33; 32],
            ikm_b_sig: vec![0x44; 64],
            creator_did: "did:dht:creator-zeta".into(),
            admin_set,
            capability_holder_set,
        }
    }

    /// AC#1: every round-5 + round-6 field is present with the expected type
    /// (compile-time + value-level binding check).
    #[test]
    fn ac1_interface_established_has_all_round5_round6_fields() {
        let evt = sample_interface_established();

        // Bind every field by name into a type-annotated reference — this is
        // a mechanical check that AC#1's nine fields exist and carry the
        // declared types. A type drift in any field fails compilation.
        let _: &u64 = &evt.epoch_a;
        let _: &u64 = &evt.epoch_b;
        let _: &[u8; 32] = &evt.ikm_a;
        let _: &Ed25519Signature = &evt.ikm_a_sig;
        let _: &[u8; 32] = &evt.ikm_b;
        let _: &Ed25519Signature = &evt.ikm_b_sig;
        let _: &DID = &evt.creator_did;
        let _: &Vec<DID> = &evt.admin_set;
        let _: &Vec<DID> = &evt.capability_holder_set;

        // Sanity-check the original (pre-OUT-042a) fields are still intact —
        // the schema commit must not regress the earlier surface.
        let _: &[u8; 32] = &evt.interface_id;
        let _: &ContextId = &evt.source_context;
        let _: &ContextId = &evt.target_context;
        let _: &OutletId = &evt.outlet_id;
        let _: &u64 = &evt.established_at;
    }

    /// AC#2: `MessagePack` round-trip preserves every field byte-for-byte.
    #[test]
    fn ac2_interface_established_messagepack_roundtrip_byte_identical() {
        let original = sample_interface_established();

        let bytes =
            rmp_serde::to_vec(&original).expect("InterfaceEstablished must MessagePack-serialize");
        let decoded: InterfaceEstablished = rmp_serde::from_slice(&bytes)
            .expect("InterfaceEstablished must MessagePack-deserialize");

        assert_eq!(decoded, original, "decoded value must equal original");

        // Re-serialize the decoded value — bytes must be byte-identical.
        let bytes2 =
            rmp_serde::to_vec(&decoded).expect("re-serializing the decoded value must succeed");
        assert_eq!(
            bytes, bytes2,
            "re-serialized bytes must match the original (byte-for-byte field preservation)"
        );
    }

    /// AC#3: Event-log round-trip — the `InterfaceEstablished` payload appended
    /// to a `scp-event-log` instance (as the body of an `OutletInterfaceAccepted`
    /// event) and re-read via `EventLog::get_event` returns byte-identical
    /// payload bytes.
    #[test]
    fn ac3_interface_established_event_log_roundtrip_byte_identical() {
        use scp_event_log::test_helpers::{did_from_pubkey, sign_event, test_keypair};
        use scp_event_log::tree::GENESIS_PREV_HASH;
        use scp_event_log::{EventLog, EventType, tree};

        let (verifying_key, signing_key) = test_keypair();
        let actor_did = did_from_pubkey(&verifying_key);

        let evt = sample_interface_established();
        let payload_bytes =
            rmp_serde::to_vec(&evt).expect("InterfaceEstablished must MessagePack-serialize");

        let mut log = EventLog::new("ctx-source-A".to_owned());
        let signed = sign_event(
            EventType::OutletInterfaceAccepted,
            &actor_did,
            1_700_000_000,
            0,
            payload_bytes.clone(),
            GENESIS_PREV_HASH,
            &signing_key,
        );
        tree::append(&mut log, &signed).expect("append should succeed");

        let retrieved = log
            .get_event(0)
            .expect("retrieving the appended event must succeed");
        assert_eq!(
            retrieved.payload.data, payload_bytes,
            "payload bytes must round-trip through EventLog::get_event byte-identically"
        );

        let decoded: InterfaceEstablished = rmp_serde::from_slice(&retrieved.payload.data).expect(
            "retrieved payload must MessagePack-deserialize back into InterfaceEstablished",
        );
        assert_eq!(
            decoded, evt,
            "round-tripped InterfaceEstablished must equal the original"
        );
    }

    /// AC#4 (pre-requisite): `creator_did` and `admin_set` are declared on the
    /// struct so OUT-042d can capture them at construction time. This story
    /// only declares the fields and their types; the actual capture wiring
    /// lands in OUT-042d.
    #[test]
    fn ac4_creator_did_and_admin_set_are_declared_on_struct() {
        let evt = sample_interface_established();

        // Field-presence check — assigning into a fresh local with the
        // declared types compiles iff the fields exist with those types.
        let creator_did: DID = evt.creator_did.clone();
        let admin_set: Vec<DID> = evt.admin_set.clone();

        // Round-trip through MessagePack to confirm both fields persist
        // verbatim — the construction-time capture in OUT-042d depends on
        // this storage path being intact.
        let bytes = rmp_serde::to_vec(&evt).unwrap();
        let decoded: InterfaceEstablished = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.creator_did, creator_did);
        assert_eq!(decoded.admin_set, admin_set);
    }

    /// AC#5: `capability_holder_set` is sorted lexicographically by DID string
    /// at construction time so `MessagePack` round-trip yields deterministic
    /// bytes regardless of insertion order.
    #[test]
    fn ac5_capability_holder_set_sorted_yields_deterministic_bytes() {
        let mut sorted: Vec<DID> = vec![
            "did:dht:zeta".into(),
            "did:dht:alpha".into(),
            "did:dht:mu".into(),
        ];
        sorted.sort();

        // Construct two events with the SAME sorted capability_holder_set —
        // round-trip bytes must be identical.
        let mut evt_a = sample_interface_established();
        evt_a.capability_holder_set = sorted.clone();
        let mut evt_b = sample_interface_established();
        evt_b.capability_holder_set = sorted.clone();

        let bytes_a = rmp_serde::to_vec(&evt_a).unwrap();
        let bytes_b = rmp_serde::to_vec(&evt_b).unwrap();
        assert_eq!(
            bytes_a, bytes_b,
            "two events with byte-identical sorted capability_holder_set must serialize byte-identically"
        );

        // Now construct an event whose capability_holder_set is the SAME set
        // but in shuffled insertion order. After sorting, it must round-trip
        // to the same bytes — proving the sort invariant produces a canonical
        // form regardless of how the caller assembled the input.
        let shuffled: Vec<DID> = vec![
            "did:dht:mu".into(),
            "did:dht:zeta".into(),
            "did:dht:alpha".into(),
        ];
        let mut evt_c = sample_interface_established();
        evt_c.capability_holder_set = shuffled;
        evt_c.capability_holder_set.sort();

        let bytes_c = rmp_serde::to_vec(&evt_c).unwrap();
        assert_eq!(
            bytes_a, bytes_c,
            "a shuffled-then-sorted capability_holder_set must yield byte-identical bytes \
             — the lexicographic sort is the canonical ordering"
        );

        // The decoded value retains the sorted order as round-tripped.
        let decoded: InterfaceEstablished = rmp_serde::from_slice(&bytes_a).unwrap();
        let mut expected_sorted = sorted.clone();
        expected_sorted.sort();
        assert_eq!(
            decoded.capability_holder_set, expected_sorted,
            "round-tripped capability_holder_set must equal the lexicographically sorted input"
        );
    }
}
