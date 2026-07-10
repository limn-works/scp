//! Compact `OutletError` code allocation and per-class slug taxonomy in the
//! `SCP-TOOL-6100..6199` sub-block per spec §5.4.4 ("Outlet Error Taxonomy")
//! and ADR-049 §4.
//!
//! # Background
//!
//! Spec §5.4.4 mandates a *compact* code set: one to two codes per
//! [`OutletErrorClass`], roughly fifteen total across the sub-block, with
//! fine-grained distinctions pushed into the `slug` field rather than minted
//! as new codes. The slug regex (shared with [`super::errors::CatalogKey`])
//! is `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` and the slug class
//! prefix MUST match the lowercased [`OutletErrorClass`] variant name. Slugs
//! are dot-separated and may carry multiple segments (e.g.
//! `transport.concurrent-streams-per-invoker`).
//!
//! # Codes allocated by this module
//!
//! Each constant below names a single sub-block code. Slugs that share a code
//! are listed in the constant's rustdoc and registered in the
//! [`slug_to_class`] table below; the *default* slug for a code is returned by
//! [`error_code_to_default_slug`].
//!
//! | Code | Class | Default slug | Slugs covered (§5.4.4 + round-4/5/6) |
//! |------|-------|--------------|--------------------------------------|
//! | [`CODE_PROTOCOL_VIOLATION`] (`SCP-TOOL-6100`) | `Protocol` | `protocol.violation` | `query-cost-violation`, `query-violation`, `kind-mismatch`, `amplification-violation`, `structural-floor-violation`, `schema-immutability-violation`, `query-misdeclaration`, `protocol.catalog-rotation-too-frequent`, `protocol.stream-already-open`, `protocol.violation` |
//! | [`CODE_PROTOCOL_SESSION`] (`SCP-TOOL-6101`) | `Protocol` | `protocol.session-id-conflict` | `protocol.session-id-conflict`, `protocol.malformed-session-id`, `protocol.unknown-session`, `protocol.context-closed-mid-stream`, `protocol.stream-already-closed` |
//! | [`CODE_AUTHORIZATION_DENIED`] (`SCP-TOOL-6110`) | `Authorization` | `authorization.denied` | `authorization.denied` (oracle-collapse target), `authorization.expired`, `authorization.revoked`, `authorization.missing`, `authorization.attenuation-violation`, `authorization.mint-limit-exceeded`, `authorization.time-box-violation`, `authorization.rate-exceeded`, `authorization.cumulative-exceeded`, `authorization.adapter-not-allowed`, `authorization.revoked-mid-stream`, `authorization.credit-stream-mismatch`, `authorization.ikm-signature-invalid`, `authorization.credit-replay` |
//! | [`CODE_AUTHORIZATION_ATTENUATION`] (`SCP-TOOL-6114`) | `Authorization` | `attenuation.mask-width-violation` | `attenuation.caveat-mint-limit-exceeded`, `attenuation.hours-of-day-high-bits-set`, `attenuation.days-of-week-high-bit-set`, `attenuation.origin-kind-stem-mismatch`, `attenuation.origin-kind-mixed-stem-root`, `attenuation.origin-kind-unspecified`, `attenuation.mask-width-violation` |
//! | [`CODE_AUTHORIZATION_SALT_ROTATION`] (`SCP-TOOL-6115`) | `Authorization` | `authorization.salt-rotation-unjustified` | `authorization.salt-rotation-unjustified` |
//! | [`CODE_INPUT_VIOLATION`] (`SCP-TOOL-6120`) | `Input` | `input.schema-violation` | `input.schema-violation`, `input.too-large`, `input.not-serializable`, `input.estimate-exceeds-bound` |
//! | [`CODE_EXECUTION_FAULT`] (`SCP-TOOL-6130`) | `Execution` | `execution.handler-panic` | `execution.handler-panic`, `execution.timeout`, `execution.non-deterministic` |
//! | [`CODE_EXECUTION_CREDIT`] (`SCP-TOOL-6131`) | `Execution` | `execution.credit-exhausted` | `execution.credit-exhausted`, `execution.stream-gap`, `execution.stream-cap-exhausted` |
//! | [`CODE_EXECUTION_CREDIT_STALL`] (`SCP-TOOL-6133`) | `Execution` | `execution.credit-stall` | `execution.credit-stall` |
//! | [`CODE_EXECUTION_CANCEL_ACK_TIMEOUT`] (`SCP-TOOL-6135`) | `Execution` | `execution.cancel-ack-timeout` | `execution.cancel-ack-timeout` |
//! | [`CODE_OUTPUT_VIOLATION`] (`SCP-TOOL-6140`) | `Output` | `output.schema-violation` | `output.schema-violation`, `output.too-large`, `output.not-serializable` |
//! | [`CODE_ECONOMIC_FAULT`] (`SCP-TOOL-6150`) | `Economic` | `economic.insufficient-funds` | `economic.insufficient-funds`, `economic.adapter-failure`, `economic.pricing-formula-error`, `economic.budget-exceeded`, `economic.escrow-overflow`, `protocol.interface-spam-cost` (cross-class slug, Economic class) |
//! | [`CODE_TRANSPORT_FAULT`] (`SCP-TOOL-6160`) | `Transport` | `transport.relay-unavailable` | `transport.relay-unavailable`, `transport.cross-context-bridge-failure`, `transport.rate-limited`, `transport.concurrent-streams-per-invoker`, `transport.concurrent-streams-per-origin-invoker`, `transport.concurrent-streams-per-outlet` |
//! | [`CODE_GOVERNANCE_FAULT`] (`SCP-TOOL-6170`) | `Governance` | `governance.outlet-deregistered` | `governance.outlet-deregistered`, `governance.outlet-suspended`, `governance.ceiling-exceeded`, `governance.consequence-active` |
//!
//! Codes `SCP-TOOL-6111`, `SCP-TOOL-6112`, `SCP-TOOL-6113`, `SCP-TOOL-6116..=6119`,
//! `SCP-TOOL-6121..=6129`, `SCP-TOOL-6132`, `SCP-TOOL-6134`, `SCP-TOOL-6136..=6139`,
//! `SCP-TOOL-6141..=6149`, `SCP-TOOL-6151..=6159`, `SCP-TOOL-6161..=6169`,
//! `SCP-TOOL-6171..=6179`, and `SCP-TOOL-6180..=6199` are **reserved** within
//! the §5.4.4 6100-6199 sub-block. Reserved codes return [`None`] from every
//! lookup function below.
//!
//! # Lookup functions
//!
//! - [`error_code_to_class`] — `&str → Option<OutletErrorClass>`. Covers every
//!   allocated code; reserved codes return [`None`].
//! - [`error_code_to_default_slug`] — `&str → Option<&'static str>`. Returns
//!   the canonical default slug per §5.4.4; reserved codes return [`None`].
//! - [`error_code_to_retry_policy`] — `&str → Option<RetryPolicy>`. Returns
//!   the default retry guidance per §5.4.4; reserved codes return [`None`].
//! - [`slug_to_class`] — `&str → Option<OutletErrorClass>`. Covers every slug
//!   in the §5.4.4 taxonomy (≥ 40 slugs after round-5/6 additions).
//! - [`validate_slug`] — `&str → Result<(), SlugError>`. Enforces the §5.4.4
//!   slug regex without allocating.
//!
//! See [`super::errors`] for the typed envelope (SCP-OUT-024).

use crate::context::outlets::errors::{OutletErrorClass, RetryPolicy, validate_catalog_key};

// ---------------------------------------------------------------------------
// Code constants — §5.4.4 6100-6199 sub-block
// ---------------------------------------------------------------------------
//
// Every constant below is a literal `SCP-TOOL-NNNN` string in the sub-block.
// The `// SCP-CODE-OK:` exemption marker on each line tells
// `scripts/check-error-codes.sh` Phase 1 that the literal is a registry
// constant (always in-range, by inspection), not an emitted error code that
// would need separate range validation.

/// `SCP-TOOL-6100` — Protocol-class registration / validation / classification.
///
/// Default slug `protocol.violation`. Slugs: `query-cost-violation`,
/// `query-violation`, `kind-mismatch`, `amplification-violation`,
/// `structural-floor-violation`, `schema-immutability-violation`,
/// `query-misdeclaration`, `protocol.catalog-rotation-too-frequent`,
/// `protocol.stream-already-open`. See §5.4.4.
pub const CODE_PROTOCOL_VIOLATION: &str = "SCP-TOOL-6100"; // SCP-CODE-OK: §5.4.4 registry constant (Protocol class)

/// `SCP-TOOL-6101` — Protocol-class session-id format and uniqueness.
///
/// Default slug `protocol.session-id-conflict`. Slugs:
/// `protocol.session-id-conflict`, `protocol.malformed-session-id`,
/// `protocol.unknown-session`, `protocol.context-closed-mid-stream`
/// (round-8 context teardown mid-stream), `protocol.stream-already-closed`
/// (control-plane call after terminal). See §6.2.1.1(a) (round-5
/// `UUIDv7`) and §5.4.4.
pub const CODE_PROTOCOL_SESSION: &str = "SCP-TOOL-6101"; // SCP-CODE-OK: §5.4.4 registry constant (Protocol class)

/// `SCP-TOOL-6110` — Authorization-class denial (UCAN, caveat, capability).
///
/// The §5.4.4 query-oracle-collapse target — a caller missing both stems on
/// the target outlet receives this code with slug `authorization.denied`
/// regardless of whether the outlet is registered, deregistered, or has
/// never existed. Default slug `authorization.denied`. See §5.4.4.
pub const CODE_AUTHORIZATION_DENIED: &str = "SCP-TOOL-6110"; // SCP-CODE-OK: §5.4.4 registry constant (Authorization class)

/// `SCP-TOOL-6114` — Authorization-class attenuation sub-class.
///
/// Round-4 split: violations of the attenuation invariants surface here so
/// the operator-side retry/log path can distinguish them from the catch-all
/// `authorization.denied`. Default slug `attenuation.mask-width-violation`.
/// Slugs: `attenuation.caveat-mint-limit-exceeded`,
/// `attenuation.hours-of-day-high-bits-set`,
/// `attenuation.days-of-week-high-bit-set`,
/// `attenuation.origin-kind-stem-mismatch`,
/// `attenuation.origin-kind-mixed-stem-root`,
/// `attenuation.origin-kind-unspecified`,
/// `attenuation.mask-width-violation`. See §5.4.4 + §7.3.8.
pub const CODE_AUTHORIZATION_ATTENUATION: &str = "SCP-TOOL-6114"; // SCP-CODE-OK: §5.4.4 registry constant (Authorization attenuation sub-class)

/// `SCP-TOOL-6115` — Authorization-class round-6 salt-rotation rejection.
///
/// Round-6 `InterfaceSaltRotated` rejection where the rotation cites no
/// qualifying admin-removal event (§6.2.0.1 `SCP-OUTLET-IKM-ROTATE-V1:`
/// preimage). Default slug `authorization.salt-rotation-unjustified`.
/// See §5.4.4 round-6.
pub const CODE_AUTHORIZATION_SALT_ROTATION: &str = "SCP-TOOL-6115"; // SCP-CODE-OK: §5.4.4 registry constant (Authorization salt-rotation)

/// `SCP-TOOL-6120` — Input-class schema / size / type violations.
///
/// Default slug `input.schema-violation`. Slugs: `input.schema-violation`,
/// `input.too-large`, `input.not-serializable`,
/// `input.estimate-exceeds-bound` (round-4 stream open
/// `estimated_chunk_count` cap). See §5.4.4.
pub const CODE_INPUT_VIOLATION: &str = "SCP-TOOL-6120"; // SCP-CODE-OK: §5.4.4 registry constant (Input class)

/// `SCP-TOOL-6130` — Execution-class handler-side fault.
///
/// Covers handler panic, timeout, non-determinism. Default slug
/// `execution.handler-panic`. Slugs: `execution.handler-panic`,
/// `execution.timeout`, `execution.non-deterministic`. See §5.4.4.
pub const CODE_EXECUTION_FAULT: &str = "SCP-TOOL-6130"; // SCP-CODE-OK: §5.4.4 registry constant (Execution class)

/// `SCP-TOOL-6131` — Execution-class credit-stream / resource-exhaustion.
///
/// Distinct from the catch-all execution fault. Default slug
/// `execution.credit-exhausted`. Slugs: `execution.credit-exhausted`,
/// `execution.stream-gap`, `execution.stream-cap-exhausted` (round-8
/// node-level concurrent-pump ceiling). See §5.4.4 + §5.4.5 streaming.
pub const CODE_EXECUTION_CREDIT: &str = "SCP-TOOL-6131"; // SCP-CODE-OK: §5.4.4 registry constant (Execution credit class)

/// `SCP-TOOL-6133` — Execution-class credit-stall (round-4 split).
///
/// Dedicated code per round-4 cancel-ack vs. credit-stall split. Default
/// slug `execution.credit-stall`. See §5.4.4 round-4.
pub const CODE_EXECUTION_CREDIT_STALL: &str = "SCP-TOOL-6133"; // SCP-CODE-OK: §5.4.4 registry constant (Execution credit-stall)

/// `SCP-TOOL-6135` — Execution-class cancel-ack-timeout (round-4).
///
/// Round-4 cancel-ack timer expiration (§5.4.5 cancel-ack timer). Default
/// slug `execution.cancel-ack-timeout`. See §5.4.4 round-4.
pub const CODE_EXECUTION_CANCEL_ACK_TIMEOUT: &str = "SCP-TOOL-6135"; // SCP-CODE-OK: §5.4.4 registry constant (Execution cancel-ack-timeout)

/// `SCP-TOOL-6140` — Output-class schema / size / redaction violations.
///
/// Default slug `output.schema-violation`. Slugs:
/// `output.schema-violation`, `output.too-large`, `output.not-serializable`.
/// See §5.4.4.
pub const CODE_OUTPUT_VIOLATION: &str = "SCP-TOOL-6140"; // SCP-CODE-OK: §5.4.4 registry constant (Output class)

/// `SCP-TOOL-6150` — Economic-class fee / budget / adapter / pricing failure.
///
/// Includes the cross-class `protocol.interface-spam-cost` slug (§6.2.0.1
/// quadratic fee — Economic class even though the slug carries a
/// `protocol.` prefix because the rule is specified at the Protocol layer).
/// Default slug `economic.insufficient-funds`. Slugs:
/// `economic.insufficient-funds`, `economic.adapter-failure`,
/// `economic.pricing-formula-error`, `economic.budget-exceeded`,
/// `economic.escrow-overflow`, `protocol.interface-spam-cost`. See §5.4.4 +
/// §6.2.0.1.
pub const CODE_ECONOMIC_FAULT: &str = "SCP-TOOL-6150"; // SCP-CODE-OK: §5.4.4 registry constant (Economic class)

/// `SCP-TOOL-6160` — Transport-class relay / bridge / concurrency-cap failure.
///
/// Default slug `transport.relay-unavailable`. Slugs:
/// `transport.relay-unavailable`, `transport.cross-context-bridge-failure`,
/// `transport.rate-limited`, `transport.concurrent-streams-per-invoker`,
/// `transport.concurrent-streams-per-origin-invoker`,
/// `transport.concurrent-streams-per-outlet`. See §5.4.4 + §5.4.5.
pub const CODE_TRANSPORT_FAULT: &str = "SCP-TOOL-6160"; // SCP-CODE-OK: §5.4.4 registry constant (Transport class)

/// `SCP-TOOL-6170` — Governance-class deregistration / suspension / ceiling.
///
/// Default slug `governance.outlet-deregistered`. Slugs:
/// `governance.outlet-deregistered`, `governance.outlet-suspended`,
/// `governance.ceiling-exceeded`, `governance.consequence-active`.
/// See §5.4.4.
pub const CODE_GOVERNANCE_FAULT: &str = "SCP-TOOL-6170"; // SCP-CODE-OK: §5.4.4 registry constant (Governance class)

/// All allocated codes in the §5.4.4 6100-6199 sub-block, in canonical order.
///
/// The size of this array is exactly the count of distinct codes the registry
/// allocates (14). The §5.4.4 design constraint is "compact" — `[12, 18]`
/// codes total. The reserved range `6180-6199` plus the gaps within each
/// class range (e.g. `6111`, `6132`, etc.) hold zero allocations.
///
/// Used by [`error_code_to_class`] / [`error_code_to_default_slug`] /
/// [`error_code_to_retry_policy`] to drive the negative branch of every
/// lookup.
pub const ALL_CODES: [&str; 14] = [
    CODE_PROTOCOL_VIOLATION,
    CODE_PROTOCOL_SESSION,
    CODE_AUTHORIZATION_DENIED,
    CODE_AUTHORIZATION_ATTENUATION,
    CODE_AUTHORIZATION_SALT_ROTATION,
    CODE_INPUT_VIOLATION,
    CODE_EXECUTION_FAULT,
    CODE_EXECUTION_CREDIT,
    CODE_EXECUTION_CREDIT_STALL,
    CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
    CODE_OUTPUT_VIOLATION,
    CODE_ECONOMIC_FAULT,
    CODE_TRANSPORT_FAULT,
    CODE_GOVERNANCE_FAULT,
];

// ---------------------------------------------------------------------------
// Slug constants — §5.4.4 catalog (round-3/4/5/6 union)
// ---------------------------------------------------------------------------
//
// Every slug below matches the §5.4.4 regex
// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.

// --- Protocol class -------------------------------------------------------

/// Slug `protocol.violation` — generic Protocol-class default.
pub const SLUG_PROTOCOL_VIOLATION: &str = "protocol.violation";
/// Slug `query-cost-violation` — §5.4.2 Query-cost-floor rule.
pub const SLUG_QUERY_COST_VIOLATION: &str = "query-cost-violation";
/// Slug `query-violation` — §5.4.2 Query semantics violation.
pub const SLUG_QUERY_VIOLATION: &str = "query-violation";
/// Slug `kind-mismatch` — §5.4.2 [`super::OutletKind`] mismatch.
pub const SLUG_KIND_MISMATCH: &str = "kind-mismatch";
/// Slug `amplification-violation` — §5.4.2 query→action amplification.
pub const SLUG_AMPLIFICATION_VIOLATION: &str = "amplification-violation";
/// Slug `structural-floor-violation` — §5.4.2 structural cost floor.
pub const SLUG_STRUCTURAL_FLOOR_VIOLATION: &str = "structural-floor-violation";
/// Slug `schema-immutability-violation` — §5.4.1 schema immutability.
pub const SLUG_SCHEMA_IMMUTABILITY_VIOLATION: &str = "schema-immutability-violation";
/// Slug `query-misdeclaration` — §5.4.2 misdeclared kind at registration.
pub const SLUG_QUERY_MISDECLARATION: &str = "query-misdeclaration";
/// Slug `protocol.catalog-rotation-too-frequent` — round-5 24h dwell.
pub const SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT: &str =
    "protocol.catalog-rotation-too-frequent";
/// Slug `protocol.stream-already-open` — §6.2.1.1(b) dup open.
pub const SLUG_PROTOCOL_STREAM_ALREADY_OPEN: &str = "protocol.stream-already-open";
/// Slug `protocol.session-id-conflict` — §6.2.1.1(a) `UUIDv7` collision.
pub const SLUG_PROTOCOL_SESSION_ID_CONFLICT: &str = "protocol.session-id-conflict";
/// Slug `protocol.malformed-session-id` — §6.2.1.1(a) `UUIDv7` format.
pub const SLUG_PROTOCOL_MALFORMED_SESSION_ID: &str = "protocol.malformed-session-id";
/// Slug `protocol.unknown-session` — §6.2.1.1(a) `OutletStreamOpen.session_id`
/// references an unknown or expired session.
pub const SLUG_PROTOCOL_UNKNOWN_SESSION: &str = "protocol.unknown-session";
/// Slug `protocol.context-closed-mid-stream` — round-8 context teardown.
///
/// Context evict/leave race during an active stream. Shares
/// [`CODE_PROTOCOL_SESSION`] (`SCP-TOOL-6101`) with the other
/// Protocol-session conditions; carries the Protocol class (NOT
/// Authorization) so a context teardown is never recorded as a UCAN
/// revocation. See §5.4.5 "Context teardown vs. revocation (round 8)".
pub const SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM: &str = "protocol.context-closed-mid-stream";
/// Slug `protocol.stream-already-closed` — stream-lifecycle guard.
///
/// Surfaced when a control-plane method (`grant_credit`, `cancel`,
/// `terminate`) is invoked against a stream that has already reached a
/// terminal chunk (`End` / `Error{terminal:true}` / cancel-ack). Shares
/// [`CODE_PROTOCOL_SESSION`] (`SCP-TOOL-6101`) with the other
/// Protocol-session-lifecycle conditions (`protocol.unknown-session`,
/// `protocol.context-closed-mid-stream`) — a post-terminal control-plane
/// call is a session-lifecycle violation, not an authorization failure,
/// so it MUST NOT collapse onto the Authorization band. See §5.4.5
/// "Cancellation and billing boundary" and the SDK lifecycle-guard
/// surface (`StreamAlreadyClosed`).
pub const SLUG_PROTOCOL_STREAM_ALREADY_CLOSED: &str = "protocol.stream-already-closed";

// --- Authorization class --------------------------------------------------

/// Slug `authorization.denied` — query-oracle-collapse target (§5.4.4).
pub const SLUG_AUTHORIZATION_DENIED: &str = "authorization.denied";
/// Slug `authorization.expired` — UCAN `nbf`/`exp` violation.
pub const SLUG_AUTHORIZATION_EXPIRED: &str = "authorization.expired";
/// Slug `authorization.revoked` — UCAN revocation matched.
pub const SLUG_AUTHORIZATION_REVOKED: &str = "authorization.revoked";
/// Slug `authorization.missing` — no UCAN presented.
pub const SLUG_AUTHORIZATION_MISSING: &str = "authorization.missing";
/// Slug `authorization.attenuation-violation` — caveat narrowing failed.
pub const SLUG_AUTHORIZATION_ATTENUATION_VIOLATION: &str = "authorization.attenuation-violation";
/// Slug `authorization.mint-limit-exceeded` — caveat mint-limit violated.
pub const SLUG_AUTHORIZATION_MINT_LIMIT_EXCEEDED: &str = "authorization.mint-limit-exceeded";
/// Slug `authorization.time-box-violation` — time-box caveat violated.
pub const SLUG_AUTHORIZATION_TIME_BOX_VIOLATION: &str = "authorization.time-box-violation";
/// Slug `authorization.rate-exceeded` — rate caveat violated.
pub const SLUG_AUTHORIZATION_RATE_EXCEEDED: &str = "authorization.rate-exceeded";
/// Slug `authorization.cumulative-exceeded` — cumulative caveat violated.
pub const SLUG_AUTHORIZATION_CUMULATIVE_EXCEEDED: &str = "authorization.cumulative-exceeded";
/// Slug `authorization.adapter-not-allowed` — adapter caveat violated.
pub const SLUG_AUTHORIZATION_ADAPTER_NOT_ALLOWED: &str = "authorization.adapter-not-allowed";
/// Slug `authorization.revoked-mid-stream` — round-4 mid-stream re-check.
pub const SLUG_AUTHORIZATION_REVOKED_MID_STREAM: &str = "authorization.revoked-mid-stream";
/// Slug `authorization.credit-stream-mismatch` — round-4 stream-identity bind.
pub const SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH: &str = "authorization.credit-stream-mismatch";
/// Slug `authorization.ikm-signature-invalid` — round-5 IKM signing.
pub const SLUG_AUTHORIZATION_IKM_SIGNATURE_INVALID: &str = "authorization.ikm-signature-invalid";
/// Slug `authorization.credit-replay` — credit-grant replay rejection.
pub const SLUG_AUTHORIZATION_CREDIT_REPLAY: &str = "authorization.credit-replay";
/// Slug `authorization.salt-rotation-unjustified` — round-6 rotation rule.
pub const SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED: &str =
    "authorization.salt-rotation-unjustified";

// --- Authorization attenuation sub-class (6114) ---------------------------

/// Slug `attenuation.caveat-mint-limit-exceeded`.
pub const SLUG_ATTENUATION_CAVEAT_MINT_LIMIT_EXCEEDED: &str =
    "attenuation.caveat-mint-limit-exceeded";
/// Slug `attenuation.hours-of-day-high-bits-set`.
pub const SLUG_ATTENUATION_HOURS_OF_DAY_HIGH_BITS_SET: &str =
    "attenuation.hours-of-day-high-bits-set";
/// Slug `attenuation.days-of-week-high-bit-set`.
pub const SLUG_ATTENUATION_DAYS_OF_WEEK_HIGH_BIT_SET: &str =
    "attenuation.days-of-week-high-bit-set";
/// Slug `attenuation.origin-kind-stem-mismatch` — round-5 §7.3.8.
pub const SLUG_ATTENUATION_ORIGIN_KIND_STEM_MISMATCH: &str =
    "attenuation.origin-kind-stem-mismatch";
/// Slug `attenuation.origin-kind-mixed-stem-root` — round-4 §7.3.8.
pub const SLUG_ATTENUATION_ORIGIN_KIND_MIXED_STEM_ROOT: &str =
    "attenuation.origin-kind-mixed-stem-root";
/// Slug `attenuation.origin-kind-unspecified` — round-4 §7.3.8.
pub const SLUG_ATTENUATION_ORIGIN_KIND_UNSPECIFIED: &str = "attenuation.origin-kind-unspecified";
/// Slug `attenuation.mask-width-violation` — round-5 §7.3.8.
pub const SLUG_ATTENUATION_MASK_WIDTH_VIOLATION: &str = "attenuation.mask-width-violation";

// --- Input class ----------------------------------------------------------

/// Slug `input.schema-violation`.
pub const SLUG_INPUT_SCHEMA_VIOLATION: &str = "input.schema-violation";
/// Slug `input.too-large`.
pub const SLUG_INPUT_TOO_LARGE: &str = "input.too-large";
/// Slug `input.not-serializable`.
pub const SLUG_INPUT_NOT_SERIALIZABLE: &str = "input.not-serializable";
/// Slug `input.estimate-exceeds-bound` — round-4 `estimated_chunk_count` cap.
pub const SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND: &str = "input.estimate-exceeds-bound";

// --- Execution class ------------------------------------------------------

/// Slug `execution.handler-panic`.
pub const SLUG_EXECUTION_HANDLER_PANIC: &str = "execution.handler-panic";
/// Slug `execution.timeout`.
pub const SLUG_EXECUTION_TIMEOUT: &str = "execution.timeout";
/// Slug `execution.non-deterministic`.
pub const SLUG_EXECUTION_NON_DETERMINISTIC: &str = "execution.non-deterministic";
/// Slug `execution.credit-exhausted`.
pub const SLUG_EXECUTION_CREDIT_EXHAUSTED: &str = "execution.credit-exhausted";
/// Slug `execution.credit-stall` — round-4 split.
pub const SLUG_EXECUTION_CREDIT_STALL: &str = "execution.credit-stall";
/// Slug `execution.stream-gap`.
pub const SLUG_EXECUTION_STREAM_GAP: &str = "execution.stream-gap";
/// Slug `execution.stream-cap-exhausted` — round-8 pump ceiling.
///
/// Node-level concurrent-pump ceiling. Shares [`CODE_EXECUTION_CREDIT`]
/// (`SCP-TOOL-6131`) with the other Execution-class resource-exhaustion
/// conditions; emitted at `OutletStreamOpen` acceptance when the
/// per-instance pump ceiling (`max_concurrent_outlet_stream_pumps`) is
/// already saturated. See §5.4.5 "Node-level concurrent-pump ceiling
/// (round 8)".
pub const SLUG_EXECUTION_STREAM_CAP_EXHAUSTED: &str = "execution.stream-cap-exhausted";
/// Slug `execution.cancel-ack-timeout` — round-4 cancel-ack timer.
pub const SLUG_EXECUTION_CANCEL_ACK_TIMEOUT: &str = "execution.cancel-ack-timeout";

// --- Output class ---------------------------------------------------------

/// Slug `output.schema-violation`.
pub const SLUG_OUTPUT_SCHEMA_VIOLATION: &str = "output.schema-violation";
/// Slug `output.too-large`.
pub const SLUG_OUTPUT_TOO_LARGE: &str = "output.too-large";
/// Slug `output.not-serializable`.
pub const SLUG_OUTPUT_NOT_SERIALIZABLE: &str = "output.not-serializable";

// --- Economic class -------------------------------------------------------

/// Slug `economic.insufficient-funds`.
pub const SLUG_ECONOMIC_INSUFFICIENT_FUNDS: &str = "economic.insufficient-funds";
/// Slug `economic.adapter-failure`.
pub const SLUG_ECONOMIC_ADAPTER_FAILURE: &str = "economic.adapter-failure";
/// Slug `economic.pricing-formula-error`.
pub const SLUG_ECONOMIC_PRICING_FORMULA_ERROR: &str = "economic.pricing-formula-error";
/// Slug `economic.budget-exceeded`.
pub const SLUG_ECONOMIC_BUDGET_EXCEEDED: &str = "economic.budget-exceeded";
/// Slug `economic.escrow-overflow` — round-4 `checked_mul` overflow.
pub const SLUG_ECONOMIC_ESCROW_OVERFLOW: &str = "economic.escrow-overflow";
/// Slug `protocol.interface-spam-cost` — Economic class, Protocol-prefixed.
///
/// §6.2.0.1 quadratic fee. The Economic class is intentional: the
/// fee-insufficient rejection is an Economic failure whose rule is
/// specified at the Protocol layer.
pub const SLUG_PROTOCOL_INTERFACE_SPAM_COST: &str = "protocol.interface-spam-cost";

// --- Transport class ------------------------------------------------------

/// Slug `transport.relay-unavailable`.
pub const SLUG_TRANSPORT_RELAY_UNAVAILABLE: &str = "transport.relay-unavailable";
/// Slug `transport.cross-context-bridge-failure`.
pub const SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE: &str =
    "transport.cross-context-bridge-failure";
/// Slug `transport.rate-limited`.
pub const SLUG_TRANSPORT_RATE_LIMITED: &str = "transport.rate-limited";
/// Slug `transport.concurrent-streams-per-invoker` — round-4 §5.4.5.
pub const SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER: &str =
    "transport.concurrent-streams-per-invoker";
/// Slug `transport.concurrent-streams-per-origin-invoker` — round-4 §5.4.5.
pub const SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER: &str =
    "transport.concurrent-streams-per-origin-invoker";
/// Slug `transport.concurrent-streams-per-outlet` — round-4 §5.4.5.
pub const SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET: &str =
    "transport.concurrent-streams-per-outlet";

// --- Governance class -----------------------------------------------------

/// Slug `governance.outlet-deregistered`.
pub const SLUG_GOVERNANCE_OUTLET_DEREGISTERED: &str = "governance.outlet-deregistered";
/// Slug `governance.outlet-suspended`.
pub const SLUG_GOVERNANCE_OUTLET_SUSPENDED: &str = "governance.outlet-suspended";
/// Slug `governance.ceiling-exceeded`.
pub const SLUG_GOVERNANCE_CEILING_EXCEEDED: &str = "governance.ceiling-exceeded";
/// Slug `governance.consequence-active`.
pub const SLUG_GOVERNANCE_CONSEQUENCE_ACTIVE: &str = "governance.consequence-active";

// ---------------------------------------------------------------------------
// SlugError — typed validation failure for `validate_slug`
// ---------------------------------------------------------------------------

/// Reason [`validate_slug`] rejected a candidate slug.
///
/// The §5.4.4 slug regex is `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`,
/// shared with [`super::errors::CatalogKey`]. Both validators delegate to the
/// underlying byte scanner [`super::errors::validate_catalog_key`], so any
/// regex-mismatch reports back as [`SlugError::Malformed`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlugError {
    /// Slug failed the §5.4.4 regex.
    #[error(
        "malformed outlet error slug: \"{slug}\" — must match ^[a-z][a-z0-9-]{{0,63}}(\\.[a-z][a-z0-9-]{{0,63}})*$"
    )]
    Malformed {
        /// The invalid slug.
        slug: String,
    },
}

/// Validates `slug` against the §5.4.4 regex.
///
/// # Regex
///
/// `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$` — lowercase ASCII,
/// dot-separated, segments are 1-64 chars, every segment must start with a
/// letter. Multi-segment slugs like
/// `transport.concurrent-streams-per-invoker` and `attenuation.mask-width-violation`
/// are valid.
///
/// # Errors
///
/// Returns [`SlugError::Malformed`] if the slug fails the regex (uppercase,
/// empty segment, leading hyphen, leading digit, double-dot, …).
pub fn validate_slug(slug: &str) -> Result<(), SlugError> {
    if validate_catalog_key(slug) {
        Ok(())
    } else {
        Err(SlugError::Malformed {
            slug: slug.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Code → class
// ---------------------------------------------------------------------------

/// Returns the [`OutletErrorClass`] for an allocated `SCP-TOOL-NNNN` code.
///
/// Returns [`None`] for any reserved or out-of-sub-block code (e.g.,
/// `SCP-TOOL-6180`, `SCP-TOOL-6111`, `SCP-TOOL-6099`, malformed input).
#[must_use]
pub fn error_code_to_class(code: &str) -> Option<OutletErrorClass> {
    match code {
        CODE_PROTOCOL_VIOLATION | CODE_PROTOCOL_SESSION => Some(OutletErrorClass::Protocol),
        CODE_AUTHORIZATION_DENIED
        | CODE_AUTHORIZATION_ATTENUATION
        | CODE_AUTHORIZATION_SALT_ROTATION => Some(OutletErrorClass::Authorization),
        CODE_INPUT_VIOLATION => Some(OutletErrorClass::Input),
        CODE_EXECUTION_FAULT
        | CODE_EXECUTION_CREDIT
        | CODE_EXECUTION_CREDIT_STALL
        | CODE_EXECUTION_CANCEL_ACK_TIMEOUT => Some(OutletErrorClass::Execution),
        CODE_OUTPUT_VIOLATION => Some(OutletErrorClass::Output),
        CODE_ECONOMIC_FAULT => Some(OutletErrorClass::Economic),
        CODE_TRANSPORT_FAULT => Some(OutletErrorClass::Transport),
        CODE_GOVERNANCE_FAULT => Some(OutletErrorClass::Governance),
        _ => None,
    }
}

/// Returns the canonical default slug for an allocated code.
///
/// Each code's "default" slug is the most representative slug under it per
/// §5.4.4. Returns [`None`] for reserved or out-of-sub-block codes.
#[must_use]
pub fn error_code_to_default_slug(code: &str) -> Option<&'static str> {
    match code {
        CODE_PROTOCOL_VIOLATION => Some(SLUG_PROTOCOL_VIOLATION),
        CODE_PROTOCOL_SESSION => Some(SLUG_PROTOCOL_SESSION_ID_CONFLICT),
        CODE_AUTHORIZATION_DENIED => Some(SLUG_AUTHORIZATION_DENIED),
        CODE_AUTHORIZATION_ATTENUATION => Some(SLUG_ATTENUATION_MASK_WIDTH_VIOLATION),
        CODE_AUTHORIZATION_SALT_ROTATION => Some(SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED),
        CODE_INPUT_VIOLATION => Some(SLUG_INPUT_SCHEMA_VIOLATION),
        CODE_EXECUTION_FAULT => Some(SLUG_EXECUTION_HANDLER_PANIC),
        CODE_EXECUTION_CREDIT => Some(SLUG_EXECUTION_CREDIT_EXHAUSTED),
        CODE_EXECUTION_CREDIT_STALL => Some(SLUG_EXECUTION_CREDIT_STALL),
        CODE_EXECUTION_CANCEL_ACK_TIMEOUT => Some(SLUG_EXECUTION_CANCEL_ACK_TIMEOUT),
        CODE_OUTPUT_VIOLATION => Some(SLUG_OUTPUT_SCHEMA_VIOLATION),
        CODE_ECONOMIC_FAULT => Some(SLUG_ECONOMIC_INSUFFICIENT_FUNDS),
        CODE_TRANSPORT_FAULT => Some(SLUG_TRANSPORT_RELAY_UNAVAILABLE),
        CODE_GOVERNANCE_FAULT => Some(SLUG_GOVERNANCE_OUTLET_DEREGISTERED),
        _ => None,
    }
}

/// Returns the default [`RetryPolicy`] for an allocated code per §5.4.4 retry
/// guidance.
///
/// The default reflects the canonical class semantics:
///
/// - Protocol / Authorization / Input / Output / Governance — `Never`
///   (deterministic rejections; retrying the same payload reproduces the
///   error).
/// - Execution timeouts / panics / non-determinism — `Never` (handler is
///   broken; retry without operator action will not converge).
/// - Execution credit / stream-gap — `Immediate` (idempotent on the
///   credit-grant side; the framework will refresh credits).
/// - Execution credit-stall (round-4 split) — `WithBackoff` 1s..30s
///   (peer is alive but back-pressured).
/// - Execution cancel-ack-timeout — `Never` (cancel was emitted; the
///   stream is gone).
/// - Economic — `Never` (operator-level intervention required).
/// - Transport — `WithBackoff` 1s..30s (network/relay flakiness; retry
///   makes sense).
///
/// Receivers MAY override the default based on contextual signals (e.g., a
/// `transport.rate-limited` envelope carrying a `retry_after_secs` detail).
/// Returns [`None`] for reserved or out-of-sub-block codes.
#[must_use]
pub fn error_code_to_retry_policy(code: &str) -> Option<RetryPolicy> {
    use std::time::Duration;
    match code {
        CODE_PROTOCOL_VIOLATION
        | CODE_PROTOCOL_SESSION
        | CODE_AUTHORIZATION_DENIED
        | CODE_AUTHORIZATION_ATTENUATION
        | CODE_AUTHORIZATION_SALT_ROTATION
        | CODE_INPUT_VIOLATION
        | CODE_EXECUTION_FAULT
        | CODE_EXECUTION_CANCEL_ACK_TIMEOUT
        | CODE_OUTPUT_VIOLATION
        | CODE_ECONOMIC_FAULT
        | CODE_GOVERNANCE_FAULT => Some(RetryPolicy::Never),
        CODE_EXECUTION_CREDIT => Some(RetryPolicy::Immediate),
        CODE_EXECUTION_CREDIT_STALL | CODE_TRANSPORT_FAULT => Some(RetryPolicy::WithBackoff {
            min: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Slug → class
// ---------------------------------------------------------------------------

/// Returns the [`OutletErrorClass`] for any registered §5.4.4 slug.
///
/// The slug→class map covers every slug listed in the module-level rustdoc
/// table (≥ 40 slugs after round-5/6 additions). Unrecognized slugs return
/// [`None`] — including syntactically valid slugs that are not in the
/// taxonomy.
///
/// **Cross-class slug.** `protocol.interface-spam-cost` carries a
/// `protocol.` prefix but maps to [`OutletErrorClass::Economic`] per
/// §6.2.0.1: the rejection is an Economic failure (insufficient quadratic
/// fee), but the *rule* is specified at the Protocol layer. The slug
/// preserves the rule's home for searchability while the class records the
/// class semantics. See SCP-OUT-025 conformance fixture.
#[must_use]
pub fn slug_to_class(slug: &str) -> Option<OutletErrorClass> {
    match slug {
        // Protocol class
        SLUG_PROTOCOL_VIOLATION
        | SLUG_QUERY_COST_VIOLATION
        | SLUG_QUERY_VIOLATION
        | SLUG_KIND_MISMATCH
        | SLUG_AMPLIFICATION_VIOLATION
        | SLUG_STRUCTURAL_FLOOR_VIOLATION
        | SLUG_SCHEMA_IMMUTABILITY_VIOLATION
        | SLUG_QUERY_MISDECLARATION
        | SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT
        | SLUG_PROTOCOL_STREAM_ALREADY_OPEN
        | SLUG_PROTOCOL_SESSION_ID_CONFLICT
        | SLUG_PROTOCOL_MALFORMED_SESSION_ID
        | SLUG_PROTOCOL_UNKNOWN_SESSION
        | SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM
        | SLUG_PROTOCOL_STREAM_ALREADY_CLOSED => Some(OutletErrorClass::Protocol),

        // Authorization class — code 6110 (general denial) AND code 6114
        // (attenuation sub-class) AND code 6115 (salt-rotation) all map to
        // the same root class `OutletErrorClass::Authorization`. The slug
        // *prefix* (`authorization.` vs `attenuation.`) records the
        // sub-class for SDK-level surfacing; the root class is shared.
        SLUG_AUTHORIZATION_DENIED
        | SLUG_AUTHORIZATION_EXPIRED
        | SLUG_AUTHORIZATION_REVOKED
        | SLUG_AUTHORIZATION_MISSING
        | SLUG_AUTHORIZATION_ATTENUATION_VIOLATION
        | SLUG_AUTHORIZATION_MINT_LIMIT_EXCEEDED
        | SLUG_AUTHORIZATION_TIME_BOX_VIOLATION
        | SLUG_AUTHORIZATION_RATE_EXCEEDED
        | SLUG_AUTHORIZATION_CUMULATIVE_EXCEEDED
        | SLUG_AUTHORIZATION_ADAPTER_NOT_ALLOWED
        | SLUG_AUTHORIZATION_REVOKED_MID_STREAM
        | SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH
        | SLUG_AUTHORIZATION_IKM_SIGNATURE_INVALID
        | SLUG_AUTHORIZATION_CREDIT_REPLAY
        | SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED
        | SLUG_ATTENUATION_CAVEAT_MINT_LIMIT_EXCEEDED
        | SLUG_ATTENUATION_HOURS_OF_DAY_HIGH_BITS_SET
        | SLUG_ATTENUATION_DAYS_OF_WEEK_HIGH_BIT_SET
        | SLUG_ATTENUATION_ORIGIN_KIND_STEM_MISMATCH
        | SLUG_ATTENUATION_ORIGIN_KIND_MIXED_STEM_ROOT
        | SLUG_ATTENUATION_ORIGIN_KIND_UNSPECIFIED
        | SLUG_ATTENUATION_MASK_WIDTH_VIOLATION => Some(OutletErrorClass::Authorization),

        // Input class
        SLUG_INPUT_SCHEMA_VIOLATION
        | SLUG_INPUT_TOO_LARGE
        | SLUG_INPUT_NOT_SERIALIZABLE
        | SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND => Some(OutletErrorClass::Input),

        // Execution class
        SLUG_EXECUTION_HANDLER_PANIC
        | SLUG_EXECUTION_TIMEOUT
        | SLUG_EXECUTION_NON_DETERMINISTIC
        | SLUG_EXECUTION_CREDIT_EXHAUSTED
        | SLUG_EXECUTION_CREDIT_STALL
        | SLUG_EXECUTION_STREAM_GAP
        | SLUG_EXECUTION_STREAM_CAP_EXHAUSTED
        | SLUG_EXECUTION_CANCEL_ACK_TIMEOUT => Some(OutletErrorClass::Execution),

        // Output class
        SLUG_OUTPUT_SCHEMA_VIOLATION | SLUG_OUTPUT_TOO_LARGE | SLUG_OUTPUT_NOT_SERIALIZABLE => {
            Some(OutletErrorClass::Output)
        }

        // Economic class (including the Protocol-prefixed cross-class slug)
        SLUG_ECONOMIC_INSUFFICIENT_FUNDS
        | SLUG_ECONOMIC_ADAPTER_FAILURE
        | SLUG_ECONOMIC_PRICING_FORMULA_ERROR
        | SLUG_ECONOMIC_BUDGET_EXCEEDED
        | SLUG_ECONOMIC_ESCROW_OVERFLOW
        | SLUG_PROTOCOL_INTERFACE_SPAM_COST => Some(OutletErrorClass::Economic),

        // Transport class
        SLUG_TRANSPORT_RELAY_UNAVAILABLE
        | SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE
        | SLUG_TRANSPORT_RATE_LIMITED
        | SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER
        | SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER
        | SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET => Some(OutletErrorClass::Transport),

        // Governance class
        SLUG_GOVERNANCE_OUTLET_DEREGISTERED
        | SLUG_GOVERNANCE_OUTLET_SUSPENDED
        | SLUG_GOVERNANCE_CEILING_EXCEEDED
        | SLUG_GOVERNANCE_CONSEQUENCE_ACTIVE => Some(OutletErrorClass::Governance),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Every code in `ALL_CODES` resolves through every lookup function.
    /// Drives AC: "every allocated code has a class, default slug, retry
    /// policy entry."
    #[test]
    fn every_allocated_code_resolves_class_default_slug_retry_policy() {
        for code in ALL_CODES {
            let class = error_code_to_class(code).unwrap_or_else(|| {
                panic!("error_code_to_class({code}) returned None for an allocated code")
            });
            let slug = error_code_to_default_slug(code).unwrap_or_else(|| {
                panic!("error_code_to_default_slug({code}) returned None for an allocated code")
            });
            let policy = error_code_to_retry_policy(code).unwrap_or_else(|| {
                panic!("error_code_to_retry_policy({code}) returned None for an allocated code")
            });
            // The default slug's class must agree with the code's class.
            assert_eq!(
                slug_to_class(slug),
                Some(class),
                "default slug {slug} for code {code} resolved to a different class than the code itself"
            );
            // RetryPolicy serializes; smoke-test that the default returned is
            // structurally well-formed (no zero-duration backoff windows).
            match policy {
                RetryPolicy::Never | RetryPolicy::Immediate => {}
                RetryPolicy::After { delay } => assert!(delay > Duration::ZERO),
                RetryPolicy::WithBackoff { min, max } => {
                    assert!(min > Duration::ZERO);
                    assert!(min <= max);
                }
            }
        }
    }

    /// AC: "an unallocated code (e.g. SCP-TOOL-6180) returns None from all
    /// three lookup functions."
    #[test]
    fn unallocated_codes_return_none_from_all_lookups() {
        // SCP-TOOL-6180 is in the §5.4.4 reserved range 6180-6199.
        let unallocated = "SCP-TOOL-6180"; // SCP-CODE-OK: §5.4.4 reserved-range fixture (6180-6199)
        assert_eq!(error_code_to_class(unallocated), None);
        assert_eq!(error_code_to_default_slug(unallocated), None);
        assert_eq!(error_code_to_retry_policy(unallocated), None);
    }

    /// Reserved range AC: every code in 6180-6199 is unallocated.
    #[test]
    fn reserved_range_6180_6199_has_zero_allocations() {
        for tail in 6180..=6199_u16 {
            // SCP-CODE-OK: §5.4.4 reserved-range fixture (6180-6199)
            let code = format!("SCP-TOOL-{tail}");
            assert_eq!(
                error_code_to_class(&code),
                None,
                "{code} should be reserved per §5.4.4 but resolved to a class"
            );
            assert_eq!(
                error_code_to_default_slug(&code),
                None,
                "{code} should be reserved per §5.4.4 but has a default slug"
            );
            assert_eq!(
                error_code_to_retry_policy(&code),
                None,
                "{code} should be reserved per §5.4.4 but has a retry policy"
            );
        }
    }

    /// Other in-block reserved codes (gaps between allocations) also resolve
    /// to None — pins the registry against accidental drift.
    #[test]
    fn within_block_reserved_codes_return_none() {
        // 6111-6113, 6116-6119, 6132, 6134, 6136-6139, 6141-6149, 6151-6159,
        // 6161-6169, 6171-6179 are all reserved gaps within the sub-block.
        let reserved_in_block = [
            "SCP-TOOL-6111", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6112", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6116", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6132", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6134", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6141", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6151", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6161", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
            "SCP-TOOL-6171", // SCP-CODE-OK: §5.4.4 reserved-gap fixture
        ];
        for code in reserved_in_block {
            assert_eq!(error_code_to_class(code), None);
            assert_eq!(error_code_to_default_slug(code), None);
            assert_eq!(error_code_to_retry_policy(code), None);
        }
    }

    /// Codes outside the §5.4.4 sub-block return None (e.g., 6099, 6200,
    /// other prefixes, malformed). Reinforces the bounded-range invariant.
    #[test]
    fn out_of_block_codes_return_none() {
        let candidates = [
            "SCP-TOOL-6099",  // SCP-CODE-OK: out-of-sub-block fixture (below 6100)
            "SCP-TOOL-6200",  // SCP-CODE-OK: out-of-sub-block fixture (above 6199)
            "SCP-TOOL-7000",  // SCP-CODE-OK: out-of-sub-block fixture (other range)
            "SCP-IDENT-1001", // SCP-CODE-OK: cross-prefix fixture (not Outlet)
            "scp-tool-6110",  // SCP-CODE-OK: lowercase fixture (canonical prefix is uppercase)
            "",
            "SCP-TOOL-",
        ];
        for code in candidates {
            assert_eq!(
                error_code_to_class(code),
                None,
                "out-of-block code {code} unexpectedly resolved"
            );
        }
    }

    /// AC: "code 6110 is returned for `Authorization::Denied` regardless of
    /// whether the caller holds the disambiguating stem (query oracle
    /// collapse per §5.4.4)."
    ///
    /// Models the §5.4.4 oracle collapse: the *code* is identical for both
    /// the `BothStemsMissing` case (no stem held; receiver sees plain
    /// `authorization.denied`) and the `OneStemPresent` case (one stem held;
    /// receiver still sees `authorization.denied` for the
    /// `AmplificationViolation` collapse since they don't hold both stems).
    /// Only when both stems are held does the slug differentiate. The code
    /// stays `SCP-TOOL-6110` across all three.
    #[test]
    fn oracle_collapse_returns_same_code_different_slugs() {
        // Caller holds neither stem: collapse hides distinguishability.
        let (code_neither, slug_neither) = error_for_authorization_denial(StemHolding::Neither);
        // Caller holds only one stem: still collapses (per §5.4.4 round-3
        // rule for AmplificationViolation specifically).
        let (code_one, slug_one) = error_for_authorization_denial(StemHolding::OneOnly);
        // Caller holds both stems: sees the disambiguated slug.
        let (code_both, slug_both) = error_for_authorization_denial(StemHolding::Both);

        assert_eq!(code_neither, CODE_AUTHORIZATION_DENIED);
        assert_eq!(code_one, CODE_AUTHORIZATION_DENIED);
        assert_eq!(code_both, CODE_AUTHORIZATION_DENIED);
        // All three carry SCP-TOOL-6110 — the oracle-collapse property.
        assert_eq!(code_neither, code_one);
        assert_eq!(code_one, code_both);

        // The collapsed cases share the `authorization.denied` slug.
        assert_eq!(slug_neither, SLUG_AUTHORIZATION_DENIED);
        assert_eq!(slug_one, SLUG_AUTHORIZATION_DENIED);
        // The full-visibility case carries the disambiguated slug.
        assert_eq!(slug_both, SLUG_AUTHORIZATION_ATTENUATION_VIOLATION);
        // The two slug values differ to prove the slug DOES vary by
        // visibility, even though the code does not.
        assert_ne!(slug_neither, slug_both);

        // Both slugs map back to the same class.
        assert_eq!(
            slug_to_class(slug_neither),
            Some(OutletErrorClass::Authorization)
        );
        assert_eq!(
            slug_to_class(slug_both),
            Some(OutletErrorClass::Authorization)
        );
    }

    /// Test fixture modelling the §5.4.4 oracle-collapse decision: a mock of
    /// the §5.4.4 emitter logic that maps the caller's stem holding to the
    /// (code, slug) pair the receiver actually sees. The function exists in
    /// the test module only — it is the harness for the `oracle_collapse_*`
    /// AC, not a production helper.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StemHolding {
        /// Caller holds neither `outlet_query:{id}` nor `outlet_call:{id}`.
        Neither,
        /// Caller holds exactly one of the two stems.
        OneOnly,
        /// Caller holds both stems.
        Both,
    }

    /// Models the §5.4.4 "`AmplificationViolation` collapses to
    /// `authorization.denied` unless caller holds BOTH stems" rule. Returns
    /// the (code, slug) pair the receiver sees.
    fn error_for_authorization_denial(holding: StemHolding) -> (&'static str, &'static str) {
        match holding {
            StemHolding::Neither | StemHolding::OneOnly => {
                (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_DENIED)
            }
            StemHolding::Both => (
                CODE_AUTHORIZATION_DENIED,
                SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Slug regex — AC: positive and negative cases including round-4 multi-
    // segment slugs.
    // -----------------------------------------------------------------------

    #[test]
    fn validate_slug_accepts_canonical_forms() {
        let positives = [
            "authorization.denied",
            "authorization", // no dot — single segment is valid per regex
            "authorization.attenuation-violation",
            "transport.concurrent-streams-per-invoker",
            "transport.concurrent-streams-per-origin-invoker",
            "transport.concurrent-streams-per-outlet",
            "execution.cancel-ack-timeout",
            "execution.credit-stall",
            "input.estimate-exceeds-bound",
            "economic.escrow-overflow",
            "protocol.catalog-rotation-too-frequent",
            "protocol.stream-already-open",
            "protocol.session-id-conflict",
            "protocol.malformed-session-id",
            "protocol.interface-spam-cost",
            "authorization.ikm-signature-invalid",
            "authorization.salt-rotation-unjustified",
            "attenuation.origin-kind-mixed-stem-root",
            "attenuation.origin-kind-stem-mismatch",
            "attenuation.origin-kind-unspecified",
            "attenuation.mask-width-violation",
            "execution.stream-cap-exhausted",
            "protocol.context-closed-mid-stream",
        ];
        for slug in positives {
            validate_slug(slug).unwrap_or_else(|e| panic!("expected valid slug {slug}: {e:?}"));
        }
    }

    #[test]
    fn validate_slug_rejects_invalid_forms() {
        let negatives = [
            "Authorization.Denied",   // uppercase — fails
            "authorization..denied",  // double dot — fails
            "",                       // empty
            ".authorization",         // leading dot
            "authorization.",         // trailing dot
            "9authorization.denied",  // segment starts with digit
            "authorization.9bad",     // segment starts with digit
            "authorization.foo_bar",  // underscore not allowed
            "-authorization.denied",  // segment starts with hyphen
            "authorization.denied!",  // bang not allowed
            " authorization.denied",  // leading space
            "authorization.denied\n", // trailing newline
        ];
        for slug in negatives {
            assert!(
                validate_slug(slug).is_err(),
                "expected slug {slug:?} to be rejected"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Round-4 ACs — slug→class lookup for the round-4 additions.
    // -----------------------------------------------------------------------

    #[test]
    fn round_4_slugs_resolve_to_correct_class() {
        let cases: [(&str, OutletErrorClass, &str); 8] = [
            (
                SLUG_EXECUTION_CANCEL_ACK_TIMEOUT,
                OutletErrorClass::Execution,
                CODE_EXECUTION_CANCEL_ACK_TIMEOUT,
            ),
            (
                SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
                OutletErrorClass::Transport,
                CODE_TRANSPORT_FAULT,
            ),
            (
                SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER,
                OutletErrorClass::Transport,
                CODE_TRANSPORT_FAULT,
            ),
            (
                SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET,
                OutletErrorClass::Transport,
                CODE_TRANSPORT_FAULT,
            ),
            (
                SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_DENIED,
            ),
            (
                SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_DENIED,
            ),
            (
                SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
                OutletErrorClass::Input,
                CODE_INPUT_VIOLATION,
            ),
            (
                SLUG_ECONOMIC_ESCROW_OVERFLOW,
                OutletErrorClass::Economic,
                CODE_ECONOMIC_FAULT,
            ),
        ];
        for (slug, expected_class, expected_code) in cases {
            assert_eq!(
                slug_to_class(slug),
                Some(expected_class),
                "round-4 slug {slug} did not map to {expected_class:?}"
            );
            // Cross-check: the expected code resolves to the same class.
            assert_eq!(
                error_code_to_class(expected_code),
                Some(expected_class),
                "round-4 code {expected_code} did not map to {expected_class:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Round-5 ACs — slug→class for round-5 BLOCKER fixes.
    // -----------------------------------------------------------------------

    #[test]
    fn round_5_slugs_resolve_to_correct_class_and_code() {
        // (slug, expected_class, expected_code).
        // The cross-class slug `protocol.interface-spam-cost` is intentional:
        // Protocol-prefixed name, Economic class, Economic code — see §6.2.0.1.
        let cases: [(&str, OutletErrorClass, &str); 10] = [
            (
                SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_VIOLATION,
            ),
            (
                SLUG_PROTOCOL_STREAM_ALREADY_OPEN,
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_VIOLATION,
            ),
            (
                SLUG_PROTOCOL_SESSION_ID_CONFLICT,
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_SESSION,
            ),
            (
                SLUG_PROTOCOL_MALFORMED_SESSION_ID,
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_SESSION,
            ),
            (
                SLUG_PROTOCOL_INTERFACE_SPAM_COST,
                OutletErrorClass::Economic,
                CODE_ECONOMIC_FAULT,
            ),
            (
                SLUG_AUTHORIZATION_IKM_SIGNATURE_INVALID,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_DENIED,
            ),
            (
                SLUG_ATTENUATION_ORIGIN_KIND_MIXED_STEM_ROOT,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_ATTENUATION,
            ),
            (
                SLUG_ATTENUATION_ORIGIN_KIND_UNSPECIFIED,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_ATTENUATION,
            ),
            (
                SLUG_ATTENUATION_ORIGIN_KIND_STEM_MISMATCH,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_ATTENUATION,
            ),
            (
                SLUG_ATTENUATION_MASK_WIDTH_VIOLATION,
                OutletErrorClass::Authorization,
                CODE_AUTHORIZATION_ATTENUATION,
            ),
        ];
        for (slug, expected_class, expected_code) in cases {
            assert_eq!(
                slug_to_class(slug),
                Some(expected_class),
                "round-5 slug {slug} did not map to {expected_class:?}"
            );
            assert_eq!(
                error_code_to_class(expected_code),
                Some(expected_class),
                "round-5 code {expected_code} did not map to {expected_class:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Round-8 ACs — new slugs share existing code bands (no new codes).
    // -----------------------------------------------------------------------

    #[test]
    fn round_8_slugs_resolve_to_correct_class_and_code() {
        // (slug, expected_class, expected_code). Both slugs are
        // sound-by-addition refinements that share an existing code band.
        let cases: [(&str, OutletErrorClass, &str); 2] = [
            (
                SLUG_EXECUTION_STREAM_CAP_EXHAUSTED,
                OutletErrorClass::Execution,
                CODE_EXECUTION_CREDIT,
            ),
            (
                SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_SESSION,
            ),
        ];
        for (slug, expected_class, expected_code) in cases {
            assert_eq!(
                slug_to_class(slug),
                Some(expected_class),
                "round-8 slug {slug} did not map to {expected_class:?}"
            );
            assert_eq!(
                error_code_to_class(expected_code),
                Some(expected_class),
                "round-8 code {expected_code} did not map to {expected_class:?}"
            );
            // Both slugs pass the §5.4.4 regex.
            validate_slug(slug)
                .unwrap_or_else(|e| panic!("round-8 slug {slug} fails regex: {e:?}"));
        }
        // The two new slugs explicitly do NOT collapse onto the
        // Authorization-class `authorization.revoked-mid-stream` band —
        // teardown is Protocol, cap-exhaustion is Execution.
        assert_ne!(
            slug_to_class(SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM),
            slug_to_class(SLUG_AUTHORIZATION_REVOKED_MID_STREAM),
            "context-closed-mid-stream must NOT share the Authorization class with revoked-mid-stream"
        );
    }

    #[test]
    fn stream_already_closed_is_protocol_session_lifecycle() {
        // `protocol.stream-already-closed` is the stream-lifecycle guard
        // raised when a control-plane method runs after the stream reached
        // a terminal chunk. It shares the Protocol-session code band
        // (SCP-TOOL-6101) with `protocol.unknown-session` and
        // `protocol.context-closed-mid-stream` — a post-terminal call is a
        // session-lifecycle violation, NOT an authorization failure, so it
        // must resolve to the Protocol class and pass the §5.4.4 regex.
        assert_eq!(
            slug_to_class(SLUG_PROTOCOL_STREAM_ALREADY_CLOSED),
            Some(OutletErrorClass::Protocol),
            "stream-already-closed must map to the Protocol class"
        );
        assert_eq!(
            error_code_to_class(CODE_PROTOCOL_SESSION),
            Some(OutletErrorClass::Protocol),
            "CODE_PROTOCOL_SESSION must map to the Protocol class"
        );
        validate_slug(SLUG_PROTOCOL_STREAM_ALREADY_CLOSED)
            .unwrap_or_else(|e| panic!("stream-already-closed fails the §5.4.4 regex: {e:?}"));
        // It must NOT collapse onto the Authorization band — a lifecycle
        // guard is not a UCAN/authorization denial.
        assert_ne!(
            slug_to_class(SLUG_PROTOCOL_STREAM_ALREADY_CLOSED),
            slug_to_class(SLUG_AUTHORIZATION_DENIED),
            "stream-already-closed must NOT share the Authorization class"
        );
    }

    // -----------------------------------------------------------------------
    // Slug count — the §5.4.4 round-5 taxonomy registers ≥ 40 slugs.
    // -----------------------------------------------------------------------

    /// Materialize every slug constant the module declares and confirm the
    /// total exceeds the §5.4.4 round-5 floor. The list mirrors the
    /// rustdoc taxonomy table; if a slug is added without a `slug_to_class`
    /// arm it will not appear here, and the assertion below will not fire
    /// — so this list also serves as a structural sanity check that every
    /// declared slug constant has a `slug_to_class` arm.
    #[test]
    fn slug_count_is_at_least_forty() {
        let slugs: &[&str] = &[
            // Protocol (15)
            SLUG_PROTOCOL_VIOLATION,
            SLUG_QUERY_COST_VIOLATION,
            SLUG_QUERY_VIOLATION,
            SLUG_KIND_MISMATCH,
            SLUG_AMPLIFICATION_VIOLATION,
            SLUG_STRUCTURAL_FLOOR_VIOLATION,
            SLUG_SCHEMA_IMMUTABILITY_VIOLATION,
            SLUG_QUERY_MISDECLARATION,
            SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
            SLUG_PROTOCOL_STREAM_ALREADY_OPEN,
            SLUG_PROTOCOL_SESSION_ID_CONFLICT,
            SLUG_PROTOCOL_MALFORMED_SESSION_ID,
            SLUG_PROTOCOL_UNKNOWN_SESSION,
            SLUG_PROTOCOL_CONTEXT_CLOSED_MID_STREAM,
            SLUG_PROTOCOL_STREAM_ALREADY_CLOSED,
            // Authorization (15)
            SLUG_AUTHORIZATION_DENIED,
            SLUG_AUTHORIZATION_EXPIRED,
            SLUG_AUTHORIZATION_REVOKED,
            SLUG_AUTHORIZATION_MISSING,
            SLUG_AUTHORIZATION_ATTENUATION_VIOLATION,
            SLUG_AUTHORIZATION_MINT_LIMIT_EXCEEDED,
            SLUG_AUTHORIZATION_TIME_BOX_VIOLATION,
            SLUG_AUTHORIZATION_RATE_EXCEEDED,
            SLUG_AUTHORIZATION_CUMULATIVE_EXCEEDED,
            SLUG_AUTHORIZATION_ADAPTER_NOT_ALLOWED,
            SLUG_AUTHORIZATION_REVOKED_MID_STREAM,
            SLUG_AUTHORIZATION_CREDIT_STREAM_MISMATCH,
            SLUG_AUTHORIZATION_IKM_SIGNATURE_INVALID,
            SLUG_AUTHORIZATION_CREDIT_REPLAY,
            SLUG_AUTHORIZATION_SALT_ROTATION_UNJUSTIFIED,
            // Authorization attenuation sub-class (7)
            SLUG_ATTENUATION_CAVEAT_MINT_LIMIT_EXCEEDED,
            SLUG_ATTENUATION_HOURS_OF_DAY_HIGH_BITS_SET,
            SLUG_ATTENUATION_DAYS_OF_WEEK_HIGH_BIT_SET,
            SLUG_ATTENUATION_ORIGIN_KIND_STEM_MISMATCH,
            SLUG_ATTENUATION_ORIGIN_KIND_MIXED_STEM_ROOT,
            SLUG_ATTENUATION_ORIGIN_KIND_UNSPECIFIED,
            SLUG_ATTENUATION_MASK_WIDTH_VIOLATION,
            // Input (4)
            SLUG_INPUT_SCHEMA_VIOLATION,
            SLUG_INPUT_TOO_LARGE,
            SLUG_INPUT_NOT_SERIALIZABLE,
            SLUG_INPUT_ESTIMATE_EXCEEDS_BOUND,
            // Execution (7)
            SLUG_EXECUTION_HANDLER_PANIC,
            SLUG_EXECUTION_TIMEOUT,
            SLUG_EXECUTION_NON_DETERMINISTIC,
            SLUG_EXECUTION_CREDIT_EXHAUSTED,
            SLUG_EXECUTION_CREDIT_STALL,
            SLUG_EXECUTION_STREAM_GAP,
            SLUG_EXECUTION_STREAM_CAP_EXHAUSTED,
            SLUG_EXECUTION_CANCEL_ACK_TIMEOUT,
            // Output (3)
            SLUG_OUTPUT_SCHEMA_VIOLATION,
            SLUG_OUTPUT_TOO_LARGE,
            SLUG_OUTPUT_NOT_SERIALIZABLE,
            // Economic + cross-class (6)
            SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
            SLUG_ECONOMIC_ADAPTER_FAILURE,
            SLUG_ECONOMIC_PRICING_FORMULA_ERROR,
            SLUG_ECONOMIC_BUDGET_EXCEEDED,
            SLUG_ECONOMIC_ESCROW_OVERFLOW,
            SLUG_PROTOCOL_INTERFACE_SPAM_COST,
            // Transport (6)
            SLUG_TRANSPORT_RELAY_UNAVAILABLE,
            SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
            SLUG_TRANSPORT_RATE_LIMITED,
            SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_INVOKER,
            SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_ORIGIN_INVOKER,
            SLUG_TRANSPORT_CONCURRENT_STREAMS_PER_OUTLET,
            // Governance (4)
            SLUG_GOVERNANCE_OUTLET_DEREGISTERED,
            SLUG_GOVERNANCE_OUTLET_SUSPENDED,
            SLUG_GOVERNANCE_CEILING_EXCEEDED,
            SLUG_GOVERNANCE_CONSEQUENCE_ACTIVE,
        ];
        assert!(
            slugs.len() >= 40,
            "expected ≥ 40 slugs in §5.4.4 round-5 taxonomy, got {}",
            slugs.len()
        );
        // Every slug must round-trip through `slug_to_class` (else the slug
        // would be silently dropped from the taxonomy).
        for slug in slugs {
            assert!(
                slug_to_class(slug).is_some(),
                "slug {slug} is declared as a constant but missing from slug_to_class()"
            );
            // Every declared slug also passes the regex.
            validate_slug(slug)
                .unwrap_or_else(|e| panic!("declared slug {slug} fails regex: {e:?}"));
        }
    }

    // -----------------------------------------------------------------------
    // Code count — the §5.4.4 compact registry has [12, 18] codes.
    // -----------------------------------------------------------------------

    #[test]
    fn code_count_is_in_compact_range() {
        let n = ALL_CODES.len();
        assert!(
            (12..=18).contains(&n),
            "§5.4.4 mandates a compact registry of [12, 18] codes; ALL_CODES has {n}"
        );
        // No duplicates.
        let mut sorted = ALL_CODES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), n, "ALL_CODES contains duplicate entries");
        // Every entry is in the §5.4.4 6100-6199 sub-block.
        for code in ALL_CODES {
            assert!(
                code.starts_with("SCP-TOOL-61"), // SCP-CODE-OK: prefix self-check (validator self-reference, §5.4.4 6100-6199)
                "code {code} not in §5.4.4 6100-6199 sub-block"
            );
            // Numeric-tail extraction: must parse as 4 digits in [6100, 6199].
            let tail = &code[code.len() - 4..];
            let n: u16 = tail
                .parse()
                .unwrap_or_else(|_| panic!("non-numeric tail in {code}"));
            assert!(
                (6100..=6199).contains(&n),
                "code {code} not in 6100-6199 sub-block"
            );
        }
    }

    // -----------------------------------------------------------------------
    // SlugError Display sanity (no implicit unwrap).
    // -----------------------------------------------------------------------

    #[test]
    fn slug_error_display_includes_the_offending_slug() {
        let err = validate_slug("Bad.Slug").unwrap_err();
        let s = err.to_string();
        assert!(s.contains("Bad.Slug"), "Display must include slug: {s}");
    }

    // -----------------------------------------------------------------------
    // Cross-check: every code's default slug is itself a registered slug.
    // -----------------------------------------------------------------------

    #[test]
    fn every_default_slug_resolves_through_slug_to_class() {
        for code in ALL_CODES {
            let slug = error_code_to_default_slug(code).unwrap();
            assert!(
                slug_to_class(slug).is_some(),
                "default slug {slug} for code {code} has no slug_to_class arm"
            );
            // The default slug also passes the regex.
            validate_slug(slug)
                .unwrap_or_else(|e| panic!("default slug {slug} fails regex: {e:?}"));
        }
    }
}
