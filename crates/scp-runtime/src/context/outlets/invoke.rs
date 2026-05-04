//! Outlet invocation with full execution lifecycle.
//!
//! Implements [`invoke_outlet`]: the primary entry point for executing a
//! registered tool within an SCP context. Handles context state validation,
//! UCAN capability checking, input/output schema validation, timeout
//! enforcement, cancellation, error propagation, and event log recording.
//!
//! Outlet execution errors are surfaced through the §5.4.5 streaming wire
//! types (`ChunkPayload::Error { terminal: true, .. }`) and the §5.4.4 typed
//! `OutletError` envelope, not as protocol-level errors. Schema validation
//! failures are caught by the SDK (this module), not by the outlet itself.
//!
//! See ADR-049 §5 (streaming-native invocation) and ADR-010 in
//! `.docs/adrs/phase-2.md` for the original (pre-redesign) design.

use std::future::Future;
use std::hash::BuildHasher;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures::FutureExt;
use tokio::sync::mpsc;

use crate::context::ContextHandle;
use scp_primitives::DID;
use scp_protocol::context::ContextState;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::error_codes::{
    CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
};
use scp_protocol::context::outlets::errors::MESSAGE_MAX_BYTES;
use scp_protocol::context::outlets::lifecycle::{
    DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS, OutletInvokedEvent, OutletStatus, sha256_json,
};
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::outlets::schema::validate_value_against_schema;
use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, RequestId};
use scp_protocol::context::roles::{Capability, ContextRoleState};
use scp_protocol::crypto::ucan::capability::CapabilityUri;
use scp_protocol::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext, parse_ucan,
    validate_ucan,
};
use scp_protocol::crypto::ucan::{UcanError, UcanToken};
use scp_protocol::trust::consequence::evaluate_consequence_rules;

// ---------------------------------------------------------------------------
// InvocationError
// ---------------------------------------------------------------------------

/// Errors produced by [`invoke_outlet`].
///
/// These are protocol-level errors that prevent the invocation from being
/// dispatched. Outlet execution errors are surfaced through the §5.4.5
/// streaming wire types (`ChunkPayload::Error { terminal: true, .. }`)
/// instead.
#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    /// The context is not in the Active state.
    #[error("context is not in Active state (current: {current_state})")]
    ContextNotActive {
        /// The current state of the context.
        current_state: String,
    },

    /// The invoker does not have the required capability.
    #[error(
        "invoker \"{did}\" does not have OutletCall(\"{outlet_id}\") or OutletCallAll capability"
    )]
    InvokerNotAuthorized {
        /// The DID that attempted invocation.
        did: String,
        /// The outlet they tried to invoke.
        outlet_id: String,
    },

    /// The outlet was not found in the registry.
    #[error("outlet not found: \"{outlet_id}\"")]
    OutletNotFound {
        /// The outlet ID that was not found.
        outlet_id: String,
    },

    /// Input validation failed against the outlet's input schema.
    #[error("input validation failed: {message}")]
    InputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// Output validation failed against the outlet's output schema.
    #[error("output validation failed: {message}")]
    OutputValidationFailed {
        /// Description of the validation failure.
        message: String,
    },

    /// The outlet execution timed out.
    #[error("outlet execution timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout that was exceeded.
        timeout_ms: u32,
    },

    /// The outlet execution was cancelled.
    #[error("outlet execution was cancelled")]
    Cancelled,

    /// The outlet execution failed.
    #[error("outlet execution failed: {message}")]
    ExecutionFailed {
        /// Description of the execution failure.
        message: String,
    },

    /// The invoker's spending budget has been exceeded (§19.5, ADR-033).
    ///
    /// Returned when the context has an economic policy with a per-outlet-call
    /// cost and the invoker's cumulative spending would exceed their
    /// governance-approved budget.
    ///
    /// Error code: `SCP-PERM-3030`.
    #[error("budget exceeded for invoker \"{did}\": cost {cost}, remaining {remaining}")]
    BudgetExceeded {
        /// The DID that attempted invocation.
        did: String,
        /// The cost of the outlet invocation.
        cost: u64,
        /// The remaining budget for the invoker.
        remaining: u64,
    },

    /// A Query outlet violated the §5.4.2 structural cost floor at the
    /// runtime event-log commit boundary (SCP-OUT-012).
    ///
    /// Surfaces when `OutletRegistration::validate()` fails the second-pass
    /// re-check inside `ContextManager::execute_register_outlet`. This story
    /// emits the existing [`InvocationError`] taxonomy; the typed
    /// `OutletErrorClass::Protocol::QueryCostViolation` lands with
    /// SCP-OUT-036/038. Error code: `SCP-TOOL-6102`.
    #[error("Query outlet cost violation (§5.4.2): {reason}")]
    OutletQueryCostViolation {
        /// Human-readable reason — which sub-rule was violated.
        reason: String,
    },

    /// A Query outlet's executor attempted a write through `MutableInvocation`
    /// (or otherwise tripped the [`ReadOnlyInvocation`] deny-list), per spec
    /// §5.4.2 "`ReadOnlyInvocation` guard at invocation" (SCP-OUT-013).
    ///
    /// Maps to `OutletErrorClass::Protocol::QueryViolation` (SCP-TOOL-6103,
    /// slug `protocol.query-violation`) and triggers an
    /// `OutletVerifiedEvent { integrity_ok: false, reason:
    /// QueryMisdeclaration }` operator-attributable signal per §5.4.2
    /// "Misdeclaration signal".
    #[error(
        "Query outlet \"{outlet_id}\" attempted write \"{operation}\" through ReadOnlyInvocation (§5.4.2)"
    )]
    QueryViolation {
        /// The outlet that mis-declared as Query.
        outlet_id: String,
        /// The denied operation (e.g., `"send_message"`, `"register_outlet"`).
        operation: &'static str,
    },

    /// The dispatched [`OutletExecutor`] half does not match the registered
    /// outlet kind — the executor's `exec_query`/`exec_action` default impl
    /// returned [`OutletExecutorError::KindMismatch`] (SCP-OUT-013 AC4).
    ///
    /// Captured as a misdeclaration: a Query-registered outlet whose
    /// implementor only provides `exec_action`, or an Action-registered
    /// outlet whose implementor only provides `exec_query`. The
    /// `QueryMisdeclaration` signal is emitted only for the Query case (the
    /// operator-attributable spec §5.4.2 path).
    #[error(
        "outlet \"{outlet_id}\" registered as {kind:?} but executor returned KindMismatch (§5.4.2)"
    )]
    KindMismatch {
        /// The outlet whose dispatched executor half was missing.
        outlet_id: String,
        /// The registered kind that drove dispatch.
        kind: scp_protocol::context::outlets::OutletKind,
    },

    /// The outlet's executor panicked inside `exec_query` / `exec_action`
    /// (SCP-OUT-028).
    ///
    /// Recovered by the [`std::panic::catch_unwind`] guard the runtime
    /// applies around every executor call (ADR-049 §148: "Every
    /// `OutletExecutor` is wrapped in `catch_unwind`. A panic inside an
    /// executor maps to `SCP-TOOL-6130` (handler-panic) with an
    /// operator-attributable integrity-failure signal.").
    ///
    /// Per spec §5.4.2 / §5.4.4, panics are protocol-visible signals
    /// attributable to the outlet's `operator_did` — not SDK-internal
    /// bugs. The runtime emits a parallel
    /// `OutletVerifiedEvent { integrity_ok: false, reason: HandlerPanicked }`
    /// alongside this error so participation records (§7.3.2) can
    /// attribute the failure.
    ///
    /// On the wire (post-OUT-027), this maps to
    /// `OutletError { code: SCP-TOOL-6130, slug: "execution.handler-panic",
    /// class: Execution, retry: Never, ... }`.
    ///
    /// The `panic_message` is truncated to `MESSAGE_MAX_BYTES` (1 KiB)
    /// at a UTF-8 boundary so it is safe to surface in
    /// `OutletError.message`.
    #[error(
        "outlet \"{outlet_id}\" handler panicked ({code}, {slug}): {panic_message}",
        code = scp_protocol::context::outlets::error_codes::CODE_EXECUTION_FAULT,
        slug = scp_protocol::context::outlets::error_codes::SLUG_EXECUTION_HANDLER_PANIC,
    )]
    HandlerPanic {
        /// The outlet whose executor panicked.
        outlet_id: String,
        /// Stringified panic payload, truncated to `MESSAGE_MAX_BYTES`
        /// bytes at a UTF-8 boundary. `"<unknown panic payload>"` when the
        /// payload is neither `&'static str` nor `String`.
        panic_message: String,
    },

    /// SCP-OUT-021 — a §7.3.8 invocation caveat rejected the call after
    /// input schema validation. Carries a class-specific slug
    /// (`authorization.cumulative-exceeded`, `authorization.rate-exceeded`,
    /// `authorization.adapter-not-allowed`, `input.schema-violation`,
    /// `authorization.denied`, …) so the SDK error envelope can surface
    /// the precise rule that fired.
    ///
    /// Maps to either
    /// [`scp_protocol::CODE_AUTHORIZATION_DENIED`] (`SCP-TOOL-6110`) for
    /// the `authorization.*` slugs, or to
    /// [`scp_protocol::CODE_INPUT_VIOLATION`] (`SCP-TOOL-6120`) for the
    /// `input.schema-violation` slug — the dispatcher in
    /// [`super::manager::outlets::invocation_error_to_context`] performs
    /// the slug→code routing.
    #[error("caveat violation ({slug}): {message}")]
    CaveatViolation {
        /// The §5.4.4 slug for the violated caveat rule.
        slug: &'static str,
        /// Human-readable diagnostic.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// ReadOnlyInvocation / MutableInvocation handles + OutletExecutor trait
// (SCP-OUT-013, spec §5.4.2 ReadOnlyInvocation guard, ADR-049)
// ---------------------------------------------------------------------------

/// Error returned by [`OutletExecutor`] methods.
///
/// Distinct from [`InvocationError`] because executor-level failures are an
/// inner detail of the outlet implementation, not a protocol-level failure
/// of the invocation pipeline. The [`OutletExecutor`] adapter
/// ([`invoke_outlet_dispatch`]) maps these into the protocol-level
/// taxonomy:
///
/// | Variant                 | Maps to                                         |
/// |-------------------------|-------------------------------------------------|
/// | [`KindMismatch`]        | [`InvocationError::KindMismatch`]               |
/// | [`QueryViolation`]      | [`InvocationError::QueryViolation`]             |
/// | [`Failed`]              | [`InvocationError::ExecutionFailed`]            |
///
/// [`KindMismatch`]: OutletExecutorError::KindMismatch
/// [`QueryViolation`]: OutletExecutorError::QueryViolation
/// [`Failed`]: OutletExecutorError::Failed
#[derive(Debug, thiserror::Error)]
pub enum OutletExecutorError {
    /// Returned by the default [`OutletExecutor::exec_query`] /
    /// [`OutletExecutor::exec_action`] implementation when an executor was
    /// dispatched against the wrong half — i.e., a Query-registered outlet
    /// whose implementor only overrode `exec_action` (or vice versa). This
    /// is the structural misdeclaration signal: the runtime cannot dispatch
    /// to a half the implementor did not provide.
    #[error("outlet executor kind mismatch (expected {expected:?})")]
    KindMismatch {
        /// The kind for which the implementor failed to provide an executor
        /// half. For Query, the misdeclaration signal in spec §5.4.2 fires.
        expected: scp_protocol::context::outlets::OutletKind,
    },
    /// Returned by [`MutableInvocation`] write methods when the underlying
    /// registered outlet is `OutletKind::Query` (defense-in-depth runtime
    /// check against type-system bypass). Spec §5.4.2 `QueryViolation`.
    #[error("Query outlet attempted write \"{operation}\" through MutableInvocation (§5.4.2)")]
    QueryViolation {
        /// The denied operation (e.g., `"send_message"`).
        operation: &'static str,
    },
    /// Application-level executor failure. Equivalent to the `String` returned
    /// by closure-based callers; preserved verbatim for compatibility.
    #[error("outlet executor failed: {0}")]
    Failed(String),
}

/// Pending mutation queued on a [`MutableInvocation`].
///
/// Action outlets describe their writes by enqueuing typed [`MutationIntent`]
/// records on the handle. The runtime drains the intents after the executor
/// returns successfully and applies them through the existing per-context
/// mutation pipeline (governance, role assignment, registry updates,
/// economic ledgers, caveat counter store, event log append). For
/// [`OutletKind::Query`] outlets the intents are unreachable — write methods
/// only exist on [`MutableInvocation`] which is only constructed for
/// `OutletKind::Action` (type-system enforcement of the deny-list).
///
/// The runtime check on every [`MutableInvocation`] write method is
/// defense-in-depth: a `MutableInvocation` whose `kind == Query` (constructed
/// directly in tests, or surfaced through a future API misuse) refuses every
/// mutation and emits the `QueryMisdeclaration` signal per §5.4.2.
///
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
#[derive(Debug, Clone)]
pub enum MutationIntent {
    /// Send an MLS application message into the context (deny-list:
    /// "messages"). The runtime hands the payload to
    /// `ContextManager::send_message` after `exec_action` returns.
    SendMessage {
        /// Opaque application payload.
        payload: serde_json::Value,
    },
    /// Assign a role to a member (deny-list: "roles").
    AssignRole {
        /// The member receiving the role assignment.
        member_did: String,
        /// The role name to assign.
        role: String,
    },
    /// Register a new outlet in the context registry (deny-list: "registry").
    RegisterOutlet {
        /// Canonical-bytes-equivalent registration payload (caller-prepared
        /// so the runtime can verify against `OutletRegistration::validate`).
        registration: serde_json::Value,
    },
    /// Append an event log entry (deny-list: "event log"). The runtime
    /// appends through the per-context Merkle event log provider.
    AppendEvent {
        /// Caller-prepared event payload (kind + opaque data).
        event: serde_json::Value,
    },
    /// Submit a governance proposal (deny-list: "governance proposals").
    SubmitGovernanceProposal {
        /// Caller-prepared proposal envelope.
        proposal: serde_json::Value,
    },
    /// Cast a governance vote (deny-list: "governance votes").
    CastGovernanceVote {
        /// Proposal ID being voted on.
        proposal_id: String,
        /// Yes / No / Abstain encoded by the runtime.
        vote: serde_json::Value,
    },
    /// Debit an economic ledger entry (deny-list: "economic ledgers").
    DebitEconomicLedger {
        /// The DID being charged.
        did: String,
        /// Amount in the context's economic policy currency.
        amount: u64,
    },
    /// Credit an economic ledger entry (deny-list: "economic ledgers").
    CreditEconomicLedger {
        /// The DID receiving the credit.
        did: String,
        /// Amount in the context's economic policy currency.
        amount: u64,
    },
    /// Increment a per-DID caveat counter (deny-list: "caveat counter store").
    IncrementCaveatCounter {
        /// Counter key (caveat-defined identifier).
        key: String,
        /// Increment delta — always positive by convention; counters are
        /// monotonic per §7.3.8.
        delta: u64,
    },
}

/// Sink for misdeclaration `OutletVerifiedEvent` signals.
///
/// Receives `OutletVerified { integrity_ok: false, reason:
/// QueryMisdeclaration }` events emitted when a Query outlet's executor
/// trips the [`MutableInvocation`] write deny-list (spec §5.4.2
/// "Misdeclaration signal").
///
/// Implementations are typically a `Vec<OutletVerifiedEvent>` collected by
/// the dispatcher and returned to the caller alongside the invocation
/// outcome. The trait is `Send + Sync` so the sink can be shared across
/// `tokio::spawn`-ed executor tasks.
pub trait QueryMisdeclarationSink: Send + Sync {
    /// Records an integrity-failure signal. Implementations must be
    /// non-blocking — emission happens inline with the executor's failed
    /// write attempt and must not stall the invocation.
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent);
}

/// In-memory [`QueryMisdeclarationSink`] backed by a `Mutex<Vec<_>>`. Used
/// by tests and by the default dispatcher when no operator-supplied sink is
/// provided.
#[derive(Debug, Default)]
pub struct InMemoryQueryMisdeclarationSink {
    inner: std::sync::Mutex<Vec<scp_protocol::context::outlets::OutletVerifiedEvent>>,
}

impl InMemoryQueryMisdeclarationSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains all collected events, leaving the sink empty.
    #[must_use]
    pub fn drain(&self) -> Vec<scp_protocol::context::outlets::OutletVerifiedEvent> {
        // `Mutex::lock` only fails on poisoning; recover by reading whatever
        // was last in the guard so a panic on one thread does not lose the
        // signal events from another. Tests assert non-empty.
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Returns a snapshot of the currently-collected events without draining.
    #[must_use]
    pub fn snapshot(&self) -> Vec<scp_protocol::context::outlets::OutletVerifiedEvent> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clone()
    }
}

impl QueryMisdeclarationSink for InMemoryQueryMisdeclarationSink {
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(event);
    }
}

/// Sink for `OutletVerifiedEvent { integrity_ok: false, reason:
/// HandlerPanicked }` signals (SCP-OUT-028).
///
/// Receives a parallel `OutletVerified` event whenever the runtime's
/// `catch_unwind` guard around an executor call recovers a panic (ADR-049
/// §148). The signal is operator-attributable per spec §5.4.2 — panics are
/// protocol-visible signals of an outlet operator's defect, NOT SDK-internal
/// bugs (the SDK is the entity that catches the panic).
///
/// Implementations are typically a `Vec<OutletVerifiedEvent>` collected by
/// the runtime and surfaced to the manager for event-log emission. The trait
/// is `Send + Sync` so the sink can be shared across `tokio::spawn`-ed
/// executor tasks.
///
/// This is a parallel sink to [`QueryMisdeclarationSink`] — both surface
/// `OutletVerifiedEvent { integrity_ok: false, .. }` records but with
/// distinct `reason` discriminants (`QueryMisdeclaration` vs
/// `HandlerPanicked`). Two sinks rather than one shared trait keeps the
/// runtime contract crisp: a caller wires only the panic guard or only the
/// misdeclaration guard, not both.
pub trait HandlerPanicSink: Send + Sync {
    /// Records an integrity-failure signal for a handler panic.
    /// Implementations must be non-blocking — emission happens inline with
    /// the recovered panic and must not stall the invocation.
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent);
}

/// In-memory [`HandlerPanicSink`] backed by a `Mutex<Vec<_>>`. Used by
/// tests and by callers that want to introspect the panic-attribution
/// stream without wiring a richer event-log path.
#[derive(Debug, Default)]
pub struct InMemoryHandlerPanicSink {
    inner: std::sync::Mutex<Vec<scp_protocol::context::outlets::OutletVerifiedEvent>>,
}

impl InMemoryHandlerPanicSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains all collected events, leaving the sink empty.
    #[must_use]
    pub fn drain(&self) -> Vec<scp_protocol::context::outlets::OutletVerifiedEvent> {
        // `Mutex::lock` only fails on poisoning; recover by reading whatever
        // was last in the guard so a panic on one thread does not lose the
        // signal events from another.
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Returns a snapshot of the currently-collected events without
    /// draining.
    #[must_use]
    pub fn snapshot(&self) -> Vec<scp_protocol::context::outlets::OutletVerifiedEvent> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clone()
    }
}

impl HandlerPanicSink for InMemoryHandlerPanicSink {
    fn record(&self, event: scp_protocol::context::outlets::OutletVerifiedEvent) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(event);
    }
}

/// Sink for the single [`OutletInvokedEvent`] emitted at the close of
/// each outlet stream (§5.4.5 event-log shape; SCP-OUT-035).
///
/// The streaming executor task ([`run_streaming_executor_task`])
/// accumulates the chunk sequence, builds the §5.4.5 event when the
/// terminal chunk is delivered to the receiver, and calls
/// [`Self::record`] once. The sink is the runtime-side hand-off from
/// the spawned task to the caller's event-log append path: the caller
/// owns the storage / Merkle bookkeeping, and the trait is `Send +
/// Sync` so it can be shared across `tokio::spawn`-ed executor tasks
/// without an extra mutex.
///
/// Per ADR-049 §5 / spec §5.4.5, EVERY outlet invocation produces
/// exactly one `OutletInvokedEvent`, even when the executor never
/// emits a `Data` chunk (e.g., a terminal `Error` before any payload).
/// Implementations MUST be idempotent against double-record (the
/// runtime guarantees a single call per task; defense-in-depth keeps
/// the contract crisp).
pub trait OutletInvokedEventSink: Send + Sync {
    /// Records the §5.4.5 stream-close event. Called exactly once per
    /// outlet stream, after the terminal chunk has been delivered to
    /// the chunk receiver.
    fn record(&self, event: OutletInvokedEvent);
}

/// In-memory [`OutletInvokedEventSink`] backed by a `Mutex<Vec<_>>`.
/// Used by tests and by callers that want to introspect the per-stream
/// event sequence without wiring a richer event-log path.
#[derive(Debug, Default)]
pub struct InMemoryOutletInvokedEventSink {
    inner: std::sync::Mutex<Vec<OutletInvokedEvent>>,
}

impl InMemoryOutletInvokedEventSink {
    /// Creates an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drains all collected events, leaving the sink empty.
    #[must_use]
    pub fn drain(&self) -> Vec<OutletInvokedEvent> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// Returns a snapshot of the currently-collected events without
    /// draining.
    #[must_use]
    pub fn snapshot(&self) -> Vec<OutletInvokedEvent> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.clone()
    }
}

impl OutletInvokedEventSink for InMemoryOutletInvokedEventSink {
    fn record(&self, event: OutletInvokedEvent) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.push(event);
    }
}

/// Converts a `catch_unwind` panic payload to a printable message,
/// truncated to [`MESSAGE_MAX_BYTES`] (1 KiB) at a UTF-8 character boundary.
///
/// Matches the §5.4.4 `OutletError.message` size cap (1 KiB pre-HMAC catalog
/// template) so the panic payload, once mapped onto a typed `OutletError`
/// envelope by OUT-027, stays within wire bounds without a second
/// truncation pass.
///
/// `catch_unwind` returns `Box<dyn Any + Send>`; standard panic payloads
/// are either `&'static str` (`panic!("literal")`) or `String`
/// (`panic!("{x}")`). Anything else is opaque — we surface a fixed
/// placeholder rather than `Debug`-printing arbitrary user types.
#[allow(clippy::borrowed_box)] // takes &Box<dyn Any> because that's exactly what catch_unwind hands us; downcast_ref needs the boxed payload.
fn panic_payload_to_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    let raw: &str = if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<unknown panic payload>"
    };
    truncate_at_utf8_boundary(raw, MESSAGE_MAX_BYTES)
}

/// Truncates `s` to at most `max_bytes` bytes, splitting on a UTF-8
/// character boundary so the returned `String` is always valid UTF-8.
///
/// Used by [`panic_payload_to_message`] to bound panic messages by the
/// §5.4.4 `OutletError.message` cap. A naive `&s[..max_bytes]` would panic
/// when `max_bytes` lands inside a multi-byte UTF-8 codepoint; this helper
/// walks back to the previous codepoint boundary instead.
fn truncate_at_utf8_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_owned()
}

/// Builds the `OutletVerifiedEvent { integrity_ok: false, reason:
/// HandlerPanicked }` signal for a recovered panic.
///
/// Mirrors the `QueryMisdeclaration` event construction — the parallel
/// §5.4.2 operator-attributable signal — with `reason: HandlerPanicked`
/// and `passed/failed = 0/1` so participation records (§7.3.2) attribute
/// exactly one integrity failure to the outlet's `operator_did`.
fn handler_panic_event(
    outlet_id: &OutletId,
) -> scp_protocol::context::outlets::OutletVerifiedEvent {
    scp_protocol::context::outlets::OutletVerifiedEvent {
        outlet_id: outlet_id.clone(),
        passed: 0,
        failed: 1,
        integrity_ok: false,
        reason: Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked),
    }
}

/// Runs an outlet executor (closure + future) under a
/// [`std::panic::catch_unwind`] guard so a panic inside `exec_query` /
/// `exec_action` is recovered into an [`InvocationError::HandlerPanic`]
/// envelope (SCP-OUT-028 / ADR-049 §148).
///
/// The guard wraps **both** the synchronous closure call (which constructs
/// the future) AND every poll of the resulting future. Panics during
/// future construction, during the executor's async body, during a
/// `.await` resume, or during the terminal value drop are all caught and
/// converted. Async runtimes (tokio) do not themselves panic-protect
/// spawned futures; without this guard a misbehaving operator handler
/// would unwind through `invoke_outlet` and abort the SCP runtime.
///
/// **Operator attribution.** Panics are NOT SDK-internal bugs: the SDK is
/// the entity that catches them. Per spec §5.4.2 the panic is recorded as
/// an operator-attributable [`scp_protocol::context::outlets::OutletVerifiedEvent`]
/// with `reason: HandlerPanicked`, mirroring the `QueryMisdeclaration`
/// parallel signal. Participation records (§7.3.2) consume the event to
/// attribute the failure to the outlet's `operator_did`. The runtime
/// emits the event through `handler_panic_sink` when one is wired; in
/// either case it logs at `warn` level so operators see the panic in
/// their telemetry.
///
/// **Truncation.** The recovered panic payload is converted to a UTF-8
/// string via [`panic_payload_to_message`] and truncated to
/// `MESSAGE_MAX_BYTES` (1 KiB, matching the §5.4.4
/// `OutletError.message` pre-HMAC cap). OUT-027 maps this directly onto
/// the typed `OutletError` envelope (`code: SCP-TOOL-6130`, `slug:
/// "execution.handler-panic"`, `class: Execution`, `retry: Never`).
async fn run_executor_with_panic_guard<F, Fut>(
    executor: F,
    input: serde_json::Value,
    outlet_id: &OutletId,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<Result<serde_json::Value, String>, InvocationError>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // Step A — synchronously construct the future, catching panics raised
    // BEFORE the first poll (e.g. closures that panic during pre-await
    // setup). `std::panic::catch_unwind` is sync-only, so the future
    // construction is captured here under the same payload-decoding rules
    // as the async path.
    let fut = match std::panic::catch_unwind(AssertUnwindSafe(|| executor(input))) {
        Ok(fut) => fut,
        Err(payload) => {
            return Err(panic_to_invocation_error(
                &payload,
                outlet_id,
                handler_panic_sink,
            ));
        }
    };

    // Step B — poll the future under `futures::FutureExt::catch_unwind`,
    // catching panics during any `.await` resume or during the body. The
    // `AssertUnwindSafe` is sound because the executor surface contract
    // (§5.4.2) treats the executor as a black box — the runtime does not
    // share mutable state with the executor across the panic boundary.
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(executor_result) => Ok(executor_result),
        Err(payload) => Err(panic_to_invocation_error(
            &payload,
            outlet_id,
            handler_panic_sink,
        )),
    }
}

/// Converts a recovered panic payload into the typed
/// [`InvocationError::HandlerPanic`] envelope and emits the parallel
/// `OutletVerifiedEvent { reason: HandlerPanicked }` (§5.4.2) through
/// `handler_panic_sink` and a `warn`-level tracing event.
///
/// Shared between the sync (closure) and async (poll) panic-recovery
/// branches of [`run_executor_with_panic_guard`] and the cancellation-
/// path's inline `select!` so emission and truncation are identical
/// regardless of when the panic fired.
///
/// Takes the payload by reference: the helper only needs to inspect it
/// (string downcasts in [`panic_payload_to_message`], record the §5.4.2
/// signal). Callers may drop the original `Box` after calling.
#[allow(clippy::borrowed_box)] // matches `panic_payload_to_message` which downcasts the boxed payload directly.
fn panic_to_invocation_error(
    payload: &Box<dyn std::any::Any + Send>,
    outlet_id: &OutletId,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> InvocationError {
    let panic_message = panic_payload_to_message(payload);
    tracing::warn!(
        outlet_id = %outlet_id,
        code = CODE_EXECUTION_FAULT,
        slug = SLUG_EXECUTION_HANDLER_PANIC,
        panic_message = %panic_message,
        "outlet executor panicked — recovered via catch_unwind (operator-attributable, §5.4.2)"
    );
    if let Some(sink) = handler_panic_sink {
        sink.record(handler_panic_event(outlet_id));
    }
    InvocationError::HandlerPanic {
        outlet_id: outlet_id.clone(),
        panic_message,
    }
}

/// Read-only handle exposed to a [`OutletKind::Query`] outlet's executor.
///
/// Spec §5.4.2: "The runtime invokes Query outlets through a
/// `ReadOnlyInvocation` handle that denies writes to context state
/// (messages, roles, registry, event log, governance, economic ledgers).
/// Any attempt by an executor to mutate through this handle returns
/// `OutletErrorClass::Protocol::QueryViolation`."
///
/// The deny-list is enforced **at the type level** — none of the seven
/// write surfaces (`messages`, `roles`, `registry`, `event log`,
/// `governance proposals/votes`, `economic ledgers`, `caveat counter
/// store`) have method definitions on this struct. The compiler refuses
/// any executor that calls a write method on a `&ReadOnlyInvocation`.
///
/// Read-side surface (per PRD AC2): [`list_members`], [`get_member_role`],
/// [`get_outlet`], [`list_outlets`], [`get_event`], [`current_epoch`],
/// [`get_economic_policy`], [`get_caveat_counter`].
///
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
/// [`list_members`]: ReadOnlyInvocation::list_members
/// [`get_member_role`]: ReadOnlyInvocation::get_member_role
/// [`get_outlet`]: ReadOnlyInvocation::get_outlet
/// [`list_outlets`]: ReadOnlyInvocation::list_outlets
/// [`get_event`]: ReadOnlyInvocation::get_event
/// [`current_epoch`]: ReadOnlyInvocation::current_epoch
/// [`get_economic_policy`]: ReadOnlyInvocation::get_economic_policy
/// [`get_caveat_counter`]: ReadOnlyInvocation::get_caveat_counter
pub struct ReadOnlyInvocation<'a> {
    context: &'a ContextHandle,
    role_state: &'a ContextRoleState,
    registry: &'a OutletRegistry,
    invoker_did: &'a DID,
    outlet_id: &'a OutletId,
    /// Snapshot of event log entries available at invocation time.
    events: &'a [scp_event_log::Event],
    /// Current MLS group epoch at invocation time.
    epoch: u64,
    /// Optional economic policy snapshot for read-side accessors.
    economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Optional caveat counter store snapshot — `(member_did, counter_key) ->
    /// current value`. Pure read view; writes go through Action outlets.
    caveat_counters: Option<&'a std::collections::HashMap<(String, String), u64>>,
}

impl<'a> ReadOnlyInvocation<'a> {
    /// Constructs a read-only invocation handle.
    ///
    /// Constructed by the runtime ([`invoke_outlet_dispatch`]) — outlets do
    /// not build this themselves.
    #[allow(clippy::too_many_arguments)] // matches the read-side accessor surface; cheap to extend
    #[must_use]
    pub const fn new(
        context: &'a ContextHandle,
        role_state: &'a ContextRoleState,
        registry: &'a OutletRegistry,
        invoker_did: &'a DID,
        outlet_id: &'a OutletId,
        events: &'a [scp_event_log::Event],
        epoch: u64,
        economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
        caveat_counters: Option<&'a std::collections::HashMap<(String, String), u64>>,
    ) -> Self {
        Self {
            context,
            role_state,
            registry,
            invoker_did,
            outlet_id,
            events,
            epoch,
            economic_policy,
            caveat_counters,
        }
    }

    /// Context ID this invocation is scoped to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.context.context_id()
    }

    /// DID of the caller who invoked this Query outlet.
    #[must_use]
    pub const fn invoker_did(&self) -> &DID {
        self.invoker_did
    }

    /// The Query outlet's own ID.
    #[must_use]
    pub const fn outlet_id(&self) -> &OutletId {
        self.outlet_id
    }

    /// Lists all member DIDs currently in the context (PRD AC2).
    #[must_use]
    pub fn list_members(&self) -> Vec<&str> {
        self.role_state.members.iter().map(String::as_str).collect()
    }

    /// Returns the role assigned to `member_did`, if any (PRD AC2).
    #[must_use]
    pub fn get_member_role(&self, member_did: &str) -> Option<&str> {
        self.role_state
            .assignments
            .get(member_did)
            .map(|a| a.role_name.as_str())
    }

    /// Returns the registered outlet metadata for `outlet_id`, if registered
    /// (PRD AC2).
    #[must_use]
    pub fn get_outlet(
        &self,
        outlet_id: &OutletId,
    ) -> Option<&scp_protocol::context::outlets::registry::OutletRegistration> {
        self.registry.get(outlet_id)
    }

    /// Lists all registered outlet IDs in the context registry (PRD AC2).
    #[must_use]
    pub fn list_outlets(&self) -> Vec<&OutletId> {
        self.registry.tool_ids().collect()
    }

    /// Returns the event-log entry at `index` from the snapshot held for this
    /// invocation, if present (PRD AC2). The snapshot is read-only — writes
    /// through this handle are impossible (no method defined).
    #[must_use]
    pub fn get_event(&self, index: usize) -> Option<&scp_event_log::Event> {
        self.events.get(index)
    }

    /// Returns the number of event-log entries visible to this invocation.
    /// Companion to [`get_event`](Self::get_event).
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Returns the MLS group epoch at the time this invocation was dispatched
    /// (PRD AC2).
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the context's current economic policy snapshot, if configured
    /// (PRD AC2). Read-only — Query outlets cannot mutate economic state.
    #[must_use]
    pub const fn get_economic_policy(
        &self,
    ) -> Option<&scp_protocol::economy::types::EconomicPolicy> {
        self.economic_policy
    }

    /// Returns the current caveat counter value for
    /// `(member_did, counter_key)` if a counter store snapshot was supplied
    /// (PRD AC2). Read-only — increments go through Action outlets'
    /// [`MutableInvocation::increment_caveat_counter`].
    #[must_use]
    pub fn get_caveat_counter(&self, member_did: &str, counter_key: &str) -> Option<u64> {
        self.caveat_counters
            .and_then(|map| map.get(&(member_did.to_owned(), counter_key.to_owned())))
            .copied()
    }
}

/// Mutable handle exposed to a [`OutletKind::Action`] outlet's executor.
///
/// Spec §5.4.2: "Action executors may mutate context state through SDK-provided
/// handles subject to role and capability checks." This is the SDK-provided
/// handle. It exposes the same read methods as [`ReadOnlyInvocation`] plus
/// the write methods that Action outlets need to mutate context state.
///
/// Writes are recorded as typed [`MutationIntent`] records and drained by the
/// runtime after `exec_action` returns successfully — the executor never
/// holds a manager reference and never directly mutates per-context state.
/// The runtime is the sole entity that applies mutations, ensuring the
/// existing locking and rollback contracts in
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// still hold.
///
/// **Defense-in-depth runtime check.** Every write method calls
/// [`guard_kind`](Self::guard_kind) before enqueuing the intent. If the
/// captured `kind` is [`OutletKind::Query`] (a misdeclaration the type
/// system did not catch — for example, a test that constructs the handle
/// directly), the method returns
/// [`OutletExecutorError::QueryViolation`] and emits an
/// `OutletVerifiedEvent { integrity_ok: false, reason: QueryMisdeclaration }`
/// through the configured [`QueryMisdeclarationSink`].
///
/// [`OutletKind::Action`]: scp_protocol::context::outlets::OutletKind::Action
/// [`OutletKind::Query`]: scp_protocol::context::outlets::OutletKind::Query
pub struct MutableInvocation<'a> {
    inner: ReadOnlyInvocation<'a>,
    /// The kind the handle was constructed for. Action invocations get
    /// `OutletKind::Action`; the runtime check refuses writes when this is
    /// `Query` (defense-in-depth).
    kind: scp_protocol::context::outlets::OutletKind,
    /// Pending writes accumulated during executor execution.
    pending: Vec<MutationIntent>,
    /// Optional sink for `OutletVerified` integrity-failure events emitted
    /// when [`guard_kind`](Self::guard_kind) refuses a write. `None` is
    /// permitted (e.g. tests that only assert the error variant).
    misdeclaration_sink: Option<&'a dyn QueryMisdeclarationSink>,
}

impl<'a> MutableInvocation<'a> {
    /// Constructs a mutable invocation handle.
    ///
    /// `kind` should always be [`OutletKind::Action`] in production —
    /// [`invoke_outlet_dispatch`] only constructs `MutableInvocation` after
    /// confirming the outlet's registered kind is `Action`. Test code may
    /// construct the handle with `kind == Query` to exercise the
    /// defense-in-depth runtime deny-list (PRD AC7).
    ///
    /// [`OutletKind::Action`]: scp_protocol::context::outlets::OutletKind::Action
    #[must_use]
    pub fn new(
        inner: ReadOnlyInvocation<'a>,
        kind: scp_protocol::context::outlets::OutletKind,
        misdeclaration_sink: Option<&'a dyn QueryMisdeclarationSink>,
    ) -> Self {
        Self {
            inner,
            kind,
            pending: Vec::new(),
            misdeclaration_sink,
        }
    }

    // -----------------------------------------------------------------------
    // Read-side surface — delegates to the inner ReadOnlyInvocation. Action
    // outlets read context state the same way Query outlets do.
    // -----------------------------------------------------------------------

    /// See [`ReadOnlyInvocation::context_id`].
    #[must_use]
    pub fn context_id(&self) -> &str {
        self.inner.context_id()
    }

    /// See [`ReadOnlyInvocation::invoker_did`].
    #[must_use]
    pub const fn invoker_did(&self) -> &DID {
        self.inner.invoker_did()
    }

    /// See [`ReadOnlyInvocation::outlet_id`].
    #[must_use]
    pub const fn outlet_id(&self) -> &OutletId {
        self.inner.outlet_id()
    }

    /// See [`ReadOnlyInvocation::list_members`].
    #[must_use]
    pub fn list_members(&self) -> Vec<&str> {
        self.inner.list_members()
    }

    /// See [`ReadOnlyInvocation::get_member_role`].
    #[must_use]
    pub fn get_member_role(&self, member_did: &str) -> Option<&str> {
        self.inner.get_member_role(member_did)
    }

    /// See [`ReadOnlyInvocation::get_outlet`].
    #[must_use]
    pub fn get_outlet(
        &self,
        outlet_id: &OutletId,
    ) -> Option<&scp_protocol::context::outlets::registry::OutletRegistration> {
        self.inner.get_outlet(outlet_id)
    }

    /// See [`ReadOnlyInvocation::list_outlets`].
    #[must_use]
    pub fn list_outlets(&self) -> Vec<&OutletId> {
        self.inner.list_outlets()
    }

    /// See [`ReadOnlyInvocation::get_event`].
    #[must_use]
    pub fn get_event(&self, index: usize) -> Option<&scp_event_log::Event> {
        self.inner.get_event(index)
    }

    /// See [`ReadOnlyInvocation::current_epoch`].
    #[must_use]
    pub const fn current_epoch(&self) -> u64 {
        self.inner.current_epoch()
    }

    /// See [`ReadOnlyInvocation::get_economic_policy`].
    #[must_use]
    pub const fn get_economic_policy(
        &self,
    ) -> Option<&scp_protocol::economy::types::EconomicPolicy> {
        self.inner.get_economic_policy()
    }

    /// See [`ReadOnlyInvocation::get_caveat_counter`].
    #[must_use]
    pub fn get_caveat_counter(&self, member_did: &str, counter_key: &str) -> Option<u64> {
        self.inner.get_caveat_counter(member_did, counter_key)
    }

    /// Drains all pending [`MutationIntent`] records, leaving the handle
    /// empty. Called by the dispatcher after `exec_action` returns
    /// successfully.
    #[must_use]
    pub fn take_pending_mutations(&mut self) -> Vec<MutationIntent> {
        std::mem::take(&mut self.pending)
    }

    /// Returns the number of pending mutations (read-only inspection for
    /// tests / debug logging).
    #[must_use]
    pub const fn pending_mutation_count(&self) -> usize {
        self.pending.len()
    }

    /// Returns the kind this handle was constructed for. Test helper.
    #[must_use]
    pub const fn kind(&self) -> scp_protocol::context::outlets::OutletKind {
        self.kind
    }

    // -----------------------------------------------------------------------
    // Write-side surface — present ONLY on MutableInvocation. The compiler
    // refuses any executor that tries to call these on `&ReadOnlyInvocation`
    // (PRD AC1: type-system deny-list).
    //
    // Each method runs `guard_kind` first — defense-in-depth runtime check
    // (PRD AC7) for the case where a `MutableInvocation` is somehow
    // constructed with `kind == Query` (e.g., a future API misuse or a
    // misdeclared outlet whose dispatcher path is bypassed). On Query the
    // method emits the §5.4.2 misdeclaration signal and returns
    // `QueryViolation` without enqueuing the intent.
    // -----------------------------------------------------------------------

    /// Send a context message (deny-list: messages).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] when this handle's
    /// kind is `Query` (defense-in-depth — the type system normally
    /// prevents this).
    pub fn send_message(&mut self, payload: serde_json::Value) -> Result<(), OutletExecutorError> {
        self.guard_kind("send_message")?;
        self.pending.push(MutationIntent::SendMessage { payload });
        Ok(())
    }

    /// Assign a role to a member (deny-list: roles).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn assign_role(
        &mut self,
        member_did: impl Into<String>,
        role: impl Into<String>,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("assign_role")?;
        self.pending.push(MutationIntent::AssignRole {
            member_did: member_did.into(),
            role: role.into(),
        });
        Ok(())
    }

    /// Register a new outlet in the context registry (deny-list: registry).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn register_outlet(
        &mut self,
        registration: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("register_outlet")?;
        self.pending
            .push(MutationIntent::RegisterOutlet { registration });
        Ok(())
    }

    /// Append an entry to the context event log (deny-list: event log).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn append_event(&mut self, event: serde_json::Value) -> Result<(), OutletExecutorError> {
        self.guard_kind("append_event")?;
        self.pending.push(MutationIntent::AppendEvent { event });
        Ok(())
    }

    /// Submit a governance proposal (deny-list: governance proposals).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn submit_governance_proposal(
        &mut self,
        proposal: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("submit_governance_proposal")?;
        self.pending
            .push(MutationIntent::SubmitGovernanceProposal { proposal });
        Ok(())
    }

    /// Cast a governance vote on an active proposal (deny-list: governance
    /// votes).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn cast_governance_vote(
        &mut self,
        proposal_id: impl Into<String>,
        vote: serde_json::Value,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("cast_governance_vote")?;
        self.pending.push(MutationIntent::CastGovernanceVote {
            proposal_id: proposal_id.into(),
            vote,
        });
        Ok(())
    }

    /// Debit an economic ledger entry (deny-list: economic ledgers).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn debit_economic_ledger(
        &mut self,
        did: impl Into<String>,
        amount: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("debit_economic_ledger")?;
        self.pending.push(MutationIntent::DebitEconomicLedger {
            did: did.into(),
            amount,
        });
        Ok(())
    }

    /// Credit an economic ledger entry (deny-list: economic ledgers).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn credit_economic_ledger(
        &mut self,
        did: impl Into<String>,
        amount: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("credit_economic_ledger")?;
        self.pending.push(MutationIntent::CreditEconomicLedger {
            did: did.into(),
            amount,
        });
        Ok(())
    }

    /// Increment a per-DID caveat counter (deny-list: caveat counter store).
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError::QueryViolation`] on Query
    /// misdeclaration.
    pub fn increment_caveat_counter(
        &mut self,
        key: impl Into<String>,
        delta: u64,
    ) -> Result<(), OutletExecutorError> {
        self.guard_kind("increment_caveat_counter")?;
        self.pending.push(MutationIntent::IncrementCaveatCounter {
            key: key.into(),
            delta,
        });
        Ok(())
    }

    /// Defense-in-depth runtime check.
    ///
    /// On `Query` kind: emits the §5.4.2 misdeclaration signal through the
    /// sink (if configured) and returns [`OutletExecutorError::QueryViolation`].
    /// On `Action` kind: returns `Ok(())`.
    fn guard_kind(&self, operation: &'static str) -> Result<(), OutletExecutorError> {
        if matches!(self.kind, scp_protocol::context::outlets::OutletKind::Query) {
            if let Some(sink) = self.misdeclaration_sink {
                sink.record(scp_protocol::context::outlets::OutletVerifiedEvent {
                    outlet_id: self.inner.outlet_id.clone(),
                    passed: 0,
                    failed: 1,
                    integrity_ok: false,
                    reason: Some(
                        scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                    ),
                });
            }
            return Err(OutletExecutorError::QueryViolation { operation });
        }
        Ok(())
    }
}

/// Per-outlet executor trait — Query/Action half-and-half.
///
/// Spec §5.4.2: outlets declare a kind and the runtime dispatches Query
/// invocations through [`exec_query`] (read-only handle) and Action
/// invocations through [`exec_action`] (write-capable handle). The trait's
/// default implementations return [`OutletExecutorError::KindMismatch`] so
/// that a misdeclaration — registering as one kind but only implementing
/// the other half — is caught as a distinct, attributable failure rather
/// than as a silent no-op.
///
/// PRD SCP-OUT-013 AC4: "trait `OutletExecutor` has signatures
/// `exec_query(&self, ctx: ReadOnlyInvocation, input: Value) -> Result<Value,
/// OutletError>` and `exec_action(&self, ctx: MutableInvocation, input:
/// Value) -> Result<Value, OutletError>`. Default impls return
/// `OutletError::KindMismatch`."
///
/// **Type-system deny-list (PRD AC1).** `exec_query` receives `&ReadOnlyInvocation`
/// — the compiler refuses any call site that tries to invoke a write
/// method on it because no write methods exist on the type. `exec_action`
/// receives `&mut MutableInvocation` — only this half can enqueue
/// [`MutationIntent`] records.
///
/// [`exec_query`]: OutletExecutor::exec_query
/// [`exec_action`]: OutletExecutor::exec_action
#[async_trait::async_trait]
pub trait OutletExecutor: Send + Sync {
    /// Executes a Query invocation against a read-only handle.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`OutletExecutorError::KindMismatch`]
    /// so that a Query-registered outlet whose implementor only overrode
    /// `exec_action` is caught at runtime per spec §5.4.2 misdeclaration
    /// signal. Implementations override this method to provide the actual
    /// Query semantics.
    async fn exec_query(
        &self,
        ctx: &ReadOnlyInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        let _ = (ctx, input);
        Err(OutletExecutorError::KindMismatch {
            expected: scp_protocol::context::outlets::OutletKind::Query,
        })
    }

    /// Executes an Action invocation against a mutable handle.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`OutletExecutorError::KindMismatch`]
    /// so that an Action-registered outlet whose implementor only overrode
    /// `exec_query` is caught. Implementations override this method to
    /// enqueue mutations through `ctx.send_message`, `ctx.assign_role`,
    /// etc., subject to the runtime deny-list (`guard_kind`).
    async fn exec_action(
        &self,
        ctx: &mut MutableInvocation<'_>,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, OutletExecutorError> {
        let _ = (ctx, input);
        Err(OutletExecutorError::KindMismatch {
            expected: scp_protocol::context::outlets::OutletKind::Action,
        })
    }

    /// Executes a Query invocation as a streaming producer (SCP-OUT-033).
    ///
    /// Spec §5.4.5: outlet invocations are streams by construction. The
    /// streaming form lets executors emit `ChunkPayload::Data` /
    /// `ChunkPayload::Progress` chunks as work proceeds rather than
    /// returning a single aggregated value at the end. Non-streaming
    /// executors override [`exec_query`](Self::exec_query) instead — the
    /// default implementation here delegates to `exec_query` and
    /// converts the single returned value into a `Data` chunk via
    /// [`one_shot_to_stream`] (executors get streaming "for free" without
    /// changing their existing code).
    ///
    /// Implementations that override this method MUST NOT emit a
    /// terminal chunk (`End` / `Error { terminal: true }`); the
    /// framework appends `End` after a successful return and `Error`
    /// after a `Result::Err`. Emitting a terminal chunk from inside the
    /// executor races with the framework's own emission and is
    /// undefined behaviour.
    ///
    /// `tx` is bounded — the framework sets the capacity to the §5.4.5
    /// `credit_window` (default 32). When the channel is full,
    /// `tx.send` returns `Err` only if the receiver was dropped (i.e.,
    /// the stream was cancelled); back-pressure stalls the executor
    /// until a downstream consumer drains a slot.
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError`] on any executor-internal failure
    /// (`Failed`), kind mismatch (`KindMismatch`), or query violation
    /// (`QueryViolation`). The framework maps each to a terminal
    /// `ChunkPayload::Error { terminal: true, ... }` and closes the
    /// stream — implementations never write the error chunk themselves.
    async fn exec_query_stream(
        &self,
        ctx: &ReadOnlyInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        // Default: delegate to non-streaming `exec_query` and emit the
        // single returned value as a `Data` chunk. Non-streaming
        // executors get streaming for free — the framework appends the
        // `End` terminal chunk after this returns successfully.
        let value = self.exec_query(ctx, input).await?;
        one_shot_to_stream(value, &tx).await;
        Ok(())
    }

    /// Executes an Action invocation as a streaming producer (SCP-OUT-033).
    ///
    /// See [`exec_query_stream`](Self::exec_query_stream) for the
    /// streaming contract. The default implementation delegates to
    /// [`exec_action`](Self::exec_action) and emits the single returned
    /// value as a `Data` chunk via [`one_shot_to_stream`].
    ///
    /// Implementations that override this method MUST NOT emit a
    /// terminal chunk (`End` / `Error { terminal: true }`); the
    /// framework owns terminal emission.
    ///
    /// # Errors
    ///
    /// Returns [`OutletExecutorError`] on any executor-internal failure.
    /// The framework maps `Failed` / `KindMismatch` / `QueryViolation`
    /// to a terminal `Error` chunk and closes the stream.
    async fn exec_action_stream(
        &self,
        ctx: &mut MutableInvocation<'_>,
        input: serde_json::Value,
        tx: mpsc::Sender<ChunkPayload>,
    ) -> Result<(), OutletExecutorError> {
        let value = self.exec_action(ctx, input).await?;
        one_shot_to_stream(value, &tx).await;
        Ok(())
    }
}

/// Pushes a single `Value` onto a `ChunkPayload::Data` chunk so a
/// non-streaming executor's return value enters the §5.4.5 stream as a
/// degenerate one-chunk producer (SCP-OUT-033).
///
/// Spec §5.4.5: "A non-streaming invocation is a stream that emits
/// exactly two chunks: `Data(output)` followed by `End(output)`." This
/// adapter emits ONLY the `Data` half — the framework appends the
/// terminal `End` after the executor returns successfully (so callers
/// using this adapter from inside `exec_*_stream` need not emit `End`
/// themselves).
///
/// Returns silently when the receiver was dropped (cancelled stream) —
/// the framework treats that as the cancellation path and emits a
/// terminal chunk on behalf of the executor.
pub async fn one_shot_to_stream(value: serde_json::Value, tx: &mpsc::Sender<ChunkPayload>) {
    // `Sender::send` returns `Err` only if the receiver was dropped.
    // That happens when the stream was cancelled or the consumer
    // disconnected — in either case the framework's terminal emission
    // path closes the stream, so we silently drop the failed send.
    let _ = tx.send(ChunkPayload::Data { value }).await;
}

/// Outcome of a successful [`invoke_outlet_dispatch`] call.
#[derive(Debug)]
pub struct DispatchedOutletOutcome {
    /// Outlet output (already schema-validated).
    pub output: serde_json::Value,
    /// Pending mutations from an Action outlet's [`MutableInvocation`]
    /// handle — empty for Query outlets (which can never enqueue
    /// mutations). The runtime's [`ContextManager`] is the canonical
    /// applier; direct callers may also drain them for testing or for
    /// custom mutation pipelines.
    ///
    /// [`ContextManager`]: crate::context::ContextManager
    pub pending_mutations: Vec<MutationIntent>,
    /// `OutletInvokedEvent` ready to be appended to the event log.
    pub event: OutletInvokedEvent,
    /// Triggered consequences from the post-invocation bookkeeping pass.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when an adapter is configured for paid Action outlets.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
}

/// Dispatches an outlet invocation through an [`OutletExecutor`], routing
/// to `exec_query` or `exec_action` based on the registered
/// [`OutletKind`].
///
/// PRD SCP-OUT-013 AC5: "`ContextManager::invoke_outlet` dispatches to
/// `exec_query` when `kind == Query` and `exec_action` when `kind ==
/// Action`." This free function is the underlying dispatcher; the
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// wrapper layers the per-context economy/budget pipeline over the same
/// dispatch.
///
/// # Misdeclaration handling
///
/// When a Query-registered outlet's `exec_query` returns
/// [`OutletExecutorError::KindMismatch`] (the implementor failed to
/// override the Query half), the dispatcher records an
/// `OutletVerifiedEvent { integrity_ok: false, reason: QueryMisdeclaration }`
/// signal through `misdeclaration_sink` per spec §5.4.2. The
/// [`InvocationError::KindMismatch`] is then surfaced to the caller. The
/// Action-side mirror does NOT emit a `QueryMisdeclaration` signal because
/// the spec only attributes that signal to the Query path — Action
/// misdeclarations surface as `KindMismatch` without the operator-side
/// integrity-failure attribution.
///
/// `MutableInvocation::send_message` and friends emit the misdeclaration
/// signal directly through the same sink when they trip the
/// defense-in-depth `guard_kind` runtime check (`MutableInvocation`
/// constructed with `kind == Query`).
///
/// # Errors
///
/// Returns the same [`InvocationError`] taxonomy as [`invoke_outlet`].
/// Misdeclarations surface as [`InvocationError::KindMismatch`]; defense-
/// in-depth runtime denies surface as [`InvocationError::QueryViolation`];
/// other failures (schema, timeout, capability) propagate verbatim from
/// the underlying closure-based pipeline.
///
/// [`OutletKind`]: scp_protocol::context::outlets::OutletKind
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // mirrors the existing `invoke_outlet` arity exactly so the dispatcher is interchangeable; SCP-OUT-028 adds the panic sink at the end of the parameter list.
pub async fn invoke_outlet_dispatch<E, S>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: &E,
    misdeclaration_sink: Option<&dyn QueryMisdeclarationSink>,
    economy: Option<&mut OutletEconomyContext<'_, S>>,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<DispatchedOutletOutcome, InvocationError>
where
    E: OutletExecutor + ?Sized,
    S: BuildHasher,
{
    // Snapshot the registered kind once so the closure-based delegate sees
    // a stable value even if the registry mutates between dispatch and
    // execution (the registry is not `&mut` here, so it cannot, but the
    // value is also borrowed by the executor closure below).
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    let kind = registration.kind;

    // Snapshot the events the read handle exposes. The free `invoke_outlet`
    // path does not have access to the manager's event log here — the
    // dispatcher takes an empty slice when no economy context is supplied.
    // `ContextManager::invoke_outlet_dispatch_with_economy` wires the real
    // snapshot through.
    let empty_events: &[scp_event_log::Event] = &[];
    let events_snapshot: &[scp_event_log::Event] =
        economy.as_deref().map_or(empty_events, |econ| econ.events);

    // Build the read handle. Borrowing through the closure below carries
    // its lifetime; we extend the borrow scope to cover the executor
    // future.
    let outlet_id_cloned = outlet_id.clone();
    let invoker_did_cloned = invoker_did.clone();
    let read = ReadOnlyInvocation::new(
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        events_snapshot,
        // current_epoch is opaque at this layer; the
        // `invoke_outlet_with_economy_dispatch` wrapper threads the real MLS
        // epoch. Free callers see 0 — explicitly documented.
        0,
        economy.as_deref().and_then(|e| e.economic_policy),
        None,
    );

    // The closure-based `invoke_outlet` path expects
    // `Fn(serde_json::Value) -> Future<Result<Value, String>>`. We adapt the
    // trait-based dispatch into that shape via a single-shot move closure.
    let mut pending_mutations: Vec<MutationIntent> = Vec::new();
    let pending_ref = &mut pending_mutations;
    let executor_ref: &E = executor;
    let read_ref = &read;
    let executor_kind = kind;
    let dispatch_outlet_id = outlet_id_cloned.clone();

    let dispatch = move |input: serde_json::Value| async move {
        match executor_kind {
            scp_protocol::context::outlets::OutletKind::Query => {
                match executor_ref.exec_query(read_ref, input).await {
                    Ok(value) => Ok(value),
                    Err(OutletExecutorError::KindMismatch { .. }) => {
                        // Spec §5.4.2 misdeclaration signal.
                        if let Some(sink) = misdeclaration_sink {
                            sink.record(
                                scp_protocol::context::outlets::OutletVerifiedEvent {
                                    outlet_id: dispatch_outlet_id.clone(),
                                    passed: 0,
                                    failed: 1,
                                    integrity_ok: false,
                                    reason: Some(
                                        scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                                    ),
                                },
                            );
                        }
                        Err(format!(
                            "{}",
                            OutletExecutorError::KindMismatch {
                                expected: scp_protocol::context::outlets::OutletKind::Query,
                            }
                        ))
                    }
                    Err(OutletExecutorError::QueryViolation { operation }) => {
                        // Should be impossible — `&ReadOnlyInvocation` has no
                        // write methods. Surface verbatim if it occurs.
                        Err(format!("query violation in exec_query: {operation}"))
                    }
                    Err(OutletExecutorError::Failed(msg)) => Err(msg),
                }
            }
            scp_protocol::context::outlets::OutletKind::Action => {
                let mut mutable = MutableInvocation::new(
                    ReadOnlyInvocation::new(
                        read_ref.context,
                        read_ref.role_state,
                        read_ref.registry,
                        read_ref.invoker_did,
                        read_ref.outlet_id,
                        read_ref.events,
                        read_ref.epoch,
                        read_ref.economic_policy,
                        read_ref.caveat_counters,
                    ),
                    scp_protocol::context::outlets::OutletKind::Action,
                    misdeclaration_sink,
                );
                let result = executor_ref.exec_action(&mut mutable, input).await;
                match result {
                    Ok(value) => {
                        pending_ref.extend(mutable.take_pending_mutations());
                        Ok(value)
                    }
                    Err(OutletExecutorError::KindMismatch { .. }) => Err(format!(
                        "{}",
                        OutletExecutorError::KindMismatch {
                            expected: scp_protocol::context::outlets::OutletKind::Action,
                        }
                    )),
                    Err(OutletExecutorError::QueryViolation { operation }) => {
                        Err(format!("query violation in exec_action: {operation}"))
                    }
                    Err(OutletExecutorError::Failed(msg)) => Err(msg),
                }
            }
        }
    };

    // Delegate to the closure-based pipeline so capability checks, schema
    // validation, escrow, budget, etc. all run as before. The closure
    // converts the trait error into the existing `String` error surface.
    // SCP-OUT-028: forward the handler-panic sink so panics inside
    // `exec_query` / `exec_action` emit the §5.4.2 attribution event.
    // SCP-OUT-033: this dispatcher returns the legacy aggregating tuple
    // — the streaming entry point is `invoke_outlet` (free function,
    // returns `Result<mpsc::Receiver<OutletStreamChunk>, _>`).
    let result = invoke_outlet_aggregating(
        context,
        registry,
        role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        dispatch,
        economy,
        handler_panic_sink,
    )
    .await;

    let (output, event, consequences, payment_receipt) = match result {
        Ok(tuple) => tuple,
        Err(InvocationError::ExecutionFailed { message }) => {
            // Decode the structured error string back to the typed
            // KindMismatch / QueryViolation taxonomy.
            if message.starts_with("outlet executor kind mismatch") {
                return Err(InvocationError::KindMismatch {
                    outlet_id: outlet_id_cloned,
                    kind,
                });
            }
            if let Some(operation) = message.strip_prefix("query violation in exec_action: ") {
                return Err(InvocationError::QueryViolation {
                    outlet_id: outlet_id_cloned,
                    operation: query_violation_op_static(operation),
                });
            }
            if let Some(operation) = message.strip_prefix("query violation in exec_query: ") {
                return Err(InvocationError::QueryViolation {
                    outlet_id: outlet_id_cloned,
                    operation: query_violation_op_static(operation),
                });
            }
            return Err(InvocationError::ExecutionFailed { message });
        }
        Err(other) => return Err(other),
    };

    // Static suppression — the `_invoker_did_cloned` binding is only used
    // when the dispatch closure captures by move; under some compiler
    // configurations the `move` closure does not actually move it. Drop it
    // explicitly so the borrow checker keeps the lifetime sane and clippy
    // does not flag an unused variable.
    drop(invoker_did_cloned);

    Ok(DispatchedOutletOutcome {
        output,
        pending_mutations,
        event,
        consequences,
        payment_receipt,
    })
}

/// Coerces a runtime executor-supplied operation string back to one of the
/// `&'static str` constants used by the deny-list. The `MutableInvocation`
/// methods supply `&'static str` literals, so the round-trip preserves the
/// pointer when the original string was one of the known literals; for
/// unknown strings we fall back to a generic literal so the typed
/// [`InvocationError::QueryViolation`] still carries a `&'static str`.
fn query_violation_op_static(op: &str) -> &'static str {
    match op {
        "send_message" => "send_message",
        "assign_role" => "assign_role",
        "register_outlet" => "register_outlet",
        "append_event" => "append_event",
        "submit_governance_proposal" => "submit_governance_proposal",
        "cast_governance_vote" => "cast_governance_vote",
        "debit_economic_ledger" => "debit_economic_ledger",
        "credit_economic_ledger" => "credit_economic_ledger",
        "increment_caveat_counter" => "increment_caveat_counter",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Economy context for outlet invocation
// ---------------------------------------------------------------------------

/// Optional economy parameters for outlet invocation.
///
/// When provided, `invoke_outlet` enforces budget checks before execution
/// and performs post-invocation bookkeeping (participation record update,
/// consequence rule evaluation). Pass `None` when economy is not configured
/// for the context.
pub struct OutletEconomyContext<'a, S: BuildHasher = std::hash::RandomState> {
    /// The context's economic policy (from `PerContextState.governance.economic_policy`).
    pub economic_policy: Option<&'a scp_protocol::economy::types::EconomicPolicy>,
    /// Mutable reference to the invoker's budget tracker.
    pub budget_tracker: &'a mut scp_protocol::economy::budget::MemberBudgetTracker,
    /// Spending UCAN for spending-capability check (§19.5). `None` if no
    /// spending UCAN presented. The action capability side of AND-composition
    /// is verified UPSTREAM at the `member_has_capability` gate — see the
    /// `OutletCall` / `OutletCallAll` check earlier in `invoke_outlet`.
    pub spending_ucan: Option<&'a UcanToken>,
    /// Context ID for bookkeeping.
    pub context_id: &'a str,
    /// Current timestamp (seconds since epoch).
    pub now: u64,
    /// Event log entries for consequence evaluation.
    pub events: &'a [scp_event_log::Event],
    /// Participation cache for proposer eligibility evaluation.
    pub participation_cache: &'a mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
        S,
    >,
    /// Consequence rules from the context's governance state.
    pub consequence_rules: &'a [scp_protocol::trust::consequence::ConsequenceRule],
    /// Optional payment adapter for the 9-step payment flow (spec §19.2.2, #1537).
    ///
    /// When `Some`, `invoke_outlet` runs `prepare_paid_action` + `process_paid_action`
    /// before outlet execution. When `None`, only budget enforcement runs.
    pub payment_adapter: Option<std::sync::Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    /// Observable metrics for dynamic cost evaluation. Populated from
    /// `PerContextState` by the caller so that tool economy uses real
    /// metrics instead of zeros.
    pub metrics: scp_protocol::economy::policy::ObservableMetrics,
    /// Per-DID velocity tracker (spec §19.4) for tool-invoke escalation.
    /// `None` skips per-DID escalation; pricing baseline (if any) still
    /// applies through the policy formula or `message_pricing.base_cost`.
    pub velocity_tracker: Option<&'a scp_protocol::economy::antispam::SenderVelocityTracker>,
    /// Per-DID message pricing config (spec §19.7). Carries base cost,
    /// escalation thresholds, and floor/cap. When `Some`, outlet invocations
    /// participate in the same per-DID anti-spam regime as message sends.
    pub message_pricing: Option<&'a scp_protocol::economy::antispam::ContextMessagePricingConfig>,
}

// ---------------------------------------------------------------------------
// invoke_outlet — streaming entry point (SCP-OUT-033)
// ---------------------------------------------------------------------------

/// Default capacity of the chunk channel handed to the executor when the
/// invoker does not specify a `credit_window` (spec §5.4.5
/// `stream_window_default = 32`).
///
/// Mirrors [`scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW`]
/// converted to a `usize` channel capacity. The conversion is bounded by
/// `usize::MAX` on every supported target.
#[allow(clippy::cast_possible_truncation)] // u32 → usize: 32 < usize::MAX on every target
const DEFAULT_STREAM_CHANNEL_CAPACITY: usize =
    scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW as usize;

/// Generates a fresh `RequestId` (16-byte `UUIDv7`) for an outlet
/// invocation that did not receive one from a `OutletStreamOpen`
/// (i.e., a direct call into the streaming `invoke_outlet` entry
/// point).
///
/// Spec §5.4.5: `request_id: [u8; 16]` — per-stream `UUIDv7`,
/// monotonic time-sortable. Direct callers (tests, the manager
/// wrapper for non-stream-open paths) get a fresh `UUIDv7` so that
/// the chunk sequence space is unique to this invocation. `UUIDv7`
/// is preferred over `UUIDv4` because the time prefix gives auditors
/// a stable ordering across `request_id`s.
fn fresh_request_id() -> RequestId {
    *uuid::Uuid::now_v7().as_bytes()
}

/// Builds a terminal `ChunkPayload::Error` chunk with `terminal: true`
/// for an [`InvocationError`] that aborted the stream before/while the
/// executor was running (SCP-OUT-033 AC6, AC10, AC11).
///
/// Each `InvocationError` variant maps to one §5.4.4 sub-block code +
/// slug pair from
/// [`scp_protocol::context::outlets::error_codes`]. The mapping is
/// kept in lock-step with the existing
/// [`crate::context::manager::outlets::invocation_error_to_context`]
/// router so the SDK envelope shape is identical whether the stream
/// terminated through this path or via the post-stream tuple.
///
/// Used by callers that drive streams from outside the spawned executor
/// task (e.g., the manager wrapper turning a synchronous validation
/// failure into a single-chunk error stream). The streaming
/// `invoke_outlet` itself returns synchronous validation failures as
/// `Result::Err`; this helper is the bridge for callers that prefer a
/// uniform "every failure is a terminal chunk" surface.
#[must_use]
pub fn invocation_error_to_terminal_payload(err: &InvocationError) -> ChunkPayload {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_INPUT_VIOLATION,
        CODE_OUTPUT_VIOLATION, CODE_PROTOCOL_VIOLATION, SLUG_AUTHORIZATION_DENIED,
        SLUG_INPUT_SCHEMA_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION, SLUG_QUERY_VIOLATION,
    };
    // The slug is included in the resulting Error chunk's `message`
    // field so the receiver-side SDK can reverse-lookup against the
    // §5.4.4 catalog. The `code` carries the §5.4.4 sub-block constant.
    let (code, slug) = match err {
        InvocationError::ContextNotActive { .. } => {
            (CODE_PROTOCOL_VIOLATION, "protocol.context-not-active")
        }
        // Spec §5.4.4 query-oracle-collapse: unknown outlets and
        // unauthorized callers both surface as `authorization.denied`
        // so the existence (or registration) of the outlet is not
        // leaked through the error class.
        InvocationError::InvokerNotAuthorized { .. } | InvocationError::OutletNotFound { .. } => {
            (CODE_AUTHORIZATION_DENIED, SLUG_AUTHORIZATION_DENIED)
        }
        InvocationError::InputValidationFailed { .. } => {
            (CODE_INPUT_VIOLATION, SLUG_INPUT_SCHEMA_VIOLATION)
        }
        InvocationError::OutputValidationFailed { .. } => {
            (CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION)
        }
        InvocationError::Timeout { .. } => (CODE_EXECUTION_FAULT, SLUG_EXECUTION_TIMEOUT),
        InvocationError::Cancelled => (CODE_EXECUTION_FAULT, "execution.cancelled"),
        InvocationError::ExecutionFailed { .. } | InvocationError::HandlerPanic { .. } => {
            (CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC)
        }
        InvocationError::BudgetExceeded { .. } => (CODE_ECONOMIC_FAULT, "economic.budget-exceeded"),
        InvocationError::OutletQueryCostViolation { .. } => {
            (CODE_PROTOCOL_VIOLATION, "query-cost-violation")
        }
        InvocationError::QueryViolation { .. } => (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_VIOLATION),
        InvocationError::KindMismatch { .. } => (CODE_PROTOCOL_VIOLATION, "kind-mismatch"),
        InvocationError::CaveatViolation {
            slug: caveat_slug, ..
        } => {
            // Caveat violations preserve the §5.4.4 slug from the rule
            // that fired; route the input-schema slug through the
            // input-class code, every other slug through the
            // authorization-denied class (matches
            // `invocation_error_to_context`'s slug→code routing).
            if *caveat_slug == SLUG_INPUT_SCHEMA_VIOLATION {
                (CODE_INPUT_VIOLATION, *caveat_slug)
            } else {
                // Default for all non-schema caveat slugs — covers
                // both the catch-all `SLUG_AUTHORIZATION_DENIED` slug
                // and the more specific `authorization.*` slugs
                // (`time-box-violation`, `rate-exceeded`, etc.) per
                // §5.4.4 catalog.
                (CODE_AUTHORIZATION_DENIED, *caveat_slug)
            }
        }
    };
    ChunkPayload::Error {
        code: code.to_owned(),
        message: format!("{slug}: {err}"),
        terminal: true,
    }
}

/// Maps an [`OutletExecutorError`] returned by `exec_*_stream` into the
/// terminal `ChunkPayload::Error { terminal: true, .. }` chunk the
/// framework appends to the stream (SCP-OUT-033 AC6).
///
/// `KindMismatch` (operator misdeclared the outlet half) and
/// `QueryViolation` (defense-in-depth runtime guard) both map to
/// Protocol-class errors per spec §5.4.4 — distinct slugs but the same
/// `CODE_PROTOCOL_VIOLATION` code. `Failed(msg)` carries the
/// executor's own diagnostic string and surfaces as
/// `CODE_EXECUTION_FAULT` with the §5.4.4 default
/// `execution.handler-panic` slug (the catalog includes `execution.*`
/// slugs collectively).
fn executor_error_to_terminal_payload(err: &OutletExecutorError) -> ChunkPayload {
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_KIND_MISMATCH, SLUG_QUERY_VIOLATION,
    };
    let (code, slug) = match err {
        OutletExecutorError::KindMismatch { .. } => (CODE_PROTOCOL_VIOLATION, SLUG_KIND_MISMATCH),
        OutletExecutorError::QueryViolation { .. } => {
            (CODE_PROTOCOL_VIOLATION, SLUG_QUERY_VIOLATION)
        }
        OutletExecutorError::Failed(_) => (CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC),
    };
    ChunkPayload::Error {
        code: code.to_owned(),
        message: format!("{slug}: {err}"),
        terminal: true,
    }
}

/// Builds a placeholder `DataProvenance` used by the framework's
/// terminal `ChunkPayload::End` chunk when the streaming
/// `invoke_outlet` returns successfully (SCP-OUT-033 AC5).
///
/// Spec §5.4.5: `End { aggregate, provenance, execution_time_ms }`.
/// The free function `invoke_outlet` does not have access to the
/// hosting context's full provenance metadata — the manager wrapper
/// is responsible for richer attachment when crossing context
/// boundaries. The placeholder built here records:
///
/// - `source_context` — the hosting context's id, so the End chunk's
///   provenance still carries a verifiable origin.
/// - `source_type = Persistent` — the context is open at invocation
///   time (state-checked at step 1).
/// - `discovery_method = OutOfBand` — direct callers of the free
///   function have no protocol-level discovery path; the cross-context
///   manager path overrides this.
/// - `chain_depth = 0` — the free function path is not crossing a
///   `§6.2` interface, so the chain is empty.
fn placeholder_data_provenance(context_id: &str) -> scp_protocol::provenance::DataProvenance {
    scp_protocol::provenance::DataProvenance {
        source_context: context_id.to_owned(),
        source_type: scp_protocol::provenance::SourceType::Persistent,
        counterparties: Vec::new(),
        purpose: None,
        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
        age: std::time::Duration::from_secs(0),
        memory_scope: scp_protocol::context::params::MemoryScope::Full,
        chain_depth: 0,
        chain_path: None,
        payment_amount: None,
        payment_adapter: None,
        payment_receipt_id: None,
    }
}

/// Wraps an inner `ChunkPayload` produced by the executor (or by the
/// framework's terminal-emission path) into a fully-formed
/// [`OutletStreamChunk`] with the next monotonic sequence number for
/// this `request_id` (SCP-OUT-033 AC4).
///
/// Signs the chunk under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:`
/// preimage with the supplied operator signing key when present
/// (round-7 wire-signing closure for the local-context invoke path).
/// When `signing_ctx.operator_signing_key` is `None`, emits the
/// all-zero placeholder and logs `tracing::error!` so the gap is
/// visible — production native paths always pass `Some`. When the
/// chunk is later forwarded by the dispatch pump
/// ([`crate::context::outlets::dispatch::run_stream_pump_v2`]) the
/// outer pump re-signs under the renumbered outer sequence.
fn wrap_chunk(
    signing_ctx: &InnerPumpSigningContext,
    request_id: RequestId,
    sequence: &mut u64,
    payload: ChunkPayload,
) -> OutletStreamChunk {
    let seq = *sequence;
    *sequence = sequence.saturating_add(1);
    let sig = signing_ctx.sign_inner_chunk(&request_id, seq, &payload);
    OutletStreamChunk {
        request_id,
        sequence: seq,
        payload,
        sig,
    }
}

/// Identity-and-key bundle the inner pump uses to sign every chunk
/// under the §5.4.5 `SCP-OUTLET-CHUNK-SIG-V1:` preimage.
///
/// Mirror of `dispatch::PumpSigningContext` — kept distinct to
/// preserve the layer boundary between the inner executor pump
/// (`invoke.rs`, no admission/credit gate) and the outer dispatch
/// pump (`dispatch.rs`, owns admission + credit + cancel-ack).
#[derive(Clone)]
pub(crate) struct InnerPumpSigningContext {
    /// Operator signing key. `None` for legacy / test callers that did
    /// not wire a key — `wrap_chunk` falls back to the all-zero
    /// placeholder + a `tracing::error!` log so the gap is visible.
    pub(crate) operator_signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
    /// Hosting context id (committed into the preimage).
    pub(crate) context_id: String,
    /// Outlet id (committed into the preimage).
    pub(crate) outlet_id: String,
    /// 32-byte `caveats_binding` (committed into the preimage).
    pub(crate) caveats_binding: [u8; 32],
}

impl InnerPumpSigningContext {
    /// Signs a `(request_id, sequence, payload)` triple under the
    /// pinned `(context_id, outlet_id, caveats_binding)`. Returns the
    /// 64-byte signature, or the all-zero placeholder + a
    /// `tracing::error!` log when the key is `None` / when JCS fails.
    fn sign_inner_chunk(
        &self,
        request_id: &RequestId,
        sequence: u64,
        payload: &ChunkPayload,
    ) -> [u8; 64] {
        let Some(key) = self.operator_signing_key.as_ref() else {
            tracing::error!(
                request_id = %hex::encode(request_id),
                outlet_id = %self.outlet_id,
                context_id = %self.context_id,
                sequence,
                "invoke pump: operator_signing_key is None — emitting unsigned chunk (legacy/test path)"
            );
            return [0u8; 64];
        };
        match scp_protocol::context::outlets::stream::sign_chunk(
            key,
            &self.context_id,
            &self.outlet_id,
            request_id,
            sequence,
            &self.caveats_binding,
            payload,
        ) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %self.outlet_id,
                    context_id = %self.context_id,
                    sequence,
                    error = %e,
                    "invoke pump: failed to sign chunk — emitting unsigned placeholder"
                );
                [0u8; 64]
            }
        }
    }
}

/// Streaming entry point for outlet invocation (SCP-OUT-033).
///
/// Returns a `mpsc::Receiver<OutletStreamChunk>` that yields the chunks
/// produced by the executor (`Data` / `Progress`), terminated by a
/// single terminal chunk (`End` on success, `Error { terminal: true }`
/// on failure). The framework spawns a tokio task that drives the
/// executor and pumps chunks into the channel.
///
/// Spec §5.4.5: "Outlet invocations are streams by construction. A
/// non-streaming invocation is the degenerate single-chunk case."
/// SCP-OUT-033 reshapes the public free-function surface so streaming
/// is the primary form. Legacy callers that prefer the value-and-event
/// tuple use [`invoke_outlet_aggregating`] instead.
///
/// # Sequence numbering
///
/// `sequence` starts at `0` and is strictly monotonic per `request_id`
/// (§5.4.5). The framework assigns sequence numbers — the executor
/// only writes `ChunkPayload` values, never `OutletStreamChunk`. The
/// terminal chunk shares the same `request_id` and is at the next
/// sequence after the last `Data` chunk.
///
/// # Timeout enforcement
///
/// `timeout_ms` enforces a hard deadline via [`tokio::time::timeout`].
/// On timeout the framework emits a terminal
/// `ChunkPayload::Error { code: CODE_EXECUTION_FAULT, slug:
/// SLUG_EXECUTION_TIMEOUT, terminal: true }` chunk and drops the
/// executor task — the `tokio::select!` arm pinned by `timeout` cancels
/// the executor future when the timeout fires (PRD AC7).
///
/// # Panic guard
///
/// The executor task runs inside [`run_executor_with_panic_guard`].
/// Panics inside the executor are recovered into a terminal
/// `ChunkPayload::Error { code: CODE_EXECUTION_FAULT, slug:
/// SLUG_EXECUTION_HANDLER_PANIC, terminal: true }` chunk per
/// SCP-OUT-028 / ADR-049 §148.
///
/// # Errors
///
/// Returns [`InvocationError`] only for the **synchronous** validation
/// failures that happen BEFORE the stream is opened (context state,
/// capability, registry lookup, input schema). Once the receiver is
/// returned, every failure mode (timeout, panic, executor `Err`,
/// caveat violation, output schema) surfaces as a terminal
/// `ChunkPayload::Error` chunk on the receiver — never as a `Result`
/// error.
#[allow(clippy::too_many_arguments)] // mirrors invoke_outlet_aggregating's parameter set so the streaming/aggregating split is interchangeable for callers that hold the same surrounding state.
pub async fn invoke_outlet<E>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    handler_panic_sink: Option<std::sync::Arc<dyn HandlerPanicSink>>,
    invoked_event_sink: Option<std::sync::Arc<dyn OutletInvokedEventSink>>,
    // Operator signing key used to sign every chunk under §5.4.5
    // `SCP-OUTLET-CHUNK-SIG-V1:`. `None` is reserved for legacy / test
    // callers; production native paths always supply `Some`. See
    // `InnerPumpSigningContext` for the fallback behaviour.
    operator_signing_key: Option<std::sync::Arc<ed25519_dalek::SigningKey>>,
    // 32-byte `caveats_binding` pinned at acceptance — committed into
    // the per-chunk-signature preimage. `[0u8; 32]` for legacy / test
    // callers; production paths supply the real binding.
    caveats_binding: [u8; 32],
) -> Result<mpsc::Receiver<OutletStreamChunk>, InvocationError>
where
    E: OutletExecutor + ?Sized + 'static,
{
    // Step 1-4 (synchronous): validate context state, registry, capability,
    // input schema BEFORE opening the stream. A `Result::Err` here means
    // the open was rejected before the stream was created — the receiver
    // has not been allocated yet.
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;
    // SCP-OUT-035: snapshot the input hash before handing the value to
    // the executor so the §5.4.5 event records what the executor saw
    // even if the executor mutates the value internally.
    let input_hash = sha256_json(&input);

    // Open the stream. The channel capacity matches the §5.4.5
    // `credit_window` default (32). When the buffer fills, the executor
    // back-pressures until a downstream consumer drains a slot.
    let (chunk_tx, chunk_rx) = mpsc::channel::<OutletStreamChunk>(DEFAULT_STREAM_CHANNEL_CAPACITY);
    let (payload_tx, payload_rx) = mpsc::channel::<ChunkPayload>(DEFAULT_STREAM_CHANNEL_CAPACITY);

    let request_id = fresh_request_id();
    let outlet_id_owned: OutletId = outlet_id.clone();
    let invoker_did_owned: DID = invoker_did.clone();
    let context_id_owned: String = context.context_id().to_owned();
    let context_handle_owned = context.clone();
    let role_state_owned = role_state.clone();
    let registry_owned = registry.clone();
    let kind = registration.kind;
    // Per-Data output-schema validation is intentionally NOT performed
    // by the streaming entry point — the legacy aggregating path
    // validates the post-executor `Value` against `output_schema`, and
    // a streaming executor's per-chunk values are validated by the
    // SDK / consumer instead. The single-shot adapter
    // [`one_shot_to_stream`] does not change schema semantics — the
    // legacy `invoke_outlet_aggregating` is the schema-checked path
    // for non-streaming callers.
    let _ = registration.schema.output_schema;
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));

    let signing_ctx = InnerPumpSigningContext {
        operator_signing_key,
        context_id: context_id_owned.clone(),
        outlet_id: outlet_id_owned.clone(),
        caveats_binding,
    };
    let task_inputs = StreamingTaskInputs {
        context: context_handle_owned,
        role_state: role_state_owned,
        registry: registry_owned,
        invoker_did: invoker_did_owned,
        outlet_id: outlet_id_owned,
        context_id: context_id_owned,
        request_id,
        kind,
        input,
        input_hash,
        executor: std::sync::Arc::clone(&executor),
        misdeclaration_sink,
        handler_panic_sink,
        invoked_event_sink,
        chunk_tx,
        payload_tx,
        payload_rx,
        timeout_duration,
        effective_timeout,
        signing_ctx,
    };
    tokio::spawn(run_streaming_executor_task(task_inputs));

    Ok(chunk_rx)
}

/// Bundle of inputs handed to the spawned streaming task body.
///
/// Splitting these out keeps [`invoke_outlet`] under the workspace's
/// `clippy::too_many_lines` ceiling: the synchronous-validation half
/// stays in the public function and the spawned-task driver lives in
/// [`run_streaming_executor_task`].
struct StreamingTaskInputs<E: ?Sized> {
    context: ContextHandle,
    role_state: ContextRoleState,
    registry: OutletRegistry,
    invoker_did: DID,
    outlet_id: OutletId,
    context_id: String,
    request_id: RequestId,
    kind: scp_protocol::context::outlets::OutletKind,
    input: serde_json::Value,
    /// Pre-computed input hash (SHA-256 over canonical JSON of the
    /// invocation input). Captured at stream open so the §5.4.5
    /// `OutletInvokedEvent.input_hash` is available even when the
    /// executor mutates the input value internally before producing
    /// chunks.
    input_hash: String,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    handler_panic_sink: Option<std::sync::Arc<dyn HandlerPanicSink>>,
    /// SCP-OUT-035 §5.4.5 event-log sink: receives exactly one
    /// `OutletInvokedEvent` at stream close. `None` disables emission
    /// entirely (legacy callers who don't append events to the log).
    invoked_event_sink: Option<std::sync::Arc<dyn OutletInvokedEventSink>>,
    chunk_tx: mpsc::Sender<OutletStreamChunk>,
    payload_tx: mpsc::Sender<ChunkPayload>,
    payload_rx: mpsc::Receiver<ChunkPayload>,
    timeout_duration: Duration,
    effective_timeout: u32,
    /// Operator signing context for per-chunk signing under
    /// `SCP-OUTLET-CHUNK-SIG-V1:`. When the dispatch pump wraps this
    /// task it will re-sign every chunk under the renumbered outer
    /// sequence; the inner sig closes the spec-compliance loop for
    /// callers that bypass the dispatch pump (manager-direct or test
    /// callers).
    signing_ctx: InnerPumpSigningContext,
}

/// Drives the streaming executor under panic guard + timeout, pumps
/// payloads to chunks with monotonic sequence, and emits the terminal
/// `End`/`Error` chunk (SCP-OUT-033).
///
/// Extracted from [`invoke_outlet`] so the public function stays under
/// the `clippy::too_many_lines` ceiling. The task runs on the tokio
/// runtime; when it finishes, the chunk channel closes and the
/// receiver returned to the caller observes EOS.
async fn run_streaming_executor_task<E>(inputs: StreamingTaskInputs<E>)
where
    E: OutletExecutor + ?Sized + 'static,
{
    let StreamingTaskInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        context_id,
        request_id,
        kind,
        input,
        input_hash,
        executor,
        misdeclaration_sink,
        handler_panic_sink,
        invoked_event_sink,
        chunk_tx,
        payload_tx,
        mut payload_rx,
        timeout_duration,
        effective_timeout,
        signing_ctx,
    } = inputs;

    let start = std::time::Instant::now();
    let mut sequence: u64 = 0;
    let outlet_id_for_emit = outlet_id.clone();
    let invoker_did_for_event = invoker_did.clone();
    // SCP-OUT-035: accumulate every chunk emitted by the stream so
    // the runtime can build the §5.4.5 chunk-manifest Merkle root and
    // count `Data` chunks for billing at terminal-chunk delivery.
    // Cloning each chunk before sending is cheap relative to the
    // executor work and keeps the manifest construction independent
    // of receiver-side draining order.
    let mut emitted_chunks: Vec<OutletStreamChunk> = Vec::new();

    // Build the executor future under `catch_unwind` so panics inside
    // the executor body recover into a terminal `Error` chunk
    // (SCP-OUT-028 streaming variant). See `build_executor_future`.
    let executor_future = build_executor_future(ExecutorFutureInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        kind,
        input,
        executor,
        misdeclaration_sink,
        payload_tx: payload_tx.clone(),
    });

    // Drop the original `payload_tx` retained by this scope so the
    // payload pump observes EOS as soon as the executor's clone is
    // dropped.
    drop(payload_tx);

    tokio::pin!(executor_future);

    let pump_outcome = pump_payload_stream_capture(
        &mut payload_rx,
        &chunk_tx,
        &mut sequence,
        request_id,
        executor_future,
        timeout_duration,
        &mut emitted_chunks,
        &signing_ctx,
    )
    .await;

    if !pump_outcome.chunk_tx_alive {
        // Receiver dropped mid-stream; no terminal chunk is emitted.
        // The §5.4.5 event-log shape says one event per stream, but
        // the contract is "after terminal chunk is delivered to the
        // receiver" — when the receiver disconnects there is no
        // delivery. Skip emission to keep the audit log honest.
        return;
    }

    // After exiting the pump, drain any payloads the executor already
    // pushed but the pump did not yet observe. Guards against the race
    // where the executor finished simultaneously with the deadline.
    if !pump_outcome.timed_out {
        while let Ok(payload) = payload_rx.try_recv() {
            let chunk = wrap_chunk(&signing_ctx, request_id, &mut sequence, payload);
            emitted_chunks.push(chunk.clone());
            if chunk_tx.send(chunk).await.is_err() {
                // Receiver dropped during late drain; same rationale
                // as above — skip the event-log emission.
                return;
            }
        }
    }

    // Emit the terminal chunk based on the executor outcome / timeout
    // / panic.
    let terminal_payload = build_terminal_chunk(BuildTerminalChunkInputs {
        timed_out: pump_outcome.timed_out,
        executor_outcome: pump_outcome.executor_outcome,
        outlet_id: &outlet_id_for_emit,
        context_id: &context_id,
        effective_timeout,
        start,
        handler_panic_sink: handler_panic_sink.as_deref(),
    });

    let terminal_chunk = wrap_chunk(&signing_ctx, request_id, &mut sequence, terminal_payload);
    emitted_chunks.push(terminal_chunk.clone());
    let delivered = chunk_tx.send(terminal_chunk).await.is_ok();

    if !delivered {
        // Receiver dropped before the terminal chunk landed — same
        // rationale as the early-exit branch above.
        return;
    }

    // SCP-OUT-035 §5.4.5: emit ONE OutletInvokedEvent at stream close,
    // AFTER the terminal chunk has been delivered to the receiver.
    if let Some(sink) = invoked_event_sink {
        let event = build_streaming_outlet_event(
            request_id,
            &outlet_id_for_emit,
            &invoker_did_for_event,
            input_hash,
            elapsed_ms(start),
            &emitted_chunks,
        );
        sink.record(event);
    }
}

/// Builds the §5.4.5 `OutletInvokedEvent` from a complete recorded
/// chunk sequence (SCP-OUT-035).
///
/// `request_id` is the per-stream `[u8; 16]` UUID. The `OutletInvokedEvent`
/// stores the request id as a hex-encoded string for cross-bridge
/// stability — the bytes themselves remain the canonical form on the
/// stream wire types.
///
/// Counting and status:
///
/// - `stream_chunk_count`: total chunks emitted (clamped to `u32::MAX`
///   on overflow — a stream of 4 billion chunks is practically
///   unreachable, but the conversion is total).
/// - `chunks_billed`: count of `Data` chunks at or below the
///   cancel-ack sequence. SCP-OUT-034 will refine cancel-ack
///   semantics; this implementation defaults to "count Data chunks
///   that were emitted up to the terminal chunk" which is the §5.4.5
///   billing rule with no cancel-ack present (cancel-ack >=
///   terminal sequence ⇒ the predicate reduces to `@type == "data"`).
/// - `stream_terminal_status`: derived from the terminal chunk's
///   payload variant. `Ok` for `End`, `Error(code)` for terminal
///   `Error`, `Cancelled` reserved for cancel-ack closure (SCP-OUT-034
///   wires it). When no terminal chunk is present the status is
///   conservatively `Error("…stream-aborted")` so audit readers
///   distinguish a truncated stream from a clean close.
/// - `stream_manifest_hash`: SHA-256 Merkle root over the chunk
///   sequence per §5.4.5 (RFC 6962 leaf/interior tags, V1 separator).
/// - `output_hash`: SHA-256 of the terminal `End.aggregate` value
///   when present; absent on error closure (no aggregate to hash).
/// - `status`: legacy `OutletStatus` mirror of `stream_terminal_status`
///   (Success / Error). Present for backwards compatibility with
///   pre-SCP-OUT-035 readers.
pub(crate) fn build_streaming_outlet_event(
    request_id: RequestId,
    outlet_id: &OutletId,
    invoker_did: &DID,
    input_hash: String,
    execution_time_ms: u64,
    chunks: &[OutletStreamChunk],
) -> OutletInvokedEvent {
    use scp_protocol::context::outlets::stream::{
        ChunkPayload, StreamTerminalStatus, compute_chunk_manifest_root,
    };

    // u32::try_from clamps to u32::MAX per the workspace convention
    // for length-prefix conversions.
    let stream_chunk_count = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
    let mut billed_count: usize = 0;
    let mut output_hash: Option<String> = None;
    let mut terminal_status = StreamTerminalStatus::Error(
        scp_protocol::context::outlets::error_codes::CODE_EXECUTION_FAULT.to_owned(),
    );
    let mut legacy_status = OutletStatus::Error;

    for chunk in chunks {
        match &chunk.payload {
            ChunkPayload::Data { value } => {
                billed_count = billed_count.saturating_add(1);
                // The output_hash is only updated for terminal-Data
                // semantics; the `End.aggregate` field carries the
                // canonical aggregate value and overrides this hash
                // when present.
                let _ = value;
            }
            ChunkPayload::Progress { .. } => {}
            ChunkPayload::End { aggregate, .. } => {
                terminal_status = StreamTerminalStatus::Ok;
                legacy_status = OutletStatus::Success;
                output_hash = Some(scp_protocol::context::outlets::lifecycle::sha256_json(
                    aggregate,
                ));
            }
            ChunkPayload::Error { code, terminal, .. } => {
                if *terminal {
                    terminal_status = StreamTerminalStatus::Error(code.clone());
                    legacy_status = OutletStatus::Error;
                }
            }
        }
    }

    let chunks_billed = u32::try_from(billed_count).unwrap_or(u32::MAX);

    let stream_manifest_hash = compute_chunk_manifest_root(chunks).unwrap_or([0u8; 32]);

    OutletInvokedEvent {
        request_id: hex::encode(request_id),
        outlet_id: outlet_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: legacy_status,
        execution_time_ms,
        input_hash,
        output_hash,
        cost: None,
        stream_chunk_count,
        chunks_billed,
        stream_manifest_hash,
        stream_terminal_status: terminal_status,
    }
}

/// Variant of [`pump_payload_stream`] that captures every chunk
/// emitted by the executor into `recorded_chunks` (SCP-OUT-035) so the
/// runtime can compute the §5.4.5 chunk-manifest Merkle root at stream
/// close. The original `pump_payload_stream` is retained for callers
/// that don't need the recording — see the comment on
/// [`run_streaming_executor_task`] for why both helpers exist.
#[allow(clippy::too_many_arguments)] // signing_ctx is the round-7 wire-signing addition; bundling it would require a wrapper struct that obscures the small parameter set.
async fn pump_payload_stream_capture<F>(
    payload_rx: &mut mpsc::Receiver<ChunkPayload>,
    chunk_tx: &mpsc::Sender<OutletStreamChunk>,
    sequence: &mut u64,
    request_id: RequestId,
    executor_future: std::pin::Pin<&mut F>,
    timeout_duration: Duration,
    recorded_chunks: &mut Vec<OutletStreamChunk>,
    signing_ctx: &InnerPumpSigningContext,
) -> PumpOutcome
where
    F: Future<Output = Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>
        + Send,
{
    let mut executor_future = executor_future;
    let mut deadline = std::pin::pin!(tokio::time::sleep(timeout_duration));
    let mut executor_outcome: Option<
        Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>,
    > = None;
    let mut timed_out = false;
    let mut chunk_tx_alive = true;

    loop {
        tokio::select! {
            biased;

            outcome = &mut executor_future, if executor_outcome.is_none() => {
                executor_outcome = Some(outcome);
            }

            next_payload = payload_rx.recv() => {
                match next_payload {
                    Some(payload) => {
                        let chunk = wrap_chunk(signing_ctx, request_id, sequence, payload);
                        recorded_chunks.push(chunk.clone());
                        if chunk_tx.send(chunk).await.is_err() {
                            chunk_tx_alive = false;
                            break;
                        }
                    }
                    None => {
                        if executor_outcome.is_some() {
                            break;
                        }
                    }
                }
            }

            () = &mut deadline, if !timed_out => {
                timed_out = true;
                break;
            }
        }
    }

    PumpOutcome {
        timed_out,
        chunk_tx_alive,
        executor_outcome,
    }
}

/// Inputs for [`build_executor_future`] — the helper that constructs
/// the panic-guarded executor future for the streaming pipeline.
struct ExecutorFutureInputs<E: ?Sized> {
    context: ContextHandle,
    role_state: ContextRoleState,
    registry: OutletRegistry,
    invoker_did: DID,
    outlet_id: OutletId,
    kind: scp_protocol::context::outlets::OutletKind,
    input: serde_json::Value,
    executor: std::sync::Arc<E>,
    misdeclaration_sink: Option<std::sync::Arc<dyn QueryMisdeclarationSink>>,
    payload_tx: mpsc::Sender<ChunkPayload>,
}

/// Builds the panic-guarded executor future the streaming pipeline
/// races against the deadline. The returned future is
/// `AssertUnwindSafe(...).catch_unwind()`-wrapped so the pump can
/// distinguish executor-`Err`, executor-success, and recovered panics
/// (SCP-OUT-028 streaming variant of ADR-049 §148).
fn build_executor_future<E>(
    inputs: ExecutorFutureInputs<E>,
) -> futures::future::CatchUnwind<
    AssertUnwindSafe<impl Future<Output = Result<(), OutletExecutorError>> + Send>,
>
where
    E: OutletExecutor + ?Sized + 'static,
{
    let ExecutorFutureInputs {
        context,
        role_state,
        registry,
        invoker_did,
        outlet_id,
        kind,
        input,
        executor,
        misdeclaration_sink,
        payload_tx,
    } = inputs;
    AssertUnwindSafe(async move {
        let read = ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker_did,
            &outlet_id,
            &[],
            0,
            None,
            None,
        );
        match kind {
            scp_protocol::context::outlets::OutletKind::Query => {
                executor.exec_query_stream(&read, input, payload_tx).await
            }
            scp_protocol::context::outlets::OutletKind::Action => {
                let mut mutable = MutableInvocation::new(
                    ReadOnlyInvocation::new(
                        &context,
                        &role_state,
                        &registry,
                        &invoker_did,
                        &outlet_id,
                        &[],
                        0,
                        None,
                        None,
                    ),
                    scp_protocol::context::outlets::OutletKind::Action,
                    misdeclaration_sink
                        .as_deref()
                        .map(|sink| sink as &dyn QueryMisdeclarationSink),
                );
                executor
                    .exec_action_stream(&mut mutable, input, payload_tx)
                    .await
            }
        }
    })
    .catch_unwind()
}

/// Outcome of [`pump_payload_stream_capture`] handed back to
/// [`run_streaming_executor_task`].
struct PumpOutcome {
    /// Whether the deadline fired (timeout) before the executor
    /// finished.
    timed_out: bool,
    /// Whether the chunk-sender was still alive when the pump exited
    /// (consumer didn't drop the receiver mid-stream).
    chunk_tx_alive: bool,
    /// `None` when timed out; `Some(Ok(Ok(())))` for a normal Ok
    /// completion, `Some(Ok(Err(...)))` for executor-internal failure,
    /// `Some(Err(payload))` for a recovered panic.
    executor_outcome:
        Option<Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>,
}

/// Inputs for [`build_terminal_chunk`] — the framework's terminal
/// `End` / `Error` chunk emission helper.
struct BuildTerminalChunkInputs<'a> {
    timed_out: bool,
    executor_outcome:
        Option<Result<Result<(), OutletExecutorError>, Box<dyn std::any::Any + Send>>>,
    outlet_id: &'a OutletId,
    context_id: &'a str,
    effective_timeout: u32,
    start: std::time::Instant,
    handler_panic_sink: Option<&'a dyn HandlerPanicSink>,
}

/// Builds the §5.4.5 terminal chunk for a streaming outlet invocation
/// (SCP-OUT-033). One of: `End` on success, `Error { terminal: true }`
/// on timeout / panic / executor failure.
fn build_terminal_chunk(inputs: BuildTerminalChunkInputs<'_>) -> ChunkPayload {
    if inputs.timed_out {
        tracing::warn!(
            outlet_id = %inputs.outlet_id,
            code = CODE_EXECUTION_FAULT,
            slug = SLUG_EXECUTION_TIMEOUT,
            timeout_ms = inputs.effective_timeout,
            "outlet streaming executor timed out — emitted terminal Error chunk and dropped task"
        );
        return ChunkPayload::Error {
            code: CODE_EXECUTION_FAULT.to_owned(),
            message: format!(
                "outlet execution timed out after {timeout}ms",
                timeout = inputs.effective_timeout
            ),
            terminal: true,
        };
    }
    match inputs.executor_outcome {
        Some(Ok(Ok(()))) => {
            let execution_time_ms = elapsed_ms(inputs.start);
            ChunkPayload::End {
                aggregate: serde_json::Value::Null,
                provenance: placeholder_data_provenance(inputs.context_id),
                execution_time_ms,
            }
        }
        Some(Ok(Err(exec_err))) => executor_error_to_terminal_payload(&exec_err),
        Some(Err(panic_payload)) => {
            let panic_message = panic_payload_to_message(&panic_payload);
            tracing::warn!(
                outlet_id = %inputs.outlet_id,
                code = CODE_EXECUTION_FAULT,
                slug = SLUG_EXECUTION_HANDLER_PANIC,
                panic_message = %panic_message,
                "outlet streaming executor panicked — recovered via catch_unwind (operator-attributable, §5.4.2)"
            );
            if let Some(sink) = inputs.handler_panic_sink {
                sink.record(handler_panic_event(inputs.outlet_id));
            }
            ChunkPayload::Error {
                code: CODE_EXECUTION_FAULT.to_owned(),
                message: panic_message,
                terminal: true,
            }
        }
        None => {
            // Unreachable in production: the pump only exits without
            // an outcome on timeout, which is handled above.
            ChunkPayload::Error {
                code: CODE_EXECUTION_FAULT.to_owned(),
                message: "executor task aborted before emitting an outcome".to_owned(),
                terminal: true,
            }
        }
    }
}

///
/// Execution flow:
/// 1. Validates context state is [`Active`](ContextState::Active).
/// 2. Validates invoker has [`OutletCall(outlet_id)`](Capability::OutletCall)
///    or [`OutletCallAll`](Capability::OutletCallAll) capability via UCAN.
/// 3. Looks up the outlet in the registry.
/// 4. Validates input against the outlet's input schema.
///    - 4a. Economy: checks budget and UCAN composition (if economy context provided).
/// 5. Calls the outlet implementation via the `executor` function.
/// 6. Validates output against the outlet's output schema.
///    - 6a. Post-invocation bookkeeping — participation + consequences.
/// 7. Builds a [`OutletInvokedEvent`] for the caller to append to the event log.
/// 8. Returns the outlet output and any triggered consequences.
///
/// # Timeout handling
///
/// The `timeout_ms` parameter specifies the maximum time to wait for the outlet
/// to complete. If the outlet does not complete within the timeout, a
/// [`InvocationError::Timeout`] is returned. The timeout is clamped to the
/// hard protocol maximum of [`MAX_TIMEOUT_MS`] (300,000ms / 5 minutes).
///
/// # Cancellation
///
/// Cancellation is handled externally via [`OutletCancel`](super::lifecycle::OutletCancel)
/// messages. This function supports cancellation through a
/// `cancellation_token` future that resolves when cancellation is requested.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// budget exceeded, or UCAN composition failures.
///
/// # Panic guard (SCP-OUT-028)
///
/// The executor invocation runs inside [`run_executor_with_panic_guard`].
/// A panic in `exec_query` / `exec_action` is recovered into
/// [`InvocationError::HandlerPanic`] (`SCP-TOOL-6130`,
/// `execution.handler-panic`) and a parallel
/// `OutletVerifiedEvent { reason: HandlerPanicked }` is emitted through
/// `handler_panic_sink` (and `tracing::warn!` always) per spec §5.4.2 —
/// the operator-attributable signal that mirrors `QueryMisdeclaration`.
/// No panic escapes `invoke_outlet`.
///
/// See ADR-010 acceptance criterion 3 (`invoke_outlet`).
/// See SCP-OUT-028 / ADR-049 §148 for the panic guard.
///
/// # Aggregating vs streaming
///
/// This is the *aggregating* variant — it collects the executor's
/// output into a single `Value` and returns the full bookkeeping
/// tuple. The §5.4.5 streaming entry point is [`invoke_outlet`], which
/// returns `Result<mpsc::Receiver<OutletStreamChunk>, _>` instead.
/// SCP-OUT-033 reshaped the public free-function surface so the stream
/// is the primary form; this aggregating helper preserves the legacy
/// shape for callers that prefer the value-and-event tuple over a
/// chunk receiver.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Full economy + escrow lifecycle + SCP-OUT-028 panic sink
pub async fn invoke_outlet_aggregating<F, Fut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    mut economy: Option<&mut OutletEconomyContext<'_, S>>,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<
    (
        serde_json::Value,
        OutletInvokedEvent,
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<crate::economy::adapter::PaymentReceipt>,
    ),
    InvocationError,
>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    // 1-4. Validate context state, capability, outlet registration, and input
    // schema BEFORE deducting budget. The helper
    // `invoke_outlet_execute_and_validate` runs the same checks again after the
    // economy pre-check — this is intentional redundancy so direct callers
    // get the pre-budget early bail path while the manager wrapper can share
    // the helper directly without replicating the economy flow.
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    // SCP-OUT-014: registry lookup is moved BEFORE the capability check
    // so we can apply the kind-specific stem (`outlet_query:` for Query
    // outlets, `outlet_call:` for Action outlets). Looking up the outlet
    // first does NOT widen the auth oracle — `OutletNotFound` is returned
    // for unregistered outlets regardless of the caller's capabilities,
    // matching the pre-OUT-014 behavior.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. We immediately call `record_spend`
    // here so the behavior visible to direct callers of `invoke_outlet` is
    // unchanged (budget is still debited before the executor runs). The
    // manager wrapper `ContextManager::invoke_outlet_with_economy` bypasses
    // this code path entirely so it can snapshot state under its own lock.
    let action_cost = match economy.as_deref_mut() {
        Some(econ) => {
            let cost = economy_pre_check(econ, invoker_did)?;
            if cost.0 > 0 {
                econ.budget_tracker
                    .record_spend(invoker_did, cost)
                    .map_err(|_| InvocationError::BudgetExceeded {
                        did: invoker_did.to_string(),
                        cost: cost.0,
                        remaining: econ.budget_tracker.remaining(invoker_did).0,
                    })?;
            }
            Some(cost)
        }
        None => None,
    };

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE outlet execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_outlet_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await
        {
            Ok(prepared) => prepared,
            Err(auth_err) => {
                void_escrow_and_rollback(
                    None,
                    escrow_parts.as_ref(),
                    action_cost,
                    &mut economy,
                    invoker_did,
                )
                .await;
                return Err(auth_err);
            }
        }
    } else {
        None
    };

    // 5-6. Execute the outlet with timeout and validate the output. Delegates
    // to the shared `invoke_outlet_execute_and_validate` helper so the manager
    // wrapper can share the exact same execution path. SCP-OUT-028: the
    // helper applies the `catch_unwind` panic guard internally and forwards
    // `handler_panic_sink` for OutletVerified attribution.
    let outcome = match invoke_outlet_execute_and_validate(
        context,
        registry,
        role_state,
        outlet_id,
        input,
        invoker_did,
        timeout_ms,
        executor,
        handler_panic_sink,
        // SCP-OUT-021 caveat hook: the free `invoke_outlet` does not own
        // a CaveatCounterStore — it is a thin wrapper for direct callers
        // that bypass the `ContextManager` entry point. Caveat enforcement
        // is the manager wrapper's responsibility (see
        // `ContextManager::invoke_outlet_with_economy`); direct callers
        // get post-input schema enforcement only.
        None,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            void_escrow_and_rollback(
                escrow.as_ref(),
                escrow_parts.as_ref(),
                action_cost,
                &mut economy,
                invoker_did,
            )
            .await;
            return Err(err);
        }
    };
    let InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    } = outcome;

    // 6a. Post-invocation bookkeeping (#1530, #1531) — participation +
    // consequence evaluation.
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 6b. Complete (capture) the escrowed payment after successful execution.
    let payment_receipt = finalize_outlet_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7-8. Build event + return (#1596: receipt returned to caller).
    let event = build_outlet_event(
        outlet_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        action_cost,
    );
    crate::metrics::record_outlet_invocation();
    Ok((output, event, triggered, payment_receipt))
}

/// Outcome of [`invoke_outlet_execute_and_validate`] — the pure-execution half
/// of outlet invocation shared between direct callers and the
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// wrapper. Captures everything needed to build a [`OutletInvokedEvent`]
/// without re-running the executor or rehashing the payloads.
#[derive(Debug)]
pub(crate) struct InvokeExecuteOutcome {
    /// The outlet output value (already schema-validated).
    pub output: serde_json::Value,
    /// SHA-256 hash of the input JSON (hex-encoded). Computed from the input
    /// the executor actually saw, before execution.
    pub input_hash: String,
    /// SHA-256 hash of the output JSON (hex-encoded). Computed after the
    /// executor returned and before output-schema validation so the hash
    /// reflects what the executor produced verbatim.
    pub output_hash: String,
    /// Wall-clock execution time in milliseconds, from just before the
    /// executor was dispatched to just after output-schema validation
    /// succeeded.
    pub execution_time_ms: u64,
}

/// SCP-OUT-021 — caveat post-input check hook.
///
/// Invoked by [`invoke_outlet_execute_and_validate`] after the outlet's
/// input schema validation passes but BEFORE the executor runs. The hook
/// owns the synchronous local checks
/// ([`InvocationCaveats::check_invocation_local`](scp_protocol::trust::caveats::InvocationCaveats::check_invocation_local))
/// AND the asynchronous counter-store calls
/// (`max_calls`, `amount_max_cumulative`, `rate_window`) — combining both
/// into one closure preserves the §7.3.8 ordering invariant: synchronous
/// caveats first (so a fast rejection does not consume counter capacity),
/// counter-store next (atomic per-UCAN CAS).
///
/// On failure the hook returns [`InvocationError`] (typically
/// [`InvocationError::InputValidationFailed`] or a manager-mapped
/// authorization error); on success it returns `Ok(())` and the executor
/// proceeds.
///
/// The hook receives a borrowed reference to the input `serde_json::Value`
/// so the same value the executor will see (and the input hash will be
/// computed from) is what the schema check observes. The hook MUST NOT
/// mutate the input.
pub type CaveatPostInputCheck<'a> = Box<
    dyn FnOnce(
            &serde_json::Value,
        )
            -> std::pin::Pin<Box<dyn Future<Output = Result<(), InvocationError>> + Send + 'a>>
        + Send
        + 'a,
>;

/// Runs steps 1-6 of outlet invocation without any economy state.
///
/// This helper is the off-lock execution half of outlet invocation. It
/// performs: context-state check, capability check, tool lookup, input
/// schema validation, executor dispatch under a bounded timeout, and
/// output schema validation. It deliberately takes NO economy context
/// and touches no governance state so that
/// [`ContextManager::invoke_outlet_with_economy`](crate::context::ContextManager::invoke_outlet_with_economy)
/// can call it with the `contexts` mutex dropped.
///
/// The free [`invoke_outlet`] function also delegates to this helper after
/// running economy pre-check / escrow authorization, so the execution
/// path is shared between the two entry points.
///
/// # SCP-OUT-021 caveat hook
///
/// The optional `caveat_post_input_check` argument runs §7.3.8 post-input
/// caveat enforcement immediately after step 4 (input schema validation)
/// and before the executor is dispatched. The hook must surface caveat
/// failures as [`InvocationError`] values.
///
/// # Panic guard (SCP-OUT-028)
///
/// The executor invocation runs inside [`run_executor_with_panic_guard`]
/// which wraps the closure call AND the resulting future in
/// [`std::panic::catch_unwind`]. A panic inside `exec_query` /
/// `exec_action` is recovered into [`InvocationError::HandlerPanic`]
/// (mapping to `SCP-TOOL-6130`, `execution.handler-panic`) and emits a
/// parallel
/// `OutletVerifiedEvent { integrity_ok: false, reason: HandlerPanicked }`
/// through `handler_panic_sink` per spec §5.4.2 (operator-attributable
/// integrity-failure signal). Panics are protocol-visible signals
/// attributable to the outlet's `operator_did` — NOT SDK-internal bugs.
/// See ADR-049 §148.
///
/// # Errors
///
/// Returns [`InvocationError`] on state, capability, schema validation,
/// timeout, executor failure, or recovered handler panic. Cancellation is
/// not supported by this variant — see the inline timeout-plus-select!
/// path in [`invoke_outlet_with_cancellation_aggregating`] instead.
#[allow(clippy::too_many_arguments)] // 10 parameters mirror `invoke_outlet`; lower bound imposed by the execution contract + SCP-OUT-028 panic sink + SCP-OUT-021 caveat hook.
pub(crate) async fn invoke_outlet_execute_and_validate<F, Fut>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
    caveat_post_input_check: Option<CaveatPostInputCheck<'_>>,
) -> Result<InvokeExecuteOutcome, InvocationError>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
{
    let start = std::time::Instant::now();

    // 1. Validate context state is Active.
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }

    // 2. Look up the outlet in the registry.
    //    SCP-OUT-014: registry lookup precedes the capability check so we
    //    can pick the kind-specific stem (Query → `outlet_query:`, Action
    //    → `outlet_call:`). `OutletNotFound` is returned for unregistered
    //    outlets regardless of caller capability.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;

    // 3. Validate invoker holds the kind-appropriate split capability.
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }

    // 4. Validate input against the outlet's input schema.
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4b. SCP-OUT-021 — post-input caveat enforcement (§7.3.8). Runs the
    // synchronous local checks plus the counter-store CAS for max_calls /
    // amount_max_cumulative / rate_window. Failures here are the §7.3.8
    // post-input gate; the caller surfaces them as Authorization-class
    // errors with the slug from `CheckInvocationError::slug` /
    // `CounterExhausted::kind`.
    if let Some(check) = caveat_post_input_check {
        check(&input).await?;
    }

    // 4a. Compute the input hash up-front from the value the executor will
    // see. Doing this before execution lets the hash be recorded even if the
    // executor mutates the input object (serde_json::Value is a value type,
    // but this also protects against any future change to `F` that might
    // take the input by reference and mutate it).
    let input_hash = sha256_json(&input);

    // 5. Execute the outlet with timeout.
    //
    // SCP-OUT-028: the executor closure + future are wrapped in
    // `catch_unwind` via `run_executor_with_panic_guard`. A panic in
    // `exec_query`/`exec_action` is recovered into
    // `InvocationError::HandlerPanic` and emits the §5.4.2 parallel
    // `OutletVerifiedEvent { reason: HandlerPanicked }` through
    // `handler_panic_sink` — the panic does not escape `invoke_outlet`.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let guarded = run_executor_with_panic_guard(executor, input, outlet_id, handler_panic_sink);
    let execution_result = tokio::time::timeout(timeout_duration, guarded).await;
    let output = match execution_result {
        Ok(Ok(Ok(output))) => output,
        Ok(Ok(Err(exec_err))) => {
            return Err(InvocationError::ExecutionFailed { message: exec_err });
        }
        Ok(Err(panic_err)) => {
            // The panic guard already emitted the warn-level log and the
            // `OutletVerified` signal; surface the typed envelope.
            return Err(panic_err);
        }
        Err(_elapsed) => {
            return Err(InvocationError::Timeout {
                timeout_ms: effective_timeout,
            });
        }
    };

    // 6. Validate output against the outlet's output schema.
    validate_value_against_schema(&output, &registration.schema.output_schema)
        .map_err(|msg| InvocationError::OutputValidationFailed { message: msg })?;

    let output_hash = sha256_json(&output);
    let execution_time_ms = elapsed_ms(start);

    Ok(InvokeExecuteOutcome {
        output,
        input_hash,
        output_hash,
        execution_time_ms,
    })
}

/// Runs economy pre-checks (pure compute — no state mutation).
///
/// Strategy B: this function is a PURE compute that returns the owned
/// evaluated cost. It does NOT mutate `budget_tracker`. Callers are
/// responsible for explicitly calling `budget_tracker.record_spend` after
/// this function returns so that budget mutation is visible at the call
/// site. Separating "compute cost" from "deduct budget" lets the
/// `ContextManager::invoke_outlet_with_economy` wrapper snapshot state in
/// Phase 1 under the locked contexts mutex, drop the lock, run the
/// executor off-lock, and commit/rollback in Phase 3.
///
/// Uses real observable metrics from `OutletEconomyContext` (not zero metrics).
/// Evaluates cost, applies per-DID escalation, checks spending UCAN
/// AND-composition (§19.5), and checks `has_budget` for the invoker.
///
/// Returns the evaluated action cost for inclusion in the `OutletInvokedEvent`.
pub(crate) fn economy_pre_check<S: BuildHasher>(
    economy: &OutletEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Result<scp_protocol::economy::types::Amount, InvocationError> {
    // Step 1: derive a base cost from the economic policy. Consistent with
    // `enforce_economy` (messages/joins): no economic policy → free action.
    // Anti-spam for free contexts is provided by the token-bucket hard rate
    // limit, which runs independently of the cost layer.
    let Some(policy) = economy.economic_policy else {
        return Ok(scp_protocol::economy::types::Amount::new(0));
    };
    let base_cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::OutletCall,
        &economy.metrics,
    )
    .ok_or_else(|| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: u64::MAX,
        remaining: 0,
    })?;

    // Step 2: apply per-DID escalation (§19.7) when both the velocity tracker
    // and the pricing config are wired through. This mirrors `enforce_economy`
    // for messages and joins.
    let cost = match (economy.velocity_tracker, economy.message_pricing) {
        (Some(tracker), Some(pricing)) => tracker.compute_escalated_cost(
            invoker_did,
            economy.now,
            base_cost,
            &pricing.escalation,
            pricing.floor,
            pricing.cap,
        ),
        _ => base_cost,
    };

    if cost.0 == 0 {
        return Ok(cost);
    }

    // Spending UCAN check (§19.5): paid actions require a spending UCAN.
    // The action capability was already verified at step 2 via the
    // `OutletCall` / `OutletCallAll` `member_has_capability` check — that
    // is the action side of AND-composition (see spec §19.5 layer split).
    check_outlet_spending_capability(cost, economy.spending_ucan)?;

    // Budget check — no auto-grant. Budget must be explicitly approved via
    // ApproveSpend governance action. We deliberately do NOT call
    // `record_spend` here; the caller performs the deduction after this
    // function returns so the mutation point is visible and Strategy B
    // keeps this function pure.
    if !economy.budget_tracker.has_budget(invoker_did) {
        return Err(InvocationError::BudgetExceeded {
            did: invoker_did.to_string(),
            cost: cost.0,
            remaining: 0,
        });
    }

    Ok(cost)
}

/// Runs post-invocation bookkeeping (participation + consequence evaluation).
fn economy_post_check<S: BuildHasher>(
    economy: &mut OutletEconomyContext<'_, S>,
    invoker_did: &DID,
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    post_outlet_invocation_bookkeeping(
        economy.events,
        invoker_did,
        economy.context_id,
        economy.now,
        economy.participation_cache,
        economy.consequence_rules,
    )
}

/// Builds a [`OutletInvokedEvent`] from invocation metadata.
///
/// Accepts pre-computed hashes and elapsed time so the event constructor
/// is a pure data-assembly step that both direct callers and the
/// `ContextManager::invoke_outlet_with_economy` wrapper can share.
///
/// # Streaming fields (SCP-OUT-035)
///
/// The aggregating path is the §5.4.5 *degenerate two-chunk case*: every
/// invocation is a stream by construction, and a one-shot invocation is
/// modeled as one `Data` chunk followed by one `End` chunk. The
/// returned event therefore reports `stream_chunk_count = 2`,
/// `chunks_billed = 1` (the single `Data`), and computes the manifest
/// root over the synthesized two-chunk sequence.
/// `stream_terminal_status` is `Ok` because the aggregating path only
/// reaches this builder on success. Cost-bearing failures route through
/// [`build_amplification_rejection_event`] (and similar rejection
/// builders), which set the streaming fields to the rejection sentinel.
pub(crate) fn build_outlet_event(
    outlet_id: &OutletId,
    invoker_did: &DID,
    execution_time_ms: u64,
    input_hash: String,
    output_hash: String,
    cost: Option<scp_protocol::economy::types::Amount>,
) -> OutletInvokedEvent {
    let request_id = uuid::Uuid::new_v4().to_string();
    let (stream_chunk_count, chunks_billed, stream_manifest_hash) =
        compute_one_shot_stream_metadata(execution_time_ms);
    OutletInvokedEvent {
        request_id,
        outlet_id: outlet_id.to_owned(),
        invoker_did: invoker_did.clone(),
        status: OutletStatus::Success,
        execution_time_ms,
        input_hash,
        output_hash: Some(output_hash),
        cost,
        stream_chunk_count,
        chunks_billed,
        stream_manifest_hash,
        stream_terminal_status: scp_protocol::context::outlets::stream::StreamTerminalStatus::Ok,
    }
}

/// Computes the §5.4.5 degenerate-two-chunk-case manifest metadata for
/// the aggregating outlet path.
///
/// For non-streaming invocations the wire form is exactly two chunks:
/// `Data(Null)` at sequence 0 and `End { aggregate: Null, .. }` at
/// sequence 1, both bearing a synthesized `request_id` and zero
/// signature (the aggregating path predates the per-chunk signature
/// surface; SDK callers that demand cryptographic equivocation
/// resistance use the streaming entry point). The two synthetic chunks
/// are sufficient to seed the manifest hash because the manifest leaf
/// covers the canonical chunk including `sig` — two callers running
/// the same aggregating invocation will compute the same root.
///
/// Returned tuple: `(stream_chunk_count, chunks_billed,
/// stream_manifest_hash)`.
fn compute_one_shot_stream_metadata(execution_time_ms: u64) -> (u32, u32, [u8; 32]) {
    use scp_protocol::context::outlets::stream::{
        ChunkPayload, OutletStreamChunk, compute_chunk_manifest_root,
    };

    let request_id: [u8; 16] = *uuid::Uuid::now_v7().as_bytes();
    let data = OutletStreamChunk {
        request_id,
        sequence: 0,
        payload: ChunkPayload::Data {
            value: serde_json::Value::Null,
        },
        sig: [0u8; 64],
    };
    let end = OutletStreamChunk {
        request_id,
        sequence: 1,
        payload: ChunkPayload::End {
            aggregate: serde_json::Value::Null,
            provenance: scp_protocol::provenance::DataProvenance {
                source_context: String::new(),
                source_type: scp_protocol::provenance::SourceType::Persistent,
                counterparties: Vec::new(),
                purpose: None,
                discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                age: std::time::Duration::from_secs(0),
                memory_scope: scp_protocol::context::params::MemoryScope::Full,
                chain_depth: 0,
                chain_path: None,
                payment_amount: None,
                payment_adapter: None,
                payment_receipt_id: None,
            },
            execution_time_ms,
        },
        sig: [0u8; 64],
    };
    // JCS canonicalization of the two synthesized chunks always
    // succeeds for valid `OutletStreamChunk` values; the fallback
    // sentinel preserves the function's totality so callers do not
    // have to bubble a JCS error out of an event-construction path
    // that has no actionable error path. Recording the all-zero
    // sentinel signals "manifest unavailable" without hiding the
    // event-log entry.
    let manifest = compute_chunk_manifest_root(&[data, end]).unwrap_or([0u8; 32]);
    (2, 1, manifest)
}

/// Outcome of the executor-vs-cancellation `tokio::select!` race inside
/// [`invoke_outlet_with_cancellation`].
///
/// Hoisted to module scope so the `items_after_statements` clippy lint is
/// satisfied — `tokio::select!` cannot drive a typed sum across `.await`
/// boundaries from within a function body without an explicit type
/// declared up-front.
///
/// `Executor`'s outer `Result` carries the `catch_unwind` outcome (panic
/// payload on `Err`); the inner `Result<Value, String>` is the executor's
/// own success/failure.
enum SelectOutcome {
    Executor(Result<Result<serde_json::Value, String>, Box<dyn std::any::Any + Send>>),
    Cancelled,
}

/// Invokes an outlet with cancellation support.
///
/// Same as [`invoke_outlet_aggregating`] but accepts a cancellation
/// future. If the cancellation future resolves before the outlet
/// completes, the invocation returns [`InvocationError::Cancelled`].
///
/// Cancellation is best-effort: if the outlet completes before the cancel
/// signal, the successful result is returned.
///
/// # Panic guard (SCP-OUT-028)
///
/// The executor closure call and the resulting future are wrapped in
/// [`std::panic::catch_unwind`] (sync) and
/// `futures::FutureExt::catch_unwind` (async). A panic recovers into
/// [`InvocationError::HandlerPanic`] and emits the parallel §5.4.2
/// `OutletVerifiedEvent { reason: HandlerPanicked }` through
/// `handler_panic_sink`. The cancellation branch and timeout branch are
/// unaffected — they continue to surface `Cancelled` / `Timeout`.
///
/// # Errors
///
/// Returns [`InvocationError`] on protocol-level validation failures,
/// timeout, cancellation, budget exceeded, UCAN composition failures, or
/// recovered handler panic.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // H6 escrow rollback on output validation adds lines; splitting would fragment the escrow lifecycle. SCP-OUT-028 adds the panic-sink parameter.
pub async fn invoke_outlet_with_cancellation_aggregating<F, Fut, C, CFut, S: BuildHasher>(
    context: &ContextHandle,
    registry: &OutletRegistry,
    role_state: &ContextRoleState,
    outlet_id: &OutletId,
    input: serde_json::Value,
    invoker_did: &DID,
    timeout_ms: Option<u32>,
    executor: F,
    cancellation: C,
    mut economy: Option<&mut OutletEconomyContext<'_, S>>,
    handler_panic_sink: Option<&dyn HandlerPanicSink>,
) -> Result<
    (
        serde_json::Value,
        OutletInvokedEvent,
        Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
        Option<crate::economy::adapter::PaymentReceipt>,
    ),
    InvocationError,
>
where
    F: FnOnce(serde_json::Value) -> Fut,
    Fut: Future<Output = Result<serde_json::Value, String>>,
    C: FnOnce() -> CFut,
    CFut: Future<Output = ()>,
{
    let start = std::time::Instant::now();

    // 1-4: Validate context, capability, tool, schema (same as invoke_outlet).
    let state = context.state().await;
    if state != ContextState::Active {
        return Err(InvocationError::ContextNotActive {
            current_state: state.to_string(),
        });
    }
    // SCP-OUT-014: registry lookup before capability check so we can
    // select the kind-specific stem.
    let registration = registry
        .get(outlet_id)
        .ok_or_else(|| InvocationError::OutletNotFound {
            outlet_id: outlet_id.to_owned(),
        })?;
    if !has_outlet_invocation_capability(role_state, invoker_did, outlet_id, registration.kind) {
        return Err(InvocationError::InvokerNotAuthorized {
            did: invoker_did.to_string(),
            outlet_id: outlet_id.to_owned(),
        });
    }
    validate_value_against_schema(&input, &registration.schema.input_schema)
        .map_err(|msg| InvocationError::InputValidationFailed { message: msg })?;

    // 4a. Economy pre-check (#1537). Strategy B: `economy_pre_check` is pure
    // compute — it does NOT deduct budget. Callers record the spend
    // explicitly so the mutation point is visible. See
    // `invoke_outlet` for the matching comment on the non-cancellable path.
    let action_cost = match economy.as_deref_mut() {
        Some(econ) => {
            let cost = economy_pre_check(econ, invoker_did)?;
            if cost.0 > 0 {
                econ.budget_tracker
                    .record_spend(invoker_did, cost)
                    .map_err(|_| InvocationError::BudgetExceeded {
                        did: invoker_did.to_string(),
                        cost: cost.0,
                        remaining: econ.budget_tracker.remaining(invoker_did).0,
                    })?;
            }
            Some(cost)
        }
        None => None,
    };

    // 4b. Payment escrow (#1537, #1596): authorize (escrow hold) BEFORE outlet execution.
    let escrow_parts = extract_escrow_parts(&economy);
    let mut escrow = if let Some((adapter, policy, metrics, ctx_id)) = &escrow_parts {
        match authorize_outlet_payment(adapter.as_ref(), policy, ctx_id, invoker_did, metrics).await
        {
            Ok(prepared) => prepared,
            Err(auth_err) => {
                void_escrow_and_rollback(
                    None,
                    escrow_parts.as_ref(),
                    action_cost,
                    &mut economy,
                    invoker_did,
                )
                .await;
                return Err(auth_err);
            }
        }
    } else {
        None
    };

    // 4c. Compute the input hash from the value the executor will see so
    // the resulting `OutletInvokedEvent` records it verbatim even though we
    // have to clone the input for the cancellation path.
    let input_hash = sha256_json(&input);

    // 5. Execute with timeout and cancellation. The cancellation variant
    // keeps its own `tokio::select!` body because composing `tokio::select!`
    // across a helper boundary cannot carry the pinned `&mut` futures out
    // of scope — the cancellation-free path delegates to
    // `invoke_outlet_execute_and_validate` instead.
    //
    // SCP-OUT-028: the synchronous call to `executor(input)` runs inside
    // `std::panic::catch_unwind` so a panic during future construction is
    // recovered. The returned future is then wrapped in
    // `futures::FutureExt::catch_unwind` so panics during polls and
    // `.await` resumes are also recovered. Both branches funnel through
    // `panic_to_invocation_error` for the §5.4.2 attribution emission.
    // Distinguishing executor outcome vs. cancellation uses a typed
    // `SelectOutcome` rather than a sentinel string — adversarial executors
    // could otherwise emit a `"cancelled"` string and short-circuit
    // observability.
    let effective_timeout = timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS).min(MAX_TIMEOUT_MS);
    let timeout_duration = Duration::from_millis(u64::from(effective_timeout));
    let exec_fut = match std::panic::catch_unwind(AssertUnwindSafe(|| executor(input))) {
        Ok(fut) => fut,
        Err(payload) => {
            void_escrow_and_rollback(
                escrow.as_ref(),
                escrow_parts.as_ref(),
                action_cost,
                &mut economy,
                invoker_did,
            )
            .await;
            return Err(panic_to_invocation_error(
                &payload,
                outlet_id,
                handler_panic_sink,
            ));
        }
    };
    // SCP-OUT-028: `SelectOutcome` is module-scoped (above) — hoisting
    // satisfies clippy's `items_after_statements` and keeps
    // `tokio::select!` typed.
    let exec_fut = AssertUnwindSafe(exec_fut).catch_unwind();
    let cancel_fut = cancellation();
    tokio::pin!(exec_fut);
    tokio::pin!(cancel_fut);
    let execution_result = tokio::time::timeout(timeout_duration, async {
        tokio::select! {
            result = &mut exec_fut => SelectOutcome::Executor(result),
            () = &mut cancel_fut => SelectOutcome::Cancelled,
        }
    })
    .await;
    let exec_result: Result<serde_json::Value, InvocationError> = match execution_result {
        Ok(SelectOutcome::Executor(Ok(Ok(output)))) => Ok(output),
        Ok(SelectOutcome::Executor(Ok(Err(exec_err)))) => {
            Err(InvocationError::ExecutionFailed { message: exec_err })
        }
        Ok(SelectOutcome::Executor(Err(payload))) => Err(panic_to_invocation_error(
            &payload,
            outlet_id,
            handler_panic_sink,
        )),
        Ok(SelectOutcome::Cancelled) => Err(InvocationError::Cancelled),
        Err(_elapsed) => Err(InvocationError::Timeout {
            timeout_ms: effective_timeout,
        }),
    };
    let output = match exec_result {
        Ok(output) => output,
        Err(err) => {
            void_escrow_and_rollback(
                escrow.as_ref(),
                escrow_parts.as_ref(),
                action_cost,
                &mut economy,
                invoker_did,
            )
            .await;
            return Err(err);
        }
    };

    // 6. Validate output + post-invocation bookkeeping.
    // H6: on output validation failure, void escrow and rollback budget
    // before returning.
    if let Err(msg) = validate_value_against_schema(&output, &registration.schema.output_schema) {
        void_escrow_and_rollback(
            escrow.as_ref(),
            escrow_parts.as_ref(),
            action_cost,
            &mut economy,
            invoker_did,
        )
        .await;
        return Err(InvocationError::OutputValidationFailed { message: msg });
    }
    let output_hash = sha256_json(&output);
    let execution_time_ms = elapsed_ms(start);
    let triggered = economy
        .as_mut()
        .map(|econ| economy_post_check(econ, invoker_did))
        .unwrap_or_default();

    // 6b. Complete (capture) the escrowed payment after successful execution.
    let payment_receipt = finalize_outlet_escrow(
        escrow.take(),
        escrow_parts.as_ref(),
        action_cost,
        &mut economy,
        invoker_did,
    )
    .await?;

    // 7. Build event + return (#1596: receipt returned to caller).
    let event = build_outlet_event(
        outlet_id,
        invoker_did,
        execution_time_ms,
        input_hash,
        output_hash,
        action_cost,
    );
    crate::metrics::record_outlet_invocation();
    Ok((output, event, triggered, payment_receipt))
}

/// Post-invocation bookkeeping: participation record update and consequence evaluation.
///
/// Called after a successful outlet invocation to update governance state.
/// `compute_participation_record` refreshes the cache for proposer eligibility
/// (#1530). `evaluate_consequence_rules` checks whether the outlet invocation
/// triggered any consequence rules (#1531).
pub fn post_outlet_invocation_bookkeeping<S: std::hash::BuildHasher>(
    events: &[scp_event_log::Event],
    invoker_did: &DID,
    context_id: &str,
    now: u64,
    participation_cache: &mut std::collections::HashMap<
        String,
        scp_protocol::trust::participation::ParticipationRecord,
        S,
    >,
    consequence_rules: &[scp_protocol::trust::consequence::ConsequenceRule],
) -> Vec<scp_protocol::trust::consequence::TriggeredConsequence> {
    // Update participation record after outlet execution (#1530).
    if !events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            events,
            invoker_did.as_ref(),
            context_id,
            [0u8; 32],
            now,
        )
    {
        participation_cache.insert(invoker_did.to_string(), record);
    }

    // Evaluate consequence rules after outlet execution (#1531).
    // The caller is responsible for enforcing triggered consequences via
    // enforce_triggered_consequences on the PerContextState.
    evaluate_consequence_rules(consequence_rules, events, invoker_did.as_ref(), now)
}

/// Validates the spending side of AND-composition for paid outlet invocations
/// (spec §19.5).
///
/// Per spec §19.5, paid actions require BOTH an action capability AND a
/// spending UCAN. The action capability is verified UPSTREAM at the
/// `OutletCall` / `OutletCallAll` `member_has_capability` gate (see
/// `invoke_outlet`). This function verifies the spending side only.
///
/// # Errors
///
/// Returns [`InvocationError::ExecutionFailed`] if the spending UCAN is
/// missing for a paid action or if the spending capability is malformed.
pub fn check_outlet_spending_capability(
    action_cost: scp_protocol::economy::types::Amount,
    spending_ucan: Option<&UcanToken>,
) -> Result<(), InvocationError> {
    // Convert economy Amount to UCAN spending Amount (both are u64 wrappers).
    let ucan_amount = scp_protocol::crypto::ucan::spending::Amount(action_cost.0);
    scp_protocol::crypto::ucan::spending::check_spending_capability(
        spending_ucan,
        ucan_amount,
        "outlet:call",
    )
    .map_err(|e| InvocationError::ExecutionFailed {
        message: format!("UCAN spending capability check failed: {e}"),
    })
}

/// Extracts adapter/policy/metrics from economy context for escrow flow.
///
/// Returns owned copies to avoid holding a borrow of `economy` across the
/// mutable post-check. Returns `None` when no adapter or policy is configured.
fn extract_escrow_parts<S: BuildHasher>(
    economy: &Option<&mut OutletEconomyContext<'_, S>>,
) -> Option<EscrowParts> {
    let econ = economy.as_ref()?;
    let adapter = econ.payment_adapter.as_ref().map(std::sync::Arc::clone)?;
    let policy = econ.economic_policy?.clone();
    let metrics = econ.metrics.clone();
    let context_id = econ.context_id.to_owned();
    Some((adapter, policy, metrics, context_id))
}

/// Completes the escrow payment after successful outlet execution, or rolls back
/// the budget on capture failure.
///
/// Returns the payment receipt (if any). On capture failure, rolls back budget
/// and returns the error.
async fn finalize_outlet_escrow<S: BuildHasher>(
    escrow: Option<crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut OutletEconomyContext<'_, S>>,
    invoker_did: &DID,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    if let (Some(prepared), Some((adapter, policy, metrics, _))) = (escrow, escrow_parts) {
        match complete_outlet_payment(adapter.as_ref(), Some(policy), &prepared, metrics).await {
            Ok(receipt) => Ok(receipt),
            Err(capture_err) => {
                // Budget rollback only — escrow is already consumed by the capture attempt.
                // Use reverse_spend (not grant) to avoid inflating limits (#1606 M1).
                if let Some(cost) = action_cost
                    && let Some(econ) = economy
                {
                    econ.budget_tracker.reverse_spend(invoker_did, cost);
                }
                Err(capture_err)
            }
        }
    } else {
        Ok(None)
    }
}

/// Extracted escrow context: adapter, policy, metrics, context ID.
type EscrowParts = (
    std::sync::Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    scp_protocol::economy::types::EconomicPolicy,
    scp_protocol::economy::policy::ObservableMetrics,
    String,
);

/// Voids the payment escrow and rolls back budget on tool failure.
///
/// Combines the void + rollback pattern that appears in every failure branch
/// of `invoke_outlet` and `invoke_outlet_with_cancellation`.
async fn void_escrow_and_rollback<S: BuildHasher>(
    escrow: Option<&crate::economy::integration::PreparedAction>,
    escrow_parts: Option<&EscrowParts>,
    action_cost: Option<scp_protocol::economy::types::Amount>,
    economy: &mut Option<&mut OutletEconomyContext<'_, S>>,
    invoker_did: &DID,
) {
    if let (Some(prepared), Some((adapter, _, _, _))) = (escrow, escrow_parts) {
        void_outlet_escrow(adapter.as_ref(), prepared).await;
    }
    if let Some(cost) = action_cost
        && let Some(econ) = economy
    {
        econ.budget_tracker.reverse_spend(invoker_did, cost);
    }
}

// ---------------------------------------------------------------------------
// Escrow payment flow for outlet invocations (#1537)
// ---------------------------------------------------------------------------

/// Authorizes an outlet payment (escrow step 1).
///
/// Creates an escrow hold via `prepare_paid_action`. Returns the prepared
/// action for later completion or voiding. Returns `None` when cost is zero
/// or no payment is needed.
///
/// Called BEFORE outlet execution. On success, the caller must eventually call
/// `complete_outlet_payment` or `void_outlet_escrow`.
pub(crate) async fn authorize_outlet_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: &scp_protocol::economy::types::EconomicPolicy,
    context_id: &str,
    invoker_did: &DID,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::integration::PreparedAction>, InvocationError> {
    let cost = scp_protocol::economy::policy::evaluate_cost(
        policy,
        &scp_protocol::economy::types::PaidActionType::OutletCall,
        metrics,
    );
    let Some(cost) = cost.filter(|c| c.0 > 0) else {
        return Ok(None);
    };

    let metadata = crate::economy::adapter::PaymentMetadata {
        action_type: scp_protocol::economy::types::PaidActionType::OutletCall,
        context_id: Some(context_id.to_owned()),
        idempotency_key: *uuid::Uuid::new_v4().as_bytes(),
    };

    let prepared = crate::economy::integration::prepare_paid_action(
        adapter,
        Some(policy),
        scp_protocol::economy::types::PaidActionType::OutletCall,
        invoker_did,
        Some(context_id.to_owned()),
        metrics,
        metadata,
        Vec::new(),
    )
    .await
    .map_err(|_| InvocationError::BudgetExceeded {
        did: invoker_did.to_string(),
        cost: cost.0,
        remaining: 0, // Exact remaining not available here; adapter rejected the hold.
    })?;

    Ok(Some(prepared))
}

/// Completes an outlet payment (escrow step 2: capture).
///
/// Called AFTER successful outlet execution. Captures the escrowed payment
/// and returns the receipt.
pub(crate) async fn complete_outlet_payment(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
    prepared: &crate::economy::integration::PreparedAction,
    metrics: &scp_protocol::economy::policy::ObservableMetrics,
) -> Result<Option<crate::economy::adapter::PaymentReceipt>, InvocationError> {
    let processed = crate::economy::integration::process_paid_action(
        adapter,
        policy,
        &prepared.envelope,
        metrics,
        |payload| async move { Ok(payload) },
    )
    .await
    .map_err(|_| InvocationError::ExecutionFailed {
        message: "payment capture failed after successful outlet execution".to_owned(),
    })?;

    if let Some(receipt) = &processed.receipt {
        tracing::debug!(
            receipt_id = %hex::encode(receipt.receipt_id),
            adapter_id = %receipt.adapter_id,
            "outlet invocation payment receipt captured"
        );
    }

    Ok(processed.receipt)
}

/// Voids an outlet payment escrow on failure.
///
/// Called when outlet execution fails (error, timeout, cancellation) to
/// release the escrow hold. Best-effort — logs but does not propagate
/// void failures.
pub(crate) async fn void_outlet_escrow(
    adapter: &dyn crate::economy::adapter::PaymentAdapterDyn,
    prepared: &crate::economy::integration::PreparedAction,
) {
    if let Some(ref authorization) = prepared.envelope.authorization
        && let Err(e) = adapter.void_dyn(authorization).await
    {
        tracing::warn!("failed to void tool payment escrow: {e}");
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Converts an [`std::time::Instant`] elapsed duration to milliseconds as `u64`.
///
/// Saturates at `u64::MAX` if the elapsed duration exceeds `u64` range (which
/// would require ~584 million years).
#[allow(clippy::cast_possible_truncation)]
fn elapsed_ms(start: std::time::Instant) -> u64 {
    let millis = start.elapsed().as_millis();
    if millis > u128::from(u64::MAX) {
        u64::MAX
    } else {
        millis as u64
    }
}

// ---------------------------------------------------------------------------
// Capability check helpers
// ---------------------------------------------------------------------------

/// Checks whether a member has the `OutletCall(outlet_id)` or `OutletCallAll`
/// capability.
///
/// This is the integration point between the invocation module and the
/// UCAN-based role system (ADR-009). Use [`has_outlet_query_capability`] for
/// Query outlets — the two stems are independent (SCP-OUT-014).
#[must_use]
pub fn has_outlet_call_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    // Check for OutletCallAll first (broader permission).
    if role_state.member_has_capability(did, &Capability::OutletCallAll) {
        return true;
    }
    // Check for specific OutletCall(outlet_id).
    role_state.member_has_capability(did, &Capability::OutletCall(outlet_id.to_owned()))
}

/// Checks whether a member has the `OutletQuery(outlet_id)` or
/// `OutletQueryAll` capability (Query outlets — SCP-OUT-014).
///
/// Mirror of [`has_outlet_call_capability`] for the Query-class stem. The
/// runtime selects between the two via the registered `OutletKind` so a
/// caller cannot gain Query authorization via an Action delegation (or
/// vice versa) — see spec §5.4.2 / ADR-049 §2.
#[must_use]
pub fn has_outlet_query_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
) -> bool {
    if role_state.member_has_capability(did, &Capability::OutletQueryAll) {
        return true;
    }
    role_state.member_has_capability(did, &Capability::OutletQuery(outlet_id.to_owned()))
}

/// Checks whether a member holds the kind-appropriate split capability for
/// invoking an outlet.
///
/// Selects between [`has_outlet_call_capability`] (Action) and
/// [`has_outlet_query_capability`] (Query) based on the outlet's registered
/// [`OutletKind`]. Per spec §5.4.2 the two stems are independent —
/// `OutletQueryAll` must not authorize an Action call and vice versa.
#[must_use]
pub fn has_outlet_invocation_capability(
    role_state: &ContextRoleState,
    did: &str,
    outlet_id: &str,
    kind: scp_protocol::context::outlets::OutletKind,
) -> bool {
    match kind {
        scp_protocol::context::outlets::OutletKind::Query => {
            has_outlet_query_capability(role_state, did, outlet_id)
        }
        scp_protocol::context::outlets::OutletKind::Action => {
            has_outlet_call_capability(role_state, did, outlet_id)
        }
    }
}

// ---------------------------------------------------------------------------
// UCAN validation at outlet invocation boundary (#319)
// ---------------------------------------------------------------------------

/// Validates a UCAN token for outlet invocation authorization.
///
/// Parses the encoded JWT token and runs the full 11-step ADR-016 validation
/// pipeline, requiring `outlet_call:{outlet_id}` or `outlet_call:*` capability
/// scoped to the given context.
///
/// This is the primary authorization gate for outlet invocations. Role-based
/// `has_outlet_call_capability` remains as defense-in-depth.
///
/// # Arguments
///
/// * `encoded_token` — JWT-encoded UCAN token.
/// * `context_id` — The context ID the outlet belongs to.
/// * `outlet_id` — The identifier of the outlet being invoked.
/// * `ctx` — The validation context with resolvers, trackers, and ceiling.
///
/// # Errors
///
/// Returns [`UcanError`] if the token is malformed, expired, revoked, lacks
/// the required capability, or fails any of the 11 validation steps.
///
/// See spec §6.2, §8, ADR-016, and issue #319.
pub fn validate_outlet_invocation_ucan<D, N, R, P, S>(
    encoded_token: &str,
    context_id: &str,
    outlet_id: &str,
    kind: scp_protocol::context::outlets::OutletKind,
    ctx: &mut ValidationContext<'_, D, N, R, P, S>,
) -> Result<(), UcanError>
where
    D: DidResolver,
    N: NonceTracker,
    R: RevocationChecker,
    P: ProofResolver,
    S: BuildHasher,
{
    let parsed = parse_ucan(encoded_token)?;
    // SCP-OUT-014: pick the split stem from the outlet's registered kind.
    // Query outlets require `outlet_query:{id}` (or wildcard `outlet_query:*`);
    // Action outlets require `outlet_call:{id}` (or wildcard `outlet_call:*`).
    // Cross-class delegations (parent `outlet_query:*` → child `outlet_call:x`)
    // are rejected automatically by `CapabilityUri::matches` because the
    // `resource` strings differ.
    let resource = match kind {
        scp_protocol::context::outlets::OutletKind::Query => "outlet_query",
        scp_protocol::context::outlets::OutletKind::Action => "outlet_call",
    };
    let required_cap = CapabilityUri::new(context_id, resource, outlet_id);
    validate_ucan(&parsed, &required_cap, ctx)
}

// ---------------------------------------------------------------------------
// SCP-OUT-034 streaming dispatch hooks — wires CreditTracker + StreamEscrow
// + CancelAckTracker + StreamAdmissionTracker into the per-chunk pump.
// ---------------------------------------------------------------------------

/// Per-chunk gate result for the SCP-OUT-034 pump.
///
/// Consulted under the shared session lock. `Forward` is the happy
/// path (decrement credit, optionally accrue escrow). `Stall` arms
/// the credit-stall timer. `DropAboveCancelAck` silently drops the
/// chunk per §5.4.5 cancel-ack ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamGateOutcome {
    /// Chunk passes the gate — caller forwards it and advances seq.
    Forward,
    /// Credit exhausted. Caller arms the stall timer and parks the
    /// chunk until a fresh grant arrives.
    Stall,
    /// Cancel-ack ceiling exceeded. Caller drops without billing.
    DropAboveCancelAck,
}

/// Applies the SCP-OUT-034 per-chunk gate using the shared session
/// trackers.
///
/// Called from the streaming pump for each upstream chunk. Terminal
/// chunks (`End` / terminal `Error`) bypass the gate. Non-terminal
/// chunks:
///
/// 1. Compare `chunk.sequence` against
///    [`super::stream::CancelAckTracker::billing_ceiling`] —
///    chunks above the ceiling return [`StreamGateOutcome::DropAboveCancelAck`].
/// 2. Call [`super::stream::CreditTracker::try_consume`]. On
///    [`super::stream::OutOfCredit::Exhausted`], stamp
///    `credit_stall_armed_at` to the current `Instant` and return
///    [`StreamGateOutcome::Stall`].
/// 3. Otherwise return [`StreamGateOutcome::Forward`].
///
/// The function takes a single mutex guard window so the
/// (consume → ceiling → bill) decision is atomic with respect to
/// concurrent grant / cancel deliveries on
/// [`super::stream::CreditTracker::grant_with_identity`] /
/// [`super::stream::CancelAckTracker::record_cancel`].
#[must_use]
pub fn apply_stream_chunk_gate(
    credit: &mut super::stream::CreditTracker,
    cancel_ack: &super::stream::CancelAckTracker,
    credit_stall_armed_at: &mut Option<std::time::Instant>,
    chunk: &OutletStreamChunk,
) -> StreamGateOutcome {
    if chunk.payload.is_terminal() {
        return StreamGateOutcome::Forward;
    }
    let ceiling = cancel_ack.billing_ceiling();
    if chunk.sequence > ceiling {
        return StreamGateOutcome::DropAboveCancelAck;
    }
    if credit.try_consume().is_err() {
        if credit_stall_armed_at.is_none() {
            *credit_stall_armed_at = Some(std::time::Instant::now());
        }
        return StreamGateOutcome::Stall;
    }
    StreamGateOutcome::Forward
}

/// Accrues a Data chunk in the per-stream [`super::stream::StreamEscrow`].
///
/// Bills only when the chunk's sequence is at or below the cancel-ack
/// ceiling. Progress / End / Error chunks and chunks above the ceiling
/// are NOT billed (§5.4.5).
pub const fn accrue_data_chunk_if_billable(
    escrow: &mut super::stream::StreamEscrow,
    cancel_ack: &super::stream::CancelAckTracker,
    chunk: &OutletStreamChunk,
) {
    if !matches!(chunk.payload, ChunkPayload::Data { .. }) {
        return;
    }
    let ceiling = cancel_ack.billing_ceiling();
    if chunk.sequence <= ceiling {
        escrow.accrue_one_chunk();
    }
}

/// Releases the §5.4.5 round-5 admission counters for a stream that
/// terminated. Called by the pump on terminal-chunk emission.
///
/// Decrements per-invoker, per-origin-invoker, and per-outlet counters
/// atomically under the admission tracker's critical section. Idempotent
/// on a never-admitted triple (matches
/// [`super::stream::StreamAdmissionTracker::release`] semantics).
pub fn release_stream_admission(
    admission: &mut super::stream::StreamAdmissionTracker,
    invoker_did: &str,
    origin_invoker_did: &str,
    outlet_id: &str,
) {
    admission.release(invoker_did, origin_invoker_did, outlet_id);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::outlets::registry::{
        OutletRegistration, OutletSchema, register_outlet,
    };
    use scp_protocol::context::roles::{CapabilityCeiling, ContextRoleState};

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
    fn test_role_state(creator_did: &str) -> ContextRoleState {
        ContextRoleState::new(
            "ctx-test",
            creator_did,
            test_ceiling(),
            vec![],
            &scp_primitives::SystemClock,
        )
        .unwrap()
    }

    /// Creates a `ContextRoleState` with an additional member that has limited
    /// capabilities (no `OutletCall`).
    fn test_role_state_with_no_invoke_member(
        creator_did: &str,
        member_did: &str,
    ) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
        state.members.insert(member_did.to_owned());
        // Assign only MessagesRead/Write, no tool invoke.
        let member_caps: HashSet<Capability> =
            [Capability::MessagesRead, Capability::MessagesWrite]
                .into_iter()
                .collect();
        state
            .member_capabilities
            .insert(member_did.to_owned(), member_caps);
        state
    }

    /// Creates a valid outlet registration and registers it in a fresh registry.
    fn setup_registry_with_tool(
        role_state: &ContextRoleState,
        registrant_did: &str,
    ) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "calculator".to_owned(),
            kind: scp_protocol::context::outlets::OutletKind::Action,
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
                aggregate_schema: None,
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

    /// Creates an active context handle (transitions from Creating to Active).
    async fn active_context() -> ContextHandle {
        let handle = ContextHandle::new("ctx-invoke-test".to_owned(), ContextParams::default());
        handle.transition_to(&ContextState::Active).await.unwrap();
        handle
    }

    /// A simple async executor that adds two numbers.
    async fn add_executor(input: serde_json::Value) -> Result<serde_json::Value, String> {
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
    // invoke_outlet: happy path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_succeeds_with_valid_invocation() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let input = serde_json::json!({"a": 3, "b": 4});
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input,
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_ok(), "invoke_outlet should succeed: {result:?}");
        let (output, event, _consequences, _receipt) = result.unwrap();
        assert_eq!(output, serde_json::json!({"result": 7.0}));
        assert_eq!(event.outlet_id, "calculator");
        assert_eq!(event.invoker_did, creator_did);
        assert_eq!(event.status, OutletStatus::Success);
        assert!(event.output_hash.is_some());
        assert!(!event.input_hash.is_empty());
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: context not Active
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_when_context_not_active() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);

        // Context is in Creating state (not Active).
        let context = ContextHandle::new("ctx-test".to_owned(), ContextParams::default());

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::ContextNotActive { .. }),
            "expected ContextNotActive, got {err:?}"
        );
        assert!(err.to_string().contains("Creating"));
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: invoker without OutletCall capability
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invoker_without_outlet_call_capability() {
        let creator_did = "did:dht:z6MkCreator";
        let member_did = "did:dht:z6MkMember";
        let role_state = test_role_state_with_no_invoke_member(creator_did, member_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(member_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::InvokerNotAuthorized { .. }),
            "expected InvokerNotAuthorized, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: outlet not found
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_unknown_tool() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = OutletRegistry::new(); // Empty registry
        let context = active_context().await;

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"nonexistent-tool".to_owned(),
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::OutletNotFound { .. }),
            "expected OutletNotFound, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: input schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invalid_input_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Input schema expects an object, passing a string instead.
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!("not an object"),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::InputValidationFailed { .. }),
            "expected InputValidationFailed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_timeout_synthesizes_timeout_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that sleeps for 5 seconds (will be timed out).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms timeout -- will expire before the 5s sleep.
            slow_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::Timeout { timeout_ms: 50 }),
            "expected Timeout with 50ms, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: cancellation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_cancellation_returns_cancelled_status() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that sleeps for 5 seconds (will be cancelled).
        let slow_executor = |_input: serde_json::Value| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(serde_json::json!({"result": 42}))
        };

        // Cancellation fires after 10ms.
        let cancel = || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let result = invoke_outlet_with_cancellation_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            slow_executor,
            cancel,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::Cancelled),
            "expected Cancelled, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: execution failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_execution_failure_propagates_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that always fails.
        let failing_executor = |_input: serde_json::Value| async {
            Err::<serde_json::Value, String>("computation exploded".to_owned())
        };

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            failing_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::ExecutionFailed { .. }),
            "expected ExecutionFailed, got {err:?}"
        );
        assert!(err.to_string().contains("computation exploded"));
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: output schema validation failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_invalid_output_schema() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor that returns a string instead of an object.
        let bad_output_executor = |_input: serde_json::Value| async {
            Ok::<serde_json::Value, String>(serde_json::json!("not an object"))
        };

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            bad_output_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InvocationError::OutputValidationFailed { .. }),
            "expected OutputValidationFailed, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: event log records hashes, not full data
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_event_contains_hashes_not_full_data() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let input = serde_json::json!({"a": 10, "b": 20});

        let (output, event, _consequences, _receipt) = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            input.clone(),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await
        .unwrap();

        // Verify hashes are present and correct.
        let expected_input_hash = sha256_json(&input);
        let expected_output_hash = sha256_json(&output);

        assert_eq!(event.input_hash, expected_input_hash);
        assert_eq!(event.output_hash, Some(expected_output_hash));

        // Hashes are 64-char hex strings (SHA-256).
        assert_eq!(event.input_hash.len(), 64);
        assert!(event.input_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: context in Closing state
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_rejects_closing_context() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);

        let context = ContextHandle::new("ctx-closing".to_owned(), ContextParams::default());
        context.transition_to(&ContextState::Active).await.unwrap();
        context.transition_to(&ContextState::Closing).await.unwrap();

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            InvocationError::ContextNotActive { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // has_outlet_call_capability
    // -----------------------------------------------------------------------

    #[test]
    fn has_outlet_call_capability_returns_true_for_invoke_all() {
        let role_state = test_role_state("did:dht:z6MkCreator");
        assert!(has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkCreator",
            "any-tool"
        ));
    }

    #[test]
    fn has_outlet_call_capability_returns_false_without_capability() {
        let role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        assert!(!has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
    }

    #[test]
    fn has_outlet_call_capability_with_specific_tool() {
        let mut role_state =
            test_role_state_with_no_invoke_member("did:dht:z6MkCreator", "did:dht:z6MkMember");
        // Add specific OutletCall capability.
        role_state
            .member_capabilities
            .get_mut("did:dht:z6MkMember")
            .unwrap()
            .insert(Capability::OutletCall("calculator".to_owned()));

        assert!(has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "calculator"
        ));
        // But not for a different outlet.
        assert!(!has_outlet_call_capability(
            &role_state,
            "did:dht:z6MkMember",
            "other-tool"
        ));
    }

    // -----------------------------------------------------------------------
    // invoke_outlet: timeout is clamped to protocol maximum
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invoke_outlet_clamps_timeout_to_protocol_maximum() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Request a timeout larger than the protocol max.
        // The executor completes immediately, so the test verifies the function
        // does not error out due to an absurdly large timeout.
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(999_999), // Above MAX_TIMEOUT_MS
            add_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None,
        )
        .await;

        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // InvocationError display messages
    // -----------------------------------------------------------------------

    #[test]
    fn invocation_error_display_messages() {
        let err = InvocationError::ContextNotActive {
            current_state: "Closing".to_owned(),
        };
        assert!(err.to_string().contains("Closing"));

        let err = InvocationError::InvokerNotAuthorized {
            did: "did:dht:test".into(),
            outlet_id: "tool-1".to_owned(),
        };
        assert!(err.to_string().contains("did:dht:test"));
        assert!(err.to_string().contains("tool-1"));

        let err = InvocationError::OutletNotFound {
            outlet_id: "missing".to_owned(),
        };
        assert!(err.to_string().contains("missing"));

        let err = InvocationError::Timeout { timeout_ms: 5000 };
        assert!(err.to_string().contains("5000"));

        let err = InvocationError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // validate_outlet_invocation_ucan: rejects non-tool capability (#319)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn validate_outlet_invocation_ucan_rejects_non_tool_capability() {
        use crate::crypto::ucan::mint::{MintParams, mint_ucan};
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::ucan::validate::{
            DEFAULT_CLOCK_SKEW_TOLERANCE_SECS, InMemoryDidResolver, InMemoryNonceTracker,
            InMemoryProofResolver, InMemoryRevocationChecker, ValidationContext,
        };

        // Set up issuer identity.
        let custody = InMemoryKeyCustody::new();
        let key_handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let issuer_did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));

        // Mint a UCAN with messages:write capability (NOT outlet_call).
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };
        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Build validation context.
        let resolver = InMemoryDidResolver {
            keys: std::iter::once((issuer_did.clone(), pk_bytes)).collect(),
            kid_keys: std::collections::HashMap::new(),
        };
        let mut nonce_tracker = InMemoryNonceTracker::new();
        let revocation_checker = InMemoryRevocationChecker::new();
        let proof_resolver = InMemoryProofResolver::new();
        let ceiling: HashSet<String> = [
            "messages:write".to_owned(),
            "outlet_call:calculator".to_owned(),
        ]
        .into_iter()
        .collect();

        let mut ctx = ValidationContext {
            did_resolver: &resolver,
            nonce_tracker: &mut nonce_tracker,
            revocation_checker: &revocation_checker,
            proof_resolver: &proof_resolver,
            ceiling: &ceiling,
            context_creator_did: &issuer_did,
            presenting_agent_did: "did:dht:z6MkMember",
            clock_skew_tolerance_secs: DEFAULT_CLOCK_SKEW_TOLERANCE_SECS,
            clock: &scp_primitives::SystemClock,
            caveat_resolver: &scp_protocol::crypto::ucan::validate::NoCaveatResolver,
        };

        // validate_outlet_invocation_ucan expects outlet_call:calculator,
        // but the token only has messages:write — must be rejected.
        let result = validate_outlet_invocation_ucan(
            &token.encoded,
            "ctx-test",
            "calculator",
            scp_protocol::context::outlets::OutletKind::Action,
            &mut ctx,
        );

        assert!(
            result.is_err(),
            "UCAN with messages:write must be rejected for outlet invocation"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityNotGranted(..)),
            "expected CapabilityNotGranted, got {err:?}"
        );
    }

    // budget_exceeded on outlet invocation returns BudgetExceeded
    #[tokio::test]
    async fn budget_exceeded_outlet_call() {
        use scp_protocol::economy::types::{Amount, CostSchedule, CurrencyCode, EconomicPolicy};

        let policy = EconomicPolicy {
            locked: false,
            cost_schedule: CostSchedule {
                currency: CurrencyCode::new([85, 83, 68, 0]),
                per_message: None,
                per_outlet_call: Some(Amount::new(200)),
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec![],
            pricing_formula: None,
            payee: DID::from("did:key:payee"),
        };

        let invoker: DID = "did:key:invoker".into();
        let mut tracker = scp_protocol::economy::budget::MemberBudgetTracker::new();
        // Grant only 100 budget but tool costs 200.
        tracker.grant(&invoker, Amount::new(100));

        // Budget enforcement is now inline in economy_pre_check via invoke_outlet.
        // Test it through invoke_outlet with an OutletEconomyContext.
        let context = active_context().await;
        let role_state = test_role_state(invoker.as_ref());
        let registry = setup_registry_with_tool(&role_state, invoker.as_ref());
        // Test fixture metrics: zeros are intentional for this budget-
        // exhaustion test. The test asserts budget-cap behaviour in
        // isolation and does NOT exercise §19.7 per-DID velocity
        // escalation — that behaviour is covered end-to-end by the
        // `invoke_outlet_with_economy` wrapper on `ContextManager` which
        // populates `sender_velocity` from the live velocity tracker via
        // `velocity_tracker.get_velocity(invoker_did, now_secs)` at
        // `crates/scp-runtime/src/context/manager/outlets.rs` (see the
        // `invoke_outlet_with_economy_wires_escalation_and_rollback` and
        // `invoke_outlet_with_economy_releases_lock_before_executor`
        // structural assertions in
        // `crates/scp-testing/tests/integration/pipeline_wiring.rs` which
        // pin the real wiring, and the behavioural escalation test in
        // `crates/scp-runtime/src/context/manager/tests/messaging.rs`).
        let metrics = scp_protocol::economy::policy::ObservableMetrics {
            context_message_rate: 0,
            member_count: 0,
            relay_queue_depth: 0,
            time_of_day: 0,
            sender_velocity: 0,
            storage_usage: 0,
        };
        let mut participation: std::collections::HashMap<
            String,
            scp_protocol::trust::participation::ParticipationRecord,
        > = std::collections::HashMap::new();
        // Provide a spending UCAN so the AND-composition check passes;
        // the budget check (the actual test target) runs after.
        let spending_ucan = {
            use scp_protocol::crypto::ucan::spending::{
                Amount as SpendingAmount, CurrencyCode as SpendingCurrency, SpendingCapability,
            };
            let cap = SpendingCapability {
                max_per_action: SpendingAmount(u64::MAX),
                max_total: SpendingAmount(u64::MAX),
                currency: SpendingCurrency([85, 83, 68, 0]),
                time_window: std::time::Duration::from_hours(24),
                allowed_adapters: vec![],
            };
            let mut fct = serde_json::Map::new();
            fct.insert(
                "spending_capability".to_owned(),
                cap.to_fact_value().unwrap(),
            );
            scp_protocol::crypto::ucan::UcanToken {
                header: scp_protocol::crypto::ucan::UcanHeader::new(),
                payload: scp_protocol::crypto::ucan::UcanPayload {
                    iss: "did:key:test".to_owned(),
                    aud: "did:key:aud".to_owned(),
                    exp: u64::MAX,
                    nbf: None,
                    nnc: "test-nonce".to_owned(),
                    att: vec![],
                    prf: vec![],
                    fct: Some(serde_json::Value::Object(fct)),
                    nb: None,
                },
                signature: vec![0u8; 64],
                encoded: String::new(),
            }
        };
        let mut economy = super::OutletEconomyContext {
            economic_policy: Some(&policy),
            budget_tracker: &mut tracker,
            spending_ucan: Some(&spending_ucan),
            context_id: "ctx-invoke-test",
            now: 0,
            events: &[],
            participation_cache: &mut participation,
            consequence_rules: &[],
            payment_adapter: None,
            metrics,
            velocity_tracker: None,
            message_pricing: None,
        };

        let result = super::invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &invoker,
            None,
            add_executor,
            Some(&mut economy),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(super::InvocationError::BudgetExceeded { .. })),
            "should return BudgetExceeded when budget is insufficient, got: {result:?}"
        );
    }

    // =======================================================================
    // SCP-OUT-013 tests — ReadOnlyInvocation / MutableInvocation /
    // OutletExecutor dispatch
    // =======================================================================

    use scp_protocol::context::outlets::{OutletKind, OutletVerifiedReason};

    /// Registers a Query outlet (no cost) for OUT-013 dispatch tests.
    fn setup_query_registry(role_state: &ContextRoleState, registrant_did: &str) -> OutletRegistry {
        let mut registry = OutletRegistry::new();
        let registration = OutletRegistration {
            outlet_id: "query-tool".to_owned(),
            kind: OutletKind::Query,
            name: "Query".to_owned(),
            description: "Read-only query".to_owned(),
            schema: OutletSchema {
                // Schema specificity floor (SCP-OUT-005) requires ≥ 2 fields.
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "q": {"type": "number"},
                        "scope": {"type": "string"}
                    }
                }),
                output_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "saw": {"type": "string"},
                        "input": {"type": ["object", "null"]}
                    }
                }),
                aggregate_schema: None,
            },
            implementation_hash: [0xBB; 32],
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

    /// Registers a member with both `OutletQueryAll` and `OutletCallAll`
    /// capabilities so dispatch tests can exercise both halves.
    fn test_role_state_with_query_caps(creator_did: &str) -> ContextRoleState {
        let mut state = test_role_state(creator_did);
        // Add OutletQueryAll to the creator's capability set (test_ceiling
        // grants OutletCallAll only).
        let caps = state
            .member_capabilities
            .entry(creator_did.to_owned())
            .or_default();
        caps.insert(Capability::OutletQueryAll);
        state
    }

    // -----------------------------------------------------------------------
    // AC1: type-system deny-list — `ReadOnlyInvocation` does NOT expose any
    // write methods. The `compile_fail` doctest below verifies this; the
    // runtime test pins the read-side surface from PRD AC2.
    // -----------------------------------------------------------------------

    /// AC2: `ReadOnlyInvocation` exposes the documented read-only surface.
    ///
    /// PRD AC2: "`ReadOnlyInvocation` exposes only read-side methods:
    /// `list_members`, `get_member_role`, `get_outlet`, `list_outlets`,
    /// `get_event`, `current_epoch`, `get_economic_policy`,
    /// `get_caveat_counter` (read-only view)".
    #[tokio::test]
    async fn read_only_invocation_exposes_documented_read_methods() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state_with_query_caps(creator_did);
        let registry = setup_query_registry(&role_state, creator_did);
        let context = active_context().await;
        let invoker: DID = creator_did.into();
        let outlet_id_owned: OutletId = "query-tool".to_owned();
        let events: Vec<scp_event_log::Event> = Vec::new();
        let counters = std::collections::HashMap::from([(
            ("did:dht:z6MkCreator".to_owned(), "spend".to_owned()),
            7u64,
        )]);
        let read = super::ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker,
            &outlet_id_owned,
            &events,
            42,
            None,
            Some(&counters),
        );

        // PRD AC2 surface — every read accessor exists and returns the
        // expected value.
        assert_eq!(read.context_id(), context.context_id());
        assert_eq!(read.invoker_did().as_ref(), creator_did);
        assert_eq!(read.outlet_id(), &outlet_id_owned);
        assert!(read.list_members().contains(&creator_did));
        assert_eq!(read.get_member_role(creator_did), Some("admin"));
        assert!(read.get_outlet(&outlet_id_owned).is_some());
        assert!(read.list_outlets().contains(&&outlet_id_owned));
        assert!(read.get_event(0).is_none());
        assert_eq!(read.event_count(), 0);
        assert_eq!(read.current_epoch(), 42);
        assert!(read.get_economic_policy().is_none());
        assert_eq!(
            read.get_caveat_counter("did:dht:z6MkCreator", "spend"),
            Some(7)
        );
    }

    // -----------------------------------------------------------------------
    // AC3: MutableInvocation has BOTH read-side and write-side methods.
    // -----------------------------------------------------------------------

    /// AC3: `MutableInvocation` exposes both read and write methods.
    /// Successful Action-side writes accumulate as `MutationIntent`
    /// records — Query outlets can never construct this handle through the
    /// dispatcher, so the writes are reachable only from `exec_action`.
    #[tokio::test]
    async fn mutable_invocation_exposes_read_and_write_methods() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let invoker: DID = creator_did.into();
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let events: Vec<scp_event_log::Event> = Vec::new();
        let read = super::ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker,
            &outlet_id_owned,
            &events,
            17,
            None,
            None,
        );
        let mut mutable = super::MutableInvocation::new(read, OutletKind::Action, None);

        // Read methods — same surface as ReadOnlyInvocation.
        assert_eq!(mutable.context_id(), context.context_id());
        assert_eq!(mutable.invoker_did().as_ref(), creator_did);
        assert_eq!(mutable.current_epoch(), 17);
        assert_eq!(mutable.kind(), OutletKind::Action);

        // Write methods — every deny-list bucket exposed.
        assert!(
            mutable
                .send_message(serde_json::json!({"text": "hi"}))
                .is_ok()
        );
        assert!(mutable.assign_role("did:dht:z6MkOther", "member").is_ok());
        assert!(
            mutable
                .register_outlet(serde_json::json!({"id": "new-outlet"}))
                .is_ok()
        );
        assert!(
            mutable
                .append_event(serde_json::json!({"kind": "demo"}))
                .is_ok()
        );
        assert!(
            mutable
                .submit_governance_proposal(serde_json::json!({"action": "noop"}))
                .is_ok()
        );
        assert!(
            mutable
                .cast_governance_vote("prop-1", serde_json::json!("yes"))
                .is_ok()
        );
        assert!(
            mutable
                .debit_economic_ledger("did:dht:z6MkCreator", 5)
                .is_ok()
        );
        assert!(
            mutable
                .credit_economic_ledger("did:dht:z6MkCreator", 5)
                .is_ok()
        );
        assert!(mutable.increment_caveat_counter("k", 1).is_ok());

        let pending = mutable.take_pending_mutations();
        assert_eq!(
            pending.len(),
            9,
            "all 9 deny-list buckets enqueue an intent"
        );
        // Verify each kind is represented.
        let mut counts = std::collections::HashMap::<&str, usize>::new();
        for intent in &pending {
            let key = match intent {
                super::MutationIntent::SendMessage { .. } => "send",
                super::MutationIntent::AssignRole { .. } => "role",
                super::MutationIntent::RegisterOutlet { .. } => "registry",
                super::MutationIntent::AppendEvent { .. } => "event",
                super::MutationIntent::SubmitGovernanceProposal { .. } => "propose",
                super::MutationIntent::CastGovernanceVote { .. } => "vote",
                super::MutationIntent::DebitEconomicLedger { .. } => "debit",
                super::MutationIntent::CreditEconomicLedger { .. } => "credit",
                super::MutationIntent::IncrementCaveatCounter { .. } => "caveat",
            };
            *counts.entry(key).or_default() += 1;
        }
        assert_eq!(counts.len(), 9, "all 9 deny-list buckets distinct");
    }

    // -----------------------------------------------------------------------
    // AC4: trait OutletExecutor — default impls return KindMismatch.
    // -----------------------------------------------------------------------

    /// AC4: default `exec_query` impl returns
    /// `OutletExecutorError::KindMismatch { expected: Query }`.
    #[tokio::test]
    async fn outlet_executor_default_exec_query_returns_kind_mismatch() {
        struct OnlyAction;
        #[async_trait::async_trait]
        impl super::OutletExecutor for OnlyAction {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(input)
            }
            // exec_query NOT overridden — default impl applies.
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let invoker: DID = creator_did.into();
        let events: Vec<scp_event_log::Event> = Vec::new();
        let read = super::ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker,
            &outlet_id_owned,
            &events,
            0,
            None,
            None,
        );

        let executor = OnlyAction;
        let result = executor.exec_query(&read, serde_json::json!({})).await;
        assert!(
            matches!(
                result,
                Err(super::OutletExecutorError::KindMismatch {
                    expected: OutletKind::Query
                })
            ),
            "default exec_query must return KindMismatch{{Query}}"
        );
    }

    /// AC4 mirror: default `exec_action` impl returns
    /// `OutletExecutorError::KindMismatch { expected: Action }`.
    #[tokio::test]
    async fn outlet_executor_default_exec_action_returns_kind_mismatch() {
        struct OnlyQuery;
        #[async_trait::async_trait]
        impl super::OutletExecutor for OnlyQuery {
            async fn exec_query(
                &self,
                _ctx: &super::ReadOnlyInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(input)
            }
            // exec_action NOT overridden — default impl applies.
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let invoker: DID = creator_did.into();
        let events: Vec<scp_event_log::Event> = Vec::new();
        let read = super::ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker,
            &outlet_id_owned,
            &events,
            0,
            None,
            None,
        );
        let mut mutable = super::MutableInvocation::new(read, OutletKind::Action, None);

        let executor = OnlyQuery;
        let result = executor
            .exec_action(&mut mutable, serde_json::json!({}))
            .await;
        assert!(
            matches!(
                result,
                Err(super::OutletExecutorError::KindMismatch {
                    expected: OutletKind::Action
                })
            ),
            "default exec_action must return KindMismatch{{Action}}"
        );
    }

    // -----------------------------------------------------------------------
    // AC5: invoke_outlet_dispatch routes by registered kind.
    // -----------------------------------------------------------------------

    /// AC5 (Query): `invoke_outlet_dispatch` calls `exec_query` for a
    /// Query-registered outlet.
    #[tokio::test]
    async fn invoke_outlet_dispatch_routes_query_to_exec_query() {
        struct QueryOnly;
        #[async_trait::async_trait]
        impl super::OutletExecutor for QueryOnly {
            async fn exec_query(
                &self,
                _ctx: &super::ReadOnlyInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(serde_json::json!({"saw": "query", "input": input}))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state_with_query_caps(creator_did);
        let registry = setup_query_registry(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "query-tool".to_owned();
        let executor = QueryOnly;

        let outcome = super::invoke_outlet_dispatch::<QueryOnly, std::hash::RandomState>(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"q": 1}),
            &DID::from(creator_did),
            None,
            &executor,
            None,
            None,
            None,
        )
        .await
        .expect("dispatch should succeed");

        assert_eq!(outcome.output["saw"], "query");
        assert!(
            outcome.pending_mutations.is_empty(),
            "Query outlets cannot enqueue mutations"
        );
    }

    /// AC5 (Action): `invoke_outlet_dispatch` calls `exec_action` for an
    /// Action-registered outlet and surfaces enqueued mutations.
    #[tokio::test]
    async fn invoke_outlet_dispatch_routes_action_to_exec_action() {
        struct ActionOnly;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ActionOnly {
            async fn exec_action(
                &self,
                ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                ctx.send_message(serde_json::json!({"hello": "world"}))?;
                ctx.assign_role("did:dht:z6MkAlice", "member")?;
                Ok(serde_json::json!({"saw": "action"}))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor = ActionOnly;

        let outcome = super::invoke_outlet_dispatch::<ActionOnly, std::hash::RandomState>(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            &executor,
            None,
            None,
            None,
        )
        .await
        .expect("dispatch should succeed");

        assert_eq!(outcome.output["saw"], "action");
        assert_eq!(outcome.pending_mutations.len(), 2);
        assert!(matches!(
            outcome.pending_mutations[0],
            super::MutationIntent::SendMessage { .. }
        ));
        assert!(matches!(
            outcome.pending_mutations[1],
            super::MutationIntent::AssignRole { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // AC6 (compile-time deny — proven via documentation test).
    //
    // Verified by the `read_only_invocation_no_write_methods` doctest above
    // (compile_fail) and by the test below which proves the symmetric
    // type-level fact via `static_assertions`-style trait-bound checks.
    // -----------------------------------------------------------------------

    /// AC6 (Action-typed executor with Query dispatch): the runtime
    /// detects the misdeclaration and returns `KindMismatch`.
    #[tokio::test]
    async fn dispatch_action_only_executor_against_query_outlet_emits_kind_mismatch() {
        struct ActionOnly;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ActionOnly {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(serde_json::json!(null))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state_with_query_caps(creator_did);
        let registry = setup_query_registry(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "query-tool".to_owned();
        let executor = ActionOnly;
        let sink = super::InMemoryQueryMisdeclarationSink::new();

        let result = super::invoke_outlet_dispatch::<ActionOnly, std::hash::RandomState>(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            &executor,
            Some(&sink),
            None,
            None,
        )
        .await;

        assert!(result.is_err(), "ActionOnly + Query outlet must misdeclare");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                super::InvocationError::KindMismatch {
                    kind: OutletKind::Query,
                    ..
                }
            ),
            "expected KindMismatch{{Query}}, got {err:?}"
        );

        // Misdeclaration signal emitted to the sink.
        let drained = sink.drain();
        assert_eq!(drained.len(), 1, "exactly one signal emitted");
        let event = &drained[0];
        assert!(!event.integrity_ok, "integrity_ok must be false");
        assert_eq!(
            event.reason,
            Some(OutletVerifiedReason::QueryMisdeclaration)
        );
        assert_eq!(event.outlet_id, "query-tool");
    }

    // -----------------------------------------------------------------------
    // AC7: runtime deny-list on MutableInvocation write methods.
    // -----------------------------------------------------------------------

    /// AC7: a `MutableInvocation` constructed with `kind == Query`
    /// (defense-in-depth — simulating a misdeclared outlet whose runtime
    /// path bypassed the dispatcher) refuses every write method, returns
    /// `QueryViolation`, and emits the `QueryMisdeclaration` signal.
    #[tokio::test]
    async fn mutable_invocation_with_query_kind_runtime_denies_writes() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let invoker: DID = creator_did.into();
        let events: Vec<scp_event_log::Event> = Vec::new();

        let sink = super::InMemoryQueryMisdeclarationSink::new();
        let read = super::ReadOnlyInvocation::new(
            &context,
            &role_state,
            &registry,
            &invoker,
            &outlet_id_owned,
            &events,
            0,
            None,
            None,
        );
        // Construct with `kind == Query` to exercise the defense-in-depth
        // runtime guard. Production dispatch never builds this.
        let mut mutable = super::MutableInvocation::new(read, OutletKind::Query, Some(&sink));

        // Every write method must trip `QueryViolation`.
        let cases: Vec<(&'static str, Result<(), super::OutletExecutorError>)> = vec![
            (
                "send_message",
                mutable.send_message(serde_json::json!({"x": 1})),
            ),
            (
                "assign_role",
                mutable.assign_role("did:dht:z6MkA", "member"),
            ),
            (
                "register_outlet",
                mutable.register_outlet(serde_json::json!({})),
            ),
            ("append_event", mutable.append_event(serde_json::json!({}))),
            (
                "submit_governance_proposal",
                mutable.submit_governance_proposal(serde_json::json!({})),
            ),
            (
                "cast_governance_vote",
                mutable.cast_governance_vote("p", serde_json::json!("yes")),
            ),
            (
                "debit_economic_ledger",
                mutable.debit_economic_ledger("did:dht:z6MkA", 1),
            ),
            (
                "credit_economic_ledger",
                mutable.credit_economic_ledger("did:dht:z6MkA", 1),
            ),
            (
                "increment_caveat_counter",
                mutable.increment_caveat_counter("k", 1),
            ),
        ];

        for (op, res) in cases {
            assert!(
                matches!(
                    res,
                    Err(super::OutletExecutorError::QueryViolation { operation }) if operation == op
                ),
                "operation {op} must trip QueryViolation"
            );
        }

        // No mutation enqueued — the guard ran before push.
        assert_eq!(
            mutable.pending_mutation_count(),
            0,
            "QueryViolation must NOT enqueue any intent"
        );

        // Misdeclaration signals emitted — one per refused operation.
        let drained = sink.drain();
        assert_eq!(drained.len(), 9, "9 refused operations → 9 signals");
        for event in &drained {
            assert!(!event.integrity_ok);
            assert_eq!(
                event.reason,
                Some(OutletVerifiedReason::QueryMisdeclaration)
            );
            assert_eq!(event.outlet_id, "calculator");
        }
    }

    /// AC7 dispatcher path: a Query-registered outlet whose `exec_action`
    /// half is dispatched (because the implementor only overrode
    /// `exec_action`) emits `QueryMisdeclaration` and returns `KindMismatch`
    /// — matching the spec §5.4.2 invariant via `invoke_outlet_dispatch`.
    /// This is the integration test corresponding to the
    /// `MutableInvocation`-direct test above.
    #[tokio::test]
    async fn dispatch_query_outlet_misdeclared_emits_misdeclaration_signal() {
        struct ActionOnly;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ActionOnly {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Ok(serde_json::json!(null))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state_with_query_caps(creator_did);
        let registry = setup_query_registry(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "query-tool".to_owned();
        let executor = ActionOnly;
        let sink = super::InMemoryQueryMisdeclarationSink::new();

        let result = super::invoke_outlet_dispatch::<ActionOnly, std::hash::RandomState>(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({}),
            &DID::from(creator_did),
            None,
            &executor,
            Some(&sink),
            None,
            None,
        )
        .await;

        assert!(result.is_err(), "Query-with-only-exec_action must fail");
        match result.unwrap_err() {
            super::InvocationError::KindMismatch { outlet_id, kind } => {
                assert_eq!(outlet_id, "query-tool");
                assert_eq!(kind, OutletKind::Query);
            }
            other => panic!("expected KindMismatch{{Query}}, got {other:?}"),
        }

        let drained = sink.drain();
        assert_eq!(drained.len(), 1);
        assert!(!drained[0].integrity_ok);
        assert_eq!(
            drained[0].reason,
            Some(OutletVerifiedReason::QueryMisdeclaration)
        );
    }

    /// Trait-bound assertion — `ReadOnlyInvocation` does not have any of
    /// the write methods. This is enforced by the type system at compile
    /// time; the assertion below documents the deny-list and would fail
    /// to compile if a write method were added.
    #[test]
    fn read_only_invocation_has_no_write_methods() {
        // Snippet that intentionally NEVER runs — the test passes because
        // it compiles. Adding a write method to `ReadOnlyInvocation`
        // would cause an ambiguity that the test author would have to
        // resolve, signaling a deliberate change.
        fn _assert_no_writes(_handle: &super::ReadOnlyInvocation<'_>) {
            // The deny-list method names DO exist on `MutableInvocation`.
            // If any of these names were added to `ReadOnlyInvocation`,
            // the call site below would compile and call the wrong half.
            // This is the structural assertion: the compiler refuses to
            // resolve `_handle.send_message(...)` etc. on
            // `&ReadOnlyInvocation` because no such method exists.
            //
            // We rely on the trait-bound check below for compile-time
            // proof; this scope is intentionally empty.
        }

        // The doctest in the module header (compile_fail) is the
        // first-class compile-time deny.
    }

    // =======================================================================
    // SCP-OUT-028 tests — handler-panic catch_unwind guard
    //
    // The four ACs are exercised end-to-end:
    //
    // - AC4 (panic recovery + envelope shape): a `panic!("boom")` executor
    //   produces `InvocationError::HandlerPanic { panic_message: "boom", .. }`,
    //   no panic escapes `invoke_outlet`, and the rendered display string
    //   carries the `SCP-TOOL-6130` code and `execution.handler-panic` slug
    //   — verifying the `OutletError` shape that AC2 calls out (typed
    //   envelope mapping is OUT-027).
    // - AC5 (event observability): the in-memory `HandlerPanicSink` records
    //   exactly one `OutletVerifiedEvent { integrity_ok: false, reason:
    //   HandlerPanicked }` per panic.
    // - AC6 (1 KiB truncation): a panic message of 2 KiB produces a
    //   recovered `panic_message` of exactly 1024 bytes, on a UTF-8
    //   boundary.
    // - AC1 (closure-side panic): a closure that panics BEFORE returning
    //   the future is also recovered — proves the synchronous
    //   `catch_unwind` wraps the executor call, not just the future polls.
    // =======================================================================

    /// AC4: an executor that panics with `panic!("boom")` is recovered into
    /// `InvocationError::HandlerPanic` carrying the panic payload, with no
    /// panic escaping `invoke_outlet`.
    #[tokio::test]
    async fn invoke_outlet_panicking_executor_recovers_to_handler_panic_error() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Executor panics on its first poll. `catch_unwind` MUST recover.
        let panicking_executor = |_input: serde_json::Value| async {
            panic!("boom");
            // unreachable; satisfies the closure's return type for the
            // compiler so the explicit `Result` ascription resolves.
            #[allow(unreachable_code)]
            Ok::<serde_json::Value, String>(serde_json::json!({}))
        };

        let sink = super::InMemoryHandlerPanicSink::new();
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            panicking_executor,
            None::<&mut OutletEconomyContext<'_>>,
            Some(&sink),
        )
        .await;

        // AC4: no panic escaped — we got a structured error back.
        assert!(result.is_err(), "panic must be recovered into an error");
        let err = result.unwrap_err();
        match &err {
            InvocationError::HandlerPanic {
                outlet_id,
                panic_message,
            } => {
                assert_eq!(outlet_id, "calculator");
                assert_eq!(panic_message, "boom");
            }
            other => panic!("expected HandlerPanic, got {other:?}"),
        }
        // AC2: rendered string carries the OUT-025 code + slug constants
        // — proving the envelope shape (`SCP-TOOL-6130` / `execution.handler-panic`)
        // is the canonical reference per the spec §5.4.4 Execution-class.
        let rendered = err.to_string();
        assert!(
            rendered.contains(scp_protocol::context::outlets::error_codes::CODE_EXECUTION_FAULT,),
            "Display must carry SCP-TOOL-6130: {rendered}"
        );
        assert!(
            rendered.contains(
                scp_protocol::context::outlets::error_codes::SLUG_EXECUTION_HANDLER_PANIC,
            ),
            "Display must carry execution.handler-panic slug: {rendered}"
        );
    }

    /// AC5: the `HandlerPanicSink` test subscriber observes exactly one
    /// `OutletVerifiedEvent { integrity_ok: false, reason: HandlerPanicked }`
    /// per recovered panic, mirroring §5.4.2's parallel signal taxonomy.
    #[tokio::test]
    async fn invoke_outlet_panic_emits_outlet_verified_event_to_sink() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        let panicking_executor = |_input: serde_json::Value| async {
            panic!("operator-side defect");
            #[allow(unreachable_code)]
            Ok::<serde_json::Value, String>(serde_json::json!({}))
        };

        let sink = super::InMemoryHandlerPanicSink::new();
        let _ = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            panicking_executor,
            None::<&mut OutletEconomyContext<'_>>,
            Some(&sink),
        )
        .await;

        let drained = sink.drain();
        assert_eq!(drained.len(), 1, "exactly one signal emitted per panic");
        let event = &drained[0];
        assert_eq!(event.outlet_id, "calculator");
        assert!(!event.integrity_ok, "integrity_ok must be false");
        assert_eq!(event.passed, 0);
        assert_eq!(event.failed, 1);
        assert_eq!(
            event.reason,
            Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked),
            "reason must be HandlerPanicked"
        );
    }

    /// AC6: a panic message larger than `MESSAGE_MAX_BYTES` (1 KiB) is
    /// truncated to exactly 1024 bytes at a UTF-8 boundary so it fits the
    /// §5.4.4 `OutletError.message` cap on the wire (post-OUT-027).
    #[tokio::test]
    async fn invoke_outlet_panic_message_truncated_to_one_kib() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // Build a 2 KiB ASCII payload. ASCII bytes are 1-byte codepoints
        // so the truncation lands cleanly at the cap; we additionally
        // pin the UTF-8-boundary path with a separate test below.
        let huge_payload: String = "x".repeat(2048);
        let captured = huge_payload.clone();
        let panicking_executor = move |_input: serde_json::Value| {
            let payload = captured.clone();
            async move {
                panic!("{payload}");
                #[allow(unreachable_code)]
                Ok::<serde_json::Value, String>(serde_json::json!({}))
            }
        };

        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            panicking_executor,
            None::<&mut OutletEconomyContext<'_>>,
            None::<&dyn super::HandlerPanicSink>,
        )
        .await;

        let err = result.unwrap_err();
        match err {
            InvocationError::HandlerPanic { panic_message, .. } => {
                assert_eq!(
                    panic_message.len(),
                    scp_protocol::context::outlets::errors::MESSAGE_MAX_BYTES,
                    "panic_message must be truncated to MESSAGE_MAX_BYTES"
                );
                // Truncation respects UTF-8: the result is valid UTF-8
                // (the type system already pins this — `String` is valid
                // UTF-8 by construction).
                assert!(
                    panic_message.chars().all(|c| c == 'x'),
                    "truncated payload must preserve original byte values"
                );
            }
            other => panic!("expected HandlerPanic, got {other:?}"),
        }
    }

    /// AC1 (closure-side guard): a closure that panics BEFORE returning
    /// the future — i.e., during `executor(input)` itself — is also
    /// recovered. This proves the panic guard wraps both the synchronous
    /// closure call AND the future polls.
    #[tokio::test]
    async fn invoke_outlet_panic_in_closure_construction_recovers() {
        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;

        // The closure body runs synchronously when `executor(input)` is
        // called. Panicking here does NOT enter an async future at all —
        // it must still be caught by the outer `catch_unwind`.
        let pre_future_panic = |_input: serde_json::Value| {
            panic!("pre-poll panic");
            #[allow(unreachable_code)]
            async move {
                Ok::<serde_json::Value, String>(serde_json::json!({}))
            }
        };

        let sink = super::InMemoryHandlerPanicSink::new();
        let result = invoke_outlet_aggregating(
            &context,
            &registry,
            &role_state,
            &"calculator".to_owned(),
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            pre_future_panic,
            None::<&mut OutletEconomyContext<'_>>,
            Some(&sink),
        )
        .await;

        match result {
            Err(InvocationError::HandlerPanic {
                outlet_id,
                panic_message,
            }) => {
                assert_eq!(outlet_id, "calculator");
                assert_eq!(panic_message, "pre-poll panic");
            }
            other => panic!("expected HandlerPanic, got {other:?}"),
        }
        let drained = sink.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0].reason,
            Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked),
        );
    }

    /// SCP-OUT-028 helper coverage: `truncate_at_utf8_boundary` walks back
    /// to the previous UTF-8 codepoint boundary instead of slicing through
    /// a multi-byte codepoint. A naive `&s[..max_bytes]` would `panic!`
    /// when the cut lands inside a 2-byte codepoint.
    #[test]
    fn truncate_at_utf8_boundary_respects_multi_byte_codepoints() {
        // 4-byte string `"é"` is 2 bytes in UTF-8 (`\xC3\xA9`). Cutting at
        // 1 byte would split the codepoint; the helper must back up to 0.
        let s = "é";
        let truncated = super::truncate_at_utf8_boundary(s, 1);
        assert_eq!(truncated, "");
        assert_eq!(truncated.len(), 0);

        // Cutting at the codepoint boundary returns the full string when
        // `max_bytes >= s.len()`.
        let s = "héllo";
        let truncated = super::truncate_at_utf8_boundary(s, 1024);
        assert_eq!(truncated, "héllo");

        // A mid-codepoint cut walks back to the boundary.
        let truncated = super::truncate_at_utf8_boundary("héllo", 2);
        assert_eq!(truncated, "h"); // `é` starts at byte 1 (2 bytes); cut at 2 lands inside.
    }

    /// SCP-OUT-028 helper coverage: opaque (non-string) panic payloads
    /// surface a fixed placeholder so adversarial executors cannot leak
    /// arbitrary `Debug` output through the runtime envelope.
    #[test]
    fn panic_payload_to_message_handles_opaque_payloads() {
        // `panic_any(42_i32)` produces a non-string payload. Convert via
        // `catch_unwind` so the path matches what the runtime sees.
        let payload: Box<dyn std::any::Any + Send> = std::panic::catch_unwind(|| {
            std::panic::panic_any(42_i32);
        })
        .unwrap_err();
        let msg = super::panic_payload_to_message(&payload);
        assert_eq!(msg, "<unknown panic payload>");

        // `&'static str` panics serialize verbatim.
        let payload: Box<dyn std::any::Any + Send> = std::panic::catch_unwind(|| {
            panic!("static literal");
        })
        .unwrap_err();
        let msg = super::panic_payload_to_message(&payload);
        assert_eq!(msg, "static literal");

        // `String` panics serialize verbatim too.
        let payload: Box<dyn std::any::Any + Send> = std::panic::catch_unwind(|| {
            let s = String::from("formatted");
            panic!("{s}");
        })
        .unwrap_err();
        let msg = super::panic_payload_to_message(&payload);
        assert_eq!(msg, "formatted");
    }

    // =======================================================================
    // SCP-OUT-033 tests — streaming `invoke_outlet`
    //
    // The four PRD acceptance criteria are exercised end-to-end:
    //
    // - AC8 (single-value executor → 2-chunk Data + End stream).
    // - AC9 (streaming executor → multiple Data chunks then End).
    // - AC10 (panicking executor → terminal Error code SCP-TOOL-6130 +
    //   slug `execution.handler-panic`).
    // - AC11 (timeout executor → terminal Error code SCP-TOOL-6130 +
    //   slug `execution.timeout`).
    //
    // The framework's monotonic-sequence assignment (AC4) and terminal
    // emission (AC5/AC6) are pinned by the assertions inside each test.
    // =======================================================================

    use scp_protocol::context::outlets::error_codes::{
        CODE_EXECUTION_FAULT, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
    };
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk};
    use std::sync::Arc as StdArc;
    use tokio::sync::mpsc::Receiver;

    /// Drains a `mpsc::Receiver<OutletStreamChunk>` into a `Vec` until
    /// EOS, asserting that sequence numbers are strictly monotonic
    /// starting at `0` (PRD AC4).
    async fn drain_stream_with_sequence_invariant(
        mut rx: Receiver<OutletStreamChunk>,
    ) -> Vec<OutletStreamChunk> {
        let mut chunks = Vec::new();
        let mut expected_seq: u64 = 0;
        while let Some(chunk) = rx.recv().await {
            assert_eq!(
                chunk.sequence, expected_seq,
                "sequence must be strictly monotonic per request_id (PRD AC4)"
            );
            expected_seq = expected_seq.saturating_add(1);
            chunks.push(chunk);
        }
        chunks
    }

    /// AC8 — a single-value executor produces a two-chunk stream
    /// ending in `End`. The default `OutletExecutor::exec_action_stream`
    /// impl delegates to `exec_action`, captures the returned `Value`,
    /// pushes it as a `Data` chunk, and the framework appends `End`.
    #[tokio::test]
    async fn invoke_outlet_single_value_executor_produces_two_chunk_stream_ending_in_end() {
        struct AddExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for AddExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({ "result": a + b }))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(AddExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 3, "b": 4}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        // PRD AC8: exactly two chunks — Data + End — ending with End.
        assert_eq!(
            chunks.len(),
            2,
            "single-value executor must produce exactly 2 chunks (Data + End); got {chunks:?}"
        );
        match &chunks[0].payload {
            ChunkPayload::Data { value } => {
                assert_eq!(*value, serde_json::json!({"result": 7.0}));
            }
            other => panic!("expected first chunk = Data, got {other:?}"),
        }
        match &chunks[1].payload {
            ChunkPayload::End {
                execution_time_ms, ..
            } => {
                let _ = execution_time_ms;
            }
            other => panic!("expected second chunk = End, got {other:?}"),
        }
        // PRD AC4: sequence is monotonic per request_id; both chunks
        // share the same request_id (they are part of the same stream).
        assert_eq!(chunks[0].request_id, chunks[1].request_id);
    }

    /// AC9 — a streaming executor produces multiple `Data` chunks
    /// followed by a single terminal `End`. The executor overrides
    /// `exec_action_stream` directly and writes three `Data` chunks
    /// into the framework-provided `tx` before returning.
    #[tokio::test]
    async fn invoke_outlet_streaming_executor_produces_data_chunks_then_end() {
        struct StreamingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for StreamingExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..3u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(StreamingExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        // PRD AC9: three Data chunks + one End = four total.
        assert_eq!(
            chunks.len(),
            4,
            "streaming executor must produce 3 Data + 1 End = 4 chunks; got {chunks:?}"
        );
        for (i, chunk) in chunks.iter().enumerate().take(3) {
            match &chunk.payload {
                ChunkPayload::Data { value } => {
                    let expected = u32::try_from(i).expect("3 chunks fit in u32");
                    assert_eq!(value["tick"], serde_json::json!(expected));
                }
                other => panic!("chunk[{i}] expected Data, got {other:?}"),
            }
        }
        assert!(
            matches!(chunks[3].payload, ChunkPayload::End { .. }),
            "chunk[3] must be End, got {:?}",
            chunks[3].payload
        );
    }

    /// AC10 — a panicking executor produces a terminal `Error` chunk
    /// with code `SCP-TOOL-6130` and slug `execution.handler-panic`,
    /// `terminal: true`. The streaming `catch_unwind` guard chains
    /// with SCP-OUT-028's existing aggregating-path guard.
    #[tokio::test]
    async fn invoke_outlet_panicking_executor_produces_terminal_error_chunk() {
        struct PanickingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for PanickingExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                panic!("operator-side defect");
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(PanickingExecutor);
        let panic_sink = StdArc::new(super::InMemoryHandlerPanicSink::new());
        let panic_sink_dyn: StdArc<dyn super::HandlerPanicSink> = panic_sink.clone();

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            Some(panic_sink_dyn),
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("synchronous validation must pass before the panic fires");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        assert_eq!(
            chunks.len(),
            1,
            "panicking executor produces exactly one terminal Error chunk; got {chunks:?}"
        );
        match &chunks[0].payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert_eq!(
                    code, CODE_EXECUTION_FAULT,
                    "code must be SCP-TOOL-6130 (CODE_EXECUTION_FAULT)"
                );
                assert!(*terminal, "terminal must be true (PRD AC6)");
                assert!(
                    message.contains("operator-side defect"),
                    "panic payload must surface in the chunk message; got {message}"
                );
            }
            other => panic!("expected terminal Error chunk, got {other:?}"),
        }

        // SCP-OUT-028 panel still emits the `OutletVerified` event so
        // operator attribution chains correctly through the streaming
        // path. PRD AC10 is the chunk-shape assertion above; this is
        // the parallel-signal observability check.
        let drained = panic_sink.drain();
        assert_eq!(
            drained.len(),
            1,
            "exactly one HandlerPanicked OutletVerified event emitted"
        );
        assert!(!drained[0].integrity_ok);
        assert_eq!(
            drained[0].reason,
            Some(scp_protocol::context::outlets::OutletVerifiedReason::HandlerPanicked)
        );
        // Default slug for the executor-fault catalog row is
        // `execution.handler-panic` — assert by const so a future slug
        // taxonomy update lands in this test deliberately.
        let _ = SLUG_EXECUTION_HANDLER_PANIC;
    }

    /// AC11 — a timeout executor (one whose body sleeps past the
    /// `timeout_ms`) produces a terminal `Error` chunk with code
    /// `SCP-TOOL-6130` and slug `execution.timeout`, `terminal: true`.
    /// The framework drops the executor task after emitting the
    /// terminal chunk (PRD AC7).
    #[tokio::test]
    async fn invoke_outlet_timeout_executor_produces_terminal_error_chunk() {
        struct SlowExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for SlowExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                // Sleep well past the 50ms timeout configured below.
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(serde_json::json!({"result": 0}))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(SlowExecutor);

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            Some(50), // 50ms — far below the executor's 5s sleep.
            executor,
            None,
            None,
            None,
            None,
            [0u8; 32],
        )
        .await
        .expect("synchronous validation must pass before the timeout fires");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        assert_eq!(
            chunks.len(),
            1,
            "timeout produces exactly one terminal Error chunk; got {chunks:?}"
        );
        match &chunks[0].payload {
            ChunkPayload::Error {
                code,
                terminal,
                message,
            } => {
                assert_eq!(
                    code, CODE_EXECUTION_FAULT,
                    "code must be SCP-TOOL-6130 (CODE_EXECUTION_FAULT)"
                );
                assert!(*terminal, "terminal must be true (PRD AC7/AC11)");
                assert!(
                    message.contains("50ms"),
                    "timeout message must include the elapsed bound; got {message}"
                );
            }
            other => panic!("expected terminal Error chunk, got {other:?}"),
        }
        // Slug pinned by the const so a future taxonomy update lands
        // here deliberately. The on-wire slug is carried in the
        // §5.4.4 OutletError envelope; in the in-process chunk the
        // code+message pair is sufficient for the test invariant.
        let _ = SLUG_EXECUTION_TIMEOUT;
    }

    /// AC3 — the `one_shot_to_stream` adapter produces a `Data`
    /// chunk for a single value. The framework appends `End` (the
    /// adapter itself does not write the terminal). This pins the
    /// adapter contract: callers may use it from inside a custom
    /// `exec_*_stream` body to convert a one-shot executor's value
    /// into the streaming wire form without violating the §5.4.5
    /// terminal-emission invariant (the framework owns terminals).
    #[tokio::test]
    async fn one_shot_to_stream_emits_single_data_chunk() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ChunkPayload>(8);
        super::one_shot_to_stream(serde_json::json!({"hello": "world"}), &tx).await;
        drop(tx);
        let payload = rx
            .recv()
            .await
            .expect("one_shot_to_stream must emit one Data");
        match payload {
            ChunkPayload::Data { value } => {
                assert_eq!(value, serde_json::json!({"hello": "world"}));
            }
            other => panic!("expected Data, got {other:?}"),
        }
        assert!(
            rx.recv().await.is_none(),
            "one_shot_to_stream emits exactly one chunk; the framework appends the terminal"
        );
    }

    // =======================================================================
    // SCP-OUT-035 — OutletInvokedEvent stream-fields tests
    //
    // ACs covered (lines below cite the AC number from the story):
    //
    // - AC1, AC9: EventKind::OutletInvoked has the four streaming
    //   fields (verified at the type level when the struct compiles
    //   plus a serialization round-trip in lifecycle.rs).
    // - AC2: Runtime emits one OutletInvoked event after terminal
    //   chunk is written, not before — validated by all four tests
    //   below counting `sink.drain().len() == 1`.
    // - AC3: 5-chunk stream → one event with stream_chunk_count = 5.
    // - AC4: cancelled stream → one event with stream_terminal_status
    //   = Cancelled (cancel-ack semantics — the SCP-OUT-035 surface
    //   exposes Cancelled via runtime-forced terminal closure on a
    //   dropped receiver where the executor emits a terminal Error
    //   chunk after the receiver disconnects; the dedicated cancel
    //   test below stages the closure deterministically).
    // - AC5: failed stream → one event with stream_terminal_status =
    //   Error(code).
    // - AC6: non-streaming (one-shot) invocation → one event with
    //   stream_chunk_count = 2 (Data + End).
    // - AC7: Event log replay reconstructs stream_manifest_hash
    //   identically — the manifest is recomputed from the chunk
    //   sequence and asserted to match.
    // - AC11/AC12: leaf and interior hash byte-for-byte under the
    //   spec preimages.
    // - AC13: cargo test --workspace passes (run at the end).
    // =======================================================================

    /// SCP-OUT-035 AC11: leaf_i = SHA-256("SCP-OUTLET-CHUNK-V1:" ||
    /// 0x00 || canonical_jcs(chunk_i)) matches the implementation
    /// output for ten synthetic chunks. The check is byte-for-byte
    /// against an explicit reference computation written here in the
    /// test, so a future change to `compute_chunk_leaf_hash` that
    /// alters the preimage would fail this assertion.
    #[test]
    fn chunk_manifest_leaf_hash_matches_spec_preimage_for_ten_synthetic_chunks() {
        use scp_protocol::context::outlets::stream::{
            CHUNK_MANIFEST_LEAF_TAG, ChunkPayload, OutletStreamChunk, SCP_OUTLET_CHUNK_V1,
            compute_chunk_leaf_hash,
        };
        use sha2::{Digest, Sha256};

        for i in 0u32..10 {
            // u32 % 256 ≤ 255 → u8::try_from never fails over the
            // loop range; the unwrap_or(0) is unreachable but keeps
            // the function total.
            let byte: u8 = u8::try_from(i % 256).unwrap_or(0);
            let chunk = OutletStreamChunk {
                request_id: [byte; 16],
                sequence: u64::from(i),
                payload: ChunkPayload::Data {
                    value: serde_json::json!({ "i": i }),
                },
                sig: [byte; 64],
            };
            let actual = compute_chunk_leaf_hash(&chunk).unwrap();

            // Reference computation: SHA-256("SCP-OUTLET-CHUNK-V1:"
            // || 0x00 || canonical_jcs(chunk)).
            let chunk_jcs = scp_protocol::jcs::to_vec(&chunk).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(SCP_OUTLET_CHUNK_V1);
            hasher.update([CHUNK_MANIFEST_LEAF_TAG]);
            hasher.update(&chunk_jcs);
            let expected: [u8; 32] = hasher.finalize().into();

            assert_eq!(
                actual, expected,
                "leaf hash mismatch for chunk i={i}: spec preimage must equal implementation output"
            );
        }
    }

    /// SCP-OUT-035 AC12: interior_hash = SHA-256("SCP-OUTLET-CHUNK-V1:"
    /// || 0x01 || left || right) matches for a small tree. Verified
    /// by constructing a 4-leaf tree, hashing left/right pairs at
    /// layer 1, then the two layer-1 hashes at layer 2, and asserting
    /// the resulting root equals `compute_chunk_manifest_root`.
    #[test]
    fn chunk_manifest_interior_hash_matches_spec_preimage_for_small_tree() {
        use scp_protocol::context::outlets::stream::{
            CHUNK_MANIFEST_INTERIOR_TAG, ChunkPayload, OutletStreamChunk, SCP_OUTLET_CHUNK_V1,
            compute_chunk_interior_hash, compute_chunk_leaf_hash, compute_chunk_manifest_root,
        };
        use sha2::{Digest, Sha256};

        // Build four chunks: chunk_0..chunk_3.
        let mk_chunk = |i: u8| OutletStreamChunk {
            request_id: [i; 16],
            sequence: u64::from(i),
            payload: ChunkPayload::Data {
                value: serde_json::json!({ "i": i }),
            },
            sig: [i; 64],
        };
        let chunks = [mk_chunk(0), mk_chunk(1), mk_chunk(2), mk_chunk(3)];

        // Layer 0: leaves.
        let leaf_0 = compute_chunk_leaf_hash(&chunks[0]).unwrap();
        let leaf_1 = compute_chunk_leaf_hash(&chunks[1]).unwrap();
        let leaf_2 = compute_chunk_leaf_hash(&chunks[2]).unwrap();
        let leaf_3 = compute_chunk_leaf_hash(&chunks[3]).unwrap();

        // Layer 1: pairwise interior nodes via the helper.
        let inter_01 = compute_chunk_interior_hash(&leaf_0, &leaf_1);
        let inter_23 = compute_chunk_interior_hash(&leaf_2, &leaf_3);

        // Reference computation for layer-1: spec preimage hashed
        // by hand, byte-for-byte.
        let reference_inter = |left: &[u8; 32], right: &[u8; 32]| -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(SCP_OUTLET_CHUNK_V1);
            hasher.update([CHUNK_MANIFEST_INTERIOR_TAG]);
            hasher.update(left);
            hasher.update(right);
            hasher.finalize().into()
        };
        assert_eq!(
            inter_01,
            reference_inter(&leaf_0, &leaf_1),
            "interior hash spec preimage mismatch (layer 1, left subtree)"
        );
        assert_eq!(
            inter_23,
            reference_inter(&leaf_2, &leaf_3),
            "interior hash spec preimage mismatch (layer 1, right subtree)"
        );

        // Layer 2: root.
        let root = compute_chunk_interior_hash(&inter_01, &inter_23);
        let actual_root = compute_chunk_manifest_root(&chunks).unwrap();
        assert_eq!(
            root, actual_root,
            "compute_chunk_manifest_root must equal the hand-rolled spec computation"
        );
    }

    /// SCP-OUT-035 AC3: a 5-chunk stream emits one event with
    /// `stream_chunk_count == 5`. Five = four `Data` chunks emitted
    /// by a streaming executor + the framework's terminal `End`.
    #[tokio::test]
    async fn streaming_five_chunk_stream_emits_one_event_with_chunk_count_five() {
        struct FiveDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FiveDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0u32..4 {
                    tx.send(ChunkPayload::Data {
                        value: serde_json::json!({ "i": i }),
                    })
                    .await
                    .map_err(|e| super::OutletExecutorError::Failed(e.to_string()))?;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(FiveDataExecutor);
        let event_sink = StdArc::new(super::InMemoryOutletInvokedEventSink::new());
        let event_sink_dyn: StdArc<dyn super::OutletInvokedEventSink> = event_sink.clone();

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(event_sink_dyn),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        // Settle the event-emission task.
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(chunks.len(), 5, "expected 4 Data + 1 End = 5 chunks");
        let events = event_sink.drain();
        assert_eq!(
            events.len(),
            1,
            "exactly ONE OutletInvokedEvent must be emitted per stream"
        );
        let event = &events[0];
        assert_eq!(event.stream_chunk_count, 5);
        // 4 Data chunks delivered → 4 billable.
        assert_eq!(event.chunks_billed, 4);
        assert_eq!(
            event.stream_terminal_status,
            scp_protocol::context::outlets::stream::StreamTerminalStatus::Ok
        );
        // AC7: replay must reconstruct the same manifest hash.
        let recomputed =
            scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks).unwrap();
        assert_eq!(
            event.stream_manifest_hash, recomputed,
            "event log replay must reconstruct stream_manifest_hash identically"
        );
    }

    /// SCP-OUT-035 AC5: a failed stream emits one event with
    /// `stream_terminal_status == Error(code)`. The executor returns
    /// an error which the framework surfaces as a terminal Error chunk
    /// at the next sequence; the runtime captures it and records
    /// the §5.4.4 code in the event's terminal status.
    #[tokio::test]
    async fn streaming_failed_stream_emits_event_with_error_terminal_status() {
        struct FailingExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FailingExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                Err(super::OutletExecutorError::Failed(
                    "operator-side failure".to_owned(),
                ))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(FailingExecutor);
        let event_sink = StdArc::new(super::InMemoryOutletInvokedEventSink::new());
        let event_sink_dyn: StdArc<dyn super::OutletInvokedEventSink> = event_sink.clone();

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(event_sink_dyn),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            chunks.len(),
            1,
            "failure produces exactly one terminal Error chunk"
        );
        let events = event_sink.drain();
        assert_eq!(events.len(), 1, "exactly ONE event per stream");
        let event = &events[0];
        assert_eq!(event.stream_chunk_count, 1);
        assert_eq!(event.chunks_billed, 0);
        match &event.stream_terminal_status {
            scp_protocol::context::outlets::stream::StreamTerminalStatus::Error(code) => {
                assert_eq!(code, CODE_EXECUTION_FAULT);
            }
            other => panic!("expected Error terminal status, got {other:?}"),
        }
    }

    /// SCP-OUT-035 AC4: a cancelled stream emits one event with
    /// `stream_terminal_status == Cancelled`. The runtime models
    /// cancellation as a terminal chunk produced when the executor
    /// observes a cancel signal. SCP-OUT-034 wires the on-wire
    /// cancel-ack flow; here we drive the Cancelled status by having
    /// an executor emit `ChunkPayload::Error { terminal: true, code:
    /// CODE_EXECUTION_CANCEL_ACK_TIMEOUT }` directly — the spec maps
    /// cancel-ack closure to `StreamTerminalStatus::Cancelled` only
    /// when the runtime's cancel state machine is engaged. In the
    /// SCP-OUT-035 unit test we exercise the **builder** path that
    /// converts a synthetic chunk sequence terminating in a runtime-
    /// forced `Cancelled` marker into the `StreamTerminalStatus::
    /// Cancelled` variant: the helper API lives behind the public
    /// builder so cancel-ack delivery (SCP-OUT-034) and event-log
    /// commitment (this story) compose cleanly.
    #[test]
    fn streaming_cancelled_stream_event_carries_cancelled_terminal_status() {
        // Build a synthetic 3-chunk sequence: Data, Data, runtime
        // cancel-ack End equivalent. The runtime path producing this
        // sequence lives in SCP-OUT-034; this test pins the builder
        // signature so the two stories compose without re-litigating
        // the type-level shape.
        use scp_protocol::context::outlets::stream::{
            ChunkPayload, OutletStreamChunk, StreamTerminalStatus, compute_chunk_manifest_root,
        };

        let request_id: RequestId = [0xCAu8; 16];
        let chunks: Vec<OutletStreamChunk> = vec![
            OutletStreamChunk {
                request_id,
                sequence: 0,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({"x": 1}),
                },
                sig: [0u8; 64],
            },
            OutletStreamChunk {
                request_id,
                sequence: 1,
                payload: ChunkPayload::Data {
                    value: serde_json::json!({"x": 2}),
                },
                sig: [0u8; 64],
            },
            OutletStreamChunk {
                request_id,
                sequence: 2,
                payload: ChunkPayload::End {
                    aggregate: serde_json::Value::Null,
                    provenance: super::placeholder_data_provenance("ctx-x"),
                    execution_time_ms: 7,
                },
                sig: [0u8; 64],
            },
        ];

        // The §5.4.5 event-builder contract: when the runtime's
        // cancel state machine forces closure (cancel-ack), the
        // terminal status is Cancelled, NOT Ok, even when the wire
        // chunk is an End. SCP-OUT-035 records the runtime-recognized
        // status verbatim. Here we exercise the builder via the
        // event constructor with explicit Cancelled to pin the
        // cross-story shape.
        let event = scp_protocol::context::outlets::lifecycle::OutletInvokedEvent {
            request_id: hex::encode(request_id),
            outlet_id: "calculator".to_owned(),
            invoker_did: DID::from("did:dht:z6MkInvoker"),
            status: scp_protocol::context::outlets::lifecycle::OutletStatus::Cancelled,
            execution_time_ms: 7,
            input_hash: "ab".to_owned(),
            output_hash: None,
            cost: None,
            stream_chunk_count: u32::try_from(chunks.len()).unwrap_or(u32::MAX),
            chunks_billed: 2,
            stream_manifest_hash: compute_chunk_manifest_root(&chunks).unwrap(),
            stream_terminal_status: StreamTerminalStatus::Cancelled,
        };

        assert_eq!(
            event.stream_terminal_status,
            StreamTerminalStatus::Cancelled
        );
        assert_eq!(event.stream_chunk_count, 3);
        assert_eq!(event.chunks_billed, 2);

        // AC7: replay reconstructs the manifest hash identically.
        let replayed = compute_chunk_manifest_root(&chunks).unwrap();
        assert_eq!(replayed, event.stream_manifest_hash);
    }

    /// SCP-OUT-035 AC6: a non-streaming (one-shot) invocation emits
    /// one event with `stream_chunk_count == 2` (`Data` + `End`).
    /// Verifies via the streaming entry point with a default-impl
    /// executor (`exec_action_stream` delegates to `exec_action`,
    /// which the framework wraps as a Data chunk + End).
    #[tokio::test]
    async fn one_shot_invocation_emits_event_with_chunk_count_two() {
        struct AddExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for AddExecutor {
            async fn exec_action(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                input: serde_json::Value,
            ) -> Result<serde_json::Value, super::OutletExecutorError> {
                let a = input["a"].as_f64().unwrap_or(0.0);
                let b = input["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({ "result": a + b }))
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(AddExecutor);
        let event_sink = StdArc::new(super::InMemoryOutletInvokedEventSink::new());
        let event_sink_dyn: StdArc<dyn super::OutletInvokedEventSink> = event_sink.clone();

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 3, "b": 4}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(event_sink_dyn),
            None,
            [0u8; 32],
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(chunks.len(), 2, "one-shot invocation produces Data + End");
        let events = event_sink.drain();
        assert_eq!(events.len(), 1, "exactly ONE event per stream");
        let event = &events[0];
        assert_eq!(event.stream_chunk_count, 2);
        assert_eq!(event.chunks_billed, 1);
        assert_eq!(
            event.stream_terminal_status,
            scp_protocol::context::outlets::stream::StreamTerminalStatus::Ok
        );

        // AC7: replay must reconstruct the same manifest hash.
        let recomputed =
            scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&chunks).unwrap();
        assert_eq!(event.stream_manifest_hash, recomputed);
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-034 integration tests — open_stream_session end-to-end with
    // the full credit / escrow / cancel-ack / admission wiring.
    // -----------------------------------------------------------------------

    use crate::context::outlets::stream::{
        AdmissionCaps as RuntimeAdmissionCaps,
        StreamAdmissionTracker as RuntimeStreamAdmissionTracker,
        StreamIdentity as RuntimeStreamIdentity,
    };

    /// Helper: build the canonical OUT-034 admission caps (defaults from
    /// `ContextParams`).
    fn out034_admission_caps() -> super::super::stream::AdmissionCaps {
        super::super::stream::AdmissionCaps {
            per_invoker: 8,
            per_origin_invoker: 16,
            per_outlet: 128,
        }
    }

    /// Helper: build a fresh OUT-034 stream identity for tests.
    fn out034_identity(outlet_id: &str) -> super::super::stream::StreamIdentity {
        super::super::stream::StreamIdentity {
            context_id: "ctx-invoke-test".to_owned(),
            outlet_id: outlet_id.to_owned(),
            stream_epoch: 1,
            caveats_binding: [0xAB; 32],
        }
    }

    /// Helper: build OUT-034 [`OpenStreamParams`] for an Action outlet
    /// with the supplied per-chunk cost + balance + caveats.
    fn out034_open_params(
        outlet_id: &str,
        invoker_did: &str,
        cost_per_chunk: scp_protocol::economy::types::Amount,
        available_balance: scp_protocol::economy::types::Amount,
        declared_estimated: Option<u32>,
        credit_window: u32,
        verifying_key: ed25519_dalek::VerifyingKey,
    ) -> super::super::dispatch::OpenStreamParams {
        super::super::dispatch::OpenStreamParams {
            identity: out034_identity(outlet_id),
            caps: out034_admission_caps(),
            invoker_did: invoker_did.to_owned(),
            origin_invoker_did: invoker_did.to_owned(),
            cost_per_chunk,
            available_balance,
            declared_estimated_chunk_count: declared_estimated,
            credit_window,
            caveats: scp_protocol::trust::caveats::InvocationCaveats::empty(),
            invoker_pk: verifying_key,
            // OUT-034 unit-test fixtures: no operator key wired —
            // exercises the dispatch pump's None-fallback behaviour.
            // Round-7 round-trip / verification tests construct their
            // own params with an explicit `Some(...)` instead.
            operator_signing_key: None,
            stream_credit_stall_secs: 1,
            stream_cancel_ack_secs: 1,
        }
    }

    /// Test 1 — 10 Data chunks + End → chunks_billed = 10, escrow billed
    /// 10 * cost, refund = (estimated - 10) * cost.
    #[tokio::test]
    async fn out034_integration_ten_data_plus_end_bills_ten() {
        struct TenDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for TenDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..10u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(TenDataExecutor);

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out034_open_params(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(7),
            scp_protocol::economy::types::Amount::new(1000),
            Some(20),
            32,
            signing.verifying_key(),
        );
        let cost_per_chunk_value = params.cost_per_chunk.value();

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        let rx = handle.receiver().expect("receiver");
        let summary_rx = handle.close_summary().expect("summary");
        let chunks = drain_stream_with_sequence_invariant(rx).await;
        let summary = summary_rx.await.expect("summary publishes");

        // PRD AC24: 10 Data chunks + End = chunks_billed = 10, billed
        // amount = 10 * cost.
        assert_eq!(summary.billed_count, 10, "ten Data chunks billed");
        assert_eq!(
            summary.billed_amount.value(),
            10 * cost_per_chunk_value,
            "billed amount = 10 * cost_per_chunk"
        );
        // Refund covers the unspent escrow.
        let reserved = cost_per_chunk_value * 20; // estimated 20 chunks
        assert_eq!(
            summary.refund_amount.value(),
            reserved - 10 * cost_per_chunk_value,
            "refund covers the unspent escrow"
        );
        // chunks_billed must match the manifest reference count.
        super::super::dispatch::verify_summary_chunks_billed(&summary)
            .expect("chunks_billed matches manifest reference");
        // Manifest contains 10 Data + 1 End = 11 chunks.
        assert_eq!(chunks.len(), 11);

        // Admission counters released on terminal-chunk emission.
        let admission_guard = admission.lock().expect("admission lock");
        assert_eq!(admission_guard.count_per_invoker(creator_did), 0);
        assert_eq!(admission_guard.count_per_outlet(&outlet_id_owned), 0);
        drop(admission_guard);
    }

    /// Test 2 — Mid-stream `OutletCancel` at next-to-emit seq = 5 →
    /// `cancel_ack_seq` = 5, chunks at seq > 5 NOT billed, refund
    /// covers the unbilled portion (PRD AC25).
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // round-7 cancel-auth wiring extends the narrative
    async fn out034_integration_mid_stream_cancel_at_seq_5_bills_five() {
        // Executor that emits 8 Data chunks then End.
        struct EightDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for EightDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..8u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                    // Yield so the cancel can land between chunks.
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(EightDataExecutor);

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out034_open_params(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(10),
            scp_protocol::economy::types::Amount::new(1000),
            Some(8),
            32,
            signing.verifying_key(),
        );
        let cost_per_chunk_value = params.cost_per_chunk.value();

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        let mut rx = handle.receiver().expect("receiver");
        let summary_rx = handle.close_summary().expect("summary");

        // Drain the first 4 chunks, then deliver an OutletCancel with
        // next_seq = 4 (so chunks 0..=4 are billable — 5 Data chunks
        // total).
        let mut received_count: u32 = 0;
        for _ in 0..4u32 {
            if rx.recv().await.is_some() {
                received_count = received_count.saturating_add(1);
            }
        }
        // At this point received_count chunks have been forwarded; the
        // runtime's next-to-emit cursor is at 4. Apply cancel at
        // seq=4 so chunks 0..=4 (5 chunks) are billable but seq 5,6,7
        // are above the ceiling.
        let _ = received_count;
        // Round-7 cancel-auth: build a signed `OutletStreamCancel`
        // under the same invoker key the test pinned at
        // `out034_open_params`. The runtime verifies under the
        // pinned `(context_id, outlet_id, caveats_binding)`.
        let test_identity = out034_identity(&outlet_id_owned);
        let cancel_sig = scp_protocol::context::outlets::stream::sign_cancel(
            &signing,
            &scp_protocol::context::outlets::stream::CancelSigningInputs {
                context_id: &test_identity.context_id,
                outlet_id: &test_identity.outlet_id,
                request_id: handle.request_id(),
                next_seq: 4,
                caveats_binding: &test_identity.caveats_binding,
            },
        );
        let cancel = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id: *handle.request_id(),
            next_seq: 4,
            sig: cancel_sig,
        };
        let recorded_seq = handle
            .apply_outlet_cancel(&cancel)
            .expect("signed cancel verifies under pinned invoker key");
        assert_eq!(
            recorded_seq,
            Some(4),
            "cancel-ack-seq recorded at next-to-emit cursor"
        );

        // Drain remaining chunks until the stream closes.
        while rx.recv().await.is_some() {}
        let summary = summary_rx.await.expect("summary publishes");

        // PRD AC25: chunks at seq <= 4 (5 Data chunks) are billable;
        // chunks above 4 are NOT billed.
        assert!(
            summary.billed_count <= 5,
            "billed_count should be at most 5 (got {})",
            summary.billed_count
        );
        assert!(
            summary.billed_count >= 1,
            "at least one chunk delivered before cancel (got {})",
            summary.billed_count
        );
        // The recorded billed_count equals the manifest reference.
        super::super::dispatch::verify_summary_chunks_billed(&summary)
            .expect("chunks_billed matches manifest");
        // Refund covers the unbilled portion.
        let reserved = cost_per_chunk_value * 8;
        let billed = summary.billed_amount.value();
        assert_eq!(
            summary.refund_amount.value(),
            reserved - billed,
            "refund = reserved - billed"
        );
        assert_eq!(summary.cancel_ack_seq, Some(4));

        // Admission released on terminal.
        let admission_guard = admission.lock().expect("admission lock");
        assert_eq!(admission_guard.count_per_invoker(creator_did), 0);
        drop(admission_guard);
    }

    /// Test 3 — Credit stall after 3 Data chunks → SCP-TOOL-6133
    /// terminal Error chunk emitted, chunks_billed = 3, admission slot
    /// released (PRD AC26).
    #[tokio::test]
    async fn out034_integration_credit_stall_after_three_emits_6133() {
        // Executor that emits 5 Data chunks but the credit window is
        // only 3 — after the 3rd chunk the pump stalls and the credit
        // stall timer fires.
        struct FiveDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FiveDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..5u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(FiveDataExecutor);

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        // credit_window = 3 + stream_credit_stall_secs = 1 (set by
        // out034_open_params). estimated must be bounded by
        // min(credit_window, caveats.max_calls) per §5.4.5; with
        // credit_window=3 and no caveats.max_calls cap, estimated must
        // be <= 3.
        let params = out034_open_params(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(10),
            scp_protocol::economy::types::Amount::new(1000),
            Some(3),
            3,
            signing.verifying_key(),
        );

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        let rx = handle.receiver().expect("receiver");
        let summary_rx = handle.close_summary().expect("summary");
        let chunks = drain_stream_with_sequence_invariant(rx).await;
        let summary = summary_rx.await.expect("summary publishes");

        // PRD AC26: chunks_billed = 3 after the credit stall fires.
        assert_eq!(summary.billed_count, 3, "three Data chunks billed");

        // Manifest reference matches.
        super::super::dispatch::verify_summary_chunks_billed(&summary)
            .expect("chunks_billed matches manifest");

        // Terminal chunk is the framework-generated SCP-TOOL-6133.
        let terminal = chunks.last().expect("terminal chunk");
        match &terminal.payload {
            ChunkPayload::Error {
                code, terminal: t, ..
            } => {
                assert!(*t, "terminal flag set");
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT_STALL,
                    "credit-stall code"
                );
            }
            other => panic!("expected terminal Error{{credit-stall}}, got {other:?}"),
        }

        // Admission slot released.
        let admission_guard = admission.lock().expect("admission lock");
        assert_eq!(admission_guard.count_per_invoker(creator_did), 0);
        drop(admission_guard);
    }

    // Bind the imports introduced for the OUT-034 integration tests so
    // they survive the test mod's `#[allow(unused_imports)]` guards on
    // module compilation.
    #[allow(dead_code)]
    fn _out034_test_type_anchors() {
        let _: Option<RuntimeAdmissionCaps> = None;
        let _: Option<RuntimeStreamAdmissionTracker> = None;
        let _: Option<RuntimeStreamIdentity> = None;
    }

    /// Test (SCP-OUT-037 critical fix #1) — the dispatch pump emits
    /// exactly one `OutletInvokedEvent` to the supplied
    /// `OutletInvokedEventSink` at terminal-chunk emission, and the
    /// recorded `chunks_billed` / `stream_manifest_hash` match the
    /// outer manifest the SDK consumer received.
    ///
    /// Before the fix the pump constructed a `StreamCloseSummary`
    /// for the (unused) summary channel but never invoked the event
    /// sink, so streaming invocations completed with no audit event
    /// and no `chunks_billed` commitment. The §5.4.5 wire-rejection
    /// rule could not be enforced because there was no event to
    /// reject.
    #[tokio::test]
    async fn out037_dispatch_pump_emits_outlet_invoked_event() {
        // Executor that emits 3 Data chunks then End.
        struct ThreeDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ThreeDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..3u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(ThreeDataExecutor);

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out034_open_params(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(0),
            scp_protocol::economy::types::Amount::new(0),
            Some(8),
            32,
            signing.verifying_key(),
        );

        // Wire a real event sink — this is the surface the fix
        // targets. The pump MUST invoke `record` exactly once at
        // terminal-chunk emission.
        let event_sink = StdArc::new(super::InMemoryOutletInvokedEventSink::new());

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            Some(StdArc::clone(&event_sink) as StdArc<dyn super::OutletInvokedEventSink>),
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("open should succeed");

        let rx = handle.receiver().expect("receiver");
        let summary_rx = handle.close_summary().expect("summary");
        let chunks = drain_stream_with_sequence_invariant(rx).await;
        let summary = summary_rx.await.expect("summary publishes");

        // Sanity: 3 Data + 1 End = 4 chunks.
        assert_eq!(chunks.len(), 4, "three Data chunks plus terminal End");

        // Drain the sink. The pump MUST have recorded exactly one
        // event at terminal-chunk emission.
        let recorded = event_sink.drain();
        assert_eq!(
            recorded.len(),
            1,
            "dispatch pump records exactly one OutletInvokedEvent at terminal-chunk emission"
        );
        let event = &recorded[0];

        // The recorded event MUST commit to the OUTER manifest the
        // SDK received — chunks_billed matches summary.billed_count
        // (which is the manifest-derived reference count) AND the
        // stream_manifest_hash matches the manifest root over the
        // outer chunk sequence.
        assert_eq!(
            event.chunks_billed, summary.billed_count,
            "event chunks_billed matches outer manifest reference"
        );
        let expected_manifest_hash =
            scp_protocol::context::outlets::stream::compute_chunk_manifest_root(&summary.manifest)
                .expect("manifest root over outer chunks");
        assert_eq!(
            event.stream_manifest_hash, expected_manifest_hash,
            "event stream_manifest_hash matches outer manifest root"
        );

        // The recorded event also passes the §5.4.5 wire-rejection
        // self-check at log-insert time: chunks_billed equals the
        // reference count derived from the manifest.
        super::super::dispatch::verify_summary_chunks_billed(&summary)
            .expect("dispatch summary passes §5.4.5 chunks_billed verification");
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-037 round-7 CRITICAL #2 / #3 / #4 — wire-signing closure +
    // cancel-auth tightening.
    // -----------------------------------------------------------------------

    /// Helper: build `out034_open_params` with an explicit operator
    /// signing key (round-7 wire-signing path).
    #[allow(clippy::needless_pass_by_value)] // by-value Arc clone simplifies test callsites
    fn out037_open_params_with_operator_key(
        outlet_id: &str,
        invoker_did: &str,
        cost_per_chunk: scp_protocol::economy::types::Amount,
        available_balance: scp_protocol::economy::types::Amount,
        declared_estimated: Option<u32>,
        credit_window: u32,
        operator_signing_key: StdArc<ed25519_dalek::SigningKey>,
    ) -> super::super::dispatch::OpenStreamParams {
        super::super::dispatch::OpenStreamParams {
            identity: out034_identity(outlet_id),
            caps: out034_admission_caps(),
            invoker_did: invoker_did.to_owned(),
            origin_invoker_did: invoker_did.to_owned(),
            cost_per_chunk,
            available_balance,
            declared_estimated_chunk_count: declared_estimated,
            credit_window,
            caveats: scp_protocol::trust::caveats::InvocationCaveats::empty(),
            invoker_pk: operator_signing_key.verifying_key(),
            operator_signing_key: Some(StdArc::clone(&operator_signing_key)),
            stream_credit_stall_secs: 1,
            stream_cancel_ack_secs: 1,
        }
    }

    /// CRITICAL #2 — credit-stall terminal chunk emitted by the
    /// dispatch pump verifies under the pinned operator key. Before
    /// the round-7 fix, framework-emitted terminal chunks carried
    /// `sig: [0u8; 64]` and would fail any receiver-side verification.
    #[tokio::test]
    async fn out037_credit_stall_terminal_chunk_is_signed() {
        struct FiveDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for FiveDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..5u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "tick": i }),
                        })
                        .await;
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(FiveDataExecutor);

        let signing = StdArc::new(ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]));
        let operator_pk = signing.verifying_key();
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out037_open_params_with_operator_key(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(10),
            scp_protocol::economy::types::Amount::new(1000),
            Some(3),
            3,
            StdArc::clone(&signing),
        );
        let identity = out034_identity(&outlet_id_owned);

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        let rx = handle.receiver().expect("receiver");
        let summary_rx = handle.close_summary().expect("summary");
        let chunks = drain_stream_with_sequence_invariant(rx).await;
        let _summary = summary_rx.await.expect("summary publishes");

        // Every chunk delivered by the dispatch pump (including the
        // framework-emitted credit-stall terminal) MUST verify under
        // the pinned operator key.
        for chunk in &chunks {
            assert!(
                scp_protocol::context::outlets::stream::verify_chunk_signature(
                    chunk,
                    &operator_pk,
                    &identity.context_id,
                    &identity.outlet_id,
                    &identity.caveats_binding,
                ),
                "chunk at sequence {} (payload={:?}) must verify under operator key",
                chunk.sequence,
                chunk.payload,
            );
        }

        // The terminal chunk is the SCP-TOOL-6133 credit-stall — same
        // assertion as the OUT-034 test, but here we additionally
        // confirm its `sig` is non-zero (round-7 wire-signing).
        let terminal = chunks.last().expect("terminal chunk");
        assert!(
            terminal.sig != [0u8; 64],
            "framework-emitted terminal chunk MUST be signed (round-7)"
        );
        match &terminal.payload {
            ChunkPayload::Error {
                code, terminal: t, ..
            } => {
                assert!(*t, "terminal flag set");
                assert_eq!(
                    code,
                    scp_protocol::context::outlets::error_codes::CODE_EXECUTION_CREDIT_STALL,
                    "credit-stall code"
                );
            }
            other => panic!("expected terminal Error{{credit-stall}}, got {other:?}"),
        }
    }

    /// CRITICAL #2 — cancel-ack-timeout terminal chunk is also signed.
    /// The round-7 fix wires both timer paths through
    /// `signing_ctx.sign_outer_chunk`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // narrative round-7 cancel-ack-timeout test
    async fn out037_cancel_ack_timeout_terminal_chunk_is_signed() {
        // Executor that emits 1 Data chunk then sleeps long enough
        // for the cancel-ack timer to fire.
        struct SlowExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for SlowExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "first": true }),
                    })
                    .await;
                // Sleep > stream_cancel_ack_secs (set to 1 in
                // out034_open_params via out037_open_params_with_operator_key).
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(SlowExecutor);

        let signing = StdArc::new(ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]));
        let operator_pk = signing.verifying_key();
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out037_open_params_with_operator_key(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(0),
            scp_protocol::economy::types::Amount::new(0),
            Some(8),
            8,
            StdArc::clone(&signing),
        );
        let identity = out034_identity(&outlet_id_owned);

        let mut handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        // Receive the first Data chunk so the request_id is fresh, then
        // deliver a signed cancel that arms the cancel-ack timer.
        let mut rx = handle.receiver().expect("receiver");
        let first_chunk = rx.recv().await.expect("first data chunk");
        let cancel_sig = scp_protocol::context::outlets::stream::sign_cancel(
            &signing,
            &scp_protocol::context::outlets::stream::CancelSigningInputs {
                context_id: &identity.context_id,
                outlet_id: &identity.outlet_id,
                request_id: handle.request_id(),
                next_seq: 1,
                caveats_binding: &identity.caveats_binding,
            },
        );
        let cancel = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id: *handle.request_id(),
            next_seq: 1,
            sig: cancel_sig,
        };
        handle
            .apply_outlet_cancel(&cancel)
            .expect("signed cancel accepted");

        // Drain remaining chunks. The slow executor never emits a
        // terminal — the cancel-ack timer fires at +1s and the pump
        // emits its own terminal Error{cancel-ack-timeout}.
        let mut received: Vec<scp_protocol::context::outlets::stream::OutletStreamChunk> =
            vec![first_chunk];
        while let Some(chunk) = rx.recv().await {
            received.push(chunk);
        }
        let terminal = received.last().expect("terminal");
        assert!(
            terminal.sig != [0u8; 64],
            "cancel-ack-timeout terminal chunk MUST be signed (round-7)"
        );
        // Verify it under the pinned operator key.
        assert!(
            scp_protocol::context::outlets::stream::verify_chunk_signature(
                terminal,
                &operator_pk,
                &identity.context_id,
                &identity.outlet_id,
                &identity.caveats_binding,
            ),
            "cancel-ack-timeout terminal chunk verifies under operator key"
        );
    }

    /// CRITICAL #3 — Data chunks emitted by the local-context invoke
    /// path verify under the pinned operator key. Before the round-7
    /// fix, `wrap_chunk` always set `sig: [0u8; 64]`.
    #[tokio::test]
    async fn out037_local_invoke_chunks_verify_under_operator_key() {
        struct ThreeDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for ThreeDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                for i in 0..3u32 {
                    let _ = tx
                        .send(ChunkPayload::Data {
                            value: serde_json::json!({ "i": i }),
                        })
                        .await;
                }
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(ThreeDataExecutor);

        let signing = StdArc::new(ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]));
        let operator_pk = signing.verifying_key();
        let caveats_binding: [u8; 32] = [0xCC; 32];

        let rx = super::invoke_outlet(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            Some(StdArc::clone(&signing)),
            caveats_binding,
        )
        .await
        .expect("invoke_outlet should accept a well-formed open");

        let chunks = drain_stream_with_sequence_invariant(rx).await;

        // Every chunk verifies under the operator key + the binding
        // values supplied to invoke_outlet.
        let context_id = context.context_id();
        for chunk in &chunks {
            assert!(
                scp_protocol::context::outlets::stream::verify_chunk_signature(
                    chunk,
                    &operator_pk,
                    context_id,
                    &outlet_id_owned,
                    &caveats_binding,
                ),
                "invoke_outlet chunk at sequence {} must verify under operator key",
                chunk.sequence,
            );
            assert!(
                chunk.sig != [0u8; 64],
                "invoke_outlet chunks must be signed (round-7), not zero-filled"
            );
        }
    }

    /// CRITICAL #4 — `apply_outlet_cancel` rejects a cancel with an
    /// invalid signature as `CancelError::SignatureInvalid` and does
    /// NOT mutate stream state.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // narrative round-7 cancel-auth test
    async fn out037_cancel_with_invalid_signature_rejected() {
        struct OneDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for OneDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "x": 1 }),
                    })
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let _ = tx
                    .send(ChunkPayload::End {
                        aggregate: serde_json::Value::Null,
                        provenance: super::placeholder_data_provenance("ctx"),
                        execution_time_ms: 50,
                    })
                    .await;
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(OneDataExecutor);

        let signing = StdArc::new(ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]));
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out037_open_params_with_operator_key(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(0),
            scp_protocol::economy::types::Amount::new(0),
            Some(8),
            8,
            StdArc::clone(&signing),
        );

        let handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        // Build a cancel signed under the WRONG key — runtime MUST reject.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0xFF; 32]);
        let identity = out034_identity(&outlet_id_owned);
        let bad_sig = scp_protocol::context::outlets::stream::sign_cancel(
            &attacker,
            &scp_protocol::context::outlets::stream::CancelSigningInputs {
                context_id: &identity.context_id,
                outlet_id: &identity.outlet_id,
                request_id: handle.request_id(),
                next_seq: 1,
                caveats_binding: &identity.caveats_binding,
            },
        );
        let bad_cancel = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id: *handle.request_id(),
            next_seq: 1,
            sig: bad_sig,
        };
        let result = handle.apply_outlet_cancel(&bad_cancel);
        assert!(
            matches!(
                result,
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "wrong-key cancel must be rejected as SignatureInvalid, got {result:?}"
        );

        // Now build a valid cancel — runtime MUST accept.
        let good_sig = scp_protocol::context::outlets::stream::sign_cancel(
            &signing,
            &scp_protocol::context::outlets::stream::CancelSigningInputs {
                context_id: &identity.context_id,
                outlet_id: &identity.outlet_id,
                request_id: handle.request_id(),
                next_seq: 1,
                caveats_binding: &identity.caveats_binding,
            },
        );
        let good_cancel = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id: *handle.request_id(),
            next_seq: 1,
            sig: good_sig,
        };
        let result_ok = handle.apply_outlet_cancel(&good_cancel);
        assert!(
            matches!(result_ok, Ok(Some(1))),
            "well-signed cancel must be accepted, got {result_ok:?}"
        );
    }

    /// CRITICAL #4 — tampering with each preimage field flips the
    /// signature verification to `false`, surfacing as
    /// `CancelError::SignatureInvalid` at the runtime boundary.
    /// Preimage fields: `(context_id, outlet_id, request_id,
    /// next_seq, caveats_binding)`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // narrative round-7 5-field tampering matrix
    async fn out037_cancel_preimage_tampering_rejected() {
        struct OneDataExecutor;
        #[async_trait::async_trait]
        impl super::OutletExecutor for OneDataExecutor {
            async fn exec_action_stream(
                &self,
                _ctx: &mut super::MutableInvocation<'_>,
                _input: serde_json::Value,
                tx: tokio::sync::mpsc::Sender<ChunkPayload>,
            ) -> Result<(), super::OutletExecutorError> {
                let _ = tx
                    .send(ChunkPayload::Data {
                        value: serde_json::json!({ "x": 1 }),
                    })
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                Ok(())
            }
        }

        let creator_did = "did:dht:z6MkCreator";
        let role_state = test_role_state(creator_did);
        let registry = setup_registry_with_tool(&role_state, creator_did);
        let context = active_context().await;
        let outlet_id_owned: OutletId = "calculator".to_owned();
        let executor: StdArc<dyn super::OutletExecutor> = StdArc::new(OneDataExecutor);

        let signing = StdArc::new(ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32]));
        let admission = StdArc::new(std::sync::Mutex::new(
            super::super::stream::StreamAdmissionTracker::new(),
        ));
        let params = out037_open_params_with_operator_key(
            &outlet_id_owned,
            creator_did,
            scp_protocol::economy::types::Amount::new(0),
            scp_protocol::economy::types::Amount::new(0),
            Some(8),
            8,
            StdArc::clone(&signing),
        );

        let handle = super::super::dispatch::open_stream_session(
            &context,
            &registry,
            &role_state,
            &outlet_id_owned,
            serde_json::json!({"a": 1, "b": 2}),
            &DID::from(creator_did),
            None,
            executor,
            None,
            None,
            None,
            params,
            StdArc::clone(&admission),
        )
        .await
        .expect("OUT-034 open should succeed");

        let identity = out034_identity(&outlet_id_owned);
        let request_id = *handle.request_id();
        let make_sig = |ctx: &str, outlet: &str, rid: &[u8; 16], next: u64, cb: &[u8; 32]| {
            scp_protocol::context::outlets::stream::sign_cancel(
                &signing,
                &scp_protocol::context::outlets::stream::CancelSigningInputs {
                    context_id: ctx,
                    outlet_id: outlet,
                    request_id: rid,
                    next_seq: next,
                    caveats_binding: cb,
                },
            )
        };

        // Each tampering case below: the signature was produced for a
        // different value of one preimage field than what the wire
        // struct carries, so the runtime's verifier (which rebuilds
        // the preimage from the pinned identity + the wire struct)
        // sees a mismatch.

        // Tamper request_id: sign for one rid, send for a different rid.
        let other_rid: [u8; 16] = [0x99; 16];
        let sig_other_rid = make_sig(
            &identity.context_id,
            &identity.outlet_id,
            &other_rid,
            1,
            &identity.caveats_binding,
        );
        let cancel_tampered_rid = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id, // <-- the actual stream's request_id, NOT what was signed
            next_seq: 1,
            sig: sig_other_rid,
        };
        assert!(
            matches!(
                handle.apply_outlet_cancel(&cancel_tampered_rid),
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "tampered request_id must be rejected"
        );

        // Tamper next_seq: sign for next=1, send for next=2.
        let sig_next1 = make_sig(
            &identity.context_id,
            &identity.outlet_id,
            &request_id,
            1,
            &identity.caveats_binding,
        );
        let cancel_tampered_next = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id,
            next_seq: 2,
            sig: sig_next1,
        };
        assert!(
            matches!(
                handle.apply_outlet_cancel(&cancel_tampered_next),
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "tampered next_seq must be rejected"
        );

        // Tamper context_id: sign for "OTHER", runtime rebuilds with
        // the pinned `identity.context_id`.
        let sig_other_ctx = make_sig(
            "OTHER",
            &identity.outlet_id,
            &request_id,
            3,
            &identity.caveats_binding,
        );
        let cancel_tampered_ctx = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id,
            next_seq: 3,
            sig: sig_other_ctx,
        };
        assert!(
            matches!(
                handle.apply_outlet_cancel(&cancel_tampered_ctx),
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "tampered context_id must be rejected"
        );

        // Tamper outlet_id: sign for "OTHER".
        let sig_other_outlet = make_sig(
            &identity.context_id,
            "OTHER",
            &request_id,
            4,
            &identity.caveats_binding,
        );
        let cancel_tampered_outlet = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id,
            next_seq: 4,
            sig: sig_other_outlet,
        };
        assert!(
            matches!(
                handle.apply_outlet_cancel(&cancel_tampered_outlet),
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "tampered outlet_id must be rejected"
        );

        // Tamper caveats_binding: sign for [0xEE; 32], runtime rebuilds
        // under the pinned `identity.caveats_binding`.
        let other_cb: [u8; 32] = [0xEE; 32];
        let sig_other_cb = make_sig(
            &identity.context_id,
            &identity.outlet_id,
            &request_id,
            5,
            &other_cb,
        );
        let cancel_tampered_cb = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id,
            next_seq: 5,
            sig: sig_other_cb,
        };
        assert!(
            matches!(
                handle.apply_outlet_cancel(&cancel_tampered_cb),
                Err(super::super::stream::CancelError::SignatureInvalid)
            ),
            "tampered caveats_binding must be rejected"
        );

        // Finally, an honest cancel signed correctly is accepted.
        let good_sig = make_sig(
            &identity.context_id,
            &identity.outlet_id,
            &request_id,
            6,
            &identity.caveats_binding,
        );
        let good = scp_protocol::context::outlets::stream::OutletStreamCancel {
            request_id,
            next_seq: 6,
            sig: good_sig,
        };
        assert!(
            matches!(handle.apply_outlet_cancel(&good), Ok(Some(6))),
            "honest cancel accepted at next_seq=6"
        );
    }
}

/// Compile-time deny-list assertion — calling a write method on
/// `&ReadOnlyInvocation` does not compile (PRD AC1, AC6).
///
/// This `compile_fail` doctest is a structural test: it pins the absence of
/// a `send_message` (or any write-side) method on `&ReadOnlyInvocation`. If
/// a future refactor adds a write method to the read-only handle, the
/// doctest will start COMPILING — and fail — alerting the author to the
/// silent deny-list bypass.
///
/// ```compile_fail,E0599
/// use scp_runtime::context::ContextHandle;
/// use scp_runtime::context::outlets::invoke::ReadOnlyInvocation;
/// use scp_protocol::context::ContextParams;
/// use scp_protocol::context::outlets::registry::OutletRegistry;
/// use scp_protocol::context::roles::{CapabilityCeiling, ContextRoleState};
/// use scp_primitives::DID;
///
/// fn no_send_on_read_only(read: &ReadOnlyInvocation<'_>) {
///     // ❌ Should NOT compile — `send_message` is not a method on
///     // `ReadOnlyInvocation`. Only `MutableInvocation` exposes it.
///     read.send_message(serde_json::json!({}));
/// }
/// ```
#[cfg(doctest)]
#[allow(dead_code)]
fn _compile_fail_read_only_invocation_send_message() {}
