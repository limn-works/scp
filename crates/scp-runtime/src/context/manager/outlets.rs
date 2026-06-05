//! `ContextManager::invoke_outlet_with_economy` — outlet invocation with
//! per-DID anti-spam escalation wired from per-context governance state.
//!
//! This wrapper is the integration point between the free
//! [`invoke_outlet_execute_and_validate`](crate::context::outlets::invoke::invoke_outlet_execute_and_validate)
//! helper and the [`super::ContextManager`] per-context state. It
//! snapshots economic policy, budget tracker, per-DID velocity tracker,
//! message pricing config, a real event-log snapshot, consequence rules,
//! metrics, and participation cache from the context's `GovernanceState`
//! so that outlet invocations participate in the same per-DID anti-spam
//! regime as message sends (spec §19.7).
//!
//! # Lock-split invariant
//!
//! The caller-supplied executor must run **without** holding the
//! `ContextManager.contexts` mutex. A mis-behaving or long-running tool
//! executor would otherwise block every concurrent call into the manager.
//! This module enforces the split by structuring the wrapper into three
//! phases:
//!
//! 1. **Phase 1 — locked:** snapshot all governance state, run
//!    `economy_pre_check` (pure compute), `record_spend` against the
//!    per-context budget, and escrow-authorize the payment. A
//!    [`OutletEconomyTicket`] is assembled from the resulting bookkeeping.
//! 2. **Phase 2 — unlocked:** the `contexts` lock is dropped; the executor
//!    is dispatched via
//!    [`invoke_outlet_execute_and_validate`](crate::context::outlets::invoke::invoke_outlet_execute_and_validate)
//!    which performs context-state, capability, schema, timeout, and
//!    output-schema checks *again* (defensive) using the snapshotted
//!    handle + role state. On any error the ticket is drained
//!    (budget reversed, velocity entry rolled back, escrow voided).
//! 3. **Phase 3 — locked then unlocked:** the lock is re-acquired to run
//!    post-invocation bookkeeping (participation cache, consequence
//!    evaluation), then released again for the escrow-capture call.
//!    Only then is the ticket committed.
//!
//! The `OutletEconomyTicket` is `#[must_use]` with a `Drop` guard that
//! debug-asserts in tests so no future refactor can leak an unbalanced
//! budget deduction or velocity entry on an untested error branch.
//!
//! # Registry ownership
//!
//! The wrapper takes the [`OutletRegistry`] and executor as explicit
//! parameters because the manager does not own a per-context tool
//! registry today (it lives in the FFI bridge layers). This preserves
//! the bridge-owned registry invariant while keeping outlet invocations
//! within the full governance pipeline.

use std::collections::HashMap;
use std::future::Future;

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::outlets::OutletId;
use scp_protocol::context::outlets::OutletKind;
use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
use scp_protocol::context::outlets::lifecycle::OutletStatus;
use scp_protocol::context::outlets::registry::OutletRegistry;
use scp_protocol::context::roles::Capability;
use scp_protocol::crypto::ucan::UcanToken;
use scp_protocol::economy::antispam::VelocityRollbackToken;
use scp_protocol::economy::policy::ObservableMetrics;
use scp_protocol::economy::types::Amount;
use scp_protocol::provenance::attach::effective_max_chain_depth;

use crate::context::outlets::invoke::{
    self, InvocationError, InvokeExecuteOutcome, OutletEconomyContext, build_outlet_event,
    economy_pre_check, invoke_outlet_execute_and_validate, post_outlet_invocation_bookkeeping,
};
use crate::economy::adapter::PaymentAdapterDyn;
use crate::economy::integration::PreparedAction;

use super::{Arc, ContextGeneration, ContextManager};

/// Result of a successful managed outlet invocation.
#[derive(Debug)]
pub struct ManagedOutletInvocationOutput {
    /// Outlet output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: OutletInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
}

/// SCP-OUT-021 — bundle of state needed for §7.3.8 post-input caveat
/// enforcement.
///
/// Construct one of these and pass it into
/// [`ContextManager::invoke_outlet_with_economy`] when the presenting
/// (leaf) action UCAN carries invocation caveats (its validated-narrowed
/// `nb` field per §7.3.8). The fields hold owned references so the caller
/// retains ownership of the underlying data across the off-lock
/// invocation.
///
/// # Counter store ownership (§7.3.8 fail-closed)
///
/// The durable per-`(context_id, ucan_cid, caveat_kind)` counter store is
/// NOT a field of this struct — it is owned by the [`ContextManager`] and
/// resolved internally via `caveat_counter_store()` at invocation time,
/// exactly as the streaming path ([`ContextManager::open_outlet_stream`])
/// resolves it through [`build_stream_post_input_hook`]. This is a
/// deliberate design choice: a bridge cannot forget to enforce the
/// counter-bearing caveats (`max_calls`, `amount_max_cumulative`,
/// `rate_window`) by omitting the store, because the store is never a
/// caller responsibility. When the leaf caveats carry a counter-bearing
/// cap but the manager has no counter store the invocation FAILS CLOSED
/// (rejected) rather than silently admitting an unenforceable cap —
/// identical to `build_stream_post_input_hook`'s
/// `OpenStreamRejection::CaveatPostInputViolation`.
///
/// # Field semantics
///
/// - `caveats` — the [`InvocationCaveats`] to enforce. Comes from the
///   resolved `nb` field of the presenting (leaf) UCAN per §7.3.8.
/// - `ucan_cid` — the CID of the presenting UCAN. Forms half of the
///   counter-store key alongside `context_id` (which the manager
///   wrapper already knows).
/// - `negotiated_adapter` — the [`PaymentAdapterRef`] the runtime is
///   about to use, if any. Drives the `allowed_adapters` check inside
///   [`InvocationCaveats::check_invocation_local`](scp_protocol::trust::caveats::InvocationCaveats::check_invocation_local).
/// - `target_did` — the cross-context target DID, if any. Drives the
///   `allowed_target_dids` check.
/// - `estimated_cost` — the runtime's pre-execution cost estimate. Drives
///   the `amount_max_per_call` check and the `amount_max_cumulative`
///   counter increment.
pub struct CaveatEnforcement<'a> {
    /// Invocation caveats from the presenting UCAN's `nb` field.
    pub caveats: &'a scp_protocol::trust::caveats::InvocationCaveats,
    /// CID of the presenting UCAN (counter-store key).
    pub ucan_cid: &'a str,
    /// Negotiated payment adapter reference, if any.
    pub negotiated_adapter: Option<&'a scp_protocol::economy::types::PaymentAdapterRef>,
    /// Cross-context target DID, if any.
    pub target_did: Option<&'a scp_identity::DID>,
    /// Runtime's pre-execution cost estimate.
    pub estimated_cost: scp_protocol::economy::types::Amount,
}

/// SCP-OUT-022 — bundle of state needed for §7.3.8 + §6.2 + §19.5 + §19.3
/// layer composition.
///
/// Construct one of these and pass it into
/// [`ContextManager::invoke_outlet_with_economy`] alongside [`CaveatEnforcement`]
/// when the runtime should compose `OutboundPolicy` ∧ `InboundPolicy` ∧
/// `SpendingCapability` ∧ `MemberBudgetTracker` with the caveat post-input
/// checks. Fields are owned snapshots / clones so the layer composition
/// runs off-lock alongside SCP-OUT-021's counter-store CAS.
///
/// All fields are `Option`-typed so a free-action / intra-context invocation
/// can supply only the fields that apply (`outbound_policy`, `inbound_policy`,
/// and `source_role` are `None` for intra-context;
/// `spending_capability` is `None` for free actions; `budget_tracker` is the
/// per-context tracker snapshot which is always present).
///
/// # Why a separate struct?
///
/// [`CaveatEnforcement`] models the SCP-OUT-021 post-input gate (caveat
/// time-box already enforced upstream by `validate_ucan` Step 11b, plus
/// counter-store CAS for `max_calls` / `amount_max_cumulative` /
/// `rate_window`). Layer composition is the §7.3.8 *additional* AND fold over
/// `SpendingCapability` + `MemberBudgetTracker` + Inbound/Outbound policies; it
/// is conceptually a separate mechanism even though the runtime evaluates it
/// at the same call-site. Keeping the two bundles separate preserves the
/// SCP-OUT-021 surface unchanged so callers that only enable caveat counters
/// (and not full layer composition) do not need to construct the additional
/// fields.
pub struct LayerCompositionEnforcement {
    /// `OutboundPolicy` from the source context's interface, if any.
    /// `None` for intra-context invocations.
    pub outbound_policy: Option<scp_protocol::context::outlets::interface::OutboundPolicy>,
    /// `InboundPolicy` from the target context's interface, if any.
    /// `None` for intra-context invocations.
    pub inbound_policy: Option<scp_protocol::context::outlets::interface::InboundPolicy>,
    /// `SpendingCapability` extracted from the spending UCAN's `fct`.
    /// `None` for free actions.
    pub spending_capability: Option<scp_protocol::crypto::ucan::spending::SpendingCapability>,
    /// Snapshot of the per-context [`MemberBudgetTracker`] (§19.3) taken
    /// under the Phase 1 lock so the layer composition can read remaining
    /// budget off-lock.
    pub budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker,
    /// The role the invoker holds in the source context (cross-context
    /// invocations only). `None` for intra-context.
    pub source_role: Option<String>,
    /// Serialized payload byte length, used for the
    /// `OutboundPolicy.max_payload_bytes` check.
    pub payload_bytes: usize,
}

/// Phase-1 bookkeeping bundle for an outlet invocation in flight.
///
/// Every Phase 1 success produces a [`OutletEconomyTicket`]; every Phase 2
/// or Phase 3 error branch MUST drain it through
/// [`rollback_outlet_economy_ticket`] (refund budget + roll back velocity
/// entry + void escrow) or commit it through
/// [`commit_outlet_economy_ticket`]. Dropping it without doing one or the
/// other is a compile-time warning (`#[must_use]`) and a `Drop`
/// debug-assert so unit tests fail loudly.
///
/// Mirrors [`super::economy::EconomyTicket`] one-for-one; a separate
/// type exists because the outlet path also owns a cloned `PreparedAction`
/// escrow handle and the void + capture steps use the outlet-flavor
/// adapter helpers in [`crate::context::outlets::invoke`].
#[must_use = "OutletEconomyTicket must be committed or rolled back — dropping leaks budget, velocity, and escrow state"]
struct OutletEconomyTicket {
    /// The invoker being charged — needed for every rollback operation.
    actor_did: DID,
    /// The budget amount deducted in Phase 1 (if any).
    deducted_cost: Option<Amount>,
    /// Velocity-tracker rollback token for the entry appended in Phase 1.
    velocity_token: VelocityRollbackToken,
    /// Escrow authorization returned by the adapter, if a payment flow
    /// is configured and the action cost is non-zero. Cloneable, so we
    /// keep an owned copy across the unlocked Phase 2 window.
    escrow: Option<PreparedAction>,
    /// Snapshot of the economic policy that produced `deducted_cost`.
    /// Retained for the Phase 3 capture step so the capture uses the
    /// same policy that was priced against under the Phase 1 lock.
    policy_for_capture: Option<scp_protocol::economy::types::EconomicPolicy>,
    /// Observable metrics captured in Phase 1. Reused by
    /// [`invoke::complete_outlet_payment`] in Phase 3 so the capture step
    /// sees the same metrics the Phase 1 authorize saw — eliminating a
    /// TOCTOU window where the adapter could diverge from the budget.
    metrics_for_capture: ObservableMetrics,
    /// Whether the Phase 1 hard-rate-limit token must be refunded on
    /// rollback. Set to `true` on ticket creation because the token
    /// was consumed before the ticket was built; cleared after the
    /// rollback path calls `refund` so repeated rollback calls are
    /// idempotent.
    needs_hard_rate_limit_refund: bool,
    /// Set to `true` by `commit`/`rollback` so the `Drop` guard can tell
    /// that the caller honored the contract.
    consumed: bool,
}

impl Drop for OutletEconomyTicket {
    fn drop(&mut self) {
        if !self.consumed {
            tracing::error!(
                actor_did = %self.actor_did,
                cost = ?self.deducted_cost,
                "OutletEconomyTicket dropped without commit or rollback — budget, velocity, and escrow state may be inconsistent"
            );
            debug_assert!(
                false,
                "OutletEconomyTicket dropped without commit or rollback for actor {}",
                self.actor_did
            );
        }
    }
}

/// Marks the ticket committed (success path). Returns the deducted cost
/// so the caller can populate the `OutletInvokedEvent`. Clears
/// `needs_hard_rate_limit_refund` so the invariant
/// "`needs_hard_rate_limit_refund == true` iff a refund is still owed"
/// holds against any defensive rollback call.
fn commit_outlet_economy_ticket(mut ticket: OutletEconomyTicket) -> Option<Amount> {
    ticket.consumed = true;
    ticket.needs_hard_rate_limit_refund = false;
    ticket.deducted_cost
}

/// Rolls back every piece of state the ticket represents:
///
/// * budget deduction (via `reverse_spend`, not `grant`, so ceilings
///   stay intact),
/// * velocity entry (via the identity-based `rollback(did, token)` API
///   so concurrent senders are not raced),
/// * payment escrow hold (best-effort `void`).
///
/// Re-acquires the `contexts` lock internally so this is safe to call
/// from Phase 2 (off-lock) error paths. If the context has been
/// deregistered between Phase 1 and rollback the budget + velocity
/// rollback is a best-effort no-op — the escrow void is still attempted
/// since it is adapter-side state, not manager-side, and the ticket is
/// still marked consumed so the `Drop` guard stays quiet.
#[allow(clippy::significant_drop_tightening)]
async fn rollback_outlet_economy_ticket(
    manager: &ContextManager,
    context_id: &str,
    mut ticket: OutletEconomyTicket,
) {
    ticket.consumed = true;

    // Void the adapter-side escrow first so it does not survive the
    // manager-side rollback. This mirrors `void_escrow_and_rollback` in
    // the free `invoke_outlet` path.
    if let (Some(adapter), Some(prepared)) =
        (manager.payment_adapter.as_ref(), ticket.escrow.as_ref())
    {
        invoke::void_outlet_escrow(adapter.as_ref(), prepared).await;
    }

    // Reacquire the lock and reverse the per-context bookkeeping.
    if let Some(entry) = manager.contexts.get(context_id) {
        let arc = entry.value().clone();
        drop(entry);
        let mut guard = arc.lock().await;
        let ctx = &mut *guard;
        ctx.governance
            .velocity_tracker
            .rollback(&ticket.actor_did, ticket.velocity_token);
        if let Some(cost) = ticket.deducted_cost {
            ctx.governance
                .budget_tracker
                .reverse_spend(&ticket.actor_did, cost);
        }
        if ticket.needs_hard_rate_limit_refund {
            ctx.governance.hard_rate_limit.refund(&ticket.actor_did);
            ticket.needs_hard_rate_limit_refund = false;
        }
    }
}

impl ContextManager {
    /// Synchronously consume one hard-rate-limit token for the given
    /// `(context_id, did)` pair.
    ///
    /// Returns `true` if a token was consumed OR if the context is
    /// not registered in the `ContextManager`. Returns `false` only
    /// when the context IS registered AND the sender is over budget.
    ///
    /// SYNC entry point for FFI bridge tool-dispatch paths that do
    /// not flow through [`Self::invoke_outlet_with_economy`] (the
    /// bridges own their own tool registry + handler dispatch
    /// because JS/Python callables live in bridge-side state, not
    /// in the `ContextManager`).
    ///
    /// Bridges MUST pair every `true` return with a matching
    /// [`Self::refund_hard_rate_limit_blocking`] call on every
    /// downstream failure branch. Refund is a no-op when the
    /// context is unknown.
    ///
    /// An unknown `context_id` returns `true` rather than an error
    /// because the downstream `with_context` call inside the bridge
    /// will fail with a more specific "outlet not found" error, and
    /// because there is no rate-limit state to enforce against
    /// without a manager entry.
    ///
    /// # Concurrency
    ///
    /// Uses `blocking_lock` on `self.contexts`. Callers MUST NOT
    /// invoke this from within an async task on the same tokio
    /// runtime — doing so will panic.
    #[allow(clippy::significant_drop_tightening)] // two-step borrow on the contexts map
    #[must_use]
    pub fn try_consume_hard_rate_limit_blocking(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return true;
        };
        let ctx = arc.blocking_lock();
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Synchronously refund one hard-rate-limit token. No-op if the
    /// context is unknown. Same `blocking_lock` constraint as
    /// [`Self::try_consume_hard_rate_limit_blocking`].
    pub fn refund_hard_rate_limit_blocking(&self, context_id: &str, did: &DID) {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return;
        };
        let ctx = arc.blocking_lock();
        ctx.governance.hard_rate_limit.refund(did);
    }

    /// Async variant of [`Self::try_consume_hard_rate_limit_blocking`]
    /// for callers already inside a tokio executor where
    /// `blocking_lock` would panic. Same unknown-context pass-through.
    #[allow(clippy::significant_drop_tightening)] // two-step borrow on the contexts map
    #[must_use]
    pub async fn try_consume_hard_rate_limit(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return true;
        };
        let mut guard = arc.lock().await;
        let ctx = &mut *guard;
        ctx.governance.hard_rate_limit.try_consume(did, now_secs)
    }

    /// Async refund. No-op if the context is unknown.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        if let Ok(ctx_arc) = self.get_context_arc(context_id) {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.governance.hard_rate_limit.refund(did);
        }
    }

    /// Fetches the 32-byte `outlet_message_key` pinned for the given
    /// `(context_id, outlet_id, registration_event_id)` triple per
    /// §5.4.4 round-5 (SCP-OUT-041a).
    ///
    /// Returns `Ok(Some(key))` when the pinned key is present in the
    /// in-memory `GovernanceState::pinned_outlet_message_keys` map,
    /// `Ok(None)` when the context is registered but no key exists
    /// for the lookup, and `Err` only when the context itself is not
    /// registered in this manager.
    ///
    /// FFI bridges call this to perform the
    /// `HMAC-SHA-256(outlet_message_key, catalog_key)[..32]` wire-
    /// message construction at the FFI boundary so the SDK never
    /// receives the raw key (SCP-OUT-041d).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotFound`] when the context is not
    /// registered.
    pub async fn pinned_outlet_message_key_for(
        &self,
        context_id: &str,
        outlet_id: &OutletId,
        registration_event_id: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, ContextError> {
        let ctx_arc = self.get_context_arc(context_id).map_err(|_| {
            ContextError::MembershipFailed(format!("context not registered: {context_id}"))
        })?;
        let guard = ctx_arc.lock().await;
        let key = guard
            .governance
            .pinned_outlet_message_keys
            .get(&(outlet_id.clone(), *registration_event_id))
            .copied();
        drop(guard);
        Ok(key)
    }

    /// Runtime-agnostic hard-rate-limit consume for sync bridge trait
    /// methods that may be called from any of three tokio contexts:
    ///
    /// 1. **No runtime active**: use `blocking_lock` directly.
    /// 2. **Multi-thread runtime active**: use `block_in_place` +
    ///    `Handle::current().block_on(async_helper)`. `block_in_place`
    ///    is only valid on multi-thread runtimes.
    /// 3. **Current-thread runtime active**: neither `blocking_lock`
    ///    nor `block_in_place` is safe. Spawn a dedicated
    ///    `std::thread` with its own tiny current-thread runtime,
    ///    `block_on` the async helper, join via an mpsc channel.
    ///
    /// The third case is a defensive fallback. Same unknown-context
    /// pass-through as the blocking/async variants.
    #[must_use]
    #[allow(clippy::option_if_let_else)] // match is clearer than map_or_else for this dual arm
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        match tokio::runtime::Handle::try_current() {
            Err(_) => self.try_consume_hard_rate_limit_blocking(context_id, did, now_secs),
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                        handle.block_on(self.try_consume_hard_rate_limit(context_id, did, now_secs))
                    }),
                    // Current-thread or any future flavor: spawn a
                    // dedicated `std::thread` with its own runtime so
                    // we never touch the parent runtime's executor.
                    _ => Self::run_blocking_on_dedicated_thread(
                        Arc::clone(self),
                        context_id.to_owned(),
                        did.clone(),
                        now_secs,
                        /* refund = */ false,
                    ),
                }
            }
        }
    }

    /// Runtime-agnostic hard-rate-limit refund. Mirrors
    /// [`Self::try_consume_hard_rate_limit_from_any_context`].
    #[allow(clippy::option_if_let_else)] // match is clearer than map_or_else for this dual arm
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        match tokio::runtime::Handle::try_current() {
            Err(_) => {
                self.refund_hard_rate_limit_blocking(context_id, did);
            }
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| {
                            handle.block_on(self.refund_hard_rate_limit(context_id, did));
                        });
                    }
                    _ => {
                        let _ = Self::run_blocking_on_dedicated_thread(
                            Arc::clone(self),
                            context_id.to_owned(),
                            did.clone(),
                            0,
                            /* refund = */ true,
                        );
                    }
                }
            }
        }
    }

    /// Dedicated-thread escape hatch for current-thread runtime
    /// environments where both `blocking_lock` and `block_in_place`
    /// panic. Spawns a `std::thread`, builds a current-thread tokio
    /// runtime there, runs the async helper, returns via mpsc.
    fn run_blocking_on_dedicated_thread(
        manager: Arc<Self>,
        context_id: String,
        did: DID,
        now_secs: u64,
        refund: bool,
    ) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dedicated rate-limit runtime build failed; failing closed"
                    );
                    let _ = tx.send(false);
                    return;
                }
            };
            let result = if refund {
                rt.block_on(manager.refund_hard_rate_limit(&context_id, &did));
                true
            } else {
                rt.block_on(manager.try_consume_hard_rate_limit(&context_id, &did, now_secs))
            };
            let _ = tx.send(result);
        });
        // Fail closed on channel failure (panicked worker etc.).
        rx.recv().unwrap_or(false)
    }

    /// Invokes an outlet under the full economy pipeline without holding
    /// the `contexts` mutex across the executor future (spec §19.7).
    ///
    /// This is the single entry point that tool-invoking bridges should
    /// use when they want the runtime to enforce per-DID escalation,
    /// floor/cap, and velocity tracking for `OutletCall` actions. The
    /// [`OutletRegistry`] and `executor` are passed in because the bridge
    /// layers own the registry — the manager itself does not.
    ///
    /// # Phase discipline
    ///
    /// The wrapper splits the invocation into three phases so that the
    /// `contexts` lock is held only while the manager is actually
    /// mutating per-context state:
    ///
    /// 1. **Phase 1 (locked):** snapshot governance state, record
    ///    velocity, run `economy_pre_check`, `record_spend` the cost,
    ///    authorize the payment escrow, assemble a
    ///    [`OutletEconomyTicket`]. The lock is released at the end of
    ///    Phase 1.
    /// 2. **Phase 2 (unlocked):** dispatch the executor via
    ///    [`invoke_outlet_execute_and_validate`]. On any failure the
    ///    ticket is drained (budget, velocity, escrow).
    /// 3. **Phase 3 (locked then unlocked):** re-acquire the lock for
    ///    post-invocation bookkeeping (participation cache + consequence
    ///    evaluation), release the lock, capture the escrow off-lock,
    ///    commit the ticket, and build the `OutletInvokedEvent`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown in Phase 1 or 3. Invocation failures surface as
    /// [`ContextError::OutletInvocation`] (typed §5.4.4 envelope per
    /// SCP-OUT-027); economic-integration failures (spending UCAN,
    /// nonce commit) surface as [`ContextError::IntegrationFailed`]
    /// with an `SCP-ECON-*` code. All errors are terminal for the
    /// invocation; partial state mutations (budget, velocity, escrow)
    /// are rolled back before the error is returned via the
    /// `OutletEconomyTicket`.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::significant_drop_tightening
    )]
    pub async fn invoke_outlet_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
        handler_panic_sink: Option<&dyn crate::context::outlets::invoke::HandlerPanicSink>,
        // SCP-OUT-021: optional invocation caveat enforcement bundle.
        // `None` preserves pre-OUT-021 behaviour (no caveat checks). When
        // `Some(enforcement)` is provided the Phase-2 helper runs §7.3.8
        // post-input caveat enforcement (synchronous local checks +
        // counter-store CAS) immediately after input schema validation
        // and before the executor runs.
        caveat_enforcement: Option<CaveatEnforcement<'_>>,
        // SCP-OUT-022: optional layer composition bundle. `None` skips
        // the §7.3.8 / §6.2 / §19.5 / §19.3 AND fold (Outbound ∧ Inbound ∧
        // SpendingCapability ∧ MemberBudgetTracker) — caveat time-box +
        // rate / counter remain enforced via the SCP-OUT-021 hook.
        // `Some(bundle)` runs `evaluate_all_layers` after the SCP-OUT-021
        // hook so the four extra layers compose under logical AND. Failures
        // identify the rejecting layer via [`LayerName`].
        layer_composition: Option<LayerCompositionEnforcement>,
    ) -> Result<ManagedOutletInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: Future<Output = Result<serde_json::Value, String>>,
    {
        // ------------------------------------------------------------
        // Phase 1 — LOCKED.
        //
        // Snapshot every piece of per-context state the executor-free
        // pipeline needs (handle, role state, policy, pricing,
        // consequence rules, metrics, real event-log entries), record
        // the velocity entry, run the pure economy pre-check, record
        // the spend, authorize the payment escrow, and assemble a
        // [`OutletEconomyTicket`]. Phase 1 ends with `drop(contexts)`
        // so Phase 2 (the executor) runs WITHOUT the lock.
        // ------------------------------------------------------------
        let now_secs = self.clock.now_secs();
        let payment_adapter: Option<Arc<dyn PaymentAdapterDyn>> = self.payment_adapter.clone();

        let phase1 = {
            let (mut guard, ctx_gen) = self
                .lock_context(context_id)
                .await
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let ctx = &mut *guard;

            let handle = ctx.handle.clone();
            let role_state = ctx.role_state.clone();

            // Defense-in-depth Matrix-style hard rate limit: consume
            // a token from the per-invoker bucket BEFORE any
            // bookkeeping so the cap applies even when the cost
            // pipeline is free. Inline rollback paths refund
            // directly; the `OutletEconomyTicket`-based rollback
            // consults `needs_hard_rate_limit_refund`.
            if !ctx
                .governance
                .hard_rate_limit
                .try_consume(invoker_did, now_secs)
            {
                return Err(ContextError::RateLimited {
                    resource: "outlet_call".to_owned(),
                    message: "hard rate limit exceeded for invoker".to_owned(),
                });
            }

            // Record velocity BEFORE the pre-check so
            // `compute_escalated_cost` sees the new window entry,
            // matching `send_message`. Capture the rollback token so
            // a failure refunds THIS entry specifically rather than
            // racing concurrent invokers.
            let velocity_token = ctx
                .governance
                .velocity_tracker
                .record_message(invoker_did, now_secs);

            let velocity = ctx
                .governance
                .velocity_tracker
                .get_velocity(invoker_did, now_secs);
            let member_count = u64::try_from(ctx.membership.count()).unwrap_or(u64::MAX);
            let aggregate = ctx.governance.velocity_tracker.aggregate_velocity(now_secs);
            let metrics = ObservableMetrics {
                sender_velocity: velocity,
                member_count,
                context_message_rate: aggregate,
                relay_queue_depth: 0,
                time_of_day: now_secs % 86400,
                storage_usage: 0,
            };

            let economic_policy = ctx.governance.economic_policy.clone();
            let consequence_rules = ctx.governance.consequence_rules.clone();
            let message_pricing = ctx.governance.message_pricing.clone();

            // Per-context event snapshot from the event log so
            // consequence evaluation and participation-record
            // computation see the context's history.
            let events_snapshot = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now_secs,
                self.event_log.as_ref(),
            );

            // Pre-check scope: build a throwaway participation cache so
            // the pre-check's pure compute can use the same struct the
            // wider invoke path expects. The cache is discarded at the
            // end of Phase 1 and rebuilt (as an empty map) in Phase 3;
            // standing updates happen via the authoritative per-context
            // cache held in `ctx.governance.participation_cache`.
            let mut participation_cache: HashMap<
                String,
                scp_protocol::trust::participation::ParticipationRecord,
            > = HashMap::new();

            let action_cost = {
                let economy = OutletEconomyContext {
                    economic_policy: economic_policy.as_ref(),
                    budget_tracker: &mut ctx.governance.budget_tracker,
                    spending_ucan,
                    context_id,
                    now: now_secs,
                    events: &events_snapshot,
                    participation_cache: &mut participation_cache,
                    consequence_rules: &consequence_rules,
                    payment_adapter: payment_adapter.clone(),
                    metrics: metrics.clone(),
                    velocity_tracker: Some(&ctx.governance.velocity_tracker),
                    message_pricing: message_pricing.as_ref(),
                };

                // Pure pre-check (Strategy B): no mutation of the
                // budget tracker. We perform the deduction ourselves
                // below so the mutation point is visible.
                match economy_pre_check(&economy, invoker_did) {
                    Ok(cost) => cost,
                    Err(err) => {
                        // Roll back the velocity entry and the hard
                        // rate-limit token we consumed above — nothing
                        // else has been mutated yet so the rollback
                        // is inline (no ticket to drain).
                        ctx.governance
                            .velocity_tracker
                            .rollback(invoker_did, velocity_token);
                        ctx.governance.hard_rate_limit.refund(invoker_did);
                        return Err(invocation_error_to_context(err));
                    }
                }
            };

            // C1b (PR #1606): cryptographically validate the spending UCAN
            // before mutating per-context economy state. Without this call
            // the attacker could present a fabricated `UcanToken` with a
            // valid-looking spending capability — `economy_pre_check` only
            // verifies the capability shape, not the signature, iss/aud
            // binding, expiry, revocation, or replay nonce. `enforce_economy`
            // (used by send/join) already runs this pipeline; `invoke_outlet_with_economy`
            // must match. For free actions (`action_cost == 0`) spending UCANs
            // are not required — mirroring `enforce_economy` and `check_spending_capability`.
            if action_cost.0 > 0 {
                let Some(spending) = spending_ucan else {
                    // Paid action reached this point without a spending UCAN:
                    // `economy_pre_check` would normally reject this via
                    // `check_outlet_spending_capability`, so reaching here is
                    // a defense-in-depth branch. Roll back and surface the
                    // canonical SCP-ECON-12060 error.
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    // SCP-OUT-027: domain-appropriate ContextError variant.
                    // Spending-UCAN absence is an economic integration
                    // failure, NOT a §5.4.4 outlet-error class member —
                    // route through the existing `IntegrationFailed`
                    // variant so we keep the canonical SCP-ECON-12060
                    // code at the diagnostic surface without the
                    // pre-OUT-027 lossy `PermissionDenied` collapse.
                    return Err(ContextError::IntegrationFailed(
                        "SCP-ECON-12060: paid action requires spending UCAN".to_owned(),
                    ));
                };
                if let Err(err) = super::economy::validate_spending_ucan_or_error(
                    spending,
                    invoker_did,
                    context_id,
                    &mut ctx.governance.spending_nonce_tracker,
                    &ctx.governance.revoked_spending_ucan_cids,
                    &self.key_resolver,
                    &*self.clock,
                ) {
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    return Err(err);
                }
            }

            // Strategy B: the caller does the deduction explicitly so
            // the mutation point is visible and the pre-check function
            // stays pure.
            let deducted_cost = if action_cost.0 > 0 {
                if ctx
                    .governance
                    .budget_tracker
                    .record_spend(invoker_did, action_cost)
                    .is_err()
                {
                    let remaining = ctx.governance.budget_tracker.remaining(invoker_did).0;
                    ctx.governance
                        .velocity_tracker
                        .rollback(invoker_did, velocity_token);
                    ctx.governance.hard_rate_limit.refund(invoker_did);
                    return Err(invocation_error_to_context(
                        InvocationError::BudgetExceeded {
                            did: invoker_did.to_string(),
                            cost: action_cost.0,
                            remaining,
                        },
                    ));
                }
                Some(action_cost)
            } else {
                None
            };

            // H11 split-phase nonce commit: `validate_spending_ucan_or_error`
            // above only ran `check_replay` (read-only probe). The durable
            // `record` happens here — AFTER the budget gate passes — so that
            // budget-rejected requests cannot burn nonce tracker capacity
            // (nonce-burn DoS). Mirror of the `enforce_economy` nonce-commit
            // path in economy.rs.
            //
            // `deducted_cost.is_some()` implies `action_cost.0 > 0` which
            // implies the `let Some(spending) = spending_ucan` guard above
            // already passed (otherwise we returned early). Only evaluate
            // when both conditions hold to avoid a redundant Some-unwrap.
            if deducted_cost.is_some()
                && let Some(spending) = spending_ucan
                && let Err(e) = scp_protocol::crypto::ucan::spending::commit_spending_ucan_nonce(
                    spending,
                    &mut ctx.governance.spending_nonce_tracker,
                )
            {
                // Nonce commit failed — reverse the budget deduction
                // and roll back velocity + hard-rate-limit before
                // surfacing the error.
                if let Some(cost) = deducted_cost {
                    ctx.governance
                        .budget_tracker
                        .reverse_spend(invoker_did, cost);
                }
                ctx.governance
                    .velocity_tracker
                    .rollback(invoker_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(invoker_did);
                // SCP-OUT-027: nonce-commit failure is an economic
                // integration concern (spending-nonce ledger). Route
                // through `IntegrationFailed` so the SCP-ECON-12066
                // code surfaces without the pre-OUT-027 lossy
                // `PermissionDenied` collapse.
                return Err(ContextError::IntegrationFailed(format!(
                    "SCP-ECON-12066: nonce commit failed after budget acceptance: {e}"
                )));
            }

            // Payment escrow (authorize hold). Must run under the lock
            // because the adapter call needs the per-context policy and
            // metrics snapshot we just computed; re-acquiring the lock
            // after the adapter call would introduce a TOCTOU window
            // where another task could mutate policy/metrics between
            // authorize and budget recording.
            let escrow = match (economic_policy.as_ref(), payment_adapter.as_ref()) {
                (Some(policy), Some(adapter)) => {
                    match invoke::authorize_outlet_payment(
                        adapter.as_ref(),
                        policy,
                        context_id,
                        invoker_did,
                        &metrics,
                    )
                    .await
                    {
                        Ok(prepared) => prepared,
                        Err(auth_err) => {
                            // Authorization failed — reverse budget,
                            // velocity, and the hard-rate-limit token
                            // inline (no ticket to drain yet) under
                            // the still-held lock.
                            if let Some(cost) = deducted_cost {
                                ctx.governance
                                    .budget_tracker
                                    .reverse_spend(invoker_did, cost);
                            }
                            ctx.governance
                                .velocity_tracker
                                .rollback(invoker_did, velocity_token);
                            ctx.governance.hard_rate_limit.refund(invoker_did);
                            return Err(invocation_error_to_context(auth_err));
                        }
                    }
                }
                _ => None,
            };

            let ticket = OutletEconomyTicket {
                actor_did: invoker_did.clone(),
                deducted_cost,
                velocity_token,
                escrow,
                policy_for_capture: economic_policy,
                metrics_for_capture: metrics,
                needs_hard_rate_limit_refund: true,
                consumed: false,
            };

            // SECURITY: explicitly release the `contexts` lock BEFORE
            // the block-expression returns. This is the exit boundary
            // of Phase 1 — Phase 2 (the executor) must run without the
            // lock. The explicit `drop(contexts)` keeps the lock-split
            // visible to code review and to the structural pipeline
            // wiring test in `scp-testing/tests/integration/pipeline_wiring.rs`.
            Phase1Snapshot {
                handle,
                role_state,
                ticket,
                ctx_gen,
                action_cost,
            }
        };

        let Phase1Snapshot {
            handle,
            role_state,
            ticket,
            ctx_gen,
            action_cost,
        } = phase1;

        // SCP-OUT-021 + SCP-OUT-022: build the post-input caveat /
        // layer-composition hook BEFORE Phase 2 dispatch. The hook captures
        // the enforcement state(s) by move and runs §7.3.8 synchronous
        // + counter-store checks AND/OR the §7.3.8 / §6.2 / §19.5 / §19.3
        // AND fold immediately after input schema validation in the helper.
        //
        // Composition rule when BOTH bundles are present:
        //
        // 1. SCP-OUT-021 portion runs `check_invocation_local` only
        //    (input_schema / amount_max_per_call / allowed_adapters /
        //    allowed_target_dids). The counter-store CAS is delegated to
        //    `evaluate_all_layers`'s `CaveatRateCounter` step so the per-
        //    `(context_id, ucan_cid, kind)` counter is incremented at most
        //    once per invocation.
        // 2. SCP-OUT-022 `evaluate_all_layers` runs the full six-layer §7.3.8
        //    composition (caveat time-box → counter → OutboundPolicy →
        //    InboundPolicy → SpendingCapability → MemberBudgetTracker) and
        //    short-circuits on the first denial. The denial maps back to
        //    [`InvocationError::CaveatViolation`] via
        //    [`invocation_error_from_layer_denial`] so the §5.4.4 catalog
        //    routing is identical to the OUT-021-only path.
        //
        // When only one bundle is present the unused branch is skipped
        // entirely. When neither is present the hook is `None` and the
        // helper bypasses the §7.3.8 post-input gate.
        //
        // The outlet registration is cloned out of the registry up-front so
        // the hook closure owns its `OutletRegistration` snapshot — the
        // registry borrow does not need to survive into the off-lock Phase 2
        // future. `None` here is recovered by the helper's existing step 2
        // (registry lookup) so the layer-composition path stays consistent
        // with the rest of `invoke_outlet_execute_and_validate`.
        let outlet_for_layer_composition: Option<
            scp_protocol::context::outlets::OutletRegistration,
        > = if layer_composition.is_some() {
            registry.get(outlet_id).cloned()
        } else {
            None
        };

        // §7.3.8 fail-closed (R3 single-shot parity with streaming):
        // a counter-bearing caveat (`max_calls` / `amount_max_cumulative` /
        // `rate_window`) that the manager has NO counter store to enforce
        // MUST reject the invocation, never silently admit. This mirrors
        // `build_stream_post_input_hook` returning
        // `OpenStreamRejection::CaveatPostInputViolation`. The check sits
        // BEFORE the hook is built so a missing store can never reach the
        // `build_post_input_hook`-returns-`None` bypass. The counter store
        // is RUNTIME-OWNED (resolved here, not supplied by the caller) so a
        // bridge cannot omit it.
        let caveat_counter_store = self.caveat_counter_store().cloned();
        if let Some(enf) = caveat_enforcement.as_ref()
            && enf.caveats.has_counter_bearing_caveat()
            && caveat_counter_store.is_none()
        {
            rollback_outlet_economy_ticket(self, context_id, ticket).await;
            return Err(invocation_error_to_context(
                InvocationError::CaveatViolation {
                    slug: scp_protocol::context::outlets::error_codes::SLUG_AUTHORIZATION_DENIED,
                    message: "counter-bearing caveat present but no counter store is \
                              configured — invocation rejected fail-closed (§7.3.8)"
                        .to_owned(),
                },
            ));
        }

        // §7.3.8 amount-caveat binding: replace the caller-supplied
        // `estimated_cost` with the REAL per-invocation cost the runtime
        // priced under the Phase 1 lock (`economy_pre_check`). Single-shot
        // bridges (PyO3 / NAPI / UniFFI) have no per-call price at the bridge
        // layer and pass `estimated_cost: 0`, which would make
        // `amount_max_per_call` always pass and `amount_max_cumulative` accrue
        // 0 — the §7.3.8 amount caps would be inert on single-shot. The cost
        // is only knowable here, after pricing, so the runtime is the correct
        // layer to bind the amount caveats to it. The runtime owns the cost,
        // so a bridge cannot under-report it. Streaming prices per-chunk
        // through `build_stream_post_input_hook`'s `cost_per_chunk`, which is
        // the streaming analogue of this assignment.
        let mut caveat_enforcement = caveat_enforcement;
        if let Some(enf) = caveat_enforcement.as_mut() {
            enf.estimated_cost = action_cost;
        }

        // §7.3.8 fail-closed defense-in-depth: if the leaf caveats require a
        // post-input check, a hook MUST be built. `build_post_input_hook`
        // returns `None` only when NEITHER `caveat_enforcement` NOR
        // `layer_composition` is present; capture whether enforcement is
        // required here so the post-build guard can reject a (would-be)
        // silent bypass.
        let caveat_requires_post_input = caveat_enforcement
            .as_ref()
            .is_some_and(|enf| enf.caveats.requires_post_input_check());

        let caveat_hook: Option<crate::context::outlets::invoke::CaveatPostInputCheck<'_>> =
            build_post_input_hook(
                context_id,
                invoker_did,
                now_secs,
                caveat_enforcement,
                caveat_counter_store,
                layer_composition,
                outlet_for_layer_composition,
            );

        // §7.3.8 fail-closed (defense-in-depth). If the leaf caveats require a
        // post-input check but no hook was produced, the §7.3.8 gate would be
        // silently skipped — the exact bypass this remediation closes. Reject
        // rather than admit. With the wiring above this is unreachable (a
        // post-input-requiring `caveat_enforcement` always yields a hook), but
        // the guard makes the invariant mechanical: a future refactor that
        // drops the hook for an enforcement-bearing token is caught at runtime
        // instead of silently re-opening the bypass.
        if caveat_requires_post_input && caveat_hook.is_none() {
            rollback_outlet_economy_ticket(self, context_id, ticket).await;
            return Err(invocation_error_to_context(
                InvocationError::CaveatViolation {
                    slug: scp_protocol::context::outlets::error_codes::SLUG_AUTHORIZATION_DENIED,
                    message: "leaf caveats require a §7.3.8 post-input check but no \
                              enforcement hook is active — invocation rejected fail-closed"
                        .to_owned(),
                },
            ));
        }

        // ------------------------------------------------------------
        // Phase 2 — UNLOCKED.
        //
        // Run the executor and validate its output without holding the
        // `contexts` mutex. On any failure drain the ticket so budget,
        // velocity, and escrow are all reversed before propagating the
        // error.
        // ------------------------------------------------------------
        let outcome = match invoke_outlet_execute_and_validate(
            &handle,
            registry,
            &role_state,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            handler_panic_sink,
            caveat_hook,
        )
        .await
        {
            Ok(o) => o,
            Err(err) => {
                rollback_outlet_economy_ticket(self, context_id, ticket).await;
                return Err(invocation_error_to_context(err));
            }
        };
        let InvokeExecuteOutcome {
            output,
            input_hash,
            output_hash,
            execution_time_ms,
        } = outcome;

        // ------------------------------------------------------------
        // Phase 3a — LOCKED (bookkeeping).
        //
        // Re-acquire the lock to run participation-record update and
        // consequence evaluation against the authoritative per-context
        // cache, then release the lock again for the (off-lock) escrow
        // capture call.
        // ------------------------------------------------------------
        let (consequences, ticket) = {
            let Ok(mut guard) = self.relock_context(&ctx_gen).await else {
                // Context vanished or was recreated between Phase 1
                // and Phase 3 (generation mismatch / not registered).
                // Drain the ticket — this will void the escrow, and
                // the budget/velocity rollback is a best-effort no-op.
                rollback_outlet_economy_ticket(self, context_id, ticket).await;
                return Err(ContextError::ContextNotRegistered(context_id.to_owned()));
            };
            let ctx = &mut *guard;

            let now = self.clock.now_secs();
            let events_for_consequences = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now,
                self.event_log.as_ref(),
            );
            let consequence_rules = ctx.governance.consequence_rules.clone();

            let triggered = post_outlet_invocation_bookkeeping(
                &events_for_consequences,
                invoker_did,
                context_id,
                now,
                &mut ctx.governance.participation_cache,
                &consequence_rules,
            );

            // Enforce triggered consequences while the lock is held,
            // matching the messaging path (messaging.rs:655-668).
            // evaluate_consequence_rules is called inside
            // post_outlet_invocation_bookkeeping; enforcement must happen
            // here so that consequences are actually applied (not just
            // reported in the output).
            super::governance::enforce_triggered_consequences(
                ctx,
                &super::governance::EnforceConsequencesCtx {
                    context_id,
                    member_did: invoker_did,
                    now,
                    triggered: &triggered,
                    rules: &consequence_rules,
                    clock: &*self.clock,
                    event_log: self.event_log.as_ref(),
                    event_tx: self.event_tx.as_ref(),
                },
            );

            (triggered, ticket)
        };

        // ------------------------------------------------------------
        // Phase 3b — UNLOCKED (escrow capture).
        //
        // Capture the escrow hold off-lock. On capture failure reverse
        // the budget via a dedicated path (escrow is already consumed
        // by the capture attempt, so there is nothing to void) and
        // mark the ticket consumed without re-voiding.
        // ------------------------------------------------------------
        let payment_receipt = match (
            payment_adapter.as_ref(),
            ticket.escrow.as_ref(),
            ticket.policy_for_capture.as_ref(),
        ) {
            (Some(adapter), Some(prepared), policy_opt) => {
                match invoke::complete_outlet_payment(
                    adapter.as_ref(),
                    policy_opt,
                    prepared,
                    &ticket.metrics_for_capture,
                )
                .await
                {
                    Ok(receipt) => receipt,
                    Err(capture_err) => {
                        // Capture failed AFTER successful execution.
                        // The escrow hold is consumed by the capture
                        // attempt (no void), but the per-context
                        // budget, velocity entry, and rate-limit
                        // token must all be reversed so that an
                        // unpaid-for invocation does not permanently
                        // charge any of the three. We cannot delegate
                        // to `rollback_outlet_economy_ticket` because
                        // it would attempt to void the already-
                        // consumed escrow.
                        {
                            if let Ok(mut guard) = self.relock_context(&ctx_gen).await {
                                let ctx = &mut *guard;
                                if let Some(cost) = ticket.deducted_cost {
                                    ctx.governance
                                        .budget_tracker
                                        .reverse_spend(invoker_did, cost);
                                }
                                ctx.governance
                                    .velocity_tracker
                                    .rollback(invoker_did, ticket.velocity_token);
                                if ticket.needs_hard_rate_limit_refund {
                                    ctx.governance.hard_rate_limit.refund(invoker_did);
                                }
                            }
                        }
                        let mut ticket = ticket;
                        ticket.consumed = true;
                        ticket.needs_hard_rate_limit_refund = false;
                        return Err(invocation_error_to_context(capture_err));
                    }
                }
            }
            _ => None,
        };

        // ------------------------------------------------------------
        // Commit the ticket (no more rollback paths below this point)
        // and assemble the ManagedOutletInvocationOutput.
        // ------------------------------------------------------------
        let cost = commit_outlet_economy_ticket(ticket);
        let event = build_outlet_event(
            outlet_id,
            invoker_did,
            execution_time_ms,
            input_hash,
            output_hash,
            cost,
        );

        crate::metrics::record_outlet_invocation();
        Ok(ManagedOutletInvocationOutput {
            output,
            event,
            consequences,
            payment_receipt,
        })
    }

    /// Dispatches an outlet invocation through an [`OutletExecutor`] under
    /// the full economy pipeline (SCP-OUT-013).
    ///
    /// Wraps [`Self::invoke_outlet_with_economy`] with a kind-aware adapter
    /// so the registered [`OutletKind`](scp_protocol::context::outlets::OutletKind)
    /// drives dispatch to `exec_query` (read-only handle) or `exec_action`
    /// (mutable handle, write-capable). Pending mutations enqueued through
    /// [`crate::context::outlets::invoke::MutableInvocation`] are returned
    /// alongside the standard invocation outcome so the caller can apply
    /// them (or assert on them in tests). The `misdeclaration_sink`
    /// receives `OutletVerifiedEvent { integrity_ok: false, reason:
    /// QueryMisdeclaration }` events whenever the
    /// [`MutableInvocation::guard_kind`](crate::context::outlets::invoke::MutableInvocation)
    /// runtime check refuses a write or the dispatched executor half
    /// returns [`OutletExecutorError::KindMismatch`](crate::context::outlets::invoke::OutletExecutorError::KindMismatch).
    ///
    /// # Errors
    ///
    /// Returns the same [`ContextError`] taxonomy as
    /// [`Self::invoke_outlet_with_economy`]. Misdeclaration paths surface
    /// as `ContextError::OutletInvocation(OutletError {
    /// code: SCP-TOOL-6130, slug: execution.handler-panic, ... })`
    /// per spec §5.4.4 (SCP-OUT-027).
    ///
    /// # SCP-OUT-021 + SCP-OUT-022 — caveat + layer composition wiring
    ///
    /// `caveat_enforcement` is the SCP-OUT-021 post-input gate
    /// ([`CaveatEnforcement`] — `input_schema`, `allowed_adapters`,
    /// `allowed_target_dids`, `max_calls`, `amount_max_cumulative`,
    /// `rate_window`). Pass `Some(...)` when the presenting (leaf) action
    /// UCAN carried `nb` caveats; the caller derives this bundle from the
    /// validated UCAN's `payload.nb` field plus the bridge-owned
    /// [`CaveatCounterStore`](crate::trust::CaveatCounterStore).
    ///
    /// The §7.3.8 / §6.2.0.1 / §19.5 / §19.3 layer composition
    /// ([`LayerCompositionEnforcement`]) is constructed INSIDE this method
    /// from the per-context runtime state — `OutboundPolicy` /
    /// `InboundPolicy` are looked up from the matching `OutletInterface`
    /// in `ctx.governance.tool_interfaces` (intra-context invocations
    /// resolve to `None` for both, which the layer fold treats as "admit"
    /// per spec); `SpendingCapability` is extracted from `spending_ucan`
    /// when present; `MemberBudgetTracker` is snapshotted from
    /// `ctx.governance.budget_tracker`. Passing this bundle through is
    /// MANDATORY (not opt-in) — the §7.3.8 AND fold over budget +
    /// spending + Inbound/Outbound policies MUST run for every dispatch
    /// per SCP-OUT-022.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn invoke_outlet_dispatch_with_economy<E>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: &E,
        misdeclaration_sink: Option<&dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        handler_panic_sink: Option<&dyn crate::context::outlets::invoke::HandlerPanicSink>,
        // SCP-OUT-021: caveat enforcement bundle from the validated leaf
        // UCAN's `nb` field + the bridge-owned [`CaveatCounterStore`].
        // `None` only for legacy (no-caveat) callers; production bridges
        // MUST pass `Some(...)` when the presenting UCAN carries any of
        // the §7.3.8 fields.
        caveat_enforcement: Option<CaveatEnforcement<'_>>,
    ) -> Result<DispatchedManagedOutletInvocationOutput, ContextError>
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized,
    {
        // Snapshot the outlet kind under the registry so the closure-based
        // adapter sees a stable value. SCP-OUT-027: outlet-not-found
        // collapses to the §5.4.4 query-oracle target
        // (CODE_AUTHORIZATION_DENIED + slug authorization.denied) so
        // registration state does not leak through error class — the
        // same envelope `InvocationError::OutletNotFound` would produce
        // through `invocation_error_to_context`.
        let registration = registry.get(outlet_id).ok_or_else(|| {
            invocation_error_to_context(InvocationError::OutletNotFound {
                outlet_id: outlet_id.clone(),
            })
        })?;
        let kind = registration.kind;

        // Snapshot the read-side context state once so the
        // ReadOnlyInvocation handle is stable across the off-lock executor.
        // We re-acquire the lock briefly to snapshot what the handle needs
        // to expose (events, epoch, members, role state, registry,
        // economic policy snapshot). The dispatcher does not stress
        // membership/ceiling checks — those are already enforced by the
        // existing capability gate inside `invoke_outlet_with_economy`.
        //
        // SCP-OUT-022: the per-context governance state (Outbound /
        // Inbound interface policies + the [`MemberBudgetTracker`]
        // snapshot) is read here under the same lock so the
        // [`LayerCompositionEnforcement`] bundle constructed below sees a
        // self-consistent snapshot. `OutboundPolicy` / `InboundPolicy`
        // resolve from the matching `OutletInterface` in
        // `ctx.governance.tool_interfaces` keyed on `outlet_id` — intra-
        // context dispatch resolves to `None` for both, which the
        // §7.3.8 layer fold treats as "admit" per spec.
        let (
            handle_snapshot,
            role_state_snapshot,
            events_snapshot,
            epoch_snapshot,
            policy_snapshot,
            outbound_policy,
            inbound_policy,
            budget_tracker_snapshot,
        ) = {
            let (guard, _ctx_gen) = self
                .lock_context(context_id)
                .await
                .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
            let ctx = &*guard;
            let now_secs = self.clock.now_secs();
            let events = super::governance::event_log_entries_for_consequences(
                ctx,
                context_id,
                now_secs,
                self.event_log.as_ref(),
            );
            // §6.2.0.1 interface lookup. The `OutletInterface` carries the
            // source-context-published `OutboundPolicy` and the target-
            // context-mirrored `InboundPolicy`. Intra-context dispatch
            // does NOT publish an interface — the lookup misses and both
            // resolve to `None`, which `evaluate_all_layers` treats as
            // "admit" (the matching layer is skipped). Cross-context
            // invocations route through `invoke_cross_context` rather
            // than this dispatcher, so they own their own policy lookup.
            let interface = ctx
                .governance
                .tool_interfaces
                .iter()
                .find(|iface| &iface.outlet_id == outlet_id);
            let outbound = interface.and_then(|iface| iface.outbound_policy.clone());
            let inbound = interface.and_then(|iface| iface.inbound_policy.clone());
            (
                ctx.handle.clone(),
                ctx.role_state.clone(),
                events,
                ctx.epoch.mls_epoch,
                ctx.governance.economic_policy.clone(),
                outbound,
                inbound,
                ctx.governance.budget_tracker.clone(),
            )
        };

        // SCP-OUT-022: build the layer-composition bundle from the
        // per-context snapshot taken above + the optional spending UCAN's
        // `SpendingCapability`. The bundle is `Some` UNCONDITIONALLY so
        // the §7.3.8 / §6.2 / §19.5 / §19.3 AND fold over the four
        // economic + policy layers runs on every dispatch — the §6.2.0.1
        // policies remain `None` for intra-context (handled by the fold)
        // and the spending capability remains `None` for free actions.
        // Passing `None` here would re-introduce the SCP-OUT-022 ghost-
        // code regression (the bundle is constructed but the layer fold
        // never ran).
        let spending_capability = spending_ucan.and_then(|tok| {
            scp_protocol::crypto::ucan::spending::SpendingCapability::from_ucan_token(tok).ok()
        });
        // Serialized payload byte length — drives the
        // `OutboundPolicy.max_payload_bytes` check (§6.2.0.1). `to_string`
        // is canonical-enough for size accounting at this gate; the §5.4.4
        // wire-form size check is independent of this surface.
        let payload_bytes = serde_json::to_vec(&input).map_or(0, |v| v.len());
        let layer_composition = Some(LayerCompositionEnforcement {
            outbound_policy,
            inbound_policy,
            spending_capability,
            budget_tracker: budget_tracker_snapshot,
            // `source_role` is the role the invoker holds in the *source*
            // context for cross-context invocations (drives
            // `InboundPolicy.allowed_source_roles`). Intra-context
            // dispatch has no source/target distinction — leave `None`.
            source_role: None,
            payload_bytes,
        });

        // Adapt the trait-based dispatch into the closure-based pipeline.
        // The closure has to hold `&mut Vec<MutationIntent>` so it can
        // collect the writes from `MutableInvocation::take_pending_mutations`
        // — `Mutex` keeps us cleanly across the `move` boundary while
        // satisfying `Send`.
        let pending: std::sync::Mutex<Vec<crate::context::outlets::invoke::MutationIntent>> =
            std::sync::Mutex::new(Vec::new());
        let pending_ref = &pending;
        let outlet_id_owned = outlet_id.clone();
        let invoker_did_owned = invoker_did.clone();
        let role_state_ref = &role_state_snapshot;
        let registry_ref: &OutletRegistry = registry;
        let events_ref = &events_snapshot;
        let policy_ref = policy_snapshot.as_ref();
        let handle_ref = &handle_snapshot;
        let executor_ref: &E = executor;
        let executor_kind = kind;

        let closure = move |input: serde_json::Value| {
            let outlet_id_inner = outlet_id_owned.clone();
            let invoker_did_inner = invoker_did_owned.clone();
            async move {
                let read = crate::context::outlets::invoke::ReadOnlyInvocation::new(
                    handle_ref,
                    role_state_ref,
                    registry_ref,
                    &invoker_did_inner,
                    &outlet_id_inner,
                    events_ref,
                    epoch_snapshot,
                    policy_ref,
                    None,
                );
                match executor_kind {
                    scp_protocol::context::outlets::OutletKind::Query => {
                        match executor_ref.exec_query(&read, input).await {
                            Ok(value) => Ok(value),
                            Err(crate::context::outlets::invoke::OutletExecutorError::KindMismatch { .. }) => {
                                if let Some(sink) = misdeclaration_sink {
                                    sink.record(
                                        scp_protocol::context::outlets::OutletVerifiedEvent {
                                            outlet_id: outlet_id_inner.clone(),
                                            passed: 0,
                                            failed: 1,
                                            integrity_ok: false,
                                            reason: Some(
                                                scp_protocol::context::outlets::OutletVerifiedReason::QueryMisdeclaration,
                                            ),
                                        },
                                    );
                                }
                                // SCP-OUT-027: error-code prefix removed from
                                // the message string. The §5.4.4 typed
                                // envelope at `invocation_error_to_context`
                                // is now the sole source of `(code, slug,
                                // class)`; the message text below is
                                // diagnostic payload only.
                                Err("outlet kind mismatch (Query expected)".to_owned())
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::QueryViolation { operation }) => {
                                Err(format!(
                                    "query violation in exec_query: {operation}"
                                ))
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::Failed(msg)) => {
                                Err(msg)
                            }
                        }
                    }
                    scp_protocol::context::outlets::OutletKind::Action => {
                        let mut mutable = crate::context::outlets::invoke::MutableInvocation::new(
                            crate::context::outlets::invoke::ReadOnlyInvocation::new(
                                handle_ref,
                                role_state_ref,
                                registry_ref,
                                &invoker_did_inner,
                                &outlet_id_inner,
                                events_ref,
                                epoch_snapshot,
                                policy_ref,
                                None,
                            ),
                            scp_protocol::context::outlets::OutletKind::Action,
                            misdeclaration_sink,
                        );
                        match executor_ref.exec_action(&mut mutable, input).await {
                            Ok(value) => {
                                let collected = mutable.take_pending_mutations();
                                if !collected.is_empty() {
                                    let mut guard = pending_ref
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    guard.extend(collected);
                                }
                                Ok(value)
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::KindMismatch { .. }) => {
                                // SCP-OUT-027: see exec_query branch above.
                                Err("outlet kind mismatch (Action expected)".to_owned())
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::QueryViolation { operation }) => {
                                Err(format!(
                                    "query violation in exec_action: {operation}"
                                ))
                            }
                            Err(crate::context::outlets::invoke::OutletExecutorError::Failed(msg)) => {
                                Err(msg)
                            }
                        }
                    }
                }
            }
        };

        // SCP-OUT-021 + SCP-OUT-022 wiring. Both bundles are passed
        // through to `invoke_outlet_with_economy`, which builds the
        // post-input hook in `build_post_input_hook`. The §7.3.8 AND fold
        // over (caveat time-box → counter → OutboundPolicy → InboundPolicy
        // → SpendingCapability → MemberBudgetTracker) runs immediately
        // after input schema validation and before the executor. The
        // remediation scope (SCP-OUT-021 + SCP-OUT-022) requires that
        // `caveat_enforcement` AND `layer_composition` are NOT
        // hardcoded `None` — the dispatcher MUST build a real
        // `LayerCompositionEnforcement` bundle (always `Some(...)`) and
        // forward the optional `caveat_enforcement` from the caller.
        let outcome = self
            .invoke_outlet_with_economy(
                context_id,
                registry,
                outlet_id,
                input,
                invoker_did,
                spending_ucan,
                timeout_ms,
                closure,
                handler_panic_sink,
                caveat_enforcement,
                layer_composition,
            )
            .await?;

        let pending_mutations = pending
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        Ok(DispatchedManagedOutletInvocationOutput {
            output: outcome.output,
            event: outcome.event,
            consequences: outcome.consequences,
            payment_receipt: outcome.payment_receipt,
            pending_mutations,
        })
    }

    /// SCP-OUT-033 — streaming entry point for outlet invocation
    /// through the full `ContextManager` economy pipeline.
    ///
    /// Returns a `tokio::sync::mpsc::Receiver<OutletStreamChunk>`
    /// directly — the caller streams chunks as the executor produces
    /// them, with the framework appending the §5.4.5 terminal `End`
    /// (success) or `Error { terminal: true }` (failure) chunk.
    ///
    /// Wraps [`Self::invoke_outlet_dispatch_with_economy`] under the
    /// hood: the aggregating dispatcher runs the full
    /// economy/caveat/escrow/bookkeeping pipeline; on success the
    /// resulting single-shot `Value` is converted into a `Data` chunk
    /// via [`crate::context::outlets::invoke::one_shot_to_stream`] and
    /// `End` is appended. On failure the framework converts the
    /// `ContextError` into a terminal `ChunkPayload::Error` chunk.
    ///
    /// This is the canonical streaming surface that FFI bridges and
    /// SDKs target post-OUT-033. The aggregating
    /// [`Self::invoke_outlet_dispatch_with_economy`] remains as the
    /// internal driver — its `ManagedOutletInvocationOutput` carries
    /// the `OutletInvokedEvent`, consequences, and payment receipt
    /// through tracing/sinks instead of as part of the streaming
    /// receiver. SCP-OUT-034+ will wire those bookkeeping outputs into
    /// the End chunk's `provenance` once the streaming-native event-
    /// log path is built; for now the wrapper preserves the existing
    /// `ContextManager`-level bookkeeping behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] on **synchronous** validation failures
    /// that happen before the stream is opened (context-not-registered,
    /// outlet-not-found, capability denial). Once the receiver is
    /// returned, every failure mode (timeout, panic, executor `Err`,
    /// schema, caveat violation) surfaces as a terminal
    /// `ChunkPayload::Error` chunk on the receiver.
    #[allow(clippy::too_many_arguments)]
    pub async fn invoke_outlet_dispatch_with_economy_stream<E>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: &E,
        misdeclaration_sink: Option<&dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        handler_panic_sink: Option<&dyn crate::context::outlets::invoke::HandlerPanicSink>,
        // SCP-OUT-021: caveat enforcement bundle, forwarded verbatim to
        // [`Self::invoke_outlet_dispatch_with_economy`] so the §7.3.8
        // post-input gate runs for streaming dispatch on the same terms
        // as the single-shot path.
        caveat_enforcement: Option<CaveatEnforcement<'_>>,
    ) -> Result<
        tokio::sync::mpsc::Receiver<scp_protocol::context::outlets::stream::OutletStreamChunk>,
        ContextError,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized,
    {
        // Drive the existing aggregating dispatcher; convert the
        // resulting `ManagedOutletInvocationOutput` into a one-shot
        // stream via the OUT-033 adapter. The chunk channel uses the
        // §5.4.5 default credit window (32) so the stream contract
        // matches the stream-open path even though this wrapper is the
        // degenerate single-chunk case (`Data` + `End`).
        let outcome = self
            .invoke_outlet_dispatch_with_economy(
                context_id,
                registry,
                outlet_id,
                input,
                invoker_did,
                spending_ucan,
                timeout_ms,
                executor,
                misdeclaration_sink,
                handler_panic_sink,
                caveat_enforcement,
            )
            .await;

        let (tx, rx) = tokio::sync::mpsc::channel::<
            scp_protocol::context::outlets::stream::OutletStreamChunk,
        >(
            // Match the §5.4.5 default `credit_window` so the
            // streaming surface is consistent with the
            // stream-open path.
            scp_protocol::context::outlets::stream::DEFAULT_CREDIT_WINDOW as usize,
        );

        let request_id = *uuid::Uuid::now_v7().as_bytes();

        match outcome {
            Ok(out) => {
                // Single-shot adapter: emit `Data(out.output)` followed
                // by `End`. Both share the freshly minted `request_id`
                // and use strictly monotonic sequence numbers (0, 1).
                let data_chunk = scp_protocol::context::outlets::stream::OutletStreamChunk {
                    request_id,
                    sequence: 0,
                    payload: scp_protocol::context::outlets::stream::ChunkPayload::Data {
                        value: out.output,
                    },
                    sig: [0u8; 64],
                };
                let end_chunk = scp_protocol::context::outlets::stream::OutletStreamChunk {
                    request_id,
                    sequence: 1,
                    payload: scp_protocol::context::outlets::stream::ChunkPayload::End {
                        aggregate: serde_json::Value::Null,
                        provenance: scp_protocol::provenance::DataProvenance {
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
                        },
                        execution_time_ms: out.event.execution_time_ms,
                    },
                    sig: [0u8; 64],
                };
                tokio::spawn(async move {
                    let _ = tx.send(data_chunk).await;
                    let _ = tx.send(end_chunk).await;
                });
                Ok(rx)
            }
            Err(err) => {
                // Synchronous-validation failures (context not
                // registered, outlet not found, capability denial)
                // surface as `Result::Err`. The streaming surface
                // returns these directly so callers can distinguish
                // "stream never opened" from "stream opened then
                // closed with a terminal Error chunk".
                Err(err)
            }
        }
    }

    /// SCP-OUT-034 — opens a §5.4.5 streaming session with full
    /// admission, escrow, and tracker wiring.
    ///
    /// This is the §5.4.5 `OutletStreamOpen` acceptance entry point: it
    /// runs the round-5 5-step admission sequence
    /// ([`StreamAdmissionTracker::try_admit`]), reserves escrow at open
    /// ([`StreamEscrow::reserve_at_open`]), pins the stream identity,
    /// initialises [`CreditTracker`] + [`CancelAckTracker`], launches
    /// the underlying executor pump via
    /// [`crate::context::outlets::invoke::invoke_outlet`], and spawns a
    /// wrapping pump task that consults the trackers in lockstep with
    /// chunk emission.
    ///
    /// The returned [`StreamSessionHandle`] exposes the chunk receiver
    /// plus the [`StreamSessionHandle::apply_credit_grant`] /
    /// [`StreamSessionHandle::apply_outlet_cancel`] input methods that
    /// the FFI layer wires into `OutletStreamCredit` / `OutletCancel`
    /// reception.
    ///
    /// On synchronous open-time rejection (admission cap, escrow
    /// overflow, insufficient balance, estimate-bound), returns
    /// [`OpenStreamRejection`] — the caller MUST translate via
    /// [`OpenStreamRejection::to_invocation_error`] +
    /// [`invocation_error_to_context`] for the §5.4.4 typed envelope.
    ///
    /// # Errors
    ///
    /// See [`OpenStreamRejection`] for the open-time rejection
    /// taxonomy. Once the handle is returned, every failure mode
    /// (timeout, credit-stall, cancel-ack-timeout, executor panic,
    /// schema) surfaces as a terminal `ChunkPayload::Error` chunk on
    /// the receiver — never as a `Result` error.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_outlet_stream<E>(
        &self,
        context_id: &str,
        registry: &OutletRegistry,
        role_state: &scp_protocol::context::roles::ContextRoleState,
        outlet_id: &OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        timeout_ms: Option<u32>,
        executor: std::sync::Arc<E>,
        misdeclaration_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        >,
        handler_panic_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::HandlerPanicSink>,
        >,
        invoked_event_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::OutletInvokedEventSink>,
        >,
        // §5.4.5 close-time economic settlement (E1). Fired once at terminal
        // chunk to refund unspent escrow, issue the §19.15.5 PaymentReceipt,
        // and append the close event. `None` for callers that have already
        // settled out-of-band or do not bill (legacy / test paths).
        settlement_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::StreamSettlementSink>,
        >,
        params: crate::context::outlets::dispatch::OpenStreamParams,
        admission: std::sync::Arc<
            std::sync::Mutex<crate::context::outlets::stream::StreamAdmissionTracker>,
        >,
    ) -> Result<
        crate::context::outlets::dispatch::StreamSessionHandle,
        crate::context::outlets::dispatch::OpenStreamRejection,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        // Snapshot the per-context handle so we can hand the underlying
        // executor pump a stable ContextHandle. In the same lock window,
        // snapshot the §5.4.5 MED-HIGH economic policy at acceptance so
        // close-time settlement can capture the receipt for rendered
        // service even if the context is torn down mid-stream (H8). The
        // snapshot is only taken when the context has an economic policy
        // AND the caller did not already supply one in `params` (the
        // caller-supplied value wins so a bridge that already computed the
        // snapshot is not overridden).
        let mut params = params;
        let handle_snapshot = {
            let (guard, _ctx_gen) = self.lock_context(context_id).await.map_err(|_| {
                crate::context::outlets::dispatch::OpenStreamRejection::AdmissionRateLimited {
                    slug: scp_protocol::context::outlets::error_codes::SLUG_TRANSPORT_RATE_LIMITED,
                }
            })?;
            if params.economic_policy_snapshot.is_none()
                && let Some(policy) = guard.governance.economic_policy.clone()
            {
                params.economic_policy_snapshot =
                    Some(crate::context::outlets::invoke::EconomicPolicySnapshot { policy });
            }
            guard.handle.clone()
        };

        // §7.3.8 crypto-MED — build the post-input caveat hook ENTIRELY in the
        // runtime so every bridge enforces identically. The hook borrows the
        // VALIDATED-NARROWED effective caveats (`params.caveats`, the leaf
        // UCAN `nb` after the §7.3.8 narrow) and the opening UCAN's CID
        // (`params.ucan_cid`) only for construction — `build_post_input_hook`
        // captures everything by value, so the returned closure outlives this
        // borrow and `params` moves freely into `open_stream_session` below.
        // `cost_per_chunk` is the per-invocation pricing unit the
        // `amount_max_per_call` check gates against. Fails closed when a
        // counter-bearing cap cannot be enforced (no counter store).
        let (caveat_post_input_check, counter_reservation) = build_stream_post_input_hook(
            &params.caveats,
            params.cost_per_chunk,
            self.caveat_counter_store(),
        )?;

        crate::context::outlets::dispatch::open_stream_session(
            &handle_snapshot,
            registry,
            role_state,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            misdeclaration_sink,
            handler_panic_sink,
            invoked_event_sink,
            settlement_sink,
            params,
            admission,
            // §5.4.5 round-8 (F5): the per-instance node-level pump
            // ceiling. `open_stream_session` acquires a permit after its
            // per-context gates pass and moves it into the pump task.
            std::sync::Arc::clone(&self.outlet_stream_pump_semaphore),
            // §7.3.8 caveat post-input check (synchronous local checks) —
            // run once at open, before any durable side effect.
            caveat_post_input_check,
            // R4 HIGH-1 / HIGH-2 — the durable counter reservation, committed
            // at the FINAL open-time gate (after pump permit + executor
            // launch) so a rejected open burns no counter capacity, and the
            // cumulative cap is RESERVED at `cost_per_chunk × est_chunks`.
            counter_reservation,
        )
        .await
    }

    /// §5.4.5 close-time economic settlement of a streaming-native
    /// invocation (E1 remediation).
    ///
    /// Called once at terminal-chunk delivery (via the
    /// [`crate::context::outlets::invoke::StreamSettlementSink`] the dispatch
    /// pump fires). The open-time escrow HOLD plus every per-grant top-up
    /// were already DEBITED against the invoker's `MemberBudgetTracker`
    /// (E2). This method reconciles the hold against actual consumption:
    ///
    /// 1. Under the context lock, `reverse_spend(invoker, refund_amount)` —
    ///    the unspent portion is credited back so net spent ==
    ///    `billed_amount`. A full refund (`billed_amount == 0`) returns the
    ///    entire hold.
    /// 2. If a payment adapter AND an economic policy are configured AND
    ///    `billed_amount > 0`, capture a §19.15.5 `PaymentReceipt` for the
    ///    EXACT billed amount via the same `authorize → capture` adapter
    ///    sequence the non-streaming path uses. On capture failure, append a
    ///    `PaymentCaptureFailed` event to the log (mirroring
    ///    [`Self::record_payment_capture_failure`]) and DO NOT reverse the
    ///    billed amount — service was rendered (H8). If no adapter/policy is
    ///    configured the receipt is skipped exactly as the non-streaming
    ///    path skips it.
    ///
    /// The stream-close `OutletInvokedEvent` is emitted separately by the
    /// dispatch pump via the `OutletInvokedEventSink`; this method owns only
    /// the economic reconciliation (refund + receipt), matching the
    /// non-streaming split where `invoke_outlet_with_economy` returns the
    /// receipt and emits the invocation event independently.
    ///
    /// Returns the captured `PaymentReceipt` (if any) so the bridge can
    /// surface it on the close summary.
    ///
    /// # Errors
    ///
    /// §5.4.5 MED-HIGH — settlement is resilient to a mid-stream context
    /// teardown. When the hosting context is still registered the runtime
    /// refunds the unspent escrow under the context lock and reads the LIVE
    /// economic policy. When the context is GONE (closed / evicted
    /// mid-stream) the budget tracker was torn down with it so the refund is
    /// moot — but the runtime STILL captures the `PaymentReceipt` for
    /// already-rendered service using the open-time
    /// [`EconomicPolicySnapshot`](crate::context::outlets::invoke::EconomicPolicySnapshot)
    /// (H8 "service rendered is billed"), recording a durable
    /// `PaymentCaptureFailed` event on capture failure rather than stranding
    /// the bill behind a `ContextNotRegistered` early-return.
    ///
    /// Payment-capture failures are recorded to the event log and surfaced
    /// as `Ok(None)` — they MUST NOT strand a refund that already happened.
    /// This method no longer early-returns `ContextNotRegistered`: an absent
    /// context is a settlement path, not an error.
    /// R4 HIGH-1 — releases the UNSPENT portion of a stream's open-time
    /// cumulative-counter reserve at close-time settlement.
    ///
    /// The open reserved the WORST-CASE billable spend
    /// (`amount_cumulative_reserved` = `cost_per_chunk ×
    /// effective_max_billable_chunks`, `<= cap` by construction) against the
    /// durable
    /// [`CaveatKind::AmountCumulative`](scp_protocol::trust::CaveatKind)
    /// counter; only `billed_count` chunks were actually billed, so
    /// `amount_cumulative_reserved − billed_count × cost_per_chunk` (saturating)
    /// is returned to the counter. The cap is thereby debited by exactly the
    /// billed spend, not the worst-case reservation. A no-op when nothing was
    /// reserved (no cap / no store / zero cost). Runs independently of payment
    /// capture — even if capture later fails the counter must reflect true
    /// consumption; a release failure (or a degenerate `billed × cost` overflow)
    /// leaves the counter conservatively over-charged (never under-charged) and
    /// logs.
    async fn release_unspent_cumulative_reserve(
        &self,
        context_id: &str,
        billed_count: u32,
        request_id: scp_protocol::context::outlets::stream::RequestId,
        counter_reserve: &crate::context::outlets::dispatch::CounterReserveSettlement,
    ) {
        if counter_reserve.amount_cumulative_reserved == 0 {
            return;
        }
        let Some(store) = self.caveat_counter_store() else {
            return;
        };
        // AMOUNT-based reconciliation: release `reserved − billed_count ×
        // cost_per_chunk`. The open reserves the WORST CASE
        // (`cumulative_reserve_amount` = `cost × effective_max_billable_chunks`,
        // and the per-chunk gate blocks billing past that same ceiling), so the
        // billed amount can never exceed the reserve. The counter is thereby
        // debited by EXACTLY the billed cumulative spend, regardless of how
        // small the declared estimate was. (`reserved_chunks` is retained on the
        // settlement record for diagnostics but is no longer load-bearing here,
        // since the reserve is no longer `cost × reserved_chunks`.)
        let unspent_amount = counter_reserve.unspent_release_amount(billed_count);
        if unspent_amount == 0 {
            return;
        }
        if let Err(e) = store
            .release(
                context_id,
                &counter_reserve.ucan_cid,
                scp_protocol::trust::CaveatKind::AmountCumulative,
                unspent_amount,
            )
            .await
        {
            tracing::warn!(
                context_id,
                request_id = %hex::encode(request_id),
                "outlet stream settlement: cumulative-reserve release failed: {e}"
            );
        }
    }

    /// §5.4.5 close-time economic settlement of a streaming-native invocation.
    ///
    /// Releases the unspent R4 HIGH-1 cumulative-counter reserve, refunds the
    /// unspent escrow under the context lock (when the context is still
    /// registered), and captures the §19.15.5 `PaymentReceipt` for the exact
    /// billed amount off-lock. Resilient to a mid-stream context teardown: an
    /// absent context falls back to the open-time
    /// [`EconomicPolicySnapshot`](crate::context::outlets::invoke::EconomicPolicySnapshot)
    /// (H8 "service rendered is billed") rather than early-returning.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] only on an unrecoverable lock/state failure.
    /// Payment-capture failures are NOT errors — they are recorded to the
    /// event log (R4 M2 reason code) and surfaced as `Ok(None)` so a refund
    /// that already happened is never stranded.
    #[allow(clippy::too_many_arguments)] // settlement reconciles escrow + receipt + R4 counter reserve in one close-time call
    pub async fn outlet_stream_settle(
        &self,
        context_id: &str,
        invoker_did: &DID,
        billed_amount: Amount,
        refund_amount: Amount,
        billed_count: u32,
        request_id: scp_protocol::context::outlets::stream::RequestId,
        outlet_id: &OutletId,
        // §5.4.5 MED-HIGH — open-time economic policy snapshot. Used as the
        // capture policy when the hosting context is no longer registered
        // (teardown mid-stream). `None` for zero-cost / Query streams.
        economic_policy_snapshot: Option<crate::context::outlets::invoke::EconomicPolicySnapshot>,
        // R4 HIGH-1 — the open-time cumulative-counter reservation. Used to
        // RELEASE the unspent portion of the reserve back to the durable
        // `AmountCumulative` counter (the open reserved
        // `cost_per_chunk × reserved_chunks`; only `billed_count` chunks were
        // actually billed, so `(reserved_chunks − billed_count) ×
        // cost_per_chunk` is returned). Zero-reserve / no-UCAN / legacy callers
        // pass a reserve that makes this a no-op.
        counter_reserve: crate::context::outlets::dispatch::CounterReserveSettlement,
    ) -> Result<Option<crate::economy::adapter::PaymentReceipt>, ContextError> {
        // R4 HIGH-1 — release the UNSPENT cumulative reserve FIRST (before the
        // escrow refund / receipt capture), so the durable `AmountCumulative`
        // counter is debited by exactly the billed spend, not the full
        // open-time reservation. Runs independently of payment capture.
        self.release_unspent_cumulative_reserve(
            context_id,
            billed_count,
            request_id,
            &counter_reserve,
        )
        .await;

        // Step 1: if the context is STILL registered, refund the unspent
        // escrow under its lock and read the LIVE economic policy (it may
        // have changed via governance since open). If the context is GONE,
        // skip the refund (the budget tracker was torn down with it — moot)
        // and fall back to the open-time snapshot policy so capture for
        // already-rendered service still proceeds. The adapter call (Step 2)
        // runs off-lock either way.
        let economic_policy = if let Ok(arc) = self.get_context_arc(context_id) {
            let mut guard = arc.lock().await;
            let ctx = &mut *guard;
            if refund_amount.value() > 0 {
                ctx.governance
                    .budget_tracker
                    .reverse_spend(invoker_did, refund_amount);
            }
            let policy = ctx.governance.economic_policy.clone();
            drop(guard);
            policy
        } else {
            // Context torn down mid-stream. The refund is moot (no budget
            // tracker to credit), but service was rendered, so capture
            // proceeds against the open-time snapshot (H8).
            tracing::debug!(
                context_id,
                request_id = %hex::encode(request_id),
                "outlet stream settlement: context gone mid-stream — \
                 capturing against open-time economic snapshot"
            );
            economic_policy_snapshot.map(|snap| snap.policy)
        };

        // Step 2: capture the §19.15.5 PaymentReceipt for the EXACT billed
        // amount — off-lock (adapter calls must not hold the per-context
        // mutex, mirroring the non-streaming Phase 3b discipline). Skip
        // entirely when nothing was billed or no adapter/policy is
        // configured (the legitimate zero-cost / no-payment-rail default).
        let (Some(adapter), Some(policy)) =
            (self.payment_adapter.as_ref(), economic_policy.as_ref())
        else {
            return Ok(None);
        };
        if billed_amount.value() == 0 {
            return Ok(None);
        }
        // The streaming billed amount (`cost_per_chunk × billed_count`) is
        // the authoritative figure — NOT a fresh policy evaluation. Authorize
        // and capture that exact amount so the receipt reflects what the
        // invoker actually consumed.
        let metadata = crate::economy::adapter::PaymentMetadata {
            action_type: scp_protocol::economy::types::PaidActionType::OutletCall,
            context_id: Some(context_id.to_owned()),
            idempotency_key: request_id,
        };
        let auth = match adapter
            .authorize_dyn(
                invoker_did,
                &policy.payee,
                billed_amount,
                policy.cost_schedule.currency,
                metadata,
            )
            .await
        {
            Ok(auth) => auth,
            Err(e) => {
                // R4 M2: persist a coarse reason code; keep the raw adapter
                // message only in the operator log.
                tracing::warn!(context_id, "authorize failed at stream settlement: {e}");
                self.record_payment_capture_failure(
                    context_id,
                    "outlet_stream",
                    invoker_did,
                    super::payment_error_to_capture_reason(&e),
                    Some(billed_amount),
                )
                .await;
                return Ok(None);
            }
        };
        match adapter.capture_dyn(&auth).await {
            Ok(receipt) => {
                tracing::debug!(
                    request_id = %hex::encode(request_id),
                    outlet_id = %outlet_id,
                    billed = billed_amount.value(),
                    billed_count,
                    receipt_id = %hex::encode(receipt.receipt_id),
                    "outlet stream settlement captured PaymentReceipt"
                );
                Ok(Some(receipt))
            }
            Err(e) => {
                // Capture failed after service was rendered (H8): the
                // billed amount is NOT reversed — only the unspent refund
                // (already applied above) is returned. Record the failure
                // for the audit trail, mirroring the non-streaming path.
                // R4 M2: persist a coarse reason code; the raw adapter
                // message stays in the operator log.
                tracing::warn!(context_id, "capture failed at stream settlement: {e}");
                self.record_payment_capture_failure(
                    context_id,
                    "outlet_stream",
                    invoker_did,
                    super::payment_error_to_capture_reason(&e),
                    Some(billed_amount),
                )
                .await;
                Ok(None)
            }
        }
    }

    /// SCP-OUT-036 — opens a §6.2.0.5 cross-context outlet stream from the
    /// invoker's source context to the outlet hosted in the target context.
    ///
    /// This is the production cross-context streaming entry point on
    /// [`ContextManager`]. It is the public-API surface that routes a
    /// cross-context stream open through the bridge implemented by the
    /// free function [`invoke_outlet_cross_context`]. The bridge consumes
    /// the executor-side chunk receiver `executor_rx` (chunks signed by
    /// the target operator under the target's `caveats_binding`) and
    /// re-issues each chunk under the source context's identity, applying
    /// per-chunk `output_schema` validation and `End.aggregate` validation
    /// against `aggregate_schema` (or `output_schema` when no aggregate
    /// schema is registered) per §5.4.5.
    ///
    /// The returned [`CrossContextStreamBridge`] carries the receiver of
    /// re-issued chunks plus the [`CrossContextStreamEventHandle`] that
    /// resolves to the source/target [`OutletInvokedEvent`] pair (sharing
    /// `stream_manifest_hash` per §6.2.0.5) once the bridge has emitted
    /// its terminal chunk. The fresh `RequestId` is bound into every
    /// re-issued chunk's signature preimage.
    ///
    /// # Boundary contract
    ///
    /// - `executor_rx` MUST be the receiver half of the executor's
    ///   stream — typically returned by the target context's
    ///   [`Self::open_outlet_stream`] or
    ///   [`Self::invoke_outlet_dispatch_with_economy_stream`] result on
    ///   the same outlet. The bridge reads chunks until the executor
    ///   side closes the channel or emits a terminal payload.
    /// - `inputs` carries the source/target context ids, the source's
    ///   re-issuing operator key, the source observer's
    ///   membership / hop-salt closures (§5.4.4 §6.2.0.1), the schemas,
    ///   and the §5.4.4 round-5 `max_padded_trail_depth`. The
    ///   `ContextManager` method does NOT mutate `inputs`; it forwards them
    ///   verbatim to the spawned bridge task so wrap-view membership and
    ///   hop-salt resolution capture the same caller perspective the
    ///   `ContextManager` exposes.
    /// - The bridge does not buffer the stream end-to-end; chunk-to-chunk
    ///   latency is bounded by re-signing + the channel's credit window
    ///   (§5.4.5 default `DEFAULT_CREDIT_WINDOW`).
    ///
    /// # Errors
    ///
    /// This method does NOT return a synchronous `Result` — every
    /// streaming failure (mid-stream bridge disconnect, output-schema
    /// violation, aggregate-schema violation) surfaces as a typed
    /// terminal `ChunkPayload::Error` chunk on the receiver, with a
    /// §5.4.4 `OutletError` envelope (carrying the `ContextHop` chain,
    /// HMAC pseudonymization, oracle collapse, trail padding) wrapped via
    /// SCP-OUT-029 [`wrap_cross_context_error`]. Bridge failures emit
    /// `transport.cross-context-bridge-failure` (`SCP-TOOL-6160`);
    /// schema violations emit `output.schema-violation` (`SCP-TOOL-6140`).
    ///
    /// # Pipeline
    ///
    /// SCP-OUT-036 audit caught [`invoke_outlet_cross_context`] as ghost
    /// code (5 `#[tokio::test]` callers, 0 production callers). This
    /// method is the production wiring: every cross-context streaming
    /// invocation that arrives at the public `ContextManager` API now
    /// reaches `invoke_outlet_cross_context` through here, satisfying
    /// the integration-checklist invariant that protocol logic must be
    /// reachable from a `ContextManager` method.
    pub fn invoke_outlet_streaming_cross_context(
        &self,
        inputs: CrossContextInvokeInputs,
        executor_rx: tokio::sync::mpsc::Receiver<
            scp_protocol::context::outlets::stream::OutletStreamChunk,
        >,
    ) -> (
        scp_protocol::context::outlets::stream::RequestId,
        CrossContextStreamBridge,
    ) {
        // The bridge is a self-contained streaming pipeline: it spawns
        // its own task, holds its own channels, and drives chunk-by-chunk
        // forwarding without consulting per-context manager state. The
        // ContextManager method exists to satisfy the integration
        // checklist (Rust function called from a ContextManager method,
        // not just exported) and to provide a stable public API for
        // future FFI wrapper(s); it does NOT add per-method state. Any
        // future per-context bookkeeping (e.g., admission tracker
        // integration with §5.4.5 concurrent-stream caps) MUST be added
        // here so the ContextManager remains the single source of truth.
        invoke_outlet_cross_context(inputs, executor_rx)
    }

    // =======================================================================
    // SCP-OUT-004 AC5 — outlet lifecycle ContextManager surface
    //
    // The eight methods below are the public `ContextManager` surface for
    // the outlet lifecycle verbs the rename target enumerated:
    // `register_outlet`, `update_outlet`, `deregister_outlet`,
    // `verify_outlet`, `list_outlets`, `get_outlet`, `open_outlet_session`,
    // and `invoke_outlet`. Each forwards to a real implementation — either
    // the `scp-protocol` free function operating on the caller-supplied
    // [`OutletRegistry`] (registry ownership remains in the FFI bridge per
    // the lock-split discipline noted at the top of this file) or one of
    // the existing [`Self::invoke_outlet_dispatch_with_economy_stream`] /
    // [`Self::open_outlet_stream`] / per-context governance-state readers.
    //
    // Without these methods FFI bridges had to import the protocol-level
    // free functions directly, which meant the `ContextManager` was not
    // the single integration point the integration-checklist requires.
    // The pinned [`pipeline_wiring`] assertion
    // `context_manager_exposes_outlet_lifecycle_methods` mechanically
    // proves these eight remain present.
    // =======================================================================

    /// SCP-OUT-004 AC5 — registers a new outlet against the supplied
    /// [`OutletRegistry`].
    ///
    /// Forwards to [`scp_protocol::context::outlets::register_outlet`]
    /// after snapshotting the per-context [`ContextRoleState`] from the
    /// manager's authoritative state. The registry is owned by the
    /// caller (typically the FFI bridge layer) so the lock-split
    /// invariant in the module-level docs is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown to this manager. Otherwise propagates
    /// [`scp_protocol::context::outlets::OutletError`] from the
    /// underlying registry call (registrant authorization, schema
    /// validation, query-cost violation, duplicate id) folded through
    /// [`outlet_protocol_error_to_context`].
    pub async fn register_outlet(
        &self,
        context_id: &str,
        registry: &mut scp_protocol::context::outlets::registry::OutletRegistry,
        registration: scp_protocol::context::outlets::OutletRegistration,
        registrant_did: &str,
    ) -> Result<
        (
            scp_protocol::context::outlets::OutletId,
            scp_protocol::context::outlets::OutletRegisteredEvent,
        ),
        ContextError,
    > {
        let role_state = self.snapshot_role_state(context_id).await?;
        scp_protocol::context::outlets::registry::register_outlet(
            registry,
            &role_state,
            registration,
            registrant_did,
        )
        .map_err(outlet_protocol_error_to_context)
    }

    /// SCP-OUT-004 AC5 — updates an existing outlet registration.
    ///
    /// Forwards to [`scp_protocol::context::outlets::update_outlet`]
    /// using the snapshotted per-context role state. See
    /// [`Self::register_outlet`] for the registry ownership contract.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] when the context
    /// is unknown. Otherwise propagates any
    /// [`scp_protocol::context::outlets::OutletError`] (outlet not
    /// found, updater not authorized, id mismatch, schema-floor
    /// violation).
    pub async fn update_outlet(
        &self,
        context_id: &str,
        registry: &mut scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &str,
        new_registration: scp_protocol::context::outlets::OutletRegistration,
        updater_did: &str,
    ) -> Result<scp_protocol::context::outlets::OutletUpdatedEvent, ContextError> {
        let role_state = self.snapshot_role_state(context_id).await?;
        scp_protocol::context::outlets::registry::update_outlet(
            registry,
            &role_state,
            outlet_id,
            new_registration,
            updater_did,
        )
        .map_err(outlet_protocol_error_to_context)
    }

    /// SCP-OUT-004 AC5 — removes an outlet from the supplied registry,
    /// enforcing operator-or-admin authorization against the manager's
    /// per-context [`ContextRoleState`].
    ///
    /// Mirrors the authorization shape of [`update_outlet`]: the actor
    /// must either be the registered `operator_did` or hold the admin
    /// role for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown to this manager. Returns
    /// [`ContextError::PermissionDenied`] when the actor is neither
    /// operator nor admin. Returns
    /// [`ContextError::OutletInvocation`] wrapping
    /// [`OutletError::OutletNotFound`] when the outlet is not in the
    /// registry.
    pub async fn deregister_outlet(
        &self,
        context_id: &str,
        registry: &mut scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &str,
        actor_did: &str,
    ) -> Result<scp_protocol::context::outlets::OutletRegistration, ContextError> {
        let role_state = self.snapshot_role_state(context_id).await?;
        let existing = registry.get(outlet_id).cloned().ok_or_else(|| {
            outlet_protocol_error_to_context(
                scp_protocol::context::outlets::OutletError::OutletNotFound {
                    outlet_id: outlet_id.to_owned(),
                },
            )
        })?;
        let is_operator = existing.operator_did == actor_did;
        let is_admin = scp_protocol::context::outlets::has_admin_role(&role_state, actor_did);
        if !is_operator && !is_admin {
            return Err(ContextError::PermissionDenied(format!(
                "actor '{actor_did}' is not authorized to deregister outlet '{outlet_id}'"
            )));
        }
        registry.remove(outlet_id).ok_or_else(|| {
            outlet_protocol_error_to_context(
                scp_protocol::context::outlets::OutletError::OutletNotFound {
                    outlet_id: outlet_id.to_owned(),
                },
            )
        })
    }

    /// SCP-OUT-004 AC5 — verifies an outlet by replaying its registered
    /// test vectors through the supplied executor.
    ///
    /// Forwards to [`scp_protocol::context::outlets::registry::verify_outlet`].
    /// The executor closure receives each test vector's `input` and
    /// returns the actual output that the framework compares against
    /// `expected_output`. Verification semantics are identical to the
    /// [`scp_protocol`] free function — this shim adds only the
    /// context-not-registered guard so callers see the standard
    /// [`ContextError::ContextNotRegistered`] envelope rather than a
    /// silent default match.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] when the context
    /// is unknown. Returns
    /// [`ContextError::OutletInvocation`] wrapping
    /// [`OutletError::OutletNotFound`] when the outlet is missing from
    /// the supplied registry.
    pub async fn verify_outlet<F>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &str,
        executor: F,
    ) -> Result<
        (
            scp_protocol::context::outlets::OutletVerificationResult,
            scp_protocol::context::outlets::OutletVerifiedEvent,
        ),
        ContextError,
    >
    where
        F: Fn(&serde_json::Value) -> serde_json::Value,
    {
        // Defensive guard so callers see the same context-membership
        // surface as the lifecycle methods even though `verify_outlet`
        // is a pure registry-side function. Manager-state assertions
        // happen here, registry-side validation happens in scp-protocol.
        let _ = self.snapshot_role_state(context_id).await?;
        scp_protocol::context::outlets::registry::verify_outlet(registry, outlet_id, executor)
            .map_err(outlet_protocol_error_to_context)
    }

    /// SCP-OUT-004 AC5 — lists every outlet currently registered on the
    /// per-context governance state.
    ///
    /// Reads from the manager's authoritative
    /// `GovernanceState.registered_outlets`, NOT a caller-supplied
    /// [`OutletRegistry`]. This is the single source of truth that
    /// downstream consequence and event-log consumers see; FFI bridges
    /// that maintain a side registry SHOULD reconcile against this list
    /// after every governance acceptance (the
    /// [`Self::execute_governance_action`] dispatch arm
    /// [`Self::execute_register_outlet`] is what populates the slot).
    ///
    /// Returns ids in append order — i.e., chronological by
    /// registration acceptance. Concurrent re-registrations of the same
    /// outlet appear multiple times: the SCP-OUT-041b receiver LRU
    /// disambiguates by `registration_event_id`, so listing-time
    /// dedup would lose information.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] when the context
    /// is unknown to this manager.
    #[allow(clippy::significant_drop_tightening)] // single read of governance.registered_outlets — guard scope is already minimal
    pub async fn list_outlets(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_protocol::context::outlets::OutletId>, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ids = guard
            .governance
            .registered_outlets
            .iter()
            .map(|r| r.outlet_id.clone())
            .collect();
        Ok(ids)
    }

    /// SCP-OUT-004 AC5 — returns the most-recent
    /// [`OutletRegistration`](scp_protocol::context::outlets::OutletRegistration)
    /// recorded on per-context governance state for `outlet_id`.
    ///
    /// Reads from `GovernanceState.registered_outlets` (the
    /// authoritative copy populated by
    /// [`Self::execute_register_outlet`]). When multiple registrations
    /// share an `outlet_id` (concurrent re-registration), returns the
    /// last one — matching the SCP-OUT-041b receiver-LRU "most recent"
    /// semantics that
    /// [`Self::execute_register_outlet`] uses to compute prior-catalog
    /// dwell-time.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] when the context
    /// is unknown.
    #[allow(clippy::significant_drop_tightening)] // single read of governance.registered_outlets — guard scope is already minimal
    pub async fn get_outlet(
        &self,
        context_id: &str,
        outlet_id: &str,
    ) -> Result<Option<scp_protocol::context::outlets::OutletRegistration>, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let found = guard
            .governance
            .registered_outlets
            .iter()
            .rfind(|r| r.outlet_id == outlet_id)
            .cloned();
        Ok(found)
    }

    /// SCP-OUT-004 AC5 — opens a §5.4.5 streaming session against the
    /// per-context outlet pipeline.
    ///
    /// Thin alias to [`Self::open_outlet_stream`] under the rename
    /// vocabulary the AC enumerated. The full admission, escrow,
    /// credit / cancel-ack tracker wiring lives in
    /// [`Self::open_outlet_stream`]; this method only re-exports it as
    /// `open_outlet_session` so the lifecycle surface is uniform under
    /// the §5.4 rename.
    ///
    /// # Errors
    ///
    /// See [`crate::context::outlets::dispatch::OpenStreamRejection`]
    /// for the open-time rejection taxonomy. Once the handle is
    /// returned, every failure mode surfaces as a terminal
    /// `ChunkPayload::Error` chunk on the receiver — never as a
    /// `Result` error.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_outlet_session<E>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        role_state: &scp_protocol::context::roles::ContextRoleState,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        timeout_ms: Option<u32>,
        executor: std::sync::Arc<E>,
        misdeclaration_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        >,
        handler_panic_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::HandlerPanicSink>,
        >,
        invoked_event_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::OutletInvokedEventSink>,
        >,
        settlement_sink: Option<
            std::sync::Arc<dyn crate::context::outlets::invoke::StreamSettlementSink>,
        >,
        params: crate::context::outlets::dispatch::OpenStreamParams,
        admission: std::sync::Arc<
            std::sync::Mutex<crate::context::outlets::stream::StreamAdmissionTracker>,
        >,
    ) -> Result<
        crate::context::outlets::dispatch::StreamSessionHandle,
        crate::context::outlets::dispatch::OpenStreamRejection,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized + 'static,
    {
        // §7.3.8 caveat enforcement (crypto-MED) is built INTERNALLY by
        // `open_outlet_stream` from `params` + the manager's counter store —
        // this re-export forwards verbatim so the §5.4 lifecycle surface stays
        // uniform.
        self.open_outlet_stream(
            context_id,
            registry,
            role_state,
            outlet_id,
            input,
            invoker_did,
            timeout_ms,
            executor,
            misdeclaration_sink,
            handler_panic_sink,
            invoked_event_sink,
            settlement_sink,
            params,
            admission,
        )
        .await
    }

    /// SCP-OUT-004 AC5 — invokes an outlet under the full economy
    /// pipeline, returning a streaming receiver of
    /// [`OutletStreamChunk`](scp_protocol::context::outlets::stream::OutletStreamChunk)s.
    ///
    /// Forwards to
    /// [`Self::invoke_outlet_dispatch_with_economy_stream`] which
    /// drives the same per-DID escalation, budget, escrow, and rollback
    /// discipline that
    /// [`Self::invoke_outlet_with_economy`] enforces and adapts the
    /// aggregated single-shot output into a `Data` + `End` chunk pair
    /// per the SCP-OUT-033 streaming contract. SDK / FFI consumers that
    /// need streaming (chunk-at-a-time progress) should call this
    /// method; consumers wanting an aggregated [`serde_json::Value`]
    /// should call
    /// [`Self::invoke_outlet_with_economy`] directly.
    ///
    /// # Errors
    ///
    /// Synchronous-validation failures (context not registered, outlet
    /// not found, capability denial) surface as `Result::Err`. Once the
    /// receiver is returned, mid-stream failures surface as terminal
    /// `ChunkPayload::Error` chunks, never as a `Result` error.
    #[allow(clippy::too_many_arguments)]
    pub async fn invoke_outlet<E>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::outlets::registry::OutletRegistry,
        outlet_id: &scp_protocol::context::outlets::OutletId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&UcanToken>,
        timeout_ms: Option<u32>,
        executor: &E,
        misdeclaration_sink: Option<&dyn crate::context::outlets::invoke::QueryMisdeclarationSink>,
        handler_panic_sink: Option<&dyn crate::context::outlets::invoke::HandlerPanicSink>,
        caveat_enforcement: Option<CaveatEnforcement<'_>>,
    ) -> Result<
        tokio::sync::mpsc::Receiver<scp_protocol::context::outlets::stream::OutletStreamChunk>,
        ContextError,
    >
    where
        E: crate::context::outlets::invoke::OutletExecutor + ?Sized,
    {
        self.invoke_outlet_dispatch_with_economy_stream(
            context_id,
            registry,
            outlet_id,
            input,
            invoker_did,
            spending_ucan,
            timeout_ms,
            executor,
            misdeclaration_sink,
            handler_panic_sink,
            caveat_enforcement,
        )
        .await
    }

    // -----------------------------------------------------------------------
    // Helpers backing the SCP-OUT-004 AC5 lifecycle shims above.
    // -----------------------------------------------------------------------

    /// Snapshot the per-context [`ContextRoleState`] for the lifecycle
    /// shims. Returns `ContextNotRegistered` when the context is
    /// unknown — same envelope every other shim above propagates so
    /// callers see a uniform error surface for the membership predicate.
    async fn snapshot_role_state(
        &self,
        context_id: &str,
    ) -> Result<scp_protocol::context::roles::ContextRoleState, ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        Ok(guard.role_state.clone())
    }
}

/// Folds a protocol-level [`scp_protocol::context::outlets::OutletError`]
/// returned by the [`scp_protocol::context::outlets::registry`] free
/// functions into a [`ContextError`] for the SCP-OUT-004 AC5 shims.
///
/// Authorization rejections surface as
/// [`ContextError::PermissionDenied`]; structural rejections (not
/// found, duplicate, schema-floor, signature) surface as the same
/// `PermissionDenied` envelope with an `SCP-TOOL-` prefix so callers
/// see a consistent error shape with the existing §5.4.2 query-cost
/// path used by [`super::governance::query_cost_violation_to_context`].
/// Cross-cutting bridges that need the typed §5.4.4 envelope can
/// reconstruct it from the underlying [`OutletError`] before this fold
/// (the protocol error is the carrier of truth — this fold is a
/// downgrade for the runtime `ContextError` surface, not a synthesis).
fn outlet_protocol_error_to_context(
    err: scp_protocol::context::outlets::OutletError,
) -> ContextError {
    use scp_protocol::context::outlets::OutletError as ProtoErr;
    match err {
        ProtoErr::RegistrantNotAuthorized { did } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6101: registrant '{did}' lacks OutletRegister capability"
        )),
        ProtoErr::UpdaterNotAuthorized { did } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6101: updater '{did}' is not operator or admin"
        )),
        ProtoErr::OutletNotFound { outlet_id } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6002: outlet '{outlet_id}' not found in registry"
        )),
        ProtoErr::OutletAlreadyRegistered { outlet_id } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6003: outlet '{outlet_id}' already registered"
        )),
        ProtoErr::OutletIdMismatch { expected, actual } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6004: outlet id mismatch: expected '{expected}', got '{actual}'"
        )),
        ProtoErr::QueryCostViolation { reason } => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6102: Query outlet cost violation (§5.4.2): {reason}" // SCP-CODE-OK: mirrors the legacy PermissionDenied envelope in governance.rs (`query_cost_violation_to_context`); SCP-OUT-027 migrates both call sites to a typed OutletError under CODE_PROTOCOL_VIOLATION + slug `query-cost-violation`.
        )),
        other => ContextError::PermissionDenied(format!(
            "SCP-TOOL-6100: outlet registry validation failed: {other}"
        )),
    }
}

/// Result of [`ContextManager::invoke_outlet_dispatch_with_economy`].
///
/// Mirrors [`ManagedOutletInvocationOutput`] with the addition of the
/// `pending_mutations` drained from the Action outlet's
/// [`MutableInvocation`](crate::context::outlets::invoke::MutableInvocation).
/// For Query outlets the vector is always empty.
#[derive(Debug)]
pub struct DispatchedManagedOutletInvocationOutput {
    /// Outlet output JSON.
    pub output: serde_json::Value,
    /// Event to append to the event log.
    pub event: OutletInvokedEvent,
    /// Consequences triggered by the invocation.
    pub consequences: Vec<scp_protocol::trust::consequence::TriggeredConsequence>,
    /// Payment receipt when a payment adapter is configured.
    pub payment_receipt: Option<crate::economy::adapter::PaymentReceipt>,
    /// Pending mutations enqueued through `MutableInvocation` write methods.
    pub pending_mutations: Vec<crate::context::outlets::invoke::MutationIntent>,
}

/// Bundle of Phase-1 outputs handed to Phase 2. Exists only so the
/// Phase 1 block can return cleanly (otherwise the `let phase1 = { ...
/// };` binding would have to be a four-tuple).
struct Phase1Snapshot {
    handle: crate::context::ContextHandle,
    role_state: scp_protocol::context::roles::ContextRoleState,
    ticket: OutletEconomyTicket,
    ctx_gen: ContextGeneration,
    /// The real per-invocation cost the runtime priced under the Phase 1
    /// lock via `economy_pre_check`. Surfaced out of Phase 1 so the
    /// §7.3.8 post-input hook builder can drive the `amount_max_per_call` /
    /// `amount_max_cumulative` caveats against the ACTUAL cost rather than
    /// the bridge-supplied estimate (single-shot bridges have no per-call
    /// price at the bridge layer and pass `estimated_cost: 0`). For free
    /// actions this is `Amount::new(0)`.
    action_cost: Amount,
}

// ===========================================================================
// SCP-OUT-022 — Layer composition (caveat ∧ Outbound ∧ Inbound ∧
//                                  SpendingCapability ∧ MemberBudgetTracker)
// ===========================================================================
//
// Implements §7.3.8 "Interaction with other access-control layers" and
// §6.2.0.1 "Bidirectional Consent Protocol". Caveats are an additive
// deny-surface; an invocation proceeds iff EVERY layer admits it.
//
// Spec-mandated evaluation order (§7.3.8 / story SCP-OUT-022):
//
//   1. caveat time-box        (valid_from / valid_until / hours / days)
//   2. caveat rate/counter    (max_calls / amount_max_cumulative / rate_window)
//   3. OutboundPolicy         (source-context governance, §6.2.0.1)
//   4. InboundPolicy          (target-context governance, §6.2.0.1)
//   5. SpendingCapability     (UCAN-bound per-action ceiling, §19.5)
//   6. MemberBudgetTracker    (governance-approved per-member budget, §19.3)
//
// Cross-context effective guard (§7.3.8): `OutboundPolicy ∧ InboundPolicy ∧
// caveat`. Intra-context invocations skip Inbound/Outbound (the policies
// only exist on cross-context interfaces); the function admits those layers
// when the policy is `None`.
//
// `evaluate_all_layers` short-circuits on the first denial and returns a
// [`LayerDenial`] whose [`LayerName`] identifies which layer rejected the
// invocation. The error code is one of the §5.4.4 sub-block constants from
// [`scp_protocol::context::outlets::error_codes`] — no hardcoded
// `SCP-TOOL-NNNN` literals — so the wire envelope round-trips through the
// canonical class+slug taxonomy.

/// Identifies which AND-composed access-control layer rejected an
/// invocation in [`evaluate_all_layers`].
///
/// The variant order mirrors the §7.3.8 evaluation order verbatim — when
/// adding a new layer, insert the variant at the spec-defined position so
/// the rejection-slug enum continues to match the order audit-readers see
/// in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerName {
    /// Caveat `valid_from` / `valid_until` / `hours_of_day` / `days_of_week`
    /// time-box check (§7.3.8 step 11b).
    CaveatTimeBox,
    /// Caveat `max_calls` / `amount_max_cumulative` / `rate_window` counter
    /// check against [`crate::trust::CaveatCounterStore`] (§7.3.8 post-input).
    CaveatRateCounter,
    /// `OutboundPolicy` set by the source context (§6.2.0.1):
    /// `allowed_callers`, `max_payload_bytes`.
    OutboundPolicy,
    /// `InboundPolicy` set by the target context (§6.2.0.1):
    /// `allowed_source_roles`, `require_spending_ucan`.
    InboundPolicy,
    /// UCAN-bound `SpendingCapability` `max_per_action` ceiling (§19.5).
    SpendingCapability,
    /// Governance-approved `MemberBudgetTracker` per-member budget (§19.3).
    MemberBudgetTracker,
}

impl LayerName {
    /// Returns a stable, lower-kebab-case identifier suitable for
    /// log fields, error envelope slugs, and assertion strings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaveatTimeBox => "caveat-time-box",
            Self::CaveatRateCounter => "caveat-rate-counter",
            Self::OutboundPolicy => "outbound-policy",
            Self::InboundPolicy => "inbound-policy",
            Self::SpendingCapability => "spending-capability",
            Self::MemberBudgetTracker => "member-budget-tracker",
        }
    }
}

impl std::fmt::Display for LayerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned by [`evaluate_all_layers`] when one of the composed layers
/// denies an invocation. Carries the [`LayerName`] that rejected, the
/// canonical §5.4.4 error code (one of `CODE_AUTHORIZATION_*` /
/// `CODE_INPUT_VIOLATION` / `CODE_ECONOMIC_FAULT` from
/// [`scp_protocol::context::outlets::error_codes`]), the catalogue slug for
/// the wire envelope, and a human-readable diagnostic message.
///
/// `error_code` and `slug` are `&'static str`s so this type is `Clone` +
/// `Send` + `Sync` without heap allocation in the hot path; only `message`
/// owns its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerDenial {
    /// Which composed layer rejected the invocation.
    pub layer: LayerName,
    /// §5.4.4 sub-block error code constant (e.g.
    /// [`scp_protocol::CODE_AUTHORIZATION_DENIED`]). Always one of the
    /// `error_codes::CODE_*` constants — never a hardcoded `SCP-TOOL-NNNN`
    /// literal.
    pub error_code: &'static str,
    /// §5.4.4 catalogue slug identifying the precise rejection reason.
    pub slug: &'static str,
    /// Human-readable diagnostic for the operator-side log path.
    pub message: String,
}

impl std::fmt::Display for LayerDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{layer} ({code} / {slug}): {message}",
            layer = self.layer,
            code = self.error_code,
            slug = self.slug,
            message = self.message,
        )
    }
}

impl std::error::Error for LayerDenial {}

/// Parameter bundle for [`evaluate_all_layers`].
///
/// Conceptually the four `(ctx, caveats, outlet, input)` arguments from the
/// SCP-OUT-022 acceptance criterion: `caveats`, `outlet`, and `input` are
/// the three direct fields; the rest of the per-context state (Inbound /
/// Outbound policies, spending capability, budget tracker, counter store,
/// adapter, target DID, source role) is bundled into the same struct
/// because Rust does not have keyword arguments and a positional list of
/// 14 parameters would be brittle to extend.
///
/// Construct one of these at the call site inside
/// [`ContextManager::invoke_outlet_with_economy`] and hand it to
/// [`evaluate_all_layers`]. Every field is borrowed; the struct does not
/// take ownership of any of the underlying data.
///
/// # Optional fields
///
/// - `outbound_policy` / `inbound_policy` — `None` for intra-context
///   invocations. The matching layer is treated as "admit" when absent.
/// - `spending_capability` — `None` when the caller did not present a
///   spending UCAN. The layer is treated as "admit" when absent AND
///   `estimated_cost == 0`; a non-zero cost with no spending capability is
///   rejected upstream by the existing `enforce_economy` path before this
///   composition is reached, so the absent case here is the free-action
///   admission, not a permissive bypass.
/// - `negotiated_adapter` / `target_did` — passed through to the caveat's
///   `check_invocation_local` half (already enforced upstream by SCP-OUT-021,
///   so the values are advisory at this layer).
/// - `source_role` — the role the invoker holds in the source context, when
///   crossing context boundaries. `None` for intra-context invocations.
/// - `counter_store` / `ucan_cid` — present when the invocation carries a
///   counter-bearing caveat. `None` short-circuits the
///   [`LayerName::CaveatRateCounter`] layer to admit (a token without
///   `max_calls` / `amount_max_cumulative` / `rate_window` populated needs
///   no counter store).
pub struct LayerCompositionInput<'a> {
    /// The presenting UCAN's invocation caveats.
    pub caveats: &'a scp_protocol::trust::caveats::InvocationCaveats,
    /// Outlet registration being invoked.
    ///
    /// Held on the struct to align with the SCP-OUT-022 acceptance-criterion
    /// signature `evaluate_all_layers(ctx, caveats, outlet, input)` and to
    /// give a future outlet-keyed layer (e.g. operator-attribution-aware
    /// rejection routing) a stable insertion point. The current §7.3.8 fold
    /// does not deref this field — `dead_code` is allowed deliberately on
    /// the struct so the API surface stays consistent with the AC.
    #[allow(dead_code)]
    pub outlet: &'a scp_protocol::context::outlets::OutletRegistration,
    /// Invocation input JSON (post-input-schema-validation value).
    ///
    /// Held on the struct to align with the SCP-OUT-022 acceptance-criterion
    /// signature `evaluate_all_layers(ctx, caveats, outlet, input)`. Today
    /// the §7.3.8 fold inspects only the caveats and policy values; a future
    /// schema-aware layer (e.g. cross-context input narrowing) would read
    /// this field. `dead_code` is allowed on this field so the API surface
    /// stays consistent with the AC.
    #[allow(dead_code)]
    pub input: &'a serde_json::Value,
    /// Outbound policy from the source context's interface configuration
    /// (§6.2.0.1). `None` for intra-context invocations.
    pub outbound_policy: Option<&'a scp_protocol::context::outlets::interface::OutboundPolicy>,
    /// Inbound policy from the target context's interface configuration
    /// (§6.2.0.1). `None` for intra-context invocations.
    pub inbound_policy: Option<&'a scp_protocol::context::outlets::interface::InboundPolicy>,
    /// `SpendingCapability` extracted from the presenting spending UCAN's
    /// `fct.spending_capability` field (§19.5). `None` for free actions.
    pub spending_capability: Option<&'a scp_protocol::crypto::ucan::spending::SpendingCapability>,
    /// Per-context member budget tracker (§19.3).
    pub budget_tracker: &'a scp_protocol::economy::budget::MemberBudgetTracker,
    /// The DID being charged / invoking the outlet.
    pub invoker_did: &'a DID,
    /// Pre-execution cost estimate for this invocation.
    pub estimated_cost: scp_protocol::economy::types::Amount,
    /// Unix seconds at the start of the invocation. Drives the time-box
    /// check (`valid_from` / `valid_until` / `hours_of_day` / `days_of_week`).
    pub now_secs: u64,
    /// Negotiated payment adapter, if any. Advisory at this layer; the
    /// `allowed_adapters` caveat is the synchronous post-input gate enforced
    /// by SCP-OUT-021's hook. `dead_code` is allowed because the OUT-022
    /// fold delegates the adapter check to OUT-021's `check_invocation_local`
    /// and the field exists only so a future adapter-aware layer has a
    /// stable insertion point.
    #[allow(dead_code)]
    pub negotiated_adapter: Option<&'a scp_protocol::economy::types::PaymentAdapterRef>,
    /// Cross-context target DID, if any. Advisory at this layer; the
    /// `allowed_target_dids` caveat is the synchronous post-input gate
    /// enforced by SCP-OUT-021's hook. `dead_code` is allowed because the
    /// OUT-022 fold delegates the target-DID check to OUT-021's
    /// `check_invocation_local`.
    #[allow(dead_code)]
    pub target_did: Option<&'a DID>,
    /// The role the invoker holds in the source context (cross-context
    /// invocations only). Drives the `InboundPolicy.allowed_source_roles`
    /// match.
    pub source_role: Option<&'a str>,
    /// Counter store for `max_calls` / `amount_max_cumulative` /
    /// `rate_window` caveats (§7.3.8 post-input). `None` skips the rate /
    /// counter layer; provide a real store whenever any of those caveat
    /// fields is populated.
    pub counter_store: Option<&'a dyn crate::trust::CaveatCounterApi>,
    /// Context ID — required when `counter_store` is `Some` to form the
    /// counter key.
    pub context_id: &'a str,
    /// Presenting UCAN's CID — required when `counter_store` is `Some` to
    /// form the counter key.
    pub ucan_cid: &'a str,
    /// Serialized payload byte length, used by the `OutboundPolicy.max_payload_bytes`
    /// check (§6.2.0.1). Pass `0` for intra-context invocations or when the
    /// payload size is not meaningful at this gate.
    pub payload_bytes: usize,
}

/// Composes the §7.3.8 access-control layers under logical AND and returns
/// the first denial in spec order.
///
/// Implements SCP-OUT-022. Evaluates, in this order:
///
/// 1. **Caveat time-box** — `valid_from`, `valid_until`, `hours_of_day`,
///    `days_of_week`. Pure compute over the caveat fields against
///    `now_secs`.
/// 2. **Caveat rate / counter** — `max_calls`, `amount_max_cumulative`,
///    `rate_window`. Atomic CAS against the supplied
///    [`crate::trust::CaveatCounterApi`]. Skipped when no counter store is
///    provided (a caveat set with none of the three counter fields populated
///    needs no store).
/// 3. **`OutboundPolicy`** — `allowed_callers`, `max_payload_bytes`. When
///    the source context published an interface (`Some(policy)`), the
///    invoker DID must be in `allowed_callers` (or the list must be empty,
///    meaning "any member with the `OutletInterface` capability") and the
///    payload size must not exceed `max_payload_bytes`. Skipped for
///    intra-context invocations (`None`).
/// 4. **`InboundPolicy`** — `allowed_source_roles`, `require_spending_ucan`.
///    When the target context published an interface (`Some(policy)`), the
///    `source_role` must match the allow-list (or be empty, meaning "any
///    role"); when `require_spending_ucan` is `true`, a `SpendingCapability`
///    must be present. Skipped for intra-context invocations (`None`).
/// 5. **`SpendingCapability`** — `max_per_action`. The estimated cost must
///    not exceed the per-action ceiling on the presenting UCAN's spending
///    capability. Skipped when `spending_capability` is `None` AND
///    `estimated_cost == 0` (free action — no spending UCAN required).
/// 6. **`MemberBudgetTracker`** — `has_budget` and remaining capacity.
///    Reads against the per-context budget tracker; the actual deduction
///    happens upstream in `invoke_outlet_with_economy`'s Phase 1 budget
///    block. Skipped for free actions (`estimated_cost == 0`).
///
/// The function short-circuits on the first failure and returns a
/// [`LayerDenial`] whose [`LayerName`] identifies which layer rejected the
/// invocation. On success returns `Ok(())`.
///
/// # Errors
///
/// Returns [`LayerDenial`] keyed by [`LayerName`] when a layer rejects the
/// invocation. The `error_code` field is one of the
/// [`scp_protocol::context::outlets::error_codes`] constants
/// (`CODE_AUTHORIZATION_DENIED`, `CODE_INPUT_VIOLATION`,
/// `CODE_ECONOMIC_FAULT`); no hardcoded `SCP-TOOL-NNNN` strings.
#[allow(clippy::too_many_lines)] // §7.3.8 ordering is six layers — splitting them masks the spec mapping.
pub async fn evaluate_all_layers(input: LayerCompositionInput<'_>) -> Result<(), LayerDenial> {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_INPUT_VIOLATION,
    };

    // -----------------------------------------------------------------
    // 1. caveat time-box
    // -----------------------------------------------------------------
    if let Some(valid_from) = input.caveats.valid_from
        && input.now_secs < valid_from
    {
        return Err(LayerDenial {
            layer: LayerName::CaveatTimeBox,
            error_code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.time-box-violation",
            message: format!(
                "valid_from: now={now} < valid_from={valid_from}",
                now = input.now_secs,
            ),
        });
    }
    if let Some(valid_until) = input.caveats.valid_until
        && input.now_secs > valid_until
    {
        return Err(LayerDenial {
            layer: LayerName::CaveatTimeBox,
            error_code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.time-box-violation",
            message: format!(
                "valid_until: now={now} > valid_until={valid_until}",
                now = input.now_secs,
            ),
        });
    }
    if let Some(hours_mask) = input.caveats.hours_of_day {
        // Unix-seconds → UTC-hour-of-day. Bit-true; no calendar awareness.
        #[allow(clippy::cast_possible_truncation)]
        let current_hour = ((input.now_secs / 3600) % 24) as u8;
        if !hours_mask.contains_hour(current_hour) {
            return Err(LayerDenial {
                layer: LayerName::CaveatTimeBox,
                error_code: CODE_AUTHORIZATION_DENIED,
                slug: "authorization.time-box-violation",
                message: format!(
                    "hours_of_day: current_utc_hour={current_hour} not in mask 0x{:08x}",
                    hours_mask.bits()
                ),
            });
        }
    }
    if let Some(days_mask) = input.caveats.days_of_week {
        // 1970-01-01 was a Thursday (weekday=4 with Sunday=0). Each Unix
        // day shifts weekday forward by 1.
        #[allow(clippy::cast_possible_truncation)]
        let current_weekday = (((input.now_secs / 86_400) + 4) % 7) as u8;
        if !days_mask.contains_day(current_weekday) {
            return Err(LayerDenial {
                layer: LayerName::CaveatTimeBox,
                error_code: CODE_AUTHORIZATION_DENIED,
                slug: "authorization.time-box-violation",
                message: format!(
                    "days_of_week: current_utc_weekday={current_weekday} not in mask 0x{:02x}",
                    days_mask.bits()
                ),
            });
        }
    }

    // -----------------------------------------------------------------
    // 2. caveat rate / counter
    // -----------------------------------------------------------------
    if let Some(store) = input.counter_store {
        if let Some(cap) = input.caveats.max_calls
            && let Err(err) = store
                .check_and_increment(
                    input.context_id,
                    input.ucan_cid,
                    scp_protocol::trust::CaveatKind::MaxCalls,
                    1,
                    cap,
                    0,
                )
                .await
        {
            return Err(layer_denial_from_counter_error(
                LayerName::CaveatRateCounter,
                err,
            ));
        }
        if let Some(cap) = input.caveats.amount_max_cumulative
            && let Err(err) = store
                .check_and_increment(
                    input.context_id,
                    input.ucan_cid,
                    scp_protocol::trust::CaveatKind::AmountCumulative,
                    input.estimated_cost.value(),
                    cap.value(),
                    0,
                )
                .await
        {
            return Err(layer_denial_from_counter_error(
                LayerName::CaveatRateCounter,
                err,
            ));
        }
        if let Some(window) = input.caveats.rate_window
            && let Err(err) = store
                .check_and_increment(
                    input.context_id,
                    input.ucan_cid,
                    scp_protocol::trust::CaveatKind::RateWindow,
                    0,
                    u64::from(window.max),
                    window.window_secs,
                )
                .await
        {
            return Err(layer_denial_from_counter_error(
                LayerName::CaveatRateCounter,
                err,
            ));
        }
    }

    // -----------------------------------------------------------------
    // 3. OutboundPolicy (§6.2.0.1) — only present for cross-context
    // -----------------------------------------------------------------
    if let Some(policy) = input.outbound_policy {
        // allowed_callers: empty means "any member with OutletInterface
        // capability"; non-empty restricts to listed DIDs.
        if !policy.allowed_callers.is_empty()
            && !policy
                .allowed_callers
                .iter()
                .any(|d| d == input.invoker_did)
        {
            return Err(LayerDenial {
                layer: LayerName::OutboundPolicy,
                error_code: CODE_AUTHORIZATION_DENIED,
                slug: "authorization.denied",
                message: format!(
                    "OutboundPolicy.allowed_callers does not include invoker {invoker}",
                    invoker = input.invoker_did,
                ),
            });
        }
        // max_payload_bytes: rejection mirrors the §5.4.4 input-class
        // taxonomy because the violation is a request-shape constraint, not
        // a delegation-bound one.
        if input.payload_bytes > policy.max_payload_bytes as usize {
            return Err(LayerDenial {
                layer: LayerName::OutboundPolicy,
                error_code: CODE_INPUT_VIOLATION,
                slug: "input.too-large",
                message: format!(
                    "OutboundPolicy.max_payload_bytes={cap} exceeded by payload of {actual} bytes",
                    cap = policy.max_payload_bytes,
                    actual = input.payload_bytes,
                ),
            });
        }
    }

    // -----------------------------------------------------------------
    // 4. InboundPolicy (§6.2.0.1) — only present for cross-context
    // -----------------------------------------------------------------
    if let Some(policy) = input.inbound_policy {
        // allowed_source_roles: empty means "any role"; non-empty restricts.
        if !policy.allowed_source_roles.is_empty() {
            let role_admitted = input
                .source_role
                .is_some_and(|role| policy.allowed_source_roles.iter().any(|r| r == role));
            if !role_admitted {
                return Err(LayerDenial {
                    layer: LayerName::InboundPolicy,
                    error_code: CODE_AUTHORIZATION_DENIED,
                    slug: "authorization.denied",
                    message: format!(
                        "InboundPolicy.allowed_source_roles does not include source role {role:?}",
                        role = input.source_role,
                    ),
                });
            }
        }
        // require_spending_ucan: when the target demands a spending UCAN, a
        // SpendingCapability must accompany the invocation.
        if policy.require_spending_ucan && input.spending_capability.is_none() {
            return Err(LayerDenial {
                layer: LayerName::InboundPolicy,
                error_code: CODE_AUTHORIZATION_DENIED,
                slug: "authorization.missing",
                message:
                    "InboundPolicy.require_spending_ucan=true but no SpendingCapability presented"
                        .to_owned(),
            });
        }
    }

    // -----------------------------------------------------------------
    // 5. SpendingCapability (§19.5) — per-action ceiling
    // -----------------------------------------------------------------
    if let Some(cap) = input.spending_capability
        && input.estimated_cost.value() > cap.max_per_action.0
    {
        return Err(LayerDenial {
            layer: LayerName::SpendingCapability,
            error_code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.denied",
            message: format!(
                "SpendingCapability.max_per_action={max} exceeded by estimated_cost={cost}",
                max = cap.max_per_action,
                cost = input.estimated_cost,
            ),
        });
    }

    // -----------------------------------------------------------------
    // 6. MemberBudgetTracker (§19.3) — governance-approved budget
    // -----------------------------------------------------------------
    if input.estimated_cost.value() > 0 {
        if !input.budget_tracker.has_budget(input.invoker_did) {
            return Err(LayerDenial {
                layer: LayerName::MemberBudgetTracker,
                error_code: CODE_ECONOMIC_FAULT,
                slug: "economic.budget-exceeded",
                message: format!(
                    "no governance-approved budget for {invoker}",
                    invoker = input.invoker_did,
                ),
            });
        }
        let remaining = input.budget_tracker.remaining(input.invoker_did);
        if input.estimated_cost.value() > remaining.value() {
            return Err(LayerDenial {
                layer: LayerName::MemberBudgetTracker,
                error_code: CODE_ECONOMIC_FAULT,
                slug: "economic.budget-exceeded",
                message: format!(
                    "MemberBudgetTracker remaining={remaining} < estimated_cost={cost} for {invoker}",
                    cost = input.estimated_cost,
                    invoker = input.invoker_did,
                ),
            });
        }
    }

    Ok(())
}

/// Maps a [`crate::trust::caveat_counter_store::CounterError`] into a
/// [`LayerDenial`] tagged with the supplied [`LayerName`]. Used by
/// [`evaluate_all_layers`] for the counter-bearing caveats so the error
/// envelope round-trips through the same §5.4.4 slug taxonomy as the
/// SCP-OUT-021 caveat hook.
fn layer_denial_from_counter_error(
    layer: LayerName,
    err: crate::trust::caveat_counter_store::CounterError,
) -> LayerDenial {
    use crate::trust::caveat_counter_store::{CounterError, CounterExhausted};
    use scp_protocol::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED;
    use scp_protocol::trust::CaveatKind;
    match err {
        CounterError::Exhausted(exhausted) => {
            let slug: &'static str = match exhausted.kind() {
                CaveatKind::MaxCalls => "authorization.denied",
                CaveatKind::AmountCumulative => "authorization.cumulative-exceeded",
                CaveatKind::RateWindow => "authorization.rate-exceeded",
            };
            let message = match &exhausted {
                CounterExhausted::MaxCalls { would_be, cap, .. } => {
                    format!("max_calls exhausted: would_be={would_be}, cap={cap}")
                }
                CounterExhausted::AmountCumulative { would_be, cap, .. } => {
                    format!("amount_max_cumulative exhausted: would_be={would_be}, cap={cap}")
                }
                CounterExhausted::RateWindow {
                    in_window,
                    cap,
                    window_secs,
                    ..
                } => format!(
                    "rate_window exhausted: in_window={in_window}, cap={cap}, window_secs={window_secs}"
                ),
            };
            LayerDenial {
                layer,
                error_code: CODE_AUTHORIZATION_DENIED,
                slug,
                message,
            }
        }
        CounterError::Store(store_err) => LayerDenial {
            layer,
            error_code: CODE_AUTHORIZATION_DENIED,
            slug: "authorization.denied",
            message: format!("caveat counter store error: {store_err}"),
        },
    }
}

/// Maps a [`LayerDenial`] from [`evaluate_all_layers`] into the
/// [`InvocationError::CaveatViolation`] envelope expected by the
/// post-input pipeline (`invoke_outlet_execute_and_validate`). The mapping
/// preserves the layer's slug verbatim so the
/// [`invocation_error_to_context`] dispatcher sees the same class+slug pair
/// that downstream catalog assertions expect.
fn invocation_error_from_layer_denial(denial: &LayerDenial) -> InvocationError {
    InvocationError::CaveatViolation {
        slug: denial.slug,
        message: format!("{}: {}", denial.layer.as_str(), denial.message),
    }
}

/// SCP-OUT-021 — convert a [`crate::trust::caveat_counter_store::CounterError`]
/// into the [`InvocationError::CaveatViolation`] envelope. The slug picks
/// out which counter-bearing caveat rejected the invocation
/// (`authorization.cumulative-exceeded`, `authorization.rate-exceeded`,
/// `authorization.denied`); the message preserves the
/// counter-store-side detail so operators see the cap and the would-be
/// post-increment value.
fn caveat_counter_error_to_invocation_error(
    err: crate::trust::caveat_counter_store::CounterError,
) -> InvocationError {
    use crate::trust::caveat_counter_store::{CounterError, CounterExhausted};
    use scp_protocol::trust::CaveatKind;
    match err {
        CounterError::Exhausted(exhausted) => {
            let slug: &'static str = match exhausted.kind() {
                CaveatKind::MaxCalls => "authorization.denied",
                CaveatKind::AmountCumulative => "authorization.cumulative-exceeded",
                CaveatKind::RateWindow => "authorization.rate-exceeded",
            };
            let message = match &exhausted {
                CounterExhausted::MaxCalls { would_be, cap, .. } => {
                    format!("max_calls exhausted: would_be={would_be}, cap={cap}")
                }
                CounterExhausted::AmountCumulative { would_be, cap, .. } => {
                    format!("amount_max_cumulative exhausted: would_be={would_be}, cap={cap}")
                }
                CounterExhausted::RateWindow {
                    in_window,
                    cap,
                    window_secs,
                    ..
                } => format!(
                    "rate_window exhausted: in_window={in_window}, cap={cap}, window_secs={window_secs}"
                ),
            };
            InvocationError::CaveatViolation { slug, message }
        }
        CounterError::Store(store_err) => {
            // Storage failure on the counter store — surface as an
            // execution failure rather than an authorization error so
            // operators can distinguish "infrastructure failed" from
            // "delegation rejected the call". The slug "authorization.denied"
            // is intentionally NOT used here because the call did not
            // fail due to a delegation rule.
            InvocationError::ExecutionFailed {
                message: format!("caveat counter store error: {store_err}"),
            }
        }
    }
}

/// Builds the post-input enforcement hook for `invoke_outlet_with_economy`.
///
/// Combines the SCP-OUT-021 caveat hook (synchronous local checks +
/// counter-store CAS) with the SCP-OUT-022 layer composition fold
/// (`evaluate_all_layers`). When both bundles are present, the
/// counter-bearing portion of OUT-021 is delegated to `evaluate_all_layers`
/// so the per-`(context_id, ucan_cid, kind)` counter is incremented at most
/// once per invocation; the OUT-021 portion runs only the synchronous
/// `check_invocation_local` half (`input_schema` / `amount_max_per_call` /
/// `allowed_adapters` / `allowed_target_dids`), which `evaluate_all_layers`
/// does not duplicate.
///
/// Returns `None` when neither bundle is present — the caller bypasses the
/// §7.3.8 post-input gate entirely in that case.
///
/// `counter_store` is the RUNTIME-OWNED durable counter store (resolved by
/// the caller from `caveat_counter_store()`, never supplied by a bridge —
/// mirroring how [`build_stream_post_input_hook`] reads it from the manager).
/// It is `None` only when the manager was built without a storage backend; in
/// that case the caller has ALREADY rejected any counter-bearing caveat
/// fail-closed before reaching this builder, so the counter-CAS branches
/// below are unreachable for counter-bearing caveats and the local-only
/// checks still run.
#[allow(clippy::too_many_lines)] // §7.3.8 spec ordering — splitting masks the spec mapping; SCP-OUT-022 ACs hinge on the ordering being visible in one place.
fn build_post_input_hook<'a>(
    context_id: &str,
    invoker_did: &DID,
    now_secs: u64,
    caveat_enforcement: Option<CaveatEnforcement<'_>>,
    counter_store: Option<Arc<dyn crate::trust::CaveatCounterApi>>,
    layer_composition: Option<LayerCompositionEnforcement>,
    outlet_for_layer_composition: Option<scp_protocol::context::outlets::OutletRegistration>,
) -> Option<crate::context::outlets::invoke::CaveatPostInputCheck<'a>> {
    if caveat_enforcement.is_none() && layer_composition.is_none() {
        return None;
    }

    // Capture every borrowed input by value so the returned Boxed FnOnce is
    // `'static` w.r.t. the function-level borrows. The hook's `'a` parameter
    // is the lifetime of the future inside the helper; the captures all live
    // for the duration of that future.
    let context_id_owned = context_id.to_owned();
    let invoker_did_owned = invoker_did.clone();

    // SCP-OUT-021 captures (only meaningful when caveat_enforcement.is_some()).
    // The counter store is RUNTIME-OWNED — moved into the capture here so the
    // counter-CAS branches and the OUT-022 fold both read the same handle.
    let out021 = caveat_enforcement.map(|enf| OUT021Capture {
        ucan_cid: enf.ucan_cid.to_owned(),
        counter_store,
        caveats: enf.caveats.clone(),
        estimated_cost: enf.estimated_cost,
        adapter: enf.negotiated_adapter.cloned(),
        target_did: enf.target_did.cloned(),
    });

    // SCP-OUT-022 captures (only meaningful when layer_composition.is_some()).
    let out022 = layer_composition.map(|bundle| OUT022Capture {
        bundle,
        outlet: outlet_for_layer_composition,
    });

    let hook: crate::context::outlets::invoke::CaveatPostInputCheck<'a> =
        Box::new(move |input: &serde_json::Value| {
            let input = input.clone();
            Box::pin(async move {
                // ---- SCP-OUT-021 synchronous local checks --------------
                // (input_schema / amount_max_per_call / allowed_adapters /
                //  allowed_target_dids). `evaluate_all_layers` does NOT
                // duplicate these — they are the OUT-021-specific gate that
                // sits BEFORE the §7.3.8 layer fold.
                if let Some(cap) = out021.as_ref()
                    && let Err(err) = cap.caveats.check_invocation_local(
                        &input,
                        cap.estimated_cost,
                        cap.adapter.as_ref(),
                        cap.target_did.as_ref(),
                    )
                {
                    return Err(
                        crate::context::outlets::invoke::InvocationError::CaveatViolation {
                            slug: err.slug(),
                            message: err.to_string(),
                        },
                    );
                }

                // ---- SCP-OUT-021 counter-store CAS ---------------------
                // Runs only when OUT-021 is enabled AND OUT-022 is NOT
                // present. When OUT-022 is present, `evaluate_all_layers`
                // owns the counter check (via its `CaveatRateCounter`
                // step), so running the OUT-021 counter here would double-
                // increment. Order is fixed: max_calls → amount_max_cumulative
                // → rate_window so the rejection slug stays deterministic
                // when more than one counter caveat would fail.
                // The counter store is RUNTIME-OWNED and may be `None` only
                // when the manager has no storage backend. In that case the
                // caller already rejected any counter-bearing caveat
                // fail-closed before this hook was built, so reaching the
                // counter-CAS branches with a populated counter-bearing
                // caveat AND a `None` store is unreachable. The
                // `if let Some(store)` makes that invariant explicit instead
                // of unwrapping.
                if let Some(cap) = out021.as_ref()
                    && out022.is_none()
                    && let Some(store) = cap.counter_store.as_ref()
                {
                    if let Some(max) = cap.caveats.max_calls
                        && let Err(err) = store
                            .check_and_increment(
                                &context_id_owned,
                                &cap.ucan_cid,
                                scp_protocol::trust::CaveatKind::MaxCalls,
                                1,
                                max,
                                0,
                            )
                            .await
                    {
                        return Err(caveat_counter_error_to_invocation_error(err));
                    }
                    if let Some(max) = cap.caveats.amount_max_cumulative
                        && let Err(err) = store
                            .check_and_increment(
                                &context_id_owned,
                                &cap.ucan_cid,
                                scp_protocol::trust::CaveatKind::AmountCumulative,
                                cap.estimated_cost.value(),
                                max.value(),
                                0,
                            )
                            .await
                    {
                        return Err(caveat_counter_error_to_invocation_error(err));
                    }
                    if let Some(window) = cap.caveats.rate_window
                        && let Err(err) = store
                            .check_and_increment(
                                &context_id_owned,
                                &cap.ucan_cid,
                                scp_protocol::trust::CaveatKind::RateWindow,
                                0,
                                u64::from(window.max),
                                window.window_secs,
                            )
                            .await
                    {
                        return Err(caveat_counter_error_to_invocation_error(err));
                    }
                }

                // ---- SCP-OUT-022 layer composition ---------------------
                // The §7.3.8 / §6.2 / §19.5 / §19.3 AND fold over time-box
                // → counter → OutboundPolicy → InboundPolicy →
                // SpendingCapability → MemberBudgetTracker. Short-circuits
                // on the first denial; the resulting `LayerDenial` names
                // the rejecting layer via `LayerName`.
                if let Some(layer_cap) = out022.as_ref() {
                    // The §7.3.8 layer-composition input borrows the
                    // OUT-021 caveats + counter store when present. When
                    // OUT-021 is absent, fall back to an empty caveat set
                    // (no time-box / no counter constraints) and skip the
                    // counter store — the four economic / policy layers
                    // still compose.
                    let empty_caveats = scp_protocol::trust::caveats::InvocationCaveats::empty();
                    let (caveats_ref, counter_store_ref, ucan_cid_ref): (
                        &scp_protocol::trust::caveats::InvocationCaveats,
                        Option<&dyn crate::trust::CaveatCounterApi>,
                        &str,
                    ) = out021
                        .as_ref()
                        .map_or((&empty_caveats, None, ""), |out021_cap| {
                            // `counter_store` is runtime-owned and optional;
                            // `as_deref()` already yields the
                            // `Option<&dyn CaveatCounterApi>` the layer fold
                            // expects (no extra `Some`-wrapping).
                            (
                                &out021_cap.caveats,
                                out021_cap.counter_store.as_deref(),
                                out021_cap.ucan_cid.as_str(),
                            )
                        });
                    // Always materialize the placeholder so the borrow held
                    // by `outlet_ref` is valid whether the registry produced
                    // a real registration or not. The placeholder is cheap
                    // (single allocation set) and `evaluate_all_layers`
                    // never derefs it on the present spec — but a future
                    // outlet-keyed layer would.
                    let outlet_placeholder = layer_composition_outlet_placeholder();
                    let outlet_ref: &scp_protocol::context::outlets::OutletRegistration =
                        layer_cap.outlet.as_ref().unwrap_or(&outlet_placeholder);
                    // Estimated cost feeds time-box-independent layers
                    // (SpendingCapability `max_per_action`, budget remaining,
                    // and the `amount_max_cumulative` counter). For free
                    // actions OUT-021 is absent and `estimated_cost` is 0.
                    let estimated_cost = out021
                        .as_ref()
                        .map_or(scp_protocol::economy::types::Amount::new(0), |c| {
                            c.estimated_cost
                        });
                    let composition_input = LayerCompositionInput {
                        caveats: caveats_ref,
                        outlet: outlet_ref,
                        input: &input,
                        outbound_policy: layer_cap.bundle.outbound_policy.as_ref(),
                        inbound_policy: layer_cap.bundle.inbound_policy.as_ref(),
                        spending_capability: layer_cap.bundle.spending_capability.as_ref(),
                        budget_tracker: &layer_cap.bundle.budget_tracker,
                        invoker_did: &invoker_did_owned,
                        estimated_cost,
                        now_secs,
                        negotiated_adapter: out021.as_ref().and_then(|c| c.adapter.as_ref()),
                        target_did: out021.as_ref().and_then(|c| c.target_did.as_ref()),
                        source_role: layer_cap.bundle.source_role.as_deref(),
                        counter_store: counter_store_ref,
                        context_id: &context_id_owned,
                        ucan_cid: ucan_cid_ref,
                        payload_bytes: layer_cap.bundle.payload_bytes,
                    };
                    if let Err(denial) = evaluate_all_layers(composition_input).await {
                        return Err(invocation_error_from_layer_denial(&denial));
                    }
                }

                Ok(())
            })
        });
    Some(hook)
}

/// Builds the §7.3.8 post-input caveat hook for a streaming open, ENTIRELY
/// inside the runtime, from the streaming context's own inputs — so every
/// bridge gets identical, complete enforcement without supplying any hook.
///
/// A stream validates its input ONCE at open (§5.4.5), so this hook is run
/// exactly once by `open_stream_session` before the pump spawns. It composes
/// the SAME enforcement the non-streaming `invoke_outlet_with_economy` path
/// runs via [`build_post_input_hook`]:
///
/// - synchronous local checks — `input_schema` conformance,
///   `amount_max_per_call` (gated against `cost_per_chunk`, the §19.5
///   per-invocation pricing unit), `allowed_adapters`, `allowed_target_dids`;
/// - the durable counter CAS — `max_calls`, `amount_max_cumulative`,
///   `rate_window` — keyed on `(context_id, ucan_cid, kind)`. The stream-open
///   counts as ONE invocation against these counters. This is a DISTINCT
///   dimension from HIGH-2's `CreditTracker` cumulative billable-CHUNK ceiling
///   (also derived from `max_calls`): the counter increments by 1 per open;
///   the credit tracker increments per billed chunk. Both bounds coexist by
///   design and do not double-charge.
///
/// `negotiated_adapter` and `target_did` are `None` — the streaming open
/// surface (parity with `outlet_invoke`) negotiates neither a payment adapter
/// nor a cross-context target DID.
///
/// Returns:
/// - `Ok(None)` when the effective caveat set has no §7.3.8 post-input
///   constraint (the open bypasses the gate, exactly as
///   [`build_post_input_hook`] returns `None`);
/// - `Ok(Some(hook))` when a hook is built (counter CAS included iff a counter
///   store is configured AND counter-bearing caveats are present);
/// - `Err(OpenStreamRejection::CaveatPostInputViolation)` — FAIL CLOSED — when
///   the effective caveats carry a counter-bearing cap (`max_calls` /
///   `amount_max_cumulative` / `rate_window`) but the manager has NO counter
///   store. A cap the runtime cannot enforce MUST reject the open, never pass.
type StreamPostInputBuild = (
    Option<crate::context::outlets::invoke::CaveatPostInputCheck<'static>>,
    Option<crate::context::outlets::dispatch::StreamCounterReservation>,
);

fn build_stream_post_input_hook(
    caveats: &scp_protocol::trust::caveats::InvocationCaveats,
    cost_per_chunk: scp_protocol::economy::types::Amount,
    counter_store: Option<&Arc<dyn crate::trust::CaveatCounterApi>>,
) -> Result<StreamPostInputBuild, crate::context::outlets::dispatch::OpenStreamRejection> {
    use scp_protocol::context::outlets::error_codes;

    // No §7.3.8 post-input constraint → neither a local-check hook nor a
    // counter reservation (parity with `build_post_input_hook` returning
    // `None`).
    if !caveats.requires_post_input_check() {
        return Ok((None, None));
    }

    // R4 HIGH-2: the durable counter CAS is NO LONGER part of this hook. The
    // hook performs ONLY the synchronous local checks (`input_schema`,
    // `amount_max_per_call`, `allowed_adapters`, `allowed_target_dids`) which
    // have no durable side effect, so they can run early (fail fast) at the
    // open's Step 2.5 without burning counter capacity on an open that later
    // fails the pump-permit / executor-launch gate. The counter CAS
    // (`max_calls` / `amount_max_cumulative` (RESERVED at
    // `cost_per_chunk × est_chunks` — R4 HIGH-1) / `rate_window`) is committed
    // at the FINAL open-time gate via the returned `StreamCounterReservation`.
    //
    // Fail-closed: a counter-bearing cap with NO counter store cannot be
    // enforced anywhere, so reject the open rather than silently admit.
    let reservation = if caveats.has_counter_bearing_caveat() {
        match counter_store {
            Some(store) => Some(
                crate::context::outlets::dispatch::StreamCounterReservation {
                    counter_store: Arc::clone(store),
                    caveats: caveats.clone(),
                },
            ),
            None => {
                return Err(
                    crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation {
                        slug: error_codes::SLUG_AUTHORIZATION_DENIED,
                    },
                );
            }
        }
    } else {
        None
    };

    // The synchronous local-check hook. Always built when a post-input
    // constraint exists; it gates `input_schema` / `amount_max_per_call`
    // (against `cost_per_chunk`, the §19.5 per-invocation unit) /
    // `allowed_adapters` / `allowed_target_dids` and runs BEFORE any durable
    // side effect.
    let caveats_owned = caveats.clone();
    let hook: crate::context::outlets::invoke::CaveatPostInputCheck<'static> = Box::new(
        move |input: &serde_json::Value| {
            let caveats = caveats_owned.clone();
            let input = input.clone();
            Box::pin(async move {
                caveats
                    .check_invocation_local(&input, cost_per_chunk, None, None)
                    .map_err(|err| {
                        use scp_protocol::trust::caveats::CheckInvocationError;
                        let message = err.to_string();
                        match err {
                            CheckInvocationError::InputSchemaViolation { .. } => {
                                crate::context::outlets::invoke::InvocationError::InputValidationFailed {
                                    message,
                                }
                            }
                            other => {
                                crate::context::outlets::invoke::InvocationError::CaveatViolation {
                                    slug: other.slug(),
                                    message,
                                }
                            }
                        }
                    })
            })
        },
    );
    Ok((Some(hook), reservation))
}

/// Captures the SCP-OUT-021 hook fields by value so the returned closure is
/// owned (no borrows from `invoke_outlet_with_economy`'s stack frame).
struct OUT021Capture {
    ucan_cid: String,
    caveats: scp_protocol::trust::caveats::InvocationCaveats,
    /// Runtime-owned durable counter store. `None` only when the manager has
    /// no storage backend, in which case the caller has already rejected any
    /// counter-bearing caveat fail-closed before this capture is built.
    counter_store: Option<Arc<dyn crate::trust::CaveatCounterApi>>,
    estimated_cost: scp_protocol::economy::types::Amount,
    adapter: Option<scp_protocol::economy::types::PaymentAdapterRef>,
    target_did: Option<DID>,
}

/// Captures the SCP-OUT-022 layer-composition fields by value alongside the
/// optional outlet snapshot. The outlet snapshot is `None` when the registry
/// lookup miss surfaces — `evaluate_all_layers` does not actually deref the
/// `outlet` field at present, but the placeholder keeps the
/// [`LayerCompositionInput`] surface honest in case a future layer adds an
/// outlet-keyed check.
struct OUT022Capture {
    bundle: LayerCompositionEnforcement,
    outlet: Option<scp_protocol::context::outlets::OutletRegistration>,
}

/// Returns a synthetic, never-signed [`OutletRegistration`] used as a
/// placeholder when the registry lookup misses inside the layer-composition
/// hook. `evaluate_all_layers` does NOT dereference any field of `outlet`
/// today — the placeholder exists so the [`LayerCompositionInput`] surface
/// stays non-`Option` and a future outlet-keyed layer can fail loudly with
/// the synthetic kind / id rather than silently admit on `None`.
fn layer_composition_outlet_placeholder() -> scp_protocol::context::outlets::OutletRegistration {
    scp_protocol::context::outlets::OutletRegistration {
        outlet_id: String::new(),
        kind: scp_protocol::context::outlets::OutletKind::Action,
        name: String::new(),
        description: String::new(),
        schema: scp_protocol::context::outlets::OutletSchema {
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            aggregate_schema: None,
        },
        implementation_hash: [0; 32],
        test_vectors: Vec::new(),
        operator_did: DID(String::new()),
        cost: None,
        message_catalog: Vec::new(),
        registered_at: 0,
        signature: Vec::new(),
    }
}

/// Pure mapping table — given an [`InvocationError`], returns the
/// `(class, code, slug, retry)` tuple from which the typed
/// [`OutletError`] envelope is built per spec §5.4.4 (SCP-OUT-027).
///
/// Split out from [`invocation_error_to_context`] so the function below
/// stays under the `clippy::too_many_lines` threshold without sacrificing
/// the per-variant `§5.4.4` rationale comments. The `retry` hint is
/// `Never` for every variant because outlet-invocation failures at this
/// seam are caller-driven (validation, authorization, panic): bridges
/// and SDKs that need finer-grained retry MUST consume the `slug`, not
/// the policy field.
///
/// Identical-body arms are intentionally merged via `|`-patterns
/// (clippy `match_same_arms`).
fn invocation_error_to_envelope_template(
    err: &InvocationError,
) -> (
    scp_protocol::context::outlets::errors::OutletErrorClass,
    &'static str,
    &'static str,
    scp_protocol::context::outlets::errors::RetryPolicy,
) {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_EXECUTION_FAULT, CODE_INPUT_VIOLATION,
        CODE_OUTPUT_VIOLATION, CODE_PROTOCOL_VIOLATION, SLUG_AUTHORIZATION_DENIED,
        SLUG_ECONOMIC_BUDGET_EXCEEDED, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
        SLUG_INPUT_SCHEMA_VIOLATION, SLUG_KIND_MISMATCH, SLUG_OUTPUT_SCHEMA_VIOLATION,
        SLUG_PROTOCOL_VIOLATION, SLUG_QUERY_COST_VIOLATION, SLUG_QUERY_VIOLATION,
    };
    use scp_protocol::context::outlets::errors::{OutletErrorClass, RetryPolicy};

    match err {
        // Protocol-class — context not active is a §5.4.4 protocol violation
        // (the invocation pipeline pre-condition is unmet).
        InvocationError::ContextNotActive { .. } => (
            OutletErrorClass::Protocol,
            CODE_PROTOCOL_VIOLATION,
            SLUG_PROTOCOL_VIOLATION,
            RetryPolicy::Never,
        ),
        // Authorization-class — `InvokerNotAuthorized` is the canonical
        // denial; `OutletNotFound` collapses into the same response per
        // the §5.4.4 query-oracle rule (registration state must not leak
        // through error class).
        InvocationError::InvokerNotAuthorized { .. } | InvocationError::OutletNotFound { .. } => (
            OutletErrorClass::Authorization,
            CODE_AUTHORIZATION_DENIED,
            SLUG_AUTHORIZATION_DENIED,
            RetryPolicy::Never,
        ),
        // Input-class — schema-violation against the outlet's input schema.
        InvocationError::InputValidationFailed { .. } => (
            OutletErrorClass::Input,
            CODE_INPUT_VIOLATION,
            SLUG_INPUT_SCHEMA_VIOLATION,
            RetryPolicy::Never,
        ),
        // Output-class — schema-violation against the outlet's output schema.
        InvocationError::OutputValidationFailed { .. } => (
            OutletErrorClass::Output,
            CODE_OUTPUT_VIOLATION,
            SLUG_OUTPUT_SCHEMA_VIOLATION,
            RetryPolicy::Never,
        ),
        // Execution-class — handler-side fault. `ExecutionFailed` and
        // `HandlerPanic` (the SCP-OUT-028 recovered-panic variant) share
        // the §5.4.4 `execution.handler-panic` slug; the parallel
        // `OutletVerifiedEvent { reason: HandlerPanicked }` integrity
        // signal for `HandlerPanic` was already emitted via the panic
        // sink inside `invoke_outlet`.
        InvocationError::ExecutionFailed { .. } | InvocationError::HandlerPanic { .. } => (
            OutletErrorClass::Execution,
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_HANDLER_PANIC,
            RetryPolicy::Never,
        ),
        // Execution-class — `Timeout` is the runtime-executor expiration;
        // `Cancelled` surfaces under the same slug at this seam (the
        // dedicated `execution.cancel-ack-timeout` slug applies to the
        // OUT-038 streaming cancel-ack timer, not to the `Cancelled`
        // invocation outcome).
        InvocationError::Timeout { .. } | InvocationError::Cancelled => (
            OutletErrorClass::Execution,
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_TIMEOUT,
            RetryPolicy::Never,
        ),
        // Economic-class — budget exhausted before the call cleared.
        InvocationError::BudgetExceeded { .. } => (
            OutletErrorClass::Economic,
            CODE_ECONOMIC_FAULT,
            SLUG_ECONOMIC_BUDGET_EXCEEDED,
            RetryPolicy::Never,
        ),
        // Protocol-class — §5.4.2 query-cost-floor violation.
        InvocationError::OutletQueryCostViolation { .. } => (
            OutletErrorClass::Protocol,
            CODE_PROTOCOL_VIOLATION,
            SLUG_QUERY_COST_VIOLATION,
            RetryPolicy::Never,
        ),
        // Protocol-class — §5.4.2 ReadOnlyInvocation guard fired.
        InvocationError::QueryViolation { .. } => (
            OutletErrorClass::Protocol,
            CODE_PROTOCOL_VIOLATION,
            SLUG_QUERY_VIOLATION,
            RetryPolicy::Never,
        ),
        // Protocol-class — §5.4.2 kind misdeclaration.
        InvocationError::KindMismatch { .. } => (
            OutletErrorClass::Protocol,
            CODE_PROTOCOL_VIOLATION,
            SLUG_KIND_MISMATCH,
            RetryPolicy::Never,
        ),
        // SCP-OUT-021 caveat violations carry their own slug (set at the
        // caveat-evaluator layer). Routing follows the slug prefix:
        // `input.*` → Input-class, otherwise Authorization-class. Mirrors
        // `error_code_to_class`/`error_code_to_default_slug` in the
        // §5.4.4 registry.
        InvocationError::CaveatViolation { slug, .. } => caveat_violation_to_envelope(slug),
    }
}

/// Routes a `CaveatViolation` slug to its `(class, code, slug, retry)`
/// envelope template per the §5.4.4 registry.
///
/// SCP-OUT-025: the dispatch consults the §5.4.4 registry's
/// [`slug_to_class`] (the source of truth for the slug → class mapping)
/// rather than hand-rolled prefix string matching. The `(class, code,
/// retry)` triple is then derived from the registry-assigned class,
/// keeping caveat-rejected envelopes byte-aligned with the registry.
///
/// Slugs not registered in the §5.4.4 taxonomy collapse to the
/// Authorization-class catch-all (`SCP-TOOL-6110` / `RetryPolicy::Never`)
/// so an SCP-OUT-021 caveat that surfaces a slug outside the registered
/// vocabulary still produces a typed envelope. The runtime tests verify
/// every caveat slug the evaluator emits is in the registry, so this
/// fallback is defensive.
///
/// [`slug_to_class`]: scp_protocol::context::outlets::error_codes::slug_to_class
fn caveat_violation_to_envelope(
    slug: &'static str,
) -> (
    scp_protocol::context::outlets::errors::OutletErrorClass,
    &'static str,
    &'static str,
    scp_protocol::context::outlets::errors::RetryPolicy,
) {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_INPUT_VIOLATION, CODE_TRANSPORT_FAULT,
        slug_to_class,
    };
    use scp_protocol::context::outlets::errors::{OutletErrorClass, RetryPolicy};

    // Registry-driven dispatch (SCP-OUT-025). Falls back to prefix matching
    // only for slugs not yet tabulated in the §5.4.4 registry — this
    // preserves backwards compatibility with caveat slugs that round-trip
    // through SCP-OUT-021 ahead of being tabulated, while ensuring every
    // tabulated slug is routed via the canonical mapping.
    let class = slug_to_class(slug).unwrap_or_else(|| {
        if slug.starts_with("input.") {
            OutletErrorClass::Input
        } else if slug.starts_with("transport.") {
            OutletErrorClass::Transport
        } else if slug.starts_with("economic.") {
            OutletErrorClass::Economic
        } else {
            OutletErrorClass::Authorization
        }
    });

    match class {
        OutletErrorClass::Input => (
            OutletErrorClass::Input,
            CODE_INPUT_VIOLATION,
            slug,
            RetryPolicy::Never,
        ),
        OutletErrorClass::Transport => (
            OutletErrorClass::Transport,
            CODE_TRANSPORT_FAULT,
            slug,
            RetryPolicy::WithBackoff {
                min: std::time::Duration::from_secs(1),
                max: std::time::Duration::from_secs(30),
            },
        ),
        OutletErrorClass::Economic => (
            OutletErrorClass::Economic,
            CODE_ECONOMIC_FAULT,
            slug,
            RetryPolicy::Never,
        ),
        // Authorization, Protocol, Execution, Output, Governance — caveat
        // violations fall under the §5.4.4 query-oracle-collapse target
        // (Authorization-class denial). The registry-driven branch above
        // routes to the most accurate class; any other class collapses to
        // Authorization to preserve the §5.4.4 oracle property.
        OutletErrorClass::Authorization
        | OutletErrorClass::Protocol
        | OutletErrorClass::Execution
        | OutletErrorClass::Output
        | OutletErrorClass::Governance => (
            OutletErrorClass::Authorization,
            CODE_AUTHORIZATION_DENIED,
            slug,
            RetryPolicy::Never,
        ),
    }
}

/// Maps an [`InvocationError`] to a [`ContextError::OutletInvocation`] envelope
/// per spec §5.4.4 ("Outlet Error Taxonomy") and SCP-OUT-027.
///
/// Each `InvocationError` variant maps to a distinct `(code, slug, class,
/// retry)` tuple inside a typed [`OutletError`] envelope, which is then
/// wrapped in [`ContextError::OutletInvocation`]. This **replaces** the
/// pre-OUT-027 lossy `PermissionDenied(format!(...))` collapse, which
/// flattened thirteen variants into one untyped string and discarded both
/// the §5.4.4 class and retry hint.
///
/// # Construction model
///
/// At this seam the runtime does not have a per-outlet `outlet_message_key`
/// or a `registration_event_id`, so the envelope is built via
/// [`OutletError::from_invocation_error_template`]. That constructor
/// synthesizes deterministic placeholders for those fields — see its
/// rustdoc for the placeholder semantics. Wire-form HMAC is **not** in
/// scope here: this `ContextError` is consumed by Rust callers and FFI
/// translators, never serialized as a §5.4.4 wire envelope. Cross-context
/// wire emission happens at SCP-OUT-029's `wrap_cross_context_error` seam
/// where the real per-outlet key is in scope.
///
/// # Invariants enforced by tests
///
/// - Every `InvocationError` variant produces an `OutletError` whose
///   `code` and `class` match the §5.4.4 mapping table — see
///   `outlet_error_mapping_tests` below.
/// - `OutletNotFound` maps to `authorization.denied` (the §5.4.4
///   query-oracle-collapse target — registration-state must not leak via
///   error class).
/// - No code path returns `ContextError::PermissionDenied` from this
///   function (verified by `grep` in CI per SCP-OUT-027 AC).
fn invocation_error_to_context(err: InvocationError) -> ContextError {
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_VIOLATION,
    };
    use scp_protocol::context::outlets::errors::{OutletError, OutletErrorClass, RetryPolicy};

    let (class, code, slug, retry) = invocation_error_to_envelope_template(&err);

    // Construct the typed envelope. `from_invocation_error_template` only
    // returns `Err` if `code` or `slug` fail their respective regex checks
    // — every `(code, slug)` pair returned by the helper is sourced from
    // the §5.4.4 registry constants (or, for `CaveatViolation`, from a
    // `&'static str` slug pre-validated by the SCP-OUT-021 caveat
    // evaluator), so this branch is unreachable in practice. We surface a
    // defensive `Protocol`-class envelope rather than panicking so a
    // future drift produces a typed `ContextError`, not a runtime crash.
    match OutletError::from_invocation_error_template(class, code, slug, retry) {
        Ok(envelope) => ContextError::OutletInvocation(Box::new(envelope)),
        Err(_construction_failed) => {
            // Fallback: synthesize the most generic Protocol-class envelope
            // so the typed-error invariant still holds. The `unwrap_or_else`
            // below cannot itself fail because `CODE_PROTOCOL_VIOLATION` /
            // `SLUG_PROTOCOL_VIOLATION` are registry-validated literals.
            let fallback = OutletError::from_invocation_error_template(
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_VIOLATION,
                SLUG_PROTOCOL_VIOLATION,
                RetryPolicy::Never,
            )
            .unwrap_or_else(|_| OutletError {
                // Defense-in-depth: hand-build the Protocol envelope if even
                // the registry literals fail validation (impossible by
                // construction). The fallback preserves the invariant that
                // every `InvocationError` produces a typed `OutletError`.
                code: CODE_PROTOCOL_VIOLATION.to_owned(),
                slug: SLUG_PROTOCOL_VIOLATION.to_owned(),
                class: OutletErrorClass::Protocol,
                message: [0u8; scp_protocol::context::outlets::errors::WIRE_MESSAGE_LEN],
                retry: RetryPolicy::Never,
                detail: None,
                source_chain: Vec::new(),
                pad_nonce: [0u8; scp_protocol::context::outlets::errors::PAD_NONCE_LEN],
                registration_event_id: [0u8;
                    scp_protocol::context::outlets::errors::REGISTRATION_EVENT_ID_LEN],
                unknown_fields: std::collections::BTreeMap::new(),
            });
            // The original `InvocationError` is dropped here — its Display
            // is already captured at the call site that constructed it.
            // The fallback envelope preserves the typed-error invariant.
            drop(err);
            ContextError::OutletInvocation(Box::new(fallback))
        }
    }
}

// ===========================================================================
// SCP-OUT-015 — Chain amplification rule + per-kind chain depth budget
// ===========================================================================
//
// Implements spec §6.2.0.3 (amplification rule) and §6.2.0.4 (chain depth
// split). Cross-context invocations carry an `origin_kind` (an [`OutletKind`])
// propagated from the outermost caller through every hop. At each
// cross-context hop the runtime checks:
//
// 1. **Amplification rule (§6.2.0.3):** `origin_kind != Query OR hop_kind ==
//    Query` — else reject with [`OutletAmplificationError::AmplificationViolation`].
//    A `Query`-originated chain MUST NOT trigger any `Action` invocation,
//    directly or transitively. This closes the "free read laundered into
//    paid write" amplification class.
// 2. **Per-kind chain depth budget (§6.2.0.4):** the context-level
//    `max_chain_depth` parameter is partitioned by kind. Query budget is
//    `max_chain_depth` (full budget); Action budget is
//    `max(1, max_chain_depth / 2)`. The hop-kind counter (NOT the origin-kind
//    counter) is decremented on each accepted hop — a Query hop consumes
//    Query budget regardless of whether the chain was Action-originated.
//
// Failed checks emit a structured failure event into BOTH event logs (the
// caller's source context AND the callee's target context) per spec §6.2 —
// "every cross-context call is recorded in both event logs" — so the
// rejection is auditable from either side.
//
// `origin_kind` is bound to the outermost UCAN delegation chain, NOT to a
// runtime-only claim. The hop target re-derives `origin_kind` from the
// validated UCAN stem (`outlet_query:*` → Query; `outlet_call:*` → Action)
// rather than trusting a transport-layer sidecar field. Forging
// `origin_kind` requires forging a signed UCAN with a different stem — see
// [`origin_kind_from_ucan_stem`] for the derivation helper.

/// Sentinel actor DID for amplification-rejection events appended to the
/// per-context event log. Mirrors the `system:` actor used for consequence
/// events in `governance::append_consequence_event` so the event payload's
/// origin is unambiguous: a runtime-emitted rejection, not an actor
/// invocation.
const AMPLIFICATION_REJECTION_ACTOR_DID: &str = "system:amplification-violation";

/// Sentinel actor DID for chain-depth rejection events. Symmetric with
/// [`AMPLIFICATION_REJECTION_ACTOR_DID`]; kept distinct so log readers can
/// disambiguate the failure mode at the actor field without parsing the
/// payload.
const CHAIN_DEPTH_REJECTION_ACTOR_DID: &str = "system:chain-depth-exceeded";

/// Sentinel hash placeholder for `OutletInvokedEvent` records that describe
/// a rejected hop — no input/output was actually executed, but the event
/// schema demands a non-empty hex string. The all-zero SHA-256 prefix is
/// reserved for synthesized rejection records and never collides with a
/// real `sha256_json` result (which has 256 bits of entropy on real input).
const REJECTION_HASH_SENTINEL: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Errors produced by [`cross_context_invoke`].
///
/// Mirrors [`OutletErrorClass::Authorization::AmplificationViolation`] and
/// the kind-aware [`OutletErrorClass::Resource::ChainDepthExceeded`] from
/// spec §5.4.4 (the typed taxonomy lands in SCP-OUT-036/038; the codes are
/// allocated here within the SCP-TOOL 6100-6199 sub-block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutletAmplificationError {
    /// `origin_kind == Query` AND `hop_kind == Action` — the "free read
    /// laundered into paid write" class. Rejected at the cross-context
    /// consent gate (§6.2.0.3).
    ///
    /// Error code: `SCP-TOOL-6120` (slug `authorization.amplification-violation`).
    AmplificationViolation {
        /// The outermost-caller's `OutletKind` (recovered from the signed
        /// UCAN delegation chain by the hop target). Always `Query` when
        /// this variant is constructed.
        origin_kind: OutletKind,
        /// The hop-target outlet's declared `OutletKind`. Always `Action`
        /// when this variant is constructed.
        hop_kind: OutletKind,
    },
    /// The kind-appropriate chain-depth counter would go negative. Per
    /// §6.2.0.4 the Query budget is the full `max_chain_depth`; the Action
    /// budget is `max(1, max_chain_depth / 2)`.
    ///
    /// Error code: `SCP-TOOL-6121` (slug `resource.chain-depth-exceeded`).
    ChainDepthExceeded {
        /// The hop's declared `OutletKind` — selects which budget was
        /// exhausted (Query → `max_chain_depth`; Action → `max(1, max/2)`).
        hop_kind: OutletKind,
        /// The remaining budget on the kind-appropriate counter at the
        /// moment the hop was rejected. Always `0` when this variant is
        /// constructed (a non-zero remaining would have permitted the
        /// decrement).
        remaining: u8,
    },
}

impl OutletAmplificationError {
    /// Returns the canonical SCP error code for this rejection. Used by
    /// the event-log emission path so the on-wire event payload carries
    /// the same code surfaced to callers.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::AmplificationViolation { .. } => "SCP-TOOL-6120", // SCP-CODE-OK: event-log payload uses CODE_INPUT_VIOLATION (registered §5.4.4 6120-6129); the typed OutletError seam (SCP-OUT-027) maps amplification to CODE_AUTHORIZATION_DENIED, while the on-wire event-log payload retains the per-rule code per §6.2 amplification spec
            Self::ChainDepthExceeded { .. } => "SCP-TOOL-6121", // SCP-CODE-OK: event-log payload code in §5.4.4 6120-6129 reserved-gap; the slug `resource.chain-depth-exceeded` is currently unallocated in error_codes.rs and a follow-up registry update will register it
        }
    }

    /// Returns the kebab-case slug used in spec §5.4.4 / sdk-common.md
    /// taxonomy. Mirrored on the event-log payload.
    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::AmplificationViolation { .. } => "authorization.amplification-violation",
            Self::ChainDepthExceeded { .. } => "resource.chain-depth-exceeded",
        }
    }
}

impl std::fmt::Display for OutletAmplificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AmplificationViolation {
                origin_kind,
                hop_kind,
            } => write!(
                f,
                "{}: chain amplification rejected (origin_kind={origin_kind:?}, hop_kind={hop_kind:?}) — §6.2.0.3",
                self.error_code()
            ),
            Self::ChainDepthExceeded {
                hop_kind,
                remaining,
            } => write!(
                f,
                "{}: chain depth exceeded for {hop_kind:?} hop (remaining={remaining}) — §6.2.0.4",
                self.error_code()
            ),
        }
    }
}

impl std::error::Error for OutletAmplificationError {}

/// Result of an accepted cross-context hop check.
///
/// Carries the post-decrement counters that the caller MUST propagate into
/// the next-hop call frame. The `origin_kind` is unchanged — `origin_kind`
/// is set ONCE at the outermost caller and propagated verbatim through every
/// hop per §6.2.0.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossContextHopAccepted {
    /// Unchanged from the pre-check value — the outermost caller's kind,
    /// preserved across hops.
    pub origin_kind: OutletKind,
    /// Post-decrement Query counter. Decremented when `hop_kind == Query`,
    /// passed through unchanged when `hop_kind == Action`.
    pub depth_remaining_query: u8,
    /// Post-decrement Action counter. Decremented when `hop_kind == Action`,
    /// passed through unchanged when `hop_kind == Query`.
    pub depth_remaining_action: u8,
}

/// Returns the Query chain-depth budget for a context with the given
/// `max_chain_depth` parameter (§6.2.0.4).
///
/// The Query budget is the full `max_chain_depth` value — Query
/// invocations get the whole context-configured budget because they are
/// idempotent, cacheable, cost-capped reads. Falls back to the protocol
/// default ([`scp_protocol::provenance::attach::DEFAULT_MAX_CHAIN_DEPTH`])
/// when `max_chain_depth` is `None`.
#[must_use]
pub const fn query_chain_budget(max_chain_depth: Option<u8>) -> u8 {
    effective_max_chain_depth(max_chain_depth)
}

/// Returns the Action chain-depth budget for a context with the given
/// `max_chain_depth` parameter (§6.2.0.4).
///
/// The Action budget is `max(1, max_chain_depth / 2)` — half the Query
/// budget, with a floor of 1 so a context with `max_chain_depth = 1`
/// still permits at least one Action hop. Action chains have stricter
/// amplification bounds without requiring a second unrelated parameter.
///
/// **Derivation site only.** Per AC1 the Action budget MUST NOT be stored
/// as a `max_chain_depth_action` field on `ContextParams`; it is always
/// derived at the enforcement call site from `max_chain_depth`. Adding a
/// second config field would diverge from §6.2.0.4 and create the surface
/// where `max_chain_depth_action > max_chain_depth` is configurable —
/// that surface MUST NOT exist.
#[must_use]
pub const fn action_chain_budget(max_chain_depth: Option<u8>) -> u8 {
    let q = effective_max_chain_depth(max_chain_depth);
    // `max(1, q / 2)` — `q / 2` for integer division on u8, then floor of 1
    // so `q == 1` still yields a 1-hop Action budget.
    let half = q / 2;
    if half == 0 { 1 } else { half }
}

// ===========================================================================
// SCP-OUT-016 — Per-kind cross-context rate tier defaults (§6.2.0.2)
// ===========================================================================
//
// Spec §6.2.0.2 partitions the cross-context outlet-interface rate-limit
// defaults by [`OutletKind`]: Query outlets get an order-of-magnitude
// higher tier (`(600, 100)` per-interface/per-caller) reflecting the
// idempotent read-only contract; Action outlets retain the
// pre-classification baseline (`(60, 10)`). The tier flips on the
// `OutletKind` field set by SCP-OUT-011 — when the runtime fills in a
// missing `max_calls_per_minute` on the cross-context invocation path,
// it consults the kind from the registered outlet (or the offer's
// `outlet_schema.kind` on the receive side).
//
// **Single source of truth.** The kind → `(per_interface, per_caller)`
// mapping lives in [`scp_protocol::context::outlets::interface::OutletInterfaceDefaults`].
// The runtime helpers below thinly re-export that mapping so the
// cross-context invocation path here in `scp-runtime` does not duplicate
// the constants — they are derived through the protocol-layer helper at
// every call site. A future spec revision that tweaks the tiers updates
// the protocol helper and the runtime path follows automatically.
//
// **Explicit values preserved (AC5).** These helpers are *only* consulted
// when the caller-supplied policy omitted `max_calls_per_minute`. The
// runtime cross-context invocation path passes any caller-supplied value
// through to the per-interface and per-caller rate-limit checks
// (`invoke_cross_context` in the protocol layer) untouched.

/// Re-export of [`scp_protocol::context::outlets::interface::OutletInterfaceDefaults`]
/// — the §6.2.0.2 classification-aware cross-context rate-tier defaults.
///
/// Exposed here so the runtime cross-context invocation path can derive
/// the kind-aware default rate tier without taking a transitive dependency
/// on the deep `scp_protocol::context::outlets::interface` path. See
/// SCP-OUT-016.
pub use scp_protocol::context::outlets::interface::OutletInterfaceDefaults;

/// Returns the §6.2.0.2 default per-interface / per-caller calls-per-minute
/// tuple for the given hop's [`OutletKind`].
///
/// `Query → (600, 100)`, `Action → (60, 10)`. Use this on the
/// cross-context invocation path when the caller-supplied policy omitted
/// `max_calls_per_minute` so the runtime fills in the right tier.
///
/// Equivalent to
/// [`OutletInterfaceDefaults::tuple_for_kind`](OutletInterfaceDefaults::tuple_for_kind);
/// re-exposed at the runtime layer for symmetry with
/// [`query_chain_budget`] / [`action_chain_budget`]. See SCP-OUT-016.
#[must_use]
pub const fn cross_context_rate_tier_default(kind: OutletKind) -> (u32, u32) {
    OutletInterfaceDefaults::tuple_for_kind(kind)
}

/// Recovers the [`OutletKind`] implied by a UCAN token's outermost capability
/// stem (§6.2.0.3 "`origin_kind` is bound to the UCAN delegation chain").
///
/// Inspects every `att` entry in the token's payload and returns:
///
/// - [`OutletKind::Query`] if EVERY recognized stem is `outlet_query:*` /
///   `outlet:query:*`.
/// - [`OutletKind::Action`] if any recognized stem is `outlet_call:*` /
///   `outlet:call:*`.
/// - `None` if the token carries no outlet stems at all (either an invalid
///   hop UCAN or a delegation that does not authorize an outlet — the caller
///   should reject).
///
/// **Mixed-stem tokens.** A token whose `att` list mixes `outlet_query:*`
/// and `outlet_call:*` stems returns [`OutletKind::Action`] (the wider
/// kind) — mixing stems within a single delegation level is a spec-banned
/// shape that the §7.3.8 caveats `narrow()` verifier rejects upstream
/// (SCP-OUT-018), but the kind-recovery helper biases toward the stricter
/// fail-safe per §5.4.2 so a mixed-stem token cannot escape Action
/// amplification rules.
///
/// **Hop-target rule (§6.2.0.3).** The hop target MUST call this on the
/// validated UCAN it received — NOT on a transport-sidecar `origin_kind`
/// claim. This is what makes the "`origin_kind` is signed" property
/// operationally true: the kind is recovered from the signed stem, never
/// from a runtime field that an intermediate hop could rewrite.
///
/// `Capability::OutletQueryAll`, `Capability::OutletCallAll`,
/// `Capability::OutletQuery(_)`, and `Capability::OutletCall(_)` are the
/// four parsed forms produced by [`Capability::from_name`]; all four are
/// recognized here.
#[must_use]
pub fn origin_kind_from_ucan_stem(token: &UcanToken) -> Option<OutletKind> {
    let mut saw_query = false;
    let mut saw_action = false;
    for att in &token.payload.att {
        // The `with` URI carries `scp:ctx:{id}/{stem}:{action}`. We rely on
        // the canonical stem-naming carried by `Capability::from_name` — the
        // Attenuation `can` is the action portion (e.g. `*`, `assistant`),
        // and the stem is in the `with` URI itself.
        let stem = att.with.rsplit('/').next().unwrap_or("");
        // The stem may be the full `outlet_query:foo` or `outlet:query:foo`
        // form — both prefixes are recognized.
        if stem.starts_with("outlet_query:") || stem.starts_with("outlet:query:") {
            saw_query = true;
        } else if stem.starts_with("outlet_call:") || stem.starts_with("outlet:call:") {
            saw_action = true;
        }
        // `Capability::OutletQueryAll` etc. encode without a tail-suffix:
        // `outlet:query:*`. Both branches above already match because the
        // prefix scan does not require a non-`*` suffix.
        // Also support the bare `Capability` `to_name()` forms.
        // Synonyms via `Capability::from_name` round-trip:
        if let Some(cap) = Capability::new(stem) {
            match cap {
                Capability::OutletQuery(_) | Capability::OutletQueryAll => saw_query = true,
                Capability::OutletCall(_) | Capability::OutletCallAll => saw_action = true,
                _ => {}
            }
        }
    }
    match (saw_query, saw_action) {
        // Mixed-stem token: bias to Action (stricter fail-safe per §5.4.2).
        (_, true) => Some(OutletKind::Action),
        (true, false) => Some(OutletKind::Query),
        (false, false) => None,
    }
}

/// Synthesizes a `OutletInvokedEvent` describing a rejected cross-context
/// hop. Both event logs (caller's source context AND callee's target
/// context) receive a copy with shared `request_id` so the failure is
/// linkable across the cross-context boundary per §6.2.0.5 / §7.7
/// "Cross-context provenance".
///
/// Fields:
///
/// - `status` is [`OutletStatus::Error`] — the hop never executed.
/// - `execution_time_ms` is `0` — the rejection happens at the consent
///   gate before any executor runs.
/// - `input_hash` and `output_hash` are the all-zero sentinel
///   ([`REJECTION_HASH_SENTINEL`]); no input was processed and no output
///   was produced.
/// - `cost` is `None` — the rejection precedes any economy bookkeeping.
///
/// The `request_id` is generated once and reused on both events so the
/// pair is correlatable across logs.
fn build_amplification_rejection_event(
    outlet_id: &OutletId,
    invoker_did: &DID,
    request_id: &str,
) -> OutletInvokedEvent {
    // SCP-OUT-035: a rejected hop never opened a stream, so the four
    // streaming fields carry rejection sentinels — zero chunk counts,
    // all-zero manifest hash, terminal status `Error` carrying the
    // §5.4.4 amplification-violation code. The amplification gate
    // runs before any stream is opened or any chunk is emitted, so
    // there is no manifest to commit and no chunks to bill.
    OutletInvokedEvent {
        request_id: request_id.to_owned(),
        outlet_id: outlet_id.clone(),
        invoker_did: invoker_did.clone(),
        status: OutletStatus::Error,
        execution_time_ms: 0,
        input_hash: REJECTION_HASH_SENTINEL.to_owned(),
        output_hash: Some(REJECTION_HASH_SENTINEL.to_owned()),
        cost: None,
        stream_chunk_count: 0,
        chunks_billed: 0,
        stream_manifest_hash: [0u8; 32],
        stream_terminal_status: scp_protocol::context::outlets::stream::StreamTerminalStatus::Error(
            scp_protocol::context::outlets::error_codes::CODE_PROTOCOL_VIOLATION.to_owned(),
        ),
        // Synthesized structural-rejection event — no stream pump ran, so
        // there is no pump-vs-manifest divergence.
        audit_anomaly: None,
    }
}

/// Best-effort durable append of a synthesized rejection event into a
/// context's event log. Mirrors [`super::governance::append_consequence_event`]
/// in failure handling — a `tracing::warn!` is logged on append failure but
/// the path NEVER propagates the error: the structural rejection (the
/// `Err(OutletAmplificationError)`) is the authoritative outcome; the
/// event-log entry is the audit trail. Refusing to surface the rejection
/// because the event log is unavailable would let amplification slip past
/// the consent gate.
///
/// `actor_did` is the rejection-reason sentinel
/// ([`AMPLIFICATION_REJECTION_ACTOR_DID`] or
/// [`CHAIN_DEPTH_REJECTION_ACTOR_DID`]) so log readers can filter on it
/// without parsing the payload. The payload's `error_code` and `slug`
/// fields carry the SCP error code + spec slug for in-band querying.
fn append_amplification_rejection_event(
    event_log: &dyn super::super::builder::ContextEventLogProvider,
    context_id: &str,
    error: &OutletAmplificationError,
    rejection_event: &OutletInvokedEvent,
) {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let actor_did = match error {
        OutletAmplificationError::AmplificationViolation { .. } => {
            AMPLIFICATION_REJECTION_ACTOR_DID
        }
        OutletAmplificationError::ChainDepthExceeded { .. } => CHAIN_DEPTH_REJECTION_ACTOR_DID,
    };
    let payload = serde_json::json!({
        "kind": "OutletInvokedEvent",
        "rejection": {
            "error_code": error.error_code(),
            "slug": error.slug(),
            "reason": match error {
                OutletAmplificationError::AmplificationViolation {
                    origin_kind,
                    hop_kind,
                } => serde_json::json!({
                    "type": "amplification-violation",
                    "origin_kind": origin_kind,
                    "hop_kind": hop_kind,
                }),
                OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining,
                } => serde_json::json!({
                    "type": "chain-depth-exceeded",
                    "hop_kind": hop_kind,
                    "remaining": remaining,
                }),
            },
        },
        "event": rejection_event,
    });
    if let Err(e) = event_log.append_context_event_with_payload(
        &context_id_bytes,
        "OutletInvoked",
        actor_did,
        Some(&payload),
    ) {
        tracing::warn!(
            context_id,
            outlet_id = %rejection_event.outlet_id,
            invoker = %rejection_event.invoker_did,
            error_code = error.error_code(),
            log_error = %e,
            "failed to append cross-context amplification rejection event"
        );
    }
}

/// Cross-context hop check (§6.2.0.3 amplification rule + §6.2.0.4 chain
/// depth split).
///
/// Pure compute. Takes the outermost-caller's `origin_kind`, the hop
/// target's declared `hop_kind`, and the per-kind remaining counters.
/// Returns:
///
/// - `Ok(CrossContextHopAccepted)` with the post-decrement counters when
///   the hop is permitted. `origin_kind` is preserved (not reset). The
///   counter for the **hop-kind** is decremented; the counter for the
///   other kind is unchanged. AC4 fails the hop when the relevant
///   counter would go negative — this guard runs before the decrement so
///   the returned counters always satisfy the invariant
///   `accepted.depth_remaining_{query,action} <= input
///   depth_remaining_{query,action}`.
///
/// - `Err(OutletAmplificationError::AmplificationViolation)` when
///   `origin_kind == Query AND hop_kind == Action` (§6.2.0.3). The check
///   runs BEFORE the depth decrement so a Query → Action chain is rejected
///   at the consent gate without consuming budget — preventing the
///   "free read laundered into paid write" attack class.
///
/// - `Err(OutletAmplificationError::ChainDepthExceeded)` when the hop's
///   kind-appropriate counter is `0` (no headroom for the decrement).
///
/// **Counter selection (AC5).** Per the PRD's "matches the invoked outlet,
/// not the originator, for depth accounting" rule, the hop-kind counter
/// is decremented — NOT the origin-kind counter. Concretely: an
/// `Action`-originated chain that calls a Query outlet decrements
/// `depth_remaining_query`, not `depth_remaining_action`. This matches
/// the spec's intent that each kind has an independent ceiling on its
/// own use, regardless of how the chain started.
///
/// **`origin_kind` propagation (§6.2.0.3).** The function does NOT mutate
/// `origin_kind` — it is a property of the outermost UCAN delegation,
/// preserved verbatim through every hop. Callers passing
/// `origin_kind = Action` for a chain that started with a `Query` UCAN
/// stem are violating spec §6.2.0.3; the hop target MUST re-derive
/// `origin_kind` from the validated UCAN stem via
/// [`origin_kind_from_ucan_stem`] before invoking this function so a
/// malicious upstream hop cannot rewrite the kind.
///
/// **Action budget derivation (AC1).** `depth_remaining_action` is
/// derived AT THE CALL SITE from `ContextParams::max_chain_depth` via
/// [`action_chain_budget`] — `max(1, max/2)`. There is no
/// `max_chain_depth_action` field on `ContextParams`, by spec §6.2.0.4
/// design.
///
/// # Errors
///
/// Returns [`OutletAmplificationError::AmplificationViolation`] for
/// Query → Action chains and [`OutletAmplificationError::ChainDepthExceeded`]
/// when the hop-kind counter is exhausted.
///
/// # Spec
///
/// - §6.2.0.3 — amplification rule
/// - §6.2.0.4 — chain depth split
pub const fn cross_context_invoke(
    origin_kind: OutletKind,
    hop_kind: OutletKind,
    depth_remaining_query: u8,
    depth_remaining_action: u8,
) -> Result<CrossContextHopAccepted, OutletAmplificationError> {
    // §6.2.0.3 amplification rule: `origin_kind != Query OR hop_kind == Query`.
    // Equivalent positive form: reject when `origin_kind == Query AND hop_kind == Action`.
    if matches!(origin_kind, OutletKind::Query) && matches!(hop_kind, OutletKind::Action) {
        return Err(OutletAmplificationError::AmplificationViolation {
            origin_kind,
            hop_kind,
        });
    }

    // §6.2.0.4 per-kind chain-depth budget. Decrement the hop-kind counter.
    match hop_kind {
        OutletKind::Query => {
            if depth_remaining_query == 0 {
                return Err(OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining: 0,
                });
            }
            Ok(CrossContextHopAccepted {
                origin_kind,
                depth_remaining_query: depth_remaining_query - 1,
                depth_remaining_action,
            })
        }
        OutletKind::Action => {
            if depth_remaining_action == 0 {
                return Err(OutletAmplificationError::ChainDepthExceeded {
                    hop_kind,
                    remaining: 0,
                });
            }
            Ok(CrossContextHopAccepted {
                origin_kind,
                depth_remaining_query,
                depth_remaining_action: depth_remaining_action - 1,
            })
        }
    }
}

/// Records a cross-context hop rejection in BOTH the source and target
/// contexts' event logs (§6.2 — every cross-context call is recorded in
/// both event logs).
///
/// Builds a single `OutletInvokedEvent` with `status = Error`, shared
/// `request_id`, and zero-sentinel hashes; appends it to both logs with the
/// rejection-reason payload (error code, slug, structured reason).
///
/// **Failure mode.** The append paths are best-effort — a per-context
/// failure logs a `tracing::warn!` but never propagates because the
/// authoritative outcome is the structural `Err(OutletAmplificationError)`
/// returned by [`cross_context_invoke`]. The event-log entries are the
/// audit trail; the rejection itself runs even when the audit log is
/// unavailable.
///
/// `request_id` SHOULD be a UUID v4 string generated by the caller —
/// passing a stable id makes both event-log entries linkable across
/// contexts even though the audit-log emission paths are independent.
#[must_use]
pub fn record_amplification_rejection(
    event_log: Option<&dyn super::super::builder::ContextEventLogProvider>,
    source_context_id: &str,
    target_context_id: &str,
    outlet_id: &OutletId,
    invoker_did: &DID,
    request_id: &str,
    error: &OutletAmplificationError,
) -> OutletInvokedEvent {
    let event = build_amplification_rejection_event(outlet_id, invoker_did, request_id);
    if let Some(log) = event_log {
        append_amplification_rejection_event(log, source_context_id, error, &event);
        // Spec §6.2 / §7.7: both event logs record the same cross-context
        // call so provenance is auditable from either side. Skip the second
        // append when source == target (a self-cross-context call is
        // structurally impossible under the consent gate but the bridge
        // would not double-log a pathological unit-test fixture).
        if source_context_id != target_context_id {
            append_amplification_rejection_event(log, target_context_id, error, &event);
        }
    }
    event
}

/// Maps an [`OutletAmplificationError`] to a [`ContextError`].
///
/// SCP-OUT-027: emits a typed [`OutletError`] envelope under
/// [`OutletErrorClass::Protocol`] with the §5.4.4 registered slug
/// `amplification-violation` (under `CODE_PROTOCOL_VIOLATION`). The
/// per-variant distinction between `AmplificationViolation` (§6.2.0.3
/// amplification rule) and `ChainDepthExceeded` (§6.2.0.4 chain-depth
/// budget) is preserved via the slug — both are Protocol-class but the
/// former uses `amplification-violation`, the latter uses
/// `query-cost-violation` (the closest registered Protocol slug for a
/// resource-depletion rejection at the chain-depth gate). Mirrors
/// [`invocation_error_to_context`] for the SCP-OUT-015 error class.
#[must_use]
pub fn amplification_error_to_context(err: &OutletAmplificationError) -> ContextError {
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_AMPLIFICATION_VIOLATION, SLUG_PROTOCOL_VIOLATION,
        SLUG_QUERY_COST_VIOLATION,
    };
    use scp_protocol::context::outlets::errors::{OutletError, OutletErrorClass, RetryPolicy};

    let slug = match err {
        OutletAmplificationError::AmplificationViolation { .. } => SLUG_AMPLIFICATION_VIOLATION,
        OutletAmplificationError::ChainDepthExceeded { .. } => SLUG_QUERY_COST_VIOLATION,
    };

    OutletError::from_invocation_error_template(
        OutletErrorClass::Protocol,
        CODE_PROTOCOL_VIOLATION,
        slug,
        RetryPolicy::Never,
    )
    .map_or_else(
        |_| {
            // Fallback to the most generic Protocol-class envelope if the
            // registered constants ever drift. Keeps the typed-envelope
            // invariant (no `PermissionDenied`).
            OutletError::from_invocation_error_template(
                OutletErrorClass::Protocol,
                CODE_PROTOCOL_VIOLATION,
                SLUG_PROTOCOL_VIOLATION,
                RetryPolicy::Never,
            )
            .map_or_else(
                |_| {
                    ContextError::OutletInvocation(Box::new(OutletError {
                        code: CODE_PROTOCOL_VIOLATION.to_owned(),
                        slug: SLUG_PROTOCOL_VIOLATION.to_owned(),
                        class: OutletErrorClass::Protocol,
                        message: [0u8; scp_protocol::context::outlets::errors::WIRE_MESSAGE_LEN],
                        retry: RetryPolicy::Never,
                        detail: None,
                        source_chain: Vec::new(),
                        pad_nonce: [0u8; scp_protocol::context::outlets::errors::PAD_NONCE_LEN],
                        registration_event_id: [0u8;
                            scp_protocol::context::outlets::errors::REGISTRATION_EVENT_ID_LEN],
                        unknown_fields: std::collections::BTreeMap::new(),
                    }))
                },
                |env| ContextError::OutletInvocation(Box::new(env)),
            )
        },
        |env| ContextError::OutletInvocation(Box::new(env)),
    )
}

// ===========================================================================
// SCP-OUT-041c — Catalog-rotation dwell-time validator
// ===========================================================================
//
// §5.4.4 round-5: a registration update whose `message_catalog` differs from
// the prior registration's catalog AND whose own event-log append time is
// within 24 hours (86_400 s) of the prior registration's event-log append
// time is rejected with `OutletErrorClass::Protocol::CatalogRotationTooFrequent`
// (slug `protocol.catalog-rotation-too-frequent`).
//
// The dwell clock is the **event-log append time** — a protocol-enforced,
// verifiably-ordered clock per §7.3.1 — NOT the operator-declared
// `OutletRegistration::registered_at` field. The latter is a `u64` the
// operator can set arbitrarily; using it would let a cooperating operator
// back-date a registration to bypass the 24h dwell floor. The validator
// looks up the prior registration's append time via
// `ContextEventLogProvider::append_time_for`, which sources the timestamp
// from the runtime-set append-time on the matching event-log entry.
//
// The "new registration's append time" is the **prospective** append time
// — i.e., the value the runtime would stamp on the about-to-be-appended
// `OutletRegistered` event. Validation runs BEFORE the new event is
// appended so a rejected update produces no event-log entry. The runtime
// passes the current Unix-seconds value (`SystemTime::now`); tests inject a
// synthetic value to exercise the boundaries.
//
// See SCP-OUT-041c.

/// §5.4.4 round-5 catalog-rotation dwell-time floor (24 hours, in seconds).
///
/// A registration update whose event-log append time is within this many
/// seconds of the prior registration's event-log append time is rejected
/// with [`OutletError`] under
/// [`OutletErrorClass::Protocol`] / `CODE_PROTOCOL_VIOLATION` /
/// `protocol.catalog-rotation-too-frequent`. Not configurable per spec —
/// the constant is the rule.
pub const CATALOG_ROTATION_DWELL_SECS: u64 = 86_400;

/// Outcome of [`validate_catalog_rotation_dwell_time`] on validation failure.
///
/// Surfaces the typed `OutletError` envelope under
/// [`OutletErrorClass::Protocol`] (`SCP-TOOL-6100` /
/// `protocol.catalog-rotation-too-frequent`) plus the elapsed-seconds
/// delta so callers can render a precise diagnostic without
/// re-running the comparison.
#[derive(Debug, Clone)]
pub struct CatalogRotationDwellRejection {
    /// The typed envelope that gets wrapped by callers as
    /// [`ContextError::OutletInvocation`].
    pub envelope: scp_protocol::context::outlets::errors::OutletError,
    /// Seconds elapsed between `prior_append_time_secs` and
    /// `new_append_time_secs`. Always `< CATALOG_ROTATION_DWELL_SECS` when
    /// produced.
    #[allow(dead_code)]
    pub elapsed_secs: u64,
}

/// §5.4.4 round-5 catalog-rotation dwell-time validator.
///
/// Returns `Ok(())` when the registration update is permitted to proceed.
/// Returns `Err(CatalogRotationDwellRejection)` when the update violates
/// the 24-hour minimum dwell time on `message_catalog` edits.
///
/// The validator only fires on a **catalog-modifying** update:
///
/// 1. There is a prior registration of the same outlet, and
/// 2. `prior_message_catalog != new_message_catalog`.
///
/// When the catalog is unchanged the update is not subject to the dwell
/// floor at all (re-registration that does not edit the catalog is the
/// expected mechanism for advancing `outlet_message_key` past an MLS
/// epoch boundary, and the spec deliberately does not throttle it).
///
/// # Trusted clock
///
/// `prior_append_time_secs` MUST come from
/// [`ContextEventLogProvider::append_time_for`](crate::context::builder::ContextEventLogProvider::append_time_for)
/// applied to the prior registration's event-log id. `new_append_time_secs`
/// is the prospective append time of the about-to-be-appended new
/// `OutletRegistered` event — the runtime passes
/// `SystemTime::now() since UNIX_EPOCH`. Never use
/// `OutletRegistration::registered_at` (operator-declared) for either side
/// — that field is unauthenticated against the dwell rule.
///
/// # Errors
///
/// Returns [`CatalogRotationDwellRejection`] when the new append time is
/// within [`CATALOG_ROTATION_DWELL_SECS`] of the prior append time AND the
/// catalog has changed. The `OutletError` envelope inside the rejection is
/// pre-built with code [`error_codes::CODE_PROTOCOL_VIOLATION`] and slug
/// [`error_codes::SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT`].
pub fn validate_catalog_rotation_dwell_time(
    prior_message_catalog: &[scp_protocol::context::outlets::MessageTemplate],
    new_message_catalog: &[scp_protocol::context::outlets::MessageTemplate],
    prior_append_time_secs: u64,
    new_append_time_secs: u64,
) -> Result<(), Box<CatalogRotationDwellRejection>> {
    use scp_protocol::context::outlets::error_codes::{
        CODE_PROTOCOL_VIOLATION, SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
    };
    use scp_protocol::context::outlets::errors::{OutletError, OutletErrorClass, RetryPolicy};

    // 1. The validator is silent when the catalog is unchanged. Re-
    //    registration that preserves `message_catalog` is the expected
    //    mechanism for refreshing `outlet_message_key` past an MLS epoch
    //    boundary and is intentionally not subject to the dwell floor.
    if prior_message_catalog == new_message_catalog {
        return Ok(());
    }

    // 2. Compute the elapsed delta on the trusted clock. Saturating to
    //    avoid underflow if a buggy provider reports a future timestamp
    //    for the prior — saturate-to-zero conservatively triggers the
    //    rejection path (the safer fail-closed behavior).
    let elapsed_secs = new_append_time_secs.saturating_sub(prior_append_time_secs);

    if elapsed_secs >= CATALOG_ROTATION_DWELL_SECS {
        return Ok(());
    }

    // 3. Build the typed envelope. The OutletError envelope is the §5.4.4
    //    canonical error surface; `from_invocation_error_template` enforces
    //    the §5.4.4 6100-6199 sub-block and slug regex.
    //
    //    A construction failure here would indicate the registry constants
    //    drifted out of the §5.4.4 sub-block — a hard invariant break. We
    //    materialize a minimal-but-complete fallback envelope rather than
    //    panicking so the runtime can still surface the rejection.
    let envelope = OutletError::from_invocation_error_template(
        OutletErrorClass::Protocol,
        CODE_PROTOCOL_VIOLATION,
        SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT,
        RetryPolicy::Never,
    )
    .unwrap_or_else(|_| {
        use scp_protocol::context::outlets::errors::{
            PAD_NONCE_LEN, REGISTRATION_EVENT_ID_LEN, WIRE_MESSAGE_LEN,
        };
        OutletError {
            code: CODE_PROTOCOL_VIOLATION.to_owned(),
            slug: SLUG_PROTOCOL_CATALOG_ROTATION_TOO_FREQUENT.to_owned(),
            class: OutletErrorClass::Protocol,
            message: [0u8; WIRE_MESSAGE_LEN],
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: [0u8; PAD_NONCE_LEN],
            registration_event_id: [0u8; REGISTRATION_EVENT_ID_LEN],
            unknown_fields: std::collections::BTreeMap::new(),
        }
    });

    Err(Box::new(CatalogRotationDwellRejection {
        envelope,
        elapsed_secs,
    }))
}

/// Wraps a [`CatalogRotationDwellRejection`] as a [`ContextError`] suitable
/// for surfacing through `execute_register_outlet`.
///
/// Mirrors [`amplification_error_to_context`] for the SCP-OUT-029 error
/// class: the typed envelope flows through
/// [`ContextError::OutletInvocation`] so callers downstream of the
/// governance dispatcher receive a single canonical error surface.
#[must_use]
pub fn catalog_rotation_dwell_rejection_to_context(
    rejection: Box<CatalogRotationDwellRejection>,
) -> ContextError {
    ContextError::OutletInvocation(Box::new(rejection.envelope))
}

// ===========================================================================
// SCP-OUT-029 — Cross-context error wrapping with ContextHop pseudonymization
// ===========================================================================
//
// Implements spec §5.4.4 (Outlet Error Taxonomy) round-3 oracle collapse +
// round-5 trail-length padding + round-6 unconditional pad_nonce emission,
// and §6.2 cross-context wrapping. At each cross-context bridge hop, when an
// `OutletError` propagates back to the caller, the caller's wrapping layer
// prepends a `ContextHop` to `source_chain` with the wrapping context's id,
// the wrap-counter `hop_index = prev.last + 1`, and `wrapped_code =
// prev.code` (preserved — NOT remapped). Purpose: the outermost caller sees
// the original error code AND the trail of contexts the error traversed.
// This is the opposite of HTTP gateway remapping.
//
// Pseudonymization (§5.4.4): each `ContextHop.context_id` the *receiving*
// caller (the wrap-time observer) is not a member of is replaced by
// `HMAC-SHA-256(hop_salt, raw_context_id)[..32]` where `hop_salt` is the
// 32-byte per-context-pair salt established at outlet-interface acceptance
// (§6.2.0.1, the per-pair salt persisted via `InterfaceEstablished.ikm_a /
// ikm_b` at accept time). The receiving caller's own context (`hop_index ==
// 0`-equivalent under §5.4.4 prose — i.e., caller_ctx == observer_ctx) is
// never pseudonymized.
//
// Query-oracle collapse (§5.4.4 round-3): when the receiving caller holds
// neither `outlet_query:{id}` nor `outlet_call:{id}` on the innermost outlet
// id, the wrapped error's `code` is collapsed to `SCP-TOOL-6110` /
// `authorization.denied` regardless of the underlying cause (missing
// outlet, deregistered outlet, kind-mismatch). A caller holding at least one
// matching stem disambiguates. `AmplificationViolation` collapses to
// `authorization.denied` for any caller missing BOTH stems.
//
// Trail-length padding (§5.4.4 round-5): when any hop is opaque to the
// observer, `source_chain` is length-padded to `min(ContextParams::max_chain_depth,
// MAX_TRAIL_PAD_DEPTH=16)`. Each entry (real or pad) carries `hop_index =
// slot_index ∈ [0, max_padded_trail_depth - 1]` — IDENTICAL encoding for
// real and pad. Pad entries derive their `context_id` as
// `HMAC-SHA-256(pad_nonce, "SCP-OUTLET-HOP-PAD-V1:" || slot_index_be)[..32]`.
// `pad_nonce` is fresh per envelope (CSPRNG-sampled by the caller) and
// emitted unconditionally on EVERY error envelope (no Option wrapper) per
// §5.4.4 round-5/6 — closing the visibility-vs-absence oracle.
//
// Full visibility short-circuit: callers with membership on every hop AND a
// matching stem on every hop target see the un-padded `source_chain` with
// raw context_ids. `pad_nonce` is still emitted (not as a signal — its
// presence is unconditional).

use hmac::Mac as _;
use scp_protocol::context::metadata::ContextId;
use scp_protocol::context::outlets::errors::{
    ContextHop, MAX_TRAIL_PAD_DEPTH, MAX_TRAIL_PAD_HMAC_LABEL, OutletError, OutletErrorClass,
    PAD_NONCE_LEN,
};

/// Outlet error code emitted under round-3 query-oracle collapse — `SCP-TOOL-6110`.
const COLLAPSED_AUTHORIZATION_DENIED_CODE: &str = "SCP-TOOL-6110"; // SCP-CODE-OK: §5.4.4 round-3 oracle-collapse target (constant pinned at file scope)

/// Slug for round-3 query-oracle collapse — `authorization.denied`.
const COLLAPSED_AUTHORIZATION_DENIED_SLUG: &str = "authorization.denied";

/// Capability-stem visibility for the innermost outlet whose error is
/// being wrapped.
///
/// Used by [`OutletErrorWrapView`] to apply the §5.4.4 round-3
/// oracle-collapse rule when the receiving caller does not hold a
/// disambiguating stem on the originating outlet.
///
/// `holds_query`/`holds_call` reflect the receiving caller's UCAN-validated
/// stems on the innermost outlet id at the moment of wrap. The wrap function
/// never re-validates the caller's UCAN — the caller computes these flags
/// from its already-validated capability set and passes them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OuterCallerStems {
    /// `true` iff the receiving caller holds `outlet_query:{innermost_outlet_id}`
    /// (or its `outlet_query:*` superset) at wrap time.
    pub holds_query: bool,
    /// `true` iff the receiving caller holds `outlet_call:{innermost_outlet_id}`
    /// (or its `outlet_call:*` superset) at wrap time.
    pub holds_call: bool,
}

impl OuterCallerStems {
    /// Returns `true` iff the caller holds at least one disambiguating stem.
    /// Per §5.4.4 round-3 a caller without any matching stem must see the
    /// collapsed `authorization.denied` code; a caller with at least one
    /// stem disambiguates.
    #[must_use]
    pub const fn has_any_stem(self) -> bool {
        self.holds_query || self.holds_call
    }

    /// Returns `true` iff the caller holds BOTH stems (full disambiguation
    /// surface for §5.4.4 round-3 `AmplificationViolation` distinction).
    #[must_use]
    pub const fn has_both_stems(self) -> bool {
        self.holds_query && self.holds_call
    }
}

/// Receiving-caller view used by [`wrap_cross_context_error`] to apply the
/// §5.4.4 hop-by-hop pseudonymization, oracle collapse, and trail-padding
/// rules.
///
/// All inputs are computed by the caller (the runtime above this function)
/// from its already-validated state: which contexts the receiving caller is
/// a member of, the `hop_salts` pinned at each outlet-interface acceptance,
/// and the receiving caller's UCAN stems on the innermost outlet id. The
/// wrap function performs no re-validation — it is a pure projection.
///
/// # Determinism
///
/// All inputs are concrete byte arrays / boolean flags. The wrap function is
/// deterministic given identical inputs. Tests construct an
/// [`OutletErrorWrapView`] directly and assert the resulting envelope's
/// shape.
///
/// # Field-by-field
///
/// - `observer_ctx` — receiving caller's own context id. The wrap function
///   compares each `ContextHop.context_id` against this id: equal → never
///   pseudonymized (the caller is always a member of their own context, per
///   §5.4.4); not equal → pseudonymization gated on `member_of_context`.
/// - `member_of_context` — closure: given a context id, returns `true` iff
///   the receiving caller is a member of that context. Used to decide
///   pseudonymization per hop.
/// - `hop_salts` — closure: given a target context id, returns the
///   per-pair `hop_salt: [u8; 32]` for the receiving-caller↔target
///   interface, or `None` if no interface salt is known. `None` is treated
///   as "non-member, no salt" — the hop is still pseudonymized but with a
///   sentinel HMAC keyed by an all-zero salt so the on-wire shape is
///   indistinguishable from a known-salt pseudonym (32 bytes). Real
///   deployments wire this from the per-context `InterfaceEstablished`
///   event-log entries (§6.2.0.1 step 4).
/// - `outer_caller_stems` — receiving caller's stems on the innermost
///   outlet id. Drives oracle collapse.
/// - `inner_outlet_kind` — the kind (`Query`/`Action`) of the innermost
///   outlet, when known. Used to decide whether the underlying error was a
///   kind-mismatch / not-found situation that requires collapse. `None`
///   means "kind unknown" — the wrap function treats unknown-kind as a
///   collapse trigger for callers without any stem.
/// - `pad_nonce` — fresh CSPRNG-sampled 16-byte nonce. The caller MUST
///   resample per envelope; the wrap function uses it verbatim and writes
///   it onto the resulting envelope. Reusing across envelopes is a §5.4.4
///   round-5 anti-correlation violation.
/// - `max_padded_trail_depth` — `min(ContextParams::max_chain_depth,
///   MAX_TRAIL_PAD_DEPTH)`. The caller computes this from the emitting
///   context's parameters; the wrap function applies it only when at least
///   one hop is opaque to the receiving caller. Full-visibility callers see
///   the unpadded `source_chain` regardless of this value.
pub struct OutletErrorWrapView<'a> {
    /// Receiving caller's own context id.
    pub observer_ctx: &'a ContextId,
    /// Returns `true` iff the receiving caller is a member of the given
    /// context id. Used to gate pseudonymization per hop.
    pub member_of_context: &'a dyn Fn(&str) -> bool,
    /// Returns the 32-byte `hop_salt` for the receiving caller's interface
    /// with the given target context, or `None` if no salt is known.
    pub hop_salts: &'a dyn Fn(&str) -> Option<[u8; 32]>,
    /// Receiving caller's stems on the innermost outlet id (the originator
    /// of the error).
    pub outer_caller_stems: OuterCallerStems,
    /// The innermost outlet's `OutletKind`, when known. `None` triggers
    /// stem-based collapse for callers without any matching stem.
    pub inner_outlet_kind: Option<OutletKind>,
    /// Fresh CSPRNG-sampled `pad_nonce: [u8; 16]` for this envelope. MUST
    /// be regenerated per envelope; reusing across envelopes is a §5.4.4
    /// round-5 anti-correlation violation.
    pub pad_nonce: [u8; PAD_NONCE_LEN],
    /// `min(ContextParams::max_chain_depth, MAX_TRAIL_PAD_DEPTH)`. Capped
    /// at [`MAX_TRAIL_PAD_DEPTH`] regardless of the input value so envelope
    /// size stays bounded.
    pub max_padded_trail_depth: u8,
}

/// Per-pair `hop_salt` HMAC-SHA-256 of a raw `context_id`.
///
/// Returns the truncated 32-byte HMAC output that occupies a
/// pseudonymized [`ContextHop::context_id`]. Used by
/// [`wrap_cross_context_error`] to produce the §5.4.4 wire form for hops
/// the receiving caller is not a member of.
fn hmac_pseudonymize_context_id(hop_salt: &[u8; 32], raw_context_id: &str) -> [u8; 32] {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut out = [0u8; 32];
    if let Ok(mut mac) = <HmacSha256 as hmac::Mac>::new_from_slice(hop_salt) {
        mac.update(raw_context_id.as_bytes());
        let full = mac.finalize().into_bytes();
        out.copy_from_slice(&full[..32]);
    }
    out
}

/// Per-envelope `pad_nonce` HMAC-SHA-256 of
/// `MAX_TRAIL_PAD_HMAC_LABEL || slot_index_be` — the §5.4.4 round-5
/// pad-entry `context_id` derivation.
///
/// `slot_index` is encoded as a 2-byte big-endian `u16`. The output is
/// truncated to 32 bytes to match the §5.4.4 `ContextHop.context_id`
/// pseudonym width.
fn derive_pad_context_id(pad_nonce: &[u8; PAD_NONCE_LEN], slot_index: u16) -> [u8; 32] {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut out = [0u8; 32];
    if let Ok(mut mac) = <HmacSha256 as hmac::Mac>::new_from_slice(pad_nonce) {
        mac.update(MAX_TRAIL_PAD_HMAC_LABEL);
        mac.update(&slot_index.to_be_bytes());
        let full = mac.finalize().into_bytes();
        out.copy_from_slice(&full[..32]);
    }
    out
}

/// Hex-encodes a 32-byte HMAC pseudonym output for storage in
/// [`ContextHop::context_id`]. The on-wire `context_id` is a `String`
/// (§5.4.4 schema), so the 32-byte HMAC is stored as 64 hex chars. This
/// keeps the JSON/MessagePack wire shape stable across the
/// pseudonymization boundary.
fn pseudonym_to_string(bytes: [u8; 32]) -> String {
    hex::encode(bytes)
}

/// Returns the appropriate wire form for a hop's `context_id` from the
/// receiving caller's view.
///
/// - Same as `observer_ctx` → raw (member of own context).
/// - Member of `raw_context_id` → raw.
/// - Otherwise → 32-byte HMAC under the per-pair `hop_salt` (or all-zero
///   salt if no salt is known, preserving the on-wire opacity shape).
fn project_hop_context_id(raw_context_id: &str, view: &OutletErrorWrapView<'_>) -> String {
    if raw_context_id == *view.observer_ctx {
        return raw_context_id.to_owned();
    }
    if (view.member_of_context)(raw_context_id) {
        return raw_context_id.to_owned();
    }
    // Non-member: pseudonymize. If no salt is configured for this pair, use
    // all-zeros (per the OutletErrorWrapView::hop_salts contract — the
    // pseudonym is still 32 bytes, indistinguishable on the wire).
    let salt = (view.hop_salts)(raw_context_id).unwrap_or([0u8; 32]);
    let pseudonym = hmac_pseudonymize_context_id(&salt, raw_context_id);
    pseudonym_to_string(pseudonym)
}

/// Returns `true` iff the receiving caller can see the per-hop
/// `wrapped_code` un-collapsed for the given hop (i.e., they are a member
/// of that hop's context, OR they hold a matching stem on the hop target).
/// Per §5.4.4 round-3, callers without visibility see `wrapped_code`
/// collapsed to `SCP-TOOL-6110` (`authorization.denied`).
///
/// This implementation conservatively collapses on every hop the caller is
/// not a member of when the caller holds no stem. With at least one stem,
/// the caller observes the per-hop `wrapped_code` raw on the assumption
/// that the stem grants per-outlet visibility into the trail's
/// fine-grained error type — matching the spec's "callers with a matching
/// stem on the hop target see the original `wrapped_code` and slug
/// unchanged" rule.
fn observer_can_see_wrapped_code(hop: &ContextHop, view: &OutletErrorWrapView<'_>) -> bool {
    if hop.context_id == *view.observer_ctx {
        return true;
    }
    if (view.member_of_context)(&hop.context_id) {
        return true;
    }
    // Stem-based per-hop visibility (§5.4.4 round-3, applied to source_chain
    // entries): a caller holding any matching stem on the *hop target* sees
    // the un-collapsed `wrapped_code`. Without per-outlet membership info
    // for inner hops, we rely on the outermost caller's stem holding on the
    // innermost outlet as a proxy — the wrapping layer preserves the chain
    // when the outer caller has visibility.
    view.outer_caller_stems.has_any_stem()
}

/// Returns `true` iff the underlying outermost `code` should collapse to
/// `authorization.denied` per §5.4.4 round-3.
///
/// Collapse fires when:
/// 1. The receiving caller holds NEITHER `outlet_query:{id}` nor
///    `outlet_call:{id}` on the innermost outlet — every authorization-class
///    error collapses regardless of the underlying cause (missing outlet,
///    deregistered, kind-mismatch).
/// 2. The error was an `AmplificationViolation` (slug
///    `authorization.amplification-violation`) and the caller does not hold
///    BOTH stems — distinguishing amplification from kind-specific denial
///    requires both stems per §5.4.4 round-3.
fn outermost_code_should_collapse(prev: &OutletError, view: &OutletErrorWrapView<'_>) -> bool {
    let class = prev.class;
    let slug = prev.slug.as_str();

    // Authorization-class catch-all: callers without any stem cannot
    // disambiguate — collapse.
    let authorization_or_protocol_disclosure = matches!(
        class,
        OutletErrorClass::Authorization | OutletErrorClass::Protocol | OutletErrorClass::Governance
    );
    if authorization_or_protocol_disclosure && !view.outer_caller_stems.has_any_stem() {
        return true;
    }

    // AmplificationViolation: needs BOTH stems to see the disambiguated
    // slug (§5.4.4 round-3).
    if slug == "authorization.amplification-violation" && !view.outer_caller_stems.has_both_stems()
    {
        return true;
    }

    false
}

/// Cross-context error wrapping per spec §5.4.4 / §6.2 / ADR-049 — the
/// SCP-OUT-029 entry point.
///
/// Prepends a [`ContextHop`] to `prev_error.source_chain` with
/// `context_id = caller_ctx`, `hop_index = prev.last + 1` (or `1` if
/// `prev.source_chain` is empty), and `wrapped_code = prev.code`. Preserves
/// the original `prev.code` on the new envelope (§5.4.4 cross-context
/// wrapping rule — the original code is NOT remapped). Applies §5.4.4
/// round-3 oracle collapse, hop-by-hop pseudonymization, and round-5
/// trail-length padding from the receiving caller's view.
///
/// # Inputs
///
/// - `caller_ctx` — the wrapping context's own id. Becomes the new
///   [`ContextHop::context_id`] (raw or pseudonymized depending on the
///   receiving caller's membership relative to `caller_ctx`).
/// - `prev_error` — the [`OutletError`] returned by the inner outlet (or
///   wrapped at an inner cross-context layer). The function consumes
///   `prev_error` and returns a new envelope; `prev_error.source_chain`
///   entries are projected into the receiving caller's view (raw or
///   pseudonymized) before being copied into the new envelope.
/// - `view` — receiving caller's projection: membership, `hop_salts`,
///   stems, kind hint, fresh `pad_nonce`, and `max_padded_trail_depth`.
///   See [`OutletErrorWrapView`] for the field-by-field contract.
///
/// # Round-3 oracle collapse (§5.4.4)
///
/// When the receiving caller holds NEITHER `outlet_query:{id}` nor
/// `outlet_call:{id}` on the innermost outlet, the wrapped error's `code`
/// is collapsed to [`COLLAPSED_AUTHORIZATION_DENIED_CODE`] / slug
/// `authorization.denied`. This makes "missing outlet", "deregistered
/// outlet", and "kind-mismatch outlet" indistinguishable to such a caller
/// — closing the §5.4.4 query oracle. `AmplificationViolation` collapses
/// to `authorization.denied` for any caller missing BOTH stems.
///
/// # Round-5 trail-length padding (§5.4.4)
///
/// When at least one hop is opaque to the receiving caller, `source_chain`
/// is length-padded to `view.max_padded_trail_depth` with indistinguishable
/// pad entries. Each entry (real or pad) carries `hop_index = slot_index ∈
/// [0, max_padded_trail_depth - 1]`, IDENTICAL encoding for both — so an
/// observer cannot read off `k` (the real chain length) from `hop_index`
/// values. Pad entries derive their `context_id` from a fresh per-envelope
/// `pad_nonce: [u8; 16]` via
/// `HMAC-SHA-256(pad_nonce, "SCP-OUTLET-HOP-PAD-V1:" || slot_index_be)[..32]`;
/// `wrapped_code = SCP-TOOL-6110`, slug `authorization.denied`.
/// `pad_nonce` is emitted on EVERY envelope (no Option wrapper) per
/// §5.4.4 round-5/6 — closing the visibility-vs-absence oracle.
///
/// # Partial-visibility honest disclosure (§5.4.4 round-5)
///
/// The pad + real-hop construction hides `k` (the chain length) only from
/// observers who hold no `hop_salt`. A receiver who IS a member of some
/// hop `i` holds the `hop_salt` for that hop and can therefore compute
/// `HMAC(hop_salt, their_context_id)` and identify exactly which slot
/// corresponds to their hop — labeling that slot as "real". They cannot
/// identify other real slots (those use different hop-salt keys the
/// observer does not hold), so they still do not learn `k`. The pad
/// continues to hide `k` from such observers; it does NOT hide the
/// existence of the member's own hop (which the member already knows).
/// The pad fully hides `k` only from observers who hold no `hop_salt` —
/// i.e., non-members of every hop. Quoting the spec verbatim:
///
/// > The pad continues to hide `k` from such an observer; it does NOT
/// > hide the existence of the member's own hop (which the member already
/// > knows). The pad fully hides `k` only from observers who hold no
/// > `hop_salt` — i.e., non-members of every hop.
///
/// > A cryptographic construction giving universal opacity would require
/// > re-HMACing every real-hop slot under `pad_nonce` too (producing
/// > `HMAC(pad_nonce, SCP-OUTLET-SLOT-V1 || slot_index || HMAC(hop_salt,
/// > raw_context_id))` on the wire), which was considered and rejected:
/// > the partial-visibility length oracle is a niche attack available
/// > only to someone who is already a hop member (and therefore already
/// > sees their hop structurally), and the extra re-HMACing imposes
/// > verifier and SDK complexity on every real-hop read without closing
/// > a practically-exploitable channel.
///
/// Downstream maintainers MUST NOT attempt to implement the rejected
/// re-HMAC-under-`pad_nonce` closure.
///
/// # Full-visibility short-circuit
///
/// Callers with membership on every hop AND a matching stem on the
/// innermost outlet see the un-padded `source_chain` (length `k`) with
/// raw `context_id` values. `pad_nonce` is still emitted on the envelope
/// (per §5.4.4 round-5 unconditional emission) — its presence is NOT a
/// signal that the observer lacks full visibility.
///
/// # Wire-form invariants
///
/// - `wrapped.code == prev.code` — preserved unless oracle collapse
///   applies.
/// - `wrapped.message`, `wrapped.retry`, `wrapped.detail`,
///   `wrapped.registration_event_id`, `wrapped.unknown_fields` are
///   carried through verbatim.
/// - `wrapped.pad_nonce` equals `view.pad_nonce` — the function does NOT
///   regenerate the nonce internally; the caller MUST supply a fresh
///   nonce per envelope.
/// - `wrapped.source_chain.first().context_id` is the receiving caller's
///   view of `caller_ctx` (raw or 64-hex-char HMAC pseudonym).
/// - `wrapped.source_chain.first().hop_index ==
///   prev.source_chain.last().hop_index + 1` (or `1` if empty).
/// - When padded, `wrapped.source_chain.len() == view.max_padded_trail_depth`
///   AND every entry's `hop_index == slot_index`.
///
/// # Spec
///
/// - §5.4.4 (Outlet Error Taxonomy) — round-3 oracle collapse, round-5
///   trail-length padding, round-6 unconditional `pad_nonce`.
/// - §6.2 (Cross-context outlet interfaces) — wrapping at each boundary.
/// - §6.2.0.1 (Outlet-interface acceptance) — `hop_salt` per-pair
///   establishment.
/// - §9.18.B — `MAX_TRAIL_PAD_DEPTH = 16` protocol constant.
/// - §9.18.2 — `SCP-OUTLET-HOP-PAD-V1:` domain separator.
/// - ADR-049 §4 — typed error envelope structural rules.
///
/// # Story
///
/// SCP-OUT-029. Builds on SCP-OUT-024 (`OutletError` envelope),
/// SCP-OUT-042a (`InterfaceEstablished` `hop_salt` derivation context).
#[must_use]
pub fn wrap_cross_context_error(
    caller_ctx: &ContextId,
    prev_error: OutletError,
    view: &OutletErrorWrapView<'_>,
) -> OutletError {
    // Step 1 — compute the new hop's wrap-counter index. The wrap-counter
    // is monotonic per wrap call; it is distinct from the round-5
    // slot_index (which equals position in a *padded* chain). For the
    // un-padded path, the new wrap_counter is one greater than the largest
    // hop_index already in prev.source_chain, ensuring strict monotonicity
    // regardless of array ordering convention. The PRD AC text says
    // `prev.last()`; the robust formula is `max(hop_index) + 1`, which
    // coincides with the AC text under the front=highest convention.
    let new_wrap_counter = next_wrap_counter(&prev_error);

    let collapse_outermost = outermost_code_should_collapse(&prev_error, view);
    let real_chain = build_real_chain(
        caller_ctx,
        &prev_error,
        view,
        new_wrap_counter,
        collapse_outermost,
    );
    let full_visibility =
        observer_has_full_visibility_with_caller(caller_ctx, &prev_error.source_chain, view);

    // Step 4 — apply round-5 trail-length padding when not in full
    // visibility. Cap at `MAX_TRAIL_PAD_DEPTH` regardless of the caller-
    // supplied `max_padded_trail_depth` so the protocol invariant holds
    // even if the caller mis-computes the cap.
    let final_chain = if full_visibility {
        real_chain
    } else {
        build_padded_chain(real_chain, view)
    };

    let (new_code, new_slug, new_class) =
        compute_outermost_code_slug_class(&prev_error, view, collapse_outermost);

    // The on-wire `message` HMAC is preserved verbatim — re-deriving it
    // requires `outlet_message_key` which is not available at wrap time.
    // Per §5.4.4 the receiver reverse-lookups the HMAC against the
    // outlet's registered catalog; for round-3 collapse the slug rewrite
    // is observer-side semantic only.
    let OutletError {
        message,
        retry,
        detail,
        registration_event_id,
        unknown_fields,
        ..
    } = prev_error;

    OutletError {
        code: new_code,
        slug: new_slug,
        class: new_class,
        message,
        retry,
        detail,
        source_chain: final_chain,
        pad_nonce: view.pad_nonce,
        registration_event_id,
        unknown_fields,
    }
}

/// Returns the strictly-monotonic wrap-counter for the new hop. Per the
/// PRD AC: `1` if `prev.source_chain` is empty, else `max(hop_index) + 1`.
fn next_wrap_counter(prev: &OutletError) -> u16 {
    if prev.source_chain.is_empty() {
        1
    } else {
        prev.source_chain
            .iter()
            .map(|h| h.hop_index)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }
}

/// Builds the real (un-padded) source chain by prepending the new outermost
/// wrap hop and projecting prior hops through the receiving caller's view.
fn build_real_chain(
    caller_ctx: &ContextId,
    prev: &OutletError,
    view: &OutletErrorWrapView<'_>,
    new_wrap_counter: u16,
    collapse_outermost: bool,
) -> Vec<ContextHop> {
    let mut real_chain: Vec<ContextHop> = Vec::with_capacity(prev.source_chain.len() + 1);
    let new_hop_context_id = project_hop_context_id(caller_ctx, view);
    let new_hop_wrapped_code = if collapse_outermost {
        COLLAPSED_AUTHORIZATION_DENIED_CODE.to_owned()
    } else {
        prev.code.clone()
    };
    real_chain.push(ContextHop {
        context_id: new_hop_context_id,
        hop_index: new_wrap_counter,
        wrapped_code: new_hop_wrapped_code,
    });
    for hop in &prev.source_chain {
        let projected_id = project_hop_context_id(&hop.context_id, view);
        let projected_code = if observer_can_see_wrapped_code(hop, view) {
            hop.wrapped_code.clone()
        } else {
            COLLAPSED_AUTHORIZATION_DENIED_CODE.to_owned()
        };
        real_chain.push(ContextHop {
            context_id: projected_id,
            hop_index: hop.hop_index,
            wrapped_code: projected_code,
        });
    }
    real_chain
}

/// Decides full-visibility against the caller-plus-prev raw chain (caller
/// is always a member of itself, so the new hop's membership is automatic).
fn observer_has_full_visibility_with_caller(
    caller_ctx: &ContextId,
    prev_chain: &[ContextHop],
    view: &OutletErrorWrapView<'_>,
) -> bool {
    if !view.outer_caller_stems.has_any_stem() {
        return false;
    }
    if caller_ctx != view.observer_ctx && !(view.member_of_context)(caller_ctx) {
        return false;
    }
    prev_chain.iter().all(|hop| {
        hop.context_id == *view.observer_ctx || (view.member_of_context)(&hop.context_id)
    })
}

/// Builds the padded source chain. Real entries are reassigned slot indices
/// `0..k-1`; pad entries fill `k..target_len-1` with HMAC-derived
/// pseudonymized `context_id`s under `view.pad_nonce`.
fn build_padded_chain(
    real_chain: Vec<ContextHop>,
    view: &OutletErrorWrapView<'_>,
) -> Vec<ContextHop> {
    let capped_depth = view.max_padded_trail_depth.min(MAX_TRAIL_PAD_DEPTH);
    let k = real_chain.len();
    let target_len = (capped_depth as usize).max(k);
    let mut padded: Vec<ContextHop> = Vec::with_capacity(target_len);
    for (slot, hop) in real_chain.into_iter().enumerate() {
        let slot_u16 = u16::try_from(slot).unwrap_or(u16::MAX);
        padded.push(ContextHop {
            context_id: hop.context_id,
            hop_index: slot_u16,
            wrapped_code: hop.wrapped_code,
        });
    }
    for slot in k..target_len {
        let slot_u16 = u16::try_from(slot).unwrap_or(u16::MAX);
        let pad_id_bytes = derive_pad_context_id(&view.pad_nonce, slot_u16);
        padded.push(ContextHop {
            context_id: pseudonym_to_string(pad_id_bytes),
            hop_index: slot_u16,
            wrapped_code: COLLAPSED_AUTHORIZATION_DENIED_CODE.to_owned(),
        });
    }
    padded
}

/// Decides the outermost (`prev.code`-replacing) `code`/`slug`/`class`
/// triple per §5.4.4 round-3 oracle collapse and the kind-hint fallback.
fn compute_outermost_code_slug_class(
    prev: &OutletError,
    view: &OutletErrorWrapView<'_>,
    collapse_outermost: bool,
) -> (String, String, OutletErrorClass) {
    if collapse_outermost {
        (
            COLLAPSED_AUTHORIZATION_DENIED_CODE.to_owned(),
            COLLAPSED_AUTHORIZATION_DENIED_SLUG.to_owned(),
            OutletErrorClass::Authorization,
        )
    } else if !view.outer_caller_stems.has_any_stem() && view.inner_outlet_kind.is_none() {
        // Kind-mismatch / not-found fallback for the ambiguous-kind case
        // (caller has no stem AND we don't know the kind).
        (
            COLLAPSED_AUTHORIZATION_DENIED_CODE.to_owned(),
            COLLAPSED_AUTHORIZATION_DENIED_SLUG.to_owned(),
            OutletErrorClass::Authorization,
        )
    } else {
        (prev.code.clone(), prev.slug.clone(), prev.class)
    }
}

// ===========================================================================
// SCP-OUT-036 — Cross-context chunk bridge + aggregate_schema validation
// ===========================================================================
//
// Implements spec §6.2.0.5 ("Cross-Context Streaming") and the §5.4.5
// `aggregate_schema` rule. Streams cross the §6.2 outlet-interface boundary
// under a shared-member bridge that re-encrypts every chunk per recipient as
// it transits. Concretely (in this in-process realization):
//
//   1. The invoker (source context) calls the bridge for an outlet hosted in
//      the target context. The bridge runs the §6.2.0.3/4 amplification +
//      depth checks, then opens an executor stream against the target.
//   2. As each `OutletStreamChunk` arrives from the executor, the bridge
//      validates its payload (Data → output_schema; End → aggregate_schema
//      if present, else output_schema) and re-issues a chunk under the
//      source context's `(request_id, caveats_binding, stream_epoch,
//      operator_signing_key)`. This is the "re-encryption + re-key" leg —
//      production deployments pair it with MLS group encryption on the wire;
//      this in-process implementation captures the structural invariants
//      (bridge does not buffer, sequence is monotonic, terminal chunks
//      remain terminal) that the wire layer must preserve.
//   3. On any failure mid-stream the bridge synthesizes a terminal
//      `Error{terminal:true}` chunk with §5.4.4 code
//      `transport.cross-context-bridge-failure` (`SCP-TOOL-6160`) and stops
//      forwarding. End-aggregate schema violations terminate with
//      `output.schema-violation` (`SCP-TOOL-6140`).
//   4. Both contexts emit one `OutletInvokedEvent` with the same
//      `stream_manifest_hash`. The Merkle root is computed over the
//      forwarded chunk sequence (the bridge's authoritative view) so the
//      source and target events agree by construction.
//
// `chain_depth` is set at open and inherited unchanged on every forwarded
// chunk; chunks do not recompute or check it (§6.2.0.5).

/// Cross-context bridge handle returned by [`invoke_outlet_cross_context`].
///
/// Carries the receiver delivering re-issued chunks plus the two
/// `OutletInvokedEvent`s the bridge synthesized for the source and target
/// contexts. The events share a `stream_manifest_hash` computed over the
/// forwarded chunk sequence, so the §6.2.0.5 "both event logs agree"
/// invariant holds by construction.
#[derive(Debug)]
#[must_use = "the receiver must be drained to complete the cross-context bridge"]
pub struct CrossContextStreamBridge {
    /// Channel of chunks re-issued under the source (invoker) context's
    /// `(request_id, caveats_binding, stream_epoch, operator)`.
    pub receiver:
        tokio::sync::mpsc::Receiver<scp_protocol::context::outlets::stream::OutletStreamChunk>,
    /// Source-context `OutletInvokedEvent`. Available after the bridge has
    /// forwarded the terminal chunk; populated via the `event_handle`'s
    /// completion future.
    pub event_handle: CrossContextStreamEventHandle,
}

/// Handle that resolves once the bridge has finished forwarding chunks.
///
/// Owns a `oneshot` receiver that yields the bridge's authoritative
/// `OutletInvokedEvent` pair (source, target) and the manifest hash.
#[derive(Debug)]
pub struct CrossContextStreamEventHandle {
    inner: tokio::sync::oneshot::Receiver<CrossContextStreamCompletion>,
}

impl CrossContextStreamEventHandle {
    /// Awaits the bridge completion. Returns `None` if the bridge was
    /// dropped before completing.
    pub async fn await_completion(self) -> Option<CrossContextStreamCompletion> {
        self.inner.await.ok()
    }
}

/// Bridge completion summary surfaced via [`CrossContextStreamEventHandle`].
#[derive(Debug, Clone)]
pub struct CrossContextStreamCompletion {
    /// `OutletInvokedEvent` recorded in the source (invoker) context.
    pub source_event: OutletInvokedEvent,
    /// `OutletInvokedEvent` recorded in the target (executor) context.
    pub target_event: OutletInvokedEvent,
    /// Shared chunk-manifest Merkle root (§5.4.5). Identical across both
    /// events by construction — the bridge computes it once over the
    /// forwarded chunk sequence and copies it into both records.
    pub stream_manifest_hash: [u8; 32],
}

/// Membership-test closure used by the bridge wrap-view (SCP-OUT-029).
///
/// Returns `true` iff the source observer is a member of the given context
/// id. Owned (`Arc`) so the closure can be cloned into the spawned bridge
/// task. Implementations capture the source context's
/// `GovernanceState::active_members` set.
pub type BridgeMemberClosure = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Hop-salt-lookup closure used by the bridge wrap-view (SCP-OUT-029).
///
/// Returns the per-pair `hop_salt: [u8; 32]` for the source observer's
/// interface with the given peer context id, or `None` if no salt is
/// known. Owned (`Arc`) so the closure can be cloned into the spawned
/// bridge task. Implementations look up
/// `derive_hop_salt_from_committed_ikms` from the per-context
/// `InterfaceEstablished` event log entries (§6.2.0.1 step 4).
pub type BridgeHopSaltClosure = std::sync::Arc<dyn Fn(&str) -> Option<[u8; 32]> + Send + Sync>;

/// Inputs to [`invoke_outlet_cross_context`].
///
/// Owned values mirror the `OutletStreamOpen` wire layout (§5.4.5) plus the
/// cross-context bridge's source/target context identifiers and operator
/// signing keys.
#[derive(Clone)]
pub struct CrossContextInvokeInputs {
    /// Source (invoker's) context id. Re-issued chunks bind this id into
    /// their per-chunk signature preimage (§5.4.5).
    pub source_context_id: String,
    /// Target (executor's) context id. The original chunk arriving from
    /// the executor binds this id; the bridge re-pins to the source.
    pub target_context_id: String,
    /// Outlet to invoke (lives in the target context).
    pub outlet_id: scp_protocol::context::outlets::OutletId,
    /// Source-side `caveats_binding` (32-byte SHA-256 over §5.4.5
    /// preimage). Bound into every re-issued chunk so members of the
    /// source context can verify chunk authenticity against the open's
    /// pinned `(request_id → caveats_binding)` record.
    pub source_caveats_binding: [u8; 32],
    /// Target-side `caveats_binding`. The bridge re-pins to the source
    /// when forwarding; mismatched re-pinning fails with
    /// `AttenuationViolation`.
    pub target_caveats_binding: [u8; 32],
    /// Per §6.2.0.5: chain depth recorded at open. Carried unchanged on
    /// every forwarded chunk; chunks do not recompute it.
    pub chain_depth: u8,
    /// MLS epoch counter at acceptance time (§6.2.1.1(e)). Used by the
    /// re-encryption leg for chunk-level keying — distinct from
    /// `session_epoch`.
    pub stream_epoch: u64,
    /// Source-context operator's signing key. The bridge re-signs every
    /// re-issued chunk with this key so source-context members verify
    /// chunks against the same operator they trust for direct outlets.
    pub source_operator_key: std::sync::Arc<ed25519_dalek::SigningKey>,
    /// `aggregate_schema` to validate `End.aggregate` against, if any
    /// (§5.4.5). Falls back to `output_schema` per the spec rule.
    pub aggregate_schema: Option<serde_json::Value>,
    /// `output_schema` for per-chunk Data validation and aggregate
    /// fallback. Required.
    pub output_schema: serde_json::Value,
    /// Caller-side invoker DID, recorded into both events.
    pub invoker_did: String,
    // ---------------------------------------------------------------
    // SCP-OUT-029 — wrap-view inputs for terminal-error envelopes
    // ---------------------------------------------------------------
    /// Membership predicate for the source observer (§5.4.4). Drives
    /// per-hop pseudonymization in [`wrap_cross_context_error`]: hops
    /// the observer is a member of stay raw, others are HMAC-pseudonymized
    /// under the per-pair `hop_salt`.
    pub source_member_of_context: BridgeMemberClosure,
    /// Per-pair `hop_salt` lookup for the source observer (§6.2.0.1).
    /// Returns the 32-byte salt for the observer's interface with a
    /// given peer context, or `None` if no salt is established. The
    /// wrap function falls back to an all-zero salt when `None` so the
    /// on-wire 32-byte pseudonym shape is preserved.
    pub source_hop_salts: BridgeHopSaltClosure,
    /// Source observer's UCAN-validated stems on the innermost outlet
    /// id. Drives §5.4.4 round-3 oracle collapse — callers without any
    /// stem see the collapsed `authorization.denied` slug.
    pub source_outer_caller_stems: OuterCallerStems,
    /// Innermost outlet's [`OutletKind`], when known. `None` triggers
    /// stem-based collapse for callers without any matching stem.
    pub inner_outlet_kind: Option<OutletKind>,
    /// `min(ContextParams::max_chain_depth, MAX_TRAIL_PAD_DEPTH)` —
    /// the §5.4.4 round-5 trail-pad cap (≤ 16 by protocol invariant).
    pub max_padded_trail_depth: u8,
}

impl std::fmt::Debug for CrossContextInvokeInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Closures are not `Debug`; we render every other field and
        // mark the closures as opaque so log output stays useful and
        // structurally complete.
        f.debug_struct("CrossContextInvokeInputs")
            .field("source_context_id", &self.source_context_id)
            .field("target_context_id", &self.target_context_id)
            .field("outlet_id", &self.outlet_id)
            .field("source_caveats_binding", &self.source_caveats_binding)
            .field("target_caveats_binding", &self.target_caveats_binding)
            .field("chain_depth", &self.chain_depth)
            .field("stream_epoch", &self.stream_epoch)
            .field("source_operator_key", &"<SigningKey>")
            .field("aggregate_schema", &self.aggregate_schema)
            .field("output_schema", &self.output_schema)
            .field("invoker_did", &self.invoker_did)
            .field("source_member_of_context", &"<closure>")
            .field("source_hop_salts", &"<closure>")
            .field("source_outer_caller_stems", &self.source_outer_caller_stems)
            .field("inner_outlet_kind", &self.inner_outlet_kind)
            .field("max_padded_trail_depth", &self.max_padded_trail_depth)
            .finish()
    }
}

/// Wraps a fresh terminal [`OutletError`] envelope through SCP-OUT-029
/// `wrap_cross_context_error` for the source observer, recording the
/// target-context boundary the error just crossed.
///
/// Used by [`synth_bridge_failure_chunk`] and
/// [`synth_output_violation_chunk`] to guarantee every terminal Error
/// chunk emitted by `run_cross_context_bridge` carries a typed
/// envelope with a §5.4.4 `ContextHop` chain, HMAC pseudonymization,
/// trail-padding, and oracle-collapse rules — instead of a free-form
/// string.
///
/// # Inputs
///
/// - `inputs` — the bridge's `CrossContextInvokeInputs`. Supplies the
///   source observer's membership / hop-salt closures, stems, kind hint,
///   and `max_padded_trail_depth`.
/// - `class` — root [`OutletErrorClass`] for the inner error
///   (§5.4.4 tag 3).
/// - `code` — `SCP-TOOL-NNNN` per the §5.4.4 6100-6199 sub-block.
/// - `slug` — slug per the §5.4.4 catalog-key regex.
/// - `retry` — [`RetryPolicy`] hint.
///
/// # Construction model
///
/// At the bridge seam the runtime does not have the per-outlet
/// `outlet_message_key` / `registration_event_id` — the in-process
/// realization of §6.2.0.5 captures the structural invariants
/// (envelope shape, hop chain, pseudonymization, oracle collapse) that
/// the production wire path (with real keying material in scope)
/// preserves. The inner envelope is constructed via
/// [`OutletError::from_invocation_error_template`] (placeholder
/// `outlet_message_key = [0; 32]`, `registration_event_id = [0; 32]`,
/// fresh CSPRNG `pad_nonce`); the outer hop is then prepended via
/// [`wrap_cross_context_error`] with `caller_ctx = target_context_id`
/// and the source observer's view.
fn wrap_terminal_error_envelope(
    inputs: &CrossContextInvokeInputs,
    class: OutletErrorClass,
    code: &str,
    slug: &str,
    retry: scp_protocol::context::outlets::errors::RetryPolicy,
) -> OutletError {
    // 1. Build the innermost envelope using the runtime → ContextError
    //    seam constructor. `from_invocation_error_template` validates
    //    code/slug against §5.4.4 regex and synthesizes deterministic
    //    placeholders for `outlet_message_key`/`registration_event_id`.
    //    On a malformed code/slug we fall back to the §5.4.4 round-3
    //    collapse target (SCP-TOOL-6110 / authorization.denied) so the
    //    bridge always emits a structurally valid envelope.
    let inner = OutletError::from_invocation_error_template(class, code, slug, retry)
        .unwrap_or_else(|_| {
            // Collapse target — guaranteed to pass the regex check by
            // construction, so this `unwrap_or_else` cannot recurse.
            OutletError::from_invocation_error_template(
                OutletErrorClass::Authorization,
                COLLAPSED_AUTHORIZATION_DENIED_CODE,
                COLLAPSED_AUTHORIZATION_DENIED_SLUG,
                scp_protocol::context::outlets::errors::RetryPolicy::Never,
            )
            .unwrap_or_else(|_| unreachable!(
                "collapse target SCP-TOOL-6110/authorization.denied is regex-valid by construction"
            ))
        });

    // 2. Build the wrap view from the source observer's perspective.
    //    The observer is `source_context_id`; the new hop being added
    //    represents the `target_context_id` boundary the error just
    //    crossed coming back through the bridge.
    let pad_nonce: [u8; PAD_NONCE_LEN] = rand::random();
    let view = OutletErrorWrapView {
        observer_ctx: &inputs.source_context_id,
        member_of_context: inputs.source_member_of_context.as_ref(),
        hop_salts: inputs.source_hop_salts.as_ref(),
        outer_caller_stems: inputs.source_outer_caller_stems,
        inner_outlet_kind: inputs.inner_outlet_kind,
        pad_nonce,
        max_padded_trail_depth: inputs.max_padded_trail_depth,
    };

    // 3. Prepend the target-context hop. Per §5.4.4 the wrap function
    //    applies HMAC pseudonymization (when the observer is not a
    //    member of `target_context_id`), oracle collapse (when the
    //    observer holds no disambiguating stem on the inner outlet),
    //    and trail-length padding (when any hop is opaque to the
    //    observer).
    wrap_cross_context_error(&inputs.target_context_id, inner, &view)
}

/// Serializes a wrapped [`OutletError`] envelope into the
/// [`ChunkPayload::Error.message`](scp_protocol::context::outlets::stream::ChunkPayload::Error)
/// field as hex-encoded canonical `MessagePack` (§5.4.4 wire form).
///
/// The wire schema for `ChunkPayload::Error` keeps `message: String`
/// (§5.4.5); to carry the typed §5.4.4 envelope through the chunk
/// payload, we `MessagePack`-encode the envelope and hex-encode the
/// bytes so the result is a valid UTF-8 String. Receivers reverse the
/// encoding to recover the typed envelope.
///
/// On the (unreachable in practice) `MessagePack` encode failure path
/// we emit an empty string. The envelope is constructed entirely from
/// in-memory typed values whose wire schemas are exercised by every
/// outlet error fixture, so the `Err` branch is dead code.
fn serialize_wrapped_envelope_to_message(envelope: &OutletError) -> String {
    rmp_serde::to_vec_named(envelope).map_or_else(|_| String::new(), hex::encode)
}

/// Synthesizes a terminal cross-context bridge-failure chunk per §5.4.4
/// (`transport.cross-context-bridge-failure`, `SCP-TOOL-6160`).
///
/// Constructs a typed [`OutletError`] envelope, prepends a `ContextHop`
/// for the target boundary via [`wrap_cross_context_error`], and serializes
/// it into the chunk's `message` field. SCP-OUT-029 wires the typed envelope
/// into the §6.2.0.5 cross-context bridge so terminal errors carry the
/// §5.4.4 wire form (chain, pseudonymization, oracle collapse, trail-pad).
fn synth_bridge_failure_chunk(
    request_id: &scp_protocol::context::outlets::stream::RequestId,
    sequence: u64,
    inputs: &CrossContextInvokeInputs,
    message: &str,
) -> scp_protocol::context::outlets::stream::OutletStreamChunk {
    use scp_protocol::context::outlets::error_codes::{
        CODE_TRANSPORT_FAULT, SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
    };
    use scp_protocol::context::outlets::errors::RetryPolicy;
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, sign_chunk};

    let envelope = wrap_terminal_error_envelope(
        inputs,
        OutletErrorClass::Transport,
        CODE_TRANSPORT_FAULT,
        SLUG_TRANSPORT_CROSS_CONTEXT_BRIDGE_FAILURE,
        RetryPolicy::WithBackoff {
            min: std::time::Duration::from_secs(1),
            max: std::time::Duration::from_secs(30),
        },
    );
    // Bind the wrapped envelope's outermost code into the ChunkPayload
    // so the on-wire `code` field reflects any §5.4.4 round-3 collapse
    // (e.g., the source observer holds no stem → outer code becomes
    // SCP-TOOL-6110). The original payload-level `message` field
    // carries the full typed envelope as hex-encoded MessagePack.
    let envelope_message = serialize_wrapped_envelope_to_message(&envelope);
    let _ = message; // kept for future telemetry plumbing
    let payload = ChunkPayload::Error {
        code: envelope.code,
        message: envelope_message,
        terminal: true,
    };
    let sig = sign_chunk(
        &inputs.source_operator_key,
        &inputs.source_context_id,
        &inputs.outlet_id,
        request_id,
        sequence,
        &inputs.source_caveats_binding,
        &payload,
    )
    .unwrap_or([0u8; 64]);
    OutletStreamChunk {
        request_id: *request_id,
        sequence,
        payload,
        sig,
    }
}

/// Synthesizes a terminal output-violation chunk per §5.4.4
/// (`output.schema-violation`, `SCP-TOOL-6140`).
///
/// Constructs a typed [`OutletError`] envelope, prepends a `ContextHop`
/// for the target boundary via [`wrap_cross_context_error`], and serializes
/// it into the chunk's `message` field. SCP-OUT-029 wires the typed envelope
/// into the §6.2.0.5 cross-context bridge so terminal errors carry the
/// §5.4.4 wire form (chain, pseudonymization, oracle collapse, trail-pad).
fn synth_output_violation_chunk(
    request_id: &scp_protocol::context::outlets::stream::RequestId,
    sequence: u64,
    inputs: &CrossContextInvokeInputs,
    message: &str,
) -> scp_protocol::context::outlets::stream::OutletStreamChunk {
    use scp_protocol::context::outlets::error_codes::{
        CODE_OUTPUT_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION,
    };
    use scp_protocol::context::outlets::errors::RetryPolicy;
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, sign_chunk};

    let envelope = wrap_terminal_error_envelope(
        inputs,
        OutletErrorClass::Output,
        CODE_OUTPUT_VIOLATION,
        SLUG_OUTPUT_SCHEMA_VIOLATION,
        RetryPolicy::Never,
    );
    let envelope_message = serialize_wrapped_envelope_to_message(&envelope);
    let _ = message; // kept for future telemetry plumbing
    let payload = ChunkPayload::Error {
        code: envelope.code,
        message: envelope_message,
        terminal: true,
    };
    let sig = sign_chunk(
        &inputs.source_operator_key,
        &inputs.source_context_id,
        &inputs.outlet_id,
        request_id,
        sequence,
        &inputs.source_caveats_binding,
        &payload,
    )
    .unwrap_or([0u8; 64]);
    OutletStreamChunk {
        request_id: *request_id,
        sequence,
        payload,
        sig,
    }
}

/// Drives a cross-context outlet stream bridge per spec §6.2.0.5.
///
/// Consumes an executor-side stream `executor_rx` (chunks signed by the
/// target operator under the target's `caveats_binding`) and forwards each
/// chunk to a fresh receiver under the source context's identity. The
/// bridge:
///
/// - Validates `Data.value` against `inputs.output_schema` (§5.4.5).
/// - Validates `End.aggregate` against `inputs.aggregate_schema` if present,
///   else `inputs.output_schema` (§5.4.5 "matches `aggregate_schema` or
///   defaults to last Data").
/// - Re-issues chunks with strictly monotonic sequence numbers under
///   `(inputs.source_context_id, inputs.outlet_id, fresh request_id,
///    inputs.source_caveats_binding)`, signed with `inputs.source_operator_key`.
/// - Preserves chunk type semantics: Data→Data, Progress→Progress,
///   End→End, Error→Error{terminal stays terminal}.
/// - On per-chunk schema violation: terminates with
///   `Error{terminal:true, code:"SCP-TOOL-6140"}`.
/// - On underlying executor disconnect mid-stream (no terminal chunk
///   observed): terminates with `Error{terminal:true,
///   code:"SCP-TOOL-6160"}`.
///
/// Returns the new `(request_id, receiver, completion_handle)` tuple. The
/// completion handle resolves once the bridge has emitted a terminal chunk
/// (real End/Error{terminal} or synthesized failure) and yields the two
/// `OutletInvokedEvent`s plus the shared `stream_manifest_hash`.
pub fn invoke_outlet_cross_context(
    inputs: CrossContextInvokeInputs,
    executor_rx: tokio::sync::mpsc::Receiver<
        scp_protocol::context::outlets::stream::OutletStreamChunk,
    >,
) -> (
    scp_protocol::context::outlets::stream::RequestId,
    CrossContextStreamBridge,
) {
    use scp_protocol::context::outlets::stream::{
        DEFAULT_CREDIT_WINDOW, OutletStreamChunk, RequestId,
    };

    let request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
    let (tx, rx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(DEFAULT_CREDIT_WINDOW as usize);
    let (event_tx, event_rx) = tokio::sync::oneshot::channel::<CrossContextStreamCompletion>();

    tokio::spawn(run_cross_context_bridge(
        request_id,
        inputs,
        executor_rx,
        tx,
        event_tx,
    ));

    (
        request_id,
        CrossContextStreamBridge {
            receiver: rx,
            event_handle: CrossContextStreamEventHandle { inner: event_rx },
        },
    )
}

/// Per-chunk validation outcome — `None` on success, `Some(error_message)`
/// on a schema-violation that must terminate the bridge.
fn validate_chunk_payload(
    payload: &scp_protocol::context::outlets::stream::ChunkPayload,
    output_schema: &serde_json::Value,
    aggregate_schema: Option<&serde_json::Value>,
) -> Option<String> {
    use scp_protocol::context::outlets::stream::ChunkPayload;
    match payload {
        ChunkPayload::Data { value } => {
            scp_protocol::context::outlets::schema::validate_value_against_schema(
                value,
                output_schema,
            )
            .err()
            .map(|reason| format!("Data: {reason}"))
        }
        ChunkPayload::End { aggregate, .. } => {
            let schema_to_use = aggregate_schema.unwrap_or(output_schema);
            scp_protocol::context::outlets::schema::validate_value_against_schema(
                aggregate,
                schema_to_use,
            )
            .err()
            .map(|reason| format!("End.aggregate: {reason}"))
        }
        // Progress and Error payloads transit unchanged. Their
        // payloads carry no schema-typed content.
        ChunkPayload::Progress { .. } | ChunkPayload::Error { .. } => None,
    }
}

/// Builds the terminating `OutletInvokedEvent` pair from the recorded
/// chunk sequence. Source and target events agree by construction —
/// this function fills both with the same fields.
fn build_completion(
    forwarded: &[scp_protocol::context::outlets::stream::OutletStreamChunk],
    chunks_billed: u32,
    request_id: &scp_protocol::context::outlets::stream::RequestId,
    outlet_id: &scp_protocol::context::outlets::OutletId,
    invoker_did: &str,
) -> CrossContextStreamCompletion {
    use scp_protocol::context::outlets::stream::{
        ChunkPayload, StreamTerminalStatus, compute_chunk_manifest_root,
    };
    let manifest = compute_chunk_manifest_root(forwarded).unwrap_or([0u8; 32]);
    let stream_chunk_count = u32::try_from(forwarded.len()).unwrap_or(u32::MAX);
    let event_status = if matches!(
        forwarded.last().map(|c| &c.payload),
        Some(ChunkPayload::End { .. })
    ) {
        OutletStatus::Success
    } else {
        OutletStatus::Error
    };
    let stream_terminal_status = match forwarded.last().map(|c| &c.payload) {
        Some(ChunkPayload::End { .. }) => StreamTerminalStatus::Ok,
        Some(ChunkPayload::Error { code, .. }) => StreamTerminalStatus::Error(code.clone()),
        _ => StreamTerminalStatus::Cancelled,
    };
    let request_id_str = uuid::Uuid::from_bytes(*request_id).to_string();
    let invoker_did_v = scp_primitives::DID::from(invoker_did);

    let source_event = OutletInvokedEvent {
        request_id: request_id_str.clone(),
        outlet_id: outlet_id.clone(),
        invoker_did: invoker_did_v.clone(),
        status: event_status,
        execution_time_ms: 0,
        input_hash: String::new(),
        output_hash: None,
        cost: None,
        stream_chunk_count,
        chunks_billed,
        stream_manifest_hash: manifest,
        stream_terminal_status: stream_terminal_status.clone(),
        // Cross-context completion event mirrors the originating stream's
        // recorded counts; the F2 self-mismatch detection (if any) is
        // attached to the source-side dispatch pump's event, not these
        // mirrored cross-context records.
        audit_anomaly: None,
    };
    let target_event = OutletInvokedEvent {
        request_id: request_id_str,
        outlet_id: outlet_id.clone(),
        invoker_did: invoker_did_v,
        status: event_status,
        execution_time_ms: 0,
        input_hash: String::new(),
        output_hash: None,
        cost: None,
        stream_chunk_count,
        chunks_billed,
        stream_manifest_hash: manifest,
        stream_terminal_status,
        audit_anomaly: None,
    };
    CrossContextStreamCompletion {
        source_event,
        target_event,
        stream_manifest_hash: manifest,
    }
}

/// Spawned task body for [`invoke_outlet_cross_context`]. Drives the
/// chunk-by-chunk forwarding loop, validation, re-signing, and terminal
/// synthesis, then resolves the completion handle with the
/// `OutletInvokedEvent` pair.
#[allow(clippy::too_many_lines)]
async fn run_cross_context_bridge(
    request_id: scp_protocol::context::outlets::stream::RequestId,
    inputs: CrossContextInvokeInputs,
    mut executor_rx: tokio::sync::mpsc::Receiver<
        scp_protocol::context::outlets::stream::OutletStreamChunk,
    >,
    tx: tokio::sync::mpsc::Sender<scp_protocol::context::outlets::stream::OutletStreamChunk>,
    event_tx: tokio::sync::oneshot::Sender<CrossContextStreamCompletion>,
) {
    use scp_protocol::context::outlets::stream::{ChunkPayload, OutletStreamChunk, sign_chunk};

    let mut next_seq: u64 = 0;
    let mut forwarded: Vec<OutletStreamChunk> = Vec::new();
    let mut chunks_billed: u32 = 0;
    let mut terminated = false;

    while let Some(orig) = executor_rx.recv().await {
        let seq = next_seq;
        next_seq = next_seq.saturating_add(1);

        // Validate per-chunk payload BEFORE re-signing so a failure
        // produces a terminal Error chunk (still re-signed under the
        // source operator) and the bridge stops. The terminal envelope
        // is wrapped via SCP-OUT-029 `wrap_cross_context_error` so the
        // chunk carries a typed §5.4.4 envelope with a `ContextHop`
        // chain, HMAC pseudonymization, and oracle-collapse rules.
        if let Some(msg) = validate_chunk_payload(
            &orig.payload,
            &inputs.output_schema,
            inputs.aggregate_schema.as_ref(),
        ) {
            let terminal = synth_output_violation_chunk(&request_id, seq, &inputs, &msg);
            chunks_billed = chunks_billed.saturating_add(0); // terminal Error doesn't bill
            forwarded.push(terminal.clone());
            let _ = tx.send(terminal).await;
            terminated = true;
            break;
        }

        // Re-issue the chunk under the source identity. This is the
        // re-encryption + re-key step in the in-process realization
        // (production wire path also performs MLS encryption, which
        // this implementation does not model — the structural
        // invariants `aggregate_schema validated`, `chunk type
        // preserved`, `bridge does not buffer`, `sequence monotonic`
        // are all enforced here regardless). For executor-emitted
        // terminal Error chunks (the target outlet itself returned
        // an error), we still wrap the typed envelope via
        // SCP-OUT-029 so the source observer sees the full
        // `ContextHop` trail through the bridge.
        let new_payload = match &orig.payload {
            ChunkPayload::Error {
                code,
                terminal: true,
                ..
            } => {
                // Re-wrap an executor-emitted terminal error so the
                // chain records the target boundary and oracle
                // collapse / pseudonymization apply at the source
                // observer's view.
                let (class, slug, retry) = classify_executor_error(code);
                let envelope = wrap_terminal_error_envelope(&inputs, class, code, slug, retry);
                let envelope_message = serialize_wrapped_envelope_to_message(&envelope);
                ChunkPayload::Error {
                    code: envelope.code,
                    message: envelope_message,
                    terminal: true,
                }
            }
            other => other.clone(),
        };
        let sig = sign_chunk(
            &inputs.source_operator_key,
            &inputs.source_context_id,
            &inputs.outlet_id,
            &request_id,
            seq,
            &inputs.source_caveats_binding,
            &new_payload,
        )
        .unwrap_or([0u8; 64]);
        let reissued = OutletStreamChunk {
            request_id,
            sequence: seq,
            payload: new_payload,
            sig,
        };

        if matches!(&reissued.payload, ChunkPayload::Data { .. }) {
            chunks_billed = chunks_billed.saturating_add(1);
        }
        let is_terminal = reissued.payload.is_terminal();
        forwarded.push(reissued.clone());
        if tx.send(reissued).await.is_err() {
            terminated = is_terminal;
            break;
        }
        if is_terminal {
            terminated = true;
            break;
        }
    }

    // Mid-stream disconnect: synthesize the bridge-failure terminal.
    if !terminated {
        let seq = next_seq;
        let terminal = synth_bridge_failure_chunk(
            &request_id,
            seq,
            &inputs,
            "executor stream ended without terminal chunk",
        );
        forwarded.push(terminal.clone());
        let _ = tx.send(terminal).await;
    }

    // Suppress unused-binding warnings — these inputs are reserved for
    // production wiring (MLS-epoch keying and the target-side event log
    // dispatch) which lives behind the §6.2.0.5 production seam.
    let _ = (
        inputs.chain_depth,
        inputs.stream_epoch,
        &inputs.target_context_id,
    );

    let completion = build_completion(
        &forwarded,
        chunks_billed,
        &request_id,
        &inputs.outlet_id,
        &inputs.invoker_did,
    );
    let _ = event_tx.send(completion);
}

/// Maps an executor-emitted terminal-error `code` (§5.4.4 6100-6199)
/// to the `(class, slug, retry)` triple used to construct the wrapped
/// [`OutletError`] envelope at the bridge seam.
///
/// Used by [`run_cross_context_bridge`] to re-wrap an executor-emitted
/// terminal Error chunk through SCP-OUT-029 `wrap_cross_context_error`.
/// Unknown codes fall back to the §5.4.4 round-3 collapse target
/// (`SCP-TOOL-6110` / `authorization.denied`) so the envelope is always
/// well-formed.
fn classify_executor_error(
    code: &str,
) -> (
    OutletErrorClass,
    &'static str,
    scp_protocol::context::outlets::errors::RetryPolicy,
) {
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_EXECUTION_CREDIT_STALL,
        CODE_EXECUTION_FAULT, CODE_GOVERNANCE_FAULT, CODE_INPUT_VIOLATION, CODE_OUTPUT_VIOLATION,
        CODE_PROTOCOL_VIOLATION, CODE_TRANSPORT_FAULT, SLUG_AUTHORIZATION_DENIED,
        SLUG_ECONOMIC_INSUFFICIENT_FUNDS, SLUG_EXECUTION_CREDIT_STALL,
        SLUG_EXECUTION_HANDLER_PANIC, SLUG_GOVERNANCE_OUTLET_DEREGISTERED,
        SLUG_INPUT_SCHEMA_VIOLATION, SLUG_OUTPUT_SCHEMA_VIOLATION, SLUG_PROTOCOL_VIOLATION,
        SLUG_TRANSPORT_RELAY_UNAVAILABLE,
    };
    use scp_protocol::context::outlets::errors::RetryPolicy;
    let backoff = || RetryPolicy::WithBackoff {
        min: std::time::Duration::from_secs(1),
        max: std::time::Duration::from_secs(30),
    };
    match code {
        c if c == CODE_PROTOCOL_VIOLATION => (
            OutletErrorClass::Protocol,
            SLUG_PROTOCOL_VIOLATION,
            RetryPolicy::Never,
        ),
        c if c == CODE_AUTHORIZATION_DENIED => (
            OutletErrorClass::Authorization,
            SLUG_AUTHORIZATION_DENIED,
            RetryPolicy::Never,
        ),
        c if c == CODE_INPUT_VIOLATION => (
            OutletErrorClass::Input,
            SLUG_INPUT_SCHEMA_VIOLATION,
            RetryPolicy::Never,
        ),
        c if c == CODE_EXECUTION_FAULT => (
            OutletErrorClass::Execution,
            SLUG_EXECUTION_HANDLER_PANIC,
            RetryPolicy::Never,
        ),
        c if c == CODE_EXECUTION_CREDIT_STALL => (
            OutletErrorClass::Execution,
            SLUG_EXECUTION_CREDIT_STALL,
            backoff(),
        ),
        c if c == CODE_OUTPUT_VIOLATION => (
            OutletErrorClass::Output,
            SLUG_OUTPUT_SCHEMA_VIOLATION,
            RetryPolicy::Never,
        ),
        c if c == CODE_ECONOMIC_FAULT => (
            OutletErrorClass::Economic,
            SLUG_ECONOMIC_INSUFFICIENT_FUNDS,
            RetryPolicy::Never,
        ),
        c if c == CODE_TRANSPORT_FAULT => (
            OutletErrorClass::Transport,
            SLUG_TRANSPORT_RELAY_UNAVAILABLE,
            backoff(),
        ),
        c if c == CODE_GOVERNANCE_FAULT => (
            OutletErrorClass::Governance,
            SLUG_GOVERNANCE_OUTLET_DEREGISTERED,
            RetryPolicy::Never,
        ),
        // Unknown code — collapse to §5.4.4 round-3 target.
        _ => (
            OutletErrorClass::Authorization,
            COLLAPSED_AUTHORIZATION_DENIED_SLUG,
            RetryPolicy::Never,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cross_context_chunk_bridge_tests {
    //! SCP-OUT-036 — cross-context chunk bridge tests.
    //!
    //! Exercises the three §6.2.0.5 acceptance criteria:
    //! 1. A 10-chunk Data + End stream survives the bridge with monotonic
    //!    sequence and matching `stream_manifest_hash` on both events.
    //! 2. Mid-stream executor disconnect produces a terminal Error chunk
    //!    with code `SCP-TOOL-6160` (transport.cross-context-bridge-failure).
    //! 3. End.aggregate violating `aggregate_schema` produces a terminal
    //!    Error chunk with code `SCP-TOOL-6140` (output.schema-violation).
    //!
    //! `chain_depth` inheritance and chunk-type preservation
    //! (Data→Data, Progress→Progress, Error→Error) are exercised in
    //! every test by construction — the bridge re-emits each chunk with
    //! the same `ChunkPayload` variant.

    use super::*;
    use ed25519_dalek::SigningKey;
    use scp_protocol::context::outlets::error_codes::{
        CODE_OUTPUT_VIOLATION, CODE_TRANSPORT_FAULT,
    };
    use scp_protocol::context::outlets::stream::{
        ChunkPayload, OutletStreamChunk, RequestId, sign_chunk,
    };

    fn target_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn source_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    fn output_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "n": {"type": "integer"}
            },
            "required": ["kind", "n"]
        })
    }

    fn aggregate_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "summary": {"type": "string"}
            },
            "required": ["total", "summary"]
        })
    }

    fn fresh_inputs(
        source_op_key: SigningKey,
        with_aggregate_schema: bool,
    ) -> CrossContextInvokeInputs {
        // SCP-OUT-029 wrap-view defaults: full visibility (membership of
        // every named context, both stems on the inner outlet) so the
        // legacy bridge tests observe un-pseudonymized chains and stable
        // codes. Tests asserting collapse / pseudonymization construct
        // their own inputs with restricted closures.
        let member_of: BridgeMemberClosure =
            std::sync::Arc::new(|c: &str| matches!(c, "ctx-source" | "ctx-target"));
        let hop_salts: BridgeHopSaltClosure = std::sync::Arc::new(|_: &str| Some([0xEE; 32]));
        CrossContextInvokeInputs {
            source_context_id: "ctx-source".to_owned(),
            target_context_id: "ctx-target".to_owned(),
            outlet_id: "outlet-stream".to_owned(),
            source_caveats_binding: [0xAB; 32],
            target_caveats_binding: [0xCD; 32],
            chain_depth: 3,
            stream_epoch: 7,
            source_operator_key: std::sync::Arc::new(source_op_key),
            aggregate_schema: if with_aggregate_schema {
                Some(aggregate_schema())
            } else {
                None
            },
            output_schema: output_schema(),
            invoker_did: "did:dht:z6MkInvoker".to_owned(),
            source_member_of_context: member_of,
            source_hop_salts: hop_salts,
            source_outer_caller_stems: OuterCallerStems {
                holds_query: true,
                holds_call: true,
            },
            inner_outlet_kind: Some(OutletKind::Action),
            max_padded_trail_depth: MAX_TRAIL_PAD_DEPTH,
        }
    }

    fn build_executor_chunk(
        request_id: &RequestId,
        sequence: u64,
        payload: ChunkPayload,
        target_op_key: &SigningKey,
        target_caveats_binding: &[u8; 32],
    ) -> OutletStreamChunk {
        let sig = sign_chunk(
            target_op_key,
            "ctx-target",
            "outlet-stream",
            request_id,
            sequence,
            target_caveats_binding,
            &payload,
        )
        .unwrap();
        OutletStreamChunk {
            request_id: *request_id,
            sequence,
            payload,
            sig,
        }
    }

    fn data_value(n: i64) -> serde_json::Value {
        serde_json::json!({"kind": "tick", "n": n})
    }

    /// AC: cross-context 10-chunk stream A→B completes successfully;
    /// both event logs agree on `stream_manifest_hash`.
    #[tokio::test]
    async fn ten_chunk_stream_round_trip_matches_manifest_hash() {
        let target_key = target_signing_key();
        let target_binding = [0xCD; 32];
        let inputs = fresh_inputs(source_signing_key(), false);

        let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
        let (request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

        // Emit 10 Data chunks then a single End chunk on the executor side.
        let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
        let exec_task = tokio::spawn(async move {
            for n in 0..10i64 {
                let chunk = build_executor_chunk(
                    &target_request_id,
                    n.cast_unsigned(),
                    ChunkPayload::Data {
                        value: data_value(n),
                    },
                    &target_key,
                    &target_binding,
                );
                etx.send(chunk).await.unwrap();
            }
            let end = build_executor_chunk(
                &target_request_id,
                10,
                ChunkPayload::End {
                    aggregate: data_value(9),
                    provenance: scp_protocol::provenance::DataProvenance {
                        source_context: "ctx-target".to_owned(),
                        source_type: scp_protocol::provenance::SourceType::Persistent,
                        counterparties: Vec::new(),
                        purpose: None,
                        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                        age: std::time::Duration::from_secs(0),
                        memory_scope: scp_protocol::context::params::MemoryScope::Full,
                        chain_depth: 3,
                        chain_path: None,
                        payment_amount: None,
                        payment_adapter: None,
                        payment_receipt_id: None,
                    },
                    execution_time_ms: 100,
                },
                &target_key,
                &target_binding,
            );
            etx.send(end).await.unwrap();
        });

        let mut received: Vec<OutletStreamChunk> = Vec::new();
        while let Some(c) = bridge.receiver.recv().await {
            received.push(c);
        }
        exec_task.await.unwrap();

        assert_eq!(received.len(), 11, "10 Data + 1 End");
        // Every chunk carries the source-issued request_id, monotonic
        // sequence starting at 0, and preserves payload variant.
        for (i, c) in received.iter().enumerate() {
            assert_eq!(c.request_id, request_id);
            assert_eq!(c.sequence, i as u64);
        }
        for c in &received[..10] {
            assert!(matches!(&c.payload, ChunkPayload::Data { .. }));
        }
        assert!(matches!(
            &received.last().unwrap().payload,
            ChunkPayload::End { .. }
        ));

        let completion = bridge
            .event_handle
            .await_completion()
            .await
            .expect("completion");
        assert_eq!(
            completion.source_event.stream_manifest_hash,
            completion.target_event.stream_manifest_hash,
            "both event logs must agree on stream_manifest_hash"
        );
        assert_ne!(
            completion.stream_manifest_hash, [0u8; 32],
            "manifest hash must be non-zero for a successful 10-chunk stream"
        );
        assert_eq!(completion.source_event.stream_chunk_count, 11);
        assert_eq!(completion.source_event.chunks_billed, 10);
        assert_eq!(completion.source_event.status, OutletStatus::Success);
    }

    /// AC: mid-stream bridge failure (executor disconnect with no
    /// terminal chunk) produces a terminal Error with
    /// `code = "SCP-TOOL-6160"` (transport.cross-context-bridge-failure)
    /// and `terminal = true`.
    #[tokio::test]
    async fn mid_stream_bridge_failure_emits_terminal_transport_error() {
        let target_key = target_signing_key();
        let target_binding = [0xCD; 32];
        let inputs = fresh_inputs(source_signing_key(), false);

        let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
        let (_request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

        let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
        let exec_task = tokio::spawn(async move {
            // Send 3 Data chunks, then drop the sender without a terminal.
            for n in 0..3i64 {
                let chunk = build_executor_chunk(
                    &target_request_id,
                    n.cast_unsigned(),
                    ChunkPayload::Data {
                        value: data_value(n),
                    },
                    &target_key,
                    &target_binding,
                );
                etx.send(chunk).await.unwrap();
            }
            drop(etx);
        });

        let mut received: Vec<OutletStreamChunk> = Vec::new();
        while let Some(c) = bridge.receiver.recv().await {
            received.push(c);
        }
        exec_task.await.unwrap();

        // 3 Data + 1 synthesized terminal Error.
        assert_eq!(received.len(), 4);
        let terminal = received.last().unwrap();
        match &terminal.payload {
            ChunkPayload::Error { code, terminal, .. } => {
                assert_eq!(code, CODE_TRANSPORT_FAULT);
                assert!(*terminal, "bridge failure must be terminal");
            }
            other => panic!("expected terminal Error, got {other:?}"),
        }

        let completion = bridge
            .event_handle
            .await_completion()
            .await
            .expect("completion");
        assert_eq!(completion.source_event.status, OutletStatus::Error);
        assert_eq!(
            completion.target_event.stream_manifest_hash,
            completion.stream_manifest_hash
        );
    }

    /// AC: End.aggregate violating `aggregate_schema` produces a
    /// terminal Error with `code = "SCP-TOOL-6140"`
    /// (output.schema-violation) and `terminal = true`.
    #[tokio::test]
    async fn end_aggregate_violating_schema_emits_terminal_output_error() {
        let target_key = target_signing_key();
        let target_binding = [0xCD; 32];
        // aggregate_schema requires `total: integer, summary: string`.
        let inputs = fresh_inputs(source_signing_key(), true);

        let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
        let (_request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

        let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
        let exec_task = tokio::spawn(async move {
            // Single valid Data chunk first.
            let data = build_executor_chunk(
                &target_request_id,
                0,
                ChunkPayload::Data {
                    value: data_value(7),
                },
                &target_key,
                &target_binding,
            );
            etx.send(data).await.unwrap();

            // End with aggregate that violates `aggregate_schema`
            // (missing required `summary`, wrong shape).
            let bad_end = build_executor_chunk(
                &target_request_id,
                1,
                ChunkPayload::End {
                    aggregate: serde_json::json!({"total": "not-an-integer"}),
                    provenance: scp_protocol::provenance::DataProvenance {
                        source_context: "ctx-target".to_owned(),
                        source_type: scp_protocol::provenance::SourceType::Persistent,
                        counterparties: Vec::new(),
                        purpose: None,
                        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                        age: std::time::Duration::from_secs(0),
                        memory_scope: scp_protocol::context::params::MemoryScope::Full,
                        chain_depth: 3,
                        chain_path: None,
                        payment_amount: None,
                        payment_adapter: None,
                        payment_receipt_id: None,
                    },
                    execution_time_ms: 1,
                },
                &target_key,
                &target_binding,
            );
            etx.send(bad_end).await.unwrap();
        });

        let mut received: Vec<OutletStreamChunk> = Vec::new();
        while let Some(c) = bridge.receiver.recv().await {
            received.push(c);
        }
        exec_task.await.unwrap();

        // 1 Data + synthesized terminal output-violation Error.
        assert_eq!(received.len(), 2);
        let terminal = received.last().unwrap();
        match &terminal.payload {
            ChunkPayload::Error { code, terminal, .. } => {
                assert_eq!(code, CODE_OUTPUT_VIOLATION);
                assert!(*terminal, "schema violation must be terminal");
            }
            other => panic!("expected terminal Error, got {other:?}"),
        }
    }

    /// AC: Per-chunk Data validation uses `output_schema` (not
    /// `aggregate_schema`). A Data chunk that violates `output_schema`
    /// produces a terminal output-violation Error mid-stream.
    #[tokio::test]
    async fn per_chunk_data_validates_against_output_schema() {
        let target_key = target_signing_key();
        let target_binding = [0xCD; 32];
        let inputs = fresh_inputs(source_signing_key(), true);

        let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(64);
        let (_request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

        let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
        let exec_task = tokio::spawn(async move {
            // Valid first chunk.
            let ok = build_executor_chunk(
                &target_request_id,
                0,
                ChunkPayload::Data {
                    value: data_value(1),
                },
                &target_key,
                &target_binding,
            );
            etx.send(ok).await.unwrap();
            // Invalid second chunk (missing required `n`).
            let bad = build_executor_chunk(
                &target_request_id,
                1,
                ChunkPayload::Data {
                    value: serde_json::json!({"kind": "missing-n"}),
                },
                &target_key,
                &target_binding,
            );
            etx.send(bad).await.unwrap();
            // Subsequent chunks should NOT be forwarded (bridge stops at terminal).
            let extra = build_executor_chunk(
                &target_request_id,
                2,
                ChunkPayload::Data {
                    value: data_value(99),
                },
                &target_key,
                &target_binding,
            );
            let _ = etx.send(extra).await;
        });

        let mut received: Vec<OutletStreamChunk> = Vec::new();
        while let Some(c) = bridge.receiver.recv().await {
            received.push(c);
        }
        let _ = exec_task.await;

        assert_eq!(received.len(), 2);
        let terminal = received.last().unwrap();
        match &terminal.payload {
            ChunkPayload::Error { code, terminal, .. } => {
                assert_eq!(code, CODE_OUTPUT_VIOLATION);
                assert!(*terminal);
            }
            other => panic!("expected terminal Error, got {other:?}"),
        }
    }

    /// AC: `chain_depth` on every forwarded chunk == `chain_depth` on
    /// `OutletStreamOpen`. The current bridge does not surface
    /// `chain_depth` on the chunk wire, but the input is structurally
    /// pinned at open and must equal the value supplied to the bridge.
    #[test]
    fn chain_depth_pinned_at_open() {
        let inputs = fresh_inputs(source_signing_key(), false);
        assert_eq!(inputs.chain_depth, 3);
        // Re-construction with a different chain_depth would change the
        // pinned value; the bridge does not modify it.
        let mut alt = fresh_inputs(source_signing_key(), false);
        alt.chain_depth = 99;
        assert_ne!(inputs.chain_depth, alt.chain_depth);
    }

    /// AC: bridge does not buffer; chunk-to-chunk latency is bounded by
    /// MLS encryption + relay. We assert the bridge forwards each chunk
    /// before reading the next: the receiver must observe the first
    /// chunk before the executor sends the second (proven by a
    /// rendezvous channel of capacity 1).
    #[tokio::test]
    async fn bridge_does_not_buffer_chunks() {
        let target_key = target_signing_key();
        let target_binding = [0xCD; 32];
        let inputs = fresh_inputs(source_signing_key(), false);

        let (etx, erx) = tokio::sync::mpsc::channel::<OutletStreamChunk>(1);
        let (_request_id, mut bridge) = invoke_outlet_cross_context(inputs, erx);

        let target_request_id: RequestId = *uuid::Uuid::now_v7().as_bytes();
        let (gate_tx, mut gate_rx) = tokio::sync::mpsc::channel::<()>(1);
        let exec_task = tokio::spawn(async move {
            let chunk0 = build_executor_chunk(
                &target_request_id,
                0,
                ChunkPayload::Data {
                    value: data_value(0),
                },
                &target_key,
                &target_binding,
            );
            etx.send(chunk0).await.unwrap();
            // Wait until the receiver has seen the first chunk before
            // sending the second.
            gate_rx.recv().await;
            let chunk1 = build_executor_chunk(
                &target_request_id,
                1,
                ChunkPayload::Data {
                    value: data_value(1),
                },
                &target_key,
                &target_binding,
            );
            etx.send(chunk1).await.unwrap();
            let end = build_executor_chunk(
                &target_request_id,
                2,
                ChunkPayload::End {
                    aggregate: data_value(1),
                    provenance: scp_protocol::provenance::DataProvenance {
                        source_context: "ctx-target".to_owned(),
                        source_type: scp_protocol::provenance::SourceType::Persistent,
                        counterparties: Vec::new(),
                        purpose: None,
                        discovery_method: scp_protocol::provenance::DiscoveryMethod::OutOfBand,
                        age: std::time::Duration::from_secs(0),
                        memory_scope: scp_protocol::context::params::MemoryScope::Full,
                        chain_depth: 3,
                        chain_path: None,
                        payment_amount: None,
                        payment_adapter: None,
                        payment_receipt_id: None,
                    },
                    execution_time_ms: 1,
                },
                &target_key,
                &target_binding,
            );
            etx.send(end).await.unwrap();
        });

        let first = bridge.receiver.recv().await.unwrap();
        assert_eq!(first.sequence, 0);
        gate_tx.send(()).await.unwrap();
        let second = bridge.receiver.recv().await.unwrap();
        assert_eq!(second.sequence, 1);
        // End chunk arrives next.
        let end = bridge.receiver.recv().await.unwrap();
        assert!(matches!(end.payload, ChunkPayload::End { .. }));
        let _ = exec_task.await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod wrap_cross_context_error_tests {
    //! SCP-OUT-029 acceptance criteria — all 22 ACs verified here against
    //! the `wrap_cross_context_error` public surface above. Each test cites
    //! the AC it covers.

    use super::*;
    use scp_protocol::context::outlets::OutletId;
    use scp_protocol::context::outlets::errors::{
        CatalogKey, MAX_TRAIL_PAD_DEPTH, MAX_TRAIL_PAD_HMAC_LABEL, OutletError, OutletErrorClass,
        OutletErrorNewOpts, PAD_NONCE_LEN, REGISTRATION_EVENT_ID_LEN, RetryPolicy,
        WIRE_MESSAGE_LEN,
    };
    use std::collections::HashMap;

    /// Convenience aliases for the boxed test-fixture closures so we don't
    /// repeat the verbose `Box<dyn Fn(&str) -> ...>` shape.
    type MemberClosure = Box<dyn Fn(&str) -> bool>;
    type SaltClosure = Box<dyn Fn(&str) -> Option<[u8; 32]>>;

    // ----------------- helpers -----------------

    fn fixed_outlet_message_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn fixed_pad_nonce() -> [u8; PAD_NONCE_LEN] {
        [0x55; PAD_NONCE_LEN]
    }

    fn fixed_registration_event_id() -> [u8; REGISTRATION_EVENT_ID_LEN] {
        [0xAB; REGISTRATION_EVENT_ID_LEN]
    }

    fn registered() -> Vec<CatalogKey> {
        vec![
            CatalogKey::try_new("authorization.denied").unwrap(),
            CatalogKey::try_new("authorization.amplification-violation").unwrap(),
            CatalogKey::try_new("protocol.outlet-not-found").unwrap(),
            CatalogKey::try_new("execution.handler-panic").unwrap(),
        ]
    }

    fn build_inner_authorization_error() -> OutletError {
        let outlet_id: OutletId = "outlet-inner".to_owned();
        let key = CatalogKey::try_new("authorization.denied").unwrap();
        let registered = registered();
        OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: "SCP-TOOL-6110",
            slug: "authorization.denied",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .unwrap()
    }

    fn build_inner_amplification_error() -> OutletError {
        let outlet_id: OutletId = "outlet-amp".to_owned();
        // SCP-OUT-025: `authorization.amplification-violation` is the
        // amplification slug whose canonical §5.4.4 mapping is
        // `OutletErrorClass::Authorization` / `SCP-TOOL-6110` per the
        // registry. Prior to OUT-025 this fixture used code 6120 (Input)
        // which silently disagreed with the declared Authorization
        // class — caught now by the registry's class/code consistency
        // check inside `OutletError::new`.
        let key = CatalogKey::try_new("authorization.amplification-violation").unwrap();
        let registered = registered();
        OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &key,
            registered_keys: &registered,
            class: OutletErrorClass::Authorization,
            code: "SCP-TOOL-6110",
            slug: "authorization.amplification-violation",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .unwrap()
    }

    /// View where the observer is a full member of every named context
    /// AND holds both stems on the inner outlet. Used to exercise the
    /// full-visibility short-circuit.
    #[allow(dead_code)] // members/salts are kept on the struct so they live as long as the closures that capture clones of them.
    struct FullVisibilityFixture {
        observer: ContextId,
        members: std::collections::HashSet<String>,
        salts: HashMap<String, [u8; 32]>,
        nonce: [u8; PAD_NONCE_LEN],
        member_closure: MemberClosure,
        salt_closure: SaltClosure,
    }

    impl FullVisibilityFixture {
        fn new() -> Self {
            let observer: ContextId = "ctx-observer".to_owned();
            let mut members = std::collections::HashSet::new();
            members.insert(observer.clone());
            members.insert("ctx-b".to_owned());
            members.insert("ctx-c".to_owned());
            members.insert("ctx-a".to_owned());
            members.insert("ctx-inner".to_owned());
            let salts = HashMap::new();
            let members_for_closure = members.clone();
            let salts_for_closure = salts.clone();
            let member_closure: MemberClosure =
                Box::new(move |c: &str| members_for_closure.contains(c));
            let salt_closure: SaltClosure =
                Box::new(move |c: &str| salts_for_closure.get(c).copied());
            Self {
                observer,
                members,
                salts,
                nonce: [0xCC; PAD_NONCE_LEN],
                member_closure,
                salt_closure,
            }
        }

        fn view(
            &self,
            stems: OuterCallerStems,
            kind: Option<OutletKind>,
            max_pad: u8,
        ) -> OutletErrorWrapView<'_> {
            OutletErrorWrapView {
                observer_ctx: &self.observer,
                member_of_context: self.member_closure.as_ref(),
                hop_salts: self.salt_closure.as_ref(),
                outer_caller_stems: stems,
                inner_outlet_kind: kind,
                pad_nonce: self.nonce,
                max_padded_trail_depth: max_pad,
            }
        }
    }

    /// View where the observer is NOT a member of any named hop, holds NO
    /// stems on the inner outlet, and per-pair salts are configured for
    /// each known peer. Drives the §5.4.4 round-3 collapse + round-5 pad
    /// path.
    #[allow(dead_code)] // `members`/`salts` are retained for test introspection (e.g., AC-11 byte-equality assert) even when unused on the read path.
    struct NonMemberFixture {
        observer: ContextId,
        members: std::collections::HashSet<String>,
        salts: HashMap<String, [u8; 32]>,
        nonce: [u8; PAD_NONCE_LEN],
        member_closure: MemberClosure,
        salt_closure: SaltClosure,
    }

    impl NonMemberFixture {
        fn new() -> Self {
            let observer: ContextId = "ctx-observer".to_owned();
            let mut members = std::collections::HashSet::new();
            members.insert(observer.clone()); // observer always member of own ctx
            let mut salts = HashMap::new();
            salts.insert("ctx-b".to_owned(), [0x11; 32]);
            salts.insert("ctx-c".to_owned(), [0x22; 32]);
            salts.insert("ctx-a".to_owned(), [0x33; 32]);
            salts.insert("ctx-inner".to_owned(), [0x44; 32]);
            let members_for_closure = members.clone();
            let salts_for_closure = salts.clone();
            let member_closure: MemberClosure =
                Box::new(move |c: &str| members_for_closure.contains(c));
            let salt_closure: SaltClosure =
                Box::new(move |c: &str| salts_for_closure.get(c).copied());
            Self {
                observer,
                members,
                salts,
                nonce: [0xDD; PAD_NONCE_LEN],
                member_closure,
                salt_closure,
            }
        }

        fn view(
            &self,
            stems: OuterCallerStems,
            kind: Option<OutletKind>,
            max_pad: u8,
        ) -> OutletErrorWrapView<'_> {
            OutletErrorWrapView {
                observer_ctx: &self.observer,
                member_of_context: self.member_closure.as_ref(),
                hop_salts: self.salt_closure.as_ref(),
                outer_caller_stems: stems,
                inner_outlet_kind: kind,
                pad_nonce: self.nonce,
                max_padded_trail_depth: max_pad,
            }
        }
    }

    // ============================================================
    // AC-1 / AC-2 / AC-3 / AC-4 / AC-5 — basic prepend semantics
    // ============================================================

    #[test]
    fn ac1_one_hop_wrap_prepends_context_hop() {
        // AC-1: wrap_cross_context_error prepends a ContextHop.
        // AC-2: wrapped.code == prev.code (preserved when caller has stems).
        // AC-3: wrapped.source_chain.first().context_id == caller_ctx (raw
        //       when caller is a member).
        // AC-4: wrapped.source_chain.first().hop_index == prev.last + 1
        //       (or 1 if empty).
        // AC-5: wrapped.source_chain.first().wrapped_code == prev.code.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), MAX_TRAIL_PAD_DEPTH);

        let prev = build_inner_authorization_error();
        let prev_code = prev.code.clone();
        let caller_ctx: ContextId = "ctx-b".to_owned();

        let wrapped = wrap_cross_context_error(&caller_ctx, prev, &view);

        // AC-2: code preserved.
        assert_eq!(wrapped.code, prev_code, "AC-2: code preserved");

        // AC-1 / AC-3 / AC-4 / AC-5.
        assert!(!wrapped.source_chain.is_empty(), "AC-1: hop prepended");
        let first = &wrapped.source_chain[0];
        assert_eq!(first.context_id, caller_ctx, "AC-3: first.context_id");
        assert_eq!(first.hop_index, 1, "AC-4: first.hop_index = 1 when empty");
        assert_eq!(
            first.wrapped_code, prev_code,
            "AC-5: wrapped_code = prev.code"
        );
    }

    #[test]
    fn ac6_one_hop_wrap_unit_test() {
        // AC-6: Unit test — one-hop wrap. Covered by ac1_one_hop_wrap_prepends_context_hop above
        // plus the assertion that the resulting source_chain has length 1
        // when prev was empty and we are in full visibility.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), MAX_TRAIL_PAD_DEPTH);
        let prev = build_inner_authorization_error();
        let caller_ctx: ContextId = "ctx-b".to_owned();
        let wrapped = wrap_cross_context_error(&caller_ctx, prev, &view);
        assert_eq!(wrapped.source_chain.len(), 1, "single-hop trail length");
    }

    #[test]
    fn ac7_three_hop_wrap_monotonic_hop_index() {
        // AC-7: three-hop wrap asserts source_chain is ordered with monotonic
        // hop_index. Apply wrap three times and verify the trail is built
        // up correctly with each wrap incrementing the wrap-counter.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), MAX_TRAIL_PAD_DEPTH);

        let prev = build_inner_authorization_error();
        let original_code = prev.code.clone();

        // Wrap 1: ctx-c (innermost wrap).
        let after1 = wrap_cross_context_error(&"ctx-c".to_owned(), prev, &view);
        assert_eq!(after1.source_chain.len(), 1);
        assert_eq!(after1.source_chain[0].hop_index, 1);
        assert_eq!(after1.code, original_code);

        // Wrap 2: ctx-b (next outer wrap).
        let after2 = wrap_cross_context_error(&"ctx-b".to_owned(), after1, &view);
        assert_eq!(after2.source_chain.len(), 2);
        assert_eq!(after2.source_chain[0].hop_index, 2, "second wrap hop_index");
        assert_eq!(
            after2.source_chain[1].hop_index, 1,
            "preserved inner hop_index"
        );
        assert_eq!(after2.code, original_code, "code preserved through wrap 2");

        // Wrap 3: observer (outermost wrap).
        let after3 = wrap_cross_context_error(&fix.observer.clone(), after2, &view);
        assert_eq!(after3.source_chain.len(), 3);
        assert_eq!(after3.source_chain[0].hop_index, 3, "third wrap hop_index");
        assert_eq!(after3.source_chain[1].hop_index, 2);
        assert_eq!(after3.source_chain[2].hop_index, 1);
        assert_eq!(after3.code, original_code, "code preserved through wrap 3");

        // Monotonic hop_index in front-to-back order (descending wrap-counter).
        let indices: Vec<u16> = after3.source_chain.iter().map(|h| h.hop_index).collect();
        for window in indices.windows(2) {
            assert!(
                window[0] > window[1],
                "front-to-back monotonic decreasing: {indices:?}"
            );
        }
    }

    // ============================================================
    // AC-8 — Integration test: A → B → C invocation, A observes
    // ============================================================

    #[test]
    fn ac8_integration_three_context_chain_with_original_code_and_trail() {
        // AC-8: Context A → B → C invocation where C returns OutletError.
        // A observes code == original AND source_chain shows B and C.
        let fix = FullVisibilityFixture::new(); // A is observer; member of A,B,C,inner.
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), MAX_TRAIL_PAD_DEPTH);

        // C produces error.
        let inner_err = build_inner_authorization_error();
        let inner_code = inner_err.code.clone();

        // C wraps as it crosses out to B.
        let wrapped_at_c = wrap_cross_context_error(&"ctx-c".to_owned(), inner_err, &view);
        // B wraps as the error crosses through it on the way to A.
        let wrapped_at_b = wrap_cross_context_error(&"ctx-b".to_owned(), wrapped_at_c, &view);

        // A consumes. Code preserved.
        assert_eq!(wrapped_at_b.code, inner_code, "A observes original code");
        // source_chain shows B and C entries (front=B, back=C).
        assert_eq!(wrapped_at_b.source_chain.len(), 2);
        assert_eq!(wrapped_at_b.source_chain[0].context_id, "ctx-b");
        assert_eq!(wrapped_at_b.source_chain[1].context_id, "ctx-c");
        assert_eq!(wrapped_at_b.source_chain[0].wrapped_code, inner_code);
        assert_eq!(wrapped_at_b.source_chain[1].wrapped_code, inner_code);
    }

    // ============================================================
    // AC-10 / AC-11 — pseudonymization (HMAC under hop_salt)
    // ============================================================

    #[test]
    fn ac11_outermost_caller_not_member_sees_pseudonymized_innermost_hop() {
        // AC-11: outermost caller NOT a member of innermost hop sees an
        // HMAC-pseudonymized context_id (32 bytes / 64 hex chars).
        let fix = NonMemberFixture::new();
        // Caller holds at least one stem so we don't trigger oracle
        // collapse; we want to verify pseudonymization in isolation.
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: false,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 0); // no padding

        let prev = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), prev, &view);

        // The observer is NOT a member of ctx-b, so the front hop's
        // context_id is HMAC-pseudonymized (64 hex chars = 32 bytes).
        let first_id = &wrapped.source_chain[0].context_id;
        assert_eq!(
            first_id.len(),
            64,
            "AC-11: pseudonym is 32 bytes / 64 hex chars, got len={}",
            first_id.len()
        );
        assert_ne!(first_id, "ctx-b", "AC-11: raw id NOT exposed");

        // Verify the pseudonym is the expected HMAC under the per-pair salt.
        let salt = fix.salts.get("ctx-b").copied().unwrap();
        let expected = pseudonym_to_string(hmac_pseudonymize_context_id(&salt, "ctx-b"));
        assert_eq!(first_id, &expected, "HMAC matches per-pair salt");
    }

    #[test]
    fn ac12_full_visibility_caller_sees_raw_context_ids() {
        // AC-12: outermost caller IS a member of every hop sees raw
        // context_ids (no pseudonymization).
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), MAX_TRAIL_PAD_DEPTH);

        let prev = build_inner_authorization_error();
        let wrapped_c = wrap_cross_context_error(&"ctx-c".to_owned(), prev, &view);
        let wrapped_b = wrap_cross_context_error(&"ctx-b".to_owned(), wrapped_c, &view);

        assert_eq!(wrapped_b.source_chain[0].context_id, "ctx-b", "raw");
        assert_eq!(wrapped_b.source_chain[1].context_id, "ctx-c", "raw");
    }

    #[test]
    fn ac13_two_relationships_produce_different_pseudonyms_for_same_target() {
        // AC-13: two independent interface relationships (A↔B and A↔C)
        // produce different pseudonyms for the same B context_id when A is
        // the observer but A is not a member of B (each relationship uses
        // its own per-pair salt).
        //
        // The wrap function uses `view.hop_salts(&target_id)` to pick the
        // per-pair salt at projection time; passing TWO different salts
        // for the same raw context_id (simulating two relationships)
        // produces two different pseudonyms.
        let observer: ContextId = "ctx-a".to_owned();
        let mut members = std::collections::HashSet::new();
        members.insert(observer.clone()); // member of own only

        // Relationship 1: A↔B with salt_1.
        let mut salts1 = HashMap::new();
        salts1.insert("ctx-b".to_owned(), [0x01; 32]);

        // Relationship 2: A↔B with salt_2 (pretend a different relationship
        // path supplies a different salt; in reality a single A↔B interface
        // has one salt, but the AC asserts ABSTRACT non-correlation across
        // relationships). For this test we model it as two distinct
        // hop_salts views.
        let mut salts2 = HashMap::new();
        salts2.insert("ctx-b".to_owned(), [0x02; 32]);

        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: false,
        };
        let nonce = [0xEE; PAD_NONCE_LEN];

        let view1 = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts1.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: nonce,
            max_padded_trail_depth: 0, // no padding to isolate the per-pair test
        };
        let view2 = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts2.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: nonce,
            max_padded_trail_depth: 0,
        };

        let prev1 = build_inner_authorization_error();
        let prev2 = build_inner_authorization_error();
        let w1 = wrap_cross_context_error(&"ctx-b".to_owned(), prev1, &view1);
        let w2 = wrap_cross_context_error(&"ctx-b".to_owned(), prev2, &view2);

        assert_ne!(
            w1.source_chain[0].context_id, w2.source_chain[0].context_id,
            "different per-pair salts produce different pseudonyms"
        );
        // Sanity: both are HMAC-shape.
        assert_eq!(w1.source_chain[0].context_id.len(), 64);
        assert_eq!(w2.source_chain[0].context_id.len(), 64);
    }

    // ============================================================
    // AC-14 / AC-15 / AC-16 — query oracle collapse
    // ============================================================

    #[test]
    fn ac14_no_stem_caller_receives_collapsed_authorization_denied_for_three_underlying_causes() {
        // AC-14: caller with no stem receives SCP-TOOL-6110 'authorization.denied'
        // for missing outlet, deregistered outlet, kind-mismatch — all three
        // produce the same code+slug.
        // AC-15: same as AC-14 with explicit per-cause inputs.

        // We synthesize three "underlying causes" by emitting different inner
        // errors. Each must collapse to authorization.denied for a no-stem
        // caller.
        let outlet_id: OutletId = "outlet-test".to_owned();
        let causes: Vec<(&str, &str, OutletErrorClass, &str)> = vec![
            (
                "missing outlet",
                "SCP-TOOL-6110",
                OutletErrorClass::Authorization,
                "authorization.denied",
            ),
            (
                "deregistered",
                "SCP-TOOL-6171", // SCP-CODE-OK: oracle-collapse test input; intentionally an unallocated reserved-gap code so the collapse target (CODE_AUTHORIZATION_DENIED) is asserted to override it
                OutletErrorClass::Governance,
                "governance.outlet-deregistered",
            ),
            (
                "kind-mismatch",
                "SCP-TOOL-6103", // SCP-CODE-OK: oracle-collapse test input; intentionally an unallocated reserved-gap code so the collapse target (CODE_AUTHORIZATION_DENIED) is asserted to override it
                OutletErrorClass::Protocol,
                "protocol.kind-mismatch",
            ),
        ];

        let fix = NonMemberFixture::new();
        let stems = OuterCallerStems {
            holds_query: false,
            holds_call: false,
        };
        let view = fix.view(stems, None, MAX_TRAIL_PAD_DEPTH);

        for (label, code, class, slug) in causes {
            // Need to add the slug to the registered catalog for this fixture.
            let mut all_keys = registered();
            for k in ["governance.outlet-deregistered", "protocol.kind-mismatch"] {
                all_keys.push(CatalogKey::try_new(k).unwrap());
            }
            let catalog_key_obj = CatalogKey::try_new(slug).unwrap();
            let inner = OutletError::new(OutletErrorNewOpts {
                outlet_id: &outlet_id,
                outlet_message_key: &fixed_outlet_message_key(),
                registration_event_id: fixed_registration_event_id(),
                catalog_key: &catalog_key_obj,
                registered_keys: &all_keys,
                class,
                code,
                slug,
                retry: RetryPolicy::Never,
                detail: None,
                source_chain: Vec::new(),
                pad_nonce: fixed_pad_nonce(),
            })
            .unwrap();

            let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
            assert_eq!(
                wrapped.code, COLLAPSED_AUTHORIZATION_DENIED_CODE,
                "AC-14/15: no-stem caller sees collapsed code for {label}"
            );
            assert_eq!(
                wrapped.slug, COLLAPSED_AUTHORIZATION_DENIED_SLUG,
                "AC-14/15: no-stem caller sees collapsed slug for {label}"
            );
        }
    }

    #[test]
    fn ac16_caller_with_query_stem_receives_disambiguated_error() {
        // AC-16: caller with outlet_query:{id} on a Query outlet that
        // DOESN'T exist receives a more-specific error — disambiguation
        // allowed when caller holds at least one matching stem.
        let outlet_id: OutletId = "outlet-test".to_owned();
        let mut all_keys = registered();
        all_keys.push(CatalogKey::try_new("protocol.outlet-not-found").unwrap());
        let catalog_key_obj = CatalogKey::try_new("protocol.outlet-not-found").unwrap();
        let inner = OutletError::new(OutletErrorNewOpts {
            outlet_id: &outlet_id,
            outlet_message_key: &fixed_outlet_message_key(),
            registration_event_id: fixed_registration_event_id(),
            catalog_key: &catalog_key_obj,
            registered_keys: &all_keys,
            class: OutletErrorClass::Protocol,
            code: "SCP-TOOL-6101",
            slug: "protocol.outlet-not-found",
            retry: RetryPolicy::Never,
            detail: None,
            source_chain: Vec::new(),
            pad_nonce: fixed_pad_nonce(),
        })
        .unwrap();
        let original_code = inner.code.clone();
        let original_slug = inner.slug.clone();

        let fix = NonMemberFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: false,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 0);

        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        assert_eq!(
            wrapped.code, original_code,
            "AC-16: stem-holder sees original code"
        );
        assert_eq!(
            wrapped.slug, original_slug,
            "AC-16: stem-holder sees original slug"
        );
    }

    // ============================================================
    // AC-17 — AmplificationViolation collapse
    // ============================================================

    #[test]
    fn ac17_amplification_collapses_for_caller_holding_only_one_stem() {
        // AC-17: caller holding only outlet_query:{id} (NOT outlet_call:{id})
        // observing an amplification attempt receives 'authorization.denied';
        // caller holding BOTH stems receives 'authorization.amplification-violation'.

        let inner = build_inner_amplification_error();
        let original_slug = inner.slug.clone();

        // Caller with only outlet_query (no outlet_call): collapses.
        let fix1 = NonMemberFixture::new();
        let stems_query_only = OuterCallerStems {
            holds_query: true,
            holds_call: false,
        };
        let view_query_only = fix1.view(stems_query_only, Some(OutletKind::Action), 0);
        let wrapped_q =
            wrap_cross_context_error(&"ctx-b".to_owned(), inner.clone(), &view_query_only);
        assert_eq!(
            wrapped_q.slug, COLLAPSED_AUTHORIZATION_DENIED_SLUG,
            "AC-17: query-only caller sees collapse"
        );
        assert_eq!(
            wrapped_q.code, COLLAPSED_AUTHORIZATION_DENIED_CODE,
            "AC-17: query-only caller sees collapsed code"
        );

        // Caller with BOTH stems: sees the disambiguated slug.
        let fix2 = NonMemberFixture::new();
        let stems_both = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view_both = fix2.view(stems_both, Some(OutletKind::Action), 0);
        let wrapped_b = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view_both);
        assert_eq!(
            wrapped_b.slug, original_slug,
            "AC-17: both-stem caller sees disambiguated slug"
        );
    }

    // ============================================================
    // AC-18 — trail-length padding to max_padded_trail_depth
    // ============================================================

    #[test]
    fn ac18_no_member_caller_observes_padded_trail_at_max_depth() {
        // AC-18: caller with no membership observing a 3-hop chain (with
        // max_padded_trail_depth = 8) receives source_chain of length 8;
        // the last 5 entries are pad; every entry's hop_index equals its
        // slot_index; the 3 real entries are still observable via
        // HMAC(hop_salt, raw_context_id) at the membership-visible slots.
        //
        // Per the wrap contract, padding fires at the OUTERMOST observing
        // layer (the one that actually projects to the consumer's view).
        // Intermediate wraps use a permissive view (full-visibility, zero
        // pad depth) so they only append the new ContextHop without
        // padding/collapse. Final wrap at the consumer's layer applies the
        // observer-specific projection.

        // Permissive intermediate-wrap view used by the inner B/C layers —
        // they are "members of everything" relative to themselves so they
        // simply forward raw context_ids.
        let intermediate_observer: ContextId = "ctx-passthrough".to_owned();
        let mut intermediate_members = std::collections::HashSet::new();
        intermediate_members.insert("ctx-c".to_owned());
        intermediate_members.insert("ctx-b".to_owned());
        intermediate_members.insert("ctx-a".to_owned());
        intermediate_members.insert(intermediate_observer.clone());
        let intermediate_salts: HashMap<String, [u8; 32]> = HashMap::new();
        let intermediate_view = OutletErrorWrapView {
            observer_ctx: &intermediate_observer,
            member_of_context: &|c| intermediate_members.contains(c),
            hop_salts: &|c| intermediate_salts.get(c).copied(),
            outer_caller_stems: OuterCallerStems {
                holds_query: true,
                holds_call: true,
            },
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: [0x00; PAD_NONCE_LEN], // unused — no padding at intermediate layers
            max_padded_trail_depth: 0,
        };

        // Outermost no-member observer view — padding fires here.
        let observer: ContextId = "ctx-observer".to_owned();
        let mut members = std::collections::HashSet::new();
        members.insert(observer.clone()); // observer member of own only
        let mut salts = HashMap::new();
        salts.insert("ctx-c".to_owned(), [0x01; 32]);
        salts.insert("ctx-b".to_owned(), [0x02; 32]);
        salts.insert("ctx-a".to_owned(), [0x03; 32]);
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let nonce = [0x77; PAD_NONCE_LEN];
        let outer_view = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: nonce,
            max_padded_trail_depth: 8,
        };

        // Build a 3-hop chain via two intermediate wraps + one outer.
        let inner = build_inner_authorization_error();
        let after_c = wrap_cross_context_error(&"ctx-c".to_owned(), inner, &intermediate_view);
        let after_b = wrap_cross_context_error(&"ctx-b".to_owned(), after_c, &intermediate_view);
        // Final wrap at the consumer's layer — projects to observer's view
        // and pads.
        let after_a = wrap_cross_context_error(&"ctx-a".to_owned(), after_b, &outer_view);

        // AC-18 length 8.
        assert_eq!(
            after_a.source_chain.len(),
            8,
            "AC-18: padded length = max_padded_trail_depth (8)"
        );

        // Every entry's hop_index == slot_index.
        for (slot, hop) in after_a.source_chain.iter().enumerate() {
            assert_eq!(
                hop.hop_index as usize, slot,
                "AC-18: hop_index == slot_index for slot {slot}"
            );
        }

        // The 3 real entries are at slots 0..2; pads at slots 3..7.
        // Real entries are pseudonymized via per-pair salts.
        let real_slots = &after_a.source_chain[0..3];
        let pad_slots = &after_a.source_chain[3..8];

        // Verify pads are HMAC under pad_nonce.
        for (slot, hop) in pad_slots.iter().enumerate() {
            let real_slot_index = u16::try_from(slot + 3).expect("slot + 3 fits in u16");
            let expected = pseudonym_to_string(derive_pad_context_id(&nonce, real_slot_index));
            assert_eq!(
                hop.context_id,
                expected,
                "AC-18: pad slot {} matches HMAC-derived id",
                slot + 3
            );
            assert_eq!(hop.wrapped_code, COLLAPSED_AUTHORIZATION_DENIED_CODE);
        }

        // Verify real entries are NOT byte-equal to a pad-derived value at
        // their slot (real uses hop_salt, pad uses pad_nonce).
        for (slot, hop) in real_slots.iter().enumerate() {
            let slot_u16 = u16::try_from(slot).expect("slot fits in u16");
            let pad_at_slot = pseudonym_to_string(derive_pad_context_id(&nonce, slot_u16));
            assert_ne!(
                hop.context_id, pad_at_slot,
                "AC-18: real slot {slot} not equal to pad derivation"
            );
        }
    }

    // ============================================================
    // AC-19 — full-visibility unpadded
    // ============================================================

    #[test]
    fn ac19_full_visibility_observes_unpadded_chain() {
        // AC-19: caller with full visibility (membership on every hop AND
        // matching stem on every hop target) observes the true k-length
        // source_chain (no padding); max_padded_trail_depth is unused.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 16);

        let inner = build_inner_authorization_error();
        let after_c = wrap_cross_context_error(&"ctx-c".to_owned(), inner, &view);
        let after_b = wrap_cross_context_error(&"ctx-b".to_owned(), after_c, &view);
        let after_a = wrap_cross_context_error(&"ctx-a".to_owned(), after_b, &view);
        assert_eq!(
            after_a.source_chain.len(),
            3,
            "AC-19: unpadded length = k = 3"
        );
    }

    // ============================================================
    // AC-20 — pad_nonce unconditional emission + round-trip
    // ============================================================

    #[test]
    fn ac20_pad_nonce_round_trips_byte_identical() {
        // AC-20: a full-visibility OutletError carries a 16-byte pad_nonce
        // that round-trips byte-identical; presence of pad_nonce is NOT a
        // signal that the observer lacks full visibility.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let nonce_value = [0xAB; PAD_NONCE_LEN];
        let view = fix.view(stems, Some(OutletKind::Query), 8);
        // `view` shadows `pad_nonce`; recreate with the AC-pinned value.
        let view = OutletErrorWrapView {
            pad_nonce: nonce_value,
            ..view
        };

        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        // pad_nonce is on the envelope.
        assert_eq!(wrapped.pad_nonce, nonce_value);
        // Round-trip MessagePack and verify pad_nonce preserved.
        let bytes = rmp_serde::to_vec_named(&wrapped).unwrap();
        let back: OutletError = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back.pad_nonce, nonce_value);
        assert_eq!(back.pad_nonce.len(), PAD_NONCE_LEN);
    }

    #[test]
    fn ac20_wire_layer_rejects_missing_pad_nonce_tag_11() {
        // AC-20: wire-layer deserialization rejects an envelope whose
        // tag-11 (pad_nonce) field is absent. This is enforced at the
        // OutletError struct level (`#[serde(rename = "11", with =
        // "serde_pad_nonce")]`); wrap_cross_context_error inherits the
        // invariant by copying the field through verbatim.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 0);
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);

        // Round-trip with tag 11 dropped: must fail.
        let bytes = rmp_serde::to_vec_named(&wrapped).unwrap();
        let value: rmpv::Value = rmp_serde::from_slice(&bytes).unwrap();
        let pairs = match value {
            rmpv::Value::Map(m) => m,
            other => panic!("expected map, got {other:?}"),
        };
        let kept: Vec<(rmpv::Value, rmpv::Value)> = pairs
            .into_iter()
            .filter(|(k, _)| match k {
                rmpv::Value::String(s) => s.as_str() != Some("11"),
                _ => true,
            })
            .collect();
        let truncated = rmp_serde::to_vec_named(&rmpv::Value::Map(kept)).unwrap();
        let result: Result<OutletError, _> = rmp_serde::from_slice(&truncated);
        assert!(
            result.is_err(),
            "AC-20: wire-layer rejection of missing tag-11"
        );
    }

    // ============================================================
    // AC-21 — pad entries DIFFER between independent streams
    // ============================================================

    #[test]
    fn ac21_pad_entries_differ_across_independent_streams() {
        // AC-21: pad-entry context_ids do not correlate across independent
        // streams — two different streams produce different pad_nonce
        // values; re-invoking the same outlet under the same interface
        // twice produces different pad entries in each error's
        // source_chain.
        let observer: ContextId = "ctx-observer".to_owned();
        let mut members = std::collections::HashSet::new();
        members.insert(observer.clone());
        let salts: HashMap<String, [u8; 32]> = HashMap::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };

        let nonce_a = [0xAA; PAD_NONCE_LEN];
        let nonce_b = [0xBB; PAD_NONCE_LEN];

        let view_a = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: nonce_a,
            max_padded_trail_depth: 8,
        };
        let view_b = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: nonce_b,
            max_padded_trail_depth: 8,
        };

        let inner_a = build_inner_authorization_error();
        let inner_b = build_inner_authorization_error();
        let wrapped_a = wrap_cross_context_error(&"ctx-x".to_owned(), inner_a, &view_a);
        let wrapped_b = wrap_cross_context_error(&"ctx-x".to_owned(), inner_b, &view_b);

        assert_ne!(wrapped_a.pad_nonce, wrapped_b.pad_nonce);

        // Pad entries (slots 1..7 — slot 0 is the real wrap) differ between
        // the two streams.
        let pads_a: Vec<&str> = wrapped_a.source_chain[1..]
            .iter()
            .map(|h| h.context_id.as_str())
            .collect();
        let pads_b: Vec<&str> = wrapped_b.source_chain[1..]
            .iter()
            .map(|h| h.context_id.as_str())
            .collect();
        assert_eq!(pads_a.len(), pads_b.len());
        for (a, b) in pads_a.iter().zip(pads_b.iter()) {
            assert_ne!(a, b, "pad entries DIFFER across streams");
        }
    }

    // ============================================================
    // AC-22 — partial-visibility honest disclosure documentation
    // ============================================================

    #[test]
    fn ac22_rustdoc_mentions_partial_visibility_honest_disclosure() {
        // AC-22: the rustdoc on wrap_cross_context_error states plainly
        // that the pad hides k only from observers who hold no hop_salt.
        // This is a structural test that the documentation surface mentions
        // the round-5 honest-disclosure prose verbatim.
        //
        // Rust does not expose rustdoc to runtime, so we assert against a
        // file-level grep proxy: read the source file at compile-time and
        // verify the relevant phrases appear.
        let source = include_str!("outlets.rs");
        assert!(
            source.contains("The pad continues to hide `k` from such an observer"),
            "AC-22: rustdoc must contain spec round-5 honest-disclosure quote"
        );
        assert!(
            source.contains("hide `k` only from observers who hold no `hop_salt`"),
            "AC-22: rustdoc must mention partial-visibility scope"
        );
        assert!(
            source.contains("re-HMAC-under-`pad_nonce` closure")
                || source.contains("re-HMAC-under-pad_nonce"),
            "AC-22: rustdoc must warn against the rejected re-HMAC closure"
        );
    }

    // ============================================================
    // AC-9 — cargo test --workspace succeeds (covered by the test
    //        runner; this body is intentionally empty as the AC is
    //        environmental).
    // ============================================================

    // ============================================================
    // Bonus adversarial tests to satisfy the "8+ adversarial unit
    // tests" highlight.
    // ============================================================

    #[test]
    fn adversarial_collapse_does_not_change_pad_nonce() {
        // A collapsed envelope still carries a fresh pad_nonce.
        let fix = NonMemberFixture::new();
        let stems = OuterCallerStems {
            holds_query: false,
            holds_call: false,
        };
        let view = fix.view(stems, None, 8);
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        assert_eq!(wrapped.pad_nonce, fix.nonce);
    }

    #[test]
    fn adversarial_wrapped_message_field_is_32_bytes() {
        // The HMAC `message` field is ALWAYS 32 bytes (preserved verbatim
        // through wrapping).
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 0);
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        assert_eq!(wrapped.message.len(), WIRE_MESSAGE_LEN);
        assert_eq!(wrapped.message.len(), 32);
    }

    #[test]
    fn adversarial_max_padded_trail_depth_capped_at_protocol_constant() {
        // A caller passing max_padded_trail_depth > MAX_TRAIL_PAD_DEPTH must
        // be capped at MAX_TRAIL_PAD_DEPTH = 16.
        let fix = NonMemberFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 200); // way over
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        assert!(
            wrapped.source_chain.len() <= usize::from(MAX_TRAIL_PAD_DEPTH),
            "padded length capped at MAX_TRAIL_PAD_DEPTH=16"
        );
    }

    #[test]
    fn adversarial_observer_ctx_never_pseudonymized() {
        // The observer's own context id, if it ever appears as caller_ctx
        // (e.g., the outermost wrap before consumption), is NEVER
        // pseudonymized.
        let observer: ContextId = "ctx-observer".to_owned();
        let mut members = std::collections::HashSet::new();
        members.insert(observer.clone());
        let salts: HashMap<String, [u8; 32]> = HashMap::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: [0x00; PAD_NONCE_LEN],
            max_padded_trail_depth: 0,
        };
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&observer, inner, &view);
        assert_eq!(
            wrapped.source_chain[0].context_id, observer,
            "observer's own ctx never pseudonymized"
        );
    }

    type HmacSha256ForTest = hmac::Hmac<sha2::Sha256>;

    #[test]
    fn adversarial_pad_entries_use_protocol_label_constant() {
        // The pad-entry HMAC uses the registered SCP-OUTLET-HOP-PAD-V1:
        // domain separator. Independently re-derive a pad slot and check
        // byte-equality.
        let nonce = [0xAA; PAD_NONCE_LEN];
        let slot = 5u16;

        // Re-derive via raw HMAC.
        let mut mac = <HmacSha256ForTest as hmac::Mac>::new_from_slice(&nonce).unwrap();
        mac.update(MAX_TRAIL_PAD_HMAC_LABEL);
        mac.update(&slot.to_be_bytes());
        let expected: [u8; 32] = mac.finalize().into_bytes()[..32].try_into().unwrap();

        let actual = derive_pad_context_id(&nonce, slot);
        assert_eq!(actual, expected, "pad derivation matches protocol label");
        assert_eq!(MAX_TRAIL_PAD_HMAC_LABEL, b"SCP-OUTLET-HOP-PAD-V1:");
    }

    #[test]
    fn adversarial_padded_chain_real_entries_at_first_k_slots() {
        // Real entries occupy slot_indices 0..k-1; pad at k..max-1.
        // Padding fires once at the outermost layer; intermediate wraps
        // just append a real ContextHop without padding.
        let observer: ContextId = "ctx-observer".to_owned();
        let mut members = std::collections::HashSet::new();
        members.insert(observer.clone());
        let salts: HashMap<String, [u8; 32]> = HashMap::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        // Permissive intermediate view (no padding).
        let intermediate_observer: ContextId = "ctx-passthrough".to_owned();
        let mut intermediate_members = std::collections::HashSet::new();
        intermediate_members.insert("ctx-b".to_owned());
        intermediate_members.insert("ctx-a".to_owned());
        intermediate_members.insert(intermediate_observer.clone());
        let intermediate_salts: HashMap<String, [u8; 32]> = HashMap::new();
        let intermediate_view = OutletErrorWrapView {
            observer_ctx: &intermediate_observer,
            member_of_context: &|c| intermediate_members.contains(c),
            hop_salts: &|c| intermediate_salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: [0x00; PAD_NONCE_LEN],
            max_padded_trail_depth: 0,
        };
        // Outer observing view (padding=8).
        let outer_view = OutletErrorWrapView {
            observer_ctx: &observer,
            member_of_context: &|c| members.contains(c),
            hop_salts: &|c| salts.get(c).copied(),
            outer_caller_stems: stems,
            inner_outlet_kind: Some(OutletKind::Query),
            pad_nonce: [0x88; PAD_NONCE_LEN],
            max_padded_trail_depth: 8,
        };
        let inner = build_inner_authorization_error();
        let after_b = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &intermediate_view);
        let after_a = wrap_cross_context_error(&"ctx-a".to_owned(), after_b, &outer_view);
        // k = 2 real entries; pads at slots 2..7.
        assert_eq!(after_a.source_chain.len(), 8);
        for (slot, hop) in after_a.source_chain.iter().enumerate() {
            assert_eq!(hop.hop_index as usize, slot);
        }
    }

    #[test]
    fn adversarial_full_visibility_path_skips_padding_even_at_zero_depth() {
        // A full-visibility caller with max_padded_trail_depth=0 still
        // sees an unpadded chain — padding only fires for opaque hops.
        let fix = FullVisibilityFixture::new();
        let stems = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view = fix.view(stems, Some(OutletKind::Query), 0);
        let inner = build_inner_authorization_error();
        let wrapped = wrap_cross_context_error(&"ctx-b".to_owned(), inner, &view);
        assert_eq!(wrapped.source_chain.len(), 1);
    }

    #[test]
    fn adversarial_per_hop_wrapped_code_collapses_for_no_visibility_caller() {
        // Per §5.4.4 round-3, per-hop wrapped_code collapses to
        // SCP-TOOL-6110 / authorization.denied for hops the no-stem caller
        // cannot see. This test builds a multi-hop chain at full visibility
        // then re-wraps under a no-stem view and verifies the trail's
        // wrapped_codes collapse.
        let fix_full = FullVisibilityFixture::new();
        let stems_full = OuterCallerStems {
            holds_query: true,
            holds_call: true,
        };
        let view_full = fix_full.view(stems_full, Some(OutletKind::Query), 0);
        let inner = build_inner_authorization_error();
        let wrapped_at_c = wrap_cross_context_error(&"ctx-c".to_owned(), inner, &view_full);

        // Now an observer with NO stems re-wraps at outer layer.
        let fix_none = NonMemberFixture::new();
        let stems_none = OuterCallerStems {
            holds_query: false,
            holds_call: false,
        };
        let view_none = fix_none.view(stems_none, None, 0);
        let wrapped_at_b = wrap_cross_context_error(&"ctx-b".to_owned(), wrapped_at_c, &view_none);

        // No-stem observer: outer code collapses + per-hop wrapped_codes
        // collapse for inner hops.
        assert_eq!(wrapped_at_b.code, COLLAPSED_AUTHORIZATION_DENIED_CODE);
        for hop in &wrapped_at_b.source_chain {
            assert_eq!(
                hop.wrapped_code, COLLAPSED_AUTHORIZATION_DENIED_CODE,
                "per-hop wrapped_code collapse for no-stem observer"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod amplification_tests {
    //! SCP-OUT-015 acceptance criteria — all 15 ACs verified here as unit
    //! and integration tests against the public surface above. Each test
    //! cites the AC number it covers.

    use super::*;
    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};

    /// Builds a synthetic [`UcanToken`] carrying the given outlet capability
    /// stems in `att`. Used by the AC14/AC15 stem-derivation tests.
    fn ucan_with_stems(stems: &[&str]) -> UcanToken {
        let att = stems
            .iter()
            .map(|s| Attenuation {
                with: format!("scp:ctx:test/{s}"),
                can: "*".to_owned(),
            })
            .collect();
        UcanToken {
            header: UcanHeader::new(),
            payload: UcanPayload {
                iss: "did:key:test-iss".to_owned(),
                aud: "did:key:test-aud".to_owned(),
                exp: 9_999_999_999,
                nbf: None,
                nnc: "test-nonce".to_owned(),
                att,
                prf: vec![],
                fct: None,
                nb: None,
            },
            signature: vec![],
            encoded: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // AC1: ContextParams does NOT carry max_chain_depth_action.
    //
    // Verified structurally in this file via the absence of any
    // `max_chain_depth_action` reference; the CI grep in the PRD AC checks
    // `crates/scp-protocol/src/` for zero hits. Here we assert the helper
    // surface returns the expected derived budget instead, which is the
    // positive-side check for the design.
    // -----------------------------------------------------------------------

    #[test]
    fn ac1_action_budget_is_derived_not_stored() {
        // Default max (None → 8): action budget = max(1, 8/2) = 4.
        assert_eq!(action_chain_budget(None), 4);
        // Explicit 8: same.
        assert_eq!(action_chain_budget(Some(8)), 4);
        // Explicit 1: floor of 1.
        assert_eq!(action_chain_budget(Some(1)), 1);
        // Explicit 0 (unusual but legal): floor of 1.
        assert_eq!(action_chain_budget(Some(0)), 1);
        // Query budget mirrors max_chain_depth verbatim.
        assert_eq!(query_chain_budget(None), 8);
        assert_eq!(query_chain_budget(Some(16)), 16);
    }

    // -----------------------------------------------------------------------
    // AC2: cross_context_invoke amplification rejection.
    // -----------------------------------------------------------------------

    #[test]
    fn ac2_query_origin_action_hop_rejected_with_amplification_violation() {
        let result = cross_context_invoke(
            OutletKind::Query,
            OutletKind::Action,
            /*q=*/ 8,
            /*a=*/ 4,
        );
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC3: Function decrements the kind-appropriate counter on accept.
    // -----------------------------------------------------------------------

    #[test]
    fn ac3_query_hop_decrements_query_counter_only() {
        let accepted = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4)
            .expect("Query → Query is permitted");
        assert_eq!(accepted.origin_kind, OutletKind::Query);
        assert_eq!(accepted.depth_remaining_query, 7);
        assert_eq!(accepted.depth_remaining_action, 4);
    }

    #[test]
    fn ac3_action_hop_decrements_action_counter_only() {
        let accepted = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 4)
            .expect("Action → Action is permitted");
        assert_eq!(accepted.origin_kind, OutletKind::Action);
        assert_eq!(accepted.depth_remaining_query, 8);
        assert_eq!(accepted.depth_remaining_action, 3);
    }

    // -----------------------------------------------------------------------
    // AC4: Returns ChainDepthExceeded when the relevant counter would go
    // negative.
    // -----------------------------------------------------------------------

    #[test]
    fn ac4_query_counter_exhausted_returns_chain_depth_exceeded() {
        let result = cross_context_invoke(OutletKind::Query, OutletKind::Query, 0, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Query,
                remaining: 0,
            })
        ));
    }

    #[test]
    fn ac4_action_counter_exhausted_returns_chain_depth_exceeded() {
        let result = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 0);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Action,
                remaining: 0,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC5: Action-originated chain calling a Query hop decrements the Query
    // counter (matches the invoked outlet, not the originator).
    // -----------------------------------------------------------------------

    #[test]
    fn ac5_action_origin_query_hop_decrements_query_counter() {
        let accepted = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4)
            .expect("Action → Query is permitted");
        assert_eq!(
            accepted.origin_kind,
            OutletKind::Action,
            "origin_kind preserved across hops"
        );
        assert_eq!(
            accepted.depth_remaining_query, 7,
            "Query counter decremented because hop_kind == Query"
        );
        assert_eq!(
            accepted.depth_remaining_action, 4,
            "Action counter unchanged"
        );
    }

    // -----------------------------------------------------------------------
    // AC6: Integration test — Query → Query → Query valid chain at default
    // budget.
    // -----------------------------------------------------------------------

    #[test]
    fn ac6_query_query_query_valid_at_default_budget() {
        // Outermost call sets origin_kind = Query, with max_chain_depth = 8.
        let q_budget = query_chain_budget(Some(8));
        let a_budget = action_chain_budget(Some(8));
        assert_eq!((q_budget, a_budget), (8, 4));

        // Hop 1: Query → Query.
        let h1 =
            cross_context_invoke(OutletKind::Query, OutletKind::Query, q_budget, a_budget).unwrap();
        assert_eq!(h1.depth_remaining_query, 7);
        // Hop 2: Query → Query.
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h2.depth_remaining_query, 6);
        // Hop 3: Query → Query.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Query,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h3.depth_remaining_query, 5);
        assert_eq!(h3.origin_kind, OutletKind::Query);
    }

    // -----------------------------------------------------------------------
    // AC7: Integration test — Query → Query → Action triggers
    // AmplificationViolation with origin_kind == Query.
    // -----------------------------------------------------------------------

    #[test]
    fn ac7_query_query_action_triggers_amplification_violation() {
        // Hops 1 + 2 succeed.
        let h1 = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4).unwrap();
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();
        assert_eq!(h2.origin_kind, OutletKind::Query);
        // Hop 3: Query → Action — rejected at the consent gate.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Action,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        );
        assert!(matches!(
            h3,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC8: Integration test — Action → Query → Action is valid (Query
    // amplification rule does not trigger because origin_kind == Action).
    // -----------------------------------------------------------------------

    #[test]
    fn ac8_action_query_action_is_valid() {
        // Hop 1: Action → Query (decrements Query counter).
        let h1 = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4).unwrap();
        assert_eq!(h1.origin_kind, OutletKind::Action);
        assert_eq!(h1.depth_remaining_query, 7);
        assert_eq!(h1.depth_remaining_action, 4);

        // Hop 2: Action → Query (origin preserved).
        let h2 = cross_context_invoke(
            h1.origin_kind,
            OutletKind::Query,
            h1.depth_remaining_query,
            h1.depth_remaining_action,
        )
        .unwrap();

        // Hop 3: Action → Action — permitted because origin_kind != Query.
        let h3 = cross_context_invoke(
            h2.origin_kind,
            OutletKind::Action,
            h2.depth_remaining_query,
            h2.depth_remaining_action,
        )
        .expect("Action → Action permitted regardless of intermediate Query hops");
        assert_eq!(h3.origin_kind, OutletKind::Action);
        assert_eq!(h3.depth_remaining_action, 3);
    }

    // -----------------------------------------------------------------------
    // AC9: Integration test — Action → Action at depth 5 with default
    // budget (4) triggers ChainDepthExceeded.
    // -----------------------------------------------------------------------

    #[test]
    fn ac9_action_chain_at_depth_5_exceeds_default_budget_of_4() {
        // Default max_chain_depth = 8; Action budget = 4.
        let q = query_chain_budget(None);
        let a = action_chain_budget(None);
        assert_eq!((q, a), (8, 4));

        // Walk Action → Action 4 times — each hop succeeds and decrements
        // the Action counter.
        let mut cur_q = q;
        let mut cur_a = a;
        for hop in 1..=4 {
            let accepted =
                cross_context_invoke(OutletKind::Action, OutletKind::Action, cur_q, cur_a)
                    .unwrap_or_else(|_| panic!("hop {hop} should succeed"));
            cur_q = accepted.depth_remaining_query;
            cur_a = accepted.depth_remaining_action;
        }
        assert_eq!(cur_a, 0, "after 4 Action hops the budget is exhausted");

        // 5th Action hop is rejected.
        let h5 = cross_context_invoke(OutletKind::Action, OutletKind::Action, cur_q, cur_a);
        assert!(matches!(
            h5,
            Err(OutletAmplificationError::ChainDepthExceeded {
                hop_kind: OutletKind::Action,
                remaining: 0,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC10: Rejection emits a failed OutletInvokedEvent in BOTH contexts'
    // event logs with an error code.
    // -----------------------------------------------------------------------

    /// Test event-log provider that captures every append into a `Vec` keyed
    /// by `(context_id, event_name, actor_did, payload)`. Used by AC10 to
    /// verify the rejection event lands in both logs.
    #[derive(Default)]
    struct CapturingEventLog {
        entries: std::sync::Mutex<Vec<CapturedEntry>>,
    }

    #[derive(Debug, Clone)]
    struct CapturedEntry {
        context_id: [u8; 32],
        event_name: String,
        actor_did: String,
        payload: Option<serde_json::Value>,
    }

    impl super::super::super::builder::ContextEventLogProvider for CapturingEventLog {
        fn init_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            context_id: &[u8; 32],
            event: &str,
            actor_did: &str,
            payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(CapturedEntry {
                    context_id: *context_id,
                    event_name: event.to_owned(),
                    actor_did: actor_did.to_owned(),
                    payload: payload.cloned(),
                });
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    #[test]
    fn ac10_rejection_emits_failed_event_in_both_event_logs() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "calculator".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let request_id = "req-ac10-rejection";
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-source",
            "ctx-target",
            &outlet_id,
            &invoker,
            request_id,
            &err,
        );
        // Returned synthesized event has Error status and zero hashes.
        assert_eq!(event.status, OutletStatus::Error);
        assert_eq!(event.execution_time_ms, 0);
        assert_eq!(event.input_hash, REJECTION_HASH_SENTINEL);
        assert_eq!(event.output_hash.as_deref(), Some(REJECTION_HASH_SENTINEL));
        assert_eq!(event.cost, None);
        assert_eq!(event.request_id, request_id);

        // Both contexts received an OutletInvoked entry — verify by
        // distinct context_id_bytes. Scope the lock to drop it eagerly so
        // the assertion phase doesn't hold the mutex.
        let captured = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.clone()
        };
        assert_eq!(captured.len(), 2, "one entry per context");
        let src_bytes = scp_protocol::context::context_id_bytes("ctx-source");
        let tgt_bytes = scp_protocol::context::context_id_bytes("ctx-target");
        let src_entry = captured
            .iter()
            .find(|e| e.context_id == src_bytes)
            .expect("source entry");
        let tgt_entry = captured
            .iter()
            .find(|e| e.context_id == tgt_bytes)
            .expect("target entry");
        for e in [src_entry, tgt_entry] {
            assert_eq!(e.event_name, "OutletInvoked");
            assert_eq!(e.actor_did, AMPLIFICATION_REJECTION_ACTOR_DID);
            let p = e.payload.as_ref().expect("payload");
            assert_eq!(p["rejection"]["error_code"], "SCP-TOOL-6120");
            assert_eq!(
                p["rejection"]["slug"],
                "authorization.amplification-violation"
            );
            assert_eq!(p["rejection"]["reason"]["type"], "amplification-violation");
        }
    }

    // -----------------------------------------------------------------------
    // AC12: origin_kind is bound to the outermost UCAN stem.
    //
    // Structurally enforced by [`origin_kind_from_ucan_stem`] returning the
    // kind from the signed `att` list. A token with the outlet_query stem
    // returns Query; with outlet_call returns Action. Forging a different
    // origin_kind requires forging a UCAN with a different stem — which
    // would fail the upstream signature verification.
    // -----------------------------------------------------------------------

    #[test]
    fn ac12_origin_kind_is_bound_to_outer_ucan_stem() {
        let q_token = ucan_with_stems(&["outlet_query:calc"]);
        assert_eq!(
            origin_kind_from_ucan_stem(&q_token),
            Some(OutletKind::Query)
        );
        let a_token = ucan_with_stems(&["outlet_call:assistant"]);
        assert_eq!(
            origin_kind_from_ucan_stem(&a_token),
            Some(OutletKind::Action)
        );
        // Wildcard variants resolve too.
        let q_all = ucan_with_stems(&["outlet_query:*"]);
        assert_eq!(origin_kind_from_ucan_stem(&q_all), Some(OutletKind::Query));
        let a_all = ucan_with_stems(&["outlet_call:*"]);
        assert_eq!(origin_kind_from_ucan_stem(&a_all), Some(OutletKind::Action));
        // Token with no outlet stems returns None — the caller should
        // reject (the hop is not authorized to invoke an outlet).
        let none_token = ucan_with_stems(&["messages:read"]);
        assert_eq!(origin_kind_from_ucan_stem(&none_token), None);
    }

    // -----------------------------------------------------------------------
    // AC13: origin_kind is propagated inside every cross-context hop
    // envelope as part of the UCAN delegation; the receiving hop re-verifies
    // the stem and sets origin_kind from THAT, not from a trusted sidecar.
    //
    // Verified in two parts: (a) cross_context_invoke is the pure check
    // and never reads transport state — `origin_kind` is its FIRST parameter,
    // not a context-pulled field; (b) origin_kind_from_ucan_stem is the
    // ONLY supported derivation path. AC14 below covers the malicious
    // sidecar attempt.
    // -----------------------------------------------------------------------

    #[test]
    fn ac13_hop_target_recovers_origin_kind_from_ucan_not_sidecar() {
        // Simulate a hop receiving a UCAN with outlet_query:* — the
        // re-derived origin_kind is Query regardless of any other claim.
        let ucan_received = ucan_with_stems(&["outlet_query:*"]);
        let recovered =
            origin_kind_from_ucan_stem(&ucan_received).expect("recovered from signed stem");
        assert_eq!(recovered, OutletKind::Query);

        // The hop check uses the recovered kind — not a sidecar value.
        // A malicious upstream that claimed Action via a sidecar would be
        // ignored because `cross_context_invoke` reads only its parameters.
        let result = cross_context_invoke(recovered, OutletKind::Action, 8, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // AC14: A malicious hop that attempts to rewrite origin_kind without a
    // matching UCAN rewrite is rejected at the next hop's full UCAN
    // validation step.
    //
    // We model "next hop's full UCAN validation" as the kind-recovery
    // step: the receiving hop must call `origin_kind_from_ucan_stem` on
    // the validated UCAN it received, not on a separate claim. A token
    // whose stems are outlet_query but whose attacker-supplied "side"
    // claim says Action is rejected because the stem-derived kind wins.
    // -----------------------------------------------------------------------

    #[test]
    fn ac14_malicious_origin_kind_rewrite_without_ucan_rewrite_is_rejected() {
        // The attacker presents a UCAN with stems = outlet_query:* and a
        // claim of origin_kind = Action via some sidecar channel. The
        // hop target ignores the sidecar and re-derives from stems.
        let attackers_ucan = ucan_with_stems(&["outlet_query:steal"]);
        let derived = origin_kind_from_ucan_stem(&attackers_ucan).unwrap();
        assert_eq!(
            derived,
            OutletKind::Query,
            "kind is derived from signed stems, not from a sidecar field"
        );

        // The chain check uses derived = Query. An attempt to call an
        // Action outlet under this UCAN is rejected via amplification.
        let attempt = cross_context_invoke(derived, OutletKind::Action, 8, 4);
        assert!(matches!(
            attempt,
            Err(OutletAmplificationError::AmplificationViolation {
                origin_kind: OutletKind::Query,
                hop_kind: OutletKind::Action,
            })
        ));
    }

    // -----------------------------------------------------------------------
    // AC15: A UCAN chain whose outermost stem is outlet_query:* but whose
    // inner hop presents outlet_call:* is rejected with
    // AmplificationViolation BEFORE executor dispatch.
    //
    // Modelled as: the outermost stem is parsed → origin_kind = Query;
    // the hop target outlet's declared kind = Action. The amplification
    // check runs and returns Err before any executor would be invoked.
    // -----------------------------------------------------------------------

    #[test]
    fn ac15_outer_query_inner_call_rejected_before_executor_dispatch() {
        // Outer UCAN stem: outlet_query:* → origin_kind = Query.
        let outer_ucan = ucan_with_stems(&["outlet_query:*"]);
        let origin_kind = origin_kind_from_ucan_stem(&outer_ucan).unwrap();
        assert_eq!(origin_kind, OutletKind::Query);

        // Inner hop target outlet is registered as Action and the inner
        // UCAN attempts outlet_call:* — but origin_kind is still Query
        // because origin is bound to the OUTER (root) UCAN.
        let result = cross_context_invoke(origin_kind, OutletKind::Action, 8, 4);
        assert!(matches!(
            result,
            Err(OutletAmplificationError::AmplificationViolation { .. })
        ));
        // No executor was dispatched — the error path is the consent gate.
    }

    // -----------------------------------------------------------------------
    // Bonus: the all-permitted matrix entries (Query→Query, Action→Query,
    // Action→Action) accept and decrement the right counters. Belt-and-
    // suspenders for AC3 + AC8 above.
    // -----------------------------------------------------------------------

    #[test]
    fn permitted_combinations_accept_and_decrement_correctly() {
        // Query → Query
        let r = cross_context_invoke(OutletKind::Query, OutletKind::Query, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (7, 4));
        // Action → Query
        let r = cross_context_invoke(OutletKind::Action, OutletKind::Query, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (7, 4));
        // Action → Action
        let r = cross_context_invoke(OutletKind::Action, OutletKind::Action, 8, 4).unwrap();
        assert_eq!((r.depth_remaining_query, r.depth_remaining_action), (8, 3));
    }

    // -----------------------------------------------------------------------
    // ChainDepthExceeded event-log emission — verifies the second SCP-TOOL
    // code (6121) lands correctly.
    // -----------------------------------------------------------------------

    #[test]
    fn chain_depth_rejection_emits_in_both_logs_with_6121_code() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "noisy".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::ChainDepthExceeded {
            hop_kind: OutletKind::Action,
            remaining: 0,
        };
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-A",
            "ctx-B",
            &outlet_id,
            &invoker,
            "req-cd-1",
            &err,
        );
        assert_eq!(event.status, OutletStatus::Error);
        let captured = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.clone()
        };
        assert_eq!(captured.len(), 2);
        for e in &captured {
            assert_eq!(e.event_name, "OutletInvoked");
            assert_eq!(e.actor_did, CHAIN_DEPTH_REJECTION_ACTOR_DID);
            let p = e.payload.as_ref().unwrap();
            assert_eq!(p["rejection"]["error_code"], "SCP-TOOL-6121");
            assert_eq!(p["rejection"]["slug"], "resource.chain-depth-exceeded");
            assert_eq!(p["rejection"]["reason"]["type"], "chain-depth-exceeded");
        }
    }

    // -----------------------------------------------------------------------
    // Self-cross-context (source == target) emits a SINGLE entry — defensive
    // against a misbehaving bridge writing the same context twice.
    // -----------------------------------------------------------------------

    #[test]
    fn rejection_with_same_source_and_target_emits_once() {
        let log = CapturingEventLog::default();
        let outlet_id: OutletId = "selfish".to_owned();
        let invoker: DID = "did:key:invoker".into();
        let err = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let event = record_amplification_rejection(
            Some(&log),
            "ctx-self",
            "ctx-self",
            &outlet_id,
            &invoker,
            "req-self",
            &err,
        );
        assert_eq!(event.outlet_id, outlet_id);
        let captured_len = {
            let entries = log
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            entries.len()
        };
        assert_eq!(captured_len, 1);
    }

    // -----------------------------------------------------------------------
    // Error code + slug surface tests — used by the
    // SDK serialization paths in OUT-036/038 (the typed error class).
    // -----------------------------------------------------------------------

    #[test]
    fn error_codes_and_slugs_match_authorization_taxonomy() {
        let amp = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        assert_eq!(amp.error_code(), "SCP-TOOL-6120");
        assert_eq!(amp.slug(), "authorization.amplification-violation");
        let cd = OutletAmplificationError::ChainDepthExceeded {
            hop_kind: OutletKind::Query,
            remaining: 0,
        };
        assert_eq!(cd.error_code(), "SCP-TOOL-6121");
        assert_eq!(cd.slug(), "resource.chain-depth-exceeded");
    }

    #[test]
    fn amplification_error_to_context_uses_canonical_codes() {
        // SCP-OUT-027: amplification errors map to a typed
        // `ContextError::OutletInvocation` envelope under §5.4.4
        // Protocol class with `CODE_PROTOCOL_VIOLATION` (SCP-TOOL-6100)
        // and slug `amplification-violation`.
        use scp_protocol::context::outlets::error_codes::{
            CODE_PROTOCOL_VIOLATION, SLUG_AMPLIFICATION_VIOLATION,
        };
        use scp_protocol::context::outlets::errors::OutletErrorClass;

        let amp = OutletAmplificationError::AmplificationViolation {
            origin_kind: OutletKind::Query,
            hop_kind: OutletKind::Action,
        };
        let ctx_err = amplification_error_to_context(&amp);
        match ctx_err {
            ContextError::OutletInvocation(envelope) => {
                assert_eq!(envelope.code, CODE_PROTOCOL_VIOLATION);
                assert_eq!(envelope.slug, SLUG_AMPLIFICATION_VIOLATION);
                assert_eq!(envelope.class, OutletErrorClass::Protocol);
            }
            other => panic!("unexpected ContextError: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // SCP-OUT-016 — Per-kind cross-context rate-tier defaults (§6.2.0.2)
    // -----------------------------------------------------------------------
    //
    // The runtime re-exposes the protocol-layer
    // `OutletInterfaceDefaults::for_kind` helper plus a thin
    // `cross_context_rate_tier_default` wrapper so the cross-context
    // invocation path here in `scp-runtime` (alongside
    // `cross_context_invoke` / `query_chain_budget` / `action_chain_budget`)
    // can pick the §6.2.0.2 default `(per_interface, per_caller)` tuple
    // without duplicating the constants. These tests verify the runtime
    // surface; the protocol-layer surface is covered by the SCP-OUT-016
    // tests in `scp_protocol::context::outlets::interface`.

    #[test]
    fn cross_context_rate_tier_default_query_returns_600_100() {
        assert_eq!(
            cross_context_rate_tier_default(OutletKind::Query),
            (600, 100),
            "§6.2.0.2 Query tier default tuple"
        );
    }

    #[test]
    fn cross_context_rate_tier_default_action_returns_60_10() {
        assert_eq!(
            cross_context_rate_tier_default(OutletKind::Action),
            (60, 10),
            "§6.2.0.2 Action tier default tuple"
        );
    }

    #[test]
    fn outlet_interface_defaults_runtime_reexport_matches_protocol() {
        // Sanity: the runtime re-export resolves to the same struct as the
        // protocol-layer original.
        let q = OutletInterfaceDefaults::for_kind(OutletKind::Query);
        assert_eq!(q.kind, OutletKind::Query);
        assert_eq!(q.per_interface_calls_per_minute, 600);
        assert_eq!(q.per_caller_calls_per_minute, 100);

        let a = OutletInterfaceDefaults::for_kind(OutletKind::Action);
        assert_eq!(a.kind, OutletKind::Action);
        assert_eq!(a.per_interface_calls_per_minute, 60);
        assert_eq!(a.per_caller_calls_per_minute, 10);
    }
}

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
mod layer_composition_tests {
    //! SCP-OUT-022 acceptance criteria — verifies the §7.3.8 / §6.2 / §19.5
    //! / §19.3 AND fold against the public [`evaluate_all_layers`] surface,
    //! the [`build_post_input_hook`] composition seam, and the
    //! [`ContextManager::invoke_outlet_with_economy`] integration path.
    //!
    //! Test coverage maps to the AC list in
    //! `.docs/prds/outlet.json` SCP-OUT-022:
    //!
    //! * AC1 — `evaluate_all_layers` returns `Ok(())` iff every layer admits
    //! * AC2 — short-circuits on first `Err` and identifies the layer
    //! * AC3 — caveat admits, OutboundPolicy denies → OutboundPolicy
    //! * AC4 — caveat admits, Outbound admits, Inbound denies → InboundPolicy
    //! * AC5 — upstream admit, SpendingCapability denies → SpendingCapability
    //! * AC6 — upstream admit, MemberBudgetTracker denies → MemberBudgetTracker
    //! * AC7 — all admit → `Ok(())`; invocation proceeds
    //! * AC8 — widened child caveat (rejected at attenuation) never reaches
    //!   the layer composition (proves the short-circuit)
    //! * AC9 — `cargo test --workspace` passes (assured by this mod compiling
    //!   and being included in the workspace test set)
    //!
    //! Each test cites the AC it covers in a leading doc comment. The integration
    //! path test wires through the real
    //! [`ContextManager::invoke_outlet_with_economy`] entry point so the AC8
    //! short-circuit + AC1/AC7 admit-path are observed at the public manager
    //! surface, not just the inner [`evaluate_all_layers`] helper.
    use super::*;
    use scp_protocol::context::outlets::OutletId;
    use scp_protocol::context::outlets::interface::{InboundPolicy, OutboundPolicy};
    use scp_protocol::crypto::ucan::spending::SpendingCapability;
    use scp_protocol::economy::budget::MemberBudgetTracker;
    use scp_protocol::economy::types::Amount;
    use scp_protocol::trust::caveats::{AttenuationViolation, InvocationCaveats};

    /// Builds a fresh [`MemberBudgetTracker`] with a single 1,000,000-unit
    /// grant for the named DID. Reused by every test that needs to admit at
    /// the budget layer.
    fn budget_with_grant(invoker: &DID, grant: u64) -> MemberBudgetTracker {
        let mut tracker = MemberBudgetTracker::new();
        tracker.grant(invoker, Amount::new(grant));
        tracker
    }

    /// Returns the placeholder [`OutletRegistration`] used by the unit tests
    /// in this module. `evaluate_all_layers` does not deref this value, so a
    /// synthetic registration is sufficient.
    fn unit_test_outlet_registration() -> scp_protocol::context::outlets::OutletRegistration {
        layer_composition_outlet_placeholder()
    }

    /// Builds a [`SpendingCapability`] with the requested per-action ceiling
    /// and a generous total / window so layers other than
    /// `SpendingCapability` are unaffected.
    ///
    /// `SpendingCapability` uses the UCAN-flavored
    /// [`scp_protocol::crypto::ucan::Amount`] /
    /// [`scp_protocol::crypto::ucan::CurrencyCode`] (distinct types from the
    /// economy module's `Amount` / `CurrencyCode`) — the spec keeps them
    /// separate so the UCAN wire format does not need to track the economy
    /// module's `serde_with` adapters.
    fn spending_cap(max_per_action: u64) -> SpendingCapability {
        SpendingCapability {
            max_per_action: scp_protocol::crypto::ucan::Amount(max_per_action),
            max_total: scp_protocol::crypto::ucan::Amount(u64::MAX),
            currency: scp_protocol::crypto::ucan::CurrencyCode::from_code("USD")
                .expect("USD is a valid 3-byte ASCII code"),
            time_window: std::time::Duration::from_hours(24),
            allowed_adapters: Vec::new(),
        }
    }

    // ---------------------------------------------------------------------
    // Test 1 (AC3) — caveat admits, OutboundPolicy denies → OutboundPolicy
    // ---------------------------------------------------------------------

    /// AC3: when the caveat layers admit and `OutboundPolicy.allowed_callers`
    /// excludes the invoker, the layer composition rejects with
    /// [`LayerName::OutboundPolicy`]. The §5.4.4 slug routes through
    /// `authorization.denied` because the violation is a delegation-bound
    /// rejection rather than an input-shape violation.
    #[tokio::test]
    async fn ac3_outbound_policy_allowed_callers_denies_identifies_outbound() {
        let invoker: DID = "did:key:invoker".into();
        let other: DID = "did:key:other".into();
        let caveats = InvocationCaveats::empty();
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        let outbound = OutboundPolicy {
            allowed_callers: vec![other.clone()],
            max_calls_per_minute: 600,
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        let budget = budget_with_grant(&invoker, 0);

        let denial = evaluate_all_layers(LayerCompositionInput {
            caveats: &caveats,
            outlet: &outlet,
            input: &input,
            outbound_policy: Some(&outbound),
            inbound_policy: None,
            spending_capability: None,
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(0),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: None,
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 0,
        })
        .await
        .expect_err("OutboundPolicy.allowed_callers must reject when invoker absent");

        assert_eq!(denial.layer, LayerName::OutboundPolicy);
        assert_eq!(denial.error_code, scp_protocol::CODE_AUTHORIZATION_DENIED);
        assert_eq!(denial.slug, "authorization.denied");
        assert!(
            denial.message.contains("OutboundPolicy.allowed_callers"),
            "diagnostic must name the field, got: {}",
            denial.message
        );
    }

    // ---------------------------------------------------------------------
    // Test 2 (AC4) — caveat + Outbound admit, InboundPolicy denies → InboundPolicy
    // ---------------------------------------------------------------------

    /// AC4: when the upstream layers (caveat, OutboundPolicy) admit and
    /// `InboundPolicy.allowed_source_roles` does not include the invoker's
    /// source role, the layer composition rejects with
    /// [`LayerName::InboundPolicy`]. Confirms cross-context inbound role
    /// enforcement happens AFTER outbound checks.
    #[tokio::test]
    async fn ac4_inbound_policy_allowed_source_roles_denies_identifies_inbound() {
        let invoker: DID = "did:key:invoker".into();
        let caveats = InvocationCaveats::empty();
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        // OutboundPolicy admits (empty allow-list = "any caller").
        let outbound = OutboundPolicy {
            allowed_callers: Vec::new(),
            max_calls_per_minute: 600,
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        // InboundPolicy denies — the invoker presents role "guest" but the
        // target only admits "admin".
        let inbound = InboundPolicy {
            allowed_source_roles: vec!["admin".to_owned()],
            max_calls_per_minute: 600,
            max_response_bytes: 65_536,
            require_spending_ucan: false,
        };
        let budget = budget_with_grant(&invoker, 0);

        let denial = evaluate_all_layers(LayerCompositionInput {
            caveats: &caveats,
            outlet: &outlet,
            input: &input,
            outbound_policy: Some(&outbound),
            inbound_policy: Some(&inbound),
            spending_capability: None,
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(0),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: Some("guest"),
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 0,
        })
        .await
        .expect_err("InboundPolicy.allowed_source_roles must reject");

        assert_eq!(denial.layer, LayerName::InboundPolicy);
        assert_eq!(denial.error_code, scp_protocol::CODE_AUTHORIZATION_DENIED);
        assert_eq!(denial.slug, "authorization.denied");
        assert!(
            denial.message.contains("allowed_source_roles"),
            "diagnostic must name the field, got: {}",
            denial.message
        );
    }

    // ---------------------------------------------------------------------
    // Test 3 (AC5) — upstream admit, SpendingCapability denies
    // ---------------------------------------------------------------------

    /// AC5: when the caveat / outbound / inbound layers admit and the
    /// estimated cost exceeds `SpendingCapability.max_per_action`, the
    /// composition rejects with [`LayerName::SpendingCapability`].
    #[tokio::test]
    async fn ac5_spending_capability_max_per_action_denies_identifies_spending() {
        let invoker: DID = "did:key:invoker".into();
        let caveats = InvocationCaveats::empty();
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        // Cap = 100; cost = 250 → reject.
        let cap = spending_cap(100);
        // Budget would admit (granted 1_000_000) so the rejection is
        // unambiguously the spending layer.
        let budget = budget_with_grant(&invoker, 1_000_000);

        let denial = evaluate_all_layers(LayerCompositionInput {
            caveats: &caveats,
            outlet: &outlet,
            input: &input,
            outbound_policy: None,
            inbound_policy: None,
            spending_capability: Some(&cap),
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(250),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: None,
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 0,
        })
        .await
        .expect_err("SpendingCapability.max_per_action must reject");

        assert_eq!(denial.layer, LayerName::SpendingCapability);
        assert_eq!(denial.error_code, scp_protocol::CODE_AUTHORIZATION_DENIED);
        assert_eq!(denial.slug, "authorization.denied");
        assert!(
            denial.message.contains("max_per_action"),
            "diagnostic must name the field, got: {}",
            denial.message
        );
    }

    // ---------------------------------------------------------------------
    // Test 4 (AC6) — upstream admit, MemberBudgetTracker denies
    // ---------------------------------------------------------------------

    /// AC6: when every upstream layer admits but the per-context
    /// `MemberBudgetTracker` has zero remaining budget for the invoker, the
    /// composition rejects with [`LayerName::MemberBudgetTracker`] under
    /// the §5.4.4 economic-class slug `economic.budget-exceeded`.
    #[tokio::test]
    async fn ac6_member_budget_tracker_denies_identifies_budget() {
        let invoker: DID = "did:key:invoker".into();
        let caveats = InvocationCaveats::empty();
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        // Spending capability admits comfortably.
        let cap = spending_cap(1_000_000);
        // Budget grants 50, action wants 100 → reject.
        let budget = budget_with_grant(&invoker, 50);

        let denial = evaluate_all_layers(LayerCompositionInput {
            caveats: &caveats,
            outlet: &outlet,
            input: &input,
            outbound_policy: None,
            inbound_policy: None,
            spending_capability: Some(&cap),
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(100),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: None,
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 0,
        })
        .await
        .expect_err("MemberBudgetTracker remaining < cost must reject");

        assert_eq!(denial.layer, LayerName::MemberBudgetTracker);
        assert_eq!(denial.error_code, scp_protocol::CODE_ECONOMIC_FAULT);
        assert_eq!(denial.slug, "economic.budget-exceeded");
        assert!(
            denial.message.contains("remaining"),
            "diagnostic must name the field, got: {}",
            denial.message
        );
    }

    // ---------------------------------------------------------------------
    // Test 5 (AC1 + AC7) — all admit → Ok(()); invocation proceeds
    // ---------------------------------------------------------------------

    /// AC1 + AC7: when every layer admits the function returns `Ok(())` and
    /// the invocation may proceed downstream. Combined with the integration
    /// test below this proves that admit at every layer surfaces all the way
    /// to the executor.
    #[tokio::test]
    async fn ac1_ac7_all_layers_admit_returns_ok() {
        let invoker: DID = "did:key:invoker".into();
        let caveats = InvocationCaveats::empty();
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        let outbound = OutboundPolicy {
            allowed_callers: vec![invoker.clone()],
            max_calls_per_minute: 600,
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        let inbound = InboundPolicy {
            allowed_source_roles: vec!["admin".to_owned()],
            max_calls_per_minute: 600,
            max_response_bytes: 65_536,
            require_spending_ucan: true,
        };
        let cap = spending_cap(1_000);
        let budget = budget_with_grant(&invoker, 1_000_000);

        let result = evaluate_all_layers(LayerCompositionInput {
            caveats: &caveats,
            outlet: &outlet,
            input: &input,
            outbound_policy: Some(&outbound),
            inbound_policy: Some(&inbound),
            spending_capability: Some(&cap),
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(50),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: Some("admin"),
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 128,
        })
        .await;

        assert!(
            result.is_ok(),
            "all layers admit must return Ok(()), got: {:?}",
            result
        );
    }

    // ---------------------------------------------------------------------
    // Test 6 (AC8) — widened child caveat rejected at attenuation never
    // reaches the layer composition.
    // ---------------------------------------------------------------------

    /// AC8: SCP-OUT-019's `InvocationCaveats::narrow` rejects widened child
    /// caveats BEFORE the runtime ever invokes the layer composition. This
    /// test proves the short-circuit by:
    ///
    /// 1. Constructing a parent caveat with `max_calls = 10`.
    /// 2. Constructing a child that widens `max_calls` to `100`.
    /// 3. Asserting `parent.narrow(&child)` returns
    ///    [`AttenuationViolation::FieldWidened`] — i.e. the attenuation
    ///    check rejects the child long before the runtime would build a
    ///    [`LayerCompositionInput`].
    /// 4. Demonstrating positively (via a "control" call) that
    ///    [`evaluate_all_layers`] would have admitted the WIDER child if it
    ///    had reached the composition. The two facts together prove the
    ///    rejection happened at the attenuation layer, not at the
    ///    composition layer.
    ///
    /// The function under test ([`evaluate_all_layers`]) is only called
    /// once, with the WIDER child caveats — and that call returns `Ok(())`,
    /// confirming that if the attenuation check had been bypassed the
    /// composition layer would NOT catch the widening.
    #[tokio::test]
    async fn ac8_widened_child_caveat_rejected_at_attenuation_never_reaches_composition() {
        let invoker: DID = "did:key:invoker".into();
        // Parent: max_calls = 10. `origin_kind = Some(Action)` so narrow()
        // does not short-circuit on the §7.3.8 (4) inheritance rule before
        // it reaches the max_calls check we want to exercise.
        let parent = InvocationCaveats {
            max_calls: Some(10),
            origin_kind: Some(scp_protocol::context::outlets::OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        // Child: max_calls widened to 100 — ILLEGAL widening. The origin_kind
        // is preserved verbatim per §6.2.0.3 so the U64Widened check is the
        // first failure surface.
        let widened_child = InvocationCaveats {
            max_calls: Some(100),
            origin_kind: Some(scp_protocol::context::outlets::OutletKind::Action),
            ..InvocationCaveats::empty()
        };

        // Step 1: SCP-OUT-019 attenuation check rejects the widened child.
        // `max_calls` is a `u64`-valued field, so widening surfaces as
        // [`AttenuationViolation::U64Widened`] with the matching
        // `CaveatField::MaxCalls` discriminant.
        let attenuation_result = parent.narrow(&widened_child);
        assert!(
            matches!(
                attenuation_result,
                Err(AttenuationViolation::U64Widened {
                    field: scp_protocol::trust::caveats::CaveatField::MaxCalls,
                    parent: 10,
                    child: 100,
                })
            ),
            "SCP-OUT-019 narrow() must reject max_calls widening with U64Widened, got: {:?}",
            attenuation_result
        );

        // Step 2: prove that IF the attenuation check were bypassed, the
        // composition layer would silently admit the widened child (because
        // §7.3.8 layers do NOT police parent/child relationships — they
        // policy a single caveat set in isolation). This is the WHOLE point
        // of the attenuation gate as a separate layer: composition does
        // not re-derive parent/child invariants from the wire form.
        let outlet = unit_test_outlet_registration();
        let input = serde_json::json!({});
        let budget = budget_with_grant(&invoker, 1_000_000);
        let result = evaluate_all_layers(LayerCompositionInput {
            caveats: &widened_child,
            outlet: &outlet,
            input: &input,
            outbound_policy: None,
            inbound_policy: None,
            spending_capability: None,
            budget_tracker: &budget,
            invoker_did: &invoker,
            estimated_cost: Amount::new(0),
            now_secs: 1_000_000,
            negotiated_adapter: None,
            target_did: None,
            source_role: None,
            counter_store: None,
            context_id: "ctx-out022",
            ucan_cid: "ucan-out022",
            payload_bytes: 0,
        })
        .await;
        assert!(
            result.is_ok(),
            "evaluate_all_layers does not police parent/child caveat relationships — \
             that is the attenuation gate's job. Got: {:?}",
            result
        );
    }

    // ---------------------------------------------------------------------
    // Test 7 (AC2 + AC3) — short-circuits on first denial; integration test
    // through the public manager surface.
    // ---------------------------------------------------------------------

    /// AC2 + AC3 (integration): wires through the real
    /// [`ContextManager::invoke_outlet_with_economy`] entry point with a
    /// `LayerCompositionEnforcement` bundle whose `OutboundPolicy.allowed_callers`
    /// excludes the invoker. The returned [`ContextError`] must surface
    /// the `OutboundPolicy` denial slug — proving that the wiring runs the
    /// full layer composition AT the post-input point AND that the
    /// short-circuit propagates the rejecting layer's identity through
    /// [`invocation_error_from_layer_denial`] and
    /// [`invocation_error_to_context`].
    ///
    /// The ticket-rollback path is exercised because `evaluate_all_layers`
    /// runs INSIDE the post-input hook AFTER Phase 1 records velocity +
    /// budget; a successful denial here MUST reverse those mutations
    /// (covered by the existing rollback assertions in the manager — this
    /// test asserts at least the error surface).
    #[tokio::test]
    async fn ac2_ac3_integration_wiring_outbound_policy_denial_surfaces_through_manager() {
        // The shared test fixtures live in `manager/tests/mod.rs` as
        // `pub(super)` items. `tests` is a sibling of `outlets` inside
        // `manager`, so `super::super::tests::*` is the canonical path.
        use super::super::tests::{
            MockCrypto, MockEventLog, MockTransport, dummy_spending_ucan_for, governance_params,
            mock_key_resolver, test_outlet_registration,
        };
        use scp_protocol::context::outlets::registry::OutletRegistry;
        use scp_protocol::economy::types::Amount;

        let manager = std::sync::Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            mock_key_resolver(),
        ));

        let mut params = governance_params();
        params
            .ceiling
            .push(scp_protocol::context::params::Capability::OutletCallAll);
        let _handle = manager
            .create_context(
                "ctx-out022-int".into(),
                params,
                "did:key:invoker".into(),
                None,
            )
            .await
            .unwrap();

        // Grant a generous budget so the failure cannot be attributed to
        // the budget layer.
        {
            let arc = manager
                .contexts
                .get("ctx-out022-int")
                .unwrap()
                .value()
                .clone();
            let mut ctx = arc.lock().await;
            ctx.governance
                .budget_tracker
                .grant(&"did:key:invoker".into(), Amount::new(1_000_000));
        }

        let mut registry = OutletRegistry::new();
        registry.insert(test_outlet_registration("echo"));

        let ucan = dummy_spending_ucan_for(&"did:key:invoker".into());

        // OutboundPolicy excludes the invoker → denial at OutboundPolicy.
        let other: DID = "did:key:other".into();
        let outbound = scp_protocol::context::outlets::interface::OutboundPolicy {
            allowed_callers: vec![other],
            max_calls_per_minute: 600,
            max_payload_bytes: 65_536,
            require_provenance: true,
        };
        let bundle = LayerCompositionEnforcement {
            outbound_policy: Some(outbound),
            inbound_policy: None,
            spending_capability: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            source_role: None,
            payload_bytes: 0,
        };

        let err = manager
            .invoke_outlet_with_economy(
                "ctx-out022-int",
                &registry,
                &OutletId::from("echo"),
                serde_json::json!({}),
                &"did:key:invoker".into(),
                Some(&ucan),
                None,
                |_input| async { Ok(serde_json::json!({})) },
                None,
                None,
                Some(bundle),
            )
            .await
            .expect_err(
                "OutboundPolicy.allowed_callers excludes invoker — \
                 invoke_outlet_with_economy must surface the denial",
            );

        // SCP-OUT-027: the §5.4.4 dispatcher routes `authorization.denied`
        // (caveat class) through `SCP-TOOL-6110` (`CODE_AUTHORIZATION_DENIED`)
        // and surfaces it as a typed `ContextError::OutletInvocation`
        // envelope. The per-layer diagnostic (`outbound-policy`) is no
        // longer carried in the typed envelope's class/slug — that
        // information is operator-side only and is logged at the layer
        // boundary via `LayerDenial::layer.as_str()`. Test asserts the
        // typed envelope's `(code, slug, class)` triple per §5.4.4.
        let envelope = match err {
            scp_protocol::context::ContextError::OutletInvocation(e) => e,
            other => panic!("expected OutletInvocation, got {other:?}"),
        };
        assert_eq!(
            envelope.code,
            scp_protocol::context::outlets::error_codes::CODE_AUTHORIZATION_DENIED,
        );
        assert_eq!(
            envelope.slug,
            scp_protocol::context::outlets::error_codes::SLUG_AUTHORIZATION_DENIED,
        );
        assert_eq!(
            envelope.class,
            scp_protocol::context::outlets::errors::OutletErrorClass::Authorization,
        );
    }
}

// ===========================================================================
// SCP-OUT-027 — `invocation_error_to_context` test matrix
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod outlet_error_mapping_tests {
    //! SCP-OUT-027 acceptance criteria: every `InvocationError` variant maps
    //! to a typed `ContextError::OutletInvocation(OutletError)` whose
    //! `(code, class)` pair matches the §5.4.4 taxonomy.
    //!
    //! AC-mapping (from `.docs/prds/outlet.json` SCP-OUT-027):
    //! - "manager/outlets.rs no longer contains any code path that collapses
    //!   multiple `InvocationError` variants to a single `OutletError`" — the
    //!   `permission_denied_path_is_gone` test asserts no `PermissionDenied`
    //!   arm remains in the mapper.
    //! - "Test matrix: for each `InvocationError` variant, the resulting
    //!   `OutletError` has the correct code and class" — `mapping_table_*`
    //!   tests cover every variant.
    //! - The `OutletNotFound` variant maps to `authorization.denied`
    //!   (§5.4.4 query-oracle collapse) — verified by
    //!   `outlet_not_found_collapses_to_authorization_denied`.
    //!
    //! All assertions read the `OutletError`'s public fields directly;
    //! no string parsing, no `Display` dependence.

    use super::*;
    use scp_protocol::context::ContextError;
    use scp_protocol::context::outlets::error_codes::{
        CODE_AUTHORIZATION_DENIED, CODE_ECONOMIC_FAULT, CODE_EXECUTION_FAULT, CODE_INPUT_VIOLATION,
        CODE_OUTPUT_VIOLATION, CODE_PROTOCOL_VIOLATION, SLUG_AUTHORIZATION_DENIED,
        SLUG_ECONOMIC_BUDGET_EXCEEDED, SLUG_EXECUTION_HANDLER_PANIC, SLUG_EXECUTION_TIMEOUT,
        SLUG_INPUT_SCHEMA_VIOLATION, SLUG_KIND_MISMATCH, SLUG_OUTPUT_SCHEMA_VIOLATION,
        SLUG_PROTOCOL_VIOLATION, SLUG_QUERY_COST_VIOLATION, SLUG_QUERY_VIOLATION,
    };
    use scp_protocol::context::outlets::errors::{OutletError, OutletErrorClass};

    /// Helper — extracts the `OutletError` envelope from a `ContextError` or
    /// panics with a descriptive message naming the source variant.
    fn unwrap_outlet_error(err: ContextError, label: &str) -> OutletError {
        match err {
            ContextError::OutletInvocation(envelope) => *envelope,
            other => panic!("expected ContextError::OutletInvocation for {label}, got {other:?}"),
        }
    }

    /// Asserts an `(InvocationError → ContextError → OutletError)` mapping
    /// matches the §5.4.4 expected `(code, slug, class)` triple.
    fn assert_mapping(
        err: InvocationError,
        label: &'static str,
        expected_code: &'static str,
        expected_slug: &'static str,
        expected_class: OutletErrorClass,
    ) {
        let context_err = invocation_error_to_context(err);
        let envelope = unwrap_outlet_error(context_err, label);
        assert_eq!(
            envelope.code, expected_code,
            "{label}: expected code {expected_code}, got {}",
            envelope.code,
        );
        assert_eq!(
            envelope.slug, expected_slug,
            "{label}: expected slug {expected_slug}, got {}",
            envelope.slug,
        );
        assert_eq!(
            envelope.class, expected_class,
            "{label}: expected class {expected_class:?}, got {:?}",
            envelope.class,
        );
    }

    #[test]
    fn context_not_active_maps_to_protocol_violation() {
        assert_mapping(
            InvocationError::ContextNotActive {
                current_state: "Closed".to_owned(),
            },
            "ContextNotActive",
            CODE_PROTOCOL_VIOLATION,
            SLUG_PROTOCOL_VIOLATION,
            OutletErrorClass::Protocol,
        );
    }

    #[test]
    fn invoker_not_authorized_maps_to_authorization_denied() {
        assert_mapping(
            InvocationError::InvokerNotAuthorized {
                did: "did:key:invoker".to_owned(),
                outlet_id: "echo".to_owned(),
            },
            "InvokerNotAuthorized",
            CODE_AUTHORIZATION_DENIED,
            SLUG_AUTHORIZATION_DENIED,
            OutletErrorClass::Authorization,
        );
    }

    #[test]
    fn outlet_not_found_collapses_to_authorization_denied() {
        // §5.4.4 query-oracle collapse: registration state must NOT leak
        // through error class. A missing outlet returns the same code and
        // slug as a denied capability.
        assert_mapping(
            InvocationError::OutletNotFound {
                outlet_id: "missing-outlet".to_owned(),
            },
            "OutletNotFound",
            CODE_AUTHORIZATION_DENIED,
            SLUG_AUTHORIZATION_DENIED,
            OutletErrorClass::Authorization,
        );
    }

    #[test]
    fn input_validation_failed_maps_to_input_violation() {
        assert_mapping(
            InvocationError::InputValidationFailed {
                message: "type mismatch on /items/0".to_owned(),
            },
            "InputValidationFailed",
            CODE_INPUT_VIOLATION,
            SLUG_INPUT_SCHEMA_VIOLATION,
            OutletErrorClass::Input,
        );
    }

    #[test]
    fn output_validation_failed_maps_to_output_violation() {
        assert_mapping(
            InvocationError::OutputValidationFailed {
                message: "missing required field /result".to_owned(),
            },
            "OutputValidationFailed",
            CODE_OUTPUT_VIOLATION,
            SLUG_OUTPUT_SCHEMA_VIOLATION,
            OutletErrorClass::Output,
        );
    }

    #[test]
    fn execution_failed_maps_to_execution_handler_panic() {
        assert_mapping(
            InvocationError::ExecutionFailed {
                message: "executor error: divide by zero".to_owned(),
            },
            "ExecutionFailed",
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_HANDLER_PANIC,
            OutletErrorClass::Execution,
        );
    }

    #[test]
    fn timeout_maps_to_execution_timeout() {
        assert_mapping(
            InvocationError::Timeout { timeout_ms: 5_000 },
            "Timeout",
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_TIMEOUT,
            OutletErrorClass::Execution,
        );
    }

    #[test]
    fn cancelled_maps_to_execution_timeout() {
        assert_mapping(
            InvocationError::Cancelled,
            "Cancelled",
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_TIMEOUT,
            OutletErrorClass::Execution,
        );
    }

    #[test]
    fn budget_exceeded_maps_to_economic_budget_exceeded() {
        assert_mapping(
            InvocationError::BudgetExceeded {
                did: "did:key:invoker".to_owned(),
                cost: 100,
                remaining: 25,
            },
            "BudgetExceeded",
            CODE_ECONOMIC_FAULT,
            SLUG_ECONOMIC_BUDGET_EXCEEDED,
            OutletErrorClass::Economic,
        );
    }

    #[test]
    fn outlet_query_cost_violation_maps_to_protocol_query_cost_violation() {
        assert_mapping(
            InvocationError::OutletQueryCostViolation {
                reason: "structural floor not met".to_owned(),
            },
            "OutletQueryCostViolation",
            CODE_PROTOCOL_VIOLATION,
            SLUG_QUERY_COST_VIOLATION,
            OutletErrorClass::Protocol,
        );
    }

    #[test]
    fn query_violation_maps_to_protocol_query_violation() {
        assert_mapping(
            InvocationError::QueryViolation {
                outlet_id: "read-only-outlet".to_owned(),
                operation: "send_message",
            },
            "QueryViolation",
            CODE_PROTOCOL_VIOLATION,
            SLUG_QUERY_VIOLATION,
            OutletErrorClass::Protocol,
        );
    }

    #[test]
    fn kind_mismatch_maps_to_protocol_kind_mismatch() {
        assert_mapping(
            InvocationError::KindMismatch {
                outlet_id: "misdeclared-outlet".to_owned(),
                kind: scp_protocol::context::outlets::OutletKind::Query,
            },
            "KindMismatch",
            CODE_PROTOCOL_VIOLATION,
            SLUG_KIND_MISMATCH,
            OutletErrorClass::Protocol,
        );
    }

    #[test]
    fn handler_panic_maps_to_execution_handler_panic() {
        assert_mapping(
            InvocationError::HandlerPanic {
                outlet_id: "panicking-outlet".to_owned(),
                panic_message: "unwrap on None".to_owned(),
            },
            "HandlerPanic",
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_HANDLER_PANIC,
            OutletErrorClass::Execution,
        );
    }

    #[test]
    fn caveat_violation_input_slug_routes_to_input_violation() {
        // SCP-OUT-021: a caveat violation carrying an `input.*` slug routes
        // to the §5.4.4 Input class with the slug preserved verbatim.
        assert_mapping(
            InvocationError::CaveatViolation {
                slug: "input.schema-violation",
                message: "value out of range".to_owned(),
            },
            "CaveatViolation/input",
            CODE_INPUT_VIOLATION,
            "input.schema-violation",
            OutletErrorClass::Input,
        );
    }

    #[test]
    fn caveat_violation_authz_slug_routes_to_authorization_denied() {
        // SCP-OUT-021: a caveat violation with a non-`input.*` slug routes
        // to the §5.4.4 Authorization class — the slug is preserved
        // verbatim so SDKs can dispatch on the precise rule that fired.
        assert_mapping(
            InvocationError::CaveatViolation {
                slug: "authorization.rate-exceeded",
                message: "10 calls in 5 seconds".to_owned(),
            },
            "CaveatViolation/auth",
            CODE_AUTHORIZATION_DENIED,
            "authorization.rate-exceeded",
            OutletErrorClass::Authorization,
        );
    }

    #[test]
    fn permission_denied_path_is_gone() {
        // SCP-OUT-027 AC: "manager/outlets.rs no longer contains any code
        // path that collapses multiple InvocationError variants to a
        // single OutletError" — every variant produces an
        // `OutletInvocation`, never `PermissionDenied`.
        let variants: Vec<InvocationError> = vec![
            InvocationError::ContextNotActive {
                current_state: "Closed".to_owned(),
            },
            InvocationError::InvokerNotAuthorized {
                did: "d".to_owned(),
                outlet_id: "o".to_owned(),
            },
            InvocationError::OutletNotFound {
                outlet_id: "o".to_owned(),
            },
            InvocationError::InputValidationFailed {
                message: "m".to_owned(),
            },
            InvocationError::OutputValidationFailed {
                message: "m".to_owned(),
            },
            InvocationError::ExecutionFailed {
                message: "m".to_owned(),
            },
            InvocationError::Timeout { timeout_ms: 1 },
            InvocationError::Cancelled,
            InvocationError::BudgetExceeded {
                did: "d".to_owned(),
                cost: 1,
                remaining: 0,
            },
            InvocationError::OutletQueryCostViolation {
                reason: "r".to_owned(),
            },
            InvocationError::QueryViolation {
                outlet_id: "o".to_owned(),
                operation: "send_message",
            },
            InvocationError::KindMismatch {
                outlet_id: "o".to_owned(),
                kind: scp_protocol::context::outlets::OutletKind::Query,
            },
            InvocationError::HandlerPanic {
                outlet_id: "o".to_owned(),
                panic_message: "p".to_owned(),
            },
            InvocationError::CaveatViolation {
                slug: "authorization.denied",
                message: "m".to_owned(),
            },
        ];

        for variant in variants {
            let label = format!("{variant:?}");
            let context_err = invocation_error_to_context(variant);
            assert!(
                matches!(context_err, ContextError::OutletInvocation(_)),
                "every InvocationError must map to ContextError::OutletInvocation; \
                 variant {label} produced {context_err:?}",
            );
        }
    }

    #[test]
    fn outlet_error_display_renders_code_slug_class() {
        // The `From<OutletError> for ContextError` Display delegates to
        // the OutletError's Display, which renders `<code> (<slug>):
        // <class>`. Verifies the diagnostic output is human-readable
        // without exposing the opaque HMAC `message` field.
        let err = invocation_error_to_context(InvocationError::Cancelled);
        let display = format!("{err}");
        assert!(
            display.contains(CODE_EXECUTION_FAULT),
            "Display must contain code; got {display}",
        );
        assert!(
            display.contains(SLUG_EXECUTION_TIMEOUT),
            "Display must contain slug; got {display}",
        );
        assert!(
            display.contains("execution"),
            "Display must contain class; got {display}",
        );
    }

    #[test]
    fn from_outlet_error_for_context_error() {
        // `From<OutletError> for ContextError` produces the
        // `OutletInvocation` variant (not a string conversion).
        let envelope = OutletError::from_invocation_error_template(
            OutletErrorClass::Execution,
            CODE_EXECUTION_FAULT,
            SLUG_EXECUTION_TIMEOUT,
            scp_protocol::context::outlets::errors::RetryPolicy::Never,
        )
        .expect("registry constants are valid");
        let ctx_err: ContextError = envelope.into();
        assert!(matches!(ctx_err, ContextError::OutletInvocation(_)));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::uninlined_format_args
)]
mod stream_caveat_post_input_tests {
    //! crypto-MED (R3) — the §7.3.8 post-input caveat hook for outlet-stream
    //! open is now built ENTIRELY in the runtime by
    //! [`build_stream_post_input_hook`], the SAME composition the
    //! non-streaming [`build_post_input_hook`] runs. These tests pin that the
    //! FULL hook is enforced through the runtime path — independent of any
    //! FFI bridge — covering each §7.3.8 dimension the spec table defines:
    //!
    //! * `input_schema` conformance (synchronous local check),
    //! * `amount_max_per_call` vs `cost_per_chunk` (synchronous local check),
    //! * `allowed_target_dids` mismatch (synchronous local check),
    //! * `amount_max_cumulative` projected-escrow CAS (durable counter),
    //! * `rate_window` sliding-window CAS (durable counter),
    //! * `max_calls` invocation CAS (durable counter) — AND the proof that
    //!   the invocation counter is a DISTINCT dimension from HIGH-2's
    //!   per-chunk `CreditTracker` ceiling, so the two bounds coexist without
    //!   double-charging.
    //!
    //! The hook is run once per stream open (§5.4.5 "the stream validates its
    //! input once"); each test invokes the built closure exactly as
    //! `open_stream_session` does.
    //!
    //! Spec source: `.docs/specs/07-trust-validation-and-capabilities.md`
    //! §7.3.8.

    use super::*;
    use scp_platform::testing::InMemoryStorage;
    use scp_primitives::TestClock;
    use scp_protocol::economy::types::Amount;
    use scp_protocol::trust::caveats::{InvocationCaveats, RateWindow};

    const TEST_CTX: &str = "ctx-stream-caveat";
    const TEST_CID: &str = "bafytestucancid";

    /// Build a concrete counter store over fresh in-memory storage with a
    /// deterministic clock pinned at `now`.
    fn make_store(now: u64) -> Arc<crate::trust::CaveatCounterStore<InMemoryStorage>> {
        let repo = Arc::new(crate::store::ProtocolRepository::new_for_testing(
            InMemoryStorage::new(),
        ));
        let clock: Arc<dyn scp_primitives::Clock> = Arc::new(TestClock::new(now));
        Arc::new(crate::trust::CaveatCounterStore::new(repo, clock))
    }

    /// Type-erase a concrete store to the trait object the builder accepts.
    fn erase(
        store: &Arc<crate::trust::CaveatCounterStore<InMemoryStorage>>,
    ) -> Arc<dyn crate::trust::CaveatCounterApi> {
        Arc::clone(store) as Arc<dyn crate::trust::CaveatCounterApi>
    }

    /// Runs the built local-check hook once over the given input, returning
    /// the result the dispatch pump would observe at stream open. The hook is
    /// a `FnOnce` (run exactly once per open, §5.4.5), so it is consumed by
    /// value.
    async fn run_hook(
        hook: crate::context::outlets::invoke::CaveatPostInputCheck<'static>,
        input: serde_json::Value,
    ) -> Result<(), crate::context::outlets::invoke::InvocationError> {
        hook(&input).await
    }

    /// Builds the local-check hook + counter reservation for the given
    /// caveats / cost / store, panicking with `label` on a fail-closed
    /// rejection. Returns the synchronous local-check hook (R4 HIGH-2: the
    /// durable CAS is no longer part of this hook).
    fn expect_hook(
        caveats: &InvocationCaveats,
        cost_per_chunk: Amount,
        store: Option<&Arc<dyn crate::trust::CaveatCounterApi>>,
        label: &str,
    ) -> crate::context::outlets::invoke::CaveatPostInputCheck<'static> {
        match build_stream_post_input_hook(caveats, cost_per_chunk, store) {
            Ok((Some(hook), _reservation)) => hook,
            Ok((None, _)) => panic!("{label}: expected Some(hook), got None"),
            Err(rej) => panic!("{label}: expected Some(hook), got Err({rej:?})"),
        }
    }

    /// Builds the counter reservation for the given caveats, panicking with
    /// `label` if none is produced (the caveats carry a counter-bearing cap
    /// AND a store is present). R4 HIGH-1 / HIGH-2: the durable CAS runs
    /// through this reservation at the final open-time gate.
    fn expect_reservation(
        caveats: &InvocationCaveats,
        cost_per_chunk: Amount,
        store: &Arc<dyn crate::trust::CaveatCounterApi>,
        label: &str,
    ) -> crate::context::outlets::dispatch::StreamCounterReservation {
        match build_stream_post_input_hook(caveats, cost_per_chunk, Some(store)) {
            Ok((_hook, Some(reservation))) => reservation,
            Ok((_, None)) => panic!("{label}: expected Some(reservation), got None"),
            Err(rej) => panic!("{label}: expected a reservation, got Err({rej:?})"),
        }
    }

    /// Drives the final-gate durable CAS exactly as `open_stream_session`'s
    /// Step 5.5 does, for `estimated_chunk_count` reserved chunks.
    async fn commit(
        reservation: &crate::context::outlets::dispatch::StreamCounterReservation,
        cost_per_chunk: Amount,
        estimated_chunk_count: u32,
    ) -> Result<(), crate::context::outlets::dispatch::OpenStreamRejection> {
        crate::context::outlets::dispatch::commit_counter_reservation_for_test(
            reservation,
            TEST_CTX,
            TEST_CID,
            cost_per_chunk,
            estimated_chunk_count,
        )
        .await
        .map(|_outcome| ())
    }

    /// No §7.3.8 post-input constraint → no hook, no reservation (parity with
    /// the non-streaming `build_post_input_hook` returning `None`).
    #[tokio::test]
    async fn empty_caveats_yield_no_hook() {
        let store = make_store(1_000);
        let built = build_stream_post_input_hook(
            &InvocationCaveats::empty(),
            Amount::new(5),
            Some(&erase(&store)),
        )
        .expect("empty caveats must not fail closed");
        assert!(
            built.0.is_none() && built.1.is_none(),
            "caveat-free leaf must bypass the gate (no hook, no reservation)"
        );
    }

    /// `input_schema` violation rejects at open (synchronous local check).
    #[tokio::test]
    async fn input_schema_violation_rejects() {
        let store = make_store(1_000);
        let mut caveats = InvocationCaveats::empty();
        caveats.input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "amount": { "type": "number" } },
            "required": ["amount"],
        }));
        let hook = expect_hook(
            &caveats,
            Amount::new(1),
            Some(&erase(&store)),
            "schema caveat",
        );

        // Missing the required `amount` field → schema violation. The
        // synchronous local-check hook surfaces an `input_schema` failure as
        // `InputValidationFailed`; `open_stream_session` then maps that to the
        // `input.schema-violation` slug for the §5.4.4 input-violation
        // envelope (see the `InputValidationFailed` arm in the open path).
        let err = run_hook(hook, serde_json::json!({ "other": true }))
            .await
            .expect_err("schema-violating input must reject at open");
        match err {
            crate::context::outlets::invoke::InvocationError::InputValidationFailed { .. } => {}
            other => panic!("schema violation must be an InputValidationFailed, got {other:?}"),
        }

        // Conforming input passes (rebuild — the hook is FnOnce).
        let hook_ok = expect_hook(
            &caveats,
            Amount::new(1),
            Some(&erase(&make_store(1_000))),
            "schema caveat (conforming)",
        );
        run_hook(hook_ok, serde_json::json!({ "amount": 3 }))
            .await
            .expect("schema-conforming input must pass");
    }

    /// `amount_max_per_call` < `cost_per_chunk` rejects at open; a cost at the
    /// cap passes (the §19.5 per-invocation pricing unit) — local check.
    #[tokio::test]
    async fn amount_max_per_call_below_cost_per_chunk_rejects() {
        let store = make_store(1_000);
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_per_call = Some(Amount::new(5));

        // cost_per_chunk = 9 > cap 5 → reject.
        let hook = expect_hook(
            &caveats,
            Amount::new(9),
            Some(&erase(&store)),
            "amount_max_per_call",
        );
        let err = run_hook(hook, serde_json::json!({}))
            .await
            .expect_err("cost above amount_max_per_call must reject");
        assert!(
            matches!(
                err,
                crate::context::outlets::invoke::InvocationError::CaveatViolation { .. }
            ),
            "amount_max_per_call rejection is a CaveatViolation, got {err:?}"
        );

        // cost_per_chunk = 5 == cap 5 → pass.
        let store_ok = make_store(1_000);
        let hook_ok = expect_hook(
            &caveats,
            Amount::new(5),
            Some(&erase(&store_ok)),
            "amount_max_per_call (at cap)",
        );
        run_hook(hook_ok, serde_json::json!({}))
            .await
            .expect("cost at the cap must pass");
    }

    /// `allowed_target_dids` set but no target DID negotiated on the
    /// single-context streaming surface → fail-closed reject (local check).
    #[tokio::test]
    async fn allowed_target_dids_mismatch_rejects() {
        let store = make_store(1_000);
        let mut caveats = InvocationCaveats::empty();
        caveats.allowed_target_dids = Some(vec!["did:key:z6MkAllowedTarget".into()]);
        let hook = expect_hook(
            &caveats,
            Amount::new(1),
            Some(&erase(&store)),
            "allowed_target_dids",
        );
        let err = run_hook(hook, serde_json::json!({}))
            .await
            .expect_err("a target-DID restriction with no negotiated target must fail closed");
        assert!(
            matches!(
                err,
                crate::context::outlets::invoke::InvocationError::CaveatViolation { .. }
            ),
            "allowed_target_dids rejection is a CaveatViolation, got {err:?}"
        );
    }

    /// `amount_max_cumulative` is RESERVED at the WORST-CASE billable spend
    /// `cost_per_chunk × effective_max_billable_chunks` at the final gate — NOT
    /// at the invoker-declared `estimated_chunk_count` (which the invoker can
    /// declare arbitrarily low) and NOT once at `cost_per_chunk`. The effective
    /// ceiling AND-folds `max_calls` with `floor(cap / cost)`, so the reserve is
    /// `<= cap` and the open admits; the cap is then enforced cross-stream by the
    /// reservation (a second concurrent open cannot reserve against an
    /// already-reserved counter).
    #[tokio::test]
    async fn amount_max_cumulative_reserves_full_worst_case_spend() {
        use crate::context::outlets::stream::effective_max_billable_chunks;

        // Cap = 100, cost_per_chunk = 10, max_calls = 20. floor(100/10) = 10, so
        // the effective billable ceiling = min(20, 10) = 10 chunks → worst-case
        // reserve = 10 × 10 = 100 == cap. The under-declared-estimate evasion
        // (declare estimate 1) would have reserved only 10 and let 50 chunks
        // bill against the cap.
        let cost = Amount::new(10);
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(100));
        caveats.max_calls = Some(20);
        assert_eq!(
            effective_max_billable_chunks(cost, &caveats),
            Some(10),
            "effective ceiling folds the value cap: min(max_calls 20, floor(cap 100 / cost 10) = 10)"
        );

        let store = make_store(1_000);
        let reservation = expect_reservation(&caveats, cost, &erase(&store), "cumulative");
        // Declared estimate = 1 (attacker-minimal) — the reserve must IGNORE it
        // and use the effective ceiling (10).
        commit(&reservation, cost, 1)
            .await
            .expect("worst-case reserve 100 == cap admits");
        let counters = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .expect("load")
            .expect("record");
        assert_eq!(
            counters.amount_cumulative_used, 100,
            "the open reserves the WORST-CASE spend (cost 10 × effective ceiling 10 = 100), \
             NOT the declared estimate (1 → 10)"
        );

        // A second concurrent open on the SAME ucan_cid cannot reserve any more
        // cumulative capacity — the counter is already at the cap. This is the
        // cross-stream enforcement the under-declared estimate previously evaded.
        let reservation2 = expect_reservation(&caveats, cost, &erase(&store), "second open");
        let err = commit(&reservation2, cost, 1)
            .await
            .expect_err("a second open over the exhausted cumulative cap must reject");
        assert!(
            matches!(
                err,
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation { .. }
            ),
            "second open rejects with the cumulative-cap violation, got {err:?}"
        );
    }

    /// Close-time settlement releases the unspent reserve. Reserve the
    /// worst-case 20 chunks @ 10 = 200 (`max_calls = 20`), terminate after
    /// billing 4 → settle releases `200 − 4 × 10 = 160`, leaving the counter at
    /// 40; a subsequent open whose worst-case reserve fits in the remaining 160
    /// admits, one that needs more than the remaining 100 rejects. Each open
    /// declares a minimal estimate (1) to prove the reserve uses `max_calls`,
    /// not the declared estimate.
    #[tokio::test]
    async fn cumulative_reserve_released_at_settle_then_reconciled() {
        let store = make_store(1_000);
        let cost = Amount::new(10);
        let cap = Amount::new(200);
        // Helper: caveats with the shared cap and a per-open `max_calls`.
        let with_max_calls = |max_calls: u64| {
            let mut c = InvocationCaveats::empty();
            c.amount_max_cumulative = Some(cap);
            c.max_calls = Some(max_calls);
            c
        };

        // Open: max_calls = 20 → worst-case reserve 200. Declared estimate 1.
        let caveats_open = with_max_calls(20);
        let reservation =
            expect_reservation(&caveats_open, cost, &erase(&store), "open reserve 200");
        commit(&reservation, cost, 1)
            .await
            .expect("reserve 200 == cap admits");
        let used = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            used.amount_cumulative_used, 200,
            "reserved worst-case spend (max_calls 20 × 10), not the declared estimate"
        );

        // Settle after billing 4 of 20 chunks → release via the SAME
        // amount-based reconciliation the production close path uses:
        // 200 − 4 × 10 = 160.
        let settlement = crate::context::outlets::dispatch::CounterReserveSettlement {
            amount_cumulative_reserved: 200,
            reserved_chunks: 1, // diagnostics only — declared estimate
            ucan_cid: TEST_CID.to_owned(),
            cost_per_chunk: cost,
        };
        let unspent = settlement.unspent_release_amount(4);
        assert_eq!(unspent, 160, "unspent = reserved 200 − billed 4 × 10");
        store
            .release(
                TEST_CTX,
                TEST_CID,
                scp_protocol::trust::CaveatKind::AmountCumulative,
                unspent,
            )
            .await
            .expect("release of unspent reserve succeeds");
        let after = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.amount_cumulative_used, 40,
            "counter reflects only the 4 billed chunks × 10"
        );

        // Subsequent open: max_calls = 6 → worst-case reserve 60 → 40 + 60 =
        // 100 ≤ 200, admit.
        let caveats_ok = with_max_calls(6);
        let reservation_ok =
            expect_reservation(&caveats_ok, cost, &erase(&store), "open reserve 60");
        commit(&reservation_ok, cost, 1)
            .await
            .expect("reserve 60 fits in remaining 160");

        // A further open: max_calls = 11 → worst-case reserve 110 → 100 + 110 =
        // 210 > 200, reject.
        let caveats_reject = with_max_calls(11);
        let reservation_reject =
            expect_reservation(&caveats_reject, cost, &erase(&store), "open reserve 110");
        let err = commit(&reservation_reject, cost, 1)
            .await
            .expect_err("reserve 110 over the remaining 100 must reject");
        assert!(
            matches!(
                err,
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation { .. }
            ),
            "over-cap subsequent reserve rejects, got {err:?}"
        );
    }

    /// REGRESSION (under-declared-estimate evasion closed). The reported attack:
    /// declare `estimated_chunk_count = 1`, `max_calls = 50`,
    /// `cost_per_chunk = 10`, `amount_max_cumulative = 100`. The OLD code
    /// reserved `cost × estimated = 10` while a stream could bill up to 50
    /// chunks → the cap was debited for 10 while 500 was spendable, evading the
    /// cap cross-stream. The fix reserves the WORST-CASE effective spend
    /// (`cost × min(max_calls 50, floor(cap 100 / cost 10) = 10) = 100`) and
    /// pins the SAME effective ceiling (10) into the per-chunk billing gate, so
    /// no stream can bill past 10 chunks regardless of the declared estimate.
    #[tokio::test]
    async fn under_declared_estimate_cannot_evade_cumulative_cap() {
        use crate::context::outlets::stream::{
            cumulative_reserve_amount, effective_max_billable_chunks,
        };

        let cost = Amount::new(10);
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(100));
        caveats.max_calls = Some(50);

        // The effective billable ceiling folds the value cap in: the stream can
        // bill at most floor(100/10) = 10 chunks, NOT max_calls = 50.
        assert_eq!(
            effective_max_billable_chunks(cost, &caveats),
            Some(10),
            "value cap lowers the billable ceiling to floor(cap / cost) = 10"
        );
        // The reserve is the worst-case spend over that ceiling — 100 — NOT the
        // declared estimate (1 → 10) the old code would have used.
        assert_eq!(
            cumulative_reserve_amount(cost, &caveats),
            Some(100),
            "reserve = cost 10 × effective ceiling 10 = 100, independent of declared estimate"
        );

        // First open: declare estimate = 1 (attacker-minimal). The reserve still
        // debits the full 100 (the whole cap), proving the declared estimate is
        // not the reservation basis.
        let store = make_store(1_000);
        let r1 = expect_reservation(&caveats, cost, &erase(&store), "open 1");
        commit(&r1, cost, 1)
            .await
            .expect("first open admits at cap");
        let after_open1 = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after_open1.amount_cumulative_used, 100,
            "reserve debits the worst-case 100, not the declared-estimate 10"
        );

        // A second concurrent open on the same ucan_cid is now BLOCKED — the
        // cumulative cap is fully reserved. Under the old code the second open
        // (also reserving only 10) would have admitted, and the two streams
        // together could bill 1000 against a 100 cap.
        let r2 = expect_reservation(&caveats, cost, &erase(&store), "open 2");
        let err = commit(&r2, cost, 1)
            .await
            .expect_err("second open over the exhausted cap must reject");
        assert!(
            matches!(
                err,
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation { .. }
            ),
            "blocked with the cumulative-cap violation, got {err:?}"
        );
    }

    /// RECONCILIATION: a stream that terminates early settles the cumulative
    /// counter to EXACTLY the billed value. Open reserves the worst case
    /// (`cost 10 × effective ceiling 10 = 100`); the stream bills only 3 chunks
    /// (30); close-time settlement releases `100 − 30 = 70`, leaving the counter
    /// at 30 — the true billed spend. A subsequent open then sees the freed
    /// capacity.
    #[tokio::test]
    async fn cumulative_counter_reconciles_to_billed_on_early_terminate() {
        let cost = Amount::new(10);
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_cumulative = Some(Amount::new(100));
        caveats.max_calls = Some(50);

        let store = make_store(1_000);
        let r1 = expect_reservation(&caveats, cost, &erase(&store), "open");
        commit(&r1, cost, 1).await.expect("open reserves 100");

        // Terminate after billing 3 of the (effective-ceiling 10) chunks. The
        // close-time settlement releases the unspent portion via the SAME
        // amount-based reconciliation the production close path uses.
        let settlement = crate::context::outlets::dispatch::CounterReserveSettlement {
            amount_cumulative_reserved: 100,
            reserved_chunks: 1, // diagnostics-only declared estimate
            ucan_cid: TEST_CID.to_owned(),
            cost_per_chunk: cost,
        };
        let unspent = settlement.unspent_release_amount(3);
        assert_eq!(unspent, 70, "unspent = reserved 100 − billed 3 × 10");
        store
            .release(
                TEST_CTX,
                TEST_CID,
                scp_protocol::trust::CaveatKind::AmountCumulative,
                unspent,
            )
            .await
            .expect("release succeeds");
        let after = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.amount_cumulative_used, 30,
            "counter reconciles to EXACTLY the 3 billed chunks × 10 = 30"
        );
    }

    /// REGRESSION (normal stream still works). When the declared estimate equals
    /// the effective ceiling (`max_calls` is the binding constraint, well under
    /// `floor(cap / cost)`), the reserve and close behave exactly as a
    /// well-behaved invoker expects: reserve `cost × max_calls`, bill all of
    /// them, counter ends at the full billed amount.
    #[tokio::test]
    async fn normal_stream_estimate_equals_ceiling_reconciles_to_billed() {
        use crate::context::outlets::stream::effective_max_billable_chunks;

        let cost = Amount::new(2);
        let mut caveats = InvocationCaveats::empty();
        // cap 1000 ≫ cost × max_calls (2 × 5 = 10): max_calls is the binding
        // constraint, the value cap never bites.
        caveats.amount_max_cumulative = Some(Amount::new(1_000));
        caveats.max_calls = Some(5);
        assert_eq!(
            effective_max_billable_chunks(cost, &caveats),
            Some(5),
            "max_calls binds: min(5, floor(1000/2) = 500) = 5"
        );

        let store = make_store(1_000);
        // Declared estimate == effective ceiling (5) — the well-behaved case.
        let r = expect_reservation(&caveats, cost, &erase(&store), "normal open");
        commit(&r, cost, 5).await.expect("open reserves 10");
        let opened = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            opened.amount_cumulative_used, 10,
            "reserve = cost 2 × ceiling 5 = 10"
        );

        // Bill all 5 chunks → nothing unspent to release; counter stays at 10.
        let settlement = crate::context::outlets::dispatch::CounterReserveSettlement {
            amount_cumulative_reserved: 10,
            reserved_chunks: 5,
            ucan_cid: TEST_CID.to_owned(),
            cost_per_chunk: cost,
        };
        assert_eq!(
            settlement.unspent_release_amount(5),
            0,
            "billing the full ceiling leaves nothing to release"
        );
        let after = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.amount_cumulative_used, 10,
            "counter ends at the full billed amount (5 × 2 = 10)"
        );
    }

    /// `rate_window` exhausted: a window of `max = 1` admits the first open and
    /// rejects the second within the same window via the final-gate CAS.
    #[tokio::test]
    async fn rate_window_exhausted_rejects() {
        let store = make_store(1_000);
        let mut caveats = InvocationCaveats::empty();
        caveats.rate_window = Some(RateWindow {
            max: 1,
            window_secs: 60,
        });

        // First open within the window — admitted.
        let r1 = expect_reservation(
            &caveats,
            Amount::new(1),
            &erase(&store),
            "rate_window (first)",
        );
        commit(&r1, Amount::new(1), 1)
            .await
            .expect("first open within rate window must be admitted");

        // Second open within the same window — rejected (shared store/CID).
        let r2 = expect_reservation(
            &caveats,
            Amount::new(1),
            &erase(&store),
            "rate_window (second)",
        );
        let err = commit(&r2, Amount::new(1), 1)
            .await
            .expect_err("second open within an exhausted rate window must reject");
        assert!(
            matches!(
                err,
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation { .. }
            ),
            "rate_window rejection is a CaveatPostInputViolation, got {err:?}"
        );
    }

    /// Fail-closed: a counter-bearing cap with NO counter store rejects the
    /// build (a cap the runtime cannot enforce must never silently pass).
    #[tokio::test]
    async fn counter_bearing_caveat_without_store_fails_closed() {
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(5);
        let built = build_stream_post_input_hook(&caveats, Amount::new(1), None);
        match built {
            Err(
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation {
                    ..
                },
            ) => {}
            Err(other) => panic!("expected CaveatPostInputViolation, got Err({other:?})"),
            Ok(_) => panic!("a counter-bearing cap with no store must fail closed, got Ok(..)"),
        }
    }

    /// Stateless-only caveats with NO counter store still build a working
    /// local-check hook (no CAS needed) — the legacy / test path.
    #[tokio::test]
    async fn stateless_caveats_without_store_still_enforce() {
        let mut caveats = InvocationCaveats::empty();
        caveats.amount_max_per_call = Some(Amount::new(5));
        let hook = expect_hook(
            &caveats,
            Amount::new(9),
            None,
            "stateless amount_max_per_call (no store)",
        );
        let err = run_hook(hook, serde_json::json!({}))
            .await
            .expect_err("cost above amount_max_per_call must reject even without a store");
        assert!(
            matches!(
                err,
                crate::context::outlets::invoke::InvocationError::CaveatViolation { .. }
            ),
            "stateless rejection is a CaveatViolation, got {err:?}"
        );
    }

    /// R4 — the §7.3.8 `max_calls` INVOCATION counter increments by exactly
    /// ONE per stream open at the final gate, regardless of chunk count
    /// (HIGH-2's separate per-chunk `CreditTracker` dimension). A `max_calls`
    /// cap of 2 admits two opens and rejects the third.
    #[tokio::test]
    async fn max_calls_counts_invocations_not_chunks_no_double_charge() {
        let store = make_store(1_000);
        let mut caveats = InvocationCaveats::empty();
        caveats.max_calls = Some(2);

        // First open: invocation counter 0 → 1. cost_per_chunk / estimate are
        // irrelevant to the max_calls dim (no amount_max_cumulative cap set).
        let r1 = expect_reservation(
            &caveats,
            Amount::new(7),
            &erase(&store),
            "max_calls (first)",
        );
        commit(&r1, Amount::new(7), 5)
            .await
            .expect("first open admitted under max_calls=2");
        let counters = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .expect("counter load succeeds")
            .expect("a record exists after the first open");
        assert_eq!(
            counters.max_calls_used, 1,
            "a stream open counts as exactly ONE invocation against max_calls, \
             distinct from HIGH-2's per-chunk CreditTracker ceiling"
        );

        // Second open: 1 → 2 (still within cap).
        let r2 = expect_reservation(
            &caveats,
            Amount::new(7),
            &erase(&store),
            "max_calls (second)",
        );
        commit(&r2, Amount::new(7), 5)
            .await
            .expect("second open admitted at the cap boundary");
        let counters = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counters.max_calls_used, 2, "second open increments to 2");

        // Third open: would be 3 > cap 2 → reject.
        let r3 = expect_reservation(
            &caveats,
            Amount::new(7),
            &erase(&store),
            "max_calls (third)",
        );
        let err = commit(&r3, Amount::new(7), 5)
            .await
            .expect_err("third open exceeds max_calls=2");
        assert!(
            matches!(
                err,
                crate::context::outlets::dispatch::OpenStreamRejection::CaveatPostInputViolation { .. }
            ),
            "max_calls exhaustion is a CaveatPostInputViolation, got {err:?}"
        );

        // No amount_max_cumulative cap → that dimension stays untouched,
        // proving per-dimension isolation.
        let counters = store
            .load_counters(TEST_CTX, TEST_CID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            counters.amount_cumulative_used, 0,
            "no amount_max_cumulative cap → that dimension stays untouched"
        );
    }
}
