// Module-level allow — the legacy inherent-impl form in
// `manager/tools.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on individual methods (two-step borrow on the contexts map). The hoisted
// bodies preserve the same lock-hold-across-await patterns deliberately
// (narrowing changes lock-ordering semantics); allowing the lint
// crate-locally keeps the hoist byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Tools-domain helpers with explicit-collaborator signatures
//! (ADR-049 §12c.4).
//!
//! # Purpose
//!
//! This module hoists the tools-domain methods that the actor handler in
//! [`crate::context::actor::handlers::tools`] currently reaches via
//! `view.manager().X(...)`. The hoist is a **pre-work** commit for the
//! actor handler body migration (later ADR-049 commits): handler bodies
//! cannot take `&ContextManager` — they take `&ActorDeps` and
//! `&mut PerContextState` — so the methods they call must accept explicit
//! collaborators rather than reaching through `self`.
//!
//! This file is the tools counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3b),
//! [`crate::context::economy_helpers`] (12c.3a),
//! [`crate::context::trust_recovery_helpers`] (12c.3a),
//! [`crate::context::standing_helpers`] (12c.4), and
//! [`crate::context::broadcast_helpers`] (12c.4).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by `manager_methods::X(supervisor, ...)` for the
//! cross-domain helpers hoisted from `ContextManager` in ADR-049 commit
//! 12c.9g.1 (helper bodies migrated to direct calls in commit 12c.9g.2;
//! no `mgr` derivation).
//!
//! The legacy inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler body owns the tools
//! path directly.
//!
//! # Top-level methods hoisted (actor-handler entry points)
//!
//! [`try_consume_hard_rate_limit`], [`refund_hard_rate_limit`].
//!
//! # Not hoisted (kept as inherent methods on `ContextManager`)
//!
//! `try_consume_hard_rate_limit_blocking`,
//! `refund_hard_rate_limit_blocking`,
//! `try_consume_hard_rate_limit_from_any_context`,
//! `refund_hard_rate_limit_from_any_context`, and
//! `invoke_tool_with_economy` are reached only from FFI bridge layers
//! (`PyO3` / NAPI / `UniFFI` / WASM), not from actor handlers. They remain
//! as inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) and are
//! out of scope for the actor-handler-driven hoist.

use scp_identity::DID;

use crate::context::manager_methods;
use crate::context::supervisor::Supervisor;

// ---------------------------------------------------------------------------
// 1. try_consume_hard_rate_limit (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit consume for callers already inside a tokio
/// executor where `blocking_lock` would panic.
///
/// Returns `true` if a token was consumed OR if the context is not
/// registered in the `ContextManager`. Returns `false` only when the
/// context IS registered AND the sender is over budget.
///
/// Hoisted body of the legacy
/// [`ContextManager::try_consume_hard_rate_limit`](crate::context::manager::ContextManager::try_consume_hard_rate_limit)
/// (ADR-049 commit 12c.4). Byte-identical behavior.
#[must_use]
pub async fn try_consume_hard_rate_limit(
    supervisor: &Supervisor,
    context_id: &str,
    did: &DID,
    now_secs: u64,
) -> bool {
    // ADR-049 commit 12c.9g.2 — returns `bool` so an unpopulated attach
    // slot degrades to the legacy unknown-context pass-through (`true`).
    // The contexts map accessor is reached directly through the supervisor;
    // no `mgr` derivation needed.
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return true;
    };
    let mut guard = arc.lock().await;
    let ctx = &mut *guard;
    ctx.governance.hard_rate_limit.try_consume(did, now_secs)
}

// ---------------------------------------------------------------------------
// 2. refund_hard_rate_limit (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Async hard-rate-limit refund. No-op if the context is unknown.
///
/// Hoisted body of the legacy
/// [`ContextManager::refund_hard_rate_limit`](crate::context::manager::ContextManager::refund_hard_rate_limit)
/// (ADR-049 commit 12c.4). Byte-identical behavior.
pub async fn refund_hard_rate_limit(supervisor: &Supervisor, context_id: &str, did: &DID) {
    // ADR-049 commit 12c.9g.2 — returns `()` so an unpopulated attach
    // slot degrades to a no-op with a tracing error for observability.
    // The detached-supervisor case is distinguished from the
    // unknown-context case via [`ContextError::NotInitialized`] vs
    // [`ContextError::ContextNotRegistered`] so the tracing diagnostic
    // remains specific.
    match manager_methods::get_context_arc(supervisor, context_id) {
        Ok(ctx_arc) => {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.governance.hard_rate_limit.refund(did);
        }
        Err(scp_protocol::context::ContextError::NotInitialized(_)) => {
            tracing::error!(
                context_id,
                "refund_hard_rate_limit: Supervisor is not attached — skipping refund \
                 (contract violation; see ADR-049 commit 12c.9d)"
            );
        }
        Err(_) => {
            // Unknown context: legacy behavior is silent no-op.
        }
    }
}
