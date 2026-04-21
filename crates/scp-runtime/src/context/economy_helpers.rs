//! Economy helpers with explicit-collaborator signatures (ADR-049 §12c.3).
//!
//! # Purpose
//!
//! This module hoists the economy-domain method that the actor handler in
//! [`crate::context::actor::handlers::economy`] currently reaches via
//! `view.manager().X(...)`. The hoist is a **pre-work** commit for the
//! actor handler body migration (later ADR-049 commits): handler bodies
//! cannot take `&ContextManager` — they take `&ActorDeps` and
//! `&mut PerContextState` — so the methods they call must accept explicit
//! collaborators rather than reaching through `self`.
//!
//! This file is the economy counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3), and
//! [`crate::context::trust_recovery_helpers`] (12c.3).
//!
//! # Behavior preservation
//!
//! [`verify_payment_receipts`] is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.payment_adapter` replaced by `mgr.payment_adapter_ref()`.
//!
//! The legacy inherent method on
//! [`ContextManager`](crate::context::manager::ContextManager) remains as
//! a one-line forwarder; it is deleted alongside the outer shim in a later
//! ADR-049 commit when the actor handler body owns the economy path
//! directly.
//!
//! # Top-level method hoisted (actor-handler entry point)
//!
//! [`verify_payment_receipts`].
//!
//! # Not hoisted (kept as pub(crate) on `ContextManager`)
//!
//! `authorize_paid_action`, `complete_paid_action`, `void_paid_action`,
//! and `record_payment_capture_failure` are cross-domain infrastructure
//! already reached from the hoisted messaging / lifecycle helpers via
//! `mgr.X(...)`; they remain as inherent methods on
//! [`ContextManager`](crate::context::manager::ContextManager) for this
//! commit. They migrate implicitly with the messaging / lifecycle
//! handlers, not as dedicated commands.

use crate::context::manager::ContextManager;
use crate::economy::adapter::PaymentReceipt;
use crate::economy::receipt::{ReceiptVerification, ReceiptVerificationError};

// ---------------------------------------------------------------------------
// verify_payment_receipts (top-level, actor-handler entry point)
// ---------------------------------------------------------------------------

/// Verifies payment receipts using the configured payment adapter
/// (hoisted body of the legacy
/// [`ContextManager::verify_payment_receipts`](crate::context::manager::ContextManager::verify_payment_receipts)).
///
/// For each receipt whose `adapter_id` matches the configured adapter,
/// calls `verify_dyn` directly. Receipts whose `adapter_id` does not
/// match the configured adapter return
/// [`ReceiptVerificationError::NoVerifierForAdapter`].
///
/// If no payment adapter is configured, all receipts return
/// [`ReceiptVerificationError::NoVerifierForAdapter`].
pub async fn verify_payment_receipts(
    mgr: &ContextManager,
    receipts: &[PaymentReceipt],
) -> Vec<Result<ReceiptVerification, ReceiptVerificationError>> {
    let mut results = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let result = match mgr.payment_adapter_ref() {
            Some(adapter) if adapter.adapter_id() == receipt.adapter_id => adapter
                .verify_dyn(receipt)
                .await
                .map(|r| ReceiptVerification {
                    receipt_id: receipt.receipt_id,
                    result: r,
                })
                .map_err(|e| ReceiptVerificationError::VerificationFailed {
                    receipt_id: receipt.receipt_id,
                    error: e,
                }),
            _ => Err(ReceiptVerificationError::NoVerifierForAdapter {
                receipt_id: receipt.receipt_id,
                adapter_id: receipt.adapter_id.clone(),
            }),
        };
        results.push(result);
    }
    results
}
