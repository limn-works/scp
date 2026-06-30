//! Crate-internal test-support fixtures shared across `#[cfg(test)]` modules.
//!
//! Doubles referenced from more than one in-crate test module live here as a
//! single `pub(crate)` source of truth rather than being copied into each test
//! module. The whole file is `#![cfg(test)]`, so nothing here ships in a
//! non-test build.
#![cfg(test)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use scp_identity::DID;

/// A [`PaymentAdapter`](crate::economy::adapter::PaymentAdapter) that counts
/// `void` calls so cross-context-saga reversal / `NeedsRepair` tests can assert
/// whether an external escrow hold was voided
/// ([`void_external_and_consume`](crate::context::tools_helpers::ToolEconomyTicket::void_external_and_consume))
/// or held for operator repair
/// ([`hold_external_for_repair`](crate::context::tools_helpers::ToolEconomyTicket::hold_external_for_repair)).
///
/// Shared by the supervisor saga-FSM tests and the actor saga-handler tests.
pub struct VoidCountingPaymentAdapter {
    pub voided: Arc<AtomicUsize>,
}

impl crate::economy::adapter::PaymentAdapter for VoidCountingPaymentAdapter {
    fn adapter_id(&self) -> &'static str {
        "void-counting"
    }
    fn capabilities(&self) -> crate::economy::adapter::AdapterCapabilities {
        crate::economy::adapter::AdapterCapabilities {
            supported_currencies: vec![scp_protocol::economy::types::CurrencyCode::from("USD")],
            supports_streaming: false,
            supports_batch_auth: false,
            supports_single_step: false,
            min_amount: None,
            max_amount: None,
            typical_settlement_ms: 0,
            requires_facilitator: false,
        }
    }
    async fn authorize(
        &self,
        from_did: &DID,
        to_did: &DID,
        amount: scp_protocol::economy::types::Amount,
        currency: scp_protocol::economy::types::CurrencyCode,
        _metadata: crate::economy::adapter::PaymentMetadata,
    ) -> Result<crate::economy::adapter::PaymentAuthorization, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::PaymentAuthorization {
            auth_id: [7u8; 32],
            payer: from_did.clone(),
            payee: to_did.clone(),
            amount,
            currency,
            adapter_id: "void-counting".to_owned(),
            created_at: 1_000_000,
            expires_at: 2_000_000,
            adapter_state: vec![],
        })
    }
    async fn capture(
        &self,
        auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<crate::economy::adapter::PaymentReceipt, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::PaymentReceipt {
            receipt_id: [9u8; 32],
            payer: auth.payer.clone(),
            payee: auth.payee.clone(),
            amount: auth.amount,
            currency: auth.currency,
            action_type: scp_protocol::economy::types::PaidActionType::ToolInvoke,
            context_id: None,
            adapter_id: "void-counting".to_owned(),
            adapter_proof: vec![],
            timestamp: 1_000_001,
            signature: vec![],
            // Synthetic test receipt: never appended to the canonical Merkle
            // log, so it is not anchored (matches `PaymentReceipt`'s unanchored
            // default; the field lies outside the signed payload).
            anchored: false,
        })
    }
    async fn void(
        &self,
        _auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        self.voided.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn verify_authorization(
        &self,
        _auth: &crate::economy::adapter::PaymentAuthorization,
    ) -> Result<(), crate::economy::adapter::PaymentError> {
        Ok(())
    }
    async fn verify(
        &self,
        _receipt: &crate::economy::adapter::PaymentReceipt,
    ) -> Result<crate::economy::adapter::VerificationResult, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::VerificationResult {
            valid: true,
            adapter_id: "void-counting".to_owned(),
            verified_amount: scp_protocol::economy::types::Amount(0),
            verified_currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
            verification_timestamp: 1_000_002,
        })
    }
    async fn refund(
        &self,
        _receipt: &crate::economy::adapter::PaymentReceipt,
        _amount: Option<scp_protocol::economy::types::Amount>,
    ) -> Result<crate::economy::adapter::RefundConfirmation, crate::economy::adapter::PaymentError>
    {
        Ok(crate::economy::adapter::RefundConfirmation {
            refund_id: [0u8; 32],
            original_receipt_id: [9u8; 32],
            refunded_amount: scp_protocol::economy::types::Amount(0),
            currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
            adapter_proof: vec![],
        })
    }
}
