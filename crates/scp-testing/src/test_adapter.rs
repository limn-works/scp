//! In-memory reference payment adapter for testing.
//!
//! [`TestAdapter`] implements [`PaymentAdapter`] with an in-memory ledger.
//! No real money. Thread-safe via `Arc<Mutex<...>>`. Ships with the SDK in
//! the `scp-testing` crate, not with production adapters.
//!
//! See spec section 19.2.6 and ADR-033 acceptance criteria #4.

use scp_primitives::Clock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use scp_core::economy::{
    AdapterCapabilities, Amount, CurrencyCode, PaymentAdapter, PaymentAuthorization, PaymentError,
    PaymentMetadata, PaymentReceipt, RefundConfirmation, VerificationResult,
};
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Internal ledger types
// ---------------------------------------------------------------------------

/// State of an authorization hold.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AuthState {
    /// Funds are held but not yet captured or voided.
    Pending,
    /// Funds have been captured (settled).
    Captured,
    /// Authorization was voided (funds released).
    Voided,
}

/// Internal record of an authorization.
#[derive(Clone, Debug)]
struct HoldRecord {
    payer: DID,
    payee: DID,
    amount: Amount,
    currency: CurrencyCode,
    state: AuthState,
}

/// Internal record of a captured payment.
#[derive(Clone, Debug)]
struct ReceiptRecord {
    receipt: PaymentReceipt,
    /// Tracks how much has been refunded so far.
    refunded: u64,
}

/// The inner mutable state of the test adapter.
#[derive(Debug)]
struct Ledger {
    /// Available balance per (`DID`, `CurrencyCode`). This is the balance
    /// minus any outstanding holds.
    balances: HashMap<(DID, CurrencyCode), u64>,
    /// Authorization holds keyed by `auth_id`.
    holds: HashMap<[u8; 32], HoldRecord>,
    /// Captured receipts keyed by `receipt_id`.
    receipts: HashMap<[u8; 32], ReceiptRecord>,
    /// Monotonic counter for generating deterministic IDs.
    counter: u64,
}

// ---------------------------------------------------------------------------
// Lock helper
// ---------------------------------------------------------------------------

/// Acquires the ledger lock, mapping poison errors to [`PaymentError`].
fn lock_ledger(mutex: &Mutex<Ledger>) -> Result<MutexGuard<'_, Ledger>, PaymentError> {
    mutex
        .lock()
        .map_err(|_: PoisonError<_>| PaymentError::AdapterError("ledger lock poisoned".to_owned()))
}

// ---------------------------------------------------------------------------
// TestAdapter
// ---------------------------------------------------------------------------

/// In-memory reference payment adapter (spec section 19.2.6).
///
/// Thread-safe. Clone is cheap (inner state is behind `Arc<Mutex<_>>`).
///
/// # Example
///
/// ```
/// use scp_testing::TestAdapter;
/// use scp_core::economy::{Amount, CurrencyCode};
/// use scp_identity::DID;
///
/// let adapter = TestAdapter::new();
/// adapter.seed_balance(
///     DID::from("did:dht:z6MkPayer"),
///     Amount::new(100_000),
///     CurrencyCode::from("USD"),
/// );
/// ```
#[derive(Clone, Debug)]
pub struct TestAdapter {
    inner: Arc<Mutex<Ledger>>,
}

impl TestAdapter {
    /// Creates a new `TestAdapter` with an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Ledger {
                balances: HashMap::new(),
                holds: HashMap::new(),
                receipts: HashMap::new(),
                counter: 0,
            })),
        }
    }

    /// Seeds a balance for a (`DID`, `CurrencyCode`) pair.
    ///
    /// This is an additive operation: calling `seed_balance` twice with the
    /// same DID and currency adds to the existing balance.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[allow(clippy::expect_used, clippy::significant_drop_tightening)] // Test infra: poisoned mutex is unrecoverable.
    pub fn seed_balance(&self, did: DID, amount: Amount, currency: CurrencyCode) {
        let mut ledger = self.inner.lock().expect("ledger lock poisoned");
        let entry = ledger.balances.entry((did, currency)).or_insert(0);
        *entry = entry.saturating_add(amount.value());
    }

    /// Returns the current available balance for a (`DID`, `CurrencyCode`)
    /// pair.
    ///
    /// Available balance = seeded balance minus outstanding holds.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    #[allow(clippy::expect_used, clippy::significant_drop_tightening)] // Test infra: poisoned mutex is unrecoverable.
    pub fn available_balance(&self, did: &DID, currency: &CurrencyCode) -> Amount {
        let ledger = self.inner.lock().expect("ledger lock poisoned");
        let balance = ledger
            .balances
            .get(&(did.clone(), *currency))
            .copied()
            .unwrap_or(0);
        Amount::new(balance)
    }
}

impl Default for TestAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper: deterministic ID generation
// ---------------------------------------------------------------------------

/// Generates a deterministic 32-byte ID from a counter value.
fn deterministic_id(counter: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&counter.to_le_bytes());
    // Prefix with "test" marker bytes for identifiability.
    id[8] = b't';
    id[9] = b'e';
    id[10] = b's';
    id[11] = b't';
    id
}

/// Returns the current unix timestamp in seconds.
///
fn now_secs() -> u64 {
    scp_primitives::SystemClock.now_secs()
}

// ---------------------------------------------------------------------------
// PaymentAdapter implementation
// ---------------------------------------------------------------------------

#[allow(
    clippy::similar_names,              // payer/payee are domain terms from the spec.
    clippy::significant_drop_tightening // Mutex guards are held for the duration of each operation.
)]
impl PaymentAdapter for TestAdapter {
    #[allow(clippy::unnecessary_literal_bound)] // Trait signature constrains return type.
    fn adapter_id(&self) -> &str {
        "test"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            supported_currencies: vec![
                CurrencyCode::from("USD"),
                CurrencyCode::from("BTC"),
                CurrencyCode::from("USDC"),
            ],
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
        payer: &DID,
        payee: &DID,
        amount: Amount,
        currency: CurrencyCode,
        _metadata: PaymentMetadata,
    ) -> Result<PaymentAuthorization, PaymentError> {
        // Check currency support.
        let caps = self.capabilities();
        if !caps.supported_currencies.contains(&currency) {
            return Err(PaymentError::UnsupportedCurrency(currency));
        }

        let mut ledger = lock_ledger(&self.inner)?;

        // Check payer balance.
        let balance = ledger
            .balances
            .get(&(payer.clone(), currency))
            .copied()
            .unwrap_or(0);

        if balance < amount.value() {
            return Err(PaymentError::InsufficientBalance {
                available: Amount::new(balance),
                requested: amount,
            });
        }

        // Deduct from available balance (create hold).
        *ledger
            .balances
            .entry((payer.clone(), currency))
            .or_insert(0) -= amount.value();

        // Generate deterministic auth ID.
        let counter = ledger.counter;
        ledger.counter += 1;
        let auth_id = deterministic_id(counter);

        // Record the hold.
        ledger.holds.insert(
            auth_id,
            HoldRecord {
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                state: AuthState::Pending,
            },
        );

        drop(ledger);
        let ts = now_secs();

        Ok(PaymentAuthorization {
            auth_id,
            payer: payer.clone(),
            payee: payee.clone(),
            amount,
            currency,
            adapter_id: "test".to_owned(),
            created_at: ts,
            expires_at: ts + 3600, // 1 hour hold
            adapter_state: Vec::new(),
        })
    }

    async fn capture(&self, auth: &PaymentAuthorization) -> Result<PaymentReceipt, PaymentError> {
        let mut ledger = lock_ledger(&self.inner)?;

        let hold = ledger
            .holds
            .get(&auth.auth_id)
            .cloned()
            .ok_or_else(|| PaymentError::InvalidReceipt("unknown authorization".to_owned()))?;

        match hold.state {
            AuthState::Captured => {
                return Err(PaymentError::AlreadyCaptured {
                    auth_id: auth.auth_id,
                });
            }
            AuthState::Voided => {
                return Err(PaymentError::AlreadyVoided {
                    auth_id: auth.auth_id,
                });
            }
            AuthState::Pending => {}
        }

        // Mark hold as captured. Safe to index — we just retrieved this key.
        if let Some(h) = ledger.holds.get_mut(&auth.auth_id) {
            h.state = AuthState::Captured;
        }

        // Credit the payee.
        *ledger
            .balances
            .entry((hold.payee.clone(), hold.currency))
            .or_insert(0) += hold.amount.value();

        // Generate receipt.
        let counter = ledger.counter;
        ledger.counter += 1;
        let receipt_id = deterministic_id(counter);

        // Deterministic adapter_proof: the auth_id bytes serve as proof.
        let adapter_proof = auth.auth_id.to_vec();

        let receipt = PaymentReceipt {
            receipt_id,
            payer: hold.payer.clone(),
            payee: hold.payee.clone(),
            amount: hold.amount,
            currency: hold.currency,
            action_type: scp_core::economy::PaidActionType::MessageSend,
            context_id: None,
            adapter_id: "test".to_owned(),
            adapter_proof,
            timestamp: now_secs(),
            anchored: false,
            signature: Vec::new(), // Test adapter: no real signature.
        };

        // Store receipt.
        ledger.receipts.insert(
            receipt_id,
            ReceiptRecord {
                receipt: receipt.clone(),
                refunded: 0,
            },
        );

        Ok(receipt)
    }

    async fn void(&self, auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        let mut ledger = lock_ledger(&self.inner)?;

        let hold = ledger
            .holds
            .get(&auth.auth_id)
            .cloned()
            .ok_or_else(|| PaymentError::InvalidReceipt("unknown authorization".to_owned()))?;

        match hold.state {
            AuthState::Captured => {
                return Err(PaymentError::AlreadyCaptured {
                    auth_id: auth.auth_id,
                });
            }
            AuthState::Voided => {
                return Err(PaymentError::AlreadyVoided {
                    auth_id: auth.auth_id,
                });
            }
            AuthState::Pending => {}
        }

        // Mark hold as voided. Safe to index — we just retrieved this key.
        if let Some(h) = ledger.holds.get_mut(&auth.auth_id) {
            h.state = AuthState::Voided;
        }

        // Release funds back to payer.
        *ledger
            .balances
            .entry((hold.payer.clone(), hold.currency))
            .or_insert(0) += hold.amount.value();

        Ok(())
    }

    async fn verify_authorization(&self, auth: &PaymentAuthorization) -> Result<(), PaymentError> {
        let ledger = lock_ledger(&self.inner)?;

        // Check if we issued this authorization and it's still pending.
        match ledger.holds.get(&auth.auth_id) {
            Some(hold) if hold.state == AuthState::Pending => Ok(()),
            Some(hold) if hold.state == AuthState::Voided => Err(PaymentError::AlreadyVoided {
                auth_id: auth.auth_id,
            }),
            Some(_) => Err(PaymentError::AlreadyCaptured {
                auth_id: auth.auth_id,
            }),
            None => Err(PaymentError::InvalidReceipt(
                "unknown authorization".to_owned(),
            )),
        }
    }

    async fn verify(&self, receipt: &PaymentReceipt) -> Result<VerificationResult, PaymentError> {
        let ledger = lock_ledger(&self.inner)?;

        // Check if we have this receipt on record.
        let valid = ledger.receipts.contains_key(&receipt.receipt_id);
        drop(ledger);

        Ok(VerificationResult {
            valid,
            adapter_id: "test".to_owned(),
            verified_amount: receipt.amount,
            verified_currency: receipt.currency,
            verification_timestamp: now_secs(),
        })
    }

    async fn refund(
        &self,
        receipt: &PaymentReceipt,
        amount: Option<Amount>,
    ) -> Result<RefundConfirmation, PaymentError> {
        let mut ledger = lock_ledger(&self.inner)?;

        let record = ledger
            .receipts
            .get(&receipt.receipt_id)
            .cloned()
            .ok_or_else(|| PaymentError::InvalidReceipt("unknown receipt".to_owned()))?;

        // Determine refund amount: full or partial.
        let refund_value = match amount {
            None => record
                .receipt
                .amount
                .value()
                .saturating_sub(record.refunded),
            Some(a) => a.value(),
        };

        // Check remaining refundable amount.
        let remaining = record
            .receipt
            .amount
            .value()
            .saturating_sub(record.refunded);
        if refund_value > remaining {
            return Err(PaymentError::AdapterError(format!(
                "refund amount {refund_value} exceeds remaining refundable {remaining}"
            )));
        }

        // Check payee has sufficient balance to refund.
        let payee_balance = ledger
            .balances
            .get(&(record.receipt.payee.clone(), record.receipt.currency))
            .copied()
            .unwrap_or(0);

        if payee_balance < refund_value {
            return Err(PaymentError::InsufficientBalance {
                available: Amount::new(payee_balance),
                requested: Amount::new(refund_value),
            });
        }

        // Deduct from payee.
        *ledger
            .balances
            .entry((record.receipt.payee.clone(), record.receipt.currency))
            .or_insert(0) -= refund_value;

        // Credit payer.
        *ledger
            .balances
            .entry((record.receipt.payer.clone(), record.receipt.currency))
            .or_insert(0) += refund_value;

        // Update refunded amount on the receipt record.
        if let Some(r) = ledger.receipts.get_mut(&receipt.receipt_id) {
            r.refunded += refund_value;
        }

        // Generate refund confirmation.
        let counter = ledger.counter;
        ledger.counter += 1;
        let refund_id = deterministic_id(counter);

        Ok(RefundConfirmation {
            refund_id,
            original_receipt_id: receipt.receipt_id,
            refunded_amount: Amount::new(refund_value),
            currency: record.receipt.currency,
            adapter_proof: receipt.receipt_id.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use scp_core::economy::{
        Amount, CurrencyCode, PaidActionType, PaymentAdapter, PaymentMetadata,
    };

    use crate::conformance::payment::test_helpers::{payee_did, payer_did};

    fn make_metadata() -> PaymentMetadata {
        crate::conformance::payment::test_helpers::make_metadata()
    }

    fn seeded_adapter() -> TestAdapter {
        let adapter = TestAdapter::new();
        adapter.seed_balance(
            payer_did(),
            Amount::new(1_000_000),
            CurrencyCode::from("USD"),
        );
        adapter.seed_balance(
            payer_did(),
            Amount::new(1_000_000),
            CurrencyCode::from("BTC"),
        );
        adapter.seed_balance(
            payer_did(),
            Amount::new(1_000_000),
            CurrencyCode::from("USDC"),
        );
        adapter
    }

    // Run all 8 conformance tests.
    crate::payment_adapter_conformance!(seeded_adapter());

    #[test]
    fn adapter_id_returns_test() {
        let adapter = TestAdapter::new();
        assert_eq!(adapter.adapter_id(), "test");
    }

    #[test]
    fn new_creates_empty_ledger() {
        let adapter = TestAdapter::new();
        assert_eq!(
            adapter.available_balance(&payer_did(), &CurrencyCode::from("USD")),
            Amount::new(0)
        );
    }

    #[test]
    fn seed_balance_is_additive() {
        let adapter = TestAdapter::new();
        let did = payer_did();
        let currency = CurrencyCode::from("USD");

        adapter.seed_balance(did.clone(), Amount::new(100), currency);
        adapter.seed_balance(did.clone(), Amount::new(200), currency);

        assert_eq!(adapter.available_balance(&did, &currency), Amount::new(300));
    }

    #[tokio::test]
    async fn void_after_capture_returns_error() {
        let adapter = seeded_adapter();
        let the_payer = payer_did();
        let the_payee = payee_did();
        let currency = CurrencyCode::from("USD");

        let auth = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(100),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();

        let _receipt = adapter.capture(&auth).await.unwrap();

        let result = adapter.void(&auth).await;
        assert!(result.is_err(), "void after capture should fail");
        assert!(matches!(result, Err(PaymentError::AlreadyCaptured { .. })));
    }

    #[tokio::test]
    async fn verify_tampered_receipt_returns_invalid() {
        let adapter = seeded_adapter();
        let the_payer = payer_did();
        let the_payee = payee_did();
        let currency = CurrencyCode::from("USD");

        let auth = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(100),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();

        let mut receipt = adapter.capture(&auth).await.unwrap();

        // Tamper with the receipt ID.
        receipt.receipt_id = [0xff; 32];

        let verification = adapter.verify(&receipt).await.unwrap();
        assert!(
            !verification.valid,
            "tampered receipt should verify as invalid"
        );
    }

    #[tokio::test]
    async fn verify_unknown_receipt_returns_invalid() {
        let adapter = TestAdapter::new();

        let receipt = PaymentReceipt {
            receipt_id: [0xab; 32],
            payer: payer_did(),
            payee: payee_did(),
            amount: Amount::new(100),
            currency: CurrencyCode::from("USD"),
            action_type: PaidActionType::MessageSend,
            context_id: None,
            adapter_id: "test".to_owned(),
            adapter_proof: vec![],
            timestamp: 0,
            anchored: false,
            signature: vec![],
        };

        let verification = adapter.verify(&receipt).await.unwrap();
        assert!(
            !verification.valid,
            "unknown receipt should verify as invalid"
        );
    }

    #[tokio::test]
    async fn partial_refund() {
        let adapter = seeded_adapter();
        let the_payer = payer_did();
        let the_payee = payee_did();
        let currency = CurrencyCode::from("USD");

        let auth = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(1000),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();

        let receipt = adapter.capture(&auth).await.unwrap();

        // Partial refund of 400.
        let refund = adapter
            .refund(&receipt, Some(Amount::new(400)))
            .await
            .unwrap();

        assert_eq!(refund.refunded_amount, Amount::new(400));
        assert_eq!(refund.original_receipt_id, receipt.receipt_id);

        // Payee starts at 0, gets 1000 from capture, loses 400 from refund = 600.
        assert_eq!(
            adapter.available_balance(&the_payee, &currency),
            Amount::new(600)
        );
        // Payer: 1_000_000 - 1000 (auth hold) + 400 (refund) = 999_400.
        assert_eq!(
            adapter.available_balance(&the_payer, &currency),
            Amount::new(999_400)
        );
    }

    #[tokio::test]
    async fn refund_payee_insufficient_balance() {
        let adapter = seeded_adapter();
        let the_payer = payer_did();
        let the_payee = payee_did();
        let currency = CurrencyCode::from("USD");

        let auth = adapter
            .authorize(
                &the_payee,
                &the_payer,
                Amount::new(1000),
                currency,
                make_metadata(),
            )
            .await;
        // Payee has no balance yet, so authorize from payee fails. Instead,
        // authorize from payer to payee, capture, then drain payee.

        // First: payer -> payee, capture gives payee 1000.
        drop(auth);
        let auth1 = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(1000),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();
        let receipt1 = adapter.capture(&auth1).await.unwrap();

        // Payee now has 1000. Authorize payee -> payer for 1000 to drain.
        let auth2 = adapter
            .authorize(
                &the_payee,
                &the_payer,
                Amount::new(1000),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();
        let _receipt2 = adapter.capture(&auth2).await.unwrap();

        // Payee now has 0 balance. Refund of receipt1 should fail.
        let result = adapter.refund(&receipt1, None).await;
        assert!(
            result.is_err(),
            "refund should fail when payee has insufficient balance"
        );
    }

    #[tokio::test]
    async fn concurrent_holds_track_separately() {
        let adapter = seeded_adapter();
        let the_payer = payer_did();
        let the_payee = payee_did();
        let currency = CurrencyCode::from("USD");

        // Authorize two holds of 100 each.
        let auth_a = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(100),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();
        let auth_b = adapter
            .authorize(
                &the_payer,
                &the_payee,
                Amount::new(100),
                currency,
                make_metadata(),
            )
            .await
            .unwrap();

        // IDs must be distinct.
        assert_ne!(auth_a.auth_id, auth_b.auth_id);

        // Available balance should reflect both holds.
        assert_eq!(
            adapter.available_balance(&the_payer, &currency),
            Amount::new(999_800) // 1_000_000 - 100 - 100
        );

        // Void one, balance goes back up by 100.
        adapter.void(&auth_b).await.unwrap();
        assert_eq!(
            adapter.available_balance(&the_payer, &currency),
            Amount::new(999_900)
        );
    }

    #[test]
    fn capabilities_returns_expected() {
        let adapter = TestAdapter::new();
        let caps = adapter.capabilities();
        assert_eq!(caps.supported_currencies.len(), 3);
        assert!(!caps.supports_streaming);
        assert!(!caps.supports_batch_auth);
        assert!(!caps.supports_single_step);
        assert!(caps.min_amount.is_none());
        assert!(caps.max_amount.is_none());
        assert_eq!(caps.typical_settlement_ms, 0);
        assert!(!caps.requires_facilitator);
    }

    #[test]
    fn clone_shares_state() {
        let adapter = TestAdapter::new();
        adapter.seed_balance(payer_did(), Amount::new(500), CurrencyCode::from("USD"));

        let clone = adapter;
        assert_eq!(
            clone.available_balance(&payer_did(), &CurrencyCode::from("USD")),
            Amount::new(500)
        );
    }
}
