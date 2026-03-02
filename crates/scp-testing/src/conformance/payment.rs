//! Payment adapter conformance test macro.
//!
//! The [`payment_adapter_conformance`] macro generates 8 test cases that
//! validate any [`PaymentAdapter`](scp_core::economy::PaymentAdapter)
//! implementation against the spec (section 19.2.6):
//!
//! 1. Authorize/capture roundtrip
//! 2. Authorize/void roundtrip
//! 3. Double-capture rejection
//! 4. Insufficient balance handling
//! 5. Verify roundtrip (receipt -> verification)
//! 6. Currency mismatch rejection
//! 7. Concurrent authorization isolation
//! 8. Refund against captured receipt
//!
//! See spec section 19.2.6 and ADR-033 in `.docs/adrs/phase-3.md`.

/// Generates 8 conformance tests for a [`PaymentAdapter`] implementation.
///
/// # Arguments
///
/// The macro takes a single expression that evaluates to an instance of a type
/// implementing [`PaymentAdapter`]. This expression is called once per test to
/// create a fresh adapter with a clean ledger.
///
/// # Example
///
/// ```ignore
/// use scp_testing::payment_adapter_conformance;
///
/// payment_adapter_conformance!(TestAdapter::new());
/// ```
///
/// See spec section 19.2.6.
#[macro_export]
macro_rules! payment_adapter_conformance {
    ($adapter_factory:expr) => {
        mod payment_adapter_conformance {
            use super::*;

            use scp_core::economy::{Amount, PaymentAdapter, PaymentError};
            use $crate::conformance::payment::test_helpers::{
                make_metadata, payee_did, payer_did, supported_currency, unsupported_currency,
            };

            #[tokio::test]
            async fn authorize_capture_roundtrip() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(1000);
                let metadata = make_metadata();

                let auth = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await
                    .expect("authorize should succeed");

                assert_eq!(auth.payer, payer);
                assert_eq!(auth.payee, payee);
                assert_eq!(auth.amount, amount);
                assert_eq!(auth.currency, currency);

                let receipt = adapter
                    .capture(&auth)
                    .await
                    .expect("capture should succeed");

                assert_eq!(receipt.payer, payer);
                assert_eq!(receipt.payee, payee);
                assert_eq!(receipt.amount, amount);
                assert_eq!(receipt.currency, currency);
                assert_eq!(receipt.adapter_id, adapter.adapter_id());
            }

            #[tokio::test]
            async fn authorize_void_roundtrip() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(500);
                let metadata = make_metadata();

                let auth = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await
                    .expect("authorize should succeed");

                adapter.void(&auth).await.expect("void should succeed");

                // After voiding, capture should fail.
                let capture_result = adapter.capture(&auth).await;
                assert!(capture_result.is_err(), "capture after void should fail");
            }

            #[tokio::test]
            async fn double_capture_rejection() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(1000);
                let metadata = make_metadata();

                let auth = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await
                    .expect("authorize should succeed");

                let _receipt = adapter
                    .capture(&auth)
                    .await
                    .expect("first capture should succeed");

                let second_capture = adapter.capture(&auth).await;
                assert!(
                    second_capture.is_err(),
                    "second capture of same authorization should fail"
                );
                if let Err(PaymentError::AlreadyCaptured { auth_id }) = &second_capture {
                    assert_eq!(*auth_id, auth.auth_id);
                } else if second_capture.is_err() {
                    // Other error types are acceptable (adapter-specific).
                }
            }

            #[tokio::test]
            async fn insufficient_balance_handling() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                // Use an extremely large amount that should exceed any test
                // ledger balance.
                let amount = Amount::new(u64::MAX);
                let metadata = make_metadata();

                let result = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await;

                assert!(
                    result.is_err(),
                    "authorization for amount exceeding balance should fail"
                );
                if let Err(PaymentError::InsufficientBalance { requested, .. }) = &result {
                    assert_eq!(*requested, amount);
                } else if result.is_err() {
                    // Other error types are acceptable (adapter-specific).
                }
            }

            #[tokio::test]
            async fn verify_roundtrip() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(750);
                let metadata = make_metadata();

                let auth = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await
                    .expect("authorize should succeed");

                let receipt = adapter
                    .capture(&auth)
                    .await
                    .expect("capture should succeed");

                let verification = adapter
                    .verify(&receipt)
                    .await
                    .expect("verify should succeed");

                assert!(verification.valid, "receipt should verify as valid");
                assert_eq!(verification.verified_amount, amount);
                assert_eq!(verification.verified_currency, currency);
                assert_eq!(verification.adapter_id, adapter.adapter_id());
            }

            #[tokio::test]
            async fn currency_mismatch_rejection() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = unsupported_currency(&adapter);
                let amount = Amount::new(100);
                let metadata = make_metadata();

                let result = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await;

                assert!(
                    result.is_err(),
                    "authorization with unsupported currency should fail"
                );
                if let Err(PaymentError::UnsupportedCurrency(c)) = &result {
                    assert_eq!(*c, currency);
                } else if result.is_err() {
                    // Other error types are acceptable (adapter-specific).
                }
            }

            #[tokio::test]
            async fn concurrent_authorization_isolation() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(100);

                // Create two independent authorizations.
                let metadata_a = make_metadata();
                let metadata_b = make_metadata();

                let auth_a = adapter
                    .authorize(&payer, &payee, amount, currency, metadata_a)
                    .await
                    .expect("first authorize should succeed");

                let auth_b = adapter
                    .authorize(&payer, &payee, amount, currency, metadata_b)
                    .await
                    .expect("second authorize should succeed");

                // Auth IDs must be distinct.
                assert_ne!(
                    auth_a.auth_id, auth_b.auth_id,
                    "concurrent authorizations must have distinct IDs"
                );

                // Capture one, void the other — each operates independently.
                let receipt = adapter
                    .capture(&auth_a)
                    .await
                    .expect("capture of auth_a should succeed");

                adapter
                    .void(&auth_b)
                    .await
                    .expect("void of auth_b should succeed");

                // Verify the captured receipt is valid.
                let verification = adapter
                    .verify(&receipt)
                    .await
                    .expect("verify should succeed");
                assert!(verification.valid);
            }

            #[tokio::test]
            async fn refund_against_captured_receipt() {
                let adapter = $adapter_factory;
                let payer = payer_did();
                let payee = payee_did();
                let currency = supported_currency(&adapter);
                let amount = Amount::new(2000);
                let metadata = make_metadata();

                let auth = adapter
                    .authorize(&payer, &payee, amount, currency, metadata)
                    .await
                    .expect("authorize should succeed");

                let receipt = adapter
                    .capture(&auth)
                    .await
                    .expect("capture should succeed");

                let refund = adapter
                    .refund(&receipt, None)
                    .await
                    .expect("full refund should succeed");

                assert_eq!(refund.original_receipt_id, receipt.receipt_id);
                assert_eq!(refund.refunded_amount, amount);
                assert_eq!(refund.currency, currency);
            }
        }
    };
}

/// Helper functions used by the conformance test macro.
///
/// These are public so the macro-generated tests can reference them, but
/// they are implementation details of the conformance suite.
pub mod test_helpers {
    use scp_core::economy::{
        AdapterCapabilities, CurrencyCode, PaidActionType, PaymentAdapter, PaymentMetadata,
    };
    use scp_identity::DID;

    /// Returns a deterministic payer DID for conformance tests.
    #[must_use]
    pub fn payer_did() -> DID {
        DID::from("did:dht:z6MkConformancePayer")
    }

    /// Returns a deterministic payee DID for conformance tests.
    #[must_use]
    pub fn payee_did() -> DID {
        DID::from("did:dht:z6MkConformancePayee")
    }

    /// Returns a [`PaymentMetadata`] with a fresh random idempotency key.
    #[must_use]
    pub fn make_metadata() -> PaymentMetadata {
        // Use a simple counter-based approach for uniqueness in tests.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&counter.to_le_bytes());
        PaymentMetadata {
            action_type: PaidActionType::MessageSend,
            context_id: None,
            idempotency_key: key,
        }
    }

    /// Returns a currency that the adapter supports.
    ///
    /// Picks the first currency from the adapter's supported currencies list.
    ///
    /// # Panics
    ///
    /// Panics if the adapter reports no supported currencies.
    #[must_use]
    #[allow(clippy::expect_used)] // Test helper — only called from macro-generated tests.
    pub fn supported_currency(adapter: &impl PaymentAdapter) -> CurrencyCode {
        let caps: AdapterCapabilities = adapter.capabilities();
        *caps
            .supported_currencies
            .first()
            .expect("adapter must support at least one currency for conformance tests")
    }

    /// Returns a currency that the adapter does NOT support.
    ///
    /// Generates a synthetic 4-byte currency code that is not in the adapter's
    /// supported list.
    #[must_use]
    pub fn unsupported_currency(adapter: &impl PaymentAdapter) -> CurrencyCode {
        let caps = adapter.capabilities();
        // Try "ZZZZ" first — extremely unlikely to be a real currency.
        let candidate = CurrencyCode::from("ZZZZ");
        if !caps.supported_currencies.contains(&candidate) {
            return candidate;
        }
        // Fallback: try "YYYY".
        let fallback = CurrencyCode::from("YYYY");
        if !caps.supported_currencies.contains(&fallback) {
            return fallback;
        }
        // Last resort: "XXXX".
        CurrencyCode::from("XXXX")
    }
}
