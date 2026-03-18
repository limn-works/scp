//! Attestation renewal orchestration (SCP-226).
//!
//! Provides renewal logic for time-locked attestations per spec section 7.3.6
//! and ADR-017. Renewable attestations carry a `renewal_interval`; renewing
//! re-verifies the attestation's signature, evidence, expiry, and revocation
//! status, then sets `renewed_at` to the current time without re-signing (the
//! field is excluded from `canonical_attestation_bytes`).
//!
//! # Renewal
//!
//! [`renew_attestation`] re-verifies the attestation via [`verify_attestation`]
//! and then clones it with `renewed_at` set to the current clock time. It
//! rejects non-renewable attestations (no `renewal_interval`), expired
//! attestations, and attestations that fail re-verification.
//!
//! Per spec section 7.3.6: "A claim verified once is a fact about the past.
//! A claim that must be continuously renewed is a fact about the present."
//! Renewal without re-verification would silently extend trust in attestations
//! whose underlying facts may have changed.
//!
//! # Scheduling
//!
//! [`RenewalChecker`] is a trait for platform-specific scheduling integration.
//! [`DefaultRenewalChecker`] implements it by comparing elapsed time since the
//! last renewal (or issuance) against the renewal interval.

use std::time::Duration;

use super::TrustError;
use super::attestation::{Attestation, DidPublicKeyResolver, verify_attestation};
use scp_identity::cache::Clock;

// ---------------------------------------------------------------------------
// RenewalError
// ---------------------------------------------------------------------------

/// Errors returned by [`renew_attestation`].
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    /// The attestation has no `renewal_interval` and cannot be renewed.
    #[error("attestation {attestation_id} has no renewal_interval and is not renewable")]
    NotRenewable {
        /// The attestation ID.
        attestation_id: String,
    },

    /// The attestation has expired (`now >= expires_at`).
    #[error("attestation {attestation_id} expired at {expired_at}")]
    Expired {
        /// The attestation ID.
        attestation_id: String,
        /// Unix timestamp (seconds) when the attestation expired.
        expired_at: u64,
    },

    /// Re-verification failed during renewal (spec section 7.3.6).
    ///
    /// The attestation's signature, evidence, expiry, or revocation status
    /// did not pass [`verify_attestation`]. The underlying [`TrustError`]
    /// contains the specific failure reason.
    #[error("attestation {attestation_id} failed re-verification: {source}")]
    VerificationFailed {
        /// The attestation ID.
        attestation_id: String,
        /// The underlying verification error.
        #[source]
        source: TrustError,
    },
}

// ---------------------------------------------------------------------------
// renew_attestation
// ---------------------------------------------------------------------------

/// Renews an attestation by re-verifying it and setting `renewed_at` to the
/// current clock time.
///
/// Per spec section 7.3.6, renewal requires re-verification: "A claim verified
/// once is a fact about the past. A claim that must be continuously renewed is
/// a fact about the present." This function calls [`verify_attestation`] before
/// updating the timestamp to ensure the attestation's signature, evidence,
/// expiry, and revocation status are still valid.
///
/// The returned attestation is a clone of the input with only `renewed_at`
/// updated. Because `renewed_at` is excluded from `canonical_attestation_bytes`,
/// the existing signature remains valid -- no re-signing is needed.
///
/// # Errors
///
/// - [`RenewalError::NotRenewable`] if `renewal_interval` is `None`.
/// - [`RenewalError::Expired`] if `expires_at` is set and `now >= expires_at`.
/// - [`RenewalError::VerificationFailed`] if [`verify_attestation`] fails.
pub fn renew_attestation(
    attestation: &Attestation,
    resolver: &impl DidPublicKeyResolver,
    clock: &impl Clock,
) -> Result<Attestation, RenewalError> {
    if attestation.renewal_interval.is_none() {
        return Err(RenewalError::NotRenewable {
            attestation_id: attestation.id.clone(),
        });
    }

    let now = clock.now();

    if let Some(expires_at) = attestation.expires_at
        && now >= expires_at
    {
        return Err(RenewalError::Expired {
            attestation_id: attestation.id.clone(),
            expired_at: expires_at,
        });
    }

    verify_attestation(attestation, resolver, clock).map_err(|e| {
        RenewalError::VerificationFailed {
            attestation_id: attestation.id.clone(),
            source: e,
        }
    })?;

    let mut renewed = attestation.clone();
    renewed.renewed_at = Some(now);
    Ok(renewed)
}

// ---------------------------------------------------------------------------
// RenewalChecker trait
// ---------------------------------------------------------------------------

/// Trait for checking whether an attestation needs renewal.
///
/// Enables platform-specific scheduling integration. Implementations may use
/// different clock sources or policies to determine renewal timing.
pub trait RenewalChecker {
    /// Returns `true` if the attestation is past its renewal interval and
    /// should be renewed.
    fn needs_renewal(&self, attestation: &Attestation) -> bool;
}

// ---------------------------------------------------------------------------
// DefaultRenewalChecker
// ---------------------------------------------------------------------------

/// Default implementation of [`RenewalChecker`].
///
/// Compares elapsed time since the last renewal (or issuance, if never renewed)
/// against the attestation's `renewal_interval`. Uses
/// `renewed_at.unwrap_or(issued_at)` as the base time, matching the freshness
/// pattern in [`check_attestation_freshness`](super::check_attestation_freshness).
pub struct DefaultRenewalChecker<C: Clock> {
    clock: C,
}

impl<C: Clock> DefaultRenewalChecker<C> {
    /// Creates a new checker with the given clock.
    #[must_use]
    pub const fn new(clock: C) -> Self {
        Self { clock }
    }
}

impl<C: Clock> RenewalChecker for DefaultRenewalChecker<C> {
    fn needs_renewal(&self, attestation: &Attestation) -> bool {
        let Some(interval) = attestation.renewal_interval else {
            return false;
        };

        let base_time = attestation.renewed_at.unwrap_or(attestation.issued_at);
        let now = self.clock.now();
        let elapsed = Duration::from_secs(now.saturating_sub(base_time));
        elapsed >= interval
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::trust::AttestationType;
    use crate::trust::attestation::{RevocationStatus, canonical_attestation_bytes};
    use scp_identity::cache::TestClock;

    struct TestResolver {
        keys: HashMap<String, Vec<u8>>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                keys: HashMap::new(),
            }
        }

        fn add_key(&mut self, did: &str, public_key: Vec<u8>) {
            self.keys.insert(did.to_owned(), public_key);
        }
    }

    impl DidPublicKeyResolver for TestResolver {
        fn resolve_public_key(&self, did: &str) -> Result<Vec<u8>, TrustError> {
            self.keys
                .get(did)
                .cloned()
                .ok_or_else(|| TrustError::AttestationSignatureInvalid {
                    attestation_id: String::new(),
                    reason: format!("DID not found: {did}"),
                })
        }
    }

    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key.to_bytes().to_vec())
    }

    fn make_signed_renewable_attestation(
        signing_key: &SigningKey,
        issued_at: u64,
        expires_at: Option<u64>,
        renewal_interval: Duration,
        renewed_at: Option<u64>,
    ) -> Attestation {
        let mut attestation = Attestation {
            id: "att-renewable".to_owned(),
            attestation_type: AttestationType::IdentityLink,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({"platform": "github"}),
            evidence: None,
            issued_at,
            expires_at,
            renewal_interval: Some(renewal_interval),
            renewed_at,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };
        let canonical = canonical_attestation_bytes(&attestation).unwrap();
        let sig = signing_key.sign(&canonical);
        attestation.signature = sig.to_bytes().to_vec();
        attestation
    }

    fn make_signed_non_renewable_attestation(
        signing_key: &SigningKey,
        issued_at: u64,
        expires_at: Option<u64>,
    ) -> Attestation {
        let mut attestation = Attestation {
            id: "att-non-renewable".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at,
            expires_at,
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![],
        };
        let canonical = canonical_attestation_bytes(&attestation).unwrap();
        let sig = signing_key.sign(&canonical);
        attestation.signature = sig.to_bytes().to_vec();
        attestation
    }

    fn make_unsigned_renewable_attestation(
        issued_at: u64,
        expires_at: Option<u64>,
        renewal_interval: Duration,
        renewed_at: Option<u64>,
    ) -> Attestation {
        Attestation {
            id: "att-renewable".to_owned(),
            attestation_type: AttestationType::IdentityLink,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({"platform": "github"}),
            evidence: None,
            issued_at,
            expires_at,
            renewal_interval: Some(renewal_interval),
            renewed_at,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
        }
    }

    // -------------------------------------------------------------------
    // renew_attestation tests
    // -------------------------------------------------------------------

    #[test]
    fn renew_updates_renewed_at() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(2000);
        let attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            Some(5000),
            Duration::from_secs(600),
            None,
        );

        let renewed = renew_attestation(&attestation, &resolver, &clock).unwrap();

        assert_eq!(renewed.renewed_at, Some(2000));
        assert_eq!(renewed.id, attestation.id);
        assert_eq!(renewed.issuer, attestation.issuer);
        assert_eq!(renewed.subject, attestation.subject);
        assert_eq!(renewed.issued_at, attestation.issued_at);
        assert_eq!(renewed.expires_at, attestation.expires_at);
        assert_eq!(renewed.renewal_interval, attestation.renewal_interval);
        assert_eq!(renewed.signature, attestation.signature);
    }

    #[test]
    fn renew_rejects_non_renewable() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(2000);
        let attestation = make_signed_non_renewable_attestation(&signing_key, 1000, Some(5000));

        let result = renew_attestation(&attestation, &resolver, &clock);

        assert!(result.is_err());
        match result {
            Err(RenewalError::NotRenewable { attestation_id }) => {
                assert_eq!(attestation_id, "att-non-renewable");
            }
            other => panic!("expected NotRenewable, got {other:?}"),
        }
    }

    #[test]
    fn renew_rejects_expired() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(6000);
        let attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            Some(5000),
            Duration::from_secs(600),
            None,
        );

        let result = renew_attestation(&attestation, &resolver, &clock);

        assert!(result.is_err());
        match result {
            Err(RenewalError::Expired {
                attestation_id,
                expired_at,
            }) => {
                assert_eq!(attestation_id, "att-renewable");
                assert_eq!(expired_at, 5000);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn renew_succeeds_without_expiry() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(999_999);
        let attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            None,
            Duration::from_secs(600),
            None,
        );

        let renewed = renew_attestation(&attestation, &resolver, &clock).unwrap();
        assert_eq!(renewed.renewed_at, Some(999_999));
    }

    #[test]
    fn renew_preserves_previous_renewed_at() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(3000);
        let attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            Some(5000),
            Duration::from_secs(600),
            Some(2000),
        );

        let renewed = renew_attestation(&attestation, &resolver, &clock).unwrap();
        assert_eq!(renewed.renewed_at, Some(3000));
    }

    #[test]
    fn renew_rejects_invalid_signature() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(2000);
        let mut attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            Some(5000),
            Duration::from_secs(600),
            None,
        );
        attestation.signature[0] ^= 0xff;

        let result = renew_attestation(&attestation, &resolver, &clock);

        assert!(result.is_err());
        match result {
            Err(RenewalError::VerificationFailed { attestation_id, .. }) => {
                assert_eq!(attestation_id, "att-renewable");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn renew_rejects_revoked_attestation() {
        let (signing_key, pubkey_bytes) = test_keypair();
        let mut resolver = TestResolver::new();
        resolver.add_key("did:key:issuer", pubkey_bytes);
        let clock = TestClock::new(2000);
        // Build an attestation that is signed WITH Revoked status so the
        // signature is valid, and verify_attestation reaches the revocation
        // check (not just the signature check).
        let mut attestation = Attestation {
            id: "att-renewable".to_owned(),
            attestation_type: AttestationType::IdentityLink,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({"platform": "github"}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(5000),
            renewal_interval: Some(Duration::from_secs(600)),
            renewed_at: None,
            revocation_status: RevocationStatus::Revoked {
                revoked_at: 1500,
                reason: Some("revoked for test".to_owned()),
                revoked_by: "did:key:issuer".into(),
            },
            signature: vec![],
        };
        let canonical = canonical_attestation_bytes(&attestation).unwrap();
        let sig = signing_key.sign(&canonical);
        attestation.signature = sig.to_bytes().to_vec();

        let result = renew_attestation(&attestation, &resolver, &clock);

        assert!(result.is_err());
        match result {
            Err(RenewalError::VerificationFailed {
                attestation_id,
                source,
            }) => {
                assert_eq!(attestation_id, "att-renewable");
                // Verify the underlying error is specifically AttestationRevoked,
                // not AttestationSignatureInvalid — proving we're testing the
                // revocation rejection path, not the signature path.
                assert!(
                    matches!(source, TrustError::AttestationRevoked { .. }),
                    "expected AttestationRevoked, got {source:?}",
                );
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn renew_rejects_unresolvable_issuer() {
        let (signing_key, _pubkey_bytes) = test_keypair();
        let resolver = TestResolver::new();
        let clock = TestClock::new(2000);
        let attestation = make_signed_renewable_attestation(
            &signing_key,
            1000,
            Some(5000),
            Duration::from_secs(600),
            None,
        );

        let result = renew_attestation(&attestation, &resolver, &clock);

        assert!(result.is_err());
        match result {
            Err(RenewalError::VerificationFailed { attestation_id, .. }) => {
                assert_eq!(attestation_id, "att-renewable");
            }
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // DefaultRenewalChecker tests
    // -------------------------------------------------------------------

    #[test]
    fn needs_renewal_true_when_past_interval() {
        let clock = TestClock::new(2000);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation =
            make_unsigned_renewable_attestation(1000, Some(5000), Duration::from_secs(600), None);

        assert!(checker.needs_renewal(&attestation));
    }

    #[test]
    fn needs_renewal_false_when_within_interval() {
        let clock = TestClock::new(1500);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation =
            make_unsigned_renewable_attestation(1000, Some(5000), Duration::from_secs(600), None);

        assert!(!checker.needs_renewal(&attestation));
    }

    #[test]
    fn needs_renewal_uses_issued_at_when_renewed_at_is_none() {
        let clock = TestClock::new(1700);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation =
            make_unsigned_renewable_attestation(1000, Some(5000), Duration::from_secs(600), None);

        assert!(
            checker.needs_renewal(&attestation),
            "1700 - 1000 = 700 >= 600, should need renewal"
        );
    }

    #[test]
    fn needs_renewal_uses_renewed_at_when_present() {
        let clock = TestClock::new(1700);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation = make_unsigned_renewable_attestation(
            1000,
            Some(5000),
            Duration::from_secs(600),
            Some(1500),
        );

        assert!(
            !checker.needs_renewal(&attestation),
            "1700 - 1500 = 200 < 600, should NOT need renewal"
        );
    }

    #[test]
    fn needs_renewal_false_for_non_renewable() {
        let clock = TestClock::new(999_999);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation = Attestation {
            id: "att-non-renewable".to_owned(),
            attestation_type: AttestationType::Endorsement,
            issuer: "did:key:issuer".into(),
            subject: "did:key:subject".into(),
            claim: serde_json::json!({}),
            evidence: None,
            issued_at: 1000,
            expires_at: Some(5000),
            renewal_interval: None,
            renewed_at: None,
            revocation_status: RevocationStatus::Active,
            signature: vec![0u8; 64],
        };

        assert!(
            !checker.needs_renewal(&attestation),
            "non-renewable attestation should never need renewal"
        );
    }

    #[test]
    fn needs_renewal_true_at_exact_boundary() {
        let clock = TestClock::new(1600);
        let checker = DefaultRenewalChecker::new(clock);
        let attestation =
            make_unsigned_renewable_attestation(1000, Some(5000), Duration::from_secs(600), None);

        assert!(
            checker.needs_renewal(&attestation),
            "1600 - 1000 = 600 >= 600, should need renewal at exact boundary"
        );
    }
}
