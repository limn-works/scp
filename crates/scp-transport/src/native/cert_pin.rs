//! Certificate pinning for SCP relay connections (spec §9.13).
//!
//! The SDK SHOULD support certificate pinning for known relays. If did:web
//! is used as a fallback, certificate pinning for the resolution server is
//! mandatory (spec §9.6.2).
//!
//! # Design
//!
//! A pin is the SHA-256 fingerprint of the relay's TLS certificate
//! (DER-encoded). On first connection, the fingerprint is recorded. On
//! subsequent connections, the presented certificate is compared against
//! the stored pin. A mismatch rejects the connection.
//!
//! Pins are stored as serializable [`CertificatePin`] values. The storage
//! backend is provided by the caller (in-memory, SQLite, etc.) — this
//! module provides types and comparison logic only.
//!
//! See spec section 9.13 (Transport Security Requirements).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A stored certificate pin for a relay endpoint.
///
/// Contains the SHA-256 fingerprint of the relay's TLS certificate
/// (DER-encoded) as observed on first connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatePin {
    /// The relay URL this pin applies to (e.g., `wss://relay.example.com/scp/v1`).
    pub relay_url: String,
    /// SHA-256 fingerprint of the TLS certificate (DER-encoded), 32 bytes.
    pub fingerprint: [u8; 32],
    /// Unix timestamp (seconds) when this pin was first recorded.
    pub pinned_at: u64,
    /// Unix timestamp (seconds) when this pin was last successfully verified.
    pub last_verified_at: u64,
}

/// Result of checking a certificate against a stored pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertPinResult {
    /// No pin exists for this relay. The caller should record the
    /// presented certificate as the initial pin.
    FirstConnection,

    /// The presented certificate matches the stored pin.
    Consistent,

    /// The presented certificate does NOT match the stored pin.
    /// The connection MUST be rejected (spec §9.13).
    Violated {
        /// The expected fingerprint (from the stored pin).
        expected: [u8; 32],
        /// The actual fingerprint of the presented certificate.
        actual: [u8; 32],
    },
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate.
///
/// This is the standard SPKI (Subject Public Key Info) fingerprint
/// used for certificate pinning. The input should be the full
/// DER-encoded certificate bytes.
#[must_use]
pub fn certificate_fingerprint(der_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der_bytes);
    digest.into()
}

/// Checks a presented certificate against a stored pin.
///
/// Returns [`CertPinResult::FirstConnection`] if `stored` is `None`,
/// [`CertPinResult::Consistent`] if the fingerprint matches, or
/// [`CertPinResult::Violated`] if the fingerprint differs.
///
/// # Arguments
///
/// * `stored` — The previously stored certificate pin, or `None` if
///   this relay has not been connected to before.
/// * `presented_der` — The DER-encoded bytes of the TLS certificate
///   presented by the relay on the current connection.
#[must_use]
pub fn check_certificate_pin(
    stored: Option<&CertificatePin>,
    presented_der: &[u8],
) -> CertPinResult {
    let actual = certificate_fingerprint(presented_der);

    let Some(pin) = stored else {
        return CertPinResult::FirstConnection;
    };

    if pin.fingerprint == actual {
        CertPinResult::Consistent
    } else {
        CertPinResult::Violated {
            expected: pin.fingerprint,
            actual,
        }
    }
}

/// Creates a new [`CertificatePin`] from a presented certificate.
///
/// Used when [`CertPinResult::FirstConnection`] is returned to record
/// the initial pin.
#[must_use]
pub fn create_certificate_pin(
    relay_url: &str,
    presented_der: &[u8],
    now_secs: u64,
) -> CertificatePin {
    CertificatePin {
        relay_url: relay_url.to_owned(),
        fingerprint: certificate_fingerprint(presented_der),
        pinned_at: now_secs,
        last_verified_at: now_secs,
    }
}

/// Updates a certificate pin's `last_verified_at` timestamp.
///
/// Called after a successful connection where the pin was verified.
#[must_use]
pub fn update_pin_last_verified(pin: &CertificatePin, now_secs: u64) -> CertificatePin {
    CertificatePin {
        last_verified_at: now_secs,
        ..pin.clone()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Fake DER certificate bytes for testing.
    const CERT_A: &[u8] = b"fake-certificate-bytes-A";
    const CERT_B: &[u8] = b"fake-certificate-bytes-B";

    #[test]
    fn certificate_fingerprint_is_deterministic() {
        let fp1 = certificate_fingerprint(CERT_A);
        let fp2 = certificate_fingerprint(CERT_A);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_certs_produce_different_fingerprints() {
        let fp_a = certificate_fingerprint(CERT_A);
        let fp_b = certificate_fingerprint(CERT_B);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn first_connection_when_no_stored_pin() {
        let result = check_certificate_pin(None, CERT_A);
        assert_eq!(result, CertPinResult::FirstConnection);
    }

    #[test]
    fn consistent_when_fingerprint_matches() {
        let pin = create_certificate_pin("wss://relay.example.com/scp/v1", CERT_A, 1000);
        let result = check_certificate_pin(Some(&pin), CERT_A);
        assert_eq!(result, CertPinResult::Consistent);
    }

    #[test]
    fn violated_when_fingerprint_differs() {
        let pin = create_certificate_pin("wss://relay.example.com/scp/v1", CERT_A, 1000);
        let result = check_certificate_pin(Some(&pin), CERT_B);

        match result {
            CertPinResult::Violated { expected, actual } => {
                assert_eq!(expected, certificate_fingerprint(CERT_A));
                assert_eq!(actual, certificate_fingerprint(CERT_B));
            }
            other => panic!("expected Violated, got {other:?}"),
        }
    }

    #[test]
    fn create_certificate_pin_sets_fields() {
        let pin = create_certificate_pin("wss://relay.example.com/scp/v1", CERT_A, 5000);

        assert_eq!(pin.relay_url, "wss://relay.example.com/scp/v1");
        assert_eq!(pin.fingerprint, certificate_fingerprint(CERT_A));
        assert_eq!(pin.pinned_at, 5000);
        assert_eq!(pin.last_verified_at, 5000);
    }

    #[test]
    fn update_pin_last_verified_preserves_fingerprint() {
        let pin = create_certificate_pin("wss://relay.example.com/scp/v1", CERT_A, 1000);
        let updated = update_pin_last_verified(&pin, 2000);

        assert_eq!(updated.fingerprint, pin.fingerprint);
        assert_eq!(updated.relay_url, pin.relay_url);
        assert_eq!(updated.pinned_at, 1000);
        assert_eq!(updated.last_verified_at, 2000);
    }

    #[test]
    fn fingerprint_is_32_bytes() {
        let fp = certificate_fingerprint(CERT_A);
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn roundtrip_serialization() {
        let pin = create_certificate_pin("wss://relay.example.com/scp/v1", CERT_A, 1000);
        let bytes = rmp_serde::to_vec(&pin).unwrap();
        let restored: CertificatePin = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(restored, pin);
    }
}
