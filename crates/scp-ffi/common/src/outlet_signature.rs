//! Shared §5.4.1 operator-signature attachment for outlet registration.
//!
//! `register_outlet` verifies that a registration carries an Ed25519 signature
//! by the key its `operator_did` encodes, so every bridge must put a real
//! signature on a registration before it calls that function. Two callers can
//! produce one:
//!
//! 1. **The operator registers its own outlet.** The bridge holds the
//!    operator's key in its own key custody, signs the §5.4.1 V2 canonical
//!    preimage, and writes the result into `signature`.
//! 2. **A registrant registers someone else's outlet.** The operator signs the
//!    preimage out of band and hands the registrant the 64 bytes, which the
//!    registrant passes as `operator_signature`.
//!
//! When neither holds, the bridge rejects the registration. It never writes an
//! empty signature and never substitutes its own key for the operator's, so a
//! stored registration always names an operator that signed for it.
//!
//! Each bridge reaches key custody through its own registry and its own async
//! model, so this module keeps the per-bridge signing step in a caller-supplied
//! closure and owns only the decision, the length check, and the error prose —
//! the three parts that must read identically across `PyO3`, napi-rs, and
//! `UniFFI`.
//!
//! Requires the `resolvers` feature (scp-core).

use scp_core::context::outlets::{OutletRegistration, compute_outlet_registration_canonical_bytes};

/// Ed25519 signature width in bytes.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Why a bridge could not put a §5.4.1 operator signature on a registration.
///
/// Each bridge maps every variant onto its own error type and error code and
/// formats the message from [`core::fmt::Display`], so the three bridges report
/// the same condition with the same words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorSignatureError {
    /// The caller supplied no signature and the bridge holds no key for
    /// `operator_did`, so nothing can sign the registration.
    OperatorKeyUnavailable {
        /// The operator DID the registration names.
        operator_did: String,
    },
    /// The caller supplied a signature of the wrong width.
    MalformedSignature {
        /// The operator DID the registration names.
        operator_did: String,
        /// How many bytes the caller supplied.
        actual_len: usize,
    },
    /// The bridge holds the operator's key but key custody refused to sign.
    CustodySigningFailed {
        /// The operator DID the registration names.
        operator_did: String,
        /// The detail key custody reported.
        detail: String,
    },
    /// Key custody returned a value that is not an Ed25519 signature.
    CustodyReturnedWrongWidth {
        /// The operator DID the registration names.
        operator_did: String,
        /// How many bytes key custody returned.
        actual_len: usize,
    },
}

impl core::fmt::Display for OperatorSignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperatorKeyUnavailable { operator_did } => write!(
                f,
                "outlet registration names operator '{operator_did}', but this bridge holds no \
                 key for that DID and the caller supplied no operator_signature — §5.4.1 \
                 requires the operator to sign the registration, so either create the \
                 operator identity on this bridge or pass the operator's 64-byte signature \
                 over the canonical registration bytes"
            ),
            Self::MalformedSignature {
                operator_did,
                actual_len,
            } => write!(
                f,
                "operator_signature for '{operator_did}' is {actual_len} bytes; §5.4.1 \
                 requires exactly {ED25519_SIGNATURE_LEN} (Ed25519)"
            ),
            Self::CustodySigningFailed {
                operator_did,
                detail,
            } => write!(
                f,
                "key custody refused to sign the outlet registration for operator \
                 '{operator_did}': {detail}"
            ),
            Self::CustodyReturnedWrongWidth {
                operator_did,
                actual_len,
            } => write!(
                f,
                "key custody returned a {actual_len}-byte value when signing the outlet \
                 registration for operator '{operator_did}'; Ed25519 signatures are \
                 {ED25519_SIGNATURE_LEN} bytes"
            ),
        }
    }
}

impl std::error::Error for OperatorSignatureError {}

/// Returns the bytes an operator signs for `registration` — the §5.4.1 V2
/// canonical digest.
///
/// A bridge computes these bytes, hands them to key custody, and writes the
/// resulting signature back with [`accept_custody_signature`]. The preimage
/// omits `signature` itself, so a bridge computes it before it fills that
/// field in.
#[must_use]
pub fn registration_signing_preimage(registration: &OutletRegistration) -> Vec<u8> {
    compute_outlet_registration_canonical_bytes(registration).to_vec()
}

/// Accepts a signature the caller supplied for `operator_did`, checking its
/// width.
///
/// # Errors
///
/// Returns [`OperatorSignatureError::MalformedSignature`] when the caller
/// supplied a value that is not 64 bytes.
pub fn accept_supplied_signature(
    operator_did: &str,
    supplied: Vec<u8>,
) -> Result<Vec<u8>, OperatorSignatureError> {
    if supplied.len() == ED25519_SIGNATURE_LEN {
        Ok(supplied)
    } else {
        Err(OperatorSignatureError::MalformedSignature {
            operator_did: operator_did.to_owned(),
            actual_len: supplied.len(),
        })
    }
}

/// Accepts a signature key custody produced for `operator_did`, checking its
/// width.
///
/// # Errors
///
/// Returns [`OperatorSignatureError::CustodyReturnedWrongWidth`] when key
/// custody returned a value that is not 64 bytes.
pub fn accept_custody_signature(
    operator_did: &str,
    produced: Vec<u8>,
) -> Result<Vec<u8>, OperatorSignatureError> {
    if produced.len() == ED25519_SIGNATURE_LEN {
        Ok(produced)
    } else {
        Err(OperatorSignatureError::CustodyReturnedWrongWidth {
            operator_did: operator_did.to_owned(),
            actual_len: produced.len(),
        })
    }
}

/// Reports that the bridge can neither sign for `operator_did` nor read a
/// caller-supplied signature.
///
/// A bridge calls this on the branch where its identity registry holds no
/// entry for the operator DID, so the three bridges emit the same refusal.
#[must_use]
pub fn operator_key_unavailable(operator_did: &str) -> OperatorSignatureError {
    OperatorSignatureError::OperatorKeyUnavailable {
        operator_did: operator_did.to_owned(),
    }
}

/// Reports that key custody refused to sign for `operator_did`.
#[must_use]
pub fn custody_signing_failed(operator_did: &str, detail: &str) -> OperatorSignatureError {
    OperatorSignatureError::CustodySigningFailed {
        operator_did: operator_did.to_owned(),
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn registration(operator_did: &str) -> OutletRegistration {
        OutletRegistration {
            outlet_id: "outlet-1".to_owned(),
            kind: scp_core::context::outlets::OutletKind::Action,
            name: "calculator".to_owned(),
            description: "adds two numbers".to_owned(),
            schema: scp_core::context::outlets::OutletSchema {
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
                aggregate_schema: None,
            },
            implementation_hash: [0x11; 32],
            test_vectors: vec![],
            operator_did: operator_did.into(),
            cost: None,
            message_catalog: Vec::new(),
            registered_at: 7,
            signature: Vec::new(),
        }
    }

    #[test]
    fn preimage_ignores_the_signature_field() {
        let unsigned = registration("did:dht:zoperator");
        let mut signed = unsigned.clone();
        signed.signature = vec![0xAB; 64];

        assert_eq!(
            registration_signing_preimage(&unsigned),
            registration_signing_preimage(&signed),
            "a bridge computes the preimage before it writes the signature, so the two must match"
        );
    }

    #[test]
    fn preimage_changes_when_a_covered_field_changes() {
        let base = registration("did:dht:zoperator");
        let mut edited = base.clone();
        edited.description = "adds two numbers and phones home".to_owned();

        assert_ne!(
            registration_signing_preimage(&base),
            registration_signing_preimage(&edited),
            "§5.4.1 commits description_hash, so the preimage must change"
        );
    }

    #[test]
    fn supplied_signature_of_the_wrong_width_is_rejected() {
        let err = accept_supplied_signature("did:dht:zoperator", vec![0x01; 63])
            .expect_err("63 bytes is not an Ed25519 signature");
        assert_eq!(
            err,
            OperatorSignatureError::MalformedSignature {
                operator_did: "did:dht:zoperator".to_owned(),
                actual_len: 63,
            }
        );
        assert!(err.to_string().contains("64"));
    }

    #[test]
    fn supplied_signature_of_the_right_width_passes_through() {
        let bytes = vec![0x02; 64];
        assert_eq!(
            accept_supplied_signature("did:dht:zoperator", bytes.clone()).unwrap(),
            bytes
        );
    }

    #[test]
    fn empty_supplied_signature_is_rejected() {
        let err = accept_supplied_signature("did:dht:zoperator", Vec::new())
            .expect_err("an empty signature must never reach register_outlet");
        assert!(matches!(
            err,
            OperatorSignatureError::MalformedSignature { actual_len: 0, .. }
        ));
    }

    #[test]
    fn custody_signature_of_the_wrong_width_is_rejected() {
        let err = accept_custody_signature("did:dht:zoperator", vec![0x03; 32])
            .expect_err("32 bytes is not an Ed25519 signature");
        assert!(matches!(
            err,
            OperatorSignatureError::CustodyReturnedWrongWidth { actual_len: 32, .. }
        ));
    }

    #[test]
    fn unavailable_operator_key_message_names_the_did_and_the_two_ways_out() {
        let message = operator_key_unavailable("did:dht:zoperator").to_string();
        assert!(message.contains("did:dht:zoperator"));
        assert!(message.contains("operator_signature"));
        assert!(message.contains("§5.4.1"));
    }

    #[test]
    fn custody_failure_message_carries_the_custody_detail() {
        let message =
            custody_signing_failed("did:dht:zoperator", "key handle destroyed").to_string();
        assert!(message.contains("key handle destroyed"));
        assert!(message.contains("did:dht:zoperator"));
    }
}
