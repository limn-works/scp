//! Shared byte/string parsing helpers for the callback-custody adapters.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges each adapt a caller-supplied
//! `KeyCustodyProvider` (a Python object / JS callback record / `UniFFI`
//! callback interface) to scp-platform's [`KeyCustody`](scp_platform::KeyCustody) trait. The provider
//! protocol speaks in raw byte arrays and opaque key-id strings; the adapters
//! must translate those into the typed [`KeyHandle`] / [`Pseudonym`] /
//! `[u8; 32]` surface. That translation — and the error messages it produces on
//! malformed provider returns — is mechanism-independent: it is identical
//! across all three bridges.
//!
//! These free functions hold that shared logic so the three bridges cannot
//! drift on either the parsing rules or the error-message text. The
//! `method: &str` parameter names the originating custody operation in error
//! messages (e.g. `"KeyCustodyProvider.derive_pseudonym returned ..."`),
//! preserving the format the `PyO3` reference bridge established.
//!
//! Pure byte/string operations — no crypto, no I/O. Gated behind the `custody`
//! feature (which pulls in `scp-platform` for the typed return values) rather
//! than folded into `resolvers`, since the resolver stack is far heavier.
//!
//! See ADR-006 and the per-bridge `CallbackKeyCustody` adapters.

use scp_platform::error::PlatformError;
use scp_platform::traits::{KeyHandle, Pseudonym};

/// Maps a host custody callback's failure to a [`PlatformError`], one mapping
/// for the `PyO3`, napi-rs and `UniFFI` bridges.
///
/// A failure carrying [`CRYPTO_4006`](crate::error_codes::CRYPTO_4006), the
/// key-not-found code, is [`PlatformError::KeyNotFound`]. A failure with any
/// other code, or with none, is [`PlatformError::CustodyError`] carrying the
/// host's code and message.
#[must_use]
pub fn host_failure(method: &str, code: Option<&str>, message: &str) -> PlatformError {
    if code == Some(crate::error_codes::CRYPTO_4006) {
        return PlatformError::KeyNotFound;
    }
    let code = code.map(|c| format!(" ({c})")).unwrap_or_default();
    PlatformError::CustodyError(format!(
        "KeyCustodyProvider.{method} failed{code}: {message}"
    ))
}

/// Parses a numeric key-id string (as returned by a `KeyCustodyProvider`) into
/// a [`KeyHandle`].
///
/// Only the canonical decimal form is accepted (the form `u64::to_string`
/// writes, which is what every bridge sends back to the host), so one host key
/// has exactly one spelling: `"007"`, `"+7"` and `" 7"` are rejected rather
/// than aliased to handle 7.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `key_id` does not parse as a
/// `u64`, or parses but is not in canonical decimal form.
pub fn parse_handle(method: &str, key_id: &str) -> Result<KeyHandle, PlatformError> {
    let id = key_id.parse::<u64>().map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned a non-numeric key_id: {key_id}"
        ))
    })?;
    if id.to_string() != key_id {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned a non-canonical key_id: {key_id:?}"
        )));
    }
    Ok(KeyHandle::new(id))
}

/// Coerces a 32-byte custody return into a fixed array.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `bytes` is not exactly 32 bytes.
pub fn expect_32(method: &str, bytes: &[u8]) -> Result<[u8; 32], PlatformError> {
    bytes.try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned {} bytes, expected 32",
            bytes.len()
        ))
    })
}

/// Validates the point a host's `derive_pseudonym` or
/// `derive_rotatable_pseudonym` returned into a [`Pseudonym`] (ADR-021's
/// 2026-09-29 amendment).
///
/// # Errors
///
/// Returns [`PlatformError::PseudonymRejected`] naming `method` and the reason
/// when `point` is not a 33-byte SEC1 compressed point on P-256 (a provider
/// still returning a 32-byte Ed25519 pseudonym fails here).
pub fn parse_pseudonym(method: &str, point: &[u8]) -> Result<Pseudonym, PlatformError> {
    Pseudonym::from_point(point).map_err(|e| match e {
        PlatformError::PseudonymRejected(reason) => {
            PlatformError::PseudonymRejected(format!("KeyCustodyProvider.{method}: {reason}"))
        }
        other => other,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn host_failure_maps_only_crypto_4006_to_key_not_found() {
        use crate::error_codes as codes;
        assert!(matches!(
            host_failure("sign", Some(codes::CRYPTO_4006), "gone"),
            PlatformError::KeyNotFound
        ));
        for code in [
            Some(codes::CRYPTO_4001),
            Some(codes::CRYPTO_4060),
            Some("x"),
            None,
        ] {
            match host_failure("sign", code, "hsm offline") {
                PlatformError::CustodyError(m) => {
                    assert!(m.contains("KeyCustodyProvider.sign failed"), "{m}");
                    assert!(m.contains("hsm offline"), "{m}");
                    if let Some(c) = code {
                        assert!(m.contains(c), "{m}");
                    }
                }
                other => panic!("{code:?} must be a custody error, got {other:?}"),
            }
        }
    }

    /// Every [`PlatformError`] variant reaches a bridge with one code:
    /// key-not-found is `SCP-CRYPTO-4006`, a rejected host pseudonym
    /// `SCP-IDENT-1055` (ADR-021, 2026-09-29 amendment), and every other
    /// variant `SCP-CRYPTO-4060`.
    #[test]
    fn custody_failure_code_covers_every_platform_error() {
        use crate::error_codes as codes;
        let table = [
            (PlatformError::KeyNotFound, codes::CRYPTO_4006),
            (
                PlatformError::PseudonymRejected("x".to_owned()),
                codes::IDENT_1055,
            ),
            (
                PlatformError::WrongKeyType {
                    expected: scp_platform::traits::KeyType::Ed25519,
                    actual: scp_platform::traits::KeyType::X25519,
                },
                codes::CRYPTO_4060,
            ),
            (
                PlatformError::StorageError("x".to_owned()),
                codes::CRYPTO_4060,
            ),
            (
                PlatformError::AttestationError("x".to_owned()),
                codes::CRYPTO_4060,
            ),
            (PlatformError::PushError("x".to_owned()), codes::CRYPTO_4060),
            (
                PlatformError::CustodyError("x".to_owned()),
                codes::CRYPTO_4060,
            ),
            (PlatformError::Unsupported("x"), codes::CRYPTO_4060),
        ];
        for (error, expected) in table {
            assert_eq!(
                codes::custody_failure_code(&scp_crypto::CustodyFailure::from(&error)),
                expected,
                "{error:?}"
            );
        }
    }

    /// §25.2 reference key, compressed:
    /// `033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027`.
    const REFERENCE_POINT: [u8; 33] = [
        0x03, 0x3b, 0x1c, 0xac, 0x23, 0xf4, 0x5c, 0xf1, 0xcd, 0xfd, 0xf0, 0xb3, 0x2f, 0x8f, 0x77,
        0x7b, 0x99, 0x16, 0x6c, 0x1b, 0x69, 0x64, 0x9c, 0x22, 0x95, 0xb1, 0x51, 0x78, 0x83, 0xd4,
        0x7f, 0x30, 0x27,
    ];

    #[test]
    fn parse_handle_accepts_numeric() {
        let handle = parse_handle("generate_keypair", "42").expect("numeric key_id parses");
        assert_eq!(handle.id(), 42);
    }

    #[test]
    fn parse_handle_rejects_non_numeric() {
        let err = parse_handle("generate_keypair", "not-a-number")
            .expect_err("non-numeric key_id is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.generate_keypair returned a non-numeric key_id: not-a-number"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn expect_32_accepts_exactly_32() {
        let bytes = [7u8; 32];
        let arr = expect_32("dh_agree", &bytes).expect("32 bytes coerces");
        assert_eq!(arr, bytes);
    }

    #[test]
    fn expect_32_rejects_wrong_length_with_exact_message() {
        let bytes = [0u8; 31];
        let err = expect_32("dh_agree", &bytes).expect_err("31 bytes is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.dh_agree returned 31 bytes, expected 32"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    /// Asserts that `err` is the `CustodyError` variant; tests assert the
    /// variant, never the message text.
    fn assert_custody_error(err: &PlatformError) {
        assert!(
            matches!(err, PlatformError::CustodyError(_)),
            "expected CustodyError, got {err:?}"
        );
    }

    #[test]
    fn parse_pseudonym_accepts_a_compressed_point() {
        let pseudo =
            parse_pseudonym("derive_pseudonym", &REFERENCE_POINT).expect("valid pseudonym parses");
        assert_eq!(pseudo.public_key().to_compressed(), REFERENCE_POINT);
    }

    /// Each malformed point is rejected as `PseudonymRejected`, and the message
    /// names the method and the reason for that row: the length for a wrong
    /// length, the leading byte for a bad prefix, and the curve for an x with
    /// no point.
    #[test]
    fn parse_pseudonym_rejects_invalid_points() {
        let reject = |bytes: &[u8], reason: &str| match parse_pseudonym("derive_pseudonym", bytes)
            .expect_err("invalid point rejected")
        {
            PlatformError::PseudonymRejected(m) => {
                assert!(
                    m.starts_with("KeyCustodyProvider.derive_pseudonym: "),
                    "{m}"
                );
                assert!(m.contains(reason), "{reason:?} not in {m}");
            }
            other => panic!("expected PseudonymRejected, got {other:?}"),
        };
        // Wrong lengths: 32 (a legacy Ed25519 key), 34, and 65 (an
        // uncompressed point, which `from_sec1` alone would accept).
        reject(&REFERENCE_POINT[1..], "got 32 bytes");
        let mut long = REFERENCE_POINT.to_vec();
        long.push(0x00);
        reject(&long, "got 34 bytes");
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        reject(&uncompressed, "got 65 bytes");
        // Bad prefix: 33 bytes led by 0x04 (the uncompressed tag).
        let mut bad_prefix = REFERENCE_POINT;
        bad_prefix[0] = 0x04;
        reject(&bad_prefix, "invalid leading byte 0x04");
        // Off-curve x: x = 1 is a field element, but 1 - 3 + b is a quadratic
        // non-residue mod p, so no y exists.
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 0x01;
        reject(&off_curve, "not on the curve");
        // x = 2^256 - 1 is not a field element at all.
        let mut not_field = [0xFFu8; 33];
        not_field[0] = 0x02;
        reject(&not_field, "not on the curve");
    }

    #[test]
    fn parse_handle_rejects_non_canonical_ids() {
        for id in ["007", "+7", "00"] {
            assert_custody_error(
                &parse_handle("derive_pseudonym", id).expect_err("non-canonical id rejected"),
            );
        }
        // `u64::from_str` already refuses surrounding whitespace.
        for id in [" 7", "7 "] {
            assert_custody_error(&parse_handle("derive_pseudonym", id).expect_err("rejected"));
        }
        assert_eq!(parse_handle("m", "0").expect("canonical zero").id(), 0);
        assert_eq!(
            parse_handle("m", "18446744073709551615")
                .expect("u64::MAX")
                .id(),
            u64::MAX
        );
    }
}
