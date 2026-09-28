//! Shared byte/string parsing helpers for the callback-custody adapters.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges each adapt a caller-supplied
//! `KeyCustodyProvider` (a Python object / JS callback record / `UniFFI`
//! callback interface) to scp-platform's [`KeyCustody`](scp_platform::KeyCustody) trait. The provider
//! protocol speaks in raw byte arrays and opaque key-id strings; the adapters
//! must translate those into the typed [`KeyHandle`] / [`PseudonymKeypair`] /
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
use scp_platform::traits::{KeyHandle, PseudonymKeypair};

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

/// Length of the pseudonym public key a provider returns: a SEC1 compressed
/// P-256 point (§9.10.4).
pub const PSEUDONYM_PUBLIC_KEY_LEN: usize = scp_crypto::p256::COMPRESSED_POINT_LEN;

/// Validates a structured `derive_pseudonym`-style return (`public_key`,
/// `key_id`) into a [`PseudonymKeypair`].
///
/// The host returns the two fields separately; no byte-splitting happens here,
/// so a key id can never be read as part of the point or the reverse.
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `key_id` is not numeric or
/// `public_key` is not a 33-byte SEC1 compressed point on P-256 (a provider
/// still returning a 32-byte Ed25519 pseudonym fails here).
pub fn parse_pseudonym(
    method: &str,
    public_key: &[u8],
    key_id: &str,
) -> Result<PseudonymKeypair, PlatformError> {
    let handle = parse_handle(method, key_id)?;
    PseudonymKeypair::new(public_key, handle)
        .map_err(|e| PlatformError::CustodyError(format!("KeyCustodyProvider.{method}: {e}")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn parse_pseudonym_accepts_point_and_key_id() {
        let pseudo = parse_pseudonym("derive_pseudonym", &REFERENCE_POINT, "123")
            .expect("valid pseudonym parses");
        assert_eq!(pseudo.public_key().as_bytes(), &REFERENCE_POINT);
        assert_eq!(pseudo.key_handle().id(), 123);
    }

    /// Every malformed point reaches a distinct rejection path in
    /// `P256PublicKey::from_sec1` (length, prefix, curve equation).
    #[test]
    fn parse_pseudonym_rejects_invalid_points() {
        let reject = |bytes: &[u8]| {
            assert_custody_error(
                &parse_pseudonym("derive_pseudonym", bytes, "7")
                    .expect_err("invalid point rejected"),
            );
        };
        // Wrong lengths: 32 (a legacy Ed25519 key) and 34.
        reject(&REFERENCE_POINT[1..]);
        let mut long = REFERENCE_POINT.to_vec();
        long.push(0x00);
        reject(&long);
        // Bad prefix: 33 bytes led by 0x04 (the uncompressed tag).
        let mut bad_prefix = REFERENCE_POINT;
        bad_prefix[0] = 0x04;
        reject(&bad_prefix);
        // Off-curve x: x = 1 is a field element, but 1 - 3 + b is a quadratic
        // non-residue mod p, so no y exists.
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 0x01;
        reject(&off_curve);
        // x = 2^256 - 1 is not a field element at all.
        let mut not_field = [0xFFu8; 33];
        not_field[0] = 0x02;
        reject(&not_field);
    }

    /// The fail-open counterexample against the old concatenated return: a
    /// 32-byte Ed25519 key `K` with key id `"22"` concatenated to `K || "22"`,
    /// whose first 33 bytes `K || 0x32` happen to be a valid P-256 point, so the
    /// split parse accepted it as a pseudonym with handle 2. With separate fields
    /// the 32-byte key is rejected on length, and a host that forwards the
    /// concatenated point anyway fails the `public_key(key_id)` binding.
    #[test]
    fn legacy_concatenation_counterexample_is_rejected() {
        let legacy_key: [u8; 32] = [
            0x02, 0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb,
            0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3,
            0x06, 0x17, 0xaf, 0xa0,
        ];
        assert_custody_error(
            &parse_pseudonym("derive_pseudonym", &legacy_key, "22").expect_err("32 bytes rejected"),
        );

        // The old split's first 33 bytes are a valid point; the
        // `public_key(key_id)` binding in `callback_custody::derive_pseudonym`
        // rejects a host that forwards them (tested there).
        let mut old_split_point = legacy_key.to_vec();
        old_split_point.push(b'2');
        parse_pseudonym("derive_pseudonym", &old_split_point, "2")
            .expect("the old split's first 33 bytes are a valid point");
    }

    #[test]
    fn parse_pseudonym_rejects_non_numeric_key_id() {
        assert_custody_error(
            &parse_pseudonym("derive_rotatable_pseudonym", &REFERENCE_POINT, "xyz")
                .expect_err("non-numeric key_id is rejected"),
        );
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
