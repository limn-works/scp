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
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `key_id` does not parse as a
/// `u64`.
pub fn parse_handle(method: &str, key_id: &str) -> Result<KeyHandle, PlatformError> {
    key_id.parse::<u64>().map(KeyHandle::new).map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned a non-numeric key_id: {key_id}"
        ))
    })
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
pub const PSEUDONYM_PUBLIC_KEY_LEN: usize = 33;

/// Unpacks a `derive_pseudonym`-style return (`[pubkey(33) || key_id_utf8]`,
/// where `pubkey` is the SEC1 compressed P-256 pseudonym point) into a
/// validated [`PseudonymKeypair`].
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `bytes` is shorter than 34 bytes,
/// the key-id portion is not valid UTF-8, the key-id is not numeric, or the
/// public key is not a valid compressed P-256 point (a provider still
/// returning a 32-byte Ed25519 pseudonym fails here).
pub fn unpack_pseudonym(method: &str, bytes: &[u8]) -> Result<PseudonymKeypair, PlatformError> {
    if bytes.len() <= PSEUDONYM_PUBLIC_KEY_LEN {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned {} bytes, expected at least 34 \
             (33-byte compressed P-256 public key + key_id)",
            bytes.len()
        )));
    }
    let (public_key_bytes, key_id_bytes) = bytes.split_at(PSEUDONYM_PUBLIC_KEY_LEN);
    let key_id_str = std::str::from_utf8(key_id_bytes).map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} key_id portion is not valid UTF-8"
        ))
    })?;
    let key_id = parse_handle(method, key_id_str)?;
    PseudonymKeypair::new(public_key_bytes, key_id)
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

    #[test]
    fn unpack_pseudonym_accepts_pubkey_plus_key_id() {
        let mut bytes = REFERENCE_POINT.to_vec();
        bytes.extend_from_slice(b"123");
        let pseudo = unpack_pseudonym("derive_pseudonym", &bytes).expect("valid pseudonym unpacks");
        assert_eq!(pseudo.public_key().as_bytes(), &REFERENCE_POINT);
        assert_eq!(pseudo.key_handle().id(), 123);
    }

    #[test]
    fn unpack_pseudonym_rejects_invalid_point() {
        // A legacy 32-byte Ed25519 pseudonym + key id: the first 33 bytes are
        // not a compressed P-256 point (prefix 0xAB), so it fails closed.
        let mut legacy = vec![0xABu8; 32];
        legacy.extend_from_slice(b"12");
        assert!(matches!(
            unpack_pseudonym("derive_pseudonym", &legacy),
            Err(PlatformError::CustodyError(_))
        ));
        // A valid prefix with x = 2^256 - 1, which is not a field element.
        let mut not_field = vec![0x02u8];
        not_field.extend_from_slice(&[0xFFu8; 32]);
        not_field.extend_from_slice(b"7");
        assert!(matches!(
            unpack_pseudonym("derive_pseudonym", &not_field),
            Err(PlatformError::CustodyError(_))
        ));
    }

    #[test]
    fn unpack_pseudonym_rejects_short_input() {
        let bytes = REFERENCE_POINT; // exactly 33 — no key_id, below the 34 minimum.
        let err =
            unpack_pseudonym("derive_pseudonym", &bytes).expect_err("33-byte input has no key_id");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.derive_pseudonym returned 33 bytes, expected at least 34 \
                     (33-byte compressed P-256 public key + key_id)"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn unpack_pseudonym_rejects_non_utf8_key_id() {
        let mut bytes = REFERENCE_POINT.to_vec();
        // 0xFF is an invalid UTF-8 lead byte.
        bytes.push(0xFF);
        let err =
            unpack_pseudonym("derive_pseudonym", &bytes).expect_err("non-utf8 key_id is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.derive_pseudonym key_id portion is not valid UTF-8"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn unpack_pseudonym_rejects_non_numeric_key_id() {
        let mut bytes = REFERENCE_POINT.to_vec();
        bytes.extend_from_slice(b"xyz");
        let err = unpack_pseudonym("derive_rotatable_pseudonym", &bytes)
            .expect_err("non-numeric key_id is rejected");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.derive_rotatable_pseudonym returned a non-numeric key_id: xyz"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }
}
