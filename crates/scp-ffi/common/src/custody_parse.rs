//! Shared byte/string parsing helpers for the callback-custody adapters.
//!
//! The `PyO3`, napi-rs, and `UniFFI` bridges each adapt a caller-supplied
//! `KeyCustodyProvider` (a Python object / JS callback record / `UniFFI`
//! callback interface) to scp-platform's [`KeyCustody`] trait. The provider
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
//! than folded into `resolvers`, since the resolver stack is far heavier and
//! WASM does not use the callback-custody path (ADR-034).
//!
//! See ADR-006 and the per-bridge `CallbackKeyCustody` adapters.

use scp_platform::error::PlatformError;
use scp_platform::traits::{KeyHandle, PseudonymKeypair, PublicKey};

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

/// Unpacks a `derive_pseudonym`-style return (`[pubkey(32) || key_id_utf8]`)
/// into a [`PseudonymKeypair`].
///
/// # Errors
///
/// Returns [`PlatformError::CustodyError`] if `bytes` is shorter than 33 bytes,
/// the key-id portion is not valid UTF-8, or the key-id is not numeric.
pub fn unpack_pseudonym(method: &str, bytes: &[u8]) -> Result<PseudonymKeypair, PlatformError> {
    if bytes.len() < 33 {
        return Err(PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} returned {} bytes, expected at least 33 \
             (32 public key + key_id)",
            bytes.len()
        )));
    }
    let public_key_bytes = &bytes[..32];
    let key_id_str = std::str::from_utf8(&bytes[32..]).map_err(|_| {
        PlatformError::CustodyError(format!(
            "KeyCustodyProvider.{method} key_id portion is not valid UTF-8"
        ))
    })?;
    let key_id = parse_handle(method, key_id_str)?;
    Ok(PseudonymKeypair {
        public_key: PublicKey::new(public_key_bytes.to_vec()),
        key_handle: key_id,
    })
}

/// Builds the extended context-id input for a rotatable pseudonym derivation.
///
/// The callback-custody protocol exposes only a single `derive_pseudonym`
/// method, so the rotatable variant is synthesized by appending the big-endian
/// epoch and the `v2` domain separator to the caller-supplied `context_id`,
/// then delegating to `derive_pseudonym`.
///
/// Layout: `context_id || epoch.to_be_bytes() (8) || b"scp-pseudonym-v2" (16)`.
///
/// This is the canonical recipe defined in `scp-platform`
/// `KeyCustody::derive_rotatable_pseudonym` (traits.rs) — "all implementations
/// MUST produce identical output" — so the byte ordering is fixed by the
/// protocol, not by any single bridge. There is deliberately NO length
/// separator between `context_id` and the epoch: the epoch is always exactly 8
/// big-endian bytes appended directly after the caller-supplied `context_id`,
/// and the trailing domain separator is a fixed 16-byte literal. A length
/// prefix would change the produced bytes and is therefore a wire-format change
/// that must originate upstream in the spec/ADR and `scp-platform` (and be
/// applied identically across all bridges and the native custody backends) — it
/// cannot be introduced here without breaking cross-bridge and over-time
/// pseudonym derivation parity.
#[must_use]
pub fn extend_context_id_for_rotation(context_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut extended = context_id.to_vec();
    extended.extend_from_slice(&epoch.to_be_bytes());
    extended.extend_from_slice(b"scp-pseudonym-v2");
    extended
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
        let mut bytes = vec![0xABu8; 32];
        bytes.extend_from_slice(b"123");
        let pseudo = unpack_pseudonym("derive_pseudonym", &bytes).expect("valid pseudonym unpacks");
        assert_eq!(pseudo.public_key.as_bytes(), &[0xABu8; 32]);
        assert_eq!(pseudo.key_handle.id(), 123);
    }

    #[test]
    fn unpack_pseudonym_rejects_short_input() {
        let bytes = [0u8; 32]; // exactly 32 — no key_id, below the 33 minimum.
        let err =
            unpack_pseudonym("derive_pseudonym", &bytes).expect_err("32-byte input has no key_id");
        match err {
            PlatformError::CustodyError(msg) => {
                assert_eq!(
                    msg,
                    "KeyCustodyProvider.derive_pseudonym returned 32 bytes, expected at least 33 \
                     (32 public key + key_id)"
                );
            }
            other => panic!("expected CustodyError, got {other:?}"),
        }
    }

    #[test]
    fn unpack_pseudonym_rejects_non_utf8_key_id() {
        let mut bytes = vec![0u8; 32];
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
        let mut bytes = vec![0u8; 32];
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

    #[test]
    fn extend_context_id_for_rotation_byte_layout() {
        let context_id = b"ctx";
        let epoch: u64 = 5;
        let extended = extend_context_id_for_rotation(context_id, epoch);

        // Layout: context_id || epoch_BE(8) || "scp-pseudonym-v2" (16 bytes).
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ctx");
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]); // 5 as 8 big-endian bytes
        expected.extend_from_slice(b"scp-pseudonym-v2");

        assert_eq!(extended, expected);
        assert_eq!(extended.len(), 3 + 8 + 16);
        // Domain separator is exactly the trailing 16 bytes.
        assert_eq!(&extended[extended.len() - 16..], b"scp-pseudonym-v2");
        // Epoch occupies the 8 bytes immediately after context_id.
        assert_eq!(&extended[3..11], &epoch.to_be_bytes());
    }
}
