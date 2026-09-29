//! The one place SCP decodes MLS wire objects that arrive from a peer.
//!
//! `tls_codec` 0.4 (its `mls` feature) `debug_assert!`s that a variable-length
//! vector header's length-of-length is at most 4 bytes before it returns
//! `InvalidVectorLength` for exactly that input. The header byte comes from the
//! peer, so in a build with debug assertions on, a hostile `KeyPackage`, Welcome
//! or commit would panic the decoder where a release build rejects it. Each
//! parser here runs the decoder under `catch_unwind` and returns
//! [`MlsError::DeserializationFailed`] either way, so every build profile, in
//! every workspace that builds this crate, rejects the bytes with a typed error.
//!
//! On wasm32 (`panic = "abort"`) nothing is caught; the browser SDK ships a
//! release build, where the assertion is compiled out.
//!
//! No other module may call `tls_deserialize` on these types;
//! `scripts/check-deleted-primitives.sh` enforces it.

use std::panic::{AssertUnwindSafe, catch_unwind};

use openmls::prelude::{KeyPackageIn, MlsMessageIn, Welcome};
use tls_codec::Deserialize;

use crate::error::MlsError;

/// Decodes one `T` from the front of `bytes`, turning a decoder panic into an
/// error.
fn parse<T: Deserialize>(kind: &'static str, bytes: &[u8]) -> Result<T, MlsError> {
    let mut reader = bytes;
    match catch_unwind(AssertUnwindSafe(|| T::tls_deserialize(&mut reader))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(MlsError::DeserializationFailed(format!("{kind}: {e}"))),
        Err(_) => Err(MlsError::DeserializationFailed(format!(
            "{kind}: malformed length header"
        ))),
    }
}

/// Decodes an `MlsMessageIn` (a commit, a proposal, an application message or
/// a Welcome) received from a peer.
///
/// # Errors
///
/// [`MlsError::DeserializationFailed`] if the bytes are not a well-formed
/// `MlsMessage`.
pub fn parse_mls_message_in(bytes: &[u8]) -> Result<MlsMessageIn, MlsError> {
    parse("MLS message", bytes)
}

/// Decodes a `KeyPackageIn` received from a peer or a directory.
///
/// # Errors
///
/// [`MlsError::DeserializationFailed`] if the bytes are not a well-formed
/// `KeyPackage`.
pub fn parse_key_package_in(bytes: &[u8]) -> Result<KeyPackageIn, MlsError> {
    parse("key package", bytes)
}

/// Decodes a bare `Welcome` body.
///
/// # Errors
///
/// [`MlsError::DeserializationFailed`] if the bytes are not a well-formed
/// `Welcome`.
pub fn parse_welcome(bytes: &[u8]) -> Result<Welcome, MlsError> {
    parse("Welcome", bytes)
}

// Every test here drives tls_codec's debug assertion, so they need it on.
#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    /// A variable-length header byte whose top two bits are `0b11`: a
    /// length-of-length of 8 bytes, above the 4 the `mls` feature allows.
    /// `tls_codec` `debug_assert!`s on it before returning an error.
    const HOSTILE_LEN: u8 = 0xC0;

    /// Pads a hostile prefix so the decoder has bytes to read past the header.
    fn hostile(prefix: &[u8]) -> Vec<u8> {
        let mut bytes = prefix.to_vec();
        bytes.push(HOSTILE_LEN);
        bytes.extend_from_slice(&[0; 16]);
        bytes
    }

    /// Each parser returns an error, not a panic, for a hostile length header,
    /// in a build with debug assertions on. Rows:
    ///
    /// | row | bytes | hostile field |
    /// |---|---|---|
    /// | KeyPackage | version 1, suite 2 | `init_key` length |
    /// | Welcome-bodied MlsMessage | version 1, wire format 3, suite 2 | `secrets` length |
    /// | commit-bodied MlsMessage | version 1, wire format 1 (public message) | `group_id` length |
    /// | bare Welcome | suite 2 | `secrets` length |
    #[test]
    fn hostile_length_header_is_an_error_not_a_panic() {
        assert!(matches!(
            parse_key_package_in(&hostile(&[0, 1, 0, 2])),
            Err(MlsError::DeserializationFailed(_))
        ));
        assert!(matches!(
            parse_mls_message_in(&hostile(&[0, 1, 0, 3, 0, 2])),
            Err(MlsError::DeserializationFailed(_))
        ));
        assert!(matches!(
            parse_mls_message_in(&hostile(&[0, 1, 0, 1])),
            Err(MlsError::DeserializationFailed(_))
        ));
        assert!(matches!(
            parse_welcome(&hostile(&[0, 2])),
            Err(MlsError::DeserializationFailed(_))
        ));
    }

    /// Decodes `bytes` as `T` without `catch_unwind` and reports whether the
    /// decoder panicked.
    fn raw_decode_panics<T: Deserialize>(bytes: &[u8]) -> bool {
        catch_unwind(|| {
            let mut reader = bytes;
            let _ = T::tls_deserialize(&mut reader);
        })
        .is_err()
    }

    /// Each row of the test above reaches `tls_codec`'s assertion: decoding it
    /// as the same type without `catch_unwind` panics. Without this control
    /// the test above could pass on bytes the decoder rejects before the
    /// header.
    #[test]
    fn hostile_length_header_reaches_the_decoder_assertion() {
        assert!(raw_decode_panics::<KeyPackageIn>(&hostile(&[0, 1, 0, 2])));
        assert!(raw_decode_panics::<MlsMessageIn>(&hostile(&[
            0, 1, 0, 3, 0, 2
        ])));
        assert!(raw_decode_panics::<MlsMessageIn>(&hostile(&[0, 1, 0, 1])));
        assert!(raw_decode_panics::<Welcome>(&hostile(&[0, 2])));
    }
}
