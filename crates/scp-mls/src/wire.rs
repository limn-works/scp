//! The one place SCP decodes MLS wire objects that arrive from a peer.
//!
//! `tls_codec` 0.4 (its `mls` feature) `debug_assert!`ed that a variable-length
//! vector header's length-of-length is at most 4 bytes, so in a build with
//! debug assertions on a hostile `KeyPackage`, Welcome or commit panicked the
//! decoder. `tls_codec` 0.5.0 returns `InvalidVectorLength` for that header in
//! every profile. Each parser here still runs the decoder under `catch_unwind`
//! and returns [`MlsError::DeserializationFailed`] for a decode error or a
//! panic, so a decoder assertion on peer bytes in any later version is a typed
//! error in every build profile, in every workspace that builds this crate.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A variable-length header byte whose top two bits are `0b11`: a
    /// length-of-length of 8 bytes, above the 4 the `mls` feature allows.
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

    /// Whether decoding `bytes` as `T` without `catch_unwind` fails at the
    /// length header, with `InvalidVectorLength`.
    fn raw_decode_hits_length_header<T: Deserialize>(bytes: &[u8]) -> bool {
        let mut reader = bytes;
        matches!(
            T::tls_deserialize(&mut reader),
            Err(tls_codec::Error::InvalidVectorLength)
        )
    }

    /// Each row of the test above reaches the decoder's length-header check:
    /// decoding it as the same type without `catch_unwind` fails with
    /// `InvalidVectorLength`. Without this control the test above could pass
    /// on bytes the decoder rejects before the header.
    #[test]
    fn hostile_length_header_reaches_the_decoder_length_check() {
        assert!(raw_decode_hits_length_header::<KeyPackageIn>(&hostile(&[
            0, 1, 0, 2
        ])));
        assert!(raw_decode_hits_length_header::<MlsMessageIn>(&hostile(&[
            0, 1, 0, 3, 0, 2
        ])));
        assert!(raw_decode_hits_length_header::<MlsMessageIn>(&hostile(&[
            0, 1, 0, 1
        ])));
        assert!(raw_decode_hits_length_header::<Welcome>(&hostile(&[0, 2])));
    }
}
