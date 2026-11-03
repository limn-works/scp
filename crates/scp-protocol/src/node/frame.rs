//! The fixed prefix every node record frame of `09-security-model.md`
//! §9.10.12 shares: `version ‖ 32-byte identifier ‖ value`.
//!
//! §9.10.12 states three decoder rules for all five frames: read and check
//! `version` before any later byte, reject a frame shorter than the 33-byte
//! prefix, and reject a `value` longer than `Max blob size − 33`.
//! [`split_frame`] runs the three in that order, so each frame's decoder
//! starts from a checked `(identifier, value)` pair.

use scp_did::Identifier;

use crate::envelope::did_record::MAX_BLOB_SIZE;

/// `version` (1) and the 32-byte identifier field.
pub const RECORD_FRAME_PREFIX_LEN: usize = 33;

/// The longest `value` a frame carries: `Max blob size − 33` (§9.18.11).
pub const MAX_RECORD_FRAME_VALUE_LEN: usize = MAX_BLOB_SIZE - RECORD_FRAME_PREFIX_LEN;

/// Why a frame's fixed prefix is refused (§9.10.12 decoder rules 1 to 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FramePrefixError {
    /// The first byte is not the frame's version.
    #[error("frame version {found}, expected {expected}")]
    WrongVersion {
        /// The version the decoder implements.
        expected: u8,
        /// The first byte.
        found: u8,
    },
    /// The frame is shorter than the 33-byte prefix.
    #[error("frame is {0} bytes, shorter than the 33-byte prefix")]
    TooShort(usize),
    /// `value` is longer than `Max blob size − 33`.
    #[error("frame value is {0} bytes, more than 262111")]
    ValueTooLarge(usize),
}

/// Checks `version`, then the prefix length, then the `value` bound, and
/// returns the identifier field and `value`.
///
/// # Errors
///
/// [`FramePrefixError`] names the first rule the bytes break.
pub fn split_frame(bytes: &[u8], version: u8) -> Result<(Identifier, &[u8]), FramePrefixError> {
    match bytes.first() {
        Some(&found) if found == version => {}
        Some(&found) => {
            return Err(FramePrefixError::WrongVersion {
                expected: version,
                found,
            });
        }
        None => return Err(FramePrefixError::TooShort(0)),
    }
    let Some((prefix, value)) = bytes.split_first_chunk::<RECORD_FRAME_PREFIX_LEN>() else {
        return Err(FramePrefixError::TooShort(bytes.len()));
    };
    if value.len() > MAX_RECORD_FRAME_VALUE_LEN {
        return Err(FramePrefixError::ValueTooLarge(value.len()));
    }
    let mut identifier = [0u8; 32];
    identifier.copy_from_slice(&prefix[1..]);
    Ok((Identifier::from_bytes(identifier), value))
}

/// `version ‖ identifier ‖ value`.
#[must_use]
pub fn join_frame(version: u8, identifier: &Identifier, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_FRAME_PREFIX_LEN + value.len());
    out.push(version);
    out.extend_from_slice(identifier.as_bytes());
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_before_the_length() {
        assert_eq!(
            split_frame(&[9], 2),
            Err(FramePrefixError::WrongVersion {
                expected: 2,
                found: 9
            })
        );
        assert_eq!(split_frame(&[], 2), Err(FramePrefixError::TooShort(0)));
        assert_eq!(
            split_frame(&[2; 32], 2),
            Err(FramePrefixError::TooShort(32))
        );
    }

    #[test]
    fn value_at_the_bound_passes_and_one_past_fails() {
        let at = join_frame(4, &Identifier::ZERO, &vec![0; MAX_RECORD_FRAME_VALUE_LEN]);
        assert!(split_frame(&at, 4).is_ok());
        let past = join_frame(
            4,
            &Identifier::ZERO,
            &vec![0; MAX_RECORD_FRAME_VALUE_LEN + 1],
        );
        assert_eq!(
            split_frame(&past, 4),
            Err(FramePrefixError::ValueTooLarge(
                MAX_RECORD_FRAME_VALUE_LEN + 1
            ))
        );
    }

    #[test]
    fn the_identifier_field_round_trips() -> Result<(), FramePrefixError> {
        let identifier = Identifier::from_bytes([7; 32]);
        let frame = join_frame(5, &identifier, b"v");
        assert_eq!(split_frame(&frame, 5)?, (identifier, &b"v"[..]));
        Ok(())
    }
}
