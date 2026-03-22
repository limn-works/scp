//! Bucket padding for SCP envelope payloads.
//!
//! Payloads are padded to fixed bucket sizes before encryption to prevent
//! relays from correlating message types by size. The padding format appends
//! zero bytes followed by a 4-byte big-endian length suffix indicating the
//! original payload length.
//!
//! **Bucket sizes:** 256 B, 1 KB, 4 KB, 16 KB, 64 KB, 256 KB.
//!
//! See ADR-002 in `.docs/adrs/phase-1.md` for the full padding design.

use super::EnvelopeError;

/// Fixed bucket sizes in bytes. Payloads are padded to the smallest bucket
/// that can contain the payload plus the 4-byte length suffix.
pub const BUCKET_SIZES: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262_144];

/// Size of the big-endian length suffix appended to padded payloads.
const LENGTH_SUFFIX_SIZE: usize = 4;

/// Pads `payload` to the next bucket boundary.
///
/// The output format is:
/// ```text
/// [original payload bytes] [zero padding bytes] [4-byte BE original length]
/// ```
///
/// The total output length equals the smallest bucket size that can contain
/// `payload.len() + 4` bytes (the 4-byte length suffix).
///
/// # Errors
///
/// Returns [`EnvelopeError::PayloadTooLarge`] if the payload plus the 4-byte
/// length suffix exceeds the largest bucket size (256 KB).
pub fn pad_to_bucket(payload: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let needed =
        payload
            .len()
            .checked_add(LENGTH_SUFFIX_SIZE)
            .ok_or(EnvelopeError::PayloadTooLarge {
                size: payload.len(),
                max: BUCKET_SIZES[BUCKET_SIZES.len() - 1],
            })?;

    let bucket_size =
        BUCKET_SIZES
            .iter()
            .find(|&&b| b >= needed)
            .ok_or(EnvelopeError::PayloadTooLarge {
                size: payload.len(),
                max: BUCKET_SIZES[BUCKET_SIZES.len() - 1] - LENGTH_SUFFIX_SIZE,
            })?;

    let mut padded = Vec::with_capacity(*bucket_size);
    padded.extend_from_slice(payload);

    // Zero-fill padding between payload end and length suffix position.
    let padding_len = bucket_size - payload.len() - LENGTH_SUFFIX_SIZE;
    padded.resize(padded.len() + padding_len, 0);

    // Append 4-byte big-endian original payload length.
    let len_u32 = u32::try_from(payload.len()).map_err(|_| EnvelopeError::PayloadTooLarge {
        size: payload.len(),
        max: BUCKET_SIZES[BUCKET_SIZES.len() - 1] - LENGTH_SUFFIX_SIZE,
    })?;
    padded.extend_from_slice(&len_u32.to_be_bytes());

    debug_assert_eq!(padded.len(), *bucket_size);

    Ok(padded)
}

/// Strips bucket padding from a padded payload, recovering the original bytes.
///
/// Reads the 4-byte big-endian length suffix at the end of `padded`, then
/// returns the first `length` bytes.
///
/// # Errors
///
/// Returns [`EnvelopeError::InvalidPadding`] if:
/// - The padded data is shorter than 4 bytes (no length suffix).
/// - The encoded length exceeds the available data.
pub fn strip_padding(padded: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if padded.len() < LENGTH_SUFFIX_SIZE {
        return Err(EnvelopeError::InvalidPadding(
            "padded data too short to contain length suffix".into(),
        ));
    }

    let suffix_start = padded.len() - LENGTH_SUFFIX_SIZE;
    let len_bytes: [u8; 4] = [
        padded[suffix_start],
        padded[suffix_start + 1],
        padded[suffix_start + 2],
        padded[suffix_start + 3],
    ];
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    if original_len > suffix_start {
        return Err(EnvelopeError::InvalidPadding(format!(
            "encoded length {original_len} exceeds available data {suffix_start}"
        )));
    }

    Ok(padded[..original_len].to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn pad_empty_payload_to_smallest_bucket() {
        let padded = pad_to_bucket(b"").unwrap();
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pad_small_payload_to_256_bucket() {
        let payload = b"hello";
        let padded = pad_to_bucket(payload).unwrap();
        assert_eq!(padded.len(), 256);
        // Verify original payload is at the start.
        assert_eq!(&padded[..5], b"hello");
    }

    #[test]
    fn pad_payload_exactly_at_bucket_boundary() {
        // 256 - 4 = 252 bytes of payload should fit in 256 bucket.
        let payload = vec![0xAB; 252];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pad_payload_one_byte_over_bucket_boundary() {
        // 253 bytes + 4 byte suffix = 257 > 256, so should go to 1024.
        let payload = vec![0xAB; 253];
        let padded = pad_to_bucket(&payload).unwrap();
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn pad_payload_too_large_returns_error() {
        let payload = vec![0xAB; 262_144]; // 256KB payload + 4 suffix won't fit.
        let result = pad_to_bucket(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn strip_recovers_original_payload() {
        let payload = b"test payload data";
        let padded = pad_to_bucket(payload).unwrap();
        let recovered = strip_padding(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn strip_empty_padded_data_fails() {
        let result = strip_padding(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn strip_with_invalid_length_fails() {
        // Create data where the length suffix claims more data than available.
        let mut bad = vec![0u8; 256];
        // Set length suffix to 300, which is > 252 (256 - 4).
        bad[252..256].copy_from_slice(&300_u32.to_be_bytes());
        let result = strip_padding(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_all_bucket_sizes() {
        for &bucket in &BUCKET_SIZES {
            // Maximum payload that fits in this bucket.
            let max_payload_len = bucket - LENGTH_SUFFIX_SIZE;
            let payload = vec![0x42; max_payload_len];
            let padded = pad_to_bucket(&payload).unwrap();
            assert_eq!(padded.len(), bucket);
            let recovered = strip_padding(&padded).unwrap();
            assert_eq!(recovered, payload);
        }
    }

    mod proptest_padding {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn pad_then_strip_roundtrip(payload in proptest::collection::vec(any::<u8>(), 0..262_140)) {
                let padded = pad_to_bucket(&payload)?;
                let recovered = strip_padding(&padded)?;
                prop_assert_eq!(&recovered, &payload);
            }

            #[test]
            fn padded_size_is_valid_bucket(payload in proptest::collection::vec(any::<u8>(), 0..262_140)) {
                let padded = pad_to_bucket(&payload)?;
                prop_assert!(BUCKET_SIZES.contains(&padded.len()));
            }
        }
    }
}
