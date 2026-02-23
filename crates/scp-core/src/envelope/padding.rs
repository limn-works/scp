//! Bucket padding for traffic analysis resistance.
//!
//! Pads payloads to fixed bucket sizes before encryption so relays cannot
//! correlate message types by ciphertext length. Buckets: 256 B, 1 KB,
//! 4 KB, 16 KB, 64 KB, 256 KB. See ADR-002 Decision 3.
//!
//! **Padding format:** `payload_bytes || padding_bytes || length_u32_be`
//!
//! The last 4 bytes are a big-endian `u32` recording the original payload
//! length. `strip_padding` reads this suffix and truncates to recover the
//! original data.

/// Bucket sizes in bytes, ascending.
pub const BUCKETS: [usize; 6] = [256, 1_024, 4_096, 16_384, 65_536, 262_144];

/// Length suffix size in bytes (big-endian `u32`).
const LENGTH_SUFFIX_BYTES: usize = 4;

/// Maximum payload size that can be padded.
///
/// Equal to the largest bucket minus the 4-byte length suffix.
pub const MAX_PAYLOAD_SIZE: usize = BUCKETS[5] - LENGTH_SUFFIX_BYTES;

/// Errors that can occur during padding operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// The payload exceeds the maximum size that fits in the largest bucket.
    #[error(
        "payload too large: {size} bytes exceeds maximum {max} bytes",
        max = MAX_PAYLOAD_SIZE
    )]
    PayloadTooLarge {
        /// Actual payload size in bytes.
        size: usize,
    },

    /// The padded data is smaller than the minimum bucket size or does not
    /// match any known bucket boundary.
    #[error("invalid padded data: length {len} does not match any bucket boundary")]
    InvalidPaddedLength {
        /// Actual length of the padded data.
        len: usize,
    },

    /// The length suffix encoded in the padded data is inconsistent
    /// (claims a payload size larger than available space).
    #[error(
        "corrupt length suffix: claims {claimed} bytes but only {available} bytes available before suffix"
    )]
    CorruptLengthSuffix {
        /// Payload length claimed by the suffix.
        claimed: usize,
        /// Bytes available before the length suffix.
        available: usize,
    },
}

/// Pads `payload` to the next bucket boundary.
///
/// Appends zero-filled padding bytes and a 4-byte big-endian `u32` length
/// suffix recording the original payload length. The total output length
/// equals the smallest bucket that can contain `payload.len() + 4`.
///
/// # Errors
///
/// Returns [`EnvelopeError::PayloadTooLarge`] if `payload` exceeds
/// [`MAX_PAYLOAD_SIZE`] bytes.
pub fn pad_to_bucket(payload: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let data_len = payload.len();

    if data_len > MAX_PAYLOAD_SIZE {
        return Err(EnvelopeError::PayloadTooLarge { size: data_len });
    }

    // Total bytes needed: payload + 4-byte length suffix.
    let total_needed = data_len + LENGTH_SUFFIX_BYTES;

    // Find the smallest bucket that fits.
    let bucket_size = BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= total_needed)
        // SAFETY (logic): total_needed <= MAX_PAYLOAD_SIZE + 4 == BUCKETS[5],
        // so at least the largest bucket always fits. The guard above ensures this.
        .unwrap_or(BUCKETS[5]);

    let padding_len = bucket_size - data_len - LENGTH_SUFFIX_BYTES;
    let len_bytes = u32::try_from(data_len)
        .map_err(|_| EnvelopeError::PayloadTooLarge { size: data_len })?
        .to_be_bytes();

    let mut out = Vec::with_capacity(bucket_size);
    out.extend_from_slice(payload);
    out.resize(out.len() + padding_len, 0);
    out.extend_from_slice(&len_bytes);

    debug_assert_eq!(out.len(), bucket_size);
    Ok(out)
}

/// Removes bucket padding and recovers the original payload.
///
/// Reads the 4-byte big-endian length suffix at the end of `padded`,
/// validates that it is consistent with the padded length, and returns
/// the original payload bytes.
///
/// # Errors
///
/// Returns [`EnvelopeError::InvalidPaddedLength`] if `padded.len()` does
/// not match any known bucket size, or [`EnvelopeError::CorruptLengthSuffix`]
/// if the encoded length exceeds the available space.
pub fn strip_padding(padded: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let total_len = padded.len();

    // Verify the padded data matches a known bucket size.
    if !BUCKETS.contains(&total_len) {
        return Err(EnvelopeError::InvalidPaddedLength { len: total_len });
    }

    if total_len < LENGTH_SUFFIX_BYTES {
        return Err(EnvelopeError::InvalidPaddedLength { len: total_len });
    }

    // Read the 4-byte big-endian length suffix.
    let suffix_start = total_len - LENGTH_SUFFIX_BYTES;
    let len_bytes: [u8; 4] = [
        padded[suffix_start],
        padded[suffix_start + 1],
        padded[suffix_start + 2],
        padded[suffix_start + 3],
    ];
    let original_len = u32::from_be_bytes(len_bytes) as usize;

    // The original payload must fit in the space before the length suffix.
    let available = total_len - LENGTH_SUFFIX_BYTES;
    if original_len > available {
        return Err(EnvelopeError::CorruptLengthSuffix {
            claimed: original_len,
            available,
        });
    }

    Ok(padded[..original_len].to_vec())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Bucket boundary tests ──────────────────────────────────────────

    #[test]
    fn empty_payload_pads_to_256() {
        let padded = pad_to_bucket(&[]).expect("empty payload should pad");
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn payload_255_bytes_exceeds_256_bucket() {
        // 255 payload + 4 suffix = 259 > 256, so next bucket is 1024.
        // The max payload that fits the 256B bucket is 252 (252 + 4 = 256).
        let data = vec![0xaa; 255];
        let padded = pad_to_bucket(&data).expect("255-byte payload should pad");
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn payload_252_bytes_pads_to_256() {
        // 252 + 4 = 256, exactly fits the 256 bucket.
        let data = vec![0xbb; 252];
        let padded = pad_to_bucket(&data).expect("252-byte payload should pad");
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn payload_257_bytes_pads_to_1024() {
        let data = vec![0xcc; 257];
        let padded = pad_to_bucket(&data).expect("257-byte payload should pad");
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn payload_1020_bytes_pads_to_1024() {
        // 1020 + 4 = 1024, exactly fits 1KB bucket.
        let data = vec![0xdd; 1020];
        let padded = pad_to_bucket(&data).expect("1020-byte payload should pad");
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn payload_1021_bytes_pads_to_4096() {
        // 1021 + 4 = 1025 > 1024, goes to 4KB bucket.
        let data = vec![0xee; 1021];
        let padded = pad_to_bucket(&data).expect("1021-byte payload should pad");
        assert_eq!(padded.len(), 4096);
    }

    #[test]
    fn max_payload_pads_to_largest_bucket() {
        let data = vec![0x00; MAX_PAYLOAD_SIZE];
        let padded = pad_to_bucket(&data).expect("max payload should pad");
        assert_eq!(padded.len(), 262_144);
    }

    #[test]
    fn payload_exceeding_max_returns_error() {
        let data = vec![0x00; MAX_PAYLOAD_SIZE + 1];
        let result = pad_to_bucket(&data);
        assert!(
            matches!(
                result,
                Err(EnvelopeError::PayloadTooLarge { size }) if size == MAX_PAYLOAD_SIZE + 1
            ),
            "expected PayloadTooLarge error"
        );
    }

    // ── Roundtrip tests ────────────────────────────────────────────────

    #[test]
    fn strip_padding_recovers_original_payload() {
        let original = vec![1, 2, 3, 4, 5];
        let padded = pad_to_bucket(&original).expect("should pad");
        let recovered = strip_padding(&padded).expect("should strip");
        assert_eq!(original, recovered);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let original: Vec<u8> = vec![];
        let padded = pad_to_bucket(&original).expect("should pad");
        let recovered = strip_padding(&padded).expect("should strip");
        assert_eq!(original, recovered);
    }

    #[test]
    fn roundtrip_at_each_bucket_boundary() {
        for &bucket in &BUCKETS {
            let payload_size = bucket - LENGTH_SUFFIX_BYTES;
            let original = vec![0xab; payload_size];
            let padded = pad_to_bucket(&original).expect("should pad");
            assert_eq!(padded.len(), bucket);
            let recovered = strip_padding(&padded).expect("should strip");
            assert_eq!(original, recovered);
        }
    }

    // ── Error case tests ───────────────────────────────────────────────

    #[test]
    fn strip_padding_rejects_non_bucket_length() {
        let bad_data = vec![0; 500]; // 500 is not a bucket size
        let result = strip_padding(&bad_data);
        assert!(matches!(
            result,
            Err(EnvelopeError::InvalidPaddedLength { len: 500 })
        ));
    }

    #[test]
    fn strip_padding_rejects_corrupt_length_suffix() {
        let mut padded = vec![0u8; 256];
        // Write a length suffix claiming 253 bytes, but only 252 available.
        let bad_len: u32 = 253;
        let suffix = bad_len.to_be_bytes();
        padded[252] = suffix[0];
        padded[253] = suffix[1];
        padded[254] = suffix[2];
        padded[255] = suffix[3];

        let result = strip_padding(&padded);
        assert!(matches!(
            result,
            Err(EnvelopeError::CorruptLengthSuffix {
                claimed: 253,
                available: 252,
            })
        ));
    }

    // ── Bucket assignment tests (per acceptance criteria) ──────────────

    #[test]
    fn pad_to_bucket_assigns_correct_buckets() {
        // Map of (payload_size, expected_bucket_size)
        let cases = [
            (0, 256),
            (1, 256),
            (251, 256),
            (252, 256),  // 252 + 4 = 256 exact fit
            (253, 1024), // 253 + 4 = 257 > 256
            (255, 1024), // 255 + 4 = 259 > 256
            (257, 1024), // 257 + 4 = 261
            (1019, 1024),
            (1020, 1024), // 1020 + 4 = 1024 exact
            (1021, 4096), // 1021 + 4 = 1025 > 1024
            (4092, 4096), // 4092 + 4 = 4096 exact
            (4093, 16384),
            (16380, 16384), // exact
            (16381, 65536),
            (65532, 65536), // exact
            (65533, 262_144),
            (262_140, 262_144), // exact, MAX_PAYLOAD_SIZE
        ];

        for (payload_size, expected_bucket) in cases {
            let data = vec![0xfe; payload_size];
            let padded =
                pad_to_bucket(&data).expect("pad_to_bucket should succeed for valid payload size");
            assert_eq!(
                padded.len(),
                expected_bucket,
                "payload size {payload_size} should pad to {expected_bucket}, got {}",
                padded.len()
            );
        }
    }

    // ── Proptest ───────────────────────────────────────────────────────

    proptest! {
        #[test]
        #[allow(clippy::unwrap_used)]
        fn padding_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD_SIZE)) {
            let padded = pad_to_bucket(&data).unwrap();
            // Padded size must match a known bucket.
            prop_assert!(BUCKETS.contains(&padded.len()),
                "padded length {} not in BUCKETS", padded.len());
            let recovered = strip_padding(&padded).unwrap();
            prop_assert_eq!(&data, &recovered);
        }
    }
}
