//! SCPR — the Relay Public-Record Frame (§9.10.12).
//!
//! The **SCPR frame** is the unencrypted counterpart to the §9.10.2 Minimal
//! Outer Envelope: where the outer envelope is *confidential by encryption*, an
//! SCPR record is *self-certifying by signature*. Its first — and, at this
//! slice, only defined — record kind is the DID document (kind 1, §3.10.2).
//!
//! # Model A — a raw relay blob, never an `OuterEnvelope`
//!
//! An SCPR record is stored as a **raw relay blob** at its routing ID. It is
//! NOT wrapped in an `OuterEnvelope`, and its bytes are NOT MLS-encrypted. The
//! relay stores the frame bytes opaquely (the relay wire protocol is
//! unchanged); the SDK transport adapter carries it over a dedicated
//! public-record raw-blob path (`publish_raw` / `query_raw`), distinct from the
//! `OuterEnvelope`-typed message path.
//!
//! # Frame layout (§9.10.12)
//!
//! ```text
//! magic:     [u8; 4]  = 0x53 0x43 0x50 0x52   ("SCPR")
//! version:   u8        = 1
//! kind:      u8                                 (record-kind discriminator)
//! seq:       u64                 8 bytes big-endian — BEP44 sequence
//! signature: [u8; 64]            Ed25519 BEP44 signature, raw fixed-width
//! value_len: u32                 4 bytes big-endian — length of value
//! value:     [u8; value_len]     BEP44-signed payload = encoded DID document
//! ```
//!
//! The fixed portion is `4 + 1 + 1 + 8 + 64 + 4 = 82` bytes, and the total
//! frame length is `82 + value_len`.
//!
//! # Framing is outside the signed authority
//!
//! The BEP44 signature covers only the BEP44-canonical bencoded buffer
//! `bencode(seq, value)` — it does NOT cover any framing byte. [`decode_did_record`]
//! therefore performs **no** verification; it only recovers the `(value,
//! signature, seq)` triple. The resolver BEP44-verifies that triple against the
//! Ed25519 key encoded in the DID string at a single decode-and-verify site
//! (§9.10.12 rule 5) before any use. Framing bytes grant no authority.
//!
//! # Wasm safety
//!
//! Pure sync, allocation-only, `tokio`-free — compiles for
//! `wasm32-unknown-unknown` (§3.10.12).

/// The 4-byte ASCII "SCPR" record magic (§9.18.8), mirroring the SCPM
/// management magic (`[0x53, 0x43, 0x50, 0x4D]`, §9.16.1). Unsigned framing —
/// grants no authority.
pub const SCPR_MAGIC: [u8; 4] = [0x53, 0x43, 0x50, 0x52];

/// The current SCPR frame version (§9.18.8). Bumped on any field-encoding change.
pub const SCPR_VERSION: u8 = 1;

/// The DID-record kind discriminator (§9.18.8). Kind 2 (`KeyPackage`) is reserved
/// but undefined; kinds 3–255 are unassigned. A decoder MUST reject any kind it
/// does not recognize.
pub const SCPR_KIND_DID_RECORD: u8 = 1;

/// The fixed (non-`value`) portion of a kind-1 frame, in bytes:
/// `4 (magic) + 1 (version) + 1 (kind) + 8 (seq) + 64 (signature) + 4 (value_len)`.
pub const SCPR_KIND1_FIXED_LEN: usize = 82;

/// Maximum relay blob size (262144 = 256 KiB, §9.18.11). `value_len` MUST NOT
/// exceed `MAX_BLOB_SIZE − SCPR_KIND1_FIXED_LEN`.
pub const MAX_BLOB_SIZE: usize = 262_144;

/// The decoded contents of an SCPR kind-1 DID-record frame: the BEP44
/// `(value, signature, seq)` triple.
///
/// Recovered from the frame bytes with **no** verification — framing grants no
/// authority (§9.10.12). The caller BEP44-verifies before use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidRecord {
    /// The BEP44-signed payload (the encoded DID document bytes).
    pub value: Vec<u8>,
    /// The 64-byte Ed25519 BEP44 signature over `bencode(seq, value)`.
    pub signature: [u8; 64],
    /// The BEP44 sequence number.
    ///
    /// Deliberately `u64` despite BEP44's signed-integer wire format. SCP never
    /// publishes negative sequence numbers.
    pub seq: u64,
}

/// Errors produced when decoding an SCPR frame.
///
/// Any decode error means the frame is discarded exactly as an invalid DHT
/// record is (§3.10.4) — never trusted, never partially parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScprError {
    /// The frame is shorter than the fixed kind-1 header.
    #[error("SCPR frame too short: {len} bytes, minimum header is {min}")]
    TooShort {
        /// Actual frame length in bytes.
        len: usize,
        /// Minimum required header length in bytes.
        min: usize,
    },

    /// The 4-byte magic prefix is not "SCPR".
    #[error("SCPR magic mismatch: expected {expected:02x?}, got {got:02x?}")]
    BadMagic {
        /// Expected magic bytes.
        expected: [u8; 4],
        /// Actual first four bytes.
        got: [u8; 4],
    },

    /// The `version` byte names a version this decoder does not implement.
    #[error("unsupported SCPR version: {got} (this decoder implements {supported})")]
    UnsupportedVersion {
        /// The version byte read from the frame.
        got: u8,
        /// The version this decoder implements.
        supported: u8,
    },

    /// The `kind` byte names a record kind this decoder does not recognize.
    #[error("unrecognized SCPR kind: {got} (this decoder recognizes {recognized})")]
    UnrecognizedKind {
        /// The kind byte read from the frame.
        got: u8,
        /// The kind this decoder recognizes.
        recognized: u8,
    },

    /// The `value_len` field exceeds the maximum permitted (§9.18.11).
    #[error("SCPR value_len too large: {value_len}, maximum is {max}")]
    ValueLenTooLarge {
        /// The declared value length.
        value_len: u64,
        /// The maximum permitted value length.
        max: u64,
    },

    /// The total frame length does not equal `82 + value_len` exactly —
    /// truncation or trailing bytes.
    #[error(
        "SCPR length mismatch: frame is {actual} bytes, expected exactly {expected} (82 + value_len {value_len})"
    )]
    LengthMismatch {
        /// Actual frame length in bytes.
        actual: usize,
        /// Expected frame length in bytes (`82 + value_len`).
        expected: u64,
        /// The declared value length.
        value_len: u64,
    },
}

/// Encodes a `(value, signature, seq)` triple as an SCPR kind-1 DID-record
/// frame (§9.10.12).
///
/// The returned bytes are the raw relay blob published via the SDK
/// public-record `publish_raw` path (§3.10.5). SCPR wraps `value` for transport
/// only; it never enters, reorders, or alters the BEP44-signed bytes.
///
/// # Panics
///
/// Does not panic. `value` longer than `MAX_BLOB_SIZE − 82` is still encoded
/// (the transport-layer blob-size limit rejects it downstream); the length
/// prefix is a `u32`, which the caller's `value` (bounded by the 256 KiB blob
/// limit) always fits.
#[must_use]
pub fn encode_did_record(value: &[u8], signature: &[u8; 64], seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SCPR_KIND1_FIXED_LEN + value.len());
    out.extend_from_slice(&SCPR_MAGIC);
    out.push(SCPR_VERSION);
    out.push(SCPR_KIND_DID_RECORD);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(signature);
    // `value.len()` is bounded by the 256 KiB relay blob limit, well within u32.
    let value_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&value_len.to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Decodes an SCPR kind-1 DID-record frame into its `(value, signature, seq)`
/// triple (§9.10.12).
///
/// Enforces the five normative decoder rules, in order, before returning: read
/// and check `version`, read and check `kind`, bound-check `value_len` first
/// with widened arithmetic, require exact-length equality, and recover the
/// triple. **No verification is performed** — framing grants no authority; the
/// caller BEP44-verifies the returned triple (§9.10.12 rule 5).
///
/// # Errors
///
/// Returns [`ScprError`] for any frame that is too short, has the wrong magic,
/// an unimplemented version, an unrecognized kind, an over-large `value_len`,
/// or whose total length is not exactly `82 + value_len` (truncation OR
/// trailing bytes). A failing frame is discarded exactly as an invalid DHT
/// record is (§3.10.4) — never partially parsed.
pub fn decode_did_record(blob: &[u8]) -> Result<DidRecord, ScprError> {
    // The fixed header must be fully present before any field is read.
    if blob.len() < SCPR_KIND1_FIXED_LEN {
        return Err(ScprError::TooShort {
            len: blob.len(),
            min: SCPR_KIND1_FIXED_LEN,
        });
    }

    // Bytes 0..4 — magic. Reject anything but "SCPR".
    let magic: [u8; 4] = [blob[0], blob[1], blob[2], blob[3]];
    if magic != SCPR_MAGIC {
        return Err(ScprError::BadMagic {
            expected: SCPR_MAGIC,
            got: magic,
        });
    }

    // Rule 1 — read and check `version` before any body byte.
    let version = blob[4];
    if version != SCPR_VERSION {
        return Err(ScprError::UnsupportedVersion {
            got: version,
            supported: SCPR_VERSION,
        });
    }

    // Rule 2 — read and check `kind`; reject unrecognized kinds.
    let kind = blob[5];
    if kind != SCPR_KIND_DID_RECORD {
        return Err(ScprError::UnrecognizedKind {
            got: kind,
            recognized: SCPR_KIND_DID_RECORD,
        });
    }

    // seq: bytes 6..14 (u64 big-endian).
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&blob[6..14]);
    let seq = u64::from_be_bytes(seq_bytes);

    // signature: bytes 14..78 (raw fixed-width, no length prefix).
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[14..78]);

    // value_len: bytes 78..82 (u32 big-endian).
    let mut value_len_bytes = [0u8; 4];
    value_len_bytes.copy_from_slice(&blob[78..82]);
    let value_len = u32::from_be_bytes(value_len_bytes);

    // Rule 3 — bound-check `value_len` FIRST, with widened (u64) arithmetic, so
    // a near-u32::MAX value_len cannot overflow the `82 + value_len` sum.
    let value_len_u64 = u64::from(value_len);
    let max_value_len = (MAX_BLOB_SIZE - SCPR_KIND1_FIXED_LEN) as u64;
    if value_len_u64 > max_value_len {
        return Err(ScprError::ValueLenTooLarge {
            value_len: value_len_u64,
            max: max_value_len,
        });
    }

    // Rule 4 — require exact-length equality (widened): reject truncation AND
    // trailing bytes. `expected` cannot overflow: value_len_u64 is bounded above.
    let expected = SCPR_KIND1_FIXED_LEN as u64 + value_len_u64;
    if blob.len() as u64 != expected {
        return Err(ScprError::LengthMismatch {
            actual: blob.len(),
            expected,
            value_len: value_len_u64,
        });
    }

    // Rule 5 — recover the triple (verification happens at the caller's single
    // decode-and-verify site). `value_len as usize` is safe: bounded by
    // max_value_len < usize::MAX on every supported target.
    let value = blob[SCPR_KIND1_FIXED_LEN..].to_vec();

    Ok(DidRecord {
        value,
        signature,
        seq,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample_triple() -> (Vec<u8>, [u8; 64], u64) {
        let value = b"{\"id\":\"did:dht:zExample\",\"verificationMethod\":[]}".to_vec();
        let mut signature = [0u8; 64];
        for (i, b) in signature.iter_mut().enumerate() {
            // `i` is 0..64, so the conversion never truncates.
            *b = u8::try_from(i).unwrap().wrapping_mul(3).wrapping_add(7);
        }
        (value, signature, 42)
    }

    #[test]
    fn round_trip_recovers_byte_identical_triple() {
        let (value, signature, seq) = sample_triple();
        let frame = encode_did_record(&value, &signature, seq);

        // Fixed portion + value.
        assert_eq!(frame.len(), SCPR_KIND1_FIXED_LEN + value.len());
        // Byte 0 is 'S' (0x53) — never an OuterEnvelope map marker.
        assert_eq!(frame[0], 0x53);
        assert_eq!(&frame[0..4], &SCPR_MAGIC);
        assert_eq!(frame[4], SCPR_VERSION);
        assert_eq!(frame[5], SCPR_KIND_DID_RECORD);

        let decoded = decode_did_record(&frame).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.signature, signature);
        assert_eq!(decoded.seq, seq);
    }

    #[test]
    fn round_trip_empty_value() {
        let signature = [0xABu8; 64];
        let frame = encode_did_record(&[], &signature, 0);
        assert_eq!(frame.len(), SCPR_KIND1_FIXED_LEN);
        let decoded = decode_did_record(&frame).unwrap();
        assert!(decoded.value.is_empty());
        assert_eq!(decoded.signature, signature);
        assert_eq!(decoded.seq, 0);
    }

    #[test]
    fn round_trip_max_seq() {
        let signature = [0x11u8; 64];
        let frame = encode_did_record(b"v", &signature, u64::MAX);
        let decoded = decode_did_record(&frame).unwrap();
        assert_eq!(decoded.seq, u64::MAX);
    }

    #[test]
    fn reject_wrong_magic() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame[0] = b'X';
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::BadMagic { .. }));
    }

    #[test]
    fn reject_unknown_version_no_partial_parse() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame[4] = 2; // version 2 — unimplemented
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(
            err,
            ScprError::UnsupportedVersion {
                got: 2,
                supported: 1
            }
        ));
    }

    #[test]
    fn reject_unknown_kind() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame[5] = 2; // kind 2 (KeyPackage) is reserved but undefined
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(
            err,
            ScprError::UnrecognizedKind {
                got: 2,
                recognized: 1
            }
        ));
    }

    #[test]
    fn reject_kind_in_unassigned_range() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame[5] = 200; // unassigned kind
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::UnrecognizedKind { got: 200, .. }));
    }

    #[test]
    fn reject_truncated_frame_shorter_than_header() {
        let frame = vec![0x53, 0x43, 0x50]; // 3 bytes — below the 82-byte header
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::TooShort { .. }));
    }

    #[test]
    fn reject_truncated_value() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame.pop(); // drop one value byte — total < 82 + value_len
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::LengthMismatch { .. }));
    }

    #[test]
    fn reject_trailing_bytes() {
        let (value, signature, seq) = sample_triple();
        let mut frame = encode_did_record(&value, &signature, seq);
        frame.push(0xFF); // one trailing byte — total > 82 + value_len
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::LengthMismatch { .. }));
    }

    #[test]
    fn reject_oversized_value_len() {
        // Craft a header whose declared value_len exceeds MAX_BLOB_SIZE − 82,
        // without actually allocating a 256 KiB frame.
        let mut frame = vec![0u8; SCPR_KIND1_FIXED_LEN];
        frame[0..4].copy_from_slice(&SCPR_MAGIC);
        frame[4] = SCPR_VERSION;
        frame[5] = SCPR_KIND_DID_RECORD;
        let too_large = u32::try_from(MAX_BLOB_SIZE - SCPR_KIND1_FIXED_LEN + 1).unwrap();
        frame[78..82].copy_from_slice(&too_large.to_be_bytes());
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::ValueLenTooLarge { .. }));
    }

    #[test]
    fn reject_near_u32_max_value_len_without_overflow() {
        // value_len = u32::MAX would overflow a naive `82 + value_len` in a
        // narrow type. The widened bound-check (rule 3) MUST reject it as
        // over-large — never panic, never wrap.
        let mut frame = vec![0u8; SCPR_KIND1_FIXED_LEN];
        frame[0..4].copy_from_slice(&SCPR_MAGIC);
        frame[4] = SCPR_VERSION;
        frame[5] = SCPR_KIND_DID_RECORD;
        frame[78..82].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = decode_did_record(&frame).unwrap_err();
        assert!(matches!(err, ScprError::ValueLenTooLarge { .. }));
    }

    #[test]
    fn value_len_at_exact_boundary_accepted() {
        // A frame whose declared value_len is exactly the maximum, with a
        // matching total length, decodes (boundary is inclusive).
        let max_value_len = MAX_BLOB_SIZE - SCPR_KIND1_FIXED_LEN;
        let value = vec![0x5Au8; max_value_len];
        let signature = [0u8; 64];
        let frame = encode_did_record(&value, &signature, 1);
        assert_eq!(frame.len(), MAX_BLOB_SIZE);
        let decoded = decode_did_record(&frame).unwrap();
        assert_eq!(decoded.value.len(), max_value_len);
    }
}
