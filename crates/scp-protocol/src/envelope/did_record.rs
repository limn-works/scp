//! DID-record relay frame (`DidRecordV1`) — the public, self-certifying
//! counterpart to the encrypted [`OuterEnvelope`](super::outer::OuterEnvelope).
//!
//! A DID record carries a `did:dht` document (§3.10.2) as a **raw relay blob**
//! at the DID routing ID (`SHA-256("scp:did:" || did_string)`), published and
//! resolved over the existing PUBLISH/QUERY operations (ADR-004) with no new
//! wire types. Where the outer envelope is confidential *by encryption*, a DID
//! record is authentic *by signature*: its authority comes from the BEP44
//! signature over `bencode(seq, value)`, never from encryption and never from
//! the relay's acceptance. This design is issue #482 (Model B); the normative
//! frame specification is §9.10.12 of the security model.
//!
//! # Wire format (§9.10.12)
//!
//! ```text
//! DID-RECORD (DidRecordV1) :=
//!   version:    u8       = 1     # frame version — gates the entire grammar
//!   public_key: [u8; 32]         # Ed25519 public key — for the RELAY's verify
//!   seq:        u64              # 8 bytes big-endian — BEP44 sequence
//!   signature:  [u8; 64]         # Ed25519 BEP44 signature, raw, no length prefix
//!   value:      [u8]             # trailing remainder — BEP44-signed payload
//! ```
//!
//! The fixed prefix is `1 + 32 + 8 + 64 = 105` bytes
//! ([`DID_RECORD_FIXED_PREFIX_LEN`]); the total frame length is
//! `105 + len(value)`. There is deliberately **no** magic tag, **no**
//! record-kind byte (the routing-ID domain is the type discriminant), and
//! **no** `value_len` prefix (`value` is unambiguously `frame_bytes[105..]`
//! because every preceding field is fixed-width — a length prefix would be
//! redundant with the blob's own length and a determinism footgun).
//!
//! # Raw binary, not a self-describing codec
//!
//! The frame is a fixed-layout binary encoding under the §9.5.1 length-prefix
//! discipline — **not** `MessagePack`/CBOR/bencode. Self-describing codecs
//! admit multiple valid encodings of the same logical value, which would break
//! byte-identical cross-binding decoding and perturb the exact `value` bytes
//! handed to BEP44 verification. [`encode`](DidRecordV1::encode) therefore
//! fixes exactly one canonical byte sequence, reproducible by every SCP
//! binding (including this wasm-safe `scp-protocol` decoder).
//!
//! # Decode is not verify
//!
//! [`decode`](DidRecordV1::decode) performs **structural** decoding only. It
//! returns the `(public_key, seq, signature, value)` tuple and grants **no
//! authority**. The frame's `public_key` is carried for a *validating relay's*
//! benefit (a relay holds only the one-way routing-ID hash and has no other
//! source of the key); the **client MUST NOT trust it**. After decoding, the
//! resolver BEP44-verifies the `(value, signature, seq)` triple against the
//! Ed25519 key derived from the DID string being resolved (§9.6.1) — at a
//! single decode-and-verify site (§9.10.12 rule 4) — before any use. That
//! verification is a separate concern, performed elsewhere; this type provides
//! only the decode half.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The only implemented DID-record frame version (byte 0 of every frame).
///
/// Any change to field encoding bumps this version; a decoder rejects every
/// other value (§9.10.12 decoder rule 1). See §9.18.11 for the registered
/// version constant.
pub const DID_RECORD_VERSION: u8 = 1;

/// Fixed-width prefix length in bytes: `version` (1) + `public_key` (32) +
/// `seq` (8) + `signature` (64) = 105 (§9.10.12, §9.18.11). `value` is the
/// trailing remainder beginning at this offset.
pub const DID_RECORD_FIXED_PREFIX_LEN: usize = 105;

/// Maximum relay blob size in bytes (§9.18.11). The frame reuses this shared
/// transport bound rather than defining a record-specific one.
///
/// This restates the authoritative `MAX_BLOB_SIZE` constant (also `262_144`,
/// from ADR-004 / §9.18.11) that the transport layer defines in
/// `scp-relay-client` (`crates/scp-relay-client/src/protocol.rs`). It is
/// duplicated here — rather than imported — only because `scp-protocol` is the
/// wasm-safe leaf crate and cannot depend on the transport crates. The value is
/// pinned to the spec (§9.18.11) by the `constants_match_spec` test below, so
/// the two definitions cannot silently drift.
pub const MAX_BLOB_SIZE: usize = 262_144;

/// Maximum length of the variable `value` field (262039 bytes).
///
/// Equal to [`MAX_BLOB_SIZE`] minus the [`DID_RECORD_FIXED_PREFIX_LEN`]
/// (262144 − 105 = 262039). A larger `value` would make the total frame exceed
/// the relay's Max blob size (§9.10.12 decoder rule 3, §9.18.11).
pub const MAX_DID_RECORD_VALUE_LEN: usize = MAX_BLOB_SIZE - DID_RECORD_FIXED_PREFIX_LEN;

/// Offset of `public_key` within the fixed prefix (`[1..33]`).
const PUBLIC_KEY_OFFSET: usize = 1;
/// Offset of `seq` within the fixed prefix (`[33..41]`).
const SEQ_OFFSET: usize = 33;
/// Offset of `signature` within the fixed prefix (`[41..105]`).
const SIGNATURE_OFFSET: usize = 41;
/// Offset of the trailing `value` remainder (`[105..]`).
const VALUE_OFFSET: usize = 105;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// A frame that fails any [`DidRecordV1::decode`] rule is rejected with one of
/// these errors — discarded exactly as an invalid DHT record is (§3.10.4),
/// never trusted and never partially parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidRecordDecodeError {
    /// The first byte is not [`DID_RECORD_VERSION`] — an unimplemented version
    /// (§9.10.12 decoder rule 1). The version is checked before any subsequent
    /// byte is interpreted, so an `OuterEnvelope` (whose first byte is a
    /// `MessagePack` map marker, never `0x01`) is never mistaken for a frame.
    #[error(
        "unknown DID-record frame version: {version:#04x} (only version {expected} is implemented)",
        expected = DID_RECORD_VERSION
    )]
    UnknownVersion {
        /// The rejected version byte read from the wire.
        version: u8,
    },

    /// The buffer is shorter than the 105-byte fixed prefix (§9.10.12 decoder
    /// rule 2) — truncation is never a partially-valid frame. Rejecting this
    /// before the value-length subtraction is what makes `len − 105`
    /// underflow-free (rule 3).
    #[error(
        "DID-record frame truncated: {len} bytes, fixed prefix requires {prefix}",
        prefix = DID_RECORD_FIXED_PREFIX_LEN
    )]
    Truncated {
        /// The actual buffer length in bytes.
        len: usize,
    },

    /// The total frame length is exactly the 105-byte prefix, so `value` is
    /// empty. `value` MUST be non-empty (§9.10.12 decoder rule 3).
    #[error(
        "DID-record frame value is empty (total length is exactly the {prefix}-byte prefix)",
        prefix = DID_RECORD_FIXED_PREFIX_LEN
    )]
    EmptyValue,

    /// The `value` remainder exceeds [`MAX_DID_RECORD_VALUE_LEN`] — the frame
    /// would overflow the relay's Max blob size (§9.10.12 decoder rule 3,
    /// §9.18.11).
    #[error("DID-record frame value too large: {len} bytes, maximum is {max}")]
    ValueTooLarge {
        /// The decoded `value` length in bytes.
        len: usize,
        /// The maximum permitted `value` length ([`MAX_DID_RECORD_VALUE_LEN`]).
        max: usize,
    },
}

/// Rejects a producer's attempt to build a malformed [`DidRecordV1`] via
/// [`DidRecordV1::try_new`].
///
/// These mirror the `value` invariants that [`DidRecordV1::decode`] enforces on
/// the wire (§9.10.12 decoder rule 3), applied at the *construction* boundary so
/// an in-memory record can never hold a `value` that would encode to a frame no
/// conformant decoder accepts. Because every constructed-or-decoded record thus
/// satisfies the invariants, [`DidRecordV1::encode`] can never emit an
/// undecodable frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidRecordBuildError {
    /// The `value` is empty. A DID record MUST carry a non-empty `value`
    /// (§9.10.12).
    #[error("DID-record value is empty; a DID record MUST carry a non-empty value")]
    EmptyValue,

    /// The `value` exceeds [`MAX_DID_RECORD_VALUE_LEN`] (§9.10.12, §9.18.11).
    #[error("DID-record value too large: {len} bytes, maximum is {max}")]
    ValueTooLarge {
        /// The supplied `value` length in bytes.
        len: usize,
        /// The maximum permitted `value` length ([`MAX_DID_RECORD_VALUE_LEN`]).
        max: usize,
    },
}

// ---------------------------------------------------------------------------
// Type
// ---------------------------------------------------------------------------

/// A decoded (or to-be-encoded) DID-record relay frame, version 1 (§9.10.12).
///
/// The struct carries only the four wire fields, all **private**: it is
/// constructed exclusively through [`try_new`](Self::try_new) (or produced by
/// [`decode`](Self::decode)), both of which enforce the `value` invariants
/// (non-empty, at most [`MAX_DID_RECORD_VALUE_LEN`] bytes). This makes a
/// malformed record *unrepresentable*: no caller can build one whose
/// [`encode`](Self::encode) would emit a frame a conformant decoder rejects.
/// The fields are read back through the [`public_key`](Self::public_key),
/// [`seq`](Self::seq), [`signature`](Self::signature), and
/// [`value`](Self::value) accessors.
///
/// The `version` byte is not a field: it is always [`DID_RECORD_VERSION`] on
/// encode, and [`decode`](Self::decode) rejects any other value — the type name
/// *is* the version.
///
/// # Trust
///
/// This type is a transport container. Constructing one, or decoding one from
/// bytes, grants **no authority** — in particular the
/// [`public_key`](Self::public_key) is never a client trust input (see the
/// module docs). BEP44 verification of the `(value, signature, seq)` triple
/// against the DID-derived key is a separate concern performed by the resolver
/// at a single site (§9.10.12 rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidRecordV1 {
    /// The identity's raw 32-byte Ed25519 public key, carried for a validating
    /// relay's signature + `DID→routing_id` binding check. **The client ignores
    /// this field for trust** and verifies against the key it derives from the
    /// DID string itself (§9.6.1, §9.10.12 "Framing is outside the signed
    /// authority").
    public_key: [u8; 32],

    /// The BEP44 sequence number governing supersession (§3.10.7). Encoded as
    /// 8 bytes big-endian.
    seq: u64,

    /// The raw 64-byte Ed25519 BEP44 signature over `bencode(seq, value)`.
    /// Fixed-width, no length prefix (§9.5.1).
    signature: [u8; 64],

    /// The sole variable-length field: the BEP44-signed payload (the encoded
    /// DID document). Carried as the trailing remainder of the frame, so its
    /// bytes are preserved octet-for-octet for BEP44 verification. Always
    /// non-empty and at most [`MAX_DID_RECORD_VALUE_LEN`] bytes (enforced by
    /// [`try_new`](Self::try_new) / [`decode`](Self::decode)).
    value: Vec<u8>,
}

impl DidRecordV1 {
    /// Builds a validated DID record from its four wire fields.
    ///
    /// This is the sole in-memory constructor. It enforces the `value`
    /// invariants at the construction boundary so the resulting record can
    /// never [`encode`](Self::encode) to a frame that [`decode`](Self::decode)
    /// (or any conformant decoder) would reject.
    ///
    /// # Errors
    ///
    /// Returns [`DidRecordBuildError::EmptyValue`] if `value` is empty, or
    /// [`DidRecordBuildError::ValueTooLarge`] if `value.len()` exceeds
    /// [`MAX_DID_RECORD_VALUE_LEN`] (§9.10.12, §9.18.11).
    pub fn try_new(
        public_key: [u8; 32],
        seq: u64,
        signature: [u8; 64],
        value: Vec<u8>,
    ) -> Result<Self, DidRecordBuildError> {
        if value.is_empty() {
            return Err(DidRecordBuildError::EmptyValue);
        }
        if value.len() > MAX_DID_RECORD_VALUE_LEN {
            return Err(DidRecordBuildError::ValueTooLarge {
                len: value.len(),
                max: MAX_DID_RECORD_VALUE_LEN,
            });
        }
        Ok(Self {
            public_key,
            seq,
            signature,
            value,
        })
    }

    /// The raw 32-byte Ed25519 public key (relay-facing; never a client trust
    /// input — see the type docs).
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The BEP44 sequence number (§3.10.7).
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The raw 64-byte Ed25519 BEP44 signature over `bencode(seq, value)`.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The BEP44-signed payload (the encoded DID document), always non-empty
    /// and at most [`MAX_DID_RECORD_VALUE_LEN`] bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Encodes the frame into its canonical byte sequence (§9.10.12).
    ///
    /// The layout is `version(0x01) ‖ public_key ‖ seq(big-endian) ‖ signature
    /// ‖ value`, producing exactly `105 + value.len()` bytes. Encoding is total
    /// and deterministic: the same [`DidRecordV1`] always yields the identical
    /// bytes across every binding (there is no self-describing codec and no
    /// non-determinism). Encoding is safe to keep total because every record is
    /// already well-formed: the `value`-length invariants (§9.10.12 rule 3) were
    /// enforced when the record was built ([`try_new`](Self::try_new)) or
    /// decoded ([`decode`](Self::decode)), so `encode` can never emit a frame a
    /// conformant decoder would reject.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DID_RECORD_FIXED_PREFIX_LEN + self.value.len());
        out.push(DID_RECORD_VERSION);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.value);
        out
    }

    /// Structurally decodes a frame from bytes, enforcing the §9.10.12
    /// decoder-determinism rules **in order**. Decode is **not** verify: the
    /// returned tuple carries no authority (see the module docs).
    ///
    /// The rules, in the exact order the spec mandates:
    /// 1. Read and check `version` before any subsequent byte; reject an
    ///    unimplemented version with no partial parse.
    /// 2. Require the full 105-byte fixed prefix; reject truncation.
    /// 3. Compute `len(value) = total − 105` *only after* rule 2 (so the
    ///    subtraction cannot underflow); reject an empty `value` and reject a
    ///    `value` longer than [`MAX_DID_RECORD_VALUE_LEN`].
    ///
    /// # Errors
    ///
    /// Returns [`DidRecordDecodeError::UnknownVersion`] if the first byte is
    /// not [`DID_RECORD_VERSION`]; [`DidRecordDecodeError::Truncated`] if the
    /// buffer is shorter than the fixed prefix;
    /// [`DidRecordDecodeError::EmptyValue`] if the total length is exactly the
    /// prefix; and [`DidRecordDecodeError::ValueTooLarge`] if the `value`
    /// remainder exceeds [`MAX_DID_RECORD_VALUE_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DidRecordDecodeError> {
        // Rule 1 — version gated first. `first()` yields `None` on an empty
        // buffer (too short to even carry a version), which is a truncation.
        let version = *bytes
            .first()
            .ok_or(DidRecordDecodeError::Truncated { len: 0 })?;
        if version != DID_RECORD_VERSION {
            return Err(DidRecordDecodeError::UnknownVersion { version });
        }

        // Rule 2 — full fixed prefix required.
        if bytes.len() < DID_RECORD_FIXED_PREFIX_LEN {
            return Err(DidRecordDecodeError::Truncated { len: bytes.len() });
        }

        // Rule 3 — value bounds, computed only after rule 2 (no underflow).
        let value_len = bytes.len() - DID_RECORD_FIXED_PREFIX_LEN;
        if value_len == 0 {
            return Err(DidRecordDecodeError::EmptyValue);
        }
        if value_len > MAX_DID_RECORD_VALUE_LEN {
            return Err(DidRecordDecodeError::ValueTooLarge {
                len: value_len,
                max: MAX_DID_RECORD_VALUE_LEN,
            });
        }

        // Fixed-width field reads. Rule 2 guarantees every slice below is
        // exactly its target width, so each `try_into` is infallible; the
        // mapped error arm is defensive (unreachable) and keeps this path free
        // of `unwrap`/`expect`/`panic`.
        let public_key: [u8; 32] = bytes[PUBLIC_KEY_OFFSET..SEQ_OFFSET]
            .try_into()
            .map_err(|_| DidRecordDecodeError::Truncated { len: bytes.len() })?;
        let seq = u64::from_be_bytes(
            bytes[SEQ_OFFSET..SIGNATURE_OFFSET]
                .try_into()
                .map_err(|_| DidRecordDecodeError::Truncated { len: bytes.len() })?,
        );
        let signature: [u8; 64] = bytes[SIGNATURE_OFFSET..VALUE_OFFSET]
            .try_into()
            .map_err(|_| DidRecordDecodeError::Truncated { len: bytes.len() })?;
        let value = bytes[VALUE_OFFSET..].to_vec();

        Ok(Self {
            public_key,
            seq,
            signature,
            value,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE_SEQ: u64 = 0x0102_0304_0506_0708;

    /// A deterministic 32-byte public key for tests.
    fn sample_public_key() -> [u8; 32] {
        [0xA1_u8; 32]
    }

    /// A deterministic 64-byte signature for tests.
    fn sample_signature() -> [u8; 64] {
        let mut sig = [0u8; 64];
        for (i, b) in sig.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = i as u8;
            }
        }
        sig
    }

    /// A deterministic value of the requested length.
    fn sample_value(value_len: usize) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        (0..value_len).map(|i| (i % 251) as u8).collect()
    }

    /// Builds a deterministic, well-formed frame with a `value` of the
    /// requested length via the validating constructor. `value_len` must be in
    /// `1..=MAX_DID_RECORD_VALUE_LEN` (a well-formed record).
    fn sample(value_len: usize) -> DidRecordV1 {
        DidRecordV1::try_new(
            sample_public_key(),
            SAMPLE_SEQ,
            sample_signature(),
            sample_value(value_len),
        )
        .expect("sample() must be called with a well-formed value length")
    }

    // -------------------------------------------------------------------
    // Validating constructor (try_new) — misuse resistance
    // -------------------------------------------------------------------

    #[test]
    fn try_new_rejects_empty_value() {
        assert_eq!(
            DidRecordV1::try_new(sample_public_key(), 7, sample_signature(), Vec::new()),
            Err(DidRecordBuildError::EmptyValue)
        );
    }

    #[test]
    fn try_new_rejects_oversize_value() {
        let value = sample_value(MAX_DID_RECORD_VALUE_LEN + 1);
        assert_eq!(
            DidRecordV1::try_new(sample_public_key(), 7, sample_signature(), value),
            Err(DidRecordBuildError::ValueTooLarge {
                len: MAX_DID_RECORD_VALUE_LEN + 1,
                max: MAX_DID_RECORD_VALUE_LEN,
            })
        );
    }

    #[test]
    fn try_new_accepts_one_byte_and_max_value() {
        // 1-byte value (minimum well-formed).
        let one = DidRecordV1::try_new(sample_public_key(), 7, sample_signature(), vec![0x2A])
            .expect("1-byte value is well-formed");
        assert_eq!(one.value(), &[0x2A]);

        // Max-size value (262039).
        let max = DidRecordV1::try_new(
            sample_public_key(),
            7,
            sample_signature(),
            sample_value(MAX_DID_RECORD_VALUE_LEN),
        )
        .expect("max-size value is well-formed");
        assert_eq!(max.value().len(), MAX_DID_RECORD_VALUE_LEN);
    }

    #[test]
    fn try_new_accessors_expose_fields() {
        let pk = sample_public_key();
        let sig = sample_signature();
        let record = DidRecordV1::try_new(pk, SAMPLE_SEQ, sig, vec![0xDE, 0xAD]).unwrap();
        assert_eq!(record.public_key(), &pk);
        assert_eq!(record.seq(), SAMPLE_SEQ);
        assert_eq!(record.signature(), &sig);
        assert_eq!(record.value(), &[0xDE, 0xAD]);
    }

    #[test]
    fn encode_of_try_new_decodes_back_byte_identically() {
        let record = DidRecordV1::try_new(
            sample_public_key(),
            SAMPLE_SEQ,
            sample_signature(),
            sample_value(200),
        )
        .unwrap();
        let bytes = record.encode();
        let decoded = DidRecordV1::decode(&bytes).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.encode(), bytes);
    }

    // -------------------------------------------------------------------
    // Byte-exact layout (AC 2)
    // -------------------------------------------------------------------

    #[test]
    fn encode_byte_exact_layout() {
        let record = sample(10);
        let bytes = record.encode();

        // Total length is exactly 105 + value.len().
        assert_eq!(bytes.len(), DID_RECORD_FIXED_PREFIX_LEN + 10);
        assert_eq!(bytes.len(), 115);

        // version at byte[0].
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[0], DID_RECORD_VERSION);

        // public_key at bytes[1..33].
        assert_eq!(&bytes[1..33], &record.public_key()[..]);

        // seq big-endian at bytes[33..41].
        assert_eq!(&bytes[33..41], &record.seq().to_be_bytes()[..]);
        // Spell the big-endian order out explicitly (MSB first).
        assert_eq!(
            &bytes[33..41],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..]
        );

        // signature at bytes[41..105].
        assert_eq!(&bytes[41..105], &record.signature()[..]);

        // value at bytes[105..].
        assert_eq!(&bytes[105..], record.value());
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(DID_RECORD_VERSION, 1);
        assert_eq!(DID_RECORD_FIXED_PREFIX_LEN, 1 + 32 + 8 + 64);
        assert_eq!(DID_RECORD_FIXED_PREFIX_LEN, 105);
        assert_eq!(MAX_BLOB_SIZE, 262_144);
        assert_eq!(MAX_DID_RECORD_VALUE_LEN, 262_144 - 105);
        assert_eq!(MAX_DID_RECORD_VALUE_LEN, 262_039);
    }

    // -------------------------------------------------------------------
    // Round-trip determinism (AC 3)
    // -------------------------------------------------------------------

    #[test]
    fn round_trip_is_byte_identical_and_idempotent() {
        let record = sample(64);
        let bytes = record.encode();

        let decoded = DidRecordV1::decode(&bytes).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.public_key(), record.public_key());
        assert_eq!(decoded.seq(), record.seq());
        assert_eq!(decoded.signature(), record.signature());
        assert_eq!(decoded.value(), record.value());

        // Re-encoding the decoded value yields identical bytes (idempotent).
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn seq_round_trips_extreme_values() {
        for seq in [0u64, 1, u64::from(u32::MAX), u64::MAX] {
            let record = DidRecordV1::try_new(
                sample_public_key(),
                seq,
                sample_signature(),
                sample_value(4),
            )
            .unwrap();
            let decoded = DidRecordV1::decode(&record.encode()).unwrap();
            assert_eq!(decoded.seq(), seq);
        }
    }

    // -------------------------------------------------------------------
    // Decoder rule 1 — version gated first (AC 4)
    // -------------------------------------------------------------------

    #[test]
    fn decode_rejects_messagepack_map_marker_as_version() {
        // An OuterEnvelope is rmp_serde-serialized as a map: its first byte is
        // a fixmap marker (0x80–0x8f) or 0xde/0xdf — never 0x01. Feeding one
        // must be rejected on the version check before any other byte.
        let mut bytes = vec![0x80_u8]; // fixmap(0) marker
        bytes.extend_from_slice(&[0u8; DID_RECORD_FIXED_PREFIX_LEN]); // otherwise long enough
        bytes.push(0xFF); // a would-be value byte
        assert_eq!(
            DidRecordV1::decode(&bytes),
            Err(DidRecordDecodeError::UnknownVersion { version: 0x80 })
        );
    }

    #[test]
    fn decode_rejects_every_non_one_version() {
        for version in [0x00_u8, 0x02, 0x7f, 0x80, 0xde, 0xdf, 0xFF] {
            // Build an otherwise-valid-length buffer, then overwrite version.
            let mut bytes = sample(8).encode();
            bytes[0] = version;
            assert_eq!(
                DidRecordV1::decode(&bytes),
                Err(DidRecordDecodeError::UnknownVersion { version }),
                "version {version:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn decode_version_checked_before_length() {
        // A single wrong-version byte is rejected as UnknownVersion (rule 1),
        // NOT as Truncated (rule 2) — proving version is checked first.
        assert_eq!(
            DidRecordV1::decode(&[0x80]),
            Err(DidRecordDecodeError::UnknownVersion { version: 0x80 })
        );
    }

    // -------------------------------------------------------------------
    // Decoder rule 2 — full fixed prefix required (AC 5)
    // -------------------------------------------------------------------

    #[test]
    fn decode_rejects_truncated_prefix_without_panic() {
        // len 0: cannot even read version -> Truncated { len: 0 }.
        assert_eq!(
            DidRecordV1::decode(&[]),
            Err(DidRecordDecodeError::Truncated { len: 0 })
        );

        // len 1 (correct version) and len 104: shorter than the 105-byte
        // prefix -> Truncated. No `len - 105` underflow, no panic in a debug
        // build (this test binary runs with debug-assertions on).
        for len in [1_usize, 2, 40, 104] {
            let bytes = vec![DID_RECORD_VERSION; len];
            assert_eq!(
                DidRecordV1::decode(&bytes),
                Err(DidRecordDecodeError::Truncated { len }),
                "length {len} must be rejected as truncated"
            );
        }
    }

    // -------------------------------------------------------------------
    // Decoder rule 3 — value bounds after prefix check (AC 6)
    // -------------------------------------------------------------------

    #[test]
    fn decode_rejects_empty_value_at_exactly_prefix_length() {
        // Exactly 105 bytes (valid version, no value) -> EmptyValue.
        let bytes = vec![DID_RECORD_VERSION; DID_RECORD_FIXED_PREFIX_LEN];
        assert_eq!(bytes.len(), 105);
        assert_eq!(
            DidRecordV1::decode(&bytes),
            Err(DidRecordDecodeError::EmptyValue)
        );
    }

    #[test]
    fn decode_accepts_one_byte_value_at_prefix_plus_one() {
        // 106 bytes -> a 1-byte value, accepted.
        let record = sample(1);
        let bytes = record.encode();
        assert_eq!(bytes.len(), 106);
        let decoded = DidRecordV1::decode(&bytes).unwrap();
        assert_eq!(decoded.value().len(), 1);
        assert_eq!(decoded, record);
    }

    #[test]
    fn decode_value_length_boundaries() {
        // Max-length value (262039) accepted.
        let ok = sample(MAX_DID_RECORD_VALUE_LEN);
        let ok_bytes = ok.encode();
        assert_eq!(ok_bytes.len(), MAX_BLOB_SIZE);
        let decoded = DidRecordV1::decode(&ok_bytes).unwrap();
        assert_eq!(decoded.value().len(), MAX_DID_RECORD_VALUE_LEN);
        assert_eq!(decoded, ok);

        // One byte over the max (262040) rejected. Built as raw bytes because a
        // well-formed DidRecordV1 with an oversize value is (deliberately)
        // unconstructable via try_new.
        let mut big_bytes = ok_bytes;
        big_bytes.push(0x00); // one extra value byte -> 262040-byte value
        assert_eq!(big_bytes.len(), MAX_BLOB_SIZE + 1);
        assert_eq!(
            DidRecordV1::decode(&big_bytes),
            Err(DidRecordDecodeError::ValueTooLarge {
                len: MAX_DID_RECORD_VALUE_LEN + 1,
                max: MAX_DID_RECORD_VALUE_LEN,
            })
        );
    }

    #[test]
    fn decode_rejects_grossly_oversize_value() {
        // A value far above the bound (near a 32-bit boundary in size) is
        // rejected without allocation surprises.
        let len = (u32::MAX as usize / 4).min(MAX_DID_RECORD_VALUE_LEN * 4);
        let mut bytes = vec![DID_RECORD_VERSION];
        bytes.resize(DID_RECORD_FIXED_PREFIX_LEN + len, 0u8);
        match DidRecordV1::decode(&bytes) {
            Err(DidRecordDecodeError::ValueTooLarge { len: got, max }) => {
                assert_eq!(got, len);
                assert_eq!(max, MAX_DID_RECORD_VALUE_LEN);
            }
            other => panic!("expected ValueTooLarge, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Trailing remainder is unambiguous — no value_len (AC: trailing test)
    // -------------------------------------------------------------------

    #[test]
    fn value_boundary_is_position_only_not_a_length_prefix() {
        // Two records that differ only in value length decode to exactly the
        // remainder after byte 105 — the boundary is positional, never read
        // from a length field.
        for value_len in [1_usize, 2, 3, 100, 1000] {
            let record = sample(value_len);
            let bytes = record.encode();
            let decoded = DidRecordV1::decode(&bytes).unwrap();
            assert_eq!(decoded.value().len(), value_len);
            assert_eq!(&bytes[VALUE_OFFSET..], decoded.value());
        }
    }

    #[test]
    fn value_containing_lengthlike_bytes_decodes_verbatim() {
        // A value whose own leading bytes look like a big-endian length prefix
        // (or a version byte) must be carried verbatim — proving there is no
        // value_len prefix being (mis)interpreted.
        let value = vec![0x00, 0x00, 0x01, 0x2C, 0x01, 0x80, 0xde, 0xff];
        let record = DidRecordV1::try_new(
            sample_public_key(),
            SAMPLE_SEQ,
            sample_signature(),
            value.clone(),
        )
        .unwrap();
        let bytes = record.encode();
        let decoded = DidRecordV1::decode(&bytes).unwrap();
        assert_eq!(decoded.value(), &value[..]);
        assert_eq!(&bytes[VALUE_OFFSET..], &value[..]);
    }

    #[test]
    fn appending_bytes_lengthens_value_not_a_separate_field() {
        // Since value is the trailing remainder, appending N bytes to the
        // frame lengthens value by exactly N.
        let record = sample(5);
        let mut bytes = record.encode();
        bytes.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        let decoded = DidRecordV1::decode(&bytes).unwrap();
        assert_eq!(decoded.value().len(), 5 + 3);
        assert_eq!(&decoded.value()[5..], &[0xAB, 0xCD, 0xEF]);
    }

    // -------------------------------------------------------------------
    // Property: encode/decode round-trip over arbitrary well-formed frames
    // -------------------------------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn prop_round_trip(
            public_key in proptest::array::uniform32(any::<u8>()),
            seq in any::<u64>(),
            signature in proptest::collection::vec(any::<u8>(), 64..=64),
            value in proptest::collection::vec(any::<u8>(), 1..=4096),
        ) {
            let sig: [u8; 64] = signature.try_into().unwrap();
            let value_len = value.len();
            let record = DidRecordV1::try_new(public_key, seq, sig, value).unwrap();
            let bytes = record.encode();
            prop_assert_eq!(bytes.len(), DID_RECORD_FIXED_PREFIX_LEN + value_len);
            let decoded = DidRecordV1::decode(&bytes).unwrap();
            prop_assert_eq!(&decoded, &record);
            prop_assert_eq!(decoded.encode(), bytes);
        }

        /// Cheap catch-all: fully-random input, most of which early-returns at
        /// the version gate. Kept for its zero cost, but the two generators
        /// below drive the deeper paths (truncation / value-length / slice
        /// reads) that this one rarely reaches (first byte == version only
        /// ~1/256 of the time).
        #[test]
        fn prop_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let result = DidRecordV1::decode(&bytes);
            prop_assert!(matches!(result, Ok(_) | Err(_)));
        }

        /// Version-correct frames of random length: prepends the real version
        /// byte then a random tail, so the truncation (len 1..104), empty-value
        /// (len == 105), value-length, and fixed-width slice-read paths all get
        /// exercised with random content — the paths the arbitrary-input
        /// generator almost never reaches.
        #[test]
        fn prop_versioned_tail_never_panics(tail in proptest::collection::vec(any::<u8>(), 0..300)) {
            let mut bytes = Vec::with_capacity(1 + tail.len());
            bytes.push(DID_RECORD_VERSION);
            bytes.extend_from_slice(&tail);
            let result = DidRecordV1::decode(&bytes);
            prop_assert!(matches!(result, Ok(_) | Err(_)));
            // A version-correct buffer of exactly the prefix length is an empty
            // value; one byte longer is the shortest well-formed frame.
            match bytes.len() {
                len if len < DID_RECORD_FIXED_PREFIX_LEN => {
                    prop_assert_eq!(result, Err(DidRecordDecodeError::Truncated { len }));
                }
                DID_RECORD_FIXED_PREFIX_LEN => {
                    prop_assert_eq!(result, Err(DidRecordDecodeError::EmptyValue));
                }
                _ => prop_assert!(result.is_ok()),
            }
        }

        /// Boundary-clustered lengths (95..=115) filled with an arbitrary byte,
        /// with the first byte either version-correct or version-wrong. This
        /// hammers the exact 105-byte prefix boundary — where the `len − 105`
        /// underflow risk lives — from both sides and both version dispositions.
        #[test]
        fn prop_prefix_boundary_never_panics(
            len in 95_usize..=115,
            fill in any::<u8>(),
            version_correct in any::<bool>(),
        ) {
            let mut bytes = vec![fill; len];
            bytes[0] = if version_correct { DID_RECORD_VERSION } else { fill };
            let result = DidRecordV1::decode(&bytes);
            prop_assert!(matches!(result, Ok(_) | Err(_)));
        }
    }
}
