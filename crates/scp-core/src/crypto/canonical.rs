//! Canonical hash construction for signed structures (§9.5.1).
//!
//! Every signed structure in the protocol uses this construction to produce
//! the bytes that are signed. The encoding is deterministic: two implementations
//! that serialize the same logical data produce identical bytes.
//!
//! # Construction
//!
//! `SHA-256(domain_separator || field_1 || field_2 || ... || field_N)`
//!
//! - Variable-length fields: 4-byte big-endian length prefix + raw bytes.
//! - Fixed-length fields (`[u8; 32]`, `[u8; 64]`): raw bytes, no prefix.
//! - `u64`: 8 bytes big-endian.
//! - `u32`: 4 bytes big-endian.
//! - `u16`: 2 bytes big-endian.
//! - Optional absent: `SHA-256(0x00)` sentinel (32 bytes).

use sha2::{Digest, Sha256};

#[cfg(test)]
use hex;

/// Sentinel value for absent optional fields: `SHA-256(0x00)`.
///
/// Pre-computed to avoid re-hashing on every call.
const ABSENT_SENTINEL: [u8; 32] = [
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
];

/// A field in a canonical hash construction.
pub enum CanonicalField<'a> {
    /// Variable-length bytes: 4-byte BE length prefix + raw bytes.
    VarBytes(&'a [u8]),
    /// Raw bytes written without any prefix. Use for fixed-size fields
    /// that aren't exactly 32 or 64 bytes (e.g., 16-byte nonce, literal tags).
    RawBytes(&'a [u8]),
    /// Fixed-length 32-byte value (hash, public key): raw bytes, no prefix.
    Fixed32(&'a [u8; 32]),
    /// Fixed-length 64-byte value (signature): raw bytes, no prefix.
    Fixed64(&'a [u8; 64]),
    /// Unsigned 64-bit integer: 8 bytes big-endian.
    U64(u64),
    /// Unsigned 32-bit integer: 4 bytes big-endian.
    U32(u32),
    /// Unsigned 16-bit integer: 2 bytes big-endian.
    U16(u16),
    /// Optional field that is absent: uses `SHA-256(0x00)` sentinel.
    Absent,
}

/// Compute the canonical hash for a signed structure.
///
/// The domain separator is written as raw UTF-8 bytes (no length prefix).
/// Each field is then encoded per the rules in §9.5.1.
///
/// # Panics
///
/// Panics if a `VarBytes` field exceeds `u32::MAX` bytes (4 GiB). This cannot
/// happen in practice — protocol messages are bounded to 256 KB (§9.10.3).
#[must_use]
pub fn canonical_hash(domain: &str, fields: &[CanonicalField<'_>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());

    for field in fields {
        match field {
            CanonicalField::VarBytes(b) => {
                // Safety: protocol messages are ≤256 KB; u32::MAX is 4 GiB.
                #[allow(clippy::expect_used)]
                let len = u32::try_from(b.len()).expect("field exceeds u32::MAX bytes");
                hasher.update(len.to_be_bytes());
                hasher.update(b);
            }
            CanonicalField::RawBytes(b) => hasher.update(b),
            CanonicalField::Fixed32(b) => hasher.update(b.as_slice()),
            CanonicalField::Fixed64(b) => hasher.update(b.as_slice()),
            CanonicalField::U64(n) => hasher.update(n.to_be_bytes()),
            CanonicalField::U32(n) => hasher.update(n.to_be_bytes()),
            CanonicalField::U16(n) => hasher.update(n.to_be_bytes()),
            CanonicalField::Absent => hasher.update(ABSENT_SENTINEL),
        }
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_sentinel_is_sha256_of_zero_byte() {
        let expected: [u8; 32] = Sha256::digest([0x00]).into();
        assert_eq!(ABSENT_SENTINEL, expected);
    }

    #[test]
    fn different_splits_produce_different_hashes() {
        // "abc" + "def" vs "ab" + "cdef" — must differ with length prefixes
        let hash1 = canonical_hash(
            "TEST:",
            &[
                CanonicalField::VarBytes(b"abc"),
                CanonicalField::VarBytes(b"def"),
            ],
        );
        let hash2 = canonical_hash(
            "TEST:",
            &[
                CanonicalField::VarBytes(b"ab"),
                CanonicalField::VarBytes(b"cdef"),
            ],
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn same_fields_produce_same_hash() {
        let hash1 = canonical_hash(
            "TEST:",
            &[
                CanonicalField::VarBytes(b"context-1"),
                CanonicalField::VarBytes(b"did:example:alice"),
                CanonicalField::U64(42),
            ],
        );
        let hash2 = canonical_hash(
            "TEST:",
            &[
                CanonicalField::VarBytes(b"context-1"),
                CanonicalField::VarBytes(b"did:example:alice"),
                CanonicalField::U64(42),
            ],
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn domain_separator_matters() {
        let hash1 = canonical_hash(
            "SCP-INNER-ENVELOPE-V1:",
            &[CanonicalField::VarBytes(b"data")],
        );
        let hash2 = canonical_hash(
            "SCP-BROADCAST-ENVELOPE-V1:",
            &[CanonicalField::VarBytes(b"data")],
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn absent_differs_from_empty() {
        let hash_absent = canonical_hash("TEST:", &[CanonicalField::Absent]);
        let hash_empty = canonical_hash("TEST:", &[CanonicalField::VarBytes(b"")]);
        assert_ne!(hash_absent, hash_empty);
    }

    #[test]
    fn u64_is_big_endian() {
        let hash = canonical_hash("TEST:", &[CanonicalField::U64(1)]);
        // Manually compute: SHA-256("TEST:" || 0x0000000000000001)
        let mut hasher = Sha256::new();
        hasher.update(b"TEST:");
        hasher.update(1u64.to_be_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn fixed32_no_length_prefix() {
        let key = [0xABu8; 32];
        let hash = canonical_hash("TEST:", &[CanonicalField::Fixed32(&key)]);
        // Manually compute: SHA-256("TEST:" || 32 bytes of 0xAB)
        let mut hasher = Sha256::new();
        hasher.update(b"TEST:");
        hasher.update([0xAB; 32]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn migration_proof_compatibility() {
        // Verify our construction matches the migration proof pattern from §9.12:
        // SHA-256("SCP-MIGRATION-V1:" || len(old_did) || old_did || len(new_did) || new_did || rotated_at)
        let old_did = b"did:dht:z6MkOLD";
        let new_did = b"did:dht:z6MkNEW";
        let rotated_at: u64 = 1_709_654_400;

        let hash = canonical_hash(
            "SCP-MIGRATION-V1:",
            &[
                CanonicalField::VarBytes(old_did),
                CanonicalField::VarBytes(new_did),
                CanonicalField::U64(rotated_at),
            ],
        );

        // Manual computation
        let mut hasher = Sha256::new();
        hasher.update(b"SCP-MIGRATION-V1:");
        #[allow(clippy::cast_possible_truncation)]
        let old_len = old_did.len() as u32;
        hasher.update(old_len.to_be_bytes());
        hasher.update(old_did);
        #[allow(clippy::cast_possible_truncation)]
        let new_len = new_did.len() as u32;
        hasher.update(new_len.to_be_bytes());
        hasher.update(new_did);
        hasher.update(rotated_at.to_be_bytes());
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(hash, expected);
    }

    #[test]
    fn golden_vector_inner_envelope() {
        // Golden test vector: a minimal InnerEnvelope canonical hash.
        // This vector can be reproduced independently in any language.
        //
        // Domain: "SCP-INNER-ENVELOPE-V1:"
        // Fields (in order per §9.5.2):
        //   1. context_id = "ctx-1" (VarBytes)
        //   2. sender_did = "did:example:alice" (VarBytes)
        //   3. epoch = 1 (U64)
        //   4. generation = 0 (U64)
        //   5. sequence = 42 (U64)
        //   6. timestamp = 1709654400 (U64)
        //   7. payload_hash = SHA-256("hello") with 4-byte length prefix (VarBytes)
        //   8. provenance_hash = absent sentinel (Absent)
        //   9. signing_key_id = "#active" (VarBytes)
        let payload_hash: [u8; 32] = Sha256::digest(b"hello").into();

        let hash = canonical_hash(
            "SCP-INNER-ENVELOPE-V1:",
            &[
                CanonicalField::VarBytes(b"ctx-1"),
                CanonicalField::VarBytes(b"did:example:alice"),
                CanonicalField::U64(1),
                CanonicalField::U64(0),
                CanonicalField::U64(42),
                CanonicalField::U64(1_709_654_400),
                CanonicalField::VarBytes(&payload_hash),
                CanonicalField::Absent,
                CanonicalField::VarBytes(b"#active"),
            ],
        );

        // Expected: SHA-256 of the concatenation above.
        // Independently verifiable via:
        //   import hashlib, struct
        //   def lp(b): return struct.pack('>I', len(b)) + b
        //   payload_hash = hashlib.sha256(b'hello').digest()
        //   absent = hashlib.sha256(b'\x00').digest()
        //   data = (b'SCP-INNER-ENVELOPE-V1:'
        //     + lp(b'ctx-1') + lp(b'did:example:alice')
        //     + struct.pack('>Q', 1) + struct.pack('>Q', 0)
        //     + struct.pack('>Q', 42) + struct.pack('>Q', 1709654400)
        //     + lp(payload_hash) + absent + lp(b'#active'))
        //   print(hashlib.sha256(data).hexdigest())
        assert_eq!(hex::encode(hash), {
            // Compute expected at test time (same construction, different code path)
            let mut h = Sha256::new();
            h.update(b"SCP-INNER-ENVELOPE-V1:");
            h.update(5u32.to_be_bytes()); // len("ctx-1")
            h.update(b"ctx-1");
            h.update(17u32.to_be_bytes()); // len("did:example:alice")
            h.update(b"did:example:alice");
            h.update(1u64.to_be_bytes());
            h.update(0u64.to_be_bytes());
            h.update(42u64.to_be_bytes());
            h.update(1_709_654_400u64.to_be_bytes());
            h.update(32u32.to_be_bytes()); // len(payload_hash)
            h.update(payload_hash);
            h.update(ABSENT_SENTINEL);
            h.update(7u32.to_be_bytes()); // len("#active")
            h.update(b"#active");
            let expected: [u8; 32] = h.finalize().into();
            hex::encode(expected)
        });
    }

    #[test]
    fn u16_encoding() {
        let hash = canonical_hash("TEST:", &[CanonicalField::U16(258)]);
        let mut hasher = Sha256::new();
        hasher.update(b"TEST:");
        hasher.update(258u16.to_be_bytes()); // 0x01, 0x02
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn fixed64_no_length_prefix() {
        let sig = [0xCDu8; 64];
        let hash = canonical_hash("TEST:", &[CanonicalField::Fixed64(&sig)]);
        let mut hasher = Sha256::new();
        hasher.update(b"TEST:");
        hasher.update([0xCD; 64]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn multiple_absent_fields() {
        let hash1 = canonical_hash("TEST:", &[CanonicalField::Absent]);
        let hash2 = canonical_hash("TEST:", &[CanonicalField::Absent, CanonicalField::Absent]);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn varbytes_32_differs_from_fixed32() {
        let data = [0xAB; 32];
        let hash_var = canonical_hash("TEST:", &[CanonicalField::VarBytes(&data)]);
        let hash_fixed = canonical_hash("TEST:", &[CanonicalField::Fixed32(&data)]);
        // VarBytes has a 4-byte length prefix; Fixed32 does not.
        assert_ne!(hash_var, hash_fixed);
    }
}
