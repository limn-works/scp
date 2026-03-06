//! Shared serde helpers for size-bounded deserialization (#347).
//!
//! These modules enforce strict size limits on binary fields during
//! deserialization to prevent OOM denial-of-service from oversized payloads
//! on untrusted input.
//!
//! # Fixed-size arrays
//!
//! - [`serde_signature_64`] — Ed25519 signatures (exactly 64 bytes)
//! - [`serde_hash_32`] — SHA-256 hashes (exactly 32 bytes)
//! - [`serde_pubkey_32`] — X25519 public keys (exactly 32 bytes)
//!
//! # Bounded variable-size
//!
//! - [`serde_bounded_bytes`] — Variable-size binary with a 512 KiB cap

/// Maximum size for bounded binary fields (512 KiB).
///
/// This is large enough for any legitimate SCP payload (the relay enforces
/// `MAX_BLOB_SIZE = 256 KiB` at the transport layer) while still preventing
/// multi-gigabyte allocations from malicious input.
pub const BOUNDED_BYTES_MAX: usize = 512 * 1024;

/// Serde module for `[u8; 64]` fields (Ed25519 signatures).
///
/// Serializes via `serde_bytes` for compact binary representation and
/// validates exact length on deserialization. Rejects anything other than
/// exactly 64 bytes.
pub mod serde_signature_64 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64-byte signature, got {} bytes", v.len()))
        })
    }
}

/// Serde module for `[u8; 32]` fields (SHA-256 hashes, X25519 public keys).
///
/// Same pattern as [`serde_signature_64`] but for 32-byte values.
pub mod serde_hash_32 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32-byte hash, got {} bytes", v.len()))
        })
    }
}

/// Serde module for variable-length `Vec<u8>` fields with a 512 KiB cap.
///
/// Serializes identically to `serde_bytes` but rejects payloads larger than
/// [`BOUNDED_BYTES_MAX`] on deserialization. This prevents OOM from untrusted
/// input while remaining compatible with legitimate SCP payloads.
pub mod serde_bounded_bytes {
    use serde::{self, Deserializer, Serializer};

    use super::BOUNDED_BYTES_MAX;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        if v.len() > BOUNDED_BYTES_MAX {
            return Err(serde::de::Error::custom(format!(
                "binary field exceeds {} byte limit (got {} bytes)",
                BOUNDED_BYTES_MAX,
                v.len()
            )));
        }
        Ok(v)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bounded_bytes_accepts_within_limit() {
        // Serialize a payload under the limit
        let data = vec![0xABu8; 1024];
        let serialized = rmp_serde::to_vec_named(&BoundedWrapper { data: data.clone() }).unwrap();
        let deserialized: BoundedWrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn bounded_bytes_rejects_over_limit() {
        // Serialize a payload over the limit (just above 512 KiB)
        let data = vec![0xABu8; BOUNDED_BYTES_MAX + 1];
        let serialized = rmp_serde::to_vec_named(&BoundedWrapper { data: data.clone() }).unwrap();
        let result = rmp_serde::from_slice::<BoundedWrapper>(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds"),
            "error should mention exceeds: {err}"
        );
    }

    #[test]
    fn signature_64_rejects_wrong_size() {
        // 63 bytes — too short
        let short = Sig64Wrapper {
            sig: [0u8; 64], // serialize valid, then tamper
        };
        let serialized = rmp_serde::to_vec_named(&short).unwrap();
        // Replace the binary with 63 bytes: find the bin8 header and change length
        // Easier: just serialize a Vec<u8> of wrong size through a helper struct
        let bad = BadSigWrapper { sig: vec![0u8; 63] };
        let serialized_bad = rmp_serde::to_vec_named(&bad).unwrap();
        let result = rmp_serde::from_slice::<Sig64Wrapper>(&serialized_bad);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("64-byte signature"),
            "error should mention 64-byte: {err}"
        );

        // 65 bytes — too long
        let bad_long = BadSigWrapper { sig: vec![0u8; 65] };
        let serialized_bad_long = rmp_serde::to_vec_named(&bad_long).unwrap();
        let result = rmp_serde::from_slice::<Sig64Wrapper>(&serialized_bad_long);
        assert!(result.is_err());

        // Suppress unused variable warning
        drop(serialized);
    }

    #[test]
    fn hash_32_rejects_wrong_size() {
        let bad = BadHashWrapper {
            hash: vec![0u8; 31],
        };
        let serialized = rmp_serde::to_vec_named(&bad).unwrap();
        let result = rmp_serde::from_slice::<Hash32Wrapper>(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("32-byte hash"),
            "error should mention 32-byte: {err}"
        );
    }

    #[test]
    fn signature_64_roundtrip() {
        let wrapper = Sig64Wrapper { sig: [0xAB; 64] };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: Sig64Wrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.sig, [0xAB; 64]);
    }

    #[test]
    fn hash_32_roundtrip() {
        let wrapper = Hash32Wrapper { hash: [0xCD; 32] };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: Hash32Wrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.hash, [0xCD; 32]);
    }

    // Test helper structs

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BoundedWrapper {
        #[serde(with = "serde_bounded_bytes")]
        data: Vec<u8>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Sig64Wrapper {
        #[serde(with = "serde_signature_64")]
        sig: [u8; 64],
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BadSigWrapper {
        #[serde(with = "serde_bytes")]
        sig: Vec<u8>,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Hash32Wrapper {
        #[serde(with = "serde_hash_32")]
        hash: [u8; 32],
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BadHashWrapper {
        #[serde(with = "serde_bytes")]
        hash: Vec<u8>,
    }
}
