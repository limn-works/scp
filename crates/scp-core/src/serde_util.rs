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
//! - [`serde_pubkey_32`] — X25519 / Ed25519 public keys (exactly 32 bytes)
//! - [`serde_hpke_sealed_60`] — HPKE-sealed sender key (exactly 60 bytes)
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

/// Maximum total wire size for an outer envelope (576 KiB).
///
/// This is `BOUNDED_BYTES_MAX` (512 KiB for the encrypted blob) plus 64 KiB
/// of overhead for `MessagePack` framing, `routing_id` (32 bytes), optional
/// `recipient_hint` (32 bytes), `blob_ttl`, and structural overhead. Checked
/// *before* deserialization in `OuterEnvelope::from_bytes` to reject
/// obviously oversized inputs without invoking the deserializer.
pub const MAX_ENVELOPE_SIZE: usize = BOUNDED_BYTES_MAX + 64 * 1024;

/// Maximum size for bounded string fields (1 KiB / 1024 bytes).
///
/// DID strings (e.g., `did:dht:z6Mk...`) are typically 50-100 bytes. Context
/// IDs are 64-character hex strings. A 1 KiB cap is generous for any
/// legitimate SCP identifier while preventing multi-gigabyte string
/// allocations from malicious input.
pub const BOUNDED_STRING_MAX: usize = 1024;

/// Serde module for `[u8; 64]` fields (Ed25519 signatures).
///
/// Serializes via `serde_bytes` for compact binary representation and
/// validates exact length on deserialization. Rejects anything other than
/// exactly 64 bytes.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
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
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
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

/// Serde module for `[u8; 32]` fields (X25519 / Ed25519 public keys).
///
/// Same pattern as [`serde_hash_32`] but with a domain-specific error message.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_pubkey_32 {
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
            serde::de::Error::custom(format!(
                "expected 32-byte public key, got {} bytes",
                v.len()
            ))
        })
    }
}

/// Serde module for `[u8; 60]` fields (HPKE-sealed sender keys).
///
/// The HPKE-sealed sender key is exactly 60 bytes: AES-128-GCM nonce (12) +
/// encrypted sender key (32) + authentication tag (16). Using a fixed-size
/// array prevents allocation of arbitrarily large buffers from malicious input.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_hpke_sealed_60 {
    use serde::{self, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 60], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 60], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!(
                "expected 60-byte HPKE sealed key, got {} bytes",
                v.len()
            ))
        })
    }
}

/// Serde module for variable-length `Vec<u8>` fields with a 512 KiB cap.
///
/// Serializes identically to `serde_bytes` but rejects payloads larger than
/// [`BOUNDED_BYTES_MAX`] on deserialization. This prevents OOM from untrusted
/// input while remaining compatible with legitimate SCP payloads.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_bounded_bytes {
    use serde::de::Visitor;
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
        struct BoundedBytesVisitor;

        impl<'de> Visitor<'de> for BoundedBytesVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "binary data up to {BOUNDED_BYTES_MAX} bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_BYTES_MAX {
                    return Err(E::custom(format!(
                        "binary field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_BYTES_MAX,
                        v.len()
                    )));
                }
                Ok(v.to_vec())
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_BYTES_MAX {
                    return Err(E::custom(format!(
                        "binary field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_BYTES_MAX,
                        v.len()
                    )));
                }
                Ok(v)
            }

            // MessagePack may present binary data as a sequence of integers.
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                // Check size_hint before allocating.
                let hint = seq.size_hint().unwrap_or(0);
                if hint > BOUNDED_BYTES_MAX {
                    return Err(serde::de::Error::custom(format!(
                        "binary field exceeds {BOUNDED_BYTES_MAX} byte limit (declared {hint} bytes)"
                    )));
                }
                let mut buf = Vec::with_capacity(hint);
                while let Some(byte) = seq.next_element::<u8>()? {
                    if buf.len() >= BOUNDED_BYTES_MAX {
                        return Err(serde::de::Error::custom(format!(
                            "binary field exceeds {BOUNDED_BYTES_MAX} byte limit"
                        )));
                    }
                    buf.push(byte);
                }
                Ok(buf)
            }
        }

        deserializer.deserialize_bytes(BoundedBytesVisitor)
    }
}

/// Serde module for `String` fields with a [`BOUNDED_STRING_MAX`] cap.
///
/// Serializes identically to the default `String` serializer but rejects
/// strings longer than [`BOUNDED_STRING_MAX`] on deserialization. This
/// prevents OOM from malicious input containing gigabyte-length identifiers
/// in `context_id`, `sender_did`, or provenance `source` fields.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_bounded_string {
    use serde::de::Visitor;
    use serde::{self, Deserializer, Serializer};

    use super::BOUNDED_STRING_MAX;

    pub fn serialize<S>(s: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedStringVisitor;

        impl Visitor<'_> for BoundedStringVisitor {
            type Value = String;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a string up to {BOUNDED_STRING_MAX} bytes")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_STRING_MAX {
                    return Err(E::custom(format!(
                        "string field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_STRING_MAX,
                        v.len()
                    )));
                }
                Ok(v.to_owned())
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_STRING_MAX {
                    return Err(E::custom(format!(
                        "string field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_STRING_MAX,
                        v.len()
                    )));
                }
                Ok(v)
            }
        }

        deserializer.deserialize_string(BoundedStringVisitor)
    }
}

/// Serde module for `Option<String>` fields with a [`BOUNDED_STRING_MAX`] cap.
///
/// Same semantics as [`serde_bounded_string`] but for optional string fields.
/// `None` is preserved through serialization/deserialization roundtrips.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_bounded_string_opt {
    use serde::de::Visitor;
    use serde::{self, Deserializer, Serializer};

    use super::BOUNDED_STRING_MAX;

    pub fn serialize<S>(s: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match s {
            Some(v) => serializer.serialize_some(v),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedOptStringVisitor;

        impl<'de> Visitor<'de> for BoundedOptStringVisitor {
            type Value = Option<String>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "an optional string up to {BOUNDED_STRING_MAX} bytes")
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<Self::Value, D2::Error> {
                super::serde_bounded_string::deserialize(deserializer).map(Some)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_STRING_MAX {
                    return Err(E::custom(format!(
                        "string field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_STRING_MAX,
                        v.len()
                    )));
                }
                Ok(Some(v.to_owned()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                if v.len() > BOUNDED_STRING_MAX {
                    return Err(E::custom(format!(
                        "string field exceeds {} byte limit (got {} bytes)",
                        BOUNDED_STRING_MAX,
                        v.len()
                    )));
                }
                Ok(Some(v))
            }
        }

        deserializer.deserialize_option(BoundedOptStringVisitor)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::assertions_on_constants
)]
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
        let serialized = rmp_serde::to_vec_named(&BoundedWrapper { data }).unwrap();
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

    // --- pubkey_32 tests ---

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Pubkey32Wrapper {
        #[serde(with = "serde_pubkey_32")]
        key: [u8; 32],
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BadPubkeyWrapper {
        #[serde(with = "serde_bytes")]
        key: Vec<u8>,
    }

    #[test]
    fn pubkey_32_roundtrip() {
        let wrapper = Pubkey32Wrapper { key: [0xEF; 32] };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: Pubkey32Wrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.key, [0xEF; 32]);
    }

    #[test]
    fn pubkey_32_rejects_wrong_size() {
        let bad = BadPubkeyWrapper { key: vec![0u8; 31] };
        let serialized = rmp_serde::to_vec_named(&bad).unwrap();
        let result = rmp_serde::from_slice::<Pubkey32Wrapper>(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("32-byte public key"),
            "error should mention 32-byte public key: {err}"
        );
    }

    // --- hpke_sealed_60 tests ---

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct HpkeSealed60Wrapper {
        #[serde(with = "serde_hpke_sealed_60")]
        sealed: [u8; 60],
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BadHpkeSealedWrapper {
        #[serde(with = "serde_bytes")]
        sealed: Vec<u8>,
    }

    #[test]
    fn hpke_sealed_60_roundtrip() {
        let wrapper = HpkeSealed60Wrapper { sealed: [0xAB; 60] };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: HpkeSealed60Wrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.sealed, [0xAB; 60]);
    }

    #[test]
    fn hpke_sealed_60_rejects_wrong_size() {
        let bad = BadHpkeSealedWrapper {
            sealed: vec![0u8; 59],
        };
        let serialized = rmp_serde::to_vec_named(&bad).unwrap();
        let result = rmp_serde::from_slice::<HpkeSealed60Wrapper>(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("60-byte HPKE sealed key"),
            "error should mention 60-byte: {err}"
        );

        // 61 bytes — too long
        let bad_long = BadHpkeSealedWrapper {
            sealed: vec![0u8; 61],
        };
        let serialized_long = rmp_serde::to_vec_named(&bad_long).unwrap();
        let result = rmp_serde::from_slice::<HpkeSealed60Wrapper>(&serialized_long);
        assert!(result.is_err());
    }

    // --- bounded_string tests ---

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BoundedStringWrapper {
        #[serde(with = "serde_bounded_string")]
        name: String,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct BoundedStringOptWrapper {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "serde_bounded_string_opt"
        )]
        name: Option<String>,
    }

    #[test]
    fn bounded_string_accepts_within_limit() {
        let wrapper = BoundedStringWrapper {
            name: "a".repeat(BOUNDED_STRING_MAX),
        };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: BoundedStringWrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.name.len(), BOUNDED_STRING_MAX);
    }

    #[test]
    fn bounded_string_rejects_over_limit() {
        let wrapper = BoundedStringWrapper {
            name: "a".repeat(BOUNDED_STRING_MAX + 1),
        };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let result = rmp_serde::from_slice::<BoundedStringWrapper>(&serialized);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds"),
            "error should mention exceeds: {err}"
        );
    }

    #[test]
    fn bounded_string_roundtrip() {
        let wrapper = BoundedStringWrapper {
            name: "did:dht:z6MkTest".into(),
        };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: BoundedStringWrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.name, "did:dht:z6MkTest");
    }

    #[test]
    fn bounded_string_opt_roundtrip_some() {
        let wrapper = BoundedStringOptWrapper {
            name: Some("hello".into()),
        };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: BoundedStringOptWrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert_eq!(deserialized.name.as_deref(), Some("hello"));
    }

    #[test]
    fn bounded_string_opt_roundtrip_none() {
        let wrapper = BoundedStringOptWrapper { name: None };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let deserialized: BoundedStringOptWrapper = rmp_serde::from_slice(&serialized).unwrap();
        assert!(deserialized.name.is_none());
    }

    #[test]
    fn bounded_string_opt_rejects_over_limit() {
        let wrapper = BoundedStringOptWrapper {
            name: Some("a".repeat(BOUNDED_STRING_MAX + 1)),
        };
        let serialized = rmp_serde::to_vec_named(&wrapper).unwrap();
        let result = rmp_serde::from_slice::<BoundedStringOptWrapper>(&serialized);
        assert!(result.is_err());
    }

    // --- constant value tests ---

    #[test]
    fn max_envelope_size_exceeds_bounded_bytes_max() {
        const { assert!(MAX_ENVELOPE_SIZE > BOUNDED_BYTES_MAX) };
        assert_eq!(MAX_ENVELOPE_SIZE, BOUNDED_BYTES_MAX + 64 * 1024);
    }

    #[test]
    fn bounded_string_max_is_1024() {
        assert_eq!(BOUNDED_STRING_MAX, 1024);
    }
}
