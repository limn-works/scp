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
//!
//! # Deterministic set serialization (signed-export canonicalization)
//!
//! - [`serde_sorted_set`] — serializes a `HashSet<T>` as a JSON/MessagePack
//!   array whose elements are emitted in a deterministic, content-derived
//!   order. RFC 8785 JCS (used to sign a `ContextExport`, spec §23.16.8)
//!   canonicalizes JSON *object* member order but NOT *array* element order,
//!   so a `HashSet` serialized with the default (iteration-order) serializer
//!   produces a non-deterministic digest. Sorting the elements before
//!   serialization makes the canonical JSON — and therefore the export
//!   signature digest — byte-identical across runs **within a single
//!   serializer/bridge-family** (ADR-050, the `BTreeSet` convention named in
//!   §23.16.8). This is NOT a cross-family byte-equivalence claim: native
//!   (`MessagePack`) and WASM (JSON) serialize structurally different snapshot
//!   value types, so only the *construction* converges, not the digest bytes.
//!   Deserialization
//!   is order-independent for a set, so sorted serialization is always safe:
//!   nothing correct can depend on a `HashSet`'s incidental iteration order.
//! - [`serde_sorted_set_map`] — serializes a `HashMap<String, HashSet<T>>`
//!   with the inner sets sorted (the outer string-keyed map is already
//!   canonicalized by JCS object-key sorting).
//! - [`serde_hex_keyed_map_32`] — serializes a `HashMap<[u8; 32], V>` as a
//!   hex-keyed JSON object so its `[u8; 32]` keys are valid JSON object keys
//!   that JCS can canonicalize (the keys are sorted by JCS object-key order).

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

    /// Serializes a 64-byte array as compact binary via `serde_bytes`.
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes exactly 64 bytes, rejecting any other length.
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

    /// Serializes a 32-byte array as compact binary via `serde_bytes`.
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes exactly 32 bytes, rejecting any other length.
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

    /// Serializes a 32-byte public key as compact binary via `serde_bytes`.
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes exactly 32 bytes as a public key, rejecting any other length.
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

    /// Serializes a 60-byte HPKE-sealed sender key as compact binary.
    pub fn serialize<S>(bytes: &[u8; 60], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes.as_slice(), serializer)
    }

    /// Deserializes exactly 60 bytes as an HPKE-sealed sender key.
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

    /// Serializes a byte slice as compact binary via `serde_bytes`.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes, serializer)
    }

    /// Deserializes variable-length binary, rejecting payloads exceeding 512 KiB.
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

    /// Serializes a string using the default string serializer.
    pub fn serialize<S>(s: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(s)
    }

    /// Deserializes a string, rejecting values exceeding 1 KiB.
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

    /// Serializes an optional string, preserving `None` as absent.
    pub fn serialize<S>(s: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match s {
            Some(v) => serializer.serialize_some(v),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional string, rejecting values exceeding 1 KiB.
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

/// Serde module for `HashSet<T>` fields that must serialize deterministically.
///
/// Emits the set as an array whose elements are ordered by their canonical
/// JSON (RFC 8785 JCS) byte sequence. Because JCS canonicalizes object-member
/// order but leaves array order untouched, a `HashSet` serialized in iteration
/// order yields a non-deterministic digest; ordering by canonical-JSON bytes
/// makes the output stable across runs **within a single serializer/bridge-
/// family** (not a cross-family byte-equivalence guarantee — see the
/// module-level note and §23.16.8).
///
/// `T` is ordered by its own canonical-JSON serialization rather than by a
/// `Ord` bound so the helper applies uniformly to set element types that do
/// not implement `Ord` (e.g. [`crate::context::roles::Capability`]). The sort
/// key is total and deterministic: two distinct elements that produced equal
/// canonical JSON would be equal values (a contradiction for set members), so
/// ties cannot occur in practice; a stable sort keeps any tie order fixed.
///
/// Deserialization restores into a `HashSet`, which is order-independent, so a
/// snapshot persisted before this change still loads unchanged.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_sorted_set {
    use std::collections::HashSet;
    use std::hash::{BuildHasher, Hash};

    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes a set as an array ordered by each element's canonical JSON.
    pub fn serialize<T, H, S>(set: &HashSet<T, H>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        H: BuildHasher,
        S: Serializer,
    {
        // Compute a deterministic sort key per element: its RFC 8785 canonical
        // JSON bytes.
        //
        // Amplification note: this performs one extra JCS serialization per set
        // element (O(n) in the number of elements), bounded by the export size
        // cap enforced upstream before signing runs (native 64 MiB / WASM
        // 16 MiB). Element types here are flat (no nested set-of-sets), so the
        // per-element JCS work is proportional to total export size, not
        // quadratic. If a nested set-of-sets element type is ever added,
        // re-evaluate the amplification factor before relying on this bound.
        //
        // A JCS failure (e.g. a future element type with a
        // non-string, non-hex map key that JCS cannot canonicalize) MUST fail
        // loudly rather than collapse to an empty key — an empty key would make
        // the sort order depend on incidental iteration order, silently
        // breaking the determinism this helper exists to guarantee. Propagate
        // it as a serialization error so the export-signing path aborts.
        let mut keyed: Vec<(Vec<u8>, &T)> = set
            .iter()
            .map(|e| crate::jcs::to_vec(e).map(|bytes| (bytes, e)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                serde::ser::Error::custom(format!(
                    "serde_sorted_set: element canonical-JSON (JCS) serialization \
                     failed, cannot produce deterministic order: {e}"
                ))
            })?;
        keyed.sort_by(|a, b| a.0.cmp(&b.0));

        let mut seq = serializer.serialize_seq(Some(keyed.len()))?;
        for (_, element) in keyed {
            seq.serialize_element(element)?;
        }
        seq.end()
    }

    /// Deserializes an array back into a `HashSet` (order-independent).
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<HashSet<T>, D::Error>
    where
        T: Deserialize<'de> + Eq + Hash,
        D: Deserializer<'de>,
    {
        let v: Vec<T> = Vec::deserialize(deserializer)?;
        Ok(v.into_iter().collect())
    }
}

/// Serde module for `HashMap<String, HashSet<T>>` fields that must serialize
/// deterministically.
///
/// The outer `String`-keyed map is already canonicalized by RFC 8785 JCS
/// (object members are emitted in sorted key order), but each inner
/// `HashSet<T>` value would serialize as an array in non-deterministic
/// iteration order. This helper emits every inner set ordered by each
/// element's canonical JSON (the same ordering as [`serde_sorted_set`]).
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_sorted_set_map {
    use std::collections::{HashMap, HashSet};
    use std::hash::{BuildHasher, Hash};

    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes the map with each inner set ordered by canonical JSON.
    pub fn serialize<T, Hm, Hs, S>(
        map: &HashMap<String, HashSet<T, Hs>, Hm>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        Hm: BuildHasher,
        Hs: BuildHasher,
        S: Serializer,
    {
        // Order the inner sets deterministically. The outer map's key order is
        // re-sorted by JCS, so the serializer-side map order does not affect
        // the canonical digest; we still emit it directly to avoid an extra
        // allocation of the outer map.
        struct SortedSet<'a, T, Hs>(&'a HashSet<T, Hs>);

        impl<T: Serialize, Hs: BuildHasher> Serialize for SortedSet<'_, T, Hs> {
            fn serialize<S2: Serializer>(&self, s: S2) -> Result<S2::Ok, S2::Error> {
                super::serde_sorted_set::serialize(self.0, s)
            }
        }

        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(k, &SortedSet(v))?;
        }
        m.end()
    }

    /// Deserializes back into a `HashMap<String, HashSet<T>>`.
    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<HashMap<String, HashSet<T>>, D::Error>
    where
        T: Deserialize<'de> + Eq + Hash,
        D: Deserializer<'de>,
    {
        let raw: HashMap<String, Vec<T>> = HashMap::deserialize(deserializer)?;
        Ok(raw
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect())
    }
}

/// Serde module for `HashMap<[u8; 32], V>` fields that must serialize
/// deterministically and survive RFC 8785 JCS canonicalization.
///
/// A `[u8; 32]` map key serializes as a JSON *array*, which `serde_json`
/// (and therefore `serde_json_canonicalizer`) rejects — JSON object keys must
/// be strings. This helper emits the map as a JSON object keyed by the
/// lowercase-hex encoding of each 32-byte key. JCS then canonicalizes the
/// object by sorting those hex keys, so the digest is deterministic regardless
/// of the source `HashMap`'s iteration order. Deserialization decodes the hex
/// keys back to `[u8; 32]`.
///
/// Used for the signed context export (spec §23.16.8, ADR-050) where the whole
/// `ContextSnapshot` — including its `[u8; 32]`-keyed governance maps — is fed
/// through JCS to form the signed digest.
#[allow(clippy::missing_errors_doc)] // Serde trait impls — error semantics are self-evident.
pub mod serde_hex_keyed_map_32 {
    use std::collections::HashMap;
    use std::hash::BuildHasher;

    use serde::de::Error as _;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes the map as a JSON object keyed by lowercase hex of each key.
    pub fn serialize<V, H, S>(
        map: &HashMap<[u8; 32], V, H>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        V: Serialize,
        H: BuildHasher,
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&hex::encode(k), v)?;
        }
        m.end()
    }

    /// Deserializes a hex-keyed object back into a `HashMap<[u8; 32], V>`.
    pub fn deserialize<'de, V, D>(deserializer: D) -> Result<HashMap<[u8; 32], V>, D::Error>
    where
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        let raw: HashMap<String, V> = HashMap::deserialize(deserializer)?;
        let mut out = HashMap::with_capacity(raw.len());
        for (k, v) in raw {
            let bytes = hex::decode(&k)
                .map_err(|e| D::Error::custom(format!("invalid hex map key {k:?}: {e}")))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
                D::Error::custom(format!("expected 32-byte map key, got {} bytes", b.len()))
            })?;
            out.insert(arr, v);
        }
        Ok(out)
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
