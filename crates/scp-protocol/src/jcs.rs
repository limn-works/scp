//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! JCS is the canonicalization scheme for challenge preimages
//! (`trust::challenge`), tool-registration and tool-invocation hashing
//! (`context::outlets`), and the other structured-hash paths that call
//! [`to_vec`] / [`to_string`] here.
//!
//! # Scope
//!
//! JCS is **not** universal — each signed structure's spec row assigns a
//! serialization per field. `trust::attestation::canonical_attestation_bytes`
//! uses JCS for the `claim` field (§9.5.2 Attestation row 5: compact JSON)
//! and `rmp_serde::to_vec_named` (`MessagePack`, named keys) for `evidence`
//! and `revocation_status`, which the §9.5.2 note explicitly sanctions for
//! those two fields. `IdentityLinkAttestation::canonical_signing_bytes` is
//! governed by a separate spec row (§3 identity, domain
//! `SCP-IDENTITY-LINK-ATTESTATION-V1:`) that mandates `MessagePack` for its
//! `claim`, `evidence`, and `revocation_status` sub-structures. The
//! scheme-per-field decisions are documented on those functions; this module
//! governs the JCS paths.

/// Serializes a value to canonical JSON bytes per RFC 8785.
///
/// # Errors
///
/// Returns an error string if serialization fails.
pub fn to_vec(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| e.to_string())
}

/// Serializes a value to a canonical JSON string per RFC 8785.
///
/// # Errors
///
/// Returns an error string if serialization fails.
pub fn to_string(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json_canonicalizer::to_string(value).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests — RFC 8785 conformance
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// RFC 8785 §3.2.3 — object keys sorted by Unicode code point order.
    #[test]
    fn key_sorting() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3
        });
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    /// RFC 8785 §3.2.3 — nested objects are also key-sorted.
    #[test]
    fn nested_key_sorting() {
        let value = serde_json::json!({
            "b": {"z": 1, "a": 2},
            "a": 1
        });
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, r#"{"a":1,"b":{"a":2,"z":1}}"#);
    }

    /// RFC 8785 §3.2.2.3 — integers serialize without trailing zeros or
    /// decimal points.
    #[test]
    fn integer_serialization() {
        let value = serde_json::json!(42);
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, "42");
    }

    /// RFC 8785 §3.2.2.3 — floating point numbers use shortest
    /// representation.
    #[test]
    fn float_serialization() {
        let value = serde_json::json!(1.0e20);
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, "100000000000000000000");
    }

    /// RFC 8785 §3.2.2.3 — negative zero becomes positive zero.
    #[test]
    fn negative_zero_becomes_zero() {
        // serde_json parses -0.0 as -0.0 but JCS requires "0".
        let value: serde_json::Value = serde_json::from_str("-0.0").unwrap();
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, "0");
    }

    /// RFC 8785 §3.2.2.1 — strings use minimal escaping.
    #[test]
    fn string_escaping() {
        let value = serde_json::json!("hello\nworld");
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, r#""hello\nworld""#);
    }

    /// RFC 8785 §3.2.4 — arrays preserve element order.
    #[test]
    fn array_order_preserved() {
        let value = serde_json::json!([3, 1, 2]);
        let canonical = to_string(&value).unwrap();
        assert_eq!(canonical, "[3,1,2]");
    }

    /// `to_vec` produces the same bytes as `to_string` encoded as UTF-8.
    #[test]
    fn to_vec_matches_to_string() {
        let value = serde_json::json!({"key": "value", "num": 123});
        let vec_result = to_vec(&value).unwrap();
        let str_result = to_string(&value).unwrap();
        assert_eq!(vec_result, str_result.as_bytes());
    }

    /// Struct with derived Serialize uses JCS-compliant output.
    #[test]
    fn struct_serialization() {
        #[derive(serde::Serialize)]
        struct Example {
            z_field: u32,
            a_field: String,
        }
        let value = Example {
            z_field: 1,
            a_field: "hello".to_owned(),
        };
        let canonical = to_string(&value).unwrap();
        // serde serializes struct fields in declaration order, but JCS
        // re-sorts by key name.
        assert_eq!(canonical, r#"{"a_field":"hello","z_field":1}"#);
    }
}
