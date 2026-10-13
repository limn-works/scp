//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! JCS is the canonicalization scheme for challenge preimages
//! (`trust::challenge`), outlet-registration and outlet-invocation hashing
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
//!
//! # I-JSON
//!
//! [`to_vec`] and [`to_string`] are the only canonicalization paths in the
//! workspace, and both run [`require_i_json`] first, so no JCS preimage or
//! hash can carry a number whose canonical bytes also stand for another
//! number. A typed `u64` field whose values can exceed 2^53 must be
//! string-encoded, as `economy::types::Amount` is.

/// Serializes a value to canonical JSON bytes per RFC 8785.
///
/// # Errors
///
/// Returns an error string if serialization fails, or if the value carries a
/// number that [`require_i_json`] rejects.
pub fn to_vec(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    serde_json_canonicalizer::to_vec(&i_json_value(value)?).map_err(|e| e.to_string())
}

/// Serializes a value to a canonical JSON string per RFC 8785.
///
/// # Errors
///
/// Returns an error string if serialization fails, or if the value carries a
/// number that [`require_i_json`] rejects.
pub fn to_string(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json_canonicalizer::to_string(&i_json_value(value)?).map_err(|e| e.to_string())
}

/// The JSON value of `value`, after [`require_i_json`] accepts it.
fn i_json_value(value: &impl serde::Serialize) -> Result<serde_json::Value, String> {
    let json = serde_json::to_value(value).map_err(|e| e.to_string())?;
    require_i_json(&json).map_err(|v| v.to_string())?;
    Ok(json)
}

/// The largest integer magnitude an I-JSON number may carry: 2^53.
///
/// RFC 8785 writes every number as an IEEE-754 double. Integers up to 2^53 are
/// exact doubles; above it two distinct integers can share one double, so they
/// canonicalize to the same bytes.
pub const I_JSON_MAX_INTEGER: u64 = 1 << 53;

/// A JSON value that breaks the I-JSON numeric constraint (RFC 7493 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("I-JSON violation at {path}: {reason}")]
pub struct IJsonViolation {
    /// RFC 6901 JSON Pointer to the offending number (`""` is the root).
    pub path: String,
    /// What the number breaks.
    pub reason: String,
}

/// Rejects a value whose RFC 8785 canonical bytes could stand for another value.
///
/// Walks `value` at every depth and fails on the first number that is:
/// - an integer of magnitude above 2^53 ([`I_JSON_MAX_INTEGER`]), whether held
///   as an integer or as an integral double;
/// - a double that is not finite.
///
/// RFC 8785 serializes numbers as ES6 doubles, so integers above 2^53 are not
/// injective: `9007199254740993` and `9007199254740992` canonicalize to the
/// same bytes, and a signature over one covers the other. [`to_vec`] and
/// [`to_string`] call this on every value they canonicalize. The
/// `Attestation.claim` field (`09-security-model.md` §9.5.2), a challenge
/// case's `input` and `expected`, and a challenge response's `result` (spec 07
/// §7.3.4) also call it directly, to report the violation as their own typed
/// error.
///
/// # Errors
///
/// Returns [`IJsonViolation`] naming the JSON Pointer of the first offending
/// number.
pub fn require_i_json(value: &serde_json::Value) -> Result<(), IJsonViolation> {
    let mut path = String::new();
    walk_i_json(value, &mut path)
}

fn walk_i_json(value: &serde_json::Value, path: &mut String) -> Result<(), IJsonViolation> {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::String(_) => {
            Ok(())
        }
        serde_json::Value::Number(n) => check_number(n, path),
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&i.to_string());
                walk_i_json(item, path)?;
                path.truncate(len);
            }
            Ok(())
        }
        serde_json::Value::Object(members) => {
            for (key, item) in members {
                let len = path.len();
                path.push('/');
                // RFC 6901 §3: `~` becomes `~0` and `/` becomes `~1`.
                path.push_str(&key.replace('~', "~0").replace('/', "~1"));
                walk_i_json(item, path)?;
                path.truncate(len);
            }
            Ok(())
        }
    }
}

fn check_number(n: &serde_json::Number, path: &str) -> Result<(), IJsonViolation> {
    let violation = |reason: String| IJsonViolation {
        path: path.to_owned(),
        reason,
    };
    if let Some(u) = n.as_u64() {
        if u > I_JSON_MAX_INTEGER {
            return Err(violation(format!("integer {u} has magnitude above 2^53")));
        }
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > I_JSON_MAX_INTEGER {
            return Err(violation(format!("integer {i} has magnitude above 2^53")));
        }
        return Ok(());
    }
    let Some(f) = n.as_f64() else {
        return Err(violation(format!("number {n} is not an IEEE-754 double")));
    };
    if !f.is_finite() {
        return Err(violation(format!("number {n} is not finite")));
    }
    // 2^53 is exactly representable, so the comparison is exact.
    #[allow(clippy::cast_precision_loss)]
    let max = I_JSON_MAX_INTEGER as f64;
    if f.fract() == 0.0 && f.abs() > max {
        return Err(violation(format!(
            "integral number {n} has magnitude above 2^53"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod i_json_tests {
    use super::*;

    #[test]
    fn accepts_integers_at_2_53_in_both_signs() {
        require_i_json(&serde_json::json!(9_007_199_254_740_992_u64)).unwrap();
        require_i_json(&serde_json::json!(-9_007_199_254_740_992_i64)).unwrap();
        require_i_json(&serde_json::json!({"a": [1, 2.5, null, "x", true]})).unwrap();
    }

    #[test]
    fn rejects_integer_beyond_2_53_at_depth_with_pointer() {
        let err =
            require_i_json(&serde_json::json!({"a/b": [0, {"n": 9_007_199_254_740_993_u64}]}))
                .unwrap_err();
        assert_eq!(err.path, "/a~1b/1/n");
    }

    #[test]
    fn rejects_negative_integer_beyond_2_53() {
        let err = require_i_json(&serde_json::json!([-9_007_199_254_740_993_i64])).unwrap_err();
        assert_eq!(err.path, "/0");
    }

    #[test]
    fn rejects_integral_double_beyond_2_53() {
        let err = require_i_json(&serde_json::json!({"x": 1e20})).unwrap_err();
        assert_eq!(err.path, "/x");
        // A fractional double is the double it parsed to: accepted.
        require_i_json(&serde_json::json!(0.1)).unwrap();
        // 2^53 held as a double is still exact.
        require_i_json(&serde_json::json!(9_007_199_254_740_992.0_f64)).unwrap();
    }

    /// The hazard the check exists for: both values canonicalize identically
    /// under the raw canonicalizer.
    #[test]
    fn values_the_check_rejects_collide_under_jcs() {
        let a = serde_json::json!(9_007_199_254_740_992_u64);
        let b = serde_json::json!(9_007_199_254_740_993_u64);
        assert_eq!(
            serde_json_canonicalizer::to_vec(&a).unwrap(),
            serde_json_canonicalizer::to_vec(&b).unwrap()
        );
        assert!(require_i_json(&a).is_ok());
        assert!(require_i_json(&b).is_err());
    }

    /// Both canonicalization entry points refuse a number beyond 2^53, at any
    /// depth and from a typed value, and still accept 2^53 itself.
    #[test]
    fn canonicalization_refuses_numbers_beyond_2_53() {
        #[derive(serde::Serialize)]
        struct Typed {
            count: u64,
        }

        let err = to_vec(&serde_json::json!({"n": 9_007_199_254_740_993_u64})).unwrap_err();
        assert!(err.contains("/n") && err.contains("2^53"), "{err}");
        assert!(to_string(&serde_json::json!([[-9_007_199_254_740_993_i64]])).is_err());
        assert!(
            to_vec(&Typed {
                count: (1 << 53) + 1
            })
            .is_err()
        );
        assert_eq!(
            to_vec(&Typed { count: 1 << 53 }).unwrap(),
            b"{\"count\":9007199254740992}".to_vec()
        );
    }

    /// No module of this crate calls the canonicalizer except through
    /// [`to_vec`] and [`to_string`], so no canonicalization skips the I-JSON
    /// check. `scp-protocol` is the only workspace crate that declares the
    /// canonicalizer as a dependency.
    #[test]
    fn only_this_module_calls_the_canonicalizer() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs")
                    && !path.ends_with("src/jcs.rs")
                    && std::fs::read_to_string(&path).unwrap().lines().any(|l| {
                        !l.trim_start().starts_with("//")
                            && l.contains("serde_json_canonicalizer::")
                    })
                {
                    offenders.push(path);
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "canonicalize through crate::jcs: {offenders:?}"
        );
    }
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

    /// RFC 8785 §3.2.2.3 — floating point numbers use the shortest ES6
    /// representation. An integral double above 2^53 such as `1e20` is
    /// outside I-JSON, so it has no canonical form here.
    #[test]
    fn float_serialization() {
        assert_eq!(to_string(&serde_json::json!(1.0e-7)).unwrap(), "1e-7");
        assert_eq!(
            to_string(&serde_json::json!(0.000_001)).unwrap(),
            "0.000001"
        );
        assert_eq!(to_string(&serde_json::json!(1.5e-300)).unwrap(), "1.5e-300");
        let err = to_string(&serde_json::json!(1.0e20)).unwrap_err();
        assert!(err.contains("2^53"), "{err}");
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
