//! JSON Schema validation helpers and MCP compatibility utilities.
//!
//! Provides structural validation for JSON Schema objects used in tool
//! registration. Full JSON Schema validation (via the `jsonschema` crate)
//! is deferred until that dependency is integrated. Current validation checks
//! that schemas are JSON objects with a `"type"` field -- sufficient for
//! structural correctness in Phase 2.
//!
//! MCP compatibility: tool schemas follow the MCP (Model Context Protocol)
//! JSON Schema convention where both input and output are described as
//! JSON Schema objects. See spec section 8.5 and ADR-010.

use serde_json::Value;

/// Errors produced by schema validation.
#[derive(Debug, thiserror::Error)]
pub enum SchemaValidationError {
    /// The schema is not a JSON object.
    #[error("schema must be a JSON object, got {kind}")]
    NotAnObject {
        /// The JSON type that was provided instead of an object.
        kind: String,
    },

    /// The schema is missing the required `"type"` field.
    #[error("schema is missing the required \"type\" field")]
    MissingTypeField,

    /// The `"type"` field is not a string value.
    #[error("schema \"type\" field must be a string, got {kind}")]
    TypeFieldNotString {
        /// The JSON type of the `"type"` field value.
        kind: String,
    },

    /// The `"type"` field contains an unrecognized JSON Schema type.
    #[error("unrecognized JSON Schema type: \"{value}\"")]
    UnrecognizedType {
        /// The unrecognized type string.
        value: String,
    },
}

/// Valid JSON Schema type values per the JSON Schema specification.
const VALID_SCHEMA_TYPES: &[&str] = &[
    "object", "array", "string", "number", "integer", "boolean", "null",
];

/// Validates that a `serde_json::Value` is a structurally valid JSON Schema.
///
/// Checks:
/// 1. The value is a JSON object.
/// 2. It contains a `"type"` field.
/// 3. The `"type"` field is a string with a recognized JSON Schema type.
///
/// This is a basic structural check, not a full JSON Schema validation.
/// Full validation would require the `jsonschema` crate.
///
/// # Errors
///
/// Returns [`SchemaValidationError`] if the value fails structural checks.
pub fn validate_schema(schema: &Value) -> Result<(), SchemaValidationError> {
    let obj = schema
        .as_object()
        .ok_or_else(|| SchemaValidationError::NotAnObject {
            kind: json_type_name(schema).to_owned(),
        })?;

    let type_field = obj
        .get("type")
        .ok_or(SchemaValidationError::MissingTypeField)?;

    let type_str =
        type_field
            .as_str()
            .ok_or_else(|| SchemaValidationError::TypeFieldNotString {
                kind: json_type_name(type_field).to_owned(),
            })?;

    if !VALID_SCHEMA_TYPES.contains(&type_str) {
        return Err(SchemaValidationError::UnrecognizedType {
            value: type_str.to_owned(),
        });
    }

    Ok(())
}

/// Validates that a JSON value conforms to a given JSON Schema (basic check).
///
/// Phase 2 implementation: performs a best-effort structural check. Validates
/// the top-level type constraint only. Full property-level validation requires
/// the `jsonschema` crate.
///
/// # Errors
///
/// Returns an error message if the value does not match the schema's type
/// constraint.
pub fn validate_value_against_schema(value: &Value, schema: &Value) -> Result<(), String> {
    let schema_obj = schema
        .as_object()
        .ok_or_else(|| "schema is not a JSON object".to_owned())?;

    let Some(type_field) = schema_obj.get("type") else {
        // If the schema has no type constraint, any value is valid.
        return Ok(());
    };

    let Some(expected_type) = type_field.as_str() else {
        return Ok(());
    };

    let matches = match expected_type {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true, // Unknown type -- pass through.
    };

    if matches {
        Ok(())
    } else {
        Err(format!(
            "expected JSON type \"{expected_type}\", got {actual}",
            actual = json_type_name(value),
        ))
    }
}

/// Returns a human-readable name for a JSON value's type.
const fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Creates a minimal valid JSON Schema for an object type.
///
/// Utility for test code and tool registration where a simple object schema
/// is needed.
#[must_use]
pub fn object_schema() -> Value {
    serde_json::json!({
        "type": "object"
    })
}

/// Creates a minimal valid JSON Schema for a string type.
///
/// Utility for test code.
#[must_use]
pub fn string_schema() -> Value {
    serde_json::json!({
        "type": "string"
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn validate_schema_accepts_valid_object_schema() {
        let schema = serde_json::json!({"type": "object", "properties": {}});
        assert!(validate_schema(&schema).is_ok());
    }

    #[test]
    fn validate_schema_accepts_all_valid_types() {
        for type_name in VALID_SCHEMA_TYPES {
            let schema = serde_json::json!({"type": type_name});
            assert!(
                validate_schema(&schema).is_ok(),
                "should accept type \"{type_name}\""
            );
        }
    }

    #[test]
    fn validate_schema_rejects_non_object() {
        let schema = serde_json::json!("not an object");
        let err = validate_schema(&schema).unwrap_err();
        assert!(
            matches!(err, SchemaValidationError::NotAnObject { .. }),
            "expected NotAnObject, got {err:?}"
        );
    }

    #[test]
    fn validate_schema_rejects_array() {
        let schema = serde_json::json!([1, 2, 3]);
        let err = validate_schema(&schema).unwrap_err();
        assert!(matches!(err, SchemaValidationError::NotAnObject { .. }));
    }

    #[test]
    fn validate_schema_rejects_missing_type_field() {
        let schema = serde_json::json!({"properties": {}});
        let err = validate_schema(&schema).unwrap_err();
        assert!(matches!(err, SchemaValidationError::MissingTypeField));
    }

    #[test]
    fn validate_schema_rejects_non_string_type() {
        let schema = serde_json::json!({"type": 42});
        let err = validate_schema(&schema).unwrap_err();
        assert!(matches!(
            err,
            SchemaValidationError::TypeFieldNotString { .. }
        ));
    }

    #[test]
    fn validate_schema_rejects_unrecognized_type() {
        let schema = serde_json::json!({"type": "unknown_type"});
        let err = validate_schema(&schema).unwrap_err();
        assert!(matches!(
            err,
            SchemaValidationError::UnrecognizedType { .. }
        ));
    }

    #[test]
    fn validate_value_accepts_matching_object() {
        let schema = serde_json::json!({"type": "object"});
        let value = serde_json::json!({"key": "value"});
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_accepts_matching_string() {
        let schema = serde_json::json!({"type": "string"});
        let value = serde_json::json!("hello");
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_type_mismatch() {
        let schema = serde_json::json!({"type": "object"});
        let value = serde_json::json!("not an object");
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_any_when_no_type() {
        let schema = serde_json::json!({"description": "anything goes"});
        let value = serde_json::json!(42);
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn object_schema_is_valid() {
        assert!(validate_schema(&object_schema()).is_ok());
    }

    #[test]
    fn string_schema_is_valid() {
        assert!(validate_schema(&string_schema()).is_ok());
    }

    #[test]
    fn json_type_name_all_variants() {
        assert_eq!(json_type_name(&Value::Null), "null");
        assert_eq!(json_type_name(&Value::Bool(true)), "boolean");
        assert_eq!(json_type_name(&serde_json::json!(42)), "number");
        assert_eq!(json_type_name(&serde_json::json!("str")), "string");
        assert_eq!(json_type_name(&serde_json::json!([])), "array");
        assert_eq!(json_type_name(&serde_json::json!({})), "object");
    }

    #[test]
    fn validate_value_integer_against_integer_schema() {
        let schema = serde_json::json!({"type": "integer"});
        let value = serde_json::json!(42);
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_float_rejected_by_integer_schema() {
        let schema = serde_json::json!({"type": "integer"});
        let value = serde_json::json!(3.14);
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_boolean_against_boolean_schema() {
        let schema = serde_json::json!({"type": "boolean"});
        let value = serde_json::json!(true);
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_null_against_null_schema() {
        let schema = serde_json::json!({"type": "null"});
        let value = Value::Null;
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn schema_validation_error_display() {
        let err = SchemaValidationError::NotAnObject {
            kind: "string".to_owned(),
        };
        assert_eq!(format!("{err}"), "schema must be a JSON object, got string");

        let err = SchemaValidationError::MissingTypeField;
        assert_eq!(
            format!("{err}"),
            "schema is missing the required \"type\" field"
        );

        let err = SchemaValidationError::TypeFieldNotString {
            kind: "number".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "schema \"type\" field must be a string, got number"
        );

        let err = SchemaValidationError::UnrecognizedType {
            value: "foobar".to_owned(),
        };
        assert_eq!(
            format!("{err}"),
            "unrecognized JSON Schema type: \"foobar\""
        );
    }
}
