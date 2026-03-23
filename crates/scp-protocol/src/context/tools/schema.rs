//! JSON Schema validation helpers and MCP compatibility utilities.
//!
//! Provides structural validation for JSON Schema objects used in tool
//! registration and full JSON Schema validation (via the `jsonschema` crate)
//! for validating values against schemas at runtime. Schema structure checks
//! verify that schemas are JSON objects with a `"type"` field.
//! Value validation delegates to the `jsonschema` crate for full constraint
//! enforcement (properties, required, additionalProperties, items,
//! numeric/string constraints, etc.).
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

/// Validates that a JSON value conforms to a given JSON Schema.
///
/// Uses the `jsonschema` crate for full JSON Schema validation, including
/// properties, required fields, `additionalProperties`, array items,
/// numeric/string constraints, enums, and patterns.
///
/// When the schema is not a JSON object (e.g., a bare string or number),
/// validation is rejected -- callers must provide a valid schema object.
///
/// # Errors
///
/// Returns an error message describing the first validation failure if the
/// value does not conform to the schema.
pub fn validate_value_against_schema(value: &Value, schema: &Value) -> Result<(), String> {
    if !schema.is_object() {
        return Err("schema is not a JSON object".to_owned());
    }

    let validator =
        jsonschema::validator_for(schema).map_err(|e| format!("invalid schema: {e}"))?;

    validator
        .validate(value)
        .map_err(|e| format!("schema validation failed: {e}"))
}

/// Minimum number of distinct property fields required by the schema
/// specificity floor (spec section 6.2, 9.2.1).
///
/// Prevents degenerate broad-schema tools that function as arbitrary
/// message channels. At least one of the input or output schemas must
/// declare this many distinct property fields.
pub const MIN_SCHEMA_FIELDS: usize = 2;

/// Counts the number of distinct property fields declared in a JSON Schema.
///
/// Only counts top-level `properties` entries in an object-type schema.
/// Returns 0 for non-object schemas or schemas without a `properties` key.
#[must_use]
pub fn count_schema_fields(schema: &Value) -> usize {
    schema
        .as_object()
        .and_then(|obj| obj.get("properties"))
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len)
}

/// Validates the schema specificity floor for a tool registration.
///
/// At least one of the input or output schemas must declare at least
/// [`MIN_SCHEMA_FIELDS`] distinct property fields. This prevents
/// degenerate single-field or empty-field schemas that function as
/// arbitrary message channels (spec section 6.2, 9.2.1).
///
/// # Errors
///
/// Returns `("input"|"output", field_count)` if neither schema meets
/// the minimum.
pub fn validate_specificity_floor(
    input_schema: &Value,
    output_schema: &Value,
) -> Result<(), (&'static str, usize)> {
    let input_fields = count_schema_fields(input_schema);
    let output_fields = count_schema_fields(output_schema);

    if input_fields >= MIN_SCHEMA_FIELDS || output_fields >= MIN_SCHEMA_FIELDS {
        return Ok(());
    }

    // Report whichever side has fewer fields (or input if tied).
    if input_fields <= output_fields {
        Err(("input", input_fields))
    } else {
        Err(("output", output_fields))
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::approx_constant
)]
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

    // -----------------------------------------------------------------------
    // Full JSON Schema validation (SCP-189)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_value_rejects_non_object_schema() {
        let schema = serde_json::json!("not an object");
        let value = serde_json::json!(42);
        let err = validate_value_against_schema(&value, &schema).unwrap_err();
        assert!(err.contains("not a JSON object"));
    }

    #[test]
    fn validate_value_rejects_missing_required_field() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "age"]
        });
        let value = serde_json::json!({"name": "Alice"});
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_all_required_fields_present() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "age"]
        });
        let value = serde_json::json!({"name": "Alice", "age": 30});
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_extra_properties_when_forbidden() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });
        let value = serde_json::json!({"name": "Alice", "secret": "payload"});
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_no_extra_properties() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });
        let value = serde_json::json!({"name": "Alice"});
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_wrong_property_type() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "count": {"type": "integer"}
            }
        });
        let value = serde_json::json!({"count": "not a number"});
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_rejects_invalid_array_items() {
        let schema = serde_json::json!({
            "type": "array",
            "items": {"type": "integer"}
        });
        let value = serde_json::json!([1, 2, "three"]);
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_valid_array_items() {
        let schema = serde_json::json!({
            "type": "array",
            "items": {"type": "integer"}
        });
        let value = serde_json::json!([1, 2, 3]);
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_number_below_minimum() {
        let schema = serde_json::json!({
            "type": "number",
            "minimum": 10
        });
        let value = serde_json::json!(5);
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_rejects_number_above_maximum() {
        let schema = serde_json::json!({
            "type": "number",
            "maximum": 100
        });
        let value = serde_json::json!(150);
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_number_in_range() {
        let schema = serde_json::json!({
            "type": "number",
            "minimum": 10,
            "maximum": 100
        });
        let value = serde_json::json!(50);
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_string_below_min_length() {
        let schema = serde_json::json!({
            "type": "string",
            "minLength": 5
        });
        let value = serde_json::json!("abc");
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_rejects_string_above_max_length() {
        let schema = serde_json::json!({
            "type": "string",
            "maxLength": 3
        });
        let value = serde_json::json!("toolong");
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_string_within_length_bounds() {
        let schema = serde_json::json!({
            "type": "string",
            "minLength": 2,
            "maxLength": 10
        });
        let value = serde_json::json!("hello");
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_string_not_matching_pattern() {
        let schema = serde_json::json!({
            "type": "string",
            "pattern": "^[a-z]+$"
        });
        let value = serde_json::json!("ABC123");
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_string_matching_pattern() {
        let schema = serde_json::json!({
            "type": "string",
            "pattern": "^[a-z]+$"
        });
        let value = serde_json::json!("abc");
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_value_not_in_enum() {
        let schema = serde_json::json!({
            "type": "string",
            "enum": ["red", "green", "blue"]
        });
        let value = serde_json::json!("yellow");
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_accepts_value_in_enum() {
        let schema = serde_json::json!({
            "type": "string",
            "enum": ["red", "green", "blue"]
        });
        let value = serde_json::json!("green");
        assert!(validate_value_against_schema(&value, &schema).is_ok());
    }

    #[test]
    fn validate_value_rejects_unknown_type_in_schema() {
        let schema = serde_json::json!({"type": "foobar"});
        let value = serde_json::json!("anything");
        // The jsonschema crate rejects unknown types -- no wildcard pass-through.
        assert!(validate_value_against_schema(&value, &schema).is_err());
    }

    #[test]
    fn validate_value_nested_object_validation() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                        "zip": {"type": "string", "pattern": "^\\d{5}$"}
                    },
                    "required": ["city", "zip"]
                }
            },
            "required": ["address"]
        });
        // Valid nested object.
        let valid = serde_json::json!({"address": {"city": "Portland", "zip": "97201"}});
        assert!(validate_value_against_schema(&valid, &schema).is_ok());

        // Invalid: missing nested required field.
        let missing_zip = serde_json::json!({"address": {"city": "Portland"}});
        assert!(validate_value_against_schema(&missing_zip, &schema).is_err());

        // Invalid: zip does not match pattern.
        let bad_zip = serde_json::json!({"address": {"city": "Portland", "zip": "abcde"}});
        assert!(validate_value_against_schema(&bad_zip, &schema).is_err());
    }

    // -----------------------------------------------------------------------
    // Schema specificity floor (spec section 6.2, 9.2.1)
    // -----------------------------------------------------------------------

    #[test]
    fn count_schema_fields_returns_property_count() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "c": {"type": "string"}
            }
        });
        assert_eq!(count_schema_fields(&schema), 3);
    }

    #[test]
    fn count_schema_fields_returns_zero_for_no_properties() {
        let schema = serde_json::json!({"type": "object"});
        assert_eq!(count_schema_fields(&schema), 0);
    }

    #[test]
    fn count_schema_fields_returns_zero_for_non_object_schema() {
        let schema = serde_json::json!({"type": "string"});
        assert_eq!(count_schema_fields(&schema), 0);
    }

    #[test]
    fn specificity_floor_passes_when_input_has_enough_fields() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"}
            }
        });
        let output = serde_json::json!({"type": "object"});
        assert!(validate_specificity_floor(&input, &output).is_ok());
    }

    #[test]
    fn specificity_floor_passes_when_output_has_enough_fields() {
        let input = serde_json::json!({"type": "object"});
        let output = serde_json::json!({
            "type": "object",
            "properties": {
                "result": {"type": "number"},
                "status": {"type": "string"}
            }
        });
        assert!(validate_specificity_floor(&input, &output).is_ok());
    }

    #[test]
    fn specificity_floor_fails_when_neither_has_enough_fields() {
        let input = serde_json::json!({
            "type": "object",
            "properties": {
                "data": {"type": "string"}
            }
        });
        let output = serde_json::json!({
            "type": "object",
            "properties": {
                "result": {"type": "string"}
            }
        });
        let result = validate_specificity_floor(&input, &output);
        assert!(result.is_err());
        let (side, count) = result.unwrap_err();
        assert_eq!(side, "input");
        assert_eq!(count, 1);
    }

    #[test]
    fn specificity_floor_fails_when_both_have_zero_fields() {
        let input = serde_json::json!({"type": "object"});
        let output = serde_json::json!({"type": "string"});
        let result = validate_specificity_floor(&input, &output);
        assert!(result.is_err());
        let (side, count) = result.unwrap_err();
        assert_eq!(side, "input");
        assert_eq!(count, 0);
    }
}
