//! Admission of `SchemaMatch` schemas (spec 07 §7.3.4 step 1).
//!
//! A challenger grades a `SchemaMatch` case by validating the subject's
//! output against a schema the challenger wrote. The gate keeps that
//! validation local, bounded and linear-time:
//!
//! - every `$schema` in the document names draft 2020-12, so no embedded
//!   resource switches dialect;
//! - every `$ref` and `$dynamicRef` is a fragment (`#…`), `$recursiveRef` is
//!   absent, and the validator's retriever refuses every fetch;
//! - every `pattern` value and every `patternProperties` key parses under
//!   the `regex-syntax` AST parser, which refuses backreferences, lookaround
//!   and the other constructs that need a backtracking matcher. jsonschema
//!   hands such patterns to `fancy-regex` unchanged, and rewrites every other
//!   ECMA pattern into one the same parser accepts, so an admitted pattern
//!   always runs on the linear `regex` engine;
//! - the canonical form fits `MAX_CHALLENGE_SCHEMA_BYTES` and nests at most
//!   `MAX_CHALLENGE_JSON_DEPTH` deep;
//! - format assertions are off, so a format checker never decides a case.
//!
//! The walk visits data positions (`const`, `enum`, `default`, `examples`)
//! too: refusing a data key that happens to be named `$schema` or `$ref` is
//! accepted over-refusal.

use serde_json::Value;

use super::TrustError;
use super::challenge::{MAX_CHALLENGE_JSON_DEPTH, MAX_CHALLENGE_SCHEMA_BYTES};

/// The only dialect a `$schema` keyword may name.
pub const DRAFT_2020_12_URI: &str = "https://json-schema.org/draft/2020-12/schema";

/// A retriever that refuses every external reference.
struct DenyAll;

impl jsonschema::Retrieve for DenyAll {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<&str>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!("schema retrieval refused: {}", uri.as_str()).into())
    }
}

/// The outcome of validating one output against an admitted schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaVerdict {
    /// The output satisfies the schema.
    Pass,
    /// The output breaks the schema.
    Fail,
    /// The matcher hit its backtrack limit. Unreachable for an admitted
    /// schema; if it occurs the case fails with reason `backtrack_limit`.
    BacktrackLimit,
}

/// The schema admission gate.
#[derive(Debug, Clone, Copy)]
pub struct SchemaGate;

impl SchemaGate {
    /// Admits `schema` for the case `test_id` and compiles it.
    ///
    /// # Errors
    ///
    /// [`TrustError::SchemaRejected`] naming the rule the schema breaks.
    pub fn admit(test_id: &str, schema: &Value) -> Result<jsonschema::Validator, TrustError> {
        let reject = |reason: String| TrustError::SchemaRejected {
            test_id: test_id.to_owned(),
            reason,
        };
        let depth = json_depth(schema);
        if depth > MAX_CHALLENGE_JSON_DEPTH {
            return Err(reject(format!(
                "depth {depth} exceeds {MAX_CHALLENGE_JSON_DEPTH}"
            )));
        }
        let bytes = crate::jcs::to_vec(schema).map_err(|e| reject(format!("not I-JSON: {e}")))?;
        if bytes.len() > MAX_CHALLENGE_SCHEMA_BYTES {
            return Err(reject(format!(
                "{} canonical bytes exceed {MAX_CHALLENGE_SCHEMA_BYTES}",
                bytes.len()
            )));
        }
        walk(schema, "").map_err(reject)?;
        jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .with_retriever(DenyAll)
            .should_validate_formats(false)
            .build(schema)
            .map_err(|e| reject(format!("does not compile: {e}")))
    }
}

/// Validates `output` with an admitted schema.
#[must_use]
pub fn schema_verdict(validator: &jsonschema::Validator, output: &Value) -> SchemaVerdict {
    match validator.validate(output) {
        Ok(()) => SchemaVerdict::Pass,
        Err(error) => match error.kind {
            jsonschema::error::ValidationErrorKind::BacktrackLimitExceeded { .. } => {
                SchemaVerdict::BacktrackLimit
            }
            _ => SchemaVerdict::Fail,
        },
    }
}

/// The container nesting depth of `value`: a scalar is 0, an empty or flat
/// container 1. Iterative, so a hostile value cannot exhaust the stack.
#[must_use]
pub fn json_depth(value: &Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 1usize)];
    while let Some((v, depth)) = stack.pop() {
        match v {
            Value::Array(items) => {
                deepest = deepest.max(depth);
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            Value::Object(map) => {
                deepest = deepest.max(depth);
                stack.extend(map.values().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    deepest
}

/// Checks every object of the document; `pointer` locates refusals.
fn walk(value: &Value, pointer: &str) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            check_object(map, pointer)?;
            for (key, child) in map {
                walk(child, &format!("{pointer}/{key}"))?;
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk(child, &format!("{pointer}/{i}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_object(map: &serde_json::Map<String, Value>, pointer: &str) -> Result<(), String> {
    if let Some(dialect) = map.get("$schema")
        && dialect.as_str() != Some(DRAFT_2020_12_URI)
    {
        return Err(format!(
            "{pointer}/$schema names {dialect}, not draft 2020-12"
        ));
    }
    for keyword in ["$ref", "$dynamicRef"] {
        if let Some(reference) = map.get(keyword)
            && !reference.as_str().is_some_and(|r| r.starts_with('#'))
        {
            return Err(format!(
                "{pointer}/{keyword} is {reference}, not a fragment reference"
            ));
        }
    }
    if map.contains_key("$recursiveRef") {
        return Err(format!("{pointer}/$recursiveRef is not admitted"));
    }
    if let Some(Value::String(pattern)) = map.get("pattern") {
        check_pattern(pattern).map_err(|e| format!("{pointer}/pattern: {e}"))?;
    }
    if let Some(Value::Object(properties)) = map.get("patternProperties") {
        for pattern in properties.keys() {
            check_pattern(pattern).map_err(|e| format!("{pointer}/patternProperties key: {e}"))?;
        }
    }
    Ok(())
}

fn check_pattern(pattern: &str) -> Result<(), String> {
    regex_syntax::ast::parse::Parser::new()
        .parse(pattern)
        .map(|_| ())
        .map_err(|e| format!("{pattern:?} needs a backtracking matcher or does not parse: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rejected(schema: &Value) -> String {
        match SchemaGate::admit("t", schema) {
            Err(TrustError::SchemaRejected { test_id, reason }) => {
                assert_eq!(test_id, "t");
                reason
            }
            Ok(_) => panic!("admitted {schema}"),
            Err(other) => panic!("unexpected {other:?}"),
        }
    }

    /// Test 8: each row is refused by the walk, named by its reason, not
    /// by a later compile failure.
    #[test]
    fn schema_gate_refuses_remote_ref_and_foreign_draft() {
        for (schema, reason) in [
            (
                json!({"$ref": "https://example.com/s.json"}),
                "/$ref is \"https://example.com/s.json\", not a fragment reference",
            ),
            (
                json!({"$ref": "other.json#/a"}),
                "/$ref is \"other.json#/a\", not a fragment reference",
            ),
            (
                json!({"$dynamicRef": "https://example.com/s.json#a"}),
                "/$dynamicRef is \"https://example.com/s.json#a\", not a fragment reference",
            ),
            (
                json!({"$recursiveRef": "#"}),
                "/$recursiveRef is not admitted",
            ),
            (
                json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
                "/$schema names \"http://json-schema.org/draft-07/schema#\", not draft 2020-12",
            ),
        ] {
            assert_eq!(rejected(&schema), reason, "{schema}");
        }
        // A fragment reference within the document is admitted.
        SchemaGate::admit(
            "t",
            &json!({
                "$schema": DRAFT_2020_12_URI,
                "$defs": {"n": {"type": "integer"}},
                "properties": {"count": {"$ref": "#/$defs/n"}}
            }),
        )
        .unwrap();
    }

    #[test]
    fn schema_gate_refuses_embedded_foreign_schema() {
        let reason = rejected(&json!({
            "$schema": DRAFT_2020_12_URI,
            "$defs": {"old": {"$id": "urn:x", "$schema": "http://json-schema.org/draft-07/schema#"}}
        }));
        assert!(reason.contains("/$defs/old/$schema"), "{reason}");
    }

    #[test]
    fn schema_gate_refuses_backreference_pattern() {
        rejected(&json!({"type": "string", "pattern": "^(a+)\\1$"}));
        rejected(&json!({"type": "string", "pattern": "^(?=a)a$"}));
        rejected(&json!({"type": "string", "pattern": "^(?<=a)b$"}));
    }

    #[test]
    fn schema_gate_refuses_lookaround_in_pattern_properties_key() {
        let reason = rejected(&json!({"patternProperties": {"^(?!x)": {"type": "string"}}}));
        assert!(reason.contains("patternProperties"), "{reason}");
    }

    /// Test 8c. `admit` compiles a schema whose resources carry remote
    /// `$id`s without fetching them, and refuses a remote reference in the
    /// walk. The validator is built with the deny-all retriever: an external
    /// reference fails to compile even with the walk bypassed, and the
    /// retriever itself refuses every URI.
    #[test]
    fn schema_gate_never_fetches() {
        let embedded = json!({
            "$id": "https://example.invalid/root.json",
            "$defs": {"a": {"$id": "https://example.invalid/a.json", "type": "string"}},
            "properties": {"x": {"$ref": "#/$defs/a"}}
        });
        let validator = SchemaGate::admit("t", &embedded).unwrap();
        assert_eq!(
            schema_verdict(&validator, &json!({"x": 1})),
            SchemaVerdict::Fail
        );
        let remote = json!({"properties": {"a": {"$ref": "https://example.invalid/s.json"}}});
        let reason = rejected(&remote);
        assert!(
            reason.starts_with("/properties/a/$ref is ") && reason.contains("not a fragment"),
            "{reason}"
        );

        let foreign = json!({"properties": {"a": {"$ref": "https://example.invalid/s.json"}}});
        let refused = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .with_retriever(DenyAll)
            .build(&foreign)
            .unwrap_err();
        assert!(refused.to_string().contains("example.invalid"), "{refused}");
        let uri = jsonschema::Uri::parse("https://example.invalid/s.json").unwrap();
        let err = jsonschema::Retrieve::retrieve(&DenyAll, &uri).unwrap_err();
        assert!(
            err.to_string().contains("schema retrieval refused"),
            "{err}"
        );
    }

    #[test]
    fn schema_formats_are_not_asserted() {
        let validator =
            SchemaGate::admit("t", &json!({"type": "string", "format": "email"})).unwrap();
        assert_eq!(
            schema_verdict(&validator, &json!("not an email")),
            SchemaVerdict::Pass
        );
    }

    #[test]
    fn schema_over_depth_refused() {
        let mut schema = json!({"type": "object"});
        for _ in 0..MAX_CHALLENGE_JSON_DEPTH {
            schema = json!({"properties": {"a": schema}});
        }
        let reason = rejected(&schema);
        assert!(reason.contains("depth"), "{reason}");
    }

    #[test]
    fn schema_over_bytes_refused() {
        let big = "x".repeat(MAX_CHALLENGE_SCHEMA_BYTES);
        let reason = rejected(&json!({"description": big}));
        assert!(reason.contains("canonical bytes"), "{reason}");
    }

    /// ECMA escapes and classes compile through the gate, and a
    /// pathological input completes quickly: the linear engine runs them.
    #[test]
    fn schema_gate_covers_compiled_ecma_patterns() {
        let input = format!("{}b", "a".repeat(64));
        for pattern in [
            "^\\d+$",
            "^\\w+$",
            "^\\s*$",
            "^[a-z]+$",
            "^[^\\d]+$",
            "^(a+)+$",
            "^(a|a)*$",
            "^(a*)*c$",
        ] {
            let validator = SchemaGate::admit("t", &json!({"type": "string", "pattern": pattern}))
                .unwrap_or_else(|e| panic!("{pattern}: {e}"));
            let verdict = schema_verdict(&validator, &json!(input));
            assert_ne!(verdict, SchemaVerdict::BacktrackLimit, "{pattern}");
        }
    }

    #[test]
    fn json_depth_counts_containers() {
        assert_eq!(json_depth(&json!(1)), 0);
        assert_eq!(json_depth(&json!([])), 1);
        assert_eq!(json_depth(&json!({"a": [1, {"b": 2}]})), 3);
    }
}
