//! Schema-based tool integrity verification and scheduling.
//!
//! Extends the exact-match [`verify_tool`](super::verify_tool) with
//! schema-based verification that checks structural compatibility (same keys,
//! compatible types) rather than exact value equality. Produces
//! [`ChallengeVerification`] results for integration with the trust subsystem.
//!
//! Also provides [`VerificationScheduler`] for periodic re-verification
//! with configurable intervals per tool.
//!
//! See issue #367.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{ToolError, ToolId, ToolRegistry, ToolVerificationResult, VectorResult};
use crate::time;
use crate::trust::challenge::{ChallengeType, ChallengeVerification, VerificationMethod};
use scp_identity::DID;

// ---------------------------------------------------------------------------
// Schema compatibility checking
// ---------------------------------------------------------------------------

/// Checks whether an actual JSON value is structurally compatible with an
/// expected value's schema.
///
/// "Compatible" means:
/// - Same JSON type (object, array, string, number, boolean, null).
/// - For objects: all keys in the expected value are present in the actual
///   value, and each corresponding value is recursively compatible.
/// - For arrays: if the expected array is non-empty, each element in the
///   actual array is compatible with the first element of the expected array
///   (treating the first element as the element schema).
///
/// This is intentionally loose: extra keys in the actual output are allowed,
/// and values need only match types -- not exact contents.
#[must_use]
pub fn schema_compatible(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(exp_map), Value::Object(act_map)) => {
            for (key, exp_val) in exp_map {
                match act_map.get(key) {
                    Some(act_val) => {
                        if !schema_compatible(exp_val, act_val) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            true
        }
        (Value::Array(exp_arr), Value::Array(act_arr)) => {
            if exp_arr.is_empty() {
                return true;
            }
            let element_schema = &exp_arr[0];
            act_arr
                .iter()
                .all(|act_elem| schema_compatible(element_schema, act_elem))
        }
        (Value::String(_), Value::String(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Null, Value::Null) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// verify_tool_integrity
// ---------------------------------------------------------------------------

/// Schema-based verification result for a single test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVectorResult {
    /// The test vector description.
    pub description: String,
    /// Whether the actual output is schema-compatible with the expected output.
    pub passed: bool,
    /// If failed, the actual output (for diagnostics).
    pub actual_output: Option<Value>,
    /// If failed, a description of the schema mismatch.
    pub mismatch_detail: Option<String>,
}

/// Result of schema-based tool integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVerificationResult {
    /// The tool that was verified.
    pub tool_id: ToolId,
    /// Per-vector results.
    pub vector_results: Vec<SchemaVectorResult>,
    /// Overall integrity assessment: true if all vectors passed.
    pub integrity_ok: bool,
}

/// Verifies a tool's integrity using schema-based output comparison.
///
/// Unlike [`verify_tool`](super::verify_tool) which requires exact value
/// equality, this function checks that the actual output is *structurally
/// compatible* with the expected output: same keys, compatible types,
/// recursive matching. Extra keys in the actual output are allowed.
///
/// Returns a [`ChallengeVerification`] that can be stored in the trust
/// subsystem, plus a [`SchemaVerificationResult`] with detailed per-vector
/// results.
///
/// # Errors
///
/// Returns [`ToolError::ToolNotFound`] if the tool is not in the registry.
/// Returns [`ToolError::ClockError`] if the system clock is unavailable.
pub fn verify_tool_integrity<F>(
    registry: &ToolRegistry,
    tool_id: &str,
    verifier_did: &DID,
    executor: F,
) -> Result<(ChallengeVerification, SchemaVerificationResult), ToolError>
where
    F: Fn(&Value) -> Value,
{
    let registration = registry
        .get(tool_id)
        .ok_or_else(|| ToolError::ToolNotFound {
            tool_id: tool_id.to_owned(),
        })?;

    let operator_did = registration.operator_did.clone();
    let mut vector_results = Vec::with_capacity(registration.test_vectors.len());

    for vector in &registration.test_vectors {
        let actual_output = executor(&vector.input);
        let passed = schema_compatible(&vector.expected_output, &actual_output);

        let mismatch_detail = if passed {
            None
        } else {
            Some(format!(
                "schema mismatch: expected structure like {}, got {}",
                serde_json::to_string(&vector.expected_output).unwrap_or_default(),
                serde_json::to_string(&actual_output).unwrap_or_default(),
            ))
        };

        vector_results.push(SchemaVectorResult {
            description: vector.description.clone(),
            passed,
            actual_output: if passed { None } else { Some(actual_output) },
            mismatch_detail,
        });
    }

    let passed_count = vector_results.iter().filter(|r| r.passed).count();
    let integrity_ok = passed_count == vector_results.len();

    let now = time::now_secs()?;

    let challenge_id = format!("tool-integrity-{tool_id}-{now}");

    let verification = ChallengeVerification {
        challenge_id,
        challenger_did: verifier_did.clone(),
        responder_did: operator_did,
        challenge_type: ChallengeType::tool_integrity(),
        verification_method: VerificationMethod::ChallengeVerified {
            challenge_type: ChallengeType::tool_integrity(),
        },
        result: serde_json::json!({
            "tool_id": tool_id,
            "vectors_passed": passed_count,
            "vectors_total": vector_results.len(),
            "integrity_ok": integrity_ok,
        }),
        completed_at: now,
        verified_at: now,
    };

    let schema_result = SchemaVerificationResult {
        tool_id: tool_id.to_owned(),
        vector_results,
        integrity_ok,
    };

    Ok((verification, schema_result))
}

/// Converts a [`SchemaVerificationResult`] to a [`ToolVerificationResult`]
/// for backward compatibility with the existing exact-match API.
#[must_use]
pub fn schema_result_to_tool_result(result: &SchemaVerificationResult) -> ToolVerificationResult {
    ToolVerificationResult {
        tool_id: result.tool_id.clone(),
        vector_results: result
            .vector_results
            .iter()
            .map(|r| VectorResult {
                description: r.description.clone(),
                passed: r.passed,
                actual_output: r.actual_output.clone(),
            })
            .collect(),
        integrity_ok: result.integrity_ok,
    }
}

// ---------------------------------------------------------------------------
// Tool verification scheduling
// ---------------------------------------------------------------------------

/// A scheduled verification entry for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolVerificationSchedule {
    /// The tool to verify.
    pub tool_id: ToolId,
    /// Verification interval in seconds.
    pub interval_secs: u64,
    /// Unix timestamp (seconds) of the last verification, or None if never
    /// verified on schedule.
    pub last_verified_at: Option<u64>,
    /// Unix timestamp (seconds) of the next scheduled verification.
    pub next_verification_at: u64,
}

/// Manager for periodic tool verification schedules.
///
/// Tracks per-tool verification intervals and determines which tools are
/// due for re-verification. The caller is responsible for actually executing
/// the verifications -- this type only tracks scheduling state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationScheduler {
    /// Scheduled verification entries keyed by tool ID.
    schedules: HashMap<ToolId, ToolVerificationSchedule>,
}

impl VerificationScheduler {
    /// Creates a new empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schedules: HashMap::new(),
        }
    }

    /// Schedules periodic verification for a tool.
    ///
    /// If the tool already has a schedule, it is replaced. The first
    /// verification is due immediately (at now).
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::ClockError`] if the system clock is unavailable.
    pub fn schedule_tool_verification(
        &mut self,
        tool_id: &str,
        interval_secs: u64,
    ) -> Result<&ToolVerificationSchedule, ToolError> {
        let now = time::now_secs()?;
        let schedule = ToolVerificationSchedule {
            tool_id: tool_id.to_owned(),
            interval_secs,
            last_verified_at: None,
            next_verification_at: now,
        };
        self.schedules.insert(tool_id.to_owned(), schedule);
        Ok(self.schedules.get(tool_id).expect("just inserted"))
    }

    /// Removes the verification schedule for a tool.
    ///
    /// Returns true if a schedule was removed.
    pub fn unschedule_tool_verification(&mut self, tool_id: &str) -> bool {
        self.schedules.remove(tool_id).is_some()
    }

    /// Returns the schedule for a tool, if any.
    #[must_use]
    pub fn get_schedule(&self, tool_id: &str) -> Option<&ToolVerificationSchedule> {
        self.schedules.get(tool_id)
    }

    /// Returns all tool IDs that are due for verification at the given
    /// timestamp.
    #[must_use]
    pub fn tools_due_at(&self, now: u64) -> Vec<ToolId> {
        self.schedules
            .values()
            .filter(|s| now >= s.next_verification_at)
            .map(|s| s.tool_id.clone())
            .collect()
    }

    /// Returns all tool IDs that are currently due for verification.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::ClockError`] if the system clock is unavailable.
    pub fn tools_due_now(&self) -> Result<Vec<ToolId>, ToolError> {
        let now = time::now_secs()?;
        Ok(self.tools_due_at(now))
    }

    /// Records that a tool was verified at the given timestamp, advancing
    /// the next verification time.
    pub fn record_verification(&mut self, tool_id: &str, verified_at: u64) {
        if let Some(schedule) = self.schedules.get_mut(tool_id) {
            schedule.last_verified_at = Some(verified_at);
            schedule.next_verification_at = verified_at + schedule.interval_secs;
        }
    }

    /// Returns the number of scheduled tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schedules.len()
    }

    /// Returns true if no tools are scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schedules.is_empty()
    }

    /// Returns an iterator over all schedules.
    pub fn schedules(&self) -> impl Iterator<Item = &ToolVerificationSchedule> {
        self.schedules.values()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::tools::registry::{TestVector, ToolRegistration, ToolSchema};
    use serde_json::json;

    fn make_registry(tool_id: &str, test_vectors: Vec<TestVector>) -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        let reg = ToolRegistration {
            tool_id: tool_id.to_owned(),
            name: format!("Test Tool {tool_id}"),
            description: "A test tool".to_owned(),
            schema: ToolSchema {
                input_schema: json!({"type": "object"}),
                output_schema: json!({"type": "object"}),
            },
            implementation_hash: [0u8; 32],
            test_vectors,
            operator_did: DID::from("did:dht:operator123"),
            economic_metadata: None,
        };
        registry.insert(reg);
        registry
    }

    #[test]
    fn compatible_same_object_structure() {
        let expected = json!({"name": "Alice", "age": 30});
        let actual = json!({"name": "Bob", "age": 25, "extra": true});
        assert!(schema_compatible(&expected, &actual));
    }

    #[test]
    fn incompatible_missing_key() {
        let expected = json!({"name": "Alice", "age": 30});
        let actual = json!({"name": "Bob"});
        assert!(!schema_compatible(&expected, &actual));
    }

    #[test]
    fn incompatible_type_mismatch() {
        let expected = json!({"name": "Alice", "age": 30});
        let actual = json!({"name": "Bob", "age": "thirty"});
        assert!(!schema_compatible(&expected, &actual));
    }

    #[test]
    fn compatible_nested_objects() {
        let expected = json!({"user": {"name": "A", "id": 1}});
        let actual = json!({"user": {"name": "B", "id": 2, "email": "b@b.com"}});
        assert!(schema_compatible(&expected, &actual));
    }

    #[test]
    fn compatible_arrays_same_element_types() {
        let expected = json!({"items": [{"id": 1, "name": "x"}]});
        let actual = json!({"items": [{"id": 2, "name": "y"}, {"id": 3, "name": "z"}]});
        assert!(schema_compatible(&expected, &actual));
    }

    #[test]
    fn compatible_empty_expected_array() {
        let expected = json!({"items": []});
        let actual = json!({"items": [1, 2, 3]});
        assert!(schema_compatible(&expected, &actual));
    }

    #[test]
    fn incompatible_array_element_type() {
        let expected = json!({"items": [1]});
        let actual = json!({"items": ["one", "two"]});
        assert!(!schema_compatible(&expected, &actual));
    }

    #[test]
    fn compatible_scalars() {
        assert!(schema_compatible(&json!("a"), &json!("b")));
        assert!(schema_compatible(&json!(1), &json!(999)));
        assert!(schema_compatible(&json!(true), &json!(false)));
        assert!(schema_compatible(&Value::Null, &Value::Null));
    }

    #[test]
    fn incompatible_scalar_type_mismatch() {
        assert!(!schema_compatible(&json!("a"), &json!(1)));
        assert!(!schema_compatible(&json!(1), &json!(true)));
        assert!(!schema_compatible(&json!(null), &json!(0)));
    }

    #[test]
    fn verify_integrity_all_pass() {
        let vectors = vec![TestVector {
            input: json!({"x": 1}),
            expected_output: json!({"result": 42, "status": "ok"}),
            description: "basic test".to_owned(),
        }];
        let registry = make_registry("calc", vectors);
        let verifier = DID::from("did:dht:verifier");

        let (verification, result) = verify_tool_integrity(
            &registry,
            "calc",
            &verifier,
            |_input| json!({"result": 99, "status": "done", "extra_field": true}),
        )
        .unwrap();

        assert!(result.integrity_ok);
        assert_eq!(result.vector_results.len(), 1);
        assert!(result.vector_results[0].passed);
        assert!(verification.challenge_id.starts_with("tool-integrity-calc-"));
        assert_eq!(verification.challenge_type, ChallengeType::tool_integrity());
    }

    #[test]
    fn verify_integrity_schema_mismatch() {
        let vectors = vec![TestVector {
            input: json!({"x": 1}),
            expected_output: json!({"result": 42}),
            description: "expects number".to_owned(),
        }];
        let registry = make_registry("calc", vectors);
        let verifier = DID::from("did:dht:verifier");

        let (verification, result) = verify_tool_integrity(
            &registry,
            "calc",
            &verifier,
            |_input| json!({"result": "not a number"}),
        )
        .unwrap();

        assert!(!result.integrity_ok);
        assert!(!result.vector_results[0].passed);
        assert!(result.vector_results[0].mismatch_detail.is_some());
        assert!(
            !verification.result.get("integrity_ok").unwrap().as_bool().unwrap()
        );
    }

    #[test]
    fn verify_integrity_tool_not_found() {
        let registry = ToolRegistry::new();
        let verifier = DID::from("did:dht:verifier");

        let err =
            verify_tool_integrity(&registry, "missing", &verifier, |_| json!({})).unwrap_err();

        match err {
            ToolError::ToolNotFound { tool_id } => assert_eq!(tool_id, "missing"),
            other => panic!("expected ToolNotFound, got: {other}"),
        }
    }

    #[test]
    fn verify_integrity_multiple_vectors_pass() {
        let vectors = vec![
            TestVector {
                input: json!({}),
                expected_output: json!({"a": 1}),
                description: "pass".to_owned(),
            },
            TestVector {
                input: json!({}),
                expected_output: json!({"a": 1}),
                description: "also pass".to_owned(),
            },
        ];
        let registry = make_registry("multi", vectors);
        let verifier = DID::from("did:dht:v");

        let (_, result) =
            verify_tool_integrity(&registry, "multi", &verifier, |_| json!({"a": 1})).unwrap();

        assert!(result.integrity_ok);
    }

    #[test]
    fn schema_result_conversion() {
        let schema_result = SchemaVerificationResult {
            tool_id: "t1".to_owned(),
            vector_results: vec![
                SchemaVectorResult {
                    description: "ok".to_owned(),
                    passed: true,
                    actual_output: None,
                    mismatch_detail: None,
                },
                SchemaVectorResult {
                    description: "fail".to_owned(),
                    passed: false,
                    actual_output: Some(json!("bad")),
                    mismatch_detail: Some("type mismatch".to_owned()),
                },
            ],
            integrity_ok: false,
        };
        let tool_result = schema_result_to_tool_result(&schema_result);
        assert_eq!(tool_result.tool_id, "t1");
        assert!(!tool_result.integrity_ok);
        assert_eq!(tool_result.vector_results.len(), 2);
        assert!(tool_result.vector_results[0].passed);
        assert!(!tool_result.vector_results[1].passed);
    }

    #[test]
    fn schedule_and_check_due() {
        let mut scheduler = VerificationScheduler::new();
        assert!(scheduler.is_empty());

        let schedule = scheduler.schedule_tool_verification("tool-a", 300).unwrap();
        assert_eq!(schedule.tool_id, "tool-a");
        assert_eq!(schedule.interval_secs, 300);
        assert!(schedule.last_verified_at.is_none());

        assert_eq!(scheduler.len(), 1);

        let due = scheduler.tools_due_now().unwrap();
        assert!(due.contains(&"tool-a".to_owned()));
    }

    #[test]
    fn record_verification_advances_schedule() {
        let mut scheduler = VerificationScheduler::new();
        scheduler.schedule_tool_verification("tool-b", 600).unwrap();

        let now = time::now_secs().unwrap();
        scheduler.record_verification("tool-b", now);

        let schedule = scheduler.get_schedule("tool-b").unwrap();
        assert_eq!(schedule.last_verified_at, Some(now));
        assert_eq!(schedule.next_verification_at, now + 600);

        let due = scheduler.tools_due_at(now);
        assert!(due.is_empty());

        let due_later = scheduler.tools_due_at(now + 600);
        assert!(due_later.contains(&"tool-b".to_owned()));
    }

    #[test]
    fn unschedule_removes_entry() {
        let mut scheduler = VerificationScheduler::new();
        scheduler.schedule_tool_verification("tool-c", 100).unwrap();
        assert_eq!(scheduler.len(), 1);

        assert!(scheduler.unschedule_tool_verification("tool-c"));
        assert!(scheduler.is_empty());
        assert!(!scheduler.unschedule_tool_verification("tool-c"));
    }

    #[test]
    fn reschedule_replaces_existing() {
        let mut scheduler = VerificationScheduler::new();
        scheduler.schedule_tool_verification("tool-d", 100).unwrap();
        scheduler.schedule_tool_verification("tool-d", 500).unwrap();

        assert_eq!(scheduler.len(), 1);
        let schedule = scheduler.get_schedule("tool-d").unwrap();
        assert_eq!(schedule.interval_secs, 500);
    }

    #[test]
    fn multiple_tools_due() {
        let mut scheduler = VerificationScheduler::new();
        scheduler.schedule_tool_verification("t1", 100).unwrap();
        scheduler.schedule_tool_verification("t2", 200).unwrap();
        scheduler.schedule_tool_verification("t3", 300).unwrap();

        let due = scheduler.tools_due_now().unwrap();
        assert_eq!(due.len(), 3);

        let now = time::now_secs().unwrap();
        scheduler.record_verification("t1", now);
        scheduler.record_verification("t2", now);

        let due = scheduler.tools_due_at(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], "t3");
    }
}
