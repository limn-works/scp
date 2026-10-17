// ChallengeCodes.kt — The error codes the bridges raise for the challenge and
// admission operations (spec 07 §7.3.4, ADR-017), and the two helpers that
// tell a caller whether, and when, to try again.
//
// Each constant is named after the Rust `TrustError` or `AdmissionError`
// variant that `crates/scp-ffi/common/src/error_codes.rs`
// (`trust_error_code`, `admission_error_code`) maps to it, and carries the
// same value. Mirrors the TypeScript, Python and Swift SDK constants.

package works.limn.scp

import uniffi.scp.ScpException

/** A protocol suite has fewer test cases than its standard's minimum. */
const val CHALLENGE_SUITE_BELOW_MINIMUM_CODE: String = "SCP-VALID-7039"

/** The challenger already holds the most open challenges it may; retry later. */
const val CHALLENGE_NOT_OPEN_CODE: String = "SCP-VALID-7099"

/** The time is outside the challenge window. */
const val CHALLENGE_EXPIRED_CODE: String = "SCP-VALID-7102"

/** The attempt is not the last graded attempt plus one. */
const val ATTEMPT_OUT_OF_ORDER_CODE: String = "SCP-VALID-7103"

/** The subject has used every attempt the policy allows. */
const val RETRIES_EXHAUSTED_CODE: String = "SCP-VALID-7104"

/** The cooldown since the last attempt has not passed; [retryAfter] names when it ends. */
const val COOLDOWN_ACTIVE_CODE: String = "SCP-VALID-7105"

/** The challenge closed after a pass or its last allowed attempt. */
const val CHALLENGE_CLOSED_CODE: String = "SCP-VALID-7106"

/** The challenger's ledger holds no live challenge with this id, request digest and subject. */
const val UNKNOWN_CHALLENGE_CODE: String = "SCP-VALID-7107"

/** The response does not answer the request, or its outputs do not match the cases one for one, in order. */
const val OUTPUTS_MISMATCH_CODE: String = "SCP-VALID-7108"

/** A `CustomEval` evaluator cannot run: unregistered, without a handler, or not callable by the challenger. */
const val EVALUATOR_UNAVAILABLE_CODE: String = "SCP-VALID-7109"

/** The verifier and the subject are the same identity. */
const val SELF_CHALLENGE_CODE: String = "SCP-VALID-7127"

/** The URI names a standard whose pass condition cannot be computed from outputs, or a system capability. */
const val STANDARD_NOT_GRADABLE_CODE: String = "SCP-VALID-7128"

/** The capability definition for the URI could not be obtained. */
const val CAPABILITY_DEFINITION_UNAVAILABLE_CODE: String = "SCP-VALID-7129"

/** A policy or retry cap is looser than the capability definition allows. */
const val POLICY_OUTSIDE_DEFINITION_CODE: String = "SCP-VALID-7137"

/** A `SchemaMatch` schema is not admissible. */
const val SCHEMA_REJECTED_CODE: String = "SCP-VALID-7138"

/** Another grading of this challenge holds a live lease; retry later. */
const val GRADING_IN_PROGRESS_CODE: String = "SCP-VALID-7139"

/** The response is larger than the protocol allows. */
const val RESPONSE_TOO_LARGE_CODE: String = "SCP-VALID-7143"

/** Two validly signed definitions for one capability URI differ. */
const val DEFINITION_EQUIVOCATION_CODE: String = "SCP-VALID-7144"

/** The challenger cannot grade another attempt now; the attempt is not used. */
const val GRADING_CAPACITY_EXHAUSTED_CODE: String = "SCP-VALID-7146"

/** A DID or URI is not canonical. */
const val NON_CANONICAL_IDENTIFIER_CODE: String = "SCP-VALID-7147"

/** A context names more capability requirements than the protocol allows. */
const val TOO_MANY_CAPABILITY_REQUIREMENTS_CODE: String = "SCP-VALID-7148"

/** The challenger lost its grading lease on an attempt; the attempt is not used. */
const val GRADING_LEASE_LOST_CODE: String = "SCP-VALID-7149"

/**
 * A capability requirement breaks a spec 07 §7.3.4.4 rule, such as a
 * `ChallengeVerified` requirement with no trusted verifier.
 */
const val INVALID_REQUIREMENT_CODE: String = "SCP-VALID-7150"

/**
 * The challenger's last challenge to this subject for this capability is
 * still inside its window; [retryAfter] names when a new one may be created.
 */
const val CHALLENGE_WINDOW_OPEN_CODE: String = "SCP-VALID-7151"

/**
 * The attempt was submitted in its challenge's creation second; [retryAfter]
 * names when the same attempt may be resubmitted.
 */
const val CHALLENGE_NOT_YET_GRADABLE_CODE: String = "SCP-VALID-7153"

private val RETRYABLE_CODES =
    setOf(
        CHALLENGE_NOT_OPEN_CODE,
        COOLDOWN_ACTIVE_CODE,
        GRADING_IN_PROGRESS_CODE,
        GRADING_CAPACITY_EXHAUSTED_CODE,
        GRADING_LEASE_LOST_CODE,
        CHALLENGE_WINDOW_OPEN_CODE,
        CHALLENGE_NOT_YET_GRADABLE_CODE,
    )

/**
 * Whether a call refused with [code] may succeed if repeated later
 * unchanged: `true` for [CHALLENGE_NOT_OPEN_CODE], [COOLDOWN_ACTIVE_CODE],
 * [GRADING_IN_PROGRESS_CODE], [GRADING_CAPACITY_EXHAUSTED_CODE],
 * [GRADING_LEASE_LOST_CODE], [CHALLENGE_WINDOW_OPEN_CODE] and
 * [CHALLENGE_NOT_YET_GRADABLE_CODE], and `false` for every other code.
 */
fun isRetryable(code: String): Boolean = code in RETRYABLE_CODES

private val RETRY_AFTER_SUFFIX = Regex("""\(retry_after=(\d+)\)$""")

/**
 * The first Unix second at which the call [error] refused may succeed, read
 * from the `(retry_after=N)` suffix the bridges append to the message of a
 * [COOLDOWN_ACTIVE_CODE], [CHALLENGE_WINDOW_OPEN_CODE] or
 * [CHALLENGE_NOT_YET_GRADABLE_CODE] refusal; `null` when the message has no
 * such suffix.
 */
fun retryAfter(error: ScpException.Validation): ULong? =
    RETRY_AFTER_SUFFIX
        .find(error.msg)
        ?.groupValues
        ?.get(1)
        ?.toULongOrNull()
