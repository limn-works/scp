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

/**
 * A signer's key could not be resolved: the instance has no DID resolver, or a
 * supplied `ChallengeVerification` could not be checked (DID resolution
 * failed, spec 03). Maps from `AdmissionError::VerificationUnavailable` and a
 * missing instance resolver.
 */
const val DID_RESOLUTION_FAILED_CODE: String = "SCP-IDENT-1033"

/**
 * The registry's JSON schema validation error, which the bridges also raise
 * for every trust error without a code of its own: a challenge, response or
 * verification whose signature does not verify, a record bound to another
 * verifier, subject, context or window, a caller who is not a member or has
 * not opted in, or a failed ledger write. Maps from each `TrustError` variant
 * `trust_error_code` does not name.
 */
const val JSON_SCHEMA_VALIDATION_FAILED_CODE: String = "SCP-VALID-7003"

/** A protocol suite has fewer test cases than its standard's minimum. */
const val CHALLENGE_SUITE_BELOW_MINIMUM_CODE: String = "SCP-VALID-7039"

/**
 * The agent capabilities JSON of a capability admission check does not decode
 * as a list of capability URIs.
 */
const val MALFORMED_AGENT_CAPABILITIES_CODE: String = "SCP-VALID-7074"

/**
 * The challenge verifications JSON of a capability admission check does not
 * decode as a list of `ChallengeVerification` records.
 */
const val MALFORMED_CHALLENGE_VERIFICATIONS_CODE: String = "SCP-VALID-7075"

/**
 * A capability requirement is unmet: the subject lacks a required capability,
 * or a `ChallengeVerified` requirement has no record that admits the subject.
 * Maps from `AdmissionError::MissingCapability` and
 * `AdmissionError::VerificationRequired`.
 */
const val ADMISSION_REQUIREMENT_UNMET_CODE: String = "SCP-VALID-7076"

/**
 * A capability admission check names an empty subject DID. Maps from
 * `AdmissionError::EmptySubjectDid`.
 */
const val EMPTY_SUBJECT_DID_CODE: String = "SCP-VALID-7077"

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

/**
 * A required capability has no passing record from a trusted challenger: the
 * only passing record comes from a verifier the requirement does not trust.
 * Maps from `AdmissionError::UntrustedVerifier`.
 */
const val UNTRUSTED_VERIFIER_CODE: String = "SCP-VALID-7121"

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
