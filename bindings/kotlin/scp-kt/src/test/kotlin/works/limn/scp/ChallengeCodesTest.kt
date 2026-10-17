// ChallengeCodesTest.kt — The challenge and admission code constants and the
// isRetryable / retryAfter helpers (ChallengeCodes.kt). Pure logic, no native
// library; TrustAggregateFfiTest.kt reads retryAfter off a real bridge refusal.

package works.limn.scp

import org.junit.jupiter.api.Test
import uniffi.scp.ScpException
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ChallengeCodesTest {
    /** Every challenge and admission code constant, with its Rust variant's value. */
    private val codes =
        mapOf(
            DID_RESOLUTION_FAILED_CODE to "SCP-IDENT-1033",
            JSON_SCHEMA_VALIDATION_FAILED_CODE to "SCP-VALID-7003",
            MALFORMED_AGENT_CAPABILITIES_CODE to "SCP-VALID-7074",
            MALFORMED_CHALLENGE_VERIFICATIONS_CODE to "SCP-VALID-7075",
            ADMISSION_REQUIREMENT_UNMET_CODE to "SCP-VALID-7076",
            EMPTY_SUBJECT_DID_CODE to "SCP-VALID-7077",
            UNTRUSTED_VERIFIER_CODE to "SCP-VALID-7121",
            CHALLENGE_SUITE_BELOW_MINIMUM_CODE to "SCP-VALID-7039",
            CHALLENGE_NOT_OPEN_CODE to "SCP-VALID-7099",
            CHALLENGE_EXPIRED_CODE to "SCP-VALID-7102",
            ATTEMPT_OUT_OF_ORDER_CODE to "SCP-VALID-7103",
            RETRIES_EXHAUSTED_CODE to "SCP-VALID-7104",
            COOLDOWN_ACTIVE_CODE to "SCP-VALID-7105",
            CHALLENGE_CLOSED_CODE to "SCP-VALID-7106",
            UNKNOWN_CHALLENGE_CODE to "SCP-VALID-7107",
            OUTPUTS_MISMATCH_CODE to "SCP-VALID-7108",
            EVALUATOR_UNAVAILABLE_CODE to "SCP-VALID-7109",
            SELF_CHALLENGE_CODE to "SCP-VALID-7127",
            STANDARD_NOT_GRADABLE_CODE to "SCP-VALID-7128",
            CAPABILITY_DEFINITION_UNAVAILABLE_CODE to "SCP-VALID-7129",
            POLICY_OUTSIDE_DEFINITION_CODE to "SCP-VALID-7137",
            SCHEMA_REJECTED_CODE to "SCP-VALID-7138",
            GRADING_IN_PROGRESS_CODE to "SCP-VALID-7139",
            RESPONSE_TOO_LARGE_CODE to "SCP-VALID-7143",
            DEFINITION_EQUIVOCATION_CODE to "SCP-VALID-7144",
            GRADING_CAPACITY_EXHAUSTED_CODE to "SCP-VALID-7146",
            NON_CANONICAL_IDENTIFIER_CODE to "SCP-VALID-7147",
            TOO_MANY_CAPABILITY_REQUIREMENTS_CODE to "SCP-VALID-7148",
            GRADING_LEASE_LOST_CODE to "SCP-VALID-7149",
            INVALID_REQUIREMENT_CODE to "SCP-VALID-7150",
            CHALLENGE_WINDOW_OPEN_CODE to "SCP-VALID-7151",
            CHALLENGE_NOT_YET_GRADABLE_CODE to "SCP-VALID-7153",
        )

    @Test
    fun `every code constant carries its Rust variant's value`() {
        assertEquals(32, codes.size)
        for ((constant, value) in codes) {
            assertEquals(value, constant)
        }
    }

    @Test
    fun `isRetryable is true exactly for the seven retry-later codes`() {
        val retryable =
            setOf(
                "SCP-VALID-7099",
                "SCP-VALID-7105",
                "SCP-VALID-7139",
                "SCP-VALID-7146",
                "SCP-VALID-7149",
                "SCP-VALID-7151",
                "SCP-VALID-7153",
            )
        for (code in codes.keys) {
            assertEquals(code in retryable, isRetryable(code), code)
        }
        assertFalse(isRetryable("SCP-VALID-7076"))
        assertFalse(isRetryable(""))
    }

    @Test
    fun `retryAfter reads the retry_after suffix and is null without one`() {
        assertEquals(
            1_700_003_600uL,
            retryAfter(
                ScpException.Validation(
                    msg = "trust evaluation failed: cooldown active (retry_after=1700003600)",
                    code = COOLDOWN_ACTIVE_CODE,
                ),
            ),
        )
        assertNull(
            retryAfter(ScpException.Validation(msg = "trust evaluation failed: closed", code = CHALLENGE_CLOSED_CODE)),
        )
        // Only a suffix counts: the key in the middle of a message is not a retry time.
        assertNull(
            retryAfter(ScpException.Validation(msg = "(retry_after=5) and more", code = COOLDOWN_ACTIVE_CODE)),
        )
        assertTrue(isRetryable(COOLDOWN_ACTIVE_CODE))
    }
}
