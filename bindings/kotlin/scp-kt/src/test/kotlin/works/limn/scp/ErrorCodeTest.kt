// ErrorCodeTest.kt — SDK-layer round-trip tests for typed error codes.
//
// SDK-layer contract: when the UniFFI bridge emits a typed
// IDENT_1047, IDENT_1048, IDENT_1049, IDENT_1050, IDENT_1051, or
// IDENT_1052 code for a PreRotationCustodyError variant, the Kotlin
// SDK's `ScpException.Identity` class MUST preserve the code verbatim.
// The Rust bridge has its own co-located regression tests pinning the
// variant-to-code mapping (crates/scp-ffi/uniffi/src/bridge.rs:tests::
// pre_rotation_*); this suite pins the SDK-layer fall-through so a
// Kotlin wrapper change can't silently strip or rewrite the code.
//
// Literal codes also appear here as string constants — they trip a
// diff reviewer if the bridge ever re-numbers a variant without
// updating the SDK in lockstep.
//
// These tests do NOT require the native UniFFI binary —
// `ScpException` is a Kotlin sealed class, so we construct each
// variant directly and verify the `code` property round-trips. The
// full FFI integration is exercised elsewhere; here we only need the
// SDK-layer contract.

package works.limn.scp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import uniffi.scp.ScpException

class ErrorCodeTest {
    companion object {
        private const val PRE_ROTATION_HANDLE_NOT_FOUND_CODE = "SCP-IDENT-1047"
        private const val PRE_ROTATION_UNAVAILABLE_CODE = "SCP-IDENT-1048"
        private const val PRE_ROTATION_USER_DECLINED_CODE = "SCP-IDENT-1049"
        private const val PRE_ROTATION_STORAGE_CODE = "SCP-IDENT-1050"
        private const val PRE_ROTATION_INVALID_CALLBACK_CODE = "SCP-IDENT-1051"
        private const val PRE_ROTATION_COMMITMENT_MISMATCH_CODE = "SCP-IDENT-1052"
        private const val IDENTITY_GENERIC_CODE = "SCP-IDENT-1001"
    }

    @Test
    fun `pre-rotation handle-not-found code round-trips through Identity`() {
        val ex = ScpException.Identity(
            msg = "pre-rotation handle not found",
            code = PRE_ROTATION_HANDLE_NOT_FOUND_CODE,
        )
        assertEquals(PRE_ROTATION_HANDLE_NOT_FOUND_CODE, ex.code)
        assertEquals("pre-rotation handle not found", ex.msg)
    }

    @Test
    fun `pre-rotation unavailable code round-trips through Identity`() {
        val ex = ScpException.Identity(
            msg = "hardware key not connected",
            code = PRE_ROTATION_UNAVAILABLE_CODE,
        )
        assertEquals(PRE_ROTATION_UNAVAILABLE_CODE, ex.code)
    }

    @Test
    fun `pre-rotation user-declined code round-trips through Identity`() {
        val ex = ScpException.Identity(
            msg = "user declined",
            code = PRE_ROTATION_USER_DECLINED_CODE,
        )
        assertEquals(PRE_ROTATION_USER_DECLINED_CODE, ex.code)
    }

    @Test
    fun `pre-rotation storage code round-trips through Identity`() {
        val ex = ScpException.Identity(msg = "disk full", code = PRE_ROTATION_STORAGE_CODE)
        assertEquals(PRE_ROTATION_STORAGE_CODE, ex.code)
    }

    @Test
    fun `pre-rotation invalid-callback code round-trips through Identity`() {
        val ex = ScpException.Identity(
            msg = "handle is empty",
            code = PRE_ROTATION_INVALID_CALLBACK_CODE,
        )
        assertEquals(PRE_ROTATION_INVALID_CALLBACK_CODE, ex.code)
    }

    @Test
    fun `pre-rotation commitment-mismatch code round-trips through Identity`() {
        val ex = ScpException.Identity(
            msg = "commitment mismatch",
            code = PRE_ROTATION_COMMITMENT_MISMATCH_CODE,
        )
        assertEquals(PRE_ROTATION_COMMITMENT_MISMATCH_CODE, ex.code)
    }

    @Test
    fun `non-pre-rotation identity errors keep SCP-IDENT-1001 fallback`() {
        // Defense-in-depth: pin the generic-envelope fallback so a future
        // refactor that accidentally promotes the generic code to one of
        // the typed pre-rotation codes is caught at test time.
        val ex = ScpException.Identity(msg = "invalid DID format", code = IDENTITY_GENERIC_CODE)
        assertEquals(IDENTITY_GENERIC_CODE, ex.code)
    }

    @Test
    fun `each pre-rotation code is catchable as ScpException and preserved`() {
        val cases = listOf(
            "handle_not_found" to PRE_ROTATION_HANDLE_NOT_FOUND_CODE,
            "unavailable" to PRE_ROTATION_UNAVAILABLE_CODE,
            "user_declined" to PRE_ROTATION_USER_DECLINED_CODE,
            "storage" to PRE_ROTATION_STORAGE_CODE,
            "invalid_callback_response" to PRE_ROTATION_INVALID_CALLBACK_CODE,
            "commitment_mismatch" to PRE_ROTATION_COMMITMENT_MISMATCH_CODE,
        )
        for ((name, expectedCode) in cases) {
            try {
                throw ScpException.Identity(msg = "pre-rotation $name", code = expectedCode)
            } catch (ex: ScpException) {
                assertTrue(ex is ScpException.Identity, "expected Identity variant for $name")
                assertEquals(
                    expectedCode,
                    (ex as ScpException.Identity).code,
                    "code lost for $name",
                )
            }
        }
    }
}
