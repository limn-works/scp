// TypedContextParamsTest.kt — TypedContextParams forwards every field to the
// UniFFI `ContextParams` record it builds.

package works.limn.scp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.PseudonymRotationPolicy

class TypedContextParamsTest {
    private fun params(rotation: PseudonymRotationPolicy?) =
        TypedContextParams(
            mode = ContextMode.ENCRYPTED,
            ceiling = listOf("messages:read"),
            ceilingPolicy = CeilingPolicy.IMMUTABLE,
            governance = GovernanceModel.SINGLE_ADMIN,
            memoryScope = MemoryScope.EPHEMERAL,
            ttlSeconds = 3600uL,
            promotable = false,
            consequenceRules = null,
            consequenceConfig = null,
            pseudonymRotation = rotation,
        )

    @Test
    fun `toContextParams forwards the pseudonym rotation policy`() {
        val policy = PseudonymRotationPolicy(intervalSecs = 3600uL, onMembershipChange = true)
        assertEquals(policy, params(policy).toContextParams().pseudonymRotation)
    }

    @Test
    fun `toContextParams leaves pseudonym rotation unset when none is given`() {
        assertNull(params(null).toContextParams().pseudonymRotation)
    }
}
