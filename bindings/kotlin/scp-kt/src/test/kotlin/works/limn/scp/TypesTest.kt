// TypesTest.kt — Unit tests for pure-Kotlin convenience types in Types.kt.
//
// The Capability helpers are pure Kotlin string construction and do not
// require the native UniFFI binary.
//
// Provenance: §5.4.2 (outlet capabilities), ADR-049 §1 (outlet→outlet rename)

package works.limn.scp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

class TypesTest {
    @Test
    fun `canonical outlet capability constants use colon form`() {
        assertEquals("outlet:query:*", Capability.OUTLET_QUERY_ALL)
        assertEquals("outlet:call:*", Capability.OUTLET_CALL_ALL)
        assertEquals("outlet:register", Capability.OUTLET_REGISTER)
        assertEquals("outlet:interface", Capability.OUTLET_INTERFACE)
        assertEquals("messages:read", Capability.MESSAGES_READ)
        assertEquals("messages:write", Capability.MESSAGES_WRITE)
    }

    @Test
    fun `outletCall builds parameterised capability string`() {
        assertEquals("outlet:call:calculator", Capability.outletCall("calculator"))
    }

    @Test
    fun `outletQuery builds parameterised capability string`() {
        assertEquals("outlet:query:calculator", Capability.outletQuery("calculator"))
    }

    @Test
    fun `outlet call wildcard covers specific outlet call`() {
        val handle = ScopedHandle(
            contextId = "ctx-1",
            grantedCapabilities = listOf(Capability.OUTLET_CALL_ALL),
            appDid = "did:key:app",
        )
        assertEquals(true, handle.hasCapability("outlet:call:calculator"))
        assertEquals(false, handle.hasCapability("outlet:query:calculator"))
    }

    @Test
    fun `outlet query wildcard covers specific outlet query`() {
        val handle = ScopedHandle(
            contextId = "ctx-1",
            grantedCapabilities = listOf(Capability.OUTLET_QUERY_ALL),
            appDid = "did:key:app",
        )
        assertEquals(true, handle.hasCapability("outlet:query:calculator"))
        assertEquals(false, handle.hasCapability("outlet:call:calculator"))
    }

    /**
     * `Scp.governanceExecute` parses through [GovernanceActionResult.fromBridge],
     * which returns the entry for a name one carries and throws
     * `SCP-GOV-11040` for a name none carries. Making it return
     * [GovernanceActionResult.EXECUTED] for an unknown name fails this test.
     */
    @Test
    fun `governance outcome parse fails closed on an unknown name`() {
        assertEquals(29, GovernanceActionResult.entries.size)
        assertEquals(
            GovernanceActionResult.MEMBER_ADDED,
            GovernanceActionResult.fromBridge("MemberAdded"),
        )
        val error =
            assertThrows<uniffi.scp.ScpException.Context> {
                GovernanceActionResult.fromBridge("SomethingThisSdkDoesNotKnow")
            }
        assertEquals("SCP-GOV-11040", error.code)
    }

    /**
     * `Scp.governancePropose` and `GovernanceBridgeOps.propose` check the
     * auto-executed outcome through
     * [GovernanceActionResult.checkProposeResponse]. Making it return [raw]
     * without parsing `execution_result` fails the unknown-name assertion.
     */
    @Test
    fun `governance propose response check fails closed on an outcome it cannot name`() {
        for (raw in listOf(
            """{"proposal_id":"00","execution_result":"RoleChanged"}""",
            """{"proposal_id":"00","execution_result":null}""",
        )) {
            assertEquals(raw, GovernanceActionResult.checkProposeResponse(raw))
        }
        for (raw in listOf(
            """{"proposal_id":"00","execution_result":"SomethingThisSdkDoesNotKnow"}""",
            "not json",
            "[]",
            """{"execution_result":7}""",
        )) {
            val error =
                assertThrows<uniffi.scp.ScpException.Context> {
                    GovernanceActionResult.checkProposeResponse(raw)
                }
            assertEquals("SCP-GOV-11040", error.code)
        }
    }
}
