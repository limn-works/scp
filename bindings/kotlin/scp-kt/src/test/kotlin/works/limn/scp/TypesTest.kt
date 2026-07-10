// TypesTest.kt — Unit tests for pure-Kotlin convenience types in Types.kt.
//
// The Capability helpers are pure Kotlin string construction and do not
// require the native UniFFI binary.
//
// Provenance: §5.4.2 (outlet capabilities), ADR-049 §1 (tool→outlet rename)

package works.limn.scp

import org.junit.jupiter.api.Assertions.assertEquals
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
}
