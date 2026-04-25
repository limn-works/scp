// OutletsTest.kt — SCP-OUT-006 Kotlin outlet namespace tests.

@file:Suppress("TooManyFunctions")

package works.limn.scp

import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class OutletsTest {
    // --------------------------------------------------------------------
    // SessionId — UUIDv7 validation.
    // --------------------------------------------------------------------

    @Test
    fun `newSessionId produces a canonical UUIDv7`() {
        val sid = newSessionId()
        assertEquals(36, sid.raw.length)
        assertEquals('7', sid.raw[14])
        SessionId.validate(sid.raw)
    }

    @Test
    fun `non-UUID rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            SessionId.of("sess-abc")
        }
    }

    @Test
    fun `UUIDv4 rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            SessionId.of("550e8400-e29b-41d4-a716-446655440000")
        }
    }

    @Test
    fun `timestamp outside 10-minute window rejected`() {
        val sid = newSessionId()
        val future = System.currentTimeMillis() + 20L * 60L * 1000L
        assertThrows(IllegalArgumentException::class.java) {
            SessionId.validate(sid.raw, future)
        }
        val past = System.currentTimeMillis() - 20L * 60L * 1000L
        assertThrows(IllegalArgumentException::class.java) {
            SessionId.validate(sid.raw, past)
        }
    }

    @Test
    fun `two generations produce independent rand_b tails`() {
        val first = newSessionId()
        val second = newSessionId()
        assertNotEquals(first, second)
        assertNotEquals(first.raw.takeLast(8), second.raw.takeLast(8))
    }

    // --------------------------------------------------------------------
    // Caveat builders.
    // --------------------------------------------------------------------

    @Test
    fun `spendingCap builder`() {
        val caveat = Caveats.spendingCap(perCall = 100L, cumulative = 1000L).build()
        assertEquals(100L, caveat.amountMaxPerCall)
        assertEquals(1000L, caveat.amountMaxCumulative)
    }

    @Test
    fun `timeBounded builder`() {
        val caveat = Caveats.timeBounded(validFrom = 0L, validUntil = 999L).build()
        assertEquals(0L, caveat.validFrom)
        assertEquals(999L, caveat.validUntil)
    }

    @Test
    fun `timeBounded rejects oversized hoursOfDay mask`() {
        assertThrows(IllegalArgumentException::class.java) {
            Caveats.timeBounded(hoursOfDay = (1u shl 25))
        }
    }

    @Test
    fun `rateLimited builder`() {
        val caveat = Caveats.rateLimited(maxCalls = 10u, rateWindow = 60u).build()
        assertEquals(10u, caveat.maxCalls)
        assertEquals(60u, caveat.rateWindow)
    }

    @Test
    fun `forTarget builder`() {
        val caveat = Caveats.forTarget(
            allowedTargetDids = listOf("did:dht:a"),
            allowedAdapters = listOf("native"),
        ).build()
        assertEquals(listOf("did:dht:a"), caveat.allowedTargetDids)
        assertEquals(listOf("native"), caveat.allowedAdapters)
    }

    @Test
    fun `originKind rejects invalid values`() {
        assertThrows(IllegalArgumentException::class.java) {
            CaveatBuilder().originKind("Other")
        }
    }

    @Test
    fun `chained builder`() {
        val caveat = Caveats.spendingCap(perCall = 100L)
            .timeBounded(validUntil = 999L)
            .rateLimited(maxCalls = 5u)
            .forTarget(allowedTargetDids = listOf("did:dht:a"))
            .inputSchema("{}")
            .originKind("Query")
            .build()
        assertEquals(100L, caveat.amountMaxPerCall)
        assertEquals(999L, caveat.validUntil)
        assertEquals(5u, caveat.maxCalls)
        assertEquals("Query", caveat.originKind)
    }

    // --------------------------------------------------------------------
    // InvocationHandle — dual consumption.
    // --------------------------------------------------------------------

    @Test
    fun `aggregate and asFlow are both reachable`() = runTest {
        val ns = InMemoryOutletNamespace()
        val id = ns.register(OutletKind.ACTION, "{\"name\":\"calc\"}")
        val handle = ns.invoke(id, "{\"x\":1}", ucanToken = "eyJ.dummy")
        val agg = handle.aggregate()
        assertTrue(agg.valueJson.contains("echo"))

        // Second handle (one handle, one consumer).
        val handle2 = ns.invoke(id, "{\"x\":2}", ucanToken = "eyJ.dummy")
        val chunks = handle2.asFlow().toList()
        assertTrue(chunks.isNotEmpty())
        assertTrue(chunks.last() is OutletStreamChunk.End)
    }

    // --------------------------------------------------------------------
    // OutletNamespace shape: all verbs + sub-namespaces.
    // --------------------------------------------------------------------

    @Test
    fun `OutletNamespace exposes every verb and sub-namespace`() = runTest {
        val ns: OutletNamespace = InMemoryOutletNamespace()
        assertNotNull(ns.sessions)
        assertNotNull(ns.offers)
        val id = ns.register(OutletKind.ACTION, "{\"name\":\"calc\"}")
        assertEquals(listOf(id), ns.list())
        val got = ns.get(id)
        assertTrue(got.contains("calc"))
        val verify = ns.verify(id)
        assertTrue(verify.passed)
        ns.update(id, "{\"name\":\"calc2\"}")
        ns.deregister(id)
        assertThrows(OutletError.NotFound::class.java) {
            runBlockingAssert { ns.get(id) }
        }
    }

    @Test
    fun `sessions exposes open, invoke, close`() = runTest {
        val ns = InMemoryOutletNamespace()
        val id = ns.register(OutletKind.ACTION, "{\"name\":\"calc\"}")
        val sid = ns.sessions.open(outletId = id, sourceContextId = "ctx-source")
        val result = ns.sessions.invoke(sid, "{\"x\":1}", "eyJ.dummy")
        assertTrue(result.contains("echo"))
        ns.sessions.close(sid)
    }

    @Test
    fun `offers exposes propose, accept, revoke, list`() = runTest {
        val ns = InMemoryOutletNamespace()
        val proposal = ns.offers.propose(
            outletId = "calc",
            targetContextId = "ctx-target",
            rateLimitJson = null,
        )
        val accepted = ns.offers.accept(proposal)
        assertTrue(accepted.contains("ctx-target"))
        val revoked = ns.offers.revoke("0".repeat(64))
        assertTrue(revoked.contains("revoked"))
        assertEquals(emptyList<String>(), ns.offers.list())
    }

    @Test
    fun `invokeCrossContext uses typed DID and OutletId`() = runTest {
        val ns = InMemoryOutletNamespace()
        val options = InvokeCrossContextOptions(
            target = DID("did:dht:target"),
            outletId = OutletId("calculator"),
            inputJson = "{\"x\":1}",
            ucan = "eyJ.dummy",
        )
        val result = ns.invokeCrossContext(options)
        assertTrue(result.contains("echo"))
    }

    // --------------------------------------------------------------------
    // Value-class type distinctness (compile-time, asserted via types).
    // --------------------------------------------------------------------

    @Test
    fun `DID and OutletId and SessionId are distinct at compile time`() {
        val did = DID("did:dht:alice")
        val outlet = OutletId("calculator")
        val sid = newSessionId()
        // Compile-time guarantee: the following lines would NOT compile —
        //     val x: DID = outlet          // type mismatch
        //     val y: OutletId = sid        // type mismatch
        //     val z: String = sid          // type mismatch
        // We assert runtime raw-string shape to anchor the doc.
        assertFalse(did.raw == outlet.raw)
        assertTrue(sid.raw.length == 36)
    }

    // --------------------------------------------------------------------
    // SCP-OUT-017 — OutletKind required + register convenience methods.
    // --------------------------------------------------------------------

    @Test
    fun `OutletKind enum has Query and Action with lowercase wire forms`() {
        assertEquals("query", OutletKind.QUERY.wire)
        assertEquals("action", OutletKind.ACTION.wire)
        assertEquals(OutletKind.QUERY, OutletKind.parse("query"))
        assertEquals(OutletKind.ACTION, OutletKind.parse("action"))
    }

    @Test
    fun `OutletKind parse rejects unknown wire strings`() {
        assertThrows(IllegalArgumentException::class.java) {
            OutletKind.parse("mutation")
        }
    }

    @Test
    fun `register requires kind and threads it through to the wire form`() = runTest {
        val ns = InMemoryOutletNamespace()
        val id = ns.register(OutletKind.QUERY, "{\"name\":\"weather\"}")
        val stored = ns.get(id)
        assertTrue(
            stored.contains("\"kind\":\"query\""),
            "InMemory impl should round-trip kind=query, got: $stored",
        )
    }

    @Test
    fun `registerQuery convenience sets kind=query`() = runTest {
        val ns = InMemoryOutletNamespace()
        val id = ns.registerQuery("{\"name\":\"weather\"}")
        val stored = ns.get(id)
        assertTrue(
            stored.contains("\"kind\":\"query\""),
            "registerQuery should set kind=query, got: $stored",
        )
    }

    @Test
    fun `registerAction convenience sets kind=action`() = runTest {
        val ns = InMemoryOutletNamespace()
        val id = ns.registerAction("{\"name\":\"send-email\"}")
        val stored = ns.get(id)
        assertTrue(
            stored.contains("\"kind\":\"action\""),
            "registerAction should set kind=action, got: $stored",
        )
    }

    // Helper: wrap a suspend call so assertThrows can observe the OutletError
    // that is thrown from a coroutine body.
    private inline fun runBlockingAssert(crossinline block: suspend () -> Unit) {
        kotlinx.coroutines.runBlocking { block() }
    }
}
