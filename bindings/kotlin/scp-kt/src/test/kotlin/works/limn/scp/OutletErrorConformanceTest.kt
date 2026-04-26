package works.limn.scp

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * SCP-OUT-031 — Kotlin OutletError sealed-hierarchy + fixture round-trip.
 *
 * Verifies the eight new sealed-hierarchy children, the [Credit] /
 * [CatalogKey] / [OutletId] branded newtypes, [InvalidGrant] uniformly
 * under the [OutletError] hierarchy, the [OutletErrorNewOptions]
 * options-object factory, [redactPii] for PII redaction, per-class
 * detail-shape rejection, and the conformance fixture round-trip.
 */
class OutletErrorConformanceTest {

    @Test
    fun `eight concrete subclasses extend OutletError`() {
        val ctors: List<Pair<OutletErrorClass, OutletError>> = listOf(
            OutletErrorClass.PROTOCOL to OutletProtocolError("x"),
            OutletErrorClass.AUTHORIZATION to AuthorizationError("x"),
            OutletErrorClass.INPUT to InputError("x"),
            OutletErrorClass.EXECUTION to ExecutionError("x"),
            OutletErrorClass.OUTPUT to OutputError("x"),
            OutletErrorClass.ECONOMIC to EconomicError("x"),
            OutletErrorClass.TRANSPORT to OutletTransportError("x"),
            OutletErrorClass.GOVERNANCE to OutletGovernanceError("x"),
        )
        assertEquals(8, ctors.size)
        for ((cls, err) in ctors) {
            assertTrue(err is OutletError)
            val classWire: OutletErrorClass = when (err) {
                is OutletProtocolError -> err.classWire
                is AuthorizationError -> err.classWire
                is InputError -> err.classWire
                is ExecutionError -> err.classWire
                is OutputError -> err.classWire
                is EconomicError -> err.classWire
                is OutletTransportError -> err.classWire
                is OutletGovernanceError -> err.classWire
                else -> error("unexpected concrete class: ${'$'}{err::class}")
            }
            assertEquals(cls, classWire)
        }
    }

    @Test
    fun `Credit factory rejects zero with InvalidGrant under OutletError`() {
        val ex = assertThrows(InvalidGrant::class.java) { creditOf(0u) }
        assertTrue(ex is OutletProtocolError)
        assertTrue(ex is OutletError)
        assertEquals("SCP-TOOL-6101", ex.code)
        assertEquals("protocol.invalid-grant", ex.slug)
    }

    @Test
    fun `Credit factory accepts positive values`() {
        val c = creditOf(1u)
        assertEquals(1u, c.raw)
        val c2 = creditOf(UInt.MAX_VALUE)
        assertEquals(UInt.MAX_VALUE, c2.raw)
    }

    @Test
    fun `CatalogKey factory rejects malformed input with OutletProtocolError`() {
        assertThrows(OutletProtocolError::class.java) { CatalogKey.of("Authorization.Denied") }
        assertThrows(OutletProtocolError::class.java) { CatalogKey.of("") }
        // Canonical forms succeed.
        CatalogKey.of("authorization.denied")
        CatalogKey.of("execution.cancel-ack-timeout")
    }

    @Test
    fun `OutletError new options-object returns typed subclass`() {
        val outlet = OutletId.of("outlet-1")
        val key = CatalogKey.of("authorization.denied")
        val err = OutletError.new(
            OutletErrorNewOptions(
                outletId = outlet,
                catalogKey = key,
                errorClass =OutletErrorClass.AUTHORIZATION,
            )
        )
        assertTrue(err is AuthorizationError)
        assertEquals("SCP-TOOL-6110", err.code)
    }

    @Test
    fun `redactPii replaces emails and DIDs`() {
        val raw = "denied for user@example.com (acting as did:dht:abc.123_xyz)"
        val out = redactPii(raw)
        assertTrue(!out.contains("user@example.com"))
        assertTrue(!out.contains("did:dht:"))
        assertTrue(out.contains("[redacted]"))
    }

    @Test
    fun `detail shape mismatch is rejected at OutletError new`() {
        val outlet = OutletId.of("outlet-1")
        val key = CatalogKey.of("authorization.denied")
        // FieldViolation is for input/output classes; using it on
        // authorization should throw OutletError.Validation.
        assertThrows(OutletError.Validation::class.java) {
            OutletError.new(
                OutletErrorNewOptions(
                    outletId = outlet,
                    catalogKey = key,
                    errorClass =OutletErrorClass.AUTHORIZATION,
                    detail = OutletErrorDetail.FieldViolation("/x", "type"),
                )
            )
        }
    }

    @TestFactory
    fun `every fixture round-trips`(): List<DynamicTest> {
        val fixtures = loadFixtures()
        assertTrue(fixtures.size >= 30, "expected ≥ 30 fixtures, got ${'$'}{fixtures.size}")
        return fixtures.map { fixture ->
            DynamicTest.dynamicTest("round-trip ${'$'}{fixture.name}") {
                val errorClass =requireNotNull(OutletErrorClass.fromWire(fixture.classWire)) {
                    "unknown class ${'$'}{fixture.classWire}"
                }
                // We construct the typed envelope by building the right
                // subclass and then re-extracting code/slug/classWire.
                val err: OutletError = when (errorClass) {
                    OutletErrorClass.PROTOCOL ->
                        OutletProtocolError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.AUTHORIZATION ->
                        AuthorizationError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.INPUT ->
                        InputError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.EXECUTION ->
                        ExecutionError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.OUTPUT ->
                        OutputError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.ECONOMIC ->
                        EconomicError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.TRANSPORT ->
                        OutletTransportError(fixture.message, fixture.code, fixture.slug)
                    OutletErrorClass.GOVERNANCE ->
                        OutletGovernanceError(fixture.message, fixture.code, fixture.slug)
                }
                assertEquals(fixture.code, err.code)
                val classWire: OutletErrorClass = when (err) {
                    is OutletProtocolError -> err.classWire
                    is AuthorizationError -> err.classWire
                    is InputError -> err.classWire
                    is ExecutionError -> err.classWire
                    is OutputError -> err.classWire
                    is EconomicError -> err.classWire
                    is OutletTransportError -> err.classWire
                    is OutletGovernanceError -> err.classWire
                    else -> error("unexpected: ${'$'}{err::class}")
                }
                assertEquals(errorClass, classWire)
            }
        }
    }

    @Test
    fun `pii fixture redacts when surfaced through subclass message`() {
        val fixtures = loadFixtures()
        val pii = fixtures.first { it.name == "redaction-pii-email-and-did" }
        assertNotNull(pii)
        val err = AuthorizationError(pii.message, pii.code, pii.slug)
        // Constructor runs `redactPii` on the message before storing.
        assertTrue(!err.message!!.contains("user@example.com"))
        assertTrue(!err.message!!.contains("did:dht:"))
        assertTrue(err.message!!.contains("[redacted]"))
    }

    // -------------------------------------------------------------------
    // Fixture loader
    // -------------------------------------------------------------------

    @Serializable
    private data class FixtureEnvelope(
        val name: String,
        val code: String,
        val slug: String,
        val classWire: String,
        val message: String,
    )

    private fun loadFixtures(): List<FixtureEnvelope> {
        // Scan up the directory tree from the test working directory
        // until we find `tests/conformance/vectors/outlet_error_fixtures.json`.
        var dir: Path = Paths.get("").toAbsolutePath()
        repeat(8) {
            val candidate = dir.resolve("tests/conformance/vectors/outlet_error_fixtures.json")
            if (Files.exists(candidate)) {
                val text = String(Files.readAllBytes(candidate))
                return parseFixturesFromJsonString(text)
            }
            dir = dir.parent ?: return@repeat
        }
        error("outlet_error_fixtures.json not found from working dir ${'$'}{Paths.get(\"\").toAbsolutePath()}")
    }

    private fun parseFixturesFromJsonString(text: String): List<FixtureEnvelope> {
        val json = Json { ignoreUnknownKeys = true }
        // Decode into a raw JsonElement and walk it.
        @Serializable
        data class RawFixture(
            val name: String,
            val code: String,
            val slug: String,
            val `class`: String,
            val message: String,
        )

        @Serializable
        data class RawOuter(val fixtures: List<RawFixture>)

        val outer = json.decodeFromString<RawOuter>(text)
        return outer.fixtures.map { f ->
            FixtureEnvelope(
                name = f.name,
                code = f.code,
                slug = f.slug,
                classWire = f.`class`,
                message = f.message,
            )
        }
    }
}
