// CaveatsRoundtripTest.kt — SCP-OUT-023 AC-7 conformance for the Kotlin SDK.
//
// Mirrors `bindings/python/tests/test_caveats_roundtrip.py`. Builds an
// `InvocationCaveats` JSON wire object, mints a UCAN through the real
// UniFFI bridge (`uniffi.scp.ucanMint(..., caveatsJson)`), decodes the
// returned JWT's payload segment, and asserts every populated caveat
// field surfaces in `payload.nb` byte-for-byte.
//
// The test skips cleanly when the UniFFI-generated native library is not
// available (mirrors `pytest.importorskip` in the Python conformance test
// and the `assumeTrue(nativeAvailable, ...)` pattern in `RealFFITest`).
//
// Provenance:
//   - .docs/prds/outlet.json — SCP-OUT-023 AC-7
//   - .docs/specs/07-trust-validation-and-capabilities.md §7.3.8
//   - bindings/python/tests/test_caveats_roundtrip.py (reference)

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@Suppress("TooManyFunctions")
@OptIn(ExperimentalCoroutinesApi::class)
class CaveatsRoundtripTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""
        private var relayHandle: Any? = null

        @JvmStatic
        @BeforeAll
        fun checkNativeLibraryAndStartRelay() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                nativeAvailable = true
                kotlinx.coroutines.runBlocking {
                    val handle = uniffi.scp.relayStartInMemory()
                    relayHandle = handle
                    val bootstrap = uniffi.scp.identityCreate("in_memory")
                    uniffi.scp.configureRelayTransport(
                        relayUrl = handle.relayUrl(),
                        localDid = bootstrap.did(),
                    )
                }
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI generated bindings not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: ExceptionInInitializerError) {
                skipReason = "Native library init error: ${e.cause?.message ?: e.message}"
            } catch (e: NoClassDefFoundError) {
                skipReason = "Native library class not found: ${e.message}"
            }
        }

        @JvmStatic
        @AfterAll
        fun shutdownRelay() {
            (relayHandle as? uniffi.scp.RelayHandle)?.shutdown()
        }

        /** Decodes the JWT payload (middle base64url segment) into a JsonObject. */
        fun decodeJwtPayload(encoded: String): JsonObject {
            val parts = encoded.split(".")
            require(parts.size == 3) { "expected 3 JWT segments, got ${parts.size}" }
            val padded = parts[1] + "=".repeat((4 - parts[1].length % 4) % 4)
            val bytes = Base64.getUrlDecoder().decode(padded)
            return Json.parseToJsonElement(String(bytes, Charsets.UTF_8)).jsonObject
        }

        /** Default cross-delegation context params with a relaxed ceiling. */
        private fun defaultParams(ceiling: List<String>) =
            uniffi.scp.ContextParams(
                mode = uniffi.scp.ContextMode.ENCRYPTED,
                ceiling = ceiling,
                ceilingPolicy = uniffi.scp.CeilingPolicy.IMMUTABLE,
                governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
                memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
                ttlSeconds = 0uL,
                promotable = false,
                minProtocolVersion = 0u,
            )

        /** Builds the 8-budgeted-fields + originKind=Action wire JSON for caveats. */
        fun primaryCaveatsJson(): String =
            buildJsonObject {
                put("amountMaxPerCall", 100)
                put("amountMaxCumulative", 1000)
                put("validFrom", 1_700_000_000)
                put("validUntil", 1_700_003_600)
                put("maxCalls", 42)
                putJsonObject("rateWindow") {
                    put("max", 1)
                    put("windowSecs", 60)
                }
                putJsonArray("allowedAdapters") {
                    add("native")
                    add("openai-compatible")
                }
                putJsonArray("allowedTargetDids") {
                    add("did:dht:zMember")
                    add("did:dht:zOther")
                }
                put("originKind", "Action")
            }.toString()

        /** Builds the companion (hoursOfDay/daysOfWeek/inputSchema/originKind=Query) wire JSON. */
        fun companionCaveatsJson(): String =
            buildJsonObject {
                put("hoursOfDay", 0x00FF_FFFF)
                put("daysOfWeek", 0x7F)
                putJsonObject("inputSchema") {
                    put("type", "object")
                    putJsonObject("properties") {
                        putJsonObject("x") { put("type", "number") }
                    }
                    putJsonArray("required") { add("x") }
                }
                put("originKind", "Query")
            }.toString()

        /** Asserts the companion mint's `nb` field carries every populated caveat. */
        fun assertCompanionNb(payloadNb: JsonObject) {
            assertEquals(0x00FF_FFFF, payloadNb["hoursOfDay"]?.jsonPrimitive?.int)
            assertEquals(0x7F, payloadNb["daysOfWeek"]?.jsonPrimitive?.int)
            val schema = payloadNb["inputSchema"]?.jsonObject
            assertNotNull(schema, "inputSchema must be present")
            assertEquals("object", schema["type"]?.jsonPrimitive?.content)
            val required = schema["required"]?.jsonArray
            assertNotNull(required, "inputSchema.required must be present")
            assertEquals(listOf("x"), required.map { it.jsonPrimitive.content })
            assertEquals("Query", payloadNb["originKind"]?.jsonPrimitive?.content)
            for (absent in listOf(
                "amountMaxPerCall",
                "amountMaxCumulative",
                "validFrom",
                "validUntil",
                "maxCalls",
                "rateWindow",
                "allowedAdapters",
                "allowedTargetDids",
            )) {
                assertFalse(payloadNb.containsKey(absent), "field $absent must be omitted from nb")
            }
        }

        /** Builds a 9-populated-field caveats wire JSON that exceeds MAX_POPULATED_CAVEATS. */
        fun overCapCaveatsJson(): String =
            buildJsonObject {
                put("amountMaxPerCall", 1)
                put("amountMaxCumulative", 2)
                put("validFrom", 3)
                put("validUntil", 4)
                put("hoursOfDay", 0x00FF_FFFF)
                put("daysOfWeek", 0x7F)
                put("maxCalls", 5)
                putJsonObject("rateWindow") {
                    put("max", 1)
                    put("windowSecs", 60)
                }
                putJsonObject("inputSchema") { put("type", "object") } // 9th field
            }.toString()

        /** Asserts the primary mint's `nb` field carries every populated caveat. */
        fun assertPrimaryNb(payloadNb: JsonObject) {
            assertEquals(100, payloadNb["amountMaxPerCall"]?.jsonPrimitive?.int)
            assertEquals(1000, payloadNb["amountMaxCumulative"]?.jsonPrimitive?.int)
            assertEquals(1_700_000_000L, payloadNb["validFrom"]?.jsonPrimitive?.long)
            assertEquals(1_700_003_600L, payloadNb["validUntil"]?.jsonPrimitive?.long)
            assertEquals(42, payloadNb["maxCalls"]?.jsonPrimitive?.int)

            val rateWindow = payloadNb["rateWindow"]?.jsonObject
            assertNotNull(rateWindow, "rateWindow must be present and a JSON object")
            assertEquals(1, rateWindow["max"]?.jsonPrimitive?.int)
            assertEquals(60, rateWindow["windowSecs"]?.jsonPrimitive?.int)

            val adapters = payloadNb["allowedAdapters"]?.jsonArray
            assertNotNull(adapters, "allowedAdapters must be present")
            assertEquals(listOf("native", "openai-compatible"), adapters.map { it.jsonPrimitive.content })

            val targets = payloadNb["allowedTargetDids"]?.jsonArray
            assertNotNull(targets, "allowedTargetDids must be present")
            assertEquals(
                listOf("did:dht:zMember", "did:dht:zOther"),
                targets.map { it.jsonPrimitive.content },
            )

            assertEquals("Action", payloadNb["originKind"]?.jsonPrimitive?.content)

            // SCP-OUT-018 `skip_serializing_if = "Option::is_none"`: omitted
            // SDK fields must not appear in `nb`, never as null.
            assertFalse(payloadNb.containsKey("hoursOfDay"), "absent field must be omitted")
            assertFalse(payloadNb.containsKey("daysOfWeek"), "absent field must be omitted")
            assertFalse(payloadNb.containsKey("inputSchema"), "absent field must be omitted")
        }
    }

    // §7.3.8 mint-limit: at most MAX_POPULATED_CAVEATS = 8 non-origin_kind
    // fields populated per envelope (origin_kind is structural and exempt).
    // This first test populates 8 budgeted fields + originKind — the
    // maximum mintable shape — and asserts every field round-trips through
    // the JWT `nb` field.
    @Test
    fun `8 budgeted caveats plus originKind round-trip via UCAN nb (SCP-OUT-023 AC-7)`() =
        runTest {
            assumeTrue(nativeAvailable, skipReason)

            // Cross-delegation: admin mints for member (avoids ADR-039 self-mint).
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val admin = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val member = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val handle =
                uniffi.scp.contextCreate(
                    admin,
                    defaultParams(listOf("messages:read", "messages:write")),
                )

            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val token =
                uniffi.scp.ucanMint(
                    handle,
                    member.did(),
                    listOf("messages:write"),
                    null,
                    primaryCaveatsJson(),
                )

            val encoded = token.encoded()
            assertTrue(encoded.isNotEmpty(), "token.encoded() must be non-empty")

            val payloadNb =
                decodeJwtPayload(encoded)["nb"]?.jsonObject
                    ?: error("JWT payload missing `nb` field")
            assertPrimaryNb(payloadNb)
        }

    // Companion mint covering the three fields the primary test omitted
    // (hoursOfDay, daysOfWeek, inputSchema) plus originKind=Query. Together
    // the two mints exercise every one of the 12 InvocationCaveats fields.
    @Test
    fun `hoursOfDay daysOfWeek inputSchema also round-trip via UCAN nb`() =
        runTest {
            assumeTrue(nativeAvailable, skipReason)

            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val admin = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val member = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val handle = uniffi.scp.contextCreate(admin, defaultParams(listOf("messages:read")))

            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val token =
                uniffi.scp.ucanMint(
                    handle,
                    member.did(),
                    listOf("messages:read"),
                    null,
                    companionCaveatsJson(),
                )

            val payloadNb =
                decodeJwtPayload(token.encoded())["nb"]?.jsonObject
                    ?: error("JWT payload missing `nb` field")
            assertCompanionNb(payloadNb)
        }

    // Mirrors `test_mint_limit_violation_surfaces_slug` in the Python
    // reference: 9 populated non-`origin_kind` fields exceeds
    // MAX_POPULATED_CAVEATS = 8 and must surface SCP-TOOL-6114 / the
    // `caveat-mint-limit-exceeded` slug.
    @Test
    fun `mint-limit violation surfaces caveat-mint-limit-exceeded slug (SCP-OUT-023 AC-6)`() =
        runTest {
            assumeTrue(nativeAvailable, skipReason)

            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val admin = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val member = uniffi.scp.identityCreate("in_memory")
            // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
            val handle = uniffi.scp.contextCreate(admin, defaultParams(listOf("messages:read")))

            val thrown =
                runCatching {
                    // SCP-DEFAULT-INSTANCE-OK: raw UniFFI binding test; bypasses SDK facade by design
                    uniffi.scp.ucanMint(
                        handle,
                        member.did(),
                        listOf("messages:read"),
                        null,
                        overCapCaveatsJson(),
                    )
                }
            val error = thrown.exceptionOrNull()
            assertNotNull(error, "expected mint-limit violation to throw")
            val message = error.message.orEmpty() + " :: " + error.toString()
            assertTrue(
                message.contains("caveat-mint-limit-exceeded"),
                "expected error to carry caveat-mint-limit-exceeded slug, got: $message",
            )
        }
}
