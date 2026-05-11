// SCP-OUT-039 cross-SDK byte-equivalence — Kotlin (UniFFI) replay.
//
// Loads the on-disk fixture at
// `tests/conformance/vectors/outlet_caveats_binding_fixtures.json` and
// asserts the UniFFI bridge produces the SAME 32-byte `caveats_binding`
// hashes the protocol-level Rust helpers produced when the fixture was
// generated. Per spec §5.4.5 line 635 / ADR-049 §5 round-5 JCS Option
// rule, the four SDKs (PyO3, NAPI, UniFFI Swift / Kotlin, WASM) MUST
// produce byte-identical output — this test is the Kotlin leg.
//
// Mirrors:
// - `bindings/python/tests/test_outlet_caveats_binding_conformance.py`
// - `bindings/typescript/tests/outlet-caveats-binding-conformance.test.ts`
// - `bindings/swift/Tests/SCPTests/OutletCaveatsBindingConformanceTests.swift`
// - `crates/scp-ffi/uniffi/tests/outlet_stream_vectors.rs` (Rust leg)
//
// The bridge surface (`OutletStreaming.computeCaveatsBinding`) accepts
// the §5.4.5 preimage inputs verbatim. The fixture stores the JCS-
// canonical `effective_caveats` string the Rust generator produced;
// the Kotlin test feeds it to the bridge unchanged. The bridge
// re-canonicalises via the same `scp_protocol::jcs` path internally
// and MUST land on the same 32-byte hash.
//
// Skips cleanly when the UniFFI-generated native library is not
// loadable — matches the pattern in `CaveatsRoundtripTest`. The
// schema-shape assertions run regardless so a malformed fixture file
// is caught even without the bridge.

package works.limn.scp

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test

@Suppress("TooManyFunctions")
class OutletCaveatsBindingConformanceTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun checkNativeLibrary() {
            // The UniFFI-generated `uniffi.scp.ScpKt` symbol class only
            // exists once the native library is on the classpath and
            // its initialiser runs without an unsatisfied-link error.
            // Any failure mode is captured for diagnostics — the
            // schema-shape tests run regardless, and the FFI-driven
            // tests skip cleanly via `assumeTrue`.
            try {
                Class.forName("uniffi.scp.ScpKt")
                nativeAvailable = true
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
    }

    @Serializable
    private data class CaveatsBindingVector(
        val name: String,
        val description: String,
        @kotlinx.serialization.SerialName("ucan_cid_hex")
        val ucanCidHex: String,
        @kotlinx.serialization.SerialName("request_id_hex")
        val requestIdHex: String,
        @kotlinx.serialization.SerialName("invoker_did")
        val invokerDid: String,
        @kotlinx.serialization.SerialName("estimated_chunk_count")
        val estimatedChunkCount: Int,
        @kotlinx.serialization.SerialName("effective_caveats_jcs")
        val effectiveCaveatsJcs: String,
        @kotlinx.serialization.SerialName("expected_caveats_binding_hex")
        val expectedCaveatsBindingHex: String,
    )

    @Serializable
    private data class ChunkSigVector(
        val name: String,
        val description: String,
        @kotlinx.serialization.SerialName("context_id") val contextId: String,
        @kotlinx.serialization.SerialName("outlet_id") val outletId: String,
        @kotlinx.serialization.SerialName("request_id_hex") val requestIdHex: String,
        val sequence: Long,
        @kotlinx.serialization.SerialName("caveats_binding_hex") val caveatsBindingHex: String,
        @kotlinx.serialization.SerialName("expected_chunk_sig_preimage_hex")
        val expectedChunkSigPreimageHex: String,
    )

    @Serializable
    private data class CreditSigVector(
        val name: String,
        val description: String,
        @kotlinx.serialization.SerialName("context_id") val contextId: String,
        @kotlinx.serialization.SerialName("outlet_id") val outletId: String,
        @kotlinx.serialization.SerialName("request_id_hex") val requestIdHex: String,
        val grant: Int,
        @kotlinx.serialization.SerialName("monotonic_seq") val monotonicSeq: Long,
        @kotlinx.serialization.SerialName("stream_epoch") val streamEpoch: Long,
        @kotlinx.serialization.SerialName("caveats_binding_hex") val caveatsBindingHex: String,
        @kotlinx.serialization.SerialName("expected_credit_sig_preimage_hex")
        val expectedCreditSigPreimageHex: String,
    )

    @Serializable
    private data class FixtureFile(
        val comment: String,
        @kotlinx.serialization.SerialName("spec_section") val specSection: String,
        val story: String,
        @kotlinx.serialization.SerialName("caveats_binding")
        val caveatsBinding: List<CaveatsBindingVector>,
        @kotlinx.serialization.SerialName("chunk_sig_preimage")
        val chunkSigPreimage: List<ChunkSigVector>,
        @kotlinx.serialization.SerialName("credit_sig_preimage")
        val creditSigPreimage: List<CreditSigVector>,
    )

    private val json = Json { ignoreUnknownKeys = true }

    private fun fixturePath(): Path {
        // Walk up from the working directory until we find the
        // repo-root fixture. Local `gradle test` runs from
        // `bindings/kotlin`; CI may run from the repo root. Either
        // anchor resolves the same canonical path.
        var dir = Paths.get("").toAbsolutePath()
        repeat(8) {
            val candidate =
                dir.resolve("tests/conformance/vectors/outlet_caveats_binding_fixtures.json")
            if (Files.exists(candidate)) return candidate
            val parent = dir.parent ?: return@repeat
            dir = parent
        }
        error(
            "outlet_caveats_binding_fixtures.json not found from " +
                Paths.get("").toAbsolutePath(),
        )
    }

    @OptIn(ExperimentalSerializationApi::class)
    private fun loadFixture(): FixtureFile {
        val bytes = Files.readAllBytes(fixturePath())
        return json.decodeFromString(FixtureFile.serializer(), String(bytes, Charsets.UTF_8))
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex string has odd length: ${hex.length}" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    // -----------------------------------------------------------------
    // Schema-only assertions — run regardless of bridge availability.
    // -----------------------------------------------------------------

    @Test
    fun fixtureCarriesMinimumVectorCountsPerSpecFloor() {
        val fixture = loadFixture()
        assertTrue(
            fixture.caveatsBinding.size >= 3,
            "fixture must carry >= 3 caveats_binding vectors; got ${fixture.caveatsBinding.size}",
        )
        assertTrue(
            fixture.chunkSigPreimage.size >= 2,
            "fixture must carry >= 2 chunk_sig_preimage vectors; got ${fixture.chunkSigPreimage.size}",
        )
        assertTrue(
            fixture.creditSigPreimage.size >= 2,
            "fixture must carry >= 2 credit_sig_preimage vectors; got ${fixture.creditSigPreimage.size}",
        )
    }

    @Test
    fun cbEmptyVectorEncodesAsLiteralEmptyObject() {
        // The cb_empty vector documents the §5.4.5 omit-none rule.
        // Its `effective_caveats_jcs` MUST be the literal `"{}"`,
        // proving the Rust generator does NOT emit explicit `null`
        // for absent Option fields. SDKs that disagree produce a
        // different binding.
        val fixture = loadFixture()
        val cbEmpty = fixture.caveatsBinding.firstOrNull { it.name == "cb_empty" }
        assertNotNull(cbEmpty, "cb_empty vector must exist")
        assertEquals(
            "{}",
            cbEmpty.effectiveCaveatsJcs,
            "cb_empty must canonicalise to literal '{}' per §5.4.5 omit-none rule",
        )
    }

    @Test
    fun eachCaveatsBindingVectorHasRequiredByteWidths() {
        val fixture = loadFixture()
        for (vector in fixture.caveatsBinding) {
            assertEquals(
                16,
                hexToBytes(vector.requestIdHex).size,
                "vector ${vector.name}: request_id must be 16 bytes",
            )
            assertEquals(
                32,
                hexToBytes(vector.expectedCaveatsBindingHex).size,
                "vector ${vector.name}: expected_caveats_binding must be 32 bytes",
            )
        }
    }

    @Test
    fun eachChunkSigPreimageVectorHasRequiredByteWidths() {
        val fixture = loadFixture()
        for (vector in fixture.chunkSigPreimage) {
            assertEquals(
                16,
                hexToBytes(vector.requestIdHex).size,
                "vector ${vector.name}: request_id must be 16 bytes",
            )
            assertEquals(
                32,
                hexToBytes(vector.caveatsBindingHex).size,
                "vector ${vector.name}: caveats_binding must be 32 bytes",
            )
            assertEquals(
                32,
                hexToBytes(vector.expectedChunkSigPreimageHex).size,
                "vector ${vector.name}: expected_chunk_sig_preimage must be 32 bytes",
            )
        }
    }

    @Test
    fun eachCreditSigPreimageVectorHasRequiredByteWidths() {
        val fixture = loadFixture()
        for (vector in fixture.creditSigPreimage) {
            assertEquals(
                32,
                hexToBytes(vector.caveatsBindingHex).size,
                "vector ${vector.name}: caveats_binding must be 32 bytes",
            )
            assertEquals(
                32,
                hexToBytes(vector.expectedCreditSigPreimageHex).size,
                "vector ${vector.name}: expected_credit_sig_preimage must be 32 bytes",
            )
        }
    }

    // -----------------------------------------------------------------
    // Bridge-driven byte-equivalence — each vector reproduces via
    // `OutletStreaming.computeCaveatsBinding`. The UniFFI bridge
    // recomputes the §5.4.5 `SCP-OUTLET-CAVEAT-BIND-V1:` preimage
    // hash internally, and MUST produce the byte-identical hash the
    // Rust generator pinned. Any divergence indicates a cross-SDK
    // regression in JCS canonicalisation, omit-none handling, or the
    // preimage byte layout.
    //
    // Skips cleanly when the native library isn't loadable (see
    // `checkNativeLibrary` in companion). Once the library is
    // available the cross-SDK invariant is enforced byte-for-byte.
    // -----------------------------------------------------------------

    @Test
    fun everyCaveatsBindingVectorReproducesByteForByteViaUniFFI() {
        assumeTrue(nativeAvailable, skipReason)

        val fixture = loadFixture()
        for (vector in fixture.caveatsBinding) {
            val ucanCid = hexToBytes(vector.ucanCidHex)
            val requestId = hexToBytes(vector.requestIdHex)

            val actual =
                OutletStreaming.computeCaveatsBinding(
                    ucanCid = ucanCid,
                    requestId = requestId,
                    invokerDid = vector.invokerDid,
                    estimatedChunkCount = vector.estimatedChunkCount.toUInt(),
                    effectiveCaveatsJson = vector.effectiveCaveatsJcs,
                )

            assertEquals(32, actual.size, "vector ${vector.name}: hash must be 32 bytes")
            assertEquals(
                vector.expectedCaveatsBindingHex,
                bytesToHex(actual),
                "vector ${vector.name}: UniFFI bridge produced ${bytesToHex(actual)}, " +
                    "expected ${vector.expectedCaveatsBindingHex}. " +
                    "Cross-SDK byte-equivalence has regressed — check JCS / omit-none.",
            )
        }
    }
}
