// RealFFITest.kt — Phase D7: Real FFI E2E tests for the Kotlin SDK
//
// These tests exercise the actual UniFFI-generated native library, validating
// the full Kotlin -> JNA -> Rust -> scp-core code path.
//
// Prerequisites:
//   1. Build the Rust cdylib: cargo build -p scp-ffi-uniffi --features allow_in_memory_custody
//   2. Generate Kotlin bindings: ./scripts/generate-uniffi-kotlin.sh --skip-build
//   3. Set LD_LIBRARY_PATH to include the compiled library directory
//   4. Run: ./gradlew :scp-kt:test --tests "works.limn.scp.RealFFITest"
//
// Provenance: Phase D7 of the integration test plan, issue #453

package works.limn.scp

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Real FFI E2E tests for the Kotlin SDK.
 *
 * These tests attempt to load the UniFFI-generated native library and exercise
 * the full SDK through real Rust code. If the native library is not available,
 * all tests are skipped via JUnit 5 assumptions.
 *
 * When the native library IS available, these tests validate:
 * - Identity creation and lifecycle (DID generation)
 * - Context creation, join, leave, close
 * - Membership queries (count, is_member, member_dids, role)
 * - Tool registration and verification
 * - UCAN mint and revoke
 * - Event log query
 * - Discovery address parsing
 * - Provenance evaluation
 * - Bridge trust evaluation
 * - Sync classification
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RealFFITest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun checkNativeLibrary() {
            try {
                // Probe the UniFFI-generated top-level functions class.
                // UniFFI namespace "scp" generates package "uniffi.scp" and
                // a Kotlin file whose JVM class is "uniffi.scp.ScpKt".
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

    @BeforeEach
    fun assumeNativeAvailable() {
        assumeTrue(nativeAvailable, skipReason)
    }

    // ── Identity ─────────────────────────────────────────────────

    @Nested
    inner class IdentityTests {
        @Test
        fun `create identity with in-memory custody`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val identity = uniffi.scp.identityCreate("in_memory")
            val did = identity.did()
            assertTrue(did.startsWith("did:dht:"), "DID should start with did:dht:, got: $did")
            assertTrue(did.length > 20, "DID should be longer than 20 chars")
        }

        @Test
        fun `multiple identities have distinct DIDs`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val a = uniffi.scp.identityCreate("in_memory")
            val b = uniffi.scp.identityCreate("in_memory")
            assertNotEquals(a.did(), b.did())
        }

        @Test
        fun `reject unknown custody type`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val result = runCatching { uniffi.scp.identityCreate("magic") }
            assertTrue(result.isFailure, "identityCreate with unknown custody should throw")
        }
    }

    // ── Context ──────────────────────────────────────────────────

    @Nested
    inner class ContextTests {
        private fun ephemeralParams(
            ceiling: List<String> = listOf("messages:read"),
        ): uniffi.scp.ContextParams = uniffi.scp.ContextParams(
            ceiling = ceiling,
            governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
            memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
            ttlSeconds = 0uL,
            promotable = false,
            minProtocolVersion = 0u,
        )

        @Test
        fun `create context returns valid handle`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val identity = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(
                identity,
                ephemeralParams(listOf("messages:read", "messages:write")),
            )
            assertTrue(handle.contextId().isNotEmpty(), "Context ID should be non-empty")
        }

        @Test
        fun `join and leave context`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val bob = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(
                alice,
                ephemeralParams(
                    listOf(
                        "messages:read",
                        "messages:write",
                        "role:assign",
                        "member:invite",
                        "member:remove",
                    ),
                ),
            )

            uniffi.scp.contextJoin(handle, bob.did())
            assertEquals(2uL, uniffi.scp.contextMemberCount(handle), "count after join")
            assertTrue(uniffi.scp.contextIsMember(handle, bob.did()))
            val members = uniffi.scp.contextMemberDids(handle)
            assertTrue(members.contains(bob.did()), "Members should include bob")
            assertTrue(members.contains(alice.did()), "Members should include alice")

            uniffi.scp.contextLeave(handle, bob.did())
            assertEquals(1uL, uniffi.scp.contextMemberCount(handle), "count after leave")
            assertFalse(uniffi.scp.contextIsMember(handle, bob.did()))
        }

        @Test
        fun `close context`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(
                alice,
                ephemeralParams(listOf("messages:read", "context:close")),
            )
            uniffi.scp.contextClose(handle, alice.did())
            val state = handle.state()
            assertTrue(
                state == "closed" || state == "closing",
                "Context state after close should be closed or closing, got: $state",
            )
        }

        @Test
        fun `drain events returns list`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(alice, ephemeralParams())
            val events = uniffi.scp.contextDrainEvents(handle)
            assertNotNull(events)
        }
    }

    // ── Membership ─────────────────────────────────────────────

    @Nested
    inner class MembershipTests {
        private fun ephemeralParams(): uniffi.scp.ContextParams = uniffi.scp.ContextParams(
            ceiling = listOf("messages:read"),
            governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
            memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
            ttlSeconds = 0uL,
            promotable = false,
            minProtocolVersion = 0u,
        )

        @Test
        fun `member count after creation is 1`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(alice, ephemeralParams())
            assertEquals(1uL, uniffi.scp.contextMemberCount(handle))
        }

        @Test
        fun `creator is member`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(alice, ephemeralParams())
            assertTrue(uniffi.scp.contextIsMember(handle, alice.did()))
        }

        @Test
        fun `creator has admin role`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(alice, ephemeralParams())
            val role = uniffi.scp.contextMemberRole(handle, alice.did())
            assertNotNull(role, "Creator should have a role")
            assertTrue(
                role.lowercase().contains("admin"),
                "Creator role should contain 'admin', got: $role",
            )
        }

        @Test
        fun `member DIDs contains creator`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val handle = uniffi.scp.contextCreate(alice, ephemeralParams())
            val members = uniffi.scp.contextMemberDids(handle)
            assertTrue(members.contains(alice.did()), "Member DIDs should contain creator")
        }
    }

    // ── Tools ────────────────────────────────────────────────────

    @Nested
    inner class ToolTests {
        @Test
        fun `register and verify tool`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val params = uniffi.scp.ContextParams(
                ceiling = listOf("messages:read", "tool:invoke:*", "tool:register"),
                governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
                memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
                ttlSeconds = 0uL,
                promotable = false,
                minProtocolVersion = 0u,
            )
            val handle = uniffi.scp.contextCreate(alice, params)
            val toolDef = uniffi.scp.ToolDefinition(
                name = "test_tool",
                description = "A test tool",
                operatorDid = alice.did(),
                inputSchemaJson = """{"type":"object","properties":{"query":{"type":"string"}}}""",
                outputSchemaJson = """{"type":"object","properties":{"result":{"type":"string"}}}""",
                testVectorsJson = null,
                implementationHash = null,
            )
            val toolId = uniffi.scp.toolRegister(handle, toolDef)
            assertTrue(toolId.isNotEmpty(), "Tool ID should be non-empty")

            val result = uniffi.scp.toolVerify(handle, toolId)
            assertTrue(result.passed, "Tool verification should pass")
        }
    }

    // ── UCAN ─────────────────────────────────────────────────────

    @Nested
    inner class UcanTests {
        @Test
        fun `mint UCAN token`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val bob = uniffi.scp.identityCreate("in_memory")
            val params = uniffi.scp.ContextParams(
                ceiling = listOf("messages:read", "messages:write"),
                governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
                memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
                ttlSeconds = 0uL,
                promotable = false,
                minProtocolVersion = 0u,
            )
            val handle = uniffi.scp.contextCreate(alice, params)
            val token = uniffi.scp.ucanMint(handle, bob.did(), listOf("messages:read"))
            val tokenData = token.tokenData()
            assertNotNull(tokenData, "Token data should be non-null")
        }

        @Test
        fun `revoke UCAN token`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val params = uniffi.scp.ContextParams(
                ceiling = listOf("messages:read"),
                governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
                memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
                ttlSeconds = 0uL,
                promotable = false,
                minProtocolVersion = 0u,
            )
            val handle = uniffi.scp.contextCreate(alice, params)

            // Mint a token so the UCAN state is fully initialised for this context.
            val bob = uniffi.scp.identityCreate("in_memory")
            val token = uniffi.scp.ucanMint(handle, bob.did(), listOf("messages:read"))
            assertNotNull(token.tokenData(), "Minted token should have data")

            // Revoke a valid UCAN token. The revoker is the context creator.
            val testToken =
                "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9." +
                    "eyJpc3MiOiJkaWQ6ZGh0OnpUZXN0SXNzdWVyIiwiYXVkIjoiZGlkOmRodDp6TWVtYmVyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ." +
                    "dGVzdC1zaWduYXR1cmUtYnl0ZXMtMDAwMDAwMDAwMDAw"
            uniffi.scp.ucanRevoke(handle, testToken, alice.did())
        }
    }

    // ── Event Log ────────────────────────────────────────────────

    @Nested
    inner class EventLogTests {
        @Test
        fun `query returns events`() = runTest {
            assumeTrue(nativeAvailable, skipReason)
            val alice = uniffi.scp.identityCreate("in_memory")
            val params = uniffi.scp.ContextParams(
                ceiling = listOf("messages:read"),
                governance = uniffi.scp.GovernanceModel.SINGLE_ADMIN,
                memoryScope = uniffi.scp.MemoryScope.EPHEMERAL,
                ttlSeconds = 0uL,
                promotable = false,
                minProtocolVersion = 0u,
            )
            val handle = uniffi.scp.contextCreate(alice, params)
            val events = uniffi.scp.eventLogQuery(handle, null)
            assertNotNull(events)
        }
    }

    // ── Discovery ────────────────────────────────────────────────

    @Nested
    inner class DiscoveryTests {
        @Test
        fun `parse unscoped address`() {
            assumeTrue(nativeAvailable, skipReason)
            val result = uniffi.scp.discoveryParseAddress("alice")
            assertTrue(
                result.contains("Unscoped"),
                "Unscoped address should contain 'Unscoped', got: $result",
            )
        }

        @Test
        fun `parse discovery handle`() {
            assumeTrue(nativeAvailable, skipReason)
            val result = uniffi.scp.discoveryParseAddress("alice@cooking-ctx")
            assertTrue(
                result.contains("DiscoveryHandle") || result.contains("DomainHandle"),
                "Should parse to DiscoveryHandle or DomainHandle, got: $result",
            )
        }
    }

    // ── Provenance ───────────────────────────────────────────────

    @Nested
    inner class ProvenanceTests {
        @Test
        fun `evaluate quality returns valid score`() {
            assumeTrue(nativeAvailable, skipReason)
            val score = uniffi.scp.evaluateProvenanceQuality(
                null,
                "persistent",
                "active",
                emptyList(),
            )
            assertTrue(score in 0u..3u, "Provenance quality score should be 0-3, got: $score")
        }

        @Test
        fun `chain depth check`() {
            assumeTrue(nativeAvailable, skipReason)
            assertTrue(
                uniffi.scp.provenanceCheckChainDepth(3u, 5u),
                "Depth 3 should be within max 5",
            )
            assertFalse(
                uniffi.scp.provenanceCheckChainDepth(6u, 5u),
                "Depth 6 should exceed max 5",
            )
        }
    }

    // ── Bridge Trust ─────────────────────────────────────────────

    @Nested
    inner class BridgeTrustTests {
        @Test
        fun `native native trust level`() {
            assumeTrue(nativeAvailable, skipReason)
            val result = uniffi.scp.bridgeEvaluateTrust(false, true, "shadow")
            assertEquals(3.toUByte(), result, "Non-bridged, native -> NativeNative (3)")
        }

        @Test
        fun `shadow bridged trust level`() {
            assumeTrue(nativeAvailable, skipReason)
            val result = uniffi.scp.bridgeEvaluateTrust(true, false, "shadow")
            assertEquals(0.toUByte(), result, "Bridged, non-native, shadow -> ShadowBridged (0)")
        }

        @Test
        fun `claimed bridged trust level`() {
            assumeTrue(nativeAvailable, skipReason)
            val result = uniffi.scp.bridgeEvaluateTrust(true, false, "claimed")
            assertEquals(1.toUByte(), result, "Bridged, non-native, claimed -> ClaimedBridged (1)")
        }
    }

    // ── Sync ─────────────────────────────────────────────────────

    @Nested
    inner class SyncTests {
        @Test
        fun `classify short offline`() {
            assumeTrue(nativeAvailable, skipReason)
            val now = 1_000_000uL
            val lastSeen = now - 3600uL
            assertEquals("short", uniffi.scp.syncClassifyOffline(lastSeen, now))
        }

        @Test
        fun `classify extended offline`() {
            assumeTrue(nativeAvailable, skipReason)
            val now = 1_000_000uL
            val lastSeen = now - 86400uL
            assertEquals("extended", uniffi.scp.syncClassifyOffline(lastSeen, now))
        }

        @Test
        fun `classify long offline`() {
            assumeTrue(nativeAvailable, skipReason)
            val now = 2_000_000uL
            val lastSeen = now - 1_000_000uL
            assertEquals("long", uniffi.scp.syncClassifyOffline(lastSeen, now))
        }
    }
}
