// RealFFITest.kt — Phase D7: Real FFI E2E tests for the Kotlin SDK
//
// STATUS: Test bodies are not yet implemented — requires UniFFI native library.
// Each test documents the planned assertion via comments but does not execute
// real FFI calls. The class is @Disabled until the native library build pipeline
// is operational (cargo build cdylib → generateUniffiBindings → link).
//
// Prerequisites:
//   1. Build the Rust cdylib: cargo build -p scp-ffi-uniffi --features allow_in_memory_custody
//   2. Generate Kotlin bindings: ./gradlew :scp-kt:generateUniffiBindings
//   3. Run: ./gradlew :scp-kt:test --tests "works.limn.scp.RealFFITest"
//
// Provenance: Phase D7 of the integration test plan

package works.limn.scp

import works.limn.scp.bridge.BridgeException
import works.limn.scp.bridge.CoroutineBridge
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
 * - Identity creation and lifecycle (DID generation, agent keys)
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
@Disabled("Test bodies not yet implemented — requires UniFFI native library build pipeline")
class RealFFITest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun checkNativeLibrary() {
            try {
                // Attempt to load the UniFFI-generated native library.
                // This will fail if the cdylib hasn't been compiled or
                // the Kotlin bindings haven't been generated.
                Class.forName("works.limn.scp.internal.NativeLib")
                nativeAvailable = true
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI native library not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: Exception) {
                skipReason = "Native library load failed: ${e.message}"
            }
        }
    }

    @BeforeEach
    fun assumeNativeAvailable() {
        assumeTrue(nativeAvailable, skipReason)
    }

    // When native bindings are available, these tests will exercise the real FFI.
    // Until then, they serve as the test specification for D7.

    @Nested
    inner class IdentityTests {
        @Test
        fun `create identity with in-memory custody`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Will call: bridge.identity.create("in_memory")
                // Assert: returned handle > 0, DID starts with "did:dht:"
            }

        @Test
        fun `multiple identities have distinct DIDs`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create two identities, assert DIDs differ
            }

        @Test
        fun `reject unknown custody type`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Assert: bridge.identity.create("magic") throws BridgeException
            }
    }

    @Nested
    inner class ContextTests {
        @Test
        fun `create context returns valid handle`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create identity, then context with ceiling ["messages:read"]
                // Assert: handle > 0
            }

        @Test
        fun `join and leave context`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create alice + bob, alice creates context, bob joins
                // Assert: member count == 2, bob is member
                // Bob leaves, assert: member count == 1, bob not member
            }

        @Test
        fun `close context`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create context with context:close capability
                // Close it, verify state
            }

        @Test
        fun `drain events returns list`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create context, drain events
                // Assert: result is valid (may be empty for fresh context)
            }
    }

    @Nested
    inner class MembershipTests {
        @Test
        fun `member count after creation is 1`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
            }

        @Test
        fun `creator is member`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
            }

        @Test
        fun `creator has admin role`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
            }

        @Test
        fun `member DIDs contains creator`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
            }
    }

    @Nested
    inner class ToolTests {
        @Test
        fun `register and verify tool`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Register tool with valid schema (2+ properties)
                // Verify: result.passed == true
            }
    }

    @Nested
    inner class UcanTests {
        @Test
        fun `mint UCAN token`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Mint token granting messages:read to audience
                // Assert: token string is non-empty
            }

        @Test
        fun `revoke UCAN token`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Mint then revoke
            }
    }

    @Nested
    inner class EventLogTests {
        @Test
        fun `query returns events`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Create context, query event log
                // Assert: result is valid JSON
            }
    }

    @Nested
    inner class DiscoveryTests {
        @Test
        fun `parse unscoped address`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Parse "alice" -> type == "unscoped"
            }

        @Test
        fun `parse discovery handle`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Parse "alice@cooking-ctx" -> discovery_handle or domain_handle
            }
    }

    @Nested
    inner class ProvenanceTests {
        @Test
        fun `evaluate quality returns valid score`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Evaluate with source_type "persistent", state "active"
                // Assert: score in 0..3
            }

        @Test
        fun `chain depth check`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // depth 3, max 5 -> true
                // depth 6, max 5 -> false
            }
    }

    @Nested
    inner class BridgeTrustTests {
        @Test
        fun `native native trust level`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Not bridged, native transport -> NativeNative (3)
            }

        @Test
        fun `shadow bridged trust level`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Bridged, non-native, shadow -> ShadowBridged (0)
            }

        @Test
        fun `claimed bridged trust level`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Bridged, non-native, claimed -> ClaimedBridged (1)
            }
    }

    @Nested
    inner class SyncTests {
        @Test
        fun `classify short offline`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // 1 hour offline -> "short"
            }

        @Test
        fun `classify extended offline`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // 1 day offline -> "extended"
            }

        @Test
        fun `classify long offline`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // 11 days offline -> "long"
            }

        @Test
        fun `get default sync policy`() =
            runTest {
                assumeTrue(nativeAvailable, skipReason)
                // Assert: policy has tier thresholds
            }
    }
}
