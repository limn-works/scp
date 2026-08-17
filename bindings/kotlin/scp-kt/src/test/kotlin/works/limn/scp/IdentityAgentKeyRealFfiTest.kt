// IdentityAgentKeyRealFfiTest.kt — real-FFI coverage for the five advanced
// identity operations the SDK capability matrix claims for Kotlin.
//
// The matrix rows `Identity/create_with_agent_key`, `Identity/add_agent_key`,
// `Identity/rotate_agent_key`, `Identity/remove_agent_key`, and
// `Identity/migrate` all carry `"kotlin": true` in
// `.docs/standards/sdk-capability-matrix.json`. This suite calls all five
// through the public `SCP` class against the compiled UniFFI cdylib, so a
// claimed cell that no production Kotlin code can reach fails here instead of
// passing a name-existence check.
//
// No stub or fake implements any binding in this file. `SCP(StorageConfig)`
// wraps the UniFFI-generated `uniffi.scp.Scp` object directly, and the
// assertions read state back off the returned `uniffi.scp.Identity` handles.
//
// Every test method here uses a BLOCK body, not an `= runBlocking { ... }`
// expression body. JUnit 5 refuses to execute a `@Test` method that returns a
// value, and `kotlin.test.assertNotNull` returns its argument — so an
// expression-bodied test whose last statement is `assertNotNull(...)` compiles,
// reports no failure, and never runs. A block body pins the return type to
// `Unit` and makes that whole class of silent skip impossible.
//
// Provenance: ADR-039 (shared-DID agent binding), ADR-048 (caller-owned SCP
// instance), spec §9.12 and ADR-003 §4b (DID rotation event distribution),
// Alec's ruling of 2026-08-17 on the Kotlin identity-advanced cells.

package works.limn.scp

import uniffi.scp.Identity
import uniffi.scp.StorageConfig
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class IdentityAgentKeyRealFfiTest {
    companion object {
        private var nativeAvailable = false
        private var skipReason = ""

        @JvmStatic
        @BeforeAll
        fun probeNativeLibrary() {
            try {
                Class.forName("uniffi.scp.ScpKt")
                Class.forName("uniffi.scp.Scp\$Companion")
                nativeAvailable = true
            } catch (e: ClassNotFoundException) {
                skipReason = "UniFFI bindings not available: ${e.message}"
            } catch (e: UnsatisfiedLinkError) {
                skipReason = "Native library link error: ${e.message}"
            } catch (e: ExceptionInInitializerError) {
                skipReason = "Native library init error: ${e.cause?.message ?: e.message}"
            } catch (e: NoClassDefFoundError) {
                skipReason = "Native library class not found: ${e.message}"
            }
        }
    }

    private lateinit var scp: SCP

    @BeforeEach
    fun setUp() {
        assumeTrue(nativeAvailable, skipReason)
        scp = SCP(StorageConfig.InMemory)
    }

    @AfterEach
    fun tearDown() {
        if (!this::scp.isInitialized) return
        // Teardown calls the UniFFI shutdown directly rather than
        // `SCP.shutdown(bridge, timeout)`, because that overload needs a
        // `CoroutineBridge`, and constructing one needs a `NativeBindings`
        // that only the test source set implements. This suite must reach the
        // five operations under test without a test double, so it takes the
        // bridge-free teardown path.
        runBlocking { scp.inner.shutdown(timeoutMillis = SHUTDOWN_TIMEOUT_MILLIS) }
    }

    private suspend fun freshIdentity(): Identity = scp.identityCreate(custody = "in_memory")

    // ── Identity/create_with_agent_key ────────────────────────────

    @Test
    fun `identityCreateWithAgentKey mints an identity that already carries an agent key`() {
        runBlocking {
            val identity = scp.identityCreateWithAgentKey(custody = "in_memory")

            assertTrue(
                identity.hasAgentKey(),
                "identityCreateWithAgentKey must return a handle whose retained ScpIdentity holds an agent key",
            )
            assertNotNull(
                identity.getAgentPublicKey(),
                "the returned DID document must expose the #agent verification method's public key",
            )
        }
    }

    // ── Identity/add_agent_key ────────────────────────────────────

    @Test
    fun `identityAddAgentKey adds an agent key to an identity created without one`() {
        runBlocking {
            val plain = freshIdentity()
            assertFalse(plain.hasAgentKey(), "identityCreate must mint an identity with no agent key")

            val withAgentKey = scp.identityAddAgentKey(plain)

            assertTrue(withAgentKey.hasAgentKey(), "identityAddAgentKey must return a handle holding an agent key")
            assertNotNull(
                withAgentKey.getAgentPublicKey(),
                "identityAddAgentKey must write the #agent verification method into the DID document",
            )
            assertEquals(
                plain.did(),
                withAgentKey.did(),
                "adding an agent key must keep the same DID — it rewrites the document, it does not migrate",
            )
        }
    }

    // ── Identity/rotate_agent_key ─────────────────────────────────

    @Test
    fun `identityRotateAgentKey replaces the agent public key and keeps the DID`() {
        runBlocking {
            val withAgentKey = scp.identityCreateWithAgentKey(custody = "in_memory")
            val originalAgentKey = assertNotNull(withAgentKey.getAgentPublicKey())

            val rotated = scp.identityRotateAgentKey(withAgentKey)

            assertTrue(
                rotated.hasAgentKey(),
                "identityRotateAgentKey must return a handle that still holds an agent key",
            )
            assertNotEquals(
                originalAgentKey,
                rotated.getAgentPublicKey(),
                "identityRotateAgentKey must generate a new #agent keypair, not reuse the old one",
            )
            assertEquals(withAgentKey.did(), rotated.did(), "rotating the agent key must keep the same DID")
        }
    }

    // ── Identity/remove_agent_key ─────────────────────────────────

    @Test
    fun `identityRemoveAgentKey drops the agent key from an identity that has one`() {
        runBlocking {
            val withAgentKey = scp.identityCreateWithAgentKey(custody = "in_memory")
            assertTrue(withAgentKey.hasAgentKey())

            val removed = scp.identityRemoveAgentKey(withAgentKey)

            assertFalse(removed.hasAgentKey(), "identityRemoveAgentKey must return a handle with no agent key")
            assertEquals(withAgentKey.did(), removed.did(), "removing the agent key must keep the same DID")
        }
    }

    // ── Identity/migrate ──────────────────────────────────────────

    @Test
    fun `identityMigrate returns a new DID and the rotation event callers must distribute`() {
        runBlocking {
            val original = freshIdentity()
            val originalDid = original.did()

            val migrated = scp.identityMigrate(original)

            assertNotEquals(originalDid, migrated.did(), "identityMigrate must mint a new DID")
            val rotationEvent = assertNotNull(
                migrated.rotationEventJson(),
                "spec §9.12 and ADR-003 §4b require a DidRotationEvent that the caller distributes to active contexts",
            )
            assertTrue(
                rotationEvent.contains(originalDid),
                "the rotation event must name the OLD DID so peers can re-bind the membership",
            )
        }
    }
}

/** Teardown deadline for the UniFFI shutdown, in milliseconds. */
private const val SHUTDOWN_TIMEOUT_MILLIS: ULong = 1_000u
