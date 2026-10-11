// ReadmeQuickStartTest.kt — proves that the code examples in
// `bindings/kotlin/README.md` compile and run.
//
// Kotlin cannot compile a README block at test time, so `ReadmeQuickStart.kt`
// and `ReadmeErrorHandling.kt` in this package hold copies that the test source
// set compiles. The copy tests fail when a copy and its README block differ,
// and the run tests call each copy. Together they turn an edit that breaks a
// README block red: the edit either diverges from the copy or, applied to both,
// stops compiling or misbehaves. The test task declares `README.md` as an
// input, so an edit to the README alone reruns these tests.
//
// The quick start uses `CustodyType.ENCRYPTED_FILE`, for which a native library
// built without the `testing` feature has no pre-rotation custody backend
// (`SCP-IDENT-1059`); the test task builds it with
// `-Pscp.uniffi.cargoFeatures=testing`, as CI does, and the run test points
// `HOME` and `SCP_KEY_PASSPHRASE` at a temporary key file. The error-handling
// test creates its identity through the test-harness in-memory key store
// (`TestHarnessCustody.kt`). A native library that is absent or fails to load
// fails the run tests, matching ScpClassTest.

package works.limn.scp.quickstart

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import uniffi.scp.CeilingPolicy
import uniffi.scp.ContextMode
import uniffi.scp.ContextParams
import uniffi.scp.GovernanceModel
import uniffi.scp.MemoryScope
import uniffi.scp.StorageConfig
import works.limn.scp.SCP
import works.limn.scp.identityCreateInMemory
import works.limn.scp.withKeyFileEnvironment
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ReadmeQuickStartTest {
    // Gradle runs tests with the `scp-kt` project directory as `user.dir`.
    private val projectDir = File(System.getProperty("user.dir"))

    @Test
    fun `README block extraction reads the block under the heading`() {
        val text =
            "# T\n\n```kotlin\nbefore()\n```\n\n### Quick Start\n\n```kotlin\nh3()\n```\n\n" +
                "## Quick Start\n\nProse.\n\n```kotlin\nquick()\n```\n\n```kotlin\nafter()\n```\n"
        assertEquals("quick()\n", readmeBlock(text, QUICK_START))
    }

    @Test
    fun `the copy matches the README Quick Start block`() {
        assertCopyMatchesReadme("ReadmeQuickStart.kt", QUICK_START)
    }

    @Test
    fun `the error handling copy matches the README Error Handling block`() {
        assertCopyMatchesReadme("ReadmeErrorHandling.kt", ERROR_HANDLING)
    }

    @Test
    fun `the README quick start runs`(
        @TempDir home: File,
    ) {
        withKeyFileEnvironment(home, "kotlin-readme-quick-start") {
            runBlocking { main() }
        }
        val keyFile = File(home, ".scp/keys.bin")
        assertTrue(keyFile.isFile, "the quick start wrote no key file at ${keyFile.path}")
    }

    // The README function returns a code only from its `catch (e: ScpException.Context)`
    // clause, and any other exception propagates, so an `SCP-CTX-` code proves that
    // clause caught the send to a closed context.
    @Test
    fun `the README error handling catches the context exception`() {
        runBlocking {
            val scp = SCP(StorageConfig.InMemory)
            val identity = scp.identityCreateInMemory()
            val ctx = scp.contextCreate(identity = identity, params = contextParams())
            scp.contextClose(handle = ctx, identity = identity)

            val code =
                sendReportingRejection(
                    scp = scp,
                    ctx = ctx,
                    identity = identity,
                    payload = "late".toByteArray(),
                )

            val rejected = assertNotNull(code, "a send to a closed context succeeded")
            assertTrue(rejected.startsWith("SCP-CTX-"), "unexpected code $rejected")
        }
    }

    private fun assertCopyMatchesReadme(
        copyFile: String,
        heading: String,
    ) {
        val readme = projectDir.resolve("../README.md").canonicalFile.readText()
        val copy = projectDir.resolve("src/test/kotlin/works/limn/scp/quickstart/$copyFile").readText()
        assertEquals(
            readmeBlock(readme, heading),
            copyBody(copy, copyFile),
            "$copyFile must match the README $heading block byte for byte",
        )
    }

    private companion object {
        const val QUICK_START = "Quick Start"
        const val ERROR_HANDLING = "Error Handling"
        const val FENCE_OPEN = "```kotlin\n"
        const val FENCE_CLOSE = "\n```\n"
        const val PACKAGE_LINE = "package works.limn.scp.quickstart\n\n"

        /** Returns the first `kotlin` block under the README's `## [heading]` line. */
        fun readmeBlock(
            readme: String,
            heading: String,
        ): String {
            val marker = "\n## $heading\n"
            check(marker in readme) { "the README has no '## $heading' heading" }
            val afterHeading = readme.substringAfter(marker)
            check(FENCE_OPEN in afterHeading) { "the $heading section has no kotlin block" }
            val body = afterHeading.substringAfter(FENCE_OPEN)
            check(FENCE_CLOSE in body) { "the $heading kotlin block has no closing fence" }
            return body.substringBefore(FENCE_CLOSE) + "\n"
        }

        /** Returns a copy file from just after its package line. */
        fun copyBody(
            source: String,
            copyFile: String,
        ): String {
            check(PACKAGE_LINE in source) { "$copyFile has no package line" }
            return source.substringAfter(PACKAGE_LINE)
        }

        fun contextParams() =
            ContextParams(
                mode = ContextMode.ENCRYPTED,
                ceiling = listOf("messages:read", "messages:write", "context:close"),
                ceilingPolicy = CeilingPolicy.IMMUTABLE,
                governance = GovernanceModel.SINGLE_ADMIN,
                memoryScope = MemoryScope.EPHEMERAL,
                ttlSeconds = 3600uL,
                promotable = false,
                minProtocolVersion = 0.toUShort(),
                maxChainDepth = null,
                maxNestingDepth = null,
                sessionCap = null,
                economicPolicy = null,
                consequenceRulesJson = null,
                consequenceConfigJson = null,
            )
    }
}
