// ReadmeQuickStartTest.kt — proves that the quick start in
// `bindings/kotlin/README.md` compiles and runs.
//
// Kotlin cannot compile a README block at test time, so `ReadmeQuickStart.kt`
// in this package holds a copy that the test source set compiles. The first
// test fails when that copy and the README block differ, and the second runs
// the copy's `main()`. Together they turn an edit that breaks the README block
// red: the edit either diverges from the copy or, applied to both, stops
// compiling or throws.
//
// The block uses `CustodyType.IN_MEMORY`, which only a native library built with
// the `testing` feature accepts; the test task builds it with
// `-Pscp.uniffi.cargoFeatures=testing`, as CI does. A native library that is
// absent or fails to load fails the run test, matching ScpClassTest.

package works.limn.scp.quickstart

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertEquals

class ReadmeQuickStartTest {
    // Gradle runs tests with the `scp-kt` project directory as `user.dir`.
    private val projectDir = File(System.getProperty("user.dir"))

    @Test
    fun `README block extraction reads the block under the heading`() {
        val text =
            "# T\n\n```kotlin\nbefore()\n```\n\n## Quick Start\n\nProse.\n\n" +
                "```kotlin\nquick()\n```\n\n```kotlin\nafter()\n```\n"
        assertEquals("quick()\n", readmeBlock(text))
    }

    @Test
    fun `the copy matches the README Quick Start block`() {
        val readme = projectDir.resolve("../README.md").canonicalFile.readText()
        val copy =
            projectDir
                .resolve("src/test/kotlin/works/limn/scp/quickstart/ReadmeQuickStart.kt")
                .readText()
        assertEquals(
            readmeBlock(readme),
            copyBody(copy),
            "ReadmeQuickStart.kt must match the README Quick Start block byte for byte",
        )
    }

    @Test
    fun `the README quick start runs`() {
        runBlocking { main() }
    }

    private companion object {
        const val HEADING = "\n## Quick Start\n"
        const val FENCE_OPEN = "```kotlin\n"
        const val FENCE_CLOSE = "\n```\n"
        const val PACKAGE_LINE = "package works.limn.scp.quickstart\n\n"

        /** Returns the first `kotlin` block under the README's Quick Start heading. */
        fun readmeBlock(readme: String): String {
            check(HEADING in readme) { "the README has no '## Quick Start' heading" }
            val afterHeading = readme.substringAfter(HEADING)
            check(FENCE_OPEN in afterHeading) { "the Quick Start section has no kotlin block" }
            val body = afterHeading.substringAfter(FENCE_OPEN)
            check(FENCE_CLOSE in body) { "the Quick Start kotlin block has no closing fence" }
            return body.substringBefore(FENCE_CLOSE) + "\n"
        }

        /** Returns `ReadmeQuickStart.kt` from just after its package line. */
        fun copyBody(source: String): String {
            check(PACKAGE_LINE in source) { "ReadmeQuickStart.kt has no package line" }
            return source.substringAfter(PACKAGE_LINE)
        }
    }
}
