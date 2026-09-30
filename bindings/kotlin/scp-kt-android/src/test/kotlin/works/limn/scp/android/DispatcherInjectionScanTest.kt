// DispatcherInjectionScanTest.kt — no SDK source dispatches onto a hardcoded Dispatchers.IO
//
// ADR-028 acceptance criterion 6: every FFI call and every subscription release runs on an
// injected `ioDispatcher`, so a test can substitute a `StandardTestDispatcher`. This test reads
// the `scp-kt` and `scp-kt-android` main sources and fails on any `withContext(...)` whose
// context names `Dispatchers.IO`. Comments are stripped first, so KDoc that names the default
// does not count. The `platform` package is not scanned: its adapters call Play Integrity and
// Firebase, never the SCP FFI, so criterion 6 does not bind them. The generated UniFFI bindings
// under `internal/uniffi` are not scanned, because the SDK does not author them.
//
// Provenance: ADR-028 acceptance criterion 6, SCP-117

package works.limn.scp.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class DispatcherInjectionScanTest {
    @Test
    fun `no scp-kt or scp-kt-android main source dispatches onto a hardcoded Dispatchers IO`() {
        val offenders = scannedSources().flatMap { file ->
            hardcodedIoDispatches(file.readText()).map { "${file.path}: $it" }
        }
        assertEquals(
            "these sources name Dispatchers.IO in withContext instead of the injected ioDispatcher",
            emptyList<String>(),
            offenders,
        )
    }

    @Test
    fun `the scan reaches both modules' main sources`() {
        val paths = scannedSources().map { it.invariantSeparatorsPath }
        assertTrue("the scan read no scp-kt source", paths.any { it.endsWith("works/limn/scp/stream/Streams.kt") })
        assertTrue(
            "the scan read no scp-kt-android source",
            paths.any { it.endsWith("works/limn/scp/android/compose/StateHolders.kt") },
        )
    }

    @Test
    fun `the scan flags a planted hardcoded dispatch in each form`() {
        val planted =
            """
            suspend fun a() = withContext(Dispatchers.IO) { call() }
            suspend fun b() = withContext(NonCancellable + Dispatchers.IO) { release() }
            suspend fun c() = withContext(
                kotlinx.coroutines.Dispatchers.IO,
            ) { call() }
            """.trimIndent()
        assertEquals(3, hardcodedIoDispatches(planted).size)
    }

    @Test
    fun `the scan passes injected dispatchers, defaults, and comments`() {
        val clean =
            """
            // `withContext(Dispatchers.IO)` is what this class avoids.
            /** Runs on [Dispatchers.IO] by default; never `withContext(Dispatchers.IO)`. */
            class A(private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO) {
                suspend fun a() = withContext(ioDispatcher) { call() }
                suspend fun b() = withContext(NonCancellable + ioDispatcher) { release() }
            }
            """.trimIndent()
        assertEquals(emptyList<String>(), hardcodedIoDispatches(clean))
    }

    private fun scannedSources(): List<File> {
        val kotlinRoot = locateKotlinRoot()
        return listOf("scp-kt", "scp-kt-android").flatMap { module ->
            val main = File(kotlinRoot, "$module/src/main/kotlin")
            main.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filterNot { file ->
                    val relative = file.relativeTo(main).invariantSeparatorsPath
                    relative.startsWith("works/limn/scp/android/platform/") ||
                        relative.startsWith("works/limn/scp/internal/uniffi/")
                }
                .toList()
        }
    }

    private fun locateKotlinRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate: File = dir
            val holdsBothModules =
                listOf("scp-kt", "scp-kt-android").all { File(candidate, "$it/src/main/kotlin").isDirectory }
            if (holdsBothModules) return candidate
            dir = candidate.parentFile
        }
        error("could not locate bindings/kotlin from ${System.getProperty("user.dir")}")
    }

    private companion object {
        val BLOCK_COMMENT = Regex("""/\*[\s\S]*?\*/""")
        val LINE_COMMENT = Regex("""//[^\n]*""")
        val HARDCODED_IO_DISPATCH = Regex("""withContext\s*\([^)]*?\bDispatchers\.IO\b""")

        /** Every `withContext(...)` in [source] whose context names `Dispatchers.IO`, after comments are removed. */
        fun hardcodedIoDispatches(source: String): List<String> {
            // A block comment becomes a space, so the code on either side of it stays apart.
            val code = source.replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, "")
            return HARDCODED_IO_DISPATCH.findAll(code).map { it.value.replace(Regex("""\s+"""), " ") }.toList()
        }
    }
}
