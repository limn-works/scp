// DispatcherInjectionScanTest.kt — no SDK source dispatches onto a hardcoded Dispatchers.IO
//
// ADR-028 acceptance criterion 6: every FFI call and every subscription release that SDK code
// dispatches runs on an injected `ioDispatcher`, so a test can substitute a
// `StandardTestDispatcher`. This test reads the `scp-kt` and `scp-kt-android` main sources and
// fails on any `withContext(...)` call whose first argument, the coroutine context, names
// `Dispatchers.IO`. A lexer removes comments (nested block comments included) and the content of
// string and character literals first, so KDoc that names the default and a string holding `//`
// or `/*` neither counts nor hides code; a string template's `${...}` expression stays code. Two
// files are not scanned, because neither calls the SCP FFI: `platform/AndroidDeviceAttestation.kt`
// dispatches only the Play Integrity token request, and `platform/AndroidPushProvider.kt` only the
// Firebase token request. The generated UniFFI bindings under `internal/uniffi` are not scanned,
// because the SDK does not author them.
//
// Provenance: ADR-028 acceptance criterion 6, SCP-117

package works.limn.scp.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun `the scan reaches both modules' main sources and skips only the two named platform files`() {
        val kotlinRoot = locateKotlinRoot()
        val paths = scannedSources().map { it.invariantSeparatorsPath }
        assertTrue("the scan read no scp-kt source", paths.any { it.endsWith("works/limn/scp/stream/Streams.kt") })
        assertTrue(
            "the scan read no scp-kt-android source",
            paths.any { it.endsWith("works/limn/scp/android/compose/StateHolders.kt") },
        )
        assertTrue(
            "the scan skipped a platform file outside the two named exclusions",
            paths.any { it.endsWith("works/limn/scp/android/platform/AndroidStorage.kt") } &&
                paths.any { it.endsWith("works/limn/scp/android/platform/AndroidKeyCustody.kt") },
        )
        for (excluded in EXCLUDED_FILES) {
            assertTrue(
                "the exclusion $excluded names no file",
                File(kotlinRoot, "scp-kt-android/src/main/kotlin/$excluded").isFile,
            )
            assertFalse("the scan read the excluded $excluded", paths.any { it.endsWith(excluded) })
        }
    }

    @Test
    fun `the scan flags a planted hardcoded dispatch in each form`() {
        val planted =
            listOf(
                "suspend fun a() = withContext(Dispatchers.IO) { call() }",
                "suspend fun b() = withContext(NonCancellable + Dispatchers.IO) { release() }",
                "suspend fun c() = withContext(\n    kotlinx.coroutines.Dispatchers.IO,\n) { call() }",
                // A call inside the context expression puts a ')' before Dispatchers.IO.
                "suspend fun d() = withContext(CoroutineName(\"release\") + Dispatchers.IO) { call() }",
                "suspend fun e() = withContext(SupervisorJob() + Dispatchers.IO) { call() }",
                "suspend fun f() = withContext<Unit>(Dispatchers . IO) { call() }",
                // A comment opener inside a string literal must not hide the code after it.
                "val u = \"https://x\"; suspend fun g() = withContext(Dispatchers.IO) { call() }",
                "val s = \"/*\"; suspend fun h() = withContext(Dispatchers.IO) { call() }; val t = \"*/\"",
                "val r = \"\"\"// raw\"\"\"; suspend fun i() = withContext(Dispatchers.IO) { call() }",
                "val q = '\"'; suspend fun j() = withContext(Dispatchers.IO) { call() }; val w = \"x\"",
                // Kotlin block comments nest, so the code after the outer close is live.
                "/* outer /* inner */ still comment */ suspend fun k() = withContext(Dispatchers.IO) { call() }",
                // A string template's expression is code.
                "val m = \"\${withContext(Dispatchers.IO) { call() }}\"",
            )
        for (source in planted) {
            assertEquals("the scan missed: $source", 1, hardcodedIoDispatches(source).size)
        }
    }

    @Test
    fun `the scan passes injected dispatchers, defaults, comments, and string content`() {
        val clean =
            listOf(
                "// `withContext(Dispatchers.IO)` is what this class avoids.",
                "/** Runs on [Dispatchers.IO] by default; never `withContext(Dispatchers.IO)`. */",
                "class A(private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO)",
                "suspend fun a() = withContext(ioDispatcher) { call() }",
                "suspend fun b() = withContext(NonCancellable + ioDispatcher) { release() }",
                "suspend fun c() = withContext(CoroutineName(\"x\") + ioDispatcher) { call() }",
                // Dispatchers.IO in the block, not the context, is not a dispatch onto it.
                "suspend fun d() = withContext(ioDispatcher) { log(Dispatchers.IO) }",
                "val s = \"withContext(Dispatchers.IO)\"",
                "val r = \"\"\"withContext(Dispatchers.IO)\"\"\"",
                "/* outer /* withContext(Dispatchers.IO) */ withContext(Dispatchers.IO) */",
            )
        for (source in clean) {
            assertEquals("the scan flagged: $source", emptyList<String>(), hardcodedIoDispatches(source))
        }
    }

    private fun scannedSources(): List<File> {
        val kotlinRoot = locateKotlinRoot()
        return listOf("scp-kt", "scp-kt-android").flatMap { module ->
            val main = File(kotlinRoot, "$module/src/main/kotlin")
            main.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filterNot { file ->
                    val relative = file.relativeTo(main).invariantSeparatorsPath
                    relative in EXCLUDED_FILES || relative.startsWith("works/limn/scp/internal/uniffi/")
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
        /** Main sources, relative to `scp-kt-android/src/main/kotlin`, that dispatch no SCP FFI call. */
        val EXCLUDED_FILES =
            setOf(
                "works/limn/scp/android/platform/AndroidDeviceAttestation.kt",
                "works/limn/scp/android/platform/AndroidPushProvider.kt",
            )
        val WITH_CONTEXT_CALL = Regex("""\bwithContext\s*(?:<[^()]*?>\s*)?\(""")
        val DISPATCHERS_IO = Regex("""\bDispatchers\s*\.\s*IO\b""")
        val WHITESPACE = Regex("""\s+""")
        const val OPENERS = "([{"
        const val CLOSERS = ")]}"

        /** Every `withContext(...)` in [source] whose context argument names `Dispatchers.IO`. */
        fun hardcodedIoDispatches(source: String): List<String> {
            val code = codeOnly(source)
            return WITH_CONTEXT_CALL.findAll(code).mapNotNull { call ->
                val context = contextArgument(code, call.range.last + 1)
                if (DISPATCHERS_IO.containsMatchIn(context)) {
                    "withContext(${context.trim().replace(WHITESPACE, " ")})"
                } else {
                    null
                }
            }.toList()
        }

        /** The text from [start] to the `,` or `)` that closes the first argument of a call. */
        fun contextArgument(code: String, start: Int): String {
            var depth = 0
            for (i in start until code.length) {
                val c = code[i]
                if (depth == 0 && (c in CLOSERS || c == ',')) return code.substring(start, i)
                if (c in OPENERS) depth++
                if (c in CLOSERS) depth--
            }
            return code.substring(start)
        }

        /**
         * [source] with each comment replaced by a space and the content of each string and
         * character literal removed. A string template's `${...}` expression is kept as code.
         */
        fun codeOnly(source: String): String = CodeOnlyLexer(source).run()
    }
}

/** Strips comments and literal content from Kotlin source for [DispatcherInjectionScanTest]. */
private class CodeOnlyLexer(private val source: String) {
    private val out = StringBuilder(source.length)

    // Open literals and template expressions, innermost last. A string frame holds RAW or
    // PLAIN; a template frame holds its current brace depth, 0 or more.
    private val frames = ArrayDeque<Int>()
    private var i = 0

    fun run(): String {
        while (i < source.length) {
            val top = frames.lastOrNull()
            if (top == RAW || top == PLAIN) stringStep(top) else codeStep(top)
        }
        return out.toString()
    }

    private fun stringStep(kind: Int) {
        when {
            source.startsWith("\${", i) -> {
                frames.addLast(0)
                out.append(' ')
                i += 2
            }
            kind == PLAIN && source[i] == '\\' -> i += 2
            kind == PLAIN && source[i] == '"' -> {
                frames.removeLast()
                out.append('"')
                i++
            }
            kind == RAW && source.startsWith(TRIPLE_QUOTE, i) -> {
                // The last three quotes of a run close a raw string.
                while (i < source.length && source[i] == '"') i++
                frames.removeLast()
                out.append(TRIPLE_QUOTE)
            }
            else -> i++
        }
    }

    private fun codeStep(templateDepth: Int?) {
        val c = source[i]
        when {
            source.startsWith("/*", i) -> skipBlockComment()
            source.startsWith("//", i) -> {
                while (i < source.length && source[i] != '\n') i++
            }
            source.startsWith(TRIPLE_QUOTE, i) -> {
                frames.addLast(RAW)
                out.append(TRIPLE_QUOTE)
                i += TRIPLE_QUOTE.length
            }
            c == '"' -> {
                frames.addLast(PLAIN)
                out.append('"')
                i++
            }
            // A backtick identifier may hold an apostrophe, which does not open a character literal.
            c == '`' -> skipQuoted('`', "`_`")
            c == '\'' -> skipQuoted('\'', "' '")
            templateDepth == 0 && c == '}' -> {
                frames.removeLast()
                out.append(' ')
                i++
            }
            else -> {
                if (templateDepth != null && c == '{') frames[frames.lastIndex] = templateDepth + 1
                if (templateDepth != null && c == '}') frames[frames.lastIndex] = templateDepth - 1
                out.append(c)
                i++
            }
        }
    }

    // Kotlin block comments nest, so a comment ends where its nesting depth returns to zero.
    private fun skipBlockComment() {
        var depth = 0
        do {
            when {
                source.startsWith("/*", i) -> {
                    depth++
                    i += 2
                }
                source.startsWith("*/", i) -> {
                    depth--
                    i += 2
                }
                else -> i++
            }
        } while (depth > 0 && i < source.length)
        out.append(' ')
    }

    private fun skipQuoted(quote: Char, placeholder: String) {
        i++
        while (i < source.length && source[i] != quote) i += if (source[i] == '\\') 2 else 1
        out.append(placeholder)
        i++
    }

    private companion object {
        const val RAW = -1
        const val PLAIN = -2
        const val TRIPLE_QUOTE = "\"\"\""
    }
}
