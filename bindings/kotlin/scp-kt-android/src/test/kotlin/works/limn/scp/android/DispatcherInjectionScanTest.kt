// DispatcherInjectionScanTest.kt — no SDK source dispatches onto a hardcoded Dispatchers.IO
//
// ADR-028 acceptance criterion 6: every FFI call and every subscription release that SDK code
// dispatches runs on an injected `ioDispatcher`, so a test can substitute a
// `StandardTestDispatcher`. This test reads the `scp-kt` and `scp-kt-android` main sources and
// fails on any `withContext(...)` call whose first argument, the coroutine context, names
// `Dispatchers.IO`, and on each other spelling that reaches the IO dispatcher under another name:
// an import of the `Dispatchers.IO` member, an import alias or typealias that renames
// `Dispatchers`, and a `val`, `var`, or `fun` whose value is `Dispatchers.IO`. A parameter default
// of `Dispatchers.IO` passes, because a caller overrides it. A lexer removes comments (nested block
// comments included) and the content of string and character literals first, so KDoc that names
// the default and a string holding `//` or `/*` neither counts nor hides code; a string template's
// `${...}` expression stays code. Two call sites may name `Dispatchers.IO`, because neither calls
// the SCP FFI: the Play Integrity token request in `platform/AndroidDeviceAttestation.kt` and the
// Firebase token request in `platform/AndroidPushProvider.kt`. Each file may hold its one
// dispatch, with exactly the block [ALLOWED_DISPATCHES] records, so a second dispatch in either
// file, or a call added to either block, fails the scan. The generated UniFFI bindings under
// `internal/uniffi` are not scanned, because the SDK does not author them.
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
        val offenders = scannedSources().flatMap { (relative, file) ->
            offenders(relative, file.readText()).map { "${file.path}: $it" }
        }
        assertEquals(
            "these sources reach Dispatchers.IO instead of the injected ioDispatcher",
            emptyList<String>(),
            offenders,
        )
    }

    @Test
    fun `the scan reaches every main source but the generated bindings, and each allowance names one live site`() {
        val sources = scannedSources().toMap()
        val paths = sources.keys
        assertTrue("the scan read no scp-kt source", "works/limn/scp/stream/Streams.kt" in paths)
        assertTrue("the scan read no scp-kt-android source", "works/limn/scp/android/compose/StateHolders.kt" in paths)
        assertTrue(
            "the scan skipped a platform file",
            "works/limn/scp/android/platform/AndroidStorage.kt" in paths &&
                "works/limn/scp/android/platform/AndroidKeyCustody.kt" in paths,
        )
        assertFalse("the scan read generated bindings", paths.any { it.startsWith(GENERATED_PREFIX) })
        for ((relative, allowed) in ALLOWED_DISPATCHES) {
            // Null when the scan did not read the file, which fails the comparison too.
            val held = sources[relative]?.let { file -> hardcodedIoDispatches(file.readText()).count { it == allowed } }
            assertEquals("$relative does not hold its allowed dispatch exactly once", 1, held)
        }
    }

    @Test
    fun `an allowed platform dispatch passes only verbatim, once, and in its own file`() {
        val push = "works/limn/scp/android/platform/AndroidPushProvider.kt"
        val allowedSource = "suspend fun register(): String {\n    return withContext(Dispatchers.IO) {\n" +
            "        FirebaseMessaging.getInstance().token.await()\n    }\n}"
        assertEquals(emptyList<String>(), offenders(push, allowedSource))
        // An SCP FFI call added to the allowed block.
        val widened = allowedSource.replace(".await()", ".await().also { bindings.pushRegister(it) }")
        assertEquals(1, offenders(push, widened).size)
        // A second dispatch in the same file.
        val second = "$allowedSource\nsuspend fun b() = withContext(Dispatchers.IO) { call() }"
        assertEquals(1, offenders(push, second).size)
        // The allowed block twice.
        assertEquals(1, offenders(push, "$allowedSource\n$allowedSource").size)
        // The allowed block in a file it does not belong to.
        assertEquals(1, offenders("works/limn/scp/android/platform/AndroidStorage.kt", allowedSource).size)
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
                // Spellings that reach the IO dispatcher under another name.
                "import kotlinx.coroutines.Dispatchers.IO\nsuspend fun l() = withContext(IO) { call() }",
                "import kotlinx.coroutines.Dispatchers.IO as Io",
                "import kotlinx.coroutines.Dispatchers as D\nsuspend fun n() = withContext(D.IO) { call() }",
                "typealias D = kotlinx.coroutines.Dispatchers",
                "private val io = Dispatchers.IO\nsuspend fun o() = withContext(io) { call() }",
                "private val io: CoroutineDispatcher get() = Dispatchers.IO",
                "private fun io() = Dispatchers.IO",
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
                "class B(\n    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,\n)",
                "fun f(ioDispatcher: CoroutineDispatcher = Dispatchers.IO) = ioDispatcher",
                "import kotlinx.coroutines.Dispatchers",
                "import kotlinx.coroutines.Dispatchers.Default",
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

    /** Each scanned main source, keyed by its path relative to its module's `src/main/kotlin`. */
    private fun scannedSources(): List<Pair<String, File>> {
        val kotlinRoot = locateKotlinRoot()
        return listOf("scp-kt", "scp-kt-android").flatMap { module ->
            val main = File(kotlinRoot, "$module/src/main/kotlin")
            main.walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .map { it.relativeTo(main).invariantSeparatorsPath to it }
                .filterNot { (relative, _) -> relative.startsWith(GENERATED_PREFIX) }
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
        const val GENERATED_PREFIX = "works/limn/scp/internal/uniffi/"

        /**
         * The one hardcoded dispatch each of two platform files may hold, keyed by path relative
         * to `scp-kt-android/src/main/kotlin`, as [hardcodedIoDispatches] reports it (whitespace
         * removed). Neither block calls the SCP FFI: one requests a Play Integrity token, the
         * other a Firebase token.
         */
        val ALLOWED_DISPATCHES =
            mapOf(
                "works/limn/scp/android/platform/AndroidDeviceAttestation.kt" to
                    "withContext(Dispatchers.IO){IntegrityManagerFactory.create(context)" +
                    ".requestIntegrityToken(IntegrityTokenRequest.builder().setNonce(nonce).build()).await()}",
                "works/limn/scp/android/platform/AndroidPushProvider.kt" to
                    "withContext(Dispatchers.IO){FirebaseMessaging.getInstance().token.await()}",
            )
        val WITH_CONTEXT_CALL = Regex("""\bwithContext\s*(?:<[^()]*?>\s*)?\(""")
        val DISPATCHERS_IO = Regex("""\bDispatchers\s*\.\s*IO\b""")
        const val COROUTINES = """kotlinx\s*\.\s*coroutines\s*\."""

        /** Spellings that reach the IO dispatcher under a name the context-argument check misses. */
        val IO_REBINDINGS =
            listOf(
                // An import of the IO member, aliased or not, lets a bare name reach it.
                Regex("""\bimport\s+$COROUTINES\s*Dispatchers\s*\.\s*IO\b"""),
                // An import alias or a typealias renames `Dispatchers`, so `D.IO` reaches it.
                Regex("""\bimport\s+$COROUTINES\s*Dispatchers\s+as\b"""),
                Regex("""\btypealias\s+\w+\s*=\s*(?:$COROUTINES\s*)?Dispatchers\b"""),
                // A val, var, or fun whose value is Dispatchers.IO. A parameter default, which a
                // caller overrides, is followed by ',' or ')' and passes.
                Regex("""\b(?:val|var|fun)\s+\w+[^=\n]*=\s*(?:$COROUTINES\s*)?Dispatchers\s*\.\s*IO\b(?!\s*[,)])"""),
            )
        val WHITESPACE = Regex("""\s+""")
        const val OPENERS = "([{"
        const val CLOSERS = ")]}"

        /** [hardcodedIoDispatches] in the file at [relative], less the one dispatch that file may hold. */
        fun offenders(relative: String, source: String): List<String> {
            val found = hardcodedIoDispatches(source).toMutableList()
            ALLOWED_DISPATCHES[relative]?.let { found.remove(it) }
            return found
        }

        /**
         * Every `withContext(...)` in [source] whose context argument names `Dispatchers.IO`,
         * reported with its trailing block and without whitespace, and every [IO_REBINDINGS] match.
         */
        fun hardcodedIoDispatches(source: String): List<String> {
            val code = codeOnly(source)
            val dispatches = WITH_CONTEXT_CALL.findAll(code).filter { call ->
                DISPATCHERS_IO.containsMatchIn(contextArgument(code, call.range.last + 1))
            }.map { call ->
                var end = closeOf(code, call.range.last)
                var next = end
                while (next < code.length && code[next].isWhitespace()) next++
                if (next < code.length && code[next] == '{') end = closeOf(code, next)
                code.substring(call.range.first, end).replace(WHITESPACE, "")
            }
            val rebindings = IO_REBINDINGS.flatMap { regex ->
                regex.findAll(code).map { it.value.replace(WHITESPACE, " ") }.toList()
            }
            return dispatches.toList() + rebindings
        }

        /** The index just past the closer that matches the opener at [open]. */
        fun closeOf(code: String, open: Int): Int {
            var depth = 0
            for (i in open until code.length) {
                if (code[i] in OPENERS) depth++
                if (code[i] in CLOSERS && --depth == 0) return i + 1
            }
            return code.length
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
