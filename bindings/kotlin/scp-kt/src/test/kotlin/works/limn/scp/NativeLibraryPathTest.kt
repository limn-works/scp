// NativeLibraryPathTest.kt — the test JVM's `jna.library.path` names the compiled cdylib
//
// Every real-FFI suite in this module skips itself through `assumeTrue(nativeAvailable)`
// when JNA cannot load `libscp_ffi_uniffi`, so a `jna.library.path` that points at the
// wrong directory turns those suites into silent skips rather than failures. `compileKotlin`
// depends on `generateUniffiBindings`, which builds the cdylib into the directory cargo
// resolves, so by the time this test runs the library exists; this test fails when the
// path Gradle hands the test JVM does not name the directory holding it.

package works.limn.scp

import java.io.File
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NativeLibraryPathTest {
    @Test
    fun `jna library path names a directory holding the uniffi cdylib`() {
        val path = System.getProperty("jna.library.path")
        assertNotNull(path, "Gradle set no jna.library.path on the test JVM")
        val names = setOf("libscp_ffi_uniffi.dylib", "libscp_ffi_uniffi.so", "scp_ffi_uniffi.dll")
        val found =
            path.split(File.pathSeparator).any { dir ->
                names.any { File(dir, it).isFile }
            }
        assertTrue(found, "no directory in jna.library.path=$path holds the scp-ffi-uniffi cdylib")
    }
}
