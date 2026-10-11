// CLibrary.kt — the process-environment calls that tests of the
// `encrypted_file` custody request (spec 03 section 3.2.2) need.
//
// The bridge reads `HOME` and `SCP_KEY_PASSPHRASE` from the process environment
// (spec 17 section 17.8), which `System.getenv` can only read, so these tests
// set them through libc and restore them before returning.

package works.limn.scp

import com.sun.jna.Library
import com.sun.jna.Native
import java.io.File

/** The libc environment calls. */
internal interface CLibrary : Library {
    fun setenv(
        name: String,
        value: String,
        overwrite: Int,
    ): Int

    fun unsetenv(name: String): Int

    fun getenv(name: String): String?
}

internal val libc: CLibrary = Native.load("c", CLibrary::class.java)

/**
 * Runs [block] with `HOME` set to [home] and `SCP_KEY_PASSPHRASE` set to
 * [passphrase], then restores both variables, unsetting one that was unset.
 */
internal fun <T> withKeyFileEnvironment(
    home: File,
    passphrase: String,
    block: () -> T,
): T {
    val savedHome = libc.getenv("HOME")
    val savedPassphrase = libc.getenv("SCP_KEY_PASSPHRASE")
    try {
        libc.setenv("HOME", home.absolutePath, 1)
        libc.setenv("SCP_KEY_PASSPHRASE", passphrase, 1)
        return block()
    } finally {
        restore("HOME", savedHome)
        restore("SCP_KEY_PASSPHRASE", savedPassphrase)
    }
}

private fun restore(
    name: String,
    saved: String?,
) {
    if (saved != null) libc.setenv(name, saved, 1) else libc.unsetenv(name)
}
