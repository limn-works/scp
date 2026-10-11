// ScpViewModelCleanupLoggingTest.kt — ScpViewModel logs cleanup failures (SCP-117)
//
// `.docs/standards/sdk-common.md` §Cleanup error handling: "Errors during cleanup are logged
// but never propagated as exceptions". ScpViewModel meets it through the default
// onCleanupFailure body and through each cleanup coroutine's log of a throwing override,
// whether onCleared or a trackContext after clear launched that coroutine. A plain JVM unit
// test turns `Log.w` into a silent no-op (`isReturnDefaultValues = true`), so these methods run
// under Robolectric, whose ShadowLog records every call.
//
// Provenance: ADR-028 acceptance criterion 11, SCP-117

package works.limn.scp.android

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import kotlinx.coroutines.Dispatchers
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog
import works.limn.scp.bridge.CoroutineBridge
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [33])
class ScpViewModelCleanupLoggingTest {
    private lateinit var stubBindings: TestNativeBindings
    private lateinit var bridge: CoroutineBridge

    @Before
    fun setUp() {
        ShadowLog.clear()
        stubBindings = TestNativeBindings()
        // Unconfined runs each leave inside onCleared, so every log call has landed when
        // clearThroughStore returns.
        bridge =
            CoroutineBridge(
                nativeBindings = stubBindings,
                ioDispatcher = Dispatchers.Unconfined,
                cpuDispatcher = Dispatchers.Unconfined,
            )
    }

    @Test
    fun `the default onCleanupFailure logs a failed leave at warning level`() {
        stubBindings.leaveThrowsForHandle = 1L
        val viewModel = DefaultCleanupViewModel()
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 5L, bridge = bridge))
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 6L, bridge = bridge))

        clearThroughStore(viewModel)

        assertEquals(listOf(1L, 2L), stubBindings.leaveCalledHandles)
        val warning = ShadowLog.getLogsForTag(TAG).single()
        assertEquals(Log.WARN, warning.type)
        assertTrue(warning.msg.contains("contextHandle=1"), "the warning names no context: ${warning.msg}")
        assertTrue(warning.throwable is ScpLeaveException, "the warning carries no leave failure")
    }

    @Test
    fun `onCleared logs an onCleanupFailure override that throws`() {
        stubBindings.leaveThrowsForHandle = 1L
        val overrideFailure = IllegalStateException("override failed")
        val viewModel = ThrowingCleanupViewModel(overrideFailure)
        viewModel.trackContext(TrackedContext(handle = 1L, identityHandle = 5L, bridge = bridge))

        clearThroughStore(viewModel)

        val warning = ShadowLog.getLogsForTag(TAG).single()
        assertEquals(Log.WARN, warning.type)
        assertTrue(warning.msg.contains("contextHandle=1"), "the warning names no context: ${warning.msg}")
        assertEquals(overrideFailure, warning.throwable)
    }

    @Test
    fun `a trackContext after clear logs an onCleanupFailure override that throws`() {
        stubBindings.leaveThrowsForHandle = 2L
        val overrideFailure = IllegalStateException("override failed")
        val viewModel = ThrowingCleanupViewModel(overrideFailure)
        clearThroughStore(viewModel)

        // Unconfined runs the post-clear leave, its failure, and the log inside trackContext.
        viewModel.trackContext(TrackedContext(handle = 2L, identityHandle = 6L, bridge = bridge))

        assertEquals(listOf(2L), stubBindings.leaveCalledHandles)
        val warning = ShadowLog.getLogsForTag(TAG).single()
        assertEquals(Log.WARN, warning.type)
        assertTrue(warning.msg.contains("contextHandle=2"), "the warning names no context: ${warning.msg}")
        assertEquals(overrideFailure, warning.throwable)
    }

    private companion object {
        const val TAG = "ScpViewModel"
    }
}

/** Keeps [ScpViewModel]'s default [ScpViewModel.onCleanupFailure] body. */
private class DefaultCleanupViewModel : ScpViewModel()

/** Throws [failure] from [onCleanupFailure]. */
private class ThrowingCleanupViewModel(private val failure: Throwable) : ScpViewModel() {
    override fun onCleanupFailure(context: TrackedContext, cause: Throwable) {
        throw failure
    }
}

/**
 * Clears [viewModel] through a [ViewModelStore], the cancel-then-onCleared path Android runs.
 * ViewModelProvider keys a view model by its class's canonical name, so [viewModel] is an
 * instance of a named class.
 */
private fun clearThroughStore(viewModel: ViewModel) {
    val store = ViewModelStore()
    val factory =
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = viewModel as T
        }
    ViewModelProvider(store, factory)[viewModel.javaClass]
    store.clear()
}
