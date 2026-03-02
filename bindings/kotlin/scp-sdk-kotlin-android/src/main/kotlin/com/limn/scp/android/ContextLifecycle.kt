// ContextLifecycle.kt — Lifecycle-aware SCP context extensions (SCP-117)
//
// Provides LifecycleOwner-scoped Flow collection for SCP contexts. Collection
// starts when the lifecycle reaches minActiveState and cancels on DESTROYED,
// preventing resource leaks in Activities and Fragments.
//
// Provenance: ADR-028 (Kotlin SDK) Android lifecycle integration, SCP-117

package com.limn.scp.android

import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.flowWithLifecycle
import kotlinx.coroutines.flow.Flow

/**
 * Collects messages from a context subscription as a [Flow], scoped to a [LifecycleOwner].
 *
 * Collection starts when the lifecycle reaches [minActiveState] (default: [Lifecycle.State.STARTED])
 * and suspends when the lifecycle drops below that state. The flow completes when the owner
 * reaches [Lifecycle.State.DESTROYED], preventing resource leaks when an Activity or Fragment
 * is destroyed while a context subscription is active.
 *
 * During [Lifecycle.State.CREATED] (i.e., when the activity is stopped but not destroyed),
 * the flow is paused but the underlying context connection is NOT closed. This allows
 * background operations to continue during ON_STOP. To customize which lifecycle state
 * keeps the flow active, pass a different [minActiveState].
 *
 * Per ADR-028: this extension lives in the `scp-sdk-kotlin-android` artifact to keep
 * the core SDK Android-free for JVM targets. The core SDK's `ContextBridge.subscribe()`
 * provides the underlying cold [Flow]; this extension wraps it with lifecycle awareness.
 *
 * Usage:
 * ```kotlin
 * val messages: Flow<String> = contextBridge
 *     .subscribe(contextHandle)
 *     .asLifecycleFlow(viewLifecycleOwner)
 * ```
 *
 * @receiver The cold [Flow] from `ContextBridge.subscribe()` or any SCP message flow.
 * @param owner The [LifecycleOwner] (Activity, Fragment, or test owner) to scope collection to.
 * @param minActiveState Minimum lifecycle state for active collection. Defaults to
 *   [Lifecycle.State.STARTED] — flow collects in STARTED and RESUMED, pauses in CREATED.
 * @return A lifecycle-aware [Flow] that completes on DESTROYED.
 */
fun <T> Flow<T>.asLifecycleFlow(
    owner: LifecycleOwner,
    minActiveState: Lifecycle.State = Lifecycle.State.STARTED,
): Flow<T> = flowWithLifecycle(owner.lifecycle, minActiveState)
