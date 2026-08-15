// BridgeException.kt — structured FFI error carrier for the Kotlin SDK.
//
// Extracted verbatim from the deleted `bridge/CoroutineBridge.kt`, which was a
// zero-implementor stub scaffold over a `NativeBindings` interface no
// production type ever implemented. `BridgeException` itself is NOT part of
// that scaffold: it is the SDK's structured-error type, thrown today by the
// pure validation helpers in `Types.kt` (`validateContentPath`,
// `validateDeployId`, `validateMimeType`) and asserted on by `ValidationTest`.
// It keeps its original fully-qualified name — `works.limn.scp.bridge.
// BridgeException` — so the public surface is unchanged by the deletion.
//
// Provenance: ADR-028 (Kotlin SDK error surface).

package works.limn.scp.bridge

/**
 * Exception carrying a structured SCP error code across the FFI boundary.
 *
 * The [code] is the machine-readable error identifier defined by the protocol
 * error taxonomy (e.g. `"SCP-VALID-7010"`); [message] is the human-readable
 * explanation. Callers switch on [code], never on message text.
 *
 * @property code Structured SCP error code.
 */
class BridgeException(
    message: String,
    val code: String,
    cause: Throwable? = null,
) : Exception(message, cause)
