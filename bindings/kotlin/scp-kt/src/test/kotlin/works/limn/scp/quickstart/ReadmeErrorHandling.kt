// The error handling example from `bindings/kotlin/README.md`, copied byte for
// byte below the package line. `ReadmeQuickStartTest` fails when the copy and
// the README block differ, and calls `sendReportingRejection` on a closed
// context, so the README block compiles and catches the error it names. Edit
// both copies together.

package works.limn.scp.quickstart

import uniffi.scp.ContextHandle
import uniffi.scp.Identity
import uniffi.scp.ScpException
import works.limn.scp.SCP

/** Sends [payload] to [ctx]; returns the error code when the context rejects the send. */
suspend fun sendReportingRejection(
    scp: SCP,
    ctx: ContextHandle,
    identity: Identity,
    payload: ByteArray,
): String? =
    try {
        scp.contextSend(handle = ctx, identity = identity, payload = payload, spendingUcanJwt = null)
        null
    } catch (e: ScpException.Context) {
        println("[${e.code}] ${e.msg}")
        e.code
    }
