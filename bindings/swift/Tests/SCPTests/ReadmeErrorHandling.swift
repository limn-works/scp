// The error handling example from `bindings/swift/README.md`, copied byte for
// byte below this header. `ReadmeQuickStartTests` fails when the copy and the
// README block differ, and calls `sendReportingRejection` on a closed context,
// so the README block compiles and catches the error it names. Edit both
// copies together.

import Foundation
import SCP

/// Sends `payload` to `ctx`; returns the error code when the context rejects the send.
func sendReportingRejection(
    scp: SCP,
    ctx: ContextHandle,
    identity: Identity,
    payload: Data
) async throws -> String? {
    do {
        try await scp.contextSend(handle: ctx, identity: identity, payload: payload, spendingUcanJwt: nil)
        return nil
    } catch let ScpError.Context(msg, code) {
        print("[\(code)] \(msg)")
        return code
    }
}
