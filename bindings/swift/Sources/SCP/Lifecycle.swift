import Foundation

/// Namespace for bridge lifecycle controls.
///
/// Exposes ``Lifecycle/suspend()`` and ``Lifecycle/resume()`` which
/// disconnect the bridge from its relay (preserving context state) and
/// clear the suspended flag, respectively.  Use when backgrounding a
/// mobile app, then call ``Lifecycle/resume()`` plus
/// ``transportConnect(relayUrl:)`` to rejoin.
///
/// See `scpSuspend` / `scpResume` in the UniFFI-generated bindings for the
/// underlying FFI contract.
public enum Lifecycle {
    /// Function signature for the suspend bridge call.
    public typealias SuspendFn = @Sendable () throws -> Void

    /// Function signature for the resume bridge call.
    public typealias ResumeFn = @Sendable () async throws -> Void

    /// Default suspend implementation — delegates to UniFFI ``scpSuspend()``.
    public static let defaultSuspend: SuspendFn = {
        try scpSuspend()
    }

    /// Default resume implementation — delegates to UniFFI ``scpResume()``.
    ///
    /// `scpResume` is `async throws` in the UniFFI bindings (the Rust
    /// entry point is `pub async fn`), so this closure is async as well.
    public static let defaultResume: ResumeFn = {
        try await scpResume()
    }

    /// Suspend the bridge instance for backgrounding.
    ///
    /// Disconnects the transport (clearing the relay connection) and marks
    /// the instance as suspended.  Context state is preserved — the
    /// instance remains alive but inactive.  Transport-dependent operations
    /// will fail until ``resume()`` is called.
    ///
    /// After suspension, callers should call ``resume()`` to re-activate and
    /// then re-establish the relay connection via ``transportConnect(relayUrl:)``.
    ///
    /// No-op if the bridge has not been initialized or has already shut down.
    ///
    /// - Parameter suspendFn: Injectable bridge function (for testing).
    ///   Defaults to the UniFFI-generated ``scpSuspend()``.
    /// - Throws: ``ScpError.transport`` if transport cleanup fails.
    @available(
        *,
        deprecated,
        message: "Operates on the default SCP instance. Construct an explicit `SCP` and call `scp.suspend()` instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func suspend(
        suspendFn: SuspendFn = defaultSuspend
    ) throws {
        try suspendFn()
    }

    /// Resume a suspended bridge instance.
    ///
    /// Clears the suspended flag so bridge operations can proceed.  The
    /// caller must re-establish the relay connection via
    /// ``transportConnect(relayUrl:)`` — resume does not reconnect
    /// automatically.
    ///
    /// No-op if the bridge is not initialized.
    ///
    /// - Parameter resumeFn: Injectable bridge function (for testing).
    ///   Defaults to the UniFFI-generated ``scpResume()``.
    /// - Throws: ``ScpError.context`` if the bridge has been permanently shut down.
    @available(
        *,
        deprecated,
        message: "Operates on the default SCP instance. Construct an explicit `SCP` and call `scp.resume()` instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
    )
    public static func resume(
        resumeFn: ResumeFn = defaultResume
    ) async throws {
        try await resumeFn()
    }
}
