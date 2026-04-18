import Foundation

// SCP — the SDK-level caller-owned bridge instance (ADR-048).
//
// Each `SCP` wraps an independent UniFFI `Scp` object (from the regenerated
// bindings), which owns its own `UniffiBridgeInstance` — registries,
// transport, context manager. Callers construct explicit instances for
// multi-identity apps and for parallel-safe tests; the free-function façade
// (`scpSuspend`, `scpResume`, `scpShutdown`) uses the process-wide default
// instance under the hood and is deprecated (see the `@available(*,
// deprecated, ...)` annotations on those free functions).
//
// Removal target for the free-function façade: two release cycles after
// Phase 4 PR 1 merge.
//
// REGENERATION REQUIRED: The committed `Internal/ScpBindings.swift` was
// generated before the Phase 4 PR 1 FFI changes and does not yet contain
// the UniFFI-generated `Scp` class. Hosted CI regenerates bindings from
// the Rust crate before running `swift build` / `swift test`. Once the
// bindings are refreshed, this file will compile against `Scp` defined
// in `ScpBindings.swift`. In local dev the file is intentionally guarded
// behind `#if canImport` checks for editor clarity, but the production
// build path assumes the generated class is present.

/// Caller-owned SCP instance — the preferred SDK entry point.
///
/// ```swift
/// let scp = SCP()                                // fresh in-memory instance
/// let shared = try SCP.default()                 // process-wide default
/// try await scp.shutdown(timeoutSecs: 5)         // graceful shutdown
/// ```
///
/// Each `SCP` wraps an independent UniFFI `Scp` handle. Handles minted
/// by one instance are rejected by others via
/// `HandleAffinityError` at the FFI boundary.
///
/// `SCP` is `@unchecked Sendable` because its internal `Scp` handle is
/// `Arc`-shared on the Rust side, and the public API only exposes
/// reads (`instanceId`) and thread-safe lifecycle methods.
public final class SCP: @unchecked Sendable {
    /// The UniFFI-generated `Scp` opaque object. `internal` so other SDK
    /// files (when PR 2 migrates methods onto `SCP`) can dispatch through
    /// it without exposing the raw opaque type to consumers.
    let inner: Scp

    /// Constructs a fresh `SCP` instance with default in-memory state.
    ///
    /// Equivalent to the UniFFI `Scp()` constructor. No state is shared
    /// with the process-wide default instance.
    public init() {
        inner = Scp()
    }

    /// Wraps an already-existing UniFFI `Scp` handle. Internal — used by
    /// the `default()` and `withStorage(_:)` factories so they can reuse
    /// the stored-handle path without leaking the opaque type.
    init(inner: Scp) {
        self.inner = inner
    }

    /// Returns an `SCP` wrapping the process-wide default instance.
    ///
    /// Repeated calls return distinct `SCP` objects sharing the same
    /// underlying UniFFI `Arc<UniffiBridgeInstance>` — their
    /// ``instanceId``s match. This is the bridge the deprecated
    /// free-function façade uses under the hood.
    ///
    /// Prefer explicit construction (`SCP()`) in new code.
    ///
    /// - Throws: ``ScpError/context`` if the default instance is currently
    ///   suspended or permanently shut down.
    public static func `default`() throws -> SCP {
        try SCP(inner: Scp.defaultInstance())
    }

    /// Constructs an `SCP` with an explicit storage configuration.
    ///
    /// In Phase 4 PR 1 only the UniFFI-default ``StorageConfig.inMemory``
    /// variant is meaningful; PR 3 adds a filesystem-backed variant.
    public static func withStorage(_ config: StorageConfig) -> SCP {
        SCP(inner: Scp.withStorage(config: config))
    }

    /// Constructs an `SCP` with an explicit persistence provider
    /// placeholder (Phase 4 PR 1 has no real persistence wiring; PR 3
    /// threads the `scp_core::context::ContextPersistence` trait through).
    public static func withPersistence() -> SCP {
        SCP(inner: Scp.withPersistence())
    }

    /// The monotonic identifier for this bridge instance, unique per
    /// process. Used by the FFI handle-affinity check.
    public var instanceId: UInt64 {
        inner.instanceId()
    }

    /// Suspends this bridge instance (mobile/desktop backgrounding).
    ///
    /// Disconnects the transport and flushes context snapshots.
    /// Transport-dependent operations fail until ``resume()`` is called.
    ///
    /// - Throws: ``ScpError/transport`` if the transport lock is poisoned.
    public func suspend() throws {
        try inner.suspend()
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag; the caller re-establishes the relay
    /// connection explicitly.
    ///
    /// - Throws: ``ScpError/context`` if the instance has been permanently
    ///   shut down.
    public func resume() throws {
        try inner.resume()
    }

    /// Shuts down this instance with a graceful deadline.
    ///
    /// Awaits in-flight tasks up to `timeoutSecs` seconds, aborts any
    /// remaining tasks, then runs typed-field cleanup. Permanent. A
    /// second call is a no-op.
    ///
    /// - Parameter timeoutSecs: Maximum seconds to wait for in-flight
    ///   tasks. Defaults to 5.
    public func shutdown(timeoutSecs: UInt64 = 5) async throws {
        try await inner.shutdown(timeoutSecs: timeoutSecs)
    }
}
