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
//
// Persistence parameter: intentionally omitted at the SDK surface until
// PR 3 wires the real `ContextPersistence` trait through — see issues
// #1260 and #1491 for progress.

/// Caller-owned SCP instance — the preferred SDK entry point.
///
/// ```swift
/// let scp = SCP()                                // fresh in-memory instance
/// let shared = try SCP.default()                 // process-wide default
/// try await scp.shutdown(timeout: 5.0)           // graceful shutdown
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
    @available(
        *,
        deprecated,
        message: "SCP.default() returns the shared process-wide bridge instance. Construct `SCP()` explicitly per tenant/identity instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
    )
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

    // NOTE: A `withPersistence` factory is intentionally not exposed at
    // the Swift SDK surface until PR 3 wires the real
    // `scp_core::context::ContextPersistence` trait through UniFFI.
    // Track progress via issues #1260 and #1491. The underlying UniFFI
    // `Scp.withPersistence()` factory still exists for internal use
    // but should not be called through the SDK layer until it has a
    // real signature.

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
    /// Awaits in-flight tasks up to `timeout` seconds, aborts any
    /// remaining tasks, then runs typed-field cleanup. Permanent. A
    /// second call is a no-op.
    ///
    /// Fractional seconds (e.g. `0.25`) are preserved to millisecond
    /// resolution before crossing the UniFFI boundary — the native
    /// side takes a `u64` millisecond count.
    ///
    /// `timeout` is clamped defensively:
    /// - `NaN` or values `<= 0` → `0` (abort in-flight tasks immediately).
    /// - `.infinity` or values that would overflow `UInt64` milliseconds
    ///   → `UInt64.max` (effectively unbounded).
    /// - Finite values in range → rounded to the nearest millisecond.
    ///
    /// Clamping avoids the runtime trap that bare `UInt64(x)` exhibits
    /// on `NaN` / `.infinity` / out-of-range Doubles (round 2
    /// api-design review finding).
    ///
    /// - Parameter timeout: Maximum wall-clock duration to wait for
    ///   in-flight tasks, expressed as a ``Foundation/TimeInterval``
    ///   (`Double` seconds). Defaults to `5.0`.
    public func shutdown(timeout: TimeInterval = 5.0) async throws {
        let millis: UInt64
        if timeout.isNaN || timeout <= 0 {
            millis = 0
        } else if timeout.isInfinite || timeout > Double(UInt64.max) / 1000.0 {
            millis = UInt64.max
        } else {
            millis = UInt64((timeout * 1000).rounded())
        }
        try await inner.shutdown(timeoutMillis: millis)
    }
}
