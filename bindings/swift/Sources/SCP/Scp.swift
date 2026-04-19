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
// Persistence: Phase 4 PR 3 wired the real `ContextPersistence` trait
// through UniFFI via `StorageConfig.sqlite(path:, key:)`. The
// ``SCP/withStorage(sqliteDir:key:)`` convenience constructor exposes
// that variant with Swift-native `URL` and `Data` types. Closes #1260
// and #1491; the Phase 4 auto-reconnect-on-resume transport fix closes
// #1678.

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
    /// Phase 4 PR 3 (closes #1260 / #1491) added
    /// ``StorageConfig/sqlite(path:key:)`` alongside the default
    /// ``StorageConfig/inMemory`` variant; callers who want a Swift-native
    /// `URL` + `Data` surface over the SQLite variant should prefer
    /// ``SCP/withStorage(sqliteDir:key:)``.
    public static func withStorage(_ config: StorageConfig) -> SCP {
        SCP(inner: Scp.withStorage(config: config))
    }

    /// Constructs an `SCP` backed by a `SQLCipher`-encrypted database at
    /// `{sqliteDir}/scp.db`.
    ///
    /// Convenience façade over ``withStorage(_:)`` with the
    /// ``StorageConfig/sqlite(path:key:)`` variant. Accepts Swift-native
    /// `URL` and `Data` and forwards to the UniFFI-generated
    /// `Scp.withStorage(config:)` constructor.
    ///
    /// The raw key material is copied once to cross the UniFFI boundary as
    /// `Vec<u8>`. The Rust side zeroes its copy after `SQLCipher` has
    /// consumed it; callers should zero their own `key` copy after this
    /// call returns — Foundation's `Data` does not guarantee zeroization
    /// on deallocation.
    ///
    /// If the underlying database cannot be opened (bad key, unreadable
    /// directory) the Rust layer logs via `tracing::error!` and returns
    /// an in-memory-only instance — matching the PyO3 / NAPI fallback
    /// behavior documented in PR 3.
    ///
    /// - Parameters:
    ///   - sqliteDir: Directory the `scp.db` file lives in. The path is
    ///     passed through `std::path::PathBuf` on the Rust side, so
    ///     percent-encoded / non-UTF-8 paths must be converted before
    ///     calling.
    ///   - key: Raw encryption key material. Typically 32 bytes
    ///     (`SQLCipher` derives the final key via PBKDF2). Callers should
    ///     zero their copy after this call returns.
    /// - Returns: A fresh `SCP` wrapping a persistent bridge instance.
    ///
    /// Closes #1260, #1491 (Swift SDK surface).
    public static func withStorage(sqliteDir: URL, key: Data) -> SCP {
        SCP(inner: Scp.withStorage(config: .sqlite(path: sqliteDir.path, key: key)))
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
    /// Clears the suspended flag, then performs any per-bridge async work
    /// chained by the UniFFI `BridgeInstanceCore::resume` override:
    ///
    /// - Reconnects every relay URL captured in the pending-URL set at
    ///   suspend time (see #1678).
    /// - Rehydrates any persisted contexts written by the PR 3 SQLite
    ///   persistence path (see #1260 / #1491).
    ///
    /// The method is `async throws` because the underlying Rust
    /// `Scp::resume` is `pub async fn`; UniFFI generates a Swift
    /// `async throws` method that awaits the Rust future on the shared
    /// tokio runtime.
    ///
    /// - Throws: ``ScpError/context`` if the instance has been permanently
    ///   shut down, or ``ScpError/transport`` if a pending relay URL
    ///   could not be reconnected.
    public func resume() async throws {
        try await inner.resume()
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
        } else if timeout.isInfinite || timeout >= Double(UInt64.max) / 1000.0 {
            // `>=` (not `>`): `Double(UInt64.max) == 2^64` due to IEEE-754
            // rounding (`Double` has 53 bits of mantissa, `UInt64` has 64),
            // so any `timeout` that is *exactly* the rounded boundary lands
            // on the "cast would overflow" side of `UInt64(x)`. A strict
            // `>` would miss that single exact value and trap in the
            // fallthrough cast. Clamping to `UInt64.max` there is correct
            // and bounded — round 3 bug-catcher + api-design finding.
            millis = UInt64.max
        } else {
            millis = UInt64((timeout * 1000).rounded())
        }
        try await inner.shutdown(timeoutMillis: millis)
    }

    // MARK: - Bridge method forwarding (ADR-048 PR 4)

    //
    // Common bridge methods are exposed on `SCP` by forwarding to the
    // underlying UniFFI `Scp` object. This lets callers write
    // `try await scp.identityCreate(...)` as an idiomatic Swift method
    // call — mirroring the `Scp.identityCreate(...)` UniFFI surface —
    // without reaching through the internal `inner` property.
    //
    // The full UniFFI method surface remains accessible through
    // `inner` for less-common operations; the subset below covers the
    // hot-path operations identified by the capability matrix. Other
    // domain-specific methods on the SDK wrappers (`Context`, etc.)
    // continue to route through their bridge closure parameters, whose
    // defaults now call `Scp.defaultInstance().<method>(...)`.

    // Identity

    /// Creates a new SCP identity with the specified custody method.
    /// Forwards to ``Scp/identityCreate(custody:)`` on ``inner``.
    public func identityCreate(custody: String) async throws -> Identity {
        try await inner.identityCreate(custody: custody)
    }

    /// Loads an existing SCP identity by DID. Forwards to
    /// ``Scp/identityLoad(did:)`` on ``inner``.
    public func identityLoad(did: String) async throws -> Identity {
        try await inner.identityLoad(did: did)
    }

    /// Resolves a DID to its document. Forwards to
    /// ``Scp/identityResolve(did:)`` on ``inner``.
    public func identityResolve(did: String) async throws -> DidDocument {
        try await inner.identityResolve(did: did)
    }

    // Context lifecycle

    /// Creates a new context. Forwards to
    /// ``Scp/contextCreate(identity:params:)`` on ``inner``.
    public func contextCreate(
        identity: Identity,
        params: ContextParams
    ) async throws -> ContextHandle {
        try await inner.contextCreate(identity: identity, params: params)
    }

    /// Joins an existing context. Forwards to
    /// ``Scp/contextJoin(handle:identity:spendingUcanJwt:)`` on ``inner``.
    public func contextJoin(
        handle: ContextHandle,
        identity: Identity,
        spendingUcanJwt: String? = nil
    ) async throws {
        try await inner.contextJoin(handle: handle, identity: identity, spendingUcanJwt: spendingUcanJwt)
    }

    /// Leaves a context. Forwards to
    /// ``Scp/contextLeave(handle:identity:)`` on ``inner``.
    public func contextLeave(handle: ContextHandle, identity: Identity) async throws {
        try await inner.contextLeave(handle: handle, identity: identity)
    }

    /// Closes a context. Forwards to
    /// ``Scp/contextClose(handle:identity:)`` on ``inner``.
    public func contextClose(handle: ContextHandle, identity: Identity) async throws {
        try await inner.contextClose(handle: handle, identity: identity)
    }

    /// Sends a message to a context. Forwards to
    /// ``Scp/contextSend(handle:identity:payload:spendingUcanJwt:)`` on ``inner``.
    public func contextSend(
        handle: ContextHandle,
        identity: Identity,
        payload: Data,
        spendingUcanJwt: String? = nil
    ) async throws {
        try await inner.contextSend(
            handle: handle,
            identity: identity,
            payload: payload,
            spendingUcanJwt: spendingUcanJwt
        )
    }

    // Transport

    /// Connects to a relay. Forwards to
    /// ``Scp/transportConnect(relayUrl:)`` on ``inner``.
    public func transportConnect(relayUrl: String) async throws -> TransportManager {
        try await inner.transportConnect(relayUrl: relayUrl)
    }

    /// Disconnects a transport manager. Forwards to
    /// ``Scp/transportDisconnect(manager:)`` on ``inner``.
    public func transportDisconnect(manager: TransportManager) async throws {
        try await inner.transportDisconnect(manager: manager)
    }

    /// Queries transport status. Forwards to
    /// ``Scp/transportStatus(manager:)`` on ``inner``.
    public func transportStatus(manager: TransportManager) async throws -> TransportStatus {
        try await inner.transportStatus(manager: manager)
    }

    // Local DID registry

    /// Registers a DID as locally controlled by this instance. Forwards to
    /// ``Scp/registerLocalDid(did:)`` on ``inner``.
    public func registerLocalDid(did: String) async throws {
        try await inner.registerLocalDid(did: did)
    }

    /// Checks whether a DID is locally controlled. Forwards to
    /// ``Scp/isLocalDid(did:)`` on ``inner``.
    public func isLocalDid(did: String) async -> Bool {
        await inner.isLocalDid(did: did)
    }
}
