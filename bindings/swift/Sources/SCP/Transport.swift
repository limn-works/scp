import Foundation

// TransportStatus is now defined by UniFFI in ScpBindings.swift as a struct with:
//   connected: Bool, relayUrl: String?, latencyMs: Double?
//
// TransportConfig is a pure Swift type (not in UniFFI) and is kept here.

// MARK: - TransportConfig

/// Configuration for the SCP transport layer.
///
/// Carries explicit relay URLs, an optional bootstrap domain for
/// `.well-known/scp` discovery, and deduplication cache parameters.
/// Passed to transport initialization to configure relay connections.
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - `.docs/scaffold/swift.md` section "Package Layout"
/// - Story SCP-101
public nonisolated struct TransportConfig: Sendable {
    /// Explicit relay WebSocket URLs provided at SDK initialization.
    public let relayUrls: [String]

    /// Optional domain for `.well-known/scp` relay discovery.
    public let bootstrapDomain: String?

    /// Maximum number of entries in the deduplication cache.
    public let dedupCacheSize: Int

    /// Time-to-live for deduplication cache entries (seconds).
    public let dedupCacheTtlSecs: UInt64

    /// Creates a ``TransportConfig`` with the given parameters.
    public init(
        relayUrls: [String] = [],
        bootstrapDomain: String? = nil,
        dedupCacheSize: Int = 10000,
        dedupCacheTtlSecs: UInt64 = 3600
    ) {
        self.relayUrls = relayUrls
        self.bootstrapDomain = bootstrapDomain
        self.dedupCacheSize = dedupCacheSize
        self.dedupCacheTtlSecs = dedupCacheTtlSecs
    }

    /// Creates a ``TransportConfig`` with explicit relay URLs.
    public static func withRelayUrls(_ relayUrls: [String]) -> TransportConfig {
        TransportConfig(relayUrls: relayUrls)
    }

    /// Creates a ``TransportConfig`` with a bootstrap domain.
    public static func withBootstrapDomain(_ domain: String) -> TransportConfig {
        TransportConfig(bootstrapDomain: domain)
    }
}

// MARK: - TransportBridge

/// Namespace for UniFFI bridge function references used by transport operations.
/// Each typealias maps 1:1 to a UniFFI-generated async function. Closures are
/// injected for testability; defaults call through to ScpBindings.
///
/// See ADR-026 for the flat delegation pattern and ADR-005 for transport spec.
public enum TransportBridge {
    /// Connect to a relay. Maps to ``transportConnect`` in ScpBindings.
    public typealias ConnectFn = @Sendable (
        _ relayUrl: String
    ) async throws -> TransportManager

    /// Query transport status. Maps to ``transportStatus`` in ScpBindings.
    public typealias StatusFn = @Sendable (
        _ manager: TransportManager
    ) async throws -> TransportStatus

    /// Disconnect from a relay. Maps to ``transportDisconnect`` in ScpBindings.
    public typealias DisconnectFn = @Sendable (
        _ manager: TransportManager
    ) async throws -> Void

    /// Default connect function that delegates to the UniFFI-generated binding.
    public static let defaultConnect: ConnectFn = { relayUrl in
        try await transportConnect(relayUrl: relayUrl)
    }

    /// Default status function that delegates to the UniFFI-generated binding.
    public static let defaultStatus: StatusFn = { manager in
        try await transportStatus(manager: manager)
    }

    /// Default disconnect function that delegates to the UniFFI-generated binding.
    public static let defaultDisconnect: DisconnectFn = { manager in
        try await transportDisconnect(manager: manager)
    }
}

// MARK: - Transport Functions

/// Connects the transport layer with the given configuration.
///
/// Delegates to the UniFFI ``transportConnect`` bridge function for each
/// relay URL in the configuration. The first successful connection is used.
///
/// - Parameters:
///   - config: Transport configuration with relay URLs and/or bootstrap domain.
///   - connectFn: Bridge function override for testing.
/// - Returns: A ``TransportManager`` handle for the established connection.
/// - Throws: ``ScpError/Transport(message:code:)`` if all connections fail.
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-221
public func connectTransport(
    config: TransportConfig,
    connectFn: TransportBridge.ConnectFn = TransportBridge.defaultConnect
) async throws -> TransportManager {
    guard let firstUrl = config.relayUrls.first else {
        throw ScpError.Transport(
            message: "No relay URLs provided in transport configuration",
            code: "SCP-TRANS-5001"
        )
    }
    return try await connectFn(firstUrl)
}

/// Queries the current transport connection status.
///
/// Delegates to the UniFFI ``transportStatus`` bridge function.
///
/// - Parameters:
///   - manager: The transport manager to query.
///   - statusFn: Bridge function override for testing.
/// - Returns: The current ``TransportStatus``.
/// - Throws: ``ScpError/Transport(message:code:)`` if the status query fails.
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-221
public func queryTransportStatus(
    manager: TransportManager,
    statusFn: TransportBridge.StatusFn = TransportBridge.defaultStatus
) async throws -> TransportStatus {
    try await statusFn(manager)
}

/// Disconnects the transport layer from the current relay.
///
/// Delegates to the UniFFI ``transportDisconnect`` bridge function, which
/// clears the relay adapter from the ``TransportManager`` and releases the
/// WebSocket connection.
///
/// This is idempotent -- calling it when already disconnected is a no-op.
///
/// - Parameters:
///   - manager: The transport manager to disconnect.
///   - disconnectFn: Bridge function override for testing.
/// - Throws: ``ScpError/Transport(message:code:)`` if the disconnect fails.
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - GitHub issue #590
public func disconnectTransport(
    manager: TransportManager,
    disconnectFn: TransportBridge.DisconnectFn = TransportBridge.defaultDisconnect
) async throws {
    try await disconnectFn(manager)
}
