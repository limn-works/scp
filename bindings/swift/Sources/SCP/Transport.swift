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

// MARK: - SCP transport convenience

public extension SCP {
    /// Connects the transport layer using a ``TransportConfig``.
    ///
    /// Takes the first relay URL from the configuration and forwards to
    /// ``SCP/transportConnect(relayUrl:)``. If the configuration has no
    /// URLs, throws ``ScpError/Transport``.
    ///
    /// - Parameter config: Transport configuration with relay URLs.
    /// - Returns: A ``TransportManager`` handle for the established connection.
    /// - Throws: ``ScpError/Transport`` if no URLs or connection fails.
    func connectTransport(config: TransportConfig) async throws -> TransportManager {
        guard let firstUrl = config.relayUrls.first else {
            throw ScpError.Transport(
                msg: "No relay URLs provided in transport configuration",
                code: "SCP-TRANS-5001"
            )
        }
        return try await transportConnect(relayUrl: firstUrl)
    }
}
