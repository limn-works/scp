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
        dedupCacheSize: Int = 10_000,
        dedupCacheTtlSecs: UInt64 = 3_600
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

// MARK: - UniFFI Bridge Stubs

/// Connect the transport layer via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `transport_connect` function.
internal func scpTransportConnect(
    config: TransportConfig,
    completion: @Sendable @escaping (Result<Void, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Transport(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TRANSPORT-001"
    )))
}

/// Query transport status via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `transport_status` function.
internal func scpTransportStatus(
    completion: @Sendable @escaping (Result<TransportStatus, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.Transport(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TRANSPORT-002"
    )))
}

// MARK: - Transport Functions

/// Connects the transport layer with the given configuration.
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-101
public func connectTransport(config: TransportConfig) async throws {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        scpTransportConnect(config: config) { result in
            switch result {
            case .success:
                continuation.resume()
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}

/// Queries the current transport connection status.
///
/// - Returns: The current ``TransportStatus``.
/// - Throws: ``ScpError/Transport(message:code:)`` if the status query fails.
public func transportStatus() async throws -> TransportStatus {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<TransportStatus, Error>) in
        scpTransportStatus { result in
            switch result {
            case .success(let status):
                continuation.resume(returning: status)
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}
