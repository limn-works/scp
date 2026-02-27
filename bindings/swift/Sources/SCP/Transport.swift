import Foundation

// MARK: - TransportConfig

/// Configuration for the SCP transport layer.
///
/// Carries explicit relay URLs, an optional bootstrap domain for
/// `.well-known/scp` discovery, and deduplication cache parameters.
/// Passed to transport initialization to configure relay connections.
///
/// The Rust transport layer implements a 5-level bootstrap priority chain
/// (spec section 18.5.1):
///
/// 1. Explicit `relayUrls` from this configuration
/// 2. DID document `SCPRelay` service entries
/// 3. `.well-known/scp` resolution from `bootstrapDomain`
/// 4. Peer relay discovery from shared contexts
/// 5. Hardcoded fallback relay list
///
/// ## Provenance
///
/// - ADR-032 (Transport) in `.docs/adrs/phase-2.md`
/// - `.docs/scaffold/swift.md` section "Package Layout"
/// - Story SCP-101
public nonisolated struct TransportConfig: Sendable {
    /// Explicit relay WebSocket URLs provided at SDK initialization.
    ///
    /// Highest trust level in the bootstrap priority chain. When non-empty,
    /// the resolver returns these URLs without trying lower priority levels.
    ///
    /// Example: `["wss://relay.example.com/scp/v1"]`
    public let relayUrls: [String]

    /// Optional domain for `.well-known/scp` relay discovery.
    ///
    /// When set, the resolver fetches `https://<domain>/.well-known/scp` and
    /// extracts the relay URL. This is priority level 3 in the bootstrap chain.
    public let bootstrapDomain: String?

    /// Maximum number of entries in the deduplication cache.
    ///
    /// The dedup cache tracks recently seen envelope identifiers to prevent
    /// duplicate delivery in merged subscription streams. Defaults to 10,000.
    public let dedupCacheSize: Int

    /// Time-to-live for deduplication cache entries (seconds).
    ///
    /// Entries older than this duration are evicted. Defaults to 3,600 (1 hour).
    public let dedupCacheTtlSecs: UInt64

    /// Creates a ``TransportConfig`` with the given parameters.
    ///
    /// - Parameters:
    ///   - relayUrls: Explicit relay URLs. Defaults to empty (use bootstrap).
    ///   - bootstrapDomain: Domain for `.well-known/scp` discovery. Defaults to `nil`.
    ///   - dedupCacheSize: Deduplication cache capacity. Defaults to 10,000.
    ///   - dedupCacheTtlSecs: Deduplication cache TTL in seconds. Defaults to 3,600.
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
    ///
    /// All other fields use their defaults.
    ///
    /// - Parameter relayUrls: The relay WebSocket URLs to use.
    /// - Returns: A new ``TransportConfig``.
    public static func withRelayUrls(_ relayUrls: [String]) -> TransportConfig {
        TransportConfig(relayUrls: relayUrls)
    }

    /// Creates a ``TransportConfig`` with a bootstrap domain.
    ///
    /// All other fields use their defaults.
    ///
    /// - Parameter domain: The domain for `.well-known/scp` relay discovery.
    /// - Returns: A new ``TransportConfig``.
    public static func withBootstrapDomain(_ domain: String) -> TransportConfig {
        TransportConfig(bootstrapDomain: domain)
    }
}

// MARK: - TransportStatus

/// The connection status of the transport layer.
///
/// Reports the state of relay connections managed by the transport manager.
public nonisolated enum TransportStatus: String, Sendable, Equatable {
    /// Not connected to any relay.
    case disconnected
    /// Connecting to a relay (handshake in progress).
    case connecting
    /// Connected to at least one relay and ready to send/receive.
    case connected
    /// Connection failed. Check relay URLs or network connectivity.
    case failed
}

// MARK: - UniFFI Bridge Stubs

/// Connect the transport layer via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `transport_connect` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - config: The transport configuration.
///   - completion: Callback delivering success or an error.
internal func scpTransportConnect(
    config: TransportConfig,
    completion: @Sendable @escaping (Result<Void, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.transport(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TRANSPORT-001"
    )))
}

/// Query transport status via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `transport_status` function.
/// When the XCFramework ships (SCP-103), this free function is replaced by
/// the auto-generated binding.
///
/// - Parameters:
///   - completion: Callback delivering the status or an error.
internal func scpTransportStatus(
    completion: @Sendable @escaping (Result<TransportStatus, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.transport(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-TRANSPORT-002"
    )))
}

// MARK: - Transport Functions

/// Connects the transport layer with the given configuration.
///
/// Initiates connections to SCP relays using the bootstrap priority chain.
/// The transport layer manages WebSocket connections, envelope routing, and
/// deduplication.
///
/// This function bridges the asynchronous UniFFI `transport_connect` call to
/// Swift concurrency via `CheckedContinuation`.
///
/// - Parameter config: The ``TransportConfig`` specifying relay URLs,
///   bootstrap domain, and cache parameters.
/// - Throws: ``ScpError/transport(message:code:)`` if relay connection fails.
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
/// Returns the aggregate status of all relay connections managed by the
/// transport layer.
///
/// - Returns: The current ``TransportStatus``.
/// - Throws: ``ScpError/transport(message:code:)`` if the status query fails.
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
