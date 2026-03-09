import Foundation

// MARK: - DiscoveryBridge

/// Namespace for UniFFI bridge function references used by discovery
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22
/// (Addressing).
enum DiscoveryBridge {
    /// Parse an SCP address string into its components.
    typealias ParseAddressFn = @Sendable (
        _ address: String
    ) throws -> String

    /// Create a discovery query as a JSON string.
    typealias CreateQueryFn = @Sendable (
        _ capabilities: [String]?,
        _ keywords: [String]?,
        _ minHistorySecs: UInt64?
    ) throws -> String

    /// Normalize an address string per SCP addressing rules.
    typealias NormalizeAddressFn = @Sendable (
        _ address: String
    ) -> String

    /// Default parse address function — delegates to UniFFI
    /// ``discoveryParseAddress``.
    static let defaultParseAddress: ParseAddressFn = { address in
        try discoveryParseAddress(address: address)
    }

    /// Default create query function — delegates to UniFFI
    /// ``discoveryCreateQuery``.
    static let defaultCreateQuery: CreateQueryFn = { capabilities, keywords, minHistorySecs in
        try discoveryCreateQuery(
            capabilities: capabilities,
            keywords: keywords,
            minHistorySecs: minHistorySecs
        )
    }

    /// Default normalize address function — delegates to UniFFI
    /// ``discoveryNormalizeAddress``.
    static let defaultNormalizeAddress: NormalizeAddressFn = { address in
        discoveryNormalizeAddress(address: address)
    }
}

// MARK: - Public API

/// Parses an SCP address string into its components.
///
/// Returns a JSON string containing the parsed address type and fields.
/// Supports four address types: discovery_handle, domain_handle,
/// attestation_handle, and unscoped.
///
/// - Parameters:
///   - address: The address string to parse.
///   - parseAddressFn: Bridge function override for testing.
/// - Returns: A JSON string with the parsed address components.
/// - Throws: ``ScpError/Validation(message:code:)`` if the address
///   format is invalid.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
public func parseAddress(
    address: String,
    parseAddressFn: DiscoveryBridge.ParseAddressFn = DiscoveryBridge.defaultParseAddress
) throws -> String {
    try parseAddressFn(address)
}

/// Creates a discovery query as a JSON string.
///
/// The query can filter by capabilities, keywords, and minimum history
/// duration.
///
/// - Parameters:
///   - capabilities: Optional capability filter list.
///   - keywords: Optional keyword filter list.
///   - minHistorySecs: Optional minimum history duration in seconds.
///   - createQueryFn: Bridge function override for testing.
/// - Returns: A JSON string containing the discovery query.
/// - Throws: ``ScpError/Validation(message:code:)`` if serialization fails.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
public func createDiscoveryQuery(
    capabilities: [String]? = nil,
    keywords: [String]? = nil,
    minHistorySecs: UInt64? = nil,
    createQueryFn: DiscoveryBridge.CreateQueryFn = DiscoveryBridge.defaultCreateQuery
) throws -> String {
    try createQueryFn(capabilities, keywords, minHistorySecs)
}

/// Normalizes an address string per SCP addressing rules.
///
/// Lowercases and trims whitespace.
///
/// - Parameters:
///   - address: The address string to normalize.
///   - normalizeAddressFn: Bridge function override for testing.
/// - Returns: The normalized address string.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
public func normalizeAddress(
    address: String,
    normalizeAddressFn: DiscoveryBridge.NormalizeAddressFn = DiscoveryBridge.defaultNormalizeAddress
) -> String {
    normalizeAddressFn(address)
}
