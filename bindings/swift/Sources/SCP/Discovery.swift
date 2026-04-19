import Foundation

// MARK: - DiscoveryBridge

/// Namespace for UniFFI bridge function references used by discovery
/// operations. Each typealias maps 1:1 to a UniFFI-generated function.
/// Closures are injected for testability; defaults call through to
/// ScpBindings.
///
/// See ADR-020 in `.docs/adrs/phase-4.md` and spec section 22
/// (Addressing).
public enum DiscoveryBridge {
    /// Parse an SCP address string into its components.
    public typealias ParseAddressFn = @Sendable (
        _ address: String
    ) throws -> String

    /// Create a discovery query as a JSON string.
    public typealias CreateQueryFn = @Sendable (
        _ capabilities: [String]?,
        _ keywords: [String]?,
        _ minHistorySecs: UInt64?
    ) throws -> String

    /// Normalize an address string per SCP addressing rules.
    public typealias NormalizeAddressFn = @Sendable (
        _ address: String
    ) -> String

    /// Default parse address function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/discoveryParseAddress(address:)``
    /// method.
    public static let defaultParseAddress: ParseAddressFn = { address in
        try discoveryParseAddress(address: address)
    }

    /// Default create query function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/discoveryCreateQuery`` method.
    public static let defaultCreateQuery: CreateQueryFn = { capabilities, keywords, minHistorySecs in
        try discoveryCreateQuery(
            capabilities: capabilities,
            keywords: keywords,
            minHistorySecs: minHistorySecs
        )
    }

    /// Default normalize address function — delegates to the process-wide
    /// default ``Scp`` instance's
    /// ``Scp/discoveryNormalizeAddress(address:)`` method.
    ///
    /// Non-throwing: returns the input unchanged if the default instance
    /// cannot be resolved.
    public static let defaultNormalizeAddress: NormalizeAddressFn = { address in
        discoveryNormalizeAddress(address: address)
    }

    /// Discover contexts from a DID string or ``scp://`` URI.
    public typealias DiscoverFn = @Sendable (
        _ query: String
    ) async throws -> String

    /// Default discover function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/contextDiscover(query:)`` method.
    public static let defaultDiscover: DiscoverFn = { query in
        try await contextDiscover(query: query)
    }

    // MARK: - Petname bridge types (§22.4)

    /// Set a petname for a DID.
    public typealias PetnameSetFn = @Sendable (
        _ ownerDid: String, _ targetDid: String, _ name: String
    ) throws -> Void

    /// Remove a petname from a DID.
    public typealias PetnameRemoveFn = @Sendable (
        _ ownerDid: String, _ targetDid: String
    ) throws -> Void

    /// Set a petname for a context.
    public typealias PetnameSetContextFn = @Sendable (
        _ ownerDid: String, _ contextId: String, _ name: String
    ) throws -> Void

    /// Remove a petname from a context.
    public typealias PetnameRemoveContextFn = @Sendable (
        _ ownerDid: String, _ contextId: String
    ) throws -> Void

    /// Resolve a petname to DIDs.
    public typealias PetnameResolveDidFn = @Sendable (
        _ ownerDid: String, _ name: String
    ) throws -> String

    /// Resolve a petname to context IDs.
    public typealias PetnameResolveContextFn = @Sendable (
        _ ownerDid: String, _ name: String
    ) throws -> String

    /// Get the petname for a DID.
    public typealias PetnameGetForDidFn = @Sendable (
        _ ownerDid: String, _ targetDid: String
    ) throws -> String?

    /// Get the petname for a context.
    public typealias PetnameGetForContextFn = @Sendable (
        _ ownerDid: String, _ contextId: String
    ) throws -> String?

    /// Default petname set — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/petnameSet`` method.
    public static let defaultPetnameSet: PetnameSetFn = { ownerDid, targetDid, name in
        try Scp.defaultInstance().petnameSet(ownerDid: ownerDid, targetDid: targetDid, name: name)
    }

    /// Default petname remove — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/petnameRemove`` method.
    public static let defaultPetnameRemove: PetnameRemoveFn = { ownerDid, targetDid in
        try Scp.defaultInstance().petnameRemove(ownerDid: ownerDid, targetDid: targetDid)
    }

    /// Default petname set context — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/petnameSetContext`` method.
    public static let defaultPetnameSetContext: PetnameSetContextFn = { ownerDid, contextId, name in
        try Scp.defaultInstance().petnameSetContext(ownerDid: ownerDid, contextId: contextId, name: name)
    }

    /// Default petname remove context — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/petnameRemoveContext`` method.
    public static let defaultPetnameRemoveContext: PetnameRemoveContextFn = { ownerDid, contextId in
        try Scp.defaultInstance().petnameRemoveContext(ownerDid: ownerDid, contextId: contextId)
    }

    /// Default petname resolve DID — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/petnameResolveDid`` method.
    public static let defaultPetnameResolveDid: PetnameResolveDidFn = { ownerDid, name in
        try Scp.defaultInstance().petnameResolveDid(ownerDid: ownerDid, name: name)
    }

    /// Default petname resolve context — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/petnameResolveContext`` method.
    public static let defaultPetnameResolveContext: PetnameResolveContextFn = { ownerDid, name in
        try Scp.defaultInstance().petnameResolveContext(ownerDid: ownerDid, name: name)
    }

    /// Default petname get for DID — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/petnameGetForDid`` method.
    public static let defaultPetnameGetForDid: PetnameGetForDidFn = { ownerDid, targetDid in
        try Scp.defaultInstance().petnameGetForDid(ownerDid: ownerDid, targetDid: targetDid)
    }

    /// Default petname get for context — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/petnameGetForContext`` method.
    public static let defaultPetnameGetForContext: PetnameGetForContextFn = { ownerDid, contextId in
        try Scp.defaultInstance().petnameGetForContext(ownerDid: ownerDid, contextId: contextId)
    }

    // MARK: - Handle registry bridge types (§22.3.1)

    /// Register a handle in a context with discovery tools.
    public typealias HandleRegisterFn = @Sendable (
        _ discoveryContextId: String, _ handle: String, _ targetJson: String,
        _ registrantDid: String, _ description: String?, _ tags: [String]?
    ) throws -> String

    /// Look up a handle in a context with discovery tools.
    public typealias HandleLookupFn = @Sendable (
        _ discoveryContextId: String, _ handle: String, _ typeFilter: String?
    ) throws -> String

    /// Deregister a handle from a context with discovery tools.
    public typealias HandleDeregisterFn = @Sendable (
        _ discoveryContextId: String, _ handle: String, _ did: String
    ) throws -> String

    /// Default handle register — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/handleRegister`` method.
    public static let defaultHandleRegister: HandleRegisterFn = {
        try Scp.defaultInstance().handleRegister(
            discoveryContextId: $0, handle: $1,
            targetJson: $2, registrantDid: $3,
            description: $4, tags: $5
        )
    }

    /// Default handle lookup — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/handleLookup`` method.
    public static let defaultHandleLookup: HandleLookupFn = {
        try Scp.defaultInstance().handleLookup(discoveryContextId: $0, handle: $1, typeFilter: $2)
    }

    /// Default handle deregister — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/handleDeregister`` method.
    public static let defaultHandleDeregister: HandleDeregisterFn = {
        try Scp.defaultInstance().handleDeregister(discoveryContextId: $0, handle: $1, did: $2)
    }

    // MARK: - Scope registry bridge types (§22.3.5, ADR-043)

    /// Register a scope name in a scope registry.
    public typealias ScopeRegisterFn = @Sendable (
        _ scopeContextId: String, _ name: String,
        _ targetContextId: String, _ relayUrls: [String],
        _ registrantDid: String,
        _ description: String?, _ tags: [String]?
    ) throws -> String

    /// Look up a scope name in a scope registry.
    public typealias ScopeLookupFn = @Sendable (
        _ scopeContextId: String, _ name: String
    ) throws -> String

    /// Deregister a scope name from a scope registry.
    public typealias ScopeDeregisterFn = @Sendable (
        _ scopeContextId: String, _ name: String, _ did: String
    ) throws -> String

    /// Default scope register — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/scopeRegister`` method.
    public static let defaultScopeRegister: ScopeRegisterFn = {
        try Scp.defaultInstance().scopeRegister(
            scopeContextId: $0, name: $1,
            targetContextId: $2, relayUrls: $3,
            registrantDid: $4, description: $5, tags: $6
        )
    }

    /// Default scope lookup — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/scopeLookup`` method.
    public static let defaultScopeLookup: ScopeLookupFn = {
        try Scp.defaultInstance().scopeLookup(scopeContextId: $0, name: $1)
    }

    /// Default scope deregister — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/scopeDeregister`` method.
    public static let defaultScopeDeregister: ScopeDeregisterFn = {
        try Scp.defaultInstance().scopeDeregister(scopeContextId: $0, name: $1, did: $2)
    }

    // MARK: - Address resolution bridge types (§22.8)

    /// Resolve an address via multi-path resolution.
    public typealias AddressResolveFn = @Sendable (
        _ ownerDid: String, _ address: String, _ knownContextsJson: String?
    ) throws -> String

    /// Default address resolve — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/addressResolve`` method.
    public static let defaultAddressResolve: AddressResolveFn = {
        try Scp.defaultInstance().addressResolve(ownerDid: $0, address: $1, knownContextsJson: $2)
    }
}

// MARK: - Public API

// MARK: - Petname operations (§22.4)

// MARK: - Handle registry operations (§22.3.1)

// MARK: - Scope registry operations (§22.3.5, ADR-043)

// MARK: - Address resolution (§22.8)

// MARK: - JSON parsing helpers

/// Parses a JSON string containing an array of strings into `[String]`.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if the JSON is
///   not valid UTF-8 or does not decode as an array of strings.
private func parseJsonStringArray(_ json: String) throws -> [String] {
    guard let data = json.data(using: .utf8) else {
        throw ScpError.Validation(
            msg: "Invalid UTF-8 in bridge response",
            code: "SCP-VALID-7200"
        )
    }
    let parsed = try JSONSerialization.jsonObject(with: data, options: [])
    guard let array = parsed as? [String] else {
        throw ScpError.Validation(
            msg: "Expected JSON array of strings from bridge",
            code: "SCP-VALID-7200"
        )
    }
    return array
}
