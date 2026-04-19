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
        try Scp.defaultInstance().discoveryParseAddress(address: address)
    }

    /// Default create query function — delegates to the process-wide
    /// default ``Scp`` instance's ``Scp/discoveryCreateQuery`` method.
    public static let defaultCreateQuery: CreateQueryFn = { capabilities, keywords, minHistorySecs in
        try Scp.defaultInstance().discoveryCreateQuery(
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
        guard let scp = try? Scp.defaultInstance() else { return address }
        return scp.discoveryNormalizeAddress(address: address)
    }

    /// Discover contexts from a DID string or ``scp://`` URI.
    public typealias DiscoverFn = @Sendable (
        _ query: String
    ) async throws -> String

    /// Default discover function — delegates to the process-wide default
    /// ``Scp`` instance's ``Scp/contextDiscover(query:)`` method.
    public static let defaultDiscover: DiscoverFn = { query in
        try await Scp.defaultInstance().contextDiscover(query: query)
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

/// Parses an SCP address string into its components.
///
/// Returns a JSON string containing the parsed address type and fields.
/// Supports four address types: DiscoveryHandle, DomainHandle,
/// AttestationHandle, and Unscoped.
///
/// - Parameters:
///   - address: The address string to parse.
///   - parseAddressFn: Bridge function override for testing.
/// - Returns: A JSON string with the parsed address components.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the address
///   format is invalid.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
/// - Throws: ``ScpError/Validation(msg:code:)`` if serialization fails.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
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
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func normalizeAddress(
    address: String,
    normalizeAddressFn: DiscoveryBridge.NormalizeAddressFn = DiscoveryBridge.defaultNormalizeAddress
) -> String {
    normalizeAddressFn(address)
}

/// Discovers contexts from a DID string or ``scp://`` URI.
///
/// Detects whether the query is a DID or an ``scp://`` URI and delegates
/// to the appropriate core discovery function.
///
/// - Parameters:
///   - query: A DID string (e.g., `"did:dht:z6Mk..."`) or an
///     ``scp://`` URI.
///   - discoverFn: Bridge function override for testing.
/// - Returns: A JSON string with an array of discovery results, each
///   containing ``context_id``, ``relay_urls``, ``publisher_did``,
///   ``discovery_source``, ``mode``, and ``metadata_summary``.
/// - Throws: ``ScpError`` if DID resolution or URI parsing fails.
///
/// ## Provenance
///
/// - ADR-020 in `.docs/adrs/phase-4.md`
/// - Spec section 22 (Addressing)
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func discover(
    query: String,
    discoverFn: DiscoveryBridge.DiscoverFn = DiscoveryBridge.defaultDiscover
) async throws -> String {
    try await discoverFn(query)
}

// MARK: - Petname operations (§22.4)

/// Assigns a petname to a DID within the owner's local namespace.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - targetDid: DID to assign the petname to.
///   - name: The petname string.
///   - petnameSetFn: Bridge function override for testing.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func setPetname(
    ownerDid: String,
    targetDid: String,
    name: String,
    petnameSetFn: DiscoveryBridge.PetnameSetFn = DiscoveryBridge.defaultPetnameSet
) throws {
    try petnameSetFn(ownerDid, targetDid, name)
}

/// Removes a petname from a DID.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - targetDid: DID to remove the petname from.
///   - petnameRemoveFn: Bridge function override for testing.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func removePetname(
    ownerDid: String,
    targetDid: String,
    petnameRemoveFn: DiscoveryBridge.PetnameRemoveFn = DiscoveryBridge.defaultPetnameRemove
) throws {
    try petnameRemoveFn(ownerDid, targetDid)
}

/// Assigns a petname to a context within the owner's local namespace.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - contextId: Context ID to assign the petname to.
///   - name: The petname string.
///   - petnameSetContextFn: Bridge function override for testing.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func setContextPetname(
    ownerDid: String,
    contextId: String,
    name: String,
    petnameSetContextFn: DiscoveryBridge.PetnameSetContextFn = DiscoveryBridge.defaultPetnameSetContext
) throws {
    try petnameSetContextFn(ownerDid, contextId, name)
}

/// Removes a petname from a context.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - contextId: Context ID to remove the petname from.
///   - petnameRemoveContextFn: Bridge function override for testing.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func removeContextPetname(
    ownerDid: String,
    contextId: String,
    petnameRemoveContextFn: DiscoveryBridge.PetnameRemoveContextFn = DiscoveryBridge.defaultPetnameRemoveContext
) throws {
    try petnameRemoveContextFn(ownerDid, contextId)
}

/// Resolves a petname to a list of DIDs.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - name: The petname to resolve.
///   - petnameResolveDidFn: Bridge function override for testing.
/// - Returns: An array of DID strings.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func resolvePetnameDid(
    ownerDid: String,
    name: String,
    petnameResolveDidFn: DiscoveryBridge.PetnameResolveDidFn = DiscoveryBridge.defaultPetnameResolveDid
) throws -> [String] {
    let json = try petnameResolveDidFn(ownerDid, name)
    return try parseJsonStringArray(json)
}

/// Resolves a petname to a list of context IDs.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - name: The petname to resolve.
///   - petnameResolveContextFn: Bridge function override for testing.
/// - Returns: An array of context ID strings.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func resolvePetnameContext(
    ownerDid: String,
    name: String,
    petnameResolveContextFn: DiscoveryBridge.PetnameResolveContextFn = DiscoveryBridge.defaultPetnameResolveContext
) throws -> [String] {
    let json = try petnameResolveContextFn(ownerDid, name)
    return try parseJsonStringArray(json)
}

/// Gets the petname assigned to a DID, if any.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - targetDid: DID to look up.
///   - petnameGetForDidFn: Bridge function override for testing.
/// - Returns: The petname string, or `nil` if no petname is assigned.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func getPetnameForDid(
    ownerDid: String,
    targetDid: String,
    petnameGetForDidFn: DiscoveryBridge.PetnameGetForDidFn = DiscoveryBridge.defaultPetnameGetForDid
) throws -> String? {
    try petnameGetForDidFn(ownerDid, targetDid)
}

/// Gets the petname assigned to a context, if any.
///
/// - Parameters:
///   - ownerDid: DID of the identity that owns this petname map.
///   - contextId: Context ID to look up.
///   - petnameGetForContextFn: Bridge function override for testing.
/// - Returns: The petname string, or `nil` if no petname is assigned.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``ownerDid`` is empty.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func getPetnameForContext(
    ownerDid: String,
    contextId: String,
    petnameGetForContextFn: DiscoveryBridge.PetnameGetForContextFn = DiscoveryBridge.defaultPetnameGetForContext
) throws -> String? {
    try petnameGetForContextFn(ownerDid, contextId)
}

// MARK: - Handle registry operations (§22.3.1)

/// Registers a handle in a context with discovery tools.
///
/// - Parameters:
///   - discoveryContextId: ID of the context.
///   - handle: The handle string to register.
///   - targetJson: JSON describing the target.
///   - registrantDid: DID of the registrant.
///   - description: Optional human-readable description.
///   - tags: Optional list of tag strings.
///   - handleRegisterFn: Bridge function override for testing.
/// - Returns: A JSON string with the registration result.
/// - Throws: ``ScpError/Validation(msg:code:)`` if ``targetJson`` is malformed.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func registerHandle(
    discoveryContextId: String,
    handle: String,
    targetJson: String,
    registrantDid: String,
    description: String? = nil,
    tags: [String]? = nil,
    handleRegisterFn: DiscoveryBridge.HandleRegisterFn = DiscoveryBridge.defaultHandleRegister
) throws -> String {
    try handleRegisterFn(discoveryContextId, handle, targetJson, registrantDid, description, tags)
}

/// Looks up a handle in a context with discovery tools.
///
/// - Parameters:
///   - discoveryContextId: ID of the context.
///   - handle: The handle string to look up.
///   - typeFilter: Optional filter: ``"identity"`` or ``"context"``.
///   - handleLookupFn: Bridge function override for testing.
/// - Returns: A JSON string with a ``results`` array of matching entries.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func lookupHandle(
    discoveryContextId: String,
    handle: String,
    typeFilter: String? = nil,
    handleLookupFn: DiscoveryBridge.HandleLookupFn = DiscoveryBridge.defaultHandleLookup
) throws -> String {
    try handleLookupFn(discoveryContextId, handle, typeFilter)
}

/// Deregisters a handle from a context with discovery tools.
///
/// - Parameters:
///   - discoveryContextId: ID of the context.
///   - handle: The handle string to deregister.
///   - did: DID of the registrant requesting deregistration.
///   - handleDeregisterFn: Bridge function override for testing.
/// - Returns: A JSON string with a ``removed`` boolean.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func deregisterHandle(
    discoveryContextId: String,
    handle: String,
    did: String,
    handleDeregisterFn: DiscoveryBridge.HandleDeregisterFn = DiscoveryBridge.defaultHandleDeregister
) throws -> String {
    try handleDeregisterFn(discoveryContextId, handle, did)
}

// MARK: - Scope registry operations (§22.3.5, ADR-043)

/// Registers a scope name in a scope registry.
///
/// - Parameters:
///   - scopeContextId: ID of the context hosting the scope registry.
///   - name: Scope name to register.
///   - targetContextId: Context ID the scope name resolves to.
///   - relayUrls: Relay URLs for the target context.
///   - registrantDid: DID of the registrant.
///   - description: Optional human-readable description.
///   - tags: Optional list of tag strings.
///   - scopeRegisterFn: Bridge function override for testing.
/// - Returns: A JSON string with the registration result.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the scope name or relay URLs are invalid.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func registerScope(
    scopeContextId: String,
    name: String,
    targetContextId: String,
    relayUrls: [String],
    registrantDid: String,
    description: String? = nil,
    tags: [String]? = nil,
    scopeRegisterFn: DiscoveryBridge.ScopeRegisterFn = DiscoveryBridge.defaultScopeRegister
) throws -> String {
    try scopeRegisterFn(
        scopeContextId, name, targetContextId, relayUrls, registrantDid, description, tags
    )
}

/// Looks up a scope name in a scope registry.
///
/// - Parameters:
///   - scopeContextId: ID of the context hosting the scope registry.
///   - name: The scope name to look up.
///   - scopeLookupFn: Bridge function override for testing.
/// - Returns: A JSON string with a ``results`` array of matching scope entries.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func lookupScope(
    scopeContextId: String,
    name: String,
    scopeLookupFn: DiscoveryBridge.ScopeLookupFn = DiscoveryBridge.defaultScopeLookup
) throws -> String {
    try scopeLookupFn(scopeContextId, name)
}

/// Deregisters a scope name from a scope registry.
///
/// - Parameters:
///   - scopeContextId: ID of the context hosting the scope registry.
///   - name: The scope name to deregister.
///   - did: DID of the registrant requesting deregistration.
///   - scopeDeregisterFn: Bridge function override for testing.
/// - Returns: A JSON string with a ``removed`` boolean.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func deregisterScope(
    scopeContextId: String,
    name: String,
    did: String,
    scopeDeregisterFn: DiscoveryBridge.ScopeDeregisterFn = DiscoveryBridge.defaultScopeDeregister
) throws -> String {
    try scopeDeregisterFn(scopeContextId, name, did)
}

// MARK: - Address resolution (§22.8)

/// Resolves a human-readable address via multi-path resolution pipeline.
///
/// Uses the petname layer first, then handle registries, then attestation
/// and domain layers per §22.8.
///
/// - Parameters:
///   - ownerDid: DID of the identity whose petname map to consult.
///   - address: The address string to resolve.
///   - knownContextsJson: Optional JSON object mapping context IDs to names.
///   - addressResolveFn: Bridge function override for testing.
/// - Returns: An array of ``AddressResolution`` dictionaries.
/// - Throws: ``ScpError/Validation(msg:code:)`` if resolution fails.
@available(
    *,
    deprecated,
    message: "Operates on the default SCP instance. Construct an explicit `SCP` and call its methods instead. Removal target: two release cycles after Phase 4 merge (ADR-048)."
)
public func resolveDiscoveryAddress(
    ownerDid: String,
    address: String,
    knownContextsJson: String? = nil,
    addressResolveFn: DiscoveryBridge.AddressResolveFn = DiscoveryBridge.defaultAddressResolve
) throws -> [[String: Any]] {
    let json = try addressResolveFn(ownerDid, address, knownContextsJson)
    guard let data = json.data(using: .utf8) else {
        throw ScpError.Validation(
            msg: "Invalid UTF-8 in bridge response",
            code: "SCP-VALID-7200"
        )
    }
    let parsed = try JSONSerialization.jsonObject(with: data, options: [])
    guard let array = parsed as? [[String: Any]] else {
        throw ScpError.Validation(
            msg: "Expected JSON array of objects from bridge",
            code: "SCP-VALID-7200"
        )
    }
    return array
}

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
