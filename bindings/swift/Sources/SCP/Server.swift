import Foundation

// RelayHandle and NodeHandle are UniFFI-generated opaque objects in ScpBindings.swift:
//   - RelayHandle: relayUrl() -> String, relayPort() -> UInt16, isShutdown() -> Bool, shutdown()
//   - NodeHandle: relayUrl() -> String, relayPort() -> UInt16, did() -> String,
//                 isShutdown() -> Bool, shutdown(),
//                 enableSiteProjection(contextId:broadcastKeyHex:authorDid:admission:hostname:
//                     indexPath:maxAssetsPerDeploy:maxDeploySizeBytes:deployRetentionCount:cspOverride:)
//                 commitDeploy(contextId:deployId:) -> UInt32
//                 rollbackDeploy(contextId:deployId:)
//                 disableSiteProjection(contextId:)
//
// Standalone UniFFI functions:
//   - relayStartInMemory() async throws -> RelayHandle
//   - relayStartLocal(dataDir: String) async throws -> RelayHandle
//   - nodeStartInMemory() async throws -> NodeHandle
//   - nodeStartLocal(dataDir: String) async throws -> NodeHandle

// MARK: - ServerBridge

/// Namespace for UniFFI bridge function references used by server operations.
/// Each typealias maps 1:1 to a UniFFI-generated async function. Closures are
/// injected for testability; defaults call through to ScpBindings.
///
/// See ADR-026 for the flat delegation pattern.
public enum ServerBridge {
    /// Start a relay with in-memory blob storage.
    public typealias RelayStartInMemoryFn = @Sendable () async throws -> RelayHandle

    /// Start a relay with redb-backed blob storage.
    public typealias RelayStartLocalFn = @Sendable (_ dataDir: String) async throws -> RelayHandle

    /// Start a full application node with in-memory storage.
    public typealias NodeStartInMemoryFn = @Sendable () async throws -> NodeHandle

    /// Start a full application node with file-backed storage.
    public typealias NodeStartLocalFn = @Sendable (_ dataDir: String) async throws -> NodeHandle

    // MARK: Node lifecycle (SCP-296, spec section 18.11.8)

    /// Enable HTTP broadcast projection for a context.
    public typealias EnableSiteProjectionFn = @Sendable (
        _ handle: NodeHandle,
        _ contextId: String,
        _ broadcastKeyHex: String,
        _ authorDid: String,
        _ admission: String,
        _ hostname: String,
        _ indexPath: String?,
        _ maxAssetsPerDeploy: UInt32?,
        _ maxDeploySizeBytes: UInt64?,
        _ deployRetentionCount: UInt32?,
        _ cspOverride: String?
    ) async throws -> Void

    /// Commit a deploy for a projected context.
    public typealias CommitDeployFn = @Sendable (
        _ handle: NodeHandle,
        _ contextId: String,
        _ deployId: String
    ) async throws -> UInt32

    /// Roll back to a previous deploy for a projected context.
    public typealias RollbackDeployFn = @Sendable (
        _ handle: NodeHandle,
        _ contextId: String,
        _ deployId: String
    ) async throws -> Void

    /// Deactivate HTTP broadcast projection for a context.
    public typealias DisableSiteProjectionFn = @Sendable (
        _ handle: NodeHandle,
        _ contextId: String
    ) async throws -> Void

    /// Default relay in-memory startup -- delegates to UniFFI ``relayStartInMemory()``.
    public static let defaultRelayStartInMemory: RelayStartInMemoryFn = {
        try await relayStartInMemory()
    }

    /// Default relay local startup -- delegates to UniFFI ``relayStartLocal(dataDir:)``.
    public static let defaultRelayStartLocal: RelayStartLocalFn = { dataDir in
        try await relayStartLocal(dataDir: dataDir)
    }

    /// Default node in-memory startup -- delegates to UniFFI ``nodeStartInMemory()``.
    public static let defaultNodeStartInMemory: NodeStartInMemoryFn = {
        try await nodeStartInMemory()
    }

    /// Default node local startup -- delegates to UniFFI ``nodeStartLocal(dataDir:)``.
    public static let defaultNodeStartLocal: NodeStartLocalFn = { dataDir in
        try await nodeStartLocal(dataDir: dataDir)
    }

    /// Default enable site projection -- delegates to UniFFI ``NodeHandle.enableSiteProjection()``.
    public static let defaultEnableSiteProjection: EnableSiteProjectionFn = { hdl, ctx, key, auth, adm, host, idx, maxA, maxS, ret, csp in // swiftlint:disable:this line_length
        try await hdl.enableSiteProjection(
            contextId: ctx, broadcastKeyHex: key, authorDid: auth,
            admission: adm, hostname: host, indexPath: idx,
            maxAssetsPerDeploy: maxA, maxDeploySizeBytes: maxS,
            deployRetentionCount: ret, cspOverride: csp
        )
    }

    /// Default commit deploy -- delegates to UniFFI ``NodeHandle.commitDeploy()``.
    public static let defaultCommitDeploy: CommitDeployFn = { handle, contextId, deployId in
        try await handle.commitDeploy(contextId: contextId, deployId: deployId)
    }

    /// Default rollback deploy -- delegates to UniFFI ``NodeHandle.rollbackDeploy()``.
    public static let defaultRollbackDeploy: RollbackDeployFn = { handle, contextId, deployId in
        try await handle.rollbackDeploy(contextId: contextId, deployId: deployId)
    }

    /// Default disable site projection -- delegates to UniFFI ``NodeHandle.disableSiteProjection()``.
    public static let defaultDisableSiteProjection: DisableSiteProjectionFn = { handle, contextId in
        try await handle.disableSiteProjection(contextId: contextId)
    }
}

// MARK: - Relay

/// Ergonomic wrapper around a running SCP relay server.
///
/// Use the static factory methods ``startInMemory(startFn:)`` or
/// ``startLocal(dataDir:startFn:)`` to create an instance. Call ``shutdown()``
/// to stop the relay.
///
/// ## Provenance
///
/// - Shared server startup module in `crates/scp-ffi-common/src/server.rs`
/// - UniFFI bridge in `crates/scp-ffi/uniffi/src/server.rs`
public struct Relay: Sendable {
    /// The underlying UniFFI handle.
    public let handle: RelayHandle

    /// The WebSocket URL clients should connect to (e.g. `ws://127.0.0.1:PORT/scp/v1`).
    public var relayUrl: String {
        handle.relayUrl()
    }

    /// The port the relay is listening on.
    public var relayPort: UInt16 {
        handle.relayPort()
    }

    /// `true` if ``shutdown()`` has already been called.
    public var isShutdown: Bool {
        handle.isShutdown()
    }

    /// Starts a relay with in-memory blob storage on an OS-assigned port.
    ///
    /// - Parameter startFn: Bridge function override for testing.
    /// - Returns: A ``Relay`` whose ``relayUrl`` property contains the WebSocket URL.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(
        startFn: ServerBridge.RelayStartInMemoryFn = ServerBridge.defaultRelayStartInMemory
    ) async throws -> Relay {
        let handle = try await startFn()
        return Relay(handle: handle)
    }

    /// Starts a relay with redb-backed blob storage on an OS-assigned port.
    ///
    /// Opens (or creates) a redb database at `<dataDir>/blobs.redb`.
    ///
    /// - Parameters:
    ///   - dataDir: Directory for persistent blob storage.
    ///   - startFn: Bridge function override for testing.
    /// - Returns: A ``Relay`` whose ``relayUrl`` property contains the WebSocket URL.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startLocal(
        dataDir: String,
        startFn: ServerBridge.RelayStartLocalFn = ServerBridge.defaultRelayStartLocal
    ) async throws -> Relay {
        let handle = try await startFn(dataDir)
        return Relay(handle: handle)
    }

    /// Signals the relay to stop accepting new connections.
    ///
    /// In-flight connection handlers drain naturally. Idempotent.
    public func shutdown() {
        handle.shutdown()
    }
}

// MARK: - Node

/// Ergonomic wrapper around a running SCP application node.
///
/// An application node includes a running relay server, a generated DID
/// identity, and (optionally) persistent storage. Use the static factory
/// methods ``startInMemory(startFn:)`` or ``startLocal(dataDir:startFn:)``
/// to create an instance.
///
/// Broadcast deployment lifecycle methods (SCP-296, spec section 18.11.8):
/// ``enableSiteProjection``, ``commitDeploy``, ``rollbackDeploy``,
/// ``disableSiteProjection``.
///
/// ## Provenance
///
/// - Shared server startup module in `crates/scp-ffi-common/src/server.rs`
/// - UniFFI bridge in `crates/scp-ffi/uniffi/src/server.rs`
public struct Node: Sendable {
    /// The underlying UniFFI handle.
    public let handle: NodeHandle

    /// The WebSocket URL for this node's relay (e.g. `ws://127.0.0.1:PORT/scp/v1`).
    public var relayUrl: String {
        handle.relayUrl()
    }

    /// The port the node's relay is listening on.
    public var relayPort: UInt16 {
        handle.relayPort()
    }

    /// The node's DID string (e.g. `did:dht:z6Mk...`).
    public var did: String {
        handle.did()
    }

    /// `true` if ``shutdown()`` has already been called.
    public var isShutdown: Bool {
        handle.isShutdown()
    }

    /// Starts a full application node with in-memory storage.
    ///
    /// Auto-wires in-memory key custody, in-memory storage, in-memory DHT
    /// client, self-signed TLS, and a relay on an OS-assigned port.
    ///
    /// - Parameter startFn: Bridge function override for testing.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(
        startFn: ServerBridge.NodeStartInMemoryFn = ServerBridge.defaultNodeStartInMemory
    ) async throws -> Node {
        let handle = try await startFn()
        return Node(handle: handle)
    }

    /// Starts a full application node with file-backed storage.
    ///
    /// Opens (or creates) persistent storage at `<dataDir>/storage/` and a
    /// redb blob database at `<dataDir>/blobs.redb`.
    ///
    /// - Parameters:
    ///   - dataDir: Directory for persistent storage.
    ///   - startFn: Bridge function override for testing.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startLocal(
        dataDir: String,
        startFn: ServerBridge.NodeStartLocalFn = ServerBridge.defaultNodeStartLocal
    ) async throws -> Node {
        let handle = try await startFn(dataDir)
        return Node(handle: handle)
    }

    /// Signals the node to stop (relay + background tasks).
    ///
    /// In-flight connection handlers drain naturally. Idempotent.
    public func shutdown() {
        handle.shutdown()
    }

    // MARK: - Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)

    /// Activates HTTP broadcast projection for a context.
    ///
    /// Registers a broadcast context for HTTP content delivery.
    ///
    /// - Parameters:
    ///   - contextId: The context ID to project.
    ///   - broadcastKeyHex: 32-byte AES-256 broadcast key as a 64-char hex string.
    ///   - authorDid: DID of the broadcast key owner.
    ///   - admission: `"open"` or `"gated"`.
    ///   - config: ``SiteConfig`` with hostname, index path, and deploy limits.
    ///   - enableFn: Bridge function override for testing.
    /// - Throws: ``ScpError`` if parameters are invalid or operation fails.
    public func enableSiteProjection(
        contextId: String,
        broadcastKeyHex: String,
        authorDid: String,
        admission: String,
        config: SiteConfig,
        enableFn: ServerBridge.EnableSiteProjectionFn = ServerBridge.defaultEnableSiteProjection
    ) async throws {
        try await enableFn(
            handle,
            contextId,
            broadcastKeyHex,
            authorDid,
            admission,
            config.hostname,
            config.indexPath == "/index.html" ? nil : config.indexPath,
            config.maxAssetsPerDeploy == 10000 ? nil : UInt32(config.maxAssetsPerDeploy),
            config.maxDeploySizeBytes == 536_870_912 ? nil : config.maxDeploySizeBytes,
            config.deployRetentionCount == 2 ? nil : UInt32(config.deployRetentionCount),
            config.cspOverride
        )
    }

    /// Commits a deploy for a projected context (section 18.11.11).
    ///
    /// Scans blobs matching the `deployId`, decrypts each to extract metadata,
    /// builds an immutable path index, and atomically swaps the serving pointer.
    ///
    /// - Parameters:
    ///   - contextId: The projected context ID.
    ///   - deployId: The deploy identifier (hex, from publish).
    ///   - commitFn: Bridge function override for testing.
    /// - Returns: The number of assets in the committed deploy.
    /// - Throws: ``ScpError`` if the context is not projected or commit fails.
    public func commitDeploy(
        contextId: String,
        deployId: String,
        commitFn: ServerBridge.CommitDeployFn = ServerBridge.defaultCommitDeploy
    ) async throws -> Int {
        let count = try await commitFn(handle, contextId, deployId)
        return Int(count)
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    ///
    /// Sets the path index pointer to a previous deploy within the retention window.
    ///
    /// - Parameters:
    ///   - contextId: The projected context ID.
    ///   - deployId: The deploy identifier to roll back to.
    ///   - rollbackFn: Bridge function override for testing.
    /// - Throws: ``ScpError`` if the context is not projected or deploy not found.
    public func rollbackDeploy(
        contextId: String,
        deployId: String,
        rollbackFn: ServerBridge.RollbackDeployFn = ServerBridge.defaultRollbackDeploy
    ) async throws {
        try await rollbackFn(handle, contextId, deployId)
    }

    /// Deactivates HTTP broadcast projection for a context.
    ///
    /// Removes the projected context from the registry and drops all retained
    /// epoch keys. Idempotent -- calling on a non-projected context is a no-op.
    ///
    /// - Parameters:
    ///   - contextId: The context ID to stop projecting.
    ///   - disableFn: Bridge function override for testing.
    /// - Throws: ``ScpError`` if the operation fails.
    public func disableSiteProjection(
        contextId: String,
        disableFn: ServerBridge.DisableSiteProjectionFn = ServerBridge.defaultDisableSiteProjection
    ) async throws {
        try await disableFn(handle, contextId)
    }
}
