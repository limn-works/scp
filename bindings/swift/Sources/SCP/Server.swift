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
//   - nodeStartInMemory(identity: Identity?) async throws -> NodeHandle
//   - nodeStartLocal(dataDir: String, identity: Identity?) async throws -> NodeHandle

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
    public typealias NodeStartInMemoryFn = @Sendable (_ identity: Identity?) async throws -> NodeHandle

    /// Start a full application node with file-backed storage.
    public typealias NodeStartLocalFn = @Sendable (_ dataDir: String, _ identity: Identity?, _ passphrase: String?) async throws -> NodeHandle

    /// Start the HTTP server in the background.
    public typealias ServeFn = @Sendable (
        _ handle: NodeHandle,
        _ bindAddr: String?
    ) async throws -> String

    /// Returns the HTTP URL of the background server, or nil.
    public typealias HttpUrlFn = @Sendable (
        _ handle: NodeHandle
    ) async -> String?

    /// Default serve -- delegates to UniFFI ``NodeHandle.serve()``.
    public static let defaultServe: ServeFn = { handle, bindAddr in
        try await handle.serve(bindAddr: bindAddr)
    }

    /// Default http_url -- delegates to UniFFI ``NodeHandle.httpUrl()``.
    public static let defaultHttpUrl: HttpUrlFn = { handle in
        await handle.httpUrl()
    }

    // MARK: Node lifecycle (SCP-296, spec section 18.11.8)

    /// Enable HTTP broadcast projection for a context.
    public typealias EnableSiteProjectionFn = @Sendable (
        _ handle: NodeHandle,
        _ contextId: String,
        _ admission: String,
        _ hostname: String,
        _ broadcastKeyHex: String?,
        _ authorDid: String?,
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

    /// Default node in-memory startup -- delegates to UniFFI ``nodeStartInMemory(identity:)``.
    public static let defaultNodeStartInMemory: NodeStartInMemoryFn = { identity in
        try await nodeStartInMemory(identity: identity)
    }

    /// Default node local startup -- delegates to UniFFI ``nodeStartLocal(dataDir:identity:passphrase:)``.
    public static let defaultNodeStartLocal: NodeStartLocalFn = { dataDir, identity, passphrase in
        try await nodeStartLocal(dataDir: dataDir, identity: identity, passphrase: passphrase)
    }

    /// Default enable site projection -- delegates to UniFFI ``NodeHandle.enableSiteProjection()``.
    public static let defaultEnableSiteProjection: EnableSiteProjectionFn = { hdl, ctx, adm, host, key, auth, idx, maxA, maxS, ret, csp in // swiftlint:disable:this line_length
        try await hdl.enableSiteProjection(
            contextId: ctx, admission: adm, hostname: host,
            broadcastKeyHex: key, authorDid: auth, indexPath: idx,
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
    /// When `identity` is provided, the node uses the pre-existing identity
    /// instead of generating a fresh one. This enables identity portability --
    /// the same DID persists across node restarts.
    ///
    /// Auto-wires in-memory key custody, in-memory storage, in-memory DHT
    /// client, self-signed TLS, and a relay on an OS-assigned port.
    ///
    /// - Parameters:
    ///   - identity: A pre-existing ``Identity`` to use, or `nil` to generate a fresh one.
    ///   - startFn: Bridge function override for testing.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(
        identity: Identity? = nil,
        startFn: ServerBridge.NodeStartInMemoryFn = ServerBridge.defaultNodeStartInMemory
    ) async throws -> Node {
        let handle = try await startFn(identity)
        return Node(handle: handle)
    }

    /// Starts a full application node with file-backed storage.
    ///
    /// When `identity` is provided, the node uses the pre-existing identity.
    /// When `nil`, the node creates or reloads a persistent identity via
    /// `FileKeyCustody`. The `passphrase` parameter is required in this mode.
    ///
    /// No passphrase is required when `identity` is provided.
    ///
    /// Opens (or creates) persistent storage at `<dataDir>/storage/` and a
    /// redb blob database at `<dataDir>/blobs.redb`.
    ///
    /// - Parameters:
    ///   - dataDir: Directory for persistent storage.
    ///   - identity: A pre-existing ``Identity`` to use, or `nil` to generate a fresh one.
    ///   - passphrase: Passphrase for Argon2id key derivation. Required when
    ///     `identity` is `nil`.
    ///   - startFn: Bridge function override for testing.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startLocal(
        dataDir: String,
        identity: Identity? = nil,
        passphrase: String? = nil,
        startFn: ServerBridge.NodeStartLocalFn = ServerBridge.defaultNodeStartLocal
    ) async throws -> Node {
        let handle = try await startFn(dataDir, identity, passphrase)
        return Node(handle: handle)
    }

    /// Signals the node to stop (relay + background tasks).
    ///
    /// In-flight connection handlers drain naturally. Idempotent.
    public func shutdown() {
        handle.shutdown()
    }

    // MARK: - HTTP server lifecycle

    /// Starts the HTTP server in the background.
    ///
    /// Defaults to `127.0.0.1:8443` (loopback only) when `bindAddr` is nil.
    /// Pass `"0.0.0.0:PORT"` for network access.
    ///
    /// **Note:** The background server does not support TLS. All HTTP traffic is
    /// plaintext. For production deployments requiring encryption, use the node
    /// binary's `serve()` with TLS configuration.
    ///
    /// - Parameters:
    ///   - bindAddr: Socket address to bind (e.g. `"127.0.0.1:8080"`).
    ///   - serveFn: Bridge function override for testing.
    /// - Returns: The actual bound address as a string.
    /// - Throws: ``ScpError`` if the server is already running or binding fails.
    @discardableResult
    public func serve(
        bindAddr: String? = nil,
        serveFn: ServerBridge.ServeFn = ServerBridge.defaultServe
    ) async throws -> String {
        try await serveFn(handle, bindAddr)
    }

    /// The HTTP URL of the background server, or `nil` if not serving.
    ///
    /// - Parameter httpUrlFn: Bridge function override for testing.
    /// - Returns: The HTTP URL or `nil`.
    public func httpUrl(
        httpUrlFn: ServerBridge.HttpUrlFn = ServerBridge.defaultHttpUrl
    ) async -> String? {
        await httpUrlFn(handle)
    }

    // MARK: - Broadcast deployment lifecycle (SCP-296, spec section 18.11.8)

    /// Activates HTTP broadcast projection for a context.
    ///
    /// Three resolution modes:
    /// 1. Both `broadcastKeyHex` **and** `authorDid` provided -- uses the
    ///    explicit key with epoch 0.
    /// 2. Only `authorDid` provided -- auto-resolves the broadcast key
    ///    using that DID (useful when the author identity differs from the
    ///    node identity).
    /// 3. Neither provided -- auto-resolves using the node's identity DID.
    ///
    /// Providing `broadcastKeyHex` without `authorDid` is an error.
    ///
    /// - Parameters:
    ///   - contextId: The context ID to project.
    ///   - admission: `"open"` or `"gated"`.
    ///   - config: ``SiteConfig`` with hostname, index path, and deploy limits.
    ///   - broadcastKeyHex: 32-byte AES-256 broadcast key as a 64-char hex string, or `nil` for auto-lookup.
    ///   - authorDid: DID of the broadcast key owner, or `nil` for auto-lookup.
    ///   - enableFn: Bridge function override for testing.
    /// - Throws: ``ScpError`` if parameters are invalid or operation fails.
    public func enableSiteProjection(
        contextId: String,
        admission: String,
        config: SiteConfig,
        broadcastKeyHex: String? = nil,
        authorDid: String? = nil,
        enableFn: ServerBridge.EnableSiteProjectionFn = ServerBridge.defaultEnableSiteProjection
    ) async throws {
        try validateAdmission(admission)
        if broadcastKeyHex != nil, authorDid == nil {
            throw ScpError.Validation(
                msg: "broadcastKeyHex requires authorDid -- provide the DID of the broadcast key owner, or omit both for auto-resolve",
                code: "SCP-TRANS-5060"
            )
        }
        if let key = broadcastKeyHex {
            try validateBroadcastKeyHex(key)
        }
        try await enableFn(
            handle,
            contextId,
            admission,
            config.hostname,
            broadcastKeyHex,
            authorDid,
            config.indexPath == "/index.html" ? nil : config.indexPath,
            config.maxAssetsPerDeploy == 10000 ? nil : UInt32(config.maxAssetsPerDeploy),
            config.maxDeploySizeBytes == 536_870_912 ? nil : UInt64(config.maxDeploySizeBytes),
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
