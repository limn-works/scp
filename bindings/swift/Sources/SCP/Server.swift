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
// Phase 4 PR 4 (ADR-048 demolition, #1549) moved relay/node startup from the
// former free UniFFI functions (`relayStartInMemory`, `relayStartLocal`,
// `nodeStartInMemory`, `nodeStartLocal`) onto the UniFFI `Scp` opaque class.
// The SDK-level `SCP` wrapper forwards them as instance methods:
//
//   scp.relayStartInMemory()
//   scp.relayStartLocal(dataDir:)
//   scp.nodeStartInMemory(identity:)
//   scp.nodeStartLocal(dataDir:identity:passphrase:)
//
// The production node start, `scp.nodeStart(config:)`, is macOS-only and sits
// at the end of this file.
//
// Factories therefore accept an `SCP` parameter so handles are stamped with
// the caller's bridge instance, and the `ServerBridge` injectable-closure
// namespace has been deleted along with the process-wide default.

// MARK: - Relay

/// Ergonomic wrapper around a running SCP relay server.
///
/// Use the static factory methods ``startInMemory(scp:)`` or
/// ``startLocal(scp:dataDir:)`` to create an instance. Call ``shutdown()``
/// to stop the relay.
///
/// ## Provenance
///
/// - Shared server startup module in `crates/scp-ffi-common/src/server.rs`
/// - UniFFI bridge in `crates/scp-ffi/uniffi/src/server.rs`
/// - ADR-048 (Multi-instance SCP) — factories take an ``SCP`` explicitly
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
    /// - Parameter scp: The SDK-level ``SCP`` instance that will own the
    ///   minted ``RelayHandle``.
    /// - Returns: A ``Relay`` whose ``relayUrl`` property contains the WebSocket URL.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(scp: SCP) async throws -> Relay {
        let handle = try await scp.relayStartInMemory()
        return Relay(handle: handle)
    }

    /// Starts a relay with redb-backed blob storage on an OS-assigned port.
    ///
    /// Opens (or creates) a redb database at `<dataDir>/blobs.redb`.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted handle.
    ///   - dataDir: Directory for persistent blob storage.
    /// - Returns: A ``Relay`` whose ``relayUrl`` property contains the WebSocket URL.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startLocal(
        scp: SCP,
        dataDir: String
    ) async throws -> Relay {
        let handle = try await scp.relayStartLocal(dataDir: dataDir)
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
/// methods ``startInMemory(scp:identity:)`` or
/// ``startLocal(scp:dataDir:identity:passphrase:)`` to create an instance.
///
/// Broadcast deployment lifecycle methods (SCP-296, spec section 18.11.8):
/// ``enableSiteProjection``, ``commitDeploy``, ``rollbackDeploy``,
/// ``disableSiteProjection``.
///
/// ## Provenance
///
/// - Shared server startup module in `crates/scp-ffi-common/src/server.rs`
/// - UniFFI bridge in `crates/scp-ffi/uniffi/src/server.rs`
/// - ADR-048 (Multi-instance SCP)
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

    /// Starts a full application node with encrypted in-memory storage.
    ///
    /// When `identity` is provided, the node uses the pre-existing identity
    /// instead of generating a fresh one. This enables identity portability --
    /// the same DID persists across node restarts.
    ///
    /// Auto-wires encrypted in-memory storage (ephemeral), self-signed TLS,
    /// and a relay on an OS-assigned port. A build carrying a test-harness
    /// feature also auto-wires in-memory key custody and an in-memory DHT
    /// client; a shipped build fails closed instead when `identity` is absent.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted handle.
    ///   - identity: A pre-existing ``Identity`` to use, or `nil` to generate a fresh one.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(
        scp: SCP,
        identity: Identity? = nil
    ) async throws -> Node {
        let handle = try await scp.nodeStartInMemory(identity: identity)
        return Node(handle: handle)
    }

    /// Starts a full application node on this instance's own storage backend.
    ///
    /// When `identity` is provided, the node uses the pre-existing identity.
    /// When `nil`, the node creates or reloads a persistent identity via
    /// `FileKeyCustody`. The `passphrase` parameter is required in this mode.
    ///
    /// No passphrase is required when `identity` is provided.
    ///
    /// A node writes protocol state into whichever storage backend `scp` was
    /// constructed with, so it opens no protocol store of its own. A caller
    /// wanting a node on a different backend constructs a second ``SCP``.
    /// `dataDir` holds a redb blob database at `<dataDir>/blobs.redb` and, when
    /// `identity` is `nil`, a key file at `<dataDir>/identity.key`.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted handle.
    ///   - dataDir: Directory holding a blob database and a key file.
    ///   - identity: A pre-existing ``Identity`` to use, or `nil` to generate a fresh one.
    ///   - passphrase: Passphrase for Argon2id key derivation. Required when
    ///     `identity` is `nil`.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startLocal(
        scp: SCP,
        dataDir: String,
        identity: Identity? = nil,
        passphrase: String? = nil
    ) async throws -> Node {
        let handle = try await scp.nodeStartLocal(
            dataDir: dataDir, identity: identity, passphrase: passphrase
        )
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
    /// - Parameter bindAddr: Socket address to bind (e.g. `"127.0.0.1:8080"`).
    /// - Returns: The actual bound address as a string.
    /// - Throws: ``ScpError`` if the server is already running or binding fails.
    @discardableResult
    public func serve(
        bindAddr: String? = nil
    ) async throws -> String {
        try await handle.serve(bindAddr: bindAddr)
    }

    /// The HTTP URL of the background server, or `nil` if not serving.
    ///
    /// - Returns: The HTTP URL or `nil`.
    public func httpUrl() async -> String? {
        await handle.httpUrl()
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
    /// - Throws: ``ScpError`` if parameters are invalid or operation fails.
    public func enableSiteProjection(
        contextId: String,
        admission: String,
        config: SiteConfig,
        broadcastKeyHex: String? = nil,
        authorDid: String? = nil
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
        try await handle.enableSiteProjection(
            contextId: contextId,
            admission: admission,
            hostname: config.hostname,
            broadcastKeyHex: broadcastKeyHex,
            authorDid: authorDid,
            indexPath: config.indexPath == "/index.html" ? nil : config.indexPath,
            maxAssetsPerDeploy: config.maxAssetsPerDeploy == 10000 ? nil : UInt32(config.maxAssetsPerDeploy),
            maxDeploySizeBytes: config.maxDeploySizeBytes == 536_870_912 ? nil : UInt64(config.maxDeploySizeBytes),
            deployRetentionCount: config.deployRetentionCount == 2 ? nil : UInt32(config.deployRetentionCount),
            cspOverride: config.cspOverride
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
    /// - Returns: The number of assets in the committed deploy.
    /// - Throws: ``ScpError`` if the context is not projected or commit fails.
    public func commitDeploy(
        contextId: String,
        deployId: String
    ) async throws -> Int {
        let count = try await handle.commitDeploy(contextId: contextId, deployId: deployId)
        return Int(count)
    }

    /// Rolls back to a previous deploy for a projected context (section 18.11.11).
    ///
    /// Sets the path index pointer to a previous deploy within the retention window.
    ///
    /// - Parameters:
    ///   - contextId: The projected context ID.
    ///   - deployId: The deploy identifier to roll back to.
    /// - Throws: ``ScpError`` if the context is not projected or deploy not found.
    public func rollbackDeploy(
        contextId: String,
        deployId: String
    ) async throws {
        try await handle.rollbackDeploy(contextId: contextId, deployId: deployId)
    }

    /// Deactivates HTTP broadcast projection for a context.
    ///
    /// Removes the projected context from the registry and drops all retained
    /// epoch keys. Idempotent -- calling on a non-projected context is a no-op.
    ///
    /// - Parameter contextId: The context ID to stop projecting.
    /// - Throws: ``ScpError`` if the operation fails.
    public func disableSiteProjection(
        contextId: String
    ) async throws {
        try await handle.disableSiteProjection(contextId: contextId)
    }
}

// MARK: - Production node start (macOS only)

#if os(macOS)
    // `NodeStartConfig` and its enums (`FfiReach`, `FfiBlobBackend`,
    // `FfiTlsMode`, `FfiDhtMode`, `FfiCorsOrigins`, `FfiNat`) are the UniFFI
    // record and enums in ScpBindings.swift, as `StorageConfig` is for
    // `SCP.init(storage:)`. They carry the field names, arms and required and
    // optional split of the bridge's `NodeStartConfig` (construction.md
    // §"Node start — `NodeStartConfig`", ADR-052): a flat config with no
    // builder, required fields with no default, and optional fields that
    // default to `nil`. The UniFFI layer is platform-agnostic; the node start
    // entry below is macOS-only, so an iOS build of the SDK has no node start.

    extension Node {
        /// Starts a node through `bridge`, the UniFFI `node_start` export,
        /// passing `config` unchanged and wrapping the returned handle.
        ///
        /// ``SCP/nodeStart(config:)`` passes `inner.nodeStart(config:)`; the
        /// tests pass a double that records the record it receives and throws
        /// each node start error. Every `ScpError` the bridge throws reaches
        /// the caller unchanged.
        static func start(
            config: NodeStartConfig,
            bridge: (NodeStartConfig) async throws -> NodeHandle
        ) async throws -> Node {
            try await Node(handle: bridge(config))
        }
    }

    public extension SCP {
        /// Starts a production node from this instance under an operator
        /// identity (construction.md §"Node start — `NodeStartConfig`").
        ///
        /// Delegates to the UniFFI `node_start` export. The node runs on this
        /// instance's own storage, under the operator ``Identity`` in
        /// `config.identity`, which this instance must have minted. Before the
        /// call returns, the bridge binds this instance's `Supervisor` to the
        /// node's relay; one running node at a time holds that binding. `dht`
        /// takes `.disabled` only: the node runs its relay and publishes
        /// nothing to a DHT.
        ///
        /// ```swift
        /// let node = try await scp.nodeStart(config: NodeStartConfig(
        ///     reach: .local,
        ///     identity: operatorIdentity,
        ///     blobStorage: .sqlite(path: "/var/lib/scp/blobs.sqlite"),
        ///     tls: .plaintext,
        ///     dht: .disabled,
        ///     corsOrigins: .allowlist(origins: ["https://app.example.org"])
        /// ))
        /// ```
        ///
        /// - Parameter config: The node's flat configuration.
        /// - Returns: The running ``Node``; its ``Node/did`` is the operator DID.
        /// - Throws: ``ScpError`` with the code sdk-common.md §"Node start error
        ///   codes" gives the failure. Every `SCP-STORAGE-` code is
        ///   `.Storage`; the bridge's `server_error_class` selects the case of
        ///   every other code. `.Storage`: `SCP-STORAGE-8007` (invalid
        ///   config), `SCP-STORAGE-8008` (blob storage open or directory
        ///   creation), `SCP-STORAGE-8009` (core node storage).
        ///   `.Validation`: `SCP-VALID-7004`. `.Identity`: `SCP-IDENT-1063`
        ///   (operator identity unavailable, including one another ``SCP``
        ///   minted), `SCP-IDENT-1001`. `.Transport`: `SCP-TRANS-5050`,
        ///   `SCP-TRANS-5051` (relay start), `SCP-TRANS-5052` (TLS),
        ///   `SCP-TRANS-5054` (serve or NAT), `SCP-TRANS-5055`,
        ///   `SCP-TRANS-5056` (the bridge could not bind the `Supervisor` to
        ///   the node and has shut the node down). `.Context`: `SCP-CTX-2053`.
        func nodeStart(config: NodeStartConfig) async throws -> Node {
            try await Node.start(config: config, bridge: inner.nodeStart(config:))
        }
    }
#endif
