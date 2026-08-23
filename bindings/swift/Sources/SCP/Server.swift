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
/// An application node includes a running relay server, a DID identity, and
/// (optionally) persistent storage. The identity is generated only when the
/// caller omits one AND the build enables `testing`; a shipped build that must
/// CREATE one fails closed, and reloading an identity the storage already holds
/// needs no explicit identity and carries no gate. Use the static factory
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

    /// Starts a full application node with in-memory storage.
    ///
    /// When `identity` is provided, a shipped build REJECTS it: UniFFI's
    /// `build_node_identity_from_uniffi` is replaced under
    /// `cfg(not(feature = "testing"))` by a stub that always returns
    /// ``ScpError/Identity`` with code `SCP-IDENT-1013`, because node identity
    /// portability needs custody access the mobile bridge does not have. On a
    /// `testing` build the node uses the pre-existing identity, so the same DID
    /// persists across restarts.
    ///
    /// Passing `nil` for `identity` requests auto-generation, which is available
    /// ONLY in a `testing` build (in-memory key custody, in-memory storage, and
    /// the in-memory DHT client). A shipped build fails closed rather than run a
    /// node backed by an in-memory DHT nullifier. A production caller cannot get
    /// one from a create call either, because this SDK's create calls fail closed
    /// the same way. Self-signed TLS; relay on an OS-assigned port.
    ///
    /// The failure arrives as `ScpError.Validation` with code
    /// `SCP-VALID-7004` and the message "auto-generated in-memory node identity
    /// is unavailable in this build". A missing storage passphrase shares that
    /// code, so read `msg` to tell the two apart.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted handle.
    ///   - identity: A pre-existing ``Identity``. Passing `nil` requests
    ///     auto-generation, which only a `testing` build provides.
    /// - Returns: A ``Node`` with ``relayUrl`` and ``did`` populated.
    /// - Throws: ``ScpError`` if startup fails.
    public static func startInMemory(
        scp: SCP,
        identity: Identity? = nil
    ) async throws -> Node {
        let handle = try await scp.nodeStartInMemory(identity: identity)
        return Node(handle: handle)
    }

    /// Starts a full application node with file-backed storage.
    ///
    /// When `identity` is provided, the node uses the pre-existing identity
    /// (on a `testing` build only).
    /// When `nil`, the node reloads a persistent identity via `FileKeyCustody`,
    /// and the `passphrase` parameter is required. CREATING one, on every run,
    /// needs a pre-rotation custody backend that only a `testing` build has, so
    /// a shipped build throws rather than mint a nullifier-backed identity.
    /// The failure arrives as `ScpError.Identity` with code `SCP-TRANS-5051` and
    /// the message "node identity operation failed".
    ///
    /// With no identity in `dataDir` this build fails on every run, not only the
    /// first: none of this SDK's create calls mints one, so nothing it offers seeds
    /// that directory. The reload branch needs a directory that already holds an
    /// identity record, and a custody holding that record's key handles. Passing
    /// `identity` does not help either, for a
    /// reason specific to this bridge: see the `SCP-IDENT-1013` note below.
    ///
    /// On a shipped build, supplying `identity` does not work either: UniFFI's
    /// `build_node_identity_from_uniffi` is `#[cfg(not(feature = "testing"))]`-
    /// replaced by a stub that always returns ``ScpError/Identity`` with code
    /// `SCP-IDENT-1013`, because node identity portability needs custody access
    /// the mobile bridge does not have. Use platform custody with
    /// `IdentitySource::Persisted` on `NodeConfig` directly.
    ///
    /// No passphrase is required when `identity` is provided.
    ///
    /// Opens (or creates) persistent storage at `<dataDir>/storage/` and a
    /// redb blob database at `<dataDir>/blobs.redb`.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that will own the minted handle.
    ///   - dataDir: Directory for persistent storage.
    ///   - identity: A pre-existing ``Identity``. Passing `nil` reloads the
    ///     identity the storage already holds, and creates one only on a `testing`
    ///     build.
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
