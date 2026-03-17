import Foundation

// RelayHandle and NodeHandle are UniFFI-generated opaque objects in ScpBindings.swift:
//   - RelayHandle: relayUrl() -> String, relayPort() -> UInt16, isShutdown() -> Bool, shutdown()
//   - NodeHandle: relayUrl() -> String, relayPort() -> UInt16, did() -> String,
//                 isShutdown() -> Bool, shutdown()
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
}
