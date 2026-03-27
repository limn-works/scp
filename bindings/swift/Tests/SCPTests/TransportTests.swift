import Foundation
@testable import SCP
import Testing

// MARK: - Transport Tests

/// Tests for transport configuration, connection, status, and envelope
/// subscription.
///
/// UniFFI TransportStatus is a struct with fields:
///   - connected: Bool
///   - relayUrl: String?
///   - latencyMs: Double?
///
/// Async roundtrip tests inject mock bridge functions to verify the delegation
/// pattern works end-to-end without a real UniFFI binary.
///
/// See ADR-032 (Transport), ADR-026 (Swift SDK), and story SCP-221.
struct TransportTests {
    // MARK: - TransportConfig type shape

    @Test("TransportConfig stores explicit relay URLs")
    func configStoresRelayUrls() {
        let config = TransportConfig(
            relayUrls: ["wss://relay1.example.com/scp/v1", "wss://relay2.example.com/scp/v1"]
        )
        #expect(config.relayUrls.count == 2)
        #expect(config.relayUrls[0] == "wss://relay1.example.com/scp/v1")
        #expect(config.bootstrapDomain == nil)
    }

    @Test("TransportConfig stores bootstrap domain")
    func configStoresBootstrapDomain() {
        let config = TransportConfig(bootstrapDomain: "example.com")
        #expect(config.bootstrapDomain == "example.com")
        #expect(config.relayUrls.isEmpty)
    }

    @Test("TransportConfig uses defaults for dedup parameters")
    func configDefaultDedupParams() {
        let config = TransportConfig()
        #expect(config.dedupCacheSize == 10000)
        #expect(config.dedupCacheTtlSecs == 3600)
    }

    @Test("TransportConfig custom dedup parameters")
    func configCustomDedupParams() {
        let config = TransportConfig(
            dedupCacheSize: 50000,
            dedupCacheTtlSecs: 7200
        )
        #expect(config.dedupCacheSize == 50000)
        #expect(config.dedupCacheTtlSecs == 7200)
    }

    @Test("TransportConfig.withRelayUrls convenience factory")
    func configWithRelayUrls() {
        let config = TransportConfig.withRelayUrls(["wss://relay.example.com/scp/v1"])
        #expect(config.relayUrls.count == 1)
        #expect(config.bootstrapDomain == nil)
        #expect(config.dedupCacheSize == 10000)
    }

    @Test("TransportConfig.withBootstrapDomain convenience factory")
    func configWithBootstrapDomain() {
        let config = TransportConfig.withBootstrapDomain("scp.example.org")
        #expect(config.bootstrapDomain == "scp.example.org")
        #expect(config.relayUrls.isEmpty)
        #expect(config.dedupCacheTtlSecs == 3600)
    }

    @Test("TransportConfig is Sendable")
    func configIsSendable() {
        let config: any Sendable = TransportConfig(relayUrls: ["wss://test"])
        #expect(config is TransportConfig)
    }

    // MARK: - TransportStatus type shape (UniFFI struct)

    @Test("TransportStatus stores connected state and relay URL")
    func statusFields() {
        let status = TransportStatus(
            connected: true,
            relayUrl: "wss://relay.example.com/scp/v1",
            latencyMs: 42.5
        )
        #expect(status.connected)
        #expect(status.relayUrl == "wss://relay.example.com/scp/v1")
        #expect(status.latencyMs == 42.5)
    }

    @Test("TransportStatus disconnected with nil fields")
    func statusDisconnected() {
        let status = TransportStatus(
            connected: false,
            relayUrl: nil,
            latencyMs: nil
        )
        #expect(!status.connected)
        #expect(status.relayUrl == nil)
        #expect(status.latencyMs == nil)
    }

    @Test("TransportStatus is Sendable")
    func statusIsSendable() {
        let status: any Sendable = TransportStatus(connected: true, relayUrl: nil, latencyMs: nil)
        #expect(status is TransportStatus)
    }

    // MARK: - Connect via injectable bridge (async roundtrip)

    @Test("connectTransport calls bridge and returns manager")
    func connectRoundtrip() async throws {
        let mockManager = TransportManager(noPointer: .init())
        var receivedUrl: String?

        let mockConnect: TransportBridge.ConnectFn = { relayUrl in
            receivedUrl = relayUrl
            return mockManager
        }

        let config = TransportConfig(relayUrls: ["wss://relay.test/scp/v1"])
        let manager = try await connectTransport(config: config, connectFn: mockConnect)

        #expect(receivedUrl == "wss://relay.test/scp/v1")
        #expect(manager === mockManager)
    }

    @Test("connectTransport throws with empty relay URLs")
    func connectWithEmptyUrlsThrows() async {
        let config = TransportConfig()
        do {
            _ = try await connectTransport(config: config)
            Issue.record("Expected connectTransport to throw")
        } catch let error as ScpError {
            if case let .Transport(_, code) = error {
                #expect(code == "SCP-TRANS-5001")
            } else {
                Issue.record("Expected ScpError.Transport, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Status via injectable bridge (async roundtrip)

    @Test("queryTransportStatus calls bridge and returns status")
    func statusRoundtrip() async throws {
        let mockManager = TransportManager(noPointer: .init())
        let expectedStatus = TransportStatus(
            connected: true,
            relayUrl: "wss://relay.test/scp/v1",
            latencyMs: 15.0
        )

        let mockStatus: TransportBridge.StatusFn = { _ in
            expectedStatus
        }

        let result = try await queryTransportStatus(
            manager: mockManager,
            statusFn: mockStatus
        )

        #expect(result.connected)
        #expect(result.relayUrl == "wss://relay.test/scp/v1")
        #expect(result.latencyMs == 15.0)
    }

    // MARK: - Disconnect via injectable bridge (async roundtrip)

    @Test("disconnectTransport calls bridge disconnect function")
    func disconnectRoundtrip() async throws {
        let mockManager = TransportManager(noPointer: .init())
        var disconnectCalled = false

        let mockDisconnect: TransportBridge.DisconnectFn = { _ in
            disconnectCalled = true
        }

        try await disconnectTransport(manager: mockManager, disconnectFn: mockDisconnect)

        #expect(disconnectCalled)
    }

    @Test("connect then disconnect lifecycle")
    func connectThenDisconnect() async throws {
        let mockManager = TransportManager(noPointer: .init())
        var connectCalled = false
        var disconnectCalled = false

        let mockConnect: TransportBridge.ConnectFn = { _ in
            connectCalled = true
            return mockManager
        }
        let mockDisconnect: TransportBridge.DisconnectFn = { _ in
            disconnectCalled = true
        }

        let config = TransportConfig(relayUrls: ["wss://relay.test/scp/v1"])
        let manager = try await connectTransport(config: config, connectFn: mockConnect)
        #expect(connectCalled)
        #expect(manager === mockManager)

        try await disconnectTransport(manager: manager, disconnectFn: mockDisconnect)
        #expect(disconnectCalled)
    }

    // MARK: - Envelope sending (via Context)

    @Test("Context send delegates payload to bridge function")
    func contextSendDelegatesPayload() async throws {
        let handle = ContextHandle(noPointer: .init())
        var sentPayload: Data?

        let sendFn: ContextBridge.SendFn = { _, _, payload, _ in
            sentPayload = payload
        }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _, _ in }
        let closeFn: ContextBridge.CloseFn = { _, _ in }

        let context = Context(
            handle: handle,
            identity: Identity(noPointer: .init()),
            contextId: "transport-ctx",
            creatorDid: "did:dht:z6MkTest",
            initialState: .active,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let payload = Data("envelope-payload".utf8)
        try await context.send(payload)

        #expect(sentPayload == payload)
    }

    // MARK: - Subscribe (via Context messages)

    @Test("Context messages stream subscribes via bridge function")
    func contextMessagesSubscribes() async throws {
        var subscribed = false
        let handle = ContextHandle(noPointer: .init())

        let sendFn: ContextBridge.SendFn = { _, _, _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, listener in
            subscribed = true
            listener.onComplete()
        }
        let leaveFn: ContextBridge.LeaveFn = { _, _ in }
        let closeFn: ContextBridge.CloseFn = { _, _ in }

        let context = Context(
            handle: handle,
            identity: Identity(noPointer: .init()),
            contextId: "subscribe-ctx",
            creatorDid: "did:dht:z6MkTest",
            initialState: .active,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let stream = try await context.messages
        for await _ in stream {}

        #expect(subscribed)
    }
} // end TransportTests
