import Foundation
import Testing

@testable import SCP

// MARK: - Transport Tests

/// Tests for transport configuration, connection, status, and envelope
/// subscription.
///
/// These tests validate the Swift ergonomics layer and type shapes for
/// transport operations. The UniFFI bridge stubs return placeholder errors
/// until SCP-103 ships.
///
/// See ADR-032 (Transport), ADR-026 (Swift SDK), and story SCP-102.
@Suite("Transport Tests")
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
        #expect(config.dedupCacheSize == 10_000)
        #expect(config.dedupCacheTtlSecs == 3_600)
    }

    @Test("TransportConfig custom dedup parameters")
    func configCustomDedupParams() {
        let config = TransportConfig(
            dedupCacheSize: 50_000,
            dedupCacheTtlSecs: 7_200
        )
        #expect(config.dedupCacheSize == 50_000)
        #expect(config.dedupCacheTtlSecs == 7_200)
    }

    @Test("TransportConfig.withRelayUrls convenience factory")
    func configWithRelayUrls() {
        let config = TransportConfig.withRelayUrls(["wss://relay.example.com/scp/v1"])
        #expect(config.relayUrls.count == 1)
        #expect(config.bootstrapDomain == nil)
        #expect(config.dedupCacheSize == 10_000)
    }

    @Test("TransportConfig.withBootstrapDomain convenience factory")
    func configWithBootstrapDomain() {
        let config = TransportConfig.withBootstrapDomain("scp.example.org")
        #expect(config.bootstrapDomain == "scp.example.org")
        #expect(config.relayUrls.isEmpty)
        #expect(config.dedupCacheTtlSecs == 3_600)
    }

    @Test("TransportConfig is Sendable")
    func configIsSendable() async {
        let config: any Sendable = TransportConfig(relayUrls: ["wss://test"])
        #expect(config is TransportConfig)
    }

    // MARK: - TransportStatus type shape

    @Test("TransportStatus raw values match expected strings")
    func statusRawValues() {
        #expect(TransportStatus.disconnected.rawValue == "disconnected")
        #expect(TransportStatus.connecting.rawValue == "connecting")
        #expect(TransportStatus.connected.rawValue == "connected")
        #expect(TransportStatus.failed.rawValue == "failed")
    }

    @Test("TransportStatus is Equatable")
    func statusEquatable() {
        #expect(TransportStatus.connected == TransportStatus.connected)
        #expect(TransportStatus.disconnected != TransportStatus.connected)
    }

    @Test("TransportStatus is Sendable")
    func statusIsSendable() async {
        let status: any Sendable = TransportStatus.connected
        #expect(status is TransportStatus)
    }

    // MARK: - Connect (bridge stub error propagation)

    @Test("connectTransport throws bridge error with SCP-TRANSPORT-001")
    func connectThrowsBridgeError() async {
        let config = TransportConfig(relayUrls: ["wss://relay.test/scp/v1"])
        do {
            try await connectTransport(config: config)
            Issue.record("Expected connectTransport to throw")
        } catch let error as ScpError {
            if case .transport(_, let code) = error {
                #expect(code == "SCP-TRANSPORT-001")
            } else {
                Issue.record("Expected ScpError.transport, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("connectTransport with empty relay URLs throws bridge error")
    func connectWithEmptyUrlsThrowsBridgeError() async {
        let config = TransportConfig()
        do {
            try await connectTransport(config: config)
            Issue.record("Expected connectTransport to throw")
        } catch let error as ScpError {
            if case .transport(_, let code) = error {
                #expect(code == "SCP-TRANSPORT-001")
            } else {
                Issue.record("Expected ScpError.transport, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Status query (bridge stub error propagation)

    @Test("transportStatus throws bridge error with SCP-TRANSPORT-002")
    func statusThrowsBridgeError() async {
        do {
            _ = try await transportStatus()
            Issue.record("Expected transportStatus to throw")
        } catch let error as ScpError {
            if case .transport(_, let code) = error {
                #expect(code == "SCP-TRANSPORT-002")
            } else {
                Issue.record("Expected ScpError.transport, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Envelope sending (via Context)

    @Test("Context send delegates payload to bridge function")
    func contextSendDelegatesPayload() async throws {
        // This is effectively an envelope send test — Context.send() wraps
        // the payload in an MLS-encrypted envelope via the bridge function.
        let handle = MockTransportContextHandle(id: "transport-ctx", state: "active")
        var sentPayload: Data?

        let sendFn: ContextBridge.SendFn = { _, payload in
            sentPayload = payload
        }
        let subscribeFn: ContextBridge.SubscribeFn = { _, _ in }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
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
        let handle = MockTransportContextHandle(id: "subscribe-ctx", state: "active")

        let sendFn: ContextBridge.SendFn = { _, _ in }
        let subscribeFn: ContextBridge.SubscribeFn = { _, listener in
            subscribed = true
            // Immediately complete to avoid hanging
            listener.onComplete()
        }
        let leaveFn: ContextBridge.LeaveFn = { _ in }
        let closeFn: ContextBridge.CloseFn = { _ in }

        let context = Context(
            handle: handle,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )

        let stream = await context.messages
        // Consume the stream to trigger subscription
        for await _ in stream {}

        #expect(subscribed)
    }

} // end TransportTests

// MARK: - Mock ContextHandle for Transport Tests

private final class MockTransportContextHandle: ContextHandleProtocol, @unchecked Sendable {
    let id: String
    let initialState: String

    init(id: String, state: String = "active") {
        self.id = id
        self.initialState = state
    }

    func contextId() -> String { id }
    func state() -> String { initialState }
}
