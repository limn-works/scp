import Foundation
@testable import SCP
import Testing

// MARK: - Context Tests

// Tests for the ``Context`` actor verifying lifecycle state machine, message
// streaming, send/receive, leave/close semantics, and bridge delegation.
//
// Uses injected mock bridge functions for testability. The UniFFI bridge
// stubs are not exercised here -- Context tests focus on the Swift ergonomics
// layer's correct behavior.
//
// See ADR-026 (Swift SDK) and story SCP-102.
// swiftlint:disable:next type_body_length
struct ContextTests {
    // MARK: - Mock ContextHandle

    /// Mock implementation of ``ContextHandleProtocol`` for testing.
    /// Returns configurable values for contextId, creatorDid, and state.
    ///
    /// UniFFI's ContextHandleProtocol requires:
    ///   - contextId() -> String
    ///   - creatorDid() -> String
    ///   - state() throws -> String
    private final class MockContextHandle: ContextHandleProtocol, @unchecked Sendable {
        let id: String
        let creator: String
        let initialState: String

        init(id: String = "test-context-001", creator: String = "did:dht:z6MkCreator", state: String = "active") {
            self.id = id
            self.creator = creator
            initialState = state
        }

        func contextId() -> String {
            id
        }

        func creatorDid() -> String {
            creator
        }

        func state() throws -> String {
            initialState
        }
    }

    // MARK: - Thread-safe test state

    /// A simple lock-based thread-safe container for test assertions.
    /// Uses `NSLock` which is available on all Apple platforms.
    private final class Locked<Value: Sendable>: @unchecked Sendable {
        private var value: Value
        private let lock = NSLock()

        init(_ value: Value) {
            self.value = value
        }

        func withLock<R>(_ body: (inout Value) -> R) -> R {
            lock.lock()
            defer { lock.unlock() }
            return body(&value)
        }

        var current: Value {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
    }

    // MARK: - Test helpers

    /// Creates a ``Context`` with mock bridge functions for testing.
    ///
    /// The returned context uses in-memory mock bridge functions. The `onSend`
    /// closure is called for each ``Context/send(_:)`` invocation, allowing tests
    /// to inspect sent payloads. The `captureListener` closure captures the
    /// ``MessageListener`` registered by ``Context/messages``, enabling
    /// tests to push messages into the stream from the outside.
    private func makeTestContext(
        contextId: String = "test-context-001",
        state: String = "active",
        onSend: (@Sendable (Data) -> Void)? = nil,
        onLeave: (@Sendable () -> Void)? = nil,
        onClose: (@Sendable () -> Void)? = nil,
        captureListener: (@Sendable (any MessageListener) -> Void)? = nil
    ) -> Context {
        let handle = MockContextHandle(id: contextId, state: state)
        let identity = Identity(noPointer: .init())

        let sendFn: ContextBridge.SendFn = { _, _, payload in
            onSend?(payload)
        }

        let subscribeFn: ContextBridge.SubscribeFn = { _, listener in
            captureListener?(listener)
        }

        let leaveFn: ContextBridge.LeaveFn = { _, _ in
            onLeave?()
        }

        let closeFn: ContextBridge.CloseFn = { _, _ in
            onClose?()
        }

        return Context(
            handle: handle,
            identity: identity,
            sendFn: sendFn,
            subscribeFn: subscribeFn,
            leaveFn: leaveFn,
            closeFn: closeFn
        )
    }

    /// Builds a ``Message`` for use in stream tests.
    private func makeTestMessage(
        sender: String = "did:dht:alice",
        payload: String = "msg",
        timestamp: UInt64 = 1_000_000,
        sequence: UInt64 = 1,
        contextId: String = "test-context-001",
        provenance: DataProvenance? = nil
    ) -> Message {
        Message(
            senderDid: sender,
            payload: Data(payload.utf8),
            timestamp: timestamp,
            sequence: sequence,
            contextId: contextId,
            provenance: provenance
        )
    }

    // MARK: - Context creation tests

    @Test("Context.create returns a context in active state")
    func createReturnsActiveContext() async throws {
        let capturedParams = Locked<ContextParams?>(nil)
        let capturedIdentity = Locked<Identity?>(nil)
        let createFn: ContextBridge.CreateFn = { identity, params in
            capturedIdentity.withLock { $0 = identity }
            capturedParams.withLock { $0 = params }
            return MockContextHandle(
                id: "ctx-create-test",
                state: "active"
            )
        }
        let noOpSend: ContextBridge.SendFn = { _, _, _ in }
        let noOpSubscribe: ContextBridge.SubscribeFn = { _, _ in }
        let noOpLeave: ContextBridge.LeaveFn = { _, _ in }
        let noOpClose: ContextBridge.CloseFn = { _, _ in }

        let identity = Identity(noPointer: .init())
        let params = ContextParams(
            ceiling: ["messages:read", "messages:write"],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0
        )

        let context = try await Context.create(
            identity: identity,
            params: params,
            createFn: createFn,
            sendFn: noOpSend,
            subscribeFn: noOpSubscribe,
            leaveFn: noOpLeave,
            closeFn: noOpClose
        )

        #expect(await context.contextId == "ctx-create-test")
        #expect(await context.state == .active)

        // Verify the factory forwarded identity to the bridge function
        let forwardedIdentity = capturedIdentity.current
        #expect(forwardedIdentity != nil)

        // Verify the factory forwarded params to the bridge function
        let forwarded = capturedParams.current
        #expect(forwarded != nil)
        #expect(forwarded?.ttlSeconds == 3600)
        #expect(forwarded?.governance == .singleAdmin)
        #expect(forwarded?.ceiling == ["messages:read", "messages:write"])
    }

    @Test("Context.create propagates bridge errors")
    func createPropagatesBridgeErrors() async {
        let createFn: ContextBridge.CreateFn = { _, _ in
            throw ScpError.Context(message: "creation failed", code: "SCP-CTX-2100")
        }
        let noOpSend: ContextBridge.SendFn = { _, _, _ in }
        let noOpSubscribe: ContextBridge.SubscribeFn = { _, _ in }
        let noOpLeave: ContextBridge.LeaveFn = { _, _ in }
        let noOpClose: ContextBridge.CloseFn = { _, _ in }

        let identity = Identity(noPointer: .init())
        let params = ContextParams(
            ceiling: [],
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 0,
            promotable: false,
            minProtocolVersion: 0
        )

        await #expect(throws: ScpError.self) {
            _ = try await Context.create(
                identity: identity,
                params: params,
                createFn: createFn,
                sendFn: noOpSend,
                subscribeFn: noOpSubscribe,
                leaveFn: noOpLeave,
                closeFn: noOpClose
            )
        }
    }

    // MARK: - Send tests

    @Test("send delivers payload via bridge function")
    func sendDeliversPayload() async throws {
        let sentPayloads = Locked<[Data]>([])
        let context = makeTestContext(onSend: { payload in
            sentPayloads.withLock { $0.append(payload) }
        })

        let payload = Data("hello, context".utf8)
        try await context.send(payload)

        let payloads = sentPayloads.current
        #expect(payloads.count == 1)
        #expect(payloads[0] == payload)
    }

    @Test("send forwards identity to bridge function")
    func sendForwardsIdentity() async throws {
        let capturedIdentity = Locked<Identity?>(nil)
        let handle = MockContextHandle()
        let identity = Identity(noPointer: .init())

        let sendFn: ContextBridge.SendFn = { _, id, _ in
            capturedIdentity.withLock { $0 = id }
        }

        let context = Context(
            handle: handle,
            identity: identity,
            sendFn: sendFn,
            subscribeFn: { _, _ in },
            leaveFn: { _, _ in },
            closeFn: { _, _ in }
        )

        try await context.send(Data("test".utf8))

        let forwarded = capturedIdentity.current
        #expect(forwarded != nil)
        #expect(forwarded === identity)
    }

    @Test("send throws when context is closed")
    func sendThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        await #expect(throws: ScpError.self) {
            try await context.send(Data("should fail".utf8))
        }
    }

    @Test("send throws SCP-CTX-2001 when context is not active")
    func sendThrowsCorrectErrorCode() async throws {
        let context = makeTestContext()
        try await context.close()

        do {
            try await context.send(Data("should fail".utf8))
            Issue.record("Expected send to throw after close")
        } catch let error as ScpError {
            if case let .Context(message, code) = error {
                #expect(code == "SCP-CTX-2001")
                #expect(message == "Context is not active")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        }
    }

    // MARK: - Message stream tests

    @Test("messages returns AsyncStream that yields messages")
    func messagesYieldsMessages() async throws {
        let capturedListener = Locked<(any MessageListener)?>(nil)

        let context = makeTestContext(captureListener: { listener in
            capturedListener.withLock { $0 = listener }
        })

        let stream = try await context.messages

        // Wait for listener to be captured (subscribeFn is called synchronously
        // within the actor-isolated `messages` property, so it should be set
        // immediately after the `await` returns)
        var listener: (any MessageListener)?
        for _ in 0 ..< 100 {
            listener = capturedListener.current
            if listener != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        guard let resolvedListener = listener else {
            Issue.record("Listener was not captured")
            return
        }

        // Push messages through the listener — using UniFFI Message (payload, not content)
        let message1 = makeTestMessage(sender: "did:dht:alice", payload: "msg1")
        let message2 = makeTestMessage(
            sender: "did:dht:bob",
            payload: "msg2",
            timestamp: 1_000_001,
            sequence: 2,
            provenance: DataProvenance(
                sourceContext: "other-ctx",
                sourceType: .persistent,
                counterparties: ["did:dht:bob"],
                purpose: nil,
                discoveryMethod: .outOfBand,
                ageSecs: 0,
                memoryScope: .full,
                chainDepth: 1,
                chainPath: nil,
                paymentAmount: nil,
                paymentAdapter: nil,
                paymentReceiptId: nil
            )
        )

        resolvedListener.onMessage(message: message1)
        resolvedListener.onMessage(message: message2)
        resolvedListener.onComplete()

        var received: [Message] = []
        for await message in stream {
            received.append(message)
        }

        #expect(received.count == 2)
        #expect(received[0].senderDid == "did:dht:alice")
        #expect(received[0].sequence == 1)
        #expect(received[1].senderDid == "did:dht:bob")
        #expect(received[1].provenance?.sourceContext == "other-ctx")
    }

    @Test("messages stream finishes on error")
    func messagesStreamFinishesOnError() async throws {
        let capturedListener = Locked<(any MessageListener)?>(nil)

        let context = makeTestContext(captureListener: { listener in
            capturedListener.withLock { $0 = listener }
        })

        let stream = try await context.messages

        var listener: (any MessageListener)?
        for _ in 0 ..< 100 {
            listener = capturedListener.current
            if listener != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        guard let resolvedListener = listener else {
            Issue.record("Listener was not captured")
            return
        }

        // Push one message then an error
        resolvedListener.onMessage(message: makeTestMessage(
            sender: "did:dht:alice",
            payload: "before-error"
        ))
        resolvedListener.onError(error: ScpError.Transport(
            message: "connection lost",
            code: "SCP-TRANS-5001"
        ))

        var received: [Message] = []
        for await message in stream {
            received.append(message)
        }

        #expect(received.count == 1)
        #expect(received[0].senderDid == "did:dht:alice")
    }

    // MARK: - Leave tests

    @Test("leave transitions state to closed")
    func leaveTransitionsState() async throws {
        let leaveCalled = Locked<Bool>(false)
        let context = makeTestContext(onLeave: {
            leaveCalled.withLock { $0 = true }
        })

        try await context.leave()

        #expect(await context.state == .closed)
        #expect(leaveCalled.current)
    }

    @Test("leave finishes the message stream")
    func leaveFinishesStream() async throws {
        let capturedListener = Locked<(any MessageListener)?>(nil)

        let context = makeTestContext(captureListener: { listener in
            capturedListener.withLock { $0 = listener }
        })

        let stream = try await context.messages

        var listener: (any MessageListener)?
        for _ in 0 ..< 100 {
            listener = capturedListener.current
            if listener != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        guard let resolvedListener = listener else {
            Issue.record("Listener was not captured")
            return
        }

        // Push a message, then leave
        resolvedListener.onMessage(message: Message(
            senderDid: "did:dht:alice",
            payload: Data("before-leave".utf8),
            timestamp: 1_000_000,
            sequence: 1,
            contextId: "test-context-001",
            provenance: nil
        ))

        try await context.leave()

        var received: [Message] = []
        for await message in stream {
            received.append(message)
        }

        // Should receive the one message sent before leave
        #expect(received.count == 1)
    }

    @Test("leave forwards identity to bridge function")
    func leaveForwardsIdentity() async throws {
        let capturedIdentity = Locked<Identity?>(nil)
        let handle = MockContextHandle()
        let identity = Identity(noPointer: .init())

        let leaveFn: ContextBridge.LeaveFn = { _, id in
            capturedIdentity.withLock { $0 = id }
        }

        let context = Context(
            handle: handle,
            identity: identity,
            sendFn: { _, _, _ in },
            subscribeFn: { _, _ in },
            leaveFn: leaveFn,
            closeFn: { _, _ in }
        )

        try await context.leave()

        let forwarded = capturedIdentity.current
        #expect(forwarded != nil)
        #expect(forwarded === identity)
    }

    @Test("leave throws when context is already closed")
    func leaveThrowsWhenClosed() async throws {
        let context = makeTestContext()
        try await context.close()

        await #expect(throws: ScpError.self) {
            try await context.leave()
        }
    }

    // MARK: - Close tests

    @Test("close transitions state to closed")
    func closeTransitionsState() async throws {
        let closeCalled = Locked<Bool>(false)
        let context = makeTestContext(onClose: {
            closeCalled.withLock { $0 = true }
        })

        try await context.close()

        #expect(await context.state == .closed)
        #expect(closeCalled.current)
    }

    @Test("close forwards identity to bridge function")
    func closeForwardsIdentity() async throws {
        let capturedIdentity = Locked<Identity?>(nil)
        let handle = MockContextHandle()
        let identity = Identity(noPointer: .init())

        let closeFn: ContextBridge.CloseFn = { _, id in
            capturedIdentity.withLock { $0 = id }
        }

        let context = Context(
            handle: handle,
            identity: identity,
            sendFn: { _, _, _ in },
            subscribeFn: { _, _ in },
            leaveFn: { _, _ in },
            closeFn: closeFn
        )

        try await context.close()

        let forwarded = capturedIdentity.current
        #expect(forwarded != nil)
        #expect(forwarded === identity)
    }

    @Test("close is idempotent -- calling twice does not throw")
    func closeIsIdempotent() async throws {
        let closeCount = Locked<Int>(0)
        let context = makeTestContext(onClose: {
            closeCount.withLock { $0 += 1 }
        })

        try await context.close()
        try await context.close()

        // Bridge close should only be called once (second call short-circuits)
        #expect(closeCount.current == 1)
        #expect(await context.state == .closed)
    }

    @Test("close finishes the message stream")
    func closeFinishesStream() async throws {
        let capturedListener = Locked<(any MessageListener)?>(nil)

        let context = makeTestContext(captureListener: { listener in
            capturedListener.withLock { $0 = listener }
        })

        let stream = try await context.messages

        var listener: (any MessageListener)?
        for _ in 0 ..< 100 {
            listener = capturedListener.current
            if listener != nil { break }
            try await Task.sleep(for: .milliseconds(10))
        }

        guard let resolvedListener = listener else {
            Issue.record("Listener was not captured")
            return
        }

        resolvedListener.onMessage(message: Message(
            senderDid: "did:dht:alice",
            payload: Data("before-close".utf8),
            timestamp: 1_000_000,
            sequence: 1,
            contextId: "test-context-001",
            provenance: nil
        ))

        try await context.close()

        var received: [Message] = []
        for await message in stream {
            received.append(message)
        }

        #expect(received.count == 1)
    }

    // MARK: - Context state tests

    @Test("context initializes with active state from handle")
    func contextInitializesWithActiveState() async {
        let context = makeTestContext(state: "active")
        #expect(await context.state == .active)
    }

    @Test("context falls back to active for unknown state strings")
    func contextFallsBackToActiveForUnknownState() async {
        let context = makeTestContext(state: "unknown-state")
        #expect(await context.state == .active)
    }

    @Test("contextId matches the handle's context ID")
    func contextIdMatchesHandle() async {
        let context = makeTestContext(contextId: "my-unique-context")
        #expect(await context.contextId == "my-unique-context")
    }

    // MARK: - No force unwrap verification

    @Test("Context actor has no force unwraps in its public API")
    func noForceUnwrapsInPublicAPI() async throws {
        // This test verifies the contract by exercising all public methods
        // with valid inputs. If any internal force unwrap existed, it would
        // crash here rather than throwing.
        let context = makeTestContext()

        // send with valid payload
        try await context.send(Data("test".utf8))

        // messages returns a stream (does not crash)
        _ = try await context.messages

        // leave succeeds
        try await context.leave()

        // State is now closed
        #expect(await context.state == .closed)
    }

    // MARK: - Single-stream enforcement tests

    @Test("messages throws SCP-CTX-2003 when a stream is already active")
    func messagesThrowsWhenStreamAlreadyActive() async throws {
        let context = makeTestContext()

        _ = try await context.messages

        await #expect(throws: ScpError.self) {
            _ = try await context.messages
        }
    }

    @Test("messages throws SCP-CTX-2001 after close")
    func messagesThrowsAfterClose() async throws {
        let context = makeTestContext()

        _ = try await context.messages
        try await context.close()

        await #expect(throws: ScpError.self) {
            _ = try await context.messages
        }
    }

    // MARK: - ContextState tests

    @Test("ContextState enum cases exist")
    func contextStateCases() {
        // UniFFI-generated ContextState is not RawRepresentable; verify cases exist.
        let states: [ContextState] = [.creating, .active, .closing, .closed, .expired]
        #expect(states.count == 5)
    }

    @Test("ContextState is Equatable")
    func contextStateEquatable() {
        #expect(ContextState.active == ContextState.active)
        #expect(ContextState.closed == ContextState.closed)
        #expect(ContextState.active != ContextState.closed)
    }

    @Test("ContextState is Sendable")
    func contextStateSendable() async {
        // Verify ContextState can cross actor boundaries without issue.
        let state: ContextState = .active
        let task = Task { state }
        let result = await task.value
        #expect(result == .active)
    }

    // MARK: - Join context tests

    @Test("joinContext calls bridge with handle and identity")
    func joinContextRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let identity = Identity(noPointer: .init())
        var joinCalled = false

        let mockJoin: ContextBridge.JoinFn = { _, _ in
            joinCalled = true
        }

        try await joinContext(handle: handle, identity: identity, joinFn: mockJoin)
        #expect(joinCalled)
    }

    @Test("joinContext propagates bridge errors")
    func joinContextPropagatesErrors() async throws {
        let handle = ContextHandle(noPointer: .init())
        let identity = Identity(noPointer: .init())

        let mockJoin: ContextBridge.JoinFn = { _, _ in
            throw ScpError.Context(
                message: "cannot join context in Closed state",
                code: "SCP-CTX-2013"
            )
        }

        do {
            try await joinContext(handle: handle, identity: identity, joinFn: mockJoin)
            Issue.record("Expected joinContext to throw")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2013")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Economic policy roundtrip (#592)

    @Test("setEconomicPolicy + getEconomicPolicy roundtrip")
    func economicPolicyRoundtrip() async throws {
        let stored = Locked<String?>(nil)
        let setFn: ContextBridge.SetEconomicPolicyFn = { _, json in
            stored.withLock { $0 = json }
        }
        let getFn: ContextBridge.GetEconomicPolicyFn = { _ in
            stored.current
        }

        let handle = MockContextHandle()
        let context = Context(
            handle: handle,
            identity: Identity(noPointer: .init()),
            sendFn: { _, _, _ in },
            subscribeFn: { _, _ in },
            leaveFn: { _, _ in },
            closeFn: { _, _ in },
            setEconomicPolicyFn: setFn,
            getEconomicPolicyFn: getFn
        )

        // Initially nil.
        let initial = try await context.getEconomicPolicy()
        #expect(initial == nil)

        // Set a policy, then read it back.
        let policyJson = """
        {"locked":false,"cost_schedule":{"currency":[85,83,68,0]},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}
        """
        try await context.setEconomicPolicy(policyJson)
        let result = try await context.getEconomicPolicy()
        #expect(result == policyJson)
    }
} // end ContextTests
