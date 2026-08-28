@testable import SCP
import XCTest

/// Contract tests for the §6.2.4 cross-context STREAMING saga SDK wrapper
/// (SCP-OUT-047) — the ``StreamingSagaHandle`` (`AsyncSequence` +
/// ``StreamingSagaHandle/aggregate()``) and the
/// ``Context/recoverStreamingSagaTruncatedClose(sagaId:callerDid:)`` entry point.
///
/// The handle-behavior tests exercise the SDK-layer contract — lazy open at
/// first pull, progressive drain, the single-consumer guard, sequence-gap
/// detection (no cross-context cancel plane), and open-rejection propagation —
/// against a scripted mock ``StreamingSagaNative`` that replays a JSON chunk
/// sequence in the exact §5.4.5 `OutletStreamChunk` wire shape. The recover test
/// is a bridge-linkage smoke test over a real in-memory `SCP` (mirroring
/// `OutletSagaTests`): it proves the wrapper forwards to the real bridge and
/// surfaces a typed `ScpError`.
///
/// Runtime-level guarantees (billed-count / execute-exactly-once) are proven
/// Rust-side and are NOT re-faked here. Mirrors the Python reference
/// `tests/test_outlets_streaming_saga.py`.
final class OutletStreamingSagaTests: XCTestCase {
    // MARK: - Wire-shape chunk builders (match §5.4.5 serialization)

    private var requestIdBytes: [Int] {
        Array(repeating: 0x01, count: 16)
    }

    private var sigBytes: [Int] {
        Array(repeating: 0x22, count: 64)
    }

    private func chunk(_ sequence: Int, _ payload: [String: Any]) throws -> Data {
        let object: [String: Any] = [
            "request_id": requestIdBytes,
            "sequence": sequence,
            "payload": payload,
            "sig": sigBytes
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func dataChunk(_ sequence: Int, _ value: Any) throws -> Data {
        try chunk(sequence, ["@type": "data", "value": value])
    }

    private func endChunk(_ sequence: Int, aggregate: Any, executionTimeMs: Int = 42) throws -> Data {
        try chunk(sequence, [
            "@type": "end",
            "aggregate": aggregate,
            "provenance": ["source": "outlet", "quality": "verified"],
            "execution_time_ms": executionTimeMs
        ])
    }

    private func errorChunk(_ sequence: Int, code: String, message: String, terminal: Bool = true) throws -> Data {
        try chunk(sequence, ["@type": "error", "code": code, "message": message, "terminal": terminal])
    }

    // MARK: - Handle construction helper

    private func makeHandle(_ native: any StreamingSagaNative) -> StreamingSagaHandle {
        StreamingSagaHandle(
            bridge: native,
            params: StreamingSagaOpenParams(
                callerDid: "did:dht:caller",
                outletRegistrationId: "outlet-reg-1",
                input: Data(#"{"a":1}"#.utf8),
                assertedNonceHex: String(repeating: "00", count: 16),
                timestampMs: 1_700_000_000_000,
                chainDepth: 0,
                ucanToken: "ucan-abc",
                proofTokens: nil,
                ucanProofId: nil,
                timeoutMs: nil,
                estimatedChunkCount: 8
            )
        )
    }

    // MARK: - Lazy open + progressive consumption

    func testOpenIsLazy() async throws {
        let native = try FakeSagaNative(chunks: [dataChunk(0, ["n": 1]), endChunk(1, aggregate: ["n": 1])])
        let handle = makeHandle(native)
        // Constructing the handle must not open the saga.
        let openCalls = await native.openCalls
        XCTAssertEqual(openCalls, 0)
        let sagaId = await handle.sagaId
        XCTAssertNil(sagaId)
    }

    func testProgressiveDrainThenTerminal() async throws {
        let native = try FakeSagaNative(chunks: [
            dataChunk(0, ["r": "a"]),
            dataChunk(1, ["r": "b"]),
            endChunk(2, aggregate: ["total": 2])
        ])
        let handle = makeHandle(native)

        var kinds: [String] = []
        for try await streamChunk in handle {
            kinds.append(streamChunk.kind)
        }
        XCTAssertEqual(kinds, ["data", "data", "end"])
        let openCalls = await native.openCalls
        XCTAssertEqual(openCalls, 1) // Opened exactly once for the whole drain.
        let sagaId = await handle.sagaId
        XCTAssertEqual(sagaId, "saga-1")
    }

    func testAggregateReturnsEndPayload() async throws {
        let native = try FakeSagaNative(chunks: [dataChunk(0, ["n": 1]), endChunk(1, aggregate: ["total": 99], executionTimeMs: 55)])
        let handle = makeHandle(native)
        let aggregate = try await handle.aggregate()
        XCTAssertEqual(aggregate.executionTimeMs, 55)
        XCTAssertEqual(aggregate.value["total"]?.intValue, 99)
    }

    // MARK: - Terminals: error chunk / gap / abnormal drop

    func testTerminalErrorChunkThrowsTypedOutletError() async throws {
        let native = try FakeSagaNative(chunks: [dataChunk(0, [:]), errorChunk(1, code: "SCP-OUTLET-6010", message: "boom")])
        let handle = makeHandle(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected a terminal Error chunk to throw")
        } catch let ScpError.Outlet(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6010")
        }
    }

    func testSequenceGapThrowsStreamGapWithoutCancel() async throws {
        // Sequence jumps 0 -> 2 (missing 1). There is no cross-context cancel op
        // on the StreamingSagaNative surface, so the gap must be a local terminal.
        let native = try FakeSagaNative(chunks: [dataChunk(0, [:]), dataChunk(2, [:])])
        let handle = makeHandle(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected a StreamGap for a non-contiguous sequence")
        } catch let OutletError.streamGap(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6131")
        }
    }

    func testAbnormalDropClosesWithoutEnd() async throws {
        let native = try FakeSagaNative(chunks: [dataChunk(0, [:])]) // no End, then nil
        let handle = makeHandle(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected protocolViolation for a stream that closed without End")
        } catch let OutletError.protocolViolation(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6100")
        }
    }

    // MARK: - Open rejection (caller-principal binding / saga terminal)

    func testOpenRejectionSurfacesOnFirstDrainAndReceiverNeverHandedOut() async throws {
        let native = FakeSagaNative(
            chunks: [],
            openError: ScpError.SagaAborted(
                msg: "[SCP-SAGA-13050] caller_did is not a member of the source context",
                code: "SCP-SAGA-13050",
                retryAfterMs: nil
            )
        )
        let handle = makeHandle(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected the open rejection to surface on first drain")
        } catch let ScpError.SagaAborted(_, code, _) {
            XCTAssertEqual(code, "SCP-SAGA-13050")
        }
        // The receiver is never handed out — the saga id stays nil.
        let sagaId = await handle.sagaId
        XCTAssertNil(sagaId)
    }

    // MARK: - Single-consumer guard

    func testSecondConcurrentDrainThrowsProtocolViolation() async throws {
        let gate = AsyncGate()
        let native = try GatedSagaNative(
            chunks: [dataChunk(0, [:]), endChunk(1, aggregate: [:])],
            gate: gate
        )
        let handle = makeHandle(native)

        async let first: Void = {
            for try await _ in handle {}
        }()
        // Wait until the first drain is parked inside pollNext, then race a second.
        await gate.waitUntilFirstPollStarted()
        do {
            _ = try await handle.aggregate()
            XCTFail("expected a concurrent second drain to throw protocolViolation")
        } catch OutletError.protocolViolation {
            // expected
        }
        await gate.release()
        _ = try await first
    }

    // MARK: - Recover truncated-close (bridge-linkage smoke test over real SCP)

    /// The `Context` recover wrapper forwards `sagaId` + `callerDid` to the real
    /// bridge. Without a live truncated saga, an unknown `sagaId` surfaces a typed
    /// `ScpError` — proving the wrapper reaches the bridge (mirrors the Kotlin
    /// end-to-end saga forwarding smoke test). Per-argument positional fidelity is
    /// asserted in the Rust/integration tests.
    func testRecoverForwardsToBridgeAndSurfacesTypedError() async throws {
        let scp = try SCP(storage: .inMemory)
        let identity = try await scp.identityCreate(custody: .inMemory)
        let params = ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write", "outlet:call:*", "outlet:register", "context:close"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            minProtocolVersion: 0,
            maxChainDepth: nil,
            maxNestingDepth: nil,
            sessionCap: nil,
            economicPolicy: nil,
            consequenceRulesJson: nil,
            consequenceConfigJson: nil
        )
        let context = try await Context.create(scp: scp, identity: identity, params: params)
        do {
            try await context.recoverStreamingSagaTruncatedClose(
                sagaId: "nonexistent-saga-id",
                callerDid: identity.did()
            )
            XCTFail("expected a typed ScpError for an unknown saga id")
        } catch is ScpError {
            // Any typed ScpError proves the call reached the real bridge.
        }
        try await scp.shutdown(timeoutMillis: 1000)
    }
}

// MARK: - Scripted mock bridges

/// A thread-safe scripted ``StreamingSagaNative`` stand-in (an actor).
///
/// `pollNext` plays back `chunks` in order then returns `nil`; `openSaga` calls
/// are counted. An optional injected `openError` models the UniFFI bridge
/// rejecting the open (caller-principal binding / saga terminal).
actor FakeSagaNative: StreamingSagaNative {
    private let chunks: [Data]
    private var index = 0
    private let sagaId: String
    private let openError: Error?
    private(set) var openCalls = 0

    init(chunks: [Data] = [], sagaId: String = "saga-1", openError: Error? = nil) {
        self.chunks = chunks
        self.sagaId = sagaId
        self.openError = openError
    }

    // swiftlint:disable:next function_parameter_count
    func openSaga(
        callerDid _: String,
        outletRegistrationId _: String,
        inputJson _: String,
        assertedNonceHex _: String,
        timestampMs _: UInt64,
        chainDepth _: UInt8,
        ucanToken _: String,
        proofTokens _: [String]?,
        ucanProofId _: String?,
        timeoutMs _: UInt32?,
        estimatedChunkCount _: UInt32?
    ) async throws -> String {
        openCalls += 1
        if let openError {
            throw openError
        }
        return sagaId
    }

    func pollNext(sagaId _: String) async throws -> Data? {
        guard index < chunks.count else {
            return nil
        }
        defer { index += 1 }
        return chunks[index]
    }
}

/// A gate that lets the first `pollNext` park so a second concurrent drain can
/// race the single-consumer guard deterministically.
actor AsyncGate {
    private var firstPollStarted = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func signalFirstPollStarted() {
        firstPollStarted = true
        for waiter in startWaiters {
            waiter.resume()
        }
        startWaiters.removeAll()
    }

    func waitUntilFirstPollStarted() async {
        if firstPollStarted {
            return
        }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func release() {
        released = true
        for waiter in releaseWaiters {
            waiter.resume()
        }
        releaseWaiters.removeAll()
    }

    func awaitRelease() async {
        if released {
            return
        }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }
}

/// A ``StreamingSagaNative`` whose FIRST `pollNext` parks on the gate after
/// signalling it started, so the single-consumer guard can be raced.
actor GatedSagaNative: StreamingSagaNative {
    private let chunks: [Data]
    private var index = 0
    private var polls = 0
    private let gate: AsyncGate

    init(chunks: [Data], gate: AsyncGate) {
        self.chunks = chunks
        self.gate = gate
    }

    // swiftlint:disable:next function_parameter_count
    func openSaga(
        callerDid _: String,
        outletRegistrationId _: String,
        inputJson _: String,
        assertedNonceHex _: String,
        timestampMs _: UInt64,
        chainDepth _: UInt8,
        ucanToken _: String,
        proofTokens _: [String]?,
        ucanProofId _: String?,
        timeoutMs _: UInt32?,
        estimatedChunkCount _: UInt32?
    ) async throws -> String {
        "saga-gated"
    }

    func pollNext(sagaId _: String) async throws -> Data? {
        polls += 1
        if polls == 1 {
            await gate.signalFirstPollStarted()
            await gate.awaitRelease()
        }
        guard index < chunks.count else {
            return nil
        }
        defer { index += 1 }
        return chunks[index]
    }
}
