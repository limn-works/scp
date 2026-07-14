@testable import SCP
import XCTest

/// Contract tests for the single-verb outlet streaming surface (SCP-OUT-038),
/// mirroring the Python reference suite `tests/test_outlets_streaming.py`.
///
/// These exercise the SDK-layer ``InvocationHandle`` contract — the
/// `AsyncSequence` + explicit ``InvocationHandle/aggregate()`` handle, the
/// ``Credit`` value type, ``InvocationHandle/grantCredit(_:)`` /
/// ``InvocationHandle/cancel()`` control-plane methods, and the lifecycle guard
/// — against a scripted mock ``OutletStreamNative`` that replays a JSON chunk
/// sequence in the exact §5.4.5 `OutletStreamChunk` wire shape (`serde_bytes`
/// fields as integer arrays).
///
/// The scripted bridge validates ALL of the SDK's iteration / aggregation /
/// control-plane / lifecycle logic without a live MLS stream. The LIVE wire path
/// (a real stream pumped over MLS with funded escrow and a granted capability)
/// is covered by the Rust C7 test in `crates/scp-ffi/src/outlet_stream.rs`; it
/// is NOT re-faked here.
final class OutletStreamingTests: XCTestCase {
    // MARK: - Credit value type

    func testValidCredit() throws {
        XCTAssertEqual(try Credit(1).value, 1)
        XCTAssertEqual(try Credit(10).value, 10)
        XCTAssertEqual(try Credit(UInt32.max).value, UInt32.max)
    }

    func testZeroThrowsInvalidGrant() {
        XCTAssertThrowsError(try Credit(0)) { error in
            guard case OutletError.invalidGrant = error else {
                return XCTFail("expected OutletError.invalidGrant, got \(error)")
            }
        }
        // Negative / >= 2**32 are unrepresentable as UInt32 — the type rejects
        // them at COMPILE time, so (unlike Python/TS) there is no runtime case to
        // test. `grantCredit` taking `Credit` (not UInt32) likewise makes a raw
        // integer a compile error.
    }

    func testCreditEqualityAndHashing() throws {
        XCTAssertEqual(try Credit(4), try Credit(4))
        XCTAssertNotEqual(try Credit(4), try Credit(5))
        XCTAssertEqual(try Credit(4).hashValue, try Credit(4).hashValue)
    }

    // MARK: - invoke() surface + lazy open

    func testInvokeReturnsHandleWithoutOpening() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 1]), endChunk(1, aggregate: ["n": 1])])
        let handle = invoke(native)
        XCTAssertTrue(handle is InvocationHandle)
        // Lazy open: invoke() must not have opened the stream yet.
        let openCalls = await native.openCalls
        XCTAssertTrue(openCalls.isEmpty)
    }

    // MARK: - Iteration + aggregation

    func testAsyncIteratesAllChunksIncludingProgress() async throws {
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 0]),
            progressChunk(1, pct: 5000, note: "halfway"),
            dataChunk(2, ["n": 1]),
            endChunk(3, aggregate: ["total": 2])
        ])
        let handle = invoke(native)

        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }

        XCTAssertEqual(collected.map(\.kind), ["data", "progress", "data", "end"])
        // Progress chunk is surfaced, not filtered.
        let progress = collected[1]
        XCTAssertEqual(progress.kind, "progress")
        XCTAssertEqual(progress.payload["pct"]?.intValue, 5000)
        XCTAssertEqual(progress.payload["note"]?.stringValue, "halfway")
        // Chunk decoding: sequence + opaque hex request_id/signature.
        XCTAssertEqual(collected[0].sequence, 0)
        XCTAssertEqual(collected[0].requestId, requestIdHex)
        XCTAssertEqual(collected[0].signature, sigHex)
        XCTAssertTrue(collected[3].isTerminal)
    }

    func testAggregateReturnsAggregate() async throws {
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 1]),
            endChunk(1, aggregate: ["total": 1], executionTimeMs: 77)
        ])
        let handle = invoke(native)

        let result = try await handle.aggregate()

        XCTAssertEqual(result.value, ["total": 1])
        XCTAssertEqual(result.executionTimeMs, 77)
        XCTAssertEqual(result.provenance, ["source": "outlet", "quality": "verified"])
    }

    func testAggregateAfterFullIterationReturnsCachedAggregate() async throws {
        // AC: 10 Data + End -> iterator yields 11 chunks AND aggregate() returns
        // End.aggregate (same handle, no re-drain).
        var chunks: [Data] = try (0 ..< 10).map { try dataChunk($0, ["n": $0]) }
        try chunks.append(endChunk(10, aggregate: ["total": 10]))
        let native = FakeNative(chunks: chunks)
        let handle = invoke(native)

        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }
        XCTAssertEqual(collected.count, 11)
        XCTAssertEqual(collected.filter { $0.kind == "data" }.count, 10)

        let result = try await handle.aggregate()
        XCTAssertEqual(result.value, ["total": 10])
    }

    func testAggregateThenIterateYieldsNothing() async throws {
        // Direction 2: aggregate-then-iterate yields nothing (already drained).
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 0]), endChunk(1, aggregate: ["n": 0])])
        let handle = invoke(native)

        _ = try await handle.aggregate()

        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }
        XCTAssertTrue(collected.isEmpty)
    }

    func testPartialIterateThenAggregateDrainsRest() async throws {
        // Direction 3: partial-iterate-then-aggregate drains the remaining
        // chunks and returns the executor's End.aggregate.
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 0]),
            dataChunk(1, ["n": 1]),
            endChunk(2, aggregate: ["total": 2])
        ])
        let handle = invoke(native)

        var seen = 0
        for try await _ in handle {
            seen += 1
            if seen == 1 { break }
        }
        XCTAssertEqual(seen, 1)

        let result = try await handle.aggregate()
        XCTAssertEqual(result.value, ["total": 2])
    }

    func testStreamOpensExactlyOnce() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 1]), endChunk(1, aggregate: ["n": 1])])
        let handle = invoke(native)
        for try await _ in handle {}
        let openCalls = await native.openCalls
        XCTAssertEqual(openCalls.count, 1)
        // open forwarded the caller identity + ucan + outlet id.
        XCTAssertEqual(openCalls[0].outletId, "outlet-1")
        XCTAssertEqual(openCalls[0].callerDid, "did:dht:caller")
        XCTAssertEqual(openCalls[0].ucanToken, "ucan-abc")
    }

    func testErrorTerminalThrowsTypedOutletErrorOnAggregate() async throws {
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 1]),
            errorChunk(1, code: "SCP-OUTLET-6130", message: "handler panic")
        ])
        let handle = invoke(native)

        do {
            _ = try await handle.aggregate()
            XCTFail("expected a terminal-error throw")
        } catch let ScpError.Outlet(msg, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6130")
            XCTAssertTrue(msg.contains("handler panic"), "message was \(msg)")
        }
    }

    func testStreamWithoutEndThrowsProtocolError() async throws {
        // Sender drops without a terminal chunk (pollNext -> nil).
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 1])])
        let handle = invoke(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected protocolViolation for a stream without End")
        } catch let OutletError.protocolViolation(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6100")
        }
    }

    func testCallerDidOverride() async throws {
        let native = try FakeNative(chunks: [endChunk(0, aggregate: ["ok": true])])
        let handle = invoke(native, callerDid: "did:dht:other")
        _ = try await handle.aggregate()
        let openCalls = await native.openCalls
        XCTAssertEqual(openCalls[0].callerDid, "did:dht:other")
    }
}

// MARK: - Control plane, lifecycle, and invariant tests

extension OutletStreamingTests {
    // MARK: - Control plane: grantCredit / cancel

    func testGrantCreditForwardsToBridge() async throws {
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 0]),
            dataChunk(1, ["n": 1]),
            endChunk(2, aggregate: ["n": 1])
        ])
        let handle = invoke(native)

        try await handle.grantCredit(Credit(4))

        let grantCalls = await native.grantCalls
        XCTAssertEqual(grantCalls.count, 1)
        XCTAssertEqual(grantCalls[0].handleId, "stream-1")
        XCTAssertEqual(grantCalls[0].callerDid, "did:dht:caller")
        XCTAssertEqual(grantCalls[0].grant, 4)
    }

    func testGrantCreditMidStreamReflected() async throws {
        // AC: call grantCredit mid-stream; the grant reaches the bridge and the
        // stream continues to its terminal.
        var chunks: [Data] = try (0 ..< 4).map { try dataChunk($0, ["n": $0]) }
        try chunks.append(endChunk(4, aggregate: ["total": 4]))
        let native = FakeNative(chunks: chunks)
        let handle = invoke(native)

        var seen = 0
        for try await _ in handle {
            seen += 1
            if seen == 2 { try await handle.grantCredit(Credit(8)) }
        }
        let grantCalls = await native.grantCalls
        XCTAssertEqual(grantCalls.count, 1)
        XCTAssertEqual(grantCalls[0].grant, 8)
        XCTAssertEqual(seen, 5)
    }

    func testCancelForwardsToBridge() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 0]), endChunk(1, aggregate: ["n": 0])])
        let handle = invoke(native)

        // Open the stream first (pull one chunk); cancel then signs at the bridge.
        // (cancel BEFORE any open is a local no-op — see testCancelBeforeOpen.)
        let iterator = handle.makeAsyncIterator()
        _ = try await iterator.next()
        try await handle.cancel()

        let cancelCalls = await native.cancelCalls
        XCTAssertEqual(cancelCalls.count, 1)
        XCTAssertEqual(cancelCalls[0].handleId, "stream-1")
        XCTAssertEqual(cancelCalls[0].callerDid, "did:dht:caller")
    }

    func testCancelMidStreamThenTerminal() async throws {
        // AC: cancel mid-stream; a terminal chunk still arrives and closes it.
        let native = try FakeNative(chunks: [
            dataChunk(0, ["n": 0]),
            dataChunk(1, ["n": 1]),
            endChunk(2, aggregate: ["cancelled": true])
        ])
        let handle = invoke(native)

        var seen = 0
        for try await _ in handle {
            seen += 1
            if seen == 1 { try await handle.cancel() }
        }
        let cancelCalls = await native.cancelCalls
        XCTAssertEqual(cancelCalls.count, 1)
        XCTAssertEqual(seen, 3)
    }

    // MARK: - Lifecycle guard: control plane after terminal

    func testGrantAfterEndThrowsStreamAlreadyClosed() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 1]), endChunk(1, aggregate: ["n": 1])])
        let handle = invoke(native)
        _ = try await handle.aggregate() // drain to End
        do {
            try await handle.grantCredit(Credit(10))
            XCTFail("expected streamAlreadyClosed")
        } catch let OutletError.streamAlreadyClosed(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6100")
        }
        let grantCalls = await native.grantCalls
        XCTAssertTrue(grantCalls.isEmpty)
    }

    func testCancelAfterEndThrowsStreamAlreadyClosed() async throws {
        let native = try FakeNative(chunks: [endChunk(0, aggregate: ["n": 1])])
        let handle = invoke(native)
        _ = try await handle.aggregate()
        do {
            try await handle.cancel()
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {
            // ok
        }
        let cancelCalls = await native.cancelCalls
        XCTAssertTrue(cancelCalls.isEmpty)
    }

    func testGrantAfterTerminalErrorThrowsStreamAlreadyClosed() async throws {
        let native = try FakeNative(chunks: [errorChunk(0, code: "SCP-OUTLET-6130", message: "boom", terminal: true)])
        let handle = invoke(native)
        // Consume the terminal error chunk via iteration (observable), which
        // closes the stream without throwing in the iterator.
        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }
        XCTAssertEqual(collected.last?.kind, "error")
        do {
            try await handle.grantCredit(Credit(10))
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {
            // ok
        }
    }

    func testCancelAfterEndViaIterationThrows() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 0]), endChunk(1, aggregate: ["n": 0])])
        let handle = invoke(native)
        for try await _ in handle {}
        do {
            try await handle.cancel()
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {
            // ok
        }
    }

    // MARK: - Bridge-error translation (UniFFI throws typed ScpError; it propagates)

    func testOpenUcanDenialSurfacesAsPermissionError() async throws {
        let native = FakeNative(openError: ScpError.Permission(msg: "authorization denied", code: "SCP-PERM-3001"))
        let handle = invoke(native)
        do {
            _ = try await handle.aggregate() // aggregate drains -> open rejects
            XCTFail("expected a permission error")
        } catch let ScpError.Permission(_, code) {
            XCTAssertEqual(code, "SCP-PERM-3001")
        }
    }

    func testOpenSchemaViolationSurfacesAsValidationError() async throws {
        let native = FakeNative(openError: ScpError.Validation(msg: "input schema", code: "SCP-VALID-7001"))
        let handle = invoke(native)
        do {
            for try await _ in handle {} // first drain opens -> rejects
            XCTFail("expected a validation error")
        } catch let ScpError.Validation(_, code) {
            XCTAssertEqual(code, "SCP-VALID-7001")
        }
    }

    func testPollMidDrainErrorSurfacesAsScpError() async throws {
        // Stream one Data chunk, then the bridge rejects the next poll mid-drain.
        let native = try FakeNative(
            chunks: [dataChunk(0, ["n": 0])],
            pollError: ScpError.Context(msg: "no active stream", code: "SCP-CTX-2001"),
            failPollAfter: 1
        )
        let handle = invoke(native)
        do {
            for try await _ in handle {}
            XCTFail("expected a context error mid-drain")
        } catch let ScpError.Context(_, code) {
            XCTAssertEqual(code, "SCP-CTX-2001")
        }
    }

    // MARK: - Concurrent-consumer guard

    func testSecondConcurrentDriverThrowsProtocolError() async throws {
        let native = BlockingPollNative()
        let handle = makeOutlets(native).invoke(
            outletId: "outlet-1",
            input: Data("{}".utf8),
            ucanToken: "ucan-abc"
        )

        let parked = expectation(description: "first poll parked")
        native.onParked = { parked.fulfill() }

        let firstIterator = handle.makeAsyncIterator()
        let first = Task { try await firstIterator.next() }
        await fulfillment(of: [parked], timeout: 2)

        // A second concurrent driver on the shared drain fails loud.
        let secondIterator = handle.makeAsyncIterator()
        do {
            _ = try await secondIterator.next()
            XCTFail("expected protocolViolation from the second concurrent driver")
        } catch OutletError.protocolViolation {
            // ok
        }

        native.release(nil) // let the legitimate first driver finish
        _ = try? await first.value
    }

    // MARK: - cancel() before first open is a local no-op close

    func testCancelBeforeOpenDoesNotOpenStream() async throws {
        let native = try FakeNative(chunks: [dataChunk(0, ["n": 0]), endChunk(1, aggregate: ["n": 0])])
        let handle = invoke(native)

        try await handle.cancel()

        // No stream was opened and no bridge cancel was signed.
        let openCalls = await native.openCalls
        let cancelCalls = await native.cancelCalls
        XCTAssertTrue(openCalls.isEmpty)
        XCTAssertTrue(cancelCalls.isEmpty)

        // The handle is now closed: further control-plane calls are guarded.
        do {
            try await handle.cancel()
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {}
        do {
            try await handle.grantCredit(Credit(1))
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {}
    }

    func testGrantCreditBeforeOpenOpensStream() async throws {
        // A grant needs a live stream, so grantCredit (unlike cancel) opens.
        let native = try FakeNative(chunks: [endChunk(0, aggregate: ["n": 0])])
        let handle = invoke(native)
        try await handle.grantCredit(Credit(2))
        let openCalls = await native.openCalls
        let grantCalls = await native.grantCalls
        XCTAssertEqual(openCalls.count, 1)
        XCTAssertEqual(grantCalls.count, 1)
        XCTAssertEqual(grantCalls[0].grant, 2)
    }

    // MARK: - Chunk parsing

    func testMalformedChunkThrowsProtocolViolation() {
        XCTAssertThrowsError(try OutletStreamChunk.parse(Data("not json".utf8))) { error in
            guard case OutletError.protocolViolation = error else {
                return XCTFail("expected protocolViolation, got \(error)")
            }
        }
    }

    func testHexStringRequestIdAccepted() throws {
        let raw = try JSONSerialization.data(withJSONObject: [
            "request_id": "aabb",
            "sequence": 0,
            "payload": ["@type": "data", "value": 1],
            "sig": "ccdd"
        ])
        let streamChunk = try OutletStreamChunk.parse(raw)
        XCTAssertEqual(streamChunk.requestId, "aabb")
        XCTAssertEqual(streamChunk.signature, "ccdd")
        XCTAssertEqual(streamChunk.kind, "data")
    }

    // MARK: - Public-surface invariant (SCP-OUT-006)

    func testNoInvokeStreamTokenInSources() throws {
        // Mirrors the SCP-OUT-006 grep AC:
        //   grep -rn 'invoke_stream\|invokeStream' bindings/ -> 0 (public surface)
        // Scans Sources/SCP excluding the generated Internal/ bridge; comment
        // lines that merely name the banned token are exempt (a doc-comment is
        // not a symbol).
        let thisFile = URL(fileURLWithPath: #filePath)
        let swiftRoot = thisFile
            .deletingLastPathComponent() // SCPTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // swift
        let sources = swiftRoot.appendingPathComponent("Sources/SCP")
        let manager = FileManager.default
        let enumerator = try XCTUnwrap(manager.enumerator(at: sources, includingPropertiesForKeys: nil))

        var offenders: [String] = []
        for case let url as URL in enumerator {
            guard url.pathExtension == "swift" else { continue }
            if url.pathComponents.contains("Internal") { continue }
            let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
                let trimmed = line.drop { $0 == " " || $0 == "\t" }
                if trimmed.hasPrefix("//") || trimmed.hasPrefix("*") || trimmed.hasPrefix("/*") { continue }
                if line.contains("invokeStream") || line.contains("invoke_stream") {
                    offenders.append("\(url.lastPathComponent): \(line)")
                }
            }
        }
        XCTAssertEqual(offenders, [], "public invokeStream found in: \(offenders)")
    }
}

// MARK: - AC6 conformance-vector smoke tests

/// AC6: the 7 cross-layer streaming vectors -> the SDK's expected terminal.
///
/// IMPORTANT boundary — where the terminal comes from:
///
/// - `credit_stall` and `cancellation` surface a terminal the BRIDGE
///   delivers. The mock plays a framework terminal (a `terminal: true` Error for
///   the credit stall; a cancel-ack `End` after the consumer cancels) and the
///   SDK faithfully surfaces `pollNext`'s terminal — the SDK cannot itself stall
///   an executor, so it does not synthesize these terminals.
/// - ONLY `sequence_gap` requires ACTIVE SDK-side detection: the drain tracks
///   the expected sequence, detects the hole ITSELF, signs the cancel through
///   the bridge, and throws ``OutletError/streamGap(msg:code:)``. The mock
///   feeds NO pre-baked cancel-ack for that vector (that would be test-gaming) —
///   the recorded cancel call proves the SDK generated it.
extension OutletStreamingTests {
    func testConformanceVectorsCoverExactlySevenNames() throws {
        let vectors = try loadStreamVectors()
        XCTAssertEqual(Set(vectors.keys), [
            "non_streaming", "multi_chunk", "cancellation", "error_terminal",
            "error_recoverable", "sequence_gap", "credit_stall"
        ])
    }

    func testVectorNonStreamingOk() async throws {
        let vector = try XCTUnwrap(try loadStreamVectors()["non_streaming"])
        let result = try await invoke(FakeNative(chunks: vector.chunkData)).aggregate()
        XCTAssertEqual(result.value, ["sum": 3])
    }

    func testVectorMultiChunkOk() async throws {
        // multi_chunk interleaves a non-billable Progress chunk (§5.4.5). The SDK
        // drain FORWARDS it (surfaced, not filtered), the monotonicity cursor
        // advances across it, and the stream still closes Ok.
        let vector = try XCTUnwrap(try loadStreamVectors()["multi_chunk"])
        let handle = invoke(FakeNative(chunks: vector.chunkData))
        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }
        XCTAssertTrue(
            collected.contains { $0.kind == "progress" },
            "the Progress chunk is yielded through the SDK drain"
        )
        XCTAssertEqual(collected.last?.kind, "end", "the stream closes Ok with End")
        let result = try await handle.aggregate()
        XCTAssertEqual(result.value, ["total": 10])
    }

    func testVectorErrorRecoverableOk() async throws {
        // The non-terminal Error (seq1) is yielded as a chunk but does NOT close.
        let vector = try XCTUnwrap(try loadStreamVectors()["error_recoverable"])
        let handle = invoke(FakeNative(chunks: vector.chunkData))
        var collected: [OutletStreamChunk] = []
        for try await streamChunk in handle {
            collected.append(streamChunk)
        }
        XCTAssertEqual(collected.map(\.kind), ["data", "error", "data", "data", "end"])
        XCTAssertEqual(collected[1].payload["terminal"]?.boolValue, false)
        let result = try await handle.aggregate()
        XCTAssertEqual(result.value, ["recovered": true])
    }

    func testVectorErrorTerminalRaises6130() async throws {
        let vector = try XCTUnwrap(try loadStreamVectors()["error_terminal"])
        XCTAssertEqual(vector.expectedErrorCode, "SCP-OUTLET-6130")
        do {
            _ = try await invoke(FakeNative(chunks: vector.chunkData)).aggregate()
            XCTFail("expected a terminal-error throw")
        } catch let ScpError.Outlet(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6130")
        }
    }

    func testVectorCreditStallRaises6133() async throws {
        // Bridge-delivered terminal: mock plays data seq0 then a framework Error
        // seq1 {terminal:true, code 6133}. The SDK surfaces it faithfully.
        let vector = try XCTUnwrap(try loadStreamVectors()["credit_stall"])
        XCTAssertEqual(vector.expectedErrorCode, "SCP-OUTLET-6133")
        do {
            _ = try await invoke(FakeNative(chunks: vector.chunkData)).aggregate()
            XCTFail("expected a terminal-error throw")
        } catch let ScpError.Outlet(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6133")
        }
    }

    func testVectorCancellationReachesTerminal() async throws {
        // Bridge-delivered terminal: consumer cancels after chunk index 1; the
        // mock plays through to its cancel-ack End. The SDK records the cancel
        // and surfaces the bridge's terminal (Cancelled).
        let vector = try XCTUnwrap(try loadStreamVectors()["cancellation"])
        let native = FakeNative(chunks: vector.chunkData)
        let handle = invoke(native)
        var idx = 0
        for try await _ in handle {
            if idx == 1 { try await handle.cancel() }
            idx += 1
        }
        let cancelCalls = await native.cancelCalls
        XCTAssertEqual(cancelCalls.count, 1)
        XCTAssertEqual(idx, vector.chunkData.count)
        let result = try await handle.aggregate()
        XCTAssertEqual(result.value, ["cancelled": true])
    }

    func testVectorSequenceGapDetectedSignedCancelRaises6131() async throws {
        // ACTIVE SDK detection: mock plays data seq0, seq1, seq3 (seq2 MISSING).
        // The drain detects the gap at seq3, itself signs a cancel through the
        // bridge, and throws streamGap(6131). NO pre-baked cancel-ack is fed.
        let vector = try XCTUnwrap(try loadStreamVectors()["sequence_gap"])
        XCTAssertEqual(vector.expectedErrorCode, "SCP-OUTLET-6131")
        let native = FakeNative(chunks: vector.chunkData)
        let handle = invoke(native)
        do {
            _ = try await handle.aggregate()
            XCTFail("expected a streamGap throw")
        } catch let OutletError.streamGap(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6131")
        }
        // The SDK ITSELF signed the receiver cancel (not fed by the mock).
        let cancelCalls = await native.cancelCalls
        XCTAssertEqual(cancelCalls.count, 1)
        // Terminal cache: the gap is sticky and control-plane is now guarded.
        do {
            _ = try await handle.aggregate()
            XCTFail("expected cached streamGap")
        } catch OutletError.streamGap {}
        do {
            try await handle.grantCredit(Credit(1))
            XCTFail("expected streamAlreadyClosed")
        } catch OutletError.streamAlreadyClosed {}
    }
}

// MARK: - Wire-shape chunk builders + invocation helpers

private extension OutletStreamingTests {
    /// 16-byte request_id, all `0x01` (mirrors the Python `_REQUEST_ID`).
    var requestIdBytes: [Int] {
        [Int](repeating: 1, count: 16)
    }

    /// 64-byte signature, all `0x22` (mirrors the Python `_SIG`).
    var sigBytes: [Int] {
        [Int](repeating: 0x22, count: 64)
    }

    var requestIdHex: String {
        String(repeating: "01", count: 16)
    }

    var sigHex: String {
        String(repeating: "22", count: 64)
    }

    /// Serializes one OutletStreamChunk exactly as `outletStreamPollNext`
    /// returns it: request_id / sig as `serde_bytes` integer arrays, payload
    /// internally tagged by `@type`.
    func chunk(_ sequence: Int, _ payload: [String: Any]) throws -> Data {
        let object: [String: Any] = [
            "request_id": requestIdBytes,
            "sequence": sequence,
            "payload": payload,
            "sig": sigBytes
        ]
        return try JSONSerialization.data(withJSONObject: object)
    }

    func dataChunk(_ sequence: Int, _ value: Any) throws -> Data {
        try chunk(sequence, ["@type": "data", "value": value])
    }

    func progressChunk(_ sequence: Int, pct: Int, note: String? = nil) throws -> Data {
        var payload: [String: Any] = ["@type": "progress", "pct": pct]
        if let note { payload["note"] = note }
        return try chunk(sequence, payload)
    }

    func endChunk(_ sequence: Int, aggregate: Any, executionTimeMs: Int = 42) throws -> Data {
        try chunk(sequence, [
            "@type": "end",
            "aggregate": aggregate,
            "provenance": ["source": "outlet", "quality": "verified"],
            "execution_time_ms": executionTimeMs
        ])
    }

    func errorChunk(_ sequence: Int, code: String, message: String, terminal: Bool = true) throws -> Data {
        try chunk(sequence, ["@type": "error", "code": code, "message": message, "terminal": terminal])
    }

    func makeOutlets(_ native: OutletStreamNative, callerDid: String = "did:dht:caller") -> Outlets {
        Outlets(bridge: native, defaultCallerDid: callerDid)
    }

    func invoke(_ native: FakeNative, callerDid: String? = nil) -> InvocationHandle {
        makeOutlets(native).invoke(
            outletId: "outlet-1",
            input: Data(#"{"q":"x"}"#.utf8),
            ucanToken: "ucan-abc",
            callerDid: callerDid
        )
    }

    // MARK: - AC6 conformance-vector loading

    /// One decoded conformance vector: its scripted chunk-byte playback plus the
    /// expected terminal, loaded from the single source of truth
    /// `tests/conformance/vectors/outlet_stream_vectors.json`.
    struct StreamVector {
        let name: String
        let chunkData: [Data]
        let expectedEndStatus: String
        let expectedErrorCode: String?
    }

    /// The repo-root vectors file, resolved by walking up from this test file
    /// (`.../bindings/swift/Tests/SCPTests/…` → repo root).
    var vectorsFileURL: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // SCPTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // swift
            .deletingLastPathComponent() // bindings
            .deletingLastPathComponent() // repo root
            .appendingPathComponent("tests/conformance/vectors/outlet_stream_vectors.json")
    }

    /// Loads the 7 vectors, serializing each chunk into the mock's wire bytes
    /// via the same `chunk(_:_:)` builder the other smoke tests use.
    func loadStreamVectors() throws -> [String: StreamVector] {
        let raw = try Data(contentsOf: vectorsFileURL)
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: raw) as? [String: Any])
        let vectors = try XCTUnwrap(root["vectors"] as? [[String: Any]])
        var out: [String: StreamVector] = [:]
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            let chunks = try XCTUnwrap(vector["chunks"] as? [[String: Any]])
            let chunkData: [Data] = try chunks.map { entry in
                let seq = try XCTUnwrap(entry["sequence"] as? Int)
                let payload = try XCTUnwrap(entry["payload"] as? [String: Any])
                return try chunk(seq, payload)
            }
            out[name] = try StreamVector(
                name: name,
                chunkData: chunkData,
                expectedEndStatus: XCTUnwrap(vector["expected_end_status"] as? String),
                expectedErrorCode: vector["expected_error_code"] as? String
            )
        }
        return out
    }
}

// MARK: - Recorded control-plane calls

struct RecordedOpenCall {
    let outletId: String
    let callerDid: String
    let ucanToken: String
    let estimatedChunkCount: UInt32?
}

struct RecordedGrantCall {
    let handleId: String
    let callerDid: String
    let grant: UInt32
}

struct RecordedCancelCall {
    let handleId: String
    let callerDid: String
}

// MARK: - Scripted mock bridges

/// A thread-safe scripted ``OutletStreamNative`` stand-in (an actor).
///
/// `pollNext` plays back `chunks` in order then returns `nil`; open / grant /
/// cancel calls are recorded for assertions. Optional injected errors model the
/// UniFFI bridge rejecting an open or a mid-drain poll.
actor FakeNative: OutletStreamNative {
    private let chunks: [Data]
    private var index = 0
    private let handleId: String
    private let openError: Error?
    private let pollError: Error?
    private let failPollAfter: Int?
    private var pollCount = 0

    private(set) var openCalls: [RecordedOpenCall] = []
    private(set) var grantCalls: [RecordedGrantCall] = []
    private(set) var cancelCalls: [RecordedCancelCall] = []

    init(
        chunks: [Data] = [],
        handleId: String = "stream-1",
        openError: Error? = nil,
        pollError: Error? = nil,
        failPollAfter: Int? = nil
    ) {
        self.chunks = chunks
        self.handleId = handleId
        self.openError = openError
        self.pollError = pollError
        self.failPollAfter = failPollAfter
    }

    func openStream(
        outletId: String,
        inputJson _: String,
        callerDid: String,
        ucanToken: String,
        proofTokens _: [String]?,
        spendingUcan _: String?,
        timeoutMs _: UInt32?,
        estimatedChunkCount: UInt32?
    ) async throws -> String {
        openCalls.append(RecordedOpenCall(
            outletId: outletId,
            callerDid: callerDid,
            ucanToken: ucanToken,
            estimatedChunkCount: estimatedChunkCount
        ))
        if let openError { throw openError }
        return handleId
    }

    func pollNext(handleId _: String) async throws -> Data? {
        pollCount += 1
        if let failPollAfter, pollCount > failPollAfter, let pollError { throw pollError }
        guard index < chunks.count else { return nil }
        let next = chunks[index]
        index += 1
        return next
    }

    func grantCredit(handleId: String, callerDid: String, grant: UInt32) async throws {
        grantCalls.append(RecordedGrantCall(handleId: handleId, callerDid: callerDid, grant: grant))
    }

    func cancel(handleId: String, callerDid: String) async throws {
        cancelCalls.append(RecordedCancelCall(handleId: handleId, callerDid: callerDid))
    }
}

/// A mock whose `pollNext` PARKS on a continuation until the test releases it —
/// letting a test deterministically interleave a second concurrent drive while
/// the first is suspended mid-poll (the single-consumer guard).
final class BlockingPollNative: OutletStreamNative, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data?, Error>?
    private let handleId = "stream-1"

    /// Invoked once the first `pollNext` has parked. Set by the test to fulfill
    /// an expectation.
    var onParked: (() -> Void)?

    func openStream(
        outletId _: String,
        inputJson _: String,
        callerDid _: String,
        ucanToken _: String,
        proofTokens _: [String]?,
        spendingUcan _: String?,
        timeoutMs _: UInt32?,
        estimatedChunkCount _: UInt32?
    ) async throws -> String {
        handleId
    }

    func pollNext(handleId _: String) async throws -> Data? {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            continuation = cont
            let callback = onParked
            lock.unlock()
            callback?()
        }
    }

    /// Resumes the parked `pollNext`, returning `data` (pass `nil` for a clean
    /// terminal).
    func release(_ data: Data?) {
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(returning: data)
    }

    func grantCredit(handleId _: String, callerDid _: String, grant _: UInt32) async throws {}

    func cancel(handleId _: String, callerDid _: String) async throws {}
}
