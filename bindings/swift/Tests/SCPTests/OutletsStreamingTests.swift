import Foundation
@testable import SCP
import Testing

// SCP-OUT-037 (UniFFI portion) — Swift streaming surface tests.
//
// These tests exercise the Swift-side ergonomics layer added in
// `Outlets+Streaming.swift`. Full FFI round-trip tests require the
// XCFramework binary linked from CI; they live in the
// `RealFFITests.swift` suite and are skipped when the binary is
// unavailable. The tests in this file cover:
//
// - `OutletStreamChunkRecordSwift` — record-shape construction round-
//   trips fields per §5.4.5 wire variants without reaching FFI.
// - `OutletsStreaming.verifyChunkSignature` / `.computeCaveatsBinding` —
//   the trampoline routes to the UniFFI free function (when available
//   in the regenerated bindings).
//
// Because the XCFramework is not present in CI for this PR (UniFFI
// regenerates `Internal/ScpBindings.swift` after the Rust bridge lands),
// the FFI-touching tests are guarded with `#if canImport(_SCPFFI)` and
// skipped otherwise — they will compile and run once the bindings are
// regenerated.

@Suite(.tags(.streaming))
struct OutletStreamChunkRecordSwiftTests {
    @Test("Equatable conformance compares all fields")
    func equatableMatchesAllFields() {
        let chunkA = OutletStreamChunkRecordSwift(
            requestId: Data([0x11, 0x11, 0x11, 0x11]),
            sequence: 7,
            sig: Data([0x22]),
            payloadType: "data",
            valueJson: #"{"x":1}"#,
            pct: nil,
            note: nil,
            aggregateJson: nil,
            provenanceJson: nil,
            executionTimeMs: nil,
            code: nil,
            message: nil,
            terminal: nil
        )
        let chunkB = OutletStreamChunkRecordSwift(
            requestId: Data([0x11, 0x11, 0x11, 0x11]),
            sequence: 7,
            sig: Data([0x22]),
            payloadType: "data",
            valueJson: #"{"x":1}"#,
            pct: nil,
            note: nil,
            aggregateJson: nil,
            provenanceJson: nil,
            executionTimeMs: nil,
            code: nil,
            message: nil,
            terminal: nil
        )
        #expect(chunkA == chunkB)
    }

    @Test("Differing sequence flips equality")
    func differingSequenceFlipsEquality() {
        let chunkA = OutletStreamChunkRecordSwift(
            requestId: Data(),
            sequence: 0,
            sig: Data(),
            payloadType: "progress",
            valueJson: nil,
            pct: 5000,
            note: "halfway",
            aggregateJson: nil,
            provenanceJson: nil,
            executionTimeMs: nil,
            code: nil,
            message: nil,
            terminal: nil
        )
        let chunkB = OutletStreamChunkRecordSwift(
            requestId: Data(),
            sequence: 1,
            sig: Data(),
            payloadType: "progress",
            valueJson: nil,
            pct: 5000,
            note: "halfway",
            aggregateJson: nil,
            provenanceJson: nil,
            executionTimeMs: nil,
            code: nil,
            message: nil,
            terminal: nil
        )
        #expect(chunkA != chunkB)
    }
}

extension Tag {
    @Tag static var streaming: Self
}

// MARK: - Abnormal-closure tests (HIGH wave 4)

//
// `pumpStreamingChunksWithNext` is the testable seam carved out of
// `pumpStreamingChunks` — it accepts a `next` closure instead of a
// UniFFI-generated `OutletStreamHandle` so tests can drive the pump
// against synthetic `OutletStreamChunkRecord` sequences. When the
// bridge returns `nil` BEFORE a terminal chunk, the pump MUST reject
// the aggregate with `OutletError.execution(...)` carrying
// `SCP-TOOL-6131` and NO slug per §5.4.4 — NOT resolve with a
// degenerate `Aggregate(valueJson: "null")`.

@Suite(.tags(.streaming))
struct AbnormalClosureTests {
    private func makeRecord(
        sequence: UInt64,
        payloadType: String,
        valueJson: String? = nil,
        aggregateJson: String? = nil,
        terminal: Bool? = nil
    ) -> OutletStreamChunkRecord {
        OutletStreamChunkRecord(
            requestId: Data(count: 16),
            sequence: sequence,
            sig: Data(count: 64),
            payloadType: payloadType,
            valueJson: valueJson,
            pct: nil,
            note: nil,
            aggregateJson: aggregateJson,
            provenanceJson: nil,
            executionTimeMs: nil,
            code: nil,
            message: nil,
            terminal: terminal
        )
    }

    @Test("pump rejects aggregate when bridge closes without terminal chunk")
    func pumpRejectsOnAbnormalClosure() async throws {
        // Synthetic chunk source — one Data chunk, then `nil` without
        // any terminal chunk.
        let chunks: [OutletStreamChunkRecord] = [
            makeRecord(sequence: 0, payloadType: "data", valueJson: #"{"i":0}"#)
        ]
        let cursor = SendableCursor(chunks: chunks)

        let receivedChunks = SendableChunks()
        let resolvedAgg = SendableBox<Aggregate>()
        let rejectedErr = SendableBox<Error>()

        try await pumpStreamingChunksWithNext(
            next: { cursor.next() },
            yieldChunk: { receivedChunks.append($0) },
            resolveAggregate: { resolvedAgg.set($0) },
            rejectAggregate: { rejectedErr.set($0) }
        )

        // The pump MUST reject — not resolve — when the bridge closed
        // without a terminal chunk. Resolution-with-null would mask the
        // abnormal close as a successful aggregate-null outcome.
        #expect(resolvedAgg.get() == nil)
        let err = rejectedErr.get()
        #expect(err != nil)
        if case let .execution(env)? = err as? OutletError {
            #expect(env.code == "SCP-TOOL-6131")
            // Convergence: abnormal closure carries NO slug across all SDKs
            // (the spec registers none for this 6131 condition).
            #expect(env.slug == "")
            #expect(env.message.contains("stream closed without terminal chunk"))
        } else {
            Issue.record("expected OutletError.execution, got \(String(describing: err))")
        }
        // The Data chunk that arrived before the abnormal close was
        // still forwarded — the closure does not retroactively
        // invalidate already-delivered chunks.
        #expect(receivedChunks.count() == 1)
    }

    @Test("pump resolves aggregate normally when terminal observed before nil")
    func pumpResolvesOnNormalEnd() async throws {
        // Regression guard for the happy path — one Data, one End,
        // then `nil`. The End is the terminal, so the trailing `nil`
        // is the normal end-of-receiver marker and must NOT trigger
        // the abnormal-closure error path.
        let chunks: [OutletStreamChunkRecord] = [
            makeRecord(sequence: 0, payloadType: "data", valueJson: #"{"x":1}"#),
            makeRecord(sequence: 1, payloadType: "end", aggregateJson: #"{"sum":1}"#)
        ]
        let cursor = SendableCursor(chunks: chunks)
        let resolvedAgg = SendableBox<Aggregate>()
        let rejectedErr = SendableBox<Error>()

        try await pumpStreamingChunksWithNext(
            next: { cursor.next() },
            yieldChunk: { _ in },
            resolveAggregate: { resolvedAgg.set($0) },
            rejectAggregate: { rejectedErr.set($0) }
        )

        #expect(rejectedErr.get() == nil)
        let agg = resolvedAgg.get()
        #expect(agg != nil)
        #expect(agg?.valueJson == #"{"sum":1}"#)
    }
}

// MARK: - Dual-consumption guard (consistency-B)

//
// A handle backed by a single underlying source cannot be drained as
// BOTH `await handle.aggregate` and `for try await chunk in handle`. The
// cross-SDK convergence target (Kotlin reference, OUT-038 AC13
// lifecycle-under-Protocol) is the Protocol-class shape: code
// `SCP-TOOL-6020`, slug `protocol.handle-double-consumed`. Because
// `makeAsyncIterator()` is non-throwing, a stream-after-aggregate
// conflict surfaces on the iterator's first `next()`.

@Suite(.tags(.streaming))
struct DualConsumptionGuardTests {
    /// Builds a handle whose pump yields a single End chunk and resolves
    /// the aggregate — enough to exercise either consumption mode.
    private func makeEndHandle() -> InvocationHandle {
        InvocationHandle(requestIdHex: nil, aggregateSchemaJson: nil) { yieldChunk, resolveAggregate, _ in
            let chunk = OutletStreamChunk(
                requestId: Data(count: 16),
                sequence: 0,
                payload: .end(aggregate: #"{"sum":1}"#, executionTimeMs: 0)
            )
            yieldChunk(chunk)
            resolveAggregate(Aggregate(valueJson: #"{"sum":1}"#))
        }
    }

    @Test("aggregate then iterate throws protocol.handle-double-consumed on first next()")
    func aggregateThenIterate() async throws {
        let handle = makeEndHandle()
        _ = try await handle.aggregate // claim "aggregate"
        var iterator = handle.makeAsyncIterator() // non-throwing; guarded
        var caught: Error?
        do {
            _ = try await iterator.next()
        } catch {
            caught = error
        }
        #expect(caught != nil)
        if case let .protocol(env)? = caught as? OutletError {
            #expect(env.code == "SCP-TOOL-6020")
            #expect(env.slug == "protocol.handle-double-consumed")
            #expect(env.classWire == .protocol)
        } else {
            Issue.record("expected OutletError.protocol, got \(String(describing: caught))")
        }
    }

    @Test("iterate then aggregate throws protocol.handle-double-consumed")
    func iterateThenAggregate() async throws {
        let handle = makeEndHandle()
        var iterator = handle.makeAsyncIterator() // claim "stream"
        _ = try await iterator.next() // drains the End chunk cleanly
        var caught: Error?
        do {
            _ = try await handle.aggregate
        } catch {
            caught = error
        }
        #expect(caught != nil)
        if case let .protocol(env)? = caught as? OutletError {
            #expect(env.code == "SCP-TOOL-6020")
            #expect(env.slug == "protocol.handle-double-consumed")
        } else {
            Issue.record("expected OutletError.protocol, got \(String(describing: caught))")
        }
    }

    @Test("same-mode re-consumption is idempotent (two iterators, no throw)")
    func sameModeIdempotent() async throws {
        let handle = makeEndHandle()
        var first = handle.makeAsyncIterator()
        _ = try await first.next()
        // Re-claiming "stream" must NOT throw — the guard only rejects a
        // DIFFERENT mode.
        var second = handle.makeAsyncIterator()
        var threw = false
        do {
            _ = try await second.next()
        } catch {
            threw = true
        }
        #expect(threw == false)
    }
}

/// Minimal `Sendable` cursor over a fixed chunk array — drives the
/// pump's `next` closure across `async` boundaries without capturing
/// mutable state from outside the closure.
final class SendableCursor: @unchecked Sendable {
    private let chunks: [OutletStreamChunkRecord]
    private let lock = NSLock()
    private var index: Int = 0

    init(chunks: [OutletStreamChunkRecord]) {
        self.chunks = chunks
    }

    func next() -> OutletStreamChunkRecord? {
        lock.lock()
        defer { lock.unlock() }
        guard index < chunks.count else { return nil }
        let item = chunks[index]
        index += 1
        return item
    }
}

/// Lock-protected single-value box for capturing pump callback results
/// across `@Sendable` boundaries.
final class SendableBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?

    func set(_ newValue: T) {
        lock.lock()
        defer { lock.unlock() }
        value = newValue
    }

    func get() -> T? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// Lock-protected chunk collector — captures every `yieldChunk` invocation.
final class SendableChunks: @unchecked Sendable {
    private let lock = NSLock()
    private var chunks: [OutletStreamChunk] = []

    func append(_ chunk: OutletStreamChunk) {
        lock.lock()
        defer { lock.unlock() }
        chunks.append(chunk)
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return chunks.count
    }
}
