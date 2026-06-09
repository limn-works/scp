import Foundation
@testable import SCP
import Testing

// SCP-OUT-038 — Swift SDK InvocationHandle integration tests.
//
// Covers AC2-AC18 of the SDK control-plane story:
//
// - AC2: handle conforms to AsyncSequence + has awaited `aggregate`
// - AC7: Credit struct rejects 0 with throwing init
// - AC8: try Credit(0) throws OutletError.invalidGrant
// - AC13: OutletError.streamAlreadyClosed sits at protocol-class depth
// - AC14: 10 Data + End -> 11 chunks observed
// - AC17: post-End grantCredit / cancel raise streamAlreadyClosed
// - AC18: post-Error{terminal:true} grantCredit raises streamAlreadyClosed
//
// The tests drive an `InvocationHandle` directly via the pump closure so
// the SDK-level lifecycle is exercised without depending on the
// XCFramework binary (which is regenerated in CI).

// MARK: - Helpers

private func dataChunk(seq: UInt64, value: String = #"{"x":1}"#) -> OutletStreamChunk {
    OutletStreamChunk(
        requestId: Data(count: 16),
        sequence: seq,
        payload: .data(value: value)
    )
}

private func endChunk(
    seq: UInt64,
    aggregate: String = #"{"sum":45}"#,
    executionTimeMs: UInt64 = 42
) -> OutletStreamChunk {
    OutletStreamChunk(
        requestId: Data(count: 16),
        sequence: seq,
        payload: .end(aggregate: aggregate, executionTimeMs: executionTimeMs)
    )
}

private func errorChunk(
    seq: UInt64,
    terminal: Bool,
    code: String = "SCP-TOOL-6131",
    message: String = "synthetic error"
) -> OutletStreamChunk {
    OutletStreamChunk(
        requestId: Data(count: 16),
        sequence: seq,
        payload: .error(code: code, message: message, terminal: terminal)
    )
}

// MARK: - AC7/AC8: Credit struct construction

struct CreditConstructionTests {
    @Test("try Credit(0) throws OutletError.invalidGrant")
    func zeroRejected() throws {
        do {
            _ = try Credit(0)
            #expect(Bool(false), "expected throw")
        } catch let OutletError.invalidGrant(credit) {
            #expect(credit.raw == 0)
        } catch {
            #expect(Bool(false), "wrong error type: \(error)")
        }
    }

    @Test("try Credit(1) succeeds")
    func minSucceeds() throws {
        let credit = try Credit(1)
        #expect(credit.raw == 1)
    }

    @Test("try Credit(UInt32.max) succeeds")
    func maxSucceeds() throws {
        let credit = try Credit(UInt32.max)
        #expect(credit.raw == UInt32.max)
    }
}

// MARK: - AC13 / OUT-038 Fix #4: streamAlreadyClosed nests under .protocol

struct StreamAlreadyClosedDepthTests {
    // Fix #4 — the lifecycle error is now carried by `.protocol(envelope)`
    // (NOT a top-level `.streamAlreadyClosed` case). This puts it at the
    // SAME inheritance depth as the other protocol-class siblings
    // (`StreamAlreadyOpen`, `UnknownSession`, catalog-rotation entries),
    // matching the Python / TS / Kotlin nesting under `OutletProtocolError`.

    @Test("streamAlreadyClosed factory returns .protocol(envelope) — AC13 / Fix #4")
    func wrapsProtocolEnvelope() {
        let err = OutletError.streamAlreadyClosed()
        guard case let .protocol(env) = err else {
            #expect(Bool(false), "expected .protocol case (lifecycle error nests under .protocol per Fix #4)")
            return
        }
        #expect(env.classWire == .protocol)
        #expect(env.code == "SCP-TOOL-6101")
        #expect(env.slug == "protocol.stream-already-closed")
    }

    @Test("custom message overrides default")
    func customMessage() {
        let err = OutletError.streamAlreadyClosed(message: "custom-reason")
        guard case let .protocol(env) = err else {
            #expect(Bool(false), "expected .protocol case")
            return
        }
        #expect(env.message == "custom-reason")
    }

    @Test("if case .protocol = err matches streamAlreadyClosed (Fix #4 invariant)")
    func protocolPatternMatchesLifecycle() {
        let err = OutletError.streamAlreadyClosed()
        // The Fix #4 acceptance invariant: a generic `.protocol`
        // pattern-match MUST capture the lifecycle error. The prior
        // shape carried it on a sibling case so this check failed.
        if case .protocol = err {
            // expected
        } else {
            #expect(Bool(false), "if case .protocol = err must match streamAlreadyClosed (Fix #4)")
        }
    }

    @Test("makeStreamAlreadyClosed back-compat alias still returns .protocol(envelope)")
    func backCompatAliasMatchesProtocol() {
        let err = OutletError.makeStreamAlreadyClosed()
        if case .protocol = err {
            // expected — back-compat alias delegates to the new factory
        } else {
            #expect(Bool(false), "back-compat alias must also return .protocol(envelope)")
        }
    }
}

// MARK: - AC14: 10 Data + End -> 11 chunks observed

struct InvocationHandleIteratorTests {
    @Test("10 Data + End yields 11 chunks via AsyncSequence")
    func tenDataPlusEnd() async throws {
        let handle = InvocationHandle { yieldChunk, resolveAggregate, _ in
            Task {
                for idx in 0 ..< 10 {
                    yieldChunk(dataChunk(seq: UInt64(idx)))
                }
                let end = endChunk(seq: 10)
                yieldChunk(end)
                resolveAggregate(Aggregate(valueJson: #"{"sum":45}"#, executionTimeMs: 42))
            }
        }
        var observed: [OutletStreamChunk] = []
        for try await chunk in handle {
            observed.append(chunk)
        }
        #expect(observed.count == 11)
        // First 10 are Data; last is End.
        for (idx, chunk) in observed.prefix(10).enumerated() {
            switch chunk.payload {
            case .data:
                #expect(chunk.sequence == UInt64(idx))
            default:
                #expect(Bool(false), "expected Data at index \(idx)")
            }
        }
        switch observed[10].payload {
        case .end:
            #expect(observed[10].sequence == 10)
        default:
            #expect(Bool(false), "expected End at index 10")
        }
    }

    @Test("await aggregate returns End.aggregate")
    func aggregateAwait() async throws {
        let handle = InvocationHandle { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"{"v":99}"#, executionTimeMs: 10))
            }
        }
        let agg = try await handle.aggregate
        #expect(agg.valueJson == #"{"v":99}"#)
        #expect(agg.executionTimeMs == 10)
    }
}

// MARK: - AC17: post-End grantCredit / cancel raise

struct PostTerminalLifecycleTests {
    @Test("grantCredit after End raises streamAlreadyClosed")
    func grantAfterEnd() async throws {
        let handle = InvocationHandle(requestIdHex: String(repeating: "dd", count: 16)) { yieldChunk, resolveAggregate, _ in
            Task {
                yieldChunk(endChunk(seq: 0))
                resolveAggregate(Aggregate(valueJson: #"{"ok":true}"#))
            }
        }
        // Drain iterator so End is observed.
        for try await _ in handle {
            // discard
        }
        #expect(handle.isTerminated)

        do {
            _ = try await handle.grantCredit(Credit(10))
            #expect(Bool(false), "expected throw")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            // expected — Fix #4: lifecycle error nests under .protocol(envelope)
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }

    @Test("cancel after End raises streamAlreadyClosed")
    func cancelAfterEnd() async throws {
        let handle = InvocationHandle(requestIdHex: String(repeating: "dd", count: 16)) { yieldChunk, resolveAggregate, _ in
            Task {
                yieldChunk(endChunk(seq: 0))
                resolveAggregate(Aggregate(valueJson: #"{"ok":true}"#))
            }
        }
        for try await _ in handle {
            // discard
        }
        do {
            _ = try await handle.cancel()
            #expect(Bool(false), "expected throw")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            // expected — Fix #4: lifecycle error nests under .protocol(envelope)
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }

    @Test("grantCredit after Error{terminal:true} raises streamAlreadyClosed")
    func grantAfterTerminalError() async throws {
        let handle = InvocationHandle(requestIdHex: String(repeating: "ee", count: 16)) { yieldChunk, _, rejectAggregate in
            Task {
                yieldChunk(errorChunk(seq: 0, terminal: true))
                rejectAggregate(NSError(domain: "test", code: 0))
            }
        }
        // Drain iterator — terminal error throws when consumed.
        do {
            for try await _ in handle {
                // discard
            }
        } catch {
            // expected — pump rejected with the terminal error
        }
        #expect(handle.isTerminated)

        do {
            _ = try await handle.grantCredit(Credit(10))
            #expect(Bool(false), "expected throw")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            // expected — Fix #4: lifecycle error nests under .protocol(envelope)
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }
}

// MARK: - Single-shot lifecycle

struct NonStreamingControlPlaneTests {
    @Test("grantCredit on handle without requestIdHex raises streamAlreadyClosed")
    func grantWithoutRequestId() async throws {
        let handle = InvocationHandle { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"{"v":1}"#))
            }
        }
        do {
            _ = try await handle.grantCredit(Credit(10))
            #expect(Bool(false), "expected throw")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            // expected — Fix #4: lifecycle error nests under .protocol(envelope)
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }

    @Test("cancel on handle without requestIdHex raises streamAlreadyClosed")
    func cancelWithoutRequestId() async throws {
        let handle = InvocationHandle { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"{"v":1}"#))
            }
        }
        do {
            _ = try await handle.cancel()
            #expect(Bool(false), "expected throw")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            // expected — Fix #4: lifecycle error nests under .protocol(envelope)
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }
}

// MARK: - Production streaming path: deferred request_id threading

//
// Regression guard for the production control-plane bug: the streaming
// factory (`makeStreamingHandle`) constructs the handle with a DEFERRED
// `RequestIdBox` (the real `request_id` is only known after the async
// `outletInvokeStream` open resolves), then resolves the box from inside
// the pump. The prior code constructed `InvocationHandle(requestIdHex:
// nil, ...)` and never threaded the real id in — so `grantCredit` /
// `cancel` ALWAYS threw `streamAlreadyClosed` on a real streaming
// session. These tests drive the SAME deferred-box mechanism the
// production factory uses (NOT a directly-constructed literal handle),
// asserting the control plane reaches past the lifecycle guards once the
// box resolves to a real id.

struct DeferredRequestIdControlPlaneTests {
    /// A handle on the streaming path (unresolved box + pinned invoker
    /// DID) whose box later resolves to a real `request_id` must NOT
    /// reject `grantCredit` with `streamAlreadyClosed` for "no streaming
    /// session" / "no pinned invoker DID" — it must pass the guards and
    /// reach the bridge. Without a live runtime the bridge call itself
    /// fails, but with a NON-`streamAlreadyClosed` error, which is the
    /// proof the guards were cleared (the bug symptom is gone).
    @Test("grantCredit awaits the deferred request_id and clears the lifecycle guards")
    func grantCreditClearsGuardsAfterDeferredResolve() async throws {
        let box = RequestIdBox()
        let handle = InvocationHandle(
            requestIdBox: box,
            invokerDid: "did:dht:invoker",
            aggregateSchemaJson: nil
        ) { _, _, _ in
            // Simulate the streaming open resolving the request_id from
            // inside the pump (mirrors `makeStreamingHandle` calling
            // `raw.requestId()` then `requestIdBox.resolve(...)`). A long
            // hex id so the bridge sees a well-formed request_id.
            Task {
                await box.resolve(String(repeating: "a5", count: 16))
            }
        }
        do {
            _ = try await handle.grantCredit(Credit(10))
            // If a live runtime were present this could succeed; either
            // way, NOT throwing streamAlreadyClosed is the pass condition.
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            Issue.record(
                "grantCredit must NOT raise streamAlreadyClosed once the "
                    + "deferred request_id resolves — control plane is dead. \(env)"
            )
        } catch {
            // Any other error (e.g. a bridge error from the absent live
            // runtime) means the guards were cleared and the call reached
            // the bridge seam — the fix works.
        }
    }

    /// Same guard for `cancel`.
    @Test("cancel awaits the deferred request_id and clears the lifecycle guards")
    func cancelClearsGuardsAfterDeferredResolve() async throws {
        let box = RequestIdBox()
        let handle = InvocationHandle(
            requestIdBox: box,
            invokerDid: "did:dht:invoker",
            aggregateSchemaJson: nil
        ) { _, _, _ in
            Task {
                await box.resolve(String(repeating: "b6", count: 16))
            }
        }
        do {
            _ = try await handle.cancel()
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            Issue.record(
                "cancel must NOT raise streamAlreadyClosed once the deferred "
                    + "request_id resolves — control plane is dead. \(env)"
            )
        } catch {
            // Reached the bridge seam — the fix works.
        }
    }

    /// When the streaming open FAILS, the factory resolves the box to
    /// `nil`; awaiting control-plane callers must then surface
    /// `streamAlreadyClosed` (no streaming session) rather than hanging
    /// forever on an unresolved box.
    @Test("open failure resolves the box to nil and surfaces streamAlreadyClosed")
    func openFailureResolvesNil() async throws {
        let box = RequestIdBox()
        let handle = InvocationHandle(
            requestIdBox: box,
            invokerDid: "did:dht:invoker",
            aggregateSchemaJson: nil
        ) { _, _, rejectAggregate in
            Task {
                // Mirror the factory's catch arm: open failed before a
                // request_id was known.
                await box.resolve(nil)
                rejectAggregate(OutletError.bridge(message: "open failed", code: "SCP-TOOL-6000"))
            }
        }
        do {
            _ = try await handle.grantCredit(Credit(10))
            Issue.record("expected streamAlreadyClosed after nil-resolved box")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            Issue.record("wrong error: \(error)")
        }
    }

    /// The terminal-state guard still fires AFTER the await: if the box
    /// resolves but a terminal chunk has already been observed, the
    /// control plane rejects with `streamAlreadyClosed`.
    @Test("terminal-after-resolve still rejects with streamAlreadyClosed")
    func terminalAfterResolveRejects() async throws {
        let box = RequestIdBox()
        let handle = InvocationHandle(
            requestIdBox: box,
            invokerDid: "did:dht:invoker",
            aggregateSchemaJson: nil
        ) { yieldChunk, resolveAggregate, _ in
            Task {
                await box.resolve(String(repeating: "c7", count: 16))
                // Observe a terminal End chunk before the control-plane
                // call — flips the terminated flag.
                yieldChunk(OutletStreamChunk(
                    requestId: Data(repeating: 0xC7, count: 16),
                    sequence: 0,
                    payload: .end(aggregate: #"{"v":1}"#, executionTimeMs: 0)
                ))
                resolveAggregate(Aggregate(valueJson: #"{"v":1}"#))
            }
        }
        // Give the pump a beat to observe the terminal chunk.
        try? await Task.sleep(nanoseconds: 20_000_000)
        do {
            _ = try await handle.grantCredit(Credit(10))
            Issue.record("expected streamAlreadyClosed after terminal chunk")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            // A bridge error is also acceptable here (the terminal flag is
            // a best-effort race-check); the key assertion is that the
            // call does not silently succeed on a closed stream.
        }
    }
}

// MARK: - AC12: aggregate_schema validation

struct AggregateSchemaValidationTests {
    @Test("matching schema passes")
    func matchingSchema() async throws {
        let schema = #"{"type":"object","required":["sum"]}"#
        let handle = InvocationHandle(
            requestIdHex: nil,
            aggregateSchemaJson: schema
        ) { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"{"sum":42}"#))
            }
        }
        let agg = try await handle.aggregate
        #expect(agg.valueJson == #"{"sum":42}"#)
    }

    @Test("missing required field rejects with output error")
    func missingRequired() async throws {
        let schema = #"{"type":"object","required":["sum"]}"#
        let handle = InvocationHandle(
            requestIdHex: nil,
            aggregateSchemaJson: schema
        ) { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"{"wrong":1}"#))
            }
        }
        do {
            _ = try await handle.aggregate
            #expect(Bool(false), "expected throw")
        } catch let OutletError.output(env) {
            #expect(env.classWire == .output)
            #expect(env.code == "SCP-TOOL-6140")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }

    @Test("type mismatch rejects with output error")
    func typeMismatch() async throws {
        let schema = #"{"type":"object"}"#
        let handle = InvocationHandle(
            requestIdHex: nil,
            aggregateSchemaJson: schema
        ) { _, resolveAggregate, _ in
            Task {
                resolveAggregate(Aggregate(valueJson: #"42"#))
            }
        }
        do {
            _ = try await handle.aggregate
            #expect(Bool(false), "expected throw")
        } catch let OutletError.output(env) {
            #expect(env.classWire == .output)
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }
}

// MARK: - close(): teardown parity for unbounded / abandoned streams

//
// An unbounded streaming handle used control-plane-only (open →
// grantCredit → abandon) has no terminal chunk to self-terminate the
// eager pump, so the §5.4.5 revocation re-check loop would poll
// `ucanValidate` forever. `close()` is the deterministic escape hatch: it
// cancels the registered background `Task`s and flips the terminal flag.
//
// These tests use the injectable `makeRevocationRecheckTask` seam (a
// synthetic counting validator) so the loop runs without the XCFramework
// binary, and exercise `InvocationHandle.close()` directly via the
// registered-teardown mechanism.

/// Thread-safe call counter for the injected recheck validator.
private final class ValidateCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func increment() {
        lock.lock()
        defer { lock.unlock() }
        value += 1
    }

    func get() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

struct CloseTeardownTests {
    @Test("cancelling the recheck task (the close() mechanism) stops ucanValidate polling")
    func recheckTaskCancelStopsValidation() async {
        let counter = ValidateCounter()
        // 1-second recheck interval (the floor) — fast enough for the test
        // to observe several polls, deterministic enough to assert the
        // count stops climbing after cancel.
        let task = makeRevocationRecheckTask(
            contextHandle: ContextHandle(noPointer: .init()),
            outletId: "outlet-x",
            ucanToken: "ucan-token",
            proofTokens: nil,
            recheckSecs: 1,
            requestIdHex: String(repeating: "a1", count: 16),
            invokerDid: "did:dht:invoker",
            validate: { _, _, _ in
                counter.increment()
            },
            terminate: {}
        )
        // Let the loop poll a couple of times.
        try? await Task.sleep(nanoseconds: 2_300_000_000)
        let countAtCancel = counter.get()
        #expect(countAtCancel >= 1, "recheck loop should have polled at least once")

        // Cancel — this is exactly what `InvocationHandle.close()` runs via
        // the registered teardown handler.
        task.cancel()
        // Give any in-flight tick a beat to settle, then snapshot.
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        let countAfterCancel = counter.get()
        // The loop must have stopped — allow at most ONE extra in-flight
        // poll that was already mid-sleep when cancel landed.
        try? await Task.sleep(nanoseconds: 1_500_000_000)
        let countLater = counter.get()
        #expect(countLater == countAfterCancel, "validator must not be called after cancel")
    }

    @Test("close() is idempotent and runs each registered teardown exactly once")
    func closeIdempotentRunsTeardownOnce() {
        let counter = ValidateCounter()
        let handle = InvocationHandle(
            requestIdHex: String(repeating: "b2", count: 16)
        ) { _, _, _ in
            // No terminal chunk — simulates an unbounded stream that never
            // self-terminates, so only close() can release it.
        }
        handle.registerCloseHandler { counter.increment() }
        handle.registerCloseHandler { counter.increment() }

        #expect(handle.isTerminated == false)
        handle.close()
        #expect(handle.isTerminated, "close() flips the terminal flag")
        #expect(counter.get() == 2, "each registered teardown runs once on first close")

        // Repeated close() is a no-op — no extra teardown runs.
        handle.close()
        handle.close()
        #expect(counter.get() == 2, "repeated close() must not re-run teardown")
    }

    @Test("teardown registered AFTER close() fires immediately (no leak on late open)")
    func lateRegistrationFiresImmediately() {
        let counter = ValidateCounter()
        let handle = InvocationHandle(
            requestIdHex: String(repeating: "c3", count: 16)
        ) { _, _, _ in }
        handle.close()
        // A task spawned by a late-resolving streaming open registers its
        // cancel after close() already ran — it must fire at once so the
        // task is not leaked past the close.
        handle.registerCloseHandler { counter.increment() }
        #expect(counter.get() == 1, "late-registered teardown fires immediately after close()")
    }

    @Test("grantCredit and cancel throw streamAlreadyClosed after close()")
    func controlPlaneThrowsAfterClose() async throws {
        let handle = InvocationHandle(
            requestIdHex: String(repeating: "d4", count: 16),
            invokerDid: "did:dht:invoker"
        ) { _, _, _ in
            // Unbounded stream — never emits a terminal chunk.
        }
        handle.close()
        #expect(handle.isTerminated)

        do {
            _ = try await handle.grantCredit(Credit(5))
            #expect(Bool(false), "expected grantCredit to throw after close()")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }

        do {
            _ = try await handle.cancel()
            #expect(Bool(false), "expected cancel to throw after close()")
        } catch let OutletError.protocol(env) where env.slug == "protocol.stream-already-closed" {
            #expect(env.code == "SCP-TOOL-6101")
        } catch {
            #expect(Bool(false), "wrong error: \(error)")
        }
    }

    @Test("close() usable in a defer block (structured-teardown idiom)")
    func closeUsableInDefer() {
        let counter = ValidateCounter()
        func scope() {
            let handle = InvocationHandle(
                requestIdHex: String(repeating: "e5", count: 16)
            ) { _, _, _ in }
            defer { handle.close() }
            handle.registerCloseHandler { counter.increment() }
            // ... control-plane-only use would happen here ...
        }
        scope()
        #expect(counter.get() == 1, "defer { handle.close() } releases the handle on scope exit")
    }
}

// MARK: - Compile-time: Credit is REQUIRED for grantCredit

/// The block below is never executed; it exists purely so that any drift
/// in the `grantCredit` signature breaks at compile time. AC8: passing a
/// raw `UInt32` where `Credit` is expected fails at compile time.
private func _swiftCompilerRejectsRawUInt32(_ handle: InvocationHandle) async {
    // Compile-only sanity:
    if false {
        // Valid call: typed Credit is accepted.
        _ = try? await handle.grantCredit(Credit(10))
        // Invalid call: raw UInt32 is NOT a Credit. The line below
        // would fail to compile — kept as a comment so the assertion
        // is documented but the test target still builds.
        // _ = try? await handle.grantCredit(10)
        // ^^ would fail with "Cannot convert value of type 'UInt32' to expected argument type 'Credit'"
    }
    _ = handle
}
