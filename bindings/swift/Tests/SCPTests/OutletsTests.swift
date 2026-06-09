import Foundation
@testable import SCP
import Testing

// SCP-OUT-006 — outlet namespace tests.
//
// Focused on the Swift-specific surface introduced by the rename:
// SessionId UUIDv7 validation, caveat builders, DID / OutletId newtypes,
// InvocationHandle dual-consumption, OutletError shape.

struct SessionIdTests {
    @Test("newSessionId produces a canonical UUIDv7")
    func testNewSessionId() throws {
        let sid = newSessionId()
        #expect(sid.raw.count == 36)
        let versionChar = sid.raw[sid.raw.index(sid.raw.startIndex, offsetBy: 14)]
        #expect(versionChar == "7")
        try SessionId.validate(raw: sid.raw)
    }

    @Test("validate rejects non-UUIDv7 strings")
    func rejectNonUuid7() {
        #expect(throws: OutletError.self) {
            try SessionId.validate(raw: "sess-abc")
        }
    }

    @Test("validate rejects UUIDv4")
    func rejectUuidV4() {
        #expect(throws: OutletError.self) {
            try SessionId.validate(raw: "550e8400-e29b-41d4-a716-446655440000")
        }
    }

    @Test("validate rejects timestamps outside the 10-minute window")
    func rejectSkew() {
        let sid = newSessionId()
        let future = Date().addingTimeInterval(20 * 60)
        #expect(throws: OutletError.self) {
            try SessionId.validate(raw: sid.raw, now: future)
        }
        let past = Date().addingTimeInterval(-20 * 60)
        #expect(throws: OutletError.self) {
            try SessionId.validate(raw: sid.raw, now: past)
        }
    }

    @Test("Two generations produce independent rand_b tails")
    func csprngIndependence() {
        let first = newSessionId()
        let second = newSessionId()
        #expect(first != second)
        let tailFirst = String(first.raw.suffix(8))
        let tailSecond = String(second.raw.suffix(8))
        #expect(tailFirst != tailSecond)
    }
}

struct NewtypeTests {
    @Test("DID wraps raw string")
    func dID() {
        let did = DID("did:dht:z6MkAlice")
        #expect(did.raw == "did:dht:z6MkAlice")
    }

    @Test("OutletId wraps raw string")
    func testOutletId() {
        let id = OutletId("calculator")
        #expect(id.raw == "calculator")
    }

    @Test("DID and OutletId are distinct Swift types")
    func distinctTypes() {
        let did = DID("did:dht:alice")
        let outletId = OutletId("did:dht:alice")
        #expect(did.raw == outletId.raw)
        #expect(type(of: did) != type(of: outletId))
    }
}

struct CaveatBuilderTests {
    @Test("spendingCap sets amount fields")
    func testSpendingCap() {
        let caveat = Caveats.spendingCap(perCall: 100, cumulative: 1000).build()
        #expect(caveat.amountMaxPerCall == 100)
        #expect(caveat.amountMaxCumulative == 1000)
    }

    @Test("timeBounded sets time fields")
    func testTimeBounded() throws {
        let caveat = try Caveats.timeBounded(validFrom: 0, validUntil: 999).build()
        #expect(caveat.validFrom == 0)
        #expect(caveat.validUntil == 999)
    }

    @Test("timeBounded rejects oversized hoursOfDay mask")
    func timeBoundedHoursMask() {
        #expect(throws: OutletError.self) {
            _ = try Caveats.timeBounded(hoursOfDay: UInt32(1) << 25)
        }
    }

    @Test("rateLimited builder")
    func testRateLimited() {
        let caveat = Caveats.rateLimited(maxCalls: 10, rateWindow: 60).build()
        #expect(caveat.maxCalls == 10)
        #expect(caveat.rateWindow == 60)
    }

    @Test("forTarget builder")
    func testForTarget() {
        let caveat = Caveats.forTarget(
            allowedTargetDids: ["did:dht:a"],
            allowedAdapters: ["native"]
        ).build()
        #expect(caveat.allowedTargetDids == ["did:dht:a"])
        #expect(caveat.allowedAdapters == ["native"])
    }

    @Test("originKind rejects invalid values")
    func originKindInvalid() {
        #expect(throws: OutletError.self) {
            _ = try CaveatBuilder().originKind("Other")
        }
    }
}

struct InvocationHandleTests {
    @Test("aggregate awaits to the end chunk value")
    func testAggregate() async throws {
        let handle = InvocationHandle { yieldChunk, resolveAggregate, _ in
            let chunk = OutletStreamChunk(
                requestId: Data(count: 16),
                sequence: 0,
                payload: .end(aggregate: "{\"result\":42}", executionTimeMs: 0)
            )
            yieldChunk(chunk)
            resolveAggregate(Aggregate(valueJson: "{\"result\":42}", executionTimeMs: 0))
        }
        let agg = try await handle.aggregate
        #expect(agg.valueJson == "{\"result\":42}")
    }

    @Test("AsyncSequence iterates chunks")
    func asyncSequence() async throws {
        let handle = InvocationHandle { yieldChunk, resolveAggregate, _ in
            let chunk = OutletStreamChunk(
                requestId: Data(count: 16),
                sequence: 0,
                payload: .data(value: "{\"partial\":1}")
            )
            yieldChunk(chunk)
            let end = OutletStreamChunk(
                requestId: Data(count: 16),
                sequence: 1,
                payload: .end(aggregate: "{\"result\":1}", executionTimeMs: 0)
            )
            yieldChunk(end)
            resolveAggregate(Aggregate(valueJson: "{\"result\":1}"))
        }
        var count = 0
        for try await _ in handle {
            count += 1
        }
        #expect(count >= 1)
    }

    @Test("errors propagate via aggregate")
    func errorPropagation() async {
        let handle = InvocationHandle { _, _, rejectAggregate in
            rejectAggregate(OutletError.executionFailed(message: "boom", code: "SCP-TOOL-6200"))
        }
        do {
            _ = try await handle.aggregate
            Issue.record("expected aggregate to throw")
        } catch is OutletError {
            // ok
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }

    /// Bug 2 regression — the aggregate continuation must resolve even
    /// when the pump resolves SYNCHRONOUSLY (inside `init`, before the
    /// `aggregateTask` body has had a chance to attach its continuation).
    /// Before the `AggregateResolverBox` fix, the resolver was a bare
    /// captured `var` written by the (later-running) `aggregateTask` and
    /// read by the pump; a synchronous resolve dropped the resolution and
    /// `await handle.aggregate` hung forever. The box buffers the early
    /// resolve and replays it on attach, so this must complete promptly.
    @Test("aggregate resolves when pump resolves before the continuation attaches")
    func aggregateResolvesUnderSynchronousResolveRace() async throws {
        // The pump body runs synchronously during `init`; `resolveAggregate`
        // is therefore invoked BEFORE `aggregateTask` attaches.
        let handle = InvocationHandle { yieldChunk, resolveAggregate, _ in
            let end = OutletStreamChunk(
                requestId: Data(count: 16),
                sequence: 0,
                payload: .end(aggregate: "{\"raced\":true}", executionTimeMs: 3)
            )
            yieldChunk(end)
            resolveAggregate(Aggregate(valueJson: "{\"raced\":true}", executionTimeMs: 3))
        }
        let agg = try await handle.aggregate
        #expect(agg.valueJson == "{\"raced\":true}")
        #expect(agg.executionTimeMs == 3)
    }

    /// Bug 2 regression — same race on the reject path. A synchronous
    /// pre-attach reject must still surface through `await handle.aggregate`
    /// rather than hanging the leaked continuation.
    @Test("aggregate rejects when pump rejects before the continuation attaches")
    func aggregateRejectsUnderSynchronousRejectRace() async {
        let handle = InvocationHandle { _, _, rejectAggregate in
            rejectAggregate(OutletError.executionFailed(message: "raced-boom", code: "SCP-TOOL-6200"))
        }
        do {
            _ = try await handle.aggregate
            Issue.record("expected aggregate to throw under the synchronous reject race")
        } catch let OutletError.executionFailed(_, code) {
            #expect(code == "SCP-TOOL-6200")
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }

    /// Bug 2 — single-resume invariant. The carrier resolves the
    /// continuation exactly once; a resolve followed by a (losing) reject,
    /// or duplicate resolves, must not double-resume the continuation
    /// (which would trap at runtime). The first outcome wins.
    @Test("aggregate carrier is single-resume — first outcome wins")
    func aggregateCarrierIsSingleResume() async throws {
        let handle = InvocationHandle { _, resolveAggregate, rejectAggregate in
            resolveAggregate(Aggregate(valueJson: "{\"first\":1}", executionTimeMs: 0))
            // Losing duplicates — must be no-ops, not a double-resume trap.
            resolveAggregate(Aggregate(valueJson: "{\"second\":2}", executionTimeMs: 0))
            rejectAggregate(OutletError.executionFailed(message: "late", code: "SCP-TOOL-6200"))
        }
        let agg = try await handle.aggregate
        #expect(agg.valueJson == "{\"first\":1}")
    }
}
