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
}
