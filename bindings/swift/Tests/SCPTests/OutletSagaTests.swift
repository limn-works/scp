@testable import SCP
import XCTest

/// Tests for the §6.2.4 cross-context outlet-invocation saga SDK wrapper
/// (`Context.invokeOutletCrossContextSaga`, PR-6c slice 3/4).
///
/// The Swift SDK surfaces the generated UniFFI types directly: the saga
/// terminal is the generated `SagaResult` (faithful nullable), and the
/// non-committed terminals are the generated `ScpError.Saga*` cases. Unlike
/// the Python/TS SDKs (which wrap untyped bridge errors into dedicated SDK
/// classes), there is no re-mapping layer here — the wrapper just
/// `async throws` and the typed error propagates. These tests therefore
/// exercise:
///   - the public type surface (SagaResult faithful pass-through incl. nil;
///     the three typed ScpError.Saga* cases carrying their fields), and
///   - the wrapper-layer guards that mirror the sibling
///     `invokeOutletCrossContext` (source-active + UTF-8 input), and
///   - end-to-end argument forwarding through the real UniFFI bridge.
///
/// The suite links the Rust binary built with `testing`, so
/// contexts and outlet registration run against the real engine.
final class OutletSagaTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    override func setUpWithError() throws {
        try super.setUpWithError()
        scp = try SCP(storage: .inMemory)
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    // MARK: - Helpers

    private func makeParams() -> ContextParams {
        ContextParams(
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
    }

    private func makeContext(identity: Identity) async throws -> Context {
        try await Context.create(scp: scp, identity: identity, params: makeParams())
    }

    /// 32 hex chars = 16 bytes — a well-formed §6.2.4 asserted-nonce input.
    private let nonceHex = String(repeating: "ab", count: 16)

    private func nowMs() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }

    // MARK: - SagaResult (D3: faithful nullable pass-through)

    /// A committed terminal carries the supervisor-minted `sagaId` plus the
    /// signed receipt and captured output bytes verbatim.
    func testSagaResultCarriesReceiptAndOutput() {
        let receipt = Data([0x01, 0x02, 0x03])
        let output = Data([0x04, 0x05])
        let result = SagaResult(sagaId: "saga-1", receipt: receipt, output: output)

        XCTAssertEqual(result.sagaId, "saga-1")
        XCTAssertEqual(result.receipt, receipt)
        XCTAssertEqual(result.output, output)
    }

    /// `receipt` and `output` are surfaced exactly as the bridge returns them
    /// — `nil` when absent, never synthesized.
    func testSagaResultPassesThroughNilReceiptAndOutput() {
        let result = SagaResult(sagaId: "saga-2", receipt: nil, output: nil)

        XCTAssertEqual(result.sagaId, "saga-2")
        XCTAssertNil(result.receipt)
        XCTAssertNil(result.output)
    }

    // MARK: - Typed terminals (D2: ScpError.Saga* surfaced directly)

    /// `SagaAborted` carries `msg`, `code`, and the rate-limit back-off hint
    /// `retryAfterMs` — a concrete cooldown when one exists.
    func testSagaAbortedCarriesRetryAfter() {
        let error = ScpError.SagaAborted(
            msg: "[SCP-SAGA-13001] prepare rejected",
            code: "SCP-SAGA-13001",
            retryAfterMs: 1500
        )
        guard case let ScpError.SagaAborted(msg, code, retryAfterMs) = error else {
            XCTFail("expected ScpError.SagaAborted, got \(error)")
            return
        }
        XCTAssertEqual(msg, "[SCP-SAGA-13001] prepare rejected")
        XCTAssertEqual(code, "SCP-SAGA-13001")
        XCTAssertEqual(retryAfterMs, 1500)
    }

    /// `retryAfterMs` is `nil` (never `0`) when no precise back-off instant
    /// exists — `0` would read as "retry immediately" and re-trip the limit.
    func testSagaAbortedPreservesNilRetryAfter() {
        let error = ScpError.SagaAborted(
            msg: "[SCP-SAGA-13002] hard limit",
            code: "SCP-SAGA-13002",
            retryAfterMs: nil
        )
        guard case let ScpError.SagaAborted(_, _, retryAfterMs) = error else {
            XCTFail("expected ScpError.SagaAborted, got \(error)")
            return
        }
        XCTAssertNil(retryAfterMs)
    }

    /// `SagaNeedsRepair` carries the durable `sagaId` operator-repair handle.
    func testSagaNeedsRepairCarriesSagaId() {
        let error = ScpError.SagaNeedsRepair(
            msg: "[SCP-SAGA-13065] commit retries exhausted",
            code: "SCP-SAGA-13065",
            sagaId: "saga-repair-7"
        )
        guard case let ScpError.SagaNeedsRepair(msg, code, sagaId) = error else {
            XCTFail("expected ScpError.SagaNeedsRepair, got \(error)")
            return
        }
        XCTAssertEqual(msg, "[SCP-SAGA-13065] commit retries exhausted")
        XCTAssertEqual(code, "SCP-SAGA-13065")
        XCTAssertEqual(sagaId, "saga-repair-7")
    }

    /// `SagaBusy` carries the contended context id that forced serialization.
    func testSagaBusyCarriesContendedContext() {
        let error = ScpError.SagaBusy(
            msg: "[SCP-SAGA-13066] participant set overlap",
            code: "SCP-SAGA-13066",
            contendedContext: "ctx-shared-42"
        )
        guard case let ScpError.SagaBusy(msg, code, contendedContext) = error else {
            XCTFail("expected ScpError.SagaBusy, got \(error)")
            return
        }
        XCTAssertEqual(msg, "[SCP-SAGA-13066] participant set overlap")
        XCTAssertEqual(code, "SCP-SAGA-13066")
        XCTAssertEqual(contendedContext, "ctx-shared-42")
    }

    // MARK: - Wrapper guards (mirror the sibling invokeOutletCrossContext)

    /// A non-active source context is rejected before any bridge call with
    /// `ScpError.Context` `SCP-CTX-2001`.
    func testSagaRejectsInactiveSourceContext() async throws {
        let identity = try await scp.identityCreate(custody: "in_memory")
        let source = try await makeContext(identity: identity)
        let target = try await makeContext(identity: identity)

        try await source.close()

        do {
            // The source-active guard fires before the registration id is ever
            // used, so a placeholder id is sufficient to exercise it.
            _ = try await source.invokeOutletCrossContextSaga(
                targetContext: target,
                callerDid: identity.did(),
                outletRegistrationId: "placeholder-registration-id",
                input: Data(#"{"city":"Berlin"}"#.utf8),
                assertedNonceHex: nonceHex,
                timestampMs: nowMs(),
                chainDepth: 0
            )
            XCTFail("expected ScpError.Context for an inactive source context")
        } catch let ScpError.Context(_, code) {
            XCTAssertEqual(code, "SCP-CTX-2001")
        }
    }

    /// Non-UTF-8 input is rejected at the wrapper boundary with
    /// `ScpError.Outlet` `SCP-OUTLET-6001` (mirrors the sibling's UTF-8 guard).
    func testSagaRejectsNonUtf8Input() async throws {
        let identity = try await scp.identityCreate(custody: "in_memory")
        let source = try await makeContext(identity: identity)
        let target = try await makeContext(identity: identity)

        // 0xFF is never a valid UTF-8 byte.
        let badInput = Data([0xFF, 0xFE, 0xFD])

        do {
            // The UTF-8 guard fires before the registration id is used.
            _ = try await source.invokeOutletCrossContextSaga(
                targetContext: target,
                callerDid: identity.did(),
                outletRegistrationId: "placeholder-registration-id",
                input: badInput,
                assertedNonceHex: nonceHex,
                timestampMs: nowMs(),
                chainDepth: 0
            )
            XCTFail("expected ScpError.Outlet for non-UTF-8 input")
        } catch let ScpError.Outlet(_, code) {
            XCTAssertEqual(code, "SCP-OUTLET-6001")
        }
    }

    // MARK: - End-to-end argument forwarding

    /// With an active source and target, the wrapper forwards all arguments
    /// past both guards into the real saga. Without bidirectional consent the
    /// supervisor reaches a non-committed terminal, so the call surfaces a
    /// typed `ScpError` — never the wrapper-layer guard codes. That proves the
    /// nine arguments (both handles, `callerDid`, `outletRegistrationId`,
    /// `inputJson`, nonce, timestamp, depth, optional proof) reach the bridge.
    ///
    /// This is a bridge-linkage smoke test: it confirms the call reaches the
    /// real bridge past both wrapper guards, but does not assert per-argument
    /// positional fidelity (a same-typed swap, e.g. `callerDid` ↔
    /// `outletRegistrationId`, would not be caught here — that assurance lives in
    /// the Rust/integration tests, since asserting it at this wrapper unit
    /// layer would require committed-saga bidirectional-consent setup).
    func testSagaForwardsArgumentsToBridge() async throws {
        try scp.configureLocalTransport(localDid: "did:key:z6MkSwiftSagaForwardTest")
        let identity = try await scp.identityCreate(custody: "in_memory")
        let source = try await makeContext(identity: identity)
        let target = try await makeContext(identity: identity)
        let outletId = try await target.registerOutlet(weatherOutlet(operatorDid: identity.did()))

        do {
            let result = try await source.invokeOutletCrossContextSaga(
                targetContext: target,
                callerDid: identity.did(),
                outletRegistrationId: outletId,
                input: Data(#"{"city":"Berlin","unit":"C"}"#.utf8),
                assertedNonceHex: nonceHex,
                timestampMs: nowMs(),
                chainDepth: 0,
                ucanProofId: nil
            )
            // A committed terminal (unlikely without consent setup) is still a
            // valid forwarding outcome: the bridge produced a SagaResult.
            XCTAssertFalse(result.sagaId.isEmpty, "committed saga must carry a sagaId")
        } catch let ScpError.Context(_, code) {
            XCTAssertNotEqual(code, "SCP-CTX-2001", "must forward past the source-active guard")
        } catch let ScpError.Outlet(_, code) {
            XCTAssertNotEqual(code, "SCP-OUTLET-6001", "must forward past the UTF-8 guard")
        } catch {
            // Any other ScpError (e.g. a typed Saga* terminal or a
            // supervisor-side rejection) means the call reached the real
            // bridge — the wrapper forwarded successfully.
            XCTAssertTrue(error is ScpError, "expected a typed ScpError from the bridge, got \(error)")
        }
    }

    // MARK: - Fixtures

    private func weatherOutlet(operatorDid: String) -> OutletDefinition {
        OutletDefinition(
            name: "weather",
            description: "Get current weather for a city",
            kind: .action,
            inputSchemaJson: #"{"type":"object","properties":{"city":{"type":"string"},"unit":{"type":"string"}},"required":["city"]}"#,
            outputSchemaJson: #"{"type":"object","properties":{"tempC":{"type":"number"},"condition":{"type":"string"}}}"#,
            operatorDid: operatorDid,
            testVectorsJson: "[]",
            implementationHash: nil,
            cost: nil
        )
    }
}
