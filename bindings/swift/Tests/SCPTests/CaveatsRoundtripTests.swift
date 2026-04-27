// CaveatsRoundtripTests.swift — SCP-OUT-023 AC-7 conformance for the Swift SDK.
//
// Mirrors `bindings/python/tests/test_caveats_roundtrip.py`. Builds an
// `InvocationCaveats` value through the SDK, mints a UCAN through the real
// UniFFI bridge (`UcanBridge.defaultMint` → `ucanMint`), decodes the
// returned JWT's payload segment, and asserts every populated caveat field
// surfaces in `payload.nb` byte-for-byte.
//
// The test skips cleanly when the native `ScpFFI.xcframework` is not
// linked (mirrors `pytest.importorskip` in the Python conformance test
// and the `requireFFI()` pattern used elsewhere in `RealFFITests.swift`).
//
// Provenance:
//   - .docs/prds/outlet.json — SCP-OUT-023 AC-7
//   - .docs/specs/07-trust-validation-and-capabilities.md §7.3.8
//   - bindings/python/tests/test_caveats_roundtrip.py (reference)

import Foundation
@testable import SCP
import Testing

// MARK: - FFI availability guard (mirrors RealFFITests.swift)

/// Returns `true` if the native Rust FFI library is linked and callable.
/// Probes a synchronous, infallible UniFFI function to detect availability
/// without crashing when the dylib is absent.
private let isFFIAvailable: Bool = {
    #if canImport(scpFFI)
        let result = discoveryNormalizeAddress(address: "  TEST  ")
        return result == "test"
    #else
        return false
    #endif
}()

/// Error thrown to skip tests when FFI is unavailable. Mirrors the pattern
/// in `RealFFITests.swift`.
private struct FFISkipError: Error {}

/// Skips the current test when the native FFI library is unavailable.
private func requireFFI() throws {
    guard isFFIAvailable else { throw FFISkipError() }
}

// MARK: - Helpers

/// Decodes a base64url-encoded UTF-8 segment, applying padding fixup.
private func base64urlDecode(_ input: String) throws -> Data {
    var b64 = input.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let padCount = (4 - b64.count % 4) % 4
    b64 += String(repeating: "=", count: padCount)
    guard let data = Data(base64Encoded: b64) else {
        throw FFISkipError()
    }
    return data
}

/// Decodes the JWT payload segment (middle dot-segment) into a JSON object.
private func decodeJwtPayload(_ encoded: String) throws -> [String: Any] {
    let parts = encoded.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else {
        throw NSError(
            domain: "CaveatsRoundtripTests",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "expected 3 JWT segments, got \(parts.count)"]
        )
    }
    let payloadData = try base64urlDecode(String(parts[1]))
    guard let obj = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
        throw NSError(
            domain: "CaveatsRoundtripTests",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "JWT payload is not a JSON object"]
        )
    }
    return obj
}

/// Creates a `ContextParams` with the cross-delegation-friendly ceiling.
private func makeCtxParams(ceiling: [String]) -> ContextParams {
    ContextParams(
        mode: .encrypted,
        ceiling: ceiling,
        ceilingPolicy: .immutable,
        governance: .singleAdmin,
        memoryScope: .full,
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

// MARK: - SCP-OUT-023 AC-7 Tests

struct CaveatsRoundtripTests {
    /// §7.3.8 mint-limit: at most MAX_POPULATED_CAVEATS = 8 non-origin_kind
    /// fields populated per envelope (origin_kind is structural and exempt).
    /// This first test populates 8 budgeted fields + originKind — the
    /// maximum mintable shape — and asserts every field round-trips through
    /// the JWT `nb` field.
    @Test("FFI: 8 budgeted caveats + originKind round-trip via UCAN nb (SCP-OUT-023 AC-7)")
    func caveatsRoundTripPrimary() async throws {
        try requireFFI()

        // Cross-delegation: admin mints for member (avoids ADR-039 self-mint).
        let admin = try await createIdentity(custody: "in_memory")
        let member = try await createIdentity(custody: "in_memory")
        let handle = try await contextCreate(
            identity: admin,
            params: makeCtxParams(ceiling: ["messages:read", "messages:write"])
        )

        var caveats = InvocationCaveats()
        caveats.amountMaxPerCall = 100
        caveats.amountMaxCumulative = 1000
        caveats.validFrom = 1_700_000_000
        caveats.validUntil = 1_700_003_600
        caveats.maxCalls = 42
        caveats.rateWindow = 60 // wrapped to {max: 1, windowSecs: 60} on the wire
        caveats.allowedAdapters = ["native", "openai-compatible"]
        caveats.allowedTargetDids = ["did:dht:zMember", "did:dht:zOther"]
        caveats.originKind = "Action" // exempt from the 8-field budget

        let token = try await mintUcanToken(
            handle: handle,
            memberDid: member.did(),
            capabilities: ["messages:write"],
            proofs: nil,
            caveats: caveats
        )

        let payload = try decodeJwtPayload(token.encoded())
        guard let payloadNb = payload["nb"] as? [String: Any] else {
            Issue.record("JWT payload missing `nb` object: \(payload)")
            return
        }

        #expect(payloadNb["amountMaxPerCall"] as? Int == 100)
        #expect(payloadNb["amountMaxCumulative"] as? Int == 1000)
        #expect(payloadNb["validFrom"] as? Int == 1_700_000_000)
        #expect(payloadNb["validUntil"] as? Int == 1_700_003_600)
        #expect(payloadNb["maxCalls"] as? Int == 42)

        // rateWindow is the {max, windowSecs} wire object.
        guard let rateWindow = payloadNb["rateWindow"] as? [String: Any] else {
            Issue.record("rateWindow missing or wrong shape: \(payloadNb["rateWindow"] ?? "nil")")
            return
        }
        #expect(rateWindow["max"] as? Int == 1)
        #expect(rateWindow["windowSecs"] as? Int == 60)

        #expect(payloadNb["allowedAdapters"] as? [String] == ["native", "openai-compatible"])
        #expect(payloadNb["allowedTargetDids"] as? [String] == ["did:dht:zMember", "did:dht:zOther"])
        #expect(payloadNb["originKind"] as? String == "Action")

        // SCP-OUT-018 `skip_serializing_if = "Option::is_none"`: omitted
        // SDK fields must not appear in `nb`, never as null.
        #expect(payloadNb["hoursOfDay"] == nil)
        #expect(payloadNb["daysOfWeek"] == nil)
        #expect(payloadNb["inputSchema"] == nil)
    }

    /// Companion mint covering the three fields the primary test omitted
    /// (hoursOfDay, daysOfWeek, inputSchema) plus originKind=Query. Together
    /// the two mints exercise every one of the 12 InvocationCaveats fields.
    @Test("FFI: hoursOfDay / daysOfWeek / inputSchema also round-trip via UCAN nb")
    func caveatsRoundTripRemainingFields() async throws {
        try requireFFI()

        let admin = try await createIdentity(custody: "in_memory")
        let member = try await createIdentity(custody: "in_memory")
        let handle = try await contextCreate(
            identity: admin,
            params: makeCtxParams(ceiling: ["messages:read"])
        )

        var caveats = InvocationCaveats()
        caveats.hoursOfDay = 0x00FF_FFFF
        caveats.daysOfWeek = 0x7F
        caveats.inputSchemaJson = "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"number\"}},\"required\":[\"x\"]}"
        caveats.originKind = "Query"

        let token = try await mintUcanToken(
            handle: handle,
            memberDid: member.did(),
            capabilities: ["messages:read"],
            proofs: nil,
            caveats: caveats
        )

        let payload = try decodeJwtPayload(token.encoded())
        guard let payloadNb = payload["nb"] as? [String: Any] else {
            Issue.record("JWT payload missing `nb` object: \(payload)")
            return
        }

        #expect(payloadNb["hoursOfDay"] as? Int == 0x00FF_FFFF)
        #expect(payloadNb["daysOfWeek"] as? Int == 0x7F)

        guard let inputSchema = payloadNb["inputSchema"] as? [String: Any] else {
            Issue.record("inputSchema missing or wrong shape: \(payloadNb["inputSchema"] ?? "nil")")
            return
        }
        #expect(inputSchema["type"] as? String == "object")
        #expect(inputSchema["required"] as? [String] == ["x"])

        #expect(payloadNb["originKind"] as? String == "Query")

        // All non-populated SDK fields must be absent from `nb`.
        #expect(payloadNb["amountMaxPerCall"] == nil)
        #expect(payloadNb["amountMaxCumulative"] == nil)
        #expect(payloadNb["validFrom"] == nil)
        #expect(payloadNb["validUntil"] == nil)
        #expect(payloadNb["maxCalls"] == nil)
        #expect(payloadNb["rateWindow"] == nil)
        #expect(payloadNb["allowedAdapters"] == nil)
        #expect(payloadNb["allowedTargetDids"] == nil)
    }

    // Mirrors `test_mint_limit_violation_surfaces_slug` in the Python
    // reference: 9 populated non-`origin_kind` fields exceeds
    // MAX_POPULATED_CAVEATS = 8 and must surface SCP-TOOL-6114
    // (`caveat-mint-limit-exceeded`).
    @Test("FFI: mint-limit violation surfaces caveat-mint-limit-exceeded slug (SCP-OUT-023 AC-6)")
    func caveatsMintLimitViolation() async throws {
        try requireFFI()

        let admin = try await createIdentity(custody: "in_memory")
        let member = try await createIdentity(custody: "in_memory")
        let handle = try await contextCreate(
            identity: admin,
            params: makeCtxParams(ceiling: ["messages:read"])
        )

        var overCap = InvocationCaveats()
        overCap.amountMaxPerCall = 1
        overCap.amountMaxCumulative = 2
        overCap.validFrom = 3
        overCap.validUntil = 4
        overCap.hoursOfDay = 0x00FF_FFFF
        overCap.daysOfWeek = 0x7F
        overCap.maxCalls = 5
        overCap.rateWindow = 60
        // 9th populated non-origin_kind field — exceeds MAX_POPULATED_CAVEATS.
        overCap.inputSchemaJson = "{\"type\":\"object\"}"

        do {
            _ = try await mintUcanToken(
                handle: handle,
                memberDid: member.did(),
                capabilities: ["messages:read"],
                proofs: nil,
                caveats: overCap
            )
            Issue.record("expected mint-limit violation to throw")
        } catch let error as ScpError {
            // The bridge surfaces the slug in either Permission or Validation.
            // Compare on the rendered description so we don't depend on
            // which arm the bridge chose.
            #expect(String(describing: error).contains("caveat-mint-limit-exceeded"))
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}
