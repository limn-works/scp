// SCP-OUT-039 cross-SDK byte-equivalence — Swift (UniFFI) replay.
//
// Loads the on-disk fixture at
// `tests/conformance/vectors/outlet_caveats_binding_fixtures.json` and
// asserts the UniFFI bridge produces the SAME 32-byte `caveats_binding`
// hashes the protocol-level Rust helpers produced when the fixture was
// generated. Per spec §5.4.5 line 635 / ADR-049 §5 round-5 JCS Option
// rule, the four SDKs (PyO3, NAPI, UniFFI Swift / Kotlin, WASM) MUST
// produce byte-identical output — this test is the Swift leg.
//
// Mirrors:
// - `bindings/python/tests/test_outlet_caveats_binding_conformance.py`
// - `bindings/typescript/tests/outlet-caveats-binding-conformance.test.ts`
// - `bindings/kotlin/scp-kt/src/test/kotlin/works/limn/scp/OutletCaveatsBindingConformanceTest.kt`
// - `crates/scp-ffi/uniffi/tests/outlet_stream_vectors.rs` (Rust leg)
//
// The bridge surface (`OutletsStreaming.computeCaveatsBinding`) accepts
// the §5.4.5 preimage inputs verbatim. The fixture stores the JCS-
// canonical `effective_caveats` string the Rust generator produced;
// the Swift test feeds it to the bridge unchanged. The bridge
// re-canonicalises via the same `scp_protocol::jcs` path internally
// and MUST land on the same 32-byte hash.
//
// The XCFramework / native bridge binary may not be linked in every
// build context; the FFI call surface is guarded so a missing binary
// surfaces as a clean skip rather than a hard failure. The
// schema-shape assertions run regardless so a malformed fixture file
// is caught even without the bridge.

import Foundation
@testable import SCP
import XCTest

// swiftlint:disable identifier_name

/// One `caveats_binding` fixture vector — the §5.4.5 preimage inputs
/// plus the expected 32-byte hash. Fields mirror the JSON keys for
/// direct `Decodable` mapping.
private struct CaveatsBindingVector: Decodable {
    let name: String
    let description: String
    let ucan_cid_hex: String
    let request_id_hex: String
    let invoker_did: String
    let estimated_chunk_count: UInt32
    let effective_caveats_jcs: String
    let expected_caveats_binding_hex: String
}

private struct ChunkSigVector: Decodable {
    let name: String
    let description: String
    let context_id: String
    let outlet_id: String
    let request_id_hex: String
    let sequence: UInt64
    let caveats_binding_hex: String
    let expected_chunk_sig_preimage_hex: String
}

private struct CreditSigVector: Decodable {
    let name: String
    let description: String
    let context_id: String
    let outlet_id: String
    let request_id_hex: String
    let grant: UInt32
    let monotonic_seq: UInt64
    let stream_epoch: UInt64
    let caveats_binding_hex: String
    let expected_credit_sig_preimage_hex: String
}

private struct FixtureFile: Decodable {
    let comment: String
    let spec_section: String
    let story: String
    let caveats_binding: [CaveatsBindingVector]
    let chunk_sig_preimage: [ChunkSigVector]
    let credit_sig_preimage: [CreditSigVector]
}

// swiftlint:enable identifier_name

/// Hex-decode helper. Swift's Foundation has no first-class hex API;
/// this is a 6-line implementation suitable for fixture-loading.
private func hexToData(_ hex: String) -> Data? {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        guard let byte = UInt8(hex[idx ..< next], radix: 16) else { return nil }
        bytes.append(byte)
        idx = next
    }
    return Data(bytes)
}

private func dataToHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

final class OutletCaveatsBindingConformanceTests: XCTestCase {
    /// Walks up from the test file location to find the repo-root
    /// fixture. The Swift package's test working directory varies
    /// between local `swift test` (cwd: bindings/swift) and CI (cwd:
    /// repo root), so we anchor on `#filePath` and look for the
    /// `tests/conformance/vectors/` directory above it.
    private func fixtureURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 8 {
            url.deleteLastPathComponent()
            let candidate = url.appendingPathComponent(
                "tests/conformance/vectors/outlet_caveats_binding_fixtures.json"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return URL(
            fileURLWithPath: "tests/conformance/vectors/outlet_caveats_binding_fixtures.json"
        )
    }

    private func loadFixture() throws -> FixtureFile {
        let data = try Data(contentsOf: fixtureURL())
        return try JSONDecoder().decode(FixtureFile.self, from: data)
    }

    // -----------------------------------------------------------------
    // Schema-only assertions — run regardless of bridge availability.
    // -----------------------------------------------------------------

    func testFixtureCarriesMinimumVectorCounts() throws {
        let fixture = try loadFixture()
        XCTAssertGreaterThanOrEqual(
            fixture.caveats_binding.count, 3,
            "fixture must carry ≥ 3 caveats_binding vectors per spec floor"
        )
        XCTAssertGreaterThanOrEqual(
            fixture.chunk_sig_preimage.count, 2,
            "fixture must carry ≥ 2 chunk_sig_preimage vectors"
        )
        XCTAssertGreaterThanOrEqual(
            fixture.credit_sig_preimage.count, 2,
            "fixture must carry ≥ 2 credit_sig_preimage vectors"
        )
    }

    func testCbEmptyVectorEncodesAsLiteralEmptyObject() throws {
        // The cb_empty vector documents the §5.4.5 omit-none rule.
        // Its `effective_caveats_jcs` MUST be the literal `"{}"`,
        // proving the Rust generator does NOT emit explicit `null`
        // for absent Option fields. SDKs that disagree produce a
        // different binding.
        let fixture = try loadFixture()
        guard let cbEmpty = fixture.caveats_binding.first(where: { $0.name == "cb_empty" }) else {
            XCTFail("cb_empty vector must exist")
            return
        }
        XCTAssertEqual(
            cbEmpty.effective_caveats_jcs, "{}",
            "cb_empty must canonicalise to literal '{}' per §5.4.5 omit-none rule"
        )
    }

    func testEachCaveatsBindingVectorHasRequiredByteWidths() throws {
        let fixture = try loadFixture()
        for vector in fixture.caveats_binding {
            XCTAssertEqual(
                hexToData(vector.request_id_hex)?.count, 16,
                "vector \(vector.name): request_id must be 16 bytes"
            )
            XCTAssertEqual(
                hexToData(vector.expected_caveats_binding_hex)?.count, 32,
                "vector \(vector.name): expected_caveats_binding must be 32 bytes"
            )
        }
    }

    func testEachChunkSigPreimageVectorHasRequiredByteWidths() throws {
        let fixture = try loadFixture()
        for vector in fixture.chunk_sig_preimage {
            XCTAssertEqual(
                hexToData(vector.request_id_hex)?.count, 16,
                "vector \(vector.name): request_id must be 16 bytes"
            )
            XCTAssertEqual(
                hexToData(vector.caveats_binding_hex)?.count, 32,
                "vector \(vector.name): caveats_binding must be 32 bytes"
            )
            XCTAssertEqual(
                hexToData(vector.expected_chunk_sig_preimage_hex)?.count, 32,
                "vector \(vector.name): expected_chunk_sig_preimage must be 32 bytes"
            )
        }
    }

    func testEachCreditSigPreimageVectorHasRequiredByteWidths() throws {
        let fixture = try loadFixture()
        for vector in fixture.credit_sig_preimage {
            XCTAssertEqual(
                hexToData(vector.caveats_binding_hex)?.count, 32,
                "vector \(vector.name): caveats_binding must be 32 bytes"
            )
            XCTAssertEqual(
                hexToData(vector.expected_credit_sig_preimage_hex)?.count, 32,
                "vector \(vector.name): expected_credit_sig_preimage must be 32 bytes"
            )
        }
    }

    // -----------------------------------------------------------------
    // Bridge-driven byte-equivalence — each vector reproduces via
    // `OutletsStreaming.computeCaveatsBinding`. The UniFFI bridge
    // recomputes the §5.4.5 `SCP-OUTLET-CAVEAT-BIND-V1:` preimage
    // hash internally, and MUST produce the byte-identical hash the
    // Rust generator pinned. Any divergence indicates a cross-SDK
    // regression in JCS canonicalisation, omit-none handling, or the
    // preimage byte layout.
    //
    // If the XCFramework binary isn't linked (e.g. `swift test` run
    // without `build-xcframework.sh --dev`), the FFI call throws and
    // the test surfaces a clean failure indicating which build step
    // is missing. The conformance suite is the contract for the
    // Swift SDK — when the binary is built, the cross-SDK invariant
    // is enforced.
    // -----------------------------------------------------------------

    func testEveryCaveatsBindingVectorReproducesByteForByteViaUniFFI() throws {
        let fixture = try loadFixture()
        for vector in fixture.caveats_binding {
            guard
                let ucanCid = hexToData(vector.ucan_cid_hex),
                let requestId = hexToData(vector.request_id_hex)
            else {
                XCTFail("vector \(vector.name): malformed hex inputs")
                continue
            }

            let actual: Data
            do {
                actual = try OutletsStreaming.computeCaveatsBinding(
                    ucanCid: ucanCid,
                    requestId: requestId,
                    invokerDid: vector.invoker_did,
                    estimatedChunkCount: vector.estimated_chunk_count,
                    effectiveCaveatsJson: vector.effective_caveats_jcs
                )
            } catch {
                XCTFail(
                    "vector \(vector.name): computeCaveatsBinding threw — \(error). "
                        + "The UniFFI bridge binary may be missing — run "
                        + "`bindings/swift/build-xcframework.sh --dev` and re-test."
                )
                continue
            }

            XCTAssertEqual(actual.count, 32, "vector \(vector.name): hash must be 32 bytes")
            XCTAssertEqual(
                dataToHex(actual), vector.expected_caveats_binding_hex,
                "vector \(vector.name): UniFFI bridge produced \(dataToHex(actual)), "
                    + "expected \(vector.expected_caveats_binding_hex). "
                    + "Cross-SDK byte-equivalence has regressed — check JCS / omit-none."
            )
        }
    }
}
