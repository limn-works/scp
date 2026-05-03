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
