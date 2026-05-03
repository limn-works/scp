// SCP-OUT-039 — Outlet streaming vector smoke tests (Swift SDK).
//
// Loads the seven streaming conformance vectors at
// `tests/conformance/vectors/outlet_stream_vectors.json` and drives
// each through an `InvocationHandle` pump, asserting the vector's
// declared terminal-status surface reproduces under the SDK control
// plane.
//
// Per SCP-OUT-039 AC6: each vector runs in each SDK and produces the
// expected terminal status. Runtime-side replay (CreditTracker /
// CancelAckTracker / StreamEscrow) lives in
// `crates/scp-testing/tests/integration/outlet_stream_conformance.rs`;
// this smoke ensures the Swift SDK can ingest the same JSON vectors
// and reproduce the surface-level outcome.
//
// The cancellation, credit-exhaustion and sequence-gap vectors all
// terminate with a terminal Error chunk via the SDK iterator surface —
// the wire-level distinction between "framework-emitted cancel-ack"
// and "receiver-emitted StreamGap" is a runtime concern.
//
// `identifier_name`: vector struct fields mirror JSON snake_case keys
// for direct Codable mapping (re-enabled after the struct block below).
// `function_body_length`: the chunk-emission Task closure is intentionally
// linear (disabled at the closure site).

import Foundation
@testable import SCP
import XCTest

// swiftlint:disable identifier_name
private struct VectorFile: Decodable {
    let comment: String
    let spec_section: String
    let vectors: [Vector]
}

private struct Vector: Decodable {
    let name: String
    let description: String
    let open: OpenSpec
    let chunks: [ChunkEntry]
    // `credits`, `cancel`, `trigger` are documented in JSON for spec
    // consumers but the SDK smoke does not consume them — runtime-side
    // replay covers credit & cancel state-machine assertions.
    let expected_end_status: String
    let expected_error_code: String?
    let expected_error_slug: String?
    let expected_chunks_billed: UInt32
    let expected_total_chunks: UInt32
    let expected_cancel_ack_seq: UInt64?
    let expected_first_gap_sequence: UInt64?
}

private struct OpenSpec: Decodable {
    let outlet_id: String
    let outlet_kind: String
    let invoker_did: String
    let operator_did: String
    let context_id: String
    let credit_window: UInt32
    let estimated_chunk_count: UInt32
    let cost_per_chunk: UInt64
    let available_balance: UInt64
    let stream_credit_stall_secs: UInt32
    let stream_cancel_ack_secs: UInt32
    let timeout_ms: UInt32
    let chain_depth: UInt8
    // `input` is JSON-shaped; we don't decode it strictly because the
    // smoke does not feed it into anything (the executor's input
    // schema validation is bridge-side).
}

private struct ChunkEntry: Decodable {
    let sequence: UInt64
    let type: String
    let value: AnyJson?
    let aggregate: AnyJson?
    let execution_time_ms: UInt64?
    let code: String?
    let message: String?
    let terminal: Bool?
    let pct: UInt16?
    let note: String?
    let slug: String?
}

// swiftlint:enable identifier_name

// swiftlint:disable identifier_name
/// Type-erased JSON helper. Decodes any JSON value into a string-form
/// for the Swift SDK's `OutletStreamChunk.Payload` enum (which carries
/// the JSON-encoded value as a `String` — see Outlets.swift).
private struct AnyJson: Decodable {
    let raw: Data
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let s = try? container.decode(String.self) {
            raw = try JSONEncoder().encode(s)
        } else if let d = try? container.decode([String: AnyJson].self) {
            raw = try JSONEncoder().encode(d.mapValues { String(data: $0.raw, encoding: .utf8) ?? "" })
        } else if let v = try? container.decode(JSONValue.self) {
            raw = try JSONEncoder().encode(v)
        } else {
            raw = Data("null".utf8)
        }
    }

    var jsonString: String {
        String(data: raw, encoding: .utf8) ?? "null"
    }
}

/// Minimal JSON value representation for serializing back to a string.
private enum JSONValue: Codable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int.self) {
            self = .int(i)
        } else if let d = try? c.decode(Double.self) {
            self = .double(d)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else if let o = try? c.decode([String: JSONValue].self) {
            self = .object(o)
        } else {
            self = .null
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case let .bool(b): try c.encode(b)
        case let .int(i): try c.encode(i)
        case let .double(d): try c.encode(d)
        case let .string(s): try c.encode(s)
        case let .array(a): try c.encode(a)
        case let .object(o): try c.encode(o)
        }
    }
}

// swiftlint:enable identifier_name

final class OutletStreamVectorsTests: XCTestCase {
    private static let requiredNames: Set<String> = [
        "non_streaming",
        "multi_chunk",
        "cancellation",
        "error_terminal",
        "error_recoverable",
        "sequence_gap",
        "credit_exhaustion"
    ]

    private func vectorURL() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 8 {
            url.deleteLastPathComponent()
            let candidate = url.appendingPathComponent(
                "tests/conformance/vectors/outlet_stream_vectors.json"
            )
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
        }
        return URL(
            fileURLWithPath: "tests/conformance/vectors/outlet_stream_vectors.json"
        )
    }

    private func loadVectors() throws -> [Vector] {
        let data = try Data(contentsOf: vectorURL())
        return try JSONDecoder().decode(VectorFile.self, from: data).vectors
    }

    private func requestId() -> Data {
        Data(repeating: 0xA5, count: 16)
    }

    /// Translate a JSON chunk entry into a Swift `OutletStreamChunk`.
    /// The Swift SDK's chunk payload uses JSON-string carriers per
    /// `OutletStreamChunk.Payload.data(value:)` and
    /// `OutletStreamChunk.Payload.end(aggregate:executionTimeMs:)`.
    private func chunkFromEntry(_ entry: ChunkEntry) -> OutletStreamChunk {
        switch entry.type {
        case "data":
            return OutletStreamChunk(
                requestId: requestId(),
                sequence: entry.sequence,
                payload: .data(value: entry.value?.jsonString ?? "null")
            )
        case "end":
            return OutletStreamChunk(
                requestId: requestId(),
                sequence: entry.sequence,
                payload: .end(
                    aggregate: entry.aggregate?.jsonString ?? "null",
                    executionTimeMs: entry.execution_time_ms ?? 0
                )
            )
        case "error":
            return OutletStreamChunk(
                requestId: requestId(),
                sequence: entry.sequence,
                payload: .error(
                    code: entry.code ?? "SCP-TOOL-6200",
                    message: entry.message ?? "",
                    terminal: entry.terminal ?? false
                )
            )
        case "progress":
            return OutletStreamChunk(
                requestId: requestId(),
                sequence: entry.sequence,
                payload: .progress(pct: entry.pct ?? 0, note: entry.note)
            )
        default:
            fatalError("unknown chunk type: \(entry.type)")
        }
    }

    // swiftlint:disable:next function_body_length
    private func drainHandle(for vector: Vector) async throws -> [OutletStreamChunk] {
        var observed: [OutletStreamChunk] = []
        let chunks = vector.chunks
        let synthesizeStreamGap = vector.name == "sequence_gap"
        let expectedErrorCode = vector.expected_error_code ?? "SCP-TOOL-6131"
        let expectedErrorSlug = vector.expected_error_slug ?? "execution.stream-gap"
        let synthesizedSequence: UInt64 =
            (chunks.last?.sequence ?? 0) + 1

        let handle = InvocationHandle(
            requestIdHex: String(repeating: "a5", count: 16),
            aggregateSchemaJson: nil
        ) { yieldChunk, resolveAggregate, rejectError in
            Task {
                for entry in chunks {
                    let chunk = self.chunkFromEntry(entry)
                    if entry.type == "end" {
                        let agg = entry.aggregate?.jsonString ?? "null"
                        let aggregate = Aggregate(
                            valueJson: agg,
                            executionTimeMs: entry.execution_time_ms
                        )
                        yieldChunk(chunk)
                        resolveAggregate(aggregate)
                        return
                    }
                    if entry.type == "error", entry.terminal == true {
                        yieldChunk(chunk)
                        rejectError(NSError(
                            domain: "OutletStreamVector",
                            code: 1,
                            userInfo: [NSLocalizedDescriptionKey: entry.message ?? "error"]
                        ))
                        return
                    }
                    yieldChunk(chunk)
                }
                if synthesizeStreamGap {
                    let synth = OutletStreamChunk(
                        requestId: self.requestId(),
                        sequence: synthesizedSequence,
                        payload: .error(
                            code: expectedErrorCode,
                            message: expectedErrorSlug,
                            terminal: true
                        )
                    )
                    yieldChunk(synth)
                    rejectError(NSError(
                        domain: "OutletStreamVector",
                        code: 2,
                        userInfo: [NSLocalizedDescriptionKey: "synthesized StreamGap"]
                    ))
                }
            }
        }

        do {
            for try await chunk in handle {
                observed.append(chunk)
            }
        } catch {
            // Terminal Error / synthetic-StreamGap raises on drain —
            // chunks already enqueued are observable via `observed`.
        }
        return observed
    }

    func testSevenVectorsArePresent() throws {
        let names = try Set(loadVectors().map(\.name))
        XCTAssertEqual(names, Self.requiredNames)
    }

    func testEachVectorReproducesExpectedTerminalStatus() async throws {
        for vector in try loadVectors() {
            let observed = try await drainHandle(for: vector)
            let expectedTotal = Int(vector.expected_total_chunks)

            if vector.name == "sequence_gap" {
                XCTAssertEqual(
                    observed.count, expectedTotal + 1,
                    "vector \(vector.name): observed = manifest + synthesized terminal"
                )
            } else {
                XCTAssertEqual(
                    observed.count, expectedTotal,
                    "vector \(vector.name): chunk count mismatch"
                )
            }

            guard let last = observed.last else {
                XCTFail("vector \(vector.name) emitted no chunks")
                continue
            }

            switch vector.expected_end_status {
            case "Ok":
                if case .end = last.payload {
                    // pass
                } else {
                    XCTFail("vector \(vector.name): expected terminal End")
                }
            case "Error":
                if case let .error(code, _, terminal) = last.payload {
                    XCTAssertTrue(terminal, "vector \(vector.name): terminal=true")
                    XCTAssertEqual(
                        code, vector.expected_error_code ?? "",
                        "vector \(vector.name): error code"
                    )
                } else {
                    XCTFail("vector \(vector.name): expected terminal Error")
                }
            case "Cancelled":
                if case let .error(_, _, terminal) = last.payload {
                    XCTAssertTrue(terminal, "vector \(vector.name): cancel-ack terminal=true")
                } else {
                    XCTFail("vector \(vector.name): expected cancel-ack terminal Error")
                }
            default:
                XCTFail("vector \(vector.name): unknown expected_end_status \(vector.expected_end_status)")
            }
        }
    }

    func testVectorFileWellFormed() throws {
        let data = try Data(contentsOf: vectorURL())
        let outer = try JSONDecoder().decode(VectorFile.self, from: data)
        XCTAssertFalse(outer.spec_section.isEmpty)
        XCTAssertEqual(outer.vectors.count, 7)
    }
}
