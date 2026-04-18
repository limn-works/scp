// SPDX-License-Identifier: MIT
//
// Long-lived Swift JSON-RPC server for cross-bridge parity testing (ADR-046).
//
// Reads length-prefixed JSON requests on stdin, dispatches to the UniFFI
// Swift bindings, and writes length-prefixed JSON responses on stdout.
//
// Wire format (HTTP-style) — identical to node_bridge_runner.ts and the
// Kotlin runner:
//
//     Content-Length: N\r\n
//     \r\n
//     <N bytes of JSON>
//
// Request: `{id, op, args, bridgeMode}` where bridgeMode is "uniffi-swift".
// Response: `{id, ok: true, result: {...}}` on success or
//           `{id, ok: false, error: {type, code, message}}` on bridge error.
//
// Bridge selection is explicit — the runner rejects any bridgeMode other
// than "uniffi-swift" per the no-auto-fallback principle in ADR-046.

import Foundation
import SCP

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

@inline(__always)
func eprint(_ s: String) {
    FileHandle.standardError.write(Data("\(s)\n".utf8))
}

/// Read exactly `n` bytes from stdin. Returns nil on EOF before `n` bytes
/// are available — the caller treats nil as a hard protocol failure
/// except at the boundary between frames (handled in readFrame).
func readExact(_ n: Int) -> Data? {
    if n == 0 { return Data() }
    var buf = Data()
    buf.reserveCapacity(n)
    let stdin = FileHandle.standardInput
    while buf.count < n {
        let remaining = n - buf.count
        let chunk = stdin.availableData
        if chunk.isEmpty {
            // availableData returns empty on EOF.
            return buf.isEmpty ? nil : nil
        }
        if chunk.count <= remaining {
            buf.append(chunk)
        } else {
            // availableData returned more than we asked for — not expected
            // with the way it's documented, but handle defensively.
            buf.append(chunk.prefix(remaining))
            // We cannot un-consume the overflow from FileHandle; guard
            // against this path by always requesting one byte at a time in
            // readHeader (see below). This branch should be unreachable.
            eprint("swift_bridge_runner: unexpected over-read from stdin")
        }
    }
    return buf
}

/// Read the header (up to and including `\r\n\r\n`), byte-by-byte to avoid
/// over-read on FileHandle. 4 KiB cap matches runner_client.py's
/// MAX_HEADER_BYTES.
func readHeader() -> String? {
    var header = Data()
    let terminator: [UInt8] = [13, 10, 13, 10]
    let stdin = FileHandle.standardInput
    while true {
        let chunk = stdin.readData(ofLength: 1)
        if chunk.isEmpty {
            // EOF before header complete — clean shutdown only if buffer empty.
            return header.isEmpty ? nil : nil
        }
        header.append(chunk)
        if header.count > 4096 {
            eprint("swift_bridge_runner: header exceeded 4 KiB")
            return nil
        }
        if header.count >= 4 {
            let last4 = Array(header.suffix(4))
            if last4 == terminator {
                return String(data: header, encoding: .utf8)
            }
        }
    }
}

struct BridgeRequest: Decodable {
    let id: Int
    let op: String
    let args: [String: JSONValue]
    let bridgeMode: String
}

struct OkResponse: Encodable {
    let id: Int
    let ok: Bool
    let result: [String: JSONValue]
}

struct ErrResponse: Encodable {
    let id: Int
    let ok: Bool
    let error: ErrorBody
}

struct ErrorBody: Encodable {
    let type: String
    let code: String
    let message: String
}

/// Minimal dynamic JSON value that can round-trip arbitrary bridge
/// responses through Encodable / Decodable without committing to a
/// typed schema per op.
enum JSONValue: Codable {
    case string(String)
    case number(Double)
    case integer(Int64)
    case bool(Bool)
    case null
    case array([JSONValue])
    case object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int64.self) { self = .integer(i); return }
        if let d = try? c.decode(Double.self) { self = .number(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([JSONValue].self) { self = .array(a); return }
        if let o = try? c.decode([String: JSONValue].self) { self = .object(o); return }
        throw DecodingError.dataCorruptedError(
            in: c, debugDescription: "unsupported JSON value"
        )
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .integer(let i): try c.encode(i)
        case .number(let d): try c.encode(d)
        case .bool(let b): try c.encode(b)
        case .null: try c.encodeNil()
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    var intValue: Int64? {
        if case .integer(let i) = self { return i }
        if case .number(let d) = self { return Int64(d) }
        return nil
    }

    var objectValue: [String: JSONValue]? {
        if case .object(let o) = self { return o }
        return nil
    }
}

func writeFrame<T: Encodable>(_ payload: T) {
    let encoder = JSONEncoder()
    // Stable ordering keeps diffs clean on the Python side.
    encoder.outputFormatting = [.sortedKeys]
    do {
        let body = try encoder.encode(payload)
        let header = "Content-Length: \(body.count)\r\n\r\n"
        let headerData = Data(header.utf8)
        let stdout = FileHandle.standardOutput
        stdout.write(headerData)
        stdout.write(body)
    } catch {
        eprint("swift_bridge_runner: failed to encode response: \(error)")
    }
}

func readFrame() -> BridgeRequest? {
    guard let header = readHeader() else { return nil }
    // Header looks like "Content-Length: N\r\n\r\n"
    let lower = header.lowercased()
    guard let range = lower.range(of: "content-length:") else {
        eprint("swift_bridge_runner: missing Content-Length header: \(header)")
        return nil
    }
    let tail = header[range.upperBound...]
    // Find the first digit run.
    let digits = tail.prefix { !$0.isNumber && !$0.isWhitespace ? false : true }
    // Strip whitespace and read the integer.
    let numStr = digits.trimmingCharacters(in: .whitespacesAndNewlines)
        .split(whereSeparator: { !$0.isNumber })
        .first
        .map(String.init) ?? ""
    guard let length = Int(numStr), length >= 0 else {
        eprint("swift_bridge_runner: invalid Content-Length: \(header)")
        return nil
    }
    if length > 16 * 1024 * 1024 {
        eprint("swift_bridge_runner: Content-Length exceeds 16 MiB: \(length)")
        return nil
    }
    guard let body = readExact(length) else {
        eprint("swift_bridge_runner: EOF reading body (\(length) bytes)")
        return nil
    }
    do {
        return try JSONDecoder().decode(BridgeRequest.self, from: body)
    } catch {
        eprint("swift_bridge_runner: failed to decode request: \(error)")
        return nil
    }
}

// ---------------------------------------------------------------------------
// Runner state (module-global caches, cleared on `reset`)
// ---------------------------------------------------------------------------

// UniFFI Swift bindings maintain their own module-global state (identity
// registry, context manager). We don't cache anything here — each op
// creates fresh identities/contexts and does not rely on handoff between
// RPCs. `reset` is still handled (returns success) because the Python
// harness sends one before every parity test.

// ---------------------------------------------------------------------------
// Op dispatch
// ---------------------------------------------------------------------------

func extractScpCode(_ message: String) -> String {
    // Match SCP-{CATEGORY}-{NNNN} — same regex used by the Bun runner.
    // Bounded fixed-string scan to avoid NSRegularExpression overhead.
    let chars = Array(message)
    let n = chars.count
    var i = 0
    while i + 4 <= n {
        if chars[i] == "S", chars[i + 1] == "C", chars[i + 2] == "P", chars[i + 3] == "-" {
            // Scan category (uppercase letters), optional more hyphens.
            var j = i + 4
            while j < n, chars[j].isLetter, chars[j].isUppercase { j += 1 }
            if j < n, chars[j] == "-" {
                j += 1
                var k = j
                while k < n, chars[k].isNumber { k += 1 }
                if k > j {
                    return String(chars[i..<k])
                }
            }
        }
        i += 1
    }
    return "UNKNOWN"
}

func toErrResponse(_ id: Int, _ error: Error) -> ErrResponse {
    let message = String(describing: error)
    let code = extractScpCode(message)
    let errType = String(describing: type(of: error))
    return ErrResponse(
        id: id,
        ok: false,
        error: ErrorBody(type: errType, code: code, message: message)
    )
}

func buildContextParams(
    ceiling: [String] = ["messages:read", "messages:write"]
) -> ContextParams {
    // Matches the other runners' defaults: single-admin, ephemeral,
    // no TTL, encrypted mode. Ceiling is the minimum set needed for
    // parity-test send/receive. Callers override ceiling for ops that
    // need additional capabilities (tool:register, etc.).
    return ContextParams(
        mode: .encrypted,
        ceiling: ceiling,
        ceilingPolicy: .immutable,
        governance: .singleAdmin,
        memoryScope: .ephemeral,
        ttlSeconds: 0,
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

func ceilingFromArgs(
    _ args: [String: JSONValue],
    default def: [String]
) -> [String] {
    guard case let .array(arr)? = args["ceiling"] else { return def }
    return arr.compactMap { $0.stringValue }
}

// MARK: - Op implementations

func opIdentityCreate(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let custody = req.args["custody"]?.stringValue ?? "in_memory"
    let identity = try await identityCreate(custody: custody)
    return [
        "did": .string(identity.did()),
        "custody": .string(custody)
    ]
}

func opContextCreate(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let paramsArg = req.args["params"]?.objectValue ?? [:]
    let mode = paramsArg["mode"]?.stringValue ?? "encrypted"
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(identity: identity, params: buildContextParams())
    return [
        "context_id": .string(handle.contextId()),
        "creator_did": .string(identity.did()),
        "mode": .string(mode)
    ]
}

func opInvalidCapability(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    // UniFFI Swift's `scpidSign` takes an `Identity` opaque handle
    // rather than a DID string, so we cannot directly exercise the
    // unregistered-DID lookup path that the PyO3 bridge tests. Instead,
    // we create a real identity and pass a malformed challenge — that
    // hits SCP-IDENT-1038 (shape validation) before any DID lookup.
    // This is the exact path `seed_operations.py` documents as the MVP
    // shared failure mode across all bridges.
    let badChallenge = "{\"protocol\":\"scpid/1\",\"nonce\":\"00\",\"audience\":\"x\",\"issued_at\":0,\"expires_at\":0}"
    do {
        let identity = try await identityCreate(custody: "in_memory")
        _ = try scpidSign(
            identity: identity,
            signingKeyId: "#active",
            challengeJson: badChallenge
        )
        return [
            "error": .object([
                "type": .string("none"),
                "code": .string("NONE"),
                "message": .string("no error raised")
            ])
        ]
    } catch {
        let message = String(describing: error)
        let code = extractScpCode(message)
        let errType = String(describing: type(of: error))
        return [
            "error": .object([
                "type": .string(errType),
                "code": .string(code),
                "message": .string(message)
            ])
        ]
    }
}

func opEventLogAppend(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(identity: identity, params: buildContextParams())
    let events = try await eventLogQuery(handle: handle, filterJson: nil)
    guard let first = events.first else {
        return [
            "event_count": .integer(0),
            "first_event_type": .string(""),
            "first_sequence": .integer(0)
        ]
    }
    return [
        "event_count": .integer(Int64(events.count)),
        "first_event_type": .string(first.eventType),
        "first_sequence": .integer(Int64(first.sequence))
    ]
}

// MARK: - Ops 6-10

let parityToolName = "parity_probe"
let parityToolCeiling = [
    "messages:read",
    "messages:write",
    "tool:register",
    "tool_invoke:*"
]

func opToolRegister(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let ceiling = ceilingFromArgs(req.args, default: parityToolCeiling)
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    let inputSchema = "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"integer\"}}}"
    let outputSchema = "{\"type\":\"object\",\"properties\":{\"y\":{\"type\":\"integer\"}}}"
    let toolId = try await toolRegister(
        handle: handle,
        definition: ToolDefinition(
            name: parityToolName,
            description: "parity harness probe tool",
            inputSchemaJson: inputSchema,
            outputSchemaJson: outputSchema,
            operatorDid: identity.did(),
            testVectorsJson: nil,
            implementationHash: nil,
            cost: nil
        )
    )
    return ["tool_id": .string(toolId)]
}

func opUcanMint(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let memberDid = req.args["member_did"]?.stringValue
        ?? "did:dht:zparitymemberparitymemberparitymemberparitymember"
    let capabilities: [String]
    if case let .array(arr)? = req.args["capabilities"] {
        capabilities = arr.compactMap { $0.stringValue }
    } else {
        capabilities = ["messages:read"]
    }
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    let token = try await ucanMint(
        handle: handle,
        memberDid: memberDid,
        capabilities: capabilities,
        proofs: nil
    )
    return [
        "issuer": .string(token.issuer()),
        "audience": .string(token.audience()),
        "capability_count": .integer(Int64(token.capabilities().count))
    ]
}

func opUcanValidateMalformed(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    // UniFFI wraps parse_ucan with SCP-PERM-3002. Xfail'd in
    // seed_operations.py against uniffi-swift.
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    do {
        try await ucanValidate(
            handle: handle,
            token: "not.a.jwt",
            capability: "scp:ctx:any/messages:read",
            presentingAgentDid: nil,
            proofTokens: nil
        )
        return [
            "error": .object([
                "type": .string("none"),
                "code": .string("NONE")
            ])
        ]
    } catch {
        let message = String(describing: error)
        let code = extractScpCode(message)
        let errType = String(describing: type(of: error))
        return [
            "error": .object([
                "type": .string(errType),
                "code": .string(code)
            ])
        ]
    }
}

func opTransportStatus(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    // UniFFI's `transport_status` now accepts an optional manager; when
    // `nil`, it returns the stateless BridgeInstance-level snapshot —
    // the same shape PyO3 and WASM expose. The parity harness always
    // exercises the handleless probe (no transport_connect, no relay
    // fixture), so every bridge reports `connected: false` here.
    let status = try await transportStatus(manager: nil)
    let connected: JSONValue = .bool(status.connected)
    let relayUrl: JSONValue
    if let url = status.relayUrl {
        relayUrl = .string(url)
    } else {
        relayUrl = .null
    }
    let latencyMs: JSONValue
    if let latency = status.latencyMs {
        latencyMs = .number(latency)
    } else {
        latencyMs = .null
    }
    return [
        "connected": connected,
        "relay_url": relayUrl,
        "latency_ms": latencyMs
    ]
}

func opEventLogQueryFiltered(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let filter: [String: JSONValue]
    if let obj = req.args["filter"]?.objectValue {
        filter = obj
    } else {
        filter = ["event_type": .string("ContextCreated")]
    }
    // Serialize the filter to a JSON string for the UniFFI API.
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let filterJson: String
    if let data = try? encoder.encode(filter),
       let str = String(data: data, encoding: .utf8) {
        filterJson = str
    } else {
        filterJson = "{\"event_type\":\"ContextCreated\"}"
    }
    let identity = try await identityCreate(custody: "in_memory")
    let handle = try await contextCreate(
        identity: identity, params: buildContextParams()
    )
    let events = try await eventLogQuery(handle: handle, filterJson: filterJson)
    let first = events.first
    return [
        "event_count": .integer(Int64(events.count)),
        "first_event_type": .string(first?.eventType ?? "")
    ]
}

func opSignMessage(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let audience = req.args["audience"]?.stringValue
        ?? "https://parity-test.example.com"
    let ttl = UInt64(req.args["ttl_seconds"]?.intValue ?? 60)
    let identity = try await identityCreate(custody: "in_memory")
    let challenge = try scpidChallenge(audience: audience, ttlSeconds: ttl)
    let responseJson = try scpidSign(
        identity: identity,
        signingKeyId: "#active",
        challengeJson: challenge
    )
    guard let data = responseJson.data(using: .utf8),
          let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw NSError(
            domain: "swift_bridge_runner",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "invalid JSON from scpidSign"]
        )
    }
    return [
        "protocol": .string((parsed["protocol"] as? String) ?? ""),
        "did": .string((parsed["did"] as? String) ?? ""),
        "signing_key_id": .string((parsed["signing_key_id"] as? String) ?? ""),
        "signature": .string((parsed["signature"] as? String) ?? "")
    ]
}

func dispatch(_ req: BridgeRequest) async -> Any {
    do {
        let result: [String: JSONValue]
        switch req.op {
        case "identity_create":
            result = try await opIdentityCreate(req)
        case "context_create":
            result = try await opContextCreate(req)
        case "invalid_capability_rejected":
            result = try await opInvalidCapability(req)
        case "event_log_append":
            result = try await opEventLogAppend(req)
        case "sign_message":
            result = try await opSignMessage(req)
        case "tool_register":
            result = try await opToolRegister(req)
        case "ucan_mint":
            result = try await opUcanMint(req)
        case "ucan_validate_malformed":
            result = try await opUcanValidateMalformed(req)
        case "transport_status":
            result = try await opTransportStatus(req)
        case "event_log_query_filtered":
            result = try await opEventLogQueryFiltered(req)
        default:
            return ErrResponse(
                id: req.id,
                ok: false,
                error: ErrorBody(
                    type: "UnknownOp",
                    code: "TEST-PARITY-1001",
                    message: "unknown op: \(req.op)"
                )
            )
        }
        return OkResponse(id: req.id, ok: true, result: result)
    } catch {
        return toErrResponse(req.id, error)
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

// Non-generic wrapper — Swift's existential Encodable can't be used as a
// direct type argument to writeFrame<T>, so we branch on the concrete
// response type before calling the generic function.
func writeResponse(_ payload: Any) {
    if let ok = payload as? OkResponse {
        writeFrame(ok)
    } else if let err = payload as? ErrResponse {
        writeFrame(err)
    } else {
        eprint("swift_bridge_runner: unexpected response type")
    }
}

// Run the async dispatch loop on a detached task and block main until
// it exits. `Swift` scripts do not have an automatic event loop, so we
// drive one explicitly.
let sem = DispatchSemaphore(value: 0)

Task.detached {
    // Emit a startup diagnostic (stderr, JSON) so the harness operator
    // can confirm which binding surface resolved. Parallel to the Bun
    // runner's bridge_parity_runner_loaded event.
    eprint("{\"event\":\"bridge_parity_runner_loaded\",\"runner\":\"swift\",\"bridge\":\"uniffi-swift\"}")

    while true {
        guard let req = readFrame() else {
            break
        }
        if req.op == "shutdown" {
            writeFrame(OkResponse(id: req.id, ok: true, result: [:]))
            break
        }
        if req.op == "reset" {
            // UniFFI Swift bindings hold their own module-globals — no
            // per-runner caches to clear. Respond ok.
            writeFrame(OkResponse(id: req.id, ok: true, result: [:]))
            continue
        }
        if req.bridgeMode != "uniffi-swift" {
            writeFrame(ErrResponse(
                id: req.id,
                ok: false,
                error: ErrorBody(
                    type: "ProtocolError",
                    code: "TEST-PARITY-1003",
                    message: "swift runner only accepts bridgeMode=uniffi-swift, got: \(req.bridgeMode)"
                )
            ))
            continue
        }
        let response = await dispatch(req)
        writeResponse(response)
    }
    sem.signal()
}

sem.wait()
