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
//
// ADR-048 / #1549 Phase 4 PR 4: every UniFFI bridge operation is now a
// per-instance method on the `Scp` opaque class. Each op constructs a
// fresh `Scp()` so handles stay scoped to the call. The pre-PR-4
// free-function façade and the DEFAULT_BRIDGE_INSTANCE it delegated
// to were both deleted.

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
    let lower = header.lowercased()
    guard let range = lower.range(of: "content-length:") else {
        eprint("swift_bridge_runner: missing Content-Length header: \(header)")
        return nil
    }
    let tail = header[range.upperBound...]
    let digits = tail.prefix { !$0.isNumber && !$0.isWhitespace ? false : true }
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
// Op dispatch
// ---------------------------------------------------------------------------

func extractScpCode(_ message: String) -> String {
    let chars = Array(message)
    let n = chars.count
    var i = 0
    while i + 4 <= n {
        if chars[i] == "S", chars[i + 1] == "C", chars[i + 2] == "P", chars[i + 3] == "-" {
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

/// Decode a 64-char hex string into a 32-byte `Data` seed for the
/// `scp.identityCreate(custody:testingSeed:)` per-instance call. Matches
/// `node_bridge_runner.ts::seedFromHex`.
func seedFromHex(_ hex: String) -> Data? {
    guard hex.count == 64 else { return nil }
    var bytes = Data(capacity: 32)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            return nil
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

func opIdentityCreate(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let custody = req.args["custody"]?.stringValue ?? "in_memory"
    let seed = req.args["seed_hex"]?.stringValue.flatMap { seedFromHex($0) }
    let identity = try await scp.identityCreate(custody: custody, testingSeed: seed)
    var out: [String: JSONValue] = [
        "did": .string(identity.did()),
        "custody": .string(custody)
    ]
    if let hex = identity.verifyingKey() {
        out["verifying_key"] = .string(hex)
    }
    return out
}

func opContextCreate(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let paramsArg = req.args["params"]?.objectValue ?? [:]
    let mode = paramsArg["mode"]?.stringValue ?? "encrypted"
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(identity: identity, params: buildContextParams())
    return [
        "context_id": .string(handle.contextId()),
        "creator_did": .string(identity.did()),
        "mode": .string(mode)
    ]
}

func opInvalidCapability(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    // UniFFI `scpidSign` takes an `Identity` opaque handle; feed it a
    // malformed challenge to hit SCP-IDENT-1038 (shape validation) before
    // any DID lookup. Matches the other runners.
    let scp = try Scp.withStorage(config: .inMemory)
    let badChallenge = "{\"protocol\":\"scpid/1\",\"nonce\":\"00\",\"audience\":\"x\",\"issued_at\":0,\"expires_at\":0}"
    do {
        let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
        _ = try scp.scpidSign(
            identity: identity,
            signingKeyId: "#active",
            challengeJson: badChallenge,
            signedAtOverride: nil
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
    let scp = try Scp.withStorage(config: .inMemory)
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(identity: identity, params: buildContextParams())
    let events = try await scp.eventLogQuery(handle: handle, filterJson: nil)
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

let parityOutletName = "parity_probe"
let parityOutletCeiling = [
    "messages:read",
    "messages:write",
    "outlet:register",
    "outlet_call:*"
]

func opOutletRegister(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let ceiling = ceilingFromArgs(req.args, default: parityOutletCeiling)
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    let inputSchema = "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"integer\"},\"label\":{\"type\":\"string\"}}}"
    let outputSchema = "{\"type\":\"object\",\"properties\":{\"y\":{\"type\":\"integer\"},\"status\":{\"type\":\"string\"}}}"
    let outletId = try await scp.outletRegister(
        handle: handle,
        definition: OutletDefinition(
            name: parityOutletName,
            description: "parity harness probe outlet",
            kind: .action,
            inputSchemaJson: inputSchema,
            outputSchemaJson: outputSchema,
            operatorDid: identity.did(),
            testVectorsJson: nil,
            implementationHash: nil,
            cost: nil
        )
    )
    return ["outlet_id": .string(outletId)]
}

func opUcanMint(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let memberDid = req.args["member_did"]?.stringValue
        ?? "did:dht:zparitymemberparitymemberparitymemberparitymember"
    let capabilities: [String]
    if case let .array(arr)? = req.args["capabilities"] {
        capabilities = arr.compactMap { $0.stringValue }
    } else {
        capabilities = ["messages:read"]
    }
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    let token = try await scp.ucanMint(
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
    let scp = try Scp.withStorage(config: .inMemory)
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    do {
        // Fail-closed presenting-agent gate: supply one so the malformed JWT is
        // rejected at PARSE (the behavior under test).
        try await scp.ucanValidate(
            handle: handle,
            token: "not.a.jwt",
            capability: "scp:ctx:any/messages:read",
            presentingAgentDid: identity.did(),
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

func opUcanEvaluateMalformed(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    // ucan_evaluate is the structured read-only counterpart to ucan_validate.
    // A malformed JWT fails the FFI token validator before reaching the
    // pipeline, surfacing as a thrown error whose code aligns across bridges
    // (canonical SCP-PERM-3001 via the shared From<UcanError> mapping).
    let scp = try Scp.withStorage(config: .inMemory)
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    do {
        // Fail-closed presenting-agent gate: supply one so the malformed JWT is
        // rejected at PARSE (the behavior under test).
        _ = try await scp.ucanEvaluate(
            handle: handle,
            token: "not.a.jwt",
            capability: "scp:ctx:any/messages:read",
            presentingAgentDid: identity.did(),
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

func opUcanEvaluateStructured(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    // Mint a VALID root token granting `messages:read`, then evaluate it
    // requiring `messages:write` (a capability the token does NOT grant). Core
    // evaluate_ucan short-circuits at grant-match and returns the partial-false
    // struct WITHOUT throwing — the no-throw counterpart to
    // opUcanEvaluateMalformed. All six booleans are compared across bridges.
    let scp = try Scp.withStorage(config: .inMemory)
    let memberDid = req.args["member_did"]?.stringValue
        ?? "did:dht:zparitymemberparitymemberparitymemberparitymember"
    let capabilities: [String]
    if case let .array(arr)? = req.args["capabilities"] {
        capabilities = arr.compactMap { $0.stringValue }
    } else {
        capabilities = ["messages:read"]
    }
    let requiredCap = req.args["required_capability"]?.stringValue ?? "messages:write"
    let ceiling = ceilingFromArgs(req.args, default: ["messages:read", "messages:write"])
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams(ceiling: ceiling)
    )
    let token = try await scp.ucanMint(
        handle: handle,
        memberDid: memberDid,
        capabilities: capabilities,
        proofs: nil
    )
    let required = "scp:ctx:\(handle.contextId())/\(requiredCap)"
    let result = try await scp.ucanEvaluate(
        handle: handle,
        token: token.encoded(),
        capability: required,
        presentingAgentDid: memberDid,
        proofTokens: nil
    )
    return [
        "tokens_valid": .bool(result.tokensValid),
        "signatures_valid": .bool(result.signaturesValid),
        "within_ceiling": .bool(result.withinCeiling),
        "nonce_valid": .bool(result.nonceValid),
        "not_revoked": .bool(result.notRevoked),
        "time_bounds_valid": .bool(result.timeBoundsValid)
    ]
}

func opTransportStatus(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    // ADR-048 §7a: UniFFI now exposes a handleless `transportManagerStatus()`
    // alongside the handle-taking `transportStatus(manager:)`, matching the
    // PyO3 / NAPI probe contract. The parity harness drives the
    // handleless path so no relay fixture is needed on the UniFFI runners.
    let scp = try Scp.withStorage(config: .inMemory)
    let status = try await scp.transportManagerStatus()
    return [
        "connected": .bool(status.connected),
        "relay_url": status.relayUrl.map(JSONValue.string) ?? .null,
        "latency_ms": status.latencyMs.map { JSONValue.number(Double($0)) } ?? .null,
    ]
}

// Shape-valid `did:dht:z…` DID guaranteed NOT to be in any bridge's
// identity registry. Mirrors `seed_operations.py::FAKE_UNREGISTERED_DID`.
let fakeUnregisteredDid =
    "did:dht:znever1never1never1never1never1never1never1never1never1never1neva"

func opUnregisteredDidRejected(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    // UniFFI `scpidSign` takes an opaque `Identity` handle rather than
    // a DID string, so we cannot reach the bridge-local registry-lookup
    // path the PyO3/NAPI bridges expose. Instead we exercise the
    // SAME error code via `identityResolve` on the fake DID: its 64-char
    // zbase32 suffix decodes to 40 bytes (not the 32 required by
    // did:dht), so `DidDht::extract_public_key` returns
    // `IdentityError::InvalidDidFormat` locally — and the bridge's
    // blanket `From<IdentityError>` maps that to SCP-IDENT-1001.
    // `identityResolve` is a module-level free function (ADR-048 §1) — it
    // resolves via a process-scoped resolver and needs no `Scp` instance.
    do {
        _ = try await identityResolve(did: fakeUnregisteredDid)
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

func opEventLogQueryFiltered(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let filter: [String: JSONValue]
    if let obj = req.args["filter"]?.objectValue {
        filter = obj
    } else {
        filter = ["event_type": .string("ContextCreated")]
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let filterJson: String
    if let data = try? encoder.encode(filter),
       let str = String(data: data, encoding: .utf8) {
        filterJson = str
    } else {
        filterJson = "{\"event_type\":\"ContextCreated\"}"
    }
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams()
    )
    let events = try await scp.eventLogQuery(handle: handle, filterJson: filterJson)
    let first = events.first
    return [
        "event_count": .integer(Int64(events.count)),
        "first_event_type": .string(first?.eventType ?? "")
    ]
}

// Fixed 32-byte nonce used when `signed_at_override` pins the SCPID
// response. Must match
// `bindings/python/tests/bridge_parity/seed_operations.py::PARITY_NONCE_HEX`.
let parityNonceHex = String(repeating: "aa", count: 32)

// Year-2286 timestamp — far enough in the future that wall-clock expiry
// cannot trip the SCPID expiry check.
let parityChallengeExpiresAtMs: Int64 = 9_999_999_999_000

/// When `signed_at_override` is supplied, REPLACE the bridge-issued
/// challenge with a pinned fixture so every bridge feeds `scpidSign`
/// the same canonical hash inputs. Mirrors
/// `node_bridge_runner.ts::patchChallengeForOverride`.
func patchChallengeForOverride(_ challengeJson: String, override: Int64?) -> String {
    guard let override = override else { return challengeJson }
    let obj: [String: Any] = [
        "protocol": "scpid/1.0",
        "nonce": parityNonceHex,
        "audience": "https://parity-test.example.com",
        "issued_at": override,
        "expires_at": parityChallengeExpiresAtMs
    ]
    guard let data = try? JSONSerialization.data(
        withJSONObject: obj, options: [.sortedKeys]
    ), let str = String(data: data, encoding: .utf8) else {
        return challengeJson
    }
    return str
}

func opSignMessage(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    let scp = try Scp.withStorage(config: .inMemory)
    let audience = req.args["audience"]?.stringValue
        ?? "https://parity-test.example.com"
    let ttl = UInt64(req.args["ttl_seconds"]?.intValue ?? 60)
    let seed = req.args["seed_hex"]?.stringValue.flatMap { seedFromHex($0) }
    let signedAtOverride = req.args["signed_at_override"]?.intValue
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: seed)
    // `scpidChallenge` is a stateless helper; remains a free function
    // in the UniFFI Swift module.
    let challenge = try scpidChallenge(audience: audience, ttlSeconds: ttl)
    let patched = patchChallengeForOverride(challenge, override: signedAtOverride)
    let responseJson = try scp.scpidSign(
        identity: identity,
        signingKeyId: "#active",
        challengeJson: patched,
        signedAtOverride: signedAtOverride.map { UInt64($0) }
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

// Drives the PRODUCTION UniFFI verify path (`Scp.eventLogVerify` →
// `Proof`). Pins the honest proof shape: a returned proof IS the
// positive answer (no `verified` flag) and its details carry the
// checkable Merkle material plus the one-snapshot `leaf_count`.
// Mirrors `seed_operations.py::_py_event_log_verify_inclusion`.
func opEventLogVerifyInclusion(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    let scp = try Scp.withStorage(config: .inMemory)
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams()
    )
    // `ContextCreated` is leaf 0 of the AUTHORITATIVE log on every bridge.
    let proof = try await scp.eventLogVerify(
        handle: handle,
        claimJson: "{\"type\":\"inclusion\",\"leaf_index\":0}"
    )
    let details = parseJsonObject(proof.detailsJson)
    let leafCount = (details["leaf_count"] as? NSNumber)?.int64Value ?? -1
    return [
        "proof_type": .string(proof.proofType),
        "leaf_count": .integer(leafCount),
        "has_leaf_hash": .bool(details.keys.contains("leaf_hash")),
        "has_path": .bool(details.keys.contains("path")),
        "has_root": .bool(details.keys.contains("root"))
    ]
}

// GitHub #1933 AC 4: an absence proof for a REAL lifecycle event must
// FAIL with SCP-CTX-2139 identically on every bridge. Extracts the
// `ContextCreated` leaf hash from this bridge's own inclusion proof so
// the absence claim provably names an event that IS in the
// authoritative log. Mirrors
// `seed_operations.py::_py_event_log_absence_rejected`.
func opEventLogAbsenceRejected(_ req: BridgeRequest) async throws -> [String: JSONValue] {
    _ = req
    let scp = try Scp.withStorage(config: .inMemory)
    let identity = try await scp.identityCreate(custody: "in_memory", testingSeed: nil)
    let handle = try await scp.contextCreate(
        identity: identity, params: buildContextParams()
    )
    let inclusion = try await scp.eventLogVerify(
        handle: handle,
        claimJson: "{\"type\":\"inclusion\",\"leaf_index\":0}"
    )
    let details = parseJsonObject(inclusion.detailsJson)
    let leafHash = details["leaf_hash"] as? String ?? ""
    do {
        _ = try await scp.eventLogVerify(
            handle: handle,
            claimJson: "{\"type\":\"absence\",\"event_hash\":\"\(leafHash)\"}"
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

/// Parses a JSON object string into `[String: Any]`; empty on failure.
func parseJsonObject(_ json: String) -> [String: Any] {
    guard let data = json.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return [:]
    }
    return obj
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
        case "outlet_register":
            result = try await opOutletRegister(req)
        case "ucan_mint":
            result = try await opUcanMint(req)
        case "ucan_evaluate_malformed":
            result = try await opUcanEvaluateMalformed(req)
        case "ucan_evaluate_structured":
            result = try await opUcanEvaluateStructured(req)
        case "ucan_validate_malformed":
            result = try await opUcanValidateMalformed(req)
        case "transport_status":
            result = try await opTransportStatus(req)
        case "event_log_query_filtered":
            result = try await opEventLogQueryFiltered(req)
        case "event_log_verify_inclusion":
            result = try await opEventLogVerifyInclusion(req)
        case "event_log_absence_of_lifecycle_event_rejected":
            result = try await opEventLogAbsenceRejected(req)
        case "unregistered_did_rejected":
            result = try await opUnregisteredDidRejected(req)
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

func writeResponse(_ payload: Any) {
    if let ok = payload as? OkResponse {
        writeFrame(ok)
    } else if let err = payload as? ErrResponse {
        writeFrame(err)
    } else {
        eprint("swift_bridge_runner: unexpected response type")
    }
}

let sem = DispatchSemaphore(value: 0)

Task.detached {
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
            // Per-op `Scp()` instances mean there are no module-level
            // runner caches to clear. Respond ok for harness parity.
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
