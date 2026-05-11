import Foundation

// SCP-OUT-006 — Swift outlets surface.
//
// Error-code prefix remains SCP-TOOL-* (§9.18 — registered namespace);
// only the class vocabulary is outlet-renamed.
//
// UniFFI-generated types used here:
// - OutletDefinition, OutletVerificationResult (ScpBindings.swift)
// - outletRegister, outletInvoke, outletVerify, outletUpdate,
//   outletDeregister, outletList, outletGet (ScpBindings.swift)
// - outletSessionOpen, outletSessionInvoke, outletSessionClose
//   (ScpBindings.swift)
// - outletInterfaceOffer, outletInterfaceAccept, outletInterfaceRevoke
//   (ScpBindings.swift)
// - outletInvokeCrossContext (ScpBindings.swift)

// MARK: - Branded newtypes (API MAJOR 28 / API MINOR round 5)

/// Distinct `DID` type — compiler rejects passing an `OutletId` where
/// a `DID` is required (API MINOR round 5; Swift's labeled-argument style
/// closes the swap-risk identified in API MAJOR 22 without needing an
/// options-object wrapper).
public struct DID: Sendable, Hashable {
    public let raw: String
    public init(_ raw: String) {
        self.raw = raw
    }
}

// `OutletId` itself is declared in `Errors.swift` as a throwing
// newtype (validates non-empty). The previous duplicate declaration
// here caused `invalid redeclaration of 'OutletId'`. Removed in HIGH
// wave 4 — the throwing constructor is the canonical brand.

/// UUIDv7 session identifier — distinct from `OutletId` / `DID`.
public struct SessionId: Sendable, Hashable {
    public let raw: String

    /// Construct a `SessionId` from a caller-supplied string after UUIDv7 +
    /// timestamp-window validation.
    public init(raw: String, now: Date = Date()) throws {
        try Self.validate(raw: raw, now: now)
        self.raw = raw
    }

    /// Construct a `SessionId` without validation — internal use only.
    init(unvalidated: String) {
        raw = unvalidated
    }

    static let uuid7Regex: NSRegularExpression = // swiftlint:disable:next force_try
        try! NSRegularExpression(
            pattern:
            "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            options: []
        )

    private static let skewToleranceMs: Int64 = 10 * 60 * 1000

    /// Throws `OutletError.validation` if `raw` is not a canonical UUIDv7 or
    /// the embedded 48-bit timestamp is outside the ±10-minute window.
    public static func validate(raw: String, now: Date = Date()) throws {
        let range = NSRange(raw.startIndex ..< raw.endIndex, in: raw)
        if Self.uuid7Regex.firstMatch(in: raw, options: [], range: range) == nil {
            throw OutletError.validation(
                message: "SessionId must be a canonical UUIDv7; got \(raw)",
                code: "SCP-VALID-7010"
            )
        }
        // Timestamp prefix = first 8 + next 4 hex chars (12 total = 48 bits).
        let prefix1 = raw.prefix(8)
        let bStart = raw.index(raw.startIndex, offsetBy: 9)
        let bEnd = raw.index(bStart, offsetBy: 4)
        let prefix2 = raw[bStart ..< bEnd]
        guard let tsMs = UInt64(String(prefix1) + String(prefix2), radix: 16) else {
            throw OutletError.validation(
                message: "SessionId timestamp parse failed for \(raw)",
                code: "SCP-VALID-7010"
            )
        }
        let nowMs = Int64(now.timeIntervalSince1970 * 1000)
        let diff = nowMs - Int64(tsMs)
        if diff > Self.skewToleranceMs {
            throw OutletError.validation(
                message: "SessionId timestamp \(tsMs) is more than 10 minutes in the past (now \(nowMs))",
                code: "SCP-VALID-7010"
            )
        }
        if diff < -Self.skewToleranceMs {
            throw OutletError.validation(
                message: "SessionId timestamp \(tsMs) is more than 10 minutes in the future (now \(nowMs))",
                code: "SCP-VALID-7010"
            )
        }
    }
}

/// Mint a fresh UUIDv7 `SessionId` using the system CSPRNG
/// (`SystemRandomNumberGenerator`) for the 74 random bits.
public func newSessionId(now: Date = Date()) -> SessionId {
    let tsMs = UInt64(now.timeIntervalSince1970 * 1000) & ((1 << 48) - 1)
    var rand = Data(count: 10)
    rand.withUnsafeMutableBytes { buf in
        guard let base = buf.baseAddress else { return }
        let ptr = base.assumingMemoryBound(to: UInt8.self)
        var rng = SystemRandomNumberGenerator()
        for index in 0 ..< 10 {
            ptr[index] = UInt8.random(in: 0 ... UInt8.max, using: &rng)
        }
    }
    var bytes = Data(count: 16)
    bytes[0] = UInt8((tsMs >> 40) & 0xFF)
    bytes[1] = UInt8((tsMs >> 32) & 0xFF)
    bytes[2] = UInt8((tsMs >> 24) & 0xFF)
    bytes[3] = UInt8((tsMs >> 16) & 0xFF)
    bytes[4] = UInt8((tsMs >> 8) & 0xFF)
    bytes[5] = UInt8(tsMs & 0xFF)
    bytes[6] = 0x70 | (rand[0] & 0x0F)
    bytes[7] = rand[1]
    bytes[8] = 0x80 | (rand[2] & 0x3F)
    bytes[9] = rand[3]
    bytes[10] = rand[4]; bytes[11] = rand[5]; bytes[12] = rand[6]
    bytes[13] = rand[7]; bytes[14] = rand[8]; bytes[15] = rand[9]
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    let formatted = "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20).prefix(12))"
    return SessionId(unvalidated: formatted)
}

// MARK: - OutletError (Swift-native shape)

/// Outlet registration, invocation, or verification errors.
///
/// The §5.4.4 sealed error taxonomy is rendered as Swift `enum` cases with
/// associated values per `OutletErrorClass` variant — the eight new cases
/// (`protocol(_:)`, `authorization(_:)`, ...) carry the typed envelope per
/// SCP-OUT-031. The pre-redesign cases (`notFound`, `executionFailed`,
/// `validation`, `unauthorized`, `bridge`) are preserved verbatim so
/// existing call sites keep compiling.
///
/// Error-code prefix remains `SCP-TOOL-*` (§9.18 — registered namespace).
public enum OutletError: Error, Sendable, Equatable {
    // Pre-OUT-031 cases (legacy back-compat).
    case notFound(message: String, code: String)
    case executionFailed(message: String, code: String)
    case validation(message: String, code: String)
    case unauthorized(message: String, code: String)
    case bridge(message: String, code: String)

    // §5.4.4 sealed-hierarchy cases — one per `OutletErrorClass` variant.
    case `protocol`(OutletEnvelope)
    case authorization(OutletEnvelope)
    case input(OutletEnvelope)
    case execution(OutletEnvelope)
    case output(OutletEnvelope)
    case economic(OutletEnvelope)
    case transport(OutletEnvelope)
    case governance(OutletEnvelope)

    // Round-6 unified zero-grant rejection — surfaces under the
    // `protocol(_:)` case so all four SDKs share an `OutletError`-rooted
    // exception class for the `Credit` zero-rejection rule.
    case invalidGrant(Credit)

    // SCP-OUT-038 AC13 / Fix #4 — `streamAlreadyClosed` is NOT a
    // top-level enum case any more. AC13 requires the lifecycle error
    // to sit at the SAME inheritance depth as the protocol-class
    // siblings (`StreamAlreadyOpen`, `UnknownSession`,
    // catalog-rotation entries) which Python / TS / Kotlin nest under
    // `OutletProtocolError`. The Swift parity is `.protocol(envelope)`.
    // The factory `OutletError.streamAlreadyClosed(message:)` returns
    // `.protocol(envelope)` so `if case .protocol = err` matches the
    // lifecycle error uniformly with every other protocol-class
    // violation. Existing call sites use the factory; the case is gone
    // — pattern-match on `.protocol(let env)` and inspect
    // `env.slug == "protocol.stream-already-closed"`.

    /// Builds a default §5.4.4 protocol-class envelope for the
    /// SCP-OUT-038 stream-already-closed lifecycle violation and
    /// returns it as `.protocol(envelope)`. The factory exists so the
    /// SDK's lifecycle-guard call sites do not have to assemble the
    /// wire-form fields themselves; callers that need to pattern-match
    /// the lifecycle error use `if case .protocol(let env) = err,
    /// env.slug == "protocol.stream-already-closed" { ... }`.
    public static func streamAlreadyClosed(message: String? = nil) -> OutletError {
        let envelope = OutletEnvelope(
            classWire: .protocol,
            code: "SCP-TOOL-6102",
            slug: "protocol.stream-already-closed",
            message: message ?? "stream has already terminated; control-plane methods rejected",
            retry: .never,
            detail: nil,
            sourceChain: [],
            padNonce: nil,
            registrationEventId: nil
        )
        return .protocol(envelope)
    }

    /// Back-compat alias for the prior factory name. Returns the same
    /// `.protocol(envelope)` value as `streamAlreadyClosed(message:)`.
    /// New call sites should use `streamAlreadyClosed(message:)`.
    public static func makeStreamAlreadyClosed(message: String? = nil) -> OutletError {
        return streamAlreadyClosed(message: message)
    }

    /// Constructs a typed `OutletError` from a keyword-only options struct
    /// (§5.4.4 round-6 swap-risk fix). Swift's labeled-argument idiom is
    /// already unambiguous, but the labelled variant is the only path
    /// emitted from the SDK so call sites are uniform across SDKs.
    public static func new(
        outletId: OutletId,
        catalogKey: CatalogKey,
        class: OutletErrorClass,
        retry: RetryPolicy = .never,
        detail: OutletErrorDetail? = nil
    ) throws -> OutletError {
        let envelope = try OutletEnvelope.makeForCreation(
            outletId: outletId,
            catalogKey: catalogKey,
            classWire: `class`,
            retry: retry,
            detail: detail
        )
        switch `class` {
        case .protocol: return .protocol(envelope)
        case .authorization: return .authorization(envelope)
        case .input: return .input(envelope)
        case .execution: return .execution(envelope)
        case .output: return .output(envelope)
        case .economic: return .economic(envelope)
        case .transport: return .transport(envelope)
        case .governance: return .governance(envelope)
        }
    }

    /// SCP-OUT-041d FFI-delegated form of `OutletError.new`. Calls the
    /// UniFFI `outletErrorNew` export which performs the §5.4.4 wire-
    /// message HMAC at the FFI boundary using the pinned per-outlet
    /// `outlet_message_key`. The SDK never sees the raw key.
    ///
    /// - Parameters:
    ///   - handle: The active context handle.
    ///   - outletId: Emitting outlet id.
    ///   - registrationEventId: 32-byte event-log id of the
    ///     `OutletRegistration` that pinned the message key.
    ///   - catalogKey: Registered catalog key.
    ///   - class: §5.4.4 root class.
    ///   - code: `SCP-TOOL-NNNN`. Defaults to the class default code.
    ///   - slug: `^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63})*$`.
    ///     Defaults to `catalogKey`.
    ///   - retry: Retry guidance. Defaults to `.never`.
    ///   - detail: Typed per-class detail.
    ///   - sourceChain: Initial cross-context hop trail.
    ///   - padNonce: 16-byte CSPRNG nonce. Defaults to a fresh value.
    public static func newViaBridge(
        handle: ContextHandle,
        outletId: OutletId,
        registrationEventId: Data,
        catalogKey: CatalogKey,
        class: OutletErrorClass,
        code: String? = nil,
        slug: String? = nil,
        retry: RetryPolicy = .never,
        detail: OutletErrorDetail? = nil,
        sourceChain: [OutletContextHop]? = nil,
        padNonce: Data? = nil
    ) async throws -> OutletError {
        guard registrationEventId.count == 32 else {
            throw OutletError.validation(
                message: "registrationEventId must be 32 bytes",
                code: "SCP-VALID-7000"
            )
        }
        let nonce = padNonce ?? Data((0 ..< 16).map { _ in UInt8.random(in: 0 ... 255) })
        guard nonce.count == 16 else {
            throw OutletError.validation(
                message: "padNonce must be 16 bytes",
                code: "SCP-VALID-7000"
            )
        }
        let codeStr = code ?? defaultCodeFor(`class`)
        let slugStr = slug ?? catalogKey
        let retryStr = retry.wireForm
        let detailJson = detail.map { detailValue -> String in
            (try? JSONEncoder().encode(detailValue)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        }
        let sourceChainJson = sourceChain.map { hops -> String in
            (try? JSONEncoder().encode(hops)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
        }
        let envelopeJson = try await outletErrorNew(
            handle: handle,
            outletId: outletId,
            registrationEventIdHex: registrationEventId.map { String(format: "%02x", $0) }.joined(),
            catalogKey: catalogKey,
            classStr: `class`.rawValue,
            code: codeStr,
            slug: slugStr,
            retryStr: retryStr,
            padNonceHex: nonce.map { String(format: "%02x", $0) }.joined(),
            detailJson: detailJson,
            sourceChainJson: sourceChainJson
        )
        let envelope = try OutletEnvelope.fromBridgeWire(envelopeJson)
        switch `class` {
        case .protocol: return .protocol(envelope)
        case .authorization: return .authorization(envelope)
        case .input: return .input(envelope)
        case .execution: return .execution(envelope)
        case .output: return .output(envelope)
        case .economic: return .economic(envelope)
        case .transport: return .transport(envelope)
        case .governance: return .governance(envelope)
        }
    }
}

/// Per-class default `SCP-TOOL-NNNN` code for the §5.4.4 envelope.
private func defaultCodeFor(_ errorClass: OutletErrorClass) -> String {
    switch errorClass {
    case .protocol: return "SCP-TOOL-6100"
    case .authorization: return "SCP-TOOL-6110"
    case .input: return "SCP-TOOL-6120"
    case .execution: return "SCP-TOOL-6130"
    case .output: return "SCP-TOOL-6140"
    case .economic: return "SCP-TOOL-6150"
    case .transport: return "SCP-TOOL-6160"
    case .governance: return "SCP-TOOL-6170"
    }
}

/// SCP-OUT-041d catalog-rotation dwell-time validator (Swift SDK).
///
/// Calls the UniFFI `outletCatalogRotationValidator` export. Returns
/// silently on success; throws an `OutletError.protocol` when the new
/// registration is within the §5.4.4 round-5 24-hour dwell floor.
public func outletCatalogRotationValidator(
    priorCatalog: [OutletMessageTemplate],
    newCatalog: [OutletMessageTemplate],
    priorAppendTimeSecs: UInt64,
    newAppendTimeSecs: UInt64
) async throws {
    let encoder = JSONEncoder()
    let priorJson = try String(data: encoder.encode(priorCatalog), encoding: .utf8) ?? "[]"
    let newJson = try String(data: encoder.encode(newCatalog), encoding: .utf8) ?? "[]"
    let result = try await outletCatalogRotationValidator(
        priorCatalogJson: priorJson,
        newCatalogJson: newJson,
        priorAppendTimeSecs: priorAppendTimeSecs,
        newAppendTimeSecs: newAppendTimeSecs
    )
    if result.isEmpty { return }
    let envelope = try OutletEnvelope.fromBridgeWire(result)
    throw OutletError.protocol(envelope)
}

/// `MessageTemplate` shape mirrored for the SCP-OUT-041d catalog-rotation
/// validator surface — `{key, template}` pairs.
public struct OutletMessageTemplate: Codable, Sendable, Equatable {
    public let key: String
    public let template: String
    public init(key: String, template: String) {
        self.key = key
        self.template = template
    }
}

/// `ContextHop` shape for the SCP-OUT-041d source_chain field.
public struct OutletContextHop: Codable, Sendable, Equatable {
    public let contextId: String
    public let hopIndex: UInt32
    public let wrappedCode: String
    public init(contextId: String, hopIndex: UInt32, wrappedCode: String) {
        self.contextId = contextId
        self.hopIndex = hopIndex
        self.wrappedCode = wrappedCode
    }

    private enum CodingKeys: String, CodingKey {
        case contextId = "context_id"
        case hopIndex = "hop_index"
        case wrappedCode = "wrapped_code"
    }
}

// MARK: - Streaming & caveats (§5.4.5, §7.3.8)

public struct OutletStreamChunk: Sendable, Equatable {
    public enum Payload: Sendable, Equatable {
        case data(value: String)
        case progress(pct: UInt16, note: String?)
        case end(aggregate: String, executionTimeMs: UInt64)
        case error(code: String, message: String, terminal: Bool)
    }

    public let requestId: Data
    public let sequence: UInt64
    public let payload: Payload
}

public struct Aggregate: Sendable, Equatable {
    public let valueJson: String
    public let executionTimeMs: UInt64?
    public init(valueJson: String, executionTimeMs: UInt64? = nil) {
        self.valueJson = valueJson
        self.executionTimeMs = executionTimeMs
    }
}

public struct InvocationCaveats: Sendable, Equatable {
    public var amountMaxPerCall: Int64?
    public var amountMaxCumulative: Int64?
    public var validFrom: Int64?
    public var validUntil: Int64?
    public var hoursOfDay: UInt32?
    public var daysOfWeek: UInt8?
    public var maxCalls: UInt32?
    public var rateWindow: UInt32?
    public var inputSchemaJson: String?
    public var allowedAdapters: [String]?
    public var allowedTargetDids: [String]?
    public var originKind: String?

    public init() {}
}

// MARK: - Caveat builder helpers (review item 33)

public enum Caveats {
    public static func spendingCap(perCall: Int64? = nil, cumulative: Int64? = nil) -> CaveatBuilder {
        CaveatBuilder().spendingCap(perCall: perCall, cumulative: cumulative)
    }

    public static func timeBounded(
        validFrom: Int64? = nil,
        validUntil: Int64? = nil,
        hoursOfDay: UInt32? = nil,
        daysOfWeek: UInt8? = nil
    ) throws -> CaveatBuilder {
        try CaveatBuilder().timeBounded(
            validFrom: validFrom,
            validUntil: validUntil,
            hoursOfDay: hoursOfDay,
            daysOfWeek: daysOfWeek
        )
    }

    public static func rateLimited(maxCalls: UInt32? = nil, rateWindow: UInt32? = nil) -> CaveatBuilder {
        CaveatBuilder().rateLimited(maxCalls: maxCalls, rateWindow: rateWindow)
    }

    public static func forTarget(
        allowedTargetDids: [String]? = nil,
        allowedAdapters: [String]? = nil
    ) -> CaveatBuilder {
        CaveatBuilder().forTarget(
            allowedTargetDids: allowedTargetDids,
            allowedAdapters: allowedAdapters
        )
    }
}

public final class CaveatBuilder {
    private var fields = InvocationCaveats()

    @discardableResult
    public func spendingCap(perCall: Int64? = nil, cumulative: Int64? = nil) -> CaveatBuilder {
        if let perCall { fields.amountMaxPerCall = perCall }
        if let cumulative { fields.amountMaxCumulative = cumulative }
        return self
    }

    @discardableResult
    public func timeBounded(
        validFrom: Int64? = nil,
        validUntil: Int64? = nil,
        hoursOfDay: UInt32? = nil,
        daysOfWeek: UInt8? = nil
    ) throws -> CaveatBuilder {
        if let validFrom { fields.validFrom = validFrom }
        if let validUntil { fields.validUntil = validUntil }
        if let hoursOfDay {
            if hoursOfDay >= (1 << 24) {
                throw OutletError.validation(
                    message: "hoursOfDay must be a 24-bit bitmask, got \(hoursOfDay)",
                    code: "SCP-VALID-7010"
                )
            }
            fields.hoursOfDay = hoursOfDay
        }
        if let daysOfWeek {
            if daysOfWeek >= (1 << 7) {
                throw OutletError.validation(
                    message: "daysOfWeek must be a 7-bit bitmask, got \(daysOfWeek)",
                    code: "SCP-VALID-7010"
                )
            }
            fields.daysOfWeek = daysOfWeek
        }
        return self
    }

    @discardableResult
    public func rateLimited(maxCalls: UInt32? = nil, rateWindow: UInt32? = nil) -> CaveatBuilder {
        if let maxCalls { fields.maxCalls = maxCalls }
        if let rateWindow { fields.rateWindow = rateWindow }
        return self
    }

    @discardableResult
    public func forTarget(
        allowedTargetDids: [String]? = nil,
        allowedAdapters: [String]? = nil
    ) -> CaveatBuilder {
        if let allowedTargetDids { fields.allowedTargetDids = allowedTargetDids }
        if let allowedAdapters { fields.allowedAdapters = allowedAdapters }
        return self
    }

    @discardableResult
    public func inputSchema(_ jsonString: String) -> CaveatBuilder {
        fields.inputSchemaJson = jsonString
        return self
    }

    @discardableResult
    public func originKind(_ kind: String) throws -> CaveatBuilder {
        if kind != "Query" && kind != "Action" {
            throw OutletError.validation(
                message: "originKind must be 'Query' or 'Action', got \(kind)",
                code: "SCP-VALID-7010"
            )
        }
        fields.originKind = kind
        return self
    }

    public func build() -> InvocationCaveats {
        fields
    }
}

// MARK: - Invocation handle (dual await + AsyncSequence per review item 32)

/// Handle returned by `ctx.outlets.invoke(id:input:)`.
///
/// Supports BOTH consumption patterns (API MAJOR 21):
///
/// * `let aggregate = try await handle.aggregate` — await the aggregate value.
/// * `for try await chunk in handle { ... }` — iterate chunks via
///   `AsyncSequence` / `AsyncThrowingStream`. Per SCP-OUT-038 AC14 the
///   iterator yields the terminal `End` chunk (10 Data + End ⇒ 11
///   chunks observed).
///
/// SCP-OUT-038 control plane (AC2-3): every handle exposes
/// `grantCredit(_: Credit)` and `cancel(nextSeq:)`. When the handle was
/// opened against a real §5.4.5 streaming session, these route to the
/// UniFFI `outletStreamGrantCredit` / `outletStreamCancel` exports.
/// When the handle wraps a degenerate single-shot invocation (no
/// streaming session), the synthesized End arrives synchronously and
/// the control-plane methods raise `OutletError.streamAlreadyClosed`
/// per AC13.
///
/// Lifecycle guard (AC13): once a terminal chunk is observed via the
/// iterator OR the await path, subsequent control-plane calls raise
/// `OutletError.streamAlreadyClosed`.
public final class InvocationHandle: @unchecked Sendable, AsyncSequence {
    public typealias Element = OutletStreamChunk

    private let stream: AsyncThrowingStream<OutletStreamChunk, Error>
    private let aggregateTask: Task<Aggregate, Error>

    /// 32-char lowercase hex `request_id` of the underlying §5.4.5
    /// stream — `nil` for handles backed by the non-streaming bridge.
    private let requestIdHex: String?

    /// Pinned invoker DID; threaded through to every control-plane
    /// bridge call as `callerDid` so the bridge can verify against
    /// its registry's pinned identity. CRITICAL #1 fix.
    private let invokerDid: String?

    /// Optional aggregate-schema (JSON Schema-shaped) for End-chunk
    /// validation per OUT-038 AC12.
    private let aggregateSchemaJson: String?

    /// Lifecycle terminal-flag — flips once an End / Error{terminal:true}
    /// chunk is observed. `@unchecked Sendable` is preserved because all
    /// mutations happen on the pump's serial queue.
    private let terminatedFlag = TerminatedFlag()

    public init(
        requestIdHex: String? = nil,
        invokerDid: String? = nil,
        aggregateSchemaJson: String? = nil,
        pump: @Sendable @escaping (
            @Sendable @escaping (OutletStreamChunk) -> Void,
            @Sendable @escaping (Aggregate) -> Void,
            @Sendable @escaping (Error) -> Void
        ) -> Void
    ) {
        self.requestIdHex = requestIdHex
        self.invokerDid = invokerDid
        self.aggregateSchemaJson = aggregateSchemaJson
        var chunkCont: AsyncThrowingStream<OutletStreamChunk, Error>.Continuation?
        let stream = AsyncThrowingStream<OutletStreamChunk, Error> { cont in
            chunkCont = cont
        }
        self.stream = stream
        var resolveAggregate: ((Aggregate) -> Void)?
        var rejectAggregate: ((Error) -> Void)?
        aggregateTask = Task {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Aggregate, Error>) in
                resolveAggregate = { cont.resume(returning: $0) }
                rejectAggregate = { cont.resume(throwing: $0) }
            }
        }
        let terminatedFlag = self.terminatedFlag
        pump(
            { chunk in
                // AC13: track terminal observation on the iterator
                // path so control-plane callers see the lifecycle
                // guard fire after observing End / terminal Error.
                let isTerminal: Bool
                switch chunk.payload {
                case .end:
                    isTerminal = true
                case let .error(_, _, terminal):
                    isTerminal = terminal
                default:
                    isTerminal = false
                }
                if isTerminal {
                    terminatedFlag.markTerminated()
                }
                chunkCont?.yield(chunk)
            },
            { agg in
                terminatedFlag.markTerminated()
                resolveAggregate?(agg)
                chunkCont?.finish()
            },
            { err in
                terminatedFlag.markTerminated()
                rejectAggregate?(err)
                chunkCont?.finish(throwing: err)
            }
        )
    }

    /// Backward-compat overload — retained so call sites that don't
    /// pass `requestIdHex` / `aggregateSchemaJson` keep compiling.
    public convenience init(pump: @Sendable @escaping (
        @Sendable @escaping (OutletStreamChunk) -> Void,
        @Sendable @escaping (Aggregate) -> Void,
        @Sendable @escaping (Error) -> Void
    ) -> Void) {
        self.init(requestIdHex: nil, aggregateSchemaJson: nil, pump: pump)
    }

    /// Await the terminal aggregate value. SCP-OUT-038 AC12: when an
    /// `aggregateSchemaJson` is bound to the handle, the aggregate is
    /// validated against the schema before resolving. Throws
    /// `OutletError.output(...)` on schema mismatch.
    public var aggregate: Aggregate {
        get async throws {
            let agg = try await aggregateTask.value
            try validateAggregate(agg)
            return agg
        }
    }

    public func makeAsyncIterator() -> AsyncThrowingStream<OutletStreamChunk, Error>.AsyncIterator {
        stream.makeAsyncIterator()
    }

    /// SCP-OUT-038 AC2/AC3 — issues an additional credit grant.
    ///
    /// `grant` MUST be a typed `Credit` value (constructed via
    /// `try Credit(rawUInt32)` which throws `OutletError.invalidGrant`
    /// for `raw == 0`). The Swift compiler rejects passing a raw
    /// `UInt32` where `Credit` is expected.
    ///
    /// - Throws: `OutletError.streamAlreadyClosed` (AC13) when the
    ///   stream has already emitted a terminal chunk.
    @discardableResult
    public func grantCredit(_ grant: Credit) async throws -> UInt32 {
        if terminatedFlag.isTerminated {
            throw OutletError.makeStreamAlreadyClosed()
        }
        guard let ridHex = requestIdHex else {
            throw OutletError.makeStreamAlreadyClosed(
                message: "grantCredit rejected: handle was opened without a streaming session"
            )
        }
        guard let did = invokerDid else {
            throw OutletError.makeStreamAlreadyClosed(
                message: "grantCredit rejected: handle has no pinned invoker DID — bridge "
                    + "caller authentication unavailable"
            )
        }
        return try await outletStreamGrantCredit(
            requestIdHex: ridHex,
            callerDid: did,
            grant: grant.raw
        )
    }

    /// SCP-OUT-038 AC2/AC3 — cancels the active stream (§5.4.5).
    ///
    /// CRITICAL #3 — `next_seq` is no longer accepted; the bridge
    /// derives the canonical next-emission cursor from runtime state.
    ///
    /// - Throws: `OutletError.streamAlreadyClosed` (AC13) when the
    ///   stream has already emitted a terminal chunk.
    @discardableResult
    public func cancel() async throws -> UInt64? {
        if terminatedFlag.isTerminated {
            throw OutletError.makeStreamAlreadyClosed()
        }
        guard let ridHex = requestIdHex else {
            throw OutletError.makeStreamAlreadyClosed(
                message: "cancel rejected: handle was opened without a streaming session"
            )
        }
        guard let did = invokerDid else {
            throw OutletError.makeStreamAlreadyClosed(
                message: "cancel rejected: handle has no pinned invoker DID — bridge "
                    + "caller authentication unavailable"
            )
        }
        return try await outletStreamCancel(requestIdHex: ridHex, callerDid: did)
    }

    /// `true` once a terminal chunk has been observed (AC13). Exposed
    /// read-only so callers can branch on it before invoking the
    /// control-plane methods.
    public var isTerminated: Bool {
        terminatedFlag.isTerminated
    }

    /// SCP-OUT-038 AC12 — validate the End.aggregate payload against
    /// the registered `aggregateSchemaJson`. No-op when no schema is
    /// bound. The validator performs a structural pass-through (type
    /// match + required fields) — the bridge has already validated at
    /// registration time per §5.4.5; this SDK-side hook is defense in
    /// depth.
    private func validateAggregate(_ agg: Aggregate) throws {
        guard let schemaJson = aggregateSchemaJson else { return }
        guard let schemaData = schemaJson.data(using: .utf8),
              let schema = try? JSONSerialization.jsonObject(with: schemaData) as? [String: Any]
        else {
            return // can't parse schema — fail open
        }
        guard let aggData = agg.valueJson.data(using: .utf8),
              let aggValue = try? JSONSerialization.jsonObject(with: aggData)
        else {
            throw makeOutputError(slug: "output.invalid-json", message: "End.aggregate is not valid JSON")
        }
        try checkSchemaType(aggValue: aggValue, schema: schema)
        try checkSchemaRequired(aggValue: aggValue, schema: schema)
    }

    private func checkSchemaType(aggValue: Any, schema: [String: Any]) throws {
        guard let declaredType = schema["type"] as? String else { return }
        let actual = jsonValueTypeName(aggValue)
        let matches = declaredType == actual
            || (declaredType == "number" && actual == "integer")
            || (declaredType == "object" && actual == "object")
        if !matches {
            throw makeOutputError(
                slug: "output.type-mismatch",
                message: "End.aggregate type '\(actual)' does not match aggregate_schema type '\(declaredType)'"
            )
        }
    }

    private func checkSchemaRequired(aggValue: Any, schema: [String: Any]) throws {
        guard let required = schema["required"] as? [String],
              let obj = aggValue as? [String: Any] else { return }
        for field in required where obj[field] == nil {
            throw makeOutputError(
                slug: "output.missing-required-field",
                message: "End.aggregate missing required field '\(field)' per aggregate_schema"
            )
        }
    }

    private func jsonValueTypeName(_ value: Any) -> String {
        if value is [Any] { return "array" }
        if value is [String: Any] { return "object" }
        if value is String { return "string" }
        if value is NSNull { return "null" }
        if let num = value as? NSNumber {
            if CFGetTypeID(num) == CFBooleanGetTypeID() { return "boolean" }
            // Bridge `intValue` (Int) to Double for the equality compare —
            // Swift 6 strict typing rejects `Int == Double`. The Double-
            // domain comparison preserves the existing semantics (an
            // integer-valued NSNumber is reported as "integer", anything
            // else as "number").
            let asDouble = num.doubleValue
            if Double(num.intValue) == asDouble, asDouble.truncatingRemainder(dividingBy: 1) == 0 {
                return "integer"
            }
            return "number"
        }
        return "unknown"
    }

    private func makeOutputError(slug: String, message: String) -> OutletError {
        OutletError.output(
            OutletEnvelope(
                classWire: .output,
                code: "SCP-TOOL-6140",
                slug: slug,
                message: message,
                retry: .never,
                detail: nil,
                sourceChain: [],
                padNonce: nil,
                registrationEventId: nil
            )
        )
    }
}

/// Internal — atomic terminal-state flag for `InvocationHandle`. Held
/// behind an `NSLock` so the iterator pump can flip it from any thread
/// while the control-plane methods read it on the caller's actor.
private final class TerminatedFlag: @unchecked Sendable {
    private var flag = false
    private let lock = NSLock()

    func markTerminated() {
        lock.lock()
        defer { lock.unlock() }
        flag = true
    }

    var isTerminated: Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }
}

// MARK: - invokeCrossContext (labeled-argument form; Swift's native idiom)

//
// Cross-context invocation uses labeled arguments (API MAJOR 22, round-5
// minor). Swift's labeled-argument style is the per-language idiom for
// target/outletId disambiguation — an options-object wrapper is not required.

// MARK: - OutletNamespace + sub-namespaces

/// `ctx.outlets` — outlet surface for a Swift `Context`.
///
/// Exposes the full verb set (`register` / `invoke` / `update` / `get` /
/// `list` / `verify` / `deregister`) plus `.sessions` and `.offers`
/// sub-namespaces. `invokeCrossContext` uses labeled arguments —
/// `target: DID`, `outletId: OutletId` — so the compiler rejects positional
/// target/outletId swap (API MINOR round 5).
public actor OutletNamespace {
    private let handle: ContextHandle
    private let identity: Identity
    public let sessions: OutletSessionsNamespace
    public let offers: OutletOffersNamespace

    init(handle: ContextHandle, identity: Identity) {
        self.handle = handle
        self.identity = identity
        sessions = OutletSessionsNamespace(handle: handle, identity: identity)
        offers = OutletOffersNamespace(handle: handle)
    }

    // MARK: register / invoke / update / get / list / verify / deregister

    /// Register an outlet in the context.
    ///
    /// SCP-OUT-017 makes `kind` REQUIRED on `OutletDefinition` — the
    /// UniFFI-generated type carries a non-optional `kind: OutletKind`
    /// field, so omitting it is a Swift compile error. Two call styles
    /// are supported:
    ///
    /// 1. **Single-argument form** — pass an `OutletDefinition`
    ///    constructed with the `kind:` labeled argument.
    /// 2. **Labeled form** — pass `kind:` plus the rest of the fields as
    ///    individual arguments. The labeled `kind:` argument is required
    ///    in this form (no default).
    public func register(_ definition: OutletDefinition) async throws -> String {
        return try await outletRegister(handle: handle, definition: definition)
    }

    /// Register an outlet using labeled arguments. `kind` is REQUIRED
    /// (no default) — Swift's labeled-argument style is the per-language
    /// idiom for surfacing the requirement at compile time.
    public func register(
        kind: OutletKind,
        name: String,
        description: String,
        inputSchemaJson: String,
        outputSchemaJson: String,
        operatorDid: String,
        testVectorsJson: String? = nil,
        implementationHash: Data? = nil,
        cost: ToolCostDefinition? = nil
    ) async throws -> String {
        let definition = OutletDefinition(
            name: name,
            description: description,
            kind: kind,
            inputSchemaJson: inputSchemaJson,
            outputSchemaJson: outputSchemaJson,
            operatorDid: operatorDid,
            testVectorsJson: testVectorsJson,
            implementationHash: implementationHash,
            cost: cost
        )
        return try await outletRegister(handle: handle, definition: definition)
    }

    /// Convenience: register an outlet with `kind: .query`.
    ///
    /// Equivalent to `register(kind: .query, ...)`. Use when the outlet
    /// is read-only and idempotent (§5.4.2).
    public func registerQuery(
        name: String,
        description: String,
        inputSchemaJson: String,
        outputSchemaJson: String,
        operatorDid: String,
        testVectorsJson: String? = nil,
        implementationHash: Data? = nil,
        cost: ToolCostDefinition? = nil
    ) async throws -> String {
        return try await register(
            kind: .query,
            name: name,
            description: description,
            inputSchemaJson: inputSchemaJson,
            outputSchemaJson: outputSchemaJson,
            operatorDid: operatorDid,
            testVectorsJson: testVectorsJson,
            implementationHash: implementationHash,
            cost: cost
        )
    }

    /// Convenience: register an outlet with `kind: .action`.
    public func registerAction(
        name: String,
        description: String,
        inputSchemaJson: String,
        outputSchemaJson: String,
        operatorDid: String,
        testVectorsJson: String? = nil,
        implementationHash: Data? = nil,
        cost: ToolCostDefinition? = nil
    ) async throws -> String {
        return try await register(
            kind: .action,
            name: name,
            description: description,
            inputSchemaJson: inputSchemaJson,
            outputSchemaJson: outputSchemaJson,
            operatorDid: operatorDid,
            testVectorsJson: testVectorsJson,
            implementationHash: implementationHash,
            cost: cost
        )
    }

    /// Invoke an outlet — the SOLE public verb (SCP-OUT-038 AC1).
    ///
    /// Returns an `InvocationHandle` that exposes both
    /// `await handle.aggregate` and `for try await chunk in handle`,
    /// plus the SCP-OUT-038 control-plane methods
    /// `handle.grantCredit(_:)` and `handle.cancel(nextSeq:)`.
    ///
    /// When `caveatsBindingHex` AND `streamEpoch` are supplied, opens
    /// a real §5.4.5 streaming session via `outletInvokeStream` — the
    /// returned handle carries a real `request_id` and grant_credit /
    /// cancel route to the runtime. When omitted, falls back to the
    /// non-streaming bridge (degenerate single-chunk per §5.4.5) and
    /// the handle's lifecycle ends synchronously — control-plane
    /// methods then raise `OutletError.streamAlreadyClosed` per AC13.
    public func invoke(
        id: String,
        input: String,
        ucanToken: String? = nil,
        proofTokens: [String]? = nil,
        spendingUcanJwt: String? = nil,
        caveatsBindingHex: String? = nil,
        streamEpoch: UInt64? = nil,
        creditWindow: UInt32? = nil,
        estimatedChunkCount: UInt32? = nil,
        aggregateSchemaJson: String? = nil
    ) -> InvocationHandle {
        if let cbh = caveatsBindingHex, let epoch = streamEpoch, let ucan = ucanToken {
            return makeStreamingHandle(
                outletId: id,
                inputJson: input,
                ucanToken: ucan,
                caveatsBindingHex: cbh,
                streamEpoch: epoch,
                proofTokens: proofTokens,
                creditWindow: creditWindow,
                estimatedChunkCount: estimatedChunkCount,
                aggregateSchemaJson: aggregateSchemaJson
            )
        }
        return makeOneShotHandle(
            outletId: id,
            inputJson: input,
            ucanToken: ucanToken,
            proofTokens: proofTokens,
            spendingUcanJwt: spendingUcanJwt,
            aggregateSchemaJson: aggregateSchemaJson
        )
    }

    private func makeOneShotHandle(
        outletId: String,
        inputJson: String,
        ucanToken: String?,
        proofTokens: [String]?,
        spendingUcanJwt: String?,
        aggregateSchemaJson: String?
    ) -> InvocationHandle {
        let handle = self.handle
        let identity = self.identity
        return InvocationHandle(
            requestIdHex: nil,
            aggregateSchemaJson: aggregateSchemaJson
        ) { yieldChunk, resolveAggregate, rejectAggregate in
            Task {
                do {
                    let output = try await outletInvoke(
                        handle: handle,
                        outletId: outletId,
                        inputJson: inputJson,
                        identity: identity,
                        ucanToken: ucanToken,
                        proofTokens: proofTokens,
                        spendingUcanJwt: spendingUcanJwt
                    )
                    let chunk = OutletStreamChunk(
                        requestId: Data(count: 16),
                        sequence: 0,
                        payload: .end(aggregate: output, executionTimeMs: 0)
                    )
                    yieldChunk(chunk)
                    resolveAggregate(Aggregate(valueJson: output))
                } catch {
                    rejectAggregate(error)
                }
            }
        }
    }

    // §5.4.5 streaming open + 4 wire-mandated knobs
    // (caveatsBinding, streamEpoch, creditWindow, estimatedChunkCount)
    // require 9 parameters; the count is bound to the spec's preimage,
    // not to the SDK's choice.
    // swiftlint:disable:next function_parameter_count
    private func makeStreamingHandle(
        outletId: String,
        inputJson: String,
        ucanToken: String,
        caveatsBindingHex: String,
        streamEpoch: UInt64,
        proofTokens: [String]?,
        creditWindow: UInt32?,
        estimatedChunkCount: UInt32?,
        aggregateSchemaJson: String?,
        ucanRecheckSecs: UInt32 = 10
    ) -> InvocationHandle {
        let handle = self.handle
        let identity = self.identity
        let invokerDidValue = identity.did()
        return InvocationHandle(
            requestIdHex: nil,
            invokerDid: invokerDidValue,
            aggregateSchemaJson: aggregateSchemaJson
        ) { yieldChunk, resolveAggregate, rejectAggregate in
            Task {
                do {
                    let raw = try await outletInvokeStream(
                        handle: handle,
                        outletId: outletId,
                        inputJson: inputJson,
                        identity: identity,
                        ucanToken: ucanToken,
                        caveatsBindingHex: caveatsBindingHex,
                        streamEpoch: streamEpoch,
                        proofTokens: proofTokens,
                        creditWindow: creditWindow,
                        estimatedChunkCount: estimatedChunkCount
                    )
                    let recheckTask = makeRevocationRecheckTask(
                        contextHandle: handle,
                        outletId: outletId,
                        ucanToken: ucanToken,
                        proofTokens: proofTokens,
                        recheckSecs: ucanRecheckSecs,
                        requestIdHex: raw.requestId(),
                        invokerDid: invokerDidValue
                    )
                    defer { recheckTask.cancel() }
                    try await pumpStreamingChunks(
                        from: raw,
                        yieldChunk: yieldChunk,
                        resolveAggregate: resolveAggregate,
                        rejectAggregate: rejectAggregate
                    )
                } catch {
                    rejectAggregate(error)
                }
            }
        }
    }

    public func update(
        id: String,
        definition: OutletDefinition,
        updaterDid: String? = nil
    ) async throws -> String {
        // `??` evaluates its right-hand side in a non-async autoclosure;
        // `await` is not legal inside the autoclosure under Swift 6
        // strict concurrency. Hoist the await out before the coalesce.
        let actor: String
        if let updaterDid {
            actor = updaterDid
        } else {
            actor = try await identityDid()
        }
        return try await outletUpdate(
            handle: handle,
            outletId: id,
            definition: definition,
            updaterDid: actor
        )
    }

    public func get(id: String) async throws -> String {
        return try await outletGet(handle: handle, outletId: id)
    }

    public func list() async throws -> [String] {
        return try await outletList(handle: handle)
    }

    public func verify(id: String) async throws -> OutletVerificationResult {
        return try await outletVerify(handle: handle, outletId: id)
    }

    public func deregister(id: String, actorDid: String? = nil) async throws {
        // Hoist the await out of the `??` autoclosure (Swift 6 strict
        // concurrency rejects async calls inside non-async autoclosures).
        let actor: String
        if let actorDid {
            actor = actorDid
        } else {
            actor = try await identityDid()
        }
        try await outletDeregister(
            handle: handle,
            outletId: id,
            actorDid: actor
        )
    }

    // MARK: invokeCrossContext (labeled-argument form)

    /// Invoke an outlet in a target context.
    ///
    /// Swift's labeled-argument style is the per-language idiom for
    /// target/outletId disambiguation (API MINOR round 5 — options-object
    /// wrapper NOT required). The typed `DID` / `OutletId` struct arguments
    /// further close the swap risk at compile time: a caller who passes an
    /// `OutletId` to `target:` fails type-checking.
    public func invokeCrossContext(
        target _: DID,
        outletId: OutletId,
        input: String,
        ucan: String,
        chainDepth: UInt8 = 0,
        proofTokens: [String]? = nil,
        targetHandle: ContextHandle
    ) async throws -> String {
        return try await outletInvokeCrossContext(
            sourceHandle: handle,
            targetHandle: targetHandle,
            outletId: outletId.raw,
            inputJson: input,
            identity: identity,
            ucanToken: ucan,
            chainDepth: chainDepth,
            proofTokens: proofTokens
        )
    }

    private func identityDid() async throws -> String {
        return identity.did()
    }
}

// MARK: - Sub-namespaces

public actor OutletSessionsNamespace {
    private let handle: ContextHandle
    private let identity: Identity

    init(handle: ContextHandle, identity: Identity) {
        self.handle = handle
        self.identity = identity
    }

    public func open(
        outletId: String,
        sourceContextId: String,
        ttlSeconds: UInt64? = nil
    ) async throws -> SessionId {
        let raw = try await outletSessionOpen(
            handle: handle,
            outletId: outletId,
            sourceContextId: sourceContextId,
            ttlSeconds: ttlSeconds
        )
        // If the bridge still returns legacy UUIDv4s we accept transparently —
        // validate only when it returns a UUIDv7.
        let regex = SessionId.uuid7Regex
        let range = NSRange(raw.startIndex ..< raw.endIndex, in: raw)
        if regex.firstMatch(in: raw, options: [], range: range) != nil {
            try SessionId.validate(raw: raw)
        }
        return SessionId(unvalidated: raw)
    }

    public func invoke(
        sessionId: SessionId,
        input: String,
        ucanToken: String,
        proofTokens: [String]? = nil
    ) async throws -> String {
        return try await outletSessionInvoke(
            handle: handle,
            sessionId: sessionId.raw,
            inputJson: input,
            identity: identity,
            ucanToken: ucanToken,
            proofTokens: proofTokens
        )
    }

    public func close(sessionId: SessionId) async throws {
        try await outletSessionClose(handle: handle, sessionId: sessionId.raw)
    }
}

public actor OutletOffersNamespace {
    private let handle: ContextHandle

    init(handle: ContextHandle) {
        self.handle = handle
    }

    public func propose(
        outletId: String,
        targetContextId: String,
        rateLimitJson: String? = nil
    ) async throws -> String {
        return try await outletInterfaceOffer(
            handle: handle,
            outletId: outletId,
            targetContextId: targetContextId,
            rateLimitJson: rateLimitJson
        )
    }

    public func accept(interfaceJson: String) async throws -> String {
        return try await outletInterfaceAccept(handle: handle, interfaceJson: interfaceJson)
    }

    public func revoke(interfaceIdHex: String) async throws -> String {
        return try await outletInterfaceRevoke(handle: handle, interfaceIdHex: interfaceIdHex)
    }

    /// List outbound outlet-interface offers.
    ///
    /// The bridge does not yet expose an offer-listing primitive; returns
    /// an empty array as a stable no-op at the SDK layer (offers are
    /// visible via the context's event log).
    public func list() async throws -> [String] {
        []
    }
}

// MARK: - Context.outlets extension

public extension Context {
    /// The outlet surface for this context (SCP-OUT-006).
    ///
    /// Exposes the full outlet verb set plus `.sessions` / `.offers`
    /// sub-namespaces. See `OutletNamespace` for the public shape.
    var outlets: OutletNamespace {
        get async {
            OutletNamespace(handle: handle, identity: identity)
        }
    }
}
