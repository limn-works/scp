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

/// Distinct `OutletId` type — see `DID`.
public struct OutletId: Sendable, Hashable {
    public let raw: String
    public init(_ raw: String) {
        self.raw = raw
    }
}

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
/// Error-code prefix remains `SCP-TOOL-*` (§9.18 — registered namespace).
public enum OutletError: Error, Sendable, Equatable {
    case notFound(message: String, code: String)
    case executionFailed(message: String, code: String)
    case validation(message: String, code: String)
    case unauthorized(message: String, code: String)
    case bridge(message: String, code: String)
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
///   `AsyncSequence` / `AsyncThrowingStream`.
public final class InvocationHandle: @unchecked Sendable, AsyncSequence {
    public typealias Element = OutletStreamChunk

    private let stream: AsyncThrowingStream<OutletStreamChunk, Error>
    private let aggregateTask: Task<Aggregate, Error>

    public init(pump: @Sendable @escaping (
        @Sendable @escaping (OutletStreamChunk) -> Void,
        @Sendable @escaping (Aggregate) -> Void,
        @Sendable @escaping (Error) -> Void
    ) -> Void) {
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
        pump(
            { chunk in chunkCont?.yield(chunk) },
            { agg in
                resolveAggregate?(agg)
                chunkCont?.finish()
            },
            { err in
                rejectAggregate?(err)
                chunkCont?.finish(throwing: err)
            }
        )
    }

    /// Await the terminal aggregate value.
    public var aggregate: Aggregate {
        get async throws {
            try await aggregateTask.value
        }
    }

    public func makeAsyncIterator() -> AsyncThrowingStream<OutletStreamChunk, Error>.AsyncIterator {
        stream.makeAsyncIterator()
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

    public func register(_ definition: OutletDefinition) async throws -> String {
        return try await outletRegister(handle: handle, definition: definition)
    }

    /// Invoke an outlet — returns an `InvocationHandle` that exposes both
    /// `await handle.aggregate` and `for try await chunk in handle`.
    public func invoke(
        id: String,
        input: String,
        ucanToken: String? = nil,
        proofTokens: [String]? = nil,
        spendingUcanJwt: String? = nil
    ) -> InvocationHandle {
        let handle = self.handle
        let identity = self.identity
        return InvocationHandle { yieldChunk, resolveAggregate, rejectAggregate in
            Task {
                do {
                    let output = try await outletInvoke(
                        handle: handle,
                        outletId: id,
                        inputJson: input,
                        identity: identity,
                        ucanToken: ucanToken,
                        proofTokens: proofTokens,
                        spendingUcanJwt: spendingUcanJwt
                    )
                    // Non-streaming bridge — synthesize a single `end` chunk.
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

    public func update(
        id: String,
        definition: OutletDefinition,
        updaterDid: String? = nil
    ) async throws -> String {
        let actor = try updaterDid ?? (await identityDid())
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
        let actor = try actorDid ?? (await identityDid())
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
