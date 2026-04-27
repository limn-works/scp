import Foundation

// ScpError is now defined by UniFFI in ScpBindings.swift.
// The generated enum uses uppercase case names: .Identity, .Context, .Permission,
// .Crypto, .Transport, .Tool, .Validation — each with (msg: String, code: String).
//
// UniFFI also provides Foundation.LocalizedError conformance in ScpBindings.swift.
// No additional conformance is needed here.

// MARK: - §5.4.4 Outlet error taxonomy (sealed Swift hierarchy)

/// Wire-form `OutletErrorClass` discriminant — one of the eight §5.4.4 root
/// classes. Each `OutletError` enum case (in `Outlets.swift`) carries an
/// associated `OutletEnvelope` whose `classWire` matches the case.
public enum OutletErrorClass: String, Sendable, Equatable, CaseIterable {
    case `protocol`
    case authorization
    case input
    case execution
    case output
    case economic
    case transport
    case governance
}

/// §5.4.4 tag-5 retry guidance — sealed Swift enum.
public enum RetryPolicy: Sendable, Equatable {
    case never
    case immediate
    case after(delayMs: UInt64)
    case withBackoff(minMs: UInt64, maxMs: UInt64)
}

/// §5.4.4 tag-8 source-chain entry.
public struct ContextHop: Sendable, Equatable {
    public let contextId: String
    public let hopIndex: UInt16
    public let wrappedCode: String

    public init(contextId: String, hopIndex: UInt16, wrappedCode: String) {
        self.contextId = contextId
        self.hopIndex = hopIndex
        self.wrappedCode = wrappedCode
    }
}

/// §5.4.4 per-class detail — closed enum (free-form `detail` is forbidden).
public enum OutletErrorDetail: Sendable, Equatable {
    case protocolRule(rule: String)
    case authorizationCapability(capability: String)
    case fieldViolation(fieldPath: String, violation: String)
    case executionTimeout(elapsedMs: UInt64)
    case executionPanic(panicLocationHash: String)
    case executionEmpty
    case economicInsufficient(needed: UInt64, currency: String)
    case economicAdapter(adapterId: String)
    case transportRateLimit(retryAfterSecs: UInt32)
    case transportRelay(relayUrlKind: RelayUrlKind)
    case governanceAction(action: String)

    public enum RelayUrlKind: String, Sendable, Equatable {
        case wss
        case wsLoopback = "ws-loopback"
        case unknown
    }

    /// Returns `true` if this detail variant is legal for `class_`.
    public func matches(class: OutletErrorClass) -> Bool {
        switch (`class`, self) {
        case (.protocol, .protocolRule): return true
        case (.authorization, .authorizationCapability): return true
        case (.input, .fieldViolation), (.output, .fieldViolation):
            return true
        case (.execution, .executionTimeout),
             (.execution, .executionPanic),
             (.execution, .executionEmpty):
            return true
        case (.economic, .economicInsufficient),
             (.economic, .economicAdapter):
            return true
        case (.transport, .transportRateLimit),
             (.transport, .transportRelay):
            return true
        case (.governance, .governanceAction): return true
        default: return false
        }
    }
}

// MARK: - Branded newtypes (Credit, CatalogKey, OutletId)

/// Round-6 brand newtype for an Outlet credit grant — `init` rejects zero
/// and over-`UInt32.max` values with `OutletError.invalidGrant`.
public struct Credit: Sendable, Hashable {
    public let raw: UInt32

    public init(_ raw: UInt32) throws {
        guard raw > 0 else {
            throw OutletError.invalidGrant(Credit(unvalidated: 0))
        }
        self.raw = raw
    }

    /// Internal initializer used to construct the associated value of the
    /// `OutletError.invalidGrant` case when zero is rejected — never used
    /// to build a public `Credit`.
    fileprivate init(unvalidated raw: UInt32) {
        self.raw = raw
    }
}

/// Round-6 brand newtype for §5.4.4 catalog keys — regex-validated.
public struct CatalogKey: Sendable, Hashable {
    public let raw: String

    public init(_ raw: String) throws {
        guard CatalogKey.isValid(raw) else {
            throw OutletError.protocol(
                OutletEnvelope(
                    classWire: .protocol,
                    code: "SCP-TOOL-6100",
                    slug: "protocol.malformed-catalog-key",
                    message: "malformed catalog key: \(raw)",
                    retry: .never,
                    detail: nil,
                    sourceChain: [],
                    padNonce: nil,
                    registrationEventId: nil
                )
            )
        }
        self.raw = raw
    }

    static func isValid(_ raw: String) -> Bool {
        guard !raw.isEmpty else { return false }
        guard raw.utf8.count <= 256 else { return false }
        let pattern = "^[a-z][a-z0-9-]{0,63}(\\.[a-z][a-z0-9-]{0,63})*$"
        return raw.range(of: pattern, options: .regularExpression) != nil
    }
}

/// Branded outlet id newtype.
public struct OutletId: Sendable, Hashable {
    public let raw: String
    public init(_ raw: String) throws {
        guard !raw.isEmpty else {
            throw OutletError.validation(
                message: "outletId must be non-empty",
                code: "SCP-VALID-7000"
            )
        }
        self.raw = raw
    }
}

// MARK: - OutletEnvelope (typed §5.4.4 envelope carried by enum cases)

/// Typed §5.4.4 envelope carried by `OutletError`'s sealed-hierarchy cases.
public struct OutletEnvelope: Sendable, Equatable {
    public let classWire: OutletErrorClass
    public let code: String
    public let slug: String
    public let message: String
    public let retry: RetryPolicy
    public let detail: OutletErrorDetail?
    public let sourceChain: [ContextHop]
    public let padNonce: Data?
    public let registrationEventId: Data?

    public init(
        classWire: OutletErrorClass,
        code: String,
        slug: String,
        message: String,
        retry: RetryPolicy,
        detail: OutletErrorDetail?,
        sourceChain: [ContextHop],
        padNonce: Data?,
        registrationEventId: Data?
    ) {
        self.classWire = classWire
        self.code = code
        self.slug = slug
        // PII redaction is mandatory before storing the message — closes
        // the §5.4.4 redaction lint at the SDK boundary.
        self.message = redactPII(message)
        self.retry = retry
        self.detail = detail
        self.sourceChain = sourceChain
        self.padNonce = padNonce
        self.registrationEventId = registrationEventId
    }

    /// Construct an envelope from a §5.4.4 `OutletError.new` call. Detail
    /// shape mismatches throw a typed `OutletError.validation`.
    static func makeForCreation(
        outletId _: OutletId,
        catalogKey: CatalogKey,
        classWire: OutletErrorClass,
        retry: RetryPolicy,
        detail: OutletErrorDetail?
    ) throws -> OutletEnvelope {
        if let detailValue = detail, !detailValue.matches(class: classWire) {
            throw OutletError.validation(
                message: "OutletError.detail shape mismatch for class \(classWire.rawValue)",
                code: "SCP-VALID-7000"
            )
        }
        let code = OutletEnvelope.defaultCode(for: classWire)
        let slug = catalogKey.raw
        return OutletEnvelope(
            classWire: classWire,
            code: code,
            slug: slug,
            message: catalogKey.raw,
            retry: retry,
            detail: detail,
            sourceChain: [],
            padNonce: nil,
            registrationEventId: nil
        )
    }

    static func defaultCode(for errorClass: OutletErrorClass) -> String {
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

    /// SCP-OUT-041d — parses the bridge wire-form JSON produced by
    /// `outletErrorNew` / `outletCatalogRotationValidator`. Field names
    /// are snake_case (`pad_nonce`, `registration_event_id`,
    /// `source_chain`); byte fields are lowercase hex strings.
    static func fromBridgeWire(_ json: String) throws -> OutletEnvelope {
        guard let data = json.data(using: .utf8),
              let any = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw OutletError.validation(
                message: "outlet error envelope is not valid JSON",
                code: "SCP-VALID-7000"
            )
        }
        guard let classRaw = any["class"] as? String,
              let classWire = OutletErrorClass(rawValue: classRaw)
        else {
            throw OutletError.validation(
                message: "outlet error envelope missing or invalid 'class'",
                code: "SCP-VALID-7000"
            )
        }
        let code = (any["code"] as? String) ?? defaultCode(for: classWire)
        let slug = (any["slug"] as? String) ?? ""
        let message = (any["message"] as? String) ?? ""
        let retryDict = any["retry"] as? [String: Any] ?? ["policy": "never"]
        let retry: RetryPolicy
        switch retryDict["policy"] as? String ?? "never" {
        case "immediate": retry = .immediate
        case "after":
            retry = .after(delayMs: (retryDict["delay_ms"] as? UInt64) ?? 0)
        case "with-backoff":
            retry = .withBackoff(
                minMs: (retryDict["min_ms"] as? UInt64) ?? 0,
                maxMs: (retryDict["max_ms"] as? UInt64) ?? 0
            )
        default: retry = .never
        }
        let padNonceData = (any["pad_nonce"] as? String).flatMap { Data(hexString: $0) }
        let regIdData = (any["registration_event_id"] as? String).flatMap { Data(hexString: $0) }
        return OutletEnvelope(
            classWire: classWire,
            code: code,
            slug: slug,
            message: message,
            retry: retry,
            detail: nil,
            sourceChain: [],
            padNonce: padNonceData,
            registrationEventId: regIdData
        )
    }
}

extension RetryPolicy {
    /// SCP-OUT-041d wire policy string for the FFI bridge call site.
    var wireForm: String {
        switch self {
        case .never: return "never"
        case .immediate: return "immediate"
        case .after: return "after"
        case .withBackoff: return "with-backoff"
        }
    }
}

private extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var idx = hexString.startIndex
        for _ in 0 ..< len {
            let next = hexString.index(idx, offsetBy: 2)
            guard next <= hexString.endIndex,
                  let byte = UInt8(hexString[idx ..< next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }
}

// MARK: - PII redaction

/// Redacts emails and DIDs from a §5.4.4 message before surfacing to logs.
///
/// Matches the same regex set as the other three SDKs.
public func redactPII(_ message: String) -> String {
    var out = message
    let emailPattern = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
    if let regex = try? NSRegularExpression(pattern: emailPattern, options: []) {
        out = regex.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(out.startIndex..., in: out),
            withTemplate: "[redacted]"
        )
    }
    let didPattern = "did:(dht|web|key):[A-Za-z0-9._-]+"
    if let regex = try? NSRegularExpression(pattern: didPattern, options: []) {
        out = regex.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(out.startIndex..., in: out),
            withTemplate: "[redacted]"
        )
    }
    return out
}
