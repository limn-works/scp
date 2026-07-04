import Foundation

// The UniFFI bridge (`crates/scp-ffi/uniffi/src/bridge.rs`) exports the raw
// trust-signal ops this file wraps idiomatically:
//   - `ucanEvaluate(handle:token:capability:presentingAgentDid:proofTokens:)`
//     returns the typed `CapabilityValidationRecord` (six per-stage booleans).
//   - `participationRecord(contextId:subjectDid:cachedAttestationsJson:)`
//     returns the typed `ParticipationRecordView` (the twelve §7.3.2 facts).
// Both are generated in `Internal/ScpBindings.swift`. This module exposes the
// Swift-idiomatic `CapabilityValidation` / `BehavioralRecord` / `TrustEvaluation`
// types and the `SCP.ucanEvaluate` / `SCP.participationRecord` / `SCP.evaluateTrust`
// wrappers ON TOP of them — mirroring the Python (`scp_sdk.trust`) and
// TypeScript (`scp.ts` / `types.ts`) SDKs field-for-field.
//
// ## Provenance
//
// - ADR-057 (Structured capability evaluation) in `.docs/adrs/phase-2.md`
// - `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.4, §7.3.2
// - ADR-017 (Trust Model) in `.docs/adrs/phase-4.md`

/// Stable error code (spec §7.3.2) the core surfaces when a context has no
/// recorded participation facts yet (an empty event log).
///
/// ``SCP/evaluateTrust(handle:subjectDid:capabilityTokens:)`` branches Layer 2
/// on this STRUCTURED code — never on error prose — folding "no facts yet" into
/// a zeroed behavioral record while letting every other failure propagate.
/// Mirrors the Python SDK `NO_PARTICIPATION_FACTS_CODE` and the TypeScript SDK
/// `NO_PARTICIPATION_FACTS_CODE`.
public let noParticipationFactsCode = "SCP-CTX-2076"

// MARK: - CapabilityValidation (Layer 1)

/// Layer 1: protocol-enforcement results (mechanical, pass/fail).
///
/// The six per-stage booleans are the canonical structured result of the
/// read-only ``SCP/ucanEvaluate(handle:token:presentingAgentDid:capability:proofTokens:)``
/// diagnostic (spec §7.2.4, ADR-057): one boolean per pipeline-stage group of
/// the 11-step ADR-016 pipeline. They are populated directly from the bridge's
/// typed ``CapabilityValidationRecord`` — never reverse-engineered by parsing
/// error prose. The result is strictly ordered and short-circuiting: a field is
/// `true` only if its stage ran *and* passed, so the first failing stage and
/// every later stage are `false`.
///
/// Mirrors the Python SDK `CapabilityValidation` dataclass and the TypeScript
/// SDK `CapabilityValidation` interface field-for-field.
public nonisolated struct CapabilityValidation: Sendable, Equatable {
    /// Step 1: the UCAN token parsed and its structure validated.
    public let tokensValid: Bool

    /// Steps 2-7: signatures, the full delegation chain, root issuer, audience,
    /// key scope, Category-A enforcement, and attenuation verify. The
    /// invoked-capability grant-match (step 6) is included ONLY when a challenge
    /// capability is supplied; in the diagnostic's intrinsic-validity mode (the
    /// mode ``SCP/evaluateTrust(handle:subjectDid:capabilityTokens:)`` uses — no
    /// challenge), step 6 is SKIPPED and this field reflects only the structural
    /// checks, not grant-match.
    public let signaturesValid: Bool

    /// Step 8: every requested capability is within the context's ceiling.
    public let withinCeiling: Bool

    /// Step 9: nonce format, freshness, and uniqueness passed. Probed read-only
    /// by the diagnostic — the nonce is NOT recorded.
    public let nonceValid: Bool

    /// Step 10: no token's revocation CID is on the revocation list.
    public let notRevoked: Bool

    /// Step 11: `exp`/`nbf` time bounds are valid (within clock-skew tolerance).
    public let timeBoundsValid: Bool

    /// Memberwise initializer.
    public init(
        tokensValid: Bool,
        signaturesValid: Bool,
        withinCeiling: Bool,
        nonceValid: Bool,
        notRevoked: Bool,
        timeBoundsValid: Bool
    ) {
        self.tokensValid = tokensValid
        self.signaturesValid = signaturesValid
        self.withinCeiling = withinCeiling
        self.nonceValid = nonceValid
        self.notRevoked = notRevoked
        self.timeBoundsValid = timeBoundsValid
    }

    /// Projects the typed UniFFI ``CapabilityValidationRecord`` onto this SDK
    /// type. Reads the six booleans directly — the per-check breakdown comes
    /// from the structured record, never from parsing error prose (spec §7.2.4,
    /// ADR-057 Decision 3).
    public init(record: CapabilityValidationRecord) {
        self.init(
            tokensValid: record.tokensValid,
            signaturesValid: record.signaturesValid,
            withinCeiling: record.withinCeiling,
            nonceValid: record.nonceValid,
            notRevoked: record.notRevoked,
            timeBoundsValid: record.timeBoundsValid
        )
    }

    /// `true` iff every per-stage check passed.
    ///
    /// The one obvious correct happy-path call: collapses the six per-stage
    /// booleans with a logical AND so consumers do not hand-roll the
    /// conjunction (and cannot silently omit a field when a new stage is added).
    /// A token is protocol-compliant only when all six are `true`. Mirrors the
    /// Python `CapabilityValidation.all_valid` accessor and the TypeScript
    /// `allValid` helper.
    ///
    /// SECURITY: this is a DIAGNOSTIC, NEVER an authorization decision. It
    /// reports that the UCAN tokens are *intrinsically well-formed and valid*;
    /// it does NOT authorize any action. In intrinsic mode (capability = `nil` —
    /// no challenge capability supplied, the mode `evaluateTrust` uses), the
    /// invoked-capability grant-match (step 6) is SKIPPED, so `allValid` (and
    /// `signaturesValid` / `withinCeiling`) being `true` does NOT assert that any
    /// specific capability is granted. The diagnostic is also read-only: the
    /// nonce is probed but NOT consumed, so the evaluated tokens remain replayable
    /// against the enforcing path — another reason this is never an authorization
    /// decision. To gate an action, pass the concrete capability to
    /// `ucanEvaluate` (which then includes grant-match in `signaturesValid`) — or
    /// use the enforcing UCAN validation path (which consumes the nonce). Treating
    /// `allValid` as "the agent may do X" is a security error.
    public var allValid: Bool {
        tokensValid
            && signaturesValid
            && withinCeiling
            && nonceValid
            && notRevoked
            && timeBoundsValid
    }
}

// MARK: - BehavioralRecord (Layer 2)

/// Layer 2: the participation facts (§7.3.2) for a subject in a context.
///
/// The scalar projection of scp-core's `ParticipationRecord`, computed ONCE in
/// the shared Rust core and surfaced through the UniFFI `participation_record`
/// op (`ParticipationRecordView`). The SDK RECEIVES these facts rather than
/// re-aggregating event-log collections client-side — eliminating cross-binding
/// divergence by construction. Mirrors the Python SDK `BehavioralRecord`, the
/// TypeScript SDK `BehavioralRecord`, and the Rust `ParticipationFacts` 1:1.
///
/// The six leaf-derived facts (participation duration, governance actions
/// against/by, context creation, role progression, tool invocation count) come
/// from the context's convergent Merkle event log. `attestationCount` is the
/// one exception: it is a credential-layer fact (§7.4), NOT event-log-derived,
/// NOT covered by `eventLogRoot`, and **verifier-relative** (two agents may
/// compute different counts from different accessible attestation sets).
public nonisolated struct BehavioralRecord: Sendable, Equatable {
    /// The DID whose participation is summarized.
    public let subjectDid: String

    /// Total seconds of context participation (§7.3.2).
    public let participationDurationSecs: UInt64

    /// Count of governance actions taken against this identity (the subject is
    /// the projected target).
    public let governanceActionsAgainst: UInt64

    /// Count of governance actions initiated by this identity.
    public let governanceActionsBy: UInt64

    /// Total tool invocations across all tool types.
    public let toolInvocationCount: UInt64

    /// Whether ``toolInvocationCount`` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `ToolInvoked` a convergent leaf — consumers
    /// MUST NOT treat the count as Merkle-proven while this is `false`.
    public let toolInvocationCountAnchored: Bool

    /// Number of contexts created by the subject (`ChildContextCreated`).
    public let contextCreationCount: UInt64

    /// Number of role transitions for the subject (`RoleAssigned`).
    public let roleProgressionCount: UInt64

    /// Number of accessible, currently-valid credential-layer attestations
    /// (§7.4) for the subject. Verifier-relative; NOT a context-event count.
    public let attestationCount: UInt64

    /// Whether ``attestationCount`` is anchored in / verifiable against a
    /// context Merkle root. Always `false`: it is a credential-layer,
    /// verifier-relative fact (§7.4), never a context-event-log count (§7.3.2).
    /// The parallel of ``toolInvocationCountAnchored``.
    public let attestationCountAnchored: Bool

    /// Unix timestamp (seconds) when the record was computed.
    public let computedAt: UInt64

    /// Merkle root (hex) of the event log at computation time.
    public let eventLogRoot: String

    /// Memberwise initializer.
    ///
    /// The twelve §7.3.2 facts are all required (no silent defaults), matching
    /// the Python/TypeScript SDKs field-for-field, so the parameter count is
    /// intrinsic to the structured record — not an avoidable code smell.
    public init(
        subjectDid: String,
        participationDurationSecs: UInt64,
        governanceActionsAgainst: UInt64,
        governanceActionsBy: UInt64,
        toolInvocationCount: UInt64,
        toolInvocationCountAnchored: Bool,
        contextCreationCount: UInt64,
        roleProgressionCount: UInt64,
        attestationCount: UInt64,
        attestationCountAnchored: Bool,
        computedAt: UInt64,
        eventLogRoot: String
    ) {
        self.subjectDid = subjectDid
        self.participationDurationSecs = participationDurationSecs
        self.governanceActionsAgainst = governanceActionsAgainst
        self.governanceActionsBy = governanceActionsBy
        self.toolInvocationCount = toolInvocationCount
        self.toolInvocationCountAnchored = toolInvocationCountAnchored
        self.contextCreationCount = contextCreationCount
        self.roleProgressionCount = roleProgressionCount
        self.attestationCount = attestationCount
        self.attestationCountAnchored = attestationCountAnchored
        self.computedAt = computedAt
        self.eventLogRoot = eventLogRoot
    }

    /// Projects the typed UniFFI ``ParticipationRecordView`` onto this SDK type.
    public init(record: ParticipationRecordView) {
        self.init(
            subjectDid: record.subjectDid,
            participationDurationSecs: record.participationDurationSecs,
            governanceActionsAgainst: record.governanceActionsAgainst,
            governanceActionsBy: record.governanceActionsBy,
            toolInvocationCount: record.toolInvocationCount,
            toolInvocationCountAnchored: record.toolInvocationCountAnchored,
            contextCreationCount: record.contextCreationCount,
            roleProgressionCount: record.roleProgressionCount,
            attestationCount: record.attestationCount,
            attestationCountAnchored: record.attestationCountAnchored,
            computedAt: record.computedAt,
            eventLogRoot: record.eventLogRoot
        )
    }

    /// A zeroed record for a subject in a context with no recorded
    /// participation facts yet (an empty event log → `SCP-CTX-2076`). All counts
    /// are `0`, both `*Anchored` flags `false`, `eventLogRoot` empty — identical
    /// in shape to the Python/TypeScript SDKs' empty-log behavioral record.
    public static func zeroed(subjectDid: String) -> BehavioralRecord {
        BehavioralRecord(
            subjectDid: subjectDid,
            participationDurationSecs: 0,
            governanceActionsAgainst: 0,
            governanceActionsBy: 0,
            toolInvocationCount: 0,
            toolInvocationCountAnchored: false,
            contextCreationCount: 0,
            roleProgressionCount: 0,
            attestationCount: 0,
            attestationCountAnchored: false,
            computedAt: 0,
            eventLogRoot: ""
        )
    }
}

// MARK: - AttestationSummary (Layer 3)

/// Layer 3: a summary of an attestation for the subject.
///
/// Mirrors the TypeScript SDK `AttestationSummary` interface. Trust evaluation
/// reports the attestation layer as an empty array until the Layer-3 source is
/// wired; the type exists so the ``TrustEvaluation`` shape is identical across
/// bindings (Agent-first API design tenet).
public nonisolated struct AttestationSummary: Sendable, Equatable {
    /// Attestation type identifier.
    public let type: String

    /// DID of the attestation issuer.
    public let issuer: String

    /// Whether the attestation is currently valid.
    public let valid: Bool

    /// Whether the attestation has been revoked.
    public let revoked: Bool

    /// Memberwise initializer.
    public init(type: String, issuer: String, valid: Bool, revoked: Bool) {
        self.type = type
        self.issuer = issuer
        self.valid = valid
        self.revoked = revoked
    }
}

// MARK: - TrustEvaluation

/// The complete structured trust evaluation for a subject in a context
/// (spec §7.2.4, ADR-057). The protocol provides the data, not the verdict —
/// the caller decides what to do with it.
///
/// Mirrors the TypeScript SDK `TrustEvaluation` interface and the Python SDK
/// `TrustEvaluation` dataclass: Layer 1 (``capabilityValidation``) is the
/// per-stage boolean result AND-combined across the evaluated token set; Layer 2
/// (``behavioralRecord``) is the Rust-computed participation record; Layer 3
/// (``attestations``) is the attestation summary set.
public nonisolated struct TrustEvaluation: Sendable, Equatable {
    /// DID of the evaluated subject.
    public let subjectDid: String

    /// ID of the context the evaluation applies to (the resolved canonical id
    /// the layers were computed against).
    public let contextId: String

    /// Layer 1: protocol enforcement (mechanical pass/fail). The six per-stage
    /// booleans are AND-combined across the evaluated capability-token set, so a
    /// single token failing a stage makes that aggregate field `false`. With no
    /// tokens supplied every field is `false` (no stage was observed to pass).
    public let capabilityValidation: CapabilityValidation

    /// Layer 2: behavioral validation (verified facts). Always a record, never
    /// `nil` — a context with no recorded participation facts yet (an empty
    /// event log) yields a zeroed ``BehavioralRecord``.
    public let behavioralRecord: BehavioralRecord

    /// Layer 3: attestation summaries for the subject.
    public let attestations: [AttestationSummary]

    /// Memberwise initializer.
    public init(
        subjectDid: String,
        contextId: String,
        capabilityValidation: CapabilityValidation,
        behavioralRecord: BehavioralRecord,
        attestations: [AttestationSummary] = []
    ) {
        self.subjectDid = subjectDid
        self.contextId = contextId
        self.capabilityValidation = capabilityValidation
        self.behavioralRecord = behavioralRecord
        self.attestations = attestations
    }
}

// MARK: - Cached-attestation wire DTOs (ADR-017 §7.4.1)

/// A JSON value, used for the freeform fields of a ``CachedAttestationEnvelope``
/// (`claim`, `evidence.data`, `revocationStatus`) that the Rust core
/// deserializes as an arbitrary `serde_json::Value`.
///
/// `Codable`, so a ``CachedAttestation`` round-trips straight onto the wire via
/// `JSONEncoder` — the Swift analogue of the Python SDK's `Any` dict values and
/// the TypeScript SDK's `unknown` fields. Literal conformances let callers write
/// `claim: ["device": "iphone", "verified": true]` with no ceremony.
public nonisolated enum JSONValue: Codable, Sendable, Equatable {
    case null
    case bool(Bool)
    case integer(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "unsupported JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case let .bool(value):
            try container.encode(value)
        case let .integer(value):
            try container.encode(value)
        case let .double(value):
            try container.encode(value)
        case let .string(value):
            try container.encode(value)
        case let .array(value):
            try container.encode(value)
        case let .object(value):
            try container.encode(value)
        }
    }
}

extension JSONValue: ExpressibleByNilLiteral, ExpressibleByBooleanLiteral,
    ExpressibleByIntegerLiteral, ExpressibleByFloatLiteral, ExpressibleByStringLiteral,
    ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    public init(nilLiteral _: ()) {
        self = .null
    }

    public init(booleanLiteral value: Bool) {
        self = .bool(value)
    }

    public init(integerLiteral value: Int64) {
        self = .integer(value)
    }

    public init(floatLiteral value: Double) {
        self = .double(value)
    }

    public init(stringLiteral value: String) {
        self = .string(value)
    }

    public init(arrayLiteral elements: JSONValue...) {
        self = .array(elements)
    }

    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(uniqueKeysWithValues: elements))
    }
}

/// Optional evidence supporting a ``CachedAttestationEnvelope``.
public nonisolated struct CachedAttestationEvidence: Codable, Sendable, Equatable {
    /// The evidence type discriminator.
    public let evidenceType: String

    /// Type-specific evidence data.
    public let data: JSONValue

    /// Memberwise initializer.
    public init(evidenceType: String, data: JSONValue) {
        self.evidenceType = evidenceType
        self.data = data
    }

    private enum CodingKeys: String, CodingKey {
        case evidenceType = "evidence_type"
        case data
    }
}

/// A `std::time::Duration` as the Rust core's serde representation
/// (`{ secs, nanos }`), used for a renewable attestation's renewal interval.
public nonisolated struct CachedAttestationDuration: Codable, Sendable, Equatable {
    /// Whole seconds.
    public let secs: UInt64

    /// Sub-second nanoseconds.
    public let nanos: UInt32

    /// Memberwise initializer.
    public init(secs: UInt64, nanos: UInt32) {
        self.secs = secs
        self.nanos = nanos
    }
}

/// Wire-format attestation envelope (ADR-017 §7.4.1).
///
/// A pass-through DTO whose `CodingKeys` are the serde-canonical snake_case the
/// Rust core deserializes, NOT the camelCase the SDK uses for core-modeled
/// types. Mirrors the Python SDK `CachedAttestationEnvelope` TypedDict and the
/// TypeScript SDK `CachedAttestationEnvelope` interface 1:1.
public nonisolated struct CachedAttestationEnvelope: Codable, Sendable, Equatable {
    /// Unique attestation identifier.
    public let id: String

    /// Attestation type (serde tag, e.g. `"IdentityLink"`).
    public let attestationType: String

    /// DID of the attestation issuer.
    public let issuer: String

    /// DID of the attestation subject.
    public let subject: String

    /// Type-specific claim data.
    public let claim: JSONValue

    /// Optional evidence supporting the attestation.
    public let evidence: CachedAttestationEvidence?

    /// Unix timestamp (seconds) when the attestation was issued.
    public let issuedAt: UInt64

    /// Optional expiry timestamp (seconds).
    public let expiresAt: UInt64?

    /// Optional renewal interval.
    public let renewalInterval: CachedAttestationDuration?

    /// Timestamp (seconds) of the last renewal, if renewable.
    public let renewedAt: UInt64?

    /// Current revocation status (serde-tagged).
    public let revocationStatus: JSONValue

    /// Ed25519 signature over the attestation content (64 bytes).
    public let signature: [UInt8]

    /// Memberwise initializer.
    public init(
        id: String,
        attestationType: String,
        issuer: String,
        subject: String,
        claim: JSONValue,
        issuedAt: UInt64,
        revocationStatus: JSONValue,
        signature: [UInt8],
        evidence: CachedAttestationEvidence? = nil,
        expiresAt: UInt64? = nil,
        renewalInterval: CachedAttestationDuration? = nil,
        renewedAt: UInt64? = nil
    ) {
        self.id = id
        self.attestationType = attestationType
        self.issuer = issuer
        self.subject = subject
        self.claim = claim
        self.evidence = evidence
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.renewalInterval = renewalInterval
        self.renewedAt = renewedAt
        self.revocationStatus = revocationStatus
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case attestationType = "attestation_type"
        case issuer
        case subject
        case claim
        case evidence
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case renewalInterval = "renewal_interval"
        case renewedAt = "renewed_at"
        case revocationStatus = "revocation_status"
        case signature
    }
}

/// A verified attestation with cache TTL metadata (ADR-017).
///
/// Pass an array of these to
/// ``SCP/participationRecord(contextId:subjectDid:cachedAttestations:)`` (or
/// ``SCP/evaluateTrust(handle:subjectDid:capabilityTokens:)``) to seed the
/// bridge's trust store before it sources the subject's verified set. Mirrors
/// the Rust `CachedAttestation`, the Python SDK `CachedAttestation` TypedDict,
/// and the TypeScript SDK `CachedAttestation` interface 1:1.
public nonisolated struct CachedAttestation: Codable, Sendable, Equatable {
    /// The verified attestation envelope.
    public let attestation: CachedAttestationEnvelope

    /// Unix timestamp (seconds) when the attestation was last verified.
    public let verifiedAt: UInt64

    /// Time-to-live in seconds for the cache entry.
    public let ttlSecs: UInt64

    /// Memberwise initializer.
    public init(attestation: CachedAttestationEnvelope, verifiedAt: UInt64, ttlSecs: UInt64) {
        self.attestation = attestation
        self.verifiedAt = verifiedAt
        self.ttlSecs = ttlSecs
    }

    private enum CodingKeys: String, CodingKey {
        case attestation
        case verifiedAt = "verified_at"
        case ttlSecs = "ttl_secs"
    }
}

/// Serializes a cached-attestation list to the serde-canonical JSON the bridge
/// `participation_record` op deserializes. Shared by `participationRecord` and
/// `evaluateTrust` so the projection lives in one place. An empty list encodes
/// to `"[]"` — the bridge then reports only what its trust store already holds
/// (verifier-relative, §7.4).
func encodeCachedAttestations(_ cachedAttestations: [CachedAttestation]) throws -> String {
    let encoder = JSONEncoder()
    let data = try encoder.encode(cachedAttestations)
    guard let json = String(data: data, encoding: .utf8) else {
        throw ScpError.Validation(
            msg: "failed to encode cached attestations as UTF-8 JSON",
            code: "SCP-VALID-7059"
        )
    }
    return json
}

// MARK: - SCP trust-signal wrappers

public extension SCP {
    /// Read-only, structured counterpart to ``SCP/ucanValidate(handle:token:capability:presentingAgentDid:proofTokens:)``.
    ///
    /// Runs the same 11-step ADR-016 validation pipeline but, instead of
    /// throwing at the first failing stage, returns a ``CapabilityValidation``
    /// of six per-stage booleans (spec §7.2.4, ADR-057). The probe never records
    /// the token's nonce, so calling it does not consume the token.
    /// Capability/signature/expiry outcomes are reported via the booleans; only
    /// malformed FFI inputs (bad handle / token / capability) throw.
    ///
    /// NOT AN AUTHORIZATION DECISION: this is a diagnostic, never a gate. Only
    /// ``SCP/ucanValidate(handle:token:capability:presentingAgentDid:proofTokens:)``
    /// (with its mandatory challenge capability) authorizes an action. A
    /// no-capability (intrinsic-validity) result skips the invoked-capability
    /// grant-match, so an all-`true` result does NOT establish the token grants
    /// any particular capability.
    ///
    /// FAIL CLOSED: `presentingAgentDid` is required by the bridge (no silent
    /// security default). Omitting it makes the bridge reject the call rather
    /// than defaulting the presenting agent to the token's own `aud` — which
    /// would make the step-5 audience check the tautology `aud == aud` and
    /// inflate trust. It precedes `capability` because it is mandatory while
    /// `capability` is optional.
    ///
    /// - Parameters:
    ///   - handle: The context handle to evaluate against.
    ///   - token: The UCAN token string to evaluate.
    ///   - presentingAgentDid: The DID under assessment — the agent the token
    ///     must be addressed to. Required.
    ///   - capability: Optional challenge capability URI. Omit it (or pass
    ///     `nil`) to evaluate the token's INTRINSIC validity with no
    ///     invoked-capability grant-match challenge — the mode `evaluateTrust`
    ///     uses. Pass a capability to additionally require the token grants it.
    ///   - proofTokens: Optional delegation-chain proof tokens.
    /// - Returns: The structured ``CapabilityValidation``.
    func ucanEvaluate(
        handle: ContextHandle,
        token: String,
        presentingAgentDid: String,
        capability: String? = nil,
        proofTokens: [String]? = nil
    ) async throws -> CapabilityValidation {
        let record = try await inner.ucanEvaluate(
            handle: handle,
            token: token,
            capability: capability,
            presentingAgentDid: presentingAgentDid,
            proofTokens: proofTokens
        )
        return CapabilityValidation(record: record)
    }

    /// Computes the participation record (§7.3.2) for a subject in a context.
    ///
    /// The shared Rust core gathers the FULL context event log and flattens the
    /// participation facts ONCE (`Supervisor::participation_record`), and the
    /// UniFFI bridge sources the subject's accessible, currently-valid
    /// attestations from its own persistent trust store (seeded by
    /// `cachedAttestations`). The SDK RECEIVES the flattened ``BehavioralRecord``
    /// — it never re-aggregates event-log collections, so every binding observes
    /// identical facts for the same context/subject.
    ///
    /// `attestationCount` is a credential-layer fact (§7.4): NOT a context-event
    /// count, NOT Merkle-anchored, and verifier-relative (computed from the
    /// attestations the bridge can access). Pass the subject's accessible
    /// attestations as `cachedAttestations` to populate it; the default (`[]`)
    /// honestly reports only what the bridge's trust store already holds — it
    /// never fabricates attestations.
    ///
    /// SECURITY: `attestationCount` is authentic-but-self-mintable — an issuer is
    /// self-certifying, so a subject can mint endorsements from DIDs it controls.
    /// It MUST NOT be a sole trust or admission factor; use the
    /// threshold/independence path (§7.3.5) for Sybil resistance.
    ///
    /// - Throws: ``ScpError`` on malformed FFI input or a behavioral compute
    ///   failure. An empty event log surfaces as ``ScpError/Context(msg:code:)``
    ///   carrying ``noParticipationFactsCode`` — callers wanting the empty-log
    ///   case as a zeroed record (rather than an error) should use
    ///   ``SCP/evaluateTrust(handle:subjectDid:capabilityTokens:)``.
    func participationRecord(
        contextId: String,
        subjectDid: String,
        cachedAttestations: [CachedAttestation] = []
    ) throws -> BehavioralRecord {
        let cachedJson = try encodeCachedAttestations(cachedAttestations)
        let view = try inner.participationRecord(
            contextId: contextId,
            subjectDid: subjectDid,
            cachedAttestationsJson: cachedJson
        )
        return BehavioralRecord(record: view)
    }

    /// Evaluate the trustworthiness of a participant within a context
    /// (spec §7.2.4, ADR-057). The protocol provides the data, not the verdict.
    ///
    /// - **Layer 1 — protocol enforcement.** Each supplied capability token is
    ///   run through the read-only ``SCP/ucanEvaluate(handle:token:presentingAgentDid:capability:proofTokens:)``
    ///   diagnostic, yielding six per-stage booleans. The booleans are
    ///   AND-combined across the token set, so one token failing a stage makes
    ///   that aggregate field `false`. This never inspects error prose — it reads
    ///   the structured ``CapabilityValidation`` directly. With no tokens
    ///   supplied, every field stays `false` (no stage was observed to pass).
    ///   The subject is passed as the presenting agent so the audience check
    ///   evaluates against the DID under assessment; no challenge capability is
    ///   supplied (intrinsic-validity mode).
    /// - **Layer 2 — behavioral validation.** RECEIVES the subject's verifiable
    ///   participation facts (§7.3.2) from the shared Rust core via
    ///   ``SCP/participationRecord(contextId:subjectDid:cachedAttestations:)``.
    ///   A context with no convergent events yet (an empty event log) is not an
    ///   error here: the behavioral record is reported with all counts zeroed,
    ///   branching on the STRUCTURED ``noParticipationFactsCode`` — never on
    ///   error prose. Any other error propagates.
    ///
    /// The evaluation is labeled with the context the layers were computed
    /// against — the handle's resolved `contextId()` — so the result is never
    /// silently mislabeled.
    ///
    /// SECURITY: the behavioral record's `attestationCount` (and any challenge
    /// results, where consumed) are authentic-but-self-mintable signals — an
    /// issuer/verifier is self-certifying, so a subject can mint them from DIDs it
    /// controls. They MUST NOT be a sole trust or admission factor; use the
    /// threshold/independence path (§7.3.5) for Sybil resistance.
    ///
    /// - Parameters:
    ///   - handle: The context handle to evaluate within.
    ///   - subjectDid: The DID of the participant being evaluated.
    ///   - capabilityTokens: Optional UCAN token strings to evaluate for Layer 1.
    /// - Returns: A structured ``TrustEvaluation`` with Layers 1 and 2 populated.
    func evaluateTrust(
        handle: ContextHandle,
        subjectDid: String,
        capabilityTokens: [String] = []
    ) async throws -> TrustEvaluation {
        // Layer 1: AND-combine the structured per-stage booleans across tokens.
        let capabilityValidation = try await aggregateCapabilityValidation(
            handle: handle,
            subjectDid: subjectDid,
            tokens: capabilityTokens
        )

        // Label the evaluation with the SAME context the layers were computed
        // against (the handle's canonical id), and key the participation-record
        // lookup off it too.
        let resolvedContextId = handle.contextId()

        // Layer 2: behavioral record RECEIVED from the shared Rust core. An
        // empty event log (SCP-CTX-2076) is folded into a zeroed record —
        // branching on the STRUCTURED code, never error prose. No cached
        // attestations are supplied, so attestationCount reflects only the
        // bridge's own trust store (verifier-relative, §7.4).
        let behavioralRecord: BehavioralRecord
        do {
            behavioralRecord = try participationRecord(
                contextId: resolvedContextId,
                subjectDid: subjectDid
            )
        } catch let ScpError.Context(_, code) where code == noParticipationFactsCode {
            behavioralRecord = BehavioralRecord.zeroed(subjectDid: subjectDid)
        }

        return TrustEvaluation(
            subjectDid: subjectDid,
            contextId: resolvedContextId,
            capabilityValidation: capabilityValidation,
            behavioralRecord: behavioralRecord
        )
    }

    /// Layer 1 of ``evaluateTrust(handle:subjectDid:capabilityTokens:)``:
    /// AND-combines the structured per-stage booleans across the token set. With
    /// no tokens every field stays `false` (no stage was observed to pass); with
    /// at least one token the combination starts from the all-`true` identity
    /// element of the boolean AND. The subject is passed as the presenting agent
    /// (audience check against the DID under assessment) with no challenge
    /// capability (intrinsic-validity mode).
    private func aggregateCapabilityValidation(
        handle: ContextHandle,
        subjectDid: String,
        tokens: [String]
    ) async throws -> CapabilityValidation {
        guard !tokens.isEmpty else {
            return CapabilityValidation(
                tokensValid: false,
                signaturesValid: false,
                withinCeiling: false,
                nonceValid: false,
                notRevoked: false,
                timeBoundsValid: false
            )
        }
        var tokensValid = true
        var signaturesValid = true
        var withinCeiling = true
        var nonceValid = true
        var notRevoked = true
        var timeBoundsValid = true
        for token in tokens {
            let perToken = try await ucanEvaluate(
                handle: handle,
                token: token,
                presentingAgentDid: subjectDid
            )
            tokensValid = tokensValid && perToken.tokensValid
            signaturesValid = signaturesValid && perToken.signaturesValid
            withinCeiling = withinCeiling && perToken.withinCeiling
            nonceValid = nonceValid && perToken.nonceValid
            notRevoked = notRevoked && perToken.notRevoked
            timeBoundsValid = timeBoundsValid && perToken.timeBoundsValid
        }
        return CapabilityValidation(
            tokensValid: tokensValid,
            signaturesValid: signaturesValid,
            withinCeiling: withinCeiling,
            nonceValid: nonceValid,
            notRevoked: notRevoked,
            timeBoundsValid: timeBoundsValid
        )
    }
}

// MARK: - AggregatedTrustInput

/// Aggregated trust input result.
///
/// Contains the JSON-decoded output of the trust aggregation pipeline. Each
/// field corresponds to one of the four trust layers. This is the typed result
/// of ``SCP/aggregateTrust(contextId:subjectDid:events:merkleRoot:consequenceRules:thresholdRequirements:attestorSets:cachedAttestations:challengeResults:)``,
/// the Swift counterpart to the Python SDK `aggregate_trust_input`.
///
/// ## Provenance
///
/// - ADR-017 acceptance criterion 9
/// - Spec section 7.3
public nonisolated struct AggregatedTrustInput {
    /// Verified attestations (Layer 3), as raw JSON-decoded objects.
    public let verifiedAttestations: [[String: Any]]

    /// Participation record (Layer 2), as a raw JSON-decoded object.
    public let participationRecord: [String: Any]

    /// Challenge-response results (Layer 3), as raw JSON-decoded objects.
    public let challengeResults: [[String: Any]]

    /// Consequence rules (Layer 4), as raw JSON-decoded objects.
    public let consequenceStructure: [[String: Any]]

    /// Threshold counts per attestation type: [met, required].
    public let thresholdCounts: [String: [Int]]
}

public extension SCP {
    /// Aggregates all trust engine layers into a single input for agent-level
    /// evaluation (§7.3).
    ///
    /// Every structured input is typed; the SDK serializes to the serde wire
    /// shapes internally (ADR-058) and routes through
    /// ``SCP/aggregateTrustInput(contextId:subjectDid:eventsJson:merkleRootJson:consequenceRulesJson:thresholdRequirementsJson:attestorSetsJson:cachedAttestationsJson:challengeResultsJson:)``
    /// unchanged, then parses the JSON result into a typed
    /// ``AggregatedTrustInput``. An empty collection is a real value ("no
    /// rules apply"), never a request for defaults — the bridge receives
    /// `[]` / `{}` exactly as passed.
    ///
    /// - Parameters:
    ///   - contextId: The context to aggregate trust inputs for.
    ///   - subjectDid: The DID of the subject to evaluate.
    ///   - events: Full signed event-log entries (``EventLogEntry``).
    ///   - merkleRoot: 32-byte Merkle root.
    ///   - consequenceRules: Typed ``ConsequenceRule`` values.
    ///   - thresholdRequirements: Typed ``ThresholdRequirement`` values keyed
    ///     by ``AttestationType``.
    ///   - attestorSets: Typed ``AttestorInfo`` lists keyed by
    ///     ``AttestationType``.
    ///   - cachedAttestations: Typed ``CachedAttestation`` values to seed the
    ///     bridge's trust store.
    ///   - challengeResults: Typed ``ChallengeVerification`` records.
    /// - Throws: ``ScpError`` on a wrong-length byte array (before any bridge
    ///   call), a serialization failure, or a bridge aggregation failure.
    func aggregateTrust(
        contextId: String,
        subjectDid: String,
        events: [EventLogEntry],
        merkleRoot: [UInt8],
        consequenceRules: [ConsequenceRule] = [],
        thresholdRequirements: [AttestationType: ThresholdRequirement] = [:],
        attestorSets: [AttestationType: [AttestorInfo]] = [:],
        cachedAttestations: [CachedAttestation] = [],
        challengeResults: [ChallengeVerification] = []
    ) throws -> AggregatedTrustInput {
        let resultJson = try aggregateTrustInput(
            contextId: contextId,
            subjectDid: subjectDid,
            eventsJson: encodeEventLogEntriesJson(events),
            merkleRootJson: encodeMerkleRootJson(merkleRoot),
            consequenceRulesJson: encodeConsequenceRulesJson(consequenceRules),
            thresholdRequirementsJson: encodeThresholdRequirementsJson(thresholdRequirements),
            attestorSetsJson: encodeAttestorSetsJson(attestorSets),
            cachedAttestationsJson: encodeCachedAttestations(cachedAttestations),
            challengeResultsJson: encodeChallengeVerificationsJson(challengeResults)
        )

        guard let data = resultJson.data(using: .utf8),
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ScpError.Validation(
                msg: "failed to parse aggregation result JSON",
                code: "SCP-VALID-7060"
            )
        }

        return AggregatedTrustInput(
            verifiedAttestations: json["verified_attestations"] as? [[String: Any]] ?? [],
            participationRecord: json["participation_record"] as? [String: Any] ?? [:],
            challengeResults: json["challenge_results"] as? [[String: Any]] ?? [],
            consequenceStructure: json["consequence_structure"] as? [[String: Any]] ?? [],
            thresholdCounts: json["threshold_counts"] as? [String: [Int]] ?? [:]
        )
    }
}

// MARK: - Participation admission types (§7.3.2.1, SCP-BA-004, ADR-058)

/// Which category of participation fact to evaluate for admission.
///
/// Each variant corresponds to one of the 7 fact categories in a
/// ``ParticipationProfile``. Encodes to the bare PascalCase variant name string
/// (`"ParticipationDuration"`, …) to match the Rust `ParticipationFact` enum's
/// default (externally-tagged) serde representation. Mirrors the TypeScript SDK
/// `ParticipationFact` union and the Python SDK enum 1:1.
///
/// See §7.3.2.1.
public nonisolated enum ParticipationFact: String, Codable, Sendable, Equatable, CaseIterable {
    /// Total seconds of context participation.
    case participationDuration = "ParticipationDuration"
    /// Count of governance actions taken against the identity.
    case governanceActionsAgainst = "GovernanceActionsAgainst"
    /// Count of governance actions initiated by the identity.
    case governanceActionsBy = "GovernanceActionsBy"
    /// Total tool invocations across all tool types.
    case toolInvocationCount = "ToolInvocationCount"
    /// Number of contexts created.
    case contextCreationCount = "ContextCreationCount"
    /// Number of role transitions.
    case roleProgressionCount = "RoleProgressionCount"
    /// Number of attestation events.
    case attestationCount = "AttestationCount"
}

/// Comparison operator and value for participation admission thresholds.
///
/// Used in ``RequireParticipation`` to specify the comparison a fact value must
/// satisfy. Serializes as the externally-tagged single-key object the Rust
/// `ParticipationThreshold` enum produces — `{"GreaterThan": 50}`,
/// `{"AtLeast": 100}`, etc. Mirrors the TypeScript SDK `ParticipationThreshold`
/// union 1:1.
///
/// See §7.3.2.1.
public nonisolated enum ParticipationThreshold: Codable, Sendable, Equatable {
    /// Fact value must be strictly greater than the associated value.
    case greaterThan(UInt64)
    /// Fact value must be strictly less than the associated value.
    case lessThan(UInt64)
    /// Fact value must be greater than or equal to the associated value.
    case atLeast(UInt64)
    /// Fact value must be less than or equal to the associated value.
    case atMost(UInt64)
    /// Fact value must equal the associated value exactly.
    case equals(UInt64)

    private enum CodingKeys: String, CodingKey {
        case greaterThan = "GreaterThan"
        case lessThan = "LessThan"
        case atLeast = "AtLeast"
        case atMost = "AtMost"
        case equals = "Equals"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .greaterThan(value):
            try container.encode(value, forKey: .greaterThan)
        case let .lessThan(value):
            try container.encode(value, forKey: .lessThan)
        case let .atLeast(value):
            try container.encode(value, forKey: .atLeast)
        case let .atMost(value):
            try container.encode(value, forKey: .atMost)
        case let .equals(value):
            try container.encode(value, forKey: .equals)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let value = try container.decodeIfPresent(UInt64.self, forKey: .greaterThan) {
            self = .greaterThan(value)
        } else if let value = try container.decodeIfPresent(UInt64.self, forKey: .lessThan) {
            self = .lessThan(value)
        } else if let value = try container.decodeIfPresent(UInt64.self, forKey: .atLeast) {
            self = .atLeast(value)
        } else if let value = try container.decodeIfPresent(UInt64.self, forKey: .atMost) {
            self = .atMost(value)
        } else if let value = try container.decodeIfPresent(UInt64.self, forKey: .equals) {
            self = .equals(value)
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: .greaterThan,
                in: container,
                debugDescription: "no known ParticipationThreshold operator key"
            )
        }
    }
}

/// A participation admission requirement declared by a context.
///
/// Each entry specifies a participation fact, a threshold, a freshness
/// requirement, and a minimum number of independent source contexts. The
/// `CodingKeys` are the serde-canonical snake_case the Rust core deserializes
/// (`Vec<RequireParticipation>`). Mirrors the TypeScript SDK
/// `RequireParticipation` interface and the Rust `RequireParticipation` struct
/// 1:1.
///
/// See §7.3.2.1.
public nonisolated struct RequireParticipation: Codable, Sendable, Equatable {
    /// Which participation category to evaluate.
    public let fact: ParticipationFact
    /// Comparison operator and value.
    public let threshold: ParticipationThreshold
    /// Maximum age in seconds for the profile's `updatedAt` timestamp. Profiles
    /// older than this are rejected.
    public let maxAgeSecs: UInt64
    /// Minimum number of independent source contexts (distinct
    /// `signerPublicKey` values) required to satisfy this requirement.
    public let minContexts: UInt32

    /// Memberwise initializer.
    public init(
        fact: ParticipationFact,
        threshold: ParticipationThreshold,
        maxAgeSecs: UInt64,
        minContexts: UInt32
    ) {
        self.fact = fact
        self.threshold = threshold
        self.maxAgeSecs = maxAgeSecs
        self.minContexts = minContexts
    }

    private enum CodingKeys: String, CodingKey {
        case fact
        case threshold
        case maxAgeSecs = "max_age_secs"
        case minContexts = "min_contexts"
    }
}

/// A context-hosted participation profile attesting to a member's verifiable
/// participation facts.
///
/// Produced by contexts for opted-in members and signed by a context-specific
/// Ed25519 key (derived with domain separation) so verifiers cannot correlate
/// which contexts share a signer. The `CodingKeys` are the serde-canonical
/// snake_case the Rust core deserializes (`Vec<ParticipationProfile>`); the
/// three byte-array fields (`eventLogRoot`/`signerPublicKey`, 32 bytes each;
/// `signature`, 64 bytes) serialize as JSON number arrays, matching the Rust
/// `[u8; N]`/`serde_bytes` representation. Mirrors the TypeScript SDK
/// `ParticipationProfile` interface and the Rust struct 1:1.
///
/// See §7.3.2.1.
public nonisolated struct ParticipationProfile: Codable, Sendable, Equatable {
    /// DID of the member this profile is about.
    public let subjectDid: String
    /// Total seconds of context participation.
    public let participationDurationSecs: UInt64
    /// Count of governance actions taken against this identity.
    public let governanceActionsAgainst: UInt64
    /// Count of governance actions initiated by this identity.
    public let governanceActionsBy: UInt64
    /// Total tool invocations across all tool types.
    public let toolInvocationCount: UInt64
    /// Whether ``toolInvocationCount`` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `ToolInvoked` a convergent leaf — consumers
    /// MUST NOT treat the count as Merkle-proven while this is `false`. The flag
    /// is part of the signed preimage, so it cannot be stripped from a signed
    /// profile.
    public let toolInvocationCountAnchored: Bool
    /// Number of contexts created.
    public let contextCreationCount: UInt64
    /// Number of role transitions.
    public let roleProgressionCount: UInt64
    /// Number of attestation events.
    public let attestationCount: UInt64
    /// Unix timestamp (seconds) of the last update to this profile.
    public let updatedAt: UInt64
    /// Merkle root of the context's event log at profile computation time
    /// (32 bytes).
    public let eventLogRoot: [UInt8]
    /// Context-specific Ed25519 public key used to sign this profile (32 bytes).
    public let signerPublicKey: [UInt8]
    /// Ed25519 signature over all fields except this one (64 bytes).
    public let signature: [UInt8]

    /// Memberwise initializer.
    public init(
        subjectDid: String,
        participationDurationSecs: UInt64,
        governanceActionsAgainst: UInt64,
        governanceActionsBy: UInt64,
        toolInvocationCount: UInt64,
        toolInvocationCountAnchored: Bool,
        contextCreationCount: UInt64,
        roleProgressionCount: UInt64,
        attestationCount: UInt64,
        updatedAt: UInt64,
        eventLogRoot: [UInt8],
        signerPublicKey: [UInt8],
        signature: [UInt8]
    ) {
        self.subjectDid = subjectDid
        self.participationDurationSecs = participationDurationSecs
        self.governanceActionsAgainst = governanceActionsAgainst
        self.governanceActionsBy = governanceActionsBy
        self.toolInvocationCount = toolInvocationCount
        self.toolInvocationCountAnchored = toolInvocationCountAnchored
        self.contextCreationCount = contextCreationCount
        self.roleProgressionCount = roleProgressionCount
        self.attestationCount = attestationCount
        self.updatedAt = updatedAt
        self.eventLogRoot = eventLogRoot
        self.signerPublicKey = signerPublicKey
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case subjectDid = "subject_did"
        case participationDurationSecs = "participation_duration_secs"
        case governanceActionsAgainst = "governance_actions_against"
        case governanceActionsBy = "governance_actions_by"
        case toolInvocationCount = "tool_invocation_count"
        case toolInvocationCountAnchored = "tool_invocation_count_anchored"
        case contextCreationCount = "context_creation_count"
        case roleProgressionCount = "role_progression_count"
        case attestationCount = "attestation_count"
        case updatedAt = "updated_at"
        case eventLogRoot = "event_log_root"
        case signerPublicKey = "signer_public_key"
        case signature
    }
}

// MARK: - Capability admission types (§7.3.4.4, SCP-ACR-008, ADR-058)

/// How a capability must be verified for admission.
///
/// Encodes to the bare variant name string (`"SelfAttested"` /
/// `"ChallengeVerified"`) to match the Rust `VerificationLevel` enum's default
/// serde representation. `ChallengeVerified` also satisfies `SelfAttested`.
/// Mirrors the TypeScript SDK `VerificationLevel` union 1:1.
public nonisolated enum VerificationLevel: String, Codable, Sendable, Equatable {
    /// The agent claims the capability (present in its capability list); no
    /// challenge proof required.
    case selfAttested = "SelfAttested"
    /// The capability was verified through the challenge-response protocol.
    case challengeVerified = "ChallengeVerified"
}

/// A single admission requirement: a capability URI and the minimum
/// verification level needed.
///
/// The `CodingKeys` are the serde-canonical snake_case the Rust core
/// deserializes (`Vec<CapabilityRequirement>`). Mirrors the TypeScript SDK
/// `CapabilityRequirement` interface and the Rust struct 1:1.
///
/// See §7.3.4.4.
public nonisolated struct CapabilityRequirement: Codable, Sendable, Equatable {
    /// The capability URI that must be present.
    public let capability: String
    /// The minimum verification level required.
    public let verificationLevel: VerificationLevel

    /// Memberwise initializer.
    public init(capability: String, verificationLevel: VerificationLevel) {
        self.capability = capability
        self.verificationLevel = verificationLevel
    }

    private enum CodingKeys: String, CodingKey {
        case capability
        case verificationLevel = "verification_level"
    }
}

/// How a capability was verified, as recorded in a ``ChallengeVerification``.
///
/// Serializes as the bare string `"SelfAttested"` or the externally-tagged
/// `{"ChallengeVerified": {"challenge_type": <uri>}}`, matching the Rust
/// `VerificationMethod` enum. The inner `challenge_type` is a bare capability
/// URI string (the Rust `ChallengeType` serializes as its URI string).
///
/// SECURITY: `verificationMethod` is NOT covered by the verifier signature
/// (ADR-017 caveat) — consumers MUST NOT key trust decisions on it.
public nonisolated enum ChallengeVerificationMethod: Codable, Sendable, Equatable {
    /// Self-attested — no challenge proof.
    case selfAttested
    /// Challenge-verified, carrying the challenge type (a capability URI).
    case challengeVerified(challengeType: String)

    private enum CodingKeys: String, CodingKey {
        case challengeVerified = "ChallengeVerified"
    }

    private enum ChallengeVerifiedKeys: String, CodingKey {
        case challengeType = "challenge_type"
    }

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .selfAttested:
            var container = encoder.singleValueContainer()
            try container.encode("SelfAttested")
        case let .challengeVerified(challengeType):
            var container = encoder.container(keyedBy: CodingKeys.self)
            var nested = container.nestedContainer(
                keyedBy: ChallengeVerifiedKeys.self,
                forKey: .challengeVerified
            )
            try nested.encode(challengeType, forKey: .challengeType)
        }
    }

    public init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let tag = try? single.decode(String.self) {
            guard tag == "SelfAttested" else {
                throw DecodingError.dataCorruptedError(
                    in: single,
                    debugDescription: "unknown VerificationMethod string: \(tag)"
                )
            }
            self = .selfAttested
            return
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let nested = try container.nestedContainer(
            keyedBy: ChallengeVerifiedKeys.self,
            forKey: .challengeVerified
        )
        self = try .challengeVerified(challengeType: nested.decode(String.self, forKey: .challengeType))
    }
}

/// A signed record that a specific verifier tested a capability and the agent
/// passed (spec §7.3.4.2, ADR-017).
///
/// Pass a list of these to
/// ``checkCapabilityRequirements(contextId:subjectDid:requirements:agentCapabilities:challengeVerifications:)``
/// to satisfy `ChallengeVerified` requirements. The `CodingKeys` are the
/// serde-canonical snake_case the Rust core deserializes
/// (`Vec<ChallengeVerification>`); `verifierSignature` is a 64-byte JSON number
/// array. Mirrors the TypeScript SDK `ChallengeVerification` interface and the
/// Rust struct 1:1.
///
/// SECURITY (ADR-017 caveat): only the *signed* fields bind trust —
/// `verificationId`, `verifierDid`, `subjectDid`, `capabilityUri`,
/// `challengeType`, `passed`, `score`, `testCount`, `passCount`, `verifiedAt`,
/// `expiresAt`, `contextId`. The `result`, `completedAt`, and
/// `verificationMethod` fields are NOT signed and can be altered after minting
/// without invalidating the signature. Consumers MUST NOT key trust decisions
/// on those unsigned fields.
public nonisolated struct ChallengeVerification: Codable, Sendable, Equatable {
    /// Unique verification identifier (derived from the challenge ID).
    public let verificationId: String
    /// DID of the verifier who issued and verified the challenge.
    public let verifierDid: String
    /// DID of the subject who answered the challenge.
    public let subjectDid: String
    /// The capability URI that was verified.
    public let capabilityUri: String
    /// The type of challenge that was verified (a capability URI string).
    public let challengeType: String
    /// How the capability was verified (unsigned metadata).
    public let verificationMethod: ChallengeVerificationMethod
    /// Whether the subject passed the challenge overall.
    public let passed: Bool
    /// Optional numeric score (0–100) for graded challenges.
    public let score: UInt32?
    /// Total number of test cases in the challenge.
    public let testCount: UInt32
    /// Number of test cases the subject passed.
    public let passCount: UInt32
    /// The challenge-specific result from the response (arbitrary JSON,
    /// unsigned).
    public let result: JSONValue
    /// Unix timestamp (seconds) when the response was completed (unsigned).
    public let completedAt: UInt64
    /// Unix timestamp (seconds) when the verification was performed.
    public let verifiedAt: UInt64
    /// Unix timestamp (seconds) when this verification expires.
    public let expiresAt: UInt64
    /// Context in which the challenge was issued, if any.
    public let contextId: String?
    /// Ed25519 signature by the verifier over the verification record
    /// (64 bytes).
    public let verifierSignature: [UInt8]

    /// Memberwise initializer.
    public init(
        verificationId: String,
        verifierDid: String,
        subjectDid: String,
        capabilityUri: String,
        challengeType: String,
        verificationMethod: ChallengeVerificationMethod,
        passed: Bool,
        testCount: UInt32,
        passCount: UInt32,
        result: JSONValue,
        completedAt: UInt64,
        verifiedAt: UInt64,
        expiresAt: UInt64,
        verifierSignature: [UInt8],
        score: UInt32? = nil,
        contextId: String? = nil
    ) {
        self.verificationId = verificationId
        self.verifierDid = verifierDid
        self.subjectDid = subjectDid
        self.capabilityUri = capabilityUri
        self.challengeType = challengeType
        self.verificationMethod = verificationMethod
        self.passed = passed
        self.score = score
        self.testCount = testCount
        self.passCount = passCount
        self.result = result
        self.completedAt = completedAt
        self.verifiedAt = verifiedAt
        self.expiresAt = expiresAt
        self.contextId = contextId
        self.verifierSignature = verifierSignature
    }

    private enum CodingKeys: String, CodingKey {
        case verificationId = "verification_id"
        case verifierDid = "verifier_did"
        case subjectDid = "subject_did"
        case capabilityUri = "capability_uri"
        case challengeType = "challenge_type"
        case verificationMethod = "verification_method"
        case passed
        case score
        case testCount = "test_count"
        case passCount = "pass_count"
        case result
        case completedAt = "completed_at"
        case verifiedAt = "verified_at"
        case expiresAt = "expires_at"
        case contextId = "context_id"
        case verifierSignature = "verifier_signature"
    }

    /// Custom encoder so the optional `score` / `contextId` fields serialize as
    /// explicit JSON `null` when absent (matching `serde_json::to_string` of the
    /// Rust `Option<T>` fields and the TypeScript SDK encoder), rather than
    /// being omitted as Swift's synthesized `encodeIfPresent` would do. The Rust
    /// deserializer accepts either shape, but explicit `null` keeps the wire
    /// form byte-identical across bindings.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(verificationId, forKey: .verificationId)
        try container.encode(verifierDid, forKey: .verifierDid)
        try container.encode(subjectDid, forKey: .subjectDid)
        try container.encode(capabilityUri, forKey: .capabilityUri)
        try container.encode(challengeType, forKey: .challengeType)
        try container.encode(verificationMethod, forKey: .verificationMethod)
        try container.encode(passed, forKey: .passed)
        try container.encode(score, forKey: .score)
        try container.encode(testCount, forKey: .testCount)
        try container.encode(passCount, forKey: .passCount)
        try container.encode(result, forKey: .result)
        try container.encode(completedAt, forKey: .completedAt)
        try container.encode(verifiedAt, forKey: .verifiedAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(contextId, forKey: .contextId)
        try container.encode(verifierSignature, forKey: .verifierSignature)
    }
}

// MARK: - Trust admission JSON encoders

/// Shared JSON encoding for the trust-admission wire inputs. Uses
/// `.sortedKeys` for deterministic output (matching the ``ConsequenceRule``
/// encoder precedent); the Rust serde deserializers are key-order-independent,
/// so alphabetical ordering is wire-compatible.
private func encodeTrustAdmissionJson(_ value: some Encodable) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    guard let json = String(data: data, encoding: .utf8) else {
        throw ScpError.Validation(
            msg: "failed to encode trust admission input as UTF-8 JSON",
            code: "SCP-VALID-7061"
        )
    }
    return json
}

/// Encodes a typed ``RequireParticipation`` array to the JSON wire shape the
/// bridge deserializes (`Vec<RequireParticipation>`). `fact` is a bare variant
/// string and `threshold` is the serde-canonical `{"<Op>": value}` shape.
public func encodeRequireParticipationJson(_ requirements: [RequireParticipation]) throws -> String {
    try encodeTrustAdmissionJson(requirements)
}

/// Throws ``ScpError/Validation(msg:code:)`` when a fixed-length byte-array
/// field has the wrong number of elements, so a malformed profile/verification
/// fails at encode time with a field-named error instead of surfacing as a
/// Rust `[u8; N]` deserialization error after the bridge call. Mirrors the
/// Python SDK's construction-time checks (ADR-058 misuse resistance).
private func requireByteLength(
    _ typeName: String,
    _ fieldName: String,
    expected: Int,
    actual: [UInt8],
    code: String
) throws {
    guard actual.count == expected else {
        throw ScpError.Validation(
            msg: "\(typeName).\(fieldName) must be exactly \(expected) elements, got \(actual.count)",
            code: code
        )
    }
}

/// Encodes a typed ``ParticipationProfile`` array to the JSON wire shape the
/// bridge deserializes (`Vec<ParticipationProfile>`). Byte-array fields pass
/// through as JSON number arrays.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `eventLogRoot` /
///   `signerPublicKey` are not exactly 32 elements or `signature` is not
///   exactly 64 elements (before any bridge call).
public func encodeParticipationProfileJson(_ profiles: [ParticipationProfile]) throws -> String {
    for profile in profiles {
        try requireByteLength(
            "ParticipationProfile", "eventLogRoot",
            expected: 32, actual: profile.eventLogRoot, code: "SCP-VALID-7062"
        )
        try requireByteLength(
            "ParticipationProfile", "signerPublicKey",
            expected: 32, actual: profile.signerPublicKey, code: "SCP-VALID-7062"
        )
        try requireByteLength(
            "ParticipationProfile", "signature",
            expected: 64, actual: profile.signature, code: "SCP-VALID-7062"
        )
    }
    return try encodeTrustAdmissionJson(profiles)
}

/// Encodes a typed ``CapabilityRequirement`` array to the JSON wire shape the
/// bridge deserializes (`Vec<CapabilityRequirement>`). `verificationLevel`
/// serializes as the bare variant string.
public func encodeCapabilityRequirementsJson(_ requirements: [CapabilityRequirement]) throws -> String {
    try encodeTrustAdmissionJson(requirements)
}

/// Encodes a typed ``ChallengeVerification`` array to the JSON wire shape the
/// bridge deserializes (`Vec<ChallengeVerification>`). The `verificationMethod`
/// discriminated union is encoded to its serde-tagged shape; `verifierSignature`
/// passes through as a number array; `score` / `contextId` serialize as explicit
/// `null` when absent.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `verifierSignature` is not
///   exactly 64 elements (before any bridge call).
public func encodeChallengeVerificationsJson(_ verifications: [ChallengeVerification]) throws -> String {
    for verification in verifications {
        try requireByteLength(
            "ChallengeVerification", "verifierSignature",
            expected: 64, actual: verification.verifierSignature, code: "SCP-VALID-7063"
        )
    }
    return try encodeTrustAdmissionJson(verifications)
}

/// Encodes the agent's self-attested capability URIs to the JSON wire shape the
/// bridge deserializes (`Vec<CapabilityUri>`). Each `CapabilityUri` serializes
/// as its plain URI string, so a `[String]` maps directly onto the wire array.
public func encodeAgentCapabilitiesJson(_ capabilities: [String]) throws -> String {
    try encodeTrustAdmissionJson(capabilities)
}

// MARK: - Trust aggregation input types (§7.3, ADR-058)

/// Attestation type (ADR-017).
///
/// Mirrors the Rust `AttestationType` enum (`scp-core`) — the 8 unit variants
/// serialize as bare PascalCase strings, both as values and as the
/// `thresholdRequirements` / `attestorSets` map keys. Mirrors the TypeScript
/// SDK `AttestationType` union and the Kotlin SDK `AttestationType` enum 1:1.
public nonisolated enum AttestationType: String, Codable, Sendable, Equatable, CaseIterable {
    /// Links an identity to an external identifier.
    case identityLink = "IdentityLink"
    /// Delegates a capability to another DID.
    case capabilityDelegation = "CapabilityDelegation"
    /// Attests to the integrity of a tool.
    case toolIntegrity = "ToolIntegrity"
    /// Attests to an agent's capability.
    case agentCapability = "AgentCapability"
    /// A general endorsement.
    case endorsement = "Endorsement"
    /// Assigns a role to a DID.
    case roleAssignment = "RoleAssignment"
    /// Endorses a context.
    case contextEndorsement = "ContextEndorsement"
    /// Witnesses participation facts.
    case participationWitness = "ParticipationWitness"
}

/// Type-specific data carried by an ``EventLogEntry``.
///
/// Mirrors the Rust `EventPayload` (`scp-event-log`): opaque payload bytes as
/// a JSON number array. An empty `data` array is the canonical representation
/// for non-parameterized events.
public nonisolated struct EventLogEntryPayload: Codable, Sendable, Equatable {
    /// Opaque payload bytes. Interpretation depends on the event type.
    public let data: [UInt8]

    /// Memberwise initializer.
    public init(data: [UInt8]) {
        self.data = data
    }
}

/// A full signed protocol event in a context event log (ADR-011).
///
/// Mirrors the Rust `Event` (`scp-event-log`) serde wire shape the bridge
/// deserializes for
/// ``SCP/aggregateTrust(contextId:subjectDid:events:merkleRoot:consequenceRules:thresholdRequirements:attestorSets:cachedAttestations:challengeResults:)``
/// (`Vec<Event>`) — the INPUT wire form, distinct from the projected event the
/// event-log query surface returns (which omits the hash-chain and signature
/// fields). The `CodingKeys` are the serde-canonical snake_case. Mirrors the
/// TypeScript SDK `EventLogEntry` interface and the Kotlin/Python models 1:1.
public nonisolated struct EventLogEntry: Codable, Sendable, Equatable {
    /// Event type — a Rust `EventType` variant name (e.g. `"MessageSent"`).
    public let eventType: String
    /// DID of the actor who produced this event.
    public let actorDid: String
    /// Unix timestamp (seconds) when the event was created.
    public let timestamp: UInt64
    /// Monotonic event sequence number within the log (0-indexed).
    public let sequence: UInt64
    /// Type-specific event data.
    public let payload: EventLogEntryPayload
    /// SHA-256 hash of the previous event (hash chain), exactly 32 bytes.
    /// `[UInt8](repeating: 0, count: 32)` for the first event (genesis
    /// sentinel).
    public let prevHash: [UInt8]
    /// Ed25519 signature over the serialized event content (64 bytes).
    public let signature: [UInt8]

    /// Memberwise initializer.
    public init(
        eventType: String,
        actorDid: String,
        timestamp: UInt64,
        sequence: UInt64,
        payload: EventLogEntryPayload,
        prevHash: [UInt8],
        signature: [UInt8]
    ) {
        self.eventType = eventType
        self.actorDid = actorDid
        self.timestamp = timestamp
        self.sequence = sequence
        self.payload = payload
        self.prevHash = prevHash
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case eventType = "event_type"
        case actorDid = "actor_did"
        case timestamp
        case sequence
        case payload
        case prevHash = "prev_hash"
        case signature
    }
}

/// N-of-M threshold requirement for attestation verification (ADR-017
/// §7.3.5).
///
/// Mirrors the Rust `ThresholdRequirement` struct (`scp-core`). The three
/// penalty parameters default to the Rust serde defaults (0.1 / 0.5 / 0.2)
/// and are always emitted explicitly, so the wire form is identical across
/// bindings. The `CodingKeys` are the serde-canonical snake_case.
public nonisolated struct ThresholdRequirement: Codable, Sendable, Equatable {
    /// The minimum number of valid attestations required (N).
    public let requiredCount: UInt32
    /// The total number of attestors in the set (M). Must be >= `requiredCount`.
    public let totalAttestors: UInt32
    /// Minimum independence score, in [0.0, 1.0].
    public let independenceThreshold: Double
    /// Independence penalty per shared context membership. Default: 0.1.
    public let sharedContextPenalty: Double
    /// Maximum total shared-context penalty for a single pair. Default: 0.5.
    public let sharedContextPenaltyCap: Double
    /// Independence penalty per mutual endorsement direction. Default: 0.2.
    public let mutualEndorsementPenalty: Double

    /// Memberwise initializer. The penalty parameters default to the Rust
    /// serde defaults.
    public init(
        requiredCount: UInt32,
        totalAttestors: UInt32,
        independenceThreshold: Double,
        sharedContextPenalty: Double = 0.1,
        sharedContextPenaltyCap: Double = 0.5,
        mutualEndorsementPenalty: Double = 0.2
    ) {
        self.requiredCount = requiredCount
        self.totalAttestors = totalAttestors
        self.independenceThreshold = independenceThreshold
        self.sharedContextPenalty = sharedContextPenalty
        self.sharedContextPenaltyCap = sharedContextPenaltyCap
        self.mutualEndorsementPenalty = mutualEndorsementPenalty
    }

    private enum CodingKeys: String, CodingKey {
        case requiredCount = "required_count"
        case totalAttestors = "total_attestors"
        case independenceThreshold = "independence_threshold"
        case sharedContextPenalty = "shared_context_penalty"
        case sharedContextPenaltyCap = "shared_context_penalty_cap"
        case mutualEndorsementPenalty = "mutual_endorsement_penalty"
    }
}

/// Information about an attestor used for independence scoring (ADR-017
/// §7.3.5).
///
/// Mirrors the Rust `AttestorInfo` struct (`scp-core`). The optional
/// `attestation` is a full attestation envelope
/// (``CachedAttestationEnvelope``); only attestations matching the required
/// type are considered. The `CodingKeys` are the serde-canonical snake_case;
/// an absent `attestation` encodes as explicit JSON `null` (matching
/// `serde_json::to_string` of the Rust `Option<Attestation>` and the
/// TypeScript SDK encoder).
public nonisolated struct AttestorInfo: Codable, Sendable, Equatable {
    /// The DID of the attestor.
    public let did: String
    /// Context IDs the attestor is a member of.
    public let contextMemberships: [String]
    /// DIDs this attestor has endorsed (mutual endorsements reduce
    /// independence).
    public let endorsements: [String]
    /// The attestation provided by this attestor, if any.
    public let attestation: CachedAttestationEnvelope?

    /// Memberwise initializer.
    public init(
        did: String,
        contextMemberships: [String],
        endorsements: [String],
        attestation: CachedAttestationEnvelope? = nil
    ) {
        self.did = did
        self.contextMemberships = contextMemberships
        self.endorsements = endorsements
        self.attestation = attestation
    }

    private enum CodingKeys: String, CodingKey {
        case did
        case contextMemberships = "context_memberships"
        case endorsements
        case attestation
    }

    /// Custom encoder so an absent `attestation` serializes as explicit JSON
    /// `null` rather than being omitted (Swift's synthesized `encodeIfPresent`
    /// behavior). The Rust deserializer accepts either shape, but explicit
    /// `null` keeps the wire form identical across bindings.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(did, forKey: .did)
        try container.encode(contextMemberships, forKey: .contextMemberships)
        try container.encode(endorsements, forKey: .endorsements)
        try container.encode(attestation, forKey: .attestation)
    }
}

/// Encodes a typed ``EventLogEntry`` array to the JSON wire shape the bridge
/// deserializes (`Vec<scp_event_log::Event>`). Byte-array fields pass through
/// as JSON number arrays.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `prevHash` is not exactly
///   32 elements or `signature` is not exactly 64 elements (before any bridge
///   call).
public func encodeEventLogEntriesJson(_ events: [EventLogEntry]) throws -> String {
    for event in events {
        try requireByteLength(
            "EventLogEntry", "prevHash",
            expected: 32, actual: event.prevHash, code: "SCP-VALID-7064"
        )
        try requireByteLength(
            "EventLogEntry", "signature",
            expected: 64, actual: event.signature, code: "SCP-VALID-7064"
        )
    }
    return try encodeTrustAdmissionJson(events)
}

/// Encodes a 32-byte Merkle root to the JSON wire shape the bridge
/// deserializes (`[u8; 32]` as a number array).
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `merkleRoot` is not exactly
///   32 elements (before any bridge call).
public func encodeMerkleRootJson(_ merkleRoot: [UInt8]) throws -> String {
    try requireByteLength(
        "AggregatedTrustInput", "merkleRoot",
        expected: 32, actual: merkleRoot, code: "SCP-VALID-7064"
    )
    return try encodeTrustAdmissionJson(merkleRoot)
}

/// Encodes a typed per-``AttestationType`` ``ThresholdRequirement`` map to
/// the JSON wire shape the bridge deserializes
/// (`HashMap<AttestationType, ThresholdRequirement>`). Map keys are the bare
/// variant strings.
public func encodeThresholdRequirementsJson(
    _ requirements: [AttestationType: ThresholdRequirement]
) throws -> String {
    try encodeTrustAdmissionJson(
        Dictionary(uniqueKeysWithValues: requirements.map { ($0.key.rawValue, $0.value) })
    )
}

/// Encodes a typed per-``AttestationType`` ``AttestorInfo`` map to the JSON
/// wire shape the bridge deserializes
/// (`HashMap<AttestationType, Vec<AttestorInfo>>`). Map keys are the bare
/// variant strings; an absent nested `attestation` encodes as explicit
/// `null`.
public func encodeAttestorSetsJson(
    _ attestorSets: [AttestationType: [AttestorInfo]]
) throws -> String {
    try encodeTrustAdmissionJson(
        Dictionary(uniqueKeysWithValues: attestorSets.map { ($0.key.rawValue, $0.value) })
    )
}

// MARK: - Typed trust-admission wrappers (ADR-058)

/// Verify participation profiles against admission requirements (§7.3.2.1).
///
/// Typed counterpart to the generated
/// ``verifyParticipationRequirements(expectedSubject:requirementsJson:profileJson:)``
/// free function: it serializes the typed ``RequireParticipation`` /
/// ``ParticipationProfile`` values to the serde wire shape (ADR-058) and calls
/// the bridge unchanged. Returns normally when all requirements are satisfied;
/// throws on any failed requirement or malformed input.
///
/// Security caveat — authenticity is not authorization: this verifies signatures
/// over the subject binding, not signer *legitimacy*. Because `signerPublicKey`
/// is self-certifying, a subject can present genuinely-signed profiles from
/// signers it controls (inflating `minContexts`). Establish signer legitimacy
/// separately (a trusted-signer set, a context-membership proof, or the §7.3.5
/// threshold/independence path); do NOT treat success as an authorization
/// decision.
///
/// - Parameters:
///   - expectedSubject: DID of the agent being admitted. Profiles for any other
///     subject are ignored (fail-closed).
///   - requirements: Typed ``RequireParticipation`` values, serialized
///     internally.
///   - profiles: Typed ``ParticipationProfile`` values, serialized internally.
/// - Throws: ``ScpError`` on any unmet requirement or a serialization failure.
public func verifyParticipationRequirements(
    expectedSubject: String,
    requirements: [RequireParticipation],
    profiles: [ParticipationProfile]
) throws {
    try verifyParticipationRequirements(
        expectedSubject: expectedSubject,
        requirementsJson: encodeRequireParticipationJson(requirements),
        profileJson: encodeParticipationProfileJson(profiles)
    )
}

/// Verify that an agent meets a context's capability requirements for admission
/// (spec §7.3.4.4).
///
/// Typed counterpart to the generated
/// ``checkCapabilityRequirements(contextId:subjectDid:requirementsJson:agentCapabilitiesJson:challengeVerificationsJson:)``
/// free function: it serializes the typed ``CapabilityRequirement`` /
/// ``ChallengeVerification`` values (and the agent capability URIs) to the serde
/// wire shape (ADR-058) and calls the bridge unchanged. `subjectDid`/`contextId`
/// bind challenge verifications to the agent and context being admitted — a
/// `ChallengeVerification` only satisfies a requirement when its signed
/// `subjectDid`/`contextId` equal these values, closing cross-subject and
/// cross-context attribution. Returns normally when all requirements are
/// satisfied; throws on any unmet requirement or malformed input.
///
/// Security caveat — authenticity is not authorization: a passing
/// `ChallengeVerified` check proves the verifier's signature is authentic and
/// bound to this subject/context, NOT that the verifier is *trusted*. Because
/// `verifierDid` is self-certifying, a subject can present a genuinely-signed
/// result from a verifier it controls. Establish verifier legitimacy separately;
/// do NOT treat success as an authorization decision.
///
/// - Parameters:
///   - contextId: The context the agent is being admitted to.
///   - subjectDid: DID of the agent being admitted.
///   - requirements: Typed ``CapabilityRequirement`` values, serialized
///     internally.
///   - agentCapabilities: The agent's self-attested capability URIs.
///   - challengeVerifications: Typed ``ChallengeVerification`` records,
///     serialized internally.
/// - Throws: ``ScpError`` on any unmet requirement or a serialization failure.
public func checkCapabilityRequirements(
    contextId: String,
    subjectDid: String,
    requirements: [CapabilityRequirement],
    agentCapabilities: [String],
    challengeVerifications: [ChallengeVerification]
) throws {
    try checkCapabilityRequirements(
        contextId: contextId,
        subjectDid: subjectDid,
        requirementsJson: encodeCapabilityRequirementsJson(requirements),
        agentCapabilitiesJson: encodeAgentCapabilitiesJson(agentCapabilities),
        challengeVerificationsJson: encodeChallengeVerificationsJson(challengeVerifications)
    )
}

// MARK: - Challenge trust inputs (§7.3.4, ADR-058)

/// A challenge request for capability verification (ADR-017, spec §7.3.4).
///
/// Mirrors the Rust `ChallengeRequest` struct (`scp-core`) serde wire shape
/// the bridge deserializes for
/// ``trustVerifyResponse(challenge:response:)``. `challengeType` is a bare
/// capability URI string (the Rust `ChallengeType` serializes as its URI
/// string); `timeout` is the Rust `std::time::Duration` serde shape
/// (``CachedAttestationDuration``). The `CodingKeys` are the serde-canonical
/// snake_case. Mirrors the TypeScript SDK `ChallengeRequest` interface and
/// the Kotlin/Python models 1:1.
public nonisolated struct ChallengeRequest: Codable, Sendable, Equatable {
    /// Unique challenge identifier (UUID v4).
    public let challengeId: String
    /// The type of challenge being issued (a capability URI string).
    public let challengeType: String
    /// DID of the entity issuing the challenge.
    public let challengerDid: String
    /// DID of the entity being challenged.
    public let subjectDid: String
    /// The capability URI being tested (spec §7.3.4.1).
    public let capabilityUri: String
    /// Challenge-specific parameters (schema, test vectors, limits, etc.).
    public let parameters: JSONValue
    /// Maximum time allowed for the subject to respond (`{ secs, nanos }`).
    public let timeout: CachedAttestationDuration
    /// Ed25519 signature over the canonical challenge bytes (64 bytes).
    public let signature: [UInt8]

    /// Memberwise initializer.
    public init(
        challengeId: String,
        challengeType: String,
        challengerDid: String,
        subjectDid: String,
        capabilityUri: String,
        parameters: JSONValue,
        timeout: CachedAttestationDuration,
        signature: [UInt8]
    ) {
        self.challengeId = challengeId
        self.challengeType = challengeType
        self.challengerDid = challengerDid
        self.subjectDid = subjectDid
        self.capabilityUri = capabilityUri
        self.parameters = parameters
        self.timeout = timeout
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case challengeId = "challenge_id"
        case challengeType = "challenge_type"
        case challengerDid = "challenger_did"
        case subjectDid = "subject_did"
        case capabilityUri = "capability_uri"
        case parameters
        case timeout
        case signature
    }
}

/// A response to a challenge request (ADR-017, spec §7.3.4).
///
/// Mirrors the Rust `ChallengeResponse` struct (`scp-core`) serde wire shape
/// the bridge deserializes for ``trustVerifyResponse(challenge:response:)``.
/// The `CodingKeys` are the serde-canonical snake_case. Mirrors the
/// TypeScript SDK `ChallengeResponse` interface and the Kotlin/Python models
/// 1:1.
public nonisolated struct ChallengeResponse: Codable, Sendable, Equatable {
    /// The challenge ID this response corresponds to.
    public let challengeId: String
    /// DID of the entity responding to the challenge.
    public let responderDid: String
    /// Challenge-specific result data (pass/fail, metrics, evidence, etc.).
    public let result: JSONValue
    /// Unix timestamp (seconds) when the response was completed.
    public let completedAt: UInt64
    /// Ed25519 signature over the canonical response bytes (64 bytes).
    public let signature: [UInt8]

    /// Memberwise initializer.
    public init(
        challengeId: String,
        responderDid: String,
        result: JSONValue,
        completedAt: UInt64,
        signature: [UInt8]
    ) {
        self.challengeId = challengeId
        self.responderDid = responderDid
        self.result = result
        self.completedAt = completedAt
        self.signature = signature
    }

    private enum CodingKeys: String, CodingKey {
        case challengeId = "challenge_id"
        case responderDid = "responder_did"
        case result
        case completedAt = "completed_at"
        case signature
    }
}

/// Encodes a single typed attestation envelope
/// (``CachedAttestationEnvelope``) to the JSON wire shape the bridge
/// deserializes for ``trustVerifyAttestation(attestation:)``
/// (`Attestation`) — exactly the shape ``encodeCachedAttestations(_:)``
/// nests per entry.
public func encodeAttestationJson(_ attestation: CachedAttestationEnvelope) throws -> String {
    try encodeTrustAdmissionJson(attestation)
}

/// Encodes a typed ``ChallengeRequest`` to the JSON wire shape the bridge
/// deserializes (`ChallengeRequest`).
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `signature` is not exactly
///   64 elements (before any bridge call).
public func encodeChallengeRequestJson(_ challenge: ChallengeRequest) throws -> String {
    try requireByteLength(
        "ChallengeRequest", "signature",
        expected: 64, actual: challenge.signature, code: "SCP-VALID-7065"
    )
    return try encodeTrustAdmissionJson(challenge)
}

/// Encodes a typed ``ChallengeResponse`` to the JSON wire shape the bridge
/// deserializes (`ChallengeResponse`).
///
/// - Throws: ``ScpError/Validation(msg:code:)`` if `signature` is not exactly
///   64 elements (before any bridge call).
public func encodeChallengeResponseJson(_ response: ChallengeResponse) throws -> String {
    try requireByteLength(
        "ChallengeResponse", "signature",
        expected: 64, actual: response.signature, code: "SCP-VALID-7065"
    )
    return try encodeTrustAdmissionJson(response)
}

// MARK: - Typed challenge-verification wrappers (ADR-058)

/// Verify an attestation's Ed25519 signature, evidence, expiry, and
/// revocation status (ADR-017, §7.4).
///
/// Typed counterpart to the generated
/// ``trustVerifyAttestation(attestationJson:)`` free function: it serializes
/// the typed attestation envelope (``CachedAttestationEnvelope``) to the
/// serde wire shape (ADR-058) and calls the bridge unchanged.
///
/// - Parameter attestation: The typed attestation envelope.
/// - Returns: The structured verification result (`valid` / `chainDepth` /
///   `errorMessage`).
/// - Throws: ``ScpError`` on a serialization failure or malformed envelope.
public func trustVerifyAttestation(
    attestation: CachedAttestationEnvelope
) throws -> AttestationVerificationResult {
    try trustVerifyAttestation(attestationJson: encodeAttestationJson(attestation))
}

public extension SCP {
    /// Verify a challenge response against its original challenge request
    /// (ADR-017, §7.3.4).
    ///
    /// Typed counterpart to
    /// ``SCP/trustVerifyResponse(challengeJson:responseJson:)``: it
    /// serializes the typed ``ChallengeRequest`` / ``ChallengeResponse`` to
    /// the serde wire shapes (ADR-058) and calls the bridge unchanged.
    ///
    /// - Parameters:
    ///   - challenge: The typed challenge request.
    ///   - response: The typed challenge response.
    /// - Returns: `true` if the response is valid (correct responder, within
    ///   timeout, valid signature), `false` otherwise.
    /// - Throws: ``ScpError`` on a wrong-length signature (before any bridge
    ///   call) or a serialization failure.
    func trustVerifyResponse(
        challenge: ChallengeRequest,
        response: ChallengeResponse
    ) throws -> Bool {
        try trustVerifyResponse(
            challengeJson: encodeChallengeRequestJson(challenge),
            responseJson: encodeChallengeResponseJson(response)
        )
    }
}
