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
/// of ``SCP/aggregateTrust(contextId:subjectDid:eventsJson:merkleRootJson:consequenceRulesJson:thresholdRequirementsJson:attestorSetsJson:cachedAttestationsJson:challengeResultsJson:)``,
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
    /// evaluation.
    ///
    /// Routes through ``SCP/aggregateTrustInput(contextId:subjectDid:eventsJson:merkleRootJson:consequenceRulesJson:thresholdRequirementsJson:attestorSetsJson:cachedAttestationsJson:challengeResultsJson:)``
    /// and parses the JSON result into a typed ``AggregatedTrustInput``.
    func aggregateTrust(
        contextId: String,
        subjectDid: String,
        eventsJson: String,
        merkleRootJson: String,
        consequenceRulesJson: String = "[]",
        thresholdRequirementsJson: String = "{}",
        attestorSetsJson: String = "{}",
        cachedAttestationsJson: String = "[]",
        challengeResultsJson: String = "[]"
    ) throws -> AggregatedTrustInput {
        let resultJson = try aggregateTrustInput(
            contextId: contextId,
            subjectDid: subjectDid,
            eventsJson: eventsJson,
            merkleRootJson: merkleRootJson,
            consequenceRulesJson: consequenceRulesJson,
            thresholdRequirementsJson: thresholdRequirementsJson,
            attestorSetsJson: attestorSetsJson,
            cachedAttestationsJson: cachedAttestationsJson,
            challengeResultsJson: challengeResultsJson
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

// MARK: - Participation Types (admission gating)

/// A verifiable participation fact type.
///
/// Participation facts represent quantifiable behavioral signals that can be
/// observed from a context's event log. They are inputs to the trust model's
/// behavioral validation layer (Layer 2).
///
/// ## Provenance
///
/// - ADR-017 Layer 2 (Behavioral Validation)
/// - Spec section 23.7 (Participation Requirements)
public enum ParticipationFact: String, Sendable, CaseIterable {
    /// Number of messages sent by the participant.
    case messagesSent = "messages_sent"

    /// Number of tools invoked by the participant.
    case toolsInvoked = "tools_invoked"

    /// Number of governance actions taken by the participant.
    case governanceActions = "governance_actions"

    /// Number of contexts the participant has joined.
    case contextsParticipated = "contexts_participated"

    /// Number of attestations the participant has verified.
    case attestationsVerified = "attestations_verified"
}

/// A minimum threshold for a specific participation fact.
public nonisolated struct ParticipationThreshold: Sendable {
    /// The participation fact to check.
    public let fact: ParticipationFact

    /// The minimum value required.
    public let minimum: UInt64

    /// Memberwise initializer.
    public init(fact: ParticipationFact, minimum: UInt64) {
        self.fact = fact
        self.minimum = minimum
    }
}

/// A participant's observed values for each participation fact.
public typealias ParticipationProfile = [ParticipationFact: UInt64]

/// A set of participation thresholds for admission gating.
public nonisolated struct RequireParticipation: Sendable {
    /// The thresholds to check.
    public let thresholds: [ParticipationThreshold]

    /// If `true`, **all** thresholds must be met (AND logic).
    public let requireAll: Bool

    /// Memberwise initializer.
    public init(thresholds: [ParticipationThreshold], requireAll: Bool = true) {
        self.thresholds = thresholds
        self.requireAll = requireAll
    }
}

// MARK: - Participation Verification

/// Verifies that a participation profile meets the required thresholds.
///
/// This is a pure Swift function with no bridge dependency.
///
/// - Parameters:
///   - requirement: The participation thresholds to check.
///   - profile: The observed participation values.
/// - Returns: `true` if the requirement is satisfied, `false` otherwise.
public func verifyParticipationRequirements(
    requirement: RequireParticipation,
    profile: ParticipationProfile
) -> Bool {
    if requirement.thresholds.isEmpty {
        return true
    }

    let results = requirement.thresholds.map { threshold -> Bool in
        let observed = profile[threshold.fact] ?? 0
        return observed >= threshold.minimum
    }

    return requirement.requireAll
        ? results.allSatisfy { $0 }
        : results.contains { $0 }
}
