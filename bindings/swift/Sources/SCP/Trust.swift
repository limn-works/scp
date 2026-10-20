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
// - ADR-059 (Structured capability evaluation) in `.docs/adrs/phase-2.md`
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
/// diagnostic (spec §7.2.4, ADR-059): one boolean per pipeline-stage group of
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
    /// ADR-059 Decision 3).
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
/// against/by, context creation, role progression, outlet invocation count) come
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

    /// Total outlet invocations across all outlet types.
    public let outletInvocationCount: UInt64

    /// Whether ``outletInvocationCount`` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `OutletInvoked` a convergent leaf — consumers
    /// MUST NOT treat the count as Merkle-proven while this is `false`.
    public let outletInvocationCountAnchored: Bool

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
    /// The parallel of ``outletInvocationCountAnchored``.
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
        outletInvocationCount: UInt64,
        outletInvocationCountAnchored: Bool,
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
        self.outletInvocationCount = outletInvocationCount
        self.outletInvocationCountAnchored = outletInvocationCountAnchored
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
            outletInvocationCount: record.outletInvocationCount,
            outletInvocationCountAnchored: record.outletInvocationCountAnchored,
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
            outletInvocationCount: 0,
            outletInvocationCountAnchored: false,
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
/// (spec §7.2.4, ADR-059). The protocol provides the data, not the verdict —
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
    /// of six per-stage booleans (spec §7.2.4, ADR-059). The probe never records
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
    ) async throws -> BehavioralRecord {
        let cachedJson = try encodeCachedAttestations(cachedAttestations)
        let view = try await inner.participationRecord(
            contextId: contextId,
            subjectDid: subjectDid,
            cachedAttestationsJson: cachedJson
        )
        return BehavioralRecord(record: view)
    }

    /// Evaluate the trustworthiness of a participant within a context
    /// (spec §7.2.4, ADR-059). The protocol provides the data, not the verdict.
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
            behavioralRecord = try await participationRecord(
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
    ) async throws -> AggregatedTrustInput {
        let resultJson = try await aggregateTrustInput(
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
                code: "SCP-VALID-7093"
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
    /// Total outlet invocations across all outlet types.
    case outletInvocationCount = "OutletInvocationCount"
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
    /// Total outlet invocations across all outlet types.
    public let outletInvocationCount: UInt64
    /// Whether ``outletInvocationCount`` is anchored in the canonical Merkle log.
    /// `false` until ADR-051 makes `OutletInvoked` a convergent leaf — consumers
    /// MUST NOT treat the count as Merkle-proven while this is `false`. The flag
    /// is part of the signed preimage, so it cannot be stripped from a signed
    /// profile.
    public let outletInvocationCountAnchored: Bool
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
        outletInvocationCount: UInt64,
        outletInvocationCountAnchored: Bool,
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
        self.outletInvocationCount = outletInvocationCount
        self.outletInvocationCountAnchored = outletInvocationCountAnchored
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
        case outletInvocationCount = "outlet_invocation_count"
        case outletInvocationCountAnchored = "outlet_invocation_count_anchored"
        case contextCreationCount = "context_creation_count"
        case roleProgressionCount = "role_progression_count"
        case attestationCount = "attestation_count"
        case updatedAt = "updated_at"
        case eventLogRoot = "event_log_root"
        case signerPublicKey = "signer_public_key"
        case signature
    }
}

// MARK: - Capability admission types (§7.3.4.4, ADR-058)

/// The most retries and the least cooldown a context accepts from a
/// challenger's standard (spec 07 §7.3.4.4). A record graded under more
/// retries or a shorter cooldown does not meet the requirement.
public nonisolated struct RetryCap: Codable, Sendable, Equatable {
    /// The most retries the challenger's standard may allow.
    public let maxRetries: UInt32
    /// The shortest cooldown, in seconds, the challenger's standard may set.
    public let minCooldownSecs: UInt32

    /// Memberwise initializer.
    public init(maxRetries: UInt32, minCooldownSecs: UInt32) {
        self.maxRetries = maxRetries
        self.minCooldownSecs = minCooldownSecs
    }

    private enum CodingKeys: String, CodingKey {
        case maxRetries = "max_retries"
        case minCooldownSecs = "min_cooldown_secs"
    }
}

/// The error code ``ChallengeVerifiedRequirement/init(capability:trustedVerifiers:retryCap:)``
/// and the bridges raise for a capability requirement that breaks a spec 07
/// §7.3.4.4 rule, such as a `ChallengeVerified` requirement with no trusted
/// verifier.
public let invalidRequirementCode = "SCP-VALID-7150"

/// A single admission requirement of a context's governance (spec 07
/// §7.3.4.4).
///
/// Pass a list of them as `capabilityRequirements` to the typed
/// ``ContextParams`` initializer, or to
/// ``SCP/governanceModifyCapabilityRequirements(handle:proposerDid:requirements:)``.
/// Each case encodes to the Rust `RawCapabilityRequirement` wire object
/// `{capability, verification_level, trusted_verifiers, retry_cap}`.
/// `selfAttested` writes `trusted_verifiers: []` and `retry_cap: null`, so no
/// case can express a `SelfAttested` requirement with verifiers or a retry
/// cap. Mirrors the TypeScript union, the Kotlin sealed class and the Python
/// dataclasses `CapabilityRequirement` 1:1.
public nonisolated enum CapabilityRequirement: Encodable, Sendable, Equatable {
    /// The agent lists `capability` among its own capabilities; no record is
    /// needed.
    case selfAttested(capability: String)
    /// The agent holds a passing record for the capability from one of the
    /// requirement's trusted verifiers.
    case challengeVerified(ChallengeVerifiedRequirement)

    private enum CodingKeys: String, CodingKey {
        case capability
        case verificationLevel = "verification_level"
        case trustedVerifiers = "trusted_verifiers"
        case retryCap = "retry_cap"
    }

    /// Writes the wire object. An absent `retryCap` encodes as explicit JSON
    /// `null`, as `serde_json::to_string` of the Rust struct writes it.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .selfAttested(capability):
            try container.encode(capability, forKey: .capability)
            try container.encode("SelfAttested", forKey: .verificationLevel)
            try container.encode([String](), forKey: .trustedVerifiers)
            try container.encodeNil(forKey: .retryCap)
        case let .challengeVerified(requirement):
            try container.encode(requirement.capability, forKey: .capability)
            try container.encode("ChallengeVerified", forKey: .verificationLevel)
            try container.encode(requirement.trustedVerifiers, forKey: .trustedVerifiers)
            try container.encode(requirement.retryCap, forKey: .retryCap)
        }
    }
}

/// The payload of ``CapabilityRequirement/challengeVerified(_:)``: the
/// capability, the challengers whose records count, and an optional bound on
/// their standards.
public nonisolated struct ChallengeVerifiedRequirement: Sendable, Equatable {
    /// The capability URI the record must name.
    public let capability: String
    /// DIDs of the challengers whose records meet the requirement; never
    /// empty.
    public let trustedVerifiers: [String]
    /// The most retries and the least cooldown a record's standard may have;
    /// `nil` leaves only the capability definition's bounds.
    public let retryCap: RetryCap?

    /// Builds the payload.
    ///
    /// - Throws: ``ScpError/Validation(msg:code:)`` with
    ///   ``invalidRequirementCode`` (`SCP-VALID-7150`) when `trustedVerifiers`
    ///   is empty, because no record could then meet the requirement.
    public init(capability: String, trustedVerifiers: [String], retryCap: RetryCap? = nil) throws {
        guard !trustedVerifiers.isEmpty else {
            throw ScpError.Validation(
                msg: "ChallengeVerified requirement for \(capability) names no trusted verifier",
                code: invalidRequirementCode
            )
        }
        self.capability = capability
        self.trustedVerifiers = trustedVerifiers
        self.retryCap = retryCap
    }
}

/// A signed record that a challenger graded a subject's response (spec 07
/// §7.3.4, ADR-017).
///
/// ``SCP/trustGradeResponse(verifier:request:response:)`` returns one; pass a
/// list of them to
/// ``SCP/checkCapabilityRequirements(contextId:subjectDid:agentCapabilities:challengeVerifications:)``
/// to meet `ChallengeVerified` requirements. The `CodingKeys` are the
/// snake_case the Rust core deserializes; `verifierSignature` is a 64-byte
/// JSON number array. The verifier's signature covers every field, so a
/// record with any field altered fails verification. Mirrors the TypeScript,
/// Kotlin and Python SDK `ChallengeVerification` and the Rust struct 1:1.
public nonisolated struct ChallengeVerification: Codable, Sendable, Equatable {
    /// The record's id, 64 lowercase hex characters.
    public let verificationId: String
    /// DID of the challenger that graded the response.
    public let verifier: String
    /// DID of the subject that answered.
    public let subject: String
    /// The capability URI that was tested.
    public let capabilityUri: String
    /// Digest of the capability definition, 64 lowercase hex characters.
    public let definitionDigest: String
    /// Digest of the request's cases (`challenge_suite_digest`), 64 lowercase
    /// hex characters.
    public let suiteDigest: String
    /// The graded request's id, 64 lowercase hex characters.
    public let challengeId: String
    /// The attempt this record grades, starting at 1.
    public let attempt: UInt32
    /// Digest of the graded response, 64 lowercase hex characters.
    public let responseDigest: String
    /// Retries the challenger's standard allowed.
    public let maxRetries: UInt32
    /// Cooldown in seconds between attempts.
    public let cooldownSecs: UInt32
    /// Score in basis points needed to pass.
    public let passThresholdBps: UInt32
    /// Least cases per category the standard required.
    public let minCategoryCases: UInt32
    /// Whether the subject passed.
    public let passed: Bool
    /// Score in basis points, 0 to 10000.
    public let score: UInt32
    /// Number of test cases graded.
    public let testCount: UInt32
    /// Number of test cases the subject passed.
    public let passCount: UInt32
    /// Unix seconds when the request was created.
    public let challengeCreatedAt: UInt64
    /// Unix seconds when the request expired.
    public let challengeExpiresAt: UInt64
    /// Unix seconds of the grading.
    public let timestamp: UInt64
    /// Unix seconds when this record expires.
    public let expiresAt: UInt64
    /// The context the challenge was administered for.
    public let contextId: String
    /// Ed25519 signature by the verifier's `#active` key over the record
    /// digest (64 bytes).
    public let verifierSignature: [UInt8]

    /// Memberwise initializer.
    public init(
        verificationId: String,
        verifier: String,
        subject: String,
        capabilityUri: String,
        definitionDigest: String,
        suiteDigest: String,
        challengeId: String,
        attempt: UInt32,
        responseDigest: String,
        maxRetries: UInt32,
        cooldownSecs: UInt32,
        passThresholdBps: UInt32,
        minCategoryCases: UInt32,
        passed: Bool,
        score: UInt32,
        testCount: UInt32,
        passCount: UInt32,
        challengeCreatedAt: UInt64,
        challengeExpiresAt: UInt64,
        timestamp: UInt64,
        expiresAt: UInt64,
        contextId: String,
        verifierSignature: [UInt8]
    ) {
        self.verificationId = verificationId
        self.verifier = verifier
        self.subject = subject
        self.capabilityUri = capabilityUri
        self.definitionDigest = definitionDigest
        self.suiteDigest = suiteDigest
        self.challengeId = challengeId
        self.attempt = attempt
        self.responseDigest = responseDigest
        self.maxRetries = maxRetries
        self.cooldownSecs = cooldownSecs
        self.passThresholdBps = passThresholdBps
        self.minCategoryCases = minCategoryCases
        self.passed = passed
        self.score = score
        self.testCount = testCount
        self.passCount = passCount
        self.challengeCreatedAt = challengeCreatedAt
        self.challengeExpiresAt = challengeExpiresAt
        self.timestamp = timestamp
        self.expiresAt = expiresAt
        self.contextId = contextId
        self.verifierSignature = verifierSignature
    }

    private enum CodingKeys: String, CodingKey {
        case verificationId = "verification_id"
        case verifier
        case subject
        case capabilityUri = "capability_uri"
        case definitionDigest = "definition_digest"
        case suiteDigest = "suite_digest"
        case challengeId = "challenge_id"
        case attempt
        case responseDigest = "response_digest"
        case maxRetries = "max_retries"
        case cooldownSecs = "cooldown_secs"
        case passThresholdBps = "pass_threshold_bps"
        case minCategoryCases = "min_category_cases"
        case passed
        case score
        case testCount = "test_count"
        case passCount = "pass_count"
        case challengeCreatedAt = "challenge_created_at"
        case challengeExpiresAt = "challenge_expires_at"
        case timestamp
        case expiresAt = "expires_at"
        case contextId = "context_id"
        case verifierSignature = "verifier_signature"
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
            code: "SCP-VALID-7094"
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
            expected: 32, actual: profile.eventLogRoot, code: "SCP-VALID-7095"
        )
        try requireByteLength(
            "ParticipationProfile", "signerPublicKey",
            expected: 32, actual: profile.signerPublicKey, code: "SCP-VALID-7095"
        )
        try requireByteLength(
            "ParticipationProfile", "signature",
            expected: 64, actual: profile.signature, code: "SCP-VALID-7095"
        )
    }
    return try encodeTrustAdmissionJson(profiles)
}

/// Encodes a typed ``CapabilityRequirement`` array to the JSON array
/// (`Vec<RawCapabilityRequirement>`) that `ContextParams.capabilityRequirementsJson`
/// and the bridge's `governanceModifyCapabilityRequirements` take. The bridge
/// validates the list.
func encodeCapabilityRequirementsJson(_ requirements: [CapabilityRequirement]) throws -> String {
    try encodeTrustAdmissionJson(requirements)
}

/// Encodes a typed ``ChallengeVerification`` array to the JSON wire shape the
/// bridge deserializes (`Vec<ChallengeVerification>`); `verifierSignature`
/// passes through as a number array.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7096` if an id
///   or digest is not 64 lowercase hex characters, `score` exceeds 10000, or
///   `verifierSignature` is not exactly 64 elements (before any bridge call).
public func encodeChallengeVerificationsJson(_ verifications: [ChallengeVerification]) throws -> String {
    for verification in verifications {
        try requireChallengeVerification(verification)
    }
    return try encodeTrustAdmissionJson(verifications)
}

/// Decodes the record JSON the bridge's `trustGradeResponse` returns.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7096` if the
///   JSON is not a record, an id or digest is not 64 lowercase hex characters,
///   `score` exceeds 10000, or the signature is not 64 bytes.
public func decodeChallengeVerificationJson(_ json: String) throws -> ChallengeVerification {
    let verification: ChallengeVerification
    do {
        verification = try JSONDecoder().decode(ChallengeVerification.self, from: Data(json.utf8))
    } catch {
        throw ScpError.Validation(
            msg: "malformed ChallengeVerification JSON: \(error)",
            code: "SCP-VALID-7096"
        )
    }
    try requireChallengeVerification(verification)
    return verification
}

private func requireChallengeVerification(_ verification: ChallengeVerification) throws {
    try requireLowerHex32(
        "ChallengeVerification", "verificationId", verification.verificationId, code: "SCP-VALID-7096"
    )
    for (field, value) in [
        ("definitionDigest", verification.definitionDigest),
        ("suiteDigest", verification.suiteDigest),
        ("challengeId", verification.challengeId),
        ("responseDigest", verification.responseDigest)
    ] {
        try requireLowerHex32("ChallengeVerification", field, value, code: "SCP-VALID-7096")
    }
    let score = verification.score
    if score > 10000 {
        throw ScpError.Validation(
            msg: "ChallengeVerification.score must be in [0, 10000], got \(score)",
            code: "SCP-VALID-7096"
        )
    }
    try requireByteLength(
        "ChallengeVerification", "verifierSignature",
        expected: 64, actual: verification.verifierSignature, code: "SCP-VALID-7096"
    )
}

/// Throws ``ScpError/Validation(msg:code:)`` unless `value` is 64 lowercase hex
/// characters, the wire form of a 32-byte challenge id, verification id or
/// suite digest.
func requireLowerHex32(_ typeName: String, _ fieldName: String, _ value: String, code: String) throws {
    let isLowerHex = value.utf8.count == 64
        && value.utf8.allSatisfy { (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0) }
    guard isLowerHex else {
        throw ScpError.Validation(
            msg: "\(typeName).\(fieldName) must be 64 lowercase hex characters",
            code: code
        )
    }
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
    /// Attests to the integrity of a outlet.
    case outletIntegrity = "OutletIntegrity"
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
            expected: 32, actual: event.prevHash, code: "SCP-VALID-7097"
        )
        try requireByteLength(
            "EventLogEntry", "signature",
            expected: 64, actual: event.signature, code: "SCP-VALID-7097"
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
        expected: 32, actual: merkleRoot, code: "SCP-VALID-7097"
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

public extension SCP {
    /// Verify that an agent meets a context's capability requirements for
    /// admission (spec 07 §7.3.4.4).
    ///
    /// Typed counterpart to
    /// ``SCP/checkCapabilityRequirements(contextId:subjectDid:agentCapabilitiesJson:challengeVerificationsJson:)``:
    /// it serializes the agent capability URIs and the typed
    /// ``ChallengeVerification`` records to the serde wire shape (ADR-058).
    ///
    /// The requirements are the ones the context's governance holds at the time
    /// of the call, set through the typed ``ContextParams`` initializer's
    /// `capabilityRequirements` or
    /// ``SCP/governanceModifyCapabilityRequirements(handle:proposerDid:requirements:)``;
    /// the caller cannot supply them. A `ChallengeVerified` requirement is met only
    /// by a passing record signed by one of its trusted verifiers, for
    /// `subjectDid` and `contextId`, within the requirement's retry cap. Each
    /// record's signature is checked against the verifier's `#active` key,
    /// resolved through this instance's DID resolver. Returns normally when all
    /// requirements are satisfied.
    ///
    /// - Parameters:
    ///   - contextId: The context the agent is being admitted to.
    ///   - subjectDid: DID of the agent being admitted.
    ///   - agentCapabilities: The agent's self-attested capability URIs.
    ///   - challengeVerifications: Typed ``ChallengeVerification`` records,
    ///     serialized internally.
    /// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7076` for an
    ///   unmet requirement, `SCP-VALID-7000` for a malformed DID,
    ///   ``nonCanonicalIdentifierCode`` for a DID that is not canonical, and
    ///   `SCP-VALID-7096` for a malformed record before any bridge call;
    ///   ``ScpError/Identity(msg:code:)`` with `SCP-IDENT-1033` when a record
    ///   must be verified and this instance has no DID resolver.
    func checkCapabilityRequirements(
        contextId: String,
        subjectDid: String,
        agentCapabilities: [String],
        challengeVerifications: [ChallengeVerification]
    ) async throws {
        try await checkCapabilityRequirements(
            contextId: contextId,
            subjectDid: subjectDid,
            agentCapabilitiesJson: encodeAgentCapabilitiesJson(agentCapabilities),
            challengeVerificationsJson: encodeChallengeVerificationsJson(challengeVerifications)
        )
    }

    /// Propose replacing the capability requirements of `handle`'s context
    /// with `requirements` (spec 07 §7.3.4.4, a `ModifyCapabilityRequirements`
    /// governance action). The list is the complete new list; `[]` clears it.
    ///
    /// Encodes `requirements` to the wire JSON and calls
    /// ``Scp/governanceModifyCapabilityRequirements(handle:proposerDid:requirementsJson:)``
    /// on ``inner``. Admission reads the new list once the proposal executes.
    ///
    /// - Parameters:
    ///   - handle: The context whose requirements change.
    ///   - proposerDid: DID of the member that proposes the change, as in
    ///     ``SCP/governancePropose(handle:proposerDid:actionJson:)``.
    ///   - requirements: The new requirements.
    /// - Returns: The bridge's proposal JSON after ``checkProposalResponse(_:)``
    ///   checks every name in it.
    /// - Throws: ``ScpError/Validation(msg:code:)`` with
    ///   ``nonCanonicalIdentifierCode``, ``tooManyCapabilityRequirementsCode``
    ///   or ``invalidRequirementCode`` for a requirement that breaks a
    ///   §7.3.4.4 rule; otherwise fails as `governancePropose` does.
    func governanceModifyCapabilityRequirements(
        handle: ContextHandle,
        proposerDid: String,
        requirements: [CapabilityRequirement]
    ) async throws -> String {
        try await checkProposalResponse(
            inner.governanceModifyCapabilityRequirements(
                handle: handle,
                proposerDid: proposerDid,
                requirementsJson: encodeCapabilityRequirementsJson(requirements)
            )
        )
    }
}

// MARK: - Challenge trust inputs (§7.3.4, ADR-058)

/// A signer's key could not be resolved: the instance has no DID resolver, or a supplied `ChallengeVerification` could not be checked (DID resolution failed, spec 03). Maps from `AdmissionError::VerificationUnavailable` and a missing instance resolver.
public let didResolutionFailedCode = "SCP-IDENT-1033"

/// The registry's JSON schema validation error, which the bridges also raise for every trust error without a code of its own: a challenge, response or verification whose signature does not verify, a record bound to another verifier, subject, context or window, a caller who is not a member or has not opted in, or a failed ledger write. Maps from each `TrustError` variant `trust_error_code` does not name.
public let jsonSchemaValidationFailedCode = "SCP-VALID-7003"

/// The error code the bridges raise when a challenge for a protocol capability URI has fewer test cases than its standard's minimum (spec 07 §7.3.4.3).
public let challengeSuiteBelowMinimumCode = "SCP-VALID-7039"

/// The agent capabilities JSON of a capability admission check does not decode as a list of capability URIs.
public let malformedAgentCapabilitiesCode = "SCP-VALID-7074"

/// The challenge verifications JSON of a capability admission check does not decode as a list of `ChallengeVerification` records.
public let malformedChallengeVerificationsCode = "SCP-VALID-7075"

/// A capability requirement is unmet: the subject lacks a required capability, or a `ChallengeVerified` requirement has no record that admits the subject. Maps from `AdmissionError::MissingCapability` and `AdmissionError::VerificationRequired`.
public let admissionRequirementUnmetCode = "SCP-VALID-7076"

/// A capability admission check names an empty subject DID. Maps from `AdmissionError::EmptySubjectDid`.
public let emptySubjectDidCode = "SCP-VALID-7077"

/// The error code the bridges raise when the challenger's ledger already holds the most open challenges it may hold, so it opens no new one; retry later.
public let challengeNotOpenCode = "SCP-VALID-7099"

/// The error code the bridges raise when the challenge's window has closed; no attempt is graded.
public let challengeExpiredCode = "SCP-VALID-7102"

/// The error code the bridges raise when an attempt number is not the next one the challenger expects.
public let attemptOutOfOrderCode = "SCP-VALID-7103"

/// The error code the bridges raise when the subject has used every attempt the challenge allows.
public let retriesExhaustedCode = "SCP-VALID-7104"

/// The error code the bridges raise when the cooldown between attempts has not passed; ``retryAfter(_:)`` reads the first second a retry may succeed.
public let cooldownActiveCode = "SCP-VALID-7105"

/// The challenge is closed: passed or out of attempts. The attempt check returns
/// this code at begin and at commit (spec 07 §7.3.4).
public let challengeClosedCode = "SCP-VALID-7106"

/// No challenge the challenger holds answers this lookup: no live challenge has
/// this id, digest and subject, or a closed one graded no response with this
/// `D_r` (spec 07 §7.3.4).
public let unknownChallengeCode = "SCP-VALID-7107"

/// The error code the bridges raise when the outputs do not answer the request's cases one for one.
public let outputsMismatchCode = "SCP-VALID-7108"

/// The error code the bridges raise when a `CustomEval` case names an evaluator outlet that is not registered in the evaluator context.
public let evaluatorUnavailableCode = "SCP-VALID-7109"

/// A required capability has no passing record from a trusted challenger: the only passing record comes from a verifier the requirement does not trust. Maps from `AdmissionError::UntrustedVerifier`.
public let untrustedVerifierCode = "SCP-VALID-7121"

/// The error code the bridges raise when the verifier and the subject decode to the same key.
public let selfChallengeCode = "SCP-VALID-7127"

/// The error code the bridges raise when a capability URI names a standard whose pass condition cannot be computed from the subject's outputs, or names a system capability.
public let standardNotGradableCode = "SCP-VALID-7128"

/// The error code the bridges raise when no capability definition can be obtained for the URI.
public let capabilityDefinitionUnavailableCode = "SCP-VALID-7129"

/// The error code the bridges raise when a policy value or a requirement's retry cap lies outside the capability definition's limits or the protocol bounds.
public let policyOutsideDefinitionCode = "SCP-VALID-7137"

/// The error code the bridges raise when a `SchemaMatch` case carries a schema the protocol does not admit.
public let schemaRejectedCode = "SCP-VALID-7138"

/// The error code the bridges raise when another grading of the challenge holds a live lease; retry later.
public let gradingInProgressCode = "SCP-VALID-7139"

/// The error code the bridges raise when a response exceeds the protocol's response size or JSON depth limit.
public let responseTooLargeCode = "SCP-VALID-7143"

/// The error code the bridges raise when two validly signed capability definitions for one URI differ.
public let definitionEquivocationCode = "SCP-VALID-7144"

/// The error code the bridges raise when the challenger cannot grade another attempt now; the attempt is not used.
public let gradingCapacityExhaustedCode = "SCP-VALID-7146"

/// The error code the bridges raise when a DID or URI is not canonical.
public let nonCanonicalIdentifierCode = "SCP-VALID-7147"

/// The error code the bridges raise when a context names more capability requirements than the protocol allows.
public let tooManyCapabilityRequirementsCode = "SCP-VALID-7148"

/// The error code the bridges raise when the challenger lost its grading lease on an attempt; the attempt is not used.
public let gradingLeaseLostCode = "SCP-VALID-7149"

/// The error code the bridges raise when a challenge to the same subject for the same capability is still open; ``retryAfter(_:)`` reads the second it closes.
public let challengeWindowOpenCode = "SCP-VALID-7151"

/// The error code the bridges raise when an attempt is graded at or before its challenge's `createdAt` second; ``retryAfter(_:)`` reads the first second grading may succeed.
public let challengeNotYetGradableCode = "SCP-VALID-7153"

/// Whether a refusal with `code` may succeed when the same call is made
/// again later, unchanged.
///
/// True exactly for ``challengeNotOpenCode``, ``cooldownActiveCode``,
/// ``gradingInProgressCode``, ``gradingCapacityExhaustedCode``,
/// ``gradingLeaseLostCode``, ``challengeWindowOpenCode`` and
/// ``challengeNotYetGradableCode``. Every other code is final for the call.
public func isRetryable(_ code: String) -> Bool {
    retryableChallengeCodes.contains(code)
}

private let retryableChallengeCodes: Set<String> = [
    challengeNotOpenCode,
    cooldownActiveCode,
    gradingInProgressCode,
    gradingCapacityExhaustedCode,
    gradingLeaseLostCode,
    challengeWindowOpenCode,
    challengeNotYetGradableCode
]

/// The first Unix second at which a refused call may succeed, read from the
/// `(retry_after=N)` suffix the bridges append to the message of a
/// ``cooldownActiveCode``, ``challengeWindowOpenCode`` or
/// ``challengeNotYetGradableCode`` refusal; `nil` when `error` carries none.
public func retryAfter(_ error: Error) -> UInt64? {
    let message: String
    switch error {
    case let ScpError.Identity(msg, _), let ScpError.Context(msg, _),
         let ScpError.Permission(msg, _), let ScpError.Crypto(msg, _),
         let ScpError.Transport(msg, _), let ScpError.Outlet(msg, _),
         let ScpError.Validation(msg, _):
        message = msg
    default:
        return nil
    }
    let key = "(retry_after="
    guard let start = message.range(of: key, options: .backwards),
          let end = message[start.upperBound...].firstIndex(of: ")")
    else {
        return nil
    }
    return UInt64(message[start.upperBound ..< end])
}

/// How a test case's output is judged (spec 07 §7.3.4.2).
///
/// Encodes to the Rust `ExpectedOutput` enum's externally tagged serde shape,
/// for example `{"ExactMatch":{"value":...}}`. `customEval` writes only
/// `{"CustomEval":{"evaluator_outlet_id":...}}`, because the Rust type carries
/// no context; ``SCP/trustCreateChallenge(_:)`` passes `evaluatorContextId` to
/// the bridge as its evaluator context. Mirrors the TypeScript
/// `ExpectedOutput` union, the Kotlin sealed class and the Python variant
/// classes 1:1.
public nonisolated enum ExpectedOutput: Encodable, Sendable, Equatable {
    /// The output must equal `value`.
    case exactMatch(value: JSONValue)
    /// The output must validate against the JSON Schema `schema`.
    case schemaMatch(schema: JSONValue)
    /// The output must contain every string in `required`.
    case containsAll(required: [String])
    /// The output must contain none of the strings in `forbidden`.
    case containsNone(forbidden: [String])
    /// The outlet `evaluatorOutletId`, registered in the context
    /// `evaluatorContextId`, judges the output. Every `customEval` case of one
    /// challenge names the same `evaluatorContextId`.
    case customEval(evaluatorOutletId: String, evaluatorContextId: String)

    private enum VariantKeys: String, CodingKey {
        case exactMatch = "ExactMatch"
        case schemaMatch = "SchemaMatch"
        case containsAll = "ContainsAll"
        case containsNone = "ContainsNone"
        case customEval = "CustomEval"
    }

    private enum FieldKeys: String, CodingKey {
        case value
        case schema
        case required
        case forbidden
        case evaluatorOutletId = "evaluator_outlet_id"
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: VariantKeys.self)
        switch self {
        case let .exactMatch(value):
            var fields = container.nestedContainer(keyedBy: FieldKeys.self, forKey: .exactMatch)
            try fields.encode(value, forKey: .value)
        case let .schemaMatch(schema):
            var fields = container.nestedContainer(keyedBy: FieldKeys.self, forKey: .schemaMatch)
            try fields.encode(schema, forKey: .schema)
        case let .containsAll(required):
            var fields = container.nestedContainer(keyedBy: FieldKeys.self, forKey: .containsAll)
            try fields.encode(required, forKey: .required)
        case let .containsNone(forbidden):
            var fields = container.nestedContainer(keyedBy: FieldKeys.self, forKey: .containsNone)
            try fields.encode(forbidden, forKey: .forbidden)
        case let .customEval(evaluatorOutletId, _):
            var fields = container.nestedContainer(keyedBy: FieldKeys.self, forKey: .customEval)
            try fields.encode(evaluatorOutletId, forKey: .evaluatorOutletId)
        }
    }
}

/// One challenger-written test case (spec 07 §7.3.4.2).
public nonisolated struct TestCase: Encodable, Sendable, Equatable {
    /// Identifier unique within the challenge.
    public let testId: String
    /// The input the subject runs.
    public let input: JSONValue
    /// How the output is judged.
    public let expected: ExpectedOutput
    /// The case's category; a BCP 47 language tag for `multilingual/v1`.
    public let category: String
    /// The case's weight in basis points; a protocol suite's weights sum to
    /// 10000.
    public let weight: UInt32

    /// Memberwise initializer.
    public init(testId: String, input: JSONValue, expected: ExpectedOutput, category: String, weight: UInt32) {
        self.testId = testId
        self.input = input
        self.expected = expected
        self.category = category
        self.weight = weight
    }

    private enum CodingKeys: String, CodingKey {
        case testId = "test_id"
        case input
        case expected
        case category
        case weight
    }
}

/// One case as the subject sees it: the test case without its expected output
/// (spec 07 §7.3.4.2). The request carries no answer, and the challenger's
/// ledger keeps the expected outputs to grade with.
///
/// Mirrors the Rust `ChallengeCase` and the TypeScript, Kotlin and Python SDK
/// `ChallengeCase` 1:1.
public nonisolated struct ChallengeCase: Codable, Sendable, Equatable {
    /// Identifier unique within the challenge.
    public let testId: String
    /// The input the subject runs.
    public let input: JSONValue
    /// The case's category.
    public let category: String
    /// The case's weight in basis points.
    public let weight: UInt32

    /// Memberwise initializer.
    public init(testId: String, input: JSONValue, category: String, weight: UInt32) {
        self.testId = testId
        self.input = input
        self.category = category
        self.weight = weight
    }

    private enum CodingKeys: String, CodingKey {
        case testId = "test_id"
        case input
        case category
        case weight
    }
}

/// A signed challenge request (spec 07 §7.3.4 step 1, ADR-017).
///
/// ``SCP/trustCreateChallenge(_:)``
/// returns one. The verifier's signature covers every field, so a request with
/// any field altered is refused when answered or graded. Mirrors the Rust
/// `ChallengeRequest` and the TypeScript, Kotlin and Python models 1:1.
public nonisolated struct ChallengeRequest: Codable, Sendable, Equatable {
    /// 64 lowercase hex characters (32 random bytes).
    public let challengeId: String
    /// The capability URI under test.
    public let capabilityUri: String
    /// Digest of the capability definition followed, 64 lowercase hex
    /// characters.
    public let definitionDigest: String
    /// The cases the subject answers, in order.
    public let testCases: [ChallengeCase]
    /// Unix seconds, challenger clock.
    public let createdAt: UInt64
    /// Unix seconds after which no attempt is graded.
    public let expiresAt: UInt64
    /// Retries allowed after the first attempt.
    public let maxRetries: UInt32
    /// Seconds between graded attempts.
    public let cooldownSecs: UInt32
    /// Score in basis points needed to pass.
    public let passThresholdBps: UInt32
    /// The context the challenge is administered in.
    public let contextId: String
    /// DID of the challenger.
    public let verifier: String
    /// DID of the challenged identity.
    public let subject: String
    /// Ed25519 signature by the verifier's `#active` key over the request
    /// digest (64 bytes).
    public let verifierSignature: [UInt8]

    /// Memberwise initializer.
    public init(
        challengeId: String,
        capabilityUri: String,
        definitionDigest: String,
        testCases: [ChallengeCase],
        createdAt: UInt64,
        expiresAt: UInt64,
        maxRetries: UInt32,
        cooldownSecs: UInt32,
        passThresholdBps: UInt32,
        contextId: String,
        verifier: String,
        subject: String,
        verifierSignature: [UInt8]
    ) {
        self.challengeId = challengeId
        self.capabilityUri = capabilityUri
        self.definitionDigest = definitionDigest
        self.testCases = testCases
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.maxRetries = maxRetries
        self.cooldownSecs = cooldownSecs
        self.passThresholdBps = passThresholdBps
        self.contextId = contextId
        self.verifier = verifier
        self.subject = subject
        self.verifierSignature = verifierSignature
    }

    private enum CodingKeys: String, CodingKey {
        case challengeId = "challenge_id"
        case capabilityUri = "capability_uri"
        case definitionDigest = "definition_digest"
        case testCases = "test_cases"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case maxRetries = "max_retries"
        case cooldownSecs = "cooldown_secs"
        case passThresholdBps = "pass_threshold_bps"
        case contextId = "context_id"
        case verifier
        case subject
        case verifierSignature = "verifier_signature"
    }
}

/// One output, answering the case with the same `testId` (spec 07 §7.3.4
/// step 2).
public nonisolated struct TestOutput: Codable, Sendable, Equatable {
    /// The case answered.
    public let testId: String
    /// The subject's output.
    public let output: JSONValue

    /// Memberwise initializer.
    public init(testId: String, output: JSONValue) {
        self.testId = testId
        self.output = output
    }

    private enum CodingKeys: String, CodingKey {
        case testId = "test_id"
        case output
    }
}

/// A subject's signed answer to one attempt (spec 07 §7.3.4 step 2, ADR-017).
///
/// ``SCP/trustRespondToChallenge(subject:request:outputs:attempt:)`` returns
/// one; pass it to ``SCP/trustGradeResponse(verifier:request:response:)``.
/// Mirrors the Rust `ChallengeResponse` and the TypeScript, Kotlin and Python
/// models 1:1.
public nonisolated struct ChallengeResponse: Codable, Sendable, Equatable {
    /// The request's challenge id, 64 lowercase hex characters.
    public let challengeId: String
    /// Digest of the request answered, 64 lowercase hex characters.
    public let requestDigest: String
    /// DID of the subject, as named in the request.
    public let subject: String
    /// The attempt number, starting at 1.
    public let attempt: UInt32
    /// One output per case, in case order.
    public let outputs: [TestOutput]
    /// Ed25519 signature by the subject's `#active` key over the response
    /// digest (64 bytes).
    public let subjectSignature: [UInt8]

    /// Memberwise initializer.
    public init(
        challengeId: String,
        requestDigest: String,
        subject: String,
        attempt: UInt32,
        outputs: [TestOutput],
        subjectSignature: [UInt8]
    ) {
        self.challengeId = challengeId
        self.requestDigest = requestDigest
        self.subject = subject
        self.attempt = attempt
        self.outputs = outputs
        self.subjectSignature = subjectSignature
    }

    private enum CodingKeys: String, CodingKey {
        case challengeId = "challenge_id"
        case requestDigest = "request_digest"
        case subject
        case attempt
        case outputs
        case subjectSignature = "subject_signature"
    }
}

/// One case's grade. The challenger keeps `reason` and never signs it.
public nonisolated struct CaseResult: Codable, Sendable, Equatable {
    /// Whether the case passed.
    public let passed: Bool
    /// Why the case failed, or the evaluator's reason; `nil` when there is
    /// none.
    public let reason: String?

    /// Memberwise initializer.
    public init(passed: Bool, reason: String?) {
        self.passed = passed
        self.reason = reason
    }
}

/// What ``SCP/trustGradeResponse(verifier:request:response:)`` returns.
public nonisolated struct GradedChallenge: Sendable, Equatable {
    /// The signed record of the graded attempt, pass or fail.
    public let record: ChallengeVerification
    /// One result per case, in case order.
    public let caseResults: [CaseResult]
    /// Why the record was not written to this instance's trust store, with its
    /// error code, or `nil` when it was. The record is valid either way.
    public let trustStoreError: TrustStoreWriteError?

    /// Memberwise initializer.
    public init(
        record: ChallengeVerification,
        caseResults: [CaseResult],
        trustStoreError: TrustStoreWriteError?
    ) {
        self.record = record
        self.caseResults = caseResults
        self.trustStoreError = trustStoreError
    }
}

/// Encodes a single typed attestation envelope
/// (``CachedAttestationEnvelope``) to the JSON wire shape the bridge
/// deserializes for ``SCP/trustVerifyAttestation(contextId:attestation:)``
/// (`Attestation`) — exactly the shape ``encodeCachedAttestations(_:)``
/// nests per entry.
public func encodeAttestationJson(_ attestation: CachedAttestationEnvelope) throws -> String {
    try encodeTrustAdmissionJson(attestation)
}

/// Encodes typed test cases to the JSON array
/// ``SCP/trustCreateChallenge(_:)``
/// passes to the bridge (`Vec<TestCase>`).
public func encodeTestCasesJson(_ testCases: [TestCase]) throws -> String {
    try encodeTrustAdmissionJson(testCases)
}

/// Encodes a typed ``ChallengeRequest`` to the JSON wire shape the bridge
/// deserializes (`ChallengeRequest`).
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7098` if an
///   id or digest is not 64 lowercase hex characters or the
///   signature is not 64 bytes (before any bridge call).
public func encodeChallengeRequestJson(_ request: ChallengeRequest) throws -> String {
    try requireChallengeRequest(request)
    return try encodeTrustAdmissionJson(request)
}

/// Decodes the request JSON the bridge returns into a typed
/// ``ChallengeRequest``.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7098` if the
///   JSON is not a request, an id or digest is not 64 lowercase hex
///   characters, or the signature is not 64 bytes.
public func decodeChallengeRequestJson(_ json: String) throws -> ChallengeRequest {
    let request: ChallengeRequest
    do {
        request = try JSONDecoder().decode(ChallengeRequest.self, from: Data(json.utf8))
    } catch {
        throw ScpError.Validation(msg: "malformed ChallengeRequest JSON: \(error)", code: "SCP-VALID-7098")
    }
    try requireChallengeRequest(request)
    return request
}

private func requireChallengeRequest(_ request: ChallengeRequest) throws {
    try requireLowerHex32("ChallengeRequest", "challengeId", request.challengeId, code: "SCP-VALID-7098")
    try requireLowerHex32(
        "ChallengeRequest", "definitionDigest", request.definitionDigest, code: "SCP-VALID-7098"
    )
    try requireByteLength(
        "ChallengeRequest", "verifierSignature",
        expected: 64, actual: request.verifierSignature, code: "SCP-VALID-7098"
    )
}

/// Encodes typed outputs to the JSON array the bridge deserializes
/// (`Vec<TestOutput>`).
public func encodeTestOutputsJson(_ outputs: [TestOutput]) throws -> String {
    try encodeTrustAdmissionJson(outputs)
}

/// Encodes a typed ``ChallengeResponse`` to the JSON wire shape the bridge
/// deserializes (`ChallengeResponse`).
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7098` if the id
///   or digest is not 64 lowercase hex characters or the signature is not 64
///   bytes (before any bridge call).
public func encodeChallengeResponseJson(_ response: ChallengeResponse) throws -> String {
    try requireChallengeResponse(response)
    return try encodeTrustAdmissionJson(response)
}

/// Decodes the response JSON the bridge returns into a typed
/// ``ChallengeResponse``.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7098` if the
///   JSON is not a response, the id or digest is not 64 lowercase hex
///   characters, or the signature is not 64 bytes.
public func decodeChallengeResponseJson(_ json: String) throws -> ChallengeResponse {
    let response: ChallengeResponse
    do {
        response = try JSONDecoder().decode(ChallengeResponse.self, from: Data(json.utf8))
    } catch {
        throw ScpError.Validation(msg: "malformed ChallengeResponse JSON: \(error)", code: "SCP-VALID-7098")
    }
    try requireChallengeResponse(response)
    return response
}

private func requireChallengeResponse(_ response: ChallengeResponse) throws {
    try requireLowerHex32("ChallengeResponse", "challengeId", response.challengeId, code: "SCP-VALID-7098")
    try requireLowerHex32("ChallengeResponse", "requestDigest", response.requestDigest, code: "SCP-VALID-7098")
    try requireByteLength(
        "ChallengeResponse", "subjectSignature",
        expected: 64, actual: response.subjectSignature, code: "SCP-VALID-7098"
    )
}

/// Decodes the per-case results JSON the grading bridge returns.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7098` if the
///   JSON is not an array of results.
public func decodeCaseResultsJson(_ json: String) throws -> [CaseResult] {
    do {
        return try JSONDecoder().decode([CaseResult].self, from: Data(json.utf8))
    } catch {
        throw ScpError.Validation(msg: "malformed CaseResult JSON: \(error)", code: "SCP-VALID-7098")
    }
}

/// The parameters of ``SCP/trustCreateChallenge(_:)``. Mirrors the TypeScript,
/// Kotlin and Python `CreateChallengeConfig` 1:1.
public nonisolated struct CreateChallengeConfig: Sendable {
    /// The challenger, whose `#active` key signs the request.
    public let verifier: Identity
    /// DID of the challenged identity.
    public let subject: String
    /// The capability URI under test.
    public let capabilityUri: String
    /// The challenger-written cases with their expected outputs; their
    /// weights sum to 10000.
    public let testCases: [TestCase]
    /// The context the challenge is administered in and the record is bound
    /// to.
    public let contextId: String
    /// The grading window: seconds from creation during which attempts are
    /// graded.
    public let windowSecs: UInt32
    /// Fewer retries or a longer cooldown than the capability definition's.
    /// A `nil` field of ``ChallengePolicy`` takes the definition's value, and
    /// a `nil` policy keeps both. A policy may only tighten the definition, on
    /// any URI.
    public let policy: ChallengePolicy?

    /// Memberwise initializer.
    public init(
        verifier: Identity,
        subject: String,
        capabilityUri: String,
        testCases: [TestCase],
        contextId: String,
        windowSecs: UInt32,
        policy: ChallengePolicy? = nil
    ) {
        self.verifier = verifier
        self.subject = subject
        self.capabilityUri = capabilityUri
        self.testCases = testCases
        self.contextId = contextId
        self.windowSecs = windowSecs
        self.policy = policy
    }
}

/// The one evaluator context the `customEval` cases of `testCases` name, or
/// `nil` when no case is `customEval`.
///
/// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7001` when two
///   cases name different contexts, because the bridge grades one challenge on
///   one evaluator context.
func evaluatorContextId(of testCases: [TestCase]) throws -> String? {
    var found: String?
    for testCase in testCases {
        guard case let .customEval(_, contextId) = testCase.expected else { continue }
        if let earlier = found, earlier != contextId {
            throw ScpError.Validation(
                msg: "CustomEval cases name two evaluator contexts, \(earlier) and \(contextId); "
                    + "one challenge has one evaluator context",
                code: "SCP-VALID-7001"
            )
        }
        found = contextId
    }
    return found
}

// MARK: - Typed challenge wrappers (ADR-058)

public extension SCP {
    /// Verify an attestation's Ed25519 signature, evidence, expiry, its own
    /// revocation status, and this instance's revocation list for
    /// `contextId` (ADR-017, §7.4.4).
    ///
    /// Serializes the typed attestation envelope
    /// (``CachedAttestationEnvelope``) to the serde wire shape (ADR-058) and
    /// calls ``Scp/trustVerifyAttestation(contextId:attestationJson:)`` on
    /// ``inner``.
    ///
    /// - Parameters:
    ///   - contextId: The context whose revocation list is checked.
    ///   - attestation: The typed attestation envelope.
    /// - Returns: The structured verification result (`valid` / `chainDepth` /
    ///   `errorMessage`).
    /// - Throws: ``ScpError`` on a serialization failure, a malformed context
    ///   id or envelope, or a revocation list that cannot be read. An
    ///   unreadable list throws; it never reads as `valid == false`.
    func trustVerifyAttestation(
        contextId: String,
        attestation: CachedAttestationEnvelope
    ) async throws -> AttestationVerificationResult {
        try await inner.trustVerifyAttestation(
            contextId: contextId,
            attestationJson: encodeAttestationJson(attestation)
        )
    }

    /// Issue a challenge request for `config.capabilityUri`, signed by
    /// `config.verifier`'s `#active` key through custody (spec 07 §7.3.4 step
    /// 1, ADR-017).
    ///
    /// The challenger writes `config.testCases` with their expected outputs.
    /// The returned request carries each case without its expected output;
    /// the challenger's ledger keeps the expected outputs to grade with. The
    /// capability definition for `capabilityUri` sets the pass threshold, the
    /// retries and the cooldown; `config.policy` may only tighten them, on any
    /// URI.
    ///
    /// The `evaluatorContextId` of the `customEval` cases is passed to the
    /// bridge as the context whose outlets grade them.
    ///
    /// - Parameter config: The challenge to issue.
    /// - Throws: ``ScpError/Validation(msg:code:)`` with `SCP-VALID-7001` when
    ///   two `customEval` cases name different evaluator contexts (before any
    ///   bridge call); ``challengeSuiteBelowMinimumCode`` when the suite has
    ///   fewer cases than the definition's minimum; `SCP-VALID-7002` for
    ///   malformed test cases; ``policyOutsideDefinitionCode`` for a policy
    ///   looser than the definition; ``challengeWindowOpenCode`` while an
    ///   earlier challenge to the same subject for the same capability is
    ///   open; ``evaluatorUnavailableCode`` for an evaluator outlet that is not
    ///   registered; ``selfChallengeCode`` when the verifier is the subject;
    ///   ``nonCanonicalIdentifierCode`` for a DID that is not canonical; and
    ///   `SCP-VALID-7098` when the returned request is malformed.
    func trustCreateChallenge(_ config: CreateChallengeConfig) async throws -> ChallengeRequest {
        let evaluatorContext = try evaluatorContextId(of: config.testCases)
        return try await decodeChallengeRequestJson(
            inner.trustCreateChallenge(
                verifier: config.verifier,
                subject: config.subject,
                capabilityUri: config.capabilityUri,
                testCasesJson: encodeTestCasesJson(config.testCases),
                contextId: config.contextId,
                windowSecs: config.windowSecs,
                evaluatorContextId: evaluatorContext,
                policy: config.policy
            ).requestJson
        )
    }

    /// Answer `request` for `attempt`, signed by `subject`'s `#active` key
    /// (spec 07 §7.3.4 step 2, ADR-017).
    ///
    /// The challenger's signature on `request` is checked against the key this
    /// instance's DID resolver returns before anything is signed.
    ///
    /// - Parameters:
    ///   - subject: The challenged identity.
    ///   - request: The signed request, as the challenger sent it.
    ///   - outputs: One output per case.
    ///   - attempt: The attempt number, starting at 1.
    /// - Throws: ``ScpError/Validation(msg:code:)`` when the request's
    ///   signature, subject or window does not hold, and `SCP-VALID-7098` for a
    ///   malformed request or returned response; ``ScpError/Identity(msg:code:)``
    ///   with `SCP-IDENT-1033` when this instance has no DID resolver.
    func trustRespondToChallenge(
        subject: Identity,
        request: ChallengeRequest,
        outputs: [TestOutput],
        attempt: UInt32
    ) async throws -> ChallengeResponse {
        try await decodeChallengeResponseJson(
            trustRespondToChallenge(
                subject: subject,
                requestJson: encodeChallengeRequestJson(request),
                outputsJson: encodeTestOutputsJson(outputs),
                attempt: attempt
            )
        )
    }

    /// Grade `response` to `request` and return the record, signed by
    /// `verifier`'s `#active` key (spec 07 §7.3.4 steps 3 and 4, ADR-017).
    ///
    /// Both signatures are checked first. The challenger's ledger then checks
    /// the attempt number, the cooldown and the window, grades each case
    /// against its stored answer, and signs a record for the attempt, pass or
    /// fail. The record is also written to this instance's trust store;
    /// ``GradedChallenge/trustStoreError`` says why when that write failed.
    ///
    /// - Parameters:
    ///   - verifier: The identity that issued `request`.
    ///   - request: The signed request.
    ///   - response: The subject's signed response.
    /// - Throws: ``ScpError/Validation(msg:code:)`` when a signature or the
    ///   attempt does not hold; with ``gradingCapacityExhaustedCode`` or
    ///   ``gradingLeaseLostCode`` for a grading that used no attempt; with
    ///   ``cooldownActiveCode`` or ``challengeNotYetGradableCode`` for an
    ///   attempt graded too early, whose retry second ``retryAfter(_:)``
    ///   reads; and with `SCP-VALID-7096` or `SCP-VALID-7098` for a malformed
    ///   input or returned record.
    func trustGradeResponse(
        verifier: Identity,
        request: ChallengeRequest,
        response: ChallengeResponse
    ) async throws -> GradedChallenge {
        let graded = try await trustGradeResponse(
            verifier: verifier,
            requestJson: encodeChallengeRequestJson(request),
            responseJson: encodeChallengeResponseJson(response)
        )
        return try GradedChallenge(
            record: decodeChallengeVerificationJson(graded.recordJson),
            caseResults: decodeCaseResultsJson(graded.reasonsJson),
            trustStoreError: graded.trustStoreError
        )
    }
}
