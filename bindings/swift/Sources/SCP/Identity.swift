import Foundation

// Identity, IdentityProtocol, and related types are defined by UniFFI in
// ScpBindings.swift.
//
// UniFFI Identity is an open class with methods:
//   - did() -> String
//   - custodyType() -> String
//   - rotateKey() async throws -> Identity
//   - hasAgentKey() -> Bool
//   - getAgentPublicKey() -> String?
//   - addAgentKey() async throws -> Identity
//   - removeAgentKey() async throws -> Identity
//   - rotateAgentKey() async throws -> Identity
//
// All caller-owned identity operations live on ``SCP`` (ADR-048), e.g.
// ``SCP/identityCreate(custody:)``, ``SCP/identityLoad(did:)``,
// ``SCP/identityResolve(did:)``, etc. The deprecated free-function
// façade has been deleted.

// MARK: - RevocationStatus

/// Revocation status for an identity attestation (§3.5).
///
/// Mirrors the Rust `RevocationStatus` enum:
///
/// - `Active` -> `.active`
/// - `Revoked { revoked_at, reason }` -> `.revoked(revokedAt:reason:)`
///
/// ## Provenance
///
/// - Spec section 3.5 (Identity Link Attestations)
public enum RevocationStatus: Sendable, Equatable {
    /// The attestation is active and valid.
    case active

    /// The attestation has been revoked.
    case revoked(revokedAt: UInt64, reason: String? = nil)

    /// The status string: `"active"` or `"revoked"`. Internal — use pattern matching.
    var status: String {
        switch self {
        case .active:
            return "active"
        case .revoked:
            return "revoked"
        }
    }

    /// Unix timestamp (seconds) when the attestation was revoked.
    /// Returns `nil` for active attestations.
    public var revokedAt: UInt64? {
        switch self {
        case .active:
            return nil
        case let .revoked(revokedAt, _):
            return revokedAt
        }
    }

    /// Optional human-readable revocation reason.
    /// Returns `nil` for active attestations.
    public var reason: String? {
        switch self {
        case .active:
            return nil
        case let .revoked(_, reason):
            return reason
        }
    }
}

// MARK: - IdentityAttestation

/// An identity link attestation binding a DID to an external platform (§3.5).
///
/// Represents a cryptographically signed claim that the DID owner also
/// controls an identity on an external platform (e.g., GitHub, X, LinkedIn).
///
/// The ``id`` is deterministically derived as
/// `hex(SHA-256(issuer || platform || handle || issued_at))`.
public struct IdentityAttestation: Sendable, Equatable {
    /// Deterministic attestation ID.
    public let id: String

    /// Platform identifier (e.g., `"github.com"`).
    public let platform: String

    /// Platform handle or username.
    public let platformHandle: String

    /// DID verification method that signed this attestation.
    public let verificationMethod: String

    /// Unix timestamp (seconds) when the evidence was last verified.
    public let verifiedAt: UInt64

    /// Revocation status.
    public let revocationStatus: RevocationStatus

    /// Optional platform-assigned unique identifier.
    public let platformId: String?

    /// Raw JSON string from the bridge for roundtrip signature verification.
    public let rawJson: String?

    /// Creates an attestation from its component fields.
    public init(
        id: String,
        platform: String,
        platformHandle: String,
        verificationMethod: String,
        verifiedAt: UInt64,
        revocationStatus: RevocationStatus = .active,
        platformId: String? = nil,
        rawJson: String? = nil
    ) {
        self.id = id
        self.platform = platform
        self.platformHandle = platformHandle
        self.verificationMethod = verificationMethod
        self.verifiedAt = verifiedAt
        self.revocationStatus = revocationStatus
        self.platformId = platformId
        self.rawJson = rawJson
    }
}

// MARK: - SCP attestation convenience

public extension SCP {
    /// Creates an identity link attestation and parses the JSON result.
    ///
    /// Loads the ``Identity`` for `did` via ``SCP/identityLoad(did:)``,
    /// calls ``SCP/identityCreateLinkAttestation`` and parses the JSON
    /// into an ``IdentityAttestation``.
    func createLinkAttestation(
        did: String,
        platform: String,
        handle: String,
        proof: String,
        verificationMethod: String,
        platformId: String? = nil
    ) async throws -> IdentityAttestation {
        let identity = try await identityLoad(did: did)
        let json = try await identityCreateLinkAttestation(
            identity: identity,
            platform: platform,
            handle: handle,
            proof: proof,
            verificationMethod: verificationMethod,
            platformId: platformId
        )
        return try AttestationWire.parseAttestation(from: json)
    }

    /// Lists link attestations for a DID and parses the JSON array.
    func listLinkAttestations(did: String) throws -> [IdentityAttestation] {
        let json = try identityLinkAttestations(did: did)
        return try AttestationWire.parseAttestations(from: json)
    }

    /// Verifies a link attestation per spec §3.5.4.
    ///
    /// Uses ``IdentityAttestation/rawJson`` when available for exact
    /// roundtrip fidelity. Falls back to re-serializing the attestation
    /// if ``rawJson`` is `nil`.
    ///
    /// `referenceProof` reports what this caller did about a class 2
    /// (`signed_post` / `dns_record`) proof resource, per §3.5.4 Class 2
    /// step 2: `"confirmed"` after fetching the resource `evidence.proof`
    /// names and finding this issuer's DID in it, `"not_fetched"` after
    /// fetching nothing.
    func verifyLinkAttestation(
        _ attestation: IdentityAttestation,
        issuerPublicKeyHex: String,
        referenceProof: String
    ) async throws -> Bool {
        let json: String
        if let raw = attestation.rawJson {
            json = raw
        } else {
            json = try AttestationWire.serializeAttestation(attestation)
        }
        // Routes to ``SCP/identityVerifyLinkAttestation``, the per-instance
        // method, because §3.5.4 step 1 resolves an issuer's DID document
        // through this instance's resolver before any signature check. A
        // UniFFI free function of that same name reaches no bridge instance
        // and declines with `SCP-IDENT-1060` (GitHub issue #2335 finding 2).
        return try await identityVerifyLinkAttestation(
            attestationJson: json,
            issuerPublicKeyHex: issuerPublicKeyHex,
            referenceProof: referenceProof
        )
    }
}

// MARK: - Attestation JSON Wire Format

/// Internal Codable claim matching Rust `AttestationClaim` JSON.
struct AttestationClaimWire: Codable {
    let platform: String
    let platformHandle: String
    let platformId: String?
    let linkType: String

    enum CodingKeys: String, CodingKey {
        case platform
        case platformHandle = "platform_handle"
        case platformId = "platform_id"
        case linkType = "link_type"
    }
}

/// Internal Codable evidence matching Rust `AttestationEvidence` JSON.
struct AttestationEvidenceWire: Codable {
    let method: String
    let proof: String
    let verifiedAt: UInt64
    let verifierDid: String?

    enum CodingKeys: String, CodingKey {
        case method
        case proof
        case verifiedAt = "verified_at"
        case verifierDid = "verifier_did"
    }
}

/// Internal Codable record matching the Rust `IdentityLinkAttestation` JSON
/// wire format produced by `serde_json::to_string`.
struct AttestationWireRecord: Codable {
    let id: String
    let typeField: String
    let issuer: String
    let subject: String
    let issuedAt: UInt64
    let expiresAt: UInt64?
    let claim: AttestationClaimWire
    let evidence: AttestationEvidenceWire
    let revocationStatus: String
    let signature: [UInt8]?

    enum CodingKeys: String, CodingKey {
        case id
        case typeField = "type"
        case issuer
        case subject
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case claim
        case evidence
        case revocationStatus = "revocation_status"
        case signature
    }

    func toIdentityAttestation(rawJson: String?) -> IdentityAttestation {
        let status: RevocationStatus = revocationStatus == "Active"
            ? .active
            : .revoked(revokedAt: issuedAt, reason: nil)
        return IdentityAttestation(
            id: id,
            platform: claim.platform,
            platformHandle: claim.platformHandle,
            verificationMethod: evidence.method,
            verifiedAt: evidence.verifiedAt,
            revocationStatus: status,
            platformId: claim.platformId,
            rawJson: rawJson
        )
    }
}

/// Bridge JSON parsing helpers for identity link attestations.
enum AttestationWire {
    /// Parses a single attestation from the bridge JSON string.
    static func parseAttestation(from json: String) throws -> IdentityAttestation {
        guard let data = json.data(using: .utf8) else {
            throw ScpError.Identity(
                msg: "attestation JSON is not valid UTF-8",
                code: "SCP-ATTEST-9015"
            )
        }
        let decoder = JSONDecoder()
        let wire = try decoder.decode(AttestationWireRecord.self, from: data)
        return wire.toIdentityAttestation(rawJson: json)
    }

    /// Parses a JSON array of attestations from the bridge.
    static func parseAttestations(from json: String) throws -> [IdentityAttestation] {
        guard let data = json.data(using: .utf8) else {
            throw ScpError.Identity(
                msg: "attestation list JSON is not valid UTF-8",
                code: "SCP-ATTEST-9016"
            )
        }
        let decoder = JSONDecoder()
        let wires = try decoder.decode([AttestationWireRecord].self, from: data)
        let encoder = JSONEncoder()
        return try wires.map { wire in
            let elementJson = try String(data: encoder.encode(wire), encoding: .utf8)
            return wire.toIdentityAttestation(rawJson: elementJson)
        }
    }

    /// Re-serializes an ``IdentityAttestation`` into the bridge JSON format.
    static func serializeAttestation(_ attestation: IdentityAttestation) throws -> String {
        let wire = AttestationWireRecord(
            id: attestation.id,
            typeField: "identity_link",
            issuer: "",
            subject: "",
            issuedAt: attestation.verifiedAt,
            expiresAt: nil,
            claim: AttestationClaimWire(
                platform: attestation.platform,
                platformHandle: attestation.platformHandle,
                platformId: attestation.platformId,
                linkType: "self_attestation"
            ),
            evidence: AttestationEvidenceWire(
                method: attestation.verificationMethod,
                proof: "",
                verifiedAt: attestation.verifiedAt,
                verifierDid: nil
            ),
            revocationStatus: attestation.revocationStatus == .active ? "Active" : "Revoked",
            signature: nil
        )
        let encoder = JSONEncoder()
        guard let json = try String(data: encoder.encode(wire), encoding: .utf8) else {
            throw ScpError.Identity(
                msg: "failed to encode attestation as UTF-8 JSON",
                code: "SCP-ATTEST-9017"
            )
        }
        return json
    }
}
