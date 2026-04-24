// ScpId.swift — Swift SDK SCPID authentication wrappers (#1059)
//
// Wraps UniFFI SCPID bridge functions for DID-based authentication
// against external services per spec section 3.11.
//
// The bridge functions exchange JSON strings; this wrapper layer
// deserializes them into typed Swift structs for ergonomic consumption.
//
// Phase 4 PR 4 (ADR-048 demolition, #1549) moved `scpidSign` and
// `scpidVerify` from free UniFFI functions onto the `Scp` opaque class.
// `ScpId.sign(...)` and `ScpId.verify(...)` therefore require an
// explicit ``SCP`` parameter; `ScpId.challenge(...)` remains a free
// function since it does not depend on any per-bridge state.
//
// Provenance: spec section 3.11 (SCPID), ADR-039 (Shared-DID Agent Binding),
//             ADR-048 (Multi-instance SCP)

import Foundation

// MARK: - Data Types

/// SCPID challenge issued by a relying party (spec section 3.11.2).
///
/// Contains a CSPRNG nonce, audience binding, and validity window.
/// Produced by ``ScpId/challenge(audience:ttl:)`` and consumed
/// by ``ScpId/sign(scp:identity:signingKeyId:challenge:)`` and
/// ``ScpId/verify(scp:response:challenge:)``.
public nonisolated struct ScpIdChallenge: Sendable {
    /// Protocol identifier and version (always `"scpid/1.0"`).
    public let protocolVersion: String

    /// 32-byte CSPRNG nonce for replay prevention (hex-encoded).
    public let nonce: String

    /// URI identifying the relying party.
    public let audience: String

    /// Unix timestamp (milliseconds) when the challenge was created.
    public let issuedAt: UInt64

    /// Unix timestamp (milliseconds) when the challenge expires.
    public let expiresAt: UInt64

    /// The raw JSON string returned by the bridge. Preserved for passing
    /// to ``ScpId/sign(scp:identity:signingKeyId:challenge:)`` and
    /// ``ScpId/verify(scp:response:challenge:)`` without re-serialization.
    public let json: String
}

/// SCPID signed response from the client (spec section 3.11.3).
///
/// Contains the signer's DID, signing key selection, echoed challenge
/// fields, and the Ed25519 signature.
public nonisolated struct ScpIdResponse: Sendable {
    /// Protocol identifier and version (always `"scpid/1.0"`).
    public let protocolVersion: String

    /// The signer's DID.
    public let did: String

    /// Which verification method signed: `"#active"` or `"#agent"`.
    public let signingKeyId: String

    /// Echo of the challenge nonce (hex-encoded).
    public let nonce: String

    /// Echo of the challenge audience URI.
    public let audience: String

    /// Unix timestamp (milliseconds) when the client signed.
    public let signedAt: UInt64

    /// Ed25519 signature over the canonical hash (hex-encoded).
    public let signature: String

    /// The raw JSON string returned by the bridge. Preserved for passing
    /// to ``ScpId/verify(scp:response:challenge:)`` without re-serialization.
    public let json: String
}

/// Result of a successful SCPID verification (spec section 3.11.4).
///
/// Returned by ``ScpId/verify(scp:response:challenge:)`` when all
/// verification steps pass.
public nonisolated struct ScpIdAuthentication: Sendable {
    /// The authenticated DID.
    public let did: String

    /// Which verification method produced the signature.
    public let signingKeyId: String

    /// Unix timestamp (milliseconds) when the client signed.
    public let signedAt: UInt64
}

// MARK: - Wire Types (JSON Decoding)

/// Wire type for deserializing challenge JSON from the bridge.
private struct ChallengeWire: Decodable {
    let protocolVersion: String
    let nonce: String
    let audience: String
    let issuedAt: UInt64
    let expiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case nonce, audience
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
    }
}

/// Wire type for deserializing response JSON from the bridge.
private struct ResponseWire: Decodable {
    let protocolVersion: String
    let did: String
    let signingKeyId: String
    let nonce: String
    let audience: String
    let signedAt: UInt64
    let signature: String

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol"
        case did
        case signingKeyId = "signing_key_id"
        case nonce, audience
        case signedAt = "signed_at"
        case signature
    }
}

/// Wire type for deserializing authentication JSON from the bridge.
private struct AuthenticationWire: Decodable {
    let did: String
    let signingKeyId: String
    let signedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case did
        case signingKeyId = "signing_key_id"
        case signedAt = "signed_at"
    }
}

// MARK: - Public API

/// Namespace for SCPID authentication operations (spec section 3.11).
///
/// Uses the caseless-enum namespace pattern consistent with the Swift SDK.
/// All operations delegate to UniFFI bridge functions/methods and parse
/// their JSON results into typed Swift structs.
public enum ScpId {
    /// Bridge function type for generating an SCPID challenge.
    public typealias ChallengeFn = @Sendable (
        _ audience: String,
        _ ttlSeconds: UInt64
    ) throws -> String

    /// Bridge function type for signing an SCPID challenge.
    public typealias SignFn = @Sendable (
        _ identity: Identity,
        _ signingKeyId: String,
        _ challengeJson: String
    ) throws -> String

    /// Bridge function type for verifying an SCPID response.
    public typealias VerifyFn = @Sendable (
        _ responseJson: String,
        _ challengeJson: String
    ) throws -> String

    /// Unbound challenge function — placeholder; callers must supply an
    /// `SCP`-bound closure via the SDK wrapper because the free
    /// `scpidChallenge` UniFFI export was removed in Phase 4 PR 5
    /// (ADR-048) and replaced with `Scp::scpid_challenge` (per-instance)
    /// so all SCPID operations route through the caller's own `SCP`
    /// rather than a process-global default.
    public static let unboundChallenge: ChallengeFn = { _, _ in
        throw ScpError.Identity(
            msg: "scpidChallenge is unbound — pass an SCP-bound closure (see SCP.scpidChallenge)",
            code: "SCP-IDENT-1046"
        )
    }

    /// Unbound sign function — placeholder; callers must supply an
    /// `SCP`-bound closure via the SDK wrapper because the free
    /// `scpidSign` UniFFI export was removed in Phase 4 PR 5 (ADR-048)
    /// and replaced with `Scp::scpid_sign` (per-instance) so signing
    /// routes through the caller's own `SCP` identity registry rather
    /// than a process-global default.
    public static let unboundSign: SignFn = { _, _, _ in
        throw ScpError.Identity(
            msg: "scpidSign is unbound — pass an SCP-bound closure (see SCP.scpidSign)",
            code: "SCP-IDENT-1046"
        )
    }

    /// Unbound verify function — placeholder; callers must supply an
    /// `SCP`-bound closure via the SDK wrapper because the free
    /// `scpidVerify` UniFFI export was removed in Phase 4 PR 5
    /// (ADR-048) and replaced with `Scp::scpid_verify` (per-instance)
    /// so the DID resolver used for signature verification is routed
    /// through the caller's own `SCP` rather than a process-global
    /// default.
    public static let unboundVerify: VerifyFn = { _, _ in
        throw ScpError.Identity(
            msg: "scpidVerify is unbound — pass an SCP-bound closure (see SCP.scpidVerify)",
            code: "SCP-IDENT-1046"
        )
    }

    // MARK: - Public API

    /// Generates an SCPID challenge for the given audience (spec section 3.11.2).
    ///
    /// Creates a challenge with a 32-byte CSPRNG nonce, audience binding,
    /// and validity window based on the TTL.
    ///
    /// This operation does not depend on any per-``SCP`` bridge state —
    /// the UniFFI bridge exposes it as a free function backed by an
    /// `OsRng` in Rust.
    ///
    /// - Parameters:
    ///   - audience: URI identifying the relying party.
    ///   - ttl: Time-to-live for the challenge. Defaults to 300 seconds.
    ///     Must be between 1 and 300 seconds.
    /// - Returns: An ``ScpIdChallenge`` with the challenge fields.
    /// - Throws: ``ScpError`` if the audience is empty or TTL is out of range.
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.2 (Challenge Generation)
    public static func challenge(
        audience: String,
        ttl: TimeInterval = 300
    ) throws -> ScpIdChallenge {
        guard ttl.isFinite, ttl >= 1, ttl <= 300 else {
            throw ScpError.Validation(
                msg: "ttl must be between 1 and 300 seconds",
                code: "SCP-IDENT-1038"
            )
        }
        let ttlSeconds = UInt64(ttl.rounded(.up))
        let json = try scpidChallenge(audience: audience, ttlSeconds: ttlSeconds)
        let wire = try JSONDecoder().decode(ChallengeWire.self, from: Data(json.utf8))
        return ScpIdChallenge(
            protocolVersion: wire.protocolVersion,
            nonce: wire.nonce,
            audience: wire.audience,
            issuedAt: wire.issuedAt,
            expiresAt: wire.expiresAt,
            json: json
        )
    }

    /// Signs an SCPID challenge with the identity's key (spec section 3.11.3).
    ///
    /// Selects the appropriate signing key (`#active` or `#agent`) from the
    /// identity, and produces a signed SCPID response.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance that minted ``identity``.
    ///   - identity: The identity to sign with.
    ///   - signingKeyId: Which key to sign with: `"#active"` or `"#agent"`.
    ///   - challenge: The challenge to sign (from ``challenge(audience:ttl:)``).
    /// - Returns: An ``ScpIdResponse`` with the signed response fields.
    /// - Throws: ``ScpError`` if the identity lacks the requested key or signing fails.
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.3 (Response Signing)
    /// - ADR-039 (Shared-DID Agent Binding)
    /// - ADR-048 (Multi-instance SCP)
    public static func sign(
        scp: SCP,
        identity: Identity,
        signingKeyId: String,
        challenge: ScpIdChallenge
    ) throws -> ScpIdResponse {
        let json = try scp.scpidSign(
            identity: identity, signingKeyId: signingKeyId, challengeJson: challenge.json
        )
        let wire = try JSONDecoder().decode(ResponseWire.self, from: Data(json.utf8))
        return ScpIdResponse(
            protocolVersion: wire.protocolVersion,
            did: wire.did,
            signingKeyId: wire.signingKeyId,
            nonce: wire.nonce,
            audience: wire.audience,
            signedAt: wire.signedAt,
            signature: wire.signature,
            json: json
        )
    }

    /// Verifies a signed SCPID response against the original challenge (spec section 3.11.4).
    ///
    /// Resolves the signer's DID document and runs the 11-step verification
    /// pipeline. A DID resolver must be initialized (via identity creation on
    /// the same ``SCP``) before calling this method.
    ///
    /// - Parameters:
    ///   - scp: The SDK-level ``SCP`` instance used to resolve the signer's DID.
    ///   - response: The signed response to verify.
    ///   - challenge: The original challenge that was signed.
    /// - Returns: An ``ScpIdAuthentication`` with the verified identity fields.
    /// - Throws: ``ScpError`` if verification fails (expired, signature invalid,
    ///   DID resolution failed, etc.).
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.4 (Verification Pipeline)
    /// - ADR-048 (Multi-instance SCP)
    public static func verify(
        scp: SCP,
        response: ScpIdResponse,
        challenge: ScpIdChallenge
    ) throws -> ScpIdAuthentication {
        let json = try scp.scpidVerify(responseJson: response.json, challengeJson: challenge.json)
        let wire = try JSONDecoder().decode(AuthenticationWire.self, from: Data(json.utf8))
        return ScpIdAuthentication(
            did: wire.did,
            signingKeyId: wire.signingKeyId,
            signedAt: wire.signedAt
        )
    }
}
