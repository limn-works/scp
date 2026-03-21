// ScpId.swift — Swift SDK SCPID authentication wrappers (#1059)
//
// Wraps UniFFI SCPID bridge functions for DID-based authentication
// against external services per spec section 3.11.
//
// The bridge functions exchange JSON strings; this wrapper layer
// deserializes them into typed Swift structs for ergonomic consumption.
//
// Provenance: spec section 3.11 (SCPID), ADR-039 (Shared-DID Agent Binding)

import Foundation

// MARK: - Data Types

/// SCPID challenge issued by a relying party (spec section 3.11.2).
///
/// Contains a CSPRNG nonce, audience binding, and validity window.
/// Produced by ``ScpId/challenge(audience:ttl:challengeFn:)`` and consumed
/// by ``ScpId/sign(identity:signingKeyId:challenge:signFn:)`` and
/// ``ScpId/verify(response:challenge:verifyFn:)``.
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
    /// to ``ScpId/sign(identity:signingKeyId:challenge:signFn:)`` and
    /// ``ScpId/verify(response:challenge:verifyFn:)`` without re-serialization.
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
    /// to ``ScpId/verify(response:challenge:verifyFn:)`` without re-serialization.
    public let json: String
}

/// Result of a successful SCPID verification (spec section 3.11.4).
///
/// Returned by ``ScpId/verify(response:challenge:verifyFn:)`` when all
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

// MARK: - Bridge Function Types

/// Namespace for SCPID authentication operations (spec section 3.11).
///
/// Uses the caseless-enum namespace pattern consistent with the Swift SDK.
/// All functions delegate to UniFFI bridge functions and parse their JSON
/// results into typed Swift structs.
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

    /// Default challenge function — delegates to UniFFI
    /// ``scpidChallenge(audience:ttlSeconds:)``.
    public static let defaultChallenge: ChallengeFn = { audience, ttlSeconds in
        try scpidChallenge(audience: audience, ttlSeconds: ttlSeconds)
    }

    /// Default sign function — delegates to UniFFI
    /// ``scpidSign(identity:signingKeyId:challengeJson:)``.
    public static let defaultSign: SignFn = { identity, signingKeyId, challengeJson in
        try scpidSign(identity: identity, signingKeyId: signingKeyId, challengeJson: challengeJson)
    }

    /// Default verify function — delegates to UniFFI
    /// ``scpidVerify(responseJson:challengeJson:)``.
    public static let defaultVerify: VerifyFn = { responseJson, challengeJson in
        try scpidVerify(responseJson: responseJson, challengeJson: challengeJson)
    }

    // MARK: - Public API

    /// Generates an SCPID challenge for the given audience (spec section 3.11.2).
    ///
    /// Creates a challenge with a 32-byte CSPRNG nonce, audience binding,
    /// and validity window based on the TTL.
    ///
    /// - Parameters:
    ///   - audience: URI identifying the relying party.
    ///   - ttl: Time-to-live for the challenge. Defaults to 300 seconds.
    ///     Must be between 1 and 300 seconds.
    ///   - challengeFn: Bridge function override for testing.
    /// - Returns: An ``ScpIdChallenge`` with the challenge fields.
    /// - Throws: ``ScpError`` if the audience is empty or TTL is out of range.
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.2 (Challenge Generation)
    public static func challenge(
        audience: String,
        ttl: TimeInterval = 300,
        challengeFn: ChallengeFn = defaultChallenge
    ) throws -> ScpIdChallenge {
        guard ttl.isFinite, ttl >= 1, ttl <= 300 else {
            throw ScpError.Validation(
                msg: "ttl must be between 1 and 300 seconds",
                code: "SCP-IDENT-1038"
            )
        }
        let ttlSeconds = UInt64(ttl.rounded(.up))
        let json = try challengeFn(audience, ttlSeconds)
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
    ///   - identity: The identity to sign with.
    ///   - signingKeyId: Which key to sign with: `"#active"` or `"#agent"`.
    ///   - challenge: The challenge to sign (from ``challenge(audience:ttl:challengeFn:)``).
    ///   - signFn: Bridge function override for testing.
    /// - Returns: An ``ScpIdResponse`` with the signed response fields.
    /// - Throws: ``ScpError`` if the identity lacks the requested key or signing fails.
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.3 (Response Signing)
    /// - ADR-039 (Shared-DID Agent Binding)
    public static func sign(
        identity: Identity,
        signingKeyId: String,
        challenge: ScpIdChallenge,
        signFn: SignFn = defaultSign
    ) throws -> ScpIdResponse {
        let json = try signFn(identity, signingKeyId, challenge.json)
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
    /// pipeline. A DID resolver must be initialized (via identity creation)
    /// before calling this method.
    ///
    /// - Parameters:
    ///   - response: The signed response to verify.
    ///   - challenge: The original challenge that was signed.
    ///   - verifyFn: Bridge function override for testing.
    /// - Returns: An ``ScpIdAuthentication`` with the verified identity fields.
    /// - Throws: ``ScpError`` if verification fails (expired, signature invalid,
    ///   DID resolution failed, etc.).
    ///
    /// ## Provenance
    ///
    /// - Spec section 3.11.4 (Verification Pipeline)
    public static func verify(
        response: ScpIdResponse,
        challenge: ScpIdChallenge,
        verifyFn: VerifyFn = defaultVerify
    ) throws -> ScpIdAuthentication {
        let json = try verifyFn(response.json, challenge.json)
        let wire = try JSONDecoder().decode(AuthenticationWire.self, from: Data(json.utf8))
        return ScpIdAuthentication(
            did: wire.did,
            signingKeyId: wire.signingKeyId,
            signedAt: wire.signedAt
        )
    }
}
