import Foundation

// MARK: - UcanToken

/// A UCAN (User Controlled Authorization Network) token.
///
/// UCAN tokens are the authorization mechanism in SCP. Every protocol action
/// in a context (message send, tool invocation, member management, role change)
/// requires a valid UCAN token with matching capabilities.
///
/// Tokens use EdDSA (Ed25519) signatures and conform to UCAN specification
/// version 0.10.0. They form delegation chains where capabilities can only
/// be attenuated (narrowed), never widened.
///
/// See ADR-016 in `.docs/adrs/phase-3.md`.
public nonisolated struct UcanToken: Sendable {
    /// The issuer DID -- the entity that created and signed this token.
    public let issuer: String

    /// The audience DID -- the entity this token is delegated to.
    public let audience: String

    /// Expiration time as a Unix timestamp (seconds since epoch).
    public let expiry: UInt64

    /// Optional not-before time as a Unix timestamp. If present, the token
    /// is not valid before this time.
    public let notBefore: UInt64?

    /// Mandatory nonce for replay prevention.
    public let nonce: String

    /// Capabilities granted by this token as resource URI / action pairs.
    public let capabilities: [UcanCapability]

    /// Proof chain -- encoded parent UCAN tokens forming the delegation chain.
    /// Empty for root tokens issued by the context creator.
    public let proofs: [String]

    /// The full encoded JWT string for signature verification.
    public let encoded: String

    /// Memberwise initializer.
    public init(
        issuer: String,
        audience: String,
        expiry: UInt64,
        notBefore: UInt64?,
        nonce: String,
        capabilities: [UcanCapability],
        proofs: [String],
        encoded: String
    ) {
        self.issuer = issuer
        self.audience = audience
        self.expiry = expiry
        self.notBefore = notBefore
        self.nonce = nonce
        self.capabilities = capabilities
        self.proofs = proofs
        self.encoded = encoded
    }
}

// MARK: - UcanCapability

/// A single capability grant within a UCAN token.
///
/// Each capability specifies a resource URI and an action. Resource URIs
/// follow the SCP capability URI format: `scp:ctx:{context_id}/{capability}`.
/// Wildcards are supported: `scp:ctx:*/messages:write` matches any context.
///
/// See ADR-016 acceptance criterion 4.
public nonisolated struct UcanCapability: Sendable {
    /// Resource URI (e.g., `"scp:ctx:abc123/messages:write"`).
    public let resource: String

    /// Action (e.g., `"invoke"`, `"read"`, `"write"`).
    public let action: String

    /// Memberwise initializer.
    public init(resource: String, action: String) {
        self.resource = resource
        self.action = action
    }
}

// MARK: - UcanValidationResult

/// The result of validating a UCAN token.
///
/// Contains the validation outcome and, if valid, the extracted token.
public nonisolated struct UcanValidationResult: Sendable {
    /// Whether the token passed all validation checks.
    public let isValid: Bool

    /// The validated token, if validation succeeded. `nil` if validation failed.
    public let token: UcanToken?

    /// A human-readable reason if validation failed. `nil` if valid.
    public let failureReason: String?

    /// Memberwise initializer.
    public init(isValid: Bool, token: UcanToken?, failureReason: String?) {
        self.isValid = isValid
        self.token = token
        self.failureReason = failureReason
    }
}

// MARK: - UniFFI Bridge Stubs

/// Validate a UCAN token via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `ucan_validate` function.
/// Performs the full 11-step validation pipeline specified in ADR-016.
///
/// - Parameters:
///   - encoded: The JWT-encoded UCAN token string.
///   - contextId: The context ID for capability ceiling checks.
///   - presenterDid: The DID of the agent presenting the token.
///   - completion: Callback delivering the validation result or an error.
internal func scpUcanValidate(
    encoded: String,
    contextId: String,
    presenterDid: String,
    completion: @Sendable @escaping (Result<UcanValidationResult, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.permission(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-UCAN-001"
    )))
}

/// Mint a new UCAN token via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `ucan_mint` function.
///
/// - Parameters:
///   - issuerDid: The DID of the issuer (signer).
///   - audienceDid: The DID of the audience (delegate).
///   - capabilities: The capabilities to grant.
///   - expirySecs: Token lifetime in seconds from now.
///   - proofs: Parent token encodings for delegation chains.
///   - completion: Callback delivering the minted token or an error.
internal func scpUcanMint(
    issuerDid: String,
    audienceDid: String,
    capabilities: [UcanCapability],
    expirySecs: UInt64,
    proofs: [String],
    completion: @Sendable @escaping (Result<UcanToken, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.permission(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-UCAN-002"
    )))
}

/// Revoke a UCAN token via the UniFFI bridge.
///
/// Placeholder stub for the UniFFI-generated `ucan_revoke` function.
///
/// - Parameters:
///   - encoded: The JWT-encoded UCAN token to revoke.
///   - revokerDid: The DID of the revoker (must be issuer or context creator).
///   - completion: Callback delivering success or an error.
internal func scpUcanRevoke(
    encoded: String,
    revokerDid: String,
    completion: @Sendable @escaping (Result<Void, ScpError>) -> Void
) {
    // Placeholder: replaced by UniFFI-generated binding (SCP-103).
    completion(.failure(.permission(
        message: "UniFFI bridge not yet available — build ScpFFI.xcframework (SCP-103)",
        code: "SCP-UCAN-003"
    )))
}

// MARK: - UCAN Public API

/// Validates a UCAN token against the full 11-step validation pipeline.
///
/// The validation checks (per ADR-016):
/// 1. JWT structure (3 base64url segments)
/// 2. Header: `alg` is `EdDSA`, `ucv` is `0.10.0`
/// 3. Ed25519 signature verification
/// 4. Root issuer matches context creator
/// 5. Audience matches presenting agent
/// 6. Expiry within 24-hour maximum
/// 7. Token not expired (`exp > now`)
/// 8. Not-before check (`nbf <= now`)
/// 9. Nonce replay prevention
/// 10. Capability within context ceiling
/// 11. Delegation chain attenuation (capabilities only narrow)
///
/// This function bridges the asynchronous UniFFI `ucan_validate` call to
/// Swift concurrency via `CheckedContinuation`.
///
/// - Parameters:
///   - encoded: The JWT-encoded UCAN token string.
///   - contextId: The context ID for capability ceiling checks.
///   - presenterDid: The DID of the agent presenting the token.
/// - Returns: A ``UcanValidationResult`` indicating whether the token is valid.
/// - Throws: ``ScpError/permission(message:code:)`` if a system error prevents
///   validation (distinct from the token being invalid, which is reported in
///   the result).
///
/// ## Provenance
///
/// - ADR-016 (UCAN) in `.docs/adrs/phase-3.md`
/// - ADR-026 (Swift SDK) in `.docs/adrs/phase-5.md`
/// - Story SCP-101
public func validate(
    encoded: String,
    contextId: String,
    presenterDid: String
) async throws -> UcanValidationResult {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<UcanValidationResult, Error>) in
        scpUcanValidate(
            encoded: encoded,
            contextId: contextId,
            presenterDid: presenterDid
        ) { result in
            switch result {
            case .success(let validationResult):
                continuation.resume(returning: validationResult)
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}

/// Mints a new UCAN token with the specified capabilities.
///
/// Creates a new UCAN token signed by the issuer, delegating the specified
/// capabilities to the audience. The token includes a mandatory nonce for
/// replay prevention and respects the 24-hour maximum expiry window.
///
/// - Parameters:
///   - issuerDid: The DID of the issuer who signs the token.
///   - audienceDid: The DID of the audience who receives the delegation.
///   - capabilities: The capabilities to grant in this token.
///   - expirySecs: Token lifetime in seconds from now (maximum 86,400 / 24 hours).
///   - proofs: Parent UCAN token encodings for delegation chains. Empty for
///     root tokens.
/// - Returns: The minted ``UcanToken``.
/// - Throws: ``ScpError/permission(message:code:)`` if minting fails (e.g.,
///   capability outside ceiling, expiry too long, signing error).
public func mint(
    issuerDid: String,
    audienceDid: String,
    capabilities: [UcanCapability],
    expirySecs: UInt64 = 3_600,
    proofs: [String] = []
) async throws -> UcanToken {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<UcanToken, Error>) in
        scpUcanMint(
            issuerDid: issuerDid,
            audienceDid: audienceDid,
            capabilities: capabilities,
            expirySecs: expirySecs,
            proofs: proofs
        ) { result in
            switch result {
            case .success(let token):
                continuation.resume(returning: token)
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}

/// Revokes a UCAN token.
///
/// Only the token's issuer or the context creator can revoke a token.
/// Revocation is distributed to all context members via MLS and recorded
/// in the context event log.
///
/// - Parameters:
///   - encoded: The JWT-encoded UCAN token to revoke.
///   - revokerDid: The DID of the entity revoking the token.
/// - Throws: ``ScpError/permission(message:code:)`` if the revoker is not
///   authorized or revocation distribution fails.
public func revoke(encoded: String, revokerDid: String) async throws {
    try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        scpUcanRevoke(encoded: encoded, revokerDid: revokerDid) { result in
            switch result {
            case .success:
                continuation.resume()
            case .failure(let error):
                continuation.resume(throwing: error)
            }
        }
    }
}
