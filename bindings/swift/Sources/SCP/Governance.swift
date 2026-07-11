import Foundation

// MARK: - GovernanceActionResult

/// Result of executing a governance action (ADR-031).
///
/// Each case corresponds to one of the 28 governance action outcomes from
/// `scp_core::context::manager::GovernanceActionResult`.
///
/// See `.docs/specs/05-contexts.md` section 5.9 and ADR-031.
public enum GovernanceActionResult: String, Sendable {
    case memberAdded = "MemberAdded"
    case memberRemoved = "MemberRemoved"
    case roleChanged = "RoleChanged"
    case outletRegistered = "OutletRegistered"
    case outletRemoved = "OutletRemoved"
    case ceilingModified = "CeilingModified"
    case contextClosed = "ContextClosed"
    case ttlExtended = "TtlExtended"
    case pruningPolicyModified = "PruningPolicyModified"
    case adminTransferred = "AdminTransferred"
    case signerAdded = "SignerAdded"
    case signerRemoved = "SignerRemoved"
    case thresholdModified = "ThresholdModified"
    case childContextCreated = "ChildContextCreated"
    case outletInterfaceEstablished = "OutletInterfaceEstablished"
    case memberReset = "MemberReset"
    case conflictResolved = "ConflictResolved"
    case contextPromoted = "ContextPromoted"
    case memberSuspended = "MemberSuspended"
    case accessRevoked = "AccessRevoked"
    case accessRestored = "AccessRestored"
    case contentKeysRotated = "ContentKeysRotated"
    case governanceReconfigured = "GovernanceReconfigured"
    case subscriberBanned = "SubscriberBanned"
    case subscriberUnbanned = "SubscriberUnbanned"
    case executed = "Executed"
}

// MARK: - MemberRole

/// Role assigned to a member within a context (spec section 5.5).
///
/// Mirrors `scp_core::context::roles::Role`.
public enum MemberRole: String, Sendable {
    /// Context administrator with full governance capabilities.
    case admin = "Admin"
    /// Moderator with messaging, moderation, and governance proposal capabilities.
    case moderator = "Moderator"
    /// Regular participant with standard capabilities.
    case member = "Member"
    /// Read-only observer with no write capabilities.
    case observer = "Observer"
    /// Custom role defined by context governance.
    case custom = "Custom"

    /// Parse a bridge-layer role string into a ``MemberRole``.
    ///
    /// Falls back to ``custom`` for unrecognised strings.
    public static func fromBridge(_ raw: String) -> MemberRole {
        let normalised = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        return MemberRole(rawValue: normalised)
            ?? MemberRole(rawValue: normalised.capitalized)
            ?? .custom
    }
}

// Phase 4 PR 4 (ADR-048 demolition, #1549): the bridge-closure namespaces
// `ContextLifecycleBridge`, `GovernanceBridge`, `MembershipBridge`, and
// `BroadcastBridge` — whose defaults called `Scp.defaultInstance()` — have
// been deleted. Every governance, membership, lifecycle, and broadcast
// operation dispatches through the ``SCP`` instance stored on the owning
// ``Context`` actor (see ``Context/scp``). This matches the Kotlin SDK
// shape and removes the implicit process-wide façade that ADR-048 demolishes.

// MARK: - Client-side Validation (SCP-297, spec §18.11.9)

/// Maximum content path length in bytes.
private let maxContentPathBytes = 1024

/// Maximum deploy ID length in bytes.
private let maxDeployIdBytes = 128

/// Throws ``ScpError/Validation`` with code `SCP-VALID-7010`.
private func contentPathError(_ message: String) -> ScpError {
    ScpError.Validation(msg: message, code: "SCP-VALID-7010")
}

/// Rejects forbidden single-character patterns in a content path.
private func rejectForbiddenPathChars(_ path: String) throws {
    let forbidden: [(Character, String)] = [
        ("\\", "ContentPath must not contain backslashes"),
        ("%", "ContentPath must not contain percent-encoded bytes"),
        ("?", "ContentPath must not contain query strings ('?')"),
        ("#", "ContentPath must not contain fragments ('#')"),
        ("\0", "ContentPath must not contain null bytes")
    ]
    for (char, msg) in forbidden where path.contains(char) {
        throw contentPathError(msg)
    }
}

/// Returns true for Unicode formatting/invisible characters.
/// Mirrors the Rust `is_unicode_formatting` helper.
private func isUnicodeFormatting(_ codePoint: UInt32) -> Bool {
    switch codePoint {
    case 0x00A0, // NBSP
         0x1680, // Ogham space mark
         0x2000 ... 0x200F, // Typographic spaces (2000-200A) + ZWSP..RLM (200B-200F)
         0x2028 ... 0x2029, // Line/paragraph separators
         0x202A ... 0x202F, // Bidi embedding controls + narrow no-break space
         0x205F, // Medium mathematical space
         0x2060 ... 0x206F, // Word joiner, invisible operators
         0x3000, // Ideographic space
         0xFEFF, // BOM / ZWNBSP
         0xFFFE ... 0xFFFF: // Non-characters
        return true
    default:
        return false
    }
}

/// Returns true if the character is a valid RFC 7230 tchar (minus '%').
private func isMimeTchar(_ scalar: Unicode.Scalar) -> Bool {
    let codePoint = scalar.value
    // ASCII alphanumeric
    if (codePoint >= 0x30 && codePoint <= 0x39) || (codePoint >= 0x41 && codePoint <= 0x5A) || (codePoint >= 0x61 && codePoint <= 0x7A) {
        return true
    }
    // !#$&'*+-.^_`|~
    switch scalar {
    case "!", "#", "$", "&", "'", "*", "+", "-", ".", "^", "_", "`", "|", "~":
        return true
    default:
        return false
    }
}

/// Rejects control characters (U+0000-U+001F, U+007F, U+0080-U+009F) in a content path.
private func rejectPathControlChars(_ path: String) throws {
    for scalar in path.unicodeScalars {
        let codePoint = scalar.value
        // C0 controls, DEL, and C1 controls
        if codePoint <= 0x1F || codePoint == 0x7F || (codePoint >= 0x80 && codePoint <= 0x9F) {
            throw contentPathError(
                "ContentPath must not contain control character U+\(String(format: "%04X", codePoint))"
            )
        }
    }
}

/// Rejects non-ASCII whitespace, bidi, and formatting characters in a content path.
private func rejectPathUnicodeFormatting(_ path: String) throws {
    for scalar in path.unicodeScalars {
        let codePoint = scalar.value
        if codePoint > 0x7F, isUnicodeFormatting(codePoint) {
            throw contentPathError(
                "ContentPath must not contain non-ASCII whitespace/formatting U+\(String(format: "%04X", codePoint))"
            )
        }
    }
}

/// Validates a content path before FFI crossing (SCP-297).
///
/// Mirrors the Rust `ContentPath::new` validation from
/// `crates/scp-core/src/context/broadcast_content.rs`.
///
/// - Parameter path: The content path to validate.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the path is invalid.
func validateContentPath(_ rawPath: String) throws {
    // NFC-normalize before validation (Fix 3)
    let path = rawPath.precomposedStringWithCanonicalMapping
    guard path.hasPrefix("/") else { throw contentPathError("ContentPath must start with '/'") }
    guard path.utf8.count <= maxContentPathBytes else {
        throw contentPathError("ContentPath exceeds \(maxContentPathBytes) bytes")
    }
    try rejectForbiddenPathChars(path)
    try rejectPathControlChars(path)
    try rejectPathUnicodeFormatting(path)
    if path.contains("//") { throw contentPathError("ContentPath must not contain '//'") }
    if path.count > 1, path.hasSuffix("/") {
        throw contentPathError("ContentPath must not have trailing slash (except root '/')")
    }
    for segment in path.split(separator: "/", omittingEmptySubsequences: false).dropFirst() {
        if segment == "." { throw contentPathError("ContentPath must not contain '.' segments") }
        if segment == ".." {
            throw contentPathError("ContentPath must not contain '..' segments (directory traversal)")
        }
    }
}

/// Validates a MIME type before FFI crossing (SCP-297).
///
/// Mirrors the Rust `MimeType::new` validation from
/// `crates/scp-core/src/context/broadcast_content.rs`.
///
/// - Parameter contentType: The MIME type to validate.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the MIME type is invalid.
func validateMimeType(_ contentType: String) throws {
    guard !contentType.isEmpty else {
        throw ScpError.Validation(msg: "MimeType must not be empty", code: "SCP-VALID-7011")
    }
    for scalar in contentType.unicodeScalars {
        let codePoint = scalar.value
        // C0 controls, DEL, and C1 controls
        if codePoint <= 0x1F || codePoint == 0x7F || (codePoint >= 0x80 && codePoint <= 0x9F) {
            throw ScpError.Validation(
                msg: "MimeType must not contain control character U+\(String(format: "%04X", codePoint))",
                code: "SCP-VALID-7011"
            )
        }
    }
    if contentType.contains(";") {
        throw ScpError.Validation(
            msg: "MimeType must not contain parameters (';' not allowed)",
            code: "SCP-VALID-7011"
        )
    }
    let slashCount = contentType.filter { $0 == "/" }.count
    guard slashCount == 1 else {
        throw ScpError.Validation(
            msg: "MimeType must be 'type/subtype' (exactly one '/')",
            code: "SCP-VALID-7011"
        )
    }
    let parts = contentType.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
    if parts.count != 2 || parts[0].isEmpty || parts[1].isEmpty {
        throw ScpError.Validation(
            msg: "MimeType type and subtype must both be non-empty",
            code: "SCP-VALID-7011"
        )
    }
    // RFC 7230 §3.2.6 tchar validation
    if !parts[0].unicodeScalars.allSatisfy({ isMimeTchar($0) }) {
        throw ScpError.Validation(
            msg: "MimeType type part contains invalid characters",
            code: "SCP-VALID-7011"
        )
    }
    if !parts[1].unicodeScalars.allSatisfy({ isMimeTchar($0) }) {
        throw ScpError.Validation(
            msg: "MimeType subtype part contains invalid characters",
            code: "SCP-VALID-7011"
        )
    }
}

/// Validates a deploy ID before FFI crossing (SCP-297).
///
/// Mirrors the Rust `validate_deploy_id` from
/// `crates/scp-core/src/context/broadcast_content.rs`.
///
/// - Parameter deployId: The deploy ID to validate.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the deploy ID is invalid.
func validateDeployId(_ deployId: String) throws {
    guard !deployId.isEmpty else {
        throw ScpError.Validation(msg: "deploy_id must not be empty", code: "SCP-VALID-7012")
    }
    guard deployId.utf8.count <= maxDeployIdBytes else {
        throw ScpError.Validation(
            msg: "deploy_id exceeds \(maxDeployIdBytes) bytes",
            code: "SCP-VALID-7012"
        )
    }
    let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
    guard deployId.unicodeScalars.allSatisfy({ $0.isASCII && allowed.contains($0) }) else {
        throw ScpError.Validation(
            msg: "deploy_id must be ASCII alphanumeric, '-', or '_'",
            code: "SCP-VALID-7012"
        )
    }
}

// MARK: - Context Governance Extensions

public extension Context {
    /// Executes a previously-approved governance proposal BY ID.
    ///
    /// Delegates to the UniFFI ``governanceExecute`` bridge function. The
    /// runtime resolves the authoritative proposal from the context actor's own
    /// quorum-validated governance engine using `proposalIdHex`; the caller
    /// supplies no proposal, action, status, or identity. An untracked /
    /// unapproved id is rejected, so a caller cannot fabricate an approved
    /// proposal. The executor and consequence subject are resolved from the
    /// tracked proposal's proposer.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded id of the approved, tracked proposal.
    /// - Returns: A ``GovernanceActionResult`` describing the outcome.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or governance execution fails.
    func executeGovernanceAction(
        proposalIdHex: String
    ) async throws -> GovernanceActionResult {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2001"
            )
        }

        let raw = try await scp.governanceExecute(
            handle: handle,
            proposalIdHex: proposalIdHex
        )
        return GovernanceActionResult(rawValue: raw) ?? .executed
    }
}

// MARK: - Context Governance Proposal Lifecycle Extensions (#621)

public extension Context {
    /// Proposes a governance action for voting.
    ///
    /// For `SingleAdmin` contexts, the proposal is auto-approved and executed
    /// immediately. For multi-admin models (Threshold, Majority, Unanimity),
    /// the proposal enters `Pending` status and must accumulate votes.
    ///
    /// - Parameters:
    ///   - actionJson: JSON-serialized ``GovernanceAction``.
    ///   - proposerDid: DID of the proposer.
    ///   - proposeFn: Bridge function override for testing.
    /// - Returns: JSON string with `proposal_id`, `status`, and `execution_result`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or the proposal fails.
    func proposeGovernanceAction(
        actionJson: String,
        proposerDid: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2041"
            )
        }

        return try await scp.governancePropose(
            handle: handle, proposerDid: proposerDid, actionJson: actionJson
        )
    }

    /// Casts an approval vote on a pending governance proposal.
    ///
    /// If the vote pushes the proposal past quorum, the action is auto-executed.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - approveFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the vote fails.
    func approveGovernanceProposal(
        proposalIdHex: String,
        voterDid: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2042"
            )
        }

        return try await scp.governanceApprove(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Casts a rejection vote on a pending governance proposal.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - rejectFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the vote fails.
    func rejectGovernanceProposal(
        proposalIdHex: String,
        voterDid: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2043"
            )
        }

        return try await scp.governanceReject(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Withdraws a previously cast vote on a pending governance proposal.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - voterDid: DID of the voter.
    ///   - withdrawFn: Bridge function override for testing.
    /// - Returns: JSON string with `status`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the withdrawal fails.
    func withdrawGovernanceVote(
        proposalIdHex: String,
        voterDid: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2044"
            )
        }

        return try await scp.governanceWithdraw(
            handle: handle, voterDid: voterDid, proposalIdHex: proposalIdHex
        )
    }

    /// Retrieves a governance proposal by hex-encoded ID.
    ///
    /// - Parameters:
    ///   - proposalIdHex: Hex-encoded 32-byte proposal ID.
    ///   - getProposalFn: Bridge function override for testing.
    /// - Returns: JSON string with proposal details.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the proposal is not found.
    func getGovernanceProposal(
        proposalIdHex: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2045"
            )
        }

        return try await scp.governanceGetProposal(handle: handle, proposalIdHex: proposalIdHex)
    }

    /// Lists all governance proposals for this context.
    ///
    /// - Parameter listProposalsFn: Bridge function override for testing.
    /// - Returns: JSON array of proposals.
    /// - Throws: ``ScpError/Context(msg:code:)`` if listing fails.
    func listGovernanceProposals() async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2046"
            )
        }

        return try await scp.governanceListProposals(handle: handle)
    }
}

// MARK: - Context Membership Extensions

public extension Context {
    /// Returns the number of members in this context.
    ///
    /// - Parameter memberCountFn: Bridge function override for testing.
    /// - Returns: The member count, or `nil` if the context is not registered.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func memberCount() async throws -> UInt64? {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.contextMemberCount(handle: handle)
    }

    /// Checks whether a DID is a member of this context.
    ///
    /// - Parameters:
    ///   - did: The DID to check.
    ///   - isMemberFn: Bridge function override for testing.
    /// - Returns: `true` if the DID is a member.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func isMember(
        did: String
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.contextIsMember(handle: handle, did: did)
    }

    /// Returns all member DIDs in this context.
    ///
    /// - Parameter memberDidsFn: Bridge function override for testing.
    /// - Returns: An array of DID strings.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func memberDids() async throws -> [String] {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.contextMemberDids(handle: handle)
    }

    /// Returns the role of a member in this context.
    ///
    /// - Parameters:
    ///   - did: The DID of the member.
    ///   - memberRoleFn: Bridge function override for testing.
    /// - Returns: A ``MemberRole``, or `nil` if the member is not found.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func memberRole(
        did: String
    ) async throws -> MemberRole? {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        guard let raw = await scp.contextMemberRole(handle: handle, did: did) else {
            return nil
        }
        return MemberRole.fromBridge(raw)
    }
}

// MARK: - Context Broadcast Extensions

public extension Context {
    /// Subscribes a DID to this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID subscribing to broadcasts.
    ///   - messagesReadUcanJwt: For a GATED broadcast context, the `messages:read`
    ///     UCAN JWT issued to `subscriberDid` by the context admin/creator (spec
    ///     §5.14.4). Unused for an OPEN context.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastSubscribe(
        subscriberDid: String,
        messagesReadUcanJwt: String? = nil
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.broadcastSubscribe(
            handle: handle,
            subscriberDid: subscriberDid,
            messagesReadUcanJwt: messagesReadUcanJwt
        )
    }

    /// Unsubscribes a DID from this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID to unsubscribe.
    ///   - rotateKeys: When `true`, all authors rotate their broadcast keys.
    ///   - unsubscribeFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastUnsubscribe(
        subscriberDid: String,
        rotateKeys: Bool = false
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.broadcastUnsubscribe(
            handle: handle, subscriberDid: subscriberDid, rotateKeys: rotateKeys
        )
    }

    /// Publishes a message to this broadcast context.
    ///
    /// - Parameters:
    ///   - identity: The identity of the author publishing the message.
    ///   - payload: The raw message payload.
    ///   - publishFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or not a broadcast context.
    func broadcastPublish(
        identity: Identity,
        payload: Data
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.broadcastPublish(handle: handle, identity: identity, payload: payload)
    }

    /// Blocks a subscriber's read access in this broadcast context.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID of the subscriber to block.
    ///   - blockerDid: The DID of the blocker.
    ///   - blockSubscriberFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the operation fails.
    func broadcastBlockSubscriber(
        subscriberDid: String,
        blockerDid: String
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.broadcastBlockSubscriber(
            handle: handle, subscriberDid: subscriberDid, blockerDid: blockerDid
        )
    }

    /// Unblocks a previously blocked subscriber in this broadcast context (§9.16.8).
    ///
    /// Forward-only restoration: the unblocked subscriber can request the
    /// current key on next pull but cannot decrypt content from the block period.
    ///
    /// - Parameters:
    ///   - subscriberDid: The DID of the subscriber to unblock.
    ///   - unblockerDid: The DID of the author performing the unblock.
    ///   - unblockSubscriberFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the operation fails.
    func broadcastUnblockSubscriber(
        subscriberDid: String,
        unblockerDid: String
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.broadcastUnblockSubscriber(
            handle: handle, subscriberDid: subscriberDid, unblockerDid: unblockerDid
        )
    }

    /// Handles a broadcast key request from a subscriber.
    ///
    /// Seals the author's current broadcast key to the requester's 32-byte
    /// X25519 ``wrappingPubkey`` (HPKE, §5.14.2). Returns the JSON of a sealed
    /// broadcast key on grant, or `nil` on deny (§5.14.8 — a denied requester
    /// receives no key material). The subscriber opens the returned JSON with
    /// ``broadcastOpenKey(sealedJson:wrappingSecret:)``.
    ///
    /// - Parameters:
    ///   - authorDid: The DID of the author handling the request.
    ///   - requesterDid: The DID of the requester.
    ///   - wrappingPubkey: The requester's 32-byte X25519 public key.
    /// - Returns: The sealed-broadcast-key JSON on grant, or `nil` on deny.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the operation fails.
    func broadcastHandleKeyRequest(
        authorDid: String,
        requesterDid: String,
        wrappingPubkey: Data
    ) async throws -> String? {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return try await scp.broadcastHandleKeyRequest(
            handle: handle, authorDid: authorDid, requesterDid: requesterDid, wrappingPubkey: wrappingPubkey
        )
    }

    /// Opens an HPKE-sealed broadcast key (§5.14.2).
    ///
    /// Pure crypto: opens the sealed key returned by
    /// ``broadcastHandleKeyRequest(authorDid:requesterDid:wrappingPubkey:)`` on
    /// grant, using the subscriber's 32-byte X25519 ``wrappingSecret``, and
    /// returns the raw 32-byte AES-256 broadcast key.
    ///
    /// - Parameters:
    ///   - sealedJson: The sealed-broadcast-key JSON from a granted request.
    ///   - wrappingSecret: The subscriber's 32-byte X25519 secret.
    /// - Returns: The raw 32-byte AES-256 broadcast key.
    /// - Throws: ``ScpError/Validation(msg:code:)`` if inputs are malformed, or
    ///   ``ScpError/Context(msg:code:)`` if the HPKE open fails.
    func broadcastOpenKey(sealedJson: String, wrappingSecret: Data) throws -> Data {
        try scp.broadcastOpenKey(sealedJson: sealedJson, wrappingSecret: wrappingSecret)
    }

    /// Returns the number of broadcast subscribers for this context.
    ///
    /// - Parameter subscriberCountFn: Bridge function override for testing.
    /// - Returns: The subscriber count, or `nil` if not a broadcast context.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func broadcastSubscriberCount() async throws -> UInt64? {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.broadcastSubscriberCount(handle: handle)
    }

    /// Checks whether a DID is a broadcast subscriber.
    ///
    /// - Parameters:
    ///   - did: The DID to check.
    ///   - isSubscriberFn: Bridge function override for testing.
    /// - Returns: `true` if the DID is a subscriber.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func broadcastIsSubscriber(
        did: String
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.broadcastIsSubscriber(handle: handle, did: did)
    }

    /// Returns the broadcast admission policy for this context.
    ///
    /// - Parameter admissionFn: Bridge function override for testing.
    /// - Returns: The policy (`"Open"` or `"Gated"`), or `nil` if not broadcast.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func broadcastAdmission() async throws -> String? {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.broadcastAdmission(handle: handle)
    }

    /// Publishes a single asset to this broadcast context as structured content (SCP-290).
    ///
    /// Constructs a `BroadcastContent` from the asset entry, computes an `ETag`,
    /// and publishes via the broadcast content delivery layer.
    ///
    /// - Parameters:
    ///   - asset: The asset to publish (path, content type, body).
    ///   - identity: The identity of the author publishing the asset.
    ///     Defaults to the context creator's identity (SCP-294b).
    ///   - deployId: Optional deploy ID to group assets into atomic deploys.
    ///   - publishAssetFn: Bridge function override for testing.
    /// - Returns: A ``PublishResult`` with `blobId` and `etag`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or publishing fails.
    func broadcastPublishAsset(
        asset: AssetEntry,
        identity: Identity? = nil,
        deployId: String? = nil
    ) async throws -> PublishResult {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        // SCP-297: Client-side validation before FFI crossing.
        try validateContentPath(asset.path)
        try validateMimeType(asset.contentType)
        if let id = deployId {
            try validateDeployId(id)
        }

        let resolvedIdentity = identity ?? self.identity
        return try await scp.broadcastPublishAsset(
            handle: handle, identity: resolvedIdentity, asset: asset, deployId: deployId
        )
    }

    /// Publishes multiple assets to this broadcast context as structured content (SCP-290).
    ///
    /// All assets are published with the same deploy ID (auto-generated if not
    /// provided). Returns a list of ``PublishResult`` values.
    ///
    /// - Parameters:
    ///   - assets: The assets to publish.
    ///   - identity: The identity of the author publishing the assets.
    ///     Defaults to the context creator's identity (SCP-294b).
    ///   - deployId: Optional deploy ID to group assets into atomic deploys.
    ///   - publishAssetsFn: Bridge function override for testing.
    /// - Returns: An array of ``PublishResult`` values, one per asset.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or publishing fails. ``ScpError/Validation(msg:code:)``
    ///   if path, contentType, or deployId is invalid (SCP-297).
    func broadcastPublishAssets(
        assets: [AssetEntry],
        identity: Identity? = nil,
        deployId: String? = nil
    ) async throws -> BatchPublishResult {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        // SCP-297: Client-side validation before FFI crossing.
        for asset in assets {
            try validateContentPath(asset.path)
            try validateMimeType(asset.contentType)
        }
        if let id = deployId {
            try validateDeployId(id)
        }

        let resolvedIdentity = identity ?? self.identity
        return try await scp.broadcastPublishAssets(
            handle: handle, identity: resolvedIdentity, assets: assets, deployId: deployId
        )
    }
}

// MARK: - Context Lifecycle Extensions

public extension Context {
    /// Drains all pending events from this context.
    ///
    /// Returns event descriptions as strings. The events are consumed (removed
    /// from the internal queue) by this call.
    ///
    /// - Parameter drainEventsFn: Bridge function override for testing.
    /// - Returns: An array of event description strings.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func drainEvents() async throws -> [String] {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return await scp.contextDrainEvents(handle: handle)
    }

    /// Handles TTL expiry for this context.
    ///
    /// Transitions the context from active to expired, destroying keys per
    /// the context's memory scope policy.
    ///
    /// - Parameter handleTtlExpiryFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func handleTtlExpiry() async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        try await scp.contextHandleTtlExpiry(handle: handle)
        state = .expired
    }

    /// Proposes a TTL extension for this context.
    ///
    /// Records consent from the given member for the proposed extension
    /// duration. Returns `true` when all members have consented (unanimous
    /// approval).
    ///
    /// - Parameters:
    ///   - memberDid: The DID of the member consenting to the extension.
    ///   - proposedSeconds: The proposed TTL extension duration in seconds.
    ///   - proposeTtlExtensionFn: Bridge function override for testing.
    /// - Returns: `true` if all members have consented, `false` otherwise.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not
    ///   active or the member is not found.
    func proposeTtlExtension(
        memberDid: String,
        proposedSeconds: UInt64
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return try await scp.contextProposeTtlExtension(
            handle: handle, memberDid: memberDid, proposedSeconds: proposedSeconds
        )
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Cancels the old timer and spawns a new one with the given duration.
    /// Call this after ``proposeTtlExtension(memberDid:proposedSeconds:proposeTtlExtensionFn:)``
    /// returns `true`.
    ///
    /// - Parameters:
    ///   - newSeconds: The new TTL duration in seconds.
    ///   - resetTtlTimerFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the context is not active.
    func resetTtlTimer(
        newSeconds: UInt64
    ) async throws {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        await scp.contextResetTtlTimer(handle: handle, newSeconds: newSeconds)
    }

    /// Exports this context's full state as serialized bytes.
    ///
    /// Returns the serialized bytes of a `StoredValue<ContextExport>` envelope
    /// (spec section 17.5), suitable for backup, migration, or transfer to
    /// another node.
    ///
    /// - Parameter exportFn: Bridge function override for testing.
    /// - Returns: The serialized context state as `Data`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if export fails.
    func exportContext() async throws -> Data {
        guard state == .active else {
            throw ScpError.Context(msg: "Context is not active", code: "SCP-CTX-2001")
        }

        return try await scp.contextExport(handle: handle)
    }
}

// MARK: - Context Import (free function)

// MARK: - Local DID Management

// MARK: - Ceiling Modification, Close, Checkpoint (#559)

public extension Context {
    /// Applies a pending ceiling modification if the notification period has elapsed.
    ///
    /// - Parameters:
    ///   - currentTimestamp: Current Unix timestamp in seconds.
    ///   - applyFn: Bridge function override for testing.
    /// - Returns: `true` if the modification was applied, `false` otherwise.
    /// - Throws: ``ScpError/Context(msg:code:)`` if the operation fails.
    func applyPendingCeilingModification(
        currentTimestamp: UInt64
    ) async throws -> Bool {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2060"
            )
        }
        return try await scp.applyPendingCeilingModification(
            handle: handle, currentTimestamp: currentTimestamp
        )
    }

    /// Finalizes the cooperative close flow for a context in ``Closing`` state.
    ///
    /// - Parameters:
    ///   - finalizeFn: Bridge function override for testing.
    /// - Throws: ``ScpError/Context(msg:code:)`` if not in Closing state.
    func finalizeClose() async throws {
        try await scp.finalizeClose(handle: handle)
    }

    /// Creates a governance checkpoint (ADR-031 section 9).
    ///
    /// - Parameters:
    ///   - checkpointSeq: Sequence number in the event log.
    ///   - merkleRootHex: Hex-encoded 32-byte Merkle root.
    ///   - eventCount: Number of events included.
    ///   - lastEventHashHex: Hex-encoded 32-byte hash.
    ///   - stateSnapshotHashHex: Hex-encoded 32-byte hash.
    ///   - creatorDid: DID of the creator.
    ///   - creatorSignatureHex: Hex-encoded Ed25519 signature.
    ///   - createFn: Bridge function override for testing.
    /// - Returns: JSON string with the ``ContextCheckpoint`` object.
    /// - Throws: ``ScpError/Context(msg:code:)`` if creation fails.
    func createGovernanceCheckpoint(
        checkpointSeq: UInt64,
        merkleRootHex: String,
        eventCount: UInt64,
        lastEventHashHex: String,
        stateSnapshotHashHex: String,
        creatorDid: String,
        creatorSignatureHex: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2062"
            )
        }
        return try await scp.createGovernanceCheckpoint(
            handle: handle,
            checkpointSeq: checkpointSeq,
            merkleRootHex: merkleRootHex,
            eventCount: eventCount,
            lastEventHashHex: lastEventHashHex,
            stateSnapshotHashHex: stateSnapshotHashHex,
            creatorDid: creatorDid,
            creatorSignatureHex: creatorSignatureHex
        )
    }

    /// Adds a cosignature to an existing governance checkpoint (ADR-031 section 9).
    ///
    /// - Parameters:
    ///   - checkpointJson: JSON-serialized checkpoint.
    ///   - signerDid: DID of the cosigner.
    ///   - signatureHex: Hex-encoded Ed25519 signature.
    ///   - addFn: Bridge function override for testing.
    /// - Returns: JSON string with `attestation_status` and updated `checkpoint`.
    /// - Throws: ``ScpError/Context(msg:code:)`` if cosignature fails.
    func addCheckpointCosignature(
        checkpointJson: String,
        signerDid: String,
        signatureHex: String
    ) async throws -> String {
        guard state == .active else {
            throw ScpError.Context(
                msg: "Context is not active",
                code: "SCP-CTX-2063"
            )
        }
        return try await scp.addCheckpointCosignature(
            handle: handle,
            checkpointJson: checkpointJson,
            signerDid: signerDid,
            signatureHex: signatureHex
        )
    }
}

// MARK: - Participation Requirements (Bridge)

// MARK: - SiteConfig (SCP-293, spec §18.11.12)

/// Node-local site configuration for broadcast projection (spec section 18.11.12).
///
/// Passed to `enableSiteProjection` to configure path-based HTTP serving of
/// broadcast content. NOT part of governance -- deployment concern only.
///
/// Mirrors `scp_node::projection::SiteConfig`.
///
/// ## Provenance
///
/// - Spec section 18.11.12 (Site Projection Configuration)
/// - SCP-293
public struct SiteConfig: Sendable, Equatable {
    /// Virtual host hostname (e.g., `"mysite.example.com"`). RFC 1123 validated.
    public let hostname: String

    /// Default path for directory requests (default: `"/index.html"`).
    public let indexPath: String

    /// Maximum assets per deploy (default: 10,000).
    public let maxAssetsPerDeploy: Int

    /// Maximum total deploy size in bytes (default: 536,870,912 = 512 MiB).
    public let maxDeploySizeBytes: Int64

    /// Number of deploys to retain (default: 2, max 8).
    public let deployRetentionCount: Int

    /// Optional CSP override. Validated: no `unsafe-eval`, `unsafe-inline`,
    /// `unsafe-hashes`, bare `*`, `data:`, `blob:`.
    public let cspOverride: String?

    /// Creates a `SiteConfig` with the given hostname and optional overrides.
    ///
    /// - Parameters:
    ///   - hostname: Virtual host hostname. Must be a valid RFC 1123 DNS name.
    ///   - indexPath: Default path for directory requests.
    ///   - maxAssetsPerDeploy: Maximum assets per deploy.
    ///   - maxDeploySizeBytes: Maximum total deploy size in bytes.
    ///   - deployRetentionCount: Number of deploys to retain (1-8).
    ///   - cspOverride: Optional CSP override string.
    /// - Throws: ``ScpError/Validation(msg:code:)`` if any parameter is invalid.
    public init(
        hostname: String,
        indexPath: String = "/index.html",
        maxAssetsPerDeploy: Int = 10000,
        maxDeploySizeBytes: Int64 = 536_870_912,
        deployRetentionCount: Int = 2,
        cspOverride: String? = nil
    ) throws {
        try SiteConfig.validateHostname(hostname)
        guard maxAssetsPerDeploy > 0 else {
            throw ScpError.Validation(
                msg: "maxAssetsPerDeploy must be >= 1, got \(maxAssetsPerDeploy)",
                code: "SCP-VALID-7020"
            )
        }
        guard maxAssetsPerDeploy <= Int(UInt32.max) else {
            throw ScpError.Validation(
                msg: "maxAssetsPerDeploy must be <= \(UInt32.max)",
                code: "SCP-VALID-7022"
            )
        }
        guard maxDeploySizeBytes > 0 else {
            throw ScpError.Validation(
                msg: "maxDeploySizeBytes must be >= 1, got \(maxDeploySizeBytes)",
                code: "SCP-VALID-7021"
            )
        }
        guard (1 ... 8).contains(deployRetentionCount) else {
            throw ScpError.Validation(
                msg: "deployRetentionCount must be between 1 and 8, got \(deployRetentionCount)",
                code: "SCP-VALID-7140"
            )
        }
        if let csp = cspOverride {
            try SiteConfig.validateCsp(csp)
        }
        self.hostname = hostname
        self.indexPath = indexPath
        self.maxAssetsPerDeploy = maxAssetsPerDeploy
        self.maxDeploySizeBytes = maxDeploySizeBytes
        self.deployRetentionCount = deployRetentionCount
        self.cspOverride = cspOverride
    }

    // MARK: - Hostname Validation

    /// Validates a hostname per RFC 1123.
    ///
    /// - Throws: ``ScpError/Validation(msg:code:)`` if the hostname is invalid.
    static func validateHostname(_ hostname: String) throws {
        guard !hostname.isEmpty else {
            throw ScpError.Validation(msg: "hostname must not be empty", code: "SCP-VALID-7141")
        }
        guard hostname.count <= 253 else {
            throw ScpError.Validation(
                msg: "hostname exceeds 253 characters", code: "SCP-VALID-7142"
            )
        }
        for label in hostname.split(separator: ".", omittingEmptySubsequences: false) {
            let labelStr = String(label)
            guard !labelStr.isEmpty, labelStr.count <= 63 else {
                throw ScpError.Validation(
                    msg: "invalid hostname label: '\(labelStr)'", code: "SCP-VALID-7013"
                )
            }
            guard labelStr.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") })
            else {
                throw ScpError.Validation(
                    msg: "hostname label contains invalid characters: '\(labelStr)'",
                    code: "SCP-VALID-7014"
                )
            }
            guard !labelStr.hasPrefix("-"), !labelStr.hasSuffix("-") else {
                throw ScpError.Validation(
                    msg: "hostname label starts or ends with '-': '\(labelStr)'",
                    code: "SCP-VALID-7015"
                )
            }
        }
    }

    // MARK: - CSP Validation

    /// Validates a CSP override string.
    ///
    /// Rejects `unsafe-eval`, `unsafe-inline`, `unsafe-hashes`, bare `*`,
    /// `data:`, and `blob:` as sources.
    ///
    /// - Throws: ``ScpError/Validation(msg:code:)`` if the CSP is invalid.
    static func validateCsp(_ csp: String) throws {
        let lower = csp.lowercased()
        let forbiddenKeywords = ["unsafe-eval", "unsafe-inline", "unsafe-hashes"]
        for keyword in forbiddenKeywords {
            guard !lower.contains(keyword) else {
                throw ScpError.Validation(
                    msg: "CSP must not contain '\(keyword)'", code: "SCP-VALID-7016"
                )
            }
        }
        for token in lower.split(whereSeparator: { $0.isWhitespace }) {
            let tokenStr = String(token)
            guard tokenStr != "*" else {
                throw ScpError.Validation(
                    msg: "CSP must not contain bare wildcard '*'", code: "SCP-VALID-7017"
                )
            }
            guard tokenStr != "data:" else {
                throw ScpError.Validation(
                    msg: "CSP must not contain 'data:' source", code: "SCP-VALID-7018"
                )
            }
            guard tokenStr != "blob:" else {
                throw ScpError.Validation(
                    msg: "CSP must not contain 'blob:' source", code: "SCP-VALID-7019"
                )
            }
        }
    }
}

// MARK: - Projection Parameter Validation (SCP-296 post-merge audit)

/// Validates an admission policy string before FFI.
///
/// Accepts both casings (`"open"`/`"Open"`, `"gated"`/`"Gated"`) because
/// the Rust bridge normalizes via `.to_lowercase()`.
///
/// - Parameter admission: The admission policy string.
/// - Throws: ``ScpError/Validation(msg:code:)`` if admission is not valid.
public func validateAdmission(_ admission: String) throws {
    let lower = admission.lowercased()
    guard lower == "open" || lower == "gated" else {
        throw ScpError.Validation(
            msg: "admission must be \"open\" or \"gated\" (case-insensitive), got \"\(admission)\"",
            code: "SCP-VALID-7023"
        )
    }
}

/// Validates a broadcast key hex string before FFI.
///
/// Must be exactly 64 hex characters (32 bytes AES-256 key).
///
/// - Parameter broadcastKeyHex: Hex-encoded 32-byte broadcast key.
/// - Throws: ``ScpError/Validation(msg:code:)`` if the string is not valid.
public func validateBroadcastKeyHex(_ broadcastKeyHex: String) throws {
    guard broadcastKeyHex.count == 64,
          broadcastKeyHex.allSatisfy({ $0.isHexDigit }) else {
        throw ScpError.Validation(
            msg: "broadcastKeyHex must be exactly 64 hex characters (32 bytes)",
            code: "SCP-VALID-7024"
        )
    }
}
