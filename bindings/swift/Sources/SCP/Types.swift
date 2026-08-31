import Foundation

// Message, OutletDefinition, and other core types are now defined by UniFFI in
// ScpBindings.swift. This file provides additional Swift-idiomatic convenience
// types that do NOT conflict with UniFFI-generated types.

// MARK: - CustodyType

/// The custody backend a caller names to `identityCreate` (section 3.2.2 of
/// the identity spec).
///
/// Section 3.2.2, "The Custody Vocabulary", states two values a caller names
/// when it selects a custody backend, and states that "The vocabulary holds no
/// third value, and a shipped build answers every other string with a typed
/// error." Each case below carries one of those two values.
///
/// `build_key_custody` in `crates/scp-ffi/uniffi/src/bridge.rs` answers
/// every other string with `SCP-VALID-7005`, and that includes `"platform"`,
/// `"software"`, `"file"`, `"platform_managed"`, and `"hardware"`.
///
/// A build carrying the UniFFI bridge's `testing` cargo feature additionally
/// accepts the raw string `"in_memory"`, which reaches the test-only in-memory
/// key store. Section 3.2.2 states that the string is a test-harness
/// affordance and not a value of this vocabulary, so this enum does not spell
/// it: a test that needs it passes the raw string to the bridge, and a shipped
/// build answers it with `SCP-IDENT-1008`.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Section 3.2.2 of the identity spec, "The Custody Vocabulary"
/// - The custody-string and identity-parameter story SCP-294 in
///   `.docs/prds/http-features.json`
public nonisolated enum CustodyType: String, Sendable, CaseIterable {
    /// Selects the on-disk key store SCP implements, which derives an AES-256
    /// key from a passphrase with Argon2id and encrypts each key entry under
    /// AES-256-GCM (`crates/scp-platform/src/file.rs`).
    ///
    /// The bridge reads the passphrase from the `SCP_KEY_PASSPHRASE`
    /// environment variable and answers an unset variable with
    /// `SCP-VALID-7005`.
    case encryptedFile = "encrypted_file"
    /// Selects the operating system's own key store, which SCP reaches through
    /// the platform key-custody callback an SDK consumer supplies.
    ///
    /// `identityCreate` supplies none, so it answers this value with
    /// `SCP-IDENT-1003` and falls back to neither the encrypted key file nor
    /// an in-memory store. Pass a `KeyCustodyProvider` to
    /// `identityCreateWithCustody` to reach the store.
    case osKeystore = "os_keystore"
}

// MARK: - BridgeMode

/// Bridge operating mode (spec section 12.2).
///
/// Determines how a bridge connector relays messages between an external
/// platform and an SCP context.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 12.2 (Bridge Connectors)
/// - ADR-023 (Bridge Connector)
public nonisolated enum BridgeMode: String, Sendable, CaseIterable {
    /// Messages forwarded verbatim. Bridge is a transparent pipe.
    case relay
    /// Bridge controls external-side identity and can act on behalf
    /// of participants.
    case puppet
    /// Bridge exposes a programmatic API rather than a chat interface.
    case api
    /// Both SCP and external participants have equal agency.
    case cooperative
}

// MARK: - ShadowStatus

/// Shadow identity provenance status (spec section 12.2).
///
/// Indicates how a bridged participant's identity was established.
/// Used for trust evaluation.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 12.2 (Bridge Connectors)
public nonisolated enum ShadowStatus: String, Sendable, CaseIterable {
    /// Identity is a shadow -- no verified link to external identity.
    case shadow
    /// External participant has completed identity claim verification.
    case claimed
}

// MARK: - Capability

/// A named capability with a declared ceiling, used for UCAN-based authorization.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
public nonisolated struct Capability: Sendable {
    /// The capability name (e.g., `"messages:write"`, `"context:close"`).
    public let name: String
    /// The ceiling value constraining this capability (e.g., `"*"`, `"read-only"`).
    public let ceiling: String

    /// Memberwise initializer.
    public init(name: String, ceiling: String) {
        self.name = name
        self.ceiling = ceiling
    }

    // MARK: - Canonical capability strings

    /// Canonical protocol capability strings.
    ///
    /// These are the SDK-facing colon-separated forms accepted by
    /// `Capability::new` in Rust (e.g. `"messages:write"`, `"outlet:call:*"`) —
    /// the shape used in context ceilings, role capability lists, and UCAN
    /// capability arrays. Parameterised capabilities are built by
    /// ``outletQuery(_:)`` and ``outletCall(_:)``.
    ///
    /// The pre-rename outlet-prefixed stems (invoke / register / interface) are
    /// deleted with no transitional alias; the protocol hard-rejects them at
    /// construction time (ADR-049 §1).
    public enum Name {
        public static let messagesRead = "messages:read"
        public static let messagesWrite = "messages:write"
        /// Query outlet capability — read-only; never billed.
        public static let outletQueryAll = "outlet:query:*"
        /// Action outlet capability — the outlet may mutate state and may incur cost (billable).
        public static let outletCallAll = "outlet:call:*"
        public static let outletRegister = "outlet:register"
        public static let memberInvite = "member:invite"
        public static let memberRemove = "member:remove"
        public static let roleAssign = "role:assign"
        public static let governancePropose = "governance:propose"
        public static let governanceVote = "governance:vote"
        public static let contextClose = "context:close"
        public static let childContextCreate = "context:child:create"
        public static let outletInterface = "outlet:interface"
        public static let bridging = "bridging"
        public static let mediaVoice = "media:voice"
        public static let mediaVideo = "media:video"
        public static let mediaScreenShare = "media:screen_share"
        public static let memberBan = "member:ban"
        public static let metadataEdit = "metadata:edit"
    }

    /// Builds the capability string for invoking a specific Query (read-only)
    /// outlet. Query outlet capability — read-only; never billed.
    /// Per spec §5.4.2.1 the `outletId` suffix must match
    /// `^[a-z0-9_-]{1,128}$`.
    public static func outletQuery(_ outletId: String) -> String {
        "outlet:query:\(outletId)"
    }

    /// Builds the capability string for invoking a specific Action (mutating)
    /// outlet. Action outlet capability — the outlet may mutate state and may
    /// incur cost (billable). Per spec §5.4.2.1 the `outletId` suffix must
    /// match `^[a-z0-9_-]{1,128}$`.
    public static func outletCall(_ outletId: String) -> String {
        "outlet:call:\(outletId)"
    }
}

// MARK: - TestVector

/// An input/output pair used for outlet conformance testing.
///
/// Mirrors `scp_core::context::outlets::TestVector`. Each vector carries a
/// human-readable description of what it validates, plus the input and
/// expected output as JSON strings.
///
/// This type is a pure Swift convenience type. It does not conflict with any
/// UniFFI-generated type.
///
/// Provenance: spec §7.3.3, ADR-010 (phase-2)
public nonisolated struct TestVector: Sendable {
    /// Human-readable description of what this test vector validates.
    public let description: String
    /// The serialized input value (JSON).
    public let input: String
    /// The expected serialized output value (JSON).
    public let expectedOutput: String

    /// Memberwise initializer.
    public init(description: String, input: String, expectedOutput: String) {
        self.description = description
        self.input = input
        self.expectedOutput = expectedOutput
    }
}
