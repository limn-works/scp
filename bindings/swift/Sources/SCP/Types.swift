import Foundation

// Message, OutletDefinition, and other core types are now defined by UniFFI in
// ScpBindings.swift. This file provides additional Swift-idiomatic convenience
// types that do NOT conflict with UniFFI-generated types.

// MARK: - CustodyType

/// The custody choice a caller passes to
/// ``SCP/identityCreate(custody:)`` and
/// ``SCP/identityCreateWithAgentKey(custody:)``: the custody request
/// vocabulary of spec section 3.2.2.
///
/// Neither method gives the parameter a default: which key store holds a
/// private key decides who can reach that key, so the caller states it. The
/// UniFFI bridge answers every value through one parser
/// (`scp_ffi_common::custody_request`), so each case gets the same answer on
/// every bridge:
///
/// - ``encryptedFile`` creates the identity over the encrypted key file.
/// - ``osKeystore`` names the host key store, which only a `KeyCustodyProvider`
///   reaches, so both methods answer it with `SCP-IDENT-1003`. Pass the
///   provider to ``SCP/identityCreateWithCustody(provider:)``; the identity it
///   returns reports `"os_keystore"` from `custodyType()`.
///
/// The type has no other case. Spec section 3.2.2 makes `in_memory` a
/// testing-build affordance and never a peer of the two request values, so a
/// test reaches the in-memory key store outside this type; a bridge built
/// without the `testing` feature answers the raw string with `SCP-IDENT-1008`.
///
/// A shipped build also refuses every identity creation with `SCP-IDENT-1059`
/// until a production pre-rotation custody backend exists (ADR-062
/// §Decision 6).
///
/// The Kotlin SDK's `works.limn.scp.CustodyType` carries the same cases. This
/// type is a pure Swift type and conflicts with no UniFFI-generated type.
///
/// ## Provenance
///
/// - Spec section 3.2.2 (Custody request vocabulary)
/// - `.docs/standards/sdk-common.md` §Custody request
/// - `.docs/standards/construction.md` (consequential choices are enums;
///   required choices are required)
/// - SCP-294 in `.docs/prds/http-features.json`
public nonisolated enum CustodyType: String, Sendable, CaseIterable {
    /// The encrypted key file at `$HOME/.scp/keys.bin`, sealed with
    /// Argon2id and AES-256-GCM under the passphrase in the
    /// `SCP_KEY_PASSPHRASE` environment variable (spec section 17.8).
    ///
    /// An unset, empty or relative `HOME`, or an unset or empty
    /// `SCP_KEY_PASSPHRASE`, is `SCP-VALID-7001`. A key directory or key file
    /// the process cannot open, including one sealed under another passphrase,
    /// is `SCP-IDENT-1008`.
    case encryptedFile = "encrypted_file"

    /// The host operating system's key store, reached only through a
    /// `KeyCustodyProvider`.
    ///
    /// ``SCP/identityCreate(custody:)`` and
    /// ``SCP/identityCreateWithAgentKey(custody:)`` take no provider, so they
    /// answer this case with `SCP-IDENT-1003`; pass the provider to
    /// ``SCP/identityCreateWithCustody(provider:)``. The value promises that
    /// the keys sit in the host's store and that every use of them goes
    /// through the provider. It promises no hardware backing: the Secure
    /// Enclave performs P-256 operations and no others (ADR-025).
    case osKeystore = "os_keystore"
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
