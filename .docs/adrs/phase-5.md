# Phase 5 Architecture Decision Records — Bridges, Media, Apple Platform, Swift SDK

**Date:** February 23, 2026
**Phase goal:** Platform bridge infrastructure, real-time media transport, Apple platform, Swift SDK.
**Timeline:** Weeks 17-20
**Dependencies between ADRs:**

```
Phase 1-4 ADRs
       |
       ├── ADR-023 (Bridges) <── ADR-019 (Provenance), ADR-008 (Governance)
       ├── ADR-024 (Media) <── ADR-001 (MLS), ADR-018 (TTL/Ceiling)
       ├── ADR-025 (Apple) <── Phase 1-2 Rust + ADR-021 (UniFFI)
       └── ADR-026 (Swift) <── ADR-021 (UniFFI) + ADR-025 (Apple)
```

Build order: ADR-023 + ADR-024 (parallel, both depend on Phase 1-4) --> ADR-025 (depends on Phase 1-2 Rust + ADR-021) --> ADR-026 (depends on ADR-021 + ADR-025)

---

## ADR-023: Bridge Connector Protocol

**Status:** Decided

### Context

Spec §12 comprehensively specifies bridge architecture. Bridges are protocol entities (not agents) that translate between external platforms and SCP. They have an accountable operator DID, operate in one of four modes, and create shadow identities for external platform participants. All bridged content carries full provenance chain. Shadow claiming via identity attestation enables users to transition from shadow to native SCP identity.

### Decision

Implement bridge support in `scp-core/bridge/`. Bridge connector as registered protocol entity with accountable operator DID. Shadow identities as restricted participants (observer default). Four operating modes (Relay, Puppet, Api, Cooperative). All bridged content carries full provenance chain. Shadow claiming via identity attestation (§3.5) is one-way and irreversible.

### Rationale

- **Protocol entity over agent:** Bridges are not agents — they don't exercise judgment or make decisions. They translate between external platforms and SCP mechanically. Making them a distinct entity type prevents confusion with agents and enforces different trust evaluation (bridges are trusted to translate faithfully, not to act autonomously).
- **Accountable operator DID:** Every bridge has a human operator whose DID is visible in context metadata. This satisfies the "human accountability" protocol tenet — bridged actions trace to the bridge operator, and through the bridge to the external platform participant.
- **Shadow identities over anonymous bridging:** External platform participants don't have SCP identities. Shadow identities give them protocol-level representation (with provenance) rather than attributing everything to the bridge operator. Shadows are restricted by default (observer role) to prevent capability escalation through bridges.
- **One-way claiming:** Once a shadow is claimed (bound to a DID via identity attestation), the binding is permanent. This prevents identity confusion and simplifies attribution — historical actions are retroattributed once and for all.
- **Four modes for different integration depths:** Relay (read-only mirroring), Puppet (bridge acts on behalf of external user), Api (platform API integration), Cooperative (native SCP support on external platform). Each mode has different trust implications visible before opt-in.

### Implementation

- **Language:** Rust
- **Crate:** `scp-core` (bridge protocol types), `scp-bridge/*` (per-platform implementations)
- **Module:** `scp-core/bridge/`

### Dependencies

- **ADR-008 (Context Governance):** Bridge registration requires context governance approval. Bridge revocation is a governance action.
- **ADR-003 (DID/Identity Attestation):** Shadow claiming uses identity attestation (§3.5) to bind external handle to DID.
- **ADR-019 (Data Provenance):** All bridged content carries `BridgeProvenance` extending `DataProvenance`.
- **ADR-011 (Event Log):** Bridge registration, shadow creation, and claiming are context events.

### Acceptance Criteria

1. **Key types:**

```rust
pub struct BridgeConnector {
    pub bridge_id: String,
    pub operator_did: DID,
    pub platform: String,
    pub mode: BridgeMode,
    pub status: BridgeStatus,
    pub registration_context: ContextId,
    pub registered_at: u64,
}

pub enum BridgeMode {
    Relay,        // Read-only mirroring from external platform
    Puppet,       // Bridge acts on behalf of external users
    Api,          // Platform API integration
    Cooperative,  // Native SCP support on external platform
}

pub enum BridgeStatus {
    Active,
    Suspended,
    Revoked,
}

pub struct ShadowIdentity {
    pub shadow_id: String,
    pub platform_handle: String,
    pub bridge_id: String,
    pub attributed_role: String,     // Default: "observer"
    pub provenance_status: ShadowProvenanceStatus,
    pub created_at: u64,
}

pub enum ShadowProvenanceStatus {
    Shadow,   // Unclaimed — attributed via bridge
    Claimed,  // Bound to a DID via identity attestation
}

/// Extension of DataProvenance for bridged content.
pub struct BridgeProvenance {
    pub base: DataProvenance,
    pub originating_platform: String,
    pub bridge_connector_id: String,
    pub operator_did: DID,
    pub bridge_mode: BridgeMode,
    pub shadow_status: ShadowProvenanceStatus,
}

pub struct ClaimRequest {
    pub shadow_id: String,
    pub claimant_did: DID,
    pub platform_handle: String,
    pub identity_attestation: Attestation,  // §3.5 attestation binding handle to DID
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}

pub enum ClaimResult {
    Success { shadow_id: String, claimant_did: DID },
    Failed { reason: ClaimError },
}

pub enum ClaimError {
    HandleMismatch,
    AttestationInvalid,
    AlreadyClaimed,
    ShadowNotFound,
}
```

2. **Bridge registration:**
   - Operator DID presents registration request to context governance.
   - Context governance approves or rejects.
   - Registered bridge visible in context metadata (visible before opt-in, per legibility tenet).
   - Registration is a context event in the Merkle log.

3. **Shadow identity creation:**
   - Bridge creates protocol entity per external platform participant.
   - Shadow carries platform handle, bridge reference, and operating mode.

4. **Shadow default role:**
   - Observer-equivalent with restricted capabilities.
   - Cannot exercise capabilities requiring verified identity.
   - Specific role upgradeable by context governance.

5. **Provenance marking:**
   - All actions/content attributed to shadow identities carry `BridgeProvenance`.
   - `BridgeProvenance` includes: originating platform, bridge connector ID, operator DID, operating mode, shadow/claimed status.
   - No shadow action mistakable for native SCP action.

6. **Trust hierarchy (two axes per §12.5):**
   - Native identity + native transport (strongest).
   - Native identity + bridged transport.
   - Claimed shadow + historical bridged.
   - Shadow + bridged (weakest).
   - Both identity confidence and transport confidence factor into evaluation.

7. **Shadow claiming:**
   - Claimant publishes identity attestation (§3.5) binding external handle to DID.
   - Protocol verifies attestation matches shadow's platform handle.
   - Shadow retired, historical actions retroattributed to claimant DID.

8. **Claiming is one-way and irreversible:**
   - Claimed shadow cannot be unclaimed.
   - Claimed shadow cannot be re-assigned to a different DID.

9. **Bridge revocation:**
   - Context governance removes bridge at any time.
   - Severing bridge disconnects all shadow identities from external platform.
   - Shadows retain their attributed actions but can no longer receive/send.

10. **Context isolation:**
    - Bridge in Context A has zero access to Context B.
    - Same platform bridged into two contexts = two separate bridge instances with separate registrations.

11. **Self-hosted bridges:**
    - Protocol treats self-hosted and managed identically.
    - Self-hosted eliminates third-party credential delegation (puppet mode).

### Scope

**Files (~5):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `BridgeConnector`, `BridgeMode`, `ShadowIdentity`, re-exports |
| `registration.rs` | Bridge registration, governance approval, context metadata integration |
| `shadow.rs` | Shadow identity creation, role management, provenance status |
| `claiming.rs` | `ClaimRequest`, `ClaimResult`, attestation verification, retroattribution |
| `provenance.rs` | `BridgeProvenance`, provenance marking for bridged content |

Per-platform implementations (`scp-bridge/x/`, `scp-bridge/bluesky/`) are separate crates built on these primitives.

**Estimated functions:** ~15 public functions, ~10 internal helpers.

---

## ADR-024: Real-Time Media Transport

**Status:** Decided

### Context

Spec §10.9.1 specifies a delegated media model. SCP governs membership, signaling, and key material. WebRTC handles actual media transport. This separation means contexts support voice/video without the protocol becoming a media transport. The key insight: MLS already provides a secure group key agreement mechanism. MLS key export (RFC 9420 §8) derives DTLS-SRTP keys for WebRTC, binding media session security to context group membership.

### Decision

Implement `scp-media/` crate. Delegated model: context provides identity + trust + governance + MLS-derived key material. Media flows over WebRTC/DTLS-SRTP. Signaling (SDP offers/answers, ICE candidates) goes through SCP as standard encrypted governed messages. No media data touches SCP relays.

### Rationale

- **Delegated over integrated:** SCP is a social protocol, not a media transport. Building media routing into SCP relays would make relays complex, high-bandwidth, and expensive. Delegating to WebRTC (purpose-built for media) keeps SCP relays as simple dumb pipes for encrypted messages.
- **MLS key export for media security:** MLS provides `exporter()` (RFC 9420 §8) which derives application-specific keys from the group state. Using this for DTLS-SRTP means media session keys are cryptographically bound to context membership — only current epoch members can derive them. Member removal triggers MLS epoch advance, which automatically invalidates prior media keys.
- **Signaling as governed messages:** SDP offers, answers, and ICE candidates flow as standard SCP messages — encrypted, authenticated, governed by context, recorded in event log. This means media session initiation is subject to the same capability checks as any other context action.
- **No media through relays:** Media frames flow peer-to-peer or through WebRTC SFU (Selective Forwarding Unit) using DTLS-SRTP. SCP relays never see or route media data. This keeps relay requirements minimal and avoids bandwidth costs.

### Implementation

- **Language:** Rust
- **Crate:** `scp-media`
- **WebRTC:** Platform-specific integration (webrtc-rs for native, browser WebRTC API for WASM)

### Dependencies

- **ADR-001 (MLS):** MLS key export (RFC 9420 §8) derives media session keys.
- **ADR-008 (Context Lifecycle/Capability Ceiling):** Media session initiation requires `media.*` capability in context ceiling.
- **ADR-009 (Roles/Capability Ceiling):** Media capabilities checked against context ceiling before session start.

### Acceptance Criteria

1. **Key types:**

```rust
pub struct MediaSession {
    pub session_id: String,
    pub context_id: ContextId,
    pub participants: Vec<DID>,
    pub capabilities: Vec<MediaCapability>,
    pub state: MediaSessionState,
    pub started_at: u64,
}

pub enum MediaCapability {
    Voice,        // maps to ceiling entry media.voice
    Video,        // maps to ceiling entry media.video
    ScreenShare,  // maps to ceiling entry media.screenShare
}

pub enum MediaSessionState {
    Initiating,
    Active,
    Ended,
}

pub enum SignalingMessage {
    Offer(SessionDescription),
    Answer(SessionDescription),
    IceCandidate(Candidate),
    SessionEnd,
}

pub struct SessionDescription {
    pub sdp: String,
    pub sender_did: DID,
}

pub struct Candidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub sender_did: DID,
}

pub struct MediaKeyMaterial {
    pub dtls_srtp_keys: Vec<u8>,
    pub epoch: u64,
    pub context_id: ContextId,
}
```

2. **MLS key export:**
   - Derive media session keys via MLS exporter (RFC 9420 §8, spec §10.9.1).
   - Keys are bound to context group state — only current epoch members can derive.
   - `export_media_keys(mls_group, label, context, length) -> MediaKeyMaterial`.

3. **Epoch-based key invalidation:**
   - Only current MLS group members can derive media keys.
   - Member removal triggers MLS epoch advance which invalidates prior media keys.
   - Receivers must re-derive keys after each epoch advance.

4. **Capability ceiling check:**
   - Media session initiation requires corresponding `media.*` capability in context ceiling.
   - `check_media_capability(context, capability) -> Result<(), MediaError>`.
   - Rejected if ceiling doesn't include the requested media type.

5. **Signaling via SCP messages:**
   - SDP offers/answers and ICE candidates flow as standard SCP messages.
   - Encrypted, authenticated, governed by context, recorded in event log.
   - Signaling messages use a dedicated `MessageType::Signaling` variant.

6. **Session teardown:**
   - Member removal from context invalidates their media session keys via MLS epoch advance.
   - Explicit `SessionEnd` message for graceful teardown.
   - `end_media_session(session_id) -> Result<(), MediaError>`.

7. **No media through SCP relays:**
   - Media frames flow peer-to-peer or through WebRTC SFU using DTLS-SRTP with MLS-derived keys.
   - SCP relays handle only signaling messages (small, infrequent).

8. **Session metadata in event log:**
   - Participants, start time, end time, capabilities used recorded in context event log.
   - Used for behavioral record derivation (ADR-017).

### Scope

**Files (~4):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `MediaSession`, `MediaCapability`, `SignalingMessage`, re-exports |
| `keys.rs` | `export_media_keys`, `MediaKeyMaterial`, MLS exporter integration |
| `session.rs` | Session lifecycle: initiate, join, end. Capability ceiling checks |
| `signaling.rs` | `SessionDescription`, `Candidate`, signaling message construction and routing |

WebRTC library integration is platform-specific (webrtc-rs for native, browser WebRTC API for WASM).

**Estimated functions:** ~12 public functions, ~8 internal helpers.

---

## ADR-025: Apple Platform Adapter

**Status:** Pending

### What This ADR Will Decide

Platform-specific implementations for iOS/macOS: Secure Enclave key custody, Apple Keychain integration, App Attest device attestation, APNs push notification delivery, and iOS-specific storage encryption (NSFileProtection).

### Blockers

- Phase 1-2 Rust core must be implemented — platform adapters implement traits defined in `scp-platform/`.
- ADR-021 (UniFFI) must define the FFI bridge — platform adapters are called through UniFFI from Swift.
- ADR-006 platform trait definitions must be finalized (`KeyCustody`, `PushProvider`, `DeviceAttestation`).

### Required Inputs When Writing

- Final `KeyCustody` trait signature (async methods, error types).
- Final `PushProvider` trait signature (registration, token refresh, opaque payload format).
- Final `DeviceAttestation` trait signature (attestation request, verification).
- Secure Enclave capability constraints: P-256 only (Ed25519 keys are software-backed in Keychain).
- APNs payload size limits and opacity requirements (§10.7).
- NSFileProtection level selection for SQLite database.

### References

- §17.8 — Platform-specific key custody table (Secure Enclave for P-256, Keychain for Ed25519).
- §9.12 — Compromise recovery protocol (6 steps including Secure Enclave verification).
- §9.15 — Key destruction verification (three trust levels, hardware-attested strongest).
- §10.7 — Push notification opacity requirement.
- `scaffold/swift.md` — XCFramework build, target slices, SPM package structure.
- `standards/swift.md` — iOS 17+, macOS 14+, Swift 6 concurrency.
- ADR-006 — Platform abstraction traits (in-memory implementations).

### Expected Decisions

- **Secure Enclave usage pattern:** Which operations use SE (P-256 signing for attestation), which use Keychain (Ed25519 identity keys, X25519 key agreement).
- **Keychain access groups and protection classes.**
- **APNs payload format:** How to satisfy §10.7 opacity while triggering the right notification behavior.
- **App Attest integration:** Attestation flow, server-side verification, fraud metric handling.
- **NSFileProtection level:** `completeUntilFirstUserAuthentication` (allows background processing) vs `complete` (stronger but breaks background refresh).
- **StrongBox opt-in policy:** Available but dramatically slow — when to use.

### Optimal Approach

Write after Phase 2 implementation stabilizes. Build the in-memory platform adapter (ADR-006) first, then implement Apple-specific versions. Test against real devices — Secure Enclave behavior differs between simulator and hardware.

### Scope

`scp-platform/apple/` — ~5 files, ~20 functions.

---

## ADR-026: Swift SDK

**Status:** Decided

### Context

The UniFFI bridge (ADR-021) generates raw Swift bindings from the Rust protocol engine. While functional, the generated surface is not idiomatic Swift — it lacks actor isolation, `AsyncSequence` streams, the `@Observable` macro, and the ergonomic patterns Swift developers expect. The Apple platform adapter (ADR-025) provides the `KeyCustody`, `PushProvider`, `Storage`, and `DeviceAttestationProvider` implementations injected into the Rust engine via UniFFI callback interfaces.

The Swift SDK ergonomics layer wraps the generated bindings to produce an idiomatic Swift API that feels native to the platform: `async/await` throughout, actor-isolated state, structured concurrency with `AsyncStream<Message>`, `@Observable` for SwiftUI, and `deinit`-safe resource cleanup. The ergonomics layer is pure Swift — zero protocol logic, zero duplication of Rust behavior. This mirrors the ADR-014 (Python SDK) pattern: flat FFI bridge → idiomatic language wrapper.

Swift 6.2 with `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` is the baseline, making `@MainActor` the default. Types that need to operate off the main actor (background crypto, streaming) explicitly opt out.

### Decision

Implement the Swift SDK as the `SCP` Swift package at `bindings/swift/`. The package imports `ScpFFI.xcframework` (UniFFI-generated binary), re-exports it through `Sources/SCP/Internal/ScpBindings.swift`, and builds a pure Swift ergonomics layer in `Sources/SCP/`. The top-level entry point is `SCP` — an actor that initializes the identity and injects the Apple platform adapter. `SCPContext` is the primary interactive type — an actor exposing `AsyncStream<Message>` for streaming and a `close()` / `deinit` lifecycle.

Actor isolation follows the Swift 6.2 approachable concurrency rules: data carrier types (`Message`, `DIDDocument`, `ToolDefinition`) are `nonisolated struct` and `Sendable` by definition. Interactive types (`SCP`, `SCPContext`, `SCPIdentity`) are custom actors. `SCPEventLog` and `SCPTransport` are `nonisolated` since they have no mutable state after construction. `SwiftUI` observation uses `@Observable` for SCP state containers (Swift 5.9+). Streaming uses `AsyncStream<Message>` (not Combine) — the right choice for Swift 6 structured concurrency. The SPM package is configured as a binary framework target with XCFramework checksum verification.

### Rationale

- **Actor isolation over `@MainActor` default for interactive types:** `SCP` and `SCPContext` manage mutable protocol state (MLS group, sender keys, connection handles). Custom actors enforce serial access to this state without blocking the main thread. `@MainActor` would block UI updates during crypto operations — wrong for any non-trivial workload.
- **`AsyncStream<Message>` over Combine:** Swift 6 strict concurrency treats Combine as a compatibility layer, not the forward path. `AsyncStream` integrates naturally with `for await` loops, structured concurrency cancellation, and `TaskGroup`. It requires zero imported frameworks and works identically on iOS, macOS, and in Swift package tests. Combine's `Publisher` → `AsyncSequence` bridging adds indirection without benefit.
- **`@Observable` for SwiftUI state:** The `@Observable` macro (Swift 5.9+, iOS 17+) tracks property access at the granularity of individual properties rather than the whole object. This means `SCPContextState` annotated with `@Observable` triggers minimal view updates when only `memberCount` changes, not when `lastMessage` changes. Property wrappers like `@Published` (Combine) are legacy in this context.
- **`deinit` + explicit `close()` for resource cleanup:** SCP contexts hold live crypto state (MLS group keys, sender AES-256 keys) that must be zeroed on deallocation. `close()` is the user-visible method for graceful teardown (leave the MLS group, flush the event log, close the transport connection). `deinit` is the safety net — it schedules a `Task { try? await close() }` to prevent resource leaks when a context object is dropped without explicit close. This matches the `Symbol.asyncDispose` pattern in the TypeScript SDK.
- **`nonisolated struct` for DTOs:** Data carrier types (`Message`, `DIDDocument`, `ToolDefinition`, `Provenance`) are value types with no mutable state after construction. Marking them `nonisolated struct` makes all members inherit nonisolated context, satisfying Swift 6 `Sendable` without `@unchecked Sendable`. They cross actor boundaries freely as `Sendable` values.
- **`SCP.create()` as async factory, not `init`:** The identity initialization path (`identity_create()`) is async (involves key generation and DID registration). Swift actors cannot have `async init`. The factory pattern `await SCP.create()` is the idiomatic solution. `ApplePlatformAdapter.make()` is injected at creation time — the caller controls custody.
- **SPM binary framework target:** XCFramework binary distribution via SPM `binaryTarget` with checksum verification gives consumers a single `Package.swift` dependency with no Rust toolchain requirement. Swift compiler verifies the binary against the declared checksum on resolution.
- **Flat delegation pattern — no logic in Swift:** Every Swift SDK method calls exactly one UniFFI bridge function. Zero protocol logic lives in the Swift layer. This prevents divergence between the Rust engine and the Swift surface and ensures one implementation of every operation.

### Implementation

**Language:** Swift 6.2+

**Package:** `bindings/swift/` published as `SCP` Swift package via GitHub releases.

**Dependencies from UniFFI:** `identity_create()`, `identity_load()`, `identity_resolve()`, `context_create()`, `context_join()`, `context_leave()`, `context_close()`, `context_send()`, `context_subscribe()` (callback interface), `tool_register()`, `tool_invoke()`, `tool_verify()`, `ucan_validate()`, `ucan_mint()`, `ucan_revoke()`, `event_log_query()`, `event_log_verify()`, `transport_connect()`, `transport_status()`, and the `ScpError` enum — all from `ScpBindings.swift`.

**File layout:**

```
bindings/swift/
  Package.swift                       # SPM package definition (binary + source targets)
  Sources/
    SCP/
      SCP.swift                       # SCP actor — top-level entry point, identity + transport init
      Identity.swift                  # SCPIdentity actor, DIDDocument struct
      Context.swift                   # SCPContext actor, AsyncStream<Message>, lifecycle
      Tools.swift                     # ToolDefinition, TestVector, ToolVerificationResult structs
      Trust.swift                     # evaluateTrust(), TrustEvaluation struct
      EventLog.swift                  # SCPEventLog class (nonisolated), Event, Proof, Checkpoint
      Transport.swift                 # TransportConfig struct, transport connection helpers
      Types.swift                     # Message, Provenance, Capability, ContextParams (nonisolated structs)
      Errors.swift                    # ScpError enum (mirrors UniFFI ScpError), LocalizedError conformance
      Ucan.swift                      # UCAN validate(), mint(), revoke() (nonisolated free functions)
      Mcp.swift                       # serveMcp(), McpClient
      Platform/
        AppleKeyCustody.swift         # KeyCustodyProvider implementation (Keychain + Secure Enclave)
        AppleDeviceAttestation.swift  # DeviceAttestationProvider (DCAppAttestService)
        ApplePushProvider.swift       # PushProvider (APNs)
        AppleStorage.swift            # StorageProvider (Core Data / file-based)
        PlatformAdapter.swift         # ApplePlatformAdapter.make() factory
      Internal/
        ScpBindings.swift             # UniFFI-generated bindings (auto-generated, do not edit)
  Tests/
    SCPTests/
      IdentityTests.swift
      ContextTests.swift
      ToolsTests.swift
      UcanTests.swift
      TransportTests.swift
      EventLogTests.swift
      McpTests.swift
      Conformance/
        ConformanceTests.swift        # Cross-language conformance test suite
```

**Package.swift:**

```swift
// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SCP",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "SCP", targets: ["SCP"]),
    ],
    targets: [
        .binaryTarget(
            name: "ScpFFI",
            url: "https://github.com/limn/scp-swift/releases/download/0.1.0/ScpFFI.xcframework.zip",
            checksum: "<sha256-checksum>"
        ),
        .target(
            name: "SCP",
            dependencies: ["ScpFFI"],
            path: "Sources/SCP",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),
        .testTarget(
            name: "SCPTests",
            dependencies: ["SCP"],
            path: "Tests/SCPTests"
        ),
    ]
)
```

**`SCP` actor — top-level entry point:**

```swift
/// Top-level SCP SDK entry point. Initialize once per process.
public actor SCP {
    public let identity: SCPIdentity

    private init(identity: SCPIdentity) {
        self.identity = identity
    }

    /// Create an SCP instance with the specified custody method.
    /// On Apple platforms, `custody: .platform` uses Keychain-backed key storage.
    /// `custody: .inMemory` uses software keys (testing only).
    public static func create(custody: CustodyMethod = .platform) async throws -> SCP {
        let adapter: ApplePlatformAdapter?
        if custody == .platform {
            adapter = try ApplePlatformAdapter.make()
        } else {
            adapter = nil
        }
        let handle = try await identity_create(
            custody: custody.rawValue,
            keyCustody: adapter?.keyCustody,
            storage: adapter?.storage,
            pushProvider: adapter?.pushProvider,
            deviceAttestation: adapter?.deviceAttestation
        )
        let identity = SCPIdentity(handle: handle)
        return SCP(identity: identity)
    }

    /// Create a new context.
    public func createContext(params: ContextParams) async throws -> SCPContext {
        let handle = try await context_create(identity: identity.handle, params: params.toRecord())
        return SCPContext(handle: handle)
    }

    /// Join an existing context by ID.
    public func joinContext(id: String) async throws -> SCPContext {
        let handle = try await context_join_by_id(identity: identity.handle, contextId: id)
        return SCPContext(handle: handle)
    }
}
```

**`SCPIdentity` actor:**

```swift
/// An SCP identity (DID). Holds the signing key handle — never exposes private key bytes.
public actor SCPIdentity {
    public let did: String
    public let custodyType: String

    internal let handle: IdentityHandle

    internal init(handle: IdentityHandle) {
        self.did = handle.did()
        self.custodyType = handle.custodyType()
        self.handle = handle
    }

    /// Load an existing identity from storage.
    public static func load(did: String) async throws -> SCPIdentity {
        let handle = try await identity_load(did: did)
        return SCPIdentity(handle: handle)
    }

    /// Resolve another identity's DID document.
    public func resolve(did: String) async throws -> DIDDocument {
        let record = try await identity_resolve(did: did)
        return DIDDocument(from: record)
    }

    /// Rotate this identity's signing key. Returns an updated identity.
    public func rotateKey() async throws -> SCPIdentity {
        let handle = try await identity_rotate_key(identity: self.handle)
        return SCPIdentity(handle: handle)
    }
}
```

**`SCPContext` actor:**

```swift
/// An active SCP context. Send messages, receive streams, invoke tools.
/// Always `close()` when done. `deinit` schedules close as a safety net.
public actor SCPContext {
    public let contextId: String
    public private(set) var state: ContextState

    private let handle: ContextHandle
    private var streamContinuation: AsyncStream<Message>.Continuation?

    internal init(handle: ContextHandle) {
        self.contextId = handle.contextId()
        self.state = ContextState(rawValue: handle.state()) ?? .active
        self.handle = handle
    }

    deinit {
        // Safety net: schedule close if caller forgot to call it explicitly.
        // `try?` intentionally suppresses errors in the deinit path.
        let h = handle
        Task { try? await context_close(handle: h) }
    }

    /// Send a message to this context.
    public func send(_ payload: Data) async throws {
        guard state == .active else { throw ScpError.context(message: "Context is not active", code: "SCP-CTX-001") }
        try await context_send(handle: handle, payload: payload)
    }

    /// AsyncStream of incoming messages. Yields until the context closes.
    public var messages: AsyncStream<Message> {
        AsyncStream { continuation in
            self.streamContinuation = continuation
            context_subscribe(handle: handle, listener: MessageListenerAdapter(continuation: continuation))
        }
    }

    /// Invoke a registered tool in this context.
    public func invoke(tool: String, input: Data) async throws -> Data {
        let output = try await tool_invoke(handle: handle, toolId: tool, inputJson: input)
        return output
    }

    /// Register a tool in this context. Returns the assigned tool ID.
    public func registerTool(_ definition: ToolDefinition) async throws -> String {
        try await tool_register(handle: handle, registration: definition.toRecord())
    }

    /// Leave this context gracefully.
    public func leave() async throws {
        try await context_leave(handle: handle, identity: nil)
        state = .closed
    }

    /// Close this context (admin only). Terminates the context for all members.
    public func close() async throws {
        try await context_close(handle: handle)
        state = .closed
        streamContinuation?.finish()
        streamContinuation = nil
    }
}

/// Adapts the UniFFI `MessageListener` callback interface to `AsyncStream.Continuation`.
private final class MessageListenerAdapter: MessageListener, @unchecked Sendable {
    private let continuation: AsyncStream<Message>.Continuation

    init(continuation: AsyncStream<Message>.Continuation) {
        self.continuation = continuation
    }

    func onMessage(message: ScpMessage) {
        continuation.yield(Message(from: message))
    }

    func onError(error: ScpError) {
        continuation.finish()
    }

    func onComplete() {
        continuation.finish()
    }
}
```

**Error hierarchy:**

```swift
/// Swift error enum mirroring the UniFFI ScpError variants.
/// Conforms to LocalizedError for SwiftUI and system error presentation.
public enum ScpError: Error, Sendable {
    case identity(message: String, code: String)
    case context(message: String, code: String)
    case permission(message: String, code: String)
    case crypto(message: String, code: String)
    case transport(message: String, code: String)
    case tool(message: String, code: String)
    case validation(message: String, code: String)
}

extension ScpError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .identity(let message, _): return message
        case .context(let message, _): return message
        case .permission(let message, _): return message
        case .crypto(let message, _): return message
        case .transport(let message, _): return message
        case .tool(let message, _): return message
        case .validation(let message, _): return message
        }
    }

    public var errorCode: String {
        switch self {
        case .identity(_, let code): return code
        case .context(_, let code): return code
        case .permission(_, let code): return code
        case .crypto(_, let code): return code
        case .transport(_, let code): return code
        case .tool(_, let code): return code
        case .validation(_, let code): return code
        }
    }
}

/// Maps UniFFI-generated ScpError to the Swift SDK ScpError.
extension ScpError {
    init(from ffiError: ScpBindings.ScpError) {
        switch ffiError {
        case .identity(let message, let code): self = .identity(message: message, code: code)
        case .context(let message, let code): self = .context(message: message, code: code)
        case .permission(let message, let code): self = .permission(message: message, code: code)
        case .crypto(let message, let code): self = .crypto(message: message, code: code)
        case .transport(let message, let code): self = .transport(message: message, code: code)
        case .tool(let message, let code): self = .tool(message: message, code: code)
        case .validation(let message, let code): self = .validation(message: message, code: code)
        }
    }
}
```

**Data carrier types (`nonisolated struct`, `Sendable`):**

```swift
/// An incoming SCP message. Sendable value type — safe to pass across actor boundaries.
public nonisolated struct Message: Sendable {
    public let senderDid: String
    public let content: Data
    public let timestamp: TimeInterval
    public let sequence: Int64
    public let contextId: String
    public let provenance: Provenance?

    init(from record: ScpMessage) {
        self.senderDid = record.senderDid
        self.content = record.content
        self.timestamp = TimeInterval(record.timestamp) / 1000.0
        self.sequence = record.sequence
        self.contextId = record.contextId
        self.provenance = record.provenance.map(Provenance.init(from:))
    }
}

/// Context creation parameters.
public nonisolated struct ContextParams: Sendable {
    public let ceiling: [String]
    public let tools: [ToolDefinition]
    public let governance: GovernanceModel
    public let ttl: TimeInterval?
    public let memoryScope: MemoryScope

    public init(
        ceiling: [String],
        tools: [ToolDefinition] = [],
        governance: GovernanceModel = .singleAdmin,
        ttl: TimeInterval? = nil,
        memoryScope: MemoryScope = .full
    ) {
        self.ceiling = ceiling
        self.tools = tools
        self.governance = governance
        self.ttl = ttl
        self.memoryScope = memoryScope
    }
}

/// A registered SCP tool definition.
public nonisolated struct ToolDefinition: Sendable {
    public let name: String
    public let description: String
    public let inputSchema: String      // JSON Schema string
    public let outputSchema: String     // JSON Schema string
    public let operatorDid: String
    public let testVectors: [TestVector]?
    public let implementationHash: Data?
}

/// A DID document resolved from the DID network.
public nonisolated struct DIDDocument: Sendable {
    public let did: String
    public let verificationMethods: [VerificationMethod]
    public let services: [ServiceEndpoint]
    public let resolvedAt: TimeInterval
}
```

**SwiftUI `@Observable` state container:**

```swift
/// SwiftUI-observable state container for an SCP context.
/// Use this as the `@State` in a view that displays context data.
@Observable
public final class SCPContextState: @unchecked Sendable {
    public private(set) var messages: [Message] = []
    public private(set) var memberCount: Int = 0
    public private(set) var isActive: Bool = false

    private var streamTask: Task<Void, Never>?

    /// Attach this state container to a live context. Begins streaming messages.
    public func attach(to context: SCPContext) {
        isActive = true
        streamTask = Task { [weak self] in
            for await message in await context.messages {
                guard let self else { break }
                self.messages.append(message)
            }
            self?.isActive = false
        }
    }

    deinit {
        streamTask?.cancel()
    }
}
```

**UCAN free functions (nonisolated):**

```swift
/// Validate a UCAN token for a capability in a context.
/// Throws `ScpError.permission` if the token is invalid or the capability is not granted.
public func validateUcan(token: String, capability: String, contextId: String) async throws {
    try await ucan_validate(token: token, capability: capability, contextId: contextId)
}

/// Mint a UCAN token delegating capabilities to a member DID.
public func mintUcan(
    identity: SCPIdentity,
    memberDid: String,
    capabilities: [String]
) async throws -> String {
    try await ucan_mint(identity: identity.handle, memberDid: memberDid, capabilities: capabilities)
}

/// Revoke a previously minted UCAN token.
public func revokeUcan(identity: SCPIdentity, tokenId: String) async throws {
    try await ucan_revoke(identity: identity.handle, tokenId: tokenId)
}
```

**Async bridging pattern — `CheckedContinuation`:**

UniFFI generates Swift `async` functions directly for all `async fn` bridge functions. The `CheckedContinuation` pattern is used only when wrapping the `context_subscribe` callback interface (which is callback-based, not async-return):

```swift
// Internal: wrap the UniFFI callback subscription in an AsyncStream.
// AsyncStream.Continuation is the Swift-native equivalent of CheckedContinuation for streams.
private func makeMessageStream(handle: ContextHandle) -> AsyncStream<Message> {
    AsyncStream { continuation in
        let listener = MessageListenerAdapter(continuation: continuation)
        context_subscribe(handle: handle, listener: listener)
        continuation.onTermination = { _ in
            // Cancellation propagates to the Rust subscription automatically
            // when the MessageListenerAdapter is deallocated.
        }
    }
}
```

### Dependencies

- **ADR-021 (UniFFI Bridge):** The Swift SDK wraps the UniFFI-generated `ScpBindings.swift` and `ScpFFI.xcframework`. Every SDK public method calls exactly one UniFFI bridge function. The bridge defines the flat function surface (`identity_create`, `context_create`, etc.), opaque object handles (`IdentityHandle`, `ContextHandle`), value records (`ScpMessage`, `ContextParams`), the `ScpError` enum, and the `MessageListener` callback interface.
- **ADR-025 (Apple Platform Adapter):** The `ApplePlatformAdapter` (implemented in ADR-025) is instantiated by `SCP.create(custody: .platform)` and injected into the Rust engine via UniFFI callback interfaces (`KeyCustodyProvider`, `StorageProvider`, `PushProvider`, `DeviceAttestationProvider`). The Swift SDK depends on the `Platform/` files being present in `Sources/SCP/Platform/`.
- **ADR-006 (Platform Abstraction):** Platform trait definitions (`KeyCustody`, `PushProvider`, `Storage`, `DeviceAttestationProvider`) shape the UniFFI callback interface contracts that the Swift SDK implements.
- **ADR-013 (PyO3 Bridge) / ADR-014 (Python SDK):** The ergonomics layer pattern — flat FFI bridge → idiomatic language wrapper — is established here and applied to Swift. Swift SDK mirrors the structural choices (no logic in the wrapper layer, delegation only) and the type category decisions (opaque handles for crypto state, value types for data).
- **ADR-022 (TypeScript SDK):** Parallel patterns: `AsyncStream<Message>` (Swift) mirrors `AsyncIterable<Message>` (TypeScript); `deinit` + `close()` (Swift) mirrors `Symbol.asyncDispose` (TypeScript). Conformance test suite is shared.

### Acceptance Criteria

1. **Package builds for all Apple targets:**

   ```bash
   swift build
   xcodebuild build -scheme SCP -destination 'platform=iOS Simulator,name=iPhone 16'
   xcodebuild build -scheme SCP -destination 'platform=macOS'
   ```

   All three commands exit 0 with zero warnings at `SWIFT_STRICT_CONCURRENCY=complete`.

2. **`SCP.create()` factory:**
   - `await SCP.create(custody: .platform)` returns an `SCP` actor with a valid `identity.did` starting with `"did:dht:"`.
   - `await SCP.create(custody: .inMemory)` returns an `SCP` actor with a software-backed identity (for testing).
   - `SCP.create()` calls `ApplePlatformAdapter.make()` when `custody == .platform` and injects all four providers.

3. **`SCPIdentity` operations:**

   ```swift
   let scp = try await SCP.create(custody: .inMemory)
   let identity = scp.identity
   #expect(await identity.did.hasPrefix("did:dht:"))
   #expect(await identity.custodyType == "in_memory")

   let doc = try await identity.resolve(did: await identity.did)
   #expect(!doc.verificationMethods.isEmpty)

   let rotated = try await identity.rotateKey()
   #expect(await rotated.did == identity.did)  // DID is stable; key material rotates
   ```

4. **`SCPContext` lifecycle:**
   - `await scp.createContext(params:)` returns an `SCPContext` with `state == .active`.
   - `await context.send(payload)` delivers an encrypted message (no throw for valid payload).
   - `await context.close()` transitions `state` to `.closed` and finishes the message stream.
   - After `close()`, `send()` throws `ScpError.context` with code `"SCP-CTX-001"`.
   - `deinit` without `close()` triggers cleanup — verified by allocating a context and setting its reference to nil without calling `close()`, then asserting no resource leak in the test teardown.

5. **Message streaming via `AsyncStream<Message>`:**

   ```swift
   let context = try await scp.createContext(params: ContextParams(ceiling: ["messages:read", "messages:write"]))
   let stream = await context.messages

   // Producer task sends 3 messages
   let producer = Task {
       for i in 0..<3 {
           try await context.send(Data("message \(i)".utf8))
       }
       try await context.close()
   }

   var received: [Message] = []
   for await message in stream {
       received.append(message)
   }
   #expect(received.count == 3)
   ```

6. **`ScpError` hierarchy:**
   - All UniFFI `ScpError` variants map 1:1 to Swift `ScpError` cases.
   - Each case has associated `message: String` and `code: String`.
   - `ScpError` conforms to `LocalizedError` — `errorDescription` returns the human-readable message.
   - Error codes follow `SCP-{CATEGORY}-{NUMBER}` format.
   - Errors thrown from bridge functions surface as `ScpError` (not raw UniFFI types) in the ergonomics layer.

7. **UCAN operations:**
   - `mintUcan(identity:memberDid:capabilities:)` returns a non-empty token string.
   - `validateUcan(token:capability:contextId:)` does not throw for a valid token and matching capability.
   - `validateUcan(token:capability:contextId:)` throws `ScpError.permission` for an invalid or expired token.
   - `revokeUcan(identity:tokenId:)` does not throw for a valid token ID.

8. **Tool operations:**

   ```swift
   let toolId = try await context.registerTool(ToolDefinition(
       name: "summarize",
       description: "Summarize text",
       inputSchema: #"{"type":"object","properties":{"text":{"type":"string"}}}"#,
       outputSchema: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
       operatorDid: await scp.identity.did,
       testVectors: nil,
       implementationHash: nil
   ))
   #expect(toolId.hasPrefix("tool-"))
   ```

9. **Event log queries:**

   ```swift
   let eventLog = await context.eventLog()
   let events = try await eventLog.query(since: Date().addingTimeInterval(-3600))
   #expect(events.allSatisfy { $0.contextId == context.contextId })

   let checkpoint = try await eventLog.checkpoint()
   #expect(!checkpoint.merkleRoot.isEmpty)
   ```

10. **SwiftUI `@Observable` integration:**
    - `SCPContextState` is `@Observable`.
    - `attach(to:)` begins appending messages to `messages` array.
    - `isActive` transitions `true` on attach, `false` when context closes.
    - Changes to `SCPContextState` properties trigger SwiftUI view updates (verified via `withObservationTracking` in tests).

11. **Swift 6 strict concurrency — zero warnings:**
    - No `@unchecked Sendable` in `Sources/SCP/` (excluding `MessageListenerAdapter` which is a UniFFI callback adapter and is explicitly justified).
    - No `nonisolated(unsafe)` anywhere.
    - No force unwraps (`!`) and no force try (`try!`) anywhere.
    - `swift build` with `-strict-concurrency=complete` exits 0 with zero warnings.

12. **Test suite passes:**

    ```bash
    swift test                                                                   # All unit tests
    xcodebuild test -scheme SCP -destination 'platform=iOS Simulator,name=iPhone 16'  # iOS
    xcodebuild test -scheme SCP -destination 'platform=macOS'                   # macOS
    ```

    All tests use Swift Testing (`@Test`, `#expect`). No XCTest.

13. **Conformance tests:**
    - The cross-language conformance test suite (from `scaffold/shared.md`) passes for Swift.
    - A context created by the Swift SDK is joinable by the Python SDK and TypeScript SDK (verified with shared test vectors).
    - Messages sent from Swift are receivable by Python and TypeScript SDK consumers.

14. **SPM distribution:**

    ```swift
    // In a consumer's Package.swift
    dependencies: [
        .package(url: "https://github.com/limn/scp-swift", from: "0.1.0"),
    ],
    targets: [
        .target(name: "MyApp", dependencies: ["SCP"]),
    ]
    ```

    `swift package resolve` completes successfully. No Rust toolchain required by the consumer.

### Scope

**Files (~16):**

| File | Purpose |
|------|---------|
| `Package.swift` | SPM package definition — binary XCFramework target + SCP source target + test target |
| `Sources/SCP/SCP.swift` | `SCP` actor — top-level entry point, `create()` factory, `createContext()`, `joinContext()` |
| `Sources/SCP/Identity.swift` | `SCPIdentity` actor — DID, `load()`, `resolve()`, `rotateKey()` |
| `Sources/SCP/Context.swift` | `SCPContext` actor — `send()`, `messages` stream, `invoke()`, `registerTool()`, `leave()`, `close()`, `deinit` |
| `Sources/SCP/Tools.swift` | `ToolDefinition`, `TestVector`, `ToolVerificationResult` nonisolated structs |
| `Sources/SCP/Trust.swift` | `evaluateTrust()`, `TrustEvaluation` struct |
| `Sources/SCP/EventLog.swift` | `SCPEventLog` (nonisolated class), `Event`, `Proof`, `Checkpoint` structs |
| `Sources/SCP/Transport.swift` | `TransportConfig` struct, transport connection helpers |
| `Sources/SCP/Types.swift` | `Message`, `Provenance`, `Capability`, `ContextParams`, `DIDDocument`, enums — all nonisolated Sendable structs |
| `Sources/SCP/Errors.swift` | `ScpError` enum, `LocalizedError` conformance, `init(from: ScpBindings.ScpError)` mapping |
| `Sources/SCP/Ucan.swift` | `validateUcan()`, `mintUcan()`, `revokeUcan()` free functions |
| `Sources/SCP/Mcp.swift` | `serveMcp()`, `McpClient` |
| `Sources/SCP/Platform/PlatformAdapter.swift` | `ApplePlatformAdapter.make()` factory — assembles all four providers |
| `Sources/SCP/Platform/AppleKeyCustody.swift` | `KeyCustodyProvider` — Keychain + DCAppAttestService |
| `Sources/SCP/Platform/AppleDeviceAttestation.swift` | `DeviceAttestationProvider` — DCAppAttestService |
| `Sources/SCP/Platform/ApplePushProvider.swift` | `PushProvider` — APNs |
| `Sources/SCP/Platform/AppleStorage.swift` | `StorageProvider` — file-based + Core Data |
| `Sources/SCP/Internal/ScpBindings.swift` | UniFFI-generated bindings (auto-generated, never edit manually) |

**Estimated functions:** ~35 public functions/methods, ~12 public types (actors + structs + enums), ~8 internal helpers.
