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

**Status:** Pending

### What This ADR Will Decide

The Swift SDK ergonomics layer built on top of UniFFI-generated bindings. Covers Swift-specific patterns (async/await, actor isolation, SwiftUI integration), error types, resource management, and the Swift Package Manager distribution.

### Blockers

- ADR-021 (UniFFI) must be written first — the Swift SDK wraps UniFFI-generated code.
- ADR-025 (Apple platform) must be written — platform adapter is a dependency of the SDK.
- Phase 1-3 implementation must be complete — SDK surface derives from Rust crate public API.

### Required Inputs When Writing

- UniFFI-generated Swift types and async functions.
- Platform adapter implementations (Apple-specific `KeyCustody`, `PushProvider`, `Storage`).
- Error hierarchy as exposed through UniFFI.
- Cross-platform conformance test suite (from `scaffold/shared.md`).

### References

- `scaffold/swift.md` — package structure, UniFFI bridging, async patterns (`CheckedContinuation`), actor isolation, XCFramework.
- `standards/swift.md` — Swift 6 strict concurrency, `@MainActor` default, `nonisolated` DTOs, Swift Testing, iOS 17+.
- `scaffold/shared.md` — cross-language naming (PascalCase types, camelCase functions), conformance tests.
- ADR-014 — Python SDK wrappers as pattern (Pythonic ergonomics layer over flat FFI).

### Expected Decisions

- **Actor isolation strategy:** Which types are `@MainActor`, which are `nonisolated`, which use custom actors.
- **Property wrapper patterns** for SCP state (e.g., `@SCPContext` for SwiftUI observation).
- **Combine/AsyncSequence choice** for streaming (`AsyncSequence` preferred per Swift 6).
- **Resource management:** `deinit` + explicit `close()` pattern for crypto state cleanup.
- **SPM package configuration:** Binary framework target with checksum verification.

### Optimal Approach

Write after ADR-021 (UniFFI) produces generated Swift code. Review the generated API, then design the ergonomics layer. Follow the Python SDK pattern (ADR-014): flat FFI bridge -> idiomatic language wrapper.

### Scope

`bindings/swift/` — ~10 files, ~30 functions (wrapping UniFFI-generated types).
