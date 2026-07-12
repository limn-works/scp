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

Implement bridge support in `scp-core/bridge/`. Bridge connector as registered protocol entity with accountable operator DID. The bridge operator signs bridge protocol messages with the `#agent` verification method on the operator's DID (ADR-039), allowing automated bridge operation without exposing the operator's `#active` key to the bridge software. Shadow identities as restricted participants (observer default). Four operating modes (Relay, Puppet, Api, Cooperative). All bridged content carries full provenance chain. Shadow claiming via identity attestation (§3.5) is one-way and irreversible.

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

// claim_shadow returns Result<ShadowClaimEvent, ClaimError>

pub enum ClaimError {
    HandleMismatch,
    AttestationInvalid,
    AlreadyClaimed,
    ShadowNotFound,
}
```

2. **Bridge registration:**
   - Operator DID presents registration request to context governance.
   - Context governance approves or rejects. The approver must be a different DID from the operator (self-approval is forbidden).
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
| `claiming.rs` | `ClaimRequest`, `ClaimError`, attestation verification, retroattribution |
| `provenance.rs` | `BridgeProvenance`, provenance marking for bridged content |

Per-platform bridge adapter implementations are built on these primitives.

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
   - Used for participation record derivation (ADR-017).

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

**Status:** Decided

### Context

SCP's platform adapter layer (ADR-006) defines four traits: `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage`. Phase 1-2 provided in-memory implementations for testing. The Apple platform adapter provides production implementations for iOS and macOS using Apple's hardware security APIs.

The key constraint shaping this ADR: **Apple's Secure Enclave only supports P-256 (NIST P-256 / secp256r1) key operations**. SCP uses Ed25519 for signing and X25519 for key agreement — neither is natively supported in the Secure Enclave. This is not a limitation the protocol can design around; it is a hardware constraint. The consequence is that SCP identity and signing keys on iOS/macOS are software-backed via the Apple Keychain. The Secure Enclave is used exclusively for App Attest device attestation (which uses a Secure Enclave-backed P-256 key internally via `DCAppAttestService`).

This design is consistent with §17.8: "Secure Enclave only supports P-256; Ed25519 keys are software-backed in Keychain." Android takes a different path — the Android Keystore TEE supports Ed25519 natively as of API 33. The Apple adapter does not pretend to offer hardware-backed key custody; it offers well-protected software custody with hardware-backed device attestation.

The UniFFI bridge (ADR-021) exposes platform traits as callback interfaces. Swift implementations of `KeyCustodyProvider`, `StorageProvider`, and `PushProvider` are passed into the Rust engine at initialization. This means the Apple adapter is implemented in Swift and bridged into Rust through UniFFI's callback interface mechanism — not as a Rust implementation of the traits.

### What This ADR Will Decide

- Key custody implementation: Keychain item storage for Ed25519 and X25519 keys (software-backed) and why the Secure Enclave is not used for signing keys.
- Device attestation implementation: App Attest (`DCAppAttestService`) for hardware-backed device attestation on iOS/macOS.
- Push notification implementation: APNs with opaque payloads per §10.7.
- Storage implementation: SQLCipher with Keychain-protected key derivation + `NSFileProtectionCompleteUntilFirstUserAuthentication` on iOS.
- Keychain access group and protection class selection.
- NSFileProtection level selection and rationale.
- Key destruction attestation for ephemeral context close (§9.15).

### Decision

Implement the Apple platform adapter in Swift (`bindings/swift/Sources/SCP/Platform/`) as four Swift classes conforming to the UniFFI callback interfaces defined in `scp.udl` (ADR-021). The adapter is injected into the Rust engine at SDK initialization via UniFFI callback interface binding.

**Key custody:** `AppleKeyCustody` stores Ed25519 and X25519 key material in the Apple Keychain as generic password items with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` protection. Keys are tagged with a `scp.key.<key_id>` label and access group `$(AppIdentifierPrefix).dev.limn.scp`. The Secure Enclave is not used for Ed25519/X25519 keys — the hardware does not support these key types. Signing operations and DH agreement are performed in software using the key material retrieved from Keychain. Private key bytes are never passed across the Swift/Rust FFI boundary; all signing and key agreement operations happen entirely within the Swift `AppleKeyCustody` implementation.

**Device attestation:** `AppleDeviceAttestation` uses `DCAppAttestService` (App Attest). A Secure Enclave-backed P-256 key is generated via `generateKey(completionHandler:)`. Attestations are requested via `attestKey(_:clientDataHash:completionHandler:)` where `clientDataHash` is `SHA-256(challenge || deviceID)`. Assertions are generated via `generateAssertion(_:clientData:completionHandler:)` for subsequent operations. The attestation token is forwarded to the SCP relay for server-side verification via Apple's attestation service endpoints. On simulator and in environments where App Attest is unavailable, the adapter falls back to a software-only attestation with `method: .softwareOnly`.

**Push notifications:** `ApplePushProvider` wraps UNUserNotificationCenter and registers with APNs via `UIApplication.registerForRemoteNotifications()` / `NSApplication.registerForRemoteNotifications()`. The APNs payload is strictly opaque per §10.7: `{"aps": {"content-available": 1}}` with no additional fields. A content-available notification (silent push) wakes the app. The app then connects to its relay set and pulls all pending encrypted envelopes. No context ID, sender DID, message preview, or other metadata is included in the payload. Apple/Google learn only that the device received a notification at a specific time.

**Storage:** `AppleStorage` wraps a SQLCipher-encrypted SQLite database (`rusqlite` with `bundled-sqlcipher` feature, bridged via UniFFI). The encryption key is a 32-byte secret stored in Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The SQLite database file itself carries `NSFileProtectionCompleteUntilFirstUserAuthentication` (iOS only), which allows background processing while the device is locked after first unlock. On macOS, file-level protection is not applicable.

### Rationale

**Why Keychain for Ed25519/X25519, not Secure Enclave:**
The Secure Enclave is a coprocessor that generates and uses P-256 keys internally. It does not accept Ed25519 or X25519 key material from software and does not expose operations on those key types. The Secure Enclave cannot be used for SCP's signing or key agreement operations. This is a permanent hardware constraint, not an Apple software policy. The Keychain provides software-backed storage for Ed25519/X25519 keys with OS-enforced access controls. This is the correct tool for this job.

**Why App Attest for device attestation (not manual P-256):**
App Attest is Apple's supported API for hardware-backed device attestation. It uses a Secure Enclave-backed P-256 key under the hood and ties the attestation to the device, the app, and the Apple App Attest service. Using App Attest means the protocol gets Secure Enclave security for attestation without managing P-256 keys manually. The alternative — manual P-256 Secure Enclave key management for attestation — would require building and operating an attestation verification service from scratch. App Attest provides this at no infrastructure cost.

**Why `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for Keychain protection:**
This protection class allows Keychain access when the device is locked, as long as the device has been unlocked at least once since boot. This is necessary for SCP background operations — processing incoming messages, maintaining relay connections, responding to push notifications — which all run while the device may be locked. `kSecAttrAccessibleWhenUnlocked` (stricter) would break background processing. `kSecAttrAccessibleAlways` (weaker) is deprecated and provides no meaningful security boundary. `ThisDeviceOnly` prevents iCloud Keychain backup, ensuring keys remain bound to the device.

**Why `NSFileProtectionCompleteUntilFirstUserAuthentication` for the SQLite file:**
Same rationale as the Keychain protection class: background processing requires file access when the device is locked after first unlock. `NSFileProtectionComplete` (stronger) encrypts the file with the user's passcode key and makes it inaccessible while the device is locked — this breaks background message processing. `NSFileProtectionCompleteUntilFirstUserAuthentication` provides strong encryption while enabling the background operations SCP requires.

**Why the adapter is in Swift (not Rust):**
Apple's Keychain, App Attest, and APNs APIs are Objective-C/Swift frameworks (`Security.framework`, `DeviceCheck.framework`, `UserNotifications.framework`). Calling them from Rust requires either direct FFI or an intermediate Swift layer. UniFFI's callback interface mechanism provides a clean, type-safe boundary: Swift implements the trait, Rust calls it through the generated bridge. This is exactly the pattern ADR-021 established. Implementing the adapter in Swift keeps Apple-specific code in the Swift SDK where it belongs and eliminates a raw Objective-C FFI layer in Rust.

**APNs opacity (§10.7):**
Silent push (`content-available: 1`) is the only APNs payload format that satisfies the opacity requirement. Alert notifications (`alert` payload) would include a visible notification with text, exposing context activity to both Apple and potentially the device lock screen. Silent push wakes the app in background with zero user-visible metadata. The SCP engine handles everything after wake.

### Biometric gating

**Amendment (2026-03-08, #392):** `AppleKeyCustody` supports optional biometric authentication (Face ID / Touch ID) gating for key access operations. This is controlled by the `BiometricPolicy` parameter at initialization time.

**Why biometric gating, not Secure Enclave key custody:**
Issue #392 originally requested Secure Enclave-backed key custody. Analysis confirmed that the Secure Enclave only supports P-256 (NIST P-256 / secp256r1) -- it cannot generate, import, or operate on Ed25519 or X25519 keys. This is a permanent hardware constraint. The current Keychain-backed architecture matches the industry standard used by Signal, WhatsApp, and every other Curve25519-based protocol on Apple platforms: software key storage in Keychain with the Secure Enclave used exclusively for device attestation (P-256).

**The biometric enhancement** adds a second factor: the Keychain protects key material at rest, and biometric authentication gates key access at use time. This is the maximum security achievable for Ed25519/X25519 keys on Apple hardware.

**Policy options:**
- `BiometricPolicy.none` (default): Keys use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. No biometric prompt. Background operations work while the device is locked. This is the existing behavior.
- `BiometricPolicy.required`: Keys are stored with `SecAccessControl` using `.biometryCurrentSet` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Face ID / Touch ID is required before `sign`, `dhAgree`, or `derivePseudonym` can access key material. `publicKey` and `destroyKey` do not require biometric authentication.

**`.biometryCurrentSet` vs `.biometryAny`:**
`.biometryCurrentSet` ties key access to the specific set of biometrics enrolled at key creation time. If a new fingerprint is enrolled or Face ID is reset, existing keys become inaccessible -- the Keychain returns `errSecAuthFailed`. This naturally triggers the compromise recovery flow (Section 9.12) since the biometric identity changed. `.biometryAny` would allow newly enrolled biometrics to access existing keys, which weakens the security model.

**Protection class change under biometric policy:**
When biometric gating is active, the protection class changes from `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. This is required because `SecAccessControl` with biometric flags needs the stricter protection class -- background access while locked is incompatible with biometric authentication (the user cannot authenticate while the device is locked). Applications using `.required` must handle this constraint: background SCP operations (relay connections, message processing) will fail while the device is locked.

**Passcode fallback:**
If the device has no biometric hardware (e.g., older iPads, Mac mini), `.biometryCurrentSet` falls back to device passcode authentication. The key is still gated, but by passcode rather than biometric. This is standard iOS/macOS behavior -- no special handling is needed.

**`custodyType` reporting:**
`custodyType()` returns `"software"` for `.none` and `"software_biometric"` for `.required`. This allows the protocol engine and remote participants to understand the custody level without exposing implementation details.

**Industry comparison:**

| App | Signing key storage | SE for attestation | Biometric gating |
|-----|--------------------|--------------------|-----------------|
| Signal | Keychain (Curve25519) | No (no attestation) | Optional (app lock) |
| WhatsApp | Keychain (Curve25519) | No (no attestation) | Optional (app lock) |
| SCP (`.none`) | Keychain (Ed25519/X25519) | Yes (App Attest P-256) | No |
| SCP (`.required`) | Keychain (Ed25519/X25519) | Yes (App Attest P-256) | Yes (per-operation) |

SCP with `.required` provides the strongest custody model achievable on Apple platforms for Curve25519 keys: Keychain encryption at rest + biometric gate at use time + hardware-backed device attestation via App Attest.

### Implementation

- **Language:** Swift 6.2+
- **Platforms:** iOS 17+, macOS 14+
- **Frameworks:** `Security.framework` (Keychain), `DeviceCheck.framework` (App Attest), `UserNotifications.framework` (APNs)
- **Module:** `bindings/swift/Sources/SCP/Platform/`
- **Bridge:** UniFFI callback interfaces (`KeyCustodyProvider`, `StorageProvider`, `PushProvider`) defined in `crates/scp-ffi/uniffi/src/scp.udl` (ADR-021)

**File layout:**

| File | Purpose |
|------|---------|
| `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift` | `KeyCustodyProvider` implementation: Keychain read/write, signing, DH agreement, pseudonym derivation, key destruction |
| `bindings/swift/Sources/SCP/Platform/AppleDeviceAttestation.swift` | `DeviceAttestationProvider` implementation: App Attest key generation, attestation, assertion |
| `bindings/swift/Sources/SCP/Platform/ApplePushProvider.swift` | `PushProvider` implementation: APNs registration, opaque silent push payload, wake signal routing |
| `bindings/swift/Sources/SCP/Platform/AppleStorage.swift` | `StorageProvider` implementation: SQLCipher bridge, Keychain key derivation, `NSFileProtectionCompleteUntilFirstUserAuthentication` |
| `bindings/swift/Sources/SCP/Platform/PlatformAdapter.swift` | `ApplePlatformAdapter`: aggregates the four providers, exposes `make()` factory, injects into `SCP.init()` |

**Key platform API usage:**

```swift
// AppleKeyCustody — store a generated Ed25519 key
let query: [String: Any] = [
    kSecClass as String:            kSecClassGenericPassword,
    kSecAttrAccount as String:      "scp.key.\(keyId)",
    kSecAttrAccessGroup as String:  "\(appIdentifierPrefix).dev.limn.scp",
    kSecAttrAccessible as String:   kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecValueData as String:        privateKeyBytes as CFData,
]
let status = SecItemAdd(query as CFDictionary, nil)

// AppleDeviceAttestation — generate App Attest key and attest
let service = DCAppAttestService.shared
service.generateKey { keyId, error in
    guard let keyId else { /* handle error */ return }
    let clientDataJSON = "{\"challenge\":\"\(Data(challenge).base64EncodedString())\",\"deviceId\":\"\(deviceId.base64EncodedString())\",\"type\":\"scp-device-attestation-v1\"}"
    let clientDataHash = Data(SHA256.hash(data: Data(clientDataJSON.utf8)))
    service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
        // attestation: Data — forward to relay for server-side verification
    }
}

// ApplePushProvider — register and return opaque token
UIApplication.shared.registerForRemoteNotifications()
// Token delivered via AppDelegate.application(_:didRegisterForRemoteNotificationsWithDeviceToken:)
// APNs payload sent by relay: {"aps": {"content-available": 1}}

// AppleStorage — derive SQLCipher key from Keychain secret
let keychainSecret = try keychainRead(account: "scp.db.key")
// Pass to SQLCipher via rusqlite PRAGMA key before any other operations
// connection.execute_batch("PRAGMA key = \"x'\(keychainSecret.hexEncodedString())'\"")

// iOS file protection: set before opening SQLite file
let dbUrl = applicationSupportDirectory.appendingPathComponent("scp.db")
try FileManager.default.setAttributes(
    [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
    ofItemAtPath: dbUrl.path
)
```

**Key destruction attestation (§9.15):**

When an ephemeral context closes, `AppleKeyCustody.destroyKey(keyId:)`:
1. Deletes the Keychain item via `SecItemDelete`.
2. Confirms deletion by attempting retrieval — verifies `errSecItemNotFound` is returned.
3. Returns `DestructionAttestation { method: .softwareOnly, confirmed: true }`.

Note: The Secure Enclave-backed P-256 key used by App Attest cannot be independently attested as destroyed by the protocol — it is managed entirely by `DCAppAttestService` and not used for SCP message keys. For SCP's Ed25519/X25519 Keychain keys, destruction is software-only. The `KeyDestructionAttestation.method` field is set to `.softwareOnly` to be honest about this trust level per §9.15.

**Compromise recovery (§9.12):**

The `AppleKeyCustody` adapter supports all six steps of the compromise recovery protocol:
1. Key rotation: `destroyKey(oldKeyId)` + `generateKeypair(keyType)`.
2. MLS Update: triggered by `scp-core` after key rotation.
3. UCAN revocation: triggered by `scp-core`.
4. KeyPackage rotation: triggered by `scp-core`.
5. Contact notification: triggered by `scp-core`.
6. Identity private state re-encryption: new key available via `publicKey(newKeyHandle)`.

The adapter itself is stateless with respect to the recovery protocol — it stores key material and executes operations, but the recovery orchestration lives in `scp-core`.

### Dependencies

- **ADR-006 (Platform Abstraction):** Defines the `KeyCustody`, `DeviceAttestation`, `Push`, and `Storage` trait signatures. The Apple adapter implements these.
- **ADR-021 (UniFFI Bridge):** Defines the callback interfaces (`KeyCustodyProvider`, `StorageProvider`, `PushProvider`) in `scp.udl`. The Apple adapter implements these callback interfaces in Swift. The adapter is injected into the Rust engine via UniFFI's callback interface binding.
- **Phase 1-2 Rust core:** The Apple adapter is called from `scp-core` through the UniFFI bridge. Phase 1-2 must be implemented before the adapter can be exercised in integration tests.
- **ADR-026 (Swift SDK):** The Swift SDK initializes the Apple adapter and injects it into `SCP.init()`. The adapter is not directly visible to SDK consumers — it is the default platform implementation selected when `custody: "platform"` is specified.

### Acceptance Criteria

1. **`AppleKeyCustody` — Keychain storage:**
   - `generateKeypair(keyType: KeyType) -> KeyHandle`: Generates an Ed25519 or X25519 keypair. Private key bytes stored in Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Returns an opaque handle (UUID string). Fails with `PlatformError.keychainError(OSStatus)` on Keychain failure. Called four times during identity creation when agent delegation is enabled (ADR-039): Identity Key, Active Signing Key, Pre-Rotation Key, and Agent Signing Key. The Agent Signing Key is always software-held (Keychain, not Secure Enclave) since it is designed for autonomous agent operation.
   - `sign(keyHandle: String, data: Data) -> Data`: Retrieves Ed25519 private key from Keychain, signs `data`, returns 64-byte signature. Returns `PlatformError.wrongKeyType` for X25519 handles.
   - `publicKey(keyHandle: String) -> Data`: Returns the 32-byte public key for a handle. Derived from the stored private key bytes.
   - `destroyKey(keyHandle: String)`: Deletes the Keychain item. Verifies deletion by confirming `errSecItemNotFound` on re-fetch. Returns `PlatformError.destructionFailed` if the item persists.
   - `dhAgree(keyHandle: String, peerPublic: Data) -> Data`: Performs X25519 ECDH. Returns the 32-byte shared secret. Private key never leaves the `AppleKeyCustody` implementation boundary. Returns `PlatformError.wrongKeyType` for Ed25519 handles.
   - `derivePseudonym(keyHandle: String, contextId: Data) -> PseudonymKeypair`: Computes `HMAC-SHA256(pseudonym_secret, contextId || "scp-pseudonym")`, derives an Ed25519 keypair from the first 32 bytes (interpreted as an RFC-8032 seed). The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key — public key bytes would be a membership-enumeration oracle (§9.10.4.A). For software-backed Keychain keys, `pseudonym_secret = HKDF-SHA256(ed25519_private_seed, salt="scp-pseudonym-secret-v1")`, which is cross-platform deterministic and matches the §25.19 vectors. For Secure Enclave keys the private key is non-exportable, so `pseudonym_secret` is a device-local value computed inside the enclave; those pseudonyms are device-local by design. Returns `PlatformError.wrongKeyType` for X25519 handles.
   - `custodyType(keyHandle: String) -> CustodyType`: Returns `CustodyType.keychain`.

2. **`AppleKeyCustody` — Keychain access:**
   - All Keychain items use `kSecAttrAccessGroup: "\(appIdentifierPrefix).dev.limn.scp"`.
   - All Keychain items use `kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
   - Key items use `kSecClass: kSecClassGenericPassword` with `kSecAttrAccount: "scp.key.<keyHandle>"`.
   - No Keychain item ever uses `kSecAttrAccessibleAlways` or an iCloud-synced protection class.

3. **`AppleDeviceAttestation` — App Attest:**
   - `attest() -> DeviceAttestationToken`: Generates an App Attest key via `DCAppAttestService.generateKey`, requests attestation with `clientDataHash = SHA256(clientDataJSON)` where `clientDataJSON = '{"challenge":"<base64(challenge)>","deviceId":"<base64(deviceId)>","type":"scp-device-attestation-v1"}'` (fields in this exact order, RFC 4648 base64, no line breaks). Returns a `DeviceAttestationToken` containing the raw attestation bytes and the key ID.
   - `verify(token: DeviceAttestationToken) -> Bool`: Verifies the attestation token structure. Full verification is server-side (relay calls Apple's attestation endpoint). Client-side verification checks that the attestation bytes are non-empty and the key ID is present.
   - On simulator or when App Attest is unavailable: `DCAppAttestService.shared.isSupported == false` → returns a synthetic token with `method: .softwareOnly`. Does not crash or throw; the caller receives a valid (but software-only) token.
   - `generateAssertion(keyId: String, clientData: Data) -> Data`: Generates a per-request assertion via `DCAppAttestService.generateAssertion(_:clientData:)`. Used for subsequent authenticated operations after initial attestation.

4. **`ApplePushProvider` — APNs:**
   - `register() -> PushToken`: Registers with APNs via `registerForRemoteNotifications()`. Returns the device token as hex string. Fails with `PlatformError.pushRegistrationFailed(String)` if APNs registration fails.
   - `handleNotification(payload: Data) -> WakeSignal`: Processes an incoming silent push notification. Verifies the payload is `{"aps": {"content-available": 1}}`. Returns `WakeSignal.wake`. Rejects payloads containing any field other than `aps.content-available`.
   - The relay MUST send only `{"aps": {"content-available": 1}}` payloads. The adapter enforces opacity on receipt. No context ID, sender DID, or message count is acceptable in the payload.
   - APNs registration uses the `.alert` notification category with `UNAuthorizationOptions.alert` only for system notification permission; the actual push payload remains silent.

5. **`AppleStorage` — SQLCipher:**
   - `store(key: String, value: Data)`: Writes `(key, value)` to the SQLCipher-encrypted SQLite database.
   - `retrieve(key: String) -> Data?`: Returns stored data or nil.
   - `delete(key: String)`: Removes a key.
   - `listKeys(prefix: String) -> [String]`: Lists keys matching a prefix in lexicographic order.
   - `deletePrefix(prefix: String) -> UInt64`: Deletes all keys matching a prefix. Returns count deleted.
   - `exists(key: String) -> Bool`: Returns true if the key exists.
   - Database encryption: 32-byte key stored in Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Passed to SQLCipher via `PRAGMA key` before any other operation on the connection.
   - iOS: database file has `NSFileProtectionCompleteUntilFirstUserAuthentication` attribute set before first open.
   - macOS: file protection not applicable; Keychain-protected encryption key provides the access control.

6. **`PlatformAdapter` initialization:**

   ```swift
   public final class ApplePlatformAdapter {
       public static func make() throws -> ApplePlatformAdapter {
           let keyCustody = AppleKeyCustody()
           let attestation = AppleDeviceAttestation()
           let push = ApplePushProvider()
           let storage = try AppleStorage.open()
           return ApplePlatformAdapter(
               keyCustody: keyCustody,
               attestation: attestation,
               push: push,
               storage: storage
           )
       }
   }
   ```

   - `ApplePlatformAdapter.make()` is called by `SCP.init()` when `custody: "platform"` is specified (ADR-026).
   - All four providers are initialized before the Rust engine starts. If any provider fails to initialize (e.g., Keychain inaccessible at boot), `make()` returns a descriptive `PlatformError`.

7. **Conformance test suite:**
   - All four providers pass the platform trait conformance macros defined in `scp-platform/testing/` (ADR-006): `key_custody_conformance!()`, `storage_conformance!()`, `attestation_conformance!()`, `push_conformance!()`.
   - Tests run on real devices (CI must include a physical iOS device lane for Keychain and App Attest tests). Simulator-only tests use `#if targetEnvironment(simulator)` fallback paths.
   - `AppleKeyCustody` round-trip test: `generateKeypair(.ed25519)` → `sign(data)` → `publicKey()` → verify signature → `destroyKey()` → confirm re-fetch fails.
   - `AppleStorage` round-trip test: `store(key, data)` → `retrieve(key)` → `listKeys(prefix)` → `delete(key)` → `exists(key) == false`.
   - `AppleDeviceAttestation` test on real device: `attest()` returns non-empty token. On simulator: returns software-only token without crashing.
   - `ApplePushProvider` test: `register()` returns a non-empty token string. `handleNotification` rejects non-opaque payloads.

8. **No Secure Enclave signing key:**
   - `AppleKeyCustody` MUST NOT generate or use Secure Enclave P-256 keys for SCP signing operations. Secure Enclave is used exclusively by `AppleDeviceAttestation` via `DCAppAttestService`.
   - This constraint is enforced by never importing `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` in `AppleKeyCustody.swift`.

9. **Key destruction verification (§9.15):**
   - `destroyKey` verifies deletion before returning.
   - `DestructionAttestation.method` is always `.softwareOnly` for Keychain-backed keys.
   - The attestation is signed by the identity key (not the destroyed key) per §9.15 protocol step 3.

10. **Conditional compilation:**
    - All Apple platform APIs are gated behind `#if os(iOS) || os(macOS)`.
    - Background processing code is gated behind `#if canImport(UIKit)` (iOS) vs `#if canImport(AppKit)` (macOS).
    - Simulator fallback paths are gated behind `#if targetEnvironment(simulator)`.

### Scope

**Files (~5):**

| File | Purpose |
|------|---------|
| `bindings/swift/Sources/SCP/Platform/AppleKeyCustody.swift` | `KeyCustodyProvider` — Keychain storage, Ed25519 signing, X25519 DH, pseudonym derivation, key destruction |
| `bindings/swift/Sources/SCP/Platform/AppleDeviceAttestation.swift` | `DeviceAttestationProvider` — App Attest key generation, attestation, assertion, simulator fallback |
| `bindings/swift/Sources/SCP/Platform/ApplePushProvider.swift` | `PushProvider` — APNs registration, opaque silent push payload enforcement |
| `bindings/swift/Sources/SCP/Platform/AppleStorage.swift` | `StorageProvider` — SQLCipher-encrypted SQLite, Keychain key derivation, `NSFileProtection` |
| `bindings/swift/Sources/SCP/Platform/PlatformAdapter.swift` | `ApplePlatformAdapter.make()` — aggregates all four providers, injected by `SCP.init()` |

**Estimated functions:** ~20 public methods across four provider implementations, ~10 internal helpers (Keychain query builders, error mapping, SQLCipher connection setup).

---

## ADR-026: Swift SDK

**Status:** Decided

### Context

The UniFFI bridge (ADR-021) generates raw Swift bindings from the Rust protocol engine. While functional, the generated surface is not idiomatic Swift — it lacks actor isolation, `AsyncSequence` streams, the `@Observable` macro, and the ergonomic patterns Swift developers expect. The Apple platform adapter (ADR-025) provides the `KeyCustody`, `PushProvider`, `Storage`, and `DeviceAttestationProvider` implementations injected into the Rust engine via UniFFI callback interfaces.

The Swift SDK ergonomics layer wraps the generated bindings to produce an idiomatic Swift API that feels native to the platform: `async/await` throughout, actor-isolated state, structured concurrency with `AsyncStream<Message>`, `@Observable` for SwiftUI, and `deinit`-safe resource cleanup. The ergonomics layer is pure Swift — zero protocol logic, zero duplication of Rust behavior. This mirrors the ADR-014 (Python SDK) pattern: flat FFI bridge → idiomatic language wrapper.

Swift 6.2 with `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` is the baseline, making `@MainActor` the default. Types that need to operate off the main actor (background crypto, streaming) explicitly opt out.

### Decision

Implement the Swift SDK as the `SCP` Swift package at `bindings/swift/`. The package imports `ScpFFI.xcframework` (UniFFI-generated binary), re-exports it through `Sources/SCP/Internal/ScpBindings.swift`, and builds a pure Swift ergonomics layer in `Sources/SCP/`. The top-level entry point is `SCP` — an actor that initializes the identity and injects the Apple platform adapter. `SCPContext` is the primary interactive type — an actor exposing `AsyncStream<Message>` for streaming and a `close()` / `deinit` lifecycle.

Actor isolation follows the Swift 6.2 approachable concurrency rules: data carrier types (`Message`, `DIDDocument`, `OutletDefinition`) are `nonisolated struct` and `Sendable` by definition. Interactive types (`SCP`, `SCPContext`, `SCPIdentity`) are custom actors. `SCPEventLog` and `SCPTransport` are `nonisolated` since they have no mutable state after construction. `SwiftUI` observation uses `@Observable` for SCP state containers (Swift 5.9+). Streaming uses `AsyncStream<Message>` (not Combine) — the right choice for Swift 6 structured concurrency. The SPM package is configured as a binary framework target with XCFramework checksum verification.

### Rationale

- **Actor isolation over `@MainActor` default for interactive types:** `SCP` and `SCPContext` manage mutable protocol state (MLS group, sender keys, connection handles). Custom actors enforce serial access to this state without blocking the main thread. `@MainActor` would block UI updates during crypto operations — wrong for any non-trivial workload.
- **`AsyncStream<Message>` over Combine:** Swift 6 strict concurrency treats Combine as a compatibility layer, not the forward path. `AsyncStream` integrates naturally with `for await` loops, structured concurrency cancellation, and `TaskGroup`. It requires zero imported frameworks and works identically on iOS, macOS, and in Swift package tests. Combine's `Publisher` → `AsyncSequence` bridging adds indirection without benefit.
- **`@Observable` for SwiftUI state:** The `@Observable` macro (Swift 5.9+, iOS 17+) tracks property access at the granularity of individual properties rather than the whole object. This means `SCPContextState` annotated with `@Observable` triggers minimal view updates when only `memberCount` changes, not when `lastMessage` changes. Property wrappers like `@Published` (Combine) are legacy in this context.
- **`deinit` + explicit `close()` for resource cleanup:** SCP contexts hold live crypto state (MLS group keys, sender AES-256 keys) that must be zeroed on deallocation. `close()` is the user-visible method for graceful teardown (leave the MLS group, flush the event log, close the transport connection). `deinit` is the safety net — it schedules a `Task { try? await close() }` to prevent resource leaks when a context object is dropped without explicit close. This matches the `Symbol.asyncDispose` pattern in the TypeScript SDK.
- **`nonisolated struct` for DTOs:** Data carrier types (`Message`, `DIDDocument`, `OutletDefinition`, `Provenance`) are value types with no mutable state after construction. Marking them `nonisolated struct` makes all members inherit nonisolated context, satisfying Swift 6 `Sendable` without `@unchecked Sendable`. They cross actor boundaries freely as `Sendable` values.
- **`SCP.create()` as async factory, not `init`:** The identity initialization path (`identity_create()`) is async (involves key generation and DID registration). Swift actors cannot have `async init`. The factory pattern `await SCP.create()` is the idiomatic solution. `ApplePlatformAdapter.make()` is injected at creation time — the caller controls custody.
- **SPM binary framework target:** XCFramework binary distribution via SPM `binaryTarget` with checksum verification gives consumers a single `Package.swift` dependency with no Rust toolchain requirement. Swift compiler verifies the binary against the declared checksum on resolution.
- **Flat delegation pattern — no logic in Swift:** Every Swift SDK method calls exactly one UniFFI bridge function. Zero protocol logic lives in the Swift layer. This prevents divergence between the Rust engine and the Swift surface and ensures one implementation of every operation.

### Implementation

**Language:** Swift 6.2+

**Package:** `bindings/swift/` published as `SCP` Swift package via GitHub releases.

**Dependencies from UniFFI:** `identity_create()`, `identity_load()`, `identity_resolve()`, `context_create()`, `context_join()`, `context_leave()`, `context_close()`, `context_send()`, `context_subscribe()` (callback interface), `outlet_register()`, `outlet_invoke()`, `outlet_verify()`, `ucan_validate()`, `ucan_mint()`, `ucan_revoke()`, `event_log_query()`, `event_log_verify()`, `transport_connect()`, `transport_disconnect()`, `transport_status()`, and the `ScpError` enum — all from `ScpBindings.swift`.

**File layout:**

```
bindings/swift/
  Package.swift                       # SPM package definition (binary + source targets)
  Sources/
    SCP/
      SCP.swift                       # SCP actor — top-level entry point, identity + transport init
      Identity.swift                  # SCPIdentity actor, DIDDocument struct
      Context.swift                   # SCPContext actor, AsyncStream<Message>, lifecycle
      Outlets.swift                     # OutletDefinition, TestVector, OutletVerificationResult structs
      Trust.swift                     # evaluateTrust(), TrustEvaluation struct
      EventLog.swift                  # SCPEventLog class (nonisolated), Event, Proof, Checkpoint
      Transport.swift                 # TransportConfig struct, transport connection helpers
      Types.swift                     # Message, Provenance, Capability, ContextParams (nonisolated structs)
      Errors.swift                    # ScpError enum (mirrors UniFFI ScpError), LocalizedError conformance
      Ucan.swift                      # UCAN validate(), mint(), revoke() (nonisolated free functions)
      Mcp.swift                       # serveMcp(), McpClient
      Platform/
        AppleKeyCustody.swift         # KeyCustodyProvider implementation (Keychain, not Secure Enclave — see ADR-025)
        AppleDeviceAttestation.swift  # DeviceAttestationProvider (DCAppAttestService)
        ApplePushProvider.swift       # PushProvider (APNs)
        AppleStorage.swift            # StorageProvider (SQLCipher + Keychain key — see ADR-025)
        PlatformAdapter.swift         # ApplePlatformAdapter.make() factory
      Internal/
        ScpBindings.swift             # UniFFI-generated bindings (auto-generated, do not edit)
  Tests/
    SCPTests/
      IdentityTests.swift
      ContextTests.swift
      OutletsTests.swift
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
/// An active SCP context. Send messages, receive streams, invoke outlets.
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
        guard state == .active else { throw ScpError.context(message: "Context is not active", code: "SCP-CTX-2001") }
        try await context_send(handle: handle, payload: payload)
    }

    /// AsyncStream of incoming messages. Yields until the context closes.
    public var messages: AsyncStream<Message> {
        AsyncStream { continuation in
            self.streamContinuation = continuation
            context_subscribe(handle: handle, listener: MessageListenerAdapter(continuation: continuation))
        }
    }

    /// Invoke a registered outlet in this context.
    public func invoke(outlet: String, input: Data) async throws -> Data {
        let output = try await outlet_invoke(handle: handle, outletId: outlet, inputJson: input)
        return output
    }

    /// Register an outlet in this context. Returns the assigned outlet ID.
    public func registerOutlet(_ definition: OutletDefinition) async throws -> String {
        try await outlet_register(handle: handle, registration: definition.toRecord())
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
    case outlet(message: String, code: String)
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
        case .outlet(let message, _): return message
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
        case .outlet(_, let code): return code
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
        case .outlet(let message, let code): self = .outlet(message: message, code: code)
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
    public let outlets: [OutletDefinition]
    public let governance: GovernanceModel
    public let ttl: TimeInterval?
    public let memoryScope: MemoryScope

    public init(
        ceiling: [String],
        outlets: [OutletDefinition] = [],
        governance: GovernanceModel = .singleAdmin,
        ttl: TimeInterval? = nil,
        memoryScope: MemoryScope = .full
    ) {
        self.ceiling = ceiling
        self.outlets = outlets
        self.governance = governance
        self.ttl = ttl
        self.memoryScope = memoryScope
    }
}

/// A registered SCP outlet definition.
public nonisolated struct OutletDefinition: Sendable {
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
   - After `close()`, `send()` throws `ScpError.context` with code `"SCP-CTX-2001"`.
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

8. **Outlet operations:**

   ```swift
   let outletId = try await context.registerTool(OutletDefinition(
       name: "summarize",
       description: "Summarize text",
       inputSchema: #"{"type":"object","properties":{"text":{"type":"string"}}}"#,
       outputSchema: #"{"type":"object","properties":{"summary":{"type":"string"}}}"#,
       operatorDid: await scp.identity.did,
       testVectors: nil,
       implementationHash: nil
   ))
   #expect(outletId.hasPrefix("outlet-"))
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
| `Sources/SCP/Outlets.swift` | `OutletDefinition`, `TestVector`, `OutletVerificationResult` nonisolated structs |
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
| `Sources/SCP/Platform/AppleStorage.swift` | `StorageProvider` — SQLCipher + Keychain key (ADR-025) |
| `Sources/SCP/Internal/ScpBindings.swift` | UniFFI-generated bindings (auto-generated, never edit manually) |

**Estimated functions:** ~35 public functions/methods, ~12 public types (actors + structs + enums), ~8 internal helpers.
