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
    let clientDataHash = SHA256.hash(data: challenge + deviceId.data(using: .utf8)!)
    service.attestKey(keyId, clientDataHash: Data(clientDataHash)) { attestation, error in
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
   - `generateKeypair(keyType: KeyType) -> KeyHandle`: Generates an Ed25519 or X25519 keypair. Private key bytes stored in Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Returns an opaque handle (UUID string). Fails with `PlatformError.keychainError(OSStatus)` on Keychain failure.
   - `sign(keyHandle: String, data: Data) -> Data`: Retrieves Ed25519 private key from Keychain, signs `data`, returns 64-byte signature. Returns `PlatformError.wrongKeyType` for X25519 handles.
   - `publicKey(keyHandle: String) -> Data`: Returns the 32-byte public key for a handle. Derived from the stored private key bytes.
   - `destroyKey(keyHandle: String)`: Deletes the Keychain item. Verifies deletion by confirming `errSecItemNotFound` on re-fetch. Returns `PlatformError.destructionFailed` if the item persists.
   - `dhAgree(keyHandle: String, peerPublic: Data) -> Data`: Performs X25519 ECDH. Returns the 32-byte shared secret. Private key never leaves the `AppleKeyCustody` implementation boundary. Returns `PlatformError.wrongKeyType` for Ed25519 handles.
   - `derivePseudonym(keyHandle: String, contextId: Data) -> PseudonymKeypair`: Computes `HMAC-SHA256(ed25519_private_key_bytes, contextId || "scp-pseudonym")`, derives Ed25519 keypair from the first 32 bytes. Algorithm is identical to `InMemoryKeyCustody` per ADR-006. Returns `PlatformError.wrongKeyType` for X25519 handles.
   - `custodyType(keyHandle: String) -> CustodyType`: Returns `CustodyType.keychain`.

2. **`AppleKeyCustody` — Keychain access:**
   - All Keychain items use `kSecAttrAccessGroup: "\(appIdentifierPrefix).dev.limn.scp"`.
   - All Keychain items use `kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
   - Key items use `kSecClass: kSecClassGenericPassword` with `kSecAttrAccount: "scp.key.<keyHandle>"`.
   - No Keychain item ever uses `kSecAttrAccessibleAlways` or an iCloud-synced protection class.

3. **`AppleDeviceAttestation` — App Attest:**
   - `attest() -> DeviceAttestationToken`: Generates an App Attest key via `DCAppAttestService.generateKey`, requests attestation with `clientDataHash = SHA256(challenge || deviceID)`. Returns a `DeviceAttestationToken` containing the raw attestation bytes and the key ID.
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
