# SCP Planning Session 04 — Technical Implementation Design

**Date:** February 21, 2026
**Scope:** Technology selection, SDK architecture, adapter/binding design, build order
**Artifacts modified:** None (new planning document — decisions here feed into future spec/sketch updates)

---

## How This Session Started

The question was: **how do you actually build this?** The spec describes a coherent system. The sketch shows API surfaces. But no software exists. This session moves from architecture to engineering — concrete technology choices, stack decisions, adapter patterns, and build sequencing.

---

## 1. Current State: Spec, Not Protocol

SCP is a specification, not a running protocol. What exists:

- `.docs/specs/` — ~1500 lines of architectural decisions, threat models, trust mechanics
- `sketch.md` — API surface sketches in pseudocode
- Three planning sessions (01–03) capturing design rationale

What does not exist:

- An SDK anyone can import
- A working transport binding
- A context key management implementation
- A DID method selection
- A UCAN capability schema
- Any running software

The gap between "detailed blueprint" and "working protocol" is the four Tier 1 items identified in planning session 02: key management, transport abstraction, DID method, and UCAN schema. These are engineering decisions, not research problems — but they hadn't been made until this session.

---

## 2. The Four Gating Decisions

These must be made in order. Each constrains the next.

### Decision 1: Group Encryption — MLS (Messaging Layer Security, RFC 9420)

**Choice:** MLS over Sender Keys.

**Rationale:**

| Property | MLS | Sender Keys |
|---|---|---|
| Member removal cost | O(log n) — tree-based | O(n) — re-encrypt to every remaining member |
| Forward secrecy | Per-epoch ratcheting | Per-sender ratcheting |
| Key destruction (for ephemeral memory scope) | Clean — destroy tree root | Requires destroying all sender keys |
| Standardization | IETF RFC 9420 | Signal protocol, no formal RFC |
| Large group scaling | Good (tree structure) | Degrades linearly |
| Implementation complexity | Higher | Lower |
| Library ecosystem | OpenMLS (Rust), mls-rs (Rust), MLS++ (C++) | libsignal (Rust/C) |

MLS wins because member removal = key rotation = blocking enforcement = ephemeral key destruction. These are all the same operation on the key tree. In a 1000-person context, removing someone with Sender Keys means re-encrypting and distributing to 999 people. MLS: ~10 operations (log₂ 1000).

**How MLS maps to SCP operations:**

```
Context created    → MLS group created → key tree initialized
Member joins       → MLS Add proposal → key tree updated, new member gets key
Member leaves      → MLS Remove proposal → key tree ratcheted, leaver excluded
Block (DID-to-DID) → MLS Remove for blocker's sub-tree → blocked party loses blocker's keys
TTL expires        → MLS group dissolved → tree root destroyed
Ephemeral close    → Same as TTL expiry → keys unrecoverable
```

**Libraries:** OpenMLS (Rust, most mature), mls-rs (Rust, by Wire). Do not implement MLS from scratch.

### Decision 2: DID Method — `did:dht` (with `did:web` fallback for Cronica v1)

**Choice:** `did:dht` as the target method. `did:web` as a pragmatic v1 stepping stone for Cronica.

**Why `did:dht`:**

| Property | `did:key` | `did:web` | `did:dht` |
|---|---|---|---|
| Key rotation | Impossible (key IS identity) | Possible (update hosted document) | Possible (update DHT record) |
| Resolution infrastructure | None needed (self-describing) | Web server required | Mainline DHT (BitTorrent's, millions of nodes) |
| Decentralization | Fully decentralized | Centralized on hosting server | Decentralized via DHT |
| Recovery | Cannot rotate key → identity lost if key lost | Server operator dependency | Rotate key, update DHT |
| Speed | Instant (no resolution) | HTTP lookup (~100ms) | DHT lookup (~1-5s) |
| Maturity | W3C standard, very mature | W3C standard, mature | Newer, fewer battle-tested libraries |

`did:key` is ruled out because recovery (§3.3) requires key rotation — if you lose a key, you need to rotate to a new one without changing identity. `did:key` makes the key the identity, so key loss = identity loss.

`did:dht` gives decentralized resolution with key rotation via the Mainline DHT. No blockchain, no server dependency, existing infrastructure with millions of nodes.

**Pragmatic v1 path:** Cronica launches with `did:web` pointing at Limn's infrastructure. Simple, fast, reliable. The SDK abstracts the DID method — apps don't know or care which method underlies. Migration from `did:web` to `did:dht` is transparent to apps and users. The DID document content is identical; only the resolution mechanism changes.

### Decision 3: Transport — Nostr Binding First, Behind a Transport Abstraction

**Transport abstraction interface (SCP defines this):**

```
interface Transport {
  // Core messaging
  send(contextID: String, envelope: EncryptedEnvelope) → Receipt
  subscribe(contextID: String, since: Date?) → Stream<EncryptedEnvelope>

  // Relay management
  connect(relayAddress: URL) → Connection
  disconnect(relayAddress: URL) → void

  // Identity-relay mapping
  publishRelayList(did: DID, relays: [URL]) → void
  discoverRelays(did: DID) → [URL]
}
```

Six methods. Deliberately thin. Everything above this interface is SCP protocol logic. Everything below it is transport-specific.

**First binding: Nostr.**

Why Nostr:
- Relays already exist. Hundreds of them. No need to build relay infrastructure from scratch.
- SCP encrypted envelopes are opaque blobs. Nostr relays store and forward signed events. These are the same operation.
- Keypair identity maps nearly 1:1 (DID public key → Nostr npub is a trivial conversion).
- WebSocket-based — works in browsers, mobile, desktop.
- NIP-42 (relay auth) exists for relays that want access control, though SCP doesn't need it (encryption-as-access-control handles this).
- Mature client libraries in every language.

**SCP envelopes as Nostr events:**

```json
{
  "kind": 30078,
  "pubkey": "npub...",
  "created_at": 1740000000,
  "tags": [
    ["d", "ctx:z6Mkq8..."],
    ["p", "npub..."]
  ],
  "content": "base64(encrypted_scp_envelope)",
  "sig": "..."
}
```

Existing Nostr relays store this without modification. They don't know it's SCP. They don't need to.

**SCP context proposals as Nostr events:**

```json
{
  "kind": 30079,
  "pubkey": "npub...",
  "created_at": 1740000000,
  "tags": [
    ["d", "prop:z6Mk..."],
    ["p", "npub..."],
    ["type", "context_proposal"]
  ],
  "content": "base64(encrypted_proposal_envelope)",
  "sig": "..."
}
```

Proposals are encrypted to the recipient's public key (NIP-44 encryption or SCP's own envelope encryption). The relay routes by the `p` tag.

### Decision 4: UCAN Capability Schema

**Capability types for v1:**

```
// Context-scoped capabilities
scp:ctx:{contextID}/messages          → read, write
scp:ctx:{contextID}/tool/{toolName}   → invoke
scp:ctx:{contextID}/members           → read, invite
scp:ctx:{contextID}/governance        → propose, approve, reject
scp:ctx:{contextID}/metadata          → read
scp:ctx:{contextID}/eventlog          → read, verify

// A2A capabilities
scp:ctx:{contextID}/proposals         → send, receive, accept, reject

// Cross-context
scp:interface:{interfaceID}           → call

// Identity-scoped
scp:identity:{did}/privatestate       → read, write
scp:identity:{did}/attestations       → create, revoke
```

**UCAN token structure (standard UCAN envelope):**

```json
{
  "header": { "alg": "EdDSA", "typ": "JWT", "ucv": "0.10.0" },
  "payload": {
    "iss": "did:dht:z6MkpT...",
    "aud": "agent:z6MkpT:ctx:z6Mkq8...",
    "att": [
      { "with": "scp:ctx:z6Mkq8.../messages", "can": "write" },
      { "with": "scp:ctx:z6Mkq8.../tool/guide_assistant", "can": "invoke" },
      { "with": "scp:ctx:z6Mkq8.../members", "can": "read" },
      { "with": "scp:ctx:z6Mkq8.../proposals", "can": "send" }
    ],
    "exp": 1740000000,
    "nnc": "unique-nonce"
  },
  "signature": "..."
}
```

**Delegation chain:** Human DID → Agent → Context-scoped token. Every token traces back to the human who authorized it. Revocation is per-token — revoke one capability in one context without affecting others.

**Libraries:** ucanto (TypeScript), rs-ucan (Rust), ucan-wasm. [Note: rs-ucan replaced by native impl in scp-core/src/crypto/ucan/]

---

## 3. SDK Architecture

### The Product Is an SDK

The SDK is the entire product. Apps are thin shells over it. The API surface is ~20-30 methods. The internals are substantial.

```
What a developer/LLM touches:        What the SDK handles invisibly:

SCP.Context.create(...)               DID key management
SCP.Context.propose(...)              UCAN token creation/validation
agent.send(...)                       MLS encryption/decryption
agent.invoke(tool, input)             Transport (relay connections)
SCP.App.declare(manifest)             Merkle tree event logs
                                      Behavioral record computation
                                      Trust evaluation
                                      Key rotation on member changes
                                      Provenance tagging
                                      Envelope signing/verification
```

### Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  PUBLIC API SURFACE (Swift / Kotlin / TypeScript)                     │
│                                                                       │
│  SCP.Identity.create()    SCP.Context.create()    SCP.Context.propose()
│  SCP.Context.join()       agent.send()            agent.invoke()
│  SCP.Trust.evaluate()     SCP.App.declare()       SCP.Capability.grant()
│                                                                       │
│  ~20-30 methods. This is what apps and LLMs see.                     │
├─────────────────────────────────────────────────────────────────────┤
│  PROTOCOL ENGINE (Rust core)                                          │
│                                                                       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │
│  │ Context       │  │ Trust         │  │ Identity      │            │
│  │ Manager       │  │ Engine        │  │ Manager       │            │
│  │               │  │               │  │               │            │
│  │ - lifecycle   │  │ - 4-layer     │  │ - DID ops     │            │
│  │ - membership  │  │   evaluation  │  │ - key custody │            │
│  │ - roles       │  │ - behavioral  │  │ - attestations│            │
│  │ - tools       │  │   records     │  │ - private     │            │
│  │ - governance  │  │ - provenance  │  │   state       │            │
│  │ - proposals   │  │ - attestation │  │ - recovery    │            │
│  │ - TTL/memory  │  │   validation  │  │               │            │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘            │
│          │                  │                   │                     │
│  ┌───────┴──────────────────┴───────────────────┴───────┐            │
│  │ CRYPTO LAYER                                          │            │
│  │                                                       │            │
│  │  MLS (OpenMLS)     UCAN (rs-ucan*)    Merkle Trees   │            │
│  │  - group mgmt      - token create     - event log    │            │
│  │  - key rotation     - chain validate  - proofs       │            │
│  │  - encrypt/decrypt  - revocation      - integrity    │            │
│  │  - epoch ratchet    - delegation                     │            │
│  └───────────────────────┬───────────────────────────────┘            │
│                          │                                            │
├──────────────────────────┼────────────────────────────────────────────┤
│  ADAPTER LAYER           │                                            │
│  (see §4 below)          │                                            │
│                          │                                            │
│  ┌───────────┐  ┌────────┴──┐  ┌───────────┐  ┌───────────┐         │
│  │ Transport │  │ Platform  │  │ MCP       │  │ Bridge    │         │
│  │ Adapters  │  │ Adapters  │  │ Adapter   │  │ Adapters  │         │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘         │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

*rs-ucan was replaced by a native implementation in scp-core/src/crypto/ucan/.

### Tech Stack

```
Core:       Rust (crypto, protocol engine, event logs, UCAN validation)
iOS SDK:    Swift (via UniFFI bindings from Rust)
Android:    Kotlin (via UniFFI bindings from Rust) — later
Web:        TypeScript/WASM (via wasm-bindgen from Rust) — later
```

Why Rust core: the crypto libraries are strongest in Rust (OpenMLS, DID/UCAN ecosystem, Nostr ecosystem). UniFFI (Mozilla's tool) generates Swift and Kotlin bindings from Rust automatically. Write the hard stuff once, expose it to every platform.

---

## 4. Adapter Architecture

Adapters are the boundary between SCP's protocol engine and everything external. Four categories of adapters, each with a defined interface contract.

### 4.1 Transport Adapters

Transport adapters implement the transport abstraction interface. They carry encrypted envelopes between participants via specific delivery infrastructure.

**Interface contract (all transport adapters implement this):**

```rust
trait TransportAdapter {
    // Send an encrypted envelope to a context's participants
    async fn send(&self, context_id: &str, envelope: &EncryptedEnvelope) -> Result<Receipt>;

    // Subscribe to incoming envelopes for a context
    async fn subscribe(&self, context_id: &str, since: Option<DateTime>) -> Result<Stream<EncryptedEnvelope>>;

    // Publish this DID's relay/endpoint list for discoverability
    async fn publish_endpoints(&self, did: &DID, endpoints: &[Url]) -> Result<()>;

    // Discover another DID's relay/endpoint list
    async fn discover_endpoints(&self, did: &DID) -> Result<Vec<Url>>;

    // Connection lifecycle
    async fn connect(&self, endpoint: &Url) -> Result<Connection>;
    async fn disconnect(&self, endpoint: &Url) -> Result<()>;

    // Adapter metadata
    fn transport_type(&self) -> TransportType;
    fn capabilities(&self) -> TransportCapabilities;
}

struct TransportCapabilities {
    supports_realtime: bool,        // can deliver immediately when both online
    supports_offline: bool,         // can store-and-forward for offline recipients
    supports_streaming: bool,       // can stream continuous updates
    max_envelope_size: usize,       // maximum payload size
    requires_relay: bool,           // does this transport need relay infrastructure
}
```

**Nostr Adapter (reference / primary):**

```rust
struct NostrTransportAdapter {
    relay_pool: RelayPool,          // manages WebSocket connections to multiple relays
    keypair: NostrKeypair,          // derived from DID keys
    subscription_manager: SubscriptionManager,
}

impl TransportAdapter for NostrTransportAdapter {
    async fn send(&self, context_id: &str, envelope: &EncryptedEnvelope) -> Result<Receipt> {
        // 1. Encode SCP envelope as Nostr event
        let event = NostrEvent {
            kind: 30078,            // custom application data
            pubkey: self.keypair.public_key(),
            tags: vec![
                Tag::Identifier(context_id.to_string()),    // ["d", "ctx:..."]
                // ["p", "npub..."] tags for each recipient (relay routing)
            ],
            content: base64_encode(envelope),
            created_at: now(),
        };
        // 2. Sign the event
        let signed = event.sign(&self.keypair)?;
        // 3. Publish to relay pool
        self.relay_pool.publish(signed).await
    }

    async fn subscribe(&self, context_id: &str, since: Option<DateTime>) -> Result<Stream<EncryptedEnvelope>> {
        // Subscribe to Nostr events tagged with this context_id
        let filter = Filter {
            kinds: vec![30078],
            tags: hashmap!{ "d" => vec![context_id.to_string()] },
            since: since.map(|d| d.timestamp()),
            ..Default::default()
        };
        let stream = self.relay_pool.subscribe(vec![filter]).await?;
        // Decode SCP envelopes from Nostr event content
        Ok(stream.map(|event| base64_decode(&event.content)))
    }

    async fn publish_endpoints(&self, did: &DID, endpoints: &[Url]) -> Result<()> {
        // Publish as NIP-65 relay list metadata
        let event = NostrEvent {
            kind: 10002,            // NIP-65 relay list
            tags: endpoints.iter().map(|url| Tag::Relay(url.clone())).collect(),
            ..Default::default()
        };
        self.relay_pool.publish(event.sign(&self.keypair)?).await
    }

    async fn discover_endpoints(&self, did: &DID) -> Result<Vec<Url>> {
        // Look up the DID's Nostr npub, query for their NIP-65 relay list
        let npub = did_to_npub(did)?;
        let filter = Filter {
            authors: vec![npub],
            kinds: vec![10002],
            ..Default::default()
        };
        let events = self.relay_pool.query(vec![filter]).await?;
        // Extract relay URLs from the most recent event
        Ok(extract_relay_urls(&events))
    }

    fn transport_type(&self) -> TransportType { TransportType::Nostr }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            supports_realtime: true,
            supports_offline: true,     // relays store events
            supports_streaming: true,   // WebSocket subscriptions
            max_envelope_size: 65_536,  // Nostr event content limit
            requires_relay: true,
        }
    }
}
```

**Matrix Adapter (future):**

```rust
struct MatrixTransportAdapter {
    client: MatrixClient,
    // Maps SCP context IDs to Matrix room IDs
    context_room_map: HashMap<String, RoomId>,
}

impl TransportAdapter for MatrixTransportAdapter {
    async fn send(&self, context_id: &str, envelope: &EncryptedEnvelope) -> Result<Receipt> {
        // 1. Resolve context_id → Matrix room
        let room_id = self.context_room_map.get(context_id)?;
        // 2. Send SCP envelope as a custom Matrix event
        let event_content = json!({
            "msgtype": "m.scp.envelope",
            "body": base64_encode(envelope),
        });
        self.client.send_message(room_id, event_content).await
    }

    async fn subscribe(&self, context_id: &str, since: Option<DateTime>) -> Result<Stream<EncryptedEnvelope>> {
        let room_id = self.context_room_map.get(context_id)?;
        // Subscribe to room events, filter for SCP envelope type
        let stream = self.client.room_events(room_id, since).await?;
        Ok(stream.filter_map(|event| {
            if event.content.msgtype == "m.scp.envelope" {
                Some(base64_decode(&event.content.body))
            } else {
                None
            }
        }))
    }

    // ... remaining methods map to Matrix room/user operations

    fn transport_type(&self) -> TransportType { TransportType::Matrix }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            supports_realtime: true,
            supports_offline: true,     // homeserver stores events
            supports_streaming: true,   // Matrix sync
            max_envelope_size: 65_536,
            requires_relay: true,       // needs a homeserver
        }
    }
}
```

**WebSocket Adapter (direct device-to-device, testing, local):**

```rust
struct WebSocketTransportAdapter {
    connections: HashMap<String, WebSocketConnection>,
}

impl TransportAdapter for WebSocketTransportAdapter {
    // Direct peer-to-peer. No relay. Only works when both devices are online.
    // Useful for: testing, local development, same-network devices.

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            supports_realtime: true,
            supports_offline: false,    // no relay = no offline delivery
            supports_streaming: true,
            max_envelope_size: 1_048_576,  // larger payloads OK (no relay limit)
            requires_relay: false,
        }
    }
}
```

**Transport adapter selection and multi-transport:**

The SDK can use multiple transport adapters simultaneously. A context might route through Nostr relays for general delivery and use direct WebSocket for real-time interaction when both parties are online.

```rust
struct TransportManager {
    adapters: Vec<Box<dyn TransportAdapter>>,
    routing_policy: RoutingPolicy,    // which adapter(s) to use for which context

    async fn send(&self, context_id: &str, envelope: &EncryptedEnvelope) -> Result<Receipt> {
        // Route through one or more adapters based on policy
        let adapters = self.routing_policy.select(context_id, &self.adapters);
        // Send through all selected adapters (redundancy for reliability)
        futures::try_join_all(adapters.iter().map(|a| a.send(context_id, envelope))).await
    }
}
```

### 4.2 Platform Adapters

Platform adapters integrate the SDK with device-specific capabilities. These handle things the protocol needs but that vary by operating system.

**Interface contract:**

```rust
trait KeyCustodyAdapter {
    // Key generation and storage
    async fn generate_keypair(&self) -> Result<KeyHandle>;
    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature>;
    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey>;

    // Key custody never exposes private keys
    fn custody_type(&self) -> CustodyType;
}

trait DeviceAttestationAdapter {
    // Sybil resistance — prove this is a real device
    async fn attest(&self) -> Result<DeviceAttestation>;
    async fn verify(&self, attestation: &DeviceAttestation) -> Result<bool>;
}

trait PushNotificationAdapter {
    // Wake the app when messages arrive
    async fn register(&self) -> Result<PushToken>;
    async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal>;
}

trait SecureStorageAdapter {
    // Encrypted local storage for tokens, keys, state
    async fn store(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
}
```

**iOS / macOS adapter implementations:**

```rust
struct AppleKeyCustody {
    // Uses iOS Secure Enclave / macOS Secure Enclave via Security framework
}
impl KeyCustodyAdapter for AppleKeyCustody {
    async fn generate_keypair(&self) -> Result<KeyHandle> {
        // SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
        // Private key never leaves the Secure Enclave
    }
    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature> {
        // SecKeyCreateSignature — signing happens inside the Enclave
    }
    fn custody_type(&self) -> CustodyType { CustodyType::SecureEnclave }
}

struct AppleDeviceAttestation {
    // Uses Apple App Attest (DeviceCheck framework)
}
impl DeviceAttestationAdapter for AppleDeviceAttestation {
    async fn attest(&self) -> Result<DeviceAttestation> {
        // DCAppAttestService.generateKey + attestKey
        // Proves: real Apple device, not jailbroken, app is legitimate
    }
}

struct ApplePush {
    // APNs (Apple Push Notification service)
}
impl PushNotificationAdapter for ApplePush {
    async fn register(&self) -> Result<PushToken> {
        // UIApplication.registerForRemoteNotifications
        // Returns device token for APNs
    }
    async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal> {
        // Opaque wake signal — no content in push, just "you have messages"
        // App wakes, pulls encrypted envelopes from relays, decrypts locally
    }
}

struct AppleKeychain {
    // Uses iOS/macOS Keychain for encrypted local storage
}
impl SecureStorageAdapter for AppleKeychain {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        // SecItemAdd with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
}
```

**Android adapter implementations (future):**

```rust
struct AndroidKeyCustody {
    // Uses Android Keystore with StrongBox (hardware-backed)
}
impl KeyCustodyAdapter for AndroidKeyCustody {
    // KeyGenParameterSpec.Builder with setIsStrongBoxBacked(true)
    fn custody_type(&self) -> CustodyType { CustodyType::AndroidKeystore }
}

struct GooglePlayIntegrity {
    // Uses Google Play Integrity API
}
impl DeviceAttestationAdapter for GooglePlayIntegrity {
    // IntegrityManager.requestIntegrityToken
}

struct AndroidFCM {
    // Firebase Cloud Messaging
}
impl PushNotificationAdapter for AndroidFCM {
    // FirebaseMessaging.getInstance().token
}

struct AndroidKeystore {
    // EncryptedSharedPreferences or direct Keystore
}
impl SecureStorageAdapter for AndroidKeystore {}
```

### 4.3 MCP Adapter

The MCP adapter makes the SCP agent appear as an MCP server to local AI models. Models don't know about SCP — they see tools.

**Interface contract:**

```rust
trait MCPAdapter {
    // Expose SCP context tools as MCP tool schemas
    fn list_tools(&self, agent: &AgentInstance) -> Vec<MCPToolSchema>;

    // Route an MCP tool call to the appropriate SCP context and tool
    async fn call_tool(&self, agent: &AgentInstance, tool_name: &str, input: Value) -> Result<Value>;

    // Expose SCP context events as MCP resources
    fn list_resources(&self, agent: &AgentInstance) -> Vec<MCPResource>;
    async fn read_resource(&self, agent: &AgentInstance, uri: &str) -> Result<Value>;
}
```

**Implementation:**

```rust
struct SCPMCPAdapter {
    context_manager: Arc<ContextManager>,
    capability_cache: CapabilityCache,
}

impl MCPAdapter for SCPMCPAdapter {
    fn list_tools(&self, agent: &AgentInstance) -> Vec<MCPToolSchema> {
        // For each context the agent participates in:
        //   For each tool in that context:
        //     If the agent's role grants invoke capability:
        //       Expose as "{context_name}/{tool_name}" with the tool's JSON schema
        //
        // Tools the agent can't access are NEVER listed — the model doesn't know they exist

        let mut tools = vec![];
        for ctx in self.context_manager.contexts_for(agent) {
            for tool in ctx.tools() {
                if agent.can_invoke(&tool) {
                    tools.push(MCPToolSchema {
                        name: format!("{}/{}", ctx.display_name(), tool.name),
                        description: tool.description.clone(),
                        input_schema: tool.input_schema.clone(),  // MCP-compatible JSON Schema
                    });
                }
            }
            // Also expose SCP actions as tools
            if agent.can_write_messages(&ctx) {
                tools.push(MCPToolSchema {
                    name: format!("{}/send_message", ctx.display_name()),
                    description: "Send a message in this context".into(),
                    input_schema: message_schema(),
                });
            }
        }
        tools
    }

    async fn call_tool(&self, agent: &AgentInstance, tool_name: &str, input: Value) -> Result<Value> {
        // 1. Parse "{context_name}/{tool_name}"
        let (context_id, tool_id) = parse_namespaced_tool(tool_name)?;
        // 2. Validate capability token
        let token = self.capability_cache.get(agent, context_id, tool_id)?;
        // 3. Create SCP tool invocation
        let envelope = create_tool_invocation(agent, context_id, tool_id, &input, &token)?;
        // 4. Encrypt with context key (MLS)
        let encrypted = agent.encrypt(context_id, &envelope)?;
        // 5. Send via transport
        let receipt = self.context_manager.transport().send(context_id, &encrypted).await?;
        // 6. Wait for response, decrypt, return plain result to model
        let response = self.context_manager.await_response(receipt).await?;
        Ok(response.output)
    }
}
```

**What the AI model sees (MCP tool list):**

```
cooking_quest/send_message        — Send a message in this context
cooking_quest/guide_assistant     — AI cooking guide
cooking_quest/step_tracker        — Track quest progress
project/send_message              — Send a message in this context
project/schedule_meeting          — Schedule a meeting with participants
```

**What the AI model does NOT see** (filtered by role):

```
cooking_quest/admin_panel         — (agent's role is member, not admin)
cooking_quest/invite_member       — (agent lacks invite capability)
project/modify_governance         — (agent lacks governance capability)
```

### 4.4 Bridge Adapters

Bridge adapters connect external platforms to SCP contexts. Each adapter translates between a platform's native protocol and SCP's protocol semantics.

**Interface contract:**

```rust
trait BridgeAdapter {
    // Platform identity
    fn platform(&self) -> PlatformType;
    fn mode(&self) -> BridgeMode;       // relay, puppet, api, cooperative

    // Inbound: external platform → SCP context
    async fn poll_external(&self) -> Result<Stream<ExternalMessage>>;
    fn translate_inbound(&self, msg: &ExternalMessage) -> Result<BridgedContent>;

    // Outbound: SCP context → external platform
    async fn send_external(&self, content: &BridgedContent) -> Result<()>;

    // Shadow identity management
    async fn create_shadow(&self, external_id: &ExternalIdentity) -> Result<ShadowIdentity>;
    async fn resolve_shadow(&self, external_id: &ExternalIdentity) -> Result<Option<ShadowIdentity>>;

    // Lifecycle
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    fn health(&self) -> BridgeHealth;
}

struct BridgedContent {
    content: MessageContent,
    provenance: BridgeProvenance {
        platform: PlatformType,
        mode: BridgeMode,
        operator: DID,
        shadow: Option<ShadowIdentity>,
        external_timestamp: DateTime,
    },
}
```

**X (Twitter) bridge adapter (relay mode):**

```rust
struct XBridgeAdapter {
    bot_account: XBotCredentials,       // single bot account on X
    operator_did: DID,
    context_id: String,
    shadow_registry: ShadowRegistry,
}

impl BridgeAdapter for XBridgeAdapter {
    fn platform(&self) -> PlatformType { PlatformType::X }
    fn mode(&self) -> BridgeMode { BridgeMode::Relay }

    async fn poll_external(&self) -> Result<Stream<ExternalMessage>> {
        // Poll X API for mentions/replies to bot account
        // or stream via X API v2 filtered stream
    }

    fn translate_inbound(&self, msg: &ExternalMessage) -> Result<BridgedContent> {
        // 1. Resolve or create shadow identity for the X user
        let shadow = self.shadow_registry.resolve_or_create(&msg.author)?;
        // 2. Wrap content with bridge provenance
        Ok(BridgedContent {
            content: MessageContent::Text(msg.text.clone()),
            provenance: BridgeProvenance {
                platform: PlatformType::X,
                mode: BridgeMode::Relay,
                operator: self.operator_did.clone(),
                shadow: Some(shadow),
                external_timestamp: msg.created_at,
            },
        })
    }
}
```

**Bluesky / AT Protocol bridge adapter (API mode — trivial because AT Protocol is open):**

```rust
struct BlueskyBridgeAdapter {
    agent: AtprotoAgent,                // AT Protocol agent
    operator_did: DID,
    context_id: String,
}

impl BridgeAdapter for BlueskyBridgeAdapter {
    fn platform(&self) -> PlatformType { PlatformType::Bluesky }
    fn mode(&self) -> BridgeMode { BridgeMode::Api }

    // AT Protocol is open — full API access, no scraping needed
    // Firehose subscription for real-time inbound
    // Direct post creation for outbound
}
```

---

## 5. Build Order

### Phase 1: Prove the Crypto Works (Weeks 1-4)

Build a single Rust binary that:
1. Creates a DID (`did:key` for now, swap method later)
2. Creates an MLS group
3. Encrypts a message to the group
4. Wraps it in an SCP envelope
5. Publishes it as a Nostr event to a local relay
6. A second instance subscribes, receives, decrypts

**Deliverable:** Two terminals on one machine exchanging encrypted messages through a local Nostr relay. The relay has no idea what's inside. ~500 lines of Rust.

If this works, everything else is elaboration. If this doesn't work, the spec is fiction.

### Phase 2: Transport + Context Lifecycle (Weeks 5-8)

- Full transport abstraction interface
- Nostr adapter (production relay connections, multi-relay pool)
- Context create, join, leave, close state machine
- Role assignment and capability ceiling enforcement
- Tool registration and invocation
- Event log (append-only, Merkle tree integrity)

**Deliverable:** Two devices creating contexts, exchanging messages, invoking tools, with role-enforced permissions. All encrypted, through real Nostr relays.

### Phase 3: Trust + A2A (Weeks 9-12)

- UCAN capability token creation, validation, revocation
- Behavioral record computation from event logs
- Trust evaluation (four layers)
- Attestation creation and verification
- Context proposals (propose/accept/reject)
- TTL, memory scope, ephemeral key destruction
- Discovery (context-mediated first)
- Data provenance tagging

**Deliverable:** Agents discovering each other, proposing ephemeral contexts, negotiating, carrying provenance-tagged data between contexts. Full trust evaluation on every proposal.

### Phase 4: Platform Adapters + Swift SDK (Weeks 13-16)

- UniFFI bindings from Rust → Swift
- Swift-native API surface
- Apple platform adapters: Secure Enclave key custody, App Attest device attestation, APNs push, Keychain storage
- MCP adapter (so AI models can participate)
- App capability declaration contract

**Deliverable:** A Swift SDK that an iOS app (Cronica) can import. Identity, contexts, tools, trust, encryption — all handled by the SDK. AI models participate via MCP without knowing SCP exists.

### Phase 5: Cronica Integration + Bridge Adapters (Weeks 17-20)

- Cronica mapping: quests as contexts, AI Guide as institutional agent
- Bridge adapter interface
- X bridge adapter (relay mode)
- Bluesky bridge adapter (API mode)
- Registry context implementation (agent discovery)

**Deliverable:** Cronica runs on SCP. The AI Guide is a tool in quest contexts. Users have DIDs. Messages are E2E encrypted. X and Bluesky users can participate via bridges. Agents can discover each other through registry contexts.

---

## 6. Difficulty Assessment

| Component | Difficulty | Why |
|---|---|---|
| MLS integration | Medium | Libraries exist (OpenMLS), but group state management is fiddly — ratcheting, out-of-order messages, concurrent updates. |
| DID resolution (`did:dht`) | Medium | Newer method, fewer battle-tested libraries. `did:web` fallback is trivial. |
| Nostr adapter | Low | Mature ecosystem. Relay protocol is simple. Many client libraries. |
| Matrix adapter | Medium | Matrix client SDK is heavier. Room state management is more complex than Nostr events. |
| WebSocket adapter | Low | Standard library work. |
| UCAN validation | Medium | Chain validation, revocation checking, caching strategy for performance at scale. |
| Event log (Merkle tree) | Medium | Append-only is easy. Pruning, checkpoints, and proof generation for large contexts need care. |
| Ephemeral key destruction | Low | MLS handles this — destroy the group state. |
| Behavioral records | Medium-Hard | Computing records across multiple context logs, handling privacy (what's visible to whom), making it fast enough for real-time trust evaluation. |
| Platform adapters (Apple) | Low-Medium | Standard iOS APIs. Secure Enclave, App Attest, APNs are well-documented. |
| MCP adapter | Low | MCP is a simple JSON-RPC protocol. Mapping SCP tools to MCP schemas is straightforward. |
| Bridge adapters | Varies | Bluesky/Mastodon (easy, open APIs), X (medium, restricted API), WhatsApp (hard, reverse-engineered). |
| Offline/sync | Hard | The spec punts on this. Real devices go offline, come back, need to catch up. MLS has mechanisms but they're complex. |
| Push notifications | Low | APNs/FCM integration is standard. Opaque payload only. |
| UniFFI bindings | Low-Medium | UniFFI generates bindings automatically but async Rust → Swift async bridging needs care. |

---

## 7. What This Session Decided

| Decision | Choice | Alternatives Rejected |
|---|---|---|
| Group encryption | MLS (RFC 9420) | Sender Keys (O(n) removal), custom (unnecessary) |
| MLS implementation | OpenMLS (Rust) | mls-rs (less mature), MLS++ (C++, harder FFI) |
| DID method (target) | `did:dht` | `did:key` (no rotation), `did:web` (centralized), `did:ion` (Bitcoin dependency) |
| DID method (Cronica v1) | `did:web` (pragmatic, migrate later) | — |
| Primary transport | Nostr binding | Matrix (heavier), libp2p (more complex), custom (unnecessary) |
| Transport architecture | Abstraction + bindings (option 2 from session 02) | Pick one transport (option 3), define relay protocol (option 1) |
| Core language | Rust | Go (weaker crypto ecosystem), TypeScript (performance), Swift (not cross-platform) |
| Cross-platform bindings | UniFFI (Mozilla) | Manual FFI (fragile), cbindgen (C-only) |
| UCAN library | rs-ucan (Rust) [Note: replaced by native impl in scp-core/src/crypto/ucan/] | ucanto (TypeScript only) |

---

## 8. What This Session Did Not Cover

- **Specific DID:DHT library selection.** The `did:dht` ecosystem is newer; library maturity needs assessment.
- **Offline/sync strategy.** Acknowledged as hard. MLS has pending proposals and welcome messages for offline members, but the sync model for extended offline periods (days/weeks) is undesigned.
- **Event log pruning.** Merkle trees grow. The pruning/checkpoint strategy for long-lived contexts is unspecified.
- **Relay infrastructure for Cronica.** Who runs the Nostr relays for Cronica's initial deployment? Self-operated? Third-party? Both?
- **Android SDK timeline.** Rust core + UniFFI supports Kotlin, but the Android platform adapters (Keystore, Play Integrity, FCM) are unbuilt.
- **Web SDK feasibility.** Rust → WASM is proven (wasm-bindgen), but browser limitations (no Secure Enclave access, limited WebSocket, no background execution) affect what the web SDK can do.
- **CI/CD and testing infrastructure.** Integration tests for multi-party MLS, transport adapter conformance tests, etc.
- **Performance targets.** What latency is acceptable for context creation, message delivery, trust evaluation? No benchmarks defined.
