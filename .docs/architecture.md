# SCP System Architecture — Build Document

**Date:** February 21, 2026
**Status:** Buildable design — this document is the engineering blueprint
**Prerequisite reading:** specs/ (protocol design), sketch.md (API surfaces), planning-sessions/planning-session-04.md + planning-sessions/planning-session-06.md (technology decisions + resolved open questions)

---

## 1. System Architecture

### 1.1 High-Level Component Map

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  APPLICATIONS                                                      │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ App      │  │ 3rd-party│  │ Agent    │  │ Generated apps   │  │
│  │ Layer    │  │ apps     │  │ scripts  │  │ (LLM-built)      │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────────────┘  │
│       │              │              │              │                │
│  ═════╪══════════════╪══════════════╪══════════════╪════════════   │
│       │              │              │              │                │
│  ┌────┴──────────────┴──────────────┴──────────────┴────────────┐  │
│  │                                                               │  │
│  │                    SCP SDK                                    │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │  PUBLIC API LAYER (~30 methods)                         │ │  │
│  │  │                                                         │ │  │
│  │  │  Language bindings:                                     │ │  │
│  │  │  • Python (PyO3)  — agent ecosystem                    │ │  │
│  │  │  • Swift (UniFFI) — iOS/macOS                          │ │  │
│  │  │  • TypeScript (wasm-bindgen/napi-rs) — web/Node        │ │  │
│  │  │  • Kotlin (UniFFI) — Android                           │ │  │
│  │  │  • Rust (native)  — direct                             │ │  │
│  │  │  • Go (cbindgen)  — community SDK (Phase 5)            │ │  │
│  │  │  • C# (cbindgen)  — community SDK (Phase 5)            │ │  │
│  │  │  • Java (cbindgen) — community SDK (Phase 5)           │ │  │
│  │  └──────────────────────┬──────────────────────────────────┘ │  │
│  │                         │                                     │  │
│  │  ┌──────────────────────┴──────────────────────────────────┐ │  │
│  │  │  PROTOCOL ENGINE (Rust)                                 │ │  │
│  │  │                                                         │ │  │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ │ │  │
│  │  │  │ Context  │ │ Identity │ │ Trust    │ │ Discovery │ │ │  │
│  │  │  │ Manager  │ │ Manager  │ │ Engine   │ │ Engine    │ │ │  │
│  │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬─────┘ │ │  │
│  │  │       │             │             │              │       │ │  │
│  │  │  ┌────┴─────────────┴─────────────┴──────────────┴────┐ │ │  │
│  │  │  │  CRYPTO LAYER                                       │ │ │  │
│  │  │  │  MLS (OpenMLS) │ UCAN (rs-ucan) │ Merkle trees    │ │ │  │
│  │  │  └────────────────────────┬────────────────────────────┘ │ │  │
│  │  └──────────────────────────┼──────────────────────────────┘ │  │
│  │                              │                                │  │
│  │  ┌──────────────────────────┼──────────────────────────────┐ │  │
│  │  │  ADAPTER LAYER           │                               │ │  │
│  │  │                          │                               │ │  │
│  │  │  ┌──────────┐ ┌─────────┴┐ ┌──────────┐ ┌───────────┐ │ │  │
│  │  │  │Transport │ │ Platform │ │ MCP      │ │ Bridge    │ │ │  │
│  │  │  │          │ │          │ │          │ │           │ │ │  │
│  │  │  │ • SCP    │ │ • Keys   │ │ • Server │ │ • X       │ │ │  │
│  │  │  │   native │ │ • Attest  │ │ • Client │ │ • Bluesky │ │ │  │
│  │  │  │ • Nostr  │ │ • Push   │ │          │ │ • Discord │ │ │  │
│  │  │  │ • Matrix │ │ • Storage│ │          │ │           │ │ │  │
│  │  │  │ • Hyper* │ │          │ │          │ │           │ │ │  │
│  │  │  │ • libp2p │ │          │ │          │ │           │ │ │  │
│  │  │  │ • WS/RTC │ │          │ │          │ │           │ │ │  │
│  │  │  │ • +more  │ │          │ │          │ │           │ │ │  │
│  │  │  └──────────┘ └──────────┘ └──────────┘ └───────────┘ │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  INFRASTRUCTURE (not owned — existing)                      │    │
│  │                                                             │    │
│  │  SCP relays │ Nostr relays │ Mainline DHT │ APNs/FCM       │    │
│  │  Hyperswarm │ libp2p nodes │ Matrix homeservers             │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### 1.2 Data Flow: Message Lifecycle

A message from Alice to Bob in a shared context. Security checkpoints (§9) are annotated with 🔒.

```
Alice's app
    │
    ▼
SDK Public API: agent.send("hello")
    │
    ▼
Context Manager: validate membership, check role capabilities
    │
    ▼
UCAN Validator: verify capability token (scp:ctx:{id}/messages → write)
    │                 🔒 UCAN nonce uniqueness check (§9.5)
    ▼
Sequence Manager: assign SCP sequence number (per-sender monotonic)
    │                 🔒 Sequence continuity for suppression detection (§9.8.5)
    ▼
Event Log: append event, compute Merkle proof
    │
    ▼
Provenance Tagger: attach provenance metadata for cross-context data
    │
    ▼
Inner Envelope Builder: sign inside encrypted payload
    │  Sign: Ed25519 over SHA256(context_id || sender_did || epoch ||
    │         generation || sequence || timestamp || payload_hash)
    │           🔒 Ed25519 inner signature — member-only verifiable (§9.8.1)
    │           🔒 Timestamp for replay bounds (§9.8.2)
    ▼
Sender-Side Key Encrypt: AES-256-GCM with Alice's sender key (§9.16)
    │           🔒 Selective readability — blocked parties see opaque ciphertext
    ▼
Bucket Padding: pad to next boundary (256B/1KB/4KB/16KB/64KB/256KB)
    │           🔒 Fixed bucket sizes prevent message size analysis (§9.10.3)
    ▼
MLS Encrypt: encrypt with context group key (current epoch)
    │           🔒 Forward secrecy: old epoch keys already deleted (§9.7.2)
    │           🔒 MLS membership_tag HMAC — inner authentication (§9.8.1)
    │           🔒 MLS generation number assigned — replay prevention (§9.8.2)
    ▼
Outer Envelope Builder: minimal envelope — NO signature
    │  routing_id: per-context pseudonym (§9.10.4)
    │  recipient_hint: recipient's pseudonym or "*" for broadcast
    │  ttl: seconds until relay deletes blob
    │  blob: the encrypted payload
    ▼
Transport Adapter: publish to 3+ relays
    │           🔒 TLS 1.3 to all relays (§9.13)
    │           🔒 Multi-relay publishing for suppression resistance (§9.9.2)
    ▼
═══════════════════ NETWORK ═══════════════════
    │
    ▼
Relay: stores opaque blob (cannot read content, cannot verify sender)
    │           🔒 Relay threat model: can drop/delay/replay, cannot forge/decrypt (§9.9.1)
    ▼
Bob's Transport Adapter: receives via relay subscription (TLS 1.3)
    │
    ▼
Outer Envelope Parser: extract routing_id, look up context
    │
    ▼
Deduplication: check hash cache + sequence + timestamp bounds
    │           🔒 Three-layer replay prevention (§9.8.2):
    │             • Hash dedup: SHA256 of encrypted blob, 10K sliding window
    │             • Sequence: per-sender expected-next tracking (after decrypt)
    │             • Timestamp: 5-min future bound, monotonic per-sender (after decrypt)
    ▼
MLS Decrypt: decrypt with Bob's leaf key in the group tree
    │           🔒 MLS membership_tag verification — sender is group member (§9.8.1)
    │           🔒 MLS generation number check — reject within-epoch replays (§9.8.2)
    ▼
Bucket Unpad: strip padding to recover plaintext size
    │
    ▼
Sender-Side Key Decrypt: AES-256-GCM with sender's cached key (§9.16)
    │
    ▼
Inner Envelope Verify: verify Ed25519 signature over payload
    │           🔒 Ed25519 inner signature — reject forged envelopes (§9.8.1)
    ▼
UCAN Validator: verify sender's capability token
    │           🔒 UCAN signature chain + nonce validation (§9.5)
    ▼
Event Log: append to local log, verify Merkle consistency
    │           🔒 Periodic consistency checkpoint comparison (§9.9.3)
    ▼
Context Manager: deliver to context, check provenance
    │
    ▼
SDK Public API: callback/stream delivers "hello" to Bob's app
```

**Security checkpoint count:** 14 independent verification steps protect each message in Encrypted mode. The two most critical are Ed25519 inner signature and MLS membership_tag — two independent integrity checks (identity key and MLS epoch secrets), both inside encryption, both member-only verifiable. Relays see only opaque blobs and cannot verify, forge, or inspect any message content or metadata.

**Broadcast mode (§5.14):** The message lifecycle differs — MLS Encrypt/Decrypt steps are replaced by per-author AES-256-GCM broadcast key encryption. There is no MLS membership_tag (authentication is signature-only via Ed25519). The routing_id is publicly derived as SHA-256(context_id) rather than HKDF-derived. Author identity is visible in the outer envelope (authors are public figures in broadcast contexts). See §5.14.5 for the BroadcastEnvelope format and send/receive paths.

### 1.3 Data Flow: MCP Integration

```
┌─────────────────────────────────────────────────────────────┐
│  LOCAL DEVICE                                                │
│                                                              │
│  ┌───────────────┐                                          │
│  │  AI Model     │   "Call context_a/guide_assistant        │
│  │  (Claude,     │    with query='butter substitute'"       │
│  │   GPT, etc.)  │                                          │
│  └──────┬────────┘                                          │
│         │ MCP JSON-RPC                                       │
│         ▼                                                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │  SCP MCP Adapter (acts as MCP server)             │       │
│  │                                                    │       │
│  │  mcp.tools.list() → only tools this agent can use │       │
│  │  mcp.tools.call() → route to SCP context + tool   │       │
│  │                                                    │       │
│  │  Invisible to model:                               │       │
│  │  • DID authentication                              │       │
│  │  • UCAN capability validation                      │       │
│  │  • MLS encryption                                  │       │
│  │  • Transport routing                               │       │
│  │  • Provenance attachment                           │       │
│  └──────┬───────────────────────────────────────────┘       │
│         │ SCP protocol                                       │
│         ▼                                                    │
│  ┌──────────────────────────────────────────────────┐       │
│  │  SCP SDK (Protocol Engine)                        │       │
│  └──────┬───────────────────────────────────────────┘       │
│         │                                                    │
└─────────┼────────────────────────────────────────────────────┘
          │ encrypted envelopes
          ▼
    SCP relays / transport
```

The model never knows SCP exists. It sees MCP tools namespaced by context. The MCP adapter handles the translation. This means every existing MCP-compatible model is already compatible with SCP — zero integration work on the model side.

### 1.4 WebMCP + UCP Integration Points

```
Browser-based SCP agent
         │
         ├──── WebMCP (navigator.modelContext)
         │     Websites expose structured tools to the agent.
         │     SCP wraps these with provenance: "tool from example.com,
         │     invoked in context X, by agent Y"
         │
         ├──── UCP (Universal Commerce Protocol)
         │     Agent transacts on behalf of human.
         │     SCP provides: identity (DID), trust evaluation of merchant,
         │     capability ceiling (spending limits), audit trail (event log)
         │
         └──── MCP (local tools)
               Agent uses local tools via MCP.
               SCP provides: same identity, trust, audit.
```

SCP doesn't implement MCP, WebMCP, or UCP. It wraps them with identity, trust, and accountability. An agent using UCP to buy something does so with an SCP DID, under UCAN capability constraints (spending limit), and the transaction is recorded in the context event log.

---

## 2. SDK Internal Architecture

### 2.1 Crate Structure (Rust)

```
scp/
├── crates/
│   ├── scp-core/              # Protocol engine — the heart
│   │   ├── context/           # Context lifecycle, membership, roles, governance
│   │   ├── identity/          # DID operations, key management
│   │   ├── trust/             # 4-layer trust evaluation, behavioral records
│   │   ├── discovery/         # Tool-interface discovery (§6.2.2)
│   │   ├── crypto/            # MLS wrapper, UCAN wrapper, Merkle trees
│   │   ├── envelope/          # SCP envelope creation, parsing, validation
│   │   ├── provenance/        # Data provenance tagging
│   │   ├── event_log/         # Append-only verifiable log
│   │   └── store/             # ProtocolStore — typed domain storage (§17.4)
│   │
│   ├── scp-transport/         # Transport abstraction + adapters
│   │   ├── trait.rs           # TransportAdapter trait
│   │   ├── native/            # SCP native relay adapter (canonical reference)
│   │   ├── nostr/             # Nostr adapter
│   │   ├── matrix/            # Matrix adapter
│   │   ├── hyperswarm/        # Holepunch/Hyperswarm adapter (DHT + NAT traversal)
│   │   ├── libp2p/            # libp2p adapter (modular p2p)
│   │   ├── websocket/         # Direct WebSocket (testing/local)
│   │   ├── webrtc/            # WebRTC adapter (browser p2p)
│   │   └── manager.rs         # Multi-transport routing
│   │
│   ├── scp-platform/          # Platform-specific adapters
│   │   ├── trait.rs           # KeyCustody, DeviceAttestation, Push, Storage traits
│   │   ├── apple/             # Secure Enclave, App Attest, APNs, Keychain
│   │   ├── android/           # Keystore, Play Integrity, FCM
│   │   ├── web/               # WebCrypto, ServiceWorker, IndexedDB
│   │   └── testing/           # In-memory implementations for tests
│   │
│   ├── scp-mcp/               # MCP adapter
│   │   ├── server.rs          # SCP agent as MCP server
│   │   └── client.rs          # SCP agent as MCP client (consuming tools)
│   │
│   ├── scp-bridge/            # Bridge adapters
│   │   ├── trait.rs           # BridgeAdapter trait
│   │   ├── x/                 # X/Twitter bridge
│   │   ├── bluesky/           # Bluesky/AT Protocol bridge
│   │   └── shadow.rs          # Shadow identity management
│   │
│   ├── scp-testing/            # Network simulation test harness (§16, dev-dependency)
│   │   ├── clock.rs           # SimulatedClock (manual time control)
│   │   ├── relay/             # InMemoryRelay, BlobStore, BehaviorMode, SubscriptionRegistry
│   │   ├── transport.rs       # InMemoryTransport (TransportAdapter over InMemoryRelay)
│   │   ├── simulator/         # NetworkSimulator, SimulatedIdentity, NetworkTopology
│   │   ├── builder.rs         # ScenarioBuilder (fluent API for test setup)
│   │   ├── assertions/        # Distributed invariant checks (Merkle, delivery, ordering, etc.)
│   │   ├── presets.rs         # Canned scenarios (two_party_basic, suppression_scenario, etc.)
│   │   └── conformance/       # Trait conformance macros (transport, storage, key_custody, etc.)
│   │
│   ├── scp-ffi/               # Foreign function interface layer
│   │   ├── uniffi/            # UniFFI definitions → Swift, Kotlin
│   │   └── pyo3/              # PyO3 definitions → Python
│   │
│   ├── scp-ffi-cbindgen/      # C ABI bridge (cbindgen) → Go, C#, Java
│   │
│   ├── scp-ffi-wasm/          # WebAssembly bridge (wasm-bindgen) → browser TypeScript
│   │
│   ├── scp-ffi-napi/          # Node.js bridge (napi-rs) → Node TypeScript
│   │
│   └── scp-cli/               # CLI tool for testing/development
│       └── main.rs
│
├── bindings/
│   ├── python/                # Python package (scp-sdk)
│   │   ├── scp_sdk/
│   │   │   ├── __init__.py    # Re-exports
│   │   │   ├── identity.py    # Pythonic wrappers
│   │   │   ├── context.py
│   │   │   ├── trust.py
│   │   │   └── discovery.py
│   │   ├── pyproject.toml
│   │   └── README.md
│   │
│   ├── typescript/            # TypeScript package (@scp/sdk)
│   │   ├── src/
│   │   │   ├── index.ts
│   │   │   ├── identity.ts
│   │   │   ├── context.ts
│   │   │   └── wasm.ts        # WASM bridge
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── swift/                 # Swift package (generated by UniFFI)
│   │   └── Sources/SCP/
│   │
│   ├── kotlin/                # Kotlin package (generated by UniFFI)
│   │   └── com/limn/scp/
│   │
│   ├── go/                    # Go package (via scp-ffi-cbindgen C ABI, Phase 5)
│   │   └── scp/
│   │
│   ├── csharp/                # C# package (via scp-ffi-cbindgen C ABI, Phase 5)
│   │   └── SCP/
│   │
│   └── java/                  # Java package (via scp-ffi-cbindgen C ABI, Phase 5)
│       └── com/limn/scp/
│
├── .docs/                     # Project knowledge (specs, ADRs, planning, standards)
│   ├── specs/                 # Protocol specification (modular, one file per topic)
│   ├── adrs/                  # Architecture Decision Records
│   ├── architecture.md        # This document
│   └── sketch.md              # API surface sketches
│
├── examples/
│   ├── python/
│   │   ├── hello_scp.py       # Minimal: create identity, create context
│   │   └── mcp_agent.py       # Agent that exposes SCP tools via MCP
│   │
│   ├── typescript/
│   │   └── hello_scp.ts
│   │
│   └── swift/
│       └── ExampleContext.swift # Quest-style context example
│
└── tests/
    ├── integration/           # Multi-party tests
    │   ├── two_party_messaging.rs
    │   ├── ephemeral_key_destruction.rs
    │   └── mcp_bridge.rs
    │
    └── conformance/           # Protocol conformance tests
        ├── envelope_format.rs
        ├── ucan_validation.rs
        └── merkle_integrity.rs
```

### 2.2 Protocol Engine Components

Each component has a defined responsibility boundary and communicates with others through typed Rust interfaces.

**ProtocolStore** — typed domain storage layer (§17.4):

```
Responsibilities:
  • Maps all structured protocol operations to flat KV Storage calls
  • Key convention enforcement (§17.3): {namespace}/{entity_id}/{sub_key}
  • Serialization: MessagePack with version envelopes (StoredValue<T>)
  • Lazy on-read migration (§17.10)
  • Context cleanup via delete_prefix
  • UCAN nonce replay prevention via exists check
  • OpenMLS StorageProvider bridge (§17.9)

Depends on:
  • Platform Adapter (Storage trait — 6 async methods)

State:
  • All protocol state flows through ProtocolStore to Storage:
    context state, membership, sender keys, event logs, nonces,
    DID cache, TOFU records, tools, sessions, relay scores, identity
```

**Context Manager** — the central coordinator:

```
Responsibilities:
  • Context create / join / leave / close state machine
  • ContextMode dispatch: Encrypted (MLS) vs. Broadcast (per-author keys, §5.14)
  • Membership tracking (who's in, what role)
  • Role and capability ceiling enforcement
  • Tool registration and invocation routing
  • Governance proposal processing
  • TTL timer management and expiry handling
  • Memory scope enforcement (key destruction triggers)

Depends on:
  • Crypto Layer (MLS group management, UCAN validation)
  • Identity Manager (DID resolution, agent instantiation)
  • Transport Adapter (envelope delivery)
  • Event Log (append events, generate proofs)
  • ProtocolStore (context state persistence — §17.4)

State:
  • Active contexts (in-memory + persisted via ProtocolStore)
  • TTL timers
  • Role/capability maps per context
```

**Identity Manager:**

```
Responsibilities:
  • DID creation (did:dht primary, did:web fallback only)
  • DID resolution with security verification (§9.6)
    - did:dht: self-certification check (BEP44 signature + sequence number)
    - did:web: TLS pinning + TOFU key recording + key change alerts
  • Key rotation (triggers MLS Update in all active contexts — §9.7.4)
  • Key Continuity Verification — safety numbers (§9.11)
  • Compromise recovery flow orchestration (§9.12)
  • KeyPackage management — publish/rotate pre-key bundles on relays (§9.7.4)
  • Attestation creation/verification/revocation
  • Identity private state (block lists, mute lists, preferences)
  • Agent instantiation per context

Depends on:
  • Platform Adapter (key custody — Secure Enclave / Keystore)
  • Crypto Layer (signing, key derivation, MLS KeyPackage generation)
  • Transport Adapter (DID document publication, KeyPackage distribution)

State:
  • Local DID document
  • Key handles (never raw keys — always via platform adapter)
  • TOFU key records — first-seen keys for contacts (§9.6.4)
  • Verification records — which contacts have been verified out-of-band (§9.11)
  • KeyPackage buffer (recommended 10 per relay — §9.7.4)
  • Attestation cache
  • Private state log (encrypted, synced across devices)
```

**Trust Engine:**

```
Responsibilities:
  • Four-layer trust evaluation
  • Behavioral record computation from event logs
  • Attestation validation (signature + evidence + freshness)
  • Discovery provenance evaluation
  • Endorsement tracking and accuracy computation
  • Challenge-response protocol

Depends on:
  • Event Log (behavioral data source)
  • Identity Manager (attestation verification)
  • Context Manager (context membership data)

State:
  • Behavioral record cache (computed, not stored)
  • Trust evaluation cache (TTL-based)
```

**Discovery Engine:**

```
Responsibilities:
  • DID document capability resolution — resolve capabilities from DID service arrays
  • Discovery context management — join/leave discovery contexts, bootstrap defaults
  • Unified search — merge results from local contacts and discovery contexts
  • Agent registration/deregistration in discovery contexts
  • Local contact index — cache of resolved DID documents for instant lookup

Depends on:
  • Context Manager (discovery contexts are standard contexts — join, tool invocation)
  • Identity Manager (DID resolution for capability lookup, DID document updates)
  • Transport Adapter (DID document publication)

State:
  • Local contact index (cached DID documents, TTL-based refresh)
  • Known discovery context IDs (defaults + user-added)
  • Registration state per discovery context
```

**Crypto Layer** (wraps external libraries — see .docs/specs/09-security-model.md §9.5 for primitive specification, §9.7 for MLS integration):

```
┌─────────────────────────────────────────────────────────────────┐
│  Crypto Layer                                                    │
│  Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519     │
│  Single ciphersuite for v1 — no negotiation (§9.5)              │
│                                                                  │
│  ┌──────────────────────┐  ┌──────────────────────┐            │
│  │ MLS Module            │  │ UCAN Module          │            │
│  │ (OpenMLS)             │  │ (rs-ucan)            │            │
│  │                       │  │                      │            │
│  │ • create_group        │  │ • create_token       │            │
│  │ • add_member          │  │   (mandatory nonce)  │            │
│  │   (Welcome + HPKE)    │  │ • validate_chain     │            │
│  │ • remove_member       │  │ • check_revocation   │            │
│  │   (Commit + epoch     │  │ • delegate           │            │
│  │    advance)           │  │                      │            │
│  │ • encrypt             │  └──────────────────────┘            │
│  │   (+ membership_tag)  │                                      │
│  │ • decrypt             │  ┌──────────────────────┐            │
│  │   (verify gen number) │  │ Security Module      │            │
│  │ • ratchet (epoch      │  │ (NEW — §9)           │            │
│  │   advance, old keys   │  │                      │            │
│  │   MUST be deleted)    │  │ • dedup_check        │            │
│  │ • update (PCS —       │  │   (hash + seq +      │            │
│  │   recommended 24h)    │  │    timestamp)        │            │
│  │ • publish_keypackages │  │ • verify_continuity  │            │
│  │ • destroy_keys        │  │   (safety numbers)   │            │
│  │   (+ platform attest) │  │ • generate_checkpoint│            │
│  └──────────────────────┘  │   (relay consistency) │            │
│                             │ • verify_checkpoint   │            │
│  ┌──────────────────────┐  │ • initiate_recovery   │            │
│  │ Merkle Module         │  │ • destroy_attest     │            │
│  │                       │  │   (ephemeral keys)   │            │
│  │ • append              │  └──────────────────────┘            │
│  │ • prove               │                                      │
│  │ • verify              │  ┌──────────────────────┐            │
│  │ • checkpoint          │  │ Envelope Module      │            │
│  │   (for relay          │  │                      │            │
│  │    consistency §9.9)  │  │ • create             │            │
│  └──────────────────────┘  │ • parse              │            │
│                             │ • sign (Ed25519 —    │            │
│                             │   binds all fields)  │            │
│                             │ • verify_signature   │            │
│                             └──────────────────────┘            │
│                                                                  │
│  MLS ↔ SCP concept mapping (§9.7.1):                            │
│    MLS Group       = SCP Context                                 │
│    MLS Member      = SCP Agent (DID + context role)              │
│    MLS Epoch       = SCP Context epoch                           │
│    MLS DS          = SCP relay(s) — explicitly untrusted         │
│    MLS AS          = DID resolution + UCAN validation            │
│    MLS KeyPackage  = Pre-key bundle for offline member addition  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**MLS Module responsibilities (§9.7):**
- One MLS group per SCP context in Encrypted mode (1:1 mapping)
- Forward secrecy: SDK MUST delete old epoch keys after Commit (§9.7.2)
- Post-compromise security: SDK MUST issue periodic MLS Updates, recommended every 24 hours (§9.7.3)
- Key lifecycle: generation (HSM-backed), distribution (KeyPackages on relays), rotation (DID update → MLS Update in all contexts), destruction (platform-attested, §9.15)
- Broadcast mode (§5.14) does NOT use MLS — it substitutes per-author AES-256-GCM broadcast keys with a pull-based key distribution protocol (identical to sender keys §9.16.2). Broadcast contexts have no MLS group, no forward secrecy (mitigated by epoch rotation on block events), and public routing_id = SHA-256(context_id).

**Security Module responsibilities (§9.8–§9.12):**
- Three-layer replay prevention: MLS generation numbers + hash dedup (10K cache) + timestamp bounds (5-min tolerance)
- Key Continuity Verification: Signal-style safety numbers for DID verification (§9.11)
- Relay Consistency Protocol: periodic Merkle root comparison for equivocation detection (§9.9.3)
- Compromise recovery: ordered key rotation across all contexts (§9.12)
- Ephemeral key destruction with platform attestation (§9.15)

### 2.3 Dependency Graph

```
                    scp-cli
                      │
                      ▼
              ┌── scp-ffi ──┐
              │   (PyO3 +   │
              │   UniFFI)   │
              └──────┬──────┘
                     │
                     ▼
               scp-core ◄─────────── scp-mcp
              ╱    │    ╲
             ╱     │     ╲
            ▼      ▼      ▼
    scp-transport  │  scp-bridge
            │      │      │
            ▼      ▼      ▼
         scp-platform (traits)
              │
              ▼
     platform implementations
     (apple / android / web / testing)

   scp-testing (dev-dependency, §16)
        │
        ├──► scp-core
        ├──► scp-transport
        └──► scp-platform
```

Build order follows the dependency graph bottom-up: platform traits → transport → core → FFI → bindings.

`scp-testing` is a dev-dependency only — it depends on core, transport, and platform but is never imported by production code. It provides the network simulation harness (InMemoryRelay, InMemoryTransport, SimulatedClock, ScenarioBuilder), trait conformance test macros, and distributed assertion utilities. See `.docs/specs/16-test-infrastructure.md` for the full specification.

### 2.4 Context Nesting

Contexts can form parent-child relationships (spec §5.13, ADR-008 `nesting.rs`). A child context is a full context — its own MLS group, event log, governance, roles, tools, ceiling, and membership — structurally and cryptographically linked to one or more parents.

**Single-parent nesting** creates sub-spaces within a context: per-task rooms, per-topic channels, breakout sessions. The child narrows the parent's scope. **Multi-parent nesting** creates a governed bridge between contexts — a shared collaboration space where members from different parent contexts interact as peers. This is the symmetric complement to tool interfaces (§6.2): tool interfaces are asymmetric and per-call; multi-parent children are symmetric and persistent.

**Ceiling inheritance.** A child's capability ceiling must be less than or equal to the intersection of all parent ceilings. This is enforced at creation time and prevents capability escalation through nesting. If a parent ceiling shrinks post-creation, the child ceiling is retrospectively reduced to maintain the invariant.

**Membership eligibility.** A member must belong to at least one parent to be eligible for the child. Eligibility is continuous — removal from a member's only parent triggers eviction from the child (MLS `remove_member`, sender key rotation, event log entry). Joining a child never grants membership in any parent, and child membership never confers eligibility for siblings.

**Lifecycle coupling.** No orphans: when the last parent closes, the child closes regardless of configuration. TTL inheritance bounds a child's TTL by the minimum parent TTL. Each parent's `on_sever` behavior is configurable independently — `cascade_close` (child closes), `evict_unique_members` (remove members eligible only through the severed parent), or `preserve_membership` (child continues, members keep their seats).

**Parent governance configuration.** Per-parent authority is configured at creation time and immutable thereafter. Configurable permissions include `canCloseChild`, `canEvictMembers`, `canRestrictCeiling`, and `requiresApprovalFor` (governance changes, tool registration, ceiling changes, membership changes). Both parents see and consent to each other's configuration before the child is created.

**Cryptographic binding.** Parent context IDs and the content hash of the parent governance configuration are included in the MLS `group_context` extensions field. The child's `group_id` is derived from this `group_context`, making the parent lineage part of the cryptographic group identity. Lineage is unforgeable — claiming different parents would require a different MLS group. Two independent verification paths (MLS `group_context` and Merkle-tree event log) must both be compromised to forge lineage.

**Depth limit.** The protocol enforces a maximum nesting depth as a protocol constant (suggested default: 3 levels). This bounds governance complexity, ceiling narrowing (deep nesting converges on empty ceilings), lifecycle cascade depth, and provenance evaluation cost.

---

## 3. Language Binding Design

### 3.1 Python SDK (Primary — Agent Ecosystem)

The Python SDK is the most critical binding. The agent ecosystem is Python. If the Python SDK is awkward, SCP fails.

**Design principles:**
- Pythonic. async/await. Type hints. No Rust concepts leaking through.
- `pip install scp-sdk` installs a wheel with the Rust binary embedded (via maturin/PyO3).
- Zero Rust toolchain required for users.

**The 20-line agent:**

```python
import scp

# Create or load identity
identity = await scp.Identity.create(custody="platform")

# Create a context
ctx = await scp.Context.create(
    creator=identity,
    ceiling=["messaging", "tool_invocation"],
    tools=[scp.Tool("assistant", schema={"query": "string"})],
)

# Agent sends a message
await ctx.send("Hello from Python")

# Agent invokes a tool
result = await ctx.invoke("assistant", {"query": "help me"})
```

**MCP server in Python (expose SCP agent to any AI model):**

```python
import scp
from scp.mcp import serve_mcp

identity = await scp.Identity.load()

# Start an MCP server that exposes all SCP contexts as tools
server = await serve_mcp(identity, host="localhost", port=8080)
# Any MCP client (Claude, GPT, etc.) can now connect and see:
#   context_a/send_message
#   context_a/guide_assistant
#   context_b/schedule_meeting
# The model calls these as normal MCP tools.
# SCP handles identity, encryption, trust, transport.
```

**LangChain integration:**

```python
from langchain.tools import BaseTool
from scp.integrations.langchain import SCPToolkit

# Create SCP toolkit for LangChain agent
toolkit = SCPToolkit(identity=my_identity, contexts=[ctx_a, ctx_b])

# Returns LangChain-compatible tools for each SCP context tool
tools = toolkit.get_tools()

# Use with any LangChain agent
agent = create_react_agent(llm, tools)
agent.invoke({"input": "Schedule a meeting with Bob"})
```

**PyO3 bridge layer:**

```
Python (scp_sdk/)              PyO3 (scp-ffi/pyo3/)         Rust (scp-core/)

scp.Identity.create()    →    py_identity_create()     →    Identity::create()
scp.Context.create()     →    py_context_create()      →    ContextManager::create()
ctx.send()               →    py_context_send()        →    Context::send()
ctx.invoke()             →    py_tool_invoke()         →    Context::invoke_tool()
```

PyO3 handles the Rust↔Python boundary: async (tokio↔asyncio), error conversion (Result↔Exception), type mapping (structs↔dataclasses). The Python layer adds ergonomics (method chaining, context managers, iterators) without reimplementing logic.

### 3.2 TypeScript SDK (Web + Node)

```typescript
import { SCP } from '@scp/sdk';

// Node.js / Deno
const identity = await SCP.Identity.create({ custody: 'platform' });
const ctx = await SCP.Context.create({
  creator: identity,
  ceiling: ['messaging'],
});
await ctx.send('Hello from TypeScript');

// Browser (WASM)
// Same API, backed by WebCrypto for keys, IndexedDB for storage
const identity = await SCP.Identity.create({ custody: 'webcrypto' });
```

TypeScript uses wasm-bindgen for the browser (Rust → WASM) and napi-rs for Node.js (Rust → native addon). Same Rust core, different FFI paths.

### 3.3 Swift SDK (iOS/macOS)

```swift
import SCP

let identity = try await SCP.Identity.create(custody: .secureEnclave)

let quest = try await SCP.Context.create(
    creator: identity,
    ceiling: [.messaging, .toolInvocation, .media],
    tools: [guideAssistant, stepTracker],
    metadata: .init(name: "Thai Cooking Quest", isPublic: true)
)

// AI guide agent joins the context
try await quest.addMember(guideAgent, role: "guide")

// User's agent invokes the guide
let advice = try await quest.invoke("guide_assistant", input: ["query": "where to start?"])
```

Swift bindings are generated by UniFFI from Rust. Swift-specific ergonomics (Combine publishers, SwiftUI integration) are added in a thin Swift wrapper layer.

### 3.4 Go, C#, Java SDKs (Community — Phase 5)

Go, C#, and Java bindings use the `scp-ffi-cbindgen` crate, which exposes a C ABI via cbindgen. Each language wraps the C interface with idiomatic bindings:

- **Go** — uses cgo to call the C ABI. Thin Go package in `bindings/go/scp/`.
- **C#** — uses P/Invoke to call the C ABI. Package in `bindings/csharp/SCP/`.
- **Java** — uses JNI/JNA to call the C ABI. Package in `bindings/java/com/limn/scp/`.

These are Phase 5 deliverables (community SDKs). The C ABI is stable and versioned; community-maintained wrappers can evolve independently. The same trait conformance suites (storage, key custody) apply through the cbindgen bridge.

---

## 4. Build Phases

### Phase 1: Crypto Proof

**Goal:** Prove the crypto stack works. Two Rust processes exchange encrypted messages through a local SCP relay.

```
Build:
  • scp-core/crypto/ — MLS wrapper (OpenMLS), UCAN wrapper (rs-ucan)
  • scp-core/envelope/ — SCP envelope creation, signing, verification
  • scp-core/identity/ — DID creation (did:dht)
  • scp-core/clock.rs — Clock trait + SystemClock (§16.3)
  • scp-transport/native/ — SCP native relay adapter (single relay)
  • scp-transport/native/blob_store.rs — BlobStore trait (§16.4.1)
  • scp-platform/testing/ — In-memory key storage (delete_prefix, exists — §17.2)
  • scp-core/store/ — Skeleton ProtocolStore (§17.4)
  • scp-core/crypto/mls/storage.rs — MlsStorageBridge (§17.9)
  • scp-testing/ — Network simulation harness (§16): InMemoryRelay, InMemoryTransport,
    SimulatedClock, ScenarioBuilder, assertion library, trait conformance macros, presets

Test:
  • Process A creates MLS group, encrypts message, publishes to local SCP relay
  • Process B subscribes, receives, decrypts
  • Relay has no idea what's inside
  • Network simulator: N-party scenarios with fault injection, suppression detection,
    equivocation detection, and deterministic time control (§16.13.1-6)
  • Trait conformance suites pass for all in-memory implementations (§16.12)
  • MlsStorageBridge: MLS group state roundtrips through bridge, state isolated
    per context (§16.13.8)
  • Assertion library meta-tests: each assert_* function (§16.10) verified against
    known-good inputs (should pass) and known-bad inputs (should return correct error
    variant). Prevents silent assertion bugs from masking protocol failures.
  • All §16.11 preset scenarios build and produce deterministic results with fixed seeds

Deliverable: ~500 lines of Rust. Two terminals exchanging encrypted messages.
  scp-testing harness verified by meta-tests before protocol tests depend on it.
```

### Phase 2: Context + Transport

**Goal:** Full context lifecycle over real SCP relays.

```
Build:
  • scp-core/context/ — create, join, leave, close state machine
  • scp-core/context/ — role assignment, capability ceiling enforcement
  • scp-core/context/ — tool registration and invocation
  • scp-core/event_log/ — Merkle tree, append, prove, verify
  • scp-core/store/ — Full ProtocolStore with all domain methods (§17.4)
  • scp-platform/ — SqliteStorage (bundled-sqlcipher, WAL mode — §17.6)
  • scp-platform/ — FilesystemStorage (§17.6)
  • scp-transport/ — transport abstraction trait
  • scp-transport/native/ — production SCP relay pool, multi-relay
  • scp-transport/native/ — SqliteBlobStore, RedbBlobStore (§17.7)
  • scp-transport/websocket/ — direct device-to-device (for testing)
  • scp-core/context/ — ContextMode::Broadcast (§5.14): per-author AES-256-GCM keys,
    BroadcastEnvelope, author/subscriber roles, public routing_id = SHA-256(context_id),
    open and gated subscriber registration, TTL enforcement for broadcast contexts

Test:
  • Two devices create context, exchange messages, invoke tools
  • Role enforcement: member can't do admin things
  • Event log integrity verification
  • Multi-relay delivery (send to 3 relays, receive from any)
  • Context state persists across process restarts (SqliteStorage)
  • ProtocolStore integration tests: lifecycle, nonces, event range queries (§17.13)
  • MlsStorageBridge tests (§16.13.8) gated against SqliteStorage
  • All new Storage/BlobStore adapters pass conformance suites
  • Block enforcement: assert_block_enforced (§16.10.6) — sender key rotation
    prevents blocked identity from decrypting, other members unaffected
  • Broadcast mode: author publishes broadcast-key-encrypted content, subscriber
    requests key and decrypts, author key epoch rotation on block events,
    open vs. gated subscriber registration, public routing_id derivation
  • Pseudonym unlinkability: assert_pseudonym_unlinkability (§16.10.5) — routing IDs
    across contexts are cryptographically unlinkable

Deliverable: Two devices with full context lifecycle over real SCP relays.
  Persistent storage for all protocol state.
```

### Phase 3: Python SDK + MCP

**Goal:** `pip install scp-sdk` works. Agents can use SCP from Python. MCP bridge works.

```
Build:
  • scp-ffi/pyo3/ — PyO3 bridge layer
  • bindings/python/ — Pythonic wrappers, async, type hints
  • scp-mcp/server.rs — SCP agent as MCP server
  • scp-mcp/client.rs — SCP agent as MCP client
  • scp-core/crypto/ucan/ — basic UCAN validation (full 4-layer trust is later)
  • Build infrastructure: maturin for Python wheel builds

Test:
  • `pip install scp-sdk` on clean Python venv
  • 20-line agent script works
  • MCP server exposes SCP tools to Claude/GPT
  • Integration test: LangChain agent using SCP tools
  • FFI conformance: storage_conformance!() and key_custody_conformance!() pass
    through PyO3 bridge — verifies the FFI layer doesn't corrupt trait contracts

Ship:
  • PyPI: scp-sdk v0.1.0
  • GitHub: open source the repo
  • Documentation: quickstart, API reference, examples

Deliverable: Working Python SDK on PyPI. Open source. Agents can use SCP.
```

### Phase 4: Trust + TypeScript

**Goal:** Full trust model, advanced context policies, TypeScript SDK.

```
Build:
  • scp-core/trust/ — four-layer evaluation, behavioral records
  • scp-core/context/ — advanced memory scope policies (basic TTL enforcement is Phase 2)
  • scp-core/discovery/ — tool-interface discovery (§6.2.2)
  • scp-core/provenance/ — data provenance tagging
  • scp-ffi/uniffi/ — UniFFI definitions (prepares Swift/Kotlin)
  • bindings/typescript/ — TypeScript SDK (wasm-bindgen for browser, napi-rs for Node)

Test:
  • Key destruction: SimulatedClock advance triggers context expiry (§16.3),
    verify ephemeral context keys are unrecoverable via MLS group state query
  • Advanced memory scope: governance-driven memory scope policy changes, nested context
    TTL inheritance, memory scope enforcement across multi-parent children
  • Trust evaluation: behavioral records persisted via ProtocolStore, trust scores
    affect context admission decisions, tested through N-party simulation
  • Discovery: tool-interface discovery (§6.2.2) returns correct results across
    contexts with different capability ceilings
  • TypeScript: same test suite as Python, in TypeScript
  • WASM conformance: WasmSqliteStorage (§17.6) passes storage_conformance!()
    through wasm-bindgen bridge

Ship:
  • PyPI: scp-sdk v0.2.0 (with trust model)
  • npm: @scp/sdk v0.1.0

Deliverable: Trust model works. TypeScript SDK ships. Two languages supported.
```

### Phase 5: Platform Adapters + Swift + Reference App

**Goal:** iOS SDK, reference app integration, bridge adapters, real-time media transport.

```
Build:
  • scp-platform/apple/ — Secure Enclave, App Attest, APNs, Keychain
  • bindings/swift/ — UniFFI-generated + Swift ergonomics layer
  • scp-bridge/x/ — X bridge adapter (relay mode)
  • scp-bridge/bluesky/ — Bluesky bridge adapter (API mode)
  • scp-media/ — WebRTC adapter, MLS key export for DTLS-SRTP (§10.9.1), signaling via context messages
  • Reference app integration: quests as contexts, AI guide as agent

Test:
  • iOS app creates identity in Secure Enclave
  • Apple platform conformance: key_custody_conformance!(), attestation_conformance!(),
    push_conformance!() pass for Secure Enclave/App Attest/APNs adapters (§16.12.3-5)
  • Quest runs as SCP context
  • Bridge: X user participates in quest via bridge
  • End-to-end: Python agent ↔ Swift app via SCP
  • Media: voice/video call between two context members, keys derived from MLS group state
  • PostgresBlobStore, S3BlobStore pass blob_store_conformance!() (§16.12.6, §17.7)

Ship:
  • Swift package
  • Reference app beta with SCP
  • Bridge adapters
  • Media transport with WebRTC

Deliverable: Reference app runs on SCP. Cross-platform: Python ↔ Swift ↔ TypeScript. Real-time media via delegated WebRTC transport.
```

### Phase 6: Scale + Harden

```
Build:
  • scp-platform/android/ — Keystore, Play Integrity, FCM
  • bindings/kotlin/ — UniFFI-generated
  • Offline/sync strategy
  • Event log pruning/checkpointing
  • Performance optimization
  • Security audit
  • Governance models beyond single-admin

Test:
  • Load testing: 1000 SimulatedIdentity instances in scp-testing simulator,
    deterministic seed, measuring MLS group operation latency and memory
  • Android platform conformance: key_custody_conformance!(), attestation_conformance!(),
    push_conformance!() pass for Keystore/Play Integrity/FCM adapters (§16.12.3-5)
  • Event log pruning correctness: pruned logs still verify, Merkle proofs for
    surviving events remain valid, checkpointed roots match pre-prune roots
  • Security: penetration testing, formal verification of crypto flows
  • Cross-platform conformance: all five language SDKs (Rust, Python, TypeScript,
    Swift, Kotlin) pass trait conformance suites through their respective FFI layers
```

---

## 5. Infrastructure Decisions

### Design Principle: The Protocol Requires No Operator

The protocol is designed so that no entity — including Limn — needs to run infrastructure for it to function. SCP must work with zero Limn involvement. Limn may choose to operate infrastructure (relays, registries, documentation) for convenience or ecosystem bootstrapping, but the protocol cannot depend on this. If Limn disappeared tomorrow, SCP must continue to function exactly as designed.

This is a hard requirement, not an aspiration. Every protocol mechanism must be evaluated against: "does this work if no one runs centralized infrastructure?"

### What The Protocol Requires (None of It From Limn)

| Infrastructure | Who runs it | Why it works without Limn |
|---|---|---|
| Transport relays | Users, communities, anyone | SCP native relay is trivially self-hostable. Existing infrastructure (Nostr relays, Hyperswarm, libp2p, Matrix homeservers) also works. Multiple transports, no single dependency. |
| DID resolution | Mainline DHT (existing) | did:dht resolves via BitTorrent's Mainline DHT — millions of existing nodes. No server to operate. Self-certifying. |
| SDK packages | PyPI, npm, crates.io | Standard open-source package distribution. Forkable. |
| Key storage | User devices | Secure Enclave, Android Keystore, WebCrypto. On-device. |

### What Does Not Exist In The Protocol

| Non-infrastructure | Why |
|---|---|
| Central relay | No privileged relay. All relays are substitutable and untrusted. |
| User database | DIDs are self-sovereign. No registry of users. |
| Key server | Keys are in hardware security modules on user devices. |
| Application server | Apps are client-side. SDK handles everything. |
| Identity provider | DIDs are self-issued. No sign-up, no approval. |
| Certificate authority | did:dht is self-certifying. No CA chain. |

---

## 6. Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| OpenMLS immaturity | Medium | High | OpenMLS is the most mature MLS library in Rust but may have edge cases. Fallback: mls-rs. Both are active. |
| PyO3 async complexity | Medium | Medium | Rust async (tokio) ↔ Python async (asyncio) bridging is tricky. Mitigate with synchronous Python API as fallback. |
| did:dht library gaps | Medium | Medium | did:dht is the primary method. If libraries hit a wall, did:web is the contingency fallback (not a planned path). SDK abstracts the DID method so the fallback is transparent to apps. |
| WASM limitations | Low | Medium | Browser WASM can't access Secure Enclave. Web SDK uses WebCrypto (software keys). Acceptable for web; native is stronger. |
| Transport adapter availability | Low | Low | SCP native relay is canonical and purpose-built. Multiple adapter options (Nostr, Hyperswarm, libp2p, Matrix, etc.) provide redundancy. No single-transport dependency. |
| MLS group state sync (offline) | High | High | Offline members accumulate pending proposals. Extended offline (days) may require group state reset. This is the hardest unsolved problem. |

---

## 7. Decision Summary

| Decision | Choice | Rationale |
|---|---|---|
| Ship order | SDK before app | Agents are the killer app. Demand is proven (Moltbook 2.6M). |
| First binding | Python (PyO3) | Agent ecosystem is overwhelmingly Python. |
| Second binding | TypeScript (wasm-bindgen/napi-rs) | Web + Node coverage. |
| Third binding | Swift (UniFFI) | iOS/macOS apps. |
| Core language | Rust | Crypto libraries, performance, cross-platform via FFI. |
| DID method (primary) | did:dht | Self-certifying, decentralized, key rotation, no server dependency. No migration path. |
| DID method (fallback) | did:web | Contingency only if did:dht libraries prove unusable. Not a planned deployment. |
| Group encryption | MLS (OpenMLS) | O(log n) removal, forward secrecy, clean key destruction. |
| Transport | SCP native relay (canonical) + adapters | No dependency on any single transport. SCP native relay is simplest reference. Adapters: Nostr, Matrix, Holepunch/Hyperswarm, libp2p, WebSocket, WebRTC, QUIC, BLE, Tor, I2P, SSB, MQTT, NATS, ZeroMQ, Yggdrasil, cjdns. |
| Capability tokens | UCAN (rs-ucan) | Per-agent, per-context, per-capability, revocable. |
| Spec status | Ships with SDK, iterates | Don't wait for perfect spec. Working code first. |
| Infrastructure owned | Almost nothing | did:dht uses Mainline DHT (existing). Everything else is existing or user-owned. |
| MCP integration | SCP agent as MCP server | Every MCP-compatible model works with SCP. Zero model-side integration. |

---

## 8. What This Document Does Not Cover

- **Specific API signatures.** See sketch.md for API surfaces (§1–§14) and security APIs (§16).
- **Protocol semantics.** See .docs/specs/ for the full protocol design.
- **Cryptographic security model.** See .docs/specs/ 09 §9.5–§9.15 for the full security specification (MITM prevention, replay prevention, relay threat model, key lifecycle, forward secrecy, PCS, compromise recovery). See planning-session-05.md for the security design rationale.
- **Technology selection rationale.** See planning-session-04.md for why MLS over Sender Keys, why did:dht, etc.
- **Context extension design.** See planning-session-03.md for the Moltbook analysis and context extension design (TTL, memory scope, templates).
- **Adapter trait definitions.** See planning-session-04.md for full Rust trait definitions.
- **Governance and deployment operations.** Undesigned. Needed before launch.
- **Pricing/business model.** Out of scope for this document.
