# SCP System Architecture — Build Document

**Date:** February 21, 2026
**Status:** Buildable design — this document is the engineering blueprint
**Prerequisite reading:** spec.md (protocol design), sketch.md (API surfaces), planning-session-04.md (technology decisions)

---

## 1. Strategy: SDK-First, Not App-First

### Why SDK-First

The original plan was Cronica-first: build the app, extract the protocol. That plan is wrong. The evidence:

- **Moltbook** (Jan 2026): 2.6 million agents in one month. Demand for agent social infrastructure is massive and proven.
- **OpenClaw**: Agents coordinating outside governed channels because no governed path exists.
- **The competitive window**: MCP (Anthropic), WebMCP (Google+Microsoft), and UCP (Google+Shopify) are all tool-level protocols. Nobody is building the social layer. The window is open but closing.

Agents ARE the killer app. The demand exists. Someone will build the killer app on top of SCP if the SDK is available. Cronica is one app built on the SDK simultaneously — not the gating function.

### What SDK-First Means

1. **Ship the SDK before shipping any app.** `pip install scp-sdk` and `npm install @scp/sdk` are the first deliverables, not Cronica.
2. **Python bindings are critical.** The agent ecosystem (LangChain, CrewAI, AutoGen, custom agents) is overwhelmingly Python. If agents can't `import scp`, the protocol doesn't exist to them.
3. **Open source everything in months 2-3.** Spec, SDK, reference implementations. Apache 2.0 or MIT.
4. **Target agent builders, not app builders.** The first users are people building agents that need to interact with other agents. The second users are app developers building agent-native applications.
5. **Cronica is built on the SDK simultaneously** — it validates the SDK surface and proves the "app on SCP" story, but doesn't block SDK release.

### The Competitive Landscape

```
┌──────────────────────────────────────────────────────────┐
│                    TOOL LEVEL                             │
│                                                          │
│  MCP         → model ↔ local tools (JSON-RPC, stdio)    │
│  WebMCP      → model ↔ web tools (navigator.modelContext)│
│  UCP         → agent ↔ commerce (checkout, orders)       │
│                                                          │
│  These define how agents USE things.                     │
├──────────────────────────────────────────────────────────┤
│                    SOCIAL LEVEL   ← SCP fills this gap   │
│                                                          │
│  SCP         → agent ↔ agent ↔ human                    │
│               identity, trust, contexts, encryption,     │
│               governance, provenance, discovery          │
│                                                          │
│  This defines how agents RELATE to each other.           │
└──────────────────────────────────────────────────────────┘
```

MCP, WebMCP, and UCP are complementary to SCP, not competitors. An SCP agent exposes itself as an MCP server locally. An SCP agent can use WebMCP-exposed tools in the browser. An SCP agent can transact via UCP. SCP provides the identity, trust, and social context that none of these protocols address.

---

## 2. System Architecture

### 2.1 High-Level Component Map

```
┌────────────────────────────────────────────────────────────────────┐
│                                                                    │
│  APPLICATIONS                                                      │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Cronica  │  │ 3rd-party│  │ Agent    │  │ Generated apps   │  │
│  │ (iOS)    │  │ apps     │  │ scripts  │  │ (LLM-built)      │  │
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
│  │  │  • TypeScript (wasm-bindgen) — web/Node                │ │  │
│  │  │  • Kotlin (UniFFI) — Android                           │ │  │
│  │  │  • Rust (native)  — direct                             │ │  │
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

### 2.2 Data Flow: Message Lifecycle

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
MLS Encrypt: encrypt with context group key (current epoch)
    │           🔒 Forward secrecy: old epoch keys already deleted (§9.7.2)
    │           🔒 MLS membership_tag HMAC — inner authentication (§9.8.1)
    │           🔒 MLS generation number assigned — replay prevention (§9.8.2)
    ▼
Envelope Builder: wrap in SCP envelope
    │  Sign: SHA256(context_id || sender_did || epoch || generation || timestamp || payload_hash)
    │           🔒 Ed25519 outer signature — verifiable by anyone (§9.8.1)
    │           🔒 Timestamp for replay bounds (§9.8.2)
    ▼
Transport Adapter (Nostr): encode as kind:30078 event, sign, publish to 3+ relays
    │           🔒 TLS 1.3 to all relays (§9.13)
    │           🔒 Multi-relay publishing for suppression resistance (§9.9.2)
    ▼
═══════════════════ NETWORK ═══════════════════
    │
    ▼
Nostr Relay: stores signed event (cannot read encrypted content)
    │           🔒 Relay threat model: can drop/delay/replay, cannot forge/decrypt (§9.9.1)
    ▼
Bob's Transport Adapter: receives via WebSocket subscription (TLS 1.3)
    │
    ▼
Envelope Parser: verify Ed25519 outer signature
    │           🔒 Signature verification — reject forged envelopes (§9.8.4)
    ▼
Deduplication: check hash cache + sequence + timestamp bounds
    │           🔒 Three-layer replay prevention (§9.8.2):
    │             • Hash dedup: SHA256 of signature, 10K sliding window
    │             • Sequence: per-sender expected-next tracking
    │             • Timestamp: 5-min future bound, monotonic per-sender
    ▼
MLS Decrypt: decrypt with Bob's leaf key in the group tree
    │           🔒 MLS membership_tag verification — sender is group member (§9.8.1)
    │           🔒 MLS generation number check — reject within-epoch replays (§9.8.2)
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

**Security checkpoint count:** 14 independent verification steps protect each message. The two most critical are Ed25519 outer signature (non-member verifiable) and MLS membership_tag (member-only verifiable) — two independent integrity checks at different trust levels.

### 2.3 Data Flow: A2A Context Proposal

```
Alice's agent                          Bob's agent
     │                                      │
     ▼                                      │
SCP.Context.propose(                        │
  to: bob.did,                              │
  purpose: "Schedule meeting",              │
  ttl: 10min,                               │
  memoryScope: .ephemeral,                  │
  discoveryProvenance: .sharedContext(...)   │
)                                           │
     │                                      │
     ▼                                      │
Trust Engine: attach Alice's behavioral     │
  record summary to proposal                │
     │                                      │
     ▼                                      │
Envelope: encrypt proposal to               │
  Bob's DID public key                      │
     │                                      │
     ▼                                      │
Transport: send as Nostr kind:30079         │
     │                                      │
     ╌╌╌╌╌╌╌╌╌ NETWORK ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▶ │
                                            ▼
                                   Transport: receive proposal
                                            │
                                            ▼
                                   Envelope: decrypt with Bob's key
                                            │
                                            ▼
                                   Trust Engine: full 4-layer evaluation
                                     • Alice's DID valid?
                                     • Capability tokens?
                                     • Behavioral record?
                                     • Discovery provenance legit?
                                            │
                                            ▼
                                   Client Policy: auto-accept? ask human?
                                     (project co-member + scheduling +
                                      TTL<30min → auto-accept)
                                            │
                                            ▼
                                   SCP.Context.acceptProposal(id)
                                            │
                                   ◄╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
     │                                      │
     ▼                                      ▼
MLS: create group with Alice + Bob    MLS: join group
     │                                      │
     ▼                                      ▼
Context active. Multi-turn negotiation happens.
TTL expires → keys destroyed → summary persists.
```

### 2.4 Data Flow: MCP Integration

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
    Nostr relays / transport
```

The model never knows SCP exists. It sees MCP tools namespaced by context. The MCP adapter handles the translation. This means every existing MCP-compatible model is already compatible with SCP — zero integration work on the model side.

### 2.5 WebMCP + UCP Integration Points

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

## 3. SDK Internal Architecture

### 3.1 Crate Structure (Rust)

```
scp/
├── crates/
│   ├── scp-core/              # Protocol engine — the heart
│   │   ├── context/           # Context lifecycle, membership, roles, governance
│   │   ├── identity/          # DID operations, key management
│   │   ├── trust/             # 4-layer trust evaluation, behavioral records
│   │   ├── discovery/         # Registry search, referrals, context-mediated
│   │   ├── crypto/            # MLS wrapper, UCAN wrapper, Merkle trees
│   │   ├── envelope/          # SCP envelope creation, parsing, validation
│   │   ├── provenance/        # Data provenance tagging
│   │   └── event_log/         # Append-only verifiable log
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
│   ├── scp-ffi/               # Foreign function interface layer
│   │   ├── uniffi/            # UniFFI definitions → Swift, Kotlin
│   │   └── pyo3/              # PyO3 definitions → Python
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
│   └── kotlin/                # Kotlin package (generated by UniFFI)
│       └── com/limn/scp/
│
├── spec/                      # Protocol specification
│   ├── spec.md
│   ├── sketch.md
│   └── planning-session-*.md
│
├── examples/
│   ├── python/
│   │   ├── hello_scp.py       # Minimal: create identity, create context
│   │   ├── a2a_scheduling.py  # Two agents negotiate a meeting
│   │   └── mcp_agent.py       # Agent that exposes SCP tools via MCP
│   │
│   ├── typescript/
│   │   ├── hello_scp.ts
│   │   └── a2a_scheduling.ts
│   │
│   └── swift/
│       └── CronicaQuest.swift # Cronica quest as SCP context
│
└── tests/
    ├── integration/           # Multi-party tests
    │   ├── two_party_messaging.rs
    │   ├── context_proposal.rs
    │   ├── ephemeral_key_destruction.rs
    │   └── mcp_bridge.rs
    │
    └── conformance/           # Protocol conformance tests
        ├── envelope_format.rs
        ├── ucan_validation.rs
        └── merkle_integrity.rs
```

### 3.2 Protocol Engine Components

Each component has a defined responsibility boundary and communicates with others through typed Rust interfaces.

**Context Manager** — the central coordinator:

```
Responsibilities:
  • Context create / join / leave / close state machine
  • Membership tracking (who's in, what role)
  • Role and capability ceiling enforcement
  • Tool registration and invocation routing
  • Governance proposal processing
  • TTL timer management and expiry handling
  • Memory scope enforcement (key destruction triggers)
  • Proposal creation, delivery, acceptance/rejection

Depends on:
  • Crypto Layer (MLS group management, UCAN validation)
  • Identity Manager (DID resolution, agent instantiation)
  • Transport Adapter (envelope delivery)
  • Event Log (append events, generate proofs)

State:
  • Active contexts (in-memory + persisted to secure storage)
  • Pending proposals (inbound + outbound)
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
  • Context-mediated discovery (member list queries)
  • Registry context interaction (search tools)
  • Referral/introduction token creation and verification
  • Referral chain depth tracking

Depends on:
  • Context Manager (member lists, tool invocation)
  • Trust Engine (behavioral records for referrals)
  • Identity Manager (DID verification)

State:
  • Introduction tokens (issued + received)
  • Registry context memberships
```

**Crypto Layer** (wraps external libraries — see spec.md §9.5 for primitive specification, §9.7 for MLS integration):

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
│    MLS DS          = Nostr relay(s) — explicitly untrusted       │
│    MLS AS          = DID resolution + UCAN validation            │
│    MLS KeyPackage  = Pre-key bundle for offline member addition  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**MLS Module responsibilities (§9.7):**
- One MLS group per SCP context (1:1 mapping)
- Forward secrecy: SDK MUST delete old epoch keys after Commit (§9.7.2)
- Post-compromise security: SDK MUST issue periodic MLS Updates, recommended every 24 hours (§9.7.3)
- Key lifecycle: generation (HSM-backed), distribution (KeyPackages on relays), rotation (DID update → MLS Update in all contexts), destruction (platform-attested, §9.15)

**Security Module responsibilities (§9.8–§9.12):**
- Three-layer replay prevention: MLS generation numbers + hash dedup (10K cache) + timestamp bounds (5-min tolerance)
- Key Continuity Verification: Signal-style safety numbers for DID verification (§9.11)
- Relay Consistency Protocol: periodic Merkle root comparison for equivocation detection (§9.9.3)
- Compromise recovery: ordered key rotation across all contexts (§9.12)
- Ephemeral key destruction with platform attestation (§9.15)

### 3.3 Dependency Graph

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
```

Build order follows the dependency graph bottom-up: platform traits → transport → core → FFI → bindings.

---

## 4. Language Binding Design

### 4.1 Python SDK (Primary — Agent Ecosystem)

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

**A2A in Python:**

```python
import scp

alice = await scp.Identity.load()
bob_did = "did:dht:z6MkpT..."

# Propose an ephemeral context
proposal = await scp.Context.propose(
    to=bob_did,
    purpose="Schedule standup",
    ttl=scp.Duration.minutes(10),
    memory_scope="ephemeral",
    discovery=scp.Discovery.shared_context(project_ctx_id),
)

# When accepted, interact
ctx = await proposal.wait_for_acceptance()
await ctx.send("What time works for standup tomorrow?")

async for msg in ctx.messages():
    print(f"{msg.sender}: {msg.content}")
    if "agreed" in msg.content.lower():
        break

# Context auto-closes at TTL. Keys destroyed.
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
scp.Context.propose()    →    py_context_propose()     →    ContextManager::propose()
ctx.send()               →    py_context_send()        →    Context::send()
ctx.invoke()             →    py_tool_invoke()         →    Context::invoke_tool()
```

PyO3 handles the Rust↔Python boundary: async (tokio↔asyncio), error conversion (Result↔Exception), type mapping (structs↔dataclasses). The Python layer adds ergonomics (method chaining, context managers, iterators) without reimplementing logic.

### 4.2 TypeScript SDK (Web + Node)

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

### 4.3 Swift SDK (iOS/macOS — Cronica)

```swift
import SCP

let identity = try await SCP.Identity.create(custody: .secureEnclave)

let quest = try await SCP.Context.create(
    creator: identity,
    ceiling: [.messaging, .toolInvocation, .media],
    tools: [guideAssistant, stepTracker],
    metadata: .init(name: "Thai Cooking Quest", isPublic: true)
)

// Cronica's AI guide joins
try await quest.addMember(chronicaGuide, role: "guide")

// User's agent invokes the guide
let advice = try await quest.invoke("guide_assistant", input: ["query": "where to start?"])
```

Swift bindings are generated by UniFFI from Rust. Swift-specific ergonomics (Combine publishers, SwiftUI integration) are added in a thin Swift wrapper layer.

---

## 5. Minimum Viable SDK (MVSDK)

The smallest SDK that is useful. This is what ships first.

### What's In

| Feature | Why it's minimum |
|---|---|
| Identity creation (did:web) | Can't do anything without identity |
| Context create/join/leave | The fundamental interaction primitive |
| Message send/receive | Minimum useful communication |
| MLS encryption/decryption | Messages must be encrypted — non-negotiable |
| Nostr transport | Must move over the network |
| UCAN token creation | Capability enforcement is core to the model |
| Basic role enforcement | Admin/member/observer — the minimum role set |
| Event log (append + verify) | Accountability is a protocol guarantee |

### What's NOT In (v1)

| Feature | Why it can wait |
|---|---|
| A2A proposals | Agents can share contexts first; bilateral negotiation is v1.1 |
| Discovery (registries, referrals) | Agents find each other through shared contexts first |
| TTL and memory scope | Contexts persist; ephemeral is an optimization |
| Bridge adapters | External platforms are a growth feature |
| Behavioral records | Trust evaluation ships after basic communication works |
| Challenge-response | Agent verification is a trust feature, not a messaging feature |
| did:dht resolution | did:web works for launch; dht migrates later |
| Governance (multi-sig, consensus) | Single-admin governance is sufficient for launch |

### MVSDK Success Criteria

Two Python agents on different machines can:
1. Create identities
2. Create a shared context
3. Exchange encrypted messages through Nostr relays
4. Invoke tools within the context
5. All messages are E2E encrypted — the relay sees nothing
6. All actions are logged in a verifiable event log

If this works in 20 lines of Python, the SDK is viable.

---

## 6. Build Phases (SDK-First)

### Phase 1: Crypto Proof (Weeks 1-4)

**Goal:** Prove the crypto stack works. Two Rust processes exchange encrypted messages through a local Nostr relay.

```
Build:
  • scp-core/crypto/ — MLS wrapper (OpenMLS), UCAN wrapper (rs-ucan)
  • scp-core/envelope/ — SCP envelope creation, signing, verification
  • scp-core/identity/ — DID creation (did:key for now)
  • scp-transport/nostr/ — Nostr adapter (single relay)
  • scp-platform/testing/ — In-memory key storage

Test:
  • Process A creates MLS group, encrypts message, publishes to local relay
  • Process B subscribes, receives, decrypts
  • Relay has no idea what's inside

Deliverable: ~500 lines of Rust. Two terminals exchanging encrypted messages.
```

### Phase 2: Context + Transport (Weeks 5-8)

**Goal:** Full context lifecycle over real Nostr relays.

```
Build:
  • scp-core/context/ — create, join, leave, close state machine
  • scp-core/context/ — role assignment, capability ceiling enforcement
  • scp-core/context/ — tool registration and invocation
  • scp-core/event_log/ — Merkle tree, append, prove, verify
  • scp-transport/ — transport abstraction trait
  • scp-transport/nostr/ — production relay pool, multi-relay
  • scp-transport/websocket/ — direct device-to-device (for testing)

Test:
  • Two devices create context, exchange messages, invoke tools
  • Role enforcement: member can't do admin things
  • Event log integrity verification
  • Multi-relay delivery (send to 3 relays, receive from any)

Deliverable: Two devices with full context lifecycle over real Nostr relays.
```

### Phase 3: Python SDK + MCP (Weeks 9-12)

**Goal:** `pip install scp-sdk` works. Agents can use SCP from Python. MCP bridge works.

```
Build:
  • scp-ffi/pyo3/ — PyO3 bridge layer
  • bindings/python/ — Pythonic wrappers, async, type hints
  • scp-mcp/server.rs — SCP agent as MCP server
  • scp-mcp/client.rs — SCP agent as MCP client
  • scp-core/trust/ — basic UCAN validation (full 4-layer trust is later)
  • Build infrastructure: maturin for Python wheel builds

Test:
  • `pip install scp-sdk` on clean Python venv
  • 20-line agent script works
  • MCP server exposes SCP tools to Claude/GPT
  • Integration test: LangChain agent using SCP tools

Ship:
  • PyPI: scp-sdk v0.1.0
  • GitHub: open source the repo
  • Documentation: quickstart, API reference, examples

Deliverable: Working Python SDK on PyPI. Open source. Agents can use SCP.
```

### Phase 4: Trust + A2A + TypeScript (Weeks 13-16)

**Goal:** Full trust model, A2A proposals, TypeScript SDK.

```
Build:
  • scp-core/trust/ — four-layer evaluation, behavioral records
  • scp-core/context/ — propose/accept/reject, TTL, memory scope
  • scp-core/discovery/ — context-mediated discovery, registry context tools
  • scp-core/provenance/ — data provenance tagging
  • scp-ffi/uniffi/ — UniFFI definitions (prepares Swift/Kotlin)
  • bindings/typescript/ — TypeScript SDK (wasm-bindgen for browser, napi-rs for Node)

Test:
  • A2A: two agents propose, negotiate, complete ephemeral interaction
  • Key destruction: verify ephemeral context keys are unrecoverable
  • Trust evaluation: proposal evaluation with behavioral record checks
  • TypeScript: same test suite as Python, in TypeScript

Ship:
  • PyPI: scp-sdk v0.2.0 (with A2A)
  • npm: @scp/sdk v0.1.0
  • Updated docs with A2A examples

Deliverable: A2A works. TypeScript SDK ships. Two languages supported.
```

### Phase 5: Platform Adapters + Swift + Cronica (Weeks 17-20)

**Goal:** iOS SDK, Cronica integration, bridge adapters.

```
Build:
  • scp-platform/apple/ — Secure Enclave, App Attest, APNs, Keychain
  • bindings/swift/ — UniFFI-generated + Swift ergonomics layer
  • scp-bridge/x/ — X bridge adapter (relay mode)
  • scp-bridge/bluesky/ — Bluesky bridge adapter (API mode)
  • scp-core/discovery/ — referral/introduction protocol
  • Cronica integration: quests as contexts, AI Guide as agent

Test:
  • iOS app creates identity in Secure Enclave
  • Cronica quest runs as SCP context
  • Bridge: X user participates in Cronica quest via bridge
  • End-to-end: Python agent ↔ Swift app via SCP

Ship:
  • Swift package
  • Cronica beta with SCP
  • Bridge adapters

Deliverable: Cronica runs on SCP. Cross-platform: Python ↔ Swift ↔ TypeScript.
```

### Phase 6: Scale + Harden (Weeks 21+)

```
Build:
  • scp-platform/android/ — Keystore, Play Integrity, FCM
  • bindings/kotlin/ — UniFFI-generated
  • did:dht migration (from did:web)
  • Offline/sync strategy
  • Event log pruning/checkpointing
  • Performance optimization
  • Security audit
  • Governance models beyond single-admin

Test:
  • Load testing: 1000-member context
  • Security: penetration testing, formal verification of crypto flows
  • Cross-platform interop: all five languages
```

---

## 7. Open Source + Community Strategy

### Month 1-2 (Pre-Release)
- Spec and planning documents public on GitHub (read-only, feedback welcome)
- Development happens in public repo
- No SDK release yet — too early for external use

### Month 3 (SDK Launch)
- PyPI: `scp-sdk` v0.1.0
- GitHub: full repo open source (Apache 2.0)
- Documentation site: protocol spec, SDK quickstart, API reference, examples
- Blog post: "SCP: Social Infrastructure for the Agent Era"

### Month 4+ (Ecosystem Building)
- Integration guides: LangChain, CrewAI, AutoGen, custom agents
- npm: `@scp/sdk` v0.1.0
- Registry context reference implementation
- Community-operated Nostr relays for SCP traffic
- SDK contribution guide
- Protocol governance: how spec changes are proposed and accepted

### Target Communities (in order)
1. **Agent builders** — LangChain/CrewAI/AutoGen developers who need agents to interact
2. **Protocol developers** — Nostr, AT Protocol, Matrix communities (transport/bridge synergies)
3. **App developers** — building agent-native applications on SCP
4. **Security researchers** — trust model, prompt injection defense, Sybil resistance

---

## 8. Infrastructure Decisions

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

## 9. Risk Assessment

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| OpenMLS immaturity | Medium | High | OpenMLS is the most mature MLS library in Rust but may have edge cases. Fallback: mls-rs. Both are active. |
| PyO3 async complexity | Medium | Medium | Rust async (tokio) ↔ Python async (asyncio) bridging is tricky. Mitigate with synchronous Python API as fallback. |
| did:dht library gaps | Medium | Medium | did:dht is the primary method. If libraries hit a wall, did:web is the contingency fallback (not a planned path). SDK abstracts the DID method so the fallback is transparent to apps. |
| WASM limitations | Low | Medium | Browser WASM can't access Secure Enclave. Web SDK uses WebCrypto (software keys). Acceptable for web; native is stronger. |
| Transport adapter availability | Low | Low | SCP native relay is canonical and purpose-built. Multiple adapter options (Nostr, Hyperswarm, libp2p, Matrix, etc.) provide redundancy. No single-transport dependency. |
| MLS group state sync (offline) | High | High | Offline members accumulate pending proposals. Extended offline (days) may require group state reset. This is the hardest unsolved problem. |

### Strategic Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Apple/Google build closed alternative | High | High | Ship fast. Open source. Build ecosystem before they ship. SCP's value is openness + agent-native design, not features. |
| No adoption (agents don't come) | Medium | Critical | The 20-line Python agent must be simpler than the alternative. If SCP is harder than raw API calls, it fails. |
| Moltbook/Clawstr network effects | Medium | High | SCP's value prop is governance + trust + provenance. Moltbook has scale but no safety. Position on safety, not features. |
| Spec-first paralysis | Medium | Medium | SDK ships before spec is complete. Ship working code, iterate spec. Don't wait for perfect spec. |

---

## 10. Decision Summary

| Decision | Choice | Rationale |
|---|---|---|
| Ship order | SDK before app | Agents are the killer app. Demand is proven (Moltbook 2.6M). |
| First binding | Python (PyO3) | Agent ecosystem is overwhelmingly Python. |
| Second binding | TypeScript (wasm-bindgen/napi-rs) | Web + Node coverage. |
| Third binding | Swift (UniFFI) | Cronica (iOS). |
| Core language | Rust | Crypto libraries, performance, cross-platform via FFI. |
| DID method (primary) | did:dht | Self-certifying, decentralized, key rotation, no server dependency. No migration path. |
| DID method (fallback) | did:web | Contingency only if did:dht libraries prove unusable. Not a planned deployment. |
| Group encryption | MLS (OpenMLS) | O(log n) removal, forward secrecy, clean key destruction. |
| Transport | SCP native relay (canonical) + adapters | No dependency on any single transport. SCP native relay is simplest reference. Adapters: Nostr, Matrix, Holepunch/Hyperswarm, libp2p, WebSocket, WebRTC, QUIC, BLE, Tor, I2P, SSB, MQTT, NATS, ZeroMQ, Yggdrasil, cjdns. |
| Capability tokens | UCAN (rs-ucan) | Per-agent, per-context, per-capability, revocable. |
| License | Apache 2.0 | Permissive. Compatible with most ecosystems. |
| Spec status | Ships with SDK, iterates | Don't wait for perfect spec. Working code first. |
| Infrastructure owned | Almost nothing | did:dht uses Mainline DHT (existing). Everything else is existing or user-owned. |
| MCP integration | SCP agent as MCP server | Every MCP-compatible model works with SCP. Zero model-side integration. |

---

## 11. What This Document Does Not Cover

- **Specific API signatures.** See sketch.md for API surfaces (§1–§14) and security APIs (§16).
- **Protocol semantics.** See spec.md for the full protocol design.
- **Cryptographic security model.** See spec.md §9.5–§9.15 for the full security specification (MITM prevention, replay prevention, relay threat model, key lifecycle, forward secrecy, PCS, compromise recovery). See planning-session-05.md for the security design rationale.
- **Technology selection rationale.** See planning-session-04.md for why MLS over Sender Keys, why did:dht, etc.
- **A2A architecture decisions.** See planning-session-03.md for the Moltbook analysis and context extension design.
- **Adapter trait definitions.** See planning-session-04.md for full Rust trait definitions.
- **Governance and deployment operations.** Undesigned. Needed before launch.
- **Pricing/business model.** Out of scope for this document.
