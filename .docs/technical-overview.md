# SCP Technical Overview

### What it is

SCP is an infrastructure protocol — not an app, not a framework, but the open infrastructure beneath applications. It solves the problem that arises when software becomes disposable and agent-generated:
identity, trust, relationships, encryption, and accountability need to be durable and portable even when the apps using them are ephemeral.

It sits at a different level than MCP (Anthropic), WebMCP (Google+Microsoft), or UCP (Google+Shopify), which are all tool-level protocols (agent ↔ tools). SCP is social-level: agent ↔ agent ↔ human
— identity, trust, contexts, encryption, governance, provenance, discovery.

### The five pillars

#### 1. Identity (DID-based)

Every actor has a did:dht decentralized identifier rooted in an Ed25519 keypair. The DID string encodes the public key directly — making it self-certifying. Resolution uses BEP44 (Mainline DHT), so
no centralized registry. Users never see keys; custody is delegated to Secure Enclave, passkeys, or platform accounts.

The key hierarchy is:
- Identity key (Ed25519) — derives the DID string, highest-security custody
- Active signing key (Ed25519, rotatable) — MLS credentials, envelope signatures, UCAN issuance
- Pre-rotation commitment — SHA-256 of a pre-staged next key, held in cold storage for compromise recovery

Identity private state (block lists, graph visibility policies, petnames, preferences) is encrypted to the owner's keys and replicated across relays as an append-only event log — the same
infrastructure as context state, but membership of one.

#### 2. Contexts (the security boundary)

All interaction happens within contexts. There is no off-context communication at the protocol level. A context is a bounded, governed space with:
- Its own MLS group key material (forward secrecy, post-compromise security)
- An append-only Merkle event log (every action is verifiable)
- A governance model (roles, permissions, capability ceiling)
- A membership roster
- Tools (stateless, schema-declared, content-addressable)

Two modes, set immutably at creation:
- Encrypted — one MLS group per context, sender-side keys, full forward secrecy. Bounded membership (~500 practical limit from MLS epoch costs).
- Broadcast — per-author AES-256 broadcast keys, no MLS. Unlimited subscriber scale. Authors are public.

Contexts are runtime objects (~5-15ms local computation, ~200ms with network). They're created as fluidly as opening a connection. Apps are composites of contexts + members + tools + data.

Key governance concepts:
- Capability ceiling — upper bound on what's possible in the context, declared at creation. Ceiling policy is either `immutable` (default, cannot change) or `governed` (modifiable through governance, changes logged and visible to all members)
- Roles — grant subsets of the ceiling; RoleAssign and RoleConfigure are separate capabilities (the person assigning roles can't define new ones)
- Memory scope — full (persistent), summary (AI-summarized then destroyed), ephemeral (destroy keys on close), set at creation

#### 3. Encryption (MLS + sender-side key layer)

The encryption stack has two independent layers:

**Layer 1: MLS (RFC 9420) via OpenMLS.** One MLS group per Encrypted context. Provides:
- Forward secrecy (old epoch keys are deleted)
- Post-compromise security (new epochs heal after key compromise)
- membership_tag HMAC (sender is provably a group member)
- Generation numbers (within-epoch replay prevention)

**Layer 2: Sender-side AES-256-GCM key.** Each member maintains a personal sender key, distributed to all members except blocked parties. This is what enables blocking without MLS group removal — when
Alice blocks Dave, she rotates her sender key and redistributes to everyone except Dave. Dave remains an MLS group member but physically cannot decrypt Alice's messages.

**Key distribution is pull-based — O(1):**
- SenderKeyEpochAdvance — broadcast: "I've rotated, epoch N"
- SenderKeyRequest — DM: "give me your current key"
- SenderKeyResponse — DM: encrypted key delivery
- 30-second grace period for in-flight messages with old keys

**Message lifecycle (14 security checkpoints):**
plaintext → UCAN validation → sequence assignment → Merkle append →
provenance tagging → inner envelope (Ed25519 sign) →
sender-side key encrypt (AES-256-GCM) → bucket padding →
MLS encrypt → outer envelope (pseudonym routing, NO signature) →
transport to 3+ relays

**Relays see only opaque blobs.** They can't read, verify, or forge content. The relay threat model: can drop, delay, or replay — but cannot decrypt or forge.

#### 4. Capabilities (UCAN)

Authorization uses UCAN (User Controlled Authorization Networks) — bearer tokens with cryptographically verifiable delegation chains. Every protocol action requires a valid UCAN:

capability: scp:ctx:{context_id}/messages → write

Validation is zero-trust on every action:
1. Signature chain valid
2. Capability matches action
3. Context ceiling permits it
4. Agent's role includes the permission
5. Token not revoked or expired
6. Nonce uniqueness check (prevents replay)
7. For paid actions: spending UCAN present and sufficient

A trusted DID with an expired token is denied. An unknown DID with a valid token is permitted. No exceptions.

#### 5. Trust (4-layer model)

Trust evaluation runs through four layers, from hardest to softest:

| Layer | What | How |
|---|---|---|
| 1. Protocol Enforcement | UCAN validation, signatures, ceilings, roles | 100% validation, 0% trust |
| 2. Behavioral Validation | Merkle event logs, behavioral records, tool verification, challenge-response, consequence mechanisms | Mostly validation, grows over time |
| 3. Attestation Authenticity | Signature verification on claims (identity links, endorsements, tool integrity) | Verified as real, not as true |
| 4. Trust Evaluation | Agent-level judgment for new identities, non-testable capabilities, novel situations | Shrinks as behavioral data grows |

**The critical property:** the trust surface shrinks over time. New identities start trust-heavy. As they participate, behavioral records accumulate, and validation replaces trust.

### Cross-context communication

Agents are absolutely isolated per context. No protocol-level cross-context awareness. Two mechanisms exist for data to cross boundaries:

1. **Tool interfaces** — asymmetric, request/response. Context A calls a tool in Context B through a shared member's local SDK. Both contexts' governance gates every call. Schema-declared, rate-limited,
  auditable, carries provenance. Supports stateful sessions (multi-turn negotiation via session IDs).
2. **Multi-parent child contexts** — symmetric. A new context with two parents that inherits the intersection of their capability ceilings. Members from both parents interact as peers in the child.

There is explicitly no direct agent-to-agent communication. This was analyzed and rejected — context isolation is the security boundary, and anything that bypasses it reintroduces the attack surface
  it was designed to eliminate.

### Provenance

All non-private data carries verifiable origin:

```rust
DataProvenance {
    sourceContext,      // where it originated
    sourceType,         // persistent / ephemeral / summary
    counterparties,     // who was in the source interaction
    discoveryMethod,    // how the source was found
    chainDepth,         // number of context boundaries crossed
    chainPath,          // ordered intermediary context IDs
}
```

Chain depth is capped at 3 hops (protocol default) to bound amplification. The absence of provenance is itself a signal — "this data has no verified origin."

### Crate architecture (Rust core)

```
crates/
  scp-core/          — Protocol engine (context, identity, trust, discovery managers)
    store/           — ProtocolRepository layer (thick), Storage trait (thin, 6 methods)
  scp-crypto/        — MLS (OpenMLS), UCAN (native impl), Merkle trees, HPKE, HKDF
  scp-transport/     — Transport adapter trait + SCP native relay adapter
  scp-relay/         — Reference relay implementation
  scp-ffi/           — UniFFI bindings (Swift, Kotlin), PyO3 (Python), wasm-bindgen (TS)
  scp-mcp/           — MCP server adapter (exposes SCP contexts as MCP tool surfaces)
```

**Storage:** MessagePack serialization with version envelopes. SQLite (bundled-sqlcipher) as universal default. BlobStore backends: SQLite, redb, PostgreSQL, S3-compatible.

### What makes it different

- **Contexts, not channels.** A context is a governed, encrypted, auditable space with its own key material, Merkle log, and tool surface. It's the security boundary, lifecycle boundary, and governance
boundary all in one.
- **Encryption IS access control.** No relay or server enforces membership — the math does. Relays are untrusted dumb pipes.
- **No operator required.** If Limn disappears tomorrow, SCP works exactly as designed. DID resolution via DHT, relays are commodity storage, governance is per-context.
- **Provenance everywhere.** Not a feature — a core protocol property. Every message, tool output, attestation, and cross-context transfer is traceable.
- **Human accountability.** Every agent chains back to a human DID. The protocol provides the mechanism; contexts decide the requirement.
- **Trust decays into validation.** New identities require trust. Established identities are validated by behavioral records from Merkle-verified event logs. The system gets more secure over time.

### Encryption and MLS — deep dive

#### Two independent encryption layers

SCP's encryption is a two-layer stack where each layer serves a distinct purpose and operates independently:

| Layer | Purpose | Key | Who can decrypt |
|---|---|---|---|
| 2. MLS Group Encryption (RFC 9420) | Group confidentiality + forward secrecy | Shared MLS group key, ratcheted per epoch | All MLS group members |
| 1. Sender-Side Key (AES-256-GCM) | Selective readability + blocking | Per-sender symmetric key, rotated on block | All non-blocked group members |

The sender-side key encrypts first. Then MLS encrypts the result. On receipt, the recipient MLS-decrypts, then sender-key-decrypts. Blocking works because the blocked party can strip the MLS layer but hits opaque ciphertext at the sender-key layer.

#### MLS integration

Every SCP context is exactly one MLS group. The mapping is 1:1:

| MLS Concept | SCP Concept | Notes |
|---|---|---|
| Group | Context | One MLS group per context |
| Member (LeafNode) | Agent in context | One leaf per agent |
| Epoch | Context epoch | Increments on membership change or key update |
| LeafNode credential | DID + UCAN | MLS credential field holds the member's DID and context-scoped UCAN |
| Welcome message | Context join token | HPKE-encrypted to new member's KeyPackage |
| KeyPackage | Pre-key bundle | Published to relays, single-use, signed by identity key |
| Proposal (Add/Remove/Update) | Governance action | Membership changes go through MLS proposals |
| Commit | Governance commit | Finalizes proposals, advances epoch |
| Application message | SCP envelope payload | Encrypted content |
| Delivery Service | SCP relay(s) | Untrusted store-and-forward |
| Authentication Service | DID resolution + UCAN validation | Fully decentralized — no AS server |

The MLS Authentication Service is where SCP diverges from typical deployments. Most MLS systems have a centralized AS that vouches for member identities. SCP has none. Each participant independently resolves DIDs from the DHT and validates UCAN chains.

**Ciphersuite — single, non-negotiable:**

```
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
```

- Key agreement: X25519 (HPKE KEM)
- Symmetric encryption: AES-128-GCM (AEAD)
- Hash: SHA-256
- Signing: Ed25519

No ciphersuite negotiation in v1. No fallback. This eliminates downgrade attacks entirely. DID-to-DID encryption (Welcome messages) uses HPKE with a matching suite: `DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`.

#### Forward secrecy

MLS provides forward secrecy through epoch-based key ratcheting. After a Commit advances the group to a new epoch, old epoch key material is destroyed:

- Old epoch keys are retained in volatile memory only (never persisted) for the shorter of: (a) all members have sent at least one message in the new epoch, or (b) 30 seconds from local Commit processing time
- After the grace window: epoch secrets, application key schedules, and ratchet tree states for past epochs are destroyed and unrecoverable
- Members who want to re-read historical messages retain the decrypted plaintext locally — they cannot re-derive old epoch keys

Interaction with memory scope:
- `full` — forward secrecy protects past messages if keys are later compromised. Plaintext retained locally.
- `ephemeral` — MLS group state destroyed on context close. All historical messages become physically unreadable.
- `summary` — AI summary generated and verified, then keys destroyed.

#### Post-compromise security (PCS)

When a member sends an MLS Update (generating a fresh HPKE keypair and ratcheting their path in the tree), any previous compromise of that member's state becomes useless for future messages.

- Periodic Updates every 24 hours for active contexts (configurable — high-security contexts can require 1-hour intervals)
- Immediate Update after reconnection following offline periods
- On Active Signing Key rotation, MLS Update in every active context with the new credential
- On Identity Key migration (new DID), `DidRotationEvent` + MLS Updates in all contexts

The vulnerability window from a key compromise is bounded: forward secrecy protects everything before compromise, PCS heals on the next Update. Maximum exposure = one PCS interval.

#### Key lifecycle

```
Identity Key (Ed25519, hardware-backed)
├── Derives the DID string (immutable)
├── Signs DID document updates
├── Signs pre-rotation commitments
├── NEVER directly encrypts group content
│
Active Signing Key (Ed25519, rotatable)
├── MLS LeafNode credentials
├── Inner envelope signatures
├── UCAN issuance
├── Rotated via DID document update signed by Identity Key
│
Pre-Rotation Key (Ed25519, cold storage)
├── SHA-256(pubkey) published as commitment
├── Revealed only during Identity Key migration
│
MLS Leaf Key (X25519, per-ciphersuite)
├── Generated by MLS library
├── Used for MLS tree key agreement
│
KeyPackages (single-use)
├── Pre-generated, published to relays
├── Buffer of ≥10 unused, replenished at 5
├── Consumed in Welcome messages
│
Sender-Side Key (AES-256-GCM, per-context)
├── One per member per context
├── Rotates ONLY on block events
└── Distributed via pull-based protocol
```

KeyPackages are strictly single-use. After consumption in a Welcome, the private key is deleted. The SDK maintains a buffer of at least 10 pre-generated KeyPackages on relays for offline group additions.

#### Sender-side key layer

MLS gives group confidentiality — outsiders can't read. But it doesn't give selective readability within the group. The sender-side key layer solves this.

| | Blocking | Removal |
|---|---|---|
| Mechanism | Sender-side key rotation | MLS Remove Commit + epoch advance |
| Scope | Per-relationship | Group-wide |
| Effect | Blocked party can't decrypt blocker's messages | Removed party can't decrypt any messages |
| Authority needed | None (unilateral) | Admin role or governance |
| Other members | Unaffected | Epoch advances for everyone |

Each member holds one AES-256-GCM symmetric sender key per context (32 bytes), plus a stable wrapping keypair (X25519) published as an MLS LeafNode extension (`scp_wrapping_key`) for HPKE wrapping during key distribution.

#### Pull-based key distribution

Sender keys use a pull-based request/response protocol instead of push:

```
1. SenderKeyEpochAdvance { sender_did, epoch, signature }
   — MLS application message, broadcast to all
   — "I've rotated my key, new epoch is N"
   — O(1) for the sender regardless of group size

2. SenderKeyRequest { requester_did, sender_did, epoch, wrapping_pubkey, signature }
   — Directed MLS application message to key holder
   — "Give me your key for epoch N"
   — wrapping_pubkey is a FRESH ephemeral X25519 key per-request

3. SenderKeyResponse { sender_did, epoch, hpke_sealed_key, ephemeral_pubkey }
   — Directed MLS application message to requester
   — Key is HPKE-encrypted to requester's ephemeral wrapping pubkey
   — O(1) per response
```

HPKE wrapping: generate ephemeral X25519 keypair → ECDH with requester's wrapping pubkey → HKDF → AES-128-GCM encrypt the sender key. Recipient-side HPKE open computes the shared secret inside the custody boundary (HSM) — the wrapping private key never leaves KeyCustody.

#### Block protocol

When Alice blocks Bob:

1. Alice generates new AES-256-GCM sender key, increments `sender_key_epoch` to N
2. Alice publishes `SenderKeyEpochAdvance { alice_did, epoch: N, signature }` — O(1) broadcast
3. Alice sends signed block notification to Bob (signature prevents forgery — MLS proves group membership but not individual sender identity within the payload)
4. Non-blocked members see the epoch advance, send `SenderKeyRequest`s — Alice's SDK checks the block list per request, responds to non-blocked members, ignores Bob
5. Bob's SDK verifies the block notification signature, rotates Bob's own sender key (excluding Alice), publishes his own epoch advance
6. Block event recorded in Merkle event log: `EventType::MemberBlocked { blocker, blocked, signature }`

Result: both Alice and Bob have new sender keys that exclude each other. Neither can read the other's future messages. All other members request and receive both new keys normally.

Sender keys deliberately do NOT rotate on MLS epoch advances. MLS handles forward secrecy at the group level. Rotating sender keys per epoch would require O(N) key requests per advance — prohibitive for active contexts. Old sender keys are retained for historical message decryption; access boundaries are defined by block events and member joins.

#### The full message pipeline — 14 security checkpoints

```
Plaintext
  │
  ├─  1. UCAN validation (capability token for messages:write)
  ├─  2. UCAN nonce uniqueness check (prevents token replay)
  │
  ├─  3. SCP sequence number assigned (per-sender monotonic)
  ├─  4. Merkle event log append + proof computation
  ├─  5. Provenance metadata attached (for cross-context data)
  │
  ├─  6. Inner envelope signed: Ed25519 over
  │      SHA256(context_id ‖ sender_did ‖ epoch ‖ generation ‖
  │             sequence ‖ timestamp ‖ payload_hash ‖ provenance_hash)
  │
  ├─  7. Sender-side key encrypt: AES-256-GCM with sender's key
  │      (blocked parties see opaque ciphertext here)
  │
  ├─  8. Bucket padding to next boundary (256B/1KB/4KB/16KB/64KB/256KB)
  │      (prevents message size analysis)
  │
  ├─  9. MLS encrypt with context group key (current epoch)
  ├─ 10. MLS membership_tag HMAC (proves sender is group member)
  ├─ 11. MLS generation number (within-epoch replay prevention)
  │
  ├─ 12. Outer envelope: routing_id (pseudonym), recipient_hint, TTL, blob
  │      (NO signature — relay learns nothing about sender)
  │
  ├─ 13. Transport to 3+ relays (TLS 1.3)
  └─ 14. Multi-relay publishing (suppression resistance)

  ═══════════════ NETWORK (relays see only opaque blobs) ═══════════════
```

The two most critical checks are the Ed25519 inner signature and MLS membership_tag — two independent integrity checks (Active Signing Key and MLS epoch secrets), both inside encryption, both member-only verifiable. An attacker must compromise BOTH the identity key AND the MLS group state to forge a message.

#### Three-layer replay prevention

| Layer | Mechanism | What it catches |
|---|---|---|
| MLS generation numbers | Per-sender counter per epoch, reject ≤ last seen | Exact replays within an epoch |
| Hash dedup | SHA256(encrypted_blob), 10K sliding window / 24hr | Replays across epochs |
| Timestamp bounds | 5min future bound, monotonic per-sender | Time-shifted replays |

#### Broadcast mode — no MLS

Broadcast contexts replace MLS entirely with per-author AES-256 broadcast keys. The pull-based key distribution protocol is identical — same `KeyEpochAdvance`, `KeyRequest`, `KeyResponse` — but sent as plain relay messages instead of MLS application messages.

| Property | Encrypted | Broadcast |
|---|---|---|
| Group encryption | MLS (one group) | None |
| Content encryption | Per-sender AES-256-GCM + MLS | Per-author AES-256-GCM only |
| Authentication | Ed25519 signature + MLS membership_tag | Ed25519 signature only |
| Forward secrecy | MLS epoch ratchet | None (mitigated by epoch rotation on block) |
| Routing ID | HKDF-derived pseudonym (private) | SHA-256(context_id) (public) |
| Author identity | Inside encrypted payload (hidden) | Visible in BroadcastEnvelope |
| Membership | MLS group (bounded ~500) | Two-tier: writers (bounded) + subscribers (unbounded) |
| Subscriber scale | ~500 practical limit | Unlimited |

The `BroadcastEnvelope`:

```rust
pub struct BroadcastEnvelope {
    pub context_id: ContextId,
    pub sender_did: DID,           // visible to relays (authors are public)
    pub sequence: u64,
    pub key_epoch: u64,
    pub timestamp: u64,
    pub content_hash: [u8; 32],    // SHA-256 of plaintext
    pub content: Vec<u8>,          // AES-256-GCM encrypted
    pub provenance: Option<DataProvenance>,
    pub signature: Ed25519Signature,
}
```

Subscriber registration uses the two-tier model from discovery contexts: a bounded writer tier (MLS members, authors) and an unbounded reader tier (DID-authenticated subscribers). Open broadcasts grant keys on DID authentication alone; gated broadcasts require a `messagesRead` UCAN from the context admin, enabling paid subscriptions, invite-only communities, and tiered access.

#### Metadata privacy — what relays see

The outer envelope is deliberately minimal:

```
1. routing_id     — per-context pseudonym (HKDF-derived, unlinkable across contexts)
2. recipient_hint — recipient pseudonym or "*" for broadcast
3. blob_ttl       — seconds until relay deletes
4. encrypted_blob — everything else
```

Sender identity, timestamps, sequence numbers, epoch, generation — all inside the encrypted payload. The relay is a dumb pipe.

Per-context pseudonyms are derived deterministically:

```
context_seed = HMAC-SHA256(identity_key_material, context_id ‖ "scp-pseudonym")
context_keypair = Ed25519_keygen(context_seed[0..32])
context_pseudonym = context_keypair.public_key
```

Same identity + same context = same pseudonym. Different context = different pseudonym. Relays cannot correlate activity across contexts. The HMAC computation happens inside the HSM custody boundary.

Additional protections:
- **Bucket padding** — 256B/1KB/4KB/16KB/64KB/256KB buckets prevent message size analysis
- **Cover traffic** — one padded message per relay per 30 seconds (default on), real messages replace dummies
- **Relay partitioning** — SDK distributes contexts across different relays to minimize overlap
- **Persistent connections** — desktop maintains constant connections regardless of activity
- **Local DHT node** — desktop runs a full Mainline DHT node so resolution queries are indistinguishable from routing traffic

#### Relay threat model

Relays are explicitly untrusted:

**CAN:** Read routing metadata (pseudonyms, TTLs, blob sizes). Drop messages (suppression). Delay messages. Replay messages. Equivocate (show different histories to different members). Correlate traffic timing. See broadcast author DIDs.

**CANNOT:** Forge messages (requires Ed25519 key + MLS secrets). Decrypt content (requires MLS group key + sender-side key). Modify messages (inner signature + membership_tag fail). Inject members (requires HPKE Welcome to joiner's KeyPackage). Read broadcast content (requires author broadcast key).

Suppression is detected by sequence gap detection, heartbeat messages (60-second intervals in active contexts), and multi-relay cross-checking (publish to 3+ relays, compare delivery — inconsistency after 30s flags the relay).

Equivocation is detected by the Relay Consistency Protocol: periodic signed `ConsistencyCheckpoint` messages containing event count, Merkle root, epoch, and timestamp. Any divergence between any two honest members detects equivocation — Sybil amplification doesn't help the attacker.

#### Compromise recovery

| Scenario | Action |
|---|---|
| Active Signing Key compromised | `rotate_active_key` — new keypair, DID doc update signed by Identity Key. DID doesn't change. MLS Update in all contexts. |
| Identity Key compromised | `migrate_identity` — pre-rotation key proves legitimacy. New DID. `DidRotationEvent` in all contexts. |
| Both compromised, pre-rotation available | Same as Identity Key — pre-rotation key resolves the race |
| All keys compromised | Social recovery — trusted contacts with admin roles remove + re-add under new identity |

After any recovery: UCAN revocation, KeyPackage rotation, contact notification, identity private state re-encryption. The exposure window is bounded by the PCS interval (default 24hrs, configurable to 1hr).

### Contexts in practice

#### Templates and lightweight creation

Creating a context from scratch means specifying a ceiling, roles, governance model, memory scope, TTL, and tools. That's the right level of control for a carefully designed space, but most contexts are routine. Templates are the fast path — named parameter bundles with fixed, predictable configurations. The protocol defines 10 well-known templates:

| Template | Mode | Purpose |
|---|---|---|
| `bilateral-ephemeral` | Encrypted | Quick DM with a time limit. Keys destroyed on expiry. |
| `bilateral-persistent` | Encrypted | Standing DM channel, no expiry. |
| `coordination` | Encrypted | Time-boxed task context with tools. Summary memory scope. |
| `group-discussion` | Encrypted | Group chat with invites. Full persistence. |
| `public-broadcast` | Broadcast | Open feed — anyone can subscribe on DID authentication alone. |
| `gated-broadcast` | Broadcast | Feed with access control — admin issues subscriber UCANs. |
| `tool-interface` | Encrypted | Cross-context tool exposure point. |
| `paid-service` | Encrypted | Tool context with per-invocation cost. Extends `tool-interface`. |
| `paid-broadcast` | Broadcast | Subscription feed. Extends `gated-broadcast`. |
| `handle-registry` | Encrypted | Discovery context that serves human-readable handles. |

Templates are protocol constants, not extensible. A template ID in context metadata is a commitment: "this context has exactly these properties." The joining party evaluates a single check — "do I accept this template from this DID at this TTL?" — instead of inspecting six parameters individually.

#### Auto-accept policies

Agents can configure rules for automatic context acceptance — the SDK joins without human confirmation when conditions are met. Example: "auto-accept `bilateral-ephemeral` from any DID I share a context with, if TTL is under 10 minutes, at most 5 per hour."

Two hard rules that cannot be overridden by any policy:
- **No auto-accept for tool-bearing contexts.** Tool access enables cross-context data flow. Auto-accepting it would silently expand the agent's attack surface.
- **No auto-accept for paid contexts.** Agents never silently incur costs.

#### Standing channels

Standing bilateral contexts are the protocol's answer to lightweight, persistent communication. Create once (~200ms), maintain indefinitely. An agent with 100 standing channels has ~200-500KB of local storage overhead and zero network cost when idle. This is the desired state — a rich contact graph, not proliferation.

#### Memory scope

What happens to context data when a context closes:

| Scope | Behavior | Use case |
|---|---|---|
| **Full** (default) | Standard persistence. Content remains accessible. | Long-lived spaces, workspaces, group chats |
| **Ephemeral** | Keys destroyed on close. SDK requests ciphertext deletion from relays. Content is physically unreadable. Metadata (who, when, purpose) persists. | Sensitive conversations, temporary coordination |
| **Summary** | AI summary generated and verified, then keys destroyed. Summary persists with provenance. | Meeting notes, decision records |

Broadcast contexts support `full` scope only — without MLS, the ephemeral/summary security properties are weaker. Future versions may define broadcast-specific ephemeral semantics.

The protocol is honest about enforcement boundaries: ephemeral scope destroys the protocol-level record. But an agent's underlying model may retain information in its own memory. The defense is provenance — any data the agent later produces from memory elsewhere carries no verified origin, and other participants see that signal.

#### Context nesting

Contexts can have parent-child relationships for two distinct purposes:

**Single-parent nesting** — sub-spaces within a context. A project context spawns a task-specific child. The child inherits the parent's ceiling (narrowed, never widened), and lifecycle coupling means the parent closing can close children.

**Multi-parent nesting** — bridges between contexts. Two contexts that need a shared collaboration space create a child with both as parents. The child's ceiling is the intersection of both parents' ceilings — the narrowest common denominator. Members from both parents can join if they meet eligibility requirements.

Protocol-enforced limits:
- **Nesting depth: unbounded by default, context-configurable.** Contexts set an explicit limit via `ContextParams::max_nesting_depth` when they want to bound cascading state propagation, capability inheritance chains, and attack surface from compromised child contexts. The default is no limit (ADR-043).
- **Ceiling intersection converges on empty.** Each level can only narrow capabilities. Deep nesting naturally constrains what's possible, preventing capability amplification through nesting.

### Apps and MCP integration

#### Apps in SCP

An app is not a protocol entity. There is no `App` type, no app DID, no app registration. What people experience as "an app" is a composite of contexts + members + tools + data. The protocol doesn't model it because the constituent parts are already first-class.

State exists at two layers:
- **Protocol state** — membership, roles, capability tokens, tool registrations, governance, content history, trust. This belongs to the protocol. It's portable and survives app death.
- **App state** — game world state, task boards, edit history. This belongs to the app.

This separation is the anti-lock-in mechanism. If you leave an app, you keep your membership, roles, trust relationships, identity, and social graph. You lose app state only if the app doesn't make it portable. Different members of the same context can use different client apps simultaneously — they share protocol state and each has their own app-layer experience.

#### MCP compatibility

SCP integrates with MCP (Model Context Protocol) through a translation layer. The SCP agent runs as an MCP server locally. The AI model sees tools and calls them via JSON-RPC. It has no awareness of SCP — no knowledge of DIDs, encryption, or governance.

```
AI Model (any MCP-speaking model)
    ↕ MCP (JSON-RPC, local)
SCP Agent (translation layer)
    ↕ SCP Protocol (encrypted, over transport)
Context [tools, roles, members, governance]
```

The agent handles everything SCP-specific: capability filtering (only exposes tools the human's role permits), DID signing, encryption, context routing. Tools from multiple contexts appear as namespaced MCP tools — `context_a/send_message`, `context_b/schedule_meeting`. Any MCP-compatible model (Claude, GPT, Gemini, local models) participates in SCP without modification.

### Discovery and addressing

#### Discovery mechanisms

Two complementary discovery channels:

**DID document capabilities** — direct lookup, zero infrastructure. Every agent may publish structured capabilities in their DID document's `service` array. Anyone who knows a DID can resolve the document via Mainline DHT and inspect capabilities. Provides lookup, not search.

**Discovery contexts** — searchable registries, SCP-native. Standard contexts with open join policies and standardized tools (`agent_search`, `agent_register`, `agent_deregister`). Anyone can create one. Two-tier membership: bounded writers (MLS members who process registrations) and unbounded readers (DID-authenticated, query via tool endpoints without joining the MLS group).

Bootstrap: SDK ships with default discovery context IDs (analogous to browser CA lists or DNS root servers). Not privileged — starting points. If all defaults are unavailable, agents fall back to direct DID resolution and manual context ID sharing.

#### Human-readable addressing

Cryptographic identifiers (`did:dht:z6Mk...`) are the protocol's canonical identifiers, but humans need something speakable. The addressing layer maps human-readable strings to DIDs and context IDs through four resolution paths:

| Path | Format | Authority | Trust level |
|---|---|---|---|
| **Petnames** | Any string (local) | The user | `LocalPetname` — highest personal trust, zero shareability |
| **Discovery context handles** | `alice@cooking-community` | Community governance | `DiscoveryContextVerified` |
| **Attestation-backed handles** | `@alice_cooks` or `@alice:github` | External platform + cryptographic attestation | `AttestationVerified` |
| **Domain handles** | `alice@example.com` | Domain operator via `.well-known/scp` | `DomainVerified` |

Resolution order for unscoped queries: petnames first (local, instant), then all other paths in parallel. If multiple paths find the same DID, the result is `MultiLayerCorroborated`. If different DIDs are found, the user disambiguates once and the selection becomes a petname — resolving the collision permanently.

Each layer degrades independently. Remove any one and the rest continue working. Petnames always work (zero infrastructure). Discovery handles work with SCP infrastructure only. Domain handles work if DNS exists. The DID remains canonical regardless of which path resolved it.

### Economic layer

#### Three levels of pricing

Economic governance is entirely optional. Free operation is the default — no economic policy means free.

| Level | Who sets it | What it covers | Visibility |
|---|---|---|---|
| **Relay** | Relay operator | Transport (bandwidth, storage, routing) | `.well-known/scp` relay config, visible before connecting |
| **Context** | Context creator/governance | Participation (messages, tools, membership) | Context metadata, visible before joining |
| **Tool** | Tool operator | Per-invocation cost, additive with context costs | Tool registration metadata |

Each level is independent. A free context on a paid relay costs only the relay fee. A paid context on a free relay costs only the context fee.

#### Spending UCANs

Paid actions require two capabilities in conjunction: an action UCAN (`messagesWrite`, `toolInvoke`, etc.) and a spending UCAN. Both are independently verified before any paid action proceeds.

Spending UCANs support delegation with attenuation — a human grants their agent $100/day, the agent can sub-delegate $10/day to a sub-task. Revocation is independent: revoke the spending UCAN and the agent retains all other capabilities but cannot authorize payments. 24-hour maximum expiry limits blast radius.

#### Anti-spam through cost escalation

The `SenderVelocity` pricing metric enables per-sender cost escalation:

- Normal conversation (1-5 msg/min): $0.001/message — negligible
- Spam rates (200+ msg/min): $0.112/message — $1,344/hour

Combined with the fact that each sybil identity needs its own spending UCAN, adapter credentials, and payment capacity, this makes bulk abuse economically irrational.

### Sybil resistance

The protocol doesn't claim to solve sybil (one person, many identities) — it makes sybil attacks expensive to mount, expensive to sustain, and costly when detected. Three layered mechanisms:

1. **Device attestation.** Hardware-backed attestation (Apple App Attest, Google Play Integrity) ties DID creation to physical devices. One device = one DID. Doesn't prove one human (someone with two phones gets two identities), but makes identity creation cost the price of a device.

2. **Earned capacity.** New identities start limited — restricted context creation, limited participation slots, constrained tool invocation rates. Capacity grows through participation history and time. Sybil accounts are cheap to create but expensive to make useful.

3. **Context-level thresholds.** Each context sets its own admission requirements — behavioral history, endorsements, attestations. A casual group chat requires just a valid DID. A high-trust financial context might require 6 months of history, 3 independent endorsements, and challenge-verified capabilities.

These compose: device attestation makes creation expensive, earned capacity makes new identities limited, context thresholds make meaningful participation require real history. And consequences for detected sybil attacks render the accounts single-use — the investment in aging and building history is lost.
