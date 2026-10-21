# 10. Infrastructure and Self-Hosting

## 10.1 Philosophy

Self-hosting is a first-class deployment model, not an afterthought. But "self-hosting" means different things at different layers, and the protocol should be honest about which layers are easy and which are hard.

What the protocol guarantees: **no infrastructure operator owns your identity, your relationships, or your social graph.** These live on your device, bound to your identifier, portable across any infrastructure. This is the non-negotiable.

What the protocol provides but doesn't trivialize: **relay and storage infrastructure.** Running your own relay is simpler than running a Matrix homeserver, but it's still a server. Managed infrastructure exists for this layer — not as a lock-in mechanism, but because reliable message delivery and media hosting have real operational costs. The protocol ensures that managed infrastructure is substitutable, not that it's unnecessary.

## 10.2 Device-as-Node

The protocol is designed so that a user's device can be a full protocol participant — not a client that talks to a server, but a node. The device stores protocol state, performs cryptographic operations, and executes protocol logic locally.

This is an explicit architectural choice to avoid Matrix's adoption failure mode, where "self-hosting" means "run a Synapse instance on a server you maintain." For SCP, the device *is* the node. But this comes with an honest constraint: **a device that's offline is a node that's unavailable.** The protocol handles this through relays (§10.4), which means every non-server deployment depends on relay infrastructure for availability. The protocol's real guarantee is not "no server needed" — it's "no server *owns* you." Your identity, your state, and your relationships live on your device. The relay is delivery infrastructure, not a dependency.

```
Deployment spectrum:

  Phone running SCP app          ← full participant when online.
       │                            Needs relay for offline delivery.
       │                            iOS background limits apply.
       │
  Laptop running SCP daemon      ← more capable. Can be always-on.
       │                            Can serve as personal relay.
       │
  Agent workstation              ← dedicated always-on hardware running
       │                            builder agents. Mac Mini, Mac Studio,
       │                            or equivalent. Non-technical users.
       │                            Already always-on for agent tasks.
       │                            Natural SCP node: relay, hosting
       │                            as marginal load.
       │                            Likely the most common always-on
       │                            self-hosted node type.
       │
  Personal server / NAS          ← power user. Persistent relay.
       │                            Not "self-hosting" in the Matrix
       │                            sense — no protocol server, just
       │                            relay + storage.
       │
  Managed infrastructure         ← convenience. High availability.
       │                            Media hosting. Paid service.
       │
  All of the above simultaneously ← the expected state for many users.
```

The **agent workstation** tier is a critical addition to the deployment model. As builder agents (LLMs that generate and manage software) become mainstream, non-technical users are acquiring dedicated always-on hardware to run them. These machines are already always-on, capable, and user-controlled. SCP infrastructure — relays, context hosting — is marginal additional load on hardware that's already running 24/7. The builder agent that generates an SCP app can also provision the infrastructure: spin up a relay, configure contexts, register outlets — developer and ops in one.

This changes relay economics fundamentally. The question is not "who pays for relay infrastructure" but "you already have the hardware, the relay is just another process." Self-hosting stops being an aspirational option for technical users and becomes the natural default for anyone with a builder agent workstation. The gravitational pull toward centralized relays weakens when most users have their own always-on node.

The protocol must function correctly at every point on this spectrum. A phone-only user and a user with dedicated infrastructure are both first-class participants. The protocol cannot assume persistent connectivity, stable IP addresses, or server-grade resources.

The critical difference from Matrix: in Matrix, your homeserver owns your identity (`@user:server`). If it dies, you're in trouble. In SCP, your identity is self-sovereign. If your relay dies, you switch relays. If your device dies, you recover your identity through social/device recovery (§3.3). No infrastructure operator holds your identity hostage. This — not the elimination of servers — is the real structural advantage.

## 10.3 Minimal Protocol State

The protocol's state footprint per context is deliberately minimal: membership list, role assignments, capability tokens, outlet registrations, governance model, and content hashes. Not content itself. Not media. Not application state.

This is load-bearing. If protocol state is small, devices can be nodes. If protocol state includes all content, only servers can play. Matrix learned this the hard way — room state accumulates unboundedly and Synapse instances consume gigabytes of RAM for large rooms.

Content storage is outside protocol scope — the protocol does not define where content lives, how it's stored, or how it's replicated. That is a client and app-layer decision (see §10.8). The protocol concerns itself with protocol state (membership, roles, tokens, governance, event logs). Content is whatever the context's participants produce and consume. The protocol delivers it through encrypted envelopes; storage is the app's responsibility.

**Verifiable event logs (§7.3.1) add a storage requirement.** Each context maintains a Merkle tree of its event history. This is protocol state — it must be available for validation queries. The tree itself is append-only and grows with context activity. For active contexts, this could become significant. The following subsections define pruning rules, checkpoint mechanisms, and availability requirements that resolve the tension between minimal state and verifiable history.

### 10.3.1 Event Log Pruning Rules

Event log pruning compresses historical event data while preserving verifiability. Pruning operates on completed checkpoint intervals — it never modifies un-checkpointed events.

**Pruning tiers:**

| Tier | Retention | What is retained | What is pruned |
|------|-----------|------------------|----------------|
| Full | All events | Complete event data + Merkle proofs | Nothing |
| Summary | Checkpoint roots + event type counts per interval | Checkpoint Merkle root, aggregate statistics (event counts by type, membership delta) | Individual event payloads and intermediate Merkle nodes |
| Root-only | Checkpoint roots only | Checkpoint Merkle root hash and sequence number | Everything except the root |

**Pruning policy:** Each context declares a pruning policy at creation as part of its governance parameters:

```
EventLogPruningPolicy {
  full_retention_checkpoints: u32,    // Number of recent checkpoints retained at Full tier (MUST >= 2, default: 10)
  summary_retention_checkpoints: u32, // Number of checkpoints retained at Summary tier after Full expires (default: 100)
  root_only_after: bool,              // Whether to prune to Root-only after Summary expires (default: true)
}
```

- The most recent `full_retention_checkpoints` checkpoints are always retained at Full tier. This ensures recent history is always available for validation queries and dispute resolution.
- The next `summary_retention_checkpoints` checkpoints are retained at Summary tier. This provides aggregate data for participation record computation (§7.3.2) without storing individual events.
- Older checkpoints are retained at Root-only tier if `root_only_after` is true, otherwise deleted entirely. Root-only checkpoints form a verifiable chain of custody — any checkpoint root can be verified against its successor.

**Maximum event log size:** The SDK MUST enforce a per-context event log size limit of 100MB at the Full tier. When the log exceeds this limit, the SDK MUST prune the oldest Full-tier checkpoint interval to Summary tier, regardless of the retention policy. This prevents unbounded state growth on resource-constrained devices.

**Pruning execution:** Pruning is performed by the SDK locally. Each device prunes independently based on the context's policy. There is no coordination protocol — devices may hold different amounts of history based on when they joined and when they last pruned. The Merkle checkpoint chain ensures that devices with different pruning states can still verify each other's claims by comparing checkpoint roots.

### 10.3.2 Checkpoint Mechanism

Checkpoints compress the event log into periodic Merkle root snapshots that serve as trust anchors for pruned history.

**Checkpoint interval:** A checkpoint is created every `checkpoint_interval` events (default: 1000, configurable per context via governance, minimum: 100, maximum: 100,000). The checkpoint interval is declared at context creation and MAY be changed via governance action.

**Checkpoint format:**

```
EventLogCheckpoint {
  context_id:       String,
  sequence_number:  u64,          // Monotonic checkpoint number (0, 1, 2, ...)
  event_range:      (u64, u64),   // (first_event_seq, last_event_seq) inclusive
  merkle_root:      [u8; 32],     // SHA-256 Merkle root of events in this interval
  previous_root:    [u8; 32],     // Merkle root of the previous checkpoint (zeros for first)
  event_count:      u64,          // Total events in this checkpoint interval
  membership_snapshot: MembershipDigest, // SHA-256 hash of the sorted membership list at checkpoint time
  timestamp:        u64,          // Wall-clock time of checkpoint creation (best-effort)
  creator_did:      Identifier,   // the member who created this checkpoint
  signature:        P256Signature,  // Signed by creator's signing key
}
```

**Checkpoint chain:** Each checkpoint includes `previous_root`, forming a hash chain. Any device can verify the integrity of the checkpoint chain by walking backward from the most recent checkpoint. A gap in the chain (missing checkpoint) is detectable by comparing `sequence_number` values.

**Checkpoint creation:** The member whose event triggers the checkpoint interval boundary creates the checkpoint. If multiple members submit the boundary event concurrently, the first checkpoint received by a majority of members is canonical (determined by the Merkle event log ordering, §7.3.1). Duplicate checkpoints for the same interval are discarded.

### 10.3.3 Event Log Availability

**Storage tiers by device type:**

| Device | Full tier | Summary tier | Root-only | Proof fetching |
|--------|-----------|--------------|-----------|----------------|
| Server/workstation | Unlimited | Unlimited | All | Serves proofs to peers |
| Desktop | Policy-based | Policy-based | All | Serves and fetches |
| Mobile | 2 checkpoints minimum | 10 checkpoints minimum | All | Fetches from relays/peers |

**Proof-on-demand protocol:** Devices that have pruned Full-tier data can request Merkle proofs from peers or relays that still hold the full data. The request format is:

```
EventLogProofRequest {
  context_id: String,
  event_sequence: u64,         // Sequence number of the event to prove
  checkpoint_sequence: u64,    // Checkpoint interval containing the event
}
```

The response includes the Merkle inclusion proof (sibling hashes along the path from the event's leaf to the checkpoint's Merkle root). The requester verifies the proof against the checkpoint root they hold locally. If the checkpoint root is unavailable locally (pruned beyond Root-only), the proof cannot be verified — the requester MUST fetch the checkpoint from a peer first.

**Relay caching:** Relays MAY cache event log checkpoints and serve them to members. Checkpoints are signed by their creator and verified by the recipient — the relay cannot forge checkpoints. Relay caching is opportunistic; the protocol does not require relays to store event log data.

## 10.4 Relay Architecture

Devices that aren't always online need relays for message delivery. Relays hold encrypted payloads and deliver them when the recipient comes online. They are the availability layer — the thing that makes the protocol work when devices are asleep, offline, or behind NAT.

**Design goals:**

- **Protocol-unaware.** Relays don't interpret protocol semantics. They store and forward encrypted blobs. This keeps relay implementation simple and prevents relay operators from gaining protocol-level influence.
- **Substitutable.** Switching relays requires no identity change, no context migration, no social disruption. Identity rests on the key-event log, not on a relay. This is the key structural difference from Matrix homeservers.
- **Untrusted for content.** Relays see encrypted payloads. They cannot read content, inspect membership, or understand context semantics. A malicious relay can delay or drop messages; it cannot compromise confidentiality or integrity.

**Honest constraints:**

- **Metadata exposure.** Traffic analysis is powerful even with encrypted payloads. The protocol provides layered metadata privacy protections: minimal outer envelopes with per-context pseudonyms, fixed bucket padding, persistent connections, constant-rate cover traffic, and relay set partitioning. (See §9.9.1 for the formal relay threat model — what relays CAN and CANNOT do — and §9.10 for the complete metadata privacy architecture.)
- **Relay discovery.** If Alice wants to reach Bob, she needs to know Bob's relay. If Bob switches relays, Alice needs to discover the new one. This requires either a centralized directory (defeats the purpose), a distributed discovery mechanism (adds complexity and latency), or multi-relay registration (Bob publishes to several relays, Alice checks all of them). Nostr's experience: users publish a relay list, clients check multiple relays. Workable but not seamless. Relay list authentication is specified in §9.6.3 — NIP-65 signed events prevent relay list substitution attacks.
- **Operational complexity.** A production relay needs reliable delivery, ordering, deduplication, rate limiting, and abuse prevention. "Simple message queue" undersells this. A reference implementation should exist, but running it reliably is a server operations task — not "install an app" level.
- **Gravitational pull.** In theory relays are commodity. In practice, network effects apply to infrastructure. Nostr shows this: a few popular relays handle most traffic. The protocol can't prevent this concentration, but key-event-log identity ensures it doesn't create lock-in — popular relay dies, users switch, identity survives. The agent workstation trend (§10.2) may significantly weaken centralization pressure — if most users run their own always-on node, personal relays become the default rather than the exception.

**Self-hosting:** Running a personal relay is feasible for technical users. It requires a stable address, TLS, and uptime commitment. This is meaningfully simpler than running a Matrix homeserver (no state resolution, no federation protocol, no room DAG) but it is still a server. The protocol should ship a reference relay that minimizes operational burden, but should not claim self-hosting is effortless.

**Multi-relay resilience.** For availability and equivocation resistance, clients SHOULD publish to 3+ relays and maintain per-relay reliability scores (§9.9.2). The Relay Consistency Protocol (§9.9.3) enables members to detect relays that show different event histories to different clients. Combined with per-sender sequence numbers (§9.8.5), clients can detect message suppression and switch to healthier relays automatically.

**Deletion is bound to the publisher.** A relay authenticates no publisher (ADR-004), so a `DELETE` proves its right with a token instead of an identity. Each PUBLISH carries `delete_token_hash = SHA-256("scp-relay-delete-v1:" || blob_id || delete_token)`, the hash of 32 bytes the publisher draws freshly for that PUBLISH and keeps, and a `DELETE` presents the token. The relay keeps each hash as a delete claim on the blob, deletes the blob once every claim on it has been presented, and answers `4043` DELETE_UNAUTHORIZED to a `DELETE` whose token matches no claim (ADR-004, operation 5). The relay learns no publisher's identifier and no value that links two blobs, and a party that learns a `blob_id` from a `QUERY` cannot delete the blob, so no third party removes another member's pending Commits, Welcomes, KeyPackages or broadcast chunks from an honest relay. Because each PUBLISH draws a fresh token, a token one relay learns from a `DELETE` matches no claim at another relay that stores the same blob. A party that holds a blob's bytes can publish it again with a claim of its own; it then keeps the blob stored until its TTL ends or until it presents its own token, but it cannot remove the blob while the publisher's claim stands. A relay that ignores these rules can delete or keep any blob it stores, which §9.9.1 already allows an untrusted relay.

**Relay conformance testing.** Relay storage backends implement the `BlobStorage` trait, which §17.1 of the persistence and storage spec, the storage architecture overview, names together with its five methods and the file that declares it. §17.11 of that spec, the extension points section, states the adapter contract: the five required methods, the two streaming methods that carry default implementations, and a passing run of the `blob_store_conformance!()` macro (§16.12.6), which tests store/retrieve roundtrips, TTL expiry, listing, deletion, and concurrent access. §17.7 of that spec, the first-party adapter roster, lists five `BlobStorage` backends: `InMemoryBlobStorage` (testing and development, shipped in phase 1), `SqliteBlobStore` (personal relays), `RedbBlobStore` (medium relays, pure Rust), `PostgresBlobStore` (production/enterprise), and `S3BlobStore` (large-scale/cloud). Every one of the five must pass the same suite. The `InMemoryRelay` of §16.4.2 of the test infrastructure spec is not one of them, because §16.4.1 of that same test infrastructure spec states that the in-memory relay stores blobs in its own `HashMap` and implements no `BlobStorage` method. Multi-relay adversarial scenarios — suppression, equivocation, delay, replay, Commit suppression — are tested via `BehaviorMode` fault injection in the network simulation harness (§16.4.3).

## 10.5 SDK Transport Architecture

The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance, provenance. This is the product. Transport is not the product.

The SDK provides a **transport abstraction layer**: a defined interface contract between protocol logic and delivery infrastructure. The abstraction specifies what properties the transport must provide (encrypted envelope delivery, offline store-and-forward, context-scoped subscription, relay discovery) without specifying how the transport implements them.

Below the abstraction, **transport bindings** adapt SCP's requirements to specific delivery infrastructure. The SDK ships at least one reference binding. The binding is responsible for encoding SCP envelopes into the transport's native format, managing transport connections, and mapping SCP identities to transport-native identities (an SCP identifier to a Nostr npub, for one).

**What SCP specifies for transport:**

- Encrypted envelope format (SCP's responsibility — the payload the transport carries)
- Transport abstraction interface (SCP's responsibility — the contract bindings must implement)
- SCP native relay protocol (SCP specifies this — the simplest possible store-and-forward relay purpose-built for SCP envelopes)
- Reference relay implementation (SCP ships this — a minimal relay for self-hosters)
- Transport adapter implementations organized by specification depth (§10.5.1). Tier 1 bindings are fully specified with wire mappings and conformance requirements. Tier 2 bindings have documented TransportAdapter mappings. Tier 3 bindings are feasibility-confirmed.

The SCP native relay is the canonical reference — the simplest possible thing that satisfies SCP's transport needs: accept encrypted blobs, store them, forward to subscribers by context ID and/or recipient identifier, respond with delivery receipts, honor deletion requests. All other adapters map the transport abstraction to their respective protocols.

**What SCP does not specify:**

- Third-party relay protocol internals (that's Nostr's/Matrix's/etc. spec, not SCP's)
- Third-party relay implementation
- Relay operations (that's either self-hosting or managed infrastructure)

**No fundamental dependency on any single transport.** The protocol must function correctly on any transport that implements the abstraction interface. SCP native relays are the default, but the protocol does not assume or require them. A deployment using only Hyperswarm, or only Matrix, or only direct WebSocket, is equally valid.

**Transport adapter conformance.** Every `TransportAdapter` implementation is verified by the `transport_conformance!()` macro (§16.12.1), which tests send/subscribe roundtrips, backfill with `since`, unsubscribe, query, delete, and deduplication. The `InMemoryTransport` (§16.5) is the reference implementation that passes conformance first; every production adapter must pass the same suite before being considered complete.

**Transport security.** All relay connections MUST use TLS 1.3 (TLS 1.2 acceptable as fallback). Certificate pinning is supported for known relays. See §9.13 for the complete transport security specification.

**Encryption-as-access-control.** Context access control is enforced through encryption, not through relay logic. Specifically, each context maps to one MLS group (§9.7.1); the MLS group key material is the access credential. All context events are encrypted with the current MLS epoch secrets before reaching the transport layer. Relays store and forward opaque blobs — they cannot read content, verify membership, or enforce roles. Key distribution is membership. Member removal triggers MLS Remove Commit + epoch advancement — the removed member does not possess the new epoch's key material and physically cannot decrypt subsequent messages. This keeps the relay layer genuinely protocol-unaware and makes any encrypted-blob-capable relay — including existing Nostr relays — usable as SCP transport without modification.

**Blocking uses a separate sender-side key layer, not MLS group membership.** Identity-to-identity blocking (§3.6) is a unilateral, per-relationship action — it does not require group coordination and does not affect the blocked party's membership in the context. When Alice blocks Dave, Alice rotates her personal sender key and redistributes it to all context members except Dave. Dave physically cannot decrypt Alice's future messages. Dave remains an MLS group member and can still decrypt messages from other members.

This is architecturally distinct from member removal, which IS a group action: MLS Remove Commit advances the entire group to a new epoch, and the removed member loses access to ALL future messages from ALL members. Blocking and removal serve different purposes and use different cryptographic mechanisms:

- **Blocking** (sender-side key layer): Unilateral. Per-relationship. Blocker writes; no group coordination. Blocked party loses access to blocker's messages only. O(n) key redistribution per block (distribute to n-1 members).
- **Removal** (MLS epoch advancement): Group action. Affects all members. Removed party loses access to all future messages. O(log n) via MLS tree ratcheting.

The sender-side key layer works as follows: each member maintains a personal sender key alongside their MLS leaf key. Messages are double-encrypted — first with the sender's personal key, then with the MLS group key. All members hold all other members' sender keys (distributed via MLS application messages). When a block is issued, the blocker generates a new sender key and distributes it to all members except the blocked party via individual MLS application messages. The blocked party can still decrypt the MLS layer but encounters ciphertext from the blocker that they cannot decrypt.

### 10.5.1 Adapter Tiers

Transport adapters are organized into three tiers by specification depth:

| Tier | Adapters | Spec level |
|------|----------|------------|
| **Tier 1: Fully specified** | SCP native relay (ADR-004), QUIC (§10.14), WebTransport (§10.15), UDP/DTLS (§10.16) | Wire format mapping, conformance suite, fallback behavior |
| **Tier 2: Mapping defined** | Nostr, Matrix, libp2p, Hyperswarm, WebRTC, MQTT, NATS, Tor, I2P, BLE, Yggdrasil/cjdns, ZeroMQ | TransportAdapter method mapping documented per adapter (§10.5.2) |
| **Tier 3: Named** | SSB | Feasibility confirmed; mapping complex (gossip/append-only model diverges from SCP's request/response semantics) |

**Tier requirements:**
- **Tier 1:** Must pass `transport_conformance!()` (§16.12.1). Full wire format specification. Fallback chain documented.
- **Tier 2:** Must document how each of the 5 `TransportAdapter` methods maps to the adapter's native primitives, plus connection model and key constraints.
- **Tier 3:** Feasibility confirmed through analysis. Spec pending.

**Transport advertisement.** Relays advertise supported transport bindings in `.well-known/scp` under `relay_config.transports`:

```json
{
  "relay_config": {
    "transports": ["websocket", "quic", "webtransport", "udp-dtls"]
  }
}
```

Clients use this to select the best available transport. `"websocket"` is always present (mandatory baseline). Other transports are optional. Clients SHOULD prefer QUIC over WebSocket when both are available (lower overhead, connection migration). Browser clients SHOULD prefer WebTransport over WebSocket when the `WebTransport` API is available.

### 10.5.2 Tier 2 Adapter Mapping Briefs

Each Tier 2 adapter documents how `TransportAdapter`'s 5 methods (`send`, `subscribe`, `unsubscribe`, `query`, `delete`) map to the adapter's native primitives, the connection model, and key constraints. These briefs are sufficient for implementation; detailed wire format specifications are not required for Tier 2.

**Nostr** (NIP-01 relay protocol)
- `send` → publish Nostr event (custom kind in 1000–9999 range, e.g., kind=29078). `routing_id` in event tag. Encrypted blob in `.content`. Avoid parameterized-replaceable kinds (30000–39999) — these store only the latest event per `d`-tag, silently discarding prior messages.
- `subscribe` → `REQ` with filter on kind + routing_id tag. Stream of `EVENT` messages.
- `unsubscribe` → `CLOSE` on the subscription.
- `query` → `REQ` with `since` timestamp filter, collect results until `EOSE`.
- `delete` → NIP-09 deletion event referencing the blob's event ID. Best-effort (relay MAY ignore).
- **Connection model:** WebSocket to Nostr relay. Existing Nostr infrastructure reusable as-is. No code changes to Nostr relays.
- **Constraints:** Nostr events are JSON (not MessagePack) — blob is base64-encoded in `.content`, adding ~33% overhead. Max event size varies by relay (typically 64KB–1MB). No server-side TTL enforcement (relay purging is operator policy).

**Matrix** (Client-Server API v1.11+)
- `send` → `PUT /_matrix/client/v3/rooms/{roomId}/send/scp.blob/{txnId}`. Blob in event content. `txnId` is a unique transaction ID for idempotency.
- `subscribe` → `/sync` long-poll with room filter. BLOBs arrive as timeline events.
- `unsubscribe` → Remove room from sync filter.
- `query` → `GET /_matrix/client/v3/rooms/{roomId}/messages` with `from` token and `dir=f`.
- `delete` → Redact event. Best-effort (federated servers may retain).
- **Connection model:** HTTPS to Matrix homeserver. Auth via Matrix access token. One "room" per routing_id.
- **Constraints:** JSON event format (base64 blob). Federation delays add latency. Homeserver stores all history (no TTL — use redaction). Rate limits vary by homeserver.

**libp2p** (peer-to-peer networking stack)
- `send` → Publish to GossipSub topic (topic = hex(routing_id)). Envelope as raw bytes.
- `subscribe` → GossipSub subscribe to topic. Stream of messages.
- `unsubscribe` → GossipSub unsubscribe from topic.
- `query` → Not natively supported. Requires a DHT or custom request/response protocol. Fall back to peer exchange.
- `delete` → Not supported (P2P, no central store).
- **Connection model:** Peer-to-peer. Connection multiplexed via yamux (mplex is deprecated). Peer discovery via mDNS (LAN) or Kademlia DHT.
- **Constraints:** No durable storage (messages lost if no peers online). No backfill. Best for real-time P2P use cases with online peers. `query` requires custom protocol or external storage.

**Hyperswarm** (Holepunch/Hypercore ecosystem)
- `send` → Write to Hypercore append-only log (one log per routing_id). Envelope as log entry.
- `subscribe` → Replicate Hypercore log, stream new entries.
- `unsubscribe` → Stop replication.
- `query` → Read Hypercore log entries with sequence number filtering.
- `delete` → Not supported (append-only). Can mark as tombstoned via subsequent entry.
- **Connection model:** P2P via Hyperswarm DHT. NAT traversal built in. Connection established by "joining" a topic (derived from routing_id).
- **Constraints:** Append-only (no true delete). Log creator must be online for initial replication. Hypercore is single-writer — each participant needs their own log, routing_id maps to a "discovery key" that finds all relevant logs.

**WebRTC** (data channels for SCP operations)
- `send` → Send on DataChannel (label = hex(routing_id)). Binary message.
- `subscribe` → Open DataChannel with label = hex(routing_id), `ondatachannel` for inbound.
- `unsubscribe` → Close DataChannel.
- `query` → Request/response over DataChannel (application-level, no native query).
- `delete` → Not applicable (P2P, no central store).
- **Connection model:** P2P via ICE (STUN/TURN). Signaling via SCP relay (bootstrap: use native relay to exchange SDP offers). DTLS encryption (DataChannels use DTLS over SCTP, not DTLS-SRTP which is for media streams). One PeerConnection per peer, multiple DataChannels per connection.
- **Constraints:** Requires signaling channel (SCP relay or out-of-band). P2P only — no durable storage, no backfill. NAT traversal via ICE. Battery-intensive on mobile (frequent STUN keepalives). Best for real-time P2P between online peers.

**MQTT** (v5.0, topic-based pub/sub)
- `send` → `PUBLISH` to topic `scp/{hex(routing_id)}`. QoS 1 (at-least-once). Blob as payload.
- `subscribe` → `SUBSCRIBE` to topic `scp/{hex(routing_id)}`. Broker delivers matching messages.
- `unsubscribe` → `UNSUBSCRIBE` from topic.
- `query` → MQTT 5.0 Request/Response with correlation data. Or: use retained messages (broker stores last message per topic).
- `delete` → Publish empty retained message to clear (limited — only clears retained, not queued).
- **Connection model:** TCP/TLS to MQTT broker. Persistent session (CleanStart=false) enables offline message queuing. Lightweight keepalive (PINGREQ).
- **Constraints:** MQTT retained messages store only the last message per topic — no full backfill. For full `query` support, need MQTT 5.0 + broker-side plugin or external storage. Binary payloads natively supported (no base64). Good fit for IoT (§10.16 constrained devices can use MQTT instead of raw UDP/DTLS).

**NATS** (lightweight messaging)
- `send` → `PUB scp.{hex(routing_id)}`. Blob as payload.
- `subscribe` → `SUB scp.{hex(routing_id)}`. Stream of messages.
- `unsubscribe` → `UNSUB`.
- `query` → NATS JetStream: `Consumer.Fetch` with `DeliverPolicy::ByStartTime(since)`.
- `delete` → JetStream message delete by sequence number.
- **Connection model:** TCP/TLS to NATS server. Lightweight text protocol. JetStream for persistence (required for `query`/`delete`).
- **Constraints:** Core NATS is fire-and-forget (no persistence) — JetStream required for SCP semantics. JetStream adds operational complexity. Very low latency (<1ms local). Binary payloads supported.

**Tor** (onion-routed transport)
- All 5 methods → delegate to underlying adapter (WebSocket or QUIC) routed through Tor.
- **Connection model:** SOCKS5 proxy to Tor circuit. WebSocket-over-Tor or QUIC-over-Tor (experimental). Relay can run as Tor hidden service (.onion address).
- **Constraints:** High latency (total circuit RTT typically 200–600ms for 3-hop circuits; hidden service connections use 6 hops — client 3 + service 3 to rendezvous — approximately doubling latency). No UDP (Tor is TCP-only — QUIC requires experimental Tor UDP support). Cover traffic less useful (Tor provides some traffic analysis resistance at the network layer, though not immune to timing correlation). Relay .onion address replaces DNS — the service record's `SCPRelay` entry carries the `.onion` URL.

**I2P** (invisible internet protocol)
- All 5 methods → delegate to underlying adapter routed through I2P.
- **Connection model:** I2P streaming library (TCP-like) or I2P datagrams (UDP-like). Relay runs as I2P destination with b32.i2p address.
- **Constraints:** Similar to Tor but fully distributed (no exit nodes). Higher latency. Smaller network. I2P datagrams enable UDP-like transport. The service record's `SCPRelay` entry uses a `.b32.i2p` URL.

**BLE** (Bluetooth Low Energy, proximity transport)
- `send` → Write to GATT characteristic (UUID derived from routing_id). Blob fragmented across writes (BLE ATT MTU default 23 bytes, up to 247 bytes with negotiation via Bluetooth 4.2+ Data Length Extension).
- `subscribe` → Enable GATT notifications on characteristic.
- `unsubscribe` → Disable GATT notifications.
- `query` → Read GATT characteristic (returns latest stored blob only — no history).
- `delete` → Not supported (peripheral manages storage).
- **Connection model:** Central (client) connects to Peripheral (device). One GATT service per SCP instance. Characteristics per routing_id. Range: ~10–100m.
- **Constraints:** Default ATT MTU 23 bytes (20 usable), negotiable to 247 bytes with DLE — fragmentation required for all but trivial blobs. Low throughput (10–100 kbps typical). No backfill. BLE connections can be dropped by mobile OS to save power. Battery-efficient (designed for IoT). Local proximity only — not a network transport.

**Yggdrasil / cjdns** (encrypted mesh networking)
- All 5 methods → delegate to underlying adapter (WebSocket, QUIC, or direct TCP) running over the mesh network's IPv6 overlay.
- **Connection model:** Yggdrasil/cjdns provides an encrypted IPv6 overlay network. SCP adapter connects to relay using the relay's Yggdrasil/cjdns IPv6 address instead of a public IP. No special adapter logic — just network-layer routing.
- **Constraints:** Requires Yggdrasil/cjdns daemon running on both client and relay. The relay advertises its mesh IPv6 address in its service record. Latency depends on mesh topology. Provides NAT traversal for free (overlay addresses are globally routable within the mesh).

**ZeroMQ** (broker-less messaging)
- `send` → `zmq_send` on PUB socket bound to `tcp://*:port` (or connect to XPUB/XSUB proxy).
- `subscribe` → `zmq_connect` SUB socket, `zmq_setsockopt(ZMQ_SUBSCRIBE, routing_id)`.
- `unsubscribe` → `zmq_setsockopt(ZMQ_UNSUBSCRIBE, routing_id)`.
- `query` → REQ/REP pattern to a storage service (not native to ZeroMQ).
- `delete` → Not natively supported (fire-and-forget).
- **Connection model:** Broker-less PUB/SUB or brokered via XPUB/XSUB proxy device. TCP or IPC transport. No built-in encryption (use CurveZMQ for transport security).
- **Constraints:** No durable storage (fire-and-forget PUB/SUB). `query`/`delete` require external storage service. Best for high-throughput LAN/datacenter use cases. CurveZMQ adds Curve25519-based encryption (NaCl/libsodium primitives) but is not TLS.

## 10.6 Content and Data Sovereignty

**Content is agnostic.** The protocol has no opinion on what content is — text, images, video, structured data, binary blobs, real-time streams. Content is whatever contexts produce and whatever frontends need to display. The protocol does not define content types, does not constrain content formats, and does not host content. App builders and their clients decide what content they support and how they store it.

**Storage is the user's responsibility — but the SDK makes it tractable.** SCP is a protocol, not an entity. It does not host anything. The people and organizations who use the protocol host their own content. But "host your own content" means different things at different scales, and the SDK must make all of them first-class:

```
Deployment spectrum for content/data:

  Generated ephemeral client          ← Content lives on the user's device
       │                                or wherever the generated app puts it.
       │                                Possibly transient. Possibly local-only.
       │
  Personal app / home server          ← User controls storage. Small scale.
       │                                Local NAS, personal cloud, phone storage.
       │
  Community app                       ← App developer chooses storage backend.
       │                                Could be managed hosting, could be
       │                                user-contributed, could be hybrid.
       │
  Enterprise app on SCP               ← Enterprise-grade databases, CDNs,
       │                                content lakes. Full infrastructure team.
       │
  All of the above simultaneously     ← Different contexts, different apps,
                                        different storage. Protocol doesn't care.
```

**What the SDK provides:** The SDK handles encrypted envelope delivery, context key management, and protocol state. For content storage, the SDK provides interfaces and guidance for sovereign storage at every scale — but does not mandate a specific backend. A generated client that stores everything locally is valid. An enterprise app with a distributed content lake is equally valid. The protocol transmits content through encrypted envelopes; where that content persists after delivery is an app-layer decision.

**Media is the same story.** Photos, video, audio, large files — these have real costs (bandwidth, transcoding, storage) that the protocol does not absorb because the protocol is not an entity that can absorb costs. Managed infrastructure services can offer media hosting as a paid service. Self-hosters handle their own media. The protocol treats media like any other content — it flows through encrypted envelopes. Heavy content may require out-of-band storage with in-band references, but that's a client implementation pattern, not a protocol requirement.

## 10.7 Notifications and Push

Mobile devices need push notifications. On iOS the only mechanism is APNs (Apple Push Notification service). On Android, FCM (Firebase Cloud Messaging). Both are platform-mediated — Apple and Google are in the delivery path.

**Push notification opacity is mandatory.** Push payloads MUST contain a wake signal and nothing else. No context ID, no sender identifier, no message preview, no metadata of any kind. The device wakes, connects to relays, pulls encrypted envelopes, and decrypts locally. Apple/Google learn only that the device received a notification at a specific time.

- **Push payloads are fully opaque.** The push payload contains exactly one piece of information: "wake up." No sender, no context, no count, no preview. The SCP agent on the device connects to its relay set and pulls all pending envelopes.
- **The push service knows timing, not content or source.** Apple/Google learn when a device received a notification. They cannot determine which context, which sender, or even whether the notification corresponds to one message or many. A WebPush push service also learns which relay sent each wake, because every WebPush request carries the relay's VAPID public key and its operator contact (§10.7.1).
- **A sovereign push alternative is desirable but not blocking.** If a mechanism emerges that enables push without platform gatekeepers, the protocol should adopt it. For now, this is an accepted constraint with the opacity guarantee limiting metadata exposure to timing only.

### 10.7.1 Push Registration Protocol

Clients register for push notifications with relays via the following wire protocol:

**PushRegistration message.** `22-human-readable-addressing.md` §22.11.4 defines the `PushRegistration` fields and their wire types, and the `PushRegistration` table of `09-security-model.md` §9.5.2 lists the fields of its signature preimage in order. The registrant signs the preimage with the key its key state lists `Current` in the `#active` role.

**Registration flow:**

1. The client generates a `PushRegistration` message and signs it with the identity's Active Signing Key.
2. The client sends the `PushRegistration` to the relay in a PUBLISH operation (ADR-004, the SCP native relay protocol) whose `routing_id` is the relay's reserved push routing ID, `SHA-256("scp-push-registration" || relay_url)`, where `relay_url` is the relay's canonical URL that `09-security-model.md` §9.18.2 defines. For a relay the client knows as a tier 3 relay entry, an `SCPRelay` entry that carries a `bridgeTarget` (`18-addressability-and-deployment.md` §18.2.1), the reserved push routing ID is that entry's tier 3 push routing ID, `SHA-256("scp-push-bridge:" || bridge_url || bridge_target)` (`09-security-model.md` §9.18.2 **Tier 3 push routing ID**), and **Tier 3 relays** below states how the PUBLISH reaches the relay.
3. The relay verifies the signature against the key the identity's key state lists `Current` in the `#active` role, resolved by replaying that identity's key-event log (`09-security-model.md` §9.7.4.2 R2, R3, R8). The relay rebuilds the preimage with its own canonical URL and target, the ones from which it derived the reserved push routing ID the PUBLISH arrived at (`09-security-model.md` §9.5.2, §9.18.2), never with a URL or target the client supplies. The target is the tier 3 entry's `bridgeTarget` when that routing ID is a tier 3 push routing ID, and `SHA-256(0x00)` otherwise. A message signed for a different relay URL or target therefore fails verification. The relay rejects an invalid signature with `4060` PUSH_REGISTRATION_REJECTED (ADR-004). A client that registers with several relays signs a separate message for each relay, with that relay's canonical URL and target.
4. The relay stores the registration, associating the push token with the identity identifier and the listed `routing_ids`. The registration key is the triple (identity identifier, platform, token), so each device of one identity, including two devices on one platform, holds its own registration, and the relay stores at most one registration per registration key. The relay holds at most 16 registrations per identity identifier (`09-security-model.md` §9.18.13). It rejects a registration whose registration key is not stored when the identity identifier already holds 16, with `4064` PUSH_REGISTRATION_LIMIT (ADR-004), and the cap never rejects a registration whose registration key is already stored. A `PushRegistration` whose `routing_ids` list is empty is invalid, and the relay rejects it with `4060` PUSH_REGISTRATION_REJECTED.
5. When a blob arrives at a routing ID that a stored registration lists in its `routing_ids`, the relay sends a wake signal to the registered token through that token's push service. A wake signal carries no content, no context, no sender and no metadata. The relay sends exactly the request this wake-signal table gives for the registration's platform:

   | Platform | Request | Headers | Body |
   |----------|---------|---------|------|
   | APNs | `POST /3/device/<APNs device token>` over HTTP/2 to the gateway of the APNs environment the relay operator configured: `api.push.apple.com` for `production`, `api.sandbox.push.apple.com` for `sandbox` | `authorization: bearer <provider JWT>`, `apns-push-type: background`, `apns-priority: 5`, `apns-topic: <the app's bundle ID>` | `{"aps":{"content-available":1}}` |
   | FCM | `POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` (the FCM HTTP v1 API) | `Authorization: Bearer <OAuth 2.0 access token>`, `Content-Type: application/json` | `{"message":{"token":"<FCM registration token>","data":{"scp":"1"},"android":{"priority":"HIGH"}}}` |
   | WebPush | `POST <endpoint>` over HTTPS, where `<endpoint>` is the endpoint URL the registration's token carries (`22-human-readable-addressing.md` §22.11.4), used byte for byte | `Content-Encoding: aes128gcm`, `Urgency: high`, `TTL: 3600`, `Authorization: vapid t=<VAPID JWT>, k=<VAPID public key>` | The RFC 8291 encryption of the 11-byte plaintext `{"scp":"1"}` to the token's `p256dh` and `auth`, as one aes128gcm record of 114 bytes |

   - The APNs body carries no `alert`, `badge` or `sound` key, and the FCM body carries no `notification` key, because each of those keys makes the operating system show a notification.
   - The FCM wake value is the string `"1"`, because FCM requires every value in `data` to be a string. The FCM registration token appears only in `message.token`.
   - The relay sets `android.priority` to `HIGH` on every FCM wake, because FCM holds a normal-priority message for a device in Android's Doze mode until Doze's next maintenance window. The relay sets no `android.ttl`, so FCM applies its default time-to-live.
   - **WebPush body.** The relay encrypts the plaintext `{"scp":"1"}` under RFC 8291 §3.4 to the token's `p256dh` and `auth`, with a P-256 ephemeral key pair and a 16-byte random salt that it generates fresh for each wake and never reuses. The body is one RFC 8188 aes128gcm record: the 86-byte header `salt (16 bytes) || rs (4-byte BE, 4,096) || idlen (1 byte, 65) || keyid`, where `keyid` is the 65-byte uncompressed ephemeral public key, then the AES-128-GCM encryption of the plaintext followed by the padding delimiter `0x02`, with no padding octets, which is 28 bytes. Every WebPush wake body is therefore 114 bytes long. The ephemeral key is never the VAPID key (RFC 8292 §2). Vector 60 of `25-test-vectors.md` §25.30 pins the body for a fixed ephemeral key and salt.
   - **VAPID JWT.** `t` is the compact serialization of a JWT that the relay signs with its VAPID private key under ES256 (RFC 8292 §2). The JOSE header is `{"typ":"JWT","alg":"ES256"}`. The claims are exactly three: `aud`, the endpoint's origin in the serialization of RFC 6454 §6.1, which is `https://`, then the host, then `:` and the port only when the endpoint names a port other than 443; `exp`, a Unix time no more than 24 hours after the request; and `sub`, the `mailto:` or `https:` contact the relay operator configured. The signature is the 64-byte `r || s`, base64url-encoded without padding. `k` is the base64url encoding, without padding, of the 65-byte uncompressed VAPID public key that the relay publishes under ADR-004. Vector 60 pins one JWT and its `Authorization` header.
   - **WebPush headers.** `TTL` is the WebPush wake TTL, 3,600 seconds (`09-security-model.md` §9.18.13), and RFC 8030 §5.2 requires it on every request. `Urgency: high` (RFC 8030 §5.3) has the push service deliver the wake to a device in a power-saving state. The request carries no other header beyond HTTP framing, so it carries no `Topic`.
   - **WebPush endpoint.** Before each wake, the relay applies the endpoint refusal rule of ADR-004 to the address it is about to connect to, and connects to that address only. When the rule refuses the address, the relay sends nothing and counts the wake as a delivery failure. The relay follows no redirect from a push service, and it counts a 3xx response as a delivery failure.
   - **WebPush responses.** A push service answers `201` when it accepts a wake. It answers `404` for an expired subscription (RFC 8030 §7.3), and some push services answer `410` for the same condition. It may answer `403` when the VAPID authentication is invalid, which includes a JWT signed by a key other than the one the subscription was created with (RFC 8292 §4.2). The relay counts each of those three answers as an invalid token response.
   - The relay operator configures one APNs environment for the relay, `production` or `sandbox`, with no default. The relay sends every APNs wake to that environment's gateway, so one relay serves APNs tokens from one environment only. A `PushRegistration` carries no field that names the environment of its token (`22-human-readable-addressing.md` §22.11.4).
   - APNs rejects a wake for a token from the other environment with reason `BadDeviceToken`. The relay counts that rejection as an invalid token response, and the implicit-deregistration rule under **PushDeregistration message** below removes the registration after 3 consecutive delivery failures for the token.

   **Device receipt rule.** The device acts on a wake only when the payload its platform hands the app passes that platform's rule. On an accepted wake, the device connects to its relay set and pulls every pending envelope. On a rejected payload, the device makes no relay connection.
   - **APNs.** iOS hands the app the payload as a parsed dictionary, never as bytes. The device accepts the wake only when that dictionary has exactly one top-level key, `aps`, and `aps` has exactly one key, `content-available`, whose value is the integer 1. The device rejects every other dictionary.
   - **FCM.** The device accepts the wake when the message's data map holds the key `scp` with the string value `"1"`. The device rejects a data map that lacks `scp` or holds another value in it, and it reads no other key of the map.
   - **WebPush.** The browser decrypts the message and hands the service worker's `push` event its data. The service worker accepts the wake only when the event carries data whose text parses as a JSON object with exactly one key, `scp`, whose value is the string `"1"`. It rejects every other payload, including a push that carries no data. On an accepted wake, the service worker posts the wake to every open page of the application, and the client in each open page connects to its relay set and pulls every pending envelope. A browser client runs only while a page of the application is open (ADR-057), so when no page is open the client pulls when a page next opens. On a rejected payload, the service worker posts nothing.
   - **WebPush notification.** A browser subscription requires `userVisibleOnly: true`, so the service worker shows a notification for every push it receives, whether it accepts or rejects the payload. The notification's title and body are constants that the application fixes once, the same for every wake from every relay, and they carry no sender, context, count or preview. Every notification carries one constant `tag`, so a new wake replaces the notification already shown, and the screen never shows how many wakes arrived.
6. The relay MUST rate-limit push notifications to at most one push per 30 seconds per device token to prevent push notification flooding.

**Freshness.** Before it verifies a signature under step 3, the relay rejects a `PushRegistration` or a `PushDeregistration` in either of two cases:
- the message's `timestamp` differs from the relay's clock by more than the push timestamp skew window, 300 seconds (`09-security-model.md` §9.18.13), in either direction;
- the message's `timestamp` is at or below the `timestamp` of the last message the relay accepted for the same registration key.

After a deregistration removes a registration, the relay keeps the accepted timestamp for that registration key for at least the skew window, so a registration replayed inside the window after its deregistration fails the second check. A relay that rejects a message changes no stored registration and no stored timestamp.

**No blob storage.** The relay never stores a message published to its reserved push routing ID as a blob, and never delivers one to a subscriber or in a QUERY response, whether it accepts or rejects the message. A client that subscribes to or queries the reserved push routing ID therefore receives no identity's token. A relay that offers no push service rejects every PUBLISH to its reserved push routing ID and stores nothing. ADR-004 registers the error code for each rejection this section states.

**Tier 3 relays.** A node reachable only through a bridge relay publishes a tier 3 relay entry (§10.12.4.1 **Bridge establishment** step 4), whose URL is the bridge relay's own URL. Three parties handle a registration for that node, and each acts as follows:
- **The node behind the bridge.** A node MAY publish several tier 3 entries, one for each bridge relay it registers with, each carrying the same `bridgeTarget` (§10.12.4 **Multiple bridges**), and the rules of this bullet apply to each entry separately. For each tier 3 entry it publishes, the node computes that entry's tier 3 push routing ID from the entry's canonical URL and `bridgeTarget`, and its relay reserves every one of those IDs before the node publishes the entries: at startup, and on each tier change (§10.12.7) before the re-publish. From then on, the node's relay applies every rule of this section to a PUBLISH at any of those IDs, whether the PUBLISH arrives on a connection to one of its own listeners or on a session a bridge relay opens to it (§10.12.4 **Sessions**), and it rebuilds each preimage with the canonical URL and `bridgeTarget` of the entry whose ID the PUBLISH arrived at (step 3). Before it applies any of those rules, the node's relay opens the payload of every PUBLISH at a reserved tier 3 ID as a **Tier 3 envelope** (below), on either path, with the URL and target of the entry whose ID the PUBLISH arrived at, and applies the rules to the message the envelope carries. On a listener connection the node's relay answers with the codes this section assigns; on a bridge session it answers with one of the three frames **Tier 3 envelope** permits. The node does not reserve the `"scp-push-registration"` routing ID of any bridge relay's URL, which is that bridge relay's own reserved push routing ID; a PUBLISH at that ID reaching the node is an ordinary blob. When the node's published entries change, between tiers or between bridge relays, the node's relay reserves the push routing IDs of the new entries in place of the old ones, whichever form each takes.
- **The bridge relay.** The bridge relay computes no tier 3 ID and changes nothing about its own reservation: it reserves the `"scp-push-registration"` routing ID of its own URL and handles registrations for itself at that ID alone. It carries a session's frames to the registered node without parsing them (§10.12.4 **Sessions**), so it never intercepts, verifies or stores a registration addressed to a node behind it, and the **Tier 3 envelope** (below) keeps it from reading one. **Misdirected registrations.** A bridge relay MUST NOT store, deliver or answer a QUERY with a PUBLISH it receives directly at `SHA-256("scp-push-bridge:" || own_url || target)`, where `own_url` is the bridge relay's own canonical URL and `target` is any routing ID it currently holds a `BRIDGE_REGISTER` registration for, and it rejects that PUBLISH with `4060` PUSH_REGISTRATION_REJECTED (ADR-004). The bridge relay holds both inputs, so it computes these IDs without verifying anything and without trusting the registrant. The rule is defense in depth: the client rule below already forbids the direct PUBLISH, and the bridge relay is untrusted, so no client relies on the rule. A PUBLISH at a tier 3 push routing ID whose target the bridge relay holds no registration for is, to the bridge relay, a PUBLISH to an ordinary routing ID.
- **The registrant client.** The client computes the tier 3 push routing ID of each tier 3 entry it registers with, signs the preimage with that entry's canonical URL and `bridgeTarget`, seals the signed message in a **Tier 3 envelope** (below), and sends a PUBLISH frame at the tier 3 push routing ID, whose payload is that envelope, on a session it opens through the bridge relay to the entry's `bridgeTarget` (§10.12.4 **Sessions**), and it reads the node's answer on that session. A session that closes, or a connection that drops, before the answer arrives leaves the client unable to tell whether the node applied the message, so the client signs the message again with a newer `timestamp` and sends it again; **Re-registration** below makes a repeated registration harmless. The client MUST NOT send that PUBLISH to the bridge relay directly. A bridge relay that holds no registration for the target, or one that does not follow **Misdirected registrations**, stores the PUBLISH as a blob and delivers the envelope to any subscriber of that routing ID, which learns that a client registered with the node and when, and reads nothing the envelope seals.

**Tier 3 envelope.** A `PushRegistration` or `PushDeregistration` for a tier 3 entry crosses the bridge relay sealed to the wrapping key of the node's device (**Recipient key** below), so the bridge relay forwards ciphertext. The envelope is built and opened as follows:
- **Suite.** HPKE in RFC 9180 Base mode under the identity-to-identity suite of `09-security-model.md` §9.5: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM. One envelope carries one message under one `Seal`, and neither party supplies an external nonce.
- **Recipient key.** The recipient key `pkR` is the stable wrapping key (`09-security-model.md` §9.16) of the node's device: the device, of the identity whose service record carries the tier 3 entry, whose SCP instance runs the node behind that entry. The node holds no key of its own: its relay opens the envelope through that device's `KeyCustody`, computing the KEM Diffie-Hellman output with `dh_agree` as `09-security-model.md` §9.16.2 **Open** step 2 does, so the private half never leaves that device's custody. Each device of the identity holds its own wrapping keypair, which the identity's key state carries as that device's wrapping-key entry (`09-security-model.md` §9.7.4.2), so an envelope sealed to another device's wrapping key fails to open at the node; the per-device wrapping-key role arrives with keri P7 (#2874). **The tier 3 entry names the key.** The client takes `pkR` from the `wrappingKey` of the tier 3 entry it registers with (`18-addressability-and-deployment.md` §18.2.1), which the identity's service record signs (`03-identity.md` §3.10.13), and reads no KeyPackage to learn it. Before it seals, the client checks that the identity's key state lists those 33 bytes `Current` as the wrapping-key entry of one of the identity's devices (`09-security-model.md` §9.7.4.2), reading the key state it verifies by replaying the identity's key-event log (`09-security-model.md` §9.7.4.2 R2, R3, R8), and it decompresses the bytes to the 65-byte uncompressed SEC1 point that HPKE takes as `pkR`. **The client refuses to seal, with a typed error and no `BRIDGE_DATA`,** when the entry carries no `wrappingKey`; when the key state lists the named key `Superseded` or `Compromised{from: N}`, lists it in an entry that is not a wrapping-key entry, or does not list it; and when the bytes do not decompress to a point on the P-256 curve. A named key that fails the check makes the tier 3 entry absent for the client (`03-identity.md` §3.10.13), so the client has nothing to seal to. **The client also refuses to seal, with a typed error and no `BRIDGE_DATA`, when its resolution of the identity's service record or of its key state fails, and when the resolution it holds of either is older than `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (`09-security-model.md` §9.18.7, 300 seconds).** It then resolves both again, and it never seals on a cached copy past that bound. The service record binds the entry to the node it routes to, so the identity's own signature names the device whose custody opens the envelope, and the key state, never the entry, decides whether that key is usable. Alec's ruling on this rule, and the architect agent's design of the field, are in §18.2.1 **`wrappingKey`**; the per-device wrapping-key role the check reads arrives with keri P7 (#2874). **Current wrapping key.** After the node's device rotates its wrapping key, the node's relay opens with that device's new key only, so an envelope sealed to the old key fails to open, and keri P7 (#2874) re-signs the service record so that its tier 3 entries name the new key (`18-addressability-and-deployment.md` §18.2.1 **`wrappingKey`**). The client therefore resolves the identity's service record and key state again before each registration and each deregistration it seals, and applies the check above to what it resolved.
- **KeyPackages at the node.** A peer that adds the identity to a group fetches the identity's KeyPackages from the node behind a tier 3 entry: it opens a session through the bridge relay to the entry's `bridgeTarget` (§10.12.4 **Sessions**) and sends a `QUERY` at the identity's KeyPackage routing ID (`09-security-model.md` §9.7.4 **KeyPackage routing ID**) on it. A `QUERY` returns at most its `limit` blobs (ADR-004), so the peer pages with ordinary `QUERY` frames on the session: while a `query_complete` `EVENT` reports a `count` equal to the `limit` it sent, it sends the next `QUERY` with `since` and `after_blob` set to the `stored_at` and `blob_id` of the last blob that page returned. The bridge's rate cap (§10.12.4 **Caps**) paces that read and never ends it. **KeyPackage admission at the node.** A relay authenticates no publisher (ADR-004), so any party can send a PUBLISH at the identity's KeyPackage routing ID to the node, on a listener connection or through a bridge relay. Junk blobs stored there would fill the pages a peer's `QUERY` at that routing ID returns, by as many blobs as their publisher chose, so the peer would page through them before it reached a KeyPackage of the identity. The node's relay therefore stores a blob at its own identity's KeyPackage routing ID only when the blob's content decodes as exactly one MLS KeyPackage with no byte left over, re-serializing that KeyPackage under the TLS presentation language of RFC 9420 §2.1 yields the blob's content byte for byte, that KeyPackage passes the validation of RFC 9420 §10.1, which verifies the KeyPackage's signature under its `leaf_node.signature_key` and the checks of RFC 9420 §7.3 on its LeafNode that depend on no group, the `s` of that ECDSA signature is at most n/2, where n is the order of the P-256 group (the low-s form of `09-security-model.md` §9.5), its `scp_keypackage_attestation` passes checks 1 to 13 of `09-security-model.md` §9.7.1 as an adder applies them to an Add, against the identity's own current key state, with the attestation's `did` equal to the identity's identifier, and the identity's own current key state lists the attestation's `wrapping_key` `Current` as the wrapping-key entry of one of its devices, which is the entry of the device that minted the KeyPackage (`09-security-model.md` §9.7.4.2). The per-device wrapping-key role that last condition reads arrives with keri P7 (#2874). **Low-s.** For every ECDSA signature `(r, s)` that verifies, `(r, n − s)` verifies too, and the two give the KeyPackage different bytes and a different KeyPackageRef (RFC 9420 §5.2); an adder that builds a Welcome from the twin names a KeyPackageRef the joining device does not hold, so the member the adder committed can never join. Every KeyPackage an SCP device mints therefore carries a low-s signature, and admission refuses a high-s one, so a twin fails at every node whichever device minted the original. It rejects every other PUBLISH at that routing ID with `KEY_PACKAGE_REJECTED` (4042, ADR-004) and stores nothing. The node's relay stores at most one blob for each `init_key`: a PUBLISH whose KeyPackage carries the `init_key` of a KeyPackage already stored at that routing ID gets `OK` with the stored blob's `blob_id` and stores nothing. Check 7 of `09-security-model.md` §9.7.1 binds the attestation to that `init_key`, and the KeyPackage signature covers every other field, so a party without the leaf's signature key cannot turn one KeyPackage into many stored blobs: a changed extension or capability fails the signature, padding fails the exact decoding, another encoding of the same KeyPackage, such as a vector length header written in more bytes than it needs, fails the re-serialization, and the twin `(r, n − s)` fails the low-s check. These checks, and no decoder's defaults, are what keep a twin out. The copy stored first is kept. **What the publisher counts.** A device that publishes a KeyPackage at the node treats `KEY_PACKAGE_REJECTED` (4042) as that KeyPackage not published, so it counts toward no KeyPackage buffer (`09-security-model.md` §9.7.4). **No DELETE at that routing ID.** The node's relay answers `DELETE_UNAUTHORIZED` (4043, ADR-004) to every `DELETE` of a blob it stores at its own identity's KeyPackage routing ID, whatever token the `DELETE` carries, and keeps the blob: only the removals this bullet states and the blob's TTL remove those blobs, so no party, the KeyPackage's publisher included, removes one through the relay protocol. **Retired init keys.** An `init_key` is single-use (`09-security-model.md` §9.7.4), so a device of the identity retires one when it consumes it at a join and when it deletes the KeyPackage that carries it, whichever device minted that KeyPackage. It retires the key by appending a `RetireInitKey` event, carrying the `init_key` and the `expires_at` of the attestation that names it, to the identity's private state (`03-identity.md` §3.7.1.1), the encrypted log every device of the identity writes and reads; the identity's devices already share that log, so retirement needs no new authenticated channel. The node's SCP instance reads that log as any device of the identity does, and for each `RetireInitKey` it reads it removes any stored blob that carries the `init_key` and adds the `init_key` to the node's retired-init-key set. The node's relay refuses with `KEY_PACKAGE_REJECTED` (4042) every PUBLISH whose KeyPackage carries a retired `init_key`. The set lives in the node's SCP instance, persisted with the node's relay store, and holds each retired `init_key` with its `expires_at`; the node drops an entry once that `expires_at` passes, because admission already refuses that attestation as expired (check 13), so the set holds at most the `init_key`s of attestations the identity issued within `MAX_KEYPACKAGE_ATTESTATION_LIFETIME`. **What retirement leaves open.** Between a device consuming an `init_key` and the node reading its `RetireInitKey`, the consumed KeyPackage stays fetchable at the node, and a relay that withholds private-state events from the node lengthens that interval up to the attestation's `expires_at`. A Welcome an adder builds from a consumed KeyPackage in that interval fails at the joining device, which has deleted the `init_key`'s private half, so the adder's Commit adds a member who never joins; nothing worse follows, because no one but the identity's devices holds that private half. This is relay-side validation of a public, self-certifying record, defense in depth under the encryption-as-access-control tenet of `AGENTS.md` and §10.12.4 **Precedent for relay-side validation of public records**: it serves availability only and is never a trust dependency, so a peer verifies every KeyPackage it reads under `09-security-model.md` §9.7.1, whatever the node admitted. **A republished old key.** When a device rotates its wrapping key (`09-security-model.md` §9.16), the identity's key state stops listing that device's old wrapping key `Current`, and the node's relay removes each stored KeyPackage once the entry for the wrapping key its attestation names is no longer `Current`. Admission refuses such a KeyPackage too, so the node refuses a saved, unexpired copy of one, although its attestation keeps verifying until its `expires_at` (`09-security-model.md` §9.10.4 **Superseded wrapping key**).
- **`info` and `aad`.** `info = "scp-push-bridge-seal-v1" || BE32(len(bridge_url)) || bridge_url || bridge_target` and `aad = BE32(len(bridge_url)) || bridge_url || bridge_target`, where `bridge_url` is the UTF-8 bytes of the entry's canonical URL (`09-security-model.md` §9.18.2) and `bridge_target` is the entry's 32-byte `bridgeTarget`. The node builds both from the entry whose tier 3 push routing ID the PUBLISH arrived at, never from bytes the client supplies. An envelope sealed for another bridge URL or another target therefore fails to open at this entry, and one sealed to any other key, another identity's or another device's of the same identity, fails to open because the KEM binds `pkR` into the shared secret (RFC 9180 §4.1).
- **Plaintext and padding.** The plaintext is the message's blob, the bytes a client publishes when it reaches a relay directly, padded under the fixed bucket padding of `09-security-model.md` §9.10.3: the blob, then zero bytes, then the blob's length as a 4-byte big-endian integer, to the smallest bucket that holds the blob and the 4 bytes. Padding is required. A registration grows by 32 bytes for each routing ID it lists and by the length of its token, so an unpadded ciphertext would tell the bridge relay how many routing IDs the device registered and which platform it uses. Within one bucket the length tells the bridge relay nothing more; the bucket tells it a size class. The bucket a registration fills depends on its token's length and the number of routing IDs it lists; a WebPush token alone can reach 2,133 bytes (`22-human-readable-addressing.md` §22.11.4), so a WebPush registration can fill the 4 KB bucket. **Size ceiling.** A tier 3 envelope uses the §9.10.3 buckets up to 64 KB and never the 256 KB bucket, so a tier 3 message's blob is at most 65,532 bytes and its payload at most 65 + 65,536 + 16 = 65,617 bytes. A 256 KB-bucket envelope, 65 + 262,144 + 16 = 262,225 bytes, exceeds the 262,144-byte limit ADR-004 sets on a PUBLISH `blob`, so no relay stores or opens one. A client refuses to seal a message whose blob exceeds 65,532 bytes, with a typed error and no `BRIDGE_DATA`. A client whose session the bridge relay closes with `BLOB_TOO_LARGE` (4010) for a `BRIDGE_DATA` carrying an envelope within the ceiling is talking to a bridge relay configured with a smaller `max_blob_size` (§10.12.4 **Data**), and it returns that refusal to its caller as the bridge relay's. A registration lists 32 bytes for each routing ID, so at most 2,047 routing IDs fit within the ceiling, fewer by the bytes of the registration's other fields.
- **Framing.** The PUBLISH payload is `enc || ct`: `enc` is the 65-byte uncompressed SEC1 encapsulated key, and `ct` is `Seal(aad, padded_plaintext)`, the padded plaintext followed by the 16-byte AEAD tag. The payload is therefore 65 + bucket + 16 bytes. It carries no version byte and no type byte, because the tier 3 push routing ID it arrives at fixes its format.
- **Opening, and what a failure does.** The node's relay validates `enc` as `09-security-model.md` §9.16.2 **Open** step 1 does, opens `ct`, strips the padding under §9.10.3, decodes the message, and then applies the freshness checks and step 3. It rejects with `4060` PUSH_REGISTRATION_REJECTED (ADR-004) a payload whose length is not 65 + 16 + a §9.10.3 bucket size of 64 KB or less (**Size ceiling**), an `enc` that fails validation, a `ct` that fails to open, a length suffix larger than the bytes before it, and an opened blob that does not decode. A rejected envelope changes no stored registration and no stored timestamp, and **No blob storage** applies to it. On a listener connection the relay sends the code this section assigns to each rejection. On a bridge session (§10.12.4 **Sessions**) it sends one of three frames, each with an empty `msg`: `OK` without `blob_id` for a message it accepts; `ERR` `4060` PUSH_REGISTRATION_REJECTED for a message it rejects with any `4xxx` code of this section, `4061` to `4064` among them; and `ERR` `5000` INTERNAL_ERROR for a message it rejects with any `5xxx` code, `5003` and `5004` among them. The answer crosses the bridge relay in the clear, where a bridge relay that breaks the rule of §10.12.4 **What the bridge reads** can parse it, and the detailed codes would tell it about the sealed message: `4061` names a platform the node sends no wakes on, `4062` that the message's `timestamp` was stale, and `4064` that the registrant already holds the per-relay cap of registrations. The three frames tell the bridge relay only that the node accepted the message, rejected it, or could not decide and may be asked again, together with how long the node took to answer. The registrant learns no more than the bridge relay: a client that receives `4060` through a bridge relay cannot tell an unconfigured platform from a bad signature, and it retries after `5000` as ADR-004 states for every `5xxx` code.
- **What the bridge relay sees.** The bridge relay reads the session frames' own fields (§10.12.4 **What the bridge reads**): the `target_routing_id` of the client's `BRIDGE_SESSION_OPEN`, which is the `bridgeTarget` it registered, and the length and arrival time of each `BRIDGE_DATA` in each direction. A bridge relay that parses the session's frames anyway also reads the tier 3 push routing ID of the PUBLISH frame and the node's answer, which **Opening, and what a failure does** limits to accepted, rejected, or ask again. Either way it reads no identifier, platform, token, routing ID or timestamp from the registration, and it cannot tell a registration from a deregistration that fills the same bucket.
- **Sign, then seal.** The client signs the message under `09-security-model.md` §9.5.2 exactly as it would for a relay it reaches directly, then seals the signed message; the signature travels inside the envelope. The signature preimage does not bind `pkR`. It binds the entry's canonical URL and `bridgeTarget`, which the node rebuilds from the entry the PUBLISH arrived at (step 3), so a node that opens a registration and re-seals it to another node's key presents a message whose signature fails at every other entry. Binding `pkR` would add no check that the URL and target do not already make, and would invalidate every signed message on each wrapping-key rotation.

The node's answer reaches the client as a `BRIDGE_DATA` on the session that carried the message (§10.12.4 **Sessions**). The bridge relay forwards every registration for a node behind it and can read none of them, which **Relay-side storage** below states.

**Re-registration.** A registration whose registration key matches a stored registration passed the freshness checks above, so its `timestamp` is newer, and it replaces the stored registration. The client re-registers whenever its `routing_ids` set changes: when it joins or leaves a context and when a pseudonym rotates (`09-security-model.md` §9.10.4.1). When the new registration's `routing_ids` also equal the stored registration's, the relay changes only the stored `timestamp`, and the relay sends the same response it sends for a replacement.

**Token refresh:** When the platform issues a new push token (e.g., APNs token rotation), the new token makes a new registration key (step 4). The client sends a `PushDeregistration` for the old token and then a `PushRegistration` for the new token. The 3-failure rule below also removes an old token the client never deregistered.

**WebPush subscriptions.** A browser `PushSubscription` is bound to the one `applicationServerKey` it was created with, a push service rejects a wake signed with any other VAPID key (RFC 8292 §4.2), and each relay holds its own VAPID key. A browser client therefore holds one subscription for each relay that hosts one of its contexts, among the `relay_urls` its contexts name (`05-contexts.md` §5.12.3.1):
- For each such relay, the client holds one service-worker registration with a scope of its own, which stays the same across sessions so that the client finds the same subscription again (indicator: a scope path ending in the lowercase hex of that relay's reserved push routing ID).
- It subscribes through that registration with `userVisibleOnly: true` and that relay's VAPID public key as `applicationServerKey`, and it sends that relay, and no other relay, a `PushRegistration` carrying that subscription's token (`22-human-readable-addressing.md` §22.11.4).
- When the client leaves its last context on a relay, it sends that relay a `PushDeregistration` for the token and unsubscribes that registration's subscription.

**VAPID key.** Before it subscribes for a relay, the client reads that relay's VAPID public key from where ADR-004 has the relay publish it: the `webpush_vapid_key` field of `relay_config` in the relay's `.well-known/scp` document, read under the rules of `18-addressability-and-deployment.md` §18.3.3. A relay whose document carries no `webpush_vapid_key` sends no WebPush wakes, and the client registers no WebPush token with it. The client reads the key again each time a page of the application starts the client. When the key differs from the `applicationServerKey` of its subscription for that relay, the client unsubscribes, subscribes again with the new key, and replaces the old token with the new one as **Token refresh** states. A `pushsubscriptionchange` event is also a token refresh: the client subscribes again with that relay's current VAPID key and replaces the old token.

**What a substituted VAPID key can do.** No signature binds the VAPID key to the relay's identity: the client trusts the key as far as it trusts the TLS connection to the relay's host, which is the connection it already publishes and subscribes over (`18-addressability-and-deployment.md` §18.3.3). Relays are untrusted, so this paragraph assumes the operator, or a party serving the document in the operator's place, publishes a key of its choosing.
- **A key the relay does not hold.** The push service answers the relay's wakes with `403`, the 3-failure rule removes the registration, and the browser receives no wakes from that relay. A relay can already withhold every wake, so the substitution costs availability only.
- **A key a third party holds.** That party, given the token the relay stores (endpoint, `p256dh`, `auth`), can push to the browser at any rate, outside the limit of step 6. Each push makes the service worker show the constant notification, and each push carrying `{"scp":"1"}` makes an open page pull from its relays. The relay operator holds the same power with its real key and the stored token, so the substitution hands that power to whoever the operator chooses and to no one the operator did not choose.
- **What no key gives.** The notification text is constant, so no key holder chooses what the screen shows. A push carries nothing the client reads beyond the receipt rule, and the client verifies every record it pulls, so no key holder learns a context, forges a record or impersonates a sender.

**PushDeregistration message.** `22-human-readable-addressing.md` §22.11.4 defines the `PushDeregistration` fields and their wire types, and the `PushDeregistration` table of `09-security-model.md` §9.5.2 lists the fields of its signature preimage in order. The registrant signs the preimage with the key its key state lists `Current` in the `#active` role, and the relay verifies it as step 3 verifies a registration.

The client sends a `PushDeregistration` to explicitly remove its push registration. The relay deletes the stored registration whose registration key is the message's (identity identifier, platform, token), and leaves the identity's other registrations in place. Implicit deregistration occurs when the relay observes push delivery failures (invalid token responses from APNs, FCM or a WebPush push service) — the relay MUST remove registrations after 3 consecutive delivery failures for the same token.

**Relay-side storage:** Push registrations are stored in the relay's local state (not in the protocol's encrypted state). The relay operator can see which identities have registered for push and their platform tokens — this is an accepted tradeoff, equivalent to any push notification service. A relay that holds a push registration learns the registering identity's identifier, the device's platform token, and every routing ID the registration lists, and it can bind each of those routing IDs to that identity. SUBSCRIBE never gave the relay that binding, because the relay authenticates no subscriber. A registration that lists a device's pseudonym routing ID therefore tells the relay which identity stands behind that pseudonym on that relay. `09-security-model.md` §9.10.4 lists this linkage among the residuals of per-context pseudonyms. A registration for a tier 3 entry crosses the bridge relay inside a **Tier 3 envelope** sealed to the wrapping key of the node's device, so the bridge relay stores nothing and reads none of the identifier, token and routing IDs the node stores. It learns that some client registered or deregistered with the node behind it, when, the envelope's bucket, and whether the node accepted the message, rejected it, or asked for a retry.

## 10.8 Multi-Device

Multi-device coordination — read state, session continuity, notification deduplication, device handoff — is a client-scope concern. The protocol provides the building blocks:

- **Identity private state (§3.7)** syncs personal configuration across devices via encrypted event log on relays.
- **Context state** is the same regardless of which device queries it.
- **Encrypted envelopes** are available on relays for any device that holds the keys.

How a client uses these to implement read markers, notification deduplication, or session handoff is the client's decision. A simple client might treat each device as independent. A sophisticated client might sync UI state through identity private state or through a dedicated coordination mechanism. The protocol delivers the same encrypted envelopes to all devices; the client decides how to present them.

### 10.8.1 Multi-Device MLS Participation Model

While client-level coordination (read markers, notification dedup) is a client-scope concern, MLS group membership for multiple devices is a protocol-level concern. Each device MUST have its own MLS leaf node — MLS does not support shared leaf nodes across devices (RFC 9420 §14).

**Per-device MLS leaf nodes:**

1. **Each device has its own MLS leaf.** An identity with N devices appears as N leaf nodes in every MLS group it participates in. Each device generates its own MLS leaf keys — the P-256 signature key that self-signs the leaf and the DHKEM(P-256) encryption key that receives path secrets (§9.5) — and maintains independent MLS epoch state.
2. **Per-device KeyPackages.** Each device generates its own KeyPackages using an **ephemeral, context-scoped MLS leaf key**; each carries a **per-device KeyPackage attestation** (LeafNode extension `scp_keypackage_attestation`, §9.7.1) binding that leaf key to the identity, signed by that identity's Active Signing Key (`#active`). The KeyPackage's credential carries the identifier (shared across devices) plus a `device_id` field (a random 16-byte identifier, stable per device) in the LeafNode extensions. This enables other members to distinguish leaf nodes belonging to one identity.
3. **Governance counting.** For governance purposes (voting, quorum, role assignment), an identity with N devices counts as ONE participant, not N. The governance engine deduplicates by identifier — it does not matter how many leaf nodes an identity has. This prevents multi-device users from gaining disproportionate governance weight.
4. **Sender key and access key sharing.** Sender keys (§9.16) and access keys (§9.17) are per-identity, not per-device. All devices of one identity share the same sender key and access key. When a device requests a sender key (§9.16.2), the key holder authorizes the requesting identity and seals the response to the fresh `wrapping_pubkey` that request carries, so the requesting device opens it with the ephemeral key it generated for that request. The stable wrapping key is per-device: each device holds its own wrapping keypair in its own `KeyCustody`, the private half never leaves that device's custody, and the identity's key state carries it as that device's wrapping-key entry (`09-security-model.md` §9.7.4.2), a role keri P7 (#2874) adds. It is not a sender key's recipient.

**Device list management.** An identity's device list is its MLS group state: the leaf nodes the group holds. The service record carries no device roster (`03-identity.md` §3.10.13, `18-addressability-and-deployment.md` §18.2.2A), so a party reads the device list from a group it belongs to and from nowhere before it joins.

5. **Adding a new device.** When a user adds a new device: (a) the new device generates an MLS leaf key and publishes KeyPackages to relays, (b) an existing device (which is already a group member) sends an MLS Add proposal for the new device's KeyPackage in each active context, (c) the group processes the Add via a Commit, and the new device receives a Welcome message. The existing device coordinates this — the new device cannot add itself because it is not yet a group member.
6. **Removing a device.** When a device is decommissioned: (a) an existing device or context admin sends an MLS Remove proposal for the departing device's leaf node, (b) the group processes the Remove via a Commit, advancing the epoch and revoking the removed device's access to future messages. If the removed device was the identity's last, that identity is effectively removed from the group.
7. **Device limit.** A single identity MUST NOT have more than 10 active devices in any single MLS group. This bounds the leaf node overhead per participant. SDKs MUST reject Add proposals that would exceed this limit.

## 10.9 Real-Time and Async

The protocol supports both real-time and asynchronous interaction. This is not a dichotomy — it's a spectrum, and the SDK provides first-class support across it.

- **Async:** Messages are encrypted, delivered to relays, fetched when the recipient's agent comes online. This is the baseline that works for all participants regardless of connectivity.
- **Real-time:** When both parties are online simultaneously, the transport layer can deliver envelopes immediately. WebSocket connections to relays, direct peer-to-peer via libp2p, or any transport binding that supports streaming delivery. Latency depends on the transport binding, not the protocol.
- **Presence, typing indicators, live collaboration:** These are outlet-level or context-level capabilities, not protocol primitives. A context that needs presence registers a presence outlet. A context that needs typing indicators includes them as ephemeral events. The protocol carries them through the same encrypted envelope system — the content is up to the context.

The SDK provides the transport abstraction and envelope delivery. Whether that delivery is batched-async or streaming-realtime depends on the transport binding and what the client needs. Both are first-class.

### 10.9.1 Real-Time Media Transport

Real-time media (voice, video, screen sharing) has different performance requirements than messaging. The full SCP message pipeline — sender-side encryption, MLS group encryption, fixed bucket padding, store-and-forward relay delivery — adds per-frame overhead and latency incompatible with real-time media at 30-60fps. Media transport uses a delegated model:

1. **Context establishes the session.** The context provides identity (who's in the call), trust (are they authorized), governance (does the context allow media), and membership enforcement. All of this happens through the standard SCP message pipeline.
2. **MLS derives media session keys.** The MLS group's key schedule exports keying material for the media session via the MLS exporter (RFC 9420 §8.5). Key derivation parameters:
   - **Exporter label:** `"scp-media-key-v1"`
   - **Exporter context:** `context_id || session_id` where `session_id` is a random 16-byte value generated by the session initiator and distributed to participants via the SCP signaling message (step 4). The `context_id` is length-prefixed (4-byte BE length + UTF-8 bytes) and `session_id` is exactly 16 bytes. This binds the exported key to both the context and the specific media session.
   - **Key length:** 32 bytes (256 bits, suitable for AES-256).
   - **DTLS-SRTP binding:** The 32-byte exported key is used as the DTLS-SRTP external PSK (pre-shared key) via the `external_psk_identity` extension (RFC 8446 §4.2.11). DTLS-SRTP negotiation uses this PSK to establish the SRTP master key, binding the media encryption to the MLS group state. Only current MLS group members can derive the PSK — non-members cannot decrypt media.
   - **Key rotation:** The media session key MUST be re-derived on every MLS epoch change (Commit processing). When the MLS epoch advances, all participants independently re-export the key using the new epoch's key schedule with the same label and context. The DTLS-SRTP session is rekeyed with the new derived key via a DTLS KeyUpdate. This ensures that members removed from the MLS group (who triggered the epoch advance) lose media decryption access immediately.
   - **Session ID distribution:** The session initiator generates `session_id` and includes it in the `MediaSessionStart` signaling message (step 4). All participants use this `session_id` for key derivation, ensuring they derive the same key.
3. **Media flows over WebRTC.** DTLS-SRTP handles the actual media encryption and transport, using keys derived from step 2. Media frames flow peer-to-peer (or through a WebRTC SFU) without passing through SCP relays or the MLS encryption pipeline. WebRTC provides the low-latency, high-throughput transport that media requires.
4. **Signaling goes through SCP.** WebRTC session negotiation (SDP offers/answers, ICE candidates) flows through the context as standard SCP messages. This means signaling is end-to-end encrypted, authenticated, and governed by the context — only members can initiate or join media sessions.

**What SCP governs:** Who can participate (membership), what media capabilities are allowed (capability ceiling), session initiation and teardown (signaling), and key material (MLS-derived). **What WebRTC handles:** Media encoding, transport, congestion control, codec negotiation, NAT traversal.

This separation means contexts can support voice/video calls without the protocol needing to become a media transport. The context is the trust boundary; WebRTC is the media pipe.

## 10.10 Business Model Direction

Managed infrastructure and media/content hosting are the probable revenue surfaces. Heavy content (video, large files, real-time streams) has real storage and bandwidth costs. The protocol works either way — self-hosters shoulder their own costs, managed infrastructure shoulders it for a fee. The point is the choice exists and the protocol doesn't prefer either.

Relay economics are the responsibility of app builders and relay operators. The protocol defines what relays do, not who runs them or how they're funded. Community-operated relays, paid relay services, app-bundled relay infrastructure, and self-hosted relays are all valid. The protocol ensures none of them create lock-in: the identity is the participant's own, and relays are substitutable. In practice, app developers who build on SCP are expected to provision relay infrastructure for their users — the same way app developers today provision API servers, databases, and CDNs. There is no assumption of free community relay infrastructure at the protocol level; a protocol foundation may eventually provide shared infrastructure, but this is not a dependency.

**Relay monetization protocol.** §19.8 specifies the protocol-level relay economic config: per-publish and per-byte-stored pricing advertised in `.well-known/scp` `relay_config` (§18.3.3), compatible payment adapters, and the `PaymentAdapter` trait (§19.2) for settlement. Relay selection in `TransportManager` (ADR-012) uses cost as a criterion alongside reliability and latency. Free relays MUST always exist in the bootstrap relay list (§18.5) — economic gatekeeping of basic protocol operation is a protocol violation.

**The agent workstation effect.** As builder agents become mainstream and users acquire dedicated always-on hardware to run them (§10.2), the relay economics shift structurally. Relay infrastructure is marginal load on hardware that's already running 24/7. Builder agents can provision SCP infrastructure — relays, context hosting — as part of generating apps. The "who pays for relays?" question dissolves for users with agent workstations: you already have the hardware, the relay is just another process. Managed infrastructure remains valuable for users without always-on hardware (phone-only users) and for heavy content workloads, but the default self-hosting path becomes significantly more accessible.

## 10.11 Build on Existing Infrastructure

The transport, data sovereignty, and self-hosting layers are the least novel parts of the system. Existing technologies provide strong foundations. The novel work — and the value — is the Shareable Context Layer that sits on top.

**Nostr** is the closest existing analog to SCP's transport and identity layer. Keypair-based identity, substitutable relays, signed events, client-side intelligence — SCP's lower stack is architecturally near-identical. SCP defines its own transport abstraction with Nostr as one possible binding rather than building directly on Nostr's event model. This preserves transport agnosticism and avoids coupling to Nostr's governance and ecosystem dynamics. SCP's encryption-as-access-control model and MLS-based group encryption requirements (§10.5) go beyond what unmodified Nostr relays provide — the transport binding approach allows SCP to use Nostr relays where they fit while maintaining its own protocol requirements.

**Matrix** provides federated messaging with strong encryption (Megolm/Olm) and a mature room model. SCP contexts could map to Matrix rooms with SCP-specific state events. Matrix's federation model is heavier than Nostr's relay model but provides stronger delivery guarantees.

**libp2p** provides peer-to-peer transport primitives (pubsub, DHT, NAT traversal) that could underpin direct device-to-device communication without relays for devices that are simultaneously online.

The protocol should define its transport requirements abstractly and provide reference bindings for at least one existing transport. The choice of primary transport binding is a design decision with ecosystem implications — it determines which existing community SCP builds alongside.

## 10.12 Relay Reachability

The deployment spectrum (§10.2) places "laptop running SCP daemon" and "agent workstation" as core self-hosting tiers. §10.4 describes relays as needing "stable address, TLS, and uptime commitment." This section specifies how a self-hosted relay behind residential NAT becomes reachable from the internet with zero manual configuration — no domain, no static IP, no router access. Domain-based deployment (§18.6) provides the broadest reach when available; this section adds a zero-config floor beneath it and specifies graceful fallback when domain-based deployment is configured but fails.

The "run it on your MacBook" thesis is the keystone of "protocol requires no operator." If a developer's laptop or an agent workstation behind residential NAT cannot serve as an SCP relay without infrastructure provisioning, self-hosting collapses to "rent a VPS" — which is just managed infrastructure with extra steps. This section closes the gap between the deployment spectrum's promise and the networking reality of consumer internet connections.

**Design principle: layered reachability.** Four tiers, tried in order. The first that produces a reachable address wins. If a domain is configured, domain-based deployment (Tier 4) is attempted first — if it works, it becomes the active tier; if it fails, fall through to Tiers 1-3. If no domain is configured, start at Tier 1. Selection is automatic — infrastructure plumbing, not a user decision.

### 10.12.1 Reachability Tiers

| Tier | Mechanism | NAT coverage | External infrastructure | Latency | Protocol changes |
|------|-----------|-------------|------------------------|---------|-----------------|
| 1 | UPnP/NAT-PMP port mapping | ~40% home routers | None | Direct | None |
| 2 | STUN hole punching | ~85% cumulative (cone NATs) | Any SCP relay as STUN server | Direct after punch | None (STUN is pre-connection) |
| 3 | Relay bridging (TURN-like) | ~100% (symmetric NAT fallback) | A willing SCP relay as bridge | +1 hop | BRIDGE_REGISTER + BRIDGE_DATA operations |
| 4 | Domain-based (existing §18.6) | 100% | DNS + ACME CA | Direct | None |

**Tier selection algorithm:**

1. If a domain is configured (`.domain()`), attempt domain-based deployment first. Verify: DNS resolves to a reachable address, ACME challenge succeeds, `wss://` WebSocket upgrade completes. If all checks pass, Tier 4 is the active tier. If any check fails, log the failure reason and fall through to step 2.
2. If no domain is configured (`.no_domain()`), or if domain-based deployment failed, probe NAT type via STUN binding request to a known relay (§10.12.3).
3. Attempt Tier 1 (UPnP/NAT-PMP). If a port mapping is obtained and external reachability is verified, Tier 1 is the active tier.
4. If Tier 1 fails and NAT type is non-symmetric (full-cone, address-restricted, or port-restricted), attempt Tier 2 (STUN hole punching). If the external address is reachable, Tier 2 is the active tier.
5. If Tier 2 fails or NAT type is symmetric, register with a bridge relay (Tier 3). Tier 3 always succeeds if a bridge relay is available.
6. If no bridge relay is available, the self-hosted relay is unreachable from the internet. Log an error. The operator can still participate as an SCP identity using external relays — they just cannot serve as a relay for others.

Selection is logged at INFO level but not exposed to the user as a choice. The SDK re-evaluates periodically (recommended: every 30 minutes) and on network change events (IP change, interface up/down). Tier changes are transparent — the service record is rewritten with the new relay address at an incremented sequence, and peers re-resolve on connection failure.

### 10.12.2 Tier 1: UPnP/NAT-PMP Port Mapping

On relay startup, the SDK attempts to open a port mapping on the local gateway using UPnP-IGD (Universal Plug and Play Internet Gateway Device) or NAT-PMP/PCP (Port Control Protocol). Both are standard protocols for requesting port forwarding from consumer routers.

**Procedure:**

1. Discover local gateway via UPnP SSDP multicast or NAT-PMP default gateway.
2. Request a port mapping: external port (any available) mapped to internal relay listen port.
3. On success, the gateway's external IP and assigned port become the relay's reachable address.
4. Verify reachability: the SDK performs a self-test by connecting to its own external address from the public internet side (via a STUN-like probe or a test connection through a known relay). If the self-test fails, the mapping is considered unreliable — fall through to Tier 2.

**Lease management:**

- UPnP mappings have a TTL (typically 10-60 minutes, router-dependent). The SDK renews at 50% TTL.
- NAT-PMP/PCP mappings have explicit lifetimes. The SDK renews at 50% lifetime.
- If renewal fails (router rebooted, UPnP disabled mid-session), the SDK detects the loss on the next renewal attempt, re-probes, and falls through to Tier 2 if re-mapping fails.
- Mapping loss triggers an immediate service-record update if the tier changes.

**External address publication:** The external `ip:port` from the UPnP/NAT-PMP response is published in the identity's relay list, projected as an `SCPRelay` service endpoint (§18.2.1), with a `ws://` URL (§10.12.6). The `RepublishManager` handles address updates when the external IP or port changes.

**Security considerations:** Opening a port via UPnP is intentional — the relay is designed to accept connections from the internet. The relay authenticates nothing at the transport level (§10.4); MLS handles all confidentiality and integrity. A UPnP-opened port exposes the relay's WebSocket endpoint, which accepts only SCP protocol operations (PUBLISH, SUBSCRIBE, QUERY, DELETE per ADR-004). The attack surface is the relay implementation itself, not the port mapping mechanism.

**Coverage:** Approximately 40% of consumer routers support UPnP-IGD or NAT-PMP. The percentage varies by region, ISP, and router model. Many ISP-provided routers disable UPnP by default. This tier is opportunistic — when it works, it provides zero-config direct reachability with no external dependencies.

**Fallthrough:** If UPnP/NAT-PMP is unavailable, disabled, or the self-test fails, proceed to Tier 2.

### 10.12.3 Tier 2: STUN Hole Punching

For routers that do not support UPnP, STUN (Session Traversal Utilities for NAT, RFC 8489) can discover the relay's external address and establish a reachable UDP socket through NAT hole punching.

**NAT type classification:** The SDK performs a STUN binding request to classify the NAT type:

| NAT type | Prevalence | Hole punchable | Behavior |
|----------|-----------|----------------|----------|
| Full-cone | ~20% | Yes | Any external host can send to the mapped address |
| Address-restricted cone | ~30% | Yes | Only hosts the internal endpoint has contacted |
| Port-restricted cone | ~35% | Yes | Only the specific host:port the internal endpoint has contacted |
| Symmetric | ~15% | No | Different mapping per destination — external address unpredictable |

**Procedure for non-symmetric NATs:**

1. The SDK opens a UDP socket and performs a STUN Binding Request (RFC 8489) to a STUN server (see below). The response contains the external `ip:port` as seen by the STUN server.
2. For full-cone NATs, this external address is immediately reachable by any host.
3. For address-restricted and port-restricted NATs, the SDK must send an initial packet to a peer before the peer can send back. Connection coordination (step 5 below) handles this.
4. The external address is published in the service record as the relay's reachable address.
5. **Connection coordination:** A peer resolving the self-hosted relay's service record obtains the external address. For restricted NATs, the self-hosted relay must initiate a packet exchange with each connecting peer. The coordination protocol below specifies how peers signal intent and exchange addresses.

**STUN hole punching coordination protocol:**

For address-restricted and port-restricted NATs, both the self-hosted relay and the connecting peer must send packets to each other's external addresses to create NAT pinholes. This requires a coordination exchange through an intermediary relay that both parties can reach:

```
HOLE_PUNCH_REQUEST (peer → intermediary relay → self-hosted relay) {
  requester_did:     Identifier,       // the connecting peer
  requester_address: SocketAddr,       // Peer's STUN-discovered external address
  target_routing_id: [u8; 32],         // routing ID of the self-hosted relay
  nonce:             [u8; 16],         // Random nonce for replay prevention
  timestamp:         u64,             // Unix timestamp (ms)
  signature:         P256Signature, // Signs "SCP-HOLE-PUNCH-V1:" || requester_address || target_routing_id || nonce || timestamp
}
```

```
HOLE_PUNCH_RESPONSE (self-hosted relay → intermediary relay → peer) {
  responder_address: SocketAddr,       // Self-hosted relay's STUN-discovered external address
  requester_did:     Identifier,       // echo of the requester
  nonce:             [u8; 16],         // Echo of request nonce
  timestamp:         u64,
  signature:         P256Signature, // Signs "SCP-HOLE-PUNCH-V1:" || responder_address || requester_did || nonce || timestamp
}
```

**Protocol sequence:**

1. The peer discovers the self-hosted relay's service record, which lists an intermediary relay address (the relay the self-hosted relay maintains a persistent connection to).
2. The peer performs a STUN binding request to discover its own external address.
3. The peer sends `HOLE_PUNCH_REQUEST` to the intermediary relay, which forwards it to the self-hosted relay over the existing connection.
4. The self-hosted relay sends `HOLE_PUNCH_RESPONSE` back through the intermediary.
5. Both parties simultaneously begin sending UDP keepalive packets to each other's external addresses (3 attempts at 500ms intervals). The first packet from each side creates the NAT pinhole; subsequent packets traverse the pinhole.
6. Once bidirectional UDP connectivity is established (verified by receiving a keepalive response), the peer upgrades to a WebSocket connection over the punched hole.
7. If no response is received after 3 attempts (1.5 seconds total), the punch has failed. The peer falls through to Tier 3 (relay bridging).

**Security:** The intermediary relay sees both external addresses but cannot inject itself into the connection — MLS handles all payload encryption. The signatures prevent address spoofing (an attacker cannot redirect a peer to a different address). The nonce prevents replay.

**Keepalive:** NAT mappings expire if unused (typical timeout: 30-120 seconds). The SDK sends a 25-second UDP keepalive to maintain the mapping. The keepalive is a minimal STUN Binding Indication (no response expected) or a zero-length UDP packet, depending on the STUN server's capabilities.

**STUN service on SCP relays:** Any SCP relay MAY serve as a STUN endpoint. STUN is lightweight (stateless, single UDP socket, minimal CPU) and can coexist with the relay's WebSocket endpoint. The relay advertises STUN support in its `.well-known/scp` `relay_config` or relay metadata.

- Self-hosted relays that have achieved public reachability (Tiers 1, 2, or 4) MAY also offer STUN service — a self-reinforcing network where every new reachable relay makes the next NAT traversal easier.

**Symmetric NAT:** If the STUN probe determines the NAT is symmetric (~15% of deployments), hole punching is not viable — the NAT assigns a different external mapping per destination, making the external address unpredictable. The SDK falls through to Tier 3.

**Fallthrough:** If NAT is symmetric, or if the STUN-discovered address fails the reachability self-test, proceed to Tier 3.

### 10.12.4 Tier 3: Relay Bridging

For deployments behind symmetric NAT (~15% of consumer internet connections), where neither UPnP nor STUN hole punching can establish direct reachability, traffic is proxied through an intermediary SCP relay acting as a transparent bridge. This is architecturally analogous to TURN (Traversal Using Relays around NAT) but uses SCP's own relay infrastructure rather than dedicated TURN servers.

**New relay operations:**

Five frames support bridge relaying: `BRIDGE_REGISTER` (self-hosted relay → bridge), and the four session frames `BRIDGE_SESSION_OPEN`, `BRIDGE_DATA`, `BRIDGE_SESSION_CREDIT` and `BRIDGE_SESSION_CLOSE`, which carry a peer's relay traffic to a self-hosted relay and back (**Sessions** below). Each frame carries the optional `ref` of the ADR-004 frame envelope.

```
BRIDGE_REGISTER {
    routing_id: [u8; 32],            // Routing ID to register
    public_key: [u8; 33],            // SEC1 compressed P-256 public key (09 §9.5)
    signature: [u8; 64],             // P-256 signature (SCP-247, see below)
    timestamp: u64,                  // Unix timestamp included in signed payload
    target_relay_hint: Option<String> // URL hint for reaching this relay directly
}
```

The bridge relay authenticates the registration (§10.12.4.1) and records the routing ID → connection mapping. Responds with `OK` on success, or `ERR` with:
- `BRIDGE_NOT_SUPPORTED` (4030) — bridging is disabled on this relay.
- `BRIDGE_LIMIT_EXCEEDED` (4031) — global or per-connection registration limit reached.
- `BRIDGE_AUTH_FAILED` (4034) — authentication failed (invalid signature, routing ID mismatch, or expired timestamp).

**Sessions.** A session is a virtual connection between one peer and one self-hosted relay registered with the bridge. The bridge holds one session for each virtual connection a peer opens, as a relay holds a connection. The peer and the self-hosted relay exchange ordinary ADR-004 frames over the session until either side closes it, and the self-hosted relay serves the session as it serves a connection to one of its own listeners, so `SUBSCRIBE` with live deliveries, `ACK`, `QUERY` paging and `PING` work over a session unchanged. A session has two legs: the peer's connection to the bridge, and the self-hosted relay's connection to the bridge that carries its `BRIDGE_REGISTER` registration. The self-hosted relay multiplexes every session the bridge opens to it over that one connection.

```
BRIDGE_SESSION_OPEN (peer → bridge) {
    session_id: u64,                 // Chosen by the peer, greater than every session ID it used on this connection
    target_routing_id: [u8; 32],     // Routing ID of the bridged relay
}

BRIDGE_SESSION_OPEN (bridge → self-hosted relay) {
    session_id: u64,                 // Chosen by the bridge, greater than every session ID it used on this connection
    target_routing_id: [u8; 32],     // The registered routing ID the peer named
    source_tag: [u8; 16],            // Equal for the sessions of one source prefix on this connection (Caps below)
}

BRIDGE_DATA (either direction, on either leg) {
    session_id: u64,                 // The session on this connection
    payload: Vec<u8>,                // One ADR-004 frame, serialized as one WebSocket message carries it
}

BRIDGE_SESSION_CREDIT (either direction, on either leg) {
    session_id: u64,                 // The session on this connection
    bytes: u32,                      // Further payload bytes the receiver of this frame may send on the session
}

BRIDGE_SESSION_CLOSE (either direction, on either leg) {
    session_id: u64,                 // The session on this connection
    code: u16,                       // 0 for an ordinary close, otherwise an ADR-004 error code
}
```

- **Session identifiers.** A session ID names a session on one connection only. The peer chooses the ID on its own leg, and the bridge chooses the ID on the self-hosted relay's leg. Each chooser makes every ID it sends in a `BRIDGE_SESSION_OPEN` greater than every ID it has used on that connection, so no ID is reused while the connection lasts, and the receiver tells an ID that was never opened from one that has closed by comparing it with the highest ID opened. The bridge keeps one record per session: the peer's connection and its session ID, the self-hosted relay's connection and its session ID, and the credit and buffered bytes of each direction. The ID on the self-hosted relay's leg encodes neither the peer, its address, nor its connection, and the bridge carries no peer identity to the self-hosted relay beyond the `source_tag` of **Caps** below; the frames a session carries hold all the routing context they need, as they do on a direct connection.
- **Opening.** Only a peer opens a session. For a peer's `BRIDGE_SESSION_OPEN`, the bridge sends the connection registered for `target_routing_id` a `BRIDGE_SESSION_OPEN` with a session ID of its own choosing and answers the peer `OK`, echoing the `ref`. It opens nothing and answers `ERR` with:
  - `BRIDGE_NOT_SUPPORTED` (4030) — bridging is disabled on this relay.
  - `BRIDGE_LIMIT_EXCEEDED` (4031) — the session would exceed a session cap of **Caps** below.
  - `BRIDGE_TARGET_NOT_FOUND` (4032) — target routing ID is not registered.
  - `INVALID_FIELD` (4003) — `session_id` is not greater than every session ID the peer has used on that connection.

  The bridge answers a `BRIDGE_SESSION_OPEN` that a self-hosted relay sends on its registered connection with `ERR` `4000` INVALID_MESSAGE and opens nothing.
- **Data.** Each `BRIDGE_DATA` carries one ADR-004 frame: a client-to-relay frame from the peer, or a relay-to-client frame from the self-hosted relay. The bridge copies the payload unchanged into a `BRIDGE_DATA` on the session's other leg, with that leg's session ID, and keeps the order of each session's frames in each direction. It sends no `OK` for a `BRIDGE_DATA`, a `BRIDGE_SESSION_CREDIT` or a `BRIDGE_SESSION_CLOSE`. A payload is at most `max_blob_size` plus 1,024 bytes (263,168 bytes under the 262,144-byte default), room for a frame that carries a blob of `max_blob_size`; when a sender exceeds that, the bridge closes the session with `BLOB_TOO_LARGE` (4010) on both legs and carries nothing of the frame.
- **Backpressure.** Each direction of each leg carries credit, counted in payload bytes. A session opens with zero credit in every direction. The receiver of each direction grants credit with `BRIDGE_SESSION_CREDIT`, and a sender sends a `BRIDGE_DATA` only when its payload length is at most the credit it holds; each payload's length reduces that credit. **Opening grant.** Each end grants at least `max_blob_size` plus 1,024 bytes when the session opens: the peer when it receives the bridge's `OK` to its `BRIDGE_SESSION_OPEN`, and the self-hosted relay when it receives the bridge's `BRIDGE_SESSION_OPEN`, so a frame of every size can cross the session from its start. A peer or self-hosted relay then grants more credit as it consumes frames. The bridge grants the sender of each direction credit as its buffer for that direction drains and as the token buckets of **Caps** allow, and never more than the buffer holds (default `max_blob_size` plus 1,024 bytes, so the largest frame fits), so it buffers at most one buffer's worth per session and direction. It forwards buffered frames as the receiving end's credit allows. A `BRIDGE_DATA` beyond its sender's credit is a flow violation: the bridge closes the session with `BRIDGE_FLOW_VIOLATION` (4035) on both legs and carries nothing of the frame. Credit stalls a session without stalling the other sessions on the self-hosted relay's connection. A self-hosted relay holds the frames it has written for a session and cannot send for want of credit up to a bound of its own, a local policy with a default of 1 MiB, and it closes a session whose held frames would exceed that bound with `BRIDGE_SESSION_CLOSE` `LIMIT_EXCEEDED` (4012). A peer that grants no credit therefore stalls only its own session, and the self-hosted relay's memory for that session stays within its bound.
- **Caps.** The bridge keys its per-source caps on the source prefix of a peer's connection, as ADR-004 defines it for `rate_limit_publish`: an IPv4 source address whole (/32), and an IPv6 source address by its leading `ipv6_source_prefix` bits, default 64 (/64). The bridge judges an IPv4-mapped IPv6 address (`::ffff:0:0/96`), which a dual-stack socket reports for an IPv4 peer, by its IPv4 address, so it keys that peer on its /32 with `family` 4, as ADR-004's endpoint refusal judges such an address. One host commonly holds a whole IPv6 /64, so a key on the full IPv6 address would give that host one allowance for each address it uses. A source prefix holds as many connections as it opens, so a cap per connection would bound nothing; the bridge is the only party that sees the address, so it is the party that keys by it. Each cap is a local relay policy:
  - **Sessions per source prefix**, across all of that prefix's connections (default 8).
  - **Sessions per registered connection** (default 256).
  - **Bytes per second per session**, in each direction (default 1 MiB).
  - **Bytes per second per source prefix**, across all of that prefix's sessions, in each direction (default 2 MiB).

  The bridge answers a `BRIDGE_SESSION_OPEN` beyond either session cap with `BRIDGE_LIMIT_EXCEEDED` (4031). It enforces each rate cap with a token bucket in payload bytes, one per session and direction and one per source prefix and direction: each bucket refills at its rate, holds at most `max_blob_size` plus 1,024 bytes, and starts full. The bridge grants a sender credit only from tokens that both the session's bucket and its source prefix's bucket hold, and each grant removes those tokens from both, so a session over either rate waits for credit and stays open, and an idle session accrues no burst larger than one largest frame. The bridge applies no other limit to session traffic and parses no payload to enforce any cap. **Source tag.** The bridge sends the self-hosted relay a `source_tag` in each `BRIDGE_SESSION_OPEN`: the first 16 bytes of `HMAC-SHA256(tag_key, family || prefix_len || prefix)`, where `family` is one byte, 4 or 6, `prefix_len` is one byte, the prefix length in bits (32 for IPv4, `ipv6_source_prefix` for IPv6), `prefix` is the source address with every bit after `prefix_len` set to zero (4 bytes for IPv4, 16 for IPv6), and `tag_key` is 32 bytes the bridge draws from a CSPRNG when the self-hosted relay's connection registers and discards when that connection closes. Sessions of one source prefix on one registered connection carry one `source_tag`; the tag reveals to the self-hosted relay which of its sessions share a source prefix while that connection lasts, and reveals neither the address, the prefix, nor any link between sessions on two registered connections or two registrations of one connection. A self-hosted relay bounds the sessions it serves on its bridge connection as local policy, with a default of 256, and answers a `BRIDGE_SESSION_OPEN` beyond its bound with `BRIDGE_SESSION_CLOSE` `LIMIT_EXCEEDED` (4012), which the bridge carries to the peer. The self-hosted relay applies each per-connection limit of ADR-004 to each session, and keys each limit ADR-004 keys on an address, `rate_limit_publish` among them, on the session's `source_tag`, so the sessions of one source prefix share one allowance as that prefix's connections would at a directly reachable relay, which keys the same limits on the same source prefix (ADR-004). **Holding sessions.** A directly reachable relay keys its per-source limits on the source prefix (ADR-004), so one prefix gets one allowance however many connections it opens, and it sets no fixed ceiling on connections: it serves new peers until its own memory, file descriptors or bandwidth run out. Through a bridge, one source prefix holds at most 8 of a self-hosted relay's sessions and shares one per-prefix allowance at the self-hosted relay. Peers on 32 distinct source prefixes under the defaults, 32 IPv4 addresses or 32 IPv6 /64s, can hold all 256 sessions a registered connection allows, and no further peer then reaches the self-hosted relay through that bridge until one of those sessions closes; a directly reachable relay has no such fixed ceiling for them to fill. The caps bound the bridge's memory and bandwidth and what one prefix can take, and they do not prevent that.
- **Closing.** Either end of a session closes it: the peer or the self-hosted relay sends `BRIDGE_SESSION_CLOSE` with code `0`, or with an ADR-004 error code that states why. The bridge frees the session and sends `BRIDGE_SESSION_CLOSE`, with the same code and the other leg's session ID, on the other leg. The bridge closes a session itself on `4010` and `4035` above, with that code on both legs. A party that has sent or received `BRIDGE_SESSION_CLOSE` for a session discards every later frame for that session ID, which covers frames that crossed the close. The bridge answers a `BRIDGE_DATA`, `BRIDGE_SESSION_CREDIT` or `BRIDGE_SESSION_CLOSE` whose session ID is greater than every session ID opened on the connection it arrived on with `BRIDGE_SESSION_UNKNOWN` (4033), and carries nothing. A peer or self-hosted relay ignores a frame from the bridge that names a session ID it holds no session for.
- **Connection loss.** When a peer's connection closes, the bridge frees every session of that connection and sends the self-hosted relay of each a `BRIDGE_SESSION_CLOSE` with code `0`. When a self-hosted relay's connection closes, the bridge frees every session of that connection, sends each session's peer `BRIDGE_SESSION_CLOSE` with `BRIDGE_TARGET_NOT_FOUND` (4032), and deregisters the relay's routing IDs (step 5 of **Bridge establishment**). A self-hosted relay frees every session of a bridge connection that closed and ends each subscription it served on them. A peer reads a closed session as a lost connection to the self-hosted relay: it opens a new session and resubscribes as ADR-004 states for a reconnect. A peer whose session closes after it sent a `PUBLISH` and before the answer arrived cannot tell whether the self-hosted relay applied the `PUBLISH`.
- **What the bridge reads.** The bridge reads the session frames' own fields, `session_id`, `target_routing_id`, `bytes` and `code`, and each payload's length and arrival time. It parses no payload: it does not decode, inspect, modify, store or cache a frame a session carries, and no rule of this section or of §10.7.1 makes it read one. The legs are TLS connections that end at the bridge, and a session carries ADR-004 frames in the clear, so a bridge that breaks this rule can parse every frame a session carries, and no party can detect that it did. No party relies on the rule. A session carries what any relay reads in its own traffic: routing IDs, `BLOB` contents that are ciphertext or public, self-certifying records (`09-security-model.md` §9.9.1), and the codes of `ERR` frames. §10.7.1 **Tier 3 envelope** seals a push registration to the identity that publishes the tier 3 entry, and limits the node's answer to it to three frames.
- **What the bridge can do.** The bridge is the server on both legs, so it can drop, delay or forge any frame of a session, as any relay can forge its own `OK`, `ERR` or `BLOB`. A forged `BLOB` fails the checks a client makes on every record it reads (`09-security-model.md` §9.9). A forged `OK` or `ERR` misstates the self-hosted relay's answer, which the bridge could already withhold by dropping the frame.

**Authentication (SCP-247):**

`BRIDGE_REGISTER` requires a P-256 ownership proof to prevent unauthorized routing ID claims. The signature covers the domain-separated payload `"SCP-BRIDGE-REGISTER-V1:" || identifier || public_key || routing_id || big-endian-u64(timestamp)` (129 bytes): the registrant's 32-byte inception-derived identifier (`09-security-model.md` §9.7.4.2 R13), its 33-byte SEC1 compressed public key, the 32-byte routing id, and the timestamp. **The preimage binds `public_key` and `identifier`** so that the signed bytes name the claimant; a preimage over the routing id and the timestamp alone is a signature any party makes under any key it chose, and it narrows the claimant to nobody. The bridge verifies:

1. The P-256 signature is valid for the provided `public_key`.
2. `SHA-256("scp:did:" || identifier)` equals the claimed `routing_id` (`09-security-model.md` §9.7.4.2 R13), **and** `public_key` is the key that identifier's key-event log lists `Current` in the `#active` role, resolved and verified under `09-security-model.md` §9.7.4.2 R2, R3 and R8. **No function maps a public key to an identifier**, because the identifier is the inception event's digest and encodes no key (R13), so the registrant supplies the identifier and the bridge recomputes the routing id from it.
3. The `timestamp` is within 60 seconds of the server's current time (replay window).

**Precedent for relay-side validation of public records.** `BRIDGE_REGISTER` establishes the pattern that a relay MAY perform a control-plane cryptographic check — verify a P-256 signature, replay a key-event log, and confirm the `SHA-256("scp:did:" || identifier)` identifier-to-routing-id binding — while remaining an untrusted, encrypted-content-blind data plane: session payloads are carried opaquely (**Sessions**), and the client re-verifies everything end-to-end regardless of the relay's acceptance. This same check extends from the control plane to a *stored public record*: an SCP-native relay MAY validate a key-event record frame it stores, under the ordered checks ADR-065, the relay ADR, pending, states, and the tag `archive/kel-combined-pre-split` preserves this branch's combined text, where a reader finds the sections that record will be written from — as an availability and anti-suppression measure. **The identity half names the two checks it states itself**: the structural decode of `09-security-model.md` §9.10.12, and the identifier-to-routing-id binding of `09-security-model.md` §9.7.4.2 R2 and R13. Every other check that order carries is the relay ADR's. It is defense-in-depth, never a trust dependency — a relay that skips or botches this validation degrades availability only, and it never touches MLS-encrypted context content, which relays can neither read nor validate.

#### 10.12.4.1 Routing ID Derivation Disambiguation

The protocol uses two distinct routing ID derivation schemes for different purposes. Implementations MUST NOT conflate them:

| Routing ID type | Derivation | Purpose | Used by |
|----------------|------------|---------|---------|
| **Identity routing ID** | `SHA-256("scp:did:" \|\| identifier)` over the identifier's 32 raw digest bytes (`09-security-model.md` §9.7.4.2 R13) | Identity-level routing — locating an identity's relay presence. Used for bridge registration, directed messages outside context scope, and relay discovery. | `BRIDGE_REGISTER` (§10.12.4), relay SUBSCRIBE for identity-level messages |
| **Context pseudonym** | `HMAC-SHA256(pseudonym_secret, context_id \|\| "scp-pseudonym")` | Context-level routing — routing messages within a specific context. Unlinkable across contexts. Never publicly derivable (§9.10.4.A). | Context message delivery, relay SUBSCRIBE for context messages |
| **Metadata routing ID** | `HMAC-SHA256(context_metadata_key, context_id \|\| "scp-metadata-v2")` | Context metadata retrieval — pre-join inspection of context parameters. | Relay QUERY for context metadata (§9.10.4.B) |

**Key distinction:** identity routing IDs are publicly derivable by design — any party that knows an identifier can compute its routing ID and send messages to it. Context pseudonyms are NOT publicly derivable — they require the pseudonym secret (§9.10.4.A), which is private key material. These serve fundamentally different privacy goals.

**Wire-level disambiguation:** The `routing_id` field in relay operations (`PUBLISH`, `SUBSCRIBE`, `BRIDGE_REGISTER`, etc.) is an opaque `[u8; 32]`. The relay does not know or care which derivation produced it. The SDK is responsible for using the correct derivation for each operation.

**Bridge establishment:**

1. The self-hosted relay behind symmetric NAT connects outbound to a bridge relay (outbound connections are not blocked by NAT).
2. The self-hosted relay registers its routing ID with the bridge via `BRIDGE_REGISTER`, proving control of its identifier with a P-256 signature.
3. The bridge relay accepts incoming connections from peers. A peer opens a session to the registered self-hosted relay with `BRIDGE_SESSION_OPEN` and exchanges relay frames with it over the existing outbound connection (**Sessions**).
4. The self-hosted relay publishes an `SCPRelay` entry (`18-addressability-and-deployment.md` §18.2.1) whose `serviceEndpoint` is the bridge relay's own URL, `wss://bridge-relay.example.com/scp/v1`, and whose `bridgeTarget` is the identity routing ID (§10.12.4.1) it registered in step 2, as 64 lowercase hex digits.
5. When the self-hosted relay disconnects, the bridge deregisters all its routing IDs and closes every session of its connection (**Connection loss**). A subsequent `BRIDGE_SESSION_OPEN` for those IDs returns `BRIDGE_TARGET_NOT_FOUND`.

**Bridge properties:**

- **Transparent.** The bridge relay sees the same metadata as any relay (§9.9.1): routing IDs, blob sizes, timing. MLS prevents content access, and the §10.7.1 **Tier 3 envelope** prevents access to a push registration or deregistration it forwards to a node behind it. The bridge CANNOT read, modify, or inject messages. It can drop, delay or forge the frames of a session (**What the bridge can do**), which carry no message the bridge can read or alter undetected.
- **Substitutable.** If a bridge relay goes down, the self-hosted relay discovers another bridge relay and re-registers. Peers re-resolve the service record and connect to the new bridge. No session state is lost — MLS sessions survive relay changes.
- **Multiple bridges.** A self-hosted relay MAY register with multiple bridge relays simultaneously for availability. Each bridge is published as a separate `SCPRelay` entry in the service record, each carrying that bridge's URL and the same `bridgeTarget`.
- **Bridge relay MAY offer this service selectively.** The broker role is a relay configuration choice — a named selector with two states (brokering disabled or enabled), disabled by default (a relay brokers nothing until explicitly enabled). This broker-role selection is independent of any internal relay connection-admission secret. Bridge relays MAY charge for bridge service via the relay economic configuration (§19.8).

**Honest constraint:** Tier 3 requires someone to operate a bridge relay that is itself publicly reachable. This is not Limn-specific — any SCP relay with a public address can serve as a bridge. But someone must operate one. This is the same pattern as bootstrap relays: the protocol requires no specific operator, but it requires that operators exist. The fallback relay list (§18.5.1) SHOULD include at least one relay that supports bridging.

**Performance:** Bridge proxying adds one network hop compared to direct connections. For typical relay traffic (small encrypted blobs, store-and-forward), the latency impact is negligible. For high-throughput use cases (media hosting, large file transfer), bridge deployment is suboptimal — operators in that situation should obtain a domain (Tier 4) or a VPS with a public IP.

### 10.12.5 Tier 4: Domain-Based Deployment

When an operator has a domain name, domain-based deployment provides the broadest reach: `wss://` with ACME-provisioned TLS, full web compatibility, `.well-known/scp` for HTTP discovery, and no NAT traversal required (the domain resolves to a publicly routable address or the operator has configured port forwarding).

This tier is specified in §18.6 (`ApplicationNode`), §18.6.3 (TLS Provisioning), and §18.3 (`.well-known/scp`). The protocol changes for this tier are zero — it is the existing deployment model.

**Relationship to Tiers 1-3:** When configured via `.domain()`, Tier 4 is attempted first. If it succeeds (DNS resolves, ACME provisions a certificate, the WebSocket endpoint is reachable), it becomes the active tier. If it fails — DNS is misconfigured, ACME challenge cannot complete, the port is unreachable — the SDK falls through to Tiers 1-3 automatically. This makes `.domain()` a best-effort optimization rather than a hard requirement: set it, and it works when conditions allow; when conditions change (laptop moves to a different network, home IP rotates), the zero-config tiers catch you.

Domain-based deployment is not a paid tier or a higher service level. Operators provision their own domain and DNS however they choose. A free domain from a dynamic DNS provider works the same as a custom domain on Cloudflare. The domain is a simple configuration attribute — easy to set, easy to change, easy to remove.

### 10.12.6 Transport Security for Self-Hosted Relays

TLS is required for all domain-based relay connections (§9.13). Self-hosted relays without a domain present a challenge: a laptop behind NAT with no domain cannot obtain a CA-signed TLS certificate, and self-signed certificates provide no trust benefit over plaintext (no trust anchor for the connecting peer to verify against).

**Key decision: `ws://` (plaintext WebSocket) is permitted exactly where `09-security-model.md` §9.13 permits it.** §9.13 states that criterion, and the table below records which tier each source falls on.

| Relay type | Where the resolver took the URL | Transport | TLS required |
|-----------|---------------|-----------|-------------|
| Domain-based | `.well-known/scp` or explicit URL | `wss://` | Yes (§9.13) |
| Self-hosted, no domain | the source §9.13's criterion admits | `ws://` permitted | No |
| Self-hosted, with domain | Either | `wss://` | Yes |

**Rationale.** TLS serves two purposes: confidentiality and server authentication.

1. **Confidentiality** is already provided by MLS. Every blob delivered through a relay is MLS-encrypted before it reaches the transport layer (§10.5). TLS on the relay connection protects already-encrypted traffic — defense in depth, not the confidentiality boundary. Removing TLS from a self-hosted relay connection does not expose message content. The confidentiality guarantee is MLS, not TLS.

2. **Server authentication** via TLS requires a domain name and a CA-signed certificate. A relay identified only by IP address behind NAT has no domain and cannot complete ACME challenges. Self-signed certificates provide no authentication benefit — any attacker can generate one. What authenticates a relay URL instead is the chain of verifications §9.13's criterion names, and the trust anchor is that chain rather than a TLS certificate.

**Enforcement constraint:** the SDK rejects a `ws://` relay URL from every source §9.13's criterion excludes, `.well-known/scp` among them. That rejection is what stops a downgrade attack in which an attacker substitutes `ws://` URLs into HTTP-based discovery, which carries no signature binding the URL to the identity.

**Metadata tradeoff.** Without TLS, network intermediaries (ISPs, network operators) can observe the same metadata that any relay operator already sees (§9.9.1): connection timing, blob sizes, routing IDs. They cannot read MLS-encrypted content. This is an accepted tradeoff for the zero-config floor. The metadata exposure is not new — it is the same exposure the relay operator has. TLS merely prevents intermediaries other than the relay from seeing it.

Operators concerned about metadata exposure to network intermediaries can:

- Add a domain and use `wss://` (Tier 4).
- Route relay traffic through a VPN or Tor.
- Use a bridge relay with `wss://` (Tier 3 always uses `wss://` because the bridge relay has a domain).

### 10.12.7 Service-Record Relay URL Encoding

Each reachability tier produces a different relay URL format for the service record's `SCPRelay` entries (§18.2.1):

| Tier | URL format | Example |
|------|-----------|---------|
| 1 (UPnP) | `ws://` with IP literal | `ws://203.0.113.42:8443/scp/v1` |
| 2 (STUN) | `ws://` with IP literal | `ws://198.51.100.7:32891/scp/v1` |
| 3 (Bridge) | `wss://` with bridge domain, plus `bridgeTarget` | `wss://bridge.example.com/scp/v1`, `bridgeTarget` `<64 hex>` |
| 4 (Domain) | `wss://` with operator domain | `wss://relay.example.com/scp/v1` |

Every tier's URL has a canonical form under the canonical relay URL rule of `09-security-model.md` §9.18.2; a tier 3 entry carries its routing target in `bridgeTarget` (`18-addressability-and-deployment.md` §18.2.1), never in the URL.

Tiers 1 and 2 use `ws://` with raw IP addresses — these are the zero-config, no-domain tiers where TLS is not available (§10.12.6). Tier 3 uses `wss://` because the bridge relay itself has a domain and TLS. Tier 4 uses `wss://` with the operator's domain.

**Address change handling.** Residential IP addresses change (ISP DHCP lease renewal, router reboot). UPnP port mappings may be reassigned. STUN-discovered addresses shift when NAT mappings expire and reform. The `RepublishManager` handles address changes by:

1. Detecting the change (periodic STUN re-probe, UPnP lease renewal response, network interface change event).
2. Writing a fresh service record at an incremented sequence carrying the new `SCPRelay` entries, signed by the designated operational key (`03-identity.md` §3.10.13). The relay list is not key state and no key event is appended, so the root set stays cold across every address change.
3. Republishing that record to the SCP relays of the identity's fallback set. There is no second layer (`18-addressability-and-deployment.md` §18.5.1).

Peers that fail to connect to a stale relay address re-resolve the identity's service record immediately. Multi-relay publishing (§18.7) provides availability during address transitions — if the self-hosted relay publishes to external relays in addition to advertising its own address, messages accumulate on external relays while the self-hosted relay's address updates propagate.

### 10.12.8 ApplicationNode Integration

`ApplicationNodeBuilder` (§18.6.2) gains additional methods for zero-config deployment:

```rust
impl ApplicationNodeBuilder {
    /// Zero-config NAT-traversed mode. No domain, no TLS, no .well-known/scp.
    /// Probes NAT, attempts Tiers 1-3, publishes a ws:// relay URL in the service record.
    pub fn no_domain(mut self) -> Self;

    /// Override the STUN endpoint used for NAT type probing.
    /// Default: bootstrap relay with STUN support.
    pub fn stun_server(mut self, url: &str) -> Self;

    /// Override the bridge relay used for Tier 3 fallback.
    /// Default: first bridge-capable relay in the community relay list (§18.5.1).
    pub fn bridge_relay(mut self, url: &str) -> Self;
}
```

**Behavior when `.no_domain()` is set:**

1. Skip ACME TLS provisioning entirely.
2. Probe NAT type via STUN binding request.
3. Attempt Tier 1 (UPnP/NAT-PMP port mapping).
4. If Tier 1 fails and NAT is non-symmetric, attempt Tier 2 (STUN hole punching).
5. If Tier 2 fails or NAT is symmetric, register with a bridge relay (Tier 3).
6. Publish the service record with a `ws://` relay URL (Tiers 1-2) or a `wss://` bridge URL (Tier 3).
7. Do NOT serve `.well-known/scp` — there is no domain to serve it from. Discovery runs through the identity's service record on the SCP relay network alone (`03-identity.md` §3.10.13).

**Behavior when `.domain()` is set:**

1. Attempt domain-based deployment first: ACME TLS provisioning, `wss://` WebSocket endpoint, `.well-known/scp` generation.
2. Verify DNS resolves correctly and the ACME challenge completes.
3. If domain-based deployment succeeds, use Tier 4. Serve `.well-known/scp`. Publish a `wss://` relay URL in the service record.
4. If domain-based deployment fails (DNS misconfigured, ACME challenge fails, port 80/443 unreachable), log the failure and fall through to `.no_domain()` behavior (steps 1-7 above).
5. The SDK re-attempts domain-based deployment periodically (recommended: every 30 minutes) in case conditions change (DNS propagation completes, port becomes reachable).

**Behavior when neither `.domain()` nor `.no_domain()` is set:**

The builder requires one of the two. Calling `.build()` without either returns an error. This forces the operator to make an explicit choice about their deployment model, even though the choice between them is simple: "Do you have a domain? `.domain()`. No? `.no_domain()`."

### 10.12.9 Threat Model

The reachability tiers introduce attack surfaces beyond the standard relay threat model (§9.9). This section catalogs them.

**UPnP mapping hijack.** A malicious device on the local network deletes or modifies the relay's UPnP port mapping. Impact: availability only — the relay becomes unreachable. MLS prevents any confidentiality or integrity impact. Mitigation: the SDK verifies the mapping periodically (at 50% TTL) and detects loss. On loss, the SDK re-attempts the mapping and, if that fails, falls through to Tier 2. A persistent attacker on the LAN can deny Tier 1 indefinitely, but cannot prevent fallthrough to other tiers.

**STUN server manipulation.** A malicious or compromised STUN server reports an incorrect external address to the self-hosted relay. Impact: availability — peers attempt to connect to the wrong address. Cannot affect confidentiality (MLS) or integrity (the designated operational key signs the service record, `03-identity.md` §3.10.13). Mitigation: the SDK validates the STUN-reported address by performing a reachability self-test (connecting to its own reported address via an intermediary). If the self-test fails, the STUN result is discarded. Additionally, the SDK SHOULD probe multiple STUN servers and compare results — divergence indicates manipulation.

**Bridge relay as man-in-the-middle.** A bridge relay has the same position as any SCP relay — it sees routing IDs, blob sizes, and timing (§9.9.1). It CANNOT read MLS-encrypted content, forge messages, modify blobs, or inject members into contexts. It CAN perform suppression, delay, and replay — the same attacks any relay can mount. The same mitigations apply: multi-relay cross-check (§9.9.2), sequence gap detection, equivocation detection (§9.9.3), and Commit suppression detection (§9.9.4). Bridge relays are substitutable — switching bridges requires only a service-record update, not a session renegotiation.

**Network metadata exposure without TLS.** For Tiers 1 and 2, relay traffic uses `ws://` (plaintext WebSocket). Network intermediaries (ISPs, network operators on the path) can observe the same metadata that the relay operator sees (§9.9.1): connection timing, blob sizes, routing IDs. They cannot read MLS-encrypted blob content. This is the same metadata exposure as the relay operator has — TLS merely prevents intermediaries other than the relay from seeing it. Accepted tradeoff for zero-config deployment (§10.12.6).

**Residential IP exposure in the service record.** Tiers 1 and 2 publish the operator's residential IP address in the service record the relay network stores. Anyone who resolves the identifier learns the operator's IP. This is inherent to self-hosting without a domain — the relay must be reachable, and reachability requires a public address. Tier 3 (bridge) exposes only the bridge relay's address, not the operator's. Privacy-conscious operators who do not want to expose their residential IP have three options:

- Use a bridge relay (Tier 3) even when not required by NAT type — the SDK could support a `force_bridge()` builder method for this.
- Route traffic through a VPN, exposing the VPN's address instead.
- Obtain a domain and use Tier 4.

**NAT type probing as fingerprint.** The initial STUN probe reveals to the STUN server that an SCP node is starting up at a given IP address and time. This is a minor information leak. Mitigation: STUN probes are indistinguishable from WebRTC STUN probes (same protocol, RFC 8489). The SCP-specific semantics are not visible on the wire.

### 10.12.10 Phase Integration

| Component | Phase | Crate | Notes |
|-----------|-------|-------|-------|
| NAT type detection (STUN probing) | Phase 2 | `scp-transport` | RFC 8489 binding requests |
| UPnP/NAT-PMP port mapping | Phase 2 | `scp-transport` | `igd-next` crate for UPnP, `natpmp` crate for NAT-PMP/PCP |
| STUN hole punching + keepalive | Phase 2 | `scp-transport` | `stun-rs` or `webrtc-rs/stun` |
| `.no_domain()` builder mode | Phase 2 | `scp-node` | `ApplicationNodeBuilder` extension |
| `ws://` transport for service-record-discovered relays | Phase 2 | `scp-transport` | Enforcement: reject `ws://` from any source but a verified service record (§18.2.1) |
| Relay bridging (BRIDGE_REGISTER + BRIDGE_DATA) | Phase 3 | `scp-transport` | Wire operations, P-256-authenticated registration, transparent forwarding |
| STUN service on SCP relays | Phase 3 | `scp-transport` | Coexists with WebSocket endpoint |

Phase 2 delivers the zero-config floor: a self-hosted relay behind most consumer NATs becomes reachable without any manual configuration. Phase 3 closes the remaining ~15% (symmetric NAT) with bridge relaying and adds STUN service to the relay fleet, making the network self-reinforcing. Domain-based deployment (Tier 4) is already specified in Phase 2 via §18.6.

### 10.12.11 Self-Hosted Website Surface

The `scp-node` reference binary exposes a `--self-host` mode that hosts a single static website entirely on SCP (the operator's home page IS the public endpoint). The website is published as broadcast content (per-author AES-256-GCM, §9.16), decrypted by the origin node, and served to ordinary web browsers over HTTP from the node's own HTTP surface. This is a distinct surface from the relay WebSocket transport governed by §10.12.6 and §10.12.7: §10.12.6 specifies the transport for SCP-protocol clients that resolve a `ws://` relay URL from a verified key-event log; the website surface serves vanilla browsers that have neither MLS nor a key-event-log trust anchor.

**Origin-root mount.** In `--self-host` mode the single deployed context is served at the origin root, not only at the canonical `/scp/broadcast/<routing_id>/site/<path>` projection path. `GET /` returns the site's configured `index_path`; `GET /<path>` returns the corresponding site asset. On an exact-path miss the handler applies standard clean-URL resolution against the in-memory path index: an extensionless `<path>` resolves to `<path>.html`, and a directory-style `<path>/` (or `<path>`) resolves to `<path>/index.html`; every candidate is validated through `ContentPath` (so traversal is still rejected) and only a genuine miss returns 404. This is required for browser correctness: an `index.html` referencing root-absolute assets (`/style.css`, `/app.js`) issues those requests at the origin root, which must resolve to the deployed site. The origin-root mount reuses the same content handler as the canonical projection path, so `ContentPath` traversal protection, decryption, `ETag`, `Cache-Control`, and CSP apply identically; it routes only to the single designated default site and never re-exposes the relay upgrade (`/scp/v1`), which is not mounted on the self-host public surface.

**Transport security (website surface).** Unlike the relay `ws://` decision in §10.12.6, the self-host website surface serves **self-signed HTTPS (TLS 1.3) by default**. The rationale of §10.12.6 — that self-signed certificates "provide no trust benefit over plaintext" — applies to SCP-protocol peers, which authenticate the relay via the verified key-event log, not via a TLS certificate. A web browser has no such mechanism: it can only speak HTTP or HTTPS, and HTTPS-Only browser modes (e.g. Safari) refuse to open `http://` origins outright. Serving plaintext would therefore make the site unopenable in a growing fraction of browsers. The node is its own certificate authority ("be your own CA"): the certificate is self-signed with no DNS name and no CA, presenting Subject Alternative Names for `localhost`, `127.0.0.1`, and — when known at serve time — the node's external/LAN IP, so raw-IP HTTPS presents a matching SAN. Because there is no certificate authority, browsers show a one-time untrusted-certificate warning; this is expected for the no-DNS model. Confidentiality and integrity of the website's underlying broadcast content are already provided by the broadcast content encryption (§9.16); the self-signed TLS layer exists to satisfy the browser's transport requirement, not to establish a new trust anchor.

**Plaintext opt-out.** Operators who explicitly want plaintext HTTP (for an initial DNS-free stress test, or a client that cannot accept a self-signed certificate) may opt out via the `SCP_NODE_SELF_HOST_PLAINTEXT=1` environment variable, restoring `http://` serving on the self-host surface. The default remains self-signed HTTPS; the opt-out is never implicit and is disclosed in the startup banner.

**Future: CA-less authentication.** Certificate pinning over the self-signed certificate (binding the certificate fingerprint into an entry of the identity's service record, which the designated operational key signs, so an SCP-aware client can verify it without a CA) is a forward-looking enhancement, not required for the browser-facing surface specified here, where the one-time untrusted-certificate warning is the accepted no-DNS UX.

## 10.13 Transport Profiles

A transport profile bundles connection strategy, cover traffic tier (§9.10.6), relay count, reconnect behavior, and connection budget for a device class. The SDK infers a profile from the platform and exposes it as a configurable parameter.

### 10.13.1 Profile Definitions

| Profile | Connections | Cover traffic | Min relays | Reconnect | Max connections |
|---------|------------|---------------|------------|-----------|----------------|
| `server` | Persistent to all assigned relays | `full` (§9.10.6) | 3 | Aggressive (1–30s exponential backoff) | Unlimited |
| `desktop` | Persistent to all assigned relays | `full` (§9.10.6) | 3 | Aggressive (1–30s exponential backoff) | 50 |
| `mobile` | Active contexts only; push bridge (§10.7) for inactive | `reduced` (§9.10.6) | 2 | Conservative (5–60s exponential backoff) | 10 |
| `constrained` | On-demand only; poll via QUERY | `off` (§9.10.6) | 1 | None (poll-based) | 2 |

**Platform inference.** The SDK selects a default profile using a two-stage strategy: compile-time target narrows the candidate set, then optional runtime heuristics refine within that set.

*Compile-time defaults:*
- `#[cfg(target_os = "ios")]` or `#[cfg(target_os = "android")]` → `mobile`
- `#[cfg(target_arch = "wasm32")]` → `desktop` (browser tabs behave like desktop)
- `#[cfg(target_os = "linux")]` → runtime refinement (see below), fallback `desktop`
- `#[cfg(target_os = "windows")]` or `#[cfg(target_os = "macos")]` → `desktop`

*Runtime refinement for Linux:*
- **Server detection:** If no display server is detected (`$DISPLAY` unset, `$WAYLAND_DISPLAY` unset) AND total system memory exceeds 2 GB → `server`. This catches headless cloud VMs, containers, and dedicated server processes.
- **Constrained detection:** If total system memory is below 256 MB OR `#[cfg(target_arch)]` is `arm`, `riscv32`, or `mips` → `constrained`. This catches Raspberry Pi Zero-class and smaller embedded devices.
- **Fallback:** If neither heuristic matches → `desktop`.

*Explicit override:* `.profile(TransportProfile::Server)` (or any variant) overrides all inference. Operators deploying SCP on Linux servers SHOULD set the profile explicitly. Runtime heuristics are best-effort defaults, not guarantees.

**Suppression resistance trade-offs.** The `mobile` profile accepts a 2-relay minimum, reducing suppression detection capability (§9.9.2) — a 30s cross-check window with 2 relays detects suppression only when one relay is fully compromised, not when both selectively suppress. The `constrained` profile accepts a single relay with no suppression detection. Both trade-offs are explicit and acceptable for their device classes: mobile devices have push notification bridging as a secondary delivery path, and constrained devices are typically behind a gateway agent that participates in full-profile contexts.

### 10.13.2 Connection Pooling

A single adapter connection to a relay is shared by all contexts assigned to that relay. Subscriptions for different contexts multiplex over the same connection (up to `max_subscriptions_per_connection`, default 100 per ADR-004).

1. **Per-relay deduplication.** `TransportManager` maintains at most one connection per relay URL, regardless of how many contexts use that relay.
2. **Reuse on assignment.** When a context is assigned a relay that already has an active connection, it reuses the existing adapter — no new connection is opened.
3. **Cross-manager sharing.** When multiple `TransportManager` instances exist in the same process (e.g., multiple `ApplicationNode` instances), they SHOULD share connections to the same relay via a shared connection pool. The pool is keyed by `(relay_url, transport_type)`.
4. **QUIC multiplexing.** QUIC (§10.14) makes pooling even more natural: multiple QUIC streams over a single QUIC connection, each stream independent. No head-of-line blocking between contexts sharing a connection.
5. **Context isolation on shared connections.** When multiple contexts share a connection to the same relay, isolation is maintained at three layers:
   - **Transport layer:** Each context subscribes under its own `routing_id` (ADR-004). The relay delivers BLOBs tagged with the matching `routing_id`, and the client demultiplexes incoming BLOBs to the correct context by this field. For QUIC (§10.14), each subscription gets its own bidirectional stream, providing stream-level isolation.
   - **Pseudonym layer:** `routing_id` values are per-context HMAC-SHA256 pseudonyms (§9.10.4). Different contexts produce cryptographically unlinkable routing identifiers. The relay cannot determine which subscriptions on a connection belong to the same or different contexts.
   - **Encryption layer:** Each context is an independent MLS group (§9.7.1). Even if the transport layer erroneously delivered a blob to the wrong subscription, the recipient could not decrypt it — they lack the other context's MLS epoch key material. Encryption-as-access-control (§10.5) is the ultimate isolation boundary; transport-layer tagging is an optimization, not a security mechanism.

### 10.13.3 Connection Budget

Each profile defines a maximum total connection count across all adapters. When the budget is reached:

1. **LRU eviction.** The least-recently-used connection (by last message send or receive timestamp) is closed.
2. **Subscription migration.** Subscriptions on the evicted connection are migrated to a surviving connection to the same relay (if one exists) or to a different relay in the context's relay set (via relay reassignment).
3. **Mobile shedding.** The `mobile` profile proactively sheds connections for inactive contexts (no sends or receives in the last 5 minutes) and relies on the push notification bridge (§10.7) to wake the connection on new messages.

Connection budgets are soft limits. The SDK MAY temporarily exceed the budget during relay set reassignment or context join operations, then converge back within the budget within 30 seconds.

## 10.14 QUIC Transport Binding

QUIC replaces WebSocket for native (non-browser) clients. Same relay, same MessagePack wire format (ADR-004), different framing. QUIC connections use per-operation streams rather than multiplexing all operations over a single bidirectional channel.

### 10.14.1 Operation Mapping

| ADR-004 Operation | WebSocket | QUIC |
|---|---|---|
| PUBLISH | Binary frame on shared connection; correlate via `ref_id` | New bidirectional stream → send PUBLISH → receive ACK/ERR → close stream |
| SUBSCRIBE | Binary frame; BLOBs arrive on shared connection tagged with `routing_id` | Open long-lived bidirectional stream → send SUBSCRIBE → receive BLOBs on same stream until close |
| UNSUBSCRIBE | Binary frame | Close the subscription's stream (clean FIN) |
| QUERY | Binary frame; results arrive tagged with `ref_id` | New bidirectional stream → send QUERY → receive results + `query_complete` → close stream |
| DELETE | Binary frame; correlate via `ref_id` | New bidirectional stream → send DELETE → receive ACK/ERR → close stream |
| PING/PONG | WebSocket frames, 30s interval | Not needed — QUIC has native keepalive via PING frames (RFC 9000 §19.2) |

**Wire format.** Each QUIC stream carries the same MessagePack-encoded messages specified in ADR-004. The `op` field, field types, and validation rules are identical. The only difference is framing: WebSocket uses binary frames on a shared connection with `ref_id` correlation; QUIC uses independent streams where responses are scoped to their stream, making `ref_id` unnecessary (though it MAY still be included for logging/debugging).

**Cover traffic over QUIC.** Same profile tier applies (§10.13). Dummies are sent as short-lived bidirectional streams identical in structure to PUBLISH operations — the relay cannot distinguish dummy streams from real PUBLISH streams. One QUIC connection covers all streams, so cover traffic cost is amortized.

### 10.14.2 Connection Lifecycle

1. **Initial connection.** Client opens a QUIC connection to the relay using `quinn` (or equivalent QUIC implementation). TLS 1.3 is built into QUIC — no separate TLS handshake.
2. **0-RTT resumption.** Resumed QUIC sessions use 0-RTT to send application data immediately without waiting for the handshake to complete, eliminating round-trip latency on reconnection. Session tickets are stored locally and rotated per the QUIC specification. 0-RTT data has no replay protection from the transport layer (RFC 9001 §9.2). SCP specifies the following 0-RTT safety classification:

   **0-RTT-safe operations (idempotent — MAY be sent as 0-RTT data):**
   - `SUBSCRIBE` — subscribing to a routing ID is idempotent; duplicate subscriptions are no-ops.
   - `QUERY` — read-only queries produce the same result regardless of replay.
   - `PING` — keepalive, inherently idempotent.

   **0-RTT-unsafe operations (non-idempotent — MUST NOT be sent as 0-RTT data):**
   - `PUBLISH` — publishing a message is not idempotent; replaying a PUBLISH creates duplicate blobs on the relay. Clients MUST wait for the 1-RTT handshake to complete before sending PUBLISH operations.
   - `DELETE` — while semantically idempotent (deleting an already-deleted blob is a no-op), DELETE carries authorization implications and MUST NOT be sent in 0-RTT to prevent replay-based deletion attacks.
   - `UNSUBSCRIBE` — replaying an UNSUBSCRIBE could cancel a subscription established after the original UNSUBSCRIBE.

   **Relay enforcement:** Relays MUST reject 0-RTT-unsafe operations received as 0-RTT data with an error response (`{ op: "ERR", code: 4010, message: "operation not permitted in 0-RTT" }`). The client MUST retry the operation after the 1-RTT handshake completes. Relays that accept 0-RTT data MUST additionally maintain a nonce-based anti-replay cache as defense-in-depth: each 0-RTT QUIC packet's `client_initial` is cached (keyed by the session ticket + packet number) with a TTL of 10 minutes. Duplicate 0-RTT packets are silently dropped.
3. **Connection migration.** When the client's IP address changes (e.g., WiFi → cellular), QUIC migrates the connection without closing it. Active subscription streams continue uninterrupted. This is critical for mobile profiles where network transitions are frequent.
4. **Reconnection.** On connection loss, the client uses profile-aware exponential backoff (§10.13.1). After reconnection, the client re-opens subscription streams with `since = last_received_stored_at - 5s` overlap (same gap-fill strategy as WebSocket, per ADR-004).
5. **Keepalive.** QUIC's native PING frame mechanism (RFC 9000 §19.2) replaces WebSocket PING/PONG. PING frames are ack-eliciting, resetting the idle timeout. No application-level keepalive is needed.

### 10.14.3 Relay QUIC Support

Relays that support QUIC:

1. **Listener.** Accept QUIC connections on the same port number (UDP) alongside WebSocket (TCP). ALPN negotiation selects the application protocol within each transport layer independently. The relay's TLS certificate covers both protocols.
2. **Shared state.** QUIC and WebSocket handlers share the same subscription registry, blob storage, rate limiters, and delivery jitter configuration.
3. **Advertisement.** Relay advertises QUIC support in `.well-known/scp` under `relay_config.transports` (§10.5.1).
4. **Fallback.** If a relay does not advertise QUIC, clients fall back to WebSocket. The client MAY probe QUIC with a single initial packet; if no response within 3 seconds, it falls back to WebSocket without further QUIC attempts for that relay until the next `.well-known/scp` refresh.

QUIC support is RECOMMENDED for production relays. WebSocket remains the mandatory baseline.

## 10.15 HTTP/3 and WebTransport

HTTP/3 (QUIC-based HTTP) serves two roles in SCP: as the relay's HTTP upgrade path for all HTTP endpoints, and as the foundation for WebTransport — the browser-facing equivalent of the QUIC transport binding (§10.14).

### 10.15.1 Relay HTTP/3 Upgrade Path

All relay HTTP endpoints benefit from HTTP/3:

- `.well-known/scp` — 0-RTT on repeat visits, faster relay discovery
- `/scp/dev/v1/*` — local dev API (§18.10) with multiplexed requests
- `/scp/v1/feed/*` — broadcast projection (§18.11) with multiplexed polling
- WebSocket upgrade — HTTP/3 supports WebSocket bootstrapping via RFC 9220 (Extended CONNECT; browser support limited as of 2026)

**Deployment model:**
1. Relay serves HTTP/1.1 + HTTP/2 on TCP:443 (via ALPN) and HTTP/3 on UDP:443 (via QUIC ALPN `h3`). Clients discover HTTP/3 availability through `Alt-Svc` headers.
2. HTTP/3 is advertised via `Alt-Svc` header on HTTP/1.1 and HTTP/2 responses.
3. Clients that support HTTP/3 upgrade transparently — no application-level protocol change.
4. `ApplicationNode::serve()` gains HTTP/3 support when the underlying server supports it (hyper + h3).

**Relay requirement:** HTTP/3 support is RECOMMENDED for public relays (improves latency for discovery and projection endpoints). Not required — HTTP/1.1 remains the baseline.

### 10.15.2 WebTransport for Browser Clients

WebTransport is the browser-facing equivalent of §10.14 (QUIC), using the WebTransport API over HTTP/3.

**Distinction from QUIC.** WebTransport is mediated by the browser's network stack. The SCP browser client transport uses the `WebTransport` API. Non-browser clients use QUIC directly (§10.14). Server-side, the relay handles both — QUIC connections and WebTransport sessions are both QUIC underneath, sharing the same subscription registry and blob storage.

**Connection model:**
1. Browser opens `new WebTransport("https://<host>/scp/v1")` — establishes HTTP/3 + WebTransport session.
2. Same per-operation stream model as §10.14.1.
3. Server must support HTTP/3 and advertise via `Alt-Svc` header.

**Relay requirements:**
- Serve HTTP/3 on the same port as HTTPS (ALPN + Alt-Svc).
- Accept WebTransport sessions at `/scp/v1`.
- Advertise in `.well-known/scp`: `relay_config.transports` includes `"webtransport"`.
- WebTransport support is OPTIONAL for relays. WebSocket remains mandatory for browser compatibility.

### 10.15.3 Fallback Chain

Browser clients follow this transport selection order:

1. **WebTransport** — attempt `new WebTransport(url)`. If the `WebTransport` API is unavailable (Safari, older browsers) or the connection fails (relay doesn't support HTTP/3), fall through.
2. **WebSocket** — fall back to `new WebSocket("wss://<host>/scp/v1")`. This is the mandatory baseline that all relays support.
3. **Error** — if WebSocket also fails, report connection failure.

The fallback is transparent to `TransportAdapter` callers. The browser client transport wraps both transports behind the same adapter interface. The browser client transport MAY switch from WebSocket to WebTransport mid-session if the relay advertises WebTransport support via `Alt-Svc`. This involves establishing a new WebTransport session and re-opening subscription streams (same gap-fill strategy as reconnection), not an in-place protocol upgrade.

## 10.16 Constrained Device Transport

For IoT, embedded, and resource-limited devices that cannot sustain TCP connections. Two options are provided; implementors choose based on their ecosystem.

### 10.16.1 MessagePack-over-DTLS

The SCP-native option for constrained devices. Uses the same MessagePack wire format as ADR-004 over DTLS 1.3 datagrams instead of WebSocket frames.

1. **DTLS 1.3 session.** Client establishes a DTLS 1.3 session with the relay. TLS 1.3 security guarantees apply.
2. **Datagram semantics.** Each operation (PUBLISH, QUERY, DELETE) is an independent DTLS datagram (or datagram sequence for payloads exceeding the path MTU). The DTLS 1.3 association holds cryptographic state and may persist across operations via Connection IDs (RFC 9146), but there is no stream-oriented connection as with TCP/QUIC — each datagram is independently routable.
3. **Session resumption.** DTLS session tickets enable 0-RTT reconnection, avoiding a full handshake on subsequent operations. DTLS 1.3 Connection IDs (RFC 9146) SHOULD be used to maintain DTLS associations across NAT rebinding events, avoiding costly re-handshakes on IP address changes.
4. **Max datagram size.** Constrained by path MTU. Common networks allow ~1200 byte UDP payloads; 6LoWPAN and other constrained link layers may be significantly smaller. Envelopes exceeding the path MTU require fragmentation at the DTLS layer. Recommended max blob size: 1024 bytes for single-datagram delivery.
5. **Anti-amplification.** Relays MUST implement DTLS 1.3 HelloRetryRequest for address validation on new associations to prevent amplification attacks (RFC 9147 §5.1).
6. **No SUBSCRIBE.** `subscribe()` is not supported over UDP (no persistent connection for push delivery). Constrained devices poll via QUERY at configurable intervals. `subscribe()` returns `TransportError::NotSupported`.

### 10.16.2 CoAP-over-DTLS

The IoT interoperability option. Uses CoAP (RFC 7252) as a framing layer over DTLS, enabling integration with existing IoT infrastructure (CoAP proxies, LwM2M, etc.).

1. **Operation mapping.** SCP operations map to CoAP methods:
   - PUBLISH → `POST /scp/{hex(routing_id)}` with blob as payload
   - QUERY → `GET /scp/{hex(routing_id)}?since={timestamp}&limit={n}`
   - DELETE → `DELETE /scp/{hex(routing_id)}/{blob_id}`
2. **CoAP Observe.** RFC 7641 Observe provides lightweight subscription: client registers observation on a resource, server pushes new blobs as notifications. This is best-effort — the server MAY stop notifying at any time, and the client must re-register. Not equivalent to persistent SUBSCRIBE.
3. **Confirmable messages.** CoAP CON messages provide at-least-once delivery semantics for PUBLISH and DELETE. NON messages may be used for QUERY when loss is acceptable.
4. **Interoperability.** CoAP proxies can bridge between constrained devices and SCP relays, translating CoAP requests to the relay's native protocol (WebSocket or QUIC).
5. **Authentication.** CoAP endpoints are unauthenticated, consistent with the native relay model (ADR-004): relays do not authenticate clients. DTLS provides transport-layer encryption; participant identity is authenticated inside the MLS-encrypted envelope (§9.13). Relay operators who want to restrict access MAY use DTLS client certificates or CoAP's `Authorization` option (RFC 9202) as rate-limiting mechanisms, but these are not required for protocol security.

### 10.16.3 Trade-offs

Constrained device transport makes explicit trade-offs:

| Property | Full profile (§10.13) | Constrained profile |
|----------|----------------------|-------------------|
| Cover traffic | Full or reduced (§9.10.6) | Off |
| Suppression resistance | 3+ relays with cross-check | Single relay, no cross-check |
| Real-time delivery | Persistent subscription streams | Poll-based (QUERY interval) or CoAP Observe (best-effort) |
| Connection overhead | Persistent TCP/QUIC + keepalive | Connectionless UDP datagrams |
| Metadata privacy | Pseudonyms + padding + jitter | Pseudonyms only (no padding budget, no jitter) |

These trade-offs are acceptable because constrained devices typically operate behind a **gateway agent** — a full-profile participant (desktop or server) that bridges between the constrained device's local transport (BLE, MQTT, or UDP/DTLS) and the full SCP relay network. The gateway provides the suppression resistance, cover traffic, and real-time delivery that the constrained device cannot sustain on its own.

## 10.17 Node vs. Participant

A `scp-node` is **pure infrastructure**: a relay (§10.4), an identity service (key-event log replay and record publication over the relay network), and an HTTP projection surface (§10.12.11). A node **never participates in a context as itself.** It stores and forwards opaque encrypted blobs (§10.4 — relays are protocol-unaware), it resolves and publishes key-event records and service records, and it serves projected broadcast content over HTTP; it does not join contexts, create MLS groups, or sign protocol messages in its own right. This is the same boundary §10.2 draws ("no server *owns* you"), §10.4 draws ("relays cannot read content, inspect membership, or understand context semantics"), §10.5 draws ("the SDK owns all protocol logic; transport is not the product"), and §10.12.6 draws (the relay authenticates nothing at the transport level — MLS is the confidentiality boundary).

**Participation is exclusively an SDK participant client bound to an identity.** All protocol participation — joining a context, creating an MLS group, publishing content, casting and verifying governance votes — is performed by an SDK participant client (a `Supervisor`/`ContextManager`) that holds custody, is bound to an identity, and runs the full protocol pipeline, including the real `IdentityBackend::resolve` path that derives each voter's key state from its key-event log (`03-identity.md` §3.10.4) before it verifies that voter's signature. There is one participant engine; a node is never a second, special kind of participant. A participant constructed without a real resolver (for example, a resolver that returns `None` for every lookup) is not a complete participant and MUST NOT be shipped.

A participant has **two deployment shapes** relative to a node:

- **Bundled (co-located).** The participant client runs **inside the node process** as a single binary. Custody and key material never cross a process boundary. The participant reaches the node's relay over the in-process loopback socket (`ws://127.0.0.1:<relay_port>/scp/v1`), authenticating with the node's internal bridge bearer token. Communication is via the loopback relay — the participant publishes encrypted envelopes onto the relay's blob storage and the node's projection scans that same storage — not via a directly shared blob backend, so the bundled binary exercises the same publish path as any external participant.

- **External (separate process).** The participant client runs in **its own process** and connects to a node's relay over the socket: loopback when on the same box, `wss://` when off-host (the transport-security rules of §10.12.5/§10.12.6 apply to the off-host case). It **brings its own custody**. **Access control for an external participant is cryptographic, not transport-level**: the relay is a protocol-unaware dumb pipe (§10.4), and the participant's authority to read or write context content is enforced by MLS group membership and UCAN capabilities (encryption-as-access-control), exactly as for any participant. External participants reach `/scp/v1` over the node's existing TLS-terminated **Full** public surface — there is no dedicated listener mode, toggle, admission token, or pre-shared secret; relays are anonymous, DHT-auto-discovered dumb pipes that participants do not hand-pick, so reachability is governed entirely by the public-surface selection (§10.12.11), the bind address, and the TLS mode (§10.12.6), exactly as for any client of the relay. Abuse prevention for an open `wss://` relay — a spam, denial-of-service, and storage-abuse vector — is provided by the relay's existing rate limiting and abuse controls (§10.4) together with relay economics (§19.8 Relay Monetization, including `rate_limit_publish`), which satisfy §10.4's "rate limiting and abuse prevention" requirement without an allowlist that is at odds with the anonymous-relay model. Enabling external participants does not expose the dev/control endpoints, which remain loopback-only: the read-only self-host public surface never mounts `/scp/v1` (§10.12.11 "Origin-root mount").

**The self-hosted website binary (`scp-node --self-host`, §10.12.11) is the bundled shape.** Publishing the operator's site is not the node participating in a context — it is a co-located SDK participant client, running inside the node process and sharing the node's custody, that creates a broadcast context and publishes the site assets as `BroadcastContent` (§5.14, ADR-042); the node then decrypts and projects them over HTTP. The participant and the node are distinct roles co-located in one process, never a single "participating node."
