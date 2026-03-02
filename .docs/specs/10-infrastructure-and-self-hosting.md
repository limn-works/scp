# 10. Infrastructure and Self-Hosting

## 10.1 Philosophy

Self-hosting is a first-class deployment model, not an afterthought. But "self-hosting" means different things at different layers, and the protocol should be honest about which layers are easy and which are hard.

What the protocol guarantees: **no infrastructure operator owns your identity, your relationships, or your social graph.** These live on your device, bound to your DID, portable across any infrastructure. This is the non-negotiable.

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
       │                            Natural SCP node: relay, hosting,
       │                            bridge connectors as marginal load.
       │                            Likely the most common always-on
       │                            self-hosted node type.
       │
  Personal server / NAS          ← power user. Persistent relay.
       │                            Hosts bridge connectors.
       │                            Not "self-hosting" in the Matrix
       │                            sense — no protocol server, just
       │                            relay + storage.
       │
  Managed infrastructure         ← convenience. High availability.
       │                            Media hosting. Paid service.
       │
  All of the above simultaneously ← the expected state for many users.
```

The **agent workstation** tier is a critical addition to the deployment model. As builder agents (LLMs that generate and manage software) become mainstream, non-technical users are acquiring dedicated always-on hardware to run them. These machines are already always-on, capable, and user-controlled. SCP infrastructure — relays, context hosting, bridge connectors — is marginal additional load on hardware that's already running 24/7. The builder agent that generates an SCP app can also provision the infrastructure: spin up a relay, configure contexts, register tools — developer and ops in one.

This changes relay economics fundamentally. The question is not "who pays for relay infrastructure" but "you already have the hardware, the relay is just another process." Self-hosting stops being an aspirational option for technical users and becomes the natural default for anyone with a builder agent workstation. The gravitational pull toward centralized relays weakens when most users have their own always-on node.

The protocol must function correctly at every point on this spectrum. A phone-only user and a user with dedicated infrastructure are both first-class participants. The protocol cannot assume persistent connectivity, stable IP addresses, or server-grade resources.

The critical difference from Matrix: in Matrix, your homeserver owns your identity (`@user:server`). If it dies, you're in trouble. In SCP, your DID is self-sovereign. If your relay dies, you switch relays. If your device dies, you recover your identity through social/device recovery (§3.3). No infrastructure operator holds your identity hostage. This — not the elimination of servers — is the real structural advantage.

## 10.3 Minimal Protocol State

The protocol's state footprint per context is deliberately minimal: membership list, role assignments, capability tokens, tool registrations, governance model, and content hashes. Not content itself. Not media. Not application state.

This is load-bearing. If protocol state is small, devices can be nodes. If protocol state includes all content, only servers can play. Matrix learned this the hard way — room state accumulates unboundedly and Synapse instances consume gigabytes of RAM for large rooms.

Content storage is outside protocol scope — the protocol does not define where content lives, how it's stored, or how it's replicated. That is a client and app-layer decision (see §10.8). The protocol concerns itself with protocol state (membership, roles, tokens, governance, event logs). Content is whatever the context's participants produce and consume. The protocol delivers it through encrypted envelopes; storage is the app's responsibility.

**Verifiable event logs (§7.3.1) add a storage requirement.** Each context maintains a Merkle tree of its event history. This is protocol state — it must be available for validation queries. The tree itself is append-only and grows with context activity. For active contexts, this could become significant. The protocol must define pruning rules (how old events are archived or summarized), checkpoint mechanisms (periodic Merkle roots that compress history), and availability requirements (does every device store the full tree, or can proofs be fetched on demand from relays or peers?). This is the primary tension between minimal state and verifiable history — the design must resolve it explicitly.

## 10.4 Relay Architecture

Devices that aren't always online need relays for message delivery. Relays hold encrypted payloads and deliver them when the recipient comes online. They are the availability layer — the thing that makes the protocol work when devices are asleep, offline, or behind NAT.

**Design goals:**

- **Protocol-unaware.** Relays don't interpret protocol semantics. They store and forward encrypted blobs. This keeps relay implementation simple and prevents relay operators from gaining protocol-level influence.
- **Substitutable.** Switching relays requires no identity change, no context migration, no social disruption. Identity is DID-based, not relay-based. This is the key structural difference from Matrix homeservers.
- **Untrusted for content.** Relays see encrypted payloads. They cannot read content, inspect membership, or understand context semantics. A malicious relay can delay or drop messages; it cannot compromise confidentiality or integrity.

**Honest constraints:**

- **Metadata exposure.** Traffic analysis is powerful even with encrypted payloads. The protocol provides layered metadata privacy protections: minimal outer envelopes with per-context pseudonyms, fixed bucket padding, persistent connections, constant-rate cover traffic, and relay set partitioning. (See §9.9.1 for the formal relay threat model — what relays CAN and CANNOT do — and §9.10 for the complete metadata privacy architecture.)
- **Relay discovery.** If Alice wants to reach Bob, she needs to know Bob's relay. If Bob switches relays, Alice needs to discover the new one. This requires either a centralized directory (defeats the purpose), a distributed discovery mechanism (adds complexity and latency), or multi-relay registration (Bob publishes to several relays, Alice checks all of them). Nostr's experience: users publish a relay list, clients check multiple relays. Workable but not seamless. Relay list authentication is specified in §9.6.3 — NIP-65 signed events prevent relay list substitution attacks.
- **Operational complexity.** A production relay needs reliable delivery, ordering, deduplication, rate limiting, and abuse prevention. "Simple message queue" undersells this. A reference implementation should exist, but running it reliably is a server operations task — not "install an app" level.
- **Gravitational pull.** In theory relays are commodity. In practice, network effects apply to infrastructure. Nostr shows this: a few popular relays handle most traffic. The protocol can't prevent this concentration, but DID-based identity ensures it doesn't create lock-in — popular relay dies, users switch, identity survives. The agent workstation trend (§10.2) may significantly weaken centralization pressure — if most users run their own always-on node, personal relays become the default rather than the exception.

**Self-hosting:** Running a personal relay is feasible for technical users. It requires a stable address, TLS, and uptime commitment. This is meaningfully simpler than running a Matrix homeserver (no state resolution, no federation protocol, no room DAG) but it is still a server. The protocol should ship a reference relay that minimizes operational burden, but should not claim self-hosting is effortless.

**Multi-relay resilience.** For availability and equivocation resistance, clients SHOULD publish to 3+ relays and maintain per-relay reliability scores (§9.9.2). The Relay Consistency Protocol (§9.9.3) enables members to detect relays that show different event histories to different clients. Combined with per-sender sequence numbers (§9.8.5), clients can detect message suppression and switch to healthier relays automatically.

**Relay conformance testing.** Relay storage backends implement the `BlobStore` trait (§16.4.1) and are verified by the `blob_store_conformance!()` macro (§16.12.6), which tests store/retrieve roundtrips, TTL expiry, listing, deletion, and concurrent access. The `InMemoryRelay` (§16.4.3) is the reference implementation; every production backend (SQLite, redb, etc.) must pass the same suite. First-party `BlobStore` adapters include `SqliteBlobStore` (personal relays), `RedbBlobStore` (medium relays, pure Rust), `PostgresBlobStore` (production/enterprise), and `S3BlobStore` (large-scale/cloud). See §17.7 for the complete adapter roster. Multi-relay adversarial scenarios — suppression, equivocation, delay, replay, Commit suppression — are tested via `BehaviorMode` fault injection in the network simulation harness (§16.4.4).

## 10.5 SDK Transport Architecture

The SCP SDK owns all protocol logic — contexts, agents, trust, capabilities, governance, bridge connectors, provenance. This is the product. Transport is not the product.

The SDK provides a **transport abstraction layer**: a defined interface contract between protocol logic and delivery infrastructure. The abstraction specifies what properties the transport must provide (encrypted envelope delivery, offline store-and-forward, context-scoped subscription, relay discovery) without specifying how the transport implements them.

Below the abstraction, **transport bindings** adapt SCP's requirements to specific delivery infrastructure. The SDK ships at least one reference binding. The binding is responsible for encoding SCP envelopes into the transport's native format, managing transport connections, and mapping SCP identities to transport-native identities (e.g., DID to Nostr npub).

**What SCP specifies for transport:**

- Encrypted envelope format (SCP's responsibility — the payload the transport carries)
- Transport abstraction interface (SCP's responsibility — the contract bindings must implement)
- SCP native relay protocol (SCP specifies this — the simplest possible store-and-forward relay purpose-built for SCP envelopes)
- Reference relay implementation (SCP ships this — a minimal relay for self-hosters)
- Transport adapter implementations organized by specification depth (§10.5.1). Tier 1 bindings are fully specified with wire mappings and conformance requirements. Tier 2 bindings have documented TransportAdapter mappings. Tier 3 bindings are feasibility-confirmed.

The SCP native relay is the canonical reference — the simplest possible thing that satisfies SCP's transport needs: accept encrypted blobs, store them, forward to subscribers by context ID and/or recipient DID, respond with delivery receipts, honor deletion requests. All other adapters map the transport abstraction to their respective protocols.

**What SCP does not specify:**

- Third-party relay protocol internals (that's Nostr's/Matrix's/etc. spec, not SCP's)
- Third-party relay implementation
- Relay operations (that's either self-hosting or managed infrastructure)

**No fundamental dependency on any single transport.** The protocol must function correctly on any transport that implements the abstraction interface. SCP native relays are the default, but the protocol does not assume or require them. A deployment using only Hyperswarm, or only Matrix, or only direct WebSocket, is equally valid.

**Transport adapter conformance.** Every `TransportAdapter` implementation is verified by the `transport_conformance!()` macro (§16.12.1), which tests send/subscribe roundtrips, backfill with `since`, unsubscribe, query, delete, and deduplication. The `InMemoryTransport` (§16.5) is the reference implementation that passes conformance first; every production adapter must pass the same suite before being considered complete.

**Transport security.** All relay connections MUST use TLS 1.3 (TLS 1.2 acceptable as fallback). Certificate pinning is supported for known relays. See §9.13 for the complete transport security specification.

**Encryption-as-access-control.** Context access control is enforced through encryption, not through relay logic. Specifically, each context maps to one MLS group (§9.7.1); the MLS group key material is the access credential. All context events are encrypted with the current MLS epoch secrets before reaching the transport layer. Relays store and forward opaque blobs — they cannot read content, verify membership, or enforce roles. Key distribution is membership. Member removal triggers MLS Remove Commit + epoch advancement — the removed member does not possess the new epoch's key material and physically cannot decrypt subsequent messages. This keeps the relay layer genuinely protocol-unaware and makes any encrypted-blob-capable relay — including existing Nostr relays — usable as SCP transport without modification.

**Blocking uses a separate sender-side key layer, not MLS group membership.** DID-to-DID blocking (§3.6) is a unilateral, per-relationship action — it does not require group coordination and does not affect the blocked party's membership in the context. When Alice blocks Dave, Alice rotates her personal sender key and redistributes it to all context members except Dave. Dave physically cannot decrypt Alice's future messages. Dave remains an MLS group member and can still decrypt messages from other members.

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
- **Constraints:** High latency (total circuit RTT typically 200–600ms for 3-hop circuits; hidden service connections use 6 hops — client 3 + service 3 to rendezvous — approximately doubling latency). No UDP (Tor is TCP-only — QUIC requires experimental Tor UDP support). Cover traffic less useful (Tor provides some traffic analysis resistance at the network layer, though not immune to timing correlation). Relay .onion address replaces DNS — DID document uses `.onion` URL.

**I2P** (invisible internet protocol)
- All 5 methods → delegate to underlying adapter routed through I2P.
- **Connection model:** I2P streaming library (TCP-like) or I2P datagrams (UDP-like). Relay runs as I2P destination with b32.i2p address.
- **Constraints:** Similar to Tor but fully distributed (no exit nodes). Higher latency. Smaller network. I2P datagrams enable UDP-like transport. DID document uses `.b32.i2p` URL.

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
- **Constraints:** Requires Yggdrasil/cjdns daemon running on both client and relay. Relay advertises mesh IPv6 address in DID document. Latency depends on mesh topology. Provides NAT traversal for free (overlay addresses are globally routable within the mesh).

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

**Push notification opacity is mandatory.** Push payloads MUST contain a wake signal and nothing else. No context ID, no sender DID, no message preview, no metadata of any kind. The device wakes, connects to relays, pulls encrypted envelopes, and decrypts locally. Apple/Google learn only that the device received a notification at a specific time.

- **Push payloads are fully opaque.** The push payload contains exactly one piece of information: "wake up." No sender, no context, no count, no preview. The SCP agent on the device connects to its relay set and pulls all pending envelopes.
- **The push service knows timing, not content or source.** Apple/Google learn when a device received a notification. They cannot determine which context, which sender, or even whether the notification corresponds to one message or many.
- **A sovereign push alternative is desirable but not blocking.** If a mechanism emerges that enables push without platform gatekeepers, the protocol should adopt it. For now, this is an accepted constraint with the opacity guarantee limiting metadata exposure to timing only.

## 10.8 Multi-Device

Multi-device coordination — read state, session continuity, notification deduplication, device handoff — is a client-scope concern. The protocol provides the building blocks:

- **Identity private state (§3.7)** syncs personal configuration across devices via encrypted event log on relays.
- **Context state** is the same regardless of which device queries it.
- **Encrypted envelopes** are available on relays for any device that holds the keys.

How a client uses these to implement read markers, notification deduplication, or session handoff is the client's decision. A simple client might treat each device as independent. A sophisticated client might sync UI state through identity private state or through a dedicated coordination mechanism. The protocol delivers the same encrypted envelopes to all devices; the client decides how to present them.

## 10.9 Real-Time and Async

The protocol supports both real-time and asynchronous interaction. This is not a dichotomy — it's a spectrum, and the SDK provides first-class support across it.

- **Async:** Messages are encrypted, delivered to relays, fetched when the recipient's agent comes online. This is the baseline that works for all participants regardless of connectivity.
- **Real-time:** When both parties are online simultaneously, the transport layer can deliver envelopes immediately. WebSocket connections to relays, direct peer-to-peer via libp2p, or any transport binding that supports streaming delivery. Latency depends on the transport binding, not the protocol.
- **Presence, typing indicators, live collaboration:** These are tool-level or context-level capabilities, not protocol primitives. A context that needs presence registers a presence tool. A context that needs typing indicators includes them as ephemeral events. The protocol carries them through the same encrypted envelope system — the content is up to the context.

The SDK provides the transport abstraction and envelope delivery. Whether that delivery is batched-async or streaming-realtime depends on the transport binding and what the client needs. Both are first-class.

### 10.9.1 Real-Time Media Transport

Real-time media (voice, video, screen sharing) has different performance requirements than messaging. The full SCP message pipeline — sender-side encryption, MLS group encryption, fixed bucket padding, store-and-forward relay delivery — adds per-frame overhead and latency incompatible with real-time media at 30-60fps. Media transport uses a delegated model:

1. **Context establishes the session.** The context provides identity (who's in the call), trust (are they authorized), governance (does the context allow media), and membership enforcement. All of this happens through the standard SCP message pipeline.
2. **MLS derives media session keys.** The MLS group's key schedule exports keying material for the media session (MLS exporter, RFC 9420 §8). This binds the media encryption to the context's group state — only current members can derive the keys.
3. **Media flows over WebRTC.** DTLS-SRTP handles the actual media encryption and transport, using keys derived from step 2. Media frames flow peer-to-peer (or through a WebRTC SFU) without passing through SCP relays or the MLS encryption pipeline. WebRTC provides the low-latency, high-throughput transport that media requires.
4. **Signaling goes through SCP.** WebRTC session negotiation (SDP offers/answers, ICE candidates) flows through the context as standard SCP messages. This means signaling is end-to-end encrypted, authenticated, and governed by the context — only members can initiate or join media sessions.

**What SCP governs:** Who can participate (membership), what media capabilities are allowed (capability ceiling), session initiation and teardown (signaling), and key material (MLS-derived). **What WebRTC handles:** Media encoding, transport, congestion control, codec negotiation, NAT traversal.

This separation means contexts can support voice/video calls without the protocol needing to become a media transport. The context is the trust boundary; WebRTC is the media pipe.

## 10.10 Business Model Direction

Managed infrastructure and media/content hosting are the probable revenue surfaces. Heavy content (video, large files, real-time streams) has real storage and bandwidth costs. The protocol works either way — self-hosters shoulder their own costs, managed infrastructure shoulders it for a fee. The point is the choice exists and the protocol doesn't prefer either.

Relay economics are the responsibility of app builders and relay operators. The protocol defines what relays do, not who runs them or how they're funded. Community-operated relays, paid relay services, app-bundled relay infrastructure, and self-hosted relays are all valid. The protocol ensures none of them create lock-in (DID identity, substitutable relays). In practice, app developers who build on SCP are expected to provision relay infrastructure for their users — the same way app developers today provision API servers, databases, and CDNs. There is no assumption of free community relay infrastructure at the protocol level; a protocol foundation may eventually provide shared infrastructure, but this is not a dependency.

**Relay monetization protocol.** §19.8 specifies the protocol-level relay economic config: per-publish and per-byte-stored pricing advertised in `.well-known/scp` `relay_config` (§18.3.3), compatible payment adapters, and the `PaymentAdapter` trait (§19.2) for settlement. Relay selection in `TransportManager` (ADR-012) uses cost as a criterion alongside reliability and latency. Free relays MUST always exist in the bootstrap relay list (§18.5) — economic gatekeeping of basic protocol operation is a protocol violation.

**The agent workstation effect.** As builder agents become mainstream and users acquire dedicated always-on hardware to run them (§10.2), the relay economics shift structurally. Relay infrastructure is marginal load on hardware that's already running 24/7. Builder agents can provision SCP infrastructure — relays, context hosting, bridge connectors — as part of generating apps. The "who pays for relays?" question dissolves for users with agent workstations: you already have the hardware, the relay is just another process. Managed infrastructure remains valuable for users without always-on hardware (phone-only users) and for heavy content workloads, but the default self-hosting path becomes significantly more accessible.

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
| 3 | Relay bridging (TURN-like) | ~100% (symmetric NAT fallback) | A willing SCP relay as bridge | +1 hop | BRIDGE operation |
| 4 | Domain-based (existing §18.6) | 100% | DNS + ACME CA | Direct | None |

**Tier selection algorithm:**

1. If a domain is configured (`.domain()`), attempt domain-based deployment first. Verify: DNS resolves to a reachable address, ACME challenge succeeds, `wss://` WebSocket upgrade completes. If all checks pass, Tier 4 is the active tier. If any check fails, log the failure reason and fall through to step 2.
2. If no domain is configured (`.no_domain()`), or if domain-based deployment failed, probe NAT type via STUN binding request to a known relay (§10.12.3).
3. Attempt Tier 1 (UPnP/NAT-PMP). If a port mapping is obtained and external reachability is verified, Tier 1 is the active tier.
4. If Tier 1 fails and NAT type is non-symmetric (full-cone, address-restricted, or port-restricted), attempt Tier 2 (STUN hole punching). If the external address is reachable, Tier 2 is the active tier.
5. If Tier 2 fails or NAT type is symmetric, register with a bridge relay (Tier 3). Tier 3 always succeeds if a bridge relay is available.
6. If no bridge relay is available, the self-hosted relay is unreachable from the internet. Log an error. The operator can still participate as an SCP identity using external relays — they just cannot serve as a relay for others.

Selection is logged at INFO level but not exposed to the user as a choice. The SDK re-evaluates periodically (recommended: every 30 minutes) and on network change events (IP change, interface up/down). Tier changes are transparent — the DID document is updated with the new relay address, and peers re-resolve on connection failure.

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
- Mapping loss triggers immediate DID document update if the tier changes.

**External address publication:** The external `ip:port` from the UPnP/NAT-PMP response is published in the DID document as an `SCPRelay` service endpoint (§18.2.1) with a `ws://` URL (§10.12.6). The `RepublishManager` handles address updates when the external IP or port changes.

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
4. The external address is published in the DID document as the relay's reachable address.
5. **Connection coordination:** A peer resolving the self-hosted relay's DID document obtains the external address. For restricted NATs, the self-hosted relay must initiate a packet exchange with each connecting peer. The relay periodically sends keepalive packets to peers that have announced their intent to connect (via a coordination message through an intermediary relay). This creates the NAT pinhole that allows the peer to connect back.

**Keepalive:** NAT mappings expire if unused (typical timeout: 30-120 seconds). The SDK sends a 25-second UDP keepalive to maintain the mapping. The keepalive is a minimal STUN Binding Indication (no response expected) or a zero-length UDP packet, depending on the STUN server's capabilities.

**STUN service on SCP relays:** Any SCP relay MAY serve as a STUN endpoint. STUN is lightweight (stateless, single UDP socket, minimal CPU) and can coexist with the relay's WebSocket endpoint. The relay advertises STUN support in its `.well-known/scp` `relay_config` or relay metadata.

- Bootstrap relays (§18.5.1, fallback relay list) MUST include at least one STUN-capable relay. This ensures that new identities can probe their NAT type without prior infrastructure.
- Self-hosted relays that have achieved public reachability (Tiers 1, 2, or 4) MAY also offer STUN service — a self-reinforcing network where every new reachable relay makes the next NAT traversal easier.

**Symmetric NAT:** If the STUN probe determines the NAT is symmetric (~15% of deployments), hole punching is not viable — the NAT assigns a different external mapping per destination, making the external address unpredictable. The SDK falls through to Tier 3.

**Fallthrough:** If NAT is symmetric, or if the STUN-discovered address fails the reachability self-test, proceed to Tier 3.

### 10.12.4 Tier 3: Relay Bridging

For deployments behind symmetric NAT (~15% of consumer internet connections), where neither UPnP nor STUN hole punching can establish direct reachability, traffic is proxied through an intermediary SCP relay acting as a transparent bridge. This is architecturally analogous to TURN (Traversal Using Relays around NAT) but uses SCP's own relay infrastructure rather than dedicated TURN servers.

**New relay operation:**

```
BRIDGE {
    target_routing_id: [u8; 32],     // Routing ID of the bridged relay
    target_relay_hint: String,        // URL hint for reaching the target
}
```

The bridge relay establishes a connection to the target self-hosted relay (which maintains an outbound connection to the bridge) and proxies blobs bidirectionally. The bridge does NOT inspect, modify, decrypt, or cache proxied blobs — it is a transparent pipe.

**Bridge establishment:**

1. The self-hosted relay behind symmetric NAT connects outbound to a bridge relay (outbound connections are not blocked by NAT).
2. The self-hosted relay registers its routing ID with the bridge via the BRIDGE operation.
3. The bridge relay accepts incoming connections from peers and forwards traffic to the registered self-hosted relay over the existing outbound connection.
4. The self-hosted relay publishes the bridge relay's address in its DID document, annotated as a bridge: `wss://bridge-relay.example.com/scp/v1?bridge_target=<hex-routing-hint>`.

**Bridge properties:**

- **Transparent.** The bridge relay sees the same metadata as any relay (§9.9.1): routing IDs, blob sizes, timing. MLS prevents content access. The bridge CANNOT read, modify, or inject messages.
- **Substitutable.** If a bridge relay goes down, the self-hosted relay discovers another bridge relay and re-registers. Peers re-resolve the DID document and connect to the new bridge. No session state is lost — MLS sessions survive relay changes.
- **Multiple bridges.** A self-hosted relay MAY register with multiple bridge relays simultaneously for availability. Each bridge is published as a separate `SCPRelay` entry in the DID document.
- **Bridge relay MAY offer this service selectively.** Configuration flag: `supports_bridge: bool`. Bridge relays MAY charge for bridge service via the relay economic configuration (§19.8).

**Honest constraint:** Tier 3 requires someone to operate a bridge relay that is itself publicly reachable. This is not Limn-specific — any SCP relay with a public address can serve as a bridge. But someone must operate one. This is the same pattern as bootstrap relays: the protocol requires no specific operator, but it requires that operators exist. The fallback relay list (§18.5.1) SHOULD include at least one relay that supports bridging.

**Performance:** Bridge proxying adds one network hop compared to direct connections. For typical relay traffic (small encrypted blobs, store-and-forward), the latency impact is negligible. For high-throughput use cases (media hosting, large file transfer), bridge deployment is suboptimal — operators in that situation should obtain a domain (Tier 4) or a VPS with a public IP.

### 10.12.5 Tier 4: Domain-Based Deployment

When an operator has a domain name, domain-based deployment provides the broadest reach: `wss://` with ACME-provisioned TLS, full web compatibility, `.well-known/scp` for HTTP discovery, and no NAT traversal required (the domain resolves to a publicly routable address or the operator has configured port forwarding).

This tier is specified in §18.6 (`ApplicationNode`), §18.6.3 (TLS Provisioning), and §18.3 (`.well-known/scp`). The protocol changes for this tier are zero — it is the existing deployment model.

**Relationship to Tiers 1-3:** When configured via `.domain()`, Tier 4 is attempted first. If it succeeds (DNS resolves, ACME provisions a certificate, the WebSocket endpoint is reachable), it becomes the active tier. If it fails — DNS is misconfigured, ACME challenge cannot complete, the port is unreachable — the SDK falls through to Tiers 1-3 automatically. This makes `.domain()` a best-effort optimization rather than a hard requirement: set it, and it works when conditions allow; when conditions change (laptop moves to a different network, home IP rotates), the zero-config tiers catch you.

Domain-based deployment is not a paid tier or a higher service level. Operators provision their own domain and DNS however they choose. A free domain from a dynamic DNS provider works the same as a custom domain on Cloudflare. The domain is a simple configuration attribute — easy to set, easy to change, easy to remove.

### 10.12.6 Transport Security for Self-Hosted Relays

TLS is required for all domain-based relay connections (§9.13). Self-hosted relays without a domain present a challenge: a laptop behind NAT with no domain cannot obtain a CA-signed TLS certificate, and self-signed certificates provide no trust benefit over plaintext (no trust anchor for the connecting peer to verify against).

**Key decision: `ws://` (plaintext WebSocket) is permitted for self-hosted relays discovered via DHT.**

| Relay type | Discovery path | Transport | TLS required |
|-----------|---------------|-----------|-------------|
| Domain-based | `.well-known/scp` or explicit URL | `wss://` | Yes (§9.13) |
| Self-hosted, no domain | DHT-resolved DID document | `ws://` permitted | No |
| Self-hosted, with domain | Either | `wss://` | Yes |

**Rationale.** TLS serves two purposes: confidentiality and server authentication.

1. **Confidentiality** is already provided by MLS. Every blob delivered through a relay is MLS-encrypted before it reaches the transport layer (§10.5). TLS on the relay connection protects already-encrypted traffic — defense in depth, not the confidentiality boundary. Removing TLS from a self-hosted relay connection does not expose message content. The confidentiality guarantee is MLS, not TLS.

2. **Server authentication** via TLS requires a domain name and a CA-signed certificate. A relay identified only by IP address behind NAT has no domain and cannot complete ACME challenges. Self-signed certificates provide no authentication benefit — any attacker can generate one. The DID document itself is the authentication mechanism: it is BEP44-signed (§9.6.1), self-certifying against the DID's public key, and published to the DHT with a monotonic sequence number. The relay URL in the DID document IS the authenticated relay address — the trust anchor is the DID document signature, not a TLS certificate.

**Enforcement constraint:** The SDK MUST reject `ws://` relay URLs obtained from `.well-known/scp` or any non-DHT discovery source. Only relay URLs resolved from a BEP44-signed DID document (self-certifying path) may use `ws://`. This prevents downgrade attacks where an attacker substitutes `ws://` URLs in HTTP-based discovery (which lacks the self-certifying property of BEP44).

**Metadata tradeoff.** Without TLS, network intermediaries (ISPs, network operators) can observe the same metadata that any relay operator already sees (§9.9.1): connection timing, blob sizes, routing IDs. They cannot read MLS-encrypted content. This is an accepted tradeoff for the zero-config floor. The metadata exposure is not new — it is the same exposure the relay operator has. TLS merely prevents intermediaries other than the relay from seeing it.

Operators concerned about metadata exposure to network intermediaries can:

- Add a domain and use `wss://` (Tier 4).
- Route relay traffic through a VPN or Tor.
- Use a bridge relay with `wss://` (Tier 3 always uses `wss://` because the bridge relay has a domain).

### 10.12.7 DID Document Relay URL Encoding

Each reachability tier produces a different relay URL format for the DID document's `SCPRelay` service endpoints (§18.2.1):

| Tier | URL format | Example |
|------|-----------|---------|
| 1 (UPnP) | `ws://` with IP literal | `ws://203.0.113.42:8443/scp/v1` |
| 2 (STUN) | `ws://` with IP literal | `ws://198.51.100.7:32891/scp/v1` |
| 3 (Bridge) | `wss://` with bridge domain | `wss://bridge.example.com/scp/v1?bridge_target=<hex-routing-hint>` |
| 4 (Domain) | `wss://` with operator domain | `wss://relay.example.com/scp/v1` |

Tiers 1 and 2 use `ws://` with raw IP addresses — these are the zero-config, no-domain tiers where TLS is not available (§10.12.6). Tier 3 uses `wss://` because the bridge relay itself has a domain and TLS. Tier 4 uses `wss://` with the operator's domain.

**Address change handling.** Residential IP addresses change (ISP DHCP lease renewal, router reboot). UPnP port mappings may be reassigned. STUN-discovered addresses shift when NAT mappings expire and reform. The `RepublishManager` handles address changes by:

1. Detecting the change (periodic STUN re-probe, UPnP lease renewal response, network interface change event).
2. Incrementing the DID document sequence number.
3. Republishing the DID document with the new relay URL to both the DHT and SCP relays (§3.10.5 when specified, otherwise DHT-only).

Peers that fail to connect to a stale relay address re-resolve the DID document immediately. Multi-relay publishing (§18.7) provides availability during address transitions — if the self-hosted relay publishes to external relays in addition to advertising its own address, messages accumulate on external relays while the self-hosted relay's address updates propagate.

### 10.12.8 ApplicationNode Integration

`ApplicationNodeBuilder` (§18.6.2) gains additional methods for zero-config deployment:

```rust
impl ApplicationNodeBuilder {
    /// Zero-config NAT-traversed mode. No domain, no TLS, no .well-known/scp.
    /// Probes NAT, attempts Tiers 1-3, publishes ws:// relay URL in DID document.
    pub fn no_domain(mut self) -> Self;

    /// Override the STUN endpoint used for NAT type probing.
    /// Default: bootstrap relay with STUN support.
    pub fn stun_server(mut self, url: &str) -> Self;

    /// Override the bridge relay used for Tier 3 fallback.
    /// Default: first bridge-capable relay in the fallback relay list.
    pub fn bridge_relay(mut self, url: &str) -> Self;
}
```

**Behavior when `.no_domain()` is set:**

1. Skip ACME TLS provisioning entirely.
2. Probe NAT type via STUN binding request.
3. Attempt Tier 1 (UPnP/NAT-PMP port mapping).
4. If Tier 1 fails and NAT is non-symmetric, attempt Tier 2 (STUN hole punching).
5. If Tier 2 fails or NAT is symmetric, register with a bridge relay (Tier 3).
6. Publish DID document with `ws://` relay URL (Tiers 1-2) or `wss://` bridge URL (Tier 3).
7. Do NOT serve `.well-known/scp` — there is no domain to serve it from. Discovery is DHT-only.

**Behavior when `.domain()` is set:**

1. Attempt domain-based deployment first: ACME TLS provisioning, `wss://` WebSocket endpoint, `.well-known/scp` generation.
2. Verify DNS resolves correctly and the ACME challenge completes.
3. If domain-based deployment succeeds, use Tier 4. Serve `.well-known/scp`. Publish `wss://` relay URL in DID document.
4. If domain-based deployment fails (DNS misconfigured, ACME challenge fails, port 80/443 unreachable), log the failure and fall through to `.no_domain()` behavior (steps 1-7 above).
5. The SDK re-attempts domain-based deployment periodically (recommended: every 30 minutes) in case conditions change (DNS propagation completes, port becomes reachable).

**Behavior when neither `.domain()` nor `.no_domain()` is set:**

The builder requires one of the two. Calling `.build()` without either returns an error. This forces the operator to make an explicit choice about their deployment model, even though the choice between them is simple: "Do you have a domain? `.domain()`. No? `.no_domain()`."

### 10.12.9 Threat Model

The reachability tiers introduce attack surfaces beyond the standard relay threat model (§9.9). This section catalogs them.

**UPnP mapping hijack.** A malicious device on the local network deletes or modifies the relay's UPnP port mapping. Impact: availability only — the relay becomes unreachable. MLS prevents any confidentiality or integrity impact. Mitigation: the SDK verifies the mapping periodically (at 50% TTL) and detects loss. On loss, the SDK re-attempts the mapping and, if that fails, falls through to Tier 2. A persistent attacker on the LAN can deny Tier 1 indefinitely, but cannot prevent fallthrough to other tiers.

**STUN server manipulation.** A malicious or compromised STUN server reports an incorrect external address to the self-hosted relay. Impact: availability — peers attempt to connect to the wrong address. Cannot affect confidentiality (MLS) or integrity (DID document is self-certifying). Mitigation: the SDK validates the STUN-reported address by performing a reachability self-test (connecting to its own reported address via an intermediary). If the self-test fails, the STUN result is discarded. Additionally, the SDK SHOULD probe multiple STUN servers and compare results — divergence indicates manipulation.

**Bridge relay as man-in-the-middle.** A bridge relay has the same position as any SCP relay — it sees routing IDs, blob sizes, and timing (§9.9.1). It CANNOT read MLS-encrypted content, forge messages, modify blobs, or inject members into contexts. It CAN perform suppression, delay, and replay — the same attacks any relay can mount. The same mitigations apply: multi-relay cross-check (§9.9.2), sequence gap detection, equivocation detection (§9.9.3), and Commit suppression detection (§9.9.4). Bridge relays are substitutable — switching bridges requires only a DID document update, not a session renegotiation.

**Network metadata exposure without TLS.** For Tiers 1 and 2, relay traffic uses `ws://` (plaintext WebSocket). Network intermediaries (ISPs, network operators on the path) can observe the same metadata that the relay operator sees (§9.9.1): connection timing, blob sizes, routing IDs. They cannot read MLS-encrypted blob content. This is the same metadata exposure as the relay operator has — TLS merely prevents intermediaries other than the relay from seeing it. Accepted tradeoff for zero-config deployment (§10.12.6).

**Residential IP exposure in DID document.** Tiers 1 and 2 publish the operator's residential IP address in the DHT-stored DID document. Anyone who resolves the DID learns the operator's IP. This is inherent to self-hosting without a domain — the relay must be reachable, and reachability requires a public address. Tier 3 (bridge) exposes only the bridge relay's address, not the operator's. Privacy-conscious operators who do not want to expose their residential IP have three options:

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
| `ws://` transport for DHT-discovered relays | Phase 2 | `scp-transport` | Enforcement: reject `ws://` from non-DHT sources |
| Relay bridging (BRIDGE operation) | Phase 3 | `scp-transport` | New wire operation, bridge registration protocol |
| STUN service on SCP relays | Phase 3 | `scp-transport` | Coexists with WebSocket endpoint |

Phase 2 delivers the zero-config floor: a self-hosted relay behind most consumer NATs becomes reachable without any manual configuration. Phase 3 closes the remaining ~15% (symmetric NAT) with bridge relaying and adds STUN service to the relay fleet, making the network self-reinforcing. Domain-based deployment (Tier 4) is already specified in Phase 2 via §18.6.

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
2. **0-RTT resumption.** Resumed QUIC sessions use 0-RTT to send application data immediately without waiting for the handshake to complete, eliminating round-trip latency on reconnection. Session tickets are stored locally and rotated per the QUIC specification. 0-RTT data has no replay protection (RFC 9001 §9.2); SCP operations sent as 0-RTT MUST be idempotent or the relay MUST implement anti-replay measures.
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

**Distinction from QUIC.** WebTransport is mediated by the browser's network stack. The SCP WASM binding uses the `WebTransport` API. Non-browser clients use QUIC directly (§10.14). Server-side, the relay handles both — QUIC connections and WebTransport sessions are both QUIC underneath, sharing the same subscription registry and blob storage.

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

The fallback is transparent to `TransportAdapter` callers. The WASM binding wraps both transports behind the same adapter interface. The WASM binding MAY switch from WebSocket to WebTransport mid-session if the relay advertises WebTransport support via `Alt-Svc`. This involves establishing a new WebTransport session and re-opening subscription streams (same gap-fill strategy as reconnection), not an in-place protocol upgrade.

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
