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
- Transport adapter implementations for existing infrastructure (Nostr, Matrix, Holepunch/Hyperswarm, libp2p, WebSocket, WebRTC, QUIC, BLE, Tor, I2P, SSB, MQTT, NATS, ZeroMQ, Yggdrasil, cjdns)

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
