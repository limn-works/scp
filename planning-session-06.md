# SCP Planning Session 06 — Design Review and Architectural Corrections

**Date:** February 22, 2026
**Scope:** Review of PR #1 (architecture branch). Corrections to blocking mechanism, DID method ordering, transport independence, provenance elevation, cross-context tool call governance, ephemeral deletion, metadata privacy, A2A reconsideration, infrastructure independence.
**Artifacts modified:** `spec.md`, `sketch.md`, `architecture.md` (changes committed to architecture branch). `open-questions.md` (new file).

---

## How This Session Started

Full review of PR #1 ("Arch thought process") which added architecture.md, planning sessions 03–05, and major updates to spec.md and sketch.md. The review identified several architectural corrections needed, elevated provenance to a core principle, and surfaced 10 open questions requiring decisions before implementation can begin.

---

## 1. Decisions Made (Closed)

### 1.1 Blocking Is Not Group Removal

**Problem:** The PR conflated blocking with MLS group removal. MLS epoch advancement excludes the blocked party from ALL future messages from ALL members — but blocking is a unilateral, per-relationship action. Alice blocking Dave should affect only Alice↔Dave visibility, not Dave's relationship with other context members.

**Decision:** Blocking uses a **sender-side key layer** separate from MLS group membership.

- Each sender maintains a symmetric AES-256 key alongside their MLS leaf key
- Messages are double-encrypted: sender key first, then MLS
- Blocking = rotate sender key, redistribute to all members except blocked party
- Blocked party can decrypt the MLS layer but gets opaque ciphertext from the blocker
- MLS group membership is unchanged — blocked party remains in the context
- This is architecturally distinct from member removal (MLS Remove Commit + epoch advancement)

**Updated:** spec.md §3.6, §10.5

### 1.2 did:dht First, did:web Fallback Only

**Problem:** The PR positioned did:web as the v1 method with migration to did:dht later. This creates throwaway work (TOFU infrastructure, TLS pinning, key-change alerting, migration path), adds a server dependency (contradicts infrastructure-minimal design), and ships into a planned migration.

**Decision:** did:dht is the primary and first implementation. did:web exists as a contingency fallback if did:dht libraries prove unusable. No migration path is built. No stepping stone.

**Rationale:** did:dht libraries exist in Rust. The risk of library issues is medium but the mitigation (fall back to did:web) is available without building it upfront. Starting with did:dht avoids building infrastructure (did:web resolution server) that the protocol doesn't need.

**Updated:** spec.md §3.8, §9.6.2, §9.13. architecture.md §3.2, §8, §9, §10. sketch.md §15.

### 1.3 Provenance Is a Core Principle

**Problem:** The PR introduced provenance as a feature of cross-context data flow (§7.7). Provenance should be foundational — a property of every protocol action, not a feature of one mechanism.

**Decision:** Provenance is core principle #3 (alongside identity, isolation, encryption, legibility, accountability). All non-private data in SCP carries verifiable origin metadata. Every message traces to sender + context + timestamp. Every attestation traces to issuer + evidence. Every tool output traces to tool + invoker + context. Every cross-context data transfer carries origin provenance. The absence of provenance is itself a signal.

**Rationale:** Provenance is not about cross-context data flow — it's about accountability and verifiability throughout the protocol. It strengthens Sybil detection (correlated provenance patterns), governance enforcement (traceable actions), and trust evaluation (verifiable claims).

**Updated:** spec.md §1 (new Core Principles section), §7.6, §7.7.

### 1.4 Context Governs Tool Calls, Not Agents

**Problem:** §6.2 (cross-context tool interfaces) described tool calls as "stateless, structured interfaces" without making explicit that the context — not the agent — governs the interaction. The distinction matters because it determines whether inter-agent interaction is context-governed (stronger) or agent-governed (weaker).

**Decision:** §6.2 now explicitly states: "The context governs the tool call, not the agent." The flow is:
1. Agent in Context A requests an outbound tool call
2. Context A's governance decides whether to permit it
3. Context B's governance decides whether to permit the inbound call and how to respond
4. Both contexts log the interaction with full provenance

Additionally, tool interfaces now support **stateful sessions** (§6.2.1) — a session ID enables multi-turn workflows within the governed tool call framework. State is maintained by the tool's context, not by the calling agent. Each call in the session is individually governed. Sessions have a TTL.

Discovery is achievable via tool interfaces (§6.2.2) — registry contexts expose search tools that other contexts can invoke through the standard tool call mechanism.

**Rationale:** This is strictly stronger governance than A2A propose/accept because both contexts mediate every interaction. It also addresses the "multi-turn gap" that was the main argument for A2A contexts. Stateful sessions with context governance cover scheduling, negotiation, and coordination without creating agent-governed channels.

**Updated:** spec.md §6.2 (rewritten), new §6.2.1 (Stateful Tool Sessions), new §6.2.2 (Discovery via Tool Interfaces).

### 1.5 Ephemeral Contexts: Delete Ciphertext + Destroy Keys

**Problem:** The PR's ephemeral memory scope only destroyed encryption keys, leaving encrypted blobs on relays as unreadable garbage. This wastes relay storage and is an unnecessary data retention.

**Decision:** Ephemeral context closure includes relay deletion requests for all encrypted event data. Keys are destroyed AND ciphertext deletion is requested.

- Relay deletion is best-effort (relays are untrusted, can't be forced)
- Defense in depth: even if relay retains blobs, keys are destroyed, data unreadable
- Relay compliance with deletion requests is tracked via relay reliability scoring
- Relays that retain data they were asked to delete are scored lower and deprioritized

**Updated:** spec.md §5.11.

### 1.6 Transport Independence — No Single-Transport Dependency

**Problem:** The PR positioned Nostr as the "primary transport" with detailed Nostr-specific event kinds, NIPs, and adapter code. This creates structural coupling to one transport.

**Decision:** SCP defines its own native relay protocol as the canonical reference. The native relay is the simplest possible store-and-forward mechanism purpose-built for SCP envelopes. All other transports are adapters behind the transport abstraction trait. No transport is "primary" — the protocol functions correctly on any transport that implements the abstraction.

**Exhaustive adapter list:**
- SCP native relay (canonical)
- Nostr
- Matrix
- Holepunch / Hyperswarm
- Hypercore / Hyperbeam
- libp2p
- WebSocket (direct)
- WebRTC
- QUIC
- Bluetooth / BLE
- Tor hidden services
- I2P
- SSB (Secure Scuttlebutt)
- MQTT
- NATS
- ZeroMQ
- Yggdrasil
- cjdns

**Updated:** spec.md §10.5. architecture.md §2.1, §3.1, §8, §9, §10.

### 1.7 The Protocol Requires No Operator

**Problem:** architecture.md §8 had a "What We Run" table listing infrastructure Limn operates. This implies the protocol depends on Limn running things.

**Decision:** The protocol is designed so that no entity — including Limn — needs to run infrastructure for it to function. If Limn disappeared tomorrow, SCP must work exactly as designed. Limn may choose to operate infrastructure for ecosystem bootstrapping, but the protocol cannot depend on this.

Every protocol mechanism must pass the test: "does this work if no one runs centralized infrastructure?"

**Updated:** architecture.md §8 (rewritten — "What We Run" replaced with "Design Principle: The Protocol Requires No Operator").

---

## 2. A2A Propose/Accept — Under Serious Reconsideration

The PR introduced propose/accept context creation (§5.12) for agent-to-agent communication. During review, this was challenged on several grounds:

1. **Cross-context tool calls with stateful sessions handle all governed inter-agent interaction** where both parties share a context. The "multi-turn gap" is closed by §6.2.1.

2. **The remaining unique capability (reaching strangers) is the attack surface.** Propose/accept allows agents to contact agents they share no context with. This is exactly the kind of cross-boundary communication that isolation was designed to prevent. The governance mechanisms (earned capacity, trust evaluation, provenance) are mitigations, not prevention.

3. **Context creation is free — it sounds like the original attack vector coming back.** If agents can create contexts to communicate, the isolation boundary is permeable. A sophisticated attacker who builds behavioral history can use this channel for brigading.

4. **The Moltbook argument has weaknesses.** SCP can't prevent ungoverned communication (agents can use HTTP, Moltbook, anything above the protocol boundary). Adding governed A2A doesn't prevent ungoverned A2A — it just provides an alternative. SCP's value is that interactions inside the protocol are trustworthy. This is a clean boundary that propose/accept blurs.

**Current leaning:** Remove propose/accept entirely. Rely on cross-context tool calls for all inter-agent interaction. Agents that need to form new relationships require human facilitation through shared contexts. This is simpler, more secure, and the original design was right.

**Status:** Open question #4 in open-questions.md. Requires final decision.

---

## 3. Metadata Privacy — No Deferral

The PR deferred metadata privacy to "future versions." This was rejected. Everything gets specced and implemented.

10 metadata privacy decisions were identified, analyzed, and given concrete suggestions in open-questions.md:

1. **Push notification opacity** — Fully opaque, mandate it
2. **Envelope format metadata** — Minimal outer envelope (routing pseudonym + blob TTL + encrypted blob)
3. **Message size normalization** — Fixed bucket padding (256B/1KB/4KB/16KB/64KB/256KB)
4. **A2A propose/accept** — Remove entirely (see §2 above)
5. **Sender-side blocking design** — AES-256 symmetric, MLS-distributed, sender-first encryption
6. **Connection privacy** — Tor hidden services for relays + persistent connections on desktop
7. **Per-context pseudonyms** — HKDF-derived, inside-encryption verification
8. **Cover traffic** — Constant-rate on persistent connections, not applicable on mobile
9. **DID resolution privacy** — Local DHT node on persistent devices, Tor-routed on mobile
10. **Relay query privacy** — Pseudonyms + relay set partitioning + subscription mixing

These suggestions form a coherent metadata privacy architecture. See open-questions.md for full analysis of each.

---

## 4. What Changed in the Codebase

### Files Modified (on architecture branch):

**spec.md:**
- Added Core Principles section to §1 (identity, isolation, provenance, encryption, legibility, accountability)
- §3.6: Blocking rewritten — sender-side key layer, not MLS removal
- §3.8: did:web reframed as fallback only
- §5.11: Ephemeral scope includes relay deletion requests
- §6.2: Rewritten — context governs tool calls, not agents
- §6.2.1: New — Stateful Tool Sessions
- §6.2.2: New — Discovery via Tool Interfaces
- §7.6: Provenance referenced as core principle
- §7.7: Provenance reframed as implementing core principle, not introducing new concept
- §9.6.2: did:web as fallback, not stepping stone
- §9.13: Certificate pinning language updated for did:web fallback
- §10.5: Transport section rewritten — SCP native relay canonical, exhaustive adapter list, transport independence

**architecture.md:**
- §2.1: Transport adapters in system diagram updated (SCP native + expanded list)
- §3.1: Crate structure updated (scp-transport/ expanded with native, hyperswarm, libp2p, webrtc)
- §3.2: Identity Manager — did:dht primary, did:web fallback
- §8: Completely rewritten — "Protocol Requires No Operator" principle
- §9: Risk table updated (transport adapter availability, did:dht risk reframed)
- §10: Decision summary updated (DID method, transport, infrastructure)

**sketch.md:**
- §15: DID method resolution note updated

### Files Created:

**open-questions.md:** 10 open questions with detailed analysis, options, tradeoffs, and concrete suggestions. Dependency graph and recommended decision order.

---

## 5. What This Session Did Not Resolve

- **A2A propose/accept: keep or remove.** Leaning remove. Needs final decision.
- **All 10 metadata privacy decisions.** Suggestions exist but need confirmation.
- **Sender-side key layer detailed spec.** Direction agreed, full protocol specification needed.
- **SCP native relay protocol specification.** Decided it should exist, not yet designed.
- **Stateful tool session protocol details.** §6.2.1 captures the concept; wire format and session lifecycle need specification.
- **Specific changes needed if A2A is removed.** §5.12, §6.4, A2A threat analysis in §9, planning-session-03.md content, sketch.md proposal APIs, architecture.md A2A references — all need cleanup.

---

## 6. Relationship to Prior Sessions

### Planning Session 03 (A2A)
The A2A architecture designed in session 03 is under reconsideration. The context extensions (TTL, memory scope) remain valuable regardless. Provenance tagging was elevated from A2A-specific to protocol-wide. If A2A is removed, the propose/accept flow, registries, and referral chains from session 03 are removed, but TTL, memory scope, and provenance remain.

### Planning Session 04 (Technical Implementation)
Technology selections (MLS, did:dht, UCAN, Rust core) are confirmed. Transport binding approach is corrected — session 04 positioned Nostr as primary; this session corrects to SCP native relay + transport independence. The adapter architecture remains valid but with expanded adapter list.

### Planning Session 05 (Security Hardening)
The cryptographic security model from session 05 is confirmed with one addition: the sender-side key layer for blocking. The envelope signature scope (§9.5) may need adjustment based on the minimal outer envelope decision (open question #2). The relay threat model (§9.9) is strengthened by metadata privacy decisions.
