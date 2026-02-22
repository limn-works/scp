# SCP Status Audit — From Spec to Implementation

**Date:** February 22, 2026
**Purpose:** Classify every feature/mechanism in the spec as ready, needs cleanup, or blocked. Identify missing specifications.
**Source material:** spec.md, sketch.md, architecture.md, planning-session-06.md, open-questions.md

---

## A. Closed Decisions

### Ready for ADR and Implementation

These designs are settled. No open questions block them.

| Area | Section | Status | Notes |
|------|---------|--------|-------|
| **Identity — DID creation** | spec §3.1, §3.8, §9.6.1 | Ready | did:dht primary, did:web fallback only. Self-certifying. Decided in session 06 §1.2. |
| **Identity — Key custody** | spec §3.2 | Ready | Secure Enclave / Keystore / Passkey / self-managed. Abstracted behind platform adapter. |
| **Identity — Recovery** | spec §3.3 | Ready | Trusted device, social recovery, platform-backed. No seed phrases. |
| **Identity — Linking** | spec §3.4 | Ready | Optional convenience links to platform accounts. |
| **Identity — Attestations** | spec §3.5, §7.4 | Ready | Common envelope format, multiple types, revocable, renewable. |
| **Identity — Private state** | spec §3.7 | Ready | Encrypted append-only log, synced across devices. Block/mute lists, preferences. |
| **Identity — Key continuity** | spec §9.11 | Ready | Signal-style safety numbers. TOFU + out-of-band verification. |
| **Identity — Compromise recovery** | spec §9.12 | Ready | 6-step ordered protocol: key rotation, MLS Update, UCAN revocation, KeyPackage rotation, notification, re-encryption. |
| **Agents — Core model** | spec §4.1–§4.8 | Ready | One per human per context, bound to DID, bring-your-own, context-bound. |
| **Agents — Capability metadata** | spec §4.4 | Ready | Self-attested vs challenge-verified. |
| **Agents — Human-agent pair** | spec §4.5 | Ready | Fundamental unit of participation. |
| **Contexts — Creation** | spec §5.1–§5.2 | Ready | By accountable identities only. |
| **Contexts — Capability ceiling** | spec §5.3 | Ready | Open question on mutability noted but not blocking — implement as immutable first (stronger security). |
| **Contexts — Tools** | spec §5.4 | Ready | Stateless, schema'd, testable, operator-attributed. MCP-compatible JSON Schema. |
| **Contexts — Roles** | spec §5.5 | Ready | Visible before opt-in, non-negotiable, custom roles supported. |
| **Contexts — Membership** | spec §5.6 | Ready | One agent per human per context. |
| **Contexts — Metadata** | spec §5.7 | Ready | Full legibility before opt-in. |
| **Contexts — TTL** | spec §5.10 | Ready | Set at creation, extension requires all-party consent, hard upper bound. |
| **Contexts — Memory scope** | spec §5.11 | Ready | Ephemeral (destroy keys + delete ciphertext), summary, full. Decided in session 06 §1.5. |
| **Cross-context — Agent isolation** | spec §6.1 | Ready | Absolute at protocol level. |
| **Cross-context — Tool interfaces** | spec §6.2 | Ready | Context governs, not agents. Bidirectional consent. Decided in session 06 §1.4. |
| **Cross-context — Discovery via tools** | spec §6.2.2 | Ready | Registry contexts expose search tools through standard tool call mechanism. |
| **Cross-context — Human as bridge** | spec §6.3 | Ready | Local coordination, no network mechanism needed. |
| **Trust — Four-layer model** | spec §7.1 | Ready | Protocol enforcement → behavioral validation → attestation authenticity → trust evaluation. |
| **Trust — Protocol enforcement (L1)** | spec §7.2 | Ready | UCAN validation on every action. Zero-trust. |
| **Trust — Behavioral validation (L2)** | spec §7.3 | Ready | Event logs, behavioral records, tool verification, challenge-response, threshold attestations, consequence mechanisms. |
| **Trust — Attestation authenticity (L3)** | spec §7.4 | Ready | Common envelope, signature verification, revocation, renewal. |
| **Trust — Trust evaluation (L4)** | spec §7.5 | Ready | Agent-level judgment. Transitive trust. Decay. |
| **Trust — Provenance** | spec §7.6–§7.7 | Ready | Core principle #3. Format specified. Absence is signal. Decided in session 06 §1.3. |
| **Products — App model** | spec §8.1–§8.3 | Ready | Apps are composites, not protocol entities. Portability via protocol state. |
| **Products — Capability declarations** | spec §8.4 | Ready | Machine-readable manifests. Declarative. |
| **Products — MCP compatibility** | spec §8.5 | Ready | SCP agent as MCP server. Tool schemas MCP-compatible. |
| **Security — Core invariants** | spec §9.1 | Ready | 7 invariants defined. |
| **Security — Sybil resistance** | spec §9.3 | Ready | Device attestation + earned capacity + context-level thresholds. |
| **Security — Systemic defense** | spec §9.4 | Ready | Validate > trust. Behavior topology. Consequences > character. |
| **Security — Crypto primitives** | spec §9.5 | Ready | Single ciphersuite. Ed25519, MLS_128, HPKE, SHA-256. |
| **Security — Identity verification** | spec §9.6 | Ready | did:dht self-certification, did:web mitigations, relay list auth, first-contact bootstrapping. |
| **Security — MLS integration** | spec §9.7 | Ready | 1:1 context↔group mapping. Forward secrecy. PCS (24h default). Key lifecycle. |
| **Security — Message security** | spec §9.8 | Ready | Two integrity checks (outer Ed25519 + inner MLS membership_tag). Three-layer replay prevention. Sequence validation. |
| **Security — Relay threat model** | spec §9.9 | Ready | CAN/CANNOT list. Suppression detection. Equivocation detection (Relay Consistency Protocol). |
| **Security — Clock model** | spec §9.14 | Ready | 5-min skew tolerance. Merkle log order authoritative. |
| **Security — Key destruction** | spec §9.15 | Ready | Platform-attested where available. Honest about limitations. |
| **Security — Transport security** | spec §9.13 | Ready | TLS 1.3 mandatory. Certificate pinning supported. |
| **Infrastructure — Philosophy** | spec §10.1 | Ready | No operator owns identity/relationships/graph. |
| **Infrastructure — Device-as-node** | spec §10.2 | Ready | Full spectrum from phone to managed infra. Agent workstation tier. |
| **Infrastructure — Minimal state** | spec §10.3 | Ready | Protocol state is small. Content storage is app-layer. |
| **Infrastructure — Relay architecture** | spec §10.4 | Ready | Protocol-unaware, substitutable, untrusted for content. |
| **Infrastructure — Transport abstraction** | spec §10.5 | Ready | SCP native relay canonical. No single-transport dependency. 17 adapters listed. Decided in session 06 §1.6. |
| **Infrastructure — Encryption as access** | spec §10.5 | Ready | MLS group key = access credential. Relays are dumb pipes. |
| **Infrastructure — Content sovereignty** | spec §10.6 | Ready | Agnostic. App-layer decision. |
| **Infrastructure — Multi-device** | spec §10.8 | Ready | Building blocks provided (private state, context state, relay envelopes). Client-scope concerns. |
| **Infrastructure — Real-time/async** | spec §10.9 | Ready | Both first-class. Transport-dependent latency. |
| **Bridges — Bridge connectors** | spec §12.2 | Ready | Protocol entity with operator DID. Registered per context. |
| **Bridges — Shadow identities** | spec §12.3 | Ready | Attributed, restricted, marked, claimable. |
| **Bridges — Operating modes** | spec §12.4 | Ready | Relay, puppet, API, cooperative. |
| **Bridges — Content provenance** | spec §12.5 | Ready | Trust hierarchy with identity × transport axes. |

### Closed — Needs Spec Cleanup

Design is settled, but spec text needs updating based on session 06 decisions.

| Area | Section | Cleanup Needed |
|------|---------|----------------|
| **Social graph — A2A visibility** | spec §3.6 | Remove A2A activity visibility paragraph if A2A removed (#4). |
| **Contexts — Propose/accept** | spec §5.12 | Remove entirely if A2A removed (#4). |
| **Cross-context — A2A isolation** | spec §6.1 | Remove A2A isolation paragraph if A2A removed (#4). |
| **Cross-context — Human as bridge** | spec §6.3 | Remove propose/accept reference, revert to original framing if A2A removed. |
| **Cross-context — Agent discovery** | spec §6.4 | Remove registries (§6.4.2), referrals (§6.4.3), keep context-mediated (§6.4.1) as tool-interface-only if A2A removed. |
| **Security — A2A threats** | spec §9.2 | Remove prompt injection via proposals, Sybil flooding, memory-based attacks, discovery manipulation if A2A removed. |
| **Security — Metadata privacy** | spec §9.10.5 | Currently says "out of scope for v1" — contradicts session 06 "no deferral." Must be rewritten once metadata privacy decisions (#1-3, #6-10) are confirmed. |
| **Envelope signature scope** | spec §9.5 | Currently includes context_id and sender_did in outer signature. Must update for minimal outer envelope (#2) and per-context pseudonyms (#7). |
| **Architecture — MVSDK** | architecture.md §5 | Lists did:web and Nostr as v1 targets, A2A as "v1.1." Must update: did:dht, SCP native relay, no A2A. |
| **Architecture — Build phases** | architecture.md §6 | Phase 1 references Nostr, Phase 4 references A2A, Phase 6 references "did:dht migration." All need updating. |
| **Architecture — Data flows** | architecture.md §2.2–2.3 | §2.2 references Nostr relay/events. §2.3 is A2A proposal flow — remove if A2A removed. |
| **Architecture — Discovery Engine** | architecture.md §3.2 | References registries, referrals, introduction tokens. Simplify if A2A removed. |
| **Architecture — Crate structure** | architecture.md §3.1 | References updated in session 06 but may still have stale A2A references. |
| **Sketch — Propose/accept APIs** | sketch.md §2 | Remove propose/accept/reject/listProposals if A2A removed. |
| **Sketch — Context proposal envelope** | sketch.md §11 | Remove context_proposal wire format if A2A removed. |
| **Sketch — Introduction token** | sketch.md §11 | Remove introduction token wire format if A2A removed. |
| **Sketch — A2A use cases** | sketch.md §14 | Remove entirely if A2A removed. |
| **Sketch — Agent discovery** | sketch.md §12 | Keep context-mediated. Remove registry and referral APIs if A2A removed. |
| **Sketch — What's Not Here Yet** | sketch.md §15 | Update to reflect current state. Several items resolved. |

---

## B. Open Questions (Need Decisions)

All 10 from open-questions.md. Each has a concrete suggestion. Listed in recommended decision order.

### Independent decisions (no dependencies)

| # | Question | Suggestion | Blocked Sections | Dependencies |
|---|----------|------------|-----------------|--------------|
| **1** | Push notification opacity | Fully opaque, mandate it | spec §10.7 | None |
| **4** | A2A propose/accept | Remove entirely | spec §5.12, §6.1, §6.3, §6.4, §9.2; sketch §2, §11, §12, §14; architecture §2.3, §3.2, §5, §6 | None (highest architectural impact) |
| **5** | Sender-side key layer design | AES-256 symmetric, MLS-distributed, sender-first encryption, protocol-notified mutual block | spec §3.6, §10.5 (needs new §9.16) | None |

### Dependent decisions (must follow order)

| # | Question | Suggestion | Blocked Sections | Depends On |
|---|----------|------------|-----------------|------------|
| **2** | Envelope format metadata | Minimal outer envelope (routing pseudonym + blob TTL + encrypted blob) | spec §9.5 (signature scope), §9.10; sketch §11 (wire format) | None, but pairs with #7 |
| **7** | Per-context pseudonyms | Yes, HKDF-derived, inside-encryption verification | spec §9.10, §10.5 (envelope format) | #2 |
| **3** | Message size normalization | Fixed bucket padding (256B/1KB/4KB/16KB/64KB/256KB) | spec §9.10 | None, but pairs with #8 |
| **6** | Connection privacy | Tor hidden services for relays + persistent connections | spec §9.10 | None, but relates to #9 |
| **8** | Cover traffic | Mandatory on persistent connections, not on push-wake | spec §9.10 | Pairs with #3 |
| **9** | DID resolution privacy | Local DHT node on persistent devices, Tor on mobile | spec §9.10 | Relates to #6 |
| **10** | Relay query privacy | Pseudonyms + relay set partitioning + subscription mixing | spec §9.10 | #7 |

### Inter-question dependencies

```
#2 (Envelope opacity) → #7 (Pseudonyms) → #10 (Relay query privacy)
#6 (Connection privacy) → #9 (DID resolution privacy)
#3 (Message size) + #8 (Cover traffic) → combined traffic analysis defense
#4 (A2A) independent but highest architectural impact
#5 (Sender-side blocking) independent
#1 (Push opacity) independent
```

---

## C. Missing Specifications

Designs that have been decided directionally but need full protocol-level specification before implementation.

### Critical Path (blocks Phase 1)

| Missing Spec | Status | Decided? | What's Needed |
|-------------|--------|----------|---------------|
| **SCP native relay protocol** | Not designed | Direction decided (session 06 §1.6) | Full protocol spec: message format, subscription mechanism, delivery receipts, deletion requests, blob TTL, authentication (if any), error codes. The simplest possible store-and-forward relay. |
| **Sender-side key layer protocol** | Partially designed | Direction decided (session 06 §1.1), detailed in OQ #5 | Full spec as §9.16: key generation, distribution via MLS, encryption order, mutual block notification, key rotation on block, storage requirements, forward secrecy interaction. Blocked by OQ #5 confirmation. |
| **Envelope format** | Partially designed | Outer envelope described in spec §9.5, sketch §11 | Must be redesigned for minimal outer envelope (OQ #2), per-context pseudonyms (OQ #7), blob TTL. Inner format mostly specified. |
| **Transport abstraction trait** | Conceptual | Transport independence decided | Formal Rust trait definition: 5-6 methods (send, subscribe, unsubscribe, query, delete). Error types. Async interface. Connection lifecycle. |

### Critical Path (blocks Phase 2)

| Missing Spec | Status | Decided? | What's Needed |
|-------------|--------|----------|---------------|
| **Context lifecycle state machine** | Conceptual | Core concepts decided | Formal state machine: states (creating, active, closing, closed, expired), transitions, events that trigger each transition, invariants at each state. |
| **Event log format** | Conceptual | Merkle tree decided (spec §7.3.1, §9.5) | Concrete format: event entry structure, hash chain construction, proof format, checkpoint format, pruning rules, storage requirements. |
| **UCAN capability schema** | Partially specified | UCAN selected (planning-session-04) | Concrete capability types (scp:ctx:{id}/messages, scp:ctx:{id}/tools/{name}, etc.), delegation chain rules, revocation list format, nonce generation. |
| **Stateful tool session protocol** | Conceptual | Concept in spec §6.2.1 | Session ID format, session state management, TTL enforcement, session-scoped governance, wire format for session calls. |

### Important but not blocking early phases

| Missing Spec | Status | Decided? | What's Needed |
|-------------|--------|----------|---------------|
| **Behavioral record schema** | Conceptual | Record types listed in spec §7.3.2 | Formal schema: field names, types, derivation rules, aggregation across contexts, privacy (what's public vs what requires capability). |
| **Offline/sync strategy** | Flagged as "hardest unsolved problem" | Not decided | MLS group state sync after extended offline. Pending proposal accumulation. Group state reset triggers. This is the highest-risk design gap. |
| **Summary generation protocol** | Conceptual | Lifecycle hooks described in spec §5.11 | Pre-close summary generation, verification window, summary format (or format freedom), both-party verification flow, key destruction timing. |
| **Governance interface** | Conceptual | Pluggable model decided | Minimum viable interface: propose/approve/reject. How custom governance models register. State machine for governance proposals. |
| **Per-context pseudonym protocol** | Partially designed | Direction in OQ #7 | HKDF derivation spec, pseudonym-to-DID verification protocol, caching rules, new-member onboarding flow. Blocked by OQ #7 confirmation. |
| **Cover traffic protocol** | Partially designed | Direction in OQ #8 | Dummy message format, constant-rate specification, real/dummy multiplexing, recipient discard protocol. Blocked by OQ #8 confirmation. |
| **Metadata privacy mechanisms** | Partially designed | Directions in OQ #1-3, #6-10 | Each confirmed OQ needs protocol-level specification. These collectively form the metadata privacy architecture. |
| **Context promotion** | Not designed | Not decided | When ephemeral/TTL context needs to become persistent. New context referencing old, or same context with TTL removed? |
| **Capability declaration format** | Conceptual | App interface decided | JSON schema for app manifests. LLM-parseable. Versioning. |
| **Registry tool schema standard** | Not designed | Registries are standard contexts | Recommended tool schema for interoperability across registries. Lower priority if A2A removed. |
| **Referral chain mechanics** | Partially designed | Concept in spec §6.4.3 | IntroductionToken wire format, chain depth limits, trust decay function. Irrelevant if A2A removed. |

---

## D. Implementation Readiness by Build Phase

### Phase 1 — Crypto Proof

| Component | Ready? | Blockers |
|-----------|--------|----------|
| MLS wrapper (OpenMLS) | **Yes** | None — spec §9.7 is complete |
| Envelope creation/signing/verification | **Partially** | Envelope format needs redesign for minimal outer envelope (OQ #2) |
| DID creation (did:dht) | **Yes** | None — direction clear, libraries exist |
| SCP native relay protocol + adapter | **No** | Protocol not yet designed |
| In-memory key storage (testing) | **Yes** | None — standard testing adapter |
| Sender-side key layer | **No** | Needs OQ #5 confirmation + full spec |

**Phase 1 blockers:** Envelope format (OQ #2), native relay protocol (undesigned), sender-side key layer (OQ #5 + spec needed).

**Phase 1 unblocked work:** MLS wrapper, DID creation, in-memory key storage, transport trait definition, basic envelope (can start with current format, redesign later).

### Phase 2 — Context + Transport

| Component | Ready? | Blockers |
|-----------|--------|----------|
| Context lifecycle state machine | **No** | Needs formal state machine spec |
| Role assignment / capability ceiling | **Yes** | Spec complete |
| Tool registration and invocation | **Yes** | Spec complete |
| Stateful tool sessions | **No** | Needs wire format spec |
| Event log (Merkle tree) | **No** | Needs concrete format spec |
| Transport abstraction trait | **No** | Needs formal trait definition |
| Multi-transport routing | **Partially** | Trait needed first |

### Phase 3 — Python SDK

| Component | Ready? | Blockers |
|-----------|--------|----------|
| PyO3 bridge layer | **Yes** | Depends on scp-core completion |
| Python wrappers | **Yes** | Depends on API surface stability |
| MCP adapter | **Yes** | Spec complete |
| UCAN validation | **No** | Needs capability schema spec |

---

## E. Recommended Sequence

1. **Decide all 10 open questions** — unblocks everything else
2. **Write sender-side key layer spec (§9.16)** — unlocks Phase 1
3. **Design SCP native relay protocol** — unlocks Phase 1
4. **Define transport abstraction trait** — unlocks Phase 1 and 2
5. **Redesign envelope format** — affects Phase 1
6. **Spec cleanup** (remove A2A if decided, update metadata privacy sections)
7. **Formal state machines** (context lifecycle, tool sessions)
8. **Event log format** — unlocks Phase 2
9. **UCAN capability schema** — unlocks Phase 2/3
10. **ADRs for Phase 1 components** — code follows immediately
