# SCP Protocol Specification Extraction Plan

**Objective:** Extract a standalone, implementation-agnostic protocol specification from SCP's current dual-purpose documentation. The result: a document (or document set) that a Go, C++, Haskell, or Java developer could pick up and implement SCP from scratch without ever seeing the Rust codebase.

**Date:** 2026-03-04

---

## 1. Current State Assessment

### 1.1 What Exists

SCP's protocol knowledge is currently spread across:

| Artifact | Lines | Role | Protocol content? |
|----------|-------|------|-------------------|
| `.docs/specs/` (24 files) | ~9,500 | Protocol + implementation spec | Mixed — see §2 |
| `.docs/adrs/` (6 phase files, 38 ADRs) | ~9,700 | Architectural decisions | Mixed — protocol decisions + implementation decisions |
| `.docs/architecture.md` | ~1,400 | Engineering blueprint | Implementation only |
| `.docs/sketch.md` | ~600 | SDK API surface | Implementation only |
| `.docs/standards/` (13 files) | ~750 | Coding standards | Implementation only |
| `.docs/scaffold/` (7 files) | varies | Per-language build guides | Implementation only |

### 1.2 The Core Problem

The current specs serve dual duty:
1. **Normative protocol requirements** ("Clients MUST verify the BEP44 signature chain") — belongs in protocol spec
2. **Reference implementation guidance** ("Implementation: crates/scp-core/src/provenance/", Rust trait definitions, crate paths, module layout) — belongs in SDK documentation

These are interleaved within the same sections, sometimes within the same paragraphs. An independent implementer must mentally filter out the Rust-specific parts, and in some cases the protocol requirement is only expressed through a Rust type definition with no language-agnostic description.

### 1.3 Key Findings from Audit

**Strengths:**
- Extensive RFC 2119 language (MUST/SHOULD/MAY) throughout specs 03, 05, 07, 09, 10, 17, 18, 22, 23, 24
- Field-level wire format definitions (inner/outer envelopes, event types, governance actions)
- State machine definitions (context lifecycle, MLS epoch ratcheting, governance proposals)
- Conformance infrastructure (7 conformance macros, integration tests)
- Thorough security analysis with threat vectors and mitigations

**Gaps:**
- Wire formats defined via Rust structs, not language-agnostic notation
- No formal grammar (ABNF, CDDL, TLS presentation language) for any message type
- No language-neutral test vectors
- No protocol evolution mechanism (no numbered proposal process)
- Specs 13 (versioning) and 14 (governance) are stubs — 10 and 9 lines respectively
- Several spec sections reference Rust crate paths as "implementation location"
- ADRs mix protocol-level decisions with implementation-level decisions (crate layout, trait design, feature flags)

**Conflicts and Inconsistencies:**
1. **BlobStore naming:** Spec §16/17 uses "BlobStore" trait with "BlobStoreError"; code uses "BlobStorage" with "StorageError". The protocol spec should define the abstract interface; the naming in code is an implementation choice.
2. **BlobStore::store signature:** Spec says store() computes blob_id internally; code's BlobStorage::store() receives blob_id from the caller. Protocol spec must define which is normative.
3. **Handles field:** Spec §22.6.1 added a "handles" field to .well-known/scp, but this was written after SCP-143 (.well-known/scp story) was marked done. The spec is ahead of the implementation. Protocol spec should include it.
4. **Handle query parameter:** Spec §22.9.1 added a "handle" query parameter to scp:// URIs, but SCP-142 (scp:// URI story) was already done. Same situation — spec is ahead.
5. **ProtocolStore scope:** Spec §17.4 describes ProtocolStore as a thick abstraction layer with ~55+ typed methods covering all domain areas. Implementation has ProtocolStore with only the economy module complete. The protocol spec should not describe ProtocolStore at all — it's an implementation pattern, not a protocol requirement. The protocol should define key conventions and serialization format.
6. **Spec 13 (Versioning):** 10 lines of aspirational prose. No concrete version negotiation protocol, no ProtocolVersion type definition, no minimum version enforcement mechanism. This is a gap that needs to be filled before the protocol spec can be complete.
7. **Spec 14 (Protocol Governance):** 9 lines about foundation governance trajectory. Not a protocol specification — it's a project governance statement. Does not belong in the protocol spec.
8. **Spec §3.10.10 DidResolver trait:** The section defines the resolution protocol (§3.10.4) in language-agnostic terms AND defines a Rust trait. The protocol part is normative; the Rust trait is implementation. Need to separate.
9. **Spec §17.2 Storage trait:** Defined as a Rust trait with async fn signatures. The protocol need is "implementations must provide key-value storage with these operations" — the Rust syntax is implementation.
10. **Architecture.md §1.2 message lifecycle:** Contains protocol-level security checkpoint annotations that ARE normative. But they're embedded in a document that is otherwise entirely implementation architecture. These need to be extracted to the protocol spec.
11. **DID document serialization divergence from did:dht.** Standard did:dht specifies DNS packet encoding (TXT/SRV records) for DID documents. SCP uses JSON-LD serialization on the relay layer, with DNS packet encoding only for the DHT layer (BEP44 compatibility). The protocol spec must explicitly define both serialization formats: JSON-LD for relay-stored documents and DNS packets for DHT-stored documents. This divergence is intentional (JSON-LD removes the 1000-byte payload limit), but it needs formal specification — currently §3.10 describes the dual-layer architecture without specifying the serialization difference between layers.
12. **Multi-key architecture underspecified and scattered.** §3.9 mentions key generation, distribution, rotation, and destruction at a high level and references §9.7.4 for the full lifecycle. The multi-key separation (Identity `#0` / Human Signing `#active` / Pre-Rotation / Agent Signing `#agent`) is described across §3.9, §3.10, §4.2, §4.5 (ADR-039), §9.7.4, §9.8.1 (updated preimage), and §11.2.3 (prior art) but not formally specified in a single authoritative section. The protocol spec must consolidate this with wire formats, not scattered across 6+ locations.
13. **Signature preimage mismatch.** ADR-039 updates the inner signature preimage to include `signing_key_id` (`context_id || sender_did || signing_key_id || epoch || ...`), but §9.8.1 as currently written does not include this field. The ADR-039 version is normative. Must be reconciled before extraction.

---

## 2. Per-File Classification

Every section of every current spec file, classified as:
- **P** = Protocol (normative, belongs in standalone spec)
- **I** = Implementation (SDK/reference impl guidance, stays in current docs)
- **N** = Non-normative informational (background, rationale, comparison — may go in companion architecture document)
- **X** = Not applicable to protocol spec (licensing, documentation plans, project governance)

### Spec 01 — Thesis (63 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| Core thesis paragraph | **P** | Problem statement and design rationale — protocol spec introduction |
| "designed for a world where" bullets | **P** | Protocol assumptions |
| Core Principles (6 items) | **P** | Protocol tenets — normative |
| Strategy: SDK-First, Not App-First | **I/X** | Limn's business strategy, not protocol |
| "Why SDK-First" (Moltbook, OpenClaw, competitive window) | **X** | Market context, not protocol |
| "What SDK-First Means" (5 items) | **I** | SDK delivery strategy |
| The Competitive Landscape (diagram + text) | **N** | Informational — could go in white paper |

**Action:** Extract Core Principles as protocol preamble. Drop SDK-first strategy and competitive landscape from protocol spec.

### Spec 02 — System Design (240 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §2.1 Conceptual Architecture (diagram) | **P** | Protocol boundary definition — normative |
| §2.1 Context modes paragraph | **P** | Encrypted vs Broadcast — normative |
| §2.2 Context Interior (diagram) | **P** | What a context contains — normative |
| §2.3 Cross-Context Communication (diagram + text) | **P** | Two mechanisms, isolation invariant — normative |
| §2.4 Trust and Capability Model (diagram) | **P** | Trust evaluation function — normative |
| §2.5 Full Stack Overview (diagram) | **P/N** | Layer model — protocol-level but high-level |

**Action:** Almost entirely protocol content. Extract as-is with minor cleanup.

### Spec 03 — Identity (387 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §3.1 Root of Identity | **P** | DID foundation — normative |
| §3.2 Key Custody | **P** | Custody abstraction — normative (defines what implementations must support) |
| §3.3 Recovery | **P** | Recovery mechanisms — normative |
| §3.4 Linking Existing Identities | **P** | Identity linking — normative |
| §3.5 Identity Attestations | **P** | Attestation properties and flows — normative |
| §3.6 Social Graph | **P** | Graph model, capability-gated queries, blocking (3 tiers) — normative |
| §3.6 "ProtocolStore methods" block | **I** | Rust method signatures for block list queries — implementation. **The protocol requirement is "implementations must support these queries"; the Rust signatures are SDK design.** |
| §3.7 Identity Private State | **P** | Private state model, encryption, sync, integrity — normative |
| §3.7.1 Block List Storage | **P** | Event types, propagation protocol — normative |
| §3.7.1 "ProtocolStore methods" block | **I** | Rust method signatures — implementation |
| §3.8 DID Resolution Security | **P** | did:dht self-certification, did:web mitigations — normative |
| §3.9 Key Lifecycle | **P** | Generation, distribution, rotation, destruction — normative |
| §3.10 DID Resolution Layers | **P** | Dual-layer architecture — normative |
| §3.10.1 Resolution Priority (table) | **P** | Priority semantics — normative |
| §3.10.2 Layer 1: SCP Relay-Based Resolution | **P** | Routing ID derivation, PUBLISH/QUERY format — normative |
| §3.10.3 Layer 2: Mainline DHT | **P** | Fallback role — normative |
| §3.10.4 Resolution Protocol | **P** | Full resolution sequence — **critical normative content** |
| §3.10.5 Publishing Protocol | **P** | Dual-layer publishing — normative |
| §3.10.6 Anti-Segmentation Invariant | **P** | MUST publish to both — normative |
| §3.10.7 Version Resolution | **P** | Sequence number authority — normative |
| §3.10.8 Security Analysis | **P** | Security properties — normative |
| §3.10.9 Privacy Properties | **P** | Privacy analysis — normative |
| §3.10.10 DidResolver Trait | **I** | Rust trait + struct definitions. **Protocol requirement is in §3.10.4; this section is SDK API.** |
| §3.10.11 Bootstrap and Network Growth | **N** | Growth trajectory — informational |
| §3.10.12 Phase Integration (table) | **I** | Build phase assignments — implementation |

**Action:** Nearly all protocol content. Remove: ProtocolStore method blocks, DidResolver trait section, Phase Integration table. These are implementation artifacts.

**GAP IDENTIFIED:** §3.10 (dual-layer resolution) is one of the most protocol-pure sections in the spec and should extract cleanly into the SCP Identity document. However, the **multi-key verification method architecture** (Identity Key `#0` / Human Signing Key `#active` / Pre-Rotation Key / Agent Signing Key `#agent`) is described across §3.9, §3.10, §4.2, §4.5, and ADR-039 but lacks a formal wire format specification. The extracted protocol spec needs:
- Explicit key commitment scheme (how the pre-rotation key hash is encoded in the DID document)
- Key rotation authorization chain (how the Human Signing Key proves it was authorized by the Identity Key)
- DID document structure showing all verification methods (`#0`, `#active`, `#agent`) and their roles
- Wire format for key rotation messages
- **Agent Signing Key (`#agent`) verification method format** — how it appears in the DID document, its relationship to the `#active` key
- **Self-delegation UCAN format** — `iss == aud` (same DID) with `fct.scp_key_scope: "#agent"`, UCAN header `signing_key_id`
- **`ScpKeyCustodyAttestation` service entry format** — DID document service entry declaring key custody model
- **`ScpCustodyViolationAttestation` format** — permanent violation logging for Category A violations by `#agent`
- **Permission category definitions** — Category A (`#0` only), Category B (user-configurable), Category C (context-configurable)

This is a P0 gap for the Identity document — the multi-key architecture and shared-DID human-agent model are novel contributions and must be specified precisely enough for independent implementation.

### Spec 04 — Agents (69 lines + ADR-039 additions)
| Section | Classification | Notes |
|---------|---------------|-------|
| §4.1 Core Principle | **P** | Human traceability — normative |
| §4.2 Binding (updated ADR-039) | **P** | Personal + institutional agents, shared-DID model, `#agent` verification method — normative |
| §4.3 One Agent Per Person Per Context (updated ADR-039) | **P** | Social constraint, `signing_key_id` attribution — normative |
| §4.4 Bring Your Own Agent | **P** | Capability metadata, self-attested vs challenge-verified — normative |
| §4.5 The Human-Agent Pair (updated ADR-039) | **P** | Shared-DID model, self-delegation UCAN, Category A/B/C permissions, 5-layer enforcement stack — **critical normative content** |
| §4.6 Agents Are Consumers, Not Enforcers | **P** | Enforcement is cryptographic — normative |
| §4.7 Context-Bound at Protocol Level | **P** | Agent isolation, A2A rejection rationale — normative |
| §4.8 Agent Fleet | **P** | Fleet model, earned capacity reference — normative |

**Action:** Entirely protocol content. Extract as-is. **Note:** ADR-039 significantly enriches §4.2, §4.3, and §4.5 with shared-DID semantics, permission categories, and the enforcement stack. These are protocol-level (not implementation-level) additions — they define how verifiers validate agent actions.

### Spec 05 — Contexts (960 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §5.1 Definition | **P** | Context definition, properties — normative |
| §5.2 Creation | **P** | Creation semantics — normative |
| §5.3 Capability Ceiling | **P** | Ceiling categories, ceiling policy, economic policy orthogonality — normative |
| §5.4 Tools | **P** | Tool registration (schema, hash, test vectors, operator DID, cost) — normative |
| §5.5 Roles | **P** | Role properties, broadcast roles — normative |
| §5.6 Membership | **P** | One-per-human, broadcast two-tier — normative |
| §5.7 Metadata | **P** | Pre-opt-in visibility — normative |
| §5.7.1 Metadata Publication | **P** | Routing ID derivation for metadata — normative |
| §5.8 TTL | **P** | Time-to-live semantics — normative |
| §5.9 Governance | **P** | GovernanceEngine interface, governance actions — normative |
| §5.9.x GovernanceAction variants | **P** | All 24 governance action types — normative |
| §5.10 Context Promotion | **P** | Ephemeral → persistent, unanimous consent — normative |
| §5.11 Memory Scope | **P** | Ephemeral/Summary/Full — normative |
| §5.12 Context Templates | **P** | Well-known templates, template IDs — normative |
| §5.12.1 Template Specification | **P** | Template parameters — normative |
| §5.12.2 Auto-Accept Policies | **P** | SDK auto-join semantics — normative |
| §5.12.3 Template Registry | **P** | Template ID format, built-in templates — normative |
| §5.12.4 Standing Bilateral Contexts | **P** | Creation semantics, ~200ms — normative |
| §5.12.5-6 Standing Channel details | **P** | Standing channel protocol — normative |
| §5.13 Context Nesting | **P** | Parent-child, ceiling intersection, eligibility, lifecycle — normative |
| §5.13.1-8 all subsections | **P** | All nesting details — normative |
| §5.14 Broadcast Contexts | **P** | ContextMode::Broadcast, per-author keys, subscriber registration — normative |
| §5.14.1-12 all subsections | **P** | Full broadcast specification — normative |
| Any Rust code blocks | **I** | Rust struct/enum definitions — need language-agnostic replacement |

**Action:** Almost entirely protocol content. The Rust code blocks (struct definitions, enum definitions) need to be replaced with language-agnostic wire format notation. The protocol semantics are all normative.

**GAP IDENTIFIED:** §5.9 references a pluggable GovernanceEngine interface but doesn't define a concrete governance protocol (how proposals are transmitted, how votes are collected, how execution is triggered at the wire level). The current spec describes what governance does but not the wire protocol for governance operations. This needs to be filled.

### Spec 06 — Cross-Context Communication (152 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All sections (§6.1-6.3) | **P** | Agent isolation, tool interfaces, transport, sessions, discovery, broadcast interactions, human bridge — all normative |

**Action:** Extract as-is. Entirely protocol content.

### Spec 07 — Trust, Validation, and Capabilities (319 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §7.1 Design Principle | **P** | Four-layer trust model — normative |
| §7.2 Layer 1: Protocol Enforcement | **P** | UCAN validation requirements — normative |
| §7.3 Layer 2: Behavioral Validation | **P** | Event logs, behavioral records, tool integrity — normative |
| §7.3.1-7 all subsections | **P** | Merkle trees, records, challenge-response, consequences — normative |
| §7.4 Layer 3: Attestation Authenticity | **P** | Signature verification — normative |
| §7.4.1-3 subsections | **P** | Admission gating, attestation independence — normative |
| §7.5 Layer 4: Trust Evaluation | **P/N** | Agent-level judgment — normative principle, informational detail |

**Action:** Extract as-is. Entirely protocol content.

### Spec 08 — Products and Apps (107 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §8.1 App Architecture | **N** | How apps relate to contexts — informational |
| §8.2 Discovery | **P/N** | App discovery model — partially normative |
| §8.3 State Portability | **P** | Protocol state portable, app state is app's concern — normative principle |
| §8.4 Generated Clients | **N** | Agent-built apps — informational |
| §8.5 MCP Compatibility | **P** | Tool schema compatibility — normative |

**Action:** Extract §8.3 (state portability) and §8.5 (MCP compatibility) as normative. Rest is informational — belongs in companion document.

### Spec 09 — Security Model (1,007 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §9.1 Core Invariants | **P** | Seven invariants — normative |
| §9.2 Threat Vectors and Mitigations | **P** | Threat model — normative |
| §9.2.1 Tool Interface Abuse (9 vectors) | **P** | All abuse vectors and mitigations — normative |
| §9.3 Sybil Resistance | **P** | Trust signals, composable approach — normative |
| §9.4 Systemic Defense Philosophy | **P** | Behavioral analysis over content inspection — normative |
| §9.5 Security Boundaries (5 boundaries) | **P** | Protocol boundary, context, role, capability, trust — normative |
| §9.6 DID Security | **P** | did:dht self-certification, BEP44, sequence numbers — normative |
| §9.6.1 BEP44 Verification | **P** | Verification algorithm — **critical normative content** |
| §9.6.2 did:web Mitigations | **P** | TOFU, TLS pinning — normative |
| §9.6.3 Relay List Authentication | **P** | NIP-65 pattern — normative |
| §9.7 MLS Integration | **P** | Epoch management, key rotation, PCS — normative |
| §9.7.1-4 MLS subsections | **P** | All MLS details — normative |
| §9.8 Message Ordering and Replay | **P** | Sequence numbers, replay detection, reorder buffer — normative |
| §9.8.1-5 subsections | **P** | Nonce dedup, ordering, clock-free — normative |
| §9.9 Relay Threat Model | **P** | What relays can/cannot do — **critical normative content** |
| §9.9.1-3 subsections | **P** | Formal model, suppression resistance, consistency protocol — normative |
| §9.10 Metadata Privacy | **P** | All 10 layered protections — normative |
| §9.10.1-10 subsections | **P** | Pseudonyms, padding, cover traffic, etc. — normative |
| §9.11 Safety Numbers | **P** | Key continuity verification — normative |
| §9.12 Key Rotation Protocol | **P** | Three-layer rotation — normative |
| §9.13 Proposal-Context Binding | **P** | Anti-fork invariant — normative |
| §9.14 Event Log Integrity | **P** | Merkle tree specification — normative |
| §9.15 Key Zeroization | **P** | Zeroize on drop requirement — normative |
| §9.16 Sender-Side Keys | **P** | Full sender key specification — **critical normative content** |
| §9.16.1-4 subsections | **P** | Blocking protocol, distribution, epoch management — normative |
| §9.17 Content Access Control | **P** | Access key layer, CEK wrapping, AAD binding — **critical normative content** |
| §9.8.1 Inner signature preimage (updated ADR-039) | **P** | Preimage now includes `signing_key_id`: `context_id \|\| sender_did \|\| signing_key_id \|\| epoch \|\| ...` — **critical normative content, wire format change** |
| Any Rust code blocks | **I** | Replace with language-agnostic notation |
| Any "see crates/..." references | **I** | Remove from protocol spec |

**Action:** Nearly the entire spec is normative protocol content. Remove Rust code blocks and crate references. This is the densest normative content in the project. **Note:** ADR-039 adds `signing_key_id` to InnerEnvelope, ScpCredential, and SenderKeyEpochAdvance — all three need wire format definitions updated.

### Spec 10 — Infrastructure and Self-Hosting (826 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §10.1 Philosophy | **P/N** | Self-hosting design philosophy — informational but establishes normative constraints |
| §10.2 Device-as-Node | **P** | Device is a full participant — normative architecture |
| §10.2 Agent workstation paragraph | **N** | Deployment commentary — informational |
| §10.3 Minimal Protocol State | **P** | State footprint constraints — normative |
| §10.4 Relay Architecture | **P** | Relay design goals and constraints — normative |
| §10.5 SDK Transport Architecture | **P** | Transport abstraction — normative |
| §10.5.1 SCP specifies for transport | **P** | Requirements list — normative |
| §10.5.2 Transport adapter roster | **P/N** | List of 17 adapters — informational (protocol doesn't require all of them) |
| §10.6 Native Relay Protocol | **P** | Wire types (PUBLISH, SUBSCRIBE, QUERY, DELETE) — **critical normative content** |
| §10.6.1-6 Native relay subsections | **P** | Wire format, bridge secret, WebSocket protocol — normative |
| §10.7 Push Notifications | **P** | Opaque push model — normative |
| §10.8 Multi-Device | **P** | Device management protocol — normative |
| §10.9 Media Transport | **P** | Delegated media model (WebRTC) — normative |
| §10.9.1 Media subsections | **P** | Setup protocol, SRTP integration — normative |
| §10.10 Rate Limiting | **P** | Rate limiting requirements — normative |
| §10.11 NAT Traversal | **P** | STUN/TURN, ICE — normative |
| §10.12 Holepunch Integration | **N** | Specific implementation approach — informational |
| Any Rust trait definitions | **I** | Replace with language-agnostic interface description |
| Any crate path references | **I** | Remove |

**Action:** Mostly protocol content. Remove crate references and Rust-specific definitions. The native relay protocol (§10.6) is critical wire format content that needs formal notation.

### Spec 11 — Prior Art (~180 lines, expanded)
| Section | Classification | Notes |
|---------|---------------|-------|
| Comparison table | **N** | Background — informational |
| §11.1 Holepunch / Hypercore (expanded) | **N** | Structural comparison of Hypercore vs SCP event logs, Autobase vs MLS multi-writer, Keet's undocumented encryption — informational but valuable context for white paper §16.3 |
| §11.1.1 Structural Comparison table | **N** | Hypercore vs SCP event logs dimension-by-dimension — informational |
| §11.1.2 Autobase and Multi-Writer | **N** | Single-writer-composed vs native multi-writer — informational |
| §11.1.3 Keet and Group Encryption | **N** | Existence proof vs published spec — informational |
| §11.1.4 Architectural Divergences | **N** | Transport coupling, trust, governance, offline — informational |
| §11.2 DID DHT and SCP's Identity Layer (new) | **P/N** | did:dht spec, SCP departures (dual-layer, three-key, healing, JSON-LD), implementation independence, governance risk. The departures description (§11.2.3) contains **normative protocol content** that belongs in the SCP Identity protocol document. The did:dht spec summary (§11.2.1) and governance analysis (§11.2.4-5) are informational. |
| §11.3 "What no existing standard covers" | **N** | Informational — updated to include DID innovations |

**Action:** Does not belong in protocol spec as a whole. However, §11.2.3 (SCP's departures from did:dht) contains normative content that should be extracted into the SCP Identity document. The structural comparisons (Hypercore, did:dht) belong in the white paper. The "What no existing standard covers" summary belongs in the white paper introduction.

### Spec 12 — Platform Bridge Connectors (169 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All sections | **P** | Bridge modes, shadow identities, provenance trust hierarchy, claiming — normative |

**Action:** Extract as-is. Entirely protocol content.

### Spec 13 — Versioning (10 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All content | **P (stub)** | Aspirational prose, no concrete protocol |

**GAP: This is a critical gap.** A protocol spec must define:
- ProtocolVersion type (concrete format: semantic versioning or numeric)
- Version declaration mechanism (how agents and contexts declare their version)
- Capability negotiation (how mismatched versions interact)
- Minimum version enforcement (how contexts set minimum version requirements)
- Forward compatibility rules (concrete, not aspirational)
- Extension point registry (how new attestation types, tool capabilities, etc. are added without version bumps)

**Action:** Must be written from scratch for the protocol spec. Current content is inadequate.

### Spec 14 — Protocol Governance (9 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All content | **X** | Project governance, not protocol specification |

**Action:** Does not belong in protocol spec. Belongs in a separate governance document or the white paper.

### Spec 15 — Regulatory Compliance (27 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| Privacy by design | **P** | Structural privacy guarantees — normative |
| GDPR / right to erasure | **P/N** | Protocol primitives for compliance — partially normative |
| Content moderation | **N** | Governance responsibilities — informational |
| Relay vs context regulatory surface | **N** | Legal analysis — informational |

**Action:** Extract the structural privacy guarantees (encryption-as-access-control, self-sovereign identity) as protocol properties in the security section. The regulatory analysis is informational.

### Spec 16 — Test Infrastructure (1,703 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §16.1-3 Architecture | **I** | Test harness architecture — implementation |
| §16.4 Relay testing | **I** | InMemoryRelay, BehaviorMode — implementation |
| §16.5-10 Simulation | **I** | NetworkTopology, ScenarioBuilder — implementation |
| §16.11 Assertions | **P** | Protocol invariant definitions — normative (what MUST hold) |
| §16.12 Conformance macros | **P/I** | What conformance requires (normative) + how it's tested (implementation) |
| §16.13-15 CI tiers | **I** | CI configuration — implementation |

**Action:** Extract conformance requirements (what a conforming implementation MUST satisfy) as a conformance section in the protocol spec. Drop all implementation details (test harness, CI tiers, assertion function signatures).

### Spec 17 — Persistence and Storage (618 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §17.1 Storage Architecture Overview | **P/I** | Client/relay storage split (normative); stack diagram with ProtocolStore (implementation) |
| §17.1 "Why Thin Trait + Thick Protocol Layer" | **I** | Implementation pattern rationale |
| §17.2 Storage Trait Evolution | **I** | Rust trait definition — implementation |
| §17.3 Key Convention | **P** | Key format specification — **normative** (implementations must use these keys) |
| §17.4 ProtocolStore | **I** | Thick layer wrapping Storage — implementation pattern |
| §17.5-6 Backend adapters | **I** | SQLite, redb, filesystem — implementation |
| §17.7 BlobStore backends | **P/I** | BlobStore interface is protocol; specific backends are implementation |
| §17.8 Migratable trait | **I** | Migration pattern — implementation |
| §17.9 Serialization | **P** | MessagePack with version envelopes — **normative** |
| §17.10 MLS Storage Bridge | **I** | OpenMLS integration — implementation |

**Action:** Extract key conventions (§17.3) and serialization format (§17.9) as normative. Extract abstract storage requirements (what operations a storage backend must support) without Rust syntax. Drop ProtocolStore, backend adapters, migration — all implementation.

**CONFLICT FLAGGED:** §17.3 key conventions are defined with zero-padded sequence numbers (`{seq:020d}`) for lexicographic ordering. This is a protocol-level requirement (event ordering depends on it). The protocol spec must define this convention precisely.

### Spec 18 — Addressability and Deployment (663 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §18.1 DID Document Structure | **P** | Service endpoint types — normative |
| §18.2 Service Endpoint Specification | **P** | All endpoint types (SCPRelay, etc.) — **critical normative content** |
| §18.3 .well-known/scp | **P** | Discovery endpoint format — normative |
| §18.4 scp:// URI | **P** | URI scheme — normative |
| §18.5 Bootstrap and Relay Discovery | **P** | DefaultRelayResolver, 5-level bootstrap — normative |
| §18.6-7 ApplicationNode | **I** | Type-state builder, Rust API — implementation |
| §18.8 TLS Configuration | **P** | TLS 1.3 requirement, ACME — normative |
| §18.9 Deployment Patterns | **N** | Deployment guidance — informational |
| §18.10 HTTP Dev API | **I** | Local debugging endpoint — implementation |
| §18.11 HTTP Broadcast Projection | **I** | HTTP distribution of broadcast content — implementation convenience |

**Action:** Extract §18.1-5 and §18.8 as normative. ApplicationNode, Dev API, and Broadcast Projection are implementation features. **Note:** §18.3 .well-known/scp must include the "handles" field from spec 22 — this is a gap in the current implementation but the protocol spec should be complete.

### Spec 19 — Economic Governance (583 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §19.1 Design Philosophy | **P** | Economic governance model — normative |
| §19.2 Payment Adapter | **P** | Adapter interface contract — normative |
| §19.2.1-2 Integration | **P** | Payment flow — normative |
| §19.3 Cost per Action | **P** | CostPolicy, action pricing — normative |
| §19.4 Payment Receipts | **P** | Receipt format, Merkle inclusion — normative |
| §19.5 Spending UCANs | **P** | Spending authorization — normative |
| §19.6 Provenance of Paid Data | **P** | Economic provenance — normative |
| §19.7 Velocity-Based Cost Escalation | **P** | SenderVelocity — normative |
| §19.8 Free Tier | **P** | Zero-cost contexts — normative |
| Any Rust code blocks | **I** | Replace with language-agnostic notation |

**Action:** Mostly protocol content. Remove Rust code blocks.

### Spec 20 — Licensing (99 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All content | **X** | Project licensing, not protocol |

**Action:** Does not belong in protocol spec. Reference in a "License" section: "The protocol specification is licensed under CC-BY 4.0."

### Spec 21 — Documentation (354 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All content | **X** | Documentation plans, not protocol |

**Action:** Does not belong in protocol spec.

### Spec 22 — Human-Readable Addressing (594 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §22.1 Design Principles | **P** | Addressing philosophy — normative |
| §22.2 Address Format | **P** | Canonical format, normalization — **normative** |
| §22.2.1 Address Types | **P** | Identity vs context addresses — normative |
| §22.2.2 Normalization | **P** | Normalization algorithm — normative |
| §22.3 Discovery Context Handles | **P** | Handle registration, lookup, deregistration — normative |
| §22.4 Petnames | **P** | Local name assignment — normative |
| §22.5 Attestation-Backed Handles | **P** | Reverse lookup — normative |
| §22.6 Domain Handles | **P** | .well-known/scp handles map — normative |
| §22.7 Unified Resolver | **P** | Resolution algorithm, priority — normative |
| §22.8 Trust Levels | **P** | TrustLevel enum, ordering — normative |
| §22.9 URI Integration | **P** | scp:// handle query parameter — normative |
| §22.10 Security Considerations | **P** | Handle security — normative |
| Any Rust code blocks | **I** | Replace with language-agnostic notation |

**Action:** Almost entirely normative. Remove Rust code blocks.

### Spec 23 — Sync and Offline Strategy (223 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §23.1 Three-Tier Offline Strategy | **P** | Tier classification — normative |
| §23.2 Client-Side Outbound Queue | **P** | Queue mechanics — normative |
| §23.3 Reconnection Protocol (6 phases) | **P** | Reconnection sequence — **normative** |
| §23.4 MLS Epoch Catch-Up | **P** | Commit recovery, fast-forward — normative |
| §23.5 Sender Key Re-acquisition | **P** | Key catch-up protocol — normative |
| §23.6 Event Log Reconciliation | **P** | Merkle-based sync — normative |
| Any Rust pseudocode | **P** | Algorithmic pseudocode (not Rust-specific) — keep as pseudocode |

**Action:** Entirely protocol content. Extract as-is.

### Spec 24 — Provenance System (190 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| §24.1 Design Principles | **P** | Provenance principles — normative |
| §24.2 Core Types | **P** | DataProvenance, SourceType, DiscoveryMethod, ProvenanceQuality — **normative** |
| §24.3 Provenance Attachment | **P** | Automatic attachment algorithm — normative |
| §24.4 Chain Depth Enforcement | **P** | Maximum depth protocol — normative |
| §24.5 Source Type Updates | **P** | Lifecycle transitions — normative |
| "See ADR-019" / "Implementation: crates/..." | **I** | Reference to implementation — remove |

**Action:** Almost entirely normative. Remove implementation references.

### Spec 00 — Open Questions (63 lines)
| Section | Classification | Notes |
|---------|---------------|-------|
| All content | **N/I** | Living registry of open/closed design decisions — does not belong in protocol spec |

**Action:** Does not belong in protocol spec. Remains as internal project artifact. Open questions should be resolved before the corresponding protocol spec section is finalized.

---

## 3. ADR Classification

The 38 ADRs across 6 phase files contain both protocol-level and implementation-level decisions. Key classification:

### Protocol-Level ADRs (extract normative content)
| ADR | Topic | Key Protocol Content |
|-----|-------|---------------------|
| ADR-001 | MLS Integration | Cipher suite selection, credential type, key package lifetime |
| ADR-002 | Envelope Format | Outer/inner envelope wire format — **critical** |
| ADR-003 | DID Method | did:dht primary, BEP44, resolution |
| ADR-004 | Native Relay Protocol | Wire types, WebSocket protocol — **critical** |
| ADR-005 | Transport Abstraction | Transport trait contract |
| ADR-007 | Sender Key Distribution | Pull model, wire types — **critical** |
| ADR-008 | Context Lifecycle | 5-state FSM, transitions — **critical** |
| ADR-009 | Roles and UCAN | UCAN validation checks |
| ADR-010 | Tool Registration | Tool registration protocol |
| ADR-011 | Verifiable Event Log | Merkle tree specification — **critical** |
| ADR-012 | Multi-Transport Routing | Routing strategy, dedup |
| ADR-016 | Discovery Contexts | Two-tier model, bootstrap |
| ADR-019 | Provenance | Provenance types and attachment |
| ADR-027 | Context Nesting | Parent-child protocol |
| ADR-029 | Broadcast Contexts | Broadcast mode protocol |
| ADR-031 | Governance Actions | 24 action types |
| ADR-038 | Content Access Control | Access key layer, CEK wrapping |
| ADR-039 | Shared-DID Human-Agent Identity | Shared-DID model, `#agent` verification method, signing_key_id, self-delegation UCAN, Category A/B/C permissions, 5-layer enforcement stack, custody attestation — **critical** |

### Implementation-Level ADRs (stay in current docs)
| ADR | Topic | Why Implementation |
|-----|-------|--------------------|
| ADR-006 | Storage Trait | Rust trait design |
| ADR-013 | Testing Framework | Test infrastructure design |
| ADR-014 | Attestation Conformance | Conformance macro design |
| ADR-020 | Tool Interface Transport | SDK-level bridging implementation |
| ADR-032 | ProtocolStore | Thick layer implementation |
| ADR-033 | FFI Strategy | Language binding approach |
| ADR-034 | WASM Architecture | wasm-bindgen specifics |
| ADR-035 | HTTP Dev API | scp-node implementation feature |
| ADR-036 | Platform Adapters | scp-platform trait design |
| ADR-037 | Key Custody | Platform-specific custody |

**Action:** Protocol-level ADR content gets absorbed into the relevant protocol spec sections (the ADR provides the rationale and alternatives; the spec provides the normative requirement). Implementation-level ADRs stay as-is.

---

## 4. Target Document Structure

The standalone protocol specification should be organized as follows:

### Option A: Single Document (Signal model)
One document, ~150-200 pages, covering the entire protocol. Simpler to manage, harder to read.

### Option B: Modular Documents (MLS/W3C model) — RECOMMENDED
Multiple focused documents, each covering a specific protocol subsystem. Easier to read, easier to update independently, follows IETF/W3C precedent.

**Proposed document set:**

| Document | Covers | Current Source |
|----------|--------|----------------|
| **SCP Core** | Thesis, system model, contexts, agents, governance | Specs 01, 02, 04, 05, 08 |
| **SCP Identity** | DID, resolution, attestations, private state, social graph | Spec 03 |
| **SCP Security** | Threat model, invariants, MLS integration, sender keys, content access, metadata privacy | Spec 09 |
| **SCP Trust** | Capability model, UCAN, behavioral validation, trust evaluation | Spec 07 |
| **SCP Transport** | Relay protocol, transport abstraction, native relay wire format | Spec 10 |
| **SCP Cross-Context** | Tool interfaces, child contexts, bridge connectors | Specs 06, 12 |
| **SCP Addressing** | Human-readable addressing, discovery, URI scheme | Spec 22 |
| **SCP Persistence** | Key conventions, serialization, storage requirements | Spec 17 (normative parts only) |
| **SCP Addressability** | .well-known/scp, DID document structure, bootstrap | Spec 18 (normative parts only) |
| **SCP Economic** | Economic governance, payment protocol, spending UCANs | Spec 19 |
| **SCP Provenance** | Provenance types, attachment, chain depth, quality tiers | Spec 24 |
| **SCP Sync** | Offline strategy, reconnection protocol, epoch catch-up | Spec 23 |
| **SCP Versioning** | Protocol versioning, capability negotiation, extension points | Spec 13 (rewritten) |
| **SCP Conformance** | Conformance requirements, test vector format | Spec 16 (requirements only) |

Each document should follow a consistent structure:
1. Abstract
2. Status
3. Requirements Language (RFC 2119 reference)
4. Document body
5. Security Considerations
6. IANA Considerations (if applicable)
7. References (Normative / Informative)

---

## 5. Wire Format Notation Strategy

### 5.1 The Problem

Currently, all wire formats are defined via Rust struct definitions:

```rust
pub struct InnerEnvelope {
    pub context_id: String,
    pub sender_did: String,
    #[serde(with = "serde_bytes")]
    pub epoch: u64,
    // ...
}
```

This is Rust, not protocol. An independent implementer needs:
- Exact field names and types (language-agnostic)
- Serialization format (MessagePack field ordering, string encoding)
- Optional vs required fields
- Field semantics (what each field means, constraints)

### 5.2 Recommended Approach: TLS Presentation Language + Prose

**For cryptographic constructs** (envelopes, key material, MLS integration): Use TLS presentation language (RFC 8446 §3). This is what MLS (RFC 9420) uses. SCP builds on MLS, so using the same notation creates natural continuity.

Example (InnerEnvelope):
```
struct {
    opaque context_id<1..2^16-1>;      /* Context identifier */
    opaque sender_did<1..2^16-1>;      /* Sender's DID string */
    uint64 epoch;                       /* MLS epoch number */
    uint64 generation;                  /* MLS generation within epoch */
    uint64 sequence;                    /* Per-sender monotonic sequence */
    uint64 timestamp;                   /* Unix timestamp (seconds) */
    opaque payload_hash[32];           /* SHA-256 of plaintext payload */
    opaque payload<0..2^32-1>;         /* Bucket-padded plaintext */
    optional<Provenance> provenance;   /* Cross-context provenance */
    opaque provenance_hash[32];        /* SHA-256 of provenance */
    opaque signature<0..2^16-1>;       /* Ed25519 signature */
} InnerEnvelope;
```

**For application-level structures** (metadata, tool schemas, discovery records): Use annotated tables with type definitions. These are JSON-compatible and don't need the cryptographic precision of TLS presentation language.

Example (.well-known/scp):
```
WellKnownScp:
  Field              Type                Required  Description
  ─────              ────                ────────  ───────────
  version            uint32              MUST      Protocol version
  did                string              MUST      Operator's DID
  relay_urls         array<string>       MUST      WebSocket relay URLs
  contexts           array<ContextRef>   MAY       Published context metadata
  handles            map<string, DID>    MAY       Handle → DID mapping (§22.6)
  relay_config       RelayConfig         MAY       Relay operational parameters
```

**For the relay protocol** (PUBLISH, SUBSCRIBE, QUERY, DELETE): Use MessagePack field definitions with explicit type tags and field ordering. The relay protocol is binary MessagePack over WebSocket, so the notation should be precise about encoding.

### 5.3 Serialization Specification

The protocol spec must define:
1. **MessagePack as the canonical serialization format** for all wire messages
2. **Field ordering rules** (alphabetical? schema-defined? — currently schema-defined via serde)
3. **String encoding** (UTF-8, always)
4. **Binary field encoding** (serde_bytes convention → MessagePack bin format)
5. **Optional field encoding** (MessagePack nil for absent optional fields)
6. **Version envelope format** (§17.9: version tag + payload)

**GAP IDENTIFIED:** The current specs do not explicitly define MessagePack field ordering. Rust's serde serializes struct fields in definition order. The protocol spec must make this explicit — either define canonical field order or specify that implementations must accept any order.

---

## 6. Test Vector Strategy

### 6.1 What Needs Test Vectors

| Category | Priority | Description |
|----------|----------|-------------|
| Envelope serialization | **P0** | InnerEnvelope, OuterEnvelope: given these field values, the serialized bytes are exactly X |
| BEP44 signature verification | **P0** | Given this DID and this document, the signature verification succeeds/fails |
| Routing ID derivation | **P0** | Given this context_id/DID, the routing_id is exactly X |
| DID routing ID derivation | **P0** | Given this DID string, SHA-256("scp:did:" \|\| did_string) is exactly X |
| Multi-key DID document | **P0** | Given these keys (`#0`, `#active`, `#agent`), the DID document structure is exactly X |
| Key rotation authorization | **P0** | Given this Identity Key and new Human Signing Key, the rotation message is exactly X |
| z-base-32 encoding | **P0** | Given this Ed25519 public key, the z-base-32 encoding is exactly X (did:dht compatibility) |
| signing_key_id in InnerEnvelope | **P0** | Given this InnerEnvelope with signing_key_id="#active", the serialized bytes and signature preimage are exactly X |
| ScpCredential with signing_key_id | **P0** | Given this ScpCredential with signing_key_id="#agent", the serialized format is exactly X |
| Self-delegation UCAN | **P0** | Given this self-delegation UCAN (iss==aud, fct.scp_key_scope="#agent"), the encoded token is exactly X |
| Custody attestation | **P1** | Given this ScpKeyCustodyAttestation, the DID document service entry format is exactly X |
| HKDF key derivation | **P0** | Given this key material and context, the derived key is exactly X |
| Sender key HPKE wrapping | **P0** | Given this sender key and recipient, the wrapped key is exactly X |
| AES-256-KW wrapping | **P0** | Given this CEK and access key, the wrapped CEK is exactly X |
| Merkle tree construction | **P1** | Given these events, the tree root is exactly X |
| Bucket padding | **P1** | Given this payload size, the padded size is exactly X |
| Address normalization | **P1** | Given this address string, the normalized form is exactly X |
| UCAN validation | **P1** | Given this UCAN token chain, validation succeeds/fails because X |
| Context state machine | **P2** | Given this state and this event, the transition produces this new state |

### 6.2 Test Vector Format

JSON files, one per category, structured as:
```json
{
  "description": "InnerEnvelope serialization vectors",
  "vectors": [
    {
      "description": "minimal envelope with no provenance",
      "input": {
        "context_id": "ctx_abc123",
        "sender_did": "did:dht:z6Mk...",
        "epoch": 0,
        "generation": 0,
        "sequence": 1,
        "timestamp": 1709568000,
        "payload_hash": "a1b2c3...",
        "payload": "48656c6c6f",
        "provenance": null,
        "provenance_hash": "0000...0000",
        "signature": "ed25519sig..."
      },
      "expected_output": "msgpack_hex_bytes...",
      "notes": "Provenance is null; provenance_hash is all-zeros"
    }
  ]
}
```

---

## 7. Gaps That Must Be Filled

### 7.1 Critical Gaps (P0 — blocks protocol spec publication)

1. **Protocol versioning (spec 13).** Must define: ProtocolVersion type, version negotiation wire protocol, minimum version enforcement, extension registry. Current content is 10 lines of aspiration. Needs a full section.

2. **Governance wire protocol.** Spec §5.9 defines governance actions and the GovernanceEngine interface, but doesn't specify the wire protocol: how is a proposal transmitted? How are votes collected? How is execution triggered? What are the message types? Currently, governance is defined at the semantic level but not at the wire level.

3. **MessagePack field ordering.** The protocol spec must define canonical field ordering for serialization determinism. Current behavior is Rust serde struct definition order, but this is an implementation artifact, not a protocol choice.

4. **Formal wire format definitions.** All message types need language-agnostic notation. See §5 of this plan.

5. **Multi-key architecture wire format (expanded by ADR-039).** The multi-key identity architecture (Identity Key `#0` / Human Signing Key `#active` / Pre-Rotation Key / Agent Signing Key `#agent`) is a novel contribution described in prose (§3.9, §3.10, §4.2, §4.5, ADR-039) but lacks formal specification. The protocol spec must define:
   - Pre-rotation key commitment format (how the hash is encoded in the DID document)
   - Key rotation authorization chain (how Human Signing Key proves authorization by Identity Key)
   - DID document structure showing all verification methods (`#0`, `#active`, `#agent`) and their service endpoint types
   - Key rotation wire message format
   - Rotation under compromise: the pre-rotation recovery protocol
   - **Agent Signing Key (`#agent`) verification method format** in DID document
   - **Self-delegation UCAN wire format:** `iss == aud` with `fct.scp_key_scope: "#agent"`, `signing_key_id` in UCAN header
   - **`signing_key_id` field** in InnerEnvelope, ScpCredential, SenderKeyEpochAdvance — how it's serialized and validated
   - **Inner signature preimage** updated to include `signing_key_id` — must match between spec §9.8.1 and ADR-039
   - **`ScpKeyCustodyAttestation`** DID document service entry format
   - **`ScpCustodyViolationAttestation`** format for permanent violation logging
   - **Permission category definitions:** Category A (`#0` only), Category B (user-configurable), Category C (context-configurable)
   - **`MintSpendingParams` refactoring:** `{ did, key_scope }` replaces `{ issuer_did, agent_did }` — wire format change in §19

   This is critical because the multi-key architecture and shared-DID model are among SCP's most significant novel contributions — they must be specified precisely enough for independent implementation.

### 7.2 Important Gaps (P1 — should be filled for completeness)

5. **Conformance requirements document.** What does a "conforming SCP implementation" mean? What is required vs optional? MLS has clear conformance language. SCP needs the same.

6. **Protocol evolution mechanism.** How does the protocol change over time? Needs a proposal format (like MSCs, BIPs, SEPs) and a process.

7. **Language-neutral test vectors.** See §6 of this plan.

8. **BlobStore interface normalization.** Spec says "BlobStore" with `store()` computing blob_id; code says "BlobStorage" with caller-provided blob_id. Protocol spec must define one canonical interface.

### 7.3 Desirable Gaps (P2 — strengthens the spec)

9. **Formal security proofs.** Formal analysis of the composed construction (MLS + sender keys + UCAN + Merkle) would be the strongest validation signal.

10. **IANA-style registry.** If the protocol is submitted to IETF, certain values need registry allocation: capability categories, governance action types, event types, DID service endpoint types.

11. **Interoperability test suite.** Beyond test vectors, a runnable interop test suite (like MLS interop events) that tests cross-implementation communication.

---

## 8. Extraction Process

### Phase 1: Preparation (1 week)

1. **Resolve open conflicts** (BlobStore naming, field ordering, .well-known/scp handles field)
2. **Fill spec 13** (versioning) with concrete protocol
3. **Define governance wire protocol** for spec 5.9
4. **Choose wire format notation** (TLS presentation language for crypto, annotated tables for application)

### Phase 2: Document Structure (1 week)

5. **Create the modular document set** (14 documents per §4 of this plan)
6. **Write document boilerplate** (abstract, status, requirements language, references)
7. **Define cross-reference scheme** between documents

### Phase 3: Content Extraction (3-4 weeks)

For each spec file, following the classification in §2 of this plan:

8. **Extract normative content** to the target document
9. **Replace Rust code blocks** with language-agnostic notation
10. **Remove implementation references** (crate paths, Rust traits, module layout)
11. **Add wire format definitions** using TLS presentation language or annotated tables
12. **Preserve RFC 2119 language** — it's already there
13. **Cross-reference** between documents where specs reference other specs
14. **Flag any ambiguity** that only the Rust code resolves (these are spec gaps that must be filled with prose)

Processing order (dependencies first):
1. SCP Core (specs 01, 02, 04, 05) — defines fundamental concepts
2. SCP Identity (spec 03) — defines identity model
3. SCP Security (spec 09) — defines security properties
4. SCP Transport (spec 10) — defines wire protocol
5. SCP Trust (spec 07) — references identity and security
6. SCP Cross-Context (specs 06, 12) — references contexts and transport
7. SCP Persistence (spec 17) — references contexts and transport
8. SCP Addressability (spec 18) — references identity and transport
9. SCP Addressing (spec 22) — references identity and discovery
10. SCP Economic (spec 19) — references contexts and governance
11. SCP Provenance (spec 24) — references cross-context
12. SCP Sync (spec 23) — references transport and MLS
13. SCP Versioning (spec 13) — written fresh
14. SCP Conformance (spec 16) — references all of the above

### Phase 4: Wire Format Definitions (2-3 weeks, parallel with Phase 3)

15. **Define all message types** in TLS presentation language:
    - InnerEnvelope, OuterEnvelope, BroadcastEnvelope
    - Relay protocol messages (PUBLISH, SUBSCRIBE, QUERY, DELETE, SUBSCRIBE_ACK, etc.)
    - SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyResponse
    - GovernanceProposal, GovernanceVote, GovernanceExecution
    - WrappedContent, WrappedCek
    - All 24 GovernanceAction variants
    - All event types (MemberJoined, RoleAssigned, MessageSent, etc.)
    - Context creation parameters
    - Tool registration record
    - UCAN token format (reference UCAN spec, define SCP-specific claims)

16. **Define all key derivation operations**:
    - Routing ID from context key (HKDF)
    - DID routing ID (SHA-256("scp:did:" || did_string))
    - Metadata routing ID (SHA-256(context_id || "scp-metadata"))
    - Broadcast routing ID (SHA-256(context_id))
    - Sender key wrapping (HPKE, domain "scp-sender-key-v1")
    - Content key wrapping (AES-256-KW)
    - Access key wrapping (HPKE, domain "scp-access-key-v1")
    - AAD construction (context_id || sender_did || sequence_number)
    - Domain separation strings (enumerate all)

17. **Define DID-specific wire formats**:
    - DID document structure (JSON-LD for relay layer, DNS packet for DHT layer)
    - Multi-key architecture: Identity Key (`#0`), Human Signing Key (`#active`), Pre-Rotation Key commitment, Agent Signing Key (`#agent`)
    - `signing_key_id` field in InnerEnvelope, ScpCredential, SenderKeyEpochAdvance
    - Inner signature preimage with `signing_key_id` (per ADR-039)
    - Self-delegation UCAN format (`iss == aud`, `fct.scp_key_scope`)
    - `ScpKeyCustodyAttestation` DID document service entry
    - `ScpCustodyViolationAttestation` format
    - `MintSpendingParams` updated format (`{ did, key_scope }` replacing `{ issuer_did, agent_did }`)
    - Key rotation authorization message
    - BEP44 signed mutable item format (for DHT publishing)
    - DID document service endpoint types (SCPRelay, IdentityPrivateState, etc.)
    - z-base-32 encoding specification (for DID string ↔ Ed25519 public key conversion)

### Phase 5: Test Vectors (2 weeks, parallel with Phase 4)

17. **Generate test vectors** from the reference implementation for each category in §6.1
18. **Verify test vectors** are reproducible from the spec alone (have someone implement from the spec, not the code)
19. **Package test vectors** as JSON files alongside the spec documents

### Phase 6: Review and Validation (2 weeks)

20. **Internal review:** Does the extracted spec fully describe the protocol? Can an independent developer implement from it?
21. **Cross-check:** For every normative requirement in the extracted spec, verify the reference implementation conforms
22. **Gap audit:** For every feature in the reference implementation, verify it traces to a normative requirement in the extracted spec
23. **Security review:** Have the security analysis sections independently reviewed

---

## 9. What Stays in the Current Docs

After extraction, the current `.docs/` directory retains its role as the **reference implementation documentation**:

| Artifact | Post-Extraction Role |
|----------|---------------------|
| `.docs/specs/` | Internal design docs for the reference implementation. May diverge from protocol spec where implementation makes different choices (naming, API shape) while remaining conformant. |
| `.docs/adrs/` | Implementation architecture decisions. Protocol-level decisions are now in the protocol spec. |
| `.docs/architecture.md` | Engineering blueprint for the Rust SDK. Unchanged. |
| `.docs/sketch.md` | SDK API surface design. Unchanged. |
| `.docs/standards/` | Coding standards for the reference implementation. Unchanged. |
| `.docs/scaffold/` | Per-language build guides. Unchanged. |

The protocol spec becomes the normative authority. The current docs become the implementation companion. When they conflict, the protocol spec governs.

---

## 10. Success Criteria

The extraction is complete when:

1. **Independence test:** A competent developer unfamiliar with the Rust codebase can read the protocol spec and implement a conforming SCP client in their language of choice without consulting the Rust source.

2. **Completeness test:** Every protocol-level behavior in the reference implementation traces to a normative requirement in the protocol spec. No behavior is defined only in code.

3. **Precision test:** Every wire format, message type, state machine, and key derivation is defined precisely enough that two independent implementations produce byte-identical output for the same input.

4. **No Rust test:** The protocol spec contains zero Rust syntax, zero crate paths, zero module names, zero trait definitions. Language-agnostic throughout.

5. **Conformance test:** The protocol spec defines what "conforming" means, and the reference implementation demonstrably conforms.

6. **Test vector test:** Language-neutral test vectors exist for all critical protocol operations, and both the reference implementation and at least one independent implementation pass them.
