# SCP Status Audit — From Spec to Implementation

**Date:** February 22, 2026
**Purpose:** Classify every feature/mechanism in the spec as ready, needs cleanup, or blocked. Identify missing specifications.
**Source material:** .docs/specs/, sketch.md, architecture.md, planning-session-06.md, open-questions.md

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
| **Contexts — Definition** | spec §5.1 | Ready | Cryptographic entities (one MLS group each), spaces not actors, runtime objects not infrastructure, where apps live. Comprehensive anchor for all context subsections. |
| **Contexts — Creation** | spec §5.1–§5.2 | Ready | By accountable identities only. Template-based (primary) or explicit params (advanced). |
| **Contexts — Capability ceiling** | spec §5.3 | Ready | Open question on mutability noted but not blocking — implement as immutable first (stronger security). |
| **Contexts — Tools** | spec §5.4 | Ready | Stateless, schema'd, testable, operator-attributed. MCP-compatible JSON Schema. Schema constraints: no unbounded string-only interfaces, minimum two distinct fields (§9.2.1). |
| **Contexts — Roles** | spec §5.5 | Ready | Visible before opt-in, non-negotiable, custom roles supported. |
| **Contexts — Membership** | spec §5.6 | Ready | One agent per human per context. |
| **Contexts — Metadata** | spec §5.7 | Ready | Full legibility before opt-in. Includes template ID, tool interface count, nesting-specific fields for child contexts. |
| **Contexts — TTL** | spec §5.10 | Ready | Set at creation, extension requires all-party consent, hard upper bound. Optional — contexts without TTL persist indefinitely (apps live in contexts). |
| **Contexts — Memory scope** | spec §5.11 | Ready | Ephemeral (destroy keys + delete ciphertext), summary, full. Decided in session 06 §1.5. |
| **Contexts — Templates** | spec §5.12 | Ready | 4 well-known templates (bilateral-ephemeral, bilateral-persistent, coordination, group-discussion). Protocol constants, not user-extensible. Template in metadata enables single-check evaluation. SDK convenience surface in sdk-common.md. |
| **Contexts — Auto-accept policies** | spec §5.12.2 | Ready | Local SDK policies for automatic context acceptance. Hard rule: never auto-accept tool-bearing contexts. Rate-limited. |
| **Contexts — Creation as runtime op** | spec §5.12.4 | Ready | ~5-15ms local, ~200ms wall clock. Invitation bundling (metadata + MLS Welcome in one delivery). Computational and network profiles specified. |
| **Contexts — Standing bilateral contexts** | spec §5.12.6 | Ready | Bilateral-persistent contexts as contact graph. Zero idle cost. SDK `standing_channel()` get-or-create. Persist across restarts. |
| **Contexts — Nesting** | spec §5.13 | Ready | Parent-child relationships. Single-parent (sub-space) and multi-parent (governed bridge). 8 subsections: ceiling inheritance (intersection), membership eligibility (continuous), creation (intrinsic tool calls, content-hash matching), parent governance config (configurable per-parent, immutable after creation, `.evict_unique_members` / `.cascade_close` / `.preserve_membership`), lifecycle coupling (no orphans, TTL inheritance), metadata/legibility, mechanism interactions, depth limit (protocol constant, suggested 3). Cryptographic binding via MLS `group_context` extensions. |
| **Contexts — Nesting crypto binding** | spec §5.13.3, §9.7.1 | Ready | Parent context IDs + governance config hash in MLS `group_context` extensions. Lineage unforgeable (different parents = different `group_id`). Two independent verification paths (MLS identity + event log). |
| **Cross-context — Agent isolation** | spec §6.1 | Ready | Absolute at protocol level. Two mechanisms for boundary crossing: tool interfaces (asymmetric) and multi-parent children (symmetric). |
| **Cross-context — Tool interfaces** | spec §6.2 | Ready | Context governs, not agents. Bidirectional consent. Chain depth limit (default: 3). Schema constraints. Stateful sessions with optional TTL and per-caller cap (default: 5). Decided in session 06 §1.4. |
| **Cross-context — Two-tier model** | spec §6.3 | Ready | Shared contexts for lightweight comms, tool interfaces for formal data exchange. Explicit framing of the two communication tiers with different overhead. |
| **Cross-context — Protocol-level discovery** | spec §6.2.2 | Ready | DID document capabilities + discovery contexts with standard tool schemas (agent_search, agent_register, agent_deregister). Two-tier model: writers (MLS, bounded ~500) + readers (DID-authenticated, unbounded). Bootstrap via SDK defaults. Unified SDK search API. |
| **Cross-context — Human as bridge** | spec §6.3 | Ready | Local coordination, no network mechanism needed. |
| **Trust — Four-layer model** | spec §7.1 | Ready | Protocol enforcement → behavioral validation → attestation authenticity → trust evaluation. |
| **Trust — Protocol enforcement (L1)** | spec §7.2 | Ready | UCAN validation on every action. Zero-trust. |
| **Trust — Behavioral validation (L2)** | spec §7.3 | Ready | Event logs, behavioral records, tool verification, challenge-response, threshold attestations, consequence mechanisms. |
| **Trust — Attestation authenticity (L3)** | spec §7.4 | Ready | Common envelope, signature verification, revocation, renewal. |
| **Trust — Trust evaluation (L4)** | spec §7.5 | Ready | Agent-level judgment. Transitive trust. Decay. |
| **Trust — Provenance** | spec §7.6–§7.7 | Ready | Core principle #3. Format specified with `chainDepth` and `chainPath` fields for cross-context hop tracking. Absence is signal. Decided in session 06 §1.3. |
| **Products — App model** | spec §8.1–§8.3 | Ready | Apps are composites, not protocol entities. Portability via protocol state. |
| **Products — Capability declarations** | spec §8.4 | Ready | Machine-readable manifests. Declarative. |
| **Products — MCP compatibility** | spec §8.5 | Ready | SCP agent as MCP server. Tool schemas MCP-compatible. |
| **Security — Core invariants** | spec §9.1 | Ready | 7 invariants defined. Invariant #5 updated for dual cross-context mechanisms (tool interfaces + multi-parent children). |
| **Security — Tool interface abuse vectors** | spec §9.2.1 | Ready | 9 vectors with concrete mitigations: broad-schema covert channels, hub aggregation, chain amplification, session exhaustion, context proliferation, human bottleneck, governance capture, caller/tool asymmetry, shadow channel incentivization. |
| **Security — Sybil resistance** | spec §9.3 | Ready | Device attestation + earned capacity + context-level thresholds. |
| **Security — Systemic defense** | spec §9.4 | Ready | Validate > trust. Behavior topology. Consequences > character. |
| **Security — Crypto primitives** | spec §9.5 | Ready | Single ciphersuite. Ed25519, MLS_128, HPKE, SHA-256. |
| **Security — Identity verification** | spec §9.6 | Ready | did:dht self-certification, did:web mitigations, relay list auth, first-contact bootstrapping. |
| **Security — MLS integration** | spec §9.7 | Ready | 1:1 context↔group mapping. Forward secrecy. PCS (24h default). Key lifecycle. |
| **Security — Message security** | spec §9.8 | Ready | Two integrity checks (inner Ed25519 signature + MLS membership_tag, both inside encryption, member-only verifiable). Three-layer replay prevention. Sequence validation with reorder buffer (accept-and-reorder, gap detection, suppression alerts). UCAN expiry ≤ 24h constraint (§9.5). |
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

### Spec Cleanup — Completed

All spec cleanup from session 06 decisions has been completed:

| Area | Status |
|------|--------|
| Direct agent-to-agent primitive — considered and rejected, all references removed from spec, sketch, and architecture | ✅ Complete |
| Metadata privacy architecture (spec §9.10) | ✅ Rewritten — 10 subsections covering full privacy architecture |
| Sender-side key layer (spec §9.16) | ✅ Written — 5 subsections covering key architecture, distribution, block protocol, blocking vs removal, forward secrecy |
| Envelope signature scope (spec §9.5) | ✅ Updated for minimal outer envelope |
| Push notification opacity (spec §10.7) | ✅ Mandated fully opaque |
| Wire format (sketch §11) | ✅ Updated for minimal outer envelope |
| "What's Not Here Yet" sections | ✅ Updated in both spec and sketch |
| Architecture MVSDK tables (§5) | ✅ Updated |
| Architecture build phases (§6) | ✅ Updated |
| Architecture data flows (§2.2) | ✅ Updated for transport independence |
| Architecture data flow diagram (§2.2) | ✅ Rewritten — reflects actual encryption stack (inner sign → sender-key → pad → MLS → minimal outer envelope) |
| Architecture discovery engine (§3.2) | ✅ Updated — DID doc capabilities, discovery contexts, unified search, bootstrap |
| Sender-side key HPKE wrapping (spec §9.16.2-3) | ✅ Fixed — keys HPKE-encrypted per recipient, block observability acknowledged |
| Envelope integrity (spec §9.8.1) | ✅ Fixed — both checks now inside encryption, member-only verifiable |
| Dedup cache key (spec §9.8.2) | ✅ Fixed — uses SHA256(encrypted_blob) instead of SHA256(envelope_signature) |
| UCAN nonce pruning (spec §9.5) | ✅ Added — token expiry ≤ 24h constraint |
| Subscription mixing (spec §9.10.8) | ✅ Removed — decoy routing IDs get zero traffic, mechanism broken |
| Cover traffic (spec §9.10.6) | ✅ Changed from mandatory to configurable, default on |
| Discovery expansion (spec §6.2.2) | ✅ Expanded — DID doc capabilities, discovery contexts, standard schemas, bootstrap, SDK unification |
| Discovery API (sketch §13) | ✅ Added — scp.discover, scp.register, bootstrap APIs |

### Context Architecture Session — Completed

Designed and specced context templates, standing channels, context nesting, and cross-context abuse mitigations. Updated spec, sketch, sdk-common, and ADR phase-2.

| Area | Status |
|------|--------|
| Context templates — 4 well-known templates (spec §5.12.1) | ✅ Written |
| Auto-accept policies (spec §5.12.2) | ✅ Written |
| SDK convenience surface (spec §5.12.3, sdk-common.md) | ✅ Written |
| Context creation as runtime operation — computational/network profiles (spec §5.12.4) | ✅ Written |
| Context lifecycle in application architecture (spec §5.12.5) | ✅ Written |
| Standing bilateral contexts / contact graph (spec §5.12.6) | ✅ Written |
| Context nesting — 8 subsections (spec §5.13) | ✅ Written |
| Cryptographic binding — parent IDs + governance hash in MLS group_context (spec §5.13.3, §9.7.1) | ✅ Written |
| Tool interface abuse vectors — 9 vectors with mitigations (spec §9.2.1) | ✅ Written |
| DataProvenance chainDepth/chainPath fields (spec §7.7.1) | ✅ Written |
| Session TTL optional, per-caller session cap (spec §6.2.1, §9.2.1) | ✅ Written |
| Schema constraints for tool interfaces (spec §6.2) | ✅ Written |
| Two-tier interaction model framing (spec §6.3) | ✅ Written |
| §5.1 enriched as comprehensive context anchor | ✅ Written |
| Cross-references updated (§2.1, §2.3, §6.1, §6.3, §9.1, §9.2) | ✅ Updated |
| §5.7 metadata — template ID, tool interface count, nesting fields | ✅ Updated |
| §16 open questions updated | ✅ Updated |
| ADR phase-2 — TemplateId enum, ChildContextCreate capability, nesting.rs, templates.rs | ✅ Updated |
| sketch.md — template creation API, child creation API, standing channel API, auto-accept API, inspect metadata, cross-context tool interface, DataProvenance, wire format, "What's Not Here Yet" | ✅ Updated |
| sdk-common.md — context creation section, standing channels | ✅ Written |

### Post-Review Fixes — Completed

Five review agents (architecture, alignment, bug-catcher, simplifier, explorer) audited the full repository. Three critical architectural bugs, several consistency issues, and stale references were identified and fixed:

| Area | Status |
|------|--------|
| HPKE wrapping key rotation (spec §9.16.1-2, ADR-007) | ✅ Fixed — stable wrapping keypair per member per context, published as LeafNode extension `scp_wrapping_key`, does not rotate on MLS epoch advances |
| Strict sequence rejection (spec §9.8.5) | ✅ Fixed — replaced with accept-and-reorder buffer semantics, gap detection with 30s timeout, suppression alerts, 100-message buffer bound |
| Discovery context scalability (spec §6.2.2) | ✅ Fixed — two-tier model: writers (MLS members, bounded ~500) and readers (DID-authenticated, unbounded). Registration via tool endpoints, not MLS join |
| ADR-007 sender key distribution mismatch | ✅ Fixed — functions 4-5 updated to single MLS message with per-recipient HPKE payloads using stable wrapping key |
| ADR-004 missing `recipient_hint` in PUBLISH | ✅ Fixed — added optional `recipient_hint` for directed delivery |
| DataProvenance `.referral` variant (spec §7.7.1, sketch §12) | ✅ Removed — stale reference |
| handoff-plan.md conditionality | ✅ Updated |
| spec §16 resolved items | ✅ Marked — event log format (ADR-011), transport layer specifics (ADR-004/005) marked resolved |
| HSM pseudonym derivation (spec §9.10.4) | ✅ Fixed — added HSM-internal HMAC fallback and non-HSM pseudonym derivation key option |
| Conformance test descriptions (sdk-common.md) | ✅ Updated — added wrapping key lifecycle and reorder buffer test descriptions |

---

## B. Open Questions — All Resolved

All 10 questions from open-questions.md have been resolved. Decisions documented in `decisions.md` and written into the spec.

| # | Question | Decision | Written Into |
|---|----------|----------|-------------|
| **1** | Push notification opacity | Fully opaque, mandatory | spec §10.7 |
| **2** | Envelope format metadata | Minimal outer envelope | spec §9.10.2, §9.5, sketch §11 |
| **3** | Message size normalization | Fixed bucket padding (256B–256KB) | spec §9.10.3 |
| **4** | Direct agent-to-agent primitive | Considered and rejected — cross-context interaction uses tool interfaces (§6.2), multi-parent child contexts (§5.13), and standing bilateral contexts (§5.12.6) | spec §5.12, §5.13, §6.2 |
| **5** | Sender-side key layer | AES-256 symmetric, HPKE-wrapped per-recipient distribution, mutual block, block observability acknowledged | spec §9.16 |
| **6** | Connection privacy | Persistent connections + TLS | spec §9.10.5 |
| **7** | Per-context pseudonyms | HKDF-derived, inside-encryption verification | spec §9.10.4 |
| **8** | Cover traffic | Configurable, default on (constant-rate on persistent connections) | spec §9.10.6 |
| **9** | DID resolution privacy | Local DHT node + caching | spec §9.10.7 |
| **10** | Relay query privacy | Pseudonyms + partitioning (subscription mixing removed — broken mechanism) | spec §9.10.8 |

---

## C. Missing Specifications

Designs that need protocol-level specification to complete. All open questions are resolved — remaining gaps are implementation details.

### Critical Path (blocks Phase 1)

| Missing Spec | Status | What's Needed |
|-------------|--------|---------------|
| **SCP native relay protocol** | Not designed | Full protocol spec: message format (minimal outer envelope is specified in §9.10.2), subscription mechanism, delivery receipts, deletion requests, blob TTL enforcement, error codes. The simplest possible store-and-forward relay. ADR-004 captures implementation approach. |
| **Transport abstraction trait** | ADR written (ADR-005) | Formal Rust trait definition with async interface. ADR provides the approach; trait definition is straightforward to implement. |

### Critical Path (blocks Phase 2)

| Missing Spec | Status | What's Needed |
|-------------|--------|---------------|
| **Context lifecycle state machine** | ADR written (ADR-008) | Formal state machine: states, transitions, invariants. ADR provides the approach. |
| **Event log format** | ADR written (ADR-011) | Concrete format: entry structure, hash chain, proof format, pruning rules. |
| **UCAN capability schema** | ADR written (ADR-016) | Concrete capability types, delegation chain rules, revocation list format, nonce generation. |
| **Stateful tool session protocol** | ADR written (ADR-010) | Session ID format, state management, TTL enforcement, wire format. |

### Important but not blocking early phases

| Missing Spec | Status | What's Needed |
|-------------|--------|---------------|
| **Behavioral record schema** | Conceptual | Formal schema: field names, types, derivation rules, aggregation, privacy levels. |
| **Offline/sync strategy** | Highest-risk design gap | MLS group state sync after extended offline. Pending proposal accumulation. Group state reset triggers. |
| **Summary generation protocol** | Conceptual | Pre-close summary generation, verification window, format, both-party verification flow. |
| **Governance interface** | Conceptual | Minimum viable interface: propose/approve/reject. Custom governance model registration. |
| **Context promotion** | Not designed | Ephemeral→persistent: new context referencing old, or same context with TTL removed? |
| **Capability declaration format** | Conceptual | JSON schema for app manifests. LLM-parseable. |

---

## D. Implementation Readiness by Build Phase

### Phase 1 — Crypto Proof (ADRs 001–007)

| Component | ADR | Ready? | Blockers |
|-----------|-----|--------|----------|
| MLS wrapper (OpenMLS) | ADR-001 | **Yes** | None |
| Envelope creation/signing/verification | ADR-002 | **Yes** | Envelope format now specified (§9.10.2, sketch §11) |
| DID creation (did:dht) | ADR-003 | **Yes** | None |
| SCP native relay protocol + adapter | ADR-004 | **Mostly** | Relay protocol needs detailed spec (envelope format is done) |
| Transport abstraction trait | ADR-005 | **Yes** | None |
| In-memory platform adapter (testing) | ADR-006 | **Yes** | None |
| Sender-side key layer | ADR-007 | **Yes** | Spec written as §9.16. Stable wrapping keypair specified (§9.16.1) — wrapping key does not rotate on MLS epoch advances. ADR-007 functions 4-5 updated to match. |

**Phase 1 status:** All ADRs written. All open questions resolved. Three critical architectural bugs fixed in post-review: (1) sender-side key wrapping now uses stable wrapping keypair instead of MLS LeafNode key, (2) sequence validation now uses accept-and-reorder instead of strict rejection, (3) ADR-007 sender key distribution aligned with spec. Relay protocol detail is the only remaining design gap.

### Phase 2 — Context + Transport (ADRs 008–012)

| Component | ADR | Ready? | Blockers |
|-----------|-----|--------|----------|
| Context lifecycle state machine | ADR-008 | **Yes** | None |
| Role assignment / capability ceiling | ADR-009 | **Yes** | None |
| Tool registration and invocation | ADR-010 | **Yes** | None |
| Verifiable event log (Merkle tree) | ADR-011 | **Yes** | None |
| Multi-transport routing | ADR-012 | **Yes** | None |

**Phase 2 status:** All ADRs written. Context templates (§5.12), nesting (§5.13), and standing channels (§5.12.6) fully specced. `nesting.rs`, `templates.rs` added to ADR-008 file scope. `ChildContextCreate` capability added to ADR-009. No blockers.

### Phase 3 — Python SDK (ADRs 013–016)

| Component | ADR | Ready? | Blockers |
|-----------|-----|--------|----------|
| PyO3 bridge layer | ADR-013 | **Yes** | Depends on scp-core (Phase 1+2) |
| Python SDK wrappers | ADR-014 | **Yes** | Depends on ADR-013 |
| MCP adapter | ADR-015 | **Yes** | Depends on ADR-013, ADR-014 |
| UCAN validation | ADR-016 | **Yes** | Depends on ADR-013 |

**Phase 3 status:** All ADRs written. Blocked only on Phase 1+2 completion.

---

## E. Recommended Next Steps

All open questions are resolved. All ADRs are written. Post-review architectural fixes completed. Context templates, nesting, standing channels, and cross-context abuse mitigations fully specced. The project is ready for implementation.

1. **Design SCP native relay protocol detail** — the one remaining design gap. Envelope format is specified; relay needs subscription mechanism, delivery receipts, deletion requests, error codes.
2. **Begin Phase 1 implementation** — start with MLS wrapper (ADR-001) and DID creation (ADR-003) in parallel, then transport trait (ADR-005), envelope (ADR-002), relay (ADR-004), sender-side keys (ADR-007). Note: sender-side key layer now requires stable wrapping keypair implementation (LeafNode extension `scp_wrapping_key`); sequence validation requires reorder buffer with gap detection.
3. **Phase 2 implementation** — context lifecycle (ADR-008), then roles (ADR-009), tools (ADR-010), event log (ADR-011), multi-transport (ADR-012). Note: Phase 2 now includes context templates (`templates.rs`), context nesting (`nesting.rs` with MLS `group_context` extensions for cryptographic binding), standing bilateral contexts, auto-accept policies, `ChildContextCreate` capability, and tool interface schema constraints. Discovery contexts use two-tier model (writer MLS members + reader DID-authenticated queries).
4. **Phase 3 implementation** — PyO3 bridge (ADR-013), Python wrappers (ADR-014), MCP adapter (ADR-015), UCAN validation (ADR-016).
5. **Address remaining design gaps as they arise** — offline/sync strategy, behavioral record schema, governance interface, context promotion, coordinated child creation protocol detail (content-hash matching, proposal timeout).
