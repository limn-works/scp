# Handoff Plan — From Design Review to Implementation Readiness

**Date:** February 22, 2026
**Purpose:** Instructions for a new agent to continue from where this session left off. The goal is to get SCP from "spec documents" to "ready to write code" as fast as possible.

---

## Context

SCP is a protocol for agent social infrastructure (identity, trust, contexts, encryption, governance, provenance). It currently exists as spec documents only — no code. A comprehensive design review was just completed (planning-session-06.md) which made several architectural corrections and identified 10 open questions.

## Key Files to Read (in this order)

1. **planning-session-06.md** — Summary of ALL decisions and changes from the review. Start here.
2. **open-questions.md** — 10 open questions with detailed analysis and concrete suggestions. These need decisions.
3. **spec.md** — The protocol specification (recently modified)
4. **sketch.md** — API surface sketches (recently modified)
5. **architecture.md** — Engineering blueprint (recently modified)
6. **planning-session-03.md** through **planning-session-05.md** — Design rationale for A2A, technology selection, and security hardening

## Task 1: Comprehensive Status Audit

Create a document (`status.md` or similar) with three sections:

### A. Closed Decisions (ready to implement)
Go through every section of spec.md, sketch.md, and architecture.md. For each feature/mechanism, classify it as:
- **Closed — ready for ADR and implementation.** The design is settled, no open questions block it.
- **Closed — but needs spec cleanup first.** The design is settled but the spec text needs updating (e.g., if A2A is removed, many sections need cleanup).
- **Blocked by open question.** Specify which open question(s) block it.

Key areas to audit:
- Identity (§3): DID creation, key management, attestations, private state
- Agents (§4): Agent model, roles, capabilities
- Contexts (§5): Lifecycle, membership, governance, TTL, memory scope
- Cross-context (§6): Tool interfaces, stateful sessions, isolation
- Trust (§7): Four-layer model, behavioral records, attestations, provenance
- Products/Apps (§8): App manifests, capability declarations
- Security (§9): All of §9.5-§9.15, plus new sender-side blocking (needs §9.16)
- Infrastructure (§10): Transport abstraction, encryption-as-access-control, relay architecture
- Bridges (§12): Bridge adapters, shadow identities
- SDK architecture: Crate structure, FFI layer, language bindings

### B. Open Questions (need decisions)
Reference open-questions.md. For each of the 10 questions, note:
- Which spec sections are blocked by this question
- Whether the suggested answer is sufficient or needs further analysis
- Dependencies between questions

### C. Missing Specifications
Identify anything that needs to be designed that hasn't been yet:
- SCP native relay protocol (decided it should exist, not yet designed)
- Sender-side key layer detailed protocol (direction agreed, needs full spec)
- Stateful tool session wire format and lifecycle
- Envelope format (affected by metadata privacy decisions)
- UCAN capability schema (partially specified in planning-session-04.md)
- Context lifecycle state machine
- Event log format (Merkle tree specifics)
- Behavioral record schema
- Offline/sync strategy (flagged as "hardest unsolved problem")
- Summary generation protocol (for summary memory scope)

## Task 2: Resolve Open Questions

Present the 10 open questions from open-questions.md to Alec for decisions. Each has a concrete suggestion. Alec's preferences:
- Prefers simpler, more elegant solutions
- Never at expense of functionality or attractiveness
- No deferral — everything gets done now, no "v2"
- Wants analysis, not opinions
- Will challenge — expect pushback and be ready to defend or adjust

If Alec confirms the suggestions, write the decisions into the spec immediately.

**Important note on A2A (#4):** If A2A propose/accept is removed (likely), the following sections need cleanup:
- spec.md: §5.12 (remove), §6.1 (remove A2A isolation paragraph), §6.3 (revert to original "human as bridge" framing), §6.4 (remove or simplify to tool-interface-only discovery), §9 A2A threat vectors (remove), §3.6 A2A activity visibility (remove)
- sketch.md: Remove propose/accept/reject APIs, context proposal envelope, introduction tokens, A2A use cases (§14). Keep TTL, memory scope, provenance — those are valuable independent of A2A.
- architecture.md: References to A2A throughout, planning session cross-references
- planning-session-03.md: This entire document is about A2A. It stays as design rationale (documents why A2A was considered and why it was rejected), but its content is no longer active spec.

## Task 3: Write ADRs for Implementation-Ready Components

For each component classified as "Closed — ready for ADR" in Task 1, write an Architecture Decision Record that:

1. States the decision and its rationale (referencing the planning session where it was decided)
2. Specifies the implementation approach (language, libraries, crate, module)
3. Lists dependencies (what must be built first)
4. Defines acceptance criteria (what "done" looks like)
5. Estimates scope (not time — just "this is N files / M functions / etc.")

**Priority order for ADRs (based on architecture.md build phases):**

Phase 1 — Crypto proof (the foundation everything else depends on):
- MLS wrapper (OpenMLS integration)
- Envelope creation, signing, verification
- DID creation (did:dht)
- SCP native relay protocol + adapter
- In-memory key storage (testing platform adapter)
- Sender-side key layer (blocking)

Phase 2 — Context + transport:
- Context lifecycle state machine
- Role assignment and capability ceiling enforcement
- Tool registration and invocation (including stateful sessions)
- Event log (Merkle tree)
- Transport abstraction trait
- Multi-transport routing

Phase 3 — Python SDK:
- PyO3 bridge layer
- Python wrappers (async, type hints)
- MCP adapter (SCP agent as MCP server)
- UCAN validation

## Task 4: Spec Cleanup

Based on decisions from Task 2, update all spec files to reflect the resolved state. This includes:
- Writing resolved open questions into the spec as permanent decisions
- Removing any content that was rejected (e.g., A2A sections if removed)
- Ensuring consistency across spec.md, sketch.md, and architecture.md
- Updating the "What's Not Here Yet" sections in sketch.md and spec.md to reflect current state

## Important Design Principles to Maintain

These came from the review and must be preserved in all future work:

1. **The protocol requires no operator.** Every mechanism must work if no one runs centralized infrastructure.
2. **Provenance is core.** All non-private data carries verifiable origin. The absence of provenance is a signal.
3. **Context governs, not agents.** Cross-context interaction goes through context governance. Agents request; contexts decide.
4. **No deferral.** Metadata privacy, sender-side blocking, transport independence — everything is specced and implemented now. Not later. Not "v2."
5. **Simple over complex.** Prefer elegant, low-overhead solutions. But never sacrifice functionality or security for simplicity.
6. **Transport independence.** No structural coupling to any transport. SCP native relay is canonical but not required.
7. **Blocking != removal.** These are different operations with different cryptographic mechanisms.
8. **Encryption-as-access-control.** Relays are untrusted dumb pipes. The math enforces access, not the relay.
