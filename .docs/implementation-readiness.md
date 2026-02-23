# Implementation Readiness — Known Gaps & Issues

**Date:** February 23, 2026
**Source:** Comprehensive artifact audit of all specs, ADRs, scaffolds, standards, and anchor files.
**Purpose:** Track known design/implementation gaps that agents should be aware of but that do NOT block Phase 1 startup.

---

## Phase 1 — Address During Implementation

### Relay Protocol Wire Format (ADR-004)
ADR-004 defines operations (PUBLISH, SUBSCRIBE, UNSUBSCRIBE, QUERY, DELETE, ACK) but does not specify:
- Serialization format (JSON over WebSocket text frames vs. MessagePack over binary)
- Error response format and codes
- Subscription backfill ordering (oldest-first or newest-first)

**Action:** Finalize during ADR-004 implementation. The envelope format is complete (§9.10.2); only the relay-side protocol framing is missing.

### DID Library Selection (ADR-003)
ADR-003 specifies: evaluate `did-dht` and `veilid-did` crates. If neither is production-ready, implement BEP44 operations directly using the `mainline` or `bittorrent-dht` crate. `did:web` is contingency fallback only.

**Action:** Evaluate during ADR-003 implementation. Decision point, not pre-decided.

### `async-trait` Crate Decision
Rust 2024 supports native `async fn` in traits (RPITIT). The `async-trait` crate is listed as a dependency but may be unnecessary.

**Action:** Decide keep/remove during Phase 1 based on whether dyn-dispatched async traits are needed.

---

## Phase 1–2 Boundary — Address Before Phase 2

### Offline Member MLS Re-Sync
Architecture.md §9 acknowledges this as "the hardest unsolved problem." Members offline for extended periods accumulate pending MLS proposals. Current mitigation: "group state reset" — but trigger conditions, initiation protocol, and context lifecycle during reset are unspecified.

**Action:** Design proposal accumulation strategy and group reset mechanism before Phase 2 context lifecycle work.

### Commit Delivery Assurance Under Adversarial Relays
Relays can suppress MLS Commits. Spec says "publish to all relays with delivery confirmation" but:
- "Delivery confirmation" semantics are undefined (ACK from relay? from recipients?)
- Recovery mechanism for split-brain state (some members got the Commit, some didn't) is unspecified

**Action:** Specify as part of ADR-004 relay protocol or as a separate design document.

### Cover Traffic Parameters
Constant-rate cover traffic is mandatory on persistent connections (Decision 8). Suggested rate: 1 message per 30 seconds. Not finalized. Dummy message format specified (single-byte flag inside encrypted payload) but relay-side distinguishability analysis is incomplete.

**Action:** Finalize rate and validate that dummy messages are indistinguishable to relays.

---

## Phase 2 — Address During Implementation

### Sybil Resistance Enforcement
§9.3 describes three layers (device attestation, earned capacity, context thresholds) but provides no concrete algorithms, thresholds, or enforcement mechanisms. Currently architectural intention only.

**Action:** Specify earned capacity algorithm and threshold defaults during Phase 2 trust/governance work.

### Tool Integrity Verification Execution
§5.4 requires "deterministic testing" of tools but does not specify: who runs tests, execution environment, what constitutes pass/fail, how many agents must verify.

**Action:** Specify during ADR-010 (tools) implementation.

### Compromise Recovery Orchestration
§9.12 lists 6 recovery steps but does not specify ordering constraints, atomicity guarantees, or partial failure handling (e.g., if MLS Update fails in one context but succeeds in others).

**Action:** Specify ordering and failure modes during Phase 2 security hardening.

### UCAN Revocation Mechanism
§9.5 mentions "revocation list" but does not specify: list format, check frequency, or behavior when revocation check fails (network error, stale list).

**Action:** Specify during ADR-009/016 (UCAN) implementation.

---

## Phase 3+ — Not Blocking

### Governance Interface Primitives
Single-admin governance is sufficient for Phase 1–2. The pluggable governance interface for multi-sig/consensus models remains unspecified. See 00-open-questions.md.

### Behavioral Record Schema
§7.3.2 defines derivable facts but the record format (serialization, exchange, verification against source logs) is unspecified. Phase 4+ concern.

### Challenge Suite Standards
§7.3.4 introduces challenge-response verification but doesn't define challenge suites. Phase 4+ concern.

### Summary Generation Protocol
For summary memory scope (§5.11): production, verification, and disagreement handling are unspecified. Phase 3+ concern.

### Bridge Connector Interface
§12 describes bridge semantics but the actual interface contract (method signatures, RPC format, error codes) is not specified. Phase 4+ concern.

---

## Confirmed Clean

The following areas passed audit with no issues:
- All 13 design decisions correctly propagated across specs
- A2A removal is complete — no residual references in split specs
- ADR phasing and dependency ordering — no cycles, build order unambiguous
- Language binding surface area — all 8 languages cover same API
- Cross-language naming — comprehensive table in shared.md, idioms respected
- Scaffold files — exist with real content, standards references are valid
- All well-known templates — consistent with decisions
- Metadata privacy architecture (§9.10) — all 10 decisions correctly implemented
- Sender-side key layer (§9.16) — fully specified including wrapping key lifecycle
