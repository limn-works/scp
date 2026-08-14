---
name: adr062-relay-querier-concurrent-refactor
description: Alignment review of RealMultiRelayQuerier concurrent JoinSet refactor (ADR-062 011a follow-on) @ 4233a6042 — APPROVED, 2 minor spec-reconciliation observations
metadata:
  type: project
---

# RealMultiRelayQuerier concurrent JoinSet refactor @ `4233a6042` (2026-08-02) — APPROVED

Follow-on to [[adr062_slice011a_relay_querier]]. `crates/scp-identity/src/relay_querier.rs` changed sequential→concurrent relay fan-out via `tokio::task::JoinSet`, each task wrapped in `tokio::time::timeout(PER_RELAY_TIMEOUT=5s)`. Selection = highest-seq valid across all relays, order-independent (strict `>`, first-received retained on tie — acceptable because same-seq records are byte-identical signed payloads).

**Alignment verdict facts:**
- §3.10.8:950 REWRITTEN to "Concurrent query across all relay URLs plus DHT, each relay guarded by an independent per-relay timeout." Code matches exactly. "concurrent" appears in BOTH spec (§3.10.8:950) and code (doc line 58, comment line 148). ✓
- `MAX_CANDIDATES_PER_RELAY = 16` (code line 43) == §3.10.2:828 `limit: N (implementation: 16)` == §3.10.8:951 cap. ✓ NOTE two enforcement points, both 16: spec `limit:16` is relay-side QUERY limit; code applies `.take(16)` client-side defensively regardless of relay return (strictly stronger).
- **Artifact flow: spec + code landed in the SAME commit `4233a6042`** (review round 2). Atomic reconciliation — no spec/code drift. Prior commits: `793203e3d` (round 1 highest-seq), `f79c1c8e4` (011a substrate).

**2 MINOR observations (non-blocking, both spec-reconciliation not code-defect):**
1. §3.10.4:885 "targets relays in priority order: own relays... **then** bootstrap relays" retains SEQUENTIAL-dispatch wording NOT reconciled with the new concurrent model. §3.10.8 was updated to "concurrent" but §3.10.4 wasn't. NOT a code violation: composer receives a FLAT `relay_urls` list; priority-order relay SELECTION (own-vs-bootstrap) is a CALLER concern (resolver assembles list). Priority's set-inclusion meaning survives; only temporal "then" is stale. Priority was never load-bearing for correctness (§3.10.7 highest-seq wins regardless of order; same-seq byte-identical). Recommend clarifying §3.10.4:885 that dispatch is concurrent, priority governs inclusion.
2. §3.10.4:898 "Each layer query has a **5-second** timeout" vs resolver.rs:219 `LAYER_TIMEOUT = 10s`. Pre-existing spec/code drift, ADJACENT (resolver.rs, not the composer under review). relay_querier.rs:49 doc comment "outer LAYER_TIMEOUT (10 s)" is ACCURATE to code. Note PER_RELAY_TIMEOUT=5s is NOT pinned to a spec number (§3.10.8 just says "independent per-relay timeout") so it doesn't contradict.
