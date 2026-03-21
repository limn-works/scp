---
name: Architectural Refactor Plan Adversarial Analysis
description: BLACK-301 through BLACK-311 — attack narratives targeting the scp-protocol extraction, ContextManager decomposition, bridge dedup, and wiring sprint. Covers facade re-export divergence, Phase B locking TOCTOU, asymmetric pipeline wiring, OnceLock-to-BridgeInstance split-brain.
type: project
---

## Refactoring Plan Adversarial Review (2026-03-21)

Plan file: `~/.claude/plans/cozy-fluttering-rose.md`
Related issues: #1446, #1448, #1447, #1549, #1529-#1552

### CRITICAL Findings

**BLACK-301: Facade re-export masking divergence (Part 1)**
- If `pub mod trust;` and `pub use scp_protocol::trust;` coexist in scp-core/lib.rs, two different trust modules resolve depending on import path
- Compiler does not error on this; runtime crypto divergence
- Mitigation: CI check that no moved module has both local `mod` and re-export

**BLACK-303: DID/SigningKeyId serde divergence (PR 0a)**
- SigningKeyId has custom serde impls (serializes as "#active"/"#agent", not "Active"/"Agent")
- Move to scp-primitives must include all custom serde impls or wire format breaks
- DID's `#[serde(transparent)]` must be preserved

**BLACK-305: Phase B per-context locking breaks TOCTOU elimination (Part 2)**
- send_message Phase 1 locks context "foo", drops lock, Phase 3 re-locks
- With DashMap, between phases: close "foo" + create new "foo" = Phase 3 operates on wrong context
- Fix: generation counter on PerContextState, verified in Phase 3

**BLACK-308: BridgeInstance + OnceLock dual path (Part 3)**
- PyO3 has 13+ OnceLock statics; cannot be atomically migrated to BridgeInstance
- Window where some ops go through OnceLock (old state) and some through BridgeInstance (new state)
- Fix: feature flag for atomic switchover, or BridgeInstance wraps OnceLocks

**BLACK-310: Asymmetric pipeline wiring (Wiring Sprint)**
- Anti-replay on receive with sequence=0 on send = either rejects all or checks nothing
- Signature verification on receive without creation on send = breaks all legitimate messages
- Fix: mandate send+receive wiring in same PR for each pipeline step

### HIGH Findings

**BLACK-302: WASM migration window (Part 1 Phase 3)**
- Between scp-protocol creation and WASM migration, security fixes don't reach WASM
- No conformance tests for sender key AAD or UCAN validation (only Merkle + schema covered)

**BLACK-304: Orphaned dead code wired wrong (PR 0c/0d)**
- seal_envelope/open_envelope are dead code that splits across crates
- When #1534 wires them, developer might create non-MLS version in scp-protocol
- No compile-time guard preventing this

**BLACK-307: Governance timeout task loses context reference (Part 2 Phase B)**
- Spawned tasks hold Arc clones of old HashMap
- Phase B replaces HashMap with DashMap, tasks see stale empty state
- No task tracking (JoinSet) to cancel and re-spawn

**BLACK-311: Merge conflict drops security checks (Wiring Sprint)**
- 5 PRs all modify same ~300-line messaging.rs
- Conflict resolution can silently revert previous PR's security checks

### "Zero Downstream Breakage" Claim Assessment

- Part 1 Phase 2 claim: CONDITIONAL — holds only if original mod declarations are deleted, not augmented. pub(crate) items in moved modules will break scp-core internal callers.
- Part 2 Phase A claim: TRUE — organizational split has no semantic impact in Rust.
- Part 2 Phase B claim: FALSE — changes lock granularity, iteration order, Arc lifetime semantics, and breaks background task references.
