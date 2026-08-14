---
name: adr062-slice1-dht-e1-review
description: ADR-062 Slice 1 / SCP-CAPINJECT-001 (DHT E1) alignment review — framing-fix APPROVE, one A5 cfg-gating consistency change
metadata:
  type: project
---

# ADR-062 Slice 1 (SCP-CAPINJECT-001, DHT E1) alignment review — 2026-07-15

Branch `feat/adr062-slice1-dht-e1`, diff `9ff9eadde..e54de4fae` (PR #2150). Round-2 full pass (round-1 died on rate-limit). Verdict: **APPROVE-WITH-CHANGES** (1 MEDIUM consistency finding; no security block).

**Why:** Verifies the round-1 finding-E fix (ADR §Non-goals A2↔A4 reframed to honestly disclose self-DID resolution REGRESSES under DhtMode::Disabled default) plus the Slice-1 code.

**How to apply:** If re-reviewing this branch or Slice 6 (G1 severance), the A5 cfg-gating inconsistency below should be reconciled first.

## What PASSED (aligned)
- **Framing fix (item 2) is excellent.** ADR:168 now says the Memory→Disabled default flip is "strictly more honest only for external DIDs" and a "functional regression" for self-DID (co-located governance vote verification inert Slice1→Slice11). Accurate, honest, down-flow (artifact fixed to match reality), NO phantom provenance (it REMOVES an over-claim), no contradiction with §Non-goals A2 / M2 disclosure reasoning / §17.17.3. No stale "not a regression" residue (only the corrected line).
- DisabledDhtClient (scp-dht dht_client/mod.rs:205): publish→Err(DhtError::Disabled) fail-closed, resolve→Ok(None) honest not-found, compiled unconditionally (NOT a nullifier). Matches §17.17.3 + ADR §D-B.
- into_client (common/dht.rs:106) fail-closed: only PkarrDhtClient, no unwrap_or/or_else/InMemory in body. FfiDhtClient::InMemory arm correctly `#[cfg(feature="testing")]` ONLY (A5-compliant, G1-relevant arm).
- Shipped artifacts CLEAN: build-matrix.yml (Python wheel/sdist, napi, uniffi release builds) enable NEITHER testing NOR allow_in_memory_custody. ci.yml added `,testing` ONLY to the Python/TS TEST jobs (sanctioned by ADR A5). Nullifier stays out of shipped graphs.
- Node defaults flipped Memory→Disabled (config.rs:410, self_host.rs:998). construction.md M2 reconciled (grep Memory=0 as fail-safe, Disabled count=4). validate-prd passes (16 files/437 stories). PRD AC edits (typed-Err→Ok(None), scp-testing NORMAL scp-dht/testing dep) match code. matrix DHT rows substantive.
- A2 behavioral test exists: dht_capability_injection.rs:84 `disabled_node_resolution_returns_ok_none_for_unknown_did` — production (no-testing) test, DualLayerResolver(NoOpRelayQuerier, DisabledDhtClient)→Ok(None).

## FINDING [MEDIUM, consistency/A5, non-blocking] — inconsistent testing-gate on DhtMode::Memory
ADR §Decision 1 **A5** (ADR:102) categorically mandates `#[cfg(feature = "testing")]` ONLY for every nullifier in-memory enum arm — explicitly "not `#[cfg(any(test, feature = "testing"))]`" (rationale: single activation path, feature-absence≡type-absence for G1).
- VIOLATING: config.rs:234 (DhtMode::Memory variant) and lib.rs:3227 (Memory publish arm) use `#[cfg(any(test, feature = "testing"))]`. Doc-comment at config.rs:231 deliberately documents the `test` disjunct.
- COMPLIANT (inconsistent with above): main.rs:492 + main.rs:571 gate Memory with `#[cfg(feature = "testing")]` only.
- Consequence: under `test && !testing` (bare `cargo test -p scp-node` w/o --features testing) the Memory VARIANT exists but main.rs's Memory match arm is gated out → the main.rs DhtMode match (main.rs:480) becomes NON-EXHAUSTIVE → compile error. Code only compiles because the workspace test invocation always passes `--features testing`, making the `test` disjunct redundant AND A5-violating.
- NOT a shipped-security hole: release builds set neither cfg, so Memory/InMemoryDhtClient/FfiDhtClient::InMemory all absent; G1-relevant bridge arm is correctly feature-only.
- FIX (down-flow correct): tighten config.rs:234 + lib.rs:3227 to `#[cfg(feature = "testing")]` (match main.rs + A5). InMemoryDhtClient struct (scp-dht mod.rs) also uses `any(test,...)` — same tightening or amend A5 first if leaf-crate type gates are intentionally exempt (they aren't per AC[4] literal "#[cfg(feature = "testing")]").
