---
name: adr049-2j-decision7-citation-precheckD-515bef7b5
description: ADR-049 2J §9 Follow-ups #1 doc correction — re-point §10→Decision 7 timeout citation + enumerate durable first-writer-wins Precheck D; ALIGNED 0 findings, resolves the round-5/8e8c84e54 §10 mis-pointer LOW
metadata:
  type: project
---

# ADR-049 Phase 2J §9 "Landed" bullet — §10→Decision 7 recitation + Precheck-D enumeration @ `515bef7b5` (2026-07-02) — ALIGNED, 0 findings

Branch `feat/adr049-2j-spawn-from-welcome`. Doc-ONLY, 1 file / 1 line (git show --stat confirms only `.docs/adrs/ADR-049-actor-per-context.md`, +1/-1). Successor that RESOLVES the LOW my `8e8c84e54` entry filed ("clause cites (§10) but §10 = Actor panic recovery, no timeout prose; fix = drop §10 or re-point to Decision 7"). This commit does exactly the re-point.

**Two corrections, both accurate + provenance-clean + non-over-claiming:**

1. **Citation re-point `(§10)` → Decision 7.** VERIFIED: Decision 7 (ADR line 154, "Async provider traits everywhere") literally contains the generic per-handler discipline — "Every transport and storage call inside a handler wraps `tokio::time::timeout(30s, ...)`." §10 (lines 212-246, "Actor panic recovery") contains ZERO timeout/`tokio::time::timeout` prose (watchdog/panic-detect/respawn-budget/poison/crash-window only). So old `(§10)` resolved to the WRONG section; new clause resolves to the section that genuinely states the discipline. No residual phantom-provenance. `LIFECYCLE_TIMEOUT = from_secs(30)` (supervisor.rs:1473) == Decision 7's 30s. Clause phrasing is careful: separates the peer-bootstrap `LIFECYCLE_TIMEOUT` *convention* (code convention, the bootstrap-region wrap) from "the same fail-closed timeout discipline Decision 7 mandates for handler transport/storage calls" (the generalizable principle) — does NOT over-claim that Decision 7 explicitly covers bootstrap regions.

2. **Enumerate "durable-snapshot first-writer-wins" in the reversible-precheck list.** VERIFIED real Precheck D (BLACK-2J-06) @ supervisor.rs:10466-10497: reads `deps.persistence.load_context(&context_id)` (10480); `Ok(None)=>{}` proceeds; `Ok(Some(_))` → `CreationFailed` refuse; `Err(e)` → `PersistenceFailed` fail-closed. Runs under `bootstrap_spawn_lock` (guard @10396) and BEFORE the irreversible `ConfirmConsume` (step 1 inside timeout region @10534-41). Reversible (read-only, no consume/persist). Precheck list `(registry-collision, pseudonym, legible-param validation, durable-snapshot first-writer-wins)` maps 1:1 to Precheck A(10404 `self.lookup`)/B(10429 pseudonym)/C(10444 param-validation)/D(10466). Enumeration now complete + accurate; A (live-registry) and D (durable-snapshot) correctly listed as distinct.

**No regression:** substantive timeout claim intact + accurate — region `ConfirmConsume→install_joined_group→durability-check(3b)→persist(4)→spawn(5)` wrapped `tokio::time::timeout(Self::LIFECYCLE_TIMEOUT, Box::pin(..))` @10520-21; elapse arm returns `TransportTimeout` @10666 with idempotent `destroy_mls_group`+`delete_context` rollback @10664-65; "cannot pin global bootstrap_spawn_lock" matches 10508-16. Prechecks A–D stay OUTSIDE the bound (nothing consumed/persisted before → early elapse impossible); finalization OUTSIDE bound (actor live, rollback must not hit it). create(2647)/import(2779,2852)/restore(4450) peer-bootstrap arms all use LIFECYCLE_TIMEOUT (parity real).

**Artifact-flow:** doc conforms to code + to upstream Decision 7 (fixing a mis-citation + completing an enumeration); not code-informs-spec. Doc-only.
