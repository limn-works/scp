---
name: adr062-reframe-inversion-review
description: ADR-062 capability-injection reframe (dependency-edge inversion §0) artifact-flow + #1733-subsumption alignment review, PR #2120 head 160b2972c
metadata:
  type: project
---

# ADR-062 reframe (dependency-direction inversion) review — 2026-07-13

Branch `docs/adr-062-capability-injection` = PR #2120, head `160b2972c`. Worktree agent-ae0cddf9d3653e5ef ADR + spec files verified BYTE-IDENTICAL to origin PR head (local git log was stale/ceiling commits — the ADR-062 files were NOT in worktree HEAD; only origin PR branch had them). Reviewed the authoritative version.

**Verdict: ALIGNED**, one NEEDS-DISCUSSION cluster (#1733 goal-narrowing + issue hygiene).

## Confirmed clean
- **Artifact flow (task 1):** spec §17.17 exists on-branch (17-persistence §17.17.1-.3, SCP-CAPSEL-8000/8001/8002/8010/8011/8012/8013; DHT nullifier §17.17.3/8013 also cross-ref'd in 03-identity:906). Reframe commits `47378357e`(ADR)+`160b2972c`(PRD) did NOT touch spec (spec last touched `6ed677d4c`, earlier). ADR correctly cites §17.17 as upstream + realizes it. The primitive/use-case dependency-inversion is a BUILD-GRAPH/arch concern (engineering), NOT protocol behavior — correctly ADR-level; spec §17.17 explicitly delegates the absence *mechanism* downstream to ADR-062 (SCP-CAPSEL-8012). No spec rule smuggled into ADR; nothing inversion-specific belongs upstream.
- **Task 3 (goals/decisions):** no drift. E1 fix (Slice 1 unconditional production-dht pyo3/napi + FfiDhtClient enum) intact; prove-absent nullifiers STRENGTHENED (type-absence via per-type primitive decomposition; G1 now asserts exactly 4 nullifier features); cross-binding semantic matrix (§5) intact; dev-only-DHT-is-nullifier preserved (`dht-in-memory` primitive under switch); two-mechanism model intact.
- **Task 4 (tenets):** exemplary root-cause fix (one inverted edge → all E-findings); SIMPLIFIES (in-mem DHT = "just one more nullifier primitive" not special case; declines selection-mechanism AST gate per over-engineering guardrail, only G1 added); no-silent-defaults central; not DOA (pre-release rename, no external consumers).

## Findings
- **F1 NEEDS-DISCUSSION (med):** ADR folds #1733 but silently narrows its **5 goals → 3**. #1733 goals 1 (move impls out of `testing/` → `in_memory/` non-test-named module) and 2 (delete `pub use testing as software;` at scp-platform/src/lib.rs:52) are DROPPED — no Slice-0 AC touches the module rename or the `software` alias. #1733 AC-1 (`grep scp_platform::testing == 0 in prod`) is intentionally superseded (durability-only InMemoryStorage now legitimately imported in prod via `in-memory-storage` primitive) and AC-5 (no In-Memory type in mobile binary) relaxed to nullifier-only (durability-only InMemoryStorage MAY compile into mobile) — both defensible but NOT reconciled against #1733's literal text. Security substance fully achieved (arguably better via G1). Recommend: Slice 0 explicitly decides fate of `pub use testing as software` + `testing/`→`in_memory/` rename (keeping `testing`-named module for legit durability-only prod imports re-creates the exact "reads as test-only" confusion #1733 targeted; no-deferral tenet says decide now, don't defer as churn).
- **F2 NEEDS-DISCUSSION (low-med):** #1733 still OPEN on GitHub, declared "no longer a separate story" only inside the ADR. Update #1733 with AC-by-AC map to ADR-062 Slice 0 (achieved / superseded-by-G1 / consciously-dropped+reason) then close-as-folded. Artifacts-are-system-of-record + provenance.
- **F3 Observation (coordination, no design conflict):** merge collisions — PR #2119 (fix/python-wheels-ci) edits `crates/scp-platform/Cargo.toml` + `bindings/python/pyproject.toml` (Slice 0 adds 5 primitive features + redefines `testing` there; Slice 1 edits pyproject maturin features). PR #1892 (release-pipeline-multiregistry) edits `.github/workflows/release.yml` (Slice 0 renames feature strings there + ADR wants a NEW bare-production release job — reconcile with #1892's rework). Textual/ordering only; OpenSSL-SQLCipher(#2119) ≠ rustls-DHT(ADR) so no logical dep conflict.
