---
name: adr062-slice6-g1-gate-sound
description: ADR-062 Slice 6 G1 shipped-feature-graph prove-absence gate audited SOUND/CONVERGENT — not a non-convergence BLOCKER
metadata:
  type: project
---

ADR-062 Slice 6 / SCP-CAPINJECT-006 (nullifier severance, branch feat/adr062-slice6-nullifier-severance) adds `scripts/check-shipped-feature-graph.sh` (G1). Audited against the non-convergent-enforcement BLOCKER criteria — VERDICT: SOUND/CONVERGENT, NOT a BLOCKER.

**Why sound (evidence from the script):**
- It is a POSITIVE ⊆-allowlist, closed by construction. `PERMITTED_ALLOWLIST` = ~37 durability-only/real-backend `crate/feature` entries. Decision procedure `check_subset` = `comm -23 resolved allowlist`; ANY resolved feature not on the allowlist FAILS. The 11 `NULLIFIER_CONTROL_FEATURES` are used ONLY as fixture positive-control inputs, NEVER in the gate decision. So novel/future/renamed nullifier features are caught without being named.
- NOT redundant with the type system. Type system makes nullifier arms unnameable-without-`testing` at compile time. G1 checks the ORTHOGONAL binary-artifact property "no test-harness feature resolves in the shipped `cargo tree -e features,no-dev` graph" — which the type system cannot see. It catches the regression class "someone re-adds `scp-platform/testing` to a prod dep line," which a bare `cargo build --features server` would NOT catch (build still succeeds, just compiles nullifiers back in). Genuine complementary value.
- Fixture harness is real, not theater. `--self-test` drives the actual `check_subset` decision proc: (a) novel `some-future-nullifier-9000` → REJECTED (proves closed), (b) allowlist trimmed of a resolved feature → REJECTED (proves ⊆ load-bearing), (c) clean ⊆ → ACCEPTED, plus leaked-testing-feature soundness cases + allowlist-has-zero-nullifier hygiene. Verified passing. Real gate exits 0 on the post-slice tree; wired as a required CI job.

**Residual soundness dependency (observation, not a flaw in G1):** end-to-end "no nullifier ships" also relies on the separately-held invariant that nullifiers are gated ONLY on the 11 cargo features, not on non-feature cfgs G1 can't see (`debug_assertions`, `cfg(unix)`, etc.). `cfg(test)` is safe (never set in a shipped build), so `#[cfg(any(test, feature="testing"))]` (as in scp-identity/src/config.rs create_inner) does NOT undermine G1. The plan's "never any(test,...)" wording is slightly imprecise but harmless.

**Rest of slice:** ~442 removed `allow_in_memory_custody` cfg lines = mechanical behavior-preserving rename into `testing`. Fail-closed pre-rotation surfacing is ALREADY DRY — each of the 3 bridges has a single `no_pre_rotation_backend()` helper the ~25 weld sites call; cross-bridge dedup infeasible (distinct ScpError types per bridge — FFI-macro-inherent). Attestation transient exemption is to `pure-helpers-allowlist.txt` (code-shape linter), NOT a G1 nullifier exception; documented, transient, removal-tracked by #2171. Nothing over-engineered.

Relates to [[sanctioned-bounded-tripwire-shape]] and [[project_codebase_map_gate_audited_clean]] — same family of correctly-bounded/positive-whitelist enforcement that should NOT be re-litigated.
