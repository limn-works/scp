---
name: project-owned-identity-did-gate
description: The OwnedIdentityDid capability-token CI gate (check-owned-identity-did.py) — structure, rules A-K, self-test honesty mechanism, build-site mint exemption
metadata:
  type: project
---

`scripts/check-owned-identity-did.py` is a tree-sitter AST gate enforcing the `OwnedIdentityDid` capability-token invariants from **ADR-049 §5** (header `### 5. OwnedIdentityDid: unforgeable by constructor visibility + private field`) and **spec §9.4.1** four-point criterion (`.docs/specs/09-security-model.md`).

**Why:** The token proves an actor owns a given identity; handler code must be able to NAME it (held by-value in `ActorDeps`, passed `&OwnedIdentityDid` to `SupervisorHandle` per-identity methods) but MUST NOT be able to CONSTRUCT/forge one. Nameable ≠ constructible.

**How to apply:** When reviewing changes to this gate or the supervisor capability:
- Canonical rule enumeration is **A–K** (X = BLACK-G01 forgery marker). Rule G = CLOSED ALLOWLIST over inherent API (only `issue_for_actor`/`reissue`/`as_did` by NAME, not classify-by-return-type — alias/impl-Trait/Result returns evade text matching). Rule K = mint-call containment (bans every `issue_for_actor` reference across `supervisor/` subtree except its def, the ONE pinned `Supervisor::build_actor_deps` call in `supervisor.rs`, and `#[cfg(test)]`).
- **Allowed visibility set** for `reissue`/`as_did`: inherited-private OR exactly `pub(in crate::context)` — never `pub`/`pub(crate)`/narrower. Struct name-vis = `pub(in crate::context)`. Mint `issue_for_actor` = `pub(super)`. Gate constants: `BUILD_SITE_REL = crates/scp-runtime/src/context/supervisor/supervisor.rs`, `BUILD_ACTOR_DEPS_FN = build_actor_deps`, `DID_PARAM_TYPE = DID`.
- **Coverage honesty:** `--self-test` runs `scripts/tests/owned-identity-did-fixture.rs`. `REQUIRED_FIXTURE_FAILURES` (positive teeth — each labeled forgery MUST be detected) + `FORBIDDEN_FIXTURE_SUBSTRINGS` (negative-control teeth — exempt cfg(test)/build-site mints must NOT be flagged). The PASS message enumerates modes DYNAMICALLY from the label list, so the documented count cannot drift from enforcement. CI (`.github/workflows/ci.yml` ~line 336/338) runs `--self-test` then the real scan.
- **Fail-closed discipline:** build-site exemption REFUSES outright (dissolves) if `build_actor_deps` body contains any macro invocation (tree-sitter can't expand) or glob `use` (can't resolve binding). Shadow detection (`_shadows_before`) is order-INDEPENDENT for item-position bindings (const/static/nested-fn/use — Rust resolves over whole block scope) but byte-order-guarded for expression-position (let/assignment).
- This is an enforcement file under CLAUDE.md's "NEVER modify enforcement files to bypass" list (via `check_ready_coverage`-style protection). Only ADD assertions; weakening needs human approval.

The `2e-gate-followup` series (17 commits, branch `chore/2e-gate-followup`) grew it 25→85 required-failure labels + 0→9 forbidden teeth, strictly additive, with the 4 production `.rs` edits being doc-comment-anchor-only (stale `plan §"..."` cap anchors → `ADR-049 §5`). Note: `plan §"..."` anchors elsewhere in `context/` are a pre-existing pervasive convention (15 files) pointing to an uncommitted actor master plan — NOT in scope to reconcile.
