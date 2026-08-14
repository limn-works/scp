---
name: project-owned-identity-did-gate
description: Convergence verdict for scripts/check-owned-identity-did.py and the test that distinguishes bounded-correctness growth from denylist-by-spelling regrowth
metadata:
  type: project
---

`scripts/check-owned-identity-did.py` is a frozen-shape POSITIVE-whitelist security gate over `crates/scp-runtime/src/context/supervisor/identity_capability.rs` (`OwnedIdentityDid` capability token, ADR-049 §5 / spec §9.4.1). It grew 689→893→1120 lines across three fix cycles. Reviewed 2026-06-17 (worktree `sole-minter`, HEAD `b369d707a`): **CONVERGED, not a regrowing arms race.**

**Why:** The denylist-by-name predecessor grew with the adversary's *vocabulary* (a fn named `forge`, then `mint`, ...) — infinite, non-convergent. This gate grows with the *finite grammar* of a Rust struct/impl/method. Each increment closed a distinct shape AXIS (module item-kind A1; struct shape A2; impl-body item-kind A3; per-method vis/param-kinds/receiver-mode/fn-modifiers/return-normalization; construction-location A4; deny(unsafe_code) presence A5). Those axes are now exhausted — there is no untyped residual left in a Rust method signature that a value-semantics-preserving forgery could exploit.

**How to apply (the decisive test for any future "is this gate regrowing?" question):** Ask — *would discovering a NEW forgery spelling force a NEW code path?* If NO (the new spelling is already rejected by a positive-by-kind / closed-allowlist / by-slot check), it is CONVERGED — do not raise an over-engineering BLOCKER. Concrete anchors that make it positive-by-kind: line ~632 (module item rejected by KIND), ~761 (impl-body item rejected by KIND), ~776 (`ALLOWED_METHODS` closed allowlist), ~837 (`mods - {"const"}` subset rejects any unknown future modifier). The 35-REJECT/5-ACCEPT self-test maps fixtures to axes, not to spellings.

**Redundancy review (Q2/Q3):** No structural over-abstraction. Two genuine ~6-line duplications exist and should be LEFT: (a) the A1 vs A3-body kind-reject tails (deliberate "A1 mirrored one level down" — extracting flattens per-axis auditability); (b) `_attr_args` vs `_attr_args_deep` (merging via a `deep=` bool re-introduces a behavior-changing boolean param). ~1120 lines is defensible: ~105 sanctioned soundness docstring + ~150 test harness/fixtures + ~390 logic whose multi-line rejection messages ARE the auditability product. No large behavior-preserving cut exists.

**Constraints when reviewing this file:** do NOT propose re-adding use-site/name-resolution/call-site analysis (the compiler's job; tree-sitter approximation is the deleted arms race — see `.docs/lessons/`), and do NOT propose cutting the soundness docstring. Related: [[lesson-security-gate-closed-allowlist]] (positive closed-allowlist > open classify-then-check for capability-type gates).
