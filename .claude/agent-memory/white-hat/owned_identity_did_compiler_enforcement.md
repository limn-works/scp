---
name: owned-identity-did-compiler-enforcement
description: OwnedIdentityDid sole-minter defense moved from 2217-line AST scanner to type-system + 2 module lints + compile_fail doctest + review (sole-minter branch, HEAD b8b648339)
metadata:
  type: project
---

# OwnedIdentityDid: scanner deleted, compiler-enforced (2026-06-17)

Branch `sole-minter` HEAD b8b648339 removed `scripts/check-owned-identity-did.py` (2217 lines) + fixture + CI job. Sole-minter capability guarantee now held by 3 layers:

1. **Type system (all outsiders, absolute):** private `did` field (E0451 on external struct-literal) + `pub(super) issue_for_actor` constructor. `pub(in crate::context)` struct name-visibility = nameable but not constructible.
2. **Compiler lints (insider body-nested vector):** `#![deny(unsafe_code)]` (+ crate `forbid`) blocks transmute/unsafe-Send; `#![deny(non_local_definitions)]` makes a body-nested `impl OwnedIdentityDid` a hard compile error.
3. **Code review (visible-diff insider edits):** module-level 2nd impl, visibility widen, new constructor, forbidden derive, pub field — all compile clean, all visible diffs to ~155-line frozen file.

## Verified empirically (rustc 1.95.0)
- non_local_definitions FIRES even when type is module-top-level and impl is nested in a same-module fn body (lint keys on nesting-level-vs-item, not module membership). Real insider vector IS covered.
- compile_fail doctest at supervisor/mod.rs L65 RUNS (`cargo test -p scp-runtime --doc context::supervisor` → 1 passed). Reachable because pub mod context → pub mod supervisor.
- Witness body compiles CLEAN under `#![allow(non_local_definitions)]` → lint is the SOLE compile-failure cause. compile_fail false-pass risk correctly designed out (smuggled() routes through sanctioned ctor, no name/visibility error to mask the lint).
- No `pub use` re-export widens OwnedIdentityDid visibility. issue_for_actor confirmed pub(super). Both lints + crate forbid are real parsed inner attrs.
- Scanner fully removed: zero lingering refs in md/sh/json/py/yml.

## Posture verdict: SOUND. Net improvement (secure-by-construction).
Findings are P2/P3 hardening only:
- **P2**: spec §9.4.1 now MANDATES reissue/as_did be exactly `pub(in crate::context)` but NOTHING mechanical enforces it (the one residual definition-shape invariant the deleted scanner's kernel DID cover). A wrench-`pub(crate)` widen of reissue compiles clean and is review-only. Candidate for a tiny bounded same-file check IF one is ever wanted — but per the lesson, review owns it.
- **P3**: compile_fail doctest uses a stand-in `Cap`, not real OwnedIdentityDid — can't (doctests can't reach pub(in crate) type). Acceptable; it witnesses the LINT, not the type.
- **P3**: lint is toolchain-version-dependent behavior; doctest is the regression tripwire for exactly this (started-compiling => test fails). Good.

## Lesson: `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md`
Capstone: "a mechanical check earns its keep only against an attacker who cannot edit the check." Insider editing identity_capability.rs could equally edit the scanner/CI → scanner marginal security = ZERO. CLAUDE.md got a new "Guard against over-engineering / non-convergent enforcement" tenet + simplifier charged to BLOCK on >3 non-convergent passes.
