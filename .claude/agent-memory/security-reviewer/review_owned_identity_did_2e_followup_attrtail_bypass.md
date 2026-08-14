---
name: review-owned-identity-did-2e-followup-attrtail-bypass
description: HIGH bypass found in check-owned-identity-did.py Fix B (commit e7dba843b) — scoped-path attr proc-macro with builtin-tail name (#[evil::allow]) launders past the in-body attribute ban. Fix A (block-scope) is CLEAN.
metadata:
  type: project
---

# 2e-gate-followup (branch chore/2e-gate-followup, commit e7dba843b) — check-owned-identity-did.py

Three findings closing PR: Fix A (item-shadow block-scope), Fix B (attr-proc-macro ban), Fix C (struct/enum/union).

**Fix A (block-scope item-shadow): CLEAN.** New `_shadows_before(fn, name, mint_node, src)` computes the mint's ancestor-`block` chain and gates each item arm (const/static/fn/struct/enum/union/use) on `_item_in_mint_scope` (item's nearest enclosing block ∈ mint chain). Verified via gate-internal harness against rustc semantics: same-block shadow (pre OR post mint) → caught; enclosing-block shadow → caught; closure/match-arm/if-block where mint is INSIDE → caught; genuine sibling/descendant block (mint NOT inside) → correctly exempt. Forgery direction preserved; the relaxation is a true false-positive fix, NOT a weakening. Fix C struct/enum/union additions correct (non-exploitable, claim-accuracy).

**Fix B (`_body_has_noninert_attr_item` / `_attr_path_tail` / `INERT_BODY_ATTRS`): HIGH bypass.** All-new in this commit. `_attr_path_tail` strips leading `path::` segments and returns ONLY the tail identifier, so a path-qualified attribute proc-macro whose tail collides with a builtin (`#[evil_crate::macros::allow]`, `#[a::b::derive]`, `#[crate::m::cfg]`, any of the 16 INERT_BODY_ATTRS tails) is judged INERT → build-site exemption granted. rustc PROVES path-qualified ≠ builtin: `#[m::allow]` → E0433 "cannot find allow in m" (builtin lints are single-segment ONLY). Built a full compilable proc-macro `#[proc_macro_attribute] pub fn allow` at /tmp/pmtest that KEEPS the item AND injects `const SHADOW` — compiles clean, expansion adds an item invisible to the pre-expansion AST walk. So `#[evil::allow] const _M:()=();` + bare mint → exempt while the macro silently injects `const owning_did` = exactly the forgery class Fix B was meant to close.
- **FIX**: refuse outright when attribute path is a `scoped_identifier` (builtins are bare `identifier` only). The attribute node child is `identifier` for builtins, `scoped_identifier` for path-qualified — clean discriminator. The `cfg_attr` inner `_scan` ALREADY rejects `scoped_identifier` correctly; apply the same to the top-level path. Localized one-liner.

**Minor (acceptable):** `#[cfg_attr(test, allow(..))]` is conservatively REFUSED (the cfg predicate `test` isn't in the allowlist) — fail-closed over-refusal, documented, zero prod impact (real body has no in-body attr).

**Production:** scan exits 0, no false-FAIL. Real `build_actor_deps` (supervisor.rs:1387) has the genuine bare `owning_did.clone()` mint at fn-body level, no in-body attr → unaffected by the bypass (insider-only reachable). prod .rs diff is doc-comment-only (ADR-049 §5 provenance); spec §9.4.1/ADR-049 §5 reissue/as_did visibility text consistent. Self-test 86 modes PASS.

**Recommendation: DO NOT LAND until Fix B scoped-path hole closed + a `build_site_scoped_attr_tail_launder` fixture added.**
