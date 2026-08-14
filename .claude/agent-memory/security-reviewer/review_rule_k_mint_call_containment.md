---
name: review-rule-k-mint-call-containment
description: Rule K (mint-call containment) added to OwnedIdentityDid CI gate — CLEAN complete categorical closure, no loophole; commit 9abd6e41a
metadata:
  type: project
---

# Rule K — mint-call containment (OwnedIdentityDid gate), commit 9abd6e41a

CLEAN, COMPLETE, STRICTLY ADDITIVE strengthening. No loophole found. Branch chore/2e-gate-followup.

**Why:** ADR-049 §5 cross-identity-isolation cap. Type system is PRIMARY (pub(super) mint + private `did` field + #![forbid(unsafe_code)] @lib.rs:21 + #![deny(unsafe_code)] @supervisor/mod.rs:40). Gate is defense-in-depth. Rule J (return-type-TEXT scan) was evadable by assoc-type projection / trait-method projection / `impl Sized` opaque return. Rule K closes the CLASS by gating the dangerous OPERATION — a CALL/value-path reference to the sole arbitrary-DID minter `issue_for_actor` — not the disguisable return type.

**How to apply / verified facts:**
- Mint = `OwnedIdentityDid::issue_for_actor(did: DID)` @identity_capability.rs:108, `pub(super)`. `super` from identity_capability = `supervisor` module ⇒ reachable only in `crates/scp-runtime/src/context/supervisor/` (= SUPERVISOR_SUBTREE_REL). Rule K scans whole subtree, fail-closed.
- Inherent impl has EXACTLY 3 fns: issue_for_actor (mint), reissue(&self) — clones, NO DID param, not a forgery vector, and as_did(&self)->&DID read-only. So EVERY arbitrary-DID forgery MUST call issue_for_actor. Premise holds.
- `_is_mint_reference` catches ALL ref shapes (probed live): scoped_call `Self::issue_for_actor`, fnptr value `Foo::issue_for_actor`, bare `issue_for_actor(d)`, qualified-trait `<T as Tr>::issue_for_actor`, AND mint inside macro_rules! body (tree-sitter tokenizes it to a bare `identifier`). Excludes: fn DEFINITION name node, scoped_identifier leading segments, `use`-path bare identifiers, `field_identifier` (x.issue_for_actor — moot, mint is not &self).
- use-as rename closed: `_use_alias_mint_tail` bans `use …::issue_for_actor as X` whole-tree (not subtree-bound, not build-site/cfg-test exempt). Plain non-alias `use …::issue_for_actor;` ALSO flagged (scoped_identifier branch doesn't exclude use paths) = stricter, fail-closed, no prod false-FAIL.
- Exemptions: (a) definition (never collected). (b) build_actor_deps — STRUCTURAL: nearest function_item named build_actor_deps AND enclosing impl_item target type literally `Supervisor`. Real site @supervisor.rs:1421 inside impl Supervisor(621)>build_actor_deps(1387). Not name-launderable from outside trusted module. (c) cfg(test): `_inside_cfg_test` walks ancestors for mod_item/fn/impl/block w/ preceding #[cfg(test)]/#[cfg(all(test,…))]. `#[cfg(not(test))]` correctly FLAGGED (probed). handle.rs:830/844/853/882 mint calls are in `#[cfg(test)] mod tests`(729) ⇒ exempt, no false-FAIL.
- No #[path] redirect mounts an out-of-subtree file into supervisor module (only key_package_actor_tests.rs, cfg(test), in-subtree, no mint ref). No `pub use`/re-export of mint anywhere (grep=0).
- Strictly additive: `fail = True` 17→26, REQUIRED_FIXTURE_FAILURES 33→69; only `-` lines are docstring letter bumps (A-G→A-K). Tuple arity (11) consistent across 2 returns + 3 unpacks + early-exit guard includes `and not mint_ref_hits`.
- self-test PASS (46 modes incl rule_k_assoc_type_projection / trait_method_projection / opaque_return / use_rename + NEW negative-control FORBIDDEN_FIXTURE_SUBSTRINGS regression teeth for exempt build-site/cfg-test mints). Real prod scan PASS. Gate registered in .github/workflows/ci.yml.
- Spec/ADR (09-security-model §Cross-identity / ADR-049 §5) edits consistent, flow downward; point-3 "constructor visible only to supervisor module" = what rule K enforces.

**Residual (OBSERVATIONS only, not loopholes):** Second `build_actor_deps` in another `impl Supervisor` block would be exempt — but that is inside the trusted supervisor module where the type system already permits minting; gate is defense-in-depth, type system primary. Acceptable.
