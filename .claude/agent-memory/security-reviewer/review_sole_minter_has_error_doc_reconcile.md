# Review: sole-minter has_error guard + doc reconcile (worktree sole-minter)

HEAD c5c145caa, merge-base 3f4ce2a1a. 11-file diff. Follow-on to the SCOPE-REDUCTION
review (see review_owned_identity_sole_minter_gate.md). VERDICT: CLEAN with ONE
LOW spec-purity nit.

## What changed since the sole-minter kernel review
- Gate gained A0 parse-health guard: `root.has_error` → fail-closed, on BOTH the
  cap file scan AND the `_has_deny_unsafe_code` mod.rs parse. Closes the gen-fn /
  unrecognized-grammar degrade-to-nested-ERROR class (kind-based whitelist would
  not see a `function_modifiers` token that the pinned grammar mis-parses).
- Doc reconcile: the prior MEDIUM finding (ADR-049 §5 over-claiming OLD gate's
  macro/#[path]/trait-return/scan-root-wide coverage) is now FULLY FIXED. §5
  rewritten to the narrowed remit; the only residual macro/#[path] mention is the
  correct NEGATION ("does NOT expand/scan macros, follow #[path]"). No over-claim
  remains.
- spec §9.4.1 + module docs: reissue/as_did "exactly pub(in crate::context)"
  clauses added — VERIFIED accurate vs code (identity_capability.rs:130 reissue,
  :142 as_did both pub(in crate::context)) and vs gate (method_spec uses
  REQUIRED_STRUCT_VIS for both).
- Code changes are DOC-COMMENT-ONLY (provenance refs §"plan..." → "ADR-049 §5").
  Struct/methods/vis/field untouched.
- Governance: CLAUDE.md adds gate to protected list + anti-over-engineering policy;
  simplifier.md gets BLOCKER mandate for non-convergent/redundant enforcement.
  Lesson ast-gate-checks-definition-not-name-resolution.md sound.

## Completeness of the type-system boundary (the load-bearing claim) — CONFIRMED
- crate-wide grep: ONLY ONE inherent `impl OwnedIdentityDid` (the cap file).
  A second inherent impl elsewhere CANNOT mint: private `did` field blocks struct
  literal outside module; `issue_for_actor` is pub(super) so only supervisor-
  module descendants can CALL it, and they're already trusted insiders.
- Production mint sole site: supervisor.rs:1421 `issue_for_actor(owning_did.clone())`
  inside build_actor_deps — owning_did is the same DID the whole ActorDeps bundle
  is built for. deps.rs:264 uses reissue(). handle.rs mints are #[cfg(test)].
- The OLD gate's build-site shadow-check is correctly delegated to the type system:
  only in-scope (supervisor-module = trusted) code can reach the mint. Right boundary.
- lib.rs:21 `#![forbid(unsafe_code)]`; supervisor/mod.rs:40 `#![deny(unsafe_code)]`;
  `pub(in crate::context) mod identity_capability;`. All A5/type-system premises hold.
- Gate real scan PASS; self-test 37 REJECT + 5 ACCEPT, all green. Fixtures genuine
  (cover every A0-A5 branch incl gen-fn, derive-behind-doc-comment, deny variants).

## ONE LOW finding (spec-purity, non-blocking)
spec §9.4.1 point 1/2: the appended "MUST be exactly `pub(in crate::context)`"
clauses bake a Rust-specific visibility token into the protocol spec as a bare MUST
WITHOUT the "Language-specific:" qualifier or "other languages MUST apply the
equivalent" escape that the rest of the same bullet uses. Consistent w/ the
no-impl-details-in-specs guidance (user memory feedback_no_impl_details_in_specs).
LOW because the bullet ALREADY mixes Rust specifics ("Rust impls MUST NOT derive
Clone...") so it's a local consistency nit, not a contradiction, and the ADR (which
IS the Rust-binding layer) is the right home for the exact token (already present
there). Optional fix: prefix the new clauses with "Language-specific (Rust):".
