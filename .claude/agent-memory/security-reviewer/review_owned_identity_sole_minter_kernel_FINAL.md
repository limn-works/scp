---
name: review-owned-identity-sole-minter-kernel-final
description: CLEAN sign-off of the OwnedIdentityDid scope-reduction to a 894-line definition-shape kernel (HEAD ede6df05e, branch chore/owned-identity-sole-minter-gate); resolves the prior name-resolution/build-site HIGH findings by DELETING that machinery
metadata:
  type: project
---

# OwnedIdentityDid sole-minter kernel — FINAL CLEAN (HEAD ede6df05e) 2026-06-17

CLEAN. This is the correct resolution of the entire prior multi-pass saga
([[review-owned-identity-did-2e-followup-attrtail-bypass]] HIGH,
[[review-owned-identity-did-buildsite-traitimpl-residual]] HIGH). The fix DELETES
the name-resolution / build-site / mint-argument machinery wholesale (~2600 lines
removed, 2868-line gate, fixture 1117 lines) and reduces to a sound, bounded,
single-file POSITIVE-WHITELIST definition-shape kernel. All those open HIGHs are
moot because the surface they lived on no longer exists.

**Why the retained invariant is right + complete (Q1):** the gate now checks ONLY
the definition of identity_capability.rs: A1 module-item positive whitelist
(only use/one struct/one inherent impl/one #[cfg(test)] mod tests — rejects by
ITEM KIND not name, so type-alias/path-qualified-impl/free-fn/macro/const/static
caught categorically), A2 struct shape (vis exactly pub(in crate::context), one
private did:DID field, inert bare built-in attrs only → any derive rejected, incl
doc-comment-interleaved via grammar-based _preceding_attr_items skipping comments),
A3 inherent impl exactly {issue_for_actor pub(super)/one by-value param,
reissue+as_did pub(in crate::context)/exactly &self} with exact return sets, A4
location-based name-agnostic struct-literal confinement, A5 real-parse
deny/forbid(unsafe_code) in mod.rs. The ONE residual the type system cannot give
= sole-minter (insider adding a 2nd in-module arbitrary-DID constructor) → A3
closed-allowlist + A1 single-impl. Unforgeability proper = TYPE SYSTEM
(pub(super) issue_for_actor + private did field + crate forbid(unsafe_code)@lib.rs:21
+ supervisor deny(unsafe_code)@mod.rs:40, both verified live). Division of labor
accurate + the real boundary. Nothing security-relevant about the DEFINITION left
unchecked.

**Docs (Q2): NO over-claim, NO under-state.** ADR-049 §5 (rewritten lines
103/109/111), spec §9.4.1 points 1+2 (reissue/as_did carve-outs), module doc
(identity_capability.rs:47-63), mod.rs, supervisor.rs, handle.rs all now describe
ONLY definition-shape coverage and EXPLICITLY disclaim use-site/macro/#[path]/
alias-resolution/call-site/build-site/mint-arg inspection. This is the exact OLD
over-claim I flagged in [[review-owned-identity-sole-minter-gate]] (ADR §5 lines
109+111 still describing the deleted name-resolution gate) — NOW RECONCILED. The
reissue "&self-only, no raw DID, never broadens reachable identities" and as_did
"read-only &DID of OWN owning identity, no From<&DID>, no public ctor" visibility-
bound clauses (never wider than the struct = the isolation half) are correct.
Nothing false after the rewrite.

**Lesson (Q3): sound.** ast-gate-checks-definition-not-name-resolution.md —
AST gate can soundly assert definition facts (finite single-file shape) but not
use-site dataflow/name-resolution (compiler-level, unbounded regress in
tree-sitter); type system is the real boundary; bounded definition-SIDE checks
(incl frozen-shape positive whitelist, same-file alias ban) are legit and should
be KEPT (explicitly warns against over-cutting — earlier draft dropped same-file
alias ban, restored); blocking bar = a COMPILING type-system-evading forgery, not
a theoretical AST-spelling gap. All three takeaways correct.

**Verified live:** real scan PASS (exit 0); self-test 24 REJECT + 3 ACCEPT PASS
(covers alias, path-qualified impl, doc-comment-interleaved derive, aliased-DID
param, free-fn minter, pub/pub(crate) struct, public field, widened vis ×3,
const/static/macro_rules/trait module items, 2nd impl, tests-without-cfg-test,
commented-out deny). identity_capability.rs matches whitelist exactly. CI-wired
(.github/workflows/ci.yml). NO other enforcement file touched (confirmed against
CLAUDE.md list). Return-type normalization for as_did `&DID` sound (only normalizes
when "::" present AND no "&"). Generic/where-clause evasions covered (impl type-name
final-segment + trait-name-non-None). Scope reduction = legitimate per the
[[lesson-security-gate-closed-allowlist]] principle: redundant weaker re-check of a
type-system-sound property is negative value.

SIGNED OFF CLEAN. The prior open HIGHs are correctly resolved by removal.
