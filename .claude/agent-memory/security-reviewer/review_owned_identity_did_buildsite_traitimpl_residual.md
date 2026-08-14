# OwnedIdentityDid build-site mint exemption — trait-impl residual (commit 731c9ebeb)

Branch `chore/2e-gate-followup`, worktree `2e-followup`. Reviewed fix that closes prior
HIGH (nested-`fn build_actor_deps`-inside-the-real-one wrongly exempt).

## Prior HIGH = CLOSED (verified)
Fix (1) adds direct-impl-method ban to `_mint_ref_exempt_build_actor_deps`
(scripts/check-owned-identity-did.py:1752-1758): parent chain must be
`function_item -> declaration_list -> impl_item`; nested fn's parent is `block` → refused.
Byte-identical structure to construction path's `is_impl_method` (2269-2273).
Drove predicate on VALID/compilable injections: (a) real production shape exempt=True
(no false-FAIL), (b) nested-fn minting own param exempt=False, (c) second-self-param
exempt=False, (d) real + unrelated nested helper exempt=True. self-test 76 modes pass;
real prod scan exit 0.

Fix (2) positional+count-bounded self-exclusion (1653-1680): receiver-shape only at
value-index 0; receiver at index≥1 → fail-closed. Closes double-self miscount.

## RESIDUAL (HIGH, same class as the fix) — trait-impl asymmetry
`_mint_ref_exempt_build_actor_deps` does NOT call `_impl_is_inherent`, but the
CONSTRUCTION path DOES (line 2279, `in_allowlisted` ANDs `_impl_is_inherent`).
A planted `impl SomeTrait for Supervisor { fn build_actor_deps(&self, d: DID) ->
OwnedIdentityDid { OwnedIdentityDid::issue_for_actor(d.clone()) } }` in supervisor.rs
passes ALL mint-call guards (file pin, name, direct-impl-method via fix1 — trait method
IS a direct `declaration_list` child, non-generic, not nested-mod, no escapable scope,
sole &DID param, mints it) and `impl_node.type` tail = `Supervisor` → exempt=True.
Verified via predicate (drive_gate4.py: (h2) exempt=[True]). Construction path REJECTS
the analogous trait-impl literal forge (hit_reason confirms trait-impl construction banned).

Same threat class as the just-closed HIGH: exemption must pin to the ONE real INHERENT
production method; a trait-impl is a laundering vehicle whose param provenance the gate
cannot vouch for. Real production build_actor_deps is INHERENT (`impl Supervisor {` at
supervisor.rs:621, method at 1387) → adding `_impl_is_inherent(impl_node)` is
zero-false-positive + strictly additive, identical pattern to fix(1).

FIX: add `if not _impl_is_inherent(impl_node): return False` after the
SUPERVISOR_IMPL_TYPE check (~line 1782) + a fixture negative case
`build_site_trait_impl`. DID NOT sign off on landing until closed.
