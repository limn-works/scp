---
name: owned-identity-did-gate-const-static-shadow
description: CRITICAL gate-defeat in check-owned-identity-did.py — const/static item shadow of build_actor_deps owning_did param evades _shadows_before
metadata:
  type: project
---

# BLACK-OIDC-001 — const/static shadow defeats owned-identity-did mint gate

Commit `731c9ebeb` (branch chore/fuzz-pin-nightly worktree 2e-bh), gate
`scripts/check-owned-identity-did.py`, rule K build-site exemption.

**Defeat:** `_shadows_before` (line ~1389) enumerates binder forms
`let_declaration`, `assignment_expression`, and `_PATTERN_BINDER_FIELDS`
(match_arm / let_condition / for_expression / closure_expression) — but
OMITS `const_item` and `static_item`. A fn-body `const owning_did: &DID =
&DID(String::new());` (or `static`) lexically before the mint shadows the
`owning_did` PARAMETER. The mint arg `owning_did.clone()` then resolves to
the attacker-controlled compile-time const, NOT the supervisor param.

**Confirmed:** Inject into real `Supervisor::build_actor_deps` in
supervisor.rs. With `#[allow(non_upper_case_globals, unused_variables)]` on
the fn, compiles clean under `RUSTFLAGS="-D warnings"` AND gate exits 0
(PASSED). Compiler's own `unused variable: owning_did` warning on the param
proves the param is shadowed/unused. Both const and static work.

**Impact:** CRITICAL. Every actor minted by the supervisor receives an
OwnedIdentityDid for the attacker DID — total cross-identity isolation
defeat — while the gate sees the mint "pinned" to the trusted param name.
Insider editing supervisor.rs (the one trusted file) is the only access
needed; the gate is the defense-in-depth meant to catch exactly this.

**Fix:** Add `const_item` and `static_item` to the `_shadows_before` walk:
any `const`/`static` item in the body whose name == the owning param and
whose `start_byte < before_byte` must dissolve the exemption (fail-closed,
identical to the `let_declaration` arm). Add self-test modes
build_site_const_shadow + build_site_static_shadow.

**What resisted (don't re-report):** macro-body mint refs (rule K sees
identifiers in macro_rules arms), paste!/concat_idents reassembly (subtree
name ban + invocation-names-cap), let/match/if-let/while-let/for/closure
shadows, bare value-path mint (not a call → not exempt), nested-block let
shadow. Residual (lower sev): reassembly ban is a NAME blocklist
{paste,concat_idents} — a proc-macro reassembler (heavy supply-chain) is
out of the set; and gate does not itself assert `#![forbid(unsafe_code)]`
present in lib.rs (relies on it externally).
