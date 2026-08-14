# OwnedIdentityDid CI gate hardening (worktree 2e-followup, HEAD 8791728aa) — 2026-06-16

Reviewed `chore(actor): harden OwnedIdentityDid gate + fix doc anchors (ADR-049 §5 follow-up)`.
Gate = `scripts/check-owned-identity-did.py` (AST/tree-sitter capability-token invariant gate, in NEVER-WEAKEN list).

## Verdict: CLEAN STRENGTHENING. One MEDIUM provenance miss (not a security weakening).

### Changes (all net-tighten, nothing weakened/removed):
- **F.3 enum HARD-FAIL** + **F.4 union HARD-FAIL**: `union_item` now COLLECTED in decl walk (was never collected on origin/main — every decl-keyed check silently skipped it). Old `(F)` allowed `struct (or enum)`; field-privacy check E does `if kind != "struct": continue`.
- **FIX-2**: `reissue`/`as_did` visibility bounded — must be `""` (private) or `pub(in crate::context)`; `pub`/`pub(crate)`/`pub(super)` all FAIL. Enforces spec §9.4.1 point-1 carve-out clause mechanically.
- Anchor repoints `§"…via module visibility"`/`§"Cross-identity isolation"` → `ADR-049 §5`.

### Proven by isolated regression (old vs new script, same fixture):
- UNION at required path w/ correct mint: OLD `decls=[]` PASS → NEW FAIL. Real latent hole closed.
- ENUM at required path w/ correct mint: OLD collected-but-PASS → NEW FAIL. Real latent hole closed.
- `pub fn reissue(&self)`: OLD PASS → NEW FAIL.
- Self-test PASSES (28 modes = len(REQUIRED_FIXTURE_FAILURES); substring-asserted per `@file:` block).
- REAL production scan PASSES (type exists: `struct OwnedIdentityDid` @identity_capability.rs:96, `pub(in crate::context)`; reissue/as_did both `pub(in crate::context)`). No false-FAIL → CI not broken.
- ADR-049 §5 anchor target EXISTS (`### 5. OwnedIdentityDid: ...` @ADR-049-actor-per-context.md:94).
- ruff clean.

### MEDIUM finding (provenance, not security):
`crates/scp-runtime/src/context/supervisor/identity_capability.rs:1-2` doc-comment STILL points at the OLD dangling anchor `§"\`OwnedIdentityDid\` via module visibility"` (wraps across 2 lines, so single-line grep misses it). Commit claims "fix doc anchors" but missed the capability's OWN defining file. Old heading does NOT exist in ADR-049 (exit 1). It's the ONLY remaining old-form ref repo-wide. Fix: repoint to `ADR-049 §5` + `spec §9.4.1`.

### OBSERVATION:
Accessor-vis check rejects `pub(super)` for reissue/as_did though that's NARROWER than the allowed `pub(in crate::context)` (fail-closed, harmless; docstring says "same name-visibility as the struct" — pub(super) would be safe but is conservatively rejected).

---

## FOLLOW-UP REVIEW (worktree 2e-followup, HEAD f5d2a197f) — 2026-06-17
Reviewed substantive `fa74e8724 fix(gate): confine build-site mint to bare-param, no escapable scope, un-aliasable DID` + head `f5d2a197f docs(gate): disambiguate fixture labels + DID_PARAM_TYPE fail-closed note`.

### Verdict: CLEAN, COMPLETE STRENGTHENING. ZERO findings. Sign off to land.
The prior MEDIUM (identity_capability.rs:1-2 dangling anchor) is FIXED on this branch (now `ADR-049 §5` + `spec §9.4.1`). All old `§"…via module visibility"`/`§"Cross-identity isolation"` anchors repointed to ADR-049 §5 across handle.rs/mod.rs/supervisor.rs/identity_capability.rs.

### Three build-site mint-arg bypasses closed (all in `_mint_ref_exempt_build_actor_deps` / `_mint_call_arg_is_owning_did` / `_scan_root`):
- **(A) Pattern-binding shadow** — `_shadows_before` extended from let/assignment to ALL non-`let` binders via `_PATTERN_BINDER_FIELDS = {match_arm:pattern, let_condition:pattern (covers if-let/while-let/let-else), for_expression:pattern, closure_expression:parameters}`. An enclosing binder's head starts < `before_byte`, so the same `n.start_byte < before_byte` test catches enclose AND lexical-precede. Byte-order preserved → post-mint binder still does NOT disqualify (CONTROL-B passes).
- **(B) Closure-laundered mint** — reuses `_escapable_scope_between(node, fn_node)` in build-site exemption: ANY `closure_expression`/`async_block`/`gen_block`/nested `function_item` between mint and fn body dissolves exemption. Production `build_actor_deps` is `async fn` but its body is a plain `block` (NOT async_block) → mint is a direct statement → stays exempt (no false-fail).
- **(C) DID type-alias** — banned subtree-wide (`SUPERVISOR_SUBTREE_REL`): `_use_alias_did_tail` for `use …DID as X`, and `type_item` with `_type_tail_identifier(rhs)==DID_PARAM_TYPE` for `type X = …DID`. Both cfg(test)-exempt + `_is_associated_type`-excluded. EXCLUSIONS SOUND: associated type reachable only as `<T as Tr>::Out` (not a bare param-type name); fn-body-local `type` not in scope for the signature's param types (won't compile) → neither can rename DID on a param. Closes the sole-DID-param-count defeat (G03-via-alias).

### Completeness argument (the core question) — AIRTIGHT:
Exempt mint must satisfy ALL: file-pin + fn-name `build_actor_deps` + `impl Supervisor` + no nested-mod-shadow + no escapable scope + EXACTLY-ONE non-self `DID`-typed param + arg is bare `<owning>`/`<owning>.clone()` pinned to that param's name + no shadow by any of the 8 Rust binding forms. Rust has exactly 8 value-binding forms for a name (let/assignment/match-arm/if-let/while-let/let-else/for/closure-param) — ALL now covered. The only non-binder channel to make `owning_did` resolve to attacker data is param-type confusion (rename DID onto attacker param) — closed by (C) (Rust has exactly 2 type-renaming mechanisms: `type X=T`, `use…as X`; both banned in subtree). NO arg-substitution channel left. WHICH DID supervisor passes as owning_did = spawn-site identity-assignment, HONESTLY out of remit (gate confines the build-site arg to the param; it cannot and should not police what the supervisor binds to that param).

### Verified live:
- `--self-test` PASS (67 modes incl all 8 new fixtures: build_site_{match_arm,if_let,while_let,for_pattern,closure_param}_shadow, build_site_closure_laundered_mint, did_type_alias_owning_param, did_use_alias).
- REAL production scan PASS (1 decl, struct `pub(in crate::context)`, reissue/as_did `pub(in crate::context)`) — NO false-FAIL.
- ruff clean. No DID alias of banned form in subtree (only a doc-comment substring, not an AST node).
- Adversarial probes (7) against `_mint_call_arg_is_owning_did`: let-else/if-let/while-let/match-arm/inline-closure-param shadows + 2nd-DID-param all → exempt=False; production shape + non-owning-for + post-mint-shadow → exempt=True. All correct.
- STRICTLY ADDITIVE: fa74e8724 deletions = docstring rewording only; f5d2a197f deletions = fixture COMMENT-label renames (G02/G03→CTM-1/MHM-1) to break label collision — not enforcement logic, not the `@file:`/mint-spelling strings REQUIRED_FIXTURE_FAILURES matches.
- DID_PARAM_TYPE exact-match is intentional + fail-closed: a future DID rename → owning-param count drops to 0 → exemption dissolves → gate FAILS the build (never silently exempts a forgery). Documented in head commit.
- Spec §9.4.1 point-2 `as_did` carve-out + ADR-049 §5 reissue/as_did visibility wording consistent with gate's enforced allowed-set. ADR-049 §5 anchor exists @line 94.

### Coverage boundary honest: type-system PRIMARY (gate = defense-in-depth), relocation-inert (file+subtree pinned), build.rs/proc-macro + spawn-site-DID-assignment explicitly out of remit. Production .rs UNCHANGED except doc-comment anchor repoints (no logic change).
