# OwnedIdentityDid gate (check-owned-identity-did.py) — Phase 2E black-hat pass @ e7dba843b

Commit "scope item-shadow walk to mint-enclosing blocks; ban attr-macro in body".
Type system PRIMARY (`issue_for_actor` pub(super), private field); gate is defense-in-depth (86 modes).

## RESULT: NO COMPILING FORGERY FOUND. Build-site exemption is sound.

Probed exhaustively (all via mutate-real-supervisor.rs + cargo check + gate-exit methodology
plus direct `_shadows_before`/`_body_has_*` harness):
- Block-scope shadow walk (the new logic): SOUND in both directions.
  - Ancestor/same-block const/use shadow of `owning_did` (incl. mint nested in if/match/loop/unsafe): CAUGHT.
  - Sibling/descendant-scope const named owning_did (mint NOT inside it): correctly NOT flagged (no FP),
    and these PASSes are SOUND — Rust resolves mint to real param, token = real owning DID.
  - Order-independence (const AFTER mint at ancestor block level): CAUGHT.
- All pattern binders (let, @-binding, ref mut match, tuple destructure, struct shorthand,
  if-let shorthand, closure param): CAUGHT.
- macro_invocation ban (any m!()/m!{}/m![]): CAUGHT. macro_rules! def w/o invocation = inert (harmless).
- glob use ban (bare `use evil::*` and in-list `use evil::{a,*}`): CAUGHT.
- attr-macro ban (`_body_has_noninert_attr_item`): catches plain `#[custom]`.

## ONE STRUCTURAL GAP (defense-in-depth only, NON-COMPILABLE here → not a forgery)
`_attr_path_tail` keys on PATH TAIL. A path-qualified custom attribute proc-macro whose tail
COLLIDES with an inert built-in name is classified inert (exemption NOT refused):
  `#[crate::evil::derive]`, `#[a::b::inline]`, `#[x::cold]`, `#[a::b::must_use]` -> noninert(refuse)=False.
INERT_BODY_ATTRS = {allow,deny,warn,forbid,expect,cfg,cfg_attr,inline,must_use,doc,derive,
  non_upper_case_globals,non_camel_case_types,non_snake_case,track_caller,cold}.
Such an attr-macro could inject `const owning_did: DID = ATTACKER;` (attr-macros emit sibling items),
which `_shadows_before` (pre-expansion AST) can't see.
WHY NOT A FORGERY: scp-runtime has NO in-tree proc-macro crate and NO reachable attribute
proc-macro whose path-tail is derive/inline/cold/must_use/etc. (deps are derive macros +
async_trait/tokio main,test/tracing instrument/rustversion — none collide AND inject). So it
does NOT compile. Defense-in-depth hardening suggestion: for path-qualified (scoped_identifier)
attributes, require the FULL path be a known built-in, not just the tail; or treat any
path-qualified in-body attribute as non-inert (fail-closed). Cheap, zero-FP (real body has no
in-body attr at all).
