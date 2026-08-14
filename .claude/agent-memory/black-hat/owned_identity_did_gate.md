# OwnedIdentityDid capability-token CI gate (scripts/check-owned-identity-did.py)

ADR-049 §5 type-system capability token. Mint = `pub(super) issue_for_actor`,
private field `did: DID`, struct `pub(in crate::context)`, crate-level
`#![forbid(unsafe_code)]` in scp-runtime/src/lib.rs:21 (the REAL unsafe enforcement).

## CURRENT KERNEL (commit 3d6a8d55e — "sound definition-shape kernel" rewrite)
The 6000-line name-resolution gate was DELETED and replaced by a ~690-line kernel
that checks DEFINITION shape only (lesson: ast-gate-checks-definition-not-name-resolution.md).
Confirmed bypasses against THIS kernel below. All COMPILE (`cargo check -p scp-runtime`)
and gate PASSES rc=0.

### FINDING 1 (HIGH) — forbidden derive hidden behind a comment
`_struct_outer_attrs` (line ~532) walks ONLY contiguous `attribute`-typed siblings
above the struct. A `line_comment` (`///`) or `block_comment` between
`#[derive(Clone)]` and the struct breaks the run → derive skipped by check 6.
Rust still applies the derive (doc desugars to `#[doc]` attr; both apply). Works
for Serialize/Deserialize/From etc. Clone lets any holder of `&OwnedIdentityDid`
duplicate the cap past the deliberately-weak `reissue`. 2-line forgery.

### FINDING 2 (HIGH) — second arbitrary-DID minter via type alias (G07 NOT fixed)
Check-8 is NAME-based: `struct_expression` named OwnedIdentityDid/Self, and
return-type token `OwnedIdentityDid`. `type Cap = OwnedIdentityDid;` + free fn
`pub(in crate::context) fn forge_for_anyone(did: DID) -> Cap { Cap { did } }`
inside the file defeats BOTH halves. Mints from any raw DID, reachable from
`crate::context::actor::handlers`. GENUINE type-system hole (in-module free fn,
private-field literal legal). The prior memory claimed the rewrite's check-8 fixed
G07 free-fn forge — it did NOT, the alias evades it. Cleanest single-file bypass.

### FINDING 3 (MEDIUM) — aliased-DID param turns reissue into a minter
`_fn_takes_raw_did` matches param type token `DID`/`Did*`. `type Owner = DID;` +
`reissue(&self, owner: Owner) -> Self { Self { did: owner } }` mints arbitrary DID;
gate thinks reissue takes no DID. Requires also fixing the in-module caller arity in
actor/deps.rs. Compiles; gate PASSES.

### FINDING 4 (MEDIUM) — deny(unsafe_code) check (check 9) satisfied by a comment
Whitespace-stripped substring search for `#![deny(unsafe_code)]`. mod.rs line ~29
DOC COMMENT mentions that literal → deleting the real attr (line 40) still passes.
NOT independently exploitable (crate-level forbid in lib.rs catches unsafe). Pure
gate soundness gap / false-negative.

## ROOT CAUSE (shared by F1/F2/F3)
Gate matches type/derive/constructor by literal NAME + sibling-ADJACENCY. Rust
type aliasing + non-attribute siblings (comments) preserve semantics while evading
name/adjacency matching. Same aliasing arms-race the lesson warned about — now
recurring INSIDE the "sound definition-shape" checks. Fixes: resolve `type X = Y`
aliases of TYPE_NAME and DID within the file before name-matching (checks 4/5/8);
collect outer attrs across intervening comments (Rust permits them); check 9 must
ignore comment/string text (parse for a real `attribute_item`).

## Assessments
- Self-test harness is REAL (`do_self_test` calls same `_enforce` as `_scan_real`),
  not vacuous. BUT fixtures cover NONE of F1-F3 (forbidden_derive fixture uses a
  CONTIGUOUS derive; no alias fixtures exist).
- False-positive: `#[cfg_attr(test, derive(Debug))]` rejected — intended strictness
  (doc forbids Debug even test-only). Defensible, not a bug.
