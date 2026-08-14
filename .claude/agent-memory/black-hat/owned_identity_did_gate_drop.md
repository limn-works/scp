# OwnedIdentityDid AST-gate drop (commit d1a39cf3d) — BOUNDARY HOLDS

Change: deleted `scripts/check-owned-identity-did.py` (1184-line tree-sitter frozen-shape
whitelist over `identity_capability.rs`) + CI job; added `#![deny(non_local_definitions)]`
to `crates/scp-runtime/src/context/supervisor/mod.rs`. Threat model = INSIDER-ONLY.

## Verdict: simplification VALID; deny-lint + type system close the COMPILER class; the
residual class is exactly what the ADR explicitly assigns to code review (and was never
mechanically wider than that under the old gate either).

## What the lints/type-system actually cover (PoC-verified, CARGO_TARGET_DIR=/tmp/bh5):
- Private `did` field blocks outsider struct-literal (E0451) even though mod is nameable
  `pub(in crate::context)` from `actor/handlers/`. [Vector A — blocked]
- Outsider nested-impl minter: doubly blocked (E0451 private field) regardless of lint. [B]
- `deny(non_local_definitions)` fires HARD ERROR for impl nested in: fn body [C],
  const block, closure, async block — ALL caught. The lint is COMPLETE for the
  body-nested-impl class.

## What NEITHER type-system NOR the two lints catch (all COMPILE CLEAN, no warning):
These require editing `identity_capability.rs` (or `supervisor/*.rs`) — pure insider.
- [E] NEW minter method added INSIDE the existing impl block (`pub(in crate::context) fn`
  → mintable from all of crate::context incl untrusted handlers). Lint silent (local impl).
- [F] Widen `issue_for_actor` `pub(super)`→`pub(in crate::context)`: ONE-TOKEN diff,
  outsider handler code then mints arbitrary DID. Lint silent.
- [G2] `macro_rules!` defined+invoked at MODULE level expands to a module-level 2nd impl
  with a wide minter. `non_local_definitions` does NOT fire (impl is module-level, not
  body-nested). Old gate A1 banned macro_invocation by KIND.
- [H] Plain module-level SECOND `impl OwnedIdentityDid` block. Lint silent (not nested).
- [D] Module-level 2nd minter in supervisor.rs (sibling file): always allowed (pub(super)
  is by-design callable from all supervisor files). NOT a regression — old gate only
  scanned identity_capability.rs + mod.rs, never supervisor.rs.
- [I] Body-semantic forgery: rewrite `reissue` body to mint attacker DID. Compiles. Old
  gate NEVER inspected bodies either (A3 charter). Backstop = `reissue_clones_the_same_owning_did`
  unit test (PASSES under `--features testing`; FAILS-to-compile without it due to
  pre-existing missing `send_induce_panic`/`TestInducePanic` test helpers — orthogonal).

## Why this is NOT a finding (the honest call):
The OLD gate scanned ONLY identity_capability.rs (CAP_FILE) + mod.rs. It froze that ONE
file's shape: exactly {issue_for_actor, reissue, as_did}, no 2nd impl/derive/macro, frozen
visibilities. Vectors E/F/G2/H ARE diffs to that frozen file — so the gate DID catch them.
BUT the ADR's own enforcement text explicitly reassigns this entire class to code review:
"adding a derive, WIDENING A VISIBILITY, or introducing a SECOND arbitrary-DID constructor
is a visible diff that review catches." So nothing review-INVISIBLE was lost. Every
gate-only vector (E/F/G2/H) is a visible edit to a ~155-line single-struct single-impl file
that adds a constructor / widens a visibility / adds an impl/macro — precisely the diffs the
ADR says review owns. The compiler now owns the ONE vector review is worst at (body-nested
2nd minter, easy to miss in a long fn) via non_local_definitions. Net: defensible trade.

## Residual notes (non-blocking, worth surfacing to orchestrator):
1. The lint catches body-nested impls but NOT module-level macro-expanded 2nd impls [G2] /
   plain 2nd impls [H] / new-method-in-existing-impl [E] / visibility-widening [F]. These now
   rest 100% on human review of the frozen file. The old gate mechanically caught them. This
   is a real reduction in MECHANICAL coverage, accepted as "review's job" per ADR-049 §5.
   If review vigilance on this file ever lapses, [F] (one-token widen) is the cheapest forge.
2. `scp-runtime` lib TEST target does not compile WITHOUT `--features testing` (pre-existing
   missing send_induce_panic). The reissue body-semantics guard only runs under that feature.
   CI uses scp-runtime/testing, so it runs in CI. Fine, but the guard is feature-gated.
