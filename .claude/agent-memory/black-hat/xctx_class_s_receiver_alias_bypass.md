---
name: xctx-class-s-receiver-alias-bypass
description: check-class-s-fail-closed.sh CLASS-A-live fail-open — receiver-prefixed markers defeated by `let x = &mut state.FIELD; x.method(` aliasing (fmt-clean, compiles); only non-execute_ handlers exposed (GOVHIT backstops execute_*)
metadata:
  type: project
---

# Class-S gate: receiver-alias CLASS-A-live fail-open (commit f29937089)

TARGET: scripts/check-class-s-fail-closed.sh fn-detector anchor is ROBUST (probed
extensively: pub/async/const/unsafe/extern "ABI"/pub(in path)/stacked-attr/
#[rustfmt::skip]-peel/multi-line-sig/where-clause/cfg_attr/doc-comment all caught).
Anchor is NOT the bug.

THE BUG — receiver-prefixed MUTATORS markers are defeated by idiomatic receiver aliasing.
Markers like `role_state.ceiling=`, `xctx_caller_reservations.insert(`,
`saga_pending.insert(`/`.remove(`, `xctx_nonce_dedup.record(`,
`membership.remove_member(`, `threshold_signers.retain(`,
`executed_proposals.insert(`, `spending_nonce_tracker.record(` embed a
`receiver.` segment. Binding the receiver to a local defeats the substring match:

    let rs = &mut state.role_state;
    rs.ceiling = CapabilityCeiling::new(lowered);   // text "rs.ceiling=" — NO marker
    persist_state_best_effort(state, deps, ctx);    // best-effort, not fail-closed

GATE EXITS 0. Fixture is `cargo fmt`-CLEAN, compiles under forbid(unsafe_code)
(NLL ends the `rs` borrow before `state` reborrow), idiomatic (de-duplicating a
repeated `state.role_state.` prefix is a NATURAL refactor — not contrived, no
#[rustfmt::skip], no nightly, no raw-ident). Confirmed live via fixtures in
crates/scp-runtime/src/context/zz_*.rs (gate-exit=0, FMT-CLEAN).

WHICH MARKERS ARE EXPOSED vs SAFE:
- EXPOSED (receiver-prefixed): role_state.ceiling=, xctx_caller_reservations.insert(,
  saga_pending.insert(/.remove(, xctx_nonce_dedup.record(, membership.remove_member(,
  threshold_signers.retain(, executed_proposals.insert(, spending_nonce_tracker.record(.
- SAFE (no receiver prefix): suspend_all(, suspend_capabilities(, threshold_value=,
  commit_spending_ucan_nonce(, enforce_*economy( — aliasing the receiver still
  leaves the bare method/ident token, so the marker still matches. (Verified:
  suspend_all via `let rs=&mut state.role_state; rs.suspend_all(..)` STILL caught;
  `gov.threshold_value = ..` STILL caught.)

BACKSTOP ANALYSIS — what makes it CLASS-A vs merely theoretical:
- GOVHIT (fail-closed-by-default for `execute_*` leaves) keys on fn NAME + presence
  of persist_state_best_effort, NOT on any marker. So an `execute_*`-named aliased
  mutator IS still caught (verified: execute_evict_member aliased → HIT). The
  governance-leaf axis is robust to aliasing.
- The TRULY EXPOSED sites are the NON-`execute_` Class-S handlers — exactly the
  cross-context saga + ceiling handlers: prepare_a (xctx_caller_reservations.insert,
  governance_helpers.rs ~), prepare_b (saga_pending.insert, xctx_nonce_dedup.record,
  saga.rs:791/807), apply_pending_ceiling_modification (role_state.ceiling=,
  governance_helpers.rs:388-414). These have NO GOVHIT backstop (header itself flags
  apply_pending_ceiling_modification as "Seam 1/black-hat, a NON-execute_ leaf"). Their
  ONLY protection is the receiver-prefixed marker → receiver-aliasing = total bypass.

LATENT not live: grep found NO current `let x = &mut state.<field>` alias of any
prefixed-marker field in production. The gap fires the moment someone refactors one
of those handlers idiomatically.

NAME-EXTRACTION sub-finding (CLASS-B): `fn r#execute_change_role(` extracts name "r"
(regex `[A-Za-z0-9_]+` stops at `#`), so a raw-ident-renamed governance leaf evades
GOVHIT. Contrived/insider (renaming to r# is pointless) — LOW.

FIX OPTIONS (structural, convergent — NOT one-more-spelling):
1. Make markers receiver-AGNOSTIC: match the method/field token alone
   (`.ceiling =`, `.xctx_caller_reservations.insert(` → just the distinctive tail
   `xctx_caller_reservations` is already unique; for ceiling use `.ceiling =` /
   bare `ceiling` field-write). Risk: more false positives (a local also named
   `ceiling`). The field names here are distinctive enough (xctx_*, saga_pending,
   executed_proposals) that dropping the receiver prefix is low-FP.
2. Extend GOVHIT-style fail-closed-by-default to the NON-execute_ Class-S handler
   set (prepare_a/prepare_b/apply_pending_*): a positive allowlist of which Class-S
   handlers may best-effort, everything else must fail-close. Closes the class by
   construction independent of marker text — the superior, convergent fix.
3. Forbid receiver aliasing of these fields via a separate lint (weak, denylist).

CONVERGENCE NOTE: the gate has had ~22 waves chasing fn-spelling. The fn-anchor is
now solid. This receiver-alias hole is a DIFFERENT axis (marker text vs fn grammar)
and is the kind of "AST gate re-checking in weaker source-text form a property the
type system can't see" that the simplifier tenet warns about. Option 2 (positive
fail-closed-by-default allowlist over the Class-S handler SET) is the structural
fix; chasing marker-text spellings is non-convergent.
