# Class-S fail-closed compile-enforcement migration — black-hat rev @272c4d079

Empirical adversarial probe of ADR-049 §9 Class-S compile-time + whitelist enforcement
(`crates/scp-runtime/src/context/actor/class_s.rs`, 5210 lines). All probes recompiled; worktree reverted clean.

## VERDICT: core compile-time guarantee HELD against every probe on the THREE privatized
fields (`PerContextState.class_s`, `GovernanceState.class_s`, `revoked_spending_ucan_cids`).
But three real residuals/weaknesses confirmed — all DISCLOSED in the file's own docs.

## Probes that FAILED (enforcement held) — privatized-field path
- 1a return `&mut` from the shared `&ClassSState` field on ClassCMut → E0308 mutability mismatch.
- 1b `*const ClassSState as *mut` + unsafe block → rejected by `#![forbid(unsafe_code)]` (lib.rs:21, CONFIRMED present).
- 1c `mem::take(self.class_s)` → E0308 (field is `&T`, take needs `&mut T`) + ClassSState not Default.
- 1d `mem::replace(self.class_s, _)` → E0308 mutability.
- 1f `*self.class_s = _` → E0594 cannot assign behind `&`.
- ClassSMut::new / ClassCMut::new are PRIVATE (no pub) → handler modules cannot construct a ClassSMut directly.
- Adding a no-persist `&mut self` Class-S mutator INSIDE the original `impl ClassSCell` → tripwire TRIPS (FAILED loudly, method in Found:).
- Second `impl ClassSCell` placed BEFORE `impl ClassSCommitToken` → tripwire TRIPS (in-region).

## FINDINGS (probes that broke something)

### F1 (MEDIUM, disclosed) — best-effort downward-auth rollback hole (ceiling/suspended_capabilities)
`ContextRoleState.ceiling` + `.suspended_capabilities` are `pub` (crates/scp-protocol/src/context/roles.rs:811,837).
`ClassCMut::role_state_mut()` (line 1549) + `ClassCSplit::from_state()` (1336) + `ClassCSplit.role_state`
hand out a whole `&mut ContextRoleState` on the NO-persist / best-effort path. A handler can
un-suspend a capability (re-grant) or re-widen the ceiling with only coalesce-window durability →
§9 downward-auth rollback the caller observed as narrowed. COMPILES; tripwire blind (scans only impl ClassSCell).
This is the file's documented "Known residual" — confirmed EXACTLY as disclosed (not worse). Boundary: 3 exits.
`RoleStateClassCMut` (the field-granular replacement, read-only ceiling/suspended) EXISTS but callers not migrated.

### F2 (MEDIUM) — view-destructure edit defeats "airtight by construction" + is invisible to ALL mechanical checks
Editing `GovernanceClassCMut::new` (627) destructure to bind `class_s` `&mut` (instead of `..` rest) +
adding a field-granular accessor `attack_class_s_mut(&mut self)->&mut GovernanceClassS` COMPILES cleanly.
FULL CHAIN `cell.class_c_view().governance_class_c_mut().attack_class_s_mut().executed_proposals.clear()`
= no-persist Class-S mutation reachable from any handler. COMPILES end-to-end, ZERO errors.
The "airtight by construction" claim only stops adding a WHOLE-bucket accessor; it does NOT stop binding a
Class-S field `&mut` in the destructure itself. Only guard = the SAFETY INVARIANT comment + review.
The whitelist tripwire scans ONLY `impl ClassSCell` — it does NOT scan GovernanceClassCMut / ClassCMut /
RoleStateClassCMut, so this edit is caught by NO mechanical check. Same applies to ClassCMut::new (1380)
and RoleStateClassCMut::new (1018). Applies to all THREE privatized fields if their view's destructure is edited.

### F3 (LOW) — tripwire region-escape: second `impl ClassSCell` AFTER `impl ClassSCommitToken`
Tripwire isolates impl text as [first `\nimpl ClassSCell {\n` .. first `\nimpl ClassSCommitToken {\n`].
A no-persist Class-S mutator in a SECOND `impl ClassSCell` block placed AFTER the token impl is OUTSIDE
the scanned region → COMPILES + tripwire PASSES. Narrow (needs odd placement; reviewer would notice),
but an honest contributor who naturally splits the impl after the token impl gets false safety.
Fix: scan ALL `impl ClassSCell` blocks, or assert exactly one exists.

### F4 (LOW, disclosed/by-design) — ClassSCommitToken Drop guard is debug-only; #[must_use] silenceable
No `[profile.release]` override → `debug_assertions` OFF in production. Token Drop guard = `debug_assert!(false)`
(no-op in release) + `tracing::error!` (just a log). `begin_class_s` → mutate → drop `_token` without commit →
COMPILES, no warning (binding to `_token` suppresses #[must_use]), and in RELEASE silently skips the
fail-closed persist → acknowledges an unpersisted Class-S consume → crash re-opens replay/re-spend window.
Enforced only by CI (debug-assertions ON) covering every drop path. Disclosed as "parity with EconomyTicket."
Weakest link: relies on test coverage, not structure. A production-only error-path drop escapes CI.

## NON-FINDINGS (defenses confirmed sound)
- Attack 4 (clear_committed_reservation_idempotent): only caller (handlers/saga.rs:1946) is inside the
  `xctx_committed_invocations.contains(&saga_id)` witnessed arm; removes xctx_caller_reservations (not the
  witness); rebuilt-irrelevant on respawn. Sound. Residual = future pub(crate) caller misuse (inherent).
- forbid(unsafe_code) backstop holds (the only `unsafe` token in the crate is a keyword inside a string literal in the tripwire lexer).

## Author's own threat model (accurate): tripwire is an honest-contributor REVIEW SPEED-BUMP,
NOT an adversarial gate — explicitly concedes anyone who can add a mutator can edit KNOWN_SAFE/delete the test.
The LOAD-BEARING guarantee is the cell's no-whole-&mut shape + forbid(unsafe). F2 shows that shape is only
as strong as the un-checked view destructures.
