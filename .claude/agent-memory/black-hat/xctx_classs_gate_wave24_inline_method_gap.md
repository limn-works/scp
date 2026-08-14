---
name: xctx-classs-gate-wave24-inline-method-gap
description: check-class-s-fail-closed.sh wave-24 CLASS-A-live fail-open — inline-form markers are METHOD-specific; any non-enumerated mutating method on a Class-S field evades
metadata:
  type: project
---

# Class-S fail-closed gate — 4th axis CLASS-A-live (wave-24, HEAD 6c939108b)

TARGET: scripts/check-class-s-fail-closed.sh. Claims to EXHAUST the bounded grammar
of "obtain mutable access to a named PerContextState Class-S field" via 3 axes:
(1) inline `field.method(`, (2) `&mut <recv>.field` borrow, (3) `field: ref mut` destructure,
plus whole-state-alias `s.field.insert(`.

## THE GAP (proven, EXIT=0)
Axis (1) inline markers are **method-specific**, enumerating exactly:
`membership.remove_member(`, `executed_proposals.insert(`, `threshold_signers.retain(`,
`saga_pending.insert(`, `saga_pending.remove(`, `xctx_nonce_dedup.record(`,
`xctx_caller_reservations.insert(`.
The companion `&mut.<field>` / `refmut:<field>` markers fire ONLY on an explicit `&mut`/
`ref mut` token in source text. An inline method-call receiver (`field.method(`) carries
NEITHER token. So ANY mutating method on a Class-S field that is NOT in the 8-method set
evades all three axes.

The fields are `HashMap`s (xctx_caller_reservations: HashMap<SagaId,CallerReservationRecord>;
saga_pending, xctx_nonce_dedup similar). Evading mutators (all idiomatic, fmt-clean,
compile under forbid(unsafe_code)):
- `state.xctx_caller_reservations.entry(k).or_insert_with(|| r)`  ← cleanest Prepare-A stage
- `.entry(k).or_default()`
- `.get_mut(k)` then field-assign on the returned `&mut` slot
- `.drain()`, `.remove_entry(k)`, `.extend(iter)`, `.clear()`, `.retain(..)`
- index-assign `map[&k] = v` (IndexMut)
- `saga_pending.retain(..)` (marker is `threshold_signers.retain(`, NOT saga_pending.retain)

## PROOF
Planted `pub fn stage_caller_reservation_probe(state:&mut PerContextState, saga_id, record)`
in crates/scp-runtime/src/context/blackhat_probe.rs doing
`state.xctx_caller_reservations.entry(saga_id).or_insert_with(|| record);` — NON-execute_
name (no GOVHIT), best-effort/no-FC persist. `cargo check -p scp-runtime --features testing`
compiles (only dead_code warn). `cargo fmt --check` clean. Gate EXIT=0 PASSED.
8-variant batch file: ALL evade, EXIT=0.

## BUCKET: CLASS-A-LIVE. This is the real residual the wave-24 "grammar EXHAUSTED" claim
misses. The grammar of `&mut`-ACQUISITION is bounded, but mutation does not require an
EXPLICIT `&mut` — a `&mut self` method (entry/get_mut/drain/...) acquires it implicitly via
autoref, invisible to source-text markers. The 3-axis claim is FALSE for inline method calls.

## FIX OPTIONS
- Enumerate more methods = non-convergent denylist (the anti-pattern the header itself warns
  against). NOT recommended.
- SOUND fix = the header's own "strictly-superior future direction": make Class-S fields
  PRIVATE + a #[must_use] mutation guard / commit-method that performs FC persist on
  drop/commit → compile error if a Class-S mutation isn't FC-committed. Type-system enforced,
  retires the entire marker grammar. (ADR-052 / construction.md direction.)
- Cheaper structural alternative: pin the marker to the FIELD only (any `<field>.` followed
  by a method that isn't a known read-only accessor) — but that's an open denylist too.
