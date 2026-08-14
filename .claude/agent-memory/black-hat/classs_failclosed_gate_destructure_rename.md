---
name: classs-failclosed-gate-destructure-rename
description: CLASS-A-LIVE bypass of check-class-s-fail-closed.sh — ref-mut destructure-rename evades both field-pinned markers and the wave-23 &mut.<field> borrow companion
metadata:
  type: project
---

# check-class-s-fail-closed.sh — destructure-rename CLASS-A fail-open (survives wave-23)

**Gate:** scripts/check-class-s-fail-closed.sh (ADR-049 §9 crash-safety). Scans crates/scp-runtime/src/context for Class-S mutation sites lacking fail-closed persist.

**Wave-23 hardening recap:** uniquely-named field markers (`xctx_caller_reservations.insert(`, `saga_pending.insert(`, `xctx_nonce_dedup.record(`, `membership.remove_member(`, `executed_proposals.insert(`, `threshold_signers.retain(`) gained `&mut.<field>` companions. `normalize_borrow` collapses `&mut <recv-path>.<field>` → `&mut.<field>`, catching the idiomatic `let r = &mut state.xctx_caller_reservations; r.insert(...)` alias at its BORROW site.

**THE SURVIVING BYPASS (CLASS-A-LIVE):** Rust struct-destructure with field-RENAME via `ref mut`:
```rust
let PerContextState { xctx_caller_reservations: ref mut resv, role_state: ref mut rs, .. } = *state;
resv.insert(saga_id, record);   // marker misses: binding is `resv`, not the field name
rs.note_reservation();
persist_state_best_effort(state, ...);   // best-effort → Class-S hazard
```
- The mutation line is `resv.insert(` → no `xctx_caller_reservations.insert(` substring.
- The pattern uses `ref mut` (a binding mode), NOT `&mut <path>.field` → `normalize_borrow` regex (`&mut[[:space:]]+<path>.<field>`) never matches. `ref mut` ≠ `&mut`.
- fmt-clean (cargo fmt leaves it byte-for-byte; verified). Compiles under `#![forbid(unsafe_code)]`. NLL drops `resv` borrow before the `persist(state)` reborrow.
- **Generalizes to EVERY uniquely-named field marker:** xctx_nonce_dedup.record (anti-replay), saga_pending.insert, membership.remove_member — all evaded, all only best-effort.
- **Idiomatic to THIS codebase:** PerContextState is already destructured in actor/state.rs:1495/1615; disjoint two-field `ref mut` borrow is the canonical Rust way to mutate two fields at once (exactly what prepare/commit saga handlers do: reservation + role/membership).

**Vectors that SELF-DEFEAT (gate holds):**
- Accessor `fn reservations_mut(&mut self) -> &mut Map { &mut self.xctx_caller_reservations }` — the `&mut self.field` in the accessor body is caught; accessor fn itself HITs.
- `std::mem::take(&mut state.saga_pending)` / `std::mem::swap(&mut state.field, ..)` — contain `&mut state.field` → caught.
- Two-hop `let rs=&mut state.role_state; let c=&mut rs.ceiling; *c=...` — evades (`.ceiling=` marker misses `*c=...`) but CLASS-B (contrived; nobody writes 2 rebinds for 1 assign).
- Newline-split `&mut\n  state.field` — evades raw text but NOT fmt-clean (rustfmt collapses to one line → caught). CLASS-B.
- `let rs=&mut state.role_state; rs.ceiling=...` — CAUGHT by receiver-agnostic `.ceiling=` marker (fixture 60).

**FNQUAL anchor + leading-attr peeler: SOLID after the hoist.** Verified pub(crate) async fn, stacked `#[rustfmt::skip] #[inline] pub fn`, `#[inline] pub(crate) extern "C" fn` all caught. peel_leading_attrs + FNQUAL BEGIN-var did not desync match-vs-extract.

**Fix options:** (a) add a `ref mut <field>` companion marker per uniquely-named field (denylist — non-convergent, the gate's own anti-pattern); (b) BETTER: stop re-checking in source-text what the type system / a persist-ordering type could enforce — e.g. make the Class-S maps only mutable through a guard type whose Drop/method enforces fail-closed persist (compiler-enforced, alias-proof). Per CLAUDE.md §"Guard against non-convergent enforcement", chasing one-more-spelling is the wrong axis.
