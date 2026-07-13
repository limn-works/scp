# Guard a restore/merge sink on the INCOMING set, never on the live store

## Context

ADR-049's Class-M floor merge (`context/supervisor/floors.rs`) is the sink that a
restore/import routes a persisted snapshot's anti-replay floors through, merging
them into the authoritative live floor registry.

## The trap (D2 — cold-restart replay)

The DELETED provider merge twin short-circuited on the LIVE store being empty:

```rust
if local_floors.is_empty() { return Ok(()); } // WRONG for a cold restart
```

On a **cold restart** the live store is empty but the snapshot (the `incoming`
set) is non-empty. Guarding on the live store makes the merge early-return, so
the snapshot's durable floors are **silently discarded** — the fresh registry
stays empty and the cold-restart anti-replay window reopens (a replayed message
at or below the persisted floor is admitted).

## The rule

**Guard the sink on `incoming.is_empty()`, never on the live store.** The
registry twins do exactly this:

```rust
if epochs.is_empty() && recv.is_empty() { return Ok(()); } // correct
```

so a cold restart (empty live registry, non-empty snapshot) RUNS the merge and
POPULATES the registry. The regression guard is a two-line change with a
one-boot-cycle security hole — easy to reintroduce, so it is pinned by a
cold-restart durability test that asserts the fresh registry is
**empty-then-populated** from the blob (that exact assertion catches the
short-circuit) and by the ADR-049 read-authority-switch decision's normative
invariant.

## Companion pattern: decomposed-prep-then-atomic-flip

The read-authority switch that surfaced this was executed as *prep slices that
land dead-but-tested code first, then one atomic flip*:

- **Prep** (separate PRs): add the new authoritative registry, the newtype, the
  `From<FloorAdvanceError>` conversion, and thread the export floors as
  pass-through params — each landing behind the old behavior, unit-tested in
  isolation, changing no live path.
- **Atomic flip** (one commit): delete the old home's read-authority (provider
  mirrors), flip the seams fail-closed, and repoint export/restore — all at
  once, so there is never a compilable intermediate state where enforcement is
  half-gone (which would be fail-OPEN).

The flip commit is the security-critical one. Verify it mechanically: a grep
that the seams contain no log-and-drop (`if let Err(e) = … { debug!… }`) and a
structural assertion that the gate precedes the install (gate-before-install).

## Also: relax a merge ceiling by TRUST, not by emptiness

The epoch-poisoning overshoot ceiling belongs ONLY on the untrusted-import path
(`RejectRegression`). A node restoring its OWN at-rest snapshot
(`MaxMergeTrustedLocal`) must load its accumulated high-water VERBATIM — else a
context whose true floor legitimately exceeds `MAX_EPOCH_ADVANCE` becomes
permanently unrestorable (the cold-restart `local = 0` makes `ceiling =
MAX_EPOCH_ADVANCE`). The LIVE per-message gates always keep their ceiling; only
the restore/import merge relaxes, and only under trusted-local.
