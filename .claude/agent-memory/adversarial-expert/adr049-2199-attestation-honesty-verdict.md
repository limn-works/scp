---
name: adr049-2199-attestation-honesty-verdict
description: Round-2 SHIP verdict on #2199 KeyDestructionAttestation honesty — DisposalOutcome privatization + orchestrator deletion confirmed
metadata:
  type: project
---

# #2199 KeyDestructionAttestation honesty — ROUND-2 SHIP (2026-08-02)

Both round-1 conditions RESOLVED and verified against code (worktree adr049-2199, rebased origin/main 83e3d2f29).

**Why:** ADR-018 attestation destroyed-flags are a provenance record; a fabricated `true` is a nullifier-class false guarantee (worse than honest absence).

**How to apply:** if revisiting #2199 or the disposal/attestation seam, this is the settled shape — do not re-litigate.

## What landed
- `DisposalOutcome` (scp-runtime state.rs ~416): `pub(crate)` struct, PRIVATE bool fields, PRIVATE `observed()` minter, `pub(crate)` read-only accessors. Sole minters: `ContextCryptoState::dispose_secrets` (observed pre-state) + Broadcast N/A `observed(false,false)`. Zero external construction (grep-verified). Fabricated `{true,true}` structurally unrepresentable outside module. Honest-by-construction is REAL not doc-only.
- Orchestrators DELETED: key_destruction.rs (382 lines) gone; `finalize_close` (ttl_close_helpers.rs:945) is the SOLE production attestation builder, reads observed accessors.
- TTL-expiry path (ttl.rs:780-813): discards DisposalOutcome, sets STEP_MLS/SENDER completion bits UNCONDITIONALLY — these are `is_complete()` despawn-gate bits (completion), NOT attestation flags (provenance). black-hat liveness fix; no fabricated flag.
- Tests: `dispose_secrets_seeded_encrypted_reports_observed_true` uses REAL two-party MLS join (stand_up_two_party); absence cases assert false.

## Residuals (non-blocking)
- MEDIUM: wire type `KeyDestructionAttestation` (scp-protocol memory_scope.rs) still has PUBLIC bool fields — a FUTURE new build site could hand-write `true` bypassing DisposalOutcome. Can't fix without inverting scp-protocol→scp-runtime dep. Natural boundary; mitigated by single documented canonical build site + code review.
- LOW: close.rs:479 says retained SummaryVerificationWindow types "tracked separately" without inline-citing #2225.
- #2225 (OPEN, verified real): SummaryVerificationWindow / §5.11 / ADR-018 AC6 wiring gap — genuine pre-existing deferral, keep-and-file is correct (deleting specced type = scope creep).

VERDICT: SHIP.
