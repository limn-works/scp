---
name: issue2199-keydestruction-attestation-gating
description: Completeness review of #2199 (gate KeyDestructionAttestation destroyed-flags on observed disposal); finding — orphaned CloseOrchestrator after UniFFI bridge deletion
metadata:
  type: project
---

# #2199 — gate KeyDestructionAttestation on observed disposal

Review of the working-tree change gating `mls_group_destroyed`/`sender_keys_destroyed`
on the OBSERVED `dispose_secrets` outcome instead of hardcoded `true`.

**Why:** pre-existing fail-open (surfaced in #2148/PR#2186 review). Hardcoded `true`
was a lying provenance record; SCP treats a nullifier-class false guarantee as worse
than honest absence.

**How to apply (findings that recur here):**
- The honesty mechanism is sound: `ContextCryptoState/PerContextState::dispose_secrets`
  now returns `#[must_use] DisposalOutcome` computed from PRE-disposal presence. Two
  distinct `dispose_secrets` exist — the actor-state one (returns DisposalOutcome) and
  `crypto/mls/provider.rs OwnedMlsCryptoState::dispose_secrets` (returns `()`, a
  different type, correctly untouched; builder.rs + supervisor.rs:13847 call THAT one).
- **Main completeness gap:** deleting the UniFFI bridge's fabricated
  `CloseOrchestrator::initiate_close` block orphaned the ENTIRE
  `key_destruction::{CloseOrchestrator, KeyDestructionOrchestrator}` module — zero
  production callers remain (grep: only defs + `mod tests`). Yet the change threaded a
  new REQUIRED `disposal` param through its dead methods. The real attestation was
  RE-implemented inline in `ttl_close_helpers::finalize_close` (a parallel build) which
  also drops the orchestrator's relay-deletion duty. Should have either wired
  finalize_close THROUGH the orchestrator, or deleted it (dead-code atomic swap).
- `#2215` deferral (record attestation into ContextClosed event-log leaf) is LEGITIMATE:
  #2199 is scoped to flag HONESTY only; recording is a durable wire-format change blocked
  on a real artifact-flow constraint (spec/ADR must decide the leaf format first). The
  attestation was log-only before too (UniFFI logged CloseAction), so no regression.
- finalize_close attestation is built→logged→dropped; `FinalizeClose` reply is
  `Result<(), ContextError>`, so callers can't reach it. Fine for #2199, but #2215 must
  thread it through the reply, not only record it.
- Scope-bleed: worktree also carries unrelated ADR-057/KeyPackageAttestation spec
  deletions (09-security-model −111, 25-test-vectors −69, ADR-057, 05-contexts). Must
  NOT bundle into the #2199 commit.
