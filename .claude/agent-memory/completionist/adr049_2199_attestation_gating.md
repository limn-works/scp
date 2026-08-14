---
name: adr049-2199-attestation-gating
description: #2199 KeyDestructionAttestation honesty gating — round-2 confirmation; orchestrator deletion + kept-specced-types decision
metadata:
  type: project
---

# SCP #2199 — KeyDestructionAttestation observed-disposal gating (round-2 CONFIRM)

Gate `mls_group_destroyed`/`sender_keys_destroyed` on the OBSERVED disposal
outcome instead of hardcoded `true`. Round-1 found INCOMPLETE (orphaned
orchestrator + dead threaded param). Round-2 deleted the orchestrator.

**Verdict: HIGH RESOLVED / functionally COMPLETE.** Two comment-only stale refs remain (see below).

Key facts for future passes:
- The honesty mechanism is `DisposalOutcome` (`scp-runtime .../actor/state.rs`): a
  `pub(crate)` struct with PRIVATE fields + PRIVATE `observed()` const-ctor, minted
  ONLY inside `crate::context::actor::state` (by `ContextCryptoState::dispose_secrets`
  from PRE-disposal presence, and the Broadcast N/A arm). Readable only via accessors.
  A fabricated `(true,true)` is structurally unrepresentable. Verified: type never
  appears in any pub/FFI signature — crate-internal only.
- Sole canonical attestation build site = `ttl_close_helpers::finalize_close`
  (returns `Option<KeyDestructionAttestation>`), consumed (LOG-ONLY) by
  `handle_finalize_close`. Durable recording into the ContextClosed leaf (ADR-018
  item-7 "recorded in close event") is deferred to **#2215** — legit, never done on main.
- TTL-EXPIRY path (`ttl.rs apply_ttl_terminal_transition`) disposes but builds NO
  attestation — discards DisposalOutcome. NOT a gap: it never built one on main.
  Round-2 also SEPARATED completion-vs-provenance on that path (STEP bits =
  completion, set unconditionally after dispose runs) — fixing a real infinite-respawn
  liveness bug an earlier revision introduced by gating STEP bits on observed flags.
  Two new liveness regression tests cover it.
- Kept-specced-types decision (CORRECT): `SummaryVerificationWindow` + dispute cluster
  have a genuine spec home — spec `05-contexts.md §5.11` (verification window 300s,
  SummaryDisputed, 24h dispute limit) + ADR-018 (phase-4.md:227) item-6 "Summary close".
  Deleting would be artifact-flow inversion. They were ALREADY unwired on main (only
  the dead orchestrator referenced them). **#2225** correctly captures the pre-existing
  unwired gap (cites ADR-018 AC6 / §5.11 / #365). Keep-and-file is complete.

Minor residue (comment-only stale provenance to the deleted module/type — should be
swept in the same PR per the dead-code-atomic-swap rule):
- `scp-protocol/.../close.rs:496-499` test-mod note still says CloseOrchestrator tests
  "moved to scp_runtime::context::key_destruction" (deleted module). Sibling note in
  memory_scope.rs:498 WAS updated to "DELETED in #2199"; this one missed.
- `scp-runtime/tests/phase2_integration.rs:717-718` "in production, this would call
  KeyDestructionOrchestrator" — now false; prod uses the actor finalize seam.

Diff-scope gotcha: the worktree was 1 commit BEHIND origin/main (HEAD 83e3d2f29 vs
origin/main 25824a30a). So `git diff origin/main` was POLLUTED with the REVERSE of
25824a30a (outlet.json, trust.ts, trust-facade.test.ts, outlets/interface.rs). The
REAL #2199 diff = `git diff HEAD` (14 files). Always diff against the committed base,
not origin/main, when a worktree is behind.
