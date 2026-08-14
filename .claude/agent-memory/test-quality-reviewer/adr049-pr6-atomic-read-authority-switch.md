---
name: adr049-pr6-atomic-read-authority-switch
description: ADR-049 PR-6 read-authority switch test review — RE-REVIEW @d02680cd9 confirms the D1 recv-seam e2e gap I flagged is now CLOSED (reorder sub-case) plus D2 >1000; residual catch-up F-2 discrimination gap
metadata:
  type: project
---

# ADR-049 PR-6 atomic read-authority switch — test review

## RE-REVIEW @d02680cd9 (branch feat/adr049-pr6-atomic-read-authority-switch)
Prior pass (@b61618887, with completionist+inquisitor) flagged: plan §9(1) FAIL-CLOSED-BLOCKS + §9(2) CATCH-UP e2e MISSING — recv-seam rested on structural `fn_body_contains` only. Now added. Verdict: **gap CLOSED for D1-reorder + D2; REVISE (non-blocking) for catch-up F-2 discrimination.**

The switch: Supervisor-owned Class-M floor registry (`supervisor/floors.rs`) is AUTHORITATIVE for recv `(epoch,sequence)` anti-replay + sender-epoch high-water; provider `open()` H9/replay/tracker DELETED → `open()` is pure decrypt + surfaces `env.receive_floor`. Enforcement moved to `decrypt_and_dispatch` (messaging_helpers.rs:2956) which `?`-gates on `check_and_advance_recv_sequence` BEFORE `Ok(Some(*env))`.

### GENUINE / CLOSED
- **D1 recv-seam (reorder)** `decrypt_and_dispatch_fail_closed_blocks_reorder_and_replay_e2e` (supervisor.rs:18770). REAL two-party join via `two_party_test_support::stand_up_two_party` (Bob installs joined group + Alice sender key epoch 1, real MLS). Alice seals 2 app envelopes; the differentiating sequence is the OUTER sender-layer `state.send_sequence` (0 then 1, provider.rs:1950/1975) — NOT the inner `sequence:0` (hardcoded in both, irrelevant to floor). Deliver msg_b(seq1) first→accepted, asserts registry floor == surfaced floor_b (proves seam CONSUMES surfaced floor, strong). Deliver msg_a(seq0) after→registry gate rejects `Err(CryptoFailed)`, floor unchanged. **The reorder MLS-decrypts because group uses OpenMLS-0.8 DEFAULT SenderRatchetConfiguration (out_of_order_tolerance=5; group.rs:468 does NOT override) → gen-0-after-gen-1 decrypts → registry gate is the real rejecter.** This is the genuine D1 e2e coverage.
- **D2 cold-restart >1000** `cold_restart_high_epoch_beyond_ceiling_restores_under_trusted_local` (supervisor.rs:18612). high=5000>MAX_EPOCH_ADVANCE(1000); real `restore_crypto_state_with_floor_guard(trusted=true)`; asserts verbatim 5000 load + replay at rf(5000,2) rejected. Load-bearing (A2 regression guard). CLOSED.
- **BUG-1b cross-axis atomicity (restore seam)** `untrusted_import_recv_regression_leaves_epoch_floor_unchanged` (supervisor.rs:18686). epoch9≥live5 PASSES but recv rf(2,0)<live rf(4,0) REGRESSES→whole merge rejected atomically, `assert_eq!(epoch, 5)` catches a non-atomic apply-epoch-then-reject. Load-bearing.
- **Registry primitives (floors.rs tests)**: `all_floors_merge_is_cross_axis_atomic` (1465, distinct 5→9 / rf(3,0)→rf(2,9), specific RecvSequenceNotMonotonic variant), `*_trusted_local_loads_high_epoch*_verbatim` (far=5000, proves ceiling skipped under MaxMergeTrustedLocal). Non-tautological, strong.
- **Concurrency** `concurrent_advances_are_strictly_monotone_no_lost_update` (1665). Two threads race 1..=2000 ladder; asserts ORDER-INDEPENDENT invariants (count_a+count_b==LADDER catches lost-update/double-accept; final floor==top). No sleep/timing → ZERO flakiness. Exemplary.

### RESIDUAL (REVISE, non-blocking)
1. **Catch-up F-2 discrimination GAP** `decrypt_and_dispatch_catch_up_after_epoch_rotation_e2e` (supervisor.rs:18872). Doc claims it proves "recv ceiling reads the just-advanced sender_epochs[alice]=2, not a stale lower floor." NOT isolated. Recv ceiling = `epoch_floor + MAX_EPOCH_ADVANCE` (floors.rs:351-352). With MAX_EPOCH_ADVANCE=1000, a recv at epoch 2 is accepted for epoch_floor ∈ {0,1,2} alike → the `check_and_advance_sender_epoch(ALICE,2)` line is NOT load-bearing for the acceptance assertion; a mutation making the ceiling read a stale/zero floor is UNCAUGHT. Test IS genuine integration (rotation→redistribute→install→decrypt at epoch2 real), just doesn't guard F-2 over-rejection. Fix: advance epoch high (e.g. 1500) and recv at an epoch in the gap (e.g. 1002) that a stale-0 ceiling(1000) rejects but advanced-1500 ceiling(2500) accepts.
2. **Reorder gate-origin not pinned**: reorder asserts `matches!(Err(CryptoFailed(_)))` broadly. If OpenMLS tolerance were ever set to 0, the reorder would become an MLS-rejection wrong-reason pass. Strengthen: assert the FloorAdvanceError Display substring ("recv-sequence floor ... non-monotonic", floors.rs:163-170) to prove gate-origin.
3. **Replay sub-assertion is MLS-covered, not gate-covered**: replaying msg_b (same MLS generation, secret erased) is rejected by OpenMLS's own ratchet at `open()` BEFORE reaching the registry recv gate. So `replay.is_err()` adds no registry-gate signal. Non-harmful; note it doesn't isolate the gate's replay path (the reorder does).

NOT executed (static review only; MLS multi_thread suite needs DYLD + slow build). Analysis rests on reading open()/seal()/decrypt_and_dispatch/floors.rs + OpenMLS default ratchet config.
