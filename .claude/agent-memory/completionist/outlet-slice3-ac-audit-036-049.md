---
name: outlet-slice3-ac-audit-036-049
description: Full AC-dimension completeness audit of outlet streaming-saga slice-3 (SCP-OUT-036/044/045/046/047/048/049) — all ACs MET, reconciliations HONEST, but stories live on divergent unmerged branches
metadata:
  type: project
---

# Outlet streaming-saga slice-3 AC audit (036/044/045/046/047/048/049)

Audited 2026-08-02, AC-dimension (every acceptance criterion as a literal checkbox).

**Verdict: COMPLETE per-story on branches.** All 91 ACs across the 7 stories MET. No gaming
patterns (no `let _ = fn;`, no `#[ignore]`'d enforcement tests, no hardcoded None where real
value exists, no phantom story refs).

**Where the code lives (branches, NOT merged to main):**
- 036/044/045/046/047/049 stacked on `feat/outlet-xctx-049-conformance` (base 3c1683116 = 036 PR #2140). Read via `git show feat/outlet-xctx-049-conformance:path`.
- 048 on its OWN tip `feat/outlet-xctx-048-wasm-session` (status=done ONLY here; correctly `pending` on the 049 branch since not merged there). 048 tip also carries a variant of 049's conformance (#2198 fadf08c31) + later main-line (#2186 birth-into-actor, capinject-011).
- Branches are DIVERGENT (not clean ancestors of each other). `git merge-base --is-ancestor` returns MISSING for every cross-pair. The `:c`/`:s` zsh modifier bites `$B:crates` — use `${B}:path`.

**The 3 flagged layered-coverage reconciliations are HONEST** (Class-S actor-state isolation, spawn_actor_with_state is pub(in crate::context) = real security property, not a test shortcut):
- Runtime proof tests EXIST + LIVE (#[tokio::test], no ignore) + substantive, in supervisor.rs on 049 branch:
  - `xctx_streaming_saga_paid_drive_ac1_ac3_ac5_ac6` (:32160) — 10-chunk paid drive: receiver-before-terminal, Committing-then-resolved, escrow reserved-during/refunded-at-close + exactly-one PaymentReceipt, non-zero manifest root == compute over all chunks, receipt.verify() under B key, BOTH event-log leaves same root.
  - `xctx_streaming_saga_truncated_close_ac7` (:32410) — crash after 5/10: keyless→NeedsRepair(escrow held), key-bearing→seals prefix, invoked==1 (asserted twice), receipt root == prefix manifest (not full), billed_count in prefix range.
- 049 conformance (crates/scp-testing/.../outlet_streaming_saga_conformance.rs): 7 live tests, KAT does 9 single-field tamper rejects; lossy test drives real gap (0,1,3) through real ReceiverSequenceTracker firing SCP-OUTLET-6131 at idx 2; aggregate test uses real validate_value_against_schema (positive+negative) → 6140.
- 047 pipeline_wiring gates use extract_fn_body AST-body extraction asserting the ACTUAL producer calls (enforce_caller_principal_binding + start_cross_context_streaming_outlet_invocation_saga; drive_recover_truncated_close + identity_registry_contains + resolve_context_signing_key) — real wiring, not dead-ref theater.

**036 highlights:** AC7 verified-append boundary (append_outlet_invoked_verified call invoke.rs:4465, def builder.rs:296, reject test surfaces ChunksBilledMismatch); AC12 cross_context_economy_gate (invoke.rs:4291) rejects if `registered_paid || billed_paid` — closes split-source bypass, called before any receiver. AC10 MLS seal is SDK delivery seam (SCP-OUT-047) by design, real two-party MLS test.

**Non-blocking observations (NOT gaps):**
1. 044 AC3 prose cites state.rs/messaging.rs as SendSequenceTracker home; real home is actor/sequence.rs. Cosmetic.
2. 046 AC4 O(1)-memory test uses powers-of-two (64, 4096) → single-peak frontiers, not widest O(log n) case (2^k−1, ~12 peaks); absolute <512-byte bound still sound. Cosmetic test-thoroughness.
3. Build-gate ACs (036 AC13, 044 AC6, 045 AC5, 046 AC9, 047 AC11/12, 048 AC8, 049 AC9) not executable in read-only branch audit — CI must confirm.

**The one integration-layer completeness fact:** slice is complete per-story but NOT consolidated/merged to main; no single branch contains all 7.
