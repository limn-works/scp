---
name: review-xctx-wave23-preparing-a-recovery
description: §6.2.4 wave-23 (b757e0cf1) — PreparingA crash-recovery over-charge fix + gate receiver-alias hardening + divergence-marker spec pin; CLEAN
metadata:
  type: project
---

# §6.2.4 saga wave-23 review (commit b757e0cf1, worktree xctx-saga)

CLEAN — no weakening, no exploitable path. Two questions both answered.

**Why:** review of a CRITICAL economic-integrity fix + a Class-S fail-closed gate hardening.
**How to apply:** baseline for future PreparingA/PreparingB recovery and check-class-s-fail-closed.sh reviews.

## Finding 1 (CRITICAL, fixed) — PreparingA recovery over-charge
- Pre-fix `recover_saga_entry` arm `Initiated | PreparingA => unconditional terminal-Aborted`. FALSE for PreparingA: FSM journals PreparingA (seq 1) BEFORE dispatch_prepare_phase(A) (supervisor.rs:6146-6158), and Prepare-A durably persists caller deduction + CallerReservationRecord. terminal-Aborted asserts "fully compensated" → §17.16.4 sweep (re-drives only NON-terminal) could never reverse → permanent silent over-charge + leaked record.
- Fix: split. `Initiated` stays unconditional-Aborted (deduction never ran — sound). `PreparingA` routes to `recover_preparing_b_entry`. Empty evidence ⇒ reconstruct_xctx_prepared returns None (supervisor.rs:5790) ⇒ xctx_caller_hex_from_participants Some on len-3 64-hex triple (5825) ⇒ redrive_caller_local_reversal. Terminal only on confirmed SettledOrAbsent OR persistence-deleted caller; else non-terminal for re-drive.
- Idempotency: actor abort handler (saga.rs:1850-1859) `None` arm reverses only if `xctx_caller_reservations.remove(saga_id)` is Some, consuming atomically; second drive → None → no-op. persist_state_fail_closed BEFORE Ok() ack (saga.rs:1886-1892); send-fail ⇒ ReversalOutstanding ⇒ non-terminal. reverse_caller_reservation_record (tools_helpers.rs:360-402) reverses exactly Prepare-A's 3 deductions + escrow void keyed by durable record — refund==charge, escrow void idempotent.
- Non-vacuity VERIFIED empirically: reverting just the arm → resident test fails (token stranded 9000, not refunded 10000). Both new tests pass; actor_saga_crash_recovery 3/3, cross_context_saga 4/4.

## Finding 2 (gate, additive) — check-class-s-fail-closed.sh receiver-alias hardening
- Added `.ceiling=` (receiver-agnostic, write-only; reads normalize to `.ceiling(`) + six `&mut.<field>` companions (membership/executed_proposals/threshold_signers/saga_pending/xctx_nonce_dedup/xctx_caller_reservations) via new normalize_borrow (collapses `&mut <recv>.<field>`, exclusive only; shared `&` reads untouched). FNQUAL regex hoisted to BEGIN var (byte-identical, Finding 4).
- VERIFIED: all 4 allowlists byte-identical (MD5) old↔new — no exemption added. Raw tag streams IDENTICAL old↔new on real tree (FC=28/FNDEF=1152/GOVFN=30/SCANNED=61, HIT/GOVHIT/NTTEST=0). --self-test 0, real scan 0. shellcheck only SC2016 (54→60, all new printf fixture lines). Read-accessor control fixtures (64,65) prove no false-positive.
- Deliberately NOT a receiver-agnostic `.remove_member(` — would collide with MLS `crypto.remove_member(`; `&mut.membership` borrow form avoids it.

## Finding 3 (spec, positive) — divergence-marker preimage pin
- .docs/specs/06:311+ pins CrossContextDivergenceMarker preimage; matches code byte-for-byte (scp-protocol/.../cross_context_saga.rs:40,375-383,88-89): domain SCP-XCTX-DIVERGENCE-V1: (distinct from receipt sep → no cross-replay), VarBytes(saga_id)‖RawBytes16(nonce)‖U8(tag)‖VarBytes(committed_event_id), Caller=0/Target=1. Closes cross-impl drift risk.

## Method notes
- `git -C $W show '<sha>:path'` mangled in zsh by the colon; extract to /tmp file instead.
- Instrument gate by `awk`-injecting `cp "$tmp_out" /tmp/...` after the `> "$tmp_out"` second-pass scan line; run both versions, diff tag streams.
- Non-vacuity: python-revert the single arm, re-run the resident test, restore via cp backup, confirm `git diff --stat` empty.
