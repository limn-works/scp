# outlet-streaming chunk-3 Fix-A/B/C/D re-review (c166ba953..941c81d97)

**VERDICT: prior 2 bugs FIXED; no new correctness defect. 2114 lib tests pass, scp-runtime checks clean.**

## Prior bugs resolved
- **#1 base_sequence leak on pump-reject-after-reserve → Fix-A DELETED base_sequence.** Reserve no longer allocates a per-sender seq; membership gate is now `contains()` only; all `rollback_sequence_number` sites removed; tests assert seq counter stays 0. (Seq now "allocate-at-consumption" on the transport/FFI send path — a FUTURE chunk; not wired yet, out of this delta's scope.)
- **#2 gen-mismatch strands durable escrow+counter on crash-restore → Fix-D.** `StreamReservationRecord` (Class-S, keyed by hex request_id) persisted at pump-open AFTER both durable reserves (dispatch.rs:2363), cleared on clean settle (outlets_helpers.rs:1535), reconciled by `ReconcileStreamReservations` sweep from restore_context (lifecycle_helpers.rs:3158).

## Why no double-refund (highest-value target)
- **Sweep vs surviving-pump-settle land on the SAME serial actor mailbox** (old mailbox dropped on crash; pump dispatches to new context_id mailbox). Both orderings safe:
  - Settle at gen G vs live G+1 → **mismatch → `CapturedWithoutMutation`**: captures §19.15.5 receipt for rendered bill against OPEN-TIME policy snapshot, touches NO owned state, does NOT clear record.
  - Reconcile drains record: refunds FULL escrow + releases FULL cumulative + clears, all in one `commit_class_s_keep`. Idempotent (saturating reverse_spend/release; cleared in same commit; KEEP-retry re-runs from restored record).
- **Clean-settle and reconcile are MUTUALLY EXCLUSIVE per record**: clean-settle requires `settlement.generation == cell.generation`; a respawn bumps generation monotonically, and only a respawn triggers restore→reconcile. No respawn ⇒ no reconcile. Generation never returns to G.
- **No double-reverse via escrow-ticket Drop + reconcile**: the Fix-D persist sits at dispatch.rs:2363, and there is NO fallible early-return between it and the `Ok(handle)` return (only infallible mpsc/oneshot channels + `spawn_pump_task`). So a persisted record ⇒ open ALWAYS returns Ok ⇒ `escrow_ticket.consume()` (supervisor.rs:11242, never Drop-reverses). Ticket-Drop and reconcile can never both fire.

## Persist/clear symmetry (no leak)
- Persist-at-open condition `params.reserved_escrow>0 || counter_commit.amount_cumulative_reserved>0` == clean-settle clear condition `settlement.reserved>0 || settlement.amount_cumulative_reserved>0`. `settlement.reserved = summary.billed+refund = reserved_escrow` (escrow-ledger conservation identity; anchor helper also preserves `billed+refund==reserved`). Symmetric ⇒ never persisted-but-not-cleared.

## Fix-C OriginAdmissionTracker
- Operator-scoped single instance on Supervisor (NOT per-context) — correct per §05-contexts.md:448 (prevents fan-out DoS across N contexts). Lock order per-context `admission` → operator `origin_admission` (leaf, always innermost) consistent across run_admission_gate/release_admission/pump-close. No lost update (origin RwLock write guard exclusive). Decrement wired at ALL 6 open-failure `release_admission` sites + pump terminal `release_stream_admission`. Survives actor crash (Supervisor persists; pump's captured Arc still valid). No stale callers of removed `StreamAdmissionTracker::count_per_origin_invoker`.

## Fix-B anchor_settlement_receipt_to_manifest
- `billed=min(cost×manifest_ref [overflow→0], reserved)`, `refund=reserved.saturating_sub(billed)`. Conservation `billed+refund==reserved` in every case; overflow fails closed; honest path byte-identical to ledger split. Receipt now anchored to operator-signed manifest count, not pump self-count.

## Residual windows (both LOW, documented, adverse-to-invoker but vanishingly rare)
- **W1: crash in the ~1-roundtrip between Step-5.5 counter-commit/escrow-debit (durable) and record-persist landing** ⇒ reserves durable, record not ⇒ reconcile finds nothing ⇒ reserves STRANDED (invoker loses budget+cap capacity). Best-effort persist widens slightly but KEEP-retry re-persists in-memory record, collapsing loss to "crash before retry" ≈ W1. Fail-direction adverse to invoker, but vs pre-Fix-D (ALL crashes stranded) it's a huge net improvement.
- **INFORMATIONAL (not a bug): budget-tracker under-counts on crash path.** Reconcile refunds FULL escrow while the mismatch-settle receipt still bills `billed` ⇒ member's internal budget-cap shows 0 spend but they actually paid `billed`. Deliberate conservative choice ("invoker never over-charged"); not member-exploitable (member can't trigger crashes; still pays via receipt).
