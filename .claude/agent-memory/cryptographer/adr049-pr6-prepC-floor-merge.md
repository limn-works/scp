---
name: adr049-pr6-prepC-floor-merge
description: Crypto review of §23.17.2 validating floor merge (validate_and_merge_epoch/recv_sequence_floors) on Supervisor Class-M registry — SOUND
metadata:
  type: project
---

# ADR-049 PR-6 Prep C — Class-M floor validating merge (SOUND)

`crates/scp-runtime/src/context/supervisor/floors.rs` (commit 6df8ec56f, branch feat/adr049-pr6-prepC-registry-authoritative-merge).

Reviewed the §23.17.2 fail-closed VALIDATING MERGE bodies. Verdict: **cryptographically SOUND**, no CONFIRMED replay/rollback holes. Prep-C is zero-prod-behavior (only caller = non-fatal log-and-drop follower seed at lifecycle_helpers.rs:1825 epoch + 1848 recv).

**Why sound (core argument):**
- Apply pass is PURE MONOTONE MAX under BOTH policies (shared apply: `and_modify(|c| *c=(*c).max(inc)).or_insert(inc)`). Floors NEVER decrease → no replay window. This is the load-bearing property and it's structural.
- Reject condition is `incoming < local` (strict). Equal accepted → max no-op (holds floor). Matches spec Inv-3 (`>=` → max, `<` → reject-whole) exactly. MERGE semantics = `>=`; the LIVE message gate `check_and_advance_*` is a SEPARATE fn using reject-on-`<=` = strict `>`. No confusion between the two.
- MaxMergeTrustedLocal (Inv-2) tolerates but CANNOT lower — shared max apply keeps live floor. Confirmed Q5.
- Atomicity (Q2): validate-all-then-apply under ONE DashMap `entry()` guard; first-failure early-return BEFORE any mutation; no `.await` (sync fn) and no unwind-panic point between passes (HashMap alloc-fail aborts, not unwinds). Registry guaranteed untouched on reject.
- Overshoot (Q3): `saturating_add(MAX_EPOCH_ADVANCE=1000)` no wrap. Epoch axis bounded BOTH policies. Sequence axis DELIBERATELY unbounded.
- ReceiveFloor derived Ord is epoch-major (epoch field declared before sequence in scp-protocol/src/context/builder.rs:33) — lexicographic correct.

**Residual notes (all LOW / fail-safe, not blocking):**
- N1 (LOW, DoS not replay): recv sequence axis unbounded → an untrusted RejectRegression import of `(current_epoch, u64::MAX)` is accepted (>= local, epoch within ceiling) and silences the sender for that epoch until next sender-key rotation (self-heals: (e+1,0) > (e,MAX)). Fail-SAFE (over-reject), never accepts a replay. Doc frames as "signed exporter"; note it's also untrusted-peer-triggerable. Severity LOW confirmed.
- N2 (carry-forward): F-2 ordering (epoch merge BEFORE recv merge, so recv overshoot reads populated sender_epochs[did]) and F-3 co-mingling (local_did never a remote sender key) are DOCUMENTED preconditions, not type-enforced. Sole caller honors F-2. If violated → fail-SAFE over-restriction (recv reads epoch_floor as 0 → ceiling 1000 → over-reject), never fail-open. Recv merge only READS sender_epochs / only WRITES recv_sequence, so local scalar can't be corrupted. When gate becomes authoritative (later atomic-core slice), split the two counters or add debug_assert.
- N3 (nit): epoch merge is parameterized `max_advance`; recv merge hardcodes `MAX_EPOCH_ADVANCE`. Both = 1000 via caller; harmless asymmetry.
- Duplicate senders in incoming Vec: each validated vs pre-merge LOCAL (not vs each other) = spec-correct; pure-max apply keeps sound; lower duplicate under RejectRegression still triggers whole-merge reject (fail-closed).
