---
name: pr2234-rotate-content-keys-kea
description: Red-team pass 1 on PR #2234 (fail-closed KeyEpochAdvance leaves, broadcast sort determinism, seed_broadcast_author test seam) at commit 432691d70
metadata:
  type: project
---

# PR #2234 `fix/rotate-content-keys-review-followup` @ 432691d70 — Red Hat pass 1

## RED-2234-1 (MEDIUM) — fail-closed KEA breaks governance-vote idempotency
`execute_revoke` / `execute_rotate_content_keys` (`crates/scp-runtime/src/context/governance_helpers.rs`)
converted the trailing per-author `KeyEpochAdvance` appends from best-effort to
`.map_err(EventLogFailed)?`. Those appends sit AFTER all authority-relevant state is
already Class-S-persisted.

Chain: KEA append fails on author k → `Err` → `execute_governance_action(...).await?`
in `vote_on_proposal_inner` (governance_helpers.rs ~4436) returns early → the trailing
`persist_state_best_effort` is SKIPPED. The approval vote was recorded through
`cell.class_c_view()` (NON-persisting), so the vote + proposal status are lost on restart
while the ban/key-rotation IS durable. Re-approval re-executes: `governance_ban_subscriber` /
`rotate_all_author_keys` rotate epochs AGAIN and append a second AccessRevoked/ContentKeysRotated
leaf. Authors that succeeded get KEA(0→1),KEA(1→2); authors that failed get only KEA(1→2) —
a permanent hole in the epoch chain. Fail-closed WITHOUT idempotency is worse for convergence
than the best-effort it replaced. N authors = N new failure points per governance vote.

## RED-2234-2 (MEDIUM) — authority-escalation seam on the broad `testing` feature
`BroadcastContext::can_write(did) == authors.contains_key(did)` (broadcast/mod.rs ~2138 region),
so `add_author` IS the `messages:write` grant. New `SeedBroadcastAuthor` command /
`Supervisor::seed_broadcast_author` / `ClassCMut::seed_broadcast_author` are all
`#[cfg(feature = "testing")]`. `scp-ffi/Cargo.toml:42`, `napi:30`, `uniffi:34` all enable
`scp-core/testing → scp-runtime/testing`, so it compiles into every bridge test build.
`crates/scp-runtime/Cargo.toml` explicitly carves `test_grant_member_capability` OUT of
`testing` into `outlet-capability-test-grant` for exactly this reason ("AUTHORITY-ESCALATION
primitive... would leak into every bridge test build"). Same for `saga-witness-test-mint`.
Doc claims it "Mirrors `Self::seed_peer_pseudonym` in purpose and gating" — seed_peer_pseudonym
seeds a ROUTING pseudonym, grants no authority. Mirror claim false on security class.
Only consumers are `crates/scp-runtime/tests/governance_integration.rs` → a dedicated
feature named in that test target's `required-features` is the established fix shape.

## RED-2234-3 (MEDIUM) — phantom provenance for the fail-closed rule
Code + spec repeatedly say "ADR-011: convergent governance trigger → convergent leaf →
fail-closed". `.docs/adrs/phase-2.md` (ADR-011) convergence doctrine governs which events are
MINTED into the canonical log (convergent → durable leaf; velocity/rate → buffer-only). It says
nothing about ERROR PROPAGATION on append failure. `grep fail-closed .docs/adrs/phase-2.md`
returns only UCAN-gate and StorageConfig hits. The `.docs/specs/05-contexts.md` §2033/§5.14.8
"fail-closed per ADR-011" text was ADDED BY THIS PR, then cited by the code — artifact-flow
inversion (code informing spec).
Also: the PR leaves `block_broadcast_subscriber`'s KEA best-effort because a unilateral block is
"single-origin, not MLS-commit-ordered". But the BROADCAST `RotateContentKeys` path is also not
MLS-commit-ordered (it takes the `broadcast_context.is_some()` branch, `(None, advances)`, no
commit bytes). The stated distinguisher does not distinguish.

## RED-2234-4 (LOW) — `checkpoint_events_since` never enters the signed checkpoint
`build_checkpoint` (`queries_helpers.rs:734`) reads `merkle_root` and `event_count` FROM THE
EVENT LOG, not from the counter. The counter only gates the 50-event / 600-second trigger in
`create_checkpoint_if_due_view`. So counter drift = a checkpoint fires early/late; it is NOT a
Merkle/§9.9.3 divergence. The pervasive "§9.9.3 checkpoint-position drift / Merkle determinism"
comments overstate it — and that overstatement is what motivated the RED-2234-1 trade.

## RED-2234-5 (LOW) — zero negative-path coverage
All new tests in `governance_integration.rs` use an in-memory event log that never fails (one
test comment says so outright). No failing-event-log harness exists anywhere in `crates/`. The
entire best-effort→fail-closed change and the "mid-loop failure leaves the counter exactly
reflecting durable leaves" claim are untested.

## What holds up (verified, do not re-flag)
- **No rate-limiter in `bounded_reply_await`** (`actor/handle.rs:117`). It is stateless mechanics:
  `timeout(REPLY_TIMEOUT=2min, rx)` → `Ok / Dropped / Elapsed`. The fail-closed hard-rate-limit is
  a SEPARATE outlets token bucket (`try_consume_hard_rate_limit`, supervisor.rs:11663) that merely
  CONSUMES a `bounded_reply_await` result. No shared/global limiter ⇒ no cross-operation DoS.
- `seed_broadcast_author`'s conversion is verbatim-equivalent to `seed_peer_pseudonym`; error
  string matches the ~41-call-site convention `"Supervisor::<m> — actor reply channel closed"` +
  `TransportFailed`. Not remotely drivable (testing-gated, no FFI export).
- In `execute_revoke`, `needs_sender_key_rotation` (requires `broadcast_context.is_none()`) and
  non-empty `rotated_authors` (requires `is_some()`) are MUTUALLY EXCLUSIVE — the KEA early
  return can never skip the H7 sender-key rotation.
- Sort fix is COMPLETE: all three Vec producers sorted; `author_dids()` / `subscribers()`
  iterators have test-only consumers; `author_did` is the HashMap key so no duplicate-key ties.
- Genuine bug fix: `block_broadcast_subscriber` went 1 bump → 2 (it previously under-counted
  whenever the KEA leaf succeeded). No double-count introduced in `unsubscribe_broadcast`
  (line 254 = MemberLeft, 294 = per-KEA).
