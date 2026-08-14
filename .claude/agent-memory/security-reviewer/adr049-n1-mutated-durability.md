# ADR-049 N1 -- Class-C mutated-flag durability fix (2026-07-09) -- CLEAN

3 handlers mutated Class-C via `class_c_view()` but returned `mutated:false`, so
coalesced best-effort persist never flushed -> writes lost on <=50ms crash. PR
flips them to `mutated:true` on write paths. Base 9f85f5346.

## Mechanism (verified)
- `Outcome.mutated` -> run loop sets `self.dirty` (mod.rs:353) -> `persist_snapshot`
  (mod.rs:550) -> `persist_state_best_effort` snapshots CURRENT PerContextState.
  It SNAPSHOTS STATE, not replays ops -- so ephemeral velocity rollback TOKEN
  (antispam.rs:570, token not persisted) is irrelevant to durability; post-rollback
  state is snapshotted directly. Class-S fail-closed persist is a SEPARATE site
  (`persist_state_fail_closed`), unchanged. mutated only drives best-effort.

## commit_a COMMIT-A-REPLAY (saga.rs:2014-2055) -- security-critical, SOUND
- `rollback_tool_economy_generation_checked` (tools_helpers.rs:1012) returns bool:
  MATCH -> `rollback_tool_economy` touches Class-C (velocity/budget/hard-rate) -> true
  -> ok_mutated. MISMATCH -> `void_external_and_consume` (external escrow only, NO
  Class-C) -> false -> ok (unmutated). Boolean PRECISELY tracks Class-C mutation.
- No double-refund: budget `reverse_spend` saturates at zero (budget.rs:150);
  velocity `rollback` is token-scoped single-entry removal; hard-rate refund gated
  by one-shot `needs_hard_rate_limit_refund` flag; ticket RAII-consumed. One ticket
  reverses at most its own reserve.
- No confused-deputy refund: generation MATCH guarantees the reserve was applied to
  THIS instance, so reversing against THIS instance's budget is correct. Mismatch
  (reserve applied to despawned instance) takes the external-void-only path.
- Replay accounting: fresh reserve (durable) + rollback (durable) = net zero. Old
  behavior (rollback non-durable) left net OVER-count on crash (safe-toward-limiting,
  but incorrect). Fix restores correctness. Branch is guarded-unreachable in today's
  FSM (committed Commit-A leaves prepared_a==None); correct-by-construction hardening.
- `clear_committed_reservation_idempotent` stays non-persisting fail-closed; coalesced
  persist now durably removes the straggler too -- harmless cleanup, idempotency
  witnessed by `xctx_committed_invocations` not the straggler.

## handle_seed_peer_pseudonym + handle_test_insert_member (messaging.rs)
- BOTH `#[cfg(feature="testing")]` gated (variants + handlers) -- NOT production
  reachable. No auth-laundering. Pseudonym = routing alias, not an authz grant.
- seed: reject arm (NotPseudonymousContext) never touches view -> err unmutated. OK.
- test_insert_member: `require_active` hoisted to pre-mutation gate (reject -> err
  unmutated); members insert lands before fallible system_assign_role -> err_mutated
  on partial. Correct partial-persist semantics.

## Verdict: APPROVE. No findings. Direction is security-correct.
