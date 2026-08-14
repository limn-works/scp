---
name: saga-1911-structural-code-tests
description: #1911 saga FSM structural SCP-SAGA code threading test review @35be7185f — keystone + per-site code asserts mutation-confirmed; one u16-overflow decoy weakness
metadata:
  type: project
---

# #1911 saga FSM structural code-threading tests (@35be7185f, SHIP)

Change: saga FSM carries `SCP-SAGA-*` codes STRUCTURALLY (`SagaReject.code: Option<u16>`, `SagaError::Aborted.code`); `saga_code_from_message` string-parse DELETED. `saga_reject!` macro (commands.rs:2736) derives BOTH `code: Some($lit)` AND `SCP-SAGA-{lit}:` message prefix from ONE literal → per-site code/message divergence impossible by construction.

**Why SHIP:** both keystone + per-site asserts mutation-confirmed load-bearing.
- Mutation: reintroduce `u16` message-parse in `lift_run_saga_error` (supervisor.rs:5661) → `lift_reads_saga_code_structurally_not_from_message` (16846) FAILS.
- Mutation: route a Prepare reject site through `From<ContextError>`→None keeping the `SCP-SAGA-130xx` message → per-site `assert_eq!(reject.code, Some(130xx))` FAILS (`left:None right:Some(13010)`). The message-substring assert alone would NOT catch this — the code assert is the load-bearing half (catches "reject site forgot its code → silent 13067 default"). All ~14 per-site asserts genuine.

**FINDING (non-blocking strengthen):** keystone's FIRST sub-case uses out-of-`u16`-range decoy token `SCP-SAGA-99999` with structural `Some(13013)`. `99999 > u16::MAX(65535)` so a reintroduced `parse::<u16>()` yields None → falls back to structural 13013 FOR THE WRONG REASON (parse failure, not "we don't parse"). My message-first parse mutation PASSED this assertion; only the SECOND sub-case (None structural + valid-u16 `SCP-SAGA-13050` → 13050≠13067) caught it. Headline comment "never the message's token (99999)" oversells. FIX: change first case's message token to a valid-but-different u16 (e.g. 13050) so message-first parse yields 13050≠13013 and the assert genuinely pins structural-over-message precedence when a structural code IS present.

**Codeless→13067 paths all pinned:** token-bucket ECON RateLimited None-backoff (`..._propagates_token_bucket_none_backoff`, asserts None not coerced to Some(0)); Prepare TransportTimeout None→13067 not 13050 (`..._maps_every_terminal` 4th case); journal-IO mark_resolved None→NeedsRepair both directions (`..._mark_resolved_failure_is_needs_repair_not_aborted`, double-charge regression).

**Behavior vs impl:** `lift_run_saga_error` is private; direct-test justified+documented (public boundary needs prohibitive 2-actor dual-commit+journal-fault pipeline). Per-site Prepare tests drive REAL `prepare_a`/`prepare_b` handlers via actor oneshots — genuine engine behavior. Flakiness Low (pure sync, fixed saga-id literals, deterministic budgets).

Build: `cargo nextest run -p scp-runtime --features scp-runtime/testing -E 'test(/.../)' ` ~46s compile, no deadlock vs main WIP. nextest positional args are substrings; use `-E 'test(/regex/)'` for regex.
