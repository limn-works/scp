---
name: wasm-slice1-roles-final-shipcheck
description: Final ship-readiness audit of WASM slice1-roles ContextRoleState test suite (HEAD f592238ba) — membership-mutation matrix COMPLETE, suite solid
metadata:
  type: project
---

# WASM slice1-roles final ship-check (HEAD f592238ba)

Audited manager.rs (12702 lines authoritative via `git show`) + consequence.rs. Conclusion: suite is SOLID and ship-ready. No high-value gaps; no over-testing flagged.

**Why:** final test-quality gate before landing the WASM slice that adopts shared `ContextRoleState` and converges to native.

**How to apply:** membership-mutation matrix is COMPLETE. Every op has success + failure/rollback through the PRODUCTION dispatch path (`propose_governance_action`→`execute_governance_action`→`dispatch_*`, or the real public methods `join_context`/`join_context_encrypted`/`leave_context`/`subscribe_broadcast`). No test fakes membership mutation via `test_insert_member` for the path under test (that helper is only used for SETUP/preconditions).

Matrix (manager.rs):
- AddMember: undefined-role reject + seq-rollback proof (10746); existing-member-bad-role NO-EVICT (10817); defined-role success + MemberJoined (10905)
- RemoveMember: execute-path empty-leaf + executor-stamp + convergent-ts + exactly-one (11639); no-mls-leaf (11767); mls-eviction-fail keeps gov state (11858); nonmember reject no-leaf (12668, calls dispatch_remove_member directly — minor)
- ChangeRole: undefined reject + role-intact (10532); defined success + cap check (10588)
- TransferAdmin: success demote/promote + creator_did immutable (10634); nonmember reject + no creator_did relocate (10695)
- join: success adds member + leaf + buffer (12588); paid-context reject (10019)
- join_encrypted: welcome-failure ROLLBACK (members/count/dids/role/seq/leaf/buffer all checked — model rollback test, 11942); success exactly-one-leaf (12057)
- leave: strip-all-state + MemberLeft (12375); last-member auto-close (12495); nonmember reject (12537)
- subscribe_broadcast: success + subscriber-role + seq-seed + idempotent (8562); non-broadcast reject CTX_2001 + no-mutation (8630)

Other behaviors covered:
- send/publish gate: read-only reject (10220), write success+seq-advance (10262), suspended reject distinct msg (10296), publish all-three (10332)
- #1886 undefined-role: AddMember/ChangeRole (manager) + consequence-path escalate-to-SuspendAll (consequence.rs:584, role-unchanged + full-suspend + exactly-one ConsequenceEscalatedToSuspendAll leaf)
- ModifyCeiling no-un-suspend: suspend→widen, member stays suspended (9880)
- export/import verbatim: whole ContextRoleState eq (11225); no-un-suspend across widen via signed export/import (11066, BLACK-CEIL-01); tokens verbatim (11158)
- deserialize/version-gate: newer+older→CTX_2094 distinct from sig CTX_2093 (8346/8370)
- ceiling malformed-reject: create (9442), modify parameterized 3 shapes fail-closed VALID_7000 (9773), import CTX_2032 (9592)

Flakiness: LOW. Identity-registry is thread_local RefCell; all 4 export/import tests do cleanup→register→...→cleanup. `register_identity_with_agent_key` uses OsRng (non-deterministic DID) but tests treat returned DID opaquely — NOT a flakiness source. Nonce tests use deterministic fixtures, no rand. Native test runner cannot call wasm time stub — gate-helper tests avoid create_context path deliberately (documented at 9970).

Behavior-vs-impl coupling: LOW. Tests assert observable state (member_role, is_member, member_has_capability, member_count, event_log_leaf_count, drain_events) + error codes, not internals. Minor impl-coupling: a few tests (`remove_member_nonmember`, `subscribe`/`leave`/`send` gate tests) call dispatch_*/public methods with `test_insert_member`-seeded preconditions rather than full propose chain — acceptable, the path under test is still production.
