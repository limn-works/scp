# Event-Log Substrate Swap (Phase 2) — Adversarial Review (HEAD bf9266777)

Runtime event log moved onto canonical `scp_event_log` RFC-6962 tree. Checkpoint/proofs/export
on `tree::root`; `state.merkle_tree` twin deleted; `MessageReceived`/`EquivocationDetected`/
`PseudonymAnnounced` durable appends removed; equivocation dedup now in-memory per-sender
`(count, root)` HashSet.

## WHAT RESISTS ATTACK (verified, do not re-flag as broken)
- Signed export forgery CLOSED. `validate_export_for_import` (export_import.rs:565) binds
  `verify_merkle_chain` replay root via `ct_eq` to the SIGNED `snapshot.event_log_merkle_root`
  (inside `verify_strict` preimage). Front-trunc fails (non-genesis prev_hash@seq0); suffix/
  middle/reorder change tree::root → ct_eq fail. exporter_did==creator_did bound first.
- RFC6962 count-ambiguity (2-leaf root == 3-leaf root via odd-promotion) is REAL math
  (PoC confirmed) but NOT exploitable: equivocation + export both gate on event_count FIRST
  (signed), and 0x00/0x01 leaf/interior domain separation blocks leaf==interior injection.
- Inclusion/consistency proofs are standard self-attesting; safe because callers compare
  against signed checkpoint root. No forgery of a non-included leaf.

## REAL FINDINGS
### HIGH — equivocation detector unsound under DORMANT cross-member replication
- compare_remote_checkpoint (queries_helpers.rs:775) compares local committer-only log vs
  remote checkpoint at equal count → Divergent → false EquivocationDetected.
- Membership/governance leaves are COMMITTER-APPENDED-ONLY with committer LOCAL clock
  (lifecycle_helpers.rs:865 now_secs; comment admits "receive-side append path is dormant,
  NOT replicated to other members"). MLS commits return early (messaging_helpers.rs:1128),
  no remote re-append. So two honest members NEVER share a leaf set → divergent roots at
  equal count = false positive. PoC: 2 committer-only logs @count=2 → compare_checkpoint=Divergent.
- Convergence tests (eventlog_convergence.rs, wasm_conformance.rs:2163) only assert the
  THEORY: both providers hand-fed identical synthetic committer-assigned timestamps. NO test
  drives two real ContextManager members through commit exchange and asserts equal root.
- ADR-051 acknowledges convergence requires the commit-ordered stream be "appended identically
  by every honest member" — but that replication is the explicit forward program, not built.

### MEDIUM — equivocation replay defense weakened to in-memory-only + accountability loss
- Removing durable EquivocationDetected append removed the local_count-advance backstop.
  Per-sender (count,root) HashSet (actor/state.rs:999) is now SOLE replay dedup.
- Set reset to empty on every init/restore/import (lifecycle_helpers.rs:1283/1851/2291), NOT
  persisted. Actor respawn/restore wipes it → same signed divergent checkpoint re-emits alert.
- EquivocationDetected no longer a durable Merkle leaf → no permanent accountability record of
  detected relay equivocation (ADR notes it as honest trade, but it IS a regression on the
  durable-accountability axis).

### LOW — verify_event_consistency exposed without root-binding caller
- queries_helpers.rs:998 wraps proof::verify_consistency (self-attesting: checks leaf_hashes
  reconstruct proof.old/new_root). No caller binds new_root to a trusted signed root. Catch-up
  Behind-arm seam explicitly unwired. Sharp edge for #1535 implementer.
