---
name: 1845-cross-member-replication-plan
description: #1845 cross-member event-log leaf replication PLAN review (branch feat/1845, HEAD fb6530cfb) — CommitMetadata sidecar; BLOCKER = no spawn-from-Welcome (receivers have no actor/event-log).
metadata:
  type: project
---

Review of the #1845 PLAN (no code yet beyond phase-2 substrate). Builds on [[eventlog-unification-phase2-final]] deferral #2 (the `#[ignore]`'d `two_real_members_converge_pending_cross_member_replication`).

**Plan:** signed `MessageType::CommitMetadata` inner-envelope sidecar mirroring `ConsistencyCheckpoint` (messaging_helpers.rs:1179 dispatch / :1255 deliver_checkpoint_message). Keyless actor (ADR-049) RECORDS pending metadata at append sites; key-holding path drains+signs+broadcasts. Drive-trigger Option 1 = hook drain into finalize_send / create_and_broadcast_checkpoint_if_due (messaging_helpers.rs:1841/1865, both carry the send signing key). Receiver dispatches deliver_commit_metadata_message → binds actor to MLS sender, skip-own-echo, skew-validate, dedup by (sender,epoch,event_type), re-append via the dormant run_buffered_post_delivery `Some(event_name)` branch (messaging_helpers.rs:662, currently dead — all callers pass None).

**VERIFIED claims (all TRUE):**
- ConsistencyCheckpoint mirror exists exactly as described. Send precedent send_checkpoint (messaging_helpers.rs:1402). NOTE: encrypted-context fan-out uses routing.peer_registry() — EMPTY peer set = silent no-op (relevant to drive-trigger convergence).
- finalize_send/create_and_broadcast_checkpoint_if_due carry `signing_key: Option<&SigningKey>`; `let Some(sk) else return` skips when no local custody — same gate applies to metadata drain. Hook is mechanically feasible.
- Dormant receive-append branch (run_buffered_post_delivery, event_name:Option + event_timestamp_secs) exists, fully documented as the cross-member forward seam. Architecture pre-anticipates this work. Clean.
- finalize_close (ttl.rs:642) takes timestamp_secs with doc-stated DUAL convention (TTL deadline OR committer close-commit time). Two distinct callers: governance execute_close_context (governance_helpers.rs:1453) vs timer handle_ttl_expiry (ttl.rs:704). Classification point is the caller — architecturally available.

**BLOCKER (Q1) — confirmed in code, highest impact:**
Welcome-joined member spawns NO per-context actor and builds NO MerkleEventLogProvider. key_package_actor.rs:1194-1197 confirm join_from_welcome "is dropped after proving the join succeeded" — no production consumer wired. Native join_context (lifecycle_helpers.rs:656) is the INVITER/admin side (runs add_member adding ANOTHER member); the Welcome-RECIPIENT path is crypto-only. FullStackNode::join_from_welcome (scp-testing node.rs:417) touches only self.crypto, never self.manager/self.event_log — joiner's Supervisor has no actor for the context. ⇒ receivers have nothing to append to. Cross-member replication is MOOT until spawn-from-Welcome exists. This is a PREREQUISITE, must be in #1845 scope or a hard-blocking dependency issue. The plan as summarized does NOT include spawn-from-Welcome.

**Q2 — Option 1 send-path drain backstop is NOT real:** compare_remote_checkpoint Behind arm (queries_helpers.rs:843) only RETURNS a count delta; doc says "Do NOT implement that fetch here" — the event-range fetch + consistency-proof catch-up is specified-separately + UNIMPLEMENTED. So a committer who commits a governance action then never sends again leaves the leaf un-replicated with NO working backstop. Correctness gap, not just latency.

**Q3 — WASM (Fork A):** WASM join_context_encrypted (manager.rs:1857) DOES append MemberJoined (unlike native keyless actor). BUT WASM has ZERO MessageType dispatch (grep: no MessageType/ConsistencyCheckpoint/CommitMetadata in wasm), only ad-hoc decrypt_message (manager.rs:1778) — no receive-side commit handling. Even existing equivocation checkpoint exchange is native-only; WASM never participates. #1845 native-only ⇒ native↔WASM stays divergent. Pre-existing gap (deferral #1, #1846) but plan should state WASM scope explicitly.

**Q5 — ordering:** receiver re-append order = arrival order of CommitMetadata envelopes, NOT commit order. Single-committer OK; multi-committer interleaving via the relay can deliver in an order != MLS-commit order, producing a different leaf SEQUENCE → different Merkle root → false-positive equivocation, the exact §9.9.3 failure. FIFO-per-sender does not give a cross-sender total order. The convergent order is the MLS-commit order; the plan needs a deterministic sequencing key (e.g. epoch + committer-assigned sequence) not arrival order. ADR-051 causal-DAG is the real answer for app events.

**Spec basis is solid:** §9.9.3 "Convergent-log requirement" para (specs/09-security-model.md:~830) explicitly requires honest members build the SAME log; this work directly serves it. Part 0 spec amendment appropriate.
