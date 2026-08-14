---
name: project-1845-commitmetadata-keyless-actor-blocker
description: #1845 cross-member leaf replication — prompt's inline-broadcast-at-append-site design is infeasible; convergent append sites run in the keyless ADR-049 actor, only the send path holds a signing key
metadata:
  type: project
---

#1845 cross-member leaf replication (branch feat/1845-cross-member-replication, off Phase-2 HEAD fb6530cfb). The task: receivers must re-append committer-assigned convergent Merkle leaves so honest members converge (else §9.9.3 equal-count⇒equal-root false-positive equivocation). Builds on [[project-eventlog-committer-assigned-timestamp]] (committer-assigned leaf timestamps, already landed).

**STOPPED before writing code — genuine architectural judgment call escalated.**

**The blocker (verified against code):** The proposed Part-2 design = "introduce `append_and_replicate_convergent_leaf` that appends locally AND broadcasts a signed `CommitMetadata` inner envelope inline at each convergent append site, reusing the checkpoint send path." This is INFEASIBLE because broadcasting a signed envelope requires an `ed25519_dalek::SigningKey`, and per ADR-049 the actor holds NO signing key ([[lesson_actor_boundary_no_key_no_retrieval]] / user-memory). The signing key only enters the actor on the SEND path, via three mailbox commands that carry `SigningKeyBytes` supplied per-call by the SDK/FFI boundary: `SendMessage`, `SendCheckpoint`/`BuildLocalCheckpoint`, `SendHeartbeat` (commands.rs ~388/396/451/493). That is exactly why `send_checkpoint` takes `signing_key: &SigningKey` and is broadcast only from `finalize_send` → `create_and_broadcast_checkpoint_if_due` (messaging_helpers.rs:1865), which receives `signing_key: Option<&SigningKey>` threaded from the caller.

**The ~50 convergent append sites do NOT have a signing key in scope** (enclosing fns verified):
- Governance execution (~30 sites): `dispatch_governance_action`(3951)/`execute_governance_action`(4447) — NO signing_key param; reached from the keyless timer handler `handle_evaluate_timeouts_actor` AND the vote-approval path. MemberJoined/Left/RoleAssigned/CeilingModified/EconomicPolicyApplied/etc. all append here.
- Membership: `join_context`(656) MemberJoined, `leave_context`(236) MemberLeft — keyless.
- broadcast_helpers: subscribe/unsubscribe/block/unblock (58/130/498/559) — keyless.
- ttl: close_context/finalize_close/try_ttl_expiry_cleanup (576/642/773) — keyless AND timer-driven (prompt itself says timer leaves get NO sidecar: each member's timer fires the convergent-deadline leaf independently).
- trust_recovery `recovery_advance_epoch`(207) — DOES mention signing_key (5 hits) — needs per-site check; may be the lone key-bearing exception.

So inline broadcast can only work for send-path leaves — which already replicate via the application stream + the dormant `Some(event_name)` receive branch (messaging_helpers.rs:663, run_buffered_post_delivery copies `msg.inner.timestamp`). The leaves that ACTUALLY cause divergence (governance/membership/lifecycle, committer-appended-only) are precisely the keyless ones.

**Correct architecture (recommendation, NOT yet ratified):** CommitMetadata replication must follow the SAME boundary pattern as heartbeat (#1533) and checkpoint: the actor cannot self-broadcast. Two viable shapes —
  (A) Actor records "pending replication metadata" into state during the keyless append; the SDK/bridge driver (which holds the key) later drains + signs + broadcasts a `CommitMetadata` envelope per pending entry — mirrors the heartbeat scheduler / reconnect driver seam ([[lesson_actor_boundary_no_key_no_retrieval]]). Needs a new mailbox command `DrainAndBroadcastCommitMetadata { sender_did, signing_key }` + bridge scheduler wiring + FFI/SDK across 4 bridges + pipeline_wiring assertion + capability matrix (full Integration checklist).
  (B) Piggyback: every committer already follows a governance/membership mutation with an MLS Commit broadcast via `try_broadcast_commit_or_enqueue` — but that path is ALSO keyless (4528, no signing_key). So (B) collapses into (A).

This is bigger than the prompt's framing (which assumed a key was at hand) and crosses the actor/FFI boundary across all 4 bridges. It is the #1533/#1540 class of "sign-on-schedule lives at the boundary" work.

**Parts that ARE feasible as-specced and could proceed independently:**
- Part 1 (CommitMetadata message type in scp-protocol) — pure type, no key needed.
- Part 3 (receiver dispatch `deliver_commit_metadata_message`) — pure receive-side, no key.
- Part 5 (move CommitBroadcasted/CommitBroadcastPending/Succeeded/Failed off the durable log to buffer-only) — INDEPENDENT of the key problem and a clean latent-divergence fix. Three durable append sites: governance_helpers.rs:4547 (CommitBroadcasted) + :4604 (CommitBroadcastPending) + actor/handlers/governance.rs:1064 (Succeeded/Pending/Failed loop). Buffer-only ContextEvents already emitted at each; just delete the durable append + `checkpoint_events_since` bump.
- Part 4's two-member test needs the FULL replication path (A) to pass non-ignored, so it can't land until the broadcast seam exists.

**Test harness facts (for whoever resumes):** `crates/scp-testing/tests/integration/reconnect_sync.rs` is the gold two-member full-stack harness (real MLS/eventlog/Supervisor + relay, `FullStackNetwork::create_node`, `add_member`/`join_from_welcome`, checkpoint exchange via `build_local_checkpoint`). `FullStackNode` uses `scp_core::context::test_supervisor` (no clock param) + a `CapturingTransport` (sends captured in `sent`, delivered manually). For skewed-clock Part-4: `Supervisor::with_providers` already accepts `clock: Option<Arc<dyn Clock>>`; `scp_primitives::TestClock` is settable; add `test_supervisor_with_clock` + `create_node_with_clock`. Skew gate: `TimestampValidator` default = 5min future / 7day past (envelope/validation.rs:32/38) — keep A/B offset within 5min.
