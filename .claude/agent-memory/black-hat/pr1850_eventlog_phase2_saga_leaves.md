---
name: pr1850-eventlog-phase2-saga-leaves
description: PR #1850 delta — saga ToolInvoked/CrossContextToolInvoked/DivergenceMarker durable leaves are non-convergent (single-actor append) yet documented "convergent" via a non-existent ADR-011 Amendment §6 carve-out; violates §9.9.3 which still lists ToolInvoked as excluded
metadata:
  type: project
---

# PR #1850 (event-log Phase-2) — BLACK-EL2-001 saga durable leaves are non-convergent

**Delta reviewed:** `git diff 4cad781e5..HEAD` (HEAD 4ef63ec2b). Commit `0187f6433` "migrate #1849 saga appends" added typed `ToolInvoked` / `CrossContextToolInvoked` / `CrossContextDivergenceMarker` as durable RFC-6962 Merkle leaves.

## BLACK-EL2-001 (HIGH) — non-convergent durable saga leaves → §9.9.3 false-positive equivocation / permanent Behind
- `CrossContextToolInvoked` appended ONLY on caller-context actor in `commit_a` (saga.rs ~1788, `append_context_event_with_payload(&req.caller_context_id, …)`). Comment at 1607-1621 claims "commit-ordered convergent durable leaf … byte-identical across every honest member."
- `ToolInvoked` appended ONLY on B's executing actor in commit-B settle (saga.rs ~1494). Same convergence claim 1470-1476.
- `CrossContextDivergenceMarker` appended ONLY on the local actor that detects one-sided commit (`emit_divergence_marker` saga.rs 2034-2094). Same claim 2046-2049.
- ADR-049 = ONE actor per context per node. Cross-context invoke is a single-initiator saga (Prepare-A/Commit-A on caller's actor), NOT a governance/MLS commit replicated to co-members. So A's OTHER members never run commit_a → never append the leaf. **Leaf existence is per-author, not convergent.** Timestamp IS convergent (B's signed recorded_timestamp_ms/1000) — but that only matters IF the leaf is replicated, which it is not.
- Equivocation compare (`queries_helpers.rs` 828-865): equal count + different root ⇒ `Divergent` (suspend); different count ⇒ `Behind`/`Ahead` (benign catch-up). Initiator has N+1 leaves, co-member N. Either (a) co-member stuck permanently `Behind` and can never catch up (no replication source for the leaf), or (b) if independent appends coincide on count, equal-count-different-root ⇒ FALSE-POSITIVE equivocation → §9.9.3 suspend_write/remove an HONEST member.

## Spec/provenance violation
- §9.9.3 (worktree `09-security-model.md:823`, UNCHANGED by this PR) STILL lists `ToolInvoked` with `MessageSent`/`PaymentReceived` as "per-author application activity [that] has no global order … until [ADR-051 DAG] lands it is excluded from the canonical log."
- ADR-051 does not exist (`.docs/adrs/*051*` = no file). DAG ordering has not landed.
- Code cites "ADR-011 Amendment §6 carve-out" ~12× — **no such section exists**. phase-2.md has ONE unnumbered "Amendment (native↔WASM event-log unification)" block (line 862). The amendment's "Events excluded from the Merkle log" says the ONLY two exclusions are MessageReceived + EquivocationDetected — directly contradicted by §9.9.3 which also excludes the per-author trio. The carve-out justifying durable saga leaves is phantom provenance.
- Tension with §6.2.4 "Dual event-log recording (normative)" which DOES mandate both logs record ToolInvoked/CrossContextToolInvoked — but §6.2.4 never reconciles this with the §9.9.3 convergent-subset exclusion. The artifact flow is broken: code resolved a spec contradiction in code instead of fixing the spec first.

**Same bug class as #1845** (see [issue-1845-commit-metadata-replication]): a leaf only one node appends, documented as "copied by every honest member." Tasks #190-196 (CommitMetadata replication) are the unbuilt fix; this PR adds MORE non-convergent durable leaves before that lands.

## What RESISTS attack (confirmed sound in this delta)
- Notification-window floor `is_effective = current >= max(effective_at, observed_at+PERIOD)` (state.rs 279/352). `observed_at` = local commit-processing clock, non-backdatable. effective_at stays convergent (leaf base). Split-concern pattern correct.
- Import re-pin: `import_context` sets `observed_at = now_for_validation` for both pending changes (lifecycle_helpers.rs 1795/1803). RESTORE path (trusted self-respawn, reads local persistence via load_persisted_context_state) keeps verbatim (2336-7) — correct; malicious export can only reach import_context, not restore_context.
- TTL: local sleep = params.ttl from arm time; convergent deadline (`creation_timestamp_secs+ttl`) is ONLY the recorded leaf timestamp, NOT the fire time (ttl_close_helpers.rs 322-349, handlers/ttl_close.rs 141-148). Backdating creation_timestamp_secs cannot cause early local fire. creation_timestamp_secs = deps.clock.now_secs() at create (not a wire field).
- MessageSent off durable log: spec-mandated (§9.9.3, ADR-011 amendment). Non-repudiation never anchored on MessageSent leaf (it's per-author, would break convergence). Sequence-reservation no-rollback-on-append-failure is benign (gaps allowed in monotonic per-author counter).
- Consequence durable leaf timestamp `convergent_consequence_timestamp` = max-by-event_sequence evidence timestamp (consequence.rs 164-170); durability gate `is_convergent_trigger` keyed on ENUM (WarningCount/Custom=durable, matched ONLY against GovernanceAction Source-1 events; MessageVelocity/ToolRate=non-durable, buffer-sourced). Buffer MessageSent estimated_ts (per-member-local) never reaches a durable leaf — matches_trigger filters it to velocity only.
- WASM time.rs now_ms() native fallback is cfg(not(wasm32)) test-only; real wasm32 keeps hardened captured Date.now. Convergence timestamps are committer-copied, not from this clock.
- NonceDedup with_ttl/ttl_secs split (key_protocol_verify.rs): saga sets dedup TTL strictly > skew (2×) so coterminous-window replay (BLACK-XCTX-01) closed for co-resident path; cross-node is a documented forward obligation.
