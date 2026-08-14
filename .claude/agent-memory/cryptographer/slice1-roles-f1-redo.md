---
name: slice1-roles-f1-redo
description: SCP-1877 slice-1 WASM F1-REDO MemberJoined leaf-timing reorder — SOUND, no actionable crypto findings
metadata:
  type: project
---

# SCP-1877 slice-1 WASM F1-REDO (commit d96c38c0d) — SOUND

Branch `wasm/1877-slice1-adopt-context-role-state`, worktree `.claude/worktrees/slice1-roles`.
F1-REDO touches ONLY `crates/scp-ffi/wasm/src/manager.rs` (consequence.rs untouched by this commit — git diff HEAD~1...HEAD empty for it).

**Why:** prior encrypted-join appended MemberJoined durable leaf + buffer event via inner `join_context` BEFORE the fallible MLS Welcome. Append-only log can't un-append → orphan leaf + phantom buffer event on Welcome failure where native produces none = reachable cross-impl equivocation (latent #1540).

**Fix:** extracted `join_context_membership_only` (membership commit + role-assign rollback, NO leaf/event). Unencrypted `join_context` calls it then appends leaf+event immediately (matches native non-MLS join). `join_context_encrypted` calls it → process Welcome → install crypto → THEN append leaf+event LAST (native Phase 5 ordering). Failed Welcome leaves no durable trace.

**Crypto invariants confirmed on FINAL code:**
- Leaf preimage UNCHANGED: both call sites build `append_log_event(EventType::MemberJoined, member_did, b"", now_secs())`. RFC 6962 leaf hash `SHA-256(0x00||serialize(Event))` in scp-event-log/tree.rs untouched. Only timestamp value + append timing differ.
- Timing REMOVES the orphan-leaf divergence (converges to native). Native lifecycle_helpers.rs join: Phase3 MLS add → Phase4 membership → Phase5 leaf append. WASM now mirrors.
- member_sequence_numbers seeded at membership (=0), rolled back with members on Welcome failure. No key-schedule/nonce issue from reorder — MLS group only installed after join_from_welcome Ok; sender key generated fresh post-success.
- No regression to UCAN ceiling / export snapshot / §5.3.1.1 (untouched).

**ONE micro-divergence (NON-BLOCKING, deferrable):** WASM samples `now_secs()` FRESH at append (post-MLS), native captures `now_secs` ONCE early (line 727) and reuses at leaf (line 994). Delta = join_from_welcome duration (sub-ms), timestamp is whole-seconds (now_ms/1000). For the COMMITTER-APPENDED-ONLY, not-yet-replicated MemberJoined leaf this is NOT a convergence concern now — native's own comment (lines 985-991) documents the leaf as committer-appended-only, receive-side dormant, cross-member convergence deferred to ADR-051. Slice-1 verdict: deferrable forward ADR-051 item, NOT a slice-1 defect. Recommend (cosmetic) capturing now_secs() once at fn top in both WASM join paths for byte-parity hygiene when ADR-051 replication lands.

Tests: welcome-failure asserts leaf_count unchanged + no drainable MemberJoined; success-path asserts exactly 1 leaf + 1 buffer event. Both correctly target the bug.
