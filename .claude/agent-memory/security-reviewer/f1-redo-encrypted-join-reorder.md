---
name: f1-redo-encrypted-join-reorder
description: WASM F1-REDO encrypted-join leaf reorder (commit d96c38c0d, branch wasm/1877-slice1-adopt-context-role-state) — security CLEAR, no findings
metadata:
  type: project
---

# F1-REDO: WASM encrypted-join MemberJoined leaf deferral — SECURITY CLEAR

Commit `d96c38c0d` on `wasm/1877-slice1-adopt-context-role-state`. Reviewed 2026-06-24. ZERO actionable findings.

**What changed** (crates/scp-ffi/wasm/src/manager.rs only — consequence.rs untouched by this commit):
- Extracted `join_context_membership_only` (private) from `join_context`. Helper does: active-check, §13.4 version gate, C2 fail-closed economy gate (SCP-ECON reject), dup-member CTX_2013, members insert + member_sequence_numbers seed + system_assign_role("member") with full rollback. Appends NO leaf, NO buffer event.
- `join_context` (unencrypted): calls helper, THEN appends MemberJoined leaf+buffer event immediately (matches native non-MLS join).
- `join_context_encrypted`: calls helper, processes MLS Welcome, and on success installs crypto + appends leaf+buffer event LAST (native Phase 5 ordering). On Welcome Err, inline-strips membership (members/assignments/member_capabilities/restore suspended/member_sequence_numbers).

**Why it's a security IMPROVEMENT, not just neutral:** Pre-F1-REDO the inner join_context appended the durable MemberJoined leaf to the append-only log BEFORE the reachable join_from_welcome failure — un-removable orphan leaf, diverged from native (latent cross-impl equivocation). Now leaf only on full success.

**Key facts verified:**
- Rollback field-set exactly matches what helper writes (system_assign_role writes assignments + member_capabilities + prune_suspensions; helper writes members + member_sequence_numbers). roles.rs:1731.
- Deferred-leaf TOCTOU window (member in role_state.members, crypto==None) is BENIGN: WASM single-threaded, &mut self exclusive for whole call, no reentrancy. Same window existed pre-change.
- push_event + append_log_event are INFALLIBLE (return (), errors logged to console, never ?-propagated) — no fallible call between crypto install and leaf append, success tail effectively atomic.
- Leaf timestamp = now_secs() committer-assigned (joiner clock §7.3.1/§9.9.3), NOT derived from attacker welcome_bytes. Identical to unencrypted leaf.
- Two new tests are REAL: negative (leaf-count-unchanged + no buffered event on Welcome fail) + positive (exactly-one leaf/event on success). Not string-search stubs.

**Lone OBSERVATION (non-blocking):** failure + success branches re-acquire via `require_active_context_mut(context_id)?` — the `?` could skip rollback if ctx deactivated mid-call, but unreachable under single-threaded WASM (join_from_welcome can't deactivate). Sound only under that invariant.
