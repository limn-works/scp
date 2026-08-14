---
name: eventlog-1847-deadlock-missed-windows
description: MEDIUM bug on fix/eventtype-audit-1847 — GovernanceDeadlockRecoveryPayload.missed_windows stores Vec.len() (count of evidence DIDs) not the missed-window counts; discards evidence
metadata:
  type: project
---

# issue #1847 event-log appends review (branch fix/eventtype-audit-1847, worktree /tmp/scp-1847)

Reviewed 5 commits (9159b1a19 GovernanceDeadlockRecovery, 6c8c0e0a7 Media, 34e07e64e TokenRevoked, 2eace6675 KeyEpochAdvance, 737206f84 provenance doc) + uncommitted governance best-effort helper extraction.

**MEDIUM finding — evidence misrepresentation (the only real bug):**
`GovernanceDeadlockRecoveryPayload.missed_windows: u32` is documented "Number of missed voting windows before fallback triggered" but is populated at governance_helpers.rs:2945 with `justification.missed_windows.len()` where `justification.missed_windows: Vec<(DID, u32)>` (per-DID consecutive-missed-window counts). `.len()` = number of evidence DIDs (≈ `unavailable_dids.len()`, redundant), NOT missed windows. Example: `missed_windows: vec![(bob,5)]` → leaf records `1`, but bob missed 5 windows. The actual per-DID u32 counts AND the evidence DIDs (which can differ from unavailable_dids) are discarded. Worse when justification has ONLY missed_windows and empty unavailable_dids (a valid case per validation at :3001 + the empty_unavailable_dids round-trip test) — ALL evidence lost. Durable append-only Merkle leaf → permanently wrong evidence. Test governance_integration.rs:3032 enshrines the bug: asserts `payload.missed_windows == justification.missed_windows.len()`. Root cause: scalar u32 field can't hold Vec<(DID,u32)> evidence; `.len()` papered over the type mismatch. FIX: change payload to `missed_windows: Vec<(String,u32)>` (completeness tenet — preserve evidence) OR minimally record max/sum of per-DID counts; then fix the test to assert real semantic.

**Verified CLEAN:** epoch arithmetic (block_subscriber/rotate_sender_key_for_block both checked_add(1); old=new.saturating_sub(1) exact since new>=1); block_ts captured once, reused for MemberBlocked+KeyEpochAdvance (intended co-location); TokenRevoked ts_secs=rotated_at/1000 (payload revoked_at ms per doc); media append computes seq/prev_hash under with_context/with_ucan_state lock (no TOCTOU, matches append_unsigned_event re-verify); best-effort vs fail-closed all sound (audit leaves after durable primary); provenance doc fix accurate (rmp_serde::to_vec = positional msgpack, not to_vec_named); scp-runtime compiles with uncommitted change; no bare unwrap/panic (only unwrap_or). Governance best-effort helper extraction semantically identical to inline, rationale correct (avoid duplicate primary leaf on retry).

**Pre-existing (NOT this diff), noted:** block_broadcast_subscriber MemberBlocked append is fail-closed AFTER durable commit_class_s_keep → append failure → caller retry → block_subscriber double-increments epoch. Same class as the governance duplicate-primary problem but predates #1847.
