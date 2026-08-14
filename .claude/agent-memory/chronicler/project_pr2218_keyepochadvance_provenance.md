---
name: pr2218-keyepochadvance-provenance
description: PR #2218 rotate_all_author_keys epoch-advance — provenance/doc findings on §5.14.10, §2008/§2015, #1847, dead-data ts
metadata:
  type: project
---

PR #2218 `fix/rotate-all-author-keys-epoch-advance` (heads 84be6115b + 050d0767f). Chronicler doc/provenance audit 2026-08-02.

**Key facts about the spec (05-contexts.md):**
- §5.14.10 (line 2043, "Event Log") is DEFINITIONAL — it declares `KeyEpochAdvance { sender_did, epoch }` as a NEW event type shared across Encrypted+Broadcast. It does NOT prescribe emission on RotateContentKeys.
- The prescriptive "all authors MUST rotate keys → mandatory KeyEpochAdvance per author" text is §5.14.8 (Blocking / governance-ban), lines 2012+2019. RotateContentKeys broadcast arm has NO spec text describing all-author epoch advance + KeyEpochAdvance emission → spec gap.
- §9.17 = "Content Access Key Layer" (encrypted-context access keys), NOT the broadcast per-author sender-key model. rotate_all_author_keys rotates broadcast per-author keys (§5.14.8 / §9.16 sender-key layer). PRD cites §9.17 for the RotateContentKeys *action* generally, so §9.17 in a broadcast-arm test comment is a mild mis-citation.

**§2008 / §2015 anti-pattern:** governance_helpers.rs execute_revoke comment `// Spec §2008 / §2015:` uses the § glyph on LINE NUMBERS (stale — real text at 2012/2019), colliding with the genuine dotted-section convention (§5.14.8 style). Pre-existing but the PR edits that function body. Should repoint to §5.14.8/§5.14.10. The PR's OWN new RotateContentKeys comment correctly uses §5.14.10 — inconsistency within one function.

**#1847:** REAL github issue but CLOSED, and it is an AUDIT issue ("canonical EventType taxonomy: variants with no durable-append producer"), not a PRD story. Lists ~7 candidate variants (Provenance, AppBound, Media, CommitBroadcast, GovernanceDeadlockRecovery, KeyEpochAdvance, TokenRevoked). This PR addresses only KeyEpochAdvance + the GovernanceDeadlockRecovery counter → does NOT fully close #1847. No PRD story governs this change; provenance rides a closed audit issue.

**Counter-fix correctness:** execute_reconfigure_governance appends GovernanceReconfigured + GovernanceDeadlockRecovery both via `.await?` (FAIL-CLOSED) → unconditional `+= 2` is sound (reaching the bump guarantees both durable). Contrast the best-effort KEA paths (execute_revoke, execute_rotate_content_keys) which correctly use conditional `+= 1 + kea_success_count`. Well-reasoned distinction. The §9.9.3 checkpoint-drift invariant lives at governance_logic.rs:156-158 (counter must equal true durable-leaf count).

**Test gaps:** (1) checkpoint_events_since counter value — the heart of both commits — is UNTESTED; integration tests assert leaf presence/count only. (2) rotate_all_author_keys sort_unstable_by(author_did) determinism (load-bearing for cross-replica Merkle root) has no test asserting returned Vec is sorted (unit test re-sorts before comparing). (3) deadlock test is PRE-EXISTING (empty diff vs main), covers happy path only — but path is fail-closed so failure-case test is non-load-bearing (LOW).

**Dead-data:** BroadcastKeyEpochAdvance.timestamp (broadcast.rs:134) rustdoc says only "Unix timestamp in ms when rotation occurred"; does NOT document it's consumed only on the per-author block relay-message path and dead on the governance/event-log path (which uses timestamp_secs). The dead-data note lives only in governance_helpers.rs, not on the shared struct field.
