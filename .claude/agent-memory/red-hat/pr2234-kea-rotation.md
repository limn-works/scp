---
name: pr2234-kea-rotation
description: Red-team analysis of PR #2234 content-key-rotation KEA best-effort + checkpoint counter; why the counter undercount and best-effort KEA are NOT exploitable
metadata:
  type: project
---

# PR #2234 fix/rotate-content-keys-review-followup — red-team verdict: CLEAN (LOW/informational only)

Fast-follow for #2218 (broadcast content-key rotation). Real review-followup delta = commit 39a19e90c (5 files); rest of `main...` diff is #2218-stack drift.

**Key architectural fact (reusable):** `checkpoint_events_since` is a LOCAL trigger heuristic ONLY (fires checkpoint at 50 events / 600s). The checkpoint's actual content — `merkle_root` and `event_count` — is read DIRECTLY from the event log inside `build_checkpoint` (queries_helpers.rs:771, `event_log_merkle_root` + `event_log_entries().len()`), NOT from the counter. So a counter undercount can NEVER corrupt checkpoint content or cause cross-replica Merkle divergence — worst case is a checkpoint fires marginally later. `+= 1 + kea_success_count` (governance_helpers.rs:1032, 3251) correctly tracks only durably-appended leaves.

**Best-effort KEA (execute_revoke:987, execute_rotate_content_keys:3205):** epoch advance is FAIL-CLOSED persisted (crypto durable → forward-fencing holds); only the SEPARATE KeyEpochAdvance provenance leaf is best-effort. NOT weaponizable: (a) payload encode = two internal u64s, cannot fail on attacker input; (b) event-log I/O failure is owner-local, not a remote channel, and would need to fail SELECTIVELY on KEA appends but not the preceding `.await?` primary leaf (which would abort the whole op); (c) the party who could exploit it (context-owning actor) already authors the log and could omit leaves anyway — no priv-esc. Impact ceiling = provenance-completeness gap, LOW.

**TODO(spec) §2033 vs §5.14.10/ADR-011:** honest self-flag that convergent-trigger semantics MIGHT require fail-closed KEA. Not a gap TODAY (actor-per-context = single authoritative owner-authored log, no independent member derivation → no divergence). RECOMMENDATION (not blocker): make KEA fail-closed via `?` like the reconfigure sibling (execute_reconfigure_governance:3389) — strictly safer, cheap, matches sibling pattern. Would also close the spec tension.

**execute_add_member None-KP (lifecycle_helpers.rs:849):** NOT a DoS. Production None KP rejected FAST (before state mutation/crypto/lock/economy) with InvalidKeyPackage. The REAL (theoretical) risk is inverse: a prod build accidentally compiled `feature="testing"` ACCEPTS None KP → unauthenticated member add. Mitigated by ADR-062 G1 gate (proves scp-platform/testing never reaches shipped artifact) — build/CI boundary, not runtime.

**UniFFI testing gate (Cargo.toml):** ADR-062 §Decision 6 consolidation (delete `allow_in_memory_custody`, fold into single honest `testing`). No RUNTIME widening in non-testing build (custody/None-accept/seams all compiled out). Removes a defense-in-depth SEPARATION (testing was independent of custody-escape); now `testing` pulls scp-platform/testing. `outlet-capability-test-grant` authority-escalation seam correctly kept SEPARATE. Protection = G1 gate.

**Sort fixes correct:** broadcast/mod.rs governance_ban_subscriber:1652 + rotate_all_author_keys:1729 both `sort_unstable_by(author_did)`. DIDs unique (HashMap key) so unstable is fine. Epoch overflow pre-validated with checked_add before any mutation (all-or-nothing) → new_epoch never wraps to 0 → old=saturating_sub(1) never confused.

Minor cosmetic: task-prompt quoted error "production add_member requires MLS key package bytes" ≠ actual code "production MlsBackend requires MLS key package bytes".
