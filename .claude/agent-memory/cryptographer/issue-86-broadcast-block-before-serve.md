---
name: issue-86-broadcast-block-before-serve
description: Crypto review of #86 broadcast block-before-serve Class-S crash-durability fix (branch fix/86, HEAD 1ea5b32e4) — SOUND
metadata:
  type: project
---

# Issue #86 — broadcast block-before-serve crash-durability (Class-S fold)

Reviewed branch `fix/86-broadcast-block-before-serve-class-s` @ `1ea5b32e4`. Verdict: **SOUND**, no blocking crypto defects.

**What changed:** broadcast security state (per-author `block_list`/`epoch`/`broadcast_key` + governance `read_exclusion_list`) now rides the fail-closed Class-S `ContextSnapshot` (`ContextSnapshot.broadcast: Option<BroadcastContextSnapshot>`, state.rs:1113). Legacy best-effort `persist_broadcast`/`load_broadcast` trait methods DELETED (pre-release). Mutation surface confined: `AuthorState.{broadcast_key,epoch,block_list}` now PRIVATE; runtime `BroadcastContextClassCMut` forwards only benign methods; security mutators reachable only via whole `&mut BroadcastContext` from `ClassSMut::rest_mut()` (fail-closed combinator). Serve path `handle_broadcast_key_request` consults `read_exclusion_list` pre-delegation. Restore reconciles via `apply_read_exclusions`.

**Key soundness facts (for future reviews of this area):**
- Ban atomicity: `execute_revoke` (governance_helpers.rs:914+917) does `read_exclusion_list.insert` + `governance_ban_subscriber` (block-list insert on every author + epoch advance + new SenderKey + registry removal) INSIDE `commit_class_s_keep` → `persist_state_fail_closed` = one atomic ContextSnapshot row BEFORE ack/event-append. No crash interleaving leaves old-epoch key servable to banned member. `handle_key_request` serves only CURRENT epoch.
- `commit_class_s_keep` (class_s.rs:2764): runs closure, then persist_state_fail_closed; Ok only if persist landed; KEEP = on persist-fail returns Err but keeps in-memory mutation (safe direction — don't re-grant).
- Key material zeroization: `SenderKey` derives ZeroizeOnDrop (crypto/sender_keys/mod.rs:83) + Debug=[REDACTED] (:103). `AuthorStateSnapshot` holds raw SenderKey but transitively wipes on drop; no Debug leak even though ContextSnapshot/BroadcastContextSnapshot derive Debug.
- At-rest: OLD store_broadcast_state and NEW persist_context both write same Storage backend (SQLCipher). No less-protected-row regression. Public export redacts `broadcast: None` (export_import.rs:809); import forces broadcast_context None / rejects broadcast exports.
- Non-leakage: serve-path Deny uses byte-identical KEY_REQUEST_DENY_REASON (broadcast/mod.rs:602). read_exclusion consult early-return is a local timing diff only, not a new message category, not wire-observable under no-response model.
- Restore reconciliation (lifecycle_helpers.rs:2353): rebuild broadcast_ctx from ctx_snapshot.broadcast then apply_read_exclusions(read_exclusion_list.iter()) — inserts excluded into EVERY author block_list + drops registry. Uses .iter() so read_exclusion_list still moves into state.access:2703. Never touches key/epoch (no key resurrection). Asymmetry: per-author block does NOT write read_exclusion_list → reconciliation can't rescue it → block_broadcast_subscriber MUST be (and is) fail-closed.
- restore_context fail-closes on routing/mode contradiction (lifecycle_helpers.rs:2596).

**Open LOW findings I reported (not fixed at review time):**
1. `ProtocolRepository::store_broadcast_state`/`load_broadcast_state` (store/context.rs:688,712) now orphaned — only test callers after trait deletion. Dead prod code + unused `context/{id}/broadcast_state` key. Delete or document.
2. Stale docs broadcast/mod.rs:1947,2019 still cite `ProtocolRepository::store_broadcast_state` as snapshot persistence path (now rides persist_context).

**Observation (not defect):** `BroadcastContextClassCParts::unsubscribe(rotate_keys=true)` (broadcast/mod.rs:766) rotates keys on benign best-effort path — OK because unsubscribe is voluntary self-removal and crash reverts roster+rotation atomically together (both in broadcast snapshot); hostile eviction uses fail-closed ban/block.

Tests present & correct: broadcast_block_persist_is_fail_closed_and_retains_block, broadcast_unblock_stays_best_effort_on_persist_failure, broadcast_governance_ban_persist_is_fail_closed, *_survives_crash_before_coalesce, *_are_one_atomic_snapshot, broadcast_key_request_denies_read_excluded_even_if_subscriber, apply_read_exclusions_does_not_rescue_a_unilateral_block.
