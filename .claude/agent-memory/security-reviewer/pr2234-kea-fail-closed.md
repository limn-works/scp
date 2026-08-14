---
name: pr2234-kea-fail-closed
description: PR #2234 fix/rotate-content-keys-review-followup — KEA best-effort→fail-closed on governance paths; SECURE, PASS
metadata:
  type: project
---

# PR #2234 KEA fail-closed on governance paths (fix/rotate-content-keys-review-followup) — 2026-08-02 — PASS, 0 CRITICAL/HIGH/MEDIUM

Follow-up to #2218. Flips KEA event-log leaf emission from best-effort→fail-closed in `execute_revoke` (governance ban) and `execute_rotate_content_keys` (RotateContentKeys), per ADR-011 "convergent governance trigger → convergent leaf". Adds sort-by-author_did to `unsubscribe` + `governance_ban_subscriber` (mirrors existing sort in `rotate_all_author_keys`). Inline per-leaf counter bumps replace post-loop `+= 1 + count`. Adds test-only `SeedBroadcastAuthor` command (mirrors SeedPeerPseudonym).

## Why it's SECURE (the load-bearing ordering)
- **Access-control-critical state is durable BEFORE any KEA leaf.** Both fns commit the ban + all-author key rotation inside a single `commit_class_s_keep(...)` closure (`.await?`) that persists fail-closed (keep-direction). The KEA leaf loop runs AFTER that persist. So a KEA-append failure CANNOT leave keys un-rotated or the ban un-applied — the rotation is upstream of and independent from the audit leaf.
- **Q2 (epoch-in-log-but-not-registry / reverse): impossible.** Registry epoch advance IS the persisted Class-S snapshot state, durable before the leaf. Fail-closed KEA leaf can only leave: registry advanced (durable) + partial KEA leaves + Err surfaced. Log lags registry — the SAFE direction (lagging log never re-grants access). No path where log is ahead of registry.
- **Q1 (atomicity): the ban + all-author rotation is atomic** inside one Class-S closure. The only "partial" is audit leaves, not auth state. KEA loop errors only occur on broadcast path (rotated_authors non-empty ⇒ broadcast_context Some ⇒ H7 needs_sender_key_rotation is false), so the skipped-tail (H7) is mutually exclusive with the KEA path — no missed downward rotation.
- **Q3 (sort): convergence-only, no security downside.** author_dids are unique (add_author rejects dupes with PermissionDenied) ⇒ sort_unstable deterministic. Fixes HashMap-iteration nondeterminism that would diverge Merkle roots across replicas/replays.
- **Counter accounting matches durable leaves in every path.** Governance paths: inline `+= 1` AFTER each confirmed `.await` append (no over-count on later failure, no under-count of already-durable leaves). Best-effort paths now ALSO use inline bumps (4th pass, commit 8818768a9 replaced the post-loop `+= 1 + kea_appended` / `+= kea_success_count` accumulators): each bump sits strictly in the `else` of `if let Err = ...append().await`, so it fires ONLY on a durable append. This is the "Bug 2 fast-follow" fix.

## 4th-pass (8818768a9) inline-bump conversion — VERIFIED CLEAN, PASS
- broadcast_helpers.rs `unsubscribe_broadcast` (bump L294 in KEA loop) + `block_broadcast_subscriber` (MemberBlocked bump L730 after `.await?`; KEA bump L768 in else). NOTE: real branch content only visible via `git show origin/branch:file` — local working tree was on detached HEAD/main (the documented gotcha).
- **Borrow checker satisfied:** `cell: &mut ClassSCell`, `deps: &ActorDeps`, `result` are 3 distinct bindings. `deps.event_log.append().await` borrows deps; the `else`-branch `*cell.class_c_view()...+= 1` borrows cell — after the await completes, no borrow held across it. In unsubscribe the `for rotation in &result.key_rotations` holds `&result` across a `&mut cell` body — distinct bindings, OK. Compiles.
- **Bump position correct:** every bump is AFTER a successful append. Unsubscribe L294 = `else` of append-Err. Block MemberBlocked L730 = after `.await?` (only reached on Ok). Block KEA L768 = `else` of append-Err. NO path bumps before an await or on a failed append.
- **Tests** (governance_ban_subscriber_bumps_counter_per_kea, block_broadcast_subscriber_counter) validate counter via EVENT-LOG LEAF-COUNT proxy (delta = 1+num_authors ban; 2 block), not a direct checkpoint_events_since read (no such test API; reconfigure test uses same proxy). Proxy is tight here: leaf-in-log ⟺ append-Ok ⟺ bump-fired.
- **Blast radius of any miscount is bounded to checkpoint CADENCE** — checkpoint_events_since is a local emission trigger, does NOT feed event_log_merkle_root; two members with identical durable leaves get identical roots regardless. Not a consensus/auth hole.
- **LOW/obs:** `unsubscribe_broadcast` inline bump (L294) has no dedicated counter test (block+ban do); symmetric to block path so low risk, coverage gap only.
- **fail-closed IMPROVES convergence** vs old best-effort: old path silently checkpointed a leaf-short log; new path errors so a leaf-short log isn't silently committed.

## Best-effort retained (correctly) on unilateral/upward paths
`block_broadcast_subscriber` (per-author unilateral block) + `unsubscribe_broadcast` (voluntary, authorization-UPWARD-safe §5.14.8) keep best-effort KEA. Coherent: only governance-CONVERGENT triggers (ban, RotateContentKeys) go fail-closed.

## Test seam gating
`SeedBroadcastAuthor` cmd + handler + ClassCMut::seed_broadcast_author + Supervisor::seed_broadcast_author all `#[cfg(feature="testing")]`. NO FFI reference (grep clean in crates/scp-ffi + bindings). `testing` not in shipped prod cdylib (G1). Even in allow_in_memory_custody builds (which pull testing) the variant compiles but is unreachable — no FFI method constructs it, needs direct Rust Supervisor access. Matches SeedPeerPseudonym precedent.

## Observation (LOW, not a defect)
Fail-closed means a transient event-log failure during KEA append returns Err to the governance caller EVEN THOUGH the ban/rotation is already durable + effective. Proposal is already Approved in-engine ⇒ retry blocked by engine (no double-execution / no re-rotation). Net: "error surfaced but action succeeded + audit trail under-documents rotation for un-appended authors, with no auto-recovery." Operational/observability nuance, not an auth/access-control hole.
