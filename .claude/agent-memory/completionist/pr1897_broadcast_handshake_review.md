---
name: pr1897-broadcast-handshake-review
description: Completeness review of PR #1897 (feat/2c-pr5-broadcast-handshake) — §5.14.13 broadcast hosting-handshake saga dispatch wiring
metadata:
  type: project
---

PR #1897 wires the §5.14.13 broadcast hosting-handshake saga dispatch (Phase 2C PR-5). Reviewed 2026-06-25.

**Scope split:** wire types (`hosting_handshake.rs` — BroadcastHostingRequest/Grant, BroadcastHostConfig clamp, AcceptedHostSnapshotEntry, OptVarBytes ucan, 2 separators) landed in a PRIOR PR; unchanged by #1897. #1897 = runtime saga dispatch only (FFI deferred per ADR-049 §3a — acceptable).

**Saga handshake is COMPLETE end-to-end:** Prepare-A/B + Commit-B/A + Abort real (not NotImplemented). Entry = `Supervisor::start_broadcast_hosting_handshake_saga` (authorize-before-reserve over both contexts; per-participant-context-set gating via `saga_participant_context_set` → {host,broadcast}). `dispatch_prepare_phase`/`dispatch_commit_phase` route BroadcastHostingHandshake to real `dispatch_bcast_*`. NeedsRepair releases concurrency slot via `_reservation` RAII drop. secret_bearing=false. Class-S (bcast_request_nonce_dedup + bcast_committed_grants) drop on cross-node export. Prepare-B: sig-bind, freshness+nonce-dedup, block-list, gated-UCAN re-bind, clamp + expires_at_ms lower-bound-reject + lifetime-ceiling clamp, aggregate cap (excludes superseded pair). All thorough.

**THE GAP (HIGH):** the §5.14.13 **snapshot-gated post-grant pull** (spec lines 1671-1681) is NOT wired. `accepted_hosts` registry is WRITE-ONLY: `upsert_accepted_host` written at Commit-B, but `accepted_host()` reader / `remove_accepted_host` / snapshot `expires_at_ms` have ZERO non-test consumers. `handle_key_request` (§5.14.2 pull) does NOT consult the snapshot — no wrapping_pubkey-equality check, no serve-time expires_at_ms refusal, no snapshot-gated block-list/gated-UCAN re-check. So the durable AcceptedHostSnapshotEntry authorizes nothing yet. The host-as-subscriber still pulls via ordinary §5.14.3 path (spec line 1681 allows that as independent subscriber-tier access), but the distinct relay-authorization pull that pins the recipient key + enforces grant expiry is absent. PR body scopes itself to "saga dispatch" + "key delivered out-of-band post-grant via §5.14.2 pull" but does NOT implement that pull. Verdict: INCOMPLETE for §5.14.13 as a whole; the saga-dispatch slice is complete.

**Note:** `BroadcastCommand::InitiateBroadcastHostingHandshake` mailbox variant intentionally returns NotImplemented (single-actor mailbox can't drive a 2-actor/2-key cross-context saga; real entry is the supervisor method). Defensible, not a finding.

Worktree: /Users/alec/Developer/limn/scp/.claude/worktrees/2c-pr5-broadcast-handshake
