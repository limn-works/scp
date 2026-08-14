---
name: spending-ucan-revocation-spec-round4-4bc8be843
description: Round-4 re-review §19.5 spending-UCAN revocation — enumerated invariants 1a/1b/2a/2b/3a/3b grounded, authz tightened; ALIGNED, zero findings
metadata:
  type: project
---

# Spending-UCAN Revocation Spec Round-4 @ branch tip 188af5ad2 §19.5 (2026-07-08) — ALIGNED (0 findings)

Branch worktree-agent-a32cd09f9850dfdd7. Commits 4bc8be843 (enumerate §19.5 "Paid-action gate invariants" 1a/1b/2a/2b/3a/3b + tighten authz) + 188af5ad2 (invariant 2b concurrency fix). Read via `git show 188af5ad2:`.

**Round-3 findings BOTH RESOLVED + verified accurate vs code:**
- Fail-closed-on-unhydrated now DESCRIBED as normative invariant **1a**: NotConfigured/Hydrated=status_known may authorize; NeedsHydration/Failed→every scp:spending:* fails CLOSED for ALL contexts incl. created-after-failure until hydration succeeds; context-scoped unaffected; hydration runs FIRST at startup. Matches economy_logic.rs (global_scope_status_unknown→is_revoked=true), deps.rs shared flag cloned into later actors, restore_on_startup order.
- Phantom-provenance CLOSED: all 6 labels code cites (1a×16, 1b×1, 2a×4, 2b×4, 3a×1, 3b×1 across 8 files) are now present in spec §19.5 as **(1a)..(3b)** labeled list. Zero phantom labels.
- Authz precision FIXED (§19.5 per-context bullet): now "authorized ONLY for the scope-context creator, or the token's issuer WHEN a current member (SCP-ECON-12067/12069) — a bare non-issuer member cannot revoke, and a non-member issuer cannot revoke there." Matches code = creator OR (issuer AND member).
- Member-gate note PRESENT (invariant 3a): "an issuer who has LEFT the context can no longer revoke a token there — availability-conservative, security-safe (gate can only decline an otherwise-authorized revoke, never grant one)." Matches 12069 membership gate.

**All 6 invariants verified accurate (no misdescription):**
- 1a fail-closed-unhydrated ✓ (round-3 code). 1b retain-on-upgrade: record default now `#[serde(default="retain_forever_moot_after")]`→`u64::MAX` never-moot RETAIN (changed from round-3's 0/GC-eligible) ✓. 2a bounded incremental: `load_for_did(iss,now)` single-DID expiry-GC'd re-derive, never blind-insert ✓. 2b atomic re-read+store under write_lock: global revoke calls supervisor DIRECTLY (not mailbox), acquires write_lock BEFORE load_for_did, stores under guard; on load-error inserts just-revoked CID under lock before surfacing err; hydrate holds SAME lock across load_all+store+mark_hydrated/failed — parity claim TRUE ✓. 3a member gate ✓. 3b non-empty revoker (12068) + creator branch requires non-empty creator ✓.

Verdict: ALIGNED. Zero findings. Coordinator's round-5 = zero-findings target met. Feature spec↔code fully converged over rounds 1-4 (self-limiting removal → nonce/expiry accuracy → GC-split → verify-fn naming → per-context unbounded honesty → enumerated invariants + concurrency 2b).
