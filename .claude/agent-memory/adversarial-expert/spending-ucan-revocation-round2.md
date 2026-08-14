---
name: spending-ucan-revocation-round2
description: Round-2 adversarial review of scope-matched spending-UCAN revocation fixes (§19.5) — what held, what didn't
metadata:
  type: project
---

# Spending-UCAN Revocation — Round 2 (fixed state @ ddd7e1dc0)

Feature: §19.5 scope-matched spending-UCAN revocation. Fixes 826bb2b88/e62b00d2a/f0a99f5e4/9a7934019/ddd7e1dc0 over base 904f6d3dc.

## Held up (could NOT break)
- **Re-spend / GC-window (BLACK-SPEND-1 attack #1): CLOSED.** GC-moot condition `revocation_moot_after_secs = exp + DEFAULT_CLOCK_SKEW_TOLERANCE_SECS`, pruned when `<= now` (revoked_spending_ucans.rs:183,235; supervisor.rs:3697). Gate expiry-rejects when `exp + tolerance <= now` (validate.rs:1337). Byte-identical boundary → no window where a live token's revocation is GC'd. DID key always matches: gate enforces iss==aud==actor_did and looks up `global_revoked_cids_for(sender_did)` (messaging_helpers.rs:995), revocation keyed by iss.
- **CID canonicalization: SOUND.** compute_revocation_cid = SHA-256 of raw JWT string (revoke.rs:661). URL_SAFE_NO_PAD rejects padding + trailing bits; sig unforgeable. Same fn both sides.
- **Authz bypass (BLACK-SPEND-2 attack #2): CLOSED.** Global issuer-only check uses cryptographically-bound iss (verify_spending_ucan_genuine checks sig against iss, iss==aud — spending.rs:431,438). Direct-dispatch fallback fails closed (supervisor.rs:3446). Context-scoped authz inside actor before mutation (economy.rs:153). Residual = documented revoker_did authentication contract (BLACK-SPEND-3, by design trusted-local).

## Findings (open)
1. **MED-HIGH — Fail-closed hydration is incomplete.** No gate-level poison. FFI `restore_all_persisted_contexts` SWALLOWS RevocationHydrationFailed (bridge_instance.rs:1729, logs warn, returns). restore_on_startup's fail-closed only means "restore didn't proceed" — subsequently spawned create/join actors share the still-empty `global_revoked_spending_cids` Arc and serve paid actions. One transient boot read failure → global revocation enforcement silently disabled until process restart (no re-hydration). Fix: poison AtomicBool consulted by gate, or abort startup.
2. **MED — In-memory global cache grows unbounded on incremental revoke.** Cache mirror only inserts, never prunes moot CIDs (supervisor.rs:3710-3716). Cache type HashMap<DID,HashSet<String>> stores no per-CID expiry (deps.rs:219) → structurally cannot prune incrementally. Only hydrate() rebuilds/GCs. Durable store IS bounded (insert-GC). Divergence: cache = superset of durable. Contradicts module doc claim GC bounds "both the durable store and the hydrated in-memory cache" (revoked_spending_ucans.rs:216-219). Self-issued payer floods = RAM DoS.
## Round 3 (fixes f9c9dc0da/15b70616f/854fd24c6/fe092f890/1e6e744d2) — ALL THREE CLOSED
- **F1 (fail-open after failed hydration): CLOSED.** Shared `GlobalRevocationHydration` Arc<AtomicU8> (NotConfigured/NeedsHydration/Hydrated/Failed); status_known = NotConfigured||Hydrated. Enforced at SINGLE chokepoint `ContextRevocationChecker::is_revoked` (economy_logic.rs:170) via REQUIRED field `global_scope_status_unknown` (no Default → compile-enforced). Both prod checker sites (economy_logic.rs:226, saga.rs:1180) compute `!status_known && scope==Global`. Store-set coupled to mark_needs_hydration (supervisor.rs:1965-1975, same block). hydrate: mark_failed on read err, cache-store BEFORE mark_hydrated (ordering sound, release/acquire). All ActorDeps carry shared flag (deps.rs:315 clone, supervisor.rs:2609). No fail-open direction.
- **F2 (unbounded cache): CLOSED.** Incremental path re-derives affected DID entry from freshly-pruned durable via `load_for_did` and REPLACES (supervisor.rs:3765-3779). Residual (info): quiet-DID moot entries persist till restart, bounded by distinct-DID count, moot=safe over-reject.
- **F3 (per-context authz): membership gate added** (economy.rs:187, SCP-ECON-12069, creator exempt) + empty-DID reject (12068). Doesn't over-deny (non-members can't spend anyway). Set still unbounded by self-issuance — honestly acknowledged, principled bound deferred to #2072.
- Info nits: load_for_did-fail-after-record-success → transient durable/cache divergence but caller sees PersistenceFailed (no false success), self-heals at hydrate. Configured store w/o ever calling hydrate → global spends fail-closed permanently (safe; FFI/node call restore).

## Round 4 (fixes 4bc8be843 spec, 188af5ad2 concurrency) — CLEAN
- apply_global_spending_revocation (supervisor.rs ~3781): write_lock acquired BEFORE load_for_did; re-derive+ArcSwap::store atomic under guard; leaf append moved AFTER drop(guard). All 3 cache writers (3794 fail-closed insert, 3808 normal, 9345 hydrate) under write_lock. No lock-free writer.
- #1 cache-loss: CLOSED. "Last store under lock" always re-derives full durable set for the DID (replace-not-merge, bounded=complete) → sees all prior records. record-outside-lock is fine (each revoke's record happens-before its own load-under-lock). Proved for all interleavings.
- #2 deadlock: NONE. write_lock is tokio::sync::Mutex (async, safe across await). load_for_did = pure storage (prune+list+load), takes no lock a write_lock-holder waits on; storage never calls back into supervisor. Leaf I/O outside lock.
- #3 fail-closed insert-on-load_for_did-error (3791-3795): correct — CID merged into entry under lock, PersistenceFailed surfaced, durable+cache consistent; stale-moot over-retention is safe direction.
- #4 test concurrent_global_revokes_same_did_do_not_clobber_cache (19751): REAL race — real revoke_spending_ucan, real inner ProtocolRepository, YieldOnLoadStore injects 8 yields at exact TOCTOU point, multi_thread worker_threads=4, 8 concurrent tasks, asserts ALL 8 CIDs survive, 8 iters. Not a mock.
- Pre-existing (NOT round-4 regression): cancellation/panic between record(3748) and cache store leaves durable-has/cache-lacks until restart — caller gets no success, self-heals at hydration. Same as error path. Safe.

## Round 6 (refactor e8d4cc974: unify to load_all reload; tip 60a098937) — CLEAN
- Extracted reload_global_revoked_cache_under_lock (supervisor.rs:9294): write_lock → store.load_all → ArcSwap::store whole map, no cache/flag mutation on err. load_for_did DELETED (zero refs). Both hydrate (9351) and apply_global (3775) call it.
- Q1 happens-before: CLEAN, cleaner than load_for_did. record (3748) seq-before helper lock; last-acquiring revoke's load_all re-derives ENTIRE durable → all concurrent same-DID CIDs present.
- Q2 error-branch second lock (3787-3792): CLEAN. Helper released its lock on err; apply re-locks, additive entry().or_default().insert(cid), atomic clone+insert+store under re-lock. cidA durable so any concurrent successful reload includes it; additive = no other DID lost.
- Q3 whole-map store: CLEAN. load_all re-derives all DIDs from durable, can't drop a durable entry. Mid-flight omission of not-yet-recorded concurrent CID self-heals (that revoke hasn't returned + its own reload re-derives).
- Q4 no new fail-open. Whole-map store STRICTER than single-DID replace. INFORMATIONAL (not regression, not blocking): error path now takes lock twice (helper acquire+release, then re-lock) vs once — marginally widens the PRE-EXISTING record→cache-update TOCTOU (gate reads lock-free via ArcSwap, so in-flight-being-revoked token can authorize between record success and cache store; exists in ALL versions). Error-path-only, caller gets PersistenceFailed, ns-scale. apply does NOT mark_failed (correct: transient incremental blip shouldn't fail-close all global spends; additive insert covers the at-risk CID).
- Test: YieldOnLoadStore now yields in load_all (19730), real revoke path, asserts got==expected_cids all survive, 8 iters. Intact.

### (superseded) Round 2 finding 3 — Per-context Class-S set bounded by FALSE claim. revoked_spending_ucans.rs:54-62 claims growth "bounded by issuer-or-creator authorization." But issuer==self (iss==aud) can self-issue unbounded distinct context-scoped tokens + revoke each; NOT time-GC'd (convergent) → bloats every member's governance state + signed export digest forever. Same false "self-limiting" reasoning the fix removed for global. Also: revoke authz (economy.rs:153) has NO context-membership check — anyone reaching a resident context actor can inject CIDs scoped to that context.
