---
name: adr049-pr4-floor-registry
description: ADR-049 PR-4 plan review — split per-sender replay floors (sender-key epoch + recv-seq) from provider.contexts into supervisor-owned DashMap floors registry. Rollback protection (#1608 / §23.17.4).
metadata:
  type: project
---

# ADR-049 PR-4 — Supervisor floor registry (plan review, 2026-07-10)

Plan: `/Users/alec/.claude/plans/adr049-pr4-floor-registry-plan.md`. Base 0f26442ac (AFTER PR-3 #2100 + #2075). My working HEAD PRE-DATES #2075 — read recv-seq merge from commit 91242d36a.

## Ground truth (code)
- `set_checked` (sender_keys/mod.rs:342): atomic read-reject-if-<=-write, SYNCHRONOUS, one borrow. No crash point mid-op today.
- `open` (provider.rs:1649) + `process_incoming_sender_key` (1412 set_checked site): both under ONE `contexts.get_mut`/`with_context` shard guard. Enforcement home = `provider.contexts` (sender_key_store.epochs + recv_sequence_tracker).
- `validate_and_merge_epoch_floors` (provider.rs:2294): reads import from provider.contexts (2324), writes merged BACK to provider.contexts (2377) = SAME home hot path enforces on. Merge and enforcement ALIGNED today.
- `validate_and_merge_recv_sequence_floors` (91242d36a): step 2b overshoot ceiling reads `sender_key_store.epoch(ctx,did)` — the cross-read that justifies co-locating epoch+recv in one ContextFloors entry. REAL dependency.
- Per-context SINGLE-WRITER actor: `ContextActor::run` (actor/mod.rs:321) pulls one `ContextCommand` at a time from single mpsc inbox. `decrypt_and_dispatch`→`open`/`process_incoming_sender_key` all run inside actor dispatch → per-context crypto is SERIALIZED regardless of DashMap concurrency.
- `crash_windows: DashMap<String,CrashWindow>` (supervisor.rs:1024) = valid Class-M precedent (supervisor-owned, survives actor unwind).

## Adjudication
- Claim 1 (TOCTOU) SOUND: single-writer actor + `floors.entry(ctx)` guard = floor advance atomic; no two keys at same epoch. Depends on per-context single-writer invariant (note for future: a parallel-receive fast-path would reopen the gate→key window, fail-safe only).
- Claim 2 (fail-safe residual) SOUND: floor is the security mechanism, self-contained + monotonic in registry independent of key insert. Gate-first ⇒ floor>=key-epoch always; crash ⇒ floor-high/key-absent ⇒ next key rejected (liveness), self-heals on sender rotation (advance past stuck floor). Dangerous key-below-floor structurally impossible.
- Claim 3 (co-locate) SOUND: cross-read real (recv 2b reads epoch floor); one-entry-per-[u8;32]-ctx, inner maps keyed by did → no cross-context leak. Sequential method calls, no nested-guard deadlock.
- Claim 4 (Class-M survival) home relocation SOUND (crash_windows precedent); BUT see BLOCKER.

## BLOCKER (claims 4/5) — merge/enforcement HOME DIVERGENCE
PR-4 routes the floor-guard MERGE to the registry (deps.supervisor) but leaves ENFORCEMENT (set_checked / open replay) reading the provider mirror. Two defects:
1. After warm respawn, `restore_crypto_state` writes RAW snapshot floors → provider mirror; the max-merge writes merged=max(live,snapshot) → registry ONLY. Provider mirror (= enforcement) left at raw stale snapshot floor. §23.17.2 Invariant-2 warm-respawn rollback protection DEFEATED for the enforcement path in PR-4→PR-5.
2. CAPTURE (export live floors) rewired to registry, but registry is a LAGGING follower (mirror-forward is a separate call AFTER the provider advance — non-atomic). Crash in the lag window ⇒ registry under-reports true provider high-water ⇒ respawn installs floor BELOW true pre-crash floor = rollback regression that does NOT exist pre-split (today capture reads the authoritative provider = always fresh).

FIX: in dual-home PR-4, the CAPTURE must read the authoritative hot-path home (provider mirror), and the merged floor MUST be written back to the enforcement home (provider mirror), OR make the registry the leading (registry-advanced-BEFORE-provider) home AND move enforcement reads to the registry — but that is PR-6 (delete mirror) and cannot be split from the merge-home switch. Do NOT rewire export_*/validate_and_merge_* reads to the registry while enforcement still reads the provider mirror.
