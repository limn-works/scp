---
name: adr049-pr4-floor-registry-split
description: PR-4 floor-registry plan interrogation — write-only-follower split, dead-actor-state premise, single-writer comment. Verified vs origin/main 6e7cd3066.
metadata:
  type: project
---

ADR-049 PR-4 builds `Supervisor.floors: DashMap<[u8;32],ContextFloors>` as a NON-AUTHORITATIVE FOLLOWER (write-only until PR-6 atomically flips read-authority + deletes provider mirror + moves enforcement). Interrogated the 3 decisions behind it.

**Why:** cryptographer BLOCKER established PR-6's read-authority switch CANNOT split from mirror-delete+enforce-move (else D1 Inv-2 bypass / D2 rollback-window replay). So PR-4 deliberately does NEITHER — only builds+seeds+mirror-forwards.

**How to apply:** all three decisions VERDICT SOUND. Verified on origin/main 6e7cd3066:
- Split is a real risk-reducing decomposition (not dead scaffolding): the ONLY way to shrink PR-6's atomic blast radius is to pre-build+pre-validate the follower while the provider stays authoritative. Follower is continuously validated by respawn coalesce-lag test (§6). Durable part (check_and_advance API + Supervisor.floors) = end-state; only the 3 mirror-forward seams are transient/deleted-in-PR-6. SOUND *provided* PR-6 is committed immediate follow-on + divergence test present (it is).
- Dead-actor-state premise SOLID: `take_crypto_state` 0 prod callers (provider.rs:296 "callable but no production site calls it yet"); actor ContextCryptoState default-constructed even in prod (supervisor.rs:11695 "actor-state crypto stays default"); recv_sequence_tracker doc future-tense ("Commit 12b.2 migrates"). Provider ContextCryptoState (provider.rs:248) is the LIVE enforcement/capture/merge home.
- Registry is NECESSARY not premature: `OwnedMlsCryptoState` (PR-7's take_crypto_state move-payload, provider.rs:312) CURRENTLY carries `recv_sequence_tracker` + `sender_key_store` (.epochs) onto the actor's PerContextState — which dies on unwind = Class-M violation. So floors MUST be extracted to a separate supervisor-owned home BEFORE PR-7. Ordering PR-4(extract)→PR-6(flip+delete fields)→PR-7(move keys) is forced+coherent; registry seams stable across PR-7.
- Decision-12 DashMap allow-listed (ADR-049:292); crash_windows (supervisor.rs:1240, entry-scoped .or_default() at :4172/:4268) is the exact live precedent — real decision, not accidental status quo. End-state documented verbatim at actor/deps.rs:137-140 ("MlsCryptoProvider reduced to a supervisor-owned store for the Class-M epoch/replay floors ... ADR-049 Decision 9; non-floor crypto moves onto ContextCryptoState in PerContextState").

**Findings (QUESTIONs, not blockers):**
1. Single-writer captured as COMMENT not guard — PROPORTIONATE (not the class-S-scanner rot case): the SECURITY invariant (never key-below-floor) is structural (single-entry-guard body + Decision-13 acquire-count test + fail-safe gate-then-insert ordering); single-writer preserves only LIVENESS (spurious-reject avoidance), violation is fail-safe. BUT plan's phrasing "claims 1/2 soundness DEPENDS on single-writer" is imprecise — sharpen the code comment to distinguish structural-security from convention-liveness, else it invites misreading.
2. "ADR-049 Decision 9" cited in code (deps.rs:137) + plan but ADR-049.md has NO literal numbered "Decision 9" heading (12/14 are referenced by number). Substance IS documented (ADR:200/237/239 Class-M supervisor-owned). Soft provenance gap — chronicler should add the numbered heading or correct the pointer.
3. Three ContextCryptoState defs (scp-client, actor/state.rs:398 staged, provider.rs:248 live) = transitional rot risk IF migration stalls; pre-existing, not created by PR-4.
