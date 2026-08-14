---
name: adr049-classm-floor-home-reconcile
description: ADR-049 §9 Class-M floor-home clarification + plan/deps.rs downward reconciliation (branch docs/adr049-classm-floor-registry-reconcile) — ALIGNED, legit downward fix, not code-informs-spec
metadata:
  type: project
---

# ADR-049 §9 Class-M floor-home reconciliation — ALIGNED, 0 findings/0 blockers

Branch `docs/adr049-classm-floor-registry-reconcile` off origin/main aaa574d0f. 3 files: ADR-049 §9 (repo), deps.rs comment (repo), master plan `generic-moseying-lightning.md` dissolution table `contexts` row (LOCAL, not in repo).

**Context:** Master plan (downstream) said per-context crypto incl. Class-M epoch/replay floors "moves entirely onto the actor" — contradicting upstream ADR §9 which requires floors stay supervisor-owned to survive actor unwind (warm-respawn max-merge input, spec §23.17.2 Inv 2). Fix corrects PLAN + stale deps.rs comment to match ADR, and adds §9 clarification naming post-dissolution floor home (reduced supervisor-owned lock-free floor registry, cloned into ActorDeps like `crypto` today, Decision 12) + classifies nonce_dedup Class-C.

**Verdict: LEGITIMATE downward reconciliation, NOT code-informs-spec.** Categorically opposite of the earlier-RETRACTED "amend §9 to bless as-built per-handler persistence" option — that would have WEAKENED the decision to match code; THIS strengthens/clarifies and pulls plan+code UP to the ADR.

**3 key questions answered:**
1. §9 edit does NOT change crash-safety decision — only names the already-decided Class-M home. Line 22 drops stale parenthetical "(the MLS crypto provider Arc)" (about to be outdated at dissolution); new sub-bullet re-supplies BOTH current home ("cloned into ActorDeps exactly as crypto is today") + future home. Explicitly FORBIDS actor-side move / dead mirror ("a spec §23.17.2 Invariant-2 violation") — strengthening restatement, not relaxation.
2. Plan edit = correct direction (downstream→match upstream). `CORRECTED 2026-07` annotation + strikethrough of old "Actor owns; no lock for WHOLE struct was wrong."
3. No smuggling of incomplete impl as final design. deps.rs still `Arc<MlsCryptoProvider>` (dissolution not done); reduced-registry is forward-looking design spec = ADR governing future impl = correct flow.

**Grounding VERIFIED (no phantom):** cited fns exist — restore_crypto_state_with_floor_guard/export_sender_key_epochs(provider.rs:2639)/validate_and_merge_epoch_floors(:2705). nonce_dedup Class-C justification code-accurate: key_protocol.rs handle_sender_key_request runs validate_sender_key_request_freshness (:244) BEFORE nonce_dedup.is_replayed (:247) → freshness is outer bound, dedup only within it.

**Observations (not blockers):** (1) nonce_dedup→Class-C is a genuinely NEW security decision (not just naming clarification) — in ADR's authority + factually grounded, but ideally wants explicit cryptographer/security-reviewer sign-off vs riding a reconciliation commit. (2) §9 sub-bullet dense (5 assertions in one para) — editorial only.
