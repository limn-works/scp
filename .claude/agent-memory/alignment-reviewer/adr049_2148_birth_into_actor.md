---
name: adr049-2148-birth-into-actor
description: ADR-049 #2148 birth-into-actor PR #2186 alignment review @ HEAD 40809c667 — ALIGNED, 1 LOW
metadata:
  type: project
---

# ADR-049 #2148 birth-into-actor (PR #2186) alignment — ALIGNED @ `40809c667` (2026-08-01)

Provider per-context-STATE dissolution (distinct from §6 trait deletion, done earlier). 4 commits: docs(adr) `bddab4a00` + 3 slices. Diff origin/main..HEAD (18 files, +1457/-3480; provider.rs alone -2860).

**Artifact-flow verdict: LEGITIMATE, not inversion.** The dissolution direction was ALREADY mandated in ADR-049 §15 (pre-edit "separable follow-on — the eventual dissolution of the concrete MlsCryptoProvider struct") and §6 (trait→two-backend replacement). The docs commit only (a) flips "eventual" → "executed by #2148, the closing edge", (b) REVOKES the PR-7-era grant ("create_mls_group/add_member remain permitted provider calls ... only for the PR-7 window"), (c) records #2167 TOCTOU as subsumed. That is downstream execution of an already-decided arc, not code reshaping the ADR.

**Code matches new ADR text at every checked point:**
- Provider struct (provider.rs:420) reduced to exactly `local_did/clock/mls_backend/hpke_backend` + one `ArcSwap<WrappingKeypair>` — NO per-context state, as ADR says.
- `contexts`/`taken_context_ids`/`broadcast_keys` maps + `with_context`/`create_group_into_slot`/`take_crypto_state` DELETED. No LIVE (non-comment) refs remain in scp-runtime (other `.contexts` hits are unrelated structs: well_known doc, test persistence, supervisor snapshot store).
- All provider orchestration (`seal/open/rotate_sender_key/advance_epoch/remove_member/mls_encrypt_management/export_crypto_state`) gone — grep for `pub fn` on provider = 0.
- Birth constructors return `OwnedMlsCryptoState` (create_mls_group_with_context:675, install_joined_group:739, create_bare_group_owned:772); caller seeds actor directly (builder.rs, supervisor WELCOME seam ~13766). Broadcast key relocated to actor `BroadcastState` (`ContextModeState::Broadcast(Box<BroadcastState>)`, state.rs:731), not dropped.
- Restore returns `(OwnedMlsCryptoState, RestoredFloors)` via build_restored_owned (provider.rs:1042); no contexts.insert round-trip.

**#2167 subsumption invariant VERIFIED true (not a recorded falsehood):** supervisor.rs:4540-4546 `spawn_actor_with_watchdog` does atomic check-then-insert under `write_lock`: `contains_key` → `Err("already registered")` → `insert`. Genuine first-writer-wins. The deleted provider `Entry::Vacant`+`taken_context_ids` guard was a redundant re-check of this property → its removal is relocation, not weakening. Enforcement: check-deleted-primitives.sh gains 6 BOUNDED positive bans (take_crypto_state/with_context/create_group_into_slot/contexts:DashMap/taken_context_ids:DashSet/broadcast_keys:DashMap) — specific deleted symbols, not a denylist chasing spellings; sound.

**Follow-ons legitimately separate (not laundering):** #2185 = pure struct rename (MlsCryptoProvider misnomer), bounded, provenance §6/§15 — correctly deferred to avoid repo-wide churn in a semantically-heavy PR (rename ≠ stub/partial). #2146 (sender-key block-list unwired) + #2147 (no per-requester rate limit) are PR-7-era sender-key ANSWER-path findings, orthogonal to the dissolution. None in #2148's scope.

**ONE LOW finding (doc coherence, non-blocking):** commit msg claims "reconcile §6/§15/§9/Consequences" but diff touches only §6 (new para L171) + two §15 paras (L367, L387). §9/Consequences untouched. Within §15, the PR-7-history paragraphs (L361/365/369/381) still describe now-DELETED primitives (`take_crypto_state`/`with_context`/`contexts`/`taken_context_ids`) in present tense — esp. L369 respawn "a taken context never re-appears in provider.contexts ... holds literally" is now vacuous post-dissolution — without a "superseded by #2148" marker, creating mild internal unevenness beside the reconciled 367/387. Defensible as frozen PR-7 decision-record history, but recommend a one-line supersession annotation OR correcting commit-msg scope. Not blocking.
